/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <assert.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <door.h>
#include <errno.h>
#include <generic.h>
#include <md5.h>
#include <sys/mkdev.h>
#include <netdb.h>
#include <nss_dbdefs.h>
#include <pwd.h>
#include <sys/stat.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <sys/systeminfo.h>
#include <syslog.h>
#include <thread.h>
#include <unistd.h>
#include <adt_xlate.h>
#include <adt_ucred.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <libinetutil.h>

static int adt_selected(struct adt_event_state *, au_event_t, int);
static int adt_init(adt_internal_state_t *, int);
static int adt_import(adt_internal_state_t *, const adt_export_data_t *);
static m_label_t *adt_ucred_label(ucred_t *);
static void adt_setto_unaudited(adt_internal_state_t *);
static int adt_get_local_address(int, struct ifaddrlist *);

#ifdef C2_DEBUG
#define	DPRINTF(x) { (void) printf x; }
#define	DFLUSH (void) fflush(stdout);
#else
#define	DPRINTF(x)
#define	DFLUSH
#endif

/*
 * Local audit states are a bit mask
 *
 * The global audit states are
 *
 * AUC_UNSET             0      - on/off hasn't been decided
 * AUC_ENABLED           1      - loaded and enabled
 *
 * The local Zone states are
 *
 * AUC_AUDITING         0x1     - audit daemon is active
 * AUC_NOAUDIT          0x2     - audit daemon is not active
 * AUC_INIT_AUDIT       0x4     - audit is ready but auditd has not run
 * AUC_NOSPACE          0x8     - audit enabled, no space for audit records
 *
 * The only values returned by auditon(A_GETCOND) are:
 * AUC_INIT_AUDIT, AUC_AUDITING, AUC_NOAUDIT, AUC_NOSPACE
 *
 * The pseudo audit state used when the c2audit module is excluded is
 *
 * AUC_DISABLED		0x100	- c2audit module is excluded
 */

static int auditstate = AUC_DISABLED;	/* default state */

/*
 * adt_write_syslog
 *
 * errors that are not the user's fault (bugs or whatever in
 * the underlying audit code are noted in syslog.)
 *
 * Avoid calling adt_write_syslog for things that can happen
 * at high volume.
 *
 * syslog's open (openlog) and close (closelog) are interesting;
 * openlog *may* create a file descriptor and is optional.  closelog
 * *will* close any open file descriptors and is also optional.
 *
 * Since syslog may also be used by the calling application, the
 * choice is to avoid openlog, which sets some otherwise useful
 * parameters, and to embed "Solaris_audit" in the log message.
 */

void
adt_write_syslog(const char *message, int err)
{
	int	save_errno = errno;
	int	mask_priority;

	DPRINTF(("syslog called: %s\n", message));

	mask_priority = setlogmask(LOG_MASK(LOG_ALERT));
	errno = err;
	syslog(LOG_ALERT, "Solaris_audit %s: %m", message);
	(void) setlogmask(mask_priority);
	errno = save_errno;
}

/*
 * return true if c2audit is not excluded.
 *
 *	For purpose of this API, anything but AUC_DISABLED
 *	is enabled; however one never actually sees
 *	AUC_DISABLED since auditon returns ENOTSUP in that case.  Any
 *	auditon error is considered the same as ENOTSUP for our
 *	purpose.  auditstate is not changed by auditon if an error
 *	is returned.
 */

/*
 * XXX	this should probably be eliminated and adt_audit_state() replace it.
 *	All the legitimate uses	are to not fork a waiting process for
 *	process exit processing, as in su, login, dtlogin.  Other bogus
 *	users are zoneadmd and init.
 *	All but dtlogin are in ON, so we can do this without cross gate
 *	synchronization.
 *
 *	No longer used in adt.c.
 */

boolean_t
adt_audit_enabled(void)
{

	(void) auditon(A_GETCOND, (caddr_t)&auditstate, sizeof (auditstate));

	return (auditstate != AUC_DISABLED);
}

/*
 *	See adt_audit_enabled() for state discussions.
 *	The state parameter is a hedge until all the uses become clear.
 *	Likely if adt_audit_enabled is brought internal to this file,
 *	it could be modified to take one or more parameters to describe the
 *	state.
 */

boolean_t
adt_audit_state(int states)
{

	(void) auditon(A_GETCOND, (caddr_t)&auditstate, sizeof (auditstate));

	return ((auditstate & states) ? B_TRUE : B_FALSE);
}

/*
 * Get user_specific/non-attributable audit mask. This may be called even when
 * auditing is off.
 */

static int
adt_get_mask_from_user(uid_t uid, au_mask_t *mask)
{
	struct passwd	pwd;
	long		buff_sz;
	char		*pwd_buff;


	if (auditstate & AUC_DISABLED) {
		/* c2audit excluded */
		mask->am_success = 0;
		mask->am_failure = 0;
	} else if (uid <= MAXUID) {
		if ((buff_sz = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
			adt_write_syslog("couldn't determine maximum size of "
			    "password buffer", errno);
			return (-1);
		}
		if ((pwd_buff = calloc(1, (size_t)++buff_sz)) == NULL) {
			return (-1);
		}
		if (getpwuid_r(uid, &pwd, pwd_buff, (int)buff_sz) == NULL) {
			errno = EINVAL;	/* user doesn't exist */
			free(pwd_buff);
			return (-1);
		}
		if (au_user_mask(pwd.pw_name, mask)) {
			free(pwd_buff);
			errno = EFAULT; /* undetermined failure */
			return (-1);
		}
		free(pwd_buff);
	} else if (auditon(A_GETKMASK, (caddr_t)mask, sizeof (*mask)) == -1) {
			return (-1);
	}

	return (0);
}

/*
 * adt_get_unique_id -- generate a hopefully unique 32 bit value
 *
 * there will be a follow up to replace this with the use of /dev/random
 *
 * An MD5 hash is taken on a buffer of
 *     hostname . audit id . unix time . pid . count
 *
 * "count = noise++;" is subject to a race condition but I don't
 * see a need to put a lock around it.
 */

au_asid_t
adt_get_unique_id(au_id_t uid)
{
	char		hostname[MAXHOSTNAMELEN];
	union {
		au_id_t		v[4];
		unsigned char	obuff[128/8];
	} output;
	MD5_CTX	context;

	static int	noise = 0;

	int		count = noise++;
	time_t		timebits = time(NULL);
	pid_t		pidbits = getpid();
	au_asid_t	retval = 0;

	if (gethostname(hostname, MAXHOSTNAMELEN)) {
		adt_write_syslog("gethostname call failed", errno);
		(void) strncpy(hostname, "invalidHostName", MAXHOSTNAMELEN);
	}

	while (retval == 0) {  /* 0 is the only invalid result */
		MD5Init(&context);

		MD5Update(&context, (unsigned char *)hostname,
		    (unsigned int) strlen((const char *)hostname));

		MD5Update(&context, (unsigned char *) &uid, sizeof (uid_t));

		MD5Update(&context,
		    (unsigned char *) &timebits, sizeof (time_t));

		MD5Update(&context, (unsigned char *) &pidbits,
		    sizeof (pid_t));

		MD5Update(&context, (unsigned char *) &(count), sizeof (int));
		MD5Final(output.obuff, &context);

		retval = output.v[count % 4];
	}
	return (retval);
}

/*
 * the following "port" function deals with the following issues:
 *
 * 1    the kernel and ucred deal with a dev_t as a 64 bit value made
 *      up from a 32 bit major and 32 bit minor.
 * 2    User space deals with a dev_t as either the above 64 bit value
 *      or a 32 bit value made from a 14 bit major and an 18 bit minor.
 * 3    The various audit interfaces (except ucred) pass the 32 or
 *      64 bit version depending the architecture of the userspace
 *      application.  If you get a port value from ucred and pass it
 *      to the kernel via auditon(), it must be squeezed into a 32
 *      bit value because the kernel knows the userspace app's bit
 *      size.
 *
 * The internal state structure for adt (adt_internal_state_t) uses
 * dev_t, so adt converts data from ucred to fit.  The import/export
 * functions, however, can't know if they are importing/exporting
 * from 64 or 32 bit applications, so they always send 64 bits and
 * the 32 bit end(s) are responsible to convert 32 -> 64 -> 32 as
 * appropriate.
 */

/*
 * adt_cpy_tid() -- if lib is 64 bit, just copy it (dev_t and port are
 * both 64 bits).  If lib is 32 bits, squeeze the two-int port into
 * a 32 bit dev_t.  A port fits in the "minor" part of au_port_t,
 * so it isn't broken up into pieces.  (When it goes to the kernel
 * and back, however, it will have been split into major/minor
 * pieces.)
 */

static void
adt_cpy_tid(au_tid_addr_t *dest, const au_tid64_addr_t *src)
{
#ifdef _LP64
	(void) memcpy(dest, src, sizeof (au_tid_addr_t));
#else	/* _LP64 */
	dest->at_type = src->at_type;

	dest->at_port  = src->at_port.at_minor & MAXMIN32;
	dest->at_port |= (src->at_port.at_major & MAXMAJ32) <<
	    NBITSMINOR32;

	(void) memcpy(dest->at_addr, src->at_addr, 4 * sizeof (uint32_t));
#endif	/* _LP64 */
}

/*
 * adt_start_session -- create interface handle, create context
 *
 * The imported_state input is normally NULL, if not, it represents
 * a continued session; its values obviate the need for a subsequent
 * call to adt_set_user().
 *
 * The flag is used to decide how to set the initial state of the session.
 * If 0, the session is "no audit" until a call to adt_set_user; if
 * ADT_USE_PROC_DATA, the session is built from the process audit
 * characteristics obtained from the kernel.  If imported_state is
 * not NULL, the resulting audit mask is an OR of the current process
 * audit mask and that passed in.
 *
 * The basic model is that the caller can use the pointer returned
 * by adt_start_session whether or not auditing is enabled or an
 * error was returned.  The functions that take the session handle
 * as input generally return without doing anything if auditing is
 * disabled.
 */

int
adt_start_session(adt_session_data_t **new_session,
    const adt_export_data_t *imported_state, adt_session_flags_t flags)
{
	adt_internal_state_t	*state;
	adt_session_flags_t	flgmask = ADT_FLAGS_ALL;

	/* test and set auditstate */
	if (adt_audit_state(AUC_DISABLED)) {
		/* c2audit excluded */
		*new_session = NULL;
		return (0);
	}

	if ((flags & ~flgmask) != 0) {
		errno = EINVAL;
		goto return_err;
	}

	if ((state = calloc(1, sizeof (adt_internal_state_t))) == NULL) {
		goto return_err;
	}

	if (adt_init(state, flags & ADT_USE_PROC_DATA) != 0) {
		goto return_err_free;    /* errno from adt_init() */
	}

	/*
	 * The imported state overwrites the initial state if the
	 * imported state represents a valid audit trail
	 */

	if (imported_state != NULL) {
		if (adt_import(state, imported_state) != 0) {
			goto return_err_free;
		}
	} else if (flags & ADT_USE_PROC_DATA) {
		state->as_session_model = ADT_PROCESS_MODEL;
	}
	state->as_flags = flags;
	DPRINTF(("(%lld) Starting session id = %08X\n",
	    (long long) getpid(), state->as_info.ai_asid));

	*new_session = (adt_session_data_t *)state;
	return (0);

return_err_free:
	free(state);
return_err:
	*new_session = NULL;
	adt_write_syslog("audit session create failed", errno);
	return (-1);
}

/*
 * adt_load_table()
 *
 * loads the event translation table into the audit session.
 */

void
adt_load_table(const adt_session_data_t *session_data,
    adt_translation_t **xlate, void (*preload)(au_event_t, adt_event_data_t *))
{
	adt_internal_state_t	*state = (adt_internal_state_t *)session_data;

	if (state != NULL) {
		assert(state->as_check == ADT_VALID);
		state->as_xlate = xlate;
		state->as_preload = preload;
	}
}

/*
 * adt_get_asid() and adt_set_asid()
 *
 * if you use this interface, you are responsible to insure that the
 * rest of the session data is populated correctly before calling
 * adt_proccess_attr()
 *
 * neither of these are intended for general use and will likely
 * remain private interfaces for a long time.  Forever is a long
 * time.  In the case of adt_set_asid(), you should have a very,
 * very good reason for setting your own session id.  The process
 * audit characteristics are not changed by put, use adt_set_proc().
 *
 * These are "volatile" (more changable than "evolving") and will
 * probably change in the S10 period.
 */

void
adt_get_asid(const adt_session_data_t *session_data, au_asid_t *asid)
{

	if (session_data == NULL) {
		*asid = 0;
	} else {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		*asid = ((adt_internal_state_t *)session_data)->as_info.ai_asid;
	}
}

void
adt_set_asid(const adt_session_data_t *session_data, const au_asid_t session_id)
{

	if (session_data != NULL) {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		((adt_internal_state_t *)session_data)->as_have_user_data |=
		    ADT_HAVE_ASID;
		((adt_internal_state_t *)session_data)->as_info.ai_asid =
		    session_id;
	}
}

/*
 * adt_get_auid() and adt_set_auid()
 *
 * neither of these are intended for general use and will likely
 * remain private interfaces for a long time.  Forever is a long
 * time.  In the case of adt_set_auid(), you should have a very,
 * very good reason for setting your own audit id.  The process
 * audit characteristics are not changed by put, use adt_set_proc().
 */

void
adt_get_auid(const adt_session_data_t *session_data, au_id_t *auid)
{

	if (session_data == NULL) {
		*auid = AU_NOAUDITID;
	} else {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		*auid = ((adt_internal_state_t *)session_data)->as_info.ai_auid;
	}
}

void
adt_set_auid(const adt_session_data_t *session_data, const au_id_t audit_id)
{

	if (session_data != NULL) {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		((adt_internal_state_t *)session_data)->as_have_user_data |=
		    ADT_HAVE_AUID;
		((adt_internal_state_t *)session_data)->as_info.ai_auid =
		    audit_id;
	}
}

/*
 * adt_get_termid(), adt_set_termid()
 *
 * if you use this interface, you are responsible to insure that the
 * rest of the session data is populated correctly before calling
 * adt_proccess_attr()
 *
 * The process  audit characteristics are not changed by put, use
 * adt_set_proc().
 */

void
adt_get_termid(const adt_session_data_t *session_data, au_tid_addr_t *termid)
{

	if (session_data == NULL) {
		(void) memset(termid, 0, sizeof (au_tid_addr_t));
		termid->at_type = AU_IPv4;
	} else {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		*termid =
		    ((adt_internal_state_t *)session_data)->as_info.ai_termid;
	}
}

void
adt_set_termid(const adt_session_data_t *session_data,
    const au_tid_addr_t *termid)
{

	if (session_data != NULL) {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		((adt_internal_state_t *)session_data)->as_info.ai_termid =
		    *termid;

		((adt_internal_state_t *)session_data)->as_have_user_data |=
		    ADT_HAVE_TID;
	}
}

/*
 * adt_get_mask(), adt_set_mask()
 *
 * if you use this interface, you are responsible to insure that the
 * rest of the session data is populated correctly before calling
 * adt_proccess_attr()
 *
 * The process  audit characteristics are not changed by put, use
 * adt_set_proc().
 */

void
adt_get_mask(const adt_session_data_t *session_data, au_mask_t *mask)
{

	if (session_data == NULL) {
		mask->am_success = 0;
		mask->am_failure = 0;
	} else {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		*mask = ((adt_internal_state_t *)session_data)->as_info.ai_mask;
	}
}

void
adt_set_mask(const adt_session_data_t *session_data, const au_mask_t *mask)
{

	if (session_data != NULL) {
		assert(((adt_internal_state_t *)session_data)->as_check ==
		    ADT_VALID);

		((adt_internal_state_t *)session_data)->as_info.ai_mask = *mask;

		((adt_internal_state_t *)session_data)->as_have_user_data |=
		    ADT_HAVE_MASK;
	}
}

/*
 * helpers for adt_load_termid
 */

static void
adt_do_ipv6_address(struct sockaddr_in6 *peer, struct sockaddr_in6 *sock,
    au_tid_addr_t *termid)
{

	termid->at_port = ((peer->sin6_port<<16) | (sock->sin6_port));
	termid->at_type = AU_IPv6;
	(void) memcpy(termid->at_addr, &peer->sin6_addr, 4 * sizeof (uint_t));
}

static void
adt_do_ipv4_address(struct sockaddr_in *peer, struct sockaddr_in *sock,
    au_tid_addr_t *termid)
{

	termid->at_port = ((peer->sin_port<<16) | (sock->sin_port));

	termid->at_type = AU_IPv4;
	termid->at_addr[0] = (uint32_t)peer->sin_addr.s_addr;
	(void) memset(&(termid->at_addr[1]), 0, 3 * sizeof (uint_t));
}

/*
 * adt_load_termid:  convenience function; inputs file handle and
 * outputs an au_tid_addr struct.
 *
 * This code was stolen from audit_settid.c; it differs from audit_settid()
 * in that it does not write the terminal id to the process.
 */

int
adt_load_termid(int fd, adt_termid_t **termid)
{
	au_tid_addr_t		*p_term;
	struct sockaddr_in6	peer;
	struct sockaddr_in6	sock;
	int			peerlen = sizeof (peer);
	int			socklen = sizeof (sock);

	/* get peer name if its a socket, else assume local terminal */

	if (getpeername(fd, (struct sockaddr *)&peer, (socklen_t *)&peerlen)
	    < 0) {
		if (errno == ENOTSOCK) {
			return (adt_load_hostname(NULL, termid));
		}
		goto return_err;
	}

	if ((p_term = calloc(1, sizeof (au_tid_addr_t))) == NULL) {
		goto return_err;
	}

	/* get sock name */
	if (getsockname(fd, (struct sockaddr *)&sock,
	    (socklen_t *)&socklen) < 0) {
		goto return_err_free;
	}

	if (peer.sin6_family == AF_INET6) {
		adt_do_ipv6_address(&peer, &sock, p_term);
	} else {
		adt_do_ipv4_address((struct sockaddr_in *)&peer,
		    (struct sockaddr_in *)&sock, p_term);
	}
	*termid = (adt_termid_t *)p_term;

	return (0);

return_err_free:
	free(p_term);
return_err:
	*termid = NULL;
	return (-1);
}

static boolean_t
adt_have_termid(au_tid_addr_t *dest)
{
	struct auditinfo_addr	audit_data;

	if (getaudit_addr(&audit_data, sizeof (audit_data)) < 0) {
		adt_write_syslog("getaudit failed", errno);
		return (B_FALSE);
	}

	if ((audit_data.ai_termid.at_type == 0) ||
	    (audit_data.ai_termid.at_addr[0] |
	    audit_data.ai_termid.at_addr[1]  |
	    audit_data.ai_termid.at_addr[2]  |
	    audit_data.ai_termid.at_addr[3]) == 0)
		return (B_FALSE);

	(void) memcpy(dest, &(audit_data.ai_termid),
	    sizeof (au_tid_addr_t));

	return (B_TRUE);
}

/*
 * adt_get_hostIP - construct a terminal id from a hostname
 *
 *	Returns	 0 = success
 *		-1 = failure and errno = ENETDOWN with the address
 *		     defaulted to IPv4 loopback.
 */

static int
adt_get_hostIP(const char *hostname, au_tid_addr_t *p_term)
{
	struct addrinfo	*ai = NULL;
	int	tries = 3;
	char	msg[512];
	int	eai_err;

	while ((tries-- > 0) &&
	    ((eai_err = getaddrinfo(hostname, NULL, NULL, &ai)) != 0)) {
		/*
		 * getaddrinfo returns its own set of errors.
		 * Log them here, so any subsequent syslogs will
		 * have a context.  adt_get_hostIP callers can only
		 * return errno, so subsequent syslogs may be lacking
		 * that getaddrinfo failed.
		 */
		(void) snprintf(msg, sizeof (msg), "getaddrinfo(%s) "
		    "failed[%s]", hostname, gai_strerror(eai_err));
		adt_write_syslog(msg, 0);

		if (eai_err != EAI_AGAIN) {

			break;
		}
		/* see if resolution becomes available */
		(void) sleep(1);
	}
	if (ai != NULL) {
		if (ai->ai_family == AF_INET) {
			p_term->at_type = AU_IPv4;
			(void) memcpy(p_term->at_addr,
			    /* LINTED */
			    &((struct sockaddr_in *)ai->ai_addr)->sin_addr,
			    AU_IPv4);
		} else {
			p_term->at_type = AU_IPv6;
			(void) memcpy(p_term->at_addr,
			    /* LINTED */
			    &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
			    AU_IPv6);
		}
		freeaddrinfo(ai);
		return (0);
	} else if (auditstate & (AUC_AUDITING | AUC_NOSPACE)) {
		auditinfo_addr_t  audit_info;

		/*
		 * auditd is running so there should be a
		 * kernel audit context
		 */
		if (auditon(A_GETKAUDIT, (caddr_t)&audit_info,
		    sizeof (audit_info)) < 0) {
			adt_write_syslog("unable to get kernel audit context",
			    errno);
			goto try_interface;
		}
		adt_write_syslog("setting Audit IP address to kernel", 0);
		*p_term = audit_info.ai_termid;
		return (0);
	}
try_interface:
	{
		struct ifaddrlist al;
		int	family;
		char	ntop[INET6_ADDRSTRLEN];

		/*
		 * getaddrinfo has failed to map the hostname
		 * to an IP address, try to get an IP address
		 * from a local interface.  If none up, default
		 * to loopback.
		 */
		family = AF_INET6;
		if (adt_get_local_address(family, &al) != 0) {
			family = AF_INET;

			if (adt_get_local_address(family, &al) != 0) {
				adt_write_syslog("adt_get_local_address "
				    "failed, no Audit IP address available, "
				    "faking loopback and error",
				    errno);
				IN_SET_LOOPBACK_ADDR(
				    (struct sockaddr_in *)&(al.addr.addr));
				(void) memcpy(p_term->at_addr, &al.addr.addr,
				    AU_IPv4);
				p_term->at_type = AU_IPv4;
				return (-1);
			}
		}
		if (family == AF_INET) {
			p_term->at_type = AU_IPv4;
			(void) memcpy(p_term->at_addr, &al.addr.addr, AU_IPv4);
		} else {
			p_term->at_type = AU_IPv6;
			(void) memcpy(p_term->at_addr, &al.addr.addr6, AU_IPv6);
		}

		(void) snprintf(msg, sizeof (msg), "mapping %s to %s",
		    hostname, inet_ntop(family, &(al.addr), ntop,
		    sizeof (ntop)));
		adt_write_syslog(msg, 0);
		return (0);
	}
}

/*
 * adt_load_hostname() is called when the caller does not have a file
 * handle that gives access to the socket info or any other way to
 * pass in both port and ip address.  The hostname input is ignored if
 * the terminal id has already been set; instead it returns the
 * existing terminal id.
 *
 * If c2audit is excluded, success is returned.
 * If the hostname lookup fails, the loopback address is assumed,
 * errno is set to ENETDOWN, this allows the caller to interpret
 * whether failure is fatal, and if not to have a address for the
 * hostname.
 * Otherwise the caller would need to be aware of the audit state.
 *
 * Other errors are ignored if not auditing.
 */

int
adt_load_hostname(const char *hostname, adt_termid_t **termid)
{
	char		localhost[MAXHOSTNAMELEN + 1];
	au_tid_addr_t	*p_term;

	if (adt_audit_state(AUC_DISABLED)) {
		/* c2audit excluded */
		*termid = NULL;
		return (0);
	}

	if ((p_term = calloc(1, sizeof (au_tid_addr_t))) == NULL) {
		goto return_err;
	}

	if (adt_have_termid(p_term)) {
		*termid = (adt_termid_t *)p_term;
		return (0);
	}
	p_term->at_port = 0;

	if (hostname == NULL || *hostname == '\0') {
		(void) sysinfo(SI_HOSTNAME, localhost, MAXHOSTNAMELEN);
		hostname = localhost;
	}
	if (adt_get_hostIP(hostname, p_term) == 0) {
		*termid = (adt_termid_t *)p_term;
		return (0);
	} else {
		*termid = (adt_termid_t *)p_term;
		return (-1);
	}

return_err:
	*termid = NULL;
	if (auditstate & AUC_NOAUDIT) {
		return (0);
	}

	return (-1);
}

/*
 * adt_load_ttyname() is called when the caller does not have a file
 * handle that gives access to the local terminal or any other way
 * of determining the device id.  The ttyname input is ignored if
 * the terminal id has already been set; instead it returns the
 * existing terminal id.
 *
 * If c2audit is excluded, success is returned.
 * The local hostname is used for the local IP address.
 * If that hostname lookup fails, the loopback address is assumed,
 * errno is set to ENETDOWN, this allows the caller to interpret
 * whether failure is fatal, and if not to have a address for the
 * hostname.
 * Otherwise the caller would need to be aware of the audit state.
 *
 * Other errors are ignored if not auditing.
 */

int
adt_load_ttyname(const char *ttyname, adt_termid_t **termid)
{
	char		localhost[MAXHOSTNAMELEN + 1];
	au_tid_addr_t	*p_term;
	struct stat	stat_buf;

	if (adt_audit_state(AUC_DISABLED)) {
		/* c2audit excluded */
		*termid = NULL;
		return (0);
	}

	if ((p_term = calloc(1, sizeof (au_tid_addr_t))) == NULL) {
		goto return_err;
	}

	if (adt_have_termid(p_term)) {
		*termid = (adt_termid_t *)p_term;
		return (0);
	}

	p_term->at_port = 0;

	if (sysinfo(SI_HOSTNAME, localhost, MAXHOSTNAMELEN) < 0) {
		goto return_err_free; /* errno from sysinfo */
	}

	if (ttyname != NULL && *ttyname != '\0') {
		if (stat(ttyname, &stat_buf) < 0) {
			goto return_err_free;
		}

		p_term->at_port = stat_buf.st_rdev;
	}

	if (adt_get_hostIP(localhost, p_term) == 0) {
		*termid = (adt_termid_t *)p_term;
		return (0);
	} else {
		*termid = (adt_termid_t *)p_term;
		return (-1);
	}

return_err_free:
	free(p_term);

return_err:
	*termid = NULL;
	if (auditstate & AUC_NOAUDIT) {
		return (0);
	}

	return (-1);
}

/*
 * adt_get_session_id returns a stringified representation of
 * the audit session id.  See also adt_get_asid() for how to
 * get the unexpurgated version.  No guarantees as to how long
 * the returned string will be or its general form; hex for now.
 *
 * An empty string is returned if auditing is off; length = 1
 * and the pointer is valid.
 *
 * returns strlen + 1 if buffer is valid; else 0 and errno.
 */

size_t
adt_get_session_id(const adt_session_data_t *session_data, char **buff)
{
	au_asid_t	session_id;
	size_t		length;
	/*
	 * output is 0x followed by
	 * two characters per byte
	 * plus terminator,
	 * except leading 0's are suppressed, so a few bytes may
	 * be unused.
	 */
	length = 2 + (2 * sizeof (session_id)) + 1;
	*buff = malloc(length);

	if (*buff == NULL) {
		return (0);
	}
	if (session_data == NULL) { /* NULL is not an error */
		**buff = '\0';
		return (1);
	}
	adt_get_asid(session_data, &session_id);

	length = snprintf(*buff, length, "0x%X", (int)session_id);

	/* length < 1 is a bug: the session data type may have changed */
	assert(length > 0);

	return (length);
}

/*
 * adt_end_session -- close handle, clear context
 *
 * if as_check is invalid, no harm, no foul, EXCEPT that this could
 * be an attempt to free data already free'd, so output to syslog
 * to help explain why the process cored dumped.
 */

int
adt_end_session(adt_session_data_t *session_data)
{
	adt_internal_state_t	*state;

	if (session_data != NULL) {
		state = (adt_internal_state_t *)session_data;
		if (state->as_check != ADT_VALID) {
			adt_write_syslog("freeing invalid data", EINVAL);
		} else {
			state->as_check = 0;
			m_label_free(state->as_label);
			free(session_data);
		}
	}
	/* no errors yet defined */
	return (0);
}

/*
 * adt_dup_session -- copy the session data
 */

int
adt_dup_session(const adt_session_data_t *source, adt_session_data_t **dest)
{
	adt_internal_state_t	*source_state;
	adt_internal_state_t	*dest_state = NULL;
	int			rc = 0;

	if (source != NULL) {
		source_state = (adt_internal_state_t *)source;
		assert(source_state->as_check == ADT_VALID);

		dest_state = malloc(sizeof (adt_internal_state_t));
		if (dest_state == NULL) {
			rc = -1;
			goto return_rc;
		}
		(void) memcpy(dest_state, source,
		    sizeof (struct adt_internal_state));

		if (source_state->as_label != NULL) {
			dest_state->as_label = NULL;
			if ((rc = m_label_dup(&dest_state->as_label,
			    source_state->as_label)) != 0) {
				free(dest_state);
				dest_state = NULL;
			}
		}
	}
return_rc:
	*dest = (adt_session_data_t *)dest_state;
	return (rc);
}

/*
 * from_export_format()
 * read from a network order buffer into struct adt_session_data
 */

static size_t
adt_from_export_format(adt_internal_state_t *internal,
    const adt_export_data_t *external)
{
	struct export_header	head;
	struct export_link	link;
	adr_t			context;
	int32_t 		offset;
	int32_t 		length;
	int32_t 		version;
	size_t			label_len;
	char			*p = (char *)external;

	adrm_start(&context, (char *)external);
	adrm_int32(&context, (int *)&head, 4);

	if ((internal->as_check = head.ax_check) != ADT_VALID) {
		errno = EINVAL;
		return (0);
	}
	offset = head.ax_link.ax_offset;
	version = head.ax_link.ax_version;
	length = head.ax_buffer_length;

	/*
	 * Skip newer versions.
	 */
	while (version > PROTOCOL_VERSION_2) {
		if (offset < 1) {
			return (0);	/* failed to match version */
		}
		p += offset;		/* point to next version # */

		if (p > (char *)external + length) {
			return (0);
		}
		adrm_start(&context, p);
		adrm_int32(&context, (int *)&link, 2);
		offset = link.ax_offset;
		version = link.ax_version;
		assert(version != 0);
	}
	/*
	 * Adjust buffer pointer to the first data item (euid).
	 */
	if (p == (char *)external) {
		adrm_start(&context, (char *)(p + sizeof (head)));
	} else {
		adrm_start(&context, (char *)(p + sizeof (link)));
	}
	/*
	 * if down rev version, neither pid nor label are included
	 * in v1 ax_size_of_tsol_data intentionally ignored
	 */
	if (version == PROTOCOL_VERSION_1) {
		adrm_int32(&context, (int *)&(internal->as_euid), 1);
		adrm_int32(&context, (int *)&(internal->as_ruid), 1);
		adrm_int32(&context, (int *)&(internal->as_egid), 1);
		adrm_int32(&context, (int *)&(internal->as_rgid), 1);
		adrm_int32(&context, (int *)&(internal->as_info.ai_auid), 1);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_mask.am_success), 2);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_termid.at_port), 1);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_termid.at_type), 1);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_termid.at_addr[0]), 4);
		adrm_int32(&context, (int *)&(internal->as_info.ai_asid), 1);
		adrm_int32(&context, (int *)&(internal->as_audit_state), 1);
		internal->as_pid = (pid_t)-1;
		internal->as_label = NULL;
	} else if (version == PROTOCOL_VERSION_2) {
		adrm_int32(&context, (int *)&(internal->as_euid), 1);
		adrm_int32(&context, (int *)&(internal->as_ruid), 1);
		adrm_int32(&context, (int *)&(internal->as_egid), 1);
		adrm_int32(&context, (int *)&(internal->as_rgid), 1);
		adrm_int32(&context, (int *)&(internal->as_info.ai_auid), 1);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_mask.am_success), 2);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_termid.at_port), 1);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_termid.at_type), 1);
		adrm_int32(&context,
		    (int *)&(internal->as_info.ai_termid.at_addr[0]), 4);
		adrm_int32(&context, (int *)&(internal->as_info.ai_asid), 1);
		adrm_int32(&context, (int *)&(internal->as_audit_state), 1);
		adrm_int32(&context, (int *)&(internal->as_pid), 1);
		adrm_int32(&context, (int *)&label_len, 1);
		if (label_len > 0) {
			/* read in and deal with different sized labels. */
			size32_t my_label_len = blabel_size();

			if ((internal->as_label =
			    m_label_alloc(MAC_LABEL)) == NULL) {
				return (0);
			}
			if (label_len > my_label_len) {
				errno = EINVAL;
				m_label_free(internal->as_label);
				return (0);
			}
			(void) memset(internal->as_label, 0, my_label_len);
			adrm_int32(&context, (int *)(internal->as_label),
			    label_len / sizeof (int32_t));
		} else {
			internal->as_label = NULL;
		}
	}

	return (length);
}

/*
 * adt_to_export_format
 * read from struct adt_session_data into a network order buffer.
 *
 * (network order 'cause this data may be shared with a remote host.)
 */

static size_t
adt_to_export_format(adt_export_data_t *external,
    adt_internal_state_t *internal)
{
	struct export_header	head;
	struct export_link	tail;
	adr_t			context;
	size32_t		label_len = 0;

	adrm_start(&context, (char *)external);

	if (internal->as_label != NULL) {
		label_len = blabel_size();
	}

	head.ax_check = ADT_VALID;
	head.ax_buffer_length = sizeof (struct adt_export_data) + label_len;

	/* version 2 first */

	head.ax_link.ax_version = PROTOCOL_VERSION_2;
	head.ax_link.ax_offset = sizeof (struct export_header) +
	    sizeof (struct adt_export_v2) + label_len;

	adrm_putint32(&context, (int *)&head, 4);

	adrm_putint32(&context, (int *)&(internal->as_euid), 1);
	adrm_putint32(&context, (int *)&(internal->as_ruid), 1);
	adrm_putint32(&context, (int *)&(internal->as_egid), 1);
	adrm_putint32(&context, (int *)&(internal->as_rgid), 1);
	adrm_putint32(&context, (int *)&(internal->as_info.ai_auid), 1);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_mask.am_success), 2);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_termid.at_port), 1);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_termid.at_type), 1);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_termid.at_addr[0]), 4);
	adrm_putint32(&context, (int *)&(internal->as_info.ai_asid), 1);
	adrm_putint32(&context, (int *)&(internal->as_audit_state), 1);
	adrm_putint32(&context, (int *)&(internal->as_pid), 1);
	adrm_putint32(&context, (int *)&label_len, 1);
	if (internal->as_label != NULL) {
		/* serialize the label */
		adrm_putint32(&context, (int *)(internal->as_label),
		    (label_len / sizeof (int32_t)));
	}

	/* now version 1 */

	tail.ax_version = PROTOCOL_VERSION_1;
	tail.ax_offset = 0;

	adrm_putint32(&context, (int *)&tail, 2);

	adrm_putint32(&context, (int *)&(internal->as_euid), 1);
	adrm_putint32(&context, (int *)&(internal->as_ruid), 1);
	adrm_putint32(&context, (int *)&(internal->as_egid), 1);
	adrm_putint32(&context, (int *)&(internal->as_rgid), 1);
	adrm_putint32(&context, (int *)&(internal->as_info.ai_auid), 1);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_mask.am_success), 2);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_termid.at_port), 1);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_termid.at_type), 1);
	adrm_putint32(&context,
	    (int *)&(internal->as_info.ai_termid.at_addr[0]), 4);
	adrm_putint32(&context, (int *)&(internal->as_info.ai_asid), 1);
	adrm_putint32(&context, (int *)&(internal->as_audit_state), 1);
	/* ignored in v1 */
	adrm_putint32(&context, (int *)&label_len, 1);

	/* finally terminator */

	tail.ax_version = 0; /* invalid version number */
	tail.ax_offset = 0;

	adrm_putint32(&context, (int *)&tail, 2);

	return (head.ax_buffer_length);
}

/*
 * adt_ucred_label() -- if label is available, duplicate it.
 */

static m_label_t *
adt_ucred_label(ucred_t *uc)
{
	m_label_t	*ul = NULL;

	if (ucred_getlabel(uc) != NULL) {
		(void) m_label_dup(&ul, ucred_getlabel(uc));
	}

	return (ul);
}

/*
 * adt_import() -- convert from network order to machine-specific order
 */

static int
adt_import(adt_internal_state_t *internal, const adt_export_data_t *external)
{
	au_mask_t mask;

	/* save local audit state */
	int	local_audit_state = internal->as_audit_state;

	if (adt_from_export_format(internal, external) < 1)
		return (-1); /* errno from adt_from_export_format */

	/*
	 * If audit isn't enabled on the remote, they were unable
	 * to generate the audit mask, so generate it based on
	 * local configuration.  If the user id has changed, the
	 * resulting mask may miss some subtleties that occurred
	 * on the remote system.
	 *
	 * If the remote failed to generate a terminal id, it is not
	 * recoverable.
	 */

	if (!(internal->as_audit_state & AUC_DISABLED)) {
		if (adt_get_mask_from_user(internal->as_info.ai_auid,
		    &(internal->as_info.ai_mask)))
			return (-1);
		if (internal->as_info.ai_auid != internal->as_ruid) {
			if (adt_get_mask_from_user(internal->as_info.ai_auid,
			    &mask))
				return (-1);
			internal->as_info.ai_mask.am_success |=
			    mask.am_success;
			internal->as_info.ai_mask.am_failure |=
			    mask.am_failure;
		}
	}
	internal->as_audit_state = local_audit_state;

	DPRINTF(("(%lld)imported asid = %X %u\n", (long long) getpid(),
	    internal->as_info.ai_asid,
	    internal->as_info.ai_asid));

	internal->as_have_user_data = ADT_HAVE_ALL;

	return (0);
}

/*
 * adt_export_session_data()
 * copies a adt_session_data struct into a network order buffer
 *
 * In a misconfigured network, the local host may have auditing
 * off while the destination may have auditing on, so if there
 * is sufficient memory, a buffer will be returned even in the
 * audit off case.
 */

size_t
adt_export_session_data(const adt_session_data_t *internal,
    adt_export_data_t **external)
{
	size32_t		length = 0;

	if ((internal != NULL) &&
	    ((adt_internal_state_t *)internal)->as_label != NULL) {
		length = blabel_size();
	}

	*external = malloc(sizeof (adt_export_data_t) + length);

	if (*external == NULL)
		return (0);

	if (internal == NULL) {
		adt_internal_state_t	*dummy;

		dummy = malloc(sizeof (adt_internal_state_t));
		if (dummy == NULL)
			goto return_length_free;

		if (adt_init(dummy, 0)) { /* 0 == don't copy from proc */
			free(dummy);
			goto return_length_free;
		}
		length = adt_to_export_format(*external, dummy);
		free(dummy);
	} else {
		length = adt_to_export_format(*external,
		    (adt_internal_state_t *)internal);
	}
	return (length);

return_length_free:
	free(*external);
	*external = NULL;
	return (0);
}

static void
adt_setto_unaudited(adt_internal_state_t *state)
{
	if (state->as_audit_state & AUC_DISABLED) {
		state->as_ruid = AU_NOAUDITID;
		state->as_euid = AU_NOAUDITID;
		state->as_rgid = AU_NOAUDITID;
		state->as_egid = AU_NOAUDITID;
		state->as_pid = (pid_t)-1;
		state->as_label = NULL;
	} else {
		state->as_info.ai_asid = 0;
		state->as_info.ai_auid = AU_NOAUDITID;

		(void) memset((void *)&(state->as_info.ai_termid), 0,
		    sizeof (au_tid_addr_t));
		state->as_info.ai_termid.at_type = AU_IPv4;

		(void) memset((void *)&(state->as_info.ai_mask), 0,
		    sizeof (au_mask_t));
		state->as_have_user_data = 0;
	}
}

/*
 * adt_init -- set session context by copying the audit characteristics
 * from the proc and picking up current uid/tid information.
 *
 * By default, an audit session is based on the process; the default
 * is overriden by adt_set_user()
 */

static int
adt_init(adt_internal_state_t *state, int use_proc_data)
{
	/* ensure auditstate is set */

	(void) adt_audit_state(0);
	state->as_audit_state = auditstate;

	if (use_proc_data) {
		state->as_ruid = getuid();
		state->as_euid = geteuid();
		state->as_rgid = getgid();
		state->as_egid = getegid();
		state->as_pid = getpid();

		if (!(state->as_audit_state & AUC_DISABLED)) {
			const au_tid64_addr_t	*tid;
			const au_mask_t		*mask;
			ucred_t			*ucred = ucred_get(P_MYID);

			/*
			 * Even if the ucred is NULL, the underlying
			 * credential may have a valid terminal id; if the
			 * terminal id is set, then that's good enough.  An
			 * example of where this matters is failed login,
			 * where rlogin/telnet sets the terminal id before
			 * calling login; login does not load the credential
			 * since auth failed.
			 */
			if (ucred == NULL) {
				if (!adt_have_termid(
				    &(state->as_info.ai_termid)))
					return (-1);
			} else {
				mask = ucred_getamask(ucred);
				if (mask != NULL) {
					state->as_info.ai_mask = *mask;
				} else {
					ucred_free(ucred);
					return (-1);
				}
				tid = ucred_getatid(ucred);
				if (tid != NULL) {
					adt_cpy_tid(&(state->as_info.ai_termid),
					    tid);
				} else {
					ucred_free(ucred);
					return (-1);
				}
				state->as_info.ai_asid = ucred_getasid(ucred);
				state->as_info.ai_auid = ucred_getauid(ucred);
				state->as_label = adt_ucred_label(ucred);
				ucred_free(ucred);
			}
			state->as_have_user_data = ADT_HAVE_ALL;
		}
	} else {
		adt_setto_unaudited(state);
	}
	state->as_session_model = ADT_SESSION_MODEL;	/* default */

	if ((state->as_audit_state & (AUC_AUDITING | AUC_NOSPACE)) &&
	    auditon(A_GETPOLICY, (caddr_t)&(state->as_kernel_audit_policy),
	    sizeof (state->as_kernel_audit_policy))) {
		return (-1);  /* errno set by auditon */
	}
	state->as_check = ADT_VALID;
	adt_load_table((adt_session_data_t *)state, &adt_xlate_table[0],
	    &adt_preload);
	return (0);
}

/*
 * adt_set_proc
 *
 * Copy the current session state to the process.  If this function
 * is called, the model becomes a process model rather than a
 * session model.
 *
 * In the current implementation, the value state->as_have_user_data
 * must contain all of: ADT_HAVE_{AUID,MASK,TID,ASID}.  These are all set
 * by adt_set_user() when the ADT_SETTID or ADT_NEW flag is passed in.
 *
 */

int
adt_set_proc(const adt_session_data_t *session_data)
{
	adt_internal_state_t	*state;

	if (session_data == NULL) {
		return (0);
	}

	state = (adt_internal_state_t *)session_data;

	assert(state->as_check == ADT_VALID);

	if ((state->as_have_user_data & (ADT_HAVE_ALL & ~ADT_HAVE_IDS)) !=
	    (ADT_HAVE_ALL & ~ADT_HAVE_IDS)) {
		errno = EINVAL;
		goto return_err;
	}

	if (setaudit_addr((auditinfo_addr_t *)&(state->as_info),
	    sizeof (auditinfo_addr_t)) < 0) {
		goto return_err;	/* errno set by setaudit_addr() */
	}

	state->as_session_model = ADT_PROCESS_MODEL;

	return (0);

return_err:
	adt_write_syslog("failed to set process audit characteristics", errno);
	return (-1);
}

static int
adt_newuser(adt_internal_state_t *state, uid_t ruid, au_tid_addr_t *termid)
{
	au_tid_addr_t	no_tid = {0, AU_IPv4, 0, 0, 0, 0};
	au_mask_t	no_mask = {0, 0};

	if (ruid == ADT_NO_AUDIT) {
		state->as_info.ai_auid = AU_NOAUDITID;
		state->as_info.ai_asid = 0;
		state->as_info.ai_termid = no_tid;
		state->as_info.ai_mask = no_mask;
		return (0);
	}
	state->as_info.ai_auid = ruid;
	state->as_info.ai_asid = adt_get_unique_id(ruid);
	if (termid != NULL)
		state->as_info.ai_termid = *termid;

	if (adt_get_mask_from_user(ruid, &(state->as_info.ai_mask)))
		return (-1);

	/* Assume intending to audit as this process */

	if (state->as_pid == (pid_t)-1)
		state->as_pid = getpid();

	if (is_system_labeled() && state->as_label == NULL) {
		ucred_t	*ucred = ucred_get(P_MYID);

		state->as_label = adt_ucred_label(ucred);
		ucred_free(ucred);
	}

	return (0);
}

static int
adt_changeuser(adt_internal_state_t *state, uid_t ruid)
{
	au_mask_t		mask;

	if (!(state->as_have_user_data & ADT_HAVE_AUID))
		state->as_info.ai_auid = ruid;
	if (!(state->as_have_user_data & ADT_HAVE_ASID))
		state->as_info.ai_asid = adt_get_unique_id(ruid);

	if (ruid <= MAXEPHUID) {
		if (adt_get_mask_from_user(ruid, &mask))
			return (-1);

		state->as_info.ai_mask.am_success |= mask.am_success;
		state->as_info.ai_mask.am_failure |= mask.am_failure;
	}
	DPRINTF(("changed mask to %08X/%08X for ruid=%d\n",
	    state->as_info.ai_mask.am_success,
	    state->as_info.ai_mask.am_failure,
	    ruid));
	return (0);
}

/*
 * adt_set_user -- see also adt_set_from_ucred()
 *
 * ADT_NO_ATTRIB is a valid uid/gid meaning "not known" or
 * "unattributed."  If ruid, change the model to session.
 *
 * ADT_NO_CHANGE is a valid uid/gid meaning "do not change this value"
 * only valid with ADT_UPDATE.
 *
 * ADT_NO_AUDIT is the external equivalent to AU_NOAUDITID -- there
 * isn't a good reason to call adt_set_user() with it unless you don't
 * have a good value yet and intend to replace it later; auid will be
 * AU_NOAUDITID.
 *
 * adt_set_user should be called even if auditing is not enabled
 * so that adt_export_session_data() will have useful stuff to
 * work with.
 *
 * See the note preceding adt_set_proc() about the use of ADT_HAVE_TID
 * and ADT_HAVE_ALL.
 */

int
adt_set_user(const adt_session_data_t *session_data, uid_t euid, gid_t egid,
    uid_t ruid, gid_t rgid, const adt_termid_t *termid,
    enum adt_user_context user_context)
{
	adt_internal_state_t	*state;
	int			rc;

	if (session_data == NULL) /* no session exists to audit */
		return (0);

	state = (adt_internal_state_t *)session_data;
	assert(state->as_check == ADT_VALID);

	switch (user_context) {
	case ADT_NEW:
		if (ruid == ADT_NO_CHANGE || euid == ADT_NO_CHANGE ||
		    rgid == ADT_NO_CHANGE || egid == ADT_NO_CHANGE) {
			errno = EINVAL;
			return (-1);
		}
		if ((rc = adt_newuser(state, ruid,
		    (au_tid_addr_t *)termid)) != 0)
			return (rc);

		state->as_have_user_data = ADT_HAVE_ALL;
		break;
	case ADT_UPDATE:
		if (state->as_have_user_data != ADT_HAVE_ALL) {
			errno = EINVAL;
			return (-1);
		}

		if (ruid != ADT_NO_CHANGE)
			if ((rc = adt_changeuser(state, ruid)) != 0)
				return (rc);
		break;
	case ADT_USER:
		if (state->as_have_user_data != ADT_HAVE_ALL) {
			errno = EINVAL;
			return (-1);
		}
		break;
	case ADT_SETTID:
		assert(termid != NULL);
		state->as_info.ai_termid = *((au_tid_addr_t *)termid);
		/* avoid fooling pam_setcred()... */
		state->as_info.ai_auid = AU_NOAUDITID;
		state->as_info.ai_asid = 0;
		state->as_info.ai_mask.am_failure = 0;
		state->as_info.ai_mask.am_success = 0;
		state->as_have_user_data = ADT_HAVE_TID |
		    ADT_HAVE_AUID | ADT_HAVE_ASID | ADT_HAVE_MASK;
		return (0);
	default:
		errno = EINVAL;
		return (-1);
	}

	if (ruid == ADT_NO_AUDIT) {
		state->as_ruid = AU_NOAUDITID;
		state->as_euid = AU_NOAUDITID;
		state->as_rgid = AU_NOAUDITID;
		state->as_egid = AU_NOAUDITID;
	} else {
		if (ruid != ADT_NO_CHANGE)
			state->as_ruid = ruid;
		if (euid != ADT_NO_CHANGE)
			state->as_euid = euid;
		if (rgid != ADT_NO_CHANGE)
			state->as_rgid = rgid;
		if (egid != ADT_NO_CHANGE)
			state->as_egid = egid;
	}

	if (ruid == ADT_NO_ATTRIB) {
		state->as_session_model = ADT_SESSION_MODEL;
	}

	return (0);
}

/*
 * adt_set_from_ucred()
 *
 * an alternate to adt_set_user that fills the same role but uses
 * a pointer to a ucred rather than a list of id's.  If the ucred
 * pointer is NULL, use the credential from the this process.
 *
 * A key difference is that for ADT_NEW, adt_set_from_ucred() does
 * not overwrite the asid and auid unless auid has not been set.
 * ADT_NEW differs from ADT_UPDATE in that it does not OR together
 * the incoming audit mask with the one that already exists.
 *
 * adt_set_from_ucred should be called even if auditing is not enabled
 * so that adt_export_session_data() will have useful stuff to
 * work with.
 */

int
adt_set_from_ucred(const adt_session_data_t *session_data, const ucred_t *uc,
    enum adt_user_context user_context)
{
	adt_internal_state_t	*state;
	int			rc = -1;
	const au_tid64_addr_t		*tid64;
	au_tid_addr_t		termid, *tid;
	ucred_t	*ucred = (ucred_t *)uc;
	boolean_t	local_uc = B_FALSE;

	if (session_data == NULL) /* no session exists to audit */
		return (0);

	state = (adt_internal_state_t *)session_data;
	assert(state->as_check == ADT_VALID);

	if (ucred == NULL) {
		ucred = ucred_get(P_MYID);

		if (ucred == NULL)
			goto return_rc;
		local_uc = B_TRUE;
	}

	switch (user_context) {
	case ADT_NEW:
		tid64 = ucred_getatid(ucred);
		if (tid64 != NULL) {
			adt_cpy_tid(&termid, tid64);
			tid = &termid;
		} else {
			tid = NULL;
		}
		if (ucred_getauid(ucred) == AU_NOAUDITID) {
			adt_setto_unaudited(state);
			state->as_have_user_data = ADT_HAVE_ALL;
			rc = 0;
			goto return_rc;
		} else {
			state->as_info.ai_auid = ucred_getauid(ucred);
			state->as_info.ai_asid = ucred_getasid(ucred);
			state->as_info.ai_mask = *ucred_getamask(ucred);
			state->as_info.ai_termid = *tid;
		}
		state->as_have_user_data = ADT_HAVE_ALL;
		break;
	case ADT_UPDATE:
		if (state->as_have_user_data != ADT_HAVE_ALL) {
			errno = EINVAL;
			goto return_rc;
		}

		if ((rc = adt_changeuser(state, ucred_getruid(ucred))) != 0)
			goto return_rc;
		break;
	case ADT_USER:
		if (state->as_have_user_data != ADT_HAVE_ALL) {
			errno = EINVAL;
			goto return_rc;
		}
		break;
	default:
		errno = EINVAL;
		goto return_rc;
	}
	rc = 0;

	state->as_ruid = ucred_getruid(ucred);
	state->as_euid = ucred_geteuid(ucred);
	state->as_rgid = ucred_getrgid(ucred);
	state->as_egid = ucred_getegid(ucred);
	state->as_pid = ucred_getpid(ucred);
	state->as_label = adt_ucred_label(ucred);

return_rc:
	if (local_uc) {
		ucred_free(ucred);
	}
	return (rc);
}

/*
 * adt_alloc_event() returns a pointer to allocated memory
 *
 */

adt_event_data_t
*adt_alloc_event(const adt_session_data_t *session_data, au_event_t event_id)
{
	struct adt_event_state	*event_state;
	adt_internal_state_t	*session_state;
	adt_event_data_t	*return_event = NULL;
	/*
	 * need to return a valid event pointer even if audit is
	 * off, else the caller will end up either (1) keeping its
	 * own flags for on/off or (2) writing to a NULL pointer.
	 * If auditing is on, the session data must be valid; otherwise
	 * we don't care.
	 */
	if (session_data != NULL) {
		session_state = (adt_internal_state_t *)session_data;
		assert(session_state->as_check == ADT_VALID);
	}
	event_state = calloc(1, sizeof (struct adt_event_state));
	if (event_state == NULL)
		goto return_ptr;

	event_state->ae_check = ADT_VALID;

	event_state->ae_event_id = event_id;
	event_state->ae_session = (struct adt_internal_state *)session_data;

	return_event = (adt_event_data_t *)&(event_state->ae_event_data);

	/*
	 * preload data so the adt_au_*() functions can detect un-supplied
	 * values (0 and NULL are free via calloc()).
	 */
	if (session_data != NULL) {
		session_state->as_preload(event_id, return_event);
	}

return_ptr:
	return (return_event);
}

/*
 * adt_getXlateTable -- look up translation table address for event id
 */

static adt_translation_t *
adt_getXlateTable(adt_translation_t **xlate, au_event_t event_id)
{
	/* xlate_table is global in adt_xlate.c */
	adt_translation_t	**p_xlate = xlate;
	adt_translation_t	*p_event;

	while (*p_xlate != NULL) {
		p_event = *p_xlate;
		if (event_id == p_event->tx_external_event)
			return (p_event);
		p_xlate++;
	}
	return (NULL);
}

/*
 * adt_calcOffsets
 *
 * the call to this function is surrounded by a mutex.
 *
 * i walks down the table picking up next_token.  j walks again to
 * calculate the offset to the input data.  k points to the next
 * token's row.  Finally, l, is used to sum the values in the
 * datadef array.
 *
 * What's going on?  The entry array is in the order of the input
 * fields but the processing of array entries is in the order of
 * the output (see next_token).  Calculating the offset to the
 * "next" input can't be done in the outer loop (i) since i doesn't
 * point to the current entry and it can't be done with the k index
 * because it doesn't represent the order of input fields.
 *
 * While the resulting algorithm is n**2, it is only done once per
 * event type.
 */

/*
 * adt_calcOffsets is only called once per event type, but it uses
 * the address alignment of memory allocated for that event as if it
 * were the same for all subsequently allocated memory.  This is
 * guaranteed by calloc/malloc.  Arrays take special handling since
 * what matters for figuring out the correct alignment is the size
 * of the array element.
 */

static void
adt_calcOffsets(struct entry *p_entry, int tablesize, void *p_data)
{
	int		i, j;
	size_t		this_size, prev_size;
	void		*struct_start = p_data;

	for (i = 0; i < tablesize; i++) {
		if (p_entry[i].en_type_def == NULL) {
			p_entry[i].en_offset = 0;
			continue;
		}
		prev_size = 0;
		p_entry[i].en_offset = (char *)p_data - (char *)struct_start;

		for (j = 0; j < p_entry[i].en_count_types; j++) {
			if (p_entry[i].en_type_def[j].dd_datatype == ADT_MSG)
				this_size = sizeof (enum adt_generic);
			else
				this_size =
				    p_entry[i].en_type_def[j].dd_input_size;

			/* adj for first entry */
			if (prev_size == 0)
				prev_size = this_size;

			if (p_entry[i].en_type_def[j].dd_datatype ==
			    ADT_UINT32ARRAY) {
				p_data = (char *)adt_adjust_address(p_data,
				    prev_size, sizeof (uint32_t)) +
				    this_size - sizeof (uint32_t);

				prev_size = sizeof (uint32_t);
			} else {
				p_data = adt_adjust_address(p_data, prev_size,
				    this_size);
				prev_size = this_size;
			}
		}
	}
}

/*
 * adt_generate_event
 * generate event record from external struct.  The order is based on
 * the output tokens, allowing for the possibility that the input data
 * is in a different order.
 *
 */

static int
adt_generate_event(const adt_event_data_t *p_extdata,
    struct adt_event_state *p_event,
    adt_translation_t *p_xlate)
{
	struct entry		*p_entry;
	static mutex_t	lock = DEFAULTMUTEX;

	p_entry = p_xlate->tx_first_entry;
	assert(p_entry != NULL);

	p_event->ae_internal_id = p_xlate->tx_internal_event;
	adt_token_open(p_event);

	/*
	 * offsets are not pre-calculated; the initial offsets are all
	 * 0; valid offsets are >= 0.  Offsets for no-input tokens such
	 * as subject are set to -1 by adt_calcOffset()
	 */
	if (p_xlate->tx_offsetsCalculated == 0) {
		(void) mutex_lock(&lock);
		p_xlate->tx_offsetsCalculated = 1;

		adt_calcOffsets(p_xlate->tx_top_entry, p_xlate->tx_entries,
		    (void *)p_extdata);
		(void) mutex_unlock(&lock);
	}
	while (p_entry != NULL) {
		adt_generate_token(p_entry, (char *)p_extdata, p_event);

		p_entry = p_entry->en_next_token;
	}
	return (adt_token_close(p_event));
}

/*
 * adt_put_event -- main event generation function.
 * The input "event" is the address of the struct containing
 * event-specific data.
 *
 * However if auditing is off or the session handle
 * is NULL, no attempt to write a record is made.
 */

int
adt_put_event(const adt_event_data_t *event, int status, int return_val)
{
	struct adt_event_state	*event_state;
	adt_translation_t	*xlate;

	if (event == NULL) {
		errno = EINVAL;
		return (-1);
	}
	event_state = (struct adt_event_state *)event;

	/* if this is a broken session or not auditing, exit */
	if ((event_state->ae_session == NULL) ||
	    !(event_state->ae_session->as_audit_state &
	    (AUC_AUDITING | AUC_NOSPACE))) {
		return (0);
	}

	assert(event_state->ae_check == ADT_VALID);

	event_state->ae_rc = status;
	event_state->ae_type = return_val;

	/* look up the event */

	xlate = adt_getXlateTable(event_state->ae_session->as_xlate,
	    event_state->ae_event_id);

	if (xlate == NULL) {
		errno = EINVAL;
		return (-1);
	}
	DPRINTF(("got event %d\n", xlate->tx_internal_event));

	if (adt_selected(event_state, xlate->tx_internal_event, status)) {
		return (adt_generate_event(event, event_state, xlate));
	}

	return (0);
}

/*
 * adt_free_event -- invalidate and free
 */

void
adt_free_event(adt_event_data_t *event)
{
	struct adt_event_state	*event_state;

	if (event == NULL)
		return;

	event_state = (struct adt_event_state *)event;

	assert(event_state->ae_check == ADT_VALID);

	event_state->ae_check = 0;

	free(event_state);
}

/*
 * adt_is_selected -- helper to adt_selected(), below.
 *
 * "sorf" is "success or fail" status; au_preselect compares
 * that with success, fail, or both.
 */

static int
adt_is_selected(au_event_t e, au_mask_t *m, int sorf)
{
	int prs_sorf;

	if (sorf == 0)
		prs_sorf = AU_PRS_SUCCESS;
	else
		prs_sorf = AU_PRS_FAILURE;

	return (au_preselect(e, m, prs_sorf, AU_PRS_REREAD));
}

/*
 * selected -- see if this event is preselected.
 *
 * if errors are encountered trying to check a preselection mask
 * or look up a user name, the event is selected.  Otherwise, the
 * preselection mask is used for the job.
 */

static int
adt_selected(struct adt_event_state *event, au_event_t actual_id, int status)
{
	adt_internal_state_t *sp;
	au_mask_t	namask;

	sp = event->ae_session;

	if ((sp->as_have_user_data & ADT_HAVE_IDS) == 0) {
		adt_write_syslog("No user data available", EINVAL);
		return (1);	/* default is "selected" */
	}

	/* non-attributable? */
	if ((sp->as_info.ai_auid == AU_NOAUDITID) ||
	    (sp->as_info.ai_auid == ADT_NO_AUDIT)) {
		if (auditon(A_GETKMASK, (caddr_t)&namask,
		    sizeof (namask)) != 0) {
			adt_write_syslog("auditon failure", errno);
			return (1);
		}
		return (adt_is_selected(actual_id, &namask, status));
	} else {
		return (adt_is_selected(actual_id, &(sp->as_info.ai_mask),
		    status));
	}
}

/*
 * Can't map the host name to an IP address in
 * adt_get_hostIP.  Get something off an interface
 * to act as the hosts IP address for auditing.
 */

static int
adt_get_local_address(int family, struct ifaddrlist *al)
{
	struct ifaddrlist	*ifal;
	char	errbuf[ERRBUFSIZE] = "empty list";
	char	msg[ERRBUFSIZE + 512];
	int	ifal_count;
	int	i;

	if ((ifal_count = ifaddrlist(&ifal, family, 0, errbuf)) < 0) {
		int serrno = errno;

		(void) snprintf(msg, sizeof (msg), "adt_get_local_address "
		    "couldn't get %d addrlist %s", family, errbuf);
		adt_write_syslog(msg, serrno);
		errno = serrno;
		return (-1);
	}

	for (i = 0; i < ifal_count; i++) {
		/*
		 * loopback always defined,
		 * even if there is no real address
		 */
		if ((ifal[i].flags & (IFF_UP | IFF_LOOPBACK)) == IFF_UP) {
			break;
		}
	}
	if (i >= ifal_count) {
		free(ifal);
		/*
		 * Callers of adt_get_hostIP() can only return
		 * errno to their callers and eventually the application.
		 * Picked one that seemed least worse for saying no
		 * usable address for Audit terminal ID.
		 */
		errno = ENETDOWN;
		return (-1);
	}

	*al = ifal[i];
	free(ifal);
	return (0);
}

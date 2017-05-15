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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <rpc/rpc.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <signal.h>
#include <pthread.h>
#include <synch.h>

#include <rpcsvc/nis.h>
#include <rpcsvc/yppasswd.h>
#include <rpcsvc/ypclnt.h>
#include <rpc/key_prot.h>
#include <rpc/rpc.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>
#include <rpcsvc/nis_dhext.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#include <libintl.h>

#include <sys/mman.h>

#include <passwdutil.h>

#include "key_call_uid.h"
#include <shadow.h>

extern	int	_nfssys(int, void *);

/*
 * int msg(pamh, ...)
 *
 * display message to the user
 */
/*PRINTFLIKE2*/
static int
msg(pam_handle_t *pamh, char *fmt, ...)
{
	va_list	ap;
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	va_start(ap, fmt);
	(void) vsnprintf(messages[0], sizeof (messages[0]), fmt, ap);
	va_end(ap);

	return (__pam_display_msg(pamh, PAM_ERROR_MSG, 1, messages, NULL));
}


/*
 * Get the secret key for the given netname, key length, and algorithm
 * type and send it to keyserv if the given pw decrypts it.  Update the
 * following counter args as necessary: get_seckey_cnt, good_pw_cnt, and
 * set_seckey_cnt.
 *
 * Returns 0 on malloc failure, else 1.
 */
static int
get_and_set_seckey(
	pam_handle_t	*pamh,			/* in */
	const char	*netname,		/* in */
	keylen_t	keylen,			/* in */
	algtype_t	algtype,		/* in */
	const char	*pw,			/* in */
	uid_t		uid,			/* in */
	gid_t		gid,			/* in */
	int		*get_seckey_cnt,	/* out */
	int		*good_pw_cnt,		/* out */
	int		*set_seckey_cnt,	/* out */
	int		flags,			/* in */
	int		debug)			/* in */
{
	char	*skey;
	int	skeylen;
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	skeylen = BITS2NIBBLES(keylen) + 1;

	if ((skey = malloc(skeylen)) == NULL) {
		return (0);
	}

	if (getsecretkey_g(netname, keylen, algtype, skey, skeylen, pw)) {
		(*get_seckey_cnt)++;

		if (skey[0]) {
			/* password does decrypt secret key */
			(*good_pw_cnt)++;
			if (key_setnet_g_uid(netname, skey, keylen, NULL, 0,
			    algtype, uid, gid) >= 0) {
				(*set_seckey_cnt)++;
			} else {
				if (debug)
					syslog(LOG_DEBUG, "pam_dhkeys: "
					    "get_and_set_seckey: could not "
					    "set secret key for keytype "
					    "%d-%d", keylen, algtype);
			}
		} else {
			if (pamh && !(flags & PAM_SILENT)) {
				(void) snprintf(messages[0],
				    sizeof (messages[0]),
				    dgettext(TEXT_DOMAIN,
				    "Password does not "
				    "decrypt secret key (type = %d-%d) "
				    "for '%s'."), keylen, algtype, netname);
				(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 1,
				    messages, NULL);
			}
		}
	} else {
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: get_and_set_seckey: "
			    "could not get secret key for keytype %d-%d",
			    keylen, algtype);
	}

	free(skey);

	return (1);
}

/*
 * int establish_key(pamh, flags, debug, netname)
 *
 * This routine establishes the Secure RPC Credentials for the
 * user specified in PAM_USER, using the password in PAM_AUTHTOK.
 *
 * Establishing RPC credentials is considered a "helper" function for the PAM
 * stack so we should only return failures or PAM_IGNORE. Returning PAM_SUCCESS
 * may short circuit the stack and circumvent later critical checks.
 *
 * we are called from pam_sm_setcred:
 *	1. if we are root (uid == 0), we do nothing and return
 *	   PAM_IGNORE.
 *	2. else, we try to establish credentials.
 *
 * We return framework errors as appropriate such as PAM_USER_UNKNOWN,
 * PAM_BUF_ERR, PAM_PERM_DENIED.
 *
 * If we succeed in establishing credentials we return PAM_IGNORE.
 *
 * If we fail to establish credentials then we return:
 *    - PAM_SERVICE_ERR (credentials needed) or PAM_SYSTEM_ERR
 *      (credentials not needed) if netname could not be created;
 *    - PAM_AUTH_ERR (credentials needed) or PAM_IGNORE (credentials
 *      not needed) if no credentials were retrieved;
 *    - PAM_AUTH_ERR if the password didn't decrypt the cred;
 *    - PAM_SYSTEM_ERR if the cred's could not be stored.
 *
 * This routine returns the user's netname in "netname".
 *
 * All tools--but the PAM stack--currently use getpass() to obtain
 * the user's secure RPC password. We must make sure we don't use more than
 * the first des_block (eight) characters of whatever is handed down to us.
 * Therefore, we use a local variable "short_pass" to hold those 8 char's.
 */
static int
establish_key(pam_handle_t *pamh, int flags, int debug, char *netname)
{
	char	*user;
	char	*passwd;
	char	short_pass[sizeof (des_block)+1], *short_passp;
	int	result;
	uid_t	uid;
	gid_t	gid;
	int	err;

	struct passwd pw;	/* Needed to obtain uid */
	char	*scratch;
	int	scratchlen;

	mechanism_t	**mechs;
	mechanism_t	**mpp;
	int	get_seckey_cnt = 0;
	int	set_seckey_cnt = 0;
	int	good_pw_cnt = 0;
	int	valid_mech_cnt = 0;

	(void) pam_get_item(pamh, PAM_USER, (void **)&user);

	if (user == NULL || *user == '\0') {
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: user NULL or empty");
		return (PAM_USER_UNKNOWN);
	}

	(void) pam_get_item(pamh, PAM_AUTHTOK, (void **)&passwd);

	scratchlen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if ((scratch = malloc(scratchlen)) == NULL)
		return (PAM_BUF_ERR);

	if (getpwnam_r(user, &pw, scratch, scratchlen) == NULL) {
		result = PAM_USER_UNKNOWN;
		goto out;
	}

	uid = pw.pw_uid;
	gid = pw.pw_gid;

	/*
	 * We don't set credentials when root logs in.
	 */
	if (uid == 0) {
		result = PAM_IGNORE;
		goto out;
	}

	err = user2netname(netname, uid, NULL);

	if (err != 1) {
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: user2netname failed");
		result = PAM_SYSTEM_ERR;
		goto out;
	}

	/* passwd can be NULL (no passwd or su as root) */
	if (passwd) {
		(void) strlcpy(short_pass, passwd, sizeof (short_pass));
		short_passp = short_pass;
	} else
		short_passp = NULL;

	if (mechs = __nis_get_mechanisms(FALSE)) {

		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;

			if (AUTH_DES_COMPAT_CHK(mp))
				break;	/* fall through to AUTH_DES below */

			if (!VALID_MECH_ENTRY(mp))
				continue;

			if (debug)
				syslog(LOG_DEBUG, "pam_dhkeys: trying "
				    "key type = %d-%d", mp->keylen,
				    mp->algtype);
			valid_mech_cnt++;
			if (!get_and_set_seckey(pamh, netname, mp->keylen,
			    mp->algtype, short_passp, uid, gid,
			    &get_seckey_cnt, &good_pw_cnt, &set_seckey_cnt,
			    flags, debug)) {
				result = PAM_BUF_ERR;
				goto out;
			}
		}
		__nis_release_mechanisms(mechs);
		/* fall through to AUTH_DES below */
	} else {
		/*
		 * No usable mechs found in security congifuration file thus
		 * fallback to AUTH_DES compat.
		 */
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: no valid mechs "
			    "found. Trying AUTH_DES.");
	}

	/*
	 * We always perform AUTH_DES for the benefit of services like NFS
	 * that may depend on the classic des 192bit key being set.
	 */
	if (!get_and_set_seckey(pamh, netname, AUTH_DES_KEYLEN,
	    AUTH_DES_ALGTYPE, short_passp, uid, gid, &get_seckey_cnt,
	    &good_pw_cnt, &set_seckey_cnt, flags, debug)) {
		result = PAM_BUF_ERR;
		goto out;
	}

	if (debug) {
		syslog(LOG_DEBUG, "pam_dhkeys: mech key totals:\n");
		syslog(LOG_DEBUG, "pam_dhkeys: %d valid mechanism(s)",
		    valid_mech_cnt);
		syslog(LOG_DEBUG, "pam_dhkeys: %d secret key(s) retrieved",
		    get_seckey_cnt);
		syslog(LOG_DEBUG, "pam_dhkeys: %d passwd decrypt successes",
		    good_pw_cnt);
		syslog(LOG_DEBUG, "pam_dhkeys: %d secret key(s) set",
		    set_seckey_cnt);
	}

	if (get_seckey_cnt == 0) {		/* No credentials */
		result = PAM_IGNORE;
		goto out;
	}

	if (good_pw_cnt == 0) {			/* wrong password */
		result = PAM_AUTH_ERR;
		goto out;
	}

	if (set_seckey_cnt == 0) {
		result = PAM_SYSTEM_ERR;
		goto out;
	}
	/* Credentials have been successfully established, return PAM_IGNORE */
	result = PAM_IGNORE;
out:
	/*
	 * If we are authenticating we attempt to establish credentials
	 * where appropriate. Failure to do so is only an error if we
	 * definitely needed them. Thus always return PAM_IGNORE
	 * if we are authenticating and credentials were not needed.
	 */
	free(scratch);

	(void) memset(short_pass, '\0', sizeof (short_pass));

	return (result);
}

/*ARGSUSED*/
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}


typedef struct argres {
	uid_t uid;
	int result;
} argres_t;

/*
 * Revoke NFS DES credentials.
 * NFS may not be installed so we need to deal with SIGSYS
 * when we call _nfssys(); we thus call _nfssys() in a seperate thread that
 * is created specifically for this call. The thread specific signalmask
 * is set to ignore SIGSYS. After the call to _nfssys(), the thread
 * ceases to exist.
 */
static void *
revoke_nfs_cred(void *ap)
{
	struct nfs_revauth_args nra;
	sigset_t isigset;
	argres_t *argres = (argres_t *)ap;

	nra.authtype = AUTH_DES;
	nra.uid = argres->uid;

	(void) sigemptyset(&isigset);
	(void) sigaddset(&isigset, SIGSYS);

	if (pthread_sigmask(SIG_BLOCK, &isigset, NULL) == 0) {
		argres->result = _nfssys(NFS_REVAUTH, &nra);
		if (argres->result < 0 && errno == ENOSYS) {
			argres->result = 0;
		}
	} else {
		argres->result = -1;
	}
	return (NULL);
}

static int
remove_key(pam_handle_t *pamh, int flags, int debug)
{
	int result;
	char *uname;
	attrlist attr_pw[2];
	struct pam_repository *auth_rep = NULL;
	pwu_repository_t *pwu_rep;
	uid_t uid;
	gid_t gid;
	argres_t argres;
	pthread_t tid;

	(void) pam_get_item(pamh, PAM_USER, (void **)&uname);
	if (uname == NULL || *uname == NULL) {
		if (debug)
			syslog(LOG_DEBUG,
			    "pam_dhkeys: user NULL or empty in remove_key()");
		return (PAM_USER_UNKNOWN);
	}

	if (strcmp(uname, "root") == 0) {
		if ((flags & PAM_SILENT) == 0) {
			char msg[3][PAM_MAX_MSG_SIZE];
			(void) snprintf(msg[0], sizeof (msg[0]),
			    dgettext(TEXT_DOMAIN,
			    "removing root credentials would"
			    " break the rpc services that"));
			(void) snprintf(msg[1], sizeof (msg[1]),
			    dgettext(TEXT_DOMAIN,
			    "use secure rpc on this host!"));
			(void) snprintf(msg[2], sizeof (msg[2]),
			    dgettext(TEXT_DOMAIN,
			    "root may use keylogout -f to do"
			    " this (at your own risk)!"));
			(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 3,
			    msg, NULL);
		}
		return (PAM_PERM_DENIED);
	}

	(void) pam_get_item(pamh, PAM_REPOSITORY, (void **)&auth_rep);
	if (auth_rep != NULL) {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL)
			return (PAM_BUF_ERR);
		pwu_rep->type = auth_rep->type;
		pwu_rep->scope = auth_rep->scope;
		pwu_rep->scope_len = auth_rep->scope_len;
	} else
		pwu_rep = PWU_DEFAULT_REP;

	/* Retrieve user's uid/gid from the password repository */
	attr_pw[0].type = ATTR_UID; attr_pw[0].next = &attr_pw[1];
	attr_pw[1].type = ATTR_GID; attr_pw[1].next = NULL;

	result = __get_authtoken_attr(uname, pwu_rep, attr_pw);

	if (pwu_rep != PWU_DEFAULT_REP)
		free(pwu_rep);

	if (result == PWU_NOT_FOUND)
		return (PAM_USER_UNKNOWN);
	if (result == PWU_DENIED)
		return (PAM_PERM_DENIED);
	if (result != PWU_SUCCESS)
		return (PAM_SYSTEM_ERR);

	uid = (uid_t)attr_pw[0].data.val_i;
	gid = (gid_t)attr_pw[1].data.val_i;

	(void) key_removesecret_g_uid(uid, gid);

	argres.uid = uid;
	argres.result = -1;

	if (pthread_create(&tid, NULL, revoke_nfs_cred, (void *)&argres) == 0)
		(void) pthread_join(tid, NULL);

	if (argres.result < 0) {
		if ((flags & PAM_SILENT) == 0) {
			(void) msg(pamh, dgettext(TEXT_DOMAIN,
			    "Warning: NFS credentials not destroyed"));
		}
		return (PAM_AUTH_ERR);
	}

	return (PAM_IGNORE);
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int	i;
	int	debug = 0;
	int	result;
	char	netname[MAXNETNAMELEN + 1];

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcmp(argv[i], "nowarn") == 0)
			flags |= PAM_SILENT;
	}

	/* Check for invalid flags */
	if (flags && (flags & PAM_ESTABLISH_CRED) == 0 &&
	    (flags & PAM_REINITIALIZE_CRED) == 0 &&
	    (flags & PAM_REFRESH_CRED) == 0 &&
	    (flags & PAM_DELETE_CRED) == 0 &&
	    (flags & PAM_SILENT) == 0) {
		syslog(LOG_ERR, "pam_dhkeys: pam_setcred: illegal flags %d",
		    flags);
		return (PAM_SYSTEM_ERR);
	}


	if ((flags & PAM_REINITIALIZE_CRED) || (flags & PAM_REFRESH_CRED)) {
		/* doesn't apply to UNIX */
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: cred reinit/refresh "
			    "ignored\n");
		return (PAM_IGNORE);
	}

	if (flags & PAM_DELETE_CRED) {
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: removing creds\n");
		result = remove_key(pamh, flags, debug);
	} else {
		result = establish_key(pamh, flags, debug, netname);
		/* Some diagnostics */
		if ((flags & PAM_SILENT) == 0) {
			if (result == PAM_AUTH_ERR)
				(void) msg(pamh, dgettext(TEXT_DOMAIN,
				    "Password does not decrypt any secret "
				    "keys for %s."), netname);
			else if (result == PAM_SYSTEM_ERR && netname[0])
				(void) msg(pamh, dgettext(TEXT_DOMAIN,
				    "Could not set secret key(s) for %s. "
				    "The key server may be down."), netname);
		}

		/* Not having credentials set is not an error... */
		result = PAM_IGNORE;
	}

	return (result);
}

/*ARGSUSED*/
void
rpc_cleanup(pam_handle_t *pamh, void *data, int pam_status)
{
	if (data) {
		(void) memset(data, 0, strlen(data));
		free(data);
	}
}

/*ARGSUSED*/
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}

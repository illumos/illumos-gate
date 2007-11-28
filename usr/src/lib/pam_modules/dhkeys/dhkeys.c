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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <rpcsvc/nispasswd.h>
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

/* to keep track of codepath */
#define	CODEPATH_PAM_SM_AUTHENTICATE	0
#define	CODEPATH_PAM_SM_SETCRED		1

#define	SUNW_OLDRPCPASS	"SUNW-OLD-RPC-PASSWORD"

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
 * This routine established the Secure RPC Credentials for the
 * user specified in PAM_USER, using the password in PAM_AUTHTOK.
 *
 * Because this routine is used for both pam_authenticate *and*
 * pam_setcred, we have to be somewhat careful:
 *
 *      - if called from pam_sm_authenticate:
 *		1. if we don't need creds (no NIS+), we don't set them
 *		   and return PAM_IGNORE.
 *              2. else, we always try to establish credentials;
 *                 if (passwd == "*NP*"), not having credentials results
 *                 in PAM_AUTH_ERR.
 *                 if (passwd != "*NP*"), any failure to set credentials
 *                 results in PAM_IGNORE
 *
 *	- if called from pam_sm_setcred:
 *		If we are root (uid == 0), we do nothing and return PAM_IGNORE.
 *		Otherwise, we try to establish the credentials.
 *		Not having credentials in this case results in PAM_IGNORE.
 *
 *	For both modi, we return PAM_IGNORE if the creds are established.
 *	If we fail, we return
 *	   - PAM_AUTH_ERR if the password didn't decrypt the cred
 *	   - PAM_SYSTEM_ERR if the cred's could not be stored.
 *
 * This routine returns the user's netname in "netname".
 *
 * All tools--but the PAM stack--currently use getpass() to obtain
 * the user's secure RPC password. We must make sure we don't use more than
 * the first des_block (eight) characters of whatever is handed down to us.
 * Therefore, we use a local variable "short_pass" to hold those 8 char's.
 */
static int
establish_key(pam_handle_t *pamh, int flags, int codepath, int debug,
	char *netname)
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

	int	need_cred;	/* is not having credentials set a failure? */
	int	auth_cred_flags;
				/*
				 * no_warn if creds not needed and
				 * authenticating
				 */
	int	auth_path = (codepath == CODEPATH_PAM_SM_AUTHENTICATE);
	char *repository_name = NULL;	/* which repository are we using */
	char *repository_pass = NULL;	/* user's password from that rep */
	pwu_repository_t *pwu_rep;
	struct pam_repository *auth_rep;
	attrlist attr_pw[2];

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
	 * We do, however, need to set the credentials if the NIS+ permissions
	 * require so. Thus, we only bail out if we're root and we're
	 * called from pam_setcred.
	 */
	if (uid == 0 && codepath == CODEPATH_PAM_SM_SETCRED) {
		result = PAM_IGNORE;
		goto out;
	}

	/*
	 * Check to see if we REALLY need to set the credentials, i.e.
	 * whether not being able to do so is an error or whether we
	 * can ignore it.
	 * We need to get the password from the repository that we're
	 * currently authenticating against. IFF this password equals
	 * "*NP" *AND* we are authenticating against NIS+, we actually
	 * do need to set the credentials. In all other cases, we
	 * can forget about them.
	 */
	(void) pam_get_item(pamh, PAM_REPOSITORY, (void **)&auth_rep);
	if (auth_rep != NULL) {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL)
			return (PAM_BUF_ERR);
		pwu_rep->type = auth_rep->type;
		pwu_rep->scope = auth_rep->scope;
		pwu_rep->scope_len = auth_rep->scope_len;
	} else
		pwu_rep = PWU_DEFAULT_REP;

	attr_pw[0].type = ATTR_PASSWD; attr_pw[0].next = &attr_pw[1];
	attr_pw[1].type = ATTR_REP_NAME; attr_pw[1].next = NULL;
	result = __get_authtoken_attr(user, pwu_rep, attr_pw);

	if (pwu_rep != PWU_DEFAULT_REP)
		free(pwu_rep);

	if (result == PWU_NOT_FOUND) {
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: user %s not found",
			    user);
		result = PAM_USER_UNKNOWN;
		goto out;
	} else if (result != PWU_SUCCESS) {
		result = PAM_PERM_DENIED;
		goto out;
	}

	repository_name = attr_pw[1].data.val_s;
	repository_pass = attr_pw[0].data.val_s;

	if (auth_path && (strcmp(repository_name, "nisplus") != 0)) {
		result = PAM_IGNORE;
		goto out;
	}

	need_cred = (strcmp(repository_pass, "*NP*") == 0);
	if (auth_path) {
		auth_cred_flags =
		    (need_cred ? flags : flags | PAM_SILENT);
	} else {
		auth_cred_flags = flags;
	}

	if (uid == 0)		/* "root", need to create a host-netname */
		err = host2netname(netname, NULL, NULL);
	else
		err = user2netname(netname, uid, NULL);

	if (err != 1) {
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: user2netname failed");
		if (need_cred) {
			syslog(LOG_ALERT, "pam_dhkeys: user %s needs "
			    "Secure RPC Credentials to login.", user);
			result = PAM_SERVICE_ERR;
		} else
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
			    auth_cred_flags, debug)) {
				result = PAM_BUF_ERR;
				goto out;
			}
		}
		__nis_release_mechanisms(mechs);
		/* fall through to AUTH_DES below */
	} else {
		/*
		 * No usable mechs found in NIS+ security cf thus
		 * fallback to AUTH_DES compat.
		 */
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: no valid mechs "
			    "found. Trying AUTH_DES.");
	}

	/*
	 * We always perform AUTH_DES for the benefit of non-NIS+
	 * services (e.g. NFS) that may depend on the classic des
	 * 192bit key being set.
	 */
	if (!get_and_set_seckey(pamh, netname, AUTH_DES_KEYLEN,
	    AUTH_DES_ALGTYPE, short_passp, uid, gid, &get_seckey_cnt,
	    &good_pw_cnt, &set_seckey_cnt, auth_cred_flags, debug)) {
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
		result = need_cred ? PAM_AUTH_ERR : PAM_IGNORE;
		goto out;
	}

	if (good_pw_cnt == 0) {			/* wrong password */
		if (auth_path) {
			result = need_cred ? PAM_AUTH_ERR : PAM_IGNORE;
		} else {
			result = PAM_AUTH_ERR;
		}
		goto out;
	}

	if (set_seckey_cnt == 0) {
		if (auth_path) {
			result = need_cred ? PAM_SYSTEM_ERR : PAM_IGNORE;
		} else {
			result = PAM_SYSTEM_ERR;
		}
		goto out;
	}

	result = PAM_IGNORE;
out:
	if (repository_name)
		free(repository_name);
	if (repository_pass)
		free(repository_pass);

	free(scratch);

	(void) memset(short_pass, '\0', sizeof (short_pass));

	return (result);
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
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

	result = establish_key(pamh, flags, CODEPATH_PAM_SM_AUTHENTICATE, debug,
	    netname);

	return (result);
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
	thread_t tid;

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
		result = establish_key(pamh, flags, CODEPATH_PAM_SM_SETCRED,
		    debug, netname);
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

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i;
	int debug = 0;
	int res;
	pam_repository_t *pam_rep;
	pwu_repository_t *pwu_rep;
	char *oldpw;
	char *user;
	int tries;
	int oldpw_ok;
	char *oldrpcpw;
	char *oldrpcpass;
	char *data;
	/* password truncated at 8 chars, see comment at establish_key() */
	char short_pass[sizeof (des_block)+1], *short_passp;

	for (i = 0; i < argc; i++)
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;

	if (debug)
		syslog(LOG_DEBUG, "pam_dhkeys: entered pam_sm_chauthtok()");

	if ((flags & PAM_PRELIM_CHECK) == 0)
		return (PAM_IGNORE);

	/*
	 * See if the old secure-rpc password has already been set
	 */
	res = pam_get_data(pamh, SUNW_OLDRPCPASS, (const void **)&oldrpcpass);
	if (res == PAM_SUCCESS) {
		if (debug)
			syslog(LOG_DEBUG,
			    "pam_dhkeys: OLDRPCPASS already set");
		return (PAM_IGNORE);
	}

	(void) pam_get_item(pamh, PAM_REPOSITORY, (void **)&pam_rep);

	(void) pam_get_item(pamh, PAM_USER, (void **)&user);

	(void) pam_get_item(pamh, PAM_AUTHTOK, (void **)&oldpw);

	if (user == NULL || *user == '\0') {
		if (debug)
			syslog(LOG_DEBUG, "pam_dhkeys: user NULL or empty");
		return (PAM_USER_UNKNOWN);
	}

	/* oldpw can be NULL (eg. root changing someone's passwd) */
	if (oldpw) {
		(void) strlcpy(short_pass, oldpw, sizeof (short_pass));
		short_passp = short_pass;
	} else
		short_passp = NULL;

	/*
	 * For NIS+ we need to check whether the old password equals
	 * the RPC password. If it doesn't, we won't be able to update
	 * the secure RPC credentials later on in the process.
	 */

	if (pam_rep == NULL)
		pwu_rep = PWU_DEFAULT_REP;
	else {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL)
			return (PAM_BUF_ERR);
		pwu_rep->type = pam_rep->type;
		pwu_rep->scope = pam_rep->scope;
		pwu_rep->scope_len = pam_rep->scope_len;
	}

	switch (__verify_rpc_passwd(user, short_passp, pwu_rep)) {
	case PWU_SUCCESS:
		/* oldpw matches RPC password, or no RPC password needed */

		if (pwu_rep != PWU_DEFAULT_REP)
			free(pwu_rep);

		if (short_passp) {
			if ((data = strdup(short_pass)) == NULL) {
				(void) memset(short_pass, '\0',
				    sizeof (short_pass));
				return (PAM_BUF_ERR);
			}
		} else
			data = NULL;

		(void) pam_set_data(pamh, SUNW_OLDRPCPASS, data, rpc_cleanup);
		return (PAM_IGNORE);

	case PWU_NOT_FOUND:
		if (pwu_rep != PWU_DEFAULT_REP)
			free(pwu_rep);
		(void) memset(short_pass, '\0', sizeof (short_pass));
		return (PAM_USER_UNKNOWN);
	case PWU_BAD_CREDPASS:
		/* The old password does not decrypt any credentials */
		break;
	case PWU_CRED_ERROR:
		/*
		 * Indicates that the user's credentials could not be
		 * retrieved or removed.  This could occur when a NIS+
		 * user is in transition to another account authority.
		 */
		if (pwu_rep != PWU_DEFAULT_REP)
			free(pwu_rep);
		(void) memset(short_pass, '\0', sizeof (short_pass));
		return (PAM_AUTHTOK_ERR);
	default:
		if (pwu_rep != PWU_DEFAULT_REP)
			free(pwu_rep);
		(void) memset(short_pass, '\0', sizeof (short_pass));
		return (PAM_SYSTEM_ERR);
	}

	/*
	 * We got here because the OLDAUTHTOK doesn't match the Secure RPC
	 * password. In compliance with the old behavior, we give the
	 * user two chances to get the password right. If that succeeds
	 * all is well; if it doesn't, we'll return an error.
	 */

	(void) msg(pamh, dgettext(TEXT_DOMAIN,
	    "This password differs from your secure RPC password."));

	tries = 0;
	oldpw_ok = 0;

	while (oldpw_ok == 0 && ++tries < 3) {
		if (tries > 1)
			(void) msg(pamh, dgettext(TEXT_DOMAIN,
			    "This password does not decrypt your "
			    "secure RPC password."));
		res = __pam_get_authtok(pamh, PAM_PROMPT, 0,
		    dgettext(TEXT_DOMAIN,
		    "Please enter your old Secure RPC password: "), &oldpw);
		if (res != PAM_SUCCESS) {
			if (pwu_rep != PWU_DEFAULT_REP)
				free(pwu_rep);
			return (res);
		}
		(void) strlcpy(short_pass, oldpw, sizeof (short_pass));
		(void) memset(oldpw, 0, strlen(oldpw));
		free(oldpw);
		oldpw = NULL;
		if (__verify_rpc_passwd(user, short_pass, pwu_rep) ==
		    PWU_SUCCESS)
			oldpw_ok = 1;
	}

	if (pwu_rep != PWU_DEFAULT_REP)
		free(pwu_rep);

	if (oldpw_ok == 0) {
		(void) memset(short_pass, '\0', sizeof (short_pass));
		return (PAM_AUTHTOK_ERR);
	}

	/*
	 * Since the PAM framework only provides space for two different
	 * password (one old and one current), there is officially no
	 * place to put additional passwords (like our old rpc password).
	 * We have no choice but to stuff it in a data item, and hope it
	 * will be picked up by the password-update routines.
	 */

	oldrpcpw = strdup(short_pass);
	(void) memset(short_pass, '\0', sizeof (short_pass));

	if (oldrpcpw == NULL)
		return (PAM_BUF_ERR);

	res = pam_set_data(pamh, SUNW_OLDRPCPASS, oldrpcpw, rpc_cleanup);

	return (res);
}

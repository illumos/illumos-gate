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
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */


#include <stdlib.h>
#include <pwd.h>
#include <shadow.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <user_attr.h>
#include <auth_attr.h>
#include <userdefs.h>
#include <deflt.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdarg.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#include <libintl.h>

#include <passwdutil.h>

#define	LOGINADMIN	"/etc/default/login"
#define	MAXTRYS		5

/*PRINTFLIKE2*/
void
error(pam_handle_t *pamh, char *fmt, ...)
{
	va_list ap;
	char messages[1][PAM_MAX_MSG_SIZE];

	va_start(ap, fmt);
	(void) vsnprintf(messages[0], sizeof (messages[0]), fmt, ap);
	(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 1, messages, NULL);
	va_end(ap);
}

static int
get_max_failed(const char *user)
{
	char *val = NULL;
	userattr_t *uattr;
	int do_lock = 0;
	int retval = 0;
	char *p;
	void	*defp;

	if ((uattr = getusernam(user)) != NULL)
		val = kva_match(uattr->attr, USERATTR_LOCK_AFTER_RETRIES_KW);

	if (val != NULL) {
		do_lock = (strcasecmp(val, "yes") == 0);
	} else if ((defp = defopen_r(AUTH_POLICY)) != NULL) {
		int flags;
		flags = defcntl_r(DC_GETFLAGS, 0, defp);
		TURNOFF(flags, DC_CASE);
		(void) defcntl_r(DC_SETFLAGS, flags, defp);
		if ((p = defread_r("LOCK_AFTER_RETRIES=", defp)) != NULL)
			do_lock = (strcasecmp(p, "yes") == 0);
		defclose_r(defp);
	}

	if (uattr != NULL)
		free_userattr(uattr);

	if (do_lock) {
		retval = MAXTRYS;
		if ((defp = defopen_r(LOGINADMIN)) != NULL) {
			if ((p = defread_r("RETRIES=", defp)) != NULL)
				retval = atoi(p);
			defclose_r(defp);
		}
	}

	return (retval);
}

static void
display_warning(pam_handle_t *pamh, int failures, char *homedir)
{
	char hushpath[MAXPATHLEN];
	struct stat buf;

	(void) snprintf(hushpath, sizeof (hushpath), "%s/.hushlogin", homedir);
	if (stat(hushpath, &buf) == 0)
		return;

	if (failures == 1)
		error(pamh, "Warning: 1 failed login attempt since last "
		    "successful login.");
	else if (failures < FAILCOUNT_MASK)
		error(pamh, "Warning: %d failed login attempts since last "
		    "successful login.", failures);
	else
		error(pamh, "Warning: at least %d failed login attempts since "
		    "last successful login.", failures);
}

/*
 * int pam_sm_authenticate(pamh, flags, arc, argv)
 *
 * This routine verifies that the password as stored in the
 * PAM_AUTHTOK item is indeed the password that belongs to the user
 * as stored in PAM_USER.
 *
 * This routine will not establish Secure RPC Credentials, the pam_dhkeys
 * module should be stacked before us if Secure RPC Credentials are needed
 * to obtain passwords.
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i;
	int debug = 0;
	int nowarn = (flags & PAM_SILENT) != 0;
	const char *user;
	const char *passwd;
	char *rep_passwd;
	char *crypt_passwd;
	char *repository_name;
	const struct pam_repository *auth_rep;
	pwu_repository_t *pwu_rep;
	attrlist attr_pw[4];
	int result;
	int server_policy = 0;
	int old_failed_count;
	char *homedir = NULL;
	int dolock = 1;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcmp(argv[i], "nowarn") == 0)
			nowarn = 1;
		else if (strcmp(argv[i], "server_policy") == 0)
			server_policy = 1;
		else if (strcmp(argv[i], "nolock") == 0)
			dolock = 0;
	}

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_unix_auth: entering pam_sm_authenticate()");

	if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS) {
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_unix_auth: USER not set");
		return (PAM_SYSTEM_ERR);
	}

	if (user == NULL || *user == '\0') {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_unix_auth: USER NULL or empty!\n");
		return (PAM_USER_UNKNOWN);
	}

	if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&passwd) !=
	    PAM_SUCCESS) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_unix_auth: AUTHTOK not set!\n");
		return (PAM_SYSTEM_ERR);
	}

	result = pam_get_item(pamh, PAM_REPOSITORY, (const void **)&auth_rep);
	if (result == PAM_SUCCESS && auth_rep != NULL) {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL)
			return (PAM_BUF_ERR);
		pwu_rep->type = auth_rep->type;
		pwu_rep->scope = auth_rep->scope;
		pwu_rep->scope_len = auth_rep->scope_len;
	} else {
		pwu_rep = PWU_DEFAULT_REP;
	}

	/*
	 * Get password and the name of the repository where the
	 * password resides.
	 */
	attr_pw[0].type = ATTR_PASSWD;		attr_pw[0].next = &attr_pw[1];
	attr_pw[1].type = ATTR_REP_NAME;	attr_pw[1].next = &attr_pw[2];
	/*
	 * Also get the current number of failed logins; we use
	 * this later to determine whether we need to reset the count
	 * on a succesful authentication. We use the home-directory
	 * to look for .hushlogin in order to optionaly surpress the
	 * "failed attempts" message.
	 */
	attr_pw[2].type = ATTR_FAILED_LOGINS;	attr_pw[2].next = &attr_pw[3];
	attr_pw[3].type = ATTR_HOMEDIR;		attr_pw[3].next = NULL;

	result = __get_authtoken_attr(user, pwu_rep, attr_pw);

	if (pwu_rep != PWU_DEFAULT_REP)
		free(pwu_rep);

	if (result == PWU_NOT_FOUND) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_unix_auth: user %s not found\n", user);
		return (PAM_USER_UNKNOWN);
	}

	if (result == PWU_DENIED) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_unix_auth: failed to obtain attributes");
		return (PAM_PERM_DENIED);
	}

	if (result != PWU_SUCCESS)
		return (PAM_SYSTEM_ERR);

	rep_passwd = attr_pw[0].data.val_s;
	repository_name = attr_pw[1].data.val_s;
	old_failed_count = attr_pw[2].data.val_i;
	homedir = attr_pw[3].data.val_s;

	/*
	 * Chop off old SunOS-style password aging information.
	 *
	 * Note: old style password aging is only defined for UNIX-style
	 *	 crypt strings, hence the comma will always be at position 14.
	 * Note: This code is here because some other vendors might still
	 *	 support this style of password aging. If we don't remove
	 *	 the age field, no one will be able to login.
	 * XXX   yank this code when we're certain this "compatibility"
	 *	 isn't needed anymore.
	 */
	if (rep_passwd != NULL && rep_passwd[0] != '$' &&
	    strlen(rep_passwd) > 13 && rep_passwd[13] == ',')
		rep_passwd[13] = '\0';

	/* Is a password check required? */
	if (rep_passwd == NULL || *rep_passwd == '\0') {
		if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
			result = PAM_AUTH_ERR;
			__pam_log(LOG_AUTH | LOG_NOTICE,
			    "pam_unix_auth: empty password for %s not allowed.",
			    user);
			goto out;
		} else {
			result = PAM_SUCCESS;
			goto out;
		}
	}

	/*
	 * Password check *is* required. Make sure we have a valid
	 * pointer in PAM_AUTHTOK
	 */
	if (passwd == NULL) {
		result = PAM_AUTH_ERR;
		goto out;
	}

	if (server_policy &&
	    strcmp(repository_name, "files") != 0 &&
	    strcmp(repository_name, "nis") != 0) {
		result = PAM_IGNORE;
		goto out;
	}

	/* Now check the entered password */
	if ((crypt_passwd = crypt(passwd, rep_passwd)) == NULL) {
		switch (errno) {
		case ENOMEM:
			result = PAM_BUF_ERR;
			break;
		case ELIBACC:
			result = PAM_OPEN_ERR;
			break;
		default:
			result = PAM_SYSTEM_ERR;
		}
		goto out;
	}

	if (strcmp(crypt_passwd, rep_passwd) == 0)
		result = PAM_SUCCESS;
	else
		result = PAM_AUTH_ERR;

	/* Clear or increment failed failed count */
	if (dolock && (result == PAM_SUCCESS && old_failed_count > 0)) {
		old_failed_count = __rst_failed_count(user, repository_name);
		if (nowarn == 0 && old_failed_count > 0)
			display_warning(pamh, old_failed_count, homedir);
	} else if (dolock && result == PAM_AUTH_ERR) {
		int max_failed = get_max_failed(user);
		if (max_failed != 0) {
			if (__incr_failed_count(user, repository_name,
			    max_failed) == PWU_ACCOUNT_LOCKED)
				result = PAM_MAXTRIES;
		}
	}
out:
	if (rep_passwd)
		free(rep_passwd);
	if (repository_name)
		free(repository_name);
	if (homedir)
		free(homedir);
	return (result);
}

/*ARGSUSED*/
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}

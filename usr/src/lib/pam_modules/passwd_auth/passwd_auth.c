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

#include <sys/types.h>
#include <sys/varargs.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <crypt.h>
#include <pwd.h>
#include <libintl.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#include <passwdutil.h>

#include <sys/note.h>

/*PRINTFLIKE3*/
void
error(int nowarn, pam_handle_t *pamh, char *fmt, ...)
{
	va_list ap;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	va_start(ap, fmt);
	(void) vsnprintf(messages[0], sizeof (messages[0]), fmt, ap);
	if (nowarn == 0)
		(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 1, messages,
		    NULL);
	va_end(ap);
}

/*
 * int pam_sm_authenticate(pamh, flags, argc, argv)
 *
 * Read authentication token from user.
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{

	const char *user;
	char *password;
	const char *service;
	int i;
	int debug = 0;
	int nowarn = 0;
	int res;
	char prompt[PAM_MAX_MSG_SIZE];
	char *auth_user = NULL;
	int retval;
	int privileged;
	char *rep_passwd = NULL;
	char *repository_name = NULL;
	attrlist al[8];
	int min;
	int max;
	int lstchg;
	int server_policy = 0;

	const pam_repository_t *auth_rep = NULL;
	pwu_repository_t *pwu_rep = NULL;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		if (strcmp(argv[i], "nowarn") == 0)
			nowarn = 1;
		if (strcmp(argv[i], "server_policy") == 0)
			server_policy = 1;
	}

	if (flags & PAM_SILENT)
		nowarn = 1;

	if ((res = pam_get_user(pamh, (const char **)&user, NULL)) !=
	    PAM_SUCCESS) {
		if (debug)
			syslog(LOG_DEBUG, "pam_passwd_auth: "
			    "get user failed: %s", pam_strerror(pamh, res));
		return (res);
	}

	if (user == NULL || *user == '\0') {
		syslog(LOG_ERR, "pam_passwd_auth: pam_sm_authenticate: "
		    "PAM_USER NULL or empty");
		return (PAM_SYSTEM_ERR);
	}

	res = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
	if (res != PAM_SUCCESS)
		return (res);

	if (password != NULL)
		return (PAM_IGNORE);

	res = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (res != PAM_SUCCESS)
		return (res);

	res = pam_get_item(pamh, PAM_REPOSITORY, (const void **)&auth_rep);
	if (res != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_passwd_auth: pam_sm_authenticate: "
		    "error getting repository");
		return (PAM_SYSTEM_ERR);
	}

	if (auth_rep == NULL) {
		pwu_rep = PWU_DEFAULT_REP;
	} else {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL)
			return (PAM_BUF_ERR);
		pwu_rep->type = auth_rep->type;
		pwu_rep->scope = auth_rep->scope;
		pwu_rep->scope_len = auth_rep->scope_len;
	}

	res = __user_to_authenticate(user, pwu_rep, &auth_user, &privileged);
	if (res != PWU_SUCCESS) {
		if (res == PWU_NOT_FOUND)
			retval = PAM_USER_UNKNOWN;
		else if (res == PWU_DENIED)
			retval = PAM_PERM_DENIED;
		else if (res == PWU_REPOSITORY_ERROR) {
			syslog(LOG_NOTICE,
			    "pam_passwd_auth: detected unsupported "
			    "configuration in /etc/nsswitch.conf.");
			error(nowarn, pamh, dgettext(TEXT_DOMAIN, "%s: "
			    "Unsupported nsswitch entry for \"passwd:\"."
			    " Use \"-r repository \"."), service);
			retval = PAM_SYSTEM_ERR;
		} else
			retval = PAM_SYSTEM_ERR;
		if (debug)
			syslog(LOG_DEBUG, "passwd_auth: __user_to_authenticate "
			    "returned %d", retval);
		goto out;
	}

	if (auth_user == NULL) {		/* No authentication needed */
		if (debug)
			syslog(LOG_DEBUG,
			    "passwd_auth: no authentication needed.");
		retval = PAM_SUCCESS;
		goto out;
	}

	/*
	 * The password prompt differs between users updating their
	 * own password, and users updating other an user's password
	 */
	if (privileged) {
		/*
		 * TRANSLATION_NOTE
		 * The following string has a single space at the end
		 */
		(void) snprintf(prompt, sizeof (prompt),
		    dgettext(TEXT_DOMAIN, "Enter %s's password: "),
		    auth_user);
	} else {
		/*
		 * TRANSLATION_NOTE
		 * The following string has a single space at the end
		 */
		(void) snprintf(prompt, sizeof (prompt),
		    dgettext(TEXT_DOMAIN, "Enter existing login password: "));
	}

	retval = __pam_get_authtok(pamh, PAM_PROMPT, PAM_AUTHTOK, prompt,
	    &password);
	if (retval != PAM_SUCCESS)
		goto out;

	if (password == NULL) {
		syslog(LOG_ERR, "pam_passwd_auth: pam_sm_authenticate: "
		    "got NULL password from get_authtok()");
		retval = PAM_AUTH_ERR;
		goto out;
	}

	/* Privileged users can skip the tests that follow */
	if (privileged)
		goto setitem;

	/*
	 * Non privileged user: so we need to check the old password
	 * and possible restrictions on password changes.
	 */

	/* Get password and it's age from the repository specified */
	al[0].type = ATTR_PASSWD; al[0].next = &al[1];
	al[1].type = ATTR_MIN; al[1].next = &al[2];
	al[2].type = ATTR_MAX; al[2].next = &al[3];
	al[3].type = ATTR_LSTCHG; al[3].next = &al[4];
	al[4].type = ATTR_WARN; al[4].next = &al[5];
	al[5].type = ATTR_INACT; al[5].next = &al[6];
	al[6].type = ATTR_EXPIRE; al[6].next = &al[7];
	al[7].type = ATTR_REP_NAME; al[7].next = NULL;

	res = __get_authtoken_attr(auth_user, pwu_rep, al);

	if (res != PWU_SUCCESS) {
		retval = PAM_SYSTEM_ERR;
		goto out;
	}

	repository_name = al[7].data.val_s;

	/*
	 * if repository isn't files|nis, and user wants to follow server
	 * policy, return PAM_IGNORE
	 */
	if (server_policy &&
	    strcmp(repository_name, "files") != 0 &&
	    strcmp(repository_name, "nis") != 0) {
		retval = PAM_IGNORE;
		goto out;
	}

	rep_passwd = al[0].data.val_s;

	/*
	 * Chop off old SunOS-style password aging information.
	 *
	 * Note: old style password aging is only defined for UNIX-style
	 *	 crypt strings, hence the comma will always be at position 14.
	 * Note: This code is here because some other vendors might still
	 *	 support this style of password aging. If we don't remove
	 *	 the age field, users won't be able to change their password.
	 * XXX   yank this code when we're certain this "compatibility"
	 *	 isn't needed anymore.
	 */
	if (rep_passwd != NULL && rep_passwd[0] != '$' &&
	    strlen(rep_passwd) > 13 && rep_passwd[13] == ',')
		rep_passwd[13] = '\0';

	if (strcmp(crypt(password, rep_passwd), rep_passwd) != 0) {
		retval = PAM_AUTH_ERR;
		goto out;
	}

	/*
	 * Now check to see if the user is allowed to change
	 * the password.
	 */
	min = al[1].data.val_i;
	max = al[2].data.val_i;
	lstchg = al[3].data.val_i;

	if (max != -1 && lstchg != 0) {
		/* aging is turned on, and a change is not forced */
		time_t daynow = DAY_NOW_32;
		if ((time_t)lstchg <= daynow) {
			/* Aged enough? */
			if (daynow < (time_t)(lstchg + min)) {
				error(nowarn, pamh, dgettext(TEXT_DOMAIN,
				    "%s: Sorry: less than %d days "
				    "since the last change."),
				    service, min);
				retval = PAM_PERM_DENIED;
				goto out;
			}

			/*
			 * users with min>max are not allowed to
			 * change their password.
			 */
			if (min > max) {
				error(nowarn, pamh, dgettext(TEXT_DOMAIN,
				    "%s: You may not change "
				    "this password."), service);
				retval = PAM_PERM_DENIED;
				goto out;
			}
		}
	}

setitem:

	retval = pam_set_item(pamh, PAM_AUTHTOK, (void *)password);

out:
	if (password) {
		(void) memset(password, 0, strlen(password));
		free(password);
	}
	if (rep_passwd) {
		(void) memset(rep_passwd, 0, strlen(rep_passwd));
		free(rep_passwd);
	}
	if (pwu_rep)
		free(pwu_rep);
	if (auth_user)
		free(auth_user);
	if (repository_name)
		free(repository_name);

	return (retval);
}

/*ARGSUSED*/
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}

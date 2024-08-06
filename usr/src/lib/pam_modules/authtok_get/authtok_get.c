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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/varargs.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#include <sys/note.h>

#include <libintl.h>

#include <passwdutil.h>

/*PRINTFLIKE2*/
void
error(pam_handle_t *pamh, char *fmt, ...)
{
	va_list ap;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	va_start(ap, fmt);
	(void) vsnprintf(messages[0], sizeof (messages[0]), fmt, ap);
	(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 1, messages, NULL);
	va_end(ap);
}

int
read_authtok(pam_handle_t *pamh, int debug)
{
	int res;
	const char *authtok;
	char *pwd;

	/*
	 * We are about to read the new AUTHTOK. Store the AUTHTOK that
	 * the user used to authenticate in OLDAUTHTOK, so it is available
	 * to future modules. If OLDAUTHTOK is already set, we leave it alone
	 */

	res = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **)&authtok);
	if (res != PAM_SUCCESS)
		return (res);

	if (authtok == NULL) {
		res = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
		if (res != PAM_SUCCESS)
			return (res);
		if (authtok != NULL) {
			res = pam_set_item(pamh, PAM_OLDAUTHTOK,
			    (void *)authtok);
			if (res == PAM_SUCCESS)
				res = pam_set_item(pamh, PAM_AUTHTOK, NULL);

			if (debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "read_authtok: Copied AUTHTOK to "
				    "OLDAUTHTOK");

			if (res != PAM_SUCCESS)
				goto out;
		}
	} else {
		/*
		 * OLDAUTHTOK was filled in. If AUTHTOK is also filled
		 * in, we either succeed a module that has done our
		 * work, or we're here because one of the modules
		 * that are stacked beyond us has returned PAM_TRY_AGAIN.
		 * In either case, we should *not* prompt for another
		 * password.
		 */
		res = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pwd);
		if (res != PAM_SUCCESS)
			goto out;
		if (pwd != NULL) {
			goto out;
		}
	}

	/*
	 * Make sure PAM_AUTHTOK is empty, or the framework will not
	 * put the value read by __pam_get_authtok into it
	 */
	(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);

	res = __pam_get_authtok(pamh, PAM_PROMPT, PAM_AUTHTOK,
	    dgettext(TEXT_DOMAIN, "New Password: "), &pwd);

	if (res != PAM_SUCCESS)
		goto out;

	if (pwd == NULL) {
		const char *service;
		if ((pam_get_item(pamh, PAM_SERVICE, (const void **)&service) ==
		    PAM_SUCCESS) && service != NULL) {
			error(pamh, dgettext(TEXT_DOMAIN, "%s: Sorry."),
			    service);
		}
		res = PAM_PERM_DENIED;
	} else {
		(void) memset(pwd, 0, strlen(pwd));
		free(pwd);
	}
out:
	if (res != PAM_SUCCESS) {
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
		(void) pam_set_item(pamh, PAM_OLDAUTHTOK, NULL);
	} else {
		/*
		 * Since we don't actually check the password, we should
		 * not return PAM_SUCCESS if everything went OK.
		 * We should return PAM_IGNORE instead.
		 */
		res = PAM_IGNORE;
	}

	return (res);
}

int
verify_authtok(pam_handle_t *pamh, int debug)
{
	int res;
	const char *authtok;
	char *pwd;

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_get: verifying authtok");

	/*
	 * All we need to do, is make sure that the user re-enters
	 * the password correctly.
	 */

	res = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
	if (res != PAM_SUCCESS || authtok == NULL)
		return (PAM_AUTHTOK_ERR);

	res = __pam_get_authtok(pamh, PAM_PROMPT, 0, dgettext(TEXT_DOMAIN,
	    "Re-enter new Password: "), &pwd);

	if (res != PAM_SUCCESS)
		return (res);

	if (strcmp(authtok, pwd) != 0) {
		const char *service;

		if ((pam_get_item(pamh, PAM_SERVICE, (const void **)&service) ==
		    PAM_SUCCESS) && service != NULL) {
			error(pamh, dgettext(TEXT_DOMAIN,
			    "%s: They don't match."), service);
		}
		(void) pam_set_item(pamh, PAM_AUTHTOK, NULL);
		(void) memset(pwd, 0, strlen(pwd));
		free(pwd);
		return (PAM_AUTHTOK_ERR);
	}

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_get: new password verified");

	(void) memset(pwd, 0, strlen(pwd));
	free(pwd);
	return (PAM_IGNORE);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i;
	int debug = 0;
	int res;

	for (i = 0; i < argc; i++)
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;

	if ((flags & PAM_PRELIM_CHECK) == PAM_PRELIM_CHECK)
		res = read_authtok(pamh, debug);
	else
		res = verify_authtok(pamh, debug);

	return (res);
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
	int i;
	int debug = 0;
	int res;
	int fail = 0;

	attrlist al[1];
	const pam_repository_t *auth_rep = NULL;
	pwu_repository_t *pwu_rep  = NULL;

	for (i = 0; i < argc; i++)
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_get:pam_sm_authenticate: flags = %d", flags);

	if ((res = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "pam_authtok_get: get user failed: %s",
			    pam_strerror(pamh, res));
		return (res);
	}

	if (user == NULL || *user == '\0') {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_authtok_get: pam_sm_authenticate: PAM_USER NULL or "
		    "empty");
		return (PAM_SYSTEM_ERR);
	}

	res = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
	if (res != PAM_SUCCESS)
		return (res);

	if (password != NULL)
		return (PAM_IGNORE);

	/*
	 * No password has been entered yet. Check to see if we need
	 * to obtain a password
	 */

	res = pam_get_item(pamh, PAM_REPOSITORY, (const void **)&auth_rep);
	if (res != PAM_SUCCESS) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_authtok_get: error getting repository");
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

	(void) memset(&al, 0, sizeof (al));
	al[0].type = ATTR_PASSWD;
	al[0].next = NULL;

	res = __get_authtoken_attr(user, pwu_rep, al);

	if (pwu_rep != PWU_DEFAULT_REP)
		free(pwu_rep);

	if (res == PWU_SUCCESS &&
	    (al[0].data.val_s == NULL || al[0].data.val_s[0] == '\0')) {
		const char *service = NULL;
		const char *rhost = NULL;

		/*
		 * if PAM_DIASALLOW_NULL_AUTHTOK has not been set, we
		 * simply return IGNORE
		 */
		if ((flags & PAM_DISALLOW_NULL_AUTHTOK) == 0)
			return (PAM_IGNORE);

		/*
		 * NULL authtoks are not allowed, so we need to fail.
		 * We will ask for a password to mask the failure however.
		 */
		(void) pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);
		(void) pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
		if (service == NULL)
			service = "unknown";
		if (rhost == NULL || *rhost == '\0')
			rhost = "localhost";
		__pam_log(LOG_AUTH | LOG_NOTICE,
		    "pam_authtok_get: %s: empty password not allowed for "
		    "%s from %s.", service, user, rhost);
		fail = 1;
	}
	if (al[0].data.val_s != NULL) {
		(void) memset(al[0].data.val_s, 0, strlen(al[0].data.val_s));
		free(al[0].data.val_s);
	}

	res = __pam_get_authtok(pamh, PAM_PROMPT, PAM_AUTHTOK,
	    dgettext(TEXT_DOMAIN, "Password: "), &password);
	if (res != PAM_SUCCESS)
		return (res);

	if (password != NULL) {
		(void) pam_set_item(pamh, PAM_AUTHTOK, (const void *)password);
		(void) memset(password, 0, strlen(password));
		free(password);
	} else if (debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_get: pam_sm_authenticate: "
		    "got NULL password from get_authtok()");
	}

	if (fail) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_get:pam_sm_authenticate: "
		    "failing because NULL authtok not allowed");
		return (PAM_AUTH_ERR);
	} else
		return (PAM_IGNORE);
}

/*ARGSUSED*/
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}

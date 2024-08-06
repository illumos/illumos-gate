/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <libintl.h>

#include "sample_utils.h"

/*
 *
 * Sample module for pam_sm_authenticate.
 *
 * options -
 *
 *	debug
 *	use_first_pass
 *	try_first_pass
 *	first_pass_good  (first password is always good when used with use/try)
 *	first_pass_bad   (first password is always bad when used with use/try)
 *	pass=foobar	 (set good password to "foobar". default good password
 *			 is test)
 *	always_fail	 always return PAM_AUTH_ERR
 *	always_succeed   always return PAM_SUCCESS
 *	always_ignore
 *
 *
 */

/*
 * pam_sm_authenticate		- Authenticate user
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	const struct pam_conv *pam_convp;
	int err, result = PAM_AUTH_ERR;
	struct pam_response *ret_resp = (struct pam_response *)0;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	int debug = 0;
	int try_first_pass = 0;
	int use_first_pass = 0;
	int first_pass_good = 0;
	int first_pass_bad = 0;
	int i, num_msg;
	const char *firstpass;
	char *password;
	char the_password[64];

	if (debug)
		syslog(LOG_DEBUG, "Sample Authentication\n");

	(void) strcpy(the_password, "test");

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcmp(argv[i], "try_first_pass") == 0)
			try_first_pass = 1;
		else if (strcmp(argv[i], "first_pass_good") == 0)
			first_pass_good = 1;
		else if (strcmp(argv[i], "first_pass_bad") == 0)
			first_pass_bad = 1;
		else if (strcmp(argv[i], "use_first_pass") == 0)
			use_first_pass = 1;
		else if (strcmp(argv[i], "always_fail") == 0)
			return (PAM_AUTH_ERR);
		else if (strcmp(argv[i], "always_succeed") == 0)
			return (PAM_SUCCESS);
		else if (strcmp(argv[i], "always_ignore") == 0)
			return (PAM_IGNORE);
		else if (sscanf(argv[i], "pass=%64s", the_password) == 1) {
			/*EMPTY*/;
		}
		else
			syslog(LOG_DEBUG, "illegal scheme option %s", argv[i]);
	}

	err = pam_get_user(pamh, &user, NULL);
	if (err != PAM_SUCCESS)
		return (err);

	err = pam_get_item(pamh, PAM_CONV, (const void**)&pam_convp);
	if (err != PAM_SUCCESS)
		return (err);

	(void) pam_get_item(pamh, PAM_AUTHTOK, (const void **)&firstpass);

	if (firstpass && (use_first_pass || try_first_pass)) {

		if ((first_pass_good ||
			strncmp(firstpass, the_password,
				strlen(the_password)) == 0) &&
				!first_pass_bad) {
					result = PAM_SUCCESS;
					goto out;
		}
		if (use_first_pass) goto out;
	}

	/*
	 * Get the password from the user
	 */
	if (firstpass) {
		(void) snprintf(messages[0], sizeof (messages[0]),
			dgettext(TEXT_DOMAIN, "TEST Password: "));
	} else {
		(void) snprintf(messages[0], sizeof (messages[0]),
			dgettext(TEXT_DOMAIN, "Password: "));
	}
	num_msg = 1;
	err = __get_authtok(pam_convp->conv,
				num_msg, messages, NULL, &ret_resp);

	if (err != PAM_SUCCESS) {
		result = err;
		goto out;
	}

	password = ret_resp->resp;

	if (password == NULL) {
		result = PAM_AUTH_ERR;
		goto out;
	}

	/* one last ditch attempt to "login" to TEST */

	if (strncmp(password, the_password, strlen(the_password)) == 0) {
		result = PAM_SUCCESS;
		if (firstpass == NULL) {
			/* this is the first password, stash it away */
			(void) pam_set_item(pamh, PAM_AUTHTOK, password);
		}
	}

out:
	if (num_msg > 0) {
		if (ret_resp != 0) {
			if (ret_resp->resp != 0) {
				/* avoid leaving password cleartext around */
				(void) memset(ret_resp->resp, 0,
					strlen(ret_resp->resp));
			}
			__free_resp(num_msg, ret_resp);
			ret_resp = 0;
		}
	}

	return (result);
}

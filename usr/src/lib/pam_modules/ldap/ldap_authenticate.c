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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include "ldap_headers.h"

/*
 *
 * LDAP module for pam_sm_authenticate.
 *
 * options -
 *
 *	debug
 *	nowarn
 */

/*
 * pam_sm_authenticate():
 * 	Authenticate user.
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *service = NULL;
	const char *user = NULL;
	int err;
	int result = PAM_AUTH_ERR;
	int debug = 0;
	int i;
	const char *password = NULL;
	ns_cred_t *credp = NULL;
	int nowarn = 0;

	/* Get the service and user */
	if ((err = pam_get_item(pamh, PAM_SERVICE, (const void **)&service)) !=
	    PAM_SUCCESS ||
	    (err = pam_get_item(pamh, PAM_USER, (const void **)&user)) !=
	    PAM_SUCCESS) {
		return (err);
	}

	/*
	 * Check options passed to this module.
	 * Silently ignore try_first_pass and use_first_pass options
	 * for the time being.
	 */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcmp(argv[i], "nowarn") == 0)
			nowarn = 1;
		else if ((strcmp(argv[i], "try_first_pass") != 0) &&
				(strcmp(argv[i], "use_first_pass") != 0))
			syslog(LOG_AUTH | LOG_DEBUG,
				"ldap pam_sm_authenticate(%s), "
				"illegal scheme option %s", service, argv[i]);
	}

	if (debug)
		syslog(LOG_AUTH | LOG_DEBUG,
			"ldap pam_sm_authenticate(%s %s), flags = %x %s",
			service, (user && *user != '\0')?user:"no-user", flags,
			(nowarn)? ", nowarn": "");

	if (!user || *user == '\0')
		return (PAM_USER_UNKNOWN);

	/* Get the password entered in the first scheme if any */
	(void) pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
	if (password == NULL) {
		if (debug)
			syslog(LOG_AUTH | LOG_DEBUG,
				"ldap pam_sm_authenticate(%s %s), "
				"AUTHTOK not set", service, user);
		return (PAM_AUTH_ERR);
	}

	/*
	 * Authenticate user using the password from PAM_AUTHTOK.
	 * If no password available or if authentication fails
	 * return the appropriate error.
	 */
	result = authenticate(&credp, user, password, NULL);
	if (result == PAM_NEW_AUTHTOK_REQD) {
		/*
		 * PAM_NEW_AUTHTOK_REQD means the
		 * user's password is good but needs
		 * to change immediately. If the service
		 * is login or similar programs, the
		 * user will be asked to change the
		 * password after the account management
		 * module is called and determined that
		 * the password has expired.
		 * So change the rc to PAM_SUCCESS here.
		 */
		result = PAM_SUCCESS;
	} else if (result == PAM_AUTHTOK_EXPIRED) {
		/*
		 * Authentication token is the right one but
		 * expired. Consider this as pass.
		 * Change rc to PAM_SUCCESS.
		 */
		result = PAM_SUCCESS;
	}

	if (credp != NULL)
		(void) __ns_ldap_freeCred(&credp);
	return (result);
}

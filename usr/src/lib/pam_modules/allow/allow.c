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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include <strings.h>
#include <syslog.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

/*
 * pam_allow - PAM service module that returns PAM_SUCCESS all service
 *		module types.
 *
 *	Entry	argv = debug, syslog call LOG_AUTH | LOG_DEBUG.
 *
 *	Exit	PAM_SUCCESS
 *
 *	Uses	PAM_USER, PAM_SERVICE
 */

static void
debug(pam_handle_t *pamh, int flags, int argc, const char **argv, char *mod)
{
	const char *user = NULL;
	const char *service = NULL;

	if (argc < 1 || strcmp(argv[0], "debug") != 0)
		return;

	(void) pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	(void) pam_get_item(pamh, PAM_USER, (const void **)&user);

	syslog(LOG_AUTH | LOG_DEBUG, "%s pam_allow:%s(%x) for %s",
	    service ? service : "No Service Specified", mod, flags,
	    user ? user : "No User Specified");
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	debug(pamh, flags, argc, argv, "pam_sm_authenticate");
	return (PAM_SUCCESS);
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	debug(pamh, flags, argc, argv, "pam_sm_setcred");
	return (PAM_SUCCESS);
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	debug(pamh, flags, argc, argv, "pam_sm_acct_mgmt");
	return (PAM_SUCCESS);
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	debug(pamh, flags, argc, argv, "pam_sm_open_session");
	return (PAM_SUCCESS);
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	debug(pamh, flags, argc, argv, "pam_sm_close_session");
	return (PAM_SUCCESS);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	debug(pamh, flags, argc, argv, "pam_sm_chauthtok");
	return (PAM_SUCCESS);
}

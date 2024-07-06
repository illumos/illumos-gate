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

#include <sys/param.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <locale.h>
#include <crypt.h>
#include <syslog.h>

extern int ruserok(const char *, int, const char *, const char *);

/*
 * pam_sm_authenticate	- Checks if the user is allowed remote access
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *host = NULL, *lusername = NULL;
	struct passwd pwd;
	char pwd_buffer[1024];
	int is_superuser;
	const char *rusername;
	int i;
	int debug = 0;

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else
			syslog(LOG_DEBUG, "illegal option %s", argv[i]);
	}

	if (pam_get_item(pamh, PAM_USER, (const void **)&lusername) !=
	    PAM_SUCCESS) {
		return (PAM_SERVICE_ERR);
	}
	if (pam_get_item(pamh, PAM_RHOST, (const void **)&host) != PAM_SUCCESS)
		return (PAM_SERVICE_ERR);
	if (pam_get_item(pamh, PAM_RUSER, (const void **)&rusername) !=
	    PAM_SUCCESS) {
		return (PAM_SERVICE_ERR);
	}

	if (lusername == NULL || *lusername == '\0')
		return (PAM_USER_UNKNOWN);
	if (rusername == NULL || *rusername == '\0')
		return (PAM_AUTH_ERR);
	if (host == NULL || *host == '\0')
		return (PAM_AUTH_ERR);

	if (debug) {
		syslog(LOG_DEBUG,
			"rhosts authenticate: user = %s, host = %s",
			lusername, host);
	}

	if (getpwnam_r(lusername, &pwd, pwd_buffer, sizeof (pwd_buffer))
								== NULL)
		return (PAM_USER_UNKNOWN);

	if (pwd.pw_uid == 0)
		is_superuser = 1;
	else
		is_superuser = 0;

	return (ruserok(host, is_superuser, rusername, lusername)
		== -1 ? PAM_AUTH_ERR : PAM_SUCCESS);

}

/*
 * dummy pam_sm_setcred - does nothing
 */
/*ARGSUSED*/
int
pam_sm_setcred(
	pam_handle_t	*pamh,
	int	flags,
	int	argc,
	const char	**argv)
{
	return (PAM_IGNORE);
}

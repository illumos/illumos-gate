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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "../../libpam/pam_impl.h"

#include <libintl.h>

/*
 * Various useful files and string constants
 */
#define	DIAL_FILE	"/etc/dialups"
#define	DPASS_FILE	"/etc/d_passwd"
#define	SHELL		"/usr/bin/sh"
#define	SCPYN(a, b)	(void) strncpy(a, b, sizeof (a))

/*
 * pam_sm_authenticate	- This is the top level function in the
 *			module called by pam_auth_port in the framework
 *			Returns: PAM_AUTH_ERR on failure, 0 on success
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *ttyn, *user;
	FILE *fp;
	char defpass[30];
	char line[80];
	char *p1 = NULL, *p2 = NULL;
	struct passwd pwd;
	char pwd_buffer[1024];
	char *password = NULL;
	int retcode;
	int i;
	int debug = 0;
	int res;

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else
			syslog(LOG_DEBUG, "illegal option %s", argv[i]);
	}

	if ((retcode = pam_get_user(pamh, &user, NULL))
					!= PAM_SUCCESS ||
	    (retcode = pam_get_item(pamh, PAM_TTY, (const void **)&ttyn))
					!= PAM_SUCCESS)
		return (retcode);

	if (debug) {
		syslog(LOG_DEBUG,
			"Dialpass authenticate user = %s, ttyn = %s",
			user ? user : "NULL", ttyn ? ttyn : "NULL");
	}

	if (ttyn == NULL || *ttyn == '\0') {
		const char *service;

		(void) pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
		syslog(LOG_ERR, "pam_dial_auth: terminal-device not specified"
		    "by %s, returning %s.", service,
		    pam_strerror(pamh, PAM_SERVICE_ERR));
		return (PAM_SERVICE_ERR);
	}
	if (getpwnam_r(user, &pwd, pwd_buffer, sizeof (pwd_buffer)) == NULL)
		return (PAM_USER_UNKNOWN);

	if ((fp = fopen(DIAL_FILE, "rF")) == NULL)
		return (PAM_IGNORE);

	while ((p1 = fgets(line, sizeof (line), fp)) != NULL) {
		while (*p1 != '\n' && *p1 != ' ' && *p1 != '\t')
			p1++;
		*p1 = '\0';
		if (strcmp(line, ttyn) == 0)
			break;
	}

	(void) fclose(fp);

	if ((fp = fopen(DPASS_FILE, "rF")) == NULL) {
		syslog(LOG_ERR, "pam_dial_auth: %s without %s, returning %s.",
		    DIAL_FILE, DPASS_FILE,
		    pam_strerror(pamh, PAM_SYSTEM_ERR));
		(void) memset(line, 0, sizeof (line));
		return (PAM_SYSTEM_ERR);
	}

	if (p1 == NULL) {
		(void) fclose(fp);
		(void) memset(line, 0, sizeof (line));
		return (PAM_IGNORE);
	}

	defpass[0] = '\0';

	while ((p1 = fgets(line, sizeof (line)-1, fp)) != NULL) {
		while (*p1 && *p1 != ':')
			p1++;
		*p1++ = '\0';
		p2 = p1;
		while (*p1 && *p1 != ':')
			p1++;
		*p1 = '\0';
		if (pwd.pw_shell != NULL && strcmp(pwd.pw_shell, line) == 0)
			break;

		if (strcmp(SHELL, line) == 0)
			SCPYN(defpass, p2);
		p2 = NULL;
	}

	(void) memset(line, 0, sizeof (line));
	(void) fclose(fp);

	if (p2 == NULL)
		p2 = defpass;

	if (*p2 != '\0') {
		res = __pam_get_authtok(pamh, PAM_PROMPT, PAM_AUTHTOK,
		    dgettext(TEXT_DOMAIN, "Dialup Password: "), &password);

		if (res != PAM_SUCCESS) {
			return (res);
		}

		if (strcmp(crypt(password, p2), p2) != 0) {
			(void) memset(password, 0, strlen(password));
			free(password);
			return (PAM_AUTH_ERR);
		}
		(void) memset(password, 0, strlen(password));
		free(password);
	}

	return (PAM_SUCCESS);
}

/*
 * dummy pam_sm_setcred - does nothing
 */
/*ARGSUSED*/
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}

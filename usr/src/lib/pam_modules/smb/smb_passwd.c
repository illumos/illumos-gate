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

#include <sys/types.h>
#include <sys/varargs.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#include <libintl.h>
#include <passwdutil.h>

#include <smbsrv/libsmb.h>

/*PRINTFLIKE3*/
static void
error(boolean_t nowarn, pam_handle_t *pamh, char *fmt, ...)
{
	va_list ap;
	char message[PAM_MAX_MSG_SIZE];

	if (nowarn)
		return;

	va_start(ap, fmt);
	(void) vsnprintf(message, sizeof (message), fmt, ap);
	(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 1, &message,
	    NULL);
	va_end(ap);
}

/*PRINTFLIKE3*/
static void
info(boolean_t nowarn, pam_handle_t *pamh, char *fmt, ...)
{
	va_list ap;
	char message[PAM_MAX_MSG_SIZE];

	if (nowarn)
		return;

	va_start(ap, fmt);
	(void) vsnprintf(message, sizeof (message), fmt, ap);
	(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1, &message,
	    NULL);
	va_end(ap);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	boolean_t debug = B_FALSE;
	boolean_t nowarn = B_FALSE;
	pwu_repository_t files_rep;
	const char *user;
	char *local_user;
	const char *newpw;
	const char *service;
	int privileged;
	int res;
	int i;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = B_TRUE;
		else if (strcmp(argv[i], "nowarn") == 0)
			nowarn = B_TRUE;
	}

	if ((flags & PAM_PRELIM_CHECK) != 0)
		return (PAM_IGNORE);

	if ((flags & PAM_UPDATE_AUTHTOK) == 0)
		return (PAM_SYSTEM_ERR);

	if ((flags & PAM_SILENT) != 0)
		nowarn = B_TRUE;

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_smb_passwd: storing authtok");

	(void) pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	(void) pam_get_item(pamh, PAM_USER, (const void **)&user);

	if (user == NULL || *user == '\0') {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_smb_passwd: username is empty");
		return (PAM_USER_UNKNOWN);
	}

	(void) pam_get_item(pamh, PAM_AUTHTOK, (const void **)&newpw);
	if (newpw == NULL) {
		/*
		 * A module on the stack has removed PAM_AUTHTOK. We fail
		 */
		return (PAM_AUTHTOK_ERR);
	}

	/* Check to see if this is a local user */
	files_rep.type = "files";
	files_rep.scope = NULL;
	files_rep.scope_len = 0;
	res = __user_to_authenticate(user, &files_rep, &local_user,
	    &privileged);
	if (res != PWU_SUCCESS) {
		switch (res) {
		case PWU_NOT_FOUND:
			/* if not a local user, ignore */
			if (debug) {
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "pam_smb_passwd: %s is not local", user);
			}
			return (PAM_IGNORE);
		case PWU_DENIED:
			return (PAM_PERM_DENIED);
		}
		return (PAM_SYSTEM_ERR);
	}

	smb_pwd_init(B_FALSE);

	res = smb_pwd_setpasswd(user, newpw);

	smb_pwd_fini();

	/*
	 * now map the various return states to user messages
	 * and PAM return codes.
	 */
	switch (res) {
	case SMB_PWE_SUCCESS:
		info(nowarn, pamh, dgettext(TEXT_DOMAIN,
		    "%s: SMB password successfully changed for %s"),
		    service, user);
		return (PAM_SUCCESS);

	case SMB_PWE_STAT_FAILED:
		__pam_log(LOG_AUTH | LOG_ERR,
		    "%s: stat of SMB password file failed", service);
		return (PAM_SYSTEM_ERR);

	case SMB_PWE_OPEN_FAILED:
	case SMB_PWE_WRITE_FAILED:
	case SMB_PWE_CLOSE_FAILED:
	case SMB_PWE_UPDATE_FAILED:
		error(nowarn, pamh, dgettext(TEXT_DOMAIN,
		    "%s: Unexpected failure. SMB password database unchanged."),
		    service);
		return (PAM_SYSTEM_ERR);

	case SMB_PWE_BUSY:
		error(nowarn, pamh, dgettext(TEXT_DOMAIN,
		    "%s: SMB password database busy. Try again later."),
		    service);

		return (PAM_AUTHTOK_LOCK_BUSY);

	case SMB_PWE_USER_UNKNOWN:
		error(nowarn, pamh, dgettext(TEXT_DOMAIN,
		    "%s: %s does not exist."), service, user);
		return (PAM_USER_UNKNOWN);

	case SMB_PWE_USER_DISABLE:
		error(nowarn, pamh, dgettext(TEXT_DOMAIN,
		    "%s: %s is disable. SMB password database unchanged."),
		    service, user);
		return (PAM_IGNORE);

	case SMB_PWE_DENIED:
		return (PAM_PERM_DENIED);

	default:
		res = PAM_SYSTEM_ERR;
		break;
	}

	return (res);
}

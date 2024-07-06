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
#include <unistd.h>
#include <pwd.h>
#include <nss_dbdefs.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#include <libintl.h>
#include <passwdutil.h>

#include <errno.h>
#include <netsmb/smb_keychain.h>

/*ARGSUSED*/
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	boolean_t debug = B_FALSE;
	char dom[20];
	const char *user;
	const char *pw;
	const char *service;
	struct passwd pwbuf;
	char buf[NSS_BUFLEN_PASSWD];
	char *home;
	uid_t uid;
	int res = PAM_SUCCESS;
	int i, mask;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = B_TRUE;
	}

	/* Since our creds don't time out, ignore a refresh. */
	if ((flags & PAM_REFRESH_CRED) != 0)
		return (PAM_IGNORE);

	/* Check for unknown options */
	mask = PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED | PAM_DELETE_CRED;
	if ((flags & ~mask) != 0)
		return (PAM_IGNORE);

	(void) pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	(void) pam_get_item(pamh, PAM_USER, (const void **)&user);

	if (user == NULL || *user == '\0') {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_smbfs_login: username is empty");
		return (PAM_IGNORE);
	}
	if (getpwnam_r(user, &pwbuf, buf, sizeof (buf)) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_smbfs_login: username %s can't be found", user);
		return (PAM_IGNORE);
	}
	uid = pwbuf.pw_uid;
	home = pwbuf.pw_dir;

	(void) pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pw);
	if (pw == NULL) {
		/*
		 * A module on the stack has removed PAM_AUTHTOK.
		 */
		return (PAM_IGNORE);
	}

	res = smbfs_default_dom_usr(home, NULL, dom, sizeof (dom), NULL, 0);
	if (res != 0)
		(void) strcpy(dom, "WORKGROUP");

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_smbfs_login: service %s, dom %s, user %s",
		    service, dom, user);

	if ((flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) != 0)
		res = smbfs_keychain_add(uid, dom, user, pw);

	if ((flags & PAM_DELETE_CRED) != 0)
		res = smbfs_keychain_del(uid, dom, user);

	/*
	 * map errors to user messages and PAM return codes.
	 */
	switch (res) {
	case SMB_KEYCHAIN_SUCCESS:
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "smbfs password successfully stored for %s", user);
		break;

	case SMB_KEYCHAIN_BADPASSWD:
		__pam_log(LOG_AUTH | LOG_ERR, "smbfs password is invalid");
		break;

	case SMB_KEYCHAIN_BADDOMAIN:
		__pam_log(LOG_AUTH | LOG_ERR,
		    "%s: smbfs domain %s is invalid", service, dom);
		break;

	case SMB_KEYCHAIN_BADUSER:
		__pam_log(LOG_AUTH | LOG_ERR, "smbfs user %s is invalid", user);
		break;

	case SMB_KEYCHAIN_NODRIVER:
		__pam_log(LOG_AUTH | LOG_ERR,
		    "driver open failed (%s), smbfs password not stored",
		    strerror(errno));
		break;

	case SMB_KEYCHAIN_UNKNOWN:
		__pam_log(LOG_AUTH | LOG_ERR,
		    "Unexpected failure, smbfs password not stored");
		break;

	default:
		__pam_log(LOG_AUTH | LOG_ERR,
		    "driver ioctl failed (%s), smbfs password not stored",
		    strerror(errno));
		break;
	}

	return (PAM_IGNORE);
}

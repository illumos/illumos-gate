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

#include <syslog.h>
#include <pwd.h>
#include <unistd.h>
#include <strings.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <libintl.h>
#include <pwd.h>
#include <user_attr.h>
#include <secdb.h>
#include <nss_dbdefs.h>
#include <security/pam_impl.h>

static int roleinlist();

/*
 * pam_sm_acct_mgmt():
 *	Account management module
 *	This module disallows roles for primary logins and adds special
 *	checks to allow roles for secondary logins.
 */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uid_t uid;
	userattr_t *user_entry;
	char *kva_value;
	const char *username;
	const char *auser;
	const char *rhost;
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	struct passwd *pw_entry, pwd;
	char buf[NSS_BUFLEN_PASSWD];

	int i;
	int debug = 0;
	int allow_remote = 0;

	(void) pam_get_item(pamh, PAM_USER, (const void **)&username);
	(void) pam_get_item(pamh, PAM_AUSER, (const void **)&auser);
	(void) pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "allow_remote") == 0) {
			allow_remote = 1;
		} else if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "pam_roles:pam_sm_acct_mgmt: illegal module "
			    "option %s", argv[i]);
		}
	}

	if (debug) {
		const char *ruser;
		const char *service;

		(void) pam_get_item(pamh, PAM_RUSER, (const void **)&ruser);
		(void) pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
		__pam_log(LOG_AUTH | LOG_DEBUG, "pam_roles:pam_sm_acct_mgmt: "
		    "service = %s, allow_remote = %d, user = %s auser = %s "
		    "ruser = %s rhost = %s\n", (service) ? service : "not set",
		    allow_remote, (username) ? username : "not set",
		    (auser) ? auser: "not set", (ruser) ? ruser: "not set",
		    (rhost) ? rhost: "not set");
	}

	if (username == NULL)
		return (PAM_USER_UNKNOWN);

	/* stop masquerades by mapping username to uid to username */

	if ((pw_entry = getpwnam_r(username, &pwd, buf, sizeof (buf))) == NULL)
		return (PAM_USER_UNKNOWN);
	if ((pw_entry = getpwuid_r(pw_entry->pw_uid, &pwd, buf,
	    sizeof (buf))) == NULL)
		return (PAM_USER_UNKNOWN);
	/*
	 * If there's no user_attr entry for the primary user or it's not a
	 * role, no further checks are needed.
	 */

	if (((user_entry = getusernam(pw_entry->pw_name)) == NULL) ||
	    ((kva_value = kva_match((kva_t *)user_entry->attr,
	    USERATTR_TYPE_KW)) == NULL) ||
	    ((strcmp(kva_value, USERATTR_TYPE_NONADMIN_KW) != 0) &&
	    (strcmp(kva_value, USERATTR_TYPE_ADMIN_KW) != 0))) {
		free_userattr(user_entry);
		return (PAM_IGNORE);
	}
	free_userattr(user_entry);

	/* username is a role */

	if (strcmp(username, pw_entry->pw_name) != 0) {
		__pam_log(LOG_AUTH | LOG_ALERT,
		    "pam_roles:pam_sm_acct_mgmt: user name %s "
		    "maps to user id %d which is user name %s",
		    username, pw_entry->pw_uid, pw_entry->pw_name);

	}

	/* Who's the user requesting the role? */

	if (auser != NULL && *auser != '\0') {
		/* authenticated requesting user */

		user_entry = getusernam(auser);
	} else {
		/* user is implied by real UID */

		if ((uid = getuid()) == 0) {
			/*
			 * Root user_attr entry cannot have roles.
			 * Force error and deny access.
			 */
			user_entry = NULL;
		} else {
			if ((pw_entry = getpwuid_r(uid, &pwd, buf,
			    sizeof (buf))) == NULL) {
				return (PAM_USER_UNKNOWN);
			}
			user_entry = getusernam(pw_entry->pw_name);
		}
	}

	if ((rhost != NULL && *rhost != '\0') &&
	    allow_remote == 0) {
		/* don't allow remote roles for this service */

		free_userattr(user_entry);
		return (PAM_PERM_DENIED);
	}

	/*
	 * If the original user does not have a user_attr entry or isn't
	 * assigned the role being assumed, fail.
	 */

	if ((user_entry == NULL) ||
	    ((kva_value = kva_match((kva_t *)user_entry->attr,
	    USERATTR_ROLES_KW)) == NULL) ||
	    (roleinlist(kva_value, username) == 0)) {
		free_userattr(user_entry);
		(void) strlcpy(messages[0], dgettext(TEXT_DOMAIN,
		    "Roles can only be assumed by authorized users"),
		    sizeof (messages[0]));
		(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 1, messages,
		    NULL);
		return (PAM_PERM_DENIED);
	}

	free_userattr(user_entry);
	return (PAM_IGNORE);
}

int
roleinlist(char *list, char *role)
{
	char *lasts = (char *)NULL;
	char *rolename = (char *)strtok_r(list, ",", &lasts);

	while (rolename) {
		if (strcmp(rolename, role) == 0)
			return (1);
		else
			rolename = (char *)strtok_r(NULL, ",", &lasts);
	}
	return (0);
}

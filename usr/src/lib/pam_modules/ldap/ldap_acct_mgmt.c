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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ldap_headers.h"

/*ARGSUSED*/
static void
ldap_cleanup(
	pam_handle_t *pamh,
	void *data,
	int pam_status)
{
	free((ldap_authtok_data *)data);
}

/*
 * warn_user_passwd_will_expire	- warn the user when the password will
 *					  expire.
 */

static void
warn_user_passwd_will_expire(
	pam_handle_t *pamh,
	int sec_until_expired)
{
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	int	days = 0, hours = 0;
	int	seconds_d = 0, seconds_h = 0;

	days = sec_until_expired / 86400;
	seconds_d = sec_until_expired % 86400;
	hours = (days * 24) + seconds_d / 3600;
	seconds_h = seconds_d % 3600;

	if (sec_until_expired <= (86400 * 2)) {
		if (seconds_d <= 3600 && days == 0)
			(void) snprintf(messages[0], sizeof (messages[0]),
			    dgettext(TEXT_DOMAIN,
			    "Your password will expire within one hour."));
		else
			(void) snprintf(messages[0], sizeof (messages[0]),
			    dgettext(TEXT_DOMAIN,
				"Your password will expire in %d hours."),
				(seconds_h == 0) ? hours : hours + 1);
	} else {
			(void) snprintf(messages[0], sizeof (messages[0]),
			    dgettext(TEXT_DOMAIN,
				"Your password will expire in %d days."),
				(seconds_d == 0) ? days : days + 1);
	}

	(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1, messages, NULL);
}


/*
 * pam_sm_acct_mgmt	main account managment routine.
 *			This routine relies on the LDAP
 *			directory server to provide the
 * 			password aging and account lockout
 * 			information. This is done by first
 *			trying to authenticate the user and
 *			then checking the password status
 *			returned.
 *
 *			Returns: module error or specific
 *			error on failure.
 */

int
pam_sm_acct_mgmt(
	pam_handle_t *pamh,
	int	flags,
	int	argc,
	const char **argv)
{

	char			*user = NULL;
	int			result = PAM_AUTH_ERR;
	int			debug = 0;
	int			i;
	char			*password = NULL;
	ns_cred_t		*credp = NULL;
	int			nowarn = 0;
	int			sec_until_expired = 0;
	ldap_authtok_data	*status;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcasecmp(argv[i], "nowarn") == 0) {
			nowarn = 1;
			flags = flags | PAM_SILENT;
		}
		else
			syslog(LOG_DEBUG,
				"pam_ldap pam_sm_acct_mgmt: "
				"illegal option %s",
				argv[i]);
	}

	if ((result = pam_get_item(pamh, PAM_USER, (void **)&user))
							!= PAM_SUCCESS)
		goto out;

	if (debug)
		syslog(LOG_DEBUG,
			"ldap pam_sm_acct_mgmt(%s), flags = %x %s",
			(user)?user:"no-user", flags,
			(nowarn)? ", nowarn": "");

	if (user == NULL) {
		result = PAM_USER_UNKNOWN;
		goto out;
	}

	/* retrieve the password from the PAM handle */
	result = pam_get_item(pamh, PAM_AUTHTOK, (void **) &password);
	if (password == NULL) {
		if (result == PAM_SUCCESS)
			result = PAM_AUTH_ERR;
		goto out;
	}

	/* Try to authenticate to get password management info */
	result = authenticate(&credp, user,
			password, &sec_until_expired);
	/*
	 * process the password management info.
	 * If user needs to change the password immediately,
	 * just return the rc.
	 * Otherwise, reset rc to the appropriate PAM error or
	 * warn the user about password expiration.
	 */
	if (result == PAM_MAXTRIES)
		/* exceed retry limit: denied access to account */
		result = PAM_PERM_DENIED;
	else if (result == PAM_AUTHTOK_EXPIRED)
		/* password expired so account expired */
		result = PAM_ACCT_EXPIRED;
	else if (result == PAM_SUCCESS) {
		/*
		 * warn the user if the password
		 * is about to expire.
		 */
		if (!(flags & PAM_SILENT) &&
			sec_until_expired > 0)
			warn_user_passwd_will_expire(pamh,
				sec_until_expired);

	}

out:
	if (credp != NULL)
		(void) __ns_ldap_freeCred(&credp);

	/* store the password aging status in the pam handle */
	if (result != PAM_SUCCESS) {
		int pam_res;
		ldap_authtok_data *authtok_data;

		pam_res = pam_get_data(
			pamh, LDAP_AUTHTOK_DATA, (const void **)&authtok_data);

		if ((status = (ldap_authtok_data *)calloc
			(1, sizeof (ldap_authtok_data))) == NULL) {
			return (PAM_BUF_ERR);
		}

		if (pam_res == PAM_SUCCESS)
			(void) memcpy(status, authtok_data,
				sizeof (ldap_authtok_data));

		status->age_status = result;
		if (pam_set_data(pamh, LDAP_AUTHTOK_DATA, status, ldap_cleanup)
							!= PAM_SUCCESS) {
			free(status);
			return (PAM_SERVICE_ERR);
		}
	}

	return (result);
}

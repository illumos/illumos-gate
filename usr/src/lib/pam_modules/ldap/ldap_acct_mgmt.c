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
 * display_acct_unlock_time - Display the time left for the account to
 * get auto unlocked after the maximum login failures has reached.
 */
static void
display_acct_unlock_time(pam_handle_t *pamh, int sec_b4_unlock)
{
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	int	days = 0, hours = 0;
	int	seconds_d = 0, seconds_h = 0;

	/* Account is locked forever */
	if (sec_b4_unlock == -1) {
		(void) snprintf(messages[0], sizeof (messages[0]),
		dgettext(TEXT_DOMAIN,
		"Your account is locked, please contact administrator."));
		(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1,
			messages, NULL);
		return;
	}

	days = sec_b4_unlock / 86400;
	seconds_d = sec_b4_unlock % 86400;
	hours = (days * 24) + seconds_d / 3600;
	seconds_h = seconds_d % 3600;

	if (sec_b4_unlock <= (86400 * 2)) {
		if (seconds_d <= 3600 && days == 0)
			(void) snprintf(messages[0], sizeof (messages[0]),
				dgettext(TEXT_DOMAIN,
				"Your account is locked and will be unlocked"
				" within one hour."));
		else
			(void) snprintf(messages[0], sizeof (messages[0]),
				dgettext(TEXT_DOMAIN,
				"Your account is locked and will be unlocked"
				" in %d hours."),
				(seconds_h == 0) ? hours : hours + 1);
	} else {
		(void) snprintf(messages[0], sizeof (messages[0]),
			dgettext(TEXT_DOMAIN,
			"Your account is locked and will be unlocked"
			" in %d days."),
			(seconds_d == 0) ? days : days + 1);
	}

	(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1, messages, NULL);
}

/*
 * warn_user_passwd_expired - warn the user that the password has expired
 */
static void
warn_user_passwd_expired(pam_handle_t *pamh, int grace)
{
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	if (grace)
		(void) snprintf(messages[0], sizeof (messages[0]),
			dgettext(TEXT_DOMAIN,
			"Your password has expired. "
			"Number of grace logins allowed are %d."),
			grace);
	else
		(void) snprintf(messages[0], sizeof (messages[0]),
			dgettext(TEXT_DOMAIN,
			"Your password has expired."));

	(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1, messages, NULL);
}

/*
 * display_passwd_reset_msg - tell user that password has been reset by
 * administrator
 */
static void
display_passwd_reset_msg(pam_handle_t *pamh)
{
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	(void) snprintf(messages[0], sizeof (messages[0]),
			dgettext(TEXT_DOMAIN,
			"Your password has been reset by administrator."));

	(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1, messages, NULL);
}

/*
 * Retreives account management related attributes for the user using
 * default binding and does local account checks .
 *
 * Return Value: PAM_SUCCESS - If account is valid, seconds param will have
 *				seconds left for password to expire
 *		 PAM_ACCT_EXPIRED - If account is inactive
 *		 PAM_NEW_AUTHTOK_REQD - Password is reset by admin
 *		 PAM_AUTHTOK_EXPIRED - User password has expired, grace
 *				param will have no. of grace logins allowed
 *		 PAM_MAXTRIES - If maximum failure of wrong password has reached
 *				seconds param will have no. of seconds for the
 *				account to get unlocked
 *		 PAM_AUTH_ERR - Failure return code
 */
static int
get_account_mgmt(const char *user, int *seconds, int *grace)
{
	int rc	= PAM_AUTH_ERR;
	AcctUsableResponse_t	acctResp;

	(void *)memset((void*)&acctResp, 0, sizeof (acctResp));
	/* get the values for local account checking */
	if ((rc = __ns_ldap_getAcctMgmt(user, &acctResp))
		!= NS_LDAP_SUCCESS) {
		syslog(LOG_DEBUG,
			"__ns_ldap_getAcctMgmt() failed for %s with error %d",
				user, rc);
		return (PAM_AUTH_ERR);
	}

	if (acctResp.choice == 0) {
		/* should be able to login */
		*seconds =
			acctResp.AcctUsableResp.seconds_before_expiry;
		return (PAM_SUCCESS);
	} else if (acctResp.choice == 1) {
		/* cannot login */
		if (acctResp.AcctUsableResp.more_info.inactive)
			/* entry inactive */
			return (PAM_ACCT_EXPIRED);
		if (acctResp.AcctUsableResp.more_info.reset)
			/* password reset by administrator */
			return (PAM_NEW_AUTHTOK_REQD);
		if (acctResp.AcctUsableResp.more_info.expired) {
			/*
			 * password expired, check for grace logins.
			 */
			*grace =
				acctResp.AcctUsableResp.more_info.rem_grace;
			return (PAM_AUTHTOK_EXPIRED);
		}
		if (acctResp.AcctUsableResp.more_info.sec_b4_unlock) {
			/* max failures reached, seconds before unlock */
			*seconds =
				acctResp.AcctUsableResp.more_info.sec_b4_unlock;
			return (PAM_MAXTRIES);
		}
	}
	return (PAM_AUTH_ERR);
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
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{

	const char *user = NULL;
	int result = PAM_AUTH_ERR;
	int debug = 0;
	int i;
	const char *password = NULL;
	ns_cred_t *credp = NULL;
	int nowarn = 0;
	int seconds = 0, grace = 0;
	ldap_authtok_data *status;

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

	if ((result = pam_get_item(pamh, PAM_USER, (const void **)&user)) !=
	    PAM_SUCCESS) {
		goto out;
	}

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
	result = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
	if (password == NULL) {
		if (debug)
			syslog(LOG_DEBUG, "ldap pam_sm_acct_mgmt: "
			    "no password for user %s", user);
		/* Do local account checking */
		result = get_account_mgmt(user, &seconds, &grace);
	} else {
		/* Try to authenticate to get password management info */
		result = authenticate(&credp, user,
				password, &seconds);
	}

	/*
	 * process the password management info.
	 * If user needs to change the password immediately,
	 * just return the rc.
	 * Otherwise, reset rc to the appropriate PAM error or
	 * warn the user about password expiration.
	 */
	if (result == PAM_MAXTRIES) {
		/* exceed retry limit, denied access to account */
		if (!(flags & PAM_SILENT))
			display_acct_unlock_time(pamh, seconds);
		result = PAM_PERM_DENIED;
	} else if (result == PAM_ACCT_EXPIRED)
		/* account is inactivated */
		result = PAM_ACCT_EXPIRED;
	else if (result == PAM_AUTHTOK_EXPIRED) {
		if (!(flags & PAM_SILENT))
			warn_user_passwd_expired(pamh, grace);
		/* password expired, check for grace logins */
		if (grace > 0)
			result = PAM_SUCCESS;
		else
			result = PAM_AUTHTOK_EXPIRED;
	} else if (result == PAM_NEW_AUTHTOK_REQD) {
		/* password has been reset by administrator */
		if (!(flags & PAM_SILENT))
			display_passwd_reset_msg(pamh);
		result = PAM_NEW_AUTHTOK_REQD;
	} else if (result == PAM_SUCCESS) {
		/*
		 * warn the user if the password
		 * is about to expire.
		 */
		if (!(flags & PAM_SILENT) &&
			seconds > 0)
			warn_user_passwd_will_expire(pamh,
				seconds);

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

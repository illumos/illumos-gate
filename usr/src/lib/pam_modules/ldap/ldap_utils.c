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
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include "ldap_headers.h"
#include <malloc.h>

/* ******************************************************************** */
/*									*/
/* 		Utilities Functions					*/
/*									*/
/* ******************************************************************** */

/*
 * __ldap_to_pamerror():
 *	converts Native LDAP errors to an equivalent PAM error
 */
int
__ldap_to_pamerror(int ldaperror)
{
	switch (ldaperror) {
		case NS_LDAP_SUCCESS:
			return (PAM_SUCCESS);

		case NS_LDAP_OP_FAILED:
			return (PAM_PERM_DENIED);

		case NS_LDAP_MEMORY:
			return (PAM_BUF_ERR);

		case NS_LDAP_CONFIG:
			return (PAM_SERVICE_ERR);

		case NS_LDAP_NOTFOUND:
		case NS_LDAP_INTERNAL:
		case NS_LDAP_PARTIAL:
		case NS_LDAP_INVALID_PARAM:
			return (PAM_SYSTEM_ERR);

		default:
			return (PAM_SYSTEM_ERR);

	}
}

/*
 * authenticate():
 *	Returns
 *	  PAM_SUCCESS            if authenticated successfully
 *	  PAM_NEW_AUTHTOK_REQD   if authenticated but user needs to
 *                               change password immediately
 *        PAM_MAXTRIES           if authentication fails due to too
 *                               many login failures
 *        PAM_AUTHTOK_EXPIRED    if user password expired
 *        PAM_PERM_DENIED        if fail to authenticate
 *        PAM_AUTH_ERR           other errors
 *
 *      Also output the second-until-expired data if authenticated
 *      but the password is about to expire.
 *	Authentication is checked by calling __ns_ldap_auth.
 */
int
authenticate(ns_cred_t **credpp, const char *usrname, const char *pwd,
    int *sec_until_expired)
{
	int		result = PAM_AUTH_ERR;
	int		ldaprc;
	int		authstried = 0;
	char		*binddn = NULL;
	char		**certpath = NULL;
	ns_auth_t	**app;
	ns_auth_t	**authpp = NULL;
	ns_auth_t	*authp = NULL;
	ns_cred_t	*credp;
	ns_ldap_error_t	*errorp = NULL;

	if ((credp = (ns_cred_t *)calloc(1, sizeof (ns_cred_t))) == NULL)
		return (PAM_BUF_ERR);

	/* Fill in the user name and password */
	if ((usrname == NULL) || (pwd == NULL) || (usrname[0] == '\0') ||
		(pwd[0] == '\0'))
		goto out;

	ldaprc = __ns_ldap_uid2dn(usrname, &binddn, NULL, &errorp);
	if ((result = __ldap_to_pamerror(ldaprc)) != PAM_SUCCESS)
		goto out;

	credp->cred.unix_cred.userID = strdup(binddn);
	credp->cred.unix_cred.passwd = strdup(pwd);
	if ((credp->cred.unix_cred.userID == NULL) ||
		(credp->cred.unix_cred.passwd == NULL)) {
		result = PAM_BUF_ERR;
		goto out;
	}

	/* get host certificate path, if one is configured */
	ldaprc = __ns_ldap_getParam(NS_LDAP_HOST_CERTPATH_P,
		(void ***)&certpath, &errorp);
	if ((result = __ldap_to_pamerror(ldaprc)) != PAM_SUCCESS)
		goto out;
	if (certpath && *certpath)
		credp->hostcertpath = *certpath;

	/* Load the service specific authentication method */
	ldaprc = __ns_ldap_getServiceAuthMethods("pam_ldap", &authpp, &errorp);
	if ((result = __ldap_to_pamerror(ldaprc)) != PAM_SUCCESS)
		goto out;

	/*
	 * if authpp is null, there is no serviceAuthenticationMethod
	 * try default authenticationMethod
	 */
	if (authpp == NULL) {
		ldaprc = __ns_ldap_getParam(NS_LDAP_AUTH_P, (void ***)&authpp,
			&errorp);
		if ((result = __ldap_to_pamerror(ldaprc)) != PAM_SUCCESS)
			goto out;
	}

	/*
	 * if authpp is still null, then can not authenticate, syslog
	 * error message and return error
	 */
	if (authpp == NULL) {
		syslog(LOG_ERR,
			"pam_ldap: no authentication method configured");
		result = PAM_AUTH_ERR;
		goto out;
	}

	/*
	 * Walk the array and try all authentication methods in order except
	 * for "none".
	 */
	for (app = authpp; *app; app++) {
		authp = *app;
		/* what about disabling other mechanisms? "tls:sasl/EXTERNAL" */
		if (authp->type == NS_LDAP_AUTH_NONE)
			continue;
		authstried++;
		credp->auth.type = authp->type;
		credp->auth.tlstype = authp->tlstype;
		credp->auth.saslmech = authp->saslmech;
		credp->auth.saslopt = authp->saslopt;
		ldaprc = __ns_ldap_auth(credp, 0, &errorp, NULL, NULL);

		/*
		 * If rc is NS_LDAP_SUCCESS, done. If not,
		 * check rc and error info to see if
		 * there's any password management data.
		 * If yes, set appropriate PAM result code
		 * and exit.
		 */
		if (ldaprc == NS_LDAP_SUCCESS) {
			/*
			 * authenticated and no
			 * password management info, done.
			 */
			result = PAM_SUCCESS;
			goto out;
		} else if (ldaprc == NS_LDAP_SUCCESS_WITH_INFO) {
			/*
			 * authenticated but need to deal with
			 * password management info
			 */
			result = PAM_SUCCESS;

			/*
			 * clear sec_until_expired just in case
			 * there's no error info
			 */
			if (sec_until_expired)
				*sec_until_expired = 0;

			if (errorp) {
				if (errorp->pwd_mgmt.status ==
					NS_PASSWD_ABOUT_TO_EXPIRE) {
					/*
					 * password about to expire;
					 * retrieve "seconds until expired"
					 */
					if (sec_until_expired)
						*sec_until_expired =
						errorp->
						pwd_mgmt.sec_until_expired;
				} else if (errorp->pwd_mgmt.status ==
					NS_PASSWD_CHANGE_NEEDED)
					/*
					 * indicate that passwd need to change
					 * right away
					 */
					result = PAM_NEW_AUTHTOK_REQD;

				(void) __ns_ldap_freeError(&errorp);
			}
			goto out;
		} else if (ldaprc == NS_LDAP_INTERNAL) {

			if (errorp) {
				/*
				 * If error due to password policy, set
				 * appropriate PAM result code and exit.
				 */
				if (errorp->pwd_mgmt.status ==
					NS_PASSWD_RETRY_EXCEEDED)
					result = PAM_MAXTRIES;
				else if (errorp->pwd_mgmt.status ==
					NS_PASSWD_EXPIRED)
					result = PAM_AUTHTOK_EXPIRED;
				else {
					/*
					 * If invalid credential,
					 * return PAM_AUTH_ERR.
					 */
					if (errorp->status ==
						LDAP_INVALID_CREDENTIALS)
						result = PAM_AUTH_ERR;
				}
				(void) __ns_ldap_freeError(&errorp);
				goto out;
			}
		}

		/* done with the error info, clean it up */
		if (errorp)
			(void) __ns_ldap_freeError(&errorp);
	}
	if (authstried == 0) {
		syslog(LOG_ERR,
			"pam_ldap: no legal authentication method configured");
		result = PAM_AUTH_ERR;
		goto out;
	}
	result = PAM_PERM_DENIED;

out:
	if (binddn)
		free(binddn);

	if (credp && (result == PAM_SUCCESS ||
		result == PAM_NEW_AUTHTOK_REQD))
		if (credpp)
			*credpp = credp;
	else
		(void) __ns_ldap_freeCred(&credp);

	if (authpp)
		(void) __ns_ldap_freeParam((void ***)&authpp);

	if (errorp)
		(void) __ns_ldap_freeError(&errorp);

	return (result);
}

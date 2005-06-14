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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <kadm5/admin.h>
#include <krb5.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <libintl.h>
#include <netdb.h>
#include "utils.h"
#include <shadow.h>

#include "krb5_repository.h"

#define	KRB5_AUTOMIGRATE_DATA	"SUNW-KRB5-AUTOMIGRATE-DATA"

/*
 * pam_sm_acct_mgmt	  main account managment routine.
 */

static int
fetch_princ_entry(
	char *princ_str,
	char *password,
	kadm5_principal_ent_rec *prent,	/* out */
	krb5_timestamp *now, /* out */
	int debug)

{
	kadm5_ret_t		code;
	krb5_principal 		princ = 0;
	char 			admin_realm[1024];
	char			kprinc[2*MAXHOSTNAMELEN];
	char			*cpw_service;
	void 			*server_handle;
	krb5_context		context;
	kadm5_config_params	params;

	if (code = krb5_init_context(&context)) {
		return (PAM_SYSTEM_ERR);
	}

	if ((code = get_kmd_kuser(context, (const char *)princ_str, kprinc,
		2*MAXHOSTNAMELEN)) != 0) {
		return (code);
	}

	code = krb5_parse_name(context, kprinc, &princ);
	if (code != 0) {
		krb5_free_context(context);
		return (PAM_SYSTEM_ERR);
	}

	if (strlen(password) == 0) {
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (acct): fetch_princ_entry: pwlen=0");
		return (PAM_AUTH_ERR);
	}

	(void) strlcpy(admin_realm,
		    krb5_princ_realm(context, princ)->data,
		    sizeof (admin_realm));

	(void) memset((char *)&params, 0, sizeof (params));
	params.mask |= KADM5_CONFIG_REALM;
	params.realm = admin_realm;

	if (kadm5_get_cpw_host_srv_name(context, admin_realm, &cpw_service)) {
		syslog(LOG_ERR,
		    dgettext(TEXT_DOMAIN,
			"PAM-KRB5 (acct):  unable to get host based "
			"service name for realm '%s'"),
			admin_realm);
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		return (PAM_SYSTEM_ERR);
	}

	code = kadm5_init_with_password(kprinc, password, cpw_service,
					&params, KADM5_STRUCT_VERSION,
					KADM5_API_VERSION_2, &server_handle);
	if (code != 0) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (acct): fetch_princ_entry: "
			    "init_with_pw failed: code = %d", code);
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		return ((code == KADM5_BAD_PASSWORD) ?
			PAM_AUTH_ERR : PAM_SYSTEM_ERR);
	}

	if (_kadm5_get_kpasswd_protocol(server_handle) != KRB5_CHGPWD_RPCSEC) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (acct): fetch_princ_entry: "
			    "non-RPCSEC_GSS chpw server, can't get "
			    "princ entry");
		(void) kadm5_destroy(server_handle);
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		return (PAM_SYSTEM_ERR);
	}

	code = kadm5_get_principal(server_handle, princ, prent,
				KADM5_PRINCIPAL_NORMAL_MASK);

	if (code != 0) {
		(void) kadm5_destroy(server_handle);
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		return ((code == KADM5_UNK_PRINC) ?
			PAM_USER_UNKNOWN : PAM_SYSTEM_ERR);
	}

	if (code = krb5_timeofday(context, now)) {
		(void) kadm5_destroy(server_handle);
		krb5_free_principal(context, princ);
		krb5_free_context(context);
		syslog(LOG_ERR,
		    dgettext(TEXT_DOMAIN,
			    "PAM-KRB5 (acct): krb5_timeofday fail: code=%d"),
		    code);
		return (PAM_SYSTEM_ERR);
	}

	(void) kadm5_destroy(server_handle);
	krb5_free_principal(context, princ);
	krb5_free_context(context);

	return (PAM_SUCCESS);
}

/*
 * exp_warn
 *
 * warn the user if her pw is set to expire
 *
 * We use the kadm protocol and chpw svc to fetch the user's KDC db
 * entry.  The user's default perms on the KDC db should allow this.
 * Note since the SEAM kadm API uses rpcsec_gss (which is diff from
 * what MS and MIT 1.2 and before uses), this probably only works
 * with a SEAM KDC.
 */

static int
exp_warn(
	pam_handle_t *pamh,
	char *user,
	char *password,
	int debug)

{
	int err;
	kadm5_principal_ent_rec prent;
	krb5_timestamp  now, days;
	char    messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

	if (debug)
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (acct): exp_warn start: user = '%s'",
		    user ? user : "<null>");

	if (!pamh || !user || !password) {
		err = PAM_SERVICE_ERR;
		goto out;
	}

	(void) memset(&prent, 0, sizeof (prent));
	if ((err = fetch_princ_entry(user, password, &prent,
				    &now, debug)) != PAM_SUCCESS) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (acct): exp_warn: fetch_pr failed %d",
			    err);
		goto out;
	}

	if (debug)
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (acct): exp_warn: fetch_princ success:"
		    " princ exp=%ld pw_exp = %ld, now =%ld, days=%ld",
		    prent.princ_expire_time,
		    prent.pw_expiration, now,
		    prent.pw_expiration > 0
		    ? ((prent.pw_expiration - now) / DAY)
		    : 0);

	/* warn user if principal's pw is set to expire */
	if (prent.pw_expiration > 0) {
		days = (prent.pw_expiration - now) / DAY;
		if (days <= 0)
			(void) snprintf(messages[0],
				sizeof (messages[0]),
				dgettext(TEXT_DOMAIN,
		"Your Kerberos password will expire within 24 hours.\n"));
		else if (days == 1)
			(void) snprintf(messages[0],
				sizeof (messages[0]),
				dgettext(TEXT_DOMAIN,
			"Your Kerberos password will expire in 1 day.\n"));
		else
			(void) snprintf(messages[0],
				sizeof (messages[0]),
				dgettext(TEXT_DOMAIN,
			"Your Kerberos password will expire in %d days.\n"),
				(int)days);

		(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1,
					messages, NULL);
	}

	/* things went smooth */
	err = PAM_SUCCESS;

out:
	if (debug)
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (acct): exp_warn end: err = %d", err);

	return (err);
}

/*
 * pam_krb5 acct_mgmt
 *
 * we do
 *    - check if pw expired (flag set in auth)
 *    - warn user if pw is set to expire
 *
 * notes
 *    - we require the auth module to have already run (sets module data)
 *    - we don't worry about an expired princ cuz if that's the case,
 *      auth would have failed
 */
int
pam_sm_acct_mgmt(
	pam_handle_t *pamh,
	int	flags,
	int	argc,
	const char **argv)

{
	char *user = NULL;
	char *userdata = NULL;
	int err;
	int i;
	krb5_module_data_t *kmd = NULL;
	char    messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	int debug = 0;  /* pam.conf entry option */
	int nowarn = 0; /* pam.conf entry option, no expire warnings */
	pam_repository_t	*rep_data = NULL;

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcasecmp(argv[i], "nowarn") == 0) {
			nowarn = 1;
			flags = flags | PAM_SILENT;
		} else {
			syslog(LOG_ERR,
			    "PAM-KRB5 (acct): illegal option %s",
			    argv[i]);
		}
	}

	if (debug)
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (acct): debug=%d, nowarn=%d",
		    debug, nowarn);

	err = pam_get_item(pamh, PAM_REPOSITORY, (void **)&rep_data);
	if (rep_data != NULL) {
		/*
		 * If the repository is not ours,
		 * return PAM_IGNORE.
		 */
		if (strcmp(rep_data->type, KRB5_REPOSITORY_NAME) != 0) {
			if (debug)
				syslog(LOG_DEBUG, "PAM-KRB5 (acct): wrong"
					"repository found (%s), returning "
					"PAM_IGNORE", rep_data->type);
			return (PAM_IGNORE);
		}
	}


	/* get user name */
	if ((err = pam_get_item(pamh, PAM_USER, (void **) &user))
	    != PAM_SUCCESS) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
					"PAM-KRB5 (acct):"
					" get user failed: err=%d"),
		    err);
		goto out;
	}

	if (user == NULL) {
		err = PAM_USER_UNKNOWN;
		goto out;
	}

	/* get pam_krb5_migrate specific data */
	err = pam_get_data(pamh, KRB5_AUTOMIGRATE_DATA,
					(const void **)&userdata);
	if (err != PAM_SUCCESS) {
		if (debug)
			syslog(LOG_DEBUG, dgettext(TEXT_DOMAIN,
				"PAM-KRB5 (acct): "
				"no module data for KRB5_AUTOMIGRATE_DATA"));
	} else {
		/*
		 * We try and reauthenticate, since this user has a
		 * newly created krb5 principal via the pam_krb5_migrate
		 * auth module. That way, this new user will have fresh
		 * creds (assuming pam_sm_authenticate() succeeds).
		 */
		if (strcmp(user, userdata) == 0)
			(void) pam_sm_authenticate(pamh, flags, argc,
					(const char **)argv);
		else
			if (debug)
				syslog(LOG_DEBUG, dgettext(TEXT_DOMAIN,
				"PAM-KRB5 (acct): PAM_USER %s"
				"does not match user %s from pam_get_data()"),
				user, (char *)userdata);
	}

	/* get krb5 module data  */
	if ((err = pam_get_data(pamh, KRB5_DATA, (const void **)&kmd))
	    != PAM_SUCCESS) {
		if (err == PAM_NO_MODULE_DATA) {
			/*
			 * pam_auth never called (possible config
			 * error; no pam_krb5 auth entry in pam.conf)
			 * or
			 * auth module returned before module data
			 * was instantiated (normal for auth 'acceptor')
			 */
			if (debug)
				syslog(LOG_DEBUG,
				    "PAM-KRB5 (acct): no module data");
			err = PAM_IGNORE;
			goto out;
		} else {
			syslog(LOG_ERR,
			    dgettext(TEXT_DOMAIN,
				    "PAM-KRB5 (acct): get module"
				    " data failed: err=%d"),
			    err);
		}
		goto out;
	}

	debug = debug || kmd->debug;

	/*
	 * auth mod set status to ignore, most likely cuz root key is
	 * in keytab, so skip other checks and return ignore
	 */
	if (kmd->auth_status == PAM_IGNORE) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (acct): kmd auth_status is IGNORE");
		err = PAM_IGNORE;
		goto out;
	}

	/*
	 * age_status will be set to PAM_NEW_AUTHTOK_REQD in pam_krb5's
	 * 'auth' if the user's key/pw has expired and needs to be changed
	 */
	if (kmd->age_status == PAM_NEW_AUTHTOK_REQD) {
		if (!nowarn) {
			(void) snprintf(messages[0], sizeof (messages[0]),
				dgettext(TEXT_DOMAIN,
				"Your Kerberos password has expired.\n"));
			(void) __pam_display_msg(pamh, PAM_TEXT_INFO,
					1, messages, NULL);
		}
		err = PAM_NEW_AUTHTOK_REQD;
		goto out;
	}

	if (!(flags & PAM_SILENT) && !nowarn && kmd->password) {
		/* if we fail, let it slide, it's only a warning brah */
		(void) exp_warn(pamh, user, kmd->password, debug);
	}

	/* everything a-ok */
	err = PAM_SUCCESS;

out:
	if (debug)
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (acct): end: %s", pam_strerror(pamh, err));

	return (err);
}

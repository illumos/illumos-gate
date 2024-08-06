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

#include <kadm5/admin.h>
#include <krb5.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <syslog.h>
#include <libintl.h>

#define	KRB5_AUTOMIGRATE_DATA	"SUNW-KRB5-AUTOMIGRATE-DATA"

static void krb5_migrate_cleanup(pam_handle_t *pamh, void *data,
				int pam_status);

/*
 * pam_sm_authenticate - Authenticate a host-based client service
 * principal to kadmind in order to permit the creation of a new user
 * principal in the client's default realm.
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	const char *user = NULL;
	char *userdata = NULL;
	char *olduserdata = NULL;
	char *password = NULL;
	int err, i;
	time_t now;

	/* pam.conf options */
	int debug = 0;
	int quiet = 0;
	int expire_pw = 0;
	char *service = NULL;

	/* krb5-specific defines */
	kadm5_ret_t retval = 0;
	krb5_context context = NULL;
	kadm5_config_params params;
	krb5_principal svcprinc;
	char *svcprincstr = NULL;
	krb5_principal userprinc;
	char *userprincstr = NULL;
	int strlength = 0;
	kadm5_principal_ent_rec kadm5_userprinc;
	char *kadmin_princ = NULL;
	char *def_realm = NULL;
	void *handle = NULL;
	long mask = 0;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else if (strcmp(argv[i], "quiet") == 0) {
			quiet = 1;
		} else if (strcmp(argv[i], "expire_pw") == 0) {
			expire_pw = 1;
		} else if ((strstr(argv[i], "client_service=") != NULL) &&
		    (strcmp((strstr(argv[i], "=") + 1), "") != 0)) {
			service = strdup(strstr(argv[i], "=") + 1);
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "PAM-KRB5-AUTOMIGRATE (auth): unrecognized "
			    "option %s", argv[i]);
		}
	}

	if (flags & PAM_SILENT)
		quiet = 1;

	err = pam_get_item(pamh, PAM_USER, (const void **)&user);
	if (err != PAM_SUCCESS) {
		goto cleanup;
	}

	/*
	 * Check if user name is *not* NULL
	 */
	if (user == NULL || (user[0] == '\0')) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5-AUTOMIGRATE (auth): user empty or null");
		goto cleanup;
	}

	/*
	 * Can't tolerate memory failure later on. Get a copy
	 * before any work is done.
	 */
	if ((userdata = strdup(user)) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Out of memory");
		goto cleanup;
	}

	/*
	 * Grok the user password
	 */
	err = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
	if (err != PAM_SUCCESS) {
		goto cleanup;
	}

	if (password == NULL || (password[0] == '\0')) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5-AUTOMIGRATE (auth): "
			    "authentication token is empty or null");
		goto cleanup;
	}


	/*
	 * Now, lets do the all krb5/kadm5 setup for the principal addition
	 */
	if (retval = krb5_init_secure_context(&context)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error initializing "
		    "krb5: %s", error_message(retval));
		goto cleanup;
	}

	(void) memset((char *)&params, 0, sizeof (params));
	(void) memset(&kadm5_userprinc, 0, sizeof (kadm5_userprinc));

	if (def_realm == NULL && krb5_get_default_realm(context, &def_realm)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error while obtaining "
		    "default krb5 realm");
		goto cleanup;
	}

	params.mask |= KADM5_CONFIG_REALM;
	params.realm = def_realm;

	if (kadm5_get_adm_host_srv_name(context, def_realm,
	    &kadmin_princ)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error while obtaining "
		    "host based service name for realm %s\n", def_realm);
		goto cleanup;
	}

	if (retval = krb5_sname_to_principal(context, NULL,
	    (service != NULL) ? service : "host", KRB5_NT_SRV_HST, &svcprinc)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error while creating "
		    "krb5 host service principal: %s",
		    error_message(retval));
		goto cleanup;
	}

	if (retval = krb5_unparse_name(context, svcprinc,
	    &svcprincstr)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error while "
		    "unparsing principal name: %s", error_message(retval));
		krb5_free_principal(context, svcprinc);
		goto cleanup;
	}

	krb5_free_principal(context, svcprinc);

	/*
	 * Initialize the kadm5 connection using the default keytab
	 */
	retval = kadm5_init_with_skey(svcprincstr, NULL,
	    kadmin_princ, &params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_2,
	    NULL, &handle);
	if (retval) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error while "
		    "doing kadm5_init_with_skey: %s", error_message(retval));
		goto cleanup;
	}


	/*
	 * The RPCSEC_GSS connection has been established; Lets check to see
	 * if the corresponding user principal exists in the KDC database.
	 * If not, lets create a new one.
	 */

	strlength = strlen(user) + strlen(def_realm) + 2;
	if ((userprincstr = malloc(strlength)) == NULL)
		goto cleanup;
	(void) strlcpy(userprincstr, user, strlength);
	(void) strlcat(userprincstr, "@", strlength);
	(void) strlcat(userprincstr, def_realm, strlength);


	if (retval = krb5_parse_name(context, userprincstr,
	    &userprinc)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error while "
		    "parsing user principal name: %s",
		    error_message(retval));
		goto cleanup;
	}

	retval = kadm5_get_principal(handle, userprinc, &kadm5_userprinc,
	    KADM5_PRINCIPAL_NORMAL_MASK);

	krb5_free_principal(context, userprinc);

	if (retval) {
		switch (retval) {
		case KADM5_AUTH_GET:
			if (debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5-AUTOMIGRATE (auth): %s does "
				    "not have the GET privilege "
				    "for kadm5_get_principal: %s",
				    svcprincstr, error_message(retval));
			break;

		case KADM5_UNK_PRINC:
		default:
			break;
		}
		/*
		 * We will try & add this principal anyways, continue on ...
		 */
		(void) memset(&kadm5_userprinc, 0, sizeof (kadm5_userprinc));
	} else {
		/*
		 * Principal already exists in the KDC database, quit now
		 */
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5-AUTOMIGRATE (auth): Principal %s "
			    "already exists in Kerberos KDC database",
			    userprincstr);
		goto cleanup;
	}



	if (retval = krb5_parse_name(context, userprincstr,
	    &(kadm5_userprinc.principal))) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5-AUTOMIGRATE (auth): Error while "
		    "parsing user principal name: %s",
		    error_message(retval));
		goto cleanup;
	}

	if (expire_pw) {
		(void) time(&now);
		/*
		 * The local system time could actually be later than the
		 * system time of the KDC we are authenticating to.  We expire
		 * w/the local system time minus clockskew so that we are
		 * assured that it is expired on this login, not the next.
		 */
		now -= context->clockskew;
		kadm5_userprinc.pw_expiration = now;
		mask |= KADM5_PW_EXPIRATION;
	}

	mask |= KADM5_PRINCIPAL;
	retval = kadm5_create_principal(handle, &kadm5_userprinc,
	    mask, password);
	if (retval) {
		switch (retval) {
		case KADM5_AUTH_ADD:
			if (debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5-AUTOMIGRATE (auth): %s does "
				    "not have the ADD privilege "
				    "for kadm5_create_principal: %s",
				    svcprincstr, error_message(retval));
			break;

		default:
			__pam_log(LOG_AUTH | LOG_ERR,
			    "PAM-KRB5-AUTOMIGRATE (auth): Generic error"
			    "while doing kadm5_create_principal: %s",
			    error_message(retval));
			break;
		}
		goto cleanup;
	}

	/*
	 * Success, new user principal has been added !
	 */
	if (!quiet) {
		char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];

		(void) snprintf(messages[0], sizeof (messages[0]),
		    dgettext(TEXT_DOMAIN, "\nUser `%s' has been "
		    "automatically migrated to the Kerberos realm %s\n"),
		    user, def_realm);
		(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1,
		    messages, NULL);
	}
	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5-AUTOMIGRATE (auth): User %s "
		    "has been added to the Kerberos KDC database",
		    userprincstr);

	/*
	 * Since this is a new krb5 principal, do a pam_set_data()
	 * for possible use by the acct_mgmt routine of pam_krb5(7)
	 */
	if (pam_get_data(pamh, KRB5_AUTOMIGRATE_DATA,
	    (const void **)&olduserdata) == PAM_SUCCESS) {
		/*
		 * We created a princ in a previous run on the same handle and
		 * it must have been for a different PAM_USER / princ name,
		 * otherwise we couldn't succeed here, unless that princ
		 * got deleted.
		 */
		if (olduserdata != NULL)
			free(olduserdata);
	}
	if (pam_set_data(pamh, KRB5_AUTOMIGRATE_DATA, userdata,
	    krb5_migrate_cleanup) != PAM_SUCCESS) {
		free(userdata);
	}

cleanup:
	if (service)
		free(service);
	if (kadmin_princ)
		free(kadmin_princ);
	if (svcprincstr)
		free(svcprincstr);
	if (userprincstr)
		free(userprincstr);
	if (def_realm)
		free(def_realm);
	(void) kadm5_free_principal_ent(handle, &kadm5_userprinc);
	(void) kadm5_destroy((void *)handle);
	if (context != NULL)
		krb5_free_context(context);

	return (PAM_IGNORE);
}

/*ARGSUSED*/
static void
krb5_migrate_cleanup(pam_handle_t *pamh, void *data, int pam_status) {
	if (data != NULL)
		free((char *)data);
}

/*ARGSUSED*/
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return (PAM_IGNORE);
}

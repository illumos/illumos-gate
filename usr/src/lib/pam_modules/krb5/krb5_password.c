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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

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
#include "krb5_repository.h"

extern int attempt_krb5_auth(pam_handle_t *, krb5_module_data_t *, const char *,
    char **, boolean_t);
extern int krb5_verifypw(const char *, char *, int);

static void display_msg(pam_handle_t *, int, char *);
static void display_msgs(pam_handle_t *, int, int,
    char msgs[][PAM_MAX_MSG_SIZE]);
static int krb5_changepw(pam_handle_t *, const char *, char *, char *, int);

/*
 * set_ccname()
 *
 * set KRB5CCNAME shell var
 */
static void
set_ccname(
	pam_handle_t *pamh,
	krb5_module_data_t *kmd,
	int login_result,
	int debug)
{
	int result;

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (password): password: finalize"
		    " ccname env, login_result =%d, env ='%s'",
		    login_result, kmd->env ? kmd->env : "<null>");

	if (kmd->env) {

		if (login_result == PAM_SUCCESS) {
				/*
				 * Put ccname into the pamh so that login
				 * apps can pick this up when they run
				 * pam_getenvlist().
				 */
			if ((result = pam_putenv(pamh, kmd->env))
			    != PAM_SUCCESS) {
				/* should not happen but... */
				__pam_log(LOG_AUTH | LOG_ERR,
				    "PAM-KRB5 (password):"
				    " pam_putenv failed: result: %d",
				    result);
				goto cleanupccname;
			}
		} else {
		cleanupccname:
				/* for lack of a Solaris unputenv() */
			krb5_unsetenv(KRB5_ENV_CCNAME);
			free(kmd->env);
			kmd->env = NULL;
		}
	}
}

/*
 * get_set_creds()
 *
 * do a krb5 login to get and set krb5 creds (needed after a pw change
 * on pw expire on login)
 */
static void
get_set_creds(
	pam_handle_t *pamh,
	krb5_module_data_t *kmd,
	const char *user,
	char *newpass,
	int debug)
{
	int login_result;

	if (!kmd || kmd->age_status != PAM_NEW_AUTHTOK_REQD)
		return;

	/*
	 * if pw has expired, get/set krb5 creds ala auth mod
	 *
	 * pwchange verified user sufficiently, so don't request strict
	 * tgt verification (will cause rcache perm issues possibly anyways)
	 */
	login_result = attempt_krb5_auth(pamh, kmd, user, &newpass, 0);
	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (password): get_set_creds: login_result= %d",
		    login_result);
	/*
	 * the krb5 login should not fail, but if so,
	 * warn the user they have to kinit(1)
	 */
	if (login_result != PAM_SUCCESS) {
		display_msg(pamh, PAM_TEXT_INFO,
		    dgettext(TEXT_DOMAIN,
		    "Warning: "
		    "Could not cache Kerberos"
		    " credentials, please run "
		    "kinit(1) or re-login\n"));
	}
	set_ccname(pamh, kmd, login_result, debug);
}
/*
 * This is the PAM Kerberos Password Change module
 *
 */

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{

	const char *user;
	int err, result = PAM_AUTHTOK_ERR;
	char *newpass = NULL;
	char *oldpass = NULL;
	int i;
	int debug = 0;
	uid_t pw_uid;
	krb5_module_data_t *kmd = NULL;
	const pam_repository_t *rep_data = NULL;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else
			__pam_log(LOG_AUTH | LOG_ERR,
			    "PAM-KRB5 (password): illegal option %s",
			    argv[i]);
	}

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (password): start: flags = %x",
		    flags);

	(void) pam_get_item(pamh, PAM_REPOSITORY, (const void **)&rep_data);

	if (rep_data != NULL) {
		if (strcmp(rep_data->type, KRB5_REPOSITORY_NAME) != 0) {
			if (debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (auth): wrong"
				    "repository found (%s), returning "
				    "PAM_IGNORE", rep_data->type);
			return (PAM_IGNORE);
		}
	}

	if (flags & PAM_PRELIM_CHECK) {
		/* Nothing to do here */
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (password): prelim check");
		return (PAM_IGNORE);
	}

	/* make sure PAM framework is telling us to update passwords */
	if (!(flags & PAM_UPDATE_AUTHTOK)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (password): bad flags: %d",
		    flags);
		return (PAM_SYSTEM_ERR);
	}


	if ((err = pam_get_data(pamh, KRB5_DATA, (const void **)&kmd))
	    != PAM_SUCCESS) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (password): get mod data failed %d",
			    err);
		kmd = NULL;
	}

	if (flags & PAM_CHANGE_EXPIRED_AUTHTOK) {
		/* let's make sure we know the krb5 pw has expired */

		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (password): kmd age status %d",
			    kmd ? kmd->age_status : -99);

		if (!kmd || kmd->age_status != PAM_NEW_AUTHTOK_REQD)
			return (PAM_IGNORE);
	}

	(void) pam_get_item(pamh, PAM_USER, (const void **)&user);

	if (user == NULL || *user == '\0') {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (password): username is empty");
		return (PAM_USER_UNKNOWN);
	}

	if (!get_pw_uid(user, &pw_uid)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (password): can't get uid for %s", user);
		return (PAM_USER_UNKNOWN);
	}

	/*
	 * if root key exists in the keytab, it's a random key so no
	 * need to prompt for pw and we just return IGNORE
	 */
	if ((strcmp(user, ROOT_UNAME) == 0) &&
	    key_in_keytab(user, debug)) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (password): "
			    "key for '%s' in keytab, returning IGNORE", user);
		result = PAM_IGNORE;
		goto out;
	}

	(void) pam_get_item(pamh, PAM_AUTHTOK, (const void **)&newpass);

	/*
	 * If the preauth type done didn't use a passwd just ignore the error.
	 */
	if (newpass == NULL)
		if (kmd && kmd->preauth_type == KRB_PKINIT)
			return (PAM_IGNORE);
		else
			return (PAM_SYSTEM_ERR);

	(void) pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **)&oldpass);

	if (oldpass == NULL)
		if (kmd && kmd->preauth_type == KRB_PKINIT)
			return (PAM_IGNORE);
		else
			return (PAM_SYSTEM_ERR);

	result = krb5_verifypw(user, oldpass, debug);
	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (password): verifypw %d", result);

	/*
	 * If it's a bad password or general failure, we are done.
	 */
	if (result != 0) {
		/*
		 * if the preauth type done didn't use a passwd just ignore the
		 * error.
		 */
		if (kmd && kmd->preauth_type == KRB_PKINIT)
			return (PAM_IGNORE);

		if (result == 2)
			display_msg(pamh, PAM_ERROR_MSG, dgettext(TEXT_DOMAIN,
			    "Old Kerberos password incorrect\n"));
		return (PAM_AUTHTOK_ERR);
	}

	/*
	 * If the old password verifies try to change it regardless of the
	 * preauth type and do not ignore the error.
	 */
	result = krb5_changepw(pamh, user, oldpass, newpass, debug);
	if (result == PAM_SUCCESS) {
		display_msg(pamh, PAM_TEXT_INFO, dgettext(TEXT_DOMAIN,
		    "Kerberos password successfully changed\n"));

		get_set_creds(pamh, kmd, user, newpass, debug);
	}

out:
	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (password): out: returns %d",
		    result);

	return (result);
}

int
krb5_verifypw(
	const char 	*princ_str,
	char	*old_password,
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

	(void) memset((char *)&params, 0, sizeof (params));

	if (code = krb5_init_secure_context(&context)) {
		return (6);
	}

	if ((code = get_kmd_kuser(context, princ_str, kprinc,
	    2*MAXHOSTNAMELEN)) != 0) {
		return (code);
	}

	/* Need to get a krb5_principal struct */

	code = krb5_parse_name(context, kprinc, &princ);

	if (code != 0)
		return (6);

	if (strlen(old_password) == 0) {
		krb5_free_principal(context, princ);
		return (5);
	}

	(void) strlcpy(admin_realm,
	    krb5_princ_realm(context, princ)->data,
	    sizeof (admin_realm));

	params.mask |= KADM5_CONFIG_REALM;
	params.realm = admin_realm;


	if (kadm5_get_cpw_host_srv_name(context, admin_realm, &cpw_service)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (password): unable to get host based "
		    "service name for realm %s\n",
		    admin_realm);
		krb5_free_principal(context, princ);
		return (3);
	}

	code = kadm5_init_with_password(kprinc, old_password, cpw_service,
	    &params, KADM5_STRUCT_VERSION,
	    KADM5_API_VERSION_2, NULL,
	    &server_handle);
	if (code != 0) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5: krb5_verifypw: init_with_pw"
			    " failed: (%s)", error_message(code));
		krb5_free_principal(context, princ);
		return ((code == KADM5_BAD_PASSWORD) ? 2 : 3);
	}

	krb5_free_principal(context, princ);

	(void) kadm5_destroy(server_handle);

	return (0);
}

/*
 * Function: krb5_changepw
 *
 * Purpose: Initialize and call lower level routines to change a password
 *
 * Arguments:
 *
 *	princ_str	principal name to use, optional
 *	old_password 	old password
 *	new_password  	new password
 *
 * Returns:
 *                      exit status of PAM_SUCCESS for success
 *			else returns PAM failure
 *
 * Requires:
 *	Passwords cannot be more than 255 characters long.
 *
 * Modifies:
 *
 * Changes the principal's password.
 *
 */
static int
krb5_changepw(
	pam_handle_t *pamh,
	const char *princ_str,
	char *old_password,
	char *new_password,
	int debug)
{
	kadm5_ret_t		code;
	krb5_principal 		princ = 0;
	char 			msg_ret[1024], admin_realm[1024];
	char			kprinc[2*MAXHOSTNAMELEN];
	char			*cpw_service;
	void 			*server_handle;
	krb5_context		context;
	kadm5_config_params	params;

	(void) memset((char *)&params, 0, sizeof (params));

	if (krb5_init_secure_context(&context) != 0)
		return (PAM_SYSTEM_ERR);

	if ((code = get_kmd_kuser(context, princ_str, kprinc,
	    2*MAXHOSTNAMELEN)) != 0) {
		return (code);
	}

	/* Need to get a krb5_principal struct */

	code = krb5_parse_name(context, kprinc, &princ);
	if (code != 0)
		return (PAM_SYSTEM_ERR);

	if (strlen(old_password) == 0) {
		krb5_free_principal(context, princ);
		return (PAM_AUTHTOK_ERR);
	}

	(void) snprintf(admin_realm, sizeof (admin_realm), "%s",
	    krb5_princ_realm(context, princ)->data);
	params.mask |= KADM5_CONFIG_REALM;
	params.realm = admin_realm;


	if (kadm5_get_cpw_host_srv_name(context, admin_realm, &cpw_service)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (password):unable to get host based "
		    "service name for realm %s\n",
		    admin_realm);
		return (PAM_SYSTEM_ERR);
	}

	code = kadm5_init_with_password(kprinc, old_password, cpw_service,
	    &params, KADM5_STRUCT_VERSION,
	    KADM5_API_VERSION_2, NULL,
	    &server_handle);
	free(cpw_service);
	if (code != 0) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (password): changepw: "
			    "init_with_pw failed:  (%s)", error_message(code));
		krb5_free_principal(context, princ);
		return ((code == KADM5_BAD_PASSWORD) ?
		    PAM_AUTHTOK_ERR : PAM_SYSTEM_ERR);
	}

	code = kadm5_chpass_principal_util(server_handle, princ,
	    new_password,
	    NULL /* don't need pw back */,
	    msg_ret,
	    sizeof (msg_ret));

	if (code) {
		char msgs[2][PAM_MAX_MSG_SIZE];

		(void) snprintf(msgs[0], PAM_MAX_MSG_SIZE, "%s",
		    dgettext(TEXT_DOMAIN,
		    "Kerberos password not changed: "));
		(void) snprintf(msgs[1], PAM_MAX_MSG_SIZE, "%s", msg_ret);

		display_msgs(pamh, PAM_ERROR_MSG, 2, msgs);
	}

	krb5_free_principal(context, princ);

	(void) kadm5_destroy(server_handle);

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (password): changepw: end %d", code);

	if (code != 0)
		return (PAM_AUTHTOK_ERR);

	return (PAM_SUCCESS);
}

static void
display_msgs(pam_handle_t *pamh,
	int msg_style, int nmsg, char msgs[][PAM_MAX_MSG_SIZE])
{
	(void) __pam_display_msg(pamh, msg_style, nmsg, msgs, NULL);
}


static void
display_msg(pam_handle_t *pamh, int msg_style, char *msg)
{
	char pam_msg[1][PAM_MAX_MSG_SIZE];

	(void) snprintf(pam_msg[0], PAM_MAX_MSG_SIZE, "%s", msg);
	display_msgs(pamh, msg_style, 1, pam_msg);
}

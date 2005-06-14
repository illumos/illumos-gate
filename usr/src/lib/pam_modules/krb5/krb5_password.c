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
#include "krb5_repository.h"

#define	PAMTXD		"SUNW_OST_SYSOSPAM"
#define	MISC_EXIT_STATUS 6
#define	DONT_DISP_POLICY	0
#define	DISP_POLICY		1

extern int attempt_krb5_auth(void *, krb5_module_data_t *, char *, char **,
			boolean_t, boolean_t);
extern int krb5_verifypw(pam_handle_t *, char *, char *, boolean_t, int);

static char *get_passwd(pam_handle_t *, char *);
static void display_msg(pam_handle_t *, int, char *);
static void display_msgs(pam_handle_t *, int, int,
		char msgs[][PAM_MAX_MSG_SIZE]);
static int krb5_changepw(pam_handle_t *, char *, char *, char *, int);

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
		syslog(LOG_DEBUG,
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
				syslog(LOG_ERR,
				    dgettext(TEXT_DOMAIN,
					    "PAM-KRB5 (password):"
					    " pam_putenv failed: result: %d"),
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
	char *user,
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
	login_result = attempt_krb5_auth(pamh, kmd, user,
					&newpass, 0, 0);
	if (debug)
		syslog(LOG_DEBUG,
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
pam_sm_chauthtok(
	pam_handle_t		*pamh,
	int			flags,
	int			argc,
	const char		**argv)
{

	char			*user;
	int			err, result = PAM_AUTH_ERR;
	char			*newpass = NULL, *vnewpass = NULL;
	char			*oldpass = NULL;
	int			i;
	int			debug = 0;
	uid_t			pw_uid;
	krb5_module_data_t	*kmd = NULL;
	char			*pam_service;
	int			promptforold = 0;
	int			promptfornew = 0;
	pam_repository_t	*rep_data = NULL;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else
			syslog(LOG_ERR,
			    dgettext(TEXT_DOMAIN,
				    "PAM-KRB5 (password): illegal option %s"),
			    argv[i]);
	}

	if (debug)
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (password): start: flags = %x",
		    flags);

	err = pam_get_item(pamh, PAM_REPOSITORY, (void **)&rep_data);
	if (rep_data != NULL) {
		if (strcmp(rep_data->type, KRB5_REPOSITORY_NAME) != 0) {
			if (debug)
				syslog(LOG_DEBUG, "PAM-KRB5 (auth): wrong"
					"repository found (%s), returning "
					"PAM_IGNORE", rep_data->type);
			return (PAM_IGNORE);
		}
	}

	if (flags & PAM_PRELIM_CHECK) {
		/* Nothing to do here */
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (password): prelim check");
		return (PAM_IGNORE);
	}

	/* make sure PAM framework is telling us to update passwords */
	if (!(flags & PAM_UPDATE_AUTHTOK)) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
			"PAM-KRB5 (password): bad flags: %d"),
			flags);
		return (PAM_SYSTEM_ERR);
	}


	if ((err = pam_get_data(pamh, KRB5_DATA, (const void **)&kmd))
	    != PAM_SUCCESS) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (password): get mod data failed %d",
			    err);
		kmd = NULL;
	}

	if (flags & PAM_CHANGE_EXPIRED_AUTHTOK) {
		/* let's make sure we know the krb5 pw has expired */

		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (password): kmd age status %d",
			    kmd ? kmd->age_status : -99);

		if (!kmd || kmd->age_status != PAM_NEW_AUTHTOK_REQD)
			return (PAM_IGNORE);
	}

	err = pam_get_item(pamh, PAM_SERVICE, (void **)&pam_service);
	if (err != PAM_SUCCESS) {
		syslog(LOG_ERR,
		    "PAM-KRB5 (password): error getting SERVICE");
		return (PAM_SYSTEM_ERR);
	}

	err = pam_get_item(pamh, PAM_USER, (void **)&user);
	if (err != PAM_SUCCESS) {
		syslog(LOG_ERR,
		    "PAM-KRB5 (password): error getting USER");
		return (PAM_SYSTEM_ERR);
	}

	if (user == NULL || user == '\0') {
		syslog(LOG_ERR,
		    "PAM-KRB5 (password): username is empty");
		return (PAM_SYSTEM_ERR);
	}

	if (!get_pw_uid(user, &pw_uid)) {
		syslog(LOG_ERR,
		    "PAM-KRB5 (password): can't get uid for %s",
		    user);
		return (PAM_AUTHTOK_ERR);
	}

	/*
	 * if root key exists in the keytab, it's a random key so no
	 * need to prompt for pw and we just return IGNORE
	 */
	if ((strcmp(user, ROOT_UNAME) == 0) &&
	    key_in_keytab(user, debug)) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (password): "
			    "key for '%s' in keytab, returning IGNORE", user);
		result = PAM_IGNORE;
		goto out;
	}

	if ((err = pam_get_item(pamh, PAM_AUTHTOK,
				(void **) &newpass)) < 0)
		return (err);

	if ((err = pam_get_item(pamh, PAM_OLDAUTHTOK,
				(void **) &oldpass)) < 0)
		return (err);

	if (!newpass && !oldpass) {
		promptforold = 1;
		promptfornew = 1;
	} else {
		/*
		 * OLDAUTHTOK not set, we're probably the first password
		 * module but the AUTHTOK is probably set from an auth mod
		 */
		if (newpass && !oldpass) {
			oldpass = newpass;
			newpass = NULL;
			promptfornew = 1;
		}

		result = krb5_verifypw(pamh, user, oldpass,
				    DONT_DISP_POLICY, debug);
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (password): verifypw first %d",
			    result);
		/*
		 * If this fails and is not bad passwd, then it might
		 * be a non-rpcsec_gss KDC so drop thru.
		 *
		 * (note in S9 change pw should work on non-rpcsec_gss KDCs
		 *  such as MIT & MS)
		 */
		if (result != 0)
			promptforold = 1;
	}

	if (promptforold) {

		oldpass = get_passwd(pamh,
				    dgettext(TEXT_DOMAIN,
					    "Old Kerberos password: "));

		if (oldpass == NULL || oldpass[0] == '\0') {
			/* Need a password to proceed */
			display_msg(pamh, PAM_ERROR_MSG,
				    dgettext(TEXT_DOMAIN,
					    "Need the old password"
					    " to proceed \n"));
			free(oldpass);
			return (PAM_AUTHTOK_ERR);
		}

		result = krb5_verifypw(pamh, user, oldpass,
				    DISP_POLICY, debug);
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (password): verifypw prforold %d",
			    result);
		/*
		 * If it's a bad password, we are done.
		 * Else, continue and try the pwch with oldpass.
		 */
		if (result == 2) {
			display_msg(pamh, PAM_ERROR_MSG,
				    dgettext(TEXT_DOMAIN,
					    "Old Kerberos"
					    " password incorrect\n"));
			(void) memset(oldpass, 0, strlen(oldpass));
			free(oldpass);
			return (PAM_AUTHTOK_ERR);
		}
	}

	if (promptfornew) {
		newpass = get_passwd(pamh, dgettext(TEXT_DOMAIN,
			"New Kerberos password: "));

		if (newpass == NULL || newpass[0] == '\0') {
			/* Need a password to proceed */
			display_msg(pamh, PAM_ERROR_MSG,
			    dgettext(TEXT_DOMAIN,
			    "Need a password to proceed \n"));
			result = PAM_AUTHTOK_ERR;
			goto out;
		}

		vnewpass = get_passwd(pamh,
				dgettext(TEXT_DOMAIN,
			"Re-enter new Kerberos password: "));

		if (vnewpass == NULL || vnewpass[0] == '\0') {
			/* Need a password to proceed */
			display_msg(pamh, PAM_ERROR_MSG,
			    dgettext(TEXT_DOMAIN,
				"Need a password to proceed \n"));
			result = PAM_AUTHTOK_ERR;
			goto out;
		}

		if (strcmp(newpass, vnewpass)) {
			display_msg(pamh, PAM_ERROR_MSG,
			    dgettext(TEXT_DOMAIN,
				"Passwords do not match \n"));
			result = PAM_AUTHTOK_ERR;
			goto out;
		}
	}

	result = krb5_changepw(pamh, user, oldpass, newpass, debug);
	if (result == PAM_SUCCESS) {
		display_msg(pamh, PAM_TEXT_INFO,
			    dgettext(TEXT_DOMAIN,
				    "Kerberos password "
				    "successfully changed\n"));

		get_set_creds(pamh, kmd, user, newpass, debug);

		(void) pam_set_item(pamh, PAM_AUTHTOK, newpass);
		(void) pam_set_item(pamh, PAM_OLDAUTHTOK, oldpass);
	}

out:
	if (promptforold && oldpass) {
		(void) memset(oldpass, 0, strlen(oldpass));
		free(oldpass);
	}
	if (newpass) {
		(void) memset(newpass, 0, strlen(newpass));
		free(newpass);
	}

	if (vnewpass) {
		(void) memset(vnewpass, 0, strlen(vnewpass));
		free(vnewpass);
	}

	if (debug)
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (password): out: returns %d",
		    result);

	return (result);
}


int
pam_sm_get_authtokattr(
	/*ARGSUSED*/
	pam_handle_t		*pamh,
	char			***ga_getattr,
	int			repository,
	const char		*nisdomain,
	int			argc,
	const char		**argv)
{
	return (PAM_SUCCESS);
}

int
pam_sm_set_authtokattr(
	/*ARGSUSED*/
	pam_handle_t		*pamh,
	const char 		**pam_setattr,
	int			repository,
	const char		*nisdomain,
	int			argc,
	const char		**argv)
{
	return (PAM_SUCCESS);
}

int
krb5_verifypw(
	pam_handle_t *pamh,
	char 	*princ_str,
	char	*old_password,
	boolean_t disp_flag,
	int debug)
{
	kadm5_ret_t		code;
	krb5_principal 		princ = 0;
	char 			admin_realm[1024];
	char			kprinc[2*MAXHOSTNAMELEN];
	char			*cpw_service;
	kadm5_principal_ent_rec principal_entry;
	kadm5_policy_ent_rec	 policy_entry;
	void 			*server_handle;
	krb5_context		context;
	kadm5_config_params	params;
#define	MSG_ROWS		5
	char			msgs[MSG_ROWS][PAM_MAX_MSG_SIZE];

	(void) memset((char *)&params, 0, sizeof (params));
	(void) memset(&principal_entry, 0, sizeof (principal_entry));
	(void) memset(&policy_entry, 0, sizeof (policy_entry));

	if (code = krb5_init_context(&context)) {
		return (6);
	}

	if ((code = get_kmd_kuser(context, (const char *)princ_str, kprinc,
		2*MAXHOSTNAMELEN)) != 0) {
		return (code);
	}

	/* Need to get a krb5_principal struct */

	code = krb5_parse_name(context, kprinc, &princ);

	if (code != 0) {
		return (MISC_EXIT_STATUS);
	}

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
		syslog(LOG_ERR,
		    dgettext(TEXT_DOMAIN,
			"PAM-KRB5 (password): unable to get host based "
			"service name for realm %s\n"),
			admin_realm);
		return (3);
	}

	code = kadm5_init_with_password(kprinc, old_password, cpw_service,
					&params, KADM5_STRUCT_VERSION,
					KADM5_API_VERSION_2, &server_handle);
	if (code != 0) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5: krb5_verifypw: init_with_pw"
			    " failed: (%s)", error_message(code));
		krb5_free_principal(context, princ);
		return ((code == KADM5_BAD_PASSWORD) ? 2 : 3);
	}

	if (disp_flag &&
	    _kadm5_get_kpasswd_protocol(server_handle) == KRB5_CHGPWD_RPCSEC) {
		/*
		 * Note: copy of this exists in login
		 * (kverify.c/get_verified_in_tkt).
		 */

		code = kadm5_get_principal(server_handle, princ,
						&principal_entry,
						KADM5_PRINCIPAL_NORMAL_MASK);
		if (code != 0) {
			krb5_free_principal(context, princ);
			(void) kadm5_destroy(server_handle);
			return ((code == KADM5_UNK_PRINC) ? 1 :
				MISC_EXIT_STATUS);
		}

		if ((principal_entry.aux_attributes & KADM5_POLICY) != 0) {
			code = kadm5_get_policy(server_handle,
						principal_entry.policy,
						&policy_entry);
			if (code != 0) {
				/*
				 * doesn't matter which error comes back,
				 * there's no nice recovery or need to
				 * differentiate to the user
				 */
				(void) kadm5_free_principal_ent(server_handle,
							&principal_entry);
				krb5_free_principal(context, princ);
				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}

			(void) snprintf(msgs[0], PAM_MAX_MSG_SIZE,
				dgettext(TEXT_DOMAIN, "POLICY_EXPLANATION:"));
			(void) snprintf(msgs[1], PAM_MAX_MSG_SIZE,
				dgettext(TEXT_DOMAIN,
					"Principal string is %s"), princ_str);
			(void) snprintf(msgs[2], PAM_MAX_MSG_SIZE,
				dgettext(TEXT_DOMAIN, "Policy Name is  %s"),
				principal_entry.policy);
			(void) snprintf(msgs[3], PAM_MAX_MSG_SIZE,
				dgettext(TEXT_DOMAIN,
					"Minimum password length is %d"),
					policy_entry.pw_min_length);
			(void) snprintf(msgs[4], PAM_MAX_MSG_SIZE,
				dgettext(TEXT_DOMAIN,
					"Minimum password classes is %d"),
					policy_entry.pw_min_classes);
			display_msgs(pamh, PAM_TEXT_INFO, MSG_ROWS, msgs);

			if (code = kadm5_free_principal_ent(server_handle,
							    &principal_entry)) {
				(void) kadm5_free_policy_ent(server_handle,
							&policy_entry);
				krb5_free_principal(context, princ);
				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}
			if (code = kadm5_free_policy_ent(server_handle,
							&policy_entry)) {
				krb5_free_principal(context, princ);

				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}
		} else {
			/*
			 * kpasswd *COULD* output something here to encourage
			 * the choice of good passwords, in the absence of
			 * an enforced policy.
			 */
			if (code = kadm5_free_principal_ent(server_handle,
							    &principal_entry)) {
				krb5_free_principal(context, princ);
				(void) kadm5_destroy(server_handle);
				return (MISC_EXIT_STATUS);
			}
		}
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
 *			1 principal unknown
 *			2 old password wrong
 *			3 cannot initialize admin server session
 *			4 new passwd mismatch or error trying to change pw
 *                      5 password not typed
 *                      6 misc error
 *                      7 incorrect usage
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
	char *princ_str,
	char *old_password,
	char *new_password,
	int debug)
{
	kadm5_ret_t		code;
	krb5_principal 		princ = 0;
	char 			msg_ret[1024], admin_realm[1024];
	char			kprinc[2*MAXHOSTNAMELEN];
	char			*cpw_service;
	kadm5_principal_ent_rec principal_entry;
	kadm5_policy_ent_rec	policy_entry;
	void 			*server_handle;
	krb5_context		context;
	kadm5_config_params	params;

	(void) memset((char *)&params, 0, sizeof (params));
	(void) memset(&principal_entry, 0, sizeof (principal_entry));
	(void) memset(&policy_entry, 0, sizeof (policy_entry));

	if (code = krb5_init_context(&context)) {
		return (6);
	}

	if ((code = get_kmd_kuser(context, (const char *)princ_str, kprinc,
		2*MAXHOSTNAMELEN)) != 0) {
		return (code);
	}

	/* Need to get a krb5_principal struct */

	code = krb5_parse_name(context, kprinc, &princ);

	if (code != 0) {
		return (MISC_EXIT_STATUS);
	}

	if (strlen(old_password) == 0) {
		krb5_free_principal(context, princ);
		return (5);
	}

	(void) snprintf(admin_realm, sizeof (admin_realm), "%s",
		krb5_princ_realm(context, princ)->data);
	params.mask |= KADM5_CONFIG_REALM;
	params.realm = admin_realm;


	if (kadm5_get_cpw_host_srv_name(context, admin_realm, &cpw_service)) {
		syslog(LOG_ERR,
			dgettext(TEXT_DOMAIN,
				"PAM-KRB5 (password):unable to get host based "
				"service name for realm %s\n"),
			admin_realm);
		return (3);
	}

	code = kadm5_init_with_password(kprinc, old_password, cpw_service,
					&params, KADM5_STRUCT_VERSION,
					KADM5_API_VERSION_2, &server_handle);
	free(cpw_service);
	if (code != 0) {
		if (debug)
			syslog(LOG_DEBUG,
			    "PAM-KRB5 (password): changepw: "
			    "init_with_pw failed:  (%s)", error_message(code));
		krb5_free_principal(context, princ);
		return ((code == KADM5_BAD_PASSWORD) ? 2 : 3);
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
		syslog(LOG_DEBUG,
		    "PAM-KRB5 (password): changepw: end %d", code);

	if (code == KRB5_LIBOS_CANTREADPWD)
		return (5);
	else if (code)
		return (4);
	else
		return (PAM_SUCCESS);
}

static char *
get_passwd(
	pam_handle_t *pamh,
	char *prompt)
{
	int		err;
	char		*p;

	err = __pam_get_authtok(pamh, PAM_PROMPT, 0, prompt, &p);

	if (err != PAM_SUCCESS) {
		return (NULL);
	}

	return (p);
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

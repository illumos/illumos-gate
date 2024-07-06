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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <syslog.h>
#include <libintl.h>
#include <k5-int.h>
#include "profile/prof_int.h"
#include <netdb.h>
#include <ctype.h>
#include "utils.h"
#include "krb5_repository.h"

#define	KRB5_DEFAULT_OPTIONS 0

int forwardable_flag = 0;
int renewable_flag = 0;
int proxiable_flag = 0;
int no_address_flag = 0;
profile_options_boolean config_option[] = {
	{ "forwardable", &forwardable_flag, 0 },
	{ "renewable",  &renewable_flag, 0 },
	{ "proxiable", &proxiable_flag, 0 },
	{ "no_addresses", &no_address_flag, 0 },
	{ NULL, NULL, 0 }
};
char *renew_timeval;
char *life_timeval;
profile_option_strings config_times[] = {
	{ "max_life", &life_timeval, 0 },
	{ "max_renewable_life",  &renew_timeval, 0 },
	{ NULL, NULL, 0 }
};
char *realmdef[] = { "realms", NULL, NULL, NULL };
char *appdef[] = { "appdefaults", "kinit", NULL };

#define	krb_realm (*(realmdef + 1))

int	attempt_krb5_auth(pam_handle_t *, krb5_module_data_t *, const char *,
	char **, boolean_t);
void	krb5_cleanup(pam_handle_t *, void *, int);

extern errcode_t profile_get_options_boolean();
extern errcode_t profile_get_options_string();
extern int krb5_verifypw(char *, char *, int);
extern krb5_error_code krb5_verify_init_creds(krb5_context,
		krb5_creds *, krb5_principal, krb5_keytab, krb5_ccache *,
		krb5_verify_init_creds_opt *);
extern krb5_error_code __krb5_get_init_creds_password(krb5_context,
		krb5_creds *, krb5_principal, char *, krb5_prompter_fct, void *,
		krb5_deltat, char *, krb5_get_init_creds_opt *,
		krb5_kdc_rep **);

/*
 * pam_sm_authenticate		- Authenticate user
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user = NULL;
	int err;
	int result = PAM_AUTH_ERR;
	/* pam.conf options */
	int debug = 0;
	int warn = 1;
	/* return an error on password expire */
	int err_on_exp = 0;
	int i;
	char *password = NULL;
	uid_t pw_uid;
	krb5_module_data_t *kmd = NULL;
	krb5_repository_data_t *krb5_data = NULL;
	const pam_repository_t *rep_data = NULL;
	boolean_t do_pkinit = FALSE;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else if (strcmp(argv[i], "nowarn") == 0) {
			warn = 0;
		} else if (strcmp(argv[i], "err_on_exp") == 0) {
			err_on_exp = 1;
		} else if (strcmp(argv[i], "pkinit") == 0) {
			do_pkinit = TRUE;
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "PAM-KRB5 (auth) unrecognized option %s", argv[i]);
		}
	}
	if (flags & PAM_SILENT) warn = 0;

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (auth): pam_sm_authenticate flags=%d",
		    flags);

	/*
	 * pam_get_data could fail if we are being called for the first time
	 * or if the module is not found, PAM_NO_MODULE_DATA is not an error
	 */
	err = pam_get_data(pamh, KRB5_DATA, (const void **)&kmd);
	if (!(err == PAM_SUCCESS || err == PAM_NO_MODULE_DATA))
		return (PAM_SYSTEM_ERR);

	/*
	 * If pam_krb5 was stacked higher in the auth stack and did PKINIT
	 * preauth sucessfully then this instance is a fallback to password
	 * based preauth and should just return PAM_IGNORE.
	 *
	 * The else clause is handled further down.
	 */
	if (kmd != NULL) {
		if (++(kmd->auth_calls) > 2) {
			/*
			 * pam_krb5 has been stacked > 2 times in the auth
			 * stack.  Clear out the current kmd and proceed as if
			 * this is the first time pam_krb5 auth has been called.
			 */
			if (debug) {
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (auth): stacked more than"
				    " two times, clearing kmd");
			}
			/* clear out/free current kmd */
			err = pam_set_data(pamh, KRB5_DATA, NULL, NULL);
			if (err != PAM_SUCCESS) {
				krb5_cleanup(pamh, kmd, err);
				result = err;
				goto out;
			}
			kmd = NULL;
		} else if (kmd->auth_calls == 2 &&
		    kmd->auth_status == PAM_SUCCESS) {
			/*
			 * The previous instance of pam_krb5 succeeded and this
			 * instance was a fall back in case it didn't succeed so
			 * return ignore.
			 */
			if (debug) {
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (auth): PKINIT succeeded "
				    "earlier so returning PAM_IGNORE");
			}
			return (PAM_IGNORE);
		}
	}

	(void) pam_get_item(pamh, PAM_USER, (const void **)&user);

	if (user == NULL || *user == '\0') {
		if (do_pkinit) {
			/*
			 * If doing PKINIT it is okay to prompt for the user
			 * name.
			 */
			if ((err = pam_get_user(pamh, &user,
			    NULL)) != PAM_SUCCESS) {
				if (debug) {
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (auth): get user failed: "
					    "%s", pam_strerror(pamh, err));
				}
				return (err);
			}
		} else {
			if (debug)
				__pam_log(LOG_AUTH | LOG_DEBUG,
				    "PAM-KRB5 (auth): user empty or null");
			return (PAM_USER_UNKNOWN);
		}
	}

	/* make sure a password entry exists for this user */
	if (!get_pw_uid(user, &pw_uid))
		return (PAM_USER_UNKNOWN);

	if (kmd == NULL) {
		kmd = calloc(1, sizeof (krb5_module_data_t));
		if (kmd == NULL) {
			result = PAM_BUF_ERR;
			goto out;
		}

		err = pam_set_data(pamh, KRB5_DATA, kmd, &krb5_cleanup);
		if (err != PAM_SUCCESS) {
			free(kmd);
			result = err;
			goto out;
		}
	}

	if (!kmd->env) {
		char buffer[512];

		if (snprintf(buffer, sizeof (buffer),
		    "%s=FILE:/tmp/krb5cc_%d",
		    KRB5_ENV_CCNAME, (int)pw_uid) >= sizeof (buffer)) {
			result = PAM_SYSTEM_ERR;
			goto out;
		}

		/* we MUST copy this to the heap for the putenv to work! */
		kmd->env = strdup(buffer);
		if (!kmd->env) {
			result = PAM_BUF_ERR;
			goto out;
		} else {
			if (putenv(kmd->env)) {
				result = PAM_SYSTEM_ERR;
				goto out;
			}
		}
	}

	if (kmd->user != NULL)
		free(kmd->user);
	if ((kmd->user = strdup(user)) == NULL) {
		result = PAM_BUF_ERR;
		goto out;
	}

	kmd->auth_status = PAM_AUTH_ERR;
	kmd->debug = debug;
	kmd->warn = warn;
	kmd->err_on_exp = err_on_exp;
	kmd->ccache = NULL;
	kmd->kcontext = NULL;
	kmd->password = NULL;
	kmd->age_status = PAM_SUCCESS;
	(void) memset((char *)&kmd->initcreds, 0, sizeof (krb5_creds));
	kmd->auth_calls = 1;
	kmd->preauth_type = do_pkinit ? KRB_PKINIT : KRB_PASSWD;

	/*
	 * For apps that already did krb5 auth exchange...
	 * Now that we've created the kmd structure, we can
	 * return SUCCESS.  'kmd' may be needed later by other
	 * PAM functions, thats why we wait until this point to
	 * return.
	 */
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
		if (rep_data->scope_len == sizeof (krb5_repository_data_t)) {
			krb5_data = (krb5_repository_data_t *)rep_data->scope;

			if (krb5_data->flags ==
			    SUNW_PAM_KRB5_ALREADY_AUTHENTICATED &&
			    krb5_data->principal != NULL &&
			    strlen(krb5_data->principal)) {
				if (debug)
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (auth): Principal "
					    "%s already authenticated",
					    krb5_data->principal);
				kmd->auth_status = PAM_SUCCESS;
				return (PAM_SUCCESS);
			}
		}
	}

	/*
	 * if root key exists in the keytab, it's a random key so no
	 * need to prompt for pw and we just return IGNORE.
	 *
	 * note we don't need to force a prompt for pw as authtok_get
	 * is required to be stacked above this module.
	 */
	if ((strcmp(user, ROOT_UNAME) == 0) &&
	    key_in_keytab(user, debug)) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): "
			    "key for '%s' in keytab, returning IGNORE", user);
		result = PAM_IGNORE;
		goto out;
	}

	(void) pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);

	result = attempt_krb5_auth(pamh, kmd, user, &password, 1);

out:
	if (kmd) {
		if (debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): pam_sm_auth finalize"
			    " ccname env, result =%d, env ='%s',"
			    " age = %d, status = %d",
			    result, kmd->env ? kmd->env : "<null>",
			    kmd->age_status, kmd->auth_status);

		if (kmd->env &&
		    !(kmd->age_status == PAM_NEW_AUTHTOK_REQD &&
		    kmd->auth_status == PAM_SUCCESS)) {


			if (result == PAM_SUCCESS) {
				/*
				 * Put ccname into the pamh so that login
				 * apps can pick this up when they run
				 * pam_getenvlist().
				 */
				if ((result = pam_putenv(pamh, kmd->env))
				    != PAM_SUCCESS) {
					/* should not happen but... */
					__pam_log(LOG_AUTH | LOG_ERR,
					    "PAM-KRB5 (auth):"
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
		kmd->auth_status = result;
	}

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (auth): end: %s", pam_strerror(pamh, result));

	return (result);
}

static krb5_error_code
pam_krb5_prompter(krb5_context ctx, void *data, const char *name,
    const char *banner, int num_prompts, krb5_prompt prompts[])
{
	krb5_error_code rc = KRB5_LIBOS_CANTREADPWD;
	pam_handle_t *pamh = (pam_handle_t *)data;
	const struct pam_conv	*pam_convp;
	struct pam_message *msgs = NULL;
	struct pam_response *ret_respp = NULL;
	int i;
	krb5_prompt_type *prompt_type = krb5_get_prompt_types(ctx);
	char tmpbuf[PAM_MAX_MSG_SIZE];

	if (prompts) {
		assert(num_prompts > 0);
	}
	/*
	 * Because this function should never be used for password prompts,
	 * disallow password prompts.
	 */
	for (i = 0; i < num_prompts; i++) {
		switch (prompt_type[i]) {
		case KRB5_PROMPT_TYPE_PASSWORD:
		case KRB5_PROMPT_TYPE_NEW_PASSWORD:
		case KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN:
			return (rc);
		}
	}

	if (pam_get_item(pamh, PAM_CONV, (const void **)&pam_convp) !=
	    PAM_SUCCESS) {
		return (rc);
	}
	if (pam_convp == NULL) {
		return (rc);
	}

	msgs = (struct pam_message *)calloc(num_prompts,
	    sizeof (struct pam_message));
	if (msgs == NULL) {
		return (rc);
	}
	(void) memset(msgs, 0, sizeof (struct pam_message) * num_prompts);

	for (i = 0; i < num_prompts; i++) {
		/* convert krb prompt style to PAM style */
		if (prompts[i].hidden) {
			msgs[i].msg_style = PAM_PROMPT_ECHO_OFF;
		} else {
			msgs[i].msg_style = PAM_PROMPT_ECHO_ON;
		}
		/*
		 * krb expects the prompting function to append ": " to the
		 * prompt string.
		 */
		if (snprintf(tmpbuf, sizeof (tmpbuf), "%s: ",
		    prompts[i].prompt) < 0) {
			goto cleanup;
		}
		msgs[i].msg = strdup(tmpbuf);
		if (msgs[i].msg == NULL) {
			goto cleanup;
		}
	}

	/*
	 * Call PAM conv function to display the prompt.
	 */

	if ((pam_convp->conv)(num_prompts, (const struct pam_message **)&msgs,
	    &ret_respp, pam_convp->appdata_ptr) == PAM_SUCCESS) {
		for (i = 0; i < num_prompts; i++) {
			/* convert PAM response to krb prompt reply format */
			assert(prompts[i].reply->data != NULL);
			assert(ret_respp[i].resp != NULL);

			if (strlcpy(prompts[i].reply->data,
			    ret_respp[i].resp, prompts[i].reply->length) >=
			    prompts[i].reply->length) {
				char errmsg[1][PAM_MAX_MSG_SIZE];

				(void) snprintf(errmsg[0], PAM_MAX_MSG_SIZE,
				    "%s", dgettext(TEXT_DOMAIN,
				    "Reply too long: "));
				(void) __pam_display_msg(pamh, PAM_ERROR_MSG,
				    1, errmsg, NULL);
				goto cleanup;
			} else {
				char *retp;

				/*
				 * newline must be replaced with \0 terminator
				 */
				retp = strchr(prompts[i].reply->data, '\n');
				if (retp != NULL)
					*retp = '\0';
				/* NULL terminator should not be counted */
				prompts[i].reply->length =
				    strlen(prompts[i].reply->data);
			}
		}
		rc = 0;
	}

cleanup:
	for (i = 0; i < num_prompts; i++) {
		if (msgs[i].msg) {
			free(msgs[i].msg);
		}
		if (ret_respp[i].resp) {
			/* 0 out sensitive data before free() */
			(void) memset(ret_respp[i].resp, 0,
			    strlen(ret_respp[i].resp));
			free(ret_respp[i].resp);
		}
	}
	free(msgs);
	free(ret_respp);
	return (rc);
}

int
attempt_krb5_auth(
	pam_handle_t *pamh,
	krb5_module_data_t	*kmd,
	const char	*user,
	char		**krb5_pass,
	boolean_t	verify_tik)
{
	krb5_principal	me = NULL, clientp = NULL;
	krb5_principal	server = NULL, serverp = NULL;
	krb5_creds	*my_creds;
	krb5_timestamp	now;
	krb5_error_code	code = 0;
	char		kuser[2*MAXHOSTNAMELEN];
	krb5_deltat	lifetime;
	krb5_deltat	rlife;
	krb5_deltat	krb5_max_duration;
	int		options = KRB5_DEFAULT_OPTIONS;
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
		KRB5_TGS_NAME
	};
	krb5_get_init_creds_opt *opts = NULL;
	krb5_kdc_rep *as_reply = NULL;
	/*
	 * "result" should not be assigned PAM_SUCCESS unless
	 * authentication has succeeded and there are no other errors.
	 *
	 * "code" is sometimes used for PAM codes, sometimes for krb5
	 * codes.  Be careful.
	 */
	int result = PAM_AUTH_ERR;

	if (kmd->debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (auth): attempt_krb5_auth: start: user='%s'",
		    user ? user : "<null>");

	/* need to free context with krb5_free_context */
	if (code = krb5_init_secure_context(&kmd->kcontext)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (auth): Error initializing "
		    "krb5: %s",
		    error_message(code));
		return (PAM_SYSTEM_ERR);
	}

	if ((code = get_kmd_kuser(kmd->kcontext, user, kuser,
	    2 * MAXHOSTNAMELEN)) != 0) {
		/* get_kmd_kuser returns proper PAM error statuses */
		return (code);
	}

	if ((code = krb5_parse_name(kmd->kcontext, kuser, &me)) != 0) {
		krb5_free_context(kmd->kcontext);
		kmd->kcontext = NULL;
		return (PAM_SYSTEM_ERR);
	}

	/* call krb5_free_cred_contents() on error */
	my_creds = &kmd->initcreds;

	if ((code =
	    krb5_copy_principal(kmd->kcontext, me, &my_creds->client))) {
		result = PAM_SYSTEM_ERR;
		goto out_err;
	}
	clientp = my_creds->client;

	if (code = krb5_build_principal_ext(kmd->kcontext, &server,
	    krb5_princ_realm(kmd->kcontext, me)->length,
	    krb5_princ_realm(kmd->kcontext, me)->data,
	    tgtname.length, tgtname.data,
	    krb5_princ_realm(kmd->kcontext, me)->length,
	    krb5_princ_realm(kmd->kcontext, me)->data, 0)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (auth): attempt_krb5_auth: "
		    "krb5_build_princ_ext failed: %s",
		    error_message(code));
		result = PAM_SYSTEM_ERR;
		goto out;
	}

	if (code = krb5_copy_principal(kmd->kcontext, server,
	    &my_creds->server)) {
		result = PAM_SYSTEM_ERR;
		goto out_err;
	}
	serverp = my_creds->server;

	if (code = krb5_timeofday(kmd->kcontext, &now)) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "PAM-KRB5 (auth): attempt_krb5_auth: "
		    "krb5_timeofday failed: %s",
		    error_message(code));
		result = PAM_SYSTEM_ERR;
		goto out;
	}

	/*
	 * set the values for lifetime and rlife to be the maximum
	 * possible
	 */
	krb5_max_duration = KRB5_KDB_EXPIRATION - now - 60*60;
	lifetime = krb5_max_duration;
	rlife = krb5_max_duration;

	/*
	 * Let us get the values for various options
	 * from Kerberos configuration file
	 */

	krb_realm = krb5_princ_realm(kmd->kcontext, me)->data;
	profile_get_options_boolean(kmd->kcontext->profile,
	    realmdef, config_option);
	profile_get_options_boolean(kmd->kcontext->profile,
	    appdef, config_option);
	profile_get_options_string(kmd->kcontext->profile,
	    realmdef, config_times);
	profile_get_options_string(kmd->kcontext->profile,
	    appdef, config_times);

	if (renew_timeval) {
		code = krb5_string_to_deltat(renew_timeval, &rlife);
		if (code != 0 || rlife == 0 || rlife > krb5_max_duration) {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "PAM-KRB5 (auth): Bad max_renewable_life "
			    " value '%s' in Kerberos config file",
			    renew_timeval);
			result = PAM_SYSTEM_ERR;
			goto out;
		}
	}
	if (life_timeval) {
		code = krb5_string_to_deltat(life_timeval, &lifetime);
		if (code != 0 || lifetime == 0 ||
		    lifetime > krb5_max_duration) {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "lifetime value '%s' in Kerberos config file",
			    life_timeval);
			result = PAM_SYSTEM_ERR;
			goto out;
		}
	}
	/*  start timer when request gets to KDC */
	my_creds->times.starttime = 0;
	my_creds->times.endtime = now + lifetime;

	if (options & KDC_OPT_RENEWABLE) {
		my_creds->times.renew_till = now + rlife;
	} else
		my_creds->times.renew_till = 0;

	code = krb5_get_init_creds_opt_alloc(kmd->kcontext, &opts);
	if (code != 0) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "Error allocating gic opts: %s",
		    error_message(code));
		result = PAM_SYSTEM_ERR;
		goto out;
	}

	krb5_get_init_creds_opt_set_tkt_life(opts, lifetime);

	if (proxiable_flag) { 		/* Set in config file */
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): Proxiable tickets "
			    "requested");
		krb5_get_init_creds_opt_set_proxiable(opts, TRUE);
	}
	if (forwardable_flag) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): Forwardable tickets "
			    "requested");
		krb5_get_init_creds_opt_set_forwardable(opts, TRUE);
	}
	if (renewable_flag) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): Renewable tickets "
			    "requested");
		krb5_get_init_creds_opt_set_renew_life(opts, rlife);
	}
	if (no_address_flag) {
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): Addressless tickets "
			    "requested");
		krb5_get_init_creds_opt_set_address_list(opts, NULL);
	}

	/*
	 * mech_krb5 interprets empty passwords as NULL passwords and tries to
	 * read a password from stdin. Since we are in pam this is bad and
	 * should not be allowed.
	 *
	 * Note, the logic now is that if the preauth_type is PKINIT then
	 * provide a proper PAMcentric prompt function that the underlying
	 * PKINIT preauth plugin will use to prompt for the PIN.
	 */
	if (kmd->preauth_type == KRB_PKINIT) {
		/*
		 * Do PKINIT preauth
		 *
		 * Note: we want to limit preauth types to just those for PKINIT
		 * but krb5_get_init_creds() doesn't support that at this point.
		 * Instead we rely on pam_krb5_prompter() to limit prompts to
		 * non-password types.  So all we can do here is set the preauth
		 * list so krb5_get_init_creds() will try that first.
		 */
		krb5_preauthtype pk_pa_list[] = {
			KRB5_PADATA_PK_AS_REQ,
			KRB5_PADATA_PK_AS_REQ_OLD
		};
		krb5_get_init_creds_opt_set_preauth_list(opts, pk_pa_list, 2);

		if (*krb5_pass == NULL || strlen(*krb5_pass) != 0) {
			if (*krb5_pass != NULL) {
				/* treat the krb5_pass as a PIN */
				code = krb5_get_init_creds_opt_set_pa(
				    kmd->kcontext, opts, "PIN", *krb5_pass);
			}

			if (!code) {
				code = __krb5_get_init_creds_password(
				    kmd->kcontext,
				    my_creds,
				    me,
				    NULL, /* clear text passwd */
				    pam_krb5_prompter, /* prompter */
				    pamh, /* prompter data */
				    0, /* start time */
				    NULL, /* defaults to krbtgt@REALM */
				    opts,
				    &as_reply);
			}
		} else {
			/* invalid PIN */
			code = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		}
	} else {
		/*
		 * Do password based preauths
		 *
		 * See earlier PKINIT comment.  We are doing something similar
		 * here but we do not pass in a prompter (we assume
		 * pam_authtok_get has already prompted for that).
		 */
		if (*krb5_pass == NULL || strlen(*krb5_pass) == 0) {
			code = KRB5KRB_AP_ERR_BAD_INTEGRITY;
		} else {
			krb5_preauthtype pk_pa_list[] = {
				KRB5_PADATA_ENC_TIMESTAMP
			};

			krb5_get_init_creds_opt_set_preauth_list(opts,
			    pk_pa_list, 1);

			/*
			 * We call our own private version of gic_pwd, because
			 * we need more information, such as password/account
			 * expiration, that is found in the as_reply.  The
			 * "prompter" interface is not granular enough for PAM
			 * to make use of.
			 */
			code = __krb5_get_init_creds_password(kmd->kcontext,
			    my_creds,
			    me,
			    *krb5_pass,	/* clear text passwd */
			    NULL,	/* prompter */
			    NULL,	/* data */
			    0,		/* start time */
			    NULL,	/* defaults to krbtgt@REALM */
			    opts,
			    &as_reply);
		}
	}

	if (kmd->debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (auth): attempt_krb5_auth: "
		    "krb5_get_init_creds_password returns: %s",
		    code == 0 ? "SUCCESS" : error_message(code));

	switch (code) {
	case 0:
		/* got a tgt, let's verify it */
		if (verify_tik) {
			krb5_verify_init_creds_opt vopts;

			krb5_principal sp = NULL;
			char kt_name[MAX_KEYTAB_NAME_LEN];
			char *fqdn;

			krb5_verify_init_creds_opt_init(&vopts);

			code = krb5_verify_init_creds(kmd->kcontext,
			    my_creds,
			    NULL,	/* defaults to host/localhost@REALM */
			    NULL,
			    NULL,
			    &vopts);

			if (code) {
				result = PAM_SYSTEM_ERR;

				/*
				 * Give a better error message when the
				 * keytable entry isn't found or the keytab
				 * file cannot be found.
				 */
				if (krb5_sname_to_principal(kmd->kcontext, NULL,
				    NULL, KRB5_NT_SRV_HST, &sp))
					fqdn = "<fqdn>";
				else
					fqdn = sp->data[1].data;

				if (krb5_kt_default_name(kmd->kcontext, kt_name,
				    sizeof (kt_name)))
					(void) strlcpy(kt_name,
					    "default keytab",
					    sizeof (kt_name));

				switch (code) {
				case KRB5_KT_NOTFOUND:
					__pam_log(LOG_AUTH | LOG_ERR,
					    "PAM-KRB5 (auth): "
					    "krb5_verify_init_creds failed:"
					    " Key table entry \"host/%s\""
					    " not found in %s",
					    fqdn, kt_name);
					break;
				case ENOENT:
					__pam_log(LOG_AUTH | LOG_ERR,
					    "PAM-KRB5 (auth): "
					    "krb5_verify_init_creds failed:"
					    " Keytab file \"%s\""
					    " does not exist.\n",
					    kt_name);
					break;
				default:
					__pam_log(LOG_AUTH | LOG_ERR,
					    "PAM-KRB5 (auth): "
					    "krb5_verify_init_creds failed:"
					    " %s",
					    error_message(code));
					break;
				}

				if (sp)
					krb5_free_principal(kmd->kcontext, sp);
			}
		}

		if (code == 0)
			kmd->expiration = as_reply->enc_part2->key_exp;

		break;

	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
		/*
		 * Since this principal is not part of the local
		 * Kerberos realm, we just return PAM_USER_UNKNOWN.
		 */
		result = PAM_USER_UNKNOWN;

		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): attempt_krb5_auth:"
			    " User is not part of the local Kerberos"
			    " realm: %s", error_message(code));
		break;

	case KRB5KDC_ERR_PREAUTH_FAILED:
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
		/*
		 * We could be trying the password from a previous
		 * pam authentication module, but we don't want to
		 * generate an error if the unix password is different
		 * than the Kerberos password...
		 */
		break;

	case KRB5KDC_ERR_KEY_EXP:
		if (!kmd->err_on_exp) {
			/*
			 * Request a tik for changepw service and it will tell
			 * us if pw is good or not. If PKINIT is being done it
			 * is possible that *krb5_pass may be NULL so check for
			 * that.  If that is the case this function will return
			 * an error.
			 */
			if (*krb5_pass != NULL) {
				code = krb5_verifypw(kuser, *krb5_pass,
				    kmd->debug);
				if (kmd->debug) {
					__pam_log(LOG_AUTH | LOG_DEBUG,
					    "PAM-KRB5 (auth): "
					    "attempt_krb5_auth: "
					    "verifypw %d", code);
				}
				if (code == 0) {
					/*
					 * pw is good, set age status for
					 * acct_mgmt.
					 */
					kmd->age_status = PAM_NEW_AUTHTOK_REQD;
				}
			}

		}
		break;

	default:
		result = PAM_SYSTEM_ERR;
		if (kmd->debug)
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "PAM-KRB5 (auth): error %d - %s",
			    code, error_message(code));
		break;
	}

	if (code == 0) {
		/*
		 * success for the entered pw or PKINIT succeeded.
		 *
		 * we can't rely on the pw in PAM_AUTHTOK
		 * to be the (correct) krb5 one so
		 * store krb5 pw in module data for
		 * use in acct_mgmt.  Note that *krb5_pass may be NULL if we're
		 * doing PKINIT.
		 */
		if (*krb5_pass != NULL &&
		    !(kmd->password = strdup(*krb5_pass))) {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "Cannot strdup password");
			result = PAM_BUF_ERR;
			goto out_err;
		}

		result = PAM_SUCCESS;
		goto out;
	}

out_err:
	/* jump (or reach) here if error and cred cache has been init */

	if (kmd->debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (auth): clearing initcreds in "
		    "pam_authenticate()");

	krb5_free_cred_contents(kmd->kcontext, &kmd->initcreds);
	(void) memset((char *)&kmd->initcreds, 0, sizeof (krb5_creds));

out:
	if (server)
		krb5_free_principal(kmd->kcontext, server);
	if (me)
		krb5_free_principal(kmd->kcontext, me);
	if (as_reply)
		krb5_free_kdc_rep(kmd->kcontext, as_reply);

	/*
	 * clientp or serverp could be NULL in certain error cases in this
	 * function.  mycreds->[client|server] could also be NULL in case
	 * of error in this function, see out_err above.  The pointers clientp
	 * and serverp reference the input argument in my_creds for
	 * get_init_creds and must be freed if the input argument does not
	 * match the output argument, which occurs during a successful call
	 * to get_init_creds.
	 */
	if (clientp && my_creds->client && clientp != my_creds->client)
		krb5_free_principal(kmd->kcontext, clientp);
	if (serverp && my_creds->server && serverp != my_creds->server)
		krb5_free_principal(kmd->kcontext, serverp);

	if (kmd->kcontext) {
		krb5_free_context(kmd->kcontext);
		kmd->kcontext = NULL;
	}
	if (opts)
		krb5_get_init_creds_opt_free(kmd->kcontext, opts);

	if (kmd->debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (auth): attempt_krb5_auth returning %d",
		    result);

	return (kmd->auth_status = result);
}

/*ARGSUSED*/
void
krb5_cleanup(pam_handle_t *pamh, void *data, int pam_status)
{
	krb5_module_data_t *kmd = (krb5_module_data_t *)data;

	if (kmd == NULL)
		return;

	if (kmd->debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "PAM-KRB5 (auth): krb5_cleanup auth_status = %d",
		    kmd->auth_status);
	}

	/*
	 * Apps could be calling pam_end here, so we should always clean
	 * up regardless of success or failure here.
	 */
	if (kmd->ccache)
		(void) krb5_cc_close(kmd->kcontext, kmd->ccache);

	if (kmd->password) {
		(void) memset(kmd->password, 0, strlen(kmd->password));
		free(kmd->password);
	}

	if (kmd->user)
		free(kmd->user);

	if (kmd->env)
		free(kmd->env);

	krb5_free_cred_contents(kmd->kcontext, &kmd->initcreds);
	(void) memset((char *)&kmd->initcreds, 0, sizeof (krb5_creds));

	free(kmd);
}

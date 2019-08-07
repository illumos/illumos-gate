/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved. */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include "k5-int.h"
#include "com_err.h"
#include <admin.h>
#include <locale.h>
#include <syslog.h>

/* Solaris Kerberos:
 *
 * Change Password functionality is handled by the libkadm5clnt.so.1 library in
 * Solaris Kerberos. In order to avoid a circular dependency between that lib
 * and the kerberos mech lib, we use the #pragma weak compiler directive.
 * This way, when applications link with the libkadm5clnt.so.1 lib the circular
 * dependancy between the two libs will be resolved.
 */

#pragma weak kadm5_get_cpw_host_srv_name
#pragma weak kadm5_init_with_password
#pragma weak kadm5_chpass_principal_util

extern kadm5_ret_t kadm5_get_cpw_host_srv_name(krb5_context, const char *,
			char **);
extern kadm5_ret_t kadm5_init_with_password(char *, char *, char *,
			kadm5_config_params *, krb5_ui_4, krb5_ui_4, char **,
			void **);
extern kadm5_ret_t kadm5_chpass_principal_util(void *, krb5_principal,
			char *, char **, char *, unsigned int);

/*
 * Solaris Kerberos:
 * See the function's definition for the description of this interface.
 */
krb5_error_code __krb5_get_init_creds_password(krb5_context,
	krb5_creds *, krb5_principal, char *, krb5_prompter_fct, void *,
	krb5_deltat, char *, krb5_get_init_creds_opt *, krb5_kdc_rep **);

static krb5_error_code
krb5_get_as_key_password(
    krb5_context context,
    krb5_principal client,
    krb5_enctype etype,
    krb5_prompter_fct prompter,
    void *prompter_data,
    krb5_data *salt,
    krb5_data *params,
    krb5_keyblock *as_key,
    void *gak_data)
{
    krb5_data *password;
    krb5_error_code ret;
    krb5_data defsalt;
    char *clientstr;
    char promptstr[1024];
    krb5_prompt prompt;
    krb5_prompt_type prompt_type;

    password = (krb5_data *) gak_data;

    /* If there's already a key of the correct etype, we're done.
       If the etype is wrong, free the existing key, and make
       a new one.

       XXX This was the old behavior, and was wrong in hw preauth
       cases.  Is this new behavior -- always asking -- correct in all
       cases?  */

    if (as_key->length) {
	if (as_key->enctype != etype) {
	    krb5_free_keyblock_contents (context, as_key);
	    as_key->length = 0;
	}
    }

    if (password->data[0] == '\0') {
	if (prompter == NULL)
		prompter = krb5_prompter_posix; /* Solaris Kerberos */

	if ((ret = krb5_unparse_name(context, client, &clientstr)))
	  return(ret);

	strcpy(promptstr, "Password for ");
	strncat(promptstr, clientstr, sizeof(promptstr)-strlen(promptstr)-1);
	promptstr[sizeof(promptstr)-1] = '\0';

	free(clientstr);

	prompt.prompt = promptstr;
	prompt.hidden = 1;
	prompt.reply = password;
	prompt_type = KRB5_PROMPT_TYPE_PASSWORD;

	/* PROMPTER_INVOCATION */
	krb5int_set_prompt_types(context, &prompt_type);
	if ((ret = (((*prompter)(context, prompter_data, NULL, NULL,
				1, &prompt))))) {
	    krb5int_set_prompt_types(context, 0);
	    return(ret);
	}
	krb5int_set_prompt_types(context, 0);
    }

    if ((salt->length == -1 || salt->length == SALT_TYPE_AFS_LENGTH) && (salt->data == NULL)) {
	if ((ret = krb5_principal2salt(context, client, &defsalt)))
	    return(ret);

	salt = &defsalt;
    } else {
	defsalt.length = 0;
    }

    ret = krb5_c_string_to_key_with_params(context, etype, password, salt,
					   params->data?params:NULL, as_key);

    if (defsalt.length)
	krb5_xfree(defsalt.data);

    return(ret);
}

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_password(krb5_context context,
			     krb5_creds *creds,
			     krb5_principal client,
			     char *password,
			     krb5_prompter_fct prompter,
			     void *data,
			     krb5_deltat start_time,
			     char *in_tkt_service,
			     krb5_get_init_creds_opt *options)
{
	/*
	 * Solaris Kerberos:
	 * We call our own private function that returns the as_reply back to
	 * the caller.  This structure contains information, such as
	 * key-expiration and last-req fields.  Entities such as pam_krb5 can
	 * use this information to provide account/password expiration warnings.
	 * The original "prompter" interface is not granular enough for PAM,
	 * as it will perform all passes w/o coordination with other modules.
	 */
	return (__krb5_get_init_creds_password(context, creds, client, password,
		prompter, data, start_time, in_tkt_service, options, NULL));
}

/*
 * Solaris Kerberos:
 * See krb5_get_init_creds_password()'s comments for the justification of this
 * private function.  Caller must free ptr_as_reply if non-NULL.
 */
krb5_error_code KRB5_CALLCONV
__krb5_get_init_creds_password(
     krb5_context context,
     krb5_creds *creds,
     krb5_principal client,
     char *password,
     krb5_prompter_fct prompter,
     void *data,
     krb5_deltat start_time,
     char *in_tkt_service,
     krb5_get_init_creds_opt *options,
     krb5_kdc_rep **ptr_as_reply)
{
   krb5_error_code ret, ret2;
   int use_master;
   krb5_kdc_rep *as_reply;
   int tries;
   krb5_creds chpw_creds;
   krb5_data pw0, pw1;
   char banner[1024], pw0array[1024], pw1array[1024];
   krb5_prompt prompt[2];
   krb5_prompt_type prompt_types[sizeof(prompt)/sizeof(prompt[0])];
   krb5_gic_opt_ext *opte = NULL;
   krb5_gic_opt_ext *chpw_opte = NULL;

   char admin_realm[1024], *cpw_service=NULL, *princ_str=NULL;
   kadm5_config_params  params;
   void *server_handle;
   const char *err_msg_1 = NULL;

   use_master = 0;
   as_reply = NULL;
   memset(&chpw_creds, 0, sizeof(chpw_creds));

   pw0.data = pw0array;

   if (password && password[0]) {
      if ((pw0.length = strlen(password)) > sizeof(pw0array)) {
	 ret = EINVAL;
	 goto cleanup;
      }
      strcpy(pw0.data, password);
   } else {
      pw0.data[0] = '\0';
      pw0.length = sizeof(pw0array);
   }

   pw1.data = pw1array;
   pw1.data[0] = '\0';
   pw1.length = sizeof(pw1array);

   ret = krb5int_gic_opt_to_opte(context, options, &opte, 1,
				 "krb5_get_init_creds_password");
   if (ret)
      goto cleanup;

   /* first try: get the requested tkt from any kdc */

   ret = krb5_get_init_creds(context, creds, client, prompter, data,
			     start_time, in_tkt_service, opte,
			     krb5_get_as_key_password, (void *) &pw0,
			     &use_master, &as_reply);
   /* check for success */

   if (ret == 0)
      goto cleanup;

   /* If all the kdc's are unavailable, or if the error was due to a
      user interrupt, or preauth errored out, fail */

   if ((ret == KRB5_KDC_UNREACH) ||
       (ret == KRB5_PREAUTH_FAILED) ||
       (ret == KRB5_LIBOS_PWDINTR) ||
       (ret == KRB5_REALM_CANT_RESOLVE))
      goto cleanup;

   /* if the reply did not come from the master kdc, try again with
      the master kdc */

   if (!use_master) {
      use_master = 1;

      if (as_reply) {
	  krb5_free_kdc_rep( context, as_reply);
	  as_reply = NULL;
      }
      
      err_msg_1 = krb5_get_error_message(context, ret);

      ret2 = krb5_get_init_creds(context, creds, client, prompter, data,
				 start_time, in_tkt_service, opte,
				 krb5_get_as_key_password, (void *) &pw0,
				 &use_master, &as_reply);
      
      if (ret2 == 0) {
	 ret = 0;
	 goto cleanup;
      }

      /* if the master is unreachable, return the error from the
	 slave we were able to contact or reset the use_master flag */

      if ((ret2 != KRB5_KDC_UNREACH) &&
	(ret2 != KRB5_REALM_CANT_RESOLVE) &&
	(ret2 != KRB5_REALM_UNKNOWN)) {
	ret = ret2;
      } else {
	use_master = 0;
	/* Solaris - if 2nd try failed, reset 1st err msg */
	if (ret2 && err_msg_1) {
	  krb5_set_error_message(context, ret, err_msg_1);
	}
      }
   }

/* Solaris Kerberos: 163 resync */
/* #ifdef USE_LOGIN_LIBRARY */
	if (ret == KRB5KDC_ERR_KEY_EXP)
		goto cleanup;	/* Login library will deal appropriately with this error */
/* #endif */

   /* at this point, we have an error from the master.  if the error
      is not password expired, or if it is but there's no prompter,
      return this error */

   if ((ret != KRB5KDC_ERR_KEY_EXP) ||
       (prompter == NULL))
      goto cleanup;

    /* historically the default has been to prompt for password change.
     * if the change password prompt option has not been set, we continue
     * to prompt.  Prompting is only disabled if the option has been set
     * and the value has been set to false.
     */
    if (!(options->flags & KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT))
	goto cleanup;

    /* ok, we have an expired password.  Give the user a few chances
      to change it */


   /*
    * Solaris Kerberos:
    * Get the correct change password service principal name to use.
    * This is necessary because SEAM based admin servers require
    * a slightly different service principal name than MIT/MS servers.
    */

   memset((char *) &params, 0, sizeof (params));

   snprintf(admin_realm, sizeof (admin_realm),
	krb5_princ_realm(context, client)->data);
   params.mask |= KADM5_CONFIG_REALM;
   params.realm = admin_realm;

   ret=kadm5_get_cpw_host_srv_name(context, admin_realm, &cpw_service);

   if (ret != KADM5_OK) {
	syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
	    "Kerberos mechanism library: Unable to get change password "
	    "service name for realm %s\n"), admin_realm);
	goto cleanup;
   } else {
	ret=0;
   }

   /* extract the string version of the principal */
   if ((ret = krb5_unparse_name(context, client, &princ_str)))
	goto cleanup;

   ret = kadm5_init_with_password(princ_str, pw0array, cpw_service,
	&params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, NULL,
	&server_handle);

   if (ret != 0) {
	goto cleanup;
   }

   prompt[0].prompt = "Enter new password";
   prompt[0].hidden = 1;
   prompt[0].reply = &pw0;
   prompt_types[0] = KRB5_PROMPT_TYPE_NEW_PASSWORD;

   prompt[1].prompt = "Enter it again";
   prompt[1].hidden = 1;
   prompt[1].reply = &pw1;
   prompt_types[1] = KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN;

   strcpy(banner, "Password expired.  You must change it now.");

   for (tries = 3; tries; tries--) {
      pw0.length = sizeof(pw0array);
      pw1.length = sizeof(pw1array);

      /* PROMPTER_INVOCATION */
      krb5int_set_prompt_types(context, prompt_types);
      if ((ret = ((*prompter)(context, data, 0, banner,
			      sizeof(prompt)/sizeof(prompt[0]), prompt))))
	 goto cleanup;
      krb5int_set_prompt_types(context, 0);


      if (strcmp(pw0.data, pw1.data) != 0) {
	 ret = KRB5_LIBOS_BADPWDMATCH;
	 sprintf(banner, "%s.  Please try again.", error_message(ret));
      } else if (pw0.length == 0) {
	 ret = KRB5_CHPW_PWDNULL;
	 sprintf(banner, "%s.  Please try again.", error_message(ret));
      } else {
	 int result_code;
	 krb5_data code_string;
	 krb5_data result_string;

	 if ((ret = krb5_change_password(context, &chpw_creds, pw0array,
					 &result_code, &code_string,
					 &result_string)))
	    goto cleanup;

	 /* the change succeeded.  go on */

	 if (result_code == 0) {
	    krb5_xfree(result_string.data);
	    break;
	 }

	 /* set this in case the retry loop falls through */

	 ret = KRB5_CHPW_FAIL;

	 if (result_code != KRB5_KPASSWD_SOFTERROR) {
	    krb5_xfree(result_string.data);
	    goto cleanup;
	 }

	 /* the error was soft, so try again */

	 /* 100 is I happen to know that no code_string will be longer
	    than 100 chars */

	 if (result_string.length > (sizeof(banner)-100))
	    result_string.length = sizeof(banner)-100;

	 sprintf(banner, "%.*s%s%.*s.  Please try again.\n",
		 (int) code_string.length, code_string.data,
		 result_string.length ? ": " : "",
		 (int) result_string.length,
		 result_string.data ? result_string.data : "");

	 krb5_xfree(code_string.data);
	 krb5_xfree(result_string.data);
      }
   }

   if (ret)
      goto cleanup;

   /* the password change was successful.  Get an initial ticket
      from the master.  this is the last try.  the return from this
      is final.  */

   ret = krb5_get_init_creds(context, creds, client, prompter, data,
			     start_time, in_tkt_service, opte,
			     krb5_get_as_key_password, (void *) &pw0,
			     &use_master, &as_reply);

cleanup:
   if (err_msg_1)
     free((void *)err_msg_1);

   krb5int_set_prompt_types(context, 0);
   /* if getting the password was successful, then check to see if the
      password is about to expire, and warn if so */

   if (ret == 0) {
      krb5_timestamp now;
      krb5_last_req_entry **last_req;
      int hours;

      /* XXX 7 days should be configurable.  This is all pretty ad hoc,
	 and could probably be improved if I was willing to screw around
	 with timezones, etc. */

      if (prompter &&
	  (in_tkt_service && cpw_service &&
	   (strcmp(in_tkt_service, cpw_service) != 0)) &&
	  ((ret = krb5_timeofday(context, &now)) == 0) &&
	  as_reply->enc_part2->key_exp &&
	  ((hours = ((as_reply->enc_part2->key_exp-now)/(60*60))) <= 7*24) &&
	  (hours >= 0)) {
	 if (hours < 1)
	    sprintf(banner,
		    "Warning: Your password will expire in less than one hour.");
	 else if (hours <= 48)
	    sprintf(banner, "Warning: Your password will expire in %d hour%s.",
		    hours, (hours == 1)?"":"s");
	 else
	    sprintf(banner, "Warning: Your password will expire in %d days.",
		    hours/24);

	 /* ignore an error here */
         /* PROMPTER_INVOCATION */
	 (*prompter)(context, data, 0, banner, 0, 0);
      } else if (prompter &&
		 (!in_tkt_service ||
		  (strcmp(in_tkt_service, "kadmin/changepw") != 0)) &&
		 as_reply->enc_part2 && as_reply->enc_part2->last_req) {
	 /*
	  * Check the last_req fields
	  */

	 for (last_req = as_reply->enc_part2->last_req; *last_req; last_req++)
	    if ((*last_req)->lr_type == KRB5_LRQ_ALL_PW_EXPTIME ||
		(*last_req)->lr_type == KRB5_LRQ_ONE_PW_EXPTIME) {
	       krb5_deltat delta;
	       char ts[256];

	       if ((ret = krb5_timeofday(context, &now)))
		  break;

	       if ((ret = krb5_timestamp_to_string((*last_req)->value,
						   ts, sizeof(ts))))
		  break;

	       delta = (*last_req)->value - now;

	       if (delta < 3600)
		  sprintf(banner,
		    "Warning: Your password will expire in less than one "
		     "hour on %s", ts);
	       else if (delta < 86400*2)
		  sprintf(banner,
		     "Warning: Your password will expire in %d hour%s on %s",
		     delta / 3600, delta < 7200 ? "" : "s", ts);
	       else
		  sprintf(banner,
		     "Warning: Your password will expire in %d days on %s",
		     delta / 86400, ts);
	       /* ignore an error here */
	       /* PROMPTER_INVOCATION */
	       (*prompter)(context, data, 0, banner, 0, 0);
	    }
      }
   }

   free(cpw_service);
   free(princ_str);
   if (opte && krb5_gic_opt_is_shadowed(opte))
      krb5_get_init_creds_opt_free(context, (krb5_get_init_creds_opt *)opte);
   memset(pw0array, 0, sizeof(pw0array));
   memset(pw1array, 0, sizeof(pw1array));
   krb5_free_cred_contents(context, &chpw_creds);
   /*
    * Solaris Kerberos:
    * Argument, ptr_as_reply, being returned to caller if success and non-NULL.
    */
   if (as_reply != NULL) {
	if (ptr_as_reply == NULL)
      	   krb5_free_kdc_rep(context, as_reply);
	else
	   *ptr_as_reply = as_reply;
   }

   return(ret);
}
krb5_error_code krb5int_populate_gic_opt (
    krb5_context context, krb5_gic_opt_ext **opte,
    krb5_flags options, krb5_address * const *addrs, krb5_enctype *ktypes,
    krb5_preauthtype *pre_auth_types, krb5_creds *creds)
{
  int i;
  krb5_int32 starttime;
  krb5_get_init_creds_opt opt;


    krb5_get_init_creds_opt_init(&opt);
    if (addrs)
      krb5_get_init_creds_opt_set_address_list(&opt, (krb5_address **) addrs);
    if (ktypes) {
	for (i=0; ktypes[i]; i++);
	if (i)
	    krb5_get_init_creds_opt_set_etype_list(&opt, ktypes, i);
    }
    if (pre_auth_types) {
	for (i=0; pre_auth_types[i]; i++);
	if (i)
	    krb5_get_init_creds_opt_set_preauth_list(&opt, pre_auth_types, i);
    }
    if (options&KDC_OPT_FORWARDABLE)
	krb5_get_init_creds_opt_set_forwardable(&opt, 1);
    else krb5_get_init_creds_opt_set_forwardable(&opt, 0);
    if (options&KDC_OPT_PROXIABLE)
	krb5_get_init_creds_opt_set_proxiable(&opt, 1);
    else krb5_get_init_creds_opt_set_proxiable(&opt, 0);
    if (creds && creds->times.endtime) {
        krb5_timeofday(context, &starttime);
        if (creds->times.starttime) starttime = creds->times.starttime;
        krb5_get_init_creds_opt_set_tkt_life(&opt, creds->times.endtime - starttime);
    }
    return krb5int_gic_opt_to_opte(context, &opt, opte, 0,
				   "krb5int_populate_gic_opt");
}

/*
  Rewrites get_in_tkt in terms of newer get_init_creds API.
 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, and using creds->times.starttime, creds->times.endtime,
 creds->times.renew_till as from, till, and rtime.  
 creds->times.renew_till is ignored unless the RENEWABLE option is requested.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 If password is non-NULL, it is converted using the cryptosystem entry
 point for a string conversion routine, seeded with the client's name.
 If password is passed as NULL, the password is read from the terminal,
 and then converted into a key.

 A succesful call will place the ticket in the credentials cache ccache.

 returns system errors, encryption errors
 */
krb5_error_code KRB5_CALLCONV
krb5_get_in_tkt_with_password(krb5_context context, krb5_flags options,
			      krb5_address *const *addrs, krb5_enctype *ktypes,
			      krb5_preauthtype *pre_auth_types,
			      const char *password, krb5_ccache ccache,
			      krb5_creds *creds, krb5_kdc_rep **ret_as_reply)
{
    krb5_error_code retval;
    krb5_data pw0;
    char pw0array[1024];
    char * server;
    krb5_principal server_princ, client_princ;
    int use_master = 0;
    krb5_gic_opt_ext *opte = NULL;

    pw0array[0] = '\0';
    pw0.data = pw0array;
    if (password) {
	pw0.length = strlen(password);
	if (pw0.length > sizeof(pw0array))
	    return EINVAL;
	strncpy(pw0.data, password, sizeof(pw0array));
	if (pw0.length == 0)
	    pw0.length = sizeof(pw0array);
    } else {
	pw0.length = sizeof(pw0array);
    }
    retval = krb5int_populate_gic_opt(context, &opte,
				      options, addrs, ktypes,
				      pre_auth_types, creds);
    if (retval)
      return (retval);
    retval = krb5_unparse_name( context, creds->server, &server);
    if (retval) {
      return (retval);
      krb5_get_init_creds_opt_free(context, (krb5_get_init_creds_opt *)opte);
    }
    server_princ = creds->server;
    client_princ = creds->client;
        retval = krb5_get_init_creds (context,
					   creds, creds->client,  
					   krb5_prompter_posix,  NULL,
					   0, server, opte,
				      krb5_get_as_key_password, &pw0,
				      &use_master, ret_as_reply);
	  krb5_free_unparsed_name( context, server);
	  krb5_get_init_creds_opt_free(context, (krb5_get_init_creds_opt *)opte);
	if (retval) {
	  return (retval);
	}
	if (creds->server)
	    krb5_free_principal( context, creds->server);
	if (creds->client)
	    krb5_free_principal( context, creds->client);
	creds->client = client_princ;
	creds->server = server_princ;
	/* store it in the ccache! */
	if (ccache)
	  if ((retval = krb5_cc_store_cred(context, ccache, creds)))
	    return (retval);
	return retval;
  }


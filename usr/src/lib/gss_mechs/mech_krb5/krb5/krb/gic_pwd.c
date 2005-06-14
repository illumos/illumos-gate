/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Gets initial credentials upon authentication
 */

#include <k5-int.h>
#include <com_err.h>
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
			kadm5_config_params *, krb5_ui_4, krb5_ui_4, void **);
extern kadm5_ret_t kadm5_chpass_principal_util(void *, krb5_principal,
			char *, char **, char *, int);

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
		prompter = krb5_prompter_posix;

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
	if (ret = (((*prompter)(context, prompter_data, NULL, NULL,
				1, &prompt)))) {
	    krb5int_set_prompt_types(context, 0);
	    return(ret);
	}
	krb5int_set_prompt_types(context, 0);
    }

    if ((salt->length == -1) && (salt->data == NULL)) {
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
krb5_get_init_creds_password(
     krb5_context context,
     krb5_creds *creds,
     krb5_principal client,
     char *password,
     krb5_prompter_fct prompter,
     void *data,
     krb5_deltat start_time,
     char *in_tkt_service,
     krb5_get_init_creds_opt *options)
{
   krb5_error_code ret, ret2;
   int use_master;
   krb5_kdc_rep *as_reply;
   int tries;
   krb5_creds chpw_creds;
   krb5_get_init_creds_opt chpw_opts;
   krb5_data pw0, pw1;
   char banner[1024], pw0array[1024], pw1array[1024];
   krb5_prompt prompt[2];
   krb5_prompt_type prompt_types[sizeof(prompt)/sizeof(prompt[0])];

   char admin_realm[1024], *cpw_service=NULL, *princ_str=NULL;
   kadm5_config_params  params;
   void *server_handle;

   use_master = 0;
   as_reply = NULL;
   memset(&chpw_creds, 0, sizeof(chpw_creds));

   pw0.data = pw0array;

   if (password) {
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

   /* first try: get the requested tkt from any kdc */

   ret = krb5_get_init_creds(context, creds, client, prompter, data,
			     start_time, in_tkt_service, options,
			     krb5_get_as_key_password, (void *) &pw0,
			     use_master, &as_reply);

   /* check for success */

   if (ret == 0)
      goto cleanup;

   /* If all the kdc's are unavailable, or if the error was due to a
      user interrupt, fail */

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

      ret2 = krb5_get_init_creds(context, creds, client, prompter, data,
				 start_time, in_tkt_service, options,
				 krb5_get_as_key_password, (void *) &pw0,
				 use_master, &as_reply);

      if (ret2 == 0) {
	 ret = 0;
	 goto cleanup;
      }

      /* if the master is unreachable, return the error from the
	 slave we were able to contact */

      if ((ret2 == KRB5_KDC_UNREACH) ||
	  (ret2 == KRB5_REALM_CANT_RESOLVE) ||
	   (ret2 == KRB5_REALM_UNKNOWN))
	 goto cleanup;

      ret = ret2;
   }

#ifdef USE_LOGIN_LIBRARY
	if (ret == KRB5KDC_ERR_KEY_EXP)
	    goto cleanup; /* Login library will deal appropriately with this error */
#endif

   /* at this point, we have an error from the master.  if the error
      is not password expired, or if it is but there's no prompter,
      return this error */

   if ((ret != KRB5KDC_ERR_KEY_EXP) ||
       (prompter == NULL))
      goto cleanup;

   /* ok, we have an expired password.  Give the user a few chances
      to change it */


   /* Solaris Kerberos:
    *
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
	&params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, &server_handle);

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

   strcpy(banner, "Password expired. You must change it now.");

   for (tries = 3; tries; tries--) {
      pw0.length = sizeof(pw0array);
      pw1.length = sizeof(pw1array);

      /* PROMPTER_INVOCATION */
      krb5int_set_prompt_types(context, prompt_types);
      if (ret = ((*prompter)(context, data, 0, banner,
			     sizeof(prompt)/sizeof(prompt[0]), prompt)))
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

         result_code = kadm5_chpass_principal_util(server_handle, client,
						pw0.data,
						NULL /* don't need pw back */,
						banner,
						sizeof(banner));

	 /* the change succeeded.  go on */

	 if (result_code == 0) {
	    break;
	 }

	 /* set this in case the retry loop falls through */

	 ret = KRB5_CHPW_FAIL;

	 if (result_code != KRB5_KPASSWD_SOFTERROR) {
	    goto cleanup;
	 }
      }
   }

   if (ret)
      goto cleanup;

   /* the password change was successful.  Get an initial ticket
      from the master.  this is the last try.  the return from this
      is final.  */

   ret = krb5_get_init_creds(context, creds, client, prompter, data,
			     start_time, in_tkt_service, options,
			     krb5_get_as_key_password, (void *) &pw0,
			     use_master, &as_reply);

cleanup:
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
      } else if  (prompter &&
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
	} /* prompter && !in_tkt_service */
   }

   free(cpw_service);
   free(princ_str);
   memset(pw0array, 0, sizeof(pw0array));
   memset(pw1array, 0, sizeof(pw1array));
   krb5_free_cred_contents(context, &chpw_creds);
   if (as_reply)
      krb5_free_kdc_rep(context, as_reply);

   return(ret);
}


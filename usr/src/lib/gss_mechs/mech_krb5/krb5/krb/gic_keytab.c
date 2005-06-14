/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
#include <k5-int.h>

/*ARGSUSED*/
static krb5_error_code
krb5_get_as_key_keytab(
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
    krb5_keytab keytab = (krb5_keytab) gak_data;
    krb5_error_code ret;
    krb5_keytab_entry kt_ent;
    krb5_keyblock *kt_key;

    /* if there's already a key of the correct etype, we're done.
       if the etype is wrong, free the existing key, and make
       a new one. */

    if (as_key->length) {
	if (as_key->enctype == etype)
	    return(0);

	krb5_free_keyblock(context, as_key);
	as_key->length = 0;
    }

    if (!krb5_c_valid_enctype(etype))
	return(KRB5_PROG_ETYPE_NOSUPP);

    if ((ret = krb5_kt_get_entry(context, keytab, client,
				 0, /* don't have vno available */
				 etype, &kt_ent)) != NULL)
	return(ret);

    ret = krb5_copy_keyblock(context, &kt_ent.key, &kt_key);

    /* again, krb5's memory management is lame... */

    *as_key = *kt_key;
    krb5_xfree(kt_key);

    (void) krb5_kt_free_entry(context, &kt_ent);

    return(ret);
}

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_keytab(
     krb5_context context,
     krb5_creds *creds,
     krb5_principal client,
     krb5_keytab arg_keytab,
     krb5_deltat start_time,
     char *in_tkt_service,
     krb5_get_init_creds_opt *options)
{
   krb5_error_code ret, ret2;
   int use_master;
   krb5_keytab keytab;

   if (arg_keytab == NULL) {
       if (ret = krb5_kt_default(context, &keytab))
	   return ret;
   } else {
       keytab = arg_keytab;
   }

   use_master = 0;

   /* first try: get the requested tkt from any kdc */

   ret = krb5_get_init_creds(context, creds, client, NULL, NULL,
			     start_time, in_tkt_service, options,
			     krb5_get_as_key_keytab, (void *) keytab,
			     use_master,NULL);

   /* check for success */

   if (ret == 0)
      goto cleanup;

   /* If all the kdc's are unavailable fail */

   if ((ret == KRB5_KDC_UNREACH) || (ret == KRB5_REALM_CANT_RESOLVE))
      goto cleanup;

   /* if the reply did not come from the master kdc, try again with
      the master kdc */

   if (!use_master) {
      use_master = 1;

      ret2 = krb5_get_init_creds(context, creds, client, NULL, NULL,
				 start_time, in_tkt_service, options,
				 krb5_get_as_key_keytab, (void *) keytab,
				 use_master, NULL);
      
      if (ret2 == 0) {
	 ret = 0;
	 goto cleanup;
      }

      /* if the master is unreachable, return the error from the
	 slave we were able to contact */

      if ((ret2 == KRB5_KDC_UNREACH) || (ret == KRB5_REALM_CANT_RESOLVE))
	 goto cleanup;

      ret = ret2;
   }

   /* at this point, we have a response from the master.  Since we don't
      do any prompting or changing for keytabs, that's it. */

cleanup:
   if (arg_keytab == NULL)
       (void) krb5_kt_close(context, keytab);

   return(ret);
}


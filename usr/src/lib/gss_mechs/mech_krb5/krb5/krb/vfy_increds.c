/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "k5-int.h"
#include "int-proto.h"

/* Solaris Kerberos */
extern krb5_error_code krb5_libdefault_boolean();

static krb5_error_code
krb5_cc_copy_creds_except(krb5_context context, krb5_ccache incc, krb5_ccache outcc, krb5_principal princ)
{
   krb5_error_code code;
   krb5_flags flags;
   krb5_cc_cursor cur;
   krb5_creds creds;

   flags = 0;				/* turns off OPENCLOSE mode */
   /* Solaris Kerberos */
   if ((code = krb5_cc_set_flags(context, incc, flags)) != 0)
      return(code);
   /* Solaris Kerberos */
   if ((code = krb5_cc_set_flags(context, outcc, flags)) != 0)
      return(code);

   /* Solaris Kerberos */
   if ((code = krb5_cc_start_seq_get(context, incc, &cur)) != 0)
      goto cleanup;

   /* Solaris Kerberos */
   while ((code = krb5_cc_next_cred(context, incc, &cur, &creds)) == 0) {
      if (krb5_principal_compare(context, princ, creds.server))
	 continue;

      code = krb5_cc_store_cred(context, outcc, &creds);
      krb5_free_cred_contents(context, &creds);
      if (code)
	 goto cleanup;
   }

   if (code != KRB5_CC_END)
      goto cleanup;

   code = 0;

cleanup:
   flags = KRB5_TC_OPENCLOSE;

   /* Solaris Kerberos */
   if (code)
      (void) krb5_cc_set_flags(context, incc, flags);
   else
      code = krb5_cc_set_flags(context, incc, flags);

   /* Solaris Kerberos */
   if (code)
      (void) krb5_cc_set_flags(context, outcc, flags);
   else
      code = krb5_cc_set_flags(context, outcc, flags);

   return(code);
}

krb5_error_code KRB5_CALLCONV
krb5_verify_init_creds(krb5_context context,
		       krb5_creds *creds,
		       krb5_principal server_arg,
		       krb5_keytab keytab_arg,
		       krb5_ccache *ccache_arg,
		       krb5_verify_init_creds_opt *options)
{
   krb5_error_code ret;
   krb5_principal server;
   krb5_keytab keytab;
   krb5_ccache ccache;
   krb5_keytab_entry kte;
   krb5_creds in_creds, *out_creds;
   krb5_auth_context authcon;
   krb5_data ap_req;
   
   /* KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN */

   server = NULL;
   keytab = NULL;
   ccache = NULL;
   out_creds = NULL;
   authcon = NULL;
   ap_req.data = NULL;

   /* Solaris Kerberos */
   if (server_arg)
      server = server_arg;
   else if (ret = krb5_sname_to_principal(context, NULL, NULL, 
					KRB5_NT_SRV_HST, &server))
      goto cleanup;
      
   /* first, check if the server is in the keytab.  If not, there's
      no reason to continue.  rd_req does all this, but there's
      no way to know that a given error is caused by a missing
      keytab or key, and not by some other problem. */

   if (keytab_arg) {
      keytab = keytab_arg;
   } else {
       /* Solaris Kerberos: ignore errors here, deal with below */
      ret = krb5_kt_default(context, &keytab);
   }

   /*
    * Solaris Kerberos:
    * Warning: be very, very careful when modifying the logic here
    */
   if (keytab == NULL ||
       (ret = krb5_kt_get_entry(context, keytab, server, 0, 0, &kte))) {
       /* this means there is no keying material.  This is ok, as long as
	  it is not prohibited by the configuration */
       /* Solaris Kerberos */
       int nofail = 1;  /* Solaris Kerberos: default return error if keytab problems */

       if (options &&
	   (options->flags & KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL)) {
	   /* first, if options are set then use the option value to set nofail */
	    nofail = options->ap_req_nofail;
       } else {
	   /* 
	    * Solaris Kerberos:
	    * Check verify_ap_req_nofail if set in config file.  Note this logic
	    * assumes that krb5_libdefault_boolean will not set nofail to a
	    * default value if verify_ap_req_nofail is not explictly set in
	    * config file.  Don't care about the return code.
	    */
	   (void) krb5_libdefault_boolean(context, &creds->client->realm,
					  "verify_ap_req_nofail",
					  &nofail);
       }
       /* Solaris Kerberos: exit without an error ONLY if nofail is false */
       if (!nofail)
	   ret = 0; 

       goto cleanup;
   }

   krb5_kt_free_entry(context, &kte);

   /* If the creds are for the server principal, we're set, just do
      a mk_req.	 Otherwise, do a get_credentials first. */

   if (krb5_principal_compare(context, server, creds->server)) {
      /* make an ap_req */
      if ((ret = krb5_mk_req_extended(context, &authcon, 0, NULL, creds,
				      &ap_req)))
	 goto cleanup;
   } else {
      /* this is unclean, but it's the easiest way without ripping the
	 library into very small pieces.  store the client's initial cred
	 in a memory ccache, then call the library.  Later, we'll copy
	 everything except the initial cred into the ccache we return to
	 the user.  A clean implementation would involve library
	 internals with a coherent idea of "in" and "out". */

      /* insert the initial cred into the ccache */

      if ((ret = krb5_cc_resolve(context, "MEMORY:rd_req", &ccache)))
	 goto cleanup;
      /* Solaris Kerberos */
      if ((ret = krb5_cc_initialize(context, ccache, creds->client)) != 0)
	 goto cleanup;

      /* Solaris Kerberos */
      if ((ret = krb5_cc_store_cred(context, ccache, creds)) != 0)
	 goto cleanup;

      /* set up for get_creds */
      memset(&in_creds, 0, sizeof(in_creds));
      in_creds.client = creds->client;
      in_creds.server = server;
      if ((ret = krb5_timeofday(context, &in_creds.times.endtime)))
	 goto cleanup;
      in_creds.times.endtime += 5*60;

      if ((ret = krb5_get_credentials(context, 0, ccache, &in_creds,
				      &out_creds)))
	 goto cleanup;

      /* make an ap_req */
      if ((ret = krb5_mk_req_extended(context, &authcon, 0, NULL, out_creds,
				      &ap_req)))
	 goto cleanup;
   }

   /* wipe the auth context for mk_req */
   if (authcon) {
      krb5_auth_con_free(context, authcon);
      authcon = NULL;
   }

   /* verify the ap_req */

   if ((ret = krb5_rd_req(context, &authcon, &ap_req, server, keytab,
			  NULL, NULL)))
      goto cleanup;

   /* if we get this far, then the verification succeeded.  We can
      still fail if the library stuff here fails, but that's it */

   if (ccache_arg && ccache) {
       if (*ccache_arg == NULL) {
	   krb5_ccache retcc;

	   retcc = NULL;

	   /* Solaris Kerberos */
	   if (((ret = krb5_cc_resolve(context, "MEMORY:rd_req2", &retcc)) != 0) ||
	       ((ret = krb5_cc_initialize(context, retcc, creds->client)) != 0) ||
	       ((ret = krb5_cc_copy_creds_except(context, ccache, retcc,
						creds->server)) != 0)) {
	       /* Solaris Kerberos */
	       if (retcc)
		   (void) krb5_cc_destroy(context, retcc);
	   } else {
	       *ccache_arg = retcc;
	   }
       } else {
	   ret = krb5_cc_copy_creds_except(context, ccache, *ccache_arg,
					   server);
       }
   }

   /* if any of the above paths returned an errors, then ret is set
      accordingly.  either that, or it's zero, which is fine, too */

cleanup:
   if (!server_arg && server)
      krb5_free_principal(context, server);
    /* Solaris Kerberos */
   if (!keytab_arg && keytab)
      (void) krb5_kt_close(context, keytab);
    /* Solaris Kerberos */
   if (ccache)
      (void) krb5_cc_destroy(context, ccache);
   if (out_creds)
      krb5_free_creds(context, out_creds);
   if (authcon)
      krb5_auth_con_free(context, authcon);
   if (ap_req.data)
      krb5_xfree(ap_req.data);

   return(ret);
}

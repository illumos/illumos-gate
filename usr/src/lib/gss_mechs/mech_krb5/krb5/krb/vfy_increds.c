#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <k5-int.h>
#include "int-proto.h"

extern krb5_error_code krb5_libdefault_boolean();

static krb5_error_code
krb5_cc_copy_creds_except(krb5_context context, krb5_ccache incc, krb5_ccache outcc, krb5_principal princ)
{
   krb5_error_code code;
   krb5_flags flags;
   krb5_cc_cursor cur;
   krb5_creds creds;

   flags = 0;				/* turns off OPENCLOSE mode */
   if ((code = krb5_cc_set_flags(context, incc, flags)) != NULL)
      return(code);
   if ((code = krb5_cc_set_flags(context, outcc, flags)) != NULL)
      return(code);

   if ((code = krb5_cc_start_seq_get(context, incc, &cur)) != NULL)
      goto cleanup;

   while ((code = krb5_cc_next_cred(context, incc, &cur, &creds)) == NULL) {
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

   if (code)
      (void) krb5_cc_set_flags(context, incc, flags);
   else
      code = krb5_cc_set_flags(context, incc, flags);

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

   if (server_arg) {
      server = server_arg;
   } else {
      if ((ret = krb5_sname_to_principal(context, NULL, NULL, 
					KRB5_NT_SRV_HST, &server))) {
	goto cleanup;
      } else {
	/*
	 * Solaris Kerberos:
	 * We check first up to see whether 'verify_ap_req_fail' is
	 * set to false, because if FALSE there is no point in
	 * proceeding any further with the strict TGT verification check
	 * for the 'host/fqdn' service principal in the local keytab.
	 */
	int nofail;
        if (krb5_libdefault_boolean(context,
				&creds->client->realm,
				"verify_ap_req_nofail",
				&nofail) == 0) {
		/*
		 * Solaris Kerberos:
		 * If the administrator has configured the system such
		 * that its OK to fail this strict TGT verification check
		 * (i.e. verify_ap_req_nofail = false), set the
		 * 'ret' code to 0 and cleanup.
		 */
		if (!nofail) {
			ret = 0;
			goto cleanup;
		}
	}
      }
   }
      
   /* first, check if the server is in the keytab.  If not, there's
      no reason to continue.  rd_req does all this, but there's
      no way to know that a given error is caused by a missing
      keytab or key, and not by some other problem. */

   if (keytab_arg) {
      keytab = keytab_arg;
   } else {
      if ((ret = krb5_kt_default(context, &keytab)))
	 goto cleanup;
   }

   if ((ret = krb5_kt_get_entry(context, keytab, server, 0, 0, &kte)) != NULL) {
       /* this means there is no keying material.  This is ok, as long as
	  it is not prohibited by the configuration */
       if (options &&
	   (options->flags & KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL)) {
	   if (options->ap_req_nofail)
	       goto cleanup;
       }
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

      if ((ret = krb5_cc_initialize(context, ccache, creds->client)) != NULL)
	 goto cleanup;

      if ((ret = krb5_cc_store_cred(context, ccache, creds)) != NULL)
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

	   if (((ret = krb5_cc_resolve(context, "MEMORY:rd_req2", &retcc)) != NULL) ||
	       ((ret = krb5_cc_initialize(context, retcc, creds->client)) != NULL) ||
	       ((ret = krb5_cc_copy_creds_except(context, ccache, retcc,
						creds->server)) != NULL)) {
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
   if (!keytab_arg && keytab)
      (void) krb5_kt_close(context, keytab);
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

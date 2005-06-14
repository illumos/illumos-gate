/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * /usr/src/lib/gss_mechs/mech_krb5/mech/copy_ccache.c
 */

#include <gssapiP_krb5.h>

GSS_DLLIMP OM_uint32 KRB5_CALLCONV
gss_krb5_copy_ccache(ctx, minor_status, cred_handle, out_ccache)
     void *ctx;
     OM_uint32 *minor_status;
     gss_cred_id_t cred_handle;
     krb5_ccache out_ccache;
{
   OM_uint32 major_status;
   krb5_gss_cred_id_t k5creds;
   krb5_cc_cursor cursor;
   krb5_creds creds;
   krb5_error_code code;
   krb5_context context = ctx;

   mutex_lock(&krb5_mutex);

   *minor_status = 0;

   /* validate the cred handle */
   major_status = krb5_gss_validate_cred_no_lock(context, minor_status,
					         cred_handle);
   if (major_status)
       goto unlock;

   k5creds = (krb5_gss_cred_id_t) cred_handle;
   if (k5creds->usage == GSS_C_ACCEPT) {
       *minor_status = (OM_uint32) G_BAD_USAGE;
	major_status = GSS_S_FAILURE;
	goto unlock;
   }

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, &context)))
       return (GSS_S_FAILURE);
#endif

   code = krb5_cc_start_seq_get(context, k5creds->ccache, &cursor);
   if (code) {
       *minor_status = code;
	major_status = GSS_S_FAILURE;
	goto unlock;
   }
   while (!code && !krb5_cc_next_cred(context, k5creds->ccache, &cursor, &creds))
       code = krb5_cc_store_cred(context, out_ccache, &creds);
   krb5_cc_end_seq_get(context, k5creds->ccache, &cursor);

   if (code) {
       *minor_status = code;
	major_status = GSS_S_FAILURE;
	goto unlock;
   } else {
       *minor_status = 0;
	major_status = GSS_S_COMPLETE;
	goto unlock;
   }

unlock:
   mutex_unlock(&krb5_mutex);
   return(major_status);
}

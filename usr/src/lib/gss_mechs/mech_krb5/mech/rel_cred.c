/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <gssapiP_krb5.h>
#include <k5-int.h>

OM_uint32
krb5_gss_release_cred(ctx, minor_status, cred_handle)
     void      *ctx;
     OM_uint32 *minor_status;
     gss_cred_id_t *cred_handle;
{
    OM_uint32 status;

    mutex_lock(&krb5_mutex);
    status = krb5_gss_release_cred_no_lock(ctx, minor_status, cred_handle);
    mutex_unlock(&krb5_mutex);
    return(status);
}

OM_uint32
krb5_gss_release_cred_no_lock(ctx, minor_status, cred_handle)
     void      *ctx;
     OM_uint32 *minor_status;
     gss_cred_id_t *cred_handle;
{
   krb5_context context = ctx;
   krb5_gss_cred_id_t cred;
   krb5_error_code code1, code2, code3;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);
#endif

   if (*cred_handle == GSS_C_NO_CREDENTIAL)
   {
      /* Solaris Kerberos:  the followin function does nothing */
      return(kg_release_defcred(minor_status));
   }

   if (! kg_delete_cred_id(*cred_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_NO_CRED);
   }

   cred = (krb5_gss_cred_id_t)*cred_handle;

   if (cred->ccache) {
      /*
       * If the ccache is a MEMORY ccache then this credential handle
       * should be the only way to get to it, at least until the advent
       * of a GSS_Duplicate_cred() (which is needed and may well be
       * added some day).  Until then MEMORY ccaches must be destroyed,
       * not closed, else their contents (tickets, session keys) will
       * leak.
       */
      if (strcmp("MEMORY", krb5_cc_get_type(context, cred->ccache)) == 0)
         code1 = krb5_cc_destroy(context, cred->ccache);
      else
         code1 = krb5_cc_close(context, cred->ccache);
   } else
      code1 = 0;

   if (cred->keytab)
      code2 = krb5_kt_close(context, cred->keytab);
   else
      code2 = 0;

   if (cred->rcache)
      code3 = krb5_rc_close(context, cred->rcache);
   else
      code3 = 0;
   if (cred->princ)
      krb5_free_principal(context, cred->princ);
   xfree(cred);

   *cred_handle = NULL;

   *minor_status = 0;
   if (code1)
      *minor_status = code1;
   if (code2)
      *minor_status = code2;
   if (code3)
      *minor_status = code3;

   return(*minor_status?GSS_S_FAILURE:GSS_S_COMPLETE);
}

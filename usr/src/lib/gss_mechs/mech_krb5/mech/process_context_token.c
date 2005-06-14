/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * $Id: process_context_token.c,v 1.10 1996/07/22 20:34:23 marc Exp $
 */

OM_uint32
krb5_gss_process_context_token(ct, minor_status, context_handle,
			       token_buffer)
     void *ct;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t token_buffer;
{
   krb5_context context;
   krb5_gss_ctx_id_rec *ctx;
   OM_uint32 majerr;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);
#endif

   mutex_lock(&krb5_mutex);
   context = ct;

   /* validate the context handle */
   if (! kg_validate_ctx_id(context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      mutex_unlock(&krb5_mutex);
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_rec *) context_handle;

   if (! ctx->established) {
      *minor_status = KG_CTX_INCOMPLETE;
      mutex_unlock(&krb5_mutex);
      return(GSS_S_NO_CONTEXT);
   }

   /* "unseal" the token */

   if (GSS_ERROR(majerr = kg_unseal(context, minor_status, (gss_ctx_id_t)ctx, 
				    token_buffer,
				    GSS_C_NO_BUFFER, NULL, NULL,
				    KG_TOK_DEL_CTX))) {
      mutex_unlock(&krb5_mutex);
      return(majerr);
   }

   /* that's it.  delete the context */
   majerr = krb5_gss_delete_sec_context_no_lock(context, minor_status, 
		   &context_handle, GSS_C_NO_BUFFER);

   mutex_unlock(&krb5_mutex);
   return(majerr);
}

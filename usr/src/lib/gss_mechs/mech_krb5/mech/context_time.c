/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
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
 * $Id: context_time.c,v 1.9 1996/07/22 20:33:41 marc Exp $
 */

OM_uint32
krb5_gss_context_time(ct, minor_status, context_handle, time_rec)
     void *ct;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     OM_uint32 *time_rec;
{
   krb5_context context = ct;
   krb5_error_code code;
   krb5_gss_ctx_id_rec *ctx;
   krb5_timestamp now;
   krb5_deltat lifetime;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, (krb5_context*) &context)))
      return(GSS_S_FAILURE);
#endif

   mutex_lock(&krb5_mutex);

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

   if (code = krb5_timeofday(context, &now)) {
      *minor_status = code;
      mutex_unlock(&krb5_mutex);
      return(GSS_S_FAILURE);
   }

   if ((lifetime = ctx->endtime - now) <= 0) {
      *time_rec = 0;
      *minor_status = 0;
      mutex_unlock(&krb5_mutex);
      return(GSS_S_CONTEXT_EXPIRED);
   } else {
      *time_rec = lifetime;
      *minor_status = 0;
      mutex_unlock(&krb5_mutex);
      return(GSS_S_COMPLETE);
   }
}

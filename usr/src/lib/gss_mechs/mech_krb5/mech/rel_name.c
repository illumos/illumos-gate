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

OM_uint32
krb5_gss_release_name(ctx, minor_status, input_name)
     void	*ctx;
     OM_uint32 *minor_status;
     gss_name_t *input_name;
{
    OM_uint32 rc;

    mutex_lock(&krb5_mutex);
    rc = krb5_gss_release_name_no_lock(ctx, minor_status, input_name);
    mutex_unlock(&krb5_mutex);
    return (rc);
}

OM_uint32
krb5_gss_release_name_no_lock(ctx, minor_status, input_name)
     void	*ctx;
     OM_uint32 *minor_status;
     gss_name_t *input_name;
{
   krb5_context context = ctx;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);
#endif


   if (! kg_validate_name(*input_name)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
   }

   (void)kg_delete_name(*input_name);

   krb5_free_principal(context, (krb5_principal) *input_name);

   *input_name = (gss_name_t) NULL;

   *minor_status = 0;
   return(GSS_S_COMPLETE);
}

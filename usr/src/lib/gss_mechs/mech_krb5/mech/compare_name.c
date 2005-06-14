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

/*
 * $Id: compare_name.c,v 1.9 1996/07/22 20:33:38 marc Exp $
 */

#include <gssapiP_krb5.h>

OM_uint32
krb5_gss_compare_name(ctx, minor_status, name1, name2, name_equal)
     void	*ctx;
     OM_uint32 *minor_status;
     gss_name_t name1;
     gss_name_t name2;
     int *name_equal;
{
   krb5_context context;
   mutex_lock(&krb5_mutex);
   context = ctx;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, (krb5_context*) &context)))
      return(GSS_S_FAILURE);
#endif

   if (! kg_validate_name(name1)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      mutex_unlock(&krb5_mutex);
      return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
   }

   if (! kg_validate_name(name2)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      mutex_unlock(&krb5_mutex);
      return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
   }

   *minor_status = 0;
   *name_equal = krb5_principal_compare(context, (krb5_principal) name1,
					(krb5_principal) name2);
   mutex_unlock(&krb5_mutex);
   return(GSS_S_COMPLETE);
}

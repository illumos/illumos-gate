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
 * $Id: indicate_mechs.c,v 1.11 1999/03/26 03:51:43 tytso Exp $
 */

#include <gssapiP_krb5.h>

/*ARGSUSED*/
OM_uint32
krb5_gss_indicate_mechs(ctx, minor_status, mech_set)
     void	*ctx;
     OM_uint32 *minor_status;
     gss_OID_set *mech_set;
{
   *minor_status = 0;

   /* Solaris Kerberos:  note that we use gss_copy_oid_set() here
    * instead of g_copy_OID_set().  Ours is defined in oid_ops.c
    */
   if (gss_copy_oid_set(minor_status, gss_mech_set_krb5_v1v2, 
	mech_set) == GSS_S_FAILURE) {
         *mech_set     = GSS_C_NO_OID_SET;
         return(GSS_S_FAILURE);
   }

   return(GSS_S_COMPLETE);
}

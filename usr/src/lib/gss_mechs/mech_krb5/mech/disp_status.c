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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gssapiP_krb5.h"
#include "gss_libinit.h"
#include "com_err.h"

/* XXXX internationalization!! */

/**/

OM_uint32
krb5_gss_display_status(minor_status, status_value, status_type,
			mech_type, message_context, status_string)
     OM_uint32 *minor_status;
     OM_uint32 status_value;
     int status_type;
     gss_OID mech_type;
     OM_uint32 *message_context;
     gss_buffer_t status_string;
{
   status_string->length = 0;
   status_string->value = NULL;

   if ((mech_type != GSS_C_NULL_OID) &&
       !g_OID_equal(gss_mech_krb5, mech_type) &&
       !g_OID_equal(gss_mech_krb5_old, mech_type)) {
       *minor_status = 0;
       return(GSS_S_BAD_MECH);
    }

   if (status_type == GSS_C_GSS_CODE) {
      return(g_display_major_status(minor_status, status_value,
				    message_context, status_string));
   } else if (status_type == GSS_C_MECH_CODE) {
      (void) gssint_initialize_library();

      if (*message_context) {
	 *minor_status = (OM_uint32) G_BAD_MSG_CTX;
	 return(GSS_S_FAILURE);
      }

      return(g_display_com_err_status(minor_status, status_value,
				      status_string));
   } else {
      *minor_status = 0;
      return(GSS_S_BAD_STATUS);
   }
}

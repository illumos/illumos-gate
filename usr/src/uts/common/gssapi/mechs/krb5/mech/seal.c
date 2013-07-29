/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

#include "gssapiP_krb5.h"

/*
 * $Id: seal.c 16171 2004-03-15 17:45:01Z raeburn $
 */

/*ARGSUSED*/
OM_uint32
krb5_gss_seal(minor_status, context_handle, conf_req_flag,
	      qop_req, input_message_buffer, conf_state,
	      output_message_buffer
#ifdef	 _KERNEL
	    , gssd_ctx_verifier
#endif
	    )
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     int conf_req_flag;
     int qop_req;
     gss_buffer_t input_message_buffer;
     int *conf_state;
     gss_buffer_t output_message_buffer;
#ifdef	 _KERNEL
     OM_uint32 gssd_ctx_verifier;
#endif
{
#ifdef	KRB5_NO_PRIVACY
 	/*
 	 * conf_req_flag must be zero;
 	 * encryption is disallowed
  	 * for global version
 	*/
     if (conf_req_flag)
       return (GSS_S_FAILURE);
#endif
 
   return(kg_seal(minor_status, context_handle, conf_req_flag,
		  qop_req, input_message_buffer, conf_state,
		  output_message_buffer, KG_TOK_SEAL_MSG));
}

/* V2 interface */
OM_uint32
krb5_gss_wrap(minor_status, context_handle, conf_req_flag,
	      qop_req, input_message_buffer, conf_state,
	      output_message_buffer)
    OM_uint32		*minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    gss_buffer_t	input_message_buffer;
    int			*conf_state;
    gss_buffer_t	output_message_buffer;
{
#ifdef	KRB5_NO_PRIVACY
     return (GSS_S_FAILURE);
#else
     return(kg_seal(minor_status, context_handle, conf_req_flag,
		   (int) qop_req, input_message_buffer, conf_state,
		   output_message_buffer, KG_TOK_WRAP_MSG));
#endif
}

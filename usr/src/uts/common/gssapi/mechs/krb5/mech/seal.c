/* EXPORT DELETE START */

/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
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
 * $Id: seal.c,v 1.11 1996/07/22 20:34:29 marc Exp $
 */
/*ARGSUSED*/
OM_uint32
krb5_gss_seal(ctx, minor_status, context_handle, conf_req_flag,
	      qop_req, input_message_buffer, conf_state,
	      output_message_buffer
#ifdef	 _KERNEL
		, gssd_ctx_verifier
#endif
)
     void	*ctx;
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
   krb5_context context;
   OM_uint32    status;

#ifdef	KRB5_NO_PRIVACY
	/* 
	 * conf_req_flag must be zero; 
	 * encryption is disallowed 
 	 * for global version
	*/
   if (conf_req_flag)	
   	return (GSS_S_FAILURE);
#endif

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
   if (GSS_ERROR(kg_get_context(minor_status, &context)))
      return(GSS_S_FAILURE);
#endif

   mutex_lock(&krb5_mutex);
   context = ctx;
   status = kg_seal(context, minor_status, context_handle, conf_req_flag,
		  qop_req, input_message_buffer, conf_state,
		  output_message_buffer, KG_TOK_SEAL_MSG);
   mutex_unlock(&krb5_mutex);
#ifdef	KRB5_NO_PRIVACY
	/*
	 * Can't be paranoid enough;
	 * if someone plugs in their version of kg_seal
	 * that does encryption we want to 
	 * disallow that too.
	*/
	if (conf_state && *conf_state) 
   		return (GSS_S_FAILURE);

#endif
   return(status);
}

/* V2 interface */
/*ARGSUSED*/
OM_uint32
krb5_gss_wrap(ctx, minor_status, context_handle, conf_req_flag,
	      qop_req, input_message_buffer, conf_state,
	      output_message_buffer)
    void		*ctx;
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
    krb5_context context;
    OM_uint32    status;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
    if (GSS_ERROR(kg_get_context(minor_status, &context)))
       return(GSS_S_FAILURE);
#endif

    mutex_lock(&krb5_mutex);
    context = ctx;
    status = kg_seal(context, minor_status, context_handle, conf_req_flag,
		   (int) qop_req, input_message_buffer, conf_state,
		   output_message_buffer, KG_TOK_WRAP_MSG);
    mutex_unlock(&krb5_mutex);
    return(status);
#endif
}
/* EXPORT DELETE END */

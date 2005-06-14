/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2000 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <gssapiP_krb5.h>
#include <k5-int.h>

/*
 * $Id: wrap_size_limit.c,v 1.7.6.2 2000/04/19 00:33:42 raeburn Exp $
 */

/* V2 interface */
 /*ARGSUSED*/
OM_uint32
krb5_gss_wrap_size_limit(ct, minor_status, context_handle, conf_req_flag,
			 qop_req, req_output_size, max_input_size)
    void		*ct;
    OM_uint32		*minor_status;
    gss_ctx_id_t	context_handle;
    int			conf_req_flag;
    gss_qop_t		qop_req;
    OM_uint32		req_output_size;
    OM_uint32		*max_input_size;
{
    krb5_context	context;
    krb5_gss_ctx_id_rec	*ctx;
    OM_uint32		conflen;
    OM_uint32		ohlen;
    OM_uint32		data_size;

   /* Solaris Kerberos:  for MT safety, we avoid the use of a default
    * context via kg_get_context() */
#if 0
    if (GSS_ERROR(kg_get_context(minor_status, &context)))
       return(GSS_S_FAILURE);
#endif

    KRB5_LOG0(KRB5_INFO, "krb5_gss_wrap_size_limit() start\n");

    /* check to make sure we aren't writing to a NULL pointer */
    if (!max_input_size)
	return(GSS_S_CALL_INACCESSIBLE_WRITE);

    mutex_lock(&krb5_mutex);
    context = ct;

    /* only default qop is allowed */
    if ((qop_req & GSS_KRB5_CONF_C_QOP_MASK) != GSS_C_QOP_DEFAULT) {
	*minor_status = (OM_uint32) G_UNKNOWN_QOP;
	mutex_unlock(&krb5_mutex); 
	return(GSS_S_BAD_QOP);
    }

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

    if (ctx->proto == 1) {
        /* No pseudo-ASN.1 wrapper overhead, so no sequence length and
           OID.  */
        OM_uint32 sz = req_output_size;
        if (conf_req_flag) {
	    size_t enclen;
	    if ( (*minor_status = krb5_c_encrypt_length(context,
				ctx->enc->enctype,
				sz, &enclen))) {
		mutex_unlock(&krb5_mutex);
		return (GSS_S_FAILURE);
	    }
	    /*
	     * The 16 byte token header is included 2 times,
	     * once at the beginning of the token and once
	     * encrypted with the plaintext data.
	     */
            while (sz > 0 && enclen + 32 > req_output_size) {
                sz--;
	        if ((*minor_status = krb5_c_encrypt_length(context,
			ctx->enc->enctype, sz, &enclen))) {
			mutex_unlock(&krb5_mutex);
			return (GSS_S_FAILURE);
		}
	    }
        } else {
            if (sz < 16 + ctx->cksum_size)
                sz = 0;
            else
                sz -= (16 + ctx->cksum_size);
        }

        *max_input_size = sz;
        *minor_status = 0;
	goto end;
    }

    data_size = req_output_size;

    /* The confounder is always used */
    conflen = kg_confounder_size(context, ctx->enc);
    data_size = (conflen + data_size + 8) & (~7);

    /*
     * If we are encrypting, check the size, it may be larger than
     * the input in some cases due to padding and byte-boundaries.
     */
    if (conf_req_flag) {
	    data_size = kg_encrypt_size(context, ctx->enc, data_size);
    }

    /*
     * Calculate the token size for a buffer that is 'req_output_size'
     * long.
     */
    ohlen = g_token_size(&(ctx->mech_used),
			(unsigned int)(data_size + ctx->cksum_size + 14)) -
	    req_output_size;

    KRB5_LOG1(KRB5_INFO, "ohlen = %u, req_output_size = %u.\n",
	ohlen, req_output_size);

    *max_input_size = (req_output_size > ohlen) ?
	    ((req_output_size - ohlen) & (~7)) : 0;

    *minor_status = 0;
end:
    mutex_unlock(&krb5_mutex);
    KRB5_LOG(KRB5_INFO, "krb5_gss_wrap_size_limit() end, "
	"max_input_size = %u.\n", *max_input_size);
    return(GSS_S_COMPLETE);
}

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
 * $Id: verify.c 16171 2004-03-15 17:45:01Z raeburn $
 */

/*ARGSUSED*/
OM_uint32
krb5_gss_verify(minor_status, context_handle,
		message_buffer, token_buffer,
		qop_state
#ifdef	 _KERNEL
		, gssd_ctx_verifier
#endif
		)
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t message_buffer;
     gss_buffer_t token_buffer;
     int *qop_state;
#ifdef	 _KERNEL
     OM_uint32 gssd_ctx_verifier;
#endif
{
     return(kg_unseal(minor_status, context_handle,
		      token_buffer, message_buffer,
		      NULL, qop_state, KG_TOK_SIGN_MSG));
}

/* V2 interface */
OM_uint32
krb5_gss_verify_mic(minor_status, context_handle,
		    message_buffer, token_buffer,
		    qop_state)
    OM_uint32		*minor_status;
    gss_ctx_id_t	context_handle;
    gss_buffer_t	message_buffer;
    gss_buffer_t	token_buffer;
    gss_qop_t		*qop_state;
{
    OM_uint32		rstat;
    int			qstate;

    rstat = kg_unseal(minor_status, context_handle,
		      token_buffer, message_buffer,
		      NULL, &qstate, KG_TOK_MIC_MSG);
    if (!rstat && qop_state)
	*qop_state = (gss_qop_t) qstate;
    return(rstat);
}

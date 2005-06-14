/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1996,1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  glue routine for gss_verify
 */

#include <mechglueP.h>

OM_uint32
gss_verify(minor_status,
		context_handle,
		message_buffer,
		token_buffer,
		qop_state)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
gss_buffer_t		message_buffer;
gss_buffer_t		token_buffer;
int *			qop_state;
{
	OM_uint32		status;
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;


	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor_status = 0;

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	if ((message_buffer == NULL) || GSS_EMPTY_BUFFER(token_buffer))
		return (GSS_S_CALL_INACCESSIBLE_READ);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t) context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);

	if (mech) {
		if (mech->gss_verify)
			status = mech->gss_verify(
						mech->context,
						minor_status,
						ctx->internal_ctx_id,
						message_buffer,
						token_buffer,
						qop_state);
		else
			status = GSS_S_UNAVAILABLE;

		return (status);
	}

    return (GSS_S_BAD_MECH);
}

OM_uint32
gss_verify_mic(minor_status,
		context_handle,
		message_buffer,
		token_buffer,
		qop_state)

OM_uint32 *		minor_status;
const gss_ctx_id_t	context_handle;
const gss_buffer_t	message_buffer;
const gss_buffer_t	token_buffer;
gss_qop_t *		qop_state;

{
	return (gss_verify(minor_status, (gss_ctx_id_t)context_handle,
			(gss_buffer_t)message_buffer,
			(gss_buffer_t)token_buffer, (int *) qop_state));
}

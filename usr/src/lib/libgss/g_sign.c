/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  glue routine gss_sign
 */

#include <mechglueP.h>

static OM_uint32
val_sign_args(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_buffer_t message_buffer,
	gss_buffer_t msg_token)
{

	/* Initialize outputs. */

	if (minor_status != NULL)
		*minor_status = 0;

	if (msg_token != GSS_C_NO_BUFFER) {
		msg_token->value = NULL;
		msg_token->length = 0;
	}

	/* Validate arguments. */

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	if (message_buffer == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (msg_token == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	return (GSS_S_COMPLETE);
}

OM_uint32
gss_sign(minor_status,
	context_handle,
	qop_req,
	message_buffer,
	msg_token)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
int			qop_req;
gss_buffer_t		message_buffer;
gss_buffer_t		msg_token;

{
	OM_uint32		status;
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;

	status = val_sign_args(minor_status, context_handle,
			message_buffer, msg_token);
	if (status != GSS_S_COMPLETE)
		return (status);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t) context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);

	if (mech) {
		if (mech->gss_sign)
			status = mech->gss_sign(
						mech->context,
						minor_status,
						ctx->internal_ctx_id,
						qop_req,
						message_buffer,
						msg_token);
		else
			status = GSS_S_UNAVAILABLE;

		return (status);
	}

	return (GSS_S_BAD_MECH);
}

OM_uint32
gss_get_mic(minor_status,
		context_handle,
		qop_req,
		message_buffer,
		msg_token)

OM_uint32 *		minor_status;
const gss_ctx_id_t	context_handle;
gss_qop_t		qop_req;
const gss_buffer_t	message_buffer;
gss_buffer_t		msg_token;

{
	return (gss_sign(minor_status, (gss_ctx_id_t)context_handle,
		(int) qop_req, (gss_buffer_t)message_buffer, msg_token));
}

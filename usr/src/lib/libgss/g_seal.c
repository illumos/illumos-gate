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
 *  glue routine for gss_seal
 */

#include <mechglueP.h>

static OM_uint32
val_seal_args(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_buffer_t input_message_buffer,
	gss_buffer_t output_message_buffer)
{

	/* Initialize outputs. */

	if (minor_status != NULL)
		*minor_status = 0;

	if (output_message_buffer != GSS_C_NO_BUFFER) {
		output_message_buffer->length = 0;
		output_message_buffer->value = NULL;
	}

	/* Validate arguments. */

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	if (input_message_buffer == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (output_message_buffer == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
gss_seal(minor_status,
		context_handle,
		conf_req_flag,
		qop_req,
		input_message_buffer,
		conf_state,
		output_message_buffer)

OM_uint32 *			minor_status;
gss_ctx_id_t			context_handle;
int				conf_req_flag;
int				qop_req;
gss_buffer_t			input_message_buffer;
int *				conf_state;
gss_buffer_t			output_message_buffer;
{
/* EXPORT DELETE START */

	OM_uint32		status;
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;

	status = val_seal_args(minor_status,
			context_handle,
			input_message_buffer,
			output_message_buffer);
	if (status != GSS_S_COMPLETE)
		return (status);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t) context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);

	if (mech) {
		if (mech->gss_seal)
			status = mech->gss_seal(
						mech->context,
						minor_status,
						ctx->internal_ctx_id,
						conf_req_flag,
						qop_req,
						input_message_buffer,
						conf_state,
						output_message_buffer);
		else
			status = GSS_S_UNAVAILABLE;

		return (status);
	}
/* EXPORT DELETE END */

	return (GSS_S_BAD_MECH);
}

OM_uint32
gss_wrap(minor_status,
		context_handle,
		conf_req_flag,
		qop_req,
		input_message_buffer,
		conf_state,
		output_message_buffer)

OM_uint32 *			minor_status;
const gss_ctx_id_t		context_handle;
int				conf_req_flag;
gss_qop_t			qop_req;
const gss_buffer_t		input_message_buffer;
int *				conf_state;
gss_buffer_t			output_message_buffer;

{
	return gss_seal(minor_status, (gss_ctx_id_t)context_handle,
			conf_req_flag, (int) qop_req,
			(gss_buffer_t)input_message_buffer, conf_state,
			output_message_buffer);
}

/*
 * New for V2
 */
OM_uint32
gss_wrap_size_limit(minor_status, context_handle, conf_req_flag,
				qop_req, req_output_size, max_input_size)
	OM_uint32		*minor_status;
	const gss_ctx_id_t	context_handle;
	int			conf_req_flag;
	gss_qop_t		qop_req;
	OM_uint32		req_output_size;
	OM_uint32		*max_input_size;
{
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor_status = 0;

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	if (max_input_size == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t) context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);

	if (!mech)
		return (GSS_S_BAD_MECH);

	if (!mech->gss_wrap_size_limit)
		return (GSS_S_UNAVAILABLE);

	return (mech->gss_wrap_size_limit(mech->context, minor_status,
				ctx->internal_ctx_id, conf_req_flag, qop_req,
				req_output_size, max_input_size));
}

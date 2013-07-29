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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *  glue routine gss_unseal
 */

#include <mechglueP.h>
#include "gssapiP_generic.h"

OM_uint32
gss_unseal(minor_status,
		context_handle,
		input_message_buffer,
		output_message_buffer,
		conf_state,
		qop_state)

OM_uint32 *		minor_status;
gss_ctx_id_t		context_handle;
gss_buffer_t		input_message_buffer;
gss_buffer_t		output_message_buffer;
int *			conf_state;
int *			qop_state;

{
	OM_uint32		status;
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;

	if (minor_status != NULL)
		*minor_status = 0;

	if (output_message_buffer != GSS_C_NO_BUFFER) {
		output_message_buffer->length = 0;
		output_message_buffer->value = NULL;
	}

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	if (input_message_buffer == GSS_C_NO_BUFFER ||
	    GSS_EMPTY_BUFFER(input_message_buffer))
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (output_message_buffer == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t) context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);

	if (mech) {
		if (mech->gss_unseal) {
			status = mech->gss_unseal(
						mech->context,
						minor_status,
						ctx->internal_ctx_id,
						input_message_buffer,
						output_message_buffer,
						conf_state,
						qop_state);
			if (status != GSS_S_COMPLETE)
				map_error(minor_status, mech);
		} else
			status = GSS_S_UNAVAILABLE;

		return (status);
	}

	return (GSS_S_BAD_MECH);
}

OM_uint32
gss_unwrap(minor_status,
		context_handle,
		input_message_buffer,
		output_message_buffer,
		conf_state,
		qop_state)

OM_uint32 *		minor_status;
const gss_ctx_id_t	context_handle;
const gss_buffer_t	input_message_buffer;
gss_buffer_t		output_message_buffer;
int *			conf_state;
gss_qop_t *		qop_state;

{
	return (gss_unseal(minor_status, (gss_ctx_id_t)context_handle,
			(gss_buffer_t)input_message_buffer,
			output_message_buffer, conf_state, (int *) qop_state));
}

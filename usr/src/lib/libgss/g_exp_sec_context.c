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
 *  glue routine for gss_export_sec_context
 */

#include <mechglueP.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

static OM_uint32 val_exp_sec_ctx_args(
	OM_uint32 *minor_status,
	gss_ctx_id_t *context_handle,
	gss_buffer_t interprocess_token)
{

	/* Initialize outputs. */

	if (minor_status != NULL)
		*minor_status = 0;

	if (interprocess_token != GSS_C_NO_BUFFER) {
		interprocess_token->length = 0;
		interprocess_token->value = NULL;
	}

	/* Validate arguments. */

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (context_handle == NULL || *context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	if (interprocess_token == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	return (GSS_S_COMPLETE);
}

OM_uint32
gss_export_sec_context(minor_status,
			context_handle,
			interprocess_token)

OM_uint32 *minor_status;
gss_ctx_id_t *context_handle;
gss_buffer_t interprocess_token;

{
	OM_uint32		status;
	OM_uint32 		length;
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;
	gss_buffer_desc		token;
	char			*buf;

	status = val_exp_sec_ctx_args(minor_status,
				context_handle, interprocess_token);
	if (status != GSS_S_COMPLETE)
		return (status);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t)*context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);
	if (!mech)
		return (GSS_S_BAD_MECH);
	if (!mech->gss_export_sec_context)
		return (GSS_S_UNAVAILABLE);

	status = mech->gss_export_sec_context(mech->context, minor_status,
					&ctx->internal_ctx_id, &token);
	if (status != GSS_S_COMPLETE)
		return (status);

	length = token.length + 4 + ctx->mech_type->length;
	interprocess_token->length = length;
	interprocess_token->value = malloc(length);
	if (interprocess_token->value == 0) {
		(void) gss_release_buffer(minor_status, &token);
		return (GSS_S_FAILURE);
	}
	buf = interprocess_token->value;
	length = ctx->mech_type->length;
	buf[3] = (unsigned char) (length & 0xFF);
	length >>= 8;
	buf[2] = (unsigned char) (length & 0xFF);
	length >>= 8;
	buf[1] = (unsigned char) (length & 0xFF);
	length >>= 8;
	buf[0] = (unsigned char) (length & 0xFF);
	(void) memcpy(buf+4, ctx->mech_type->elements,
			(size_t)ctx->mech_type->length);
	(void) memcpy(buf+4+ctx->mech_type->length, token.value, token.length);

	(void) gss_release_buffer(minor_status, &token);

	free(ctx->mech_type->elements);
	free(ctx->mech_type);
	free(ctx);
	*context_handle = 0;

	return (GSS_S_COMPLETE);
}

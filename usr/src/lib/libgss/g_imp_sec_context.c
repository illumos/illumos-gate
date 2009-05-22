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
 *  glue routine gss_export_sec_context
 */

#include <mechglueP.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static OM_uint32
val_imp_sec_ctx_args(
	OM_uint32 *minor_status,
	gss_buffer_t interprocess_token,
	gss_ctx_id_t *context_handle)
{

	/* Initialize outputs. */
	if (minor_status != NULL)
		*minor_status = 0;

	if (context_handle != NULL)
		*context_handle = GSS_C_NO_CONTEXT;

	/* Validate arguments. */

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (context_handle == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (interprocess_token == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_DEFECTIVE_TOKEN);

	if (GSS_EMPTY_BUFFER(interprocess_token))
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_DEFECTIVE_TOKEN);

	return (GSS_S_COMPLETE);
}

OM_uint32
gss_import_sec_context(minor_status,
			interprocess_token,
			context_handle)

OM_uint32 *		minor_status;
const gss_buffer_t	interprocess_token;
gss_ctx_id_t 		*context_handle;

{
	OM_uint32		length = 0;
	OM_uint32		status;
	char			*p;
	gss_union_ctx_id_t	ctx;
	gss_buffer_desc		token;
	gss_mechanism		mech;

	status = val_imp_sec_ctx_args(minor_status,
				interprocess_token, context_handle);
	if (status != GSS_S_COMPLETE)
		return (status);

	/* Initial value needed below. */
	status = GSS_S_FAILURE;

	ctx = (gss_union_ctx_id_t)malloc(sizeof (gss_union_ctx_id_desc));
	if (!ctx)
		return (GSS_S_FAILURE);

	ctx->mech_type = (gss_OID) malloc(sizeof (gss_OID_desc));
	if (!ctx->mech_type) {
		free(ctx);
		return (GSS_S_FAILURE);
	}

	if (interprocess_token->length >= sizeof (OM_uint32)) {
		p = interprocess_token->value;
		length = (OM_uint32)*p++;
		length = (OM_uint32)(length << 8) + *p++;
		length = (OM_uint32)(length << 8) + *p++;
		length = (OM_uint32)(length << 8) + *p++;
	}

	if (length == 0 ||
	    length > (interprocess_token->length - sizeof (OM_uint32))) {
		free(ctx);
		return (GSS_S_CALL_BAD_STRUCTURE | GSS_S_DEFECTIVE_TOKEN);
	}

	ctx->mech_type->length = length;
	ctx->mech_type->elements = malloc(length);
	if (!ctx->mech_type->elements) {
		goto error_out;
	}
	(void) memcpy(ctx->mech_type->elements, p, length);
	p += length;

	token.length = interprocess_token->length - sizeof (OM_uint32) - length;
	token.value = p;

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	mech = __gss_get_mechanism(ctx->mech_type);
	if (!mech) {
		status = GSS_S_BAD_MECH;
		goto error_out;
	}
	if (!mech->gss_import_sec_context) {
		status = GSS_S_UNAVAILABLE;
		goto error_out;
	}

	status = mech->gss_import_sec_context(mech->context, minor_status,
					&token, &ctx->internal_ctx_id);

	if (status == GSS_S_COMPLETE) {
		*context_handle = (gss_ctx_id_t)ctx;
		return (GSS_S_COMPLETE);
	}

error_out:
	if (ctx) {
		if (ctx->mech_type) {
			if (ctx->mech_type->elements)
				free(ctx->mech_type->elements);
			free(ctx->mech_type);
		}
		free(ctx);
	}
	return (status);
}

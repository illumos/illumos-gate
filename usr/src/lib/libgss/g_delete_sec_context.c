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
 *  glue routine for gss_delete_sec_context
 */

#include <mechglueP.h>
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

OM_uint32
gss_delete_sec_context(minor_status,
				context_handle,
				output_token)

OM_uint32 *			minor_status;
gss_ctx_id_t *			context_handle;
gss_buffer_t			output_token;

{
	OM_uint32		status;
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* if the context_handle is Null, return NO_CONTEXT error */
	if (context_handle == NULL || *context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t) *context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);

	if (mech) {

		if (mech->gss_delete_sec_context)
			status = mech->gss_delete_sec_context(mech->context,
							minor_status,
							&ctx->internal_ctx_id,
							output_token);
		else
			status = GSS_S_UNAVAILABLE;

		/* now free up the space for the union context structure */
		free(ctx->mech_type->elements);
		free(ctx->mech_type);
		free(*context_handle);
		*context_handle = NULL;

		return (status);
	}

	return (GSS_S_BAD_MECH);
}

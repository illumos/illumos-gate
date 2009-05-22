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
 *  glue routine for gss_inquire_context
 */

#include <mechglueP.h>
#include <stdlib.h>

static OM_uint32
val_inq_ctx_args(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_name_t *src_name,
	gss_name_t *targ_name,
	gss_OID *mech_type)
{

	/* Initialize outputs. */

	if (minor_status != NULL)
		*minor_status = 0;

	if (src_name != NULL)
		*src_name = GSS_C_NO_NAME;

	if (targ_name != NULL)
		*targ_name = GSS_C_NO_NAME;

	if (mech_type != NULL)
		*mech_type = GSS_C_NO_OID;

	/* Validate arguments. */

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);

	return (GSS_S_COMPLETE);
}

/* Last argument new for V2 */
OM_uint32
gss_inquire_context(
		minor_status,
		context_handle,
		src_name,
		targ_name,
		lifetime_rec,
		mech_type,
		ctx_flags,
		locally_initiated,
		open)

OM_uint32 *minor_status;
const gss_ctx_id_t context_handle;
gss_name_t *src_name;
gss_name_t *targ_name;
OM_uint32 *lifetime_rec;
gss_OID *mech_type;
OM_uint32 *ctx_flags;
int *locally_initiated;
int *open;

{
	gss_union_ctx_id_t	ctx;
	gss_mechanism		mech;
	OM_uint32		status, temp_minor;
	gss_name_t localTargName = NULL, localSourceName = NULL;

	status = val_inq_ctx_args(minor_status,
				context_handle,
				src_name,
				targ_name,
				mech_type);
	if (status != GSS_S_COMPLETE)
		return (status);

	/*
	 * select the approprate underlying mechanism routine and
	 * call it.
	 */

	ctx = (gss_union_ctx_id_t)context_handle;
	mech = __gss_get_mechanism(ctx->mech_type);

	if (!mech || !mech->gss_inquire_context || !mech->gss_display_name ||
		!mech->gss_release_name) {
		return (GSS_S_UNAVAILABLE);
	}

	status = mech->gss_inquire_context(
				mech->context,
				minor_status,
				ctx->internal_ctx_id,
				(src_name ? &localSourceName : NULL),
				(targ_name ? &localTargName : NULL),
				lifetime_rec,
				NULL,
				ctx_flags,
				locally_initiated,
				open);

	if (status != GSS_S_COMPLETE) {
		return (status);
	}

	/* need to convert names */
	if (src_name) {
		status = __gss_convert_name_to_union_name(minor_status, mech,
						localSourceName, src_name);
		if (status != GSS_S_COMPLETE) {
			if (localTargName)
				mech->gss_release_name(mech->context,
						&temp_minor, &localTargName);
			return (status);
		}
	}

	if (targ_name) {
		status = __gss_convert_name_to_union_name(minor_status, mech,
						localTargName, targ_name);

		if (status != GSS_S_COMPLETE) {
			if (src_name)
				(void) gss_release_name(&temp_minor, src_name);

			return (status);
		}
	}

	/* spec says mech type must point to static storage */
	if (mech_type)
		*mech_type = &mech->mech_type;
	return (GSS_S_COMPLETE);
}

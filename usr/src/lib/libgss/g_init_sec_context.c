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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  glue routine for gss_init_sec_context
 */
#include <mechglueP.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

OM_uint32
gss_init_sec_context(minor_status,
			claimant_cred_handle,
			context_handle,
			target_name,
			req_mech_type,
			req_flags,
			time_req,
			input_chan_bindings,
			input_token,
			actual_mech_type,
			output_token,
			ret_flags,
			time_rec)

OM_uint32 *			minor_status;
const gss_cred_id_t		claimant_cred_handle;
gss_ctx_id_t 			*context_handle;
const gss_name_t		target_name;
const gss_OID			req_mech_type;
OM_uint32			req_flags;
OM_uint32			time_req;
const gss_channel_bindings_t	input_chan_bindings;
const gss_buffer_t		input_token;
gss_OID *			actual_mech_type;
gss_buffer_t			output_token;
OM_uint32 *			ret_flags;
OM_uint32 *			time_rec;

{
	OM_uint32		status, temp_minor_status;
	gss_union_name_t	union_name;
	gss_union_cred_t	union_cred;
	gss_name_t		internal_name;
	gss_union_ctx_id_t	union_ctx_id;
	gss_OID			mech_type = GSS_C_NULL_OID;
	gss_mechanism		mech;
	gss_cred_id_t		input_cred_handle;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor_status = 0;

	/* clear output values */
	if (actual_mech_type)
		*actual_mech_type = NULL;

	if (context_handle == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE | GSS_S_NO_CONTEXT);

	if (target_name == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME);

	if (output_token == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	output_token->value = NULL;
	output_token->length = 0;


	if (req_mech_type)
		mech_type = (gss_OID)req_mech_type;

	union_name = (gss_union_name_t)target_name;

	/*
	 * obtain the gss mechanism information for the requested
	 * mechanism.  If mech_type is NULL, set it to the resultant
	 * mechanism
	 */
	mech = __gss_get_mechanism(mech_type);
	if (mech == NULL)
		return (GSS_S_BAD_MECH);

	if (mech->gss_init_sec_context == NULL)
		return (GSS_S_UNAVAILABLE);

	if (mech_type == GSS_C_NULL_OID)
		mech_type = &mech->mech_type;

	/*
	 * If target_name is mechanism_specific, then it must match the
	 * mech_type that we're about to use.  Otherwise, do an import on
	 * the external_name form of the target name.
	 */
	if (union_name->mech_type &&
			g_OID_equal(union_name->mech_type, mech_type)) {
		internal_name = union_name->mech_name;
	} else {
		if ((status = __gss_import_internal_name(minor_status,
					mech_type, union_name,
					&internal_name)) != GSS_S_COMPLETE)
			return (status);
	}

	/*
	 * if context_handle is GSS_C_NO_CONTEXT, allocate a union context
	 * descriptor to hold the mech type information as well as the
	 * underlying mechanism context handle. Otherwise, cast the
	 * value of *context_handle to the union context variable.
	 */
	if (*context_handle == GSS_C_NO_CONTEXT) {
		status = GSS_S_FAILURE;
		union_ctx_id = (gss_union_ctx_id_t)
			malloc(sizeof (gss_union_ctx_id_desc));
		if (union_ctx_id == NULL)
			goto end;

		if (generic_gss_copy_oid(&temp_minor_status, mech_type,
				&union_ctx_id->mech_type) != GSS_S_COMPLETE) {
			free(union_ctx_id);
			goto end;
		}

		/* copy the supplied context handle */
		union_ctx_id->internal_ctx_id = *context_handle;
	} else
		union_ctx_id = (gss_union_ctx_id_t)*context_handle;

	/*
	 * get the appropriate cred handle from the union cred struct.
	 * defaults to GSS_C_NO_CREDENTIAL if there is no cred, which will
	 * use the default credential.
	 */
	union_cred = (gss_union_cred_t)claimant_cred_handle;
	input_cred_handle = __gss_get_mechanism_cred(union_cred, mech_type);

	/*
	 * now call the approprate underlying mechanism routine
	 */

	status = mech->gss_init_sec_context(
				mech->context,
				minor_status,
				input_cred_handle,
				&union_ctx_id->internal_ctx_id,
				internal_name,
				mech_type,
				req_flags,
				time_req,
				input_chan_bindings,
				input_token,
				actual_mech_type,
				output_token,
				ret_flags,
				time_rec);

	if (status != GSS_S_COMPLETE && status != GSS_S_CONTINUE_NEEDED) {
		/*
		 * the spec says (the preferred) method is to delete all
		 * context info on the first call to init, and on all
		 * subsequent calls make the caller responsible for
		 * calling gss_delete_sec_context
		 */
		if (*context_handle == GSS_C_NO_CONTEXT) {
			free(union_ctx_id->mech_type->elements);
			free(union_ctx_id->mech_type);
			free(union_ctx_id);
		}
	} else if (*context_handle == GSS_C_NO_CONTEXT)
		*context_handle = (gss_ctx_id_t)union_ctx_id;

end:
	if (union_name->mech_name == NULL ||
		union_name->mech_name != internal_name) {
		(void) __gss_release_internal_name(&temp_minor_status,
					mech_type, &internal_name);
	}

	return (status);
}

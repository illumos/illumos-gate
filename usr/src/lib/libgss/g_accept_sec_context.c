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
 *  glue routine for gss_accept_sec_context
 */

#include <mechglueP.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

static OM_uint32
val_acc_sec_ctx_args(
	OM_uint32 *minor_status,
	gss_ctx_id_t *context_handle,
	gss_buffer_t input_token_buffer,
	gss_name_t *src_name,
	gss_OID *mech_type,
	gss_buffer_t output_token,
	gss_cred_id_t *d_cred)
{

	/* Initialize outputs. */

	if (minor_status != NULL)
		*minor_status = 0;

	if (src_name != NULL)
		*src_name = GSS_C_NO_NAME;

	if (mech_type != NULL)
		*mech_type = GSS_C_NO_OID;

	if (output_token != GSS_C_NO_BUFFER) {
		output_token->length = 0;
		output_token->value = NULL;
	}

	if (d_cred != NULL)
		*d_cred = GSS_C_NO_CREDENTIAL;

	/* Validate arguments. */

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (context_handle == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (input_token_buffer == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (output_token == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	return (GSS_S_COMPLETE);
}

OM_uint32
gss_accept_sec_context(minor_status,
			context_handle,
			verifier_cred_handle,
			input_token_buffer,
			input_chan_bindings,
			src_name,
			mech_type,
			output_token,
			ret_flags,
			time_rec,
			d_cred)

OM_uint32 			*minor_status;
gss_ctx_id_t			*context_handle;
const gss_cred_id_t		verifier_cred_handle;
const gss_buffer_t		input_token_buffer;
const gss_channel_bindings_t	input_chan_bindings;
gss_name_t			*src_name;
gss_OID				*mech_type;
gss_buffer_t			output_token;
OM_uint32			*ret_flags;
OM_uint32			*time_rec;
gss_cred_id_t			*d_cred; /* delegated cred handle */

{
	OM_uint32		status, temp_status, t_minstat;
	gss_union_ctx_id_t	union_ctx_id;
	gss_union_cred_t	union_cred;
	gss_cred_id_t	input_cred_handle = GSS_C_NO_CREDENTIAL;
	gss_cred_id_t	tmp_d_cred = GSS_C_NO_CREDENTIAL;
	gss_name_t		internal_name = GSS_C_NO_NAME;
	gss_name_t		tmp_src_name = GSS_C_NO_NAME;
	gss_OID_desc	token_mech_type_desc;
	gss_OID		token_mech_type = &token_mech_type_desc;
	gss_OID		actual_mech = GSS_C_NO_OID;
	OM_uint32	flags;
	gss_mechanism	mech;

	status = val_acc_sec_ctx_args(minor_status,
				context_handle,
				input_token_buffer,
				src_name,
				mech_type,
				output_token,
				d_cred);
	if (status != GSS_S_COMPLETE)
		return (status);

	/*
	 * if context_handle is GSS_C_NO_CONTEXT, allocate a union context
	 * descriptor to hold the mech type information as well as the
	 * underlying mechanism context handle. Otherwise, cast the
	 * value of *context_handle to the union context variable.
	 */

	if (*context_handle == GSS_C_NO_CONTEXT) {

		if (input_token_buffer == GSS_C_NO_BUFFER)
			return (GSS_S_CALL_INACCESSIBLE_READ);

		/* Get the token mech type */
		status = __gss_get_mech_type(token_mech_type,
					input_token_buffer);

		if (status)
			return (status);

		status = GSS_S_FAILURE;
		union_ctx_id = (gss_union_ctx_id_t)
			malloc(sizeof (gss_union_ctx_id_desc));
		if (!union_ctx_id)
			return (GSS_S_FAILURE);

		union_ctx_id->internal_ctx_id = GSS_C_NO_CONTEXT;
		status = generic_gss_copy_oid(&t_minstat,
					token_mech_type,
					&union_ctx_id->mech_type);
		if (status != GSS_S_COMPLETE) {
			free(union_ctx_id);
			return (status);
		}

		/* set the new context handle to caller's data */
		*context_handle = (gss_ctx_id_t)union_ctx_id;
	} else {
		union_ctx_id = (gss_union_ctx_id_t)*context_handle;
		token_mech_type = union_ctx_id->mech_type;
	}

	/*
	 * get the appropriate cred handle from the union cred struct.
	 * defaults to GSS_C_NO_CREDENTIAL if there is no cred, which will
	 * use the default credential.
	 */
	union_cred = (gss_union_cred_t)verifier_cred_handle;
	input_cred_handle = __gss_get_mechanism_cred(union_cred,
						token_mech_type);

	/*
	 * now select the approprate underlying mechanism routine and
	 * call it.
	 */

	mech = __gss_get_mechanism(token_mech_type);
	if (mech && mech->gss_accept_sec_context) {
		status = mech->gss_accept_sec_context(
					mech->context,
					minor_status,
					&union_ctx_id->internal_ctx_id,
					input_cred_handle,
					input_token_buffer,
					input_chan_bindings,
					&internal_name,
					&actual_mech,
					output_token,
					&flags,
					time_rec,
					d_cred ? &tmp_d_cred : NULL);

		/* If there's more work to do, keep going... */
		if (status == GSS_S_CONTINUE_NEEDED)
			return (GSS_S_CONTINUE_NEEDED);

		/* if the call failed, return with failure */
		if (status != GSS_S_COMPLETE)
			goto error_out;

		if (mech_type != NULL)
			*mech_type = actual_mech;

		/*
		 * if src_name is non-NULL,
		 * convert internal_name into a union name equivalent
		 * First call the mechanism specific display_name()
		 * then call gss_import_name() to create
		 * the union name struct cast to src_name
		 */
		if (internal_name != NULL) {
			temp_status = __gss_convert_name_to_union_name(
				&t_minstat, mech,
				internal_name, &tmp_src_name);
			if (temp_status != GSS_S_COMPLETE) {
				*minor_status = t_minstat;
				if (output_token->length)
					(void) gss_release_buffer(
						&t_minstat,
						output_token);
				if (internal_name != GSS_C_NO_NAME)
					mech->gss_release_name(
						mech->context,
						&t_minstat,
						&internal_name);
				return (temp_status);
			}
			if (src_name != NULL) {
				*src_name = tmp_src_name;
			}
		} else if (src_name != NULL) {
			*src_name = GSS_C_NO_NAME;
		}

		/* Ensure we're returning correct creds format */
		if ((flags & GSS_C_DELEG_FLAG) &&
		    tmp_d_cred != GSS_C_NO_CREDENTIAL) {
			/*
			 * If we got back an OID different from the original
			 * token OID, assume the delegated_cred is already
			 * a proper union_cred and just return it.  Don't
			 * try to re-wrap it.  This is for SPNEGO or other
			 * pseudo-mechanisms.
			 */
			if (actual_mech != GSS_C_NO_OID &&
			    token_mech_type != GSS_C_NO_OID &&
			    !g_OID_equal(actual_mech, token_mech_type)) {
				*d_cred = tmp_d_cred;
			} else {
				gss_union_cred_t d_u_cred = NULL;

				d_u_cred = malloc(sizeof (gss_union_cred_desc));
				if (d_u_cred == NULL) {
					status = GSS_S_FAILURE;
					goto error_out;
				}
				(void) memset(d_u_cred, 0,
					    sizeof (gss_union_cred_desc));

				d_u_cred->count = 1;

				status = generic_gss_copy_oid(
					&t_minstat,
					actual_mech,
					&d_u_cred->mechs_array);

				if (status != GSS_S_COMPLETE) {
					free(d_u_cred);
					goto error_out;
				}

				d_u_cred->cred_array = malloc(
						sizeof (gss_cred_id_t));
				if (d_u_cred->cred_array != NULL) {
					d_u_cred->cred_array[0] = tmp_d_cred;
				} else {
					free(d_u_cred);
					status = GSS_S_FAILURE;
					goto error_out;
				}

				if (status != GSS_S_COMPLETE) {
					free(d_u_cred->cred_array);
					free(d_u_cred);
					goto error_out;
				}

				internal_name = GSS_C_NO_NAME;

				d_u_cred->auxinfo.creation_time = time(0);
				d_u_cred->auxinfo.time_rec = 0;

				if (mech->gss_inquire_cred) {
					status = mech->gss_inquire_cred(
						mech->context,
						minor_status,
						tmp_d_cred,
						&internal_name,
						&d_u_cred->auxinfo.time_rec,
						&d_u_cred->auxinfo.cred_usage,
						NULL);
				}

				if (internal_name != NULL) {
					temp_status =
					    __gss_convert_name_to_union_name(
						&t_minstat, mech,
						internal_name, &tmp_src_name);
					if (temp_status != GSS_S_COMPLETE) {
						*minor_status = t_minstat;
						if (output_token->length)
						    (void) gss_release_buffer(
								&t_minstat,
								output_token);
						free(d_u_cred->cred_array);
						free(d_u_cred);
						return (temp_status);
					}
				}

				if (tmp_src_name != NULL) {
					status = gss_display_name(
						&t_minstat,
						tmp_src_name,
						&d_u_cred->auxinfo.name,
						&d_u_cred->auxinfo.name_type);
				}

				*d_cred = (gss_cred_id_t)d_u_cred;
			}
		}
		if (ret_flags != NULL) {
			*ret_flags = flags;
		}

		if (src_name == NULL && tmp_src_name != NULL)
			(void) gss_release_name(&t_minstat,
					&tmp_src_name);
		return	(status);
	} else {

		status = GSS_S_BAD_MECH;
	}

error_out:
	if (union_ctx_id) {
		if (union_ctx_id->mech_type) {
			if (union_ctx_id->mech_type->elements)
				free(union_ctx_id->mech_type->elements);
			free(union_ctx_id->mech_type);
		}
		free(union_ctx_id);
		*context_handle = GSS_C_NO_CONTEXT;
	}

#if 0
	/*
	 * Solaris Kerberos
	 * Don't release, it causes a problem with error token.
	 */
	if (output_token->length)
		(void) gss_release_buffer(&t_minstat, output_token);
#endif

	if (src_name)
		*src_name = GSS_C_NO_NAME;

	if (tmp_src_name != GSS_C_NO_NAME)
		(void) gss_release_buffer(&t_minstat,
			(gss_buffer_t)tmp_src_name);

	return (status);
}

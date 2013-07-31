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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * A module that implements a dummy security mechanism.
 * It's mainly used to test GSS-API application. Multiple tokens
 * exchanged during security context establishment can be
 * specified through dummy_mech.conf located in /etc.
 *
 */
#ifndef	lint
#define	dummy_gss_accept_sec_context \
		dummy_867227349
#define	dummy_gss_acquire_cred \
		dummy_352458907
#define	dummy_gss_add_cred \
		dummy_911432290
#define	dummy_gss_compare_name \
		dummy_396663848
#define	dummy_gss_context_time \
		dummy_955669998
#define	dummy_gss_delete_sec_context \
		dummy_440868788
#define	dummy_gss_display_name \
		dummy_999874939
#define	dummy_gss_display_status \
		dummy_485073729
#define	dummy_gss_export_sec_context \
		dummy_1044079879
#define	dummy_gss_import_name \
		dummy_529311438
#define	dummy_gss_import_sec_context \
		dummy_14542996
#define	dummy_gss_indicate_mechs \
		dummy_573516378
#define	dummy_gss_init_sec_context \
		dummy_58780705
#define	dummy_gss_inquire_context \
		dummy_617721319
#define	dummy_gss_inquire_cred \
		dummy_102985645
#define	dummy_gss_inquire_cred_by_mech \
		dummy_661926260
#define	dummy_gss_inquire_names_for_mech \
		dummy_147190586
#define	dummy_gss_internal_release_oid \
		dummy_706163968
#define	dummy_gss_process_context_token \
		dummy_191395526
#define	dummy_gss_release_cred \
		dummy_750368909
#define	dummy_gss_release_name \
		dummy_235600467
#define	dummy_gss_seal \
		dummy_794573849
#define	dummy_gss_sign \
		dummy_279838176
#define	dummy_gss_unseal \
		dummy_838778790
#define	dummy_gss_verify \
		dummy_324010348
#define	dummy_gss_wrap_size_limit \
		dummy_882983731
#define	dummy_pname_to_uid \
		dummy_345475423
#endif

#include <stdio.h>
#include <stdlib.h>
#include <gssapiP_dummy.h>
#include <mechglueP.h>
#include <gssapi_err_generic.h>

#define	dummy_context_name_len	19
/* private routines for dummy_mechanism */
static dummy_token_t make_dummy_token(char *name);
static void free_dummy_token(dummy_token_t *token);
static gss_buffer_desc make_dummy_token_buffer(char *name);
static gss_buffer_desc make_dummy_token_msg(void *data, int datalen);
static int der_length_size(int length);
static void der_write_length(unsigned char ** buf, int length);
static int der_read_length(unsigned char **buf, int *bufsize);
static int g_token_size(gss_OID mech, unsigned int body_size);
static void g_make_token_header(gss_OID mech, int body_size,
				unsigned char **buf, int tok_type);
static int g_verify_token_header(gss_OID mech, int *body_size,
				unsigned char **buf_in, int tok_type,
				int toksize);


/* private global variables */
static char dummy_srcname[] = "dummy source";
static OM_uint32 dummy_flags;
static int token_nums;

/*
 * The Mech OID:
 * { iso(1) org(3) internet(6) dod(1) private(4) enterprises(1) sun(42)
 *  products(2) gssapi(26) mechtypes(1) dummy(2) }
 */
static struct gss_config dummy_mechanism =
	{{10, "\053\006\001\004\001\052\002\032\001\002"},
	NULL,
	dummy_gss_acquire_cred,
	dummy_gss_release_cred,
	dummy_gss_init_sec_context,
	dummy_gss_accept_sec_context,
	dummy_gss_unseal,
	dummy_gss_process_context_token,
	dummy_gss_delete_sec_context,
	dummy_gss_context_time,
	dummy_gss_display_status,
	dummy_gss_indicate_mechs,
	dummy_gss_compare_name,
	dummy_gss_display_name,
	dummy_gss_import_name,
	dummy_gss_release_name,
	dummy_gss_inquire_cred,
	dummy_gss_add_cred,
	dummy_gss_seal,
	dummy_gss_export_sec_context,
	dummy_gss_import_sec_context,
	dummy_gss_inquire_cred_by_mech,
	dummy_gss_inquire_names_for_mech,
	dummy_gss_inquire_context,
	dummy_gss_internal_release_oid,
	dummy_gss_wrap_size_limit,
	dummy_pname_to_uid,
	NULL,	/* __gss_userok */
	NULL,	/* _export name */
	dummy_gss_sign,
	dummy_gss_verify,
	NULL,	/* _store_cred */
};

gss_mechanism
gss_mech_initialize(oid)
const gss_OID oid;
{
	FILE *fp;

	dprintf("Entering gss_mech_initialize\n");

	if (oid == NULL ||
		!g_OID_equal(oid, &dummy_mechanism.mech_type)) {
		fprintf(stderr, "invalid dummy mechanism oid.\n");
		return (NULL);
	}

	fp = fopen("/etc/dummy_mech_token.conf", "rF");
	if (fp == NULL) {
		fprintf(stderr, "dummy_mech.conf is not found.\n");
		fprintf(stderr, "Setting number tokens exchanged to 1\n");
		token_nums = 1;
	} else {
		fscanf(fp, "%d", &token_nums);
		fclose(fp);
		dprintf("dummy_mech.conf is found.\n");
		dprintf1("Setting number tokens exchanged to %d\n", token_nums);
	}

	if (token_nums == 1)
		dummy_flags = GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;
	else
		dummy_flags = GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG
				| GSS_C_MUTUAL_FLAG;

	dprintf("Leaving gss_mech_initialize\n");
	return (&dummy_mechanism);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_acquire_cred(ctx, minor_status, desired_name, time_req, desired_mechs,
			cred_usage, output_cred_handle,
			actual_mechs, time_rec)
	void *ctx;
	OM_uint32 *minor_status;
	gss_name_t desired_name;
	OM_uint32 time_req;
	gss_OID_set desired_mechs;
	gss_cred_usage_t cred_usage;
	gss_cred_id_t *output_cred_handle;
	gss_OID_set *actual_mechs;
	OM_uint32 *time_rec;
{
	dprintf("Entering dummy_gss_acquire_cred\n");

	if (actual_mechs)
		*actual_mechs = NULL;
	if (time_rec)
		*time_rec = 0;

	*output_cred_handle = (gss_cred_id_t)
				make_dummy_token("dummy_gss_acquire_cred");
	if (time_rec)  /* user may pass a null pointer */
		*time_rec = GSS_C_INDEFINITE;
	if (actual_mechs) {
		if (gss_copy_oid_set(minor_status, gss_mech_set_dummy,
				actual_mechs) == GSS_S_FAILURE) {
			return (GSS_S_FAILURE);
		}
	}

	dprintf("Leaving dummy_gss_acquire_cred\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_release_cred(ctx, minor_status, cred_handle)
	void *ctx;
	OM_uint32 *minor_status;
	gss_cred_id_t *cred_handle;
{
	dprintf("Entering dummy_gss_release_cred\n");

	free_dummy_token((dummy_token_t *)(cred_handle));
	*cred_handle = NULL;

	dprintf("Leaving dummy_gss_release_cred\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_init_sec_context(ct, minor_status, claimant_cred_handle,
				context_handle, target_name, mech_type,
				req_flags, time_req, input_chan_bindings,
				input_token, actual_mech_type, output_token,
				ret_flags, time_rec)
	void *ct;
	OM_uint32 *minor_status;
	gss_cred_id_t claimant_cred_handle;
	gss_ctx_id_t *context_handle;
	gss_name_t target_name;
	gss_OID mech_type;
	OM_uint32 req_flags;
	OM_uint32 time_req;
	gss_channel_bindings_t input_chan_bindings;
	gss_buffer_t input_token;
	gss_OID *actual_mech_type;
	gss_buffer_t output_token;
	OM_uint32 *ret_flags;
	OM_uint32 *time_rec;
{
	dummy_gss_ctx_id_t ctx;
	char token_string[64];
	OM_uint32 ret;
	OM_uint32 aret;
	int send_token = 0;

	dprintf("Entering init_sec_context\n");

	output_token->length = 0;
	output_token->value = NULL;
	if (actual_mech_type)
		*actual_mech_type = NULL;

	if (*context_handle == GSS_C_NO_CONTEXT) {

		if (input_token != NULL && input_token->value != NULL)
			return (GSS_S_FAILURE);

		ctx = (dummy_gss_ctx_id_t)malloc(sizeof (dummy_gss_ctx_id_rec));
		ctx->established = 0;
		ctx->last_stat = 0xffffffff;
		*context_handle = (gss_ctx_id_t)ctx;
		/*
		 * Initiator interpretation of config file. If 2 or more
		 * the client returns CONTINUE_NNED on the first call.
		 */
		if (token_nums >= 2) {
			ret = GSS_S_CONTINUE_NEEDED;
		} else {
			ret = GSS_S_COMPLETE;
		}
		send_token = 1;
	} else {
		unsigned char *ptr;
		int bodysize;
		int err;

		if (input_token == NULL || input_token->value == NULL) {
			ctx->last_stat = GSS_S_FAILURE;
			return (GSS_S_FAILURE);
		}

		ctx = (dummy_gss_ctx_id_t)(*context_handle);


		ptr = (unsigned char *) input_token->value;
		if (err = g_verify_token_header((gss_OID)gss_mech_dummy,
		    &bodysize, &ptr, 0, input_token->length)) {

			*minor_status = err;
			ctx->last_stat = GSS_S_DEFECTIVE_TOKEN;
			return (GSS_S_DEFECTIVE_TOKEN);
		}

		if (sscanf((char *)ptr, "%d", &aret) < 1) {
			*minor_status = 1;
			ctx->last_stat = GSS_S_DEFECTIVE_TOKEN;
			return (GSS_S_DEFECTIVE_TOKEN);
		}

		if (aret == GSS_S_CONTINUE_NEEDED) {
			if (ctx->last_stat == GSS_S_COMPLETE) {
				/*
				 * RFC 2078, page 36, under GSS_S_COMPLETE
				 * says that acceptor (target) has sufficient
				 * information to perform per-message
				 * processing. So if initiator previously
				 * returned GSS_S_COMPLETE, and acceptor
				 * says he needs more, then we have
				 * a problem.
				 */
				ctx->last_stat = GSS_S_FAILURE;
				return (GSS_S_FAILURE);
			}
			ret = GSS_S_CONTINUE_NEEDED;
			send_token = 1;
		} else {
			ret = GSS_S_COMPLETE;
			send_token = 0;
		}
	}
	if (ret_flags)  /* user may pass a null pointer */
		*ret_flags = dummy_flags;
	if (time_rec)  /* user may pass a null pointer */
		*time_rec = GSS_C_INDEFINITE;
	if (actual_mech_type)
		*actual_mech_type = (gss_OID) gss_mech_dummy;

	if (send_token == 1) {
		sprintf(token_string, "%d", ret);

		*output_token = make_dummy_token_msg(
				token_string, strlen(token_string) + 1);
	} else {
		*output_token = make_dummy_token_msg(NULL, 0);
	}

	if (ret == GSS_S_COMPLETE)
		ctx->established = 1;

	ctx->last_stat = ret;
	return (ret);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_accept_sec_context(ct, minor_status, context_handle,
				verifier_cred_handle, input_token,
				input_chan_bindings, src_name, mech_type,
				output_token, ret_flags, time_rec,
				delegated_cred_handle)
	void *ct;
	OM_uint32 *minor_status;
	gss_ctx_id_t *context_handle;
	gss_cred_id_t verifier_cred_handle;
	gss_buffer_t input_token;
	gss_channel_bindings_t input_chan_bindings;
	gss_name_t *src_name;
	gss_OID *mech_type;
	gss_buffer_t output_token;
	OM_uint32 *ret_flags;
	OM_uint32 *time_rec;
	gss_cred_id_t *delegated_cred_handle;
{
	dummy_gss_ctx_id_t ctx;
	char token_string[64];
	gss_buffer_desc name;
	OM_uint32 status;
	gss_name_t temp;
	unsigned char *ptr;
	int bodysize;
	int err;
	OM_uint32 iret;
	int return_token = 0;

	dprintf("Entering accept_sec_context\n");

	if (src_name)
		*src_name = (gss_name_t)NULL;
	output_token->length = 0;
	output_token->value = NULL;
	if (mech_type)
		*mech_type = GSS_C_NULL_OID;
	/* return a bogus cred handle */
	if (delegated_cred_handle)
		*delegated_cred_handle = GSS_C_NO_CREDENTIAL;

	/* Check for defective input token. */
	ptr = (unsigned char *) input_token->value;
	if (err = g_verify_token_header((gss_OID)gss_mech_dummy, &bodysize,
					&ptr, 0,
					input_token->length)) {
		*minor_status = err;
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	if (sscanf((char *)ptr, "%d", &iret) < 1) {
		*minor_status = 1;
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	if (*context_handle == GSS_C_NO_CONTEXT) {
		ctx = (dummy_gss_ctx_id_t)malloc(sizeof (dummy_gss_ctx_id_rec));
		ctx->token_number = token_nums;
		ctx->established = 0;
		*context_handle = (gss_ctx_id_t)ctx;
	} else {
		ctx = (dummy_gss_ctx_id_t)(*context_handle);
	}

	if (ret_flags)  /* user may pass a null pointer */
		*ret_flags = dummy_flags;
	if (time_rec)  /* user may pass a null pointer */
		*time_rec = GSS_C_INDEFINITE;
	if (mech_type)
		*mech_type = (gss_OID)gss_mech_dummy;

	/*
	 * RFC 2078, page 36, under GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED
	 * tells us whether to return a token or not.
	 */

	if (iret == GSS_S_CONTINUE_NEEDED)
		return_token = 1;
	else
		return_token = 0;


	if (ctx->token_number > 1) {
		/*
		 * RFC 2078, page 36, under GSS_S_COMPLETE, says that if
		 * initiator is done, the target (us) has what it needs, so
		 * it must return GSS_S_COMPLETE;
		 */
		if (iret == GSS_S_CONTINUE_NEEDED)
			status = GSS_S_CONTINUE_NEEDED;
		else
			status = GSS_S_COMPLETE;

	} else
		status = GSS_S_COMPLETE;

	/* source name is ready at GSS_S_COMPLELE */
	if ((status == GSS_S_COMPLETE) && src_name) {
		name.length = strlen(dummy_srcname);
		name.value = dummy_srcname;
		status = dummy_gss_import_name(ct, minor_status, &name,
				(gss_OID)GSS_C_NT_USER_NAME, &temp);
		if (status != GSS_S_COMPLETE) {
			free(*context_handle);
			*context_handle = GSS_C_NO_CONTEXT;
			return (status);
		}
		*src_name = temp;
	}

	if (status == GSS_S_COMPLETE) {
		ctx->established = 1;
	}

	if (return_token == 1) {
		sprintf(token_string, "%d", status);

		*output_token = make_dummy_token_msg(
				token_string, strlen(token_string) + 1);
	} else {
		*output_token = make_dummy_token_msg(NULL, 0);
	}

	if (ctx->token_number > 0)
		ctx->token_number--;

	return (status);
}


/*ARGSUSED*/
OM_uint32
dummy_gss_process_context_token(ct, minor_status, context_handle, token_buffer)
	void *ct;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t token_buffer;
{
	dprintf("In process_sec_context\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_delete_sec_context(ct, minor_status, context_handle, output_token)
	void *ct;
	OM_uint32 *minor_status;
	gss_ctx_id_t *context_handle;
	gss_buffer_t output_token;
{
	dummy_gss_ctx_id_t ctx;

	dprintf("Entering delete_sec_context\n");

	/* Make the length to 0, so the output token is not sent to peer */
	if (output_token) {
		output_token->length = 0;
		output_token->value = NULL;
	}

	if (*context_handle == GSS_C_NO_CONTEXT) {
		*minor_status = 0;
		return (GSS_S_COMPLETE);
	}

	ctx = (dummy_gss_ctx_id_t)*context_handle;
	free(ctx);
	*context_handle = GSS_C_NO_CONTEXT;

	dprintf("Leaving delete_sec_context\n");
	return (GSS_S_COMPLETE);
}


/*ARGSUSED*/
OM_uint32
dummy_gss_context_time(ct, minor_status, context_handle, time_rec)
	void *ct;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	OM_uint32 *time_rec;
{
	dprintf("In context_time\n");
	if (time_rec)  /* user may pass a null pointer */
		return (GSS_S_FAILURE);
	else
		*time_rec = GSS_C_INDEFINITE;
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_sign(ctx, minor_status, context_handle,
		qop_req, message_buffer, message_token)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	int qop_req;
	gss_buffer_t message_buffer;
	gss_buffer_t message_token;
{
	char token_string[] = "dummy_gss_sign";
	dummy_gss_ctx_id_t context;

	dprintf("Entering gss_sign\n");

	context = (dummy_gss_ctx_id_t)(context_handle);
	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);
	if (!context->established)
		return (GSS_S_NO_CONTEXT);

	*message_token = make_dummy_token_msg(
			token_string, strlen(token_string));

	dprintf("Leaving gss_sign\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_verify(ctx, minor_status, context_handle,
		message_buffer, token_buffer, qop_state)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t message_buffer;
	gss_buffer_t token_buffer;
	int *qop_state;
{
	unsigned char *ptr;
	int bodysize;
	int err;
	dummy_gss_ctx_id_t context;

	dprintf("Entering gss_verify\n");

	context = (dummy_gss_ctx_id_t)(context_handle);
	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);
	if (!context->established)
		return (GSS_S_NO_CONTEXT);

	/* Check for defective input token. */
	ptr = (unsigned char *) token_buffer->value;
	if (err = g_verify_token_header((gss_OID)gss_mech_dummy, &bodysize,
					&ptr, 0,
					token_buffer->length)) {
		*minor_status = err;
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	if (qop_state)
		*qop_state = GSS_C_QOP_DEFAULT;

	dprintf("Leaving gss_verify\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_seal(ctx, minor_status, context_handle, conf_req_flag,
		qop_req, input_message_buffer, conf_state,
		output_message_buffer)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	int conf_req_flag;
	int qop_req;
	gss_buffer_t input_message_buffer;
	int *conf_state;
	gss_buffer_t output_message_buffer;
{
	gss_buffer_desc output;
	dummy_gss_ctx_id_t context;

	dprintf("Entering gss_seal\n");

	context = (dummy_gss_ctx_id_t)(context_handle);
	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);
	if (!context->established)
		return (GSS_S_NO_CONTEXT);

	/* Copy the input message to output message */
	output = make_dummy_token_msg(
		input_message_buffer->value, input_message_buffer->length);

	if (conf_state)
		*conf_state = 1;

	*output_message_buffer = output;

	dprintf("Leaving gss_seal\n");
	return (GSS_S_COMPLETE);
}




/*ARGSUSED*/
OM_uint32
dummy_gss_unseal(ctx, minor_status, context_handle,
		input_message_buffer, output_message_buffer,
		conf_state, qop_state)
	void *ctx;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t input_message_buffer;
	gss_buffer_t output_message_buffer;
	int *conf_state;
	int *qop_state;
{
	gss_buffer_desc output;
	unsigned char *ptr;
	int bodysize;
	int err;
	dummy_gss_ctx_id_t context;

	dprintf("Entering gss_unseal\n");

	context = (dummy_gss_ctx_id_t)(context_handle);
	if (context_handle == GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);
	if (!context->established)
		return (GSS_S_NO_CONTEXT);

	ptr = (unsigned char *) input_message_buffer->value;
	if (err = g_verify_token_header((gss_OID)gss_mech_dummy, &bodysize,
					&ptr, 0,
					input_message_buffer->length)) {
		*minor_status = err;
		return (GSS_S_DEFECTIVE_TOKEN);
	}
	output.length = bodysize;
	output.value = (void *)malloc(output.length);
	memcpy(output.value, ptr, output.length);

	*output_message_buffer = output;
	if (qop_state)
		*qop_state = GSS_C_QOP_DEFAULT;
	if (conf_state)
		*conf_state = 1;

	dprintf("Leaving gss_unseal\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_display_status(ctx, minor_status, status_value, status_type,
			mech_type, message_context, status_string)
	void *ctx;
	OM_uint32 *minor_status;
	OM_uint32 status_value;
	int status_type;
	gss_OID mech_type;
	OM_uint32 *message_context;
	gss_buffer_t status_string;
{
	dprintf("Entering display_status\n");

	*message_context = 0;
	*status_string = make_dummy_token_buffer("dummy_gss_display_status");

	dprintf("Leaving display_status\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_indicate_mechs(ctx, minor_status, mech_set)
	void *ctx;
	OM_uint32 *minor_status;
	gss_OID_set *mech_set;
{
	dprintf("Entering indicate_mechs\n");

	*minor_status = 0;
	if (mech_set) {
		if (gss_copy_oid_set(minor_status, gss_mech_set_dummy,
				mech_set) == GSS_S_FAILURE) {
			return (GSS_S_FAILURE);
		}
	}

	dprintf("Leaving indicate_mechs\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_compare_name(ctx, minor_status, name1, name2, name_equal)
	void *ctx;
	OM_uint32 *minor_status;
	gss_name_t name1;
	gss_name_t name2;
	int *name_equal;
{
	dummy_name_t name_1 = (dummy_name_t)name1;
	dummy_name_t name_2 = (dummy_name_t)name2;

	dprintf("Entering compare_name\n");

	if (g_OID_equal(name_1->type, name_2->type) &&
	(name_1->buffer->length == name_2->buffer->length) &&
	!memcmp(name_1->buffer->value, name_2->buffer->value,
	name_1->buffer->length))
		*name_equal = 1;
	else
		*name_equal = 0;

	dprintf("Leaving compare_name\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_display_name(ctx, minor_status, input_name, output_name_buffer,
			output_name_type)
	void *ctx;
	OM_uint32 *minor_status;
	gss_name_t input_name;
	gss_buffer_t output_name_buffer;
	gss_OID *output_name_type;
{
	OM_uint32 status = GSS_S_COMPLETE;
	dummy_name_t name = (dummy_name_t)input_name;

	dprintf("Entering display_name\n");

	if (g_OID_equal(name->type, GSS_C_NT_USER_NAME) ||
	g_OID_equal(name->type, GSS_C_NT_MACHINE_UID_NAME) ||
	g_OID_equal(name->type, GSS_C_NT_STRING_UID_NAME) ||
	g_OID_equal(name->type, GSS_C_NT_HOSTBASED_SERVICE)) {
/*
 *		output_name_buffer = (gss_buffer_t)
 *					malloc(sizeof (gss_buffer_desc));
 */
		if (output_name_buffer == NULL)
			return (GSS_S_FAILURE);

		output_name_buffer->length = name->buffer->length;
		output_name_buffer->value = (void *)
						malloc(name->buffer->length);
		if (output_name_buffer->value == NULL)
			return (GSS_S_FAILURE);

		memcpy(output_name_buffer->value, name->buffer->value,
			name->buffer->length);
		if (output_name_type)
			*output_name_type = name->type;

		dprintf("Leaving display_name\n");
		return (status);
	}

	dprintf("Leaving display_name\n");
	return (GSS_S_BAD_NAMETYPE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_import_name(ctx, minor_status, input_name_buffer,
			input_name_type, output_name)
	void *ctx;
	OM_uint32 *minor_status;
	gss_buffer_t input_name_buffer;
	gss_OID input_name_type;
	gss_name_t *output_name;
{
	OM_uint32 status;

	dprintf("Entering import_name\n");

	*output_name = NULL;
	*minor_status = 0;

	if (input_name_type == GSS_C_NULL_OID)
		return (GSS_S_BAD_NAMETYPE);

	if (g_OID_equal(input_name_type, GSS_C_NT_USER_NAME) ||
	g_OID_equal(input_name_type, GSS_C_NT_MACHINE_UID_NAME) ||
	g_OID_equal(input_name_type, GSS_C_NT_STRING_UID_NAME) ||
	g_OID_equal(input_name_type, GSS_C_NT_HOSTBASED_SERVICE)) {
		dummy_name_t name = (dummy_name_t)
					malloc(sizeof (dummy_name_desc));
		name->buffer = (gss_buffer_t)malloc(sizeof (gss_buffer_desc));
		name->buffer->length = input_name_buffer->length;
		name->buffer->value = (void *)malloc(input_name_buffer->length);
		if (name->buffer->value == NULL)
			return (GSS_S_FAILURE);

		memcpy(name->buffer->value, input_name_buffer->value,
				input_name_buffer->length);

		status = generic_gss_copy_oid(minor_status,
		input_name_type, &(name->type));
		*output_name = (gss_name_t)name;
		dprintf("Leaving import_name\n");
		return (status);
	}
	dprintf("Leaving import_name\n");
	return (GSS_S_BAD_NAMETYPE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_release_name(ctx, minor_status, input_name)
	void *ctx;
	OM_uint32 *minor_status;
	gss_name_t *input_name;
{
	dummy_name_t name = (dummy_name_t)*input_name;

	dprintf("Entering release_name\n");
	free(name->buffer->value);
	generic_gss_release_oid(minor_status, &(name->type));
	free(name->buffer);
	free(name);
	dprintf("Leaving release_name\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_inquire_cred(ctx, minor_status, cred_handle, name, lifetime_ret,
			cred_usage, mechanisms)
	void *ctx;
	OM_uint32 *minor_status;
	gss_cred_id_t cred_handle;
	gss_name_t *name;
	OM_uint32 *lifetime_ret;
	gss_cred_usage_t *cred_usage;
	gss_OID_set *mechanisms;
{
	dprintf("Entering inquire_cred\n");
	if (name)
		*name = (gss_name_t)make_dummy_token
				("dummy gss credential");
	if (lifetime_ret)
		*lifetime_ret = GSS_C_INDEFINITE;
	if (cred_usage)
		*cred_usage = GSS_C_BOTH;
	if (mechanisms) {
		if (gss_copy_oid_set(minor_status, gss_mech_set_dummy,
				mechanisms) == GSS_S_FAILURE)
			return (GSS_S_FAILURE);
	}

	dprintf("Leaving inquire_cred\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_add_cred(ctx, minor_status, input_cred_handle,
			desired_name, desired_mech, cred_usage,
			initiator_time_req, acceptor_time_req,
			output_cred_handle, actual_mechs,
			initiator_time_rec, acceptor_time_rec)
	void *ctx;
	OM_uint32 *minor_status;
	gss_cred_id_t input_cred_handle;
	gss_name_t desired_name;
	gss_OID desired_mech;
	gss_cred_usage_t cred_usage;
	OM_uint32 initiator_time_req;
	OM_uint32 acceptor_time_req;
	gss_cred_id_t *output_cred_handle;
	gss_OID_set *actual_mechs;
	OM_uint32 *initiator_time_rec;
	OM_uint32 *acceptor_time_rec;
{
	dprintf("Entering add_cred\n");

	if ((desired_mech != GSS_C_NULL_OID) &&
	(g_OID_equal(desired_mech, gss_mech_dummy)))
		return (GSS_S_BAD_MECH);
	*minor_status = 0;

	dprintf("Leaving add_cred\n");

	/* This routine likes in kerberos V5 is never be used / called by */
	/* the GSS_API. It simply returns GSS_S_DUPLICATE_ELEMENT to indicate */
	/* this error */

	return (GSS_S_DUPLICATE_ELEMENT);
}

/* Should I add the token structure to deal with import/export */
/* of sec_context. For now, I just create dummy interprocess token, and when */
/* the peer accept it, it calls the import_sec_context.The import_sec_context */
/* creates new sec_context with status established. (rather than get it */
/* from interprocess token. it can be done because the sec context in dummy */
/* mechanism is very simple (contains only status if it's established). */
/*ARGSUSED*/
OM_uint32
dummy_gss_export_sec_context(ct, minor_status, context_handle,
				interprocess_token)
	void *ct;
	OM_uint32 *minor_status;
	gss_ctx_id_t *context_handle;
	gss_buffer_t interprocess_token;
{
	char str[] = "dummy_gss_export_sec_context";

	dprintf("Entering export_sec_context\n");

	*interprocess_token = make_dummy_token_msg(str, strlen(str));
	free(*context_handle);
	*context_handle = GSS_C_NO_CONTEXT;

	dprintf("Leaving export_sec_context\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_import_sec_context(ct, minor_status, interprocess_token,
				context_handle)
void *ct;
OM_uint32 *minor_status;
gss_buffer_t interprocess_token;
gss_ctx_id_t *context_handle;
{
	/* Assume that we got ctx from the interprocess token. */
	dummy_gss_ctx_id_t ctx;

	dprintf("Entering import_sec_context\n");

	ctx = (dummy_gss_ctx_id_t)malloc(sizeof (dummy_gss_ctx_id_rec));
	ctx->token_number = 0;
	ctx->established = 1;

	*context_handle = (gss_ctx_id_t)ctx;

	dprintf("Leaving import_sec_context\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_inquire_cred_by_mech(ctx, minor_status, cred_handle,
				mech_type, name, initiator_lifetime,
				acceptor_lifetime, cred_usage)
	void *ctx;
	OM_uint32 *minor_status;
	gss_cred_id_t cred_handle;
	gss_OID mech_type;
	gss_name_t *name;
	OM_uint32 *initiator_lifetime;
	OM_uint32 *acceptor_lifetime;
	gss_cred_usage_t *cred_usage;
{
	dprintf("Entering inquire_cred_by_mech\n");
	if (name)
		*name = (gss_name_t)make_dummy_token("dummy credential name");
	if (initiator_lifetime)
		*initiator_lifetime = GSS_C_INDEFINITE;
	if (acceptor_lifetime)
		*acceptor_lifetime = GSS_C_INDEFINITE;
	if (cred_usage)
		*cred_usage = GSS_C_BOTH;

	dprintf("Leaving inquire_cred_by_mech\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_inquire_names_for_mech(ctx, minor_status, mechanism, name_types)
	void		*ctx;
	OM_uint32	*minor_status;
	gss_OID		mechanism;
	gss_OID_set	*name_types;
{
	OM_uint32   major, minor;

	dprintf("Entering inquire_names_for_mech\n");
	/*
	 * We only know how to handle our own mechanism.
	 */
	if ((mechanism != GSS_C_NULL_OID) &&
	!g_OID_equal(gss_mech_dummy, mechanism)) {
		*minor_status = 0;
		return (GSS_S_FAILURE);
	}

	major = gss_create_empty_oid_set(minor_status, name_types);
	if (major == GSS_S_COMPLETE) {
		/* Now add our members. */
		if (((major = gss_add_oid_set_member(minor_status,
			(gss_OID) GSS_C_NT_USER_NAME, name_types))
		== GSS_S_COMPLETE) &&
		((major = gss_add_oid_set_member(minor_status,
			(gss_OID) GSS_C_NT_MACHINE_UID_NAME, name_types))
		== GSS_S_COMPLETE) &&
		((major = gss_add_oid_set_member(minor_status,
			(gss_OID) GSS_C_NT_STRING_UID_NAME, name_types))
		== GSS_S_COMPLETE)) {
			major = gss_add_oid_set_member(minor_status,
			(gss_OID) GSS_C_NT_HOSTBASED_SERVICE, name_types);
		}

		if (major != GSS_S_COMPLETE)
			(void) gss_release_oid_set(&minor, name_types);
	}

	dprintf("Leaving inquire_names_for_mech\n");
	return (major);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_inquire_context(ct, minor_status, context_handle, initiator_name,
			acceptor_name, lifetime_rec, mech_type, ret_flags,
			locally_initiated, open)
	void *ct;
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_name_t *initiator_name;
	gss_name_t *acceptor_name;
	OM_uint32 *lifetime_rec;
	gss_OID *mech_type;
	OM_uint32 *ret_flags;
	int *locally_initiated;
	int *open;
{
	dummy_gss_ctx_id_t ctx;
	dummy_name_t name1, name2;
	OM_uint32 status;

	dprintf("Entering inquire_context\n");

	ctx = (dummy_gss_ctx_id_t)(context_handle);
	name1 = (dummy_name_t)
				malloc(sizeof (dummy_name_desc));
	name1->buffer = (gss_buffer_t)malloc(sizeof (gss_buffer_desc));
	name1->buffer->length = dummy_context_name_len;
	name1->buffer->value = make_dummy_token("dummy context name");
	status = generic_gss_copy_oid(minor_status,
		(gss_OID) GSS_C_NT_USER_NAME, &(name1->type));
	if (status != GSS_S_COMPLETE)
		return (status);
	if (initiator_name)
		*initiator_name = (gss_name_t)name1;

	name2 = (dummy_name_t)
				malloc(sizeof (dummy_name_desc));
	name2->buffer = (gss_buffer_t)malloc(sizeof (gss_buffer_desc));
	name2->buffer->length = dummy_context_name_len;
	name2->buffer->value = make_dummy_token("dummy context name");
	status = generic_gss_copy_oid(minor_status,
		(gss_OID) GSS_C_NT_USER_NAME, &(name2->type));
	if (status != GSS_S_COMPLETE)
		return (status);
	if (acceptor_name)
		*acceptor_name = (gss_name_t)name2;

	if (lifetime_rec)  /* user may pass a null pointer */
		*lifetime_rec = GSS_C_INDEFINITE;
	if (mech_type)
		*mech_type = (gss_OID)gss_mech_dummy;
	if (ret_flags)
		*ret_flags = dummy_flags;
	if (open)
	*open = ctx->established;

	dprintf("Leaving inquire_context\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_internal_release_oid(ct, minor_status, oid)
	void		*ct;
	OM_uint32	*minor_status;
	gss_OID		*oid;
{
	dprintf("Entering internal_release_oid\n");

	/* Similar to krb5_gss_internal_release_oid */

	if (*oid != gss_mech_dummy)
		return (GSS_S_CONTINUE_NEEDED); /* We don't know this oid */

	*minor_status = 0;
	*oid = GSS_C_NO_OID;

	dprintf("Leaving internal_release_oid\n");
	return (GSS_S_COMPLETE);
}

/*ARGSUSED*/
OM_uint32
dummy_gss_wrap_size_limit(ct, minor_status, context_handle, conf_req_flag,
				qop_req, req_output_size, max_input_size)
	void		*ct;
	OM_uint32	*minor_status;
	gss_ctx_id_t	context_handle;
	int		conf_req_flag;
	gss_qop_t	qop_req;
	OM_uint32	req_output_size;
	OM_uint32	*max_input_size;
{
	dprintf("Entering wrap_size_limit\n");
	*max_input_size = req_output_size;
	dprintf("Leaving wrap_size_limit\n");
	return (GSS_S_COMPLETE);
}

/* ARGSUSED */
OM_uint32
dummy_pname_to_uid(ct, minor_status, name, uidOut)
	void *ct;
	OM_uint32 *minor_status;
	const gss_name_t name;
	uid_t *uidOut;
{
	dprintf("Entering pname_to_uid\n");
	*minor_status = 0;
	*uidOut = 60001;
	dprintf("Leaving pname_to_uid\n");
	return (GSS_S_COMPLETE);
}

static dummy_token_t
make_dummy_token(char *name)
{
	dummy_token_t token;

	token = (dummy_token_t)malloc(strlen(name)+1);
	strcpy(token, name);
	return (token);
}

static void
free_dummy_token(dummy_token_t *token)
{
	free(*token);
	*token = NULL;
}

static gss_buffer_desc
make_dummy_token_buffer(char *name)
{
	gss_buffer_desc buffer;

	if (name == NULL) {
		buffer.length = 0;
		buffer.value = NULL;
	} else {
		buffer.length = strlen(name)+1;
		buffer.value = make_dummy_token(name);
	}
	return (buffer);
}

static gss_buffer_desc
make_dummy_token_msg(void *data, int dataLen)
{
	gss_buffer_desc buffer;
	int tlen;
	unsigned char *t;
	unsigned char *ptr;

	if (data == NULL) {
		buffer.length = 0;
		buffer.value = NULL;
		return (buffer);
	}

	tlen = g_token_size((gss_OID)gss_mech_dummy, dataLen);
	t = (unsigned char *) malloc(tlen);
	ptr = t;

	g_make_token_header((gss_OID)gss_mech_dummy, dataLen, &ptr, 0);
	memcpy(ptr, data, dataLen);

	buffer.length = tlen;
	buffer.value = (void *) t;
	return (buffer);
}

static int
der_length_size(length)
	int length;
{
	if (length < (1<<7))
		return (1);
	else if (length < (1<<8))
		return (2);
	else if (length < (1<<16))
		return (3);
	else if (length < (1<<24))
		return (4);
	else
		return (5);
}

static void
der_write_length(buf, length)
	unsigned char **buf;
	int length;
{
	if (length < (1<<7)) {
		*(*buf)++ = (unsigned char) length;
	} else {
		*(*buf)++ = (unsigned char) (der_length_size(length)+127);
		if (length >= (1<<24))
			*(*buf)++ = (unsigned char) (length>>24);
		if (length >= (1<<16))
			*(*buf)++ = (unsigned char) ((length>>16)&0xff);
		if (length >= (1<<8))
			*(*buf)++ = (unsigned char) ((length>>8)&0xff);
		*(*buf)++ = (unsigned char) (length&0xff);
	}
}

static int
der_read_length(buf, bufsize)
unsigned char **buf;
int *bufsize;
{
	unsigned char sf;
	int ret;

	if (*bufsize < 1)
		return (-1);

	sf = *(*buf)++;
	(*bufsize)--;
	if (sf & 0x80) {
		if ((sf &= 0x7f) > ((*bufsize)-1))
			return (-1);

		if (sf > DUMMY_SIZE_OF_INT)
			return (-1);
		ret = 0;
		for (; sf; sf--) {
		ret = (ret<<8) + (*(*buf)++);
		(*bufsize)--;
	}
	} else {
		ret = sf;
	}

	return (ret);
}

static int
g_token_size(mech, body_size)
	gss_OID mech;
	unsigned int body_size;
{
	/* set body_size to sequence contents size */
	body_size += 4 + (int)mech->length;	/* NEED overflow check */
	return (1 + der_length_size(body_size) + body_size);
}

static void
g_make_token_header(mech, body_size, buf, tok_type)
	gss_OID mech;
	int body_size;
	unsigned char **buf;
	int tok_type;
{
	*(*buf)++ = 0x60;
	der_write_length(buf, 4 + mech->length + body_size);
	*(*buf)++ = 0x06;
	*(*buf)++ = (unsigned char) mech->length;
	TWRITE_STR(*buf, mech->elements, ((int)mech->length));
	*(*buf)++ = (unsigned char) ((tok_type>>8)&0xff);
	*(*buf)++ = (unsigned char) (tok_type&0xff);
}

static int
g_verify_token_header(mech, body_size, buf_in, tok_type, toksize)
gss_OID mech;
int *body_size;
unsigned char **buf_in;
int tok_type;
int toksize;
{
	unsigned char *buf = *buf_in;
	int seqsize;
	gss_OID_desc toid;
	int ret = 0;

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);
	if (*buf++ != 0x60)
		return (G_BAD_TOK_HEADER);

	if ((seqsize = der_read_length(&buf, &toksize)) < 0)
		return (G_BAD_TOK_HEADER);

	if (seqsize != toksize)
		return (G_BAD_TOK_HEADER);

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);
	if (*buf++ != 0x06)
		return (G_BAD_TOK_HEADER);

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);
	toid.length = *buf++;

	if ((toksize -= toid.length) < 0)
		return (G_BAD_TOK_HEADER);
	toid.elements = buf;
	buf += toid.length;

	if (!g_OID_equal(&toid, mech))
		ret = G_WRONG_MECH;

	/*
	 * G_WRONG_MECH is not returned immediately because it's more important
	 * to return G_BAD_TOK_HEADER if the token header is in fact bad
	 */

	if ((toksize -= 2) < 0)
		return (G_BAD_TOK_HEADER);

	if ((*buf++ != ((tok_type>>8)&0xff)) ||
	    (*buf++ != (tok_type&0xff)))
		return (G_BAD_TOK_HEADER);

	if (!ret) {
		*buf_in = buf;
		*body_size = toksize;
	}

	return (ret);
}

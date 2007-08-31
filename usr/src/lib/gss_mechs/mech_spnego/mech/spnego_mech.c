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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * A module that implements the spnego security mechanism.
 * It is used to negotiate the security mechanism between
 * peers using the GSS-API.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<errno.h>
#include	"gssapiP_spnego.h"
#include	<mechglueP.h>
#include	<gssapi_err_generic.h>
#include	<rpc/types.h>
#include	<libintl.h>

/* der routines defined in libgss */
extern unsigned int der_length_size(OM_uint32);
extern int get_der_length(uchar_t **, OM_uint32, OM_uint32*);
extern int put_der_length(OM_uint32, uchar_t **, OM_uint32);


/* private routines for spnego_mechanism */
static spnego_token_t make_spnego_token(char *);
static gss_buffer_desc make_err_msg(char *);
static int g_token_size(gss_OID, OM_uint32);
static int g_make_token_header(gss_OID, int, uchar_t **, int);
static int g_verify_token_header(gss_OID, int *, uchar_t **, int, int);
static int g_verify_neg_token_init(uchar_t **, int);
static OM_uint32 get_negResult(unsigned char **, int);
static gss_OID get_mech_oid(OM_uint32 *, uchar_t **, size_t);
static gss_buffer_t get_input_token(unsigned char **, int);
static gss_OID_set get_mech_set(OM_uint32 *, unsigned char **, int);
static OM_uint32 get_req_flags(uchar_t **, int *, OM_uint32 *);
static OM_uint32 get_available_mechs(OM_uint32 *, gss_name_t,
	gss_cred_usage_t, gss_cred_id_t *, gss_OID_set *);
static void release_spnego_ctx(spnego_gss_ctx_id_t *);
static void check_spnego_options(spnego_gss_ctx_id_t);
static spnego_gss_ctx_id_t create_spnego_ctx(void);
static int put_mech_set(uchar_t **, gss_OID_set, int);
static int put_input_token(uchar_t **, gss_buffer_t, int);
static int put_mech_oid(uchar_t **, gss_OID_desc *, int);
static int put_negResult(uchar_t **, OM_uint32, int);

static gss_OID
negotiate_mech_type(OM_uint32 *, gss_OID_set, gss_OID_set,
		OM_uint32 *, bool_t *);
static int
g_get_tag_and_length(unsigned char **, uchar_t, int, int *);

static int
make_spnego_tokenInit_msg(spnego_gss_ctx_id_t, gss_OID_set,
			gss_buffer_t, send_token_flag,
			gss_buffer_t);
static int
make_spnego_tokenTarg_msg(OM_uint32, gss_OID, gss_buffer_t,
			gss_buffer_t, send_token_flag, int,
			gss_buffer_t);

/*
 * The Mech OID for SPNEGO:
 * { iso(1) org(3) dod(6) internet(1) security(5)
 *  mechanism(5) spnego(2) }
 */
static struct gss_config spnego_mechanism =
{{SPNEGO_OID_LENGTH, SPNEGO_OID},
	NULL,
	spnego_gss_acquire_cred,
	spnego_gss_release_cred,
	spnego_gss_init_sec_context,
	spnego_gss_accept_sec_context,
/* EXPORT DELETE START */ /* CRYPT DELETE START */
	spnego_gss_unseal,		/* gss_unseal */
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	NULL,				/* gss_process_context_token */
	spnego_gss_delete_sec_context,	/* gss_delete_sec_context */
	spnego_gss_context_time,	/* gss_context_time */
	spnego_gss_display_status,
	NULL,				/* gss_indicate_mechs */
	NULL,				/* gss_compare_name */
	spnego_gss_display_name,
	spnego_gss_import_name,
	spnego_gss_release_name,
	spnego_gss_inquire_cred,	/* gss_inquire_cred */
	NULL,				/* gss_add_cred */
/* EXPORT DELETE START */ /* CRYPT DELETE START */
	spnego_gss_seal,		/* gss_seal */
/* EXPORT DELETE END */ /* CRYPT DELETE END */
	spnego_gss_export_sec_context,	/* gss_export_sec_context */
	spnego_gss_import_sec_context,	/* gss_import_sec_context */
	NULL, 				/* gss_inquire_cred_by_mech */
	spnego_gss_inquire_names_for_mech,
	spnego_gss_inquire_context,	/* gss_inquire_context */
	NULL,				/* gss_internal_release_oid */
	spnego_gss_wrap_size_limit,	/* gss_wrap_size_limit */
	NULL,				/* gss_pname_to_uid */
	NULL,				/* __gss_userok */
	NULL,				/* gss_export_name */
/* EXPORT DELETE START */
/* CRYPT DELETE START */
#if 0
/* CRYPT DELETE END */
	spnego_gss_seal,
	spnego_gss_unseal,
/* CRYPT DELETE START */
#endif
/* CRYPT DELETE END */
/* EXPORT DELETE END */
	spnego_gss_sign,		/* gss_sign */
	spnego_gss_verify,		/* gss_verify */
	NULL,				/* gss_store_cred */
};

gss_mechanism
gss_mech_initialize(const gss_OID oid)
{
	dsyslog("Entering gss_mech_initialize\n");

	if (oid == NULL ||
	    !g_OID_equal(oid, &spnego_mechanism.mech_type)) {
		dsyslog("invalid spnego mechanism oid.\n");
		return (NULL);
	}

	dsyslog("Leaving gss_mech_initialize\n");
	return (&spnego_mechanism);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_acquire_cred(void *ctx,
			OM_uint32 *minor_status,
			gss_name_t desired_name,
			OM_uint32 time_req,
			gss_OID_set desired_mechs,
			gss_cred_usage_t cred_usage,
			gss_cred_id_t *output_cred_handle,
			gss_OID_set *actual_mechs,
			OM_uint32 *time_rec)
{
	OM_uint32 status;
	gss_OID_set amechs;
	dsyslog("Entering spnego_gss_acquire_cred\n");

	if (actual_mechs)
		*actual_mechs = NULL;

	if (time_rec)
		*time_rec = 0;

	/*
	 * If the user did not specify a list of mechs,
	 * use get_available_mechs to collect a list of
	 * mechs for which creds are available.
	 */
	if (desired_mechs == GSS_C_NULL_OID_SET) {
		status = get_available_mechs(minor_status,
		    desired_name, cred_usage,
		    output_cred_handle, &amechs);
	} else {
		/*
		 * The caller gave a specific list of mechanisms,
		 * so just get whatever creds are available.
		 * gss_acquire_creds will return the subset of mechs for
		 * which the given 'output_cred_handle' is valid.
		 */
		status = gss_acquire_cred(minor_status,
		    desired_name, time_req, desired_mechs, cred_usage,
		    output_cred_handle, &amechs, time_rec);
	}

	if (actual_mechs && amechs != GSS_C_NULL_OID_SET) {
		(void) gss_copy_oid_set(minor_status, amechs, actual_mechs);
	}
	(void) gss_release_oid_set(minor_status, &amechs);

	dsyslog("Leaving spnego_gss_acquire_cred\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_release_cred(void *ctx,
			OM_uint32 *minor_status,
			gss_cred_id_t *cred_handle)
{
	OM_uint32 status;

	dsyslog("Entering spnego_gss_release_cred\n");

	if (minor_status == NULL || cred_handle == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = 0;

	if (*cred_handle == GSS_C_NO_CREDENTIAL)
		return (GSS_S_COMPLETE);

	status = gss_release_cred(minor_status, cred_handle);

	dsyslog("Leaving spnego_gss_release_cred\n");
	return (status);
}

static void
check_spnego_options(spnego_gss_ctx_id_t spnego_ctx)
{
	spnego_ctx->optionStr = __gss_get_modOptions(
	    (const gss_OID)&spnego_oids[0]);
	if (spnego_ctx->optionStr != NULL &&
	    strstr(spnego_ctx->optionStr, "msinterop")) {
		spnego_ctx->MS_Interop = 1;
	} else {
		spnego_ctx->MS_Interop = 0;
	}
}

static spnego_gss_ctx_id_t
create_spnego_ctx(void)
{
	spnego_gss_ctx_id_t spnego_ctx = NULL;
	spnego_ctx = (spnego_gss_ctx_id_t)
	    malloc(sizeof (spnego_gss_ctx_id_rec));

	if (spnego_ctx == NULL) {
		return (NULL);
	}

	spnego_ctx->ctx_handle = GSS_C_NO_CONTEXT;
	spnego_ctx->internal_mech = NULL;
	spnego_ctx->optionStr = NULL;
	spnego_ctx->optimistic = 0;
	spnego_ctx->MS_Interop = 0;
	spnego_ctx->DER_mechTypes.length = NULL;
	spnego_ctx->DER_mechTypes.value = GSS_C_NO_BUFFER;

	check_spnego_options(spnego_ctx);

	return (spnego_ctx);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_init_sec_context(void *ct,
			OM_uint32 *minor_status,
			gss_cred_id_t claimant_cred_handle,
			gss_ctx_id_t *context_handle,
			gss_name_t target_name,
			gss_OID mech_type,
			OM_uint32 req_flags,
			OM_uint32 time_req,
			gss_channel_bindings_t input_chan_bindings,
			gss_buffer_t input_token,
			gss_OID *actual_mech,
			gss_buffer_t output_token,
			OM_uint32 *ret_flags,
			OM_uint32 *time_rec)
{
	OM_uint32 ret = 0;
	OM_uint32 status = 0;
	OM_uint32 mstat;
	OM_uint32 local_ret_flags = 0;

	/*
	 * send_token is used to indicate in later steps
	 * what type of token, if any should be sent or processed.
	 * NO_TOKEN_SEND = no token should be sent
	 * INIT_TOKEN_SEND = initial token will be sent
	 * CONT_TOKEN_SEND = continuing tokens to be sent
	 * CHECK_MIC = no token to be sent, but have a MIC to check.
	 */
	send_token_flag send_token = NO_TOKEN_SEND;

	gss_OID_set mechSet;
	spnego_gss_ctx_id_t spnego_ctx = NULL;
	gss_buffer_t i_output_token = GSS_C_NO_BUFFER;
	gss_buffer_t i_input_token = GSS_C_NO_BUFFER;
	gss_buffer_t mechListMIC = NULL;
	gss_cred_id_t *credlistptr = NULL, credlist;
	gss_qop_t *qop_state = NULL;
	unsigned char *ptr;
	int len;

	dsyslog("Entering init_sec_context\n");

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	*minor_status = 0;
	output_token->length = 0;
	output_token->value = NULL;

	if (actual_mech)
		*actual_mech = NULL;

	if (*context_handle == GSS_C_NO_CONTEXT) {

		/* determine negotiation mech set */
		if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
			credlistptr = &credlist;

			mstat = get_available_mechs(minor_status,
			    GSS_C_NO_NAME, GSS_C_INITIATE,
			    credlistptr, &mechSet);
		} else {
			/*
			 * Use the list of mechs included in the
			 * cred that we were given.
			 */
			mstat = gss_inquire_cred(minor_status,
			    claimant_cred_handle, NULL, NULL,
			    NULL, &mechSet);
		}
		if (mstat != GSS_S_COMPLETE)
			return (mstat);

		if ((spnego_ctx = create_spnego_ctx()) == NULL) {
			ret = GSS_S_FAILURE;
			goto cleanup;
		}

		/*
		 * need to pull the first mech from mechSet to do first
		 * init ctx
		 */
		status = generic_gss_copy_oid(minor_status,
		    mechSet->elements, &spnego_ctx->internal_mech);

		if (status != GSS_S_COMPLETE) {
			ret = GSS_S_FAILURE;
			goto cleanup;
		}

		if (input_token != NULL && input_token->value != NULL) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto cleanup;
		}

		/*
		 * The actual context is not yet determined,
		 * set the output context_handle to refer to
		 * the spnego context itself.
		 */
		spnego_ctx->ctx_handle = GSS_C_NO_CONTEXT;
		*context_handle = (gss_ctx_id_t)spnego_ctx;
		send_token = INIT_TOKEN_SEND;
		ret = GSS_S_CONTINUE_NEEDED;
	} else {
		mechSet = NULL;
		spnego_ctx = (spnego_gss_ctx_id_t)(*context_handle);

		if (input_token == NULL || input_token->value == NULL) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto cleanup;
		}
		ptr = (unsigned char *) input_token->value;

		switch (get_negResult(&ptr, input_token->length)) {
		case ACCEPT_DEFECTIVE_TOKEN:
			*minor_status = 1;
			ret = GSS_S_DEFECTIVE_TOKEN;
			break;
		case ACCEPT_INCOMPLETE: {
			/* pull out mech from token */
			gss_OID internal_mech =
			    get_mech_oid(minor_status, &ptr,
			    input_token->length -
			    (ptr - (uchar_t *)input_token->value));

			/*
			 * check if first mech in neg set, if it isn't,
			 * release and copy chosen mech to context,
			 * delete internal context from prior mech
			 */
			if (internal_mech != NULL &&
			    ((internal_mech->length !=
			    spnego_ctx->internal_mech->length) ||
			    /* CSTYLED */
			    memcmp(spnego_ctx->internal_mech->elements,
			    internal_mech->elements,
			    spnego_ctx->internal_mech->length))) {

				(void) gss_delete_sec_context(&mstat,
				    &spnego_ctx->ctx_handle, NULL);

				spnego_ctx->ctx_handle = GSS_C_NO_CONTEXT;
				(void) generic_gss_release_oid(
				    &mstat, &spnego_ctx->internal_mech);

				status = generic_gss_copy_oid(
				    minor_status, internal_mech,
				    &spnego_ctx->internal_mech);

				if (status != GSS_S_COMPLETE)
					ret = GSS_S_DEFECTIVE_TOKEN;
				else
					ret = GSS_S_COMPLETE;

				(void) generic_gss_release_oid(&mstat,
				    &internal_mech);
			} else if (internal_mech == NULL) {
				ret = GSS_S_DEFECTIVE_TOKEN;
				send_token = NO_TOKEN_SEND;
			} else {
				ret = GSS_S_COMPLETE;
			}
			if (ret == GSS_S_COMPLETE) {
				/*
				 * Check for a token, it may contain
				 * an error message.
				 */
				if (*ptr ==  (CONTEXT | 0x02)) {
					if (g_get_tag_and_length(&ptr,
					    (CONTEXT | 0x02),
					    input_token->length - (ptr -
					    (uchar_t *)input_token->value),
					    &len) < 0) {
						ret = GSS_S_DEFECTIVE_TOKEN;
					} else {
						i_input_token = get_input_token(
						    &ptr, len);
						if (i_input_token  != NULL) {
							/*CSTYLED*/
							ret = GSS_S_CONTINUE_NEEDED;
							send_token =
							    CONT_TOKEN_SEND;
						} else {
							/*CSTYLED*/
							ret = GSS_S_DEFECTIVE_TOKEN;
							send_token =
							    NO_TOKEN_SEND;
						}
					}
				}
			}
			break;
		}
		case ACCEPT_COMPLETE:
			/* pull out mech from token */
			if (spnego_ctx->internal_mech != NULL)
				(void) generic_gss_release_oid(&mstat,
				    &spnego_ctx->internal_mech);

			spnego_ctx->internal_mech =
			    get_mech_oid(minor_status, &ptr,
			    input_token->length -
			    (ptr - (uchar_t *)input_token->value));

			if (spnego_ctx->internal_mech == NULL) {
				/* CSTYLED */
				*minor_status = ERR_SPNEGO_NO_MECH_FROM_ACCEPTOR;
				ret = GSS_S_FAILURE;
			}

			if (ret != GSS_S_FAILURE && *ptr == (CONTEXT | 0x02)) {
				if (g_get_tag_and_length(&ptr, (CONTEXT | 0x02),
				    input_token->length - (ptr -
				    (uchar_t *)input_token->value), &len) < 0) {
					ret = GSS_S_DEFECTIVE_TOKEN;
				} else {
					i_input_token = get_input_token(&ptr,
					    len);
					if (i_input_token  != NULL) {
						ret = GSS_S_COMPLETE;
						send_token = CHECK_MIC;
					} else {
						ret = GSS_S_DEFECTIVE_TOKEN;
						send_token = NO_TOKEN_SEND;
					}
				}
			} else if (ret == GSS_S_CONTINUE_NEEDED ||
			    ret == GSS_S_COMPLETE) {
				send_token = CHECK_MIC;
			}

			/*
			 * If we sent "optimistic" initial token,
			 * but the acceptor did not send a response token,
			 * this is an error.
			 */
			if (ret == GSS_S_COMPLETE &&
			    i_input_token == GSS_C_NO_BUFFER &&
			    spnego_ctx->last_status == GSS_S_CONTINUE_NEEDED &&
			    spnego_ctx->optimistic) {
				/* CSTYLED */
				*minor_status = ERR_SPNEGO_NO_TOKEN_FROM_ACCEPTOR;
				ret = GSS_S_DEFECTIVE_TOKEN;
				send_token = NO_TOKEN_SEND;
			}

			if (send_token != NO_TOKEN_SEND) {
				if (i_input_token == NULL)
					ret = GSS_S_COMPLETE;
				else
					ret = GSS_S_CONTINUE_NEEDED;
				send_token = CHECK_MIC;
			}
			break;

		case REJECT:
			ret = GSS_S_BAD_MECH;
			*minor_status = ERR_SPNEGO_NEGOTIATION_FAILED;
			send_token = NO_TOKEN_SEND;
			break;

		default:
			ret = GSS_S_FAILURE;
			send_token = NO_TOKEN_SEND;
			break;
		}
	}


	if (send_token == NO_TOKEN_SEND) {
		output_token->length = 0;
		output_token->value = NULL;
		goto cleanup;
	}

	i_output_token = (gss_buffer_t)malloc(sizeof (gss_buffer_desc));

	if (i_output_token == NULL) {
		ret = status = GSS_S_FAILURE;
		goto cleanup;
	}

	i_output_token->length = 0;
	i_output_token->value = NULL;

	if (ret == GSS_S_CONTINUE_NEEDED) {
		gss_OID inner_mech_type = GSS_C_NO_OID;

		status = gss_init_sec_context(minor_status,
		    claimant_cred_handle,
		    &spnego_ctx->ctx_handle,
		    target_name,
		    spnego_ctx->internal_mech,
		    req_flags,
		    time_req,
		    NULL,
		    i_input_token,
		    &inner_mech_type,
		    i_output_token,
		    &local_ret_flags,
		    time_rec);

		if (ret_flags)
			*ret_flags = local_ret_flags;

		spnego_ctx->last_status = status;

		if (i_input_token != GSS_C_NO_BUFFER) {
			(void) gss_release_buffer(&mstat, i_input_token);
			free(i_input_token);
		}

		if ((status != GSS_S_COMPLETE) &&
		    (status != GSS_S_CONTINUE_NEEDED)) {
			ret = status;
		}

		/* create mic/check mic */
		if ((i_output_token->length == 0) &&
		    (status == GSS_S_COMPLETE) &&
		    (local_ret_flags & GSS_C_INTEG_FLAG)) {
			if (*ptr == (CONTEXT | 0x03)) {
				if (g_get_tag_and_length(&ptr,
				    (CONTEXT | 0x03), input_token->length -
				    (ptr - (uchar_t *)input_token->value),
				    &len) < 0) {
					ret = GSS_S_DEFECTIVE_TOKEN;
				} else {
					ret = GSS_S_COMPLETE;
					mechListMIC = get_input_token(&ptr,
					    len);
					if (mechListMIC == NULL)
						ret = GSS_S_DEFECTIVE_TOKEN;
					else if (!spnego_ctx->MS_Interop &&
					    spnego_ctx->DER_mechTypes.length >
					    0) {
						status = gss_verify_mic(
						    minor_status,
						    spnego_ctx->ctx_handle,
						    &spnego_ctx->DER_mechTypes,
						    mechListMIC, qop_state);
					}
				}
			} else if (!spnego_ctx->MS_Interop) {
			/*
			 * If no MIC was sent and we are in
			 * "standard" mode (i.e. NOT MS_Interop),
			 * the MIC must be present.
			 */
				ret = GSS_S_DEFECTIVE_TOKEN;
			} else {
				/* In "MS_Interop" mode, MIC is ignored. */
				ret = GSS_S_COMPLETE;
			}
		}
	}

	if ((status == GSS_S_COMPLETE) &&
	    (ret == GSS_S_COMPLETE)) {
		if (actual_mech) {
			(void) generic_gss_release_oid(&mstat, actual_mech);
			ret = generic_gss_copy_oid(&mstat,
			    spnego_ctx->internal_mech, actual_mech);
			if (ret != GSS_S_COMPLETE)
				goto cleanup;
		}

	} else if (ret == GSS_S_CONTINUE_NEEDED) {
		if (make_spnego_tokenInit_msg(spnego_ctx,
		    mechSet, i_output_token, send_token,
		    output_token) < 0) {
			ret = GSS_S_DEFECTIVE_TOKEN;
		}
	}

cleanup:
	if (status != GSS_S_COMPLETE)
		ret = status;
	if (ret != GSS_S_COMPLETE &&
	    ret != GSS_S_CONTINUE_NEEDED) {
		if (spnego_ctx != NULL &&
		    spnego_ctx->ctx_handle != NULL)
			gss_delete_sec_context(&mstat, &spnego_ctx->ctx_handle,
			    GSS_C_NO_BUFFER);

		if (spnego_ctx != NULL)
			release_spnego_ctx(&spnego_ctx);

		*context_handle = GSS_C_NO_CONTEXT;

		if (output_token)
			(void) gss_release_buffer(&mstat, output_token);
	}

	if (i_output_token != GSS_C_NO_BUFFER) {
		(void) gss_release_buffer(&mstat, i_output_token);
		free(i_output_token);
	}

	if (mechListMIC != GSS_C_NO_BUFFER) {
		(void) gss_release_buffer(&mstat, mechListMIC);
		free(mechListMIC);
	}

	if (mechSet != NULL)
		(void) gss_release_oid_set(&mstat, &mechSet);

	if (credlistptr != NULL)
		(void) gss_release_cred(&mstat, credlistptr);

	return (ret);
} /* init_sec_context */

/*ARGSUSED*/
OM_uint32
spnego_gss_accept_sec_context(void *ct,
			    OM_uint32 *minor_status,
			    gss_ctx_id_t *context_handle,
			    gss_cred_id_t verifier_cred_handle,
			    gss_buffer_t input_token,
			    gss_channel_bindings_t input_chan_bindings,
			    gss_name_t *src_name,
			    gss_OID *mech_type,
			    gss_buffer_t output_token,
			    OM_uint32 *ret_flags,
			    OM_uint32 *time_rec,
			    gss_cred_id_t *delegated_cred_handle)
{
	spnego_gss_ctx_id_t spnego_ctx = NULL;
	gss_OID mech_wanted = NULL;
	gss_OID_set mechSet = GSS_C_NO_OID_SET;
	gss_OID_set supported_mechSet = GSS_C_NO_OID_SET;
	gss_buffer_t i_output_token = GSS_C_NO_BUFFER;
	gss_buffer_t i_input_token = GSS_C_NO_BUFFER;
	gss_buffer_t mechListMIC = GSS_C_NO_BUFFER;
	gss_cred_id_t acquired_cred = NULL;
	gss_name_t internal_name = GSS_C_NO_NAME;
	OM_uint32 status = GSS_S_COMPLETE;
	OM_uint32 ret = GSS_S_COMPLETE;
	unsigned char *ptr;
	unsigned char *bufstart;
	int bodysize;
	int err, len;
	OM_uint32 negResult;
	OM_uint32 minor_stat;
	OM_uint32 mstat;
	OM_uint32 req_flags;
	OM_uint32 mechsetlen;
	gss_qop_t qop_state;
	send_token_flag return_token =  NO_TOKEN_SEND;
	bool_t firstMech;
	bool_t Need_Cred = FALSE;
	OM_uint32 local_ret_flags = 0;
	uchar_t *buf, *tmp;

	dsyslog("Entering accept_sec_context\n");

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	if (src_name)
		*src_name = (gss_name_t)NULL;

	output_token->length = 0;
	output_token->value = NULL;
	*minor_status = 0;

	if (mech_type)
		*mech_type = GSS_C_NULL_OID;

	/* return a bogus cred handle */
	if (delegated_cred_handle)
		*delegated_cred_handle = GSS_C_NO_CREDENTIAL;

	if (verifier_cred_handle == GSS_C_NO_CREDENTIAL) {
		Need_Cred = TRUE;
	}

	/* Check for defective input token. */
	ptr = bufstart = (unsigned char *) input_token->value;
	if (err = g_verify_token_header((gss_OID)gss_mech_spnego, &bodysize,
	    &ptr, 0, input_token->length)) {
		*minor_status = err;
		ret = GSS_S_DEFECTIVE_TOKEN;
		negResult = REJECT;
		return_token = ERROR_TOKEN_SEND;
		goto senderror;
	}

	/*
	 * set up of context, determine mech to be used, save mechset
	 * for use later in integrety check.
	 */
	if (*context_handle == GSS_C_NO_CONTEXT) {
		if ((spnego_ctx = create_spnego_ctx()) == NULL)
			return (GSS_S_FAILURE);

		/*
		 * Until the accept operation is complete, the
		 * context_handle returned should refer to
		 * the spnego context.
		 */
		*context_handle = (gss_ctx_id_t)spnego_ctx;
		minor_stat = get_available_mechs(minor_status,
		    GSS_C_NO_NAME, GSS_C_ACCEPT,
		    NULL, &supported_mechSet);

		if (minor_stat != GSS_S_COMPLETE) {
			release_spnego_ctx(&spnego_ctx);
			*context_handle = GSS_C_NO_CONTEXT;
			return (minor_stat);
		}

		if (Need_Cred) {
			minor_stat = gss_acquire_cred(minor_status,
			    GSS_C_NO_NAME, NULL, supported_mechSet,
			    GSS_C_ACCEPT, &acquired_cred, NULL,
			    NULL);

			if (minor_stat != GSS_S_COMPLETE) {
				(void) gss_release_oid_set(minor_status,
				    &supported_mechSet);
				release_spnego_ctx(&spnego_ctx);
				*context_handle = GSS_C_NO_CONTEXT;
				return (minor_stat);
			} else {
				verifier_cred_handle = acquired_cred;
			}
		}

		if (err = g_verify_neg_token_init(&ptr, input_token->length)) {
			*minor_status = err;
			ret = GSS_S_DEFECTIVE_TOKEN;
			negResult = REJECT;
			return_token = ERROR_TOKEN_SEND;
			goto senderror;
		}

		/*
		 * Allocate space to hold the mechTypes
		 * because we need it later.
		 */
		mechsetlen = input_token->length - (ptr - bufstart);
		buf = (uchar_t *)malloc(mechsetlen);
		if (buf == NULL) {
			ret = GSS_S_FAILURE;
			goto cleanup;
		}
		(void) memcpy(buf, ptr, mechsetlen);
		ptr = bufstart = buf;

		/*
		 * Get pointers to the DER encoded MechSet so we
		 * can properly check and calculate a MIC later.
		 */
		spnego_ctx->DER_mechTypes.value = ptr;
		mechSet = get_mech_set(minor_status, &ptr, mechsetlen);
		if (mechSet == NULL) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			negResult = REJECT;
			return_token = ERROR_TOKEN_SEND;
			goto senderror;
		}
		spnego_ctx->DER_mechTypes.length = ptr - bufstart;
		mechsetlen -= (ptr - bufstart);

		/*
		 * Select the best match between the list of mechs
		 * that the initiator requested and the list that
		 * the acceptor will support.
		 */
		mech_wanted = negotiate_mech_type(minor_status,
		    supported_mechSet, mechSet, &negResult,
		    &firstMech);

		(void) gss_release_oid_set(&minor_stat, &supported_mechSet);
		(void) gss_release_oid_set(&minor_stat, &mechSet);
		supported_mechSet = NULL;
		mechSet = NULL;

		if (get_req_flags(&ptr, (int *)&mechsetlen, &req_flags) ==
		    ACCEPT_DEFECTIVE_TOKEN) {
			negResult = REJECT;
		}

		tmp = ptr;
		if (negResult == ACCEPT_COMPLETE) {
			if (g_get_tag_and_length(&ptr, (CONTEXT | 0x02),
			    mechsetlen, &len) < 0) {
				negResult = REJECT;
			} else {
				i_input_token = get_input_token(&ptr, len);
				if (i_input_token == NULL) {
					negResult = REJECT;
				}
			}
			return_token = INIT_TOKEN_SEND;
		}
		if (negResult == REJECT) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			return_token = ERROR_TOKEN_SEND;
		} else {
			ret = GSS_S_CONTINUE_NEEDED;
			return_token = INIT_TOKEN_SEND;
		}

		mechsetlen -= ptr - tmp;
		/*
		 * Check to see if there is a MechListMIC field
		 */
		if (negResult == ACCEPT_COMPLETE && mechsetlen > 0) {
			tmp = ptr;
			if (g_get_tag_and_length(&ptr, (CONTEXT | 0x03),
			    mechsetlen, &len) >= 0) {
				mechListMIC = get_input_token(&ptr, len);
				if (mechListMIC == GSS_C_NO_BUFFER) {
					negResult = REJECT;
					return_token = ERROR_TOKEN_SEND;
					ret = GSS_S_DEFECTIVE_TOKEN;
				}
				mechsetlen -= (ptr - tmp);
			}
		}
	} else {
		/*
		 * get internal input token and context for continued
		 * calls of spnego_gss_init_sec_context.
		 */
		i_input_token = get_input_token(&ptr,
		    input_token->length - (ptr -
		    (uchar_t *)input_token->value));
		if (i_input_token == NULL) {
			negResult = REJECT;
			return_token = ERROR_TOKEN_SEND;
			ret = GSS_S_DEFECTIVE_TOKEN;
		} else {
			spnego_ctx = (spnego_gss_ctx_id_t)(*context_handle);
			return_token = CONT_TOKEN_SEND;
		}
	}

	/*
	 * If we still don't have a cred, we have an error.
	 */
	if (verifier_cred_handle == GSS_C_NO_CREDENTIAL) {
		ret = GSS_S_FAILURE;
		goto cleanup;
	}

	/* If we have an error already, bail out */
	if (ret != GSS_S_COMPLETE && ret != GSS_S_CONTINUE_NEEDED)
		goto senderror;

	if (i_input_token != GSS_C_NO_BUFFER) {
		i_output_token = (gss_buffer_t)malloc(sizeof (gss_buffer_desc));

		if (i_output_token == NULL) {
			ret = GSS_S_FAILURE;
			goto cleanup;
		}

		i_output_token->length = 0;
		i_output_token->value = NULL;

		status = gss_accept_sec_context(&minor_stat,
		    &spnego_ctx->ctx_handle, verifier_cred_handle,
		    i_input_token, GSS_C_NO_CHANNEL_BINDINGS,
		    &internal_name, mech_type, i_output_token,
		    &local_ret_flags, time_rec, delegated_cred_handle);

		if ((status != GSS_S_COMPLETE) &&
		    (status != GSS_S_CONTINUE_NEEDED)) {
			*minor_status = minor_stat;
			(void) gss_release_buffer(&mstat, i_input_token);

			if (i_input_token != GSS_C_NO_BUFFER) {
				free(i_input_token);
				i_input_token = GSS_C_NO_BUFFER;
			}

			ret = status;

			/*
			 * Reject the request with an error token.
			 */
			negResult = REJECT;
			return_token = ERROR_TOKEN_SEND;

			goto senderror;
		}

		if (ret_flags)
			*ret_flags = local_ret_flags;

		if (i_input_token != GSS_C_NO_BUFFER) {
			(void) gss_release_buffer(&mstat, i_input_token);
			free(i_input_token);
			i_input_token = GSS_C_NO_BUFFER;
		}

		/* If we got a MIC, verify it if possible */
		if ((status == GSS_S_COMPLETE) &&
		    (local_ret_flags & GSS_C_INTEG_FLAG) &&
		    mechListMIC != GSS_C_NO_BUFFER &&
		    !spnego_ctx->MS_Interop) {

			ret = gss_verify_mic(minor_status,
			    spnego_ctx->ctx_handle,
			    &spnego_ctx->DER_mechTypes,
			    mechListMIC, &qop_state);

			(void) gss_release_buffer(&mstat, mechListMIC);
			free(mechListMIC);
			mechListMIC = GSS_C_NO_BUFFER;

			if (ret != GSS_S_COMPLETE) {
				negResult = REJECT;
				return_token = ERROR_TOKEN_SEND;
				goto senderror;
			}
		}

		/*
		 * If the MIC was verified OK, create a new MIC
		 * for the response message.
		 */
		if (status == GSS_S_COMPLETE &&
		    (local_ret_flags & GSS_C_INTEG_FLAG) &&
		    !spnego_ctx->MS_Interop) {
			mechListMIC = (gss_buffer_t)
			    malloc(sizeof (gss_buffer_desc));

			if (mechListMIC == NULL ||
			    spnego_ctx->DER_mechTypes.length == 0) {
				ret = GSS_S_FAILURE;
				goto cleanup;
			}

			ret = gss_get_mic(minor_status,
			    spnego_ctx->ctx_handle,
			    GSS_C_QOP_DEFAULT,
			    &spnego_ctx->DER_mechTypes,
			    mechListMIC);

			if (ret != GSS_S_COMPLETE) {
				negResult = REJECT;
				return_token = ERROR_TOKEN_SEND;
				goto senderror;
			}
		}
		ret = status;

		if (status == GSS_S_COMPLETE) {
			if (internal_name != NULL && src_name != NULL)
				*src_name = internal_name;
		}


		if (status == GSS_S_CONTINUE_NEEDED) {
			if (return_token == INIT_TOKEN_SEND)
				negResult = ACCEPT_INCOMPLETE;
		}
	}

senderror:
	if ((return_token == INIT_TOKEN_SEND) ||
	    (return_token == CONT_TOKEN_SEND) ||
	    (return_token == ERROR_TOKEN_SEND)) {
		int MS_Interop = 0;

		if (spnego_ctx)
			MS_Interop = spnego_ctx->MS_Interop;

		/*
		 * create response for the initiator.
		 */
		err = make_spnego_tokenTarg_msg(negResult,
		    mech_wanted, i_output_token,
		    mechListMIC, return_token,
		    MS_Interop, output_token);

		(void) gss_release_buffer(&mstat, mechListMIC);
		free(mechListMIC);

		/*
		 * If we could not make the response token,
		 * we will have to fail without sending a response.
		 */
		if (err) {
			(void) gss_release_buffer(&mstat, output_token);
		}
	} else {
		(void) gss_release_buffer(&mstat, output_token);
	}

cleanup:
	if (ret != GSS_S_COMPLETE &&
	    ret != GSS_S_CONTINUE_NEEDED) {
		if (spnego_ctx != NULL) {
			(void) gss_delete_sec_context(&mstat,
			    &spnego_ctx->ctx_handle, NULL);

			spnego_ctx->ctx_handle = NULL;

			release_spnego_ctx(&spnego_ctx);
		}
		*context_handle = GSS_C_NO_CONTEXT;
	}
	if (mech_wanted != NULL) {
		generic_gss_release_oid(&mstat, &mech_wanted);
	}

	(void) gss_release_cred(minor_status, &acquired_cred);
	(void) gss_release_oid_set(minor_status, &supported_mechSet);

	(void) gss_release_buffer(&mstat, i_output_token);
	free(i_output_token);

	return (ret);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_display_status(void *ctx,
		OM_uint32 *minor_status,
		OM_uint32 status_value,
		int status_type,
		gss_OID mech_type,
		OM_uint32 *message_context,
		gss_buffer_t status_string)
{
	OM_uint32 ret = GSS_S_COMPLETE;
	dsyslog("Entering display_status\n");

	*message_context = 0;
	switch (status_value) {
		case ERR_SPNEGO_NO_MECHS_AVAILABLE:
			*status_string = make_err_msg(gettext(
			    "SPNEGO cannot find mechanisms to negotiate"));
			break;
		case ERR_SPNEGO_NO_CREDS_ACQUIRED:
			*status_string = make_err_msg(gettext(
			    "SPNEGO failed to acquire creds"));
			break;
		case ERR_SPNEGO_NO_MECH_FROM_ACCEPTOR:
			*status_string = make_err_msg(gettext(
			    "SPNEGO acceptor did not select a mechanism"));
			break;
		case ERR_SPNEGO_NEGOTIATION_FAILED:
			*status_string = make_err_msg(gettext(
			    "SPNEGO failed to negotiate a mechanism"));
			break;
		case ERR_SPNEGO_NO_TOKEN_FROM_ACCEPTOR:
			*status_string = make_err_msg(gettext(
			    "SPNEGO acceptor did not return a valid token"));
			break;
		case ERR_SPNEGO_BAD_INPUT_PARAMETER:
			*status_string = make_err_msg(gettext(
			    "SPNEGO function received an incorrect input "
			    "parameter"));
			break;
		default:
			status_string->length = 0;
			status_string->value = "";
			ret = GSS_S_BAD_STATUS;
			break;
	}

	dsyslog("Leaving display_status\n");
	return (ret);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_import_name(void *ctx,
		    OM_uint32 *minor_status,
		    gss_buffer_t input_name_buffer,
		    gss_OID input_name_type,
		    gss_name_t *output_name)
{
	OM_uint32 status;

	dsyslog("Entering import_name\n");

	status = gss_import_name(minor_status, input_name_buffer,
	    input_name_type, output_name);

	dsyslog("Leaving import_name\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_release_name(void *ctx,
			OM_uint32 *minor_status,
			gss_name_t *input_name)
{
	OM_uint32 status;

	dsyslog("Entering release_name\n");

	status = gss_release_name(minor_status, input_name);

	dsyslog("Leaving release_name\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_display_name(void *ctx,
			OM_uint32 *minor_status,
			gss_name_t input_name,
			gss_buffer_t output_name_buffer,
			gss_OID *output_name_type)
{
	OM_uint32 status = GSS_S_COMPLETE;
	dsyslog("Entering display_name\n");

	status = gss_display_name(minor_status, input_name,
	    output_name_buffer, output_name_type);

	dsyslog("Leaving display_name\n");
	return (status);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_inquire_cred(void *ctx,
	OM_uint32 *minor_status,
	const gss_cred_id_t cred_handle,
	gss_name_t *name,
	OM_uint32 *lifetime,
	gss_cred_usage_t *cred_usage,
	gss_OID_set *mechanisms)
{
	OM_uint32 stat = GSS_S_COMPLETE;
	gss_cred_id_t *credlistptr = NULL, credlist = NULL;
	OM_uint32 init_lt, accept_lt;
	int i;

	if (cred_handle == GSS_C_NO_CREDENTIAL) {
		OM_uint32 tstat;
		credlistptr = &credlist;

		/*
		 * Get a list of all non-SPNEGO
		 * mechanisms that are available and
		 * acquire a default cred.
		 */
		stat = get_available_mechs(minor_status,
		    NULL, GSS_C_BOTH, credlistptr, mechanisms);

		/*
		 * inquire about the default cred from the
		 * first non-SPNEGO mechanism that was found.
		 */
		if (stat == GSS_S_COMPLETE && mechanisms &&
		    (*mechanisms)->count > 0) {
			i = 0;
			do {
				stat = gss_inquire_cred_by_mech(
				    minor_status, credlist,
				    &((*mechanisms)->elements[i]),
				    name, &init_lt, &accept_lt,
				    cred_usage);

				/*
				 * Set the lifetime to the correct value.
				 */
				if (stat == GSS_S_COMPLETE) {
					if (*cred_usage == GSS_C_INITIATE)
						*lifetime = init_lt;
					else
						*lifetime = accept_lt;
				}
				if (credlist != GSS_C_NO_CREDENTIAL)
					(void) gss_release_cred(&tstat,
					    &credlist);
			} while (stat != GSS_S_COMPLETE &&
			    (i < (*mechanisms)->count));
		}
	} else {
		/*
		 * This should not happen, it cannot be processed.
		 */
		stat = GSS_S_FAILURE;
		if (minor_status != NULL)
			*minor_status = ERR_SPNEGO_BAD_INPUT_PARAMETER;
	}
	return (stat);
}

/*ARGSUSED*/
OM_uint32
spnego_gss_inquire_names_for_mech(void *ctx,
				OM_uint32	*minor_status,
				gss_OID		mechanism,
				gss_OID_set	*name_types)
{
	OM_uint32   major, minor;

	dsyslog("Entering inquire_names_for_mech\n");
	/*
	 * We only know how to handle our own mechanism.
	 */
	if ((mechanism != GSS_C_NULL_OID) &&
	    !g_OID_equal(gss_mech_spnego, mechanism)) {
		*minor_status = 0;
		return (GSS_S_FAILURE);
	}

	major = gss_create_empty_oid_set(minor_status, name_types);
	if (major == GSS_S_COMPLETE) {
		/* Now add our members. */
		if (((major = gss_add_oid_set_member(minor_status,
		    (gss_OID) GSS_C_NT_USER_NAME,
		    name_types)) == GSS_S_COMPLETE) &&
		    ((major = gss_add_oid_set_member(minor_status,
		    (gss_OID) GSS_C_NT_MACHINE_UID_NAME,
		    name_types)) == GSS_S_COMPLETE) &&
		    ((major = gss_add_oid_set_member(minor_status,
		    (gss_OID) GSS_C_NT_STRING_UID_NAME,
		    name_types)) == GSS_S_COMPLETE)) {
			major = gss_add_oid_set_member(minor_status,
			    (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
			    name_types);
		}

		if (major != GSS_S_COMPLETE)
			(void) gss_release_oid_set(&minor, name_types);
	}

	dsyslog("Leaving inquire_names_for_mech\n");
	return (major);
}

OM_uint32
spnego_gss_unseal(void *context,
		OM_uint32 *minor_status,
		gss_ctx_id_t context_handle,
		gss_buffer_t input_message_buffer,
		gss_buffer_t output_message_buffer,
		int *conf_state,
		int *qop_state)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx = (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_unseal(minor_status,
	    ctx->ctx_handle, input_message_buffer,
	    output_message_buffer, conf_state, qop_state);

	return (ret);
}

OM_uint32
spnego_gss_seal(void *context,
		OM_uint32 *minor_status,
		gss_ctx_id_t context_handle,
		int conf_req_flag,
		int qop_req,
		gss_buffer_t input_message_buffer,
		int *conf_state,
		gss_buffer_t output_message_buffer)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx =
	    (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_seal(minor_status,
	    ctx->ctx_handle, conf_req_flag,
	    qop_req, input_message_buffer,
	    conf_state, output_message_buffer);

	return (ret);
}

OM_uint32
spnego_gss_process_context_token(void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	const gss_buffer_t token_buffer)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx =
	    (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_process_context_token(minor_status,
	    ctx->ctx_handle, token_buffer);

	return (ret);
}

OM_uint32
spnego_gss_delete_sec_context(void *context,
			    OM_uint32 *minor_status,
			    gss_ctx_id_t *context_handle,
			    gss_buffer_t output_token)
{
	OM_uint32 ret = GSS_S_COMPLETE;
	spnego_gss_ctx_id_t *ctx =
	    (spnego_gss_ctx_id_t *)context_handle;

	if (context_handle == NULL || *ctx == NULL)
		return (GSS_S_NO_CONTEXT);

	/*
	 * If this is still a SPNEGO mech, release it locally.
	 */
	if ((*ctx)->ctx_handle == GSS_C_NO_CONTEXT) {
		(void) release_spnego_ctx(ctx);
	} else {
		ret = gss_delete_sec_context(minor_status,
		    &(*ctx)->ctx_handle, output_token);
	}

	return (ret);
}

OM_uint32
spnego_gss_context_time(void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	OM_uint32	*time_rec)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx =
	    (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_context_time(minor_status,
	    ctx->ctx_handle, time_rec);

	return (ret);
}

OM_uint32
spnego_gss_export_sec_context(void *context,
	OM_uint32	  *minor_status,
	gss_ctx_id_t *context_handle,
	gss_buffer_t interprocess_token)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t *ctx =
	    (spnego_gss_ctx_id_t *)context_handle;

	if (context_handle == NULL || *ctx == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_export_sec_context(minor_status,
	    &(*ctx)->ctx_handle, interprocess_token);
	return (ret);
}

OM_uint32
spnego_gss_import_sec_context(void *context,
	OM_uint32		*minor_status,
	const gss_buffer_t	interprocess_token,
	gss_ctx_id_t		*context_handle)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	if ((ctx = create_spnego_ctx()) == NULL) {
		*minor_status = ENOMEM;
		return (GSS_S_FAILURE);
	}

	ret = gss_import_sec_context(minor_status,
	    interprocess_token, &(ctx->ctx_handle));
	if (GSS_ERROR(ret)) {
		(void) release_spnego_ctx(&ctx);
		return (ret);
	}

	*context_handle = (gss_ctx_id_t)ctx;

	return (ret);
}

OM_uint32
spnego_gss_inquire_context(void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	gss_name_t	*src_name,
	gss_name_t	*targ_name,
	OM_uint32	*lifetime_rec,
	gss_OID		*mech_type,
	OM_uint32	*ctx_flags,
	int		*locally_initiated,
	int		*open)
{
	OM_uint32 ret = GSS_S_COMPLETE;
	spnego_gss_ctx_id_t ctx =
	    (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_inquire_context(minor_status,
	    ctx->ctx_handle, src_name,
	    targ_name, lifetime_rec,
	    mech_type, ctx_flags,
	    locally_initiated, open);

	return (ret);
}

OM_uint32
spnego_gss_wrap_size_limit(void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	int		conf_req_flag,
	gss_qop_t	qop_req,
	OM_uint32	req_output_size,
	OM_uint32	*max_input_size)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx =
	    (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_wrap_size_limit(minor_status,
	    ctx->ctx_handle, conf_req_flag,
	    qop_req, req_output_size,
	    max_input_size);
	return (ret);
}

OM_uint32
spnego_gss_sign(void *context,
		OM_uint32 *minor_status,
		const gss_ctx_id_t context_handle,
		int  qop_req,
		const gss_buffer_t message_buffer,
		gss_buffer_t message_token)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx =
	    (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_sign(minor_status,
	    ctx->ctx_handle,
	    qop_req,
	    message_buffer,
	    message_token);

	return (ret);
}

OM_uint32
spnego_gss_verify(void *context,
	OM_uint32 *minor_status,
	const gss_ctx_id_t context_handle,
	const gss_buffer_t msg_buffer,
	const gss_buffer_t token_buffer,
	int *qop_state)
{
	OM_uint32 ret;
	spnego_gss_ctx_id_t ctx =
	    (spnego_gss_ctx_id_t)context_handle;

	if (context_handle == NULL)
		return (GSS_S_NO_CONTEXT);

	ret = gss_verify_mic(minor_status,
	    ctx->ctx_handle,
	    msg_buffer,
	    token_buffer,
	    (uint32_t *)qop_state);
	return (ret);
}

/*
 * We will release everything but the ctx_handle so that it
 * can be passed back to init/accept context. This routine should
 * not be called until after the ctx_handle memory is assigned to
 * the supplied context handle from init/accept context.
 */
static void
release_spnego_ctx(spnego_gss_ctx_id_t *ctx)
{
	spnego_gss_ctx_id_t context;
	OM_uint32 minor_stat;

	if (ctx != NULL)
		context = *ctx;
	else
		return;

	if (context != NULL) {
		(void) gss_release_buffer(&minor_stat,
		    &context->DER_mechTypes);

		(void) generic_gss_release_oid(&minor_stat,
		    &context->internal_mech);

		if (context->optionStr != NULL) {
			free(context->optionStr);
			context->optionStr = NULL;
		}
		if (context->ctx_handle != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor_stat,
			    &context->ctx_handle, GSS_C_NO_BUFFER);

		free(context);
		*ctx = NULL;
	}
}

/*
 * Can't use gss_indicate_mechs by itself to get available mechs for
 * SPNEGO because it will also return the SPNEGO mech and we do not
 * want to consider SPNEGO as an available security mech for
 * negotiation. For this reason, get_available_mechs will return
 * all available mechs except SPNEGO.
 *
 * If a ptr to a creds list is given, this function will attempt
 * to acquire creds for the creds given and trim the list of
 * returned mechanisms to only those for which creds are valid.
 *
 */
static OM_uint32
get_available_mechs(OM_uint32 *minor_status,
	gss_name_t name, gss_cred_usage_t usage,
	gss_cred_id_t *creds, gss_OID_set *rmechs)
{
	int		i;
	int		found = 0;
	OM_uint32 stat = GSS_S_COMPLETE;
	gss_OID_set mechs, goodmechs;

	stat = gss_indicate_mechs(minor_status, &mechs);

	if (stat != GSS_S_COMPLETE) {
		return (stat);
	}

	stat = gss_create_empty_oid_set(minor_status, rmechs);

	if (stat != GSS_S_COMPLETE) {
		(void) gss_release_oid_set(minor_status, &mechs);
		return (stat);
	}

	for (i = 0; i < mechs->count && stat == GSS_S_COMPLETE; i++) {
		if ((mechs->elements[i].length
		    != spnego_mechanism.mech_type.length) ||
		    memcmp(mechs->elements[i].elements,
		    spnego_mechanism.mech_type.elements,
		    spnego_mechanism.mech_type.length)) {

			stat = gss_add_oid_set_member(minor_status,
			    &mechs->elements[i], rmechs);
			if (stat == GSS_S_COMPLETE)
				found++;
		}
	}

	/*
	 * If the caller wanted a list of creds returned,
	 * trim the list of mechanisms down to only those
	 * for which the creds are valid.
	 */
	if (found > 0 && stat == GSS_S_COMPLETE && creds != NULL) {
		stat = gss_acquire_cred(minor_status,
		    name, NULL, *rmechs, usage, creds,
		    &goodmechs, NULL);

		/*
		 * Drop the old list in favor of the new
		 * "trimmed" list.
		 */
		(void) gss_release_oid_set(minor_status, rmechs);
		if (stat == GSS_S_COMPLETE) {
			(void) gss_copy_oid_set(minor_status,
			    goodmechs, rmechs);
			(void) gss_release_oid_set(minor_status, &goodmechs);
		}
	}

	(void) gss_release_oid_set(minor_status, &mechs);
	if (found == 0 || stat != GSS_S_COMPLETE) {
		*minor_status = ERR_SPNEGO_NO_MECHS_AVAILABLE;
		if (stat == GSS_S_COMPLETE)
			stat = GSS_S_FAILURE;
	}

	return (stat);
}

/* following are token creation and reading routines */

/*
 * If buff_in is not pointing to a MECH_OID, then return NULL and do not
 * advance the buffer, otherwise, decode the mech_oid from the buffer and
 * place in gss_OID.
 */
static gss_OID
get_mech_oid(OM_uint32 *minor_status, unsigned char **buff_in, size_t length)
{
	OM_uint32	status;
	gss_OID_desc 	toid;
	gss_OID		mech_out = NULL;
	uchar_t		*start, *end;

	if (length < 1 || **buff_in != MECH_OID)
		return (NULL);

	start = *buff_in;
	end = start + length;

	(*buff_in)++;
	toid.length = *(*buff_in)++;

	if ((*buff_in + toid.length) > end)
		return (NULL);

	toid.elements = *buff_in;
	*buff_in += toid.length;

	status = generic_gss_copy_oid(minor_status, &toid, &mech_out);

	if (status != GSS_S_COMPLETE)
		mech_out = NULL;

	return (mech_out);
}

/*
 * der encode the given mechanism oid into buf_out, advancing the
 * buffer pointer.
 */

static int
put_mech_oid(unsigned char **buf_out, gss_OID_desc *mech, int buflen)
{
	if (buflen < mech->length + 2)
		return (-1);
	*(*buf_out)++ = MECH_OID;
	*(*buf_out)++ = (unsigned char) mech->length;
	memcpy((void *)(*buf_out), mech->elements, mech->length);
	*buf_out += mech->length;
	return (0);
}

/*
 * verify that buff_in points to an octet string, if it does not,
 * return NULL and don't advance the pointer. If it is an octet string
 * decode buff_in into a gss_buffer_t and return it, advancing the
 * buffer pointer.
 */
static gss_buffer_t
get_input_token(unsigned char **buff_in, int buff_length)
{
	gss_buffer_t input_token;
	unsigned int bytes;

	if (**buff_in != OCTET_STRING)
		return (NULL);

	(*buff_in)++;
	input_token = (gss_buffer_t)malloc(sizeof (gss_buffer_desc));

	if (input_token == NULL)
		return (NULL);

	input_token->length = get_der_length(buff_in, buff_length, &bytes);
	if ((int)input_token->length == -1) {
		free(input_token);
		return (NULL);
	}
	input_token->value = malloc(input_token->length);

	if (input_token->value == NULL) {
		free(input_token);
		return (NULL);
	}

	(void) memcpy(input_token->value, *buff_in, input_token->length);
	*buff_in += input_token->length;
	return (input_token);
}

/*
 * verify that the input token length is not 0. If it is, just return.
 * If the token length is greater than 0, der encode as an octet string
 * and place in buf_out, advancing buf_out.
 */

static int
put_input_token(unsigned char **buf_out, gss_buffer_t input_token,
		int buflen)
{
	int ret;

	/* if token length is 0, we do not want to send */
	if (input_token->length == 0)
		return (0);

	if (input_token->length > buflen)
		return (-1);

	*(*buf_out)++ = OCTET_STRING;
	if ((ret = put_der_length(input_token->length, buf_out,
	    input_token->length)))
		return (ret);
	TWRITE_STR(*buf_out, input_token->value, ((int)input_token->length));
	return (0);
}

/*
 * verify that buff_in points to a sequence of der encoding. The mech
 * set is the only sequence of encoded object in the token, so if it is
 * a sequence of encoding, decode the mechset into a gss_OID_set and
 * return it, advancing the buffer pointer.
 */
static gss_OID_set
get_mech_set(OM_uint32 *minor_status, unsigned char **buff_in, int buff_length)
{
	gss_OID_set returned_mechSet;
	OM_uint32 major_status;
	OM_uint32 length;
	OM_uint32 bytes;
	OM_uint32 set_length;
	uchar_t		*start;
	int i;

	if (**buff_in != SEQUENCE_OF)
		return (NULL);

	start = *buff_in;
	(*buff_in)++;

	length = get_der_length(buff_in, buff_length, &bytes);

	major_status = gss_create_empty_oid_set(minor_status,
	    &returned_mechSet);
	if (major_status != GSS_S_COMPLETE)
		return (NULL);

	for (set_length = 0, i = 0; set_length < length; i++) {
		gss_OID_desc *temp = get_mech_oid(minor_status, buff_in,
		    buff_length - (*buff_in - start));
		if (temp != NULL) {
			major_status = gss_add_oid_set_member(minor_status,
			    temp, &returned_mechSet);
			if (major_status == GSS_S_COMPLETE) {
				set_length +=
				    returned_mechSet->elements[i].length +2;
				generic_gss_release_oid(minor_status, &temp);
			}
		}
	}

	return (returned_mechSet);
}

/*
 * der encode the passed mechSet and place it into buf_out,
 * advancing the buffer pointer.
 */
static int
put_mech_set(uchar_t **buf_out, gss_OID_set mechSet, int buflen)
{
	int i, ret;
	OM_uint32 length = 0;
	uchar_t *start;

	if (buf_out == NULL || *buf_out == NULL)
		return (-1);

	start = *buf_out;

	*(*buf_out)++ = SEQUENCE_OF;

	for (i = 0; i < mechSet->count; i++) {
		/*
		 * Mech OID ASN.1 size = 2 + length.
		 * 1 = 0x06, 1 for length of OID
		 * typically, less than 128, so only 1 byte needed.
		 */
		length += 1 + der_length_size(mechSet->elements[i].length) +
		    mechSet->elements[i].length;
	}
	if (length > (buflen-1))
		return (-1);

	if (put_der_length(length, buf_out, buflen-1) < 0)
		return (-1);

	for (i = 0; i < mechSet->count; i++) {
		if ((ret = put_mech_oid(buf_out, &mechSet->elements[i],
		    buflen - (int)(*buf_out	 - start))))
			return (ret);
	}
	return (0);
}

/*
 * Verify that buff_in is pointing to a BIT_STRING with the correct
 * length and padding for the req_flags. If it is, decode req_flags
 * and return them, otherwise, return NULL.
 */
static OM_uint32
get_req_flags(unsigned char **buff_in, int *bodysize, OM_uint32 *req_flags)
{
	int len;
	uchar_t *start = *buff_in;

	/* It is OK if no ReqFlags data is sent. */
	if (**buff_in != (CONTEXT | 0x01))
		return (0);

	/* If they are sent, make sure the fields are correct. */
	if (g_get_tag_and_length(buff_in, (CONTEXT | 0x01),
	    *bodysize, &len) < 0)
		return (ACCEPT_DEFECTIVE_TOKEN);

	/* We don't care what the flags are. */
	(*buff_in) += len;

	/* Don't return any flags, this field is useless */
	*req_flags = 0;

	*bodysize -= *buff_in - start;
	return (0);
}

/*
 * get the negotiation results, decoding the ENUMERATED type result
 * from the buffer, advancing the buffer pointer.
 */
static OM_uint32
get_negResult(unsigned char **buff_in, int bodysize)
{
	unsigned char *iptr = *buff_in;
	int len;
	unsigned int bytes;
	OM_uint32 result;
	/*
	 * Verify that the data is ASN.1 encoded correctly
	 */
	if (g_get_tag_and_length(buff_in, (CONTEXT | 0x01),
	    bodysize, &len) < 0)
		return (ACCEPT_DEFECTIVE_TOKEN);

	if (*(*buff_in)++ == SEQUENCE) {
		if ((len = get_der_length(buff_in,
		    bodysize - (*buff_in - iptr), &bytes)) < 0)
			return (ACCEPT_DEFECTIVE_TOKEN);
	} else {
		return (ACCEPT_INCOMPLETE);
	}

	/*
	 * if we find an octet string, we need to return
	 * incomplete so that we process the token correctly.
	 * Anything else unexpected, we reject.
	 */
	if (*(*buff_in)++ == CONTEXT) {
		if ((len = get_der_length(buff_in, bodysize -
		    (*buff_in - iptr), &bytes)) < 0)
			return (ACCEPT_DEFECTIVE_TOKEN);
	} else {
		return (ACCEPT_INCOMPLETE);
	}

	if (*(*buff_in) == OCTET_STRING)
		return (ACCEPT_INCOMPLETE);

	if (*(*buff_in)++ != ENUMERATED)
		return (ACCEPT_DEFECTIVE_TOKEN);

	if (*(*buff_in)++ != ENUMERATION_LENGTH)
		return (ACCEPT_DEFECTIVE_TOKEN);

	/*
	 * Save the result byte to return later.
	 * This is the result
	 */
	result = (OM_uint32)*(*buff_in)++;

	if (g_get_tag_and_length(buff_in, (CONTEXT | 0x01),
	    bodysize - (*buff_in - iptr), &len) < 0)
		result = ACCEPT_DEFECTIVE_TOKEN;

	return (result);
}

/*
 * der encode the passed negResults as an ENUMERATED type and
 * place it in buf_out, advancing the buffer.
 */

static int
put_negResult(uchar_t **buf_out, OM_uint32 negResult, int buflen)
{
	if (buflen < 3)
		return (-1);
	*(*buf_out)++ = ENUMERATED;
	*(*buf_out)++ = ENUMERATION_LENGTH;
	*(*buf_out)++ = (unsigned char) negResult;
	return (0);
}

/*
 * This routine compares the recieved mechset to the mechset that
 * this server can support. It looks sequentially through the mechset
 * and the first one that matches what the server can support is
 * chosen as the negotiated mechanism. If one is found, negResult
 * is set to ACCEPT_COMPLETE, otherwise we return NULL and negResult
 * is set to REJECT. Also, for purposes of determining latter behavior,
 * the flag, firstMech is used to indicate if the chosen mechanism is the
 * first of the mechset or not.
 */
static gss_OID
negotiate_mech_type(OM_uint32 *minor_status,
	gss_OID_set supported_mechSet,
	gss_OID_set mechset,
	OM_uint32 *negResult,
	bool_t *firstMech)
{
	gss_OID returned_mech;
	OM_uint32 status;
	int present;
	int i;

	for (i = 0; i < mechset->count; i++) {
		gss_test_oid_set_member(minor_status, &mechset->elements[i],
		    supported_mechSet, &present);
		if (present == TRUE) {
			*negResult = ACCEPT_COMPLETE;

			if (i == 0)
				*firstMech = TRUE;
			else
				*firstMech = FALSE;

			status = generic_gss_copy_oid(minor_status,
			    &mechset->elements[i], &returned_mech);

			if (status != GSS_S_COMPLETE) {
				*negResult = REJECT;
				return (NULL);
			}

			return (returned_mech);
		}
	}

	*negResult = REJECT;
	return (NULL);
}

/*
 * the next two routines make a token buffer suitable for
 * spnego_gss_display_status. These currently take the string
 * in name and place it in the token. Eventually, if
 * spnego_gss_display_status returns valid error messages,
 * these routines will be changes to return the error string.
 */
static spnego_token_t
make_spnego_token(char *name)
{
	spnego_token_t token;

	token = (spnego_token_t)malloc(strlen(name)+1);

	if (token == NULL)
		return (NULL);
	strcpy(token, name);
	return (token);
}

static gss_buffer_desc
make_err_msg(char *name)
{
	gss_buffer_desc buffer;

	if (name == NULL) {
		buffer.length = 0;
		buffer.value = NULL;
	} else {
		buffer.length = strlen(name)+1;
		buffer.value = make_spnego_token(name);
	}

	return (buffer);
}

/*
 * Create the client side spnego token passed back to gss_init_sec_context
 * and eventually up to the application program and over to the server.
 *
 * Use DER rules, definite length method per RFC 2478
 */
static int
make_spnego_tokenInit_msg(spnego_gss_ctx_id_t spnego_ctx,
	gss_OID_set mechSet,
	gss_buffer_t data, send_token_flag sendtoken,
	gss_buffer_t outbuf)
{
	OM_uint32 status, minor_stat;
	int tlen, dataLen = 0, ret = 0;
	int MechSetLen = 0;
	int negTokenInitSize = 0;
	int i;
	unsigned char *t;
	unsigned char *ptr;
	unsigned char *MechListPtr = NULL;
	gss_buffer_desc MICbuff;

	if (outbuf == GSS_C_NO_BUFFER)
		return (-1);

	outbuf->length = 0;
	outbuf->value = NULL;

	/* calculate the data length */

	/* no token generated if sendtoken is not init or cont */
	if ((sendtoken < INIT_TOKEN_SEND) ||
	    (sendtoken > CONT_TOKEN_SEND)) {
		return (-1);
	}

	/*
	 * if this is the init token, we will send the mechset
	 * so include it's length.
	 */
	if (sendtoken == INIT_TOKEN_SEND) {
		/*
		 * Count bytes for the mechSet data
		 * Encoded in final output as:
		 * 0xa0 [DER LEN] 0x30 [DER LEN] [DATA]
		 */
		for (i = 0; i < mechSet->count; i++)
			MechSetLen += 1 +
			    der_length_size(mechSet->elements[i].length) +
			    mechSet->elements[i].length;

		MechSetLen += 1 + der_length_size(MechSetLen);
		dataLen += 1 + der_length_size(MechSetLen) + MechSetLen;

		MechListPtr = (uchar_t *)malloc(dataLen);
		ptr = (uchar_t *)MechListPtr;

		if (MechListPtr != NULL) {
			if ((ret = put_mech_set(&ptr, mechSet, dataLen))) {
				free(MechListPtr);
				goto errout;
			}
		} else {
			ret = -1;
			goto errout;
		}

		/*
		 * The MIC is done over the DER encoded mechSet.
		 */
		spnego_ctx->DER_mechTypes.value = MechListPtr;
		spnego_ctx->DER_mechTypes.length = ptr - MechListPtr;

		/*
		 * Only send the MIC if we are *NOT* interoperating
		 * with Microsoft.
		 */
		if (!spnego_ctx->MS_Interop) {
			/*
			 * MechListMIC = DER(MIC(DER(MechSet)))
			 * Calculate it here, stick it in the buffer later.
			 */
			MICbuff.length = 0;
			MICbuff.value = NULL;
			status = gss_get_mic(&minor_stat,
			    spnego_ctx->ctx_handle, GSS_C_QOP_DEFAULT,
			    &spnego_ctx->DER_mechTypes, &MICbuff);
			/*
			 * If the MIC operation succeeded, use it,
			 * but don't fail if it did not succeed.
			 * MIC is optional and is not supported by all
			 * mechanisms all the time.
			 */
			if (status  == GSS_S_COMPLETE) {
				/*
				 * Encoded in final output as:
				 * 0xa3 [DER LEN] 0x04 [DER LEN] [DATA]
				 *	--s--   -------tlen------------
				 */
				tlen = 1 + der_length_size(MICbuff.length) +
				    MICbuff.length;

				dataLen += 1 + der_length_size(tlen) + tlen;
			}
		}
	}

	/*
	 * If a token from gss_init_sec_context exists,
	 * add the length of the token + the ASN.1 overhead
	 */
	if (data != NULL) {
		/*
		 * Encoded in final output as:
		 * 0xa2 [DER LEN] 0x04 [DER LEN] [DATA]
		 * -----s--------|--------s2----------
		 */
		tlen = 1 + der_length_size(data->length) + data->length;

		dataLen += 1 + der_length_size(tlen) + tlen;
	}

	/*
	 * Add size of DER encoding
	 * [ SEQUENCE { MechTypeList | ReqFLags | Token | mechListMIC } ]
	 *   0x30 [DER_LEN] [data]
	 *
	 */
	dataLen += 1 + der_length_size(dataLen);

	/*
	 * negTokenInitSize indicates the bytes needed to
	 * hold the ASN.1 encoding of the entire NegTokenInit
	 * SEQUENCE.
	 * 0xa0 [DER_LEN] + data
	 *
	 */
	negTokenInitSize = dataLen;

	tlen = g_token_size((gss_OID)gss_mech_spnego,
	    negTokenInitSize + 1 +
	    der_length_size(negTokenInitSize));

	t = (unsigned char *) malloc(tlen);

	if (t == NULL) {
		return (-1);
	}

	ptr = t;

	/* create the message */
	if ((ret = g_make_token_header((gss_OID)gss_mech_spnego,
	    1 + negTokenInitSize + der_length_size(negTokenInitSize),
	    &ptr, tlen)))
		goto errout;

	if (sendtoken == INIT_TOKEN_SEND) {
		*ptr++ = CONTEXT; /* NegotiationToken identifier */
		if ((ret = put_der_length(negTokenInitSize, &ptr, tlen)))
			goto errout;

		*ptr++ = SEQUENCE;
		if ((ret = put_der_length(negTokenInitSize - 4, &ptr,
		    tlen - (int)(ptr-t))))
			goto errout;

		*ptr++ = CONTEXT; /* MechTypeList identifier */
		if ((ret = put_der_length(spnego_ctx->DER_mechTypes.length,
		    &ptr, tlen - (int)(ptr-t))))
			goto errout;

		/* We already encoded the MechSetList */
		(void) memcpy(ptr, spnego_ctx->DER_mechTypes.value,
		    spnego_ctx->DER_mechTypes.length);

		ptr += spnego_ctx->DER_mechTypes.length;

	}

	if (data != NULL) {
		*ptr++ = CONTEXT | 0x02;
		if ((ret = put_der_length(data->length + 4,
		    &ptr, tlen - (int)(ptr - t))))
			goto errout;

		if ((ret = put_input_token(&ptr, data,
		    tlen - (int)(ptr - t))))
			goto errout;

		/*
		 * We are in "optimistic" mode if we send a token
		 * with out initial message.
		 */
		spnego_ctx->optimistic = (sendtoken == INIT_TOKEN_SEND);
	}

	if (!spnego_ctx->MS_Interop && MICbuff.length > 0) {
		/* We already calculated the MechListMIC above */
		int len = 1 +  der_length_size(MICbuff.length) + MICbuff.length;
		*ptr++ = CONTEXT | 0x03;
		if ((ret = put_der_length(len, &ptr, tlen - (int)(ptr - t))))
			goto errout;

		if ((ret = put_input_token(&ptr, &MICbuff,
		    tlen - (int)(ptr - t))))
			goto errout;

		(void) gss_release_buffer(&minor_stat, &MICbuff);
	}

errout:
	if (ret != 0) {
		if (t)
			free(t);
		t = NULL;
		tlen = 0;
	}
	outbuf->length = tlen;
	outbuf->value = (void *) t;

	return (ret);
}

/*
 * create the server side spnego token passed back to
 * gss_accept_sec_context and eventually up to the application program
 * and over to the client.
 */
static int
make_spnego_tokenTarg_msg(OM_uint32 status, gss_OID mech_wanted,
			gss_buffer_t data, gss_buffer_t mechListMIC,
			send_token_flag sendtoken, int MS_Flag,
			gss_buffer_t outbuf)
{
	int tlen;
	int ret;
	int NegTokenTargSize;
	int negresultTokenSize;
	int NegTokenSize;
	int rspTokenSize;
	int micTokenSize;
	int dataLen = 0;
	unsigned char *t;
	unsigned char *ptr;

	if (outbuf == GSS_C_NO_BUFFER)
		return (GSS_S_DEFECTIVE_TOKEN);

	outbuf->length = 0;
	outbuf->value = NULL;

	/*
	 * ASN.1 encoding of the negResult
	 * ENUMERATED type is 3 bytes
	 *  ENUMERATED TAG, Length, Value,
	 * Plus 2 bytes for the CONTEXT id and length.
	 */
	negresultTokenSize = 5;

	/*
	 * calculate data length
	 *
	 * If this is the initial token, include length of
	 * mech_type and the negotiation result fields.
	 */
	if (sendtoken == INIT_TOKEN_SEND) {

		if (mech_wanted != NULL) {
			int mechlistTokenSize;
			/*
			 * 1 byte for the CONTEXT ID(0xa0),
			 * 1 byte for the OID ID(0x06)
			 * 1 byte for OID Length field
			 * Plus the rest... (OID Length, OID value)
			 */
			mechlistTokenSize = 3 + mech_wanted->length +
			    der_length_size(mech_wanted->length);

			dataLen = negresultTokenSize + mechlistTokenSize;
		}
	} else {
		/*
		 * If this is a response from a server, count
		 * the space needed for the negResult field.
		 * LENGTH(2) + ENUM(2) + result
		 */
		dataLen = negresultTokenSize;
	}
	if (data != NULL && data->length > 0) {
		/* Length of the inner token */
		rspTokenSize = 1 + der_length_size(data->length) +
		    data->length;

		dataLen += rspTokenSize;

		/* Length of the outer token */
		dataLen += 1 + der_length_size(rspTokenSize);
	}
	if (mechListMIC != NULL) {

		/* Length of the inner token */
		micTokenSize = 1 + der_length_size(mechListMIC->length) +
		    mechListMIC->length;

		dataLen += micTokenSize;

		/* Length of the outer token */
		dataLen += 1 + der_length_size(micTokenSize);
	} else if (data != NULL && data->length > 0 && MS_Flag) {
		dataLen += rspTokenSize;
		dataLen += 1 + der_length_size(rspTokenSize);
	}

	/*
	 * Add size of DER encoded:
	 * NegTokenTarg [ SEQUENCE ] of
	 *    NegResult[0] ENUMERATED {
	 *	accept_completed(0),
	 *	accept_incomplete(1),
	 *	reject(2) }
	 *    supportedMech [1] MechType OPTIONAL,
	 *    responseToken [2] OCTET STRING OPTIONAL,
	 *    mechListMIC   [3] OCTET STRING OPTIONAL
	 *
	 * size = data->length + MechListMic + SupportedMech len +
	 *	Result Length + ASN.1 overhead
	 */
	NegTokenTargSize = dataLen;
	dataLen += 1 + der_length_size(NegTokenTargSize);

	/*
	 * NegotiationToken [ CHOICE ]{
	 *    negTokenInit  [0]	 NegTokenInit,
	 *    negTokenTarg  [1]	 NegTokenTarg }
	 */
	NegTokenSize = dataLen;
	dataLen += 1 + der_length_size(NegTokenSize);

	tlen = dataLen;
	t = (unsigned char *) malloc(tlen);

	if (t == NULL) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto errout;
	}

	ptr = t;

	if (sendtoken == INIT_TOKEN_SEND ||
	    sendtoken == ERROR_TOKEN_SEND) {
		/*
		 * Indicate that we are sending CHOICE 1
		 * (NegTokenTarg)
		 */
		*ptr++ = CONTEXT | 0x01;
		if ((ret = put_der_length(NegTokenSize, &ptr, dataLen))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}

		*ptr++ = SEQUENCE;
		if ((ret = put_der_length(NegTokenTargSize, &ptr,
		    tlen - (int)(ptr-t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}

		/*
		 * First field of the NegTokenTarg SEQUENCE
		 * is the ENUMERATED NegResult.
		 */
		*ptr++ = CONTEXT;
		if ((ret = put_der_length(3, &ptr,
		    tlen - (int)(ptr-t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
		if ((ret = put_negResult(&ptr, status,
		    tlen - (int)(ptr - t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}

		if (sendtoken != ERROR_TOKEN_SEND && mech_wanted != NULL) {
			/*
			 * Next, is the Supported MechType
			 */
			*ptr++ = CONTEXT | 0x01;
			if ((ret = put_der_length(mech_wanted->length + 2,
			    &ptr, tlen - (int)(ptr - t)))) {
				ret = GSS_S_DEFECTIVE_TOKEN;
				goto errout;
			}
			if ((ret = put_mech_oid(&ptr, mech_wanted,
			    tlen - (int)(ptr - t)))) {
				ret = GSS_S_DEFECTIVE_TOKEN;
				goto errout;
			}
		}
	}

	if (data != NULL && data->length > 0) {
		*ptr++ = CONTEXT | 0x02;
		if ((ret = put_der_length(rspTokenSize, &ptr,
		    tlen - (int)(ptr - t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
		if ((ret = put_input_token(&ptr, data,
		    tlen - (int)(ptr - t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
	}
	if (mechListMIC != NULL) {
		*ptr++ = CONTEXT | 0x03;
		if ((ret = put_der_length(micTokenSize, &ptr,
		    tlen - (int)(ptr - t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
		if ((ret = put_input_token(&ptr, mechListMIC,
		    tlen - (int)(ptr - t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
	} else if (data != NULL && data->length > 0 && MS_Flag) {
		*ptr++ = CONTEXT | 0x03;
		if ((ret = put_der_length(rspTokenSize, &ptr,
		    tlen - (int)(ptr - t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
			goto errout;
		}
		if ((ret = put_input_token(&ptr, data,
		    tlen - (int)(ptr - t)))) {
			ret = GSS_S_DEFECTIVE_TOKEN;
		}
	}
errout:
	if (ret != 0) {
		if (t)
			free(t);
	} else {
		outbuf->length = ptr - t;
		outbuf->value = (void *) t;
	}

	return (ret);
}

/* determine size of token */
static int
g_token_size(gss_OID mech, unsigned int body_size)
{
	int hdrsize;

	/*
	 * Initialize the header size to the
	 * MECH_OID byte + the bytes needed to indicate the
	 * length of the OID + the OID itself.
	 *
	 * 0x06 [MECHLENFIELD] MECHDATA
	 */
	hdrsize = 1 + der_length_size(mech->length) + mech->length;

	/*
	 * Now add the bytes needed for the initial header
	 * token bytes:
	 * 0x60 + [DER_LEN] + HDRSIZE
	 */
	hdrsize += 1 + der_length_size(body_size + hdrsize);

	return (hdrsize + body_size);
}

/*
 * generate token header.
 *
 * Use DER Definite Length method per RFC2478
 * Use of indefinite length encoding will not be compatible
 * with Microsoft or others that actually follow the spec.
 */
static int
g_make_token_header(gss_OID mech,
	int body_size,
	unsigned char **buf,
	int totallen)
{
	int hdrsize, ret = 0;
	unsigned char *p = *buf;

	hdrsize = 1 + der_length_size(mech->length) + mech->length;

	*(*buf)++ = HEADER_ID;
	if ((ret = put_der_length(hdrsize + body_size, buf, totallen)))
		return (ret);

	*(*buf)++ = MECH_OID;
	if ((ret = put_der_length(mech->length, buf,
	    totallen - (int)(p - *buf))))
		return (ret);
	TWRITE_STR(*buf, mech->elements, ((int)mech->length));
	return (0);
}

static int
g_get_tag_and_length(unsigned char **buf, uchar_t tag, int buflen, int *outlen)
{
	unsigned char *ptr = *buf;
	int ret = -1; /* pessimists, assume failure ! */
	OM_uint32 encoded_len;

	if (buflen > 0 && *ptr == tag) {
		ptr++;
		*outlen = get_der_length(&ptr, buflen, &encoded_len);
		if (*outlen < 0)
			ret = *outlen;
		if ((ptr + *outlen) > (*buf + buflen))
			ret = -1;
		else
			ret = 0;
	}

	*buf = ptr;
	return (ret);
}

static int
g_verify_neg_token_init(unsigned char **buf_in, int cur_size)
{
	unsigned char *buf = *buf_in;
	unsigned char *endptr = buf + cur_size;
	int seqsize;
	int ret = 0;
	unsigned int bytes;

	/*
	 * Verify this is a NegotiationToken type token
	 * - check for a0(context specific identifier)
	 * - get length and verify that enoughd ata exists
	 */
	if (g_get_tag_and_length(&buf, CONTEXT, cur_size, &seqsize) < 0)
		return (G_BAD_TOK_HEADER);

	cur_size = seqsize; /* should indicate bytes remaining */

	/*
	 * Verify the next piece, it should identify this as
	 * a strucure of type NegTokenInit.
	 */
	if (*buf++ == SEQUENCE) {
		if ((seqsize = get_der_length(&buf, cur_size, &bytes)) < 0)
			return (G_BAD_TOK_HEADER);
		/*
		 * Make sure we have the entire buffer as described
		 */
		if (buf + seqsize > endptr)
			return (G_BAD_TOK_HEADER);
	} else {
		return (G_BAD_TOK_HEADER);
	}

	cur_size = seqsize; /* should indicate bytes remaining */

	/*
	 * Verify that the first blob is a sequence of mechTypes
	 */
	if (*buf++ == CONTEXT) {
		if ((seqsize = get_der_length(&buf, cur_size, &bytes)) < 0)
			return (G_BAD_TOK_HEADER);
		/*
		 * Make sure we have the entire buffer as described
		 */
		if (buf + bytes > endptr)
			return (G_BAD_TOK_HEADER);
	} else {
		return (G_BAD_TOK_HEADER);
	}

	/*
	 * At this point, *buf should be at the beginning of the
	 * DER encoded list of mech types that are to be negotiated.
	 */
	*buf_in = buf;

	return (ret);

}

/* verify token header. */
static int
g_verify_token_header(gss_OID mech,
	int *body_size,
	unsigned char **buf_in,
	int tok_type,
	int toksize)
{
	unsigned char *buf = *buf_in;
	int seqsize;
	gss_OID_desc toid;
	int ret = 0;
	unsigned int bytes;

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);

	if (*buf++ != HEADER_ID)
		return (G_BAD_TOK_HEADER);

	if ((seqsize = get_der_length(&buf, toksize, &bytes)) < 0)
		return (G_BAD_TOK_HEADER);

	if ((seqsize + bytes) != toksize)
		return (G_BAD_TOK_HEADER);

	if ((toksize -= 1) < 0)
		return (G_BAD_TOK_HEADER);


	if (*buf++ != MECH_OID)
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

	if (!ret) {
		*buf_in = buf;
		*body_size = toksize;
	}

	return (ret);
}

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
 *	MICwrap.c
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>
#include "dh_gssapi.h"
#include "crypto.h"

/*
 * This module implements the GSS-API entry points gss_sign,
 * gss_verify, gss_seal, and gss_unseal.
 */

/*
 * __dh_gss_sign: Sign (Caluculate a check sum as specified by the qop
 * and encrypt it with a cipher also determined by the qop using the context
 * session keys). the message with the given qop and return
 * a Diffie-Hellman DH_MIC token pointed to by token.
 */

OM_uint32
__dh_gss_sign(void *ctx, /* Per mechanism context (not used) */
	    OM_uint32 *minor, /* Mechanism status */
	    gss_ctx_id_t context, /* GSS context */
	    int qop_req, /* Requested qop */
	    gss_buffer_t message, /* Input message */
	    gss_buffer_t token /* output token */)
{
_NOTE(ARGUNUSED(ctx))
	/* context is a Diffie-Hellman context */
	dh_gss_context_t cntx = (dh_gss_context_t)context;
	dh_token_desc tok;
	/* grap a pointer to the mic part of the token */
	dh_mic_t mic = &tok.ver.dh_version_u.body.dh_token_body_desc_u.sign;
	dh_key_set keys;

	/*
	 * Make sure we can return the mechanism status an the token
	 * containning the MIC
	 */
	if (minor == 0 || token == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Make sure the context is valid */
	if ((*minor = __dh_validate_context(cntx)) != DH_SUCCESS)
		return (GSS_S_NO_CONTEXT);

	/* that it is established, */
	if (cntx->state != ESTABLISHED)
		return (GSS_S_NO_CONTEXT);

	/* and that it has not expired */
	if (cntx->expire != GSS_C_INDEFINITE && cntx->expire < time(0))
		return (GSS_S_CONTEXT_EXPIRED);

	/* Package the context session keys in a key_set for __make_token */
	keys.dh_key_set_len = cntx->no_keys;
	keys.dh_key_set_val = cntx->keys;

	/* Set the token version number and type */
	tok.ver.verno = cntx->proto_version;
	tok.ver.dh_version_u.body.type = DH_MIC;

	/* Set the token qop, seq_number and client flag */
	mic->qop = qop_req;

	mic->seqnum = __dh_next_seqno(cntx);

	mic->client_flag = cntx->initiate;

	/*
	 * Build the the output token from the message the diffie-hellman
	 * non serialized tok and the context keys.
	 */
	if ((*minor = __make_token(token, message, &tok, &keys))
	    != DH_SUCCESS) {
		return (GSS_S_FAILURE);
	}

	return (GSS_S_COMPLETE);
}


/*
 * __dh_gss_verify: calculate the signature of the message and compare
 * it to the signature represented by the DH_MIC token supplied. If the
 * major return value is GSS_S_COMPLETE, then *qop will be the qop that
 * was used in token.
 */

OM_uint32
__dh_gss_verify(void *ctx, /* Per mechanism context (not used) */
		OM_uint32 *minor, /* Mechanism status */
		gss_ctx_id_t context, /* GSS context */
		gss_buffer_t message, /* The message */
		gss_buffer_t token, /* The DH_MIC message token */
		int *qop /* qop used */)
{
_NOTE(ARGUNUSED(ctx))
	/* context is a Diffie-Hellman context */
	dh_gss_context_t cntx = (dh_gss_context_t)context;
	dh_token_desc tok;
	/* Grab the mic of the token */
	dh_mic_t mic = &tok.ver.dh_version_u.body.dh_token_body_desc_u.sign;
	dh_key_set keys;
	OM_uint32 stat;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Validate the context */
	if ((*minor = __dh_validate_context(cntx)) != DH_SUCCESS)
		return (GSS_S_NO_CONTEXT);

	/* Check that the context is established */
	if (cntx->state != ESTABLISHED)
		return (GSS_S_NO_CONTEXT);

	/* and that it has not expired */
	if (cntx->expire != GSS_C_INDEFINITE && cntx->expire < time(0))
		return (GSS_S_CONTEXT_EXPIRED);

	/* Package up the context session keys in to a key set */
	keys.dh_key_set_len = cntx->no_keys;
	keys.dh_key_set_val = cntx->keys;

	/* Deserialize token into tok using messaget and keys */
	if ((*minor = __get_token(token, message,
				&tok, &keys)) != DH_SUCCESS) {
		switch (*minor) {
		case DH_DECODE_FAILURE:
			return (GSS_S_DEFECTIVE_TOKEN);
		case DH_VERIFIER_MISMATCH:
			return (GSS_S_BAD_SIG);
		default:
			return (GSS_S_FAILURE);
		}
	}

	/* Check that the tok version is supported */
	if (tok.ver.verno != cntx->proto_version ||
	    tok.ver.dh_version_u.body.type != DH_MIC) {
		xdr_free(xdr_dh_token_desc, (char *)&tok);
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	/* Set the return qop */
	if (qop != NULL)
		*qop = mic->qop;

	/* Sequence & Replay detection here */
	stat = __dh_seq_detection(cntx, mic->seqnum);

	/* free the deserialize token tok */
	xdr_free(xdr_dh_token_desc, (char *)&tok);

	/*
	 * If client flag is the same as the initiator flag, we're talking
	 * to our selves or we're being spoofed. We return
	 * GSS_S_DUPLICATE_TOKEN since its the best return code in the
	 * supplementry group.
	 */

	if (mic->client_flag == cntx->initiate)
		stat |= GSS_S_DUPLICATE_TOKEN;

	return (stat);
}


/*
 * __dh_gss_seal: Seal a message, i.e, it wraps or embeds a supplied message
 * in a DH_WRAP token to be delivered to the other side. A message check
 * over the whole message is include and is selected base on the supplied
 * qop. If the qop supports privacy and confidentiality was requested, then
 * the embedded message will be encrypted. A return flag will be set if
 * the message was encrypted.
 *
 * NOTE: IN THE CURRENT PRODUCT NO QOP CAN SUPPORT PRIVACY. THE *conf_state
 * FLAG WILL ALWAYS BE ZERO.
 */

OM_uint32
__dh_gss_seal(void * ctx, /* Per mechanism context */
	    OM_uint32 *minor, /* Mechanism status */
	    gss_ctx_id_t context, /* GSS context */
	    int conf_req, /* True to request privacy */
	    int qop_req, /* Use the requested qop */
	    gss_buffer_t input, /* Input message to wrap */
	    int *conf_state, /* True if message was encrypted */
	    gss_buffer_t output /* Contains the ouputed DH_WRAP token*/)
{
_NOTE(ARGUNUSED(ctx))
	/* context is a Diffie-Hellman context */
	dh_gss_context_t cntx = (dh_gss_context_t)context;
	dh_token_desc tok;
	/* Get a pointer to the wrap protion of the token */
	dh_wrap_t wrap = &tok.ver.dh_version_u.body.dh_token_body_desc_u.seal;
	dh_key_set keys;
	gss_buffer_desc body;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* See if the context is valid */
	if ((*minor = __dh_validate_context(cntx)) != DH_SUCCESS)
		return (GSS_S_NO_CONTEXT);

	/* that it is established, */
	if (cntx->state != ESTABLISHED)
		return (GSS_S_NO_CONTEXT);

	/* and that it has not expired */
	if (cntx->expire != GSS_C_INDEFINITE && cntx->expire < time(0))
		return (GSS_S_CONTEXT_EXPIRED);

	/* Package the session keys in a key_set */
	keys.dh_key_set_len = cntx->no_keys;
	keys.dh_key_set_val = cntx->keys;

	/* Set the version and token type */
	tok.ver.verno = cntx->proto_version;
	tok.ver.dh_version_u.body.type = DH_WRAP;

	/* Set the qop, initiate flag, and sequence number */
	wrap->mic.qop = qop_req;
	wrap->mic.client_flag = cntx->initiate;
	wrap->mic.seqnum = __dh_next_seqno(cntx);

	/*
	 * Wrap the supplied message and encrypted if it is requested
	 * and allowed. The qop will have to have an associated cipher
	 * routine. NOTE: BECAUSE OF EXPORT CONTROLS, THE MECHANISM
	 * CURRENTLY WILL NOT DO ENCRYPTION AND conf_stat WILL ALWAY BE SET
	 * TO FALSE.
	 */
	if ((*minor = __QOPSeal(wrap->mic.qop, input, conf_req,
				&keys, &body, conf_state)) != DH_SUCCESS) {
		__free_signature(&tok.verifier);
		return (GSS_S_FAILURE);
	}

	/* The body now contains the wrapped orignal message */
	wrap->body.body_len = body.length;
	wrap->body.body_val = (char *)body.value;

	/*
	 * Tell the other side if encrypted.
	 * SEE NOTE ABOVE. THIS WILL ALWAYS BE FALSE.
	 */
	if (conf_state)
		wrap->conf_flag = *conf_state;
	else
		wrap->conf_flag = FALSE;

	/* Serialize the token tok into output using the session keys */
	if ((*minor = __make_token(output, NULL, &tok, &keys)) != DH_SUCCESS) {
		__dh_release_buffer(&body);
		return (GSS_S_FAILURE);
	}
	/* We're done with the wrapped body */
	__dh_release_buffer(&body);

	return (GSS_S_COMPLETE);
}

/*
 * __dh_gss_unseal: Unwrap a supplied DH_WRAP token extracting the orginal
 * message, qop_used, and whether privacy was used.
 *
 * NOTE: BECAUSE OF EXPORT CONTROLS, NO QOP IN THE MECHANISM SUPPORTS
 * PRIVACY. *conf_state WILL ALWAY BE FALSE.
 */

OM_uint32
__dh_gss_unseal(void *ctx, /* Per mechanism context (not used) */
		OM_uint32 *minor, /* Mechanism status */
		gss_ctx_id_t context, /* GSS context handle */
		gss_buffer_t input, /* Wrapped Diffie-Hellman token */
		gss_buffer_t output, /* The unwrapped message */
		int *conf_state, /* True if the message was encrypted */
		int *qop_used /* QOP used in token */)
{
_NOTE(ARGUNUSED(ctx))
	/* context is a Diffie-Hellman context */
	dh_gss_context_t cntx = (dh_gss_context_t)context;
	dh_token_desc tok;
	/* Grap the wrap portion of the above token */
	dh_wrap_t wrap = &tok.ver.dh_version_u.body.dh_token_body_desc_u.seal;
	dh_key_set keys;
	gss_buffer_desc message;
	OM_uint32 stat;

	if (minor == 0 || conf_state == 0 || output == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Validate context, */
	if ((*minor = __dh_validate_context(cntx)) != DH_SUCCESS)
		return (GSS_S_NO_CONTEXT);

	/* check if it is established, */
	if (cntx->state != ESTABLISHED)
		return (GSS_S_NO_CONTEXT);

	/* and that it has not expired */
	if (cntx->expire != GSS_C_INDEFINITE && cntx->expire < time(0))
		return (GSS_S_CONTEXT_EXPIRED);

	/* Package up the session keys in to a key_set */
	keys.dh_key_set_len = cntx->no_keys;
	keys.dh_key_set_val = cntx->keys;

	/* Deserialize the input in to  tok using keys */
	if ((*minor = __get_token(input, NULL, &tok, &keys)) != DH_SUCCESS) {
		switch (*minor) {
		case DH_DECODE_FAILURE:
		case DH_UNKNOWN_QOP:
			return (GSS_S_DEFECTIVE_TOKEN);
		case DH_VERIFIER_MISMATCH:
			return (GSS_S_BAD_SIG);
		default:
			return (GSS_S_FAILURE);
		}
	}

	/* Set the qop_used and confidentiality state */
	if (qop_used != NULL)
		*qop_used = wrap->mic.qop;
	*conf_state = wrap->conf_flag;

	/* See if this is a version that we can support */
	if (tok.ver.verno != cntx->proto_version ||
	    tok.ver.dh_version_u.body.type != DH_WRAP) {
		xdr_free(xdr_dh_token_desc, (char *)&tok);
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	/* Put the unwrapped body in to a gss_buffer */
	message.length = wrap->body.body_len;
	message.value = wrap->body.body_val;

	/*
	 * Unwrap the message putting the result in output. We use the
	 * qop from the token, the session keys, and set *conf_state if
	 * encryption was used.
	 *
	 * NOTE: THIS MECHANISM DOES NOT SUPPORT ENCRYPTION. *conf_state
	 * WILL ALWAY BE FALSE.
	 */
	if ((*minor = __QOPUnSeal(wrap->mic.qop, &message,
				*conf_state, &keys, output))
	    != DH_SUCCESS) {
		xdr_free(xdr_dh_token_desc, (char *)&tok);
		return (*minor == DH_UNKNOWN_QOP ?
				GSS_S_DEFECTIVE_TOKEN : GSS_S_FAILURE);
	}

	/* Sequence & Replay detection here */
	stat = __dh_seq_detection(cntx, wrap->mic.seqnum);

	/*
	 * If client flag is the same as the initiator flag, we're talking
	 * to our selves or we're being spoofed. We return
	 * GSS_S_DUPLICATE_TOKEN since its the best return code in the
	 * supplementry group.
	 */

	if (wrap->mic.client_flag == cntx->initiate)
		stat |= GSS_S_DUPLICATE_TOKEN;

	/* Were done with the deserialize token, tok */
	xdr_free(xdr_dh_token_desc, (char *)&tok);

	return (stat);
}

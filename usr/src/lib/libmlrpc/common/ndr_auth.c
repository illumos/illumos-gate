/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Tintri by DDN, Inc. All Rights Reserved.
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <libmlrpc.h>
#include <sys/sysmacros.h>
#include <strings.h>

/*
 * Initializes the sec_trailer (ndr_sec_t).
 * The actual token is allocated and set later (in the SSP).
 */
int
ndr_add_auth_token(ndr_auth_ctx_t *ctx, ndr_xa_t *mxa)
{
	ndr_stream_t *nds = &mxa->send_nds;
	ndr_sec_t *secp = &mxa->send_auth;

	secp->auth_type = ctx->auth_type;
	secp->auth_level = ctx->auth_level;
	secp->auth_rsvd = 0;

	/*
	 * [MS-RPCE] 2.2.2.12 "Authentication Tokens"
	 * auth_pad_len aligns the packet to 16 bytes.
	 */
	secp->auth_pad_len = P2ROUNDUP(nds->pdu_scan_offset, 16) -
	    nds->pdu_scan_offset;
	if (NDS_PAD_PDU(nds, nds->pdu_scan_offset,
	    secp->auth_pad_len, NULL) == 0)
		return (NDR_DRC_FAULT_SEC_ENCODE_TOO_BIG);

	/* PAD_PDU doesn't adjust scan_offset */
	nds->pdu_scan_offset += secp->auth_pad_len;
	nds->pdu_body_size = nds->pdu_scan_offset -
	    nds->pdu_body_offset;

	secp->auth_context_id = ctx->auth_context_id;
	return (NDR_DRC_OK);
}

/*
 * Does gss_init_sec_context (or equivalent) and creates
 * the sec_trailer and the auth token.
 *
 * Used during binds (and alter context).
 *
 * Currently, only NETLOGON auth with Integrity/Privacy protection
 * is implemented.
 */
int
ndr_add_sec_context(ndr_auth_ctx_t *ctx, ndr_xa_t *mxa)
{
	int rc;

	if (ctx->auth_level == NDR_C_AUTHN_NONE ||
	    ctx->auth_type == NDR_C_AUTHN_NONE)
		return (NDR_DRC_OK);

	if (ctx->auth_type != NDR_C_AUTHN_GSS_NETLOGON)
		return (NDR_DRC_FAULT_SEC_TYPE_UNIMPLEMENTED);

	if (ctx->auth_level != NDR_C_AUTHN_LEVEL_PKT_INTEGRITY &&
	    ctx->auth_level != NDR_C_AUTHN_LEVEL_PKT_PRIVACY)
		return (NDR_DRC_FAULT_SEC_LEVEL_UNIMPLEMENTED);

	if ((rc = ndr_add_auth_token(ctx, mxa)) != 0)
		return (rc);

	return (ctx->auth_ops.nao_init(ctx->auth_ctx, mxa));
}

/*
 * Does response-side gss_init_sec_context (or equivalent) and validates
 * the sec_trailer and the auth token.
 *
 * Used during bind (and alter context) ACKs.
 */
int
ndr_recv_sec_context(ndr_auth_ctx_t *ctx, ndr_xa_t *mxa)
{
	ndr_sec_t *bind_secp = &mxa->send_auth;
	ndr_sec_t *ack_secp = &mxa->recv_auth;

	if (ctx->auth_level == NDR_C_AUTHN_NONE ||
	    ctx->auth_type == NDR_C_AUTHN_NONE) {
		if (mxa->recv_hdr.common_hdr.auth_length != 0)
			return (NDR_DRC_FAULT_SEC_AUTH_LENGTH_INVALID);
		return (NDR_DRC_OK);
	} else if (mxa->recv_hdr.common_hdr.auth_length == 0) {
		return (NDR_DRC_FAULT_SEC_AUTH_LENGTH_INVALID);
	}

	if (bind_secp->auth_type != ack_secp->auth_type)
		return (NDR_DRC_FAULT_SEC_AUTH_TYPE_INVALID);
	if (bind_secp->auth_level != ack_secp->auth_level)
		return (NDR_DRC_FAULT_SEC_AUTH_LEVEL_INVALID);

	return (ctx->auth_ops.nao_recv(ctx->auth_ctx, mxa));
}

/*
 * Does gss_MICEx (or equivalent) and creates
 * the sec_trailer and the auth token.
 *
 * Used upon sending a request (client)/response (server) packet.
 */
int
ndr_add_auth(ndr_auth_ctx_t *ctx, ndr_xa_t *mxa)
{
	int rc;

	if (ctx->auth_level == NDR_C_AUTHN_NONE ||
	    ctx->auth_type == NDR_C_AUTHN_NONE)
		return (NDR_DRC_OK);

	if (ctx->auth_type != NDR_C_AUTHN_GSS_NETLOGON)
		return (NDR_DRC_FAULT_SEC_TYPE_UNIMPLEMENTED);

	if (ctx->auth_level != NDR_C_AUTHN_LEVEL_PKT_INTEGRITY &&
	    ctx->auth_level != NDR_C_AUTHN_LEVEL_PKT_PRIVACY)
		return (NDR_DRC_FAULT_SEC_LEVEL_UNIMPLEMENTED);

	if ((rc = ndr_add_auth_token(ctx, mxa)) != 0)
		return (rc);

	if (ctx->auth_level == NDR_C_AUTHN_LEVEL_PKT_PRIVACY)
		return (ctx->auth_ops.nao_encrypt(ctx->auth_ctx, mxa));
	return (ctx->auth_ops.nao_sign(ctx->auth_ctx, mxa));
}

/*
 * Does gss_VerifyMICEx (or equivalent) and validates
 * the sec_trailer and the auth token.
 *
 * Used upon receiving a request (server)/response (client) packet.
 *
 * If auth_verify_resp is B_FALSE, this doesn't verify responses (but
 * the SSP may still have side-effects).
 */
int
ndr_check_auth(ndr_auth_ctx_t *ctx, ndr_xa_t *mxa)
{
	ndr_sec_t *secp = &mxa->recv_auth;

	if (ctx->auth_level == NDR_C_AUTHN_NONE ||
	    ctx->auth_type == NDR_C_AUTHN_NONE) {
		if (mxa->recv_hdr.common_hdr.auth_length != 0)
			return (NDR_DRC_FAULT_SEC_AUTH_LENGTH_INVALID);
		return (NDR_DRC_OK);
	} else if (mxa->recv_hdr.common_hdr.auth_length == 0) {
		return (NDR_DRC_FAULT_SEC_AUTH_LENGTH_INVALID);
	}

	if (ctx->auth_type != secp->auth_type ||
	    ctx->auth_type != NDR_C_AUTHN_GSS_NETLOGON)
		return (NDR_DRC_FAULT_SEC_AUTH_TYPE_INVALID);

	if (ctx->auth_level != secp->auth_level ||
	    (ctx->auth_level != NDR_C_AUTHN_LEVEL_PKT_INTEGRITY &&
	    ctx->auth_level != NDR_C_AUTHN_LEVEL_PKT_PRIVACY))
		return (NDR_DRC_FAULT_SEC_AUTH_LEVEL_INVALID);

	if (ctx->auth_level == NDR_C_AUTHN_LEVEL_PKT_PRIVACY)
		return (ctx->auth_ops.nao_decrypt(ctx->auth_ctx, mxa,
		    ctx->auth_verify_resp));
	return (ctx->auth_ops.nao_verify(ctx->auth_ctx, mxa,
	    ctx->auth_verify_resp));
}

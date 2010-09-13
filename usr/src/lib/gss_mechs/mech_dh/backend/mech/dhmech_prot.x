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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Diffie-Hellman GSS protocol descriptions
 */

#ifdef RPC_HDR
%/*
% *  dhmech_prot.h
% *
% * Copyright (c) 1997, by Sun Microsystems, Inc.
% * All rights reserved.
% *
% * Diffie-Hellman GSS protocol descriptions
% */
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%#include <rpc/key_prot.h>
#endif

/* Token types */

enum dh_token_type {
	DH_INIT_CNTX = 1,
	DH_ACCEPT_CNTX = 2,
	DH_MIC = 3,
	DH_WRAP = 4,
	DH_DESTROY_CNTX = 5
};

const DH_MAX_CHECKSUM_SIZE = 128;
const DH_PROTO_VERSION = 1;
const DH_MAX_SESSION_KEYS = 64;

typedef opaque dh_buffer_desc<>;
typedef dh_buffer_desc *dh_buffer_t;
typedef opaque dh_signature<DH_MAX_CHECKSUM_SIZE>; /* Encrypted checksum */
typedef dh_signature *dh_signature_t;
typedef des_block dh_key_set<DH_MAX_SESSION_KEYS>;
typedef dh_key_set *dh_key_set_t;
typedef unsigned int dh_qop_t;

struct dh_channel_binding_desc {
	unsigned initiator_addrtype;
	dh_buffer_desc initiator_address;
	unsigned acceptor_addrtype;
	dh_buffer_desc acceptor_address;
	dh_buffer_desc application_data;
};
typedef dh_channel_binding_desc *dh_channel_binding_t;

struct dh_cntx_desc {
	netnamestr remote;
	netnamestr local;
	unsigned flags;		/* Supported flag values from
				 * gss_init_sec_context/gss_accept_sec_context
				 */
	unsigned expire;
	dh_channel_binding_t channel;
};
typedef dh_cntx_desc *dh_cntx_t;

struct dh_init_context_desc {
	dh_cntx_desc	cntx;
	dh_key_set keys;	/* Session keys encrypted
				 * with the common key
				 */
};
typedef dh_init_context_desc *dh_init_context_t;

struct dh_accept_context_desc {
	dh_cntx_desc cntx;
};
typedef dh_accept_context_desc *dh_accept_context_t;

struct dh_mic_desc {
	dh_qop_t qop;
	unsigned seqnum;
	bool client_flag;	/* True if from  client (context initator). */
};
typedef dh_mic_desc *dh_mic_t;

struct dh_wrap_desc {
	dh_mic_desc mic;
	bool conf_flag;
	opaque body<>;		/*
				 * If conf_flag, then body is an encrypted
				 * serialize opaque msg<>
				 */
};
typedef dh_wrap_desc *dh_wrap_t;

union dh_token_body_desc switch (dh_token_type type) {
	case DH_INIT_CNTX:
		dh_init_context_desc init_context;
	case DH_ACCEPT_CNTX:
		dh_accept_context_desc accept_context;
	case DH_MIC:
		dh_mic_desc sign;
	case DH_WRAP:
		dh_wrap_desc seal;
	case DH_DESTROY_CNTX:
		void;
};
typedef dh_token_body_desc *dh_token_body_t;

/*
 * We define a discriminated union to handle different versions of the
 * protocal. We will always have a verifier follow this versioned body
 * as the last member of the token.
 *
 * Currently there is only one version, DH_PROTO_VERSION (1).
 */
union dh_version switch (unsigned verno) {
	case DH_PROTO_VERSION:
		dh_token_body_desc body;
};

/*
 * Note: All versions of the Diffie-Hellman protocol will provide a
 * verifier as the last part of a token. In this way we will always
 * be able to calucate the signature over the entire versioned body of the
 * the token.
 */

struct dh_token_desc {
	dh_version ver;
	dh_signature verifier;
};
typedef dh_token_desc *dh_token_t;

/*
 * The token return from gss_init_sec_context will be as follows:
 *
 *	0x60	tag for APPLICATION 0, SEQUENCE  (constructed, definite length)
 * 	<length>  DER encoded
 *	0x06	tag for OID, the mech type.
 *	<mech type> DER encoded
 *	token_desc   XDR encoded
 */

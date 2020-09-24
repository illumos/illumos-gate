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
 */

#include <sys/md5.h>
#include <strings.h>
#include <stdio.h>
#include <smbsrv/netrauth.h>
#include <smbsrv/string.h>
#include <smbsrv/libsmb.h>
#include <libmlsvc.h>
#include <resolv.h>

/*
 * NETLOGON SSP for "Secure RPC" works as follows:
 * 1. The client binds to the DC without RPC-level authentication.
 * 2. The client and server negotiate a Session Key using a client
 * and server challenge, plus a shared secret (the machine password).
 * This happens via NetrServerReqChallenge and NetrServerAuthenticate.
 * The key is bound to a particular Computer/Server Name pair.
 * 3. The client then establishes a new bind (or alters its existing one),
 * this time requesting the NETLOGON provider for RPC-level authentication.
 * The server uses the Computer and Domain names provided in the
 * authentication token in the bind request in order to find
 * the previously-negotiated Session Key (and rejects the bind if none
 * exists).
 * 4. The client and server then use this Session Key to provide
 * integrity and/or confidentiality to future NETLOGON RPC messages.
 *
 * The functions in this file implement the NETLOGON SSP, as defined in
 * [MS-NRPC] 3.3 "Netlogon as a Security Support Provider".
 *
 * Session Key negotiation is implemented in netr_auth.c.
 * It is the same key that is used for generating NETLOGON credentials.
 */

enum nl_token_type {
	NL_AUTH_REQUEST = 0x00000000,
	NL_AUTH_RESPONSE = 0x00000001
};

/*
 * DOMAIN = domain name
 * COMPUTER = client computer name
 * HOST = client host name
 *
 * NB = NetBios format
 * DNS = FQDN
 *
 * OEM = OEM_STRING
 * COMPRESSED = Compressed UTF-8 string
 *
 * Each of these is NULL-terminated, and delinated by such.
 * They are always found in this order, when specified.
 *
 * We currently use everything but NL_HOST_DNS_COMPRESSED_FLAG.
 */
#define	NL_DOMAIN_NB_OEM_FLAG		0x00000001
#define	NL_COMPUTER_NB_OEM_FLAG		0x00000002
#define	NL_DOMAIN_DNS_COMPRESSED_FLAG	0x00000004
#define	NL_HOST_DNS_COMPRESSED_FLAG	0x00000008
#define	NL_COMPUTER_NB_COMPRESSED_FLAG	0x00000010

#define	NL_DOMAIN_FLAGS			\
	(NL_DOMAIN_NB_OEM_FLAG|NL_DOMAIN_DNS_COMPRESSED_FLAG)
#define	NL_COMPUTER_FLAGS		\
	(NL_COMPUTER_NB_OEM_FLAG|		\
	NL_HOST_DNS_COMPRESSED_FLAG|		\
	NL_COMPUTER_NB_COMPRESSED_FLAG)

#define	MD_DIGEST_LEN 16

/* These structures are OPAQUE at the RPC level - not marshalled. */
typedef struct nl_auth_message {
	uint32_t nam_type;
	uint32_t nam_flags;
	uchar_t nam_str[1];
} nl_auth_message_t;

/*
 * The size of this structure is used for space accounting.
 * The confounder is not present on the wire unless confidentiality
 * has been negotiated. If we ever support confidentiality,
 * we'll need to adjust space accounting based on whether
 * the confounder is needed.
 */
typedef struct nl_auth_sig {
	uint16_t nas_sig_alg;
	uint16_t nas_seal_alg;
	uint16_t nas_pad;
	uint16_t nas_flags;
	uchar_t nas_seqnum[8];
	uchar_t nas_sig[8];
	/* uchar_t nas_confounder[8]; */ /* only for encryption */
} nl_auth_sig_t;

void
netr_show_msg(nl_auth_message_t *nam, ndr_stream_t *nds)
{
	ndo_printf(nds, NULL, "nl_auth_message: type=0x%x flags=0x%x");
}

void
netr_show_sig(nl_auth_sig_t *nas, ndr_stream_t *nds)
{
	ndo_printf(nds, NULL, "nl_auth_sig: SignatureAlg=0x%x SealAlg=0x%x "
	    "pad=0x%x flags=0x%x SequenceNumber=%llu Signature=0x%x",
	    nas->nas_sig_alg, nas->nas_seal_alg, nas->nas_pad,
	    nas->nas_flags, *(uint64_t *)nas->nas_seqnum,
	    *(uint64_t *)nas->nas_sig);
}

/*
 * NETLOGON SSP gss_init_sec_context equivalent
 * [MS-RPCE] 3.3.4.1.1 "Generating an Initial NL_AUTH_MESSAGE"
 *
 * We need to encode at least one Computer name and at least one
 * Domain name. The server uses this to find the Session Key
 * negotiated earlier between this client and server.
 *
 * We attempt to provide NL_DOMAIN_NB_OEM_FLAG, NL_COMPUTER_NB_OEM_FLAG,
 * NL_DOMAIN_DNS_COMPRESSED_FLAG, and NL_COMPUTER_NB_COMPRESSED_FLAG.
 *
 * See the above comments for how these are encoded.
 */
int
netr_ssp_init(void *arg, ndr_xa_t *mxa)
{
	netr_info_t *auth = arg;
	ndr_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	nl_auth_message_t *nam;
	size_t domain_len, comp_len, len;
	int slen;
	uchar_t *dnptrs[3], **dnlastptr;

	domain_len = smb_sbequiv_strlen(auth->nb_domain);
	comp_len = smb_sbequiv_strlen(auth->hostname);

	/*
	 * Need to allocate length for two OEM_STRINGs + NULL bytes, plus space
	 * sufficient for two NULL-terminated compressed UTF-8 strings.
	 * For the UTF-8 strings, use 2*len as a heuristic.
	 */
	len = domain_len + 1 + comp_len + 1 +
	    strlen(auth->hostname) * 2 + strlen(auth->fqdn_domain) * 2;

	hdr->auth_length = 0;

	nam = NDR_MALLOC(mxa, len);
	if (nam == NULL)
		return (NDR_DRC_FAULT_SEC_OUT_OF_MEMORY);

	nam->nam_type = NL_AUTH_REQUEST;
	nam->nam_flags = 0;

	if (domain_len != -1) {
		slen = smb_mbstooem(nam->nam_str, auth->nb_domain, domain_len);
		if (slen >= 0) {
			hdr->auth_length += slen + 1;
			nam->nam_str[hdr->auth_length - 1] = '\0';
			nam->nam_flags |= NL_DOMAIN_NB_OEM_FLAG;
		}
	}

	if (comp_len != -1) {
		slen = smb_mbstooem(nam->nam_str + hdr->auth_length,
		    auth->hostname, comp_len);
		if (slen >= 0) {
			hdr->auth_length += slen + 1;
			nam->nam_str[hdr->auth_length - 1] = '\0';
			nam->nam_flags |= NL_COMPUTER_NB_OEM_FLAG;
		}
	}

	dnptrs[0] = NULL;
	dnlastptr = &dnptrs[sizeof (dnptrs) / sizeof (dnptrs[0])];

	slen = dn_comp(auth->fqdn_domain, nam->nam_str + hdr->auth_length,
	    len - hdr->auth_length, dnptrs, dnlastptr);

	if (slen >= 0) {
		hdr->auth_length += slen;
		nam->nam_str[hdr->auth_length] = '\0';
		nam->nam_flags |= NL_DOMAIN_DNS_COMPRESSED_FLAG;
	}

	slen = dn_comp(auth->hostname, nam->nam_str + hdr->auth_length,
	    len - hdr->auth_length, dnptrs, dnlastptr);
	if (slen >= 0) {
		hdr->auth_length += slen;
		nam->nam_str[hdr->auth_length] = '\0';
		nam->nam_flags |= NL_COMPUTER_NB_COMPRESSED_FLAG;
	}

	/* We must provide at least one Domain Name and Computer Name */
	if ((nam->nam_flags & NL_DOMAIN_FLAGS) == 0 ||
	    (nam->nam_flags & NL_COMPUTER_FLAGS) == 0)
		return (NDR_DRC_FAULT_SEC_ENCODE_FAILED);

	mxa->send_auth.auth_value = (void *)nam;
	hdr->auth_length += sizeof (nam->nam_flags) + sizeof (nam->nam_type);

	return (0);
}

/*
 * NETLOGON SSP response-side gss_init_sec_context equivalent
 * [MS-RPCE] 3.3.4.1.4 "Receiving a Return NL_AUTH_MESSAGE"
 */
int
netr_ssp_recv(void *arg, ndr_xa_t *mxa)
{
	netr_info_t *auth = arg;
	ndr_common_header_t *ahdr = &mxa->recv_hdr.common_hdr;
	ndr_sec_t *ack_secp = &mxa->recv_auth;
	nl_auth_message_t *nam;
	int rc;

	nam = (nl_auth_message_t *)ack_secp->auth_value;

	/* We only need to verify the length ("at least 12") and the type */
	if (ahdr->auth_length < 12) {
		rc = NDR_DRC_FAULT_SEC_AUTH_LENGTH_INVALID;
		goto errout;
	}
	if (nam->nam_type != NL_AUTH_RESPONSE) {
		rc = NDR_DRC_FAULT_SEC_META_INVALID;
		goto errout;
	}
	auth->clh_seqnum = 0;

	return (NDR_DRC_OK);

errout:
	netr_show_msg(nam, &mxa->recv_nds);
	return (rc);
}

/* returns byte N of seqnum */
#define	CLS_BYTE(n, seqnum) ((seqnum >> (8 * (n))) & 0xff)

/*
 * NETLOGON SSP gss_MICEx equivalent
 * [MS-RPCE] 3.3.4.2.1 "Generating a Client Netlogon Signature Token"
 *
 * Set up the metadata, encrypt and increment the SequenceNumber,
 * and sign the PDU body.
 */
int
netr_ssp_sign(void *arg, ndr_xa_t *mxa)
{
	uint32_t zeroes = 0;
	netr_info_t *auth = arg;
	ndr_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	ndr_stream_t *nds = &mxa->send_nds;
	nl_auth_sig_t *nas;
	MD5_CTX md5h;
	BYTE local_sig[MD_DIGEST_LEN];
	BYTE enc_key[MD_DIGEST_LEN];

	hdr->auth_length = sizeof (nl_auth_sig_t);

	nas = NDR_MALLOC(mxa, hdr->auth_length);
	if (nas == NULL)
		return (NDR_DRC_FAULT_SEC_OUT_OF_MEMORY);

	/*
	 * SignatureAlgorithm is first byte 0x77, second byte 00 for HMAC-MD5
	 * or 0x13, 0x00 for AES-HMAC-SHA256.
	 *
	 * SealAlgorithm is first byte 0x7A, second byte 00 for RC4
	 * or 0x1A, 0x00 for AES-CFB8, or 0xffff for No Sealing.
	 *
	 * Pad is always 0xffff, and flags is always 0x0000.
	 *
	 * SequenceNumber is a computed, encrypted, 64-bit number.
	 *
	 * Each of these is always encoded in little-endian order.
	 */
	nas->nas_sig_alg = 0x0077;
	nas->nas_seal_alg = 0xffff;
	nas->nas_pad = 0xffff;
	nas->nas_flags = 0;

	/*
	 * Calculate the SequenceNumber.
	 * Note that byte 4 gets modified, as per the spec -
	 * It's the only byte that is not just set to some other byte.
	 */
	nas->nas_seqnum[0] = CLS_BYTE(3, auth->clh_seqnum);
	nas->nas_seqnum[1] = CLS_BYTE(2, auth->clh_seqnum);
	nas->nas_seqnum[2] = CLS_BYTE(1, auth->clh_seqnum);
	nas->nas_seqnum[3] = CLS_BYTE(0, auth->clh_seqnum);
	nas->nas_seqnum[4] = CLS_BYTE(7, auth->clh_seqnum) | 0x80;
	nas->nas_seqnum[5] = CLS_BYTE(6, auth->clh_seqnum);
	nas->nas_seqnum[6] = CLS_BYTE(5, auth->clh_seqnum);
	nas->nas_seqnum[7] = CLS_BYTE(4, auth->clh_seqnum);

	auth->clh_seqnum++;

	/*
	 * The HMAC-MD5 signature is computed as follows:
	 * First 8 bytes of
	 * HMAC_MD5(
	 *	MD5(0x00000000 | sig_alg | seal_alg | pad | flags | PDU body),
	 *	session_key)
	 */
	MD5Init(&md5h);
	MD5Update(&md5h, (uchar_t *)&zeroes, 4);
	MD5Update(&md5h, (uchar_t *)nas, 8);
	MD5Update(&md5h,
	    (uchar_t *)nds->pdu_base_addr + nds->pdu_body_offset,
	    nds->pdu_body_size);

	MD5Final(local_sig, &md5h);
	if (smb_auth_hmac_md5(local_sig, sizeof (local_sig),
	    auth->session_key.key, auth->session_key.len,
	    local_sig) != 0)
		return (NDR_DRC_FAULT_SEC_SSP_FAILED);

	bcopy(local_sig, nas->nas_sig, 8);

	/*
	 * Encrypt the SequenceNumber.
	 * For RC4 Encryption, the EncryptionKey is computed as follows:
	 * HMAC_MD5(signature, HMAC_MD5(0x00000000, session_key))
	 */
	if (smb_auth_hmac_md5((uchar_t *)&zeroes, 4,
	    auth->session_key.key, auth->session_key.len,
	    enc_key) != 0)
		return (NDR_DRC_FAULT_SEC_SSP_FAILED);
	if (smb_auth_hmac_md5((uchar_t *)nas->nas_sig, sizeof (nas->nas_sig),
	    enc_key, sizeof (enc_key),
	    enc_key) != 0)
		return (NDR_DRC_FAULT_SEC_SSP_FAILED);

	if (smb_auth_RC4(nas->nas_seqnum, sizeof (nas->nas_seqnum),
	    enc_key, sizeof (enc_key),
	    nas->nas_seqnum, sizeof (nas->nas_seqnum)) != 0)
		return (NDR_DRC_FAULT_SEC_SSP_FAILED);

	mxa->send_auth.auth_value = (void *)nas;

	return (NDR_DRC_OK);
}

/*
 * NETLOGON SSP gss_VerifyMICEx equivalent
 * [MS-RPCE] 3.3.4.2.4 "Receiving a Server Netlogon Signature Token"
 *
 * Verify the metadata, decrypt, verify, and increment the SequenceNumber,
 * and validate the PDU body against the provided signature.
 */
int
netr_ssp_verify(void *arg, ndr_xa_t *mxa, boolean_t verify_resp)
{
	uint32_t zeroes = 0;
	netr_info_t *auth = arg;
	ndr_sec_t *secp = &mxa->recv_auth;
	ndr_stream_t *nds = &mxa->recv_nds;
	nl_auth_sig_t *nas;
	MD5_CTX md5h;
	BYTE local_sig[MD_DIGEST_LEN];
	BYTE dec_key[MD_DIGEST_LEN];
	BYTE local_seqnum[8];
	int rc;
	boolean_t seqnum_bumped = B_FALSE;

	nas = (nl_auth_sig_t *)secp->auth_value;

	/*
	 * Verify SignatureAlgorithm, SealAlgorithm, and Pad are as expected.
	 * These follow the same values as in the Client Signature.
	 */
	if (nas->nas_sig_alg != 0x0077 ||
	    nas->nas_seal_alg != 0xffff ||
	    nas->nas_pad != 0xffff) {
		rc = NDR_DRC_FAULT_SEC_META_INVALID;
		goto errout;
	}

	/* Decrypt the SequenceNumber. This is done the same as the Client. */
	if (smb_auth_hmac_md5((uchar_t *)&zeroes, 4,
	    auth->session_key.key, auth->session_key.len,
	    dec_key) != 0) {
		rc = NDR_DRC_FAULT_SEC_SSP_FAILED;
		goto errout;
	}
	if (smb_auth_hmac_md5((uchar_t *)nas->nas_sig, sizeof (nas->nas_sig),
	    dec_key, sizeof (dec_key),
	    dec_key) != 0) {
		rc = NDR_DRC_FAULT_SEC_SSP_FAILED;
		goto errout;
	}

	if (smb_auth_RC4(nas->nas_seqnum, sizeof (nas->nas_seqnum),
	    dec_key, sizeof (dec_key),
	    nas->nas_seqnum, sizeof (nas->nas_seqnum)) != 0) {
		rc = NDR_DRC_FAULT_SEC_SSP_FAILED;
		goto errout;
	}

	/*
	 * Calculate a local version of the SequenceNumber.
	 * Note that byte 4 does NOT get modified, unlike the client.
	 */
	local_seqnum[0] = CLS_BYTE(3, auth->clh_seqnum);
	local_seqnum[1] = CLS_BYTE(2, auth->clh_seqnum);
	local_seqnum[2] = CLS_BYTE(1, auth->clh_seqnum);
	local_seqnum[3] = CLS_BYTE(0, auth->clh_seqnum);
	local_seqnum[4] = CLS_BYTE(7, auth->clh_seqnum);
	local_seqnum[5] = CLS_BYTE(6, auth->clh_seqnum);
	local_seqnum[6] = CLS_BYTE(5, auth->clh_seqnum);
	local_seqnum[7] = CLS_BYTE(4, auth->clh_seqnum);

	/* If the SequenceNumbers don't match, this is out of order - drop it */
	if (bcmp(local_seqnum, nas->nas_seqnum, sizeof (local_seqnum)) != 0) {
		ndo_printf(nds, NULL, "CalculatedSeqnum: %llu "
		    "DecryptedSeqnum: %llu",
		    *(uint64_t *)local_seqnum, *(uint64_t *)nas->nas_seqnum);
		rc = NDR_DRC_FAULT_SEC_SEQNUM_INVALID;
		goto errout;
	}

	auth->clh_seqnum++;
	seqnum_bumped = B_TRUE;

	/*
	 * Calculate the signature.
	 * This is done the same as the Client.
	 */
	MD5Init(&md5h);
	MD5Update(&md5h, (uchar_t *)&zeroes, 4);
	MD5Update(&md5h, (uchar_t *)nas, 8);
	MD5Update(&md5h,
	    (uchar_t *)nds->pdu_base_addr + nds->pdu_body_offset,
	    nds->pdu_body_size);
	MD5Final(local_sig, &md5h);
	if (smb_auth_hmac_md5(local_sig, sizeof (local_sig),
	    auth->session_key.key, auth->session_key.len,
	    local_sig) != 0) {
		rc = NDR_DRC_FAULT_SEC_SSP_FAILED;
		goto errout;
	}

	/* If the first 8 bytes don't match, drop it */
	if (bcmp(local_sig, nas->nas_sig, 8) != 0) {
		ndo_printf(nds, NULL, "CalculatedSig: %llu "
		    "PacketSig: %llu",
		    *(uint64_t *)local_sig, *(uint64_t *)nas->nas_sig);
		rc = NDR_DRC_FAULT_SEC_SIG_INVALID;
		goto errout;
	}

	return (NDR_DRC_OK);

errout:
	netr_show_sig(nas, &mxa->recv_nds);

	if (!verify_resp) {
		if (!seqnum_bumped)
			auth->clh_seqnum++;
		return (NDR_DRC_OK);
	}

	return (rc);
}

extern struct netr_info netr_global_info;

ndr_auth_ctx_t netr_ssp_ctx = {
	.auth_ops = {
		.nao_init = netr_ssp_init,
		.nao_recv = netr_ssp_recv,
		.nao_sign = netr_ssp_sign,
		.nao_verify = netr_ssp_verify
	},
	.auth_ctx = &netr_global_info,
	.auth_context_id = 0,
	.auth_type = NDR_C_AUTHN_GSS_NETLOGON,
	.auth_level = NDR_C_AUTHN_LEVEL_PKT_INTEGRITY,
	.auth_verify_resp = B_TRUE
};

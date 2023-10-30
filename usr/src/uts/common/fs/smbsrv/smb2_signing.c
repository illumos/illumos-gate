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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2020-2023 RackTop Systems, Inc.
 */
/*
 * These routines provide the SMB MAC signing for the SMB2 server.
 * The routines calculate the signature of a SMB message in an mbuf chain.
 *
 * The following table describes the client server
 * signing registry relationship
 *
 *		| Required	| Enabled     | Disabled
 * -------------+---------------+------------ +--------------
 * Required	| Signed	| Signed      | Fail
 * -------------+---------------+-------------+-----------------
 * Enabled	| Signed	| Signed      | Not Signed
 * -------------+---------------+-------------+----------------
 * Disabled	| Fail		| Not Signed  | Not Signed
 */

#include <sys/uio.h>
#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_kcrypt.h>
#include <sys/isa_defs.h>
#include <sys/byteorder.h>
#include <sys/cmn_err.h>

#define	SMB2_SIG_OFFS	48
#define	SMB2_SIG_SIZE	16

/*
 * Called during session destroy.
 */
static void
smb2_sign_fini(smb_session_t *s)
{
	smb_crypto_mech_t *mech;

	if ((mech = s->sign_mech) != NULL) {
		kmem_free(mech, sizeof (*mech));
		s->sign_mech = NULL;
	}
}

void
smb2_sign_init_mech(smb_session_t *s)
{
	smb_crypto_mech_t *mech;
	int (*get_mech)(smb_crypto_mech_t *);
	int rc;

	if (s->sign_mech != NULL)
		return;

	if (s->dialect >= SMB_VERS_3_0) {
		get_mech = smb3_cmac_getmech;
	} else {
		get_mech = smb2_hmac_getmech;
	}

	mech = kmem_zalloc(sizeof (*mech), KM_SLEEP);
	rc = get_mech(mech);
	if (rc != 0) {
		kmem_free(mech, sizeof (*mech));
		return;
	}
	s->sign_mech = mech;
	s->sign_fini = smb2_sign_fini;
}

/*
 * smb2_sign_begin
 * Handles both SMB2 & SMB3
 *
 * Get the mechanism info.
 * Intializes MAC key based on the user session key and store it in
 * the signing structure.  This begins signing on this session.
 */
void
smb2_sign_begin(smb_request_t *sr, smb_token_t *token)
{
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->uid_user;
	struct smb_key *sign_key = &u->u_sign_key;

	sign_key->len = 0;

	/*
	 * We should normally have a session key here because
	 * our caller filters out Anonymous and Guest logons.
	 * However, buggy clients could get us here without a
	 * session key, in which case we'll fail later when a
	 * request that requires signing can't be checked.
	 * Also, don't bother initializing if we don't have a mechanism.
	 */
	if (token->tkn_ssnkey.val == NULL || token->tkn_ssnkey.len == 0 ||
	    s->sign_mech == NULL)
		return;

	/*
	 * Compute and store the signing key, which lives in
	 * the user structure.
	 */
	if (s->dialect >= SMB_VERS_3_0) {
		/*
		 * For SMB3, the signing key is a "KDF" hash of the
		 * session key.   Limit the SessionKey input to its
		 * maximum size (16 bytes)
		 */
		uint32_t ssnkey_len = MIN(token->tkn_ssnkey.len, SMB2_KEYLEN);
		if (s->dialect >= SMB_VERS_3_11) {
			if (smb3_kdf(sign_key->key, SMB2_KEYLEN,
			    token->tkn_ssnkey.val, ssnkey_len,
			    (uint8_t *)"SMBSigningKey", 14,
			    u->u_preauth_hashval, SHA512_DIGEST_LENGTH)
			    != 0)
				return;
		} else {
			if (smb3_kdf(sign_key->key, SMB2_KEYLEN,
			    token->tkn_ssnkey.val, ssnkey_len,
			    (uint8_t *)"SMB2AESCMAC", 12,
			    (uint8_t *)"SmbSign", 8)
			    != 0)
				return;
		}
		sign_key->len = SMB2_KEYLEN;
	} else {
		/*
		 * For SMB2, the signing key is just the first 16 bytes
		 * of the session key (truncated or padded with zeros).
		 * [MS-SMB2] 3.2.5.3.1
		 */
		sign_key->len = SMB2_KEYLEN;
		bcopy(token->tkn_ssnkey.val, sign_key->key,
		    MIN(token->tkn_ssnkey.len, sign_key->len));
	}

	mutex_enter(&u->u_mutex);
	if ((s->srv_secmode & SMB2_NEGOTIATE_SIGNING_ENABLED) != 0)
		u->u_sign_flags |= SMB_SIGNING_ENABLED;
	if ((s->srv_secmode & SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0 ||
	    (s->cli_secmode & SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0)
		u->u_sign_flags |=
		    SMB_SIGNING_ENABLED | SMB_SIGNING_CHECK;
	mutex_exit(&u->u_mutex);

	/*
	 * If we just turned on signing, the current request
	 * (an SMB2 session setup) will have come in without
	 * SMB2_FLAGS_SIGNED (and not signed) but the response
	 * is is supposed to be signed. [MS-SMB2] 3.3.5.5
	 */
	if (u->u_sign_flags & SMB_SIGNING_ENABLED)
		sr->smb2_hdr_flags |= SMB2_FLAGS_SIGNED;
}

/*
 * smb2_sign_calc
 *
 * Calculates MAC signature for the given buffer and returns
 * it in the mac_sign parameter.
 *
 * The signature algorithm is to compute HMAC SHA256 or AES_CMAC
 * over the entire command, with the signature field set to zeros.
 *
 * Return 0 if  success else non-zero
 */

static int
smb2_sign_calc(smb_request_t *sr, struct mbuf_chain *mbc,
    uint8_t *digest)
{
	uint8_t tmp_hdr[SMB2_HDR_SIZE];
	smb_crypto_mech_t mech;
	smb_crypto_param_t param;
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->uid_user;
	struct smb_key *sign_key = &u->u_sign_key;
	struct mbuf *mbuf;
	smb_vdb_t *in_vdb = NULL;
	int offset, resid, tlen, rc;
	int hdr_iov_cnt = 0;

	if (s->sign_mech == NULL || sign_key->len == 0)
		return (-1);

	mech = *((smb_crypto_mech_t *)s->sign_mech);

	if (s->dialect < SMB_VERS_3_0)
		smb2_sign_init_hmac_param(&mech, &param, SMB2_SIG_SIZE);

	/*
	 * Work with a copy of the SMB2 header so we can
	 * clear the signature field without modifying
	 * the original message.
	 */
	tlen = SMB2_HDR_SIZE;
	offset = mbc->chain_offset;
	resid = mbc->max_bytes - offset;
	if (smb_mbc_peek(mbc, offset, "#c", tlen, tmp_hdr) != 0)
		return (-1);
	bzero(tmp_hdr + SMB2_SIG_OFFS, SMB2_SIG_SIZE);

	/* Build a UIO vector for the auth data. */
	in_vdb = smb_get_vdb(sr);
	in_vdb->vdb_uio.uio_resid = resid;

	in_vdb->vdb_uio.uio_iov[hdr_iov_cnt].iov_base = (char *)tmp_hdr;
	in_vdb->vdb_uio.uio_iov[hdr_iov_cnt++].iov_len = tlen;

	offset += tlen;
	resid -= tlen;

	/*
	 * Digest the rest of the SMB packet, starting at the data
	 * just after the SMB header.
	 *
	 * Advance to the src mbuf where we start digesting.
	 */
	mbuf = mbc->chain;
	while (mbuf != NULL && (offset >= mbuf->m_len)) {
		offset -= mbuf->m_len;
		mbuf = mbuf->m_next;
	}

	if (mbuf == NULL)
		return (-1);

	/*
	 * Digest the remainder of this mbuf, limited to the
	 * residual count, and starting at the current offset.
	 * (typically SMB2_HDR_SIZE)
	 */
	tlen = mbuf->m_len - offset;
	if (tlen > resid)
		tlen = resid;

	in_vdb->vdb_uio.uio_iov[hdr_iov_cnt].iov_base = mbuf->m_data + offset;
	in_vdb->vdb_uio.uio_iov[hdr_iov_cnt++].iov_len = tlen;

	/*
	 * Digest any more mbufs in the chain.
	 */
	rc = smb_mbuf_mkuio_cont(mbuf->m_next, &in_vdb->vdb_uio, hdr_iov_cnt);
	if (rc != 0)
		return (-1);

	/*
	 * Note: digest is _always_ SMB2_SIG_SIZE,
	 * even if the mech uses a longer one.
	 */
	if ((rc = smb2_mac_uio(&mech, sign_key->key, sign_key->len,
	    &in_vdb->vdb_uio, digest)) != 0)
		return (rc);

	return (0);
}

/*
 * smb2_sign_check_request
 *
 * Calculates MAC signature for the request mbuf chain
 * using the next expected sequence number and compares
 * it to the given signature.
 *
 * Note it does not check the signature for secondary transactions
 * as their sequence number is the same as the original request.
 *
 * Return 0 if the signature verifies, otherwise, returns -1;
 *
 */
int
smb2_sign_check_request(smb_request_t *sr)
{
	uint8_t req_sig[SMB2_SIG_SIZE];
	uint8_t vfy_sig[SMB2_SIG_SIZE];
	struct mbuf_chain *mbc = &sr->smb_data;
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->uid_user;
	int sig_off;

	/*
	 * Don't check commands with a zero session ID.
	 * [MS-SMB2] 3.3.4.1.1
	 */
	if (sr->smb2_ssnid == 0 || u == NULL)
		return (0);

	/*
	 * If the negotiated signing mechanism is unavailable
	 * (which is not expected, so this is mostly paranoia)
	 * smb2_sign_init_mech would leave s->sign_fini = NULL
	 * and s->sign_mech invalid.  Checking s->sign_fini is
	 * easiest (type of s->sign_mech varies K vs U).
	 * If the mech is unsupported, return failure.
	 */
	if (s->sign_fini == NULL)
		return (-1);

	/* Get the request signature. */
	sig_off = sr->smb2_cmd_hdr + SMB2_SIG_OFFS;
	if (smb_mbc_peek(mbc, sig_off, "#c", SMB2_SIG_SIZE, req_sig) != 0)
		return (-1);

	/*
	 * Compute the correct signature and compare.
	 */
	if (smb2_sign_calc(sr, mbc, vfy_sig) != 0)
		return (-1);

	if (memcmp(vfy_sig, req_sig, SMB2_SIG_SIZE) == 0) {
		return (0);
	}

	DTRACE_PROBE2(signature__mismatch, smb_request_t *, sr,
	    uint8_t *, vfy_sig);

	return (-1);
}

/*
 * smb2_sign_reply
 *
 * Calculates MAC signature for the given mbuf chain,
 * and write it to the signature field in the mbuf.
 *
 */
void
smb2_sign_reply(smb_request_t *sr)
{
	uint8_t reply_sig[SMB2_SIG_SIZE];
	struct mbuf_chain tmp_mbc;
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->uid_user;
	int hdr_off, msg_len;

	if (u == NULL)
		return;

	/*
	 * If the negotiated signing mechanism is unavailable
	 * (which is not expected, so this is mostly paranoia)
	 * smb2_sign_init_mech would leave s->sign_fini = NULL
	 * and s->sign_mech invalid.  Checking s->sign_fini is
	 * easiest (type of s->sign_mech varies K vs U).
	 * If the mech is unsupported, just don't sign.
	 * The (un-signed) reponse will probably cause the
	 * client to drop the connection.
	 */
	if (s->sign_fini == NULL)
		return;

	msg_len = sr->reply.chain_offset - sr->smb2_reply_hdr;
	(void) MBC_SHADOW_CHAIN(&tmp_mbc, &sr->reply,
	    sr->smb2_reply_hdr, msg_len);

	/*
	 * Calculate the MAC signature for this reply.
	 */
	if (smb2_sign_calc(sr, &tmp_mbc, reply_sig) != 0)
		return;

	/*
	 * Poke the signature into the response.
	 */
	hdr_off = sr->smb2_reply_hdr + SMB2_SIG_OFFS;
	(void) smb_mbc_poke(&sr->reply, hdr_off, "#c",
	    SMB2_SIG_SIZE, reply_sig);
}

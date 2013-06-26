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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
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
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_signing.h>
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
	smb_sign_mech_t *mech;

	if ((mech = s->sign_mech) != NULL) {
		kmem_free(mech, sizeof (*mech));
		s->sign_mech = NULL;
	}
}

/*
 * smb2_sign_begin
 *
 * Get the mechanism info.
 * Intializes MAC key based on the user session key and store it in
 * the signing structure.  This begins signing on this session.
 */
int
smb2_sign_begin(smb_request_t *sr, smb_token_t *token)
{
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->uid_user;
	struct smb_key *sign_key = &u->u_sign_key;
	smb_sign_mech_t *mech;
	int rc;

	/*
	 * We should normally have a session key here because
	 * our caller filters out Anonymous and Guest logons.
	 * However, buggy clients could get us here without a
	 * session key, in which case we'll fail later when a
	 * request that requires signing can't be checked.
	 */
	if (token->tkn_ssnkey.val == NULL || token->tkn_ssnkey.len == 0)
		return (0);

	/*
	 * Session-level initialization (once per session)
	 * Get mech handle, sign_fini function.
	 */
	smb_rwx_rwenter(&s->s_lock, RW_WRITER);
	if (s->sign_mech == NULL) {
		mech = kmem_zalloc(sizeof (*mech), KM_SLEEP);
		rc = smb2_hmac_getmech(mech);
		if (rc != 0) {
			kmem_free(mech, sizeof (*mech));
			smb_rwx_rwexit(&s->s_lock);
			return (rc);
		}
		s->sign_mech = mech;
		s->sign_fini = smb2_sign_fini;
	}
	smb_rwx_rwexit(&s->s_lock);

	/*
	 * Compute and store the signing key, which lives in
	 * the user structure.
	 */
	sign_key->len = SMB2_SIG_SIZE;

	/*
	 * For SMB2, the signing key is just the first 16 bytes
	 * of the session key (truncated or padded with zeros).
	 * [MS-SMB2] 3.2.5.3.1
	 */
	bcopy(token->tkn_ssnkey.val, sign_key->key,
	    MIN(token->tkn_ssnkey.len, sign_key->len));

	mutex_enter(&u->u_mutex);
	if (s->secmode & SMB2_NEGOTIATE_SIGNING_ENABLED)
		u->u_sign_flags |= SMB_SIGNING_ENABLED;
	if (s->secmode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
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

	return (0);
}

/*
 * smb2_sign_calc
 *
 * Calculates MAC signature for the given buffer and returns
 * it in the mac_sign parameter.
 *
 * The signature is in the last 16 bytes of the SMB2 header.
 * The signature algorighm is to compute HMAC SHA256 over the
 * entire command, with the signature field set to zeros.
 *
 * Return 0 if  success else -1
 */
static int
smb2_sign_calc(smb_request_t *sr, struct mbuf_chain *mbc,
    uint8_t *digest)
{
	uint8_t tmp_hdr[SMB2_HDR_SIZE];
	smb_sign_ctx_t ctx = 0;
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->uid_user;
	struct smb_key *sign_key = &u->u_sign_key;
	struct mbuf *mbuf;
	int offset, resid, tlen, rc;

	if (s->sign_mech == NULL || sign_key->len == 0)
		return (-1);

	rc = smb2_hmac_init(&ctx, s->sign_mech, sign_key->key, sign_key->len);
	if (rc != 0)
		return (rc);

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
	if ((rc = smb2_hmac_update(ctx, tmp_hdr, tlen)) != 0)
		return (rc);
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
	rc = smb2_hmac_update(ctx, (uint8_t *)mbuf->m_data + offset, tlen);
	if (rc != 0)
		return (rc);
	resid -= tlen;

	/*
	 * Digest any more mbufs in the chain.
	 */
	while (resid > 0) {
		mbuf = mbuf->m_next;
		if (mbuf == NULL)
			return (-1);
		tlen = mbuf->m_len;
		if (tlen > resid)
			tlen = resid;
		rc = smb2_hmac_update(ctx, (uint8_t *)mbuf->m_data, tlen);
		if (rc != 0)
			return (rc);
		resid -= tlen;
	}

	/*
	 * Note: digest is _always_ SMB2_SIG_SIZE,
	 * even if the mech uses a longer one.
	 */
	if ((rc = smb2_hmac_final(ctx, digest)) != 0)
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
	smb_user_t *u = sr->uid_user;
	int sig_off;

	/*
	 * Don't check commands with a zero session ID.
	 * [MS-SMB2] 3.3.4.1.1
	 */
	if (sr->smb_uid == 0 || u == NULL)
		return (0);

	/* Get the request signature. */
	sig_off = sr->smb2_cmd_hdr + SMB2_SIG_OFFS;
	if (smb_mbc_peek(mbc, sig_off, "#c", SMB2_SIG_SIZE, req_sig) != 0)
		return (-1);

	/*
	 * Compute the correct signature and compare.
	 */
	if (smb2_sign_calc(sr, mbc, vfy_sig) != 0)
		return (-1);
	if (memcmp(vfy_sig, req_sig, SMB2_SIG_SIZE) != 0) {
		cmn_err(CE_NOTE, "smb2_sign_check_request: bad signature");
		return (-1);
	}

	return (0);
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
	smb_user_t *u = sr->uid_user;
	int hdr_off, msg_len;

	if (u == NULL)
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

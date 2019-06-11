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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Routines for smb3 encryption.
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_kcrypt.h>
#include <sys/random.h>
#include <sys/cmn_err.h>

#define	SMB3_NONCE_OFFS		20
#define	SMB3_SIG_OFFS		4
#define	SMB3_NONCE_SIZE		11 /* 12 for gcm later */

/*
 * Inputs to KDF for EncryptionKey and DecryptionKey.
 * See comment for smb3_do_kdf for content.
 */
static uint8_t encrypt_kdf_input[30] = {
	0, 0, 0, 1, 'S', 'M', 'B', '2',
	'A', 'E', 'S', 'C', 'C', 'M', 0, 0,
	'S', 'e', 'r', 'v', 'e', 'r', 'O',
	'u', 't', 0, 0, 0, 0, 0x80 };

static uint8_t decrypt_kdf_input[30] = {
	0, 0, 0, 1, 'S', 'M', 'B', '2',
	'A', 'E', 'S', 'C', 'C', 'M', 0, 0,
	'S', 'e', 'r', 'v', 'e', 'r', 'I',
	'n', ' ', 0, 0, 0, 0, 0x80 };

/*
 * Arbitrary value used to prevent nonce reuse via overflow. Currently
 * 2^64 - 2^32 - 1. Assumes we can't have (or are unlikely to have)
 * 2^32 concurrent messages when we hit this number.
 */
static uint64_t smb3_max_nonce = 0xffffffff00000000ULL;

/*
 * Nonce generation based on draft-mcgrew-iv-gen-01
 * "Generation of Deterministic Initialization Vectors (IVs) and Nonces"
 *
 * Generate an 8-byte random salt and a 3-byte random 'fixed' value.
 * then, nonce = (++counter ^ salt) || fixed
 *
 * This protects against nonce-reuse (8-byte counter), as well as known
 * attacks on reusing nonces with different keys
 */

void
smb3_encrypt_init_nonce(smb_user_t *user)
{
	user->u_nonce_cnt = 0;
	(void) random_get_pseudo_bytes(user->u_nonce_fixed,
	    sizeof (user->u_nonce_fixed));
	(void) random_get_pseudo_bytes((uint8_t *)&user->u_salt,
	    sizeof (user->u_salt));
}

int
smb3_encrypt_gen_nonce(smb_user_t *user, uint8_t *buf, size_t len)
{
	uint64_t cnt = atomic_inc_64_nv(&user->u_nonce_cnt);

	/*
	 * Nonces must be unique per-key for the life of the key.
	 * Bail before we roll over to avoid breaking the crypto.
	 */

	if (cnt > smb3_max_nonce)
		return (-1);

	cnt ^= user->u_salt;
	bcopy((uint8_t *)&cnt, buf, sizeof (cnt));

	ASSERT(len > sizeof (cnt));
	bcopy(user->u_nonce_fixed, buf + sizeof (cnt), len - sizeof (cnt));
	return (0);
}

int
smb3_encrypt_init_mech(smb_session_t *s)
{
	smb_crypto_mech_t *mech;
	int rc;

	if (s->enc_mech != NULL)
		return (0);

	mech = kmem_zalloc(sizeof (*mech), KM_SLEEP);
	rc = smb3_encrypt_getmech(mech);
	if (rc != 0) {
		kmem_free(mech, sizeof (*mech));
		return (rc);
	}
	s->enc_mech = mech;

	return (0);
}

/*
 * Initializes keys/state required for SMB3 Encryption.
 * Note: If a failure occurs here, don't fail the request.
 * Instead, return an error when we attempt to encrypt/decrypt.
 */
void
smb3_encrypt_begin(smb_request_t *sr, smb_token_t *token)
{
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->uid_user;
	struct smb_key *enc_key = &u->u_enc_key;
	struct smb_key *dec_key = &u->u_dec_key;

	/*
	 * In order to enforce encryption, all users need to
	 * have Session.EncryptData properly set, even anon/guest.
	 */
	u->u_encrypt = s->s_server->sv_cfg.skc_encrypt;
	enc_key->len = 0;
	dec_key->len = 0;

	/*
	 * If we don't have a session key, we'll fail later when a
	 * request that requires (en/de)cryption can't be (en/de)crypted.
	 * Also don't bother initializing if we don't have a mechanism.
	 */
	if (token->tkn_ssnkey.val == NULL || token->tkn_ssnkey.len == 0 ||
	    s->enc_mech == NULL)
		return;

	/*
	 * Compute and store the encryption keys, which live in
	 * the user structure.
	 */

	/*
	 * For SMB3, the encrypt/decrypt keys are derived from
	 * the session key using KDF in counter mode.
	 */
	if (smb3_do_kdf(enc_key->key, encrypt_kdf_input,
	    sizeof (encrypt_kdf_input), token->tkn_ssnkey.val,
	    token->tkn_ssnkey.len) != 0)
		return;

	if (smb3_do_kdf(dec_key->key, decrypt_kdf_input,
	    sizeof (decrypt_kdf_input), token->tkn_ssnkey.val,
	    token->tkn_ssnkey.len) != 0)
		return;

	smb3_encrypt_init_nonce(u);

	enc_key->len = SMB3_KEYLEN;
	dec_key->len = SMB3_KEYLEN;
}

/*
 * Decrypt the request in sr->command.
 * This decrypts "in place", though due to CCM's design,
 * it processes all input before doing any output.
 */
int
smb3_decrypt_sr(smb_request_t *sr)
{
	struct mbuf_chain *mbc = &sr->command;
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->tform_ssn;
	uint8_t tmp_hdr[SMB2_HDR_SIZE];
	smb3_enc_ctx_t ctx;
	struct smb_key *dec_key = &u->u_dec_key;
	struct mbuf *mbuf;
	int offset, resid, tlen, rc;
	smb3_crypto_param_t param;
	smb_crypto_mech_t mech;

	ASSERT(u != NULL);
	if (s->enc_mech == NULL || dec_key->len != 16) {
		return (-1);
	}

	tlen = SMB3_TFORM_HDR_SIZE - SMB3_NONCE_OFFS;
	offset = mbc->chain_offset + SMB3_NONCE_OFFS;
	resid = mbc->max_bytes - offset;

	if (resid < (sr->msgsize + tlen)) {
		cmn_err(CE_WARN, "too little data to decrypt");
		return (-1);
	}

	if (smb_mbc_peek(mbc, offset, "#c", tlen, tmp_hdr) != 0) {
		return (-1);
	}

	offset += tlen;
	resid -= tlen;

	/*
	 * The transform header, minus the PROTOCOL_ID and the
	 * SIGNATURE, is authenticated but not encrypted.
	 */
	smb3_crypto_init_param(&param, sr->nonce, SMB3_NONCE_SIZE,
	    tmp_hdr, tlen, sr->msgsize + SMB2_SIG_SIZE);

	/*
	 * Unlike signing, which uses one global mech struct,
	 * encryption requires modifying the mech to add a
	 * per-use param struct. Thus, we need to make a copy.
	 */
	mech = *(smb_crypto_mech_t *)s->enc_mech;
	rc = smb3_decrypt_init(&ctx, &mech, &param,
	    dec_key->key, dec_key->len);
	if (rc != 0) {
		return (rc);
	}

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
	 */
	tlen = mbuf->m_len - offset;
	if (tlen > resid)
		tlen = resid;

	rc = smb3_decrypt_update(&ctx, (uint8_t *)mbuf->m_data + offset, tlen);
	if (rc != 0) {
		return (rc);
	}
	resid -= tlen;

	/*
	 * Digest any more mbufs in the chain.
	 */
	while (resid > 0) {
		mbuf = mbuf->m_next;
		if (mbuf == NULL) {
			smb3_encrypt_cancel(&ctx);
			return (-1);
		}
		tlen = mbuf->m_len;
		if (tlen > resid)
			tlen = resid;
		rc = smb3_decrypt_update(&ctx, (uint8_t *)mbuf->m_data, tlen);
		if (rc != 0) {
			return (rc);
		}
		resid -= tlen;
	}

	/*
	 * AES_CCM processes the signature like normal data.
	 */
	rc = smb3_decrypt_update(&ctx, sr->smb2_sig, SMB2_SIG_SIZE);

	if (rc != 0) {
		cmn_err(CE_WARN, "failed to process signature");
		return (rc);
	}
	/*
	 * smb3_decrypt_final will return an error
	 * if the signatures don't match.
	 */
	rc = smb3_decrypt_final(&ctx, sr->sr_request_buf, sr->sr_req_length);

	/*
	 * We had to decode TFORM_HDR_SIZE bytes before we got here,
	 * and we just peeked the first TFORM_HDR_SIZE bytes at the
	 * beginning of this function, so this can't underflow.
	 */
	ASSERT(sr->command.max_bytes > SMB3_TFORM_HDR_SIZE);
	sr->command.max_bytes -= SMB3_TFORM_HDR_SIZE;
	return (rc);
}

/*
 * Encrypt the response in in_mbc, and output
 * an encrypted response in out_mbc.
 * The data in in_mbc is preserved.
 */
int
smb3_encrypt_sr(smb_request_t *sr, struct mbuf_chain *in_mbc,
    struct mbuf_chain *out_mbc)
{
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->tform_ssn;
	uint8_t *buf = (uint8_t *)out_mbc->chain->m_data;
	size_t buflen = out_mbc->max_bytes;
	smb3_enc_ctx_t ctx;
	struct smb_key *enc_key = &u->u_enc_key;
	struct mbuf *mbuf;
	int resid, tlen, rc;
	smb3_crypto_param_t param;
	smb_crypto_mech_t mech;

	ASSERT(u != NULL);
	if (s->enc_mech == NULL || enc_key->len != 16) {
		return (-1);
	}

	rc = smb3_encrypt_gen_nonce(u, sr->nonce, SMB3_NONCE_SIZE);

	if (rc != 0) {
		cmn_err(CE_WARN, "ran out of nonces");
		return (-1);
	}

	(void) smb_mbc_poke(out_mbc, SMB3_NONCE_OFFS, "#c",
	    SMB3_NONCE_SIZE, sr->nonce);

	resid = in_mbc->max_bytes;

	/*
	 * The transform header, minus the PROTOCOL_ID and the
	 * SIGNATURE, is authenticated but not encrypted.
	 */
	smb3_crypto_init_param(&param,
	    sr->nonce, SMB3_NONCE_SIZE,
	    buf + SMB3_NONCE_OFFS, SMB3_TFORM_HDR_SIZE - SMB3_NONCE_OFFS,
	    resid);

	/*
	 * Unlike signing, which uses one global mech struct,
	 * encryption requires modifying the mech to add a
	 * per-use param struct. Thus, we need to make a copy.
	 */
	mech = *(smb_crypto_mech_t *)s->enc_mech;
	rc = smb3_encrypt_init(&ctx, &mech, &param,
	    enc_key->key, enc_key->len, buf + SMB3_TFORM_HDR_SIZE,
	    buflen - SMB3_TFORM_HDR_SIZE);
	if (rc != 0) {
		return (rc);
	}

	/*
	 * Unlike signing and decryption, we're processing the entirety of the
	 * message here, so we don't skip anything.
	 */
	mbuf = in_mbc->chain;
	while (resid > 0 && mbuf != NULL) {
		tlen = mbuf->m_len;
		if (tlen > resid)
			tlen = resid;
		rc = smb3_encrypt_update(&ctx, (uint8_t *)mbuf->m_data, tlen);
		if (rc != 0) {
			return (rc);
		}
		resid -= tlen;
		mbuf = mbuf->m_next;
	}

	if (mbuf == NULL && resid > 0) {
		cmn_err(CE_WARN, "not enough data to encrypt");
		smb3_encrypt_cancel(&ctx);
		return (-1);
	}

	rc = smb3_encrypt_final(&ctx, buf + SMB3_SIG_OFFS);

	return (rc);
}

void
smb3_encrypt_fini(smb_session_t *s)
{
	smb_crypto_mech_t *mech;

	if ((mech = s->enc_mech) != NULL) {
		kmem_free(mech, sizeof (*mech));
		s->enc_mech = NULL;
	}
}

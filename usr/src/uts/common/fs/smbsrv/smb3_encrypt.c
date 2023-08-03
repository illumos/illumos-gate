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
 * Copyright 2017-2021 Tintri by DDN, Inc.  All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
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

static int
smb3_encrypt_gen_nonce(smb_user_t *user, uint8_t *buf, size_t len)
{
	uint64_t cnt;

	/*
	 * Nonces must be unique per-key for the life of the key.
	 * Bail before we roll over to avoid breaking the crypto.
	 */
	cnt = atomic_inc_64_nv(&user->u_nonce_cnt);
	if (cnt > smb3_max_nonce)
		return (-1);

	cnt ^= user->u_salt;

	bcopy((uint8_t *)&cnt, buf, sizeof (cnt));

	ASSERT(len <= 16);	// th_nonce
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

	switch (s->smb31_enc_cipherid) {
	case SMB3_CIPHER_AES256_GCM:
	case SMB3_CIPHER_AES128_GCM:
		rc = smb3_aes_gcm_getmech(mech);
		break;
	case SMB3_CIPHER_AES256_CCM:
	case SMB3_CIPHER_AES128_CCM:
		rc = smb3_aes_ccm_getmech(mech);
		break;
	default:
		rc = -1;
		break;
	}

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
smb3_encrypt_begin(smb_user_t *u, smb_token_t *token)
{
	smb_session_t *s = u->u_session;
	struct smb_key *enc_key = &u->u_enc_key;
	struct smb_key *dec_key = &u->u_dec_key;
	uint32_t derived_keylen, input_keylen;

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
	 *
	 * AES256 Keys are derived from the 'FullSessionKey', which is the
	 * entirety of what we got in the token; AES128 Keys are derived from
	 * the 'SessionKey', which is the first 16 bytes of the key we got in
	 * the token.
	 */
	if (s->dialect >= SMB_VERS_3_11) {
		if (s->smb31_enc_cipherid == SMB3_CIPHER_AES256_GCM ||
		    s->smb31_enc_cipherid == SMB3_CIPHER_AES256_CCM) {
			derived_keylen = AES256_KEY_LENGTH;
			input_keylen = token->tkn_ssnkey.len;
		} else {
			derived_keylen = AES128_KEY_LENGTH;
			input_keylen = MIN(SMB2_SSN_KEYLEN,
			    token->tkn_ssnkey.len);
		}

		if (smb3_kdf(enc_key->key, derived_keylen,
		    token->tkn_ssnkey.val, input_keylen,
		    (uint8_t *)"SMBS2CCipherKey", 16,
		    u->u_preauth_hashval, SHA512_DIGEST_LENGTH) != 0)
			return;

		if (smb3_kdf(dec_key->key, derived_keylen,
		    token->tkn_ssnkey.val, input_keylen,
		    (uint8_t *)"SMBC2SCipherKey", 16,
		    u->u_preauth_hashval, SHA512_DIGEST_LENGTH) != 0)
			return;

		enc_key->len = derived_keylen;
		dec_key->len = derived_keylen;
	} else {
		derived_keylen = AES128_KEY_LENGTH;
		input_keylen = MIN(SMB2_SSN_KEYLEN, token->tkn_ssnkey.len);

		if (smb3_kdf(enc_key->key, derived_keylen,
		    token->tkn_ssnkey.val, input_keylen,
		    (uint8_t *)"SMB2AESCCM", 11,
		    (uint8_t *)"ServerOut", 10) != 0)
			return;

		if (smb3_kdf(dec_key->key, derived_keylen,
		    token->tkn_ssnkey.val, input_keylen,
		    (uint8_t *)"SMB2AESCCM", 11,
		    (uint8_t *)"ServerIn ", 10) != 0)
			return;

		enc_key->len = derived_keylen;
		dec_key->len = derived_keylen;
	}

	smb3_encrypt_init_nonce(u);

	/*
	 * XXX todo: setup crypto context for enc_key, dec_key.
	 * See crypto_create_ctx_template(mech, key, tmpl,...)
	 *
	 * Will need a new indirect functions eg.
	 *	smb3_encrypt_init_templ(s->enc_mech, enc_key);
	 *	smb3_encrypt_init_templ(s->enc_mech, dec_key);
	 * where struct smb_key gains a new member:
	 *	void *template;
	 *
	 * Already have s->enc_mech from smb3_encrypt_init_mech().
	 */
}

static int
smb3_decode_tform_header(smb_request_t *sr, struct mbuf_chain *mbc)
{
	uint32_t protocolid;
	uint16_t flags;
	int rc;

	rc = smb_mbc_decodef(
	    mbc, "l16c16cl..wq",
	    &protocolid,	/*  l  */
	    sr->smb2_sig,	/* 16c */
	    sr->th_nonce,	/* 16c */
	    &sr->th_msglen,	/* l */
	    /* reserved	  .. */
	    &flags,		/* w */
	    &sr->th_ssnid);	/* q */
	if (rc)
		return (rc);

	/* This was checked in smb2sr_newrq() */
	ASSERT3U(protocolid, ==, SMB3_ENCRYPTED_MAGIC);

	if (flags != 1) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "flags field not 1: %x", flags);
#endif
		return (-1);
	}

	return (rc);
}

static int
smb3_encode_tform_header(smb_request_t *sr, struct mbuf_chain *mbc)
{
	int rc;

	rc = smb_mbc_encodef(
	    mbc, "l16.16clwwq",
	    SMB3_ENCRYPTED_MAGIC, /* l */
	    /* signature(16)	   16. (filled in later) */
	    sr->th_nonce,	/* 16c */
	    sr->th_msglen,	/* l */
	    0, /* reserved	   w */
	    1, /* flags		   w */
	    sr->th_ssnid); /* q */

	return (rc);
}

/*
 * Get an smb_vdb_t and initialize it.
 * Free'd via smb_request_free
 */
static smb_vdb_t *
smb3_get_vdb(smb_request_t *sr)
{
	smb_vdb_t *vdb;

	vdb = smb_srm_zalloc(sr, sizeof (*vdb));
	vdb->vdb_uio.uio_iov = &vdb->vdb_iovec[0];
	vdb->vdb_uio.uio_iovcnt = MAX_IOVEC;
	vdb->vdb_uio.uio_segflg = UIO_SYSSPACE;
	vdb->vdb_uio.uio_extflg = UIO_COPY_DEFAULT;

	return (vdb);
}

/*
 * Decrypt the request in mbc_in into out_mbc which as been
 * setup by the caller.  The caller will replace sr->command
 * with out_mbc if this succeeds, or will free which ever one
 * ends up not being used as sr->command.
 *
 * The encrypted request in in_mbc is left unmodified here,
 * and free'd by the caller when appropriate.
 *
 * Error return values here are just for visibility in dtrace.
 * Anything non-zero results in a connection drop.
 */
int
smb3_decrypt_sr(smb_request_t *sr,
    struct mbuf_chain *in_mbc,	// transform header + ciphertext
    struct mbuf_chain *out_mbc)	// cleartext
{
	smb_enc_ctx_t ctx;
	uint8_t th_raw[SMB3_TFORM_HDR_SIZE];
	uint8_t *authdata;
	size_t authlen;
	size_t cipherlen;
	smb_vdb_t *in_vdb = NULL;
	smb_vdb_t *out_vdb = NULL;
	smb_session_t *s = sr->session;
	smb_user_t *u;
	struct smb_key *dec_key;
	int cnt, rc;
	boolean_t gcm;
	size_t nonce_size;
	uint_t keylen;

	if (s->enc_mech == NULL)
		return (SET_ERROR(-1));

	switch (s->smb31_enc_cipherid) {
	default:
		ASSERT(0);
		/* fallthrough */
	case SMB3_CIPHER_AES128_CCM:	// 1
		gcm = B_FALSE;
		nonce_size = SMB3_AES_CCM_NONCE_SIZE;
		keylen = AES128_KEY_LENGTH;
		break;
	case SMB3_CIPHER_AES128_GCM:	// 2
		gcm = B_TRUE;
		nonce_size = SMB3_AES_GCM_NONCE_SIZE;
		keylen = AES128_KEY_LENGTH;
		break;
	case SMB3_CIPHER_AES256_CCM:	// 3
		gcm = B_FALSE;
		nonce_size = SMB3_AES_CCM_NONCE_SIZE;
		keylen = AES256_KEY_LENGTH;
		break;
	case SMB3_CIPHER_AES256_GCM:	// 4
		gcm = B_TRUE;
		nonce_size = SMB3_AES_GCM_NONCE_SIZE;
		keylen = AES256_KEY_LENGTH;
		break;
	}

	/*
	 * Get the transform header, in both raw form and decoded,
	 * then remove the transform header from the message.
	 * Note: the signature lands in sr->smb2_sig
	 */
	if (smb_mbc_peek(in_mbc, 0, "#c",
	    SMB3_TFORM_HDR_SIZE, th_raw) != 0) {
		return (SET_ERROR(-2));
	}
	rc = smb3_decode_tform_header(sr, in_mbc);
	if (rc != 0) {
		return (SET_ERROR(-3));
	}
	m_adjust(in_mbc->chain, SMB3_TFORM_HDR_SIZE);
	ASSERT(in_mbc->max_bytes > SMB3_TFORM_HDR_SIZE);
	in_mbc->max_bytes -= SMB3_TFORM_HDR_SIZE;
	in_mbc->chain_offset = 0;

	/*
	 * Bounds-check the stated length of the encapsulated message.
	 */
	if (sr->th_msglen < SMB2_HDR_SIZE ||
	    sr->th_msglen > in_mbc->max_bytes) {
		return (SET_ERROR(-4));
	}
	cipherlen = sr->th_msglen + SMB2_SIG_SIZE;

	/*
	 * Lookup/validate the transform session ID so we'll
	 * have the key we'll need.  Release for this happens
	 * in smb_request_free().
	 */
	u = smb_session_lookup_ssnid(s, sr->th_ssnid);
	if (u == NULL) {
		return (SET_ERROR(-5));
	}
	sr->th_sid_user = u;
	dec_key = &u->u_dec_key;
	if (dec_key->len != keylen) {
		return (SET_ERROR(-6));
	}

	/*
	 * Initialize crypto I/F: mech, params, key
	 *
	 * Unlike signing, which uses one global mech struct,
	 * encryption requires modifying the mech to add a
	 * per-use param struct. Thus, we need to make a copy.
	 */
	bzero(&ctx, sizeof (ctx));
	ctx.mech = *((smb_crypto_mech_t *)s->enc_mech);

	/*
	 * The transform header, minus the PROTOCOL_ID and the
	 * SIGNATURE, is authenticated but not encrypted.
	 * (That's the "auth data" passed to init)
	 *
	 * Param init for CCM also needs the cipher length, which is
	 * the clear length + 16, but note that the last 16 bytes is
	 * the signature in the transform header.
	 */
	authdata = th_raw + SMB3_NONCE_OFFS;
	authlen = SMB3_TFORM_HDR_SIZE - SMB3_NONCE_OFFS;

	if (gcm) {
		smb3_crypto_init_gcm_param(&ctx,
		    sr->th_nonce, nonce_size,
		    authdata, authlen);
	} else {
		smb3_crypto_init_ccm_param(&ctx,
		    sr->th_nonce, nonce_size,
		    authdata, authlen, cipherlen);
	}

	rc = smb3_decrypt_init(&ctx,
	    dec_key->key, dec_key->len);
	if (rc != 0)
		return (SET_ERROR(-7));

	/*
	 * Build a UIO vector for the ciphertext (in)
	 * a: remainder of the 1s segment after the transform header
	 * b: all subsequent segments of this message
	 * c: final 16 byte signature from the transform header
	 */
	in_vdb = smb3_get_vdb(sr);
	in_vdb->vdb_uio.uio_resid = sr->th_msglen;
	rc = smb_mbuf_mkuio(in_mbc->chain, &in_vdb->vdb_uio);
	if (rc != 0)
		return (SET_ERROR(-8));

	/* Add one more uio seg. for the signature. */
	cnt = in_vdb->vdb_uio.uio_iovcnt;
	if ((cnt + 1) > MAX_IOVEC)
		return (SET_ERROR(-9));
	in_vdb->vdb_uio.uio_iov[cnt].iov_base = (void *)sr->smb2_sig;
	in_vdb->vdb_uio.uio_iov[cnt].iov_len = SMB2_SIG_SIZE;
	in_vdb->vdb_uio.uio_iovcnt = cnt + 1;
	in_vdb->vdb_uio.uio_resid += SMB2_SIG_SIZE;

	/*
	 * Build a UIO vector for the cleartext (out)
	 */
	out_vdb = smb3_get_vdb(sr);
	out_vdb->vdb_uio.uio_resid = sr->th_msglen;
	rc = smb_mbuf_mkuio(out_mbc->chain, &out_vdb->vdb_uio);
	if (rc != 0)
		return (SET_ERROR(-10));

	/*
	 * Have in/out UIO descriptors.  Decrypt!
	 */
	rc = smb3_decrypt_uio(&ctx, &in_vdb->vdb_uio, &out_vdb->vdb_uio);
	if (rc != 0) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "smb3_decrypt_uio failed");
#endif
		return (SET_ERROR(-11));
	}

	return (rc);
}

/*
 * Encrypt the response in in_mbc into out_mbc which as been
 * setup by the caller.  The caller will send out_mbc if this
 * returns success, and otherwise will free out_mbc.
 *
 * The cleartext response in in_mbc is left unmodified here,
 * and free'd in smb_request_free.
 *
 * Error return values here are just for visibility in dtrace.
 * Anything non-zero results in a connection drop.
 */
int
smb3_encrypt_sr(smb_request_t *sr,
    struct mbuf_chain *in_mbc,	// cleartext
    struct mbuf_chain *out_mbc)	// transform header + ciphertext
{
	smb_enc_ctx_t ctx;
	uint8_t th_raw[SMB3_TFORM_HDR_SIZE];
	uint8_t *authdata;
	size_t authlen;
	smb_vdb_t *in_vdb = NULL;
	smb_vdb_t *out_vdb = NULL;
	smb_session_t *s = sr->session;
	smb_user_t *u = sr->th_sid_user;
	struct smb_key *enc_key = &u->u_enc_key;
	int cnt, rc;
	boolean_t gcm;
	size_t nonce_size;
	uint_t keylen;

	VERIFY(u != NULL); // and have sr->th_ssnid

	switch (s->smb31_enc_cipherid) {
	default:
		ASSERT(0);
		/* fallthrough */
	case SMB3_CIPHER_AES128_CCM:	// 1
		gcm = B_FALSE;
		nonce_size = SMB3_AES_CCM_NONCE_SIZE;
		keylen = AES128_KEY_LENGTH;
		break;
	case SMB3_CIPHER_AES128_GCM:	// 2
		gcm = B_TRUE;
		nonce_size = SMB3_AES_GCM_NONCE_SIZE;
		keylen = AES128_KEY_LENGTH;
		break;
	case SMB3_CIPHER_AES256_CCM:	// 3
		gcm = B_FALSE;
		nonce_size = SMB3_AES_CCM_NONCE_SIZE;
		keylen = AES256_KEY_LENGTH;
		break;
	case SMB3_CIPHER_AES256_GCM:	// 4
		gcm = B_TRUE;
		nonce_size = SMB3_AES_GCM_NONCE_SIZE;
		keylen = AES256_KEY_LENGTH;
		break;
	}
	if (s->enc_mech == NULL || enc_key->len != keylen) {
		return (SET_ERROR(-1));
	}

	/*
	 * Need to fill in the transform header for everything
	 * after the signature, needed as the "auth" data.
	 * The signature is stuffed in later.  So we need:
	 *   the nonce, msgsize, flags, th_ssnid
	 */
	rc = smb3_encrypt_gen_nonce(u, sr->th_nonce, nonce_size);
	if (rc != 0) {
		cmn_err(CE_WARN, "ran out of nonces");
		return (SET_ERROR(-2));
	}
	if (smb3_encode_tform_header(sr, out_mbc) != 0) {
		cmn_err(CE_WARN, "couldn't encode transform header");
		return (SET_ERROR(-3));
	}

	/* Get the raw header to use as auth data */
	if (smb_mbc_peek(out_mbc, 0, "#c",
	    SMB3_TFORM_HDR_SIZE, th_raw) != 0)
		return (SET_ERROR(-4));

	/*
	 * Initialize crypto I/F: mech, params, key
	 *
	 * Unlike signing, which uses one global mech struct,
	 * encryption requires modifying the mech to add a
	 * per-use param struct. Thus, we need to make a copy.
	 */
	bzero(&ctx, sizeof (ctx));
	ctx.mech = *((smb_crypto_mech_t *)s->enc_mech);

	/*
	 * The transform header, minus the PROTOCOL_ID and the
	 * SIGNATURE, is authenticated but not encrypted.
	 * (That's the "auth data" passed to init)
	 *
	 * Param init for CCM also needs the cipher length, which is
	 * the clear length + 16, but note that the last 16 bytes is
	 * the signature in the transform header.
	 *
	 * Note: sr->th_msglen already set by caller
	 */
	authdata = th_raw + SMB3_NONCE_OFFS;
	authlen = SMB3_TFORM_HDR_SIZE - SMB3_NONCE_OFFS;

	if (gcm) {
		smb3_crypto_init_gcm_param(&ctx,
		    sr->th_nonce, nonce_size,
		    authdata, authlen);
	} else {
		smb3_crypto_init_ccm_param(&ctx,
		    sr->th_nonce, nonce_size,
		    authdata, authlen, sr->th_msglen);
	}

	rc = smb3_encrypt_init(&ctx,
	    enc_key->key, enc_key->len);
	if (rc != 0)
		return (SET_ERROR(-5));

	/*
	 * Build a UIO vector for the cleartext (in)
	 */
	in_vdb = smb3_get_vdb(sr);
	in_vdb->vdb_uio.uio_resid = sr->th_msglen;
	rc = smb_mbuf_mkuio(in_mbc->chain, &in_vdb->vdb_uio);
	if (rc != 0)
		return (SET_ERROR(-6));

	/*
	 * Build a UIO vector for the ciphertext (out)
	 * a: remainder of the 1s segment after the transform header
	 * b: all subsequent segments of this message
	 * c: final 16 byte signature that will go in the TH
	 *
	 * Caller puts transform header in its own mblk so we can
	 * just skip the first mlbk when building the uio.
	 */
	out_vdb = smb3_get_vdb(sr);
	out_vdb->vdb_uio.uio_resid = sr->th_msglen;
	rc = smb_mbuf_mkuio(out_mbc->chain->m_next, &out_vdb->vdb_uio);
	if (rc != 0)
		return (SET_ERROR(-7));

	/* Add one more uio seg. for the signature. */
	cnt = out_vdb->vdb_uio.uio_iovcnt;
	if ((cnt + 1) > MAX_IOVEC)
		return (SET_ERROR(-8));
	out_vdb->vdb_uio.uio_iov[cnt].iov_base = (void *)sr->smb2_sig;
	out_vdb->vdb_uio.uio_iov[cnt].iov_len = SMB2_SIG_SIZE;
	out_vdb->vdb_uio.uio_iovcnt = cnt + 1;
	out_vdb->vdb_uio.uio_resid += SMB2_SIG_SIZE;

	/*
	 * Have in/out UIO descriptors. Encrypt!
	 */
	rc = smb3_encrypt_uio(&ctx, &in_vdb->vdb_uio, &out_vdb->vdb_uio);
	if (rc != 0) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "smb3_encrypt_uio failed");
#endif
		return (SET_ERROR(-9));
	}

	/*
	 * Now patch the final signature into the transform header
	 */
	(void) smb_mbc_poke(out_mbc, SMB3_SIG_OFFS, "#c",
	    SMB2_SIG_SIZE, sr->smb2_sig);

	return (rc);
}

void
smb3_encrypt_ssn_fini(smb_session_t *s)
{
	smb_crypto_mech_t *mech;

	if ((mech = s->enc_mech) != NULL) {
		kmem_free(mech, sizeof (*mech));
		s->enc_mech = NULL;
	}
}

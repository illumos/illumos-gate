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
 * Copyright 2018-2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2020-2024 RackTop Systems, Inc.
 */

/*
 * Helper functions for SMB3 encryption using the
 * Kernel Cryptographic Framework (KCF)
 *
 * There are two implementations of these functions:
 * This one (for kernel) and another for user space:
 * See: lib/smbclnt/libfknsmb/common/fksmb_crypt_pkcs.c
 *
 * Contrary to what one might assume from the file name,
 * there should be NO SMB implementation knowledge here
 * beyond a few carefully selected things (nsmb_kcrypt.h).
 */

#include <sys/types.h>
#include <sys/crypto/api.h>

#include <netsmb/nsmb_kcrypt.h>

#include <sys/cmn_err.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>

/*
 * Common function to see if a mech is available.
 */
static int
find_mech(smb_crypto_mech_t *mech, const char *name)
{
	crypto_mech_type_t t;

	t = crypto_mech2id(name);
	if (t == CRYPTO_MECH_INVALID) {
		cmn_err(CE_NOTE, "nsmb: no kcf mech: %s", name);
		return (-1);
	}
	mech->cm_type = t;
	return (0);
}

/*
 * SMB3 encryption helpers:
 * (getmech, init, update, final)
 */

int
nsmb_aes_ccm_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_AES_CCM));
}

int
nsmb_aes_gcm_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_AES_GCM));
}

void
nsmb_crypto_init_ccm_param(smb_enc_ctx_t *ctx,
    uint8_t *nonce, size_t noncesize,
    uint8_t *auth, size_t authsize,
    size_t datasize)
{

	ASSERT3U(noncesize, >=, SMB3_AES_CCM_NONCE_SIZE);

	ctx->param.ccm.ulMACSize = SMB2_SIG_SIZE;
	ctx->param.ccm.ulNonceSize = SMB3_AES_CCM_NONCE_SIZE;
	ctx->param.ccm.nonce = nonce;
	ctx->param.ccm.ulDataSize = datasize;
	ctx->param.ccm.ulAuthDataSize = authsize;
	ctx->param.ccm.authData = auth;

	ctx->mech.cm_param = (caddr_t)&ctx->param.ccm;
	ctx->mech.cm_param_len = sizeof (ctx->param.ccm);
}

void
nsmb_crypto_init_gcm_param(smb_enc_ctx_t *ctx,
    uint8_t *nonce, size_t noncesize,
    uint8_t *auth, size_t authsize)
{

	ASSERT3U(noncesize, >=, SMB3_AES_GCM_NONCE_SIZE);

	ctx->param.gcm.pIv = nonce;
	ctx->param.gcm.ulIvLen = SMB3_AES_GCM_NONCE_SIZE;
	ctx->param.gcm.ulTagBits = SMB2_SIG_SIZE << 3;	/* bytes to bits */
	ctx->param.gcm.pAAD = auth;			/* auth data */
	ctx->param.gcm.ulAADLen = authsize;		/* auth data len */

	ctx->mech.cm_param = (caddr_t)&ctx->param.gcm;
	ctx->mech.cm_param_len = sizeof (ctx->param.gcm);
}

/*
 * KCF doesn't need anything to happen in this call, but
 * wants that key when we call encrypt or decrypt, so
 * just stash the key here.
 */
int
nsmb_encrypt_init(smb_enc_ctx_t *ctxp,
    uint8_t *key, size_t keylen)
{
	bzero(&ctxp->ckey, sizeof (ctxp->ckey));
	ctxp->ckey.ck_format = CRYPTO_KEY_RAW;
	ctxp->ckey.ck_data = key;
	ctxp->ckey.ck_length = keylen * 8; /* in bits */

	return (0);
}

int
nsmb_decrypt_init(smb_enc_ctx_t *ctxp,
    uint8_t *key, size_t keylen)
{
	bzero(&ctxp->ckey, sizeof (ctxp->ckey));
	ctxp->ckey.ck_format = CRYPTO_KEY_RAW;
	ctxp->ckey.ck_data = key;
	ctxp->ckey.ck_length = keylen * 8; /* in bits */

	return (0);
}

/*
 * Nothing to cleanup after crypto_encrypt, crypto_decrypt
 * The user space variant has work to do.
 */
void
nsmb_enc_ctx_done(smb_enc_ctx_t *ctxp)
{
}

/*
 * Encrypt a whole message with scatter/gather (MBLK)
 */
int
nsmb_encrypt_mblks(smb_enc_ctx_t *ctxp, mblk_t *mp, size_t clearlen)
{
	crypto_data_t in_cd, out_cd;
	size_t inlen, outlen;
	int rv;

	inlen = clearlen;
	outlen = clearlen + SMB2_SIG_SIZE;
	ASSERT(msgsize(mp) >= outlen);

	bzero(&in_cd, sizeof (crypto_data_t));
	in_cd.cd_format = CRYPTO_DATA_MBLK;
	in_cd.cd_length = inlen;
	in_cd.cd_mp = mp;

	bzero(&out_cd, sizeof (crypto_data_t));
	out_cd.cd_format = CRYPTO_DATA_MBLK;
	out_cd.cd_length = outlen;
	out_cd.cd_mp = mp;

	rv = crypto_encrypt(&ctxp->mech, &in_cd,
	    &ctxp->ckey, tmpl, &out_cd, NULL);
	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "nsmb: crypto_encrypt failed: 0x%x", rv);
		return (-1);
	}

	return (0);
}

/*
 * Decrypt a whole message with scatter/gather (MBLK)
 */
int
nsmb_decrypt_mblks(smb_enc_ctx_t *ctxp, mblk_t *mp, size_t cipherlen)
{
	crypto_data_t in_cd, out_cd;
	size_t inlen, outlen;
	int rv;

	if (cipherlen <= SMB2_SIG_SIZE)
		return (-1);
	inlen = cipherlen;
	outlen = cipherlen - SMB2_SIG_SIZE;
	ASSERT(msgsize(mp) >= inlen);

	/* In is ciphertext */
	bzero(&in_cd, sizeof (crypto_data_t));
	in_cd.cd_format = CRYPTO_DATA_MBLK;
	in_cd.cd_length = inlen;
	in_cd.cd_mp = mp;

	/* Out is plaintext */
	bzero(&out_cd, sizeof (crypto_data_t));
	out_cd.cd_format = CRYPTO_DATA_MBLK;
	out_cd.cd_length = outlen;
	out_cd.cd_mp = mp;

	rv = crypto_decrypt(&ctxp->mech, &in_cd,
	    &ctxp->ckey, tmpl, &out_cd, NULL);
	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "nsmb: crypto_decrypt failed: 0x%x", rv);
		return (-1);
	}

	return (0);
}

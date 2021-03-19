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
 * Copyright 2021 RackTop Systems, Inc.
 */

/*
 * Helper functions for SMB3 encryption using PKCS#11
 *
 * There are two implementations of these functions:
 * This one (for user space) and another for kernel.
 * See: uts/common/fs/smbsrv/smb3_encrypt_kcf.c
 *
 * Contrary to what one might assume from the file name,
 * there should be NO SMB implementation knowledge here
 * beyond a few carefully selected things (smb_kcrypt.h).
 */

#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <smbsrv/smb_kcrypt.h>

#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <stdlib.h>
#include <strings.h>

/*
 * Common function to see if a mech is available.
 */
static int
find_mech(CK_MECHANISM_TYPE id)
{
	CK_SESSION_HANDLE hdl;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(id, &hdl);
	if (rv != CKR_OK) {
		return (-1);
	}
	(void) C_CloseSession(hdl);

	return (0);
}

/*
 * SMB3 encryption helpers:
 * (getmech, init, update, final)
 */

int
smb3_aes_ccm_getmech(smb_crypto_mech_t *mech)
{

	if (find_mech(CKM_AES_CCM) != 0) {
		cmn_err(CE_NOTE, "PKCS#11: no mech AES_CCM");
		return (-1);
	}

	mech->mechanism = CKM_AES_CCM;
	return (0);
}

int
smb3_aes_gcm_getmech(smb_crypto_mech_t *mech)
{

	if (find_mech(CKM_AES_GCM) != 0) {
		cmn_err(CE_NOTE, "PKCS#11: no mech CKM_AES_GCM");
		return (-1);
	}

	mech->mechanism = CKM_AES_GCM;
	return (0);
}

void
smb3_crypto_init_ccm_param(smb_enc_ctx_t *ctx,
    uint8_t *nonce, size_t noncesize,
    uint8_t *auth, size_t authsize,
    size_t datasize)
{

	ASSERT3U(noncesize, >=, SMB3_AES_CCM_NONCE_SIZE);

	/* CK_CCM_PARAMS */
	ctx->param.ccm.ulDataLen = datasize;
	ctx->param.ccm.pNonce = nonce;
	ctx->param.ccm.ulNonceLen = SMB3_AES_CCM_NONCE_SIZE;
	ctx->param.ccm.pAAD = auth;
	ctx->param.ccm.ulAADLen = authsize;
	ctx->param.ccm.ulMACLen = SMB2_SIG_SIZE;

	ctx->mech.pParameter = (caddr_t)&ctx->param.ccm;
	ctx->mech.ulParameterLen = sizeof (ctx->param.ccm);
}

void
smb3_crypto_init_gcm_param(smb_enc_ctx_t *ctx,
    uint8_t *nonce, size_t noncesize,
    uint8_t *auth, size_t authsize)
{

	ASSERT3U(noncesize, >=, SMB3_AES_GCM_NONCE_SIZE);

	/* CK_GCM_PARAMS */
	ctx->param.gcm.pIv = nonce;
	ctx->param.gcm.ulIvLen = SMB3_AES_GCM_NONCE_SIZE;
	ctx->param.gcm.pAAD = auth;			/* auth data */
	ctx->param.gcm.ulAADLen = authsize;		/* auth data len */
	ctx->param.gcm.ulTagBits = SMB2_SIG_SIZE << 3;	/* bytes to bits */

	ctx->mech.pParameter = (caddr_t)&ctx->param.gcm;
	ctx->mech.ulParameterLen = sizeof (ctx->param.gcm);
}

/*
 * Start the KCF encrypt session, load the key
 * If this returns zero, the caller should call
 * smb3_enc_ctx_done to cleanup the context,
 * even if there are intervening errors.
 */
int
smb3_encrypt_init(smb_enc_ctx_t *ctxp,
    uint8_t *key, size_t keylen)
{
	CK_OBJECT_HANDLE hkey = 0;
	CK_MECHANISM *mech = &ctxp->mech;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mech->mechanism, &ctxp->ctx);
	if (rv != CKR_OK)
		return (-1);

	rv = SUNW_C_KeyToObject(ctxp->ctx, mech->mechanism,
	    key, keylen, &hkey);
	if (rv != CKR_OK)
		return (-1);

	rv = C_EncryptInit(ctxp->ctx, mech, hkey);
	if (rv != CKR_OK) {
		cmn_err(CE_WARN, "C_EncryptInit failed: 0x%lx", rv);
	}
	(void) C_DestroyObject(ctxp->ctx, hkey);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Start the KCF decrypt session, load the key
 * If this returns zero, the caller should call
 * smb3_enc_ctx_done to cleanup the context,
 * even if there are intervening errors.
 */
int
smb3_decrypt_init(smb_enc_ctx_t *ctxp,
    uint8_t *key, size_t keylen)
{
	CK_OBJECT_HANDLE hkey = 0;
	CK_MECHANISM *mech = &ctxp->mech;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mech->mechanism, &ctxp->ctx);
	if (rv != CKR_OK)
		return (-1);

	rv = SUNW_C_KeyToObject(ctxp->ctx, mech->mechanism,
	    key, keylen, &hkey);
	if (rv != CKR_OK)
		return (-1);

	rv = C_DecryptInit(ctxp->ctx, mech, hkey);
	if (rv != CKR_OK) {
		cmn_err(CE_WARN, "C_DecryptInit failed: 0x%lx", rv);
	}
	(void) C_DestroyObject(ctxp->ctx, hkey);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Encrypt a whole message with scatter/gather (UIO)
 *
 * While the PKCS#11 implementation internally has the ability to
 * handle scatter/gather, it currently presents no interface for it.
 * As this library is used primarily for debugging, performance in
 * here is not a big concern, so we'll get around the limitation of
 * libpkcs11 by copying to/from a contiguous working buffer.
 */
int
smb3_encrypt_uio(smb_enc_ctx_t *ctxp, uio_t *in, uio_t *out)
{
	uint8_t *buf = NULL;
	size_t inlen, outlen;
	ulong_t tlen;
	int err, rc = -1;
	CK_RV rv;

	if (in->uio_resid <= 0)
		return (-1);
	inlen = in->uio_resid;
	outlen = inlen + 16;
	buf = malloc(outlen);
	if (buf == NULL)
		return (-1);

	/* Copy from uio segs to buf */
	err = uiomove(buf, inlen, UIO_WRITE, in);
	if (err != 0)
		goto out;

	/* Encrypt in-place in our work buffer. */
	tlen = outlen;
	rv = C_Encrypt(ctxp->ctx, buf, inlen, buf, &tlen);
	if (rv != CKR_OK) {
		cmn_err(CE_WARN, "C_Encrypt failed: 0x%lx", rv);
		goto out;
	}
	if (tlen != outlen) {
		cmn_err(CE_WARN, "smb3_encrypt_uio outlen %d vs %d",
		    (int)tlen, (int)outlen);
		goto out;
	}

	/* Copy from buf to uio segs */
	err = uiomove(buf, outlen, UIO_READ, out);
	if (err != 0)
		goto out;

	rc = 0;
out:
	free(buf);

	return (rc);
}

int
smb3_decrypt_uio(smb_enc_ctx_t *ctxp, uio_t *in, uio_t *out)
{
	uint8_t *buf = NULL;
	size_t inlen, outlen;
	ulong_t tlen;
	int err, rc = -1;
	CK_RV rv;

	if (in->uio_resid <= 16)
		return (-1);
	inlen = in->uio_resid;
	outlen = inlen - 16;
	buf = malloc(inlen);
	if (buf == NULL)
		return (-1);

	/* Copy from uio segs to buf */
	err = uiomove(buf, inlen, UIO_WRITE, in);
	if (err != 0)
		goto out;

	/* Decrypt in-place in our work buffer. */
	tlen = outlen;
	rv = C_Decrypt(ctxp->ctx, buf, inlen, buf, &tlen);
	if (rv != CKR_OK) {
		cmn_err(CE_WARN, "C_Decrypt failed: 0x%lx", rv);
		goto out;
	}
	if (tlen != outlen) {
		cmn_err(CE_WARN, "smb3_decrypt_uio outlen %d vs %d",
		    (int)tlen, (int)outlen);
		goto out;
	}

	/* Copy from buf to uio segs */
	err = uiomove(buf, outlen, UIO_READ, out);
	if (err != 0)
		goto out;

	rc = 0;
out:
	free(buf);

	return (rc);
}

void
smb3_enc_ctx_done(smb_enc_ctx_t *ctxp)
{
	if (ctxp->ctx != 0) {
		(void) C_CloseSession(ctxp->ctx);
		ctxp->ctx = 0;
	}
}

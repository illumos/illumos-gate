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
 * Copyright 2021-2024 RackTop Systems, Inc.
 */

/*
 * Helper functions for SMB3 encryption using PKCS#11
 *
 * There are two implementations of these functions:
 * This one (for user space) and another for kernel.
 * See: uts/common/fs/smbclnt/netsmb/smb_crypt_kcf.c
 *
 * Contrary to what one might assume from the file name,
 * there should be NO SMB implementation knowledge here
 * beyond a few carefully selected things (nsmb_kcrypt.h).
 */

#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <netsmb/nsmb_kcrypt.h>

#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <stdlib.h>
#include <strings.h>

size_t	msgsize(mblk_t *);
static int copy_mblks(void *buf, size_t buflen, enum uio_rw, mblk_t *m);

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
nsmb_aes_ccm_getmech(smb_crypto_mech_t *mech)
{

	if (find_mech(CKM_AES_CCM) != 0) {
		cmn_err(CE_NOTE, "PKCS#11: no mech AES_CCM");
		return (-1);
	}

	mech->mechanism = CKM_AES_CCM;
	return (0);
}

int
nsmb_aes_gcm_getmech(smb_crypto_mech_t *mech)
{

	if (find_mech(CKM_AES_GCM) != 0) {
		cmn_err(CE_NOTE, "PKCS#11: no mech AES_GCM");
		return (-1);
	}

	mech->mechanism = CKM_AES_GCM;
	return (0);
}

void
nsmb_crypto_init_ccm_param(smb_enc_ctx_t *ctx,
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
nsmb_crypto_init_gcm_param(smb_enc_ctx_t *ctx,
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
 * nsmb_enc_ctx_done to cleanup the context,
 * even if there are intervening errors.
 */
int
nsmb_encrypt_init(smb_enc_ctx_t *ctxp,
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
 * nsmb_enc_ctx_done to cleanup the context,
 * even if there are intervening errors.
 */
int
nsmb_decrypt_init(smb_enc_ctx_t *ctxp,
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

void
nsmb_enc_ctx_done(smb_enc_ctx_t *ctxp)
{
	if (ctxp->ctx != 0) {
		(void) C_CloseSession(ctxp->ctx);
		ctxp->ctx = 0;
	}
}

/*
 * Encrypt a whole message with scatter/gather (MBLK)
 *
 * While the PKCS#11 implementation internally has the ability to
 * handle scatter/gather, it currently presents no interface for it.
 * As this library is used primarily for debugging, performance in
 * here is not a big concern, so we'll get around the limitation of
 * libpkcs11 by copying to/from a contiguous working buffer.
 */
int
nsmb_encrypt_mblks(smb_enc_ctx_t *ctxp, mblk_t *mp, size_t clearlen)
{
	uint8_t *buf;
	size_t inlen, outlen;
	ulong_t tlen;
	int err;
	CK_RV rv;

	inlen = clearlen;
	outlen = clearlen + SMB2_SIG_SIZE;
	ASSERT(msgsize(mp) >= outlen);

	buf = malloc(outlen);
	if (buf == NULL)
		return (-1);

	/* Copy from mblk chain to buf */
	err = copy_mblks(buf, inlen, UIO_WRITE, mp);
	if (err != 0)
		return (-1);

	/* Encrypt in-place in our work buffer. */
	tlen = outlen;
	rv = C_Encrypt(ctxp->ctx, buf, inlen, buf, &tlen);
	if (rv != CKR_OK) {
		cmn_err(CE_WARN, "C_Encrypt failed: 0x%lx", rv);
		return (-1);
	}
	if (tlen != outlen) {
		cmn_err(CE_WARN, "nsmb_encrypt_mblks outlen %d vs %d",
		    (int)tlen, (int)outlen);
		return (-1);
	}

	/* Copy from buf to mblk segs */
	err = copy_mblks(buf, outlen, UIO_READ, mp);
	if (err != 0)
		return (-1);

	return (0);
}

/*
 * Decrypt a whole message with scatter/gather (MBLK)
 */
int
nsmb_decrypt_mblks(smb_enc_ctx_t *ctxp, mblk_t *mp, size_t cipherlen)
{
	uint8_t *buf;
	size_t inlen, outlen;
	ulong_t tlen;
	int err;
	CK_RV rv;

	if (cipherlen <= SMB2_SIG_SIZE)
		return (-1);
	inlen = cipherlen;
	outlen = cipherlen - SMB2_SIG_SIZE;
	ASSERT(msgsize(mp) >= inlen);

	buf = malloc(inlen);
	if (buf == NULL)
		return (-1);

	/* Copy from mblk chain to buf */
	err = copy_mblks(buf, inlen, UIO_WRITE, mp);
	if (err != 0)
		return (-1);

	/* Decrypt in-place in our work buffer. */
	tlen = outlen;
	rv = C_Decrypt(ctxp->ctx, buf, inlen, buf, &tlen);
	if (rv != CKR_OK) {
		cmn_err(CE_WARN, "C_Decrypt failed: 0x%lx", rv);
		return (-1);
	}
	if (tlen != outlen) {
		cmn_err(CE_WARN, "nsmb_decrypt_mblks outlen %d vs %d",
		    (int)tlen, (int)outlen);
		return (-1);
	}

	/* Copy from buf to mblk segs */
	err = copy_mblks(buf, outlen, UIO_READ, mp);
	if (err != 0)
		return (-1);

	return (0);
}

static int
copy_mblks(void *buf, size_t buflen, enum uio_rw rw, mblk_t *m)
{
	uchar_t *p = buf;
	size_t rem = buflen;
	size_t len;

	while (rem > 0) {
		if (m == NULL)
			return (-1);
		ASSERT(m->b_datap->db_type == M_DATA);
		len = MBLKL(m);
		if (len > rem)
			len = rem;
		if (rw == UIO_READ) {
			/* buf to mblks */
			bcopy(p, m->b_rptr, len);
		} else {
			/* mblks to buf */
			bcopy(m->b_rptr, p, len);
		}
		m = m->b_cont;
		p += len;
		rem -= len;
	}
	return (0);
}

size_t
msgsize(mblk_t *mp)
{
	size_t	n = 0;

	for (; mp != NULL; mp = mp->b_cont)
		n += MBLKL(mp);

	return (n);
}

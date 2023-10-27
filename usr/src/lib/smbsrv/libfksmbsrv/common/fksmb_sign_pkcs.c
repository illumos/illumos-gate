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
 * Copyright 2022-2023 RackTop Systems, Inc.
 */

/*
 * Helper functions for SMB signing using PKCS#11
 *
 * There are two implementations of these functions:
 * This one (for user space) and another for kernel.
 * See: uts/common/fs/smbsrv/smb_sign_kcf.c
 */

#include <stdlib.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kcrypt.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

/*
 * Common function to see if a mech is available.
 */
static int
find_mech(smb_crypto_mech_t *mech, ulong_t mid)
{
	CK_SESSION_HANDLE hdl;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mid, &hdl);
	if (rv != CKR_OK) {
		cmn_err(CE_NOTE, "PKCS#11: no mech 0x%x",
		    (unsigned int)mid);
		return (-1);
	}
	(void) C_CloseSession(hdl);

	mech->mechanism = mid;
	mech->pParameter = NULL;
	mech->ulParameterLen = 0;
	return (0);
}

/*
 * SMB1 signing helpers:
 * (getmech, init, update, final)
 */

/*
 * Find out if we have this mech.
 */
int
smb_md5_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, CKM_MD5));
}

/*
 * Start PKCS#11 session.
 */
int
smb_md5_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech)
{
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mech->mechanism, ctxp);
	if (rv != CKR_OK)
		return (-1);

	rv = C_DigestInit(*ctxp, mech);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Digest one segment
 */
int
smb_md5_update(smb_sign_ctx_t ctx, void *buf, size_t len)
{
	CK_RV rv;

	rv = C_DigestUpdate(ctx, buf, len);
	if (rv != CKR_OK)
		(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Get the final digest.
 */
int
smb_md5_final(smb_sign_ctx_t ctx, uint8_t *digest16)
{
	CK_ULONG len = MD5_DIGEST_LENGTH;
	CK_RV rv;

	rv = C_DigestFinal(ctx, digest16, &len);
	(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * SMB2 signing helpers:
 * (getmech, init, update, final)
 */

/*
 * Find out if we have this mech.
 */
int
smb2_hmac_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, CKM_SHA256_HMAC_GENERAL));
}

int
smb3_cmac_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, CKM_AES_CMAC));
}

/*
 * Note, the SMB2 signature is the first 16 bytes of the digest,
 * even in the case of SHA256 HMAC (32-byte digest).
 *
 * CMAC has no parameter.
 */
void
smb2_sign_init_hmac_param(smb_enc_ctx_t *ctx, ulong_t hmac_len)
{
	ctx->param.hmac = hmac_len;

	ctx->mech.pParameter = (caddr_t)&ctx->param.hmac;
	ctx->mech.ulParameterLen = sizeof (ctx->param.hmac);
}

/*
 * Start PKCS#11 session, load the key.
 */
int
smb2_mac_init(smb_enc_ctx_t *ctxp, uint8_t *key, size_t key_len)
{
	CK_OBJECT_HANDLE hkey = 0;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(ctxp->mech.mechanism, &ctxp->ctx);
	if (rv != CKR_OK)
		return (-1);

	rv = SUNW_C_KeyToObject(ctxp->ctx, ctxp->mech.mechanism,
	    key, key_len, &hkey);
	if (rv != CKR_OK)
		return (-1);

	rv = C_SignInit(ctxp->ctx, &ctxp->mech, hkey);
	(void) C_DestroyObject(ctxp->ctx, hkey);
	if (rv != CKR_OK) {
		(void) C_CloseSession(ctxp->ctx);
		return (-1);
	}

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Digest one segment
 */
int
smb2_mac_update(smb_enc_ctx_t *ctxp, uint8_t *in, size_t len)
{
	CK_RV rv;

	rv = C_SignUpdate(ctxp->ctx, in, len);
	if (rv != CKR_OK)
		(void) C_CloseSession(ctxp->ctx);

	return (rv == CKR_OK ? 0 : -1);
}

int
smb2_mac_final(smb_enc_ctx_t *ctxp, uint8_t *digest16)
{
	CK_ULONG len = SMB2_SIG_SIZE;
	CK_RV rv;

	rv = C_SignFinal(ctxp->ctx, digest16, &len);
	(void) C_CloseSession(ctxp->ctx);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * One-shot HMAC function used in smb3_kdf
 */
int
smb2_hmac_one(smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len,
    uint8_t *data, size_t data_len,
    uint8_t *mac, size_t mac_len)
{
	CK_SESSION_HANDLE hssn = 0;
	CK_OBJECT_HANDLE hkey = 0;
	CK_ULONG ck_maclen = mac_len;
	CK_MAC_GENERAL_PARAMS out_len = mac_len;
	CK_RV rv;
	int rc = 0;

	rv = SUNW_C_GetMechSession(mech->mechanism, &hssn);
	if (rv != CKR_OK)
		return (-1);

	rv = SUNW_C_KeyToObject(hssn, mech->mechanism,
	    key, key_len, &hkey);
	if (rv != CKR_OK) {
		rc = -2;
		goto out;
	}

	mech->pParameter = (caddr_t)&out_len;
	mech->ulParameterLen = sizeof (out_len);

	rv = C_SignInit(hssn, mech, hkey);
	if (rv != CKR_OK) {
		rc = -3;
		goto out;
	}

	rv = C_Sign(hssn, data, data_len, mac, &ck_maclen);
	if (rv != CKR_OK) {
		rc = -4;
		goto out;
	}

	if (ck_maclen != mac_len) {
		rc = -5;
		goto out;
	}
	rc = 0;

out:
	if (hkey != 0)
		(void) C_DestroyObject(hssn, hkey);
	if (hssn != 0)
		(void) C_CloseSession(hssn);
	mech->pParameter = NULL;
	mech->ulParameterLen = 0;

	return (rc);
}

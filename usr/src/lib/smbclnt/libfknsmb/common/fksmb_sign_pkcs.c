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
 * Copyright 2022-2024 RackTop Systems, Inc.
 */

/*
 * Helper functions for SMB signing using PKCS#11
 *
 * There are two implementations of these functions:
 * This one (for user space) and another for kernel.
 * See: uts/common/fs/smbclnt/netsmb/smb_sign_kcf.c
 *
 * Contrary to what one might assume from the file name,
 * there should be NO SMB implementation knowledge here
 * beyond a few carefully selected things (nsmb_kcrypt.h).
 */

#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <netsmb/nsmb_kcrypt.h>

#include <stdlib.h>
#include <strings.h>
#include <sys/cmn_err.h>

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
nsmb_md5_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, CKM_MD5));
}

/*
 * Start PKCS#11 session.
 */
int
nsmb_md5_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech)
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
nsmb_md5_update(smb_sign_ctx_t ctx, void *buf, size_t len)
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
nsmb_md5_final(smb_sign_ctx_t ctx, uint8_t *digest16)
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
nsmb_hmac_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, CKM_SHA256_HMAC));
}

/*
 * Start PKCS#11 session, load the key.
 */
int
nsmb_hmac_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len)
{
	CK_OBJECT_HANDLE hkey = 0;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mech->mechanism, ctxp);
	if (rv != CKR_OK)
		return (-1);

	rv = SUNW_C_KeyToObject(*ctxp, mech->mechanism,
	    key, key_len, &hkey);
	if (rv != CKR_OK)
		return (-1);

	rv = C_SignInit(*ctxp, mech, hkey);
	(void) C_DestroyObject(*ctxp, hkey);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Digest one segment
 */
int
nsmb_hmac_update(smb_sign_ctx_t ctx, uint8_t *in, size_t len)
{
	CK_RV rv;

	rv = C_SignUpdate(ctx, in, len);
	if (rv != CKR_OK)
		(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Note, the SMB2 signature is the first 16 bytes of the
 * 32-byte SHA256 HMAC digest.  This is specifically for
 * SMB2 signing, and NOT a generic HMAC function.
 */
int
nsmb_hmac_final(smb_sign_ctx_t ctx, uint8_t *digest16)
{
	uint8_t full_digest[SHA256_DIGEST_LENGTH];
	CK_ULONG len = SHA256_DIGEST_LENGTH;
	CK_RV rv;

	rv = C_SignFinal(ctx, full_digest, &len);
	if (rv == CKR_OK)
		bcopy(full_digest, digest16, 16);

	(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * One-shot HMAC function used in smb3_kdf
 */
int
nsmb_hmac_one(smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len,
    uint8_t *data, size_t data_len,
    uint8_t *mac, size_t mac_len)
{
	CK_SESSION_HANDLE hssn = 0;
	CK_OBJECT_HANDLE hkey = 0;
	CK_ULONG ck_maclen = mac_len;
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

	return (rc);
}

/*
 * SMB3 signing helpers:
 * (getmech, init, update, final)
 */

/*
 * Find out if we have this mech.
 */
int
nsmb_cmac_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, CKM_AES_CMAC));
}

/*
 * Start PKCS#11 session, load the key.
 */
int
nsmb_cmac_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len)
{
	CK_OBJECT_HANDLE hkey = 0;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mech->mechanism, ctxp);
	if (rv != CKR_OK)
		return (-1);

	rv = SUNW_C_KeyToObject(*ctxp, mech->mechanism,
	    key, key_len, &hkey);
	if (rv != CKR_OK) {
		(void) C_CloseSession(*ctxp);
		return (-1);
	}

	rv = C_SignInit(*ctxp, mech, hkey);
	(void) C_DestroyObject(*ctxp, hkey);
	if (rv != CKR_OK) {
		(void) C_CloseSession(*ctxp);
		return (-1);
	}

	return (0);
}

/*
 * Digest one segment
 */
int
nsmb_cmac_update(smb_sign_ctx_t ctx, uint8_t *in, size_t len)
{
	CK_RV rv;

	rv = C_SignUpdate(ctx, in, len);
	if (rv != CKR_OK)
		(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Note, the SMB2 signature is just the AES CMAC digest.
 * (both are 16 bytes long)
 */
int
nsmb_cmac_final(smb_sign_ctx_t ctx, uint8_t *digest)
{
	CK_ULONG len = SMB2_SIG_SIZE;
	CK_RV rv;

	rv = C_SignFinal(ctx, digest, &len);
	(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
}

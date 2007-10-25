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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/md4.h>
#include <sys/types.h>
#include <string.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <cryptoutil.h>
#include <smbsrv/libsmb.h>

static void smb_auth_keyprep(const unsigned char *pwstr, unsigned char *keystr);

/*
 * smb_auth_md4
 *
 * Compute an MD4 digest.
 */
int
smb_auth_md4(unsigned char *result, unsigned char *input, int length)
{
	MD4_CTX md4_context;

	MD4Init(&md4_context);
	MD4Update(&md4_context, input, length);
	MD4Final(result, &md4_context);
	return (SMBAUTH_SUCCESS);
}

int
smb_auth_hmac_md5(unsigned char *data,
	int data_len,
	unsigned char *key,
	int key_len,
	unsigned char *digest)
{
	CK_RV rv;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE hKey;
	CK_SESSION_HANDLE hSession;
	unsigned long diglen = MD_DIGEST_LEN;

	mechanism.mechanism = CKM_MD5_HMAC;
	mechanism.pParameter = 0;
	mechanism.ulParameterLen = 0;
	rv = SUNW_C_GetMechSession(mechanism.mechanism, &hSession);
	if (rv != CKR_OK) {
		return (SMBAUTH_FAILURE);
	}

	rv = SUNW_C_KeyToObject(hSession, mechanism.mechanism,
	    key, key_len, &hKey);
	if (rv != CKR_OK) {
		(void) C_CloseSession(hSession);
		return (SMBAUTH_FAILURE);
	}

	/* Initialize the digest operation in the session */
	rv = C_SignInit(hSession, &mechanism, hKey);
	if (rv != CKR_OK) {
		(void) C_DestroyObject(hSession, hKey);
		(void) C_CloseSession(hSession);
		return (SMBAUTH_FAILURE);
	}
	rv = C_SignUpdate(hSession, (CK_BYTE_PTR)data, data_len);
	if (rv != CKR_OK) {
		(void) C_DestroyObject(hSession, hKey);
		(void) C_CloseSession(hSession);
		return (SMBAUTH_FAILURE);
	}
	rv = C_SignFinal(hSession, (CK_BYTE_PTR)digest, &diglen);
	if (rv != CKR_OK) {
		(void) C_DestroyObject(hSession, hKey);
		(void) C_CloseSession(hSession);
		return (SMBAUTH_FAILURE);
	}
	(void) C_DestroyObject(hSession, hKey);
	(void) C_CloseSession(hSession);
	if (diglen != MD_DIGEST_LEN) {
		return (SMBAUTH_FAILURE);
	}
	return (SMBAUTH_SUCCESS);
}

int
smb_auth_DES(unsigned char *Result, int ResultLen,
    unsigned char *Key, int KeyLen,
    unsigned char *Data, int DataLen)
{
	CK_RV rv;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE hKey;
	CK_SESSION_HANDLE hSession;
	CK_ULONG ciphertext_len;
	uchar_t des_key[8];
	int error = 0;
	int K, D;
	int k, d;

	/* Calculate proper number of iterations */
	K = KeyLen / 7;
	D = DataLen / 8;

	if (ResultLen < (K * 8 * D)) {
		return (SMBAUTH_FAILURE);
	}

	/*
	 * Use SUNW convenience function to initialize the cryptoki
	 * library, and open a session with a slot that supports
	 * the mechanism we plan on using.
	 */
	mechanism.mechanism = CKM_DES_ECB;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;
	rv = SUNW_C_GetMechSession(mechanism.mechanism, &hSession);
	if (rv != CKR_OK) {
		return (SMBAUTH_FAILURE);
	}

	for (k = 0; k < K; k++) {
		smb_auth_keyprep(&Key[k * 7], des_key);
		rv = SUNW_C_KeyToObject(hSession, mechanism.mechanism,
		    des_key, 8, &hKey);
		if (rv != CKR_OK) {
			error = 1;
			goto exit_session;
		}
		/* Initialize the encryption operation in the session */
		rv = C_EncryptInit(hSession, &mechanism, hKey);
		if (rv != CKR_OK) {
			error = 1;
			goto exit_encrypt;
		}
		ciphertext_len = DataLen;
		for (d = 0; d < D; d++) {
			/* Read in the data and encrypt this portion */
			rv = C_EncryptUpdate(hSession,
			    (CK_BYTE_PTR)Data + (d * 8), 8,
			    &Result[(k * (8 * D)) + (d * 8)],
			    &ciphertext_len);
			if (rv != CKR_OK) {
				error = 1;
				goto exit_encrypt;
			}
		}
		(void) C_DestroyObject(hSession, hKey);
	}
	goto exit_session;

exit_encrypt:
	(void) C_DestroyObject(hSession, hKey);
exit_session:
	(void) C_CloseSession(hSession);

	if (error)
		return (SMBAUTH_FAILURE);

	return (SMBAUTH_SUCCESS);
}

/*
 * smb_auth_keyprep
 *
 * Takes 7  bytes of keying material and expands it into 8 bytes with
 * the keying material in the upper 7 bits of each byte.
 */
static void
smb_auth_keyprep(const unsigned char *pwstr, unsigned char *keystr)
{
	keystr[0] = pwstr[0];
	keystr[1] = (pwstr[0] << 7) | (pwstr[1] >> 1);
	keystr[2] = (pwstr[1] << 6) | (pwstr[2] >> 2);
	keystr[3] = (pwstr[2] << 5) | (pwstr[3] >> 3);
	keystr[4] = (pwstr[3] << 4) | (pwstr[4] >> 4);
	keystr[5] = (pwstr[4] << 3) | (pwstr[5] >> 5);
	keystr[6] = (pwstr[5] << 2) | (pwstr[6] >> 6);
	keystr[7] = pwstr[6] << 1;
}

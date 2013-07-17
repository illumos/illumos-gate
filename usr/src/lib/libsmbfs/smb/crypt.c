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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Crypto support, using libpkcs11
 *
 * Some code copied from the server: libsmb smb_crypt.c
 * with minor changes, i.e. errno.h return values.
 * XXX: Later, make the server use these.
 */

#include <sys/types.h>
#include <sys/md4.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <cryptoutil.h>

#include "smb_crypt.h"

static void
smb_initlmkey(uchar_t *keyout, const uchar_t *keyin);

/*
 * Like libsmb smb_auth_DES,
 * but use uchar_t, return errno.
 */
int
smb_encrypt_DES(uchar_t *Result, int ResultLen,
    const uchar_t *Key, int KeyLen,
    const uchar_t *Data, int DataLen)
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

	/*
	 * Calculate proper number of iterations.
	 * Known call cases include:
	 *   ResultLen=16, KeyLen=14, DataLen=8
	 *   ResultLen=24, KeyLen=21, DataLen=8
	 *   ResultLen=16, KeyLen=14, DataLen=16
	 */
	K = KeyLen / 7;
	D = DataLen / 8;
	if ((KeyLen % 7) || (DataLen % 8))
		return (EINVAL);
	if (K == 0 || D == 0)
		return (EINVAL);
	if (ResultLen < (K * 8))
		return (EINVAL);

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
		return (ENOTSUP);
	}

	for (d = k = 0; k < K; k++, d++) {
		/* Cycle the input again, as necessary. */
		if (d == D)
			d = 0;
		smb_initlmkey(des_key, &Key[k * 7]);
		rv = SUNW_C_KeyToObject(hSession, mechanism.mechanism,
		    des_key, 8, &hKey);
		if (rv != CKR_OK) {
			error = EIO;
			goto exit_session;
		}
		/* Initialize the encryption operation in the session */
		rv = C_EncryptInit(hSession, &mechanism, hKey);
		if (rv != CKR_OK) {
			error = EIO;
			goto exit_encrypt;
		}
		ciphertext_len = 8;

		/* Read in the data and encrypt this portion */
		rv = C_EncryptUpdate(hSession,
		    (CK_BYTE_PTR)Data + (d * 8), 8,
		    (CK_BYTE_PTR)Result + (k * 8),
		    &ciphertext_len);
		if (rv != CKR_OK) {
			error = EIO;
			goto exit_encrypt;
		}

		(void) C_DestroyObject(hSession, hKey);
	}
	goto exit_session;

exit_encrypt:
	(void) C_DestroyObject(hSession, hKey);
exit_session:
	(void) C_CloseSession(hSession);

	return (error);
}

/*
 * See "Netlogon Credential Computation" section of MS-NRPC document.
 * Same as in libsmb, but output arg first.
 */
static void
smb_initlmkey(uchar_t *keyout, const uchar_t *keyin)
{
	int i;

	keyout[0] = keyin[0] >> 0x01;
	keyout[1] = ((keyin[0] & 0x01) << 6) | (keyin[1] >> 2);
	keyout[2] = ((keyin[1] & 0x03) << 5) | (keyin[2] >> 3);
	keyout[3] = ((keyin[2] & 0x07) << 4) | (keyin[3] >> 4);
	keyout[4] = ((keyin[3] & 0x0f) << 3) | (keyin[4] >> 5);
	keyout[5] = ((keyin[4] & 0x1f) << 2) | (keyin[5] >> 6);
	keyout[6] = ((keyin[5] & 0x3f) << 1) | (keyin[6] >> 7);
	keyout[7] = keyin[6] & 0x7f;

	for (i = 0; i < 8; i++)
		keyout[i] = (keyout[i] << 1) & 0xfe;
}

/*
 * CKM_RC4
 */
int
smb_encrypt_RC4(uchar_t *Result, int ResultLen,
	const uchar_t *Key, int KeyLen,
	const uchar_t *Data, int DataLen)
{
	CK_RV rv;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE hKey;
	CK_SESSION_HANDLE hSession;
	CK_ULONG ciphertext_len;
	int error = EIO;

	/*
	 * Use SUNW convenience function to initialize the cryptoki
	 * library, and open a session with a slot that supports
	 * the mechanism we plan on using.
	 */
	mechanism.mechanism = CKM_RC4;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;
	rv = SUNW_C_GetMechSession(mechanism.mechanism, &hSession);
	if (rv != CKR_OK) {
		return (ENOTSUP);
	}

	rv = SUNW_C_KeyToObject(hSession, mechanism.mechanism,
	    Key, KeyLen, &hKey);
	if (rv != CKR_OK)
		goto exit_session;

	/* Initialize the encryption operation in the session */
	rv = C_EncryptInit(hSession, &mechanism, hKey);
	if (rv != CKR_OK)
		goto exit_encrypt;

	ciphertext_len = ResultLen;
	rv = C_EncryptUpdate(hSession,
	    (CK_BYTE_PTR)Data, DataLen,
	    (CK_BYTE_PTR)Result, &ciphertext_len);
	if (rv == CKR_OK)
		error = 0;

exit_encrypt:
	(void) C_DestroyObject(hSession, hKey);
exit_session:
	(void) C_CloseSession(hSession);

	return (error);
}

/*
 * Get some random bytes from /dev/urandom
 *
 * There may be a preferred way to call this via libpkcs11
 * XXX: (see: C_GenerateRandom, etc. -- later...)
 * Just read from /dev/urandom for now.
 */
int
smb_get_urandom(void *data, size_t dlen)
{
	int fd, rlen;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return (errno);

	rlen = read(fd, data, dlen);
	close(fd);

	if (rlen < 0)
		return (errno);
	if (rlen < dlen)
		return (EIO);
	return (0);
}

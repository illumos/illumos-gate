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
 * Copyright 2018, Joyent, Inc.
 */

/*
 * Encryption and Decryption Functions
 * (as defined in PKCS#11 spec sections 11.8 and 11.9)
 */

#include "metaGlobal.h"


/*
 * meta_EncryptInit
 *
 */
CK_RV
meta_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *key;

	if (pMechanism == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hKey, &key);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_operation_init_defer(CKF_ENCRYPT, session, pMechanism, key);

	OBJRELEASE(key);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_Encrypt
 *
 */
CK_RV
meta_Encrypt(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pulEncryptedDataLen == NULL) {
		meta_operation_cleanup(session, CKF_ENCRYPT, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Allow pData to be NULL as long as the length is 0 in order to
	 * support ciphers that permit 0 byte inputs (e.g. combined mode
	 * ciphers), otherwise consider pData being NULL as invalid.
	 */
	if (pData == NULL && ulDataLen != 0) {
		meta_operation_cleanup(session, CKF_ENCRYPT, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_ENCRYPT, MODE_SINGLE, session, NULL,
	    pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_EncryptUpdate
 *
 */
CK_RV
meta_EncryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pPart == NULL || pulEncryptedPartLen == NULL) {
		meta_operation_cleanup(session, CKF_ENCRYPT, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_ENCRYPT, MODE_UPDATE, session, NULL,
	    pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_EncryptFinal
 *
 */
CK_RV
meta_EncryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pulLastEncryptedPartLen == NULL) {
		meta_operation_cleanup(session, CKF_ENCRYPT, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_ENCRYPT, MODE_FINAL, session, NULL,
	    NULL, 0, pLastEncryptedPart, pulLastEncryptedPartLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DecryptInit
 *
 */
CK_RV
meta_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	meta_session_t *session;
	meta_object_t *key;

	if (pMechanism == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	rv = meta_handle2object(hKey, &key);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = meta_operation_init_defer(CKF_DECRYPT, session, pMechanism, key);

	OBJRELEASE(key);
	REFRELEASE(session);

	return (rv);
}


/*
 * meta_Decrypt
 *
 */
CK_RV
meta_Decrypt(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pEncryptedData == NULL || pulDataLen == NULL) {
		meta_operation_cleanup(session, CKF_DECRYPT, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_DECRYPT, MODE_SINGLE, session, NULL,
	    pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DecryptUpdate
 *
 */
CK_RV
meta_DecryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pEncryptedPart == NULL || pulPartLen == NULL) {
		meta_operation_cleanup(session, CKF_DECRYPT, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_DECRYPT, MODE_UPDATE, session, NULL,
	    pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);

	REFRELEASE(session);

	return (rv);
}


/*
 * meta_DecryptFinal
 *
 */
CK_RV
meta_DecryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv;
	meta_session_t *session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (pulLastPartLen == NULL) {
		meta_operation_cleanup(session, CKF_DECRYPT, FALSE);
		REFRELEASE(session);
		return (CKR_ARGUMENTS_BAD);
	}

	rv = meta_do_operation(CKF_DECRYPT, MODE_FINAL, session, NULL,
	    NULL, 0, pLastPart, pulLastPartLen);

	REFRELEASE(session);

	return (rv);
}

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
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softOps.h"


CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	soft_object_t	*key_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv != CKR_OK)
		goto clean_exit;

	/* Check to see if key object allows for encryption. */
	if (!(key_p->bool_attr_mask & ENCRYPT_BOOL_ON)) {
		rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto clean_exit1;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Check to see if encrypt operation is already active. */
	if (session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE) {
		/* free the memory to avoid memory leak */
		soft_crypt_cleanup(session_p, B_TRUE, lock_held);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_Encrypt or C_EncryptFinal to actually obtain the final piece
	 * of ciphertext.
	 */
	session_p->encrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_encrypt_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->encrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

clean_exit1:
	OBJ_REFRELE(key_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * How to handle zero input length depends on the mechanism in use.
	 * For secret key mechanisms, unpadded ones yield zero length output,
	 * but padded ones always result in greater than zero length output.
	 */
	if (pData == NULL && ulDataLen != 0) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/*
	 * Only check if pulEncryptedDataLen is NULL.
	 * No need to check if pEncryptedData is NULL because
	 * application might just ask for the length of buffer to hold
	 * the ciphertext.
	 */
	if (pulEncryptedDataLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Application must call C_EncryptInit before calling C_Encrypt. */
	if (!(session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * C_Encrypt must be called without intervening C_EncryptUpdate
	 * calls.
	 */
	if (session_p->encrypt.flags & CRYPTO_OPERATION_UPDATE) {
		/*
		 * C_Encrypt can not be used to terminate a multi-part
		 * operation, so we'll leave the active encrypt operation
		 * flag on and let the application continue with the
		 * encrypt update operation.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_encrypt(session_p, pData, ulDataLen, pEncryptedData,
	    pulEncryptedDataLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pEncryptedData == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active encrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the ciphertext.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* Clear context, free key, and release session counter */
	soft_crypt_cleanup(session_p, B_TRUE, B_FALSE);
	return (rv);
}


CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Only check if input buffer is null.  How to handle zero input
	 * length depends on the mechanism in use.  For secret key mechanisms,
	 * unpadded ones yeild zero length output, but padded ones always
	 * result in greater than zero length output.
	 */
	if (pPart == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/*
	 * Only check if pulEncryptedPartLen is NULL.
	 * No need to check if pEncryptedPart is NULL because
	 * application might just ask for the length of buffer to hold
	 * the ciphertext.
	 */
	if (pulEncryptedPartLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Application must call C_EncryptInit before calling
	 * C_EncryptUpdate.
	 */
	if (!(session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->encrypt.flags |= CRYPTO_OPERATION_UPDATE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_encrypt_update(session_p, pPart, ulPartLen,
	    pEncryptedPart, pulEncryptedPartLen);

	/*
	 * If CKR_OK or CKR_BUFFER_TOO_SMALL, don't terminate the
	 * current encryption operation.
	 */
	if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL)) {
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current encrypt
	 * operation by resetting the active and update flags.
	 */
	soft_crypt_cleanup(session_p, B_TRUE, lock_held);

	return (rv);
}


CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pulLastEncryptedPartLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Application must call C_EncryptInit before calling
	 * C_EncryptFinal.
	 */
	if (!(session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_encrypt_final(session_p, pLastEncryptedPart,
	    pulLastEncryptedPartLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pLastEncryptedPart == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active encrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the ciphertext.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

	/* Terminates the active encrypt operation. */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->encrypt.flags = 0;
	lock_held = B_TRUE;
	SES_REFRELE(session_p, lock_held);

	return (rv);

clean_exit:
	/* Terminates the active encrypt operation. */
	soft_crypt_cleanup(session_p, B_TRUE, lock_held);

	return (rv);
}

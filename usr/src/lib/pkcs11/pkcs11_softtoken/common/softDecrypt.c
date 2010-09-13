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
 */

#include <pthread.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softOps.h"


CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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

	/* Check to see if key object allows for decryption. */
	if (!(key_p->bool_attr_mask & DECRYPT_BOOL_ON)) {
		rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto clean_exit1;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Check to see if decrypt operation is already active. */
	if (session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE) {
		/* free the memory to avoid memory leak */
		soft_crypt_cleanup(session_p, B_FALSE, lock_held);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_Decrypt or C_DecryptFinal to actually obtain the final piece
	 * of plaintext.
	 */
	session_p->decrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_decrypt_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->decrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

clean_exit1:
	OBJ_REFRELE(key_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obatin the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Only check if input buffer is null.  How to handle zero input
	 * length depents on the mechanism in use.  For secret key mechanisms,
	 * unpadded ones yield zero length output, but padded ones always
	 * result in smaller than original, possibly zero, length output.
	 */
	if (pEncryptedData == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/*
	 * No need to check pData because application might
	 * just want to know the length of decrypted data.
	 */
	if (pulDataLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Application must call C_DecryptInit before calling C_Decrypt. */
	if (!(session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * C_Decrypt must be called without intervening C_DecryptUpdate
	 * calls.
	 */
	if (session_p->decrypt.flags & CRYPTO_OPERATION_UPDATE) {
		/*
		 * C_Decrypt can not be used to terminate a multi-part
		 * operation, so we'll leave the active decrypt operation
		 * flag on and let the application continue with the
		 * decrypt update operation.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_decrypt(session_p, pEncryptedData, ulEncryptedDataLen,
	    pData, pulDataLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pData == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active decrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the plaintext.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* Clear context, free key, and release session counter */
	soft_crypt_cleanup(session_p, B_FALSE, B_FALSE);

	return (rv);
}


CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
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
	 * length depents on the mechanism in use.  For secret key mechanisms,
	 * unpadded ones yeild zero length output, but padded ones always
	 * result in smaller than original, possibly zero, length output.
	 */
	if (pEncryptedPart == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/*
	 * Only check if pulPartLen is NULL.
	 * No need to check if pPart is NULL because application
	 * might just ask for the length of buffer to hold the
	 * recovered data.
	 */
	if (pulPartLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Application must call C_DecryptInit before calling
	 * C_DecryptUpdate.
	 */
	if (!(session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->decrypt.flags |= CRYPTO_OPERATION_UPDATE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_decrypt_update(session_p, pEncryptedPart,
	    ulEncryptedPartLen, pPart, pulPartLen);

	/*
	 * If CKR_OK or CKR_BUFFER_TOO_SMALL, don't terminate the
	 * current decryption operation.
	 */
	if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL)) {
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current decrypt
	 * operation by resetting the active and update flags.
	 */
	soft_crypt_cleanup(session_p, B_FALSE, lock_held);

	return (rv);
}

CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
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

	if (pulLastPartLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Application must call C_DecryptInit before calling
	 * C_DecryptFinal.
	 */
	if (!(session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_decrypt_final(session_p, pLastPart, pulLastPartLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pLastPart == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active decrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the plaintext.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

	/* Terminates the active encrypt operation. */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->decrypt.flags = 0;
	lock_held = B_TRUE;
	SES_REFRELE(session_p, lock_held);
	return (rv);

clean_exit:
	/* Terminates the active decrypt operation */
	soft_crypt_cleanup(session_p, B_FALSE, lock_held);

	return (rv);
}

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
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <string.h>
#include <strings.h>
#include <security/cryptoki.h>
#include "kmsGlobal.h"
#include "kmsCrypt.h"


/*
 * kms_decrypt_init()
 *
 * Arguments:
 *	session_p:	pointer to kms_session_t struct
 *	pMechanism:	pointer to CK_MECHANISM struct provided by application
 *	key_p:		pointer to key kms_object_t struct
 *
 * Description:
 *	called by C_DecryptInit(). This function calls the corresponding
 *	decrypt init routine based on the mechanism.
 *
 * Returns:
 *	CKR_OK: success
 *	CKR_HOST_MEMORY: run out of system memory
 *	CKR_MECHANISM_PARAM_INVALID: invalid parameters in mechanism
 *	CKR_MECHANISM_INVALID: invalid mechanism type
 *	CKR_KEY_TYPE_INCONSISTENT: incorrect type of key to use
 *				   with the specified mechanism
 */
CK_RV
kms_decrypt_init(kms_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    kms_object_t *key_p)
{

	CK_RV rv;

	switch (pMechanism->mechanism) {
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	{
		kms_aes_ctx_t *kms_aes_ctx;

		if (key_p->key_type != CKK_AES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		if ((pMechanism->pParameter == NULL) ||
		    (pMechanism->ulParameterLen != AES_BLOCK_LEN)) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		rv = kms_aes_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		kms_aes_ctx = (kms_aes_ctx_t *)session_p->decrypt.context;

		/* Save Initialization Vector (IV) in the context. */
		(void) memcpy(kms_aes_ctx->ivec, pMechanism->pParameter,
		    AES_BLOCK_LEN);

		/* Allocate a context for AES cipher-block chaining. */
		kms_aes_ctx->aes_cbc = (void *)aes_cbc_ctx_init(
		    kms_aes_ctx->key_sched, kms_aes_ctx->keysched_len,
		    kms_aes_ctx->ivec);

		if (kms_aes_ctx->aes_cbc == NULL) {
			bzero(kms_aes_ctx->key_sched,
			    kms_aes_ctx->keysched_len);
			free(kms_aes_ctx->key_sched);
			free(session_p->decrypt.context);
			session_p->decrypt.context = NULL;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (CKR_HOST_MEMORY);
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		return (rv);
	}
	default:
		return (CKR_MECHANISM_INVALID);
	}
}

CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
	CK_RV		rv;
	kms_session_t	*session_p;
	kms_object_t	*key_p;
	boolean_t	lock_held = B_FALSE;

	if (!kms_initialized)
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
		kms_crypt_cleanup(session_p, B_FALSE, lock_held);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_Decrypt or C_DecryptFinal to actually obtain the final piece
	 * of plaintext.
	 */
	session_p->decrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_decrypt_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->decrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

clean_exit1:
	OBJ_REFRELE(key_p);
clean_exit:
	REFRELE(session_p, lock_held);
	return (rv);
}

CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedData, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV		rv;
	kms_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!kms_initialized)
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
		REFRELE(session_p, lock_held);
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
		REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_aes_decrypt_common(session_p, pEncryptedData,
	    ulEncryptedData, pData, pulDataLen, FALSE);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pData == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active decrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the plaintext.
		 */
		REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* Clear context, free key, and release session counter */
	kms_crypt_cleanup(session_p, B_FALSE, B_FALSE);

	return (rv);
}

CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{

	CK_RV		rv;
	kms_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!kms_initialized)
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
		REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->decrypt.flags |= CRYPTO_OPERATION_UPDATE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_aes_decrypt_common(session_p, pEncryptedPart,
	    ulEncryptedPartLen, pPart, pulPartLen, B_TRUE);

	/*
	 * If CKR_OK or CKR_BUFFER_TOO_SMALL, don't terminate the
	 * current decryption operation.
	 */
	if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL)) {
		REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current decrypt
	 * operation by resetting the active and update flags.
	 */
	kms_crypt_cleanup(session_p, B_FALSE, lock_held);

	return (rv);
}

CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
{

	CK_RV		rv;
	kms_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!kms_initialized)
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
		REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_aes_decrypt_final(session_p, pLastPart, pulLastPartLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pLastPart == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active decrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the plaintext.
		 */
		REFRELE(session_p, lock_held);
		return (rv);
	}

	/* Terminates the active encrypt operation. */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->decrypt.flags = 0;
	lock_held = B_TRUE;
	REFRELE(session_p, lock_held);
	return (rv);

clean_exit:
	/* Terminates the active decrypt operation */
	kms_crypt_cleanup(session_p, B_FALSE, lock_held);

	return (rv);
}

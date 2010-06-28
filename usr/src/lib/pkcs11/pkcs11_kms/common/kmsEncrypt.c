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

static CK_RV
kms_encrypt_init(kms_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    kms_object_t *key_p)
{
	CK_RV rv = CKR_OK;
	kms_aes_ctx_t *kms_aes_ctx;

	if (pMechanism->mechanism != CKM_AES_CBC &&
	    pMechanism->mechanism != CKM_AES_CBC_PAD)
		return (CKR_MECHANISM_INVALID);

	if (key_p->key_type != CKK_AES) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	if ((pMechanism->pParameter == NULL) ||
	    (pMechanism->ulParameterLen != AES_BLOCK_LEN)) {
		return (CKR_MECHANISM_PARAM_INVALID);
	}

	rv = kms_aes_crypt_init_common(session_p, pMechanism,
	    key_p, B_TRUE);

	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);

	kms_aes_ctx = (kms_aes_ctx_t *)session_p->encrypt.context;
	/* Copy Initialization Vector (IV) into the context. */

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
		free(session_p->encrypt.context);
		session_p->encrypt.context = NULL;
		rv = CKR_HOST_MEMORY;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

void
kms_crypt_cleanup(kms_session_t *session_p, boolean_t encrypt,
	boolean_t lock_held)
{
	kms_active_op_t *active_op;
	boolean_t lock_true = B_TRUE;
	kms_aes_ctx_t *kms_aes_ctx;
	aes_ctx_t *aes_ctx;

	if (!lock_held)
		(void) pthread_mutex_lock(&session_p->session_mutex);

	active_op = (encrypt) ? &(session_p->encrypt) : &(session_p->decrypt);
	if (active_op->mech.mechanism != CKM_AES_CBC &&
	    active_op->mech.mechanism != CKM_AES_CBC_PAD)
		return;

	kms_aes_ctx = (kms_aes_ctx_t *)active_op->context;

	if (kms_aes_ctx != NULL) {
		aes_ctx = (aes_ctx_t *)kms_aes_ctx->aes_cbc;
		if (aes_ctx != NULL) {
			bzero(aes_ctx->ac_keysched, aes_ctx->ac_keysched_len);
			free(kms_aes_ctx->aes_cbc);
			bzero(kms_aes_ctx->key_sched,
			    kms_aes_ctx->keysched_len);
			free(kms_aes_ctx->key_sched);
		}
	}
	if (active_op->context != NULL) {
		free(active_op->context);
		active_op->context = NULL;
	}
	active_op->flags = 0;
	if (!lock_held)
		REFRELE(session_p, lock_true);
}

CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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

	if (pMechanism->mechanism != CKM_AES_CBC &&
	    pMechanism->mechanism != CKM_AES_CBC_PAD)
		return (CKR_MECHANISM_INVALID);

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
		kms_crypt_cleanup(session_p, B_TRUE, lock_held);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_Encrypt or C_EncryptFinal to actually obtain the final piece
	 * of ciphertext.
	 */
	session_p->encrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_encrypt_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->encrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

clean_exit1:
	OBJ_REFRELE(key_p);
clean_exit:
	REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
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
	 * length depends on the mechanism in use.  For secret key mechanisms,
	 * unpadded ones yield zero length output, but padded ones always
	 * result in greater than zero length output.
	 */
	if (pData == NULL) {
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
		REFRELE(session_p, lock_held);
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
		REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_aes_encrypt_common(session_p, pData, ulDataLen, pEncryptedData,
	    pulEncryptedDataLen, 0);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pEncryptedData == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active encrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the ciphertext.
		 */
		REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* Clear context, free key, and release session counter */
	kms_crypt_cleanup(session_p, B_TRUE, B_FALSE);
	return (rv);
}

CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
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
		REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->encrypt.flags |= CRYPTO_OPERATION_UPDATE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_aes_encrypt_common(session_p, pPart, ulPartLen,
	    pEncryptedPart, pulEncryptedPartLen, B_TRUE);

	/*
	 * If CKR_OK or CKR_BUFFER_TOO_SMALL, don't terminate the
	 * current encryption operation.
	 */
	if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL)) {
		REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current encrypt
	 * operation by resetting the active and update flags.
	 */
	kms_crypt_cleanup(session_p, B_TRUE, lock_held);

	return (rv);
}


CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen)
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
		REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = kms_aes_encrypt_final(session_p, pLastEncryptedPart,
	    pulLastEncryptedPartLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pLastEncryptedPart == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active encrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the ciphertext.
		 */
		REFRELE(session_p, lock_held);
		return (rv);
	}

	/* Terminates the active encrypt operation. */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->encrypt.flags = 0;
	lock_held = B_TRUE;
	REFRELE(session_p, lock_held);

	return (rv);

clean_exit:
	/* Terminates the active encrypt operation. */
	kms_crypt_cleanup(session_p, B_TRUE, lock_held);

	return (rv);
}

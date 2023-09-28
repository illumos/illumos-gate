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
#include "softObject.h"
#include "softOps.h"
#include "softSession.h"


CK_RV
C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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
	if (rv != CKR_OK) {
		goto clean_exit;
	}

	/* Check to see if key object supports verification. */
	if (!(key_p->bool_attr_mask & VERIFY_BOOL_ON)) {
		rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto clean_exit1;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Check to see if verify operation is already active. */
	if (session_p->verify.flags & CRYPTO_OPERATION_ACTIVE) {
		/* free the memory to avoid memory leak */
		soft_sign_verify_cleanup(session_p, B_FALSE, B_TRUE);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_Verify or C_VerifyFinal to verify a signature on data.
	 */
	session_p->verify.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_verify_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->verify.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

clean_exit1:
	OBJ_REFRELE(key_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obatin the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pData == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Application must call C_VerifyInit before calling C_Verify. */
	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * C_Verify must be called without intervening C_VerifyUpdate
	 * calls.
	 */
	if (session_p->verify.flags & CRYPTO_OPERATION_UPDATE) {
		/*
		 * C_Verify can not be used to terminate a multi-part
		 * operation, so we'll leave the active verify operation
		 * flag on and let the application continue with the
		 * verify update operation.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_verify(session_p, pData, ulDataLen, pSignature,
	    ulSignatureLen);

clean_exit:
	/* Clear context, free key, and release session counter */
	soft_sign_verify_cleanup(session_p, B_FALSE, B_FALSE);
	return (rv);
}


CK_RV
C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (ulPartLen == 0) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OK);
	}

	if (pPart == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Application must call C_VerifyInit before calling
	 * C_VerifyUpdate.
	 */
	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->verify.flags |= CRYPTO_OPERATION_UPDATE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_verify_update(session_p, pPart, ulPartLen);

	if (rv == CKR_OK) {
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* After error, clear context, free key, & release session counter */
	soft_sign_verify_cleanup(session_p, B_FALSE, B_FALSE);

	return (rv);
}


CK_RV
C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/*
	 * Application must call C_VerifyInit before calling
	 * C_VerifyFinal.
	 */
	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_verify_final(session_p, pSignature, ulSignatureLen);

	/* Clear contexts, free key, and release session counter */
	soft_sign_verify_cleanup(session_p, B_FALSE, B_FALSE);
	return (rv);
}


CK_RV
C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
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
	if (rv != CKR_OK) {
		goto clean_exit;
	}

	/* Check to see if key object supports verify_recover. */
	if (!(key_p->bool_attr_mask & VERIFY_RECOVER_BOOL_ON)) {
		rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto clean_exit1;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	/* Check to see if verify operation is already active. */
	if (session_p->verify.flags & CRYPTO_OPERATION_ACTIVE) {
		/* free the memory to avoid memory leak */
		soft_sign_verify_cleanup(session_p, B_FALSE, B_TRUE);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_VerifyRecover to actually obtain the recovered message.
	 */
	session_p->verify.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_verify_recover_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->verify.flags &= ~CRYPTO_OPERATION_ACTIVE;
		lock_held = B_TRUE;
	}

clean_exit1:
	OBJ_REFRELE(key_p);
clean_exit:
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obatin the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pSignature == NULL) || (pulDataLen == NULL)) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	lock_held = B_TRUE;

	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	lock_held = B_FALSE;

	rv = soft_verify_recover(session_p, pSignature,
	    ulSignatureLen, pData, pulDataLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pData == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active verify operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the signature.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* Clear context, free key, and release session counter */
	soft_sign_verify_cleanup(session_p, B_FALSE, B_FALSE);
	return (rv);
}

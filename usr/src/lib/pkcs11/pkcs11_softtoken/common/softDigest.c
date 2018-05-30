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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softOps.h"
#include "softSession.h"


CK_RV
C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pMechanism == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Check to see if digest operation is already active */
	if (session_p->digest.flags & CRYPTO_OPERATION_ACTIVE) {
		/*
		 * Free the memory to avoid memory leak.
		 * digest.context is only a flat structure.
		 */
		soft_digest_cleanup(session_p, lock_held);
	}

	/*
	 * This active flag will remain ON until application calls either
	 * C_Digest or C_DigestFinal to actually obtain the value of
	 * the message digest.
	 */
	session_p->digest.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_digest_init(session_p, pMechanism);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->digest.flags &= ~CRYPTO_OPERATION_ACTIVE;
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and SES_REFRELE()
		 * will release the session lock for us.
		 */
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	lock_held = B_FALSE;
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pData == NULL && ulDataLen != 0) || pulDigestLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Application must call C_DigestInit before calling C_Digest */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and SES_REFRELE()
		 * will release the session lock for us.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * C_Digest must be called without intervening C_DigestUpdate
	 * calls.
	 */
	if (session_p->digest.flags & CRYPTO_OPERATION_UPDATE) {
		/*
		 * C_Digest can not be used to terminate a multi-part
		 * operation, so we'll leave the active digest operation
		 * flag on and let the application continue with the
		 * digest update operation.
		 *
		 * Decrement the session reference count.
		 * We hold the session lock, and SES_REFRELE()
		 * will release the session lock for us.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_digest(session_p, pData, ulDataLen, pDigest, pulDigestLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pDigest == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active digest operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the message digest.
		 *
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		lock_held = B_FALSE;
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Terminates the active digest operation.
	 * Application needs to call C_DigestInit again for next
	 * digest operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	soft_digest_cleanup(session_p, lock_held);

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and SES_REFRELE()
	 * will release the session lock for us.
	 */
	SES_REFRELE(session_p, lock_held);

	return (rv);
}


CK_RV
C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pPart == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	/*
	 * Application must call C_DigestInit before calling
	 * C_DigestUpdate.
	 */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and SES_REFRELE()
		 * will release the session lock for us.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/* Set update flag to protect C_Digest */
	session_p->digest.flags |= CRYPTO_OPERATION_UPDATE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_digest_update(session_p, pPart, ulPartLen);

	if (rv == CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		lock_held = B_FALSE;
		SES_REFRELE(session_p, lock_held);
		return (CKR_OK);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current digest
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	soft_digest_cleanup(session_p, lock_held);

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and SES_REFRELE()
	 * will release the session lock for us.
	 */
	SES_REFRELE(session_p, lock_held);

	return (rv);
}


CK_RV
C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	soft_object_t	*key_p;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv != CKR_OK)
		goto clean_exit;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/*
	 * Application must call C_DigestInit before calling
	 * C_DigestKey.
	 */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and SES_REFRELE()
		 * will release the session lock for us.
		 */
		OBJ_REFRELE(key_p);
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * Remember the fact that a key was thrown into the mix, so that
	 * C_DigestFinal bzero()'s the digest context before freeing it.
	 */
	session_p->digest.flags |= (CRYPTO_KEY_DIGESTED |
	    CRYPTO_OPERATION_UPDATE);

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_digest_key(session_p, key_p);

	if (rv == CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		lock_held = B_FALSE;
		OBJ_REFRELE(key_p);
		SES_REFRELE(session_p, lock_held);
		return (CKR_OK);
	}

	OBJ_REFRELE(key_p);
clean_exit:
	/*
	 * After an error occurred, terminate the current digest
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	soft_digest_cleanup(session_p, lock_held);

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and SES_REFRELE()
	 * will release the session lock for us.
	 */
	SES_REFRELE(session_p, lock_held);
	return (rv);
}


CK_RV
C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen)
{

	CK_RV		rv;
	soft_session_t	*session_p;
	boolean_t lock_held = B_TRUE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pulDigestLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	/*
	 * Application must call C_DigestInit before calling
	 * C_DigestFinal.
	 */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and SES_REFRELE()
		 * will release the session lock for us.
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_digest_final(session_p, pDigest, pulDigestLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (pDigest == NULL && rv == CKR_OK)) {
		/*
		 * We will not terminate the active digest operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the message digest.
		 *
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		lock_held = B_FALSE;
		SES_REFRELE(session_p, lock_held);
		return (rv);
	}

clean_exit:
	/* Terminates the active digest operation */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	soft_digest_cleanup(session_p, lock_held);

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and SES_REFRELE()
	 * will release the session lock for us.
	 */
	SES_REFRELE(session_p, lock_held);

	return (rv);
}

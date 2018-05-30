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
 * Copyright 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <errno.h>
#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelEmulate.h"

static CK_RV
common_digest_init(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, boolean_t is_external_caller)
{
	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_digest_init_t digest_init;
	crypto_mech_type_t k_mech_type;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pMechanism == NULL)
		return (CKR_ARGUMENTS_BAD);

	/*
	 * Get the kernel's internal mechanism number.
	 */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Acquire the session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * This active flag will remain ON until application calls either
	 * C_Digest or C_DigestFinal to actually obtain the value of
	 * the message digest.
	 */
	session_p->digest.flags |= CRYPTO_OPERATION_ACTIVE;

	if (SLOT_HAS_LIMITED_HASH(session_p) && is_external_caller) {
		session_p->digest.mech.mechanism = pMechanism->mechanism;
		session_p->digest.mech.pParameter = NULL;
		session_p->digest.mech.ulParameterLen = 0;
		session_p->digest.flags |= CRYPTO_EMULATE;
		rv = emulate_buf_init(session_p, EDIGEST_LENGTH, OP_DIGEST);
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	digest_init.di_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	digest_init.di_mech.cm_type = k_mech_type;
	digest_init.di_mech.cm_param = pMechanism->pParameter;

	/*
	 * If pParameter is NULL, set cm_param_len to be 0, so that ioctl call
	 * will have a clean input data.
	 */
	if (pMechanism->pParameter != NULL)
		digest_init.di_mech.cm_param_len = pMechanism->ulParameterLen;
	else
		digest_init.di_mech.cm_param_len = 0;

	while ((r = ioctl(kernel_fd, CRYPTO_DIGEST_INIT, &digest_init)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(digest_init.di_return_value);
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		ses_lock_held = B_TRUE;
		session_p->digest.flags &= ~CRYPTO_OPERATION_ACTIVE;
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and REFRELE()
		 * will release the session lock for us.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/*
	 * Decrement the session reference count.
	 * We do not hold the session lock.
	 */
	REFRELE(session_p, ses_lock_held);
	return (rv);
}

CK_RV
C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	return (common_digest_init(hSession, pMechanism, B_TRUE));
}

CK_RV
C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_digest_t digest;
	int r;

	if (!kernel_initialized)
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
	ses_lock_held = B_TRUE;

	/* Application must call C_DigestInit before calling C_Digest */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and REFRELE()
		 * will release the session lock for us.
		 */
		REFRELE(session_p, ses_lock_held);
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
		 * We hold the session lock, and REFRELE()
		 * will release the session lock for us.
		 */
		REFRELE(session_p, ses_lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	if (session_p->digest.flags & CRYPTO_EMULATE) {
		crypto_active_op_t *opp;
		CK_MECHANISM_PTR pMechanism;

		opp = &(session_p->digest);
		if (opp->context == NULL) {
			REFRELE(session_p, ses_lock_held);
			return (CKR_ARGUMENTS_BAD);
		}
		pMechanism = &(opp->mech);

		if ((ulDataLen < SLOT_THRESHOLD(session_p)) ||
		    (ulDataLen > SLOT_HASH_MAX_INDATA_LEN(session_p))) {
			session_p->digest.flags |= CRYPTO_EMULATE_USING_SW;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;

			rv = do_soft_digest(get_spp(opp), pMechanism,
			    pData, ulDataLen, pDigest, pulDigestLen,
			    OP_INIT | OP_SINGLE);
			goto done;
		} else if (!(session_p->digest.flags &
		    CRYPTO_EMULATE_INIT_DONE)) {
			session_p->digest.flags |= CRYPTO_EMULATE_INIT_DONE;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;

			rv = common_digest_init(hSession, pMechanism, B_FALSE);
			if (rv != CKR_OK)
				goto clean_exit;
			(void) pthread_mutex_lock(&session_p->session_mutex);
			ses_lock_held = B_TRUE;
		}
	}

	digest.cd_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	digest.cd_datalen =  ulDataLen;
	digest.cd_databuf = (char *)pData;
	digest.cd_digestbuf = (char *)pDigest;
	digest.cd_digestlen = *pulDigestLen;

	while ((r = ioctl(kernel_fd, CRYPTO_DIGEST, &digest)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(digest.cd_return_value);
	}

	if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL))
		*pulDigestLen = digest.cd_digestlen;

done:
	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pDigest == NULL)) {
		/*
		 * We will not terminate the active digest operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the message digest.
		 *
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Terminates the active digest operation.
	 * Application needs to call C_DigestInit again for next
	 * digest operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	REINIT_OPBUF(&session_p->digest);
	session_p->digest.flags = 0;

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and REFRELE()
	 * will release the session lock for us.
	 */
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

CK_RV
C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_digest_update_t digest_update;
	int r;

	if (!kernel_initialized)
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
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_DigestInit before calling
	 * C_DigestUpdate.
	 */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and REFRELE()
		 * will release the session lock for us.
		 */
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/* Set update flag to protect C_Digest */
	session_p->digest.flags |= CRYPTO_OPERATION_UPDATE;

	if (session_p->digest.flags & CRYPTO_EMULATE) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		ses_lock_held = B_FALSE;
		rv = emulate_update(session_p, pPart, ulPartLen, OP_DIGEST);
		goto done;
	}

	digest_update.du_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	digest_update.du_datalen =  ulPartLen;
	digest_update.du_databuf = (char *)pPart;

	while ((r = ioctl(kernel_fd, CRYPTO_DIGEST_UPDATE,
	    &digest_update)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(digest_update.du_return_value);
	}

done:
	if (rv == CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		REFRELE(session_p, ses_lock_held);
		return (CKR_OK);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current digest
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	REINIT_OPBUF(&session_p->digest);
	session_p->digest.flags = 0;

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and REFRELE()
	 * will release the session lock for us.
	 */
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{

	CK_RV		rv;
	kernel_session_t	*session_p;
	kernel_object_t	*key_p;
	boolean_t ses_lock_held = B_FALSE;
	CK_BYTE_PTR	pPart;
	CK_ULONG	ulPartLen;
	crypto_digest_key_t digest_key;
	crypto_digest_update_t digest_update;
	int r;

	if (!kernel_initialized)
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
	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		ses_lock_held = B_TRUE;
		REINIT_OPBUF(&session_p->digest);
		session_p->digest.flags = 0;
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Check the key type */
	if (key_p->is_lib_obj && (key_p->class != CKO_SECRET_KEY)) {
		rv = CKR_KEY_INDIGESTIBLE;
		goto clean_exit;
	}

	/*
	 * Application must call C_DigestInit before calling
	 * C_DigestKey.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and REFRELE()
		 * will release the session lock for us.
		 */
		OBJ_REFRELE(key_p);
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}
	session_p->digest.flags |= CRYPTO_OPERATION_UPDATE;

	/*
	 * If the key object is from the HW provider, call CRYPTO_DIGEST_KEY
	 * ioctl. Otherwise, call CRYPTO_DIGEST_UPDATE ioctl and pass the key
	 * by value.
	 */
	if (key_p->is_lib_obj) {
		digest_update.du_session = session_p->k_session;
	} else {
		digest_key.dk_session = session_p->k_session;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	if (!key_p->is_lib_obj) {
		if (session_p->digest.flags & CRYPTO_EMULATE) {
			rv = CKR_FUNCTION_NOT_SUPPORTED;
			goto clean_exit;
		}
		digest_key.dk_key.ck_format = CRYPTO_KEY_REFERENCE;
		digest_key.dk_key.ck_obj_id = key_p->k_handle;
		while ((r = ioctl(kernel_fd, CRYPTO_DIGEST_KEY,
		    &digest_key)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    digest_key.dk_return_value);
		}
	} else {
		ulPartLen = OBJ_SEC_VALUE_LEN(key_p);
		if (ulPartLen == 0) {
			rv = CKR_KEY_SIZE_RANGE;
			goto clean_exit;
		}

		pPart = (CK_BYTE_PTR) OBJ_SEC_VALUE(key_p);
		if (pPart == NULL) {
			rv = CKR_KEY_HANDLE_INVALID;
			goto clean_exit;
		}

		(void) pthread_mutex_lock(&session_p->session_mutex);
		ses_lock_held = B_TRUE;
		if (session_p->digest.flags & CRYPTO_EMULATE) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;
			rv = emulate_update(session_p, pPart,
			    ulPartLen, OP_DIGEST);
			goto done;
		}
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		ses_lock_held = B_FALSE;

		digest_update.du_datalen = ulPartLen;
		digest_update.du_databuf = (char *)pPart;

		while ((r = ioctl(kernel_fd, CRYPTO_DIGEST_UPDATE,
		    &digest_update)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			rv = CKR_FUNCTION_FAILED;
		} else {
			rv = crypto2pkcs11_error_number(
			    digest_update.du_return_value);
		}
	}

done:
	if (rv == CKR_OK) {
		/*
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		OBJ_REFRELE(key_p);
		REFRELE(session_p, ses_lock_held);
		return (CKR_OK);
	}

clean_exit:
	OBJ_REFRELE(key_p);
	/*
	 * After an error occurred, terminate the current digest
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	REINIT_OPBUF(&session_p->digest);
	session_p->digest.flags = 0;

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and REFRELE()
	 * will release the session lock for us.
	 */
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_digest_final_t digest_final;
	int r;

	if (!kernel_initialized)
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
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_DigestInit before calling
	 * C_DigestFinal.
	 */
	if (!(session_p->digest.flags & CRYPTO_OPERATION_ACTIVE)) {
		/*
		 * Decrement the session reference count.
		 * We hold the session lock, and REFRELE()
		 * will release the session lock for us.
		 */
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/* The order of checks is important here */
	if (session_p->digest.flags & CRYPTO_EMULATE_USING_SW) {
		if (session_p->digest.flags & CRYPTO_EMULATE_UPDATE_DONE) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;
			rv = do_soft_digest(get_spp(&session_p->digest),
			    NULL, NULL, NULL, pDigest, pulDigestLen, OP_FINAL);
		} else {
			/*
			 * We end up here if an earlier C_DigestFinal() call
			 * took the C_Digest() path and it had returned
			 * CKR_BUFFER_TOO_SMALL.
			 */
			digest_buf_t *bufp = session_p->digest.context;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;
			if (bufp == NULL || bufp->buf == NULL) {
				rv = CKR_ARGUMENTS_BAD;
				goto clean_exit;
			}
			rv = do_soft_digest(get_spp(&session_p->digest),
			    NULL, bufp->buf, bufp->indata_len,
			    pDigest, pulDigestLen, OP_SINGLE);
		}
		goto done;
	} else if (session_p->digest.flags & CRYPTO_EMULATE) {
		digest_buf_t *bufp = session_p->digest.context;

		/*
		 * We are emulating a single-part operation now.
		 * So, clear the flag.
		 */
		session_p->digest.flags &= ~CRYPTO_OPERATION_UPDATE;
		if (bufp == NULL || bufp->buf == NULL) {
			rv = CKR_ARGUMENTS_BAD;
			goto clean_exit;
		}
		REFRELE(session_p, ses_lock_held);
		rv = C_Digest(hSession, bufp->buf, bufp->indata_len,
		    pDigest, pulDigestLen);
		return (rv);
	}

	digest_final.df_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	digest_final.df_digestlen = *pulDigestLen;
	digest_final.df_digestbuf = (char *)pDigest;

	while ((r = ioctl(kernel_fd, CRYPTO_DIGEST_FINAL, &digest_final)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(digest_final.df_return_value);
	}

	if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL))
		*pulDigestLen = digest_final.df_digestlen;

done:
	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pDigest == NULL)) {
		/*
		 * We will not terminate the active digest operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the message digest.
		 *
		 * Decrement the session reference count.
		 * We do not hold the session lock.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/* Terminates the active digest operation */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	REINIT_OPBUF(&session_p->digest);
	session_p->digest.flags = 0;

	/*
	 * Decrement the session reference count.
	 * We hold the session lock, and REFRELE()
	 * will release the session lock for us.
	 */
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

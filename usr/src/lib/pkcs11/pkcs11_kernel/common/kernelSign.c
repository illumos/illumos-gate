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

#include <errno.h>
#include <security/cryptoki.h>
#include <sys/crypto/ioctl.h>
#include "kernelGlobal.h"
#include "kernelObject.h"
#include "kernelSession.h"
#include "kernelEmulate.h"

CK_RV
C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	kernel_session_t *session_p;
	kernel_object_t *key_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_sign_init_t sign_init;
	crypto_mech_type_t k_mech_type;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pMechanism == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Get the kernel's internal mechanism number. */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK) {
		return (rv);
	}

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv != CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Check to see if key object supports signature. */
	if (key_p->is_lib_obj && !(key_p->bool_attr_mask & SIGN_BOOL_ON)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * This active flag will remain ON until application calls either
	 * C_Sign or C_SignFinal to actually obtain the signature.
	 */
	session_p->sign.flags = CRYPTO_OPERATION_ACTIVE;
	sign_init.si_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	if (!key_p->is_lib_obj) {
		sign_init.si_key.ck_format = CRYPTO_KEY_REFERENCE;
		sign_init.si_key.ck_obj_id = key_p->k_handle;
	} else {
		if (key_p->class == CKO_SECRET_KEY) {
			sign_init.si_key.ck_format = CRYPTO_KEY_RAW;
			sign_init.si_key.ck_data =
			    get_symmetric_key_value(key_p);
			if (sign_init.si_key.ck_data == NULL) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
			sign_init.si_key.ck_length =
			    OBJ_SEC(key_p)->sk_value_len << 3;

		} else if (key_p->key_type == CKK_RSA) {
			rv = get_rsa_private_key(key_p, &sign_init.si_key);
			if (rv != CKR_OK) {
				goto clean_exit;
			}
		} else if (key_p->key_type == CKK_DSA) {
			rv = get_dsa_private_key(key_p, &sign_init.si_key);
			if (rv != CKR_OK) {
				goto clean_exit;
			}
		} else if (key_p->key_type == CKK_EC) {
			rv = get_ec_private_key(key_p, &sign_init.si_key);
			if (rv != CKR_OK) {
				goto clean_exit;
			}
		} else {
			rv = CKR_KEY_TYPE_INCONSISTENT;
			goto clean_exit;
		}
	}

	sign_init.si_mech.cm_type = k_mech_type;
	sign_init.si_mech.cm_param = pMechanism->pParameter;
	sign_init.si_mech.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_SIGN_INIT, &sign_init)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(sign_init.si_return_value);
	}

	if (rv == CKR_OK && SLOT_HAS_LIMITED_HMAC(session_p) &&
	    is_hmac(pMechanism->mechanism)) {
		if (key_p->is_lib_obj && key_p->class == CKO_SECRET_KEY) {
			(void) pthread_mutex_lock(&session_p->session_mutex);
			session_p->sign.flags |= CRYPTO_EMULATE;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			rv = emulate_init(session_p, pMechanism,
			    &(sign_init.si_key), OP_SIGN);
		} else {
			rv = CKR_ARGUMENTS_BAD;
		}
	}

	if (key_p->is_lib_obj) {
		if (key_p->class == CKO_SECRET_KEY) {
			free(sign_init.si_key.ck_data);
		} else {
			free_key_attributes(&sign_init.si_key);
		}
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->sign.flags &= ~CRYPTO_OPERATION_ACTIVE;
		ses_lock_held = B_TRUE;
	}

clean_exit:
	OBJ_REFRELE(key_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_sign_t sign;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pulSignatureLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Application must call C_SignInit before calling C_Sign. */
	if (!(session_p->sign.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * C_Sign must be called without intervening C_SignUpdate
	 * calls.
	 */
	if (session_p->sign.flags & CRYPTO_OPERATION_UPDATE) {
		/*
		 * C_Sign can not be used to terminate a multi-part
		 * operation, so we'll leave the active sign operation
		 * flag on and let the application continue with the
		 * sign update operation.
		 */
		REFRELE(session_p, ses_lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	if (session_p->sign.flags & CRYPTO_EMULATE) {
		if ((ulDataLen < SLOT_THRESHOLD(session_p)) ||
		    (ulDataLen > SLOT_HMAC_MAX_INDATA_LEN(session_p))) {
			session_p->sign.flags |= CRYPTO_EMULATE_USING_SW;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;

			rv = do_soft_hmac_sign(get_spp(&session_p->sign),
			    pData, ulDataLen,
			    pSignature, pulSignatureLen, OP_SINGLE);
			goto done;
		} else {
			free_soft_ctx(get_sp(&session_p->sign), OP_SIGN);
		}
	}

	sign.cs_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	sign.cs_datalen = ulDataLen;
	sign.cs_databuf = (char *)pData;
	sign.cs_signlen = *pulSignatureLen;
	sign.cs_signbuf = (char *)pSignature;

	while ((r = ioctl(kernel_fd, CRYPTO_SIGN, &sign)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(sign.cs_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulSignatureLen = sign.cs_signlen;

done:
	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pSignature == NULL)) {
		/*
		 * We will not terminate the active sign operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the signature.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Terminates the active sign operation.
	 * Application needs to call C_SignInit again for next
	 * sign operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	REINIT_OPBUF(&session_p->sign);
	session_p->sign.flags = 0;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_sign_update_t sign_update;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pPart == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_SignInit before calling
	 * C_SignUpdate.
	 */
	if (!(session_p->sign.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->sign.flags |= CRYPTO_OPERATION_UPDATE;

	if (session_p->sign.flags & CRYPTO_EMULATE) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		ses_lock_held = B_FALSE;
		rv = emulate_update(session_p, pPart, ulPartLen, OP_SIGN);
		goto done;
	}

	sign_update.su_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	sign_update.su_datalen = ulPartLen;
	sign_update.su_databuf = (char *)pPart;

	while ((r = ioctl(kernel_fd, CRYPTO_SIGN_UPDATE, &sign_update)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(sign_update.su_return_value);
	}

done:
	if (rv == CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current sign
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	REINIT_OPBUF(&session_p->sign);
	session_p->sign.flags = 0;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_sign_final_t sign_final;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pulSignatureLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_SignInit before calling
	 * C_SignFinal.
	 */
	if (!(session_p->sign.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/* The order of checks is important here */
	if (session_p->sign.flags & CRYPTO_EMULATE_USING_SW) {
		if (session_p->sign.flags & CRYPTO_EMULATE_UPDATE_DONE) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;
			rv = do_soft_hmac_sign(get_spp(&session_p->sign),
			    NULL, 0, pSignature, pulSignatureLen, OP_FINAL);
		} else {
			/*
			 * We end up here if an earlier C_SignFinal() call
			 * took the C_Sign() path and it had returned
			 * CKR_BUFFER_TOO_SMALL.
			 */
			digest_buf_t *bufp = session_p->sign.context;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;
			if (bufp == NULL || bufp->buf == NULL) {
				rv = CKR_ARGUMENTS_BAD;
				goto clean_exit;
			}
			rv = do_soft_hmac_sign(get_spp(&session_p->sign),
			    bufp->buf, bufp->indata_len,
			    pSignature, pulSignatureLen, OP_SINGLE);
		}
		goto done;
	} else if (session_p->sign.flags & CRYPTO_EMULATE) {
		digest_buf_t *bufp = session_p->sign.context;

		/*
		 * We are emulating a single-part operation now.
		 * So, clear the flag.
		 */
		session_p->sign.flags &= ~CRYPTO_OPERATION_UPDATE;
		if (bufp == NULL || bufp->buf == NULL) {
			rv = CKR_ARGUMENTS_BAD;
			goto clean_exit;
		}
		REFRELE(session_p, ses_lock_held);
		rv = C_Sign(hSession, bufp->buf, bufp->indata_len,
		    pSignature, pulSignatureLen);
		return (rv);
	}

	sign_final.sf_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	sign_final.sf_signlen = *pulSignatureLen;
	sign_final.sf_signbuf = (char *)pSignature;

	while ((r = ioctl(kernel_fd, CRYPTO_SIGN_FINAL, &sign_final)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(sign_final.sf_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulSignatureLen = sign_final.sf_signlen;

done:
	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pSignature == NULL)) {
		/*
		 * We will not terminate the active sign operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the signature.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/* Terminates the active sign operation */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	REINIT_OPBUF(&session_p->sign);
	session_p->sign.flags = 0;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{

	CK_RV rv;
	kernel_session_t *session_p;
	kernel_object_t *key_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_sign_recover_init_t sr_init;
	crypto_mech_type_t k_mech_type;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pMechanism == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Get the kernel's internal mechanism number. */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv != CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/*
	 * Check to see if key object is a RSA key and if it supports
	 * sign_recover.
	 */
	if (key_p->is_lib_obj && !((key_p->key_type == CKK_RSA) &&
	    (key_p->bool_attr_mask & SIGN_RECOVER_BOOL_ON))) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * This active flag will remain ON until application calls
	 * C_SignRecover to actually obtain the signature.
	 */
	session_p->sign.flags = CRYPTO_OPERATION_ACTIVE;

	/* Set up the key data */
	if (!key_p->is_lib_obj) {
		sr_init.ri_key.ck_format = CRYPTO_KEY_REFERENCE;
		sr_init.ri_key.ck_obj_id = key_p->k_handle;
	} else {
		if (key_p->key_type == CKK_RSA) {
			if (get_rsa_private_key(key_p, &sr_init.ri_key) !=
			    CKR_OK) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
		} else {
			rv = CKR_KEY_TYPE_INCONSISTENT;
			goto clean_exit;
		}
	}

	sr_init.ri_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	sr_init.ri_mech.cm_type = k_mech_type;
	sr_init.ri_mech.cm_param = pMechanism->pParameter;
	sr_init.ri_mech.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_SIGN_RECOVER_INIT, &sr_init)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(sr_init.ri_return_value);
	}

	if (key_p->is_lib_obj) {
		free_key_attributes(&sr_init.ri_key);
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->sign.flags &= ~CRYPTO_OPERATION_ACTIVE;
		ses_lock_held = B_TRUE;
	}

clean_exit:
	OBJ_REFRELE(key_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_sign_recover_t sign_recover;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obatin the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pulSignatureLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Application must call C_SignInit before calling C_Sign. */
	if (!(session_p->sign.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	sign_recover.sr_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	sign_recover.sr_datalen = ulDataLen;
	sign_recover.sr_databuf = (char *)pData;
	sign_recover.sr_signlen = *pulSignatureLen;
	sign_recover.sr_signbuf = (char *)pSignature;

	while ((r = ioctl(kernel_fd, CRYPTO_SIGN_RECOVER, &sign_recover)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(sign_recover.sr_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulSignatureLen = sign_recover.sr_signlen;

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pSignature == NULL)) {
		/*
		 * We will not terminate the active sign operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the signature.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Terminates the active sign operation.
	 * Application needs to call C_SignInit again for next
	 * sign operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	session_p->sign.flags = 0;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

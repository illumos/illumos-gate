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

#include <stdlib.h>
#include <errno.h>
#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelObject.h"
#include "kernelSession.h"
#include "kernelEmulate.h"

CK_RV
C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	kernel_session_t *session_p;
	kernel_object_t	*key_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_verify_init_t verify_init;
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

	/* Check to see if key object supports verification. */
	if (key_p->is_lib_obj && !(key_p->bool_attr_mask & VERIFY_BOOL_ON)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * This active flag will remain ON until application calls either
	 * C_Verify or C_VerifyFinal to verify a signature on data.
	 */
	session_p->verify.flags = CRYPTO_OPERATION_ACTIVE;

	if (!key_p->is_lib_obj) {
		verify_init.vi_key.ck_format = CRYPTO_KEY_REFERENCE;
		verify_init.vi_key.ck_obj_id = key_p->k_handle;
	} else {
		if (key_p->class == CKO_SECRET_KEY) {
			verify_init.vi_key.ck_format = CRYPTO_KEY_RAW;
			verify_init.vi_key.ck_data =
			    get_symmetric_key_value(key_p);
			if (verify_init.vi_key.ck_data == NULL) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
			verify_init.vi_key.ck_length =
			    OBJ_SEC(key_p)->sk_value_len << 3;

		} else if (key_p->key_type == CKK_RSA) {
			if (get_rsa_public_key(key_p, &verify_init.vi_key) !=
			    CKR_OK) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
		} else if (key_p->key_type == CKK_DSA) {
			if (get_dsa_public_key(key_p, &verify_init.vi_key) !=
			    CKR_OK) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
		} else if (key_p->key_type == CKK_EC) {
			if (get_ec_public_key(key_p, &verify_init.vi_key) !=
			    CKR_OK) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
		} else {
			rv = CKR_KEY_TYPE_INCONSISTENT;
			goto clean_exit;
		}
	}

	verify_init.vi_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	verify_init.vi_mech.cm_type = k_mech_type;
	verify_init.vi_mech.cm_param = pMechanism->pParameter;
	verify_init.vi_mech.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_VERIFY_INIT, &verify_init)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(verify_init.vi_return_value);
	}

	if (rv == CKR_OK && SLOT_HAS_LIMITED_HMAC(session_p) &&
	    is_hmac(pMechanism->mechanism)) {
		if (key_p->is_lib_obj && key_p->class == CKO_SECRET_KEY) {
			(void) pthread_mutex_lock(&session_p->session_mutex);
			session_p->verify.flags |= CRYPTO_EMULATE;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			rv = emulate_init(session_p, pMechanism,
			    &(verify_init.vi_key), OP_VERIFY);
		} else {
			rv = CKR_FUNCTION_FAILED;
		}
	}

	/* free the memory allocated for verify_init.vi_key */
	if (key_p->is_lib_obj) {
		if (key_p->class == CKO_SECRET_KEY) {
			free(verify_init.vi_key.ck_data);
		} else {
			free_key_attributes(&verify_init.vi_key);
		}
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->verify.flags &= ~CRYPTO_OPERATION_ACTIVE;
		ses_lock_held = B_TRUE;
	}

clean_exit:
	OBJ_REFRELE(key_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_verify_t verify;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obatin the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Application must call C_VerifyInit before calling C_Verify. */
	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
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
		REFRELE(session_p, ses_lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	if (session_p->verify.flags & CRYPTO_EMULATE) {
		if ((ulDataLen < SLOT_THRESHOLD(session_p)) ||
		    (ulDataLen > SLOT_HMAC_MAX_INDATA_LEN(session_p))) {
			session_p->verify.flags |= CRYPTO_EMULATE_USING_SW;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;

			rv = do_soft_hmac_verify(get_spp(&session_p->verify),
			    pData, ulDataLen,
			    pSignature, ulSignatureLen, OP_SINGLE);
			goto clean_exit;
		} else {
			free_soft_ctx(get_sp(&session_p->verify), OP_VERIFY);
		}
	}

	verify.cv_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	verify.cv_datalen = ulDataLen;
	verify.cv_databuf = (char *)pData;
	verify.cv_signlen = ulSignatureLen;
	verify.cv_signbuf = (char *)pSignature;

	while ((r = ioctl(kernel_fd, CRYPTO_VERIFY, &verify)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(verify.cv_return_value);
	}

clean_exit:
	/*
	 * Always terminate the active verify operation.
	 * Application needs to call C_VerifyInit again for next
	 * verify operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	REINIT_OPBUF(&session_p->verify);
	session_p->verify.flags = 0;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_verify_update_t verify_update;
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
	 * Application must call C_VerifyInit before calling
	 * C_VerifyUpdate.
	 */
	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->verify.flags |= CRYPTO_OPERATION_UPDATE;

	if (session_p->verify.flags & CRYPTO_EMULATE) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		ses_lock_held = B_FALSE;
		rv = emulate_update(session_p, pPart, ulPartLen, OP_VERIFY);
		goto done;
	}

	verify_update.vu_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	verify_update.vu_datalen = ulPartLen;
	verify_update.vu_databuf = (char *)pPart;

	while ((r = ioctl(kernel_fd, CRYPTO_VERIFY_UPDATE,
	    &verify_update)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(verify_update.vu_return_value);
	}

done:
	if (rv == CKR_OK) {
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current verify
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	REINIT_OPBUF(&session_p->verify);
	session_p->verify.flags = 0;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_verify_final_t verify_final;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_VerifyInit before calling
	 * C_VerifyFinal.
	 */
	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	/* The order of checks is important here */
	if (session_p->verify.flags & CRYPTO_EMULATE_USING_SW) {
		if (session_p->verify.flags & CRYPTO_EMULATE_UPDATE_DONE) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;
			rv = do_soft_hmac_verify(get_spp(&session_p->verify),
			    NULL, 0, pSignature, ulSignatureLen,
			    OP_FINAL);
		} else {
			/*
			 * We should not end up here even if an earlier
			 * C_VerifyFinal() call took the C_Verify() path as
			 * it never returns CKR_BUFFER_TOO_SMALL.
			 */
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			ses_lock_held = B_FALSE;
			rv = CKR_ARGUMENTS_BAD;
		}
		goto clean_exit;
	} else if (session_p->verify.flags & CRYPTO_EMULATE) {
		digest_buf_t *bufp = session_p->verify.context;

		/*
		 * We are emulating a single-part operation now.
		 * So, clear the flag.
		 */
		session_p->verify.flags &= ~CRYPTO_OPERATION_UPDATE;
		if (bufp == NULL || bufp->buf == NULL) {
			rv = CKR_ARGUMENTS_BAD;
			goto clean_exit;
		}
		REFRELE(session_p, ses_lock_held);
		rv = C_Verify(hSession, bufp->buf, bufp->indata_len,
		    pSignature, ulSignatureLen);
		return (rv);
	}

	verify_final.vf_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	verify_final.vf_signlen = ulSignatureLen;
	verify_final.vf_signbuf = (char *)pSignature;

	while ((r = ioctl(kernel_fd, CRYPTO_VERIFY_FINAL, &verify_final)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(verify_final.vf_return_value);
	}

clean_exit:
	/* Always terminate the active verify operation */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;
	REINIT_OPBUF(&session_p->verify);
	session_p->verify.flags = 0;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{

	CK_RV rv;
	kernel_session_t *session_p;
	kernel_object_t	*key_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_verify_recover_init_t vr_init;
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
	 * verify_recover.
	 */
	if (key_p->is_lib_obj && !((key_p->key_type == CKK_RSA) &&
	    (key_p->bool_attr_mask & VERIFY_RECOVER_BOOL_ON))) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * This active flag will remain ON until application calls
	 * C_VerifyRecover to verify a signature on data.
	 */
	session_p->verify.flags = CRYPTO_OPERATION_ACTIVE;

	/* Set up the key data */
	if (!key_p->is_lib_obj) {
		vr_init.ri_key.ck_format = CRYPTO_KEY_REFERENCE;
		vr_init.ri_key.ck_obj_id = key_p->k_handle;
	} else {
		if (key_p->key_type == CKK_RSA) {
			if (get_rsa_public_key(key_p, &vr_init.ri_key) !=
			    CKR_OK) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
		} else {
			rv = CKR_KEY_TYPE_INCONSISTENT;
			goto clean_exit;
		}
	}

	vr_init.ri_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	vr_init.ri_mech.cm_type = k_mech_type;
	vr_init.ri_mech.cm_param = pMechanism->pParameter;
	vr_init.ri_mech.cm_param_len = pMechanism->ulParameterLen;

	while ((r = ioctl(kernel_fd, CRYPTO_VERIFY_RECOVER_INIT,
	    &vr_init)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(vr_init.ri_return_value);
	}

	/* free the memory allocated for vr_init.ri_key */
	if (key_p->is_lib_obj) {
		free_key_attributes(&vr_init.ri_key);
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->verify.flags &= ~CRYPTO_OPERATION_ACTIVE;
		ses_lock_held = B_TRUE;
	}

clean_exit:
	OBJ_REFRELE(key_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_verify_recover_t verify_recover;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (pSignature == NULL || pulDataLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_VerifyRecoverInit before calling
	 * C_Verify.
	 */
	if (!(session_p->verify.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	verify_recover.vr_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;
	verify_recover.vr_signlen = ulSignatureLen;
	verify_recover.vr_signbuf = (char *)pSignature;
	verify_recover.vr_datalen = *pulDataLen;
	verify_recover.vr_databuf = (char *)pData;

	while ((r = ioctl(kernel_fd, CRYPTO_VERIFY_RECOVER,
	    &verify_recover)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(
		    verify_recover.vr_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulDataLen = verify_recover.vr_datalen;

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pData == NULL)) {
		/*
		 * We will not terminate the active verify operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the recovered data.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Always terminate the active verify operation.
	 * Application needs to call C_VerifyInit again for next
	 * verify operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->verify.flags = 0;
	ses_lock_held = B_TRUE;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

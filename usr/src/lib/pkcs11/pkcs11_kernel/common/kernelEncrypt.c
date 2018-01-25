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
#include <stdlib.h>
#include <errno.h>
#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelObject.h"


CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{

	CK_RV rv;
	kernel_session_t *session_p;
	kernel_object_t	*key_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_encrypt_init_t encrypt_init;
	crypto_mech_type_t k_mech_type;
	int r;
	CK_AES_CCM_PARAMS ccm_params = { 0 };

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

	/* Check to see if key object allows for encryption. */
	if (key_p->is_lib_obj && !(key_p->bool_attr_mask & ENCRYPT_BOOL_ON)) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * This active flag will remain ON until application calls either
	 * C_Encrypt or C_EncryptFinal to actually obtain the final piece
	 * of ciphertext.
	 */
	session_p->encrypt.flags = CRYPTO_OPERATION_ACTIVE;

	/* set up key data */
	if (!key_p->is_lib_obj) {
		encrypt_init.ei_key.ck_format = CRYPTO_KEY_REFERENCE;
		encrypt_init.ei_key.ck_obj_id = key_p->k_handle;
	} else {
		if (key_p->class == CKO_SECRET_KEY) {
			encrypt_init.ei_key.ck_format = CRYPTO_KEY_RAW;
			encrypt_init.ei_key.ck_data =
			    get_symmetric_key_value(key_p);
			if (encrypt_init.ei_key.ck_data == NULL) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
			encrypt_init.ei_key.ck_length =
			    OBJ_SEC(key_p)->sk_value_len << 3;

		} else if (key_p->key_type == CKK_RSA) {
			if (get_rsa_public_key(key_p, &encrypt_init.ei_key) !=
			    CKR_OK) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
		} else {
			rv = CKR_KEY_TYPE_INCONSISTENT;
			goto clean_exit;
		}
	}

	encrypt_init.ei_session = session_p->k_session;
	session_p->encrypt.mech = *pMechanism;

	/* Cache this capability value for efficiency */
	if (INPLACE_MECHANISM(session_p->encrypt.mech.mechanism)) {
		session_p->encrypt.flags |= CRYPTO_OPERATION_INPLACE_OK;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	ses_lock_held = B_FALSE;
	encrypt_init.ei_mech.cm_type = k_mech_type;
	encrypt_init.ei_mech.cm_param = pMechanism->pParameter;
	encrypt_init.ei_mech.cm_param_len = pMechanism->ulParameterLen;

	/*
	 * PKCS#11 uses CK_CCM_PARAMS as its mechanism parameter, while the
	 * kernel uses CK_AES_CCM_PARAMS.  Unlike
	 * CK_GCM_PARAMS / CK_AES_GCM_PARAMS, the two definitions are not
	 * equivalent -- the fields are defined in different orders, so
	 * we much translate.
	 */
	if (session_p->encrypt.mech.mechanism == CKM_AES_CCM) {
		if (pMechanism->ulParameterLen != sizeof (CK_CCM_PARAMS)) {
			rv = CKR_MECHANISM_PARAM_INVALID;
			goto clean_exit;
		}
		p11_to_kernel_ccm_params(pMechanism->pParameter, &ccm_params);
		encrypt_init.ei_mech.cm_param = (caddr_t)&ccm_params;
		encrypt_init.ei_mech.cm_param_len = sizeof (ccm_params);
	}

	while ((r = ioctl(kernel_fd, CRYPTO_ENCRYPT_INIT, &encrypt_init)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		if (encrypt_init.ei_return_value != CRYPTO_SUCCESS) {
			rv = crypto2pkcs11_error_number(
			    encrypt_init.ei_return_value);
		}
	}

	/* Free memory allocated for decrypt_init.di_key */
	if (key_p->is_lib_obj) {
		if (key_p->class == CKO_SECRET_KEY) {
			free(encrypt_init.ei_key.ck_data);
		} else if (key_p->key_type == CKK_RSA) {
			free_key_attributes(&encrypt_init.ei_key);
		}
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->encrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		ses_lock_held = B_TRUE;
	}

clean_exit:
	/*
	 * ccm_params does not contain any key material -- just lengths and
	 * pointers, therefore it does not need to be zeroed on exit.
	 */
	OBJ_REFRELE(key_p);
	REFRELE(session_p, ses_lock_held);
	return (rv);
}


CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	boolean_t inplace;
	crypto_encrypt_t encrypt;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

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

	/*
	 * Some encryption algs (often combined mode ciphers such as AES-GCM)
	 * allow 0-byte inputs to encrypt.
	 */
	if (pData == NULL && ulDataLen != 0) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Application must call C_EncryptInit before calling C_Encrypt. */
	if (!(session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
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
		REFRELE(session_p, ses_lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	encrypt.ce_session = session_p->k_session;

	/*
	 * Certain mechanisms, where the length of the ciphertext is
	 * same as the transformed plaintext, can be optimized
	 * by the kernel into an in-place operation. Unfortunately,
	 * some applications use a ciphertext buffer that is larger
	 * than it needs to be. We fix that here.
	 */
	inplace = (session_p->encrypt.flags & CRYPTO_OPERATION_INPLACE_OK) != 0;
	if (ulDataLen < *pulEncryptedDataLen && inplace) {
		encrypt.ce_encrlen = ulDataLen;
	} else {
		encrypt.ce_encrlen = *pulEncryptedDataLen;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	encrypt.ce_datalen = ulDataLen;
	encrypt.ce_databuf = (char *)pData;
	encrypt.ce_encrbuf = (char *)pEncryptedData;
	encrypt.ce_flags =
	    ((inplace && (pEncryptedData != NULL)) ||
	    (pData == pEncryptedData)) &&
	    (encrypt.ce_encrlen == encrypt.ce_datalen) ?
	    CRYPTO_INPLACE_OPERATION : 0;

	while ((r = ioctl(kernel_fd, CRYPTO_ENCRYPT, &encrypt)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(encrypt.ce_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulEncryptedDataLen = encrypt.ce_encrlen;

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pEncryptedData == NULL)) {
		/*
		 * We will not terminate the active encrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the ciphertext.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Terminates the active encrypt operation.
	 * Application needs to call C_EncryptInit again for next
	 * encrypt operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->encrypt.flags = 0;
	ses_lock_held = B_TRUE;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	boolean_t inplace;
	crypto_encrypt_update_t encrypt_update;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

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
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_EncryptInit before calling
	 * C_EncryptUpdate.
	 */
	if (!(session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->encrypt.flags |= CRYPTO_OPERATION_UPDATE;

	encrypt_update.eu_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	encrypt_update.eu_datalen = ulPartLen;
	encrypt_update.eu_databuf = (char *)pPart;
	encrypt_update.eu_encrlen = *pulEncryptedPartLen;
	encrypt_update.eu_encrbuf = (char *)pEncryptedPart;

	inplace = (session_p->encrypt.flags & CRYPTO_OPERATION_INPLACE_OK) != 0;
	encrypt_update.eu_flags =
	    ((inplace && (pEncryptedPart != NULL)) ||
	    (pPart == pEncryptedPart)) &&
	    (encrypt_update.eu_encrlen == encrypt_update.eu_datalen) ?
	    CRYPTO_INPLACE_OPERATION : 0;

	while ((r = ioctl(kernel_fd, CRYPTO_ENCRYPT_UPDATE,
	    &encrypt_update)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(
		    encrypt_update.eu_return_value);
	}

	/*
	 * If CKR_OK or CKR_BUFFER_TOO_SMALL, set the output length.
	 * We don't terminate the current encryption operation.
	 */
	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) {
		*pulEncryptedPartLen = encrypt_update.eu_encrlen;
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current encrypt
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->encrypt.flags = 0;
	ses_lock_held = B_TRUE;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_encrypt_final_t encrypt_final;
	int r;

	if (!kernel_initialized)
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
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_EncryptInit before calling
	 * C_EncryptFinal.
	 */
	if (!(session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	encrypt_final.ef_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	encrypt_final.ef_encrlen = *pulLastEncryptedPartLen;
	encrypt_final.ef_encrbuf = (char *)pLastEncryptedPart;

	while ((r = ioctl(kernel_fd, CRYPTO_ENCRYPT_FINAL,
	    &encrypt_final)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(encrypt_final.ef_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulLastEncryptedPartLen = encrypt_final.ef_encrlen;

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pLastEncryptedPart == NULL)) {
		/*
		 * We will not terminate the active encrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the ciphertext.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/* Terminates the active encrypt operation. */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->encrypt.flags = 0;
	ses_lock_held = B_TRUE;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

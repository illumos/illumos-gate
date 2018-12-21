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


/*
 * Real decryptInit work. The caller doesn't hold the session lock.
 */
CK_RV
kernel_decrypt_init(kernel_session_t *session_p, kernel_object_t *key_p,
    CK_MECHANISM_PTR pMechanism)
{
	CK_RV rv;
	crypto_decrypt_init_t decrypt_init;
	crypto_mech_type_t k_mech_type;
	boolean_t ses_lock_held = B_FALSE;
	int r;
	CK_AES_CCM_PARAMS ccm_params = { 0 };

	/* Check to see if key object allows for decryption. */
	if (key_p->is_lib_obj && !(key_p->bool_attr_mask & DECRYPT_BOOL_ON)) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	/* Get the kernel's internal mechanism number. */
	rv = kernel_mech(pMechanism->mechanism, &k_mech_type);
	if (rv != CKR_OK)
		return (rv);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/*
	 * This active flag will remain ON until application calls either
	 * C_Decrypt or C_DecryptFinal to actually obtain the final piece
	 * of plaintext.
	 */
	session_p->decrypt.flags = CRYPTO_OPERATION_ACTIVE;

	/* set up key data */
	if (!key_p->is_lib_obj) {
		decrypt_init.di_key.ck_format = CRYPTO_KEY_REFERENCE;
		decrypt_init.di_key.ck_obj_id = key_p->k_handle;
	} else {
		if (key_p->class == CKO_SECRET_KEY) {
			decrypt_init.di_key.ck_format = CRYPTO_KEY_RAW;
			decrypt_init.di_key.ck_data =
			    get_symmetric_key_value(key_p);
			if (decrypt_init.di_key.ck_data == NULL) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
			/* KEF key lengths are expressed in bits */
			decrypt_init.di_key.ck_length =
			    OBJ_SEC(key_p)->sk_value_len << 3;

		} else if (key_p->key_type == CKK_RSA) {
			if (get_rsa_private_key(key_p, &decrypt_init.di_key) !=
			    CKR_OK) {
				rv = CKR_HOST_MEMORY;
				goto clean_exit;
			}
		} else {
			rv = CKR_KEY_TYPE_INCONSISTENT;
			goto clean_exit;
		}
	}

	decrypt_init.di_session = session_p->k_session;
	session_p->decrypt.mech = *pMechanism;

	/* Cache this capability value for efficiency */
	if (INPLACE_MECHANISM(session_p->decrypt.mech.mechanism)) {
		session_p->decrypt.flags |= CRYPTO_OPERATION_INPLACE_OK;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	ses_lock_held = B_FALSE;
	decrypt_init.di_mech.cm_type = k_mech_type;
	decrypt_init.di_mech.cm_param = pMechanism->pParameter;
	decrypt_init.di_mech.cm_param_len = pMechanism->ulParameterLen;

	/*
	 * PKCS#11 uses CK_CCM_PARAMS as its mechanism parameter, while the
	 * kernel uses CK_AES_CCM_PARAMS.  Unlike
	 * CK_GCM_PARAMS / CK_AES_GCM_PARAMS, the two definitions are not
	 * equivalent -- the fields are defined in different orders, so
	 * we must translate.
	 */
	if (session_p->decrypt.mech.mechanism == CKM_AES_CCM) {
		if (pMechanism->ulParameterLen != sizeof (CK_CCM_PARAMS)) {
			rv = CKR_MECHANISM_PARAM_INVALID;
			goto clean_exit;
		}
		p11_to_kernel_ccm_params(pMechanism->pParameter, &ccm_params);
		decrypt_init.di_mech.cm_param = (caddr_t)&ccm_params;
		decrypt_init.di_mech.cm_param_len = sizeof (ccm_params);
	}

	while ((r = ioctl(kernel_fd, CRYPTO_DECRYPT_INIT, &decrypt_init)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(decrypt_init.di_return_value);
	}

	/* Free memory allocated for decrypt_init.di_key */
	if (key_p->is_lib_obj) {
		if (key_p->class == CKO_SECRET_KEY) {
			free(decrypt_init.di_key.ck_data);
		} else if (key_p->key_type == CKK_RSA) {
			free_key_attributes(&decrypt_init.di_key);
		}
	}

clean_exit:
	/*
	 * ccm_params does not contain any key material -- just lengths and
	 * pointers, therefore it does not need to be zeroed on exit.
	 */
	if (!ses_lock_held) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		ses_lock_held = B_TRUE;
	}

	if (rv != CKR_OK)
		session_p->decrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;

	if (ses_lock_held) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		ses_lock_held = B_FALSE;
	}

	return (rv);
}

CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{

	CK_RV rv;
	kernel_session_t *session_p;
	kernel_object_t	*key_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pMechanism == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Obtain the object pointer. */
	HANDLE2OBJECT(hKey, key_p, rv);
	if (rv == CKR_OK) {
		rv = kernel_decrypt_init(session_p, key_p, pMechanism);
		OBJ_REFRELE(key_p);
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}



/*
 * Real decrypt work. The caller doesn't hold the session lock.
 */
CK_RV
kernel_decrypt(kernel_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedData, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	crypto_decrypt_t decrypt;
	boolean_t ses_lock_held = B_FALSE;
	boolean_t inplace;
	CK_RV rv;
	int r;

	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	/* Application must call C_DecryptInit before calling C_Decrypt. */
	if (!(session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
		goto clean_exit;
	}

	/*
	 * C_Decrypt must be called without intervening C_DecryptUpdate
	 * calls.
	 */
	if (session_p->decrypt.flags & CRYPTO_OPERATION_UPDATE) {
		/*
		 * C_Decrypt cannot be used to terminate a multiple-part
		 * operation, so we'll leave the active decrypt operation
		 * flag on and let the application continue with the
		 * decrypt update operation.
		 */
		rv = CKR_FUNCTION_FAILED;
		goto clean_exit;
	}

	decrypt.cd_session = session_p->k_session;

	/*
	 * Certain mechanisms, where the length of the plaintext is
	 * same as the transformed ciphertext, can be optimized
	 * by the kernel into an in-place operation. Unfortunately,
	 * some applications use a plaintext buffer that is larger
	 * than it needs to be. We fix that here.
	 */
	inplace = (session_p->decrypt.flags & CRYPTO_OPERATION_INPLACE_OK) != 0;

	if (ulEncryptedData < *pulDataLen && inplace) {
		decrypt.cd_datalen = ulEncryptedData;
	} else {
		decrypt.cd_datalen = *pulDataLen;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	decrypt.cd_databuf = (char *)pData;
	decrypt.cd_encrlen = ulEncryptedData;
	decrypt.cd_encrbuf = (char *)pEncryptedData;
	decrypt.cd_flags =
	    ((inplace && (pData != NULL)) || (pData == pEncryptedData)) &&
	    (decrypt.cd_datalen == decrypt.cd_encrlen) ?
	    CRYPTO_INPLACE_OPERATION : 0;

	while ((r = ioctl(kernel_fd, CRYPTO_DECRYPT, &decrypt)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(decrypt.cd_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulDataLen = decrypt.cd_datalen;

clean_exit:

	if (ses_lock_held)
		(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedData, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * No need to check pData because application might
	 * just want to know the length of decrypted data.
	 */
	if (pulDataLen == NULL) {
		rv = CKR_ARGUMENTS_BAD;
		goto clean_exit;
	}

	rv = kernel_decrypt(session_p, pEncryptedData, ulEncryptedData, pData,
	    pulDataLen);

	if ((rv == CKR_BUFFER_TOO_SMALL) ||
	    (rv == CKR_OK && pData == NULL)) {
		/*
		 * We will not terminate the active decrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the plaintext.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * Terminates the active decrypt operation.
	 * Application needs to call C_DecryptInit again for next
	 * decrypt operation.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->decrypt.flags = 0;
	ses_lock_held = B_TRUE;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	boolean_t inplace;
	crypto_decrypt_update_t decrypt_update;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

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
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_DecryptInit before calling
	 * C_DecryptUpdate.
	 */
	if (!(session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	session_p->decrypt.flags |= CRYPTO_OPERATION_UPDATE;

	decrypt_update.du_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	decrypt_update.du_datalen = *pulPartLen;
	decrypt_update.du_databuf = (char *)pPart;
	decrypt_update.du_encrlen = ulEncryptedPartLen;
	decrypt_update.du_encrbuf = (char *)pEncryptedPart;

	inplace = (session_p->decrypt.flags & CRYPTO_OPERATION_INPLACE_OK) != 0;
	decrypt_update.du_flags =
	    ((inplace && (pPart != NULL)) || (pPart == pEncryptedPart)) &&
	    (decrypt_update.du_datalen == decrypt_update.du_encrlen) ?
	    CRYPTO_INPLACE_OPERATION : 0;

	while ((r = ioctl(kernel_fd, CRYPTO_DECRYPT_UPDATE,
	    &decrypt_update)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(
		    decrypt_update.du_return_value);
	}

	/*
	 * If CKR_OK or CKR_BUFFER_TOO_SMALL, set the output length.
	 * We don't terminate the current decryption operation.
	 */
	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) {
		*pulPartLen = decrypt_update.du_datalen;
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/*
	 * After an error occurred, terminate the current decrypt
	 * operation by resetting the active and update flags.
	 */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->decrypt.flags = 0;
	ses_lock_held = B_TRUE;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}


CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
{

	CK_RV rv;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_decrypt_final_t decrypt_final;
	int r;

	if (!kernel_initialized)
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
	ses_lock_held = B_TRUE;

	/*
	 * Application must call C_DecryptInit before calling
	 * C_DecryptFinal.
	 */
	if (!(session_p->decrypt.flags & CRYPTO_OPERATION_ACTIVE)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_OPERATION_NOT_INITIALIZED);
	}

	decrypt_final.df_session = session_p->k_session;
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	ses_lock_held = B_FALSE;

	decrypt_final.df_datalen = *pulLastPartLen;
	decrypt_final.df_databuf = (char *)pLastPart;

	while ((r = ioctl(kernel_fd, CRYPTO_DECRYPT_FINAL,
	    &decrypt_final)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(decrypt_final.df_return_value);
	}

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*pulLastPartLen = decrypt_final.df_datalen;

	if (rv == CKR_BUFFER_TOO_SMALL ||
	    (rv == CKR_OK && pLastPart == NULL)) {
		/*
		 * We will not terminate the active decrypt operation flag,
		 * when the application-supplied buffer is too small, or
		 * the application asks for the length of buffer to hold
		 * the plaintext.
		 */
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

clean_exit:
	/* Terminates the active decrypt operation */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->decrypt.flags = 0;
	ses_lock_held = B_TRUE;
	REFRELE(session_p, ses_lock_held);

	return (rv);
}

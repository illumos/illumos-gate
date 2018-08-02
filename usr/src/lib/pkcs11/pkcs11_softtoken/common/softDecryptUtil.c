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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <modes/modes.h>
#include <arcfour.h>
#include "softSession.h"
#include "softObject.h"
#include "softOps.h"
#include "softCrypt.h"
#include "softRSA.h"

/*
 * Remove padding bytes.
 */
CK_RV
soft_remove_pkcs7_padding(CK_BYTE *pData, CK_ULONG padded_len,
    CK_ULONG *pulDataLen)
{
	CK_RV	rv;

#ifdef	__sparcv9
	if ((rv = pkcs7_decode(pData, (&padded_len))) != CKR_OK)
#else	/* !__sparcv9 */
	if ((rv = pkcs7_decode(pData, (size_t *)(&padded_len))) != CKR_OK)
#endif	/* __sparcv9 */
		return (rv);

	*pulDataLen = padded_len;
	return (CKR_OK);
}


/*
 * soft_decrypt_init()
 *
 * Arguments:
 *	session_p:	pointer to soft_session_t struct
 *	pMechanism:	pointer to CK_MECHANISM struct provided by application
 *	key_p:		pointer to key soft_object_t struct
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
soft_decrypt_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *key_p)
{

	CK_RV rv;

	switch (pMechanism->mechanism) {

	case CKM_DES_ECB:

		if (key_p->key_type != CKK_DES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		goto ecb_common;

	case CKM_DES3_ECB:

		if ((key_p->key_type != CKK_DES2) &&
		    (key_p->key_type != CKK_DES3)) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

ecb_common:

		return (soft_des_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:

		if (key_p->key_type != CKK_DES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		goto cbc_common;

	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	{
		soft_des_ctx_t *soft_des_ctx;

		if ((key_p->key_type != CKK_DES2) &&
		    (key_p->key_type != CKK_DES3)) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

cbc_common:
		if ((pMechanism->pParameter == NULL) ||
		    (pMechanism->ulParameterLen != DES_BLOCK_LEN)) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		rv = soft_des_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_des_ctx = (soft_des_ctx_t *)session_p->decrypt.context;
		/* Save Initialization Vector (IV) in the context. */
		(void) memcpy(soft_des_ctx->ivec, pMechanism->pParameter,
		    DES_BLOCK_LEN);

		/* Allocate a context for DES cipher-block chaining. */
		soft_des_ctx->des_cbc = (void *)des_cbc_ctx_init(
		    soft_des_ctx->key_sched, soft_des_ctx->keysched_len,
		    soft_des_ctx->ivec, key_p->key_type);

		if (soft_des_ctx->des_cbc == NULL) {
			freezero(soft_des_ctx->key_sched,
			    soft_des_ctx->keysched_len);
			freezero(session_p->decrypt.context,
			    sizeof (soft_des_ctx_t));
			session_p->decrypt.context = NULL;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (CKR_HOST_MEMORY);
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		return (rv);
	}
	case CKM_AES_ECB:

		if (key_p->key_type != CKK_AES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		return (soft_aes_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	{
		soft_aes_ctx_t *soft_aes_ctx;

		if (key_p->key_type != CKK_AES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		if ((pMechanism->pParameter == NULL) ||
		    (pMechanism->ulParameterLen != AES_BLOCK_LEN)) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		rv = soft_aes_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->decrypt.context;

		/* Save Initialization Vector (IV) in the context. */
		(void) memcpy(soft_aes_ctx->ivec, pMechanism->pParameter,
		    AES_BLOCK_LEN);

		/* Allocate a context for AES cipher-block chaining. */
		soft_aes_ctx->aes_cbc = (void *)aes_cbc_ctx_init(
		    soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len,
		    soft_aes_ctx->ivec);

		if (soft_aes_ctx->aes_cbc == NULL) {
			freezero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			freezero(session_p->decrypt.context,
			    sizeof (soft_aes_ctx_t));
			session_p->decrypt.context = NULL;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (CKR_HOST_MEMORY);
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		return (rv);
	}
	case CKM_AES_CTR:
	{
		soft_aes_ctx_t *soft_aes_ctx;

		if (key_p->key_type != CKK_AES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		if (pMechanism->pParameter == NULL ||
		    pMechanism->ulParameterLen != sizeof (CK_AES_CTR_PARAMS)) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		rv = soft_aes_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->decrypt.context;
		soft_aes_ctx->aes_cbc = aes_ctr_ctx_init(
		    soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len,
		    pMechanism->pParameter);

		if (soft_aes_ctx->aes_cbc == NULL) {
			freezero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			freezero(session_p->decrypt.context,
			    sizeof (soft_aes_ctx_t));
			session_p->decrypt.context = NULL;
			rv = CKR_HOST_MEMORY;
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		return (rv);
	}
	case CKM_BLOWFISH_CBC:
	{
		soft_blowfish_ctx_t *soft_blowfish_ctx;

		if (key_p->key_type != CKK_BLOWFISH)
			return (CKR_KEY_TYPE_INCONSISTENT);

		if ((pMechanism->pParameter == NULL) ||
		    (pMechanism->ulParameterLen != BLOWFISH_BLOCK_LEN))
			return (CKR_MECHANISM_PARAM_INVALID);

		rv = soft_blowfish_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_blowfish_ctx =
		    (soft_blowfish_ctx_t *)session_p->decrypt.context;

		/* Save Initialization Vector in the context. */
		(void) memcpy(soft_blowfish_ctx->ivec, pMechanism->pParameter,
		    BLOWFISH_BLOCK_LEN);

		/* Allocate a context for CBC */
		soft_blowfish_ctx->blowfish_cbc =
		    (void *)blowfish_cbc_ctx_init(soft_blowfish_ctx->key_sched,
		    soft_blowfish_ctx->keysched_len,
		    soft_blowfish_ctx->ivec);

		if (soft_blowfish_ctx->blowfish_cbc == NULL) {
			freezero(soft_blowfish_ctx->key_sched,
			    soft_blowfish_ctx->keysched_len);
			freezero(session_p->decrypt.context,
			    sizeof (soft_blowfish_ctx_t));
			session_p->decrypt.context = NULL;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (CKR_HOST_MEMORY);
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return (rv);
	}

	case CKM_RC4:

		if (key_p->key_type != CKK_RC4) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		return (soft_arcfour_crypt_init(session_p, pMechanism, key_p,
		    B_FALSE));

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		if (key_p->key_type != CKK_RSA) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		return (soft_rsa_crypt_init_common(session_p, pMechanism,
		    key_p, B_FALSE));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}


/*
 * soft_decrypt_common()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pEncrypted:	pointer to the encrypted data as input
 *	ulEncryptedLen:	length of the input data
 *	pData:		pointer to the output data contains plaintext
 *	pulDataLen:	pointer to the length of the output data
 *	Update:		boolean flag indicates caller is soft_decrypt
 *			or soft_decrypt_update
 *
 * Description:
 *      This function calls the corresponding decrypt routine based
 *	on the mechanism.
 *
 * Returns:
 *	see soft_decrypt_common().
 */
CK_RV
soft_decrypt_common(soft_session_t *session_p, CK_BYTE_PTR pEncrypted,
    CK_ULONG ulEncryptedLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen, boolean_t Update)
{

	CK_MECHANISM_TYPE mechanism = session_p->decrypt.mech.mechanism;

	switch (mechanism) {

	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES3_ECB:
	case CKM_DES3_CBC:

		if (ulEncryptedLen == 0) {
			*pulDataLen = 0;
			return (CKR_OK);
		}
		/* FALLTHROUGH */

	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:

		return (soft_des_decrypt_common(session_p, pEncrypted,
		    ulEncryptedLen, pData, pulDataLen, Update));

	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CTR:

		if (ulEncryptedLen == 0) {
			*pulDataLen = 0;
			return (CKR_OK);
		}
		/* FALLTHROUGH */

	case CKM_AES_CBC_PAD:

		return (soft_aes_decrypt_common(session_p, pEncrypted,
		    ulEncryptedLen, pData, pulDataLen, Update));

	case CKM_BLOWFISH_CBC:

		if (ulEncryptedLen == 0) {
			*pulDataLen = 0;
			return (CKR_OK);
		}

		return (soft_blowfish_decrypt_common(session_p, pEncrypted,
		    ulEncryptedLen, pData, pulDataLen, Update));

	case CKM_RC4:

		if (ulEncryptedLen == 0) {
			*pulDataLen = 0;
			return (CKR_OK);
		}


		return (soft_arcfour_crypt(&(session_p->decrypt), pEncrypted,
		    ulEncryptedLen, pData, pulDataLen));

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_decrypt_common(session_p, pEncrypted,
		    ulEncryptedLen, pData, pulDataLen, mechanism));

	default:
		return (CKR_MECHANISM_INVALID);

	}
}


/*
 * soft_decrypt()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pEncryptedData: pointer to the encrypted data as input
 *	ulEncryptedDataLen: length of the input data
 *	pData:		pointer to the output data contains plaintext
 *	pulDataLen:	pointer to the length of the output data
 *
 * Description:
 *      called by C_Decrypt(). This function calls the soft_decrypt_common
 *	routine.
 *
 * Returns:
 *	see soft_decrypt_common().
 */
CK_RV
soft_decrypt(soft_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen)
{

	return (soft_decrypt_common(session_p, pEncryptedData,
	    ulEncryptedDataLen, pData, pulDataLen, B_FALSE));
}


/*
 * soft_decrypt_update()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pEncryptedPart: pointer to the encrypted data as input
 *	ulEncryptedPartLen: length of the input data
 *	pPart:          pointer to the output data contains plaintext
 *	pulPartLen:     pointer to the length of the output data
 *
 * Description:
 *      called by C_DecryptUpdate(). This function calls the
 *	soft_decrypt_common routine (with update flag on).
 *
 * Returns:
 *	see soft_decrypt_common().
 */
CK_RV
soft_decrypt_update(soft_session_t *session_p, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_MECHANISM_TYPE mechanism = session_p->decrypt.mech.mechanism;

	switch (mechanism) {

	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTR:
	case CKM_BLOWFISH_CBC:
	case CKM_RC4:

		return (soft_decrypt_common(session_p, pEncryptedPart,
		    ulEncryptedPartLen, pPart, pulPartLen, B_TRUE));

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		return (CKR_MECHANISM_INVALID);
	}

}


/*
 * soft_decrypt_final()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pLastPart:	pointer to the last recovered data part
 *      pulLastPartLen:	pointer to the length of the last recovered data part
 *
 * Description:
 *      called by C_DecryptFinal().
 *
 * Returns:
 *	CKR_OK: success
 *	CKR_FUNCTION_FAILED: decrypt final function failed
 *	CKR_ENCRYPTED_DATA_LEN_RANGE: remaining buffer contains bad length
 */
CK_RV
soft_decrypt_final(soft_session_t *session_p, CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->decrypt.mech.mechanism;
	CK_ULONG out_len;
	CK_RV rv = CKR_OK;
	int rc;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (session_p->decrypt.context == NULL) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
		*pulLastPartLen = 0;
		goto clean2;
	}
	switch (mechanism) {

	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	{

		soft_des_ctx_t *soft_des_ctx;

		soft_des_ctx = (soft_des_ctx_t *)session_p->decrypt.context;

		/*
		 * We should have only one block of data left in the
		 * remaining buffer.
		 */
		if (soft_des_ctx->remain_len != DES_BLOCK_LEN) {
			*pulLastPartLen = 0;
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
			/* Cleanup memory space. */
			free(soft_des_ctx->des_cbc);
			freezero(soft_des_ctx->key_sched,
			    soft_des_ctx->keysched_len);

			goto clean1;
		}

		out_len = DES_BLOCK_LEN;

		/*
		 * If application asks for the length of the output buffer
		 * to hold the plaintext?
		 */
		if (pLastPart == NULL) {
			*pulLastPartLen = out_len;
			rv = CKR_OK;
			goto clean2;
		} else {
			crypto_data_t out;

			/* Copy remaining data to the output buffer. */
			(void) memcpy(pLastPart, soft_des_ctx->data,
			    DES_BLOCK_LEN);

			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = DES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)pLastPart;
			out.cd_raw.iov_len = DES_BLOCK_LEN;

			/* Decrypt final block of data. */
			rc = des_decrypt_contiguous_blocks(
			    (des_ctx_t *)soft_des_ctx->des_cbc,
			    (char *)pLastPart, DES_BLOCK_LEN, &out);

			if (rc == 0) {
				/*
				 * Remove padding bytes after decryption of
				 * ciphertext block to produce the original
				 * plaintext.
				 */
				rv = soft_remove_pkcs7_padding(pLastPart,
				    DES_BLOCK_LEN, &out_len);
				if (rv != CKR_OK)
					*pulLastPartLen = 0;
				else
					*pulLastPartLen = out_len;
			} else {
				*pulLastPartLen = 0;
				rv = CKR_FUNCTION_FAILED;
			}

			/* Cleanup memory space. */
			free(soft_des_ctx->des_cbc);
			freezero(soft_des_ctx->key_sched,
			    soft_des_ctx->keysched_len);

		}

		break;
	}

	case CKM_DES_CBC:
	case CKM_DES_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_ECB:
	{

		soft_des_ctx_t *soft_des_ctx;

		soft_des_ctx = (soft_des_ctx_t *)session_p->decrypt.context;
		/*
		 * CKM_DES_CBC and CKM_DES_ECB does not do any padding,
		 * so when the final is called, the remaining buffer
		 * should not contain any more data.
		 */
		*pulLastPartLen = 0;
		if (soft_des_ctx->remain_len != 0) {
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
		} else {
			if (pLastPart == NULL)
				goto clean2;
		}

		/* Cleanup memory space. */
		free(soft_des_ctx->des_cbc);
		freezero(soft_des_ctx->key_sched,
		    soft_des_ctx->keysched_len);

		break;
	}

	case CKM_AES_CBC_PAD:
	{

		soft_aes_ctx_t *soft_aes_ctx;

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->decrypt.context;

		/*
		 * We should have only one block of data left in the
		 * remaining buffer.
		 */
		if (soft_aes_ctx->remain_len != AES_BLOCK_LEN) {
			*pulLastPartLen = 0;
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
			/* Cleanup memory space. */
			free(soft_aes_ctx->aes_cbc);
			freezero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);

			goto clean1;
		}

		out_len = AES_BLOCK_LEN;

		/*
		 * If application asks for the length of the output buffer
		 * to hold the plaintext?
		 */
		if (pLastPart == NULL) {
			*pulLastPartLen = out_len;
			rv = CKR_OK;
			goto clean2;
		} else {
			crypto_data_t out;

			/* Copy remaining data to the output buffer. */
			(void) memcpy(pLastPart, soft_aes_ctx->data,
			    AES_BLOCK_LEN);

			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = AES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)pLastPart;
			out.cd_raw.iov_len = AES_BLOCK_LEN;

			/* Decrypt final block of data. */
			rc = aes_decrypt_contiguous_blocks(
			    (aes_ctx_t *)soft_aes_ctx->aes_cbc,
			    (char *)pLastPart, AES_BLOCK_LEN, &out);

			if (rc == 0) {
				/*
				 * Remove padding bytes after decryption of
				 * ciphertext block to produce the original
				 * plaintext.
				 */
				rv = soft_remove_pkcs7_padding(pLastPart,
				    AES_BLOCK_LEN, &out_len);
				if (rv != CKR_OK)
					*pulLastPartLen = 0;
				else
					*pulLastPartLen = out_len;
			} else {
				*pulLastPartLen = 0;
				rv = CKR_FUNCTION_FAILED;
			}

			/* Cleanup memory space. */
			free(soft_aes_ctx->aes_cbc);
			freezero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);

		}

		break;
	}

	case CKM_AES_CBC:
	case CKM_AES_ECB:
	{
		soft_aes_ctx_t *soft_aes_ctx;

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->decrypt.context;
		/*
		 * CKM_AES_CBC and CKM_AES_ECB does not do any padding,
		 * so when the final is called, the remaining buffer
		 * should not contain any more data.
		 */
		*pulLastPartLen = 0;
		if (soft_aes_ctx->remain_len != 0) {
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
		} else {
			if (pLastPart == NULL)
				goto clean2;
		}

		/* Cleanup memory space. */
		free(soft_aes_ctx->aes_cbc);
		freezero(soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len);

		break;
	}
	case CKM_AES_CTR:
	{
		crypto_data_t out;
		soft_aes_ctx_t *soft_aes_ctx;
		ctr_ctx_t *ctr_ctx;
		size_t len;

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->decrypt.context;
		ctr_ctx = soft_aes_ctx->aes_cbc;
		len = ctr_ctx->ctr_remainder_len;
		if (pLastPart == NULL) {
			*pulLastPartLen = len;
			goto clean1;
		}
		if (len > 0) {
			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = len;
			out.cd_raw.iov_base = (char *)pLastPart;
			out.cd_raw.iov_len = len;

			rv = ctr_mode_final(ctr_ctx, &out, aes_encrypt_block);
			if (rv == CRYPTO_DATA_LEN_RANGE)
				rv = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
		}
		if (rv == CRYPTO_BUFFER_TOO_SMALL) {
			*pulLastPartLen = len;
			goto clean1;
		}

		/* Cleanup memory space. */
		free(ctr_ctx);
		freezero(soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len);

		break;
	}
	case CKM_BLOWFISH_CBC:
	{
		soft_blowfish_ctx_t *soft_blowfish_ctx;

		soft_blowfish_ctx =
		    (soft_blowfish_ctx_t *)session_p->decrypt.context;

		*pulLastPartLen = 0;
		if (soft_blowfish_ctx->remain_len != 0)
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
		else {
			if (pLastPart == NULL)
				goto clean2;
		}

		free(soft_blowfish_ctx->blowfish_cbc);
		freezero(soft_blowfish_ctx->key_sched,
		    soft_blowfish_ctx->keysched_len);

		break;
	}

	case CKM_RC4:
	{
		ARCFour_key *key = (ARCFour_key *)session_p->decrypt.context;
		explicit_bzero(key, sizeof (*key));
		*pulLastPartLen = 0;
		break;
	}

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		rv = CKR_MECHANISM_INVALID;
		break;
	}

clean1:
	free(session_p->decrypt.context);
	session_p->decrypt.context = NULL;

clean2:
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);

}

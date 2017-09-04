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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
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
 * Add padding bytes with the value of length of padding.
 */
void
soft_add_pkcs7_padding(CK_BYTE *buf, int block_size, CK_ULONG data_len)
{
	(void) pkcs7_encode(NULL, data_len, buf, block_size, block_size);
}

/*
 * Perform encrypt init operation internally for the support of
 * CKM_AES and CKM_DES MAC operations.
 *
 * This function is called with the session being held, and without
 * its mutex taken.
 */
CK_RV
soft_encrypt_init_internal(soft_session_t *session_p, CK_MECHANISM_PTR
    pMechanism, soft_object_t *key_p)
{
	CK_RV rv;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Check to see if encrypt operation is already active */
	if (session_p->encrypt.flags & CRYPTO_OPERATION_ACTIVE) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return (CKR_OPERATION_ACTIVE);
	}

	session_p->encrypt.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_encrypt_init(session_p, pMechanism, key_p);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->encrypt.flags &= ~CRYPTO_OPERATION_ACTIVE;
		(void) pthread_mutex_unlock(&session_p->session_mutex);
	}

	return (rv);
}

/*
 * soft_encrypt_init()
 *
 * Arguments:
 *	session_p:	pointer to soft_session_t struct
 *	pMechanism:	pointer to CK_MECHANISM struct provided by application
 *	key_p:		pointer to key soft_object_t struct
 *
 * Description:
 *	called by C_EncryptInit(). This function calls the corresponding
 *	encrypt init routine based on the mechanism.
 *
 * Returns:
 *	CKR_OK: success
 *	CKR_HOST_MEMORY: run out of system memory
 *	CKR_MECHANISM_PARAM_INVALID: invalid parameters in mechanism
 *	CKR_MECHANISM_INVALID: invalid mechanism type
 *	CKR_KEY_TYPE_INCONSISTENT: incorrect type of key to use
 *		with the specified mechanism
 */
CK_RV
soft_encrypt_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
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
		    key_p, B_TRUE));

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
		    key_p, B_TRUE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_des_ctx = (soft_des_ctx_t *)session_p->encrypt.context;
		/* Copy Initialization Vector (IV) into the context. */
		(void) memcpy(soft_des_ctx->ivec, pMechanism->pParameter,
		    DES_BLOCK_LEN);

		/* Allocate a context for DES cipher-block chaining. */
		soft_des_ctx->des_cbc = (void *)des_cbc_ctx_init(
		    soft_des_ctx->key_sched, soft_des_ctx->keysched_len,
		    soft_des_ctx->ivec, key_p->key_type);

		if (soft_des_ctx->des_cbc == NULL) {
			bzero(soft_des_ctx->key_sched,
			    soft_des_ctx->keysched_len);
			free(soft_des_ctx->key_sched);
			free(session_p->encrypt.context);
			session_p->encrypt.context = NULL;
			rv = CKR_HOST_MEMORY;
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		return (rv);
	}
	case CKM_AES_ECB:

		if (key_p->key_type != CKK_AES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		return (soft_aes_crypt_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		if ((pMechanism->pParameter == NULL) ||
		    (pMechanism->ulParameterLen != AES_BLOCK_LEN)) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}
	/* FALLTHRU */
	case CKM_AES_CMAC:
	{
		soft_aes_ctx_t *soft_aes_ctx;

		if (key_p->key_type != CKK_AES) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}


		rv = soft_aes_crypt_init_common(session_p, pMechanism,
		    key_p, B_TRUE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->encrypt.context;
		/* Copy Initialization Vector (IV) into the context. */
		if (pMechanism->mechanism == CKM_AES_CMAC) {
			(void) bzero(soft_aes_ctx->ivec, AES_BLOCK_LEN);
			/* Allocate a context for AES cipher-block chaining. */
			soft_aes_ctx->aes_cbc = (void *)aes_cmac_ctx_init(
			    soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
		} else {
			(void) memcpy(soft_aes_ctx->ivec,
			    pMechanism->pParameter,
			    AES_BLOCK_LEN);
			/* Allocate a context for AES cipher-block chaining. */
			soft_aes_ctx->aes_cbc = (void *)aes_cbc_ctx_init(
			    soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len,
			    soft_aes_ctx->ivec);
		}
		if (soft_aes_ctx->aes_cbc == NULL) {
			bzero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			free(soft_aes_ctx->key_sched);
			free(session_p->encrypt.context);
			session_p->encrypt.context = NULL;
			rv = CKR_HOST_MEMORY;
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
		    key_p, B_TRUE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->encrypt.context;
		soft_aes_ctx->aes_cbc = aes_ctr_ctx_init(
		    soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len,
		    pMechanism->pParameter);

		if (soft_aes_ctx->aes_cbc == NULL) {
			bzero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			free(soft_aes_ctx->key_sched);
			free(session_p->encrypt.context);
			session_p->encrypt.context = NULL;
			rv = CKR_HOST_MEMORY;
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		return (rv);
	}
	case CKM_RC4:

		if (key_p->key_type != CKK_RC4) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		return (soft_arcfour_crypt_init(session_p, pMechanism, key_p,
		    B_TRUE));

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		if (key_p->key_type != CKK_RSA) {
			return (CKR_KEY_TYPE_INCONSISTENT);
		}

		return (soft_rsa_crypt_init_common(session_p, pMechanism,
		    key_p, B_TRUE));

	case CKM_BLOWFISH_CBC:
	{
		soft_blowfish_ctx_t *soft_blowfish_ctx;

		if (key_p->key_type != CKK_BLOWFISH)
			return (CKR_KEY_TYPE_INCONSISTENT);

		if ((pMechanism->pParameter == NULL) ||
		    (pMechanism->ulParameterLen != BLOWFISH_BLOCK_LEN))
			return (CKR_MECHANISM_PARAM_INVALID);

		rv = soft_blowfish_crypt_init_common(session_p, pMechanism,
		    key_p, B_TRUE);

		if (rv != CKR_OK)
			return (rv);

		(void) pthread_mutex_lock(&session_p->session_mutex);

		soft_blowfish_ctx =
		    (soft_blowfish_ctx_t *)session_p->encrypt.context;
		/* Copy Initialization Vector (IV) into the context. */
		(void) memcpy(soft_blowfish_ctx->ivec, pMechanism->pParameter,
		    BLOWFISH_BLOCK_LEN);

		/* Allocate a context for Blowfish cipher-block chaining */
		soft_blowfish_ctx->blowfish_cbc =
		    (void *)blowfish_cbc_ctx_init(soft_blowfish_ctx->key_sched,
		    soft_blowfish_ctx->keysched_len,
		    soft_blowfish_ctx->ivec);

		if (soft_blowfish_ctx->blowfish_cbc == NULL) {
			bzero(soft_blowfish_ctx->key_sched,
			    soft_blowfish_ctx->keysched_len);
			free(soft_blowfish_ctx->key_sched);
			free(session_p->encrypt.context);
			session_p->encrypt.context = NULL;
			rv = CKR_HOST_MEMORY;
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		return (rv);
	}
	default:
		return (CKR_MECHANISM_INVALID);
	}
}


/*
 * soft_encrypt_common()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pData:		pointer to the input data to be encrypted
 *	ulDataLen:	length of the input data
 *	pEncrypted:	pointer to the output data after encryption
 *	pulEncryptedLen: pointer to the length of the output data
 *	update:		boolean flag indicates caller is soft_encrypt
 *			or soft_encrypt_update
 *
 * Description:
 *      This function calls the corresponding encrypt routine based
 *	on the mechanism.
 *
 * Returns:
 *	see corresponding encrypt routine.
 */
CK_RV
soft_encrypt_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncrypted,
    CK_ULONG_PTR pulEncryptedLen, boolean_t update)
{

	CK_MECHANISM_TYPE mechanism = session_p->encrypt.mech.mechanism;

	switch (mechanism) {

	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES3_ECB:
	case CKM_DES3_CBC:

		if (ulDataLen == 0) {
			*pulEncryptedLen = 0;
			return (CKR_OK);
		}
		/* FALLTHROUGH */

	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:

		return (soft_des_encrypt_common(session_p, pData,
		    ulDataLen, pEncrypted, pulEncryptedLen, update));

	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CTR:

		if (ulDataLen == 0) {
			*pulEncryptedLen = 0;
			return (CKR_OK);
		}
		/* FALLTHROUGH */

	case CKM_AES_CMAC:
	case CKM_AES_CBC_PAD:

		return (soft_aes_encrypt_common(session_p, pData,
		    ulDataLen, pEncrypted, pulEncryptedLen, update));

	case CKM_BLOWFISH_CBC:

		if (ulDataLen == 0) {
			*pulEncryptedLen = 0;
			return (CKR_OK);
		}

		return (soft_blowfish_encrypt_common(session_p, pData,
		    ulDataLen, pEncrypted, pulEncryptedLen, update));

	case CKM_RC4:

		if (ulDataLen == 0) {
			*pulEncryptedLen = 0;
			return (CKR_OK);
		}

		return (soft_arcfour_crypt(&(session_p->encrypt), pData,
		    ulDataLen, pEncrypted, pulEncryptedLen));

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:

		return (soft_rsa_encrypt_common(session_p, pData,
		    ulDataLen, pEncrypted, pulEncryptedLen, mechanism));

	default:
		return (CKR_MECHANISM_INVALID);
	}
}


/*
 * soft_encrypt()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pData:		pointer to the input data to be encrypted
 *	ulDataLen:	length of the input data
 *	pEncryptedData:	pointer to the output data after encryption
 *	pulEncryptedDataLen: pointer to the length of the output data
 *
 * Description:
 *      called by C_Encrypt(). This function calls the soft_encrypt_common
 *	routine.
 *
 * Returns:
 *	see soft_encrypt_common().
 */
CK_RV
soft_encrypt(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{

	return (soft_encrypt_common(session_p, pData, ulDataLen,
	    pEncryptedData, pulEncryptedDataLen, B_FALSE));
}


/*
 * soft_encrypt_update()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pPart:		pointer to the input data to be digested
 *      ulPartLen:	length of the input data
 *	pEncryptedPart:	pointer to the ciphertext
 *	pulEncryptedPartLen: pointer to the length of the ciphertext
 *
 * Description:
 *      called by C_EncryptUpdate(). This function calls the
 *	soft_encrypt_common routine (with update flag on).
 *
 * Returns:
 *	see soft_encrypt_common().
 */
CK_RV
soft_encrypt_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->encrypt.mech.mechanism;

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
	case CKM_AES_CMAC:
	case CKM_AES_CTR:
	case CKM_BLOWFISH_CBC:
	case CKM_RC4:

		return (soft_encrypt_common(session_p, pPart, ulPartLen,
		    pEncryptedPart, pulEncryptedPartLen, B_TRUE));

	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		return (CKR_MECHANISM_INVALID);
	}
}


/*
 * soft_encrypt_final()
 *
 * Arguments:
 *      session_p:		pointer to soft_session_t struct
 *      pLastEncryptedPart:	pointer to the last encrypted data part
 *      pulLastEncryptedPartLen: pointer to the length of the last
 *				encrypted data part
 *
 * Description:
 *      called by C_EncryptFinal().
 *
 * Returns:
 *	CKR_OK: success
 *	CKR_FUNCTION_FAILED: encrypt final function failed
 *	CKR_DATA_LEN_RANGE: remaining buffer contains bad length
 */
CK_RV
soft_encrypt_final(soft_session_t *session_p, CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen)
{

	CK_MECHANISM_TYPE mechanism = session_p->encrypt.mech.mechanism;
	CK_ULONG out_len;
	CK_RV rv = CKR_OK;
	int rc;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (session_p->encrypt.context == NULL) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
		*pulLastEncryptedPartLen = 0;
		goto clean1;
	}
	switch (mechanism) {

	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	{
		soft_des_ctx_t *soft_des_ctx;

		soft_des_ctx = (soft_des_ctx_t *)session_p->encrypt.context;
		/*
		 * For CKM_DES_CBC_PAD, compute output length with
		 * padding. If the remaining buffer has one block
		 * of data, then output length will be two blocksize of
		 * ciphertext. If the remaining buffer has less than
		 * one block of data, then output length will be
		 * one blocksize.
		 */
		if (soft_des_ctx->remain_len == DES_BLOCK_LEN)
			out_len = 2 * DES_BLOCK_LEN;
		else
			out_len = DES_BLOCK_LEN;

		if (pLastEncryptedPart == NULL) {
			/*
			 * Application asks for the length of the output
			 * buffer to hold the ciphertext.
			 */
			*pulLastEncryptedPartLen = out_len;
			goto clean1;
		} else {
			crypto_data_t out;

			/* Copy remaining data to the output buffer. */
			(void) memcpy(pLastEncryptedPart, soft_des_ctx->data,
			    soft_des_ctx->remain_len);

			/*
			 * Add padding bytes prior to encrypt final.
			 */
			soft_add_pkcs7_padding(pLastEncryptedPart +
			    soft_des_ctx->remain_len, DES_BLOCK_LEN,
			    soft_des_ctx->remain_len);

			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = out_len;
			out.cd_raw.iov_base = (char *)pLastEncryptedPart;
			out.cd_raw.iov_len = out_len;

			/* Encrypt multiple blocks of data. */
			rc = des_encrypt_contiguous_blocks(
			    (des_ctx_t *)soft_des_ctx->des_cbc,
			    (char *)pLastEncryptedPart, out_len, &out);

			if (rc == 0) {
				*pulLastEncryptedPartLen = out_len;
			} else {
				*pulLastEncryptedPartLen = 0;
				rv = CKR_FUNCTION_FAILED;
			}

			/* Cleanup memory space. */
			free(soft_des_ctx->des_cbc);
			bzero(soft_des_ctx->key_sched,
			    soft_des_ctx->keysched_len);
			free(soft_des_ctx->key_sched);
		}

		break;
	}
	case CKM_DES_CBC:
	case CKM_DES_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_ECB:
	{

		soft_des_ctx_t *soft_des_ctx;

		soft_des_ctx = (soft_des_ctx_t *)session_p->encrypt.context;
		/*
		 * CKM_DES_CBC and CKM_DES_ECB does not do any padding,
		 * so when the final is called, the remaining buffer
		 * should not contain any more data.
		 */
		*pulLastEncryptedPartLen = 0;
		if (soft_des_ctx->remain_len != 0) {
			rv = CKR_DATA_LEN_RANGE;
		} else {
			if (pLastEncryptedPart == NULL)
				goto clean1;
		}

		/* Cleanup memory space. */
		free(soft_des_ctx->des_cbc);
		bzero(soft_des_ctx->key_sched, soft_des_ctx->keysched_len);
		free(soft_des_ctx->key_sched);

		break;
	}
	case CKM_AES_CBC_PAD:
	{
		soft_aes_ctx_t *soft_aes_ctx;

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->encrypt.context;
		/*
		 * For CKM_AES_CBC_PAD, compute output length with
		 * padding. If the remaining buffer has one block
		 * of data, then output length will be two blocksize of
		 * ciphertext. If the remaining buffer has less than
		 * one block of data, then output length will be
		 * one blocksize.
		 */
		if (soft_aes_ctx->remain_len == AES_BLOCK_LEN)
			out_len = 2 * AES_BLOCK_LEN;
		else
			out_len = AES_BLOCK_LEN;

		if (pLastEncryptedPart == NULL) {
			/*
			 * Application asks for the length of the output
			 * buffer to hold the ciphertext.
			 */
			*pulLastEncryptedPartLen = out_len;
			goto clean1;
		} else {
			crypto_data_t out;

			/* Copy remaining data to the output buffer. */
			(void) memcpy(pLastEncryptedPart, soft_aes_ctx->data,
			    soft_aes_ctx->remain_len);

			/*
			 * Add padding bytes prior to encrypt final.
			 */
			soft_add_pkcs7_padding(pLastEncryptedPart +
			    soft_aes_ctx->remain_len, AES_BLOCK_LEN,
			    soft_aes_ctx->remain_len);

			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = out_len;
			out.cd_raw.iov_base = (char *)pLastEncryptedPart;
			out.cd_raw.iov_len = out_len;

			/* Encrypt multiple blocks of data. */
			rc = aes_encrypt_contiguous_blocks(
			    (aes_ctx_t *)soft_aes_ctx->aes_cbc,
			    (char *)pLastEncryptedPart, out_len, &out);

			if (rc == 0) {
				*pulLastEncryptedPartLen = out_len;
			} else {
				*pulLastEncryptedPartLen = 0;
				rv = CKR_FUNCTION_FAILED;
			}

			/* Cleanup memory space. */
			free(soft_aes_ctx->aes_cbc);
			bzero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			free(soft_aes_ctx->key_sched);
		}

		break;
	}
	case CKM_AES_CMAC:
	{
		soft_aes_ctx_t *soft_aes_ctx;
		soft_aes_ctx = (soft_aes_ctx_t *)session_p->encrypt.context;

		if (pLastEncryptedPart == NULL) {
			/*
			 * Application asks for the length of the output
			 * buffer to hold the ciphertext.
			 */
			*pulLastEncryptedPartLen = AES_BLOCK_LEN;
			goto clean1;
		} else {
			crypto_data_t out;

			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = AES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)pLastEncryptedPart;
			out.cd_raw.iov_len = AES_BLOCK_LEN;

			rc = cmac_mode_final(soft_aes_ctx->aes_cbc, &out,
			    aes_encrypt_block, aes_xor_block);

			if (rc == 0) {
				*pulLastEncryptedPartLen = AES_BLOCK_LEN;
			} else {
				*pulLastEncryptedPartLen = 0;
				rv = CKR_FUNCTION_FAILED;
			}

			/* Cleanup memory space. */
			free(soft_aes_ctx->aes_cbc);
			bzero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			free(soft_aes_ctx->key_sched);
		}

		break;
	}
	case CKM_AES_CBC:
	case CKM_AES_ECB:
	{
		soft_aes_ctx_t *soft_aes_ctx;

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->encrypt.context;
		/*
		 * CKM_AES_CBC and CKM_AES_ECB does not do any padding,
		 * so when the final is called, the remaining buffer
		 * should not contain any more data.
		 */
		*pulLastEncryptedPartLen = 0;
		if (soft_aes_ctx->remain_len != 0) {
			rv = CKR_DATA_LEN_RANGE;
		} else {
			if (pLastEncryptedPart == NULL)
				goto clean1;
		}

		/* Cleanup memory space. */
		free(soft_aes_ctx->aes_cbc);
		bzero(soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len);
		free(soft_aes_ctx->key_sched);

		break;
	}
	case CKM_AES_CTR:
	{
		crypto_data_t out;
		soft_aes_ctx_t *soft_aes_ctx;
		ctr_ctx_t *ctr_ctx;
		size_t len;

		soft_aes_ctx = (soft_aes_ctx_t *)session_p->encrypt.context;
		ctr_ctx = soft_aes_ctx->aes_cbc;
		len = ctr_ctx->ctr_remainder_len;

		if (pLastEncryptedPart == NULL) {
			*pulLastEncryptedPartLen = len;
			goto clean1;
		}
		if (len > 0) {
			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = len;
			out.cd_raw.iov_base = (char *)pLastEncryptedPart;
			out.cd_raw.iov_len = len;

			rv = ctr_mode_final(ctr_ctx, &out, aes_encrypt_block);
		}
		if (rv == CRYPTO_BUFFER_TOO_SMALL) {
			*pulLastEncryptedPartLen = len;
			goto clean1;
		}

		/* Cleanup memory space. */
		free(ctr_ctx);
		bzero(soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len);
		free(soft_aes_ctx->key_sched);

		break;
	}
	case CKM_BLOWFISH_CBC:
	{
		soft_blowfish_ctx_t *soft_blowfish_ctx;

		soft_blowfish_ctx =
		    (soft_blowfish_ctx_t *)session_p->encrypt.context;
		/*
		 * CKM_BLOWFISH_CBC does not do any padding, so when the
		 * final is called, the remaining buffer should not contain
		 * any more data
		 */
		*pulLastEncryptedPartLen = 0;
		if (soft_blowfish_ctx->remain_len != 0)
			rv = CKR_DATA_LEN_RANGE;
		else {
			if (pLastEncryptedPart == NULL)
				goto clean1;
		}

		free(soft_blowfish_ctx->blowfish_cbc);
		bzero(soft_blowfish_ctx->key_sched,
		    soft_blowfish_ctx->keysched_len);
		free(soft_blowfish_ctx->key_sched);
		break;
	}

	case CKM_RC4:
	{
		ARCFour_key *key = (ARCFour_key *)session_p->encrypt.context;
		/* Remaining data size is always zero for RC4. */
		*pulLastEncryptedPartLen = 0;
		if (pLastEncryptedPart == NULL)
			goto clean1;
		bzero(key, sizeof (*key));
		break;
	}
	default:
		/* PKCS11: The mechanism only supports single-part operation. */
		rv = CKR_MECHANISM_INVALID;
		break;
	}

	free(session_p->encrypt.context);
	session_p->encrypt.context = NULL;
clean1:
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

/*
 * This function frees the allocated active crypto context and the
 * lower level of allocated struct as needed.
 * This function is called by the 1st tier of encrypt/decrypt routines
 * or by the 2nd tier of session close routine. Since the 1st tier
 * caller will always call this function without locking the session
 * mutex and the 2nd tier caller will call with the lock, we add the
 * third parameter "lock_held" to distinguish this case.
 */
void
soft_crypt_cleanup(soft_session_t *session_p, boolean_t encrypt,
    boolean_t lock_held)
{

	crypto_active_op_t *active_op;
	boolean_t lock_true = B_TRUE;

	if (!lock_held)
		(void) pthread_mutex_lock(&session_p->session_mutex);

	active_op = (encrypt) ? &(session_p->encrypt) : &(session_p->decrypt);

	switch (active_op->mech.mechanism) {

	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	case CKM_DES_CBC:
	case CKM_DES_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_ECB:
	{

		soft_des_ctx_t *soft_des_ctx =
		    (soft_des_ctx_t *)active_op->context;
		des_ctx_t *des_ctx;

		if (soft_des_ctx != NULL) {
			des_ctx = (des_ctx_t *)soft_des_ctx->des_cbc;
			if (des_ctx != NULL) {
				bzero(des_ctx->dc_keysched,
				    des_ctx->dc_keysched_len);
				free(soft_des_ctx->des_cbc);
			}
			bzero(soft_des_ctx->key_sched,
			    soft_des_ctx->keysched_len);
			free(soft_des_ctx->key_sched);
		}
		break;
	}

	case CKM_AES_CBC_PAD:
	case CKM_AES_CBC:
	case CKM_AES_CMAC:
	case CKM_AES_ECB:
	{
		soft_aes_ctx_t *soft_aes_ctx =
		    (soft_aes_ctx_t *)active_op->context;
		aes_ctx_t *aes_ctx;

		if (soft_aes_ctx != NULL) {
			aes_ctx = (aes_ctx_t *)soft_aes_ctx->aes_cbc;
			if (aes_ctx != NULL) {
				bzero(aes_ctx->ac_keysched,
				    aes_ctx->ac_keysched_len);
				free(soft_aes_ctx->aes_cbc);
			}
			bzero(soft_aes_ctx->key_sched,
			    soft_aes_ctx->keysched_len);
			free(soft_aes_ctx->key_sched);
		}
		break;
	}

	case CKM_BLOWFISH_CBC:
	{
		soft_blowfish_ctx_t *soft_blowfish_ctx =
		    (soft_blowfish_ctx_t *)active_op->context;
		blowfish_ctx_t *blowfish_ctx;

		if (soft_blowfish_ctx != NULL) {
			blowfish_ctx =
			    (blowfish_ctx_t *)soft_blowfish_ctx->blowfish_cbc;
			if (blowfish_ctx != NULL) {
				bzero(blowfish_ctx->bc_keysched,
				    blowfish_ctx->bc_keysched_len);
				free(soft_blowfish_ctx->blowfish_cbc);
			}

			bzero(soft_blowfish_ctx->key_sched,
			    soft_blowfish_ctx->keysched_len);
			free(soft_blowfish_ctx->key_sched);
		}
		break;
	}

	case CKM_RC4:
	{
		ARCFour_key *key = (ARCFour_key *)active_op->context;

		if (key != NULL)
			bzero(key, sizeof (*key));
		break;
	}

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	{
		soft_rsa_ctx_t *rsa_ctx =
		    (soft_rsa_ctx_t *)active_op->context;

		if (rsa_ctx != NULL)
			if (rsa_ctx->key != NULL) {
				soft_cleanup_object(rsa_ctx->key);
				free(rsa_ctx->key);
			}

		break;
	}

	} /* switch */

	if (active_op->context != NULL) {
		free(active_op->context);
		active_op->context = NULL;
	}

	active_op->flags = 0;

	if (!lock_held)
		SES_REFRELE(session_p, lock_true);
}

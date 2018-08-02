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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include "softSession.h"
#include "softObject.h"
#include "softCrypt.h"
#include <blowfish_impl.h>

CK_RV
soft_blowfish_crypt_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p, boolean_t encrypt)
{
	size_t size;
	soft_blowfish_ctx_t *soft_blowfish_ctx;

	soft_blowfish_ctx = calloc(1, sizeof (soft_blowfish_ctx_t));
	if (soft_blowfish_ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	soft_blowfish_ctx->key_sched = blowfish_alloc_keysched(&size, 0);

	if (soft_blowfish_ctx->key_sched == NULL) {
		free(soft_blowfish_ctx);
		return (CKR_HOST_MEMORY);
	}

	soft_blowfish_ctx->keysched_len = size;

	(void) pthread_mutex_lock(&session_p->session_mutex);
	if (encrypt) {
		/* Called by C_EncryptInit */
		session_p->encrypt.context = soft_blowfish_ctx;
		session_p->encrypt.mech.mechanism = pMechanism->mechanism;
	} else {
		/* Called by C_DecryptInit */
		session_p->decrypt.context = soft_blowfish_ctx;
		session_p->decrypt.mech.mechanism = pMechanism->mechanism;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	/*
	 * If this is a non-sensitive key and it does NOT have
	 * a key schedule yet, then allocate one and expand it.
	 * Otherwise, if it's a non-sensitive key, and it DOES have
	 * a key schedule already attached to it, just copy the
	 * pre-expanded schedule to the context and avoid the
	 * extra key schedule expansion operation.
	 */
	if (!(key_p->bool_attr_mask & SENSITIVE_BOOL_ON)) {
		if (OBJ_KEY_SCHED(key_p) == NULL) {
			void *ks;

			(void) pthread_mutex_lock(&key_p->object_mutex);
			if (OBJ_KEY_SCHED(key_p) == NULL) {
				ks = blowfish_alloc_keysched(&size, 0);
				if (ks == NULL) {
					(void) pthread_mutex_unlock(
					    &key_p->object_mutex);
					free(soft_blowfish_ctx);
					return (CKR_HOST_MEMORY);
				}

				blowfish_init_keysched(OBJ_SEC_VALUE(key_p),
				    (OBJ_SEC_VALUE_LEN(key_p) * 8), ks);

				OBJ_KEY_SCHED_LEN(key_p) = size;
				OBJ_KEY_SCHED(key_p) = ks;
			}
			(void) pthread_mutex_unlock(&key_p->object_mutex);
		}
		(void) memcpy(soft_blowfish_ctx->key_sched,
		    OBJ_KEY_SCHED(key_p), OBJ_KEY_SCHED_LEN(key_p));
		soft_blowfish_ctx->keysched_len = OBJ_KEY_SCHED_LEN(key_p);

	} else {
		/*
		 * Initialize key schedule for Blowfish.
		 * blowfish_init_keysched() requires key length in bits.
		 */
		blowfish_init_keysched(OBJ_SEC_VALUE(key_p),
		    (OBJ_SEC_VALUE_LEN(key_p) * 8),
		    soft_blowfish_ctx->key_sched);
	}
	return (CKR_OK);
}


/*
 * soft_blowfish_encrypt_common()
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
 *      CKR_OK: success
 *      CKR_BUFFER_TOO_SMALL: the output buffer provided by application
 *			      is too small
 *	CKR_FUNCTION_FAILED: encrypt function failed
 *	CKR_DATA_LEN_RANGE: the input data is not a multiple of blocksize
 */
CK_RV
soft_blowfish_encrypt_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncrypted, CK_ULONG_PTR pulEncryptedLen,
    boolean_t update)
{
	int rc = 0;
	CK_RV rv = CKR_OK;
	soft_blowfish_ctx_t *soft_blowfish_ctx =
	    (soft_blowfish_ctx_t *)session_p->encrypt.context;
	blowfish_ctx_t *blowfish_ctx;
	CK_BYTE *in_buf = NULL;
	CK_BYTE *out_buf = NULL;
	CK_ULONG out_len;
	CK_ULONG total_len;
	CK_ULONG remain;
	crypto_data_t out;

	/*
	 * Blowfish only takes input length that is a multiple of blocksize
	 * for C_Encrypt function with the mechanism CKM_BLOWFISH_CBC.
	 *
	 */
	if (!update) {
		if ((ulDataLen % BLOWFISH_BLOCK_LEN) != 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto cleanup;
		}

		out_len = ulDataLen;
		/*
		 * If application asks for the length of the output buffer
		 * to hold the ciphertext?
		 */
		if (pEncrypted == NULL) {
			*pulEncryptedLen = out_len;
			return (CKR_OK);
		}

		/* Is the application-supplied buffer large enough? */
		if (*pulEncryptedLen < out_len) {
			*pulEncryptedLen = out_len;
			return (CKR_BUFFER_TOO_SMALL);
		}

		in_buf = pData;
		out_buf = pEncrypted;
	} else {
		/*
		 * Called by C_EncryptUpdate
		 *
		 * Add the lengths of last remaining data and current
		 * plaintext together to get the total input length.
		 */
		total_len = soft_blowfish_ctx->remain_len + ulDataLen;

		/*
		 * If the total input length is less than one blocksize,
		 * we will need to delay encryption until when more data
		 * comes in next C_EncryptUpdate or when C_EncryptFinal
		 * is called.
		 */
		if (total_len < BLOWFISH_BLOCK_LEN) {
			if (pEncrypted != NULL) {
				/*
				 * Save input data and its length in
				 * the remaining buffer of BLOWFISH context.
				 */
				(void) memcpy(soft_blowfish_ctx->data +
				    soft_blowfish_ctx->remain_len, pData,
				    ulDataLen);
				soft_blowfish_ctx->remain_len += ulDataLen;
			}

			/* Set encrypted data length to 0. */
			*pulEncryptedLen = 0;
			return (CKR_OK);
		}

		/* Compute the length of remaing data. */
		remain = total_len % BLOWFISH_BLOCK_LEN;

		/*
		 * Make sure that the output length is a multiple of
		 * blocksize.
		 */
		out_len = total_len - remain;

		/*
		 * If application asks for the length of the output buffer
		 * to hold the ciphertext?
		 */
		if (pEncrypted == NULL) {
			*pulEncryptedLen = out_len;
			return (CKR_OK);
		}

		/* Is the application-supplied buffer large enough? */
		if (*pulEncryptedLen < out_len) {
			*pulEncryptedLen = out_len;
			return (CKR_BUFFER_TOO_SMALL);
		}

		if (soft_blowfish_ctx->remain_len != 0) {
			/*
			 * Copy last remaining data and current input data
			 * to the output buffer.
			 */
			(void) memmove(pEncrypted +
			    soft_blowfish_ctx->remain_len,
			    pData, out_len - soft_blowfish_ctx->remain_len);
			(void) memcpy(pEncrypted, soft_blowfish_ctx->data,
			    soft_blowfish_ctx->remain_len);
			bzero(soft_blowfish_ctx->data,
			    soft_blowfish_ctx->remain_len);

			in_buf = pEncrypted;
		} else {
			in_buf = pData;
		}
		out_buf = pEncrypted;
	}

	/*
	 * Begin Encryption now.
	 */

	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_offset = 0;
	out.cd_length = out_len;
	out.cd_raw.iov_base = (char *)out_buf;
	out.cd_raw.iov_len = out_len;

	/* Encrypt multiple blocks of data. */
	rc = blowfish_encrypt_contiguous_blocks(
	    (blowfish_ctx_t *)soft_blowfish_ctx->blowfish_cbc,
	    (char *)in_buf, out_len, &out);

	if (rc == 0) {
		*pulEncryptedLen = out_len;
		if (update) {
			/*
			 * For encrypt update, if there is remaining data,
			 * save it and it's length in the context.
			 */
			if (remain != 0)
				(void) memcpy(soft_blowfish_ctx->data, pData +
				    (ulDataLen - remain), remain);

			soft_blowfish_ctx->remain_len = remain;
			return (CKR_OK);
		}

	} else {
		*pulEncryptedLen = 0;
		rv = CKR_FUNCTION_FAILED;
	}

cleanup:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	blowfish_ctx = (blowfish_ctx_t *)soft_blowfish_ctx->blowfish_cbc;
	freezero(blowfish_ctx, sizeof (cbc_ctx_t));
	freezero(soft_blowfish_ctx->key_sched,
	    soft_blowfish_ctx->keysched_len);
	freezero(session_p->encrypt.context,
	    sizeof (soft_blowfish_ctx_t));
	session_p->encrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}


CK_RV
soft_blowfish_decrypt_common(soft_session_t *session_p, CK_BYTE_PTR pEncrypted,
    CK_ULONG ulEncryptedLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen,
    boolean_t update)
{
	int rc = 0;
	CK_RV rv = CKR_OK;
	soft_blowfish_ctx_t *soft_blowfish_ctx =
	    (soft_blowfish_ctx_t *)session_p->decrypt.context;
	blowfish_ctx_t *blowfish_ctx;
	CK_BYTE *in_buf = NULL;
	CK_BYTE *out_buf = NULL;
	CK_ULONG out_len;
	CK_ULONG total_len;
	CK_ULONG remain;
	crypto_data_t out;

	/*
	 * Blowfish only takes input length that is a multiple of 16 bytes
	 * for C_Decrypt function using CKM_BLOWFISH_CBC.
	 */

	if (!update) {
		/* Called by C_Decrypt */
		if ((ulEncryptedLen % BLOWFISH_BLOCK_LEN) != 0) {
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
			goto cleanup;
		}

		/*
		 * If application asks for the length of the output buffer
		 * to hold the plaintext?
		 */
		if (pData == NULL) {
			*pulDataLen = ulEncryptedLen;
			return (CKR_OK);
		}

		/* Is the application-supplied buffer large enough? */
		if (*pulDataLen < ulEncryptedLen) {
			*pulDataLen = ulEncryptedLen;
			return (CKR_BUFFER_TOO_SMALL);
		}
		out_len = ulEncryptedLen;
		in_buf = pEncrypted;
		out_buf = pData;
	} else {
		/*
		 * Called by C_DecryptUpdate
		 *
		 * Add the lengths of last remaining data and current
		 * input data together to get the total input length.
		 */
		total_len = soft_blowfish_ctx->remain_len + ulEncryptedLen;

		if (total_len < BLOWFISH_BLOCK_LEN) {
			if (pData != NULL) {
				(void) memcpy(soft_blowfish_ctx->data +
				    soft_blowfish_ctx->remain_len,
				    pEncrypted, ulEncryptedLen);

				soft_blowfish_ctx->remain_len += ulEncryptedLen;
			}

			/* Set output data length to 0. */
			*pulDataLen = 0;
			return (CKR_OK);
		}

		/* Compute the length of remaining data. */
		remain = total_len % BLOWFISH_BLOCK_LEN;

		/*
		 * Make sure that the output length is a multiple of
		 * blocksize.
		 */
		out_len = total_len - remain;

		/*
		 * if application asks for the length of the output buffer
		 * to hold the plaintext?
		 */
		if (pData == NULL) {
			*pulDataLen = out_len;
			return (CKR_OK);
		}

		/*
		 * Is the application-supplied buffer large enough?
		 */
		if (*pulDataLen < out_len) {
			*pulDataLen = out_len;
			return (CKR_BUFFER_TOO_SMALL);
		}

		if (soft_blowfish_ctx->remain_len != 0) {
			/*
			 * Copy last remaining data and current input data
			 * to the output buffer.
			 */
			(void) memmove(pData + soft_blowfish_ctx->remain_len,
			    pEncrypted,
			    out_len - soft_blowfish_ctx->remain_len);
			(void) memcpy(pData, soft_blowfish_ctx->data,
			    soft_blowfish_ctx->remain_len);
			bzero(soft_blowfish_ctx->data,
			    soft_blowfish_ctx->remain_len);


			in_buf = pData;
		} else {
			in_buf = pEncrypted;
		}

		out_buf = pData;
	}

	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_offset = 0;
	out.cd_length = out_len;
	out.cd_raw.iov_base = (char *)out_buf;
	out.cd_raw.iov_len = out_len;

	/* Decrypt multiple blocks of data. */
	rc = blowfish_decrypt_contiguous_blocks(
	    (blowfish_ctx_t *)soft_blowfish_ctx->blowfish_cbc,
	    (char *)in_buf, out_len, &out);

	if (rc == 0) {
		*pulDataLen = out_len;
		if (update) {
			/*
			 * For decrypt update, if there is remaining data,
			 * save it and its length in the context.
			 */
			if (remain != 0)
				(void) memcpy(soft_blowfish_ctx->data,
				    pEncrypted + (ulEncryptedLen - remain),
				    remain);
			soft_blowfish_ctx->remain_len = remain;
			return (CKR_OK);
		}


	} else {
		*pulDataLen = 0;
		rv = CKR_FUNCTION_FAILED;
	}

cleanup:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	blowfish_ctx = (blowfish_ctx_t *)soft_blowfish_ctx->blowfish_cbc;
	free(blowfish_ctx);
	freezero(soft_blowfish_ctx->key_sched,
	    soft_blowfish_ctx->keysched_len);
	freezero(session_p->decrypt.context,
	    sizeof (soft_blowfish_ctx_t));
	session_p->decrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

/*
 * Allocate and initialize a context for BLOWFISH CBC mode of operation.
 */

void *
blowfish_cbc_ctx_init(void *key_sched, size_t size, uint8_t *ivec)
{

	cbc_ctx_t *cbc_ctx;

	if ((cbc_ctx = calloc(1, sizeof (cbc_ctx_t))) == NULL)
		return (NULL);

	cbc_ctx->cbc_keysched = key_sched;

	(void) memcpy(&cbc_ctx->cbc_iv[0], ivec, BLOWFISH_BLOCK_LEN);

	cbc_ctx->cbc_lastp = (uint8_t *)&(cbc_ctx->cbc_iv);
	cbc_ctx->cbc_keysched_len = size;
	cbc_ctx->cbc_flags |= CBC_MODE;

	return (cbc_ctx);
}

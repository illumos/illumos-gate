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
#include <des_impl.h>
#include "softSession.h"
#include "softObject.h"
#include "softCrypt.h"
#include "softOps.h"

/*
 * Allocate context for the active encryption or decryption operation, and
 * generate DES or DES3 key schedule to speed up the operation.
 */
CK_RV
soft_des_crypt_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p,
    boolean_t encrypt)
{

	size_t size;
	soft_des_ctx_t *soft_des_ctx;

	soft_des_ctx = calloc(1, sizeof (soft_des_ctx_t));
	if (soft_des_ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/* Allocate key schedule for DES or DES3 based on key type. */
	if (key_p->key_type == CKK_DES)
		soft_des_ctx->key_sched = des_alloc_keysched(&size, DES, 0);
	else
		soft_des_ctx->key_sched = des_alloc_keysched(&size, DES3, 0);

	if (soft_des_ctx->key_sched == NULL) {
		free(soft_des_ctx);
		return (CKR_HOST_MEMORY);
	}

	soft_des_ctx->keysched_len = size;
	soft_des_ctx->key_type = key_p->key_type;

	(void) pthread_mutex_lock(&session_p->session_mutex);
	if (encrypt) {
		/* Called by C_EncryptInit. */
		session_p->encrypt.context = soft_des_ctx;
		session_p->encrypt.mech.mechanism = pMechanism->mechanism;
	} else {
		/* Called by C_DecryptInit. */
		session_p->decrypt.context = soft_des_ctx;
		session_p->decrypt.mech.mechanism = pMechanism->mechanism;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	/*
	 * If this is a non-sensitive key and it does NOT have
	 * a key schedule yet, then allocate one and expand it.
	 * Otherwise, if its a non-sensitive key, and it DOES have
	 * a key schedule already attached to it, just copy the
	 * pre-expanded schedule to the context and avoid the
	 * extra key schedule expansion operation.
	 */
	if (!(key_p->bool_attr_mask & SENSITIVE_BOOL_ON)) {
		if (OBJ_KEY_SCHED(key_p) == NULL) {
			void *ks;
			(void) pthread_mutex_lock(&key_p->object_mutex);
			if (OBJ_KEY_SCHED(key_p) == NULL) {
				if (key_p->key_type == CKK_DES)
					ks = des_alloc_keysched(&size, DES, 0);
				else
					ks = des_alloc_keysched(&size, DES3, 0);
				if (ks == NULL) {
					(void) pthread_mutex_unlock(
					    &key_p->object_mutex);
					free(soft_des_ctx);
					return (CKR_HOST_MEMORY);
				}
				/* Initialize key schedule for DES or DES3. */
				if (key_p->key_type == CKK_DES)
					des_init_keysched(
					    OBJ_SEC(key_p)->sk_value, DES, ks);
				else if (key_p->key_type == CKK_DES2)
					/*
					 * DES3 encryption/decryption needs to
					 * support a DES2 key.
					 */
					des_init_keysched(
					    OBJ_SEC(key_p)->sk_value, DES2, ks);
				else
					des_init_keysched(
					    OBJ_SEC(key_p)->sk_value, DES3, ks);

				OBJ_KEY_SCHED_LEN(key_p) = size;
				OBJ_KEY_SCHED(key_p) = ks;
			}
			(void) pthread_mutex_unlock(&key_p->object_mutex);
		}

		/* Copy the pre-expanded key schedule from the key object */
		(void) memcpy(soft_des_ctx->key_sched, OBJ_KEY_SCHED(key_p),
		    OBJ_KEY_SCHED_LEN(key_p));
		soft_des_ctx->keysched_len = OBJ_KEY_SCHED_LEN(key_p);
	} else {
		/* for sensitive keys, we cannot cache the key schedule */
		if (key_p->key_type == CKK_DES)
			des_init_keysched(OBJ_SEC(key_p)->sk_value,
			    DES, soft_des_ctx->key_sched);
		else if (key_p->key_type == CKK_DES2)
			/*
			 * DES3 encryption/decryption needs to
			 * support a DES2 key.
			 */
			des_init_keysched(OBJ_SEC(key_p)->sk_value,
			    DES2, soft_des_ctx->key_sched);
		else
			des_init_keysched(OBJ_SEC(key_p)->sk_value,
			    DES3, soft_des_ctx->key_sched);
	}

	return (CKR_OK);
}


/*
 * soft_des_encrypt_common()
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
soft_des_encrypt_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncrypted,
    CK_ULONG_PTR pulEncryptedLen, boolean_t update)
{
	int rc = 0;
	CK_RV rv = CKR_OK;
	soft_des_ctx_t *soft_des_ctx =
	    (soft_des_ctx_t *)session_p->encrypt.context;
	des_ctx_t *des_ctx;
	CK_MECHANISM_TYPE mechanism = session_p->encrypt.mech.mechanism;
	CK_BYTE *in_buf = NULL;
	CK_BYTE *out_buf = NULL;
	CK_ULONG out_len;
	CK_ULONG total_len;
	CK_ULONG remain;
	boolean_t pad_mechanism = B_FALSE;

	pad_mechanism = (mechanism == CKM_DES_CBC_PAD ||
	    mechanism == CKM_DES3_CBC_PAD);
	/*
	 * DES only takes input length that is a multiple of blocksize
	 * for C_Encrypt function with the mechanism CKM_DES<n>_ECB or
	 * CKM_DES<n>_CBC.
	 *
	 * DES allows any input length for C_Encrypt function with the
	 * mechanism CKM_DES<n>_CBC_PAD and for C_EncryptUpdate function.
	 */
	if (!update && !pad_mechanism) {
		if ((ulDataLen % DES_BLOCK_LEN) != 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto cleanup;
		}
	}

	if (!update) {
		/*
		 * Called by C_Encrypt
		 */
		if (pad_mechanism) {
			/*
			 * For CKM_DES<n>_CBC_PAD, compute output length to
			 * count for the padding. If the length of input
			 * data is a multiple of blocksize, then make output
			 * length to be the sum of the input length and
			 * one blocksize. Otherwise, output length will
			 * be rounded up to the next multiple of blocksize.
			 */
			out_len = DES_BLOCK_LEN *
			    (ulDataLen / DES_BLOCK_LEN + 1);
		} else {
			/*
			 * For non-padding mode, the output length will
			 * be same as the input length.
			 */
			out_len = ulDataLen;
		}

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

		/* Encrypt pad bytes in a separate operation */
		if (pad_mechanism) {
			out_len -= DES_BLOCK_LEN;
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
		total_len = soft_des_ctx->remain_len + ulDataLen;

		/*
		 * If the total input length is less than one blocksize,
		 * or if the total input length is just one blocksize and
		 * the mechanism is CKM_DES<n>_CBC_PAD, we will need to delay
		 * encryption until when more data comes in next
		 * C_EncryptUpdate or when C_EncryptFinal is called.
		 */
		if ((total_len < DES_BLOCK_LEN) ||
		    (pad_mechanism && (total_len == DES_BLOCK_LEN))) {
			if (pData != NULL) {
				/*
				 * Save input data and its length in
				 * the remaining buffer of DES context.
				 */
				(void) memcpy(soft_des_ctx->data +
				    soft_des_ctx->remain_len, pData, ulDataLen);
				soft_des_ctx->remain_len += ulDataLen;
			}

			/* Set encrypted data length to 0. */
			*pulEncryptedLen = 0;
			return (CKR_OK);
		}

		/* Compute the length of remaing data. */
		remain = total_len % DES_BLOCK_LEN;

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

		if (soft_des_ctx->remain_len != 0) {
			/*
			 * Copy last remaining data and current input data
			 * to the output buffer.
			 */
			(void) memmove(pEncrypted + soft_des_ctx->remain_len,
			    pData, out_len - soft_des_ctx->remain_len);
			(void) memcpy(pEncrypted, soft_des_ctx->data,
			    soft_des_ctx->remain_len);
			bzero(soft_des_ctx->data, soft_des_ctx->remain_len);

			in_buf = pEncrypted;
		} else {
			in_buf = pData;
		}
		out_buf = pEncrypted;
	}

	/*
	 * Begin Encryption now.
	 */
	switch (mechanism) {

	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	{

		ulong_t i;
		uint8_t *tmp_inbuf;
		uint8_t *tmp_outbuf;

		for (i = 0; i < out_len; i += DES_BLOCK_LEN) {
			tmp_inbuf = &in_buf[i];
			tmp_outbuf = &out_buf[i];
			/* Crunch one block of data for DES. */
			if (soft_des_ctx->key_type == CKK_DES)
				(void) des_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_FALSE);
			else
				(void) des3_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_FALSE);
		}

		if (update) {
			/*
			 * For encrypt update, if there is remaining
			 * data, save it and its length in the context.
			 */
			if (remain != 0)
				(void) memcpy(soft_des_ctx->data, pData +
				    (ulDataLen - remain), remain);
			soft_des_ctx->remain_len = remain;
		}

		*pulEncryptedLen = out_len;
		break;
	}

	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	{
		crypto_data_t out;

		out.cd_format =  CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Encrypt multiple blocks of data. */
		rc = des_encrypt_contiguous_blocks(
		    (des_ctx_t *)soft_des_ctx->des_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0)
			goto encrypt_failed;

		if (update) {
			/*
			 * For encrypt update, if there is remaining data,
			 * save it and its length in the context.
			 */
			if (remain != 0)
				(void) memcpy(soft_des_ctx->data, pData +
				    (ulDataLen - remain), remain);
			soft_des_ctx->remain_len = remain;
		} else if (pad_mechanism) {
			/*
			 * Save the remainder of the input
			 * block in a temporary block because
			 * we don't want to overrun the input buffer
			 * by tacking on pad bytes.
			 */
			CK_BYTE tmpblock[DES_BLOCK_LEN];
			(void) memcpy(tmpblock, in_buf + out_len,
			    ulDataLen - out_len);
			soft_add_pkcs7_padding(tmpblock +
			    (ulDataLen - out_len),
			    DES_BLOCK_LEN, ulDataLen - out_len);

			out.cd_offset = out_len;
			out.cd_length = DES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)out_buf;
			out.cd_raw.iov_len = out_len + DES_BLOCK_LEN;

			/* Encrypt last block containing pad bytes. */
			rc = des_encrypt_contiguous_blocks(
			    (des_ctx_t *)soft_des_ctx->des_cbc,
			    (char *)tmpblock, DES_BLOCK_LEN, &out);
			out_len += DES_BLOCK_LEN;
		}

		if (rc == 0) {
			*pulEncryptedLen = out_len;
			break;
		}
encrypt_failed:
		*pulEncryptedLen = 0;
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;

	}
	} /* end switch */

	if (update)
		return (CKR_OK);

	/*
	 * The following code will be executed if the caller is
	 * soft_encrypt() or an error occurred. The encryption
	 * operation will be terminated so we need to do some cleanup.
	 */
cleanup:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	des_ctx = (des_ctx_t *)soft_des_ctx->des_cbc;
	free(des_ctx);
	freezero(soft_des_ctx->key_sched, soft_des_ctx->keysched_len);
	freezero(session_p->encrypt.context, sizeof (soft_des_ctx_t));
	session_p->encrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}


/*
 * soft_des_decrypt_common()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pEncrypted:	pointer to the input data to be decrypted
 *	ulEncryptedLen:	length of the input data
 *	pData:		pointer to the output data
 *	pulDataLen:	pointer to the length of the output data
 *	Update:		boolean flag indicates caller is soft_decrypt
 *			or soft_decrypt_update
 *
 * Description:
 *      This function calls the corresponding decrypt routine based
 *	on the mechanism.
 *
 * Returns:
 *      CKR_OK: success
 *      CKR_BUFFER_TOO_SMALL: the output buffer provided by application
 *			      is too small
 *	CKR_ENCRYPTED_DATA_LEN_RANGE: the input data is not a multiple
 *				      of blocksize
 *	CKR_FUNCTION_FAILED: decrypt function failed
 */
CK_RV
soft_des_decrypt_common(soft_session_t *session_p, CK_BYTE_PTR pEncrypted,
    CK_ULONG ulEncryptedLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen, boolean_t update)
{

	int rc = 0;
	CK_RV rv = CKR_OK;
	soft_des_ctx_t *soft_des_ctx =
	    (soft_des_ctx_t *)session_p->decrypt.context;
	des_ctx_t *des_ctx;
	CK_MECHANISM_TYPE mechanism = session_p->decrypt.mech.mechanism;
	CK_BYTE *in_buf = NULL;
	CK_BYTE *out_buf = NULL;
	CK_ULONG out_len;
	CK_ULONG total_len;
	CK_ULONG remain;
	boolean_t pad_mechanism = B_FALSE;

	pad_mechanism = (mechanism == CKM_DES_CBC_PAD ||
	    mechanism == CKM_DES3_CBC_PAD);
	/*
	 * DES only takes input length that is a multiple of 8 bytes
	 * for C_Decrypt function with the mechanism CKM_DES<n>_ECB,
	 * CKM_DES<n>_CBC or CKM_DES<n>_CBC_PAD.
	 *
	 * DES allows any input length for C_DecryptUpdate function.
	 */
	if (!update) {
		/*
		 * Called by C_Decrypt
		 */
		if ((ulEncryptedLen % DES_BLOCK_LEN) != 0) {
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
		if (!pad_mechanism) {
			if (*pulDataLen < ulEncryptedLen) {
				*pulDataLen = ulEncryptedLen;
				return (CKR_BUFFER_TOO_SMALL);
			}

			/* Set output length same as input length. */
			out_len = ulEncryptedLen;
		} else {
			/*
			 * For CKM_DES<n>_CBC_PAD, we don't know how
			 * many bytes for padding at this time, so
			 * we'd assume one block was padded.
			 */
			if (*pulDataLen < (ulEncryptedLen - DES_BLOCK_LEN)) {
				*pulDataLen = ulEncryptedLen - DES_BLOCK_LEN;
				return (CKR_BUFFER_TOO_SMALL);
			}
			out_len = ulEncryptedLen - DES_BLOCK_LEN;
		}
		in_buf = pEncrypted;
		out_buf = pData;
	} else {
		/*
		 *  Called by C_DecryptUpdate
		 *
		 * Add the lengths of last remaining data and current
		 * input data together to get the total input length.
		 */
		total_len = soft_des_ctx->remain_len + ulEncryptedLen;

		/*
		 * If the total input length is less than one blocksize,
		 * or if the total input length is just one blocksize and
		 * the mechanism is CKM_DES<n>_CBC_PAD, we will need to delay
		 * decryption until when more data comes in next
		 * C_DecryptUpdate or when C_DecryptFinal is called.
		 */
		if ((total_len < DES_BLOCK_LEN) ||
		    (pad_mechanism && (total_len == DES_BLOCK_LEN))) {
			if (pEncrypted != NULL) {
				/*
				 * Save input data and its length in
				 * the remaining buffer of DES context.
				 */
				(void) memcpy(soft_des_ctx->data +
				    soft_des_ctx->remain_len,
				    pEncrypted, ulEncryptedLen);
				soft_des_ctx->remain_len += ulEncryptedLen;
			}

			/* Set output data length to 0. */
			*pulDataLen = 0;
			return (CKR_OK);
		}

		/* Compute the length of remaing data. */
		remain = total_len % DES_BLOCK_LEN;

		/*
		 * Make sure that the output length is a multiple of
		 * blocksize.
		 */
		out_len = total_len - remain;

		if (pad_mechanism) {
			/*
			 * If the input data length is a multiple of
			 * blocksize, then save the last block of input
			 * data in the remaining buffer. C_DecryptFinal
			 * will handle this last block of data.
			 */
			if (remain == 0) {
				remain = DES_BLOCK_LEN;
				out_len -= DES_BLOCK_LEN;
			}
		}

		/*
		 * If application asks for the length of the output buffer
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

		if (soft_des_ctx->remain_len != 0) {
			/*
			 * Copy last remaining data and current input data
			 * to the output buffer.
			 */
			(void) memmove(pData + soft_des_ctx->remain_len,
			    pEncrypted, out_len - soft_des_ctx->remain_len);
			(void) memcpy(pData, soft_des_ctx->data,
			    soft_des_ctx->remain_len);
			bzero(soft_des_ctx->data, soft_des_ctx->remain_len);

			in_buf = pData;
		} else {
			in_buf = pEncrypted;
		}
		out_buf = pData;
	}

	/*
	 * Begin Decryption.
	 */
	switch (mechanism) {

	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	{
		uint8_t *tmp_inbuf;
		uint8_t *tmp_outbuf;
		ulong_t i;

		for (i = 0; i < out_len; i += DES_BLOCK_LEN) {
			tmp_inbuf = &in_buf[i];
			tmp_outbuf = &out_buf[i];
			/* Crunch one block of data for DES. */
			if (soft_des_ctx->key_type == CKK_DES)
				(void) des_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_TRUE);
			else
				(void) des3_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_TRUE);
		}

		if (update) {
			/*
			 * For decrypt update, if there is remaining
			 * data, save it and its length in the context.
			 */
			if (remain != 0)
				(void) memcpy(soft_des_ctx->data, pEncrypted +
				    (ulEncryptedLen - remain), remain);
			soft_des_ctx->remain_len = remain;
		}

		*pulDataLen = out_len;
		break;
	}

	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	{
		crypto_data_t out;
		CK_ULONG rem_len;
		uint8_t last_block[DES_BLOCK_LEN];

		out.cd_format =  CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Decrypt multiple blocks of data. */
		rc = des_decrypt_contiguous_blocks(
		    (des_ctx_t *)soft_des_ctx->des_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0)
			goto decrypt_failed;

		if (pad_mechanism && !update) {
			/* Decrypt last block containing pad bytes. */
			out.cd_offset = 0;
			out.cd_length = DES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)last_block;
			out.cd_raw.iov_len = DES_BLOCK_LEN;

			/* Decrypt last block containing pad bytes. */
			rc = des_decrypt_contiguous_blocks(
			    (des_ctx_t *)soft_des_ctx->des_cbc,
			    (char *)in_buf + out_len, DES_BLOCK_LEN, &out);

			if (rc != 0)
				goto decrypt_failed;

			/*
			 * Remove padding bytes after decryption of
			 * ciphertext block to produce the original
			 * plaintext.
			 */
			rv = soft_remove_pkcs7_padding(last_block,
			    DES_BLOCK_LEN, &rem_len);
			if (rv == CKR_OK) {
				if (rem_len != 0)
					(void) memcpy(out_buf + out_len,
					    last_block, rem_len);
				*pulDataLen = out_len + rem_len;
			} else {
				*pulDataLen = 0;
				goto cleanup;
			}
		} else {
			*pulDataLen = out_len;
		}

		if (update) {
			/*
			 * For decrypt update, if there is remaining data,
			 * save it and its length in the context.
			 */
			if (remain != 0)
				(void) memcpy(soft_des_ctx->data, pEncrypted +
				    (ulEncryptedLen - remain), remain);
			soft_des_ctx->remain_len = remain;
		}

		if (rc == 0)
			break;
decrypt_failed:
		*pulDataLen = 0;
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}
	} /* end switch */

	if (update)
		return (CKR_OK);

	/*
	 * The following code will be executed if the caller is
	 * soft_decrypt() or an error occurred. The decryption
	 * operation will be terminated so we need to do some cleanup.
	 */
cleanup:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	des_ctx = (des_ctx_t *)soft_des_ctx->des_cbc;
	free(des_ctx);
	freezero(soft_des_ctx->key_sched, soft_des_ctx->keysched_len);
	freezero(session_p->decrypt.context, sizeof (soft_des_ctx_t));
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}


/*
 * Allocate and initialize a context for DES CBC mode of operation.
 */
void *
des_cbc_ctx_init(void *key_sched, size_t size, uint8_t *ivec, CK_KEY_TYPE type)
{

	cbc_ctx_t *cbc_ctx;

	if ((cbc_ctx = calloc(1, sizeof (cbc_ctx_t))) == NULL)
		return (NULL);

	cbc_ctx->cbc_keysched = key_sched;

	(void) memcpy(&cbc_ctx->cbc_iv[0], ivec, DES_BLOCK_LEN);

	cbc_ctx->cbc_lastp = (uint8_t *)&cbc_ctx->cbc_iv[0];
	cbc_ctx->cbc_keysched_len = size;
	if (type == CKK_DES)
		cbc_ctx->cbc_flags |= CBC_MODE;
	else
		cbc_ctx->cbc_flags |= CBC_MODE | DES3_STRENGTH;

	return (cbc_ctx);

}

/*
 * Allocate and initialize DES contexts for both signing and encrypting,
 * saving both context pointers in the session struct. For general-length DES
 * MAC, check the length in the parameter to see if it is in the right range.
 */
CK_RV
soft_des_sign_verify_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p, boolean_t sign_op)
{
	soft_des_ctx_t	*soft_des_ctx;
	CK_MECHANISM	encrypt_mech;
	CK_RV rv;

	if ((key_p->class != CKO_SECRET_KEY) || (key_p->key_type != CKK_DES)) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	/* allocate memory for the sign/verify context */
	soft_des_ctx = malloc(sizeof (soft_des_ctx_t));
	if (soft_des_ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	soft_des_ctx->key_type = key_p->key_type;

	/* initialization vector is zero for DES MAC */
	bzero(soft_des_ctx->ivec, DES_BLOCK_LEN);

	switch (pMechanism->mechanism) {

	case CKM_DES_MAC_GENERAL:

		if (pMechanism->ulParameterLen !=
		    sizeof (CK_MAC_GENERAL_PARAMS)) {
			free(soft_des_ctx);
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		if (*(CK_MAC_GENERAL_PARAMS *)pMechanism->pParameter >
		    DES_BLOCK_LEN) {
			free(soft_des_ctx);
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		soft_des_ctx->mac_len = *((CK_MAC_GENERAL_PARAMS_PTR)
		    pMechanism->pParameter);

		/*FALLTHRU*/
	case CKM_DES_MAC:

		/*
		 * For non-general DES MAC, output is always half as
		 * large as block size
		 */
		if (pMechanism->mechanism == CKM_DES_MAC) {
			soft_des_ctx->mac_len = DES_MAC_LEN;
		}

		/* allocate a context for DES encryption */
		encrypt_mech.mechanism = CKM_DES_CBC_PAD;
		encrypt_mech.pParameter = (void *)soft_des_ctx->ivec;
		encrypt_mech.ulParameterLen = DES_BLOCK_LEN;
		rv = soft_encrypt_init_internal(session_p, &encrypt_mech,
		    key_p);
		if (rv != CKR_OK) {
			free(soft_des_ctx);
			return (rv);
		}

		(void) pthread_mutex_lock(&session_p->session_mutex);

		if (sign_op) {
			session_p->sign.context = soft_des_ctx;
			session_p->sign.mech.mechanism = pMechanism->mechanism;
		} else {
			session_p->verify.context = soft_des_ctx;
			session_p->verify.mech.mechanism =
			    pMechanism->mechanism;
		}

		(void) pthread_mutex_unlock(&session_p->session_mutex);

		break;
	}
	return (CKR_OK);
}

/*
 * Called by soft_sign(), soft_sign_final(), soft_verify() or
 * soft_verify_final().
 */
CK_RV
soft_des_sign_verify_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned, CK_ULONG_PTR pulSignedLen,
    boolean_t sign_op, boolean_t Final)
{
	soft_des_ctx_t		*soft_des_ctx_sign_verify;
	soft_des_ctx_t		*soft_des_ctx_encrypt;
	CK_RV			rv;
	CK_BYTE			*pEncrypted = NULL;
	CK_ULONG		ulEncryptedLen = 0;
	uint8_t			remainder;
	CK_BYTE			last_block[DES_BLOCK_LEN];
	des_ctx_t		*des_ctx = NULL;

	if (sign_op) {
		soft_des_ctx_sign_verify =
		    (soft_des_ctx_t *)session_p->sign.context;

		if (soft_des_ctx_sign_verify->mac_len == 0) {
			*pulSignedLen = 0;
			goto clean_exit;
		}

		/* Application asks for the length of the output buffer. */
		if (pSigned == NULL) {
			*pulSignedLen = soft_des_ctx_sign_verify->mac_len;
			return (CKR_OK);
		}

		/* Is the application-supplied buffer large enough? */
		if (*pulSignedLen < soft_des_ctx_sign_verify->mac_len) {
			*pulSignedLen = soft_des_ctx_sign_verify->mac_len;
			return (CKR_BUFFER_TOO_SMALL);
		}
	} else {
		soft_des_ctx_sign_verify =
		    (soft_des_ctx_t *)session_p->verify.context;
	}

	if (Final) {
		soft_des_ctx_encrypt =
		    (soft_des_ctx_t *)session_p->encrypt.context;

		/*
		 * If there is data left in the buffer from a previous
		 * SignUpdate() call, pass enough zeroed data to a
		 * soft_sign_update call to pad the remainder
		 */
		if (soft_des_ctx_encrypt->remain_len != 0) {
			bzero(last_block, DES_BLOCK_LEN);
			ulEncryptedLen = DES_BLOCK_LEN;

			/*
			 * By passing a buffer to soft_encrypt_final,
			 * we force it to pad the remaining block
			 * and encrypt it.
			 */
			rv = soft_encrypt_final(session_p, last_block,
			    &ulEncryptedLen);
			if (rv != CKR_OK) {
				goto clean_exit;
			}
		} else {
			/*
			 * The last block of enciphered data is stored in:
			 * soft_des_ctx_encrypt->des_cbc->des_ctx->dc_lastp
			 * Copy that data to last_block
			 */
			soft_des_ctx_encrypt =
			    (soft_des_ctx_t *)session_p->encrypt.context;
			des_ctx = (des_ctx_t *)soft_des_ctx_encrypt->des_cbc;
			(void) memcpy(last_block, des_ctx->dc_lastp,
			    DES_BLOCK_LEN);

			/*
			 * Passing a NULL output buffer here
			 * forces the routine to just return.
			 */
			rv = soft_encrypt_final(session_p, NULL,
			    &ulEncryptedLen);
		}

	} else {
		/*
		 * If the input length is not multiple of block size, then
		 * determine the correct encrypted data length by rounding
		 */
		remainder = ulDataLen % DES_BLOCK_LEN;
		/*
		 * Because we always use DES_CBC_PAD mechanism
		 * for sign/verify operations, the input will
		 * be padded to the next 8 byte boundary.
		 * Adjust the length fields here accordingly.
		 */
		ulEncryptedLen = ulDataLen + (DES_BLOCK_LEN - remainder);

		pEncrypted = malloc(sizeof (CK_BYTE) * ulEncryptedLen);
		if (pEncrypted == NULL) {
			rv = CKR_HOST_MEMORY;
			goto clean_exit;
		}

		/*
		 * Pad the last block with zeros by copying pData into a zeroed
		 * pEncrypted. Then pass pEncrypted into soft_encrypt as input
		 */
		bzero(pEncrypted, ulEncryptedLen);
		(void) memcpy(pEncrypted, pData, ulDataLen);

		rv = soft_encrypt(session_p, pEncrypted, ulDataLen,
		    pEncrypted, &ulEncryptedLen);
		(void) memcpy(last_block,
		    &pEncrypted[ulEncryptedLen - DES_BLOCK_LEN], DES_BLOCK_LEN);
	}

	if (rv == CKR_OK) {
		*pulSignedLen = soft_des_ctx_sign_verify->mac_len;

		/* the leftmost mac_len bytes of last_block is our MAC */
		(void) memcpy(pSigned, last_block, *pulSignedLen);
	}

clean_exit:

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* soft_encrypt_common() has freed the encrypt context */
	if (sign_op) {
		free(session_p->sign.context);
		session_p->sign.context = NULL;
	} else {
		free(session_p->verify.context);
		session_p->verify.context = NULL;
	}
	session_p->encrypt.flags = 0;

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	if (pEncrypted) {
		free(pEncrypted);
	}

	return (rv);
}

/*
 * Called by soft_sign_update()
 */
CK_RV
soft_des_mac_sign_verify_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	/*
	 * The DES MAC is calculated by taking the specified number of
	 * left-most bytes within the last block of
	 * encrypted data, while the context of the multi-part
	 * encryption stores the block necessary for XORing with the
	 * input as per cipher block chaining . Therefore, none of the
	 * intermediary encrypted blocks of data are necessary for
	 * the DES MAC, and we can create a placeholder local buffer
	 * for the encrypted data, which is immediately throw away.
	 */

	soft_des_ctx_t	*soft_des_ctx_encrypt;
	CK_BYTE		*pEncrypted = NULL;
	CK_ULONG	ulEncryptedLen;
	CK_ULONG	total_len;
	uint8_t		remainder;
	CK_RV		rv;

	soft_des_ctx_encrypt = (soft_des_ctx_t *)session_p->encrypt.context;

	/* Avoid the malloc if we won't be encrypting any data */
	total_len = soft_des_ctx_encrypt->remain_len + ulPartLen;

	if (total_len < DES_BLOCK_LEN) {
		rv = soft_encrypt_update(session_p, pPart, ulPartLen, NULL,
		    &ulEncryptedLen);
	} else {
		remainder = ulPartLen % DES_BLOCK_LEN;

		/* round up to the nearest multiple of block size */
		ulEncryptedLen = ulPartLen + (DES_BLOCK_LEN - remainder);
		pEncrypted = malloc(sizeof (CK_BYTE) * ulEncryptedLen);

		if (pEncrypted != NULL) {
			rv = soft_encrypt_update(session_p, pPart, ulPartLen,
			    pEncrypted, &ulEncryptedLen);
			free(pEncrypted);
		} else {
			rv = CKR_HOST_MEMORY;
		}
	}
	return (rv);
}

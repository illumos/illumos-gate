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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <aes_impl.h>

#include "kmsSession.h"
#include "kmsObject.h"
#include "kmsCrypt.h"

/*
 * Add padding bytes with the value of length of padding.
 */
static void
kms_add_pkcs7_padding(CK_BYTE *buf, int block_size, CK_ULONG data_len)
{

	ulong_t i, pad_len;
	CK_BYTE pad_value;

	pad_len = block_size - (data_len % block_size);
	pad_value = (CK_BYTE)pad_len;

	for (i = 0; i < pad_len; i++)
		buf[i] = pad_value;
}

/*
 * Remove padding bytes.
 */
static CK_RV
kms_remove_pkcs7_padding(CK_BYTE *pData, CK_ULONG padded_len,
    CK_ULONG *pulDataLen, int block_size)
{

	CK_BYTE  pad_value;
	ulong_t i;

	pad_value = pData[padded_len - 1];


	/* Make sure there is a valid padding value. */
	if ((pad_value == 0) || (pad_value > block_size))
		return (CKR_ENCRYPTED_DATA_INVALID);

	for (i = padded_len - pad_value; i < padded_len; i++)
		if (pad_value != pData[i])
			return (CKR_ENCRYPTED_DATA_INVALID);

	*pulDataLen = padded_len - pad_value;
	return (CKR_OK);
}

/*
 * Allocate context for the active encryption or decryption operation, and
 * generate AES key schedule to speed up the operation.
 */
CK_RV
kms_aes_crypt_init_common(kms_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, kms_object_t *key_p,
    boolean_t encrypt)
{
	size_t size;
	kms_aes_ctx_t *kms_aes_ctx;

	kms_aes_ctx = calloc(1, sizeof (kms_aes_ctx_t));
	if (kms_aes_ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	kms_aes_ctx->key_sched = aes_alloc_keysched(&size, 0);

	if (kms_aes_ctx->key_sched == NULL) {
		free(kms_aes_ctx);
		return (CKR_HOST_MEMORY);
	}

	kms_aes_ctx->keysched_len = size;

	(void) pthread_mutex_lock(&session_p->session_mutex);
	if (encrypt) {
		/* Called by C_EncryptInit. */
		session_p->encrypt.context = kms_aes_ctx;
		session_p->encrypt.mech.mechanism = pMechanism->mechanism;
	} else {
		/* Called by C_DecryptInit. */
		session_p->decrypt.context = kms_aes_ctx;
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
				ks = aes_alloc_keysched(&size, 0);
				if (ks == NULL) {
					(void) pthread_mutex_unlock(
					    &key_p->object_mutex);
					free(kms_aes_ctx);
					return (CKR_HOST_MEMORY);
				}
#ifdef	__sparcv9
				/* LINTED */
				aes_init_keysched(OBJ_SEC_VALUE(key_p), (uint_t)
				    (OBJ_SEC_VALUE_LEN(key_p) * 8), ks);
#else	/* !__sparcv9 */
				aes_init_keysched(OBJ_SEC_VALUE(key_p),
				    (OBJ_SEC_VALUE_LEN(key_p) * 8), ks);
#endif	/* __sparcv9 */
				OBJ_KEY_SCHED_LEN(key_p) = size;
				OBJ_KEY_SCHED(key_p) = ks;
			}
			(void) pthread_mutex_unlock(&key_p->object_mutex);
		}
		(void) memcpy(kms_aes_ctx->key_sched, OBJ_KEY_SCHED(key_p),
		    OBJ_KEY_SCHED_LEN(key_p));
		kms_aes_ctx->keysched_len = OBJ_KEY_SCHED_LEN(key_p);
	} else {
		/*
		 * Initialize key schedule for AES. aes_init_keysched()
		 * requires key length in bits.
		 */
#ifdef	__sparcv9
		/* LINTED */
		aes_init_keysched(OBJ_SEC_VALUE(key_p), (uint_t)
		    (OBJ_SEC_VALUE_LEN(key_p) * 8), kms_aes_ctx->key_sched);
#else	/* !__sparcv9 */
		aes_init_keysched(OBJ_SEC_VALUE(key_p),
		    (OBJ_SEC_VALUE_LEN(key_p) * 8), kms_aes_ctx->key_sched);
#endif	/* __sparcv9 */
	}
	return (CKR_OK);
}

/*
 * kms_aes_encrypt_common()
 *
 * Arguments:
 *      session_p:	pointer to kms_session_t struct
 *	pData:		pointer to the input data to be encrypted
 *	ulDataLen:	length of the input data
 *	pEncrypted:	pointer to the output data after encryption
 *	pulEncryptedLen: pointer to the length of the output data
 *	update:		boolean flag indicates caller is kms_encrypt
 *			or kms_encrypt_update
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
kms_aes_encrypt_common(kms_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncrypted,
    CK_ULONG_PTR pulEncryptedLen, boolean_t update)
{

	int rc = 0;
	CK_RV rv = CKR_OK;
	kms_aes_ctx_t *kms_aes_ctx =
	    (kms_aes_ctx_t *)session_p->encrypt.context;
	aes_ctx_t *aes_ctx;
	CK_MECHANISM_TYPE mechanism = session_p->encrypt.mech.mechanism;
	CK_BYTE *in_buf = NULL;
	CK_BYTE *out_buf = NULL;
	CK_ULONG out_len;
	CK_ULONG total_len;
	CK_ULONG remain;

	if (mechanism == CKM_AES_CTR)
		goto do_encryption;

	/*
	 * AES only takes input length that is a multiple of blocksize
	 * for C_Encrypt function with the mechanism CKM_AES_ECB or
	 * CKM_AES_CBC.
	 *
	 * AES allows any input length for C_Encrypt function with the
	 * mechanism CKM_AES_CBC_PAD and for C_EncryptUpdate function.
	 */
	if ((!update) && (mechanism != CKM_AES_CBC_PAD)) {
		if ((ulDataLen % AES_BLOCK_LEN) != 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto cleanup;
		}
	}

	if (!update) {
		/*
		 * Called by C_Encrypt
		 */
		if (mechanism == CKM_AES_CBC_PAD) {
			/*
			 * For CKM_AES_CBC_PAD, compute output length to
			 * count for the padding. If the length of input
			 * data is a multiple of blocksize, then make output
			 * length to be the sum of the input length and
			 * one blocksize. Otherwise, output length will
			 * be rounded up to the next multiple of blocksize.
			 */
			out_len = AES_BLOCK_LEN *
			    (ulDataLen / AES_BLOCK_LEN + 1);
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
		if (mechanism == CKM_AES_CBC_PAD) {
			out_len -= AES_BLOCK_LEN;
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
		total_len = kms_aes_ctx->remain_len + ulDataLen;

		/*
		 * If the total input length is less than one blocksize,
		 * or if the total input length is just one blocksize and
		 * the mechanism is CKM_AES_CBC_PAD, we will need to delay
		 * encryption until when more data comes in next
		 * C_EncryptUpdate or when C_EncryptFinal is called.
		 */
		if ((total_len < AES_BLOCK_LEN) ||
		    ((mechanism == CKM_AES_CBC_PAD) &&
		    (total_len == AES_BLOCK_LEN))) {
			if (pEncrypted != NULL) {
				/*
				 * Save input data and its length in
				 * the remaining buffer of AES context.
				 */
				(void) memcpy(kms_aes_ctx->data +
				    kms_aes_ctx->remain_len, pData, ulDataLen);
				kms_aes_ctx->remain_len += ulDataLen;
			}

			/* Set encrypted data length to 0. */
			*pulEncryptedLen = 0;
			return (CKR_OK);
		}

		/* Compute the length of remaing data. */
		remain = total_len % AES_BLOCK_LEN;

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

		if (kms_aes_ctx->remain_len != 0) {
			/*
			 * Copy last remaining data and current input data
			 * to the output buffer.
			 */
			(void) memmove(pEncrypted + kms_aes_ctx->remain_len,
			    pData, out_len - kms_aes_ctx->remain_len);
			(void) memcpy(pEncrypted, kms_aes_ctx->data,
			    kms_aes_ctx->remain_len);
			bzero(kms_aes_ctx->data, kms_aes_ctx->remain_len);

			in_buf = pEncrypted;
		} else {
			in_buf = pData;
		}
		out_buf = pEncrypted;
	}

do_encryption:
	/*
	 * Begin Encryption now.
	 */
	switch (mechanism) {

	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	{
		crypto_data_t out;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Encrypt multiple blocks of data. */
		rc = aes_encrypt_contiguous_blocks(
		    (aes_ctx_t *)kms_aes_ctx->aes_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0)
			goto encrypt_failed;

		if (update) {
			/*
			 * For encrypt update, if there is remaining data,
			 * save it and its length in the context.
			 */
			if (remain != 0)
				(void) memcpy(kms_aes_ctx->data, pData +
				    (ulDataLen - remain), remain);
			kms_aes_ctx->remain_len = remain;
		} else if (mechanism == CKM_AES_CBC_PAD) {
			/*
			 * Save the remainder of the input
			 * block in a temporary block because
			 * we dont want to overrun the buffer
			 * by tacking on pad bytes.
			 */
			CK_BYTE tmpblock[AES_BLOCK_LEN];
			(void) memcpy(tmpblock, in_buf + out_len,
			    ulDataLen - out_len);
			kms_add_pkcs7_padding(tmpblock +
			    (ulDataLen - out_len),
			    AES_BLOCK_LEN, ulDataLen - out_len);

			out.cd_offset = out_len;
			out.cd_length = AES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)out_buf;
			out.cd_raw.iov_len = out_len + AES_BLOCK_LEN;

			/* Encrypt last block containing pad bytes. */
			rc = aes_encrypt_contiguous_blocks(
			    (aes_ctx_t *)kms_aes_ctx->aes_cbc,
			    (char *)tmpblock, AES_BLOCK_LEN, &out);

			out_len += AES_BLOCK_LEN;
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
	default:
		rv = CKR_MECHANISM_INVALID;
		goto cleanup;
	} /* end switch */

	if (update)
		return (CKR_OK);

	/*
	 * The following code will be executed if the caller is
	 * kms_encrypt() or an error occurred. The encryption
	 * operation will be terminated so we need to do some cleanup.
	 */
cleanup:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	aes_ctx = (aes_ctx_t *)kms_aes_ctx->aes_cbc;
	if (aes_ctx != NULL) {
		bzero(aes_ctx->ac_keysched, aes_ctx->ac_keysched_len);
		free(kms_aes_ctx->aes_cbc);
	}

	bzero(kms_aes_ctx->key_sched, kms_aes_ctx->keysched_len);
	free(kms_aes_ctx->key_sched);
	free(session_p->encrypt.context);
	session_p->encrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}


/*
 * kms_aes_decrypt_common()
 *
 * Arguments:
 *      session_p:	pointer to kms_session_t struct
 *	pEncrypted:	pointer to the input data to be decrypted
 *	ulEncryptedLen:	length of the input data
 *	pData:		pointer to the output data
 *	pulDataLen:	pointer to the length of the output data
 *	Update:		boolean flag indicates caller is kms_decrypt
 *			or kms_decrypt_update
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
kms_aes_decrypt_common(kms_session_t *session_p, CK_BYTE_PTR pEncrypted,
    CK_ULONG ulEncryptedLen, CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen, boolean_t update)
{

	int rc = 0;
	CK_RV rv = CKR_OK;
	kms_aes_ctx_t *kms_aes_ctx =
	    (kms_aes_ctx_t *)session_p->decrypt.context;
	aes_ctx_t *aes_ctx;
	CK_MECHANISM_TYPE mechanism = session_p->decrypt.mech.mechanism;
	CK_BYTE *in_buf = NULL;
	CK_BYTE *out_buf = NULL;
	CK_ULONG out_len;
	CK_ULONG total_len;
	CK_ULONG remain;

	if (mechanism == CKM_AES_CTR)
		goto do_decryption;

	/*
	 * AES only takes input length that is a multiple of 16 bytes
	 * for C_Decrypt function with the mechanism CKM_AES_ECB,
	 * CKM_AES_CBC or CKM_AES_CBC_PAD.
	 *
	 * AES allows any input length for C_DecryptUpdate function.
	 */
	if (!update) {
		/*
		 * Called by C_Decrypt
		 */
		if ((ulEncryptedLen % AES_BLOCK_LEN) != 0) {
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
		if (mechanism != CKM_AES_CBC_PAD) {
			if (*pulDataLen < ulEncryptedLen) {
				*pulDataLen = ulEncryptedLen;
				return (CKR_BUFFER_TOO_SMALL);
			}
			out_len = ulEncryptedLen;
		} else {
			/*
			 * For CKM_AES_CBC_PAD, we don't know how
			 * many bytes for padding at this time, so
			 * we'd assume one block was padded.
			 */
			if (*pulDataLen < (ulEncryptedLen - AES_BLOCK_LEN)) {
				*pulDataLen = ulEncryptedLen - AES_BLOCK_LEN;
				return (CKR_BUFFER_TOO_SMALL);
			}
			out_len = ulEncryptedLen - AES_BLOCK_LEN;
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
		total_len = kms_aes_ctx->remain_len + ulEncryptedLen;

		/*
		 * If the total input length is less than one blocksize,
		 * or if the total input length is just one blocksize and
		 * the mechanism is CKM_AES_CBC_PAD, we will need to delay
		 * decryption until when more data comes in next
		 * C_DecryptUpdate or when C_DecryptFinal is called.
		 */
		if ((total_len < AES_BLOCK_LEN) ||
		    ((mechanism == CKM_AES_CBC_PAD) &&
		    (total_len == AES_BLOCK_LEN))) {
			if (pData != NULL) {
				/*
				 * Save input data and its length in
				 * the remaining buffer of AES context.
				 */
				(void) memcpy(kms_aes_ctx->data +
				    kms_aes_ctx->remain_len,
				    pEncrypted, ulEncryptedLen);
				kms_aes_ctx->remain_len += ulEncryptedLen;
			}

			/* Set output data length to 0. */
			*pulDataLen = 0;
			return (CKR_OK);
		}

		/* Compute the length of remaing data. */
		remain = total_len % AES_BLOCK_LEN;

		/*
		 * Make sure that the output length is a multiple of
		 * blocksize.
		 */
		out_len = total_len - remain;

		if (mechanism == CKM_AES_CBC_PAD) {
			/*
			 * If the input data length is a multiple of
			 * blocksize, then save the last block of input
			 * data in the remaining buffer. C_DecryptFinal
			 * will handle this last block of data.
			 */
			if (remain == 0) {
				remain = AES_BLOCK_LEN;
				out_len -= AES_BLOCK_LEN;
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

		if (kms_aes_ctx->remain_len != 0) {
			/*
			 * Copy last remaining data and current input data
			 * to the output buffer.
			 */
			(void) memmove(pData + kms_aes_ctx->remain_len,
			    pEncrypted, out_len - kms_aes_ctx->remain_len);
			(void) memcpy(pData, kms_aes_ctx->data,
			    kms_aes_ctx->remain_len);
			bzero(kms_aes_ctx->data, kms_aes_ctx->remain_len);

			in_buf = pData;
		} else {
			in_buf = pEncrypted;
		}
		out_buf = pData;
	}

do_decryption:
	/*
	 * Begin Decryption.
	 */
	switch (mechanism) {
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	{
		crypto_data_t out;
		CK_ULONG rem_len;
		uint8_t last_block[AES_BLOCK_LEN];

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Decrypt multiple blocks of data. */
		rc = aes_decrypt_contiguous_blocks(
		    (aes_ctx_t *)kms_aes_ctx->aes_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0)
			goto decrypt_failed;

		if ((mechanism == CKM_AES_CBC_PAD) && (!update)) {
			/* Decrypt last block containing pad bytes. */
			out.cd_offset = 0;
			out.cd_length = AES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)last_block;
			out.cd_raw.iov_len = AES_BLOCK_LEN;

			/* Decrypt last block containing pad bytes. */
			rc = aes_decrypt_contiguous_blocks(
			    (aes_ctx_t *)kms_aes_ctx->aes_cbc,
			    (char *)in_buf + out_len, AES_BLOCK_LEN, &out);

			if (rc != 0)
				goto decrypt_failed;

			/*
			 * Remove padding bytes after decryption of
			 * ciphertext block to produce the original
			 * plaintext.
			 */
			rv = kms_remove_pkcs7_padding(last_block,
			    AES_BLOCK_LEN, &rem_len, AES_BLOCK_LEN);
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
				(void) memcpy(kms_aes_ctx->data, pEncrypted +
				    (ulEncryptedLen - remain), remain);
			kms_aes_ctx->remain_len = remain;
		}

		if (rc == 0)
			break;
decrypt_failed:
		*pulDataLen = 0;
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}
	default:
		rv = CKR_MECHANISM_INVALID;
		goto cleanup;
	} /* end switch */

	if (update)
		return (CKR_OK);

	/*
	 * The following code will be executed if the caller is
	 * kms_decrypt() or an error occurred. The decryption
	 * operation will be terminated so we need to do some cleanup.
	 */
cleanup:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	aes_ctx = (aes_ctx_t *)kms_aes_ctx->aes_cbc;
	if (aes_ctx != NULL) {
		bzero(aes_ctx->ac_keysched, aes_ctx->ac_keysched_len);
		free(kms_aes_ctx->aes_cbc);
	}

	bzero(kms_aes_ctx->key_sched, kms_aes_ctx->keysched_len);
	free(kms_aes_ctx->key_sched);
	free(session_p->decrypt.context);
	session_p->decrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}


/*
 * Allocate and initialize a context for AES CBC mode of operation.
 */
void *
aes_cbc_ctx_init(void *key_sched, size_t size, uint8_t *ivec)
{
	aes_ctx_t *aes_ctx;

	if ((aes_ctx = calloc(1, sizeof (aes_ctx_t))) == NULL)
		return (NULL);

	aes_ctx->ac_keysched = key_sched;

	(void) memcpy(&aes_ctx->ac_iv[0], ivec, AES_BLOCK_LEN);

	aes_ctx->ac_lastp = (uint8_t *)aes_ctx->ac_iv;
	aes_ctx->ac_keysched_len = size;
	aes_ctx->ac_flags |= CBC_MODE;

	return ((void *)aes_ctx);
}

/*
 * kms_encrypt_final()
 *
 * Arguments:
 *      session_p:		pointer to kms_session_t struct
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
kms_aes_encrypt_final(kms_session_t *session_p, CK_BYTE_PTR pLastEncryptedPart,
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

	}
	if (mechanism == CKM_AES_CBC_PAD) {
		kms_aes_ctx_t *aes_ctx;

		aes_ctx = (kms_aes_ctx_t *)session_p->encrypt.context;
		/*
		 * For CKM_AES_CBC_PAD, compute output length with
		 * padding. If the remaining buffer has one block
		 * of data, then output length will be two blocksize of
		 * ciphertext. If the remaining buffer has less than
		 * one block of data, then output length will be
		 * one blocksize.
		 */
		if (aes_ctx->remain_len == AES_BLOCK_LEN)
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
			(void) memcpy(pLastEncryptedPart, aes_ctx->data,
			    aes_ctx->remain_len);

			/*
			 * Add padding bytes prior to encrypt final.
			 */
			kms_add_pkcs7_padding(pLastEncryptedPart +
			    aes_ctx->remain_len, AES_BLOCK_LEN,
			    aes_ctx->remain_len);

			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = out_len;
			out.cd_raw.iov_base = (char *)pLastEncryptedPart;
			out.cd_raw.iov_len = out_len;

			/* Encrypt multiple blocks of data. */
			rc = aes_encrypt_contiguous_blocks(
			    (aes_ctx_t *)aes_ctx->aes_cbc,
			    (char *)pLastEncryptedPart, out_len, &out);

			if (rc == 0) {
				*pulLastEncryptedPartLen = out_len;
			} else {
				*pulLastEncryptedPartLen = 0;
				rv = CKR_FUNCTION_FAILED;
			}

			/* Cleanup memory space. */
			free(aes_ctx->aes_cbc);
			bzero(aes_ctx->key_sched,
			    aes_ctx->keysched_len);
			free(aes_ctx->key_sched);
		}
	} else if (mechanism == CKM_AES_CBC) {
		kms_aes_ctx_t *aes_ctx;

		aes_ctx = (kms_aes_ctx_t *)session_p->encrypt.context;
		/*
		 * CKM_AES_CBC and CKM_AES_ECB does not do any padding,
		 * so when the final is called, the remaining buffer
		 * should not contain any more data.
		 */
		*pulLastEncryptedPartLen = 0;
		if (aes_ctx->remain_len != 0) {
			rv = CKR_DATA_LEN_RANGE;
		} else {
			if (pLastEncryptedPart == NULL)
				goto clean1;
		}

		/* Cleanup memory space. */
		free(aes_ctx->aes_cbc);
		bzero(aes_ctx->key_sched, aes_ctx->keysched_len);
		free(aes_ctx->key_sched);
	} else {
		rv = CKR_MECHANISM_INVALID;
	}

	free(session_p->encrypt.context);
	session_p->encrypt.context = NULL;
clean1:
	(void) pthread_mutex_unlock(&session_p->session_mutex);
	return (rv);
}

/*
 * kms_decrypt_final()
 *
 * Arguments:
 *      session_p:	pointer to kms_session_t struct
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
kms_aes_decrypt_final(kms_session_t *session_p, CK_BYTE_PTR pLastPart,
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

	case CKM_AES_CBC_PAD:
	{
		kms_aes_ctx_t *kms_aes_ctx;
		kms_aes_ctx = (kms_aes_ctx_t *)session_p->decrypt.context;

		/*
		 * We should have only one block of data left in the
		 * remaining buffer.
		 */
		if (kms_aes_ctx->remain_len != AES_BLOCK_LEN) {
			*pulLastPartLen = 0;
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
			/* Cleanup memory space. */
			free(kms_aes_ctx->aes_cbc);
			bzero(kms_aes_ctx->key_sched,
			    kms_aes_ctx->keysched_len);
			free(kms_aes_ctx->key_sched);

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
			(void) memcpy(pLastPart, kms_aes_ctx->data,
			    AES_BLOCK_LEN);

			out.cd_format = CRYPTO_DATA_RAW;
			out.cd_offset = 0;
			out.cd_length = AES_BLOCK_LEN;
			out.cd_raw.iov_base = (char *)pLastPart;
			out.cd_raw.iov_len = AES_BLOCK_LEN;

			/* Decrypt final block of data. */
			rc = aes_decrypt_contiguous_blocks(
			    (aes_ctx_t *)kms_aes_ctx->aes_cbc,
			    (char *)pLastPart, AES_BLOCK_LEN, &out);

			if (rc == 0) {
				/*
				 * Remove padding bytes after decryption of
				 * ciphertext block to produce the original
				 * plaintext.
				 */
				rv = kms_remove_pkcs7_padding(pLastPart,
				    AES_BLOCK_LEN, &out_len, AES_BLOCK_LEN);
				if (rv != CKR_OK)
					*pulLastPartLen = 0;
				else
					*pulLastPartLen = out_len;
			} else {
				*pulLastPartLen = 0;
				rv = CKR_FUNCTION_FAILED;
			}

			/* Cleanup memory space. */
			free(kms_aes_ctx->aes_cbc);
			bzero(kms_aes_ctx->key_sched,
			    kms_aes_ctx->keysched_len);
			free(kms_aes_ctx->key_sched);

		}

		break;
	}

	case CKM_AES_CBC:
	{
		kms_aes_ctx_t *kms_aes_ctx;

		kms_aes_ctx = (kms_aes_ctx_t *)session_p->decrypt.context;
		/*
		 * CKM_AES_CBC and CKM_AES_ECB does not do any padding,
		 * so when the final is called, the remaining buffer
		 * should not contain any more data.
		 */
		*pulLastPartLen = 0;
		if (kms_aes_ctx->remain_len != 0) {
			rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
		} else {
			if (pLastPart == NULL)
				goto clean2;
		}

		/* Cleanup memory space. */
		free(kms_aes_ctx->aes_cbc);
		bzero(kms_aes_ctx->key_sched, kms_aes_ctx->keysched_len);
		free(kms_aes_ctx->key_sched);

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

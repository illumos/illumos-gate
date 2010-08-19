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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/crypto/common.h>
#include <modes/modes.h>
#define	_AES_FIPS_POST
#include <fips/fips_test_vectors.h>
#ifndef	_KERNEL
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softCrypt.h"
#else
#define	_AES_IMPL
#include <aes/aes_impl.h>
#endif


#ifdef _KERNEL
void *
aes_cbc_ctx_init(void *key_sched, size_t size, uint8_t *ivec)
{

	cbc_ctx_t *cbc_ctx;

	if ((cbc_ctx = kmem_zalloc(sizeof (cbc_ctx_t), KM_SLEEP)) == NULL)
		return (NULL);

	cbc_ctx->cbc_keysched = key_sched;
	cbc_ctx->cbc_keysched_len = size;

	(void) memcpy(&cbc_ctx->cbc_iv[0], ivec, AES_BLOCK_LEN);

	cbc_ctx->cbc_lastp = (uint8_t *)cbc_ctx->cbc_iv;
	cbc_ctx->cbc_flags |= CBC_MODE;

	return (cbc_ctx);
}

/*
 * Allocate and initialize a context for AES CTR mode of operation.
 */
void *
aes_ctr_ctx_init(void *key_sched, size_t size, uint8_t *param)
{

	ctr_ctx_t *ctr_ctx;
	CK_AES_CTR_PARAMS *pp;

	/* LINTED: pointer alignment */
	pp = (CK_AES_CTR_PARAMS *)param;

	if ((ctr_ctx = kmem_zalloc(sizeof (ctr_ctx_t), KM_SLEEP)) == NULL)
		return (NULL);

	ctr_ctx->ctr_keysched = key_sched;
	ctr_ctx->ctr_keysched_len = size;

	if (ctr_init_ctx(ctr_ctx, pp->ulCounterBits, pp->cb,
	    aes_copy_block) != CRYPTO_SUCCESS) {
		kmem_free(ctr_ctx, sizeof (ctr_ctx_t));
		return (NULL);
	}
	ctr_ctx->ctr_flags |= CTR_MODE;

	return (ctr_ctx);
}

/*
 * Allocate and initialize a context for AES CCM mode of operation.
 */
void *
aes_ccm_ctx_init(void *key_sched, size_t size, uint8_t *param,
	boolean_t is_encrypt_init)
{

	ccm_ctx_t *ccm_ctx;

	if ((ccm_ctx = kmem_zalloc(sizeof (ccm_ctx_t), KM_SLEEP)) == NULL)
		return (NULL);

	ccm_ctx->ccm_keysched = key_sched;
	ccm_ctx->ccm_keysched_len = size;

	if (ccm_init_ctx(ccm_ctx, (char *)param, KM_SLEEP,
	    is_encrypt_init, AES_BLOCK_LEN, aes_encrypt_block,
	    aes_xor_block) != CRYPTO_SUCCESS) {
		kmem_free(ccm_ctx, sizeof (ccm_ctx_t));
		return (NULL);
	}
	ccm_ctx->ccm_flags |= CCM_MODE;

	return (ccm_ctx);
}

/*
 * Allocate and initialize a context for AES CCM mode of operation.
 */
void *
aes_gcm_ctx_init(void *key_sched, size_t size, uint8_t *param)
{

	gcm_ctx_t *gcm_ctx;

	if ((gcm_ctx = kmem_zalloc(sizeof (gcm_ctx_t), KM_SLEEP)) == NULL)
		return (NULL);

	gcm_ctx->gcm_keysched = key_sched;
	gcm_ctx->gcm_keysched_len = size;

	if (gcm_init_ctx(gcm_ctx, (char *)param, AES_BLOCK_LEN,
	    aes_encrypt_block, aes_copy_block,
	    aes_xor_block) != CRYPTO_SUCCESS) {
		kmem_free(gcm_ctx, sizeof (gcm_ctx_t));
		return (NULL);
	}
	gcm_ctx->gcm_flags |= GCM_MODE;

	return (gcm_ctx);
}

void *
aes_gmac_ctx_init(void *key_sched, size_t size, uint8_t *param)
{

	gcm_ctx_t *gcm_ctx;

	if ((gcm_ctx = kmem_zalloc(sizeof (gcm_ctx_t), KM_SLEEP)) == NULL)
		return (NULL);

	gcm_ctx->gcm_keysched = key_sched;
	gcm_ctx->gcm_keysched_len = size;

	if (gmac_init_ctx(gcm_ctx, (char *)param, AES_BLOCK_LEN,
	    aes_encrypt_block, aes_copy_block,
	    aes_xor_block) != CRYPTO_SUCCESS) {
		kmem_free(gcm_ctx, sizeof (gcm_ctx_t));
		return (NULL);
	}
	gcm_ctx->gcm_flags |= GMAC_MODE;

	return (gcm_ctx);
}
#endif


/*
 * Allocate context for the active encryption or decryption operation, and
 * generate AES key schedule to speed up the operation.
 */
soft_aes_ctx_t *
#ifdef _KERNEL
fips_aes_build_context(uint8_t *key, int key_len, uint8_t *iv,
	aes_mech_type_t mechanism, boolean_t is_encrypt_init)
#else
fips_aes_build_context(uint8_t *key, int key_len, uint8_t *iv,
	CK_MECHANISM_TYPE mechanism)
#endif
{
	size_t size;
	soft_aes_ctx_t *soft_aes_ctx;
	CK_AES_CTR_PARAMS pp;

#ifdef _KERNEL
	if ((soft_aes_ctx = kmem_zalloc(sizeof (soft_aes_ctx_t),
	    KM_SLEEP)) == NULL)
#else
	if ((soft_aes_ctx = calloc(1, sizeof (soft_aes_ctx_t)))
	    == NULL)
#endif
		return (NULL);


	soft_aes_ctx->key_sched = aes_alloc_keysched(&size, 0);

	if (soft_aes_ctx->key_sched == NULL) {
#ifdef _KERNEL
		kmem_free(soft_aes_ctx, sizeof (soft_aes_ctx_t));
#else
		free(soft_aes_ctx);
#endif
		return (NULL);
	}

	soft_aes_ctx->keysched_len = size;

#ifdef	__sparcv9
	aes_init_keysched(key, (uint_t)(key_len * 8),
	    soft_aes_ctx->key_sched);
#else	/* !__sparcv9 */
	aes_init_keysched(key, (key_len * 8),
	    soft_aes_ctx->key_sched);
#endif	/* __sparcv9 */

	switch (mechanism) {

	case CKM_AES_CBC:

		/* Save Initialization Vector (IV) in the context. */
		(void) memcpy(soft_aes_ctx->ivec, iv, AES_BLOCK_LEN);
		/* Allocate a context for AES cipher-block chaining. */
		soft_aes_ctx->aes_cbc = (void *)aes_cbc_ctx_init(
		    soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len,
		    soft_aes_ctx->ivec);
		break;

	case CKM_AES_CTR:

		pp.ulCounterBits = 16;
		(void) memcpy(pp.cb, iv, AES_BLOCK_LEN);
		soft_aes_ctx->aes_cbc = aes_ctr_ctx_init(
		    soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len,
		    (uint8_t *)&pp);
		break;

#ifdef _KERNEL
	case AES_CCM_MECH_INFO_TYPE:
		soft_aes_ctx->aes_cbc = aes_ccm_ctx_init(
		    soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len, iv,
		    is_encrypt_init);
		break;

	case AES_GCM_MECH_INFO_TYPE:
		soft_aes_ctx->aes_cbc = aes_gcm_ctx_init(
		    soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len, iv);
		break;

	case AES_GMAC_MECH_INFO_TYPE:
		soft_aes_ctx->aes_cbc = aes_gmac_ctx_init(
		    soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len, iv);
		break;
#endif
	default:
		return (soft_aes_ctx);
	}

	if (soft_aes_ctx->aes_cbc == NULL) {
		bzero(soft_aes_ctx->key_sched,
		    soft_aes_ctx->keysched_len);
#ifdef _KERNEL
		kmem_free(soft_aes_ctx->key_sched, size);
#else
		free(soft_aes_ctx->key_sched);
#endif
		return (NULL);
	}

	return (soft_aes_ctx);
}

#ifdef _KERNEL
void
fips_aes_free_context(soft_aes_ctx_t *soft_aes_ctx)
{

	common_ctx_t *aes_ctx;

	aes_ctx = (common_ctx_t *)soft_aes_ctx->aes_cbc;

	if (aes_ctx != NULL) {
		bzero(aes_ctx->cc_keysched, aes_ctx->cc_keysched_len);
		kmem_free(aes_ctx->cc_keysched,
		    aes_ctx->cc_keysched_len);
		crypto_free_mode_ctx(aes_ctx);
	} else {
		/* ECB MODE */
		bzero(soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len);
		kmem_free(soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len);
	}

	kmem_free(soft_aes_ctx, sizeof (soft_aes_ctx_t));

}

#else
void
fips_aes_free_context(soft_aes_ctx_t *soft_aes_ctx)
{

	common_ctx_t *aes_ctx;

	aes_ctx = (common_ctx_t *)soft_aes_ctx->aes_cbc;

	if (aes_ctx != NULL) {
		bzero(aes_ctx->cc_keysched, aes_ctx->cc_keysched_len);
		free(aes_ctx->cc_keysched);
		free(soft_aes_ctx->aes_cbc);
	} else {
		/* ECB MODE */
		bzero(soft_aes_ctx->key_sched, soft_aes_ctx->keysched_len);
		free(soft_aes_ctx->key_sched);
	}

	free(soft_aes_ctx);

}
#endif

/*
 * fips_aes_encrypt()
 *
 * Arguments:
 *	soft_aes_ctx:	pointer to AES context
 *	in_buf:		pointer to the input data to be encrypted
 *	ulDataLen:	length of the input data
 *	out_buf:	pointer to the output data after encryption
 *	pulEncryptedLen: pointer to the length of the output data
 *	mechanism:	CKM_AES_ECB or CKM_AES_CBC
 *
 * Description:
 *	This function calls the corresponding low-level encrypt
 *	routine based on the mechanism.
 *
 */
#ifdef _KERNEL
int
fips_aes_encrypt(soft_aes_ctx_t *soft_aes_ctx, uchar_t *in_buf,
	ulong_t ulDataLen, uchar_t *out_buf,
	ulong_t *pulEncryptedLen, aes_mech_type_t mechanism)
#else
CK_RV
fips_aes_encrypt(soft_aes_ctx_t *soft_aes_ctx, CK_BYTE_PTR in_buf,
	CK_ULONG ulDataLen, CK_BYTE_PTR out_buf,
	CK_ULONG_PTR pulEncryptedLen, CK_MECHANISM_TYPE mechanism)
#endif
{

	int rc = 0;
	CK_RV rv = CKR_OK;
	ulong_t out_len;

	/*
	 * AES only takes input length that is a multiple of 16-byte
	 */
	if ((ulDataLen % AES_BLOCK_LEN) != 0)
		return (CKR_DATA_LEN_RANGE);

	/*
	 * For non-padding mode, the output length will
	 * be same as the input length.
	 */
	out_len = ulDataLen;

	/*
	 * Begin Encryption now.
	 */
	switch (mechanism) {

	case CKM_AES_ECB:
	{

		ulong_t i;
		uint8_t *tmp_inbuf;
		uint8_t *tmp_outbuf;

		for (i = 0; i < out_len; i += AES_BLOCK_LEN) {
			tmp_inbuf = &in_buf[i];
			tmp_outbuf = &out_buf[i];
			/* Crunch one block of data for AES. */
			(void) aes_encrypt_block(soft_aes_ctx->key_sched,
			    tmp_inbuf, tmp_outbuf);
		}

		*pulEncryptedLen = out_len;

		break;
	}

	case CKM_AES_CBC:
	{
		crypto_data_t out;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Encrypt multiple blocks of data. */
		rc = aes_encrypt_contiguous_blocks(
		    (aes_ctx_t *)soft_aes_ctx->aes_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0)
			goto encrypt_failed;

		if (rc == 0) {
			*pulEncryptedLen = out_len;
			break;
		}
encrypt_failed:
		*pulEncryptedLen = 0;
		return (CKR_DEVICE_ERROR);
	}

	case CKM_AES_CTR:
	{
		crypto_data_t out;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		rc = aes_encrypt_contiguous_blocks(soft_aes_ctx->aes_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0) {
			*pulEncryptedLen = 0;
			return (CKR_DEVICE_ERROR);
		}
		/*
		 * Since AES counter mode is a stream cipher, we call
		 * aes_counter_final() to pick up any remaining bytes.
		 * It is an internal function that does not destroy
		 * the context like *normal* final routines.
		 */
		if (((aes_ctx_t *)soft_aes_ctx->aes_cbc)->ac_remainder_len
		    > 0) {
			rc = ctr_mode_final(soft_aes_ctx->aes_cbc, &out,
			    aes_encrypt_block);
			if (rc != 0) {
				*pulEncryptedLen = 0;
				return (CKR_DEVICE_ERROR);
			}
		}

		*pulEncryptedLen = out_len;
		break;
	}

#ifdef _KERNEL
	case AES_CCM_MECH_INFO_TYPE:
	{
		crypto_data_t out;
		size_t saved_length, length_needed;
		aes_ctx_t *aes_ctx = soft_aes_ctx->aes_cbc;
		ccm_ctx_t *ccm_ctx = soft_aes_ctx->aes_cbc;

		length_needed = ulDataLen + aes_ctx->ac_mac_len;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = length_needed;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = length_needed;

		saved_length = out.cd_length;

		rc = aes_encrypt_contiguous_blocks(aes_ctx,
		    (char *)in_buf, ulDataLen, &out);

		if (rc != 0) {
			*pulEncryptedLen = 0;
			return (rc);
		}

		/*
		 * ccm_encrypt_final() will compute the MAC and append
		 * it to existing ciphertext. So, need to adjust the left over
		 * length value accordingly
		 */

		/* order of following 2 lines MUST not be reversed */
		out.cd_offset = ccm_ctx->ccm_processed_data_len;
		out.cd_length = saved_length - ccm_ctx->ccm_processed_data_len;

		rc = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulEncryptedLen = 0;
			return (rc);
		}

		*pulEncryptedLen = length_needed;
		break;
	}

	case AES_GCM_MECH_INFO_TYPE:
	{
		crypto_data_t out;
		size_t saved_length, length_needed;
		aes_ctx_t *aes_ctx = soft_aes_ctx->aes_cbc;
		gcm_ctx_t *gcm_ctx = soft_aes_ctx->aes_cbc;

		/*
		 * Output:
		 * A ciphertext, denoted C, whose bit length is the same as
		 * that of the plaintext.
		 * An authentication tag, or tag, for short, denoted T.
		 */

		length_needed = ulDataLen + aes_ctx->ac_tag_len;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = length_needed;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = length_needed;

		saved_length = out.cd_length;

		rc = aes_encrypt_contiguous_blocks(aes_ctx,
		    (char *)in_buf, ulDataLen, &out);

		if (rc != 0) {
			*pulEncryptedLen = 0;
			return (rc);
		}

		/*
		 * ccm_encrypt_final() will compute the MAC and append
		 * it to existing ciphertext. So, need to adjust the left over
		 * length value accordingly
		 */

		/* order of following 2 lines MUST not be reversed */
		out.cd_offset = gcm_ctx->gcm_processed_data_len;
		out.cd_length = saved_length - gcm_ctx->gcm_processed_data_len;

		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulEncryptedLen = 0;
			return (rc);
		}

		*pulEncryptedLen = length_needed;
		break;
	}

	case AES_GMAC_MECH_INFO_TYPE:
	{
		crypto_data_t out;
		size_t length_needed;
		aes_ctx_t *aes_ctx = soft_aes_ctx->aes_cbc;

		length_needed = aes_ctx->ac_tag_len;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = length_needed;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = length_needed;

		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulEncryptedLen = 0;
			return (rc);
		}

		*pulEncryptedLen = length_needed;
		break;
	}
#endif /* _KERNEL */
	} /* end switch */

	return (rv);
}

/*
 * fips_aes_decrypt()
 *
 * Arguments:
 *	soft_aes_ctx:	pointer to AES context
 *	in_buf:	pointer to the input data to be decrypted
 *	ulEncryptedLen:	length of the input data
 *	out_buf:	pointer to the output data
 *	pulDataLen:	pointer to the length of the output data
 *	mechanism:	CKM_AES_ECB or CKM_AES_CBC
 *
 * Description:
 *      This function calls the corresponding low-level decrypt
 *	function based on the mechanism.
 *
 */
#ifdef _KERNEL
int
fips_aes_decrypt(soft_aes_ctx_t *soft_aes_ctx, uchar_t *in_buf,
	ulong_t ulEncryptedLen, uchar_t *out_buf,
	ulong_t *pulDataLen, aes_mech_type_t mechanism)
#else
CK_RV
fips_aes_decrypt(soft_aes_ctx_t *soft_aes_ctx, CK_BYTE_PTR in_buf,
	CK_ULONG ulEncryptedLen, CK_BYTE_PTR out_buf,
	CK_ULONG_PTR pulDataLen, CK_MECHANISM_TYPE mechanism)
#endif
{

	int rc = 0;
	CK_RV rv = CKR_OK;
	ulong_t out_len;

	/*
	 * AES only takes input length that is a multiple of 16 bytes
	 */
	if ((ulEncryptedLen % AES_BLOCK_LEN) != 0)
		return (CKR_ENCRYPTED_DATA_LEN_RANGE);

	/*
	 * For non-padding mode, the output length will
	 * be same as the input length.
	 */
	out_len = ulEncryptedLen;

	/*
	 * Begin Decryption.
	 */
	switch (mechanism) {

	case CKM_AES_ECB:
	{

		ulong_t i;
		uint8_t *tmp_inbuf;
		uint8_t *tmp_outbuf;

		for (i = 0; i < out_len; i += AES_BLOCK_LEN) {
			tmp_inbuf = &in_buf[i];
			tmp_outbuf = &out_buf[i];
			/* Crunch one block of data for AES. */
			(void) aes_decrypt_block(soft_aes_ctx->key_sched,
			    tmp_inbuf, tmp_outbuf);
		}

		*pulDataLen = out_len;

		break;
	}

	case CKM_AES_CBC:
	{
		crypto_data_t out;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Decrypt multiple blocks of data. */
		rc = aes_decrypt_contiguous_blocks(
		    (aes_ctx_t *)soft_aes_ctx->aes_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0)
			goto decrypt_failed;


		*pulDataLen = out_len;

		if (rc == 0)
			break;
decrypt_failed:
		*pulDataLen = 0;
		return (CKR_DEVICE_ERROR);
	}

	case CKM_AES_CTR:
	{
		crypto_data_t out;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = *pulDataLen;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = *pulDataLen;

		rc = aes_decrypt_contiguous_blocks(soft_aes_ctx->aes_cbc,
		    (char *)in_buf, out_len, &out);

		if (rc != 0) {
			*pulDataLen = 0;
			return (CKR_DEVICE_ERROR);
		}

		/*
		 * Since AES counter mode is a stream cipher, we call
		 * aes_counter_final() to pick up any remaining bytes.
		 * It is an internal function that does not destroy
		 * the context like *normal* final routines.
		 */
		if (((aes_ctx_t *)soft_aes_ctx->aes_cbc)->ac_remainder_len
		    > 0) {
			rc = ctr_mode_final(soft_aes_ctx->aes_cbc, &out,
			    aes_encrypt_block);

			if (rc == CKR_DATA_LEN_RANGE)
				return (CKR_ENCRYPTED_DATA_LEN_RANGE);
		}

		*pulDataLen = out_len;
		break;
	}

#ifdef _KERNEL
	case AES_CCM_MECH_INFO_TYPE:
	{
		crypto_data_t out;
		size_t length_needed;
		aes_ctx_t *aes_ctx = soft_aes_ctx->aes_cbc;
		ccm_ctx_t *ccm_ctx = soft_aes_ctx->aes_cbc;

		length_needed = ulEncryptedLen + ccm_ctx->ccm_mac_len;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = ulEncryptedLen;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = ulEncryptedLen;

		rc = aes_decrypt_contiguous_blocks(aes_ctx,
		    (char *)in_buf, length_needed, &out);

		if (rc != 0) {
			*pulDataLen = 0;
			return (CRYPTO_FAILED);
		}

		/* order of following 2 lines MUST not be reversed */
		out.cd_offset = 0;
		out.cd_length = ulEncryptedLen;

		rc = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulDataLen = 0;
			return (CRYPTO_FAILED);
		}

		*pulDataLen = ulEncryptedLen;

		break;
	}

	case AES_GCM_MECH_INFO_TYPE:
	{
		crypto_data_t out;
		size_t length_needed;
		aes_ctx_t *aes_ctx = soft_aes_ctx->aes_cbc;

		length_needed = ulEncryptedLen + aes_ctx->ac_tag_len;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = ulEncryptedLen;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = ulEncryptedLen;

		rc = aes_decrypt_contiguous_blocks(aes_ctx,
		    (char *)in_buf, length_needed, &out);

		if (rc != 0) {
			*pulDataLen = 0;
			return (CRYPTO_FAILED);
		}

		/* order of following 2 lines MUST not be reversed */
		out.cd_offset = 0;
		out.cd_length = aes_ctx->ac_tag_len;

		rc = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block,
		    aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulDataLen = 0;
			return (CRYPTO_FAILED);
		}

		*pulDataLen = ulEncryptedLen;

		break;
	}

	case AES_GMAC_MECH_INFO_TYPE:
	{
		crypto_data_t out;
		size_t length_needed;
		aes_ctx_t *aes_ctx = soft_aes_ctx->aes_cbc;

		length_needed = aes_ctx->ac_tag_len;

		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = 0;
		out.cd_raw.iov_base = (char *)NULL;
		out.cd_raw.iov_len = 0;

		rc = aes_decrypt_contiguous_blocks(aes_ctx,
		    (char *)in_buf, length_needed, &out);

		if (rc != 0) {
			*pulDataLen = 0;
			return (CRYPTO_FAILED);
		}

		/* order of following 2 lines MUST not be reversed */
		out.cd_format = CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = 0;
		out.cd_raw.iov_base = (char *)NULL;
		out.cd_raw.iov_len = 0;

		rc = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block,
		    aes_xor_block);

		if (rc != CRYPTO_SUCCESS) {
			*pulDataLen = 0;
			return (CRYPTO_FAILED);
		}

		*pulDataLen = 0;

		break;
	}
#endif
	} /* end switch */

	return (rv);
}

/* AES self-test for 128-bit, 192-bit, or 256-bit key sizes */
int
fips_aes_post(int aes_key_size)
{
	uint8_t *aes_ecb_known_ciphertext =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ecb128_known_ciphertext :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ecb192_known_ciphertext :
	    aes_ecb256_known_ciphertext;

	uint8_t *aes_cbc_known_ciphertext =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_cbc128_known_ciphertext :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_cbc192_known_ciphertext :
	    aes_cbc256_known_ciphertext;

	uint8_t *aes_ctr_known_ciphertext =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ctr128_known_ciphertext :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ctr192_known_ciphertext :
	    aes_ctr256_known_ciphertext;

	uint8_t *aes_ctr_known_key =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ctr128_known_key :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ctr192_known_key :
	    aes_ctr256_known_key;

#ifdef _KERNEL
	uint8_t *aes_ccm_known_plaintext =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ccm128_known_plaintext :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ccm192_known_plaintext :
	    aes_ccm256_known_plaintext;

	uint8_t *aes_ccm_known_ciphertext =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ccm128_known_ciphertext :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ccm192_known_ciphertext :
	    aes_ccm256_known_ciphertext;

	uint8_t *aes_ccm_known_key =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ccm128_known_key :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ccm192_known_key :
	    aes_ccm256_known_key;

	uint8_t *aes_ccm_known_adata =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ccm128_known_adata :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ccm192_known_adata :
	    aes_ccm256_known_adata;

	uint8_t *aes_ccm_known_nonce =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_ccm128_known_nonce :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_ccm192_known_nonce :
	    aes_ccm256_known_nonce;

	uint8_t *aes_gcm_known_key =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gcm128_known_key :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gcm192_known_key :
	    aes_gcm256_known_key;

	uint8_t *aes_gcm_known_iv =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gcm128_known_iv :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gcm192_known_iv :
	    aes_gcm256_known_iv;

	uint8_t *aes_gcm_known_plaintext =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gcm128_known_plaintext :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gcm192_known_plaintext :
	    aes_gcm256_known_plaintext;

	uint8_t *aes_gcm_known_ciphertext =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gcm128_known_ciphertext :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gcm192_known_ciphertext :
	    aes_gcm256_known_ciphertext;

	uint8_t *aes_gcm_known_adata =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gcm128_known_adata :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gcm192_known_adata :
	    aes_gcm256_known_adata;

	uint8_t *aes_gmac_known_key =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gmac128_known_key :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gmac192_known_key :
	    aes_gmac256_known_key;

	uint8_t *aes_gmac_known_iv =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gmac128_known_iv :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gmac192_known_iv :
	    aes_gmac256_known_iv;

	uint8_t *aes_gmac_known_tag =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gmac128_known_tag :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gmac192_known_tag :
	    aes_gmac256_known_tag;

	uint8_t *aes_gmac_known_adata =
	    (aes_key_size == FIPS_AES_128_KEY_SIZE) ?
	    aes_gmac128_known_adata :
	    (aes_key_size == FIPS_AES_192_KEY_SIZE) ?
	    aes_gmac192_known_adata :
	    aes_gmac256_known_adata;

	/* AES variables. */
	uint8_t aes_ccm_computed_ciphertext[3*FIPS_AES_ENCRYPT_LENGTH];
	uint8_t aes_ccm_computed_plaintext[2*FIPS_AES_DECRYPT_LENGTH];
	uint8_t aes_gcm_computed_ciphertext[2*FIPS_AES_ENCRYPT_LENGTH];
	uint8_t aes_gcm_computed_plaintext[FIPS_AES_DECRYPT_LENGTH];
	uint8_t aes_gmac_computed_tag[FIPS_AES_ENCRYPT_LENGTH];
	CK_AES_CCM_PARAMS ccm_param;
	CK_AES_GCM_PARAMS gcm_param;
	CK_AES_GMAC_PARAMS gmac_param;
#endif

	uint8_t aes_computed_ciphertext[FIPS_AES_ENCRYPT_LENGTH];
	uint8_t aes_computed_plaintext[FIPS_AES_DECRYPT_LENGTH];
	soft_aes_ctx_t  *aes_context;
	ulong_t aes_bytes_encrypted;
	ulong_t aes_bytes_decrypted;
	int rv;

	/* check if aes_key_size is 128, 192, or 256 bits */
	if ((aes_key_size != FIPS_AES_128_KEY_SIZE) &&
	    (aes_key_size != FIPS_AES_192_KEY_SIZE) &&
	    (aes_key_size != FIPS_AES_256_KEY_SIZE))
		return (CKR_DEVICE_ERROR);

	/*
	 * AES-ECB Known Answer Encryption Test
	 */
#ifdef _KERNEL
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, NULL, AES_ECB_MECH_INFO_TYPE, B_FALSE);
#else
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, NULL, CKM_AES_ECB);
#endif

	if (aes_context == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = fips_aes_encrypt(aes_context, aes_known_plaintext,
	    FIPS_AES_ENCRYPT_LENGTH, aes_computed_ciphertext,
	    &aes_bytes_encrypted, CKM_AES_ECB);

	fips_aes_free_context(aes_context);

	if ((rv != CKR_OK) ||
	    (aes_bytes_encrypted != FIPS_AES_ENCRYPT_LENGTH) ||
	    (memcmp(aes_computed_ciphertext, aes_ecb_known_ciphertext,
	    FIPS_AES_ENCRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * AES-ECB Known Answer Decryption Test
	 */
#ifdef _KERNEL
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, NULL, AES_ECB_MECH_INFO_TYPE, B_FALSE);
#else
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, NULL, CKM_AES_ECB);
#endif

	if (aes_context == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = fips_aes_decrypt(aes_context, aes_ecb_known_ciphertext,
	    FIPS_AES_DECRYPT_LENGTH, aes_computed_plaintext,
	    &aes_bytes_decrypted, CKM_AES_ECB);

	fips_aes_free_context(aes_context);

	if ((rv != CKR_OK) ||
	    (aes_bytes_decrypted != FIPS_AES_DECRYPT_LENGTH) ||
	    (memcmp(aes_computed_plaintext, aes_known_plaintext,
	    FIPS_AES_DECRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * AES-CBC Known Answer Encryption Test
	 */
#ifdef _KERNEL
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, aes_cbc_known_initialization_vector,
	    AES_CBC_MECH_INFO_TYPE, B_FALSE);
#else
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, aes_cbc_known_initialization_vector,
	    CKM_AES_CBC);
#endif

	if (aes_context == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = fips_aes_encrypt(aes_context, aes_known_plaintext,
	    FIPS_AES_ENCRYPT_LENGTH, aes_computed_ciphertext,
	    &aes_bytes_encrypted, CKM_AES_CBC);

	fips_aes_free_context(aes_context);

	if ((rv != CKR_OK) ||
	    (aes_bytes_encrypted != FIPS_AES_ENCRYPT_LENGTH) ||
	    (memcmp(aes_computed_ciphertext, aes_cbc_known_ciphertext,
	    FIPS_AES_ENCRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * AES-CBC Known Answer Decryption Test
	 */
#ifdef _KERNEL
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, aes_cbc_known_initialization_vector,
	    AES_CBC_MECH_INFO_TYPE, B_FALSE);
#else
	aes_context = fips_aes_build_context(aes_known_key,
	    aes_key_size, aes_cbc_known_initialization_vector,
	    CKM_AES_CBC);
#endif

	if (aes_context == NULL)
		return (CRYPTO_HOST_MEMORY);

	rv = fips_aes_decrypt(aes_context, aes_cbc_known_ciphertext,
	    FIPS_AES_DECRYPT_LENGTH, aes_computed_plaintext,
	    &aes_bytes_decrypted, CKM_AES_CBC);

	fips_aes_free_context(aes_context);

	if ((rv != CKR_OK) ||
	    (aes_bytes_decrypted != FIPS_AES_DECRYPT_LENGTH) ||
	    (memcmp(aes_computed_plaintext, aes_known_plaintext,
	    FIPS_AES_DECRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * AES-CTR Known Answer Encryption Test
	 */
#ifdef _KERNEL
	aes_context = fips_aes_build_context(aes_ctr_known_key,
	    aes_key_size, aes_ctr_known_counter,
	    AES_CTR_MECH_INFO_TYPE, B_FALSE);
#else
	aes_context = fips_aes_build_context(aes_ctr_known_key,
	    aes_key_size, aes_ctr_known_counter, CKM_AES_CTR);
#endif

	if (aes_context == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = fips_aes_encrypt(aes_context, aes_ctr_known_plaintext,
	    FIPS_AES_ENCRYPT_LENGTH, aes_computed_ciphertext,
	    &aes_bytes_encrypted, CKM_AES_CTR);

	fips_aes_free_context(aes_context);

	if ((rv != CKR_OK) ||
	    (aes_bytes_encrypted != FIPS_AES_ENCRYPT_LENGTH) ||
	    (memcmp(aes_computed_ciphertext, aes_ctr_known_ciphertext,
	    FIPS_AES_ENCRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * AES-CTR Known Answer Decryption Test
	 */
#ifdef _KERNEL
	aes_context = fips_aes_build_context(aes_ctr_known_key,
	    aes_key_size, aes_ctr_known_counter,
	    AES_CTR_MECH_INFO_TYPE, B_FALSE);
#else
	aes_context = fips_aes_build_context(aes_ctr_known_key,
	    aes_key_size, aes_ctr_known_counter,
	    CKM_AES_CTR);
#endif
	if (aes_context == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = fips_aes_decrypt(aes_context, aes_ctr_known_ciphertext,
	    FIPS_AES_DECRYPT_LENGTH, aes_computed_plaintext,
	    &aes_bytes_decrypted, CKM_AES_CTR);

	fips_aes_free_context(aes_context);

	if ((rv != CKR_OK) ||
	    (aes_bytes_decrypted != FIPS_AES_DECRYPT_LENGTH) ||
	    (memcmp(aes_computed_plaintext, aes_ctr_known_plaintext,
	    FIPS_AES_DECRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * The following POSTs are only available in Kernel
	 *
	 * CCM, GCM, and GMAC
	 */
#ifdef _KERNEL

	/*
	 * AES-CCM Known Answer Encryption Test
	 */
	ccm_param.ulMACSize = 16; /* Tlen */
	ccm_param.ulNonceSize = 7; /* Nlen */
	ccm_param.ulAuthDataSize = 30; /* Alen */
	ccm_param.ulDataSize = 32; /* Plen or Clen */
	ccm_param.nonce = aes_ccm_known_nonce;
	ccm_param.authData = aes_ccm_known_adata;

	aes_context = fips_aes_build_context(aes_ccm_known_key,
	    aes_key_size, (uint8_t *)&ccm_param,
	    AES_CCM_MECH_INFO_TYPE, B_TRUE);

	if (aes_context == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	rv = fips_aes_encrypt(aes_context, aes_ccm_known_plaintext,
	    2*FIPS_AES_ENCRYPT_LENGTH, aes_ccm_computed_ciphertext,
	    &aes_bytes_encrypted, AES_CCM_MECH_INFO_TYPE);

	fips_aes_free_context(aes_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (aes_bytes_encrypted != 3*FIPS_AES_ENCRYPT_LENGTH) ||
	    (memcmp(aes_ccm_computed_ciphertext, aes_ccm_known_ciphertext,
	    3*FIPS_AES_ENCRYPT_LENGTH) != 0))
		return (CRYPTO_DEVICE_ERROR);

	/*
	 * AES-CCM Known Answer Decryption Test
	 */
	ccm_param.ulMACSize = 16; /* Tlen */
	ccm_param.ulNonceSize = 7; /* Nlen */
	ccm_param.ulAuthDataSize = 30; /* Alen */
	ccm_param.ulDataSize = 48; /* Plen or Clen */
	ccm_param.nonce = aes_ccm_known_nonce;
	ccm_param.authData = aes_ccm_known_adata;

	aes_context = fips_aes_build_context(aes_ccm_known_key,
	    aes_key_size, (uint8_t *)&ccm_param,
	    AES_CCM_MECH_INFO_TYPE, B_FALSE);

	if (aes_context == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	rv = fips_aes_decrypt(aes_context, aes_ccm_known_ciphertext,
	    2*FIPS_AES_DECRYPT_LENGTH, aes_ccm_computed_plaintext,
	    &aes_bytes_decrypted, AES_CCM_MECH_INFO_TYPE);

	fips_aes_free_context(aes_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (aes_bytes_decrypted != 2*FIPS_AES_DECRYPT_LENGTH) ||
	    (memcmp(aes_ccm_computed_plaintext, aes_ccm_known_plaintext,
	    2*FIPS_AES_DECRYPT_LENGTH) != 0))
		return (CRYPTO_DEVICE_ERROR);

	/*
	 * AES-GCM Known Answer Encryption Test
	 */
	gcm_param.pIv = aes_gcm_known_iv;
	gcm_param.ulIvLen = AES_GMAC_IV_LEN; /* IVlen = 96 bits */
	gcm_param.ulTagBits = AES_GMAC_TAG_BITS; /* Taglen = 128 bits */
	gcm_param.ulAADLen = 16;
	gcm_param.pAAD = aes_gcm_known_adata;

	aes_context = fips_aes_build_context(aes_gcm_known_key,
	    aes_key_size, (uint8_t *)&gcm_param,
	    AES_GCM_MECH_INFO_TYPE, B_TRUE);

	if (aes_context == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	rv = fips_aes_encrypt(aes_context, aes_gcm_known_plaintext,
	    FIPS_AES_ENCRYPT_LENGTH, aes_gcm_computed_ciphertext,
	    &aes_bytes_encrypted, AES_GCM_MECH_INFO_TYPE);

	fips_aes_free_context(aes_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (aes_bytes_encrypted != 2*FIPS_AES_ENCRYPT_LENGTH) ||
	    (memcmp(aes_gcm_computed_ciphertext, aes_gcm_known_ciphertext,
	    2*FIPS_AES_ENCRYPT_LENGTH) != 0))
		return (CRYPTO_DEVICE_ERROR);

	/*
	 * AES-GCM Known Answer Decryption Test
	 */
	aes_context = fips_aes_build_context(aes_gcm_known_key,
	    aes_key_size, (uint8_t *)&gcm_param,
	    AES_GCM_MECH_INFO_TYPE, B_FALSE);

	if (aes_context == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	rv = fips_aes_decrypt(aes_context, aes_gcm_known_ciphertext,
	    FIPS_AES_DECRYPT_LENGTH, aes_gcm_computed_plaintext,
	    &aes_bytes_decrypted, AES_GCM_MECH_INFO_TYPE);

	fips_aes_free_context(aes_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (aes_bytes_decrypted != FIPS_AES_DECRYPT_LENGTH) ||
	    (memcmp(aes_gcm_computed_plaintext, aes_gcm_known_plaintext,
	    FIPS_AES_DECRYPT_LENGTH) != 0))
		return (CRYPTO_DEVICE_ERROR);

	/*
	 * AES-GMAC Known Answer Encryption Test
	 */
	gmac_param.pIv = aes_gmac_known_iv;
	gmac_param.ulAADLen = 16;
	gmac_param.pAAD = aes_gmac_known_adata;

	aes_context = fips_aes_build_context(aes_gmac_known_key,
	    aes_key_size, (uint8_t *)&gmac_param,
	    AES_GMAC_MECH_INFO_TYPE, B_TRUE);

	if (aes_context == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	rv = fips_aes_encrypt(aes_context, NULL,
	    0, aes_gmac_computed_tag,
	    &aes_bytes_encrypted, AES_GMAC_MECH_INFO_TYPE);

	fips_aes_free_context(aes_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (aes_bytes_encrypted != FIPS_AES_ENCRYPT_LENGTH) ||
	    (memcmp(aes_gmac_computed_tag, aes_gmac_known_tag,
	    FIPS_AES_ENCRYPT_LENGTH) != 0))
		return (CRYPTO_DEVICE_ERROR);

	/*
	 * AES-GMAC Known Answer Decryption Test
	 */

	aes_context = fips_aes_build_context(aes_gmac_known_key,
	    aes_key_size, (uint8_t *)&gmac_param,
	    AES_GMAC_MECH_INFO_TYPE, B_FALSE);

	if (aes_context == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	rv = fips_aes_decrypt(aes_context, aes_gmac_known_tag,
	    FIPS_AES_DECRYPT_LENGTH, NULL,
	    &aes_bytes_decrypted, AES_GMAC_MECH_INFO_TYPE);

	fips_aes_free_context(aes_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (aes_bytes_decrypted != 0))
		return (CRYPTO_DEVICE_ERROR);

#endif /* _KERNEL */

	return (CRYPTO_SUCCESS);
}

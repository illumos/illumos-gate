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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/crypto/common.h>
#include <modes/modes.h>
#define	_AES_FIPS_POST
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
	/* AES Known Key (up to 256-bits). */
	static uint8_t aes_known_key[] = {
		"AES-128 RIJNDAELLEADNJIR 821-SEA"
	};

	/* AES-CBC Known Initialization Vector (128-bits). */
	static uint8_t aes_cbc_known_initialization_vector[] =
		{ "SecurityytiruceS" };

	/* AES Known Plaintext (128-bits). (blocksize is 128-bits) */
	static uint8_t aes_known_plaintext[] = { "Sun Open Solaris" };

	/* AES Known Ciphertext (128-bit key). */
	static uint8_t aes_ecb128_known_ciphertext[] = {
		0xcc, 0xd1, 0xd0, 0xf3, 0xfd, 0x44, 0xb1, 0x4d,
		0xfe, 0x33, 0x20, 0x72, 0x3c, 0xf3, 0x4d, 0x27
	};

	static uint8_t aes_cbc128_known_ciphertext[]  = {
		0x59, 0x34, 0x55, 0xd1, 0x89, 0x9b, 0xf4, 0xa5,
		0x16, 0x2c, 0x4c, 0x14, 0xd3, 0xe2, 0xe5, 0xed
	};

	/* AES Known Ciphertext (192-bit key). */
	static uint8_t aes_ecb192_known_ciphertext[] = {
		0xa3, 0x78, 0x10, 0x44, 0xd8, 0xee, 0x8a, 0x98,
		0x41, 0xa4, 0xeb, 0x96, 0x57, 0xd8, 0xa0, 0xc5
	};

	static uint8_t aes_cbc192_known_ciphertext[]  = {
		0x22, 0x9c, 0x68, 0xc6, 0x86, 0x68, 0xcc, 0x6a,
		0x56, 0x2c, 0xb8, 0xe0, 0x16, 0x4e, 0x8b, 0x78
	};

	/* AES Known Ciphertext (256-bit key). */
	static uint8_t aes_ecb256_known_ciphertext[] = {
		0xe4, 0x65, 0x92, 0x7f, 0xd0, 0xdd, 0x59, 0x49,
		0x79, 0xc3, 0xac, 0x96, 0x30, 0xad, 0x32, 0x52
	};

	static uint8_t aes_cbc256_known_ciphertext[]  = {
		0xd9, 0x44, 0x43, 0xe8, 0xdb, 0x60, 0x6b, 0xde,
		0xc2, 0x84, 0xbf, 0xb9, 0xaf, 0x43, 0x3f, 0x51
	};

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

	/* AES-CTR Known Key (128-bits). */
	static uint8_t aes_ctr128_known_key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	/* AES-CTR Known Key (192-bits). */
	static uint8_t aes_ctr192_known_key[] = {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
	};

	/* AES-CTR Known Key (256-bits). */
	static uint8_t aes_ctr256_known_key[] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};

	/* AES-CTR Known Initialization Counter (128-bits). */
	static uint8_t aes_ctr_known_counter[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	};

	/* AES-CTR Known Plaintext (128-bits). */
	static uint8_t aes_ctr_known_plaintext[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
	};

	/* AES-CTR Known Ciphertext. */
	static uint8_t aes_ctr128_known_ciphertext[] = {
		0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
		0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
	};

	static uint8_t aes_ctr192_known_ciphertext[]  = {
		0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2,
		0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b
	};

	static uint8_t aes_ctr256_known_ciphertext[]  = {
		0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
		0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28
	};

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
	/* AES-CCM Known Key (128-bits). */
	static uint8_t aes_ccm128_known_key[] = {
		0x06, 0xfd, 0xf0, 0x83, 0xb5, 0xcb, 0x3b, 0xc7,
		0xc0, 0x6d, 0x4d, 0xe5, 0xa6, 0x34, 0xc6, 0x50
	};

	/* AES-CCM Known Key (192-bits). */
	static uint8_t aes_ccm192_known_key[] = {
		0xde, 0x91, 0x08, 0x63, 0xbe, 0x59, 0xb8, 0x7a,
		0x45, 0x9b, 0xa6, 0xce, 0x2d, 0x7e, 0x71, 0x56,
		0x1c, 0x5c, 0x15, 0xea, 0x1b, 0x6b, 0x05, 0x06
	};

	/* AES-CCM Known Key (256-bits). */
	static uint8_t aes_ccm256_known_key[] = {
		0x84, 0x9c, 0x1d, 0xeb, 0x80, 0xf8, 0x5b, 0x7d,
		0x25, 0x33, 0x64, 0x75, 0x4b, 0xdc, 0x5d, 0xf0,
		0xe8, 0x1c, 0x98, 0x8a, 0x78, 0x8f, 0x15, 0xd1,
		0xa2, 0x52, 0x49, 0xfa, 0x18, 0x5e, 0x1f, 0xd3
	};

	/* AES-CCM Known Nonce Nlen = 7 bytes (for 128-bits key). */
	static uint8_t aes_ccm128_known_nonce[] = {
		0xfd, 0xe2, 0xd5, 0x4c, 0x65, 0x4e, 0xe4
	};

	/* AES-CCM Known Nonce Nlen = 7 bytes (192-bits). */
	static uint8_t aes_ccm192_known_nonce[] = {
		0xcf, 0xb3, 0x48, 0xfa, 0x04, 0x36, 0xa2
	};

	/* AES-CCM Known Nonce Nlen = 7 bytes (256-bits). */
	static uint8_t aes_ccm256_known_nonce[] = {
		0x75, 0xa5, 0x5b, 0x58, 0x33, 0x9d, 0x1c
	};

	/* AES-CCM Known Adata Alen = 30 bytes (128-bits). */
	static uint8_t aes_ccm128_known_adata[] = {
		0xe0, 0xdf, 0xfc, 0x4c, 0x92, 0x90, 0xd8, 0x28,
		0xef, 0xe7, 0xc6, 0xbe, 0x4a, 0xbc, 0xd1, 0x3e,
		0x23, 0x61, 0x92, 0x2f, 0xfa, 0x27, 0xa4, 0x0e,
		0x61, 0x24, 0x58, 0x38, 0x55, 0x33
	};

	/* AES-CCM Known Adata Alen = 30 bytes (192-bits). */
	static uint8_t aes_ccm192_known_adata[] = {
		0x4c, 0x5b, 0x4f, 0xfe, 0x80, 0xba, 0x7a, 0xe5,
		0xd3, 0xe8, 0xbc, 0xf6, 0x55, 0x83, 0xcf, 0x58,
		0xa2, 0x82, 0x59, 0x65, 0xba, 0xbd, 0x63, 0x53,
		0x0c, 0xb0, 0x0c, 0x14, 0xd4, 0x7b
	};

	/* AES-CCM Known Adata Alen = 30 bytes (256-bits). */
	static uint8_t aes_ccm256_known_adata[] = {
		0x27, 0xb7, 0xec, 0x91, 0x08, 0xe1, 0x4d, 0x12,
		0xd3, 0xd3, 0xb8, 0x49, 0x09, 0xde, 0xd0, 0x9a,
		0x8f, 0x23, 0xbf, 0xd6, 0x02, 0x9b, 0x2a, 0x5e,
		0x4a, 0x5a, 0x63, 0x8c, 0x72, 0x14
	};

	/* AES-CCM Known Payload Plen = 32 bytes (128-bits). */
	static uint8_t aes_ccm128_known_plaintext[] = {
		0x77, 0xca, 0xdf, 0xa5, 0xb1, 0x23, 0xfe, 0x07,
		0x8d, 0xca, 0x94, 0xe2, 0x66, 0x3f, 0x73, 0xd0,
		0x3f, 0x0b, 0x4d, 0xc8, 0x05, 0xf6, 0x1c, 0xef,
		0x13, 0x79, 0xc0, 0xb1, 0xfc, 0x76, 0xea, 0x11
	};

	/* AES-CCM Known Payload Plen = 32 bytes (192-bits). */
	static uint8_t aes_ccm192_known_plaintext[] = {
		0xf9, 0x8a, 0x58, 0x59, 0x44, 0x2d, 0x2a, 0xf9,
		0x65, 0x03, 0x36, 0x6d, 0x8a, 0x58, 0x29, 0xf9,
		0xef, 0x47, 0x44, 0x30, 0xf4, 0x7e, 0x0d, 0xcd,
		0x73, 0x41, 0x45, 0xdf, 0x50, 0xb2, 0x1b, 0x29
	};

	/* AES-CCM Known Payload Plen = 32 bytes (256-bits). */
	static uint8_t aes_ccm256_known_plaintext[] = {
		0x25, 0x28, 0x3f, 0x05, 0x41, 0xd6, 0x66, 0x3b,
		0xdb, 0x8f, 0xe9, 0xe7, 0x7b, 0x06, 0xc0, 0xee,
		0xfe, 0xf6, 0xc9, 0x8b, 0x45, 0x08, 0x18, 0x4e,
		0x2e, 0xf7, 0x8e, 0x64, 0xc3, 0xf2, 0xad, 0x18
	};

	/*
	 * AES-CCM Known Ciphertext
	 * Clen = 32 bytes + Tlen = 16 bytes (128-bits).
	 */
	static uint8_t aes_ccm128_known_ciphertext[] = {
		0x33, 0x50, 0x58, 0xbb, 0x5f, 0x13, 0x8d, 0xc9,
		0x5b, 0x2c, 0xa4, 0x50, 0x1d, 0x7f, 0xd4, 0xa5,
		0xb9, 0xb8, 0x71, 0x83, 0x8f, 0x82, 0x27, 0x5f,
		0x75, 0x3e, 0x30, 0xf9, 0x9d, 0xad, 0xc2, 0xe9,
		0x66, 0x93, 0x56, 0x98, 0x01, 0x1e, 0x3c, 0x11,
		0x74, 0xdb, 0x9b, 0xca, 0xce, 0x0f, 0xc3, 0x35
	};

	/*
	 * AES-CCM Known Ciphertext
	 * Clen = 32 bytes + Tlen = 16 bytes (192-bits).
	 */
	static uint8_t aes_ccm192_known_ciphertext[] = {
		0xa7, 0x40, 0xd0, 0x25, 0xbd, 0x3e, 0x8f, 0xd5,
		0x28, 0x3e, 0xee, 0xaa, 0xf9, 0xa7, 0xfc, 0xf2,
		0x33, 0xf6, 0x69, 0xb8, 0xdc, 0x9c, 0x74, 0xb1,
		0x46, 0xf4, 0xd6, 0xcc, 0x0a, 0x16, 0x12, 0x0c,
		0x7c, 0x3c, 0x43, 0x76, 0x94, 0xf6, 0x9a, 0x14,
		0xa0, 0xfb, 0xab, 0x9c, 0x2c, 0xd3, 0x5c, 0x09
	};

	/*
	 * AES-CCM Known Ciphertext
	 * Clen = 32 bytes + Tlen = 16 bytes (256-bits).
	 */
	static uint8_t aes_ccm256_known_ciphertext[] = {
		0xf6, 0x4d, 0x24, 0x69, 0x0e, 0xde, 0xc9, 0xc0,
		0x1e, 0x42, 0xc0, 0x78, 0x29, 0xcf, 0xdb, 0xfe,
		0xab, 0x52, 0x9a, 0xb1, 0x07, 0xe4, 0xac, 0xdf,
		0x48, 0x46, 0x46, 0xc1, 0xe2, 0xb2, 0x0f, 0x36,
		0x5f, 0xeb, 0x44, 0xcf, 0xa8, 0x80, 0x80, 0x23,
		0xc9, 0xee, 0xc7, 0x56, 0x24, 0x63, 0x6e, 0x7e
	};

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

	/* AES-GCM Known Key (128-bits). */
	static uint8_t aes_gcm128_known_key[] = {
		0x7d, 0xf9, 0x9c, 0xdf, 0x7d, 0x00, 0xd9, 0xea,
		0xd3, 0x85, 0x17, 0x1b, 0x29, 0xae, 0xcf, 0xbc
	};

	/* AES-GCM Known Key (192-bits). */
	static uint8_t aes_gcm192_known_key[] = {
		0x85, 0xf4, 0x34, 0x7a, 0xf5, 0x98, 0x1e, 0xd9,
		0x89, 0x85, 0x98, 0x1a, 0x53, 0xfc, 0xc5, 0xbf,
		0x53, 0x6c, 0x91, 0x4b, 0x18, 0x3c, 0xe8, 0x12
	};

	/* AES-GCM	 Known Key (256-bits). */
	static uint8_t aes_gcm256_known_key[] = {
		0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92,
		0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1,
		0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
		0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
	};

	/* AES-GCM Known Initialization Vector (128-bits). */
	static uint8_t aes_gcm128_known_iv[] = {
		0x27, 0x4c, 0x4e, 0xae, 0xfe, 0xef, 0xae, 0x26,
		0x80, 0xb0, 0xef, 0xd5
	};

	/* AES-GCM Known Initialization Vector (192-bits). */
	static uint8_t aes_gcm192_known_iv[] = {
		0xd4, 0xfb, 0x33, 0xc6, 0x51, 0xc8, 0x86, 0xff,
		0x28, 0x80, 0xef, 0x96
	};

	/* AES-GCM Known Initialization Vector (256-bits). */
	static uint8_t aes_gcm256_known_iv[] = {
		0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0,
		0xee, 0xd0, 0x66, 0x84
	};

	/* AES-GCM Known AAD Alen = 16 bytes (128-bits). */
	static uint8_t aes_gcm128_known_adata[] = {
		0x60, 0xe8, 0xb0, 0x37, 0xec, 0xdf, 0x4d, 0x82,
		0x8c, 0x83, 0x0d, 0xcf, 0xc5, 0xce, 0xd4, 0x9c
	};

	/* AES-GCM Known AAD Alen = 16 bytes (192-bits). */
	static uint8_t aes_gcm192_known_adata[] = {
		0x44, 0x3a, 0xdf, 0xad, 0xbb, 0x29, 0xd6, 0x8c,
		0x55, 0xe2, 0x02, 0x2d, 0xca, 0x62, 0x9b, 0x51
	};

	/* AES-GCM Known AAD Alen = 16 bytes (256-bits). */
	static uint8_t aes_gcm256_known_adata[] = {
		0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
		0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde
	};

	/* AES-GCM Known Payload Plen = 16 bytes (128-bits). */
	static uint8_t aes_gcm128_known_plaintext[] = {
		0x99, 0x66, 0x7d, 0xc9, 0x62, 0xb3, 0x9f, 0x14,
		0x8c, 0xdd, 0xfe, 0x68, 0xf9, 0x0a, 0x43, 0xf9
	};

	/* AES-GCM Known Payload Plen = 16 bytes (192-bits). */
	static uint8_t aes_gcm192_known_plaintext[] = {
		0x7f, 0x9c, 0x08, 0x1d, 0x6a, 0xcc, 0xa8, 0xab,
		0x71, 0x75, 0xcb, 0xd0, 0x49, 0x42, 0xba, 0xad
	};
	/* AES-GCM Known Payload Plen = 16 bytes (256-bits). */
	static uint8_t aes_gcm256_known_plaintext[] = {
		0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e,
		0xeb, 0x31, 0xb2, 0xea, 0xcc, 0x2b, 0xf2, 0xa5
	};

	/* AES-GCM Known Ciphertext Clen = 16 bytes (128-bits) + tag */
	static uint8_t aes_gcm128_known_ciphertext[] = {
		0x2b, 0x5f, 0x57, 0xf2, 0x62, 0x27, 0xe0, 0x94,
		0xe7, 0xf8, 0x01, 0x23, 0xf9, 0xed, 0xbd, 0xe8,
		0x16, 0xee, 0x08, 0xb4, 0xd8, 0x07, 0xe5, 0xdb,
		0xd5, 0x70, 0x3c, 0xb3, 0xcf, 0x53, 0x8c, 0x14
	};

	/* AES-GCM Known Ciphertext Clen = 16 bytes (192-bits) + tag */
	static uint8_t aes_gcm192_known_ciphertext[] = {
		0xdd, 0x7e, 0x7e, 0x45, 0x5b, 0x21, 0xd8, 0x84,
		0x3d, 0x7b, 0xc3, 0x1f, 0x21, 0x07, 0xf9, 0x55,
		0x9f, 0x0e, 0x8d, 0xe2, 0x6d, 0xb4, 0x95, 0xf5,
		0x91, 0x1f, 0xb6, 0x0c, 0xf5, 0xf2, 0x3a, 0xf9
	};

	/* AES-GCM Known Ciphertext Clen = 16 bytes (256-bits)+ tag */
	static uint8_t aes_gcm256_known_ciphertext[] = {
		0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c,
		0xd5, 0x36, 0x86, 0x7e, 0xb9, 0xf2, 0x17, 0x36,
		0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87,
		0xd7, 0x37, 0xee, 0x62, 0x98, 0xf7, 0x7e, 0x0c
	};

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

	/*
	 * Source: NIST gcmEncryptExtIV128.txt
	 * Count = 0, [Keylen = 128], [IVlen = 96], [PTlen = 0],
	 * [AADlen = 128], [Taglen = 128]
	 *
	 * Source: NIST gcmEncryptExtIV192.txt
	 * Count = 0, [Keylen = 192], [IVlen = 96], [PTlen = 0],
	 * [AADlen = 128], [Taglen = 128]
	 *
	 * Source: NIST gcmEncryptExtIV256.txt
	 * Count = 0, [Keylen = 256], [IVlen = 96], [PTlen = 0],
	 * [AADlen = 128], [Taglen = 128]
	 */

	/* AES-GMAC Known Key (128-bits). */
	static uint8_t aes_gmac128_known_key[] = {
		0x7d, 0x70, 0xd2, 0x32, 0x48, 0xc4, 0x7e, 0xb3,
		0xd2, 0x73, 0xdf, 0x81, 0xed, 0x30, 0x24, 0xbd
	};

	/* AES-GMAC Known Key (192-bits). */
	static uint8_t aes_gmac192_known_key[] = {
		0x03, 0x60, 0x22, 0xfe, 0x26, 0x9a, 0xdc, 0xad,
		0xb5, 0x73, 0x11, 0xa4, 0xa0, 0xed, 0x2a, 0x84,
		0x18, 0x34, 0xb8, 0xb6, 0xd8, 0xa0, 0x7f, 0x41
	};

	/* AES-GMAC Known Key (256-bits). */
	static uint8_t aes_gmac256_known_key[] = {
		0xbb, 0x10, 0x10, 0x06, 0x4f, 0xb8, 0x35, 0x23,
		0xea, 0x9d, 0xf3, 0x2b, 0xad, 0x9f, 0x1f, 0x2a,
		0x4f, 0xce, 0xfc, 0x0f, 0x21, 0x07, 0xc0, 0xaa,
		0xba, 0xd9, 0xb7, 0x56, 0xd8, 0x09, 0x21, 0x9d
	};

	/* AES-GMAC Known Initialization Vector (128-bits). */
	static uint8_t aes_gmac128_known_iv[] = {
		0xab, 0x53, 0x23, 0x33, 0xd6, 0x76, 0x51, 0x20,
		0x8b, 0x8c, 0x34, 0x85
	};

	/* AES-GMAC Known Initialization Vector (192-bits). */
	static uint8_t aes_gmac192_known_iv[] = {
		0x85, 0x65, 0xb2, 0x15, 0x3a, 0x3f, 0x34, 0x9a,
		0x07, 0x31, 0x06, 0x79
	};

	/* AES-GMAC Known Initialization Vector (256-bits). */
	static uint8_t aes_gmac256_known_iv[] = {
		0x2f, 0x9a, 0xd0, 0x12, 0xad, 0xfc, 0x12, 0x73,
		0x43, 0xfb, 0xe0, 0x56
	};

	/* AES-GMAC Known Tag (128-bits). */
	static uint8_t aes_gmac128_known_tag[] = {
		0xcf, 0x89, 0x50, 0xa3, 0x10, 0xf5, 0xab, 0x8b,
		0x69, 0xd5, 0x00, 0x11, 0x1a, 0x44, 0xb0, 0x96
	};

	/* AES-GMAC Known Tag (192-bits). */
	static uint8_t aes_gmac192_known_tag[] = {
		0x90, 0x21, 0xaf, 0x4c, 0xa0, 0x8d, 0x01, 0xef,
		0x82, 0x5a, 0x42, 0xf9, 0xbe, 0x3a, 0xb3, 0xe9
	};

	/* AES-GMAC Known Tag (256-bits). */
	static uint8_t aes_gmac256_known_tag[] = {
		0xef, 0x06, 0xd5, 0x4d, 0xfd, 0x00, 0x02, 0x1d,
		0x75, 0x27, 0xdf, 0xf2, 0x6f, 0xc9, 0xd4, 0x84
	};

	/* AES-GMAC Known AAD Alen = 16 bytes (128-bits). */
	static uint8_t aes_gmac128_known_adata[] = {
		0x7d, 0x1d, 0x42, 0xe8, 0x94, 0x60, 0xe9, 0x44,
		0xbf, 0xa4, 0x83, 0xdb, 0xe6, 0x92, 0xf0, 0x8d
	};

	/* AES-GMAC Known AAD Alen = 16 bytes (192-bits). */
	static uint8_t aes_gmac192_known_adata[] = {
		0xad, 0xcf, 0x4f, 0xbb, 0xa0, 0xe0, 0x6a, 0x63,
		0x70, 0x71, 0x1a, 0x57, 0xf8, 0xdc, 0xd0, 0xc9
	};

	/* AES-GMAC Known AAD Alen = 16 bytes (256-bits). */
	static uint8_t aes_gmac256_known_adata[] = {
		0xdb, 0x98, 0xd9, 0x0d, 0x1b, 0x69, 0x5c, 0xdb,
		0x74, 0x7a, 0x34, 0x3f, 0xbb, 0xc9, 0xf1, 0x41
	};

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

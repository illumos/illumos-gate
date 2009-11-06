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
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/crypto/common.h>
#include <sys/cmn_err.h>
#include <modes/modes.h>
#define	_DES_FIPS_POST
#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softCrypt.h"
#else
#define	_DES_IMPL
#include <des/des_impl.h>
#endif

#ifndef _KERNEL
/*
 * Allocate context for the DES encryption or decryption operation, and
 * generate DES or DES3 key schedule to speed up the operation.
 */
soft_des_ctx_t *
des_build_context(uint8_t *key, uint8_t *iv, CK_KEY_TYPE key_type,
	CK_MECHANISM_TYPE mechanism)
{

	size_t size;
	soft_des_ctx_t *soft_des_ctx;

	soft_des_ctx = calloc(1, sizeof (soft_des_ctx_t));
	if (soft_des_ctx == NULL) {
		return (NULL);
	}

	/* Allocate key schedule for DES or DES3 based on key type. */
	if (key_type == CKK_DES) {
		soft_des_ctx->key_sched = des_alloc_keysched(&size, DES, 0);
		if (soft_des_ctx->key_sched == NULL) {
			free(soft_des_ctx);
			return (NULL);
		}
		des_init_keysched(key, DES, soft_des_ctx->key_sched);
	} else {
		soft_des_ctx->key_sched = des_alloc_keysched(&size, DES3, 0);
		if (soft_des_ctx->key_sched == NULL) {
			free(soft_des_ctx);
			return (NULL);
		}
		des_init_keysched(key, DES3, soft_des_ctx->key_sched);
	}

	soft_des_ctx->keysched_len = size;
	soft_des_ctx->key_type = key_type;

	if ((mechanism == CKM_DES_CBC) || (mechanism == CKM_DES3_CBC)) {
		/* Save Initialization Vector (IV) in the context. */
		(void) memcpy(soft_des_ctx->ivec, iv, DES_BLOCK_LEN);

		/* Allocate a context for DES cipher-block chaining. */
		soft_des_ctx->des_cbc = (void *)des_cbc_ctx_init(
		    soft_des_ctx->key_sched, soft_des_ctx->keysched_len,
		    soft_des_ctx->ivec, soft_des_ctx->key_type);

		if (soft_des_ctx->des_cbc == NULL) {
			bzero(soft_des_ctx->key_sched,
			    soft_des_ctx->keysched_len);
			free(soft_des_ctx->key_sched);
			return (NULL);
		}
	}

	return (soft_des_ctx);
}

/*
 * Free the DES context.
 */
void
fips_des_free_context(soft_des_ctx_t *soft_des_ctx)
{

	des_ctx_t *des_ctx;

	des_ctx = (des_ctx_t *)soft_des_ctx->des_cbc;
	if (des_ctx != NULL) {
		bzero(des_ctx->dc_keysched, des_ctx->dc_keysched_len);
		free(soft_des_ctx->des_cbc);
	}

	bzero(soft_des_ctx->key_sched, soft_des_ctx->keysched_len);
	free(soft_des_ctx->key_sched);
	free(soft_des_ctx);
}
#else

static void
des_copy_block64(uint8_t *in, uint64_t *out)
{
	if (IS_P2ALIGNED(in, sizeof (uint64_t))) {
		/* LINTED: pointer alignment */
		out[0] = *(uint64_t *)&in[0];
	} else {
		uint64_t tmp64;

#ifdef _BIG_ENDIAN
		tmp64 = (((uint64_t)in[0] << 56) |
		    ((uint64_t)in[1] << 48) |
		    ((uint64_t)in[2] << 40) |
		    ((uint64_t)in[3] << 32) |
		    ((uint64_t)in[4] << 24) |
		    ((uint64_t)in[5] << 16) |
		    ((uint64_t)in[6] << 8) |
		    (uint64_t)in[7]);
#else
		tmp64 = (((uint64_t)in[7] << 56) |
		    ((uint64_t)in[6] << 48) |
		    ((uint64_t)in[5] << 40) |
		    ((uint64_t)in[4] << 32) |
		    ((uint64_t)in[3] << 24) |
		    ((uint64_t)in[2] << 16) |
		    ((uint64_t)in[1] << 8) |
		    (uint64_t)in[0]);
#endif /* _BIG_ENDIAN */

		out[0] = tmp64;
	}
}

des_ctx_t *
des_build_context(uint8_t *key, uint8_t *iv,
	des_mech_type_t mech_type)
{
	int rv = CRYPTO_SUCCESS;
	void *keysched;
	size_t size;
	des_ctx_t *des_ctx = NULL;
	des_strength_t strength;

	switch (mech_type) {
	case DES_ECB_MECH_INFO_TYPE:
		des_ctx = ecb_alloc_ctx(KM_SLEEP);
		/* FALLTHRU */
	case DES_CBC_MECH_INFO_TYPE:
		strength = DES;
		if (des_ctx == NULL)
			des_ctx = cbc_alloc_ctx(KM_SLEEP);
		break;
	case DES3_ECB_MECH_INFO_TYPE:
		des_ctx = ecb_alloc_ctx(KM_SLEEP);
		/* FALLTHRU */
	case DES3_CBC_MECH_INFO_TYPE:
		strength = DES3;
		if (des_ctx == NULL)
			des_ctx = cbc_alloc_ctx(KM_SLEEP);
		break;
	default:
		return (NULL);
	}

	if ((keysched = des_alloc_keysched(&size, strength,
	    KM_SLEEP)) == NULL)
		return (NULL);

	/*
	 * Initialize key schedule.
	 * Key length is stored in the key.
	 */
	des_init_keysched(key, strength, keysched);

	des_ctx->dc_flags |= PROVIDER_OWNS_KEY_SCHEDULE;
	des_ctx->dc_keysched_len = size;
	des_ctx->dc_keysched = keysched;

	if (strength == DES3) {
		des_ctx->dc_flags |= DES3_STRENGTH;
	}

	switch (mech_type) {
	case DES_CBC_MECH_INFO_TYPE:
	case DES3_CBC_MECH_INFO_TYPE:
		/* Save Initialization Vector (IV) in the context. */
		rv = cbc_init_ctx((cbc_ctx_t *)des_ctx, (char *)iv,
		    DES_BLOCK_LEN, DES_BLOCK_LEN, des_copy_block64);
		break;
	case DES_ECB_MECH_INFO_TYPE:
	case DES3_ECB_MECH_INFO_TYPE:
		des_ctx->dc_flags |= ECB_MODE;
	}

	if (rv != CRYPTO_SUCCESS) {
		if (des_ctx->dc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			bzero(keysched, size);
			kmem_free(keysched, size);
		}
	}

	return (des_ctx);
}

void
fips_des_free_context(des_ctx_t *des_ctx)
{

	if (des_ctx != NULL) {
		if (des_ctx->dc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(des_ctx->dc_keysched_len != 0);
			bzero(des_ctx->dc_keysched, des_ctx->dc_keysched_len);
			kmem_free(des_ctx->dc_keysched,
			    des_ctx->dc_keysched_len);
		}
		bzero(des_ctx, sizeof (des_ctx_t));
		kmem_free(des_ctx, sizeof (des_ctx_t));
	}
}
#endif

/*
 * fips_des_encrypt()
 *
 * Arguments:
 *	soft_des_ctx:	pointer to DES context
 *	in_buf:		pointer to the input data to be encrypted
 *	ulDataLen:	length of the input data
 *	out_buf:	pointer to the output data after encryption
 *	pulEncryptedLen: pointer to the length of the output data
 *	mechanism:	CKM_DES_ECB, CKM_DES3_ECB, CKM_DES_CBC, CKM_DES3_CBC
 *
 * Description:
 *	This function calls the corresponding DES low-level encrypt
 *	routine based on the mechanism.
 *
 */
#ifndef _KERNEL
CK_RV
fips_des_encrypt(soft_des_ctx_t *soft_des_ctx, CK_BYTE_PTR in_buf,
	CK_ULONG ulDataLen, CK_BYTE_PTR out_buf,
	CK_ULONG_PTR pulEncryptedLen, CK_MECHANISM_TYPE mechanism)
#else
int
fips_des_encrypt(des_ctx_t *des_ctx, uint8_t *in_buf,
	ulong_t ulDataLen, uint8_t *out_buf,
	ulong_t *pulEncryptedLen, des_mech_type_t mechanism)
#endif
{

	CK_RV rv = CKR_OK;
	int rc = 0;
	ulong_t out_len;

	/*
	 * DES only takes input length that is a multiple of blocksize
	 * with the mechanism CKM_DES<n>_ECB or CKM_DES<n>_CBC.
	 */
	if ((ulDataLen % DES_BLOCK_LEN) != 0) {
		return (CKR_DATA_LEN_RANGE);
	}

	/*
	 * For non-padding mode, the output length will
	 * be same as the input length.
	 */
	out_len = ulDataLen;

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
#ifndef _KERNEL
			if (soft_des_ctx->key_type == CKK_DES)
				(void) des_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_FALSE);
			else
				(void) des3_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_FALSE);
#else
			if (mechanism == DES_ECB_MECH_INFO_TYPE)
				(void) des_crunch_block(des_ctx->dc_keysched,
				    tmp_inbuf, tmp_outbuf, B_FALSE);
			else
				(void) des3_crunch_block(des_ctx->dc_keysched,
				    tmp_inbuf, tmp_outbuf, B_FALSE);
#endif
		}

		*pulEncryptedLen = out_len;
		break;
	}

	case CKM_DES_CBC:
	case CKM_DES3_CBC:
	{
		crypto_data_t out;

		out.cd_format =  CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Encrypt multiple blocks of data. */
		rc = des_encrypt_contiguous_blocks(
#ifndef _KERNEL
		    (des_ctx_t *)soft_des_ctx->des_cbc,
#else
			des_ctx,
#endif
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
	} /* end switch */

	return (rv);
}

/*
 * fips_des_decrypt()
 *
 * Arguments:
 *	soft_des_ctx:	pointer to DES context
 *	in_buf:	pointer to the input data to be decrypted
 *	ulEncryptedLen:	length of the input data
 *	out_buf:	pointer to the output data
 *	pulDataLen:	pointer to the length of the output data
 *	mechanism:	CKM_DES_ECB, CKM_DES3_ECB, CKM_DES_CBC, CKM_DES3_CBC
 *
 * Description:
 *      This function calls the corresponding DES low-level decrypt
 *	function based on the mechanism.
 *
 */
#ifndef _KERNEL
CK_RV
fips_des_decrypt(soft_des_ctx_t *soft_des_ctx, CK_BYTE_PTR in_buf,
	CK_ULONG ulEncryptedLen, CK_BYTE_PTR out_buf,
	CK_ULONG_PTR pulDataLen, CK_MECHANISM_TYPE mechanism)
#else
int
fips_des_decrypt(des_ctx_t *des_ctx, uint8_t *in_buf,
	ulong_t ulEncryptedLen, uint8_t *out_buf,
	ulong_t *pulDataLen, des_mech_type_t mechanism)
#endif
{

	CK_RV rv = CKR_OK;
	int rc = 0;
	ulong_t out_len;

	/*
	 * DES only takes input length that is a multiple of 8 bytes
	 * with the mechanism CKM_DES<n>_ECB, CKM_DES<n>_CBC or
	 * CKM_DES<n>_CBC_PAD.
	 */
	if ((ulEncryptedLen % DES_BLOCK_LEN) != 0) {
		return (CKR_DATA_LEN_RANGE);
	}

	/* Set output length same as input length. */
	out_len = ulEncryptedLen;

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
#ifndef _KERNEL
			if (soft_des_ctx->key_type == CKK_DES)
				(void) des_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_TRUE);
			else
				(void) des3_crunch_block(
				    soft_des_ctx->key_sched,
				    tmp_inbuf, tmp_outbuf, B_TRUE);
#else
			if (mechanism == DES_ECB_MECH_INFO_TYPE)
				(void) des_crunch_block(des_ctx->dc_keysched,
				    tmp_inbuf, tmp_outbuf, B_TRUE);
			else
				(void) des3_crunch_block(des_ctx->dc_keysched,
				    tmp_inbuf, tmp_outbuf, B_TRUE);
#endif
		}

		*pulDataLen = out_len;
		break;
	}

	case CKM_DES_CBC:
	case CKM_DES3_CBC:
	{
		crypto_data_t out;
		out.cd_format =  CRYPTO_DATA_RAW;
		out.cd_offset = 0;
		out.cd_length = out_len;
		out.cd_raw.iov_base = (char *)out_buf;
		out.cd_raw.iov_len = out_len;

		/* Decrypt multiple blocks of data. */
		rc = des_decrypt_contiguous_blocks(
#ifndef _KERNEL
		    (des_ctx_t *)soft_des_ctx->des_cbc,
#else
		    des_ctx,
#endif
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
	} /* end switch */

	return (rv);
}

/*
 * DES3 Power-On SelfTest(s).
 */
int
fips_des3_post(void)
{

	/* DES3 Known Key. */
	static uint8_t des3_known_key[] = { "ANSI Triple-DES Key Data" };

	/* DES3-CBC Known Initialization Vector (64-bits). */
	static uint8_t des3_cbc_known_iv[] = { "Security" };

	/* DES3 Known Plaintext (64-bits). */
	static uint8_t des3_ecb_known_plaintext[] = { "Solaris!" };
	static uint8_t des3_cbc_known_plaintext[] = { "Solaris!" };

	/* DES3 Known Ciphertext (64-bits). */
	static uint8_t des3_ecb_known_ciphertext[] = {
		0x17, 0x0d, 0x1f, 0x13, 0xd3, 0xa0, 0x3a, 0x63
	};

	static uint8_t des3_cbc_known_ciphertext[] = {
		0x7f, 0x62, 0x44, 0xb3, 0xf8, 0x77, 0xf8, 0xf8
	};

	/* DES3 variables. */
	uint8_t des3_computed_ciphertext[FIPS_DES3_ENCRYPT_LENGTH];
	uint8_t des3_computed_plaintext[FIPS_DES3_DECRYPT_LENGTH];

#ifdef _KERNEL
	des_ctx_t *des3_context;
#else
	soft_des_ctx_t *des3_context;
#endif

	ulong_t des3_bytes_encrypted;
	ulong_t des3_bytes_decrypted;
	int rv;

	/*
	 * DES3 ECB Known Answer Encryption Test
	 */
#ifdef _KERNEL
	des3_context = des_build_context(des3_known_key, NULL,
	    DES3_ECB_MECH_INFO_TYPE);
#else
	des3_context = des_build_context(des3_known_key, NULL,
	    CKK_DES3, CKM_DES3_ECB);
#endif

	if (des3_context == NULL)
		return (CKR_HOST_MEMORY);

#ifdef _KERNEL
	rv = fips_des_encrypt(des3_context, des3_ecb_known_plaintext,
	    FIPS_DES3_ENCRYPT_LENGTH, des3_computed_ciphertext,
	    &des3_bytes_encrypted, DES3_ECB_MECH_INFO_TYPE);
#else
	rv = fips_des_encrypt(des3_context, des3_ecb_known_plaintext,
	    FIPS_DES3_ENCRYPT_LENGTH, des3_computed_ciphertext,
	    &des3_bytes_encrypted, CKM_DES3_ECB);
#endif

	fips_des_free_context(des3_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (des3_bytes_encrypted != FIPS_DES3_ENCRYPT_LENGTH) ||
	    (memcmp(des3_computed_ciphertext, des3_ecb_known_ciphertext,
	    FIPS_DES3_ENCRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * DES3 ECB Known Answer Decryption Test
	 */
#ifdef _KERNEL
	des3_context = des_build_context(des3_known_key, NULL,
	    DES3_ECB_MECH_INFO_TYPE);
#else
	des3_context = des_build_context(des3_known_key, NULL,
	    CKK_DES3, CKM_DES3_ECB);
#endif

	if (des3_context == NULL)
		return (CKR_HOST_MEMORY);

#ifdef _KERNEL
	rv = fips_des_decrypt(des3_context, des3_ecb_known_ciphertext,
	    FIPS_DES3_DECRYPT_LENGTH, des3_computed_plaintext,
	    &des3_bytes_decrypted, DES3_ECB_MECH_INFO_TYPE);
#else
	rv = fips_des_decrypt(des3_context, des3_ecb_known_ciphertext,
	    FIPS_DES3_DECRYPT_LENGTH, des3_computed_plaintext,
	    &des3_bytes_decrypted, CKM_DES3_ECB);
#endif

	fips_des_free_context(des3_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (des3_bytes_decrypted != FIPS_DES3_DECRYPT_LENGTH) ||
	    (memcmp(des3_computed_plaintext, des3_ecb_known_plaintext,
	    FIPS_DES3_DECRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * DES3 CBC Known Answer Encryption Test
	 */
#ifdef _KERNEL
	des3_context = des_build_context(des3_known_key, des3_cbc_known_iv,
	    DES3_CBC_MECH_INFO_TYPE);
#else
	des3_context = des_build_context(des3_known_key, des3_cbc_known_iv,
	    CKK_DES3, CKM_DES3_CBC);
#endif

	if (des3_context == NULL)
		return (CKR_HOST_MEMORY);

#ifdef _KERNEL
	rv = fips_des_encrypt(des3_context, des3_cbc_known_plaintext,
	    FIPS_DES3_ENCRYPT_LENGTH, des3_computed_ciphertext,
	    &des3_bytes_encrypted, DES3_CBC_MECH_INFO_TYPE);
#else
	rv = fips_des_encrypt(des3_context, des3_cbc_known_plaintext,
	    FIPS_DES3_ENCRYPT_LENGTH, des3_computed_ciphertext,
	    &des3_bytes_encrypted, CKM_DES3_CBC);
#endif

	fips_des_free_context(des3_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (des3_bytes_encrypted != FIPS_DES3_ENCRYPT_LENGTH) ||
	    (memcmp(des3_computed_ciphertext, des3_cbc_known_ciphertext,
	    FIPS_DES3_ENCRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * DES3 CBC Known Answer Decryption Test
	 */
#ifdef _KERNEL
	des3_context = des_build_context(des3_known_key, des3_cbc_known_iv,
	    DES3_CBC_MECH_INFO_TYPE);
#else
	des3_context = des_build_context(des3_known_key, des3_cbc_known_iv,
	    CKK_DES3, CKM_DES3_CBC);
#endif

	if (des3_context == NULL)
		return (CKR_HOST_MEMORY);

#ifdef _KERNEL
	rv = fips_des_decrypt(des3_context, des3_cbc_known_ciphertext,
	    FIPS_DES3_DECRYPT_LENGTH, des3_computed_plaintext,
	    &des3_bytes_decrypted, DES3_CBC_MECH_INFO_TYPE);
#else
	rv = fips_des_decrypt(des3_context, des3_cbc_known_ciphertext,
	    FIPS_DES3_DECRYPT_LENGTH, des3_computed_plaintext,
	    &des3_bytes_decrypted, CKM_DES3_CBC);
#endif

	fips_des_free_context(des3_context);

	if ((rv != CRYPTO_SUCCESS) ||
	    (des3_bytes_decrypted != FIPS_DES3_DECRYPT_LENGTH) ||
	    (memcmp(des3_computed_plaintext, des3_cbc_known_plaintext,
	    FIPS_DES3_DECRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	return (CKR_OK);
}

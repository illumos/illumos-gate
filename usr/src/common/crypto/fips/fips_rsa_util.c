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
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sha1.h>
#define	_SHA2_IMPL
#include <sys/sha2.h>
#include <sys/crypto/common.h>
#define	_RSA_FIPS_POST
#include <rsa/rsa_impl.h>
#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softMAC.h"
#endif
#include <sha2/sha2_impl.h>

int
fips_rsa_encrypt(uint8_t *modulus, int modulus_len,
	uint8_t *expo, int expo_len,
	uint8_t *in, int in_len, uint8_t *out)
{

	RSAkey *rsakey;
	BIGNUM msg;
	CK_RV rv = CKR_OK;

#ifdef _KERNEL
	if ((rsakey = kmem_zalloc(sizeof (RSAkey), KM_SLEEP)) == NULL) {
#else
	if ((rsakey = calloc(1, sizeof (RSAkey))) == NULL) {
#endif
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	if (RSA_key_init(rsakey, modulus_len * 4, modulus_len * 4) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean2;
	}

	/* Size for big_init is in (32-bit) words. */
	if (big_init(&msg, CHARLEN2BIGNUMLEN(in_len)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean3;
	}

	/* Convert octet string exponent to big integer format. */
	bytestring2bignum(&(rsakey->e), expo, expo_len);

	/* Convert octet string modulus to big integer format. */
	bytestring2bignum(&(rsakey->n), modulus, modulus_len);

	/* Convert octet string input data to big integer format. */
	bytestring2bignum(&msg, (uchar_t *)in, in_len);

	if (big_cmp_abs(&msg, &(rsakey->n)) > 0) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean4;
	}

	/* Perform RSA computation on big integer input data. */
	if (big_modexp(&msg, &msg, &(rsakey->e), &(rsakey->n), NULL) !=
	    BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean4;
	}

	/* Convert the big integer output data to octet string. */
	bignum2bytestring((uchar_t *)out, &msg, modulus_len);

clean4:
	big_finish(&msg);
clean3:
	RSA_key_finish(rsakey);
clean2:
#ifndef _KERNEL
	free(rsakey);
#else
	kmem_free(rsakey, sizeof (RSAkey));
#endif
clean1:

	return (rv);
}

int
fips_rsa_decrypt(RSAPrivateKey_t *key, uint8_t *in, int in_len,
	uint8_t *out)
{

	RSAkey *rsakey;
	BIGNUM msg;
	CK_RV rv = CKR_OK;

#ifdef _KERNEL
	if ((rsakey = kmem_zalloc(sizeof (RSAkey), KM_SLEEP)) == NULL) {
#else
	if ((rsakey = calloc(1, sizeof (RSAkey))) == NULL) {
#endif
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	/* psize and qsize for RSA_key_init is in bits. */
	if (RSA_key_init(rsakey, key->prime2_len * 8, key->prime1_len * 8)
	    != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean2;
	}

	/* Size for big_init is in (32-bit) words. */
	if (big_init(&msg, CHARLEN2BIGNUMLEN(in_len)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean3;
	}

	/* Convert octet string input data to big integer format. */
	bytestring2bignum(&msg, (uchar_t *)in, in_len);

	/* Convert octet string modulus to big integer format. */
	bytestring2bignum(&(rsakey->n), key->modulus, key->modulus_len);

	if (big_cmp_abs(&msg, &(rsakey->n)) > 0) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean4;
	}

	/* Convert the rest of private key attributes to big integer format. */
	bytestring2bignum(&(rsakey->dmodpminus1), key->exponent2,
	    key->exponent2_len);
	bytestring2bignum(&(rsakey->dmodqminus1), key->exponent1,
	    key->exponent1_len);
	bytestring2bignum(&(rsakey->p), key->prime2, key->prime2_len);
	bytestring2bignum(&(rsakey->q), key->prime1, key->prime1_len);
	bytestring2bignum(&(rsakey->pinvmodq), key->coef, key->coef_len);

	if ((big_cmp_abs(&(rsakey->dmodpminus1), &(rsakey->p)) > 0) ||
	    (big_cmp_abs(&(rsakey->dmodqminus1), &(rsakey->q)) > 0) ||
	    (big_cmp_abs(&(rsakey->pinvmodq), &(rsakey->q)) > 0)) {
#ifndef _KERNEL
		rv = CKR_KEY_SIZE_RANGE;
#else
		rv = CRYPTO_KEY_SIZE_RANGE;
#endif
		goto clean4;
	}

	/* Perform RSA computation on big integer input data. */
	if (big_modexp_crt(&msg, &msg, &(rsakey->dmodpminus1),
	    &(rsakey->dmodqminus1), &(rsakey->p), &(rsakey->q),
	    &(rsakey->pinvmodq), NULL, NULL) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean4;
	}

	/* Convert the big integer output data to octet string. */
	bignum2bytestring((uchar_t *)out, &msg, key->modulus_len);

clean4:
	big_finish(&msg);
clean3:
	RSA_key_finish(rsakey);
clean2:
#ifndef _KERNEL
	free(rsakey);
#else
	kmem_free(rsakey, sizeof (RSAkey));
#endif
clean1:

	return (rv);

}

int
fips_rsa_sign(RSAPrivateKey_t *rsa_params, uint8_t *in,
	uint32_t inlen, uint8_t *out)
{
	BIGNUM msg;
	RSAkey rsakey;
	CK_RV rv = CKR_OK;

	/* psize and qsize for RSA_key_init is in bits. */
	if (RSA_key_init(&rsakey, rsa_params->prime2_len * 8,
	    rsa_params->prime1_len * 8) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	/* Size for big_init is in BIG_CHUNK_TYPE words. */
	if (big_init(&msg, CHARLEN2BIGNUMLEN(inlen)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean2;
	}

	/* Convert octet string input data to big integer format. */
	bytestring2bignum(&msg, (uchar_t *)in, inlen);

	/* Convert octet string modulus to big integer format. */
	bytestring2bignum(&(rsakey.n), rsa_params->modulus,
	    rsa_params->modulus_len);

	if (big_cmp_abs(&msg, &(rsakey.n)) > 0) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean3;
	}

	/* Convert the rest of private key attributes to big integer format. */
	bytestring2bignum(&(rsakey.dmodpminus1), rsa_params->exponent2,
	    rsa_params->exponent2_len);
	bytestring2bignum(&(rsakey.dmodqminus1), rsa_params->exponent1,
	    rsa_params->exponent1_len);
	bytestring2bignum(&(rsakey.p), rsa_params->prime2,
	    rsa_params->prime2_len);
	bytestring2bignum(&(rsakey.q), rsa_params->prime1,
	    rsa_params->prime1_len);
	bytestring2bignum(&(rsakey.pinvmodq), rsa_params->coef,
	    rsa_params->coef_len);

	if ((big_cmp_abs(&(rsakey.dmodpminus1), &(rsakey.p)) > 0) ||
	    (big_cmp_abs(&(rsakey.dmodqminus1), &(rsakey.q)) > 0) ||
	    (big_cmp_abs(&(rsakey.pinvmodq), &(rsakey.q)) > 0)) {
#ifndef _KERNEL
		rv = CKR_KEY_SIZE_RANGE;
#else
		rv = CRYPTO_KEY_SIZE_RANGE;
#endif
		goto clean3;
	}

	/* Perform RSA computation on big integer input data. */
	if (big_modexp_crt(&msg, &msg, &(rsakey.dmodpminus1),
	    &(rsakey.dmodqminus1), &(rsakey.p), &(rsakey.q),
	    &(rsakey.pinvmodq), NULL, NULL) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean3;
	}

	/* Convert the big integer output data to octet string. */
	bignum2bytestring((uchar_t *)out, &msg, rsa_params->modulus_len);

clean3:
	big_finish(&msg);
clean2:
	RSA_key_finish(&rsakey);
clean1:

	return (rv);

}

int
fips_rsa_verify(RSAPrivateKey_t *rsa_params, uint8_t *in, uint32_t in_len,
    uint8_t *out)
{

	BIGNUM msg;
	RSAkey rsakey;
	CK_RV rv = CKR_OK;

	if (RSA_key_init(&rsakey, rsa_params->modulus_len * 4,
	    rsa_params->modulus_len * 4) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	/* Size for big_init is in BIG_CHUNK_TYPE words. */
	if (big_init(&msg, CHARLEN2BIGNUMLEN(in_len)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean2;
	}

	/* Convert octet string exponent to big integer format. */
	bytestring2bignum(&(rsakey.e), rsa_params->public_expo,
	    rsa_params->public_expo_len);

	/* Convert octet string modulus to big integer format. */
	bytestring2bignum(&(rsakey.n), rsa_params->modulus,
	    rsa_params->modulus_len);

	/* Convert octet string input data to big integer format. */
	bytestring2bignum(&msg, (uchar_t *)in, in_len);

	if (big_cmp_abs(&msg, &(rsakey.n)) > 0) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean3;
	}

	/* Perform RSA computation on big integer input data. */
	if (big_modexp(&msg, &msg, &(rsakey.e), &(rsakey.n), NULL) !=
	    BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean3;
	}

	/* Convert the big integer output data to octet string. */
	bignum2bytestring((uchar_t *)out, &msg, rsa_params->modulus_len);

clean3:
	big_finish(&msg);
clean2:
	RSA_key_finish(&rsakey);
clean1:

	return (rv);
}

static CK_RV
#ifdef _KERNEL
fips_rsa_sign_verify_test(sha2_mech_t mechanism,
#else
fips_rsa_sign_verify_test(CK_MECHANISM_TYPE mechanism,
#endif
	RSAPrivateKey_t	*rsa_private_key,
	unsigned char *rsa_known_msg,
	unsigned int rsa_msg_length,
	unsigned char *rsa_computed_signature,
	unsigned char *der_data, int sign)

{
	unsigned char  hash[SHA512_DIGEST_LENGTH];    /* SHA digest */
	SHA1_CTX *sha1_context = NULL;
	SHA2_CTX *sha2_context = NULL;
	int hash_len;
	CK_RV rv;
	CK_ULONG der_len;
	CK_BYTE  *der_prefix;
	CK_ULONG der_data_len;
	CK_BYTE	plain_data[MAX_RSA_KEYLENGTH_IN_BYTES];
	uint32_t modulus_len;

	switch (mechanism) {
#ifdef _KERNEL
	case SHA1_TYPE:
#else
	case CKM_SHA_1:
#endif
	{

#ifdef _KERNEL
		if ((sha1_context = kmem_zalloc(sizeof (SHA1_CTX),
		    KM_SLEEP)) == NULL)
#else
		if ((sha1_context = malloc(sizeof (SHA1_CTX))) == NULL)
#endif
			return (CKR_HOST_MEMORY);

		SHA1Init(sha1_context);

#ifdef	__sparcv9
		SHA1Update(sha1_context, rsa_known_msg,
		    (uint_t)rsa_msg_length);
#else	/* !__sparcv9 */
		SHA1Update(sha1_context, rsa_known_msg, rsa_msg_length);
#endif	/* __sparcv9 */
		SHA1Final(hash, sha1_context);

		hash_len = SHA1_DIGEST_LENGTH;

		/*
		 * Prepare the DER encoding of the DigestInfo value
		 * by setting it to:
		 *	<MECH>_DER_PREFIX || H
		 */
		der_len = SHA1_DER_PREFIX_Len;
		der_prefix = (CK_BYTE *)SHA1_DER_PREFIX;
		(void) memcpy(der_data, der_prefix, der_len);
		(void) memcpy(der_data + der_len, hash, hash_len);
		der_data_len = der_len + hash_len;
		break;
	}

#ifdef _KERNEL
	case SHA256_TYPE:
#else
	case CKM_SHA256:
#endif
	{

		sha2_context = fips_sha2_build_context(mechanism);
		if (sha2_context == NULL)
			return (CKR_HOST_MEMORY);

		rv = fips_sha2_hash(sha2_context, rsa_known_msg,
		    rsa_msg_length, hash);
		hash_len = SHA256_DIGEST_LENGTH;

		/*
		 * Prepare the DER encoding of the DigestInfo value
		 * by setting it to:
		 *	<MECH>_DER_PREFIX || H
		 */
		(void) memcpy(der_data, SHA256_DER_PREFIX,
		    SHA2_DER_PREFIX_Len);
		(void) memcpy(der_data + SHA2_DER_PREFIX_Len, hash, hash_len);
		der_data_len = SHA2_DER_PREFIX_Len + hash_len;
		break;
	}
#ifdef _KERNEL
	case SHA384_TYPE:
#else
	case CKM_SHA384:
#endif
	{

		sha2_context = fips_sha2_build_context(mechanism);
		if (sha2_context == NULL)
			return (CKR_HOST_MEMORY);

		rv = fips_sha2_hash(sha2_context, rsa_known_msg,
			rsa_msg_length, hash);
		hash_len = SHA384_DIGEST_LENGTH;

		/*
		 * Prepare the DER encoding of the DigestInfo value
		 * by setting it to:
		 *	<MECH>_DER_PREFIX || H
		 */
		(void) memcpy(der_data, SHA384_DER_PREFIX,
		    SHA2_DER_PREFIX_Len);
		(void) memcpy(der_data + SHA2_DER_PREFIX_Len, hash, hash_len);
		der_data_len = SHA2_DER_PREFIX_Len + hash_len;
		break;
	}
#ifdef _KERNEL
	case SHA512_TYPE:
#else
	case CKM_SHA512:
#endif
	{

		sha2_context = fips_sha2_build_context(mechanism);
		if (sha2_context == NULL)
			return (CKR_HOST_MEMORY);

		rv = fips_sha2_hash(sha2_context, rsa_known_msg,
			rsa_msg_length, hash);
		hash_len = SHA512_DIGEST_LENGTH;

		/*
		 * Prepare the DER encoding of the DigestInfo value
		 * by setting it to:
		 *	<MECH>_DER_PREFIX || H
		 */
		(void) memcpy(der_data, SHA512_DER_PREFIX,
		    SHA2_DER_PREFIX_Len);
		(void) memcpy(der_data + SHA2_DER_PREFIX_Len, hash, hash_len);
		der_data_len = SHA2_DER_PREFIX_Len + hash_len;
		break;
	}
	}

	modulus_len = rsa_private_key->modulus_len;

	if (sign) {
		rv = soft_sign_rsa_pkcs_encode(der_data, der_data_len,
		    plain_data, modulus_len);

		if (rv != CKR_OK) {
			return (CKR_DEVICE_ERROR);
		}

		rv = fips_rsa_sign(rsa_private_key, plain_data, modulus_len,
			rsa_computed_signature);

		if (rv != CKR_OK) {
			return (CKR_DEVICE_ERROR);
		}
	} else {
		/*
		 * Perform RSA decryption with the signer's RSA public key
		 * for verification process.
		 */
		rv = fips_rsa_verify(rsa_private_key, rsa_computed_signature,
		    modulus_len, plain_data);

		if (rv == CKR_OK) {

			/*
			 * Strip off the encoded padding bytes in front of the
			 * recovered data, then compare the recovered data with
			 * the original data.
			 */
			int data_len = modulus_len;

			rv = soft_verify_rsa_pkcs_decode(plain_data, &data_len);
			if (rv != CKR_OK) {
				return (CKR_DEVICE_ERROR);
			}

			if ((CK_ULONG)data_len != der_data_len) {
#ifdef _KERNEL
				return (CRYPTO_SIGNATURE_LEN_RANGE);
#else
				return (CKR_SIGNATURE_LEN_RANGE);
#endif
			} else if (memcmp(der_data,
			    &plain_data[modulus_len - data_len],
			    data_len) != 0) {
				return (CKR_SIGNATURE_INVALID);
			}
		} else {

			return (CKR_DEVICE_ERROR);
		}
	}
	return (CKR_OK);
}


/*
 * RSA Power-On SelfTest(s).
 */
int
fips_rsa_post(void)
{
	/*
	 * RSA Known Modulus used in both Public/Private Key Values (1024-bits).
	 */
	static uint8_t rsa_modulus[FIPS_RSA_MODULUS_LENGTH] = {
		0xd5, 0x84, 0x95, 0x07, 0xf4, 0xd0, 0x1f, 0x82,
		0xf3, 0x79, 0xf4, 0x99, 0x48, 0x10, 0xe1, 0x71,
		0xa5, 0x62, 0x22, 0xa3, 0x4b, 0x00, 0xe3, 0x5b,
		0x3a, 0xcc, 0x10, 0x83, 0xe0, 0xaf, 0x61, 0x13,
		0x54, 0x6a, 0xa2, 0x6a, 0x2c, 0x5e, 0xb3, 0xcc,
		0xa3, 0x71, 0x9a, 0xb2, 0x3e, 0x78, 0xec, 0xb5,
		0x0e, 0x6e, 0x31, 0x3b, 0x77, 0x1f, 0x6e, 0x94,
		0x41, 0x60, 0xd5, 0x6e, 0xd9, 0xc6, 0xf9, 0x29,
		0xc3, 0x40, 0x36, 0x25, 0xdb, 0xea, 0x0b, 0x07,
		0xae, 0x76, 0xfd, 0x99, 0x29, 0xf4, 0x22, 0xc1,
		0x1a, 0x8f, 0x05, 0xfe, 0x98, 0x09, 0x07, 0x05,
		0xc2, 0x0f, 0x0b, 0x11, 0x83, 0x39, 0xca, 0xc7,
		0x43, 0x63, 0xff, 0x33, 0x80, 0xe7, 0xc3, 0x78,
		0xae, 0xf1, 0x73, 0x52, 0x98, 0x1d, 0xde, 0x5c,
		0x53, 0x6e, 0x01, 0x73, 0x0d, 0x12, 0x7e, 0x77,
		0x03, 0xf1, 0xef, 0x1b, 0xc8, 0xa8, 0x0f, 0x97
	};

	/* RSA Known Public Key Values (24-bits). */
	static uint8_t rsa_public_exponent[FIPS_RSA_PUBLIC_EXPONENT_LENGTH] = {
		0x01, 0x00, 0x01
	};

	/*
	 * RSA Known Private Key Values (version		 is    8-bits),
	 *				(private exponent	 is 1024-bits),
	 *				(private prime0		 is  512-bits),
	 *				(private prime1		 is  512-bits),
	 *				(private prime exponent0 is  512-bits),
	 *				(private prime exponent1 is  512-bits),
	 *				and (private coefficient is  512-bits).
	 */
	static uint8_t rsa_version[] = { 0x00 };

	static uint8_t rsa_private_exponent[FIPS_RSA_PRIVATE_EXPONENT_LENGTH]
		= {
		0x85, 0x27, 0x47, 0x61, 0x4c, 0xd4, 0xb5, 0xb2,
		0x0e, 0x70, 0x91, 0x8f, 0x3d, 0x97, 0xf9, 0x5f,
		0xcc, 0x09, 0x65, 0x1c, 0x7c, 0x5b, 0xb3, 0x6d,
		0x63, 0x3f, 0x7b, 0x55, 0x22, 0xbb, 0x7c, 0x48,
		0x77, 0xae, 0x80, 0x56, 0xc2, 0x10, 0xd5, 0x03,
		0xdb, 0x31, 0xaf, 0x8d, 0x54, 0xd4, 0x48, 0x99,
		0xa8, 0xc4, 0x23, 0x43, 0xb8, 0x48, 0x0b, 0xc7,
		0xbc, 0xf5, 0xcc, 0x64, 0x72, 0xbf, 0x59, 0x06,
		0x04, 0x1c, 0x32, 0xf5, 0x14, 0x2e, 0x6e, 0xe2,
		0x0f, 0x5c, 0xde, 0x36, 0x3c, 0x6e, 0x7c, 0x4d,
		0xcc, 0xd3, 0x00, 0x6e, 0xe5, 0x45, 0x46, 0xef,
		0x4d, 0x25, 0x46, 0x6d, 0x7f, 0xed, 0xbb, 0x4f,
		0x4d, 0x9f, 0xda, 0x87, 0x47, 0x8f, 0x74, 0x44,
		0xb7, 0xbe, 0x9d, 0xf5, 0xdd, 0xd2, 0x4c, 0xa5,
		0xab, 0x74, 0xe5, 0x29, 0xa1, 0xd2, 0x45, 0x3b,
		0x33, 0xde, 0xd5, 0xae, 0xf7, 0x03, 0x10, 0x21
	};

	static uint8_t rsa_prime0[FIPS_RSA_PRIME0_LENGTH]   = {
		0xf9, 0x74, 0x8f, 0x16, 0x02, 0x6b, 0xa0, 0xee,
		0x7f, 0x28, 0x97, 0x91, 0xdc, 0xec, 0xc0, 0x7c,
		0x49, 0xc2, 0x85, 0x76, 0xee, 0x66, 0x74, 0x2d,
		0x1a, 0xb8, 0xf7, 0x2f, 0x11, 0x5b, 0x36, 0xd8,
		0x46, 0x33, 0x3b, 0xd8, 0xf3, 0x2d, 0xa1, 0x03,
		0x83, 0x2b, 0xec, 0x35, 0x43, 0x32, 0xff, 0xdd,
		0x81, 0x7c, 0xfd, 0x65, 0x13, 0x04, 0x7c, 0xfc,
		0x03, 0x97, 0xf0, 0xd5, 0x62, 0xdc, 0x0d, 0xbf
	};

	static uint8_t rsa_prime1[FIPS_RSA_PRIME1_LENGTH]   = {
		0xdb, 0x1e, 0xa7, 0x3d, 0xe7, 0xfa, 0x8b, 0x04,
		0x83, 0x48, 0xf3, 0xa5, 0x31, 0x9d, 0x35, 0x5e,
		0x4d, 0x54, 0x77, 0xcc, 0x84, 0x09, 0xf3, 0x11,
		0x0d, 0x54, 0xed, 0x85, 0x39, 0xa9, 0xca, 0xa8,
		0xea, 0xae, 0x19, 0x9c, 0x75, 0xdb, 0x88, 0xb8,
		0x04, 0x8d, 0x54, 0xc6, 0xa4, 0x80, 0xf8, 0x93,
		0xf0, 0xdb, 0x19, 0xef, 0xd7, 0x87, 0x8a, 0x8f,
		0x5a, 0x09, 0x2e, 0x54, 0xf3, 0x45, 0x24, 0x29
	};

	static uint8_t rsa_exponent0[FIPS_RSA_EXPONENT0_LENGTH] = {
		0x6a, 0xd1, 0x25, 0x80, 0x18, 0x33, 0x3c, 0x2b,
		0x44, 0x19, 0xfe, 0xa5, 0x40, 0x03, 0xc4, 0xfc,
		0xb3, 0x9c, 0xef, 0x07, 0x99, 0x58, 0x17, 0xc1,
		0x44, 0xa3, 0x15, 0x7d, 0x7b, 0x22, 0x22, 0xdf,
		0x03, 0x58, 0x66, 0xf5, 0x24, 0x54, 0x52, 0x91,
		0x2d, 0x76, 0xfe, 0x63, 0x64, 0x4e, 0x0f, 0x50,
		0x2b, 0x65, 0x79, 0x1f, 0xf1, 0xbf, 0xc7, 0x41,
		0x26, 0xcc, 0xc6, 0x1c, 0xa9, 0x83, 0x6f, 0x03
	};

	static uint8_t rsa_exponent1[FIPS_RSA_EXPONENT1_LENGTH] = {
		0x12, 0x84, 0x1a, 0x99, 0xce, 0x9a, 0x8b, 0x58,
		0xcc, 0x47, 0x43, 0xdf, 0x77, 0xbb, 0xd3, 0x20,
		0xae, 0xe4, 0x2e, 0x63, 0x67, 0xdc, 0xf7, 0x5f,
		0x3f, 0x83, 0x27, 0xb7, 0x14, 0x52, 0x56, 0xbf,
		0xc3, 0x65, 0x06, 0xe1, 0x03, 0xcc, 0x93, 0x57,
		0x09, 0x7b, 0x6f, 0xe8, 0x81, 0x4a, 0x2c, 0xb7,
		0x43, 0xa9, 0x20, 0x1d, 0xf6, 0x56, 0x8b, 0xcc,
		0xe5, 0x4c, 0xd5, 0x4f, 0x74, 0x67, 0x29, 0x51
	};

	static uint8_t rsa_coefficient[FIPS_RSA_COEFFICIENT_LENGTH] = {
		0x23, 0xab, 0xf4, 0x03, 0x2f, 0x29, 0x95, 0x74,
		0xac, 0x1a, 0x33, 0x96, 0x62, 0xed, 0xf7, 0xf6,
		0xae, 0x07, 0x2a, 0x2e, 0xe8, 0xab, 0xfb, 0x1e,
		0xb9, 0xb2, 0x88, 0x1e, 0x85, 0x05, 0x42, 0x64,
		0x03, 0xb2, 0x8b, 0xc1, 0x81, 0x75, 0xd7, 0xba,
		0xaa, 0xd4, 0x31, 0x3c, 0x8a, 0x96, 0x23, 0x9d,
		0x3f, 0x06, 0x3e, 0x44, 0xa9, 0x62, 0x2f, 0x61,
		0x5a, 0x51, 0x82, 0x2c, 0x04, 0x85, 0x73, 0xd1
	};

	/* RSA Known Plaintext Message (1024-bits). */
	static uint8_t rsa_known_plaintext_msg[FIPS_RSA_MESSAGE_LENGTH] = {
		"Known plaintext message utilized"
		"for RSA Encryption &  Decryption"
		"block, SHA1, SHA256, SHA384  and"
		"SHA512 RSA Signature KAT tests."
	};

	/* RSA Known Ciphertext (1024-bits). */
	static uint8_t rsa_known_ciphertext[] = {
		0x1e, 0x7e, 0x12, 0xbb, 0x15, 0x62, 0xd0, 0x23,
		0x53, 0x4c, 0x51, 0x97, 0x77, 0x06, 0xa0, 0xbb,
		0x26, 0x99, 0x9a, 0x8f, 0x39, 0xad, 0x88, 0x5c,
		0xc4, 0xce, 0x33, 0x40, 0x94, 0x92, 0xb4, 0x0e,
		0xab, 0x71, 0xa9, 0x5d, 0x9a, 0x37, 0xe3, 0x9a,
		0x24, 0x95, 0x13, 0xea, 0x0f, 0xbb, 0xf7, 0xff,
		0xdf, 0x31, 0x33, 0x23, 0x1d, 0xce, 0x26, 0x9e,
		0xd1, 0xde, 0x98, 0x40, 0xde, 0x57, 0x86, 0x12,
		0xf1, 0xe6, 0x5a, 0x3f, 0x08, 0x02, 0x81, 0x85,
		0xe0, 0xd9, 0xad, 0x3c, 0x8c, 0x71, 0xf8, 0xcf,
		0x0a, 0x98, 0xc5, 0x08, 0xdc, 0xc4, 0xca, 0x8c,
		0x23, 0x1b, 0x4d, 0x9b, 0xb5, 0x13, 0x44, 0xe1,
		0x5f, 0xf9, 0x30, 0x80, 0x25, 0xe0, 0x1e, 0x94,
		0xa3, 0x0c, 0xdc, 0x82, 0x2e, 0xfb, 0x30, 0xbe,
		0x89, 0xba, 0x76, 0xb6, 0x23, 0xf7, 0xda, 0x7c,
		0xca, 0xe6, 0x02, 0xbd, 0x92, 0xce, 0x64, 0xfc
	};

	/* RSA Known Signed Hash (1024-bits). */
	static uint8_t rsa_known_sha1_signature[] = {
		0xd2, 0xa4, 0xe0, 0x2b, 0xc7, 0x03, 0x7f, 0xc6,
		0x06, 0x9e, 0xa2, 0x82, 0x19, 0xe9, 0x2b, 0xaf,
		0xe3, 0x48, 0x88, 0xc1, 0xf3, 0xb5, 0x0d, 0xe4,
		0x52, 0x9e, 0xad, 0xd5, 0x58, 0xb5, 0x9f, 0xe8,
		0x40, 0xe9, 0xb7, 0x2e, 0xc6, 0x71, 0x58, 0x56,
		0x04, 0xac, 0xb0, 0xf3, 0x3a, 0x42, 0x38, 0x08,
		0xc4, 0x43, 0x39, 0xba, 0x19, 0xce, 0xb1, 0x99,
		0xf1, 0x8d, 0x89, 0xd8, 0x50, 0x07, 0x14, 0x3d,
		0xcf, 0xd0, 0xb6, 0x79, 0xde, 0x9c, 0x89, 0x32,
		0xb0, 0x73, 0x3f, 0xed, 0x03, 0x0b, 0xdf, 0x6d,
		0x7e, 0xc9, 0x1c, 0x39, 0xe8, 0x2b, 0x16, 0x09,
		0xbb, 0x5f, 0x99, 0x2f, 0xeb, 0xf3, 0x37, 0x73,
		0x0d, 0x0e, 0xcc, 0x95, 0xad, 0x90, 0x80, 0x03,
		0x1d, 0x80, 0x55, 0x37, 0xa1, 0x2a, 0x71, 0x76,
		0x23, 0x87, 0x8c, 0x9b, 0x41, 0x07, 0xc6, 0x3d,
		0xc6, 0xa3, 0x7d, 0x1b, 0xff, 0x4e, 0x11, 0x19
	};

	/* RSA Known Signed Hash (1024-bits). */
	static uint8_t rsa_known_sha256_signature[] = {
		0x27, 0x35, 0xdd, 0xc4, 0xf8, 0xe2, 0x0b, 0xa3,
		0xef, 0x63, 0x57, 0x3b, 0xe1, 0x58, 0x9a, 0xbc,
		0x20, 0x9c, 0x25, 0x12, 0x01, 0xbf, 0xbb, 0x29,
		0x80, 0x1a, 0xb1, 0x37, 0x9c, 0xcd, 0x67, 0xc7,
		0x0d, 0xf8, 0x64, 0x10, 0x9f, 0xe2, 0xa1, 0x9b,
		0x21, 0x90, 0xcc, 0xda, 0x8b, 0x76, 0x5e, 0x79,
		0x00, 0x9d, 0x58, 0x8b, 0x8a, 0xb3, 0xc3, 0xb5,
		0xf1, 0x54, 0xc5, 0x8c, 0x72, 0xba, 0xde, 0x51,
		0x3c, 0x6b, 0x94, 0xd6, 0xf3, 0x1b, 0xa2, 0x53,
		0xe6, 0x1a, 0x46, 0x1d, 0x7f, 0x14, 0x86, 0xcc,
		0xa6, 0x30, 0x92, 0x96, 0xc0, 0x96, 0x24, 0xf0,
		0x42, 0x53, 0x4c, 0xdd, 0x27, 0xdf, 0x1d, 0x2e,
		0x8b, 0x83, 0xbe, 0xed, 0x85, 0x1d, 0x50, 0x46,
		0xa3, 0x7d, 0x20, 0xea, 0x3e, 0x91, 0xfb, 0xf6,
		0x86, 0x51, 0xfd, 0x8c, 0xe5, 0x31, 0xe6, 0x7e,
		0x60, 0x08, 0x0e, 0xec, 0xa6, 0xea, 0x24, 0x8d
	};

	/* RSA Known Signed Hash (1024-bits). */
	static uint8_t rsa_known_sha384_signature[] = {
		0x0b, 0x03, 0x94, 0x4f, 0x94, 0x78, 0x9b, 0x96,
		0x76, 0xeb, 0x72, 0x58, 0xe1, 0xc5, 0xc7, 0x5f,
		0x85, 0x01, 0xa8, 0xc4, 0xf6, 0x1a, 0xb5, 0x2c,
		0xd1, 0xd8, 0x87, 0xde, 0x3a, 0x9c, 0x9f, 0x57,
		0x81, 0x2a, 0x1e, 0x23, 0x07, 0x70, 0xb0, 0xf9,
		0x28, 0x3d, 0xfa, 0xe5, 0x2e, 0x1b, 0x9a, 0x72,
		0xc3, 0x74, 0xb3, 0x42, 0x1c, 0x9a, 0x13, 0xdc,
		0xc9, 0xd6, 0xd5, 0x88, 0xc9, 0x9c, 0x46, 0xf1,
		0x0c, 0xa6, 0xf7, 0xd8, 0x06, 0xa3, 0x1b, 0xdf,
		0x55, 0xb3, 0x1b, 0x7b, 0x58, 0x1d, 0xff, 0x19,
		0xc7, 0xe0, 0xdd, 0x59, 0xac, 0x2f, 0x78, 0x71,
		0xe7, 0xe0, 0x17, 0xa3, 0x1c, 0x5c, 0x92, 0xef,
		0xb6, 0x75, 0xed, 0xbe, 0x18, 0x39, 0x6b, 0xd7,
		0xc9, 0x08, 0x62, 0x55, 0x62, 0xac, 0x5d, 0xa1,
		0x9b, 0xd5, 0xb8, 0x98, 0x15, 0xc0, 0xf5, 0x41,
		0x85, 0x44, 0x96, 0xca, 0x10, 0xdc, 0x57, 0x21
	};

	/* RSA Known Signed Hash (1024-bits). */
	static uint8_t rsa_known_sha512_signature[] = {
		0xa5, 0xd0, 0x80, 0x04, 0x22, 0xfc, 0x80, 0x73,
		0x7d, 0x46, 0xc8, 0x7b, 0xac, 0x44, 0x7b, 0xe6,
		0x07, 0xe5, 0x61, 0x4c, 0x33, 0x7f, 0x6f, 0x46,
		0x7c, 0x30, 0xe3, 0x75, 0x59, 0x4b, 0x42, 0xf3,
		0x9f, 0x35, 0x3c, 0x10, 0x56, 0xdb, 0xd2, 0x69,
		0x43, 0xcb, 0x77, 0xe9, 0x7d, 0xcd, 0x07, 0x43,
		0xc5, 0xd4, 0x0c, 0x9d, 0xf5, 0x92, 0xbd, 0x0e,
		0x3b, 0xb7, 0x68, 0x88, 0x84, 0xca, 0xae, 0x0d,
		0xab, 0x71, 0x10, 0xad, 0xab, 0x27, 0xe4, 0xa3,
		0x24, 0x41, 0xeb, 0x1c, 0xa6, 0x5f, 0xf1, 0x85,
		0xd0, 0xf6, 0x22, 0x74, 0x3d, 0x81, 0xbe, 0xdd,
		0x1b, 0x2a, 0x4c, 0xd1, 0x6c, 0xb5, 0x6d, 0x7a,
		0xbb, 0x99, 0x69, 0x01, 0xa6, 0xc0, 0x98, 0xfa,
		0x97, 0xa3, 0xd1, 0xb0, 0xdf, 0x09, 0xe3, 0x3d,
		0x88, 0xee, 0x90, 0xf3, 0x10, 0x41, 0x0f, 0x06,
		0x31, 0xe9, 0x60, 0x2d, 0xbf, 0x63, 0x7b, 0xf8
	};

	RSAPrivateKey_t	rsa_private_key;
	CK_RV rv;
	uint8_t rsa_computed_ciphertext[FIPS_RSA_ENCRYPT_LENGTH];
	uint8_t rsa_computed_plaintext[FIPS_RSA_DECRYPT_LENGTH];
	uint8_t  rsa_computed_signature[FIPS_RSA_SIGNATURE_LENGTH];
	CK_BYTE der_data[SHA512_DIGEST_LENGTH + SHA2_DER_PREFIX_Len];

	/*
	 * RSA Known Answer Encryption Test.
	 */

	/* Perform RSA Public Key Encryption. */
	rv = fips_rsa_encrypt(rsa_modulus, FIPS_RSA_MODULUS_LENGTH,
	    rsa_public_exponent, FIPS_RSA_PUBLIC_EXPONENT_LENGTH,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_ciphertext);

	if ((rv != CKR_OK) ||
	    (memcmp(rsa_computed_ciphertext, rsa_known_ciphertext,
	    FIPS_RSA_ENCRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/*
	 * RSA Known Answer Decryption Test.
	 */
	rsa_private_key.version = rsa_version;
	rsa_private_key.version_len = FIPS_RSA_PRIVATE_VERSION_LENGTH;
	rsa_private_key.modulus = rsa_modulus;
	rsa_private_key.modulus_len = FIPS_RSA_MODULUS_LENGTH;
	rsa_private_key.public_expo = rsa_public_exponent;
	rsa_private_key.public_expo_len = FIPS_RSA_PUBLIC_EXPONENT_LENGTH;
	rsa_private_key.private_expo = rsa_private_exponent;
	rsa_private_key.private_expo_len = FIPS_RSA_PRIVATE_EXPONENT_LENGTH;
	rsa_private_key.prime1 = rsa_prime0;
	rsa_private_key.prime1_len = FIPS_RSA_PRIME0_LENGTH;
	rsa_private_key.prime2 = rsa_prime1;
	rsa_private_key.prime2_len = FIPS_RSA_PRIME1_LENGTH;
	rsa_private_key.exponent1 = rsa_exponent0;
	rsa_private_key.exponent1_len = FIPS_RSA_EXPONENT0_LENGTH;
	rsa_private_key.exponent2 = rsa_exponent1;
	rsa_private_key.exponent2_len = FIPS_RSA_EXPONENT1_LENGTH;
	rsa_private_key.coef = rsa_coefficient;
	rsa_private_key.coef_len = FIPS_RSA_COEFFICIENT_LENGTH;

	/* Perform RSA Private Key Decryption. */
	rv = fips_rsa_decrypt(&rsa_private_key, rsa_known_ciphertext,
	    FIPS_RSA_MESSAGE_LENGTH, rsa_computed_plaintext);

	if ((rv != CKR_OK) ||
	    (memcmp(rsa_computed_plaintext, rsa_known_plaintext_msg,
	    FIPS_RSA_DECRYPT_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

	/* SHA-1 Sign/Verify */
#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA1_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA_1, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#endif

	if ((rv != CKR_OK) ||
	    (memcmp(rsa_computed_signature, rsa_known_sha1_signature,
	    FIPS_RSA_SIGNATURE_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA1_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA_1, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#endif

	if (rv != CKR_OK)
		goto rsa_loser;

	/* SHA256 Sign/Verify */
#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA256_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA256, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#endif

	if ((rv != CKR_OK) ||
	    (memcmp(rsa_computed_signature, rsa_known_sha256_signature,
	    FIPS_RSA_SIGNATURE_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA256_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA256, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#endif

	if (rv != CKR_OK)
		goto rsa_loser;

	/* SHA384 Sign/Verify */
#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA384_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA384, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#endif

	if ((rv != CKR_OK) ||
	    (memcmp(rsa_computed_signature, rsa_known_sha384_signature,
	    FIPS_RSA_SIGNATURE_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA384_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA384, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#endif

	if (rv != CKR_OK)
		goto rsa_loser;

	/* SHA512 Sign/Verify */
#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA512_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA512, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 1);
#endif

	if ((rv != CKR_OK) ||
	    (memcmp(rsa_computed_signature, rsa_known_sha512_signature,
	    FIPS_RSA_SIGNATURE_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

#ifdef _KERNEL
	rv = fips_rsa_sign_verify_test(SHA512_TYPE, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#else
	rv = fips_rsa_sign_verify_test(CKM_SHA512, &rsa_private_key,
	    rsa_known_plaintext_msg, FIPS_RSA_MESSAGE_LENGTH,
	    rsa_computed_signature, der_data, 0);
#endif

rsa_loser:
	if (rv != CKR_OK)
		return (CKR_DEVICE_ERROR);
	else
		return (CKR_OK);

}

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
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sha1.h>
#define	_SHA2_IMPL
#include <sys/sha2.h>
#include <sys/crypto/common.h>
#include <modes/modes.h>
#include <bignum.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softCrypt.h"
#include "softGlobal.h"
#include "softRSA.h"
#include "softDSA.h"
#include "softRandom.h"
#include "softOps.h"
#include "softMAC.h"
#include "softFipsDSA.h"
#include <sha1_impl.h>

CK_RV
fips_generate_dsa_key(DSAkey *key, uint8_t *seed, int seed_len)
{
	BIG_ERR_CODE err;


	bytestring2bignum(&key->x, seed, seed_len);

	/* Compute public key y = g**x mod p */
	if ((err = big_modexp(&(key->y), &(key->g), (&key->x),
	    (&key->p), NULL)) != BIG_OK)
		return (convert_rv(err));

	return (CKR_OK);
}

CK_RV
fips_dsa_genkey_pair(DSAParams_t *dsa_params, fips_key_t *pubkey,
	fips_key_t *prikey, uint8_t *seed, int seed_len)
{
	BIG_ERR_CODE brv;
	CK_RV rv;
	DSAkey	dsakey = {0};

	/*
	 * initialize the dsa key
	 * Note: big_extend takes length in words
	 */
	if ((brv = DSA_key_init(&dsakey, dsa_params->prime_len * 8))
	    != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	if ((brv = big_extend(&dsakey.p,
	    CHARLEN2BIGNUMLEN(dsa_params->prime_len))) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	bytestring2bignum(&dsakey.p, dsa_params->prime, dsa_params->prime_len);

	if ((brv = big_extend(&dsakey.q,
	    CHARLEN2BIGNUMLEN(dsa_params->subprime_len))) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	bytestring2bignum(&dsakey.q, dsa_params->subprime,
	    dsa_params->subprime_len);

	if ((brv = big_extend(&dsakey.g,
	    CHARLEN2BIGNUMLEN(dsa_params->base_len))) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	bytestring2bignum(&dsakey.g, dsa_params->base, dsa_params->base_len);

	/*
	 * generate DSA key pair
	 * Note: bignum.len is length of value in words
	 */
	if ((rv = fips_generate_dsa_key(&dsakey, seed, seed_len)) != CKR_OK) {
		goto cleanexit;
	}

	/* pubkey->key_len = dsakey.y.len * (int)sizeof (uint32_t); */
	pubkey->key_len = dsa_params->prime_len;
	if ((pubkey->key = malloc(pubkey->key_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanexit;
	}
	bignum2bytestring(pubkey->key, &dsakey.y, pubkey->key_len);

	/* prikey->key_len = dsakey.x.len * (int)sizeof (uint32_t); */
	prikey->key_len = DSA_SUBPRIME_BYTES;
	if ((prikey->key = malloc(prikey->key_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanexit;
	}
	bignum2bytestring(prikey->key, &dsakey.x, prikey->key_len);
	DSA_key_finish(&dsakey);
	return (CKR_OK);

cleanexit:
	DSA_key_finish(&dsakey);

	if (pubkey->key != NULL) {
		free(pubkey->key);
	}

	if (prikey->key != NULL) {
		free(prikey->key);
	}

	return (rv);
}

CK_RV
fips_dsa_digest_sign(DSAParams_t *dsa_params, fips_key_t *key,
	CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out,
	uint8_t *seed, int seed_len)
{


	DSAkey dsakey;
	BIGNUM msg, tmp, tmp1, tmp2;
	BIG_ERR_CODE err;
	CK_RV rv = CKR_OK;
	SHA1_CTX *sha1_context = NULL;
	uint8_t sha1_computed_digest[FIPS_DSA_DIGEST_LENGTH];

	sha1_context = fips_sha1_build_context();
	if (sha1_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha1_hash(sha1_context, in, inlen, sha1_computed_digest);

	if ((err = DSA_key_init(&dsakey, dsa_params->prime_len * 8)) !=
	    BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	if ((err = big_init(&msg, BIG_CHUNKS_FOR_160BITS)) != BIG_OK) {
		goto clean2;
	}
	if ((err = big_init(&tmp, CHARLEN2BIGNUMLEN(dsa_params->prime_len) +
	    2 * BIG_CHUNKS_FOR_160BITS + 1)) != BIG_OK) {
		goto clean3;
	}
	if ((err = big_init(&tmp1, 2 * BIG_CHUNKS_FOR_160BITS + 1)) != BIG_OK) {
		goto clean4;
	}
	if ((err = big_init(&tmp2, BIG_CHUNKS_FOR_160BITS)) != BIG_OK) {
		goto clean5;
	}

	bytestring2bignum(&(dsakey.g), dsa_params->base,
	    dsa_params->prime_len);
	bytestring2bignum(&(dsakey.x), key->key, seed_len);
	bytestring2bignum(&(dsakey.p), dsa_params->prime,
	    dsa_params->prime_len);
	bytestring2bignum(&(dsakey.q), dsa_params->subprime,
	    DSA_SUBPRIME_BYTES);
	bytestring2bignum(&msg, (uchar_t *)sha1_computed_digest,
	    FIPS_DSA_DIGEST_LENGTH);

	bytestring2bignum(&(dsakey.k), seed, seed_len);

	if ((err = big_div_pos(NULL, &(dsakey.k), &(dsakey.k),
	    &(dsakey.q))) != BIG_OK)
		goto clean6;

	if ((err = big_modexp(&tmp, &(dsakey.g), &(dsakey.k), &(dsakey.p),
	    NULL)) != BIG_OK)
		goto clean6;

	if ((err = big_div_pos(NULL, &(dsakey.r), &tmp, &(dsakey.q))) !=
	    BIG_OK)
		goto clean6;

	if ((err = big_ext_gcd_pos(NULL, NULL, &tmp, &(dsakey.q),
	    &(dsakey.k))) != BIG_OK)
		goto clean6;

	if (tmp.sign == -1)
		if ((err = big_add(&tmp, &tmp, &(dsakey.q))) != BIG_OK)
			goto clean6;			/* tmp <- k^-1 */

	if ((err = big_mul(&tmp1, &(dsakey.x), &(dsakey.r))) != BIG_OK)
		goto clean6;

	if ((err = big_add(&tmp1, &tmp1, &msg)) != BIG_OK)
		goto clean6;

	if ((err = big_mul(&tmp, &tmp1, &tmp)) != BIG_OK)
		goto clean6;

	if ((err = big_div_pos(NULL, &(dsakey.s), &tmp, &(dsakey.q))) !=
	    BIG_OK)
		goto clean6;

	bignum2bytestring((uchar_t *)out, &(dsakey.r), 20);
	bignum2bytestring((uchar_t *)out + 20, &(dsakey.s), 20);

	err = BIG_OK;

clean6:
	big_finish(&tmp2);
clean5:
	big_finish(&tmp1);
clean4:
	big_finish(&tmp);
clean3:
	big_finish(&msg);
clean2:
	DSA_key_finish(&dsakey);
	if (err == BIG_OK)
		rv = CKR_OK;
	else if (err == BIG_NO_MEM)
		rv = CKR_HOST_MEMORY;
	else
		rv = CKR_FUNCTION_FAILED;
clean1:
	free(sha1_context);
	return (rv);
}

CK_RV
fips_dsa_verify(DSAParams_t *dsa_params, fips_key_t *key,
	CK_BYTE_PTR data, CK_BYTE_PTR sig)
{

	DSAkey dsakey;
	BIGNUM msg, tmp1, tmp2, tmp3;
	CK_RV rv = CKR_OK;
	SHA1_CTX *sha1_context = NULL;
	uint8_t sha1_computed_digest[FIPS_DSA_DIGEST_LENGTH];

	sha1_context = fips_sha1_build_context();
	if (sha1_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha1_hash(sha1_context, data,
	    FIPS_DSA_DIGEST_LENGTH, sha1_computed_digest);

	if (DSA_key_init(&dsakey, dsa_params->prime_len * 8) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}

	rv = CKR_HOST_MEMORY;
	if (big_init(&msg, BIG_CHUNKS_FOR_160BITS) != BIG_OK) {
		goto clean6;
	}
	if (big_init(&tmp1, 2 * CHARLEN2BIGNUMLEN(dsa_params->prime_len)) !=
	    BIG_OK) {
		goto clean7;
	}
	if (big_init(&tmp2, CHARLEN2BIGNUMLEN(dsa_params->prime_len)) !=
	    BIG_OK) {
		goto clean8;
	}
	if (big_init(&tmp3, 2 * BIG_CHUNKS_FOR_160BITS) != BIG_OK) {
		goto clean9;
	}

	bytestring2bignum(&(dsakey.g), dsa_params->base,
	    dsa_params->base_len);
	bytestring2bignum(&(dsakey.y), key->key, key->key_len);
	bytestring2bignum(&(dsakey.p), dsa_params->prime,
	    dsa_params->prime_len);
	bytestring2bignum(&(dsakey.q), dsa_params->subprime,
	    DSA_SUBPRIME_BYTES);
	bytestring2bignum(&(dsakey.r), (uchar_t *)sig, 20);
	bytestring2bignum(&(dsakey.s), ((uchar_t *)sig) + 20, 20);
	bytestring2bignum(&msg, (uchar_t *)sha1_computed_digest,
	    FIPS_DSA_DIGEST_LENGTH);

	if (big_ext_gcd_pos(NULL, &tmp2, NULL, &(dsakey.s), &(dsakey.q)) !=
	    BIG_OK)
		goto clean10;

	if (tmp2.sign == -1)
		if (big_add(&tmp2, &tmp2, &(dsakey.q)) != BIG_OK)
			goto clean10;			/* tmp2 <- w */

	if (big_mul(&tmp1, &msg, &tmp2) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.q)) != BIG_OK)
		goto clean10;				/* tmp1 <- u_1 */

	if (big_mul(&tmp2, &tmp2, &(dsakey.r)) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp2, &tmp2, &(dsakey.q)) != BIG_OK)
		goto clean10;				/* tmp2 <- u_2 */

	if (big_modexp(&tmp1, &(dsakey.g), &tmp1, &(dsakey.p), NULL) !=
	    BIG_OK)
		goto clean10;

	if (big_modexp(&tmp2, &(dsakey.y), &tmp2, &(dsakey.p), NULL) !=
	    BIG_OK)
		goto clean10;

	if (big_mul(&tmp1, &tmp1, &tmp2) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.p)) != BIG_OK)
		goto clean10;

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.q)) != BIG_OK)
		goto clean10;

	if (big_cmp_abs(&tmp1, &(dsakey.r)) == 0)
		rv = CKR_OK;
	else
		rv = CKR_SIGNATURE_INVALID;

clean10:
	big_finish(&tmp3);
clean9:
	big_finish(&tmp2);
clean8:
	big_finish(&tmp1);
clean7:
	big_finish(&msg);
clean6:
	DSA_key_finish(&dsakey);
clean1:
	free(sha1_context);
	return (rv);
}

/*
 * DSA Power-On SelfTest(s).
 */
CK_RV
soft_fips_dsa_post(void)
{
	/* DSA Known P (1024-bits), Q (160-bits), and G (1024-bits) Values. */
	static uint8_t dsa_P[] = {
		0x80, 0xb0, 0xd1, 0x9d, 0x6e, 0xa4, 0xf3, 0x28,
		0x9f, 0x24, 0xa9, 0x8a, 0x49, 0xd0, 0x0c, 0x63,
		0xe8, 0x59, 0x04, 0xf9, 0x89, 0x4a, 0x5e, 0xc0,
		0x6d, 0xd2, 0x67, 0x6b, 0x37, 0x81, 0x83, 0x0c,
		0xfe, 0x3a, 0x8a, 0xfd, 0xa0, 0x3b, 0x08, 0x91,
		0x1c, 0xcb, 0xb5, 0x63, 0xb0, 0x1c, 0x70, 0xd0,
		0xae, 0xe1, 0x60, 0x2e, 0x12, 0xeb, 0x54, 0xc7,
		0xcf, 0xc6, 0xcc, 0xae, 0x97, 0x52, 0x32, 0x63,
		0xd3, 0xeb, 0x55, 0xea, 0x2f, 0x4c, 0xd5, 0xd7,
		0x3f, 0xda, 0xec, 0x49, 0x27, 0x0b, 0x14, 0x56,
		0xc5, 0x09, 0xbe, 0x4d, 0x09, 0x15, 0x75, 0x2b,
		0xa3, 0x42, 0x0d, 0x03, 0x71, 0xdf, 0x0f, 0xf4,
		0x0e, 0xe9, 0x0c, 0x46, 0x93, 0x3d, 0x3f, 0xa6,
		0x6c, 0xdb, 0xca, 0xe5, 0xac, 0x96, 0xc8, 0x64,
		0x5c, 0xec, 0x4b, 0x35, 0x65, 0xfc, 0xfb, 0x5a,
		0x1b, 0x04, 0x1b, 0xa1, 0x0e, 0xfd, 0x88, 0x15
	};

	static uint8_t dsa_Q[] = {
		0xad, 0x22, 0x59, 0xdf, 0xe5, 0xec, 0x4c, 0x6e,
		0xf9, 0x43, 0xf0, 0x4b, 0x2d, 0x50, 0x51, 0xc6,
		0x91, 0x99, 0x8b, 0xcf
	};

	static uint8_t dsa_G[] = {
		0x78, 0x6e, 0xa9, 0xd8, 0xcd, 0x4a, 0x85, 0xa4,
		0x45, 0xb6, 0x6e, 0x5d, 0x21, 0x50, 0x61, 0xf6,
		0x5f, 0xdf, 0x5c, 0x7a, 0xde, 0x0d, 0x19, 0xd3,
		0xc1, 0x3b, 0x14, 0xcc, 0x8e, 0xed, 0xdb, 0x17,
		0xb6, 0xca, 0xba, 0x86, 0xa9, 0xea, 0x51, 0x2d,
		0xc1, 0xa9, 0x16, 0xda, 0xf8, 0x7b, 0x59, 0x8a,
		0xdf, 0xcb, 0xa4, 0x67, 0x00, 0x44, 0xea, 0x24,
		0x73, 0xe5, 0xcb, 0x4b, 0xaf, 0x2a, 0x31, 0x25,
		0x22, 0x28, 0x3f, 0x16, 0x10, 0x82, 0xf7, 0xeb,
		0x94, 0x0d, 0xdd, 0x09, 0x22, 0x14, 0x08, 0x79,
		0xba, 0x11, 0x0b, 0xf1, 0xff, 0x2d, 0x67, 0xac,
		0xeb, 0xb6, 0x55, 0x51, 0x69, 0x97, 0xa7, 0x25,
		0x6b, 0x9c, 0xa0, 0x9b, 0xd5, 0x08, 0x9b, 0x27,
		0x42, 0x1c, 0x7a, 0x69, 0x57, 0xe6, 0x2e, 0xed,
		0xa9, 0x5b, 0x25, 0xe8, 0x1f, 0xd2, 0xed, 0x1f,
		0xdf, 0xe7, 0x80, 0x17, 0xba, 0x0d, 0x4d, 0x38
	};

	/*
	 * DSA Known Random Values (known random key block is 160-bits)
	 * and (known random signature block is 160-bits).
	 */
	static uint8_t dsa_known_random_key_block[] = {
		"This is DSA RNG key!"
	};

	static uint8_t dsa_known_random_signature_block[] = {
		"Random DSA Signature"
	};

	/* DSA Known Digest (160-bits) */
	static uint8_t dsa_known_digest[] = {
		"DSA Signature Digest"
	};

	/* DSA Known Signature (320-bits). */
	static uint8_t dsa_known_signature[] = {
		0x25, 0x7c, 0x3a, 0x79, 0x32, 0x45, 0xb7, 0x32,
		0x70, 0xca, 0x62, 0x63, 0x2b, 0xf6, 0x29, 0x2c,
		0x22, 0x2a, 0x03, 0xce, 0x65, 0x02, 0x72, 0x5a,
		0x66, 0x29, 0xcf, 0x56, 0xe6, 0xdf, 0xb0, 0xcc,
		0x53, 0x72, 0x56, 0x70, 0x92, 0xb5, 0x45, 0x75

	};

	/* DSA variables. */
	DSAParams_t	dsa_params;
	CK_RV rv = CKR_OK;

	fips_key_t dsa_private_key;
	fips_key_t dsa_public_key;
	uint8_t dsa_computed_signature[FIPS_DSA_SIGNATURE_LENGTH];

	dsa_params.prime = dsa_P;
	dsa_params.prime_len = FIPS_DSA_PRIME_LENGTH;
	dsa_params.subprime = dsa_Q;
	dsa_params.subprime_len = FIPS_DSA_SUBPRIME_LENGTH;
	dsa_params.base = dsa_G;
	dsa_params.base_len = FIPS_DSA_BASE_LENGTH;


	/* Generate a DSA public/private key pair. */
	rv = fips_dsa_genkey_pair(&dsa_params, &dsa_public_key,
	    &dsa_private_key, dsa_known_random_key_block,
	    FIPS_DSA_SEED_LENGTH);

	if (rv != CKR_OK)
		return (CKR_DEVICE_ERROR);

	/*
	 * DSA Known Answer Signature Test
	 */

	/* Perform DSA signature process. */
	rv = fips_dsa_digest_sign(&dsa_params, &dsa_private_key,
	    dsa_known_digest, FIPS_DSA_DIGEST_LENGTH,
	    dsa_computed_signature, dsa_known_random_signature_block,
	    FIPS_DSA_SEED_LENGTH);

	if ((rv != CKR_OK) ||
	    (memcmp(dsa_computed_signature, dsa_known_signature,
	    FIPS_DSA_SIGNATURE_LENGTH) != 0)) {
		goto clean;
	}

	/*
	 * DSA Known Answer Verification Test
	 */

	/* Perform DSA verification process. */
	rv = fips_dsa_verify(&dsa_params, &dsa_public_key,
	    dsa_known_digest, dsa_computed_signature);

clean:
	free(dsa_private_key.key);
	free(dsa_public_key.key);

	if (rv != CKR_OK)
		return (CKR_DEVICE_ERROR);
	else
		return (CKR_OK);

}

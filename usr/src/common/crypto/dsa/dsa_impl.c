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
 */

/*
 * This file contains DSA helper routines common to
 * the PKCS11 soft token code and the kernel DSA code.
 */

#include <sys/types.h>
#include <bignum.h>

#ifdef _KERNEL
#include <sys/param.h>
#else
#include <strings.h>
#include <cryptoutil.h>
#endif

#include <sys/crypto/common.h>
#include "dsa_impl.h"


static CK_RV
convert_rv(BIG_ERR_CODE err)
{
	switch (err) {

	case BIG_OK:
		return (CKR_OK);

	case BIG_NO_MEM:
		return (CKR_HOST_MEMORY);

	case BIG_NO_RANDOM:
		return (CKR_DEVICE_ERROR);

	case BIG_INVALID_ARGS:
		return (CKR_ARGUMENTS_BAD);

	case BIG_DIV_BY_0:
	default:
		return (CKR_GENERAL_ERROR);
	}
}

/* size is in bits */
static BIG_ERR_CODE
DSA_key_init(DSAkey *key, int size)
{
	BIG_ERR_CODE err = BIG_OK;
	int len, len160;

	len = BITLEN2BIGNUMLEN(size);
	len160 = BIG_CHUNKS_FOR_160BITS;
	key->size = size;
	if ((err = big_init(&(key->q), len160)) != BIG_OK)
		return (err);
	if ((err = big_init(&(key->p), len)) != BIG_OK)
		goto ret1;
	if ((err = big_init(&(key->g), len)) != BIG_OK)
		goto ret2;
	if ((err = big_init(&(key->x), len160)) != BIG_OK)
		goto ret3;
	if ((err = big_init(&(key->y), len)) != BIG_OK)
		goto ret4;
	if ((err = big_init(&(key->k), len160)) != BIG_OK)
		goto ret5;
	if ((err = big_init(&(key->r), len160)) != BIG_OK)
		goto ret6;
	if ((err = big_init(&(key->s), len160)) != BIG_OK)
		goto ret7;
	if ((err = big_init(&(key->v), len160)) != BIG_OK)
		goto ret8;

	return (BIG_OK);

ret8:
	big_finish(&(key->s));
ret7:
	big_finish(&(key->r));
ret6:
	big_finish(&(key->k));
ret5:
	big_finish(&(key->y));
ret4:
	big_finish(&(key->x));
ret3:
	big_finish(&(key->g));
ret2:
	big_finish(&(key->p));
ret1:
	big_finish(&(key->q));
	return (err);
}

static void
DSA_key_finish(DSAkey *key)
{

	big_finish(&(key->v));
	big_finish(&(key->s));
	big_finish(&(key->r));
	big_finish(&(key->k));
	big_finish(&(key->y));
	big_finish(&(key->x));
	big_finish(&(key->g));
	big_finish(&(key->p));
	big_finish(&(key->q));

}

/*
 * Generate DSA private x and public y from prime p, subprime q, and base g.
 */
static CK_RV
generate_dsa_key(DSAkey *key, int (*rfunc)(void *, size_t))
{
	BIG_ERR_CODE err;
	int (*rf)(void *, size_t);

	rf = rfunc;
	if (rf == NULL) {
#ifdef _KERNEL
		rf = random_get_pseudo_bytes;
#else
		rf = pkcs11_get_urandom;
#endif
	}
	do {
		if ((err = big_random(&(key->x), DSA_SUBPRIME_BITS, rf)) !=
		    BIG_OK) {
			return (convert_rv(err));
		}
	} while (big_cmp_abs(&(key->x), &(key->q)) > 0);

	if ((err = big_modexp(&(key->y), &(key->g), (&key->x), (&key->p),
	    NULL)) != BIG_OK)
		return (convert_rv(err));

	return (CKR_OK);
}

CK_RV
dsa_genkey_pair(DSAbytekey *bkey)
{
	CK_RV rv = CKR_OK;
	BIG_ERR_CODE brv;
	DSAkey	dsakey;
	uint32_t prime_bytes;
	uint32_t subprime_bytes;

	prime_bytes = CRYPTO_BITS2BYTES(bkey->prime_bits);

	if ((prime_bytes < MIN_DSA_KEY_LEN) ||
	    (prime_bytes > MAX_DSA_KEY_LEN)) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	/*
	 * There is no check here that prime_bits must be a multiple of 64,
	 * and thus that prime_bytes must be a multiple of 8.
	 */

	subprime_bytes = CRYPTO_BITS2BYTES(bkey->subprime_bits);

	if (subprime_bytes != DSA_SUBPRIME_BYTES) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	if (bkey->public_y == NULL || bkey->private_x == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Initialize the DSA key.
	 * Note: big_extend takes length in words.
	 */
	if ((brv = DSA_key_init(&dsakey, bkey->prime_bits)) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}

	/* Convert prime p to bignum. */
	if ((brv = big_extend(&(dsakey.p),
	    CHARLEN2BIGNUMLEN(prime_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}
	bytestring2bignum(&(dsakey.p), bkey->prime, prime_bytes);

	/* Convert prime q to bignum. */
	if ((brv = big_extend(&(dsakey.q),
	    CHARLEN2BIGNUMLEN(subprime_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}
	bytestring2bignum(&(dsakey.q), bkey->subprime, subprime_bytes);

	/* Convert base g to bignum. */
	if ((brv = big_extend(&(dsakey.g),
	    CHARLEN2BIGNUMLEN(bkey->base_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto cleanexit;
	}
	bytestring2bignum(&(dsakey.g), bkey->base, bkey->base_bytes);

	/*
	 * Generate DSA key pair.
	 * Note: bignum.len is length of value in words.
	 */
	if ((rv = generate_dsa_key(&dsakey, bkey->rfunc)) !=
	    CKR_OK) {
		goto cleanexit;
	}

	bkey->public_y_bits = CRYPTO_BYTES2BITS(prime_bytes);
	bignum2bytestring(bkey->public_y, &(dsakey.y), prime_bytes);

	bkey->private_x_bits = CRYPTO_BYTES2BITS(DSA_SUBPRIME_BYTES);
	bignum2bytestring(bkey->private_x, &(dsakey.x), DSA_SUBPRIME_BYTES);

cleanexit:
	DSA_key_finish(&dsakey);

	return (rv);
}

/*
 * DSA sign operation
 */
CK_RV
dsa_sign(DSAbytekey *bkey, uchar_t *in, uint32_t inlen, uchar_t *out)
{
	CK_RV rv = CKR_OK;
	BIG_ERR_CODE brv;
	DSAkey dsakey;
	BIGNUM msg, tmp, tmp1;
	uint32_t prime_bytes;
	uint32_t subprime_bytes;
	uint32_t value_bytes;
	int (*rf)(void *, size_t);

	prime_bytes = CRYPTO_BITS2BYTES(bkey->prime_bits);
	subprime_bytes = CRYPTO_BITS2BYTES(bkey->subprime_bits);

	if (DSA_SUBPRIME_BYTES != subprime_bytes) {
		return (CKR_KEY_SIZE_RANGE);
	}

	value_bytes = CRYPTO_BITS2BYTES(bkey->private_x_bits);	/* len of x */

	if (DSA_SUBPRIME_BYTES < value_bytes) {
		return (CKR_KEY_SIZE_RANGE);
	}

	/*
	 * Initialize the DH key.
	 * Note: big_extend takes length in words.
	 */
	if ((brv = DSA_key_init(&dsakey, bkey->prime_bits)) != BIG_OK) {
		return (CKR_HOST_MEMORY);
	}

	if ((brv = big_extend(&(dsakey.p),
	    CHARLEN2BIGNUMLEN(prime_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.p), bkey->prime, prime_bytes);

	if ((brv = big_extend(&(dsakey.q),
	    CHARLEN2BIGNUMLEN(subprime_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.q), bkey->subprime, subprime_bytes);

	if ((brv = big_extend(&(dsakey.g),
	    CHARLEN2BIGNUMLEN(bkey->base_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.g), bkey->base, bkey->base_bytes);

	if ((brv = big_extend(&(dsakey.x),
	    CHARLEN2BIGNUMLEN(value_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.x), bkey->private_x, value_bytes);

	if ((brv = big_init(&msg, BIG_CHUNKS_FOR_160BITS)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&msg, in, inlen);

	/*
	 * Compute signature.
	 */
	if ((brv = big_init(&tmp, CHARLEN2BIGNUMLEN(prime_bytes) +
	    2 * BIG_CHUNKS_FOR_160BITS + 1)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean2;
	}
	if ((brv = big_init(&tmp1, 2 * BIG_CHUNKS_FOR_160BITS + 1)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean3;
	}

	rf = bkey->rfunc;
	if (rf == NULL) {
#ifdef _KERNEL
		rf = random_get_pseudo_bytes;
#else
		rf = pkcs11_get_urandom;
#endif
	}
	if ((brv = big_random(&(dsakey.k), DSA_SUBPRIME_BITS, rf)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	if ((brv = big_div_pos(NULL, &(dsakey.k), &(dsakey.k),
	    &(dsakey.q))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	if ((brv = big_modexp(&tmp, &(dsakey.g), &(dsakey.k), &(dsakey.p),
	    NULL)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	if ((brv = big_div_pos(NULL, &(dsakey.r), &tmp, &(dsakey.q))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}


	if ((brv = big_ext_gcd_pos(NULL, NULL, &tmp, &(dsakey.q),
	    &(dsakey.k))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	if (tmp.sign == -1)
		if ((brv = big_add(&tmp, &tmp, &(dsakey.q))) != BIG_OK) {
			rv = convert_rv(brv);
			goto clean4;			/* tmp <- k^-1 */
		}

	if ((brv = big_mul(&tmp1, &(dsakey.x), &(dsakey.r))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	if ((brv = big_add(&tmp1, &tmp1, &msg)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	if ((brv = big_mul(&tmp, &tmp1, &tmp)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	if ((brv = big_div_pos(NULL, &(dsakey.s), &tmp, &(dsakey.q))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto clean4;
	}

	/*
	 * Signature is in DSA key r and s values, copy to out
	 */
	bignum2bytestring(out, &(dsakey.r), DSA_SUBPRIME_BYTES);
	bignum2bytestring(out + DSA_SUBPRIME_BYTES, &(dsakey.s),
	    DSA_SUBPRIME_BYTES);

clean4:
	big_finish(&tmp1);
clean3:
	big_finish(&tmp);
clean2:
	big_finish(&msg);
clean1:
	DSA_key_finish(&dsakey);

	return (rv);
}

/*
 * DSA verify operation
 */
CK_RV
dsa_verify(DSAbytekey *bkey, uchar_t *data, uchar_t *sig)
{
	CK_RV rv = CKR_OK;
	BIG_ERR_CODE brv;
	DSAkey dsakey;
	BIGNUM msg, tmp1, tmp2, tmp3;
	uint32_t prime_bytes;
	uint32_t subprime_bytes;
	uint32_t value_bytes;

	prime_bytes = CRYPTO_BITS2BYTES(bkey->prime_bits);
	subprime_bytes = CRYPTO_BITS2BYTES(bkey->subprime_bits);

	if (DSA_SUBPRIME_BYTES != subprime_bytes) {
		return (CKR_KEY_SIZE_RANGE);
	}

	if (prime_bytes < bkey->base_bytes) {
		return (CKR_KEY_SIZE_RANGE);
	}

	value_bytes = CRYPTO_BITS2BYTES(bkey->public_y_bits);	/* len of y */
	if (prime_bytes < value_bytes) {
		return (CKR_KEY_SIZE_RANGE);
	}

	/*
	 * Initialize the DSA key.
	 * Note: big_extend takes length in words.
	 */
	if (DSA_key_init(&dsakey, bkey->prime_bits) != BIG_OK) {
		return (CKR_HOST_MEMORY);
	}

	if ((brv = big_extend(&(dsakey.p),
	    CHARLEN2BIGNUMLEN(prime_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.p), bkey->prime, prime_bytes);

	if ((brv = big_extend(&(dsakey.q),
	    CHARLEN2BIGNUMLEN(subprime_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.q), bkey->subprime, subprime_bytes);

	if ((brv = big_extend(&(dsakey.g),
	    CHARLEN2BIGNUMLEN(bkey->base_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.g), bkey->base, bkey->base_bytes);

	if ((brv = big_extend(&(dsakey.y),
	    CHARLEN2BIGNUMLEN(value_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.y), bkey->public_y, value_bytes);

	/*
	 * Copy signature to DSA key r and s values
	 */
	if ((brv = big_extend(&(dsakey.r),
	    CHARLEN2BIGNUMLEN(DSA_SUBPRIME_BYTES))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.r), sig, DSA_SUBPRIME_BYTES);

	if ((brv = big_extend(&(dsakey.s),
	    CHARLEN2BIGNUMLEN(DSA_SUBPRIME_BYTES))) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean1;
	}
	bytestring2bignum(&(dsakey.s), sig + DSA_SUBPRIME_BYTES,
	    DSA_SUBPRIME_BYTES);


	if (big_init(&msg, BIG_CHUNKS_FOR_160BITS) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}
	bytestring2bignum(&msg, data, DSA_SUBPRIME_BYTES);

	if (big_init(&tmp1, 2 * CHARLEN2BIGNUMLEN(prime_bytes)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean2;
	}
	if (big_init(&tmp2, CHARLEN2BIGNUMLEN(prime_bytes)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean3;
	}
	if (big_init(&tmp3, 2 * BIG_CHUNKS_FOR_160BITS) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean4;
	}

	/*
	 * Verify signature against msg.
	 */
	if (big_ext_gcd_pos(NULL, &tmp2, NULL, &(dsakey.s), &(dsakey.q)) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (tmp2.sign == -1)
		if (big_add(&tmp2, &tmp2, &(dsakey.q)) != BIG_OK) {
			rv = convert_rv(brv);
			goto clean5;			/* tmp2 <- w */
		}

	if (big_mul(&tmp1, &msg, &tmp2) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.q)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;				/* tmp1 <- u_1 */
	}

	if (big_mul(&tmp2, &tmp2, &(dsakey.r)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (big_div_pos(NULL, &tmp2, &tmp2, &(dsakey.q)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;				/* tmp2 <- u_2 */
	}

	if (big_modexp(&tmp1, &(dsakey.g), &tmp1, &(dsakey.p), NULL) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (big_modexp(&tmp2, &(dsakey.y), &tmp2, &(dsakey.p), NULL) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (big_mul(&tmp1, &tmp1, &tmp2) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.p)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (big_div_pos(NULL, &tmp1, &tmp1, &(dsakey.q)) != BIG_OK) {
		rv = convert_rv(brv);
		goto clean5;
	}

	if (big_cmp_abs(&tmp1, &(dsakey.r)) == 0)
		rv = CKR_OK;
	else
		rv = CKR_SIGNATURE_INVALID;

clean5:
	big_finish(&tmp3);
clean4:
	big_finish(&tmp2);
clean3:
	big_finish(&tmp1);
clean2:
	big_finish(&msg);
clean1:
	DSA_key_finish(&dsakey);

	return (rv);
}

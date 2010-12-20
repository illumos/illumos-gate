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
 * This file contains DH helper routines common to
 * the PKCS11 soft token code and the kernel DH code.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <bignum.h>

#ifdef _KERNEL
#include <sys/param.h>
#else
#include <strings.h>
#include <cryptoutil.h>
#endif

#include <sys/crypto/common.h>
#include <des/des_impl.h>
#include "dh_impl.h"


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
DH_key_init(DHkey *key, int size)
{
	BIG_ERR_CODE err = BIG_OK;
	int len;

	len = BITLEN2BIGNUMLEN(size);
	key->size = size;

	if ((err = big_init(&(key->p), len)) != BIG_OK)
		return (err);
	if ((err = big_init(&(key->g), len)) != BIG_OK)
		goto ret1;
	if ((err = big_init(&(key->x), len)) != BIG_OK)
		goto ret2;
	if ((err = big_init(&(key->y), len)) != BIG_OK)
		goto ret3;

	return (BIG_OK);

ret3:
	big_finish(&(key->x));
ret2:
	big_finish(&(key->g));
ret1:
	big_finish(&(key->p));
	return (err);
}

static void
DH_key_finish(DHkey *key)
{

	big_finish(&(key->y));
	big_finish(&(key->x));
	big_finish(&(key->g));
	big_finish(&(key->p));

}

/*
 * Generate DH key pair x and y, given prime p and base g.
 * Can optionally provided bit length of x, not to exceed bit length of p.
 *
 * For those not familiar with DH keys, there are 4 components:
 * p - a known prime
 * g - the base 0 < g < p
 * x - a random number 0 < x < p-1, or if a smaller value is desired,
 *     2^(len-1) <= x < 2^(len)
 * y = g^x mod p, this implies 0 < y < p.  That is important!
 */
CK_RV
dh_genkey_pair(DHbytekey *bkey)
{
	CK_RV		rv = CKR_OK;
	BIG_ERR_CODE	brv;
	uint32_t	primebit_len;
	DHkey		dhkey;
	int		(*rf)(void *, size_t);
	uint32_t	prime_bytes;

	if (bkey == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Must have prime and base set, value bits can be 0 or non-0 */
	if (bkey->prime_bits == 0 || bkey->prime == NULL ||
	    bkey->base_bytes == 0 || bkey->base == NULL)
		return (CKR_ARGUMENTS_BAD);

	prime_bytes = CRYPTO_BITS2BYTES(bkey->prime_bits);

	if ((prime_bytes < MIN_DH_KEYLENGTH_IN_BYTES) ||
	    (prime_bytes > MAX_DH_KEYLENGTH_IN_BYTES)) {
		return (CKR_KEY_SIZE_RANGE);
	}

	/*
	 * Initialize the DH key.
	 * Note: big_extend takes length in words.
	 */
	if ((brv = DH_key_init(&dhkey, bkey->prime_bits)) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	/* Convert prime p to bignum. */
	if ((brv = big_extend(&(dhkey.p), CHARLEN2BIGNUMLEN(prime_bytes))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}
	bytestring2bignum(&(dhkey.p), bkey->prime, prime_bytes);

	/* Convert base g to bignum. */
	if ((brv = big_extend(&(dhkey.g),
	    CHARLEN2BIGNUMLEN(bkey->base_bytes))) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}
	bytestring2bignum(&(dhkey.g), bkey->base, bkey->base_bytes);

	/* Base g cannot be greater than prime p. */
	if (big_cmp_abs(&(dhkey.g), &(dhkey.p)) >= 0) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret;
	}

	/*
	 * The intention of selecting a private-value length is to reduce
	 * the computation time for key agreement, while maintaining a
	 * given level of security.
	 */

	/* Maximum bit length for private-value x is bit length of prime p */
	primebit_len = big_bitlength(&(dhkey.p));

	if (bkey->value_bits == 0)
		bkey->value_bits = primebit_len;

	if (bkey->value_bits > primebit_len) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret;
	}

	/* Generate DH key pair private and public values. */
	if ((brv = big_extend(&(dhkey.x), BITLEN2BIGNUMLEN(bkey->value_bits)))
	    != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	if ((brv = big_extend(&(dhkey.y), CHARLEN2BIGNUMLEN(prime_bytes)))
	    != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	/*
	 * The big integer of the private value shall be generated privately
	 * and randomly.
	 */
	rf = bkey->rfunc;
	if (rf == NULL) {
#ifdef _KERNEL
		rf = random_get_pseudo_bytes;
#else
		rf = pkcs11_get_urandom;
#endif
	}

	if ((brv = big_random(&(dhkey.x), bkey->value_bits, rf)) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	/*
	 * The base g shall be raised to the private value x modulo p to
	 * give an integer y, the integer public value, i.e. y = (g^x) mod p.
	 */
	if ((brv = big_modexp(&(dhkey.y), &(dhkey.g), &(dhkey.x),
	    &(dhkey.p), NULL)) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	bignum2bytestring(bkey->private_x, &(dhkey.x),
	    CRYPTO_BITS2BYTES(bkey->value_bits));
	bignum2bytestring(bkey->public_y, &(dhkey.y), prime_bytes);

ret:
	DH_key_finish(&dhkey);

	return (rv);
}

/*
 * DH key derive operation, flag is ignored in userland
 */
CK_RV
dh_key_derive(DHbytekey *bkey, uint32_t key_type,	/* = CKK_KEY_TYPE */
    uchar_t *secretkey, uint32_t *secretkey_len,	/* derived secret */
    int flag)
{
	CK_RV		rv = CKR_OK;
	BIG_ERR_CODE	brv;
	DHkey		dhkey;
	uchar_t		*s = NULL;
	uint32_t	s_bytes = 0;
	uint32_t	prime_bytes;
	uint32_t	value_bytes;
	size_t		s_alloc;

	if (bkey == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Must have prime, private value and public value */
	if (bkey->prime_bits == 0 || bkey->prime == NULL ||
	    bkey->value_bits == 0 || bkey->private_x == NULL ||
	    bkey->public_y == NULL)
		return (CKR_ARGUMENTS_BAD);

	if (secretkey == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	prime_bytes = CRYPTO_BITS2BYTES(bkey->prime_bits);
	value_bytes = CRYPTO_BITS2BYTES(bkey->value_bits);

	/*
	 * Initialize the DH key.
	 * Note: big_extend takes length in words.
	 */
	if ((brv = DH_key_init(&dhkey, bkey->prime_bits)) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	/* Convert prime p to bignum. */
	if ((brv = big_extend(&(dhkey.p), CHARLEN2BIGNUMLEN(prime_bytes))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}
	bytestring2bignum(&(dhkey.p), bkey->prime, prime_bytes);

	/* Convert private-value x to bignum. */
	if ((brv = big_extend(&(dhkey.x), CHARLEN2BIGNUMLEN(value_bytes))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}
	bytestring2bignum(&(dhkey.x), bkey->private_x, value_bytes);

	/* Convert public-value y to bignum. */
	if ((brv = big_extend(&(dhkey.y), CHARLEN2BIGNUMLEN(prime_bytes))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}
	bytestring2bignum(&(dhkey.y), bkey->public_y, prime_bytes);

	/*
	 * Recycle base g as a temporary variable to compute the derived
	 * secret value which is "g" = (y^x) mod p.  (Not recomputing g.)
	 */
	if ((brv = big_extend(&(dhkey.g), CHARLEN2BIGNUMLEN(prime_bytes))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	if ((brv = big_modexp(&(dhkey.g), &(dhkey.y), &(dhkey.x),
	    &(dhkey.p), NULL)) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret;
	}

	s_alloc = P2ROUNDUP_TYPED(prime_bytes, sizeof (BIG_CHUNK_TYPE), size_t);

#ifdef _KERNEL
	if ((s = kmem_alloc(s_alloc, flag)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto ret;
	}
#else
	if ((s = malloc(s_alloc)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto ret;
	}
#endif
	s_bytes = dhkey.g.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(s, &(dhkey.g), s_bytes);

	switch (key_type) {

	case CKK_DES:
		*secretkey_len = DES_KEYSIZE;
		break;
	case CKK_DES2:
		*secretkey_len = DES2_KEYSIZE;
		break;
	case CKK_DES3:
		*secretkey_len = DES3_KEYSIZE;
		break;
	case CKK_RC4:
	case CKK_AES:
	case CKK_GENERIC_SECRET:
		/* use provided secret key length, if any */
		break;
	default:
		/* invalid key type */
		rv = CKR_ATTRIBUTE_TYPE_INVALID;
		goto ret;
	}

	if (*secretkey_len == 0) {
		*secretkey_len = s_bytes;
	}

	if (*secretkey_len > s_bytes) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret;
	}

	/*
	 * The truncation removes bytes from the leading end of the
	 * secret value.
	 */
	(void) memcpy(secretkey, (s + s_bytes - *secretkey_len),
	    *secretkey_len);

ret:
	if (s != NULL)
#ifdef _KERNEL
		kmem_free(s, s_alloc);
#else
		free(s);
#endif

	DH_key_finish(&dhkey);

	return (rv);
}

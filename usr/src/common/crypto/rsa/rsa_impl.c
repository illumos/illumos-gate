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
 * This file contains RSA helper routines common to
 * the PKCS11 soft token code and the kernel RSA code.
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
#include "rsa_impl.h"

/*
 * DER encoding T of the DigestInfo values for MD5, SHA1, and SHA2
 * from PKCS#1 v2.1: RSA Cryptography Standard Section 9.2 Note 1
 *
 * MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H
 * SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H
 * SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
 * SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
 * SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
 *
 * Where H is the digested output from MD5 or SHA1. We define the constant
 * byte array (the prefix) here and use it rather than doing the DER
 * encoding of the OID in a separate routine.
 */
const CK_BYTE MD5_DER_PREFIX[MD5_DER_PREFIX_Len] = {0x30, 0x20, 0x30, 0x0c,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
    0x04, 0x10};

const CK_BYTE SHA1_DER_PREFIX[SHA1_DER_PREFIX_Len] = {0x30, 0x21, 0x30,
    0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

const CK_BYTE SHA1_DER_PREFIX_OID[SHA1_DER_PREFIX_OID_Len] = {0x30, 0x1f, 0x30,
    0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14};

const CK_BYTE SHA256_DER_PREFIX[SHA2_DER_PREFIX_Len] = {0x30, 0x31, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20};

const CK_BYTE SHA384_DER_PREFIX[SHA2_DER_PREFIX_Len] = {0x30, 0x41, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30};

const CK_BYTE SHA512_DER_PREFIX[SHA2_DER_PREFIX_Len] = {0x30, 0x51, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40};

const CK_BYTE DEFAULT_PUB_EXPO[DEFAULT_PUB_EXPO_Len] = { 0x01, 0x00, 0x01 };


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

/* psize and qsize are in bits */
static BIG_ERR_CODE
RSA_key_init(RSAkey *key, int psize, int qsize)
{
	BIG_ERR_CODE err = BIG_OK;

	int plen, qlen, nlen;

	plen = BITLEN2BIGNUMLEN(psize);
	qlen = BITLEN2BIGNUMLEN(qsize);
	nlen = plen + qlen;
	key->size = psize + qsize;
	if ((err = big_init(&(key->p), plen)) != BIG_OK)
		return (err);
	if ((err = big_init(&(key->q), qlen)) != BIG_OK)
		goto ret1;
	if ((err = big_init(&(key->n), nlen)) != BIG_OK)
		goto ret2;
	if ((err = big_init(&(key->d), nlen)) != BIG_OK)
		goto ret3;
	if ((err = big_init(&(key->e), nlen)) != BIG_OK)
		goto ret4;
	if ((err = big_init(&(key->dmodpminus1), plen)) != BIG_OK)
		goto ret5;
	if ((err = big_init(&(key->dmodqminus1), qlen)) != BIG_OK)
		goto ret6;
	if ((err = big_init(&(key->pinvmodq), qlen)) != BIG_OK)
		goto ret7;
	if ((err = big_init(&(key->p_rr), plen)) != BIG_OK)
		goto ret8;
	if ((err = big_init(&(key->q_rr), qlen)) != BIG_OK)
		goto ret9;
	if ((err = big_init(&(key->n_rr), nlen)) != BIG_OK)
		goto ret10;

	return (BIG_OK);

ret10:
	big_finish(&(key->q_rr));
ret9:
	big_finish(&(key->p_rr));
ret8:
	big_finish(&(key->pinvmodq));
ret7:
	big_finish(&(key->dmodqminus1));
ret6:
	big_finish(&(key->dmodpminus1));
ret5:
	big_finish(&(key->e));
ret4:
	big_finish(&(key->d));
ret3:
	big_finish(&(key->n));
ret2:
	big_finish(&(key->q));
ret1:
	big_finish(&(key->p));

	return (err);
}

static void
RSA_key_finish(RSAkey *key)
{
	big_finish(&(key->n_rr));
	big_finish(&(key->q_rr));
	big_finish(&(key->p_rr));
	big_finish(&(key->pinvmodq));
	big_finish(&(key->dmodqminus1));
	big_finish(&(key->dmodpminus1));
	big_finish(&(key->e));
	big_finish(&(key->d));
	big_finish(&(key->n));
	big_finish(&(key->q));
	big_finish(&(key->p));
}

/*
 * Generate RSA key
 */
static CK_RV
generate_rsa_key(RSAkey *key, int psize, int qsize, BIGNUM *pubexp,
    int (*rfunc)(void *, size_t))
{
	CK_RV		rv = CKR_OK;

	int		(*rf)(void *, size_t);
	BIGNUM		a, b, c, d, e, f, g, h;
	int		len, keylen, size;
	BIG_ERR_CODE	brv = BIG_OK;

	size = psize + qsize;
	keylen = BITLEN2BIGNUMLEN(size);
	len = keylen * 2 + 1;
	key->size = size;

	/*
	 * Note: It is not really necessary to compute e, it is in pubexp:
	 * 	(void) big_copy(&(key->e), pubexp);
	 */

	a.malloced = 0;
	b.malloced = 0;
	c.malloced = 0;
	d.malloced = 0;
	e.malloced = 0;
	f.malloced = 0;
	g.malloced = 0;
	h.malloced = 0;

	if ((big_init(&a, len) != BIG_OK) ||
	    (big_init(&b, len) != BIG_OK) ||
	    (big_init(&c, len) != BIG_OK) ||
	    (big_init(&d, len) != BIG_OK) ||
	    (big_init(&e, len) != BIG_OK) ||
	    (big_init(&f, len) != BIG_OK) ||
	    (big_init(&g, len) != BIG_OK) ||
	    (big_init(&h, len) != BIG_OK)) {
		big_finish(&h);
		big_finish(&g);
		big_finish(&f);
		big_finish(&e);
		big_finish(&d);
		big_finish(&c);
		big_finish(&b);
		big_finish(&a);

		return (CKR_HOST_MEMORY);
	}

	rf = rfunc;
	if (rf == NULL) {
#ifdef _KERNEL
		rf = (int (*)(void *, size_t))random_get_pseudo_bytes;
#else
		rf = pkcs11_get_urandom;
#endif
	}

nextp:
	if ((brv = big_random(&a, psize, rf)) != BIG_OK) {
		goto ret;
	}

	if ((brv = big_nextprime_pos(&b, &a)) != BIG_OK) {
		goto ret;
	}
	/* b now contains the potential prime p */

	(void) big_sub_pos(&a, &b, &big_One);
	if ((brv = big_ext_gcd_pos(&f, &d, &g, pubexp, &a)) != BIG_OK) {
		goto ret;
	}
	if (big_cmp_abs(&f, &big_One) != 0) {
		goto nextp;
	}

	if ((brv = big_random(&c, qsize, rf)) != BIG_OK) {
		goto ret;
	}

nextq:
	(void) big_add(&a, &c, &big_Two);

	if (big_bitlength(&a) != qsize) {
		goto nextp;
	}
	if (big_cmp_abs(&a, &b) == 0) {
		goto nextp;
	}
	if ((brv = big_nextprime_pos(&c, &a)) != BIG_OK) {
		goto ret;
	}
	/* c now contains the potential prime q */

	if ((brv = big_mul(&g, &b, &c)) != BIG_OK) {
		goto ret;
	}
	if (big_bitlength(&g) != size) {
		goto nextp;
	}
	/* g now contains the potential modulus n */

	(void) big_sub_pos(&a, &b, &big_One);
	(void) big_sub_pos(&d, &c, &big_One);

	if ((brv = big_mul(&a, &a, &d)) != BIG_OK) {
		goto ret;
	}
	if ((brv = big_ext_gcd_pos(&f, &d, &h, pubexp, &a)) != BIG_OK) {
		goto ret;
	}
	if (big_cmp_abs(&f, &big_One) != 0) {
		goto nextq;
	} else {
		(void) big_copy(&e, pubexp);
	}
	if (d.sign == -1) {
		if ((brv = big_add(&d, &d, &a)) != BIG_OK) {
			goto ret;
		}
	}
	(void) big_copy(&(key->p), &b);
	(void) big_copy(&(key->q), &c);
	(void) big_copy(&(key->n), &g);
	(void) big_copy(&(key->d), &d);
	(void) big_copy(&(key->e), &e);

	if ((brv = big_ext_gcd_pos(&a, &f, &h, &b, &c)) != BIG_OK) {
		goto ret;
	}
	if (f.sign == -1) {
		if ((brv = big_add(&f, &f, &c)) != BIG_OK) {
			goto ret;
		}
	}
	(void) big_copy(&(key->pinvmodq), &f);

	(void) big_sub(&a, &b, &big_One);
	if ((brv = big_div_pos(&a, &f, &d, &a)) != BIG_OK) {
		goto ret;
	}
	(void) big_copy(&(key->dmodpminus1), &f);
	(void) big_sub(&a, &c, &big_One);
	if ((brv = big_div_pos(&a, &f, &d, &a)) != BIG_OK) {
		goto ret;
	}
	(void) big_copy(&(key->dmodqminus1), &f);

	/* pairwise consistency check:  decrypt and encrypt restores value */
	if ((brv = big_random(&h, size, rf)) != BIG_OK) {
		goto ret;
	}
	if ((brv = big_div_pos(&a, &h, &h, &g)) != BIG_OK) {
		goto ret;
	}
	if ((brv = big_modexp(&a, &h, &d, &g, NULL)) != BIG_OK) {
		goto ret;
	}

	if ((brv = big_modexp(&b, &a, &e, &g, NULL)) != BIG_OK) {
		goto ret;
	}

	if (big_cmp_abs(&b, &h) != 0) {
		/* this should not happen */
		rv = generate_rsa_key(key, psize, qsize, pubexp, rf);
		goto ret1;
	} else {
		brv = BIG_OK;
	}

ret:
	rv = convert_rv(brv);
ret1:
	big_finish(&h);
	big_finish(&g);
	big_finish(&f);
	big_finish(&e);
	big_finish(&d);
	big_finish(&c);
	big_finish(&b);
	big_finish(&a);

	return (rv);
}

CK_RV
rsa_genkey_pair(RSAbytekey *bkey)
{
	/*
	 * NOTE:  Whomever originally wrote this function swapped p and q.
	 * This table shows the mapping between name convention used here
	 * versus what is used in most texts that describe RSA key generation.
	 *	This function:			Standard convention:
	 *	--------------			--------------------
	 *	modulus, n			-same-
	 *	prime 1, q			prime 1, p
	 *	prime 2, p			prime 2, q
	 *	private exponent, d		-same-
	 *	public exponent, e		-same-
	 *	exponent 1, d mod (q-1)		d mod (p-1)
	 *	exponent 2, d mod (p-1)		d mod (q-1)
	 *	coefficient, p^-1 mod q		q^-1 mod p
	 *
	 * Also notice the struct member for coefficient is named .pinvmodq
	 * rather than .qinvmodp, reflecting the switch.
	 *
	 * The code here wasn't unswapped, because "it works".  Further,
	 * p and q are interchangeable as long as exponent 1 and 2 and
	 * the coefficient are kept straight too.  This note is here to
	 * make the reader aware of the switcheroo.
	 */
	CK_RV	rv = CKR_OK;

	BIGNUM	public_exponent = {0};
	RSAkey	rsakey;
	uint32_t modulus_bytes;

	if (bkey == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Must have modulus bits set */
	if (bkey->modulus_bits == 0)
		return (CKR_ARGUMENTS_BAD);

	/* Must have public exponent set */
	if (bkey->pubexpo_bytes == 0 || bkey->pubexpo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Note: modulus_bits may not be same as (8 * sizeof (modulus)) */
	modulus_bytes = CRYPTO_BITS2BYTES(bkey->modulus_bits);

	/* Modulus length needs to be between min key size and max key size. */
	if ((modulus_bytes < MIN_RSA_KEYLENGTH_IN_BYTES) ||
	    (modulus_bytes > MAX_RSA_KEYLENGTH_IN_BYTES)) {
		return (CKR_KEY_SIZE_RANGE);
	}

	/*
	 * Initialize the RSA key.
	 */
	if (RSA_key_init(&rsakey, modulus_bytes * 4, modulus_bytes * 4) !=
	    BIG_OK) {
		return (CKR_HOST_MEMORY);
	}

	/* Create a public exponent in bignum format. */
	if (big_init(&public_exponent,
	    CHARLEN2BIGNUMLEN(bkey->pubexpo_bytes)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean1;
	}
	bytestring2bignum(&public_exponent, bkey->pubexpo, bkey->pubexpo_bytes);

	/* Generate RSA key pair. */
	if ((rv = generate_rsa_key(&rsakey,
	    modulus_bytes * 4, modulus_bytes * 4, &public_exponent,
	    bkey->rfunc)) != CKR_OK) {
		big_finish(&public_exponent);
		goto clean1;
	}
	big_finish(&public_exponent);

	/* modulus_bytes = rsakey.n.len * (int)sizeof (BIG_CHUNK_TYPE); */
	bignum2bytestring(bkey->modulus, &(rsakey.n), modulus_bytes);

	bkey->privexpo_bytes = rsakey.d.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(bkey->privexpo, &(rsakey.d), bkey->privexpo_bytes);

	bkey->pubexpo_bytes = rsakey.e.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(bkey->pubexpo, &(rsakey.e), bkey->pubexpo_bytes);

	bkey->prime1_bytes = rsakey.q.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(bkey->prime1, &(rsakey.q), bkey->prime1_bytes);

	bkey->prime2_bytes = rsakey.p.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(bkey->prime2, &(rsakey.p), bkey->prime2_bytes);

	bkey->expo1_bytes =
	    rsakey.dmodqminus1.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(bkey->expo1, &(rsakey.dmodqminus1),
	    bkey->expo1_bytes);

	bkey->expo2_bytes =
	    rsakey.dmodpminus1.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(bkey->expo2,
	    &(rsakey.dmodpminus1), bkey->expo2_bytes);

	bkey->coeff_bytes =
	    rsakey.pinvmodq.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(bkey->coeff, &(rsakey.pinvmodq), bkey->coeff_bytes);

clean1:
	RSA_key_finish(&rsakey);

	return (rv);
}

/*
 * RSA encrypt operation
 */
CK_RV
rsa_encrypt(RSAbytekey *bkey, uchar_t *in, uint32_t in_len, uchar_t *out)
{
	CK_RV rv = CKR_OK;

	BIGNUM msg;
	RSAkey rsakey;
	uint32_t modulus_bytes;

	if (bkey == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Must have modulus and public exponent set */
	if (bkey->modulus_bits == 0 || bkey->modulus == NULL ||
	    bkey->pubexpo_bytes == 0 || bkey->pubexpo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Note: modulus_bits may not be same as (8 * sizeof (modulus)) */
	modulus_bytes = CRYPTO_BITS2BYTES(bkey->modulus_bits);

	if (bkey->pubexpo_bytes > modulus_bytes) {
		return (CKR_KEY_SIZE_RANGE);
	}

	/* psize and qsize for RSA_key_init is in bits. */
	if (RSA_key_init(&rsakey, modulus_bytes * 4, modulus_bytes * 4) !=
	    BIG_OK) {
		return (CKR_HOST_MEMORY);
	}

	/* Size for big_init is in BIG_CHUNK_TYPE words. */
	if (big_init(&msg, CHARLEN2BIGNUMLEN(in_len)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean2;
	}
	bytestring2bignum(&msg, in, in_len);

	/* Convert public exponent and modulus to big integer format. */
	bytestring2bignum(&(rsakey.e), bkey->pubexpo, bkey->pubexpo_bytes);
	bytestring2bignum(&(rsakey.n), bkey->modulus, modulus_bytes);

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
	bignum2bytestring(out, &msg, modulus_bytes);

clean3:
	big_finish(&msg);
clean2:
	RSA_key_finish(&rsakey);

	return (rv);
}

/*
 * RSA decrypt operation
 */
CK_RV
rsa_decrypt(RSAbytekey *bkey, uchar_t *in, uint32_t in_len, uchar_t *out)
{
	CK_RV rv = CKR_OK;

	BIGNUM msg;
	RSAkey rsakey;
	uint32_t modulus_bytes;

	if (bkey == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Must have modulus, prime1, prime2, expo1, expo2, and coeff set */
	if (bkey->modulus_bits == 0 || bkey->modulus == NULL ||
	    bkey->prime1_bytes == 0 || bkey->prime1 == NULL ||
	    bkey->prime2_bytes == 0 || bkey->prime2 == NULL ||
	    bkey->expo1_bytes == 0 || bkey->expo1 == NULL ||
	    bkey->expo2_bytes == 0 || bkey->expo2 == NULL ||
	    bkey->coeff_bytes == 0 || bkey->coeff == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Note: modulus_bits may not be same as (8 * sizeof (modulus)) */
	modulus_bytes = CRYPTO_BITS2BYTES(bkey->modulus_bits);

	/* psize and qsize for RSA_key_init is in bits. */
	if (RSA_key_init(&rsakey, CRYPTO_BYTES2BITS(bkey->prime2_bytes),
	    CRYPTO_BYTES2BITS(bkey->prime1_bytes)) != BIG_OK) {
		return (CKR_HOST_MEMORY);
	}

	/* Size for big_init is in BIG_CHUNK_TYPE words. */
	if (big_init(&msg, CHARLEN2BIGNUMLEN(in_len)) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean3;
	}
	/* Convert octet string input data to big integer format. */
	bytestring2bignum(&msg, in, in_len);

	/* Convert octet string modulus to big integer format. */
	bytestring2bignum(&(rsakey.n), bkey->modulus, modulus_bytes);

	if (big_cmp_abs(&msg, &(rsakey.n)) > 0) {
		rv = CKR_DATA_LEN_RANGE;
		goto clean4;
	}

	/* Convert the rest of private key attributes to big integer format. */
	bytestring2bignum(&(rsakey.q), bkey->prime1, bkey->prime1_bytes);
	bytestring2bignum(&(rsakey.p), bkey->prime2, bkey->prime2_bytes);
	bytestring2bignum(&(rsakey.dmodqminus1),
	    bkey->expo1, bkey->expo1_bytes);
	bytestring2bignum(&(rsakey.dmodpminus1),
	    bkey->expo2, bkey->expo2_bytes);
	bytestring2bignum(&(rsakey.pinvmodq),
	    bkey->coeff, bkey->coeff_bytes);

	if ((big_cmp_abs(&(rsakey.dmodpminus1), &(rsakey.p)) > 0) ||
	    (big_cmp_abs(&(rsakey.dmodqminus1), &(rsakey.q)) > 0) ||
	    (big_cmp_abs(&(rsakey.pinvmodq), &(rsakey.q)) > 0)) {
		rv = CKR_KEY_SIZE_RANGE;
		goto clean4;
	}

	/* Perform RSA computation on big integer input data. */
	if (big_modexp_crt(&msg, &msg, &(rsakey.dmodpminus1),
	    &(rsakey.dmodqminus1), &(rsakey.p), &(rsakey.q),
	    &(rsakey.pinvmodq), NULL, NULL) != BIG_OK) {
		rv = CKR_HOST_MEMORY;
		goto clean4;
	}

	/* Convert the big integer output data to octet string. */
	bignum2bytestring(out, &msg, modulus_bytes);

clean4:
	big_finish(&msg);
clean3:
	RSA_key_finish(&rsakey);

	return (rv);
}

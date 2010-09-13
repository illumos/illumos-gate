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

#ifndef _DSA_IMPL_H
#define	_DSA_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <bignum.h>

/* DSA Signature is always 40 bytes */
#define	DSA_SIGNATURE_LENGTH	40
#define	MIN_DSA_KEY_LEN		(512 >> 3)
#define	MAX_DSA_KEY_LEN		(1024 >> 3)

#define	DSA_SUBPRIME_BITS	160
#define	DSA_SUBPRIME_BYTES	(DSA_SUBPRIME_BITS >> 3)

#ifdef _KERNEL

#include <sys/sunddi.h>
#include <sys/crypto/common.h>

#define	CK_RV			int

#define	CKR_OK			CRYPTO_SUCCESS
#define	CKR_ARGUMENTS_BAD	CRYPTO_ARGUMENTS_BAD
#define	CKR_ATTRIBUTE_VALUE_INVALID	CRYPTO_ATTRIBUTE_VALUE_INVALID
#define	CKR_DEVICE_ERROR	CRYPTO_DEVICE_ERROR
#define	CKR_GENERAL_ERROR	CRYPTO_GENERAL_ERROR
#define	CKR_HOST_MEMORY		CRYPTO_HOST_MEMORY
#define	CKR_KEY_SIZE_RANGE	CRYPTO_KEY_SIZE_RANGE
#define	CKR_SIGNATURE_INVALID	CRYPTO_SIGNATURE_INVALID

int random_get_bytes(uint8_t *ran_out, size_t ran_len);
int random_get_pseudo_bytes(uint8_t *ran_out, size_t ran_len);

#else

#include <security/cryptoki.h>
#include <security/pkcs11t.h>

#endif	/* _KERNEL */


/* DSA key using BIGNUM representations */
typedef struct {
	int 	size;		/* key size in bits */
	BIGNUM	p;		/* p (<size-bit> prime) */
	BIGNUM	q;		/* q (160-bit prime) */
	BIGNUM	g;		/* g (the base) */
	BIGNUM	x;		/* private key (< q) */
	BIGNUM	y;		/* = g^x mod p */
	BIGNUM	k;		/* k (random number < q) */
	BIGNUM	r;		/* r (signature 1st part) */
	BIGNUM	s;		/* s (signature 2st part) */
	BIGNUM	v;		/* v (verification value - should be = r) */
	BIGNUM	p_rr;		/* 2^(2*(32*p->len)) mod p */
	BIGNUM	q_rr;		/* 2^(2*(32*q->len)) mod q */
} DSAkey;

/* DSA key using byte string representations, useful for parameter lists */
typedef struct {
	uint32_t prime_bits;	/* size */
	uchar_t	*prime;		/* p */
	uint32_t subprime_bits;	/* = 160 */
	uchar_t	*subprime;	/* q */
	uint32_t base_bytes;
	uchar_t	*base;		/* g */
	uchar_t	*private_x;	/* x */
	uint32_t private_x_bits;
	uchar_t	*public_y;	/* y */
	uint32_t public_y_bits;
	uchar_t	*signature;	/* concat(r, s) */
	int	(*rfunc)(void *, size_t);	/* random function */
} DSAbytekey;


CK_RV dsa_genkey_pair(DSAbytekey *bkey);

CK_RV dsa_sign(DSAbytekey *bkey, uchar_t *msg, uint32_t msglen, uchar_t *sig);

CK_RV dsa_verify(DSAbytekey *bkey, uchar_t *msg, uchar_t *sig);

#ifdef	__cplusplus
}
#endif

#endif /* _DSA_IMPL_H */

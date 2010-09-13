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

#ifndef _RSA_IMPL_H
#define	_RSA_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <bignum.h>

#define	MIN_RSA_KEYLENGTH_IN_BYTES	32
#define	MAX_RSA_KEYLENGTH_IN_BYTES	512
#define	RSA_MIN_KEY_LEN	256	/* RSA min key length in bits */
#define	RSA_MAX_KEY_LEN	4096	/* RSA max key length in bits */

#ifdef _KERNEL

#include <sys/sunddi.h>
#include <sys/crypto/common.h>

#define	CK_BYTE			uchar_t
#define	CK_ULONG		ulong_t
#define	CK_RV			int

#define	CKR_OK			CRYPTO_SUCCESS
#define	CKR_ARGUMENTS_BAD	CRYPTO_ARGUMENTS_BAD
#define	CKR_DATA_LEN_RANGE	CRYPTO_DATA_LEN_RANGE
#define	CKR_DEVICE_ERROR	CRYPTO_DEVICE_ERROR
#define	CKR_GENERAL_ERROR	CRYPTO_GENERAL_ERROR
#define	CKR_HOST_MEMORY		CRYPTO_HOST_MEMORY
#define	CKR_KEY_SIZE_RANGE	CRYPTO_KEY_SIZE_RANGE

int random_get_bytes(uint8_t *ran_out, size_t ran_len);
int random_get_pseudo_bytes(uint8_t *ran_out, size_t ran_len);

#else

#include <security/cryptoki.h>
#include <security/pkcs11t.h>

#endif	/* _KERNEL */

#define	MD5_DER_PREFIX_Len	18
#define	SHA1_DER_PREFIX_Len	15
#define	SHA1_DER_PREFIX_OID_Len	13
#define	SHA2_DER_PREFIX_Len	19
#define	DEFAULT_PUB_EXPO_Len	3

extern const CK_BYTE MD5_DER_PREFIX[MD5_DER_PREFIX_Len];
extern const CK_BYTE SHA1_DER_PREFIX[SHA1_DER_PREFIX_Len];
extern const CK_BYTE SHA1_DER_PREFIX_OID[SHA1_DER_PREFIX_OID_Len];
extern const CK_BYTE SHA256_DER_PREFIX[SHA2_DER_PREFIX_Len];
extern const CK_BYTE SHA384_DER_PREFIX[SHA2_DER_PREFIX_Len];
extern const CK_BYTE SHA512_DER_PREFIX[SHA2_DER_PREFIX_Len];
extern const CK_BYTE DEFAULT_PUB_EXPO[DEFAULT_PUB_EXPO_Len];


/* RSA key using BIGNUM representations */
typedef struct {
	int 	size;		/* key size in bits */
	BIGNUM	p;		/* p */
	BIGNUM	q;		/* q */
	BIGNUM	n;		/* n = p * q (the modulus) */
	BIGNUM	d;		/* private exponent */
	BIGNUM	e;		/* public exponent */
	BIGNUM	dmodpminus1;	/* d mod (p - 1) (exponent 1) */
	BIGNUM	dmodqminus1;	/* d mod (q - 1) (exponent 2) */
	BIGNUM	pinvmodq;	/* p^(-1) mod q (the coefficient) */
	BIGNUM	p_rr;		/* 2^(2*(32*p->len)) mod p */
	BIGNUM	q_rr;		/* 2^(2*(32*q->len)) mod q */
	BIGNUM	n_rr;		/* 2^(2*(32*n->len)) mod n */
} RSAkey;

/* RSA key using byte string representations, useful for parameter lists */
typedef struct {
	uint32_t modulus_bits;	/* size */
	uchar_t	*modulus;	/* n */
	uint32_t privexpo_bytes;
	uchar_t	*privexpo;	/* d */
	uint32_t pubexpo_bytes;
	uchar_t	*pubexpo;	/* e */
	uint32_t prime1_bytes;
	uchar_t	*prime1;	/* p */
	uint32_t prime2_bytes;
	uchar_t	*prime2;	/* q */
	uint32_t expo1_bytes;
	uchar_t	*expo1;		/* = d mod (p - 1) */
	uint32_t expo2_bytes;
	uchar_t	*expo2;		/* = d mod (q - 1) */
	uint32_t coeff_bytes;	/* = q bytes, .... or = p bytes */
	uchar_t *coeff;		/* = p^(-1) mod q, or = q^(-1) mod p */
	int (*rfunc)(void *, size_t);	/* random function */
} RSAbytekey;


CK_RV rsa_genkey_pair(RSAbytekey *bkey);

CK_RV rsa_encrypt(RSAbytekey *bkey,
    uchar_t *msg, uint32_t msglen, uchar_t *encrmsg);

CK_RV rsa_decrypt(RSAbytekey *bkey,
    uchar_t *encrmsg, uint32_t encrmsglen, uchar_t *msg);

#define	rsa_sign(key, msg, len, sig)	rsa_decrypt((key), (msg), (len), (sig))
#define	rsa_verify(key, msg, len, sig)	rsa_encrypt((key), (msg), (len), (sig))

#ifdef	__cplusplus
}
#endif

#endif /* _RSA_IMPL_H */

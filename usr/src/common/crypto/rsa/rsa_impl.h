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

#define	MIN_PKCS1_PADLEN	11

#ifdef _KERNEL

#include <sys/sunddi.h>
#include <sys/crypto/common.h>

#define	CK_BYTE			uchar_t
#define	CK_ULONG		ulong_t
#define	CK_RV			int
#define	CKR_OK			CRYPTO_SUCCESS
#define	CKR_HOST_MEMORY		CRYPTO_HOST_MEMORY
#define	CKR_DATA_LEN_RANGE	CRYPTO_DATA_LEN_RANGE
#define	CKR_ENCRYPTED_DATA_INVALID	CRYPTO_ENCRYPTED_DATA_INVALID
#define	CKR_SIGNATURE_INVALID	CRYPTO_SIGNATURE_INVALID
#define	CKR_FUNCTION_FAILED	CRYPTO_NOT_SUPPORTED

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

typedef struct {
	int 	size;		/* key size in bits */
	BIGNUM	p;		/* p */
	BIGNUM	q;		/* q */
	BIGNUM	n;		/* n = p * q (the modulus) */
	BIGNUM	d;		/* private exponent */
	BIGNUM	e;		/* public exponent */
	BIGNUM	dmodpminus1;	/* d mod (p - 1) */
	BIGNUM	dmodqminus1;	/* d mod (q - 1) */
	BIGNUM	pinvmodq;	/* p^(-1) mod q */
	BIGNUM	p_rr;		/* 2^(2*(32*p->len)) mod p */
	BIGNUM	q_rr;		/* 2^(2*(32*q->len)) mod q */
	BIGNUM	n_rr;		/* 2^(2*(32*n->len)) mod n */
} RSAkey;

BIG_ERR_CODE RSA_key_init(RSAkey *key, int psize, int qsize);
void RSA_key_finish(RSAkey *key);

CK_RV soft_encrypt_rsa_pkcs_encode(uint8_t *databuf,
    size_t datalen, uint8_t *padbuf, size_t padbuflen);
CK_RV soft_decrypt_rsa_pkcs_decode(uint8_t *padbuf, int *plen);

CK_RV soft_sign_rsa_pkcs_encode(uint8_t *pData, size_t dataLen,
    uint8_t *data, size_t mbit_l);
CK_RV soft_verify_rsa_pkcs_decode(uint8_t *data, int *mbit_l);

#ifdef _KERNEL
int knzero_random_generator(uint8_t *ran_out, size_t ran_len);
void kmemset(uint8_t *buf, char pattern, size_t len);
#endif

/*
 * The following definitions and declarations are only used by RSA FIPS POST
 */
#ifdef _RSA_FIPS_POST

/* RSA FIPS Declarations */
#define	FIPS_RSA_PUBLIC_EXPONENT_LENGTH		  3 /*   24-bits */
#define	FIPS_RSA_PRIVATE_VERSION_LENGTH		  1 /*    8-bits */
#define	FIPS_RSA_MESSAGE_LENGTH			128 /* 1024-bits */
#define	FIPS_RSA_COEFFICIENT_LENGTH		 64 /*  512-bits */
#define	FIPS_RSA_PRIME0_LENGTH			 64 /*  512-bits */
#define	FIPS_RSA_PRIME1_LENGTH			 64 /*  512-bits */
#define	FIPS_RSA_EXPONENT0_LENGTH		 64 /*  512-bits */
#define	FIPS_RSA_EXPONENT1_LENGTH		 64 /*  512-bits */
#define	FIPS_RSA_PRIVATE_EXPONENT_LENGTH	128 /* 1024-bits */
#define	FIPS_RSA_ENCRYPT_LENGTH			128 /* 1024-bits */
#define	FIPS_RSA_DECRYPT_LENGTH			128 /* 1024-bits */
#define	FIPS_RSA_SIGNATURE_LENGTH		128 /* 1024-bits */
#define	FIPS_RSA_MODULUS_LENGTH			128 /* 1024-bits */
#define	MAX_KEY_ATTR_BUFLEN			1024

typedef struct RSAPrivateKey_s {
	uint8_t		*version;
	int		version_len;
	uint8_t		*modulus;
	int		modulus_len;
	uint8_t		*public_expo;
	int		public_expo_len;
	uint8_t		*private_expo;
	int		private_expo_len;
	uint8_t		*prime1;
	int		prime1_len;
	uint8_t		*prime2;
	int		prime2_len;
	uint8_t		*exponent1;
	int		exponent1_len;
	uint8_t		*exponent2;
	int		exponent2_len;
	uint8_t		*coef;
	int		coef_len;
} RSAPrivateKey_t;

/* RSA FIPS functions */
extern int fips_rsa_post(void);
extern int fips_rsa_encrypt(uint8_t *, int, uint8_t *,
	int, uint8_t *, int, uint8_t *);
extern int fips_rsa_decrypt(RSAPrivateKey_t *, uint8_t *,
	int, uint8_t *);
extern int fips_rsa_sign(RSAPrivateKey_t *, uint8_t *,
	uint32_t, uint8_t *);
extern int fips_rsa_verify(RSAPrivateKey_t *, uint8_t *, uint32_t,
	uint8_t *);

#endif /* _RSA_FIPS_POST */

#ifdef	__cplusplus
}
#endif

#endif /* _RSA_IMPL_H */

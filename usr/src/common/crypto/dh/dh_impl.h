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

#ifndef _DH_IMPL_H
#define	_DH_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <bignum.h>

#define	MIN_DH_KEYLENGTH_IN_BYTES	8
#define	MAX_DH_KEYLENGTH_IN_BYTES	512
#define	DH_MIN_KEY_LEN		64
#define	DH_MAX_KEY_LEN		4096

#ifdef _KERNEL

#include <sys/sunddi.h>
#include <sys/crypto/common.h>

#define	CK_RV			ulong_t

#define	CKR_OK			CRYPTO_SUCCESS
#define	CKR_ARGUMENTS_BAD	CRYPTO_ARGUMENTS_BAD
#define	CKR_ATTRIBUTE_TYPE_INVALID	CRYPTO_ATTRIBUTE_TYPE_INVALID
#define	CKR_ATTRIBUTE_VALUE_INVALID	CRYPTO_ATTRIBUTE_VALUE_INVALID
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


/* DH key using BIGNUM representations */
typedef struct {
	int 	size;		/* key size in bits */
	BIGNUM	p;		/* p (prime) */
	BIGNUM	g;		/* g (base) */
	BIGNUM	x;		/* private value (random) */
	BIGNUM	y;		/* public value (= g^x mod p) */
} DHkey;

/* DH key using byte string representations, useful for parameter lists */
typedef struct {
	uint32_t prime_bits;	/* size */
	uchar_t	*prime;		/* p */
	uint32_t base_bytes;
	uchar_t *base;		/* g */
	uint32_t value_bits;	/* for both x and y */
	uchar_t	*private_x;	/* x */
	uchar_t *public_y;	/* y */
	int	(*rfunc)(void *, size_t);	/* random function */
} DHbytekey;


CK_RV dh_genkey_pair(DHbytekey *bkey);

CK_RV dh_key_derive(DHbytekey *bkey, uint32_t key_type,
    uchar_t *secretkey, uint32_t *secretkey_len, int flag);

#ifdef	__cplusplus
}
#endif

#endif /* _DH_IMPL_H */

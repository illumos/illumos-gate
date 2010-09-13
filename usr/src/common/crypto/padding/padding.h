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

#ifndef _PADDING_H
#define	_PADDING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	MIN_PKCS1_PADLEN	11

/*
 * Values for PKCS#1 method of encoding/decoding.
 */
#define	PKCS1_ENCRYPT		0x02
#define	PKCS1_DECRYPT		0x02
#define	PKCS1_SIGN		0x01
#define	PKCS1_VERIFY		0x01

#ifdef _KERNEL

#include <sys/sunddi.h>
#include <sys/crypto/common.h>

#define	CK_BYTE			uchar_t
#define	CK_ULONG		ulong_t

#define	CKR_DATA_LEN_RANGE	CRYPTO_DATA_LEN_RANGE
#define	CKR_DEVICE_ERROR	CRYPTO_DEVICE_ERROR
#define	CKR_ENCRYPTED_DATA_INVALID	CRYPTO_ENCRYPTED_DATA_INVALID
#define	CKR_SIGNATURE_INVALID	CRYPTO_SIGNATURE_INVALID

int knzero_random_generator(uint8_t *ran_out, size_t ran_len);
void kmemset(uint8_t *buf, char pattern, size_t len);

#else

#include <security/cryptoki.h>
#include <security/pkcs11t.h>

#endif	/* _KERNEL */

int pkcs1_encode(int method, uint8_t *databuf, size_t datalen, uint8_t *padbuf,
    size_t padbuflen);
int pkcs1_decode(int method, uint8_t *padbuf, size_t *plen);

int pkcs7_encode(uint8_t *databuf, size_t datalen, uint8_t *padbuf,
    size_t padbuflen, uint8_t multiple);
int pkcs7_decode(uint8_t *padbuf, size_t *plen);

#ifdef	__cplusplus
}
#endif

#endif /* _PADDING_H */

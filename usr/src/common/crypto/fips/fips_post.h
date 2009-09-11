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

#ifndef	_FIPS_POST_H
#define	_FIPS_POST_H

#ifdef __cplusplus
extern "C" {
#endif

#define	FIPS_KNOWN_HMAC_MESSAGE_LENGTH	64	/* 512-bits */

#ifdef _KERNEL

#define	CK_BYTE				uchar_t
#define	CK_ULONG			ulong_t
#define	CK_RV				int
#define	CKR_OK				CRYPTO_SUCCESS
#define	CKR_HOST_MEMORY			CRYPTO_HOST_MEMORY
#define	CKR_DEVICE_ERROR		CRYPTO_DEVICE_ERROR
#define	CKR_DATA_LEN_RANGE		CRYPTO_DATA_LEN_RANGE
#define	CKR_ENCRYPTED_DATA_LEN_RANGE	CRYPTO_ENCRYPTED_DATA_LEN_RANGE
#define	CKR_ENCRYPTED_DATA_INVALID	CRYPTO_ENCRYPTED_DATA_INVALID
#define	CKR_SIGNATURE_INVALID		CRYPTO_SIGNATURE_INVALID
#define	CKR_ARGUMENTS_BAD		CRYPTO_ARGUMENTS_BAD

#else

#define	FIPS_RNG_XKEY_LENGTH		32	/* 256-bits */
#define	PAIRWISE_DIGEST_LENGTH		20	/* 160-bits */
#define	PAIRWISE_MESSAGE_LENGTH		20	/* 160-bits */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _FIPS_POST_H */

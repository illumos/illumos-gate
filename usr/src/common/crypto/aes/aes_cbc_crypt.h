/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AES_CBC_CRYPT_H
#define	_AES_CBC_CRYPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/crypto/common.h>
#include "aes_impl.h"

/*
 * ac_keysched:		Pointer to key schedule.
 *
 * ac_keysched_len:	Length of the key schedule.
 *
 * ac_remainder:	This is for residual data, i.e. data that can't
 *			be processed because there are too few bytes.
 *			Must wait until more data arrives.
 *
 * ac_remainder_len:	Number of bytes in ac_remainder.
 *
 * ac_iv:		Scratch buffer that sometimes contains the IV.
 *
 * ac_lastblock:	Scratch buffer.
 *
 * ac_lastp:		Pointer to previous block of ciphertext.
 *
 * ac_copy_to:		Pointer to where encrypted residual data needs
 *			to be copied.
 *
 * ac_flags:		AES_PROVIDER_OWNS_KEY_SCHEDULE
 *			When a context is freed, it is necessary
 *			to know whether the key schedule was allocated
 *			by the caller, or by aes_encrypt_init() or
 *			aes_decrypt_init().  If allocated by the latter,
 *			then it needs to be freed.
 *
 *			AES_ECB_MODE, AES_CBC_MODE, or AES_CTR_MODE
 */
typedef struct aes_ctx {
	void *ac_keysched;
	size_t ac_keysched_len;
	uint64_t ac_iv[2];
	uint64_t ac_lastblock[2];
	uint64_t ac_remainder[2];
	size_t ac_remainder_len;
	uint8_t *ac_lastp;
	uint8_t *ac_copy_to;
	uint32_t ac_flags;
} aes_ctx_t;

/*
 * ac_cb		Counter block.
 *
 * ac_counter_mask	Mask of counter bits in the last 8 bytes of the
 * 			counter block.
 */
#define	ac_cb		ac_iv
#define	ac_counter_mask	ac_lastblock[0]

#define	AES_PROVIDER_OWNS_KEY_SCHEDULE	0x00000001
#define	AES_ECB_MODE			0x00000002
#define	AES_CBC_MODE			0x00000004
#define	AES_CTR_MODE			0x00000008

/* CK_AES_CTR_PARAMS provides parameters to the CKM_AES_CTR mechanism */
typedef struct CK_AES_CTR_PARAMS {
	ulong_t	ulCounterBits;
	uchar_t *cb;
} CK_AES_CTR_PARAMS;

#ifdef _KERNEL
/* needed for 32-bit applications running on 64-bit kernels */
typedef struct CK_AES_CTR_PARAMS32 {
	uint32_t ulCounterBits;
	caddr32_t cb;
} CK_AES_CTR_PARAMS32;
#endif /* _KERNEL */

extern int aes_encrypt_contiguous_blocks(aes_ctx_t *, char *, size_t,
    crypto_data_t *);
extern int aes_decrypt_contiguous_blocks(aes_ctx_t *, char *, size_t,
    crypto_data_t *);
extern int aes_counter_final(aes_ctx_t *, crypto_data_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _AES_CBC_CRYPT_H */

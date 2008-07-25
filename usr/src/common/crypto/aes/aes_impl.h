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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AES_IMPL_H
#define	_AES_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common definitions used by AES.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/crypto/common.h>

/* Similar to sysmacros.h IS_P2ALIGNED, but checks two pointers: */
#define	IS_P2ALIGNED2(v, w, a) \
	((((uintptr_t)(v) | (uintptr_t)(w)) & ((uintptr_t)(a) - 1)) == 0)

#define	AES_BLOCK_LEN	16	/* bytes */
/* Round constant length, in number of 32-bit elements: */
#define	RC_LENGTH	(5 * ((AES_BLOCK_LEN) / 4 - 2))

#define	AES_COPY_BLOCK(src, dst) \
	(dst)[0] = (src)[0]; \
	(dst)[1] = (src)[1]; \
	(dst)[2] = (src)[2]; \
	(dst)[3] = (src)[3]; \
	(dst)[4] = (src)[4]; \
	(dst)[5] = (src)[5]; \
	(dst)[6] = (src)[6]; \
	(dst)[7] = (src)[7]; \
	(dst)[8] = (src)[8]; \
	(dst)[9] = (src)[9]; \
	(dst)[10] = (src)[10]; \
	(dst)[11] = (src)[11]; \
	(dst)[12] = (src)[12]; \
	(dst)[13] = (src)[13]; \
	(dst)[14] = (src)[14]; \
	(dst)[15] = (src)[15]

#define	AES_XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]; \
	(dst)[8] ^= (src)[8]; \
	(dst)[9] ^= (src)[9]; \
	(dst)[10] ^= (src)[10]; \
	(dst)[11] ^= (src)[11]; \
	(dst)[12] ^= (src)[12]; \
	(dst)[13] ^= (src)[13]; \
	(dst)[14] ^= (src)[14]; \
	(dst)[15] ^= (src)[15]

/* AES key size definitions */
#define	AES_MINBITS		128
#define	AES_MINBYTES		((AES_MINBITS) >> 3)
#define	AES_MAXBITS		256
#define	AES_MAXBYTES		((AES_MAXBITS) >> 3)

#define	AES_MIN_KEY_BYTES	((AES_MINBITS) >> 3)
#define	AES_MAX_KEY_BYTES	((AES_MAXBITS) >> 3)
#define	AES_192_KEY_BYTES	24
#define	AES_IV_LEN		16

/* AES key schedule may be implemented with 32- or 64-bit elements: */
#define	AES_32BIT_KS		32
#define	AES_64BIT_KS		64

#define	MAX_AES_NR		14 /* Maximum number of rounds */
#define	MAX_AES_NB		4  /* Number of columns comprising a state */

typedef union {
#ifdef	sun4u
	uint64_t	ks64[((MAX_AES_NR) + 1) * (MAX_AES_NB)];
#endif
	uint32_t	ks32[((MAX_AES_NR) + 1) * (MAX_AES_NB)];
} aes_ks_t;

typedef struct aes_key aes_key_t;
struct aes_key {
	int		nr;
	int		type;
	aes_ks_t	encr_ks;
	aes_ks_t	decr_ks;
};

extern int aes_encrypt_contiguous_blocks(void *, char *, size_t,
    crypto_data_t *);
extern int aes_decrypt_contiguous_blocks(void *, char *, size_t,
    crypto_data_t *);
extern int aes_encrypt_block(const void *ks, const uint8_t *pt, uint8_t *ct);
extern int aes_decrypt_block(const void *ks, const uint8_t *ct, uint8_t *pt);
extern void aes_init_keysched(const uint8_t *cipherKey, uint_t keyBits,
	void *keysched);
extern void *aes_alloc_keysched(size_t *size, int kmflag);
extern void aes_copy_block(uint8_t *, uint8_t *);
extern void aes_xor_block(uint8_t *, uint8_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _AES_IMPL_H */

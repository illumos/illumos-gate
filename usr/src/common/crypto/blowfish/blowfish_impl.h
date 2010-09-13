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

#ifndef	_BLOWFISH_IMPL_H
#define	_BLOWFISH_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common definitions used by Blowfish.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	BLOWFISH_COPY_BLOCK(src, dst) \
	(dst)[0] = (src)[0]; \
	(dst)[1] = (src)[1]; \
	(dst)[2] = (src)[2]; \
	(dst)[3] = (src)[3]; \
	(dst)[4] = (src)[4]; \
	(dst)[5] = (src)[5]; \
	(dst)[6] = (src)[6]; \
	(dst)[7] = (src)[7]

#define	BLOWFISH_XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]

#define	BLOWFISH_MINBITS	32
#define	BLOWFISH_MINBYTES	(BLOWFISH_MINBITS >> 3)
#define	BLOWFISH_MAXBITS	448
#define	BLOWFISH_MAXBYTES	(BLOWFISH_MAXBITS >> 3)

#define	BLOWFISH_IV_LEN		8
#define	BLOWFISH_BLOCK_LEN	8
#define	BLOWFISH_KEY_INCREMENT	8
#define	BLOWFISH_DEFAULT	128

extern int blowfish_encrypt_contiguous_blocks(void *, char *, size_t,
    crypto_data_t *);
extern int blowfish_decrypt_contiguous_blocks(void *, char *, size_t,
    crypto_data_t *);
extern int blowfish_encrypt_block(const void *, const uint8_t *, uint8_t *);
extern int blowfish_decrypt_block(const void *, const uint8_t *, uint8_t *);
extern void blowfish_init_keysched(uint8_t *, uint_t, void *);
extern void *blowfish_alloc_keysched(size_t *, int);
extern void blowfish_copy_block(uint8_t *, uint8_t *);
extern void blowfish_xor_block(uint8_t *, uint8_t *);
#ifdef	__cplusplus
}
#endif

#endif	/* _BLOWFISH_IMPL_H */

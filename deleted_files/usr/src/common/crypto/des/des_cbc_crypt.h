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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DES_CBC_CRYPT_H
#define	_DES_CBC_CRYPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "sys/crypto/common.h"
#include "des_impl.h"

/*
 * dc_keysched:		Pointer to key schedule.
 *
 * dc_keysched_len:	Length of the key schedule.
 *
 * dc_remainder:	This is for residual data, i.e. data that can't
 *			be processed because there are too few bytes.
 *			Must wait until more data arrives.
 *
 * dc_remainder_len:	Number of bytes in dc_remainder.
 *
 * dc_iv:		Scratch buffer that sometimes contains the IV.
 *
 * dc_lastblock:	Scratch buffer.
 *
 * dc_lastp:		Pointer to previous block of ciphertext.
 *
 * dc_copy_to:		Pointer to where encrypted residual data needs
 *			to be copied.
 *
 * dc_flags:		DES_PROVIDER_OWNS_KEY_SCHEDULE
 *			When a context is freed, it is necessary
 *			to know whether the key schedule was allocated
 *			by the caller, or by des_encrypt_init() or
 *			des_decrypt_init().  If allocated by the latter,
 *			then it needs to be freed.
 *
 *			DES_CBC_MODE
 *			If flag is not set, the mode is DES_ECB_MODE.
 *
 *			DES3_STRENGTH
 *			If flag is not set, then it's regular DES.
 *
 */
typedef struct des_ctx {
	void *dc_keysched;
	size_t dc_keysched_len;
	uint64_t dc_iv;
	uint64_t dc_lastblock;
	uint64_t dc_remainder;
	size_t dc_remainder_len;
	uint8_t *dc_lastp;
	uint8_t *dc_copy_to;
	uint32_t dc_flags;
} des_ctx_t;

#define	DES_PROVIDER_OWNS_KEY_SCHEDULE	0x00000001
#define	DES_CBC_MODE			0x00000002
#define	DES3_STRENGTH			0x00000004

extern int des_encrypt_contiguous_blocks(des_ctx_t *, char *, size_t,
    crypto_data_t *);
extern int des_decrypt_contiguous_blocks(des_ctx_t *, char *, size_t,
    crypto_data_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DES_CBC_CRYPT_H */

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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#if defined(_KERNEL) && !defined(_BOOT)
#include <sys/systm.h>
#else
#include <strings.h>
#endif
#include "cbc.h"

#define	CBC_MAX_BLOCK_SIZE	64

static void
cbc_xorblock(uint8_t *lastp, uint8_t *thisp, int blocksize)
{
	uint32_t *this32p;
	uint32_t *last32p;
	int i;

	if (IS_P2ALIGNED(thisp, sizeof (uint32_t)) &&
	    IS_P2ALIGNED(lastp, sizeof (uint32_t)) &&
	    IS_P2ALIGNED(blocksize, sizeof (uint32_t))) {
		/* LINTED */
		this32p = (uint32_t *)thisp;
		/* LINTED */
		last32p = (uint32_t *)lastp;
		for (i = 0; i < blocksize; i += 4) {
			*this32p ^= *last32p;
			this32p++;
			last32p++;
		}
	} else {
		for (i = 0; i < blocksize; i++) {
			thisp[i] ^= lastp[i];
		}
	}
}

boolean_t
cbc_encrypt(cbc_handle_t *ch, uint8_t *data, size_t datalen,
	uint8_t *IV)
{
	uint8_t *lastp;
	uint8_t *thisp;
	size_t i;

	if (!IS_P2ALIGNED(datalen, ch->blocklen)) {
		return (B_FALSE);
	}

	thisp = data;
	lastp = IV;

	for (i = 0; i < datalen; i += ch->blocklen) {
		cbc_xorblock(lastp, thisp, ch->blocklen);
		/* Encrypt the current block. */
		ch->encrypt(ch->ks, thisp);
		lastp = thisp;
		thisp += ch->blocklen;
	}

	bcopy(lastp, IV, ch->blocklen);
	return (B_TRUE);
}

boolean_t
cbc_decrypt(cbc_handle_t *ch, uint8_t *data, size_t datalen,
	uint8_t *IV)
{
	uint8_t cbcblock[CBC_MAX_BLOCK_SIZE];
	uint8_t *lastp;
	uint8_t *thisp;
	size_t i;

	if (!IS_P2ALIGNED(datalen, ch->blocklen)) {
		return (B_FALSE);
	}

	thisp = data;
	lastp = IV;

	for (i = 0; i < datalen; i += ch->blocklen) {

		/* Copy the current ciphertext block. */
		bcopy(thisp, cbcblock, ch->blocklen);

		/* Decrypt the current block. */
		ch->decrypt(ch->ks, thisp);

		cbc_xorblock(lastp, thisp, ch->blocklen);

		/* Save the last ciphertext block. */
		bcopy(cbcblock, lastp, ch->blocklen);
		thisp += ch->blocklen;
	}

	return (B_TRUE);
}

void
cbc_makehandle(cbc_handle_t *ch, void *cookie, uint32_t keysize,
	uint32_t blocksize, uint32_t ivsize,
	void (*encrypt)(void *, uint8_t *),
	void (*decrypt)(void *, uint8_t *))
{
	ch->ks = cookie;
	ch->keylen = keysize;
	ch->blocklen = blocksize;
	ch->ivlen = ivsize;
	ch->encrypt = encrypt;
	ch->decrypt = decrypt;
}

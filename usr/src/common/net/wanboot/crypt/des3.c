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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <strings.h>
#include <sys/sysmacros.h>

#include "des3.h"
#include "des.h"

typedef struct keysched_s {
	uint32_t ksch_encrypt1[16][2];
	uint32_t ksch_encrypt2[16][2];
	uint32_t ksch_encrypt3[16][2];

	uint32_t ksch_decrypt1[16][2];
	uint32_t ksch_decrypt2[16][2];
	uint32_t ksch_decrypt3[16][2];
} keysched_t;

int
des3_init(void **cookie)
{
	if ((*cookie = malloc(sizeof (keysched_t))) == NULL) {
		return (-1);
	}
	return (0);
}

void
des3_fini(void *cookie)
{
	free(cookie);
}

void
des3_encrypt(void *cookie, uint8_t *block)
{
	keysched_t *ksch = (keysched_t *)cookie;

	des(ksch->ksch_encrypt1, block);
	des(ksch->ksch_decrypt2, block);
	des(ksch->ksch_encrypt3, block);
}

void
des3_decrypt(void *cookie, uint8_t *block)
{
	keysched_t *ksch = (keysched_t *)cookie;

	des(ksch->ksch_decrypt3, block);
	des(ksch->ksch_encrypt2, block);
	des(ksch->ksch_decrypt1, block);
}

/*
 * Generate key schedule for triple DES in E-D-E (or D-E-D) mode.
 *
 * The key argument is taken to be 24 bytes. The first 8 bytes are K1
 * for the first stage, the second 8 bytes are K2 for the middle stage
 * and the third 8 bytes are K3 for the last stage
 */
void
des3_key(void *cookie, const uint8_t *key)
{
	keysched_t *ks = (keysched_t *)cookie;
	uint8_t *k1 = (uint8_t *)key;
	uint8_t *k2 = k1 + DES_KEY_SIZE;
	uint8_t *k3 = k2 + DES_KEY_SIZE;

	des_key(ks->ksch_decrypt1, k1, B_TRUE);
	des_key(ks->ksch_encrypt1, k1, B_FALSE);
	des_key(ks->ksch_decrypt2, k2, B_TRUE);
	des_key(ks->ksch_encrypt2, k2, B_FALSE);
	des_key(ks->ksch_decrypt3, k3, B_TRUE);
	des_key(ks->ksch_encrypt3, k3, B_FALSE);
}


boolean_t
des3_keycheck(const uint8_t *key)
{
	uint64_t key_so_far;
	uint64_t scratch;
	uint64_t *currentkey;
	uint64_t tmpbuf[3];
	uint_t parity;
	uint_t num_weakkeys = 0;
	uint_t i;
	uint_t j;

	/*
	 * Table of weak and semi-weak keys.  Fortunately, weak keys are
	 * endian-independent, and some semi-weak keys can be paired up in
	 * endian-opposite order.  Since keys are stored as uint64_t's,
	 * use the ifdef _LITTLE_ENDIAN where appropriate.
	 */
	static uint64_t des_weak_keys[] = {
		/* Really weak keys.  Byte-order independent values. */
		0x0101010101010101ULL,
		0x1f1f1f1f0e0e0e0eULL,
		0xe0e0e0e0f1f1f1f1ULL,
		0xfefefefefefefefeULL,

		/* Semi-weak (and a few possibly-weak) keys. */

		/* Byte-order independent semi-weak keys. */
		0x01fe01fe01fe01feULL,	0xfe01fe01fe01fe01ULL,

		/* Byte-order dependent semi-weak keys. */
#ifdef _LITTLE_ENDIAN
		0xf10ef10ee01fe01fULL,	0x0ef10ef11fe01fe0ULL,
		0x01f101f101e001e0ULL,	0xf101f101e001e001ULL,
		0x0efe0efe1ffe1ffeULL,	0xfe0efe0efe1ffe1fULL,
		0x010e010e011f011fULL,	0x0e010e011f011f01ULL,
		0xf1fef1fee0fee0feULL,	0xfef1fef1fee0fee0ULL,
#else	/* Big endian */
		0x1fe01fe00ef10ef1ULL,	0xe01fe01ff10ef10eULL,
		0x01e001e001f101f1ULL,	0xe001e001f101f101ULL,
		0x1ffe1ffe0efe0efeULL,	0xfe1ffe1ffe0efe0eULL,
		0x011f011f010e010eULL,	0x1f011f010e010e01ULL,
		0xe0fee0fef1fef1feULL,	0xfee0fee0fef1fef1ULL,
#endif

		/* We'll save the other possibly-weak keys for the future. */
	};

	if (IS_P2ALIGNED(key, sizeof (uint64_t))) {
		/* LINTED */
		currentkey = (uint64_t *)key;
	} else {
		currentkey = tmpbuf;
		bcopy(key, currentkey, 3 * sizeof (uint64_t));
	}

	for (j = 0; j < 3; j++) {
		key_so_far = currentkey[j];
		scratch = key_so_far;

		/* Unroll the loop within each byte. */
		for (i = 0; i < 8; i++) {
			parity = 1;

			/*
			 * Start shifting at byte n, right to left.
			 * Low bit (0) doesn't count.
			 */
			scratch >>= 1;
			if (scratch & 0x1)	/* bit 1 */
				parity++;
			scratch >>= 1;
			if (scratch & 0x1)	/* bit 2 */
				parity++;
			scratch >>= 1;
			if (scratch & 0x1)	/* bit 3 */
				parity++;
			scratch >>= 1;
			if (scratch & 0x1)	/* bit 4 */
				parity++;
			scratch >>= 1;
			if (scratch & 0x1)	/* bit 5 */
				parity++;
			scratch >>= 1;
			if (scratch & 0x1)	/* bit 6 */
			parity++;
			scratch >>= 1;
			if (scratch & 0x1)	/* bit 7 */
				parity++;
			scratch >>= 1;

			parity &= 1;	/* Mask off other bits. */

			/* Will common subexpression elimination help me? */
			key_so_far &= ~((uint64_t)1 << (i << 3));
			key_so_far |= ((uint64_t)parity << (i << 3));
		}

		/* Do weak key check itself. */
		for (i = 0; i < (sizeof (des_weak_keys) / sizeof (uint64_t));
		    i++) {
			if (key_so_far == des_weak_keys[i]) {
				/* In 3DES, one weak key is OK.  Two is bad. */
				if (++num_weakkeys > 1) {
					return (B_FALSE);
				} else {
					/*
					 * We found a weak key, but since
					 * we've only found one weak key,
					 * we can not reject the whole 3DES
					 * set of keys as weak.
					 *
					 * Break from the weak key loop
					 * (since this DES key is weak) and
					 * continue on.
					 */
					break;
				}
			}
		}

		/*
		 * Fix key extension, adjust bits if necessary.
		 */
		currentkey[j] = key_so_far;
	}

	/*
	 * Perform key equivalence checks, now that parity is properly set.
	 * All three keys must be unique.
	 */
	if (currentkey[0] == currentkey[1] || currentkey[1] == currentkey[2] ||
	    currentkey[2] == currentkey[0]) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

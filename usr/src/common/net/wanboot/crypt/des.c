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

/*
 * Portable C version of des() and des_key() functions.
 * This version is very similar to that in Part V of Applied Cryptography
 * by Bruce Schneier.
 *
 * This information is in the public domain 12/15/95 P. Karn
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#if defined(_KERNEL) && !defined(_BOOT)
#include <sys/systm.h>
#else
#include <strings.h>
#endif

#include "des.h"

/*
 * Combined SP lookup table, linked in
 * For best results, ensure that this is aligned on a 32-bit boundary;
 */
static uint32_t Spbox[8][64] = {
	0x01010400U, 0x00000000U, 0x00010000U, 0x01010404U,
	0x01010004U, 0x00010404U, 0x00000004U, 0x00010000U,
	0x00000400U, 0x01010400U, 0x01010404U, 0x00000400U,
	0x01000404U, 0x01010004U, 0x01000000U, 0x00000004U,
	0x00000404U, 0x01000400U, 0x01000400U, 0x00010400U,
	0x00010400U, 0x01010000U, 0x01010000U, 0x01000404U,
	0x00010004U, 0x01000004U, 0x01000004U, 0x00010004U,
	0x00000000U, 0x00000404U, 0x00010404U, 0x01000000U,
	0x00010000U, 0x01010404U, 0x00000004U, 0x01010000U,
	0x01010400U, 0x01000000U, 0x01000000U, 0x00000400U,
	0x01010004U, 0x00010000U, 0x00010400U, 0x01000004U,
	0x00000400U, 0x00000004U, 0x01000404U, 0x00010404U,
	0x01010404U, 0x00010004U, 0x01010000U, 0x01000404U,
	0x01000004U, 0x00000404U, 0x00010404U, 0x01010400U,
	0x00000404U, 0x01000400U, 0x01000400U, 0x00000000U,
	0x00010004U, 0x00010400U, 0x00000000U, 0x01010004U,
	0x80108020U, 0x80008000U, 0x00008000U, 0x00108020U,
	0x00100000U, 0x00000020U, 0x80100020U, 0x80008020U,
	0x80000020U, 0x80108020U, 0x80108000U, 0x80000000U,
	0x80008000U, 0x00100000U, 0x00000020U, 0x80100020U,
	0x00108000U, 0x00100020U, 0x80008020U, 0x00000000U,
	0x80000000U, 0x00008000U, 0x00108020U, 0x80100000U,
	0x00100020U, 0x80000020U, 0x00000000U, 0x00108000U,
	0x00008020U, 0x80108000U, 0x80100000U, 0x00008020U,
	0x00000000U, 0x00108020U, 0x80100020U, 0x00100000U,
	0x80008020U, 0x80100000U, 0x80108000U, 0x00008000U,
	0x80100000U, 0x80008000U, 0x00000020U, 0x80108020U,
	0x00108020U, 0x00000020U, 0x00008000U, 0x80000000U,
	0x00008020U, 0x80108000U, 0x00100000U, 0x80000020U,
	0x00100020U, 0x80008020U, 0x80000020U, 0x00100020U,
	0x00108000U, 0x00000000U, 0x80008000U, 0x00008020U,
	0x80000000U, 0x80100020U, 0x80108020U, 0x00108000U,
	0x00000208U, 0x08020200U, 0x00000000U, 0x08020008U,
	0x08000200U, 0x00000000U, 0x00020208U, 0x08000200U,
	0x00020008U, 0x08000008U, 0x08000008U, 0x00020000U,
	0x08020208U, 0x00020008U, 0x08020000U, 0x00000208U,
	0x08000000U, 0x00000008U, 0x08020200U, 0x00000200U,
	0x00020200U, 0x08020000U, 0x08020008U, 0x00020208U,
	0x08000208U, 0x00020200U, 0x00020000U, 0x08000208U,
	0x00000008U, 0x08020208U, 0x00000200U, 0x08000000U,
	0x08020200U, 0x08000000U, 0x00020008U, 0x00000208U,
	0x00020000U, 0x08020200U, 0x08000200U, 0x00000000U,
	0x00000200U, 0x00020008U, 0x08020208U, 0x08000200U,
	0x08000008U, 0x00000200U, 0x00000000U, 0x08020008U,
	0x08000208U, 0x00020000U, 0x08000000U, 0x08020208U,
	0x00000008U, 0x00020208U, 0x00020200U, 0x08000008U,
	0x08020000U, 0x08000208U, 0x00000208U, 0x08020000U,
	0x00020208U, 0x00000008U, 0x08020008U, 0x00020200U,
	0x00802001U, 0x00002081U, 0x00002081U, 0x00000080U,
	0x00802080U, 0x00800081U, 0x00800001U, 0x00002001U,
	0x00000000U, 0x00802000U, 0x00802000U, 0x00802081U,
	0x00000081U, 0x00000000U, 0x00800080U, 0x00800001U,
	0x00000001U, 0x00002000U, 0x00800000U, 0x00802001U,
	0x00000080U, 0x00800000U, 0x00002001U, 0x00002080U,
	0x00800081U, 0x00000001U, 0x00002080U, 0x00800080U,
	0x00002000U, 0x00802080U, 0x00802081U, 0x00000081U,
	0x00800080U, 0x00800001U, 0x00802000U, 0x00802081U,
	0x00000081U, 0x00000000U, 0x00000000U, 0x00802000U,
	0x00002080U, 0x00800080U, 0x00800081U, 0x00000001U,
	0x00802001U, 0x00002081U, 0x00002081U, 0x00000080U,
	0x00802081U, 0x00000081U, 0x00000001U, 0x00002000U,
	0x00800001U, 0x00002001U, 0x00802080U, 0x00800081U,
	0x00002001U, 0x00002080U, 0x00800000U, 0x00802001U,
	0x00000080U, 0x00800000U, 0x00002000U, 0x00802080U,
	0x00000100U, 0x02080100U, 0x02080000U, 0x42000100U,
	0x00080000U, 0x00000100U, 0x40000000U, 0x02080000U,
	0x40080100U, 0x00080000U, 0x02000100U, 0x40080100U,
	0x42000100U, 0x42080000U, 0x00080100U, 0x40000000U,
	0x02000000U, 0x40080000U, 0x40080000U, 0x00000000U,
	0x40000100U, 0x42080100U, 0x42080100U, 0x02000100U,
	0x42080000U, 0x40000100U, 0x00000000U, 0x42000000U,
	0x02080100U, 0x02000000U, 0x42000000U, 0x00080100U,
	0x00080000U, 0x42000100U, 0x00000100U, 0x02000000U,
	0x40000000U, 0x02080000U, 0x42000100U, 0x40080100U,
	0x02000100U, 0x40000000U, 0x42080000U, 0x02080100U,
	0x40080100U, 0x00000100U, 0x02000000U, 0x42080000U,
	0x42080100U, 0x00080100U, 0x42000000U, 0x42080100U,
	0x02080000U, 0x00000000U, 0x40080000U, 0x42000000U,
	0x00080100U, 0x02000100U, 0x40000100U, 0x00080000U,
	0x00000000U, 0x40080000U, 0x02080100U, 0x40000100U,
	0x20000010U, 0x20400000U, 0x00004000U, 0x20404010U,
	0x20400000U, 0x00000010U, 0x20404010U, 0x00400000U,
	0x20004000U, 0x00404010U, 0x00400000U, 0x20000010U,
	0x00400010U, 0x20004000U, 0x20000000U, 0x00004010U,
	0x00000000U, 0x00400010U, 0x20004010U, 0x00004000U,
	0x00404000U, 0x20004010U, 0x00000010U, 0x20400010U,
	0x20400010U, 0x00000000U, 0x00404010U, 0x20404000U,
	0x00004010U, 0x00404000U, 0x20404000U, 0x20000000U,
	0x20004000U, 0x00000010U, 0x20400010U, 0x00404000U,
	0x20404010U, 0x00400000U, 0x00004010U, 0x20000010U,
	0x00400000U, 0x20004000U, 0x20000000U, 0x00004010U,
	0x20000010U, 0x20404010U, 0x00404000U, 0x20400000U,
	0x00404010U, 0x20404000U, 0x00000000U, 0x20400010U,
	0x00000010U, 0x00004000U, 0x20400000U, 0x00404010U,
	0x00004000U, 0x00400010U, 0x20004010U, 0x00000000U,
	0x20404000U, 0x20000000U, 0x00400010U, 0x20004010U,
	0x00200000U, 0x04200002U, 0x04000802U, 0x00000000U,
	0x00000800U, 0x04000802U, 0x00200802U, 0x04200800U,
	0x04200802U, 0x00200000U, 0x00000000U, 0x04000002U,
	0x00000002U, 0x04000000U, 0x04200002U, 0x00000802U,
	0x04000800U, 0x00200802U, 0x00200002U, 0x04000800U,
	0x04000002U, 0x04200000U, 0x04200800U, 0x00200002U,
	0x04200000U, 0x00000800U, 0x00000802U, 0x04200802U,
	0x00200800U, 0x00000002U, 0x04000000U, 0x00200800U,
	0x04000000U, 0x00200800U, 0x00200000U, 0x04000802U,
	0x04000802U, 0x04200002U, 0x04200002U, 0x00000002U,
	0x00200002U, 0x04000000U, 0x04000800U, 0x00200000U,
	0x04200800U, 0x00000802U, 0x00200802U, 0x04200800U,
	0x00000802U, 0x04000002U, 0x04200802U, 0x04200000U,
	0x00200800U, 0x00000000U, 0x00000002U, 0x04200802U,
	0x00000000U, 0x00200802U, 0x04200000U, 0x00000800U,
	0x04000002U, 0x04000800U, 0x00000800U, 0x00200002U,
	0x10001040U, 0x00001000U, 0x00040000U, 0x10041040U,
	0x10000000U, 0x10001040U, 0x00000040U, 0x10000000U,
	0x00040040U, 0x10040000U, 0x10041040U, 0x00041000U,
	0x10041000U, 0x00041040U, 0x00001000U, 0x00000040U,
	0x10040000U, 0x10000040U, 0x10001000U, 0x00001040U,
	0x00041000U, 0x00040040U, 0x10040040U, 0x10041000U,
	0x00001040U, 0x00000000U, 0x00000000U, 0x10040040U,
	0x10000040U, 0x10001000U, 0x00041040U, 0x00040000U,
	0x00041040U, 0x00040000U, 0x10041000U, 0x00001000U,
	0x00000040U, 0x10040040U, 0x00001000U, 0x00041040U,
	0x10001000U, 0x00000040U, 0x10000040U, 0x10040000U,
	0x10040040U, 0x10000000U, 0x00040000U, 0x10001040U,
	0x00000000U, 0x10041040U, 0x00040040U, 0x10000040U,
	0x10040000U, 0x10001000U, 0x10001040U, 0x00000000U,
	0x10041040U, 0x00041000U, 0x00041000U, 0x00001040U,
	0x00001040U, 0x00040040U, 0x10000000U, 0x10041000U,
};

/*
 * Primitive function F.
 * Input is r, subkey array in keys, output is XORed into l.
 * Each round consumes eight 6-bit subkeys, one for
 * each of the 8 S-boxes, 2 longs for each round.
 * Each long contains four 6-bit subkeys, each taking up a byte.
 * The first long contains, from high to low end, the subkeys for
 * S-boxes 1, 3, 5 & 7; the second contains the subkeys for S-boxes
 * 2, 4, 6 & 8 (using the origin-1 S-box numbering in the standard,
 * not the origin-0 numbering used elsewhere in this code)
 * See comments elsewhere about the pre-rotated values of r and Spbox.
 */
#define	F(l, r, key) {\
	work = ((r >> 4) | (r << 28)) ^ (key)[0];\
	l ^= Spbox[6][work & 0x3f];\
	l ^= Spbox[4][(work >> 8) & 0x3f];\
	l ^= Spbox[2][(work >> 16) & 0x3f];\
	l ^= Spbox[0][(work >> 24) & 0x3f];\
	work = r ^ (key)[1];\
	l ^= Spbox[7][work & 0x3f];\
	l ^= Spbox[5][(work >> 8) & 0x3f];\
	l ^= Spbox[3][(work >> 16) & 0x3f];\
	l ^= Spbox[1][(work >> 24) & 0x3f];\
}

/* Encrypt or decrypt a block of data in ECB mode */
void
des(void *cookie, uint8_t *block)
{
	uint32_t *ks = (uint32_t *)cookie;
	uint32_t left;
	uint32_t right;
	uint32_t work;

	/* Read input block and place in left/right in big-endian order */
	left = ((uint32_t)block[0] << 24) |
	    ((uint32_t)block[1] << 16) |
	    ((uint32_t)block[2] << 8) |
	    (uint32_t)block[3];
	right = ((uint32_t)block[4] << 24) |
	    ((uint32_t)block[5] << 16) |
	    ((uint32_t)block[6] << 8) |
	    (uint32_t)block[7];

	/*
	 * Hoey's clever initial permutation algorithm, from Outerbridge
	 * (see Schneier p 478)
	 *
	 * The convention here is the same as Outerbridge: rotate each
	 * register left by 1 bit, i.e., so that "left" contains permuted
	 * input bits 2, 3, 4, ... 1 and "right" contains 33, 34, 35, ... 32
	 * (using origin-1 numbering as in the FIPS). This allows us to avoid
	 * one of the two rotates that would otherwise be required in each of
	 * the 16 rounds.
	 */
	work = ((left >> 4) ^ right) & 0x0f0f0f0f;
	right ^= work;
	left ^= work << 4;
	work = ((left >> 16) ^ right) & 0xffff;
	right ^= work;
	left ^= work << 16;
	work = ((right >> 2) ^ left) & 0x33333333;
	left ^= work;
	right ^= (work << 2);
	work = ((right >> 8) ^ left) & 0xff00ff;
	left ^= work;
	right ^= (work << 8);
	right = (right << 1) | (right >> 31);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left << 1) | (left >> 31);

	/* First key */
	F(left, right, ks);
	F(right, left, ks + 2);
	F(left, right, ks + 4);
	F(right, left, ks + 6);
	F(left, right, ks + 8);
	F(right, left, ks + 10);
	F(left, right, ks + 12);
	F(right, left, ks + 14);
	F(left, right, ks + 16);
	F(right, left, ks + 18);
	F(left, right, ks + 20);
	F(right, left, ks + 22);
	F(left, right, ks + 24);
	F(right, left, ks + 26);
	F(left, right, ks + 28);
	F(right, left, ks + 30);

	/* Inverse permutation, also from Hoey via Outerbridge and Schneier */
	right = (right << 31) | (right >> 1);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left >> 1) | (left  << 31);
	work = ((left >> 8) ^ right) & 0xff00ff;
	right ^= work;
	left ^= work << 8;
	work = ((left >> 2) ^ right) & 0x33333333;
	right ^= work;
	left ^= work << 2;
	work = ((right >> 16) ^ left) & 0xffff;
	left ^= work;
	right ^= work << 16;
	work = ((right >> 4) ^ left) & 0x0f0f0f0f;
	left ^= work;
	right ^= work << 4;

	/* Put the block back into the user's buffer with final swap */
	block[0] = right >> 24;
	block[1] = right >> 16;
	block[2] = right >> 8;
	block[3] = right;
	block[4] = left >> 24;
	block[5] = left >> 16;
	block[6] = left >> 8;
	block[7] = left;
}

/* Key schedule-related tables from FIPS-46 */

/* permuted choice table (key) */
static unsigned char pc1[] = {
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
};

/* number left rotations of pc1 */
static unsigned char totrot[] = {
	1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

/* permuted choice key (table) */
static unsigned char pc2[] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

/* End of DES-defined tables */


/* bit 0 is left-most in byte */
static int bytebit[] = {
	0200, 0100, 040, 020, 010, 04, 02, 01
};

/*
 * Generate key schedule for encryption or decryption
 * depending on the value of "decrypt"
 */
void
des_key(DES_KS k, const unsigned char *key, int decrypt)
{
	unsigned char pc1m[56];		/* place to modify pc1 into */
	unsigned char pcr[56];		/* place to rotate pc1 into */
	int i;
	int j;
	int l;
	int m;
	unsigned char ks[8];

	for (j = 0; j < 56; j++) {	/* convert pc1 to bits of key */
		l = pc1[j] - 1;		/* integer bit location	 */
		m = l & 07;		/* find bit		 */
		pc1m[j] = (key[l >>3 ]	/* find which key byte l is in */
			& bytebit[m])	/* and which bit of that byte */
			? 1 : 0;	/* and store 1-bit result */
	}
	for (i = 0; i < 16; i++) {	/* key chunk for each iteration */
		bzero(ks, sizeof (ks));	/* Clear key schedule */
		for (j = 0; j < 56; j++) /* rotate pc1 the right amount */
			pcr[j] = pc1m[(l = j + totrot[decrypt ? 15 - i : i]) <
			    (j < 28 ? 28 : 56) ? l : l - 28];
			/* rotate left and right halves independently */
		for (j = 0; j < 48; j++) {	/* select bits individually */
			/* check bit that goes to ks[j] */
			if (pcr[pc2[j] - 1]) {
				/* mask it in if it's there */
				l = j % 6;
				ks[j/6] |= bytebit[l] >> 2;
			}
		}
		/* Now convert to packed odd/even interleaved form */
		k[i][0] = ((uint32_t)ks[0] << 24) |
		    ((uint32_t)ks[2] << 16) |
		    ((uint32_t)ks[4] << 8) |
		    ((uint32_t)ks[6]);
		k[i][1] = ((uint32_t)ks[1] << 24) |
		    ((uint32_t)ks[3] << 16) |
		    ((uint32_t)ks[5] << 8) |
		    ((uint32_t)ks[7]);
	}
}

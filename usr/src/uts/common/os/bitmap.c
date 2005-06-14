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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Operations on bitmaps of arbitrary size
 * A bitmap is a vector of 1 or more ulongs.
 * The user of the package is responsible for range checks and keeping
 * track of sizes.
 */

#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/debug.h>		/* ASSERT */

/*
 * Return index of first available bit in denoted bitmap, or -1 for
 * failure.  Size is the cardinality of the bitmap; that is, the
 * number of bits.
 * No side-effects.  In particular, does not update bitmap.
 * Caller is responsible for range checks.
 */
index_t
bt_availbit(ulong_t *bitmap, size_t nbits)
{
	index_t	maxword;	/* index of last in map */
	index_t	wx;		/* word index in map */

	/*
	 * Look for a word with a bit off.
	 * Subtract one from nbits because we're converting it to a
	 * a range of indices.
	 */
	nbits -= 1;
	maxword = nbits >> BT_ULSHIFT;
	for (wx = 0; wx <= maxword; wx++)
		if (bitmap[wx] != ~0)
			break;

	if (wx <= maxword) {
		/*
		 * Found a word with a bit off.  Now find the bit in the word.
		 */
		index_t	bx;	/* bit index in word */
		index_t	maxbit; /* last bit to look at */
		ulong_t		word;
		ulong_t		bit;

		maxbit = wx == maxword ? nbits & BT_ULMASK : BT_NBIPUL - 1;
		word = bitmap[wx];
		bit = 1;
		for (bx = 0; bx <= maxbit; bx++, bit <<= 1) {
			if (!(word & bit)) {
				return (wx << BT_ULSHIFT | bx);
			}
		}
	}
	return (-1);
}


/*
 * Find highest order bit that is on, and is within or below
 * the word specified by wx.
 */
int
bt_gethighbit(ulong_t *mapp, int wx)
{
	ulong_t word;

	while ((word = mapp[wx]) == 0) {
		wx--;
		if (wx < 0) {
			return (-1);
		}
	}
	return (wx << BT_ULSHIFT | (highbit(word) - 1));
}


/*
 * Search the bitmap for a consecutive pattern of 1's.
 * Search starts at position pos1.
 * Returns 1 on success and 0 on failure.
 * Side effects.
 * Returns indices to the first bit (pos1)
 * and one past the last bit (pos2) in the pattern.
 */
int
bt_range(ulong_t *bitmap, size_t *pos1, size_t *pos2, size_t end_pos)
{
	size_t pos;

	for (pos = *pos1; pos < end_pos; pos++)
		if (BT_TEST(bitmap, pos))
			break;

	if (pos == end_pos)
		return (0);

	*pos1 = pos;

	for (; pos < end_pos; pos++)
		if (!BT_TEST(bitmap, pos))
			break;
	*pos2 = pos;

	return (1);
}


/*
 * return the parity of the supplied long
 *
 * this works by successively partitioning the argument in half, and
 * setting the parity of the result to the parity of the 2 halfs, until
 * only one bit is left
 */
int
odd_parity(ulong_t i)
{
#ifdef _LP64
	i ^= i >> 32;
#endif
	i ^= i >> 16;
	i ^= i >> 8;
	i ^= i >> 4;
	i ^= i >> 2;
	i ^= i >> 1;

	return (i & 0x01);
}


/*
 * get the lowest bit in the range of 'start' and 'stop', inclusive.
 * I.e., if caller calls bt_getlowbit(map, X, Y), any value between X and Y,
 * including X and Y can be returned.
 * Neither start nor stop is required to align with word boundaries.
 * If a bit is set in the range, the bit position is returned; otherwise,
 * a -1 is returned.
 */
int
bt_getlowbit(ulong_t *map, size_t start, size_t stop)
{
	ulong_t		word;
	int		counter = start >> BT_ULSHIFT;
	int		limit = stop >> BT_ULSHIFT;
	index_t		partial_start = start & BT_ULMASK;
	index_t		partial_stop = stop & BT_ULMASK;

	if (start > stop) {
		return (-1);
	}

	/*
	 * The range between 'start' and 'stop' can be very large, and the
	 * '1' bits in this range can be sparse.
	 * For performance reason, the underlying implementation operates
	 * on words, not on bits.
	 */
	word = map[counter];

	if (partial_start) {
		/*
		 * Since the start is not aligned on word boundary, we
		 * need to patch the unwanted low order bits with 0's before
		 * operating on the first bitmap word.
		 */
		word = word & (BT_ULMAXMASK << partial_start);
	}

	/*
	 * Locate a word from the map array with one of the bits set.
	 */

	while ((word == 0) && (counter < limit)) {
		word = map[++counter];
	}

	/*
	 * The end of range has similar problems if it is not aligned.
	 * Taking care of the end which is not aligned.
	 */

	if ((counter == limit) && (partial_stop != BT_ULMASK)) {
		/*
		 * Take care the partial word by patch the high order
		 * bits with 0's. Here we dealing with the case that
		 * the last word of the bitmap is not aligned.
		 */

		ASSERT(partial_stop < BT_ULMASK);
		word = word & (~(BT_ULMAXMASK << partial_stop + 1));
	}

	/*
	 * Examine the word.
	 */
	if (word == 0) {
		return (-1);
	} else {
		return ((counter << BT_ULSHIFT) | (lowbit(word) - 1));
	}
}

/*
 * Copy the bitmap.
 */
void
bt_copy(ulong_t *from, ulong_t *to, ulong_t size)
{
	ulong_t i;
	for (i = 0; i < size; i++)
		*to++ = *from++;
}

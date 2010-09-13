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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/bitset.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

/*
 * Initialize a bitset_t.
 * After bitset_init(), the bitset will be zero sized.
 */
void
bitset_init(bitset_t *b)
{
	bzero(b, sizeof (bitset_t));
}

/*
 * Initialize a bitset_t using a fanout. The fanout factor is platform
 * specific and passed in as a power of two.
 */
void
bitset_init_fanout(bitset_t *b, uint_t fanout)
{
	bzero(b, sizeof (bitset_t));
	b->bs_fanout = fanout;
}

/*
 * Uninitialize a bitset_t.
 * This will free the bitset's data, leaving it zero sized.
 */
void
bitset_fini(bitset_t *b)
{
	if (b->bs_words > 0)
		kmem_free(b->bs_set, b->bs_words * sizeof (ulong_t));
}

/*
 * Resize a bitset to where it can hold els number of elements.
 * This can either grow or shrink the bitset holding capacity.
 * In the case of shrinkage, elements that reside outside the new
 * holding capacity of the bitset are lost.
 */
void
bitset_resize(bitset_t *b, uint_t els)
{
	uint_t	nwords;
	ulong_t	*bset_new, *bset_tmp;

	nwords = BT_BITOUL(els << b->bs_fanout);
	if (b->bs_words == nwords)
		return;	/* already properly sized */

	/*
	 * Allocate the new ulong_t array, and copy the old one, if there
	 * was an old one.
	 */
	if (nwords > 0) {
		bset_new = kmem_zalloc(nwords * sizeof (ulong_t), KM_SLEEP);
		if (b->bs_words > 0)
			bcopy(b->bs_set, bset_new,
			    MIN(b->bs_words, nwords) * sizeof (ulong_t));
	} else {
		bset_new = NULL;
	}

	/* swap out the old ulong_t array for new one */
	bset_tmp = b->bs_set;
	b->bs_set = bset_new;

	/* free up the old array */
	if (b->bs_words > 0)
		kmem_free(bset_tmp, b->bs_words * sizeof (ulong_t));

	b->bs_words = nwords;
}

/*
 * Returns the current holding capacity of the bitset.
 */
uint_t
bitset_capacity(bitset_t *b)
{
	return (b->bs_words * BT_NBIPUL);
}

/*
 * Add (set) and delete (clear) bits in the bitset.
 *
 * Adding a bit that is already set, or removing a bit that's already clear
 * is legal.
 *
 * Adding or deleting an element that falls outside the bitset's current
 * holding capacity is illegal.
 */
void
bitset_add(bitset_t *b, uint_t elt)
{
	uint_t pos = (elt << b->bs_fanout);

	ASSERT(b->bs_words * BT_NBIPUL > pos);
	BT_SET(b->bs_set, pos);
}

/*
 * Set a bit in an atomically safe way.
 */
void
bitset_atomic_add(bitset_t *b, uint_t elt)
{
	uint_t pos = (elt << b->bs_fanout);

	ASSERT(b->bs_words * BT_NBIPUL > pos);
	BT_ATOMIC_SET(b->bs_set, pos);
}

/*
 * Atomically test that a given bit isn't set, and set it.
 * Returns -1 if the bit was already set.
 */
int
bitset_atomic_test_and_add(bitset_t *b, uint_t elt)
{
	uint_t pos = (elt << b->bs_fanout);
	int ret;

	ASSERT(b->bs_words * BT_NBIPUL > pos);
	BT_ATOMIC_SET_EXCL(b->bs_set, pos, ret);

	return (ret);
}

/*
 * Clear a bit.
 */
void
bitset_del(bitset_t *b, uint_t elt)
{
	uint_t pos = (elt << b->bs_fanout);

	ASSERT(b->bs_words * BT_NBIPUL > pos);
	BT_CLEAR(b->bs_set, pos);
}

/*
 * Clear a bit in an atomically safe way.
 */
void
bitset_atomic_del(bitset_t *b, uint_t elt)
{
	uint_t pos = (elt << b->bs_fanout);

	ASSERT(b->bs_words * BT_NBIPUL > pos);
	BT_ATOMIC_CLEAR(b->bs_set, pos);
}

/*
 * Atomically test that a bit is set, and clear it.
 * Returns -1 if the bit was already clear.
 */
int
bitset_atomic_test_and_del(bitset_t *b, uint_t elt)
{
	uint_t pos = (elt << b->bs_fanout);
	int ret;

	ASSERT(b->bs_words * BT_NBIPUL > pos);
	BT_ATOMIC_CLEAR_EXCL(b->bs_set, pos, ret);

	return (ret);
}

/*
 * Return non-zero if the bit is present in the set.
 */
int
bitset_in_set(bitset_t *b, uint_t elt)
{
	uint_t pos = (elt << b->bs_fanout);

	if (pos >= b->bs_words * BT_NBIPUL)
		return (0);

	return (BT_TEST(b->bs_set, pos));
}

/*
 * Return non-zero if the bitset is empty.
 */
int
bitset_is_null(bitset_t *b)
{
	int i;

	for (i = 0; i < b->bs_words; i++)
		if (b->bs_set[i] != 0)
			return (0);
	return (1);
}

/*
 * Perform a non-victimizing search for a set bit in a word.
 * A "seed" is passed to pseudo-randomize the search.
 * Return -1 if no set bit was found.
 */
static uint_t
bitset_find_in_word(ulong_t w, uint_t seed)
{
	uint_t rotate_bit, elt = (uint_t)-1;
	ulong_t rotated_word;

	if (w == (ulong_t)0)
		return (elt);

	rotate_bit = seed % BT_NBIPUL;
	rotated_word = (w >> rotate_bit) | (w << (BT_NBIPUL - rotate_bit));
	elt = (uint_t)(lowbit(rotated_word) - 1);
	if (elt != (uint_t)-1)
		elt = ((elt + rotate_bit) % BT_NBIPUL);

	return (elt);
}

/*
 * Select a bit that is set in the bitset in a non-victimizing fashion
 * (e.g. doesn't bias the low/high order bits/words).
 * Return -1 if no set bit was found
 */
uint_t
bitset_find(bitset_t *b)
{
	uint_t start, i;
	uint_t elt = (uint_t)-1;
	uint_t seed;

	seed = CPU_PSEUDO_RANDOM();

	ASSERT(b->bs_words > 0);
	start = seed % b->bs_words;

	i = start;
	do {
		elt = bitset_find_in_word(b->bs_set[i], seed);
		if (elt != (uint_t)-1) {
			elt += i * BT_NBIPUL;
			return (elt >> b->bs_fanout);
		}
		if (++i == b->bs_words)
			i = 0;
	} while (i != start);

	return (elt);
}

/*
 * AND, OR, and XOR bitset computations, returns 1 if resulting bitset has any
 * set bits. Operands must have the same fanout, if any.
 */
int
bitset_and(bitset_t *bs1, bitset_t *bs2, bitset_t *res)
{
	int i, anyset;

	ASSERT(bs1->bs_fanout == bs2->bs_fanout);
	ASSERT(bs1->bs_fanout == res->bs_fanout);

	for (anyset = 0, i = 0; i < bs1->bs_words; i++) {
		if ((res->bs_set[i] = (bs1->bs_set[i] & bs2->bs_set[i])) != 0)
			anyset = 1;
	}
	return (anyset);
}

int
bitset_or(bitset_t *bs1, bitset_t *bs2, bitset_t *res)
{
	int i, anyset;

	ASSERT(bs1->bs_fanout == bs2->bs_fanout);
	ASSERT(bs1->bs_fanout == res->bs_fanout);

	for (anyset = 0, i = 0; i < bs1->bs_words; i++) {
		if ((res->bs_set[i] = (bs1->bs_set[i] | bs2->bs_set[i])) != 0)
			anyset = 1;
	}
	return (anyset);
}

int
bitset_xor(bitset_t *bs1, bitset_t *bs2, bitset_t *res)
{
	int i, anyset = 0;

	ASSERT(bs1->bs_fanout == bs2->bs_fanout);
	ASSERT(bs1->bs_fanout == res->bs_fanout);

	for (i = 0; i < bs1->bs_words; i++) {
		if ((res->bs_set[i] = (bs1->bs_set[i] ^ bs2->bs_set[i])) != 0)
			anyset = 1;
	}
	return (anyset);
}

/*
 * Return 1 if bitmaps are identical.
 */
int
bitset_match(bitset_t *bs1, bitset_t *bs2)
{
	int i;

	if (bs1->bs_words != bs2->bs_words)
		return (0);

	for (i = 0; i < bs1->bs_words; i++)
		if (bs1->bs_set[i] != bs2->bs_set[i])
			return (0);
	return (1);
}

/*
 * Zero a bitset_t.
 */
void
bitset_zero(bitset_t *b)
{
	bzero(b->bs_set, sizeof (ulong_t) * b->bs_words);
}

/*
 * Copy a bitset_t.
 */
void
bitset_copy(bitset_t *src, bitset_t *dest)
{
	ASSERT(src->bs_fanout == dest->bs_fanout);
	bcopy(src->bs_set, dest->bs_set, sizeof (ulong_t) * src->bs_words);
}

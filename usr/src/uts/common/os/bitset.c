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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/bitset.h>
#include <sys/kmem.h>
#include <sys/systm.h>
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
 * Resize a bitset to where it can hold sz number of bits.
 * This can either grow or shrink the bitset holding capacity.
 * In the case of shrinkage, elements that reside outside the new
 * holding capacity of the bitset are lost.
 */
void
bitset_resize(bitset_t *b, uint_t sz)
{
	uint_t	nwords;
	ulong_t	*bset_new, *bset_tmp;

	nwords = BT_BITOUL(sz);
	if (b->bs_words == nwords)
		return;	/* already properly sized */

	/*
	 * Allocate the new ulong_t array, and copy the old one.
	 */
	if (nwords > 0) {
		bset_new = kmem_zalloc(nwords * sizeof (ulong_t), KM_SLEEP);
		bcopy(b->bs_set, bset_new,
		    MIN(b->bs_words, nwords) * sizeof (ulong_t));
	} else {
		bset_new = NULL;
	}

	/* swap out the old ulong_t array for new one */
	bset_tmp = b->bs_set;
	b->bs_set = bset_new;

	/* free up the old array */
	kmem_free(bset_tmp, b->bs_words * sizeof (ulong_t));
	b->bs_words = nwords;
}

/*
 * Returns the current holding capacity of the bitset
 */
uint_t
bitset_capacity(bitset_t *b)
{
	return (b->bs_words * BT_NBIPUL);
}

/*
 * Add and delete bits in the bitset.
 *
 * Adding a bit that is already set, and clearing a bit that's already clear
 * is legal.
 *
 * Adding or deleting an element that falls outside the bitset's current
 * holding capacity is illegal.
 */
void
bitset_add(bitset_t *b, uint_t elt)
{
	ASSERT(b->bs_words * BT_NBIPUL > elt);

	BT_SET(b->bs_set, elt);
}

void
bitset_del(bitset_t *b, uint_t elt)
{
	ASSERT(b->bs_words * BT_NBIPUL > elt);

	BT_CLEAR(b->bs_set, elt);
}

/*
 * Return non-zero if the bit is present in the set
 */
int
bitset_in_set(bitset_t *b, uint_t elt)
{
	if (elt >= b->bs_words * BT_NBIPUL)
		return (0);

	return (BT_TEST(b->bs_set, elt));
}

/*
 * Return non-zero if the bitset is empty
 */
int
bitset_is_null(bitset_t *b)
{
	int	i;

	for (i = 0; i < b->bs_words; i++)
		if (b->bs_set[i] != 0)
			return (0);
	return (1);
}

/*
 * Find the first set bit in the bitset
 * Return -1 if no bit was found
 */
uint_t
bitset_find(bitset_t *b)
{
	uint_t	i;
	uint_t	elt = (uint_t)-1;

	for (i = 0; i < b->bs_words; i++) {
		elt = (uint_t)(lowbit(b->bs_set[i]) - 1);
		if (elt != (uint_t)-1) {
			elt += i * BT_NBIPUL;
			break;
		}
	}
	return (elt);
}

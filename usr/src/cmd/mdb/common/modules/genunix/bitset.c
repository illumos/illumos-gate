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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <sys/bitset.h>

#include "bitset.h"		/* XXX work out ifdef in include file... */

void
bitset_help(void)
{
	mdb_printf("Print the bitset at the address given\n");
}

static void
bitset_free(bitset_t *bs)
{
	if (bs == NULL)
		return;
	if (bs->bs_set && bs->bs_words)
		mdb_free(bs->bs_set, bs->bs_words * sizeof (ulong_t));
	mdb_free(bs, sizeof (*bs));
}

static bitset_t *
bitset_get(uintptr_t bsaddr)
{
	bitset_t	*bs;

	bs = mdb_zalloc(sizeof (*bs), UM_SLEEP);
	if (mdb_vread(bs, sizeof (*bs), bsaddr) == -1) {
		mdb_warn("couldn't read bitset 0x%p", bsaddr);
		bitset_free(bs);
		return (NULL);
	}

	bsaddr = (uintptr_t)bs->bs_set;
	bs->bs_set = mdb_alloc(bs->bs_words * sizeof (ulong_t), UM_SLEEP);
	if (mdb_vread(bs->bs_set,
	    bs->bs_words * sizeof (ulong_t), bsaddr) == -1) {
		mdb_warn("couldn't read bitset bs_set 0x%p", bsaddr);
		bitset_free(bs);
		return (NULL);
	}
	return (bs);

}

static int
bitset_highbit(bitset_t *bs)
{
	int	high;
	int	i;

	if ((bs->bs_set == NULL) || (bs->bs_words == 0))
		return (-1);

	/* move backwards through words */
	for (i = bs->bs_words; i >= 0; i--)
		if (bs->bs_set[i])
			break;
	if (i < 0)
		return (-1);

	/* move backwards through bits */
	high = i << BT_ULSHIFT;
	for (i = BT_NBIPUL - 1; i; i--)
		if (BT_TEST(bs->bs_set, high + i))
			break;
	return (high + i + 1);
}

static int
pow10(int exp)
{
	int	res;

	for (res = 1; exp; exp--)
		res *= 10;
	return (res);
}

static int
log10(int val)
{
	int	res = 0;

	do {
		res++;
		val /= 10;
	} while (val);
	return (res);
}

/*
 * The following prints a bitset with a 'ruler' that look like this
 *
 *              11111111112222222222333333333344444444445555555555666666666677
 *    012345678901234567890123456789012345678901234567890123456789012345678901
 * xx:........................................................................
 *                                11111111111111111111111111111111111111111111
 *    777777778888888888999999999900000000001111111111222222222233333333334444
 *    234567890123456789012345678901234567890123456789012345678901234567890123
 *    ........................................................................
 *    111111111111111111111111111111111111111111111111111111112222222222222222
 *    444444555555555566666666667777777777888888888899999999990000000000111111
 *    456789012345678901234567890123456789012345678901234567890123456789012345
 *    ........................................................................
 *    2222222222
 *    1111222222
 *    6789012345
 *    ..........
 *
 * to identify individual bits that are set.
 */
static void
bitset_print(bitset_t *bs, char *label, int width)
{
	int	val_start;
	int	val_max;
	int	label_width;
	int	ruler_width;
	int	v, vm, vi;
	int	nl, l;
	int	i;
	int	p;
	char	c;

	val_start = 0;
	val_max = bitset_highbit(bs) + 1;
	if (val_max <= val_start) {
		mdb_printf("%s: empty-set", label);
		return;
	}

	label_width = strlen(label) + 1;
	ruler_width = width - label_width;

	for (v = val_start; v < val_max; v = vm) {
		if ((v + ruler_width) < val_max)
			vm = v + ruler_width;
		else
			vm = val_max;

		nl = log10(vm) - 1;
		for (l = nl; l >= 0; l--) {
			p = pow10(l);
			for (i = 0; i < label_width; i++)
				mdb_printf(" ");

			for (vi = v; vi < vm; vi++) {
				c = '0' + ((vi / p) % 10);
				if ((l == nl) && (c == '0'))
					c = ' ';
				mdb_printf("%c", c);
			}

			mdb_printf("\n");
		}

		if (v == val_start) {
			mdb_printf("%s:", label);
		} else {
			for (i = 0; i < label_width; i++)
				mdb_printf(" ");
		}
		for (vi = v; vi < vm; vi++) {
			if (BT_TEST(bs->bs_set, vi))
				mdb_printf("X");
			else
				mdb_printf(".");
		}
		mdb_printf("\n");
	}
}

/*ARGSUSED*/
int
bitset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	bitset_t	*bs;

	bs = bitset_get(addr);
	if (bs == NULL)
		return (DCMD_ERR);

	bitset_print(bs, "label", 80);
	bitset_free(bs);
	return (DCMD_OK);
}

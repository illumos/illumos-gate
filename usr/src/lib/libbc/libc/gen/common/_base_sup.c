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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "base_conversion.h"

#ifdef DEBUG

void
_display_big_float(_big_float *pbf, unsigned base)
{
	int             i;

	for (i = 0; i < pbf->blength; i++) {
		switch (base) {
		case 2:
			printf(" + %d * 2** %d", pbf->bsignificand[i], (16 * i + pbf->bexponent));
			break;
		case 10:
			printf(" + %d * 10** %d", pbf->bsignificand[i], (4 * i + pbf->bexponent));
			break;
		}
		if ((i % 4) == 3)
			printf("\n");
	}
	printf("\n");
}

#endif

void
_integerstring_to_big_decimal(char ds[], unsigned ndigs, unsigned nzin,
    unsigned *pnzout, _big_float *pd)
{
	/*
	 * Convert ndigs decimal digits from ds, and up to 3 trailing zeros,
	 * into a decimal big_float in *pd.  nzin tells how many implicit
	 * trailing zeros may be used, while *pnzout tells how many were
	 * actually absorbed.  Up to 3 are used if available so that
	 * (ndigs+*pnzout) % 4 = 0.
	 */

	int             extras, taken, id, ids;

#ifdef DEBUG
	printf(" _integerstring_to_big_decimal: ndigs %d nzin %d ds %s \n", ndigs, nzin, ds);
#endif

	/* Compute how many trailing zeros we're going to put in *pd. */

	extras = ndigs % 4;
	if ((extras > 0) && (nzin != 0)) {
		taken = 4 - extras;
		if (taken > nzin)
			taken = nzin;
	} else
		taken = 0;

	*pnzout = nzin - taken;

#define IDIGIT(i) ((i < 0) ? 0 : ((i < ndigs) ? (ds[i] - '0') : 0))

	pd->bexponent = 0;
	pd->blength = (ndigs + taken + 3) / 4;

	ids = (ndigs + taken) - 4 * pd->blength;
	id = pd->blength - 1;

#ifdef DEBUG
	printf(" _integerstring_to_big_decimal exponent %d ids %d id %d \n", pd->bexponent, ids, id);
#endif

	pd->bsignificand[id] = 1000 * IDIGIT(ids) + 100 * IDIGIT(ids + 1) + 10 * IDIGIT(ids + 2) + IDIGIT(ids + 3);
	ids += 4;

	for (; ids < (int) (ndigs + taken - 4); ids += 4) {	/* Additional digits to
								 * be found. Main loop. */
		id--;
		pd->bsignificand[id] = 1000 * ds[ids] + 100 * ds[ids + 1] + 10 * ds[ids + 2] + ds[ids + 3] - 1111 * '0';
	}

#ifdef DEBUG
	assert((id == 1) || (id == 0));
#endif
	if (id != 0)
		pd->bsignificand[0] = 1000 * IDIGIT(ids) + 100 * IDIGIT(ids + 1) + 10 * IDIGIT(ids + 2) + IDIGIT(ids + 3);

#ifdef DEBUG
	printf(" _integerstring_to_big_decimal: ");
	_display_big_float(pd, 10);
#endif
}

void
_fractionstring_to_big_decimal(char ds[], unsigned ndigs, unsigned nzin,
    _big_float *pbf)
{
	/*
	 * Converts a decimal string containing an implicit point, nzin
	 * leading implicit zeros, and ndigs explicit digits, into a big
	 * float.
	 */

	int             ids, ibf;

#ifdef DEBUG
	printf(" _fractionstring_to_big_decimal ndigs %d nzin %d s %s \n", ndigs, nzin, ds);
#endif

	pbf->bexponent = -(int) (nzin + ndigs);
	pbf->blength = (ndigs + 3) / 4;

	ids = nzin + ndigs - 4 * pbf->blength;
	ibf = pbf->blength - 1;

#ifdef DEBUG
	printf(" _fractionstring_to_big_decimal exponent %d ids %d ibf %d \n", pbf->bexponent, ids, ibf);
#endif

#define FDIGIT(i) ((i < nzin) ? 0 : ((i < (nzin+ndigs)) ? (ds[i-nzin] - '0') : 0))

	pbf->bsignificand[ibf] = 1000 * FDIGIT(ids) + 100 * FDIGIT(ids + 1) + 10 * FDIGIT(ids + 2) + FDIGIT(ids + 3);
	ids += 4;

	for (; ids < (int) (nzin + ndigs - 4); ids += 4) {	/* Additional digits to
								 * be found. Main loop. */
		ibf--;
		pbf->bsignificand[ibf] = 1000 * ds[ids - nzin] + 100 * ds[ids + 1 - nzin] + 10 * ds[ids + 2 - nzin] + ds[ids + 3 - nzin] - 1111 * '0';
	}

	if (ibf > 0) {
#ifdef DEBUG
		assert(ibf == 1);
#endif
		pbf->bsignificand[0] = 1000 * FDIGIT(ids) + 100 * FDIGIT(ids + 1) + 10 * FDIGIT(ids + 2) + FDIGIT(ids + 3);
	} else {
#ifdef DEBUG
		assert(ibf == 0);
#endif
	}

#ifdef DEBUG
	printf(" _fractionstring_to_big_decimal: ");
	_display_big_float(pbf, 10);
#endif
}

void
_mul_10000short(_big_float *pbf, long unsigned carry)
{
	int             j;
	long unsigned   p;

	for (j = 0; j < pbf->blength; j++) {
		p = _prod_10000_b65536(pbf->bsignificand[j], carry);
		pbf->bsignificand[j] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	while (carry != 0) {
		p = _carry_out_b10000(carry);
		pbf->bsignificand[j++] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
	pbf->blength = j;
}

void
_big_decimal_to_big_binary(_big_float *pd, _big_float *pb)
{
	/* Convert _big_float from decimal form to binary form. */

	int             id, idbound;
	_BIG_FLOAT_DIGIT sticky, carry;
	_BIG_FLOAT_DIGIT multiplier;

#ifdef DEBUG
	assert(pd->bexponent >= -3);
	assert(pd->bexponent <= 3);
#endif
	pb->bexponent = 0;
	pb->blength = 1;
	id = pd->blength - 1;
	if ((id == 0) && (pd->bexponent < 0)) {
		pb->bsignificand[0] = 0;
	} else {
		pb->bsignificand[0] = pd->bsignificand[id--];
		idbound = (pd->bexponent < 0) ? 1 : 0;	/* How far to carry next
							 * for loop depends on
							 * whether last digit
							 * requires special
							 * treatment. */
		for (; id >= idbound; id--) {
			_mul_10000short(pb, (long unsigned) pd->bsignificand[id]);
		}
	}
	if (pd->bexponent < 0) {/* Have to save some integer bits, discard
				 * and stick some fraction bits at the end. */
#ifdef DEBUG
		assert(id == 0);
#endif
		sticky = 0;
		carry = pd->bsignificand[0];
		multiplier = 10000;
		switch (pd->bexponent) {
		case -1:
			sticky = carry % 10;
			carry /= 10;
			multiplier = 1000;
			break;
		case -2:
			sticky = carry % 100;
			carry /= 100;
			multiplier = 100;
			break;
		case -3:
			sticky = carry % 1000;
			carry /= 1000;
			multiplier = 10;
			break;
		}
		_multiply_base_two(pb, multiplier, (long unsigned) carry);
		if (sticky != 0)
			pb->bsignificand[0] |= 1;	/* Save lost bits. */
	} else if (pd->bexponent > 0) {	/* Have to append some zeros. */
		switch (pd->bexponent) {
		case 1:
			multiplier = 10;
			break;
		case 2:
			multiplier = 100;
			break;
		case 3:
			multiplier = 1000;
			break;
		}
		carry = 0;
		_multiply_base_two(pb, multiplier, (long unsigned) carry);
	}
#ifdef DEBUG
	printf(" _big_decimal_to_big_binary ");
	_display_big_float(pb, 2);
#endif
}

void
_big_binary_to_unpacked(_big_float *pb, unpacked *pu)
{
	/* Convert a binary big_float to a binary_unpacked.	 */

	int             ib, iu;

#ifdef DEBUG
	assert(pb->bsignificand[pb->blength - 1] != 0);	/* Assert pb is
							 * normalized. */
#endif

	iu = 0;
	for (ib = pb->blength - 1; ((ib - 1) >= 0) && (iu < UNPACKED_SIZE); ib -= 2) {
		pu->significand[iu++] = pb->bsignificand[ib] << 16 | pb->bsignificand[ib - 1];
	}
	if (iu < UNPACKED_SIZE) {	/* The big float fits in the unpacked
					 * with no rounding. 	 */
		if (ib == 0)
			pu->significand[iu++] = pb->bsignificand[ib] << 16;
		for (; iu < UNPACKED_SIZE; iu++)
			pu->significand[iu] = 0;
	} else {		/* The big float is too big; chop, stick, and
				 * normalize. */
		while (pb->bsignificand[ib] == 0)
			ib--;
		if (ib >= 0)
			pu->significand[UNPACKED_SIZE - 1] |= 1;	/* Stick lsb if nonzero
									 * found. */
	}

	pu->exponent = 16 * pb->blength + pb->bexponent - 1;
	_fp_normalize(pu);

#ifdef DEBUG
	printf(" _big_binary_to_unpacked \n");
	_display_unpacked(pu);
#endif
}

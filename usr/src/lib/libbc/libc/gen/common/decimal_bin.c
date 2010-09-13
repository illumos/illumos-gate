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
 * Copyright (c) 1988-1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/* Conversion between binary and decimal floating point. */

#include "base_conversion.h"

void
decimal_to_binary_integer(ds, ndigs, nzeros, nsig, pb)
	char            ds[];	/* Input decimal integer string. */
unsigned        ndigs;		/* Input number of explicit digits in ds. */
unsigned        nzeros;		/* Input number of implicit trailing zeros. */
unsigned        nsig;		/* Input number of significant bits required. */
_big_float     *pb;		/* Pointer to big_float to receive result. */

/*
 * Converts a decimal integer string ds with ndigs explicit leading digits
 * and nzeros implicit trailing zeros to a _big_float **pb, which only
 * requires nsig significand bits.
 */
/* Inexactness is indicated by pb->bsignificand[0] |= 1. */
/*
 * If the input is too big for a big_float, pb->bexponent is set to 0x7fff.
 */

{
	unsigned        nzout;
	_big_float      d, *pbout;

	d.bsize = _BIG_FLOAT_SIZE;
	_integerstring_to_big_decimal(ds, ndigs, nzeros, &nzout, &d);
	_big_decimal_to_big_binary(&d, pb);
	if (nzout != 0) {
		_big_float_times_power(pb, 10, (int) nzout, (int) nsig, &pbout);
		switch ((unsigned int)pbout) {
		case ((unsigned int)BIG_FLOAT_TIMES_TOOBIG):
#ifdef DEBUG
			(void) printf(" decimal_to_binary_integer: decimal exponent %d too large for tables ", nzout);
#endif
			pb->bexponent = 0x7fff;
			break;
		case ((unsigned int)BIG_FLOAT_TIMES_NOMEM):
			{
				char            bcastring[80];

				(void) sprintf(bcastring, " decimal exponent %d ", nzout);
				_base_conversion_abort(ENOMEM, bcastring);
				break;
			}
		default:
#ifdef DEBUG
			if (pbout != pb)
				(void) printf(" decimal_to_binary_integer: large decimal exponent %d needs heap buffer \n", nzout);
			printf(" decimal_to_binary_integer: product ");
			_display_big_float(pb, 2);
#endif
			if (pbout != pb) {	/* We don't really need such
						 * a large product; the
						 * target can't be more than
						 * a quad! */
				int             i, allweneed;

				allweneed = 2 + (nsig + 2) / 16;
				for (i = 0; i < allweneed; i++)
					pb->bsignificand[i] = pbout->bsignificand[i + pbout->blength - allweneed];
				for (i = 0; (pbout->bsignificand[i] == 0); i++);
				if (i < (pbout->blength - allweneed))
					pb->bsignificand[0] |= 1;	/* Stick discarded bits. */

				pb->blength = allweneed;
				pb->bexponent = pbout->bexponent + 16 * (pbout->blength - allweneed);
#ifdef DEBUG
				printf(" decimal_to_binary_integer: removed %d excess digits from product \n", pbout->blength - allweneed);
				_display_big_float(pb, 2);
#endif
				_free_big_float(pbout);
			}
			break;
		}
	}
}

void
decimal_to_binary_fraction(ds, ndigs, nzeros, nsig, pb)
	char            ds[];	/* Decimal integer string input. */
unsigned        ndigs;		/* Number of explicit digits to read. */
unsigned        nzeros;		/* Number of implicit leading zeros before
				 * digits. */
unsigned        nsig;		/* Number of significant bits needed. */
_big_float     *pb;		/* Pointer to intended big_float result. */

/*
 * Converts an explicit decimal string *ds[0]..*ds[ndigs-1] preceded by
 * nzeros implicit leading zeros after the point into a big_float at *pb. If
 * the input does not fit exactly in a big_float, the least significant bit
 * of pbout->significand is stuck on. If the input is too big for the base
 * conversion tables, pb->bexponent is set to 0x7fff.
 */

{
	unsigned        twopower, twosig;
	int             i, excess;
	_big_float      d, *pdout;

	d.bsize = _BIG_FLOAT_SIZE;
	_fractionstring_to_big_decimal(ds, ndigs, nzeros, &d);

	twopower = nsig + 3 + (((nzeros + 1) * (unsigned long) 217706) >> 16);
	twosig = 1 + (((nsig + 2) * (unsigned long) 19729) >> 16);

#ifdef DEBUG
	printf(" decimal_to_binary_fraction sigbits %d twopower %d twosig %d \n",
	       nsig, twopower, twosig);
#endif
	_big_float_times_power(&d, 2, (int) twopower, (int) twosig, &pdout);
	switch ((unsigned int)pdout) {
	case ((unsigned int)BIG_FLOAT_TIMES_TOOBIG):
#ifdef DEBUG
		(void) printf(" decimal_to_binary_fraction binary exponent %d too large for tables ", twopower);
#endif
		pb->bexponent = 0x7fff;
		goto ret;
	case ((unsigned int)BIG_FLOAT_TIMES_NOMEM):
		{
			char            bcastring[80];

			(void) sprintf(bcastring, " binary exponent %d ", twopower);
			_base_conversion_abort(ENOMEM, bcastring);
			break;
		}
	default:
#ifdef DEBUG
		if (&d != pdout)
			printf(" decimal_to_binary_fraction large binary exponent %d needs heap buffer \n", twopower);
		printf(" product ");
		_display_big_float(pdout, 10);
#endif
		break;
	}


	if (pdout->bexponent <= -4) {
		/* Have computed appropriate decimal part; now toss fraction. */
		excess = (-pdout->bexponent) / 4;
#ifdef DEBUG
		printf(" discard %d excess fraction digits \n", 4 * excess);
#endif
		for (i = 0; (i < excess) && ((pdout)->bsignificand[i] == 0); i++);
		if (i < excess)
			(pdout)->bsignificand[excess] |= 1;	/* Sticky bit for
								 * discarded fraction. */
		for (i = excess; i < (pdout)->blength; i++)
			(pdout)->bsignificand[i - excess] = (pdout)->bsignificand[i];

		(pdout)->blength -= excess;
		(pdout)->bexponent += 4 * excess;
	}
	_big_decimal_to_big_binary(pdout, pb);
	if (pdout != &d)
		_free_big_float(pdout);
	pb->bexponent = -twopower;

ret:
	return;
}

void
decimal_to_unpacked(px, pd, significant_bits)
	unpacked       *px;
	decimal_record *pd;
	unsigned        significant_bits;

/*
 * Converts *pd to *px so that *px can be correctly rounded. significant_bits
 * tells how many bits will be significant in the final result to avoid
 * superfluous computation. Inexactness is communicated by sticking on the
 * lsb of px->significand[UNPACKED_SIZE-1]. Integer buffer overflow is
 * indicated with a huge positive exponent.
 */

{
	int             frac_bits, sigint;
	unsigned        length, ndigs, ntz, nlz, ifrac, nfrac;
	_big_float      bi, bf, *ptounpacked = &bi;

	px->sign = pd->sign;
	px->fpclass = pd->fpclass;
	if ((px->fpclass != fp_normal) && (px->fpclass != fp_subnormal))
		goto ret;
	for (length = 0; pd->ds[length] != 0; length++);
	if (length == 0) {	/* A zero significand slipped by. */
		px->fpclass = fp_zero;
		goto ret;
	}
	/* Length contains the number of explicit digits in string. */
	if (pd->exponent >= 0) {/* All integer digits. */
		ndigs = length;
		ntz = pd->exponent;	/* Trailing zeros. */
		ifrac = 0;
		nfrac = 0;	/* No fraction digits. */
		nlz = 0;
	} else if (length <= -pd->exponent) {	/* No integer digits. */
		ndigs = 0;
		ntz = 0;
		ifrac = 0;
		nfrac = length;
		nlz = -pd->exponent - length;	/* Leading zeros. */
	} else {		/* Some integer digits, some fraction digits. */
		ndigs = length + pd->exponent;
		ntz = 0;
		ifrac = ndigs;
		nfrac = -pd->exponent;
		nlz = 0;
		while ((pd->ds[ifrac] == '0') && (nfrac != 0)) {
			ifrac++;
			nfrac--;
			nlz++;
		}		/* Remove leading zeros. */
	}
	if (ndigs != 0) {	/* Convert integer digits. */

		bi.bsize = _BIG_FLOAT_SIZE;
		decimal_to_binary_integer(pd->ds, ndigs, ntz, significant_bits, &bi);
		if (bi.bexponent == 0x7fff) {	/* Too big for buffer. */
			px->exponent = 0x000fffff;
			px->significand[0] = 0x80000000;
			goto ret;
		}
		sigint = 16 * (bi.blength + bi.bexponent - 1);
		if (sigint < 0)
			sigint = 0;
	} else {		/* No integer digits. */
		bi.blength = 0;
		bi.bsignificand[0] = 0;
		bi.bexponent = 0;
		sigint = 0;
	}
	frac_bits = significant_bits - sigint + 2;
	bf.blength = 0;
	if ((nfrac != 0) && (frac_bits > 0)) {	/* Convert fraction digits,
						 * even if we only need a
						 * round or sticky.  */

		bf.bsize = _BIG_FLOAT_SIZE;
		decimal_to_binary_fraction(&(pd->ds[ifrac]), nfrac, nlz, (unsigned) frac_bits, &bf);
	} else {		/* Only need fraction bits for sticky. */
		if (nfrac != 0)
			bi.bsignificand[0] |= 1;	/* Stick for fraction. */
	}
	if (bi.blength == 0) {	/* No integer digits; all fraction. */
		if (bf.bexponent == 0x7fff) {	/* Buffer overflowed. */
			px->exponent = -0x000fffff;
			px->significand[0] = 0x80000000;
			goto ret;
		}
		ptounpacked = &bf;	/* Exceptional case - all fraction. */
		goto punpack;
	}
	if (bf.blength != 0) {	/* Combine integer and fraction bits. */
		int             expdiff = bi.bexponent - (bf.bexponent + 16 * (bf.blength - 1));	/* Exponent difference. */
		int             uneeded = 2 + (significant_bits + 2) / 16;	/* Number of big float
										 * digits needed. */
		int             nmove, leftshift, i, if0;

#ifdef DEBUG
		printf(" bi+bf exponent diff is %d \n", expdiff);
		printf(" need %d big float digits \n", uneeded);
		assert(bi.blength != 0);
		assert(bf.blength != 0);
		assert(bi.bsignificand[bi.blength - 1] != 0);	/* Normalized bi. */
		assert(bf.bsignificand[bf.blength - 1] != 0);	/* Normalized bf. */
		assert(bi.bexponent >= 0);	/* bi is all integer */
		assert(((-bf.bexponent - 16 * (bf.blength - 1)) >= 16) ||
		       ((bf.bsignificand[bf.blength - 1] >> (-bf.bexponent - 16 * (bf.blength - 1))) == 0));
		/* assert either bf << 1 or bf < 1 */
		/*
		 * Assert that integer and fraction parts don't overlap by
		 * more than one big digit.
		 */
		assert(expdiff > 0);
		assert(uneeded <= (2 * UNPACKED_SIZE));
#endif


		if (bi.blength >= uneeded) {	/* bi will overflow unpacked,
						 * so bf is just a sticky. */
			bi.bsignificand[0] |= 1;
			goto punpack;
		}
		leftshift = 16 - (expdiff % 16);
		if (leftshift > 0) {	/* shift bf to align with bi. */
			expdiff += 16 * bf.blength;
			_left_shift_base_two(&bf, (short unsigned) leftshift);
			expdiff -= 16 * bf.blength;	/* If bf.blength is
							 * longer, adjust
							 * expdiff. */
		}
		expdiff += leftshift;
		expdiff /= 16;	/* Remaining expdiff in _BIG_FLOAT_DIGITS. */
		expdiff--;
#ifdef DEBUG
		assert(expdiff >= 0);	/* expdiff is now equal to the size
					 * of the hole between bi and bf. */
#endif
		nmove = uneeded - bi.blength;
		/* nmove is the number of words to add to bi. */
		if (nmove < 0)
			nmove = 0;
		if (nmove > (expdiff + bf.blength))
			nmove = (expdiff + bf.blength);
#ifdef DEBUG
		printf(" increase bi by %d words to merge \n", nmove);
#endif
		if (nmove == 0)
			i = -1;
		else
			for (i = (bi.blength - 1 + nmove); i >= nmove; i--)
				bi.bsignificand[i] = bi.bsignificand[i - nmove];
		for (; (i >= 0) && (expdiff > 0); i--) {	/* Fill hole with zeros. */
			expdiff--;
			bi.bsignificand[i] = 0;
		}
		if0 = i;
		for (; i >= 0; i--)
			bi.bsignificand[i] = bf.bsignificand[i + bf.blength - 1 - if0];
		for (i = (bf.blength - 2 - if0); bf.bsignificand[i] == 0; i--);
		/* Find first non-zero. */
		if (i >= 0)
			bi.bsignificand[0] |= 1;	/* If non-zero found,
							 * stick it. */
		bi.blength += nmove;
		bi.bexponent -= 16 * nmove;
		goto punpack;
	}
punpack:
	ptounpacked->bsignificand[0] |= pd->more;	/* Stick in any lost
							 * digits. */

#ifdef DEBUG
	printf(" merged bi and bf: ");
	_display_big_float(ptounpacked, 2);
#endif

	_big_binary_to_unpacked(ptounpacked, px);

ret:
	return;
}

/* PUBLIC FUNCTIONS */

/*
 * decimal_to_floating routines convert the decimal record at *pd to the
 * floating type item at *px, observing the modes specified in *pm and
 * setting exceptions in *ps.
 * 
 * pd->sign and pd->fpclass are always taken into account.
 *
 * pd->exponent, pd->ds and pd->ndigits are used when pd->fpclass is
 * fp_normal or fp_subnormal.  In these cases pd->ds is expected to
 * contain one or more ascii digits followed by a null and pd->ndigits
 * is assumed to be the length of the string pd->ds.  Notice that for
 * efficiency reasons, the assumption that pd->ndigits == strlen(pd->ds)
 * is NEVER verified.
 *
 * px is set to a correctly rounded approximation to
 * (sign)*(ds)*10**(exponent) If pd->more != 0 then additional nonzero digits
 * are assumed to follow those in ds; fp_inexact is set accordingly.
 * 
 * Thus if pd->exponent == -2 and pd->ds = "1234", *px will get 12.34 rounded to
 * storage precision.
 * 
 * px is correctly rounded according to the IEEE rounding modes in pm->rd.  *ps
 * is set to contain fp_inexact, fp_underflow, or fp_overflow if any of these
 * arise.
 * 
 * pm->df and pm->ndigits are never used.
 * 
 */

void
decimal_to_single(px, pm, pd, ps)
	single         *px;
	decimal_mode   *pm;
	decimal_record *pd;
	fp_exception_field_type *ps;
{
	single_equivalence kluge;
	unpacked        u;

	*ps = 0;		/* Initialize to no floating-point
				 * exceptions. */
	kluge.f.msw.sign = pd->sign ? 1 : 0;
	switch (pd->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		break;
	case fp_infinity:
		kluge.f.msw.exponent = 0xff;
		kluge.f.msw.significand = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0xff;
		kluge.f.msw.significand = 0x7fffff;
		break;
	case fp_signaling:
		kluge.f.msw.exponent = 0xff;
		kluge.f.msw.significand = 0x3fffff;
		break;
	default:
		if (pd->exponent > SINGLE_MAXE) {	/* Guaranteed overflow. */
			u.sign = pd->sign == 0 ? 0 : 1;
			u.fpclass = fp_normal;
			u.exponent = 0x000fffff;
			u.significand[0] = 0x80000000;
		} else if (pd->exponent >= -SINGLE_MAXE) {	/* Guaranteed in range. */
			goto inrange;
		} else if (pd->exponent <= (-SINGLE_MAXE - DECIMAL_STRING_LENGTH)) {	/* Guaranteed deep
											 * underflow. */
			goto underflow;
		} else {	/* Deep underflow possible, depending on
				 * string length. */
			int             i;

			for (i = 0; (pd->ds[i] != 0) && (i < (-pd->exponent - SINGLE_MAXE)); i++);
			if (i < (-pd->exponent - SINGLE_MAXE)) {	/* Deep underflow */
		underflow:
				u.sign = pd->sign == 0 ? 0 : 1;
				u.fpclass = fp_normal;
				u.exponent = -0x000fffff;
				u.significand[0] = 0x80000000;
			} else {/* In range. */
		inrange:
				decimal_to_unpacked(&u, pd, 24);
			}
		}
		_fp_current_exceptions = 0;
		_fp_current_direction = pm->rd;
		_pack_single(&u, &kluge.x);
		*ps = _fp_current_exceptions;
	}
	*px = kluge.x;
}

void
decimal_to_double(px, pm, pd, ps)
	double         *px;
	decimal_mode   *pm;
	decimal_record *pd;
	fp_exception_field_type *ps;
{
	double_equivalence kluge;
	unpacked        u;

	*ps = 0;		/* Initialize to no floating-point
				 * exceptions. */
	kluge.f.msw.sign = pd->sign ? 1 : 0;
	switch (pd->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_infinity:
		kluge.f.msw.exponent = 0x7ff;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0x7ff;
		kluge.f.msw.significand = 0xfffff;
		kluge.f.significand2 = 0xffffffff;
		break;
	case fp_signaling:
		kluge.f.msw.exponent = 0x7ff;
		kluge.f.msw.significand = 0x7ffff;
		kluge.f.significand2 = 0xffffffff;
		break;
	default:
		if (pd->exponent > DOUBLE_MAXE) {	/* Guaranteed overflow. */
			u.sign = pd->sign == 0 ? 0 : 1;
			u.fpclass = fp_normal;
			u.exponent = 0x000fffff;
			u.significand[0] = 0x80000000;
		} else if (pd->exponent >= -DOUBLE_MAXE) {	/* Guaranteed in range. */
			goto inrange;
		} else if (pd->exponent <= (-DOUBLE_MAXE - DECIMAL_STRING_LENGTH)) {	/* Guaranteed deep
											 * underflow. */
			goto underflow;
		} else {	/* Deep underflow possible, depending on
				 * string length. */
			int             i;

			for (i = 0; (pd->ds[i] != 0) && (i < (-pd->exponent - DOUBLE_MAXE)); i++);
			if (i < (-pd->exponent - DOUBLE_MAXE)) {	/* Deep underflow */
		underflow:
				u.sign = pd->sign == 0 ? 0 : 1;
				u.fpclass = fp_normal;
				u.exponent = -0x000fffff;
				u.significand[0] = 0x80000000;
			} else {/* In range. */
		inrange:
				decimal_to_unpacked(&u, pd, 53);
			}
		}
		_fp_current_exceptions = 0;
		_fp_current_direction = pm->rd;
		_pack_double(&u, &kluge.x);
		*ps = _fp_current_exceptions;
	}
	*px = kluge.x;
}

void
decimal_to_extended(px, pm, pd, ps)
	extended       *px;
	decimal_mode   *pm;
	decimal_record *pd;
	fp_exception_field_type *ps;
{
	extended_equivalence kluge;
	unpacked        u;

	*ps = 0;		/* Initialize to no floating-point
				 * exceptions. */
	kluge.f.msw.sign = pd->sign ? 1 : 0;
	switch (pd->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_infinity:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.significand = 0;
		kluge.f.significand2 = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.significand = 0xffffffff;
		kluge.f.significand2 = 0xffffffff;
		break;
	case fp_signaling:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.significand = 0x3fffffff;
		kluge.f.significand2 = 0xffffffff;
		break;
	default:
		if (pd->exponent > EXTENDED_MAXE) {	/* Guaranteed overflow. */
			u.sign = pd->sign == 0 ? 0 : 1;
			u.fpclass = fp_normal;
			u.exponent = 0x000fffff;
			u.significand[0] = 0x80000000;
		} else if (pd->exponent >= -EXTENDED_MAXE) {	/* Guaranteed in range. */
			goto inrange;
		} else if (pd->exponent <= (-EXTENDED_MAXE - DECIMAL_STRING_LENGTH)) {	/* Guaranteed deep
											 * underflow. */
			goto underflow;
		} else {	/* Deep underflow possible, depending on
				 * string length. */
			int             i;

			for (i = 0; (pd->ds[i] != 0) && (i < (-pd->exponent - EXTENDED_MAXE)); i++);
			if (i < (-pd->exponent - EXTENDED_MAXE)) {	/* Deep underflow */
		underflow:
				u.sign = pd->sign == 0 ? 0 : 1;
				u.fpclass = fp_normal;
				u.exponent = -0x000fffff;
				u.significand[0] = 0x80000000;
			} else {/* In range. */
		inrange:
				decimal_to_unpacked(&u, pd, 64);
			}
		}
		_fp_current_exceptions = 0;
		_fp_current_direction = pm->rd;
		_fp_current_precision = fp_extended;
		_pack_extended(&u, px);
		*ps = _fp_current_exceptions;
		return;
	}
	(*px)[0] = kluge.x[0];
	(*px)[1] = kluge.x[1];
	(*px)[2] = kluge.x[2];
}

void
decimal_to_quadruple(px, pm, pd, ps)
	quadruple      *px;
	decimal_mode   *pm;
	decimal_record *pd;
	fp_exception_field_type *ps;
{
	quadruple_equivalence kluge;
	unpacked        u;
	int             i;

	*ps = 0;		/* Initialize to no floating-point
				 * exceptions. */
	kluge.f.msw.sign = pd->sign ? 1 : 0;
	switch (pd->fpclass) {
	case fp_zero:
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		kluge.f.significand3 = 0;
		kluge.f.significand4 = 0;
		break;
	case fp_infinity:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		kluge.f.significand3 = 0;
		kluge.f.significand4 = 0;
		break;
	case fp_quiet:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.msw.significand = 0xffff;
		kluge.f.significand2 = 0xffffffff;
		kluge.f.significand3 = 0xffffffff;
		kluge.f.significand4 = 0xffffffff;
		break;
	case fp_signaling:
		kluge.f.msw.exponent = 0x7fff;
		kluge.f.msw.significand = 0x7fff;
		kluge.f.significand2 = 0xffffffff;
		kluge.f.significand3 = 0xffffffff;
		kluge.f.significand4 = 0xffffffff;
		break;
	default:
		if (pd->exponent > QUAD_MAXE) {	/* Guaranteed overflow. */
			u.sign = pd->sign == 0 ? 0 : 1;
			u.fpclass = fp_normal;
			u.exponent = 0x000fffff;
			u.significand[0] = 0x80000000;
		} else if (pd->exponent >= -QUAD_MAXE) {	/* Guaranteed in range. */
			goto inrange;
		} else if (pd->exponent <= (-QUAD_MAXE - DECIMAL_STRING_LENGTH)) {	/* Guaranteed deep
											 * underflow. */
			goto underflow;
		} else {	/* Deep underflow possible, depending on
				 * string length. */

			for (i = 0; (pd->ds[i] != 0) && (i < (-pd->exponent - QUAD_MAXE)); i++);
			if (i < (-pd->exponent - QUAD_MAXE)) {	/* Deep underflow */
		underflow:
				u.sign = pd->sign == 0 ? 0 : 1;
				u.fpclass = fp_normal;
				u.exponent = -0x000fffff;
				u.significand[0] = 0x80000000;
			} else {/* In range. */
		inrange:
				decimal_to_unpacked(&u, pd, 113);
			}
		}
		_fp_current_exceptions = 0;
		_fp_current_direction = pm->rd;
		_pack_quadruple(&u, px);
		*ps = _fp_current_exceptions;
		return;
	}
#ifdef __STDC__
	*px = kluge.x;
#else
	for (i = 0; i < 4; i++)
		px->u[i] = kluge.x.u[i];
#endif
}

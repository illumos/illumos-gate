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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Conversion from decimal to binary floating point
 */

#include "lint.h"
#include <stdlib.h>
#include "base_conversion.h"

/*
 * Convert the integer part of a nonzero base-10^4 _big_float *pd
 * to base 2^16 in **ppb.  The converted value is accurate to nsig
 * significant bits.  On exit, *sticky is nonzero if *pd had a
 * nonzero fractional part.  If pd->exponent > 0 and **ppb is not
 * large enough to hold the final converted value (i.e., the con-
 * verted significand scaled by 10^pd->exponent), then on exit,
 * *ppb will point to a newly allocated _big_float, which must be
 * freed by the caller.  (The number of significant bits we need
 * should fit in pb, but __big_float_times_power may allocate new
 * storage anyway because the exact product could require more than
 * 16000 bits.)
 *
 * This routine does not check that **ppb is large enough to hold
 * the result of converting the significand of *pd.
 */
static void
__big_decimal_to_big_binary(_big_float *pd, int nsig, _big_float **ppb,
    int *sticky)
{
	_big_float	*pb;
	int		i, j, len, s;
	unsigned int	carry;

	pb = *ppb;

	/* convert pd a digit at a time, most significant first */
	if (pd->bexponent + ((pd->blength - 1) << 2) >= 0) {
		pb->bsignificand[0] = pd->bsignificand[pd->blength - 1];
		len = 1;
		for (i = pd->blength - 2; i >= 0 &&
		    pd->bexponent + (i << 2) >= 0; i--) {
			/* multiply pb by 10^4 and add next digit */
			carry = pd->bsignificand[i];
			for (j = 0; j < len; j++) {
				carry += (unsigned int)pb->bsignificand[j]
				    * 10000;
				pb->bsignificand[j] = carry & 0xffff;
				carry >>= 16;
			}
			if (carry)
				pb->bsignificand[j++] = carry;
			len = j;
		}
	} else {
		i = pd->blength - 1;
		len = 0;
	}

	/* convert any partial digit */
	if (i >= 0 && pd->bexponent + (i << 2) > -4) {
		s = pd->bexponent + (i << 2) + 4;
		/* multiply pb by 10^s and add partial digit */
		carry = pd->bsignificand[i];
		if (s == 1) {
			s = carry % 1000;
			carry = carry / 1000;
			for (j = 0; j < len; j++) {
				carry += (unsigned int)pb->bsignificand[j]
				    * 10;
				pb->bsignificand[j] = carry & 0xffff;
				carry >>= 16;
			}
		} else if (s == 2) {
			s = carry % 100;
			carry = carry / 100;
			for (j = 0; j < len; j++) {
				carry += (unsigned int)pb->bsignificand[j]
				    * 100;
				pb->bsignificand[j] = carry & 0xffff;
				carry >>= 16;
			}
		} else {
			s = carry % 10;
			carry = carry / 10;
			for (j = 0; j < len; j++) {
				carry += (unsigned int)pb->bsignificand[j]
				    * 1000;
				pb->bsignificand[j] = carry & 0xffff;
				carry >>= 16;
			}
		}
		if (carry)
			pb->bsignificand[j++] = carry;
		len = j;
		i--;
	} else {
		s = 0;
	}

	pb->blength = len;
	pb->bexponent = 0;

	/* continue accumulating sticky flag */
	while (i >= 0)
		s |= pd->bsignificand[i--];
	*sticky = s;

	if (pd->bexponent > 0) {
		/* scale pb by 10^pd->exponent */
		__big_float_times_power(pb, 10, pd->bexponent, nsig, ppb);
	}
}

/*
 * Convert the decimal_record *pd to an unpacked datum *px accurately
 * enough that *px can be rounded correctly to sigbits significant bits.
 * (We may assume sigbits <= 113.)
 */
static void
__decimal_to_unpacked(unpacked *px, decimal_record *pd, int sigbits)
{
	_big_float	d, b, *pbd, *pbb;
	char		*ds;
	int		ids, i, ix, exp, ndigs;
	int		sticky, powtwo, sigdigits;

	px->sign = pd->sign;
	px->fpclass = pd->fpclass;
	ds = pd->ds;
	ndigs = pd->ndigits;
	exp = pd->exponent;

	/* remove trailing zeroes */
	while (ndigs > 0 && ds[ndigs - 1] == '0') {
		exp++;
		ndigs--;
	}
	if (ndigs < 1) {
		/* nothing left */
		px->fpclass = fp_zero;
		return;
	}

	/* convert remaining digits to a base-10^4 _big_float */
	d.bsize = _BIG_FLOAT_SIZE;
	d.bexponent = exp;
	d.blength = (ndigs + 3) >> 2;
	i = d.blength - 1;
	ids = ndigs - (d.blength << 2);
	switch (ids) {
	case -1:
		d.bsignificand[i] = 100 * ds[ids + 1] +
		    10 * ds[ids + 2] + ds[ids + 3] - 111 * '0';
		i--;
		ids += 4;
		break;

	case -2:
		d.bsignificand[i] = 10 * ds[ids + 2] + ds[ids + 3] - 11 * '0';
		i--;
		ids += 4;
		break;

	case -3:
		d.bsignificand[i] = ds[ids + 3] - '0';
		i--;
		ids += 4;
		break;
	}
	while (i >= 0) {
		d.bsignificand[i] = 1000 * ds[ids] + 100 * ds[ids + 1] +
		    10 * ds[ids + 2] + ds[ids + 3] - 1111 * '0';
		i--;
		ids += 4;
	}

	pbd = &d;
	powtwo = 0;

	/* pre-scale to get the bits we want into the integer part */
	if (exp < 0) {
		/* i is a lower bound on log10(x) */
		i = exp + ndigs - 1;
		if (i <= 0 || ((i * 217705) >> 16) < sigbits + 2) {
			/*
			 * Scale by 2^(sigbits + 2 + u) where
			 * u is an upper bound on -log2(x).
			 */
			powtwo = sigbits + 2;
			if (i < 0)
				powtwo += ((-i * 217706) + 65535) >> 16;
			else if (i > 0)
				powtwo -= (i * 217705) >> 16;
			/*
			 * Take sigdigits large enough to get
			 * all integral digits correct.
			 */
			sigdigits = i + 1 + (((powtwo * 19729) + 65535) >> 16);
			__big_float_times_power(&d, 2, powtwo, sigdigits, &pbd);
		}
	}

	/* convert to base 2^16 */
	b.bsize = _BIG_FLOAT_SIZE;
	pbb = &b;
	__big_decimal_to_big_binary(pbd, sigbits + 2, &pbb, &sticky);

	/* adjust pbb->bexponent based on the scale factor above */
	pbb->bexponent -= powtwo;

	/* convert to unpacked */
	ix = 0;
	for (i = pbb->blength - 1; i > 0 && ix < 5; i -= 2) {
		px->significand[ix++] = (pbb->bsignificand[i] << 16) |
		    pbb->bsignificand[i - 1];
	}
	if (ix < 5) {
		/* pad with zeroes */
		if (i == 0)
			px->significand[ix++] = pbb->bsignificand[i] << 16;
		while (ix < 5)
			px->significand[ix++] = 0;
	} else {
		/* truncate and set a sticky bit if necessary */
		while (i >= 0 && pbb->bsignificand[i] == 0)
			i--;
		if (i >= 0)
			px->significand[4] |= 1;
	}
	if (sticky | pd->more)
		px->significand[4] |= 1;
	px->exponent = pbb->bexponent + (pbb->blength << 4) - 1;

	/* normalize so the most significant bit is set */
	while (px->significand[0] < 0x80000000u) {
		px->significand[0] = (px->significand[0] << 1) |
		    (px->significand[1] >> 31);
		px->significand[1] = (px->significand[1] << 1) |
		    (px->significand[2] >> 31);
		px->significand[2] = (px->significand[2] << 1) |
		    (px->significand[3] >> 31);
		px->significand[3] = (px->significand[3] << 1) |
		    (px->significand[4] >> 31);
		px->significand[4] <<= 1;
		px->exponent--;
	}

	if (pbd != &d)
		(void) free((void *)pbd);
	if (pbb != &b)
		(void) free((void *)pbb);
}

/*
 * Convert a string s consisting of n <= 18 ASCII decimal digits
 * to an integer value in double precision format, and set *pe
 * to the number of rounding errors incurred (0 or 1).
 */
static double
__digits_to_double(char *s, int n, int *pe)
{
	int	i, acc;
	double	t, th, tl;

	if (n <= 9) {
		acc = s[0] - '0';
		for (i = 1; i < n; i++) {
			/* acc <- 10 * acc + next digit */
			acc = (acc << 1) + (acc << 3) + s[i] - '0';
		}
		t = (double)acc;
		*pe = 0;
	} else {
		acc = s[0] - '0';
		for (i = 1; i < (n - 9); i++) {
			/* acc <- 10 * acc + next digit */
			acc = (acc << 1) + (acc << 3) + s[i] - '0';
		}
		th = 1.0e9 * (double)acc;	/* this will be exact */
		acc = s[n - 9] - '0';
		for (i = n - 8; i < n; i++) {
			/* acc <- 10 * acc + next digit */
			acc = (acc << 1) + (acc << 3) + s[i] - '0';
		}
		tl = (double)acc;
		/* add and indicate whether or not the sum is exact */
		t = th + tl;
		*pe = ((t - th) == tl)? 0 : 1;
	}
	return (t);
}

static union {
	int	i[2];
	double	d;
} C[] = {
#ifdef _LITTLE_ENDIAN
	{ 0x00000000, 0x3cc40000 },
#else
	{ 0x3cc40000, 0x00000000 },	/* 5 * 2^-53 */
#endif
};

#define	five2m53	C[0].d

static int
__fast_decimal_to_single(single *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	double			dds, delta, ddsplus, ddsminus, df1;
	int			n, exp, rounded, e;
	float			f1, f2;
	__ieee_flags_type	fb;

	if (pm->rd != fp_nearest)
		return (0);

	exp = pd->exponent;
	if (pd->ndigits <= 18) {
		rounded = 0;
		n = pd->ndigits;
	} else {
		rounded = 1;
		n = 18;
		exp += pd->ndigits - 18;
	}
	/*
	 * exp must be in the range of the table, and the result
	 * must not underflow or overflow.
	 */
	if (exp < -__TBL_TENS_MAX || exp + n < -36 || exp + n > 38)
		return (0);

	__get_ieee_flags(&fb);
	dds = __digits_to_double(pd->ds, n, &e);
	if (e != 0)
		rounded = 1;
	if (exp > 0) {
		/* small positive exponent */
		if (exp > __TBL_TENS_EXACT)
			rounded = 1;
		if (rounded) {
			dds *= __tbl_tens[exp];
		} else {
			dds = __mul_set(dds, __tbl_tens[exp], &e);
			if (e)
				rounded = 1;
		}
	} else if (exp < 0) {
		/* small negative exponent */
		if (-exp > __TBL_TENS_EXACT)
			rounded = 1;
		if (rounded) {
			dds /= __tbl_tens[-exp];
		} else {
			dds = __div_set(dds, __tbl_tens[-exp], &e);
			if (e)
				rounded = 1;
		}
	}

	/*
	 * At this point dds may have four rounding errors due to
	 * (i) truncation of pd->ds to 18 digits, (ii) inexact con-
	 * version of pd->ds to binary, (iii) scaling by a power of
	 * ten that is not exactly representable, and (iv) roundoff
	 * error in the multiplication.  Below we will incur one more
	 * rounding error when we add or subtract delta and dds.  We
	 * construct delta so that even after this last rounding error,
	 * ddsplus is an upper bound on the exact value and ddsminus
	 * is a lower bound.  Then as long as both of these quantities
	 * round to the same single precision number, that number
	 * will be the correctly rounded single precision result.
	 * (If any rounding errors have been committed, then we must
	 * also be certain that the result can't be exact.)
	 */
	delta = five2m53 * dds;
	ddsplus = dds + delta;
	ddsminus = dds - delta;
	f1 = (float)(ddsplus);
	f2 = (float)(ddsminus);
	df1 = f1;
	__set_ieee_flags(&fb);
	if (f1 != f2)
		return (0);
	if (rounded) {
		/*
		 * If ddsminus <= f1 <= ddsplus, the result might be
		 * exact; we have to convert the long way to be sure.
		 */
		if (ddsminus <= df1 && df1 <= ddsplus)
			return (0);
		*ps = (1 << fp_inexact);
	} else {
		*ps = (df1 == dds)? 0 : (1 << fp_inexact);
	}
	*px = (pd->sign)? -f1 : f1;
	return (1);
}

/*
 * Attempt conversion to double using floating-point arithmetic.
 * Return 1 if it works (at most one rounding error), 0 if it doesn't.
 */
static int
__fast_decimal_to_double(double *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	double			dds;
	int			e;
	__ieee_flags_type	fb;

	if (pm->rd != fp_nearest || pd->ndigits > 18 || pd->exponent
	    > __TBL_TENS_EXACT || pd->exponent < -__TBL_TENS_EXACT)
		return (0);

	__get_ieee_flags(&fb);
	dds = __digits_to_double(pd->ds, pd->ndigits, &e);
	if (e != 0) {
		__set_ieee_flags(&fb);
		return (0);
	}
	if (pd->exponent > 0)
		dds = __mul_set(dds, __tbl_tens[pd->exponent], &e);
	else if (pd->exponent < 0)
		dds = __div_set(dds, __tbl_tens[-pd->exponent], &e);
	*px = (pd->sign)? -dds : dds;
	*ps = (e)? (1 << fp_inexact) : 0;
	__set_ieee_flags(&fb);
	return (1);
}

/* PUBLIC FUNCTIONS */

/*
 * The following routines convert the decimal record *pd to a floating
 * point value *px observing the rounding mode specified in pm->rd and
 * passing back any floating point exceptions that occur in *ps.
 *
 * pd->sign and pd->fpclass are always taken into account.  pd->exponent
 * and pd->ds are used when pd->fpclass is fp_normal or fp_subnormal.
 * In these cases, pd->ds must contain a null-terminated string of one
 * or more ASCII digits, the first of which is not zero, and pd->ndigits
 * must equal the length of this string.  If m is the integer represented
 * by the string pd->ds, then *px will be set to a correctly rounded
 * approximation to
 *
 *   -1**(pd->sign) * m * 10**(pd->exponent)
 *
 * (If pd->more != 0 then additional nonzero digits are assumed to follow
 * those in pd->ds, so m is effectively replaced by m + epsilon in the
 * expression above.)
 *
 * For example, if pd->exponent == -2 and pd->ds holds "1234", then *px
 * will be a correctly rounded approximation to 12.34.
 *
 * Note that the only mode that matters is the rounding direction pm->rd;
 * pm->df and pm->ndigits are never used.
 */

/* maximum decimal exponent we need to consider */
#define	SINGLE_MAXE	  47
#define	DOUBLE_MAXE	 326
#define	EXTENDED_MAXE	4968
#define	QUAD_MAXE	4968

void
decimal_to_single(single *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	single_equivalence	*kluge;
	unpacked		u;
	fp_exception_field_type	ef;
	int			i;

	/* special values */
	kluge = (single_equivalence *)px;
	switch (pd->fpclass) {
	case fp_zero:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0;
		kluge->f.msw.significand = 0;
		*ps = 0;
		return;

	case fp_infinity:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0xff;
		kluge->f.msw.significand = 0;
		*ps = 0;
		return;

	case fp_quiet:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0xff;
		kluge->f.msw.significand = 0x7fffff;
		*ps = 0;
		return;

	case fp_signaling:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0xff;
		kluge->f.msw.significand = 0x3fffff;
		*ps = 0;
		return;
	}

	/* numeric values */
	ef = 0;
	if (pd->exponent + pd->ndigits > SINGLE_MAXE) {
		/* result must overflow */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = 0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else if (pd->exponent + pd->ndigits < -SINGLE_MAXE) {
		/* result must underflow completely */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = -0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else {
		/* result may be in range */
		if (__fast_decimal_to_single(px, pm, pd, &ef) == 1) {
			*ps = ef;
			if (ef != 0)
				__base_conversion_set_exception(ef);
			return;
		}
		__decimal_to_unpacked(&u, pd, 24);
	}
	__pack_single(&u, px, pm->rd, &ef);
	*ps = ef;
	if (ef != 0)
		__base_conversion_set_exception(ef);
}

void
decimal_to_double(double *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	double_equivalence	*kluge;
	unpacked		u;
	fp_exception_field_type	ef;
	int			i;

	/* special values */
	kluge = (double_equivalence *)px;
	switch (pd->fpclass) {
	case fp_zero:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0;
		kluge->f.msw.significand = 0;
		kluge->f.significand2 = 0;
		*ps = 0;
		return;

	case fp_infinity:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7ff;
		kluge->f.msw.significand = 0;
		kluge->f.significand2 = 0;
		*ps = 0;
		return;

	case fp_quiet:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7ff;
		kluge->f.msw.significand = 0xfffff;
		kluge->f.significand2 = 0xffffffff;
		*ps = 0;
		return;

	case fp_signaling:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7ff;
		kluge->f.msw.significand = 0x7ffff;
		kluge->f.significand2 = 0xffffffff;
		*ps = 0;
		return;
	}

	/* numeric values */
	ef = 0;
	if (pd->exponent + pd->ndigits > DOUBLE_MAXE) {
		/* result must overflow */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = 0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else if (pd->exponent + pd->ndigits < -DOUBLE_MAXE) {
		/* result must underflow completely */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = -0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else {
		/* result may be in range */
		if (__fast_decimal_to_double(px, pm, pd, &ef) == 1) {
			*ps = ef;
			if (ef != 0)
				__base_conversion_set_exception(ef);
			return;
		}
		__decimal_to_unpacked(&u, pd, 53);
	}
	__pack_double(&u, px, pm->rd, &ef);
	*ps = ef;
	if (ef != 0)
		__base_conversion_set_exception(ef);
}

void
decimal_to_extended(extended *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	extended_equivalence	*kluge;
	unpacked		u;
	double_equivalence	dd;
	fp_exception_field_type ef;
	int			i;

	/* special values */
	kluge = (extended_equivalence *)px;
	switch (pd->fpclass) {
	case fp_zero:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0;
		kluge->f.significand = 0;
		kluge->f.significand2 = 0;
		*ps = 0;
		return;

	case fp_infinity:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7fff;
		kluge->f.significand = 0x80000000;
		kluge->f.significand2 = 0;
		*ps = 0;
		return;

	case fp_quiet:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7fff;
		kluge->f.significand = 0xffffffff;
		kluge->f.significand2 = 0xffffffff;
		*ps = 0;
		return;

	case fp_signaling:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7fff;
		kluge->f.significand = 0xbfffffff;
		kluge->f.significand2 = 0xffffffff;
		*ps = 0;
		return;
	}

	/* numeric values */
	ef = 0;
	if (pd->exponent + pd->ndigits > EXTENDED_MAXE) {
		/* result must overflow */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = 0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else if (pd->exponent + pd->ndigits < -EXTENDED_MAXE) {
		/* result must underflow completely */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = -0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else {
		/* result may be in range */
		if (__fast_decimal_to_double(&dd.x, pm, pd, &ef) == 1 &&
		    ef == 0) {
			u.sign = dd.f.msw.sign;
			u.fpclass = fp_normal;
			u.exponent = dd.f.msw.exponent - DOUBLE_BIAS;
			u.significand[0] = ((0x100000 |
			    dd.f.msw.significand) << 11) |
			    (dd.f.significand2 >> 21);
			u.significand[1] = dd.f.significand2 << 11;
			for (i = 2; i < UNPACKED_SIZE; i++)
				u.significand[i] = 0;
		} else {
			__decimal_to_unpacked(&u, pd, 64);
		}
	}
	__pack_extended(&u, px, pm->rd, &ef);
	*ps = ef;
	if (ef != 0)
		__base_conversion_set_exception(ef);
}

void
decimal_to_quadruple(quadruple *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	quadruple_equivalence	*kluge;
	unpacked		u;
	double_equivalence	dd;
	fp_exception_field_type ef;
	int			i;

	/* special values */
	kluge = (quadruple_equivalence *)px;
	switch (pd->fpclass) {
	case fp_zero:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0;
		kluge->f.msw.significand = 0;
		kluge->f.significand2 = 0;
		kluge->f.significand3 = 0;
		kluge->f.significand4 = 0;
		*ps = 0;
		return;

	case fp_infinity:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7fff;
		kluge->f.msw.significand = 0;
		kluge->f.significand2 = 0;
		kluge->f.significand3 = 0;
		kluge->f.significand4 = 0;
		*ps = 0;
		return;

	case fp_quiet:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7fff;
		kluge->f.msw.significand = 0xffff;
		kluge->f.significand2 = 0xffffffff;
		kluge->f.significand3 = 0xffffffff;
		kluge->f.significand4 = 0xffffffff;
		*ps = 0;
		return;

	case fp_signaling:
		kluge->f.msw.sign = (pd->sign)? 1 : 0;
		kluge->f.msw.exponent = 0x7fff;
		kluge->f.msw.significand = 0x7fff;
		kluge->f.significand2 = 0xffffffff;
		kluge->f.significand3 = 0xffffffff;
		kluge->f.significand4 = 0xffffffff;
		*ps = 0;
		return;
	}

	/* numeric values */
	ef = 0;
	if (pd->exponent + pd->ndigits > QUAD_MAXE) {
		/* result must overflow */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = 0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else if (pd->exponent + pd->ndigits < -QUAD_MAXE) {
		/* result must underflow completely */
		u.sign = (pd->sign != 0);
		u.fpclass = fp_normal;
		u.exponent = -0x000fffff;
		u.significand[0] = 0x80000000;
		for (i = 1; i < UNPACKED_SIZE; i++)
			u.significand[i] = 0;
	} else {
		/* result may be in range */
		if (__fast_decimal_to_double(&dd.x, pm, pd, &ef) == 1 &&
		    ef == 0) {
			u.sign = dd.f.msw.sign;
			u.fpclass = fp_normal;
			u.exponent = dd.f.msw.exponent - DOUBLE_BIAS;
			u.significand[0] = ((0x100000 |
			    dd.f.msw.significand) << 11) |
			    (dd.f.significand2 >> 21);
			u.significand[1] = dd.f.significand2 << 11;
			for (i = 2; i < UNPACKED_SIZE; i++)
				u.significand[i] = 0;
		} else {
			__decimal_to_unpacked(&u, pd, 113);
		}
	}
	__pack_quadruple(&u, px, pm->rd, &ef);
	*ps = ef;
	if (ef != 0)
		__base_conversion_set_exception(ef);
}

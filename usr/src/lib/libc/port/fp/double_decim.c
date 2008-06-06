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
 * Conversion from binary to decimal floating point
 */

#include "lint.h"
#include <stdlib.h>
#include "base_conversion.h"

/*
 * Any sensible programmer would inline the following routine where
 * it is used below.  Unfortunately, the Sun SPARC compilers are not
 * consistent in generating efficient code for this, so inlining it
 * as written can cause the *_to_decimal functions to take twice as
 * long in some cases.
 *
 * We might be tempted, then, to rewrite the source to match the most
 * efficient code the compilers generate and inline that.  Alas, the
 * most efficient code on SPARC uses 32x32->64 bit multiply, which
 * can't be expressed directly in source code.  We could use long long,
 * which would imply 64x64->64 bit multiply; this would work perfectly
 * well on SPARC in v8plus mode.  But as of Solaris 10, libc for SPARC
 * is still built in v8 mode, and of course, x86 is another story.
 *
 * We could also choose to use an inline template to get the most
 * efficient code without incurring the full cost of a function call.
 * Since I expect that would not buy much performance gain, and I
 * prefer to avoid using inline templates for things that can be
 * written in a perfectly straightforward way in C, I've settled
 * for this implementation.  I hope that someday the compilers will
 * get less flaky and/or someone will come up with a better way to
 * do this.
 */
static unsigned int
__quorem10000(unsigned int x, unsigned short *pr)
{
	*pr = x % 10000;
	return (x / 10000);
}

/*
 * Convert the integer part of a nonzero base-2^16 _big_float *pb
 * to base 10^4 in **ppd.  The converted value is accurate to nsig
 * significant digits.  On exit, *sticky is nonzero if *pb had a
 * nonzero fractional part.  If pb->exponent > 0 and **ppd is not
 * large enough to hold the final converted value (i.e., the con-
 * verted significand scaled by 2^pb->exponent), then on exit,
 * *ppd will point to a newly allocated _big_float, which must be
 * freed by the caller.  (The number of significant digits we need
 * should fit in pd, but __big_float_times_power may allocate new
 * storage anyway because we could be multiplying by as much as
 * 2^16271, which would require more than 4000 digits.)
 *
 * This routine does not check that **ppd is large enough to hold
 * the result of converting the significand of *pb.
 */
static void
__big_binary_to_big_decimal(_big_float *pb, int nsig, _big_float **ppd,
    int *sticky)
{
	_big_float	*pd;
	int		i, j, len, s;
	unsigned int	carry;

	pd = *ppd;

	/* convert pb a digit at a time, most significant first */
	if (pb->bexponent + ((pb->blength - 1) << 4) >= 0) {
		carry = pb->bsignificand[pb->blength - 1];
		pd->bsignificand[1] = __quorem10000(carry,
		    &pd->bsignificand[0]);
		len = (pd->bsignificand[1])? 2 : 1;
		for (i = pb->blength - 2; i >= 0 &&
		    pb->bexponent + (i << 4) >= 0; i--) {
			/* multiply pd by 2^16 and add next digit */
			carry = pb->bsignificand[i];
			for (j = 0; j < len; j++) {
				carry += (unsigned int)pd->bsignificand[j]
				    << 16;
				carry = __quorem10000(carry,
				    &pd->bsignificand[j]);
			}
			while (carry != 0) {
				carry = __quorem10000(carry,
				    &pd->bsignificand[j]);
				j++;
			}
			len = j;
		}
	} else {
		i = pb->blength - 1;
		len = 0;
	}

	/* convert any partial digit */
	if (i >= 0 && pb->bexponent + (i << 4) > -16) {
		s = pb->bexponent + (i << 4) + 16;
		/* multiply pd by 2^s and add partial digit */
		carry = pb->bsignificand[i] >> (16 - s);
		for (j = 0; j < len; j++) {
			carry += (unsigned int)pd->bsignificand[j] << s;
			carry = __quorem10000(carry, &pd->bsignificand[j]);
		}
		while (carry != 0) {
			carry = __quorem10000(carry, &pd->bsignificand[j]);
			j++;
		}
		len = j;
		s = pb->bsignificand[i] & ((1 << (16 - s)) - 1);
		i--;
	} else {
		s = 0;
	}

	pd->blength = len;
	pd->bexponent = 0;

	/* continue accumulating sticky flag */
	while (i >= 0)
		s |= pb->bsignificand[i--];
	*sticky = s;

	if (pb->bexponent > 0) {
		/* scale pd by 2^pb->bexponent */
		__big_float_times_power(pd, 2, pb->bexponent, nsig, ppd);
	}
}

/*
 * Convert a base-10^4 _big_float *pf to a decimal string in *pd,
 * rounding according to the modes in *pm and recording any exceptions
 * in *ps.  If sticky is nonzero, then additional nonzero digits are
 * assumed to follow those in *pf.  pd->sign must have already been
 * filled in, and pd->fpclass is not modified.  The resulting string
 * is stored in pd->ds, terminated by a null byte.  The length of this
 * string is stored in pd->ndigits, and the corresponding exponent
 * is stored in pd->exponent.  If the converted value is not exact,
 * the inexact flag is set in *ps.
 *
 * When pm->df == fixed_form, we may discover that the result would
 * have more than DECIMAL_STRING_LENGTH - 1 digits.  In this case,
 * we put DECIMAL_STRING_LENGTH - 1 digits into *pd, adjusting both
 * the exponent and the decimal place at which the value is rounded
 * as need be, and we set the overflow flag in *ps.  (Raising overflow
 * is a bug, but we have to do it to maintain backward compatibility.)
 *
 * *pf may be modified.
 */
static void
__big_decimal_to_string(_big_float *pf, int sticky, decimal_mode *pm,
    decimal_record *pd, fp_exception_field_type *ps)
{
	unsigned short	d;
	int		e, er, efirst, elast, i, is, j;
	char		s[4], round;

	/* set e = floor(log10(*pf)) */
	i = pf->blength - 1;
	if (i < 0) {
		e = pf->bexponent = -DECIMAL_STRING_LENGTH - 2;
	} else {
		e = pf->bexponent + (i << 2);
		d = pf->bsignificand[i];
		if (d >= 1000)
			e += 3;
		else if (d >= 100)
			e += 2;
		else if (d >= 10)
			e++;
	}

	/*
	 * Determine the power of ten after which to round and the
	 * powers corresponding to the first and last digits desired
	 * in the result.
	 */
	if (pm->df == fixed_form) {
		/* F format */
		er = -pm->ndigits;
		if (er < 0) {
			efirst = (e >= 0)? e : -1;
			elast = er;
		} else {
			efirst = (e >= er)? e : ((er > 0)? er - 1 : 0);
			elast = 0;
		}

		/* check for possible overflow of pd->ds */
		if (efirst - elast >= DECIMAL_STRING_LENGTH - 1) {
			efirst = e;
			elast = e - DECIMAL_STRING_LENGTH + 2;
			if (er < elast)
				er = elast;
			*ps |= 1 << fp_overflow;
		}
	} else {
		/* E format */
		efirst = e;
		elast = er = e - pm->ndigits + 1;
	}

	/* retrieve digits down to the (er - 1) place */
	is = 0;
	for (e = efirst; e >= pf->bexponent + (pf->blength << 2) &&
	    e >= er - 1; e--)
		pd->ds[is++] = '0';

	i = pf->blength - 1;
	j = 3 - ((e - pf->bexponent) & 3);
	if (j > 0 && e >= er - 1) {
		__four_digits_quick(pf->bsignificand[i], s);
		while (j <= 3 && e >= er - 1) {
			pd->ds[is++] = s[j++];
			e--;
		}
		while (j <= 3)
			sticky |= (s[j++] - '0');
		i--;
	}

	while ((i | (e - er - 2)) >= 0) {  /* i >= 0 && e >= er + 2 */
		__four_digits_quick(pf->bsignificand[i], pd->ds + is);
		is += 4;
		e -= 4;
		i--;
	}

	if (i >= 0) {
		if (e >= er - 1) {
			__four_digits_quick(pf->bsignificand[i], s);
			for (j = 0; e >= er - 1; j++) {
				pd->ds[is++] = s[j];
				e--;
			}
			while (j <= 3)
				sticky |= (s[j++] - '0');
			i--;
		}
	} else {
		while (e-- >= er - 1)
			pd->ds[is++] = '0';
	}

	/* collect rounding information */
	round = pd->ds[--is];
	while (i >= 0)
		sticky |= pf->bsignificand[i--];

	/* add more trailing zeroes if need be */
	for (e = er - 1; e >= elast; e--)
		pd->ds[is++] = '0';

	pd->exponent = elast;
	pd->ndigits = is;
	pd->ds[is] = '\0';

	/* round */
	if (round == '0' && sticky == 0)
		return;

	*ps |= 1 << fp_inexact;

	switch (pm->rd) {
	case fp_nearest:
		if (round < '5' || (round == '5' && sticky == 0 &&
		    (is <= 0 || (pd->ds[is - 1] & 1) == 0)))
			return;
		break;

	case fp_positive:
		if (pd->sign)
			return;
		break;

	case fp_negative:
		if (!pd->sign)
			return;
		break;

	default:
		return;
	}

	/* round up */
	for (i = efirst - er; i >= 0 && pd->ds[i] == '9'; i--)
		pd->ds[i] = '0';
	if (i >= 0) {
		(pd->ds[i])++;
	} else {
		/* rounding carry out has occurred */
		pd->ds[0] = '1';
		if (pm->df == floating_form) {
			pd->exponent++;
		} else if (is == DECIMAL_STRING_LENGTH - 1) {
			pd->exponent++;
			*ps |= 1 << fp_overflow;
		} else {
			if (is > 0)
				pd->ds[is] = '0';
			is++;
			pd->ndigits = is;
			pd->ds[is] = '\0';
		}
	}
}

/*
 * Convert a binary floating point value represented by *pf to a
 * decimal record *pd according to the modes in *pm.  Any exceptions
 * incurred are passed back via *ps.
 */
static void
__bigfloat_to_decimal(_big_float *bf, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	_big_float	*pbf, *pbd, d;
	int		sticky, powten, sigbits, sigdigits, i;

	/*
	 * If pm->ndigits is too large or too small, set the overflow
	 * flag in *ps and do nothing.  (Raising overflow is a bug,
	 * but we have to do it to maintain backward compatibility.)
	 */
	if (pm->ndigits >= DECIMAL_STRING_LENGTH || pm->ndigits <=
	    ((pm->df == floating_form)? 0 : -DECIMAL_STRING_LENGTH)) {
		*ps = 1 << fp_overflow;
		return;
	}

	pbf = bf;
	powten = 0;

	/* pre-scale to get the digits we want into the integer part */
	if (pm->df == fixed_form) {
		/* F format */
		if (pm->ndigits >= 0 && bf->bexponent < 0) {
			/*
			 * Scale by 10^min(-bf->bexponent, pm->ndigits + 1).
			 */
			powten = pm->ndigits + 1;
			if (powten > -bf->bexponent)
				powten = -bf->bexponent;
			/*
			 * Take sigbits large enough to get all integral
			 * digits correct.
			 */
			sigbits = bf->bexponent + (bf->blength << 4) +
			    (((powten * 217706) + 65535) >> 16);
			if (sigbits < 1)
				sigbits = 1;
			__big_float_times_power(bf, 10, powten, sigbits, &pbf);
		}
		sigdigits = DECIMAL_STRING_LENGTH + 1;
	} else {
		/* E format */
		if (bf->bexponent < 0) {
			/* i is a lower bound on log2(x) */
			i = bf->bexponent + ((bf->blength - 1) << 4);
			if (i <= 0 || ((i * 19728) >> 16) < pm->ndigits + 1) {
				/*
				 * Scale by 10^min(-bf->bexponent,
				 * pm->ndigits + 1 + u) where u is
				 * an upper bound on -log10(x).
				 */
				powten = pm->ndigits + 1;
				if (i < 0)
					powten += ((-i * 19729) + 65535) >> 16;
				else if (i > 0)
					powten -= (i * 19728) >> 16;
				if (powten > -bf->bexponent)
					powten = -bf->bexponent;
				/*
				 * Take sigbits large enough to get
				 * all integral digits correct.
				 */
				sigbits = i + 16 +
				    (((powten * 217706) + 65535) >> 16);
				__big_float_times_power(bf, 10, powten,
				    sigbits, &pbf);
			}
		}
		sigdigits = pm->ndigits + 2;
	}

	/* convert to base 10^4 */
	d.bsize = _BIG_FLOAT_SIZE;
	pbd = &d;
	__big_binary_to_big_decimal(pbf, sigdigits, &pbd, &sticky);

	/* adjust pbd->bexponent based on the scale factor above */
	pbd->bexponent -= powten;

	/* convert to ASCII */
	__big_decimal_to_string(pbd, sticky, pm, pd, ps);

	if (pbf != bf)
		(void) free((void *)pbf);
	if (pbd != &d)
		(void) free((void *)pbd);
}

/* remove trailing zeroes from the significand of p */
static void
__shorten(_big_float *p)
{
	int	length = p->blength;
	int	zeros, i;

	/* count trailing zeros */
	for (zeros = 0; zeros < length && p->bsignificand[zeros] == 0; zeros++)
		;
	if (zeros) {
		length -= zeros;
		p->bexponent += zeros << 4;
		for (i = 0; i < length; i++)
			p->bsignificand[i] = p->bsignificand[i + zeros];
		p->blength = length;
	}
}

/*
 * Unpack a normal or subnormal double into a _big_float.
 */
static void
__double_to_bigfloat(double *px, _big_float *pf)
{
	double_equivalence	*x;

	x = (double_equivalence *)px;
	pf->bsize = _BIG_FLOAT_SIZE;
	pf->bexponent = x->f.msw.exponent - DOUBLE_BIAS - 52;
	pf->blength = 4;
	pf->bsignificand[0] = x->f.significand2 & 0xffff;
	pf->bsignificand[1] = x->f.significand2 >> 16;
	pf->bsignificand[2] = x->f.msw.significand & 0xffff;
	pf->bsignificand[3] = x->f.msw.significand >> 16;
	if (x->f.msw.exponent == 0) {
		pf->bexponent++;
		while (pf->bsignificand[pf->blength - 1] == 0)
			pf->blength--;
	} else {
		pf->bsignificand[3] += 0x10;
	}
	__shorten(pf);
}

/*
 * Unpack a normal or subnormal extended into a _big_float.
 */
static void
__extended_to_bigfloat(extended *px, _big_float *pf)
{
	extended_equivalence	*x;

	x = (extended_equivalence *)px;
	pf->bsize = _BIG_FLOAT_SIZE;
	pf->bexponent = x->f.msw.exponent - EXTENDED_BIAS - 63;
	pf->blength = 4;
	pf->bsignificand[0] = x->f.significand2 & 0xffff;
	pf->bsignificand[1] = x->f.significand2 >> 16;
	pf->bsignificand[2] = x->f.significand & 0xffff;
	pf->bsignificand[3] = x->f.significand >> 16;
	if (x->f.msw.exponent == 0) {
		pf->bexponent++;
		while (pf->bsignificand[pf->blength - 1] == 0)
			pf->blength--;
	}
	__shorten(pf);
}

/*
 * Unpack a normal or subnormal quad into a _big_float.
 */
static void
__quadruple_to_bigfloat(quadruple *px, _big_float *pf)
{
	quadruple_equivalence	*x;

	x = (quadruple_equivalence *)px;
	pf->bsize = _BIG_FLOAT_SIZE;
	pf->bexponent = x->f.msw.exponent - QUAD_BIAS - 112;
	pf->bsignificand[0] = x->f.significand4 & 0xffff;
	pf->bsignificand[1] = x->f.significand4 >> 16;
	pf->bsignificand[2] = x->f.significand3 & 0xffff;
	pf->bsignificand[3] = x->f.significand3 >> 16;
	pf->bsignificand[4] = x->f.significand2 & 0xffff;
	pf->bsignificand[5] = x->f.significand2 >> 16;
	pf->bsignificand[6] = x->f.msw.significand;
	if (x->f.msw.exponent == 0) {
		pf->blength = 7;
		pf->bexponent++;
		while (pf->bsignificand[pf->blength - 1] == 0)
			pf->blength--;
	} else {
		pf->blength = 8;
		pf->bsignificand[7] = 1;
	}
	__shorten(pf);
}

/* PUBLIC ROUTINES */

void
single_to_decimal(single *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	single_equivalence	*kluge;
	_big_float		bf;
	fp_exception_field_type	ef;
	double			x;

	kluge = (single_equivalence *)px;
	pd->sign = kluge->f.msw.sign;

	/* decide what to do based on the class of x */
	if (kluge->f.msw.exponent == 0) {	/* 0 or subnormal */
		if (kluge->f.msw.significand == 0) {
			pd->fpclass = fp_zero;
			*ps = 0;
			return;
		} else {
#if defined(__sparc)
			int	i;

			pd->fpclass = fp_subnormal;
			/*
			 * On SPARC, simply converting *px to double
			 * can flush a subnormal value to zero when
			 * nonstandard mode is enabled, so we have
			 * to go through all this nonsense instead.
			 */
			i = *(int *)px;
			x = (double)(i & ~0x80000000);
			if (i < 0)
				x = -x;
			x *= 1.401298464324817070923730e-45; /* 2^-149 */
			ef = 0;
			if (__fast_double_to_decimal(&x, pm, pd, &ef)) {
				__double_to_bigfloat(&x, &bf);
				__bigfloat_to_decimal(&bf, pm, pd, &ef);
			}
			if (ef != 0)
				__base_conversion_set_exception(ef);
			*ps = ef;
			return;
#else
			pd->fpclass = fp_subnormal;
#endif
		}
	} else if (kluge->f.msw.exponent == 0xff) {	/* inf or nan */
		if (kluge->f.msw.significand == 0)
			pd->fpclass = fp_infinity;
		else if (kluge->f.msw.significand >= 0x400000)
			pd->fpclass = fp_quiet;
		else
			pd->fpclass = fp_signaling;
		*ps = 0;
		return;
	} else {
		pd->fpclass = fp_normal;
	}

	ef = 0;
	x = *px;
	if (__fast_double_to_decimal(&x, pm, pd, &ef)) {
		__double_to_bigfloat(&x, &bf);
		__bigfloat_to_decimal(&bf, pm, pd, &ef);
	}
	if (ef != 0)
		__base_conversion_set_exception(ef);
	*ps = ef;
}

void
double_to_decimal(double *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	double_equivalence	*kluge;
	_big_float		bf;
	fp_exception_field_type	ef;

	kluge = (double_equivalence *)px;
	pd->sign = kluge->f.msw.sign;

	/* decide what to do based on the class of x */
	if (kluge->f.msw.exponent == 0) {	/* 0 or subnormal */
		if (kluge->f.msw.significand == 0 &&
		    kluge->f.significand2 == 0) {
			pd->fpclass = fp_zero;
			*ps = 0;
			return;
		} else {
			pd->fpclass = fp_subnormal;
		}
	} else if (kluge->f.msw.exponent == 0x7ff) {	/* inf or nan */
		if (kluge->f.msw.significand == 0 &&
		    kluge->f.significand2 == 0)
			pd->fpclass = fp_infinity;
		else if (kluge->f.msw.significand >= 0x80000)
			pd->fpclass = fp_quiet;
		else
			pd->fpclass = fp_signaling;
		*ps = 0;
		return;
	} else {
		pd->fpclass = fp_normal;
	}

	ef = 0;
	if (__fast_double_to_decimal(px, pm, pd, &ef)) {
		__double_to_bigfloat(px, &bf);
		__bigfloat_to_decimal(&bf, pm, pd, &ef);
	}
	if (ef != 0)
		__base_conversion_set_exception(ef);
	*ps = ef;
}

void
extended_to_decimal(extended *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	extended_equivalence	*kluge;
	_big_float		bf;
	fp_exception_field_type	ef;

	kluge = (extended_equivalence *)px;
	pd->sign = kluge->f.msw.sign;

	/* decide what to do based on the class of x */
	if (kluge->f.msw.exponent == 0) {	/* 0 or subnormal */
		if ((kluge->f.significand | kluge->f.significand2) == 0) {
			pd->fpclass = fp_zero;
			*ps = 0;
			return;
		} else {
			/*
			 * x could be a pseudo-denormal, but the distinction
			 * doesn't matter
			 */
			pd->fpclass = fp_subnormal;
		}
	} else if ((kluge->f.significand & 0x80000000) == 0) {
		/*
		 * In Intel's extended format, if the exponent is
		 * nonzero but the explicit integer bit is zero, this
		 * is an "unsupported format" bit pattern; treat it
		 * like a signaling NaN.
		 */
		pd->fpclass = fp_signaling;
		*ps = 0;
		return;
	} else if (kluge->f.msw.exponent == 0x7fff) {	/* inf or nan */
		if (((kluge->f.significand & 0x7fffffff) |
		    kluge->f.significand2) == 0)
			pd->fpclass = fp_infinity;
		else if ((kluge->f.significand & 0x7fffffff) >= 0x40000000)
			pd->fpclass = fp_quiet;
		else
			pd->fpclass = fp_signaling;
		*ps = 0;
		return;
	} else {
		pd->fpclass = fp_normal;
	}

	ef = 0;
	__extended_to_bigfloat(px, &bf);
	__bigfloat_to_decimal(&bf, pm, pd, &ef);
	if (ef != 0)
		__base_conversion_set_exception(ef);
	*ps = ef;
}

void
quadruple_to_decimal(quadruple *px, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	quadruple_equivalence	*kluge;
	_big_float		bf;
	fp_exception_field_type	ef;

	kluge = (quadruple_equivalence *)px;
	pd->sign = kluge->f.msw.sign;

	/* decide what to do based on the class of x */
	if (kluge->f.msw.exponent == 0) {	/* 0 or subnormal */
		if (kluge->f.msw.significand == 0 &&
		    (kluge->f.significand2 | kluge->f.significand3 |
		    kluge->f.significand4) == 0) {
			pd->fpclass = fp_zero;
			*ps = 0;
			return;
		} else {
			pd->fpclass = fp_subnormal;
		}
	} else if (kluge->f.msw.exponent == 0x7fff) {	/* inf or nan */
		if (kluge->f.msw.significand == 0 &&
		    (kluge->f.significand2 | kluge->f.significand3 |
		    kluge->f.significand4) == 0)
			pd->fpclass = fp_infinity;
		else if (kluge->f.msw.significand >= 0x8000)
			pd->fpclass = fp_quiet;
		else
			pd->fpclass = fp_signaling;
		*ps = 0;
		return;
	} else {
		pd->fpclass = fp_normal;
	}

	ef = 0;
	__quadruple_to_bigfloat(px, &bf);
	__bigfloat_to_decimal(&bf, pm, pd, &ef);
	if (ef != 0)
		__base_conversion_set_exception(ef);
	*ps = ef;
}

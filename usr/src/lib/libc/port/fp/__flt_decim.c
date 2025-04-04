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

/*
 * Short cut for conversion from double precision to decimal
 * floating point
 */

#include "lint.h"
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "base_conversion.h"

/*
 * Powers of ten rounded up.  If i is the largest index such that
 * tbl_decade[i] <= x, then:
 *
 *  if i == 0 then x < 10^-49
 *  else if i == TBL_DECADE_MAX then x >= 10^67
 *  else 10^(i-TBL_DECADE_OFFSET) <= x < 10^(i-TBL_DECADE_OFFSET+1)
 */

#define	TBL_DECADE_OFFSET	50
#define	TBL_DECADE_MAX		117

static const double tbl_decade[TBL_DECADE_MAX + 1] = {
	0.0,
	1.00000000000000012631e-49, 1.00000000000000012631e-48,
	1.00000000000000009593e-47, 1.00000000000000002300e-46,
	1.00000000000000013968e-45, 1.00000000000000007745e-44,
	1.00000000000000007745e-43, 1.00000000000000003762e-42,
	1.00000000000000000576e-41, 1.00000000000000013321e-40,
	1.00000000000000009243e-39, 1.00000000000000009243e-38,
	1.00000000000000006632e-37, 1.00000000000000010809e-36,
	1.00000000000000000786e-35, 1.00000000000000014150e-34,
	1.00000000000000005597e-33, 1.00000000000000005597e-32,
	1.00000000000000008334e-31, 1.00000000000000008334e-30,
	1.00000000000000008334e-29, 1.00000000000000008334e-28,
	1.00000000000000003849e-27, 1.00000000000000003849e-26,
	1.00000000000000003849e-25, 1.00000000000000010737e-24,
	1.00000000000000010737e-23, 1.00000000000000004860e-22,
	1.00000000000000009562e-21, 1.00000000000000009562e-20,
	1.00000000000000009562e-19, 1.00000000000000007154e-18,
	1.00000000000000007154e-17, 1.00000000000000010236e-16,
	1.00000000000000007771e-15, 1.00000000000000015659e-14,
	1.00000000000000003037e-13, 1.00000000000000018184e-12,
	1.00000000000000010106e-11, 1.00000000000000003643e-10,
	1.00000000000000006228e-09, 1.00000000000000002092e-08,
	1.00000000000000008710e-07, 1.00000000000000016651e-06,
	1.00000000000000008180e-05, 1.00000000000000004792e-04,
	1.00000000000000002082e-03, 1.00000000000000002082e-02,
	1.00000000000000005551e-01, 1.00000000000000000000e+00,
	1.00000000000000000000e+01, 1.00000000000000000000e+02,
	1.00000000000000000000e+03, 1.00000000000000000000e+04,
	1.00000000000000000000e+05, 1.00000000000000000000e+06,
	1.00000000000000000000e+07, 1.00000000000000000000e+08,
	1.00000000000000000000e+09, 1.00000000000000000000e+10,
	1.00000000000000000000e+11, 1.00000000000000000000e+12,
	1.00000000000000000000e+13, 1.00000000000000000000e+14,
	1.00000000000000000000e+15, 1.00000000000000000000e+16,
	1.00000000000000000000e+17, 1.00000000000000000000e+18,
	1.00000000000000000000e+19, 1.00000000000000000000e+20,
	1.00000000000000000000e+21, 1.00000000000000000000e+22,
	1.00000000000000008389e+23, 1.00000000000000011744e+24,
	1.00000000000000009060e+25, 1.00000000000000004765e+26,
	1.00000000000000001329e+27, 1.00000000000000017821e+28,
	1.00000000000000009025e+29, 1.00000000000000001988e+30,
	1.00000000000000007618e+31, 1.00000000000000005366e+32,
	1.00000000000000008969e+33, 1.00000000000000006087e+34,
	1.00000000000000015310e+35, 1.00000000000000004242e+36,
	1.00000000000000007194e+37, 1.00000000000000016638e+38,
	1.00000000000000009082e+39, 1.00000000000000003038e+40,
	1.00000000000000000620e+41, 1.00000000000000004489e+42,
	1.00000000000000001394e+43, 1.00000000000000008821e+44,
	1.00000000000000008821e+45, 1.00000000000000011990e+46,
	1.00000000000000004385e+47, 1.00000000000000004385e+48,
	1.00000000000000007630e+49, 1.00000000000000007630e+50,
	1.00000000000000015937e+51, 1.00000000000000012614e+52,
	1.00000000000000020590e+53, 1.00000000000000007829e+54,
	1.00000000000000001024e+55, 1.00000000000000009190e+56,
	1.00000000000000004835e+57, 1.00000000000000008319e+58,
	1.00000000000000008319e+59, 1.00000000000000012779e+60,
	1.00000000000000009211e+61, 1.00000000000000003502e+62,
	1.00000000000000005786e+63, 1.00000000000000002132e+64,
	1.00000000000000010901e+65, 1.00000000000000013239e+66,
	1.00000000000000013239e+67
};

/*
 * Convert a positive double precision integer x <= 2147483647999999744
 * (the largest double less than 2^31 * 10^9; this implementation works
 * up to the largest double less than 2^25 * 10^12) to a string of ASCII
 * decimal digits, adding leading zeroes so that the result has at least
 * n digits.  The string is terminated by a null byte, and its length
 * is returned.
 *
 * This routine assumes round-to-nearest mode is in effect and any
 * exceptions raised will be ignored.
 */

#define	tenm4	tbl_decade[TBL_DECADE_OFFSET - 4]
#define	ten4	tbl_decade[TBL_DECADE_OFFSET + 4]
#define	tenm12	tbl_decade[TBL_DECADE_OFFSET - 12]
#define	ten12	tbl_decade[TBL_DECADE_OFFSET + 12]
#define	one	tbl_decade[TBL_DECADE_OFFSET]

static int
__double_to_digits(double x, char *s, int n)
{
	double		y;
	int		d[5], i, j;
	char		*ss, tmp[4];

	/* decompose x into four-digit chunks */
	y = (int)(x * tenm12);
	x -= y * ten12;
	if (x < 0.0) {
		y -= one;
		x += ten12;
	}
	d[0] = (int)(y * tenm4);
	d[1] = (int)(y - d[0] * ten4);
	y = (int)(x * tenm4);
	d[4] = (int)(x - y * ten4);
	d[2] = (int)(y * tenm4);
	d[3] = (int)(y - d[2] * ten4);

	/*
	 * Find the first nonzero chunk or the point at which to start
	 * converting so we have n digits, whichever comes first.
	 */
	ss = s;
	if (n > 20) {
		for (j = 0; j < n - 20; j++)
			*ss++ = '0';
		i = 0;
	} else {
		for (i = 0; d[i] == 0 && n <= ((4 - i) << 2); i++)
			;
		__four_digits_quick(d[i], tmp);
		for (j = 0; j < 4 && tmp[j] == '0' &&
		    n <= ((4 - i) << 2) + 3 - j; j++)
			;
		while (j < 4)
			*ss++ = tmp[j++];
		i++;
	}

	/* continue converting four-digit chunks */
	while (i < 5) {
		__four_digits_quick(d[i], ss);
		ss += 4;
		i++;
	}

	*ss = '\0';
	return (ss - s);
}

/*
 * Round a positive double precision number *x to the nearest integer,
 * returning the result and passing back an indication of accuracy in
 * *pe.  On entry, nrx is the number of rounding errors already com-
 * mitted in forming *x.  On exit, *pe is 0 if *x was already integral
 * and exact, 1 if the result is the correctly rounded integer value
 * but not exact, and 2 if error in *x precludes determining the cor-
 * rectly rounded integer value (i.e., the error might be larger than
 * 1/2 - |*x - rx|, where rx is the nearest integer to *x).
 */

static union {
	unsigned int	i[2];
	double		d;
} C[] = {
#ifdef _LITTLE_ENDIAN
	{ 0x00000000, 0x43300000 },
	{ 0x00000000, 0x3ca00000 },
	{ 0x00000000, 0x3fe00000 },
	{ 0xffffffff, 0x3fdfffff },
#else
	{ 0x43300000, 0x00000000 },
	{ 0x3ca00000, 0x00000000 },
	{ 0x3fe00000, 0x00000000 },
	{ 0x3fdfffff, 0xffffffff },	/* nextafter(1/2, 0) */
#endif
};

#define	two52	C[0].d
#define	twom53	C[1].d
#define	half	C[2].d
#define	halfdec	C[3].d

static double
__arint_set_n(double *x, int nrx, int *pe)
{
	int	hx;
	double	rx, rmx;

#ifdef _LITTLE_ENDIAN
	hx = *(1+(int *)x);
#else
	hx = *(int *)x;
#endif
	if (hx >= 0x43300000) {
		/* x >= 2^52, so it's already integral */
		if (nrx == 0)
			*pe = 0;
		else if (nrx == 1 && hx < 0x43400000)
			*pe = 1;
		else
			*pe = 2;
		return (*x);
	} else if (hx < 0x3fe00000) {
		/* x < 1/2 */
		if (nrx > 1 && hx == 0x3fdfffff)
			*pe = (*x == halfdec)? 2 : 1;
		else
			*pe = 1;
		return (0.0);
	}

	rx = (*x + two52) - two52;
	if (nrx == 0) {
		*pe = (rx == *x)? 0 : 1;
	} else {
		rmx = rx - *x;
		if (rmx < 0.0)
			rmx = -rmx;
		*pe = (nrx * twom53 * *x < half - rmx)? 1 : 2;
	}
	return (rx);
}

/*
 * Attempt to convert dd to a decimal record *pd according to the
 * modes in *pm using double precision floating point.  Return zero
 * and sets *ps to reflect any exceptions incurred if successful.
 * Return a nonzero value if unsuccessful.
 */
int
__fast_double_to_decimal(double *dd, decimal_mode *pm, decimal_record *pd,
    fp_exception_field_type *ps)
{
	int			i, is, esum, eround, hd;
	double			dds;
	__ieee_flags_type	fb;

	if (pm->rd != fp_nearest)
		return (1);

	if (pm->df == fixed_form) {
		/* F format */
		if (pm->ndigits < 0 || pm->ndigits > __TBL_TENS_MAX)
			return (1);
		__get_ieee_flags(&fb);
		dds = __dabs(dd);
		esum = 0;
		if (pm->ndigits) {
			/* scale by a positive power of ten */
			if (pm->ndigits > __TBL_TENS_EXACT) {
				dds *= __tbl_tens[pm->ndigits];
				esum = 2;
			} else {
				dds = __mul_set(dds, __tbl_tens[pm->ndigits],
				    &eround);
				esum = eround;
			}
		}
		if (dds > 2147483647999999744.0) {
			__set_ieee_flags(&fb);
			return (1);
		}
		dds = __arint_set_n(&dds, esum, &eround);
		if (eround == 2) {
			/* error is too large to round reliably; punt */
			__set_ieee_flags(&fb);
			return (1);
		}
		if (dds == 0.0) {
			is = (pm->ndigits > 0)? pm->ndigits : 1;
			for (i = 0; i < is; i++)
				pd->ds[i] = '0';
			pd->ds[is] = '\0';
			eround++;
		} else {
			is = __double_to_digits(dds, pd->ds, pm->ndigits);
		}
		pd->ndigits = is;
		pd->exponent = -pm->ndigits;
	} else {
		/* E format */
		if (pm->ndigits < 1 || pm->ndigits > 18)
			return (1);
		__get_ieee_flags(&fb);
		dds = __dabs(dd);
		/* find the decade containing dds */
#ifdef _LITTLE_ENDIAN
		hd = *(1+(int *)dd);
#else
		hd = *(int *)dd;
#endif
		hd = (hd >> 20) & 0x7ff;
		if (hd >= 0x400) {
			if (hd > 0x4e0)
				i = TBL_DECADE_MAX;
			else
				i = TBL_DECADE_MAX - ((0x4e0 - hd) >> 2);
		} else {
			if (hd < 0x358)
				i = 0;
			else
				i = TBL_DECADE_OFFSET - ((0x3ff - hd) >> 2);
		}
		while (dds < tbl_decade[i])
			i--;
		/* determine the power of ten by which to scale */
		i = pm->ndigits - 1 - (i - TBL_DECADE_OFFSET);
		esum = 0;
		if (i > 0) {
			/* scale by a positive power of ten */
			if (i > __TBL_TENS_EXACT) {
				if (i > __TBL_TENS_MAX) {
					__set_ieee_flags(&fb);
					return (1);
				}
				dds *= __tbl_tens[i];
				esum = 2;
			} else {
				dds = __mul_set(dds, __tbl_tens[i], &eround);
				esum = eround;
			}
		} else if (i < 0) {
			/* scale by a negative power of ten */
			if (-i > __TBL_TENS_EXACT) {
				if (-i > __TBL_TENS_MAX) {
					__set_ieee_flags(&fb);
					return (1);
				}
				dds /= __tbl_tens[-i];
				esum = 2;
			} else {
				dds = __div_set(dds, __tbl_tens[-i], &eround);
				esum = eround;
			}
		}
		dds = __arint_set_n(&dds, esum, &eround);
		if (eround == 2) {
			/* error is too large to round reliably; punt */
			__set_ieee_flags(&fb);
			return (1);
		}
		is = __double_to_digits(dds, pd->ds, 1);
		if (is > pm->ndigits) {
			/*
			 * The result rounded up to the next larger power
			 * of ten; just discard the last zero and adjust
			 * the exponent.
			 */
			pd->ds[--is] = '\0';
			i--;
		}
		pd->ndigits = is;
		pd->exponent = -i;
	}
	*ps = (eround == 0)? 0 : (1 << fp_inexact);
	__set_ieee_flags(&fb);
	return (0);
}

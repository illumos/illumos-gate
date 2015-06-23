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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/isa_defs.h>
#include "libm_inlines.h"

#ifdef _LITTLE_ENDIAN
#define HI(x)	*(1+(int*)x)
#define LO(x)	*(unsigned*)x
#else
#define HI(x)	*(int*)x
#define LO(x)	*(1+(unsigned*)x)
#endif

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

/* double hypot(double x, double y)
 *
 * Method :
 *	1. Special cases:
 *		x or y is +Inf or -Inf				=> +Inf
 *		x or y is NaN					=> QNaN
 *	2. Computes hypot(x,y):
 *		hypot(x,y) = m * sqrt(xnm * xnm + ynm * ynm)
 *	Where:
 *		m = max(|x|,|y|)
 *		xnm = x * (1/m)
 *		ynm = y * (1/m)
 *
 *	Compute xnm * xnm + ynm * ynm by simulating
 *	muti-precision arithmetic.
 *
 * Accuracy:
 *	Maximum error observed: less than 0.872 ulp after 16.777.216.000
 *	results.
 */

extern double sqrt(double);
extern double fabs(double);

static const unsigned long long LCONST[] = {
0x41b0000000000000ULL,	/* D2ON28 = 2 ** 28		*/
0x0010000000000000ULL,	/* D2ONM1022 = 2 ** -1022	*/
0x7fd0000000000000ULL	/* D2ONP1022 = 2 **  1022	*/
};

static void
__vhypot_n(int n, double * restrict px, int stridex, double * restrict py,
	int stridey, double * restrict pz, int stridez);

#pragma no_inline(__vhypot_n)

#define RETURN(ret)						\
{								\
	*pz = (ret);						\
	py += stridey;						\
	pz += stridez;						\
	if (n_n == 0)						\
	{							\
		hx0 = HI(px);					\
		hy0 = HI(py);					\
		spx = px; spy = py; spz = pz;			\
		continue;					\
	}							\
	n--;							\
	break;							\
}

void
__vhypot(int n, double * restrict px, int stridex, double * restrict py,
	int stridey, double * restrict pz, int stridez)
{
	int		hx0, hx1, hy0, j0, diff;
	double		x_hi, x_lo, y_hi, y_lo;
	double		scl = 0;
	double		x, y, res;
	double		*spx, *spy, *spz;
	int		n_n;
	double		D2ON28 = ((double*)LCONST)[0];		/* 2 ** 28	*/
	double		D2ONM1022 = ((double*)LCONST)[1];	/* 2 **-1022	*/
	double		D2ONP1022 = ((double*)LCONST)[2];	/* 2 ** 1022	*/

	while (n > 1)
	{
		n_n = 0;
		spx = px;
		spy = py;
		spz = pz;
		hx0 = HI(px);
		hy0 = HI(py);
		for (; n > 1 ; n--)
		{
			px += stridex;
			hx0 &= 0x7fffffff;
			hy0 &= 0x7fffffff;

			if (hx0 >= 0x7fe00000)	/* |X| >= 2**1023 or Inf or NaN */
			{
				diff = hy0 - hx0;
				j0 = diff >> 31;
				j0 = hy0 - (diff & j0);
				j0 &= 0x7ff00000;
				x = *(px - stridex);
				y = *py;
				x = fabs(x);
				y = fabs(y);
				if (j0 >= 0x7ff00000)	/* |X| or |Y| = Inf or NaN */
				{
					int lx = LO((px - stridex));
					int ly = LO(py);
					if (hx0 == 0x7ff00000 && lx == 0) res = x == y ? y : x;
					else if (hy0 == 0x7ff00000 && ly == 0) res = x == y ? x : y;
					else res = x + y;
					RETURN (res)
				}
				else
				{
					j0 = diff >> 31;
					if (((diff ^ j0) - j0) < 0x03600000)	/* max(|X|,|Y|)/min(|X|,|Y|) < 2**54 */
					{
						x *= D2ONM1022;
						y *= D2ONM1022;

						x_hi = (x + D2ON28) - D2ON28;
						x_lo = x - x_hi;
						y_hi = (y + D2ON28) - D2ON28;
						y_lo = y - y_hi;
						res = (x_hi * x_hi + y_hi * y_hi);
						res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);

						res = sqrt (res);

						res = D2ONP1022 * res;
						RETURN (res)
					}
					else RETURN (x + y)
				}
			}
			if (hy0 >= 0x7fe00000)	/* |Y| >= 2**1023 or Inf or NaN */
			{
				diff = hy0 - hx0;
				j0 = diff >> 31;
				j0 = hy0 - (diff & j0);
				j0 &= 0x7ff00000;
				x = *(px - stridex);
				y = *py;
				x = fabs(x);
				y = fabs(y);
				if (j0 >= 0x7ff00000)	/* |X| or |Y| = Inf or NaN */
				{
					int lx = LO((px - stridex));
					int ly = LO(py);
					if (hx0 == 0x7ff00000 && lx == 0) res = x == y ? y : x;
					else if (hy0 == 0x7ff00000 && ly == 0) res = x == y ? x : y;
					else res = x + y;
					RETURN (res)
				}
				else
				{
					j0 = diff >> 31;
					if (((diff ^ j0) - j0) < 0x03600000)	/* max(|X|,|Y|)/min(|X|,|Y|) < 2**54 */
					{
						x *= D2ONM1022;
						y *= D2ONM1022;

						x_hi = (x + D2ON28) - D2ON28;
						x_lo = x - x_hi;
						y_hi = (y + D2ON28) - D2ON28;
						y_lo = y - y_hi;
						res = (x_hi * x_hi + y_hi * y_hi);
						res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);

						res = sqrt (res);

						res = D2ONP1022 * res;
						RETURN (res)
					}
					else RETURN (x + y)
				}
			}

			hx1 = HI(px);

			if (hx0 < 0x00100000 && hy0 < 0x00100000)	/* X and Y are subnormal */
			{
				x = *(px - stridex);
				y = *py;

				x *= D2ONP1022;
				y *= D2ONP1022;

				x_hi = (x + D2ON28) - D2ON28;
				x_lo = x - x_hi;
				y_hi = (y + D2ON28) - D2ON28;
				y_lo = y - y_hi;
				res = (x_hi * x_hi + y_hi * y_hi);
				res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);

				res = sqrt(res);

				res = D2ONM1022 * res;
				RETURN (res)
			}

			hx0 = hx1;
			py += stridey;
			pz += stridez;
			n_n++;
			hy0 = HI(py);
		}
		if (n_n > 0)
			__vhypot_n (n_n, spx, stridex, spy, stridey, spz, stridez);
	}

	if (n > 0)
	{
		x = *px;
		y = *py;
		hx0 = HI(px);
		hy0 = HI(py);

		hx0 &= 0x7fffffff;
		hy0 &= 0x7fffffff;

		diff = hy0 - hx0;
		j0 = diff >> 31;
		j0 = hy0 - (diff & j0);
		j0 &= 0x7ff00000;

		if (j0 >= 0x7fe00000)	/* max(|X|,|Y|) >= 2**1023 or X or Y = Inf or NaN */
		{
			x = fabs(x);
			y = fabs(y);
			if (j0 >= 0x7ff00000)	/* |X| or |Y| = Inf or NaN */
			{
				int lx = LO(px);
				int ly = LO(py);
				if (hx0 == 0x7ff00000 && lx == 0) res = x == y ? y : x;
				else if (hy0 == 0x7ff00000 && ly == 0) res = x == y ? x : y;
				else res = x + y;
				*pz = res;
				return;
			}
			else
			{
				j0 = diff >> 31;
				if (((diff ^ j0) - j0) < 0x03600000)	/* max(|X|,|Y|)/min(|X|,|Y|) < 2**54 */
				{
					x *= D2ONM1022;
					y *= D2ONM1022;

					x_hi = (x + D2ON28) - D2ON28;
					x_lo = x - x_hi;
					y_hi = (y + D2ON28) - D2ON28;
					y_lo = y - y_hi;
					res = (x_hi * x_hi + y_hi * y_hi);
					res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);

					res = sqrt (res);

					res = D2ONP1022 * res;
					*pz = res;
					return;
				}
				else
				{
					*pz = x + y;
					return;
				}
			}
		}

		if (j0 < 0x00100000)	/* X and Y are subnormal */
		{
			x *= D2ONP1022;
			y *= D2ONP1022;

			x_hi = (x + D2ON28) - D2ON28;
			x_lo = x - x_hi;
			y_hi = (y + D2ON28) - D2ON28;
			y_lo = y - y_hi;
			res = (x_hi * x_hi + y_hi * y_hi);
			res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);

			res = sqrt(res);

			res = D2ONM1022 * res;
			*pz = res;
			return;
		}

		HI(&scl) = (0x7fe00000 - j0);

		x *= scl;
		y *= scl;

		x_hi = (x + D2ON28) - D2ON28;
		y_hi = (y + D2ON28) - D2ON28;
		x_lo = x - x_hi;
		y_lo = y - y_hi;

		res = (x_hi * x_hi + y_hi * y_hi);
		res += ((x + x_hi) * x_lo + (y + y_hi) * y_lo);

		res = sqrt(res);

		HI(&scl) = j0;

		res = scl * res;
		*pz = res;
	}
}

static void
__vhypot_n(int n, double * restrict px, int stridex, double * restrict py,
	int stridey, double * restrict pz, int stridez)
{
	int		hx0, hy0, j0, diff0;
	double		x_hi0, x_lo0, y_hi0, y_lo0, scl0 = 0;
	double		x0, y0, res0;
	double		D2ON28 = ((double*)LCONST)[0];		/* 2 ** 28	*/

	for(; n > 0 ; n--)
	{
		x0 = *px;
		y0 = *py;
		hx0 = HI(px);
		hy0 = HI(py);

		hx0 &= 0x7fffffff;
		hy0 &= 0x7fffffff;

		diff0 = hy0 - hx0;
		j0 = diff0 >> 31;
		j0 = hy0 - (diff0 & j0);
		j0 &= 0x7ff00000;

		px += stridex;
		py += stridey;

		HI(&scl0) = (0x7fe00000 - j0);

		x0 *= scl0;
		y0 *= scl0;

		x_hi0 = (x0 + D2ON28) - D2ON28;
		y_hi0 = (y0 + D2ON28) - D2ON28;
		x_lo0 = x0 - x_hi0;
		y_lo0 = y0 - y_hi0;

		res0 = (x_hi0 * x_hi0 + y_hi0 * y_hi0);
		res0 += ((x0 + x_hi0) * x_lo0 + (y0 + y_hi0) * y_lo0);

		res0 = sqrt(res0);

		HI(&scl0) = j0;

		res0 = scl0 * res0;
		*pz = res0;

		pz += stridez;
	}
}

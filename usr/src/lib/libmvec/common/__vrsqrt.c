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

/* double rsqrt(double x)
 *
 * Method :
 *	1. Special cases:
 *		for x = NaN				=> QNaN;
 *		for x = +Inf				=> 0;
 *		for x is negative, -Inf			=> QNaN + invalid;
 *		for x = +0				=> +Inf + divide-by-zero;
 *		for x = -0				=> -Inf + divide-by-zero.
 *	2. Computes reciprocal square root from:
 *		x = m * 2**n
 *	Where:
 *		m = [0.5, 2),
 *		n = ((exponent + 1) & ~1).
 *	Then:
 *		rsqrt(x) = 1/sqrt( m * 2**n ) = (2 ** (-n/2)) * (1/sqrt(m))
 *	2. Computes 1/sqrt(m) from:
 *		1/sqrt(m) = (1/sqrt(m0)) * (1/sqrt(1 + (1/m0)*dm))
 *	Where:
 *		m = m0 + dm,
 *		m0 = 0.5 * (1 + k/64) for m = [0.5,         0.5+127/256), k = [0, 63];
 *		m0 = 1.0 * (0 + k/64) for m = [0.5+127/256, 1.0+127/128), k = [64, 127];
 *		m0 = 2.0              for m = [1.0+127/128, 2.0),         k = 128.
 *	Then:
 *		1/sqrt(m0) is looked up in a table,
 *		1/m0 is computed as (1/sqrt(m0)) * (1/sqrt(m0)).
 *		1/sqrt(1 + (1/m0)*dm) is computed using approximation:
 *			1/sqrt(1 + z) = (((((a6 * z + a5) * z + a4) * z + a3)
 *						* z + a2) * z + a1) * z + a0
 *			where z = [-1/128, 1/128].
 *
 * Accuracy:
 *	The maximum relative error for the approximating
 *	polynomial is 2**(-56.26).
 *	Maximum error observed: less than 0.563 ulp after 1.500.000.000
 *	results.
 */

extern double sqrt (double);
extern const double __vlibm_TBL_rsqrt[];

static void
__vrsqrt_n(int n, double * restrict px, int stridex, double * restrict py, int stridey);

#pragma no_inline(__vrsqrt_n)

#define RETURN(ret)						\
{								\
	*py = (ret);						\
	py += stridey;						\
	if (n_n == 0)						\
	{							\
		spx = px; spy = py;				\
		hx = HI(px);					\
		continue;					\
	}							\
	n--;							\
	break;							\
}

static const double
	DONE = 1.0,
	K1 = -5.00000000000005209867e-01,
	K2 =  3.75000000000004884257e-01,
	K3 = -3.12499999317136886551e-01,
	K4 =  2.73437499359815081532e-01,
	K5 = -2.46116125605037803130e-01,
	K6 =  2.25606914648617522896e-01;

void
__vrsqrt(int n, double * restrict px, int stridex, double * restrict py, int stridey)
{
	double		*spx, *spy;
	int		ax, lx, hx, n_n;
	double		res;

	while (n > 1)
	{
		n_n = 0;
		spx = px;
		spy = py;
		hx = HI(px);
		for (; n > 1 ; n--)
		{
			px += stridex;
			if (hx >= 0x7ff00000)		/* X = NaN or Inf	*/
			{
				res = *(px - stridex);
				RETURN (DONE / res)
			}

			py += stridey;

			if (hx < 0x00100000)		/* X = denormal, zero or negative	*/
			{
				py -= stridey;
				ax = hx & 0x7fffffff;
				lx = LO((px - stridex));
				res = *(px - stridex);

				if ((ax | lx) == 0)	/* |X| = zero	*/
				{
					RETURN (DONE / res)
				}
				else if (hx >= 0)	/* X = denormal	*/
				{
					double		res_c0, dsqrt_exp0;
					int		ind0, sqrt_exp0;
					double		xx0, dexp_hi0, dexp_lo0;
					int		hx0, resh0, res_ch0;

					res = *(long long*)&res;

					hx0 = HI(&res);
					sqrt_exp0 = (0x817 - (hx0 >> 21)) << 20;
					ind0 = (((hx0 >> 10) & 0x7f8) + 8) & -16;

					resh0 = (hx0 & 0x001fffff) | 0x3fe00000;
					res_ch0 = (resh0 + 0x00002000) & 0x7fffc000;
					HI(&res) = resh0;
					HI(&res_c0) = res_ch0;
					LO(&res_c0) = 0;

					dexp_hi0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[0];
					dexp_lo0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[1];
					xx0 = dexp_hi0 * dexp_hi0;
					xx0 = (res - res_c0) * xx0;
					res = (((((K6 * xx0 + K5) * xx0 + K4) * xx0 + K3) * xx0 + K2) * xx0 + K1) * xx0;

					res = dexp_hi0 * res + dexp_lo0 + dexp_hi0;

					HI(&dsqrt_exp0) = sqrt_exp0;
					LO(&dsqrt_exp0) = 0;
					res *= dsqrt_exp0;

					RETURN (res)
				}
				else	/* X = negative	*/
				{
					RETURN (sqrt(res))
				}
			}
			n_n++;
			hx = HI(px);
		}
		if (n_n > 0)
			__vrsqrt_n(n_n, spx, stridex, spy, stridey);
	}
	if (n > 0)
	{
		hx = HI(px);

		if (hx >= 0x7ff00000)		/* X = NaN or Inf	*/
		{
			res = *px;
			*py = DONE / res;
		}
		else if (hx < 0x00100000)	/* X = denormal, zero or negative	*/
		{
			ax = hx & 0x7fffffff;
			lx = LO(px);
			res = *px;

			if ((ax | lx) == 0)	/* |X| = zero	*/
			{
				*py = DONE / res;
			}
			else if (hx >= 0)	/* X = denormal	*/
			{
				double		res_c0, dsqrt_exp0;
				int		ind0, sqrt_exp0;
				double		xx0, dexp_hi0, dexp_lo0;
				int		hx0, resh0, res_ch0;

				res = *(long long*)&res;

				hx0 = HI(&res);
				sqrt_exp0 = (0x817 - (hx0 >> 21)) << 20;
				ind0 = (((hx0 >> 10) & 0x7f8) + 8) & -16;

				resh0 = (hx0 & 0x001fffff) | 0x3fe00000;
				res_ch0 = (resh0 + 0x00002000) & 0x7fffc000;
				HI(&res) = resh0;
				HI(&res_c0) = res_ch0;
				LO(&res_c0) = 0;

				dexp_hi0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[0];
				dexp_lo0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[1];
				xx0 = dexp_hi0 * dexp_hi0;
				xx0 = (res - res_c0) * xx0;
				res = (((((K6 * xx0 + K5) * xx0 + K4) * xx0 + K3) * xx0 + K2) * xx0 + K1) * xx0;

				res = dexp_hi0 * res + dexp_lo0 + dexp_hi0;

				HI(&dsqrt_exp0) = sqrt_exp0;
				LO(&dsqrt_exp0) = 0;
				res *= dsqrt_exp0;

				*py = res;
			}
			else	/* X = negative	*/
			{
				*py = sqrt(res);
			}
		}
		else
		{
			double		res_c0, dsqrt_exp0;
			int		ind0, sqrt_exp0;
			double		xx0, dexp_hi0, dexp_lo0;
			int		resh0, res_ch0;

			sqrt_exp0 = (0x5fe - (hx >> 21)) << 20;
			ind0 = (((hx >> 10) & 0x7f8) + 8) & -16;

			resh0 = (hx & 0x001fffff) | 0x3fe00000;
			res_ch0 = (resh0 + 0x00002000) & 0x7fffc000;
			HI(&res) = resh0;
			LO(&res) = LO(px);
			HI(&res_c0) = res_ch0;
			LO(&res_c0) = 0;

			dexp_hi0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[0];
			dexp_lo0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[1];
			xx0 = dexp_hi0 * dexp_hi0;
			xx0 = (res - res_c0) * xx0;
			res = (((((K6 * xx0 + K5) * xx0 + K4) * xx0 + K3) * xx0 + K2) * xx0 + K1) * xx0;

			res = dexp_hi0 * res + dexp_lo0 + dexp_hi0;

			HI(&dsqrt_exp0) = sqrt_exp0;
			LO(&dsqrt_exp0) = 0;
			res *= dsqrt_exp0;

			*py = res;
		}
	}
}

static void
__vrsqrt_n(int n, double * restrict px, int stridex, double * restrict py, int stridey)
{
	double		res0, res_c0, dsqrt_exp0;
	double		res1, res_c1, dsqrt_exp1;
	double		res2, res_c2, dsqrt_exp2;
	int		ind0, sqrt_exp0;
	int		ind1, sqrt_exp1;
	int		ind2, sqrt_exp2;
	double		xx0, dexp_hi0, dexp_lo0;
	double		xx1, dexp_hi1, dexp_lo1;
	double		xx2, dexp_hi2, dexp_lo2;
	int		hx0, resh0, res_ch0;
	int		hx1, resh1, res_ch1;
	int		hx2, resh2, res_ch2;

	LO(&dsqrt_exp0) = 0;
	LO(&dsqrt_exp1) = 0;
	LO(&dsqrt_exp2) = 0;
	LO(&res_c0) = 0;
	LO(&res_c1) = 0;
	LO(&res_c2) = 0;

	for(; n > 2 ; n -= 3)
	{
		hx0 = HI(px);
		LO(&res0) = LO(px);
		px += stridex;

		hx1 = HI(px);
		LO(&res1) = LO(px);
		px += stridex;

		hx2 = HI(px);
		LO(&res2) = LO(px);
		px += stridex;

		sqrt_exp0 = (0x5fe - (hx0 >> 21)) << 20;
		sqrt_exp1 = (0x5fe - (hx1 >> 21)) << 20;
		sqrt_exp2 = (0x5fe - (hx2 >> 21)) << 20;
		ind0 = (((hx0 >> 10) & 0x7f8) + 8) & -16;
		ind1 = (((hx1 >> 10) & 0x7f8) + 8) & -16;
		ind2 = (((hx2 >> 10) & 0x7f8) + 8) & -16;

		resh0 = (hx0 & 0x001fffff) | 0x3fe00000;
		resh1 = (hx1 & 0x001fffff) | 0x3fe00000;
		resh2 = (hx2 & 0x001fffff) | 0x3fe00000;
		res_ch0 = (resh0 + 0x00002000) & 0x7fffc000;
		res_ch1 = (resh1 + 0x00002000) & 0x7fffc000;
		res_ch2 = (resh2 + 0x00002000) & 0x7fffc000;
		HI(&res0) = resh0;
		HI(&res1) = resh1;
		HI(&res2) = resh2;
		HI(&res_c0) = res_ch0;
		HI(&res_c1) = res_ch1;
		HI(&res_c2) = res_ch2;

		dexp_hi0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[0];
		dexp_hi1 = ((double*)((char*)__vlibm_TBL_rsqrt + ind1))[0];
		dexp_hi2 = ((double*)((char*)__vlibm_TBL_rsqrt + ind2))[0];
		dexp_lo0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[1];
		dexp_lo1 = ((double*)((char*)__vlibm_TBL_rsqrt + ind1))[1];
		dexp_lo2 = ((double*)((char*)__vlibm_TBL_rsqrt + ind2))[1];
		xx0 = dexp_hi0 * dexp_hi0;
		xx1 = dexp_hi1 * dexp_hi1;
		xx2 = dexp_hi2 * dexp_hi2;
		xx0 = (res0 - res_c0) * xx0;
		xx1 = (res1 - res_c1) * xx1;
		xx2 = (res2 - res_c2) * xx2;
		res0 = (((((K6 * xx0 + K5) * xx0 + K4) * xx0 + K3) * xx0 + K2) * xx0 + K1) * xx0;
		res1 = (((((K6 * xx1 + K5) * xx1 + K4) * xx1 + K3) * xx1 + K2) * xx1 + K1) * xx1;
		res2 = (((((K6 * xx2 + K5) * xx2 + K4) * xx2 + K3) * xx2 + K2) * xx2 + K1) * xx2;

		res0 = dexp_hi0 * res0 + dexp_lo0 + dexp_hi0;
		res1 = dexp_hi1 * res1 + dexp_lo1 + dexp_hi1;
		res2 = dexp_hi2 * res2 + dexp_lo2 + dexp_hi2;

		HI(&dsqrt_exp0) = sqrt_exp0;
		HI(&dsqrt_exp1) = sqrt_exp1;
		HI(&dsqrt_exp2) = sqrt_exp2;
		res0 *= dsqrt_exp0;
		res1 *= dsqrt_exp1;
		res2 *= dsqrt_exp2;

		*py = res0;
		py += stridey;

		*py = res1;
		py += stridey;

		*py = res2;
		py += stridey;
	}

	for(; n > 0 ; n--)
	{
		hx0 = HI(px);

		sqrt_exp0 = (0x5fe - (hx0 >> 21)) << 20;
		ind0 = (((hx0 >> 10) & 0x7f8) + 8) & -16;

		resh0 = (hx0 & 0x001fffff) | 0x3fe00000;
		res_ch0 = (resh0 + 0x00002000) & 0x7fffc000;
		HI(&res0) = resh0;
		LO(&res0) = LO(px);
		HI(&res_c0) = res_ch0;
		LO(&res_c0) = 0;

		px += stridex;

		dexp_hi0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[0];
		dexp_lo0 = ((double*)((char*)__vlibm_TBL_rsqrt + ind0))[1];
		xx0 = dexp_hi0 * dexp_hi0;
		xx0 = (res0 - res_c0) * xx0;
		res0 = (((((K6 * xx0 + K5) * xx0 + K4) * xx0 + K3) * xx0 + K2) * xx0 + K1) * xx0;

		res0 = dexp_hi0 * res0 + dexp_lo0 + dexp_hi0;

		HI(&dsqrt_exp0) = sqrt_exp0;
		LO(&dsqrt_exp0) = 0;
		res0 *= dsqrt_exp0;

		*py = res0;
		py += stridey;
	}
}

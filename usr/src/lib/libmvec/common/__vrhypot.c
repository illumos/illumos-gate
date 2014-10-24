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

/* double rhypot(double x, double y)
 *
 * Method :
 *	1. Special cases:
 *		x or  y = Inf					=> 0
 *		x or  y = NaN					=> QNaN
 *		x and y = 0					=> Inf + divide-by-zero
 *	2. Computes rhypot(x,y):
 *		rhypot(x,y) = m * sqrt(1/(xnm * xnm + ynm * ynm))
 *	Where:
 *		m = 1/max(|x|,|y|)
 *		xnm = x * m
 *		ynm = y * m
 *
 *	Compute 1/(xnm * xnm + ynm * ynm) by simulating
 *	muti-precision arithmetic.
 *
 * Accuracy:
 *	Maximum error observed: less than 0.869 ulp after 1.000.000.000
 *	results.
 */

extern double sqrt(double);
extern double fabs(double);

static const int __vlibm_TBL_rhypot[] = {
/* i = [0,127]
 * TBL[i] = 0x3ff00000 + *(int*)&(1.0 / *(double*)&(0x3ff0000000000000ULL + (i << 45))); */
 0x7fe00000,  0x7fdfc07f, 0x7fdf81f8,  0x7fdf4465,
 0x7fdf07c1,  0x7fdecc07, 0x7fde9131,  0x7fde573a,
 0x7fde1e1e,  0x7fdde5d6, 0x7fddae60,  0x7fdd77b6,
 0x7fdd41d4,  0x7fdd0cb5, 0x7fdcd856,  0x7fdca4b3,
 0x7fdc71c7,  0x7fdc3f8f, 0x7fdc0e07,  0x7fdbdd2b,
 0x7fdbacf9,  0x7fdb7d6c, 0x7fdb4e81,  0x7fdb2036,
 0x7fdaf286,  0x7fdac570, 0x7fda98ef,  0x7fda6d01,
 0x7fda41a4,  0x7fda16d3, 0x7fd9ec8e,  0x7fd9c2d1,
 0x7fd99999,  0x7fd970e4, 0x7fd948b0,  0x7fd920fb,
 0x7fd8f9c1,  0x7fd8d301, 0x7fd8acb9,  0x7fd886e5,
 0x7fd86186,  0x7fd83c97, 0x7fd81818,  0x7fd7f405,
 0x7fd7d05f,  0x7fd7ad22, 0x7fd78a4c,  0x7fd767dc,
 0x7fd745d1,  0x7fd72428, 0x7fd702e0,  0x7fd6e1f7,
 0x7fd6c16c,  0x7fd6a13c, 0x7fd68168,  0x7fd661ec,
 0x7fd642c8,  0x7fd623fa, 0x7fd60581,  0x7fd5e75b,
 0x7fd5c988,  0x7fd5ac05, 0x7fd58ed2,  0x7fd571ed,
 0x7fd55555,  0x7fd53909, 0x7fd51d07,  0x7fd50150,
 0x7fd4e5e0,  0x7fd4cab8, 0x7fd4afd6,  0x7fd49539,
 0x7fd47ae1,  0x7fd460cb, 0x7fd446f8,  0x7fd42d66,
 0x7fd41414,  0x7fd3fb01, 0x7fd3e22c,  0x7fd3c995,
 0x7fd3b13b,  0x7fd3991c, 0x7fd38138,  0x7fd3698d,
 0x7fd3521c,  0x7fd33ae4, 0x7fd323e3,  0x7fd30d19,
 0x7fd2f684,  0x7fd2e025, 0x7fd2c9fb,  0x7fd2b404,
 0x7fd29e41,  0x7fd288b0, 0x7fd27350,  0x7fd25e22,
 0x7fd24924,  0x7fd23456, 0x7fd21fb7,  0x7fd20b47,
 0x7fd1f704,  0x7fd1e2ef, 0x7fd1cf06,  0x7fd1bb4a,
 0x7fd1a7b9,  0x7fd19453, 0x7fd18118,  0x7fd16e06,
 0x7fd15b1e,  0x7fd1485f, 0x7fd135c8,  0x7fd12358,
 0x7fd11111,  0x7fd0fef0, 0x7fd0ecf5,  0x7fd0db20,
 0x7fd0c971,  0x7fd0b7e6, 0x7fd0a681,  0x7fd0953f,
 0x7fd08421,  0x7fd07326, 0x7fd0624d,  0x7fd05197,
 0x7fd04104,  0x7fd03091, 0x7fd02040,  0x7fd01010,
};

static const unsigned long long LCONST[] = {
0x3ff0000000000000ULL,	/* DONE = 1.0		*/
0x4000000000000000ULL,	/* DTWO = 2.0		*/
0x4230000000000000ULL,	/* D2ON36 = 2**36	*/
0x7fd0000000000000ULL,	/* D2ON1022 = 2**1022	*/
0x3cb0000000000000ULL,	/* D2ONM52 = 2**-52	*/
};

#define RET_SC(I)										\
	px += stridex;										\
	py += stridey;										\
	pz += stridez;										\
	if (--n <= 0)										\
		break;										\
	goto start##I;

#define RETURN(I, ret)										\
{												\
	pz[0] = (ret);										\
	RET_SC(I)										\
}

#define PREP(I)											\
hx##I = HI(px);										\
hy##I = HI(py);										\
hx##I &= 0x7fffffff;										\
hy##I &= 0x7fffffff;										\
pz##I = pz;											\
if (hx##I >= 0x7ff00000 || hy##I >= 0x7ff00000)	/* |X| or |Y| = Inf,NaN */		\
{												\
	lx = LO(px);									\
	ly = LO(py);									\
	x = *px;										\
	y = *py;										\
	if (hx##I == 0x7ff00000 && lx == 0) res0 = 0.0;		/* |X| = Inf */		\
	else if (hy##I == 0x7ff00000 && ly == 0) res0 = 0.0;	/* |Y| = Inf */		\
	else res0 = fabs(x) + fabs(y);								\
												\
	RETURN (I, res0)									\
}												\
x##I = *px;											\
y##I = *py;											\
diff0 = hy##I - hx##I;										\
j0 = diff0 >> 31;										\
if (hx##I < 0x00100000 && hy##I < 0x00100000)	/* |X| and |Y| = subnormal or zero */		\
{												\
	lx = LO(px);									\
	ly = LO(py);									\
	x = x##I;										\
	y = y##I;										\
												\
	if ((hx##I | hy##I | lx | ly) == 0)	/* |X| and |Y| = 0 */				\
		RETURN (I, DONE / 0.0)							\
												\
	x = fabs(x);										\
	y = fabs(y);										\
												\
	x = *(long long*)&x;									\
	y = *(long long*)&y;									\
												\
	x *= D2ONM52;										\
	y *= D2ONM52;										\
												\
	x_hi0 = (x + D2ON36) - D2ON36;							\
	y_hi0 = (y + D2ON36) - D2ON36;							\
	x_lo0 = x - x_hi0;									\
	y_lo0 = y - y_hi0;									\
	res0_hi = (x_hi0 * x_hi0 + y_hi0 * y_hi0);						\
	res0_lo = ((x + x_hi0) * x_lo0 + (y + y_hi0) * y_lo0);					\
												\
	dres0 = res0_hi + res0_lo;								\
												\
	iarr0 = HI(&dres0);								\
	iexp0 = iarr0 & 0xfff00000;								\
												\
	iarr0 = (iarr0 >> 11) & 0x1fc;								\
	itbl0 = ((int*)((char*)__vlibm_TBL_rhypot + iarr0))[0];					\
	itbl0 -= iexp0;										\
	HI(&dd0) = itbl0;						\
	LO(&dd0) = 0;								\
												\
	dd0 = dd0 * (DTWO - dd0 * dres0);							\
	dd0 = dd0 * (DTWO - dd0 * dres0);							\
	dres0 = dd0 * (DTWO - dd0 * dres0);							\
												\
	HI(&res0) = HI(&dres0) & 0xffffff00;					\
	LO(&res0) = 0;								\
	res0 += (DONE - res0_hi * res0 - res0_lo * res0) * dres0;				\
	res0 = sqrt (res0);									\
												\
	res0 = D2ON1022 * res0;									\
	RETURN (I, res0)									\
}												\
j0 = hy##I - (diff0 & j0);									\
j0 &= 0x7ff00000;										\
HI(&scl##I) = 0x7ff00000 - j0;

void
__vrhypot(int n, double * restrict px, int stridex, double * restrict py,
	int stridey, double * restrict pz, int stridez)
{
	int		i = 0;
	double		x, y;
	double		x_hi0, x_lo0, y_hi0, y_lo0, scl0 = 0;
	double		x0, y0, res0, dd0;
	double		res0_hi,res0_lo, dres0;
	double		x_hi1, x_lo1, y_hi1, y_lo1, scl1 = 0;
	double		x1 = 0.0L, y1 = 0.0L, res1, dd1;
	double		res1_hi,res1_lo, dres1;
	double		x_hi2, x_lo2, y_hi2, y_lo2, scl2 = 0;
	double		x2, y2, res2, dd2;
	double		res2_hi,res2_lo, dres2;

	int		hx0, hy0, j0, diff0;
	int		iarr0, iexp0, itbl0;
	int		hx1, hy1;
	int		iarr1, iexp1, itbl1;
	int		hx2, hy2;
	int		iarr2, iexp2, itbl2;

	int		lx, ly;

	double		DONE = ((double*)LCONST)[0];
	double		DTWO = ((double*)LCONST)[1];
	double		D2ON36 = ((double*)LCONST)[2];
	double		D2ON1022 = ((double*)LCONST)[3];
	double		D2ONM52 = ((double*)LCONST)[4];

	double		*pz0, *pz1 = 0, *pz2;

	do
	{
start0:
		PREP(0)
		px += stridex;
		py += stridey;
		pz += stridez;
		i = 1;
		if (--n <= 0)
			break;

start1:
		PREP(1)
		px += stridex;
		py += stridey;
		pz += stridez;
		i = 2;
		if (--n <= 0)
			break;

start2:
		PREP(2)

		x0 *= scl0;
		y0 *= scl0;
		x1 *= scl1;
		y1 *= scl1;
		x2 *= scl2;
		y2 *= scl2;

		x_hi0 = (x0 + D2ON36) - D2ON36;
		y_hi0 = (y0 + D2ON36) - D2ON36;
		x_hi1 = (x1 + D2ON36) - D2ON36;
		y_hi1 = (y1 + D2ON36) - D2ON36;
		x_hi2 = (x2 + D2ON36) - D2ON36;
		y_hi2 = (y2 + D2ON36) - D2ON36;
		x_lo0 = x0 - x_hi0;
		y_lo0 = y0 - y_hi0;
		x_lo1 = x1 - x_hi1;
		y_lo1 = y1 - y_hi1;
		x_lo2 = x2 - x_hi2;
		y_lo2 = y2 - y_hi2;
		res0_hi = (x_hi0 * x_hi0 + y_hi0 * y_hi0);
		res1_hi = (x_hi1 * x_hi1 + y_hi1 * y_hi1);
		res2_hi = (x_hi2 * x_hi2 + y_hi2 * y_hi2);
		res0_lo = ((x0 + x_hi0) * x_lo0 + (y0 + y_hi0) * y_lo0);
		res1_lo = ((x1 + x_hi1) * x_lo1 + (y1 + y_hi1) * y_lo1);
		res2_lo = ((x2 + x_hi2) * x_lo2 + (y2 + y_hi2) * y_lo2);

		dres0 = res0_hi + res0_lo;
		dres1 = res1_hi + res1_lo;
		dres2 = res2_hi + res2_lo;

		iarr0 = HI(&dres0);
		iarr1 = HI(&dres1);
		iarr2 = HI(&dres2);
		iexp0 = iarr0 & 0xfff00000;
		iexp1 = iarr1 & 0xfff00000;
		iexp2 = iarr2 & 0xfff00000;

		iarr0 = (iarr0 >> 11) & 0x1fc;
		iarr1 = (iarr1 >> 11) & 0x1fc;
		iarr2 = (iarr2 >> 11) & 0x1fc;
		itbl0 = ((int*)((char*)__vlibm_TBL_rhypot + iarr0))[0];
		itbl1 = ((int*)((char*)__vlibm_TBL_rhypot + iarr1))[0];
		itbl2 = ((int*)((char*)__vlibm_TBL_rhypot + iarr2))[0];
		itbl0 -= iexp0;
		itbl1 -= iexp1;
		itbl2 -= iexp2;
		HI(&dd0) = itbl0;
		HI(&dd1) = itbl1;
		HI(&dd2) = itbl2;
		LO(&dd0) = 0;
		LO(&dd1) = 0;
		LO(&dd2) = 0;

		dd0 = dd0 * (DTWO - dd0 * dres0);
		dd1 = dd1 * (DTWO - dd1 * dres1);
		dd2 = dd2 * (DTWO - dd2 * dres2);
		dd0 = dd0 * (DTWO - dd0 * dres0);
		dd1 = dd1 * (DTWO - dd1 * dres1);
		dd2 = dd2 * (DTWO - dd2 * dres2);
		dres0 = dd0 * (DTWO - dd0 * dres0);
		dres1 = dd1 * (DTWO - dd1 * dres1);
		dres2 = dd2 * (DTWO - dd2 * dres2);

		HI(&res0) = HI(&dres0) & 0xffffff00;
		HI(&res1) = HI(&dres1) & 0xffffff00;
		HI(&res2) = HI(&dres2) & 0xffffff00;
		LO(&res0) = 0;
		LO(&res1) = 0;
		LO(&res2) = 0;
		res0 += (DONE - res0_hi * res0 - res0_lo * res0) * dres0;
		res1 += (DONE - res1_hi * res1 - res1_lo * res1) * dres1;
		res2 += (DONE - res2_hi * res2 - res2_lo * res2) * dres2;
		res0 = sqrt (res0);
		res1 = sqrt (res1);
		res2 = sqrt (res2);

		res0 = scl0 * res0;
		res1 = scl1 * res1;
		res2 = scl2 * res2;

		*pz0 = res0;
		*pz1 = res1;
		*pz2 = res2;

		px += stridex;
		py += stridey;
		pz += stridez;
		i = 0;

	} while (--n > 0);

	if (i > 0)
	{
		x0 *= scl0;
		y0 *= scl0;

		x_hi0 = (x0 + D2ON36) - D2ON36;
		y_hi0 = (y0 + D2ON36) - D2ON36;
		x_lo0 = x0 - x_hi0;
		y_lo0 = y0 - y_hi0;
		res0_hi = (x_hi0 * x_hi0 + y_hi0 * y_hi0);
		res0_lo = ((x0 + x_hi0) * x_lo0 + (y0 + y_hi0) * y_lo0);

		dres0 = res0_hi + res0_lo;

		iarr0 = HI(&dres0);
		iexp0 = iarr0 & 0xfff00000;

		iarr0 = (iarr0 >> 11) & 0x1fc;
		itbl0 = ((int*)((char*)__vlibm_TBL_rhypot + iarr0))[0];
		itbl0 -= iexp0;
		HI(&dd0) = itbl0;
		LO(&dd0) = 0;

		dd0 = dd0 * (DTWO - dd0 * dres0);
		dd0 = dd0 * (DTWO - dd0 * dres0);
		dres0 = dd0 * (DTWO - dd0 * dres0);

		HI(&res0) = HI(&dres0) & 0xffffff00;
		LO(&res0) = 0;
		res0 += (DONE - res0_hi * res0 - res0_lo * res0) * dres0;
		res0 = sqrt (res0);

		res0 = scl0 * res0;

		*pz0 = res0;

		if (i > 1)
		{
			x1 *= scl1;
			y1 *= scl1;

			x_hi1 = (x1 + D2ON36) - D2ON36;
			y_hi1 = (y1 + D2ON36) - D2ON36;
			x_lo1 = x1 - x_hi1;
			y_lo1 = y1 - y_hi1;
			res1_hi = (x_hi1 * x_hi1 + y_hi1 * y_hi1);
			res1_lo = ((x1 + x_hi1) * x_lo1 + (y1 + y_hi1) * y_lo1);

			dres1 = res1_hi + res1_lo;

			iarr1 = HI(&dres1);
			iexp1 = iarr1 & 0xfff00000;

			iarr1 = (iarr1 >> 11) & 0x1fc;
			itbl1 = ((int*)((char*)__vlibm_TBL_rhypot + iarr1))[0];
			itbl1 -= iexp1;
			HI(&dd1) = itbl1;
			LO(&dd1) = 0;

			dd1 = dd1 * (DTWO - dd1 * dres1);
			dd1 = dd1 * (DTWO - dd1 * dres1);
			dres1 = dd1 * (DTWO - dd1 * dres1);

			HI(&res1) = HI(&dres1) & 0xffffff00;
			LO(&res1) = 0;
			res1 += (DONE - res1_hi * res1 - res1_lo * res1) * dres1;
			res1 = sqrt (res1);

			res1 = scl1 * res1;

			*pz1 = res1;
		}
	}
}

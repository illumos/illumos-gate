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

#pragma weak __pow = pow

/*
 * pow(x,y) return x**y
 *		      n
 * Method:  Let x =  2   * (1+f)
 *	1. Compute and return log2(x) in two pieces:
 *		log2(x) = w1 + w2,
 *	   where w1 has 24 bits trailing zero.
 *	2. Perform y*log2(x) by simulating muti-precision arithmetic
 *	3. Return x**y = exp2(y*log(x))
 *
 * Special cases:
 *	1.  (anything) ** +-0 is 1
 *	1'. 1 ** (anything)   is 1	(C99; 1 ** +-INF/NAN used to be NAN)
 *	2.  (anything) ** 1   is itself
 *	3.  (anything except 1) ** NAN is NAN ("except 1" is C99)
 *	4.  NAN ** (anything except 0) is NAN
 *	5.  +-(|x| > 1) **  +INF is +INF
 *	6.  +-(|x| > 1) **  -INF is +0
 *	7.  +-(|x| < 1) **  +INF is +0
 *	8.  +-(|x| < 1) **  -INF is +INF
 *	9.  -1          ** +-INF is 1	(C99; -1 ** +-INF used to be NAN)
 *	10. +0 ** (+anything except 0, NAN)               is +0
 *	11. -0 ** (+anything except 0, NAN, odd integer)  is +0
 *	12. +0 ** (-anything except 0, NAN)               is +INF
 *	13. -0 ** (-anything except 0, NAN, odd integer)  is +INF
 *	14. -0 ** (odd integer) = -( +0 ** (odd integer) )
 *	15. +INF ** (+anything except 0,NAN) is +INF
 *	16. +INF ** (-anything except 0,NAN) is +0
 *	17. -INF ** (anything)  = -0 ** (-anything)
 *	18. (-anything) ** (integer) is (-1)**(integer)*(+anything**integer)
 *	19. (-anything except 0 and inf) ** (non-integer) is NAN
 *
 * Accuracy:
 *	pow(x,y) returns x**y nearly rounded. In particular
 *			pow(integer,integer)
 *	always returns the correct integer provided it is representable.
 */

#include "libm.h"
#include "xpg6.h"	/* __xpg6 */
#define	_C99SUSv3_pow	_C99SUSv3_pow_treats_Inf_as_an_even_int

static const double zero = 0.0, one = 1.0, two = 2.0;

extern const double _TBL_log2_hi[], _TBL_log2_lo[];
static const double
	two53 = 9007199254740992.0,
	A1_hi = 2.8853900432586669921875,
	A1_lo = 3.8519259825035041963606002e-8,
	A1 = 2.885390081777926817222541963606002026086e+0000,
	A2 = 9.617966939207270828380543979852286255862e-0001,
	A3 = 5.770807680887875964868853124873696201995e-0001,
	B0_hi = 2.8853900432586669921875,
	B0_lo = 3.8519259822532793056374320585e-8,
	B0 = 2.885390081777926814720293056374320585689e+0000,
	B1 = 9.617966939259755138949202350396200257632e-0001,
	B2 = 5.770780163585687000782112776448797953382e-0001,
	B3 = 4.121985488948771523290174512461778354953e-0001,
	B4 = 3.207590534812432970433641789022666850193e-0001;

static double
log2_x(double x, double *w) {
	double f, s, z, qn, h, t;
	int *px = (int *) &x;
	int *pz = (int *) &z;
	int i, j, ix, n;

	n = 0;
	ix = px[HIWORD];
	if (ix >= 0x3fef03f1 && ix < 0x3ff08208) {	/* 65/63 > x > 63/65 */
		double f1, v;
		f = x - one;
		if (((ix - 0x3ff00000) | px[LOWORD]) == 0) {
			*w = zero;
			return (zero);		/* log2(1)= +0 */
		}
		qn = one / (two + f);
		s = f * qn;				/* |s|<2**-6 */
		v = s * s;
		h = (double) ((float) s);
		f1 = (double) ((float) f);
		t = qn * (((f - two * h) - h * f1) - h * (f - f1));
								/* s = h+t */
		f1 = h * B0_lo + s * (v * (B1 + v * (B2 + v * (B3 + v * B4))));
		t = f1 + t * B0;
		h *= B0_hi;
		s = (double) ((float) (h + t));
		*w = t - (s - h);
		return (s);
	}
	if (ix < 0x00100000) {				/* subnormal x */
		x *= two53;
		n = -53;
		ix = px[HIWORD];
	}
	/* LARGE N */
	n += ((ix + 0x1000) >> 20) - 0x3ff;
	ix = (ix & 0x000fffff) | 0x3ff00000;		/* scale x to [1,2] */
	px[HIWORD] = ix;
	i = ix + 0x1000;
	pz[HIWORD] = i & 0xffffe000;
	pz[LOWORD] = 0;
	qn = one / (x + z);
	f = x - z;
	s = f * qn;
	h = (double) ((float) s);
	t = qn * ((f - (h + h) * z) - h * f);
	j = (i >> 13) & 0x7f;
	f = s * s;
	t = t * A1 + h * A1_lo;
	t += (s * f) * (A2 + f * A3);
	qn = h * A1_hi;
	s = n + _TBL_log2_hi[j];
	h = qn + s;
	t += _TBL_log2_lo[j] - ((h - s) - qn);
	f = (double) ((float) (h + t));
	*w = t - (f - h);
	return (f);
}

extern const double _TBL_exp2_hi[], _TBL_exp2_lo[];
static const double		/* poly app of 2^x-1 on [-1e-10,2^-7+1e-10] */
	E1 = 6.931471805599453100674958533810346197328e-0001,
	E2 = 2.402265069587779347846769151717493815979e-0001,
	E3 = 5.550410866475410512631124892773937864699e-0002,
	E4 = 9.618143209991026824853712740162451423355e-0003,
	E5 = 1.333357676549940345096774122231849082991e-0003;

double
pow(double x, double y) {
	double z, ax;
	double y1, y2, w1, w2;
	int sbx, sby, j, k, yisint;
	int hx, hy, ahx, ahy;
	unsigned lx, ly;
	int *pz = (int *) &z;

	hx = ((int *) &x)[HIWORD];
	lx = ((unsigned *) &x)[LOWORD];
	hy = ((int *) &y)[HIWORD];
	ly = ((unsigned *) &y)[LOWORD];
	ahx = hx & ~0x80000000;
	ahy = hy & ~0x80000000;
	if ((ahy | ly) == 0) {	/* y==zero  */
		if ((ahx | lx) == 0)
			z = _SVID_libm_err(x, y, 20);	/* +-0**+-0 */
		else if ((ahx | (((lx | -lx) >> 31) & 1)) > 0x7ff00000)
			z = _SVID_libm_err(x, y, 42);	/* NaN**+-0 */
		else
			z = one;			/* x**+-0 = 1 */
		return (z);
	} else if (hx == 0x3ff00000 && lx == 0 &&
		(__xpg6 & _C99SUSv3_pow) != 0)
		return (one);			/* C99: 1**anything = 1 */
	else if (ahx > 0x7ff00000 || (ahx == 0x7ff00000 && lx != 0) ||
		ahy > 0x7ff00000 || (ahy == 0x7ff00000 && ly != 0))
		return (x * y);	/* +-NaN return x*y; + -> * for Cheetah */
				/* includes Sun: 1**NaN = NaN */
	sbx = (unsigned) hx >> 31;
	sby = (unsigned) hy >> 31;
	ax = fabs(x);

	/*
	 * determine if y is an odd int when x < 0
	 * yisint = 0 ... y is not an integer
	 * yisint = 1 ... y is an odd int
	 * yisint = 2 ... y is an even int
	 */
	yisint = 0;
	if (sbx) {
		if (ahy >= 0x43400000)
			yisint = 2;		/* even integer y */
		else if (ahy >= 0x3ff00000) {
			k = (ahy >> 20) - 0x3ff;	/* exponent */
			if (k > 20) {
				j = ly >> (52 - k);
				if ((j << (52 - k)) == ly)
					yisint = 2 - (j & 1);
			} else if (ly == 0) {
				j = ahy >> (20 - k);
				if ((j << (20 - k)) == ahy)
					yisint = 2 - (j & 1);
			}
		}
	}
	/* special value of y */
	if (ly == 0) {
		if (ahy == 0x7ff00000) {	/* y is +-inf */
			if (((ahx - 0x3ff00000) | lx) == 0) {
				if ((__xpg6 & _C99SUSv3_pow) != 0)
					return (one);
						/* C99: (-1)**+-inf = 1 */
				else
					return (y - y);
						/* Sun: (+-1)**+-inf = NaN */
			} else if (ahx >= 0x3ff00000)
						/* (|x|>1)**+,-inf = inf,0 */
				return (sby == 0 ? y : zero);
			else			/* (|x|<1)**-,+inf = inf,0 */
				return (sby != 0 ? -y : zero);
		}
		if (ahy == 0x3ff00000) {	/* y is  +-1 */
			if (sby != 0) {	/* y is -1 */
				if (x == zero)	/* divided by zero */
					return (_SVID_libm_err(x, y, 23));
				else if (ahx < 0x40000 || ((ahx - 0x40000) |
					lx) == 0)	/* overflow */
					return (_SVID_libm_err(x, y, 21));
				else
					return (one / x);
			} else
				return (x);
		}
		if (hy == 0x40000000) {		/* y is  2 */
			if (ahx >= 0x5ff00000 && ahx < 0x7ff00000)
				return (_SVID_libm_err(x, y, 21));
							/* x*x overflow */
			else if ((ahx < 0x1e56a09e && (ahx | lx) != 0) ||
				(ahx == 0x1e56a09e && lx < 0x667f3bcd))
				return (_SVID_libm_err(x, y, 22));
							/* x*x underflow */
			else
				return (x * x);
		}
		if (hy == 0x3fe00000) {
			if (!((ahx | lx) == 0 || ((ahx - 0x7ff00000) | lx) ==
				0 || sbx == 1))
				return (sqrt(x));	/* y is 0.5 and x > 0 */
		}
	}
	/* special value of x */
	if (lx == 0) {
		if (ahx == 0x7ff00000 || ahx == 0 || ahx == 0x3ff00000) {
			/* x is +-0,+-inf,-1 */
			z = ax;
			if (sby == 1) {
				z = one / z;	/* z = |x|**y */
				if (ahx == 0)
					return (_SVID_libm_err(x, y, 23));
			}
			if (sbx == 1) {
				if (ahx == 0x3ff00000 && yisint == 0)
					z = _SVID_libm_err(x, y, 24);
					/* neg**non-integral is NaN + invalid */
				else if (yisint == 1)
					z = -z;	/* (x<0)**odd = -(|x|**odd) */
			}
			return (z);
		}
	}
	/* (x<0)**(non-int) is NaN */
	if (sbx == 1 && yisint == 0)
		return (_SVID_libm_err(x, y, 24));
	/* Now ax is finite, y is finite */
	/* first compute log2(ax) = w1+w2, with 24 bits w1 */
	w1 = log2_x(ax, &w2);

	/* split up y into y1+y2 and compute (y1+y2)*(w1+w2) */
	if (((ly & 0x07ffffff) == 0) || ahy >= 0x47e00000 ||
		ahy <= 0x38100000) {
		/* no need to split if y is short or too large or too small */
		y1 = y * w1;
		y2 = y * w2;
	} else {
		y1 = (double) ((float) y);
		y2 = (y - y1) * w1 + y * w2;
		y1 *= w1;
	}
	z = y1 + y2;
	j = pz[HIWORD];
	if (j >= 0x40900000) {				/* z >= 1024 */
		if (!(j == 0x40900000 && pz[LOWORD] == 0))	/* z > 1024 */
			return (_SVID_libm_err(x, y, 21));	/* overflow */
		else {
			w2 = y1 - z;
			w2 += y2;
							/* rounded to inf */
			if (w2 >= -8.008566259537296567160e-17)
				return (_SVID_libm_err(x, y, 21));
								/* overflow */
		}
	} else if ((j & ~0x80000000) >= 0x4090cc00) {	/* z <= -1075 */
		if (!(j == 0xc090cc00 && pz[LOWORD] == 0))	/* z < -1075 */
			return (_SVID_libm_err(x, y, 22));	/* underflow */
		else {
			w2 = y1 - z;
			w2 += y2;
			if (w2 <= zero)			/* underflow */
				return (_SVID_libm_err(x, y, 22));
		}
	}
	/*
	 * compute 2**(k+f[j]+g)
	 */
	k = (int) (z * 64.0 + (((hy ^ (ahx - 0x3ff00000)) > 0) ? 0.5 : -0.5));
	j = k & 63;
	w1 = y2 - ((double) k * 0.015625 - y1);
	w2 = _TBL_exp2_hi[j];
	z = _TBL_exp2_lo[j] + (w2 * w1) * (E1 + w1 * (E2 + w1 * (E3 + w1 *
		(E4 + w1 * E5))));
	z += w2;
	k >>= 6;
	if (k < -1021)
		z = scalbn(z, k);
	else			/* subnormal output */
		pz[HIWORD] += k << 20;
	if (sbx == 1 && yisint == 1)
		z = -z;		/* (-ve)**(odd int) */
	return (z);
}

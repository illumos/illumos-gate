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

#pragma weak __powl = powl

#include "libm.h"
#include "xpg6.h"	/* __xpg6 */
#define	_C99SUSv3_pow	_C99SUSv3_pow_treats_Inf_as_an_even_int

#if defined(__sparc)
#define	i0	0
#define	i1	1
#define	i2	2
#define	i3	3

static const long double zero = 0.0L, one = 1.0L, two = 2.0L;

extern const long double _TBL_logl_hi[], _TBL_logl_lo[];

static const long double
	two113 = 10384593717069655257060992658440192.0L,
	ln2hi = 6.931471805599453094172319547495844850203e-0001L,
	ln2lo = 1.667085920830552208890449330400379754169e-0025L,
	A2 = 6.666666666666666666666666666666091393804e-0001L,
	A3 = 4.000000000000000000000000407167070220671e-0001L,
	A4 = 2.857142857142857142730077490612903681164e-0001L,
	A5 = 2.222222222222242577702836920812882605099e-0001L,
	A6 = 1.818181816435493395985912667105885828356e-0001L,
	A7 = 1.538537835211839751112067512805496931725e-0001L,
	B1 = 6.666666666666666666666666666666666667787e-0001L,
	B2 = 3.999999999999999999999999999999848524411e-0001L,
	B3 = 2.857142857142857142857142865084581075070e-0001L,
	B4 = 2.222222222222222222222010781800643808497e-0001L,
	B5 = 1.818181818181818185051442171337036403674e-0001L,
	B6 = 1.538461538461508363540720286292008207673e-0001L,
	B7 = 1.333333333506731842033180638329317108428e-0001L,
	B8 = 1.176469984587418890634302788283946761670e-0001L,
	B9 = 1.053794891561452331722969901564862497132e-0001L;

static long double
logl_x(long double x, long double *w) {
	long double f, f1, v, s, z, qn, h, t;
	int *px = (int *) &x;
	int *pz = (int *) &z;
	int i, j, ix, n;

	n = 0;
	ix = px[i0];
	if (ix > 0x3ffef03f && ix < 0x3fff0820) {	/* 65/63 > x > 63/65 */
		f = x - one;
		z = f * f;
		if (((ix - 0x3fff0000) | px[i1] | px[i2] | px[i3]) == 0) {
			*w = zero;
			return (zero);	/* log(1)= +0 */
		}
		qn = one / (two + f);
		s = f * qn;	/* |s|<2**-6 */
		v = s * s;
		h = (long double) (2.0 * (double) s);
		f1 = (long double) ((double) f);
		t = ((two * (f - h) - h * f1) - h * (f - f1)) * qn +
			s * (v * (B1 + v * (B2 + v * (B3 + v * (B4 +
			v * (B5 + v * (B6 + v * (B7 + v * (B8 + v * B9)))))))));
		s = (long double) ((double) (h + t));
		*w = t - (s - h);
		return (s);
	}
	if (ix < 0x00010000) {	/* subnormal x */
		x *= two113;
		n = -113;
		ix = px[i0];
	}
	/* LARGE_N */
	n += ((ix + 0x200) >> 16) - 0x3fff;
	ix = (ix & 0x0000ffff) | 0x3fff0000;	/* scale x to [1,2] */
	px[i0] = ix;
	i = ix + 0x200;
	pz[i0] = i & 0xfffffc00;
	pz[i1] = pz[i2] = pz[i3] = 0;
	qn = one / (x + z);
	f = x - z;
	s = f * qn;
	f1 = (long double) ((double) f);
	h = (long double) (2.0 * (double) s);
	t = qn * ((two * (f - z * h) - h * f1) - h * (f - f1));
	j = (i >> 10) & 0x3f;
	v = s * s;
	qn = (long double) n;
	t += qn * ln2lo + _TBL_logl_lo[j];
	t += s * (v * (A2 + v * (A3 + v * (A4 + v * (A5 + v * (A6 +
		v * A7))))));
	v = qn * ln2hi + _TBL_logl_hi[j];
	s = h + v;
	t += (h - (s - v));
	z = (long double) ((double) (s + t));
	*w = t - (z - s);
	return (z);
}

extern const long double _TBL_expl_hi[], _TBL_expl_lo[];
static const long double
	invln2_32 = 4.616624130844682903551758979206054839765e+1L,
	ln2_32hi = 2.166084939249829091928849858592451515688e-2L,
	ln2_32lo = 5.209643502595475652782654157501186731779e-27L,
	ln2_64 = 1.083042469624914545964425189778400898568e-2L;

long double
powl(long double x, long double y) {
	long double z, ax;
	long double y1, y2, w1, w2;
	int sbx, sby, j, k, yisint, m;
	int hx, lx, hy, ly, ahx, ahy;
	int *pz = (int *) &z;
	int *px = (int *) &x;
	int *py = (int *) &y;

	hx = px[i0];
	lx = px[i1] | px[i2] | px[i3];
	hy = py[i0];
	ly = py[i1] | py[i2] | py[i3];
	ahx = hx & ~0x80000000;
	ahy = hy & ~0x80000000;

	if ((ahy | ly) == 0)
		return (one);		/* x**+-0 = 1 */
	else if (hx == 0x3fff0000 && lx == 0 &&
		(__xpg6 & _C99SUSv3_pow) != 0)
		return (one);		/* C99: 1**anything = 1 */
	else if (ahx > 0x7fff0000 || (ahx == 0x7fff0000 && lx != 0) ||
		ahy > 0x7fff0000 || (ahy == 0x7fff0000 && ly != 0))
		return (x + y);		/* +-NaN return x+y */
					/* includes Sun: 1**NaN = NaN */
	sbx = (unsigned) hx >> 31;
	sby = (unsigned) hy >> 31;
	ax = fabsl(x);
	/*
	 * determine if y is an odd int when x < 0
	 * yisint = 0 ... y is not an integer
	 * yisint = 1 ... y is an odd int
	 * yisint = 2 ... y is an even int
	 */
	yisint = 0;
	if (sbx) {
		if (ahy >= 0x40700000)	/* if |y|>=2**113 */
			yisint = 2;	/* even integer y */
		else if (ahy >= 0x3fff0000) {
			k = (ahy >> 16) - 0x3fff;	/* exponent */
			if (k > 80) {
				j = ((unsigned) py[i3]) >> (112 - k);
				if ((j << (112 - k)) == py[i3])
					yisint = 2 - (j & 1);
			} else if (k > 48) {
				j = ((unsigned) py[i2]) >> (80 - k);
				if ((j << (80 - k)) == py[i2])
					yisint = 2 - (j & 1);
			} else if (k > 16) {
				j = ((unsigned) py[i1]) >> (48 - k);
				if ((j << (48 - k)) == py[i1])
					yisint = 2 - (j & 1);
			} else if (ly == 0) {
				j = ahy >> (16 - k);
				if ((j << (16 - k)) == ahy)
					yisint = 2 - (j & 1);
			}
		}
	}

	/* special value of y */
	if (ly == 0) {
		if (ahy == 0x7fff0000) {	/* y is +-inf */
			if (((ahx - 0x3fff0000) | lx) == 0) {
				if ((__xpg6 & _C99SUSv3_pow) != 0)
					return (one);
						/* C99: (-1)**+-inf = 1 */
				else
					return (y - y);
						/* Sun: (+-1)**+-inf = NaN */
			} else if (ahx >= 0x3fff0000)
						/* (|x|>1)**+,-inf = inf,0 */
				return (sby == 0 ? y : zero);
			else			/* (|x|<1)**-,+inf = inf,0 */
				return (sby != 0 ? -y : zero);
		} else if (ahy == 0x3fff0000) {	/* y is +-1 */
			if (sby != 0)
				return (one / x);
			else
				return (x);
		} else if (hy == 0x40000000)	/* y is 2 */
			return (x * x);
		else if (hy == 0x3ffe0000) {	/* y is 0.5 */
			if (!((ahx | lx) == 0 || ((ahx - 0x7fff0000) | lx) ==
				0))
				return (sqrtl(x));
		}
	}

	/* special value of x */
	if (lx == 0) {
		if (ahx == 0x7fff0000 || ahx == 0 || ahx == 0x3fff0000) {
							/* x is +-0,+-inf,+-1 */
			z = ax;
			if (sby == 1)
				z = one / z;	/* z = 1/|x| if y is negative */
			if (sbx == 1) {
				if (ahx == 0x3fff0000 && yisint == 0)
					z = zero / zero;
						/* (-1)**non-int is NaN */
				else if (yisint == 1)
					z = -z;	/* (x<0)**odd = -(|x|**odd) */
			}
			return (z);
		}
	}

	/* (x<0)**(non-int) is NaN */
	if (sbx == 1 && yisint == 0)
		return (zero / zero);	/* should be volatile */

	/* Now ax is finite, y is finite */
	/* first compute log(ax) = w1+w2, with 53 bits w1 */
	w1 = logl_x(ax, &w2);

	/* split up y into y1+y2 and compute (y1+y2)*(w1+w2) */
	if (ly == 0 || ahy >= 0x43fe0000) {
		y1 = y * w1;
		y2 = y * w2;
	} else {
		y1 = (long double) ((double) y);
		y2 = (y - y1) * w1 + y * w2;
		y1 *= w1;
	}
	z = y1 + y2;
	j = pz[i0];
	if ((unsigned) j >= 0xffff0000) {		/* NaN or -inf */
		if (sbx == 1 && yisint == 1)
			return (one / z);
		else
			return (-one / z);
	} else if ((j & ~0x80000000) < 0x3fc30000) {	/* |x|<2^-60 */
		if (sbx == 1 && yisint == 1)
			return (-one - z);
		else
			return (one + z);
	} else if (j > 0) {
		if (j > 0x400d0000) {
			if (sbx == 1 && yisint == 1)
				return (scalbnl(-one, 20000));
			else
				return (scalbnl(one, 20000));
		}
		k = (int) (invln2_32 * (z + ln2_64));
	} else {
		if ((unsigned) j > 0xc00d0000) {
			if (sbx == 1 && yisint == 1)
				return (scalbnl(-one, -20000));
			else
				return (scalbnl(one, -20000));
		}
		k = (int) (invln2_32 * (z - ln2_64));
	}
	j = k & 0x1f;
	m = k >> 5;
	{
		/* rational approximation coeffs for [-(ln2)/64,(ln2)/64] */
		long double
			t1 = 1.666666666666666666666666666660876387437e-1L,
			t2 = -2.777777777777777777777707812093173478756e-3L,
			t3 = 6.613756613756613482074280932874221202424e-5L,
			t4 = -1.653439153392139954169609822742235851120e-6L,
			t5 = 4.175314851769539751387852116610973796053e-8L;
		long double t = (long double) k;

		w1 = (y2 - (t * ln2_32hi - y1)) - t * ln2_32lo;
		t = w1 * w1;
		w2 = (w1 - t * (t1 + t * (t2 + t * (t3 + t * (t4 + t * t5))))) -
			two;
		z = _TBL_expl_hi[j] - ((_TBL_expl_hi[j] * (w1 + w1)) / w2 -
			_TBL_expl_lo[j]);
	}
	j = m + (pz[i0] >> 16);
	if (j && (unsigned) j < 0x7fff)
		pz[i0] += m << 16;
	else
		z = scalbnl(z, m);

	if (sbx == 1 && yisint == 1)
		z = -z;		/* (-ve)**(odd int) */
	return (z);
}
#else
#error Unsupported Architecture
#endif	/* defined(__sparc) */

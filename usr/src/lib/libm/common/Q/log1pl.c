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

#ifdef __LITTLE_ENDIAN
#define	H0(x)	*(3 + (int *) &x)
#define	H1(x)	*(2 + (int *) &x)
#define	H2(x)	*(1 + (int *) &x)
#define	H3(x)	*(int *) &x
#else
#define	H0(x)	*(int *) &x
#define	H1(x)	*(1 + (int *) &x)
#define	H2(x)	*(2 + (int *) &x)
#define	H3(x)	*(3 + (int *) &x)
#endif

/*
 * log1pl(x)
 * Table look-up algorithm by modifying logl.c
 * By K.C. Ng, July 6, 1995
 *
 * (a). For 1+x in [31/33,33/31], using a special approximation:
 *	s = x/(2.0+x);	... here |s| <= 0.03125
 *	z = s*s;
 *	return x-s*(x-z*(B1+z*(B2+z*(B3+z*(B4+...+z*B9)...))));
 *	(i.e., x is in [-2/33,2/31])
 *
 * (b). Otherwise, normalize 1+x = 2^n * 1.f.
 * 	Here we may need a correction term for 1+x rounded.
 *	Use a 6-bit table look-up: find a 6 bit g that match f to 6.5 bits,
 *	then
 *	    log(1+x) = n*ln2 + log(1.g) + log(1.f/1.g).
 *	Here the leading and trailing values of log(1.g) are obtained from
 *	a size-64 table.
 *	For log(1.f/1.g), let s = (1.f-1.g)/(1.f+1.g). Note that
 *		1.f = 2^-n(1+x)
 *
 *	then
 *	    log(1.f/1.g) = log((1+s)/(1-s)) = 2s + 2/3 s^3 + 2/5 s^5 +...
 *	Note that |s|<2**-8=0.00390625. We use an odd s-polynomial
 *	approximation to compute log(1.f/1.g):
 *		s*(A1+s^2*(A2+s^2*(A3+s^2*(A4+s^2*(A5+s^2*(A6+s^2*A7))))))
 *	(Precision is 2**-136.91 bits, absolute error)
 *
 *      CAUTION:
 *	For x>=1, compute 1+x will lost one bit (OK).
 *	For x in [-0.5,-1), 1+x is exact.
 *	For x in (-0.5,-2/33]U[2/31,1), up to 4 last bits of x will be lost
 *	in 1+x.  Therefore, to recover the lost bits, one need to compute
 *	1.f-1.g accurately.
 *
 * 	Let hx = HI(x), m = (hx>>16)-0x3fff (=ilogbl(x)), note that
 *		-2/33 = -0.0606...= 2^-5 * 1.939...,
 *		 2/31 =  0.09375  = 2^-4 * 1.500...,
 *	so for x in (-0.5,-2/33], -5<=m<=-2,  n= -1, 1+f=2*(1+x)
 *	   for x in [2/33,1),     -4<=m<=-1,  n=  0, f=x
 *
 *      In short:
 * 	if x>0, let g: hg= ((hx + (0x200<<(-m)))>>(10-m))<<(10-m)
 *	then 1.f-1.g = x-g
 *	if x<0, let g': hg' =((ix-(0x200)<<(-m-1))>>(9-m))<<(9-m)
 *	(ix=hx&0x7fffffff)
 *	then 1.f-1.g = 2*(g'+x),
 *
 * (c). The final result is computed by
 *		(n*ln2_hi+_TBL_logl_hi[j]) +
 *			( (n*ln2_lo+_TBL_logl_lo[j]) + s*(A1+...) )
 *
 * Note.
 *	For ln2_hi and _TBL_logl_hi[j], we force their last 32 bit to be zero
 *	so that n*ln2_hi + _TBL_logl_hi[j] is exact. Here
 *	_TBL_logl_hi[j] + _TBL_logl_lo[j] match log(1+j*2**-6) to 194 bits
 *
 *
 * Special cases:
 *	log(x) is NaN with signal if x < 0 (including -INF) ;
 *	log(+INF) is +INF; log(0) is -INF with signal;
 *	log(NaN) is that NaN with no signal.
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following constants.
 * The decimal values may be used, provided that the compiler will convert
 * from decimal to binary accurately enough to produce the hexadecimal values
 * shown.
 */

#pragma weak log1pl = __log1pl

#include "libm.h"

extern const long double _TBL_logl_hi[], _TBL_logl_lo[];

static const long double
zero	=   0.0L,
one	=   1.0L,
two	=   2.0L,
ln2hi	=   6.931471805599453094172319547495844850203e-0001L,
ln2lo	=   1.667085920830552208890449330400379754169e-0025L,
A1	=   2.000000000000000000000000000000000000024e+0000L,
A2	=   6.666666666666666666666666666666091393804e-0001L,
A3	=   4.000000000000000000000000407167070220671e-0001L,
A4	=   2.857142857142857142730077490612903681164e-0001L,
A5	=   2.222222222222242577702836920812882605099e-0001L,
A6	=   1.818181816435493395985912667105885828356e-0001L,
A7	=   1.538537835211839751112067512805496931725e-0001L,
B1	=   6.666666666666666666666666666666961498329e-0001L,
B2	=   3.999999999999999999999999990037655042358e-0001L,
B3	=   2.857142857142857142857273426428347457918e-0001L,
B4	=   2.222222222222222221353229049747910109566e-0001L,
B5	=   1.818181818181821503532559306309070138046e-0001L,
B6	=   1.538461538453809210486356084587356788556e-0001L,
B7	=   1.333333344463358756121456892645178795480e-0001L,
B8	=   1.176460904783899064854645174603360383792e-0001L,
B9	=   1.057293869956598995326368602518056990746e-0001L;

long double
log1pl(long double x) {
	long double f, s, z, qn, h, t, y, g;
	int i, j, ix, iy, n, hx, m;

	hx = H0(x);
	ix = hx & 0x7fffffff;
	if (ix < 0x3ffaf07c) {	/* |x|<2/33 */
		if (ix <= 0x3f8d0000) {	/* x <= 2**-114, return x */
			if ((int) x == 0)
				return (x);
		}
		s = x / (two + x);	/* |s|<2**-8 */
		z = s * s;
		return (x - s * (x - z * (B1 + z * (B2 + z * (B3 + z * (B4 +
		    z * (B5 + z * (B6 + z * (B7 + z * (B8 + z * B9))))))))));
	}
	if (ix >= 0x7fff0000) {	/* x is +inf or NaN */
		return (x + fabsl(x));
	}
	if (hx < 0 && ix >= 0x3fff0000) {
		if (ix > 0x3fff0000 || (H1(x) | H2(x) | H3(x)) != 0)
			x = zero;
		return (x / zero);	/* log1p(x) is NaN  if x<-1 */
		/* log1p(-1) is -inf */
	}
	if (ix >= 0x7ffeffff)
		y = x;		/* avoid spurious overflow */
	else
		y = one + x;
	iy = H0(y);
	n = ((iy + 0x200) >> 16) - 0x3fff;
	iy = (iy & 0x0000ffff) | 0x3fff0000;	/* scale 1+x to [1,2] */
	H0(y) = iy;
	z = zero;
	m = (ix >> 16) - 0x3fff;
	/* HI(1+x) = (((hx&0xffff)|0x10000)>>(-m))|0x3fff0000 */
	if (n == 0) {		/* x in [2/33,1) */
		g = zero;
		H0(g) = ((hx + (0x200 << (-m))) >> (10 - m)) << (10 - m);
		t = x - g;
		i = (((((hx & 0xffff) | 0x10000) >> (-m)) | 0x3fff0000) +
			0x200) >> 10;
		H0(z) = i << 10;

	} else if ((1 + n) == 0 && (ix < 0x3ffe0000)) {	/* x in (-0.5,-2/33] */
		g = zero;
		H0(g) = ((ix + (0x200 << (-m - 1))) >> (9 - m)) << (9 - m);
		t = g + x;
		t = t + t;
		/*
		 * HI(2*(1+x)) =
		 * ((0x10000-(((hx&0xffff)|0x10000)>>(-m)))<<1)|0x3fff0000
		 */
		/*
		 * i =
		 * ((((0x10000-(((hx&0xffff)|0x10000)>>(-m)))<<1)|0x3fff0000)+
		 * 0x200)>>10; H0(z)=i<<10;
		 */
		z = two * (one - g);
		i = H0(z) >> 10;
	} else {
		i = (iy + 0x200) >> 10;
		H0(z) = i << 10;
		t = y - z;
	}

	s = t / (y + z);
	j = i & 0x3f;
	z = s * s;
	qn = (long double) n;
	t = qn * ln2lo + _TBL_logl_lo[j];
	h = qn * ln2hi + _TBL_logl_hi[j];
	f = t + s * (A1 + z * (A2 + z * (A3 + z * (A4 + z * (A5 + z * (A6 +
		z * A7))))));
	return (h + f);
}

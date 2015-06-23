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

#pragma weak __logl = logl

/*
 * logl(x)
 * Table look-up algorithm
 * By K.C. Ng, March 6, 1989
 *
 * (a). For x in [31/33,33/31], using a special approximation:
 *	f = x - 1;
 *	s = f/(2.0+f);	... here |s| <= 0.03125
 *	z = s*s;
 *	return f-s*(f-z*(B1+z*(B2+z*(B3+z*(B4+...+z*B9)...))));
 *
 * (b). Otherwise, normalize x = 2^n * 1.f.
 *	Use a 6-bit table look-up: find a 6 bit g that match f to 6.5 bits,
 *	then
 *	    log(x) = n*ln2 + log(1.g) + log(1.f/1.g).
 *	Here the leading and trailing values of log(1.g) are obtained from
 *	a size-64 table.
 *	For log(1.f/1.g), let s = (1.f-1.g)/(1.f+1.g), then
 *	    log(1.f/1.g) = log((1+s)/(1-s)) = 2s + 2/3 s^3 + 2/5 s^5 +...
 *	Note that |s|<2**-8=0.00390625. We use an odd s-polynomial
 *	approximation to compute log(1.f/1.g):
 *		s*(A1+s^2*(A2+s^2*(A3+s^2*(A4+s^2*(A5+s^2*(A6+s^2*A7))))))
 *	(Precision is 2**-136.91 bits, absolute error)
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

#include "libm.h"

extern const long double _TBL_logl_hi[], _TBL_logl_lo[];

static const long double
	zero	=   0.0L,
	one	=   1.0L,
	two	=   2.0L,
	two113  =   10384593717069655257060992658440192.0L,
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
logl(long double x) {
	long double f, s, z, qn, h, t;
	int *px = (int *) &x;
	int *pz = (int *) &z;
	int i, j, ix, i0, i1, n;

	/* get long double precision word ordering */
	if (*(int *) &one == 0) {
		i0 = 3;
		i1 = 0;
	} else {
		i0 = 0;
		i1 = 3;
	}

	n = 0;
	ix = px[i0];
	if (ix > 0x3ffee0f8) {	/* if x >  31/33 */
		if (ix < 0x3fff1084) {	/* if x < 33/31 */
			f = x - one;
			z = f * f;
			if (((ix - 0x3fff0000) | px[i1] | px[2] | px[1]) == 0) {
				return (zero);	/* log(1)= +0 */
			}
			s = f / (two + f);	/* |s|<2**-8 */
			z = s * s;
			return (f - s * (f - z * (B1 + z * (B2 + z * (B3 +
				z * (B4 + z * (B5 + z * (B6 + z * (B7 +
				z * (B8 + z * B9))))))))));
		}
		if (ix >= 0x7fff0000)
			return (x + x);	/* x is +inf or NaN */
		goto LARGE_N;
	}
	if (ix >= 0x00010000)
		goto LARGE_N;
	i = ix & 0x7fffffff;
	if ((i | px[i1] | px[2] | px[1]) == 0) {
		px[i0] |= 0x80000000;
		return (one / x);	/* log(0.0) = -inf */
	}
	if (ix < 0) {
		if ((unsigned) ix >= 0xffff0000)
			return (x - x);	/* x is -inf or NaN */
		return (zero / zero);	/* log(x<0) is NaN  */
	}
	/* subnormal x */
	x *= two113;
	n = -113;
	ix = px[i0];
LARGE_N:
	n += ((ix + 0x200) >> 16) - 0x3fff;
	ix = (ix & 0x0000ffff) | 0x3fff0000;	/* scale x to [1,2] */
	px[i0] = ix;
	i = ix + 0x200;
	pz[i0] = i & 0xfffffc00;
	pz[i1] = pz[1] = pz[2] = 0;
	s = (x - z) / (x + z);
	j = (i >> 10) & 0x3f;
	z = s * s;
	qn = (long double) n;
	t = qn * ln2lo + _TBL_logl_lo[j];
	h = qn * ln2hi + _TBL_logl_hi[j];
	f = t + s * (A1 + z * (A2 + z * (A3 + z * (A4 + z * (A5 +
		z * (A6 + z * A7))))));
	return (h + f);
}

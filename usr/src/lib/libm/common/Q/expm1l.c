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

#if defined(ELFOBJ)
#pragma weak expm1l = __expm1l
#endif
#if !defined(__sparc)
#error Unsupported architecture
#endif

/*
 * expm1l(x)
 *
 * Table driven method
 * Written by K.C. Ng, June 1995.
 * Algorithm :
 *	1. expm1(x) = x if x<2**-114
 *	2. if |x| <= 0.0625 = 1/16, use approximation
 *		expm1(x) = x + x*P/(2-P)
 * where
 * 	P = x - z*(P1+z*(P2+z*(P3+z*(P4+z*(P5+z*P6+z*P7))))), z = x*x;
 * (this formula is derived from
 *	2-P+x = R = x*(exp(x)+1)/(exp(x)-1) ~ 2 + x*x/6 - x^4/360 + ...)
 *
 * P1 =   1.66666666666666666666666666666638500528074603030e-0001
 * P2 =  -2.77777777777777777777777759668391122822266551158e-0003
 * P3 =   6.61375661375661375657437408890138814721051293054e-0005
 * P4 =  -1.65343915343915303310185228411892601606669528828e-0006
 * P5 =   4.17535139755122945763580609663414647067443411178e-0008
 * P6 =  -1.05683795988668526689182102605260986731620026832e-0009
 * P7 =   2.67544168821852702827123344217198187229611470514e-0011
 *
 * Accuracy: |R-x*(exp(x)+1)/(exp(x)-1)|<=2**-119.13
 *
 *	3. For 1/16 < |x| < 1.125, choose x(+-i) ~ +-(i+4.5)/64, i=0,..,67
 *	   since
 *		exp(x) = exp(xi+(x-xi))= exp(xi)*exp((x-xi))
 *	   we have
 *		expm1(x) = expm1(xi)+(exp(xi))*(expm1(x-xi))
 *	   where
 *		|s=x-xi| <= 1/128
 *	   and
 *	expm1(s)=2s/(2-R), R= s-s^2*(T1+s^2*(T2+s^2*(T3+s^2*(T4+s^2*T5))))
 *
 * T1 =   1.666666666666666666666666666660876387437e-1L,
 * T2 =  -2.777777777777777777777707812093173478756e-3L,
 * T3 =   6.613756613756613482074280932874221202424e-5L,
 * T4 =  -1.653439153392139954169609822742235851120e-6L,
 * T5 =   4.175314851769539751387852116610973796053e-8L;
 *
 *	4. For |x| >= 1.125, return exp(x)-1.
 *	    (see algorithm for exp)
 *
 * Special cases:
 *	expm1l(INF) is INF, expm1l(NaN) is NaN;
 *	expm1l(-INF)= -1;
 *	for finite argument, only expm1l(0)=0 is exact.
 *
 * Accuracy:
 *	according to an error analysis, the error is always less than
 *	2 ulp (unit in the last place).
 *
 * Misc. info.
 *	For 113 bit long double
 *		if x >  1.135652340629414394949193107797076342845e+4
 *      then expm1l(x) overflow;
 *
 * Constants:
 * Only decimal values are given. We assume that the compiler will convert
 * from decimal to binary accurately enough to produce the correct
 * hexadecimal values.
 */

#include "libm.h"

extern const long double _TBL_expl_hi[], _TBL_expl_lo[];
extern const long double _TBL_expm1lx[], _TBL_expm1l[];

static const long double
	zero		= +0.0L,
	one		= +1.0L,
	two		= +2.0L,
	ln2_64		= +1.083042469624914545964425189778400898568e-2L,
	ovflthreshold	= +1.135652340629414394949193107797076342845e+4L,
	invln2_32	= +4.616624130844682903551758979206054839765e+1L,
	ln2_32hi	= +2.166084939249829091928849858592451515688e-2L,
	ln2_32lo	= +5.209643502595475652782654157501186731779e-27L,
	huge		= +1.0e4000L,
	tiny		= +1.0e-4000L,
	P1 = +1.66666666666666666666666666666638500528074603030e-0001L,
	P2 = -2.77777777777777777777777759668391122822266551158e-0003L,
	P3 = +6.61375661375661375657437408890138814721051293054e-0005L,
	P4 = -1.65343915343915303310185228411892601606669528828e-0006L,
	P5 = +4.17535139755122945763580609663414647067443411178e-0008L,
	P6 = -1.05683795988668526689182102605260986731620026832e-0009L,
	P7 = +2.67544168821852702827123344217198187229611470514e-0011L,
/* rational approximation coeffs for [-(ln2)/64,(ln2)/64] */
	T1 = +1.666666666666666666666666666660876387437e-1L,
	T2 = -2.777777777777777777777707812093173478756e-3L,
	T3 = +6.613756613756613482074280932874221202424e-5L,
	T4 = -1.653439153392139954169609822742235851120e-6L,
	T5 = +4.175314851769539751387852116610973796053e-8L;

long double
expm1l(long double x) {
	int hx, ix, j, k, m;
	long double t, r, s, w;

	hx = ((int *) &x)[HIXWORD];
	ix = hx & ~0x80000000;
	if (ix >= 0x7fff0000) {
		if (x != x)
			return (x + x);	/* NaN */
		if (x < zero)
			return (-one);	/* -inf */
		return (x);	/* +inf */
	}
	if (ix < 0x3fff4000) {	/* |x| < 1.25 */
		if (ix < 0x3ffb0000) {	/* |x| < 0.0625 */
			if (ix < 0x3f8d0000) {
				if ((int) x == 0)
					return (x);	/* |x|<2^-114 */
			}
			t = x * x;
			r = (x - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t *
				(P5 + t * (P6 + t * P7)))))));
			return (x + (x * r) / (two - r));
		}
		/* compute i = [64*x] */
		m = 0x4009 - (ix >> 16);
		j = ((ix & 0x0000ffff) | 0x10000) >> m;	/* j=4,...,67 */
		if (hx < 0)
			j += 82;			/* negative */
		s = x - _TBL_expm1lx[j];
		t = s * s;
		r = s - t * (T1 + t * (T2 + t * (T3 + t * (T4 + t * T5))));
		r = (s + s) / (two - r);
		w = _TBL_expm1l[j];
		return (w + (w + one) * r);
	}
	if (hx > 0) {
		if (x > ovflthreshold)
			return (huge * huge);
		k = (int) (invln2_32 * (x + ln2_64));
	} else {
		if (x < -80.0)
			return (tiny - x / x);
		k = (int) (invln2_32 * (x - ln2_64));
	}
	j = k & 0x1f;
	m = k >> 5;
	t = (long double) k;
	x = (x - t * ln2_32hi) - t * ln2_32lo;
	t = x * x;
	r = (x - t * (T1 + t * (T2 + t * (T3 + t * (T4 + t * T5))))) - two;
	x = _TBL_expl_hi[j] - ((_TBL_expl_hi[j] * (x + x)) / r -
		_TBL_expl_lo[j]);
	return (scalbnl(x, m) - one);
}

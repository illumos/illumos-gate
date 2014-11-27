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

/*
 * expl(x)
 * Table driven method
 * Written by K.C. Ng, November 1988.
 * Algorithm :
 *	1. Argument Reduction: given the input x, find r and integer k
 *	   and j such that
 *	             x = (32k+j)*ln2 + r,  |r| <= (1/64)*ln2 .
 *
 *	2. expl(x) = 2^k * (2^(j/32) + 2^(j/32)*expm1(r))
 *	   Note:
 *	   a. expm1(r) = (2r)/(2-R), R = r - r^2*(t1 + t2*r^2)
 *	   b. 2^(j/32) is represented as
 *			_TBL_expl_hi[j]+_TBL_expl_lo[j]
 *         where
 *		_TBL_expl_hi[j] = 2^(j/32) rounded
 *		_TBL_expl_lo[j] = 2^(j/32) - _TBL_expl_hi[j].
 *
 * Special cases:
 *	expl(INF) is INF, expl(NaN) is NaN;
 *	expl(-INF)=  0;
 *	for finite argument, only expl(0)=1 is exact.
 *
 * Accuracy:
 *	according to an error analysis, the error is always less than
 *	an ulp (unit in the last place).
 *
 * Misc. info.
 *	For 113 bit long double
 *		if x >  1.135652340629414394949193107797076342845e+4
 *      then expl(x) overflow;
 *		if x < -1.143346274333629787883724384345262150341e+4
 *	then expl(x) underflow
 *
 * Constants:
 * Only decimal values are given. We assume that the compiler will convert
 * from decimal to binary accurately enough to produce the correct
 * hexadecimal values.
 */

#pragma weak __expl = expl

#include "libm.h"

extern const long double _TBL_expl_hi[], _TBL_expl_lo[];

static const long double
one		=  1.0L,
two		=  2.0L,
ln2_64		=  1.083042469624914545964425189778400898568e-2L,
ovflthreshold	=  1.135652340629414394949193107797076342845e+4L,
unflthreshold	= -1.143346274333629787883724384345262150341e+4L,
invln2_32	=  4.616624130844682903551758979206054839765e+1L,
ln2_32hi	=  2.166084939249829091928849858592451515688e-2L,
ln2_32lo	=  5.209643502595475652782654157501186731779e-27L;

/* rational approximation coeffs for [-(ln2)/64,(ln2)/64] */
static const long double
t1 =   1.666666666666666666666666666660876387437e-1L,
t2 =  -2.777777777777777777777707812093173478756e-3L,
t3 =   6.613756613756613482074280932874221202424e-5L,
t4 =  -1.653439153392139954169609822742235851120e-6L,
t5 =   4.175314851769539751387852116610973796053e-8L;

long double
expl(long double x) {
	int *px = (int *) &x, ix, j, k, m;
	long double t, r;

	ix = px[0];				/* high word of x */
	if (ix >= 0x7fff0000)
		return (x + x);			/* NaN of +inf */
	if (((unsigned) ix) >= 0xffff0000)
		return (-one / x);		/* NaN or -inf */
	if ((ix & 0x7fffffff) < 0x3fc30000) {
		if ((int) x < 1)
			return (one + x);	/* |x|<2^-60 */
	}
	if (ix > 0) {
		if (x > ovflthreshold)
			return (scalbnl(x, 20000));
		k = (int) (invln2_32 * (x + ln2_64));
	} else {
		if (x < unflthreshold)
			return (scalbnl(-x, -40000));
		k = (int) (invln2_32 * (x - ln2_64));
	}
	j  = k&0x1f;
	m  = k>>5;
	t  = (long double) k;
	x  = (x - t * ln2_32hi) - t * ln2_32lo;
	t  = x * x;
	r  = (x - t * (t1 + t * (t2 + t * (t3 + t * (t4 + t * t5))))) - two;
	x  = _TBL_expl_hi[j] - ((_TBL_expl_hi[j] * (x + x)) / r -
		_TBL_expl_lo[j]);
	return (scalbnl(x, m));
}

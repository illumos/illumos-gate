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
 * __k_cosl(long double x, long double y)
 * kernel cos function on [-pi/4, pi/4], pi/4 ~ 0.785398164
 * Input x is assumed to be bounded by ~pi/4 in magnitude.
 * Input y is the tail of x.
 *
 * Table look up algorithm
 *	1. by cos(-x) = cos(x), we may replace x by |x|
 *	2. if x < 25/128 = [0x3ffc4000, 0] = 0.15625 , then
 *	     if x < 2^-57 (hx < 0x3fc60000 0), return 1.0 with inexact if x !=  0
 *	     z = x*x;
 *	     if x <= 1/128 = 2**-7 = 0.0078125
 *		cos(x)=1.0+z*(qq1+z*(qq2+z*(qq3+z*(qq4+z*qq5))))
 *	     else
 *	        cos(x)=1.0+z*(q1+ ... z*q8)
 *	3. else
 *		ht = (hx + 0x400)&0x7ffff800	(round x to a break point t)
 *		lt = 0
 *		i  = (hy-0x3ffc4000)>>11;	(i<=64)
 *		x' = (x - t)+y 			(|x'| ~<= 2^-7
 *	   By
 *		cos(t+x')
 *		  = cos(t)cos(x')-sin(t)sin(x')
 *		  = cos(t)(1+z*(qq1+z*qq2))-[sin(t)]*x*(1+z*(pp1+z*pp2))
 *		  = cos(t) + [cos(t)]*(z*(qq1+z*qq2))-
 *				[sin(t)]*x*(1+z*(pp1+z*pp2))
 *
 *	   Thus,
 *		let a= _TBL_cos_hi[i], b = _TBL_cos_lo[i], c= _TBL_sin_hi[i],
 *		x = (x-t)+y
 *		z = x*x;
 *		cos(t+x) = a+(b+ (-c*x*(1+z*(pp1+z*pp2))+a*(z*(qq1+z*qq2)))
 */

#include "libm.h"

extern const long double _TBL_cosl_hi[], _TBL_cosl_lo[], _TBL_sinl_hi[];
static const long double
	one	= 1.0L,
/*
 *                   3           11       -122.32
 * |sin(x) - (x+pp1*x +...+ pp5*x  )| <= 2        for |x|<1/64
 */
	pp1	= -1.666666666666666666666666666586782940810e-0001L,
	pp2	= +8.333333333333333333333003723660929317540e-0003L,
	pp3	= -1.984126984126984076045903483778337804470e-0004L,
	pp4	= +2.755731922361906641319723106210900949413e-0006L,
	pp5	= -2.505198398570947019093998469135012057673e-0008L,
/*
 *		    2	         16       -117.11
 * |cos(x) - (1+q1*x + ... + q8*x  )| <= 2        for |x|<= 0.15625
 */
	q1	= -4.999999999999999999999999999999756416975e-0001L,
	q2	= +4.166666666666666666666666664006066577258e-0002L,
	q3	= -1.388888888888888888888877700363937169637e-0003L,
	q4	= +2.480158730158730158494468463031814083559e-0005L,
	q5	= -2.755731922398586276322819250356005542871e-0007L,
	q6	= +2.087675698767424261441959760729854017855e-0009L,
	q7	= -1.147074481239662089072452129010790774761e-0011L,
	q8	= +4.777761647399651599730663422263531034782e-0014L,
/*
 *		     2	         10       -123.84
 * |cos(x) - (1+qq1*x +...+ qq5*x  )| <= 2        for |x|<=1/128
 */
	qq1	= -4.999999999999999999999999999999378373641e-0001L,
	qq2	= +4.166666666666666666666665478399327703130e-0002L,
	qq3	= -1.388888888888888888058211230618051613494e-0003L,
	qq4	= +2.480158730156105377771585658905303111866e-0005L,
	qq5	= -2.755728099762526325736488376695157008736e-0007L;

#define	i0	0

long double
__k_cosl(long double x, long double y) {
	long double a, t, z, w;
	int *pt = (int *) &t, *px = (int *) &x;
	int i, j, hx, ix;

	t = 1.0L;
	hx = px[i0];
	ix = hx & 0x7fffffff;
	if (ix < 0x3ffc4000) {
		if (ix < 0x3fc60000)
			if ((i = (int) x) == 0)
				return (one);	/* generate inexact */
		z = x * x;

		if (ix < 0x3ff80000)	/* 0.0078125 */
			return one + z * (qq1 + z * (qq2 + z * (qq3 +
				z * (qq4 + z * qq5))));
		else
			return one + z * (q1 + z * (q2 + z * (q3 +
				z * (q4 + z * (q5 + z * (q6 + z * (q7 +
				z * q8)))))));
	}
	j = (ix + 0x400) & 0x7ffff800;
	i = (j - 0x3ffc4000) >> 11;
	pt[i0] = j;
	if (hx > 0)
		x = y - (t - x);
	else
		x = (-y) - (t + x);
	a = _TBL_cosl_hi[i];
	z = x * x;
	t = z * (qq1 + z * (qq2 + z * (qq3 + z * (qq4 + z * qq5))));
	w = x * (one + z * (pp1 + z * (pp2 + z * (pp3 + z * (pp4 + z * pp5)))));
	t = _TBL_cosl_lo[i] - (_TBL_sinl_hi[i] * w - a * t);
	return (a + t);
}

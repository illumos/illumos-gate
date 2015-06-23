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

/* INDENT OFF */
/*
 * __k_sinl( long double x;  long double y )
 * kernel sin function on [-pi/4, pi/4], pi/4 ~ 0.785398164
 * Input x is assumed to be bounded by ~pi/4 in magnitude.
 * Input y is the tail of x.
 *
 * Table look up algorithm
 *	1. by sin(-x) = -sin(x), need only to consider positive x
 *	2. if x < 25/128 = [0x3ffc9000,0,0,0] = 0.1953125 , then
 *	     if x < 2^-57 (hx < 0x3fc60000,0,0,0), return x (inexact if x !=  0)
 *	     z = x*x;
 *	     if x <= 1/64 = 2**-6
 *		sin(x) = x + (y+(x*z)*(p1 + z*p2))
 *	     else
 *		sin(x) = x + (y+(x*z)*(p1 + z*(p2 + z*(p3 + z*p4))))
 *	3. else
 *		ht = (hx + 0x400)&0x7ffff800	(round x to a break point t)
 *		lt = 0
 *		i  = (hy-0x3ffc4000)>>11;	(i<=64)
 *		x' = (x - t)+y 			(|x'| ~<= 2^-7
 *	   By
 *		sin(t+x')
 *		  = sin(t)cos(x')+cos(t)sin(x')
 *		  = sin(t)(1+z*(qq1+z*qq2))+[cos(t)]*x*(1+z*(pp1+z*pp2))
 *		  = sin(t) + [sin(t)]*(z*(qq1+z*qq2))+
 *				[cos(t)]*x*(1+z*(pp1+z*pp2))
 *
 *	   Thus,
 *		let a= _TBL_sin_hi[i], b = _TBL_sin_lo[i], c= _TBL_cos_hi[i],
 *		x = (x-t)+y
 *		z = x*x;
 *		sin(t+x) = a+(b+ ((c*x)*(1+z*(pp1+z*pp2))+a*(z*(qq1+z*qq2)))
 */

#include "libm.h"

#include <sys/isa_defs.h>

extern const long double _TBL_sinl_hi[], _TBL_sinl_lo[], _TBL_cosl_hi[];
static const long double
one	= 1.0,
/*
 * |sin(x) - (x+pp1*x^3+...+ pp5*x^11)| <= 2^-122.32 for |x|<1/64
 */
pp1	= -1.666666666666666666666666666586782940810e-0001L,
pp2	=  8.333333333333333333333003723660929317540e-0003L,
pp3	= -1.984126984126984076045903483778337804470e-0004L,
pp4	=  2.755731922361906641319723106210900949413e-0006L,
pp5	= -2.505198398570947019093998469135012057673e-0008L,
/*
 * |(sin(x) - (x+p1*x^3+...+p8*x^17)|
 * |------------------------------- | <= 2^-116.17 for |x|<0.1953125
 * |                 x              |
 */
p1	= -1.666666666666666666666666666666211262297e-0001L,
p2	=  8.333333333333333333333333301497876908541e-0003L,
p3	= -1.984126984126984126984041302881180621922e-0004L,
p4	=  2.755731922398589064100587351307269621093e-0006L,
p5	= -2.505210838544163129378906953765595393873e-0008L,
p6	=  1.605904383643244375050998243778534074273e-0010L,
p7	= -7.647162722800685516901456114270824622699e-0013L,
p8	=  2.810046428661902961725428841068844462603e-0015L,
/*
 *		     2	         10        -123.84
 * |cos(x) - (1+qq1*x +...+ qq5*x  )| <= 2        for |x|<=1/128
 */
qq1	= -4.999999999999999999999999999999378373641e-0001L,
qq2	=  4.166666666666666666666665478399327703130e-0002L,
qq3	= -1.388888888888888888058211230618051613494e-0003L,
qq4	=  2.480158730156105377771585658905303111866e-0005L,
qq5	= -2.755728099762526325736488376695157008736e-0007L;
/* INDENT ON */
long double
__k_sinl(long double x, long double y) {
	long double a, t, z, w;
	int *pt = (int *) &t, *px = (int *) &x;
	int i, j, hx, ix;

	t = 1.0L;
#if defined(__i386) || defined(__amd64)
	XTOI(px, hx);
#else
	hx = px[0];
#endif
	ix = hx & 0x7fffffff;
	if (ix < 0x3ffc9000) {
		if (ix < 0x3fc60000)
			if (((int) x) == 0)
				return (x);	/* generate inexact */
		z = x * x;
		t = z * (p1 + z * (p2 + z * (p3 + z * (p4 + z * (p5 + z *
			(p6 + z * (p7 + z * p8)))))));
		t = y + x * t;
		return (x + t);
	}
	j = (ix + 0x400) & 0x7ffff800;
	i = (j - 0x3ffc4000) >> 11;
#if defined(__i386) || defined(__amd64)
	ITOX(j, pt);
#else
	pt[0] = j;
#endif
	if (hx > 0)
		x = y - (t - x);
	else
		x = (-y) - (t + x);
	a = _TBL_sinl_hi[i];
	z = x * x;
	t = z * (qq1 + z * (qq2 + z * (qq3 + z * (qq4 + z * qq5))));
	w = x * (one + z * (pp1 + z * (pp2 + z * (pp3 + z * (pp4 + z *
		pp5)))));
	t = _TBL_cosl_hi[i] * w + a * t;
	t += _TBL_sinl_lo[i];
	if (hx < 0)
		return (-a - t);
	else
		return (a + t);
}

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
 * __k_tanl( long double x;  long double y; int k )
 * kernel tan/cotan function on [-pi/4, pi/4], pi/4 ~ 0.785398164
 * Input x is assumed to be bounded by ~pi/4 in magnitude.
 * Input y is the tail of x.
 * Input k indicate -- tan if k=0; else -1/tan
 *
 * Table look up algorithm
 *	1. by tan(-x) = -tan(x), need only to consider positive x
 *	2. if x < 5/32 = [0x3ffc4000, 0] = 0.15625 , then
 *	     if x < 2^-57 (hx < 0x3fc40000 0), set w=x with inexact if x !=  0
 *	     else
 *		z = x*x;
 *		w = x + (y+(x*z)*(t1+z*(t2+z*(t3+z*(t4+z*(t5+z*t6))))))
 *	   return (k == 0 ? w : 1/w);
 *	3. else
 *		ht = (hx + 0x400)&0x7ffff800	(round x to a break point t)
 *		lt = 0
 *		i  = (hy-0x3ffc4000)>>11;	(i<=64)
 *		x' = (x - t)+y 			(|x'| ~<= 2^-7)
 *	   By
 *		tan(t+x')
 *		  = (tan(t)+tan(x'))/(1-tan(x')tan(t))
 *	   We have
 *		             sin(x')+tan(t)*(tan(t)*sin(x'))
 *		  = tan(t) + -------------------------------	for k=0
 *			        cos(x') - tan(t)*sin(x')
 *
 *		             cos(x') - tan(t)*sin(x')
 *		  = - --------------------------------------	for k=1
 *		       tan(t) + tan(t)*(cos(x')-1) + sin(x')
 *
 *
 *	   where 	tan(t) is from the table,
 *			sin(x') = x + pp1*x^3 + ...+ pp5*x^11
 *			cos(x') = 1 + qq1*x^2 + ...+ qq5*x^10
 */

#include "libm.h"

#include <sys/isa_defs.h>

extern const long double _TBL_tanl_hi[], _TBL_tanl_lo[];
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
 *                   2           10        -123.84
 * |cos(x) - (1+qq1*x +...+ qq5*x  )| <= 2        for |x|<=1/128
 */
qq1	= -4.999999999999999999999999999999378373641e-0001L,
qq2	=  4.166666666666666666666665478399327703130e-0002L,
qq3	= -1.388888888888888888058211230618051613494e-0003L,
qq4	=  2.480158730156105377771585658905303111866e-0005L,
qq5	= -2.755728099762526325736488376695157008736e-0007L,
/*
 * |tan(x) - (x+t1*x^3+...+t6*x^13)|
 * |------------------------------ | <= 2^-59.73 for |x|<0.15625
 * |                x              |
 */
t1	=  3.333333333333333333333333333333423342490e-0001L,
t2	=  1.333333333333333333333333333093838744537e-0001L,
t3	=  5.396825396825396825396827906318682662250e-0002L,
t4	=  2.186948853615520282185576976994418486911e-0002L,
t5	=  8.863235529902196573354554519991152936246e-0003L,
t6	=  3.592128036572480064652191427543994878790e-0003L,
t7	=  1.455834387051455257856833807581901305474e-0003L,
t8	=  5.900274409318599857829983256201725587477e-0004L,
t9	=  2.391291152117265181501116961901122362937e-0004L,
t10	=  9.691533169382729742394024173194981882375e-0005L,
t11	=  3.927994733186415603228178184225780859951e-0005L,
t12	=  1.588300018848323824227640064883334101288e-0005L,
t13	=  6.916271223396808311166202285131722231723e-0006L;
/* INDENT ON */
long double
__k_tanl(long double x, long double y, int k) {
	long double a, t, z, w = 0.0, s, c;
	int *pt = (int *) &t, *px = (int *) &x;
	int i, j, hx, ix;

	t = 1.0;
#if defined(__i386) || defined(__amd64)
	XTOI(px, hx);
#else
	hx = px[0];
#endif
	ix = hx & 0x7fffffff;
	if (ix < 0x3ffc4000) {
		if (ix < 0x3fc60000) {
			if ((i = (int) x) == 0)	/* generate inexact */
				w = x;
		} else {
			z = x * x;
			if (ix < 0x3ff30000)	/* 2**-12 */
				t = z * (t1 + z * (t2 + z * (t3 + z * t4)));
			else
				t = z * (t1 + z * (t2 + z * (t3 + z * (t4 +
					z * (t5 + z * (t6 + z * (t7 + z *
					(t8 + z * (t9 + z * (t10 + z * (t11 +
					z * (t12 + z * t13))))))))))));
			t = y + x * t;
			w = x + t;
		}
		return (k == 0 ? w : -one / w);
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
	a = _TBL_tanl_hi[i];
	z = x * x;
	/* cos(x)-1 */
	t = z * (qq1 + z * (qq2 + z * (qq3 + z * (qq4 + z * qq5))));
	/* sin(x) */
	s = x * (one + z * (pp1 + z * (pp2 + z * (pp3 + z * (pp4 + z *
		pp5)))));
	if (k == 0) {
		w = a * s;
		t = _TBL_tanl_lo[i] + (s + a * w) / (one - (w - t));
		return (hx < 0 ? -a - t : a + t);
	} else {
		w = s + a * t;
		c = w + _TBL_tanl_lo[i];
		z = (one - (a * s - t));
		return (hx >= 0 ? z / (-a - c) : z / (a + c));
	}
}

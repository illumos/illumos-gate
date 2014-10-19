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
 * __k_tan( double x;  double y; int k )
 * kernel tan/cotan function on [-pi/4, pi/4], pi/4 ~ 0.785398164
 * Input x is assumed to be bounded by ~pi/4 in magnitude.
 * Input y is the tail of x.
 * Input k indicate -- tan if k=0; else -1/tan
 *
 * Table look up algorithm
 *	1. by tan(-x) = -tan(x), need only to consider positive x
 *	2. if x < 5/32 = [0x3fc40000, 0] = 0.15625 , then
 *	     if x < 2^-27 (hx < 0x3e400000 0), set w=x with inexact if x !=  0
 *	     else
 *		z = x*x;
 *		w = x + (y+(x*z)*(t1+z*(t2+z*(t3+z*(t4+z*(t5+z*t6))))))
 *	   return (k == 0)? w: 1/w;
 *	3. else
 *		ht = (hx + 0x4000)&0x7fff8000	(round x to a break point t)
 *		lt = 0
 *		i  = (hy-0x3fc40000)>>15;	(i<=64)
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
 *			sin(x') = x + pp1*x^3 + pp2*x^5
 *			cos(x') = 1 + qq1*x^2 + qq2*x^4
 */

#include "libm.h"

extern const double _TBL_tan_hi[], _TBL_tan_lo[];
static const double q[] = {
/* one  = */  1.0,
/*
 *                       2       2       -59.56
 * |sin(x) - pp1*x*(pp2+x *(pp3+x )| <= 2        for |x|<1/64
 */
/* pp1  = */  8.33326120969096230395312119298978359438478946686e-0003,
/* pp2  = */  1.20001038589438965215025680596868692381425944526e+0002,
/* pp3  = */ -2.00001730975089451192161504877731204032897949219e+0001,

/*
 *                   2      2        -56.19
 * |cos(x) - (1+qq1*x (qq2+x ))| <= 2        for |x|<=1/128
 */
/* qq1  = */  4.16665486385721928197511942926212213933467864990e-0002,
/* qq2  = */ -1.20000339921340035687080671777948737144470214844e+0001,

/*
 * |tan(x) - PF(x)|
 * |--------------| <= 2^-58.57 for |x|<0.15625
 * |      x       |
 *
 * where (let z = x*x)
 *	PF(x) = x + (t1*x*z)(t2 + z(t3 + z))(t4 + z)(t5 + z(t6 + z))
 */
/* t1 = */  3.71923358986516816929168705030406272271648049355e-0003,
/* t2 = */  6.02645120354857866118436504621058702468872070312e+0000,
/* t3 = */  2.42627327587398156083509093150496482849121093750e+0000,
/* t4 = */  2.44968983934252770851003333518747240304946899414e+0000,
/* t5 = */  6.07089252571767978849948121933266520500183105469e+0000,
/* t6 = */ -2.49403756995593761658369658107403665781021118164e+0000,
};


#define	one q[0]
#define	pp1 q[1]
#define	pp2 q[2]
#define	pp3 q[3]
#define	qq1 q[4]
#define	qq2 q[5]
#define	t1  q[6]
#define	t2  q[7]
#define	t3  q[8]
#define	t4  q[9]
#define	t5  q[10]
#define	t6  q[11]

/* INDENT ON */


double
__k_tan(double x, double y, int k) {
	double a, t, z, w = 0.0L, s, c, r, rh, xh, xl;
	int i, j, hx, ix;

	t = one;
	hx = ((int *) &x)[HIWORD];
	ix = hx & 0x7fffffff;
	if (ix < 0x3fc40000) {		/* 0.15625 */
		if (ix < 0x3e400000) {	/* 2^-27 */
			if ((i = (int) x) == 0)		/* generate inexact */
				w = x;
			t = y;
		} else {
			z = x * x;
			t = y + (((t1 * x) * z) * (t2 + z * (t3 + z))) *
				((t4 + z) * (t5 + z * (t6 + z)));
			w = x + t;
		}
		if (k == 0)
			return (w);
		/*
		 * Compute -1/(x+T) with great care
		 * Let r = -1/(x+T), rh = r chopped to 20 bits.
		 * Also let xh	= x+T chopped to 20 bits, xl = (x-xh)+T. Then
		 *   -1/(x+T)	= rh + (-1/(x+T)-rh) = rh + r*(1+rh*(x+T))
		 *		= rh + r*((1+rh*xh)+rh*xl).
		 */
		rh = r = -one / w;
		((int *) &rh)[LOWORD] = 0;
		xh = w;
		((int *) &xh)[LOWORD] = 0;
		xl = (x - xh) + t;
		return (rh + r * ((one + rh * xh) + rh * xl));
	}
	j = (ix + 0x4000) & 0x7fff8000;
	i = (j - 0x3fc40000) >> 15;
	((int *) &t)[HIWORD] = j;
	if (hx > 0)
		x = y - (t - x);
	else
		x = -y - (t + x);
	a = _TBL_tan_hi[i];
	z = x * x;
	s = (pp1 * x) * (pp2 + z * (pp3 + z));	/* sin(x) */
	t = (qq1 * z) * (qq2 + z);		/* cos(x) - 1 */
	if (k == 0) {
		w = a * s;
		t = _TBL_tan_lo[i] + (s + a * w) / (one - (w - t));
		return (hx < 0 ? -a - t : a + t);
	} else {
		w = s + a * t;
		c = w + _TBL_tan_lo[i];
		t = a * s - t;
		/*
		 * Now try to compute [(1-T)/(a+c)] accurately
		 *
		 * Let r = 1/(a+c), rh = (1-T)*r chopped to 20 bits.
		 * Also let xh = a+c chopped to 20 bits, xl = (a-xh)+c. Then
		 *	(1-T)/(a+c) = rh + ((1-T)/(a+c)-rh)
		 *		= rh + r*(1-T-rh*(a+c))
		 *		= rh + r*((1-T-rh*xh)-rh*xl)
		 *		= rh + r*(((1-rh*xh)-T)-rh*xl)
		 */
		r = one / (a + c);
		rh = (one - t) * r;
		((int *) &rh)[LOWORD] = 0;
		xh = a + c;
		((int *) &xh)[LOWORD] = 0;
		xl = (a - xh) + c;
		z = rh + r * (((one - rh * xh) - t) - rh * xl);
		return (hx >= 0 ? -z : z);
	}
}

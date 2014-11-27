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

#pragma weak __atanl = atanl

/*
 * atanl(x)
 * Table look-up algorithm
 * By K.C. Ng, March 9, 1989
 *
 * Algorithm.
 *
 * The algorithm is based on atan(x)=atan(y)+atan((x-y)/(1+x*y)).
 * We use poly1(x) to approximate atan(x) for x in [0,1/8] with
 * error (relative)
 * 	|(atan(x)-poly1(x))/x|<= 2^-115.94 	long double
 * 	|(atan(x)-poly1(x))/x|<= 2^-58.85	double
 * 	|(atan(x)-poly1(x))/x|<= 2^-25.53 	float
 * and use poly2(x) to approximate atan(x) for x in [0,1/65] with
 * error (absolute)
 *	|atan(x)-poly2(x)|<= 2^-122.15		long double
 *	|atan(x)-poly2(x)|<= 2^-64.79		double
 *	|atan(x)-poly2(x)|<= 2^-35.36		float
 * Here poly1 and poly2 are odd polynomial with the following form:
 *		x + x^3*(a1+x^2*(a2+...))
 *
 * (0). Purge off Inf and NaN and 0
 * (1). Reduce x to positive by atan(x) = -atan(-x).
 * (2). For x <= 1/8, use
 *	(2.1) if x < 2^(-prec/2-2), atan(x) =  x  with inexact
 *	(2.2) Otherwise
 *		atan(x) = poly1(x)
 * (3). For x >= 8 then
 *	(3.1) if x >= 2^(prec+2),   atan(x) = atan(inf) - pio2lo
 *	(3.2) if x >= 2^(prec/3+2), atan(x) = atan(inf) - 1/x
 *	(3.3) if x >  65,           atan(x) = atan(inf) - poly2(1/x)
 *	(3.4) Otherwise,	    atan(x) = atan(inf) - poly1(1/x)
 *
 * (4). Now x is in (0.125, 8)
 *      Find y that match x to 4.5 bit after binary (easy).
 *	If iy is the high word of y, then
 *		single : j = (iy - 0x3e000000) >> 19
 *		double : j = (iy - 0x3fc00000) >> 16
 *		quad   : j = (iy - 0x3ffc0000) >> 12
 *
 *	Let s = (x-y)/(1+x*y). Then
 *	atan(x) = atan(y) + poly1(s)
 *		= _TBL_atanl_hi[j] + (_TBL_atanl_lo[j] + poly2(s) )
 *
 *	Note. |s| <= 1.5384615385e-02 = 1/65. Maxium occurs at x = 1.03125
 *
 */

#include "libm.h"

extern const long double _TBL_atanl_hi[], _TBL_atanl_lo[];
static const long double
	one	=   1.0L,
	p1  	=  -3.333333333333333333333333333331344526118e-0001L,
	p2  	=   1.999999999999999999999999989931277668570e-0001L,
	p3  	=  -1.428571428571428571428553606221309530901e-0001L,
	p4  	=   1.111111111111111111095219842737139747418e-0001L,
	p5  	=  -9.090909090909090825503603835248061123323e-0002L,
	p6  	=   7.692307692307664052130743214708925258904e-0002L,
	p7  	=  -6.666666666660213835187713228363717388266e-0002L,
	p8  	=   5.882352940152439399097283359608661949504e-0002L,
	p9  	=  -5.263157780447533993046614040509529668487e-0002L,
	p10 	=   4.761895816878184933175855990886788439447e-0002L,
	p11 	=  -4.347345005832274022681019724553538135922e-0002L,
	p12 	=   3.983031914579635037502589204647752042736e-0002L,
	p13 	=  -3.348206704469830575196657749413894897554e-0002L,
	q1  	=  -3.333333333333333333333333333195273650186e-0001L,
	q2  	=   1.999999999999999999999988146114392615808e-0001L,
	q3  	=  -1.428571428571428571057630319435467111253e-0001L,
	q4  	=   1.111111111111105373263048208994541544098e-0001L,
	q5  	=  -9.090909090421834209167373258681021816441e-0002L,
	q6  	=   7.692305377813692706850171767150701644539e-0002L,
	q7  	=  -6.660896644393861499914731734305717901330e-0002L,
	pio2hi	=   1.570796326794896619231321691639751398740e+0000L,
	pio2lo	=   4.335905065061890512398522013021675984381e-0035L;

#define	i0	0
#define	i1	3

long double
atanl(long double x) {
	long double y, z, r, p, s;
	int *px = (int *) &x, *py = (int *) &y;
	int ix, iy, sign, j;

	ix = px[i0];
	sign = ix & 0x80000000;
	ix ^= sign;

	/* for |x| < 1/8 */
	if (ix < 0x3ffc0000) {
		if (ix < 0x3feb0000) {	/* when |x| < 2**(-prec/6-2) */
			if (ix < 0x3fc50000) {	/* if |x| < 2**(-prec/2-2) */
				s = one;
				*(3 - i0 + (int *) &s) = -1;	/* s = 1-ulp */
				*(1 + (int *) &s) = -1;
				*(2 + (int *) &s) = -1;
				*(i0 + (int *) &s) -= 1;
				if ((int) (s * x) < 1)
					return (x);	/* raise inexact */
			}
			z = x * x;
			if (ix < 0x3fe20000) {	/* if |x| < 2**(-prec/4-1) */
				return (x + (x * z) * p1);
			} else {	/* if |x| < 2**(-prec/6-2) */
				return (x + (x * z) * (p1 + z * p2));
			}
		}
		z = x * x;
		return (x + (x * z) * (p1 + z * (p2 + z * (p3 + z * (p4 +
			z * (p5 + z * (p6 + z * (p7 + z * (p8 + z * (p9 +
			z * (p10 + z * (p11 + z * (p12 + z * p13)))))))))))));
	}

	/* for |x| >= 8.0 */
	if (ix >= 0x40020000) {
		px[i0] = ix;
		if (ix < 0x40050400) {	/* x <  65 */
			r = one / x;
			z = r * r;
			/*
			 * poly1
			 */
			y = r * (one + z * (p1 + z * (p2 + z * (p3 +
				z * (p4 + z * (p5 + z * (p6 + z * (p7 +
				z * (p8 + z * (p9 + z * (p10 + z * (p11 +
				z * (p12 + z * p13)))))))))))));
			y -= pio2lo;
		} else if (ix < 0x40260000) {	/* x <  2**(prec/3+2) */
			r = one / x;
			z = r * r;
			/*
			 * poly2
			 */
			y = r * (one + z * (q1 + z * (q2 + z * (q3 + z * (q4 +
				z * (q5 + z * (q6 + z * q7)))))));
			y -= pio2lo;
		} else if (ix < 0x40720000) {	/* x <  2**(prec+2) */
			y = one / x - pio2lo;
		} else if (ix < 0x7fff0000) {	/* x <  inf */
			y = -pio2lo;
		} else {		/* x is inf or NaN */
			if (((ix - 0x7fff0000) | px[1] | px[2] | px[i1]) != 0)
				return (x - x);
			y = -pio2lo;
		}

		if (sign == 0)
			return (pio2hi - y);
		else
			return (y - pio2hi);
	}

	/* now x is between 1/8 and 8 */
	px[i0] = ix;
	iy = (ix + 0x00000800) & 0x7ffff000;
	py[i0] = iy;
	py[1] = py[2] = py[i1] = 0;
	j = (iy - 0x3ffc0000) >> 12;

	if (sign == 0)
		s = (x - y) / (one + x * y);
	else
		s = (y - x) / (one + x * y);
	z = s * s;
	if (ix == iy)
		p = s * (one + z * (q1 + z * (q2 + z * (q3 + z * q4))));
	else
		p = s * (one + z * (q1 + z * (q2 + z * (q3 + z * (q4 +
			z * (q5 + z * (q6 + z * q7)))))));
	if (sign == 0) {
		r = p + _TBL_atanl_lo[j];
		return (r + _TBL_atanl_hi[j]);
	} else {
		r = p - _TBL_atanl_lo[j];
		return (r - _TBL_atanl_hi[j]);
	}
}

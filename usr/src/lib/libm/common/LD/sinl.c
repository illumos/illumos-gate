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

#pragma weak __sinl = sinl

/* INDENT OFF */
/* sinl(x)
 * Table look-up algorithm by K.C. Ng, November, 1989.
 *
 * kernel function:
 *	__k_sinl		... sin function on [-pi/4,pi/4]
 *	__k_cosl		... cos function on [-pi/4,pi/4]
 *	__rem_pio2l	... argument reduction routine
 *
 * Method.
 *      Let S and C denote the sin and cos respectively on [-PI/4, +PI/4].
 *      1. Assume the argument x is reduced to y1+y2 = x-k*pi/2 in
 *	   [-pi/2 , +pi/2], and let n = k mod 4.
 *	2. Let S=S(y1+y2), C=C(y1+y2). Depending on n, we have
 *
 *          n        sin(x)      cos(x)        tan(x)
 *     ----------------------------------------------------------
 *	    0	       S	   C		 S/C
 *	    1	       C	  -S		-C/S
 *	    2	      -S	  -C		 S/C
 *	    3	      -C	   S		-C/S
 *     ----------------------------------------------------------
 *
 * Special cases:
 *      Let trig be any of sin, cos, or tan.
 *      trig(+-INF)  is NaN, with signals;
 *      trig(NaN)    is that NaN;
 *
 * Accuracy:
 *	computer TRIG(x) returns trig(x) nearly rounded.
 */
/* INDENT ON */

#include "libm.h"
#include "longdouble.h"

#include <sys/isa_defs.h>

long double
sinl(long double x) {
	long double y[2], z = 0.0L;
	int n, ix;
#if defined(__i386) || defined(__amd64)
	int *px = (int *) &x;
#endif

	/* sin(Inf or NaN) is NaN */
	if (!finitel(x))
		return x - x;

	/* High word of x. */
#if defined(__i386) || defined(__amd64)
	XTOI(px, ix);
#else
	ix = *(int *) &x;
#endif
	/* |x| ~< pi/4 */
	ix &= 0x7fffffff;
	if (ix <= 0x3ffe9220)
		return __k_sinl(x, z);

	/* argument reduction needed */
	else {
		n = __rem_pio2l(x, y);
		switch (n & 3) {
		case 0:
			return __k_sinl(y[0], y[1]);
		case 1:
			return __k_cosl(y[0], y[1]);
		case 2:
			return -__k_sinl(y[0], y[1]);
		case 3:
			return -__k_cosl(y[0], y[1]);
		/* NOTREACHED */
		}
	}
	return 0.0L;
}

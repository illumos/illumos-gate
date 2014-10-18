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

#pragma weak atan = __atan

/* INDENT OFF */
/*
 * atan(x)
 * Accurate Table look-up algorithm with polynomial approximation in
 * partially product form.
 *
 * -- K.C. Ng, October 17, 2004
 *
 * Algorithm
 *
 * (1). Purge off Inf and NaN and 0
 * (2). Reduce x to positive by atan(x) = -atan(-x).
 * (3). For x <= 1/8 and let z = x*x, return
 *	(2.1) if x < 2^(-prec/2), atan(x) = x  with inexact flag raised
 *	(2.2) if x < 2^(-prec/4-1), atan(x) = x+(x/3)(x*x)
 *	(2.3) if x < 2^(-prec/6-2), atan(x) = x+(z-5/3)(z*x/5)
 *	(2.4) Otherwise
 *		atan(x) = poly1(x) = x + A * B,
 *	where
 *		A = (p1*x*z) * (p2+z(p3+z))
 *		B = (p4+z)+z*z) * (p5+z(p6+z))
 *	Note: (i) domain of poly1 is [0, 1/8], (ii) remez relative
 *	approximation error of poly1 is bounded by
 * 		|(atan(x)-poly1(x))/x| <= 2^-57.61
 * (4). For x >= 8 then
 *	(3.1) if x >= 2^prec,     atan(x) = atan(inf) - pio2lo
 *	(3.2) if x >= 2^(prec/3), atan(x) = atan(inf) - 1/x
 *	(3.3) if x <= 65,	  atan(x) = atan(inf) - poly1(1/x)
 *	(3.4) otherwise           atan(x) = atan(inf) - poly2(1/x)
 *	where
 *		poly2(r) = (q1*r) * (q2+z(q3+z)) * (q4+z),
 *	its domain is [0, 0.0154]; and its remez absolute
 *	approximation error is bounded by
 *		|atan(x)-poly2(x)|<= 2^-59.45
 *
 * (5). Now x is in (0.125, 8).
 *	Recall identity
 *		atan(x) = atan(y) + atan((x-y)/(1+x*y)).
 *	Let j = (ix - 0x3fc00000) >> 16, 0 <= j < 96, where ix is the high
 *	part of x in IEEE double format. Then
 *		atan(x) = atan(y[j]) + poly2((x-y[j])/(1+x*y[j]))
 *	where y[j] are carefully chosen so that it matches x to around 4.5
 *	bits and at the same time atan(y[j]) is very close to an IEEE double
 *	floating point number. Calculation indicates that
 *		max|(x-y[j])/(1+x*y[j])| < 0.0154
 *		j,x
 *
 * Accuracy: Maximum error observed is bounded by 0.6 ulp after testing
 * more than 10 million random arguments
 */
/* INDENT ON */

#include "libm.h"
#include "libm_synonyms.h"
#include "libm_protos.h"

extern const double _TBL_atan[];
static const double g[] = {
/* one	= */  1.0,
/* p1	= */  8.02176624254765935351230154992663301527500152588e-0002,
/* p2	= */  1.27223421700559402580665846471674740314483642578e+0000,
/* p3	= */ -1.20606901800503640842521235754247754812240600586e+0000,
/* p4	= */ -2.36088967922325565496066701598465442657470703125e+0000,
/* p5	= */  1.38345799501389166152875986881554126739501953125e+0000,
/* p6	= */  1.06742368078953453469637224770849570631980895996e+0000,
/* q1   = */ -1.42796626333911796935538518482644576579332351685e-0001,
/* q2   = */  3.51427110447873227059810477159863497078605962912e+0000,
/* q3   = */  5.92129112708164262457444237952586263418197631836e-0001,
/* q4   = */ -1.99272234785683144409063061175402253866195678711e+0000,
/* pio2hi */  1.570796326794896558e+00,
/* pio2lo */  6.123233995736765886e-17,
/* t1   = */ -0.333333333333333333333333333333333,
/* t2   = */  0.2,
/* t3   = */ -1.666666666666666666666666666666666,
};

#define	one g[0]
#define	p1 g[1]
#define	p2 g[2]
#define	p3 g[3]
#define	p4 g[4]
#define	p5 g[5]
#define	p6 g[6]
#define	q1 g[7]
#define	q2 g[8]
#define	q3 g[9]
#define	q4 g[10]
#define	pio2hi g[11]
#define	pio2lo g[12]
#define	t1 g[13]
#define	t2 g[14]
#define	t3 g[15]


double
atan(double x) {
	double y, z, r, p, s;
	int ix, lx, hx, j;

	hx = ((int *) &x)[HIWORD];
	lx = ((int *) &x)[LOWORD];
	ix = hx & ~0x80000000;
	j = ix >> 20;

	/* for |x| < 1/8 */
	if (j < 0x3fc) {
		if (j < 0x3f5) {	/* when |x| < 2**(-prec/6-2) */
			if (j < 0x3e3) {	/* if |x| < 2**(-prec/2-2) */
				return ((int) x == 0 ? x : one);
			}
			if (j < 0x3f1) {	/* if |x| < 2**(-prec/4-1) */
				return (x + (x * t1) * (x * x));
			} else {	/* if |x| < 2**(-prec/6-2) */
				z = x * x;
				s = t2 * x;
				return (x + (t3 + z) * (s * z));
			}
		}
		z = x * x; s = p1 * x;
		return (x + ((s * z) * (p2 + z * (p3 + z))) *
				(((p4 + z) + z * z) * (p5 + z * (p6 + z))));
	}

	/* for |x| >= 8.0 */
	if (j >= 0x402) {
		if (j < 0x436) {
			r = one / x;
			if (hx >= 0) {
				y =  pio2hi; p =  pio2lo;
			} else {
				y = -pio2hi; p = -pio2lo;
			}
			if (ix < 0x40504000) {	/* x <  65 */
				z = r * r;
				s = p1 * r;
				return (y + ((p - r) - ((s * z) *
					(p2 + z * (p3 + z))) *
					(((p4 + z) + z * z) *
					(p5 + z * (p6 + z)))));
			} else if (j < 0x412) {
				z = r * r;
				return (y + (p - ((q1 * r) * (q4 + z)) *
					(q2 + z * (q3 + z))));
			} else
				return (y + (p - r));
		} else {
			if (j >= 0x7ff) /* x is inf or NaN */
				if (((ix - 0x7ff00000) | lx) != 0)
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
					return (ix >= 0x7ff80000 ? x : x - x);
					/* assumes sparc-like QNaN */
#else
					return (x - x);
#endif
			y = -pio2lo;
			return (hx >= 0 ? pio2hi - y : y - pio2hi);
		}
	} else {	/* now x is between 1/8 and 8 */
		double *w, w0, w1, s, z;
		w = (double *) _TBL_atan + (((ix - 0x3fc00000) >> 16) << 1);
		w0 = (hx >= 0)? w[0] : -w[0];
		s = (x - w0) / (one + x * w0);
		w1 = (hx >= 0)? w[1] : -w[1];
		z = s * s;
		return (((q1 * s) * (q4 + z)) * (q2 + z * (q3 + z)) + w1);
	}
}

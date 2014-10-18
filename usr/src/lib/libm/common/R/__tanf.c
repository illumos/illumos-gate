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

#include "libm.h"

/* INDENT OFF */
/*
 * float __k_tan(double x);
 * kernel (float) tan function on [-pi/4, pi/4], pi/4 ~ 0.785398164
 * Input x is in double and assumed to be bounded by ~pi/4 in magnitude.
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following constants.
 * The decimal values may be used, provided that the compiler will convert
 * from decimal to binary accurately enough to produce the hexadecimal values
 * shown.
 */

static const double q[] = {
/* one */ 1.0,
/* P0 */  4.46066928428959230679140546271810308098793029785e-0003,
/* P1 */  4.92165316309189027066395283327437937259674072266e+0000,
/* P2 */ -7.11410648161473480044492134766187518835067749023e-0001,
/* P3 */  4.08549808374053391446523164631798863410949707031e+0000,
/* P4 */  2.50411070398050927821032018982805311679840087891e+0000,
/* P5 */  1.11492064560251158411574579076841473579406738281e+0001,
/* P6 */ -1.50565540968422650891511693771462887525558471680e+0000,
/* P7 */ -1.81484378878349295050043110677506774663925170898e+0000,
/* T0 */  3.333335997532835641297409611782510896641e-0001,
/* T1 */  2.999997598248363761541668282006867229939e+00,
};
/* INDENT ON */

#define	one q[0]
#define	P0 q[1]
#define	P1 q[2]
#define	P2 q[3]
#define	P3 q[4]
#define	P4 q[5]
#define	P5 q[6]
#define	P6 q[7]
#define	P7 q[8]
#define	T0 q[9]
#define	T1 q[10]

float
__k_tanf(double x, int n) {
	float ft = 0.0;
	double z, w;
	int ix;

	ix = ((int *) &x)[HIWORD] & ~0x80000000;	/* ix = leading |x| */
	/* small argument */
	if (ix < 0x3f800000) {		/* if |x| < 0.0078125 = 2**-7 */
		if (ix < 0x3f100000) {	/* if |x| < 2**-14 */
			if ((int) x == 0) {	/* raise inexact if x != 0 */
				ft = n == 0 ? (float) x : (float) (-one / x);
			}
			return (ft);
		}
		z = (x * T0) * (T1 + x * x);
		ft = n == 0 ? (float) z : (float) (-one / z);
		return (ft);
	}
	z = x * x;
	w = ((P0 * x) * (P1 + z * (P2 + z)) * (P3 + z * (P4 + z)))
		* (P5 + z * (P6 + z * (P7 + z)));
	ft = n == 0 ? (float) w : (float) (-one / w);
	return (ft);
}

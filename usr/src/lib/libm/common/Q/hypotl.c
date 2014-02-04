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

#pragma weak hypotl = __hypotl

/*
 * long double hypotl(long double x, long double y);
 * Method :
 *	If z=x*x+y*y has error less than sqrt(2)/2 ulp than sqrt(z) has
 *	error less than 1 ulp.
 *	So, compute sqrt(x*x+y*y) with some care as follows:
 *	Assume x>y>0;
 *	1. save and set rounding to round-to-nearest
 *	2. if x > 2y  use
 *		x1*x1+(y*y+(x2*(x+x2))) for x*x+y*y
 *	where x1 = x with lower 64 bits cleared, x2 = x-x1; else
 *	3. if x <= 2y use
 *		t1*y1+((x-y)*(x-y)+(t1*y2+t2*y))
 *	where t1 = 2x with lower 64 bits cleared, t2 = 2x-t1, y1= y with
 *	lower 64 bits chopped, y2 = y-y1.
 *
 *	NOTE: DO NOT remove parenthsis!
 *
 * Special cases:
 *	hypot(x,y) is INF if x or y is +INF or -INF; else
 *	hypot(x,y) is NAN if x or y is NAN.
 *
 * Accuracy:
 * 	hypot(x,y) returns sqrt(x^2+y^2) with error less than 1 ulps (units
 *	in the last place)
 */

#include "libm.h"
#include "longdouble.h"

extern enum fp_direction_type __swapRD(enum fp_direction_type);

static const long double zero = 0.0L, one = 1.0L;

long double
hypotl(long double x, long double y) {
	int n0, n1, n2, n3;
	long double t1, t2, y1, y2, w;
	int *px = (int *) &x, *py = (int *) &y;
	int *pt1 = (int *) &t1, *py1 = (int *) &y1;
	enum fp_direction_type rd;
	int j, k, nx, ny, nz;

	if ((*(int *) &one) != 0) {	/* determine word ordering */
		n0 = 0;
		n1 = 1;
		n2 = 2;
		n3 = 3;
	} else {
		n0 = 3;
		n1 = 2;
		n2 = 1;
		n3 = 0;
	}

	px[n0] &= 0x7fffffff;	/* clear sign bit of x and y */
	py[n0] &= 0x7fffffff;
	k = 0x7fff0000;
	nx = px[n0] & k;	/* exponent of x and y */
	ny = py[n0] & k;
	if (ny > nx) {
		w = x;
		x = y;
		y = w;
		nz = ny;
		ny = nx;
		nx = nz;
	}			/* force x > y */
	if ((nx - ny) >= 0x00730000)
		return (x + y);	/* x/y >= 2**116 */
	if (nx < 0x5ff30000 && ny > 0x205b0000) {	/* medium x,y */
		/* save and set RD to Rounding to nearest */
		rd = __swapRD(fp_nearest);
		w = x - y;
		if (w > y) {
			pt1[n0] = px[n0];
			pt1[n1] = px[n1];
			pt1[n2] = pt1[n3] = 0;
			t2 = x - t1;
			x = sqrtl(t1 * t1 - (y * (-y) - t2 * (x + t1)));
		} else {
			x = x + x;
			py1[n0] = py[n0];
			py1[n1] = py[n1];
			py1[n2] = py1[n3] = 0;
			y2 = y - y1;
			pt1[n0] = px[n0];
			pt1[n1] = px[n1];
			pt1[n2] = pt1[n3] = 0;
			t2 = x - t1;
			x = sqrtl(t1 * y1 - (w * (-w) - (t2 * y1 + y2 * x)));
		}
		if (rd != fp_nearest)
			(void) __swapRD(rd);	/* restore rounding mode */
		return (x);
	} else {
		if (nx == k || ny == k) {	/* x or y is INF or NaN */
			if (isinfl(x))
				t2 = x;
			else if (isinfl(y))
				t2 = y;
			else
				t2 = x + y;	/* invalid if x or y is sNaN */
			return (t2);
		}
		if (ny == 0) {
			if (y == zero || x == zero)
				return (x + y);
			t1 = scalbnl(one, 16381);
			x *= t1;
			y *= t1;
			return (scalbnl(one, -16381) * hypotl(x, y));
		}
		j = nx - 0x3fff0000;
		px[n0] -= j;
		py[n0] -= j;
		pt1[n0] = nx;
		pt1[n1] = pt1[n2] = pt1[n3] = 0;
		return (t1 * hypotl(x, y));
	}
}

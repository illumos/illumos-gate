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

#pragma weak __hypotl = hypotl

/*
 * hypotl(x,y)
 * Method :
 *	If z=x*x+y*y has error less than sqrt(2)/2 ulp than sqrt(z) has
 *	error less than 1 ulp.
 *	So, compute sqrt(x*x+y*y) with some care as follows:
 *	Assume x>y>0;
 *	1. save and set rounding to round-to-nearest
 *	2. if x > 2y  use
 *		x1*x1+(y*y+(x2*(x+x2))) for x*x+y*y
 *	where x1 = x with lower 32 bits cleared, x2 = x-x1; else
 *	3. if x <= 2y use
 *		t1*y1+((x-y)*(x-y)+(t1*y2+t2*y))
 *	where t1 = 2x with lower 64 bits cleared, t2 = 2x-t1, y1= y with
 *	lower 32 bits cleared, y2 = y-y1.
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

#if defined(__x86)
extern enum fp_direction_type __swap87RD(enum fp_direction_type);

#define	k	0x7fff

long double
hypotl(long double x, long double y) {
	long double t1, t2, y1, y2, w;
	int *px = (int *) &x, *py = (int *) &y;
	int *pt1 = (int *) &t1, *py1 = (int *) &y1;
	enum fp_direction_type rd;
	int j, nx, ny, nz;

	px[2] &= 0x7fff;	/* clear sign bit and padding bits of x and y */
	py[2] &= 0x7fff;
	nx = px[2];		/* biased exponent of x and y */
	ny = py[2];
	if (ny > nx) {
		w = x;
		x = y;
		y = w;
		nz = ny;
		ny = nx;
		nx = nz;
	}			/* force nx >= ny */
	if (nx - ny >= 66)
		return (x + y);	/* x / y >= 2**65 */
	if (nx < 0x5ff3 && ny > 0x205b) {	/* medium x,y */
		/* save and set RD to Rounding to nearest */
		rd = __swap87RD(fp_nearest);
		w = x - y;
		if (w > y) {
			pt1[2] = px[2];
			pt1[1] = px[1];
			pt1[0] = 0;
			t2 = x - t1;
			x = sqrtl(t1 * t1 - (y * (-y) - t2 * (x + t1)));
		} else {
			x += x;
			py1[2] = py[2];
			py1[1] = py[1];
			py1[0] = 0;
			y2 = y - y1;
			pt1[2] = px[2];
			pt1[1] = px[1];
			pt1[0] = 0;
			t2 = x - t1;
			x = sqrtl(t1 * y1 - (w * (-w) - (t2 * y1 + y2 * x)));
		}
		if (rd != fp_nearest)
			__swap87RD(rd);	/* restore rounding mode */
		return (x);
	} else {
		if (nx == k || ny == k) {	/* x or y is INF or NaN */
			/* since nx >= ny; nx is always k within this block */
			if (px[1] == 0x80000000 && px[0] == 0)
				return (x);
			else if (ny == k && py[1] == 0x80000000 && py[0] == 0)
				return (y);
			else
				return (x + y);
		}
		if (ny == 0) {
			if (y == 0.L || x == 0.L)
				return (x + y);
			pt1[2] = 0x3fff + 16381;
			pt1[1] = 0x80000000;
			pt1[0] = 0;
			py1[2] = 0x3fff - 16381;
			py1[1] = 0x80000000;
			py1[0] = 0;
			x *= t1;
			y *= t1;
			return (y1 * hypotl(x, y));
		}
		j = nx - 0x3fff;
		px[2] -= j;
		py[2] -= j;
		pt1[2] = nx;
		pt1[1] = 0x80000000;
		pt1[0] = 0;
		return (t1 * hypotl(x, y));
	}
}
#endif

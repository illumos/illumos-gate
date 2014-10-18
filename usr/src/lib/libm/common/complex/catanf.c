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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak catanf = __catanf

#include "libm.h"
#include "complex_wrapper.h"

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const float
	pi_2 = 1.570796326794896558e+00F,
	zero = 0.0F,
	half = 0.5F,
	two = 2.0F,
	one = 1.0F;

fcomplex
catanf(fcomplex z) {
	fcomplex	ans;
	float		x, y, ax, ay, t;
	double		dx, dy, dt;
	int		hx, hy, ix, iy;

	x = F_RE(z);
	y = F_IM(z);
	ax = fabsf(x);
	ay = fabsf(y);
	hx = THE_WORD(x);
	hy = THE_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;

	if (ix >= 0x7f800000) {		/* x is inf or NaN */
		if (ix == 0x7f800000) {
			F_RE(ans) = pi_2;
			F_IM(ans) = zero;
		} else {
			F_RE(ans) = x * x;
			if (iy == 0 || iy == 0x7f800000)
				F_IM(ans) = zero;
			else
				F_IM(ans) = (fabsf(y) - ay) / (fabsf(y) - ay);
		}
	} else if (iy >= 0x7f800000) {	/* y is inf or NaN */
		if (iy == 0x7f800000) {
			F_RE(ans) = pi_2;
			F_IM(ans) = zero;
		} else {
			F_RE(ans) = (fabsf(x) - ax) / (fabsf(x) - ax);
			F_IM(ans) = y * y;
		}
	} else if (ix == 0) {
		/* INDENT OFF */
		/*
		 * x = 0
		 *      1                            1
		 * A = --- * atan2(2x, 1-x*x-y*y) = --- atan2(0,1-|y|)
		 *      2                            2
		 *
		 *     1     [ (y+1)*(y+1) ]   1          2      1         2y
		 * B = - log [ ----------- ] = - log (1+ ---) or - log(1+ ----)
		 *     4     [ (y-1)*(y-1) ]   2         y-1     2         1-y
		 */
		/* INDENT ON */
		t = one - ay;
		if (iy == 0x3f800000) {
			/* y=1: catan(0,1)=(0,+inf) with 1/0 signal */
			F_IM(ans) = ay / ax;
			F_RE(ans) = zero;
		} else if (iy > 0x3f800000) {	/* y>1 */
			F_IM(ans) = half * log1pf(two / (-t));
			F_RE(ans) = pi_2;
		} else {		/* y<1 */
			F_IM(ans) = half * log1pf((ay + ay) / t);
			F_RE(ans) = zero;
		}
	} else {
		/* INDENT OFF */
		/*
		 * use double precision x,y
		 *      1
		 * A = --- * atan2(2x, 1-x*x-y*y)
		 *      2
		 *
		 *     1     [ x*x+(y+1)*(y+1) ]   1               4y
		 * B = - log [ --------------- ] = - log (1+ -----------------)
		 *     4     [ x*x+(y-1)*(y-1) ]   4         x*x + (y-1)*(y-1)
		 */
		/* INDENT ON */
#if defined(__i386) && !defined(__amd64)
		int	rp = __swapRP(fp_extended);
#endif
		dx = (double)ax;
		dy = (double)ay;
		F_RE(ans) = (float)(0.5 * atan2(dx + dx,
		    1.0 - dx * dx - dy * dy));
		dt = dy - 1.0;
		F_IM(ans) = (float)(0.25 * log1p(4.0 * dy /
		    (dx * dx + dt * dt)));
#if defined(__i386) && !defined(__amd64)
		if (rp != fp_extended)
			(void) __swapRP(rp);
#endif
	}
	if (hx < 0)
		F_RE(ans) = -F_RE(ans);
	if (hy < 0)
		F_IM(ans) = -F_IM(ans);
	return (ans);
}

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

#pragma weak clogf = __clogf

#include "libm.h"
#include "complex_wrapper.h"

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

fcomplex
clogf(fcomplex z) {
	fcomplex	ans;
	float		x, y, ax, ay;
	double		dx, dy;
	int		ix, iy, hx, hy;

	x = F_RE(z);
	y = F_IM(z);
	hx = THE_WORD(x);
	hy = THE_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	ay = fabsf(y);
	ax = fabsf(x);
	F_IM(ans) = atan2f(y, x);
	if (ix >= 0x7f800000 || iy >= 0x7f800000) {
		/* x or y is Inf or NaN */
		if (iy == 0x7f800000)
			F_RE(ans) = ay;
		else if (ix == 0x7f800000)
			F_RE(ans) = ax;
		else
			F_RE(ans) = ax + ay;
	} else {
#if defined(__i386) && !defined(__amd64)
		int	rp = __swapRP(fp_extended);
#endif
		dx = (double)ax;
		dy = (double)ay;
		if (ix == 0x3f800000)
			F_RE(ans) = (float)(0.5 * log1p(dy * dy));
		else if (iy == 0x3f800000)
			F_RE(ans) = (float)(0.5 * log1p(dx * dx));
		else if ((ix | iy) == 0)
			F_RE(ans) = -1.0f / ax;
		else
			F_RE(ans) = (float)(0.5 * log(dx * dx + dy * dy));
#if defined(__i386) && !defined(__amd64)
		if (rp != fp_extended)
			(void) __swapRP(rp);
#endif
	}
	return (ans);
}

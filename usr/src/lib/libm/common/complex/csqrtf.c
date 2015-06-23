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

#pragma weak __csqrtf = csqrtf

#include "libm.h"		/* sqrt/fabsf/sqrtf */
#include "complex_wrapper.h"

/* INDENT OFF */
static const float zero = 0.0F;
/* INDENT ON */

fcomplex
csqrtf(fcomplex z) {
	fcomplex ans;
	double dt, dx, dy;
	float x, y, t, ax, ay, w;
	int ix, iy, hx, hy;

	x = F_RE(z);
	y = F_IM(z);
	hx = THE_WORD(x);
	hy = THE_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	ay = fabsf(y);
	ax = fabsf(x);
	if (ix >= 0x7f800000 || iy >= 0x7f800000) {
		/* x or y is Inf or NaN */
		if (iy == 0x7f800000)
			F_IM(ans) = F_RE(ans) = ay;
		else if (ix == 0x7f800000) {
			if (hx > 0) {
				F_RE(ans) = ax;
				F_IM(ans) = ay * zero;
			} else {
				F_RE(ans) = ay * zero;
				F_IM(ans) = ax;
			}
		} else
			F_IM(ans) = F_RE(ans) = ax + ay;
	} else if (iy == 0) {
		if (hx >= 0) {
			F_RE(ans) = sqrtf(ax);
			F_IM(ans) = zero;
		} else {
			F_IM(ans) = sqrtf(ax);
			F_RE(ans) = zero;
		}
	} else {
		dx = (double) ax;
		dy = (double) ay;
		dt = sqrt(0.5 * (sqrt(dx * dx + dy * dy) + dx));
		t = (float) dt;
		w = (float) (dy / (dt + dt));
		if (hx >= 0) {
			F_RE(ans) = t;
			F_IM(ans) = w;
		} else {
			F_IM(ans) = t;
			F_RE(ans) = w;
		}
	}
	if (hy < 0)
		F_IM(ans) = -F_IM(ans);
	return (ans);
}

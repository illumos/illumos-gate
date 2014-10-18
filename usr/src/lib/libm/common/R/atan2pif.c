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

#pragma weak atan2pif = __atan2pif

#include "libm.h"

static const double invpi = 0.3183098861837906715377675;

float
atan2pif(float y, float x) {
	int	ix, iy, hx, hy;

	ix = *(int *)&x;
	iy = *(int *)&y;
	hx = ix & ~0x80000000;
	hy = iy & ~0x80000000;
	if (hx > 0x7f800000 || hy > 0x7f800000) /* x or y is nan */
		return (x * y);
	if ((hx | hy) == 0) {
		/* x and y are both zero */
		if (ix == 0)
			return (y);
		return ((iy == 0)? 1.0f : -1.0f);
	}
	return ((float)(invpi * atan2((double)y, (double)x)));
}

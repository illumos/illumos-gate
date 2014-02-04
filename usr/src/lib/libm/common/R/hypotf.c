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

#pragma weak hypotf = __hypotf

#include "libm.h"

float
hypotf(float x, float y) {
	double dx, dy;
	float w;
	int ix, iy;

	ix = (*(int *) &x) & 0x7fffffff;
	iy = (*(int *) &y) & 0x7fffffff;
	if (ix >= 0x7f800000) {
		if (ix == 0x7f800000)
			*(int *) &w = x == y ? iy : ix;	/* w = |x| = inf */
		else if (iy == 0x7f800000)
			*(int *) &w = x == y ? ix : iy;	/* w = |y| = inf */
		else
			w = fabsf(x) * fabsf(y);	/* + -> * for Cheetah */
	} else if (iy >= 0x7f800000) {
		if (iy == 0x7f800000)
			*(int *) &w = x == y ? ix : iy;	/* w = |y| = inf */
		else
			w = fabsf(x) * fabsf(y);	/* + -> * for Cheetah */
	} else if (ix == 0)
		*(int *) &w = iy;	/* w = |y|  */
	else if (iy == 0)
		*(int *) &w = ix;	/* w = |x|  */
	else {
		dx = (double) x;
		dy = (double) y;
		w = (float) sqrt(dx * dx + dy * dy);
	}
	return (w);
}

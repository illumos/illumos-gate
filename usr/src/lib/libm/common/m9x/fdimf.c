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

#pragma weak fdimf = __fdimf

#include "libm.h"	/* for islessequal macro */

float
__fdimf(float x, float y) {
	/*
	 * On SPARC v8plus/v9, this could be implemented as follows
	 * (assuming %f0 = x, %f1 = y, return value left in %f0):
	 *
	 * fcmps	%fcc0,%f0,%f1
	 * st		%g0,[scratch]	! use fzero instead of st/ld
	 * ld		[scratch],%f2	! if VIS is available
	 * fnegs	%f2,%f3
	 * fmovsle	%fcc0,%f2,%f0
	 * fmovsle	%fcc0,%f3,%f1
	 * fsubs	%f0,%f1,%f0
	 */
	if (islessequal(x, y)) {
		x = 0.0f;
		y = -x;
	}
	return (x - y);
}

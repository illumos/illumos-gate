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

#pragma weak fdim = __fdim

/*
 * fdim(x,y) returns x - y if x > y, +0 if x <= y, and NaN if x and
 * y are unordered.
 *
 * fdim(x,y) raises overflow or inexact if x > y and x - y overflows
 * or is inexact.  It raises invalid if either operand is a signaling
 * NaN.  Otherwise, it raises no exceptions.
 */

#include "libm.h"	/* for islessequal macro */

double
__fdim(double x, double y) {
	if (islessequal(x, y)) {
		x = 0.0;
		y = -x;
	}
	return (x - y);
}

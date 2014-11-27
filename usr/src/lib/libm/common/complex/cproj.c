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

#pragma weak __cproj = cproj

/* INDENT OFF */
/*
 * dcomplex cproj(dcomplex z);
 *
 * If one of the component of z = (x,y) is an inf, then
 *	cproj(z) = (+inf, copysign(0,y));
 * otherwise,
 *	cproj(z) = z
 */
/* INDENT ON */

#include "libm.h"			/* fabs */
#include "complex_wrapper.h"

static const double zero = 0.0;

dcomplex
cproj(dcomplex z) {
	double x, y;
	int ix, iy, hx, hy, lx, ly;

	x = D_RE(z);
	y = D_IM(z);
	hx = HI_WORD(x);
	lx = LO_WORD(x);
	hy = HI_WORD(y);
	ly = LO_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	if (ISINF(iy, ly)) {
		D_RE(z) = fabs(y);
		D_IM(z) = hy >= 0 ? zero : -zero;
	} else if (ISINF(ix, lx)) {
		D_RE(z) = fabs(x);
		D_IM(z) = hy >= 0 ? zero : -zero;
	}
	return (z);
}

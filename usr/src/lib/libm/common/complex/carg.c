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

#pragma weak carg = __carg

#include "libm_synonyms.h"
#include <math.h>		/* atan2 */
#include "complex_wrapper.h"

static const double
	pi	= 3.14159265358979311600e+00,
	pi_lo	= 1.22464679914735320717e-16;

double
carg(dcomplex z) {
	int	ix, iy;

	ix = ((int *)&(D_RE(z)))[HIWORD];
	iy = ((int *)&(D_IM(z)))[HIWORD];
	if ((((ix | iy) & ~0x80000000) | ((int *)&(D_RE(z)))[LOWORD] |
	    ((int *)&(D_IM(z)))[LOWORD]) == 0) {
		/* x and y are both zero */
		if (ix == 0)
			return (D_IM(z));
		return ((iy == 0)? pi + pi_lo : -pi - pi_lo);
	}
	return (atan2(D_IM(z), D_RE(z)));
}

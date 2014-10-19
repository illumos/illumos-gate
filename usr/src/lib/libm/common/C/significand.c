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

#if defined(ELFOBJ)
#pragma weak significand = __significand
#endif

#include "libm.h"

double
significand(double x) {
	int ix = ((int *) &x)[HIWORD] & ~0x80000000;

	/* weed out 0/+-Inf/NaN because C99 ilogb raises invalid on them */
	if ((ix | ((int *) &x)[LOWORD]) == 0 || ix >= 0x7ff00000)
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
		return ((ix & 0x80000) != 0 ? x : x + x);
		/* assumes sparc-like QNaN */
#else
		return (x + x);
#endif
	else
		return (scalbn(x, -ilogb(x)));
}

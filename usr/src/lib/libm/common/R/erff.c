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

#pragma weak erff = __erff
#pragma weak erfcf = __erfcf

#include "libm.h"

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

float
erff(float x) {
	int	ix;

	ix = *(int *)&x & ~0x80000000;
	if (ix > 0x7f800000)	/* x is NaN */
		return (x * x);
	return ((float)erf((double)x));
}

float
erfcf(float x) {
	float	f;
	int	ix;
#if defined(__i386) && !defined(__amd64)
	int	rp;
#endif

	ix = *(int *)&x & ~0x80000000;
	if (ix > 0x7f800000)	/* x is NaN */
		return (x * x);

#if defined(__i386) && !defined(__amd64)
	rp = __swapRP(fp_extended);
#endif
	f = (float)erfc((double)x);
#if defined(__i386) && !defined(__amd64)
	if (rp != fp_extended)
		(void) __swapRP(rp);
#endif
	return (f);
}

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

#pragma weak scalb = __scalb
#pragma weak _scalb = __scalb

#include "libm.h"

double
scalb(double x, double fn) {
	int	hn, in, n;
	double	z;

	if (isnan(x) || isnan(fn))
		return (x * fn);

	in = ((int *)&fn)[HIWORD];
	hn = in & ~0x80000000;
	if (hn == 0x7ff00000)	/* fn is inf */
		return (_SVID_libm_err(x, fn, 47));

	/* see if fn is an integer without raising inexact */
	if (hn >= 0x43300000) {
		/* |fn| >= 2^52, so it must be an integer */
		n = (in < 0)? -65000 : 65000;
	} else if (hn < 0x3ff00000) {
		/* |fn| < 1, so it must be zero or non-integer */
		return ((fn == 0.0)? x : (x - x) / (x - x));
	} else if (hn < 0x41400000) {
		/* |fn| < 2^21 */
		if ((hn & ((1 << (0x413 - (hn >> 20))) - 1))
		    | ((int *)&fn)[LOWORD])
			return ((x - x) / (x - x));
		n = (int)fn;
	} else {
		if (((int *)&fn)[LOWORD] & ((1 << (0x433 - (hn >> 20))) - 1))
			return ((x - x) / (x - x));
		n = (in < 0)? -65000 : 65000;
	}
	z = scalbn(x, n);
	if (z != x) {
		if (z == 0.0)
			return (_SVID_libm_err(x, fn, 33));
		if (!finite(z))
			return (_SVID_libm_err(x, fn, 32));
	}
	return (z);
}

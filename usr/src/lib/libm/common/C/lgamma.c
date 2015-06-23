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

#pragma weak __lgamma = lgamma

#include "libm.h"

extern int signgam;

double
lgamma(double x) {
	double	g;

	if (!finite(x))
		return (x * x);

	g = rint(x);
	if (x == g && x <= 0.0) {
		signgam = 1;
		return (_SVID_libm_err(x, x, 15));
	}

	g = __k_lgamma(x, &signgam);
	if (!finite(g))
	    g = _SVID_libm_err(x, x, 14);
	return (g);
}

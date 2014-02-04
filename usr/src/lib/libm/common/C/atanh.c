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

#pragma weak atanh = __atanh

/* INDENT OFF */
/*
 * atanh(x)
 * Code originated from 4.3bsd.
 * Modified by K.C. Ng for SUN 4.0 libm.
 * Method :
 *                  1              2x                          x
 *	atanh(x) = --- * log(1 + -------) = 0.5 * log1p(2 * --------)
 *                  2             1 - x                      1 - x
 * Note: to guarantee atanh(-x) = -atanh(x), we use
 *                 sign(x)             |x|
 *	atanh(x) = ------- * log1p(2*-------).
 *                    2              1 - |x|
 *
 * Special cases:
 *	atanh(x) is NaN if |x| > 1 with signal;
 *	atanh(NaN) is that NaN with no signal;
 *	atanh(+-1) is +-INF with signal.
 */
/* INDENT ON */

#include "libm.h"
#include "libm_synonyms.h"
#include "libm_protos.h"
#include <math.h>

double
atanh(double x) {
	double t;

	if (isnan(x))
		return (x * x);		/* switched from x + x for Cheetah */
	t = fabs(x);
	if (t > 1.0)
		return (_SVID_libm_err(x, x, 30));	/* sNaN */
	if (t == 1.0)
		return (_SVID_libm_err(x, x, 31));	/* x/0; */
	t = t / (1.0 - t);
	return (copysign(0.5, x) * log1p(t + t));
}

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

#pragma weak cacosh = __cacosh

/* INDENT OFF */
/*
 * dcomplex cacosh(dcomplex z);
 *	cacosh z = +-i cacos z .
 * In order to make conj(cacosh(z))=cacosh(conj(z)),
 * we define
 *	cacosh z = sign(Im(z))*i cacos z .
 *
 */
/* INDENT ON */

#include "libm.h"	/* fabs/isnan/isinf/signbit */
#include "complex_wrapper.h"

/* need to work on special cases according to spec */

dcomplex
cacosh(dcomplex z) {
	dcomplex w, ans;
	double x, y;

	w = cacos(z);
	x = D_RE(z);
	y = D_IM(z);
	if (isnan(y)) {
		D_IM(ans) = y + y;
		if (isinf(x))
			D_RE(ans) = fabs(x);
		else
			D_RE(ans) = y;
	} else if (signbit(y) == 0) {
		D_RE(ans) = -D_IM(w);
		D_IM(ans) = D_RE(w);
	} else {
		D_RE(ans) = D_IM(w);
		D_IM(ans) = -D_RE(w);
	}
	return (ans);
}

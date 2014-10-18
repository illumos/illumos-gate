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

#pragma weak cacoshl = __cacoshl

#include "libm.h"	/* fabsl/isnanl/isinfl/signbitl */
#include "complex_wrapper.h"
#include "longdouble.h"

/* INDENT OFF */
/*
 * ldcomplex cacoshl(ldcomplex z);
 *	cacosh z = +-i cacos z .
 * In order to make conj(cacosh(z))=cacosh(conj(z)),
 * we define
 *	cacosh z = sign(Im(z))*i cacos z .
 *
 */
/* INDENT ON */

ldcomplex
cacoshl(ldcomplex z) {
	ldcomplex w, ans;
	long double x, y;

	w = cacosl(z);
	x = LD_RE(z);
	y = LD_IM(z);
	if (isnanl(y)) {
		LD_IM(ans) = y + y;
		if (isinfl(x))
			LD_RE(ans) = fabsl(x);
		else
			LD_RE(ans) = y;
	} else if (signbitl(y) == 0) {
		LD_RE(ans) = -LD_IM(w);
		LD_IM(ans) = LD_RE(w);
	} else {
		LD_RE(ans) = LD_IM(w);
		LD_IM(ans) = -LD_RE(w);
	}
	return (ans);
}

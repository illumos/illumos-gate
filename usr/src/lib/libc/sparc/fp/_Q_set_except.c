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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/ieeefp.h>
#include <ieeefp.h>

static const double zero = 0.0, tiny = 1.0e-307, tiny2 = 1.001e-307,
	huge = 1.0e300;

/*
 * _Q_set_exception(ex) simulates the floating point exceptions indicated by
 * ex.  This routine is not used by the new quad emulation routines but is
 * still used by ../crt/_ftoll.c.
 */
int
_Q_set_exception(unsigned int ex)
{
	/* LINTED set but not used */
	volatile double t;

	if (ex == 0)
		t = zero - zero;			/* clear cexc */
	else {
		if ((ex & (1 << fp_invalid)) != 0)
			t = zero / zero;
		if ((ex & (1 << fp_overflow)) != 0)
			t = huge * huge;
		if ((ex & (1 << fp_underflow)) != 0) {
			if ((ex & (1 << fp_inexact)) != 0 ||
			    (fpgetmask() & FP_X_UFL) != 0)
				t = tiny * tiny;
			else
				t = tiny2 - tiny;	/* exact */
		}
		if ((ex & (1 << fp_division)) != 0)
			t = tiny / zero;
		if ((ex & (1 << fp_inexact)) != 0)
			t = huge + tiny;
	}
	return (0);
}

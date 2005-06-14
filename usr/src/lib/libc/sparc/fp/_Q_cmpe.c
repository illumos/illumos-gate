/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1994-1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "quad.h"

#ifdef __sparcv9
#define	_Q_cmpe	_Qp_cmpe
#endif

/*
 * _Q_cmpe(x, y) returns the condition code that would result from
 * fcmpeq *x, *y (and raises the same exceptions).
 */
enum fcc_type
_Q_cmpe(const union longdouble *x, const union longdouble *y)
{
	unsigned int	xm, ym, fsr;

	if (QUAD_ISNAN(*x) || QUAD_ISNAN(*y)) {
		/* nan, signal invalid */
		__quad_getfsrp(&fsr);
		if (fsr & FSR_NVM) {
			__quad_fcmpeq(x, y, &fsr);
			return ((fsr >> 10) & 3);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
			__quad_setfsrp(&fsr);
		}
		return (fcc_unordered);
	}

	/* ignore sign of zero */
	xm = x->l.msw;
	if (QUAD_ISZERO(*x))
		xm &= 0x7fffffff;
	ym = y->l.msw;
	if (QUAD_ISZERO(*y))
		ym &= 0x7fffffff;

	if ((xm ^ ym) & 0x80000000)	/* x and y have opposite signs */
		return ((ym & 0x80000000)? fcc_greater : fcc_less);

	if (xm & 0x80000000) {
		if (xm > ym)
			return (fcc_less);
		if (xm < ym)
			return (fcc_greater);
		if (x->l.frac2 > y->l.frac2)
			return (fcc_less);
		if (x->l.frac2 < y->l.frac2)
			return (fcc_greater);
		if (x->l.frac3 > y->l.frac3)
			return (fcc_less);
		if (x->l.frac3 < y->l.frac3)
			return (fcc_greater);
		if (x->l.frac4 > y->l.frac4)
			return (fcc_less);
		if (x->l.frac4 < y->l.frac4)
			return (fcc_greater);
		return (fcc_equal);
	}
	if (xm < ym)
		return (fcc_less);
	if (xm > ym)
		return (fcc_greater);
	if (x->l.frac2 < y->l.frac2)
		return (fcc_less);
	if (x->l.frac2 > y->l.frac2)
		return (fcc_greater);
	if (x->l.frac3 < y->l.frac3)
		return (fcc_less);
	if (x->l.frac3 > y->l.frac3)
		return (fcc_greater);
	if (x->l.frac4 < y->l.frac4)
		return (fcc_less);
	if (x->l.frac4 > y->l.frac4)
		return (fcc_greater);
	return (fcc_equal);
}

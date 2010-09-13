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
#define	_Q_feq	_Qp_feq
#define	_Q_fne	_Qp_fne
#define	_Q_flt	_Qp_flt
#define	_Q_fle	_Qp_fle
#define	_Q_fgt	_Qp_fgt
#define	_Q_fge	_Qp_fge
#endif

/*
 * _Q_feq(x, y) returns nonzero if *x == *y and zero otherwise.
 * If either *x or *y is a signaling NaN, the invalid operation
 * exception is raised.
 */
int
_Q_feq(const union longdouble *x, const union longdouble *y)
{
	unsigned int	fsr;

	if (QUAD_ISNAN(*x) || QUAD_ISNAN(*y)) {
		if ((QUAD_ISNAN(*x) && !(x->l.msw & 0x8000)) ||
		    (QUAD_ISNAN(*y) && !(y->l.msw & 0x8000))) {
			/* snan, signal invalid */
			__quad_getfsrp(&fsr);
			if (fsr & FSR_NVM) {
				__quad_fcmpq(x, y, &fsr);
				return (((fsr >> 10) & 3) == fcc_equal);
			} else {
				fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
				__quad_setfsrp(&fsr);
			}
		}
		return (0);
	}
	if (QUAD_ISZERO(*x) && QUAD_ISZERO(*y))
		return (1);
	return ((x->l.msw ^ y->l.msw | x->l.frac2 ^ y->l.frac2 |
	    x->l.frac3 ^ y->l.frac3 | x->l.frac4 ^ y->l.frac4) == 0);
}

/*
 * _Q_fne(x, y) returns nonzero if *x != *y and zero otherwise.
 * If either *x or *y is a signaling NaN, the invalid operation
 * exception is raised.
 */
int
_Q_fne(const union longdouble *x, const union longdouble *y)
{
	unsigned int	fsr;

	if (QUAD_ISNAN(*x) || QUAD_ISNAN(*y)) {
		if ((QUAD_ISNAN(*x) && !(x->l.msw & 0x8000)) ||
		    (QUAD_ISNAN(*y) && !(y->l.msw & 0x8000))) {
			/* snan, signal invalid */
			__quad_getfsrp(&fsr);
			if (fsr & FSR_NVM) {
				__quad_fcmpq(x, y, &fsr);
				return (((fsr >> 10) & 3) != fcc_equal);
			} else {
				fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
				__quad_setfsrp(&fsr);
			}
		}
		return (1); /* x != y is TRUE if x or y is NaN */
	}
	if (QUAD_ISZERO(*x) && QUAD_ISZERO(*y))
		return (0);
	return ((x->l.msw ^ y->l.msw | x->l.frac2 ^ y->l.frac2 |
		x->l.frac3 ^ y->l.frac3 | x->l.frac4 ^ y->l.frac4) != 0);
}

/*
 * _Q_flt(x, y) returns nonzero if *x < *y and zero otherwise.  If
 * either *x or *y is NaN, the invalid operation exception is raised.
 */
int
_Q_flt(const union longdouble *x, const union longdouble *y)
{
	unsigned int	xm, ym, fsr;

	if (QUAD_ISNAN(*x) || QUAD_ISNAN(*y)) {
		/* nan, signal invalid */
		__quad_getfsrp(&fsr);
		if (fsr & FSR_NVM) {
			__quad_fcmpeq(x, y, &fsr);
			return (((fsr >> 10) & 3) == fcc_less);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
			__quad_setfsrp(&fsr);
		}
		return (0);
	}

	/* ignore sign of zero */
	xm = x->l.msw;
	if (QUAD_ISZERO(*x))
		xm &= 0x7fffffff;
	ym = y->l.msw;
	if (QUAD_ISZERO(*y))
		ym &= 0x7fffffff;

	if ((xm ^ ym) & 0x80000000)	/* x and y have opposite signs */
		return ((ym & 0x80000000) == 0);

	if (xm & 0x80000000) {
		return (xm > ym || xm == ym && (x->l.frac2 > y->l.frac2 ||
		    x->l.frac2 == y->l.frac2 && (x->l.frac3 > y->l.frac3 ||
		    x->l.frac3 == y->l.frac3 && x->l.frac4 > y->l.frac4)));
	}
	return (xm < ym || xm == ym && (x->l.frac2 < y->l.frac2 ||
	    x->l.frac2 == y->l.frac2 && (x->l.frac3 < y->l.frac3 ||
	    x->l.frac3 == y->l.frac3 && x->l.frac4 < y->l.frac4)));
}

/*
 * _Q_fle(x, y) returns nonzero if *x <= *y and zero otherwise.  If
 * either *x or *y is NaN, the invalid operation exception is raised.
 */
int
_Q_fle(const union longdouble *x, const union longdouble *y)
{
	unsigned int	xm, ym, fsr;

	if (QUAD_ISNAN(*x) || QUAD_ISNAN(*y)) {
		/* nan, signal invalid */
		__quad_getfsrp(&fsr);
		if (fsr & FSR_NVM) {
			__quad_fcmpeq(x, y, &fsr);
			fsr = (fsr >> 10) & 3;
			return (fsr == fcc_less || fsr == fcc_equal);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
			__quad_setfsrp(&fsr);
		}
		return (0);
	}

	/* ignore sign of zero */
	xm = x->l.msw;
	if (QUAD_ISZERO(*x))
		xm &= 0x7fffffff;
	ym = y->l.msw;
	if (QUAD_ISZERO(*y))
		ym &= 0x7fffffff;

	if ((xm ^ ym) & 0x80000000)	/* x and y have opposite signs */
		return ((ym & 0x80000000) == 0);

	if (xm & 0x80000000) {
		return (xm > ym || xm == ym && (x->l.frac2 > y->l.frac2 ||
		    x->l.frac2 == y->l.frac2 && (x->l.frac3 > y->l.frac3 ||
		    x->l.frac3 == y->l.frac3 && x->l.frac4 >= y->l.frac4)));
	}
	return (xm < ym || xm == ym && (x->l.frac2 < y->l.frac2 ||
	    x->l.frac2 == y->l.frac2 && (x->l.frac3 < y->l.frac3 ||
	    x->l.frac3 == y->l.frac3 && x->l.frac4 <= y->l.frac4)));
}

/*
 * _Q_fgt(x, y) returns nonzero if *x > *y and zero otherwise.  If
 * either *x or *y is NaN, the invalid operation exception is raised.
 */
int
_Q_fgt(const union longdouble *x, const union longdouble *y)
{
	unsigned int	xm, ym, fsr;

	if (QUAD_ISNAN(*x) || QUAD_ISNAN(*y)) {
		/* nan, signal invalid */
		__quad_getfsrp(&fsr);
		if (fsr & FSR_NVM) {
			__quad_fcmpeq(x, y, &fsr);
			return (((fsr >> 10) & 3) == fcc_greater);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
			__quad_setfsrp(&fsr);
		}
		return (0);
	}

	/* ignore sign of zero */
	xm = x->l.msw;
	if (QUAD_ISZERO(*x))
		xm &= 0x7fffffff;
	ym = y->l.msw;
	if (QUAD_ISZERO(*y))
		ym &= 0x7fffffff;

	if ((xm ^ ym) & 0x80000000)	/* x and y have opposite signs */
		return ((ym & 0x80000000) != 0);

	if (xm & 0x80000000) {
		return (xm < ym || xm == ym && (x->l.frac2 < y->l.frac2 ||
		    x->l.frac2 == y->l.frac2 && (x->l.frac3 < y->l.frac3 ||
		    x->l.frac3 == y->l.frac3 && x->l.frac4 < y->l.frac4)));
	}
	return (xm > ym || xm == ym && (x->l.frac2 > y->l.frac2 ||
	    x->l.frac2 == y->l.frac2 && (x->l.frac3 > y->l.frac3 ||
	    x->l.frac3 == y->l.frac3 && x->l.frac4 > y->l.frac4)));
}

/*
 * _Q_fge(x, y) returns nonzero if *x >= *y and zero otherwise.  If
 * either *x or *y is NaN, the invalid operation exception is raised.
 */
int
_Q_fge(const union longdouble *x, const union longdouble *y)
{
	unsigned int	xm, ym, fsr;

	if (QUAD_ISNAN(*x) || QUAD_ISNAN(*y)) {
		/* nan, signal invalid */
		__quad_getfsrp(&fsr);
		if (fsr & FSR_NVM) {
			__quad_fcmpeq(x, y, &fsr);
			fsr = (fsr >> 10) & 3;
			return (fsr == fcc_greater || fsr == fcc_equal);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
			__quad_setfsrp(&fsr);
		}
		return (0);
	}

	/* ignore sign of zero */
	xm = x->l.msw;
	if (QUAD_ISZERO(*x))
		xm &= 0x7fffffff;
	ym = y->l.msw;
	if (QUAD_ISZERO(*y))
		ym &= 0x7fffffff;

	if ((xm ^ ym) & 0x80000000)	/* x and y have opposite signs */
		return ((ym & 0x80000000) != 0);

	if (xm & 0x80000000) {
		return (xm < ym || xm == ym && (x->l.frac2 < y->l.frac2 ||
		    x->l.frac2 == y->l.frac2 && (x->l.frac3 < y->l.frac3 ||
		    x->l.frac3 == y->l.frac3 && x->l.frac4 <= y->l.frac4)));
	}
	return (xm > ym || xm == ym && (x->l.frac2 > y->l.frac2 ||
	    x->l.frac2 == y->l.frac2 && (x->l.frac3 > y->l.frac3 ||
	    x->l.frac3 == y->l.frac3 && x->l.frac4 >= y->l.frac4)));
}

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
#define	_Q_qtod	_Qp_qtod
#endif

/*
 * _Q_qtod(x) returns (double)*x.
 */
double
_Q_qtod(const union longdouble *x)
{
	union xdouble	u;
	unsigned int	xm, round, sticky, fsr, rm;
	int		subnormal, e;

	xm = x->l.msw & 0x7fffffff;

	/* get the rounding mode, fudging directed rounding modes */
	/* as though the result were positive */
	__quad_getfsrp(&fsr);
	rm = fsr >> 30;
	if (x->l.msw & 0x80000000)
		rm ^= (rm >> 1);

	/* handle nan, inf, and out-of-range cases */
	if (xm >= 0x43ff0000) {
		if (xm >= 0x7fff0000) {
			if ((xm & 0xffff) | x->l.frac2 | x->l.frac3 |
			    x->l.frac4) {
				/* x is nan */
				u.l.hi = (x->l.msw & 0x80000000) | 0x7ff80000;
				u.l.hi |= ((xm & 0x7fff) << 4) |
				    (x->l.frac2 >> 28);
				u.l.lo = (x->l.frac2 << 4) |
				    (x->l.frac3 >> 28);
				if (!(xm & 0x8000)) {
					/* snan, signal invalid */
					if (fsr & FSR_NVM) {
						__quad_fqtod(x, &u.d);
					} else {
						fsr = (fsr & ~FSR_CEXC) |
						    FSR_NVA | FSR_NVC;
						__quad_setfsrp(&fsr);
					}
				}
				return (u.d);
			}
			/* x is inf */
			u.l.hi = (x->l.msw & 0x80000000) | 0x7ff00000;
			u.l.lo = 0;
			return (u.d);
		}
		/* x is too big, overflow */
		if (rm == FSR_RN || rm == FSR_RP) {
			u.l.hi = 0x7ff00000;
			u.l.lo = 0;
		} else {
			u.l.hi = 0x7fefffff;
			u.l.lo = 0xffffffff;
		}
		u.l.hi |= (x->l.msw & 0x80000000);
		if (fsr & (FSR_OFM | FSR_NXM)) {
			__quad_fqtod(x, &u.d);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_OFA | FSR_OFC |
			    FSR_NXA | FSR_NXC;
			__quad_setfsrp(&fsr);
		}
		return (u.d);
	}

	subnormal = 0;
	if (xm < 0x3c010000) {
		if (xm < 0x3bcc0000) {
			if (QUAD_ISZERO(*x)) {
				u.l.hi = (x->l.msw & 0x80000000);
				u.l.lo = 0;
				return (u.d);
			}
			/* x is too small, underflow */
			u.l.hi = (x->l.msw & 0x80000000);
			u.l.lo = ((rm == FSR_RP)? 1 : 0);
			if (fsr & (FSR_UFM | FSR_NXM)) {
				__quad_fqtod(x, &u.d);
			} else {
				fsr = (fsr & ~FSR_CEXC) | FSR_UFA | FSR_UFC |
				    FSR_NXA | FSR_NXC;
				__quad_setfsrp(&fsr);
			}
			return (u.d);
		}

		/* x is in the subnormal range for double */
		subnormal = 1;
		u.l.hi = 0x80000 | ((xm & 0xffff) << 3) | (x->l.frac2 >> 29);
		u.l.lo = (x->l.frac2 << 3) | (x->l.frac3 >> 29);
		round = x->l.frac3 & 0x10000000;
		sticky = (x->l.frac3 & 0xfffffff) | x->l.frac4;
		e = 0x3c00 - (xm >> 16);
		if (e >= 32) {
			sticky |= round | (u.l.lo & 0x7fffffff);
			round = u.l.lo & 0x80000000;
			u.l.lo = u.l.hi;
			u.l.hi = 0;
			e -= 32;
		}
		if (e) {
			sticky |= round | (u.l.lo & ((1 << (e - 1)) - 1));
			round = u.l.lo & (1 << (e - 1));
			u.l.lo = (u.l.lo >> e) | (u.l.hi << (32 - e));
			u.l.hi >>= e;
		}
	} else {
		/* x is in the normal range for double */
		u.l.hi = ((xm - 0x3c000000) << 4) | (x->l.frac2 >> 28);
		u.l.lo = (x->l.frac2 << 4) | (x->l.frac3 >> 28);
		round = x->l.frac3 & 0x8000000;
		sticky = (x->l.frac3 & 0x7ffffff) | x->l.frac4;
	}

	/* see if we need to round */
	fsr &= ~FSR_CEXC;
	if (round | sticky) {
		fsr |= FSR_NXC;
		if (subnormal)
			fsr |= FSR_UFC;

		/* round up if necessary */
		if (rm == FSR_RP || (rm == FSR_RN && round && (sticky ||
		    (u.l.lo & 1)))) {
			/* round up and check for overflow */
			if (++u.l.lo == 0)
				if (++u.l.hi >= 0x7ff00000)
					fsr |= FSR_OFC;
		}
	}

	/* if result is exact and subnormal but underflow trapping is */
	/* enabled, signal underflow */
	else if (subnormal && (fsr & FSR_UFM))
		fsr |= FSR_UFC;

	/* attach the sign and raise exceptions as need be */
	u.l.hi |= (x->l.msw & 0x80000000);
	if ((fsr & FSR_CEXC) & (fsr >> 23)) {
		__quad_setfsrp(&fsr);
		__quad_fqtod(x, &u.d);
	} else {
		fsr |= (fsr & 0x1f) << 5;
		__quad_setfsrp(&fsr);
	}
	return (u.d);
}

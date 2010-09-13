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
#define	_Q_qtos	_Qp_qtos
#endif

/*
 * _Q_qtos(x) returns (float)*x.
 */
float
_Q_qtos(const union longdouble *x)
{
	union {
		float		f;
		unsigned int	l;
	} u;
	unsigned int		xm, round, sticky, fsr, rm;
	int			subnormal, e;

	xm = x->l.msw & 0x7fffffff;

	/* get the rounding mode, fudging directed rounding modes */
	/* as though the result were positive */
	__quad_getfsrp(&fsr);
	rm = fsr >> 30;
	if (x->l.msw & 0x80000000)
		rm ^= (rm >> 1);

	/* handle nan, inf, and out-of-range cases */
	if (xm >= 0x407f0000) {
		if (xm >= 0x7fff0000) {
			if ((xm & 0xffff) | x->l.frac2 | x->l.frac3 |
			    x->l.frac4) {
				/* x is nan */
				u.l = (x->l.msw & 0x80000000) | 0x7fc00000;
				u.l |= ((xm & 0x7fff) << 7) |
				    (x->l.frac2 >> 25);
				if (!(xm & 0x8000)) {
					/* snan, signal invalid */
					if (fsr & FSR_NVM) {
						__quad_fqtos(x, &u.f);
					} else {
						fsr = (fsr & ~FSR_CEXC) |
						    FSR_NVA | FSR_NVC;
						__quad_setfsrp(&fsr);
					}
				}
				return (u.f);
			}
			/* x is inf */
			u.l = (x->l.msw & 0x80000000) | 0x7f800000;
			return (u.f);
		}
		/* x is too big, overflow */
		if (rm == FSR_RN || rm == FSR_RP)
			u.l = 0x7f800000;
		else
			u.l = 0x7f7fffff;
		u.l |= (x->l.msw & 0x80000000);
		if (fsr & (FSR_OFM | FSR_NXM)) {
			__quad_fqtos(x, &u.f);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_OFA | FSR_OFC |
			    FSR_NXA | FSR_NXC;
			__quad_setfsrp(&fsr);
		}
		return (u.f);
	}

	subnormal = 0;
	if (xm < 0x3f810000) {
		if (xm < 0x3f690000) {
			if (QUAD_ISZERO(*x)) {
				u.l = (x->l.msw & 0x80000000);
				return (u.f);
			}
			/* x is too small, underflow */
			u.l = ((rm == FSR_RP)? 1 : 0);
			u.l |= (x->l.msw & 0x80000000);
			if (fsr & (FSR_UFM | FSR_NXM)) {
				__quad_fqtos(x, &u.f);
			} else {
				fsr = (fsr & ~FSR_CEXC) | FSR_UFA | FSR_UFC |
				    FSR_NXA | FSR_NXC;
				__quad_setfsrp(&fsr);
			}
			return (u.f);
		}

		/* x is in the subnormal range for single */
		subnormal = 1;
		u.l = 0x800000 | ((xm & 0xffff) << 7) | (x->l.frac2 >> 25);
		e = 0x3f80 - (xm >> 16);
		round = u.l & (1 << e);
		sticky = (u.l & ((1 << e) - 1)) | (x->l.frac2 & 0x1ffffff) |
			x->l.frac3 | x->l.frac4;
		u.l >>= e + 1;
	} else {
		/* x is in the normal range for single */
		u.l = ((xm - 0x3f800000) << 7) | (x->l.frac2 >> 25);
		round = x->l.frac2 & 0x1000000;
		sticky = (x->l.frac2 & 0xffffff) | x->l.frac3 | x->l.frac4;
	}

	/* see if we need to round */
	fsr &= ~FSR_CEXC;
	if (round | sticky) {
		fsr |= FSR_NXC;
		if (subnormal)
			fsr |= FSR_UFC;

		/* round up if necessary */
		if (rm == FSR_RP || (rm == FSR_RN && round && (sticky ||
		    (u.l & 1)))) {
			/* round up and check for overflow */
			if (++u.l >= 0x7f800000)
				fsr |= FSR_OFC;
		}
	}

	/* if result is exact and subnormal but underflow trapping is */
	/* enabled, signal underflow */
	else if (subnormal && (fsr & FSR_UFM))
		fsr |= FSR_UFC;

	/* attach the sign and raise exceptions as need be */
	u.l |= (x->l.msw & 0x80000000);
	if ((fsr & FSR_CEXC) & (fsr >> 23)) {
		__quad_setfsrp(&fsr);
		__quad_fqtos(x, &u.f);
	} else {
		fsr |= (fsr & 0x1f) << 5;
		__quad_setfsrp(&fsr);
	}
	return (u.f);
}

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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "quad.h"

#ifdef __sparcv9

/*
 * _Qp_sub(pz, ox, oy) sets *pz = *ox - *oy.
 */
void
_Qp_sub(union longdouble *pz, const union longdouble *ox,
	const union longdouble *oy)

#else

/*
 * _Q_sub(ox, oy) returns *ox - *oy.
 */
union longdouble
_Q_sub(const union longdouble *ox, const union longdouble *oy)

#endif	/* __sparcv9 */

{
	union longdouble	z;
	const union longdouble	*x, *y;
	unsigned int		xm, ym, tm, fsr;
	int			flip;

	/* sort so |x| >= |y| */
	xm = ox->l.msw & 0x7fffffff;
	ym = oy->l.msw & 0x7fffffff;
	if (ym > xm || ym == xm && (oy->l.frac2 > ox->l.frac2 ||
	    oy->l.frac2 == ox->l.frac2 && (oy->l.frac3 > ox->l.frac3 ||
	    oy->l.frac3 == ox->l.frac3 && oy->l.frac4 > ox->l.frac4))) {
		y = ox;
		x = oy;
		tm = xm;
		xm = ym;
		ym = tm;
		flip = 0x80000000;
	} else {
		x = ox;
		y = oy;
		flip = 0;
	}

	/* get the fsr */
	__quad_getfsrp(&fsr);

	/* handle nan and inf cases */
	if (xm >= 0x7fff0000) {
		/* x is nan or inf */
		if (ym >= 0x7fff0000) {
			/* y is nan or inf */
			if ((ym & 0xffff) | y->l.frac2 | y->l.frac3 |
			    y->l.frac4) {
				/* y is nan; x must be nan too */
				/* the following logic implements V9 app. B */
				if (!(ym & 0x8000)) {
					/* y is snan, signal invalid */
					if (fsr & FSR_NVM) {
						__quad_fsubq(ox, oy, &Z);
					} else {
						Z = (xm & 0x8000)? *y : *oy;
						Z.l.msw |= 0x8000;
						fsr = (fsr & ~FSR_CEXC) |
						    FSR_NVA | FSR_NVC;
						__quad_setfsrp(&fsr);
					}
					QUAD_RETURN(Z);
				}
				/* x and y are both qnan */
				Z = *oy;
				QUAD_RETURN(Z);
			}
			if (!((xm & 0xffff) | x->l.frac2 | x->l.frac3 |
			    x->l.frac4)) {
				/* x and y are both inf */
				if (!((x->l.msw ^ y->l.msw) & 0x80000000)) {
					/* inf - inf, signal invalid */
					if (fsr & FSR_NVM) {
						__quad_fsubq(ox, oy, &Z);
					} else {
						Z.l.msw = 0x7fffffff;
						Z.l.frac2 = Z.l.frac3 =
						    Z.l.frac4 = 0xffffffff;
						fsr = (fsr & ~FSR_CEXC) |
						    FSR_NVA | FSR_NVC;
						__quad_setfsrp(&fsr);
					}
					QUAD_RETURN(Z);
				}
				/* inf + inf, return inf */
				Z = *x;
				Z.l.msw ^= flip;
				QUAD_RETURN(Z);
			}
		}
		if ((xm & 0xffff) | x->l.frac2 | x->l.frac3 | x->l.frac4) {
			/* x is nan */
			if (!(xm & 0x8000)) {
				/* snan, signal invalid */
				if (fsr & FSR_NVM) {
					__quad_fsubq(ox, oy, &Z);
				} else {
					Z = *x;
					Z.l.msw |= 0x8000;
					fsr = (fsr & ~FSR_CEXC) | FSR_NVA |
					    FSR_NVC;
					__quad_setfsrp(&fsr);
				}
				QUAD_RETURN(Z);
			}
			Z = *x;
			QUAD_RETURN(Z);
		}
		/* x is inf */
		Z = *x;
		Z.l.msw ^= flip;
		QUAD_RETURN(Z);
	}

	/* now x and y are finite and |x| >= |y| */
	fsr &= ~FSR_CEXC;
	z.l.msw = (x->l.msw & 0x80000000) ^ flip;
	if ((x->l.msw ^ y->l.msw) & 0x80000000)
		__quad_mag_add(x, y, &z, &fsr);
	else
		__quad_mag_sub(x, y, &z, &fsr);
	if ((fsr & FSR_CEXC) & (fsr >> 23)) {
		__quad_setfsrp(&fsr);
		__quad_fsubq(ox, oy, &Z);
	} else {
		Z = z;
		fsr |= (fsr & 0x1f) << 5;
		__quad_setfsrp(&fsr);
	}
	QUAD_RETURN(Z);
}

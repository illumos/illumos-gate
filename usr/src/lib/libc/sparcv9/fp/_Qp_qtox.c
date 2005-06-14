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

/*
 * _Qp_qtox(x) returns (long)*x.
 */
long
_Qp_qtox(const union longdouble *x)
{
	long		i, round;
	unsigned int	xm, fsr;

	xm = x->l.msw & 0x7fffffff;

	__quad_getfsrp(&fsr);

	/* handle nan, inf, and out-of-range cases */
	if (xm >= 0x403e0000) {
		if (x->l.msw == 0xc03e0000 && x->l.frac2 == 0 &&
		    (x->l.frac3 & 0xfffe0000) == 0) {
			/* return largest negative 64 bit int */
			i = 0x8000000000000000ul;
			if ((x->l.frac3 & 0x1ffff) | x->l.frac4) {
				/* signal inexact */
				if (fsr & FSR_NXM) {
					__quad_fqtox(x, &i);
				} else {
					fsr = (fsr & ~FSR_CEXC) | FSR_NXA |
					    FSR_NXC;
					__quad_setfsrp(&fsr);
				}
			}
			return (i);
		}
		i = ((x->l.msw & 0x80000000)? 0x8000000000000000ul :
		    0x7fffffffffffffffl);
		if (fsr & FSR_NVM) {
			__quad_fqtox(x, &i);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
			__quad_setfsrp(&fsr);
		}
		return (i);
	}
	if (xm < 0x3fff0000) {
		i = 0l;
		if (xm | x->l.frac2 | x->l.frac3 | x->l.frac4) {
			/* signal inexact */
			if (fsr & FSR_NXM) {
				__quad_fqtox(x, &i);
			} else {
				fsr = (fsr & ~FSR_CEXC) | FSR_NXA | FSR_NXC;
				__quad_setfsrp(&fsr);
			}
		}
		return (i);
	}

	/* now x is in the range of 64 bit int */
	i = 0x4000000000000000l | ((long) (xm & 0xffff) << 46) |
	    ((long) x->l.frac2 << 14) | (x->l.frac3 >> 18);
	round = i & ((1l << (0x403d - (xm >> 16))) - 1);
	i >>= (0x403d - (xm >> 16));
	if (x->l.msw & 0x80000000)
		i = -i;
	if (round | (x->l.frac3 & 0x3ffff) | x->l.frac4) {
		/* signal inexact */
		if (fsr & FSR_NXM) {
			__quad_fqtox(x, &i);
		} else {
			fsr = (fsr & ~FSR_CEXC) | FSR_NXA | FSR_NXC;
			__quad_setfsrp(&fsr);
		}
	}
	return (i);
}

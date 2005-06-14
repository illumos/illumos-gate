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

/*
 * _Qp_stoq(pz, x) sets *pz = (long double)x.
 */
void
_Qp_stoq(union longdouble *pz, float x)

#else

/*
 * _Qp_stoq(x) returns (long double)x.
 */
union longdouble
_Q_stoq(float x)

#endif /* __sparcv9 */

{
#ifndef __sparcv9
	union longdouble	z;
#endif
	union {
		float		f;
		unsigned int	l;
	} u;
	unsigned int		m, f, fsr;

	/* extract the exponent */
	u.f = x;
	m = ((u.l & 0x7f800000) >> 7) + 0x3f800000;
	if (m == 0x3f800000) {
		/* x is zero or denormal */
		if (u.l & 0x7fffff) {
			/* x is denormal, normalize it */
			m = 0x3f810000;
			f = u.l & 0x7fffff;
			do {
				f <<= 1;
				m -= 0x10000;
			} while ((f & 0x7f800000) == 0);
			u.l = (u.l & 0x80000000) | f;
		} else {
			m = 0;
		}
	} else if (m == 0x407f0000) {
		/* x is inf or nan */
		m = 0x7fff0000;
		if ((u.l & 0x3fffff) && (u.l & 0x400000) == 0) {
			/* snan, signal invalid */
			__quad_getfsrp(&fsr);
			if (fsr & FSR_NVM) {
				__quad_fstoq(&x, &Z);
				QUAD_RETURN(Z);
			} else {
				fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
				__quad_setfsrp(&fsr);
			}
			u.l |= 0x400000;
		}
	}
	Z.l.msw = m | (u.l & 0x80000000) | ((u.l & 0x7fff80) >> 7);
	Z.l.frac2 = u.l << 25;
	Z.l.frac3 = Z.l.frac4 = 0;
	QUAD_RETURN(Z);
}

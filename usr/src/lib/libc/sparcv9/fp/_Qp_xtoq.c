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
 * _Qp_xtoq(pz, x) sets *pz = (long double)x.
 */
void
_Qp_xtoq(union longdouble *pz, long x)
{
	unsigned int	s, e;

	/* extract the sign */
	s = 0;
	if (x < 0) {
		if ((unsigned long) x == 0x8000000000000000ul) {
			/* largest negative 64 bit int */
			Z.l.msw = 0xc03e0000;
			Z.l.frac2 = Z.l.frac3 = Z.l.frac4 = 0;
			QUAD_RETURN(Z);
		}
		x = -x;
		s = 0x80000000;
	} else if (x == 0) {
		Z.l.msw = Z.l.frac2 = Z.l.frac3 = Z.l.frac4 = 0;
		QUAD_RETURN(Z);
	}

	/* find the most significant bit */
	for (e = 62; (x & (1l << e)) == 0; e--)
		;

	if (e > 48) {
		Z.l.msw = ((unsigned long) x >> (e - 16)) & 0xffff;
		Z.l.frac2 = (unsigned long) x >> (e - 48);
		Z.l.frac3 = (unsigned long) x << (80 - e);
	} else if (e > 16) {
		Z.l.msw = ((unsigned long) x >> (e - 16)) & 0xffff;
		Z.l.frac2 = (unsigned long) x << (48 - e);
		Z.l.frac3 = 0;
	} else {
		Z.l.msw = ((unsigned long) x << (16 - e)) & 0xffff;
		Z.l.frac2 = Z.l.frac3 = 0;
	}
	Z.l.frac4 = 0;
	Z.l.msw |= s | ((e + 0x3fff) << 16);
	QUAD_RETURN(Z);
}

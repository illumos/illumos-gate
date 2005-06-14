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
 * _Qp_uitoq(pz, x) sets *pz = (long double)x.
 */
void
_Qp_uitoq(union longdouble *pz, unsigned int x)

#else

/*
 * _Q_utoq(x) returns (long double)x.
 */
union longdouble
_Q_utoq(unsigned int x)

#endif /* __sparcv9 */

{
#ifndef __sparcv9
	union longdouble	z;
#endif
	unsigned int		e;

	/* test for zero */
	if (x == 0) {
		Z.l.msw = Z.l.frac2 = Z.l.frac3 = Z.l.frac4 = 0;
		QUAD_RETURN(Z);
	}

	/* find the most significant bit */
	for (e = 31; (x & (1 << e)) == 0; e--)
		;

	if (e > 16) {
		Z.l.msw = ((unsigned) x >> (e - 16)) & 0xffff;
		Z.l.frac2 = (unsigned) x << (48 - e);
	} else {
		Z.l.msw = ((unsigned) x << (16 - e)) & 0xffff;
		Z.l.frac2 = 0;
	}
	Z.l.frac3 = Z.l.frac4 = 0;
	Z.l.msw |= ((e + 0x3fff) << 16);
	QUAD_RETURN(Z);
}

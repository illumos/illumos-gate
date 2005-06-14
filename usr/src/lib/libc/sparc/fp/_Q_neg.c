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
 * _Qp_neg(pz, x) sets *pz = -*x.
 */
void
_Qp_neg(union longdouble *pz, const union longdouble *x)

#else

/*
 * _Q_neg(x) returns -*x.
 */
union longdouble
_Q_neg(const union longdouble *x)

#endif /* __sparcv9 */

{
#ifndef __sparcv9
	union	longdouble	z;
#endif

	Z.l.msw = x->l.msw ^ 0x80000000;
	Z.l.frac2 = x->l.frac2;
	Z.l.frac3 = x->l.frac3;
	Z.l.frac4 = x->l.frac4;
	QUAD_RETURN(Z);
}

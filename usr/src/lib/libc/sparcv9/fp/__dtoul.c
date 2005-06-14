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

/*
 * __dtoul(x) converts double x to unsigned long.
 */
unsigned long
__dtoul(double x)
{
	union {
		double		d;
		unsigned long	l;
	} u;

	u.d = x;

	/* handle cases for which double->unsigned long differs from */
	/* double->signed long */
	if ((u.l >> 52) == 0x43e) {
		/* 2^63 <= x < 2^64 */
		return (0x8000000000000000ul | (u.l << 11));
	}

	/* for all other cases, just convert to signed long */
	return ((long)x);
}

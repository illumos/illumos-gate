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
 * Copyright (c) 1991-1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"

/*
 * These routines are to support the compiler run-time only, and
 * should NOT be called directly from C!
 */

extern unsigned long long __umul32x32to64(unsigned, unsigned);

long long
__mul64(long long i, long long j)
{
	unsigned i0, i1, j0, j1;
	int sign = 0;
	long long result = 0;

	if (i < 0) {
		i = -i;
		sign = 1;
	}
	if (j < 0) {
		j = -j;
		sign ^= 1;
	}

	i1 = (unsigned)i;
	j0 = j >> 32;
	j1 = (unsigned)j;

	if (j1) {
		if (i1)
			result = __umul32x32to64(i1, j1);
		if ((i0 = i >> 32) != 0)
			result += ((unsigned long long)(i0 * j1)) << 32;
	}
	if (j0 && i1)
		result += ((unsigned long long)(i1 * j0)) << 32;
	return (sign ? -result : result);
}


unsigned long long
__umul64(unsigned long long i, unsigned long long j)
{
	unsigned i0, i1, j0, j1;
	unsigned long long result = 0;

	i1 = i;
	j0 = j >> 32;
	j1 = j;

	if (j1) {
		if (i1)
			result = __umul32x32to64(i1, j1);
		if ((i0 = i >> 32) != 0)
			result += ((unsigned long long)(i0 * j1)) << 32;
	}
	if (j0 && i1)
		result += ((unsigned long long)(i1 * j0)) << 32;
	return (result);
}

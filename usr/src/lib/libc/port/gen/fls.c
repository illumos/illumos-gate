/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "lint.h"
#include <string.h>
#include <strings.h>
#include <sys/types.h>

static int
fls_impl(uint64_t bits)
{
	int i = 1;
	uint32_t bits32;

	if (bits == 0)
		return (0);

	if ((bits32 = (uint32_t)(bits >> 32)) != 0)
		i += 32;
	else
		bits32 = (uint32_t)bits;

	if ((bits32 & 0xffff0000) != 0) {
		bits32 >>= 16;
		i += 16;
	}
	if ((bits32 & 0xff00) != 0) {
		bits32 >>= 8;
		i += 8;
	}
	if ((bits32 & 0xf0) != 0) {
		bits32 >>= 4;
		i += 4;
	}
	if ((bits32 & 0xc) != 0) {
		bits32 >>= 2;
		i += 2;
	}
	if ((bits32 & 0x2) != 0)
		i += 1;

	return (i);
}

int
fls(int bits)
{
	return (fls_impl((uint64_t)(uint_t)bits));
}

int
flsl(long bits)
{
	return (fls_impl((uint64_t)(ulong_t)bits));
}

int
flsll(long long bits)
{
	return (fls_impl((uint64_t)(u_longlong_t)bits));
}

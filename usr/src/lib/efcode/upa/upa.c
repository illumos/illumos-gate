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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <fcode/private.h>

static void
do_decode_unit(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "upa:decode-unit");
	parse_two_int(env);
	if ((TOS & 0x1c0) == 0) {
		TOS = ((TOS << 1) | 0x1c0);
	}
}

static void
do_encode_unit(fcode_env_t *env)
{
	static char buf[8];
	fstack_t hi, mid, lo;
	int dev, fn, len;

	CHECK_DEPTH(env, 2, "upa:encode-unit");
	hi = POP(DS);
	lo = POP(DS);
	hi = ((hi >> 1) & 0x1f);
	sprintf(buf, "%x,%x", hi, lo);
	push_a_string(env, buf);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	create_int_prop(env, "#address-cells", 2);
	create_int_prop(env, "#size-cells", 2);

	FORTH(0,	"decode-unit",		do_decode_unit);
	FORTH(0,	"encode-unit",		do_encode_unit);

}

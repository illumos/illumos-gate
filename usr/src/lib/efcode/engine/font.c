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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcode/private.h>

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	P1275(0x16a, 0,		"default-font",		fc_unimplemented);
	P1275(0x16b, 0,		"set-font",		fc_unimplemented);
	P1275(0x16c, 0,		"char-height",		fc_unimplemented);
	P1275(0x16d, 0,		"char-width",		fc_unimplemented);
	P1275(0x16e, 0,		">font",		fc_unimplemented);
	P1275(0x16f, 0,		"fontbytes",		fc_unimplemented);
}

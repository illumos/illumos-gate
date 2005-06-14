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

	FCODE(0x180, 0,	"fb8-draw-character",		fc_unimplemented);
	FCODE(0x181, 0,	"fb8-reset-screen",		fc_unimplemented);
	FCODE(0x182, 0,	"fb8-toggle-cursor",		fc_unimplemented);
	FCODE(0x183, 0,	"fb8-erase-screen",		fc_unimplemented);
	FCODE(0x184, 0,	"fb8-blink-screen",		fc_unimplemented);
	FCODE(0x185, 0,	"fb8-invert-screen",		fc_unimplemented);
	FCODE(0x186, 0,	"fb8-insert-characters",	fc_unimplemented);
	FCODE(0x187, 0,	"fb8-delete-characters",	fc_unimplemented);
	FCODE(0x188, 0,	"fb8-insert-lines",		fc_unimplemented);
	FCODE(0x189, 0,	"fb8-delete-lines",		fc_unimplemented);
	FCODE(0x18a, 0,	"fb8-draw-logo",		fc_unimplemented);
	FCODE(0x18b, 0,	"fb8-install",			fc_unimplemented);
}

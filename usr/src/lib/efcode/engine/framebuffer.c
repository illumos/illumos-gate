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

	FCODE(0x11c, 0,		"is-install",		fc_unimplemented);
	FCODE(0x11d, 0,		"is-remove",		fc_unimplemented);
	FCODE(0x11e, 0,		"is-selftest",		fc_unimplemented);

	FCODE(0x121, 0,		"display-status",	fc_unimplemented);

	FCODE(0x150, 0,		"#lines",		fc_unimplemented);
	FCODE(0x151, 0,		"#columns",		fc_unimplemented);
	FCODE(0x152, 0,		"line#",		fc_unimplemented);
	FCODE(0x153, 0,		"column#",		fc_unimplemented);
	FCODE(0x154, 0,		"inverse?",		fc_unimplemented);
	FCODE(0x155, 0,		"inverse-screen?",	fc_unimplemented);
	FCODE(0x156, 0,		"frame-buffer-busy?",	fc_historical);
	FCODE(0x157, 0,		"draw-character",	fc_unimplemented);
	FCODE(0x158, 0,		"reset-screen",		fc_unimplemented);
	FCODE(0x159, 0,		"toggle-cursor",	fc_unimplemented);
	FCODE(0x15a, 0,		"erase-screen",		fc_unimplemented);
	FCODE(0x15b, 0,		"blink-screen",		fc_unimplemented);
	FCODE(0x15c, 0,		"invert-screen",	fc_unimplemented);
	FCODE(0x15d, 0,		"insert-characters",	fc_unimplemented);
	FCODE(0x15e, 0,		"delete-characters",	fc_unimplemented);
	FCODE(0x15f, 0,		"insert-lines",		fc_unimplemented);
	FCODE(0x160, 0,		"delete-lines",		fc_unimplemented);
	FCODE(0x161, 0,		"draw-logo",		fc_unimplemented);
	FCODE(0x162, 0,		"frame-buffer-adr",	fc_unimplemented);
	FCODE(0x163, 0,		"screen-height",	fc_unimplemented);
	FCODE(0x164, 0,		"screen-width",		fc_unimplemented);
	FCODE(0x165, 0,		"window-top",		fc_unimplemented);
	FCODE(0x166, 0,		"window-left",		fc_unimplemented);
}

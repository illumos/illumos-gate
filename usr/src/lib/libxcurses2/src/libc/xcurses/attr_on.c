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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * attr_on.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/attr_on.c 1.2 1998/05/28 17:10:05 "
"cbates Exp $";
#endif
#endif

#include <private.h>

#undef attr_on

int
attr_on(attr_t at, void *opts)
{
	(void) wattr_on(stdscr, at, opts);

	return (OK);
}

#undef attr_off

int
attr_off(attr_t at, void *opts)
{
	(void) wattr_off(stdscr, at, opts);

	return (OK);
}

#undef attr_set

int
attr_set(attr_t at, short co, void *opts)
{
	(void) wattr_set(stdscr, at, co, opts);

	return (OK);
}

#undef color_set

int
color_set(short co, void *opts)
{
	(void) wcolor_set(stdscr, co, opts);

	return (OK);
}

#undef attr_get

int
attr_get(attr_t *at, short *co, void *opts)
{
	(void) wattr_get(stdscr, at, co, opts);

	return (OK);
}

#undef standout
#undef wstandout

int
standout(void)
{
	(void) wstandout(stdscr);

	return (1);
}

#undef standend
#undef wstandend

int
standend(void)
{
	(void) wstandend(stdscr);

	return (1);
}

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
 * attron.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/attron.c 1.3 1998/05/28 17:10:10 "
"cbates Exp $";
#endif
#endif

#include <private.h>

int
attron(int at)
{
	return (wattron(stdscr, at));
}

int
attroff(int at)
{
	return (wattroff(stdscr, at));
}

int
attrset(int at)
{
	return (wattrset(stdscr, at));
}

#undef COLOR_PAIR

int
COLOR_PAIR(int co)
{
	int ch;

	ch = co << __COLOR_SHIFT;

	return (ch);
}

#undef PAIR_NUMBER

int
PAIR_NUMBER(int at)
{
	int pair;

	pair = (int)(((unsigned int)at & A_COLOR) >> __COLOR_SHIFT);

	return (pair);
}

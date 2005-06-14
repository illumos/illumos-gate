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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * getch.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/getch.c 1.1 1995/05/25 17:56:14 ant Exp $";
#endif
#endif

#include <private.h>

#undef getch

int
getch()
{
	int value;

#ifdef M_CURSES_TRACE
	__m_trace("getch(void)");
#endif

	value = wgetch(stdscr);

	return __m_return_int("getch", value);
}

#undef mvgetch

int
mvgetch(y, x)
int y, x;
{
	int value;

#ifdef M_CURSES_TRACE
	__m_trace("mvgetch(%d, %d)", y, x);
#endif

	if (wmove(stdscr, y, x))
		return __m_return_int("mvgetch", EOF);

	value = wgetch(stdscr);

	return __m_return_int("mvgetch", value);
}

#undef mvwgetch

int
mvwgetch(w, y, x)
WINDOW *w;
int y, x;
{
	int value;

#ifdef M_CURSES_TRACE
	__m_trace("mvwgetch(%p, %d, %d)", w, y, x);
#endif

	if (wmove(w, y, x))
		return __m_return_int("mvgetch", EOF);

	value = wgetch(w);

	return __m_return_int("mvwgetch", value);
}


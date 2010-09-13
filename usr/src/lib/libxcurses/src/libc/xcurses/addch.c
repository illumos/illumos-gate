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
 * addch.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/addch.c 1.3 1995/07/07 17:59:07 ant Exp $";
#endif
#endif

#include <private.h>

int
(addch)(chtype ch)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("addch(%lx)", ch);
#endif

	code = waddch(stdscr, ch);

	return __m_return_code("addch", code);
}

int
(mvaddch)(int y, int x, chtype ch)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvaddch(%d, %d, %lx)", y, x, ch);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = waddch(stdscr, ch);

	return __m_return_code("mvaddch", code);
}

int
(mvwaddch)(WINDOW *w, int y, int x, chtype ch)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwaddch(%p, %d, %d, %lx)", w, y, x, ch);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = waddch(w, ch);

	return __m_return_code("mvwaddch", code);
}


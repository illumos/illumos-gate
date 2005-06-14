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
 * addnstr.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/addnstr.c 1.3 1995/07/07 17:59:11 ant Exp $";
#endif
#endif

#include <private.h>

int
(addnstr)(str, n)
const char *str;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("addnstr(%p, %d)", str, n);
#endif

	code = waddnstr(stdscr, str, n);

	return __m_return_code("addnstr", code);
}

int
(mvaddnstr)(y, x, str, n)
int y, x;
const char *str;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvaddnstr(%d, %d, %p, %d)", y, x, str, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = waddnstr(stdscr, str, n);

	return __m_return_code("mvaddnstr", code);
}

int
(mvwaddnstr)(w, y, x, str, n)
WINDOW *w;
int y, x;
const char *str;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwaddnstr(%p, %d, %d, %p, %d)", w, y, x, str, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = waddnstr(w, str, n);

	return __m_return_code("mvwaddnstr", code);
}

int
(addstr)(str)
const char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("addstr(%p)", str);
#endif

	code = waddnstr(stdscr, str, -1);

	return __m_return_code("addstr", code);
}

int
(mvaddstr)(y, x, str)
int y, x;
const char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvaddstr(%d, %d, %p)", y, x, str);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = waddnstr(stdscr, str, -1);

	return __m_return_code("mvaddstr", code);
}

int
(mvwaddstr)(w, y, x, str)
WINDOW *w;
int y, x;
const char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwaddstr(%p, %d, %d, %p)", w, y, x, str);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = waddnstr(w, str, -1);

	return __m_return_code("mvwaddstr", code);
}

int
(waddstr)(w, str)
WINDOW *w;
const char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("waddstr(%p, %p)", w, str);
#endif

	code = waddnstr(w, str, -1);

	return __m_return_code("waddstr", code);
}


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
 * getnstr.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/getnstr.c 1.1 1995/06/06 19:11:25 ant Exp $";
#endif
#endif

#include <private.h>

int
(getnstr)(str, n)
char *str;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("getnstr(%p, %d)", str, n);
#endif

	code = wgetnstr(stdscr, str, n);

	return __m_return_code("getnstr", code);
}

int
(mvgetnstr)(y, x, str, n)
int y, x;
char *str;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvgetnstr(%d, %d, %p, %d)", y, x, str, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wgetnstr(stdscr, str, n);

	return __m_return_code("mvgetnstr", code);
}

int
(mvwgetnstr)(w, y, x, str, n)
WINDOW *w;
int y, x;
char *str;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwgetnstr(%p, %d, %d, %p, %d)", w, y, x, str, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wgetnstr(w, str, n);

	return __m_return_code("mvwgetnstr", code);
}

int
(getstr)(str)
char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("getstr(%p)", str);
#endif

	code = wgetnstr(stdscr, str, -1);

	return __m_return_code("getstr", code);
}

int
(mvgetstr)(y, x, str)
int y, x;
char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvgetstr(%d, %d, %p)", y, x, str);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wgetnstr(stdscr, str, -1);

	return __m_return_code("mvgetstr", code);
}

int
(mvwgetstr)(w, y, x, str)
WINDOW *w;
int y, x;
char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwgetstr(%p, %d, %d, %p)", w, y, x, str);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wgetnstr(w, str, -1);

	return __m_return_code("mvwgetstr", code);
}


int
(wgetstr)(w, str)
WINDOW *w;
char *str;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("wgetstr(%p, %p)", w, str);
#endif

	code = wgetnstr(w, str, -1);

	return __m_return_code("wgetstr", code);
}


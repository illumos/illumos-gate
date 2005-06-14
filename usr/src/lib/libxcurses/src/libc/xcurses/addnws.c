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
 * addnws.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/addnws.c 1.2 1995/05/18 20:55:00 ant Exp $";
#endif
#endif

#include <private.h>

#undef addnwstr

int
addnwstr(wcs, n)
const wchar_t *wcs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("addnwstr(%p, %d)", wcs, n);
#endif

	code = waddnwstr(stdscr, wcs, n);

	return __m_return_code("addnwstr", code);
}

#undef mvaddnwstr

int
mvaddnwstr(y, x, wcs, n)
int y, x;
const wchar_t *wcs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvaddnwstr(%d, %d, %p, %d)", y, x, wcs, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = waddnwstr(stdscr, wcs, n);

	return __m_return_code("mvaddnwstr", code);
}

#undef mvwaddnwstr

int
mvwaddnwstr(w, y, x, wcs, n)
WINDOW *w;
int y, x;
const wchar_t *wcs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwaddnwstr(%p, %d, %d, %p, %d)", w, y, x, wcs, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = waddnwstr(w, wcs, n);

	return __m_return_code("mvwaddnwstr", code);
}

#undef addwstr

int
addwstr(wcs)
const wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("addwstr(%p)", wcs);
#endif

	code = waddnwstr(stdscr, wcs, -1);

	return __m_return_code("addwstr", code);
}

#undef mvaddwstr

int
mvaddwstr(y, x, wcs)
int y, x;
const wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvaddwstr(%d, %d, %p)", y, x, wcs);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = waddnwstr(stdscr, wcs, -1);

	return __m_return_code("mvaddwstr", code);
}

#undef mvwaddwstr

int
mvwaddwstr(w, y, x, wcs)
WINDOW *w;
int y, x;
const wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwaddwstr(%p, %d, %d, %p)", w, y, x, wcs);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = waddnwstr(w, wcs, -1);

	return __m_return_code("mvwaddwstr", code);
}

#undef waddwstr

int
waddwstr(w, wcs)
WINDOW *w;
const wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("waddwstr(%p, %p)", w, wcs);
#endif

	code = waddnwstr(w, wcs, -1);

	return __m_return_code("waddwstr", code);
}


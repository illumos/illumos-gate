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
 * inchn.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/inchn.c 1.1 1995/06/13 21:05:53 ant Exp $";
#endif
#endif

#include <private.h>

int
(inchnstr)(chs, n)
chtype *chs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("inchnstr(%p, %d)", chs, n);
#endif

	code = winchnstr(stdscr, chs, n);

	return __m_return_code("inchnstr", code);
}

int
(mvinchnstr)(y, x, chs, n)
int y, x;
chtype *chs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvinchnstr(%d, %d, %p, %d)", y, x, chs, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winchnstr(stdscr, chs, n);

	return __m_return_code("mvinchnstr", code);
}

int
(mvwinchnstr)(w, y, x, chs, n)
WINDOW *w;
int y, x;
chtype *chs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwinchnstr(%p, %d, %d, %p, %d)", w, y, x, chs, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = winchnstr(w, chs, n);

	return __m_return_code("mvwinchnstr", code);
}

int
(inchstr)(chs)
chtype *chs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("inchstr(%p)", chs);
#endif

	code = winchnstr(stdscr, chs, -1);

	return __m_return_code("inchstr", code);
}

int
(mvinchstr)(y, x, chs)
int y, x;
chtype *chs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvinchstr(%d, %d, %p)", y, x, chs);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winchnstr(stdscr, chs, -1);

	return __m_return_code("mvinchstr", code);
}

int
(mvwinchstr)(w, y, x, chs)
WINDOW *w;
int y, x;
chtype *chs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwinchstr(%p, %d, %d, %p)", w, y, x, chs);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = winchnstr(w, chs, -1);

	return __m_return_code("mvwinchstr", code);
}

int
(winchstr)(w, chs)
WINDOW *w;
chtype *chs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("winchstr(%p, %p)", w, chs);
#endif

	code = winchnstr(w, chs, -1);

	return __m_return_code("winchstr", code);
}


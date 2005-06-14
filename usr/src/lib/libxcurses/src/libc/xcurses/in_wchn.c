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
 * in_wchn.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/in_wchn.c 1.1 1995/06/13 21:14:26 ant Exp $";
#endif
#endif

#include <private.h>

int
(in_wchnstr)(ccs, n)
cchar_t *ccs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("in_wchnstr(%p, %d)", ccs, n);
#endif

	code = win_wchnstr(stdscr, ccs, n);

	return __m_return_code("in_wchnstr", code);
}

int
(mvin_wchnstr)(y, x, ccs, n)
int y, x;
cchar_t *ccs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvin_wchnstr(%d, %d, %p, %d)", y, x, ccs, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = win_wchnstr(stdscr, ccs, n);

	return __m_return_code("mvin_wchnstr", code);
}

int
(mvwin_wchnstr)(w, y, x, ccs, n)
WINDOW *w;
int y, x;
cchar_t *ccs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwin_wchnstr(%p, %d, %d, %p, %d)", w, y, x, ccs, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = win_wchnstr(w, ccs, n);

	return __m_return_code("mvwin_wchnstr", code);
}

int
(in_wchstr)(ccs)
cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("in_wchstr(%p)", ccs);
#endif

	code = win_wchnstr(stdscr, ccs, -1);

	return __m_return_code("in_wchstr", code);
}

int
(mvin_wchstr)(y, x, ccs)
int y, x;
cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvin_wchstr(%d, %d, %p)", y, x, ccs);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = win_wchnstr(stdscr, ccs, -1);

	return __m_return_code("mvin_wchstr", code);
}

int
(mvwin_wchstr)(w, y, x, ccs)
WINDOW *w;
int y, x;
cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwin_wchstr(%p, %d, %d, %p)", w, y, x, ccs);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = win_wchnstr(w, ccs, -1);

	return __m_return_code("mvwin_wchstr", code);
}

int
(win_wchstr)(w, ccs)
WINDOW *w;
cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("win_wchstr(%p, %p)", w, ccs);
#endif

	code = win_wchnstr(w, ccs, -1);

	return __m_return_code("win_wchstr", code);
}


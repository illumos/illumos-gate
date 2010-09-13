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
 * getn_ws.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/getn_ws.c 1.1 1995/07/06 14:01:35 ant Exp $";
#endif
#endif

#include <private.h>

int
(getn_wstr)(wis, n)
wint_t *wis;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("getn_wstr(%p, %d)", wis, n);
#endif

	code = wgetn_wstr(stdscr, wis, n);

	return __m_return_code("getn_wstr", code);
}

int
(mvgetn_wstr)(y, x, wis, n)
int y, x;
wint_t *wis;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvgetn_wstr(%d, %d, %p, %d)", y, x, wis, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wgetn_wstr(stdscr, wis, n);

	return __m_return_code("mvgetn_wstr", code);
}

int
(mvwgetn_wstr)(w, y, x, wis, n)
WINDOW *w;
int y, x;
wint_t *wis;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwgetn_wstr(%p, %d, %d, %p, %d)", w, y, x, wis, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wgetn_wstr(w, wis, n);

	return __m_return_code("mvwgetn_wstr", code);
}

int
(get_wstr)(wis)
wint_t *wis;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("get_wstr(%p)", wis);
#endif

	code = wgetn_wstr(stdscr, wis, -1);

	return __m_return_code("get_wstr", code);
}

int
(mvget_wstr)(y, x, wis)
int y, x;
wint_t *wis;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvget_wstr(%d, %d, %p)", y, x, wis);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wgetn_wstr(stdscr, wis, -1);

	return __m_return_code("mvget_wstr", code);
}

int
(mvwget_wstr)(w, y, x, wis)
WINDOW *w;
int y, x;
wint_t *wis;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwget_wstr(%p, %d, %d, %p)", w, y, x, wis);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wgetn_wstr(w, wis, -1);

	return __m_return_code("mvwget_wstr", code);
}


int
(wget_wstr)(w, wis)
WINDOW *w;
wint_t *wis;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("wget_wstr(%p, %p)", w, wis);
#endif

	code = wgetn_wstr(w, wis, -1);

	return __m_return_code("wget_wstr", code);
}


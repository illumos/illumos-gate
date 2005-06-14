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
 * innwwstr.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/innwstr.c 1.1 1995/06/14 15:26:08 ant Exp $";
#endif
#endif

#include <private.h>

int
(innwstr)(wcs, n)
wchar_t *wcs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("innwstr(%p, %d)", wcs, n);
#endif

	code = winnwstr(stdscr, wcs, n);

	return __m_return_code("innwstr", code);
}

int
(mvinnwstr)(y, x, wcs, n)
int y, x;
wchar_t *wcs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvinnwstr(%d, %d, %p, %d)", y, x, wcs, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winnwstr(stdscr, wcs, n);

	return __m_return_code("mvinnwstr", code);
}

int
(mvwinnwstr)(w, y, x, wcs, n)
WINDOW *w;
int y, x;
wchar_t *wcs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwinnwstr(%p, %d, %d, %p, %d)", w, y, x, wcs, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = winnwstr(w, wcs, n);

	return __m_return_code("mvwinnwstr", code);
}

int
(inwstr)(wcs)
wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("inwstr(%p)", wcs);
#endif

	code = winnwstr(stdscr, wcs, -1);

	return __m_return_code("inwstr", code);
}

int
(mvinwstr)(y, x, wcs)
int y, x;
wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvinwstr(%d, %d, %p)", y, x, wcs);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winnwstr(stdscr, wcs, -1);

	return __m_return_code("mvinwstr", code);
}

int
(mvwinwstr)(w, y, x, wcs)
WINDOW *w;
int y, x;
wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwinwstr(%p, %d, %d, %p)", w, y, x, wcs);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = winnwstr(w, wcs, -1);

	return __m_return_code("mvwinwstr", code);
}

int
(winwstr)(w, wcs)
WINDOW *w;
wchar_t *wcs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("winwstr(%p, %p)", w, wcs);
#endif

	code = winnwstr(w, wcs, -1);

	return __m_return_code("winwstr", code);
}


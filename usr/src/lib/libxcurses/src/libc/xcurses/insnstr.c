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
 * insnstr.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/insnstr.c 1.1 1995/06/15 17:35:00 ant Exp $";
#endif
#endif

#include <private.h>

int
(insnstr)(mbs, n)
const char *mbs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("insnstr(%p, %d)", mbs, n);
#endif

	code = winsnstr(stdscr, mbs, n);

	return __m_return_code("insnstr", code);
}

int
(mvinsnstr)(y, x, mbs, n)
int y, x;
const char *mbs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvinsnstr(%d, %d, %p, %d)", y, x, mbs, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winsnstr(stdscr, mbs, n);

	return __m_return_code("mvinsnstr", code);
}

int
(mvwinsnstr)(w, y, x, mbs, n)
WINDOW *w;
int y, x;
const char *mbs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwinsnstr(%p, %d, %d, %p, %d)", w, y, x, mbs, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = winsnstr(w, mbs, n);

	return __m_return_code("mvwinsnstr", code);
}

int
(insstr)(mbs)
const char *mbs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("insstr(%p)", mbs);
#endif

	code = winsnstr(stdscr, mbs, -1);

	return __m_return_code("insstr", code);
}

int
(mvinsstr)(y, x, mbs)
int y, x;
const char *mbs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvinsstr(%d, %d, %p)", y, x, mbs);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winsnstr(stdscr, mbs, -1);

	return __m_return_code("mvinsstr", code);
}

int
(mvwinsstr)(w, y, x, mbs)
WINDOW *w;
int y, x;
const char *mbs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwinsstr(%p, %d, %d, %p)", w, y, x, mbs);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = winsnstr(w, mbs, -1);

	return __m_return_code("mvwinsstr", code);
}

int
(winsstr)(w, mbs)
WINDOW *w;
const char *mbs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("winsstr(%p, %p)", w, mbs);
#endif

	code = winsnstr(w, mbs, -1);

	return __m_return_code("winsstr", code);
}


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
 * addwchn.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/addwchn.c 1.1 1995/05/30 13:39:41 ant Exp $";
#endif
#endif

#include <private.h>

#undef add_wchnstr

int
add_wchnstr(ccs, n)
const cchar_t *ccs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("add_wchnstr(%p, %d)", ccs, n);
#endif

	code = wadd_wchnstr(stdscr, ccs, n);

	return __m_return_code("add_wchnstr", code);
}

#undef mvadd_wchnstr

int
mvadd_wchnstr(y, x, ccs, n)
int y, x;
const cchar_t *ccs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvadd_wchnstr(%d, %d, %p, %d)", y, x, ccs, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wadd_wchnstr(stdscr, ccs, n);

	return __m_return_code("mvadd_wchnstr", code);
}

#undef mvwadd_wchnstr

int
mvwadd_wchnstr(w, y, x, ccs, n)
WINDOW *w;
int y, x;
const cchar_t *ccs;
int n;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwadd_wchnstr(%p, %d, %d, %p, %d)", w, y, x, ccs, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wadd_wchnstr(w, ccs, n);

	return __m_return_code("mvwadd_wchnstr", code);
}

#undef add_wchstr

int
add_wchstr(ccs)
const cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("add_wchstr(%p)", ccs);
#endif

	code = wadd_wchnstr(stdscr, ccs, -1);

	return __m_return_code("add_wchstr", code);
}

#undef mvadd_wchstr

int
mvadd_wchstr(y, x, ccs)
int y, x;
const cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvadd_wchstr(%d, %d, %p)", y, x, ccs);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wadd_wchnstr(stdscr, ccs, -1);

	return __m_return_code("mvadd_wchstr", code);
}

#undef mvwadd_wchstr

int
mvwadd_wchstr(w, y, x, ccs)
WINDOW *w;
int y, x;
const cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwadd_wchstr(%p, %d, %d, %p)", w, y, x, ccs);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wadd_wchnstr(w, ccs, -1);

	return __m_return_code("mvwadd_wchstr", code);
}

#undef wadd_wchstr

int
wadd_wchstr(w, ccs)
WINDOW *w;
const cchar_t *ccs;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("wadd_wchstr(%p, %p)", w, ccs);
#endif

	code = wadd_wchnstr(w, ccs, -1);

	return __m_return_code("wadd_wchstr", code);
}


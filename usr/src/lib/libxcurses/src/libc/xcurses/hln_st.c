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
 * hln_st.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/hln_st.c 1.1 1995/05/29 19:59:32 ant Exp $";
#endif
#endif

#include <private.h>

#undef hline_set

int
hline_set(const cchar_t *h, int n)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("hline_set(%p, %d)", h, n);
#endif

	code = whline_set(stdscr, h, n);

	return __m_return_code("hline_set", code);
}

#undef mvhline_set

int
mvhline_set(int y, int x, const cchar_t *h, int n)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvhline_set(%d, %d, %p, %d)", y, x, h, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = whline_set(stdscr, h, n);

	return __m_return_code("mvhline_set", code);
}

#undef mvwhline_set

int
mvwhline_set(WINDOW *w, int y, int x, const cchar_t *h, int n)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwhline_set(%p, %d, %d, %p, %d)", w, y, x, h, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = whline_set(w, h, n);

	return __m_return_code("mvwhline_set", code);
}

#undef vline_set

int
vline_set(const cchar_t *v, int n)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("vline_set(%p, %d)", v, n);
#endif

	code = wvline_set(stdscr, v, n);

	return __m_return_code("vline_set", code);
}

#undef mvvline_set

int
mvvline_set(int y, int x, const cchar_t *v, int n)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvvline_set(%d, %d, %p, %d)", y, x, v, n);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wvline_set(stdscr, v, n);

	return __m_return_code("mvvline_set", code);
}

#undef mvwvline_set

int
mvwvline_set(WINDOW *w, int y, int x, const cchar_t *v, int n)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwvline_set(%p, %d, %d, %p, %d)", w, y, x, v, n);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wvline_set(w, v, n);

	return __m_return_code("mvwvline_set", code);
}


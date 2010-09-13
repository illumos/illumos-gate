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
 * get_wch.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/get_wch.c 1.1 1995/05/25 17:56:22 ant Exp $";
#endif
#endif

#include <private.h>

#undef get_wch

int
get_wch(wcp)
wint_t *wcp;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("get_wch(%p)", wcp);
#endif

	code = wget_wch(stdscr, wcp);

	return __m_return_code("get_wch", code);
}

#undef mvget_wch

int
mvget_wch(y, x, wcp)
int y, x;
wint_t *wcp;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvget_wch(%d, %d, %p)", y, x, wcp);
#endif

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wget_wch(stdscr, wcp);

	return __m_return_code("mvget_wch", code);
}

#undef mvwget_wch

int
mvwget_wch(w, y, x, wcp)
WINDOW *w;
int y, x;
wint_t *wcp;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("mvwget_wch(%p, %d, %d, %p)", w, y, x, wcp);
#endif

	if ((code = wmove(w, y, x)) == OK)
		code = wget_wch(w, wcp);

	return __m_return_code("mvwget_wch", code);
}


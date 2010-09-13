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
 * echo_wch.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/echo_wch.c 1.1 1995/06/05 20:26:37 ant Exp $";
#endif
#endif

#include <private.h>

int
(echo_wchar)(const cchar_t *ch)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("echo_wchar(%p)", ch);
#endif

	if ((code = wadd_wch(stdscr, ch)) == OK)
		code = wrefresh(stdscr);

	return __m_return_code("echo_wchar", code);
}

int
(wecho_wchar)(WINDOW *w, const cchar_t *ch)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("wecho_wchar(%p, %p)", w, ch);
#endif

	if ((code = wadd_wch(w, ch)) == OK)
		code = wrefresh(w);

	return __m_return_code("wecho_wchar", code);
}

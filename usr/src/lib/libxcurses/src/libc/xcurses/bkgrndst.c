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
 * bkgrndst.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/bkgrndst.c 1.3 1995/08/28 19:22:20 danv Exp $";
#endif
#endif

#include <private.h>

void
(bkgrndset)(bg)
const cchar_t *bg;
{
#ifdef M_CURSES_TRACE
	__m_trace("bkgrndset(%p)", bg);
#endif

	stdscr->_bg = *bg;

	__m_return_void("bkgrndset");
}

void
(wbkgrndset)(w, bg)
WINDOW *w;
const cchar_t *bg;
{
#ifdef M_CURSES_TRACE
	__m_trace("wbkgrndset(%p, %p)", w, bg);
#endif

	w->_bg = *bg;

	__m_return_void("wbkgrndset");
}

int
(getbkgrnd)(bg)
cchar_t *bg;
{
#ifdef M_CURSES_TRACE
	__m_trace("getbkgrnd(%p)", bg);
#endif

	*bg = stdscr->_bg;

	return __m_return_code("getbkgrnd", OK);
}

int
(wgetbkgrnd)(w, bg)
WINDOW *w;
cchar_t *bg;
{
#ifdef M_CURSES_TRACE
	__m_trace("wgetbkgrnd(%p, %p)", w, bg);
#endif

	*bg = w->_bg;

	return __m_return_code("wgetbkgrnd", OK);
}

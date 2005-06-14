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
 * wattron.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wattron.c 1.1 1995/06/07 14:11:56 ant Exp $";
#endif
#endif

#include <private.h>

int
wattron(WINDOW *w, int at)
{
	cchar_t cc;

#ifdef M_CURSES_TRACE
        __m_trace("wattron(%p, %ld)", w, at);
#endif

	(void) __m_chtype_cc((chtype) at, &cc);
	w->_fg._at |= cc._at;

	return __m_return_code("wattron", OK);
}

int
wattroff(WINDOW *w, int at)
{
	cchar_t cc;

#ifdef M_CURSES_TRACE
        __m_trace("wattroff(%p, %ld)", w, at);
#endif

	(void) __m_chtype_cc((chtype) at, &cc);
	w->_fg._at &= ~cc._at;

	return __m_return_code("wattroff", OK);
}

int
wattrset(WINDOW *w, int at)
{
	cchar_t cc;

#ifdef M_CURSES_TRACE
        __m_trace("wattrset(%p, %ld)", w, at);
#endif

	(void) __m_chtype_cc((chtype) at, &cc);
	w->_fg._co = cc._co;
	w->_fg._at = cc._at;

	return __m_return_code("wattrset", OK);
}

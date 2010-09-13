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
 * attron.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/attron.c 1.3 1995/07/07 17:59:14 ant Exp $";
#endif
#endif

#include <private.h>

int
attron(int at)
{
	cchar_t cc;

#ifdef M_CURSES_TRACE
        __m_trace("attron(%lx)", at);
#endif

	(void) __m_chtype_cc((chtype) at, &cc);
	stdscr->_fg._at |= cc._at;

	return __m_return_code("attron", OK);
}

int
attroff(int at)
{
	cchar_t cc;

#ifdef M_CURSES_TRACE
        __m_trace("attroff(%lx)", (long) at);
#endif

	(void) __m_chtype_cc((chtype) at, &cc);
	stdscr->_fg._at &= ~cc._at;

	return __m_return_code("attroff", OK);
}

int
attrset(int at)
{
	cchar_t cc;

#ifdef M_CURSES_TRACE
        __m_trace("attrset(%lx)", (long) at);
#endif

	(void) __m_chtype_cc((chtype) at, &cc);
	stdscr->_fg._co = cc._co;
	stdscr->_fg._at = cc._at;

	return __m_return_code("attrset", OK);
}

chtype
(COLOR_PAIR)(short co)
{
	chtype ch;

#ifdef M_CURSES_TRACE
        __m_trace("COLOR_PAIR(%d)", co);
#endif

	ch = (chtype)(co) << __COLOR_SHIFT;

	return __m_return_chtype("COLOR_PAIR", ch);
}
	
short
(PAIR_NUMBER)(chtype at)
{
	short pair;

#ifdef M_CURSES_TRACE
        __m_trace("PAIR_NUMBER(%ld)", at);
#endif

	pair = (short) ((at & A_COLOR) >> __COLOR_SHIFT);

	return __m_return_int("PAIR_NUMBER", pair);
}

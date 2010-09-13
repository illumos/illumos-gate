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
 * inch.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/inch.c 1.1 1995/06/12 20:24:39 ant Exp $";
#endif
#endif

#include <private.h>

chtype
(inch)()
{
	chtype ch;

#ifdef M_CURSES_TRACE
	__m_trace("inch(void)");
#endif

	ch = winch(stdscr);

	return __m_return_chtype("inch", ch);
}

chtype
(mvinch)(y, x)
int y, x;
{
	chtype ch;

#ifdef M_CURSES_TRACE
	__m_trace("mvinch(%d, %d)", y, x);
#endif

	if ((ch = (chtype) wmove(stdscr, y, x)) != (chtype) ERR)
		ch = winch(stdscr);

	return __m_return_chtype("mvinch", ch);
}

chtype
(mvwinch)(w, y, x)
WINDOW *w;
int y, x;
{
	chtype ch;

#ifdef M_CURSES_TRACE
	__m_trace("mvwinch(%p, %d, %d)", w, y, x);
#endif

	if ((ch = (chtype) wmove(w, y, x)) != (chtype) ERR)
		ch = winch(w);

	return __m_return_chtype("mvwinch", ch);
}

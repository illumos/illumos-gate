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
 * bkgdset.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/bkgdset.c 1.2 1995/06/12 20:24:16 ant Exp $";
#endif
#endif

#include <private.h>

int
(bkgdset)(chtype bg)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("bkgdset(%lx)", bg);
#endif

	code = __m_chtype_cc(bg, &stdscr->_bg);

	return __m_return_code("bkgdset", code);
}

int
(wbkgdset)(WINDOW *w, chtype bg)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("wbkgdset(%p, %lx)", w, bg);
#endif

	code = __m_chtype_cc(bg, &w->_bg);

	return __m_return_code("wbkgdset", code);
}

chtype
(getbkgd)(WINDOW *w)
{
	chtype bg;

#ifdef M_CURSES_TRACE
	__m_trace("getbkgd(%p)", w);
#endif

	bg = __m_cc_chtype(&w->_bg);

	return __m_return_chtype("getbkgd", bg);
}

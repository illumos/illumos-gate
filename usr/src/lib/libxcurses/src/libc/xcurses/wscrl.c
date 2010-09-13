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
 * wscrl.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wscrl.c 1.4 1995/07/26 17:43:20 ant Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*f
 * For positive n scroll the window up n lines (line i+n becomes i);
 * otherwise scroll the window down n lines.
 */
int
wscrl(w, n)
WINDOW *w;
int n;
{
	int y, x, width, start, finish, to; 

#ifdef M_CURSES_TRACE
	__m_trace("wscrl(%p, %d)", w, n);
#endif

	if (n == 0)
		return __m_return_code("wscrl", OK);

	/* Shuffle pointers in order to scroll.  The region 
	 * from start to finish inclusive will be moved to
	 * either the top or bottom of _line[].
	 */
	if (0 < n) {
		start = w->_top;
		finish = w->_top + n - 1;
		to = w->_bottom;
	} else {
		start = w->_bottom + n;
		finish = w->_bottom - 1;
		to = w->_top;
	}

	/* Blank out new lines. */
	if (__m_cc_erase(w, start, 0, finish, w->_maxx-1) == -1)
		return __m_return_code("wscrl", ERR);

	/* Scroll lines by shuffling pointers. */
	(void) __m_ptr_move((void **) w->_line, w->_maxy, start, finish, to);

	if ((w->_flags & W_FULL_WINDOW)
	&& w->_top == 0 && w->_bottom == w->_maxy)
		w->_scroll += n;
	else
		w->_scroll = 0;

	(void) wtouchln(w, 0, w->_maxy, 1);

	WSYNC(w);

	return __m_return_code("wscrl", WFLUSH(w));
}

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
 * winsdel.c		
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/winsdel.c 1.4 1995/06/21 20:31:02 ant Exp $";
#endif
#endif

#include <private.h>
#include <stdlib.h>

/*f
 * Insert/delete rows from a window.
 *
 * Positive N inserts rows and negative N deletes.  The size of the
 * window remains fixed so that rows insert/deleted will cause rows to
 * disappear/appear at the end of the window.
 *
 * NOTE: This routine called in doupdate.c with curscr as window.  
 */
int
winsdelln(w, n)
WINDOW *w;
int n;
{
	int row;

#ifdef M_CURSES_TRACE
	__m_trace("winsdelln(%p, %d)", w, n);
#endif

	/* Check bounds and limit if necessary. */
	if (w->_maxy < w->_cury + abs(n))
		n = (w->_maxy - w->_cury + 1) * (n < 0 ? -1 : 1);

	/* Insert/delete accomplished by pointer shuffling. */
	if (n < 0) {
		/* Delete n lines from current cursor line. */
		(void) __m_ptr_move(
			(void **) w->_line, w->_maxy, 
			w->_cury, w->_cury - (n+1), w->_maxy
		);

		/* Blank lines come in at the bottom of the screen. */
		row = w->_maxy + n;
	} else {
		/* Insert n lines before current cursor line. */
		(void) __m_ptr_move(
			(void **) w->_line, w->_maxy, 
			w->_maxy - n, w->_maxy-1, w->_cury
		);

		/* Blank lines inserted at the cursor line. */
		row = w->_cury;
	}

	/* Clear inserted/deleted lines. */ 
	(void) __m_cc_erase(w, row, 0, row + abs(n), w->_maxx-1);

	/* Mark from the cursor line to the end of window as dirty. */ 
	(void) wtouchln(w, w->_cury, w->_maxy - w->_cury, 1);

	/* If we insert/delete lines at the top of the screen and we're,
	 * permitted to scroll, then treat the action as a scroll.
	 */
	if (w->_scroll && w->_cury == 0 && n != 0 && (w->_flags & W_FULL_WINDOW)
	&& w->_top == 0 && w->_bottom == w->_maxy)
                w->_scroll += n;
        else
                w->_scroll = 0;

	WSYNC(w);

	return __m_return_code("winsdelln", WFLUSH(w));
}


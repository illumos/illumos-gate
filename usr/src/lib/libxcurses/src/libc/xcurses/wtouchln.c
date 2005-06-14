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
 * wtouchln.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wtouchln.c 1.1 1995/05/12 20:06:28 ant Exp $";
#endif
#endif

#include <private.h>

/*f
 * Given a window, start from line y, and mark n lines either as touched
 * or untouched since the last call to wrefresh().
 */
int
wtouchln(w, y, n, bf)
WINDOW *w;
int y, n, bf;
{
	int first, last;

#ifdef M_CURSES_TRACE
	__m_trace("wtouchln(%p, %d, %d, %d)", w, y, n, bf);
#endif
	first = bf ? 0 : w->_maxx;
	last = bf ? w->_maxx : -1;

	for (; y < w->_maxy && 0 < n; ++y, --n) {
		w->_first[y] = first; 
		w->_last[y] = last; 
	}

	return __m_return_code("wtouchln", OK);
}

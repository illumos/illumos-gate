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
 * win_wchn.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/win_wchn.c 1.1 1995/06/14 15:26:05 ant Exp $";
#endif
#endif

#include <private.h>

int
win_wchnstr(w, ccs, n)
WINDOW *w;
cchar_t *ccs;
int n;
{
	int x, eol;
	cchar_t *cp, null = { 0 };

#ifdef M_CURSES_TRACE
	__m_trace("win_wchnstr(%p, %p, %d)", w, ccs, n);
#endif

	eol = (n < 0 || w->_maxx < w->_curx + n) ? w->_maxx : w->_curx + n;
 
        for (cp = w->_line[w->_cury], x = w->_curx; x < eol; ++ccs) {
		*ccs = *cp;
		ccs->_f = 1;

		x = __m_cc_next(w, w->_cury, x);
	}

	/* For an unbounded buffer or a buffer with room remaining,
	 * null terminate the buffer.
	 */
	if (n < 0 || eol < w->_curx + n) 
		*ccs = null;

	return __m_return_code("win_wchnstr", OK);
}

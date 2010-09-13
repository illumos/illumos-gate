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
 * whln_st.c		
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/whln_st.c 1.4 1995/07/07 18:53:05 ant Exp $";
#endif
#endif

#include <private.h>

int
whline_set(w, h, n)
WINDOW *w;
const cchar_t *h;
int n;
{
	int x, width;

#ifdef M_CURSES_TRACE
	__m_trace("whline_set(%p, %p, %d)",  w, h, n);
#endif

	if (h == (const cchar_t *) 0)
		h = WACS_HLINE;

	n += w->_curx;
	if (w->_maxx < n)
		n = w->_maxx;

	for (x = w->_curx; x < n; x += width)
                if ((width = __m_cc_replace(w, w->_cury, x, h, 0)) == -1)
			return __m_return_code("whline_set", ERR);

	WSYNC(w);

	return __m_return_code("whline_set", WFLUSH(w));
}

int
wvline_set(w, v, n)
WINDOW *w;
const cchar_t *v;
int n;
{
	int y;

#ifdef M_CURSES_TRACE
	__m_trace("wvline_set(%p, %p, %d)",  w, v, n);
#endif

	if (v == (const cchar_t *) 0)
		v = WACS_VLINE;

	n += w->_cury;
	if (w->_maxy < n)
		n = w->_maxy;

	for (y = w->_cury; y < n; ++y)
                if (__m_cc_replace(w, y, w->_curx, v, 0) == -1)
			return __m_return_code("wvline_set", ERR);

	WSYNC(w);

	return __m_return_code("wvline_set", WFLUSH(w));
}


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
 * wins_nws.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wins_nws.c 1.3 1995/09/27 18:49:50 ant Exp $";
#endif
#endif

#include <private.h>

int
wins_nwstr(w, wcs, n)
WINDOW *w;
const wchar_t *wcs;
int n;
{
	cchar_t cc;
	int i, y, x;  

#ifdef M_CURSES_TRACE
	__m_trace("wins_nwstr(%p, %p, n)", w, wcs, n);
#endif

	y = w->_cury; 
	x = w->_curx;

	if (n < 0)
		n = INT_MAX;

	for ( ; *wcs != '\0' && 0 < n; n -= i, wcs += i) {
		if ((i = __m_wcs_cc(wcs, w->_bg._at, w->_bg._co, &cc)) < 0
		|| __m_wins_wch(w, y, x, &cc, &y, &x) == ERR)
			return __m_return_code("wins_nwstr", ERR);
	}

	WSYNC(w);

	return __m_return_code("wins_nwstr", WFLUSH(w));
}

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
 * waddchn.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/waddchn.c 1.3 1995/06/21 20:30:54 ant Exp $";
#endif
#endif

#include <private.h>

int
waddchnstr(WINDOW *w, const chtype *chs, int n)
{
	cchar_t cc;
	int x, width;

#ifdef M_CURSES_TRACE
	__m_trace("waddchnstr(%p, %p, %d)", w, chs, n);
#endif

	if (n < 0 || w->_maxx < (n += w->_curx))
		n = w->_maxx;

	for (x = w->_curx; x < n && *chs != 0; x += width, ++chs) {
                (void) __m_chtype_cc(*chs, &cc);
		width = __m_cc_replace(w, w->_cury, x, &cc, 0);
        }

	WSYNC(w);

	return __m_return_code("waddchnstr", WFLUSH(w));
}

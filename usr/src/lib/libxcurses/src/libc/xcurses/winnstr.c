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
 * winnstr.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/winnstr.c 1.1 1995/06/14 15:26:06 ant Exp $";
#endif
#endif

#include <private.h>

int
winnstr(w, mbs, n)
WINDOW *w;
char *mbs;
int n;
{
	int y, x;

#ifdef M_CURSES_TRACE
	__m_trace("winnstr(%p, %p, %d)", w, mbs, n);
#endif

	y = w->_cury;
	x = w->_curx;

	if (n < 0)
		n = w->_maxx + 1;

	/* Write first character as a multibyte string. */
	(void) __m_cc_mbs(&w->_line[y][x], mbs, n);

	/* Write additional characters without colour and attributes. */
	for (;;) {
		x = __m_cc_next(w, y, x);
		if (w->_maxx <= x)
			break;
		if (__m_cc_mbs(&w->_line[y][x], (char *) 0, 0) < 0)
			break;
	}

        /* Return to initial shift state and terminate string. */
        (void) __m_cc_mbs((const cchar_t *) 0, (char *) 0, 0);
 
	return __m_return_code("winnstr", OK);
}

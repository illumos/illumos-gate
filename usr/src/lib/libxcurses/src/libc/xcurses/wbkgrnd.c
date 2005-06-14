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
 * wbkgrnd.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wbkgrnd.c 1.4 1995/06/21 20:30:57 ant Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*f
 * Combine the new background setting with every position in the window.
 * The background is any combination of attributes and a character.
 * Only the attribute part is used to set the background of non-blank
 * characters, while both character and attributes are used for blank
 * positions.
 */
int
wbkgrnd(w, bg)
WINDOW *w;
const cchar_t *bg;
{
	short y, x;
	cchar_t old_bg, *cp;

#ifdef M_CURSES_TRACE
	__m_trace("wbkgrnd(%p, %p)", w, bg);
#endif

	old_bg = w->_bg;
	w->_bg = *bg;
	
	for (y = 0; y < w->_maxy; ++y) {
		for (cp = w->_line[y], x = 0; x < w->_maxx; ++x) {
			old_bg._f = cp->_f;
			if (__m_cc_compare(cp, &w->_bg, 0)) {
				/* Replace entire background character. */
				*cp = *bg;
			} else {
				/* Disable old background attributes. */
				cp->_at &= ~old_bg._at;

				/* Enable new background and current
				 * foreground.  The foreground is included
				 * in case there was overlap with the old
				 * background and the foreground.
				 */
				cp->_at |= bg->_at | w->_fg._at;
			}
		}

		/* Mark line as touched. */
		w->_first[y] = 0;
		w->_last[y] = x;
	}

	WSYNC(w);

	return __m_return_code("wbkgrnd", WFLUSH(w));
}

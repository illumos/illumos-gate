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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

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
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/wscrl.c 1.8 1998/06/04 17:52:07 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*
 * For positive n scroll the window up n lines (line i+n becomes i);
 * otherwise scroll the window down n lines.
 */
int
wscrl(WINDOW *w, int n)
{
	int	start, finish, to;

	if (!(w->_flags & W_CAN_SCROLL))
		return (ERR);

	if (n == 0)
		return (OK);

	if (w->_parent) {
		/* Sub-window should not shuffle pointers (parent owns them) */
		int	row;
		cchar_t	save;
		int	first;

		if (n > 0) {
			for (row = w->_top; row < w->_bottom; row++) {
				if (row < w->_bottom - n) {
					if (!w->_line[row+n][0]._f)	{
						/*
						 * Tail end of
						 * a multi-col-char
						 */
						(void) __m_cc_erase(w, row + n,
							0, row + n, 0);
					}
					/*
					 * Erase trailing multi-col-chars
					 * where they hang into parent window
					 */
					first = __m_cc_first(w, row + n,
						w->_maxx - 1);
					save = w->_line[row + n][first];
					(void) __m_cc_erase(w, row + n,
						first, row + n, first);
					w->_line[row + n][first] = save;
					(void) memcpy(w->_line[row],
						w->_line[row + n],
						sizeof (cchar_t) * w->_maxx);
				} else {
					(void) __m_cc_erase(w, row, 0,
						w->_bottom -1, w->_maxx - 1);
					break;
				}
			}
		} else {
			abort();
		}
	} else {
		/*
		 * Shuffle pointers in order to scroll.  The region
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
		(void) __m_cc_erase(w, start, 0, finish, w->_maxx - 1);

		/* Scroll lines by shuffling pointers. */
		(void) __m_ptr_move((void **) w->_line, w->_maxy,
			start, finish, to);
	}

	if ((w->_flags & W_FULL_WINDOW) &&
		w->_top == 0 && w->_bottom == w->_maxy)
		w->_scroll += (short) n;
	else
		w->_scroll = 0;

	(void) wtouchln(w, 0, w->_maxy, 1);
	wtouchln_hard(w, 0, w->_maxy);

#ifdef	BREAKS_fimmedok_fimmedok1_2
	w->_flags |= W_FLUSH;
#endif	/* BREAKS_fimmedok_fimmedok1_2 */

	WSYNC(w);

	return (WFLUSH(w));
}

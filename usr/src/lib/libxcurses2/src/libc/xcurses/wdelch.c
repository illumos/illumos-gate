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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * wdelch.c
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
"libxcurses/src/libc/xcurses/rcs/wdelch.c 1.3 1998/05/26 14:22:13 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*
 * Delete the character under the cursor; all characters to the right of
 * the cursor on the same line are moved to the left by one position and
 * the last character on the line is filled with a blank. The cursor
 * position does not change.
 */
int
wdelch(WINDOW *w)
{
	int	next, width, y, x;

	y = w->_cury;
	x = w->_curx;

	next = __m_cc_next(w, y, x);
	x = __m_cc_first(w, y, x);

	/* Determine the character width to delete. */
	width = __m_cc_width(&w->_line[y][x]);

	/* Shift line left to erase the character under the cursor. */
	(void) memcpy(&w->_line[y][x], &w->_line[y][next],
		(w->_maxx - next) * sizeof (**w->_line));

	/*
	 * Add blank(s) to the end of line based on the width
	 * of the character that was deleted.
	 */
	(void) __m_cc_erase(w, y, w->_maxx - width, y, w->_maxx - 1);

	/* Set dity region markers. */
	if (x < w->_first[y])
		w->_first[y] = (short) x;
	w->_last[y] = w->_maxx;

	WSYNC(w);

	return (WFLUSH(w));
}

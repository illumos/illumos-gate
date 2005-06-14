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
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

int
wmoveprevch(WINDOW *win)
/*
 * wmoveprevch --- moves the cursor back to the previous char of char
 * cursor is currently on.  This is used to move back over a multi-column
 * character.  When the cursor is on a character at the left-most
 * column, the cursor will stay there.
 */
{
	chtype	*_yy;
	short	x;

	(void) wadjcurspos(win);
	x = win->_curx;
	if (x == 0) /* Can't back up any more. */
		return (ERR);
	_yy = win->_y[win->_cury];
	--x;
	while ((x > 0) && (ISCBIT(_yy[x])))
		--x;
	win->_curx = x;
	win->_flags |= _WINMOVED;
	return (win->_immed ? wrefresh(win): OK);
}

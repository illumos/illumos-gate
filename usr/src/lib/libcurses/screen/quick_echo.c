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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

extern	int	outchcount;

/*
 *  These routines short-circuit much of the innards of curses in order to get
 *  a single character output to the screen quickly! It is used by waddch().
 */

int
_quick_echo(WINDOW *win, chtype ch)
{
	short	y = win->_cury;
	short	SPy = y + win->_begy + win->_yoffset;
	short	SPx = (win->_curx - 1) + win->_begx;
	chtype	rawc = _CHAR(ch), rawattrs = _ATTR(ch);

	if ((curscr->_flags & _CANT_BE_IMMED) ||
	    (win->_flags & _WINCHANGED) ||
	    (win->_clear) || (curscr->_clear) ||
	    (_virtscr->_flags & _WINCHANGED) ||
	    (SPy > ((LINES + SP->Yabove) - 1)) || (SPx > (COLS - 1)) ||
	    (SP->slk && (SP->slk->_changed == TRUE))) {
		win->_flags |= _WINCHANGED;
		return (wrefresh(win));
	}

	outchcount = 0;
	win->_firstch[y] = _INFINITY;
	win->_lastch[y] = -1;
	/* If the cursor is not in the right place, put it there! */
	if ((SPy != curscr->_cury) || (SPx != curscr->_curx)) {
		(void) mvcur(curscr->_cury, curscr->_curx, SPy, SPx);
		curscr->_cury = SPy;
	}
	curscr->_curx = SPx + 1;
	_CURHASH[SPy] = _NOHASH;
	if (ch != ' ') {
		if (SPx > _ENDNS[SPy])
			_ENDNS[SPy] = SPx;
		if (SPx < _BEGNS[SPy])
			_BEGNS[SPy] = SPx;
	}
	_virtscr->_y[SPy][SPx] = curscr->_y[SPy][SPx] = ch;

	if (rawattrs != curscr->_attrs)
		_VIDS(rawattrs, curscr->_attrs);

	if (SP->phys_irm)
		_OFFINSERT();

	/* Write it out! */
	/* LINTED */
	(void) _outch((char) rawc);
	(void) fflush(SP->term_file);

	return (outchcount);
}

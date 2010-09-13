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
#include	<string.h>
#include	"curses_inc.h"

/*
 * Insert/delete lines
 * id < 0 : number of lines to delete
 * id > 0 : number of lines to insert
 */

int
winsdelln(WINDOW *win, int id)
{
	int	endy, endx, to, fr, num_lines, dir;
	chtype	*sw;
	char	*mk;
	bool	savimmed, savesync;
	short	x, y, quick, *begch, *endch;
#ifdef	_VR3_COMPAT_CODE
	/* LINTED */
	void		(*update_ptr)();

	/*
	 * Null out the update pointer so that in wclrtoeol we do not
	 * update the _y16 area but we wait till the bottom of this
	 * function to do it in one fell swoop.
	 */

	if (_y16update) {
		update_ptr = _y16update;
		_y16update = NULL;
	} else
		update_ptr = NULL;
#endif	/* _VR3_COMPAT_CODE */

	if ((win->_cury >= win->_tmarg) && (win->_cury <= win->_bmarg))
		endy = win->_bmarg + 1;
	else
		endy = win->_maxy;

	if (id < 0) {
		/*
		 * Check that the amount of lines to delete aren't larger
		 * than the window.  We save num_lines only so that we
		 * don't have to re-compute if the if comes out true.
		 */

		if ((num_lines = win->_cury - endy) > id)
			id = num_lines;

		/*
		 * "fr" is the line that we are coming "fr"om and
		 * moving "to" the new place.  This is the offset which
		 * we have to re-align our pointers by.
		 * We want to start setting the current line's pointer
		 * to point to the offset's line.  We want to move line "fr"
		 * to line "to".
		 */

		to = win->_cury;
		fr = to - id;
		num_lines = endy - fr;
		dir = 1;
	} else {
		/* can't insert more lines than are in the region */
		if ((num_lines = endy - win->_cury) < id)
			id = num_lines;

		to = endy - 1;
		fr = to - id;
		num_lines = fr - (win->_cury - 1);
		dir = -1;
	}

	/*
	 * If this window has no parents or children, then we can manipulate
	 * pointers to simulate insert/delete line.  Otherwise,
	 * to propogate the changes to parents and siblings
	 * we have to memcpy the text around.
	 *
	 * Set quick to tell us which we have to do.
	 */
	quick = ((win->_ndescs <= 0) && (win->_parent == NULL));

	begch = win->_firstch;
	endch = win->_lastch;
	endx = win->_maxx;

	for (; num_lines > 0; num_lines--, to += dir, fr += dir) {
		/* can be done quickly */
		if (quick) {
			sw = win->_y[to];
			win->_y[to] = win->_y[fr];
			win->_y[fr] = sw;
			if ((win == curscr) && _MARKS != NULL) {
				mk = _MARKS[to];
				_MARKS[to] = _MARKS[fr];
				_MARKS[fr] = mk;

				/* for color terminal do the same for */
				/* color marks */

				if (_COLOR_MARKS != NULL) {
					mk = _COLOR_MARKS[to];
					_COLOR_MARKS[to] = _COLOR_MARKS[fr];
					_COLOR_MARKS[fr] = mk;
				}
			}
		} else
			/* slow update */
			(void) memcpy((char *) win->_y[to], (char *)
			    win->_y[fr], (endx * sizeof (chtype)));


		/*
		 * If this is curscr, the firstch[] and lastch[]
		 * arrays contain blank information.
		 */

		if (win == curscr) {
			begch[to] = begch[fr];
			endch[to] = endch[fr];
			_CURHASH[to] = _CURHASH[fr];
		} else {
			/* regular window, update the change structure */
			begch[to] = 0;
			endch[to] = endx - 1;
		}
	}

	/* clear the insert/delete lines */
	if (id < 0)
		num_lines = endy - to;
	else
		num_lines = to - (win->_cury - 1);

	if (num_lines > 0) {		/* Is this if needed ? */
		savimmed = win->_immed;
		savesync = win->_sync;
		win->_immed = win->_sync = FALSE;
		x = win->_curx;
		y = win->_cury;

		win->_curx = 0;
		for (; num_lines > 0; --num_lines, to += dir) {
			/* LINTED */
			win->_cury = (short) to;
			(void) wclrtoeol(win);
		}

		win->_curx = x;
		win->_cury = y;
		win->_immed = savimmed;
		win->_sync = savesync;
	}
	win->_flags |= (_WINCHANGED|_WINSDEL);

#ifdef	_VR3_COMPAT_CODE
	if (update_ptr) {
		_y16update = update_ptr;
		(*_y16update)(win, endy - y, endx, y, 0);
	}
#endif	/* _VR3_COMPAT_CODE */

	if (win->_sync)
		wsyncup(win);

	return ((win != curscr && savimmed) ? wrefresh(win) : OK);
}

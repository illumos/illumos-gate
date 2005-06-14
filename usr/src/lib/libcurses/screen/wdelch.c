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

/*
 * This routine performs a delete-char on the line,
 * leaving (_cury, _curx) unchanged.
 */

int
wdelch(WINDOW *win)
{
	chtype	*temp1, *temp2;
	chtype	*end;
	int	cury = win->_cury;
	short	curx = win->_curx;
	chtype	*cp;
	int	s;

	end = &win->_y[cury][win->_maxx - 1];
	temp2 = &win->_y[cury][curx + 1];
	temp1 = temp2 - 1;

	s = 1;
	win->_nbyte = -1;
	if (_scrmax > 1) {
		if (ISMBIT(*temp1)) {
			win->_insmode = TRUE;
			if (_mbvalid(win) == ERR)
				return (ERR);
			curx = win->_curx;
			temp1 = &win->_y[cury][curx];
		}
		if (ISMBIT(*end)) {
			for (cp = end; cp >= temp1; --cp)
				if (!ISCBIT(*cp))
					break;
			if (cp + _curs_scrwidth[TYPE(*cp)] > end+1)
				end = cp - 1;
		}
		if (ISMBIT(*temp1))
			s = _curs_scrwidth[TYPE(RBYTE(*temp1))];
		end -= s - 1;
		temp2 = &win->_y[cury][curx+s];
	}

	while (temp1 < end)
		*temp1++ = *temp2++;

	while (s--)
		*temp1++ = win->_bkgd;

#ifdef	_VR3_COMPAT_CODE
	if (_y16update)
		(*_y16update)(win, 1, win->_maxx - curx, cury, curx);
#endif	/* _VR3_COMPAT_CODE */

	win->_lastch[cury] = win->_maxx - 1;
	if (win->_firstch[cury] > curx)
		win->_firstch[cury] = curx;

	win->_flags |= _WINCHANGED;

	if (win->_sync)
		wsyncup(win);

	return (win->_immed ? wrefresh(win) : OK);
}

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
#include	<stdlib.h>
#include	"curses_inc.h"

/* This routine clears up to the end of line. */

int
wclrtoeol(WINDOW *win)
{
	int	y = win->_cury;
	int	x = win->_curx;
	int	maxx = win->_maxx;
	int			cx;
	chtype		wc;

	if (win != curscr) {
		win->_nbyte = -1;
		if (_scrmax > 1) {
			if (ISMBIT(win->_y[y][x])) {
				win->_insmode = TRUE;
				if (_mbvalid(win) == ERR)
					return (ERR);
				x = win->_curx;
			}
			if (ISMBIT(win->_y[y][maxx - 1])) {
				for (cx = maxx - 1; cx >= x; --cx)
					if (!ISCBIT(win->_y[y][cx]))
						break;
				wc = RBYTE(win->_y[y][cx]);
				if (cx + _curs_scrwidth[TYPE(wc)] > maxx)
					maxx = cx - 1;
			}
		}
	}

	memSset(&win->_y[y][x], win->_bkgd, maxx - x);
	maxx = win->_maxx;

#ifdef	_VR3_COMPAT_CODE
	if (_y16update)
		(*_y16update)(win, 1, maxx - x, y, x);
#endif	/* _VR3_COMPAT_CODE */

	/* if curscr, reset blank structure */
	if (win == curscr) {
		if (_BEGNS[y] >= x)
			/* LINTED */
			_BEGNS[y] = (short) maxx;
		if (_ENDNS[y] >= x)
			_ENDNS[y] = _BEGNS[y] > x ? -1 : x-1;

		_CURHASH[y] = x == 0 ? 0 : _NOHASH;

		if (_MARKS != NULL) {
			char	*mkp = _MARKS[y];
			int	endx = COLS /
				BITSPERBYTE + (COLS  %BITSPERBYTE ? 1 : 0);
			int	m = x / BITSPERBYTE + 1;

			for (; m < endx; ++m)
				mkp[m] = 0;
			mkp += x / BITSPERBYTE;
			if ((m = x % BITSPERBYTE) == 0)
				*mkp = 0;
			else
				for (; m < BITSPERBYTE; ++m)
					*mkp &= ~(1 << m);

			/* if color terminal, do the same for color marks */

			if (_COLOR_MARKS != NULL) {
				mkp = _COLOR_MARKS[y];

				m = x / BITSPERBYTE + 1;
				for (; m < endx; ++m)
					mkp[m] = 0;
				mkp += x / BITSPERBYTE;
				if ((m = x % BITSPERBYTE) == 0)
					*mkp = 0;
				else
					for (; m < BITSPERBYTE; ++m)
						*mkp &= ~(1 << m);
			}
		}
		return (OK);
	} else {
		/* update firstch and lastch for the line. */
#ifdef	DEBUG
	if (outf)
		fprintf(outf, "CLRTOEOL: line %d begx = %d, maxx = %d, "
		    "lastch = %d, next firstch %d\n", y, win->_begx,
		    win->_firstch[y], win->_lastch[y], win->_firstch[y+1]);
#endif	/* DEBUG */

		if (win->_firstch[y] > x)
		    /* LINTED */
		    win->_firstch[y] = (short) x;
		win->_lastch[y] = maxx - 1;
		win->_flags |= _WINCHANGED;
		/* sync with ancestors structures */
		if (win->_sync)
			wsyncup(win);

		return (win->_immed ? wrefresh(win) : OK);
	}
}

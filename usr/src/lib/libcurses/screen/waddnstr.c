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

/* This routine adds a string starting at (_cury, _curx) */

int
waddnstr(WINDOW *win, char *tstr, int i)
{
	chtype	ch;
	short	maxx_1 = win->_maxx - 1, cury = win->_cury,
		curx = win->_curx;
	chtype	**_y = win->_y;
	bool	savimmed = win->_immed,
		savsync = win->_sync;
	int	rv = OK;
	int	pflag;
	unsigned	char *str = (unsigned char *)tstr;

#ifdef	DEBUG
	if (outf) {
		if (win == stdscr)
			fprintf(outf, "waddnstr(stdscr, ");
		else
			fprintf(outf, "waddnstr(%o, ", win);
		fprintf(outf, "\"%s\")\n", str);
	}
#endif	/* DEBUG */

	/* throw away any current partial character */
	win->_nbyte = -1;
	win->_insmode = FALSE;
	pflag = 1;

	win->_immed = win->_sync = FALSE;

	if (i < 0)
		i = MAXINT;

	while (((ch = *str) != 0) && (i-- > 0)) {
		if (pflag == 1) {
			if (_scrmax > 1 && (rv = _mbvalid(win)) == ERR)
				break;
			curx = win->_curx;
			cury = win->_cury;
		}
		if (_mbtrue && ISMBIT(ch)) {
			int	m, k, ty;
			chtype		c;
			/* make sure we have the whole character */
			c = RBYTE(ch);
			ty = TYPE(c);
			m = cswidth[ty] - (ty == 0 ? 1 : 0);
			for (k = 1; str[k] != '\0' && k <= m; ++k)
				if (!ISMBIT(str[k]))
					break;
			if (k <= m)
				break;
			if (m > i)
				break;
			for (k = 0; k <= m; ++k, ++str) {
				if ((rv = _mbaddch(win, A_NORMAL,
				    RBYTE(*str))) == ERR)
					goto done;
				if (k > 0)
					i--;
			}
			pflag = 1;
			cury = win->_cury;
			curx = win->_curx;
			continue;
		}

		/* do normal characters while not next to edge */
		if ((ch >= ' ') && (ch != _CTRL('?')) && (curx < maxx_1)) {
			if (_scrmax > 1 && ISMBIT(_y[cury][curx]) &&
			    (rv = _mbclrch(win, cury, curx)) == ERR)
				break;
			if (curx < win->_firstch[cury])
				win->_firstch[cury] = curx;
			if (curx > win->_lastch[cury])
				win->_lastch[cury] = curx;
			ch = _WCHAR(win, ch);
			_y[cury][curx] = ch;
#ifdef	_VR3_COMPAT_CODE
			if (_y16update)
				/* LINTED */
				win->_y16[cury][curx] = _TO_OCHTYPE(ch);
#endif	/* _VR3_COMPAT_CODE */
			curx++;
			pflag = 0;
		} else {
			win->_curx = curx;
			/* found a char that is too tough to handle above */
			if (waddch(win, ch) == ERR) {
				rv = ERR;
				break;
			}
			cury = win->_cury;
			curx = win->_curx;
			pflag = 1;
		}
		str++;
		win->_curx = curx;
	}

done :
	win->_curx = curx;
	win->_flags |= _WINCHANGED;
	win->_sync = savsync;
	if (win->_sync)
		wsyncup(win);

	return ((win->_immed = savimmed) ? wrefresh(win) : rv);
}

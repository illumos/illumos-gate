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
 * Insert to 'win' at most n chars of a string
 * starting at (cury, curx). However, if n <= 0,
 * insert the entire string.
 * \n, \t, \r, \b are treated in the same way
 * as other control chars.
 */

int
winsnstr(WINDOW *win, char *tsp, int n)
{
	chtype		*wcp;
	int		x, cury, endx, maxx, len;
	bool		savscrl, savsync, savimmed;
	short		savx, savy;
	unsigned char	*sp = (unsigned char *)tsp;

	/* only insert at the start of a character */
	win->_nbyte = -1;
	win->_insmode = TRUE;
	if (_scrmax > 1 && _mbvalid(win) == ERR)
		return (ERR);

	if (n < 0)
		n = MAXINT;

	/* compute total length of the insertion */
	endx = win->_curx;
	maxx = win->_maxx;
	for (x = 0; sp[x] != '\0' && x < n && endx < maxx; ++x) {
		len = (sp[x] < ' '|| sp[x] == _CTRL('?')) ? 2 : 1;

		if (ISMBIT(sp[x])) {
			int	m, k, ty;
			chtype	c;

			/* see if the entire character is defined */
			c = RBYTE(sp[x]);
			ty = TYPE(c);
			m = x + cswidth[ty] - (ty == 0 ? 1 : 0);
			for (k = x + 1; sp[k] != '\0' && k <= m; ++k) {
				c = RBYTE(sp[k]);
				if (TYPE(c) != 0)
					break;
			}
			if (k <= m)
				break;
			/* recompute # of columns used */
			len = _curs_scrwidth[ty];
			/* skip an appropriate number of bytes */
			x = m;
		}

		if ((endx += len) > maxx) {
			endx -= len;
			break;
		}
	}

	/* length of chars to be shifted */
	if ((len = endx - win->_curx) <= 0)
		return (ERR);

	/* number of chars insertible */
	n = x;

	/* shift data */
	cury = win->_cury;

	if (_mbinsshift(win, len) == ERR)
		return (ERR);

	/* insert new data */
	wcp = win->_y[cury] + win->_curx;

	/* act as if we are adding characters */
	savx = win->_curx;
	savy = win->_cury;
	win->_insmode = FALSE;
	savscrl = win->_scroll;
	savimmed = win->_immed;
	savsync = win->_sync;
	win->_scroll = win->_sync;

	for (; n > 0; --n, ++sp) {
		/* multi-byte characters */
		if (_mbtrue && ISMBIT(*sp)) {
			(void) _mbaddch(win, A_NORMAL, RBYTE(*sp));
			wcp = win->_y[cury] + win->_curx;
			continue;
		}
		if (_scrmax > 1 && ISMBIT(*wcp))
			(void) _mbclrch(win, cury, win->_curx);
		/* single byte character */
		win->_nbyte = -1;

		if (*sp < ' ' || *sp == _CTRL('?')) {
			*wcp++ = _CHAR('^') | win->_attrs;
			*wcp = _CHAR(_UNCTRL(*sp)) | win->_attrs;
		} else
			*wcp = _CHAR(*sp) | win->_attrs;
		win->_curx += (*sp < ' ' || *sp == _CTRL('?')) ? 2 : 1;
		++wcp;
	}
	win->_curx = savx;
	win->_cury = savy;

	/* update the change structure */
	if (win->_firstch[cury] > win->_curx)
		win->_firstch[cury] = win->_curx;
	win->_lastch[cury] = maxx - 1;

	win->_flags |= _WINCHANGED;

	win->_scroll = savscrl;
	win->_sync = savsync;
	win->_immed = savimmed;

	if (win->_sync)
		wsyncup(win);
	return (win->_immed ? wrefresh(win) : OK);
}

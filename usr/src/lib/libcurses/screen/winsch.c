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
#include	<ctype.h>

/* Insert a character at (curx, cury). */

int
winsch(WINDOW *win, chtype c)
{
	short	curx = win->_curx;
	int	n, cury = win->_cury;
	chtype	*wcp, a;
	int		rv;

	a = _ATTR(c);
	c &= A_CHARTEXT;

	rv = OK;
	win->_insmode = TRUE;
	if (_scrmax > 1 && (rv = _mbvalid(win)) == ERR)
		goto done;
	/* take care of multi-byte characters */
	if (_mbtrue && ISMBIT(c)) {
		rv = _mbaddch(win, A_NORMAL, RBYTE(c));
		goto done;
	}
	win->_nbyte = -1;
	curx = win->_curx;

	/* let waddch() worry about these */
	if (c == '\r' || c == '\b')
		return (waddch(win, c));

	/* with \n, in contrast to waddch, we don't clear-to-eol */
	if (c == '\n') {
		if (cury >= (win->_maxy-1) || cury == win->_bmarg)
			return (wscrl(win, 1));
		else {
			win->_cury++;
			win->_curx = 0;
			return (OK);
		}
	}

	/* with tabs or control characters, we have to do more */
	if (c == '\t') {
		n = (TABSIZE - (curx % TABSIZE));
		if ((curx + n) >= win->_maxx)
			n = win->_maxx - curx;
		c = ' ';
	} else {
		if (iscntrl((int) c) != 0) {
			if (curx >= win->_maxx-1)
				return (ERR);
			n = 2;
		} else
			n = 1;
	}

	/* shift right */
	wcp = win->_y[cury] + curx;
	if ((rv = _mbinsshift(win, n)) == ERR)
		goto done;

	/* insert new control character */
	if (c < ' ' || c == _CTRL('?')) {
		*wcp++ = '^' | win->_attrs | a;
		*wcp = _UNCTRL(c) | win->_attrs | a;
	} else {
		/* normal characters */
		c = _WCHAR(win, c) | a;
		for (; n > 0; --n)
			*wcp++ = c;
	}

done:
	if (curx < win->_firstch[cury])
		win->_firstch[cury] = curx;
	win->_lastch[cury] = win->_maxx-1;

	win->_flags |= _WINCHANGED;

	if (win->_sync)
		wsyncup(win);

	return ((rv == OK && win->_immed) ? wrefresh(win) : rv);
}

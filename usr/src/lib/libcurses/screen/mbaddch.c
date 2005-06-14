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
/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

/*
 *	Clear the space occupied by a multicolumn character
 */

int
_mbclrch(WINDOW *win, int y, int x)
{
	chtype	*wcp, *ep, *wp, wc;

	/* ASSERT(_scrmax > 1); */

	wcp = win->_y[y];
	wp = wcp + x;

	/* compute the bounds for the character */
	if (ISCBIT(*wp)) {
		for (; wp >= wcp; --wp)
			if (!ISCBIT(*wp))
				break;
		if (wp < wcp)
			return (ERR);
	}
	wc = RBYTE(*wp);
	ep = wp + _curs_scrwidth[TYPE(wc)];
	if (ep > wcp + win->_maxx)
		return (ERR);

	/* update the change structure */
	/*LINTED*/
	if ((x = (int)(wp - wcp)) < win->_firstch[y])
		/*LINTED*/
		win->_firstch[y] = (short)x;
	/*LINTED*/
	if ((x = (int)(ep - wcp) - 1) > win->_lastch[y])
		/*LINTED*/
		win->_lastch[y] = (short)x;

	/* clear the character */
	for (; wp < ep; ++wp)
		*wp = win->_bkgd;
	return (OK);
}



/*
 *	Make sure the window cursor point to a valid place.
 *	If win->_insmode or isedge, the cursor has to
 *	point to the start of a whole character; otherwise, the
 *	cursor has to point to a part of a whole character.
 */

int
_mbvalid(WINDOW *win)
{
	chtype	*wp, *wcp, *ecp, wc;
	int		x;
	bool	isedge;

	/* ASSERT(_scrmax > 1); */

	x = win->_curx;
	wcp = win->_y[win->_cury];
	wp = wcp + x;
	if (!ISMBIT(*wp))
		return (OK);

	ecp = wcp + win->_maxx;
	isedge = FALSE;

	/* make wp points to the start column of a mb-character */
	if (ISCBIT(*wp)) {
		for (; wp >= wcp; --wp)
			if (!ISCBIT(*wp))
				break;
		if (wp < wcp) {
			for (wp = wcp + x + 1; wp < ecp; ++wp)
				if (!ISCBIT(*wp))
					break;
			if (wp >= ecp)
				return (ERR);
			isedge = TRUE;
		}
	}

	/* make sure that wp points to a whole character */
	wc = RBYTE(*wp);
	if (wp + _curs_scrwidth[TYPE(wc)] > ecp) {
		for (wp -= 1; wp >= wcp; --wp)
			if (!ISCBIT(*wp))
				break;
		if (wp < wcp)
			return (ERR);
		isedge = TRUE;
	}

	if (isedge || win->_insmode)
		/*LINTED*/
		win->_curx = (short)(wp-wcp);
	return (OK);
}



/*
 *	Add/insert multi-byte characters
 */

int
_mbaddch(WINDOW *win, chtype a, chtype c)
{
	int		n, x, y, nc, m, len, nbyte, ty;
	chtype		*wcp, wc;
	char		*wch, rc[2];

	/* ASSERT(_mbtrue); */

	/* decode the character into a sequence of bytes */
	nc = 0;
	if (ISCBIT(c))
		/*LINTED*/
		rc[nc++] = (char)(LBYTE(c)|MBIT);
	if (ISMBIT(c))
		/*LINTED*/
		rc[nc++] = (char)RBYTE(c);

	a |= win->_attrs;

	/* add the sequence to the image */
	for (n = 0; n < nc; ++n) {
		wc = RBYTE(rc[n]);
		ty = TYPE(wc);
		wch = win->_waitc;

		/* first byte of a multi-byte character */
		if (ty > 0 || win->_nbyte < 0) {
			/*LINTED*/
			wch[0] = (char)wc;
			win->_nbyte = cswidth[ty] + (ty == 0 ? 0 : 1);
			win->_index = 1;
		} else {
		/* non-first byte */
			/*LINTED*/
			wch[win->_index] = (char)wc;
			win->_index += 1;
		}

		/* if character is not ready to process */
		if (win->_index < win->_nbyte)
			continue;

		/* begin processing the character */
		nbyte = win->_nbyte;
		win->_nbyte = -1;
		wc = RBYTE(wch[0]);
		len = _curs_scrwidth[TYPE(wc)];

		/* window too small or char cannot be stored */
		if (len > win->_maxx || 2*len < nbyte)
			continue;

		/* if the character won't fit into the line */
		if ((win->_curx + len) > win->_maxx &&
		    (win->_insmode || waddch(win, '\n') == ERR))
			continue;

		y = win->_cury;
		x = win->_curx;
		wcp = win->_y[y] + x;

		if (win->_insmode) {
			/* perform the right shift */
			if (_mbinsshift(win, len) == ERR)
				continue;
		} else if (_scrmax > 1) {
			/* clear any multi-byte char about to be overwritten */
			for (m = 0; m < len; ++m)
				if (ISMBIT(wcp[m]) &&
				    _mbclrch(win, y, x + m) == ERR)
					break;
			if (m < len)
				continue;
		}

		/* pack two bytes at a time */
		for (m = nbyte/2; m > 0; m -= 1, wch += 2)
			*wcp++ = _CHAR((RBYTE(wch[1]) << 8) |
			    RBYTE(wch[0])) | CBIT | a;

		/* do the remaining byte if any */
		if ((nbyte%2) != 0)
			*wcp++ = RBYTE(wch[0]) | CBIT | a;

		/* fill-in for remaining display columns */
		for (m = (nbyte / 2) + (nbyte % 2); m < len; ++m)
			*wcp++ = (CBIT|MBIT) | a;

		/* the first column has Continue BIT off */
		win->_y[y][x] &= ~CBIT;

		if (win->_insmode == FALSE) {
			if (x < win->_firstch[y])
				/*LINTED*/
				win->_firstch[y] = (short)x;
			if ((x += len-1) >= win->_maxx)
				x = win->_maxx-1;
			if (x > win->_lastch[y])
				/*LINTED*/
				win->_lastch[y] = (short)x;

			if ((win->_curx += len) >= win->_maxx) {
				if (y >= (win->_maxy-1) || y == win->_bmarg) {
					win->_curx = win->_maxx-1;
					if (wscrl(win, 1) == ERR)
						continue;
				} else {
					win->_cury += 1;
					win->_curx = 0;
				}
			}
		}
	}

	return (OK);
}

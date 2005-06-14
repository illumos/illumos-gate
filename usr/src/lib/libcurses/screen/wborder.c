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

/*
 *	Draw a box around a window.
 *
 *	ls : the character and attributes used for the left side.
 *	rs : right side.
 *	ts : top side.
 *	bs : bottom side.
 */

#define	_LEFTSIDE	variables[0]
#define	_RIGHTSIDE	variables[1]
#define	_TOPSIDE	variables[2]
#define	_BOTTOMSIDE	variables[3]
#define	_TOPLEFT	variables[4]
#define	_TOPRIGHT	variables[5]
#define	_BOTTOMLEFT	variables[6]
#define	_BOTTOMRIGHT	variables[7]

static	char	acs_values[] = {
		    'x', /* ACS_VLINE */
		    'x', /* ACS_VLINE */
		    'q', /* ACS_HLINE */
		    'q', /* ACS_HLINE */
		    'l', /* ACS_ULCORNER */
		    'k', /* ACS_URCORNER */
		    'm', /* ACS_LLCORNER */
		    'j' /* ACS_LRCORNER */
		};

int
wborder(WINDOW *win, chtype ls, chtype rs, chtype ts,
	chtype bs, chtype tl, chtype tr, chtype bl, chtype br)
{
	int	i, endy = win->_maxy - 1, endx = win->_maxx - 2;
	chtype	**_y = win->_y;	/* register version */
	chtype	*line_ptr, variables[8];
	int	x, sx, xend;
	chtype	wc;

	_LEFTSIDE = ls;
	_RIGHTSIDE = rs;
	_TOPSIDE = ts;
	_BOTTOMSIDE = bs;
	_TOPLEFT = tl;
	_TOPRIGHT = tr;
	_BOTTOMLEFT = bl;
	_BOTTOMRIGHT = br;

	for (i = 0; i < 8; i++) {
		if (_CHAR(variables[i]) == 0 ||
		    variables[i] & 0xFF00)
			variables[i] = acs_map[acs_values[i]];
		if (ISCBIT(variables[i]))
			variables[i] = _CHAR((RBYTE(variables[i])<<8) | \
			(LBYTE(variables[i])|MBIT)) | CBIT;
		variables[i] &= ~CBIT;
		variables[i] = _WCHAR(win, variables[i]) | _ATTR(variables[i]);
	}

	/* do top and bottom edges and corners */
	xend = win->_maxx-1;
	x = 0;
	for (; x <= xend; ++x)
		if (!ISCBIT(_y[0][x]))
			break;
	for (; xend >= x; --xend)
		if (!ISCBIT(_y[0][endx])) {
			int	m;
			wc = RBYTE(_y[0][xend]);
			if ((m = xend + _curs_scrwidth[TYPE(wc)]) > win->_maxx)
				xend -= 1;
			else
				xend = m - 1;
			endx = xend - 1;
			break;
		}
	sx = x == 0 ? 1 : x;
	memSset((line_ptr = &_y[0][sx]), _TOPSIDE, endx);
	if (x == 0)
		*(--line_ptr) = _TOPLEFT;
	if (endx == win->_maxx-2)
		line_ptr[++endx] = _TOPRIGHT;

	xend = win->_maxx-1;
	x = 0;
	for (; x <= xend; ++x)
		if (!ISCBIT(_y[endy][x]))
			break;
	for (; xend >= x; --xend)
		if (!ISCBIT(_y[endy][xend])) {
			int	m;
			wc = RBYTE(_y[endy][xend]);
			if ((m = xend + _curs_scrwidth[TYPE(wc)]) > win->_maxx)
				xend -= 1;
			else
				xend = m - 1;
			endx = xend - 1;
			break;
		}
	sx = x == 0 ? 1 : x;

	memSset((line_ptr = &_y[endy][sx]), _BOTTOMSIDE, endx);
	if (x == 0)
		*--line_ptr = _BOTTOMLEFT;
	if (endx == win->_maxx-2)
		line_ptr[++endx] = _BOTTOMRIGHT;

#ifdef	_VR3_COMPAT_CODE
	if (_y16update) {
		(*_y16update)(win, 1, ++endx, 0, 0);
		(*_y16update)(win, 1, endx--, endy, 0);
	}
#endif	/* _VR3_COMPAT_CODE */

	/* left and right edges */
	while (--endy > 0) {
		wc = _y[endy][0];
		if (!ISCBIT(wc) && _curs_scrwidth[TYPE(RBYTE(wc))] == 1)
			_y[endy][0] = _LEFTSIDE;
		wc = _y[endy][endx];
		if (!ISCBIT(wc) && _curs_scrwidth[TYPE(RBYTE(wc))] == 1)
			_y[endy][endx] = _RIGHTSIDE;

#ifdef	_VR3_COMPAT_CODE
		if (_y16update) {
			/* LINTED */
			win->_y16[endy][0] =  _TO_OCHTYPE(_LEFTSIDE);
			/* LINTED */
			win->_y16[endy][endx] = _TO_OCHTYPE(_RIGHTSIDE);
		}
#endif	/* _VR3_COMPAT_CODE */
	}
	return (wtouchln((win), 0, (win)->_maxy, TRUE));
}

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

/* Change the background of a window.  nbkgd :	new background. */

int
wbkgd(WINDOW *win, chtype nbkgd)
{
	short	maxx;
	int	x, y;
	chtype	*wcp, obkgda, obkgdc, nbkgda,
		nbkgdc, acolor, c;
	short	*begch, *endch;

	/* if 'nbkgd' contains color information, but this is not a color   */
	/* terminal, erase that information.				*/

	if ((nbkgd & A_COLOR) && (cur_term->_pairs_tbl == NULL))
		nbkgd &= ~A_COLOR;

	if (nbkgd == win->_bkgd)
		return (OK);

	obkgdc = _CHAR(win->_bkgd);
	obkgda = _ATTR(win->_bkgd);

	nbkgdc = _CHAR(nbkgd);
	nbkgda = _ATTR(nbkgd);

	/* switch byte order if necessary */
	if (ISCBIT(nbkgdc))
		nbkgdc = _CHAR((RBYTE(nbkgdc) << 8) | (LBYTE(nbkgdc)|MBIT)) |
		    CBIT;
	c = RBYTE(nbkgdc);
	if ((nbkgdc < ' ' || nbkgdc == _CTRL('?')) ||
	    _curs_scrwidth[TYPE(c)] > 1)
		nbkgdc = obkgdc;
	nbkgd = (nbkgdc & ~CBIT) | nbkgda;

	win->_bkgd = nbkgd;

	/* delete the old background from the attribute field and replace    */
	/* it with the new background.  Note: if the same attribute was	*/
	/* first set by wbkgd() and then by wattron(), or vice versa, it */
	/* will be deleted, so the effect of wattron() will be lost.	 */
	/* This applies to both video and color attributes.		 */

	if ((acolor = (win->_attrs & A_COLOR)) != 0) {
		if (acolor == (obkgda & A_COLOR)) {
			win->_attrs = _ATTR((win->_attrs & ~obkgda) | nbkgda);
		} else {
			win->_attrs = _ATTR((win->_attrs &
			    (~obkgda | A_COLOR)) | (nbkgda & ~A_COLOR));
		}
	} else
		win->_attrs = _ATTR((win->_attrs & ~obkgda) | nbkgda);

	maxx = win->_maxx - 1;
	begch = win->_firstch;
	endch = win->_lastch;
	for (y = win->_maxy-1; y >= 0; --y, ++begch, ++endch) {
		for (x = maxx, wcp = win->_y[y]; x-- >= 0; ++wcp) {
			if ((c = _CHAR(*wcp)) == obkgdc)
				c = nbkgdc;
			if ((acolor = (*wcp & A_COLOR)) != 0) {
				if (acolor == (obkgda & A_COLOR))
					*wcp = c | _ATTR((*wcp & ~obkgda) |
					    nbkgda);
				else
					*wcp = c | _ATTR((*wcp & (~obkgda |
					    A_COLOR)) | (nbkgda & ~A_COLOR));
			} else
				*wcp = c | _ATTR((*wcp & ~obkgda) | nbkgda);
		}
		*begch = 0;
		*endch = maxx;
	}

	win->_flags |= _WINCHANGED;
	if (win->_sync)
		wsyncup(win);

	return (win->_immed ? wrefresh(win) : OK);
}

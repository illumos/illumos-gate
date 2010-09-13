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
 *	Move(cury, curx) of win to(y, x).
 *	It is guaranteed that the cursor is left at the start
 *	of a whole character nearest to(y, x).
 */

int
wmbmove(WINDOW *win, int y, int x)
{
	chtype	*wcp, *wp, *ep;

	if (y < 0 || x < 0 || y >= win->_maxy || x >= win->_maxx)
		return (ERR);

	if (_scrmax > 1) {
		wcp = win->_y[y];
		wp = wcp + x;
		ep = wcp + win->_maxx;

		/* make wp points to the start of a character */
		if (ISCBIT(*wp)) {
			for (; wp >= wcp; --wp)
				if (!ISCBIT(*wp))
					break;
			if (wp < wcp) {
				wp = wcp+x+1;
				for (; wp < ep; ++wp)
					if (!ISCBIT(*wp))
						break;
			}
		}

		/* make sure that the character is whole */
		if (wp + _curs_scrwidth[TYPE(*wp)] > ep)
			return (ERR);

		/* the new x position */
		/*LINTED*/
		x = (int)(wp - wcp);
	}

	if (y != win->_cury || x != win->_curx) {
		win->_nbyte = -1;
		/*LINTED*/
		win->_cury = (short)y;
		/*LINTED*/
		win->_curx = (short)x;
	}

	return (win->_immed ? wrefresh(win) : OK);
}

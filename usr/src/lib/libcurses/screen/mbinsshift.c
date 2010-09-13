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
 *	Shift right an interval of characters
 */

int
_mbinsshift(WINDOW *win, int len)
{
	int	x, y, maxx,  mv;
	chtype	*wcp, *wp, *ep;

	y = win->_cury;
	x = win->_curx;
	maxx = win->_maxx;
	wcp  = win->_y[y];

	/* ASSERT(!ISCBIT(wcp[x])); */

	/* shift up to a whole character */
	if (_scrmax > 1) {
		wp = wcp + maxx - 1;
		if (ISMBIT(*wp)) {
			reg chtype	rb;

			for (; wp >= wcp; --wp)
				if (!ISCBIT(*wp))
					break;
			if (wp < wcp)
				return (ERR);
			rb = RBYTE(*wp);
			if ((wp + _curs_scrwidth[TYPE(rb)]) > (wcp + maxx))
				/*LINTED*/
				maxx = (int)(wp - wcp);
			}
		}

	/* see if any data need to move */
	if ((mv = maxx - (x+len)) <= 0)
		return (OK);

	/* the end of the moved interval must be whole */
	if (ISCBIT(wcp[x + mv]))
		(void) _mbclrch(win, y, x + mv - 1);

	/* move data */
	ep = wcp + x + len;
	for (wp = wcp + maxx - 1; wp >= ep; --wp)
		*wp = *(wp - len);

	/* clear a possible partial multibyte character */
	if (ISMBIT(*wp))
		for (ep = wp; ep >= wcp; --ep) {
			mv = (int)(ISCBIT(*ep));
			*ep = win->_bkgd;
			if (!mv)
				break;
		}

	/* update the change structure */
	if (x < win->_firstch[y])
		/*LINTED*/
		win->_firstch[y] = (short)x;
	win->_lastch[y] = maxx - 1;

	return (OK);
}

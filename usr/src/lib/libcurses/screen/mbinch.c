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
 *	Get the(y, x) character of a window and
 *	return it in a 0-terminated string.
 */
char
*wmbinch(WINDOW *win, int y, int x)
{
	short		savx, savy;
	int		k;
	chtype		*wp, *ep, wc;
	static char	rs[CSMAX + 1];

	k = 0;
	savx = win->_curx;
	savy = win->_cury;

	if (wmbmove(win, y, x) == ERR)
		goto done;
	wp = win->_y[win->_cury] + win->_curx;
	wc = RBYTE(*wp);
	ep = wp + _curs_scrwidth[TYPE(wc & 0377)];

	for (; wp < ep; ++wp) {
		if ((wc = RBYTE(*wp)) == MBIT)
			break;
		/*LINTED*/
		rs[k++] = (char)wc;
		if ((wc = LBYTE(*wp)|MBIT) == MBIT)
			break;
		/*LINTED*/
		rs[k++] = (char)wc;
	}
done :
	win->_curx = savx;
	win->_cury = savy;
	rs[k] = '\0';
	return (rs);
}

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
 * Read in ncols worth of data from window win and assign the
 * chars to string. NULL terminate string upon completion.
 * Return the number of chtypes copied.
 */

int
winwchnstr(WINDOW *win, chtype *string, int ncols)
{
	chtype	*ptr = &(win->_y[win->_cury][win->_curx]);
	int	counter = 0;
	int	maxcols = win->_maxx - win->_curx;
	int	scrw, s, wc;
	char	*mp, mbbuf[CSMAX+1];
	wchar_t	wch;
	chtype	rawc;
	chtype	attr;

	if (ncols < 0)
		ncols = MAXINT;

	while (ISCBIT(*ptr)) {
		ptr--;
		maxcols++;
	}

	while ((counter < ncols) && maxcols > 0) {
		attr = *ptr & A_WATTRIBUTES;
		rawc = *ptr & A_WCHARTEXT;
		(void) mbeucw((int)RBYTE(rawc));
		scrw = mbscrw((int)RBYTE(rawc));
		for (mp = mbbuf, s = 0; s < scrw; s++, maxcols--, ptr++) {
			if ((wc = (int)RBYTE(rawc)) == MBIT)
				continue;
			/* LINTED */
			*mp++ = (char) wc;
			if ((wc = (int)(LBYTE(rawc) | MBIT)) == MBIT)
				continue;
			/* LINTED */
			*mp++ = (char) wc;
		}
		*mp = '\0';
		if (_curs_mbtowc(&wch, mbbuf, CSMAX) <= 0)
			break;
		*string++ = wch | attr;
		counter++;
	}
	if (counter < ncols)
		*string = (chtype) 0;
	return (counter);
}

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
 * Copy n chars in window win from current cursor position to end
 * of window into char buffer str.  Return the number of chars copied.
 */

int
winnstr(WINDOW *win, char *str, int ncols)
{
	int	counter = 0;
	int	cy = win->_cury;
	chtype	*ptr = &(win->_y[cy][win->_curx]),
		*pmax = &(win->_y[cy][win->_maxx]);
	chtype	wc;
	int	eucw, scrw, s;


	while (ISCBIT(*ptr))
		ptr--;

	if (ncols < -1)
		ncols = MAXINT;

	while (counter < ncols) {
		scrw = mbscrw((int) RBYTE(*ptr));
		eucw = mbeucw((int) RBYTE(*ptr));
		if (counter + eucw > ncols)
			break;

		for (s = 0; s < scrw; s++, ptr++) {
			if ((wc = RBYTE(*ptr)) == MBIT)
				continue;
			/* LINTED */
			*str++ = (char) wc;
			counter++;
			if ((wc = LBYTE(*ptr) | MBIT) == MBIT)
				continue;
			/* LINTED */
			*str++ = (char) wc;
			counter++;
		}

		if (ptr >= pmax) {
			if (++cy == win->_maxy)
				break;

			ptr = &(win->_y[cy][0]);
			pmax = ptr + win->_maxx;
		}
	}
	if (counter < ncols)
		*str = '\0';

	return (counter);
}

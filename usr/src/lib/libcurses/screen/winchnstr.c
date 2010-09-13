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
 * Read in ncols worth of data from window win and assign the
 * chars to string. NULL terminate string upon completion.
 * Return the number of chtypes copied.
 */

int
winchnstr(WINDOW *win, chtype *string, int ncols)
{
	chtype	*ptr = &(win->_y[win->_cury][win->_curx]);
	int	counter = 0;
	int	maxcols = win->_maxx - win->_curx;
	int	eucw, scrw, s;
	chtype	rawc, attr, wc;

	if (ncols < 0)
		ncols = MAXINT;

	while (ISCBIT(*ptr)) {
		ptr--;
		maxcols++;
	}

	while ((counter < ncols) && maxcols > 0) {
		eucw = mbeucw((int) RBYTE(*ptr));
		scrw = mbscrw((int) RBYTE(*ptr));

		if (counter + eucw > ncols)
			break;
		for (s = 0; s < scrw; s++, maxcols--, ptr++) {
			attr = _ATTR(*ptr);
			rawc = _CHAR(*ptr);
			if ((wc = RBYTE(rawc)) == MBIT)
				continue;
			*string++ = wc | attr;
			counter++;
			if ((wc = LBYTE(rawc) | MBIT) == MBIT)
				continue;
			*string++ = wc | attr;
			counter++;
		}
	}
	if (counter < ncols)
		*string = (chtype) 0;
	return (counter);
}

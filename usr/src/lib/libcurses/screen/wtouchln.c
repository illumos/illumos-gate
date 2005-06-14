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
 * Make a number of lines look like they have/have not been changed.
 * y: the start line
 * n: the number of lines affected
 * changed:	1: changed
 * 		0: not changed
 * 		-1: changed. Called internally - In this mode
 *		even REDRAW lines are changed.
 */

int
wtouchln(WINDOW *win, int y, int n, int changed)
{
	short	*firstch, *lastch, b, e;
	int	maxy = win->_maxy;

	if (y >= maxy)
		return (ERR);
	if (y < 0)
		y = 0;
	if ((y + n) > maxy)
		n = maxy - y;
	firstch = win->_firstch + y;
	lastch = win->_lastch + y;
	if (changed) {
		win->_flags |= _WINCHANGED;
		b = 0;
		e = win->_maxx - 1;
	} else {
		b = _INFINITY;
		e = -1;
		win->_flags &= ~_WINCHANGED;
	}

	for (; n-- > 0; firstch++, lastch++) {
		if (changed == -1 || *firstch != _REDRAW)
			*firstch = b, *lastch = e;
	}

	if ((changed == 1) && win->_sync)
		wsyncup(win);

	return (((changed == 1) && win->_immed) ? wrefresh(win) : OK);
}

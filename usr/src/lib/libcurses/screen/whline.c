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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#include	<sys/types.h>
#include	<stdlib.h>
#include	"curses_inc.h"

int
whline(WINDOW *win, chtype horch, int num_chars)
{
	short	cury = win->_cury, curx = win->_curx;
	chtype  a, *fp = &(win->_y[cury][curx]);

	if (num_chars <= 0)
		return (ERR);

	if (num_chars > win->_maxx - curx)
		num_chars = win->_maxx - curx;
	if (horch == 0)
		horch = ACS_HLINE;
	a = _ATTR(horch);
	horch = _WCHAR(win, horch) | a;
	memSset(fp, horch | win->_attrs, num_chars);
	if (curx < win->_firstch[cury])
		win->_firstch[cury] = curx;
	if ((curx += (num_chars - 1)) > win->_lastch[cury])
		win->_lastch[cury] = curx;
	win->_flags |= _WINCHANGED;

	if (win->_sync)
		wsyncup(win);

	return (win->_immed ? wrefresh(win) : OK);
}

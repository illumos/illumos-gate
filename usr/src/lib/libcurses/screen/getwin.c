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

#define		SEPARATE_READ	6

/* Read a window that was stored by putwin. */

WINDOW	*
getwin(FILE *filep)
{
	short		*save_fch, win_nums[SEPARATE_READ], maxy, maxx, nelt;
	WINDOW		*win = NULL;
	chtype		**ecp, **wcp;

	/* read everything from _cury to _bkgd inclusive */

	nelt = sizeof (WINDOW) - sizeof (win->_y) - sizeof (win->_parent) -
	    sizeof (win->_parx) - sizeof (win->_pary) -
	    sizeof (win->_ndescs) - sizeof (win->_delay) -
	    (SEPARATE_READ * sizeof (short));

	if ((fread((char *) win_nums, sizeof (short), SEPARATE_READ, filep) !=
	    SEPARATE_READ) || ((win = _makenew(maxy = win_nums[2], maxx =
	    win_nums[3], win_nums[4], win_nums[5])) == NULL)) {
		goto err;
	}

	if (_image(win) == ERR) {
		win = (WINDOW *) NULL;
		goto err;
	}
	save_fch = win->_firstch;

	if (fread(&(win->_flags), 1, nelt, filep) != nelt)
		goto err;

	win->_firstch = save_fch;
	win->_lastch = save_fch + maxy;

	/* read the image */
	wcp = win->_y;
	ecp = wcp + maxy;

	while (wcp < ecp)
		if (fread((char *) *wcp++, sizeof (chtype), maxx, filep) !=
		    maxx) {
err :
			if (win != NULL)
				(void) delwin(win);
			return ((WINDOW *) NULL);
	}

	win->_cury = win_nums[0];
	win->_curx = win_nums[1];
	win->_use_idl = win->_use_keypad = FALSE;

	return (win);
}

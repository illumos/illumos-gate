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
 *	Make a  derived window of an existing window. The two windows
 *	share the same character image.
 *		orig:	the original window
 *		nl, nc:	numbers of lines and columns
 *		by, bx:	coordinates for upper-left corner of the derived
 *			window in the coord system of the parent window.
 */

WINDOW	*
derwin(WINDOW *orig, int num_lines, int nc, int by, int bx)
{
	int	y;
	WINDOW	*win = (WINDOW *) NULL, *par;
	chtype	**w_y, **o_y;
#ifdef	_VR3_COMPAT_CODE
	_ochtype	**w_y16, **o_y16;
#endif	/* _VR3_COMPAT_CODE */

	/* make sure window fits inside the original one */
	if (by < 0 || (by + num_lines) > orig->_maxy || bx < 0 ||
	    (bx + nc) > orig->_maxx)
		goto done;
	if (nc == 0)
		nc = orig->_maxx - bx;
	if (num_lines == 0)
		num_lines = orig->_maxy - by;

	/* Create the window skeleton */
	if ((win = _makenew(num_lines, nc, by + orig->_begy,
	    bx + orig->_begx)) == NULL)
		goto done;

	/* inheritance */
	/*LINTED*/
	win->_parx = (short) bx;
	/*LINTED*/
	win->_pary = (short) by;
	win->_bkgd = orig->_bkgd;
	win->_attrs = orig->_attrs;
	w_y = win->_y;
	o_y = orig->_y;

#ifdef	_VR3_COMPAT_CODE
	if (_y16update) {
		int	hby = by;

		w_y16 = win ->_y16;
		o_y16 = orig->_y16;

		for (y = 0; y < num_lines; y++, hby++)
			w_y16[y] = o_y16[hby] + bx;
	}
#endif	/* _VR3_COMPAT_CODE */

	for (y = 0; y < num_lines; y++, by++)
		w_y[y] = o_y[by] + bx;

	win->_yoffset = orig->_yoffset;

	/* update descendant number of ancestors */
	win->_parent = orig;
	for (par = win->_parent; par != NULL; par = par->_parent)
		par->_ndescs += 1;

done:
	return (win);
}

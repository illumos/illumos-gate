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

/* Sync the changes in a window with its ancestors. */

void
wsyncup(WINDOW *win)
{
	short	*wbch, *wech, *pbch, *pech, bch, ech;
	int	wy, px, py, endy;
	WINDOW	*par;

	for (par = win->_parent; par != NULL; win = par, par = par->_parent) {
		py = win->_pary;
		px = win->_parx;
		endy = win->_maxy;

		wbch = win->_firstch;
		wech = win->_lastch;
		pbch = par->_firstch+ py;
		pech = par->_lastch+ py;

		/*
		 * I don't think we need check WINCHANGED first.
		 * The reasoning is that all internal calls will have come
		 * from a function that did change the window.  And assumably
		 * all external calls will work the same way.
		 */
		par->_flags |= _WINCHANGED;
		/* check each line */
		for (wy = 0; wy < endy; ++wy, ++wbch, ++wech, ++pbch, ++pech)
			if (*wbch != _INFINITY) {
				bch = px + *wbch;
				ech = px + *wech;
				if (*pbch > bch)
					*pbch = bch;
				if (*pech < ech)
					*pech = ech;
			}
	}
}

void
wcursyncup(WINDOW *win)
{
	WINDOW	*par = win->_parent;

	while (par != NULL) {
		par->_cury = win->_cury + win->_pary;
		par->_curx = win->_curx + win->_parx;
		par = (win = par)->_parent;
	}
}

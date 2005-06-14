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

/* Make the changes in ancestors visible in win. */

void
wsyncdown(WINDOW *win)
{
	short	*wbch, *wech, *pbch, *pech, bch, ech, endx;
	int	wy, px, py, endy;
	WINDOW	*par;

	py = win->_pary;
	px = win->_parx;
	endy = win->_maxy;
	endx = win->_maxx - 1;

	for (par = win->_parent; par != NULL; par = par->_parent) {
		if (par->_flags & (_WINCHANGED | _WIN_ADD_ONE |
		    _WIN_INS_ONE)) {
			wbch = win->_firstch;
			wech = win->_lastch;
			pbch = par->_firstch + py;
			pech = par->_lastch + py;

			for (wy = 0; wy < endy; ++wy, ++wbch, ++wech,
			    ++pbch, ++pech) {
				if (*pbch != _INFINITY) {
					if ((bch = *pbch - px) < 0)
						bch = 0;
					if ((ech = *pech - px) > endx)
						ech = endx;
					if (!(bch > endx || ech < 0)) {
						if (*wbch > bch)
							*wbch = bch;
						if (*wech < ech)
							*wech = ech;
					}
				}
			}
			win->_flags |= _WINCHANGED;
		}

		py += par->_pary;
		px += par->_parx;
	}
}

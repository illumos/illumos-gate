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
 * Move a derived window inside its parent window.
 * This routine does not change the screen relative
 * parameters begx and begy. Thus, it can be used to
 * display different parts of the parent window at
 * the same screen coordinate.
 */

int
mvderwin(WINDOW *win, int pary, int parx)
{
	int	y, maxy;
	WINDOW	*par;
	chtype	obkgd, **wc, **pc;
	short	*begch, *endch, maxx;

	if ((par = win->_parent) == NULL)
		goto bad;
	if (pary == win->_pary && parx == win->_parx)
		return (OK);

	maxy = win->_maxy-1;
	maxx = win->_maxx-1;
	if ((parx + maxx) >= par->_maxx || (pary + maxy) >= par->_maxy)
bad:
		return (ERR);

	/* save all old changes */
	wsyncup(win);

	/* rearrange pointers */
	/*LINTED*/
	win->_parx = (short) parx;
	/*LINTED*/
	win->_pary = (short) pary;
	wc = win->_y;
	pc = par->_y + pary;
	begch = win->_firstch;
	endch = win->_lastch;
	for (y = 0; y <= maxy; ++y, ++wc, ++pc, ++begch, ++endch) {
		*wc = *pc + parx;
		*begch = 0;
		*endch = maxx;
	}

	/* change background to our own */
	obkgd = win->_bkgd;
	win->_bkgd = par->_bkgd;
	return (wbkgd(win, obkgd));
}

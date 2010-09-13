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
#include	<stdlib.h>
#include	"curses_inc.h"

/*
 * Pad refresh. These routines are provided for upward compatibility
 * with the 'pad' structure of Sys V.2. Since windows now can be of
 * arbitrary size and derived windows can be moved within their
 * parent windows effortlessly, a separate notion of 'pad' as
 * a larger-than-screen window is no longer necessary.
 *
 * pminy, pminx: the area (pminy, pminx, maxy, maxx) of pad is refreshed
 * sminy, sminx, smaxy, smaxx: the screen area to be affected.
 */

int
prefresh(WINDOW *pad, int pminy, int pminx, int sminy,
	int sminx, int smaxy, int smaxx)
{
	return (_prefresh(wrefresh, pad, pminy, pminx, sminy,
	    sminx, smaxy, smaxx));
}

int
_prefresh(int (*func)(WINDOW *), WINDOW *pad, int pminy, int pminx,
	int sminy, int sminx, int smaxy, int smaxx)
{

	/*
	 * If pad->_padwin doesn't exist(meaning that this is
	 * the first call to p*refresh) create it as a derived window
	 */

	if (!pad->_padwin) {
		if ((pad->_padwin = derwin(pad, pad->_maxy, pad->_maxx,
		    0, 0)) == NULL) {
			goto bad;
		}
	/* else  pad->_padwin->_use_idl = TRUE; */

	/*
	 * The following makes parent window to run in fast mode
	 * by creating an illusion that it has no derived windows
	 */

		pad->_ndescs--;
	}

	if (_padjust(pad, pminy, pminx, sminy, sminx, smaxy, smaxx) == ERR)
bad:
		return (ERR);

	(*func)(pad->_padwin);
	return (OK);
}

int
_padjust(WINDOW *pad, int pminy, int pminx, int sminy,
	int sminx, int smaxy, int smaxx)
{
	short	prows, pcols, y;
	WINDOW	*padwin = pad->_padwin;
	chtype	**p_y, **o_y;

	/* make sure the area requested to be updated is on the pad */

	if ((pminy >= pad->_maxy) || (pminx >= pad->_maxx))
		return (ERR);

	/* determine the area of the pad to be updated 	*/

	if (pminy < 0)
		pminy = 0;
	if (pminx < 0)
		pminx = 0;

	/* determine the screen area affected */

	if (sminy < 0)
		sminy = 0;
	if (sminx < 0)
		sminx = 0;
	if (smaxy < sminy)
		smaxy = LINES - 1;
	if (smaxx < sminx)
		smaxx = COLS - 1;

	/*
	 * Modify the area of the pad to be updated taking into
	 * consideration screen parameters.
	 */

	if ((prows = (smaxy - sminy) + 1) > (y = pad->_maxy - pminy))
		prows = y;
	if ((pcols = (smaxx - sminx) + 1) > (y = pad->_maxx - pminx))
		pcols = y;

	if (((padwin->_cury = pad->_cury - pminy) < 0) ||
	    (padwin->_cury >= prows))
		padwin->_cury = 0;
	if (((padwin->_curx = pad->_curx - pminx) < 0) ||
	    (padwin->_curx >= pcols))
		padwin->_curx = 0;

	padwin->_leave = pad->_leave;
	padwin->_use_idl = pad->_use_idl;


	/*
	 * If padwin refers to the same derwin, return.  Otherwise
	 * update the coordinates and malloc'ed areas of the padwin
	 */

	if ((padwin->_begy == sminy) && (padwin->_begx == sminx) &&
	    (padwin->_maxy == prows) && (padwin->_maxx == pcols) &&
	    (padwin->_y[0] == (pad->_y[pminy] + pminx)) &&
	    (!(pad->_flags & _WINSDEL))) {
		goto good;
	}

	/* update the coordinates of the pad */

	padwin->_maxy = prows;
	padwin->_maxx = pcols;
	/* LINTED */
	padwin->_begy = (short)sminy;
	/* LINTED */
	padwin->_begx = (short)sminx;
	/* LINTED */
	padwin->_pary = (short)pminy;
	/* LINTED */
	padwin->_parx = (short)pminx;

	/* update the malloc'ed areas */

	p_y = padwin->_y;
	o_y = pad->_y;

	for (y = 0; y < prows; y++, pminy++)
		p_y[y] = o_y[pminy] + pminx;

	(void) wtouchln(padwin, 0, prows, TRUE);
good:
	return (OK);
}

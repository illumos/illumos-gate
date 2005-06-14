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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * prefresh.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/prefresh.c 1.4 1998/06/03 16:06:14 "
"cbates Exp $";
#endif
#endif

#include <private.h>

/*
 * Update newscr with the given pad then display to the terminal.
 */
int
prefresh(WINDOW *w, int pminr, int pminc, int sminr, int sminc,
	int smaxr, int smaxc)
{
	int	code;

	code = pnoutrefresh(w, pminr, pminc, sminr, sminc, smaxr, smaxc);
	if (code == OK)
		code = doupdate();

	return (code);
}

/*
 * Update newscr with the given pad.  This allows newscr to
 * be updated with several windows before doing a doupdate().
 *
 * MKS extension permits windows that are not pads to be refreshed
 * using this function.
 */
int
pnoutrefresh(WINDOW *pad, int pminr, int pminc, int sminr, int sminc,
	int smaxr, int smaxc)
{
	WINDOW	*ns;
	int	row, dy, dx;

	ns = __m_screen->_newscr;

	/* Adjust regions to be within bounds. */
	if (pminr < 0)
		pminr = 0;
	if (pminc < 0)
		pminc = 0;
	if (sminr < 0)
		sminr = 0;
	if (sminc < 0)
		sminc = 0;
	if (ns->_maxy <= smaxr)
		smaxr = ns->_maxy-1;
	if (ns->_maxx <= smaxc)
		smaxc = ns->_maxx-1;

	if (pad->_maxy <= pminr || pad->_maxx <= pminc ||
		smaxr < sminr || smaxc < sminc)
		return (ERR);

	/* Clear displayed region. */
	for (row = sminr; row < smaxr; ++row) {
		(void) __m_cc_erase(ns, row, sminc, row, smaxc);
	}

	/*
	 * Determine the proper maximums in case smaxr and smaxc mapped
	 * beyond the bottom and right-hand edges of the pad.
	 */
	if (pad->_maxx <= pminc + smaxc-sminc + 1)
		smaxc = sminc + pad->_maxx - 1 - pminc;
	if (pad->_maxy <= pminr + smaxr-sminr + 1)
		smaxr = sminr + pad->_maxy - 1 - pminr;

	/* Remember refresh region (inclusive). */
	pad->_refy = (short) pminr;
	pad->_refx = (short) pminc;
	pad->_sminy = (short) sminr;
	pad->_sminx = (short) sminc;
	pad->_smaxy = (short) smaxr;
	pad->_smaxx = (short) smaxc;

	(void) copywin(pad, ns, pminr, pminc, sminr, sminc, smaxr, smaxc, 0);

	/* Last refreshed window controls W_LEAVE_CURSOR flag. */
	ns->_flags &= ~W_LEAVE_CURSOR;
	ns->_flags |= pad->_flags &
		(W_CLEAR_WINDOW | W_REDRAW_WINDOW | W_LEAVE_CURSOR);
	pad->_flags &= ~(W_CLEAR_WINDOW | W_REDRAW_WINDOW);

	/* Figure out where to leave the cursor. */
	dy = pad->_cury - pminr + pad->_begy;
	dx = pad->_curx - pminc + pad->_begx;

	ns->_cury = (dy < 0) ? 0 :
		((ns->_maxy <= dy) ? ns->_maxy - 1 : (short) dy);
	ns->_curx = (dx < 0) ? 0 :
		((ns->_maxx <= dx) ? ns->_maxx - 1 : (short) dx);

	return (OK);
}

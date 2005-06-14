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
 * wbrdr.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wbrdr.c 1.2 "
"1995/07/07 18:53:03 ant Exp $";
#endif
#endif

#include <private.h>

/*
 * Draw a border around the edges of the window. The parms correspond to
 * a character and attribute for the left, right, top, and bottom sides,
 * top left, top right, bottom left, and bottom right corners. A zero in
 * any character parm means to take the default.
 */
int
wborder(WINDOW *w,
	chtype ls, chtype rs, chtype ts, chtype bs,
	chtype tl, chtype tr, chtype bl, chtype br)
{
	int	code;
	cchar_t	wls, wrs, wts, wbs, wtl, wtr, wbl, wbr;

	if (ls == 0)
		ls = ACS_VLINE;
	(void) __m_acs_cc(ls, &wls);

	if (rs == 0)
		rs = ACS_VLINE;
	(void) __m_acs_cc(rs, &wrs);

	if (ts == 0)
		ts = ACS_HLINE;
	(void) __m_acs_cc(ts, &wts);

	if (bs == 0)
		bs = ACS_HLINE;
	(void) __m_acs_cc(bs, &wbs);

	if (tl == 0)
		tl = ACS_ULCORNER;
	(void) __m_acs_cc(tl, &wtl);

	if (tr == 0)
		tr = ACS_URCORNER;
	(void) __m_acs_cc(tr, &wtr);

	if (bl == 0)
		bl = ACS_LLCORNER;
	(void) __m_acs_cc(bl, &wbl);

	if (br == 0)
		br = ACS_LRCORNER;
	(void) __m_acs_cc(br, &wbr);

	code = wborder_set(w, &wls, &wrs, &wts, &wbs, &wtl, &wtr, &wbl, &wbr);

	return (code);
}

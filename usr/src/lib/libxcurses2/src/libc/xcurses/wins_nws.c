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
 * wins_nws.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/wins_nws.c 1.2 1998/04/30 20:30:42 "
"cbates Exp $";
#endif
#endif

#include <private.h>

int
wins_nwstr(WINDOW *w, const wchar_t *wcs, int n)
{
	cchar_t	cc;
	int	i, y, x;

	y = w->_cury;
	x = w->_curx;

	if (n < 0)
		n = INT_MAX;

	/* Must start with a spacing character */
	if ((wcwidth(*wcs) <= 0) && !iswcntrl(*wcs))
		return (ERR);

	for (; *wcs != '\0' && 0 < n; n -= i, wcs += i) {
		if ((i = __m_wcs_cc(wcs, w->_bg._at, w->_fg._co, &cc))
			< 0	|| __m_wins_wch(w, y, x, &cc, &y, &x) == ERR)
			break;
	}

	WSYNC(w);

	return (WFLUSH(w));
}

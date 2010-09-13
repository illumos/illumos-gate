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
 * copywin.c
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
"libxcurses/src/libc/xcurses/rcs/copywin.c 1.6 1998/06/01 17:29:15 "
"cbates Exp $";
#endif
#endif

#include <private.h>

#undef min
#define	min(a, b)		((a) < (b) ? (a) : (b))

/*
 * Version of copywin used internally by Curses to compute
 * the intersection of the two windows before calling copywin().
 */
int
__m_copywin(const WINDOW *s, WINDOW *t, int transparent)
{
	int code, sminr, sminc, tminr, tminc, tmaxr, tmaxc;

	tmaxc = min(s->_begx + s->_maxx, t->_begx + t->_maxx) - 1 - t->_begx;
	tmaxr = min(s->_begy + s->_maxy, t->_begy + t->_maxy) - 1 - t->_begy;

	if (s->_begy < t->_begy) {
		sminr = t->_begy - s->_begy;
		tminr = 0;
	} else {
		sminr = 0;
		tminr = s->_begy - t->_begy;
	}
	if (s->_begx < t->_begx) {
		sminc = t->_begx - s->_begx;
		tminc = 0;
	} else {
		sminc = 0;
		tminc = s->_begx- t->_begx;
	}
	code = copywin(s, t, sminr, sminc,
		tminr, tminc, tmaxr, tmaxc, transparent);

	return (code);
}

/*
 * Overlay specified part of source window over destination window
 * NOTE copying is destructive only if transparent is set to false.
 */
int
copywin(const WINDOW *s, WINDOW *t,
	int sminr, int sminc, int tminr, int tminc,
	int tmaxr, int tmaxc, int transparent)
{
	int	tc;
	cchar_t	*st, *tt;
	cchar_t	bg = s->_bg;

	for (; tminr <= tmaxr; ++tminr, ++sminr) {
		st = s->_line[sminr] + sminc;
		tt = t->_line[tminr] + tminc;

		/* Copy source region to target. */
		for (tc = tminc; tc <= tmaxc; ++tc, ++tt, ++st) {
			if (transparent) {
				if (__m_cc_compare(st, &bg, 1))
					continue;
			}
			*tt = *st;
			__m_touch_locs(t, tminr, tc, tc + 1);
		}
#ifdef M_CURSES_SENSIBLE_WINDOWS
		/*
		 * Case 4 -
		 * Expand incomplete glyph from source into target window.
		 */
		if (0 < tminc && !t->_line[tminr][tminc]._f)
			(void) __m_cc_expand(t, tminr, tminc, -1);
		if (tmaxc + 1 < t->_maxx && !__m_cc_islast(t, tminr, tmaxc))
			(void) __m_cc_expand(t, tminr, tmaxc, 1);
#endif /* M_CURSES_SENSIBLE_WINDOWS */
	}

	return (OK);
}

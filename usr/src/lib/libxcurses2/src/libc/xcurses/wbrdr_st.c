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
 * wbrdr_st.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wbrdr_st.c 1.6 "
"1995/07/07 18:52:43 ant Exp $";
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
wborder_set(WINDOW *w, const cchar_t *ls, const cchar_t *rs,
	const cchar_t *ts, const cchar_t *bs, const cchar_t *tl,
	const cchar_t *tr, const cchar_t *bl, const cchar_t *br)
{
	short	oflags;
	int	x, y, code;

	code = ERR;
	x = w->_curx;
	y = w->_cury;

	oflags = w->_flags & (W_FLUSH | W_SYNC_UP);
	w->_flags &= ~(W_FLUSH | W_SYNC_UP);

	/* Verticals. */
	(void) wmove(w, 0, 0);
	(void) wvline_set(w, ls, w->_maxy);
	(void) wmove(w, 0, w->_maxx-1);
	(void) wvline_set(w, rs, w->_maxy);

	/* Horizontals. */
	(void) wmove(w, 0, 1);
	(void) whline_set(w, ts, w->_maxx-2);
	(void) wmove(w, w->_maxy-1, 1);
	(void) whline_set(w, bs, w->_maxx-2);

	w->_flags |= oflags;

	/* Corners. */
	if (tl == NULL)
		tl = WACS_ULCORNER;
	if (tr == NULL)
		tr = WACS_URCORNER;
	if (bl == NULL)
		bl = WACS_LLCORNER;
	if (br == NULL)
		br = WACS_LRCORNER;

	if (__m_cc_replace(w, 0, 0, tl, 0) == -1)
		goto error;
	if (__m_cc_replace(w, 0, w->_maxx-1, tr, 0) == -1)
		goto error;
	if (__m_cc_replace(w, w->_maxy-1, 0, bl, 0) == -1)
		goto error;
	if (__m_cc_replace(w, w->_maxy-1, w->_maxx-1, br, 0) == -1)
		goto error;

	(void) wmove(w, y, x);

	WSYNC(w);

	code = WFLUSH(w);
error:
	return (code);
}

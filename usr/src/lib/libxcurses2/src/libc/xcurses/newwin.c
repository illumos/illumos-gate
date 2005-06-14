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
 * newwin.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/newwin.c 1.11 1998/06/04 14:26:16 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <stdlib.h>

#undef werase

/*
 * Create and return a pointer to a new window or pad.
 *
 * For a window, provide the dimensions and location of the upper
 * left hand corner of the window.  If either dimension is zero (0)
 * then the default sizes will be LINES-begy and COLS-begx.
 *
 * For a pad, provide the dimensions and -1 for begy and begx.
 * If either dimension is zero (0) then the default sizes will be
 * LINES and COLS.
 *
 * If parent is not null, then create a sub-window of the parent
 * window.
 */
WINDOW *
__m_newwin(WINDOW *parent,
	int nlines, int ncols, int begy, int begx)
{
	WINDOW	*w;
	int	x, y, dx, dy;
	int	isPad;

	isPad = ((begy < 0) && (begx < 0)) ||
		(parent && (parent->_flags & W_IS_PAD));

	if (parent == NULL) {
		/* Check for default dimensions. */
		if (nlines == 0) {
			nlines = lines;
			if (0 <= begy)
				nlines -= begy;
		}
		if (ncols == 0) {
			ncols = columns;
			if (0 <= begx)
				ncols -= begx;
		}
	} else {
		/*
		 * Make sure window dimensions remain within parent's
		 * window so that the new subwindow is a proper subset
		 * of the parent.
		 */
		if (begy < parent->_begy || begx < parent->_begx ||
			parent->_maxy < (begy-parent->_begy) + nlines ||
			parent->_maxx < (begx-parent->_begx) + ncols)
			goto error_1;

		/*
		 * If either dimension is zero (0), use the max size
		 * for the dimension from the parent window less the
		 * subwindow's starting location.
		 */
		if (nlines == 0)
			nlines = parent->_maxy - (begy - parent->_begy);
		if (ncols == 0)
			ncols = parent->_maxx - (begx - parent->_begx);
	}

	if (!isPad) {
		/* Check that a window fits on the screen. */
		if (0 <= begy) {
			if (lines < begy + nlines) {
				goto error_1;
			}
		}
		if (0 <= begx) {
			if (columns < begx + ncols) {
				goto error_1;
			}
		}
	}

	w = (WINDOW *) calloc(1, sizeof (*w));
	if (w == NULL)
		goto error_1;

	w->_first = (short *) calloc((size_t) (nlines + nlines),
		sizeof (*w->_first));
	if (w->_first == NULL)
		goto error_2;

	w->_last = &w->_first[nlines];

	w->_line = (cchar_t **) calloc((size_t) nlines, sizeof (*w->_line));
	if (w->_line == NULL)
		goto error_2;

	/* Window rendition. */
	(void) setcchar(&w->_bg, L" ", WA_NORMAL, 0, (void *) 0);
	(void) setcchar(&w->_fg, L" ", WA_NORMAL, 0, (void *) 0);
	if (parent == NULL) {
		w->_base = (cchar_t *) malloc((size_t) (nlines * ncols) *
			sizeof (*w->_base));
		if (w->_base == NULL)
			goto error_2;

		w->_line[0] = w->_base;
		for (y = 0; y < nlines; y++) {
			if (y)
				w->_line[y] = &w->_line[y-1][ncols];
			for (x = 0; x < ncols; ++x) {
				w->_line[y][x] = w->_bg;
			}
		}
	} else {
		/*
		 * The new window's origin (0,0) maps to (begy, begx) in the
		 * parent's window.  In effect, subwin() is a method by which
		 * a portion of a parent's window can be addressed using a
		 * (0,0) origin.
		 */
		dy = begy - parent->_begy;
		dx = begx - parent->_begx;

		w->_base = NULL;

		for (y = 0; y < nlines; ++y)
			w->_line[y] = &parent->_line[dy++][dx];
	}

	w->_begy = (short) begy;
	w->_begx = (short) begx;
	w->_cury = w->_curx = 0;
	w->_maxy = (short) nlines;
	w->_maxx = (short) ncols;
	w->_parent = parent;

	/* Software scroll region. */
	w->_top = 0;
	w->_bottom = (short) nlines;
	w->_scroll = 0;

	/* Window initially blocks for input. */
	w->_vmin = 1;
	w->_vtime = 0;
	w->_flags = W_USE_TIMEOUT;

	/* Determine window properties. */
	if (isPad) {
		/* This window is a PAD */
		w->_flags |= W_IS_PAD;	/* Inherit PAD attribute */
		if (((begy < 0) && (begx < 0)) ||
			(parent && !(parent->_flags & W_IS_PAD))) {
			/* Child of a normal window */
			w->_begy = w->_begx = 0;
			/*
			 * Map to upper left portion of
			 * display by default (???)
			 */
			w->_sminy = w->_sminx = 0;
			w->_smaxx = w->_maxx;
			w->_smaxy = w->_maxy;
		}
	} else if (begx + ncols == columns) {
		/* Writing to last column should trigger auto-margin wrap. */
		w->_flags |= W_END_LINE;

		if (begx == 0) {
			w->_flags |= W_FULL_LINE;

			if (begy == 0 && nlines == lines)
				w->_flags |= W_FULL_WINDOW;
		}

		/* Will writing to bottom-right triggers scroll? */
		if (begy + nlines == lines)
			w->_flags |= W_SCROLL_WINDOW;
	}

	/* Initial screen clear for full screen windows only. */
	if (w->_flags & W_FULL_WINDOW) {
		w->_flags |= W_CLEAR_WINDOW;
		/* Reset dirty region markers. */
		(void) wtouchln(w, 0, w->_maxy, 0);
	} else {
		if (!parent) {
			/* Do not erase sub windows */
			(void) werase(w);
		}
	}

	return (w);
error_2:
	(void) delwin(w);
error_1:
	return (NULL);
}

int
delwin(WINDOW *w)
{
	if (w == NULL)
		return (OK);


	if (w->_line != NULL) {
		if (w->_base != NULL)
			free(w->_base);

		free(w->_line);
	}

	if (w->_first != NULL)
		free(w->_first);

	free(w);

	return (OK);
}

WINDOW *
derwin(WINDOW *parent,
	int nlines, int ncols, int begy, int begx)
{
	WINDOW	*w;

	if (parent == NULL)
		return (NULL);

	/* Absolute screen address. */
	begy += parent->_begy;
	begx += parent->_begx;

	w = __m_newwin(parent, nlines, ncols, begy, begx);

	return (w);
}

WINDOW *
newwin(int nlines, int ncols, int begy, int begx)
{
	WINDOW	*w;

	w = __m_newwin(NULL, nlines, ncols, begy, begx);

	return (w);
}

WINDOW *
subwin(WINDOW *parent, int nlines, int ncols, int begy, int begx)
{
	WINDOW	*w;

	if (parent == NULL)
		return (NULL);

	w = __m_newwin(parent, nlines, ncols, begy, begx);

	return (w);
}

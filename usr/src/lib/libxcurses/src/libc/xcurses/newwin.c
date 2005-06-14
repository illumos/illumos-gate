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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/newwin.c 1.9 1995/09/28 20:15:58 ant Exp $";
#endif
#endif

#include <private.h>
#include <stdlib.h>

/*f
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
__m_newwin(parent, nlines, ncols, begy, begx)
WINDOW *parent;
int nlines, ncols, begy, begx;
{
	WINDOW *w;
	int x, y, dx, dy;

#ifdef M_CURSES_TRACE
	__m_trace(
		"__m_newwin(%p, %d, %d, %d, %d)", 
		parent, nlines, ncols, begy, begx
	);
#endif

	if (parent == (WINDOW *) 0) {
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
		/* Make sure window dimensions remain within parent's
		 * window so that the new subwindow is a proper subset
		 * of the parent.
		 */
		if (begy < parent->_begy || begx < parent->_begx
		|| parent->_maxy < (begy-parent->_begy) + nlines
		|| parent->_maxx < (begx-parent->_begx) + ncols)
			goto error_1;

		/* If either dimension is zero (0), use the max size
		 * for the dimension from the parent window less the
		 * subwindow's starting location.
		 */
		if (nlines == 0)
			nlines = parent->_maxy - (begy - parent->_begy);
		if (ncols == 0)
			ncols = parent->_maxx - (begx - parent->_begx);
	}

	/* Check that a window fits on the screen. */
	if (0 <= begy) {
		if (lines < begy + nlines)
			goto error_1;
	}
	if (0 <= begx) {
		if (columns < begx + ncols)
			goto error_1;
	}
	
	w = (WINDOW *) calloc(1, sizeof *w);
	if (w == (WINDOW *) 0)
		goto error_1;

	w->_first = (short *) calloc(
		(size_t) (nlines + nlines), sizeof *w->_first
	);
	if (w->_first == (short *) 0)
		goto error_2;

	w->_last = &w->_first[nlines];

	w->_line = (cchar_t **) calloc((size_t) nlines, sizeof *w->_line);
	if (w->_line == (cchar_t **) 0)
		goto error_2;

	/* Window rendition. */
	(void) setcchar(
		&w->_bg, M_MB_L(" "), WA_NORMAL, 0, (void *) 0
	);
	(void) setcchar(
		&w->_fg, M_MB_L(" "), WA_NORMAL, 0, (void *) 0
	);

	if (parent == (WINDOW *) 0) {
		w->_base = (cchar_t *) malloc(
			(size_t) (nlines * ncols) * sizeof *w->_base
		);
		if (w->_base == (cchar_t *) 0)
			goto error_2;

		w->_line[y = 0] = w->_base;
		do {
			for (x = 0; x < ncols; ++x)
				w->_line[y][x] = w->_bg;
			w->_line[y+1] = &w->_line[y][x];
		} while (++y < nlines-1);
	} else {
		/* The new window's origin (0,0) maps to (begy, begx) in the
		 * parent's window.  In effect, subwin() is a method by which
		 * a portion of a parent's window can be addressed using a
		 * (0,0) origin.
		 */
		dy = begy - parent->_begy;
		dx = begx - parent->_begx;

		w->_base = (cchar_t *) 0;

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
	if ((begy < 0 && begx < 0) 
	|| (parent != (WINDOW *) 0 && (parent->_flags & W_IS_PAD))) {
		w->_flags |= W_IS_PAD;
		w->_begy = w->_begx = 0;
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
	if (w->_flags & W_FULL_WINDOW)
		w->_flags |= W_CLEAR_WINDOW;

	/* Reset dirty region markers. */
	(void) wtouchln(w, 0, w->_maxy, 0);

	return __m_return_pointer("__m_newwin", w);
error_2:
	(void) delwin(w);
error_1:
	return __m_return_pointer("__m_newwin", (WINDOW *) 0);
}

int
delwin(w)
WINDOW *w;
{
	if (w == (WINDOW *) 0)
		return OK;

#ifdef M_CURSES_TRACE
	__m_trace(
		"delwin(%p) which is a %s%s.", w,
		(w->_parent == (WINDOW *) 0) ? "normal " : "sub-",
		(w->_flags & W_IS_PAD) ? "pad" : "window"
	);
#endif

	if (w->_line != (cchar_t **) 0) {
		if (w->_base != (cchar_t *) 0)
			free(w->_base);

		free(w->_line);
	}

	if (w->_first != (short *) 0)
		free(w->_first);

        free(w);

	return __m_return_code("delwin", OK);
}

WINDOW *
derwin(parent, nlines, ncols, begy, begx)
WINDOW *parent;
int nlines, ncols, begy, begx;
{
	WINDOW *w;

#ifdef M_CURSES_TRACE
	__m_trace(
		"derwin(%p, %d, %d, %d, %d)", 
		parent, nlines, ncols, begy, begx
	);
#endif

	if (parent == (WINDOW *) 0)
		return __m_return_pointer("derwin", (WINDOW *) 0);

	/* Absolute screen address. */
	begy += parent->_begy;
	begx += parent->_begx;

	w = __m_newwin(parent, nlines, ncols, begy, begx);

	return __m_return_pointer("derwin", w);
}

WINDOW *
newwin(nlines, ncols, begy, begx)
int nlines, ncols, begy, begx;
{
	WINDOW *w;

#ifdef M_CURSES_TRACE
	__m_trace("newwin(%d, %d, %d, %d)", nlines, ncols, begy, begx);
#endif

	w = __m_newwin((WINDOW *) 0, nlines, ncols, begy, begx);

	return __m_return_pointer("newwin", w);
}

WINDOW *
subwin(parent, nlines, ncols, begy, begx)
WINDOW *parent;
int nlines, ncols, begy, begx;
{
	WINDOW *w;

#ifdef M_CURSES_TRACE
	__m_trace(
		"subwin(%p, %d, %d, %d, %d)", 
		parent, nlines, ncols, begy, begx
	);
#endif

	if (parent == (WINDOW *) 0)
		return __m_return_pointer("subwin", (WINDOW *) 0);

	w = __m_newwin(parent, nlines, ncols, begy, begx);

	return __m_return_pointer("subwin", w);
}


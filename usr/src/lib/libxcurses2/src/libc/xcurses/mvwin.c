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
 * mvwin.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/mvwin.c 1.3 "
"1995/06/15 19:19:58 ant Exp $";
#endif
#endif

#include <private.h>

/*
 * Move window so that the upper left-hand corner is at (x,y). If the move
 * would cause the window to be off the screen, it is an error and the
 * window is not moved.  Moving subwindows is allowed, but should be
 * avoided.
 */
int
mvwin(WINDOW *w, int by, int bx)
{
	int	i, dx, dy;
	WINDOW	*parent = w->_parent;

	/* Check lower bounds of new window position. */
	if (by < 0 || bx < 0)
		return (ERR);

	if (parent == NULL) {
		/* Check upper bounds of normal window. */
		if (lines < by + w->_maxy || columns < bx + w->_maxx)
			return (ERR);
	} else {
		/* Check upper bounds of sub-window. */
		if (parent->_begy + parent->_maxy < by + w->_maxy ||
			parent->_begx + parent->_maxx < bx + w->_maxx)
			return (ERR);

		/*
		 * Move the sub-window's line pointers to the parent
		 * window's data.
		 */
		dy = by - parent->_begy;
		dx = bx - parent->_begx;

		for (i = 0; i <= w->_maxy; ++i)
			w->_line[i] = &parent->_line[dy++][dx];
	}

	w->_begy = (short) by;
	w->_begx = (short) bx;
	(void) wtouchln(w, 0, w->_maxy, 1);

	return (OK);
}

int
mvderwin(WINDOW *w, int py, int px)
{
	int	code;
	WINDOW	*parent;

	parent = w->_parent;

	if (parent == NULL)
		return (ERR);

	/* Absolute screen address. */
	py += parent->_begy;
	px += parent->_begx;

	code = mvwin(w, py, px);

	return (code);
}

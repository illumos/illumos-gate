/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#ifndef lint
static char
sccsid[] = "@(#)mvwin.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif	/* not lint */

#include	"curses.ext"

/*
 * relocate the starting position of a window
 */

int
mvwin(WINDOW *win, int by, int bx)
{
	WINDOW	*orig;
	int	dy, dx;

	if (by + win->_maxy > LINES || bx + win->_maxx > COLS)
		return (ERR);
	dy = by - win->_begy;
	dx = bx - win->_begx;
	orig = win->_orig;
	if (orig == NULL) {
		orig = win;
		do {
			win->_begy += dy;
			win->_begx += dx;
			_swflags_(win);
			win = win->_nextp;
		} while (win != orig);
	} else {
		if (by < orig->_begy || win->_maxy + dy > orig->_maxy)
			return (ERR);
		if (bx < orig->_begx || win->_maxx + dx > orig->_maxx)
			return (ERR);
		win->_begy = (short)by;
		win->_begx = (short)bx;
		_swflags_(win);
		_set_subwin_(orig, win);
	}
	(void) touchwin(win);
	return (OK);
}

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

#ifndef lint
static char
sccsid[] = "@(#)addch.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif	/* not lint */

#include	"curses.ext"

/* forward declaration */
static void set_ch(WINDOW *, int, int, int);

/*
 *	This routine adds the character to the current position
 */

int
waddch(WINDOW *win, char c)
{
	int		x, y;
	int		newx;

	x = win->_curx;
	y = win->_cury;
#ifdef FULLDEBUG
	fprintf(outf, "ADDCH('%c') at (%d, %d)\n", c, y, x);
#endif
	switch (c) {
	case '\t':
		for (newx = x + (8 - (x & 07)); x < newx; x++)
			if (waddch(win, ' ') == ERR)
				return (ERR);
		return (OK);

	default:
#ifdef FULLDEBUG
		fprintf(outf, "ADDCH: 1: y = %d, x = %d, firstch = %d,"
		    " lastch = %d\n", y, x, win->_firstch[y],
		    win->_lastch[y]);
#endif
		if (win->_flags & _STANDOUT)
			c |= _STANDOUT;
		set_ch(win, y, x, c);
		win->_y[y][x++] = c;
		if (x >= win->_maxx) {
			x = 0;
newline:
			if (++y >= win->_maxy)
				if (win->_scroll) {
					(void) scroll(win);
					--y;
				}
				else
					return (ERR);
		}
#ifdef FULLDEBUG
		fprintf(outf, "ADDCH: 2: y = %d, x = %d, firstch = %d,"
		    " lastch = %d\n", y, x, win->_firstch[y],
		    win->_lastch[y]);
#endif
		break;
	case '\n':
		(void) wclrtoeol(win);
		if (!NONL)
			x = 0;
		goto newline;
	case '\r':
		x = 0;
		break;
	case '\b':
		if (--x < 0)
			x = 0;
		break;
	}
	win->_curx = (short)x;
	win->_cury = (short)y;
	return (OK);
}

/*
 * set_ch:
 *	Set the first and last change flags for this window.
 */

static void
set_ch(WINDOW *win, int y, int x, int ch)
{
#ifdef	FULLDEBUG
	fprintf(outf, "SET_CH(%0.2o, %d, %d)\n", win, y, x);
#endif
	if (win->_y[y][x] != ch) {
		x += win->_ch_off;
		if (win->_firstch[y] == _NOCHANGE)
			win->_firstch[y] = win->_lastch[y] = (short)x;
		else if (x < win->_firstch[y])
			win->_firstch[y] = (short)x;
		else if (x > win->_lastch[y])
			win->_lastch[y] = (short)x;
#ifdef FULLDEBUG
		fprintf(outf, "SET_CH: change gives f/l: %d/%d [%d/%d]\n",
		    win->_firstch[y], win->_lastch[y],
		    win->_firstch[y] - win->_ch_off,
		    win->_lastch[y] - win->_ch_off);
#endif
	}
}

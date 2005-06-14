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
sccsid[] = "@(#)touchwin.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif	/* not lint */

#include	"curses.ext"

/*
 * make it look like the whole window has been changed.
 *
 */

int
touchwin(WINDOW *win)
{
	int	y, maxy;

#ifdef	DEBUG
	fprintf(outf, "TOUCHWIN(%0.2o)\n", win);
#endif
	maxy = win->_maxy;
	for (y = 0; y < maxy; y++)
		(void) touchline(win, y, 0, win->_maxx - 1);
	return (OK);
}

/*
 * touch a given line
 */

int
touchline(WINDOW *win, int y, int sx, int ex)
{
#ifdef DEBUG
	fprintf(outf, "TOUCHLINE(%0.2o, %d, %d, %d)\n", win, y, sx, ex);
	fprintf(outf, "TOUCHLINE:first = %d, last = %d\n",
	    win->_firstch[y], win->_lastch[y]);
#endif
	sx += win->_ch_off;
	ex += win->_ch_off;
	if (win->_firstch[y] == _NOCHANGE) {
		win->_firstch[y] = (short)sx;
		win->_lastch[y] = (short)ex;
	} else {
		if (win->_firstch[y] > sx)
			win->_firstch[y] = (short)sx;
		if (win->_lastch[y] < ex)
			win->_lastch[y] = (short)ex;
	}
#ifdef	DEBUG
	fprintf(outf, "TOUCHLINE:first = %d, last = %d\n",
	    win->_firstch[y], win->_lastch[y]);
#endif
	return (OK);
}

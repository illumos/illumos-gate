/*
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
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
sccsid[] = "@(#)insch.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	"curses.ext"

/*
 *	This routine performs an insert-char on the line, leaving
 * (_cury,_curx) unchanged.
 */

int
winsch(WINDOW *win, char c)
{
	char	*temp1, *temp2;
	char	*end;

	end = &win->_y[win->_cury][win->_curx];
	temp1 = &win->_y[win->_cury][win->_maxx - 1];
	temp2 = temp1 - 1;
	while (temp1 > end)
		*temp1-- = *temp2--;
	*temp1 = c;
	(void) touchline(win, win->_cury, win->_curx, win->_maxx - 1);
	if (win->_cury == LINES - 1 && win->_y[LINES-1][COLS-1] != ' ')
		if (win->_scroll) {
			(void) wrefresh(win);
			(void) scroll(win);
			win->_cury--;
		}
		else
			return (ERR);
	return (OK);
}

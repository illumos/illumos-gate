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
sccsid[] = "@(#)deleteln.c 1.8 89/08/24 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	"curses.ext"
#include	<string.h>

/*
 *	This routine deletes a line from the screen.  It leaves
 * (_cury,_curx) unchanged.
 */

int
wdeleteln(WINDOW *win)
{
	char	*temp;
	int	y;
	char	*end;

#ifdef DEBUG
	fprintf(outf, "DELETELN(%0.2o)\n", win);
#endif
	temp = win->_y[win->_cury];
	for (y = win->_cury; y < win->_maxy - 1; y++) {
		if (win->_orig == NULL)
			win->_y[y] = win->_y[y + 1];
		else
			(void) memmove(win->_y[y], win->_y[y+1], win->_maxx);
		(void) touchline(win, y, 0, win->_maxx - 1);
	}
	if (win->_orig == NULL)
		win->_y[y] = temp;
	else
		temp = win->_y[y];
	for (end = &temp[win->_maxx]; temp < end; )
		*temp++ = ' ';
	(void) touchline(win, y, 0, win->_maxx - 1);
	if (win->_orig == NULL)
		_id_subwins(win);
	return (OK);
}

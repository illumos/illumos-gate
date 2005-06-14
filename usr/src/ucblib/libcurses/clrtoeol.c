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
sccsid[] = "@(#)clrtoeol.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	<stddef.h>
#include	"curses.ext"

/*
 *	This routine clears up to the end of line
 */

int
wclrtoeol(WINDOW *win)
{
	char	*sp, *end;
	int	y, x;
	char	*maxx;
	ptrdiff_t	minx;

	y = win->_cury;
	x = win->_curx;
	end = &win->_y[y][win->_maxx];
	minx = _NOCHANGE;
	maxx = &win->_y[y][x];
	for (sp = maxx; sp < end; sp++)
		if (*sp != ' ') {
			maxx = sp;
			if (minx == _NOCHANGE)
				minx = sp - win->_y[y];
			*sp = ' ';
		}
	/*
	 * update firstch and lastch for the line
	 */
	(void) touchline(win, y, win->_curx, win->_maxx - 1);

#ifdef DEBUG
	fprintf(outf, "CLRTOEOL: minx = %d, maxx = %d, firstch = %d,"
	    " lastch = %d\n", minx, maxx - win->_y[y], win->_firstch[y],
	    win->_lastch[y]);
#endif
	return (OK);
}

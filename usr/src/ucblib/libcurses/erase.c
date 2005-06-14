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
sccsid[] = "@(#)erase.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif	/* not lint */

#include	<stddef.h>
#include	"curses.ext"

/*
 *	This routine erases everything on the window.
 */

int
werase(WINDOW *win)
{
	int	y;
	char	*sp, *end, *start, *maxx;
	ptrdiff_t	minx;

#ifdef DEBUG
	fprintf(outf, "WERASE(%0.2o)\n", win);
#endif
	for (y = 0; y < win->_maxy; y++) {
		minx = _NOCHANGE;
		start = win->_y[y];
		end = &start[win->_maxx];
		for (sp = start; sp < end; sp++)
			if (*sp != ' ') {
				maxx = sp;
				if (minx == _NOCHANGE)
					minx = sp - start;
				*sp = ' ';
			}
		if (minx != _NOCHANGE)
			(void) touchline(win, y, (int)minx,
				(int)(maxx - win->_y[y]));
	}
	win->_curx = win->_cury = 0;
	return (OK);
}

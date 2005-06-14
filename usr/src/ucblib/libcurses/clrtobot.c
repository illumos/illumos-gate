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
sccsid[] = "@(#)clrtobot.c 1.7 88/02/08 SMI"; /* from UCB 5.2 85/10/24 */
#endif	/* not lint */

#include	<stddef.h>
#include	"curses.ext"

/*
 *	This routine erases everything on the window.
 */

int
wclrtobot(WINDOW *win)
{
	int	y;
	char	*sp, *end, *maxx;
	int	startx;
	ptrdiff_t	minx;

	startx = win->_curx;
	for (y = win->_cury; y < win->_maxy; y++) {
		minx = _NOCHANGE;
		end = &win->_y[y][win->_maxx];
		for (sp = &win->_y[y][startx]; sp < end; sp++)
			if (*sp != ' ') {
				maxx = sp;
				if (minx == _NOCHANGE)
					minx = sp - win->_y[y];
				*sp = ' ';
			}
		if (minx != _NOCHANGE)
			(void) touchline(win, y, (int)minx,
			    (int)(maxx - &win->_y[y][0]));
		startx = 0;
	}
	return (OK);
}

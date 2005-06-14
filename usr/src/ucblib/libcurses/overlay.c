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
sccsid[] = "@(#)overlay.c 1.9 89/07/13 SMI"; /* from UCB 5.2 86/02/12 */
#endif /* not lint */

#include	"curses.ext"
#include	<ctype.h>

#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))

/*
 *	This routine writes win1 on win2 non-destructively.
 */

int
overlay(WINDOW *win1, WINDOW *win2)
{
	char	*sp, *end;
	int	x, y, endy, endx, starty, startx;
	int 	y1, y2;

#ifdef DEBUG
	fprintf(outf, "OVERLAY(%0.2o, %0.2o);\n", win1, win2);
#endif
	starty = max(win1->_begy, win2->_begy);
	startx = max(win1->_begx, win2->_begx);
	endy = min(win1->_maxy + win1->_begy, win2->_maxy + win2->_begy);
	endx = min(win1->_maxx + win1->_begx, win2->_maxx + win2->_begx);
#ifdef DEBUG
	fprintf(outf, "OVERLAY:from (%d,%d) to (%d,%d)\n",
	    starty, startx, endy, endx);
#endif
	if (starty >= endy || startx >= endx)
		return (OK);
	y1 = starty - win1->_begy;
	y2 = starty - win2->_begy;
	for (y = starty; y < endy; y++, y1++, y2++) {
		end = &win1->_y[y1][endx - win1->_begx];
		x = startx - win2->_begx;
		for (sp = &win1->_y[y1][startx - win1->_begx]; sp < end; sp++) {
			if (!isspace(*sp))
				(void) mvwaddch(win2, y2, x, *sp);
			x++;
		}
	}
	return (OK);
}

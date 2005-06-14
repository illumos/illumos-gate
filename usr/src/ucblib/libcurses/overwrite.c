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
sccsid[] = "@(#)overwrite.c 1.7 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif	/* not lint */

#include	"curses.ext"
#include	<ctype.h>
#include	<string.h>

#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))

/*
 *	This routine writes win1 on win2 destructively.
 */

int
overwrite(WINDOW *win1, WINDOW *win2)
{
	int	x, y, endy, endx, starty, startx;

#ifdef DEBUG
	fprintf(outf, "OVERWRITE(%0.2o, %0.2o);\n", win1, win2);
#endif
	starty = max(win1->_begy, win2->_begy);
	startx = max(win1->_begx, win2->_begx);
	endy = min(win1->_maxy + win1->_begy, win2->_maxy + win2->_begy);
	endx = min(win1->_maxx + win1->_begx, win2->_maxx + win2->_begx);
	if (starty >= endy || startx >= endx)
		return (OK);
#ifdef DEBUG
	fprintf(outf, "OVERWRITE:from (%d,%d) to (%d,%d)\n",
	    starty, startx, endy, endx);
#endif
	x = endx - startx;
	for (y = starty; y < endy; y++) {
		(void) memmove(&win2->_y[y - win2->_begy][startx - win2->_begx],
		    &win1->_y[y - win1->_begy][startx - win1->_begx], x);
		(void) touchline(win2, y, startx - win2->_begx,
		    endx - win2->_begx);
	}
	return (OK);
}

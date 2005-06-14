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
sccsid[] = "@(#)move.c 1.7 88/02/08 SMI"; /* from UCB 5.2 85/10/08 */
#endif	/* not lint */

#include	"curses.ext"

/*
 *	This routine moves the cursor to the given point
 */

int
wmove(WINDOW *win, int y, int x)
{
#ifdef DEBUG
	fprintf(outf, "MOVE to (%d, %d)\n", y, x);
#endif
	if (x < 0 || y < 0)
		return (ERR);
	if (x >= win->_maxx || y >= win->_maxy)
		return (ERR);
	win->_curx = (short)x;
	win->_cury = (short)y;
	return (OK);
}

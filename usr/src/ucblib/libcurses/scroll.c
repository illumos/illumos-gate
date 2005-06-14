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
sccsid[] = "@(#)scroll.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	"curses.ext"

/*
 *	This routine scrolls the window up a line.
 */

int
scroll(WINDOW *win)
{
	int	oy, ox;

#ifdef DEBUG
	fprintf(outf, "SCROLL(%0.2o)\n", win);
#endif

	if (!win->_scroll)
		return (ERR);

	getyx(win, oy, ox);
	(void) wmove(win, 0, 0);
	(void) wdeleteln(win);
	(void) wmove(win, oy, ox);

	if (win == curscr) {
		(void) _putchar('\n');
		if (!NONL)
			win->_curx = 0;
#ifdef DEBUG
		fprintf(outf, "SCROLL: win == curscr\n");
#endif
	}

	return (OK);
}

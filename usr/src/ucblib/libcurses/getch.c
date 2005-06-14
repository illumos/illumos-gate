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
sccsid[] = "@(#)getch.c 1.9 88/02/08 SMI"; /* from UCB 5.3 86/04/16 */
#endif	/* not lint */

#include	"curses.ext"

/*
 *	This routine reads in a character from the window.
 */

int
wgetch(WINDOW *win)
{
	bool	weset = FALSE;
	char	inp;

	if (!win->_scroll && (win->_flags&_FULLWIN) &&
	    win->_curx == win->_maxx - 1 && win->_cury == win->_maxy - 1)
		return (ERR);
#ifdef DEBUG
	fprintf(outf, "WGETCH: _echoit = %c, _rawmode = %c\n",
		_echoit ? 'T' : 'F', _rawmode ? 'T' : 'F');
#endif
	if (_echoit && !_rawmode) {
		cbreak();
		weset++;
	}
	inp = getchar();
#ifdef DEBUG
	fprintf(outf, "WGETCH got '%s'\n", unctrl(inp));
#endif
	if (_echoit) {
		(void) mvwaddch(curscr, win->_cury + win->_begy,
			win->_curx + win->_begx, inp);
		(void) waddch(win, inp);
	}
	if (weset)
		nocbreak();
	return ((int)inp);
}

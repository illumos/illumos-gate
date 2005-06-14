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
sccsid[] = "@(#)addstr.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	"curses.ext"

/*
 *	This routine adds a string starting at (_cury,_curx)
 */

int
waddstr(WINDOW *win, char *str)
{
#ifdef DEBUG
	fprintf(outf, "WADDSTR(\"%s\")\n", str);
#endif
	while (*str)
		if (waddch(win, *str++) == ERR)
			return (ERR);
	return (OK);
}

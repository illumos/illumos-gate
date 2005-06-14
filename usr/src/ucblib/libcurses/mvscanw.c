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
sccsid[] = "@(#)mvscanw.c 1.8 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	<stdarg.h>
#include	"curses.ext"

/*
 * implement the mvscanw commands.  Due to the variable number of
 * arguments, they cannot be macros.  Another sigh....
 */

int
mvscanw(int y, int x, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	return (move(y, x) == OK ? _sscans(stdscr, fmt, ap) : ERR);
}

int
mvwscanw(WINDOW *win, int y, int x, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	return (wmove(win, y, x) == OK ? _sscans(win, fmt, ap) : ERR);
}

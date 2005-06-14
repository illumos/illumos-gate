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
sccsid[] = "@(#)printw.c 1.8 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	<stdarg.h>

/*
 * printw and friends
 *
 */

#include	"curses.ext"

/*
 *	This routine implements a printf on the standard screen.
 */

int
printw(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	return (_sprintw(stdscr, fmt, ap));
}

/*
 *	This routine implements a printf on the given window.
 */

int
wprintw(WINDOW *win, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	return (_sprintw(win, fmt, ap));
}
/*
 *	This routine actually executes the printf and adds it to the window
 *
 *	This code now uses the vsprintf routine, which portably digs
 *	into stdio.  We provide a vsprintf for older systems that don't
 *	have one.
 */

int
_sprintw(WINDOW *win, char *fmt, va_list ap)
{
	char	buf[512];

	(void) vsprintf(buf, fmt, ap);
	return (waddstr(win, buf));
}

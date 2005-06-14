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
sccsid[] = "@(#)scanw.c 1.8 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif	/* not lint */

#include	<stdarg.h>
#include	<string.h>

/*
 * scanw and friends
 */

#include	"curses.ext"

/*
 *	This routine implements a scanf on the standard screen.
 */

int
scanw(char *fmt, ...)
{	int j;
	va_list ap;

	va_start(ap, fmt);
	j = _sscans(stdscr, fmt, ap);
	va_end(ap);
	return (j);
}

/*
 *	This routine implements a scanf on the given window.
 */

int
wscanw(WINDOW *win, char *fmt, ...)
{
	va_list ap;
	int j;

	va_start(ap, fmt);
	j = _sscans(win, fmt, ap);
	va_end(ap);
	return (j);
}
/*
 *	This routine actually executes the scanf from the window.
 *
 *	This is really a modified version of "sscanf".  As such,
 * it assumes that sscanf interfaces with the other scanf functions
 * in a certain way.  If this is not how your system works, you
 * will have to modify this routine to use the interface that your
 * "sscanf" uses.
 */

int
_sscans(WINDOW *win, char *fmt, va_list	ap)
{
	char	buf[100];
	FILE	junk;

	junk._flag = _IOREAD|_IOWRT;
	junk._base = junk._ptr = (unsigned char *)buf;
	if (wgetstr(win, buf) == ERR)
		return (ERR);
	junk._cnt = (ssize_t)strlen(buf);
	return (_doscan(&junk, fmt, ap));
}

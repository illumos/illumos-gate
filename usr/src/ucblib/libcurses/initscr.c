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
sccsid[] = "@(#)initscr.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	"curses.ext"
#include	<term.h>
#include	<stdlib.h>
#include	<signal.h>

/*
 *	This routine initializes the current and standard screen.
 */

WINDOW *
initscr(void)
{
	char	*sp;

#ifdef DEBUG
	fprintf(outf, "INITSCR()\n");
#endif
	if (My_term)
		(void) setterm(Def_term);
	else {
		(void) gettmode();
		if ((sp = getenv("TERM")) == NULL)
			sp = Def_term;
		(void) setterm(sp);
#ifdef DEBUG
		fprintf(outf, "INITSCR: term = %s\n", sp);
#endif
	}
	(void) _puts(TI);
	(void) _puts(VS);
#ifdef SIGTSTP
	(void) signal(SIGTSTP, (void(*)(int))tstp);
#endif
	if (curscr != NULL) {
#ifdef DEBUG
		fprintf(outf, "INITSCR: curscr = 0%o\n", curscr);
#endif
		(void) delwin(curscr);
	}
#ifdef DEBUG
	fprintf(outf, "LINES = %d, COLS = %d\n", LINES, COLS);
#endif
	if ((curscr = newwin(LINES, COLS, 0, 0)) == ERR)
		return (ERR);
	clearok(curscr, TRUE);
	curscr->_flags &= ~_FULLLINE;
	if (stdscr != NULL) {
#ifdef DEBUG
		fprintf(outf, "INITSCR: stdscr = 0%o\n", stdscr);
#endif
		(void) delwin(stdscr);
	}
	stdscr = newwin(LINES, COLS, 0, 0);
	return (stdscr);
}

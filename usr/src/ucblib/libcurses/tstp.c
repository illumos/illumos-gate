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

#ifndef lint
static char
sccsid[] = "@(#)tstp.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

#include	<sys/types.h>
#include	<signal.h>
#include	"curses.ext"
#include	<sgtty.h>

/*
 * handle stop and start signals
 *
 * @(#)tstp.c	5.1 (Berkeley) 6/7/85
 */

void
tstp(void)
{
#ifdef SIGTSTP

	SGTTY	tty;
#ifdef DEBUG
	if (outf)
		(void) fflush(outf);
#endif
	tty = _tty;
	(void) mvcur(0, COLS - 1, LINES - 1, 0);
	(void) endwin();
	(void) fflush(stdout);
	/* reset signal handler so kill below stops us */
	(void) signal(SIGTSTP, SIG_DFL);
	(void) sigsetmask(sigblock(0) &~ sigmask(SIGTSTP));
	(void) kill(0, SIGTSTP);
	(void) sigblock(sigmask(SIGTSTP));
	(void) signal(SIGTSTP, (void(*)(int))tstp);
	_tty = tty;
	(void) stty(_tty_ch, &_tty);
	(void) wrefresh(curscr);
#endif	/* SIGTSTP */
}

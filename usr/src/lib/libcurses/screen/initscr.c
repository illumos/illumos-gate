/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<stdlib.h>
#include	<signal.h>
#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * This routine initializes the current and standard screen,
 * and sets up the terminal.  In case of error, initscr aborts.
 * If you want an error status returned, call
 *	scp = newscreen(getenv("TERM"), 0, 0, 0, stdout, stdin);
 */

WINDOW	*
initscr(void)
{
#ifdef	SIGPOLL
	void	(*savsignal)(int);
	extern	void	_ccleanup(int);
#else	/* SIGPOLL */
	int		(*savsignal)();
	extern	int	_ccleanup(int);
#endif	/* SIGPOLL */

#ifdef	SIGTSTP
	extern	void	_tstp(int);
#endif	/* SIGTSTP */

	static	char	i_called_before = FALSE;

/* Free structures we are about to throw away so we can reuse the memory. */

	if (i_called_before && SP) {
		delscreen(SP);
		SP = NULL;
	}
	if (newscreen(NULL, 0, 0, 0, stdout, stdin) == NULL) {
		(void) reset_shell_mode();
		if (term_errno != -1)
			termerr();
		else
			curserr();
		exit(1);
	}

#ifdef	DEBUG
	if (outf)
		fprintf(outf, "initscr: term = %s\n", SP);
#endif	/* DEBUG */
	i_called_before = TRUE;

#ifdef	SIGTSTP
	/*LINTED*/
	if ((savsignal = signal(SIGTSTP, SIG_IGN)) == SIG_DFL)
		(void) signal(SIGTSTP, _tstp);
	else
		(void) signal(SIGTSTP, savsignal);
#endif	/* SIGTSTP */
	/*LINTED*/
	if ((savsignal = signal(SIGINT, SIG_IGN)) == SIG_DFL)
		(void) signal(SIGINT, _ccleanup);
	else
		(void) signal(SIGINT, savsignal);

	/*LINTED*/
	if ((savsignal = signal(SIGQUIT, SIG_IGN)) == SIG_DFL)
		(void) signal(SIGQUIT, _ccleanup);
	else
		(void) signal(SIGQUIT, savsignal);

	return (stdscr);
}

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

#include	<sys/types.h>
#include	<stdlib.h>
#include	<signal.h>
#include	"curses_inc.h"


/* handle stop and start signals */

#ifdef	SIGTSTP
void
_tstp(int dummy)
{
#ifdef	DEBUG
	if (outf)
		(void) fflush(outf);
#endif	/* DEBUG */
	curscr->_attrs = A_ATTRIBUTES;
	(void) endwin();
	(void) fflush(stdout);
	(void) kill(0, SIGTSTP);
	(void) signal(SIGTSTP, _tstp);
	(void) fixterm();
	/* changed ehr3 SP->doclear = 1; */
	curscr->_clear = TRUE;
	(void) wrefresh(curscr);
}
#endif	/* SIGTSTP */

void
_ccleanup(int signo)
{
	(void) signal(signo, SIG_IGN);

	/*
	 * Fake curses into thinking that all attributes are on so that
	 * endwin will turn them off since the < BREAK > key may have
	 * interrupted the sequence to turn them off.
	 */

	curscr->_attrs = A_ATTRIBUTES;
	(void) endwin();
#ifdef	DEBUG
	fprintf(stderr, "signal %d caught. quitting.\n", signo);
#endif	/* DEBUG */
	if (signo == SIGQUIT)
		(void) abort();
	else
		exit(1);
}

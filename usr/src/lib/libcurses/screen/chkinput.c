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

/*
 * chkinput()
 *
 * Routine to check to see if any input is waiting.
 * It returns a 1 if there is input waiting, and a zero if
 * no input is waiting.
 *
 * This function replaces system calls to ioctl() with the FIONREAD
 * parameter. It enables curses to stop a screen refresh whenever
 * a character is input.
 * Standard BTL UNIX 4.0 or 5.0 does not handle FIONREAD.
 * Changes have been made to 'wrefresh.c' to
 * call this routine as "_inputpending = chkinput()".
 * (delay.c and getch.c also use FIONREAD for nodelay, select and fast peek,
 * but these routines have not been changed).
 *
 * Philip N. Crusius - July 20, 1983
 * Modified to handle various systems March 9, 1984 by Mark Horton.
 */

#include	<unistd.h>
#include	<sys/types.h>
#include	"curses_inc.h"

#ifdef	FIONREAD
#define	HAVE_CHK

int
_chkinput(void)
{
	int	i;

	ioctl(SP->check_fd, FIONREAD, &i);
	return (i > 0);
}
#endif	/* FIONREAD */

#ifdef	SELECT
#ifndef	HAVE_CHK
#define	HAVE_CHK

int
_chkinput(void)
{
	int ifds, ofds, efds, n;
	struct timeval tv;

	ifds = 1 << SP->check_fd;
	ofds = efds = 0;
	tv.tv_sec = tv.t_usec = 0;
	n = select(20, &ifds, &ofds, &efds, &tv);
	return (n > 0);
}
#endif	/* HAVE_CHK */
#endif	/* SELECT */

#ifndef	HAVE_CHK
#ifdef	SYSV

int
_chkinput(void)
{
	unsigned	char	c;	/* character input */

	/*
	 * Only check typeahead if the user is using our input
	 * routines. This is because the read below will put
	 * stuff into the inputQ that will never be read and the
	 * screen will never get updated from now on.
	 * This code should GO AWAY when a poll() or FIONREAD can
	 * be done on the file descriptor as then the check
	 * will be non-destructive.
	 */

	if (!cur_term->fl_typeahdok ||
	    (cur_term->_chars_on_queue == INP_QSIZE) ||
	    (cur_term->_check_fd < 0)) {
		goto bad;
	}

	/* If input is waiting in curses queue, return (TRUE). */

	if ((int)cur_term->_chars_on_queue > 0) {
#ifdef	DEBUG
		if (outf) {
			(void) fprintf(outf, "Found a character on the input "
			    "queue\n");
			_print_queue();
		}
#endif	/* DEBUG */
		goto good;
	}

	if (read(cur_term->_check_fd, (char *)&c, 1) > 0) {
#ifdef	DEBUG
		if (outf) {
			(void) fprintf(outf, "Reading ahead\n");
		}
#endif	/* DEBUG */
		/*
		 * A character was waiting.  Put it at the end
		 * of the curses queue and return 1 to show that
		 * input is waiting.
		 */
#ifdef	DEBUG
		if (outf)
			_print_queue();
#endif	/* DEBUG */
		cur_term->_input_queue[cur_term->_chars_on_queue++] = c;
good:
		return (TRUE);
	} else {
		/* No input was waiting so return 0. */
#ifdef	DEBUG
		if (outf)
			(void) fprintf(outf, "No input waiting\n");
#endif	/* DEBUG */
bad:
		return (FALSE);
	}
}
#else	/* SYSV */
int
_chkinput()
{
	return (FALSE);
}
#endif	/* SYSV */
#endif	/* HAVE_CHK */

#ifdef	DEBUG
void
_print_queue()	/* FOR DEBUG ONLY */
{
	int		i, j = cur_term->_chars_on_queue;
	chtype		*inputQ = cur_term->_input_queue;

	if (outf)
		for (i = 0; i < j; i++)
			(void) fprintf(outf, "inputQ[%d] = %c\n", i, inputQ[i]);
}
#endif	/* DEBUG */

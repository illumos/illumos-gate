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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

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

/*
 * this file contains the I/O handling and the exchange of
 * edit characters. This connection itself is established in ctl.c
 */

#include "talk.h"
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/filio.h>
#include <libintl.h>

#define	A_LONG_TIME 10000000
#define	STDIN_MASK (1<<fileno(stdin))	/* the bit mask for standard input */

/*
 * The routine to do the actual talking
 */

void
talk()
{
	int read_template, sockt_mask;
	int read_set, nb;
	char buf[BUFSIZ];
	struct timeval wait;

	message(gettext("Connection established"));
	beep(); beep(); beep();
	current_line = 0;

	sockt_mask = (1<<sockt);

	/*
	 * wait on both the other process (sockt_mask) and
	 * standard input ( STDIN_MASK )
	 */

	read_template = sockt_mask | STDIN_MASK;

	forever {

		read_set = read_template;

		wait.tv_sec = A_LONG_TIME;
		wait.tv_usec = 0;

		nb = select(32, (fd_set *)&read_set, 0, 0, &wait);

		if (nb <= 0) {

			/* We may be returning from an interrupt handler */

			if (errno == EINTR) {
				read_set = read_template;
				continue;
			} else {
				/* panic, we don't know what happened */
				p_error(
				gettext("Unexpected error from select"));
				quit();
			}
		}

		if (read_set & sockt_mask) {

			/* There is data on sockt */
			nb = read(sockt, buf, sizeof (buf));

			if (nb <= 0) {
				message(gettext("Connection closed. Exiting"));
				pause();	/* wait for Ctrl-C */
				quit();
			} else {
				display(&rem_win, buf, nb);
			}
		}

		if (read_set & STDIN_MASK) {

			/*
			 * we can't make the tty non_blocking, because
			 * curses's output routines would screw up
			 */

			ioctl(0, FIONREAD, (struct sgttyb *)&nb);
			nb = read(0, buf, nb);
			display(&my_win, buf, nb);
			write(sockt, buf, nb);

			/*
			 * We might lose data here because sockt is
			 * non-blocking
			 */
		}
	}
}


/*
 * p_error prints the system error message on the standard location
 * on the screen and then exits. (i.e. a curses version of perror)
 */

void
p_error(char *string)
{
	wmove(my_win.x_win, current_line%my_win.x_nlines, 0);
	wprintw(my_win.x_win, "[%s : %s]\n", string, strerror(errno));
	wrefresh(my_win.x_win);
	move(LINES-1, 0);
	refresh();
	quit();
}

/* display string in the standard location */

void
message(char *string)
{
	wmove(my_win.x_win, current_line%my_win.x_nlines, 0);
	wprintw(my_win.x_win, "[%s]\n", string);
	wrefresh(my_win.x_win);
}

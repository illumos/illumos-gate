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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
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
 * init_disp contains the initialization code for the display package,
 * as well as the signal handling routines
 */

#include "talk.h"
#include <signal.h>
#include <libintl.h>

#ifdef SYSV
#define	signal(s, f)	sigset(s, f)
#endif /* SYSV */

static void sig_sent();

/*
 * set up curses, catch the appropriate signals, and build the
 * various windows
 */

void
init_display()
{
	initscr();
	curses_initialized = 1;

	clear();
	refresh();

	noecho();
	crmode();

	signal(SIGINT, sig_sent);
	signal(SIGPIPE, sig_sent);

	/* curses takes care of ^Z */

	my_win.x_nlines = LINES / 2;
	my_win.x_ncols = COLS;
	my_win.x_win = newwin(my_win.x_nlines, my_win.x_ncols, 0, 0);
	scrollok(my_win.x_win, FALSE);
	wclear(my_win.x_win);

	rem_win.x_nlines = LINES / 2 - 1;
	rem_win.x_ncols = COLS;
	rem_win.x_win = newwin(rem_win.x_nlines, rem_win.x_ncols,
						my_win.x_nlines+1, 0);
	scrollok(rem_win.x_win, FALSE);
	wclear(rem_win.x_win);

	line_win = newwin(1, COLS, my_win.x_nlines, 0);
	box(line_win, '-', '-');
	wrefresh(line_win);

	/* let them know we are working on it */

	current_state = gettext("No connection yet");
}

	/*
	 * trade edit characters with the other talk. By agreement
	 * the first three characters each talk transmits after
	 * connection are the three edit characters
	 */

void
set_edit_chars()
{
	char buf[3];
	int cc;
#ifdef SYSV
	struct termios tty;
	ioctl(0, TCGETS, (struct termios *)&tty);

	buf[0] = my_win.cerase = tty.c_cc[VERASE];
					/* for SVID should be VERSE */
	buf[1] = my_win.kill = tty.c_cc[VKILL];
	buf[2] = my_win.werase = tty.c_cc[VWERASE];
					/* for SVID should be VWERSE */
#else /* ! SYSV */
	struct sgttyb tty;
	struct ltchars ltc;

	gtty(0, &tty);

	ioctl(0, TIOCGLTC, (struct sgttyb *)&ltc);

	my_win.cerase = tty.sg_erase;
	my_win.kill = tty.sg_kill;

	if (ltc.t_werasc == (char)-1) {
		my_win.werase = '\027';	 /* control W */
	} else {
		my_win.werase = ltc.t_werasc;
	}

	buf[0] = my_win.cerase;
	buf[1] = my_win.kill;
	buf[2] = my_win.werase;
#endif /* SYSV */

	cc = write(sockt, buf, sizeof (buf));

	if (cc != sizeof (buf)) {
		p_error(gettext("Lost the connection"));
	}

	cc = read(sockt, buf, sizeof (buf));

	if (cc != sizeof (buf)) {
		p_error(gettext("Lost the connection"));
	}

	rem_win.cerase = buf[0];
	rem_win.kill = buf[1];
	rem_win.werase = buf[2];
}

static void
sig_sent()
{
	message(gettext("Connection closing. Exiting"));
	quit();
}

/*
 * All done talking...hang up the phone and reset terminal thingy's
 */

void
quit()
{
	if (curses_initialized) {
		wmove(rem_win.x_win, rem_win.x_nlines-1, 0);
		wclrtoeol(rem_win.x_win);
		wrefresh(rem_win.x_win);
		endwin();
	}

	if (invitation_waiting) {
		send_delete();
	}

	exit(0);
}

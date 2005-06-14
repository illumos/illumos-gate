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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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
 * The window 'manager', initializes curses and handles the actual
 * displaying of text
 */

#include "talk.h"
#include <ctype.h>

static int readwin(WINDOW *, int, int);
static void xscroll(register xwin_t *, int);

xwin_t my_win;
xwin_t rem_win;
WINDOW *line_win;

int curses_initialized = 0;

/*
 * max HAS to be a function, it is called with
 * a argument of the form --foo at least once.
 */

static int
max(a, b)
int a, b;
{
	if (a > b) {
	return (a);
	} else {
	return (b);
	}
}

/*
 * Display some text on somebody's window, processing some control
 * characters while we are at it.
 */

int
display(win, text, size)
register xwin_t *win;
register char *text;
int size;
{
	register int i;
	int mb_cur_max = MB_CUR_MAX;

	for (i = 0; i < size; i++) {
	int itext;

	if (*text == '\n'|| *text == '\r') {
		xscroll(win, 0);
		text++;
		continue;
	}

		/* erase character */

	if (*text == win->cerase) {
		wmove(win->x_win, win->x_line, max(--win->x_col, 0));
		getyx(win->x_win, win->x_line, win->x_col);
		waddch(win->x_win, ' ');
		wmove(win->x_win, win->x_line, win->x_col);
		getyx(win->x_win, win->x_line, win->x_col);
		text++;
		continue;
	}
	/*
	 * On word erase search backwards until we find
	 * the beginning of a word or the beginning of
	 * the line.
	 */
	if (*text == win->werase) {
		int endcol, xcol, i, c;

		endcol = win->x_col;
		xcol = endcol - 1;
		while (xcol >= 0) {
		c = readwin(win->x_win, win->x_line, xcol);
		if (c != ' ')
			break;
		xcol--;
		}
		while (xcol >= 0) {
		c = readwin(win->x_win, win->x_line, xcol);
		if (c == ' ')
			break;
		xcol--;
		}
		wmove(win->x_win, win->x_line, xcol + 1);
		for (i = xcol + 1; i < endcol; i++)
		waddch(win->x_win, ' ');
		wmove(win->x_win, win->x_line, xcol + 1);
		getyx(win->x_win, win->x_line, win->x_col);
		continue;
	}
		/* line kill */
	if (*text == win->kill) {
		wmove(win->x_win, win->x_line, 0);
		wclrtoeol(win->x_win);
		getyx(win->x_win, win->x_line, win->x_col);
		text++;
		continue;
	}
	if (*text == '\f') {
		if (win == &my_win)
		wrefresh(curscr);
		text++;
		continue;
	}
	/* EOF character */
	if (*text == '\004') {
		quit();
	}

	/* typing alert character will alert recipient's terminal */

	if (*text == '\007') {
		beep();
		continue;
	}

	/* check for wrap around */
	if (win->x_col == COLS-1) {
		xscroll(win, 0);
	}

	/*
	 * Handle the multibyte case
	 * We print '?' for nonprintable widechars.
	 */

	if (mb_cur_max > 1 && mblen(text, mb_cur_max) > 1) {
		wchar_t wc;
		int len;

		len = mbtowc(&wc, text, mb_cur_max);

		if (iswprint(wc) || iswspace(wc)) {
		/* its printable, put out the bytes */
			do {
				if (win->x_col == COLS-1) /* wraparound */
					xscroll(win, 0);
				waddch(win->x_win, *text++);
				getyx(win->x_win, win->x_line, win->x_col);
			} while (--len > 0);
			continue;
		}
		/*
		 * otherwise, punt and print a question mark.
		 */
		text += len;
		waddch(win->x_win, '?');
		getyx(win->x_win, win->x_line, win->x_col);
		continue;
	}

	itext = (unsigned int) *text;
	if (isprint(itext) || *text == ' ' || *text == '\t' ||
		*text == '\013' || *text == '\007' /* bell */) {
		waddch(win->x_win, *text);
	} else {

		if (!isascii(*text)) {
			/* check for wrap around */
			if (win->x_col == COLS-3) {
				xscroll(win, 0);
			}
			waddch(win->x_win, 'M');
			waddch(win->x_win, '-');
			*text = toascii(*text);
		}
		if (iscntrl(*text)) {

			/* check for wrap around */
			getyx(win->x_win, win->x_line, win->x_col);
			if (win->x_col == COLS-2) {
				xscroll(win, 0);
			}

			waddch(win->x_win, '^');
			waddch(win->x_win, *text + 0100);
		}
		else
			waddch(win->x_win, *text);
	}

	getyx(win->x_win, win->x_line, win->x_col);
	text++;

	}  /* for loop */
	wrefresh(win->x_win);
	return (0);
}

/*
 * Read the character at the indicated position in win
 */

static int
readwin(win, line, col)
WINDOW *win;
int line, col;
{
int oldline, oldcol;
register int c;

	getyx(win, oldline, oldcol);
	wmove(win, line, col);
	c = winch(win);
	wmove(win, oldline, oldcol);
	return (c);
}

/*
 * Scroll a window, blanking out the line following the current line
 * so that the current position is obvious
 */

static void
xscroll(win, flag)
register xwin_t *win;
int flag;
{
	if (flag == -1) {
		wmove(win->x_win, 0, 0);
		win->x_line = 0;
		win->x_col = 0;
		return;
	}
	win->x_line = (win->x_line + 1) % win->x_nlines;
	win->x_col = 0;
	wmove(win->x_win, win->x_line, win->x_col);
	wclrtoeol(win->x_win);
	wmove(win->x_win, (win->x_line + 1) % win->x_nlines, win->x_col);
	wclrtoeol(win->x_win);
	wmove(win->x_win, win->x_line, win->x_col);
}

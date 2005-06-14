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
#include	"curses_inc.h"

#define		LENGTH	256

/* This routine gets a string starting at (_cury, _curx) */

int
wgetstr(WINDOW *win, char *str)
{
	return ((wgetnstr(win, str, LENGTH) == ERR) ? ERR : OK);
}

int
wgetnstr(WINDOW *win, char *str, int n)
{
	int	cpos = 0, ch;
	int	nbyte = 0;
	int	tbyte = 0;
	int	byte[LENGTH];
	int	eucw, scrw;
	int	docont = 0;
	char	*cp = str;
	int	i = 0;
	int	total = 0;
	char	myerase, mykill;
	char	rownum[LENGTH], colnum[LENGTH], length[LENGTH];
	int	doecho = SP->fl_echoit;
	int	savecb = cur_term->_fl_rawmode;
	bool	savsync, savimmed, savleave;

#ifdef	DEBUG
	if (outf)
		fprintf(outf, "doecho %d, savecb %d\n", doecho, savecb);
#endif	/* DEBUG */

	myerase = erasechar();
	mykill = killchar();
	if (!savecb)
		(void) cbreak();

	if (doecho) {
		SP->fl_echoit = FALSE;
		savsync = win->_sync;
		savimmed = win->_immed;
		savleave = win->_leave;
		win->_immed = win->_sync = win->_leave = FALSE;
		(void) wrefresh(win);
		if (n > LENGTH)
			n = LENGTH;
	}
	n--;

	while (nbyte < n) {
		if (doecho && !docont) {
			rownum[cpos] = win->_cury;
			colnum[cpos] = win->_curx;
		}

		ch = wgetch(win);
		if (docont)
			goto cont;

		if ((ch == ERR) || (ch == '\n') || (ch == '\r') ||
		    (ch == KEY_ENTER))
			break;
		if ((ch == myerase) || (ch == KEY_LEFT) ||
		    (ch == KEY_BACKSPACE) || (ch == mykill)) {
			if (cpos > 0) {
				if (ch == mykill) {
					i = total;
					total = cpos = 0;
					nbyte = 0;
					cp = str;
				} else {
					cpos--;
					cp -= byte[cpos];
					if (doecho)
						total -= (i = length[cpos]);
				}
				if (doecho) {
					(void) wmove(win, rownum[cpos],
					    colnum[cpos]);
					/* Add the correct amount of blanks. */
					for (; i > 0; i--)
						(void) waddch(win, ' ');
					/* Move back after the blanks are */
					/* put in. */
					(void) wmove(win, rownum[cpos],
					    colnum[cpos]);
					/* Update total. */
					(void) wrefresh(win);
				}
			} else
				if (doecho)
					(void) beep();
		} else if ((KEY_MIN <= ch) && (ch <= KEY_MAX))
				(void) beep();
			else {
cont:
				/* LINTED */
				*cp++ = (char)ch;
				if (docont) {
					tbyte++;
				} else if (ISMBIT(ch)) {
					docont = 1;
					tbyte = 1;
					scrw = mbscrw(ch);
					eucw = mbeucw(ch);
				}

				if (docont && (tbyte >= eucw)) {
					docont = 0;
					tbyte = 0;
					if (doecho) {
						byte[cpos] = eucw;
						/* LINTED */
						length[cpos] = (char)scrw;
						(void) wechochar(win,
						    (chtype) ch);
					}
				} else if (doecho) {
					/* Add the length of the */
					/* character to total. */
					byte[cpos] = 1;
					if (ch >= ' ')
						length[cpos] = 1;
					else
						if (ch == '\t')
							length[cpos] = TABSIZE-
							    (colnum[cpos] %
							    TABSIZE);
						else
							length[cpos] = 2;
					total += length[cpos];
					(void) wechochar(win, (chtype) ch);
				}
				if (!docont)
					cpos++;
				nbyte++;
			}
	}

	*cp = '\0';

	if (!savecb)
		(void) nocbreak();
	/*
	 * The following code is equivalent to waddch(win, '\n')
	 * except that it does not do a wclrtoeol.
	 */
	if (doecho) {
		SP->fl_echoit = TRUE;
		win->_curx = 0;
		if (win->_cury + 1 > win->_bmarg)
			(void) wscrl(win, 1);
		else
			win->_cury++;

		win->_sync = savsync;
		win->_immed = savimmed;
		win->_leave = savleave;
		(void) wrefresh(win);
	}
	return (ch);
}

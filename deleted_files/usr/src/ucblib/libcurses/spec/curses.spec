#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#

function	initscr
include		<curses.h>
declaration	WINDOW *initscr(void)
version		SUNW_1.1
end

function	newwin
include		<curses.h>
declaration	WINDOW *newwin(int nlines, int ncols, int begin_y, int begin_x)
version		SUNW_1.1
end

function	subwin
include		<curses.h>
declaration	WINDOW *subwin(WINDOW *orig, int nlines, int ncols, \
			int begin_y, int begin_x)
version		SUNW_1.1
end

function	longname
include		<curses.h>
declaration	char *longname(char *bp, char *def)
version		SUNW_1.1
end

function	getcap
include		<curses.h>
declaration	char *getcap(char *name)
version		SUNW_1.1
end

function	gettmode
include		<curses.h>
declaration	int gettmode(void)
version		SUNW_1.1
end

function	idlok
include		<curses.h>
declaration	int idlok(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	wstandout
include		<curses.h>
declaration	char *wstandout(WINDOW *win)
version		SUNW_1.1
end

function	wstandend
include		<curses.h>
declaration	char *wstandend(WINDOW *win)
version		SUNW_1.1
end

function	box
include		<curses.h>
declaration	int box(WINDOW *win, char vert, char hor)
version		SUNW_1.1
end

function	touchwin
include		<curses.h>
declaration	int touchwin(WINDOW *win)
version		SUNW_1.1
end

function	touchline
include		<curses.h>
declaration	int touchline(WINDOW *win, int y, int sx, int ex)
version		SUNW_1.1
end

function	mvcur
include		<curses.h>
declaration	int mvcur(int ly, int lx, int y, int x)
version		SUNW_1.1
end

function	wmove
include		<curses.h>
declaration	int wmove(WINDOW *win, int y, int x)
version		SUNW_1.1
end

function	scroll
include		<curses.h>
declaration	int scroll(WINDOW *win)
version		SUNW_1.1
end

function	werase
include		<curses.h>
declaration	int werase(WINDOW *win)
version		SUNW_1.1
end

function	wrefresh
include		<curses.h>
declaration	int wrefresh(WINDOW *win)
version		SUNW_1.1
end

function	endwin
include		<curses.h>
declaration	int endwin(void)
version		SUNW_1.1
end

function	mvwin
include		<curses.h>
declaration	int mvwin(WINDOW *win, int by, int bx)
version		SUNW_1.1
end

function	delwin
include		<curses.h>
declaration	int delwin(WINDOW *win)
version		SUNW_1.1
end

function	overlay
include		<curses.h>
declaration	int overlay(WINDOW *win1, WINDOW *win2)
version		SUNW_1.1
end

function	overwrite
include		<curses.h>
declaration	int overwrite(WINDOW *win1, WINDOW *win2)
version		SUNW_1.1
end

function	winsertln
include		<curses.h>
declaration	int winsertln(WINDOW *win)
version		SUNW_1.1
end

function	wdeleteln
include		<curses.h>
declaration	int wdeleteln(WINDOW *win)
version		SUNW_1.1
end

function	wgetstr
include		<curses.h>
declaration	int wgetstr(WINDOW *win, char *str)
version		SUNW_1.1
end

function	wgetch
include		<curses.h>
declaration	int wgetch(WINDOW *win)
version		SUNW_1.1
end

function	waddch
include		<curses.h>
declaration	int waddch(WINDOW *win, char c)
version		SUNW_1.1
end

function	waddstr
include		<curses.h>
declaration	int waddstr(WINDOW *win, char *str)
version		SUNW_1.1
end

function	winsch
include		<curses.h>
declaration	int winsch(WINDOW *win, char c)
version		SUNW_1.1
end

function	wdelch
include		<curses.h>
declaration	int wdelch(WINDOW *win)
version		SUNW_1.1
end

function	wclear
include		<curses.h>
declaration	int wclear(WINDOW *win)
version		SUNW_1.1
end

function	wclrtobot
include		<curses.h>
declaration	int wclrtobot(WINDOW *win)
version		SUNW_1.1
end

function	wclrtoeol
include		<curses.h>
declaration	int wclrtoeol(WINDOW *win)
version		SUNW_1.1
end

function	printw
include		<curses.h>
declaration	int printw(char *fmt, ...)
version		SUNW_1.1
end

function	wprintw
include		<curses.h>
declaration	int wprintw(WINDOW *win, char *fmt, ...)
version		SUNW_1.1
end

function	mvprintw
include		<curses.h>
declaration	int mvprintw(int y, int x, char *fmt, ...)
version		SUNW_1.1
end

function	mvwprintw
include		<curses.h>
declaration	int mvwprintw(WINDOW *win, int y, int x, char *fmt, ...)
version		SUNW_1.1
end

function	scanw
include		<curses.h>
declaration	int scanw(char *fmt, ...)
version		SUNW_1.1
end

function	wscanw
include		<curses.h>
declaration	int wscanw(WINDOW *win, char *fmt, ...)
version		SUNW_1.1
end

function	mvscanw
include		<curses.h>
declaration	int mvscanw(int y, int x, char *fmt, ...)
version		SUNW_1.1
end

function	mvwscanw
include		<curses.h>
declaration	int mvwscanw(WINDOW *win, int y, int x, char *fmt, ...)
version		SUNW_1.1
end

function	setterm
include		<curses.h>
declaration	int setterm(char *type)
version		SUNW_1.1
end

data		_unctrl
version		SUNW_1.1
end

data		My_term
version		SUNW_1.1
end

data		_echoit
version		SUNW_1.1
end

data		_rawmode
version		SUNW_1.1
end

data		_endwin
version		SUNW_1.1
end

data		LINES
version		SUNW_1.1
end

data		COLS
version		SUNW_1.1
end

data		_tty_ch
version		SUNW_1.1
end

data		_res_flg
version		SUNW_1.1
end

data		_tty
version		SUNW_1.1
end

data		stdscr
version		SUNW_1.1
end

data		curscr
version		SUNW_1.1
end

data		Def_term
version		SUNW_1.1
end

data		ttytype
version		SUNW_1.1
end

# termcap capabilities (bool)
data		AM
version		SUNW_1.1
end

data		BS
version		SUNW_1.1
end

data		CA
version		SUNW_1.1
end

data		DA
version		SUNW_1.1
end

data		DB
version		SUNW_1.1
end

data		EO
version		SUNW_1.1
end

data		HC
version		SUNW_1.1
end

data		HZ
version		SUNW_1.1
end

data		IN
version		SUNW_1.1
end

data		MI
version		SUNW_1.1
end

data		MS
version		SUNW_1.1
end

data		NC
version		SUNW_1.1
end

data		NS
version		SUNW_1.1
end

data		OS
version		SUNW_1.1
end

data		UL
version		SUNW_1.1
end

data		XB
version		SUNW_1.1
end

data		XN
version		SUNW_1.1
end

data		XT
version		SUNW_1.1
end

data		XS
version		SUNW_1.1
end

data		XX
version		SUNW_1.1
end

# termcap capabilities (char *)
data		AL
version		SUNW_1.1
end

data		BC
version		SUNW_1.1
end

data		BT
version		SUNW_1.1
end

data		CD
version		SUNW_1.1
end

data		CE
version		SUNW_1.1
end

data		CL
version		SUNW_1.1
end

data		CM
version		SUNW_1.1
end

data		CR
version		SUNW_1.1
end

data		CS
version		SUNW_1.1
end

data		DC
version		SUNW_1.1
end

data		DL
version		SUNW_1.1
end

data		DM
version		SUNW_1.1
end

data		DO
version		SUNW_1.1
end

data		ED
version		SUNW_1.1
end

data		EI
version		SUNW_1.1
end

data		K0
version		SUNW_1.1
end

data		K1
version		SUNW_1.1
end

data		K2
version		SUNW_1.1
end

data		K3
version		SUNW_1.1
end

data		K4
version		SUNW_1.1
end

data		K5
version		SUNW_1.1
end

data		K6
version		SUNW_1.1
end

data		K7
version		SUNW_1.1
end

data		K8
version		SUNW_1.1
end

data		K9
version		SUNW_1.1
end

data		HO
version		SUNW_1.1
end

data		IC
version		SUNW_1.1
end

data		IM
version		SUNW_1.1
end

data		IP
version		SUNW_1.1
end

data		KD
version		SUNW_1.1
end

data		KE
version		SUNW_1.1
end

data		KH
version		SUNW_1.1
end

data		KL
version		SUNW_1.1
end

data		KR
version		SUNW_1.1
end

data		KS
version		SUNW_1.1
end

data		KU
version		SUNW_1.1
end

data		LL
version		SUNW_1.1
end

data		MA
version		SUNW_1.1
end

data		ND
version		SUNW_1.1
end

data		NL
version		SUNW_1.1
end

data		RC
version		SUNW_1.1
end

data		SC
version		SUNW_1.1
end

data		SE
version		SUNW_1.1
end

data		SF
version		SUNW_1.1
end

data		SO
version		SUNW_1.1
end

data		SR
version		SUNW_1.1
end

data		TA
version		SUNW_1.1
end

data		TE
version		SUNW_1.1
end

data		TI
version		SUNW_1.1
end

data		UC
version		SUNW_1.1
end

data		UE
version		SUNW_1.1
end

data		UP
version		SUNW_1.1
end

data		US
version		SUNW_1.1
end

data		VB
version		SUNW_1.1
end

data		VS
version		SUNW_1.1
end

data		VE
version		SUNW_1.1
end

data		AL_PARM
version		SUNW_1.1
end

data		DL_PARM
version		SUNW_1.1
end

data		UP_PARM
version		SUNW_1.1
end

data		DOWN_PARM
version		SUNW_1.1
end

data		LEFT_PARM
version		SUNW_1.1
end

data		RIGHT_PARM
version		SUNW_1.1
end

data		PC
version		SUNW_1.1
end

# for tty modes
data		GT
version		SUNW_1.1
end

data		NONL
version		SUNW_1.1
end

data		UPPERCASE
version		SUNW_1.1
end

data		normtty
version		SUNW_1.1
end

data		_pfast
version		SUNW_1.1
end

function	_putchar
version		SUNWprivate_1.1
end

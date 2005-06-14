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
# lib/libxcurses/spec/xcurses.spec

data		COLORS
version		SUNW_1.2
end		

data		COLOR_PAIRS
version		SUNW_1.2
end		

data		COLS
version		SUNW_1.2
end		

data		LINES
version		SUNW_1.2
end		

data		cur_term
version		SUNW_1.2
end		

data		stdscr
version		SUNW_1.2
end		

data		curscr
version		SUNW_1.2
end		

function	putp
include		<curses.h>
declaration	int putp(const char *str)
version		SUNW_1.2
end		

function	tparm
include		<term.h>
declaration	char *tparm(char *cap, long p1, long p2, \
		    long p3, long p4, long p5, long p6, long p7, \
		    long p8, long p9)
version		SUNW_1.2
end		

function	tputs
include		<curses.h>
declaration	int tputs(const char *str, int affcnt, int (*putfunc) (int))
version		SUNW_1.2
end		

function	add_wchstr
version		SUNW_1.2
end

function	mvget_wstr
version		SUNW_1.2
end

function	COLOR_PAIR
include		<curses.h>
declaration	int COLOR_PAIR(int n);
version		SUNW_1.1
end		

function	PAIR_NUMBER
include		<curses.h>
declaration	int PAIR_NUMBER(int value)
version		SUNW_1.1
end		

function	add_wch
include		<curses.h>
declaration	int add_wch(const cchar_t *wch)
version		SUNW_1.1
end		

function	add_wchnstr
include		<curses.h>
declaration	int add_wchnstr(const cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	addch
include		<curses.h>
declaration	int addch(const chtype ch)
version		SUNW_1.1
end		

function	addchnstr
include		<curses.h>
declaration	int addchnstr(const chtype *chstr, int n)
version		SUNW_1.1
end		

function	addchstr
include		<curses.h>
declaration	int addchstr(const chtype *chstr)
version		SUNW_1.1
end		

function	addnstr
include		<curses.h>
declaration	int addnstr(const char *str, int n)
version		SUNW_1.1
end		

function	addnwstr
include		<curses.h>
declaration	int addnwstr(const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	addstr
include		<curses.h>
declaration	int addstr(const char *str)
version		SUNW_1.1
end		

function	addwstr
include		<curses.h>
declaration	int addwstr(const wchar_t *wstr)
version		SUNW_1.1
end		

function	attr_get
include		<curses.h>
declaration	int attr_get(attr_t *attrs, short *color, void *opts)
version		SUNW_1.1
end		

function	attr_on
include		<curses.h>
declaration	int attr_on(attr_t attrs, void *opts)
version		SUNW_1.1
end		

function	attr_off
include		<curses.h>
declaration	int attr_off(attr_t attrs, void *opts)
version		SUNW_1.1
end		

function	attr_set
include		<curses.h>
declaration	int attr_set(attr_t attrs, short color, void *opts)
version		SUNW_1.1
end		

function	attron
include		<curses.h>
declaration	int attron(int attrs)
version		SUNW_1.1
end		

function	attroff
include		<curses.h>
declaration	int attroff(int attrs)
version		SUNW_1.1
end		

function	attrset
include		<curses.h>
declaration	int attrset(int attrs)
version		SUNW_1.1
end		

function	baudrate
include		<curses.h>
declaration	int baudrate(void)
version		SUNW_1.1
end		

function	beep
include		<curses.h>
declaration	int beep(void);
version		SUNW_1.1
end		

function	bkgd
include		<curses.h>
declaration	int bkgd(chtype ch)
version		SUNW_1.1
end		

function	bkgdset
include		<curses.h>
declaration	void bkgdset(chtype ch)
version		SUNW_1.1
end		

function	bkgrnd
include		<curses.h>
declaration	int bkgrnd(const cchar_t *wch)
version		SUNW_1.1
end		

function	bkgrndset
include		<curses.h>
declaration	void bkgrndset(const cchar_t *wch)
version		SUNW_1.1
end		

function	border
include		<curses.h>
declaration	int border(chtype ls, chtype rs, chtype ts, chtype bs, \
		    chtype tl, chtype tr, chtype bl, chtype br)
version		SUNW_1.1
end		

function	border_set
include		<curses.h>
declaration	int border_set(const cchar_t *ls, const cchar_t *rs, \
		    const cchar_t *ts, const cchar_t *bs, const cchar_t *tl, \
		    const cchar_t *tr, const cchar_t *bl, const cchar_t *br)
version		SUNW_1.1
end		

function	box
include		<curses.h>
declaration	int box(WINDOW *win, chtype verch, chtype horch)
version		SUNW_1.1
end		

function	box_set
include		<curses.h>
declaration	int box_set(WINDOW *win, const cchar_t *verch, \
		    const cchar_t *horch)
version		SUNW_1.1
end		

function	can_change_color
include		<curses.h>
declaration	bool can_change_color(void)
version		SUNW_1.1
end		

function	cbreak
include		<curses.h>
declaration	int cbreak(void)
version		SUNW_1.1
end		

function	chgat
include		<curses.h>
declaration	int chgat(int n, attr_t attr, short color, const void *opts)
version		SUNW_1.1
end		

function	clear
include		<curses.h>
declaration	int clear(void)
version		SUNW_1.1
end		

function	clearok
include		<curses.h>
declaration	int clearok(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	clrtobot
include		<curses.h>
declaration	int clrtobot(void)
version		SUNW_1.1
end		

function	clrtoeol
include		<curses.h>
declaration	int clrtoeol(void)
version		SUNW_1.1
end		

function	color_content
include		<curses.h>
declaration	int color_content(short color, short *red, short *green, \
		    short *blue)
version		SUNW_1.1
end		

function	color_set
include		<curses.h>
declaration	int color_set(short color, void *opts)
version		SUNW_1.1
end		

function	copywin
include		<curses.h>
declaration	int copywin(const WINDOW *srcwin, WINDOW *dstwin, \
		    int sminrow, int smincol, int dminrow, int dmincol, \
		    int dmaxrow, int dmaxcol, int overlay)
version		SUNW_1.1
end		

function	curs_set
include		<curses.h>
declaration	int curs_set(int visibility)
version		SUNW_1.1
end		

function	def_shell_mode
include		<curses.h>
declaration	int def_shell_mode(void)
version		SUNW_1.1
end		

function	def_prog_mode
include		<curses.h>
declaration	int def_prog_mode(void)
version		SUNW_1.1
end		

function	del_curterm
include		<term.h>
declaration	int del_curterm(TERMINAL *oterm)
version		SUNW_1.1
end		

function	delay_output
include		<curses.h>
declaration	int delay_output(int ms)
version		SUNW_1.1
end		

function	delch
include		<curses.h>
declaration	int delch(void)
version		SUNW_1.1
end		

function	deleteln
include		<curses.h>
declaration	int deleteln(void)
version		SUNW_1.1
end		

function	delscreen
include		<curses.h>
declaration	void delscreen(SCREEN *sp)
version		SUNW_1.1
end		

function	delwin
include		<curses.h>
declaration	int delwin(WINDOW *win)
version		SUNW_1.1
end		

function	derwin
include		<curses.h>
declaration	WINDOW *derwin(WINDOW *orig, int nlines, int ncols, \
		    int begin_y, int begin_x)
version		SUNW_1.1
end		

function	doupdate
include		<curses.h>
declaration	int doupdate(void)
version		SUNW_1.1
end		

function	dupwin
include		<curses.h>
declaration	WINDOW *dupwin(WINDOW *win)
version		SUNW_1.1
end		

function	echo
include		<curses.h>
declaration	int echo(void)
version		SUNW_1.1
end		

function	echo_wchar
include		<curses.h>
declaration	int echo_wchar(const cchar_t *wch)
version		SUNW_1.1
end		

function	echochar
include		<curses.h>
declaration	int echochar(const chtype ch)
version		SUNW_1.1
end		

function	endwin
include		<curses.h>
declaration	int endwin(void)
version		SUNW_1.1
end		

function	erase
include		<curses.h>
declaration	int erase(void)
version		SUNW_1.1
end		

function	erasechar
include		<curses.h>
declaration	char erasechar(void)
version		SUNW_1.1
end		

function	erasewchar
include		<curses.h>
declaration	int erasewchar(wchar_t *ch)
version		SUNW_1.1
end		

function	filter
include		<curses.h>
declaration	void filter(void)
version		SUNW_1.1
end		

function	flash
include		<curses.h>
declaration	int flash(void)
version		SUNW_1.1
end		

function	flushinp
include		<curses.h>
declaration	int flushinp(void)
version		SUNW_1.1
end		

function	get_wch
include		<curses.h>
declaration	int get_wch(wint_t *ch)
version		SUNW_1.1
end		

function	get_wstr
include		<curses.h>
declaration	int get_wstr(wint_t *wstr)
version		SUNW_1.1
end		

function	getbkgd
include		<curses.h>
declaration	chtype getbkgd(WINDOW *win)
version		SUNW_1.1
end		

function	getbkgrnd
include		<curses.h>
declaration	int getbkgrnd(cchar_t *wch)
version		SUNW_1.1
end		

function	getcchar
include		<curses.h>
declaration	int getcchar(const cchar_t *wcval, wchar_t *wch, \
		    attr_t *attrs, short *color_pair, void *opt)
version		SUNW_1.1
end		

function	getch
include		<curses.h>
declaration	int getch(void)
version		SUNW_1.1
end		

function	getn_wstr
include		<curses.h>
declaration	int  getn_wstr(wint_t  *wstr,  int n)
version		SUNW_1.1
end		

function	getnstr
include		<curses.h>
declaration	int getnstr(char *str, int n)
version		SUNW_1.1
end		

function	getstr
include		<curses.h>
declaration	int getstr(char *str)
version		SUNW_1.1
end		

function	getwin
include		<curses.h>
declaration	WINDOW *getwin(FILE *filep)
version		SUNW_1.1
end		

function	halfdelay
include		<curses.h>
declaration	int halfdelay(int tenths)
version		SUNW_1.1
end		

function	has_colors
include		<curses.h>
declaration	bool has_colors(void)
version		SUNW_1.1
end		

function	has_ic
include		<curses.h>
declaration	bool has_ic(void)
version		SUNW_1.1
end		

function	has_il
include		<curses.h>
declaration	bool has_il(void)
version		SUNW_1.1
end		

function	hline
include		<curses.h>
declaration	int hline(chtype ch, int n)
version		SUNW_1.1
end		

function	hline_set
include		<curses.h>
declaration	int hline_set(const cchar_t *ch, int n)
version		SUNW_1.1
end		

function	idcok
include		<curses.h>
declaration	void idcok(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	idlok
include		<curses.h>
declaration	int idlok(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	immedok
include		<curses.h>
declaration	void immedok(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	in_wch
include		<curses.h>
declaration	int in_wch(cchar_t *wcval)
version		SUNW_1.1
end		

function	in_wchnstr
include		<curses.h>
declaration	int in_wchnstr(cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	in_wchstr
include		<curses.h>
declaration	int in_wchstr(cchar_t *wchstr)
version		SUNW_1.1
end		

function	inch
include		<curses.h>
declaration	chtype inch(void)
version		SUNW_1.1
end		

function	inchnstr
include		<curses.h>
declaration	int inchnstr(chtype *chstr, int n)
version		SUNW_1.1
end		

function	inchstr
include		<curses.h>
declaration	int inchstr(chtype *chstr)
version		SUNW_1.1
end		

function	init_color
include		<curses.h>
declaration	int init_color(short color, short red, short green, short blue)
version		SUNW_1.1
end		

function	init_pair
include		<curses.h>
declaration	int init_pair(short pair, short f, short b)
version		SUNW_1.1
end		

function	initscr
include		<curses.h>
declaration	WINDOW *initscr(void)
version		SUNW_1.1
end		

function	innstr
include		<curses.h>
declaration	int innstr(char *str, int n)
version		SUNW_1.1
end		

function	innwstr
include		<curses.h>
declaration	int innwstr(wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	ins_nwstr
include		<curses.h>
declaration	int ins_nwstr(const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	ins_wch
include		<curses.h>
declaration	int ins_wch(const cchar_t *wch)
version		SUNW_1.1
end		

function	ins_wstr
include		<curses.h>
declaration	int ins_wstr(const wchar_t *wstr)
version		SUNW_1.1
end		

function	insch
include		<curses.h>
declaration	int insch(chtype ch)
version		SUNW_1.1
end		

function	insdelln
include		<curses.h>
declaration	int insdelln(int n)
version		SUNW_1.1
end		

function	insertln
include		<curses.h>
declaration	int insertln(void)
version		SUNW_1.1
end		

function	insnstr
include		<curses.h>
declaration	int insnstr(const char *str, int n)
version		SUNW_1.1
end		

function	insstr
include		<curses.h>
declaration	int insstr(const char *str)
version		SUNW_1.1
end		

function	instr
include		<curses.h>
declaration	int instr(char *str)
version		SUNW_1.1
end		

function	intrflush
include		<curses.h>
declaration	int intrflush(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	inwstr
include		<curses.h>
declaration	int inwstr(wchar_t *wstr)
version		SUNW_1.1
end		

function	is_linetouched
include		<curses.h>
declaration	bool is_linetouched(WINDOW *win, int line)
version		SUNW_1.1
end		

function	is_wintouched
include		<curses.h>
declaration	bool is_wintouched(WINDOW *win)
version		SUNW_1.1
end		

function	isendwin
include		<curses.h>
declaration	bool isendwin(void)
version		SUNW_1.1
end		

function	key_name
include		<curses.h>
declaration	char *key_name(wchar_t wc)
version		SUNW_1.1
end		

function	keyname
include		<curses.h>
declaration	char *keyname(int c)
version		SUNW_1.1
end		

function	keypad
include		<curses.h>
declaration	int keypad(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	killchar
include		<curses.h>
declaration	char killchar(void)
version		SUNW_1.1
end		

function	killwchar
include		<curses.h>
declaration	int killwchar(wchar_t *ch)
version		SUNW_1.1
end		

function	leaveok
include		<curses.h>
declaration	int leaveok(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	longname
include		<curses.h>
declaration	char *longname(void)
version		SUNW_1.1
end		

function	meta
include		<curses.h>
declaration	int meta(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	move
include		<curses.h>
declaration	int move(int y, int x)
version		SUNW_1.1
end		

function	mvadd_wch
include		<curses.h>
declaration	int mvadd_wch(int y, int x, const cchar_t *wch)
version		SUNW_1.1
end		

function	mvadd_wchnstr
include		<curses.h>
declaration	int mvadd_wchnstr(int y, int x, \
		    const cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	mvadd_wchstr
include		<curses.h>
declaration	int mvadd_wchstr(int y, int x, const cchar_t *wchstr)
version		SUNW_1.1
end		

function	mvaddch
include		<curses.h>
declaration	int mvaddch(int y, int x, const chtype ch)
version		SUNW_1.1
end		

function	mvaddchnstr
include		<curses.h>
declaration	int mvaddchnstr(int y, int x, const chtype *chstr, int n)
version		SUNW_1.1
end		

function	mvaddchstr
include		<curses.h>
declaration	int mvaddchstr(int y, int x, const chtype *chstr)
version		SUNW_1.1
end		

function	mvaddnstr
include		<curses.h>
declaration	int mvaddnstr(int y, int x, const char *str, int n)
version		SUNW_1.1
end		

function	mvaddnwstr
include		<curses.h>
declaration	int mvaddnwstr(int y, int x, const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	mvaddstr
include		<curses.h>
declaration	int mvaddstr(int y, int x, const char *str)
version		SUNW_1.1
end		

function	mvaddwstr
include		<curses.h>
declaration	int mvaddwstr(int y, int x, const wchar_t *wstr)
version		SUNW_1.1
end		

function	mvchgat
include		<curses.h>
declaration	int mvchgat(int y, int x, int n, attr_t attr, \
		    short color, const void *opts)
version		SUNW_1.1
end		

function	mvcur
include		<curses.h>
declaration	int mvcur(int oldrow, int oldcol, int newrow, int newcol)
version		SUNW_1.1
end		

function	mvdelch
include		<curses.h>
declaration	int mvdelch(int y, int x)
version		SUNW_1.1
end		

function	mvderwin
include		<curses.h>
declaration	int mvderwin(WINDOW *win, int par_y, int par_x)
version		SUNW_1.1
end		

function	mvget_wch
include		<curses.h>
declaration	int mvget_wch(int y, int x, wint_t *ch)
version		SUNW_1.1
end		

function	mvgetch
include		<curses.h>
declaration	int mvgetch(int y, int x)
version		SUNW_1.1
end		

function	mvgetn_wstr
include		<curses.h>
declaration	int mvgetn_wstr(int y, int x, wint_t *wstr, int n)
version		SUNW_1.1
end		

function	mvgetnstr
include		<curses.h>
declaration	int mvgetnstr(int y, int x, char *str, int n)
version		SUNW_1.1
end		

function	mvgetstr
include		<curses.h>
declaration	int mvgetstr(int y, int x, char *str)
version		SUNW_1.1
end		

function	mvhline
include		<curses.h>
declaration	int mvhline(int y, int x, chtype ch, int n)
version		SUNW_1.1
end		

function	mvhline_set
include		<curses.h>
declaration	int mvhline_set(int y, int x, const cchar_t *wch, int n)
version		SUNW_1.1
end		

function	mvin_wch
include		<curses.h>
declaration	int mvin_wch(int y, int x, cchar_t *wcval)
version		SUNW_1.1
end		

function	mvin_wchnstr
include		<curses.h>
declaration	int mvin_wchnstr(int y, int x, cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	mvin_wchstr
include		<curses.h>
declaration	int mvin_wchstr(int y, int x, cchar_t *wchstr)
version		SUNW_1.1
end		

function	mvinch
include		<curses.h>
declaration	chtype mvinch(int y, int x)
version		SUNW_1.1
end		

function	mvinchnstr
include		<curses.h>
declaration	int mvinchnstr(int y, int x, chtype *chstr, int n)
version		SUNW_1.1
end		

function	mvinchstr
include		<curses.h>
declaration	int mvinchstr(int y, int x, chtype *chstr)
version		SUNW_1.1
end		

function	mvinnstr
include		<curses.h>
declaration	int mvinnstr(int y, int x, char *str, int n)
version		SUNW_1.1
end		

function	mvinnwstr
include		<curses.h>
declaration	int mvinnwstr(int y, int x, wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	mvins_nwstr
include		<curses.h>
declaration	int mvins_nwstr(int y, int x, const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	mvins_wch
include		<curses.h>
declaration	int mvins_wch(int y, int x, const cchar_t *wch)
version		SUNW_1.1
end		

function	mvins_wstr
include		<curses.h>
declaration	int mvins_wstr(int y, int x, const wchar_t *wstr)
version		SUNW_1.1
end		

function	mvinsch
include		<curses.h>
declaration	int mvinsch(int y, int x, chtype ch)
version		SUNW_1.1
end		

function	mvinsnstr
include		<curses.h>
declaration	int mvinsnstr(int y, int x, const char *str, int n)
version		SUNW_1.1
end		

function	mvinsstr
include		<curses.h>
declaration	int mvinsstr(int y, int x, const char *str)
version		SUNW_1.1
end		

function	mvinstr
include		<curses.h>
declaration	int mvinstr(int y, int x, char *str)
version		SUNW_1.1
end		

function	mvinwstr
include		<curses.h>
declaration	int mvinwstr(int y, int x, wchar_t *wstr)
version		SUNW_1.1
end		

function	mvprintw
include		<curses.h>
declaration	int mvprintw(int y, int x, char *fmt, ...)
version		SUNW_1.1
end		

function	mvscanw
include		<curses.h>
declaration	int mvscanw(int y, int x, char *fmt, ...)
version		SUNW_1.1
end		

function	mvwadd_wch
include		<curses.h>
declaration	int mvwadd_wch(WINDOW *win, int y, int x, const cchar_t *wch)
version		SUNW_1.1
end		

function	mvwadd_wchnstr
include		<curses.h>
declaration	int mvwadd_wchnstr(WINDOW *win, int y, int x, \
		    const cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	mvwadd_wchstr
include		<curses.h>
declaration	int mvwadd_wchstr(WINDOW *win, int y, int x, \
		    const cchar_t *wchstr)
version		SUNW_1.1
end		

function	mvwaddch
include		<curses.h>
declaration	int mvwaddch(WINDOW *win, int y, int x, const chtype ch)
version		SUNW_1.1
end		

function	mvwaddchnstr
include		<curses.h>
declaration	int mvwaddchnstr(WINDOW *win, int y, int x, \
		    const chtype *chstr, int n)
version		SUNW_1.1
end		

function	mvwaddchstr
include		<curses.h>
declaration	int mvwaddchstr(WINDOW *win, int  y, int x, \
		    const chtype *chstr)
version		SUNW_1.1
end		

function	mvwaddnstr
include		<curses.h>
declaration	int mvwaddnstr(WINDOW *win, int y, int x, \
		    const char *str, int n)
version		SUNW_1.1
end		

function	mvwaddnwstr
include		<curses.h>
declaration	int mvwaddnwstr(WINDOW *win, int y, int x, \
		    const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	mvwaddstr
include		<curses.h>
declaration	int mvwaddstr(WINDOW *win, int y, int x, const char *str)
version		SUNW_1.1
end		

function	mvwaddwstr
include		<curses.h>
declaration	int mvwaddwstr(WINDOW *win, int y, int x, const wchar_t *wstr)
version		SUNW_1.1
end		

function	mvwchgat
include		<curses.h>
declaration	int mvwchgat(WINDOW *win, int y, int x, int n, \
		    attr_t attr, short color, const void *opts)
version		SUNW_1.1
end		

function	mvwdelch
include		<curses.h>
declaration	int mvwdelch(WINDOW *win, int y, int x)
version		SUNW_1.1
end		

function	mvwget_wch
include		<curses.h>
declaration	int mvwget_wch(WINDOW *win, int y, int x, wint_t *ch)
version		SUNW_1.1
end		

function	mvwget_wstr
include		<curses.h>
declaration	int mvwget_wstr(WINDOW *win, int y, int x, wint_t *wstr)
version		SUNW_1.1
end		

function	mvwgetch
include		<curses.h>
declaration	int mvwgetch(WINDOW *win, int y, int x)
version		SUNW_1.1
end		

function	mvwgetn_wstr
include		<curses.h>
declaration	int mvwgetn_wstr(WINDOW *win, int y, int x, wint_t *wstr, int n)
version		SUNW_1.1
end		

function	mvwgetnstr
include		<curses.h>
declaration	int mvwgetnstr(WINDOW *win, int y, int x, char *str, int n)
version		SUNW_1.1
end		

function	mvwgetstr
include		<curses.h>
declaration	int mvwgetstr(WINDOW *win, int y, int x, char *str)
version		SUNW_1.1
end		

function	mvwhline
include		<curses.h>
declaration	int mvwhline(WINDOW *win, int y, int x, chtype ch, int n)
version		SUNW_1.1
end		

function	mvwhline_set
include		<curses.h>
declaration	int mvwhline_set(WINDOW *win, int y, int  x, \
		    const cchar_t *wch, int n)
version		SUNW_1.1
end		

function	mvwin_wch
include		<curses.h>
declaration	int mvwin_wch(WINDOW *win, int y, int x, cchar_t *wcval)
version		SUNW_1.1
end		

function	mvwin_wchnstr
include		<curses.h>
declaration	int mvwin_wchnstr(WINDOW *win, int y, int x, \
		    cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	mvwin_wchstr
include		<curses.h>
declaration	int  mvwin_wchstr(WINDOW *win, int y, int x, cchar_t *wchstr)
version		SUNW_1.1
end		

function	mvwin
include		<curses.h>
declaration	int mvwin(WINDOW *win, int y, int x)
version		SUNW_1.1
end		

function	mvwinch
include		<curses.h>
declaration	chtype mvwinch(WINDOW *win, int y, int x)
version		SUNW_1.1
end		

function	mvwinchnstr
include		<curses.h>
declaration	int mvwinchnstr(WINDOW *win, int y, int x, chtype *chstr, int n)
version		SUNW_1.1
end		

function	mvwinchstr
include		<curses.h>
declaration	int mvwinchstr(WINDOW *win, int y, int x, chtype *chstr)
version		SUNW_1.1
end		

function	mvwinnstr
include		<curses.h>
declaration	int mvwinnstr(WINDOW *win, int y, int x, char *str, int n)
version		SUNW_1.1
end		

function	mvwinnwstr
include		<curses.h>
declaration	int mvwinnwstr(WINDOW*win, int y, int x, wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	mvwins_nwstr
include		<curses.h>
declaration	int mvwins_nwstr(WINDOW *win, int y, int x, \
			    const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	mvwins_wch
include		<curses.h>
declaration	int mvwins_wch(WINDOW *win, int y, int x, const cchar_t *wch)
version		SUNW_1.1
end		

function	mvwins_wstr
include		<curses.h>
declaration	int mvwins_wstr(WINDOW *win, int y, int x, const wchar_t *wstr)
version		SUNW_1.1
end		

function	mvwinsch
include		<curses.h>
declaration	int mvwinsch(WINDOW *win, int y, int x, chtype ch)
version		SUNW_1.1
end		

function	mvwinsnstr
include		<curses.h>
declaration	int mvwinsnstr(WINDOW *win, int y, int x, \
		    const char *str, int n)
version		SUNW_1.1
end		

function	mvwinsstr
include		<curses.h>
declaration	int mvwinsstr(WINDOW *win, int y, int x, const char *str)
version		SUNW_1.1
end		

function	mvwinstr
include		<curses.h>
declaration	int mvwinstr(WINDOW *win, int y, int x, char *str)
version		SUNW_1.1
end		

function	mvwinwstr
include		<curses.h>
declaration	int mvwinwstr(WINDOW*win, int y, int x, wchar_t *wstr)
version		SUNW_1.1
end		

function	mvwprintw
include		<curses.h>
declaration	int mvwprintw(WINDOW *win, int y, int x, char *fmt, ...)
version		SUNW_1.1
end		

function	mvwscanw
include		<curses.h>
declaration	int mvwscanw(WINDOW *win, int y, int x, char *fmt, ...)
version		SUNW_1.1
end		

function	mvwvline
include		<curses.h>
declaration	int mvwvline(WINDOW *win, int y, int x, chtype ch, int n)
version		SUNW_1.1
end		

function	mvwvline_set
include		<curses.h>
declaration	int mvwvline_set(WINDOW *win, int y, int x, \
		    const  cchar_t *wch, int n)
version		SUNW_1.1
end		

function	mvvline
include		<curses.h>
declaration	int mvvline(int y, int x, chtype ch, int n)
version		SUNW_1.1
end		

function	mvvline_set
include		<curses.h>
declaration	int mvvline_set(int y, int x, const cchar_t *wch, int n)
version		SUNW_1.1
end		

function	napms
include		<curses.h>
declaration	int napms(int ms)
version		SUNW_1.1
end		

function	newpad
include		<curses.h>
declaration	WINDOW *newpad(int nlines, int ncols)
version		SUNW_1.1
end		

function	newterm
include		<curses.h>
declaration	SCREEN *newterm(char *type, FILE *outfp, FILE *infp)
version		SUNW_1.1
end		

function	newwin
include		<curses.h>
declaration	WINDOW *newwin(int nlines, int ncols, int begin_y, int begin_x)
version		SUNW_1.1
end		

function	nocbreak
include		<curses.h>
declaration	int nocbreak(void)
version		SUNW_1.1
end		

function	nodelay
include		<curses.h>
declaration	int nodelay(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	noecho
include		<curses.h>
declaration	int noecho(void)
version		SUNW_1.1
end		

function	noqiflush
include		<curses.h>
declaration	void noqiflush(void)
version		SUNW_1.1
end		

function	nonl
include		<curses.h>
declaration	int nonl(void)
version		SUNW_1.1
end		

function	noraw
include		<curses.h>
declaration	int noraw(void)
version		SUNW_1.1
end		

function	notimeout
include		<curses.h>
declaration	int notimeout(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	nl
include		<curses.h>
declaration	int nl(void)
version		SUNW_1.1
end		

function	overlay
include		<curses.h>
declaration	int overlay(const WINDOW *srcwin, WINDOW *dstwin)
version		SUNW_1.1
end		

function	overwrite
include		<curses.h>
declaration	int overwrite(const WINDOW *srcwin, WINDOW *dstwin)
version		SUNW_1.1
end		

function	pair_content
include		<curses.h>
declaration	int pair_content(short pair, short *f, short *b)
version		SUNW_1.1
end		

function	pecho_wchar
include		<curses.h>
declaration	int pecho_wchar(WINDOW *pad, const cchar_t *wch)
version		SUNW_1.1
end		

function	pechochar
include		<curses.h>
declaration	int pechochar(WINDOW *pad, chtype ch)
version		SUNW_1.1
end		

function	pnoutrefresh
include		<curses.h>
declaration	int pnoutrefresh(WINDOW *pad, int pminrow, \
		    int pmincol, int sminrow, int smincol, \
		    int smaxrow, int smaxcol)
version		SUNW_1.1
end		

function	prefresh
include		<curses.h>
declaration	int prefresh(WINDOW *pad, int pminrow, int pmincol, \
		    int sminrow, int smincol, int smaxrow, int smaxcol)
version		SUNW_1.1
end		

function	printw
include		<curses.h>
declaration	int printw(char *fmt, ...)
version		SUNW_1.1
end		

function	putwin
include		<curses.h>
declaration	int putwin(WINDOW *win, FILE *filep)
version		SUNW_1.1
end		

function	qiflush
include		<curses.h>
declaration	void qiflush(void)
version		SUNW_1.1
end		

function	raw
include		<curses.h>
declaration	int raw(void)
version		SUNW_1.1
end		

function	redrawwin
include		<curses.h>
declaration	int redrawwin(WINDOW *win)
version		SUNW_1.1
end		

function	refresh
include		<curses.h>
declaration	int refresh(void)
version		SUNW_1.1
end		

function	reset_prog_mode
include		<curses.h>
declaration	int reset_prog_mode(void)
version		SUNW_1.1
end		

function	reset_shell_mode
include		<curses.h>
declaration	int reset_shell_mode(void)
version		SUNW_1.1
end		

function	resetty
include		<curses.h>
declaration	int resetty(void)
version		SUNW_1.1
end		

function	restartterm
include		<curses.h>
declaration	int restartterm(char *term, int fildes, int *errret)
version		SUNW_1.1
end		

function	ripoffline
include		<curses.h>
declaration	int ripoffline(int line, int (*init)(WINDOW *win, int width))
version		SUNW_1.1
end		

function	savetty
include		<curses.h>
declaration	int savetty(void)
version		SUNW_1.1
end		

function	scanw
include		<curses.h>
declaration	int scanw(char *fmt, ...)
version		SUNW_1.1
end		

function	scr_dump
include		<curses.h>
declaration	int scr_dump(const char *filename)
version		SUNW_1.1
end		

function	scr_init
include		<curses.h>
declaration	int scr_init(const char *filename)
version		SUNW_1.1
end		

function	scr_restore
include		<curses.h>
declaration	int scr_restore(const char *filename)
version		SUNW_1.1
end		

function	scr_set
include		<curses.h>
declaration	int scr_set(const char *filename)
version		SUNW_1.1
end		

function	scrl
include		<curses.h>
declaration	int scrl(int n)
version		SUNW_1.1
end		

function	scroll
include		<curses.h>
declaration	int scroll(WINDOW *win)
version		SUNW_1.1
end		

function	scrollok
include		<curses.h>
declaration	int scrollok(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	set_curterm
include		<curses.h>
declaration	TERMINAL *set_curterm (TERMINAL *nterm)
version		SUNW_1.1
end		

function	set_term
include		<curses.h>
declaration	SCREEN *set_term(SCREEN *new)
version		SUNW_1.1
end		

function	setcchar
include		<curses.h>
declaration	int setcchar(cchar_t *wcval, const wchar_t *wch, \
		    const attr_t attrs, short color_pair, const void *opts)
version		SUNW_1.1
end		

function	setscrreg
include		<curses.h>
declaration	int setscrreg(int top, int bot)
version		SUNW_1.1
end		

function	setupterm
include		<term.h>
declaration	int setupterm(char *term, int fildes, int *errret)
version		SUNW_1.1
end		

function	slk_attr_off
include		<curses.h>
declaration	int slk_attr_off(const attr_t attrs, void *opts)
version		SUNW_1.1
end		

function	slk_attr_on
include		<curses.h>
declaration	int slk_attr_on(const attr_t attrs, void *opts)
version		SUNW_1.1
end		

function	slk_attr_set
include		<curses.h>
declaration	int slk_attr_set(const attr_t attrs, \
		    short color_pair_number, void *opts)
version		SUNW_1.1
end		

function	slk_attron
include		<curses.h>
declaration	int slk_attron(const chtype attrs)
version		SUNW_1.1
end		

function	slk_attroff
include		<curses.h>
declaration	int slk_attroff(const chtype attrs)
version		SUNW_1.1
end		

function	slk_attrset
include		<curses.h>
declaration	int slk_attrset(const chtype attrs)
version		SUNW_1.1
end		

function	slk_clear
include		<curses.h>
declaration	int slk_clear(void)
version		SUNW_1.1
end		

function	slk_color
include		<curses.h>
declaration	int slk_color(short color_pair_number)
version		SUNW_1.1
end		

function	slk_init
include		<curses.h>
declaration	int slk_init(int fmt)
version		SUNW_1.1
end		

function	slk_label
include		<curses.h>
declaration	char *slk_label(int labnum)
version		SUNW_1.1
end		

function	slk_noutrefresh
include		<curses.h>
declaration	int slk_noutrefresh(void)
version		SUNW_1.1
end		

function	slk_refresh
include		<curses.h>
declaration	int slk_refresh(void)
version		SUNW_1.1
end		

function	slk_restore
include		<curses.h>
declaration	int slk_restore(void)
version		SUNW_1.1
end		

function	slk_set
include		<curses.h>
declaration	int slk_set(int labnum, const char *label, int justify)
version		SUNW_1.1
end		

function	slk_touch
include		<curses.h>
declaration	int slk_touch(void)
version		SUNW_1.1
end		

function	slk_wset
include		<curses.h>
declaration	int slk_wset(int labnum, const wchar_t *label, int justify)
version		SUNW_1.1
end		

function	standend
include		<curses.h>
declaration	int standend(void)
version		SUNW_1.1
end		

function	standout
include		<curses.h>
declaration	int standout(void)
version		SUNW_1.1
end		

function	start_color
include		<curses.h>
declaration	int start_color(void)
version		SUNW_1.1
end		

function	subpad
include		<curses.h>
declaration	WINDOW *subpad(WINDOW *orig, int, int, int, int)
version		SUNW_1.1
end		

function	subwin
include		<curses.h>
declaration	WINDOW *subwin(WINDOW *orig, int nlines, int ncols, \
		    int begin_y, int begin_x)
version		SUNW_1.1
end		

function	syncok
include		<curses.h>
declaration	int syncok(WINDOW *win, bool bf)
version		SUNW_1.1
end		

function	term_attrs
include		<curses.h>
declaration	attr_t term_attrs(void)
version		SUNW_1.1
end		

function	termattrs
include		<curses.h>
declaration	chtype termattrs(void)
version		SUNW_1.1
end		

function	termname
include		<curses.h>
declaration	char *termname(void)
version		SUNW_1.1
end		

function	tgetent
include		<term.h>
declaration	int tgetent(char *bp, const char *name)
version		SUNW_1.1
end		

function	tgetflag
include		<term.h>
declaration	int tgetflag(char id[2])
version		SUNW_1.1
end		

function	tgetnum
include		<term.h>
declaration	int tgetnum(char id[2])
version		SUNW_1.1
end		

function	tgetstr
include		<term.h>
declaration	char *tgetstr(char id[2], char **area)
version		SUNW_1.1
end		

function	tgoto
include		<term.h>
declaration	char *tgoto(char *cap, int col, int row)
version		SUNW_1.1
end		

function	tigetflag
include		<term.h>
declaration	int tigetflag(char *capname)
version		SUNW_1.1
end		

function	tigetnum
include		<term.h>
declaration	int tigetnum(char *capname)
version		SUNW_1.1
end		

function	tigetstr
include		<term.h>
declaration	char *tigetstr(char *capname)
version		SUNW_1.1
end		

function	timeout
include		<curses.h>
declaration	void timeout(int delay)
version		SUNW_1.1
end		

function	touchline
include		<curses.h>
declaration	int touchline(WINDOW *win, int start, int count)
version		SUNW_1.1
end		

function	touchwin
include		<curses.h>
declaration	int touchwin(WINDOW *win)
version		SUNW_1.1
end		

function	typeahead
include		<curses.h>
declaration	int typeahead(int fd)
version		SUNW_1.1
end		

function	unctrl
include		<unctrl.h>
declaration	char *unctrl(chtype c)
version		SUNW_1.1
end		

function	unget_wch
include		<curses.h>
declaration	int unget_wch(const wchar_t wch)
version		SUNW_1.1
end		

function	ungetch
include		<curses.h>
declaration	int ungetch(int ch)
version		SUNW_1.1
end		

function	untouchwin
include		<curses.h>
declaration	int untouchwin(WINDOW *win)
version		SUNW_1.1
end		

function	use_env
include		<curses.h>
declaration	void use_env(bool boolval)
version		SUNW_1.1
end		

function	vid_attr
include		<curses.h>
declaration	int vid_attr(attr_t attr, short color_pair_number, void *opt)
version		SUNW_1.1
end		

function	vid_puts
include		<curses.h>
declaration	int vid_puts(attr_t attr, short color_pair_number, \
		    void *opt, int (*putfunc) (int))
version		SUNW_1.1
end		

function	vidattr
include		<curses.h>
declaration	int vidattr(chtype attr)
version		SUNW_1.1
end		

function	vidputs
include		<curses.h>
declaration	int vidputs(chtype attr, int (*putfunc) (int))
version		SUNW_1.1
end		

function	vline
include		<curses.h>
declaration	int vline(chtype ch, int n)
version		SUNW_1.1
end		

function	vline_set
include		<curses.h>
declaration	int vline_set(const cchar_t *wch, int n)
version		SUNW_1.1
end		

function	vw_printw
include		<stdarg.h>, <curses.h>
declaration	int vw_printw(WINDOW *win, char *fmt, va_list varglist)
version		SUNW_1.1
end		

function	vw_scanw
include		<stdarg.h>, <curses.h>
declaration	int vw_scanw(WINDOW *win, char *fmt, va_list varglist)
version		SUNW_1.1
end		

# This is a deprecated function which includes a deprecated header
# Since the inclusion of the deprecated header causes problems
# we comment out the include and declaration lines.
function	vwprintw
#include		<varargs.h>, <curses.h>
#declaration	int vwprintw(WINDOW *win, char *fmt, va_list varglist)
version		SUNW_1.1
end

# This is a deprecated function which includes a deprecated header
# Since the inclusion of the deprecated header causes problems
# we comment out the include and declaration lines.
function	vwscanw
#include		<varargs.h>, <curses.h>
#declaration	int vwscanw(WINDOW *win, char *fmt, va_list varglist)
version		SUNW_1.1
end
function	wadd_wch
include		<curses.h>
declaration	int wadd_wch(WINDOW *win, const cchar_t *wch)
version		SUNW_1.1
end		

function	wadd_wchnstr
include		<curses.h>
declaration	int wadd_wchnstr(WINDOW *win, const cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	wadd_wchstr
include		<curses.h>
declaration	int wadd_wchstr(WINDOW *win, const cchar_t *wchstr)
version		SUNW_1.1
end		

function	waddch
include		<curses.h>
declaration	int waddch(WINDOW *win, const chtype ch)
version		SUNW_1.1
end		

function	waddchnstr
include		<curses.h>
declaration	int waddchnstr(WINDOW *win, const chtype *chstr, int n)
version		SUNW_1.1
end		

function	waddchstr
include		<curses.h>
declaration	int waddchstr(WINDOW *win, const chtype *chstr)
version		SUNW_1.1
end		

function	waddnstr
include		<curses.h>
declaration	int waddnstr(WINDOW *win, const char *str, int n)
version		SUNW_1.1
end		

function	waddnwstr
include		<curses.h>
declaration	int waddnwstr(WINDOW*win, const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	waddstr
include		<curses.h>
declaration	int waddstr(WINDOW *win, const char *str)
version		SUNW_1.1
end		

function	waddwstr
include		<curses.h>
declaration	int waddwstr(WINDOW *WIN, const wchar_t *wstr)
version		SUNW_1.1
end		

function	wattr_get
include		<curses.h>
declaration	int wattr_get(WINDOW *win, attr_t *attrs, short *color, \
		    void *opts)
version		SUNW_1.1
end		

function	wattr_on
include		<curses.h>
declaration	int wattr_on(WINDOW *win, attr_t attrs, void *opts)
version		SUNW_1.1
end		

function	wattr_off
include		<curses.h>
declaration	int wattr_off(WINDOW *win, attr_t attrs, void *opts)
version		SUNW_1.1
end		

function	wattr_set
include		<curses.h>
declaration	int wattr_set(WINDOW *win, attr_t attrs, short  color, \
		    void *opts)
version		SUNW_1.1
end		

function	wattron
include		<curses.h>
declaration	int wattron(WINDOW *win, int attrs)
version		SUNW_1.1
end		

function	wattroff
include		<curses.h>
declaration	int wattroff(WINDOW *win, int attrs)
version		SUNW_1.1
end		

function	wattrset
include		<curses.h>
declaration	int wattrset(WINDOW *win, int attrs)
version		SUNW_1.1
end		

function	wbkgd
include		<curses.h>
declaration	int wbkgd(WINDOW *win, chtype ch)
version		SUNW_1.1
end		

function	wbkgdset
include		<curses.h>
declaration	void wbkgdset(WINDOW *win, chtype ch)
version		SUNW_1.1
end		

function	wbkgrnd
include		<curses.h>
declaration	int wbkgrnd(WINDOW *win, const cchar_t *wch)
version		SUNW_1.1
end		

function	wbkgrndset
include		<curses.h>
declaration	void wbkgrndset(WINDOW *win, const cchar_t *wch)
version		SUNW_1.1
end		

function	wborder
include		<curses.h>
declaration	int wborder(WINDOW *win, chtype ls, chtype rs, chtype ts, \
		    chtype bs, chtype tl, chtype tr, chtype bl, chtype br)
version		SUNW_1.1
end		

function	wborder_set
include		<curses.h>
declaration	int  wborder_set(WINDOW *win, const cchar_t *ls, \
		    const cchar_t *rs, const cchar_t *ts, \
		    const cchar_t *bs, const cchar_t *tl, \
		    const cchar_t *tr, const cchar_t *bl, const cchar_t *br)
version		SUNW_1.1
end		

function	wchgat
include		<curses.h>
declaration	int wchgat(WINDOW *win, int n, attr_t attr, \
		    short color, const void *opts)
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

function	wcolor_set
include		<curses.h>
declaration	int wcolor_set(WINDOW *win, short color, void *opts)
version		SUNW_1.1
end		

function	wcursyncup
include		<curses.h>
declaration	void wcursyncup(WINDOW *win)
version		SUNW_1.1
end		

function	wdelch
include		<curses.h>
declaration	int wdelch(WINDOW *win)
version		SUNW_1.1
end		

function	wdeleteln
include		<curses.h>
declaration	int wdeleteln(WINDOW *win)
version		SUNW_1.1
end		

function	wecho_wchar
include		<curses.h>
declaration	int wecho_wchar(WINDOW *win, const cchar_t *wch)
version		SUNW_1.1
end		

function	wechochar
include		<curses.h>
declaration	int wechochar(WINDOW *win, const chtype ch)
version		SUNW_1.1
end		

function	werase
include		<curses.h>
declaration	int werase(WINDOW *win)
version		SUNW_1.1
end		

function	wget_wch
include		<curses.h>
declaration	int wget_wch(WINDOW *win, wint_t *ch)
version		SUNW_1.1
end		

function	wget_wstr
include		<curses.h>
declaration	int wget_wstr(WINDOW *win, wint_t *wstr)
version		SUNW_1.1
end		

function	wgetbkgrnd
include		<curses.h>
declaration	int wgetbkgrnd(WINDOW *win, cchar_t *wch)
version		SUNW_1.1
end		

function	wgetch
include		<curses.h>
declaration	int wgetch(WINDOW *win)
version		SUNW_1.1
end		

function	wgetn_wstr
include		<curses.h>
declaration	int wgetn_wstr(WINDOW *win, wint_t *wstr, int n)
version		SUNW_1.1
end		

function	wgetnstr
include		<curses.h>
declaration	int wgetnstr(WINDOW *win, char *str, int n)
version		SUNW_1.1
end		

function	wgetstr
include		<curses.h>
declaration	int wgetstr(WINDOW *win, char *str)
version		SUNW_1.1
end		

function	whline
include		<curses.h>
declaration	int whline(WINDOW *win, chtype ch, int n)
version		SUNW_1.1
end		

function	whline_set
include		<curses.h>
declaration	int whline_set(WINDOW *win, const cchar_t *wch, int n)
version		SUNW_1.1
end		

function	win_wch
include		<curses.h>
declaration	int win_wch(WINDOW *win, cchar_t *wcval)
version		SUNW_1.1
end		

function	win_wchnstr
include		<curses.h>
declaration	int win_wchnstr(WINDOW *win, cchar_t *wchstr, int n)
version		SUNW_1.1
end		

function	win_wchstr
include		<curses.h>
declaration	int win_wchstr(WINDOW *win, cchar_t *wchstr)
version		SUNW_1.1
end		

function	winch
include		<curses.h>
declaration	chtype winch(WINDOW *win)
version		SUNW_1.1
end		

function	winchnstr
include		<curses.h>
declaration	int winchnstr(WINDOW *win, chtype *chstr, int n)
version		SUNW_1.1
end		

function	winchstr
include		<curses.h>
declaration	int winchstr(WINDOW *win, chtype *chstr)
version		SUNW_1.1
end		

function	winnstr
include		<curses.h>
declaration	int winnstr(WINDOW *win, char *str, int n)
version		SUNW_1.1
end		

function	winnwstr
include		<curses.h>
declaration	int winnwstr(WINDOW*win, wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	wins_nwstr
include		<curses.h>
declaration	int wins_nwstr(WINDOW *win, const wchar_t *wstr, int n)
version		SUNW_1.1
end		

function	wins_wch
include		<curses.h>
declaration	int wins_wch(WINDOW *win, const cchar_t *wch)
version		SUNW_1.1
end		

function	wins_wstr
include		<curses.h>
declaration	int wins_wstr(WINDOW *win, const wchar_t *wstr)
version		SUNW_1.1
end		

function	winsch
include		<curses.h>
declaration	int winsch(WINDOW *win, chtype ch)
version		SUNW_1.1
end		

function	winsdelln
include		<curses.h>
declaration	int winsdelln(WINDOW *win, int n)
version		SUNW_1.1
end		

function	winsertln
include		<curses.h>
declaration	int winsertln(WINDOW *win)
version		SUNW_1.1
end		

function	winsnstr
include		<curses.h>
declaration	int winsnstr(WINDOW *win, const char *str, int n)
version		SUNW_1.1
end		

function	winsstr
include		<curses.h>
declaration	int winsstr(WINDOW *win, const char *str)
version		SUNW_1.1
end		

function	winstr
include		<curses.h>
declaration	int winstr(WINDOW *win, char *str)
version		SUNW_1.1
end		

function	winwstr
include		<curses.h>
declaration	int winwstr(WINDOW*win, wchar_t *wstr)
version		SUNW_1.1
end		

function	wmove
include		<curses.h>
declaration	int wmove(WINDOW *win, int y, int x)
version		SUNW_1.1
end		

function	wnoutrefresh
include		<curses.h>
declaration	int wnoutrefresh(WINDOW *win)
version		SUNW_1.1
end		

function	wprintw
include		<curses.h>
declaration	int wprintw(WINDOW *win, char *fmt, ...)
version		SUNW_1.1
end		

function	wredrawln
include		<curses.h>
declaration	int wredrawln(WINDOW *win, int beg_line, int num_lines)
version		SUNW_1.1
end		

function	wrefresh
include		<curses.h>
declaration	int wrefresh(WINDOW *win)
version		SUNW_1.1
end		

function	wscanw
include		<curses.h>
declaration	int wscanw(WINDOW *win, char *fmt, ...)
version		SUNW_1.1
end		

function	wscrl
include		<curses.h>
declaration	int wscrl(WINDOW *win, int n)
version		SUNW_1.1
end		

function	wsetscrreg
include		<curses.h>
declaration	int wsetscrreg(WINDOW *win, int top, int bot)
version		SUNW_1.1
end		

function	wstandout
include		<curses.h>
declaration	int wstandout(WINDOW *win)
version		SUNW_1.1
end		

function	wstandend
include		<curses.h>
declaration	int wstandend(WINDOW *win)
version		SUNW_1.1
end		

function	wsyncdown
include		<curses.h>
declaration	void wsyncdown(WINDOW *win)
version		SUNW_1.1
end		

function	wsyncup
include		<curses.h>
declaration	void wsyncup(WINDOW *win)
version		SUNW_1.1
end		

function	wtimeout
include		<curses.h>
declaration	void wtimeout(WINDOW *win, int delay)
version		SUNW_1.1
end		

function	wtouchln
include		<curses.h>
declaration	int wtouchln(WINDOW *win, int y, int n, int changed)
version		SUNW_1.1
end		

function	wunctrl
include		<curses.h>
declaration	wchar_t *wunctrl(cchar_t *wc)
version		SUNW_1.1
end		

function	wvline
include		<curses.h>
declaration	int wvline(WINDOW *win, chtype ch, int n)
version		SUNW_1.1
end		

function	wvline_set
include		<curses.h>
declaration	int wvline_set(WINDOW *win, const cchar_t *wch, int n)
version		SUNW_1.1
end		

data		__cht1
version		SUNWprivate_1.1
end

data		__cht2
version		SUNWprivate_1.1
end

data		__pcht1
version		SUNWprivate_1.1
end

data		__pcht2
version		SUNWprivate_1.1
end

data		__w1
version		SUNWprivate_1.1
end

data		__WACS_VLINE
version		SUNWprivate_1.1
end

data		__WACS_HLINE
version		SUNWprivate_1.1
end

data		__WACS_ULCORNER
version		SUNWprivate_1.1
end

data		__WACS_URCORNER
version		SUNWprivate_1.1
end

data		__WACS_LLCORNER
version		SUNWprivate_1.1
end

data		__WACS_LRCORNER
version		SUNWprivate_1.1
end

data		__WACS_RTEE
version		SUNWprivate_1.1
end

data		__WACS_LTEE
version		SUNWprivate_1.1
end

data		__WACS_BTEE
version		SUNWprivate_1.1
end

data		__WACS_TTEE
version		SUNWprivate_1.1
end

data		__WACS_PLUS
version		SUNWprivate_1.1
end

data		__WACS_S1
version		SUNWprivate_1.1
end

data		__WACS_S9
version		SUNWprivate_1.1
end

data		__WACS_DIAMOND
version		SUNWprivate_1.1
end

data		__WACS_CKBOARD
version		SUNWprivate_1.1
end

data		__WACS_DEGREE
version		SUNWprivate_1.1
end

data		__WACS_PLMINUS
version		SUNWprivate_1.1
end

data		__WACS_BULLET
version		SUNWprivate_1.1
end

data		__WACS_LARROW
version		SUNWprivate_1.1
end

data		__WACS_RARROW
version		SUNWprivate_1.1
end

data		__WACS_DARROW
version		SUNWprivate_1.1
end

data		__WACS_UARROW
version		SUNWprivate_1.1
end

data		__WACS_BOARD
version		SUNWprivate_1.1
end

data		__WACS_LANTERN
version		SUNWprivate_1.1
end

data		__WACS_BLOCK
version		SUNWprivate_1.1
end

data		boolcodes
version		SUNWprivate_1.1
end

data		boolfnames
version		SUNWprivate_1.1
end

data		boolnames
version		SUNWprivate_1.1
end

data		numcodes
version		SUNWprivate_1.1
end

data		numfnames
version		SUNWprivate_1.1
end

data		numnames
version		SUNWprivate_1.1
end

data		strcodes
version		SUNWprivate_1.1
end

data		strfnames
version		SUNWprivate_1.1
end

data		strnames
version		SUNWprivate_1.1
end

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
# lib/libcurses/spec/curses.spec

function	_getsyx
declaration	int _getsyx(int *yp, int *xp)
version		SUNW_1.1
end

function	_meta
declaration	int _meta(int bf)
version		SUNW_1.1
end

function	_ring
include		<curses.h>, <term.h>
declaration	int _ring(bool bf)
version		SUNW_1.1
end

function	_setecho
declaration	int _setecho(int bf)
version		SUNW_1.1
end

function	_setnonl
declaration	int _setnonl(int bf)
version		SUNW_1.1
end

function	_setqiflush
declaration	void _setqiflush(int yes)
version		SUNW_1.1
end

function	baudrate
declaration	int baudrate(void)
version		SUNW_1.1
end

function	can_change_color
include		<curses.h>, <term.h>
declaration	bool can_change_color(void)
version		SUNW_1.1
end

function	cbreak
declaration	int cbreak(void)
version		SUNW_1.1
end

function	color_content
declaration	int color_content(short color, short *r, short *g, short *b)
version		SUNW_1.1
end

function	copywin
declaration	int copywin(WINDOW *Srcwin, WINDOW *Dstwin, int minRowSrc, \
			int minColSrc, int minRowDst, int minColDst, \
			int maxRowDst, int maxColDst, int over_lay)
version		SUNW_1.1
end

function	crmode
declaration	int crmode(void)
version		SUNW_1.1
end

function	curserr
declaration	void curserr(void)
version		SUNWprivate_1.1
end

function	curs_set
declaration	int curs_set(int visibility)
version		SUNW_1.1
end

function	def_prog_mode
declaration	int def_prog_mode(void)
version		SUNW_1.1
end

function	def_shell_mode
declaration	int def_shell_mode(void)
version		SUNW_1.1
end

function	delay_output
declaration	int delay_output(int ms)
version		SUNW_1.1
end

function	delkeymap
include		<curses.h>, <term.h>
declaration	void delkeymap(TERMINAL *terminal)
version		SUNWprivate_1.1
end

function	delscreen
include		<curses.h>, <term.h>
declaration	void delscreen(SCREEN *screen)
version		SUNW_1.1
end

function	delterm
include		<curses.h>, <term.h>
declaration	int delterm(TERMINAL *terminal)
version		SUNWprivate_1.1
end

function	delwin
include		<curses.h>, <term.h>
declaration	int delwin(WINDOW *win)
version		SUNW_1.1
end

function	derwin
declaration	WINDOW *derwin(WINDOW *win, int num_lines, int nc, \
			int by, int bx)
version		SUNW_1.1
end

function	doupdate
declaration	int doupdate(void)
version		SUNW_1.1
end

function	dupwin
declaration	WINDOW *dupwin(WINDOW *win)
version		SUNW_1.1
end

function	endwin
declaration	int endwin(void)
version		SUNW_1.1
end

function	erasechar
declaration	char erasechar(void)
version		SUNW_1.1
end

function	filter
declaration	int filter(void)
version		SUNW_1.1
end

function	flushinp
declaration	int flushinp(void)
version		SUNW_1.1
end

function	getbmap
declaration	unsigned long getbmap(void)
version		SUNWprivate_1.1
end

function	getmouse
declaration	unsigned long getmouse(void)
version		SUNWprivate_1.1
end

function	getwin
declaration	WINDOW *getwin(FILE *filep)
version		SUNW_1.1
end

function	has_colors
include		<curses.h>, <term.h>
declaration	bool has_colors(void)
version		SUNW_1.1
end

function	has_ic
declaration	int has_ic(void)
version		SUNW_1.1
end

function	has_il
declaration	int has_il(void)
version		SUNW_1.1
end

function	idlok
include		<curses.h>, <term.h>
declaration	int idlok(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	immedok
include		<curses.h>, <term.h>
declaration	void immedok(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	init_color
declaration	int init_color(short color, short r, short g, short b)
version		SUNW_1.1
end

function	init_pair
declaration	int init_pair(short pair, short f, short b)
version		SUNW_1.1
end

function	initscr32 extends libcurses/spec/curses.spec initscr
version		SUNWprivate_1.1
end

function	initscr
include		<curses.h>, <term.h>
declaration	WINDOW *initscr(void)
version		SUNW_1.1
end

function	isendwin
declaration	int isendwin(void)
version		SUNW_1.1
end

function	keyname
declaration	char *keyname(int key)
version		SUNW_1.1
end

function	keypad
include		<curses.h>, <term.h>
declaration	int keypad(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	killchar
declaration	char killchar(void)
version		SUNW_1.1
end

function	longname
declaration	char *longname(void)
version		SUNW_1.1
end

function	m_addch
declaration	int m_addch(int c)
version		SUNWprivate_1.1
end

function	m_addstr
declaration	int m_addstr(char *str)
version		SUNWprivate_1.1
end

function	m_clear
declaration	int m_clear(void)
version		SUNWprivate_1.1
end

function	m_erase
declaration	int m_erase(void)
version		SUNWprivate_1.1
end

function	m_initscr
declaration	WINDOW *m_initscr(void)
version		SUNWprivate_1.1
end

function	m_move
declaration	int m_move(int x, int y)
version		SUNWprivate_1.1
end

function	m_newterm
include		<curses.h>, <term.h>
declaration	SCREEN *m_newterm(char *type, FILE *outfptr, FILE *infptr)
version		SUNWprivate_1.1
end

function	m_refresh
declaration	int m_refresh(void)
version		SUNWprivate_1.1
end

function	map_button
declaration	int map_button(unsigned long a)
version		SUNWprivate_1.1
end

function	mouse_off
declaration	int mouse_off(long mbe)
version		SUNWprivate_1.1
end

function	mouse_on
declaration	int mouse_on(long mbe)
version		SUNWprivate_1.1
end

function	mouse_set
declaration	int mouse_set(long mbe)
version		SUNWprivate_1.1
end

function	mvcur
declaration	int mvcur(int cury, int curx, int newy, int newx)
version		SUNW_1.1
end

function	mvderwin
declaration	int mvderwin(WINDOW *win, int pary, int parx)
version		SUNW_1.1
end

function	mvprintw
declaration	int mvprintw(int y, int x, ...)
version		SUNW_1.1
end

function	mvscanw
declaration	int mvscanw(int y, int x, ...)
version		SUNW_1.1
end

function	mvwin
declaration	int mvwin(WINDOW *win, int by, int bx)
version		SUNW_1.1
end

function	mvwprintw
declaration	int mvwprintw(WINDOW *win, int y, int x, ...)
version		SUNW_1.1
end

function	mvwscanw
declaration	int mvwscanw(WINDOW *win, int y, int x, ...)
version		SUNW_1.1
end

function	napms
declaration	int napms(int ms)
version		SUNW_1.1
end

function	newkey
include		<curses.h>, <term.h>
declaration	int newkey(char *rcvchars, short keyval, bool macro)
version		SUNWprivate_1.1
end

function	newterm32 extends libcurses/spec/curses.spec newterm
version		SUNWprivate_1.1
end

function	newterm
include		<curses.h>, <term.h>
declaration	SCREEN *newterm(char *type, FILE *fout, FILE *fin)
version		SUNW_1.1
end

function	newscreen
include		<curses.h>, <term.h>
declaration	SCREEN *newscreen(char *type, int lsize, int csize, int \
			tabsize, FILE *outfptr, FILE *infptr)
version		SUNWprivate_1.1
end

function	newpad
declaration	WINDOW *newpad(int l, int nc)
version		SUNW_1.1
end

function	newwin
declaration	WINDOW *newwin(int nlines, int ncols, int by, int bx)
version		SUNW_1.1
end

function	nocbreak
declaration	int nocbreak(void)
version		SUNW_1.1
end

function	nocrmode
declaration	int nocrmode(void)
version		SUNW_1.1
end

function	noraw
declaration	int noraw(void)
version		SUNW_1.1
end

function	pair_content
declaration	int pair_content(short pair, short *f, short *b)
version		SUNW_1.1
end

function	p32echochar extends libcurses/spec/curses.spec pechochar
version		SUNWprivate_1.1
end

function	pechochar
include		<curses.h>, <term.h>
declaration	int pechochar(WINDOW *win, chtype c)
version		SUNW_1.1
end

function	pechowchar
declaration	int pechowchar(WINDOW *pad, chtype ch)
version		SUNW_1.1
end

function	pnoutrefresh
declaration	int pnoutrefresh(WINDOW *pad, int pby, int pbx, int sby, \
			int sbx, int sey, int sex)
version		SUNW_1.1
end

function	printw
declaration	int printw(char *fmt, ...)
version		SUNW_1.1
end

function	prefresh
declaration	int prefresh(WINDOW *pad, int pminy, int pminx, int sminy, \
			int sminx, int smaxy, int smaxx)
version		SUNW_1.1
end

function	putwin
declaration	int putwin(WINDOW *win, FILE *filep)
version		SUNW_1.1
end

function	raw
declaration	int raw(void)
version		SUNW_1.1
end

function	redrawwin
include		<term.h>
declaration	int redrawwin(WINDOW *win)
version		SUNW_1.1
end

function	request_mouse_pos
declaration	int request_mouse_pos(void)
version		SUNWprivate_1.1
end

function	reset_prog_mode
declaration	int reset_prog_mode(void)
version		SUNW_1.1
end

function	reset_shell_mode
declaration	int reset_shell_mode(void)
version		SUNW_1.1
end

function	resetty
declaration	int resetty(void)
version		SUNW_1.1
end

function	ripoffline
declaration	int ripoffline(int line, int (*init)(WINDOW *, int))
version		SUNW_1.1
end

function	savetty
declaration	int savetty(void)
version		SUNW_1.1
end

function	scanw
declaration	int scanw(char *fmt, ...)
version		SUNW_1.1
end

function	scr_dump
declaration	int scr_dump(char *file)
version		SUNW_1.1
end

function	setcurscreen
include		<curses.h>, <term.h>
declaration	SCREEN *setcurscreen(SCREEN *new)
version		SUNWprivate_1.1
end

function	setcurterm
include		<curses.h>, <term.h>
declaration	TERMINAL *setcurterm(TERMINAL *newterminal)
version		SUNWprivate_1.1
end

function	setsyx
declaration	int setsyx(int y, int x)
version		SUNW_1.1
end

function	setupterm
declaration	int setupterm(char *term, int filenum, int *errret)
version		SUNW_1.1
end

function	slk_attroff
declaration	int slk_attroff(chtype a)
version		SUNW_1.1
end

function	slk_attron
declaration	int slk_attron(chtype a)
version		SUNW_1.1
end

function	slk_attrset
declaration	int slk_attrset(chtype a)
version		SUNW_1.1
end

function	slk_clear
declaration	int slk_clear(void)
version		SUNW_1.1
end

function	slk_label
declaration	char *slk_label(int n)
version		SUNW_1.1
end

function	slk_noutrefresh
declaration	int slk_noutrefresh(void)
version		SUNW_1.1
end

function	slk_refresh
declaration	int slk_refresh(void)
version		SUNW_1.1
end

function	slk_restore
declaration	int slk_restore(void)
version		SUNW_1.1
end

function	slk_set
declaration	int slk_set(int n, char *lab, int f)
version		SUNW_1.1
end

function	slk_start
declaration	int slk_start(int ng, int *gp)
version		SUNWprivate_1.1
end

function	slk_touch
declaration	int slk_touch(void)
version		SUNW_1.1
end

function	start_color
declaration	int start_color(void)
version		SUNW_1.1
end

function	termattrs
declaration	chtype termattrs(void)
version		SUNW_1.1
end

function	termname
declaration	char *termname(void)
version		SUNW_1.1
end

function	traceoff
declaration	int traceoff(void)
version		SUNWprivate_1.1
end

function	traceon
declaration	int traceon(void)
version		SUNWprivate_1.1
end

function	typeahead
declaration	int typeahead(int fd)
version		SUNW_1.1
end

function	unctrl
declaration	char *unctrl(int ch)
version		SUNW_1.1
end

function	ungetch
declaration	int ungetch(int ch)
version		SUNW_1.1
end

function	ungetwch
declaration	int ungetwch(wchar_t code)
version		SUNW_1.1
end

function	vidupdate
declaration	void vidupdate(chtype newmode, chtype oldmode, \
			int (*outc)(char))
version		SUNWprivate_1.1
end

function	vwprintw
declaration	int vwprintw(WINDOW *win, char *fmt, va_list ap)
version		SUNW_1.1
end

function	vwscanw
declaration	int vwscanw(WINDOW *win, char *fmt, va_list ap)
version		SUNW_1.1
end

function	w32addch extends libcurses/spec/curses.spec waddch
version		SUNWprivate_1.1
end

function	waddch
declaration	int waddch(WINDOW *win, chtype ch)
version		SUNW_1.1
end

function	waddchnstr
declaration	int waddchnstr(WINDOW *win, chtype *string, int ncols)
version		SUNW_1.1
end

function	waddnstr
declaration	int waddnstr(WINDOW *win, char *tstr, int i)
version		SUNW_1.1
end

function	waddnwstr
declaration	int waddnwstr(WINDOW *win, wchar_t *code, int n)
version		SUNW_1.1
end

function	waddwch
declaration	int waddwch(WINDOW *win, chtype c)
version		SUNW_1.1
end

function	waddwchnstr
declaration	int waddwchnstr(WINDOW *win, chtype *string, int ncols)
version		SUNW_1.1
end

function	w32attroff extends libcurses/spec/curses.spec wattroff
version		SUNWprivate_1.1
end

function	w32attron extends libcurses/spec/curses.spec wattron
version		SUNWprivate_1.1
end

function	w32attrset extends libcurses/spec/curses.spec wattrset
version		SUNWprivate_1.1
end

function	w32echochar extends libcurses/spec/curses.spec wechochar
version		SUNWprivate_1.1
end

function	w32insch extends libcurses/spec/curses.spec winsch
version		SUNWprivate_1.1
end

function	wattroff
declaration	int wattroff(WINDOW *win, chtype attrs)
version		SUNW_1.1
end

function	wattron
declaration	int wattron(WINDOW *win, chtype attrs)
version		SUNW_1.1
end

function	wattrset
declaration	int wattrset(WINDOW *win, chtype attrs)
version		SUNW_1.1
end

function	wbkgd
declaration	int wbkgd(WINDOW *win, chtype nbkgd)
version		SUNW_1.1
end

function	wborder
declaration	int wborder(WINDOW *win, chtype ls, chtype rs, chtype ts, \
			chtype bs, chtype tl, chtype tr, chtype bl, chtype br)
version		SUNW_1.1
end

function	wclrtobot
declaration	int wclrtobot(WINDOW *win)
version		SUNW_1.1
end

function	wclrtoeol
declaration	int wclrtoeol(WINDOW *win)
version		SUNW_1.1
end

function	wcursyncup
declaration	void wcursyncup(WINDOW *win)
version		SUNW_1.1
end

function	wdelch
declaration	int wdelch(WINDOW *win)
version		SUNW_1.1
end

function	wechochar
declaration	int wechochar(WINDOW *win, chtype c)
version		SUNW_1.1
end

function	wechowchar
declaration	int wechowchar(WINDOW *win, chtype ch)
version		SUNW_1.1
end

function	wgetch
declaration	int wgetch(WINDOW *win)
version		SUNW_1.1
end

function	wgetstr
declaration	int wgetstr(WINDOW *win, char *str)
version		SUNW_1.1
end

function	wgetnstr
declaration	int wgetnstr(WINDOW *win, char *str, int n)
version		SUNW_1.1
end

function	wgetnwstr
declaration	int wgetnwstr(WINDOW *win, wchar_t *str, int n)
version		SUNW_1.1
end

function	wgetwch
declaration	int wgetwch(WINDOW *win)
version		SUNW_1.1
end

function	wgetwstr
declaration	int wgetwstr(WINDOW *win, wchar_t *str)
version		SUNW_1.1
end

function	whline
declaration	int whline(WINDOW *win, chtype ch, int num_chars)
version		SUNW_1.1
end

function	winchnstr
declaration	int winchnstr(WINDOW *win, chtype *string, int ncols)
version		SUNW_1.1
end

function	winchstr
declaration	int winchstr(WINDOW *win, chtype *string)
version		SUNW_1.1
end

function	winnstr
declaration	int winnstr(WINDOW *win, char *string, int ncols)
version		SUNW_1.1
end

function	winnwstr
declaration	int winnwstr(WINDOW *win, wchar_t *wstr, int ncols)
version		SUNW_1.1
end

function	winsch
declaration	int winsch(WINDOW *win, chtype c)
version		SUNW_1.1
end

function	winsdelln
declaration	int winsdelln(WINDOW *win, int id)
version		SUNW_1.1
end

function	winsnstr
declaration	int winsnstr(WINDOW *win, char *tsp, int n)
version		SUNW_1.1
end

function	winsnwstr
declaration	int winsnwstr(WINDOW *win, wchar_t *code, int n)
version		SUNW_1.1
end

function	winstr
declaration	int winstr(WINDOW *win, char *str)
version		SUNW_1.1
end

function	winswch
declaration	int winswch(WINDOW *win, chtype c)
version		SUNW_1.1
end

function	winwch
declaration	chtype winwch(WINDOW *win)
version		SUNW_1.1
end

function	winwchnstr
declaration	int winwchnstr(WINDOW *win, chtype *string, int ncols)
version		SUNW_1.1
end

function	winwstr
declaration	int winwstr(WINDOW *win, wchar_t *wstr)
version		SUNW_1.1
end

function	wmouse_position
declaration	void wmouse_position(WINDOW *win, int *x, int *y)
version		SUNWprivate_1.1
end

function	wmove
declaration	int wmove(WINDOW *win, int y, int x)
version		SUNW_1.1
end

function	wnoutrefresh
declaration	int wnoutrefresh(WINDOW *win)
version		SUNW_1.1
end

function	wprintw
declaration	int wprintw(WINDOW *win, ...)
version		SUNW_1.1
end

function	wredrawln
declaration	int wredrawln(WINDOW *win, int begline, int numlines)
version		SUNW_1.1
end

function	wrefresh
declaration	int wrefresh(WINDOW *win)
version		SUNW_1.1
end

function	wscanw
declaration	int wscanw(WINDOW *win, ...)
version		SUNW_1.1
end

function	wscrl
declaration	int wscrl(WINDOW *win, int n)
version		SUNW_1.1
end

function	wsetscrreg
declaration	int wsetscrreg(WINDOW *win, int topy, int boty)
version		SUNW_1.1
end

function	wstandend
declaration	int wstandend(WINDOW *win)
version		SUNW_1.1
end

function	wstandout
declaration	int wstandout(WINDOW *win)
version		SUNW_1.1
end

function	wsyncdown
declaration	void wsyncdown(WINDOW *win)
version		SUNW_1.1
end

function	wsyncup
declaration	void wsyncup(WINDOW *win)
version		SUNW_1.1
end

function	wtouchln
declaration	int wtouchln(WINDOW *win, int y, int n, int changed)
version		SUNW_1.1
end

function	wvline
declaration	int wvline(WINDOW *win, chtype vertch, int num_chars)
version		SUNW_1.1
end

data		BC
version		SUNWprivate_1.1
end

data		COLORS
version		SUNWprivate_1.1
end

data		COLOR_PAIRS
version		SUNWprivate_1.1
end

data		COLS
version		SUNWprivate_1.1
end

data		Def_term
version		SUNWprivate_1.1
end

data		LINES
version		SUNWprivate_1.1
end

data		Mouse_status
version		SUNWprivate_1.1
end

data		Oldcolors
version		SUNWprivate_1.1
end

data		PC
version		SUNWprivate_1.1
end

data		SP
version		SUNWprivate_1.1
end

data		TABSIZE
version		SUNWprivate_1.1
end

data		UP
version		SUNWprivate_1.1
end

function	__sscans
declaration	int __sscans(WINDOW *win, char *fmt, ...)
version		SUNWprivate_1.1
end

function	_blast_keys
include		<curses.h>, <term.h>
declaration	void _blast_keys(TERMINAL *terminal)
version		SUNWprivate_1.1
end

function	_branchto
declaration	char *_branchto(char *cp, char to)
version		SUNWprivate_1.1
end

data		_called_before
version		SUNWprivate_1.1
end

function	_ccleanup
declaration	void _ccleanup(int signo)
version		SUNWprivate_1.1
end

function	_change_color
declaration	void _change_color(short newcolor, short oldcolor, \
			int (*outc)(char))
version		SUNWprivate_1.1
end

function	_change_video
include		<curses.h>, <term.h>
declaration	int _change_video(chtype newmode, chtype oldmode, int \
			(*outc)(char), bool color_terminal)
version		SUNWprivate_1.1
end

function	_chkinput
declaration	int _chkinput(void)
version		SUNWprivate_1.1
end

function	_countchar
declaration	int _countchar(void)
version		SUNWprivate_1.1
end

data		_csmax
version		SUNWprivate_1.1
end

function	_curs_mbstowcs
declaration	size_t _curs_mbstowcs(wchar_t *pwcs, const char *s, size_t n)
version		SUNWprivate_1.1
end

function	_curs_mbtowc
declaration	int _curs_mbtowc(wchar_t *wchar, const char *s, size_t n)
version		SUNWprivate_1.1
end

data		_curs_scrwidth
version		SUNWprivate_1.1
end

function	_curs_wcstombs
declaration	size_t _curs_wcstombs(char *s, const wchar_t *pwcs, size_t n)
version		SUNWprivate_1.1
end

function	_curs_wctomb
declaration	int _curs_wctomb(char *s, const wchar_t wchar)
version		SUNWprivate_1.1
end

function	_delay
declaration	int _delay(int delay, int (*outc)(char))
version		SUNWprivate_1.1
end

data		_do_slk_noref
version		SUNWprivate_1.1
end

data		_do_slk_ref
version		SUNWprivate_1.1
end

data		_do_slk_tch
version		SUNWprivate_1.1
end

data		_endwin
version		SUNWprivate_1.1
end

data		_first_term
version		SUNWprivate_1.1
end

data		_frst_bools
version		SUNWprivate_1.1
end

data		_frst_nums
version		SUNWprivate_1.1
end

data		_frst_strs
version		SUNWprivate_1.1
end

data		_frst_tblstr
version		SUNWprivate_1.1
end

function	_image
declaration	int _image(WINDOW *win)
version		SUNWprivate_1.1
end

function	_init_HP_pair
declaration	void _init_HP_pair(short pair, short f, short b)
version		SUNWprivate_1.1
end

function	_init_costs
declaration	void _init_costs(void)
version		SUNWprivate_1.1
end

data		_lib_version
version		SUNWprivate_1.1
end

function	_makenew
declaration	WINDOW *_makenew(int nlines, int ncols, int begy, int begx)
version		SUNWprivate_1.1
end

function	_mbaddch
declaration	int _mbaddch(WINDOW *win, chtype a, chtype b)
version		SUNWprivate_1.1
end

function	_mbclrch
declaration	int _mbclrch(WINDOW *win, int y, int x)
version		SUNWprivate_1.1
end

function	_mbinsshift
declaration	int _mbinsshift(WINDOW *win, int len)
version		SUNWprivate_1.1
end

data		_mbtrue
version		SUNWprivate_1.1
end

function	_mbvalid
declaration	int _mbvalid(WINDOW *win)
version		SUNWprivate_1.1
end

function	_outch
declaration	int _outch(char c)
version		SUNWprivate_1.1
end

function	_outchar
declaration	int _outchar(char ch)
version		SUNWprivate_1.1
end

function	_outwch
declaration	int _outwch(chtype c)
version		SUNWprivate_1.1
end

function	_overlap
declaration	int _overlap(WINDOW *Srcwin, WINDOW *Dstwin, int Overlay)
version		SUNWprivate_1.1
end

function	_padjust
declaration	int _padjust(WINDOW *pad, int pminy, int pminx, int sminy, \
			int sminx, int smaxy, int smaxx)
version		SUNWprivate_1.1
end

function	_prefresh
declaration	int _prefresh(int (*func)(WINDOW *), WINDOW *pad, int pminy, \
			int pminx, int sminy, int sminx, int smaxy, int smaxx)
version		SUNWprivate_1.1
end

function	_quick_echo
declaration	int _quick_echo(WINDOW *win, chtype ch)
version		SUNWprivate_1.1
end

data		_quick_ptr
version		SUNWprivate_1.1
end

data		_rip_init
version		SUNWprivate_1.1
end

function	_scr_all
declaration	int _scr_all(char *file, int which)
version		SUNWprivate_1.1
end

data		_scrmax
version		SUNWprivate_1.1
end

data		_setidln
version		SUNWprivate_1.1
end

data		_slk_init
version		SUNWprivate_1.1
end

function	_slk_update
declaration	int     _slk_update(void)
version		SUNWprivate_1.1
end

function	_sprintw
declaration	int _sprintw(WINDOW *win, char *fmt, ...)
version		SUNWprivate_1.1
end

function	_strbyte2code
declaration	wchar_t *_strbyte2code(char *code, wchar_t *byte, int n)
version		SUNWprivate_1.1
end

function	_strcode2byte
declaration	char *_strcode2byte(wchar_t *code, char *b, int n)
version		SUNWprivate_1.1
end

function	_tcsearch
declaration	int _tcsearch(char *cap, short offsets[], char *names[], \
			int size, int n)
version		SUNWprivate_1.1
end

function	_tstp
declaration	void _tstp(int dummy)
version		SUNWprivate_1.1
end

data		_unctrl
version		SUNWprivate_1.1
end

function	_update_old_y_area
declaration	void _update_old_y_area(WINDOW *win, int nlines, int ncols, \
			int start_line, int start_col)
version		SUNWprivate_1.1
end

data		_use_env
version		SUNWprivate_1.1
end

data		_useidln
version		SUNWprivate_1.1
end

data		_virtscr
version		SUNWprivate_1.1
end

data		_y16update
version		SUNWprivate_1.1
end

data		acs32map
version		SUNWprivate_1.1
end

data		acs_map
version		SUNWprivate_1.1
end

function	addch
declaration	int addch(chtype ch)
version		SUNW_1.1
end

function	addchnstr
declaration	int addchnstr(chtype *s, int n)
version		SUNW_1.1
end

function	addchstr
declaration	int addchstr(chtype *s)
version		SUNW_1.1
end

function	addnstr
declaration	int addnstr(char *s, int n)
version		SUNW_1.1
end

function	addnwstr
declaration	int addnwstr(wchar_t *s, int n)
version		SUNW_1.1
end

function	addstr
declaration	int addstr(char *s)
version		SUNW_1.1
end

function	addwch
declaration	int addwch(chtype ch)
version		SUNW_1.1
end

function	addwchnstr
declaration	int addwchnstr(chtype *str, int n)
version		SUNW_1.1
end

function	addwchstr
declaration	int addwchstr(chtype *str)
version		SUNW_1.1
end

function	addwstr
declaration	int addwstr(wchar_t *ws)
version		SUNW_1.1
end

function	attroff
declaration	int attroff(chtype at)
version		SUNW_1.1
end

function	attron
declaration	int attron(chtype at)
version		SUNW_1.1
end

function	attrset
declaration	int attrset(chtype at)
version		SUNW_1.1
end

function	beep
declaration	int beep(void)
version		SUNW_1.1
end

data		bit_attributes
version		SUNWprivate_1.1
end

data		bkgd
version		SUNW_1.1
end

function	bkgdset
declaration	void bkgdset(chtype c)
version		SUNW_1.1
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

function	border
declaration	int border(chtype ls, chtype rs, chtype ts, chtype bs, \
			chtype tl, chtype tr, chtype bl, chtype br)
version		SUNW_1.1
end

function	box32 extends libcurses/spec/curses.spec box
version		SUNWprivate_1.1
end

function	box
declaration	int box(WINDOW *win, chtype verch, chtype horch)
version		SUNW_1.1
end

function	cconvert
declaration	char *cconvert(char *string)
version		SUNWprivate_1.1
end

function	cexpand
declaration	char *cexpand(char *str)
version		SUNWprivate_1.1
end

function	clear
declaration	int clear(void)
version		SUNW_1.1
end

function	clearok
include		<curses.h>, <term.h>
declaration	int clearok(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	clrtobot
declaration	int clrtobot(void)
version		SUNW_1.1
end

function	clrtoeol
declaration	int clrtoeol(void)
version		SUNW_1.1
end

function	cpr
declaration	int cpr(FILE *f, char *c)
version		SUNWprivate_1.1
end

data		cswidth
version		SUNWprivate_1.1
end

data		cur_bools
version		SUNWprivate_1.1
end

data		cur_nums
version		SUNWprivate_1.1
end

data		cur_strs
version		SUNWprivate_1.1
end

data		cur_term
version		SUNWprivate_1.1
end

data		curs_err_strings
version		SUNWprivate_1.1
end

data		curs_errno
version		SUNWprivate_1.1
end

data		curs_parm_err
version		SUNWprivate_1.1
end

data		curscr
version		SUNWprivate_1.1
end

data		curses_version
version		SUNWprivate_1.1
end

function	del_curterm
include		<curses.h>, <term.h>
declaration	int del_curterm(TERMINAL *terminal)
version		SUNW_1.1
end

function	delch
declaration	int delch(void)
version		SUNW_1.1
end

function	deleteln
declaration	int deleteln(void)
version		SUNW_1.1
end

function	delkey
declaration	int delkey(char *sends, int keyval)
version		SUNWprivate_1.1
end

function	draino
declaration	int draino(int ms)
version		SUNWprivate_1.1
end

function	echo
declaration	int echo(void)
version		SUNW_1.1
end

function	echochar
declaration	int echochar(chtype ch)
version		SUNW_1.1
end

function	echowchar
declaration	int echowchar(chtype ch)
version		SUNW_1.1
end

function	erase
declaration	int erase(void)
version		SUNW_1.1
end

function	fixterm
declaration	int fixterm(void)
version		SUNWprivate_1.1
end

function	flash
declaration	int flash(void)
version		SUNW_1.1
end

function	force_doupdate
declaration	int force_doupdate(void)
version		SUNWprivate_1.1
end

function	garbagedlines
declaration	int garbagedlines(WINDOW  *win, int start, int finish)
version		SUNWprivate_1.1
end

function	garbagedwin
declaration	int garbagedwin(WINDOW  *win)
version		SUNWprivate_1.1
end

function	getattrs
declaration	chtype getattrs(WINDOW *win)
version		SUNWprivate_1.1
end

function	getbegx
declaration	int getbegx(WINDOW *win)
version		SUNWprivate_1.1
end

function	getbegy
declaration	int getbegy(WINDOW *win)
version		SUNWprivate_1.1
end

function	getbkgd
declaration	chtype getbkgd(WINDOW *win)
version		SUNWprivate_1.1
end

function	getch
declaration	int getch(void)
version		SUNW_1.1
end

function	getcurx
declaration	int getcurx(WINDOW *win)
version		SUNWprivate_1.1
end

function	getcury
declaration	int getcury(WINDOW *win)
version		SUNWprivate_1.1
end

function	getmaxx
declaration	int getmaxx(WINDOW *win)
version		SUNWprivate_1.1
end

function	getmaxy
declaration	int getmaxy(WINDOW *win)
version		SUNWprivate_1.1
end

function	getnwstr
declaration	int getnwstr(wchar_t *ws, int n)
version		SUNW_1.1
end

function	getparx
declaration	int getparx(WINDOW *win)
version		SUNWprivate_1.1
end

function	getpary
declaration	int getpary(WINDOW *win)
version		SUNWprivate_1.1
end

function	getstr
declaration	int getstr(char *str)
version		SUNW_1.1
end

function	gettmode
declaration	int gettmode(void)
version		SUNWprivate_1.1
end

function	getwch
declaration	int getwch(void)
version		SUNW_1.1
end

function	getwstr
declaration	int getwstr(wchar_t *ws)
version		SUNW_1.1
end

function	halfdelay
declaration	int halfdelay(int tens)
version		SUNW_1.1
end

function	hline
declaration	int hline(chtype horch, int num_chars)
version		SUNWprivate_1.1
end

function	idcok
include		<curses.h>, <term.h>
declaration	void idcok(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	inch
declaration	chtype inch(void)
version		SUNW_1.1
end

function	inchnstr
declaration	int inchnstr(chtype *s, int n)
version		SUNW_1.1
end

function	inchstr
declaration	int inchstr(chtype *s)
version		SUNW_1.1
end

function	iexpand
declaration	char *iexpand(char *string)
version		SUNWprivate_1.1
end

function	infotocap
declaration	char *infotocap(char *value, int *err)
version		SUNWprivate_1.1
end

function	init_acs
declaration	int init_acs(void)
version		SUNWprivate_1.1
end

function	innstr
declaration	int innstr(char *s, int n)
version		SUNW_1.1
end

function	innwstr
declaration	int innwstr(wchar_t *ws, int n);
version		SUNW_1.1
end

function	insch
declaration	int insch(chtype c)
version		SUNW_1.1
end

function	insdelln
declaration	int insdelln(int id)
version		SUNW_1.1
end

function	insertln
declaration	int insertln(void)
version		SUNW_1.1
end

function	insnstr
declaration	int insnstr(char *s, int n)
version		SUNW_1.1
end

function	insnwstr
declaration	int insnwstr(wchar_t *ws, int n)
version		SUNW_1.1
end

function	insstr
declaration	int insstr(char *s)
version		SUNW_1.1
end

function	instr
declaration	int instr(char *s)
version		SUNW_1.1
end

function	inswch
declaration	int inswch(chtype c)
version		SUNW_1.1
end

function	inswstr
declaration	int inswstr(wchar_t *ws)
version		SUNW_1.1
end

function	intrflush
declaration	int intrflush(WINDOW *win, int flag)
version		SUNW_1.1
end

function	inwch
declaration	chtype inwch(void)
version		SUNW_1.1
end

function	inwchnstr
declaration	int inwchnstr(chtype *str, int n)
version		SUNW_1.1
end

function	inwchstr
declaration	int inwchstr(chtype *str)
version		SUNW_1.1
end

function	inwstr
declaration	int inwstr(wchar_t *ws)
version		SUNW_1.1
end

function	is_linetouched
declaration	int is_linetouched(WINDOW *win, int line)
version		SUNW_1.1
end

function	is_wintouched
declaration	int is_wintouched(WINDOW *win)
version		SUNW_1.1
end

function	leaveok
include		<curses.h>, <term.h>
declaration	int leaveok(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	makenew
declaration	WINDOW *makenew(int nlines, int ncols, int begy, int begx)
version		SUNWprivate_1.1
end

function	mbcharlen
declaration	int mbcharlen(char *sp)
version		SUNWprivate_1.1
end

function	mbdisplen
declaration	int mbdisplen(char *sp)
version		SUNWprivate_1.1
end

function	mbeucw
declaration	int mbeucw(int c)
version		SUNWprivate_1.1
end

function	mbgetwidth
declaration	void mbgetwidth(void)
version		SUNWprivate_1.1
end

function	mbscrw
declaration	int mbscrw(int c)
version		SUNWprivate_1.1
end

function	memSset
declaration	void memSset(chtype *s, chtype c, int n)
version		SUNWprivate_1.1
end

function	meta
declaration	int meta(WINDOW *win, int flag)
version		SUNW_1.1
end

function	move
declaration	int move(int y, int x)
version		SUNW_1.1
end

function	mvaddch
declaration	int mvaddch(int y, int x, chtype ch)
version		SUNW_1.1
end

function	mvaddchnstr
declaration	int mvaddchnstr(int y, int x, chtype *s, int n)
version		SUNW_1.1
end

function	mvaddchstr
declaration	int mvaddchstr(int y, int x, chtype *s)
version		SUNW_1.1
end

function	mvaddnstr
declaration	int mvaddnstr(int y, int x, char *s, int n)
version		SUNW_1.1
end

function	mvaddnwstr
declaration	int mvaddnwstr(int y, int x, wchar_t *ws, int n)
version		SUNW_1.1
end

function	mvaddstr
declaration	int mvaddstr(int y, int x, char *str)
version		SUNW_1.1
end

function	mvaddwch
declaration	int mvaddwch(int y, int x, chtype ch)
version		SUNW_1.1
end

function	mvaddwchnstr
declaration	int mvaddwchnstr(int y, int x, chtype *str, int n)
version		SUNW_1.1
end

function	mvaddwchstr
declaration	int mvaddwchstr(int y, int x, chtype *s)
version		SUNW_1.1
end

function	mvaddwstr
declaration	int mvaddwstr(int y, int x, wchar_t *ws)
version		SUNW_1.1
end

function	mvdelch
declaration	int mvdelch(int y, int x)
version		SUNW_1.1
end

function	mvgetch
declaration	int mvgetch(int y, int x)
version		SUNW_1.1
end

function	mvgetnwstr
declaration	int mvgetnwstr(int y, int x, wchar_t *ws, int n)
version		SUNW_1.1
end

function	mvgetstr
declaration	int mvgetstr(int y, int x, char *str)
version		SUNW_1.1
end

function	mvgetwch
declaration	int mvgetwch(int y, int x)
version		SUNW_1.1
end

function	mvgetwstr
declaration	int mvgetwstr(int y, int x, wchar_t *ws)
version		SUNW_1.1
end

function	mvhline
declaration	int mvhline(int y, int x, chtype ch, int n)
version		SUNWprivate_1.1
end

function	mvinch
declaration	chtype mvinch(int y, int x)
version		SUNW_1.1
end

function	mvinchnstr
declaration	int mvinchnstr(int y, int x, chtype *str, int n)
version		SUNW_1.1
end

function	mvinchstr
declaration	int mvinchstr(int y, int x, chtype *str)
version		SUNW_1.1
end

function	mvinnstr
declaration	int mvinnstr(int y, int x, char *s, int n)
version		SUNW_1.1
end

function	mvinnwstr
declaration	int mvinnwstr(int y, int x, wchar_t *ws, int n)
version		SUNW_1.1
end

function	mvinsch
declaration	int mvinsch(int y, int x, chtype ch)
version		SUNW_1.1
end

function	mvinsnstr
declaration	int mvinsnstr(int y, int x, char *s, int n)
version		SUNW_1.1
end

function	mvinsnwstr
declaration	int mvinsnwstr(int y, int x, wchar_t *ws, int n)
version		SUNW_1.1
end

function	mvinsstr
declaration	int mvinsstr(int y, int x, char *s)
version		SUNW_1.1
end

function	mvinstr
declaration	int mvinstr(int y, int x, char *s)
version		SUNW_1.1
end

function	mvinswch
declaration	int mvinswch(int y, int x, chtype ch)
version		SUNW_1.1
end

function	mvinswstr
declaration	int mvinswstr(int y, int x, wchar_t *ws)
version		SUNW_1.1
end

function	mvinwch
declaration	chtype mvinwch(int y, int x)
version		SUNW_1.1
end

function	mvinwchnstr
declaration	int mvinwchnstr(int y, int x, chtype *str, int n)
version		SUNW_1.1
end

function	mvinwchstr
declaration	int mvinwchstr(int y, int x, chtype *str)
version		SUNW_1.1
end

function	mvinwstr
declaration	int mvinwstr(int y, int x, wchar_t *ws)
version		SUNW_1.1
end

function	mvvline
declaration	int mvvline(int y, int x, chtype c, int n)
version		SUNWprivate_1.1
end

function	mvwaddch
declaration	int mvwaddch(WINDOW *win, int y, int x, chtype ch)
version		SUNW_1.1
end

function	mvwaddchnstr
declaration	int mvwaddchnstr(WINDOW *win, int y, int x, chtype *ch, int n)
version		SUNW_1.1
end

function	mvwaddchstr
declaration	int mvwaddchstr(WINDOW *win, int y, int x, chtype *ch)
version		SUNW_1.1
end

function	mvwaddnstr
declaration	int mvwaddnstr(WINDOW *win, int y, int x, char *c, int n)
version		SUNW_1.1
end

function	mvwaddnwstr
declaration	int mvwaddnwstr(WINDOW *win, int y, int x, wchar_t *wc, int n)
version		SUNW_1.1
end

function	mvwaddstr
declaration	int mvwaddstr(WINDOW *win, int y, int x, char *str)
version		SUNW_1.1
end

function	mvwaddwch
declaration	int mvwaddwch(WINDOW *win, int y, int x, chtype ch)
version		SUNW_1.1
end

function	mvwaddwchnstr
declaration	int mvwaddwchnstr(WINDOW *win, int y, int x, chtype *str, int n)
version		SUNW_1.1
end

function	mvwaddwchstr
declaration	int mvwaddwchstr(WINDOW *win, int y, int x, chtype *str)
version		SUNW_1.1
end

function	mvwaddwstr
declaration	int mvwaddwstr(WINDOW *win, int y, int x, wchar_t *wc)
version		SUNW_1.1
end

function	mvwdelch
declaration	int mvwdelch(WINDOW *win, int y, int x)
version		SUNW_1.1
end

function	mvwgetch
declaration	int mvwgetch(WINDOW *win, int y, int x)
version		SUNW_1.1
end

function	mvwgetnwstr
declaration	int mvwgetnwstr(WINDOW *win, int y, int x, wchar_t *ws, int n)
version		SUNW_1.1
end

function	mvwgetstr
declaration	int mvwgetstr(WINDOW *win, int y, int x, char *str)
version		SUNW_1.1
end

function	mvwgetwch
declaration	int mvwgetwch(WINDOW *win, int y, int x)
version		SUNW_1.1
end

function	mvwgetwstr
declaration	int mvwgetwstr(WINDOW *win, int y, int x, wchar_t *ws)
version		SUNW_1.1
end

function	mvwhline
declaration	int mvwhline(WINDOW *win, int y, int x, chtype c, int n)
version		SUNWprivate_1.1
end

function	mvwinch
declaration	chtype mvwinch(WINDOW *win, int y, int x)
version		SUNW_1.1
end

function	mvwinchnstr
declaration	int mvwinchnstr(WINDOW *win, int y, int x, chtype *s, int n)
version		SUNW_1.1
end

function	mvwinchstr
declaration	int mvwinchstr(WINDOW *win, int y, int x, chtype *str)
version		SUNW_1.1
end

function	mvwinnstr
declaration	int mvwinnstr(WINDOW *win, int y, int x, char *str, int n)
version		SUNW_1.1
end

function	mvwinnwstr
declaration	int mvwinnwstr(WINDOW *win, int y, int x, wchar_t *ws, int n)
version		SUNW_1.1
end

function	mvwinsch
declaration	int mvwinsch(WINDOW *win, int y, int x, chtype c)
version		SUNW_1.1
end

function	mvwinsnstr
declaration	int mvwinsnstr(WINDOW *win, int y, int x, char *str, int n)
version		SUNW_1.1
end

function	mvwinsnwstr
declaration	int mvwinsnwstr(WINDOW *win, int y, int x, wchar_t *ws, int n)
version		SUNW_1.1
end

function	mvwinsstr
declaration	int mvwinsstr(WINDOW *win, int y, int x, char *str)
version		SUNW_1.1
end

function	mvwinstr
declaration	int mvwinstr(WINDOW *win, int y, int x, char *str)
version		SUNW_1.1
end

function	mvwinswch
declaration	int mvwinswch(WINDOW *win, int y, int x, chtype c)
version		SUNW_1.1
end

function	mvwinswstr
declaration	int mvwinswstr(WINDOW *win, int y, int x, wchar_t *ws)
version		SUNW_1.1
end

function	mvwinwch
declaration	chtype mvwinwch(WINDOW *win, int y, int x)
version		SUNW_1.1
end

function	mvwinwchnstr
declaration	int mvwinwchnstr(WINDOW *win, int y, int x, chtype *str, int n)
version		SUNW_1.1
end

function	mvwinwchstr
declaration	int mvwinwchstr(WINDOW *win, int y, int x, chtype *str)
version		SUNW_1.1
end

function	mvwinwstr
declaration	int mvwinwstr(WINDOW *win, int y, int x, wchar_t *ws)
version		SUNW_1.1
end

function	mvwvline
declaration	int mvwvline(WINDOW *win, int y, int x, chtype c, int n)
version		SUNWprivate_1.1
end

function	nl
declaration	int nl(void)
version		SUNW_1.1
end

function	nodelay
include		<curses.h>, <term.h>
declaration	int nodelay(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	noecho
declaration	int noecho(void)
version		SUNW_1.1
end

function	nonl
declaration	int nonl(void)
version		SUNW_1.1
end

function	noqiflush
declaration	void noqiflush(void)
version		SUNW_1.1
end

function	notimeout
include		<curses.h>, <term.h>
declaration	int notimeout(WINDOW *win, bool bf)
version		SUNW_1.1
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

data		ospeed
version		SUNWprivate_1.1
end

data		outchcount
version		SUNWprivate_1.1
end

function	overlay
declaration	int overlay(WINDOW *src, WINDOW *dst)
version		SUNW_1.1
end

function	overwrite
declaration	int overwrite(WINDOW *src, WINDOW *dst)
version		SUNW_1.1
end

data		prog_istermios
version		SUNWprivate_1.1
end

function	pr_bfooting
declaration	void pr_bfooting(void)
version		SUNWprivate_1.1
end

function	pr_bheading
declaration	void pr_bheading(void)
version		SUNWprivate_1.1
end

function	pr_boolean
declaration	void pr_boolean(char *infoname, char *capname, \
			char *fullname, int value)
version		SUNWprivate_1.1
end

function	pr_caprestrict
declaration	void pr_caprestrict(int onoff)
version		SUNWprivate_1.1
end

function	pr_heading
declaration	void pr_heading(char *term, char *synonyms)
version		SUNWprivate_1.1
end

function	pr_init
include		<print.h>
declaration	void pr_init(enum printtypes type)
version		SUNWprivate_1.1
end

function	pr_nfooting
declaration	void pr_nfooting(void)
version		SUNWprivate_1.1
end

function	pr_nheading
declaration	void pr_nheading(void)
version		SUNWprivate_1.1
end

function	pr_number
declaration	void pr_number(char *infoname, char *capname, \
			char *fullname, int value)
version		SUNWprivate_1.1
end

function	pr_onecolumn
declaration	void pr_onecolumn(int onoff)
version		SUNWprivate_1.1
end

function	pr_sfooting
declaration	void pr_sfooting(void)
version		SUNWprivate_1.1
end

function	pr_sheading
declaration	void pr_sheading(void)
version		SUNWprivate_1.1
end

function	pr_string
declaration	void pr_string(char *infoname, char *capname, \
			char *fullname, char *value)
version		SUNWprivate_1.1
end

function	pr_width
declaration	void pr_width(int nwidth)
version		SUNWprivate_1.1
end

data		progname
version		SUNWprivate_1.1
end

function	putp
declaration	int putp(char *str)
version		SUNW_1.1
end

function	qiflush
declaration	void qiflush(void)
version		SUNW_1.1
end

function	refresh
declaration	int refresh(void)
version		SUNW_1.1
end

function	resetterm
declaration	int resetterm(void)
version		SUNWprivate_1.1
end

function	restartterm
declaration	int restartterm(char * term, int filenum, int *errret)
version		SUNW_1.1
end

function	rmpadding
declaration	char *rmpadding(char *str, char *padbuffer, int *padding)
version		SUNWprivate_1.1
end

function	saveterm
declaration	int saveterm(void)
version		SUNWprivate_1.1
end

function	scr_init
declaration	int scr_init(char *file)
version		SUNW_1.1
end

function	scr_ll_dump
declaration	int scr_ll_dump(FILE *filep)
version		SUNWprivate_1.1
end

function	scr_reset
declaration	int scr_reset(FILE *filep, int type)
version		SUNWprivate_1.1
end

function	scr_restore
declaration	int scr_restore(char *file)
version		SUNW_1.1
end

function	scr_set
declaration	int scr_set(char *file)
version		SUNW_1.1
end

function	scrl
declaration	int scrl(int n)
version		SUNW_1.1
end

function	scroll
declaration	int scroll(WINDOW *win)
version		SUNW_1.1
end

function	scrollok
include		<curses.h>, <term.h>
declaration	int scrollok(WINDOW *win, bool bf)
version		SUNW_1.1
end

function	set_curterm
include		<curses.h>, <term.h>
declaration	TERMINAL *set_curterm(TERMINAL *newterminal)
version		SUNWprivate_1.1
end

function	set_term
include		<curses.h>, <term.h>
declaration	SCREEN *set_term(SCREEN *screen)
version		SUNW_1.1
end

function	setkeymap
declaration	int setkeymap(void)
version		SUNWprivate_1.1
end

function	setscrreg
declaration	int setscrreg(int t, int b)
version		SUNW_1.1
end

function	setterm
declaration	int setterm(char *name)
version		SUNW_1.1
end

data		shell_istermios
version		SUNWprivate_1.1
end

function	slk_init
declaration	int slk_init(int f)
version		SUNW_1.1
end

function	standend
declaration	int standend(void)
version		SUNW_1.1
end

function	standout
declaration	int standout(void)
version		SUNW_1.1
end

data		stdscr
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

function	subpad
include		<curses.h>, <term.h>
declaration	WINDOW *subpad(WINDOW *win, int l, int nc, int by, int bx)
version		SUNW_1.1
end

function	subwin
include		<curses.h>, <term.h>
declaration	WINDOW *subwin(WINDOW *win, int l, int nc, int by, int bx)
version		SUNW_1.1
end

function	syncok
include		<curses.h>, <term.h>
declaration	int syncok(WINDOW *win, bool bf)
version		SUNW_1.1
end

data		term_err_strings
version		SUNWprivate_1.1
end

data		term_errno
version		SUNWprivate_1.1
end

data		term_parm_err
version		SUNWprivate_1.1
end

function	termerr
declaration	void termerr(void)
version		SUNWprivate_1.1
end

function	tgetch
declaration	int tgetch(int interpret)
version		SUNWprivate_1.1
end

function	tgetent
declaration	int tgetent(char *bp, char *name)
version		SUNW_1.1
end

function	tgetflag
declaration	int tgetflag(char *tcstr)
version		SUNW_1.1
end

function	tgetnum
declaration	int tgetnum(char *tcstr)
version		SUNW_1.1
end

function	tgetstr
declaration	char *tgetstr(char *tcstr, char **area)
version		SUNW_1.1
end

function	tgetwch
declaration	wchar_t tgetwch(int cntl)
version		SUNWprivate_1.1
end

function	tgoto
declaration	char *tgoto(char *cap, int col, int row)
version		SUNW_1.1
end

function	tifgetflag
declaration	int tifgetflag(char *tistr)
version		SUNWprivate_1.1
end

function	tifgetnum
declaration	int tifgetnum(char *tistr)
version		SUNWprivate_1.1
end

function	tifgetstr
declaration	char *tifgetstr(char *tistr)
version		SUNWprivate_1.1
end

function	tigetflag
declaration	int tigetflag(char *tistr)
version		SUNW_1.1
end

function	tigetnum
declaration	int tigetnum(char *tistr)
version		SUNW_1.1
end

function	tigetstr
declaration	char *tigetstr(char *tistr)
version		SUNW_1.1
end

function	timeout
declaration	void timeout(int tm)
version		SUNW_1.1
end

function	tinputfd
declaration	void tinputfd(int fd)
version		SUNWprivate_1.1
end

function	touchline
include		<curses.h>, <term.h>
declaration	int touchline(WINDOW *win, int y, int n)
version		SUNW_1.1
end

function	touchwin
include		<curses.h>, <term.h>
declaration	int touchwin(WINDOW *win)
version		SUNW_1.1
end

function	tparm
declaration	char *tparm(char *str, long int p1, long int p2, long int p3, \
			long int p4, long int p5, long int p6, long int p7, \
			long int p8, long int p9)
version		SUNW_1.1
end

function	tparm_p0
declaration	char    *tparm_p0(char *instring)
version		SUNWprivate_1.1
end

function	tparm_p1
declaration	char    *tparm_p1(char *instring, long l1)
version		SUNWprivate_1.1
end

function	tparm_p2
declaration	char *tparm_p2(char *instring, long l1, long l2)
version		SUNWprivate_1.1
end

function	tparm_p3
declaration	char *tparm_p3(char *instring, long l1, long l2, long l3)
version		SUNWprivate_1.1
end

function	tparm_p4
declaration	char *tparm_p4(char *instring, long l1, long l2, \
			long l3, long l4)
version		SUNWprivate_1.1
end

function	tparm_p7
declaration	char *tparm_p7(char *instring, long l1, long l2, \
			long l3, long l4, long l5, long l6, long l7)
version		SUNWprivate_1.1
end

function	tpr
declaration	void tpr(FILE *stream, char *string)
version		SUNWprivate_1.1
end

function	tputs
declaration	int tputs(char *cp, int affcnt, int (*outc)(char))
version		SUNW_1.1
end

function	ttimeout
declaration	int ttimeout(int delay)
version		SUNWprivate_1.1
end

data		ttytype
version		SUNWprivate_1.1
end

function	untouchwin
include		<curses.h>, <term.h>
declaration	int untouchwin(WINDOW *win)
version		SUNW_1.1
end

function	use_env
declaration	void use_env(int bf)
version		SUNWprivate_1.1
end

function	vid32attr extends libcurses/spec/curses.spec vidattr
version		SUNWprivate_1.1
end

function	vid32puts extends libcurses/spec/curses.spec vidputs
version		SUNWprivate_1.1
end

function	vidattr
declaration	int vidattr(chtype newmode)
version		SUNW_1.1
end

function	vidputs
declaration	int vidputs(chtype a, int (*b)(char))
version		SUNW_1.1
end

function	vline
declaration	int vline(chtype vertch, int num_chars)
version		SUNWprivate_1.1
end

function	waddchstr
include		<curses.h>, <term.h>
declaration	int waddchstr(WINDOW *win, chtype *str)
version		SUNW_1.1
end

function	waddstr
include		<curses.h>, <term.h>
declaration	int waddstr(WINDOW *win, char *str)
version		SUNW_1.1
end

function	waddwchstr
include		<curses.h>, <term.h>
declaration	int waddwchstr(WINDOW *win, chtype *str)
version		SUNW_1.1
end

function	waddwstr
include		<curses.h>, <term.h>
declaration	int waddwstr(WINDOW *win, wchar_t *ws)
version		SUNW_1.1
end

function	wadjcurspos
include		<curses.h>, <term.h>
declaration	int wadjcurspos(WINDOW *win)
version		SUNW_1.1
end

function	wbkgdset
include		<curses.h>, <term.h>
declaration	void wbkgdset(WINDOW *win, chtype c)
version		SUNW_1.1
end

function	wclear
include		<curses.h>, <term.h>
declaration	int wclear(WINDOW *win)
version		SUNW_1.1
end

function	wcscrw
declaration	int wcscrw(wchar_t wc)
version		SUNWprivate_1.1
end

function	wdeleteln
include		<curses.h>, <term.h>
declaration	int wdeleteln(WINDOW *win)
version		SUNW_1.1
end

function	werase
include		<curses.h>, <term.h>
declaration	int werase(WINDOW *win)
version		SUNW_1.1
end

function	winch
include		<curses.h>, <term.h>
declaration	chtype winch(WINDOW *win)
version		SUNW_1.1
end

function	winsertln
include		<curses.h>, <term.h>
declaration	int winsertln(WINDOW *win)
version		SUNW_1.1
end

function	winsstr
include		<curses.h>, <term.h>
declaration	int winsstr(WINDOW *win, char *str)
version		SUNW_1.1
end

function	winswstr
include		<curses.h>, <term.h>
declaration	int winswstr(WINDOW *win, wchar_t *ws)
version		SUNW_1.1
end

function	winwchstr
include		<curses.h>, <term.h>
declaration	int winwchstr(WINDOW *win, chtype *str)
version		SUNW_1.1
end

function	wmbinch
include		<curses.h>, <term.h>
declaration	char *wmbinch(WINDOW *win, int y, int x)
version		SUNWprivate_1.1
end

function	wmbmove
include		<curses.h>, <term.h>
declaration	int wmbmove(WINDOW *win, int y, int x)
version		SUNWprivate_1.1
end

function	wmovenextch
include		<curses.h>, <term.h>
declaration	int wmovenextch(WINDOW *win)
version		SUNW_1.1
end

function	wmoveprevch
include		<curses.h>, <term.h>
declaration	int wmoveprevch(WINDOW *win)
version		SUNW_1.1
end

function	wtimeout
include		<curses.h>, <term.h>
declaration	void wtimeout(WINDOW *win, int tm)
version		SUNW_1.1
end

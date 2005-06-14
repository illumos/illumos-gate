/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_CURSES_H
#define	_CURSES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WINDOW

#include	<stdio.h>
#include	<sgtty.h>

#undef		HZ		/* in case they've included <sys/param.h> */

#if !(defined(__cplusplus) && defined(_BOOL))
#define	bool	char
#endif

#define	reg	register

#define	TRUE	(1)
#define	FALSE	(0)
#define	ERR	(0)
#define	OK	(1)

#define	_ENDLINE	001
#define	_FULLWIN	002
#define	_SCROLLWIN	004
#define	_FLUSH		010
#define	_FULLLINE	020
#define	_IDLINE		040
#define	_STANDOUT	0200
#define	_NOCHANGE	-1

#define	_puts(s)	tputs(s, 0, _putchar)

typedef	struct sgttyb	SGTTY;

/*
 * Capabilities from termcap
 */

extern	bool	AM, BS, CA, DA, DB, EO, HC, HZ, IN, MI, MS, NC, NS, OS, UL,
		XB, XN, XT, XS, XX;
extern	char	*AL, *BC, *BT, *CD, *CE, *CL, *CM, *CR, *CS, *DC, *DL,
		*DM, *DO, *ED, *EI, *K0, *K1, *K2, *K3, *K4, *K5, *K6,
		*K7, *K8, *K9, *HO, *IC, *IM, *IP, *KD, *KE, *KH, *KL,
		*KR, *KS, *KU, *LL, *MA, *ND, *NL, *RC, *SC, *SE, *SF,
		*SO, *SR, *TA, *TE, *TI, *UC, *UE, *UP, *US, *VB, *VS,
		*VE, *AL_PARM, *DL_PARM, *UP_PARM, *DOWN_PARM,
		*LEFT_PARM, *RIGHT_PARM;
extern char	PC;

/*
 * From the tty modes...
 */

extern bool	GT, NONL, UPPERCASE, normtty, _pfast;

struct _win_st {
	short		_cury, _curx;
	short		_maxy, _maxx;
	short		_begy, _begx;
	short		_flags;
	short		_ch_off;
	bool		_clear;
	bool		_leave;
	bool		_scroll;
	char		**_y;
	short		*_firstch;
	short		*_lastch;
	struct _win_st	*_nextp, *_orig;
};

#define	WINDOW	struct _win_st

extern bool	My_term, _echoit, _rawmode, _endwin;

extern char	*Def_term, ttytype[50];

extern int	LINES, COLS, _tty_ch, _res_flg;

extern SGTTY	_tty;

extern WINDOW	*stdscr, *curscr;

#define	VOID(x)	(x)

/*
 * pseudo functions for standard screen
 */
#define	addch(ch)	VOID(waddch(stdscr, ch))
#define	getch()		VOID(wgetch(stdscr))
#define	addstr(str)	VOID(waddstr(stdscr, str))
#define	getstr(str)	VOID(wgetstr(stdscr, str))
#define	move(y, x)	VOID(wmove(stdscr, y, x))
#define	clear()		VOID(wclear(stdscr))
#define	erase()		VOID(werase(stdscr))
#define	clrtobot()	VOID(wclrtobot(stdscr))
#define	clrtoeol()	VOID(wclrtoeol(stdscr))
#define	insertln()	VOID(winsertln(stdscr))
#define	deleteln()	VOID(wdeleteln(stdscr))
#define	refresh()	VOID(wrefresh(stdscr))
#define	inch()		VOID(winch(stdscr))
#define	insch(c)	VOID(winsch(stdscr, c))
#define	delch()		VOID(wdelch(stdscr))
#define	standout()	VOID(wstandout(stdscr))
#define	standend()	VOID(wstandend(stdscr))

/*
 * mv functions
 */
#define	mvwaddch(win, y, x, ch)	VOID(wmove(win, y, x) == ERR ? \
				ERR:waddch(win, ch))
#define	mvwgetch(win, y, x)	VOID(wmove(win, y, x) == ERR?ERR:wgetch(win))
#define	mvwaddstr(win, y, x, str)	VOID(wmove(win, y, x) == ERR? \
					ERR:waddstr(win, str))
#define	mvwgetstr(win, y, x, str)	VOID(wmove(win, y, x) == ERR? \
					ERR:wgetstr(win, str))
#define	mvwinch(win, y, x)	VOID(wmove(win, y, x) == ERR ? ERR : winch(win))
#define	mvwdelch(win, y, x)	VOID(wmove(win, y, x) == ERR ? \
				ERR : wdelch(win))
#define	mvwinsch(win, y, x, c)	VOID(wmove(win, y, x) == ERR ? \
				ERR:winsch(win, c))
#define	mvaddch(y, x, ch)	mvwaddch(stdscr, y, x, ch)
#define	mvgetch(y, x)		mvwgetch(stdscr, y, x)
#define	mvaddstr(y, x, str)	mvwaddstr(stdscr, y, x, str)
#define	mvgetstr(y, x, str)	mvwgetstr(stdscr, y, x, str)
#define	mvinch(y, x)		mvwinch(stdscr, y, x)
#define	mvdelch(y, x)		mvwdelch(stdscr, y, x)
#define	mvinsch(y, x, c)	mvwinsch(stdscr, y, x, c)

/*
 * pseudo functions
 */

#define	clearok(win, bf)	(win->_clear = bf)
#define	leaveok(win, bf)	(win->_leave = bf)
#define	scrollok(win, bf)	(win->_scroll = bf)
#define	flushok(win, bf)	(bf ? (win->_flags |= _FLUSH): \
				(win->_flags &= ~_FLUSH))
#define	getyx(win, y, x)	 y = win->_cury, x = win->_curx
#define	winch(win)		(win->_y[win->_cury][win->_curx] & 0177)

#define	raw()	 (_tty.sg_flags |= RAW, _pfast = _rawmode = TRUE, \
		(void) stty(_tty_ch, &_tty))
#define	noraw()  (_tty.sg_flags &= ~RAW, _rawmode = FALSE, \
		_pfast = !(_tty.sg_flags & CRMOD), (void) stty(_tty_ch, &_tty))
#define	cbreak() (_tty.sg_flags |= CBREAK, _rawmode = TRUE, \
		(void) stty(_tty_ch, &_tty))
#define	nocbreak() (_tty.sg_flags &= ~CBREAK, _rawmode = FALSE, \
		(void) stty(_tty_ch, &_tty))
#define	crmode() cbreak()	/* backwards compatability */
#define	nocrmode() nocbreak()	/* backwards compatability */
#define	echo()	 (_tty.sg_flags |= ECHO, _echoit = TRUE, \
		(void) stty(_tty_ch, &_tty))
#define	noecho() (_tty.sg_flags &= ~ECHO, _echoit = FALSE, \
		(void) stty(_tty_ch, &_tty))
#define	nl()	 (_tty.sg_flags |= CRMOD, _pfast = _rawmode, \
		(void) stty(_tty_ch, &_tty))
#define	nonl()	 (_tty.sg_flags &= ~CRMOD, _pfast = TRUE, \
		(void) stty(_tty_ch, &_tty))
#define	savetty() ((void) gtty(_tty_ch, &_tty), _res_flg = _tty.sg_flags)
#define	resetty() (_tty.sg_flags = _res_flg, (void) stty(_tty_ch, &_tty))

#define	erasechar()	(_tty.sg_erase)
#define	killchar()	(_tty.sg_kill)
#define	baudrate()	(_tty.sg_ospeed)

/*
 * chtype is the type used to store a character together with attributes.
 * It can be set to "char" to save space, or "int" to get more attributes.
 */
#ifdef CHTYPE
typedef CHTYPE chtype;
#else
typedef unsigned int chtype;
#endif

#ifndef __STDC__
WINDOW	*initscr(), *newwin(), *subwin();
char	*longname(), *getcap();
#else
extern WINDOW *initscr(void);
extern WINDOW *newwin(int, int, int, int);
extern WINDOW *subwin(WINDOW *, int, int, int, int);
extern char *longname(char *, char *);
extern char *getcap(char *);
extern char *wstandout(WINDOW *);
extern char *wstandend(WINDOW *);
extern int gettmode(void);
extern int idlok(WINDOW *, bool);
extern int box(WINDOW *, char, char);
extern int touchwin(WINDOW *);
extern int touchline(WINDOW *, int, int, int);
extern int mvcur(int, int, int, int);
extern int wmove(WINDOW *, int, int);
extern int scroll(WINDOW *);
extern int werase(WINDOW *);
extern int wrefresh(WINDOW *);
extern int endwin(void);
extern int mvwin(WINDOW *, int, int);
extern int delwin(WINDOW *);
extern int overlay(WINDOW *, WINDOW *);
extern int overwrite(WINDOW *, WINDOW *);
extern int winsertln(WINDOW *);
extern int wdeleteln(WINDOW *);
extern int wgetstr(WINDOW *, char *);
extern int wgetch(WINDOW *);
extern int waddch(WINDOW *, char);
extern int waddstr(WINDOW *, char *);
extern int winsch(WINDOW *, char);
extern int wdelch(WINDOW *);
extern int wclear(WINDOW *);
extern int wclrtobot(WINDOW *);
extern int wclrtoeol(WINDOW *);
extern int printw(char *, ...);
extern int wprintw(WINDOW *, char *, ...);
extern int mvprintw(int, int, char *, ...);
extern int mvwprintw(WINDOW *, int, int, char *, ...);
extern int scanw(char *, ...);
extern int wscanw(WINDOW *, char *, ...);
extern int mvscanw(int, int, char *, ...);
extern int mvwscanw(WINDOW *, int, int, char *, ...);
extern int setterm(char *);
#endif	/* __STDC__ */

/*
 * Used to be in unctrl.h.
 */
#define	unctrl(c)	_unctrl[(c) & 0177]
extern char *_unctrl[];
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _CURSES_H */

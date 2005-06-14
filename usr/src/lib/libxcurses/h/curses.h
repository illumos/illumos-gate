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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * curses.h
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifndef __M_CURSES_H__
#define __M_CURSES_H__

#define _XOPEN_CURSES

#include <stdio.h>
#include <term.h>
#include <unctrl.h>
#include <wchar.h>

#ifndef EOF
#define EOF			(-1)
#endif

#ifndef WEOF
#define WEOF			(-1)
#endif

/*
 * Not all <wchar.h> are created equal.
 */
#ifndef _MBSTATE_T
#define _MBSTATE_T
typedef int mbstate_t;
#endif

#define ERR			EOF
#define OK			0

#if !(defined(__cplusplus) && defined(_BOOL))
typedef	short bool;
#endif

#define TRUE    		1
#define FALSE   		0

typedef unsigned short attr_t;

/*
 * These attributes and masks can be applied to an attr_t.  
 * These are ordered according to the <no_color_video> mask,
 * which has been extended to include additional attributes.
 */
#define WA_NORMAL	0x0
#define WA_STANDOUT	0x0001
#define WA_UNDERLINE	0x0002
#define WA_REVERSE	0x0004
#define WA_BLINK	0x0008
#define WA_DIM		0x0010
#define WA_BOLD		0x0020
#define WA_INVIS	0x0040
#define WA_PROTECT	0x0080
#define WA_ALTCHARSET	0x0100
#define WA_HORIZONTAL	0x0200
#define WA_LEFT		0x0400
#define WA_LOW		0x0800
#define WA_RIGHT	0x1000
#define WA_TOP		0x2000
#define WA_VERTICAL	0x4000

#define WA_SGR_MASK	0x01ff		/* Historical attribute set. */
#define WA_SGR1_MASK	0x7e00		/* Extended attribute set. */

/*
 * Internal attribute used to support <ceol_standout_glitch>.
 */
#define WA_COOKIE	0x8000

/*
 * Color names.
 */
#define COLOR_BLACK     0
#define COLOR_BLUE      1
#define COLOR_GREEN     2
#define COLOR_CYAN      3
#define COLOR_RED       4
#define COLOR_MAGENTA   5
#define COLOR_YELLOW    6
#define COLOR_WHITE     7

/*
 * A cchar_t details the attributes, color, and a string of wide characters 
 * composing a complex character (p12).  The wide character string consists
 * of a spacing character (wcwidth() > 0) and zero or more non-spacing 
 * characters.  Xcurses (p17) states that the minimum number of non-spacing 
 * characters associated with a spacing character must be at least 5, if a 
 * limit is imposed.
 */
#define M_CCHAR_MAX	6

/***
 *** Opaque data type.  Keep your grubby mits off.
 ***/
typedef struct {
	short _f;			/* True if start of character. */ 
	short _n;			/* Number of elements in wc[]. */
        short _co;			/* Color pair number. */
        attr_t _at;			/* Attribute flags. */
        wchar_t _wc[M_CCHAR_MAX];	/* Complex spacing character. */
} cchar_t;

/***
 *** Opaque data type.  Keep your grubby mits off.
 ***/
typedef struct window_t {
	cchar_t _bg;			/* Background. */ 
	cchar_t _fg;			/* Foreground, ignore character. */
	short _cury, _curx;		/* Curent cursor position in window. */
	short _begy, _begx;		/* Upper-left origin on screen. */
	short _maxy, _maxx;		/* Window dimensions. */
	short _top, _bottom;		/* Window's software scroll region. */
	short _refy, _refx;		/* Pad origin of last refresh. */ 
	short _sminy, _sminx;		/* T-L screen corner of last refresh. */
	short _smaxy, _smaxx;		/* B-R screen corner of last refresh. */
	short _vmin, _vtime;		/* wtimeout() control. */
	short *_first, *_last;		/* Dirty region for each screen line. */
	unsigned short _flags;		/* Internal flags for the window. */
	unsigned short _scroll;		/* Internal for scroll optimization. */
	cchar_t **_line;
	cchar_t *_base;			/* Block of M*N screen cells. */
	struct window_t *_parent;	/* Parent of sub-window. */
} WINDOW;

/***
 *** Opaque data type.  Keep your grubby mits off.
 ***/
typedef struct {
	int _kfd;		/* typeahead() file descriptor. */
	FILE *_if, *_of;	/* I/O file pointers. */
	TERMINAL *_term;	/* Associated terminfo entry. */
	WINDOW *_newscr;	/* New screen image built by wnoutrefresh(). */
	WINDOW *_curscr;	/* Current screen image after doupdate(). */
	mbstate_t _state;	/* Current multibyte state of _of. */
	unsigned long *_hash;	/* Hash values for curscr's screen lines. */
	unsigned short _flags;	/* Assorted flags. */
	void *_decode;		/* Function key decode tree. */
	void *_in;		/* Wide I/O object. */
	struct {
		int _size;	/* Allocated size of the input stack. */
		int _count;	/* Number of entries on the input stack. */
		int *_stack;	/* Buffer used for the input stack. */
	} _unget;
	struct {
		WINDOW *_w;	/* Exists on if emulating soft label keys. */
		char *_labels[8];	/* Soft label key strings. */
		short _justify[8];	/* Justification for label. */
	} _slk;
} SCREEN;

#ifndef __M_UNCTRL_H__
/*
 * Backwards compatiblity with historical Curses applications.
 */
typedef unsigned long chtype;
#endif

/*
 * These attributes and masks can be applied to a chtype.  
 * They are order according to the <no_color_video> mask.
 */
#define A_NORMAL        0x00000000L
#define A_ATTRIBUTES    0xffff0000L	/* Color/Attribute mask */
#define A_CHARTEXT      0x0000ffffL     /* 16-bit character mask */
#define A_COLOR         0xfe000000L     /* Colour mask, see __COLOR_SHIFT */
#define A_STANDOUT      0x00010000L
#define A_UNDERLINE     0x00020000L
#define A_REVERSE       0x00040000L
#define A_BLINK         0x00080000L
#define A_DIM           0x00100000L
#define A_BOLD          0x00200000L
#define A_INVIS         0x00400000L
#define A_PROTECT       0x00800000L
#define A_ALTCHARSET    0x01000000L

/*
 * Colour atttribute support for chtype. 
 */
#define __COLOR_SHIFT	26

/*
 * Characters constants used with a chtype.
 * Mapping defined in Xcurses Section 6.2.12 (p260).
 */
#define ACS_VLINE       (A_ALTCHARSET | 'x')
#define ACS_HLINE       (A_ALTCHARSET | 'q')
#define ACS_ULCORNER    (A_ALTCHARSET | 'l')
#define ACS_URCORNER    (A_ALTCHARSET | 'k')
#define ACS_LLCORNER    (A_ALTCHARSET | 'm')
#define ACS_LRCORNER    (A_ALTCHARSET | 'j')
#define ACS_RTEE        (A_ALTCHARSET | 'u')
#define ACS_LTEE        (A_ALTCHARSET | 't')
#define ACS_BTEE        (A_ALTCHARSET | 'v')
#define ACS_TTEE        (A_ALTCHARSET | 'w')
#define ACS_PLUS        (A_ALTCHARSET | 'n')
#define ACS_S1          (A_ALTCHARSET | 'o')
#define ACS_S9          (A_ALTCHARSET | 's')
#define ACS_DIAMOND     (A_ALTCHARSET | '`')
#define ACS_CKBOARD     (A_ALTCHARSET | 'a')
#define ACS_DEGREE      (A_ALTCHARSET | 'f')
#define ACS_PLMINUS     (A_ALTCHARSET | 'g')
#define ACS_BULLET      (A_ALTCHARSET | '~')
#define ACS_LARROW      (A_ALTCHARSET | ',')
#define ACS_RARROW      (A_ALTCHARSET | '+')
#define ACS_DARROW      (A_ALTCHARSET | '.')
#define ACS_UARROW      (A_ALTCHARSET | '-')
#define ACS_BOARD       (A_ALTCHARSET | 'h')
#define ACS_LANTERN     (A_ALTCHARSET | 'I')
#define ACS_BLOCK       (A_ALTCHARSET | '0')
 
#ifndef _XOPEN_SOURCE
/*
 * MKS Extensions for double width box characters.
 */
#define ACS_DVLINE      ACS_VLINE
#define ACS_DHLINE      ACS_HLINE
#define ACS_DULCORNER   ACS_ULCORNER
#define ACS_DURCORNER   ACS_URCORNER
#define ACS_DLLCORNER   ACS_LLCORNER
#define ACS_DLRCORNER   ACS_LRCORNER
#define ACS_DRTEE       ACS_RTEE
#define ACS_DLTEE       ACS_LTEE
#define ACS_DBTEE       ACS_BTEE
#define ACS_DTTEE       ACS_TTEE
#endif /* _XOPEN_SOURCE */

/*
 * Wide characters constants for a cchar_t. 
 */
extern const cchar_t __WACS_VLINE;
extern const cchar_t __WACS_HLINE;
extern const cchar_t __WACS_ULCORNER;
extern const cchar_t __WACS_URCORNER;
extern const cchar_t __WACS_LLCORNER;
extern const cchar_t __WACS_LRCORNER;
extern const cchar_t __WACS_RTEE;
extern const cchar_t __WACS_LTEE;
extern const cchar_t __WACS_BTEE;
extern const cchar_t __WACS_TTEE;
extern const cchar_t __WACS_PLUS;
extern const cchar_t __WACS_S1;
extern const cchar_t __WACS_S9;
extern const cchar_t __WACS_DIAMOND;
extern const cchar_t __WACS_CKBOARD;
extern const cchar_t __WACS_DEGREE;
extern const cchar_t __WACS_PLMINUS;
extern const cchar_t __WACS_BULLET;
extern const cchar_t __WACS_LARROW;
extern const cchar_t __WACS_RARROW;
extern const cchar_t __WACS_DARROW;
extern const cchar_t __WACS_UARROW;
extern const cchar_t __WACS_BOARD;
extern const cchar_t __WACS_LANTERN;
extern const cchar_t __WACS_BLOCK;

#define WACS_VLINE	&__WACS_VLINE
#define WACS_HLINE	&__WACS_HLINE
#define WACS_ULCORNER	&__WACS_ULCORNER
#define WACS_URCORNER	&__WACS_URCORNER
#define WACS_LLCORNER	&__WACS_LLCORNER
#define WACS_LRCORNER	&__WACS_LRCORNER
#define WACS_RTEE	&__WACS_RTEE
#define WACS_LTEE	&__WACS_LTEE
#define WACS_BTEE	&__WACS_BTEE
#define WACS_TTEE	&__WACS_TTEE
#define WACS_PLUS	&__WACS_PLUS
#define WACS_S1		&__WACS_S1
#define WACS_S9		&__WACS_S9
#define WACS_DIAMOND	&__WACS_DIAMOND
#define WACS_CKBOARD	&__WACS_CKBOARD
#define WACS_DEGREE	&__WACS_DEGREE
#define WACS_PLMINUS	&__WACS_PLMINUS
#define WACS_BULLET	&__WACS_BULLET
#define WACS_LARROW	&__WACS_LARROW
#define WACS_RARROW	&__WACS_RARROW
#define WACS_DARROW	&__WACS_DARROW
#define WACS_UARROW	&__WACS_UARROW
#define WACS_BOARD	&__WACS_BOARD
#define WACS_LANTERN	&__WACS_LANTERN
#define WACS_BLOCK	&__WACS_BLOCK
 
#ifndef _XOPEN_SOURCE
/*
 * MKS Extensions for double width box characters.
 */
#define WACS_DVLINE      WACS_VLINE
#define WACS_DHLINE      WACS_HLINE
#define WACS_DULCORNER   WACS_ULCORNER
#define WACS_DURCORNER   WACS_URCORNER
#define WACS_DLLCORNER   WACS_LLCORNER
#define WACS_DLRCORNER   WACS_LRCORNER
#define WACS_DRTEE       WACS_RTEE
#define WACS_DLTEE       WACS_LTEE
#define WACS_DBTEE       WACS_BTEE
#define WACS_DTTEE       WACS_TTEE
#endif /* _XOPEN_SOURCE */

/*
 * Internal functions.
 */
extern int __m_outc(int);
extern int __m_tty_wc(int, wchar_t *);
extern int __m_chtype_cc(chtype, cchar_t *);
extern chtype __m_cc_chtype(const cchar_t *);
extern int __m_copywin(const WINDOW *, WINDOW *, int);
extern WINDOW *__m_newwin(WINDOW *, int, int, int, int);
 
/*
 * Internal macros.
 */
#define __m_getpary(w)		((w)->_parent == (WINDOW *) 0 ? -1 \
				: (w)->_begy - (w)->_parent->_begy)
#define __m_getparx(w)		((w)->_parent == (WINDOW *) 0 ? -1 \
				: (w)->_begx - (w)->_parent->_begx)

/*
 * Global Window Macros
 */
#define getyx(w,y,x)            (y = (w)->_cury, x = (w)->_curx)
#define getbegyx(w,y,x)         (y = (w)->_begy, x = (w)->_begx)
#define getmaxyx(w,y,x)         (y = (w)->_maxy, x = (w)->_maxx)
#define getparyx(w,y,x)         (y = __m_getpary(w), x = __m_getparx(w))

/*
 * Global variables
 */
extern int LINES, COLS;
extern int COLORS, COLOR_PAIRS;
extern WINDOW *curscr, *stdscr;

#ifndef _XOPEN_SOURCE
/*
 * Non-portable extension functions.
 */
extern int wistombs(char *, const wint_t *, int);
extern int wistowcs(wchar_t *, const wint_t *, int);
#endif /* _XOPEN_SOURCE */

#ifdef M_CURSES_TRACE
/*
 * Curses trace facility is only available with a version of 
 * the library that was compiled with -DM_CURSES_TRACE. 
 */
extern void traceoff(void);
extern void traceon(void);
#endif /* M_CURSES_TRACE */

extern int addch(chtype);
extern int addchnstr(const chtype *, int);
extern int addchstr(const chtype *);
extern int add_wch(const cchar_t *);
extern int add_wchnstr(const cchar_t *, int);
extern int add_wchstr(const cchar_t *);
extern int mvaddch(int, int, chtype);
extern int mvaddchnstr(int, int, const chtype *, int);
extern int mvaddchstr(int, int, const chtype *);
extern int mvadd_wch(int, int, const cchar_t *);
extern int mvadd_wchnstr(int, int, const cchar_t *, int);
extern int mvadd_wchstr(int, int, const cchar_t *);
extern int mvwaddch(WINDOW *, int, int, chtype);
extern int mvwaddchnstr(WINDOW *, int, int, const chtype *, int);
extern int mvwaddchstr(WINDOW *, int, int, const chtype *);
extern int mvwadd_wch(WINDOW *, int, int, const cchar_t *);
extern int mvwadd_wchnstr(WINDOW *, int, int, const cchar_t *, int);
extern int mvwadd_wchstr(WINDOW *, int, int, const cchar_t *);
extern int waddch(WINDOW *, chtype);
extern int waddchnstr(WINDOW *, const chtype *, int);
extern int waddchstr(WINDOW *, const chtype *);
extern int wadd_wch(WINDOW *, const cchar_t *);
extern int wadd_wchnstr(WINDOW *, const cchar_t *, int);
extern int wadd_wchstr(WINDOW *, const cchar_t *);

extern int addnstr(const char *, int);
extern int addstr(const char *);
extern int addnwstr(const wchar_t *, int);
extern int addwstr(const wchar_t *);
extern int mvaddnstr(int, int, const char *, int);
extern int mvaddstr(int, int, const char *);
extern int mvaddnwstr(int, int, const wchar_t *, int);
extern int mvaddwstr(int, int, const wchar_t *);
extern int mvwaddnstr(WINDOW *, int, int, const char *, int);
extern int mvwaddstr(WINDOW *, int, int, const char *);
extern int mvwaddnwstr(WINDOW *, int, int, const wchar_t *, int);
extern int mvwaddwstr(WINDOW *, int, int, const wchar_t *);
extern int waddnstr(WINDOW *, const char *, int);
extern int waddstr(WINDOW *, const char *);
extern int waddnwstr(WINDOW *, const wchar_t *, int);
extern int waddwstr(WINDOW *, const wchar_t *);

extern int attroff(int);
extern int attron(int);
extern int attrset(int);
extern int wattroff(WINDOW *, int);
extern int wattron(WINDOW *, int);
extern int wattrset(WINDOW *, int);

extern int attr_get(attr_t *, short *, void *);
extern int attr_off(attr_t, void *);
extern int attr_on(attr_t, void *);
extern int attr_set(attr_t, short, void *);
extern int color_set(short, void *);
extern int wattr_get(WINDOW *, attr_t *, short *, void *);
extern int wattr_off(WINDOW *, attr_t, void *);
extern int wattr_on(WINDOW *, attr_t, void *);
extern int wattr_set(WINDOW *, attr_t, short, void *);
extern int wcolor_set(WINDOW *, short, void *);

extern chtype COLOR_PAIR(short);
extern short PAIR_NUMBER(chtype);

extern int baudrate(void);

extern int delay_output(int);
extern int napms(int);

extern int beep(void);
extern int flash(void);

extern int bkgd(chtype);
extern int bkgdset(chtype);
extern chtype getbkgd(WINDOW *);
extern int wbkgd(WINDOW *, chtype);
extern int wbkgdset(WINDOW *, chtype);

extern int bkgrnd(const cchar_t *);
extern void bkgrndset(const cchar_t *);
extern int getbkgrnd(cchar_t *);
extern int wbkgrnd(WINDOW *, const cchar_t *);
extern void wbkgrndset(WINDOW *, const cchar_t *);
extern int wgetbkgrnd(WINDOW *, cchar_t *);

extern int border(
	chtype, chtype, chtype, chtype, 
	chtype, chtype, chtype, chtype);
extern int border_set(
	const cchar_t *, const cchar_t *, 
	const cchar_t *, const cchar_t *, 
	const cchar_t *, const cchar_t *, 
	const cchar_t *, const cchar_t *);
extern int box(WINDOW *, chtype, chtype);
extern int box_set(WINDOW *, const cchar_t *, const cchar_t *);
extern int wborder(
	WINDOW *,
	chtype, chtype, chtype, chtype, 
	chtype, chtype, chtype, chtype);
extern int wborder_set(
	WINDOW *,
	const cchar_t *, const cchar_t *, 
	const cchar_t *, const cchar_t *, 
	const cchar_t *, const cchar_t *, 
	const cchar_t *, const cchar_t *);

extern bool can_change_color(void);
extern int color_content(short, short *, short *, short *);
extern bool has_colors(void);
extern int init_color(short, short, short, short);
extern int init_pair(short, short, short);
extern int pair_content(short, short *, short *);
extern int start_color(void);

extern int cbreak(void);
extern int halfdelay(int);
extern int nocbreak(void);
extern int raw(void);
extern int noraw(void);

extern int chgat(int, attr_t, short, const void *);
extern int mvchgat(int, int, int, attr_t, short, const void *);
extern int mvwchgat(WINDOW *, int, int, int, attr_t, short, const void *);
extern int wchgat(WINDOW *, int, attr_t, short, const void *);

extern int clear(void);
extern int clrtobot(void);
extern int clrtoeol(void);
extern int erase(void);
extern int wclear(WINDOW *);
extern int wclrtobot(WINDOW *);
extern int wclrtoeol(WINDOW *);
extern int werase(WINDOW *);

extern int clearok(WINDOW *, bool);
extern void idcok(WINDOW *, bool);
extern int idlok(WINDOW *, bool);
extern void immedok(WINDOW *, bool);
extern int intrflush(WINDOW *, bool);
extern int keypad(WINDOW *, bool);
extern int leaveok(WINDOW *, bool);
extern int meta(WINDOW *, bool);
extern int nodelay(WINDOW *, bool);
extern int notimeout(WINDOW *, bool);
extern int scrollok(WINDOW *, bool);
extern int syncok(WINDOW *, bool);

extern int copywin(const WINDOW *, WINDOW *, int, int, int, int, int, int, int);
extern int overlay(const WINDOW *, WINDOW *);
extern int overwrite(const WINDOW *, WINDOW *);

extern int curs_set(int);

extern int def_prog_mode(void);
extern int def_shell_mode(void);
extern int reset_prog_mode(void);
extern int reset_shell_mode(void);

extern int delch(void);
extern int mvdelch(int, int);
extern int mvwdelch(WINDOW *, int, int);
extern int wdelch(WINDOW *);

extern int deleteln(void);
extern int insdelln(int);
extern int insertln(void);
extern int wdeleteln(WINDOW *);
extern int winsdelln(WINDOW *, int);
extern int winsertln(WINDOW *);

extern void delscreen(SCREEN *);
extern SCREEN *newterm(char *, FILE *, FILE *);
extern SCREEN *set_term(SCREEN *);

extern int delwin(WINDOW *);
extern WINDOW *derwin(WINDOW *, int, int, int, int);
extern WINDOW *dupwin(WINDOW *);
extern WINDOW *getwin(FILE *);
extern int mvwin(WINDOW *, int, int);
extern int mvderwin(WINDOW *, int, int);
extern WINDOW *newwin(int, int, int, int);
extern int putwin(WINDOW *,  FILE *);
extern int redrawwin(WINDOW *);
extern WINDOW *subwin(WINDOW *, int, int, int, int);
extern int wredrawln(WINDOW *, int, int);

extern int doupdate(void);
extern int refresh(void);
extern int wnoutrefresh(WINDOW *);
extern int wrefresh(WINDOW *);

extern int echo(void);
extern int noecho(void);
extern int echochar(chtype);
extern int echo_wchar(const cchar_t *);
extern int wechochar(WINDOW *, chtype);
extern int wecho_wchar(WINDOW *, const cchar_t *);

extern int endwin(void);
extern void filter(void);
extern WINDOW *initscr(void);
extern bool isendwin(void);
extern int ripoffline(int, int (*)(WINDOW *, int));
extern int typeahead(int);
extern void use_env(bool);

extern int erasechar(void);
extern int erasewchar(wchar_t *);
extern int killchar(void);
extern int killwchar(wchar_t *);

extern int flushinp(void);

extern int getcchar(const cchar_t *, wchar_t *, attr_t *, short *, void *);
extern int setcchar(cchar_t *, const wchar_t *, attr_t, short, const void *);

extern int getch(void);
extern int get_wch(wint_t *);
extern int mvgetch(int, int);
extern int mvget_wch(int, int, wint_t *);
extern int mvwgetch(WINDOW *, int, int);
extern int mvwget_wch(WINDOW *, int, int, wint_t *);
extern int wgetch(WINDOW *);
extern int wget_wch(WINDOW *, wint_t *);

extern int getnstr(char *, int);
extern int getstr(char *);
extern int mvgetnstr(int, int, char *, int);
extern int mvgetstr(int, int, char *);
extern int mvwgetnstr(WINDOW *, int, int, char *, int);
extern int mvwgetstr(WINDOW *, int, int, char *);
extern int wgetnstr(WINDOW *, char *, int);
extern int wgetstr(WINDOW *, char *);

extern int getn_wstr(wint_t *, int);
extern int get_wstr(wint_t *);
extern int mvgetn_wstr(int, int, wint_t *, int);
extern int mvget_wstr(int, int, wint_t *);
extern int mvwgetn_wstr(WINDOW *, int, int, wint_t *, int);
extern int mvwget_wstr(WINDOW *, int, int, wint_t *);
extern int wgetn_wstr(WINDOW *, wint_t *, int);
extern int wget_wstr(WINDOW *, wint_t *);

extern bool has_ic(void);
extern bool has_il(void);

extern int hline(chtype, int);
extern int hline_set(const cchar_t *, int);
extern int vline(chtype, int);
extern int vline_set(const cchar_t *, int);
extern int mvhline(int, int, chtype, int);
extern int mvhline_set(int, int, const cchar_t *, int);
extern int mvvline(int, int, chtype, int);
extern int mvvline_set(int, int, const cchar_t *, int);
extern int mvwhline(WINDOW *, int, int, chtype, int);
extern int mvwhline_set(WINDOW *, int, int, const cchar_t *, int);
extern int mvwvline(WINDOW *, int, int, chtype, int);
extern int mvwvline_set(WINDOW *, int, int, const cchar_t *, int);
extern int whline(WINDOW *, chtype, int);
extern int whline_set(WINDOW *, const cchar_t *, int);
extern int wvline(WINDOW *, chtype, int);
extern int wvline_set(WINDOW *, const cchar_t *, int);

extern chtype inch(void);
extern int inchnstr(chtype *, int);
extern int inchstr(chtype *);
extern int in_wch(cchar_t *);
extern int in_wchnstr(cchar_t *, int);
extern int in_wchstr(cchar_t *);
extern chtype mvinch(int, int);
extern int mvinchnstr(int, int, chtype *, int);
extern int mvinchstr(int, int, chtype *);
extern int mvin_wch(int, int, cchar_t *);
extern int mvin_wchnstr(int, int, cchar_t *, int);
extern int mvin_wchstr(int, int, cchar_t *);
extern chtype mvwinch(WINDOW *, int, int);
extern int mvwinchnstr(WINDOW *, int, int, chtype *, int);
extern int mvwinchstr(WINDOW *, int, int, chtype *);
extern int mvwin_wch(WINDOW *, int, int, cchar_t *);
extern int mvwin_wchnstr(WINDOW *, int, int, cchar_t *, int);
extern int mvwin_wchstr(WINDOW *, int, int, cchar_t *);
extern chtype winch(WINDOW *);
extern int winchnstr(WINDOW *, chtype *, int);
extern int winchstr(WINDOW *, chtype *);
extern int win_wch(WINDOW *, cchar_t *);
extern int win_wchnstr(WINDOW *, cchar_t *, int);
extern int win_wchstr(WINDOW *, cchar_t *);

extern int innstr(char *, int);
extern int instr(char *);
extern int innwstr(wchar_t *, int);
extern int inwstr(wchar_t *);
extern int mvinnstr(int, int, char *, int);
extern int mvinstr(int, int, char *);
extern int mvinnwstr(int, int, wchar_t *, int);
extern int mvinwstr(int, int, wchar_t *);
extern int mvwinnstr(WINDOW *, int, int, char *, int);
extern int mvwinstr(WINDOW *, int, int, char *);
extern int mvwinnwstr(WINDOW *, int, int, wchar_t *, int);
extern int mvwinwstr(WINDOW *, int, int, wchar_t *);
extern int winnstr(WINDOW *, char *, int);
extern int winstr(WINDOW *, char *);
extern int winnwstr(WINDOW *, wchar_t *, int);
extern int winwstr(WINDOW *, wchar_t *);

extern int insch(chtype);
extern int ins_wch(const cchar_t *);
extern int mvinsch(int, int, chtype);
extern int mvins_wch(int, int, const cchar_t *);
extern int mvwinsch(WINDOW *, int, int, chtype);
extern int mvwins_wch(WINDOW *, int, int, const cchar_t *);
extern int winsch(WINDOW *, chtype);
extern int wins_wch(WINDOW *, const cchar_t *);

extern int insnstr(const char *, int);
extern int insstr(const char *);
extern int ins_nwstr(const wchar_t *, int);
extern int ins_wstr(const wchar_t *);
extern int mvinsnstr(int, int, const char *, int);
extern int mvinsstr(int, int, const char *);
extern int mvins_nwstr(int, int, const wchar_t *, int);
extern int mvins_wstr(int, int, const wchar_t *);
extern int mvwinsnstr(WINDOW *, int, int, const char *, int);
extern int mvwinsstr(WINDOW *, int, int, const char *);
extern int mvwins_nwstr(WINDOW *, int, int, const wchar_t *, int);
extern int mvwins_wstr(WINDOW *, int, int, const wchar_t *);
extern int winsnstr(WINDOW *, const char *, int);
extern int winsstr(WINDOW *, const char *);
extern int wins_nwstr(WINDOW *, const wchar_t *, int);
extern int wins_wstr(WINDOW *, const wchar_t *);

extern bool is_linetouched(WINDOW *, int);
extern bool is_wintouched(WINDOW *);
extern int touchline(WINDOW *, int, int);
extern int touchwin(WINDOW *);
extern int wtouchln(WINDOW *, int, int, int);
extern int untouchwin(WINDOW *);

extern const char *keyname(int);
extern const char *key_name(wchar_t);

extern char *longname(void);
extern char *termname(void);

extern int move(int, int);
extern int wmove(WINDOW *, int, int);

extern int mvcur(int, int, int, int);

extern WINDOW *newpad(int, int);
extern int pechochar(WINDOW *, chtype);
extern int pecho_wchar(WINDOW *, const cchar_t *);
extern int pnoutrefresh(WINDOW *, int, int, int, int, int, int);
extern int prefresh(WINDOW *, int, int, int, int, int, int);
extern WINDOW *subpad(WINDOW *, int, int, int, int);

extern int nl(void);
extern int nonl(void);

extern int printw(const char *, ...);
extern int mvprintw(int, int, const char *, ...);
extern int mvwprintw(WINDOW *, int, int, const char *, ...);
#if defined(sun)
extern int vwprintw(WINDOW *, const char *, __va_list);
extern int vw_printw(WINDOW *, const char *, __va_list);
#else
extern int vwprintw(WINDOW *, const char *, void *);
extern int vw_printw(WINDOW *, const char *, void *);
#endif
extern int wprintw(WINDOW *, const char *, ...);

extern void qiflush(void);
extern void noqiflush(void);

extern int resetty(void);
extern int savetty(void);

extern int scanw(const char *, ...);
extern int mvscanw(int, int, const char *, ...);
extern int mvwscanw(WINDOW *, int, int, const char *, ...);
#if defined(sun)
extern int vwscanw(WINDOW *, const char *, __va_list);
extern int vw_scanw(WINDOW *, const char *, __va_list);
#else
extern int vwscanw(WINDOW *, const char *, void *);
extern int vw_scanw(WINDOW *, const char *, void *);
#endif
extern int wscanw(WINDOW *, const char *, ...);

extern int scr_dump(const char *);
extern int scr_init(const char *);
extern int scr_restore(const char *);
extern int scr_set(const char *);

extern int scrl(int);
extern int scroll(WINDOW *);
extern int setscrreg(int, int);
extern int wscrl(WINDOW *, int);
extern int wsetscrreg(WINDOW *, int, int);

extern int slk_attroff(const chtype);
extern int slk_attron(const chtype);
extern int slk_attrset(const chtype);
extern int slk_attr_off(const attr_t, void *);
extern int slk_attr_on(const attr_t, void *);
extern int slk_attr_set(const attr_t, short, void *);
extern int slk_color_set(short);
extern int slk_clear(void);
extern int slk_init(int);
extern char *slk_label(int);
extern int slk_noutrefresh(void);
extern int slk_refresh(void);
extern int slk_restore(void);
extern int slk_set(int, const char *, int);
extern int slk_touch(void);
extern int slk_wset(int, const wchar_t *, int);

extern int standend(void);
extern int wstandend(WINDOW *);
extern int standout(void);
extern int wstandout(WINDOW *);

extern chtype termattrs(void);
extern attr_t term_attrs(void);

extern void timeout(int);
extern void wtimeout(WINDOW *, int);

extern int ungetch(int);
extern int unget_wch(const wchar_t);

extern int vidattr(chtype);
extern int vid_attr(attr_t, short, void *);
extern int vidputs(chtype, int (*)(int));
extern int vid_puts(attr_t, short, void *, int (*)(int));

extern void wcursyncup(WINDOW *);
extern void wsyncdown(WINDOW *);
extern void wsyncup(WINDOW *);

extern const wchar_t *wunctrl(const cchar_t *);

/*
 * These macros are not suitable for strict XPG4 conformance, 
 * because some of them evaluate their arguments more than once.
 * However, they can improve speed and size of an application,
 * provided an application is careful about not using side effects
 * with function/macro parameters.
 */
#ifndef _XOPEN_SOURCE_EXTENDED

#define addch(ch)			waddch(stdscr,ch)
#define mvaddch(y,x,ch)			(move(y,x)?ERR:addch(ch))
#define mvwaddch(w,y,x,ch)		(wmove(w,y,x)?ERR:waddch(w,ch))

#define add_wch(cp)			wadd_wch(stdscr,cp)
#define mvadd_wch(y,x,cp)		(move(y,x)?ERR:add_wch(cp))
#define mvwadd_wch(w,y,x,cp)		(wmove(w,y,x)?ERR:wadd_wch(w,cp))

#define addchnstr(chs,n)		waddchnstr(stdscr,chs,n)
#define addchstr(chs)			waddchstr(stdscr,chs)
#define mvaddchnstr(y,x,chs,n)		(move(y,x)?ERR:addchnstr(chs,n))
#define mvaddchstr(y,x,chs)		(move(y,x)?ERR:addchstr(chs))
#define mvwaddchnstr(w,y,x,chs,n)	(wmove(w,y,x)?ERR:waddchnstr(w,chs,n))
#define mvwaddchstr(w,y,x,chs)		(wmove(w,y,x)?ERR:waddchstr(w,chs))
#define waddchstr(w,chs)		waddchnstr(w,chs,-1)

#define add_wchnstr(cp,n)		wadd_wchnstr(stdscr,cp,n)
#define add_wchstr(cp)			wadd_wchstr(stdscr,cp)
#define mvadd_wchnstr(y,x,cp,n)		(move(y,x)?ERR:add_wchnstr(cp,n))
#define mvadd_wchstr(y,x,cp)		(move(y,x)?ERR:add_wchstr(cp))
#define mvwadd_wchnstr(w,y,x,cp,n)	(wmove(w,y,x)?ERR:wadd_wchnstr(w,cp,n))
#define mvwadd_wchstr(w,y,x,cp)		(wmove(w,y,x)?ERR:wadd_wchstr(w,cp))
#define wadd_wchstr(w,cp)		wadd_wchnstr(w,cp,-1)

#define addnstr(s,n)			waddnstr(stdscr,s,n)
#define addstr(s)			waddstr(stdscr,s)
#define mvaddnstr(y,x,s,n)		(move(y,x)?ERR:addnstr(s,n))
#define mvaddstr(y,x,s)			(move(y,x)?ERR:addstr(s))
#define mvwaddnstr(w,y,x,s,n)		(wmove(w,y,x)?ERR:waddnstr(w,s,n))
#define mvwaddstr(w,y,x,s)		(wmove(w,y,x)?ERR:waddstr(w,s))
#define waddstr(w,wcs)			waddnstr(w,wcs,-1)

#define addnwstr(wcs,n)			waddnwstr(stdscr,wcs,n)
#define addwstr(wcs)			waddwstr(stdscr,wcs)
#define mvaddnwstr(y,x,wcs,n)		(move(y,x)?ERR:addnwstr(wcs,n))
#define mvaddwstr(y,x,wcs)		(move(y,x)?ERR:addwstr(wcs))
#define mvwaddnwstr(w,y,x,wcs,n)	(wmove(w,y,x)?ERR:waddnwstr(w,wcs,n))
#define mvwaddwstr(w,y,x,wcs)		(wmove(w,y,x)?ERR:waddwstr(w,wcs))
#define waddwstr(w,wcs)			waddnwstr(w,wcs,-1)

#define attr_get(a,c,o)			wattr_get(stdscr,a,c,o)
#define attr_off(a,o)			wattr_off(stdscr,a,o)
#define attr_on(a,o)			wattr_on(stdscr,a,o)
#define attr_set(a,c,o)			wattr_set(stdscr,a,c,o)

#define COLOR_PAIR(n)   		((chtype)(n)<<__COLOR_SHIFT)
#define PAIR_NUMBER(a)  		(((chtype)(a)&A_COLOR)>>__COLOR_SHIFT)

#define bkgd(ch)			wbkgd(stdscr, ch)
#define bkgdset(ch)			__m_chtype_cc(ch, &stdscr->_bg)
#define getbkgd(w)			__m_cc_chtype(&(w)->_bg)
#define wbkgdset(w,ch)			__m_chtype_cc(ch, &(w)->_bg)

#define bkgrnd(b)			wbkgrnd(stdscr,b)
#define bkgrndset(b)			wbkgrndset(stdscr,b)
#define getbkgrnd(b)			wgetbkgrnd(stdscr,b)
#define wbkgrndset(w,b)			((w)->_bg = *(b))
#define wgetbkgrnd(w,b)			(*(b) = (w)->_bg, OK)

#define border(ls, rs, ts, bs, tl, tr, bl, br) \
	wborder(stdscr, ls, rs, ts, bs, tl, tr, bl, br)
#define border_set(ls, rs, ts, bs, tl, tr, bl, br) \
	wborder_set(stdscr, ls, rs, ts, bs, tl, tr, bl, br)
#define box(w,v,h)			wborder(w,v,v,h,h,0,0,0,0)
#define box_set(w,v,h)			wborder_set(w,v,v,h,h,0,0,0,0)

#define can_change_color()		(2 < max_colors && can_change \
					&& initialize_color != (char *) 0)
#define has_colors()			(0 < max_colors)

#define chgat(n,a,co,p)			wchgat(stdscr,n,a,co,p)
#define mvchgat(y,x,n,a,co,p)		(move(y,x)?ERR:chgat(n,a,co,p))
#define mvwchgat(w,y,x,n,a,co,p)	(wmove(w,y,x)?ERR:wchgat(w,n,a,co,p))

#define clear()				wclear(stdscr)
#define clrtobot()			wclrtobot(stdscr)
#define clrtoeol()			wclrtoeol(stdscr)
#define erase()				werase(stdscr)
#define wclear(w)			(clearok(w,1)?ERR:werase(w))
#define werase(w)			(wmove(w,0,0)?ERR:wclrtobot(w))

#define delch()				wdelch(stdscr)
#define mvdelch(y,x)			(move(y,x)?ERR:delch())
#define mvwdelch(w,y,x)			(wmove(w,y,x)?ERR:wdelch(w))

#define deleteln()			wdeleteln(stdscr)
#define insdelln(n)			winsdelln(stdscr,n)
#define insertln()			winsertln(stdscr)
#define wdeleteln(w)			winsdelln(w, -1)
#define winsertln(w)			winsdelln(w, 1)

#define refresh()			wrefresh(stdscr)

#define echochar(ch)			wechochar(stdscr,ch)
#define echo_wchar(cp)			wecho_wchar(stdscr,cp)
#define wechochar(w,ch)			(waddch(w,ch)?ERR:wrefresh(w))
#define wecho_wchar(w,cp)		(wadd_wch(w,cp)?ERR:wrefresh(w))

#define erasewchar(wp)			__m_tty_wc(VERASE, wp)
#define killwchar(wp)			__m_tty_wc(VKILL, wp)

#define getch()				wgetch(stdscr)
#define mvgetch(y,x)			(move(y,x)?ERR:getch())
#define mvwgetch(w,y,x)			(wmove(w,y,x)?ERR:wgetch(w))

#define get_wch(wcp)			wget_wch(stdscr,wcp)
#define mvget_wch(y,x,wcp)		(move(y,x)?ERR:get_wch(wcp))
#define mvwget_wch(w,y,x,wcp)		(wmove(w,y,x)?ERR:wget_wch(w,wcp))

#define getnstr(s,n)			wgetnstr(stdscr,s,n)
#define getstr(s)			wgetstr(stdscr,s)
#define mvgetnstr(y,x,s,n)		(move(y,x)?ERR:getnstr(s,n))
#define mvgetstr(y,x,s)			(move(y,x)?ERR:getstr(s))
#define mvwgetnstr(w,y,x,s,n)		(wmove(w,y,x)?ERR:wgetnstr(w,s,n))
#define mvwgetstr(w,y,x,s)		(wmove(w,y,x)?ERR:wgetstr(w,s))
#define wgetstr(w,s)			wgetnstr(w,s,-1)

#define getn_wstr(wcs,n)		wgetn_wstr(stdscr,wcs,n)
#define get_wstr(wcs)			wget_wstr(stdscr,wcs)
#define mvgetn_wstr(y,x,wcs,n)		(move(y,x)?ERR:getn_wstr(wcs,n))
#define mvget_wstr(y,x,wcs)		(move(y,x)?ERR:get_wstr(wcs))
#define mvwgetn_wstr(w,y,x,wcs,n)	(wmove(w,y,x)?ERR:wgetn_wstr(w,wcs,n))
#define mvwget_wstr(w,y,x,wcs)		(wmove(w,y,x)?ERR:wget_wstr(w,wcs))
#define wget_wstr(w,wcs)		wgetn_wstr(w,wcs,-1)

#define has_ic()			(((insert_character != (char *) 0 \
					   || parm_ich != (char *) 0) \
					  && (delete_character != (char *) 0 \
					      || parm_dch != (char *) 0)) \
					 || (enter_insert_mode != (char *) 0 \
					     && exit_insert_mode))

#define has_il()			(((insert_line != (char *) 0 \
					   || parm_insert_line != (char *) 0) \
					  && (delete_line != (char *) 0 \
					      || parm_delete_line !=(char*)0)) \
					 || change_scroll_region != (char *) 0)


#define hline(ch,n)			whline(stdscr,ch,n)
#define vline(ch,n)			wvline(stdscr,ch,n)
#define mvhline(y,x,ch,n)		(move(y,x)?ERR:hline(ch,n))
#define mvvline(y,x,ch,n)		(move(y,x)?ERR:vline(ch,n))
#define mvwhline(w,y,x,ch,n)		(wmove(w,y,x)?ERR:whline(w,ch,n))
#define mvwvline(w,y,x,ch,n)		(wmove(w,y,x)?ERR:wvline(w,ch,n))

#define hline_set(cp,n)			whline_set(stdscr,cp,n)
#define vline_set(cp,n)			wvline_set(stdscr,cp,n)
#define mvhline_set(y,x,cp,n)		(move(y,x)?ERR:hline_set(cp,n))
#define mvvline_set(y,x,cp,n)		(move(y,x)?ERR:vline_set(cp,n))
#define mvwhline_set(w,y,x,cp,n)	(wmove(w,y,x)?ERR:whline_set(w,cp,n))
#define mvwvline_set(w,y,x,cp,n)	(wmove(w,y,x)?ERR:wvline_set(w,cp,n))

#define inch()				winch(stdscr)
#define mvinch(y,x)			(move(y,x)?ERR:inch())
#define mvwinch(w,y,x)			(wmove(w,y,x)?ERR:winch(w))

#define in_wch(cp)			win_wch(stdscr,cp)
#define mvin_wch(y,x,cp)		(move(y,x)?ERR:in_wch(cp))
#define mvwin_wch(w,y,x,cp)		(wmove(w,y,x)?ERR:win_wch(w,cp))

#define inchnstr(chs,n)			winchnstr(stdscr,chs,n)
#define inchstr(chs)			winchstr(stdscr,chs)
#define mvinchnstr(y,x,chs,n)		(move(y,x)?ERR:inchnstr(chs,n))
#define mvinchstr(y,x,chs)		(move(y,x)?ERR:inchstr(chs))
#define mvwinchnstr(w,y,x,chs,n)	(wmove(w,y,x)?ERR:winchnstr(w,chs,n))
#define mvwinchstr(w,y,x,chs)		(wmove(w,y,x)?ERR:winchstr(w,chs))
#define winchstr(w,chs)			winchnstr(w,chs,-1)

#define in_wchnstr(cp,n)		win_wchnstr(stdscr,cp,n)
#define in_wchstr(cp)			win_wchstr(stdscr,cp)
#define mvin_wchnstr(y,x,cp,n)		(move(y,x)?ERR:in_wchnstr(cp,n))
#define mvin_wchstr(y,x,cp)		(move(y,x)?ERR:in_wchstr(cp))
#define mvwin_wchnstr(w,y,x,cp,n)	(wmove(w,y,x)?ERR:win_wchnstr(w,cp,n))
#define mvwin_wchstr(w,y,x,cp)		(wmove(w,y,x)?ERR:win_wchstr(w,cp))
#define win_wchstr(w,cp)		win_wchnstr(w,cp,-1)

#define innstr(s,n)			winnstr(stdscr,s,n)
#define instr(s)			winstr(stdscr,s)
#define mvinnstr(y,x,s,n)		(move(y,x)?ERR:innstr(s,n))
#define mvinstr(y,x,s)			(move(y,x)?ERR:instr(s))
#define mvwinnstr(w,y,x,s,n)		(wmove(w,y,x)?ERR:winnstr(w,s,n))
#define mvwinstr(w,y,x,s)		(wmove(w,y,x)?ERR:winstr(w,s))
#define winstr(w,s)			winnstr(w,s,-1)

#define innwstr(wcs,n)			winnwstr(stdscr,wcs,n)
#define inwstr(wcs)			winwstr(stdscr,wcs)
#define mvinnwstr(y,x,wcs,n)		(move(y,x)?ERR:innwstr(wcs,n))
#define mvinwstr(y,x,wcs)		(move(y,x)?ERR:inwstr(wcs))
#define mvwinnwstr(w,y,x,wcs,n)		(wmove(w,y,x)?ERR:winnwstr(w,wcs,n))
#define mvwinwstr(w,y,x,wcs)		(wmove(w,y,x)?ERR:winwstr(w,wcs))
#define winwstr(w,wcs)			winnwstr(w,wcs,-1)

#define insch(ch)			winsch(stdscr,ch)
#define mvinsch(y,x,ch)			(move(y,x)?ERR:insch(ch))
#define mvwinsch(w,y,x,ch)		(wmove(w,y,x)?ERR:winsch(w,ch))

#define ins_wch(cp)			wins_wch(stdscr,cp)
#define mvins_wch(y,x,cp)		(move(y,x)?ERR:ins_wch(cp))
#define mvwins_wch(w,y,x,cp)		(wmove(w,y,x)?ERR:wins_wch(w,cp))

#define insnstr(s,n)			winsnstr(stdscr,s,n)
#define insstr(s)			winsstr(stdscr,s)
#define mvinsnstr(y,x,s,n)		(move(y,x)?ERR:insnstr(s,n))
#define mvinsstr(y,x,s)			(move(y,x)?ERR:insstr(s))
#define	mvwinsnstr(w, y, x, s, n)	(wmove(w, y, x)?ERR:winsnstr(w, s, n))
#define	mvwinsstr(w, y, x, s)		(wmove(w, y, x)?ERR:winsstr(w, s))
#define	winsstr(w, s)			winsnstr(w, s, -1)

#define	ins_nwstr(wcs, n)		wins_nwstr(stdscr, wcs, n)
#define	ins_wstr(wcs)			wins_wstr(stdscr, wcs)
#define	mvins_nwstr(y, x, wcs, n)	(move(y, x)?ERR:ins_nwstr(wcs, n))
#define	mvins_wstr(y, x, wcs)		(move(y, x)?ERR:ins_wstr(wcs))
#define	mvwins_nwstr(w, y, x, wcs, n)	(wmove(w, y, x)?ERR:wins_nwstr(w,wcs,n))
#define	mvwins_wstr(w, y, x, wcs)	(wmove(w, y, x)?ERR:wins_wstr(w,wcs))
#define	wins_wstr(w, wcs)		wins_nwstr(w, wcs, -1)

#define	is_linetouched(w, y)		(0 <= (w)->_last[y])

#define	mvcur(or, oc, nr, nc)		__m_mvcur(or, oc, nr, nc, __m_outc)

#define	move(y, x)			wmove(stdscr, y, x)

#define	overlay(s, t)			__m_copywin(s, t, 1)
#define	overwrite(s, t)			__m_copywin(s, t, 0)

#define	newpad(ny, nx)			__m_newwin((WINDOW *) 0, ny, nx, -1, -1)
#define	subpad(par, ny, nx, by, bx)	subwin(par, ny, nx, by, bx)

#define	nodelay(w, bf)			(wtimeout(w, (bf)?0:-1), OK)
#define	timeout(n)			wtimeout(stdscr, n)

#define	qiflush()			((void) intrflush((WINDOW *) 0, 1))
#define	noqiflush()			((void) intrflush((WINDOW *) 0, 0))

#define	redrawwin(w)			wredrawln(w, 0, (w)->_maxy)

#define	scrl(n)				wscrl(stdscr, n)
#define	setscrreg(t, b)			wsetscrreg(stdscr, t, b)

#define	standend()			wstandend(stdscr)
#define	standout()			wstandout(stdscr)
#define	wstandend(w)			(wattr_set(w, WA_NORMAL, COLOR_BLACK, \
					(void *)0), 1)
#define	wstandout(w)			(wattr_on(w, WA_STANDOUT, (void *)0), 1)

#define	touchline(w, y, n)		wtouchln(w, y, n, 1)
#define	touchwin(w)			wtouchln(w, 0, (w)->_maxy, 1)
#define	untouchwin(w)			wtouchln(w, 0, (w)->_maxy, 0)

#define	termname()			(cur_term->_term)

#ifndef _XOPEN_SOURCE
/*
 * Obsolete functions names.
 */
#define	crmode				cbreak
#define	nocrmode			nocbreak
#define	saveterm			def_prog_mode
#define	fixterm				reset_prog_mode
#define	resetterm			reset_shell_mode
#endif /* _XOPEN_SOURCE */
#endif /* _XOPEN_SOURCE_EXTENDED */

/*
 * Special Keys
 *
 * Keypad layout
 *	A1	up	A3
 *     left	B2     right
 *	C1     down	C3
 *
 * Chossing negative values for KEY_ constants means that they can
 * be safely returned in either an int or long type.
 */
#define	__KEY_BASE	(-2)
#define	__KEY_MAX	__KEY_BASE

#define	KEY_CODE_YES	(__KEY_BASE-1)		/* Special indicator. */

#define	KEY_BREAK	(__KEY_BASE-2)		/* Break key (unreliable) */
#define	KEY_DOWN	(__KEY_BASE-3)		/* The four arrow keys ... */
#define	KEY_UP		(__KEY_BASE-4)
#define	KEY_LEFT	(__KEY_BASE-5)
#define	KEY_RIGHT	(__KEY_BASE-6)
#define	KEY_HOME	(__KEY_BASE-7)		/* Move to upper-left corner. */
#define	KEY_BACKSPACE	(__KEY_BASE-8)		/* Backspace */
#define	KEY_F0		(__KEY_BASE-9)		/* Function keys.  Space for */
#define	KEY_F(n)	(KEY_F0-(n))    	/* 64 keys is reserved. */
#define	KEY_DL		(__KEY_BASE-73)		/* Delete line */
#define	KEY_IL		(__KEY_BASE-74)		/* Insert line */
#define	KEY_DC		(__KEY_BASE-75)		/* Delete character */
#define	KEY_IC		(__KEY_BASE-76)		/* Ins char / enter ins mode */
#define	KEY_EIC		(__KEY_BASE-77)		/* Exit insert char mode */
#define	KEY_CLEAR	(__KEY_BASE-78)		/* Clear screen */
#define	KEY_EOS		(__KEY_BASE-79)		/* Clear to end of screen */
#define	KEY_EOL		(__KEY_BASE-80)		/* Clear to end of line */
#define	KEY_SF		(__KEY_BASE-81)		/* Scroll 1 line forward */
#define	KEY_SR		(__KEY_BASE-82)		/* Scroll 1 line backwards */
#define	KEY_NPAGE	(__KEY_BASE-83)		/* Next page */
#define	KEY_PPAGE	(__KEY_BASE-84)		/* Previous page */
#define	KEY_STAB	(__KEY_BASE-85)		/* Set tab */
#define	KEY_CTAB	(__KEY_BASE-86)		/* Clear tab */
#define	KEY_CATAB	(__KEY_BASE-87)		/* Clear all tabs */
#define	KEY_ENTER	(__KEY_BASE-88)		/* Enter or send */
#define	KEY_SRESET	(__KEY_BASE-89)		/* Soft (partial) reset */
#define	KEY_RESET	(__KEY_BASE-90)		/* Hard reset */
#define	KEY_PRINT	(__KEY_BASE-91)		/* Print or copy */
#define	KEY_LL		(__KEY_BASE-92)		/* Move to lower left corner. */
#define	KEY_A1		(__KEY_BASE-93)		/* Upper left of keypad */
#define	KEY_A3		(__KEY_BASE-94) 	/* Upper rght of keypad */
#define	KEY_B2		(__KEY_BASE-95) 	/* Center of keypad */
#define	KEY_C1		(__KEY_BASE-96) 	/* Lower left of keypad */
#define	KEY_C3		(__KEY_BASE-97) 	/* Lower right of keypad */
#define	KEY_BTAB	(__KEY_BASE-98) 	/* Back Tab */
#define	KEY_BEG		(__KEY_BASE-99) 	/* Beginning */
#define	KEY_CANCEL	(__KEY_BASE-100)
#define	KEY_CLOSE	(__KEY_BASE-101)
#define	KEY_COMMAND	(__KEY_BASE-102)
#define	KEY_COPY	(__KEY_BASE-103)
#define	KEY_CREATE	(__KEY_BASE-104)
#define	KEY_END		(__KEY_BASE-105)
#define	KEY_EXIT	(__KEY_BASE-106)
#define	KEY_FIND	(__KEY_BASE-107)
#define	KEY_HELP	(__KEY_BASE-108)
#define	KEY_MARK	(__KEY_BASE-109)
#define	KEY_MESSAGE	(__KEY_BASE-110)
#define	KEY_MOUSE	(__KEY_BASE-111)	/* Mouse event occured */
#define	KEY_MOVE	(__KEY_BASE-112)
#define	KEY_NEXT	(__KEY_BASE-113)	/* Next object */
#define	KEY_OPEN	(__KEY_BASE-114)
#define	KEY_OPTIONS	(__KEY_BASE-115)
#define	KEY_PREVIOUS	(__KEY_BASE-116)	/* Previous object */
#define	KEY_REDO	(__KEY_BASE-117)
#define	KEY_REFERENCE	(__KEY_BASE-118)
#define	KEY_REFRESH	(__KEY_BASE-119)
#define	KEY_REPLACE	(__KEY_BASE-120)
#define	KEY_RESTART	(__KEY_BASE-121)
#define	KEY_RESUME	(__KEY_BASE-122)
#define	KEY_SAVE	(__KEY_BASE-123)
#define	KEY_SBEG	(__KEY_BASE-124)	/* Shifted keys */
#define	KEY_SCANCEL	(__KEY_BASE-125)
#define	KEY_SCOMMAND	(__KEY_BASE-126)
#define	KEY_SCOPY	(__KEY_BASE-127)
#define	KEY_SCREATE	(__KEY_BASE-128)
#define	KEY_SDC		(__KEY_BASE-129)
#define	KEY_SDL		(__KEY_BASE-130)
#define	KEY_SELECT	(__KEY_BASE-131)	/* Select */
#define	KEY_SEND	(__KEY_BASE-132)	/* Shifted end key */
#define	KEY_SEOL	(__KEY_BASE-133)
#define	KEY_SEXIT	(__KEY_BASE-134)
#define	KEY_SFIND	(__KEY_BASE-135)
#define	KEY_SHELP	(__KEY_BASE-136)
#define	KEY_SHOME	(__KEY_BASE-137)
#define	KEY_SIC		(__KEY_BASE-138)
#define	KEY_SLEFT	(__KEY_BASE-139)
#define	KEY_SMESSAGE	(__KEY_BASE-140)
#define	KEY_SMOVE	(__KEY_BASE-141)
#define	KEY_SNEXT	(__KEY_BASE-142)
#define	KEY_SOPTIONS	(__KEY_BASE-143)
#define	KEY_SPREVIOUS	(__KEY_BASE-144)
#define	KEY_SPRINT	(__KEY_BASE-145)
#define	KEY_SREDO	(__KEY_BASE-146)
#define	KEY_SREPLACE	(__KEY_BASE-147)
#define	KEY_SRIGHT	(__KEY_BASE-148)
#define	KEY_SRSUME	(__KEY_BASE-149)
#define	KEY_SSAVE	(__KEY_BASE-150)
#define	KEY_SSUSPEND	(__KEY_BASE-151)
#define	KEY_SUNDO	(__KEY_BASE-152)
#define	KEY_SUSPEND	(__KEY_BASE-153)
#define	KEY_UNDO	(__KEY_BASE-154)

#define	__KEY_MIN	(__KEY_BASE-155)

#endif /* __M_CURSES_H__ */

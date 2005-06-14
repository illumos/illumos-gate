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
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CURSES_H
#define	_CURSES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * curses.h
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#include <sys/isa_defs.h>
#include <stdio.h>
#include <term.h>
#include <wchar.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	_XOPEN_CURSES

#ifndef EOF
#define	EOF			(-1)
#endif

#ifndef WEOF
#define	WEOF		((wint_t)(-1))
#endif

#define	ERR			EOF
#define	OK			0

#if !(defined(__cplusplus) && defined(_BOOL))
#ifndef _BOOL_DEFINED
typedef short	bool;
#define	_BOOL_DEFINED
#endif
#endif

#define	TRUE    		1
#define	FALSE   		0

typedef unsigned short	attr_t;

/*
 * These attributes and masks can be applied to an attr_t.
 * These are ordered according to the <no_color_video> mask,
 * which has been extended to include additional attributes.
 */
#define	WA_NORMAL	0x0
#define	WA_STANDOUT	0x0001
#define	WA_UNDERLINE	0x0002
#define	WA_REVERSE	0x0004
#define	WA_BLINK	0x0008
#define	WA_DIM		0x0010
#define	WA_BOLD		0x0020
#define	WA_INVIS	0x0040
#define	WA_PROTECT	0x0080
#define	WA_ALTCHARSET	0x0100
#define	WA_HORIZONTAL	0x0200
#define	WA_LEFT		0x0400
#define	WA_LOW		0x0800
#define	WA_RIGHT	0x1000
#define	WA_TOP		0x2000
#define	WA_VERTICAL	0x4000

#define	WA_SGR_MASK	0x01ff		/* Historical attribute set. */
#define	WA_SGR1_MASK	0x7e00		/* Extended attribute set. */

/*
 * Internal attribute used to support <ceol_standout_glitch>.
 */
#define	WA_COOKIE	0x8000

/*
 * Color names.
 */
#define	COLOR_BLACK	0
#define	COLOR_RED	1
#define	COLOR_GREEN	2
#define	COLOR_YELLOW	3
#define	COLOR_BLUE	4
#define	COLOR_MAGENTA	5
#define	COLOR_CYAN	6
#define	COLOR_WHITE	7

/*
 * A cchar_t details the attributes, color, and a string of wide characters
 * composing a complex character (p12).  The wide character string consists
 * of a spacing character (wcwidth() > 0) and zero or more non-spacing
 * characters.  Xcurses (p17) states that the minimum number of non-spacing
 * characters associated with a spacing character must be at least 5, if a
 * limit is imposed.
 */
#define	_M_CCHAR_MAX	6

/*
 * Opaque data type.
 */
typedef struct {
	short	_f;			/* True if start of character. */
	short	_n;			/* Number of elements in wc[]. */
	short	_co;		/* Color pair number. */
	attr_t	_at;		/* Attribute flags. */
	wchar_t	_wc[_M_CCHAR_MAX];	/* Complex spacing character. */
} cchar_t;

/*
 * Opaque data type.
 */
typedef struct window_t {
	cchar_t	_bg;		/* Background. */
	cchar_t	_fg;		/* Foreground, ignore character. */
	short	_cury, _curx;	/* Curent cursor position in window. */
	short	_begy, _begx;	/* Upper-left origin on screen. */
	short	_maxy, _maxx;	/* Window dimensions. */
	short	_top, _bottom;	/* Window's software scroll region. */
	short	_refy, _refx;	/* Pad origin of last refresh. */
	short	_sminy, _sminx;	/* T-L screen corner of last refresh. */
	short	_smaxy, _smaxx;	/* B-R screen corner of last refresh. */
	short	_vmin, _vtime;	/* wtimeout() control. */
	short	*_first, *_last;	/* Dirty region for each screen line. */
	unsigned short	_flags;		/* Internal flags for the window. */
	unsigned short	_scroll;	/* Internal for scroll optimization. */
	cchar_t	**_line;
	cchar_t	*_base;		/* Block of M*N screen cells. */
	struct window_t	*_parent;	/* Parent of sub-window. */
} WINDOW;

/*
 * Opaque data type.
 */
typedef struct {
	int _kfd;		/* typeahead() file descriptor. */
	FILE *_if, *_of;	/* I/O file pointers. */
	TERMINAL *_term;	/* Associated terminfo entry. */
	WINDOW *_newscr;	/* New screen image built by wnoutrefresh(). */
	WINDOW *_curscr;	/* Current screen image after doupdate(). */
	mbstate_t _state;	/* Current multibyte state of _of. */
#if defined(_LP64)
	unsigned int	*_hash;	/* Hash values for curscr's screen lines. */
#else
	unsigned long	*_hash;	/* Hash values for curscr's screen lines. */
#endif /* defined(_LP64) */
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
		char	*_saved[8];	/* exact representation of label */
	} _slk;
} SCREEN;


/*
 * Backwards compatiblity with historical Curses applications.
 */
#ifndef	_CHTYPE
#define	_CHTYPE
#if defined(_LP64)
typedef unsigned int	chtype;
#else
typedef unsigned long	chtype;
#endif
#endif

/*
 * These attributes and masks can be applied to a chtype.
 * They are order according to the <no_color_video> mask.
 */
#if defined(_LP64)
#define	A_NORMAL		0x00000000U
#define	A_ATTRIBUTES	0xffff0000U	/* Color/Attribute mask */
#define	A_CHARTEXT		0x0000ffffU	/* 16-bit character mask */
#define	A_STANDOUT		0x00010000U
#define	A_UNDERLINE		0x00020000U
#define	A_REVERSE		0x00040000U
#define	A_BLINK			0x00080000U
#define	A_DIM			0x00100000U
#define	A_BOLD			0x00200000U
#define	A_INVIS			0x00400000U
#define	A_PROTECT		0x00800000U
#define	A_ALTCHARSET	0x01000000U
#define	A_COLOR			0xfe000000U	/* Color mask */
#else	/* defined(_LP64) */
#define	A_NORMAL		0x00000000UL
#define	A_ATTRIBUTES	0xffff0000UL	/* Color/Attribute mask */
#define	A_CHARTEXT		0x0000ffffUL	/* 16-bit character mask */
#define	A_STANDOUT		0x00010000UL
#define	A_UNDERLINE		0x00020000UL
#define	A_REVERSE		0x00040000UL
#define	A_BLINK			0x00080000UL
#define	A_DIM			0x00100000UL
#define	A_BOLD			0x00200000UL
#define	A_INVIS			0x00400000UL
#define	A_PROTECT		0x00800000UL
#define	A_ALTCHARSET	0x01000000UL
#define	A_COLOR			0xfe000000UL	/* Color mask */
#endif	/* defined(_LP64) */

/*
 * Color atttribute support for chtype.
 */
#define	__COLOR_SHIFT	26

/*
 * Characters constants used with a chtype.
 * Mapping defined in Xcurses Section 6.2.12 (p260).
 */
#define	ACS_VLINE	(A_ALTCHARSET | 'x')
#define	ACS_HLINE	(A_ALTCHARSET | 'q')
#define	ACS_ULCORNER	(A_ALTCHARSET | 'l')
#define	ACS_URCORNER	(A_ALTCHARSET | 'k')
#define	ACS_LLCORNER	(A_ALTCHARSET | 'm')
#define	ACS_LRCORNER	(A_ALTCHARSET | 'j')
#define	ACS_RTEE	(A_ALTCHARSET | 'u')
#define	ACS_LTEE	(A_ALTCHARSET | 't')
#define	ACS_BTEE	(A_ALTCHARSET | 'v')
#define	ACS_TTEE	(A_ALTCHARSET | 'w')
#define	ACS_PLUS	(A_ALTCHARSET | 'n')
#define	ACS_S1	(A_ALTCHARSET | 'o')
#define	ACS_S9	(A_ALTCHARSET | 's')
#define	ACS_DIAMOND	(A_ALTCHARSET | '`')
#define	ACS_CKBOARD	(A_ALTCHARSET | 'a')
#define	ACS_DEGREE	(A_ALTCHARSET | 'f')
#define	ACS_PLMINUS	(A_ALTCHARSET | 'g')
#define	ACS_BULLET	(A_ALTCHARSET | '~')
#define	ACS_LARROW	(A_ALTCHARSET | ',')
#define	ACS_RARROW	(A_ALTCHARSET | '+')
#define	ACS_DARROW	(A_ALTCHARSET | '.')
#define	ACS_UARROW	(A_ALTCHARSET | '-')
#define	ACS_BOARD	(A_ALTCHARSET | 'h')
#define	ACS_LANTERN	(A_ALTCHARSET | 'i')
#define	ACS_BLOCK	(A_ALTCHARSET | '0')

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

#define	WACS_VLINE	&__WACS_VLINE
#define	WACS_HLINE	&__WACS_HLINE
#define	WACS_ULCORNER	&__WACS_ULCORNER
#define	WACS_URCORNER	&__WACS_URCORNER
#define	WACS_LLCORNER	&__WACS_LLCORNER
#define	WACS_LRCORNER	&__WACS_LRCORNER
#define	WACS_RTEE	&__WACS_RTEE
#define	WACS_LTEE	&__WACS_LTEE
#define	WACS_BTEE	&__WACS_BTEE
#define	WACS_TTEE	&__WACS_TTEE
#define	WACS_PLUS	&__WACS_PLUS
#define	WACS_S1		&__WACS_S1
#define	WACS_S9		&__WACS_S9
#define	WACS_DIAMOND	&__WACS_DIAMOND
#define	WACS_CKBOARD	&__WACS_CKBOARD
#define	WACS_DEGREE	&__WACS_DEGREE
#define	WACS_PLMINUS	&__WACS_PLMINUS
#define	WACS_BULLET	&__WACS_BULLET
#define	WACS_LARROW	&__WACS_LARROW
#define	WACS_RARROW	&__WACS_RARROW
#define	WACS_DARROW	&__WACS_DARROW
#define	WACS_UARROW	&__WACS_UARROW
#define	WACS_BOARD	&__WACS_BOARD
#define	WACS_LANTERN	&__WACS_LANTERN
#define	WACS_BLOCK	&__WACS_BLOCK


/*
 * Internal macros.
 */
#define	__m_getpary(w)		((w)->_parent == (WINDOW *) 0 ? -1 \
				: (w)->_begy - (w)->_parent->_begy)
#define	__m_getparx(w)		((w)->_parent == (WINDOW *) 0 ? -1 \
				: (w)->_begx - (w)->_parent->_begx)

/*
 * Global Window Macros
 */
#define	getyx(w, y, x)	(y = (w)->_cury, x = (w)->_curx)
#define	getbegyx(w, y, x)	(y = (w)->_begy, x = (w)->_begx)
#define	getmaxyx(w, y, x)	(y = (w)->_maxy, x = (w)->_maxx)
#define	getparyx(w, y, x)	(y = __m_getpary(w), x = __m_getparx(w))

/*
 * Global variables
 */
extern int LINES, COLS;
extern WINDOW *curscr, *stdscr;
extern int COLORS, COLOR_PAIRS;

extern int addch(chtype);
extern int addchnstr(const chtype *, int);
extern int addchstr(const chtype *);
extern int addnstr(const char *, int);
extern int addnwstr(const wchar_t *, int);
extern int addstr(const char *);
extern int add_wch(const cchar_t *);
extern int add_wchnstr(const cchar_t *, int);
extern int add_wchstr(const cchar_t *);
extern int addwstr(const wchar_t *);
extern int attroff(int);
extern int attron(int);
extern int attrset(int);
extern int attr_get(attr_t *, short *, void *);
extern int attr_off(attr_t, void *);
extern int attr_on(attr_t, void *);
extern int attr_set(attr_t, short, void *);
extern int baudrate(void);
extern int beep(void);
extern int bkgd(chtype);
extern void	bkgdset(chtype);
extern int bkgrnd(const cchar_t *);
extern void bkgrndset(const cchar_t *);
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
extern bool can_change_color(void);
extern int cbreak(void);
extern int chgat(int, attr_t, short, const void *);
extern int clearok(WINDOW *, bool);
extern int clear(void);
extern int clrtobot(void);
extern int clrtoeol(void);
extern int color_content(short, short *, short *, short *);
extern int COLOR_PAIR(int);
extern int color_set(short, void *);
extern int copywin(const WINDOW *, WINDOW *,
	int, int, int, int, int, int, int);
extern int curs_set(int);
extern int def_prog_mode(void);
extern int def_shell_mode(void);
extern int delay_output(int);
extern int delch(void);
extern int deleteln(void);
extern void delscreen(SCREEN *);
extern int delwin(WINDOW *);
extern WINDOW *derwin(WINDOW *, int, int, int, int);
extern int doupdate(void);
extern WINDOW *dupwin(WINDOW *);
extern int echo(void);
extern int echochar(const chtype);
extern int echo_wchar(const cchar_t *);
extern int endwin(void);
extern char erasechar(void);
extern int erase(void);
extern int erasewchar(wchar_t *);
extern void filter(void);
extern int flash(void);
extern int flushinp(void);
extern chtype getbkgd(WINDOW *);
extern int getbkgrnd(cchar_t *);
extern int getcchar(const cchar_t *, wchar_t *, attr_t *, short *, void *);
extern int getch(void);
extern int getnstr(char *, int);
extern int getn_wstr(wint_t *, int);
extern int getstr(char *);
extern int get_wch(wint_t *);
extern WINDOW *getwin(FILE *);
extern int get_wstr(wint_t *);
extern int halfdelay(int);
extern bool has_colors(void);
extern bool has_ic(void);
extern bool has_il(void);
extern int hline(chtype, int);
extern int hline_set(const cchar_t *, int);
extern void idcok(WINDOW *, bool);
extern int idlok(WINDOW *, bool);
extern void immedok(WINDOW *, bool);
extern chtype inch(void);
extern int inchnstr(chtype *, int);
extern int inchstr(chtype *);
extern WINDOW *initscr(void);
extern int init_color(short, short, short, short);
extern int init_pair(short, short, short);
extern int innstr(char *, int);
extern int innwstr(wchar_t *, int);
extern int insch(chtype);
extern int insdelln(int);
extern int insertln(void);
extern int insnstr(const char *, int);
extern int ins_nwstr(const wchar_t *, int);
extern int insstr(const char *);
extern int instr(char *);
extern int ins_wch(const cchar_t *);
extern int ins_wstr(const wchar_t *);
extern int intrflush(WINDOW *, bool);
extern int in_wch(cchar_t *);
extern int in_wchnstr(cchar_t *, int);
extern int in_wchstr(cchar_t *);
extern int inwstr(wchar_t *);
extern bool isendwin(void);
extern bool is_linetouched(WINDOW *, int);
extern bool is_wintouched(WINDOW *);
extern char *keyname(int);
extern char *key_name(wchar_t);
extern int keypad(WINDOW *, bool);
extern char killchar(void);
extern int killwchar(wchar_t *);
extern int leaveok(WINDOW *, bool);
extern char *longname(void);
extern int meta(WINDOW *, bool);
extern int move(int, int);
extern int mvaddch(int, int, chtype);
extern int mvaddchnstr(int, int, const chtype *, int);
extern int mvaddchstr(int, int, const chtype *);
extern int mvaddnstr(int, int, const char *, int);
extern int mvaddnwstr(int, int, const wchar_t *, int);
extern int mvaddstr(int, int, const char *);
extern int mvadd_wch(int, int, const cchar_t *);
extern int mvadd_wchnstr(int, int, const cchar_t *, int);
extern int mvadd_wchstr(int, int, const cchar_t *);
extern int mvaddwstr(int, int, const wchar_t *);
extern int mvchgat(int, int, int, attr_t, short, const void *);
extern int mvcur(int, int, int, int);
extern int mvdelch(int, int);
extern int mvderwin(WINDOW *, int, int);
extern int mvgetch(int, int);
extern int mvgetnstr(int, int, char *, int);
extern int mvgetn_wstr(int, int, wint_t *, int);
extern int mvgetstr(int, int, char *);
extern int mvget_wch(int, int, wint_t *);
extern int mvget_wstr(int, int, wint_t *);
extern int mvhline(int, int, chtype, int);
extern int mvhline_set(int, int, const cchar_t *, int);
extern chtype mvinch(int, int);
extern int mvinchnstr(int, int, chtype *, int);
extern int mvinchstr(int, int, chtype *);
extern int mvinnstr(int, int, char *, int);
extern int mvinnwstr(int, int, wchar_t *, int);
extern int mvinsch(int, int, chtype);
extern int mvinsnstr(int, int, const char *, int);
extern int mvins_nwstr(int, int, const wchar_t *, int);
extern int mvinsstr(int, int, const char *);
extern int mvinstr(int, int, char *);
extern int mvins_wch(int, int, const cchar_t *);
extern int mvins_wstr(int, int, const wchar_t *);
extern int mvin_wch(int, int, cchar_t *);
extern int mvin_wchnstr(int, int, cchar_t *, int);
extern int mvin_wchstr(int, int, cchar_t *);
extern int mvinwstr(int, int, wchar_t *);
extern int mvprintw(int, int, char *, ...);
extern int mvscanw(int, int, char *, ...);
extern int mvvline(int, int, chtype, int);
extern int mvvline_set(int, int, const cchar_t *, int);
extern int mvwaddch(WINDOW *, int, int, chtype);
extern int mvwaddchnstr(WINDOW *, int, int, const chtype *, int);
extern int mvwaddchstr(WINDOW *, int, int, const chtype *);
extern int mvwaddnstr(WINDOW *, int, int, const char *, int);
extern int mvwaddnwstr(WINDOW *, int, int, const wchar_t *, int);
extern int mvwaddstr(WINDOW *, int, int, const char *);
extern int mvwadd_wch(WINDOW *, int, int, const cchar_t *);
extern int mvwadd_wchnstr(WINDOW *, int, int, const cchar_t *, int);
extern int mvwadd_wchstr(WINDOW *, int, int, const cchar_t *);
extern int mvwaddwstr(WINDOW *, int, int, const wchar_t *);
extern int mvwchgat(WINDOW *, int, int, int, attr_t, short, const void *);
extern int mvwdelch(WINDOW *, int, int);
extern int mvwgetch(WINDOW *, int, int);
extern int mvwgetnstr(WINDOW *, int, int, char *, int);
extern int mvwgetn_wstr(WINDOW *, int, int, wint_t *, int);
extern int mvwgetstr(WINDOW *, int, int, char *);
extern int mvwget_wch(WINDOW *, int, int, wint_t *);
extern int mvwget_wstr(WINDOW *, int, int, wint_t *);
extern int mvwhline(WINDOW *, int, int, chtype, int);
extern int mvwhline_set(WINDOW *, int, int, const cchar_t *, int);
extern int mvwin(WINDOW *, int, int);
extern chtype mvwinch(WINDOW *, int, int);
extern int mvwinchnstr(WINDOW *, int, int, chtype *, int);
extern int mvwinchstr(WINDOW *, int, int, chtype *);
extern int mvwinnstr(WINDOW *, int, int, char *, int);
extern int mvwinnwstr(WINDOW *, int, int, wchar_t *, int);
extern int mvwinsch(WINDOW *, int, int, chtype);
extern int mvwinsnstr(WINDOW *, int, int, const char *, int);
extern int mvwins_nwstr(WINDOW *, int, int, const wchar_t *, int);
extern int mvwinsstr(WINDOW *, int, int, const char *);
extern int mvwinstr(WINDOW *, int, int, char *);
extern int mvwins_wch(WINDOW *, int, int, const cchar_t *);
extern int mvwins_wstr(WINDOW *, int, int, const wchar_t *);
extern int mvwin_wch(WINDOW *, int, int, cchar_t *);
extern int mvwin_wchnstr(WINDOW *, int, int, cchar_t *, int);
extern int mvwin_wchstr(WINDOW *, int, int, cchar_t *);
extern int mvwinwstr(WINDOW *, int, int, wchar_t *);
extern int mvwprintw(WINDOW *, int, int, char *, ...);
extern int mvwscanw(WINDOW *, int, int, char *, ...);
extern int mvwvline(WINDOW *, int, int, chtype, int);
extern int mvwvline_set(WINDOW *, int, int, const cchar_t *, int);
extern int napms(int);
extern WINDOW *newpad(int, int);
extern SCREEN *newterm(char *, FILE *, FILE *);
extern WINDOW *newwin(int, int, int, int);
extern int nl(void);
extern int nocbreak(void);
extern int nodelay(WINDOW *, bool);
extern int noecho(void);
extern int nonl(void);
extern void noqiflush(void);
extern int noraw(void);
extern int notimeout(WINDOW *, bool);
extern int overlay(const WINDOW *, WINDOW *);
extern int overwrite(const WINDOW *, WINDOW *);
extern int pair_content(short, short *, short *);
extern int PAIR_NUMBER(int);
extern int pechochar(WINDOW *, chtype);
extern int pecho_wchar(WINDOW *, const cchar_t *);
extern int pnoutrefresh(WINDOW *, int, int, int, int, int, int);
extern int prefresh(WINDOW *, int, int, int, int, int, int);
extern int printw(char *, ...);
extern int putwin(WINDOW *,  FILE *);
extern void qiflush(void);
extern int raw(void);
extern int redrawwin(WINDOW *);
extern int refresh(void);
extern int reset_prog_mode(void);
extern int reset_shell_mode(void);
extern int resetty(void);
extern int ripoffline(int, int (*)(WINDOW *, int));
extern int savetty(void);
extern int scanw(char *, ...);
extern int scr_dump(const char *);
extern int scr_init(const char *);
extern int scrl(int);
extern int scroll(WINDOW *);
extern int scrollok(WINDOW *, bool);
extern int scr_restore(const char *);
extern int scr_set(const char *);
extern int setcchar(cchar_t *, const wchar_t *, const attr_t,
	short, const void *);
extern int setscrreg(int, int);
extern SCREEN *set_term(SCREEN *);
extern int slk_attr_off(const attr_t, void *);
extern int slk_attroff(const chtype);
extern int slk_attr_on(const attr_t, void *);
extern int slk_attron(const chtype);
extern int slk_attr_set(const attr_t, short, void *);
extern int slk_attrset(const chtype);
extern int slk_clear(void);
extern int slk_color(short);
extern int slk_init(int);
extern char *slk_label(int);
extern int slk_noutrefresh(void);
extern int slk_refresh(void);
extern int slk_restore(void);
extern int slk_set(int, const char *, int);
extern int slk_touch(void);
extern int slk_wset(int, const wchar_t *, int);
extern int standend(void);
extern int standout(void);
extern int start_color(void);
extern WINDOW *subpad(WINDOW *, int, int, int, int);
extern WINDOW *subwin(WINDOW *, int, int, int, int);
extern int syncok(WINDOW *, bool);
extern chtype termattrs(void);
extern attr_t term_attrs(void);
extern char *termname(void);
extern void timeout(int);
extern int touchline(WINDOW *, int, int);
extern int touchwin(WINDOW *);
extern int typeahead(int);
extern int ungetch(int);
extern int unget_wch(const wchar_t);
extern int untouchwin(WINDOW *);
extern void use_env(bool);
extern int vid_attr(attr_t, short, void *);
extern int vidattr(chtype);
extern int vid_puts(attr_t, short, void *, int (*)(int));
extern int vidputs(chtype, int (*)(int));
extern int vline(chtype, int);
extern int vline_set(const cchar_t *, int);
extern int vwprintw(WINDOW *, char *, __va_list);
extern int vw_printw(WINDOW *, char *, __va_list);
extern int vwscanw(WINDOW *, char *, __va_list);
extern int vw_scanw(WINDOW *, char *, __va_list);
extern int waddch(WINDOW *, const chtype);
extern int waddchnstr(WINDOW *, const chtype *, int);
extern int waddchstr(WINDOW *, const chtype *);
extern int waddnstr(WINDOW *, const char *, int);
extern int waddnwstr(WINDOW *, const wchar_t *, int);
extern int waddstr(WINDOW *, const char *);
extern int wadd_wch(WINDOW *, const cchar_t *);
extern int wadd_wchnstr(WINDOW *, const cchar_t *, int);
extern int wadd_wchstr(WINDOW *, const cchar_t *);
extern int waddwstr(WINDOW *, const wchar_t *);
extern int wattroff(WINDOW *, int);
extern int wattron(WINDOW *, int);
extern int wattrset(WINDOW *, int);
extern int wattr_get(WINDOW *, attr_t *, short *, void *);
extern int wattr_off(WINDOW *, attr_t, void *);
extern int wattr_on(WINDOW *, attr_t, void *);
extern int wattr_set(WINDOW *, attr_t, short, void *);
extern int wbkgd(WINDOW *, chtype);
extern void	wbkgdset(WINDOW *, chtype);
extern int wbkgrnd(WINDOW *, const cchar_t *);
extern void wbkgrndset(WINDOW *, const cchar_t *);
extern int wborder(WINDOW *,
	chtype, chtype, chtype, chtype,
	chtype, chtype, chtype, chtype);
extern int wborder_set(WINDOW *,
	const cchar_t *, const cchar_t *,
	const cchar_t *, const cchar_t *,
	const cchar_t *, const cchar_t *,
	const cchar_t *, const cchar_t *);
extern int wchgat(WINDOW *, int, attr_t, short, const void *);
extern int wclear(WINDOW *);
extern int wclrtobot(WINDOW *);
extern int wclrtoeol(WINDOW *);
extern void wcursyncup(WINDOW *);
extern int wcolor_set(WINDOW *, short, void *);
extern int wdelch(WINDOW *);
extern int wdeleteln(WINDOW *);
extern int wechochar(WINDOW *, const chtype);
extern int wecho_wchar(WINDOW *, const cchar_t *);
extern int werase(WINDOW *);
extern int wgetbkgrnd(WINDOW *, cchar_t *);
extern int wgetch(WINDOW *);
extern int wgetnstr(WINDOW *, char *, int);
extern int wgetn_wstr(WINDOW *, wint_t *, int);
extern int wgetstr(WINDOW *, char *);
extern int wget_wch(WINDOW *, wint_t *);
extern int wget_wstr(WINDOW *, wint_t *);
extern int whline(WINDOW *, chtype, int);
extern int whline_set(WINDOW *, const cchar_t *, int);
extern chtype winch(WINDOW *);
extern int winchnstr(WINDOW *, chtype *, int);
extern int winchstr(WINDOW *, chtype *);
extern int winnstr(WINDOW *, char *, int);
extern int winnwstr(WINDOW *, wchar_t *, int);
extern int winsch(WINDOW *, chtype);
extern int winsdelln(WINDOW *, int);
extern int winsertln(WINDOW *);
extern int winsnstr(WINDOW *, const char *, int);
extern int wins_nwstr(WINDOW *, const wchar_t *, int);
extern int winsstr(WINDOW *, const char *);
extern int winstr(WINDOW *, char *);
extern int wins_wch(WINDOW *, const cchar_t *);
extern int wins_wstr(WINDOW *, const wchar_t *);
extern int win_wch(WINDOW *, cchar_t *);
extern int win_wchnstr(WINDOW *, cchar_t *, int);
extern int win_wchstr(WINDOW *, cchar_t *);
extern int winwstr(WINDOW *, wchar_t *);
extern int wmove(WINDOW *, int, int);
extern int wnoutrefresh(WINDOW *);
extern int wprintw(WINDOW *, char *, ...);
extern int wredrawln(WINDOW *, int, int);
extern int wrefresh(WINDOW *);
extern int wscanw(WINDOW *, char *, ...);
extern int wscrl(WINDOW *, int);
extern int wsetscrreg(WINDOW *, int, int);
extern int wstandend(WINDOW *);
extern int wstandout(WINDOW *);
extern void wsyncup(WINDOW *);
extern void wsyncdown(WINDOW *);
extern void wtimeout(WINDOW *, int);
extern int wtouchln(WINDOW *, int, int, int);
extern wchar_t *wunctrl(cchar_t *);
extern int wvline(WINDOW *, chtype, int);
extern int wvline_set(WINDOW *, const cchar_t *, int);

#if !defined(__lint)
/*
 * These macros can improve speed and size of an application.
 */
extern WINDOW	*__w1;
extern chtype	__cht1;
extern chtype	__cht2;
extern cchar_t	*__pcht1;
extern cchar_t	*__pcht2;

#define	addch(ch)	waddch(stdscr, ch)
#define	mvaddch(y, x, ch)	(move(y, x) ? ((ch), ERR) : addch(ch))
#define	mvwaddch(w, y, x, ch)	\
	(wmove(__w1 = (w), y, x) ? ((ch), ERR) : waddch(__w1, ch))

#define	add_wch(cp)	wadd_wch(stdscr, cp)
#define	mvadd_wch(y, x, cp)	(move(y, x) ? ((cp), ERR) : add_wch(cp))
#define	mvwadd_wch(w, y, x, cp)	\
	(wmove(__w1 = (w), y, x) ? ((cp), ERR) : wadd_wch(__w1, cp))

#define	addchnstr(chs, n)	waddchnstr(stdscr, chs, n)
#define	addchstr(chs)	waddchstr(stdscr, chs)
#define	mvaddchnstr(y, x, chs, n)	\
	(move(y, x) ? ((chs), (n), ERR) : addchnstr(chs, n))

#define	mvaddchstr(y, x, chs)	\
	(move(y, x) ? ((chs), ERR) : addchstr(chs))

#define	mvwaddchnstr(w, y, x, chs, n)	\
	(wmove(__w1 = (w), y, x) ? ((chs), (n), ERR) :\
	waddchnstr(__w1, chs, n))

#define	mvwaddchstr(w, y, x, chs)	\
	(wmove(__w1 = (w), y, x) ? ((chs), ERR) : waddchstr(__w1, chs))

#define	waddchstr(w, chs)	waddchnstr(w, chs, -1)

#define	add_wchnstr(cp, n)	wadd_wchnstr(stdscr, cp, n)
#define	add_wchstr(cp)	wadd_wchstr(stdscr, cp)
#define	mvadd_wchnstr(y, x, cp, n)	\
	(move(y, x) ? ((cp), (n), ERR) : add_wchnstr(cp, n))

#define	mvadd_wchstr(y, x, cp)	\
	(move(y, x) ? ((cp), ERR) : add_wchstr(cp))

#define	mvwadd_wchnstr(w, y, x, cp, n)	\
	(wmove(__w1 = (w), y, x) ? ((cp), (n), ERR) :\
	wadd_wchnstr(__w1, cp, n))

#define	mvwadd_wchstr(w, y, x, cp)	\
	(wmove(__w1 = (w), y, x) ? ((cp), ERR) :\
	wadd_wchstr(__w1, cp))

#define	wadd_wchstr(w, cp)	wadd_wchnstr(w, cp, -1)
#define	addnstr(s, n)	waddnstr(stdscr, s, n)
#define	addstr(s)	waddstr(stdscr, s)
#define	mvaddnstr(y, x, s, n)	\
	(move(y, x) ? (s, n, ERR) : addnstr(s, n))

#define	mvaddstr(y, x, s)	\
	(move(y, x) ? (s, ERR) : addstr(s))

#define	mvwaddnstr(w, y, x, s, n)	\
	(wmove(__w1 = (w), y, x) ? (s, n, ERR) : waddnstr(__w1, s, n))

#define	mvwaddstr(w, y, x, s)	\
	(wmove(__w1 = (w), y, x) ? (s, ERR) : waddstr(__w1, s))

#define	waddstr(w, wcs)	waddnstr(w, wcs, -1)
#define	addnwstr(wcs, n)	waddnwstr(stdscr, wcs, n)
#define	addwstr(wcs)	waddwstr(stdscr, wcs)
#define	mvaddnwstr(y, x, wcs, n)	\
	(move(y, x) ? (wcs, n, ERR) : addnwstr(wcs, n))

#define	mvaddwstr(y, x, wcs)	\
	(move(y, x) ? (wcs, ERR) : addwstr(wcs))

#define	mvwaddnwstr(w, y, x, wcs, n)	\
	(wmove(__w1 = (w), y, x) ? (wcs, n, ERR) :\
	waddnwstr(__w1, wcs, n))

#define	mvwaddwstr(w, y, x, wcs)	\
	(wmove(__w1 = (w), y, x) ? (wcs, ERR) : waddwstr(__w1, wcs))

#define	waddwstr(w, wcs)	waddnwstr(w, wcs, -1)
#define	attr_get(a, c, o)	wattr_get(stdscr, a, c, o)
#define	attr_off(a, o)	wattr_off(stdscr, a, o)
#define	attr_on(a, o)	wattr_on(stdscr, a, o)
#define	attr_set(a, c, o)	wattr_set(stdscr, a, c, o)

#define	COLOR_PAIR(n)	((chtype)(n) << __COLOR_SHIFT)
#define	PAIR_NUMBER(a)  (((chtype)(a) & A_COLOR) >> __COLOR_SHIFT)

#define	bkgd(ch)	wbkgd(stdscr, ch)
#define	bkgdset(ch)	wbkgdset(stdscr, ch)

#define	bkgrnd(b)	wbkgrnd(stdscr, b)
#define	bkgrndset(b)	wbkgrndset(stdscr, b)
#define	getbkgrnd(b)	wgetbkgrnd(stdscr, b)
#define	wgetbkgrnd(w, b)	(*(b) = (w)->_bg, OK)

#define	border(ls, rs, ts, bs, tl, tr, bl, br)	\
	wborder(stdscr, ls, rs, ts, bs, tl, tr, bl, br)

#define	border_set(ls, rs, ts, bs, tl, tr, bl, br)	\
	wborder_set(stdscr, ls, rs, ts, bs, tl, tr, bl, br)

#define	box(w, v, h)	\
	wborder(w, __cht1 = (v), __cht1, __cht2 = (h), __cht2, 0, 0, 0, 0)

#define	box_set(w, v, h)	\
	wborder_set(w, __pcht1 = (v), __pcht1, __pcht2 = (h), __pcht2,\
	0, 0, 0, 0)

#define	can_change_color()	\
	(2 < max_colors && can_change && initialize_color != NULL)

#define	has_colors()	(0 < max_colors)

#define	chgat(n, a, co, p)	wchgat(stdscr, n, a, co, p)
#define	mvchgat(y, x, n, a, co, p)	\
	(move(y, x) ? (n, a, co, p, ERR) : chgat(n, a, co, p))

#define	mvwchgat(w, y, x, n, a, co, p)	\
	(wmove(__w1 = (w), y, x) ? (n, a, co, p, ERR) :\
	wchgat(__w1, n, a, co, p))

#define	clear()	wclear(stdscr)
#define	clrtobot()	wclrtobot(stdscr)
#define	clrtoeol()	wclrtoeol(stdscr)
#define	erase()	werase(stdscr)
#define	wclear(w)	\
	(clearok(__w1 = (w), 1) ? ERR : werase(__w1))

#define	werase(w)	\
	(wmove(__w1 = (w), 0, 0) ? ERR : wclrtobot(__w1))

#define	delch()	wdelch(stdscr)
#define	mvdelch(y, x)	(move(y, x) ? ERR : delch())
#define	mvwdelch(w, y, x)	\
	(wmove(__w1 = (w), y, x) ? ERR : wdelch(__w1))

#define	deleteln()	wdeleteln(stdscr)
#define	insdelln(n)	winsdelln(stdscr, n)
#define	insertln()	winsertln(stdscr)
#define	wdeleteln(w)	winsdelln(w, -1)
#define	winsertln(w)	winsdelln(w, 1)
#define	refresh()	wrefresh(stdscr)
#define	echochar(ch)	wechochar(stdscr, ch)
#define	echo_wchar(cp)	wecho_wchar(stdscr, cp)
#define	wechochar(w, ch)	\
	(waddch(__w1 = (w), ch) ? (wrefresh(__w1), ERR) :\
	wrefresh(__w1))

#define	wecho_wchar(w, cp)	\
	(wadd_wch(__w1 = (w), cp) ? (wrefresh(__w1), ERR) :\
	wrefresh(__w1))

#define	getch()	wgetch(stdscr)
#define	mvgetch(y, x)	(move(y, x) ? ERR : getch())
#define	mvwgetch(w, y, x)	\
	(wmove(__w1 = (w), y, x) ? ERR : wgetch(__w1))

#define	get_wch(wcp)	wget_wch(stdscr, wcp)
#define	mvget_wch(y, x, wcp)	\
	(move(y, x) ? (wcp, ERR) : get_wch(wcp))

#define	mvwget_wch(w, y, x, wcp)	\
	(wmove(__w1 = (w), y, x) ? (wcp, ERR) : wget_wch(__w1, wcp))

#define	getnstr(s, n)	wgetnstr(stdscr, s, n)
#define	getstr(s)	wgetstr(stdscr, s)
#define	mvgetnstr(y, x, s, n)	\
	(move(y, x) ? (s, n, ERR) : getnstr(s, n))

#define	mvgetstr(y, x, s)	\
	(move(y, x) ? (s, ERR) : getstr(s))

#define	mvwgetnstr(w, y, x, s, n)	\
	(wmove(__w1 = (w), y, x) ? (s, n, ERR) : wgetnstr(__w1, s, n))

#define	mvwgetstr(w, y, x, s)	\
	(wmove(__w1 = (w), y, x) ? (s, ERR) : wgetstr(__w1, s))

#define	wgetstr(w, s)	wgetnstr(w, s, -1)
#define	getn_wstr(wcs, n)	wgetn_wstr(stdscr, wcs, n)
#define	get_wstr(wcs)	wget_wstr(stdscr, wcs)
#define	mvgetn_wstr(y, x, wcs, n)	\
	(move(y, x) ? (wcs, n, ERR) : getn_wstr(wcs, n))

#define	mvget_wstr(y, x, wcs)	\
	(move(y, x) ? (wcs, ERR) : get_wstr(wcs))

#define	mvwgetn_wstr(w, y, x, wcs, n)	\
	(wmove(__w1 = (w), y, x) ? (wcs, n, ERR) :\
	wgetn_wstr(__w1, wcs, n))

#define	mvwget_wstr(w, y, x, wcs)	\
	(wmove(__w1 = (w), y, x) ? (wcs, ERR) : wget_wstr(__w1, wcs))

#define	wget_wstr(w, wcs)	wgetn_wstr(w, wcs, -1)

#define	has_ic()	\
	(((insert_character != NULL || parm_ich != NULL) && \
	(delete_character != NULL || parm_dch != NULL)) || \
	(enter_insert_mode != NULL && exit_insert_mode))

#define	has_il()	\
	(((insert_line != NULL || parm_insert_line != NULL) && \
	(delete_line != NULL || parm_delete_line != NULL)) || \
	change_scroll_region != NULL)

#define	hline(ch, n)	whline(stdscr, ch, n)
#define	vline(ch, n)	wvline(stdscr, ch, n)
#define	mvhline(y, x, ch, n)	\
	(move(y, x) ? (ch, n, ERR) : hline(ch, n))

#define	mvvline(y, x, ch, n)	\
	(move(y, x) ? (ch, n, ERR) : vline(ch, n))

#define	mvwhline(w, y, x, ch, n)	\
	(wmove(__w1 = (w), y, x) ? (ch, n, ERR) : whline(__w1, ch, n))

#define	mvwvline(w, y, x, ch, n)	\
	(wmove(__w1 = (w), y, x) ? (ch, n, ERR) : wvline(__w1, ch, n))

#define	hline_set(cp, n)	whline_set(stdscr, cp, n)
#define	vline_set(cp, n)	wvline_set(stdscr, cp, n)
#define	mvhline_set(y, x, cp, n)	\
	(move(y, x) ? (cp, n, ERR) : hline_set(cp, n))

#define	mvvline_set(y, x, cp, n)	\
	(move(y, x) ? (cp, n, ERR) : vline_set(cp, n))

#define	mvwhline_set(w, y, x, cp, n)	\
	(wmove(__w1 = (w), y, x) ? (cp, n, ERR) : whline_set(__w1, cp, n))

#define	mvwvline_set(w, y, x, cp, n)	\
	(wmove(__w1 = (w), y, x) ? (cp, n, ERR) : wvline_set(__w1, cp, n))

#define	inch()	winch(stdscr)
#define	mvinch(y, x)	(move(y, x) ? ERR : inch())
#define	mvwinch(w, y, x)	\
	(wmove(__w1 = (w), y, x) ? ERR : winch(__w1))

#define	in_wch(cp)	win_wch(stdscr, cp)
#define	mvin_wch(y, x, cp)	\
	(move(y, x) ? (cp, ERR) : in_wch(cp))

#define	mvwin_wch(w, y, x, cp)	\
	(wmove(__w1 = (w), y, x) ? (cp, ERR) : win_wch(__w1, cp))

#define	inchnstr(chs, n)	winchnstr(stdscr, chs, n)
#define	inchstr(chs)	winchstr(stdscr, chs)
#define	mvinchnstr(y, x, chs, n)	\
	(move(y, x) ? (chs, n, ERR) : inchnstr(chs, n))

#define	mvinchstr(y, x, chs)	\
	(move(y, x) ? (chs, ERR) : inchstr(chs))

#define	mvwinchnstr(w, y, x, chs, n)	\
	(wmove(__w1 = (w), y, x) ? (chs, n, ERR) : winchnstr(__w1, chs, n))

#define	mvwinchstr(w, y, x, chs)	\
	(wmove(__w1 = (w), y, x) ? (chs, ERR) : winchstr(__w1, chs))

#define	winchstr(w, chs)	winchnstr(w, chs, -1)
#define	in_wchnstr(cp, n)	win_wchnstr(stdscr, cp, n)
#define	in_wchstr(cp)	win_wchstr(stdscr, cp)
#define	mvin_wchnstr(y, x, cp, n)	\
	(move(y, x) ? (cp, n, ERR) : in_wchnstr(cp, n))

#define	mvin_wchstr(y, x, cp)	\
	(move(y, x) ? (cp, ERR) : in_wchstr(cp))

#define	mvwin_wchnstr(w, y, x, cp, n)	\
	(wmove(__w1 = (w), y, x) ? (cp, n, ERR) :\
	win_wchnstr(__w1, cp, n))

#define	mvwin_wchstr(w, y, x, cp)	\
	(wmove(__w1 = (w), y, x) ? (cp, ERR) : win_wchstr(__w1, cp))

#define	win_wchstr(w, cp)	win_wchnstr(w, cp, -1)
#define	innstr(s, n)	winnstr(stdscr, s, n)
#define	instr(s)	winstr(stdscr, s)
#define	mvinnstr(y, x, s, n)	\
	(move(y, x) ? (s, n, ERR) : innstr(s, n))

#define	mvinstr(y, x, s)	\
	(move(y, x) ? (s, ERR) : instr(s))

#define	mvwinnstr(w, y, x, s, n)	\
	(wmove(__w1 = (w), y, x) ? (s, n, ERR) : winnstr(__w1, s, n))

#define	mvwinstr(w, y, x, s)	\
	(wmove(__w1 = (w), y, x) ? (s, ERR) : winstr(__w1, s))

#define	winstr(w, s)	(winnstr(w, s, -1), OK)
#define	innwstr(wcs, n)	winnwstr(stdscr, wcs, n)
#define	inwstr(wcs)	winwstr(stdscr, wcs)
#define	mvinnwstr(y, x, wcs, n)	\
	(move(y, x) ? (wcs, n, ERR) : innwstr(wcs, n))

#define	mvinwstr(y, x, wcs)	\
	(move(y, x) ? (wcs, ERR) : inwstr(wcs))

#define	mvwinnwstr(w, y, x, wcs, n)	\
	(wmove(__w1 = (w), y, x) ? (wcs, n, ERR) :\
	winnwstr(__w1, wcs, n))

#define	mvwinwstr(w, y, x, wcs)	\
	(wmove(__w1 = (w), y, x) ? (wcs, ERR) : winwstr(__w1, wcs))

#define	winwstr(w, wcs)	(winnwstr(w, wcs, -1), OK)
#define	insch(ch)	winsch(stdscr, ch)
#define	mvinsch(y, x, ch)	(move(y, x) ? (ch, ERR) : insch(ch))
#define	mvwinsch(w, y, x, ch)	\
	(wmove(__w1 = (w), y, x) ? (ch, ERR) : winsch(__w1, ch))

#define	ins_wch(cp)	wins_wch(stdscr, cp)
#define	mvins_wch(y, x, cp)	(move(y, x) ? (cp, ERR) : ins_wch(cp))
#define	mvwins_wch(w, y, x, cp)	\
	(wmove(__w1 = (w), y, x) ? (cp, ERR) : wins_wch(__w1, cp))

#define	insnstr(s, n)	winsnstr(stdscr, s, n)
#define	insstr(s)	winsstr(stdscr, s)
#define	mvinsnstr(y, x, s, n)	(move(y, x) ? (s, n, ERR) : insnstr(s, n))
#define	mvinsstr(y, x, s)	(move(y, x) ? (s, ERR) : insstr(s))
#define	mvwinsnstr(w, y, x, s, n)	\
	(wmove(__w1 = (w), y, x) ? (s, n, ERR) : winsnstr(__w1, s, n))

#define	mvwinsstr(w, y, x, s)	\
	(wmove(__w1 = (w), y, x) ? (s, ERR) : winsstr(__w1, s))

#define	winsstr(w, s)	winsnstr(w, s, -1)
#define	ins_nwstr(wcs, n)	wins_nwstr(stdscr, wcs, n)
#define	ins_wstr(wcs)	wins_wstr(stdscr, wcs)
#define	mvins_nwstr(y, x, wcs, n)	\
	(move(y, x) ? (wcs, n, ERR) : ins_nwstr(wcs, n))

#define	mvins_wstr(y, x, wcs)	(move(y, x) ? (wcs, ERR) : ins_wstr(wcs))
#define	mvwins_nwstr(w, y, x, wcs, n)	\
	(wmove(__w1 = (w), y, x) ? (wcs, n, ERR) : wins_nwstr(__w1, wcs, n))

#define	mvwins_wstr(w, y, x, wcs)	\
	(wmove(__w1 = (w), y, x) ? (wcs, ERR) : wins_wstr(__w1, wcs))

#define	wins_wstr(w, wcs)	wins_nwstr(w, wcs, -1)
#define	is_linetouched(w, y)	(0 <= (w)->_last[y])
#define	move(y, x)	wmove(stdscr, y, x)
#define	subpad(par, ny, nx, by, bx)	subwin(par, ny, nx, by, bx)
#define	nodelay(w, bf)	(wtimeout(w, (bf) ? 0: -1), OK)
#define	timeout(n)	wtimeout(stdscr, n)
#define	qiflush()	((void) intrflush(NULL, 1))
#define	noqiflush()	((void) intrflush(NULL, 0))
#define	redrawwin(w)	wredrawln(__w1 = (w), 0, (__w1)->_maxy)
#define	scrl(n)	wscrl(stdscr, n)
#define	setscrreg(t, b)	wsetscrreg(stdscr, t, b)
#define	standend()	wstandend(stdscr)
#define	standout()	wstandout(stdscr)
#define	touchline(w, y, n)	wtouchln(w, y, n, 1)
#define	touchwin(w)	wtouchln(__w1 = (w), 0, __w1->_maxy, 1)
#define	untouchwin(w)	wtouchln(__w1 = (w), 0, __w1->_maxy, 0)
#define	termname()			(cur_term->_term)

#endif	/* !defined(__lint) */

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

#ifdef	__cplusplus
}
#endif

#endif /* _CURSES_H */

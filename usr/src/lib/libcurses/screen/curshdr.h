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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef _CURSHDR_H
#define	_CURSHDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	_NOHASH		(-1)	/* if the hash value is unknown */
#define	_REDRAW		(-2)	/* if line need redrawn */
#define	_BLANK		(-3)	/* if line is blank */
#define	_THASH		(123)	/* base hash if clash with other hashes */
#define	_KEY		(01)
#define	_MACRO		(02)

#define	_INPUTPENDING	cur_term->_iwait
#define	_PUTS(x, y)	(void) tputs(x, y, _outch)
#define	_VIDS(na, oa)	(vidupdate((na), (oa), _outch), curscr->_attrs = (na))
#define	_ONINSERT()	(_PUTS(enter_insert_mode, 1), SP->phys_irm = TRUE)
#define	_OFFINSERT()	(_PUTS(exit_insert_mode, 1), SP->phys_irm = FALSE)
#define	_STRNOTEQ(a, b)	(a == NULL ? (b != NULL) : \
			    (b == NULL ? 1 : strcmp(a, b)))

/*
 * IC and IL overheads and costs should be set to this
 * value if the corresponding feature is missing
 */

#define	LARGECOST	500

typedef	struct
{
    short	icfixed;		/* Insert char fixed overhead */
    short	dcfixed;		/* Delete char fixed overhead */
    short	Insert_character;
    short	Delete_character;
    short	Cursor_home;
    short	Cursor_to_ll;
    short	Cursor_left;
    short	Cursor_right;
    short	Cursor_down;
    short	Cursor_up;
    short	Carriage_return;
    short	Tab;
    short	Back_tab;
    short	Clr_eol;
    short	Clr_bol;
    short	Parm_ich;
    short	Parm_dch;
    short	Parm_left_cursor;
    short	Parm_up_cursor;
    short	Parm_down_cursor;
    short	Parm_right_cursor;
    short	Cursor_address;
    short	Row_address;
} COSTS;

#define	_COST(field)	(SP->term_costs.field)

/* Soft label keys */

#define	LABMAX	16	/* max number of labels allowed */
#define	LABLEN	8	/* max length of each label */

typedef	struct
{
    WINDOW	*_win;		/* the window to display labels */
    char	_ldis[LABMAX][LABLEN+1]; /* labels suitable to display */
    char	_lval[LABMAX][LABLEN+1]; /* labels' true values */
    short	_labx[LABMAX];	/* where to display labels */
    short	_num;		/* actual number of labels */
    short	_len;		/* real length of labels */
    bool	_changed;	/* TRUE if some labels changed */
    bool	_lch[LABMAX];	/* change status */
} SLK_MAP;

struct	screen
{
    unsigned	fl_echoit : 1;	/* in software echo mode */
    unsigned	fl_endwin : 2;	/* has called endwin */
    unsigned	fl_meta : 1;	/* in meta mode */
    unsigned	fl_nonl : 1;	/* do not xlate input \r-> \n */
    unsigned	yesidln : 1;	/* has idln capabilities */
    unsigned	dmode : 1;	/* Terminal has delete mode */
    unsigned	imode : 1;	/* Terminal has insert mode */
    unsigned	ichok : 1;	/* Terminal can insert characters */
    unsigned	dchok : 1;	/* Terminal can delete characters */
    unsigned	sid_equal : 1;	/* enter insert and delete mode equal */
    unsigned	eid_equal : 1;	/* exit insert and delete mode equal */
    unsigned	phys_irm : 1;	/* in insert mode or not */
    long	baud;		/* baud rate of this tty */
    short	kp_state;	/* 1 iff keypad is on, else 0 */
    short	Yabove;		/* How many lines are above stdscr */
    short	lsize;		/* How many lines decided by newscreen */
    short	csize;		/* How many columns decided by newscreen */
    short	tsize;		/* How big is a tab decided by newscreen */
    WINDOW	*std_scr;	/* primary output screen */
    WINDOW	*cur_scr;	/* what's physically on the screen */
    WINDOW	*virt_scr;	/* what's virtually on the screen */
    int		*cur_hash;	/* hash table of curscr */
    int		*virt_hash;	/* hash table of virtscr */
    TERMINAL	*tcap;		/* TERMINFO info */
    FILE	*term_file;	/* File to write on for output. */
    FILE	*input_file;	/* Where to get keyboard input */
    SLK_MAP	*slk;		/* Soft label information */
    char	**_mks;		/* marks, only used with xhp terminals */
    COSTS	term_costs;	/* costs of various capabilities */
    SGTTY	save_tty_buf;	/* saved termio state of this tty */
#ifdef	SYSV
    SGTTYS	save_tty_bufs;	/* saved termios state of this tty */
#endif
    char	**_color_mks;	/* marks, only used with color xhp terminals */
    unsigned long  _trap_mbe;		/* trap these mouse button events    */
    unsigned long  _map_mbe_to_key;	/* map selected buttons on top of    */
					/* slk's to function keys */
};

extern	SCREEN	*SP;
extern	WINDOW	*_virtscr;

#ifdef	DEBUG
#ifndef	outf
extern	FILE	*outf;
#endif	/* outf */
#endif	/* DEBUG */

extern	short	cswidth[],	/* byte size of multi-byte chars */
		_curs_scrwidth[];	/* display size */
extern	short	_csmax,
		_scrmax;
extern	bool	_mbtrue;

#define	MBIT		0200		/* indicator for a multi-byte char */
#define	CBIT		002000000000	/* indicator for a continuing col */
#define	RBYTE(x)	((x) & 0377)
#define	LBYTE(x)	(((x) >> 8) & 0177)
#define	ISMBIT(x)	((x) & MBIT)
#define	SETMBIT(x)	((x) |= MBIT)
#define	CLRMBIT(x)	((x) &= ~MBIT)
#define	ISCBIT(x)	((x) & CBIT)
#define	SETCBIT(x)	((x) |= CBIT)
#define	CLRCBIT(x)	((x) &= ~CBIT)
#define	TYPE(x)		((x) == SS2 ? 1 : (x) == SS3 ? 2 : ISMBIT(x) ? 0 : 3)
#define	TRIM		037777777777	/* 0xFFFFFFFF */

/* terminfo magic number */
#define	MAGNUM	0432

/* curses screen dump magic number */
#define	SVR2_DUMP_MAGIC_NUMBER	0433
#define	SVR3_DUMP_MAGIC_NUMBER	0434

/* Getting the baud rate is different on the two systems. */

#ifdef	SYSV
#define	_BR(x)	(x.c_cflag & CBAUD)
#define	_BRS(x)	(cfgetospeed(&x))
#include	<values.h>
#else	/* SYSV */
#define	BITSPERBYTE	8
#define	MAXINT		32767
#define	_BR(x)	(x.sg_ispeed)
#endif	/* SYSV */

#define	_BLNKCHAR	' '
#define	_CTRL(c)	(c | 0100)
#define	_ATTR(c)	((c) & A_ATTRIBUTES)
#define	_CHAR(c)	((c) & A_CHARTEXT)

/*
 *	combine CHAR par of the character with the attributes of the window.
 *	Two points: 1) If character is blank, usebackground instead
 *		    2) If character contains color, delete color from
 *			window attribute.
 */

#define	_WCHAR(w, c)    (_CHAR((c) == _BLNKCHAR ? (w)->_bkgd : (c))| \
			    (((c) & A_COLOR) ? ((w)->_attrs & ~A_COLOR) : \
			    ((w)->_attrs)))

#define	_DARKCHAR(c)	((c) != _BLNKCHAR)
#define	_UNCTRL(c)	((c) ^ 0100)

/* blank lines info of curscr */
#define	_BEGNS		curscr->_firstch
#define	_ENDNS		curscr->_lastch

/* hash tables */
#define	_CURHASH	SP->cur_hash
#define	_VIRTHASH	SP->virt_hash

/* top/bot line changed */
#define	_VIRTTOP	_virtscr->_parx
#define	_VIRTBOT	_virtscr->_pary

/* video marks */
#define	_MARKS		SP->_mks
#define	_COLOR_MARKS	SP->_color_mks

#define	_NUMELEMENTS(x)	(sizeof (x)/sizeof (x[0]))

#ifdef	_VR3_COMPAT_CODE
/*
 * #define	_TO_OCHTYPE(x)		((_ochtype)(((x&A_ATTRIBUTES)>>9)| \
 * 						(x&0x0000007FUL)))
 */
#define	_TO_OCHTYPE(x)		((_ochtype)(((x&A_ATTRIBUTES)>>9)|(x&0177)))
#define	_FROM_OCHTYPE(x)	((chtype) ((x&0177) | ((x&0177600)<<9)))
extern	void	(*_y16update)(WINDOW *, int, int, int, int);
#endif	/* _VR3_COMPAT_CODE */

/* functions for screen updates */

extern	int	(*_setidln)(void);
extern	int	(*_useidln)(void);
extern	int	(*_quick_ptr)(WINDOW *, chtype);
extern	int	(_quick_echo)(WINDOW *, chtype);

/* min/max functions */

#define	_MIN(a, b)	((a) < (b) ? (a) : (b))
#define	_MAX(a, b)	((a) > (b) ? (a) : (b))

extern	int	(*_do_slk_ref)(void);
extern	int	(*_do_slk_tch)(void);
extern	int	(*_do_slk_noref)(void);
extern	int	_image(WINDOW *);
extern	int	_outch(char);
extern	int	_outwch(chtype);
extern	int	_chkinput(void);
extern	int	_curs_mbtowc(wchar_t *, const char *, size_t);
extern	int	_curs_wctomb(char *, wchar_t);
extern	int	_delay(int, int (*)(char));
extern	int	_mbaddch(WINDOW *, chtype, chtype);
extern	int	_mbclrch(WINDOW *, int, int);
extern	int	_mbinsshift(WINDOW *, int), _mbvalid(WINDOW *);
extern	int	_padjust(WINDOW *, int, int, int, int, int, int);
extern	int	_prefresh(int (*)(WINDOW *), WINDOW *, int, int, int,
		int, int, int);
extern	int	_overlap(WINDOW *, WINDOW *, int);
extern	int	_scr_all(char *, int);
extern	int	_slk_update(void);
extern	int	_tcsearch(char *, short [], char *[], int, int);
extern	int	_vsscanf(const char *, const char *, __va_list);
extern	int	force_doupdate(void);
extern	int	init_acs(void);
extern	int	mbscrw(int);
extern	int	mbeucw(int);
extern	int	scr_ll_dump(FILE *);
extern	int	scr_reset(FILE *, int);
extern	int	setkeymap(void);
extern	int	ttimeout(int);
extern	int	wadjcurspos(WINDOW *);
extern	int	wcscrw(wchar_t);
extern	int	wmbmove(WINDOW *, int, int);

extern	chtype	tgetch(int);

extern	WINDOW	*_makenew(int, int, int, int);

extern	void	(*_slk_init)(void);
extern	void	(*_rip_init)(void);
extern	void	delkeymap(TERMINAL *);
extern	void	mbgetwidth(void);
extern	void	memSset(chtype *, chtype, int);
extern	void	_blast_keys(TERMINAL *);
extern	void	_init_costs(void);
extern	void	_init_HP_pair(short, short, short);
extern	void	_update_old_y_area(WINDOW *, int, int, int, int);

extern	char    *tparm_p0(char *);
extern	char    *tparm_p1(char *, long);
extern	char    *tparm_p2(char *, long, long);
extern	char    *tparm_p3(char *, long, long, long);
extern	char    *tparm_p4(char *, long, long, long, long);
extern	char    *tparm_p7(char *, long, long, long, long, long, long, long);


extern	char	*infotocap(char *, int *);
extern	char	*_strcode2byte(wchar_t *, char *, int);
extern	char	*wmbinch(WINDOW *, int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _CURSHDR_H */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

/*LINTLIBRARY*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	"curses_inc.h"

#ifdef	_VR2_COMPAT_CODE
extern	char	_endwin;
#endif	/* _VR2_COMPAT_CODE */

/* 1200 is put at the 0th location since 0 is probably a mistake. */
static long baud_convert[] = {
	1200, 50, 75, 110, 134, 150, 200, 300, 600, 1200,
	1800, 2400, 4800, 9600, 19200, 38400, 57600, 76800,
	115200, 153600, 230400, 307200, 460800, 921600,
	1000000, 1152000, 1500000, 2000000, 2500000,
	3000000, 3500000, 4000000
};

static	char	isfilter = 0;
static	int	_chk_trm(void);
static	void	_forget(void);

/*
 * newscreen sets up a terminal and returns a pointer to the terminal
 * structure or NULL in case of an error.  The parameters are:
 *	type: terminal type
 *	lsize, csize, tabsize: physical sizes
 *	infptr, outfptr: input and output stdio stream file pointers
 */

SCREEN	*
newscreen(char *type, int lsize, int csize, int tabsize,
	FILE *outfptr, FILE *infptr)
{
	int		old_lines = LINES, old_cols = COLS, retcode;
#ifndef	_IOFBF
	char	*sobuf;
#endif	/* _IOBUF */
	WINDOW	*old_curscr = curscr;
	SCREEN	*old = SP;
	TERMINAL	*old_term = cur_term;

#ifdef	DEBUG
	if (outf == NULL) {
		outf = fopen("trace", "w");
		if (outf == NULL) {
			perror("trace");
			exit(-1);
		}
		setbuf(outf, (char *)NULL);
	}

	if (outf)
		fprintf(outf, "NEWTERM(type=%s, outfptr=%x %d, infptr=%x %d) "
		    "isatty(2) %d, getenv %s\n", type, outfptr,
		    fileno(outfptr), infptr, fileno(infptr), isatty(2),
		    getenv("TERM"));
#endif	/* DEBUG */


	/* read in terminfo file */

	if (setupterm(type, fileno(outfptr), &retcode) != 0)
		goto err2;

	/* the max length of a multi-byte character */
	_csmax = (cswidth[0] > cswidth[1]+1 ?
	    (cswidth[0] > cswidth[2]+1 ? cswidth[0] : cswidth[2]+1) :
	    (cswidth[1] > cswidth[2] ? cswidth[1]+1 : cswidth[2]+1));
	if (_csmax > CSMAX)
		goto err2;
	/* the max length of a multi-column character */
	_scrmax = _curs_scrwidth[0] > _curs_scrwidth[1] ?
	    (_curs_scrwidth[0] > _curs_scrwidth[2] ? _curs_scrwidth[0] :
	    _curs_scrwidth[2]) : (_curs_scrwidth[1] > _curs_scrwidth[2] ?
	    _curs_scrwidth[1] : _curs_scrwidth[2]);
	/* true multi-byte/multi-column case */
	_mbtrue = (_csmax > 1 || _scrmax > 1);

	if ((curs_errno = _chk_trm()) != -1) {
		(void) strcpy(curs_parm_err, cur_term->_termname);
		goto err2;
	}

	/* use calloc because almost everything needs to be zero */
	if ((SP = (SCREEN *) calloc(1, sizeof (SCREEN))) == NULL)
		goto err1;

	SP->term_file = outfptr;
	SP->input_file = infptr;

	/*
	 * The default is echo, for upward compatibility, but we do
	 * all echoing in curses to avoid problems with the tty driver
	 * echoing things during critical sections.
	 */

	SP->fl_echoit = 1;

	/* set some fields for cur_term structure */

	(void) typeahead(fileno(infptr));
	(void) tinputfd(fileno(infptr));

	/*
	 * We use LINES instead of the SP variable and a local variable because
	 * slk_init and rip_init update the LINES value and application code
	 * may look at the value of LINES in the function called by rip_init.
	 */

	/* LINTED */
	LINES = SP->lsize = lsize > 0 ? lsize : lines;

	/* force the output to be buffered */
#ifdef	_IOFBF
	(void) setvbuf(outfptr, (char *)NULL, _IOFBF, 0);
#else	/* _IOFBF */
	if ((sobuf = malloc(BUFSIZ)) == NULL) {
		curs_errno = CURS_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(curs_parm_err, "newscreen");
#endif	/* DEBUG */
	}
	setbuf(outfptr, sobuf);
#endif	/* _IOFBF */

#ifdef	SYSV
	SP->baud = baud_convert[_BRS(PROGTTYS)];
#else	/* SYSV */
	SP->baud = baud_convert[_BR(PROGTTY)];
#endif	/* SYSV */

	/* figure out how much each terminal capability costs */
	_init_costs();

	/* initialize the array of alternate characters */
	(void) init_acs();

	SP->tcap = cur_term;

	/* set tty settings to something reasonable for us */
#ifdef	SYSV
	PROGTTYS.c_lflag &= ~ECHO;
	PROGTTYS.c_lflag |= ISIG;
	PROGTTYS.c_oflag &= ~(OCRNL|ONLCR); /* why would anyone set OCRNL? */
#else	/* SYSV */
	PROGTTY.sg_flags &= ~(RAW|ECHO|CRMOD);
#endif	/* SYSV */

	(void) cbreak();

	/* LINTED */
	COLS = SP->csize = csize > 0 ? csize : columns;
	if (tabsize == 0)
		tabsize = (init_tabs == -1) ? 8 : init_tabs;
	/* LINTED */
	SP->tsize = (short)tabsize;
#ifdef	DEBUG
	if (outf)
		fprintf(outf, "LINES = %d, COLS = %d\n", LINES, COLS);
#endif	/* DEBUG */

	if ((curscr = SP->cur_scr = newwin(LINES, COLS, 0, 0)) == NULL)
		goto err;

	SP->fl_endwin = 2;
#ifdef	_VR2_COMPAT_CODE
	_endwin = FALSE;
#endif	/* _VR2_COMPAT_CODE */
	curscr->_sync = TRUE;

	/*
	 * This will tell _quick_echo(if it's ever called), whether
	 * _quick_echo should let wrefresh handle everything.
	 */

	if (ceol_standout_glitch || (magic_cookie_glitch >= 0) ||
	    tilde_glitch || (transparent_underline && erase_overstrike)) {
		curscr->_flags |= _CANT_BE_IMMED;
	}
	if (!(SP->virt_scr = newwin(LINES, COLS, 0, 0)))
		goto err;
	_virtscr = SP->virt_scr;

	SP->virt_scr->_clear = FALSE;

	/* video mark map for cookie terminals */

	if (ceol_standout_glitch || (magic_cookie_glitch >= 0)) {
		int	i, nc;
		char	**marks;

		if ((marks = (char **)calloc((unsigned)LINES,
		    sizeof (char *))) == NULL)
			goto err;
		SP->_mks = marks;
		nc = (COLS / BITSPERBYTE) + (COLS % BITSPERBYTE ? 1 : 0);
		if ((*marks = (char *)calloc((unsigned)nc * LINES,
		    sizeof (char))) == NULL)
			goto err;
		for (i = LINES - 1; i-- > 0; ++marks)
			*(marks + 1) = *marks + nc;
	}

	/* hash tables for lines */
	if ((SP->cur_hash = (int *)calloc((unsigned)2 * LINES,
	    sizeof (int))) == NULL)
		goto err;
	SP->virt_hash = SP->cur_hash + LINES;

	/* adjust the screen size if soft labels and/or ripoffline are used */
	if (_slk_init)
		(*_slk_init)();
	if (_rip_init)
		(*_rip_init)();

	if ((SP->std_scr = newwin(LINES, COLS, 0, 0)) == NULL) {
		/* free all the storage allocated above and return NULL */
err:
		delscreen(SP);
		COLS = old_cols;
		curscr = old_curscr;
		LINES = old_lines;
err1:
		SP = old;

		curs_errno = CURS_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(curs_parm_err, "newscreen");
#endif	/* DEBUG */

err2:
		cur_term = old_term;
		return (NULL);
	}
#ifdef	DEBUG
	if (outf)
		fprintf(outf, "SP %x, stdscr %x, curscr %x\n",
		    SP, SP->std_scr, curscr);
#endif	/* DEBUG */

	if (((SP->imode = (enter_insert_mode && exit_insert_mode)) != 0) &&
	    ((SP->dmode = (enter_delete_mode && exit_delete_mode)) != 0)) {
		if (strcmp(enter_insert_mode, enter_delete_mode) == 0)
			SP->sid_equal = TRUE;
		if (strcmp(exit_insert_mode, exit_delete_mode) == 0)
			SP->eid_equal = TRUE;
	}
	SP->ichok = (SP->imode || insert_character || parm_ich);
	SP->dchok = (delete_character || parm_dch);

	stdscr = SP->std_scr;
	TABSIZE = SP->tsize;

	return (SP);
}

/*
 * check if terminal have capabilities to do basic cursor movements and
 * screen clearing
 */
static int
_chk_trm(void)
{
	short	error_num = -1;
#ifdef	DEBUG
	if (outf)
		fprintf(outf, "chk_trm().\n");
#endif	/* DEBUG */

	if (generic_type)
		error_num = CURS_UNKNOWN;
	else {
		if (isfilter) {
			_forget();
			/* Only need to move left or right on current line */
			if (!(cursor_left || carriage_return ||
			    column_address || parm_left_cursor)) {
				goto out_stupid;
			}
		} else {
			if ((hard_copy || over_strike) ||
			/* some way to move up, down, left */
			    (!(cursor_address) &&
			    (!((cursor_up || cursor_home) && cursor_down &&
			    (cursor_left || carriage_return)))) ||
			    (!clear_screen)) {
out_stupid:
				error_num = CURS_STUPID;
			}
		}
	}
	return (error_num);
}

int
filter(void)
{
	isfilter = 1;
	return (OK);
}

/*
 * if (for some reason) user assumes that terminal has only one line,
 * disable all capabilities that deal with non-horizontal cursor movement
 */
static void
_forget(void)
{
	row_address = cursor_address = clear_screen = parm_down_cursor =
	    cursor_up = cursor_down = NULL;
	cursor_home = carriage_return;
	lines = 1;
}

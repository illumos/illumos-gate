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
#include	<sys/types.h>
#include	<fcntl.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>
#include	<zone.h>
#include	"curses_inc.h"

#define	TERMPATH	"/usr/share/lib/terminfo/"
#define	TERMPATHLEN	512

extern	bool	_use_env;	/* in curses.c */

chtype	bit_attributes[NUM_ATTRIBUTES] = {
	    A_STANDOUT,
	    A_UNDERLINE,
	    A_ALTCHARSET,
	    A_REVERSE,
	    A_BLINK,
	    A_DIM,
	    A_BOLD,
	    A_INVIS,
	    A_PROTECT
	};

char	*Def_term = "unknown",	/* default terminal type */
	term_parm_err[32], ttytype[BUFSIZ], _frst_tblstr[1400];

TERMINAL		_first_term, *cur_term = &_first_term;
struct	_bool_struct	_frst_bools, *cur_bools = &_frst_bools;
struct	_num_struct	_frst_nums, *cur_nums = &_frst_nums;
struct	_str_struct	_frst_strs, *cur_strs = &_frst_strs;

/* _called_before is used/cleared by delterm.c and restart.c */
char	_called_before = 0;
short	term_errno = -1;

#ifdef SYSV
int	prog_istermios = -1;
int	shell_istermios = -1;
#endif

#ifdef	DUMPTI
extern	char	*boolfnames[], *boolnames[], *boolcodes[],
		*numfnames[], *numnames[], *numcodes[],
		*strfnames[], *strnames[], *strcodes[];

main(int argc, char **argv)	/* FOR DEBUG ONLY */
{
	if (argc > 1)
		setupterm(argv[1], 1, (int *)0);
	else
		setupterm((char *)0, 1, (int *)0);
	return (0);
}

_Pr(int ch)	/* FOR DEBUG ONLY */
{
	if (ch >= 0200) {
		printf("M-");
		ch -= 0200;
	}
	if ((ch < ' ') || (ch == 0177))
		printf("^%c", ch ^ 0100);
	else
		printf("%c", ch);
}

_Sprint(int n, char *string)	/* FOR DEBUG ONLY */
{
	int	ch;

	if (n == -1) {
		printf(".\n");
		return;
	}
	printf(", string = '");
	while (ch = *string++)
		_Pr(ch&0377);

	printf("'.\n");
}

_Mprint(int n, char *memory)	/* FOR DEBUG ONLY */
{
	unsigned	char	ch;

	while (ch = *memory++, n-- > 0)
		_Pr(ch&0377);
}

#define	_Vr2getshi()	_Vr2getsh(ip-2)

#if	vax || pdp11
#define	_Vr2getsh(ip)	(* (short *)(ip))
#endif	/* vax || pdp11 */

#ifndef	_Vr2getsh
/*
 * Here is a more portable version, which does not assume byte ordering
 * in shorts, sign extension, etc.
 */
_Vr2getsh(char *p)
{
	int	rv;

	if (*p == (char)0377)
		return (-1);
	rv = (unsigned char) *p++;
	rv += (unsigned char) *p * 256;
	return (rv);
}
#endif	/* _Vr2getsh */

#endif	/* DUMPTI */

#define	_Getshi()	_Getsh(ip); ip += 2

/*
 * "function" to get a short from a pointer.  The short is in a standard
 * format: two bytes, the first is the low order byte, the second is
 * the high order byte (base 256).  The only negative numbers allowed are
 * -1 and -2, which are represented as 255,255 and 255,254  This format
 * happens to be the same as the hardware on the pdp-11, vax, and 386,
 * making it fast and convenient and small to do this on a pdp-11.
 */

#if	vax || pdp11 || i386
#define	_Getsh(ip)	(* (short *)ip)
#endif	/* vax || pdp11 */
/*
 * The following macro is partly due to Mike Laman, laman@sdcsvax
 *	NCR @ Torrey Pines.		- Tony Hansen
 */
#if	u3b || u3b15 || u3b2 || m68000
#define	_Getsh(ip)	((short)(*((unsigned char *)ip) | (*(ip+1) << 8)))
#endif	/* u3b || u3b15 || u3b2 || m68000 */

#ifndef	_Getsh
/*
 * Here is a more portable version, which does not assume byte ordering
 * in shorts, sign extension, etc.  For the sake of the porters,
 * two alternative implementations, for the machines that don't have
 * casting to "unsigned char", are also given, but commented out.
 * Not ANSI C implementation assumes that the * C preprocessor does
 * sign-extension the same as on the machine being compiled for.
 */
static int
_Getsh(char *p)
{
	int	rv, rv2;

	rv  = (unsigned char) p[0];
	rv2 = (unsigned char) p[1];

	/* the following stuff is only for porting.  See the comment above */

#ifdef FOR_PORTING
#if    CHAR_MIN < 0
	rv = (*p++) & 0377;
	rv2 = (*p) & 0377;
#else   /* CHAR_MIN < 0 */
	rv = *p++;
	rv2 = *p;
#endif  /* CHAR_MIN < 0 */

#endif  /* FOR_PORTING  */

	if ((rv2 == 0377) && ((rv == 0377) || (rv == 0376)))
		return (-1);
	return (rv + (rv2 * 256));
}
#endif	/* _Getsh */

/*
 * setupterm: low level routine to dig up terminfo from database
 * and read it in.  Parms are terminal type (0 means use getenv("TERM"),
 * file descriptor all output will go to (for ioctls), and a pointer
 * to an int into which the error return code goes (0 means to bomb
 * out with an error message if there's an error).  Thus,
 * setupterm((char *)0, 1, (int *)0) is a reasonable way for a simple
 * program to set up.
 */
int
setupterm(char *term, int filenum, int *errret)
	/* filenum - This is a UNIX file descriptor, not a stdio ptr. */
{
	char	tiebuf[4096];
	char	fname[TERMPATHLEN];
	char	*ip;
	char	*cp;
	int	n, tfd;
	char	*lcp, *ccp, **on_sequences, **str_array;
	int	snames, nbools, nints, nstrs, sstrtab;
	char	*strtab;
#ifdef	DUMPTI
	int		Vr2val;
#endif	/* DUMPTI */

	(void) mbgetwidth();

	if (term == NULL)
		term = getenv("TERM");

	if (term == NULL || *term == '\0')
		term = Def_term;

	tfd = -1;
	errno = 0; 	/* ehr3 */

	if (errret != 0)
		*errret = -1;

	if (((cp = getenv("TERMINFO")) != 0) && *cp) {
		/* $TERMINFO/?/$TERM */
		if (snprintf(fname, sizeof (fname),
			"%s/%c/%s", cp, *term, term) >= sizeof (fname)) {
			term_errno = TERMINFO_TOO_LONG;
			goto out_err;
		}

		tfd = open(fname, 0);
#ifdef	DUMPTI
		printf("looking in file %s\n", fname);
#endif	/* DUMPTI */
		if ((tfd < 0) && (errno == EACCES))
			goto cant_read;
	}

	if (tfd < 0) {
		const char *zroot = zone_get_nroot();
		/* /usr/share/lib/terminfo/?/$TERM */
		if (snprintf(fname, sizeof (fname),
			"%s/%s/%c/%s", zroot == NULL ? "" : zroot, TERMPATH,
			*term, term) >= sizeof (fname)) {
			term_errno = TERMINFO_TOO_LONG;
			goto out_err;
		}

		tfd = open(fname, 0);
#ifdef	DUMPTI
		printf("looking in file %s\n", fname);
#endif	/* DUMPTI */

	}

	if (tfd < 0) {
		if (errno == EACCES) {
cant_read:
			term_errno = NOT_READABLE;
		} else {
			if (access(TERMPATH, 0) == -1)
				term_errno = UNACCESSIBLE;
			else {
				term_errno = NO_TERMINAL;
				if (errret != 0)
					*errret = 0;
			}
		}
		/*
		 * if the length of the specified terminal name is longer
		 * than 31, it will be chopped after the 31st byte.
		 * This should be a rare case.
		 */
		(void) strncpy(term_parm_err, term, 31);
		term_parm_err[31] = '\0';
		goto out_err;
	}

	/* LINTED */
	n = (int)read(tfd, tiebuf, sizeof (tiebuf));
	(void) close(tfd);

	if (n <= 0) {
corrupt:
		term_errno = CORRUPTED;
		goto out_err;
	} else
		if (n == sizeof (tiebuf)) {
			term_errno = ENTRY_TOO_LONG;
			goto out_err;
		}
	cp = ttytype;
	ip = tiebuf;

	/* Pick up header */
	snames = _Getshi();
#ifdef	DUMPTI
	Vr2val = _Vr2getshi();
	printf("Magic number = %d, %#o [%d, %#o].\n", snames,
	    snames, Vr2val, Vr2val);
#endif	/* DUMPTI */
	if (snames != MAGNUM)
		goto corrupt;
	snames = _Getshi();
#ifdef	DUMPTI
	Vr2val = _Vr2getshi();
	printf("Size of names = %d, %#o [%d, %#o].\n", snames,
	    snames, Vr2val, Vr2val);
#endif	/* DUMPTI */

	nbools = _Getshi();
#ifdef	DUMPTI
	Vr2val = _Vr2getshi();
	printf("Number of bools = %d, %#o [%d, %#o].\n", nbools,
	    nbools, Vr2val, Vr2val);
#endif	/* DUMPTI */

	nints = _Getshi();
#ifdef	DUMPTI
	Vr2val = _Vr2getshi();
	printf("Number of ints = %d, %#o [%d, %#o].\n", nints, nints,
	    Vr2val, Vr2val);
#endif	/* DUMPTI */

	nstrs = _Getshi();
#ifdef	DUMPTI
	Vr2val = _Vr2getshi();
	printf("Number of strings = %d, %#o [%d, %#o].\n", nstrs, nstrs,
	    Vr2val, Vr2val);
#endif	/* DUMPTI */

	sstrtab = _Getshi();
#ifdef	DUMPTI
	Vr2val = _Vr2getshi();
	printf("Size of string table = %d, %#o [%d, %#o].\n", sstrtab,
	    sstrtab, Vr2val, Vr2val);
	printf("Names are: %.*s.\n", snames, ip);
#endif	/* DUMPTI */

	/* allocate all of the space */
	strtab = NULL;
	if (_called_before) {
		/* 2nd or more times through */
		if ((cur_term = (TERMINAL *)
		    calloc(sizeof (TERMINAL), 1)) == NULL)
			goto badmalloc;
		if ((cur_bools = (struct _bool_struct *)
		    calloc(sizeof (struct _bool_struct), 1)) == NULL)
			goto freeterminal;
		if ((cur_nums = (struct _num_struct *)
		    calloc(sizeof (struct _num_struct), 1)) == NULL)
			goto freebools;
		if ((cur_strs = (struct _str_struct *)
		    calloc(sizeof (struct _str_struct), 1)) == NULL) {
freenums:
			free((char *)cur_nums);
freebools:
			free((char *)cur_bools);
freeterminal:
			free((char *)cur_term);
badmalloc:
			term_errno = TERM_BAD_MALLOC;
#ifdef	DEBUG
			strcpy(term_parm_err, "setupterm");
#endif	/* DEBUG */
out_err:
			if (errret == 0) {
				termerr();
				exit(-term_errno);
			} else
				return (ERR);
		}
	} else {
		/* First time through */
		_called_before = TRUE;
		cur_term = &_first_term;
		cur_bools = &_frst_bools;
		cur_nums = &_frst_nums;
		cur_strs = &_frst_strs;
		if (sstrtab < sizeof (_frst_tblstr))
			strtab = _frst_tblstr;
	}

	if (strtab == NULL) {
		if ((strtab = (char *)malloc((unsigned)sstrtab)) == NULL) {
			if (cur_strs != &_frst_strs)
				free((char *)cur_strs);
			goto freenums;
		}
	}

	/* no more catchable errors */
	if (errret)
		*errret = 1;

	(void) strncpy(cur_term->_termname, term, 14);
	/* In case the name is exactly 15 characters */
	cur_term->_termname[14] = '\0';
	cur_term->_bools = cur_bools;
	cur_term->_nums = cur_nums;
	cur_term->_strs = cur_strs;
	cur_term->_strtab = strtab;
	cur_term->sgr_mode = cur_term->sgr_faked = A_NORMAL;

	if (filenum == 1 && !isatty(filenum))
		filenum = 2;	/* Allow output redirect */
	/* LINTED */
	cur_term->Filedes = (short)filenum;
	_blast_keys(cur_term);
	cur_term->_iwait = cur_term->fl_typeahdok = cur_term->_chars_on_queue =
		cur_term->_fl_rawmode = cur_term->_ungotten = 0;
	cur_term->_cursorstate = 1;
	cur_term->_delay = cur_term->_inputfd = cur_term->_check_fd = -1;
	(void) memset((char *)cur_term->_regs, 0, 26 * sizeof (short));

#ifndef	DUMPTI
	(void) def_shell_mode();
	/* This is a useful default for PROGTTY, too */
#ifdef SYSV
	if (shell_istermios < 0) {
		int i;

		SHELLTTY.c_lflag = SHELLTTYS.c_lflag;
		SHELLTTY.c_oflag = SHELLTTYS.c_oflag;
		SHELLTTY.c_iflag = SHELLTTYS.c_iflag;
		SHELLTTY.c_cflag = SHELLTTYS.c_cflag;
		for (i = 0; i < NCC; i++)
			SHELLTTY.c_cc[i] = SHELLTTYS.c_cc[i];
		PROGTTY = SHELLTTY;
		prog_istermios = -1;

		PROGTTYS.c_lflag = PROGTTY.c_lflag;
		PROGTTYS.c_oflag = PROGTTY.c_oflag;
		PROGTTYS.c_iflag = PROGTTY.c_iflag;
		PROGTTYS.c_cflag = PROGTTY.c_cflag;
		for (i = 0; i < NCC; i++)
			PROGTTYS.c_cc[i] = PROGTTY.c_cc[i];
	} else {
		PROGTTYS = SHELLTTYS;
		prog_istermios = 0;
	}
#else	/* SYSV */
	PROGTTY = SHELLTTY;
#endif	/* SYSV */
#endif	/* DUMPTI */

	/* Skip names of terminals */
	(void) memcpy((char *)cp, (char *)ip, (snames * sizeof (*cp)));
	ip += snames;

	/*
	 * Pull out the booleans.
	 * The for loop below takes care of a new curses with an old tic
	 * file and visa-versa.  nbools says how many bools the tic file has.
	 * So, we only loop for as long as there are bools to read.
	 * However, if this is an old curses that doesn't have all the
	 * bools that this new tic has dumped, then the extra if
	 * "if (cp < fp)" says that if we are going to read into our structure
	 * passed its size don't do it but we still need to keep bumping
	 * up the pointer of what we read in from the terminfo file.
	 */
	{
		char	*fp = &cur_bools->Sentinel;
		char	s;
#ifdef	DUMPTI
		int	tempindex = 0;
#endif	/* DUMPTI */
		cp = &cur_bools->_auto_left_margin;
		while (nbools--) {
			s = *ip++;
#ifdef	DUMPTI
			printf("Bool %s [%s] (%s) = %d.\n",
			    boolfnames[tempindex], boolnames[tempindex],
			    boolcodes[tempindex], s);
			tempindex++;
#endif	/* DUMPTI */
			if (cp < fp)
				*cp++ = s & 01;
		}
		if (cp < fp)
			(void) memset(cp, 0, ((fp - cp) * sizeof (bool)));
	}

	/* Force proper alignment */
	if (((unsigned long) ip) & 1)
		ip++;

	/*
	 * Pull out the numbers.
	 */
	{
		short	*sp = &cur_nums->_columns;
		short	*fp = &cur_nums->Sentinel;
		int	s;
#ifdef	DUMPTI
		int	tempindex = 0;
#endif	/* DUMPTI */

		while (nints--) {
			s = _Getshi();
#ifdef	DUMPTI
			Vr2val = _Vr2getshi();
			printf("Num %s [%s] (%s) = %d [%d].\n",
			    numfnames[tempindex], numnames[tempindex],
			    numcodes[tempindex], s, Vr2val);
			tempindex++;
#endif	/* DUMPTI */
			if (sp < fp)
				if (s < 0)
					*sp++ = -1;
				else
					/* LINTED */
					*sp++ = (short)s;
		}
		if (sp < fp)
			(void) memset((char *)sp, '\377',
			    ((fp - sp) * sizeof (short)));
	}

	if (_use_env) {
		/*
		 * This ioctl defines the window size and overrides what
		 * it says in terminfo.
		 */
		{
			struct	winsize	w;

			if (ioctl(filenum, TIOCGWINSZ, &w) != -1) {
				if (w.ws_row != 0)
					cur_nums->_lines = w.ws_row;
				if (w.ws_col != 0)
					cur_nums->_columns = w.ws_col;
#ifdef	DUMPTI
				printf("ioctl TIOCGWINSZ override: "
				    "(lines, columns) = (%d, %d)\n",
				    w.ws_row, w.ws_col);
#endif	/* DUMPTI */
			}
		}

		/*
		 * Check $LINES and $COLUMNS.
		 */
		{
			int	ilines, icolumns;

			lcp = getenv("LINES");
			ccp = getenv("COLUMNS");
			if (lcp)
				if ((ilines = atoi(lcp)) > 0) {
					/* LINTED */
					cur_nums->_lines = (short)ilines;
#ifdef	DUMPTI
					printf("$LINES override: lines = %d\n",
					    ilines);
#endif	/* DUMPTI */
				}
			if (ccp)
				if ((icolumns = atoi(ccp)) > 0) {
					/* LINTED */
					cur_nums->_columns = (short)icolumns;
#ifdef	DUMPTI
					printf("$COLUMNS override: columns = "
					    "%d\n", icolumns);
#endif	/* DUMPTI */
				}
		}
	}

	/* Pull out the strings. */
	{
		char	**pp = &cur_strs->strs._back_tab;
		char	**fp = &cur_strs->strs4.Sentinel;
#ifdef	DUMPTI
		int	tempindex = 0;
		char	*startstr = ip + sizeof (short) *
					    nstrs;

		printf("string table = '");
		_Mprint(sstrtab, startstr);
		printf("'\n");
#endif	/* DUMPTI */

		while (nstrs--) {
			n = _Getshi();
#ifdef	DUMPTI
			Vr2val = _Vr2getshi();
			printf("String %s [%s] (%s) offset = %d [%d]",
			    strfnames[tempindex], strnames[tempindex],
			    strcodes[tempindex], n, Vr2val);
			tempindex++;
#endif	/* DUMPTI */
			if (pp < fp) {
#ifdef	DUMPTI
				_Sprint(n, startstr+n);
#endif	/* DUMPTI */
				if (n < 0)
					*pp++ = NULL;
				else
					*pp++ = strtab + n;
			}
#ifdef	DUMPTI
			else
				_Sprint(-1, (char *)0);
#endif	/* DUMPTI */
		}
		if (pp < fp)
		(void) memset((char *)pp, 0, ((fp - pp) * sizeof (charptr)));
	}

	(void) memcpy(strtab, ip, sstrtab);

#ifndef	DUMPTI

	/*
	 * If tabs are being expanded in software, turn this off
	 * so output won't get messed up.  Also, don't use tab
	 * or backtab, even if the terminal has them, since the
	 * user might not have hardware tabs set right.
	 */
#ifdef	SYSV
	if ((PROGTTYS.c_oflag & TABDLY) == TAB3) {
		PROGTTYS.c_oflag &= ~TABDLY;
		(void) reset_prog_mode();
		goto next;
	}
#else	/* SYSV */
	if ((PROGTTY.sg_flags & XTABS) == XTABS) {
		PROGTTY.sg_flags &= ~XTABS;
		(void) reset_prog_mode();
		goto next;
	}
#endif	/* SYSV */
	if (dest_tabs_magic_smso) {
next:
		cur_strs->strs2._tab = cur_strs->strs._back_tab = NULL;
	}

#ifdef	LTILDE
	ioctl(cur_term -> Filedes, TIOCLGET, &n);
#endif	/* LTILDE */
#endif	/* DUMPTI */

#ifdef	_VR2_COMPAT_CODE
	(void) memcpy(&cur_term->_b1, &cur_bools->_auto_left_margin,
	    (char *)&cur_term->_c1 - (char *)&cur_term->_b1);
	(void) memcpy((char *)&cur_term->_c1, (char *)&cur_nums->_columns,
	    (char *)&cur_term->_Vr2_Astrs._s1 - (char *)&cur_term->_c1);
	(void) memcpy((char *)&cur_term->_Vr2_Astrs._s1,
	    (char *)&cur_strs->strs._back_tab,
	    (char *)&cur_term->Filedes - (char *)&cur_term->_Vr2_Astrs._s1);
#endif	/* _VR2_COMPAT_CODE */

	on_sequences = cur_term->turn_on_seq;
	str_array = (char **)cur_strs;
	{
		static	char	offsets[] = {
			    35,	/* enter_standout_mode, */
			    36,	/* enter_underline_mode, */
			    25,	/* enter_alt_charset_mode, */
			    34,	/* enter_reverse_mode, */
			    26,	/* enter_blink_mode, */
			    30,	/* enter_dim_mode, */
			    27,	/* enter_bold_mode, */
			    32,	/* enter_secure_mode, */
			    33,	/* enter_protected_mode, */
			};

		for (n = 0; n < NUM_ATTRIBUTES; n++) {
			if ((on_sequences[n] = str_array[offsets[n]]) != 0)
				cur_term->bit_vector |= bit_attributes[n];
		}
	}

	if (!(set_attributes)) {
		static	char	faked_attrs[] = { 1, 3, 4, 6 },
			offsets[] = {
			    43,	/* exit_standout_mode, */
			    44,	/* exit_underline_mode, */
			    38,	/* exit_alt_charset_mode, */
			};
		char		**off_sequences = cur_term->turn_off_seq;
		int		i;

		if ((max_attributes == -1) && (ceol_standout_glitch ||
		    (magic_cookie_glitch >= 0)))
			max_attributes = 1;

		/* Figure out what attributes need to be faked. */
		/* See vidupdate.c */

		for (n = 0; n < sizeof (faked_attrs); n++) {
			if (on_sequences[0] != NULL) {
				if ((!on_sequences[i = faked_attrs[n]]) ||
				    (strcmp(on_sequences[i],
				    on_sequences[0]) == 0)) {
					cur_term->sgr_faked |=
					    bit_attributes[i];
				}
			} else {
				if (!on_sequences[i = faked_attrs[n]]) {
					cur_term->sgr_faked |=
					    bit_attributes[i];
				}
			}
		}

		cur_term->check_turn_off = A_STANDOUT | A_UNDERLINE |
		    A_ALTCHARSET;

		for (n = 0; n < sizeof (offsets); n++) {
			if ((!(off_sequences[n] = str_array[offsets[n]])) ||
			    ((n > 0) && off_sequences[0] &&
			    (strcmp(off_sequences[n], off_sequences[0]) ==
			    0)) || ((n == 2) && (exit_attribute_mode) &&
			    (strcmp(exit_attribute_mode, off_sequences[n]) ==
			    0))) {
				cur_term->check_turn_off &= ~bit_attributes[n];
			}
		}
	}
	cur_term->cursor_seq[0] = cursor_invisible;
	cur_term->cursor_seq[1] = cursor_normal;
	cur_term->cursor_seq[2] = cursor_visible;
	cur_term->_pairs_tbl = (_Color_pair *) NULL;
	cur_term->_color_tbl = (_Color *) NULL;

	return (OK);
}

void
_blast_keys(TERMINAL *terminal)
{
	terminal->_keys = NULL;
	terminal->internal_keys = NULL;
	terminal->_ksz = terminal->_first_macro = 0;
	terminal->_lastkey_ordered = terminal->_lastmacro_ordered = -1;
	(void) memset((char *)terminal->funckeystarter, 0, 0400 *
	    sizeof (bool));
}

#ifndef	DUMPTI

int
reset_prog_mode(void)
{
#ifdef	SYSV
	if (_BRS(PROGTTYS)) {
		if (prog_istermios < 0) {
			int i;

			PROGTTY.c_lflag = PROGTTYS.c_lflag;
			PROGTTY.c_oflag = PROGTTYS.c_oflag;
			PROGTTY.c_iflag = PROGTTYS.c_iflag;
			PROGTTY.c_cflag = PROGTTYS.c_cflag;
			for (i = 0; i < NCC; i++)
				PROGTTY.c_cc[i] = PROGTTYS.c_cc[i];
			(void) ioctl(cur_term -> Filedes, TCSETAW, &PROGTTY);
		} else
			(void) ioctl(cur_term -> Filedes, TCSETSW, &PROGTTYS);
	}
#else	/* SYSV */
	if (_BR(PROGTTY))
		(void) ioctl(cur_term -> Filedes, TIOCSETN, &PROGTTY);
#endif	/* SYSV */

#ifdef	LTILDE
	ioctl(cur_term -> Filedes, TIOCLGET, &cur_term -> oldlmode);
	cur_term -> newlmode = cur_term -> oldlmode & ~LTILDE;
	if (cur_term -> newlmode != cur_term -> oldlmode)
		ioctl(cur_term -> Filedes, TIOCLSET, &cur_term -> newlmode);
#endif	/* LTILDE */
#ifdef	DIOCSETT
	if (cur_term -> old.st_termt == 0)
		ioctl(cur_term->Filedes, DIOCGETT, &cur_term -> old);
	cur_term -> new = cur_term -> old;
	cur_term -> new.st_termt = 0;
	cur_term -> new.st_flgs |= TM_SET;
	ioctl(cur_term->Filedes, DIOCSETT, &cur_term -> new);
#endif	/* DIOCSETT */
	return (OK);
}

int
def_shell_mode(void)
{
#ifdef	SYSV
	if ((shell_istermios =
	    ioctl(cur_term -> Filedes, TCGETS, &SHELLTTYS)) < 0) {
		int i;

		(void) ioctl(cur_term -> Filedes, TCGETA, &SHELLTTY);
		SHELLTTYS.c_lflag = SHELLTTY.c_lflag;
		SHELLTTYS.c_oflag = SHELLTTY.c_oflag;
		SHELLTTYS.c_iflag = SHELLTTY.c_iflag;
		SHELLTTYS.c_cflag = SHELLTTY.c_cflag;
		for (i = 0; i < NCC; i++)
			SHELLTTYS.c_cc[i] = SHELLTTY.c_cc[i];
	}
#else	/* SYSV */
	(void) ioctl(cur_term -> Filedes, TIOCGETP, &SHELLTTY);
#endif	/* SYSV */
	return (OK);
}

#endif	/* DUMPTI */

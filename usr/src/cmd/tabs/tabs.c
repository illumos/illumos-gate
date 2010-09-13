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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	tabs [tabspec] [+mn] [-Ttype]
 *	set tabs (and margin, if +mn), for terminal type
 */


#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <curses.h>
#include <term.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>

#define	EQ(a, b)	(strcmp(a, b) == 0)
/*	max # columns used (needed for GSI) */
#define	NCOLS	256
#define	NTABS	65	/* max # tabs +1 (to be set) */
#define	NTABSCL	21	/* max # tabs + 1 that will be cleared */
#define	ESC	033
#define	CLEAR	'2'
#define	SET	'1'
#define	TAB	'\t'
#define	CR	'\r'
#define	NMG	0	/* no margin setting */
#define	GMG	1	/* DTC300s margin */
#define	TMG	2	/* TERMINET margin */
#define	DMG	3	/* DASI450 margin */
#define	FMG	4	/* TTY 43 margin */
#define	TRMG	5	/* Trendata 4000a */

#define	TCLRLN	0	/* long, repetitive, general tab clear */

static char tsethp[] = {ESC,  '1', 0};		/* (default) */
static char tsetibm[] = {ESC, '0', 0};		/* ibm */
static char tclrhp[] = {ESC, '3', CR, 0};	/* hp terminals */
/* short sequence for many terminals */
static char tclrsh[] = {ESC, CLEAR, CR, 0};
static char tclrgs[] = {ESC, TAB, CR, 0};	/* short, for 300s */
static char tclr40[] = {ESC, 'R', CR, 0};	/* TTY 40/2, 4424 */
static char tclribm[] = {ESC, '1', CR, 0};	/* ibm */

static struct ttab {
	char *ttype;	/* -Tttype */
	char *tclr;	/* char sequence to clear tabs and return carriage */
	int tmaxtab;	/* maximum allowed position */
} *tt;

static struct ttab termtab[] = {
	"",		tclrsh,	132,
	"1620-12",	tclrsh,	158,
	"1620-12-8",	tclrsh,	158,
	"1700-12",	tclrsh,	132,
	"1700-12-8",	tclrsh,	158,
	"300-12",	TCLRLN,	158,
	"300s-12",	tclrgs,	158,
	"4424",		tclr40,	 80,
	"4000a",	tclrsh,	132,
	"4000a-12",	tclrsh,	158,
	"450-12",	tclrsh,	158,
	"450-12-8",	tclrsh,	158,
	"2631",		tclrhp, 240,
	"2631-c",	tclrhp, 240,
	"ibm",		tclribm, 80,
	0
};

static int	err;
static int 	tmarg;
static char	settab[32], clear_tabs[32];

static int	maxtab;		/* max tab for repetitive spec */
static int	margin;
static int	margflg;	/* >0 ==> +m option used, 0 ==> not */
static char	*terminal = "";
static char	*tabspec = "-8";	/* default tab specification */

static struct termio ttyold;	/* tty table */
static int	ttyisave;	/* save for input modes */
static int	ttyosave;	/* save for output modes */
static int	istty;		/* 1 ==> is actual tty */

static struct	stat	statbuf;
static char	*devtty;

static void scantab(char *scan, int tabvect[NTABS], int level);
static void repetab(char *scan, int tabvect[NTABS]);
static void arbitab(char *scan, int tabvect[NTABS]);
static void filetab(char *scan, int tabvect[NTABS], int level);
static int getmarg(char *term);
static struct ttab *termadj();
static void settabs(int tabvect[NTABS]);
static char *cleartabs(register char *p, char *qq);
static int getnum(char **scan1);
static void endup();
static int stdtab(char option[], int tabvect[]);
static void usage();
static int chk_codes(char *codes);

int
main(int argc, char **argv)
{
	int tabvect[NTABS];	/* build tab list here */
	char *scan;	/* scan pointer to next char */
	char operand[LINE_MAX];
	int option_end = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) signal(SIGINT, endup);
	if (ioctl(1, TCGETA, &ttyold) == 0) {
		ttyisave = ttyold.c_iflag;
		ttyosave = ttyold.c_oflag;
		(void) fstat(1, &statbuf);
		devtty = ttyname(1);
		(void) chmod(devtty, 0000);	/* nobody, not even us */
		istty++;
	}
	tabvect[0] = 0;	/* mark as not yet filled in */
	while (--argc > 0) {
		scan = *++argv;
		if (*scan == '+') {
			if (!option_end) {
				if (*++scan == 'm') {
					margflg++;
					if (*++scan)
						margin = getnum(&scan);
					else
						margin = 10;
				} else {
					(void) fprintf(stderr, gettext(
				"tabs: %s: invalid tab spec\n"), scan-1);
					usage();
				}
			} else {
				/*
				 * only n1[,n2,...] operand can follow
				 * end of options delimiter "--"
				 */
				(void) fprintf(stderr, gettext(
				"tabs: %s: invalid tab stop operand\n"), scan);
				usage();
			}
		} else if (*scan == '-') {
			if (!option_end) {
				if (*(scan+1) == 'T') {
					/* allow space or no space after -T */
					if (*(scan+2) == '\0') {
						if (--argc > 0)
							terminal = *++argv;
						else
							usage();
					} else
						terminal = scan+2;
				} else if (*(scan+1) == '-')
					if (*(scan+2) == '\0')
						option_end = 1;
					else
						tabspec = scan; /* --file */
				else if (strcmp(scan+1, "code") == 0) {
					/* EMPTY */
					/* skip to next argument */
				} else if (chk_codes(scan+1) ||
				    (isdigit(*(scan+1)) && *(scan+2) == '\0')) {
					/*
					 * valid code or single digit decimal
					 * number
					 */
					tabspec = scan;
				} else {
					(void) fprintf(stderr, gettext(
					"tabs: %s: invalid tab spec\n"), scan);
					usage();
				}
			} else {
				/*
				 * only n1[,n2,...] operand can follow
				 * end of options delimiter "--"
				 */
				(void) fprintf(stderr, gettext(
				"tabs: %s: invalid tab stop operand\n"), scan);
				usage();
			}
		} else {
			/*
			 * Tab-stop values separated using either commas
			 * or blanks.  If any number (except the first one)
			 * is preceded by a plus sign, it is taken as an
			 * increment to be added to the previous value.
			 */
			operand[0] = '\0';
			while (argc > 0) {
				if (strrchr(*argv, '-') == (char *)NULL) {
					(void) strcat(operand, *argv);
					if (argc > 1)
						(void) strcat(operand, ",");
					--argc;
					++argv;
				} else {
					(void) fprintf(stderr, gettext(
		"tabs: %s: tab stop values must be positive integers\n"),
					    *argv);
					usage();
				}
			}
			tabspec = operand;	/* save tab specification */
		}
	}
	if (*terminal == '\0') {
		if ((terminal = getenv("TERM")) == (char *)NULL ||
		    *terminal == '\0') {
			/*
			 * Use tab setting and clearing sequences specified
			 * by the ANSI standard.
			 */
			terminal = "ansi+tabs";
		}
	}
	if (setupterm(terminal, 1, &err) == ERR) {
		(void) fprintf(stderr, gettext(
		"tabs: %s: terminfo file not found\n"), terminal);
		usage();
	} else if (!tigetstr("hts")) {
		(void) fprintf(stderr, gettext(
		"tabs: cannot set tabs on terminal type %s\n"), terminal);
		usage();
	}
	if (err <= 0 || columns <= 0 || set_tab == 0) {
		tt = termadj();
		if (strcmp(terminal, "ibm") == 0)
			(void) strcpy(settab, tsetibm);
		else
			(void) strcpy(settab, tsethp);
		(void) strcpy(clear_tabs, tt->tclr);
		maxtab = tt->tmaxtab;
	} else {
		maxtab = columns;
		(void) strcpy(settab, set_tab);
		(void) strcpy(clear_tabs, clear_all_tabs);
	}
	scantab(tabspec, tabvect, 0);
	if (!tabvect[0])
		repetab("8", tabvect);
	settabs(tabvect);
	endup();
	return (0);
}

/*
 * return 1 if code option is valid, otherwise return 0
 */
int
chk_codes(char *code)
{
	if (*(code+1) == '\0' && (*code == 'a' || *code == 'c' ||
	    *code == 'f' || *code == 'p' || *code == 's' || *code == 'u'))
			return (1);
	else if (*(code+1) == '2' && *(code+2) == '\0' &&
	    (*code == 'a' || *code == 'c'))
			return (1);
	else if (*code == 'c' && *(code+1) == '3' && *(code+2) == '\0')
		return (1);
	return (0);
}

/*	scantab: scan 1 tabspec & return tab list for it */
void
scantab(char *scan, int tabvect[NTABS], int level)
{
	char c;
	if (*scan == '-') {
		if ((c = *++scan) == '-')
			filetab(++scan, tabvect, level);
		else if (c >= '0' && c <= '9')
			repetab(scan, tabvect);
		else if (stdtab(scan, tabvect)) {
			endup();
			(void) fprintf(stderr, gettext(
			"tabs: %s: unknown tab code\n"), scan);
			usage();
		}
	} else {
		arbitab(scan, tabvect);
	}
}

/*	repetab: scan and set repetitve tabs, 1+n, 1+2*n, etc */

void
repetab(char *scan, int tabvect[NTABS])
{
	int incr, i, tabn;
	int limit;
	incr = getnum(&scan);
	tabn = 1;
	limit = (maxtab-1)/(incr?incr:1)-1; /* # last actual tab */
	if (limit > NTABS-2)
		limit = NTABS-2;
	for (i = 0; i <= limit; i++)
		tabvect[i] = tabn += incr;
	tabvect[i] = 0;
}

/*	arbitab: handle list of arbitrary tabs */

void
arbitab(char *scan, int tabvect[NTABS])
{
	char *scan_save;
	int i, t, last;

	scan_save = scan;
	last = 0;
	for (i = 0; i < NTABS-1; ) {
		if (*scan == '+') {
			scan++;		/* +n ==> increment, not absolute */
			if (t = getnum(&scan))
				tabvect[i++] = last += t;
			else {
				endup();
				(void) fprintf(stderr, gettext(
				"tabs: %s: invalid increment\n"), scan_save);
				usage();
			}
		} else {
			if ((t = getnum(&scan)) > last)
				tabvect[i++] = last = t;
			else {
				endup();
				(void) fprintf(stderr, gettext(
				"tabs: %s: invalid tab stop\n"), scan_save);
				usage();
			}
		}
		if (*scan++ != ',') break;
	}
	if (last > NCOLS) {
		endup();
		(void) fprintf(stderr, gettext(
	"tabs: %s: last tab stop would be set at a column greater than %d\n"),
		    scan_save, NCOLS);
		usage();
	}
	tabvect[i] = 0;
}

/*	filetab: copy tabspec from existing file */
#define	CARDSIZ	132

void
filetab(char *scan, int tabvect[NTABS], int level)
{
	int length, i;
	char c;
	int fildes;
	char card[CARDSIZ];	/* buffer area for 1st card in file */
	char state, found;
	char *temp;
	if (level) {
		endup();
		(void) fprintf(stderr, gettext(
		"tabs: %s points to another file: invalid file indirection\n"),
		    scan);
		exit(1);
	}
	if ((fildes = open(scan, O_RDONLY)) < 0) {
		endup();
		(void) fprintf(stderr, gettext("tabs: %s: "), scan);
		perror("");
		exit(1);
	}
	length = read(fildes, card, CARDSIZ);
	(void) close(fildes);
	found = state = 0;
	scan = 0;
	for (i = 0; i < length && (c = card[i]) != '\n'; i++) {
		switch (state) {
		case 0:
			state = (c == '<'); break;
		case 1:
			state = (c == ':')?2:0; break;
		case 2:
			if (c == 't')
				state = 3;
			else if (c == ':')
				state = 6;
			else if (c != ' ')
				state = 5;
			break;
		case 3:
			if (c == ' ')
				state = 2;
			else {
				scan = &card[i];
				state = 4;
			}
			break;
		case 4:
			if (c == ' ') {
				card[i] = '\0';
				state = 5;
			} else if (c == ':') {
				card[i] = '\0';
				state = 6;
			}
			break;
		case 5:
			if (c == ' ')
				state = 2;
			else if (c == ':')
				state = 6;
			break;
		case 6:
			if (c == '>') {
				found = 1;
				goto done;
			} else state = 5;
			break;
		}
	}
done:
	if (found && scan != 0) {
		scantab(scan, tabvect, 1);
		temp = scan;
		while (*++temp)
			;
		*temp = '\n';
	}
	else
		scantab("-8", tabvect, 1);
}

int
getmarg(char *term)
{
	if (strncmp(term, "1620", 4) == 0 ||
	    strncmp(term, "1700", 4) == 0 || strncmp(term, "450", 3) == 0)
		return (DMG);
	else if (strncmp(term, "300s", 4) == 0)
		return (GMG);
	else if (strncmp(term, "4000a", 5) == 0)
		return (TRMG);
	else if (strcmp(term, "43") == 0)
		return (FMG);
	else if (strcmp(term, "tn300") == 0 || strcmp(term, "tn1200") == 0)
		return (TMG);
	else
		return (NMG);
}



struct ttab *
termadj(void)
{
	struct ttab *t;

	if (strncmp(terminal, "40-2", 4) == 0 || strncmp(terminal,
	    "40/2", 4) == 0 || strncmp(terminal, "4420", 4) == 0)
		(void) strcpy(terminal, "4424");
	else if (strncmp(terminal, "ibm", 3) == 0 || strcmp(terminal,
	    "3101") == 0 || strcmp(terminal, "system1") == 0)
		(void) strcpy(terminal, "ibm");

	for (t = termtab; t->ttype; t++) {
		if (EQ(terminal, t->ttype))
			return (t);
	}
/* should have message */
	return (termtab);
}

char	*cleartabs();
/*
 *	settabs: set actual tabs at terminal
 *	note: this code caters to necessities of handling GSI and
 *	other terminals in a consistent way.
 */

void
settabs(int tabvect[NTABS])
{
	char setbuf[512];	/* 2+3*NTABS+2+NCOLS+NTABS (+ some extra) */
	char *p;		/* ptr for assembly in setbuf */
	int *curtab;		/* ptr to tabvect item */
	int i, previous, nblanks;
	if (istty) {
		ttyold.c_iflag &= ~ICRNL;
		ttyold.c_oflag &= ~(ONLCR|OCRNL|ONOCR|ONLRET);
		(void) ioctl(1, TCSETAW, &ttyold);	/* turn off cr-lf map */
	}
	p = setbuf;
	*p++ = CR;
	p = cleartabs(p, clear_tabs);

	if (margflg) {
		tmarg = getmarg(terminal);
		switch (tmarg) {
		case GMG:	/* GSI300S */
		/*
		 * NOTE: the 300S appears somewhat odd, in that there is
		 * a column 0, but there is no way to do a direct tab to it.
		 * The sequence ESC 'T' '\0' jumps to column 27 and prints
		 * a '0', without changing the margin.
		 */
			*p++ = ESC;
			*p++ = 'T';	/* setup for direct tab */
			if (margin &= 0177)	/* normal case */
				*p++ = margin;
			else {			/* +m0 case */
				*p++ = 1;	/* column 1 */
				*p++ = '\b';	/* column 0 */
			}
			*p++ = margin;	/* direct horizontal tab */
			*p++ = ESC;
			*p++ = '0';	/* actual margin set */
			break;
		case TMG:	/* TERMINET 300 & 1200 */
			while (margin--)
				*p++ = ' ';
			break;
		case DMG:	/* DASI450/DIABLO 1620 */
			*p++ = ESC;	/* direct tab ignores margin */
			*p++ = '\t';
			if (margin == 3) {
				*p++ = (margin & 0177);
				*p++ = ' ';
			}
			else
				*p++ = (margin & 0177) + 1;
			*p++ = ESC;
			*p++ = '9';
			break;
		case FMG:	/* TTY 43 */
			p--;
			*p++ = ESC;
			*p++ = 'x';
			*p++ = CR;
			while (margin--)
				*p++ = ' ';
			*p++ = ESC;
			*p++ = 'l';
			*p++ = CR;
			(void) write(1, setbuf, p - setbuf);
			return;
		case TRMG:
			p--;
			*p++ = ESC;
			*p++ = 'N';
			while (margin--)
				*p++ = ' ';
			*p++ = ESC;
			*p++ = 'F';
			break;
		}
	}

/*
 *	actual setting: at least terminals do this consistently!
 */
	previous = 1; curtab = tabvect;
	while ((nblanks = *curtab-previous) >= 0 &&
	    previous + nblanks <= maxtab) {
		for (i = 1; i <= nblanks; i++) *p++ = ' ';
		previous = *curtab++;
		(void) strcpy(p, settab);
		p += strlen(settab);
	}
	*p++ = CR;
	if (EQ(terminal, "4424"))
		*p++ = '\n';	/* TTY40/2 needs LF, not just CR */
	(void) write(1, setbuf, p - setbuf);
}


/*
 *	Set software tabs.  This only works on UNIX/370 using a series/1
 *	front-end processor.
 */


/*	cleartabs(pointer to buffer, pointer to clear sequence) */
char *
cleartabs(register char *p, char *qq)
{
	int i;
	char *q;
	q = qq;
	if (clear_tabs == 0) {		/* if repetitive sequence */
		*p++ = CR;
		for (i = 0; i < NTABSCL - 1; i++) {
			*p++ = TAB;
			*p++ = ESC;
			*p++ = CLEAR;
		}
		*p++ = CR;
	} else {
		while (*p++ = *q++)	/* copy table sequence */
			;
		p--;			/* adjust for null */
		if (EQ(terminal, "4424")) {	/* TTY40 extra delays needed */
			*p++ = '\0';
			*p++ = '\0';
			*p++ = '\0';
			*p++ = '\0';
		}
	}
	return (p);
}
/*	getnum: scan and convert number, return zero if none found */
/*	set scan ptr to addr of ending delimeter */
int
getnum(char **scan1)
{
	int n;
	char c, *scan;
	n = 0;
	scan = *scan1;
	while ((c = *scan++) >= '0' && c <= '9') n = n * 10 + c -'0';
	*scan1 = --scan;
	return (n);
}

/*	usage: terminate processing with usage message */
void
usage(void)
{
	(void) fprintf(stderr, gettext(
"usage: tabs [ -n| --file| [[-code] -a| -a2| -c| -c2| -c3| -f| -p| -s| -u]] \
[+m[n]] [-T type]\n"));

	(void) fprintf(stderr, gettext(
"       tabs [-T type][+m[n]] n1[,n2,...]\n"));

	endup();
	exit(1);
}

/*	endup: make sure tty mode reset & exit */
void
endup(void)
{

	if (istty) {
		ttyold.c_iflag = ttyisave;
		ttyold.c_oflag = ttyosave;
		/* reset cr-lf to previous */
		(void) ioctl(1, TCSETAW, &ttyold);
		(void) chmod(devtty, statbuf.st_mode);
	}
	if (err > 0) {
		(void) resetterm();
	}
}

/*
 *	stdtabs: standard tabs table
 *	format: option code letter(s), null, tabs, null
 */
static char stdtabs[] = {
'a',	0, 1, 10, 16, 36, 72, 0,		/* IBM 370 Assembler */
'a', '2', 0, 1, 10, 16, 40, 72, 0,		/* IBM Assembler alternative */
'c',	0, 1, 8, 12, 16, 20, 55, 0,		/* COBOL, normal */
'c', '2', 0, 1, 6, 10, 14, 49, 0,		/* COBOL, crunched */
'c', '3', 0, 1, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 67,
	0,					/* crunched COBOL, many tabs */
'f',	0, 1, 7, 11, 15, 19, 23, 0,		/* FORTRAN */
'p',	0, 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 0,
						/* PL/I */
's',	0, 1, 10, 55, 0, 			/* SNOBOL */
'u',	0, 1, 12, 20, 44, 0,			/* UNIVAC ASM */
0};

/*
 *	stdtab: return tab list for any "canned" tab option.
 *	entry: option points to null-terminated option string
 *		tabvect points to vector to be filled in
 *	exit: return (0) if legal, tabvect filled, ending with zero
 *		return (-1) if unknown option
 */
int
stdtab(char option[], int tabvect[])
{
	char *sp;
	tabvect[0] = 0;
	sp = stdtabs;
	while (*sp) {
		if (EQ(option, sp)) {
			while (*sp++)		/* skip to 1st tab value */
				;
			while (*tabvect++ = *sp++)	/* copy, make int */
				;
			return (0);
		}
		while (*sp++)	/* skip to 1st tab value */
			;
		while (*sp++)		/* skip over tab list */
			;
	}
	return (-1);
}

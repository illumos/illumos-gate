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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	FUNCTION PAGE INDEX
 * Function	Page		Description
 * append	16	Append chars to end of line.
 * begtrunc	16	Truncate characters from beginning of line.
 * center	5	Center text in the work area.
 * cnvtspec	7	Convert tab spec to tab positions.
 * endtrunc	16	Truncate chars from end of line.
 * inputtabs	17	Expand according to input tab specs.
 * main		3	MAIN
 * inputn	5	Read a command line option number.
 * options	4	Process command line options.
 * outputtabs	19	Contract according to output tab specs.
 * prepend	16	Prepend chars to line.
 * process	15	Process one line of input.
 * readline	14	Read one line from the file.
 * readspec	12	Read a tabspec from a file.
 * sstrip	18	Strip SCCS SID char from beginning of line.
 * sadd		18	Add SCCS SID chars to end of line.
 * type		14	Determine type of a character.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define	MAXOPTS	50
#define	NCOLS	512
#define	MAXLINE	512
#define	NUMBER	'0'
#define	LINELEN	80

static int tabtbl[500] = {		/* Table containing tab stops	*/
	1, 9, 17, 25, 33, 41, 49, 57, 65, 73, 0,
					/* Default tabs			*/
	1, 10, 16, 36, 72, 0,		/* IBM 370 Assembler		*/
	1, 10, 16, 40, 72, 0,		/* IBM 370 Assembler (alt.)	*/
	1, 8, 12, 16, 20, 55, 0,	/* COBOL			*/
	1, 6, 10, 14, 49, 0,		/* COBOL (crunched)		*/
	1, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 67, 0,
					/* COBOL (crunched, many cols.)	*/
	1, 7, 11, 15, 19, 23, 0,	/* FORTRAN			*/
	1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 0,
					/* PL/1				*/
	1, 10, 55, 0,			/* SNOBOL			*/
	1, 12, 20, 44, 0 },		/* UNIVAC Assembler		*/

	*nexttab = &tabtbl[87],		/* Pointer to next empty slot	*/

	*spectbl[40] = {	/* Table of pointers into tabtbl	*/
	&tabtbl[0],		/* Default specification		*/
	&tabtbl[11],		/* -a  specification			*/
	&tabtbl[17],		/* -a2 specification			*/
	&tabtbl[23],		/* -c  specification			*/
	&tabtbl[30],		/* -c2 specification			*/
	&tabtbl[36],		/* -c3 specification			*/
	&tabtbl[54],		/* -f  specification			*/
	&tabtbl[61],		/* -p  specification			*/
	&tabtbl[78],		/* -s  specification			*/
	&tabtbl[82] },		/* -u  specification			*/

	savek;		/* Stores char count stripped from front of line. */
static int nextspec = 10,	/* Index to next slot			*/
	sitabspec = -1,		/* Index to "standard input" spec.	*/
	effll	= 80,		/* Effective line length		*/
	optionf = 0,		/* 'f' option set			*/
	soption = 0,		/* 's' option used. */
	files	= 0,		/* Number of input files		*/
	kludge	= 0,		/* Kludge to allow reread of 1st line	*/
	okludge = 0,		/* Kludge to indicate reading "o" option */
	lock	= 0;		/* Lock to prevent file indirection	*/

static char pachar = ' ',	/* Prepend/append character		*/
	work[3*NCOLS+1],	/* Work area				*/
	*pfirst,		/* Pointer to beginning of line 	*/
	*plast,			/* Pointer to end of line		*/
	*wfirst = &work[0],	/* Pointer to beginning of work area	*/
	*wlast  = &work[3*NCOLS], /* Pointer to end of work area	*/
	siline[NCOLS],		/* First standard input line		*/
	savchr[8],		/* Holds char stripped from line start */
	format[80] = "-8";	/* Array to hold format line		*/

static struct f {
	char	option;
	int	param;
	}	optl[MAXOPTS],	/* List of command line options 	*/
		*flp = optl;	/* Pointer to next open slot		*/

static void append(int);
static void begtrunc(int);
static void center(void);
static int cnvtspec(char *);
static void endtrunc(int);
static int inputn(char *);
static void inputtabs(int);
static void options(int, char **);
static void outputtabs(int);
static void prepend(int);
static void process(FILE *);
static char *readline(FILE *, char *);
static int readspec(char *);
static void sadd(void);
static void sstrip(void);
static char type(char);

int
main(int argc, char **argv)
{
	char	*scan;		/* String scan pointer			*/
	FILE	*fp;		/* Pointer to current file		*/

	options(argc, argv);
	if (optionf) {		/* Write tab spec format line. */
		(void) fputs("<:t", stdout);
		(void) fputs(format, stdout);
		(void) fputs(" d:>\n", stdout);
	}
	if (files) {
		while (--argc) {
			scan = *++argv;
			if (*scan != '-') {
				if ((fp = fopen(scan, "r")) == NULL) {
					(void) fprintf(stderr,
					    "newform: can't open %s\n", scan);
					exit(1);
				}
				process(fp);
				(void) fclose(fp);
			}
		}
	} else {
		process(stdin);
	}
	return (0);
}


static void
options(int argc, char **argv)		/* Process command line options	*/
{
	int	n;		/* Temporary number holder		*/
	char	*scan;		/* Pointer to individual option strings	*/
	char	c;		/* Option character			*/

/*	changes to option parsing includes checks for exceeding	*/
/*	initial buffer sizes					*/

	while (--argc > 0) {
		scan = *++argv;
		if (*scan++ == '-') {
			switch (c = *scan++) {
			case 'a':
				flp->option = 'a';
				flp->param = inputn(scan);
				if (flp->param <= NCOLS)
					flp++;
				else {
					(void) fprintf(stderr, "newform: "
					    "prefix request larger than "
					    "buffer, %d\n", NCOLS);
					exit(1);
				}
				break;
			case 'b':
			case 'e':
				flp->option = c;
				flp->param = inputn(scan);
				flp++;
				break;
			case 'p':
				flp->option = 'p';
				flp->param = inputn(scan);
				if (flp->param <= NCOLS)
					flp++;
				else {
					(void) fprintf(stderr, "newform: "
					    "prefix request larger than "
					    "buffer, %d\n", NCOLS);
					exit(1);
				}
				break;
			case 'c':
				flp->option = 'c';
				flp->param = *scan ? *scan : ' ';
				flp++;
				break;
			case 'f':
				flp->option = 'f';
				optionf++;
				flp++;
				break;
			case 'i':
				flp->option = 'i';
				flp->param = cnvtspec(scan);
				flp++;
				break;
			case 'o':
				if (*scan == '-' && *(scan+1) == '0' &&
				    *(scan+2) == '\0')
					break;
			/* Above allows the -o-0 option to be ignored. */
				flp->option = 'o';
				(void) strcpy(format, scan);
				okludge++;
				flp->param = cnvtspec(scan);
				okludge--;
				if (flp->param == 0)
					(void) strcpy(format, "-8");
				flp++;
				break;
			case 'l':
				flp->option = 'l';
				flp->param = ((n = inputn(scan)) ? n : 72);
				if (flp->param <= (3*NCOLS))
					flp++;
				else {
					(void) fprintf(stderr, "newform: "
					    "line length request larger "
					    "than buffer, %d \n", (3*NCOLS));
					exit(1);
				}
				break;
			case 's':
				flp->option = 's';
				flp++;
				soption++;
				break;
			default:
				goto usageerr;
				}
			}
		else
			files++;
		}
	return;
usageerr:
	(void) fprintf(stderr, "usage: newform  [-s] [-itabspec] [-otabspec] ");
	(void) fprintf(stderr, "[-pn] [-en] [-an] [-f] [-cchar]\n\t\t");
	(void) fprintf(stderr, "[-ln] [-bn] [file ...]\n");
	exit(1);
}
/* _________________________________________________________________ */

static int
inputn(char *scan)		/* Read a command option number		*/
	/* Pointer to string of digits */
{
	int	n;		/* Number				*/
	char	c;		/* Character being scanned		*/

	n = 0;
	while ((c = *scan++) >= '0' && c <= '9')
		n = n * 10 + c - '0';
	return (n);
}
/* _________________________________________________________________ */

static void
center(void)			/* Center the text in the work area.	*/
{
	char	*tfirst;	/* Pointer for moving buffer down	*/
	char	*tlast;		/* Pointer for moving buffer up		*/
	char	*tptr;		/* Temporary				*/

	if (plast - pfirst > MAXLINE) {
		(void) fprintf(stderr, "newform: internal line too long\n");
		exit(1);
	}
	if (pfirst < &work[NCOLS]) {
		tlast = plast + (&work[NCOLS] - pfirst);
		tptr = tlast;
		while (plast >= pfirst) *tlast-- = *plast--;
		pfirst = ++tlast;
		plast = tptr;
	} else {
		tfirst = &work[NCOLS];
		tptr = tfirst;
		while (pfirst <= plast) *tfirst++ = *pfirst++;
		plast = --tfirst;
		pfirst = tptr;
	}
}

static int
cnvtspec(char *p)	/* Convert tab specification to tab positions.	*/
	/* Pointer to spec string. */
{
	int	state,		/* DFA state				*/
		spectype,	/* Specification type			*/
		number[40],	/* Array of read-in numbers		*/
		tp,		/* Pointer to last number		*/
		ix;		/* Temporary				*/
	int	tspec = 0;	/* Tab spec pointer			*/
	char	c,		/* Temporary				*/
		*filep;		/* Pointer to file name			*/
	FILE	*fp;		/* File pointer				*/

	state = 0;
	while (state >= 0) {
		c = *p++;
		switch (state) {
		case 0:
			switch (type(c)) {
			case '\0':
				spectype = 0;
				state = -1;
				break;
			case NUMBER:
				state = 1;
				tp = 0;
				number[tp] = c - '0';
				break;
			case '-':
				state = 3;
				break;
			default:
				goto tabspecerr;
				}
			break;
		case 1:
			switch (type(c)) {
			case '\0':
				spectype = 11;
				state = -1;
				break;
			case NUMBER:
				state = 1;
				number[tp] = number[tp] * 10 + c - '0';
				break;
			case ',':
				state = 2;
				break;
			default:
				goto tabspecerr;
				}
			break;
		case 2:
			if (type(c) == NUMBER) {
				state = 1;
				number[++tp] = c - '0';
				}
			else
				goto tabspecerr;

			break;
		case 3:
			switch (type(c)) {
			case '-':
				state = 4;
				break;
			case 'a':
				state = 5;
				break;
			case 'c':
				state = 7;
				break;
			case 'f':
				state = 10;
				break;
			case 'p':
				state = 11;
				break;
			case 's':
				state = 12;
				break;
			case 'u':
				state = 13;
				break;
			case NUMBER:
				state = 14;
				number[0] = c - '0';
				break;
			default:
				goto tabspecerr;
				}
			break;
		case 4:
			if (c == '\0') {
				spectype = 12;
				state = -1;
			} else {
				filep = --p;
				spectype = 13;
				state = -1;
			}
			break;
		case 5:
			if (c == '\0') {
				spectype = 1;
				state = -1;
			} else if (c == '2')
				state = 6;
			else
				goto tabspecerr;
			break;
		case 6:
			if (c == '\0') {
				spectype = 2;
				state = -1;
				}
			else
				goto tabspecerr;
			break;
		case 7:
			switch (c) {
			case '\0':
				spectype = 3;
				state = -1;
				break;
			case '2':
				state = 8;
				break;
			case '3':
				state = 9;
				break;
			default:
				goto tabspecerr;
				}
			break;
		case 8:
			if (c == '\0') {
				spectype = 4;
				state = -1;
				}
			else
				goto tabspecerr;
			break;
		case 9:
			if (c == '\0') {
				spectype = 5;
				state = -1;
				}
			else
				goto tabspecerr;
			break;
		case 10:
			if (c == '\0') {
				spectype = 6;
				state = -1;
				}
			else
				goto tabspecerr;
			break;
		case 11:
			if (c == '\0') {
				spectype = 7;
				state = -1;
				}
			else
				goto tabspecerr;
			break;
		case 12:
			if (c == '\0') {
				spectype = 8;
				state = -1;
				}
			else
				goto tabspecerr;
			break;
		case 13:
			if (c == '\0') {
				spectype = 9;
				state = -1;
				}
			else
				goto tabspecerr;
			break;
		case 14:
			if (type(c) == NUMBER) {
				state = 14;
				number[0] = number[0] * 10 + c - '0';
			} else if (c == '\0') {
				spectype = 10;
				state = -1;
			} else
				goto tabspecerr;
			break;
		}
	}
	if (spectype <= 9)
		return (spectype);
	if (spectype == 10) {
		spectype = nextspec++;
		spectbl[spectype] = nexttab;
		*nexttab = 1;
		if (number[0] == 0) number[0] = 1; /* Prevent infinite loop. */
		while (*nexttab < LINELEN) {
			*(nexttab + 1) = *nexttab;
			*++nexttab += number[0];
			}
		*nexttab++ = '\0';
		return (spectype);
	}
	if (spectype == 11) {
		spectype = nextspec++;
		spectbl[spectype] = nexttab;
		*nexttab++ = 1;
		for (ix = 0; ix <= tp; ix++) {
			*nexttab++ = number[ix];
			if ((number[ix] >= number[ix+1]) && (ix != tp))
				goto tabspecerr;
			}
		*nexttab++ = '\0';
		return (spectype);
	}
	if (lock == 1) {
		(void) fprintf(stderr,
		    "newform: tabspec indirection illegal\n");
		exit(1);
	}
	lock = 1;
	if (spectype == 12) {
		if (sitabspec >= 0) {
			tspec = sitabspec;
		} else {
			if (readline(stdin, siline) != NULL) {
				kludge = 1;
				tspec = readspec(siline);
				sitabspec = tspec;
			}
		}
	}
	if (spectype == 13) {
		if ((fp = fopen(filep, "r")) == NULL) {
			(void) fprintf(stderr,
			    "newform: can't open %s\n", filep);
			exit(1);
		}
		(void) readline(fp, work);
		(void) fclose(fp);
		tspec = readspec(work);
	}
	lock = 0;
	return (tspec);
tabspecerr:
	(void) fprintf(stderr, "newform: tabspec in error\n");
	(void) fprintf(stderr,
	    "tabspec is \t-a\t-a2\t-c\t-c2\t-c3\t-f\t-p\t-s\n");
	(void) fprintf(stderr,
	    "\t\t-u\t--\t--file\t-number\tnumber,..,number\n");
	exit(1);
	/* NOTREACHED */
}

static int
readspec(char *p)		/* Read a tabspec from a file		*/
	/* Pointer to buffer to process */
{
	int	state,		/* Current state			*/
		firsttime,	/* Flag to indicate spec found		*/
		value;		/* Function value			*/
	char	c,		/* Char being looked at			*/
		*tabspecp,	/* Pointer to spec string		*/
		*restore = " ",	/* Character to be restored		*/
		repch;		/* Character to replace with		*/

	state = 0;
	firsttime = 1;
	while (state >= 0) {
		c = *p++;
		switch (state) {
		case 0:
			state = (c == '<') ? 1 : 0;
			break;
		case 1:
			state = (c == ':') ? 2 : 0;
			break;
		case 2:
			state = (c == 't') ? 4
				: ((c == ' ') || (c == '\t')) ? 2 : 3;
			break;
		case 3:
			state = ((c == ' ') || (c == '\t')) ? 2 : 3;
			break;
		case 4:
			if (firsttime) {
				tabspecp = --p;
				p++;
				firsttime = 0;
				}
			if ((c == ' ') || (c == '\t') || (c == ':')) {
				repch = *(restore = p - 1);
				*restore = '\0';
				}
			state = (c == ':') ? 6
				: ((c == ' ') || (c == '\t')) ? 5 : 4;
			break;
		case 5:
			state = (c == ':') ? 6 : 5;
			break;
		case 6:
			state = (c == '>') ? -2 : 5;
			break;
			}
		if (c == '\n') state = -1;
		}
	if (okludge)
		(void) strcpy(format, tabspecp);
	value = (state == -1) ? 0 : cnvtspec(tabspecp);
	*restore = repch;
	return (value);
}

static char *
readline(FILE *fp, char *area)		/* Read one line from the file.	*/
	/* fp - File to read from */
	/* area - Array of characters to read into */
{
	int	c;		/* Current character			*/
	char	*xarea,		/* Temporary pointer to character array	*/
		*temp;		/* Array pointer			*/



/* check for existence of stdin before attempting to read 		*/
/* kludge refers to reading from stdin to get tabspecs for option -i--	*/

	xarea = area;
	if (kludge && (fp == stdin)) {
		if (fp != NULL) {
			temp = siline;
			while ((*area++ = *temp++) != '\n')
				;
			kludge = 0;
			return (xarea);
		} else
			return (NULL);
	} else {

/* check for exceeding size of buffer when reading valid input */

		while (wlast - area) {
			switch (c = getc(fp)) {
			case EOF:
				if (area == xarea)
					return (NULL);
				/* FALLTHROUGH */
			case '\n':	/* EOF falls through to here */
				*area = '\n';
				return (xarea);
			}
			*area = c;
			area++;
		}
		(void) printf("newform: input line larger than buffer area \n");
		exit(1);
	}
	/* NOTREACHED */
}
/* _________________________________________________________________ */

static char
type(char c)			/* Determine type of a character	*/
	/* Character to check */
{
	return ((c >= '0') && (c <= '9') ? NUMBER : c);
}

static void
process(FILE *fp)		/* Process one line of input		*/
	/* File pointer for current input */
{
	struct	f	*lp;	/* Pointer to structs			*/
	char	chrnow;		/* For int to char conversion. */

	while (readline(fp, &work[NCOLS]) != NULL) {
		effll = 80;
		pachar = ' ';
		pfirst = plast = &work[NCOLS];
		while (*plast != '\n') plast++;

/*	changes to line parsing includes checks for exceeding	*/
/*	line size when modifying text				*/

		for (lp = optl; lp < flp; lp++) {
			switch (lp->option) {
			case 'a':
				append(lp->param);
				break;
			case 'b':
				if (lp->param <= (plast - pfirst))
					begtrunc(lp->param);
				else
					(void) fprintf(stderr,
					    "newform: truncate "
					    "request larger than line, %d \n",
					    (plast - pfirst));
				break;
			case 'c':
				chrnow = lp->param;
				pachar = chrnow ? chrnow : ' ';
				break;
			case 'e':
				if (lp->param <= (plast - pfirst))
					endtrunc(lp->param);
				else
					(void) fprintf(stderr,
					    "newform: truncate "
					    "request larger than line, %d \n",
					    (plast - pfirst));
				break;
			case 'f':
				/* Ignored */
				break;
			case 'i':
				inputtabs(lp->param);
				break;
			case 'l':	/* New eff line length */
				effll = lp->param ? lp->param : 72;
				break;
			case 's':
				sstrip();
				break;
			case 'o':
				outputtabs(lp->param);
				break;
			case 'p':
				prepend(lp->param);
				break;
			}
		}
		if (soption) sadd();
		*++plast = '\0';
		(void) fputs(pfirst, stdout);
	}
}

static void
append(int n)			/* Append characters to end of line.	*/
	/* Number of characters to append. */
{
	if (plast - pfirst < effll) {
		n = n ? n : effll - (plast - pfirst);
		if (plast + n > wlast) center();
		while (n--) *plast++ = pachar;
		*plast = '\n';
		}
}
/* _________________________________________________________________ */

static void
prepend(int n)			/* Prepend characters to line.		*/
	/* Number of characters to prepend. */
{
	if (plast - pfirst < effll) {
		n = n ? n : effll - (plast - pfirst);
		if (pfirst - n < wfirst) center();
		while (n--) *--pfirst = pachar;
		}
}
/* _________________________________________________________________ */

static void
begtrunc(int n)		/* Truncate characters from beginning of line.	*/
	/* Number of characters to truncate. */
{
	if (plast - pfirst > effll) {
		n = n ? n : plast - pfirst - effll;
		pfirst += n;
		if (pfirst >= plast)
			*(pfirst = plast = &work[NCOLS]) = '\n';
		}
}
/* _________________________________________________________________ */

static void
endtrunc(int n)			/* Truncate characters from end of line. */
	/* Number of characters to truncate. */
{
	if (plast - pfirst > effll) {
		n = n ? n : plast - pfirst - effll;
		plast -= n;
		if (pfirst >= plast)
			*(pfirst = plast = &work[NCOLS]) = '\n';
		else
			*plast = '\n';
		}
}

static void
inputtabs(int p)	/* Expand according to input tab specifications. */
	/* Pointer to tab specification. */
{
	int	*tabs;		/* Pointer to tabs			*/
	char	*tfirst,	/* Pointer to new buffer start		*/
		*tlast;		/* Pointer to new buffer end		*/
	char	c;		/* Character being scanned		*/
	int	logcol;		/* Logical column			*/

	tabs = spectbl[p];
	tfirst = tlast = work;
	logcol = 1;
	center();
	while (pfirst <= plast) {
		if (logcol >= *tabs) tabs++;
		switch (c = *pfirst++) {
		case '\b':
			if (logcol > 1) logcol--;
			*tlast++ = c;
			if (logcol < *tabs) tabs--;
			break;
		case '\t':
			while (logcol < *tabs) {
				*tlast++ = ' ';
				logcol++;
				}
			tabs++;
			break;
		default:
			*tlast++ = c;
			logcol++;
			break;
			}
		}
	pfirst = tfirst;
	plast = --tlast;
}
/*
 * Add SCCS SID (generated by a "get -m" command) to the end of each line.
 * Sequence is as follows for EACH line:
 *	Check for at least 1 tab.  Err if none.
 *	Strip off all char up to & including first tab.
 *	If more than 8 char were stripped, the 8 th is replaced by
 *		a '*' & the remainder are discarded.
 *	Unless user specified an "a", append blanks to fill
 *		out line to eff. line length (default= 72 char).
 *	Truncate lines > eff. line length (default=72).
 *	Add stripped char to end of line.
 */
static void
sstrip(void)
{
	int i, k;
	char *c, *savec;

	k = -1;
	c = pfirst;
	while (*c != '\t' && *c != '\n') {
		k++;
		c++;
	}
	if (*c != '\t') {
		(void) fprintf(stderr, "not -s format\r\n");
		exit(1);
	}

	savec = c;
	c = pfirst;
	savek = (k > 7) ? 7 : k;
	for (i = 0; i <= savek; i++) savchr[i] = *c++;	/* Tab not saved */
	if (k > 7) savchr[7] = '*';

	pfirst = ++savec;		/* Point pfirst to char after tab */
}
/* ================================================================= */

static void
sadd(void)
{
	int i;

	for (i = 0; i <= savek; i++) *plast++ = savchr[i];
	*plast = '\n';
}

static void
outputtabs(int p)	/* Contract according to output tab specifications. */
	/* Pointer to tab specification. */
{
	int	*tabs;		/* Pointer to tabs			*/
	char	*tfirst,	/* Pointer to new buffer start		*/
		*tlast,		/* Pointer to new buffer end		*/
		*mark;		/* Marker pointer			*/
	char c;			/* Character being scanned		*/
	int	logcol;		/* Logical column			*/

	tabs = spectbl[p];
	tfirst = tlast = pfirst;
	logcol = 1;
	while (pfirst <= plast) {
		if (logcol == *tabs) tabs++;
		switch (c = *pfirst++) {
		case '\b':
			if (logcol > 1) logcol--;
			*tlast++ = c;
			if (logcol < *tabs) tabs--;
			break;
		case ' ':
			mark = tlast;
			do {
				*tlast++ = ' ';
				logcol++;
				if (logcol == *tabs) {
					*mark++ = '\t';
					tlast = mark;
					tabs++;
					}
				} while (*pfirst++ == ' ');
			pfirst--;
			break;
		default:
			logcol++;
			*tlast++ = c;
			break;
			}
		}
	pfirst = tfirst;
	plast = --tlast;
}

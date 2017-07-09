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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/* Copyright (c) 1982 Regents of the University of California */

/*
 *    unifdef - remove ifdef'ed lines
 */

#include <stdio.h>
#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

FILE *input;
#ifndef YES
#define	YES 1
#define	NO  0
#endif

char *progname;
char *filename;
char text;		/* -t option in effect: this is a text file */
char lnblank;		/* -l option in effect: blank deleted lines */
char complement;	/* -c option in effect: complement the operation */
#define	MAXSYMS 100
char true[MAXSYMS];
char ignore[MAXSYMS];
char *sym[MAXSYMS];
signed char insym[MAXSYMS];
#define	KWSIZE 8
char buf[KWSIZE];
char nsyms;
char incomment;
#define	QUOTE1 0
#define	QUOTE2 1
char inquote[2];
int exitstat;

static char *skipcomment(char *cp);
static char *skipquote(char *cp, int type);
static char *nextsym(char *p);
static int doif(int thissym, int inif, int prevreject, int depth);
static void pfile(void);
static int getlin(char *line, int maxline, FILE *inp, int expandtabs);
static void prname(void);
static void flushline(int keep);
static int checkline(int *cursym);
static int error(int err, int line, int depth);
static void putlin(char *line, FILE *fio);

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "Usage: %s [-l] [-t] [-c] [[-Dsym] [-Usym] [-idsym] "
	    "[-iusym]]... [file]\n"
	    "    At least one arg from [-D -U -id -iu] is required\n"),
	    progname);
	exit(2);
}

int
main(int argc, char **argv)
{
	char **curarg;
	char *cp;
	char *cp1;
	char ignorethis;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0][0] ? argv[0] : "unifdef";

	for (curarg = &argv[1]; --argc > 0; curarg++) {
		if (*(cp1 = cp = *curarg) != '-')
			break;
		if (*++cp1 == 'i') {
			ignorethis = YES;
			cp1++;
		} else
			ignorethis = NO;
		if ((*cp1 == 'D' || *cp1 == 'U') &&
		    cp1[1] != '\0') {
			if (nsyms >= MAXSYMS) {
				prname();
				(void) fprintf(stderr,
				    gettext("too many symbols.\n"));
				exit(2);
			}
			ignore[nsyms] = ignorethis;
			true[nsyms] = *cp1 == 'D' ? YES : NO;
			sym[nsyms++] = &cp1[1];
		} else if (ignorethis)
			goto unrec;
		else if (strcmp(&cp[1], "t") == 0)
			text = YES;
		else if (strcmp(&cp[1], "l") == 0)
			lnblank = YES;
		else if (strcmp(&cp[1], "c") == 0)
			complement = YES;
		else {
unrec:
			prname();
			(void) fprintf(stderr,
			    gettext("unrecognized option: %s\n"), cp);
			usage();
		}
	}
	if (nsyms == 0) {
		usage();
	}

	if (argc > 1) {
		prname();
		(void) fprintf(stderr, gettext("can only do one file.\n"));
	} else if (argc == 1) {
		filename = *curarg;
		if ((input = fopen(filename, "r")) != NULL) {
			pfile();
			(void) fclose(input);
		} else {
			prname();
			perror(*curarg);
		}
	} else {
		filename = "[stdin]";
		input = stdin;
		pfile();
	}

	(void) fflush(stdout);
	return (exitstat);
}

/* types of input lines: */
#define	PLAIN	0   /* ordinary line */
#define	TRUE	1   /* a true  #ifdef of a symbol known to us */
#define	FALSE	2   /* a false #ifdef of a symbol known to us */
#define	OTHER	3   /* an #ifdef of a symbol not known to us */
#define	ELSE	4   /* #else */
#define	ENDIF	5   /* #endif */
#define	LEOF	6   /* end of file */

/* should be int declaration, was char */
int reject;    /* 0 or 1: pass thru; 1 or 2: ignore comments */
int linenum;    /* current line number */
int stqcline;   /* start of current comment or quote */

char *errs[] = {
#define	NO_ERR		0
			"",
#define	END_ERR		1
			"",
#define	ELSE_ERR	2
			"Inappropriate else",
#define	ENDIF_ERR	3
			"Inappropriate endif",
#define	IEOF_ERR	4
			"Premature EOF in ifdef",
#define	CEOF_ERR	5
			"Premature EOF in comment",
#define	Q1EOF_ERR	6
			"Premature EOF in quoted character",
#define	Q2EOF_ERR	7
			"Premature EOF in quoted string"
};

static void
pfile(void)
{
	reject = 0;
	(void) doif(-1, NO, reject, 0);
}

static int
doif(
    int thissym,	/* index of the symbol who was last ifdef'ed */
    int inif,		/* YES or NO we are inside an ifdef */
    int prevreject,	/* previous value of reject */
    int depth		/* depth of ifdef's */
)
{
	int lineval;
	int thisreject;
	int doret;	/* tmp return value of doif */
	int cursym;	/* index of the symbol returned by checkline */
	int stline;	/* line number when called this time */
	int err;

	stline = linenum;
	for (;;) {
		switch (lineval = checkline(&cursym)) {
		case PLAIN:
			flushline(YES);
			break;

		case TRUE:
		case FALSE:
			thisreject = reject;
			if (lineval == TRUE)
				insym[cursym] = 1;
			else {
				if (reject < 2)
					reject = ignore[cursym] ? 1 : 2;
				insym[cursym] = -1;
			}
			if (ignore[cursym])
				flushline(YES);
			else {
				exitstat = 0;
				flushline(NO);
			}
			if ((doret = doif(cursym, YES,
			    thisreject, depth + 1)) != NO_ERR)
				return (error(doret, stline, depth));
			break;

		case OTHER:
			flushline(YES);
			if ((doret = doif(-1, YES,
			    reject, depth + 1)) != NO_ERR)
				return (error(doret, stline, depth));
			break;

		case ELSE:
			if (inif != 1)
				return (error(ELSE_ERR, linenum, depth));
			inif = 2;
			if (thissym >= 0) {
				if ((insym[thissym] = -insym[thissym]) < 0)
					reject = ignore[thissym] ? 1 : 2;
				else
					reject = prevreject;
				if (!ignore[thissym]) {
					flushline(NO);
					break;
				}
			}
			flushline(YES);
			break;

		case ENDIF:
			if (inif == 0)
				return (error(ENDIF_ERR, linenum, depth));
			if (thissym >= 0) {
				insym[thissym] = 0;
				reject = prevreject;
				if (!ignore[thissym]) {
					flushline(NO);
					return (NO_ERR);
				}
			}
			flushline(YES);
			return (NO_ERR);

		case LEOF:
			err = incomment
			    ? CEOF_ERR
			    : inquote[QUOTE1]
			    ? Q1EOF_ERR
			    : inquote[QUOTE2]
			    ? Q2EOF_ERR
			    : NO_ERR;
			if (inif) {
				if (err != NO_ERR)
					(void) error(err, stqcline, depth);
				return (error(IEOF_ERR, stline, depth));
			} else if (err != NO_ERR)
				return (error(err, stqcline, depth));
			else
				return (NO_ERR);
		}
	}
}

#define	endsym(c) (!isalpha(c) && !isdigit(c) && c != '_')

#define	MAXLINE 256
char tline[MAXLINE];

static int
checkline(int *cursym)
{
	char *cp;
	char *symp;
	char chr;
	char *scp;
	int retval;
	int symind;
	char keyword[KWSIZE];

	linenum++;
	if (getlin(tline, sizeof (tline), input, NO) == EOF)
		return (LEOF);

	retval = PLAIN;
	if (*(cp = tline) != '#' || incomment ||
	    inquote[QUOTE1] || inquote[QUOTE2])
		goto eol;

	cp = skipcomment(++cp);
	symp = keyword;
	while (!endsym (*cp)) {
		*symp = *cp++;
		if (++symp >= &keyword[KWSIZE])
			goto eol;
	}
	*symp = '\0';

	if (strcmp(keyword, "ifdef") == 0) {
		retval = YES;
		goto ifdef;
	} else if (strcmp(keyword, "if") == 0) {
		cp = skipcomment(++cp);
		if (strcmp(nextsym(cp), "defined") == 0) {
			cp += strlen("defined") + 1;
			/* skip to identifier */
			while (endsym(*cp))
				++cp;
			retval = YES;
			goto ifdef;
		} else {
			retval = OTHER;
			goto eol;
		}
	} else if (strcmp(keyword, "ifndef") == 0) {
		retval = NO;
ifdef:
		scp = cp = skipcomment(cp);
		if (incomment) {
			retval = PLAIN;
			goto eol;
		}
		symind = 0;
		for (;;) {
			if (insym[symind] == 0) {
				for (symp = sym[symind], cp = scp;
				*symp && *cp == *symp; cp++, symp++) {
					/* NULL */
				}
				chr = *cp;
				if (*symp == '\0' && endsym(chr)) {
					*cursym = symind;
					retval = (retval ^ true[symind]) ?
					    FALSE : TRUE;
					break;
				}
			}
			if (++symind >= nsyms) {
				retval = OTHER;
				break;
			}
		}
	} else if (strcmp(keyword, "else") == 0)
		retval = ELSE;
	else if (strcmp(keyword, "endif") == 0)
		retval = ENDIF;

eol:
	if (!text && !reject)
		while (*cp) {
			if (incomment)
				cp = skipcomment(cp);
			else if (inquote[QUOTE1])
				cp = skipquote(cp, QUOTE1);
			else if (inquote[QUOTE2])
				cp = skipquote(cp, QUOTE2);
			else if (*cp == '/' && cp[1] == '*')
				cp = skipcomment(cp);
			else if (*cp == '\'')
				cp = skipquote(cp, QUOTE1);
			else if (*cp == '"')
				cp = skipquote(cp, QUOTE2);
			else
				cp++;
		}
	return (retval);
}

/*
 * Skip over comments and stop at the next character
 *  position that is not whitespace.
 */
static char *
skipcomment(char *cp)
{
	if (incomment)
		goto inside;
	for (;;) {
		while (*cp == ' ' || *cp == '\t')
			cp++;
		if (text)
			return (cp);
		if (cp[0] != '/' || cp[1] != '*')
			return (cp);
		cp += 2;
		if (!incomment) {
			incomment = YES;
			stqcline = linenum;
		}
inside:
		for (;;) {
			for (; *cp != '*'; cp++)
				if (*cp == '\0')
					return (cp);
			if (*++cp == '/')
				break;
		}
		incomment = NO;
		cp++;
	}
}

/*
 * Skip over a quoted string or character and stop at the next charaacter
 *  position that is not whitespace.
 */
static char *
skipquote(char *cp, int type)
{
	char qchar;

	qchar = type == QUOTE1 ? '\'' : '"';

	if (inquote[type])
		goto inside;
	for (;;) {
		if (*cp != qchar)
			return (cp);
		cp++;
		if (!inquote[type]) {
			inquote[type] = YES;
			stqcline = linenum;
		}
inside:
		for (; ; cp++) {
			if (*cp == qchar)
				break;
			if (*cp == '\0' || *cp == '\\' && *++cp == '\0')
				return (cp);
		}
		inquote[type] = NO;
		cp++;
	}
}

/*
 *   special getlin - treats form-feed as an end-of-line
 *                    and expands tabs if asked for
 */
static int
getlin(char *line, int maxline, FILE *inp, int expandtabs)
{
	int tmp;
	int num;
	int chr;
#ifdef FFSPECIAL
	static char havechar = NO;  /* have leftover char from last time */
	static char svchar;
#endif

	num = 0;
#ifdef FFSPECIAL
	if (havechar) {
		havechar = NO;
		chr = svchar;
		goto ent;
	}
#endif
	while (num + 8 < maxline) {   /* leave room for tab */
		chr = getc(inp);
		if (isprint(chr)) {
#ifdef FFSPECIAL
ent:
#endif
			*line++ = chr;
			num++;
		} else
			switch (chr) {
			case EOF:
				return (EOF);

			case '\t':
				if (expandtabs) {
					num += tmp = 8 - (num & 7);
					do
						*line++ = ' ';
					while (--tmp);
					break;
				}
				/* FALLTHROUGH */
			default:
				*line++ = chr;
				num++;
				break;

			case '\n':
				*line = '\n';
				num++;
				goto end;

#ifdef FFSPECIAL
			case '\f':
				if (++num == 1)
					*line = '\f';
				else {
					*line = '\n';
					havechar = YES;
					svchar = chr;
				}
				goto end;
#endif
			}
	}
end:
	*++line = '\0';
	return (num);
}

static void
flushline(int keep)
{
	if ((keep && reject < 2) ^ complement)
		putlin(tline, stdout);
	else if (lnblank)
		putlin("\n", stdout);
}

/*
 *  putlin - for tools
 */
static void
putlin(char *line, FILE *fio)
{
	char chr;

	while (chr = *line++)
		(void) putc(chr, fio);
}

static void
prname(void)
{
	(void) fprintf(stderr, "%s: ", progname);
}


static int
error(int err, int line, int depth)
{
	if (err == END_ERR)
		return (err);

	prname();

#ifndef TESTING
	(void) fprintf(stderr, gettext("Error in %s line %d: %s.\n"),
	    filename, line, gettext(errs[err]));
#endif

#ifdef TESTING
	(void) fprintf(stderr, gettext("Error in %s line %d: %s. "),
	    filename, line, errs[err]);
	(void) fprintf(stderr, gettext("ifdef depth: %d\n"), depth);
#endif

	exitstat = 1;
	return (depth > 1 ? IEOF_ERR : END_ERR);
}

/* return the next token in the line buffer */
char *
nextsym(char *p)
{
	char *key;
	int i = KWSIZE;

	key = buf;
	while (!endsym(*p) && --i)
		*key++ = *p++;
	*key = '\0';

	return (buf);
}

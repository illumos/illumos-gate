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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <sys/varargs.h>

/*
 * Deroff command -- strip troff, eqn, and Tbl sequences from a file.
 * Has three flags argument, -w, to cause output one word per line
 * rather than in the original format.
 * -mm (or -ms) causes the corresponding macro's to be interpreted
 * so that just sentences are output
 * -ml  also gets rid of lists.
 * -i causes deroff to ignore .so and .nx commands.
 * Deroff follows .so and .nx commands, removes contents of macro
 * definitions, equations (both .EQ ... .EN and $...$),
 * Tbl command sequences, and Troff backslash constructions.
 *
 * All input is through the C macro; the most recently read character
 * is in c.
 */

#define	C	((c = getc(infile)) == EOF ? eof() : \
		    ((c == ldelim) && (filesp == files) ? skeqn() : c))
#define	C1	((c = getc(infile)) == EOF ? eof() : c)
#define	SKIP	while (C != '\n')
#define	SKIP_TO_COM	SKIP; SKIP; pc = c; \
			while ((C != '.') || (pc != '\n') || \
			    (C > 'Z')) { \
				pc = c; \
			}

#define	YES 1
#define	NO 0
#define	MS 0
#define	MM 1
#define	ONE 1
#define	TWO 2

#define	NOCHAR -2
#define	SPECIAL 0
#define	APOS 1
#define	DIGIT 2
#define	LETTER 3

#define	MAXLINESZ	512

static int wordflag = NO;
static int msflag = NO;
static int iflag = NO;
static int mac = MM;
static int disp = 0;
static int inmacro = NO;
static int intable = NO;
static int lindx;
static size_t linesize = MAXLINESZ;

static char chars[128];  /* SPECIAL, APOS, DIGIT, or LETTER */

static char *line = NULL;

static char c;
static int pc;
static int ldelim	= NOCHAR;
static int rdelim	= NOCHAR;

static int argc;
static char **argv;

extern int optind;
extern char *optarg;
static char fname[50];
static FILE *files[15];
static FILE **filesp;
static FILE *infile;

static void backsl(void);
static void comline(void);
static char *copys(char *);
static int eof(void);
static void eqn(void);
static void fatal(const char *, ...);
static void fatal_msg(char *);
static void getfname(void);
static void macro(void);
static FILE *opn(char *);
static void putmac(char *, int);
static void putwords(int);
static void regline(int, int);
static void sce(void);
static int skeqn(void);
static void sdis(char, char);
static void stbl(void);
static void tbl(void);
static void usage(void);
static void work(void)	__NORETURN;

int
main(int ac, char **av)
{
	int i;
	int errflg = 0;
	int optchar;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	argc = ac;
	argv = av;
	while ((optchar = getopt(argc, argv, "wim:")) != EOF) {
		switch (optchar) {
		case 'w':
			wordflag = YES;
			break;
		case 'm':
			msflag = YES;
			if (*optarg == 'm')
				mac = MM;
			else if (*optarg == 's')
				mac = MS;
			else if (*optarg == 'l')
				disp = 1;
			else
				errflg++;
			break;
		case 'i':
			iflag = YES;
			break;
		case '?':
			errflg++;
		}
	}
	if (errflg) {
		usage();
		return (1);
	}
	if (optind == argc)
		infile = stdin;
	else
		infile = opn(argv[optind++]);
	files[0] = infile;
	filesp = &files[0];

	for (i = 'a'; i <= 'z'; ++i)
		chars[i] = LETTER;
	for (i = 'A'; i <= 'Z'; ++i)
		chars[i] = LETTER;
	for (i = '0'; i <= '9'; ++i)
		chars[i] = DIGIT;
	chars['\''] = APOS;
	chars['&'] = APOS;
	work();
	/* NOTREACHED */
}


static int
skeqn(void)
{
	while ((c = getc(infile)) != rdelim) {
		if (c == EOF) {
			c = eof();
		} else if (c == '"') {
			while ((c = getc(infile)) != '"') {
				if (c == EOF) {
					c = eof();
				} else if (c == '\\') {
					if ((c = getc(infile)) == EOF) {
						c = eof();
					}
				}
			}
		}
	}
	if (msflag) {
		return (c = 'x');
	}
	return (c = ' ');
}


/* Functions calling opn() should ensure 'p' is non-null */
static FILE *
opn(char *p)
{
	FILE *fd;

	assert(p != NULL);
	if ((fd = fopen(p, "r")) == NULL)
		fatal(gettext("Cannot open file %s: %s\n"), p, strerror(errno));

	return (fd);
}



static int
eof(void)
{
	if (infile != stdin)
		(void) fclose(infile);
	if (filesp > files) {
		infile = *--filesp;
	} else if (optind < argc) {
		infile = opn(argv[optind++]);
	} else {
		exit(0);
	}

	return (C);
}



static void
getfname(void)
{
	char *p;
	struct chain {
		struct chain *nextp;
		char *datap;
	};
	struct chain *q;
	static struct chain *namechain = NULL;

	while (C == ' ')
		;

	for (p = fname; ((*p = c) != '\n') && (c != ' ') && (c != '\t') &&
	    (c != '\\'); ++p) {
		(void) C;
	}
	*p = '\0';
	while (c != '\n') {
		(void) C;
	}

	/* see if this name has already been used */
	for (q = namechain; q; q = q->nextp)
		if (strcmp(fname, q->datap) != 0) {
			fname[0] = '\0';
			return;
		}

	q = (struct chain *)calloc(1, sizeof (*namechain));
	q->nextp = namechain;
	q->datap = copys(fname);
	namechain = q;
}


/*
 * Functions calling fatal() should ensure 'format' and
 * arguments are non-null.
 */
static void
fatal(const char *format, ...)
{
	va_list	alist;

	assert(format != NULL);
	(void) fputs(gettext("deroff: "), stderr);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	exit(1);
}

/* Functions calling fatal_msg() should ensure 's' is non-null */
static void
fatal_msg(char *s)
{
	assert(s != NULL);
	(void) fprintf(stderr, gettext("deroff: %s\n"), s);
	exit(1);
}

static void
usage(void)
{
	(void) fputs(gettext(
	    "usage: deroff [ -w ] [ -m (m s l) ] [ -i ] "
	    "[ file ] ... \n"), stderr);
}

static void
work(void)
{

	for (;;) {
		if ((C == '.') || (c == '\''))
			comline();
		else
			regline(NO, TWO);
	}
}


static void
regline(int macline, int cnst)
{

	if (line == NULL) {
		if ((line = (char *)malloc(linesize * sizeof (char))) == NULL) {
			fatal_msg(gettext("Cannot allocate memory"));
		}
	}

	lindx = 0;
	line[lindx] = c;
	for (;;) {
		if (c == '\\') {
			line[lindx] = ' ';
			backsl();
			if (c == '%') {	/* no blank for hyphenation char */
				lindx--;
			}
		}
		if (c == '\n') {
			break;
		}
		/*
		 * We're just about to add another character to the line
		 * buffer so ensure we don't overrun it.
		 */
		if (++lindx >= linesize - 1) {
			linesize = linesize * 2;
			if ((line = (char *)realloc(line,
			    linesize * sizeof (char))) == NULL) {
				fatal_msg(gettext("Cannot allocate memory"));
			}
		}
		if (intable && (c == 'T')) {
			line[lindx] = C;
			if ((c == '{') || (c == '}')) {
				line[lindx - 1] = ' ';
				line[lindx] = C;
			}
		} else {
			line[lindx] = C;
		}
	}

	line[lindx] = '\0';

	if (line[0] != '\0') {
		if (wordflag) {
			putwords(macline);
		} else if (macline) {
			putmac(line, cnst);
		} else {
			(void) puts(line);
		}
	}
}




static void
putmac(char *s, int cnst)
{
	char *t;

	while (*s) {
		while ((*s == ' ') || (*s == '\t')) {
			(void) putchar(*s++);
		}
		for (t = s; (*t != ' ') && (*t != '\t') && (*t != '\0'); ++t)
			;
		if (*s == '\"')
			s++;
		if ((t > s + cnst) && (chars[s[0]] == LETTER) &&
		    (chars[s[1]] == LETTER)) {
			while (s < t) {
				if (*s == '\"')
					s++;
				else
					(void) putchar(*s++);
			}
		} else {
			s = t;
		}
	}
	(void) putchar('\n');
}



static void
putwords(int macline)	/* break into words for -w option */
{
	char *p, *p1;
	int i, nlet;

	for (p1 = line; ; ) {
		/* skip initial specials ampersands and apostrophes */
		while (chars[*p1] < DIGIT) {
			if (*p1++ == '\0')
				return;
		}
		nlet = 0;
		for (p = p1; (i = chars[*p]) != SPECIAL; ++p) {
			if (i == LETTER)
				++nlet;
		}

		if ((!macline && (nlet > 1)) /* MDM definition of word */ ||
		    (macline && (nlet > 2) && (chars[p1[0]] == LETTER) &&
		    (chars[p1[1]] == LETTER))) {
			/* delete trailing ampersands and apostrophes */
			while ((p[-1] == '\'') || (p[-1] == '&')) {
				--p;
			}
			while (p1 < p) {
				(void) putchar(*p1++);
			}
			(void) putchar('\n');
		} else {
			p1 = p;
		}
	}
}



static void
comline(void)
{
	int c1, c2;

	while ((C == ' ') || (c == '\t'))
		;
comx:
	if ((c1 = c) == '\n')
		return;
	c2 = C;
	if ((c1 == '.') && (c2 != '.'))
		inmacro = NO;
	if (c2 == '\n')
		return;

	if ((c1 == 'E') && (c2 == 'Q') && (filesp == files)) {
		eqn();
	} else if ((c1 == 'T') && ((c2 == 'S') || (c2 == 'C') ||
	    (c2 == '&')) && (filesp == files)) {
		if (msflag) {
			stbl();
		} else {
			tbl();
		}
	} else if ((c1 == 'T') && (c2 == 'E')) {
		intable = NO;
	} else if (!inmacro && (c1 == 'd') && (c2 == 'e')) {
		macro();
	} else if (!inmacro && (c1 == 'i') && (c2 == 'g')) {
		macro();
	} else if (!inmacro && (c1 == 'a') && (c2 == 'm')) {
		macro();
	} else if ((c1 == 's') && (c2 == 'o')) {
		if (iflag) {
			SKIP;
		} else {
			getfname();
			if (fname[0]) {
				infile = *++filesp = opn(fname);
			}
		}
	} else if ((c1 == 'n') && (c2 == 'x')) {
		if (iflag) {
			SKIP;
		} else {
			getfname();
			if (fname[0] == '\0') {
				exit(0);
			}
			if (infile != stdin) {
				(void) fclose(infile);
			}
			infile = *filesp = opn(fname);
		}
	} else if ((c1 == 'h') && (c2 == 'w')) {
		SKIP;
	} else if (msflag && (c1 == 'T') && (c2 == 'L')) {
		SKIP_TO_COM;
		goto comx;
	} else if (msflag && (c1 == 'N') && (c2 == 'R')) {
		SKIP;
	} else if (msflag && (c1 == 'A') && ((c2 == 'U') || (c2 == 'I'))) {
		if (mac == MM) {
			SKIP;
		} else {
			SKIP_TO_COM;
			goto comx;
		}
	} else if (msflag && (c1 == 'F') && (c2 == 'S')) {
		SKIP_TO_COM;
		goto comx;
	} else if (msflag && (c1 == 'S') && (c2 == 'H')) {
		SKIP_TO_COM;
		goto comx;
	} else if (msflag && (c1 == 'N') && (c2 == 'H')) {
		SKIP_TO_COM;
		goto comx;
	} else if (msflag && (c1 == 'O') && (c2 == 'K')) {
		SKIP_TO_COM;
		goto comx;
	} else if (msflag && (c1 == 'N') && (c2 == 'D')) {
		SKIP;
	} else if (msflag && (mac == MM) && (c1 == 'H') &&
	    ((c2 == ' ') || (c2 == 'U'))) {
		SKIP;
	} else if (msflag && (mac == MM) && (c2 == 'L')) {
		if (disp || (c1 == 'R')) {
			sdis('L', 'E');
		} else {
			SKIP;
			(void) putchar('.');
		}
	} else if (msflag && ((c1 == 'D') || (c1 == 'N') ||
	    (c1 == 'K') || (c1 == 'P')) && (c2 == 'S')) {
		sdis(c1, 'E');		/* removed RS-RE */
	} else if (msflag && (c1 == 'K' && c2 == 'F')) {
		sdis(c1, 'E');
	} else if (msflag && (c1 == 'n') && (c2 == 'f')) {
		sdis('f', 'i');
	} else if (msflag && (c1 == 'c') && (c2 == 'e')) {
		sce();
	} else {
		if ((c1 == '.') && (c2 == '.')) {
			while (C == '.')
				;
		}
		++inmacro;
		if ((c1 <= 'Z') && msflag) {
			regline(YES, ONE);
		} else {
			regline(YES, TWO);
		}
		--inmacro;
	}
}



static void
macro(void)
{
	if (msflag) {
		/* look for  .. */
		do {
			SKIP;
		} while ((C != '.') || (C != '.') || (C == '.'));
		if (c != '\n') {
			SKIP;
		}
		return;
	}
	SKIP;
	inmacro = YES;
}




static void
sdis(char a1, char a2)
{
	int c1, c2;
	int eqnf;
	int notdone = 1;
	eqnf = 1;
	SKIP;
	while (notdone) {
		while (C != '.')
			SKIP;
		if ((c1 = C) == '\n')
			continue;
		if ((c2 = C) == '\n')
			continue;
		if ((c1 == a1) && (c2 == a2)) {
			SKIP;
			if (eqnf)
				(void) putchar('.');
			(void) putchar('\n');
			return;
		} else if ((a1 == 'D') && (c1 == 'E') && (c2 == 'Q')) {
			eqn();
			eqnf = 0;
		} else {
			SKIP;
		}
	}
}

static void
tbl(void)
{
	while (C != '.')
		;
	SKIP;
	intable = YES;
}

static void
stbl(void)
{
	while (C != '.')
		;
	SKIP_TO_COM;
	if ((c != 'T') || (C != 'E')) {
		SKIP;
		pc = c;
		while ((C != '.') || (pc != '\n') ||
		    (C != 'T') || (C != 'E')) {
			pc = c;
		}
	}
}

static void
eqn(void)
{
	int c1, c2;
	int dflg;
	int last;

	last = 0;
	dflg = 1;
	SKIP;

	for (;;) {
		if ((C1 == '.') || (c == '\'')) {
			while ((C1 == ' ') || (c == '\t'))
				;
			if ((c == 'E') && (C1 == 'N')) {
				SKIP;
				if (msflag && dflg) {
					(void) putchar('x');
					(void) putchar(' ');
					if (last) {
						(void) putchar('.');
						(void) putchar(' ');
					}
				}
				return;
			}
		} else if (c == 'd') {	/* look for delim */
			if ((C1 == 'e') && (C1 == 'l')) {
				if ((C1 == 'i') && (C1 == 'm')) {
					while (C1 == ' ')
						;
					if (((c1 = c) == '\n') ||
					    ((c2 = C1) == '\n') ||
					    ((c1 == 'o') && (c2 == 'f') &&
					    (C1 == 'f'))) {
						ldelim = NOCHAR;
						rdelim = NOCHAR;
					} else {
						ldelim = c1;
						rdelim = c2;
					}
				}
				dflg = 0;
			}
		}

		if (c != '\n') {
			while (C1 != '\n') {
				if (c == '.') {
					last = 1;
				} else {
					last = 0;
				}
			}
		}
	}
}



static void
backsl(void)	/* skip over a complete backslash construction */
{
	int bdelim;

sw:	switch (C) {
	case '"':
		SKIP;
		return;
	case 's':
		if (C == '\\') {
			backsl();
		} else {
			while ((C >= '0') && (c <= '9'))
				;
			(void) ungetc(c, infile);
			c = '0';
		}
		lindx--;
		return;

	case 'f':
	case 'n':
	case '*':
		if (C != '(')
			return;
		/* FALLTHROUGH */

	case '(':
		if (C != '\n') {
			(void) C;
		}
		return;

	case '$':
		(void) C;	/* discard argument number */
		return;

	case 'b':
	case 'x':
	case 'v':
	case 'h':
	case 'w':
	case 'o':
	case 'l':
	case 'L':
		if ((bdelim = C) == '\n')
			return;
		while ((C != '\n') && (c != bdelim))
			if (c == '\\')
				backsl();
		return;

	case '\\':
		if (inmacro)
			goto sw;
	default:
		return;
	}
}




static char *
copys(char *s)
{
	char *t, *t0;

	if ((t0 = t = calloc((unsigned)(strlen(s) + 1), sizeof (*t))) == NULL)
		fatal_msg(gettext("Cannot allocate memory"));

	while (*t++ = *s++)
		;
	return (t0);
}

static void
sce(void)
{
	char *ap;
	int n, i;
	char a[10];

	for (ap = a; C != '\n'; ap++) {
		*ap = c;
		if (ap == &a[9]) {
			SKIP;
			ap = a;
			break;
		}
	}
	if (ap != a) {
		n = atoi(a);
	} else {
		n = 1;
	}
	for (i = 0; i < n; ) {
		if (C == '.') {
			if (C == 'c') {
				if (C == 'e') {
					while (C == ' ')
						;
					if (c == '0') {
						break;
					} else {
						SKIP;
					}
				} else {
					SKIP;
				}
			} else {
				SKIP;
			}
		} else {
			SKIP;
			i++;
		}
	}
}

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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#
/* cut : cut and paste columns of a table (projection of a relation) */
/* Release 1.5; handles single backspaces as produced by nroff    */

#include <stdio.h>	/* make: cc cut.c */
#include <ctype.h>
#include <limits.h>
#include <locale.h>
#include <wchar.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define	MAX_RANGES	MAX_INPUT	/* maximum number of ranges */
					/* as input args */

static void	bfunc(void);
static void	bnfunc(void);
static void	cfunc(void);
static void	ffunc(void);
static wchar_t	*read_line(FILE *);
static void	process_list(char *);
static void	diag(const char *);
static void	usage(void);

static wchar_t wdel = '\t';
static int	dellen;
static int	supflag = 0;
static int	rstart[MAX_RANGES];
static int	rend[MAX_RANGES];
static int	nranges = 0;
static FILE	*inptr;
static char	dummy[MB_LEN_MAX];

static wchar_t	*linebuf = NULL;
static int	bufsiz;

int
main(int argc, char **argv)
{
	int	c;
	char	*list;
	int	status = 0;
	int	bflag, nflag, cflag, fflag, dflag, filenr;
	void	(*funcp)();

	bflag = nflag = cflag = fflag = dflag = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "b:c:d:f:ns")) != EOF)
		switch (c) {
			case 'b':
				if (fflag || cflag)
					usage();
				bflag++;
				list = optarg;
				break;

			case 'c':
				if (fflag || bflag)
					usage();
				cflag++;
				list = optarg;
				break;

			case 'd':
				dellen = mbtowc(&wdel, optarg, MB_CUR_MAX);
				if (dellen == -1) {
					diag("no delimiter specified");
				} else if (dellen != strlen(optarg))
					diag("invalid delimiter");
				dflag++;
				break;

			case 'f':
				if (bflag || cflag)
					usage();
				fflag++;
				list = optarg;
				break;

			case 'n':
				nflag++;
				break;

			case 's':
				supflag++;
				break;

			case '?':
				usage();
		}

	argv = &argv[optind];
	argc -= optind;

	/* you must use one and only one option -b, -c, or -f */
	if (!(cflag || fflag || bflag))
		usage();

	/*
	 * Make sure combination of options is correct
	 */
	if (nflag) {
		if (cflag || fflag) {
			(void) fprintf(stderr, gettext(
			    "cut: -n may only be used with -b\n"));
			usage();
		}
	}

	if (dflag || supflag) {
		if (bflag || cflag) {
			if (dflag)
				(void) fprintf(stderr, gettext(
				    "cut: -d may only be used with -f\n"));
			if (supflag)
				(void) fprintf(stderr, gettext(
				    "cut: -s may only be used with -f\n"));
			usage();
		}
	}

	process_list(list);

	if (cflag) {
		funcp = cfunc;
	} else if (bflag) {
		if (nflag)
			funcp = bnfunc;
		else
			funcp = bfunc;
	} else { /* fflag */
		funcp = ffunc;
	}

	if (nranges == 0)
		diag("no list specified");

	filenr = 0;
	do {	/* for all input files */
		if (argc == 0 || strcmp(argv[filenr], "-") == 0)
			inptr = stdin;
		else {
			if ((inptr = fopen(argv[filenr], "r")) == NULL) {
				(void) fprintf(stderr, "cut: %s: %s\n",
				    argv[filenr], strerror(errno));
				status = 1;
				continue;
			}
			/*
			 * ftell() is used to check whether the file is an
			 * open file descriptor and if the file is associate
			 * with the a pipe, a FIFO,or a socket if file cannot
			 * be opened ftell() can be used to check the status
			 * of the file
			 */
			if (ftell(inptr) == -1) {
				(void) fprintf(stderr, "cut: %s: %s\n",
				    argv[filenr], strerror(errno));
				status = 1;
				continue;
			}
		}
		(*funcp)();
		(void) fclose(inptr);
	} while (++filenr < argc);
	return (status);
}

/* parse range list argument and set-up rstart/rend array */
void
process_list(char *list)
{
	int inrange = 0;
	int start = 0;
	int num = 0;
	char *rlist = list;
	char *p;
	int i, j;
	int tmp;

	/* first, parse list of ranges */
	do {
		p = rlist;
		switch (*p) {
			case '-':
				if (inrange)
					diag("invalid range specifier");

				inrange = 1;
				if (num == 0)
					start = 1;
				else {
					start = num;
					num = 0;
				}
				break;

			case '\0':
			case ',':
			case ' ':
			case '\t':
				/*
				 * this is temporary - it will change
				 * when the isblank() routine becomes
				 * available.
				 */
				if (nranges == MAX_RANGES)
					diag("too many ranges specified");

				if (inrange) {
					if (num == 0)
						num = INT_MAX;
					if (num < start)
						diag("ranges must be "
						    "increasing");
					rstart[nranges] = start;
					rend[nranges] = num;
					nranges++;
				} else {
					rstart[nranges] = num;
					rend[nranges] = num;
					nranges++;
				}

				num = 0;
				start = 0;
				inrange = 0;

				if (*p == '\0')
					continue;
				break;

			default:
				if (!isdigit(*p))
					diag("invalid character in range");
				num = atoi(p);
				while (isdigit(*rlist))
					rlist++;
				continue;
		}
		rlist++;
	} while (*p != '\0');

	/* then, consolidate ranges where possible */
	for (i = 0; i < (nranges - 1); i++) {
		for (j = i + 1; j < nranges; j++) {
			if (rstart[i] != 0 && rend[i] != 0 &&
			    (!(rend[i] < rstart[j] || rstart[i] > rend[j]))) {
				if (rstart[i] < rstart[j])
					rstart[j] = rstart[i];
				if (rend[i] > rend[j])
					rend[j] = rend[i];
				rstart[i] = 0;
				rend[i] = 0;
				break;
			}
		}
	}

	/* then, weed out the zero'ed/consolidated entries */
	for (i = 0; i < nranges; ) {
		if (rstart[i] == 0 && rend[i] == 0) {
			for (j = i; j < (nranges - 1); j++) {
				rstart[j] = rstart[j+1];
				rend[j] = rend[j+1];
			}
			nranges--;
		} else if (rstart[i] == 0 || rend[i] == 0) {
			diag("Internal error processing input");
		} else {
			i++;
		}
	}

	/* finally, sort the remaining entries */
	for (i = 0; i < (nranges - 1); i++) {
		for (j = i+1; j < nranges; j++) {
			if (rstart[i] > rend[j]) {
				tmp = rstart[i];
				rstart[i] = rstart[j];
				rstart[j] = tmp;

				tmp = rend[i];
				rend[i] = rend[j];
				rend[j] = tmp;
			}
		}
	}

#ifdef DEBUG
	/* dump ranges */
	for (i = 0; i < nranges; i++) {
		(void) printf("Range %d - start: %d end: %d\n", i, rstart[i],
		    rend[i]);
	}
#endif
}

/* called when -c is used */
/* print out those characters selected */

void
cfunc(void)
{
	wint_t	c;		/* current character */
	int	pos = 0;	/* current position within line */
	int	inrange = 0;	/* is 'pos' within a range */
	int	rndx = 0;	/* current index into range table */

	while ((c = fgetwc(inptr)) != EOF) {
		if (c == '\n') {
			(void) putchar('\n');

			/* reset per-line variables */
			pos = 0;
			inrange = 0;
			rndx = 0;
		} else {
			pos++;

			/*
			 * check if current character is within range and,
			 * if so, print it.
			 */
			if (!inrange)
				if (pos == rstart[rndx])
					inrange = 1;

			if (inrange) {
				(void) putwchar(c);
				if (pos == rend[rndx]) {
					inrange = 0;
					rndx++;
					/*
					 * optimization -
					 * check for last range index
					 * and eat chars until newline
					 * if so.
					 */
				}
			}
		}
	}
}

void
bfunc(void) /* called when -b is used but -n is not */
{
	int	c;		/* current character */
	int	pos = 0;	/* current position within line */
	int	inrange = 0;	/* is 'pos' within a range */
	int	rndx = 0;	/* current index into range table */

	while ((c = getc(inptr)) != EOF) {
		if (c == L'\n') {
			(void) putchar('\n');

			/* reset per-line variables */
			pos = 0;
			inrange = 0;
			rndx = 0;
		} else {
			pos++;

			/*
			 * check if current character is within range and,
			 * if so, print it.
			 */
			if (!inrange)
				if (pos == rstart[rndx])
					inrange = 1;

			if (inrange) {
				(void) putchar(c);
				if (pos == rend[rndx]) {
					inrange = 0;
					rndx++;
					/*
					 * optimization -
					 * check for last range index
					 * and eat chars until newline
					 * if so.
					 */
				}
			}
		}
	}
}


void
bnfunc(void) /* called when -b -n is used */
{
	wint_t	c;		/* current character */
	int	pos = 0;	/* current position within line */
	int	inrange = 0;	/* is 'pos' within a range */
	int	rndx = 0;	/* current index into range table */
	int	wlen;		/* byte length of current wide char */

	while ((c = fgetwc(inptr)) != EOF) {
		if (c == '\n') {
			(void) putchar('\n');

			/* reset per-line variables */
			pos = 0;
			inrange = 0;
			rndx = 0;
		} else {
			if (rndx >= nranges)
				continue;

			if ((wlen = wctomb(dummy, c)) < 0)
				diag("invalid multibyte character");
			pos += wlen;

			/*
			 * when trying to figure this out, remember that
			 * pos is actually pointing to the start byte of
			 * the next char.
			 */

			/*
			 * if char starts after beginning of range,
			 * for the moment, consider it in range.
			 */
			if (!inrange && pos < rstart[rndx])
				continue;

			/*
			 * If tail of the multibyte is out of the range.
			 * do not print the character.
			 * (See XCU4)
			 */
			if (pos <= rend[rndx]) {
				inrange = 1;
				(void) putwchar(c);
				continue;
			}
			inrange = 0;
			while (++rndx < nranges && pos >= rstart[rndx]) {
				if (pos <= rend[rndx]) {
					inrange = 1;
					(void) putwchar(c);
					break;
				}
			}
		}
	}
}

wchar_t *
read_line(FILE *fp)
{
	wint_t	c;
	wchar_t	*cp;
	int charcnt;

	/* alloc the line buffer if it isn't already there */
	if (linebuf == NULL) {
		bufsiz = BUFSIZ - 1;
		if ((linebuf = (wchar_t *)malloc((bufsiz + 1) *
		    sizeof (wchar_t))) == NULL)
			diag("unable to allocate enough memory");
	}

	cp = linebuf;
	charcnt = 0;
	while ((c = fgetwc(fp)) != EOF) {
		if (c == '\n') {
			*cp = NULL;
			return (linebuf);
		} else {
			charcnt++;
			if (charcnt == bufsiz) {
				/*
				 * there is no line length limitation so we
				 * have to be ready to expand the line buffer.
				 */
				bufsiz += BUFSIZ;
				if ((linebuf = (wchar_t *)realloc(linebuf,
				    (bufsiz + 1) * sizeof (wchar_t))) == NULL)
					diag("unable to allocate "
					    "enough memory");

				cp = linebuf + charcnt - 1;
			}
			*cp++ = c;
		}
	}

	if (cp != linebuf) {
		*cp = NULL;
		return (linebuf);
	} else
		return (NULL);
}

void
ffunc(void)  /* called when -f is used */
{
	int	fpos;		/* current field position within line */
	int	inrange;	/* is 'pos' within a range */
	int	rndx;		/* current index into range table */
	int	need_del;	/* need to put a delimiter char in output */
	wchar_t	*linep;		/* pointer to line buffer */
	wchar_t	*cp, *ncp;	/* working pointers into linebuf */

	while ((linep = read_line(inptr)) != NULL) {

		/* first, prune out line with no delimiters */
		if (wcschr(linep, wdel) == NULL) {
#if !defined(__lint)	/* lint doesn't grok "%ws" */
			if (!supflag)
				(void) printf("%ws\n", linep);
#endif
			continue;
		}

		/* init per-line variable */
		fpos = 1;
		inrange = 0;
		rndx = 0;
		need_del = 0;

		for (ncp = cp = linep; ncp != NULL; fpos++) {
			/* why continue processing if no more ranges? */
			if (rndx >= nranges)
				break;

			/* find the next field delimiter */
			ncp = wcschr(cp, wdel);

			if (!inrange)
				if (fpos == rstart[rndx])
					inrange = 1;

			if (inrange) {
				if (need_del)
					(void) putwchar(wdel);

				if (ncp == NULL) {
					/*
					 * if there are no more delimiters
					 * and we are in the range, print
					 * out the rest of the line.
					 */
#if !defined(__lint)	/* lint doesn't grok "%ws" */
					(void) printf("%ws", cp);
#endif
					break;
				}
				else
					while (cp != ncp)
						(void) putwchar(*cp++);
				need_del = 1;

				if (fpos == rend[rndx]) {
					inrange = 0;
					rndx++;
				}
			}

			if (ncp != NULL)
				cp = ncp + 1;
		}
		(void) putchar('\n');
	}
}


void
diag(const char *s)
{
	(void) fprintf(stderr, "cut: ");
	(void) fprintf(stderr, gettext(s));
	(void) fprintf(stderr, "\n");
	exit(2);
}


void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: cut -b list [-n] [filename ...]\n"
	    "       cut -c list [filename ...]\n"
	    "       cut -f list [-d delim] [-s] [filename]\n"));
	exit(2);
}

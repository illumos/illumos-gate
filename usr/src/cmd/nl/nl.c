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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <locale.h>
#include <regexpr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wchar.h>
#include <wctype.h>
#include <limits.h>

#define	EXPSIZ		512

#ifdef XPG4
#define	USAGE "usage: nl [-p] [-b type] [-d delim] [ -f type] " \
	"[-h type] [-i incr] [-l num] [-n format]\n" \
	"[-s sep] [-v startnum] [-w width] [file]\n"
#else
#define	USAGE "usage: nl [-p] [-btype] [-ddelim] [ -ftype] " \
	"[-htype] [-iincr] [-lnum] [-nformat] [-ssep] " \
	"[-vstartnum] [-wwidth] [file]\n"
#endif

#ifdef u370
	int nbra, sed;	/* u370 - not used in nl.c, but extern in regexp.h */
#endif
static int width = 6;	/* Declare default width of number */
static char nbuf[100];	/* Declare bufsize used in convert/pad/cnt routines */
static char *bexpbuf;	/* Declare the regexp buf */
static char *hexpbuf;	/* Declare the regexp buf */
static char *fexpbuf;	/* Declare the regexp buf */
static char delim1 = '\\';
static char delim2 = ':';	/* Default delimiters. */
static char pad = ' ';	/* Declare the default pad for numbers */
static char *s;	/* Declare the temp array for args */
static char s1[EXPSIZ];	/* Declare the conversion array */
static char format = 'n'; /* Declare the format of numbers to be rt just */
static int q = 2;	/* Initialize arg pointer to drop 1st 2 chars */
static int k;	/* Declare var for return of convert */
static int r;	/* Declare the arg array ptr for string args */

#ifdef XPG4
static int convert(int, char *);
#else
static int convert(char *);
#endif
static void num(int, int);
static void npad(int, char *);
#ifdef XPG4
static void optmsg(int, char *);
#else
static void optmsg(char *);
#endif
static void pnum(int, char *);
static void regerr(int);
static void usage();

extern char *optarg;	/* getopt support */
extern int optind;

int
main(int argc, char *argv[])
{
	register int j;
	register int i = 0;
	register char *p;
	register char header = 'n';
	register char body = 't';
	register char footer = 'n';
	char line[LINE_MAX];
	char tempchr;	/* Temporary holding variable. */
	char swtch = 'n';
	char cntck = 'n';
	char type;
	int cnt;	/* line counter */
	int pass1 = 1;	/* First pass flag. 1=pass1, 0=additional passes. */
	char sep[EXPSIZ];
	char pat[EXPSIZ];
	int startcnt = 1;
	int increment = 1;
	int blank = 1;
	int blankctr = 0;
	int c;
	int lnt;
	char last;
	FILE *iptr = stdin;
	FILE *optr = stdout;
#ifndef XPG4
	int option_end = 0;
#endif

	sep[0] = '\t';
	sep[1] = '\0';

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

#ifdef XPG4
	/*
	 * XPG4:  Allow either a space or no space between the
	 *	  options and their required arguments.
	 */

	while (argc > 0) {
		while ((c = getopt(argc, argv,
		    "pb:d:f:h:i:l:n:s:v:w:")) != EOF) {

			switch (c) {
			case 'h':
				switch (*optarg) {
				case 'n':
					header = 'n';
					break;
				case 't':
					header = 't';
					break;
				case 'a':
					header = 'a';
					break;
				case 'p':
					(void) strcpy(pat, optarg+1);
					header = 'h';
					hexpbuf =
					    compile(pat, NULL,  NULL);
					if (regerrno)
						regerr(regerrno);
					break;
				case '\0':
					header = 'n';
					break;
				default:
					optmsg(c, optarg);
				}
				break;
			case 'b':
				switch (*optarg) {
				case 't':
					body = 't';
					break;
				case 'a':
					body = 'a';
					break;
				case 'n':
					body = 'n';
					break;
				case 'p':
					(void) strcpy(pat, optarg+1);
					body = 'b';
					bexpbuf =
					    compile(pat, NULL, NULL);
					if (regerrno)
						regerr(regerrno);
					break;
				case '\0':
					body = 't';
					break;
				default:
					optmsg(c, optarg);
				}
				break;
			case 'f':
				switch (*optarg) {
				case 'n':
					footer = 'n';
					break;
				case 't':
					footer = 't';
					break;
				case 'a':
					footer = 'a';
					break;
				case 'p':
					(void) strcpy(pat, optarg+1);
					footer = 'f';
					fexpbuf =
					    compile(pat, NULL, NULL);
					if (regerrno)
						regerr(regerrno);
					break;
				case '\0':
					footer = 'n';
					break;
				default:
					optmsg(c, optarg);
				}
				break;
			case 'p':
				if (optarg == (char *)NULL)
					cntck = 'y';
				else
					optmsg(c, optarg);
				break;
			case 'v':
				if (*optarg == '\0')
					startcnt = 1;
				else
					startcnt = convert(c, optarg);
				break;
			case 'i':
				if (*optarg == '\0')
					increment = 1;
				else
					increment = convert(c, optarg);
				break;
			case 'w':
				if (*optarg == '\0')
					width = 6;
				else
					width = convert(c, optarg);
				break;
			case 'l':
				if (*optarg == '\0')
					blank = 1;
				else
					blank = convert(c, optarg);
				break;
			case 'n':
				switch (*optarg) {
				case 'l':
					if (*(optarg+1) == 'n')
						format = 'l';
					else
						optmsg(c, optarg);
					break;
				case 'r':
					if ((*(optarg+1) == 'n') ||
					    (*(optarg+1) == 'z'))
						format = *(optarg+1);
					else
						optmsg(c, optarg);
					break;
				case '\0':
					format = 'n';
					break;
				default:
					optmsg(c, optarg);
					break;
				}
				break;
			case 's':
				(void) strcpy(sep, optarg);
				break;
			case 'd':
				delim1 = *optarg;

				if (*(optarg+1) == '\0')
					break;
				delim2 = *(optarg+1);
				if (*(optarg+2) != '\0')
					optmsg(c, optarg);
				break;
			default:
				optmsg(c, optarg);
			} /* end switch char returned from getopt() */
		} /* end while getopt */

		argv += optind;
		argc -= optind;
		optind = 0;

		if (argc > 0) {
			if ((iptr = fopen(argv[0], "r")) == NULL)  {
				(void) fprintf(stderr, "nl: %s: ", argv[0]);
				perror("");
				return (1);
			}
			++argv;
			--argc;
		}
	} /* end while argc > 0 */
/* end XPG4 version of argument parsing */
#else
/*
 * Solaris:  For backward compatibility, do not allow a space between the
 *	     options and their arguments.  Option arguments are optional,
 *	     not required as in the XPG4 version of nl.
 */
for (j = 1; j < argc; j++) {
	if (argv[j][i] == '-' && (c = argv[j][i + 1])) {
		if (!option_end) {
			switch (c) {
			case 'h':
				switch (argv[j][i + 2]) {
					case 'n':
						header = 'n';
						break;
					case 't':
						header = 't';
						break;
					case 'a':
						header = 'a';
						break;
					case 'p':
						s = argv[j];
						q = 3;
						r = 0;
						while (s[q] != '\0') {
							pat[r] = s[q];
							r++;
							q++;
						}
						pat[r] = '\0';
						header = 'h';
						hexpbuf =
						    compile(pat, NULL, NULL);
						if (regerrno)
							regerr(regerrno);
						break;
					case '\0':
						header = 'n';
						break;
					default:
						optmsg(argv[j]);
				}
				break;
			case 'b':
				switch (argv[j][i + 2]) {
					case 't':
						body = 't';
						break;
					case 'a':
						body = 'a';
						break;
					case 'n':
						body = 'n';
						break;
					case 'p':
						s = argv[j];
						q = 3;
						r = 0;
						while (s[q] != '\0') {
							pat[r] = s[q];
							r++;
							q++;
						}
						pat[r] = '\0';
						body = 'b';
						bexpbuf =
						    compile(pat, NULL, NULL);
						if (regerrno)
							regerr(regerrno);
						break;
					case '\0':
						body = 't';
						break;
					default:
						optmsg(argv[j]);
				}
				break;
			case 'f':
				switch (argv[j][i + 2]) {
					case 'n':
						footer = 'n';
						break;
					case 't':
						footer = 't';
						break;
					case 'a':
						footer = 'a';
						break;
					case 'p':
						s = argv[j];
						q = 3;
						r = 0;
						while (s[q] != '\0') {
							pat[r] = s[q];
							r++;
							q++;
						}
						pat[r] = '\0';
						footer = 'f';
						fexpbuf =
						    compile(pat, NULL, NULL);
						if (regerrno)
							regerr(regerrno);
						break;
					case '\0':
						footer = 'n';
						break;
					default:
						optmsg(argv[j]);
				}
				break;
			case 'p':
				if (argv[j][i+2] == '\0')
				cntck = 'y';
				else
				{
				optmsg(argv[j]);
				}
				break;
			case 'v':
				if (argv[j][i+2] == '\0')
				startcnt = 1;
				else
				startcnt = convert(argv[j]);
				break;
			case 'i':
				if (argv[j][i+2] == '\0')
				increment = 1;
				else
				increment = convert(argv[j]);
				break;
			case 'w':
				if (argv[j][i+2] == '\0')
				width = 6;
				else
				width = convert(argv[j]);
				break;
			case 'l':
				if (argv[j][i+2] == '\0')
				blank = 1;
				else
				blank = convert(argv[j]);
				break;
			case 'n':
				switch (argv[j][i+2]) {
					case 'l':
						if (argv[j][i+3] == 'n')
						format = 'l';
						else
				{
				optmsg(argv[j]);
				}
						break;
					case 'r':
						if ((argv[j][i+3] == 'n') ||
						    (argv[j][i+3] == 'z'))
						format = argv[j][i+3];
						else
				{
				optmsg(argv[j]);
				}
						break;
					case '\0':
						format = 'n';
						break;
					default:
				optmsg(argv[j]);
					break;
				}
				break;
			case 's':
				if (argv[j][i + 2] != '\0') {
					s = argv[j];
					q = 2;
					r = 0;
					while (s[q] != '\0') {
						sep[r] = s[q];
						r++;
						q++;
					}
					sep[r] = '\0';
				}
				/* else default sep is tab (set above) */
				break;
			case 'd':
				tempchr = argv[j][i+2];
				if (tempchr == '\0')break;
				delim1 = tempchr;

				tempchr = argv[j][i+3];
				if (tempchr == '\0')break;
				delim2 = tempchr;
				if (argv[j][i+4] != '\0')optmsg(argv[j]);
				break;
			case '-':
				if (argv[j][i + 2] == '\0') {
					option_end = 1;
					break;
				}
				/* FALLTHROUGH */
			default:
				optmsg(argv[j]);
			}
		} else if ((iptr = fopen(argv[j], "r")) == NULL)  {
			/* end of options, filename starting with '-' */
			(void) fprintf(stderr, "nl: %s: ", argv[j]);
			perror("");
			return (1);
		}
	} else if ((iptr = fopen(argv[j], "r")) == NULL)  {
		/* filename starting with char other than '-' */
		(void) fprintf(stderr, "nl: %s: ", argv[j]);
		perror("");
		return (1);
	}
} /* closing brace of for loop */
/* end Solaris version of argument parsing */
#endif

	/* ON FIRST PASS ONLY, SET LINE COUNTER (cnt) = startcnt & */
	/* SET DEFAULT BODY TYPE TO NUMBER ALL LINES.	*/
	if (pass1) {
		cnt = startcnt;
		type = body;
		last = 'b';
		pass1 = 0;
	}

/*
 *		DO WHILE THERE IS INPUT
 *		CHECK TO SEE IF LINE IS NUMBERED,
 *		IF SO, CALCULATE NUM, PRINT NUM,
 *		THEN OUTPUT SEPERATOR CHAR AND LINE
 */

	while ((p = fgets(line, sizeof (line), iptr)) != NULL) {
	if (p[0] == delim1 && p[1] == delim2) {
		if (p[2] == delim1 &&
		    p[3] == delim2 &&
		    p[4] == delim1 &&
		    p[5] == delim2 &&
		    p[6] == '\n') {
			if (cntck != 'y')
				cnt = startcnt;
			type = header;
			last = 'h';
			swtch = 'y';
		} else {
			if (p[2] == delim1 && p[3] == delim2 && p[4] == '\n') {
				if (cntck != 'y' && last != 'h')
					cnt = startcnt;
				type = body;
				last = 'b';
				swtch = 'y';
			} else {
				if (p[0] == delim1 && p[1] == delim2 &&
							p[2] == '\n') {
					if (cntck != 'y' && last == 'f')
						cnt = startcnt;
					type = footer;
					last = 'f';
					swtch = 'y';
				}
			}
		}
	}
	if (p[0] != '\n') {
		lnt = strlen(p);
		if (p[lnt-1] == '\n')
			p[lnt-1] = NULL;
	}

	if (swtch == 'y') {
		swtch = 'n';
		(void) fprintf(optr, "\n");
	} else {
		switch (type) {
		case 'n':
			npad(width, sep);
			break;
		case 't':
			/*
			 * XPG4: The wording of Spec 1170 is misleading;
			 * the official interpretation is to number all
			 * non-empty lines, ie: the Solaris code has not
			 * been changed.
			 */
			if (p[0] != '\n') {
				pnum(cnt, sep);
				cnt += increment;
			} else {
				npad(width, sep);
			}
			break;
		case 'a':
			if (p[0] == '\n') {
				blankctr++;
				if (blank == blankctr) {
					blankctr = 0;
					pnum(cnt, sep);
					cnt += increment;
				} else
					npad(width, sep);
			} else {
				blankctr = 0;
				pnum(cnt, sep);
				cnt += increment;
			}
			break;
		case 'b':
			if (step(p, bexpbuf)) {
				pnum(cnt, sep);
				cnt += increment;
			} else {
				npad(width, sep);
			}
			break;
		case 'h':
			if (step(p, hexpbuf)) {
				pnum(cnt, sep);
				cnt += increment;
			} else {
				npad(width, sep);
			}
			break;
		case 'f':
			if (step(p, fexpbuf)) {
				pnum(cnt, sep);
				cnt += increment;
			} else {
				npad(width, sep);
			}
			break;
		}
		if (p[0] != '\n')
			p[lnt-1] = '\n';
		(void) fprintf(optr, "%s", line);

	}	/* Closing brace of "else" */
	}	/* Closing brace of "while". */
	(void) fclose(iptr);

	return (0);
}

/*		REGEXP ERR ROUTINE		*/

static void
regerr(int c)
{
	(void) fprintf(stderr, gettext(
	    "nl: invalid regular expression: error code %d\n"), c);
	exit(1);
}

/*		CALCULATE NUMBER ROUTINE	*/

static void
pnum(int n, char *sep)
{
	register int	i;

	if (format == 'z') {
		pad = '0';
	}
	for (i = 0; i < width; i++)
		nbuf[i] = pad;
	num(n, width - 1);
	if (format == 'l') {
		while (nbuf[0] == ' ') {
			for (i = 0; i < width; i++)
				nbuf[i] = nbuf[i+1];
			nbuf[width-1] = ' ';
		}
	}
	(void) printf("%s%s", nbuf, sep);
}

/*		IF NUM > 10, THEN USE THIS CALCULATE ROUTINE		*/

static void
num(int v, int p)
{
	if (v < 10)
		nbuf[p] = v + '0';
	else {
		nbuf[p] = (v % 10) + '0';
		if (p > 0)
			num(v / 10, p - 1);
	}
}

/*		CONVERT ARG STRINGS TO STRING ARRAYS	*/

#ifdef XPG4
static int
convert(int c, char *option_arg)
{
	s = option_arg;
	q = r = 0;
	while (s[q] != '\0') {
		if (s[q] >= '0' && s[q] <= '9') {
			s1[r] = s[q];
			r++;
			q++;
		} else
			optmsg(c, option_arg);
	}
	s1[r] = '\0';
	k = atoi(s1);
	return (k);
}
#else
/* Solaris version */
static int
convert(char *argv)
{
	s = (char *)argv;
	q = 2;
	r = 0;
	while (s[q] != '\0') {
		if (s[q] >= '0' && s[q] <= '9') {
			s1[r] = s[q];
			r++;
			q++;
		} else {
			optmsg(argv);
		}
	}
	s1[r] = '\0';
	k = atoi(s1);
	return (k);
}
#endif

/*		CALCULATE NUM/TEXT SEPRATOR		*/

static void
npad(int width, char *sep)
{
	register int i;

	pad = ' ';
	for (i = 0; i < width; i++)
		nbuf[i] = pad;
	(void) printf("%s", nbuf);

	for (i = 0; i < (int)strlen(sep); i++)
		(void) printf(" ");
}

#ifdef XPG4
static void
optmsg(int option, char *option_arg)
{
	if (option_arg != (char *)NULL) {
		(void) fprintf(stderr, gettext(
		    "nl: invalid option (-%c %s)\n"), option, option_arg);
	}
	/* else getopt() will print illegal option message */
	usage();
}
#else
/* Solaris version */
static void
optmsg(char *option)
{
	(void) fprintf(stderr, gettext("nl: invalid option (%s)\n"), option);
	usage();
}
#endif

void
usage()
{
	(void) fprintf(stderr, gettext(USAGE));
	exit(1);
}

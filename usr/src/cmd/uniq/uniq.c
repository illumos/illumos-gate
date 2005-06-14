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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * uniq: delete repeated lines within a file.
 *
 * uniq [-c|-d|-u][-f fields][-s char] [input_file [output_file]]
 * OR:
 * uniq [-c|-d|-u][-n][+m] [input_file [output_file]]
 */

#include <stdio.h>
#include <ctype.h>
#include <locale.h>
#include <stdlib.h>
#include <libintl.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#define	isWblank(c)	\
	((c == 0x09 || c == 0x20) ? 1 : (iswctype((c), _ISBLANK|_ISSPACE)))


#define	BLOCKSIZE 1000	/* How much line buffer to allocate at a time */

static int	mcount = 0;	/* # of mutually exclusive flags used	*/
static int	fields = 0;	/* # of fields to be ignored		*/
static int	letters = 0;	/* # of letters to be ignored		*/
static int	linec;
static char	mode;		/* = [c, d, u]				*/
static int	uniq;
static int	mac;		/* our modified argc, after parseargs()	*/
static char	**mav;		/* our modified argv, after parseargs()	*/
static char 	*skip();

/*
 * according to spec 1170 (draft April 8, 1994), there are two
 * ways to use uniq; and both ways are mutually exclusive. we use modeflag
 * to insure that the user doesn't mix these mutually exclusive flags.
 * if the [-f -s] flags are used, modeflag should be 1. if [-n +m] are
 * used, then modeflag should be 2. so the possible values for modeflag are:
 *	0:	[-f,-s] && [-n, +m] weren't specified. default to XBD.
 *	1:	either -f or -s was specified. XBD specification.
 *	2:	either -n or +m was specified. obsolescent usage.
 */
#define	MODEFLAG_FS	1	/* modeflag bits: -f or -s was specified */
#define	MODEFLAG_NM	2	/* modeflag bits: -n or _m was specified */

static int	modeflag = 0;	/* 0,1 = XBD spec. 2 = Obsolescent usage */


static char	usage0[] = "uniq [-c|-d|-u][-f fields][-s char]";
static char	usage1[] = "uniq [-c|-d|-u][-n][+m]";

static void	printe();
static int	gline(char **buf, int *size);
static void	pline(char *buf);
static int	equal(char *b1, char *b2);
static void	parseargs(int ac, char **av);
static void	usage();


int
main(int argc, char *argv[])
{
	int	c;			/* for getopt(3C) parsing	*/
	char	*b1 = NULL, *b2 = NULL;
	int	b1size = BLOCKSIZE, b2size = BLOCKSIZE;
	FILE *temp;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((b1 = ((char *) malloc((unsigned) BLOCKSIZE))) == NULL || (b2 =
			((char *) malloc((unsigned) BLOCKSIZE))) == NULL)
		printe(gettext("out of memory\n"), "");

	parseargs(argc, argv);	/* reformat all arguments for getopt	*/

	/* handle all of uniq's arguments via getopt(3C):		*/
	while ((c = getopt(mac, mav, "n:m:cduf:s:")) != EOF) {
		switch (c) {
		case 'n':	/* parseargs() psuedo argument for -#	*/
			modeflag |= MODEFLAG_NM;
			fields = atoi(optarg);
			break;

		case 'm':	/* parseargs() psuedo argument for +#	*/
			modeflag |= MODEFLAG_NM;
			letters = atoi(optarg);
			break;

		case 'c':	/* -c: precede output lines		*/
			/* FALLTHROUGH!					*/
		case 'd':	/* -d: suppress non-repeated lines	*/
			/* FALLTHROUGH!					*/
		case 'u':	/* -u: suppress repeated lines		*/
			mcount++;
			mode = c;
			break;

		case 'f':	/* -f: ignore 1st fields on input lines	*/
			modeflag |= MODEFLAG_FS;
			if (isdigit((unsigned char)*optarg) != 0) {
				fields = atoi(optarg);
			} else {
				(void) fprintf(stderr, "uniq -f: %s: %s\n",
				gettext("bad fields value"), optarg);
				usage();
				exit(1);
			}
			break;

		case 's':	/* -s: ignore 1st chars on comparisons	*/
			modeflag |= MODEFLAG_FS;
			if (isdigit((unsigned char)*optarg) != 0) {
				letters = atoi(optarg);
			} else {
				(void) fprintf(stderr, "uniq -s: %s: %s\n",
				gettext("bad fields value"), optarg);
				usage();
				exit(1);
			}
			break;

		default:
			usage();
			exit(2);
			break;
		}
	}

	/* see if we have any mutually exclusive options:		*/
	if (mcount > 1) {
		(void) fprintf(stderr,
		    gettext("Mutually exclusive options were given!\n"));
		usage();
		exit(3);
	}

	/* see if the user mixed the old style usage with the new:	*/
	if (modeflag > MODEFLAG_NM) {
		(void) fprintf(stderr, gettext(
			"Mutually exclusive command lines arguments!\n"));
		usage();
		exit(4);
	}

	/* if there are more arguments than getopt(3C) handled:		*/
	if (mav[optind] != (char *) NULL) {
		/* if the user specified an input filename:		*/
		if (*mav[optind] != (char) NULL) {
			/* if the user didn't specify stdin:		*/
			if (strcmp(mav[optind], "-") != 0) {
				if ((temp = fopen(mav[optind], "r")) == NULL) {
					printe(gettext("cannot open %s\n"),
					mav[optind]);
				}

				(void) fclose(temp);
				(void) freopen(mav[optind], "r", stdin);
			}
		}

		/* if the user specified an output filename:		*/
		if ((mav[optind + 1] != (char *) NULL) &&
		(*mav[optind + 1] != (char) NULL)) {
			if (freopen(mav[optind + 1], "w", stdout) == NULL) {
				printe(gettext("cannot create %s\n"),
				mav[optind + 1]);
			}
		}
	}

	if (gline(&b1, &b1size))
		exit(0);
	for (; ; ) {
		linec++;
		if (gline(&b2, &b2size)) {
			pline(b1);
			exit(0);
		}
		if (!equal(b1, b2)) {
			pline(b1);
			linec = 0;
			do {
				linec++;
				if (gline(&b1, &b1size)) {
					pline(b2);
					exit(0);
				}
			} while (equal(b1, b2));
			pline(b2);
			linec = 0;
		}
	}
}

/*
 * Get an input line, dynamically growing the buffer as necessary.
 */
static int
gline(buf, size)
char **buf;
int *size;
{
	register int	c, left = *size;
	register char	*input = *buf;

	while ((c = getchar()) != '\n')
	{
		if (c == EOF)
			return (1);

		*input++ = c;
		if (--left == 0)
		{
			*buf = (char *) realloc(*buf, *size + BLOCKSIZE);
			if (*buf == NULL)
				printe(gettext("out of memory\n"), "");

			input = (*buf) + *size;
			left = BLOCKSIZE;
			*size += BLOCKSIZE;
		}
	}

	*input = '\0';
	return (0);
}

static void
pline(buf)
register char buf[];
{

	switch (mode) {

	case 'u':
		if (uniq) {
			uniq = 0;
			return;
		}
		break;

	case 'd':
		if (uniq) break;
		return;

	case 'c':
		(void) printf("%4d ", linec);
	}
	uniq = 0;
	(void) fputs(buf, stdout);
	(void) putchar('\n');
}

/*
 * equal: see if two strings are the same, accounting for any skipping.
 *	similar to strcmp(), except that we call skip() first.
 *	output:	1 if the strings are the same. 0 otherwise.
 */
static int
equal(b1, b2)
register char b1[], b2[];
{
	b1 = skip(b1);
	b2 = skip(b2);

	if (strcmp(b1, b2) == 0) {	/* if they're the same,		*/
		uniq++;
		return (1);
	}

	return (0);
}

char *
skip(char *s)
{
	int nf, nl;
	int clen;		/* # bytes which comprise a mb char	*/
	wchar_t	wc;		/* the xlated version of each mb char	*/

	nf = nl = 0;

	/*
	 * we want to skip all user-specified fields first, and then
	 * any specified characters. so while there're fields to be
	 * skipped, examine each (possible m.b.) char. for each field,
	 * we first skip all blanks. then we skip any non-blank chars.
	 */

	while (nf++ < fields) {
		/* skip blank characters (s.b. or m.b) */
		clen = mbtowc(&wc, s, MB_CUR_MAX);
		while ((clen > 0) && isWblank(wc)) {
			s += clen;
			clen = mbtowc(&wc, s, MB_CUR_MAX);
		}

		if (clen == -1) {
			/*
			 * illegal char found
			 * treat it as a non-blank single byte char
			 */
			s++;
			clen = mbtowc(&wc, s, MB_CUR_MAX);
		} else if (clen == 0) {
			/* EOL found */
			break;
		}

		/* skip non-blank and illegal characters */
		while (((clen > 0) && !isWblank(wc)) ||
			(clen == -1)) {
			s += clen > 0 ? clen : 1;
			clen = mbtowc(&wc, s, MB_CUR_MAX);
		}

		/* if we've encountered EOL */
		if (clen == 0) {
			break;
		}
	}

	/*
	 * skip all user-specified letters, s.b. or m.b.
	 */

	while (nl++ < letters) {
		clen = mbtowc(&wc, s, MB_CUR_MAX);

		/* if we've encountered EOL */
		if (clen == 0) {
			break;
		}
		s += clen > 0 ? clen : 1;

	}
	return (s);
}

static void
printe(p, s)
char *p, *s;
{
	(void) fprintf(stderr, p, s);
	exit(1);
}



/*
 * parseargs():		modify the args
 *	this routine is used to transform all arguments into a format
 *	which is acceptable to getopt(3C), and which retains backwards
 *	Solaris 2.[0-4] compatibility.
 *
 *	This routine allows us to make full use of getopts, without any
 *	funny argument processing in main().
 *
 *	The other alternative would be to hand-craft the processed arguments
 *	during and after getopt(3C) - which usually leads to uglier code
 *	in main(). I've opted to keep the ugliness isolated down here,
 *	instead of in main().
 *
 *	We leave the following arguments unchanged:
 *		[-c | -d | -u], [-f fields] [-s char].
 *
 *	We modify the following arguments:
 *		-# (a.k.a. -n)	to "-n #"
 *		+# (a.k.a. +n)	to "-m #"
 *
 *	E.g. -3 gets changed to the psuedo argument "-n 3".
 *
 *	N.B.: we *DON'T* map -# to -f, nor +# to -s, as -/+ usage is
 *		mutually exclusive with -f & -s according to the
 *		spec 1170 man page.
 *
 *	Anything after the valid options is assumed to be input or
 *	output filenames.
 *
 */
static void
parseargs(ac, av)
int ac;
char **av;
{
	int i;			/* current argument			*/
	int fflag;		/* 0 = haven't found input/output file	*/
	int minusflag;		/* !0 = have hit a "--": end of flags	*/
	size_t sz;		/* size of the argument			*/
	size_t mav_sz;		/* size of our psuedo argument space	*/

	i = mac = fflag = minusflag = 0;	/* proper initializations */

	mav_sz = (size_t) ((ac + 1) * sizeof (char *));
	if ((mav = malloc(mav_sz)) == (char **) NULL) {
		perror("malloc failed");
		exit(1);
	}

	/* for each argument, see if we need to change things:		*/
	while ((av[i] != (char *) NULL) && (av[i][0] != (char) NULL)) {
		/*
		 * if we're doing argument processing, and we have
		 * a "+" sign, then it should be of the form: +#.
		 * map it to "-m #".
		 */
		if ((fflag == 0) && (minusflag == 0) && (av[i][0] == '+')) {
			if ((av[i][1] == (char) NULL) ||
			    (atoi(&av[i][1]) <= 0)) {
				/*
				 * The user did not follow the + with a
				 * positive decimal integer.
				 * Exit here because we don't want getopt() to
				 * print an error message about the -m option,
				 * since it doesn't exist in the man page!
				 */
				usage();
				exit(1);
			}
			/* since we're adding an arg, need to inc mav space */
			mav_sz += sizeof (char *);
			if ((mav = realloc(mav, mav_sz)) == (char **) NULL) {
				perror("realloc failed");
				exit(1);
			}

			if ((mav[mac] = malloc(sizeof ("-m") + 1)) ==
			    (char *) NULL) {
				perror("malloc failed");
				exit(1);
			}

			(void) strcpy(mav[mac], "-m");
			++mac;		/* prepare for 2nd argument	*/


			/* add the arg to our modified space	*/
			if ((mav[mac] = malloc(strlen(&av[i][1]) + 1)) ==
			    (char *) NULL) {
				perror("malloc failed");
				exit(1);
			}

			(void) strcpy(mav[mac++], &av[i++][1]);
			continue;
		}

		/*
		 * Here we need to see if the user typed -#, where # is
		 * a positive integer.
		 * Allow for input file named "-" (standard input).
		 */
		if ((fflag == 0) && (minusflag == 0) && (av[i][0] == '-') &&
		    (av[i][1] != (char) NULL) && (atoi(&av[i][1]) > 0)) {
			/* this user did, so convert it to "-n #".	*/

			/* since we're adding an arg, need to inc mav space */
			mav_sz += sizeof (char *);
			if ((mav = realloc(mav, mav_sz)) == (char **) NULL) {
				perror("realloc failed");
				exit(1);
			}

			if ((mav[mac] = malloc(sizeof ("-n") + 1)) ==
			    (char *) NULL) {
				perror("malloc failed");
				exit(1);
			}

			(void) strcpy(mav[mac++], "-n");

			if ((mav[mac] = malloc(strlen(&av[i][1] + 1))) ==
			    (char *) NULL) {
				perror("malloc failed");
				exit(1);
			}

			(void) strcpy(mav[mac++], &av[i++][1]);
			continue;
		}

		/* the rest should be normal argument processing:	*/

		/* first copy the argument:				*/
		sz = strlen(&av[i][0]);
		if ((mav[mac] = malloc(sz + 1)) == (char *) NULL) {
			perror("malloc failed");
			exit(1);
		}

		(void) strcpy(mav[mac], av[i]);

		/* see if we need to do any further processing:		*/
		if ((av[i][0] == '-') && (av[i][1] != (char) NULL) &&
		(minusflag == 0)) {

			switch (av[i][1]) {
			/*
			 * start of all the other expected arguments.
			 * here we keep continuing - eventually we'll
			 * either run out of arguments, or we'll run
			 * into the input & output files (after which
			 * we terminate this loop).
			 */

			/* flags without subarguments:			*/
			case	'c':	/* FALLTHROUGH			*/
			case	'd':	/* FALLTHROUGH			*/
			case	'u':
				break; /* no more processing required	*/


			/* flags with required subarguments:		*/
			case	'f':	/* FALLTHROUGH			*/
			case	's':
				if (av[i][2] == (char) NULL) {
					/*
					 * The user has put white space
					 * between the option and its argument;
					 * alloc some space, & add the next
					 * arg.
					 */
					++mac;	/* inc our arg count	*/
					++i;	/* mv to next (sub)arg	*/

					/*
					 * If there's no next argument, then
					 * simply return; getopt(3C) will
					 * print a message about the missing
					 * option argument.
					 */
					if ((av[i] == (char *) NULL) ||
					    av[i][0] == (char) NULL)
						return;
					else {
						/* add the subargument */
						mav[mac] = malloc(
							strlen(&av[i][0]));
						if (mav[mac] == (char *) NULL) {
							perror("malloc failed");
							exit(1);
						}
						(void) strcpy(mav[mac],
								&av[i][0]);
					}
				}

				break;

			case	'-':	/* --: end of arguments		*/
				minusflag = 1;
				break;

			default:
				/*
				 * no flags == input/output file. inc
				 * fflag, so that:
				 *	- we do no further argument processing.
				 *	- we know apriori that there will
				 *		be no more than 2 files.
				 * we leave if we hit the second file.
				 */
				if (++fflag >= 2) {
					/*
					 * we've copied the file argument
					 * already, so leave.
					 */
					mav[++mac] = (char *) NULL;
					return;
				}

				break;
			}
		} else if (i > 0) {	/* if we're not the 1st arg	*/
			/*
			 * here it's not a flag, so it *must* be either
			 * the input or the output file, including stdin.
			 *
			 * set fflag, so we don't mishandle the -[cdu] flags.
			 */
			if (++fflag >= 2) {
				/*
				 * we've copied the file argument
				 * already, so leave.
				 */
				mav[++mac] = (char *) NULL;
				return;
			}
		}

		mac++;
		i++;
	}

	mav[mac] = (char *) NULL;
}

static void
usage()
{
	(void) fprintf(stderr, "Usage:\t%s [input_file [output_file]]\n",
		usage0);
	(void) fprintf(stderr, "Or:\t%s [input_file [output_file]]\n",
		usage1);
}

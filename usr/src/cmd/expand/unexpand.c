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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * unexpand - put tabs into a file replacing blanks
 */
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <locale.h>
#include <libintl.h>
#include <wchar.h>

#define	INPUT_SIZ	LINE_MAX	/* POSIX.2 */
#define	MAX_TABS	100		/* maximum number of tabstops */

static int	nstops = 0;		/* total number of tabstops */
static int	tabstops[MAX_TABS];	/* the tabstops themselves */

static void tabify(wchar_t *, int);
static void getstops(const char *);
static void usage(void);

int
main(argc, argv)
int argc;
char *argv[];
{
	int		flag;		/* option flag read by getopt() */
	int		all = 0;	/* -a flag */
	int		status = 0;
	wchar_t		input_buf[INPUT_SIZ+1];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((flag = getopt(argc, argv, "at:")) != EOF) {
		switch (flag) {
		case 'a':
			all++;
			break;

		case 't':		/* POSIX.2 */
			all++;		/* -t turns on -a */
			getstops(optarg);
			break;

		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv = &argv[optind];

	do {
		if (argc > 0) {
			if (freopen(argv[0], "r", stdin) == NULL) {
				(void) fprintf(stderr, "unexpand: ");
				perror(argv[0]);
				status++;
			}
			argc--, argv++;
		}

		while (fgetws(input_buf, INPUT_SIZ, stdin) != NULL) {
			input_buf[INPUT_SIZ] = 0;
			tabify(input_buf, all);
		}
	} while (argc > 0);

	return (status);
	/* NOTREACHED */
}

void
tabify(wchar_t *ibuf, int all)
{
	wchar_t *cp;		/* current position in ibuf */
	int ocol = 0;		/* current output column */
	int cstop = 0;		/* current tabstop */
	int spaces = 0;		/* spaces to convert to tab */
	int	p_col;

	cp = ibuf;

	for (;;) {
		switch (*cp) {
		case ' ':
			cp++;

			spaces++;
			ocol++;

			if (nstops == 0) {		/* default tab = 8 */
				if ((ocol & 7) != 0)
					break;
			} else if (nstops == 1) {	/* tab width */
				if ((ocol % tabstops[0]) != 0)
					break;
			} else {			/* explicit tabstops */
				while (cstop < nstops &&
				    ocol > tabstops[cstop])
					cstop++;

				if (cstop >= nstops) {
					(void) putchar(' ');
					spaces = 0;
					break;
				}

				if (ocol != tabstops[cstop])
					break;
				cstop++;
			}

			/*
			 * if we get to this point, we must be at a
			 * tab stop.  if spaces, then write out a tab.
			 */
			if (spaces > 0) {
				(void) putchar(((spaces > 1) ? '\t' : ' '));
				spaces = 0;
			}

			break;

		case '\b':		/* POSIX.2 */
			while (spaces-- > 0)
				(void) putchar(' ');
			spaces = 0;

			cp++;
			(void) putchar('\b');

			if (--ocol < 0)
				ocol = 0;

			/* just in case */
			cstop = 0;
			break;

		case '\t':
			cp++;
			(void) putchar('\t');

			/* adjust ocol to current tabstop */
			if (nstops == 0) {
				ocol = (ocol + 8) & ~07;
			} else if (nstops == 1) {
				ocol += ocol % tabstops[0];
			} else {
				if (cstop < nstops &&
				    ocol < tabstops[cstop])
					ocol = tabstops[cstop++];
				else
					ocol++;
			}

			spaces = 0;
			break;

		default:
			while (spaces-- > 0)
				(void) putchar(' ');
			spaces = 0;

			if (*cp == 0 || *cp == '\n' || all == 0) {
				/*
				 * either end of input line or -a not set
				 */
				while (*cp != 0)
					(void) putwchar(*cp++);
				return;
			}

			(void) putwchar(*cp++);
			if ((p_col = wcwidth(*cp)) < 0)
				p_col = 0;
			ocol += p_col;
			break;
		}
	}
}

static void
getstops(const char *cp)
{
	register int i;

	for (;;) {
		i = 0;
		while (*cp >= '0' && *cp <= '9')
			i = i * 10 + *cp++ - '0';

		if (i <= 0 || i > INT_MAX) {
			(void) fprintf(stderr, gettext(
			    "unexpand: invalid tablist item\n"));
			usage();
		}

		if (nstops > 0 && i <= tabstops[nstops-1]) {
			(void) fprintf(stderr, gettext(
			    "unexpand: tablist must be increasing\n"));
			usage();
		}

		if (nstops == MAX_TABS) {
			(void) fprintf(stderr, gettext(
			    "unexpand: number of tabstops limited to %d\n"),
				MAX_TABS);
			usage();
		}

		tabstops[nstops++] = i;
		if (*cp == 0)
			break;
		if (*cp != ',' && *cp != ' ') {
			(void) fprintf(stderr, gettext(
			    "unexpand: invalid tablist separator\n"));
			usage();
		}

		cp++;
	}
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: unexpand [-a ] [-t tablist] [file ...]\n"));
	exit(2);
	/* NOTREACHED */
}

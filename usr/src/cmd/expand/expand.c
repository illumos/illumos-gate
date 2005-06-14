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

#include <stdio.h>
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <wchar.h>

/*
 * expand - expand tabs to equivalent spaces
 */
static int		nstops = 0;
static int		tabstops[100];
static int		isClocale;

static void getstops(const char *);
static void usage(void);

int
main(argc, argv)
int argc;
char *argv[];
{
	static char	ibuf[BUFSIZ];
	register int	c, column;
	register int	n;
	register int	i, j;
	char		*locale;
	int		flag, tflag = 0;
	int		len;
	int		p_col;
	wchar_t		wc;
	char		*p1, *p2;

	(void) setlocale(LC_ALL, "");
	locale = setlocale(LC_CTYPE, NULL);
	isClocale = (strcmp(locale, "C") == 0);
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * First, look for and extract any "-<number>" args then pass
	 * them to getstops().
	 */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0)
			break;

		if (*argv[i] != '-')
			continue;
		if (!isdigit(*(argv[i]+1)))
			continue;

		getstops(argv[i]+1);
		tflag++;

		/* Pull this arg from list */
		for (j = i; j < (argc-1); j++)
			argv[j] = argv[j+1];
		argc--;
	}

	while ((flag = getopt(argc, argv, "t:")) != EOF) {
		switch (flag) {
		case 't':
			if (tflag)
				usage();

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
				perror(argv[0]);
				exit(1);
				/* NOTREACHED */
			}
			argc--;
			argv++;
		}

		column = 0;
		p1 = p2 = ibuf;
		for (;;) {
			if (p1 >= p2) {
				p1 = ibuf;
				if ((len = fread(p1, 1, BUFSIZ, stdin)) <= 0)
					break;
				p2 = p1 + len;
			}

			c = *p1++;
			switch (c) {
			case '\t':
				if (nstops == 0) {
					do {
						(void) putchar(' ');
						column++;
					} while (column & 07);
					continue;
				}
				if (nstops == 1) {
					do {
						(void) putchar(' ');
						column++;
					} while (
					    ((column - 1) % tabstops[0]) !=
						(tabstops[0] - 1));
					continue;
				}
				for (n = 0; n < nstops; n++)
					if (tabstops[n] > column)
						break;
				if (n == nstops) {
					(void) putchar(' ');
					column++;
					continue;
				}
				while (column < tabstops[n]) {
					(void) putchar(' ');
					column++;
				}
				continue;

			case '\b':
				if (column)
					column--;
				(void) putchar('\b');
				continue;

			default:
				if (isClocale) {
					(void) putchar(c);
					column++;
					continue;
				}

				if (isascii(c)) {
					(void) putchar(c);
					column++;
					continue;
				}

				p1--;
				if ((len = (p2 - p1)) <
					(unsigned int)MB_CUR_MAX) {
					for (n = 0; n < len; n++)
						ibuf[n] = *p1++;
					p1 = ibuf;
					p2 = p1 + n;
					if ((len = fread(p2, 1, BUFSIZ - n,
							stdin)) > 0)
						p2 += len;
				}
				if ((len = (p2 - p1)) >
					(unsigned int)MB_CUR_MAX)
					len = (unsigned int)MB_CUR_MAX;

				if ((len = mbtowc(&wc, p1, len)) <= 0) {
					(void) putchar(c);
					column++;
					p1++;
					continue;
				}

				if ((p_col = wcwidth(wc)) < 0)
					p_col = len;
				p1 += len;
				(void) putwchar(wc);
				column += p_col;
				continue;

			case '\n':
				(void) putchar(c);
				column = 0;
				continue;
			}
		}
	} while (argc > 0);

	return (0);
	/* NOTREACHED */
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
				"expand: invalid tablist\n"));
			usage();
		}

		if (nstops > 0 && i <= tabstops[nstops-1]) {
			(void) fprintf(stderr, gettext(
				"expand: tablist must be increasing\n"));
			usage();
		}

		tabstops[nstops++] = i;
		if (*cp == 0)
			break;

		if (*cp != ',' && *cp != ' ') {
			(void) fprintf(stderr, gettext(
				"expand: invalid tablist\n"));
			usage();
		}
		cp++;
	}
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
		"usage: expand [-t tablist] [file ...]\n"
		"       expand [-tabstop] [-tab1,tab2,...,tabn] [file ...]\n"));
	exit(2);
	/* NOTREACHED */
}

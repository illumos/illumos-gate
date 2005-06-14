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
 *	process common lines of two files
 */

#include 	<locale.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

static int compare(char *, char *);
static int rd(FILE *, char *);
static FILE *openfil(char *);
static void copy(FILE *, char *, int);
static void usage(void);
static void wr(char *, int);

#define	LB	2050	/* P1003.2 minimum (2048) + 2 */

#define	RDTWO(ib1, lb1, ib2, lb2) \
	{ \
		if (rd(ib1, lb1) < 0) { \
			if (rd(ib2, lb2) < 0) \
				exit(0); \
			copy(ib2, lb2, 2); \
		} \
		if (rd(ib2, lb2) < 0) \
			copy(ib1, lb1, 1); \
	}

static int	one;
static int	two;
static int	three;

static char	ldr[3][3] = {"", "\t", "\t\t"};

static FILE	*ib1;
static FILE	*ib2;
static int	is_c_locale;

int
main(int argc, char **argv)
{
	int	l = 1;
	int	c;		/* used for getopt() */
	char	lb1[LB], lb2[LB], *collate;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((collate = setlocale(LC_COLLATE, NULL)) == NULL) {
		(void) fprintf(stderr,
			gettext("Query of LC_COLLATE category failed\n"));
		exit(4);
	}

	is_c_locale = (strcmp("C", collate) == 0) ? 1 : 0;
	while ((c = getopt(argc, argv, "123")) != EOF)
		switch (c) {
		case '1':
			if (!one) {
				one = 1;
				ldr[1][0] = ldr[2][l--] = '\0';
			}
			break;
		case '2':
			if (!two) {
				two = 1;
				ldr[2][l--] = '\0';
			}
			break;
		case '3':
			three = 1;
			break;

		default:
			usage();
		}

	argc -= optind;
	argv  = &argv[optind];

	if (argc != 2)
		usage();
	ib1 = openfil(argv[0]);
	ib2 = openfil(argv[1]);
	RDTWO(ib1, lb1, ib2, lb2);
	for (;;) {
		switch (compare(lb1, lb2)) {
			case 0:
				wr(lb1, 3);
				RDTWO(ib1, lb1, ib2, lb2);
				continue;

			case 1:
				wr(lb1, 1);
				if (rd(ib1, lb1) < 0)
					copy(ib2, lb2, 2);
				continue;

			case 2:
				wr(lb2, 2);
				if (rd(ib2, lb2) < 0)
					copy(ib1, lb1, 1);
				continue;
			/*
			 * case "3" means lines are equal in collation,
			 * but not identical (not very likely)
			 */
			case 3:
				wr(lb1, 1);
				wr(lb2, 2);
				RDTWO(ib1, lb1, ib2, lb2);
				continue;
		}
	}
	/* NOTREACHED */
	return (0);
}

static int
rd(file, buf)
FILE *file;
char *buf;
{
	register int i, j;
	i = j = 0;
	while ((j = getc(file)) != EOF) {
		*buf = (char)j;
		if (*buf == '\n' || i > LB-2) {
			*buf = '\0';
			return (0);
		}
		i++;
		buf++;
	}
	return (-1);
}

static void
wr(str, n)
char *str;
int n;
{
	switch (n) {
		case 1:
			if (one)
				return;
			break;

		case 2:
			if (two)
				return;
			break;

		case 3:
			if (three)
				return;
	}
	(void) printf("%s%s\n", ldr[n-1], str);
}

static void
copy(ibuf, lbuf, n)
FILE *ibuf;
char *lbuf;
int n;
{
	do {
		wr(lbuf, n);
	} while (rd(ibuf, lbuf) >= 0);

	exit(0);
}

static int
compare(a, b)
char *a, *b;
{
	register char *ra, *rb;
	int ret;

	ra = a - 1;
	rb = b - 1;
	while (*++ra == *++rb)
		if (*ra == '\0')
			return (0);

	/* For "C" locale, just compare bytes */
	if (is_c_locale) {
		if (*ra < *rb)
			return (1);
		return (2);
	}
	/* For other locales, call locale-sensitive compare routine */
	else {
		ret = strcoll(a, b);
		return (ret == 0 ? 3 : (ret < 0 ? 1 : 2));
	}
}

static FILE *
openfil(s)
char *s;
{
	FILE *b;
	if (s[0] == '-' && s[1] == 0)
		b = stdin;
	else if ((b = fopen(s, "r")) == NULL) {
		(void) fprintf(stderr, "comm: ");
		perror(s);
		exit(2);
	}
	return (b);
}

static void
usage()
{
	(void) fprintf(stderr, gettext("usage: comm [-123] file1 file2\n"));
	exit(2);
}

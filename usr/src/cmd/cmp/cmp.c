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
/* Portions Copyright 2006 Stephen P. Potter */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	compare two files
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include 	<locale.h>
#include	<sys/types.h>

FILE	*file1, *file2;

char	*arg;

int	eflg;
int	lflg = 1;

offset_t	line = 1;
offset_t	chr = 0;
offset_t	skip1;
offset_t	skip2;

offset_t 	otoi(char *);

static void narg(void);
static void barg(void);
static void earg(void);

int
main(int argc, char **argv)
{
	int		c;
	int		c1, c2;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "ls")) != EOF)
		switch (c) {
			case 'l':
				lflg = 2;
				break;
			case 's':
				lflg = 0;
				break;
			case '?':
			default:
				narg();
		}
	argv += optind;
	argc -= optind;
	if (argc < 2 || argc > 4)
		narg();

	arg = argv[0];
	if (arg[0] == '-' && arg[1] == 0)
		file1 = stdin;
	else if ((file1 = fopen(arg, "r")) == NULL)
		barg();

	arg = argv[1];
	if (arg[0] == '-' && arg[1] == 0)
		file2 = stdin;
	else if ((file2 = fopen(arg, "r")) == NULL)
		barg();

	if (file1 == stdin && file2 == stdin)
		narg();

	if (argc > 2)
		skip1 = otoi(argv[2]);
	if (argc > 3)
		skip2 = otoi(argv[3]);
	while (skip1) {
		if ((c1 = getc(file1)) == EOF) {
			arg = argv[0];
			earg();
		}
		skip1--;
	}
	while (skip2) {
		if ((c2 = getc(file2)) == EOF) {
			arg = argv[1];
			earg();
		}
		skip2--;
	}

	for (;;) {
		chr++;
		c1 = getc(file1);
		c2 = getc(file2);
		if (c1 == c2) {
			if (c1 == '\n')
				line++;
			if (c1 == EOF) {
				if (eflg)
					return (1);
				return (0);
			}
			continue;
		}
		if (lflg == 0)
			return (1);
		if (c1 == EOF) {
			arg = argv[0];
			earg();
		}
		if (c2 == EOF)
			earg();
		if (lflg == 1) {
			(void) printf(
			    gettext("%s %s differ: char %lld, line %lld\n"),
			    argv[0], arg, chr, line);
			return (1);
		}
		eflg = 1;
		(void) printf("%6lld %3o %3o\n", chr, c1, c2);
	}
}

offset_t
otoi(s)
char *s;
{
	offset_t v;
	int base;

	v = 0;
	base = 10;
	if (*s == '0')
		base = 8;
	while (isdigit(*s))
		v = v*base + *s++ - '0';
	return (v);
}

static void
narg()
{
	(void) fprintf(stderr,
	    gettext("usage: cmp [-l | -s] file1 file2 [skip1] [skip2]\n"));
	exit(2);
}

static void
barg()
{
	if (lflg)
		(void) fprintf(stderr, gettext("cmp: cannot open %s\n"), arg);
	exit(2);
}

static void
earg()
{
	(void) fprintf(stderr, gettext("cmp: EOF on %s\n"), arg);
	exit(1);
}

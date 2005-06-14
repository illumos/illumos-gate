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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <ctype.h>
#include <limits.h>
#include <locale.h>
#include <nl_types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define	FF '\f'
#define	NL '\n'
#define	NUL '\0'

static	void usage(void);
static	void disp_file(FILE *f, char *filename);
static	FILE *get_next_file(int, char *, char *[], int);
static	void finish(int need_a_newline);

int estatus = 0;	/* exit status */
int i;			/* argv index */

int
main(int argc, char *argv[])
{
	int c;
	int form_feeds		= 0;
	int need_a_newline	= 0;
	char *filename		= NULL;
	FILE *f;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"  /* Use this only if it were not */
#endif

	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "f")) != EOF) {
		switch (c) {
		case 'f':
			form_feeds = 1;
			break;

		case '?':
			usage();
		}
	}

	i = optind;
	if (argc <= i) {
		filename = NULL;
		f = stdin;
	} else {
		f = get_next_file(need_a_newline, filename, argv, argc);
	}

	need_a_newline = 0;
	for (;;) {
		/* interpret the first character in the line */

		c = getc(f);
		switch (c) {
		case EOF:
			disp_file(f, filename);

			if (i >= argc)
				finish(need_a_newline);

			f = get_next_file(need_a_newline, filename, argv, argc);

			if (need_a_newline) {
				(void) putchar(NL);
				need_a_newline = 0;
			}

			if (form_feeds)
				(void) putchar(FF);

			continue;

		case NL:
			if (need_a_newline)
				(void) putchar(NL);
			need_a_newline = 1;
			continue;

		case '+':
			if (need_a_newline)
				(void) putchar('\r');
			break;

		case '0':
			if (need_a_newline)
				(void) putchar(NL);
			(void) putchar(NL);
			break;

		case '1':
			if (need_a_newline)
				(void) putchar(NL);
			(void) putchar(FF);
			break;

		case ' ':
		default:
			if (need_a_newline)
				(void) putchar(NL);
			break;
		}

		need_a_newline = 0;

		for (;;) {
			c = getc(f);
			if (c == NL) {
				need_a_newline = 1;
				break;
			} else if (c == EOF) {
				disp_file(f, filename);

				if (i >= argc)
					finish(need_a_newline);

				f = get_next_file(need_a_newline, filename,
				    argv, argc);

				if (form_feeds) {
					(void) putchar(NL);
					(void) putchar(FF);
					need_a_newline = 0;
					break;
				}
			} else {
				(void) putchar(c);
			}
		}
	}
	/* NOTREACHED */
	return (0);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: asa [-f] [-|file...]\n"));
	exit(1);
}


static	void
disp_file(FILE *f, char *filename)
{

	if (ferror(f)) {
		int	serror = errno;
		if (filename) {
			(void) fprintf(stderr, gettext(
			    "asa: read error on file %s\n"), filename);
		} else {
			(void) fprintf(stderr, gettext(
			    "asa: read error on standard input\n"));
		}
		errno = serror;
		perror("");
		estatus = 1;
	}

	(void) fclose(f);

}

static	FILE *
get_next_file(int need_a_newline, char *filename, char *argv[], int argc)
{
	FILE	*f;
	if (strcmp(argv[i], "-") == 0) {
		filename = NULL;
		f = stdin;
	} else {
		/*
		 * Process each file operand.  If unsuccessful, affect the
		 * exit status and continue processing the next operand.
		 */
		filename = argv[i];
		while ((f = fopen(filename, "r")) == NULL) {
			int	serror = errno;
			(void) fprintf(stderr,
				gettext("asa: cannot open %s:"), filename);
			errno = serror;
			perror("");
			estatus = 1;
			if (++i < argc) {
				if (strcmp(argv[i], "-") == 0) {
					filename = NULL;
					f = stdin;
					break;
				} else {
					filename = argv[i];
				}
			} else {
				finish(need_a_newline);
			}
		}
	}
	++i;
	return (f);
}

static	void
finish(int need_a_newline)
{
	if (need_a_newline)
		(void) putchar(NL);
	exit(estatus);
}

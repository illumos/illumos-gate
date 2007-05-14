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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	wc -- word and line count
 */

#include	<stdio.h>
#include	<limits.h>
#include	<locale.h>
#include	<wctype.h>
#include	<stdlib.h>
#include	<errno.h>
#include	<string.h>
#include	<euc.h>

#undef BUFSIZ
#define	BUFSIZ	4096
unsigned char	b[BUFSIZ];

FILE *fptr = stdin;
unsigned long long 	wordct;
unsigned long long	twordct;
unsigned long long	linect;
unsigned long long	tlinect;
unsigned long long	charct;
unsigned long long	tcharct;
unsigned long long	real_charct;
unsigned long long	real_tcharct;

int cflag = 0, mflag = 0, lflag = 0, wflag = 0;

static void wcp(unsigned long long, unsigned long long,
	unsigned long long, unsigned long long);
static void usage(void);

int
main(int argc, char **argv)
{
	unsigned char *p1, *p2;
	unsigned int c;
	int	flag;
	int	i, token;
	int	status = 0;
	wchar_t wc;
	int	len, n, errflag;


	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);


	while ((flag = getopt(argc, argv, "cCmlw")) != EOF) {
		switch (flag) {
		case 'c':
			if (mflag)
				usage();

			cflag++;
			break;

		case 'C':
		case 'm':		/* POSIX.2 */
			if (cflag)
				usage();
			mflag++;
			break;

		case 'l':
			lflag++;
			break;

		case 'w':
			wflag++;
			break;

		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv = &argv[optind];

	/*
	 * If no flags set, use defaults
	 */
	if (cflag == 0 && mflag == 0 && lflag == 0 && wflag == 0) {
		cflag = 1;
		lflag = 1;
		wflag = 1;
	}

	i = 0;
	do {
		if (argc > 0 && (fptr = fopen(argv[i], "r")) == NULL) {
			(void) fprintf(stderr, "wc: %s: %s\n",
			    argv[i], strerror(errno));
			status = 2;
			continue;
		}

		p1 = p2 = b;
		linect = 0;
		wordct = 0;
		charct = 0;
		real_charct = 0;
		token = 0;
		errflag = 0;
		for (;;) {
			if (p1 >= p2) {
				p1 = b;
				c = fread(p1, 1, BUFSIZ, fptr);
				if (c == 0) {
					if (feof(fptr))
						break;
					/*
					 * skip the file and generate error
					 * message when failed to read the
					 * file.
					 */
					if (ferror(fptr)) {
						(void) fprintf(stderr, gettext(
						    "wc: cannot read %s: %s\n"),
						    argv[i], strerror(errno));
						status = 2;
						errflag = 1;
						break;
					}
				}
				charct += c;
				p2 = p1+c;
			}
			c = *p1++;
			real_charct++;
			if (ISASCII(c)) {
				if (isspace(c)) {
					if (c == '\n')
						linect++;
					token = 0;
					continue;
				}

				if (!token) {
					wordct++;
					token++;
				}
			} else {
				p1--;
				if ((len = (p2 - p1)) <
						(unsigned int)MB_CUR_MAX) {
					for (n = 0; n < len; n++)
						b[n] = *p1++;
					p1 = b;
					p2 = p1 + n;
					c = fread(p2, 1, BUFSIZ - n, fptr);
					if ((int)c > 0) {
						charct += c;
						p2 += c;
					}
				}

				if ((len = (p2 - p1)) >
						(unsigned int)MB_CUR_MAX)
					len = (unsigned int)MB_CUR_MAX;
				if ((len = mbtowc(&wc, (char *)p1, len)) > 0) {
					p1 += len;
					if (iswspace(wc)) {
						token = 0;
						continue;
					}
				} else
					p1++;
				if (!token) {
					wordct++;
					token++;
				}
			}
		}
		/* print lines, words, chars */
printwc:
		(void) fclose(fptr);
		if (errflag)
			continue;

		wcp(charct, wordct, linect, real_charct);
		if (argc > 0) {
			(void) printf(" %s\n", argv[i]);
		}
		else
			(void) printf("\n");
		tlinect += linect;
		twordct += wordct;
		tcharct += charct;
		real_tcharct += real_charct;
	} while (++i < argc);

	if (argc > 1) {
		wcp(tcharct, twordct, tlinect, real_tcharct);
		(void) printf(" total\n");
	}
	return (status);
}

static void
wcp(
	unsigned long long charct,
	unsigned long long wordct,
	unsigned long long linect,
	unsigned long long real_charct)
{
	if (lflag)
		(void) printf((linect < 10000000) ? " %7llu" :
			" %llu", linect);

	if (wflag)
		(void) printf((wordct < 10000000) ? " %7llu" :
			" %llu", wordct);

	if (cflag)
		(void) printf((charct < 10000000) ? " %7llu" :
			" %llu", charct);
	else if (mflag)
		(void) printf((real_charct < 10000000) ? " %7llu" :
			" %llu", real_charct);
}

static void
usage()
{
	(void) fprintf(stderr, gettext(
		"usage: wc [-c | -m | -C] [-lw] [file ...]\n"));
	exit(2);
}

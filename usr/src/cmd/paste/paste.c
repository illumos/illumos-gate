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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <locale.h>
#include <widec.h>
#include <stdlib.h>
#include <limits.h>


#define	MAXOPNF	12  	/* maximal no. of open files (not with -s option) */
#define	MAXOPNF_STR	"12"
#define	RUB	'\177'


/*
 * Function prototypes
 */
static	void	diag(char *, char *);
static	int	move(char *, wchar_t *);
static	void	usage();

int
main(int argc, char **argv)
{
	int 		i, j, k, eofcount, nfiles, maxline, glue;
	int		delcount = 1;
	int		onefile  = 0;
	register	int c;
	wchar_t		del[LINE_MAX];
	wchar_t		outbuf[LINE_MAX], l, t;
	register 	wchar_t *p;
	FILE		*inptr[MAXOPNF];
	int		arg_ind;
	int		file_ind;
	int		error = 0;


	/* Get locale variables from environment */
	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	del[0] = '\t';
	maxline = LINE_MAX -2;

	/* Get command arguments */
	while ((c = getopt(argc, argv, "d:s")) != EOF) {
		switch (c) {
		case 'd' :
			delcount = move(optarg, del);
			if (delcount < 1)
				diag("paste: no delimiters\n", NULL);
			break;

		case 's' :
			onefile++;
			break;

		case '?':
			usage();

			/* NOTREACHED */
			break;
		}
	}

	if (!onefile) {	/* not -s option: parallel line merging */

		/* Find explicit stdin and file names */
		for (file_ind = 0, arg_ind = optind; arg_ind < argc &&
		    file_ind < MAXOPNF; arg_ind++) {
			if (argv[arg_ind][0] == '-' &&
			    argv[arg_ind][1] == '\0') {
				inptr[file_ind++] = stdin;
			} else if (arg_ind >= optind) {
				inptr[file_ind++] = fopen(argv[arg_ind], "r");
				if (inptr[file_ind -1] == NULL) {
					diag("paste: cannot open %s\n",
					    argv[arg_ind]);
				}
			}
		}
		if (arg_ind < argc) {
			char	maxopnf_buf[LINE_MAX];
			(void) sprintf(maxopnf_buf, "%d", MAXOPNF);
			diag("paste: too many files- limit %s\n", maxopnf_buf);
		}
		nfiles = file_ind;

		do {
			p = &outbuf[0];
			eofcount = 0;
			j = k = 0;
			for (i = 0; i < nfiles; i++) {
				while ((c = fgetwc(inptr[i])) != '\n' &&
				    c != EOF) {
					if (++j <= maxline)
						*p++ = c;
					else {
						diag(
						    "paste: line too long\n",
						    NULL);
					}
				}
				if ((l = del[k]) != RUB)
					*p++ = l;

				k = (k + 1) % delcount;

				if (c == EOF)
					eofcount++;
			}
			if (l != RUB)
				*--p = '\n';
			else
				*p = '\n';
			*++p = 0;
			if (eofcount < nfiles)
				(void) printf("%ws", outbuf);
		} while (eofcount < nfiles);

	} else { /* -s option: serial file pasting (old 127 paste command) */

		for (i = optind; i < argc; i++) {
			p = &outbuf[0];
			glue = 0;
			j = 0;
			k = 0;
			t = 0;
			if (argv[i][0] == '-' &&
			    argv[i][1] == '\0') {
				inptr[0] = stdin;
			} else if (i >= optind) {
				inptr[0] = fopen(argv[i], "r");
				if (inptr[0] == NULL) {
				    (void) fprintf(stderr, gettext(
					"paste: cannot open %s\n"), argv[i]);
				    error = 1;
				}
			}

			/* Argument not a file name */
			if (inptr[0] == NULL) {
				continue;
			}

			while ((c = fgetwc(inptr[0])) != EOF) {
				if (j >= maxline) {
					t = *--p;
					*++p = 0;
					(void) printf("%ws", outbuf);
					p = &outbuf[0];
					j = 0;
				}
				if (glue) {
					glue = 0;
					l = del[k];
					if (l != RUB) {
						*p++ = l;
						t = l;
						j++;
					}
					k = (k + 1) % delcount;
				}
				if (c != '\n') {
					*p++ = c;
					t = c;
					j++;
				} else glue++;
			}
			if (t != '\n') {
				*p++ = '\n';
				j++;
			}
			if (j > 0) {
				*p = 0;
				(void) printf("%ws", outbuf);
			}
		}
	}
	return (error);
}


static	void
diag(char *s, char *arg)
{
	(void) fprintf(stderr, gettext(s), arg);
	exit(1);
}


static	int
move(char *from, wchar_t *to)
{
	int i, n;
	wchar_t wc;

	i = 0;
	while (*from) {
		n = mbtowc(&wc, from, MB_CUR_MAX);
		if (n <= 0)
			return (0); /* invalid character as a delimiter */
		from += n;
		if (wc != L'\\') *to++ = wc;
		else {
			n = mbtowc(&wc, from, MB_CUR_MAX);
			if (n <= 0)
				return (0);
			from += n;
			switch (wc) {
				case L'0' : *to++ = RUB;
						break;
				case L't' : *to++ = L'\t';
						break;
				case L'n' : *to++ = L'\n';
						break;
				default  : *to++ = wc;
						break;
			}
		}
		i++;
	}
	return (i);
}


static	void
usage()
{
	(void) fprintf(stderr, gettext(
	"usage: paste [-s] [-d list] file  \n\n"));
	exit(1);
}

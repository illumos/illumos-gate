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

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */
/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <string.h>
#include <ctype.h>

#define	DEF_LINE_COUNT	10

static	void	copyout(off_t, int);
static	void	Usage();
static	FILE	*input;


/*
 * head - give the first few lines of a stream or of each of a set of files.
 * Optionally shows a specific number of bytes instead.
 */
int
main(int argc, char **argv)
{
	int	fileCount;
	int	around = 0;
	int	i;
	int	opt;
	off_t	linecnt	= DEF_LINE_COUNT;
	int	isline = 1;
	int	error = 0;
	int	quiet = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* check for non-standard "-line-count" option */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0)
			break;

		if ((argv[i][0] == '-') && isdigit(argv[i][1])) {
			if (strlen(&argv[i][1]) !=
			    strspn(&argv[i][1], "0123456789")) {
				(void) fprintf(stderr, gettext(
				    "%s: Badly formed number\n"), argv[0]);
				Usage();
			}

			linecnt = (off_t)strtoll(&argv[i][1], (char **)NULL,
			    10);
			while (i < argc) {
				argv[i] = argv[i + 1];
				i++;
			}
			argc--;
		}
	}

	/* get options */
	while ((opt = getopt(argc, argv, "qvn:c:")) != EOF) {
		switch (opt) {
		case 'n':
		case 'c':
			if ((strcmp(optarg, "--") == 0) || (optind > argc)) {
				(void) fprintf(stderr, gettext(
				    "%s: Missing -%c argument\n"), argv[0],
				    optopt);
				Usage();
			}
			linecnt = (off_t)strtoll(optarg, (char **)NULL, 10);
			if (linecnt <= 0) {
				(void) fprintf(stderr, gettext(
				    "%s: Invalid \"-%c %s\" option\n"),
				    argv[0], optopt, optarg);
				Usage();
			}
			isline = optopt != 'c';
			break;
		case 'q':
			quiet = 1;
			break;
		case 'v':
			quiet = 0;
			break;
		default:
			Usage();
		}
	}

	fileCount = argc - optind;

	do {
		if ((argv[optind] == NULL) && around)
			break;

		if (argv[optind] != NULL) {
			if (input != NULL)
				(void) fclose(input);
			if ((input = fopen(argv[optind], "r")) == NULL) {
				perror(argv[optind]);
				error = 1;
				optind++;
				continue;
			}
		} else {
			input = stdin;
		}

		if (quiet == 0) {
			if (around)
				(void) putchar('\n');

			if (fileCount > 1)
				(void) printf("==> %s <==\n", argv[optind]);
		}

		if (argv[optind] != NULL)
			optind++;

		copyout(linecnt, isline);
		(void) fflush(stdout);
		around++;

	} while (argv[optind] != NULL);

	return (error);
}

static void
copyout(off_t cnt, int isline)
{
	char lbuf[BUFSIZ];
	size_t len;

	while (cnt > 0 && fgets(lbuf, sizeof (lbuf), input) != 0) {
		len = strlen(lbuf);
		if (isline) {
			(void) printf("%s", lbuf);
			/*
			 * only count as a line if buffer read ends with newline
			 */
			if (len > 0) {
				if (lbuf[len - 1] == '\n') {
					(void) fflush(stdout);
					cnt--;
				}
			}
		} else {
			if (len > cnt) {
				lbuf[cnt] = '\0';
				len = cnt;
			}
			(void) printf("%s", lbuf);
			cnt -= len;
			(void) fflush(stdout);
		}
	}
}

static void
Usage()
{
	(void) printf(gettext("usage: head [-q] [-v] [-n #] [-c #] [-#] "
	    "[filename...]\n"));
	exit(1);
}

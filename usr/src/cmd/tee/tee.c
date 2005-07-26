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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * tee - pipe fitting
 */

#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <locale.h>

#define	min(a, b)	((a) > (b) ? (b) : (a))
#define	MAXFILES 20

static void stash(int);

static int ofiles = 0;
static int ispipe = 0;		/* output goes to pipe or special file */
static int openf[MAXFILES] = { 1 };
static char in[PIPE_BUF];
static const char *usage = "usage: tee [-ai] [file...]\n";

int
main(int argc, char **argv)
{
	int		w;
	int		c;
	int		aflag		= 0;
	int		errorcode	= 0;
	struct stat	buf;


	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"  /* Use this only if it weren't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "ai")) != EOF) {
		switch (c) {
			case 'a':
				aflag++;
				break;
			case 'i':
				(void) signal(SIGINT, SIG_IGN);
				break;
			case '?':
				(void) fprintf(stderr, gettext(usage));
				exit(1);
		}
	}
	argc -= optind;
	argv = &argv[optind];

	(void) fstat(1, &buf);
	if (S_ISFIFO(buf.st_mode) || S_ISCHR(buf.st_mode))
		ispipe++;

	openf[ofiles++] = 1;
	while (argc-- > 0 && ofiles < MAXFILES) {
		openf[ofiles] = open(argv[0],
		    O_WRONLY|O_CREAT|(aflag ? O_APPEND:O_TRUNC), 0666);
		if (openf[ofiles] < 0) {
			(void) fprintf(stderr, "tee: ");
			perror(argv[0]);
			errorcode++;
		} else {
			if (fstat(openf[ofiles], &buf) >= 0) {
				if (S_ISCHR(buf.st_mode))
					ispipe++;
				ofiles++;
			} else {
				(void) fprintf(stderr, "tee: ");
				perror(argv[0]);
				errorcode++;
			}
		}
		argv++;
	}
	if (argc >= 0 && ofiles >= MAXFILES) {
		argv--;
		(void) fprintf(stderr, gettext("tee: too many input files; "
		    "ignoring file(s) listed after %s\n"), argv[0]);
		errorcode++;
	}

	while ((w = read(0, in, PIPE_BUF)) > 0)
		stash(w);
	if (w < 0) {
		(void) fprintf(stderr, gettext("tee: read error on input\n"));
		exit(1);
	}
	return (errorcode);
}

static void
stash(int nbytes)
{
	register int k, i, chunk, nb;

	chunk = ispipe ? PIPE_BUF : nbytes;
	for (i = 0; i < nbytes; i += chunk) {
		nb = min(chunk, nbytes - i);
		for (k = 0; k < ofiles; k++)
			(void) write(openf[k], in+i, nb);
	}
}

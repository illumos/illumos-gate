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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * mesg -- set current tty to accept or
 *	forbid write permission.
 *
 *	mesg [-y | -n | y | n]
 *		y allow messages
 *		n forbid messages
 *	return codes
 *		0 if messages are ON or turned ON
 *		1 if messages are OFF or turned OFF
 *		2 if an error occurs
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>

static void error(const char *s);
static void newmode(mode_t m);
static void usage(void);

static char *tty;

int
main(int argc, char *argv[])
{
	int i, c, r = 0;
	int action = 0;
	struct stat sbuf;

	extern int optind;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Check stdin, stdout and stderr, in order, for a tty
	 */
	for (i = 0; i <= 2; i++) {
		if ((tty = ttyname(i)) != NULL)
			break;
	}

	if (stat(tty, &sbuf) < 0)
		error("cannot stat");

	if (argc < 2) {
		if (sbuf.st_mode & (S_IWGRP | S_IWOTH)) {
			(void) printf("is y\n");
		} else {
			r = 1;
			(void) printf("is n\n");
		}
		exit(r);
	}

	while ((c = getopt(argc, argv, "yn")) != EOF) {
		switch (c) {
		case 'y':
			if (action > 0)
				usage();

			newmode(S_IRUSR | S_IWUSR | S_IWGRP);
			action++;
			break;

		case 'n':
			if (action > 0)
				usage();

			newmode(S_IRUSR | S_IWUSR);
			r = 1;
			action++;
			break;

		case '?':
			usage();
			break;
		}
	}

	/*
	 * Required for POSIX.2
	 */
	if (argc > optind) {
		if (action > 0)
			usage();

		switch (*argv[optind]) {
		case 'y':
			newmode(S_IRUSR | S_IWUSR | S_IWGRP);
			break;

		case 'n':
			newmode(S_IRUSR | S_IWUSR);
			r = 1;
			break;

		default:
			usage();
			break;
		}
	}

	return (r);
}

void
error(const char *s)
{
	(void) fprintf(stderr, "mesg: ");
	(void) fprintf(stderr, "%s\n", s);
	exit(2);
}

void
newmode(mode_t m)
{
	if (chmod(tty, m) < 0)
		error("cannot change mode");
}

void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: mesg [-y | -n | y | n]\n"));
	exit(2);
}

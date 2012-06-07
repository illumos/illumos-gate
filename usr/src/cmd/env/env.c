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

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */
/*
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 */

/*
 *	env [ - ] [ name=value ]... [command arg...]
 *	set environment, then execute command (or print environment)
 *	- says start fresh, otherwise merge with inherited environment
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>


static	void	Usage();
extern	char	**environ;


int
main(int argc, char **argv)
{
	char	**p;
	int	opt;
	int	i;


	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* check for non-standard "-" option */
	if ((argc > 1) && (strcmp(argv[1], "-")) == 0) {
		(void) clearenv();
		for (i = 1; i < argc; i++)
			argv[i] = argv[i+1];
		argc--;
	}

	/* get options */
	while ((opt = getopt(argc, argv, "i")) != EOF) {
		switch (opt) {
		case 'i':
			(void) clearenv();
			break;

		default:
			Usage();
		}
	}

	/* get environment strings */
	while (argv[optind] != NULL && strchr(argv[optind], '=') != NULL) {
		if (putenv(argv[optind])) {
			(void) perror(argv[optind]);
			exit(1);
		}
		optind++;
	}

	/* if no utility, output environment strings */
	if (argv[optind] == NULL) {
		p = environ;
		while (*p != NULL)
			(void) puts(*p++);
	} else {
		(void) execvp(argv[optind],  &argv[optind]);
		(void) fprintf(stderr, "%s: %s: %s\n", argv[0], argv[optind],
		    strerror(errno));
		exit(((errno == ENOENT) || (errno == ENOTDIR)) ? 127 : 126);
	}
	return (0);
}


static	void
Usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage: env [-i] [name=value ...] [utility [argument ...]]\n"
	    "       env [-] [name=value ...] [utility [argument ...]]\n"));
	exit(1);
}

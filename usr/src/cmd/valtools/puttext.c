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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include "libadm.h"

static char	*prog;
static int	nflag;
static int	lmarg, rmarg;

static void
usage(void)
{
	(void) fprintf(stderr,
		gettext("usage: %s [-r rmarg] [-l lmarg] string\n"),
		prog);
	exit(1);
}

/*
 * Given argv[0], return a pointer to the basename of the program.
 */
static char *
prog_name(char *arg0)
{
	char *str;

	/* first strip trailing '/' characters (exec() allows these!) */
	str = arg0 + strlen(arg0);
	while (str > arg0 && *--str == '/')
		*str = '\0';
	if ((str = strrchr(arg0, '/')) != NULL)
		return (str + 1);
	return (arg0);
}

int
main(int argc, char **argv)
{
	int c;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog = prog_name(argv[0]);

	while ((c = getopt(argc, argv, "nr:l:?")) != EOF) {
		switch (c) {
		case 'n':
			nflag++;
			break;

		case 'r':
			rmarg = atoi(optarg);
			break;

		case 'l':
			lmarg = atoi(optarg);
			break;

		default:
			usage();
		}
	}

	if ((optind + 1) != argc)
		usage();

	(void) puttext(stdout, argv[optind], lmarg, rmarg);
	if (!nflag)
		(void) fputc('\n', stdout);
	return (0);
}

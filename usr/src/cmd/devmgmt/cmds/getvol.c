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

/*LINTLIBRARY*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <devmgmt.h>

extern char	*optarg;
extern int	optind,
		ckquit,
		ckwidth;

char	*prog;
char	*label, *fsname;
char	*prompt;
int	options = 0;
int	kpid = (-2);
int	signo = SIGKILL;

static void usage(void);

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
	int c, n;

	prog = prog_name(argv[0]);

	while ((c = getopt(argc, argv, "fFownx:l:p:k:s:?QW:")) != EOF) {
		switch (c) {
		case 'Q':
			ckquit = 0;
			break;

		case 'W':
			ckwidth = atol(optarg);
			break;

		case 'f':
			options |= DM_FORMAT;
			break;

		case 'F':
			options |= DM_FORMFS;
			break;

		case 'o':
			options |= DM_OLABEL;
			break;

		case 'n':
			options |= DM_BATCH;
			break;

		case 'w':
			options |= DM_WLABEL;
			break;

		case 'l':
			if (label)
				usage();
			label = optarg;
			break;

		case 'p':
			prompt = optarg;
			break;

		case 'x':
			if (label)
				usage();
			label = optarg;
			options |= DM_ELABEL;
			break;

		case 'k':
			kpid = atol(optarg);
			break;

		case 's':
			signo = atol(optarg);
			break;

		default:
			usage();
		}
	}

	if ((optind+1) != argc)
		usage();

	switch (n = getvol(argv[optind], label, options, prompt)) {
	case 0:
		break;

	case 1:
		(void) fprintf(stderr,
			"%s: ERROR: unable to access device <%s>\n",
			prog, argv[optind]);
		break;

	case 2:
		(void) fprintf(stderr, "%s: ERROR: unknown device <%s>\n",
			prog, argv[optind]);
		break;

	case 3:
		if (kpid > -2)
			(void) kill(kpid, signo);
		break;

	case 4:
		(void) fprintf(stderr, "%s: ERROR: bad label on <%s>\n",
			prog, argv[optind]);
		break;

	default:
		(void) fprintf(stderr, "%s: ERROR: unknown device error\n",
			prog);
		break;
	}

	return (n);
}

static void
usage()
{
	fprintf(stderr,
	    "usage: %s [-owfF] [-x extlabel] [-l [fsname],volname] device\n",
	    prog);
	fprintf(stderr,
	    "usage: %s [-n] [-x extlabel] [-l [fsname],volname] device\n",
	    prog);
	exit(1);
}

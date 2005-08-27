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

/*
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <libintl.h>
#include <string.h>
#include <unistd.h>
#include <zone.h>

extern int do_prominfo(int, char *, int, int);

static char *
setprogname(char *name)
{
	char	*p;

	if (p = strrchr(name, '/'))
		return (p + 1);
	else
		return (name);
}

int
main(int argc, char *argv[])
{
	int	c;
	int	syserrlog = 0;
	char	*progname = setprogname(argv[0]);
	int	print_flag = 1;
	int	logging = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr,
		    gettext("%s can only be run in the global zone\n"),
		    progname);
		return (1);
	}

	while ((c = getopt(argc, argv, "vl")) != -1)  {
		switch (c)  {
		case 'v':
			++syserrlog;
			break;

		case 'l':
			logging = 1;
			break;

		default:
			(void) fprintf(stderr, "Usage: %s [-lv]\n", progname);
			return (1);
		}
	}

	return (do_prominfo(syserrlog, progname, logging, print_flag));
}

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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>

static void
usage(void)
{
	(void) fprintf(stderr, "%s\n\n", gettext("usage: yppasswd [username]"));
	(void) fprintf(stderr, "%s\n", gettext("NOTE:"));
	(void) fprintf(stderr, "%s\n", gettext("yppasswd and nispasswd have "
			"been replaced by the new passwd command."));
	(void) fprintf(stderr, "%s\n",
		gettext("See passwd(1) for more information."));
}

int
main(int argc, char *argv[])
{
	char *new_argv[5];

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc > 2) {
		usage();
		exit(1);
	}
	new_argv[0] = "yppasswd";
	new_argv[1] = "-r";
	new_argv[2] = "nis";
	if (argc == 1) {
		new_argv[3] = NULL;
	} else {
		new_argv[3] = argv[1];
		new_argv[4] = NULL;
	}

	(void) execvp("/bin/passwd", new_argv);
	perror("/bin/passwd");
	return (1);
}

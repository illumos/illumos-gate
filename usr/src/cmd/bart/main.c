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

#include <signal.h>
#include <unistd.h>
#include <locale.h>
#include <sys/acl.h>
#include "bart.h"

int
main(int argc, char **argv)
{
	/* Make sure we are in the correct locale */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* Superficial check of the arguments.  Note usage() exits the pgm */
	if (argc < 2)
		usage();

	/*
	 * OK, hand it off to bart_create() or bart_compare().
	 *
	 * Since the command line was 'bart create ..',  or 'bart compare ..',
	 * those subcommands should start parsing options at &argv[1], and
	 *  (argc-1) to be consistent.
	 */
	if (strcmp(argv[1], "create") == 0)
		return (bart_create((argc-1), (argv+1)));
	else if (strcmp(argv[1], "compare") == 0) {
		return (bart_compare((argc-1), (argv+1)));

	} else usage();

	return (FATAL_EXIT);
}
void
usage()
{
	(void) fprintf(stderr, USAGE_MSG);
	exit(FATAL_EXIT);
}
void *
safe_calloc(size_t size)
{
	char	*ptr;

	ptr = calloc((size_t)1, size);
	if (ptr == NULL)
		exit(FATAL_EXIT);
	else return (ptr);

	/* NOTREACHED */
}

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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	niserror.c
 *
 *	This module prints the error message associated with an NIS+
 * error code.
 */

#include <stdio.h>
#include <ctype.h>
#include <rpcsvc/nis.h>

static void
usage()
{
	fprintf(stderr, "usage: niserror error-num\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	nis_error	err;

	if (argc != 2)
		usage();

	if (! isdigit(*argv[1]))
		usage();

	err = (nis_error) atoi(argv[1]);
	printf("%s\n", nis_sperrno(err));
	return (0);
}

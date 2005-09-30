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
 *	nispath.c
 *
 * This little utility will print out the search path for a given
 * NIS+ name.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <rpcsvc/nis.h>

void
usage(cmd)
	char	*cmd;
{
	fprintf(stderr, "usage : %s [-v] name\n", cmd);
	exit(1);
}

int
main(int argc, char *argv[])
{
	nis_name	*result;
	int		i = 0;
	char		*name;
	int		verbose = 0;

	if ((argc == 1) || (argc > 3))
		usage(argv[0]);

	if (argc == 3) {
		if (strcmp(argv[1], "-v") == 0)
			verbose = 1;
		else
			usage(argv[0]);
		name = argv[2];
	} else {
		if (strcmp(argv[1], "-v") == 0)
			usage(argv[0]);
		name = argv[1];
	}

	result = nis_getnames(name);
	if (verbose) {
		printf("For NIS+ Name : \"%s\"\n", name);
		printf("Search Path   :\n");
	}
	if (! result) {
		if (verbose)
			printf("\t**NONE**\n");
		exit(1);
	} else
		while (result[i]) {
			if (verbose)
				printf("\t");
			printf("\"%s\"\n", result[i++]);
		}
	return (0);
}

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
 * Copyright 1990, 1991 Sun Microsystems, Inc.  All Rights Reserved.
 *
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>

/* Checks group (-g) or world (default) writeability.
 * Returns as exit code: 0 = writable
 *                       1 = not writable
 */

main(int argc, char **argv)
{
	int group = 0, xmode = 0;
	struct stat statb;

	if (argc < 2) {
		printf("Usage: %s [-g] file\n",argv[0]);
		exit(0);
	}

	if (argc > 2) {
		if (!strcmp(argv[1], "-g")) {
			group = 1;
			argc--;
			argv++;
		}
	}

	if (stat(*++argv,&statb) < 0) {
		exit(2);
	}

	if (group)
		xmode = statb.st_mode & S_IWGRP;
	else 
		xmode = statb.st_mode & S_IWOTH;

	exit(!xmode);
}

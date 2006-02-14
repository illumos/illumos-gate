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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define	USAGE "Usage: minmode pathname mode\n"

/*
 * minmode: takes a pathname and a mode representation in octal, sets
 * the new mode to be stricter than both the current mode and the specified
 * mode.
 * If successful, prints the new mode (exit status = 0);
 * if unsuccessful, prints the usage message (exit status = -1).
 */

int
main(int argc, char **argv)
{
	char *bufp;
	struct stat sbuf;
	long mode, perm, sbits;
	long currmode, currperm, currsbits;
	long newmode, newperm, newsbits;
	long strtol();
	void perror();

	if (argc != 3) {
		printf("%s\n", USAGE);
		return (1);
	}

	mode = strtol(argv[2], &bufp, 8);
	if (*bufp != '\0') {
		printf("minmode: invalid mode - %s\n", argv[2]);
		printf("%s\n", USAGE);
		return (1);
	}

	if (stat(argv[1], &sbuf)) {
		printf("minmode: can't stat %s\n", argv[1]);
		perror(0);
		printf("%s\n", USAGE);
		return (1);
	}
	currmode = ((long)sbuf.st_mode) & 07777;

	perm = mode & 0777;
	sbits = mode & 007000;
	currperm = currmode & 0777;
	currsbits = currmode & 007000;
	newperm = perm & currperm;
	newsbits = sbits | currsbits;
	newmode = newsbits | newperm;
	if (newmode == currmode)
		return (1);
	printf("%o\n", newmode);
	return (0);
}

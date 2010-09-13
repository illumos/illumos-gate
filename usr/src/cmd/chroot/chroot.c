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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	if (argc < 3) {
		(void) fprintf(stderr,
		    "usage: chroot rootdir command [arg ...]\n");
		exit(1);
	}

	if (chroot(argv[1]) != 0) {
		(void) fprintf(stderr, "chroot(\"%s\"): %s\n", argv[1],
		    strerror(errno));
		exit(1);
	}

	if (chdir("/") != 0) {
		(void) fprintf(stderr, "Can't chdir to new root\n");
		exit(1);
	}

	(void) execv(argv[2], &argv[2]);
	perror("chroot: exec failed");
	return (1);
}

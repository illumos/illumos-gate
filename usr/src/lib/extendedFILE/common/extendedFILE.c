/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	_FILE_FD_MAX 255

/*
 * This 32-bit only preloadable library enables extended fd FILE's.
 */

#pragma	init(init_STDIO_bad_fd)

void
init_STDIO_bad_fd(void)
{
	int action = -1;	/* default signal */
	int closed_fd = -1;	/* default fd */
	char *ptr;
	int signal;
	int retval;

	/*
	 * user specified badfd
	 */
	if ((ptr = getenv("_STDIO_BADFD")) != NULL) {
		closed_fd = atoi(ptr);
		if (closed_fd < 3 || closed_fd > _FILE_FD_MAX) {
			(void) fprintf(stderr, "File descriptor must be"
			    " in the range 3-%d inclusive.\n", _FILE_FD_MAX);
			exit(1);
		}
	}

	/*
	 * user specified action
	 */
	if ((ptr = getenv("_STDIO_BADFD_SIGNAL")) != NULL) {
		/* accept numbers or symbolic names */
		if (strncmp(ptr, "SIG", 3) == 0)	/* begins with "SIG"? */
			ptr = ptr + 3;
		retval = str2sig(ptr, &signal);
		if (retval == -1) {
			(void) fprintf(stderr,
			    "Invalid signal name or number.\n");
			exit(1);
		}
		action = signal;
	}

	if ((closed_fd = enable_extended_FILE_stdio(closed_fd, action)) == -1) {
		perror("enable_extended_FILE_stdio(3C)");
		exit(1);
	}
}

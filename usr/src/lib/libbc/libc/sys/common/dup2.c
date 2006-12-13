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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#define	OPEN_MAX	20		/* Taken from SVR4 limits.h */

int
dup2(
	int fildes,		/* file descriptor to be duplicated */
	int fildes2)		/* desired file descriptor */
{
	int	tmperrno;	/* local work area */
	int	open_max;	/* max open files */
	int	ret;		/* return value */
	int	fds;		/* duplicate files descriptor */

	if ((open_max = ulimit(4, 0)) < 0)
		open_max = OPEN_MAX;	/* take a guess */

	/* Be sure fildes is valid and open */
	if (fcntl(fildes, F_GETFL, 0) == -1) {
		errno = EBADF;
		return (-1);
	}

	/* Be sure fildes2 is in valid range */
	if (fildes2 < 0 || fildes2 >= open_max) {
		errno = EBADF;
		return (-1);
	}

	/* Check if file descriptors are equal */
	if (fildes == fildes2) {
		/* open and equal so no dup necessary */
		return (fildes2);
	}
	/* Close in case it was open for another file */
	/* Must save and restore errno in case file was not open */
	tmperrno = errno;
	close(fildes2);
	errno = tmperrno;

	/* Do the dup */
	if ((ret = fcntl(fildes, F_DUPFD, fildes2)) != -1) {
		if ((fds = fd_get(fildes)) != -1)
			fd_add(fildes2, fds);
	}
	return (ret);
}

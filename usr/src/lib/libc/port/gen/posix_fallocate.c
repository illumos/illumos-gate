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

#include "lint.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * Return the proper Posix error number for a failed (EINVAL) fcntl() operation.
 */
static int
fallocate_errno(int fd)
{
	struct stat64 statb;
	int error;

	if (fstat64(fd, &statb) != 0)		/* can't happen? */
		error = EBADF;
	else if (S_ISFIFO(statb.st_mode))	/* pipe or FIFO */
		error = ESPIPE;
	else if (!S_ISREG(statb.st_mode))	/* not a regular file */
		error = ENODEV;
	else			/* the file system doesn't support F_ALLOCSP */
		error = EINVAL;

	return (error);
}

int
posix_fallocate(int fd, off_t offset, off_t len)
{
	struct flock lck;
	int error;

	if (offset < 0 || len <= 0)
		return (EINVAL);

	lck.l_whence = 0;
	lck.l_start = offset;
	lck.l_len = len;
	lck.l_type = F_WRLCK;

	if (fcntl(fd, F_ALLOCSP, &lck) == -1) {
		if ((error = errno) == EINVAL)
			error = fallocate_errno(fd);
		else if (error == EOVERFLOW)
			error = EFBIG;
		return (error);
	}
	return (0);
}

#if !defined(_LP64)

int
posix_fallocate64(int fd, off64_t offset, off64_t len)
{
	struct flock64 lck;
	int error;

	if (offset < 0 || len <= 0)
		return (EINVAL);

	lck.l_whence = 0;
	lck.l_start = offset;
	lck.l_len = len;
	lck.l_type = F_WRLCK;

	if (fcntl(fd, F_ALLOCSP64, &lck) == -1) {
		if ((error = errno) == EINVAL)
			error = fallocate_errno(fd);
		else if (error == EOVERFLOW)
			error = EFBIG;
		return (error);
	}
	return (0);
}

#endif

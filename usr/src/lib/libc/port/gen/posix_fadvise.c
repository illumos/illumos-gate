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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * SUSv3 - file advisory information
 *
 * This function does nothing, but that's OK because the
 * Posix specification doesn't require it to do anything
 * other than return appropriate error numbers.
 *
 * In the future, a file system dependent fadvise() or fcntl()
 * interface, similar to madvise(), should be developed to enable
 * the kernel to optimize I/O operations based on the given advice.
 */

/* ARGSUSED1 */
int
posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	struct stat64 statb;

	switch (advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_WILLNEED:
	case POSIX_FADV_DONTNEED:
	case POSIX_FADV_NOREUSE:
		break;
	default:
		return (EINVAL);
	}
	if (len < 0)
		return (EINVAL);
	if (fstat64(fd, &statb) != 0)
		return (EBADF);
	if (S_ISFIFO(statb.st_mode))
		return (ESPIPE);
	return (0);
}

#if !defined(_LP64)

/* ARGSUSED1 */
int
posix_fadvise64(int fd, off64_t offset, off64_t len, int advice)
{
	struct stat64 statb;

	switch (advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_WILLNEED:
	case POSIX_FADV_DONTNEED:
	case POSIX_FADV_NOREUSE:
		break;
	default:
		return (EINVAL);
	}
	if (len < 0)
		return (EINVAL);
	if (fstat64(fd, &statb) != 0)
		return (EBADF);
	if (S_ISFIFO(statb.st_mode))
		return (ESPIPE);
	return (0);
}

#endif

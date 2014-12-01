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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/lx_types.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

/*
 * ZFS does not enforce the process.max-file-size rctl on a file which is
 * grown in size via truncate/ftruncate, since that is simply metadata which
 * does  not consume any additional space. However, LTP truncate03 depends on
 * this behavior so we enforce it here.
 */
static boolean_t
p_fsize_excd(const char *path, off_t length)
{
	struct stat64 sb;
	struct rlimit rl;

	if (stat64(path, &sb) == 0 && sb.st_size < length) {
		/* We are growing the file, check the rlimit */
		if (getrlimit(RLIMIT_FSIZE, &rl) == 0 && length > rl.rlim_cur)
			return (B_TRUE);
	}

	return (B_FALSE);
}

static boolean_t
f_fsize_excd(int fd, off_t length)
{
	struct stat64 sb;
	struct rlimit rl;

	if (fstat64(fd, &sb) == 0 && sb.st_size < length) {
		/* We are growing the file, check the rlimit */
		if (getrlimit(RLIMIT_FSIZE, &rl) == 0 && length > rl.rlim_cur)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * On Illumos, truncate() and ftruncate() are implemented in libc, so these are
 * layered on those interfaces.
 */

long
lx_truncate(uintptr_t path, uintptr_t length)
{
#if defined(_ILP32)
	if ((off_t)length >= 0xffffffffUL)
		return (-EFBIG);
#endif

	if (length > 0 && p_fsize_excd((const char *)path, (off_t)length))
		return (-EFBIG);

	return (truncate((const char *)path, (off_t)length) == 0 ? 0 : -errno);
}

long
lx_ftruncate(uintptr_t fd, uintptr_t length)
{
	int r;

#if defined(_ILP32)
	if ((off_t)length >= 0xffffffffUL)
		return (-EFBIG);
#endif

	if (length > 0 && f_fsize_excd((int)fd, (off_t)length))
		return (-EFBIG);

	r = ftruncate((int)fd, (off_t)length);
	/*
	 * On Linux, truncating a file opened read-only returns EINVAL whereas
	 * Illumos returns EBADF.
	 */
	if (r != 0) {
		if (errno == EBADF) {
			int mode;

			if ((mode = fcntl(fd, F_GETFL, 0)) != -1 &&
			    (mode & O_ACCMODE) == O_RDONLY)
				r = -EINVAL;
			else
				r = -EBADF; /* keep existing errno */
		} else {
			r = -errno;
		}
	}
	return (r);
}

long
lx_truncate64(uintptr_t path, uintptr_t length_lo, uintptr_t length_hi)
{
	uint64_t len = LX_32TO64(length_lo, length_hi);

	if (len >= 0x7fffffffffffffffULL)
		return (-EFBIG);

	if (len > 0 && p_fsize_excd((const char *)path, (off_t)len))
		return (-EFBIG);

	return (truncate64((const char *)path, len) == 0 ? 0 : -errno);
}

long
lx_ftruncate64(uintptr_t fd, uintptr_t length_lo, uintptr_t length_hi)
{
	int r;
	uint64_t len = LX_32TO64(length_lo, length_hi);

	if (len >= 0x7fffffffffffffffULL)
		return (-EFBIG);

	if (len > 0 && f_fsize_excd((int)fd, (off_t)len))
		return (-EFBIG);

	r = ftruncate64((int)fd, len);
	/*
	 * On Linux, truncating a file opened read-only returns EINVAL whereas
	 * Illumos returns EBADF.
	 */
	if (r != 0) {
		if (errno == EBADF) {
			int mode;

			if ((mode = fcntl(fd, F_GETFL, 0)) != -1 &&
			    (mode & O_ACCMODE) == O_RDONLY)
				r = -EINVAL;
			else
				r = -EBADF; /* keep existing errno */
		} else {
			r = -errno;
		}
	}

	return (r);
}

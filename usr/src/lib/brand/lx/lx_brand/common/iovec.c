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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <alloca.h>
#include <string.h>
#include <sys/lx_syscall.h>
#include <sys/lx_misc.h>
#include <sys/lx_types.h>

static int
lx_is_directory(int fd)
{
	struct stat64 sbuf;

	if (fstat64(fd, &sbuf) < 0)
		sbuf.st_mode = 0;

	return ((sbuf.st_mode & S_IFMT) == S_IFDIR);
}

#if defined(_LP64)
long
lx_pread(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int 		fd = (int)p1;
	void		*buf = (void *)p2;
	size_t		nbyte = (size_t)p3;
	off64_t		off = (off64_t)p4;
	ssize_t		ret;

	if (lx_is_directory(fd))
		return (-EISDIR);

	ret = pread64(fd, buf, nbyte, off);

	if (ret < 0)
		return (-errno);

	return (ret);
}

/*
 * On Linux, the pwrite(2) system call behaves identically to Solaris except
 * in the case of the file being opened with O_APPEND. In that case Linux's
 * pwrite(2) ignores the offset parameter and instead appends the data to the
 * file without modifying the current seek pointer.
 */
long
lx_pwrite(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int fd = (int)p1;
	void *buf = (void *)p2;
	size_t nbyte = (size_t)p3;
	off64_t off = (off64_t)p4;
	ssize_t ret;
	int rval;
	struct stat64 statbuf;

	if ((rval = fcntl(fd, F_GETFL, 0)) < 0)
		return (-errno);

	if (!(rval & O_APPEND)) {
		ret = pwrite64(fd, buf, nbyte, off);
	} else if ((ret = fstat64(fd, &statbuf)) == 0) {
		ret = pwrite64(fd, buf, nbyte, statbuf.st_size);
	}

	if (ret < 0)
		return (-errno);

	return (ret);
}

#else /* 32 bit */

long
lx_pread64(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5)
{
	int 		fd = (int)p1;
	void		*buf = (void *)p2;
	size_t		nbyte = (size_t)p3;
	uintptr_t	off_lo = p4;
	uintptr_t	off_hi = p5;
	ssize_t		ret;

	if (lx_is_directory(fd))
		return (-EISDIR);

	ret = pread64(fd, buf, nbyte, (off64_t)LX_32TO64(off_lo, off_hi));

	if (ret < 0)
		return (-errno);

	return (ret);
}

/*
 * On Linux, the pwrite(2) system call behaves identically to Solaris except
 * in the case of the file being opened with O_APPEND. In that case Linux's
 * pwrite(2) ignores the offset parameter and instead appends the data to the
 * file without modifying the current seek pointer.
 */
long
lx_pwrite64(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
    uintptr_t p5)
{
	int fd = (int)p1;
	void *buf = (void *)p2;
	size_t nbyte = (size_t)p3;
	uintptr_t off_lo = p4;
	uintptr_t off_hi = p5;
	ssize_t ret;
	int rval;
	struct stat64 statbuf;

	if ((rval = fcntl(fd, F_GETFL, 0)) < 0)
		return (-errno);

	if (!(rval & O_APPEND)) {
		ret = pwrite64(fd, buf, nbyte,
		    (off64_t)LX_32TO64(off_lo, off_hi));
	} else if ((ret = fstat64(fd, &statbuf)) == 0) {
		ret = pwrite64(fd, buf, nbyte, statbuf.st_size);
	}

	if (ret < 0)
		return (-errno);

	return (ret);
}
#endif

long
lx_preadv(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int 		fd = (int)p1;
	const struct iovec *iovp = (const struct iovec *)p2;
	int		cnt = (int)p3;
	off_t		off = (off_t)p4;
	ssize_t		ret;

	ret = preadv(fd, iovp, cnt, off);
	return (ret < 0 ? -errno : ret);
}

long
lx_pwritev(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int 		fd = (int)p1;
	const struct iovec *iovp = (const struct iovec *)p2;
	int		cnt = (int)p3;
	off_t		off = (off_t)p4;
	ssize_t		ret;

	ret = pwritev(fd, iovp, cnt, off);
	return (ret < 0 ? -errno : ret);
}

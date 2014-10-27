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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
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

long
lx_read(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int 		fd = (int)p1;
	void		*buf = (void *)p2;
	size_t		nbyte = (size_t)p3;
	ssize_t		ret;

	if (lx_is_directory(fd))
		return (-EISDIR);

	if ((ret = read(fd, buf, nbyte)) < 0)
		return (-errno);

	return (ret);
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

/*
 * Implementation of Linux readv() and writev() system calls.
 *
 * The Linux system calls differ from the Solaris system calls in a few key
 * areas:
 *
 * - On Solaris, the maximum number of I/O vectors that can be passed to readv()
 *   or writev() is IOV_MAX (16).  Linux has a much larger restriction (1024).
 *
 * - Passing 0 as a vector count is an error on Solaris, but on Linux results
 *   in a return value of 0. Even though the man page says the opposite.
 *
 * - If the Nth vector results in an error, Solaris will return an error code
 *   for the entire operation.  Linux only returns an error if there has been
 *   no data transferred yet.  Otherwise, it returns the number of bytes
 *   transferred up until that point.
 *
 * In order to accomodate these differences, we implement these functions as a
 * series of ordinary read() or write() calls.
 */

#define	LX_IOV_MAX 1024		/* Also called MAX_IOVEC */

static int
lx_iovec_copy_and_check(const struct iovec *iovp, struct iovec *iov, int count)
{
#if defined(_ILP32)
	int	i;
	ssize_t	cnt = 0;
#endif

	if (uucopy(iovp, (void *)iov, count * sizeof (struct iovec)) != 0)
		return (-errno);

#if defined(_ILP32)
	for (i = 0; i < count; i++) {
		cnt += iov[i].iov_len;
		if (iov[i].iov_len < 0 || cnt < 0)
			return (-EINVAL);
	}
#endif

	return (0);
}

long
lx_readv(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int			fd = (int)p1;
	const struct iovec	*iovp = (const struct iovec *)p2;
	int			count = (int)p3;
	struct iovec		*iov;
	ssize_t			total = 0, ret;
	int			i;

	if (count == 0)
		return (0);

	if (count < 0 || count > LX_IOV_MAX)
		return (-EINVAL);

	if (lx_is_directory(fd))
		return (-EISDIR);

	iov = SAFE_ALLOCA(count * sizeof (struct iovec));
	if (iov == NULL)
		return (-ENOMEM);
	if ((ret = lx_iovec_copy_and_check(iovp, iov, count)) != 0)
		return (ret);

	for (i = 0; i < count; i++) {
		ret = read(fd, iov[i].iov_base, iov[i].iov_len);

		if (ret < 0) {
			if (total > 0)
				return (total);
			return (-errno);
		}

		total += ret;
	}

	return (total);
}

long
lx_writev(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int			fd = (int)p1;
	const struct iovec	*iovp = (const struct iovec *)p2;
	int			count = (int)p3;
	struct iovec		*iov;
	ssize_t			total = 0, ret;
	int			i;

	if (count == 0)
		return (0);

	if (count < 0 || count > LX_IOV_MAX)
		return (-EINVAL);

	iov = SAFE_ALLOCA(count * sizeof (struct iovec));
	if (iov == NULL)
		return (-ENOMEM);
	if ((ret = lx_iovec_copy_and_check(iovp, iov, count)) != 0)
		return (ret);

	for (i = 0; i < count; i++) {
		ret = write(fd, iov[i].iov_base, iov[i].iov_len);

		if (ret < 0) {
			if (total > 0)
				return (total);
			return (-errno);
		}

		total += ret;
	}

	return (total);
}

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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libintl.h>
#include <stdio.h>

#include <sys/lx_types.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>

static int
ltos_open_flags(uintptr_t p2)
{
	int flags;

	if ((p2 & O_ACCMODE) == LX_O_RDONLY)
		flags = O_RDONLY;
	else if ((p2 & O_ACCMODE) == LX_O_WRONLY)
		flags = O_WRONLY;
	else
		flags = O_RDWR;

	if (p2 & LX_O_CREAT) {
		flags |= O_CREAT;
	}

	if (p2 & LX_O_EXCL)
		flags |= O_EXCL;
	if (p2 & LX_O_NOCTTY)
		flags |= O_NOCTTY;
	if (p2 & LX_O_TRUNC)
		flags |= O_TRUNC;
	if (p2 & LX_O_APPEND)
		flags |= O_APPEND;
	if (p2 & LX_O_NONBLOCK)
		flags |= O_NONBLOCK;
	if (p2 & LX_O_SYNC)
		flags |= O_SYNC;
	if (p2 & LX_O_LARGEFILE)
		flags |= O_LARGEFILE;
	if (p2 & LX_O_NOFOLLOW)
		flags |= O_NOFOLLOW;
	if (p2 & LX_O_CLOEXEC)
		flags |= O_CLOEXEC;

	/*
	 * Linux uses the LX_O_DIRECT flag to do raw, synchronous I/O to the
	 * device backing the fd in question.  Solaris doesn't have similar
	 * functionality, but we can attempt to simulate it using the flags
	 * (O_RSYNC|O_SYNC) and directio(3C).
	 *
	 * The LX_O_DIRECT flag also requires that the transfer size and
	 * alignment of I/O buffers be a multiple of the logical block size for
	 * the underlying file system, but frankly there isn't an easy way to
	 * support that functionality without doing something like adding an
	 * fcntl(2) flag to denote LX_O_DIRECT mode.
	 *
	 * Since LX_O_DIRECT is merely a performance advisory, we'll just
	 * emulate what we can and trust that the only applications expecting
	 * an error when performing I/O from a misaligned buffer or when
	 * passing a transfer size is not a multiple of the underlying file
	 * system block size will be test suites.
	 */
	if (p2 & LX_O_DIRECT)
		flags |= (O_RSYNC|O_SYNC);

	return (flags);
}

static int
lx_open_postprocess(int fd, uintptr_t p2)
{
	struct stat64 statbuf;

	/*
	 * Check the file type AFTER opening the file to avoid a race condition
	 * where the file we want to open could change types between a stat64()
	 * and an open().
	 */
	if (p2 & LX_O_DIRECTORY) {
		if (fstat64(fd, &statbuf) < 0) {
			int ret = -errno;

			(void) close(fd);
			return (ret);
		} else if (!S_ISDIR(statbuf.st_mode)) {
			(void) close(fd);
			return (-ENOTDIR);
		}
	}

	if (p2 & LX_O_DIRECT)
		(void) directio(fd, DIRECTIO_ON);

	/*
	 * Set the ASYNC flag if passsed.
	 */
	if (p2 & LX_O_ASYNC) {
		if (fcntl(fd, F_SETFL, FASYNC) < 0) {
			int ret = -errno;

			(void) close(fd);
			return (ret);
		}
	}

	return (fd);
}

long
lx_openat(uintptr_t ext1, uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int atfd = (int)ext1;
	int flags, fd;
	mode_t mode = 0;
	char *path = (char *)p1;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	flags = ltos_open_flags(p2);

	if (flags & O_CREAT) {
		mode = (mode_t)p3;
	}

	lx_debug("\topenat(%d, %s, 0%o, 0%o)", atfd, path, flags, mode);

	if ((fd = openat(atfd, path, flags, mode)) < 0)
		return (-errno);

	return (lx_open_postprocess(fd, p2));
}

long
lx_open(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int flags, fd;
	mode_t mode = 0;
	char *path = (char *)p1;

	flags = ltos_open_flags(p2);

	if (flags & O_CREAT) {
		mode = (mode_t)p3;
	}

	lx_debug("\topen(%s, 0%o, 0%o)", path, flags, mode);

	if ((fd = open(path, flags, mode)) < 0)
		return (-errno);

	return (lx_open_postprocess(fd, p2));
}

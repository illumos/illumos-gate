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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fdopendir, dirfd -- C library extension routines
 *
 * We use lmalloc()/lfree() rather than malloc()/free() in
 * order to allow opendir()/readdir()/closedir() to be called
 * while holding internal libc locks.
 */

#pragma weak fdopendir = _fdopendir
#pragma weak dirfd = _dirfd

#include "synonyms.h"
#include <mtlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "libc.h"

extern int __fcntl(int fd, int cmd, intptr_t arg);

DIR *
fdopendir(int fd)
{
	private_DIR *pdirp = lmalloc(sizeof (*pdirp));
	DIR *dirp = (DIR *)pdirp;
	void *buf = lmalloc(DIRBUF);
	int error = 0;
	struct stat64 sbuf;

	if (pdirp == NULL || buf == NULL)
		goto fail;
	/*
	 * POSIX mandated behavior
	 * close on exec if using file descriptor
	 */
	if (__fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		goto fail;
	if (fstat64(fd, &sbuf) < 0)
		goto fail;
	if ((sbuf.st_mode & S_IFMT) != S_IFDIR) {
		error = ENOTDIR;
		goto fail;
	}
	dirp->dd_buf = buf;
	dirp->dd_fd = fd;
	dirp->dd_loc = 0;
	dirp->dd_size = 0;
	(void) mutex_init(&pdirp->dd_lock, USYNC_THREAD, NULL);
	return (dirp);

fail:
	if (pdirp != NULL)
		lfree(pdirp, sizeof (*pdirp));
	if (buf != NULL)
		lfree(buf, DIRBUF);
	if (error)
		errno = error;
	return (NULL);
}

int
dirfd(DIR *dirp)
{
	return (dirp->dd_fd);
}

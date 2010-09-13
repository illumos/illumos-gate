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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include <sys/param.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

/*
 * open a directory.
 */
DIR *
opendir(name)
	char *name;
{
	register DIR *dirp;
	register int fd;
	struct stat sb;
	extern int errno;
	extern char *malloc();
	extern int open(), close(), fstat();

	if ((fd = open(name, O_RDONLY | O_NDELAY)) == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1) {
		(void) close(fd);
		return (NULL);
	}
	if ((sb.st_mode & S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		(void) close(fd);
		return (NULL);
	}
	if (((dirp = (DIR *)malloc(sizeof(DIR))) == NULL) ||
	    ((dirp->dd_buf = malloc(sb.st_blksize)) == NULL)) {
		if (dirp)
			free(dirp);
		(void) close(fd);
		return (NULL);
	}
	dirp->dd_fd = fd;
	dirp->dd_loc = 0;
	dirp->dd_size = 0;
	dirp->dd_bsize = sb.st_blksize;
	dirp->dd_off = 0;
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	return (dirp);
}

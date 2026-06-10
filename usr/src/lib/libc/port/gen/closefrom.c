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
 * Copyright 2023 Bill Sommerfeld <sommerfeld@alum.mit.edu>
 * Copyright 2026 Oxide Computer Company
 */

#pragma weak _closefrom = closefrom
#pragma weak _fdwalk = fdwalk

#include "lint.h"
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <alloca.h>
#include <sys/resource.h>

/* Initial size of the open file descriptor array */
#define	FDS_SZ	(1024 * sizeof (int))

/*
 * Iterate over all open file descriptors, calling 'func' on each one.
 * Terminate the iteration when 'func' returns non-zero or when all
 * open file descriptors have been processed.  Return the value of
 * the last non-zero return from 'func' or zero.
 */
int
fdwalk(int (*func)(void *, int), void *cd)
{
	int err = errno;
	int rv = 0;
	int max_fds = INT_MAX;
	struct rlimit rl;
	DIR *dirp;
	struct dirent64 *dp;
	int *fds;
	size_t fds_sz;
	int nfds;
	int i;

	nfds = 0;
	fds = alloca(FDS_SZ);
	fds_sz = FDS_SZ;
	if ((dirp = opendir("/proc/self/fd")) != NULL) {
		/*
		 * Collect all of the open file descriptors and close
		 * the directory before calling 'func' on any of them.
		 */
		while ((dp = readdir64(dirp)) != NULL) {
			/* skip '.', '..' and the opendir() fd */
			if (!isdigit(dp->d_name[0]) ||
			    (i = atoi(dp->d_name)) == dirp->dd_fd)
				continue;
			if (fds_sz <= nfds * sizeof (int)) {
				fds = memcpy(alloca(fds_sz * 2), fds, fds_sz);
				fds_sz *= 2;
			}
			fds[nfds++] = i;
		}
		(void) closedir(dirp);
	} else {
		/*
		 * We could not open the /proc file descriptor directory.
		 * We have to do it the hard way.
		 */
		if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
			max_fds = (rl.rlim_max == RLIM_INFINITY)?
			    INT_MAX : rl.rlim_max;
		for (i = 0; i < max_fds; i++) {
			if (fcntl(i, F_GETFD) < 0)
				continue;
			if (fds_sz <= nfds * sizeof (int)) {
				fds = memcpy(alloca(fds_sz * 2), fds, fds_sz);
				fds_sz *= 2;
			}
			fds[nfds++] = i;
		}
	}

	/*
	 * Restore the original value of errno so that
	 * the caller sees only the value of errno set
	 * by the callback function.
	 */
	errno = err;

	/*
	 * Perform the callbacks on all of the open files.
	 */
	for (i = 0; i < nfds; i++)
		if ((rv = func(cd, fds[i])) != 0)
			break;

	return (rv);
}

/*
 * Close all open file descriptors greater than or equal to lowfd.
 * close_range() takes care of cancelling any outstanding asynchronous
 * I/O against the descriptors before they are closed.
 */
void
closefrom(int lowfd)
{
	int low = (lowfd < 0) ? 0 : lowfd;

	(void) close_range((unsigned int)low, UINT_MAX, 0);
}

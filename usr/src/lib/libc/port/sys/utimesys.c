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
 */

/*
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#include "lint.h"
#include <string.h>
#include <utime.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>

int
futimens(int fd, const timespec_t times[2])
{
	return (syscall(SYS_utimesys, 0, fd, times));
}

int
utimensat(int fd, const char *path, const timespec_t times[2], int flag)
{
	return (syscall(SYS_utimesys, 1, fd, path, times, flag));
}

#pragma weak _utime = utime
int
utime(const char *path, const struct utimbuf *times)
{
	struct utimbuf ltimes;
	timespec_t ts[2];
	timespec_t *tsp;

	if (times == NULL) {
		tsp = NULL;
	} else {
		/* use uucopy() to behave like a system call */
		if (uucopy(times, &ltimes, sizeof (ltimes)) != 0)
			return (-1);	/* uucopy() set errno to EFAULT */
		ts[0].tv_sec = ltimes.actime;
		ts[0].tv_nsec = 0;
		ts[1].tv_sec = ltimes.modtime;
		ts[1].tv_nsec = 0;
		tsp = ts;
	}
	return (utimensat(AT_FDCWD, path, tsp, 0));
}

static int
utimes_impl(const char *path, const struct timeval times[2], int flag)
{
	struct timeval ltimes[2];
	timespec_t ts[2];
	timespec_t *tsp;

	if (times == NULL) {
		tsp = NULL;
	} else {
		/* use uucopy() to behave like a system call */
		if (uucopy(times, ltimes, sizeof (ltimes)) != 0)
			return (-1);	/* uucopy() set errno to EFAULT */
		ts[0].tv_sec = ltimes[0].tv_sec;
		ts[0].tv_nsec = ltimes[0].tv_usec * 1000;
		ts[1].tv_sec = ltimes[1].tv_sec;
		ts[1].tv_nsec = ltimes[1].tv_usec * 1000;
		tsp = ts;
	}
	return (utimensat(AT_FDCWD, path, tsp, flag));
}

int
utimes(const char *path, const struct timeval *times)
{
	return (utimes_impl(path, times, 0));
}

int
lutimes(const char *path, const struct timeval *times)
{
	return (utimes_impl(path, times, AT_SYMLINK_NOFOLLOW));
}

#pragma weak _futimesat = futimesat
int
futimesat(int fd, const char *path, const struct timeval *times)
{
	struct timeval ltimes[2];
	timespec_t ts[2];
	timespec_t *tsp;

	if (times == NULL) {
		tsp = NULL;
	} else {
		/* use uucopy() to behave like a system call */
		if (uucopy(times, ltimes, sizeof (ltimes)) != 0)
			return (-1);	/* uucopy() set errno to EFAULT */
		ts[0].tv_sec = ltimes[0].tv_sec;
		ts[0].tv_nsec = ltimes[0].tv_usec * 1000;
		ts[1].tv_sec = ltimes[1].tv_sec;
		ts[1].tv_nsec = ltimes[1].tv_usec * 1000;
		tsp = ts;
	}

	if (path == NULL)
		return (futimens(fd, tsp));

	return (utimensat(fd, path, tsp, 0));
}

int
futimes(int fd, const struct timeval *times)
{
	return (futimesat(fd, NULL, times));
}

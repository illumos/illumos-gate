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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <wait.h>
#include <fcntl.h>
#include <thread.h>
#include <unistd.h>
#include <errno.h>
#include <ucontext.h>
#include <syslog.h>
#include <rpcsvc/daemon_utils.h>

static int open_daemon_lock(const char *, int);

/*
 * Use an advisory lock to ensure that only one daemon process is
 * active in the system at any point in time. If the lock is held
 * by another process, do not block but return the pid owner of
 * the lock to the caller immediately. The lock is cleared if the
 * holding daemon process exits for any reason even if the lock
 * file remains, so the daemon can be restarted if necessary.
 */

/*
 * check if another process is holding lock on the lock file.
 *
 * return: 0 if file is not locked, else,
 *	   1 if file is locked by another process, else,
 *	   -1 on any error.
 */
int
_check_daemon_lock(const char *name)
{
	int		fd, err;
	struct flock	lock;

	if ((fd = open_daemon_lock(name, O_RDONLY)) == -1) {
		if (errno == ENOENT)
			return (0);
		return (-1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = (off_t)0;
	lock.l_len = (off_t)0;

	err = fcntl(fd, F_GETLK, &lock);
	(void) close(fd);

	if (err == -1)
		return (-1);

	return ((lock.l_type == F_UNLCK) ? 0 : 1);
}

static int
open_daemon_lock(const char *name, int mode)
{
	char		lock_file[MAXPATHLEN], buf[MAXPATHLEN];
	int		fd;
	char		*p;

	/*
	 * Our args look like this:
	 *   svc:/network/nfs/status:default
	 * We want to create a lock file named like this:
	 *   /etc/svc/volatile/nfs-status.lock
	 * i.e., we want the last two path components in the name.
	 */
	(void) strncpy(buf, name, MAXPATHLEN);

	/* First, strip off ":<instance>", if present. */
	p = strrchr(buf, ':');
	if (p != NULL)
		*p = '\0';

	/* Next, find final '/' and replace it with a dash */
	p = strrchr(buf, '/');
	if (p == NULL)
		p = buf;
	else {
		*p = '-';
		/* Now find the start of what we want our name to be */
		p = strrchr(buf, '/');
		if (p == NULL)
			p = buf;
		else
			p++;
	}

	(void) snprintf(lock_file, MAXPATHLEN, "/etc/svc/volatile/%s.lock", p);

	if ((fd = open(lock_file, mode, 0644)) == -1)
		return (-1);

	if (mode & O_CREAT)
		(void) fchmod(fd, 0644);

	return (fd);
}
/*
 * lock the file, write caller's pid to the lock file
 * return: 0 if caller can establish lock, else,
 *	   pid of the current lock holder, else,
 *	   -1 on any printable error.
 */
pid_t
_enter_daemon_lock(const char *name)
{
	int		fd;
	pid_t		pid;
	char		line[BUFSIZ];
	struct flock	lock;

	pid = getpid();
	(void) snprintf(line, sizeof (line), "%ld\n", pid);

	if ((fd = open_daemon_lock(name, O_RDWR|O_CREAT)) == -1)
		return ((pid_t)-1);

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = (off_t)0;
	lock.l_len = (off_t)0;

	if (fcntl(fd, F_SETLK, &lock) == -1) {
		if (fcntl(fd, F_GETLK, &lock) == -1) {
			(void) close(fd);
			return ((pid_t)-1);
		}
		(void) close(fd);
		return (lock.l_pid);
	}

	if (write(fd, line, strlen(line)) == -1) {
		(void) close(fd);
		return ((pid_t)-1);
	}

	return ((pid_t)0);
}

int
_create_daemon_lock(const char *name, uid_t uid, gid_t gid)
{
	int fd = open_daemon_lock(name, O_CREAT);
	int ret;

	if (fd < 0)
		return (-1);

	ret = fchown(fd, uid, gid);
	(void) close(fd);

	return (ret);
}

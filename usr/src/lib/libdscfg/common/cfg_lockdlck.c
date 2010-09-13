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

#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>

#include "cfg_impl.h"
#include "cfg_lockd.h"


#define	segment_off(s)	((off_t)(s) * sizeof (pid_t))

static int local_lockfd;
static int local_lockfda;

void
cfg_lfinit()
{
	local_lockfd = open(CFG_RDEV_LOCKFILE, O_RDWR|O_CREAT, 0644);
	local_lockfda = open(CFG_RDEV_LOCKFILE, O_RDWR|O_APPEND, 0644);
}

int
cfg_filelock(int segment, int flag)
{
	struct flock lk;
	struct stat sb;
	pid_t pid = 0;
	off_t off = segment_off(segment);
	int rc;

	while (fstat(local_lockfd, &sb) == -1 && errno == EINTR)
		;
	if (sb.st_size < off + sizeof (pid_t)) {
		if ((flag&O_CREAT) == 0)
			return (CFG_LF_EOF);
		write(local_lockfda, &pid, sizeof (pid_t));
	}
	bzero(&lk, sizeof (lk));
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = off;
	lk.l_len = (off_t)sizeof (pid_t);

	while ((rc = fcntl(local_lockfd, F_SETLK, &lk)) < 0 && errno == EINTR)
		;
	if (rc == -1 && errno == EAGAIN)
		return (CFG_LF_AGAIN);

	return (CFG_LF_OKAY);
}


int
cfg_fileunlock(int segment)
{
	struct flock lk;
	off_t off = segment_off(segment);

	bzero(&lk, sizeof (lk));
	lk.l_type = F_UNLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = off;
	lk.l_len = (off_t)sizeof (pid_t);

	while (fcntl(local_lockfd, F_SETLK, &lk) < 0 && errno == EINTR)
		;
	return (1);
}

void
cfg_readpid(int segment, pid_t *pidp)
{
	off_t	off  = segment_off(segment);
	lseek(local_lockfd, off, SEEK_SET);
	read(local_lockfd, pidp, sizeof (pid_t));
}

void
cfg_writepid(int segment, pid_t pid)
{
	off_t	off  = segment_off(segment);
	lseek(local_lockfd, off, SEEK_SET);
	write(local_lockfd, &pid, sizeof (pid_t));
}

void
cfg_enterpid()
{
	int i;
	pid_t	pid;

	for (i = 0; ; i++) {
		if (cfg_filelock(i, O_CREAT) == CFG_LF_OKAY) {
			cfg_readpid(i, &pid);
			if (pid != (pid_t)0) {
				cfg_fileunlock(i);
				continue;
			}
			pid = getpid();
			cfg_writepid(i, pid);
			break;
		}
	}
}

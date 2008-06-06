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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/types.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <shadow.h>
#include <errno.h>
#include <thread.h>
#include "mtlib.h"

#define	LOCKFILE	"/etc/.pwd.lock"
#define	S_WAITTIME	15

static struct flock flock =	{
			0,	/* l_type */
			0,	/* l_whence */
			0,	/* l_start */
			0,	/* l_len */
			0,	/* l_sysid */
			0	/* l_pid */
			};

/*
 * lckpwdf() returns a 0 for a successful lock within W_WAITTIME
 * seconds and -1 otherwise.  We stand on our head to make it MT-safe.
 */

static pid_t lck_pid = 0;	/* process's pid at last lock */
static thread_t lck_tid = 0;	/* thread that holds the lock */
static int fildes = -1;
static mutex_t lck_lock = DEFAULTMUTEX;

int
lckpwdf(void)
{
	int seconds = 0;

	lmutex_lock(&lck_lock);
	for (;;) {
		if (lck_pid != 0 && lck_pid != getpid()) {
			/* somebody forked */
			lck_pid = 0;
			lck_tid = 0;
		}
		if (lck_tid == 0) {
			if ((fildes = creat(LOCKFILE, 0600)) == -1)
				break;
			flock.l_type = F_WRLCK;
			if (fcntl(fildes, F_SETLK, &flock) != -1) {
				lck_pid = getpid();
				lck_tid = thr_self();
				lmutex_unlock(&lck_lock);
				return (0);
			}
			(void) close(fildes);
			fildes = -1;
		}
		if (seconds++ >= S_WAITTIME) {
			/*
			 * For compatibility with the past, pretend
			 * that we were interrupted by SIGALRM.
			 */
			errno = EINTR;
			break;
		}
		lmutex_unlock(&lck_lock);
		(void) sleep(1);
		lmutex_lock(&lck_lock);
	}
	lmutex_unlock(&lck_lock);
	return (-1);
}

/*
 * ulckpwdf() returns 0 for a successful unlock and -1 otherwise
 */
int
ulckpwdf(void)
{
	lmutex_lock(&lck_lock);
	if (lck_tid == thr_self() && fildes >= 0) {
		flock.l_type = F_UNLCK;
		(void) fcntl(fildes, F_SETLK, &flock);
		(void) close(fildes);
		fildes = -1;
		lck_pid = 0;
		lck_tid = 0;
		lmutex_unlock(&lck_lock);
		return (0);
	}
	lmutex_unlock(&lck_lock);
	return (-1);
}

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
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h> /* alarm() */

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
 *	yplckpwdf() returns a 0 for a successful lock within W_WAITTIME
 *	and -1 otherwise
 */

static int fildes = -1;
extern char lockfile[];

/* ARGSUSED */
static void
almhdlr(int sig)
{
}

int
yplckpwdf()
{
	int retval;
	if ((fildes = creat(lockfile, 0600)) == -1)
		return (-1);

	flock.l_type = F_WRLCK;
	(void) sigset(SIGALRM, almhdlr);
	(void) alarm(S_WAITTIME);
	retval = fcntl(fildes, F_SETLKW, (int)&flock);
	(void) alarm(0);
	(void) sigset(SIGALRM, SIG_DFL);
	return (retval);

}

/*
 *	ypulckpwdf() returns 0 for a successful unlock and -1 otherwise
 */
int
ypulckpwdf()
{
	if (fildes == -1)
		return (-1);

	flock.l_type = F_UNLCK;
	(void) fcntl(fildes, F_SETLK, (int)&flock);
	(void) close(fildes);
	fildes = -1;
	return (0);

}

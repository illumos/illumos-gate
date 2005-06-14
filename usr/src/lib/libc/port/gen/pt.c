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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma weak ptsname = _ptsname
#pragma weak grantpt = _grantpt
#pragma weak unlockpt = _unlockpt
#pragma weak posix_openpt = _posix_openpt

#include "synonyms.h"
#include <mtlib.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/mkdev.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ptms.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <wait.h>
#include <synch.h>
#include <thread.h>
#include <spawn.h>
#include <libc.h>
#include "tsd.h"

#define	PTSNAME "/dev/pts/"		/* slave name */
#define	PTLEN   32			/* slave name length */
#define	PTPATH  "/usr/lib/pt_chmod"    	/* setuid root program */
#define	PTPGM   "pt_chmod"		/* setuid root program */

static void itoa(int, char *);
static int grantpt_u(int, int);

/*
 *  Check that fd argument is a file descriptor of an opened master.
 *  Do this by sending an ISPTM ioctl message down stream. Ioctl()
 *  will fail if:(1) fd is not a valid file descriptor.(2) the file
 *  represented by fd does not understand ISPTM(not a master device).
 *  If we have a valid master, get its minor number via fstat().
 *  Concatenate it to PTSNAME and return it as the name of the slave
 *  device.
 */
static dev_t
ptsdev(int fd)
{
	struct stat64 status;
	struct strioctl istr;

	istr.ic_cmd = ISPTM;
	istr.ic_len = 0;
	istr.ic_timout = 0;
	istr.ic_dp = NULL;

	if (ioctl(fd, I_STR, &istr) < 0 || fstat64(fd, &status) < 0)
		return (NODEV);

	return (minor(status.st_rdev));
}

static int
ptscreate(void)
{
	static mutex_t clk = DEFAULTMUTEX;
	int ret;

	lmutex_lock(&clk);
	ret = grantpt_u(-1, 1);
	lmutex_unlock(&clk);
	return (ret);
}

char *
ptsname(int fd)
{
	dev_t dev;
	char *sname;

	if ((dev = ptsdev(fd)) == NODEV)
		return (NULL);

	sname = tsdalloc(_T_PTSNAME, PTLEN, NULL);
	if (sname == NULL)
		return (NULL);
	(void) strcpy(sname, PTSNAME);
	itoa(dev, sname + strlen(PTSNAME));

	/*
	 * devfsadm synchronization: if the node does not exist,
	 * attempt to synchronize with slave device node creation.
	 */
	if (access(sname, F_OK) ==  0 ||
	    (ptscreate() == 0 && access(sname, F_OK) == 0))
		return (sname);
	return (NULL);
}

/*
 * Send an ioctl down to the master device requesting the
 * master/slave pair be unlocked.
 */
int
unlockpt(int fd)
{
	struct strioctl istr;

	istr.ic_cmd = UNLKPT;
	istr.ic_len = 0;
	istr.ic_timout = 0;
	istr.ic_dp = NULL;

	if (ioctl(fd, I_STR, &istr) < 0)
		return (-1);

	return (0);
}


/*
 * Execute a setuid root program to change the mode, ownership and
 * group of the slave device. The parent forks a child process that
 * executes the setuid program. It then waits for the child to return.
 *
 * When create is 1, execute the setuid root program without arguments,
 * to create minor nodes and symlinks for all slave devices.
 */
static int
grantpt_u(int fd, int create)
{
	extern char **environ;
	char *argvec[3];
	int	st_loc;
	pid_t	pid;
	int	w;
	char	fds[24];
	sigset_t oset, nset;
	int	error;

	/* validate the file descriptor before proceeding */
	if (create != 1 && ptsdev(fd) == NODEV)
		return (-1);

	if (sigemptyset(&nset) == -1)
		return (-1);
	if (sigaddset(&nset, SIGCHLD) == -1)
		return (-1);
	if (sigprocmask(SIG_BLOCK, &nset, &oset) == -1)
		return (-1);

	itoa(fd, fds);
	argvec[0] = PTPGM;
	argvec[1] = create == 1 ? NULL : fds;
	argvec[2] = NULL;
	error = posix_spawn(&pid, PTPATH, NULL, NULL, argvec, environ);
	if (error) {
		(void) sigprocmask(SIG_SETMASK, &oset, NULL);
		errno = error;
		return (-1);
	}

	/*
	 * waitpid() returns the process id for the child process
	 * on success or -1 on failure.
	 */
	while ((w = waitpid(pid, &st_loc, 0)) < 0 && errno == EINTR)
		continue;

	/* Restore signal mask */
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);

	/*
	 * If SIGCHLD is currently ignored, waitpid() fails with
	 * ECHILD after the child terminates.
	 * This is not a failure; assume the child succeded.
	 */
	if (w == -1) {
		if (errno != ECHILD)
			return (-1);
		st_loc = 0;
	}

	/*
	 * If child terminated due to exit() and the exit status is zero
	 *	return success
	 * else it was an exit(-1) or it was struck by a signal
	 *	return failure (EACCES)
	 */
	if (WIFEXITED(st_loc) && WEXITSTATUS(st_loc) == 0)
		return (0);
	errno = EACCES;
	return (-1);
}

int
grantpt(int fd)
{
	static mutex_t glk = DEFAULTMUTEX;
	int ret;

	lmutex_lock(&glk);
	ret = grantpt_u(fd, 0);
	lmutex_unlock(&glk);
	return (ret);
}

/*
 * Send an ioctl down to the master device requesting the master/slave pair
 * be assigned to the given zone.
 */
int
zonept(int fd, zoneid_t zoneid)
{
	struct strioctl istr;

	istr.ic_cmd = ZONEPT;
	istr.ic_len = sizeof (zoneid);
	istr.ic_timout = 0;
	istr.ic_dp = (char *)&zoneid;

	if (ioctl(fd, I_STR, &istr) != 0) {
		return (-1);
	}
	return (0);
}


static void
itoa(int i, char *ptr)
{
	int dig = 0;
	int tempi;

	tempi = i;
	do {
		dig++;
		tempi /= 10;
	} while (tempi);

	ptr += dig;
	*ptr = '\0';
	while (--dig >= 0) {
		*(--ptr) = i % 10 + '0';
		i /= 10;
	}
}


/*
 * added for SUSv3 standard
 *
 * Open a pseudo-terminal device.  External interface.
 */

int
posix_openpt(int oflag)
{
	return (open("/dev/ptmx", oflag));
}

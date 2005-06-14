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
 *
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef lint
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#endif  lint

#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<string.h>
#include	<dirent.h>
#include	<rmmount.h>
#include	<signal.h>

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
#include	<sys/vtoc.h>
#include	<sys/param.h>
#include	<sys/ioccom.h>

/*
 * Do good stuff for wabi.
 */


/*
 * volmgt related ioctls. common for wabi and sunpc
 */

#define VOLMGT_ISRUNNING	_IOR('b', 3, int)
#define VOLMGT_SETRUNSTATE	_IO('b', 4)
#define VOLMGT_PIDREGISTER	_IOW('b', 5, dev_t)
#define VOLMGT_PIDUNREGISTER	_IOW('b', 6, dev_t)
#define VOLMGT_GETDEVPID	_IOWR('b', 7, struct devpid_pkt) 
#define VOLMGT_SETCHANGE	_IOW('b', 8, dev_t)
#define VOLMGT_GETCHANGE	_IOWR('b', 9, struct devchg_pkt)

struct devpid_pkt {
	dev_t dev;
	pid_t pid;
};

#define WABIDEV	"/dev/wabi"

/* for debug messages */
extern char	*prog_name;
extern int	prog_pid;

#define	TRUE	(-1)
#define	FALSE	(0)

int
action(struct action_arg **aa, int argc, char **argv)
{
	char			*atype = getenv("VOLUME_ACTION");
	char			*devname;
	struct stat 		sb;
	struct devpid_pkt	dp;
	int			fd;
	int			flag = 0;

	if ((fd = open(WABIDEV, O_RDWR)) < 0) {
		dprintf("action_wabi: couldn't open %s; %m\n", WABIDEV);
		return (FALSE);
	}


	if (ioctl(fd, VOLMGT_ISRUNNING, &flag) < 0) {
		dprintf("action_wabi: isrunning failed; %m\n");
		close(fd);
		return (FALSE);
	}

	if (!flag) {
		dprintf("action_wabi: wabi is not running\n");
		close(fd);
		return (FALSE);
	}
	
	dprintf("action_wabi: wabi is alive\n");

	/* insert case is simple, so we just get that out of the way */
	if (!strcmp(atype, "insert")) {
		aa[0]->aa_mnt = FALSE;	/* don't mount the media */
		close(fd);
		return (TRUE);
	}

	/* well, if it's not insert or eject, we'll just leave right here */
	if (strcmp(atype, "eject") != 0) {
		close(fd);
		return (FALSE);
	}

	devname = (char *)volmgt_symdev(getenv("VOLUME_SYMDEV"));
	if (devname == NULL) {
		dprintf("action_wabi: no /dev name for %s\n", 
		    getenv("VOLUME_SYMDEV"));
		close(fd);
		return (FALSE);
	}

	if (stat(devname, &sb) < 0) {
		dprintf("action_wabi: couldn't find %s\n", devname);
		free(devname);
		close(fd);
		return (FALSE);
	}
	dprintf("action_wabi: device is %s\n", devname);

	dp.dev = sb.st_rdev;

	if (ioctl(fd, VOLMGT_GETDEVPID, &dp) < 0) {
		dprintf("action_wabi: getdevpid failed; %m\n");
		free(devname);
		close(fd);
		return (FALSE);
	}

	/*
	 * wabi's got the device.
	 */
	if (dp.pid) {
		dprintf("action_wabi: wabi is pid %d, dev_t is 0x%x\n",
		    dp.pid, dp.dev);
		if (ioctl(fd, VOLMGT_SETCHANGE, &sb.st_rdev) < 0) {
			dprintf("action_wabi: setchange failed; %m\n");
		}
		if (kill(dp.pid, SIGUSR1) < 0) {
			dprintf("action_wabi: kill of pid %d failed; %m\n");
		}
	}

	free(devname);
	close (fd);
	return (TRUE);
}

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

/*
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Oxide Computer Company
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#pragma weak _ptsname = ptsname
#pragma weak _grantpt = grantpt
#pragma weak _unlockpt = unlockpt

#include "lint.h"
#include "libc.h"
#include "mtlib.h"
#include <sys/types.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/mkdev.h>
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
#include <spawn.h>
#include <grp.h>
#include "tsd.h"

#define	PTSNAME "/dev/pts/"		/* slave name */
#define	PTLEN   32			/* slave name length */
#define	DEFAULT_TTY_GROUP	"tty"	/* slave device group owner */

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

int
ptsname_r(int fd, char *name, size_t len)
{
	dev_t dev;

	if (name == NULL)
		return (EINVAL);

	if ((dev = ptsdev(fd)) == NODEV)
		return (errno);

	if (snprintf(name, len, "%s%d", PTSNAME, dev) >= len)
		return (ERANGE);

	/*
	 * This lookup will create the /dev/pts node (if the corresponding pty
	 * exists). POSIX basically never really indicated whether or not
	 * ptsname() was allowed to return errors or not, though we did. If we
	 * played strictly by the book, this should probably be an EINVAL or
	 * ENOTTY return; however, to help someone have a chance of debugging
	 * this if something goes wrong we stick with our traditional behavior
	 * and return a slightly broader errno set. If this causes portability
	 * issues in practice, then it should be changed to just return EINVAL.
	 */
	if (access(name, F_OK) != 0)
		return (errno);

	return (0);
}

char *
ptsname(int fd)
{
	int ret;
	char *sname;

	sname = tsdalloc(_T_PTSNAME, PTLEN, NULL);
	if (sname == NULL)
		return (NULL);

	if ((ret = ptsname_r(fd, sname, PTLEN)) != 0) {
		errno = ret;
		return (NULL);
	}

	return (sname);
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
 * XPG4v2 requires that open of a slave pseudo terminal device
 * provides the process with an interface that is identical to
 * the terminal interface.
 *
 * To satisfy this, in strict XPG4v2 mode, this routine also sends
 * a message down the stream that sets a flag in the kernel module
 * so that additional actions are performed when opening an
 * associated slave PTY device. When this happens, modules are
 * automatically pushed onto the stream to provide terminal
 * semantics and those modules are then informed that they should
 * behave in strict XPG4v2 mode which modifies their behaviour. In
 * particular, in strict XPG4v2 mode, empty blocks will be sent up
 * the master side of the stream rather than being suppressed.
 *
 * Most applications do not expect this behaviour so it is only
 * enabled for programs compiled in strict XPG4v2 mode (see
 * stdlib.h).
 */
int
__unlockpt_xpg4(int fd)
{
	int ret;

	if ((ret = unlockpt(fd)) == 0) {
		struct strioctl istr;

		istr.ic_cmd = PTSSTTY;
		istr.ic_len = 0;
		istr.ic_timout = 0;
		istr.ic_dp = NULL;

		if (ioctl(fd, I_STR, &istr) < 0)
			ret = -1;
	}

	return (ret);
}

int
grantpt(int fd)
{
	struct strioctl istr;
	pt_own_t pto;
	struct group *gr_name;

	/* validate the file descriptor before proceeding */
	if (ptsdev(fd) == NODEV)
		return (-1);

	pto.pto_ruid = getuid();

	gr_name = getgrnam(DEFAULT_TTY_GROUP);
	if (gr_name)
		pto.pto_rgid = gr_name->gr_gid;
	else
		pto.pto_rgid = getgid();

	istr.ic_cmd = OWNERPT;
	istr.ic_len = sizeof (pt_own_t);
	istr.ic_timout = 0;
	istr.ic_dp = (char *)&pto;

	if (ioctl(fd, I_STR, &istr) != 0) {
		errno = EACCES;
		return (-1);
	}

	return (0);
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

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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/filio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <libintl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <sys/lx_fcntl.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

/*
 * flock() applies or removes an advisory lock on the file
 * associated with the file descriptor fd.
 *
 * operation is: LX_LOCK_SH, LX_LOCK_EX, LX_LOCK_UN, LX_LOCK_NB
 */
long
lx_flock(uintptr_t p1, uintptr_t p2)
{
	int			fd = (int)p1;
	int			operation = (int)p2;
	struct flock		fl;
	int			cmd;
	int			ret;

	if (operation & LX_LOCK_NB) {
		cmd = F_FLOCK;
		operation &= ~LX_LOCK_NB; /* turn off this bit */
	} else {
		cmd = F_FLOCKW;
	}

	switch (operation) {
		case LX_LOCK_UN:
			fl.l_type = F_UNLCK;
			break;
		case LX_LOCK_SH:
			fl.l_type = F_RDLCK;
			break;
		case LX_LOCK_EX:
			fl.l_type = F_WRLCK;
			break;
		default:
			return (-EINVAL);
	}

	fl.l_whence = 0;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_sysid = 0;
	fl.l_pid = 0;

	ret = fcntl(fd, cmd, &fl);

	return ((ret == -1) ? -errno : ret);
}

/*
 * Based on Illumos posix_fadvise which does nothing. The only difference is
 * that on Linux an fd refering to a pipe or FIFO returns EINVAL.
 * The Linux POSIX_FADV_* values are the same as the Illumos values.
 * See how glibc calls fadvise64; the offeset is a 64bit value, but the length
 * is not, whereas fadvise64_64 passes both the offset and length as 64bit
 * values.
 */
/* ARGSUSED */
long
lx_fadvise64(uintptr_t p1, off64_t p2, uintptr_t p3, uintptr_t p4)
{
	int fd = (int)p1;
	int advice = (int)p4;
	int32_t len = (int32_t)p3;
	struct stat64 statb;

	switch (advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_WILLNEED:
	case POSIX_FADV_DONTNEED:
	case POSIX_FADV_NOREUSE:
		break;
	default:
		return (-EINVAL);
	}
	if (len < 0)
		return (-EINVAL);
	if (fstat64(fd, &statb) != 0)
		return (-EBADF);
	if (S_ISFIFO(statb.st_mode))
		return (-ESPIPE);
	return (0);
}

long
lx_fadvise64_64(uintptr_t p1, off64_t p2, off64_t p3, uintptr_t p4)
{

	if (p3 < 0)
		return (-EINVAL);

	return (lx_fadvise64(p1, p2, 0, p4));
}

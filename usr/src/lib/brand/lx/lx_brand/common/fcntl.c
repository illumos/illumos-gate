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

static int lx_fcntl_com(int fd, int cmd, ulong_t arg);
static void ltos_flock(struct lx_flock *l, struct flock *s);
static void stol_flock(struct flock *s, struct lx_flock *l);
static void ltos_flock64(struct lx_flock64 *l, struct flock64 *s);
static void stol_flock64(struct flock64 *s, struct lx_flock64 *l);
static short ltos_type(short l_type);
static short stol_type(short l_type);
static int lx_fcntl_getfl(int fd);
static int lx_fcntl_setfl(int fd, ulong_t arg);

long
lx_dup2(uintptr_t p1, uintptr_t p2)
{
	int oldfd = (int)p1;
	int newfd = (int)p2;
	int rc;

	rc = fcntl(oldfd, F_DUP2FD, newfd);
	return ((rc == -1) ? -errno : rc);
}

long
lx_dup3(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int oldfd = (int)p1;
	int newfd = (int)p2;
	int flags = (int)p3;
	int rc;

	/* The only valid flag is O_CLOEXEC. */
	if (flags & ~LX_O_CLOEXEC)
		return (-EINVAL);

	if (oldfd == newfd)
		return (-EINVAL);

	rc = fcntl(oldfd, (flags == 0) ? F_DUP2FD : F_DUP2FD_CLOEXEC, newfd);
	return ((rc == -1) ? -errno : rc);
}

long
lx_fcntl(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int		fd = (int)p1;
	int		cmd = (int)p2;
	ulong_t		arg = (ulong_t)p3;
	struct lx_flock lxflk;
	struct flock	fl;
	int		lk = 0;
	int		rc;

	/*
	 * The 64-bit fcntl commands must go through fcntl64().
	 */
	if (cmd == LX_F_GETLK64 || cmd == LX_F_SETLK64 ||
	    cmd == LX_F_SETLKW64)
		return (-EINVAL);

	if (cmd == LX_F_SETSIG || cmd == LX_F_GETSIG || cmd == LX_F_SETLEASE ||
	    cmd == LX_F_GETLEASE) {
		lx_unsupported("unsupported fcntl command: %d", cmd);
		return (-ENOTSUP);
	}

	if (cmd == LX_F_GETLK || cmd == LX_F_SETLK ||
	    cmd == LX_F_SETLKW) {
		if (uucopy((void *)p3, (void *)&lxflk,
		    sizeof (struct lx_flock)) != 0)
			return (-errno);
		lk = 1;
		ltos_flock(&lxflk, &fl);
		arg = (ulong_t)&fl;
	}

	rc = lx_fcntl_com(fd, cmd, arg);

	if (lk && rc >= 0) {
		stol_flock(&fl, &lxflk);
		if (uucopy((void *)&lxflk, (void *)p3,
		    sizeof (struct lx_flock)) != 0)
			return (-errno);
	}

	return (rc);
}

long
lx_fcntl64(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int		fd = (int)p1;
	int		cmd = (int)p2;
	struct lx_flock lxflk;
	struct lx_flock64 lxflk64;
	struct flock	fl;
	struct flock64	fl64;
	int		rc;

	if (cmd == LX_F_SETSIG || cmd == LX_F_GETSIG || cmd == LX_F_SETLEASE ||
	    cmd == LX_F_GETLEASE) {
		lx_unsupported("unsupported fcntl64 command: %d", cmd);
		return (-ENOTSUP);
	}

	if (cmd == LX_F_GETLK || cmd == LX_F_SETLK || cmd == LX_F_SETLKW) {
		if (uucopy((void *)p3, (void *)&lxflk,
		    sizeof (struct lx_flock)) != 0)
			return (-errno);
		ltos_flock(&lxflk, &fl);
		rc = lx_fcntl_com(fd, cmd, (ulong_t)&fl);
		if (rc >= 0) {
			stol_flock(&fl, &lxflk);
			if (uucopy((void *)&lxflk, (void *)p3,
			    sizeof (struct lx_flock)) != 0)
				return (-errno);
		}
	} else if (cmd == LX_F_GETLK64 || cmd == LX_F_SETLKW64 || \
	    cmd == LX_F_SETLK64) {
		if (uucopy((void *)p3, (void *)&lxflk64,
		    sizeof (struct lx_flock64)) != 0)
			return (-errno);
		ltos_flock64(&lxflk64, &fl64);
		rc = lx_fcntl_com(fd, cmd, (ulong_t)&fl64);
		if (rc >= 0) {
			stol_flock64(&fl64, &lxflk64);
			if (uucopy((void *)&lxflk64, (void *)p3,
			    sizeof (struct lx_flock64)) != 0)
				return (-errno);
		}
	} else {
		rc = lx_fcntl_com(fd, cmd, (ulong_t)p3);
	}

	return (rc);
}

static int
lx_fcntl_com(int fd, int cmd, ulong_t arg)
{
	int		rc = 0;

	switch (cmd) {
	case LX_F_DUPFD:
		rc = fcntl(fd, F_DUPFD, arg);
		break;

	case LX_F_DUPFD_CLOEXEC:
		rc = fcntl(fd, F_DUPFD_CLOEXEC, arg);
		break;

	case LX_F_GETFD:
		rc = fcntl(fd, F_GETFD, 0);
		break;

	case LX_F_SETFD:
		rc = fcntl(fd, F_SETFD, arg);
		break;

	case LX_F_GETFL:
		rc = lx_fcntl_getfl(fd);
		break;

	case LX_F_SETFL:
		rc = lx_fcntl_setfl(fd, arg);
		break;

	case LX_F_GETLK:
		rc = fcntl(fd, F_GETLK, arg);
		break;

	case LX_F_SETLK:
		rc = fcntl(fd, F_SETLK, arg);
		break;

	case LX_F_SETLKW:
		rc = fcntl(fd, F_SETLKW, arg);
		break;

	case LX_F_GETLK64:
		rc = fcntl(fd, F_GETLK64, arg);
		break;

	case LX_F_SETLK64:
		rc = fcntl(fd, F_SETLK64, arg);
		break;

	case LX_F_SETLKW64:
		rc = fcntl(fd, F_SETLKW64, arg);
		break;

	case LX_F_SETOWN:
		if ((int)arg == 1) {
			/* Setown for the init process uses the real pid. */
			arg = (ulong_t)zoneinit_pid;
		}

		rc = fcntl(fd, F_SETOWN, arg);
		break;

	case LX_F_GETOWN:
		rc = fcntl(fd, F_GETOWN, arg);
		if (rc == zoneinit_pid) {
			/* Getown for the init process returns 1. */
			rc = 1;
		}
		break;

	default:
		return (-EINVAL);
	}

	return ((rc == -1) ? -errno : rc);
}


#define	LTOS_FLOCK(l, s)						\
{									\
	s->l_type = ltos_type(l->l_type);				\
	s->l_whence = l->l_whence;					\
	s->l_start = l->l_start;					\
	s->l_len = l->l_len;						\
	s->l_sysid = 0;			/* not defined in linux */	\
	s->l_pid = (pid_t)l->l_pid;					\
}

#define	STOL_FLOCK(s, l)						\
{									\
	l->l_type = stol_type(s->l_type);				\
	l->l_whence = s->l_whence;					\
	l->l_start = s->l_start;					\
	l->l_len = s->l_len;						\
	l->l_pid = (int)s->l_pid;					\
}

static void
ltos_flock(struct lx_flock *l, struct flock *s)
{
	LTOS_FLOCK(l, s)
}

static void
stol_flock(struct flock *s, struct lx_flock *l)
{
	STOL_FLOCK(s, l)
}

static void
ltos_flock64(struct lx_flock64 *l, struct flock64 *s)
{
	LTOS_FLOCK(l, s)
}

static void
stol_flock64(struct flock64 *s, struct lx_flock64 *l)
{
	STOL_FLOCK(s, l)
}

static short
ltos_type(short l_type)
{
	switch (l_type) {
	case LX_F_RDLCK:
		return (F_RDLCK);
	case LX_F_WRLCK:
		return (F_WRLCK);
	case LX_F_UNLCK:
		return (F_UNLCK);
	default:
		return (-1);
	}
}

static short
stol_type(short l_type)
{
	switch (l_type) {
	case F_RDLCK:
		return (LX_F_RDLCK);
	case F_WRLCK:
		return (LX_F_WRLCK);
	case F_UNLCK:
		return (LX_F_UNLCK);
	default:
		/* can't ever happen */
		return (0);
	}
}

int
lx_fcntl_getfl(int fd)
{
	int retval;
	int rc;

	retval = fcntl(fd, F_GETFL, 0);

	if ((retval & O_ACCMODE) == O_RDONLY)
		rc = LX_O_RDONLY;
	else if ((retval & O_ACCMODE) == O_WRONLY)
		rc = LX_O_WRONLY;
	else
		rc = LX_O_RDWR;
	/* O_NDELAY != O_NONBLOCK, so we need to check for both */
	if (retval & O_NDELAY)
		rc |= LX_O_NDELAY;
	if (retval & O_NONBLOCK)
		rc |= LX_O_NONBLOCK;
	if (retval & O_APPEND)
		rc |= LX_O_APPEND;
	if (retval & O_SYNC)
		rc |= LX_O_SYNC;
	if (retval & O_LARGEFILE)
		rc |= LX_O_LARGEFILE;
	if (retval & FASYNC)
		rc |= LX_O_ASYNC;

	return (rc);
}

int
lx_fcntl_setfl(int fd, ulong_t arg)
{
	int new_arg;

	new_arg = 0;
	/* LX_O_NDELAY == LX_O_NONBLOCK, so we only check for one */
	if (arg & LX_O_NDELAY)
		new_arg |= O_NONBLOCK;
	if (arg & LX_O_APPEND)
		new_arg |= O_APPEND;
	if (arg & LX_O_SYNC)
		new_arg |= O_SYNC;
	if (arg & LX_O_LARGEFILE)
		new_arg |= O_LARGEFILE;
	if (arg & LX_O_ASYNC)
		new_arg |= FASYNC;

	return ((fcntl(fd, F_SETFL, new_arg) == 0) ? 0 : -errno);
}

/*
 * flock() applies or removes an advisory lock on the file
 * associated with the file descriptor fd.
 *
 * Stolen verbatim from usr/src/ucblib/libucb/port/sys/flock.c
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

	/* In non-blocking lock, use F_SETLK for cmd, F_SETLKW otherwise */
	if (operation & LX_LOCK_NB) {
		cmd = F_SETLK;
		operation &= ~LX_LOCK_NB; /* turn off this bit */
	} else
		cmd = F_SETLKW;

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

	ret = fcntl(fd, cmd, &fl);

	if (ret == -1 && errno == EACCES)
		return (-EWOULDBLOCK);

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

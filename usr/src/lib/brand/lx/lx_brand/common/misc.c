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
 * Copyright 2016 Joyent, Inc.
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <priv.h>
#include <strings.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <sys/lx_fcntl.h>

extern int sethostname(char *, int);

/* ARGUSED */
long
lx_rename(uintptr_t p1, uintptr_t p2)
{
	int ret;

	ret = rename((const char *)p1, (const char *)p2);

	if (ret < 0) {
		/*
		 * If rename(2) failed and we're in install mode, return
		 * success if the the reason we failed was either because the
		 * source file didn't actually exist or if it was because we
		 * tried to rename it to be the name of a device currently in
		 * use (resulting in an EBUSY.)
		 *
		 * To help install along further, if the failure was due
		 * to an EBUSY, delete the original file so we don't leave
		 * extra files lying around.
		 */
		if (lx_install != 0) {
			if (errno == ENOENT)
				return (0);

			if (errno == EBUSY) {
				(void) unlink((const char *)p1);
				return (0);
			}
		}

		return (-errno);
	}

	return (0);
}

long
lx_renameat(uintptr_t ext1, uintptr_t p1, uintptr_t ext2, uintptr_t p2)
{
	int ret;
	int atfd1 = (int)ext1;
	int atfd2 = (int)ext2;

	if (atfd1 == LX_AT_FDCWD)
		atfd1 = AT_FDCWD;

	if (atfd2 == LX_AT_FDCWD)
		atfd2 = AT_FDCWD;

	ret = renameat(atfd1, (const char *)p1, atfd2, (const char *)p2);

	if (ret < 0) {
		/* see lx_rename() for why we check lx_install */
		if (lx_install != 0) {
			if (errno == ENOENT)
				return (0);

			if (errno == EBUSY) {
				(void) unlinkat(ext1, (const char *)p1, 0);
				return (0);
			}
		}

		return (-errno);
	}

	return (0);
}

/*ARGSUSED*/
long
lx_reboot(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int magic = (int)p1;
	int magic2 = (int)p2;
	uint_t flag = (int)p3;
	int rc;

	if (magic != LINUX_REBOOT_MAGIC1)
		return (-EINVAL);
	if (magic2 != LINUX_REBOOT_MAGIC2 && magic2 != LINUX_REBOOT_MAGIC2A &&
	    magic2 != LINUX_REBOOT_MAGIC2B && magic2 != LINUX_REBOOT_MAGIC2C &&
	    magic2 != LINUX_REBOOT_MAGIC2D)
		return (-EINVAL);

	if (geteuid() != 0)
		return (-EPERM);

	switch (flag) {
	case LINUX_REBOOT_CMD_CAD_ON:
	case LINUX_REBOOT_CMD_CAD_OFF:
		/* ignored */
		rc = 0;
		break;
	case LINUX_REBOOT_CMD_POWER_OFF:
	case LINUX_REBOOT_CMD_HALT:
		rc = reboot(RB_HALT, NULL);
		break;
	case LINUX_REBOOT_CMD_RESTART:
	case LINUX_REBOOT_CMD_RESTART2:
		/* RESTART2 may need more work */
		lx_msg("Restarting system.\n");
		rc = reboot(RB_AUTOBOOT, NULL);
		break;
	default:
		return (-EINVAL);
	}

	return ((rc == -1) ? -errno : rc);
}

/*
 * {get,set}groups16() - Handle the conversion between 16-bit Linux gids and
 * 32-bit illumos gids.
 */
long
lx_getgroups16(uintptr_t p1, uintptr_t p2)
{
	int count = (int)p1;
	lx_gid16_t *grouplist = (lx_gid16_t *)p2;
	gid_t *grouplist32;
	int ret;
	int i;

	if (count < 0)
		return (-EINVAL);

	grouplist32 = malloc(count * sizeof (gid_t));
	if (grouplist32 == NULL && count > 0) {
		free(grouplist32);
		return (-ENOMEM);
	}
	if ((ret = getgroups(count, grouplist32)) < 0) {
		free(grouplist32);
		return (-errno);
	}

	/* we must not modify the list if the incoming count was 0 */
	if (count > 0) {
		for (i = 0; i < ret; i++)
			grouplist[i] = LX_GID32_TO_GID16(grouplist32[i]);
	}

	free(grouplist32);
	return (ret);
}

long
lx_setgroups16(uintptr_t p1, uintptr_t p2)
{
	long rv;
	int count = (int)p1;
	lx_gid16_t *grouplist = NULL;
	gid_t *grouplist32 = NULL;
	int i;

	if ((grouplist = malloc(count * sizeof (lx_gid16_t))) == NULL) {
		return (-ENOMEM);
	}
	if (uucopy((void *)p2, grouplist, count * sizeof (lx_gid16_t)) != 0) {
		free(grouplist);
		return (-EFAULT);
	}

	grouplist32 = malloc(count * sizeof (gid_t));
	if (grouplist32 == NULL) {
		free(grouplist);
		return (-ENOMEM);
	}
	for (i = 0; i < count; i++)
		grouplist32[i] = LX_GID16_TO_GID32(grouplist[i]);

	/* order matters here to get the correct errno back */
	if (count > NGROUPS_MAX_DEFAULT) {
		free(grouplist);
		free(grouplist32);
		return (-EINVAL);
	}

	rv = setgroups(count, grouplist32);

	free(grouplist);
	free(grouplist32);

	return (rv != 0 ? -errno : 0);
}

/*
 * mknod() - Since we don't have the SYS_CONFIG privilege within a zone, the
 * only mode we have to support is S_IFIFO.  We also have to distinguish between
 * an invalid type and insufficient privileges.
 */
#define	LX_S_IFMT	0170000
#define	LX_S_IFDIR	0040000
#define	LX_S_IFCHR	0020000
#define	LX_S_IFBLK	0060000
#define	LX_S_IFREG	0100000
#define	LX_S_IFIFO	0010000
#define	LX_S_IFLNK	0120000
#define	LX_S_IFSOCK	0140000

/*ARGSUSED*/
long
lx_mknod(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	char *path = (char *)p1;
	lx_dev_t lx_dev = (lx_dev_t)p3;
	struct sockaddr_un sockaddr;
	struct stat statbuf;
	mode_t mode, type;
	dev_t dev;
	int fd;

	type = ((mode_t)p2 & LX_S_IFMT);
	mode = ((mode_t)p2 & 07777);

	switch (type) {
	case 0:
	case LX_S_IFREG:
		/* create a regular file */
		if (stat(path, &statbuf) == 0)
			return (-EEXIST);

		if (errno != ENOENT)
			return (-errno);

		if ((fd = creat(path, mode)) < 0)
			return (-errno);

		(void) close(fd);
		return (0);

	case LX_S_IFSOCK:
		/*
		 * Create a UNIX domain socket.
		 *
		 * Most programmers aren't even aware you can do this.
		 *
		 * Note you can also do this via illumos' mknod(2), but
		 * Linux allows anyone who can create a UNIX domain
		 * socket via bind(2) to create one via mknod(2);
		 * illumos requires the caller to be privileged.
		 */
		if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			return (-errno);

		if (stat(path, &statbuf) == 0)
			return (-EEXIST);

		if (errno != ENOENT)
			return (-errno);

		if (uucopy(path, &sockaddr.sun_path,
		    sizeof (sockaddr.sun_path)) < 0)
			return (-errno);

		/* assure NULL termination of sockaddr.sun_path */
		sockaddr.sun_path[sizeof (sockaddr.sun_path) - 1] = '\0';
		sockaddr.sun_family = AF_UNIX;

		if (bind(fd, (struct sockaddr *)&sockaddr,
		    strlen(sockaddr.sun_path) +
		    sizeof (sockaddr.sun_family)) < 0)
			return (-errno);

		(void) close(fd);
		return (0);

	case LX_S_IFIFO:
		dev = 0;
		break;

	case LX_S_IFCHR:
	case LX_S_IFBLK:
		/*
		 * The "dev" RPM package wants to create all possible Linux
		 * device nodes, so just report its mknod()s as having
		 * succeeded if we're in install mode.
		 */
		if (lx_install != 0) {
			lx_debug("lx_mknod: install mode spoofed creation of "
			    "Linux device [%lld, %lld]\n",
			    LX_GETMAJOR(lx_dev), LX_GETMINOR(lx_dev));

			return (0);
		}

		dev = makedevice(LX_GETMAJOR(lx_dev), LX_GETMINOR(lx_dev));
		break;

	default:
		return (-EINVAL);
	}

	return (mknod(path, mode | type, dev) ? -errno : 0);
}

long
lx_sethostname(uintptr_t p1, uintptr_t p2)
{
	char *name = (char *)p1;
	int len = (size_t)p2;

	return (sethostname(name, len) ? -errno : 0);
}

long
lx_setdomainname(uintptr_t p1, uintptr_t p2)
{
	char *name = (char *)p1;
	int len = (size_t)p2;
	long rval;

	if (len < 0 || len >= LX_SYS_UTS_LN)
		return (-EINVAL);

	rval = sysinfo(SI_SET_SRPC_DOMAIN, name, len);

	return ((rval < 0) ? -errno : 0);
}

long
lx_execve(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	char *filename = (char *)p1;
	char **argv = (char **)p2;
	char **envp = (char **)p3;
	char *nullist[] = { NULL };

	if (argv == NULL)
		argv = nullist;

	/*
	 * Emulate PR_SET_KEEPCAPS which is reset on execve. If this is not done
	 * the emulated capabilities could be reduced more than expected.
	 */
	(void) setpflags(PRIV_AWARE_RESET, 1);

	/* This is a normal exec call. */
	(void) execve(filename, argv, envp);

	return (-errno);
}

long
lx_setgroups(uintptr_t p1, uintptr_t p2)
{
	int ng = (int)p1;
	gid_t *glist = NULL;
	int i, r;

	lx_debug("\tlx_setgroups(%d, 0x%p", ng, p2);

	if (ng > 0) {
		if ((glist = (gid_t *)malloc(ng * sizeof (gid_t))) == NULL)
			return (-ENOMEM);

		if (uucopy((void *)p2, glist, ng * sizeof (gid_t)) != 0) {
			free(glist);
			return (-errno);
		}

		/*
		 * Linux doesn't check the validity of the group IDs, but
		 * illumos does. Change any invalid group IDs to a known, valid
		 * value (yuck).
		 */
		for (i = 0; i < ng; i++) {
			if (glist[i] > MAXUID)
				glist[i] = MAXUID;
		}
	}

	/* order matters here to get the correct errno back */
	if (ng > NGROUPS_MAX_DEFAULT) {
		free(glist);
		return (-EINVAL);
	}

	r = syscall(SYS_brand, B_HELPER_SETGROUPS, ng, glist);

	free(glist);
	return ((r == -1) ? -errno : r);
}

/*
 * For syslog(), as there is no kernel and nothing to log, we simply emulate a
 * kernel cyclic buffer (LOG_BUF_LEN) of 0 bytes, only handling errors for bad
 * input.  All actions except 3 and 10 require CAP_SYS_ADMIN or CAP_SYSLOG, in
 * lieu of full capabilities support for now we just perform an euid check.
 */
long
lx_syslog(int type, char *bufp, int len)
{
	if (type < 0 || type > 10)
		return (-EINVAL);

	if ((type != 3 && type != 10) && (geteuid() != 0))
		return (-EPERM);

	if ((type >= 2 && type <= 4) && (bufp == NULL || len < 0))
		return (-EINVAL);

	if ((type == 8) && (len < 1 || len > 8))
		return (-EINVAL);

	return (0);
}

/*
 * The following are pass-through functions but we need to return the correct
 * long so that the errno propagates back to the Linux code correctly.
 */

long
lx_alarm(unsigned int seconds)
{
	int r;

	r = alarm(seconds);
	return ((r == -1) ? -errno : r);
}

long
lx_close(int fildes)
{
	int r;

	r = close(fildes);
	return ((r == -1) ? -errno : r);
}

long
lx_chdir(const char *path)
{
	int r;

	r = chdir(path);
	return ((r == -1) ? -errno : r);
}

long
lx_chroot(const char *path)
{
	int r;

	r = chroot(path);
	return ((r == -1) ? -errno : r);
}

long
lx_creat(const char *path, mode_t mode)
{
	int r;

	r = creat(path, mode);
	return ((r == -1) ? -errno : r);
}

long
lx_fchdir(int fildes)
{
	int r;

	r = fchdir(fildes);
	return ((r == -1) ? -errno : r);
}

long
lx_getgroups(int gidsetsize, gid_t *grouplist)
{
	int r;

	r = getgroups(gidsetsize, grouplist);
	return ((r == -1) ? -errno : r);
}

long
lx_getitimer(int which, struct itimerval *value)
{
	int r;

	r = getitimer(which, value);
	return ((r == -1) ? -errno : r);
}

long
lx_inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
	int r;

	r = inotify_add_watch(fd, pathname, mask);
	return ((r == -1) ? -errno : r);
}

long
lx_inotify_init(void)
{
	int r;

	r = inotify_init();
	return ((r == -1) ? -errno : r);
}

long
lx_inotify_init1(int flags)
{
	int r;

	r = inotify_init1(flags);
	return ((r == -1) ? -errno : r);
}

long
lx_inotify_rm_watch(int fd, int wd)
{
	int r;

	r = inotify_rm_watch(fd, wd);
	return ((r == -1) ? -errno : r);
}

long
lx_mincore(caddr_t addr, size_t len, char *vec)
{
	int r;

	r = mincore(addr, len, vec);
	if (r == -1 && errno == EINVAL) {
		/*
		 * LTP mincore01 expects mincore with a huge len to fail with
		 * ENOMEM on a modern kernel but on Linux 2.6.11 and earlier it
		 * returns EINVAL.
		 */
		if (strcmp(lx_release, "2.6.11") > 0 && (long)len < 0)
			errno = ENOMEM;
	}
	return ((r == -1) ? -errno : r);
}

long
lx_munmap(void *addr, size_t len)
{
	int r;

	r = munmap(addr, len);
	return ((r == -1) ? -errno : r);
}

long
lx_nice(int incr)
{
	int r;

	r = nice(incr);
	return ((r == -1) ? -errno : r);
}

long
lx_pause(void)
{
	int r;

	r = pause();
	return ((r == -1) ? -errno : r);
}

long
lx_shmdt(char *shmaddr)
{
	int r;

	r = shmdt(shmaddr);
	return ((r == -1) ? -errno : r);
}

long
lx_stime(const time_t *tp)
{
	int r;

	r = stime(tp);
	return ((r == -1) ? -errno : r);
}

long
lx_symlink(const char *name1, const char *name2)
{
	int r;

	r = symlink(name1, name2);
	return ((r == -1) ? -errno : r);
}

long
lx_utimes(const char *path, const struct timeval times[2])
{
	int r;

	r = utimes(path, times);
	return ((r == -1) ? -errno : r);
}

long
lx_vhangup(void)
{
	if (geteuid() != 0)
		return (-EPERM);

	vhangup();

	return (0);
}

long
lx_eventfd(unsigned int initval)
{
	return (lx_eventfd2(initval, 0));
}

long
lx_eventfd2(unsigned int initval, int flags)
{
	int r = eventfd(initval, flags);

	/*
	 * eventfd(3C) may fail with ENOENT if /dev/eventfd is not available.
	 * It is less jarring to Linux programs to tell them that the system
	 * call is not supported than to report an error number they are not
	 * expecting.
	 */
	if (r == -1 && errno == ENOENT)
		return (-ENOTSUP);

	return (r == -1 ? -errno : r);
}

/*
 * We lucked out here.  Linux and Solaris have exactly the same
 * rusage structures.
 */
long
lx_getrusage(uintptr_t p1, uintptr_t p2)
{
	int who = (int)p1;
	struct rusage *rup = (struct rusage *)p2;
	int rv, swho;

	if (who == LX_RUSAGE_SELF)
		swho = RUSAGE_SELF;
	else if (who == LX_RUSAGE_CHILDREN)
		swho = RUSAGE_CHILDREN;
	else if (who == LX_RUSAGE_THREAD)
		swho = RUSAGE_LWP;
	else
		return (-EINVAL);

	rv = getrusage(swho, rup);

	return (rv < 0 ? -errno : 0);
}

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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <assert.h>
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <macros.h>
#include <sys/brand.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/lx_types.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_stat.h>
#include <sys/lx_syscall.h>
#include <sys/lx_thunk_server.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_thread.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>
#include <thread.h>
#include <unistd.h>
#include <libintl.h>
#include <zone.h>
#include <priv.h>
#include <lx_syscall.h>

extern int sethostname(char *, int);

struct lx_sysinfo {
	int64_t si_uptime;	/* Seconds since boot */
	uint64_t si_loads[3];	/* 1, 5, and 15 minute avg runq length */
	uint64_t si_totalram;	/* Total memory size */
	uint64_t si_freeram;	/* Available memory */
	uint64_t si_sharedram;	/* Shared memory */
	uint64_t si_bufferram;	/* Buffer memory */
	uint64_t si_totalswap;	/* Total swap space */
	uint64_t si_freeswap;	/* Avail swap space */
	uint16_t si_procs;	/* Process count */
	uint16_t si_pad;	/* Padding */
	uint64_t si_totalhigh;	/* High memory size */
	uint64_t si_freehigh;	/* Avail high memory */
	uint32_t si_mem_unit;	/* Unit size of memory fields */
};

struct lx_sysinfo32 {
	int32_t si_uptime;	/* Seconds since boot */
	uint32_t si_loads[3];	/* 1, 5, and 15 minute avg runq length */
	uint32_t si_totalram;	/* Total memory size */
	uint32_t si_freeram;	/* Available memory */
	uint32_t si_sharedram;	/* Shared memory */
	uint32_t si_bufferram;	/* Buffer memory */
	uint32_t si_totalswap;	/* Total swap space */
	uint32_t si_freeswap;	/* Avail swap space */
	uint16_t si_procs;	/* Process count */
	uint16_t si_pad;	/* Padding */
	uint32_t si_totalhigh;	/* High memory size */
	uint32_t si_freehigh;	/* Avail high memory */
	uint32_t si_mem_unit;	/* Unit size of memory fields */
};

extern long lx_sysinfo(struct lx_sysinfo *sip);

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
 * getcwd() - Linux syscall semantics are slightly different; we need to return
 * the length of the pathname copied (+ 1 for the terminating NULL byte.)
 */
long
lx_getcwd(uintptr_t p1, uintptr_t p2)
{
	char *buf;
	size_t buflen = (size_t)p2;
	size_t copylen, local_len;
	size_t len = 0;

	if ((getcwd((char *)p1, (size_t)p2)) == NULL)
		return (-errno);

	/*
	 * We need the length of the pathname getcwd() copied but we never want
	 * to dereference a Linux pointer for any reason.
	 *
	 * Thus, to get the string length we will uucopy() up to copylen
	 * bytes at a time into a local buffer and will walk each chunk looking
	 * for the string-terminating NULL byte.
	 *
	 * We can use strlen() to find the length of the string in the
	 * local buffer by delimiting the buffer with a NULL byte in the
	 * last element that will never be overwritten.
	 */
	copylen = min(buflen, MAXPATHLEN + 1);
	buf = SAFE_ALLOCA(copylen + 1);
	if (buf == NULL)
		return (-ENOMEM);
	buf[copylen] = '\0';

	for (;;) {
		if (uucopy((char *)p1 + len, buf, copylen) != 0)
			return (-errno);

		local_len = strlen(buf);
		len += local_len;

		/*
		 * If the strlen() is less than copylen, we found the
		 * real end of the string -- not the NULL byte used to
		 * delimit the end of our buffer.
		 */
		if (local_len != copylen)
			break;

		/* prepare to check the next chunk of the string */
		buflen -= copylen;
		copylen = min(buflen, copylen);
	}

	return (len + 1);
}

long
lx_uname(uintptr_t p1)
{
	struct lx_utsname *un = (struct lx_utsname *)p1;
	char buf[LX_SYS_UTS_LN + 1];

	if (gethostname(un->nodename, sizeof (un->nodename)) == -1)
		return (-errno);

	(void) strlcpy(un->sysname, LX_UNAME_SYSNAME, LX_SYS_UTS_LN);
	(void) strlcpy(un->release, lx_release, LX_SYS_UTS_LN);
	(void) strlcpy(un->version, LX_UNAME_VERSION, LX_SYS_UTS_LN);
	(void) strlcpy(un->machine, LX_UNAME_MACHINE, LX_SYS_UTS_LN);
	if ((sysinfo(SI_SRPC_DOMAIN, buf, LX_SYS_UTS_LN) < 0))
		un->domainname[0] = '\0';
	else
		(void) strlcpy(un->domainname, buf, LX_SYS_UTS_LN);

	return (0);
}

/*
 * {get,set}groups16() - Handle the conversion between 16-bit Linux gids and
 * 32-bit Solaris gids.
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

	grouplist32 = SAFE_ALLOCA(count * sizeof (gid_t));
	if (grouplist32 == NULL && count > 0)
		return (-ENOMEM);
	if ((ret = getgroups(count, grouplist32)) < 0)
		return (-errno);

	/* we must not modify the list if the incoming count was 0 */
	if (count > 0) {
		for (i = 0; i < ret; i++)
			grouplist[i] = LX_GID32_TO_GID16(grouplist32[i]);
	}

	return (ret);
}

long
lx_setgroups16(uintptr_t p1, uintptr_t p2)
{
	int count = (int)p1;
	lx_gid16_t *grouplist = (lx_gid16_t *)p2;
	gid_t *grouplist32;
	int i;

	grouplist32 = SAFE_ALLOCA(count * sizeof (gid_t));
	if (grouplist32 == NULL)
		return (-ENOMEM);
	for (i = 0; i < count; i++)
		grouplist32[i] = LX_GID16_TO_GID32(grouplist[i]);

	/* order matters here to get the correct errno back */
	if (count > NGROUPS_MAX_DEFAULT)
		return (-EINVAL);

	return (setgroups(count, grouplist32) ? -errno : 0);
}

/*
 * personality().  We don't really support Linux personalities, but we have to
 * emulate enough (or ahem, lie) to show that we support the basic personality.
 * We also allow certain (relatively) harmless bits of the personality to be
 * "set" -- keeping track of whatever lie we're telling so we don't get caught
 * out too easily.
 */
#define	LX_PER_LINUX			0x0
#define	LX_PER_MASK			0xff

/*
 * These are for what Linux calls "bug emulation".
 */
#define	LX_PER_UNAME26			0x0020000
#define	LX_PER_ADDR_NO_RANDOMIZE	0x0040000
#define	LX_PER_FDPIC_FUNCPTRS		0x0080000
#define	LX_PER_MMAP_PAGE_ZERO		0x0100000
#define	LX_PER_ADDR_COMPAT_LAYOUT	0x0200000
#define	LX_PER_READ_IMPLIES_EXEC	0x0400000
#define	LX_PER_ADDR_LIMIT_32BIT		0x0800000
#define	LX_PER_SHORT_INODE		0x1000000
#define	LX_PER_WHOLE_SECONDS		0x2000000
#define	LX_PER_STICKY_TIMEOUTS		0x4000000
#define	LX_PER_ADDR_LIMIT_3GB		0x8000000

long
lx_personality(uintptr_t p1)
{
	static int current = LX_PER_LINUX;
	int per = (int)p1;

	switch (per) {
	case -1:
		/* Request current personality */
		return (current);
	case LX_PER_LINUX:
		current = per;
		return (0);
	default:
		if (per & LX_PER_MASK)
			return (-EINVAL);

		/*
		 * We allow a subset of the legacy emulation personality
		 * attributes to be "turned on" -- which we put in quotes
		 * because we don't actually change our behavior based on
		 * them.  (Note that we silently ignore the others.)
		 */
		current = per & (LX_PER_ADDR_LIMIT_3GB |
		    LX_PER_ADDR_NO_RANDOMIZE | LX_PER_ADDR_COMPAT_LAYOUT);

		return (0);
	}
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
		 * Note you can also do this via Solaris' mknod(2), but
		 * Linux allows anyone who can create a UNIX domain
		 * socket via bind(2) to create one via mknod(2);
		 * Solaris requires the caller to be privileged.
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
lx_getpid(void)
{
	int pid;

	/* First call the thunk server hook. */
	if (lxt_server_pid(&pid) != 0)
		return (pid);

	pid = syscall(SYS_brand, B_IKE_SYSCALL + LX_EMUL_getpid);
	return ((pid == -1) ? -errno : pid);
}

long
lx_execve(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	char *filename = (char *)p1;
	char **argv = (char **)p2;
	char **envp = (char **)p3;
	char *nullist[] = { NULL };
	char path[64];

	/* First call the thunk server hook. */
	lxt_server_exec_check();

	/* Get a copy of the executable we're trying to run */
	path[0] = '\0';
	(void) uucopystr(filename, path, sizeof (path));

	/* Check if we're trying to run a native binary */
	if (strncmp(path, "/native/usr/lib/brand/lx/lx_native",
	    sizeof (path)) == 0) {
		/* Skip the first element in the argv array */
		argv++;

		/*
		 * The name of the new program to execute was the first
		 * parameter passed to lx_native.
		 */
		if (uucopy(argv, &filename, sizeof (char *)) != 0)
			return (-errno);

		(void) syscall(SYS_brand, B_EXEC_NATIVE, filename, argv, envp,
		    NULL, NULL, NULL);
		return (-errno);
	}

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
		if ((glist = (gid_t *)SAFE_ALLOCA(ng * sizeof (gid_t))) == NULL)
			return (-ENOMEM);

		if (uucopy((void *)p2, glist, ng * sizeof (gid_t)) != 0)
			return (-errno);

		/*
		 * Linux doesn't check the validity of the group IDs, but
		 * Solaris does. Change any invalid group IDs to a known, valid
		 * value (yuck).
		 */
		for (i = 0; i < ng; i++) {
			if (glist[i] > MAXUID)
				glist[i] = MAXUID;
		}
	}

	/* order matters here to get the correct errno back */
	if (ng > NGROUPS_MAX_DEFAULT)
		return (-EINVAL);

	r = syscall(SYS_brand, B_IKE_SYSCALL + LX_EMUL_setgroups,
	    ng, glist);

	return ((r == -1) ? -errno : r);
}

/*
 * Linux currently defines 42 options for prctl (PR_CAPBSET_READ,
 * PR_CAPBSET_DROP, etc.). Most of these are not emulated.
 */
long
lx_prctl(int option, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5)
{
	psinfo_t psinfo;
	size_t fnamelen = sizeof (psinfo.pr_fname);
	size_t psargslen = sizeof (psinfo.pr_psargs);
	int fd;

	if (option == LX_PR_GET_DUMPABLE) {
		/* Indicate that process is always dumpable */
		return (1);
	}

	if (option == LX_PR_SET_DUMPABLE) {
		if (arg2 != 1 && arg2 != 0)
			return (-EINVAL);
		/* Lie about altering process dumpability */
		return (0);
	}

	if (option == LX_PR_SET_KEEPCAPS) {
		/*
		 * The closest illumos analog to SET_KEEPCAPS is the PRIV_AWARE
		 * flag.  There are probably some cases where it's not exactly
		 * the same, but this will do for a first try.
		 */
		if (arg2 == 0) {
			if (setpflags(PRIV_AWARE_RESET, 1) != 0)
				return (-errno);
		} else {
			if (setpflags(PRIV_AWARE, 1) != 0)
				return (-errno);
		}
		return (0);
	}

	if (option != LX_PR_SET_NAME) {
		lx_unsupported("prctl option %d", option);
		return (-ENOSYS);
	}

	/*
	 * In Linux, PR_SET_NAME sets the name of the thread, not the process.
	 * Due to the historical quirks of Linux's asinine thread model, this
	 * name is effectively the name of the process (as visible via ps(1))
	 * if the thread is the first of its task group.  The first thread is
	 * therefore special, and to best mimic Linux semantics (and absent a
	 * notion of per-LWP names), we do nothing (but return success) on LWPs
	 * other than LWP 1.
	 */
	if (thr_self() != 1)
		return (0);

	if (uucopy((void *)arg2, psinfo.pr_fname,
	    MIN(LX_PR_SET_NAME_NAMELEN, fnamelen)) != 0)
		return (-errno);

	psinfo.pr_fname[fnamelen - 1] = '\0';

	if (uucopy((void *)arg2, psinfo.pr_psargs,
	    MIN(LX_PR_SET_NAME_NAMELEN, psargslen)) != 0)
		return (-errno);

	psinfo.pr_psargs[psargslen - 1] = '\0';

	if ((fd = open("/native/proc/self/psinfo", O_WRONLY)) < 0)
		return (-errno);

	if (pwrite(fd, psinfo.pr_fname, fnamelen,
	    (uintptr_t)psinfo.pr_fname - (uintptr_t)&psinfo) != fnamelen) {
		(void) close(fd);
		return (-EIO);
	}

	if (pwrite(fd, psinfo.pr_psargs, psargslen,
	    (uintptr_t)psinfo.pr_psargs - (uintptr_t)&psinfo) != psargslen) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);

	return (0);
}

#if defined(_LP64)
long
lx_arch_prctl(int code, uintptr_t addr)
{
	long rv;
	int ret;
	lx_tsd_t	*lx_tsd;

	rv = syscall(SYS_brand, B_IKE_SYSCALL + LX_EMUL_arch_prctl, code, addr);

	if (code == LX_ARCH_SET_FS && rv == 0) {
		/* Track lx fsbase for debugging purposes */
		if ((ret = thr_getspecific(lx_tsd_key,
		    (void **)&lx_tsd)) != 0) {
			lx_err_fatal("arch_prctl: unable to read TSD: %s",
			    strerror(ret));
		}
		lx_tsd->lxtsd_fsbase = addr;
	}
	return ((rv == 0) ? 0 : -errno);
}
#endif

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

long
lx_sysinfo32(uintptr_t arg)
{
	struct lx_sysinfo32 *sip = (struct lx_sysinfo32 *)arg;
	struct lx_sysinfo32 si;
	struct lx_sysinfo sil;
	int i;

	if (syscall(SYS_brand, B_IKE_SYSCALL + LX_EMUL_sysinfo, &sil) != 0)
		return (-errno);

	si.si_uptime = sil.si_uptime;

	for (i = 0; i < 3; i++) {
		if ((sil.si_loads[i]) > 0x7fffffff)
			si.si_loads[i] = 0x7fffffff;
		else
			si.si_loads[i] = sil.si_loads[i];
	}

	si.si_procs = sil.si_procs;
	si.si_totalram = sil.si_totalram;
	si.si_freeram = sil.si_freeram;
	si.si_totalswap = sil.si_totalswap;
	si.si_freeswap = sil.si_freeswap;
	si.si_mem_unit = sil.si_mem_unit;

	si.si_bufferram = sil.si_bufferram;
	si.si_sharedram = sil.si_sharedram;

	si.si_totalhigh = sil.si_totalhigh;
	si.si_freehigh = sil.si_freehigh;

	if (uucopy(&si, sip, sizeof (si)) != 0)
		return (-errno);

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
lx_dup(int fildes)
{
	int r;

	r = dup(fildes);
	return ((r == -1) ? -errno : r);
}

long
lx_epoll_pwait(int epfd, void *events, int maxevents, int timeout,
    const sigset_t *sigmask)
{
	int r;

	r = epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	return ((r == -1) ? -errno : r);
}

long
lx_epoll_create(int size)
{
	int r;

	r = epoll_create(size);
	return ((r == -1) ? -errno : r);
}

long
lx_epoll_create1(int flags)
{
	int r;

	r = epoll_create1(flags);
	return ((r == -1) ? -errno : r);
}

long
lx_epoll_wait(int epfd, void *events, int maxevents, int timeout)
{
	int r;

	r = epoll_wait(epfd, events, maxevents, timeout);
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
lx_fchmod(int fildes, mode_t mode)
{
	int r;

	r = fchmod(fildes, mode);
	return ((r == -1) ? -errno : r);
}

/*
 * We support neither the second argument (NUMA node), nor the third (obsolete
 * pre-2.6.24 caching functionality which was ultimately broken).
 */
long
lx_getcpu(unsigned int *cpu, uintptr_t p2, uintptr_t p3)
{
	psinfo_t psinfo;
	int procfd;
	unsigned int curcpu;

	if ((procfd = open("/native/proc/self/psinfo", O_RDONLY)) == -1)
		return (-errno);

	if (read(procfd, &psinfo, sizeof (psinfo_t)) == -1)
		return (-errno);

	curcpu = psinfo.pr_lwp.pr_onpro;

	return ((uucopy(&curcpu, cpu, sizeof (curcpu)) != 0) ? -errno : 0);
}

long
lx_getgid(void)
{
	int r;

	r = getgid();
	return (r);
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
lx_getuid(void)
{
	int r;

	r = getuid();
	return (r);
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
lx_lchown(const char *path, uid_t owner, gid_t group)
{
	int r;

	r = lchown(path, owner, group);
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
lx_mkdir(const char *path, mode_t mode)
{
	int r;

	r = mkdir(path, mode);
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
lx_nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
	int r;

	r = nanosleep(rqtp, rmtp);
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
lx_setgid(gid_t gid)
{
	int r;

	r = setgid(gid);
	return ((r == -1) ? -errno : r);
}

long
lx_setuid(uid_t uid)
{
	int r;

	r = setuid(uid);
	return ((r == -1) ? -errno : r);
}

long
lx_setregid(gid_t rgid, gid_t egid)
{
	int r;

	r = setregid(rgid, egid);
	return ((r == -1) ? -errno : r);
}

long
lx_setreuid(uid_t ruid, uid_t euid)
{
	int r;

	r = setreuid(ruid, euid);
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
lx_umask(mode_t cmask)
{
	int r;

	r = umask(cmask);
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
lx_write(int fildes, const void *buf, size_t nbyte)
{
	int r;

	r = write(fildes, buf, nbyte);
	return ((r == -1) ? -errno : r);
}

long
lx_yield(void)
{

	yield();
	return (0);
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

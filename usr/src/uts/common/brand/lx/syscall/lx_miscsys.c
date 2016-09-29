/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/systeminfo.h>
#include <sys/fcntl.h>
#include <sys/resource.h>
#include <sys/uadmin.h>
#include <sys/lx_misc.h>

#define	LINUX_REBOOT_MAGIC1		0xfee1dead
#define	LINUX_REBOOT_MAGIC2		672274793
#define	LINUX_REBOOT_MAGIC2A		85072278
#define	LINUX_REBOOT_MAGIC2B		369367448
#define	LINUX_REBOOT_MAGIC2C		537993216

#define	LINUX_REBOOT_CMD_RESTART	0x1234567
#define	LINUX_REBOOT_CMD_HALT		0xcdef0123
#define	LINUX_REBOOT_CMD_CAD_ON		0x89abcdef
#define	LINUX_REBOOT_CMD_CAD_OFF	0
#define	LINUX_REBOOT_CMD_POWER_OFF	0x4321fedc
#define	LINUX_REBOOT_CMD_RESTART2	0xa1b2c3d4
#define	LINUX_REBOOT_CMD_SW_SUSPEND	0xD000FCE2
#define	LINUX_REBOOT_CMD_KEXEC		0x45584543

#define	LX_RUSAGE_SELF			0
#define	LX_RUSAGE_CHILDREN		(-1)
#define	LX_RUSAGE_BOTH			(-2)
#define	LX_RUSAGE_THREAD		1

/* From uts/common/fs/vfs.c */
extern void vfs_sync(int);
/* From uts/common/os/grow.c */
extern int mincore(caddr_t, size_t, char *);
extern int munmap(caddr_t, size_t);
/* From uts/common/os/session.c */
extern int vhangup();
/* From uts/common/syscall/alarm.c */
extern int alarm(int);
/* From uts/common/syscall/chdir.c */
extern int chdir(char *);
extern int chroot(char *);
extern int fchdir(int);
/* From uts/common/syscall/nice.c */
extern int nice(int);
/* From uts/common/syscall/open.c */
extern int open(char *, int, int);
/* From uts/common/syscall/pause.c */
extern int pause();
/* From uts/common/syscall/rusagesys.c */
extern int rusagesys(int, void *, void *, void *, void *);
/* From uts/common/syscall/systeminfo.c */
extern long systeminfo(int, char *, long);
/* From uts/common/syscall/timers.c */
extern int getitimer(uint_t, struct itimerval *);
/* From uts/common/syscall/time.c */
extern int stime(time_t);
/* From uts/common/syscall/uadmin.c */
extern int uadmin(int, int, uintptr_t);

long
lx_alarm(int seconds)
{
	return (alarm(seconds));
}

long
lx_chdir(char *path)
{
	return (chdir(path));
}

long
lx_chroot(char *path)
{
	return (chroot(path));
}

long
lx_creat(char *path, mode_t mode)
{
	return (open(path, O_WRONLY | O_CREAT | O_TRUNC, mode));
}

long
lx_fchdir(int fd)
{
	return (fchdir(fd));
}

long
lx_getitimer(int which, struct itimerval *value)
{
	return (getitimer(which, value));
}

/* Linux and illumos have the same rusage structures. */
long
lx_getrusage(int who, struct rusage *rup)
{
	int code;

	switch (who) {
	case LX_RUSAGE_SELF:
		code = _RUSAGESYS_GETRUSAGE;
		break;
	case LX_RUSAGE_CHILDREN:
		code = _RUSAGESYS_GETRUSAGE_CHLD;
		break;
	case LX_RUSAGE_THREAD:
		code = _RUSAGESYS_GETRUSAGE_LWP;
		break;
	default:
		return (set_errno(EINVAL));
	}

	return (rusagesys(code, rup, NULL, NULL, NULL));
}

long
lx_mincore(caddr_t addr, size_t len, char *vec)
{
	int r;

	r = mincore(addr, len, vec);
	if (r == EINVAL) {
		/*
		 * LTP mincore01 expects mincore with a huge len to fail with
		 * ENOMEM on a modern kernel, although on Linux 2.6.11 and
		 * earlier, it will return EINVAL.
		 */
		if (lx_kern_release_cmp(curzone, "2.6.11") > 0 && (long)len < 0)
			return (set_errno(ENOMEM));
	}
	return (r);
}

long
lx_munmap(void *addr, size_t len)
{
	return (munmap(addr, len));
}

long
lx_nice(int incr)
{
	return (nice(incr));
}

long
lx_pause(void)
{
	return (pause());
}

/*ARGSUSED*/
long
lx_reboot(int magic1, int magic2, uint_t flag, uintptr_t p4)
{
	if (magic1 != LINUX_REBOOT_MAGIC1)
		return (set_errno(EINVAL));

	switch (magic2) {
	case LINUX_REBOOT_MAGIC2:
	case LINUX_REBOOT_MAGIC2A:
	case LINUX_REBOOT_MAGIC2B:
	case LINUX_REBOOT_MAGIC2C:
		break;
	default:
		return (set_errno(EINVAL));
	}

	/*
	 * Once we have better Linux capabilities(7) support we should check
	 * CAP_SYS_BOOT instead.
	 */
	if (crgetuid(CRED()) != 0)
		return (set_errno(EPERM));

	switch (flag) {
	case LINUX_REBOOT_CMD_CAD_ON:
	case LINUX_REBOOT_CMD_CAD_OFF:
		/* ignored */
		return (0);

	case LINUX_REBOOT_CMD_POWER_OFF:
	case LINUX_REBOOT_CMD_HALT:
		return (uadmin(A_SHUTDOWN, AD_HALT, NULL));

	case LINUX_REBOOT_CMD_RESTART:
	case LINUX_REBOOT_CMD_RESTART2:
		/* RESTART2 may need more work */
		return (uadmin(A_SHUTDOWN, AD_BOOT, NULL));

	default:
		return (set_errno(EINVAL));
	}
}

long
lx_setdomainname(char *name, long len)
{
	if (len < 0 || len >= LX_SYS_UTS_LN)
		return (set_errno(EINVAL));

	ttolwp(curthread)->lwp_errno = 0;
	(void) systeminfo(SI_SET_SRPC_DOMAIN, name, len);
	if (ttolwp(curthread)->lwp_errno != 0)
		return (ttolwp(curthread)->lwp_errno);
	return (0);
}

long
lx_sethostname(char *name, size_t len)
{
	ttolwp(curthread)->lwp_errno = 0;
	(void) systeminfo(SI_SET_HOSTNAME, name, len);
	if (ttolwp(curthread)->lwp_errno != 0)
		return (ttolwp(curthread)->lwp_errno);
	return (0);
}

long
lx_stime(time_t *tp)
{
	time_t time;

	if (copyin(tp, &time, sizeof (time)) != 0)
		return (set_errno(EFAULT));

	return (stime(time));
}

long
lx_sync(void)
{
	vfs_sync(0);
	return (0);
}

/*
 * For syslog, since there is no Linux kernel and nothing to log, we simply
 * emulate a kernel buffer (LOG_BUF_LEN) of 0 bytes and only handle errors for
 * bad input. All actions except 3 and 10 require CAP_SYS_ADMIN or CAP_SYSLOG
 * so without full capabilities support, for now we just perform an euid check.
 */
long
lx_syslog(int type, char *bufp, int len)
{
	if (type < 0 || type > 10)
		return (set_errno(EINVAL));

	if (type != 3 && type != 10 && crgetuid(CRED()) != 0)
		return (set_errno(EPERM));

	if (type >= 2 && type <= 4 && (bufp == NULL || len < 0))
		return (set_errno(EINVAL));

	if (type == 8 && (len < 1 || len > 8))
		return (set_errno(EINVAL));

	return (0);
}

long
lx_vhangup(void)
{
	if (crgetuid(CRED()) != 0)
		return (set_errno(EPERM));

	/*
	 * The native vhangup code does nothing except check for the sys_config
	 * privilege. Eventually we'll first want to check our emulation for the
	 * Linux CAP_SYS_TTY_CONFIG capability, but currently, since we've
	 * already checked that our process is root, just succeed.
	 */
	return (0);
}

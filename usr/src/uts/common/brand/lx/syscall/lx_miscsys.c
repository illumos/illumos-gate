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
#include <lx_syscall.h>

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
/* From uts/common/syscall/chdir.c */
extern int chdir_proc(proc_t *, vnode_t *, boolean_t, boolean_t);
/* From uts/common/fs/lookup.c */
extern int lookupname(char *, enum uio_seg, int, vnode_t **, vnode_t **);
/* From uts/common/fs/fs_subr.c */
extern int fs_need_estale_retry(int);

/* The callback arguments when handling a FS clone group. */
typedef struct {
	vnode_t	*lcfa_vp;
	boolean_t lcfa_type;
} lx_clone_fs_arg_t;

long
lx_alarm(int seconds)
{
	return (alarm(seconds));
}

static int
lx_clone_fs_cb(proc_t *pp, void *arg)
{
	lx_clone_fs_arg_t *ap = (lx_clone_fs_arg_t *)arg;
	int err;

	/*
	 * The initial lookupname() from lx_clone_fs_do_group() will have added
	 * a hold on the vnode to ensure its existence throughout the walk. We
	 * need to add another hold for each process in the group.
	 */
	VN_HOLD(ap->lcfa_vp);
	if ((err = chdir_proc(pp, ap->lcfa_vp, ap->lcfa_type, B_TRUE)) != 0) {
		/* if we failed, chdir_proc already did a rele on vp */
		return (err);
	}

	return (0);
}

/*
 * Check to see if the process is in a CLONE_FS clone group. Return false
 * if not (the normal case), otherwise perform the setup, do the group walk
 * and return true.
 */
static boolean_t
lx_clone_fs_do_group(char *path, boolean_t is_chroot, int *errp)
{
	lx_proc_data_t *lproc = ttolxproc(curthread);
	vnode_t *vp;
	lx_clone_fs_arg_t arg;
	int err;
	int estale_retry = 0;

	if (!lx_clone_grp_member(lproc, LX_CLONE_FS))
		return (B_FALSE);

	/* Handle the rare case of being in a CLONE_FS clone group */

retry:
	err = lookupname(path, UIO_USERSPACE, FOLLOW, NULLVPP, &vp);
	if (err != 0) {
		if (err == ESTALE && fs_need_estale_retry(estale_retry++))
			goto retry;
		*errp = err;
		return (B_TRUE);
	}

	arg.lcfa_vp = vp;
	arg.lcfa_type = is_chroot;

	/*
	 * We use the VN_HOLD from the lookup to guarantee vp exists for the
	 * entire walk.
	 */
	err = lx_clone_grp_walk(lproc, LX_CLONE_FS, lx_clone_fs_cb,
	    (void *)&arg);
	VN_RELE(vp);
	*errp = err;
	return (B_TRUE);
}

long
lx_chdir(char *path)
{
	int err;

	/* Handle the rare case of being in a CLONE_FS clone group */
	if (lx_clone_fs_do_group(path, B_FALSE, &err))
		return ((err != 0) ? set_errno(err) : 0);

	return (chdir(path));
}

long
lx_chroot(char *path)
{
	int err;

	/* Handle the rare case of being in a CLONE_FS clone group */
	if (lx_clone_fs_do_group(path, B_TRUE, &err))
		return ((err != 0) ? set_errno(err) : 0);

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

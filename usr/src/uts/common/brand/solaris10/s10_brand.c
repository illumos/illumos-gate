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
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/errno.h>
#include <sys/exec.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/model.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/cmn_err.h>
#include <sys/archsystm.h>
#include <sys/pathname.h>
#include <sys/sunddi.h>

#include <sys/machbrand.h>
#include <sys/brand.h>
#include "s10_brand.h"

char *s10_emulation_table = NULL;

void	s10_init_brand_data(zone_t *);
void	s10_free_brand_data(zone_t *);
void	s10_setbrand(proc_t *);
int	s10_getattr(zone_t *, int, void *, size_t *);
int	s10_setattr(zone_t *, int, void *, size_t);
int	s10_brandsys(int, int64_t *, uintptr_t, uintptr_t, uintptr_t,
		uintptr_t, uintptr_t, uintptr_t);
void	s10_copy_procdata(proc_t *, proc_t *);
void	s10_proc_exit(struct proc *, klwp_t *);
void	s10_exec();
int	s10_initlwp(klwp_t *);
void	s10_forklwp(klwp_t *, klwp_t *);
void	s10_freelwp(klwp_t *);
void	s10_lwpexit(klwp_t *);
int	s10_elfexec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
	long *, int, caddr_t, cred_t *, int);
void	s10_sigset_native_to_s10(sigset_t *);
void	s10_sigset_s10_to_native(sigset_t *);

/* s10 brand */
struct brand_ops s10_brops = {
	s10_init_brand_data,
	s10_free_brand_data,
	s10_brandsys,
	s10_setbrand,
	s10_getattr,
	s10_setattr,
	s10_copy_procdata,
	s10_proc_exit,
	s10_exec,
	lwp_setrval,
	s10_initlwp,
	s10_forklwp,
	s10_freelwp,
	s10_lwpexit,
	s10_elfexec,
	s10_sigset_native_to_s10,
	s10_sigset_s10_to_native,
	S10_NSIG,
};

#ifdef	sparc

struct brand_mach_ops s10_mops = {
	s10_brand_syscall_callback,
	s10_brand_syscall32_callback
};

#else	/* sparc */

#ifdef	__amd64

struct brand_mach_ops s10_mops = {
	s10_brand_sysenter_callback,
	s10_brand_int91_callback,
	s10_brand_syscall_callback,
	s10_brand_syscall32_callback
};

#else	/* ! __amd64 */

struct brand_mach_ops s10_mops = {
	s10_brand_sysenter_callback,
	NULL,
	s10_brand_syscall_callback,
	NULL
};
#endif	/* __amd64 */

#endif	/* _sparc */

struct brand	s10_brand = {
	BRAND_VER_1,
	"solaris10",
	&s10_brops,
	&s10_mops
};

static struct modlbrand modlbrand = {
	&mod_brandops,		/* type of module */
	"Solaris 10 Brand",	/* description of module */
	&s10_brand		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlbrand, NULL
};

void
s10_setbrand(proc_t *p)
{
	brand_solaris_setbrand(p, &s10_brand);
}

/*ARGSUSED*/
int
s10_getattr(zone_t *zone, int attr, void *buf, size_t *bufsize)
{
	ASSERT(zone->zone_brand == &s10_brand);
	if (attr == S10_EMUL_BITMAP) {
		if (buf == NULL || *bufsize != sizeof (s10_emul_bitmap_t))
			return (EINVAL);
		if (copyout(((s10_zone_data_t *)zone->zone_brand_data)->
		    emul_bitmap, buf, sizeof (s10_emul_bitmap_t)) != 0)
			return (EFAULT);
		return (0);
	}

	return (EINVAL);
}

int
s10_setattr(zone_t *zone, int attr, void *buf, size_t bufsize)
{
	ASSERT(zone->zone_brand == &s10_brand);
	if (attr == S10_EMUL_BITMAP) {
		if (buf == NULL || bufsize != sizeof (s10_emul_bitmap_t))
			return (EINVAL);
		if (copyin(buf, ((s10_zone_data_t *)zone->zone_brand_data)->
		    emul_bitmap, sizeof (s10_emul_bitmap_t)) != 0)
			return (EFAULT);
		return (0);
	}

	return (EINVAL);
}

#ifdef	__amd64
/*
 * The Nevada kernel clears %fs for threads in 64-bit x86 processes but S10's
 * libc expects %fs to be nonzero.  This causes some committed
 * libc/libthread interfaces (e.g., thr_main()) to fail, which impacts several
 * libraries, including libdoor.  This function sets the specified LWP's %fs
 * register to the legacy S10 selector value (LWPFS_SEL).
 *
 * The best solution to the aforementioned problem is backporting CRs
 * 6467491 to Solaris 10 so that 64-bit x86 Solaris 10 processes
 * would accept zero for %fs.  Backporting the CRs is a requirement for running
 * S10 Containers in PV domUs because 64-bit Xen clears %fsbase when %fs is
 * nonzero.  Such behavior breaks 64-bit processes because Xen has to fetch the
 * FS segments' base addresses from the LWPs' GDTs, which are only capable of
 * 32-bit addressing.
 */
/*ARGSUSED*/
static void
s10_amd64_correct_fsreg(klwp_t *l)
{
	if (lwp_getdatamodel(l) == DATAMODEL_NATIVE) {
		kpreempt_disable();
		l->lwp_pcb.pcb_fs = LWPFS_SEL;
		l->lwp_pcb.pcb_rupdate = 1;
		lwptot(l)->t_post_sys = 1;	/* Guarantee update_sregs() */
		kpreempt_enable();
	}
}
#endif	/* __amd64 */

/*
 * Native processes are started with the native ld.so.1 as the command.  This
 * brand op is invoked by s10_npreload to fix up the command and arguments
 * so that apps like pgrep or ps see the expected command strings.
 */
int
s10_native(void *cmd, void *args)
{
	struct user	*up = PTOU(curproc);
	char		cmd_buf[MAXCOMLEN + 1];
	char		arg_buf[PSARGSZ];

	if (copyin(cmd, &cmd_buf, sizeof (cmd_buf)) != 0)
		return (EFAULT);
	if (copyin(args, &arg_buf, sizeof (arg_buf)) != 0)
		return (EFAULT);

	/*
	 * Make sure that the process' interpreter is the native dynamic linker.
	 * Convention dictates that native processes executing within solaris10-
	 * branded zones are interpreted by the native dynamic linker (the
	 * process and its arguments are specified as arguments to the dynamic
	 * linker).  If this convention is violated (i.e.,
	 * brandsys(B_S10_NATIVE, ...) is invoked by a process that shouldn't be
	 * native), then do nothing and silently indicate success.
	 */
	if (strcmp(up->u_comm, S10_LINKER_NAME) != 0)
		return (0);

	/*
	 * The sizeof has an extra value for the trailing '\0' so this covers
	 * the appended " " in the following strcmps.
	 */
	if (strncmp(up->u_psargs, BRAND_NATIVE_LINKER64 " ",
	    sizeof (BRAND_NATIVE_LINKER64)) != 0 &&
	    strncmp(up->u_psargs, BRAND_NATIVE_LINKER32 " ",
	    sizeof (BRAND_NATIVE_LINKER32)) != 0)
		return (0);

	mutex_enter(&curproc->p_lock);
	(void) strlcpy(up->u_comm, cmd_buf, sizeof (up->u_comm));
	(void) strlcpy(up->u_psargs, arg_buf, sizeof (up->u_psargs));
	mutex_exit(&curproc->p_lock);

	return (0);
}

/*ARGSUSED*/
int
s10_brandsys(int cmd, int64_t *rval, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	proc_t	*p = curproc;
	int	res;

	*rval = 0;

	if (cmd == B_S10_NATIVE)
		return (s10_native((void *)arg1, (void *)arg2));

	res = brand_solaris_cmd(cmd, arg1, arg2, arg3, &s10_brand, S10_VERSION);
	if (res >= 0)
		return (res);

	switch ((cmd)) {
	case B_S10_PIDINFO:
		/*
		 * The s10 brand needs to be able to get the pid of the
		 * current process and the pid of the zone's init, and it
		 * needs to do this on every process startup.  Early in
		 * brand startup, we can't call getpid() because calls to
		 * getpid() represent a magical signal to some old-skool
		 * debuggers.  By merging all of this into one call, we
		 * make this quite a bit cheaper and easier to handle in
		 * the brand module.
		 */
		if (copyout(&p->p_pid, (void *)arg1, sizeof (pid_t)) != 0)
			return (EFAULT);
		if (copyout(&p->p_zone->zone_proc_initpid, (void *)arg2,
		    sizeof (pid_t)) != 0)
			return (EFAULT);
		return (0);

	case B_S10_ISFDXATTRDIR: {
		/*
		 * This subcommand enables the userland brand emulation library
		 * to determine whether a file descriptor refers to an extended
		 * file attributes directory.  There is no standard syscall or
		 * libc function that can make such a determination.
		 */
		file_t *dir_filep;

		dir_filep = getf((int)arg1);
		if (dir_filep == NULL)
			return (EBADF);
		ASSERT(dir_filep->f_vnode != NULL);
		*rval = IS_XATTRDIR(dir_filep->f_vnode);
		releasef((int)arg1);
		return (0);
	}

#ifdef	__amd64
	case B_S10_FSREGCORRECTION:
		/*
		 * This subcommand exists so that the SYS_lwp_private and
		 * SYS_lwp_create syscalls can manually set the current thread's
		 * %fs register to the legacy S10 selector value for 64-bit x86
		 * processes.
		 */
		s10_amd64_correct_fsreg(ttolwp(curthread));
		return (0);
#endif	/* __amd64 */
	}

	return (EINVAL);
}

void
s10_copy_procdata(proc_t *child, proc_t *parent)
{
	brand_solaris_copy_procdata(child, parent, &s10_brand);
}

void
s10_proc_exit(struct proc *p, klwp_t *l)
{
	brand_solaris_proc_exit(p, l, &s10_brand);
}

void
s10_exec()
{
	brand_solaris_exec(&s10_brand);
}

int
s10_initlwp(klwp_t *l)
{
	return (brand_solaris_initlwp(l, &s10_brand));
}

void
s10_forklwp(klwp_t *p, klwp_t *c)
{
	brand_solaris_forklwp(p, c, &s10_brand);

#ifdef	__amd64
	/*
	 * Only correct the child's %fs register if the parent's %fs register
	 * is LWPFS_SEL.  If the parent's %fs register is zero, then the Solaris
	 * 10 environment that we're emulating uses a version of libc that
	 * works when %fs is zero (i.e., it contains backports of CRs 6467491
	 * and 6501650).
	 */
	if (p->lwp_pcb.pcb_fs == LWPFS_SEL)
		s10_amd64_correct_fsreg(c);
#endif	/* __amd64 */
}

void
s10_freelwp(klwp_t *l)
{
	brand_solaris_freelwp(l, &s10_brand);
}

void
s10_lwpexit(klwp_t *l)
{
	brand_solaris_lwpexit(l, &s10_brand);
}

void
s10_free_brand_data(zone_t *zone)
{
	kmem_free(zone->zone_brand_data, sizeof (s10_zone_data_t));
}

void
s10_init_brand_data(zone_t *zone)
{
	ASSERT(zone->zone_brand == &s10_brand);
	ASSERT(zone->zone_brand_data == NULL);
	zone->zone_brand_data = kmem_zalloc(sizeof (s10_zone_data_t), KM_SLEEP);
}

int
s10_elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
	int level, long *execsz, int setid, caddr_t exec_file, cred_t *cred,
	int brand_action)
{
	return (brand_solaris_elfexec(vp, uap, args, idatap, level, execsz,
	    setid, exec_file, cred, brand_action, &s10_brand, S10_BRANDNAME,
	    S10_LIB, S10_LIB32, S10_LINKER, S10_LINKER32));
}

void
s10_sigset_native_to_s10(sigset_t *set)
{
	int nativesig;
	int s10sig;
	sigset_t s10set;

	/*
	 * Shortcut: we know the first 32 signals are the same in both
	 * s10 and native Solaris.  Just assign the first word.
	 */
	s10set.__sigbits[0] = set->__sigbits[0];
	s10set.__sigbits[1] = 0;
	s10set.__sigbits[2] = 0;
	s10set.__sigbits[3] = 0;

	/*
	 * Copy the remainder of the initial set of common signals.
	 */
	for (nativesig = 33; nativesig < S10_SIGRTMIN; nativesig++)
		if (sigismember(set, nativesig))
			sigaddset(&s10set, nativesig);

	/*
	 * Convert any native RT signals to their S10 values.
	 */
	for (nativesig = _SIGRTMIN, s10sig = S10_SIGRTMIN;
	    nativesig <= _SIGRTMAX && s10sig <= S10_SIGRTMAX;
	    nativesig++, s10sig++) {
		if (sigismember(set, nativesig))
			sigaddset(&s10set, s10sig);
	}

	*set = s10set;
}

void
s10_sigset_s10_to_native(sigset_t *set)
{
	int s10sig;
	int nativesig;
	sigset_t nativeset;

	/*
	 * Shortcut: we know the first 32 signals are the same in both
	 * s10 and native Solaris.  Just assign the first word.
	 */
	nativeset.__sigbits[0] = set->__sigbits[0];
	nativeset.__sigbits[1] = 0;
	nativeset.__sigbits[2] = 0;
	nativeset.__sigbits[3] = 0;

	/*
	 * Copy the remainder of the initial set of common signals.
	 */
	for (s10sig = 33; s10sig < S10_SIGRTMIN; s10sig++)
		if (sigismember(set, s10sig))
			sigaddset(&nativeset, s10sig);

	/*
	 * Convert any S10 RT signals to their native values.
	 */
	for (s10sig = S10_SIGRTMIN, nativesig = _SIGRTMIN;
	    s10sig <= S10_SIGRTMAX && nativesig <= _SIGRTMAX;
	    s10sig++, nativesig++) {
		if (sigismember(set, s10sig))
			sigaddset(&nativeset, nativesig);
	}

	*set = nativeset;
}

int
_init(void)
{
	int err;

	/*
	 * Set up the table indicating which system calls we want to
	 * interpose on.  We should probably build this automatically from
	 * a list of system calls that is shared with the user-space
	 * library.
	 */
	s10_emulation_table = kmem_zalloc(NSYSCALL, KM_SLEEP);
	s10_emulation_table[S10_SYS_forkall] = 1;		/*   2 */
	s10_emulation_table[S10_SYS_open] = 1;			/*   5 */
	s10_emulation_table[S10_SYS_wait] = 1;			/*   7 */
	s10_emulation_table[S10_SYS_creat] = 1;			/*   8 */
	s10_emulation_table[S10_SYS_link] = 1;			/*   9 */
	s10_emulation_table[S10_SYS_unlink] = 1;		/*  10 */
	s10_emulation_table[S10_SYS_exec] = 1;			/*  11 */
	s10_emulation_table[S10_SYS_mknod] = 1;			/*  14 */
	s10_emulation_table[S10_SYS_chmod] = 1;			/*  15 */
	s10_emulation_table[S10_SYS_chown] = 1;			/*  16 */
	s10_emulation_table[S10_SYS_stat] = 1;			/*  18 */
	s10_emulation_table[S10_SYS_umount] = 1;		/*  22 */
	s10_emulation_table[S10_SYS_fstat] = 1;			/*  28 */
	s10_emulation_table[S10_SYS_utime] = 1;			/*  30 */
	s10_emulation_table[S10_SYS_access] = 1;		/*  33 */
	s10_emulation_table[SYS_kill] = 1;			/*  37 */
	s10_emulation_table[S10_SYS_dup] = 1;			/*  41 */
	s10_emulation_table[S10_SYS_pipe] = 1;			/*  42 */
	s10_emulation_table[SYS_ioctl] = 1;			/*  54 */
	s10_emulation_table[SYS_execve] = 1;			/*  59 */
	s10_emulation_table[SYS_acctctl] = 1;			/*  71 */
	s10_emulation_table[S10_SYS_issetugid] = 1;		/*  75 */
	s10_emulation_table[S10_SYS_fsat] = 1;			/*  76 */
	s10_emulation_table[S10_SYS_rmdir] = 1;			/*  79 */
	s10_emulation_table[S10_SYS_mkdir] = 1;			/*  80 */
	s10_emulation_table[SYS_getdents] = 1;			/*  81 */
	s10_emulation_table[S10_SYS_poll] = 1;			/*  87 */
	s10_emulation_table[S10_SYS_lstat] = 1;			/*  88 */
	s10_emulation_table[S10_SYS_symlink] = 1;		/*  89 */
	s10_emulation_table[S10_SYS_readlink] = 1;		/*  90 */
	s10_emulation_table[S10_SYS_fchmod] = 1;		/*  93 */
	s10_emulation_table[S10_SYS_fchown] = 1;		/*  94 */
	s10_emulation_table[SYS_sigprocmask] = 1;		/*  95 */
	s10_emulation_table[SYS_sigsuspend] = 1;		/*  96 */
	s10_emulation_table[SYS_sigaction] = 1;			/*  98 */
	s10_emulation_table[SYS_sigpending] = 1;		/*  99 */
	s10_emulation_table[SYS_waitid] = 1;			/* 107 */
	s10_emulation_table[SYS_sigsendsys] = 1;		/* 108 */
#if defined(__x86)
	s10_emulation_table[S10_SYS_xstat] = 1;			/* 123 */
	s10_emulation_table[S10_SYS_lxstat] = 1;		/* 124 */
	s10_emulation_table[S10_SYS_fxstat] = 1;		/* 125 */
	s10_emulation_table[S10_SYS_xmknod] = 1;		/* 126 */
#endif
	s10_emulation_table[S10_SYS_lchown] = 1;		/* 130 */
	s10_emulation_table[S10_SYS_rename] = 1;		/* 134 */
	s10_emulation_table[SYS_uname] = 1;			/* 135 */
	s10_emulation_table[SYS_sysconfig] = 1;			/* 137 */
	s10_emulation_table[SYS_systeminfo] = 1;		/* 139 */
	s10_emulation_table[S10_SYS_fork1] = 1;			/* 143 */
	s10_emulation_table[SYS_sigtimedwait] = 1;		/* 144 */
	s10_emulation_table[S10_SYS_lwp_sema_wait] = 1;		/* 147 */
	s10_emulation_table[S10_SYS_utimes] = 1;		/* 154 */
	s10_emulation_table[SYS_lwp_create] = 1;		/* 159 */
	s10_emulation_table[SYS_lwp_kill] = 1;			/* 163 */
	s10_emulation_table[SYS_lwp_sigmask] = 1;		/* 165 */
#if defined(__amd64)
	s10_emulation_table[SYS_lwp_private] = 1;		/* 166 */
#endif	/* __amd64 */
	s10_emulation_table[S10_SYS_lwp_mutex_lock] = 1;	/* 169 */
	s10_emulation_table[SYS_pwrite] = 1;			/* 174 */
	s10_emulation_table[SYS_acl] = 1;			/* 185 */
	s10_emulation_table[SYS_auditsys] = 1;			/* 186 */
	s10_emulation_table[SYS_sigqueue] = 1;			/* 190 */
	s10_emulation_table[SYS_facl] = 1;			/* 200 */
	s10_emulation_table[SYS_signotify] = 1;			/* 205 */
	s10_emulation_table[SYS_lwp_mutex_timedlock] = 1;	/* 210 */
	s10_emulation_table[SYS_getdents64] = 1;		/* 213 */
	s10_emulation_table[S10_SYS_stat64] = 1;		/* 215 */
	s10_emulation_table[S10_SYS_lstat64] = 1;		/* 216 */
	s10_emulation_table[S10_SYS_fstat64] = 1;		/* 217 */
	s10_emulation_table[SYS_pwrite64] = 1;			/* 223 */
	s10_emulation_table[S10_SYS_creat64] = 1;		/* 224 */
	s10_emulation_table[S10_SYS_open64] = 1;		/* 225 */
	s10_emulation_table[SYS_zone] = 1;			/* 227 */
	s10_emulation_table[S10_SYS_so_socket] = 1;		/* 230 */
	s10_emulation_table[S10_SYS_accept] = 1;		/* 234 */
	s10_emulation_table[SYS_lwp_mutex_trylock] = 1;		/* 251 */

	err = mod_install(&modlinkage);
	if (err) {
		cmn_err(CE_WARN, "Couldn't install brand module");
		kmem_free(s10_emulation_table, NSYSCALL);
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (brand_solaris_fini(&s10_emulation_table, &modlinkage,
	    &s10_brand));
}

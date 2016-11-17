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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/model.h>
#include <sys/privregs.h>
#include <sys/brand.h>
#include <sys/machbrand.h>
#include <sys/sdt.h>
#include <sys/lx_syscalls.h>
#include <sys/lx_brand.h>
#include <sys/lx_impl.h>
#include <sys/lx_misc.h>
#include <lx_errno.h>


/*
 * Flags for sysent entries:
 */
#define	LX_SYS_NOSYS_REASON	0x07
#define	LX_SYS_EBPARG6		0x08

/*
 * Flags that denote the specific reason we do not have a particular system
 * call.  These reasons are only valid if the function is NULL.
 */
#define	NOSYS_USERMODE		0
#define	NOSYS_NULL		1
#define	NOSYS_NONE		2
#define	NOSYS_NO_EQUIV		3
#define	NOSYS_KERNEL		4
#define	NOSYS_UNDOC		5
#define	NOSYS_OBSOLETE		6
#define	NOSYS_MAX		NOSYS_OBSOLETE

#if NOSYS_MAX > LX_SYS_NOSYS_REASON
#error NOSYS reason codes must fit in LX_SYS_NOSYS_REASON
#endif

/*
 * Strings describing the reason we do not emulate a particular system call
 * in the kernel.
 */
static char *nosys_reasons[] = {
	NULL, /* NOSYS_USERMODE means this call is emulated in usermode */
	"Not done yet",
	"No such Linux system call",
	"No equivalent illumos functionality",
	"Reads/modifies Linux kernel state",
	"Undocumented and/or rarely used system call",
	"Unsupported, obsolete system call"
};


#if defined(_LP64)
/*
 * System call handler table and entry count for Linux x86_64 (amd64):
 */
lx_sysent_t lx_sysent64[LX_NSYSCALLS + 1];
int lx_nsysent64;
#endif
/*
 * System call handler table and entry count for Linux x86 (i386):
 */
lx_sysent_t lx_sysent32[LX_NSYSCALLS + 1];
int lx_nsysent32;

#if defined(_LP64)
struct lx_vsyscall
{
	uintptr_t lv_addr;
	uintptr_t lv_scnum;
} lx_vsyscalls[] = {
	{ LX_VSYS_gettimeofday, LX_SYS_gettimeofday },
	{ LX_VSYS_time, LX_SYS_time },
	{ LX_VSYS_getcpu, LX_SYS_getcpu },
	{ NULL, NULL }
};
#endif

#if defined(__amd64)
static int
lx_emulate_args(klwp_t *lwp, const lx_sysent_t *s, uintptr_t *args)
{
	struct regs *rp = lwptoregs(lwp);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		/*
		 * Note: Syscall argument passing is different from function
		 * call argument passing on amd64.  For function calls, the
		 * fourth arg is passed via %rcx, but for system calls the 4th
		 * arg is passed via %r10.  This is because in amd64, the
		 * syscall instruction puts the lower 32 bits of %rflags in
		 * %r11 and puts the %rip value to %rcx.
		 *
		 * Appendix A of the amd64 ABI (Linux conventions) states that
		 * syscalls are limited to 6 args and no arg is passed on the
		 * stack.
		 */
		args[0] = rp->r_rdi;
		args[1] = rp->r_rsi;
		args[2] = rp->r_rdx;
		args[3] = rp->r_r10;
		args[4] = rp->r_r8;
		args[5] = rp->r_r9;
	} else {
		/*
		 * If the system call takes 6 args, then libc has stashed them
		 * in memory at the address contained in %ebx. Except for some
		 * syscalls which store the 6th argument in %ebp.
		 */
		if (s->sy_narg == 6 && !(s->sy_flags & LX_SYS_EBPARG6)) {
			uint32_t args32[6];

			if (copyin((void *)rp->r_rbx, &args32,
			    sizeof (args32)) != 0) {
				/*
				 * Clear the argument vector so that the
				 * trace probe does not expose kernel
				 * memory.
				 */
				bzero(args, 6 * sizeof (uintptr_t));
				return (set_errno(EFAULT));
			}

			args[0] = args32[0];
			args[1] = args32[1];
			args[2] = args32[2];
			args[3] = args32[3];
			args[4] = args32[4];
			args[5] = args32[5];
		} else {
			args[0] = rp->r_rbx;
			args[1] = rp->r_rcx;
			args[2] = rp->r_rdx;
			args[3] = rp->r_rsi;
			args[4] = rp->r_rdi;
			args[5] = rp->r_rbp;
		}
	}

	return (0);
}

#else	/* !__amd64 */

static int
lx_emulate_args(klwp_t *lwp, const lx_sysent_t *s, uintptr_t *args)
{
	struct regs *rp = lwptoregs(lwp);

	/*
	 * If the system call takes 6 args, then libc has stashed them
	 * in memory at the address contained in %ebx. Except for some
	 * syscalls which store the 6th argument in %ebp.
	 */
	if (s->sy_narg == 6 && !(s->sy_flags & LX_SYS_EBPARG6)) {
		if (copyin((void *)rp->r_ebx, args, 6 * sizeof (uintptr_t)) !=
		    0) {
			/*
			 * Clear the argument vector so that the trace probe
			 * does not expose kernel memory.
			 */
			bzero(args, 6 * sizeof (uintptr_t));
			return (set_errno(EFAULT));
		}
	} else {
		args[0] = rp->r_ebx;
		args[1] = rp->r_ecx;
		args[2] = rp->r_edx;
		args[3] = rp->r_esi;
		args[4] = rp->r_edi;
		args[5] = rp->r_ebp;
	}

	return (0);
}
#endif

void
lx_syscall_return(klwp_t *lwp, int syscall_num, long ret)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	int error = lwp->lwp_errno;

	if (error != EINTR) {
		/*
		 * If this system call was not interrupted, clear the system
		 * call restart flag before lx_setcontext() can pass it to
		 * usermode.
		 */
		lwpd->br_syscall_restart = B_FALSE;
	}

	if (error != 0) {
		/*
		 * Convert from illumos to Linux errno:
		 */
		ret = -lx_errno(error, EINVAL);
	}

	/*
	 * 32-bit Linux system calls return via %eax; 64-bit calls return via
	 * %rax.
	 */
	rp->r_r0 = ret;

	/*
	 * Hold for the ptrace(2) "syscall-exit-stop" condition if required by
	 * PTRACE_SYSCALL.  Note that the register state may be modified by
	 * tracer.
	 */
	(void) lx_ptrace_stop(LX_PR_SYSEXIT);

	/*
	 * Fire the DTrace "lx-syscall:::return" probe:
	 */
	lx_trace_sysreturn(syscall_num, ret);

	/*
	 * Clear errno for next time.  We do not clear "br_syscall_restart" or
	 * "br_syscall_num" as they are potentially used by "lx_savecontext()"
	 * in the signal delivery path.
	 */
	lwp->lwp_errno = 0;

	lx_check_strict_failure(lwpd);

	/*
	 * We want complete control of the registers on return from this
	 * emulated Linux system call:
	 */
	lwp->lwp_eosys = JUSTRETURN;
}

static void
lx_syscall_unsup_msg(lx_sysent_t *s, int syscall_num, int unsup_reason)
{
	char buf[100];

	if (s == NULL) {
		(void) snprintf(buf, sizeof (buf), "NOSYS (%d): out of bounds",
		    syscall_num);
	} else {
		VERIFY(unsup_reason < (sizeof (nosys_reasons) /
		    sizeof (*nosys_reasons)));

		if (s->sy_name == NULL) {
			(void) snprintf(buf, sizeof (buf), "NOSYS (%d): %s",
			    syscall_num, nosys_reasons[unsup_reason]);
		} else {
			(void) snprintf(buf, sizeof (buf), "NOSYS (%s): %s",
			    s->sy_name, nosys_reasons[unsup_reason]);
		}
	}

	lx_unsupported(buf);
}

/*
 * This function is used to override the processing of arguments and
 * invocation of a handler for emulated system calls, installed on each
 * branded LWP as "lwp_brand_syscall".  If this system call should use the
 * native path, we return 1.  If we handled this system call (and have made
 * arrangements with respect to post-return usermode register state) we
 * return 0.
 */
int
lx_syscall_enter(void)
{
	klwp_t *lwp = ttolwp(curthread);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	int syscall_num;
	int error;
	long ret = 0;
	lx_sysent_t *s;
	uintptr_t args[6];
	unsigned int unsup_reason;

	/*
	 * If we got here, we should have an LWP-specific brand data
	 * structure.
	 */
	VERIFY(lwpd != NULL);

	if (lwpd->br_stack_mode != LX_STACK_MODE_BRAND) {
		/*
		 * The lwp is not in in BRAND execution mode, so we return
		 * to the regular native system call path.
		 */
		DTRACE_PROBE(brand__lx__syscall__hook__skip);
		return (1);
	}

	/*
	 * Clear the restartable system call flag.  This flag will be set
	 * on in the system call handler if the call is a candidate for
	 * a restart.  It will be saved by lx_setcontext() in the event
	 * that we take a signal, and used in the signal handling path
	 * to restart the system call iff SA_RESTART was set for this
	 * signal.  Save the system call number so that we can store it
	 * in the saved context if required.
	 */
	lwpd->br_syscall_restart = B_FALSE;
	lwpd->br_syscall_num = (int)rp->r_r0;

	/*
	 * Hold for the ptrace(2) "syscall-entry-stop" condition if traced by
	 * PTRACE_SYSCALL.  The system call number and arguments may be
	 * modified by the tracer.
	 */
	(void) lx_ptrace_stop(LX_PR_SYSENTRY);

	/*
	 * Check that the system call number is within the bounds we expect.
	 */
	syscall_num = lwpd->br_syscall_num;
	if (syscall_num < 0 || syscall_num > LX_MAX_SYSCALL(lwp)) {
		lx_syscall_unsup_msg(NULL, syscall_num, 0);

		(void) set_errno(ENOTSUP);
		lx_syscall_return(lwp, syscall_num, -1);
		return (0);
	}

#if defined(_LP64)
	if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
		s = &lx_sysent64[syscall_num];
	} else
#endif
	{
		s = &lx_sysent32[syscall_num];
	}

	/*
	 * Process the arguments for this system call and fire the DTrace
	 * "lx-syscall:::entry" probe:
	 */
	error = lx_emulate_args(lwp, s, args);
	lx_trace_sysenter(syscall_num, args);
	if (error != 0) {
		/*
		 * Could not read and process the arguments.  Return the error
		 * to the process.
		 */
		(void) set_errno(error);
		lx_syscall_return(lwp, syscall_num, -1);
		return (0);
	}

	if (s->sy_callc != NULL) {
		/*
		 * Call the in-kernel handler for this Linux system call:
		 */
		lwpd->br_eosys = NORMALRETURN;
		ret = s->sy_callc(args[0], args[1], args[2], args[3], args[4],
		    args[5]);
		if (lwpd->br_eosys == NORMALRETURN) {
			lx_syscall_return(lwp, syscall_num, ret);
		}
		return (0);
	}

	/*
	 * There is no in-kernel handler.
	 */
	switch (unsup_reason = (s->sy_flags & LX_SYS_NOSYS_REASON)) {
	case NOSYS_USERMODE:
		/*
		 * Pass to the usermode emulation routine.
		 */
#if defined(_LP64)
		if (get_udatamodel() != DATAMODEL_NATIVE) {
			lx_emulate_user32(lwp, syscall_num, args);
		} else
#endif
		{
			lx_emulate_user(lwp, syscall_num, args);
		}
		return (0);

	default:
		/*
		 * We are not emulating this system call at all.
		 */
		lx_syscall_unsup_msg(s, syscall_num, unsup_reason);

		(void) set_errno(ENOTSUP);
		lx_syscall_return(lwp, syscall_num, -1);
		return (0);
	}
}

#if defined(_LP64)
/*
 * Emulate vsyscall support.
 *
 * Linux magically maps a single page into the address space of each process,
 * allowing them to make 'vsyscalls'.  Originally designed to counteract the
 * perceived overhead of regular system calls, vsyscalls were implemented as
 * code residing in userspace which could be called directly.  The userspace
 * implementations of these vsyscalls which have now been replaced by
 * instructions which vector into the normal syscall path.
 *
 * Implementing vsyscalls on Illumos is complicated by the fact that the
 * required static address region resides inside the kernel address space.
 * Rather than mapping a user-accessible page into the KAS, a different
 * approach is taken.  The vsyscall gate is emulated by interposing on
 * pagefaults in trap().  An attempt to execute a known vsyscall address will
 * result in emulating the appropriate system call rather than inducing a
 * SIGSEGV.
 */
void
lx_vsyscall_enter(proc_t *p, klwp_t *lwp, int scnum)
{
	struct regs *rp = lwptoregs(lwp);
	uintptr_t raddr;

	/*
	 * Fetch the return address from the process stack.
	 */
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));
	if (copyin((void *)rp->r_rsp, &raddr, sizeof (raddr)) != 0) {
#if DEBUG
		printf("lx_vsyscall_call: bad brand stack at vsyscall "
		    "cmd=%s, pid=%d, sp=0x%p\n", PTOU(p)->u_comm,
		    p->p_pid, (void *)rp->r_rsp);
#endif

		/*
		 * The process jumped to the vsyscall address without a
		 * correctly configured stack.  Terminate the process.
		 */
		exit(CLD_KILLED, SIGSEGV);
		return;
	}

	DTRACE_PROBE1(brand__lx__vsyscall, int, scnum);

	/* Simulate vectoring into the syscall */
	rp->r_rax = scnum;
	rp->r_rip = raddr;
	rp->r_rsp += sizeof (uintptr_t);

	(void) lx_syscall_enter();
}

boolean_t
lx_vsyscall_iscall(klwp_t *lwp, uintptr_t addr, int *scnum)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	int i;

	if (lwpd->br_stack_mode != LX_STACK_MODE_BRAND) {
		/*
		 * We only handle vsyscalls when running Linux code.
		 */
		return (B_FALSE);
	}

	if (addr < LX_VSYSCALL_ADDR ||
	    addr >= (LX_VSYSCALL_ADDR + LX_VSYSCALL_SIZE)) {
		/*
		 * Ignore faults outside the vsyscall page.
		 */
		return (B_FALSE);
	}

	for (i = 0; lx_vsyscalls[i].lv_addr != NULL; i++) {
		if (addr == lx_vsyscalls[i].lv_addr) {
			/*
			 * This is a valid vsyscall address.
			 */
			*scnum = lx_vsyscalls[i].lv_scnum;
			return (B_TRUE);
		}
	}

	lx_unsupported("bad vsyscall access");
	return (B_FALSE);
}
#endif

/*
 * Linux defines system call numbers for 32-bit x86 in the file:
 *   arch/x86/syscalls/syscall_32.tbl
 */
lx_sysent_t lx_sysent32[] = {
	{"nosys",	NULL,			NOSYS_NONE,	0}, /*  0 */
	{"exit",	NULL,			0,		1}, /*  1 */
	{"fork",	NULL,			0,		0}, /*  2 */
	{"read",	lx_read,		0,		3}, /*  3 */
	{"write",	lx_write,		0,		3}, /*  4 */
	{"open",	lx_open,		0,		3}, /*  5 */
	{"close",	lx_close,		0,		1}, /*  6 */
	{"waitpid",	lx_waitpid,		0,		3}, /*  7 */
	{"creat",	lx_creat,		0,		2}, /*  8 */
	{"link",	lx_link,		0,		2}, /*  9 */
	{"unlink",	lx_unlink,		0,		1}, /* 10 */
	{"execve",	NULL,			0,		3}, /* 11 */
	{"chdir",	lx_chdir,		0,		1}, /* 12 */
	{"time",	lx_time,		0,		1}, /* 13 */
	{"mknod",	NULL,			0,		3}, /* 14 */
	{"chmod",	lx_chmod,		0,		2}, /* 15 */
	{"lchown16",	lx_lchown16,		0,		3}, /* 16 */
	{"break",	NULL,			NOSYS_OBSOLETE,	0}, /* 17 */
	{"stat",	NULL,			NOSYS_OBSOLETE,	0}, /* 18 */
	{"lseek",	lx_lseek32,		0,		3}, /* 19 */
	{"getpid",	lx_getpid,		0,		0}, /* 20 */
	{"mount",	lx_mount,		0,		5}, /* 21 */
	{"umount",	lx_umount,		0,		1}, /* 22 */
	{"setuid16",	lx_setuid16,		0,		1}, /* 23 */
	{"getuid16",	lx_getuid16,		0,		0}, /* 24 */
	{"stime",	lx_stime,		0,		1}, /* 25 */
	{"ptrace",	lx_ptrace,		0,		4}, /* 26 */
	{"alarm",	lx_alarm,		0,		1}, /* 27 */
	{"fstat",	NULL,			NOSYS_OBSOLETE,	0}, /* 28 */
	{"pause",	lx_pause,		0,		0}, /* 29 */
	{"utime",	NULL,			0,		2}, /* 30 */
	{"stty",	NULL,			NOSYS_OBSOLETE,	0}, /* 31 */
	{"gtty",	NULL,			NOSYS_OBSOLETE,	0}, /* 32 */
	{"access",	lx_access,		0,		2}, /* 33 */
	{"nice",	lx_nice,		0,		1}, /* 34 */
	{"ftime",	NULL,			NOSYS_OBSOLETE,	0}, /* 35 */
	{"sync",	lx_sync,		0, 		0}, /* 36 */
	{"kill",	lx_kill,		0,		2}, /* 37 */
	{"rename",	lx_rename,		0,		2}, /* 38 */
	{"mkdir",	lx_mkdir,		0,		2}, /* 39 */
	{"rmdir",	NULL,			0,		1}, /* 40 */
	{"dup",		lx_dup,			0,		1}, /* 41 */
	{"pipe",	lx_pipe,		0,		1}, /* 42 */
	{"times",	NULL,			0,		1}, /* 43 */
	{"prof",	NULL,			NOSYS_OBSOLETE,	0}, /* 44 */
	{"brk",		lx_brk,			0,		1}, /* 45 */
	{"setgid16",	lx_setgid16,		0,		1}, /* 46 */
	{"getgid16",	lx_getgid16,		0,		0}, /* 47 */
	{"signal",	NULL,			0,		2}, /* 48 */
	{"geteuid16",	lx_geteuid16,		0,		0}, /* 49 */
	{"getegid16",	lx_getegid16,		0,		0}, /* 50 */
	{"acct",	NULL,			NOSYS_NO_EQUIV,	0}, /* 51 */
	{"umount2",	lx_umount2,		0,		2}, /* 52 */
	{"lock",	NULL,			NOSYS_OBSOLETE,	0}, /* 53 */
	{"ioctl",	lx_ioctl,		0,		3}, /* 54 */
	{"fcntl",	lx_fcntl,		0,		3}, /* 55 */
	{"mpx",		NULL,			NOSYS_OBSOLETE,	0}, /* 56 */
	{"setpgid",	lx_setpgid,		0,		2}, /* 57 */
	{"ulimit",	NULL,			NOSYS_OBSOLETE,	0}, /* 58 */
	{"olduname",	NULL,			NOSYS_OBSOLETE,	0}, /* 59 */
	{"umask",	lx_umask,		0,		1}, /* 60 */
	{"chroot",	lx_chroot,		0,		1}, /* 61 */
	{"ustat",	NULL,			NOSYS_OBSOLETE,	2}, /* 62 */
	{"dup2",	lx_dup2,		0,		2}, /* 63 */
	{"getppid",	lx_getppid,		0,		0}, /* 64 */
	{"getpgrp",	lx_getpgrp,		0,		0}, /* 65 */
	{"setsid",	lx_setsid,		0,		0}, /* 66 */
	{"sigaction",	NULL,			0,		3}, /* 67 */
	{"sgetmask",	NULL,			NOSYS_OBSOLETE,	0}, /* 68 */
	{"ssetmask",	NULL,			NOSYS_OBSOLETE,	0}, /* 69 */
	{"setreuid16",	lx_setreuid16,		0,		2}, /* 70 */
	{"setregid16",	lx_setregid16,		0,		2}, /* 71 */
	{"sigsuspend",	NULL,			0,		1}, /* 72 */
	{"sigpending",	NULL,			0,		1}, /* 73 */
	{"sethostname",	lx_sethostname,		0,		2}, /* 74 */
	{"setrlimit",	lx_setrlimit,		0,		2}, /* 75 */
	{"getrlimit",	lx_oldgetrlimit,	0,		2}, /* 76 */
	{"getrusage",	lx_getrusage,		0,		2}, /* 77 */
	{"gettimeofday", lx_gettimeofday,	0,		2}, /* 78 */
	{"settimeofday", NULL, 			0,		2}, /* 79 */
	{"getgroups16",	NULL,			0,		2}, /* 80 */
	{"setgroups16",	NULL,			0,		2}, /* 81 */
	{"select",	NULL,			NOSYS_OBSOLETE,	0}, /* 82 */
	{"symlink",	lx_symlink,		0,		2}, /* 83 */
	{"oldlstat",	NULL,			NOSYS_OBSOLETE,	0}, /* 84 */
	{"readlink",	lx_readlink,		0,		3}, /* 85 */
	{"uselib",	NULL,			NOSYS_KERNEL,	0}, /* 86 */
	{"swapon",	NULL,			NOSYS_KERNEL,	0}, /* 87 */
	{"reboot",	lx_reboot,		0,		4}, /* 88 */
	{"readdir",	NULL,			0,		3}, /* 89 */
	{"mmap",	NULL,			0,		6}, /* 90 */
	{"munmap",	lx_munmap,		0,		2}, /* 91 */
	{"truncate",	NULL,			0,		2}, /* 92 */
	{"ftruncate",	NULL,			0,		2}, /* 93 */
	{"fchmod",	lx_fchmod,		0,		2}, /* 94 */
	{"fchown16",	lx_fchown16,		0,		3}, /* 95 */
	{"getpriority",	lx_getpriority,		0,		2}, /* 96 */
	{"setpriority",	lx_setpriority,		0,		3}, /* 97 */
	{"profil",	NULL,			NOSYS_NO_EQUIV,	0}, /* 98 */
	{"statfs",	NULL,			0,		2}, /* 99 */
	{"fstatfs",	NULL,			0,		2}, /* 100 */
	{"ioperm",	NULL,			NOSYS_NO_EQUIV,	0}, /* 101 */
	{"socketcall",	lx_socketcall,		0,		2}, /* 102 */
	{"syslog",	lx_syslog,		0,		3}, /* 103 */
	{"setitimer",	NULL,			0,		3}, /* 104 */
	{"getitimer",	lx_getitimer,		0,		2}, /* 105 */
	{"stat",	lx_stat32,		0,		2}, /* 106 */
	{"lstat",	lx_lstat32,		0,		2}, /* 107 */
	{"fstat",	lx_fstat32,		0,		2}, /* 108 */
	{"uname",	NULL,			NOSYS_OBSOLETE,	0}, /* 109 */
	{"oldiopl",	NULL,			NOSYS_NO_EQUIV,	0}, /* 110 */
	{"vhangup",	lx_vhangup,		0,		0}, /* 111 */
	{"idle",	NULL,			NOSYS_NO_EQUIV,	0}, /* 112 */
	{"vm86old",	NULL,			NOSYS_OBSOLETE,	0}, /* 113 */
	{"wait4",	lx_wait4,		0,		4}, /* 114 */
	{"swapoff",	NULL,			NOSYS_KERNEL,	0}, /* 115 */
	{"sysinfo",	lx_sysinfo32,		0,		1}, /* 116 */
	{"ipc",		NULL,			0,		5}, /* 117 */
	{"fsync",	NULL,			0,		1}, /* 118 */
	{"sigreturn",	NULL,			0,		1}, /* 119 */
	{"clone",	NULL,			0,		5}, /* 120 */
	{"setdomainname", lx_setdomainname,	0,		2}, /* 121 */
	{"uname",	lx_uname,		0,		1}, /* 122 */
	{"modify_ldt",	lx_modify_ldt,		0,		3}, /* 123 */
	{"adjtimex",	NULL,			0,		1}, /* 124 */
	{"mprotect",	NULL,			0,		3}, /* 125 */
	{"sigprocmask",	NULL,			0,		3}, /* 126 */
	{"create_module", NULL,			NOSYS_KERNEL,	0}, /* 127 */
	{"init_module",	NULL,			NOSYS_KERNEL,	0}, /* 128 */
	{"delete_module", NULL,			NOSYS_KERNEL,	0}, /* 129 */
	{"get_kernel_syms", NULL,		NOSYS_KERNEL,	0}, /* 130 */
	{"quotactl",	NULL,			NOSYS_KERNEL,	0}, /* 131 */
	{"getpgid",	lx_getpgid,		0,		1}, /* 132 */
	{"fchdir",	lx_fchdir,		0,		1}, /* 133 */
	{"bdflush",	NULL,			NOSYS_KERNEL,	0}, /* 134 */
	{"sysfs",	NULL,			0,		3}, /* 135 */
	{"personality",	lx_personality,		0,		1}, /* 136 */
	{"afs_syscall",	NULL,			NOSYS_KERNEL,	0}, /* 137 */
	{"setfsuid16",	lx_setfsuid16,		0,		1}, /* 138 */
	{"setfsgid16",	lx_setfsgid16,		0,		1}, /* 139 */
	{"llseek",	lx_llseek,		0,		5}, /* 140 */
	{"getdents",	lx_getdents_32,		0,		3}, /* 141 */
	{"select",	lx_select,		0,		5}, /* 142 */
	{"flock",	NULL,			0,		2}, /* 143 */
	{"msync",	NULL,			0,		3}, /* 144 */
	{"readv",	lx_readv,		0,		3}, /* 145 */
	{"writev",	lx_writev,		0,		3}, /* 146 */
	{"getsid",	lx_getsid,		0,		1}, /* 147 */
	{"fdatasync",	NULL,			0,		1}, /* 148 */
	{"sysctl",	NULL,			0,		1}, /* 149 */
	{"mlock",	NULL,			0,		2}, /* 150 */
	{"munlock",	NULL,			0,		2}, /* 151 */
	{"mlockall",	NULL,			0,		1}, /* 152 */
	{"munlockall",	NULL,			0,		0}, /* 153 */
	{"sched_setparam", lx_sched_setparam,	0,		2}, /* 154 */
	{"sched_getparam", lx_sched_getparam,	0,		2}, /* 155 */
	{"sched_setscheduler", lx_sched_setscheduler, 0,	3}, /* 156 */
	{"sched_getscheduler", lx_sched_getscheduler, 0,	1}, /* 157 */
	{"sched_yield",	lx_sched_yield,		0,		0}, /* 158 */
	{"sched_get_priority_max", lx_sched_get_priority_max, 0, 1}, /* 159 */
	{"sched_get_priority_min", lx_sched_get_priority_min, 0, 1}, /* 160 */
	{"sched_rr_get_interval", lx_sched_rr_get_interval,  0,	 2}, /* 161 */
	{"nanosleep",	lx_nanosleep,		0,		2}, /* 162 */
	{"mremap",	NULL,			0,		5}, /* 163 */
	{"setresuid16",	lx_setresuid16,		0,		3}, /* 164 */
	{"getresuid16",	lx_getresuid16,		0,		3}, /* 165 */
	{"vm86",	NULL,			NOSYS_NO_EQUIV,	0}, /* 166 */
	{"query_module", NULL,			0,		5}, /* 167 */
	{"poll",	lx_poll,		0,		3}, /* 168 */
	{"nfsservctl",	NULL,			NOSYS_KERNEL,	0}, /* 169 */
	{"setresgid16",	lx_setresgid16,		0,		3}, /* 170 */
	{"getresgid16",	lx_getresgid16,		0,		3}, /* 171 */
	{"prctl",	lx_prctl,		0,		5}, /* 172 */
	{"rt_sigreturn", NULL,			0,		0}, /* 173 */
	{"rt_sigaction", NULL,			0,		4}, /* 174 */
	{"rt_sigprocmask", NULL,		0,		4}, /* 175 */
	{"rt_sigpending", NULL,			0,		2}, /* 176 */
	{"rt_sigtimedwait", NULL,		0,		4}, /* 177 */
	{"rt_sigqueueinfo", NULL,		0,		3}, /* 178 */
	{"rt_sigsuspend", NULL,			0,		2}, /* 179 */
	{"pread64",	lx_pread32,		0,		5}, /* 180 */
	{"pwrite64",	lx_pwrite32,		0,		5}, /* 181 */
	{"chown16",	lx_chown16,		0,		3}, /* 182 */
	{"getcwd",	lx_getcwd,		0,		2}, /* 183 */
	{"capget",	NULL,			0,		2}, /* 184 */
	{"capset",	NULL,			0,		2}, /* 185 */
	{"sigaltstack",	NULL,			0,		2}, /* 186 */
	{"sendfile",	NULL,			0,		4}, /* 187 */
	{"getpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 188 */
	{"putpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 189 */
	{"vfork",	NULL,			0,		0}, /* 190 */
	{"getrlimit",	lx_getrlimit,		0,		2}, /* 191 */
	{"mmap2",	NULL,			LX_SYS_EBPARG6,	6}, /* 192 */
	{"truncate64",	NULL,			0,		3}, /* 193 */
	{"ftruncate64",	NULL,			0,		3}, /* 194 */
	{"stat64",	lx_stat64,		0,		2}, /* 195 */
	{"lstat64",	lx_lstat64,		0,		2}, /* 196 */
	{"fstat64",	lx_fstat64,		0,		2}, /* 197 */
	{"lchown",	lx_lchown,		0,		3}, /* 198 */
	{"getuid",	lx_getuid,		0,		0}, /* 199 */
	{"getgid",	lx_getgid,		0,		0}, /* 200 */
	{"geteuid",	lx_geteuid,		0,		0}, /* 201 */
	{"getegid",	lx_getegid,		0,		0}, /* 202 */
	{"setreuid",	lx_setreuid,		0,		0}, /* 203 */
	{"setregid",	lx_setregid,		0,		0}, /* 204 */
	{"getgroups",	NULL,			0,		2}, /* 205 */
	{"setgroups",	NULL,			0,		2}, /* 206 */
	{"fchown",	lx_fchown,		0,		3}, /* 207 */
	{"setresuid",	lx_setresuid,		0,		3}, /* 208 */
	{"getresuid",	lx_getresuid,		0,		3}, /* 209 */
	{"setresgid",	lx_setresgid,		0,		3}, /* 210 */
	{"getresgid",	lx_getresgid,		0,		3}, /* 211 */
	{"chown",	lx_chown,		0,		3}, /* 212 */
	{"setuid",	lx_setuid,		0,		1}, /* 213 */
	{"setgid",	lx_setgid,		0,		1}, /* 214 */
	{"setfsuid",	lx_setfsuid,		0,		1}, /* 215 */
	{"setfsgid",	lx_setfsgid,		0,		1}, /* 216 */
	{"pivot_root",	NULL,			NOSYS_KERNEL,	0}, /* 217 */
	{"mincore",	lx_mincore,		0,		3}, /* 218 */
	{"madvise",	NULL,			0,		3}, /* 219 */
	{"getdents64",	lx_getdents64,		0,		3}, /* 220 */
	{"fcntl64",	lx_fcntl64,		0,		3}, /* 221 */
	{"tux",		NULL,			NOSYS_NO_EQUIV,	0}, /* 222 */
	{"security",	NULL,			NOSYS_NO_EQUIV,	0}, /* 223 */
	{"gettid",	lx_gettid,		0,		0}, /* 224 */
	{"readahead",	NULL,			NOSYS_NO_EQUIV,	0}, /* 225 */
	{"setxattr",	lx_setxattr,		0,		5}, /* 226 */
	{"lsetxattr",	lx_lsetxattr,		0,		5}, /* 227 */
	{"fsetxattr",	lx_fsetxattr,		0,		5}, /* 228 */
	{"getxattr",	lx_getxattr,		0,		4}, /* 229 */
	{"lgetxattr",	lx_lgetxattr,		0,		4}, /* 230 */
	{"fgetxattr",	lx_fgetxattr,		0,		4}, /* 231 */
	{"listxattr",	lx_listxattr,		0,		3}, /* 232 */
	{"llistxattr",	lx_llistxattr,		0,		3}, /* 233 */
	{"flistxattr",	lx_flistxattr,		0,		3}, /* 234 */
	{"removexattr",	lx_removexattr,		0,		2}, /* 235 */
	{"lremovexattr", lx_lremovexattr,	0,		2}, /* 236 */
	{"fremovexattr", lx_fremovexattr,	0,		2}, /* 237 */
	{"tkill",	lx_tkill,		0,		2}, /* 238 */
	{"sendfile64",	NULL,			0,		4}, /* 239 */
	{"futex",	lx_futex,		LX_SYS_EBPARG6,	6}, /* 240 */
	{"sched_setaffinity", lx_sched_setaffinity,	0,	3}, /* 241 */
	{"sched_getaffinity", lx_sched_getaffinity,	0,	3}, /* 242 */
	{"set_thread_area", lx_set_thread_area,	0,		1}, /* 243 */
	{"get_thread_area", lx_get_thread_area,	0,		1}, /* 244 */
	{"io_setup",	lx_io_setup,		0,		2}, /* 245 */
	{"io_destroy",	NULL,			0,		1}, /* 246 */
	{"io_getevents", NULL,			0,		5}, /* 247 */
	{"io_submit",	NULL,			0,		3}, /* 248 */
	{"io_cancel",	NULL,			0,		3}, /* 249 */
	{"fadvise64",	lx_fadvise64_32,	0,		5}, /* 250 */
	{"nosys",	NULL,			0,		0}, /* 251 */
	{"group_exit",	NULL,			0,		1}, /* 252 */
	{"lookup_dcookie", NULL,		NOSYS_NO_EQUIV,	0}, /* 253 */
	{"epoll_create", lx_epoll_create,	0,		1}, /* 254 */
	{"epoll_ctl",	lx_epoll_ctl,		0,		4}, /* 255 */
	{"epoll_wait",	lx_epoll_wait,		0,		4}, /* 256 */
	{"remap_file_pages", NULL,		NOSYS_NO_EQUIV,	0}, /* 257 */
	{"set_tid_address", lx_set_tid_address,	0,		1}, /* 258 */
	{"timer_create", lx_timer_create,	0,		3}, /* 259 */
	{"timer_settime", NULL,			0,		4}, /* 260 */
	{"timer_gettime", NULL,			0,		2}, /* 261 */
	{"timer_getoverrun", NULL,		0,		1}, /* 262 */
	{"timer_delete", NULL,			0,		1}, /* 263 */
	{"clock_settime", lx_clock_settime,	0,		2}, /* 264 */
	{"clock_gettime", lx_clock_gettime,	0,		2}, /* 265 */
	{"clock_getres", lx_clock_getres,	0,		2}, /* 266 */
	{"clock_nanosleep", NULL,		0,		4}, /* 267 */
	{"statfs64",	NULL,			0,		2}, /* 268 */
	{"fstatfs64",	NULL,			0,		2}, /* 269 */
	{"tgkill",	lx_tgkill,		0,		3}, /* 270 */

/*
 * The following system calls only exist in kernel 2.6 and greater:
 */
	{"utimes",	NULL,			0,		2}, /* 271 */
	{"fadvise64_64", lx_fadvise64_64,	LX_SYS_EBPARG6,	6}, /* 272 */
	{"vserver",	NULL,			NOSYS_NULL,	0}, /* 273 */
	{"mbind",	NULL,			NOSYS_NULL,	0}, /* 274 */
	{"get_mempolicy", NULL,			NOSYS_NULL,	0}, /* 275 */
	{"set_mempolicy", NULL,			NOSYS_NULL,	0}, /* 276 */
	{"mq_open",	NULL,			NOSYS_NULL,	0}, /* 277 */
	{"mq_unlink",	NULL,			NOSYS_NULL,	0}, /* 278 */
	{"mq_timedsend", NULL,			NOSYS_NULL,	0}, /* 279 */
	{"mq_timedreceive", NULL,		NOSYS_NULL,	0}, /* 280 */
	{"mq_notify",	NULL,			NOSYS_NULL,	0}, /* 281 */
	{"mq_getsetattr", NULL,			NOSYS_NULL,	0}, /* 282 */
	{"kexec_load",	NULL,			NOSYS_NULL,	0}, /* 283 */
	{"waitid",	lx_waitid,		0,		4}, /* 284 */
	{"sys_setaltroot", NULL,		NOSYS_NULL,	0}, /* 285 */
	{"add_key",	NULL,			NOSYS_NULL,	0}, /* 286 */
	{"request_key",	NULL,			NOSYS_NULL,	0}, /* 287 */
	{"keyctl",	NULL,			NOSYS_NULL,	0}, /* 288 */
	{"ioprio_set",	lx_ioprio_set,		0,		3}, /* 289 */
	{"ioprio_get",	lx_ioprio_get,		0,		2}, /* 290 */
	{"inotify_init", NULL,			0,		0}, /* 291 */
	{"inotify_add_watch", NULL,		0,		3}, /* 292 */
	{"inotify_rm_watch", NULL,		0,		2}, /* 293 */
	{"migrate_pages", NULL,			NOSYS_NULL,	0}, /* 294 */
	{"openat",	lx_openat,		0,		4}, /* 295 */
	{"mkdirat",	lx_mkdirat,		0,		3}, /* 296 */
	{"mknodat",	NULL,			0,		4}, /* 297 */
	{"fchownat",	lx_fchownat,		0,		5}, /* 298 */
	{"futimesat",	NULL,			0,		3}, /* 299 */
	{"fstatat64",	lx_fstatat64,		0,		4}, /* 300 */
	{"unlinkat",	lx_unlinkat,		0,		3}, /* 301 */
	{"renameat",	lx_renameat,		0,		4}, /* 302 */
	{"linkat",	lx_linkat,		0,		5}, /* 303 */
	{"symlinkat",	lx_symlinkat,		0,		3}, /* 304 */
	{"readlinkat",	lx_readlinkat,		0,		4}, /* 305 */
	{"fchmodat",	lx_fchmodat,		0,		3}, /* 306 */
	{"faccessat",	lx_faccessat,		0,		4}, /* 307 */
	{"pselect6",	lx_pselect,		LX_SYS_EBPARG6,	6}, /* 308 */
	{"ppoll",	lx_ppoll,		0,		5}, /* 309 */
	{"unshare",	NULL,			NOSYS_NULL,	0}, /* 310 */
	{"set_robust_list", lx_set_robust_list,	0,		2}, /* 311 */
	{"get_robust_list", lx_get_robust_list,	0,		3}, /* 312 */
	{"splice",	NULL,			NOSYS_NULL,	0}, /* 313 */
	{"sync_file_range", lx_sync_file_range,	0,		4}, /* 314 */
	{"tee",		NULL,			NOSYS_NULL,	0}, /* 315 */
	{"vmsplice",	NULL,			NOSYS_NULL,	0}, /* 316 */
	{"move_pages",	NULL,			NOSYS_NULL,	0}, /* 317 */
	{"getcpu",	lx_getcpu,		0,		3}, /* 318 */
	{"epoll_pwait",	lx_epoll_pwait,		0,		5}, /* 319 */
	{"utimensat",	NULL,			0,		4}, /* 320 */
	{"signalfd",	NULL,			0,		3}, /* 321 */
	{"timerfd_create", NULL,		0,		2}, /* 322 */
	{"eventfd",	NULL,			0,		1}, /* 323 */
	{"fallocate",	lx_fallocate32,		LX_SYS_EBPARG6,	6}, /* 324 */
	{"timerfd_settime", NULL,		0,		4}, /* 325 */
	{"timerfd_gettime", NULL,		0,		2}, /* 326 */
	{"signalfd4",	NULL,			0,		4}, /* 327 */
	{"eventfd2",	NULL,			0,		2}, /* 328 */
	{"epoll_create1", lx_epoll_create1,	0,		1}, /* 329 */
	{"dup3",	lx_dup3,		0,		3}, /* 330 */
	{"pipe2",	lx_pipe2,		0,		2}, /* 331 */
	{"inotify_init1", NULL,			0,		1}, /* 332 */
	{"preadv",	lx_preadv32,		0,		5}, /* 333 */
	{"pwritev",	lx_pwritev32,		0,		5}, /* 334 */
	{"rt_tgsigqueueinfo", NULL,		0,		4}, /* 335 */
	{"perf_event_open", NULL,		NOSYS_NULL,	0}, /* 336 */
	{"recvmmsg",	NULL,			NOSYS_NULL,	0}, /* 337 */
	{"fanotify_init", NULL,			NOSYS_NULL,	0}, /* 338 */
	{"fanotify_mark", NULL,			NOSYS_NULL,	0}, /* 339 */
	{"prlimit64",	lx_prlimit64,		0,		4}, /* 340 */
	{"name_to_handle_at", NULL,		NOSYS_NULL,	0}, /* 341 */
	{"open_by_handle_at", NULL,		NOSYS_NULL,	0}, /* 342 */
	{"clock_adjtime", NULL,			NOSYS_NULL,	0}, /* 343 */
	{"syncfs",	lx_syncfs,		0,		1}, /* 344 */
	{"sendmmsg",	NULL,			NOSYS_NULL,	0}, /* 345 */
	{"setns",	NULL,			NOSYS_NULL,	0}, /* 346 */
	{"process_vm_readv", NULL,		NOSYS_NULL,	0}, /* 347 */
	{"process_vm_writev", NULL,		NOSYS_NULL,	0}, /* 348 */
	{"kcmp",	NULL,			NOSYS_NULL,	0}, /* 349 */
	{"finit_module", NULL,			NOSYS_NULL,	0}, /* 350 */
	{"sched_setattr", lx_sched_setattr,	0,		3}, /* 351 */
	{"sched_getattr", lx_sched_getattr,	0,		4}, /* 352 */
	{"renameat2",	NULL,			NOSYS_NULL,	0}, /* 353 */
	{"seccomp",	NULL,			NOSYS_NULL,	0}, /* 354 */
	{"getrandom",	lx_getrandom,		0,		3}, /* 355 */
	{"memfd_create", NULL,			NOSYS_NULL,	0}, /* 356 */
	{"bpf",		NULL,			NOSYS_NULL,	0}, /* 357 */
	{"execveat",	NULL,			NOSYS_NULL,	0}, /* 358 */
};

#if defined(_LP64)
/*
 * Linux defines system call numbers for 64-bit x86 in the file:
 *   arch/x86/syscalls/syscall_64.tbl
 */
lx_sysent_t lx_sysent64[] = {
	{"read",	lx_read,		0,		3}, /* 0 */
	{"write",	lx_write,		0,		3}, /* 1 */
	{"open",	lx_open,		0,		3}, /* 2 */
	{"close",	lx_close,		0,		1}, /* 3 */
	{"stat",	lx_stat64,		0,		2}, /* 4 */
	{"fstat",	lx_fstat64,		0,		2}, /* 5 */
	{"lstat",	lx_lstat64,		0,		2}, /* 6 */
	{"poll",	lx_poll,		0,		3}, /* 7 */
	{"lseek",	lx_lseek64,		0,		3}, /* 8 */
	{"mmap",	NULL,			0,		6}, /* 9 */
	{"mprotect",	NULL,			0,		3}, /* 10 */
	{"munmap",	lx_munmap,		0,		2}, /* 11 */
	{"brk",		lx_brk,			0,		1}, /* 12 */
	{"rt_sigaction", NULL,			0,		4}, /* 13 */
	{"rt_sigprocmask", NULL,		0,		4}, /* 14 */
	{"rt_sigreturn", NULL,			0,		0}, /* 15 */
	{"ioctl",	lx_ioctl,		0,		3}, /* 16 */
	{"pread64",	lx_pread,		0,		4}, /* 17 */
	{"pwrite64",	lx_pwrite,		0,		4}, /* 18 */
	{"readv",	lx_readv,		0,		3}, /* 19 */
	{"writev",	lx_writev,		0,		3}, /* 20 */
	{"access",	lx_access,		0,		2}, /* 21 */
	{"pipe",	lx_pipe,		0,		1}, /* 22 */
	{"select",	lx_select,		0,		5}, /* 23 */
	{"sched_yield",	lx_sched_yield,		0,		0}, /* 24 */
	{"mremap",	NULL,			0,		5}, /* 25 */
	{"msync",	NULL,			0,		3}, /* 26 */
	{"mincore",	lx_mincore,		0,		3}, /* 27 */
	{"madvise",	NULL,			0,		3}, /* 28 */
	{"shmget",	NULL,			0,		3}, /* 29 */
	{"shmat",	NULL,			0,		4}, /* 30 */
	{"shmctl",	NULL,			0,		3}, /* 31 */
	{"dup",		lx_dup,			0,		1}, /* 32 */
	{"dup2",	lx_dup2,		0,		2}, /* 33 */
	{"pause",	lx_pause,		0,		0}, /* 34 */
	{"nanosleep",	lx_nanosleep,		0,		2}, /* 35 */
	{"getitimer",	lx_getitimer,		0,		2}, /* 36 */
	{"alarm",	lx_alarm,		0,		1}, /* 37 */
	{"setitimer",	NULL,			0,		3}, /* 38 */
	{"getpid",	lx_getpid,		0,		0}, /* 39 */
	{"sendfile",	NULL,			0,		4}, /* 40 */
	{"socket",	lx_socket,		0,		3}, /* 41 */
	{"connect",	lx_connect,		0,		3}, /* 42 */
	{"accept",	lx_accept,		0,		3}, /* 43 */
	{"sendto",	lx_sendto,		0,		6}, /* 44 */
	{"recvfrom",	lx_recvfrom,		0,		6}, /* 45 */
	{"sendmsg",	lx_sendmsg,		0,		3}, /* 46 */
	{"recvmsg",	lx_recvmsg,		0,		3}, /* 47 */
	{"shutdown",	lx_shutdown,		0,		2}, /* 48 */
	{"bind",	lx_bind,		0,		3}, /* 49 */
	{"listen",	lx_listen,		0,		2}, /* 50 */
	{"getsockname",	lx_getsockname,		0,		3}, /* 51 */
	{"getpeername",	lx_getpeername,		0,		3}, /* 52 */
	{"socketpair",	lx_socketpair,		0,		4}, /* 53 */
	{"setsockopt",	lx_setsockopt,		0,		5}, /* 54 */
	{"getsockopt",	lx_getsockopt,		0,		5}, /* 55 */
	{"clone",	NULL,			0,		5}, /* 56 */
	{"fork",	NULL,			0,		0}, /* 57 */
	{"vfork",	NULL,			0,		0}, /* 58 */
	{"execve",	NULL,			0,		3}, /* 59 */
	{"exit",	NULL,			0,		1}, /* 60 */
	{"wait4",	lx_wait4,		0,		4}, /* 61 */
	{"kill",	lx_kill,		0,		2}, /* 62 */
	{"uname",	lx_uname,		0,		1}, /* 63 */
	{"semget",	NULL,			0,		3}, /* 64 */
	{"semop",	NULL,			0,		3}, /* 65 */
	{"semctl",	NULL,			0,		4}, /* 66 */
	{"shmdt",	NULL,			0,		1}, /* 67 */
	{"msgget",	NULL,			0,		2}, /* 68 */
	{"msgsnd",	NULL,			0,		4}, /* 69 */
	{"msgrcv",	NULL,			0,		5}, /* 70 */
	{"msgctl",	NULL,			0,		3}, /* 71 */
	{"fcntl",	lx_fcntl64,		0,		3}, /* 72 */
	{"flock",	NULL,			0,		2}, /* 73 */
	{"fsync",	NULL,			0,		1}, /* 74 */
	{"fdatasync",	NULL,			0,		1}, /* 75 */
	{"truncate",	NULL,			0,		2}, /* 76 */
	{"ftruncate",	NULL,			0,		2}, /* 77 */
	{"getdents",	lx_getdents_64,		0,		3}, /* 78 */
	{"getcwd",	lx_getcwd,		0,		2}, /* 79 */
	{"chdir",	lx_chdir,		0,		1}, /* 80 */
	{"fchdir",	lx_fchdir,		0,		1}, /* 81 */
	{"rename",	lx_rename,		0,		2}, /* 82 */
	{"mkdir",	lx_mkdir,		0,		2}, /* 83 */
	{"rmdir",	NULL,			0,		1}, /* 84 */
	{"creat",	lx_creat,		0,		2}, /* 85 */
	{"link",	lx_link,		0,		2}, /* 86 */
	{"unlink",	lx_unlink,		0,		1}, /* 87 */
	{"symlink",	lx_symlink,		0,		2}, /* 88 */
	{"readlink",	lx_readlink,		0,		3}, /* 89 */
	{"chmod",	lx_chmod,		0,		2}, /* 90 */
	{"fchmod",	lx_fchmod,		0,		2}, /* 91 */
	{"chown",	lx_chown,		0,		3}, /* 92 */
	{"fchown",	lx_fchown,		0,		3}, /* 93 */
	{"lchown",	lx_lchown,		0,		3}, /* 94 */
	{"umask",	lx_umask,		0,		1}, /* 95 */
	{"gettimeofday", lx_gettimeofday,	0,		2}, /* 96 */
	{"getrlimit",	lx_getrlimit,		0,		2}, /* 97 */
	{"getrusage",	lx_getrusage,		0,		2}, /* 98 */
	{"sysinfo",	lx_sysinfo64,		0,		1}, /* 99 */
	{"times",	NULL,			0,		1}, /* 100 */
	{"ptrace",	lx_ptrace,		0,		4}, /* 101 */
	{"getuid",	lx_getuid,		0,		0}, /* 102 */
	{"syslog",	lx_syslog,		0,		3}, /* 103 */
	{"getgid",	lx_getgid,		0,		0}, /* 104 */
	{"setuid",	lx_setuid,		0,		1}, /* 105 */
	{"setgid",	lx_setgid,		0,		1}, /* 106 */
	{"geteuid",	lx_geteuid,		0,		0}, /* 107 */
	{"getegid",	lx_getegid,		0,		0}, /* 108 */
	{"setpgid",	lx_setpgid,		0,		2}, /* 109 */
	{"getppid",	lx_getppid,		0,		0}, /* 110 */
	{"getpgrp",	lx_getpgrp,		0,		0}, /* 111 */
	{"setsid",	lx_setsid,		0,		0}, /* 112 */
	{"setreuid",	lx_setreuid,		0,		0}, /* 113 */
	{"setregid",	lx_setregid,		0,		0}, /* 114 */
	{"getgroups",	NULL,			0,		2}, /* 115 */
	{"setgroups",	NULL,			0,		2}, /* 116 */
	{"setresuid",	lx_setresuid,		0,		3}, /* 117 */
	{"getresuid",	lx_getresuid,		0,		3}, /* 118 */
	{"setresgid",	lx_setresgid,		0,		3}, /* 119 */
	{"getresgid",	lx_getresgid,		0,		3}, /* 120 */
	{"getpgid",	lx_getpgid,		0,		1}, /* 121 */
	{"setfsuid",	lx_setfsuid,		0,		1}, /* 122 */
	{"setfsgid",	lx_setfsgid,		0,		1}, /* 123 */
	{"getsid",	lx_getsid,		0,		1}, /* 124 */
	{"capget",	NULL,			0,		2}, /* 125 */
	{"capset",	NULL,			0,		2}, /* 126 */
	{"rt_sigpending", NULL,			0,		2}, /* 127 */
	{"rt_sigtimedwait", NULL,		0,		4}, /* 128 */
	{"rt_sigqueueinfo", NULL,		0,		3}, /* 129 */
	{"rt_sigsuspend", NULL,			0,		2}, /* 130 */
	{"sigaltstack",	NULL,			0,		2}, /* 131 */
	{"utime",	NULL,			0,		2}, /* 132 */
	{"mknod",	NULL,			0,		3}, /* 133 */
	{"uselib",	NULL,			NOSYS_KERNEL,	0}, /* 134 */
	{"personality",	lx_personality,		0,		1}, /* 135 */
	{"ustat",	NULL,			NOSYS_OBSOLETE,	2}, /* 136 */
	{"statfs",	NULL,			0,		2}, /* 137 */
	{"fstatfs",	NULL,			0,		2}, /* 138 */
	{"sysfs",	NULL,			0,		3}, /* 139 */
	{"getpriority",	lx_getpriority,		0,		2}, /* 140 */
	{"setpriority",	lx_setpriority,		0,		3}, /* 141 */
	{"sched_setparam", lx_sched_setparam,	0,		2}, /* 142 */
	{"sched_getparam", lx_sched_getparam,	0,		2}, /* 143 */
	{"sched_setscheduler", lx_sched_setscheduler, 0,	3}, /* 144 */
	{"sched_getscheduler", lx_sched_getscheduler, 0,	1}, /* 145 */
	{"sched_get_priority_max", lx_sched_get_priority_max, 0, 1}, /* 146 */
	{"sched_get_priority_min", lx_sched_get_priority_min, 0, 1}, /* 147 */
	{"sched_rr_get_interval", lx_sched_rr_get_interval, 0,	2}, /* 148 */
	{"mlock",	NULL,			0,		2}, /* 149 */
	{"munlock",	NULL,			0,		2}, /* 150 */
	{"mlockall",	NULL,			0,		1}, /* 151 */
	{"munlockall",	NULL,			0,		0}, /* 152 */
	{"vhangup",	lx_vhangup,		0,		0}, /* 153 */
	{"modify_ldt",	lx_modify_ldt,		0,		3}, /* 154 */
	{"pivot_root",	NULL,			NOSYS_KERNEL,	0}, /* 155 */
	{"sysctl",	NULL,			0,		1}, /* 156 */
	{"prctl",	lx_prctl,		0,		5}, /* 157 */
	{"arch_prctl",	lx_arch_prctl,		0,		2}, /* 158 */
	{"adjtimex",	NULL,			0,		1}, /* 159 */
	{"setrlimit",	lx_setrlimit,		0,		2}, /* 160 */
	{"chroot",	lx_chroot,		0,		1}, /* 161 */
	{"sync",	lx_sync,		0,		0}, /* 162 */
	{"acct",	NULL,			NOSYS_NO_EQUIV,	0}, /* 163 */
	{"settimeofday", NULL,			0,		2}, /* 164 */
	{"mount",	lx_mount,		0,		5}, /* 165 */
	{"umount2",	lx_umount2,		0,		2}, /* 166 */
	{"swapon",	NULL,			NOSYS_KERNEL,	0}, /* 167 */
	{"swapoff",	NULL,			NOSYS_KERNEL,	0}, /* 168 */
	{"reboot",	lx_reboot,		0,		4}, /* 169 */
	{"sethostname",	lx_sethostname,		0,		2}, /* 170 */
	{"setdomainname", lx_setdomainname,	0,		2}, /* 171 */
	{"iopl",	NULL,			NOSYS_NO_EQUIV,	0}, /* 172 */
	{"ioperm",	NULL,			NOSYS_NO_EQUIV,	0}, /* 173 */
	{"create_module", NULL,			NOSYS_KERNEL,	0}, /* 174 */
	{"init_module",	NULL,			NOSYS_KERNEL,	0}, /* 175 */
	{"delete_module", NULL,			NOSYS_KERNEL,	0}, /* 176 */
	{"get_kernel_syms", NULL,		NOSYS_KERNEL,	0}, /* 177 */
	{"query_module", NULL,			0,		5}, /* 178 */
	{"quotactl",	NULL,			NOSYS_KERNEL,	0}, /* 179 */
	{"nfsservctl",	NULL,			NOSYS_KERNEL,	0}, /* 180 */
	{"getpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 181 */
	{"putpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 182 */
	{"afs_syscall",	NULL,			NOSYS_KERNEL,	0}, /* 183 */
	{"tux",		NULL,			NOSYS_NO_EQUIV,	0}, /* 184 */
	{"security",	NULL,			NOSYS_NO_EQUIV,	0}, /* 185 */
	{"gettid",	lx_gettid,		0,		0}, /* 186 */
	{"readahead",	NULL,			NOSYS_NO_EQUIV,	0}, /* 187 */
	{"setxattr",	lx_setxattr,		0,		5}, /* 188 */
	{"lsetxattr",	lx_lsetxattr,		0,		5}, /* 189 */
	{"fsetxattr",	lx_fsetxattr,		0,		5}, /* 190 */
	{"getxattr",	lx_getxattr,		0,		4}, /* 191 */
	{"lgetxattr",	lx_lgetxattr,		0,		4}, /* 192 */
	{"fgetxattr",	lx_fgetxattr,		0,		4}, /* 193 */
	{"listxattr",	lx_listxattr,		0,		3}, /* 194 */
	{"llistxattr",	lx_llistxattr,		0,		3}, /* 195 */
	{"flistxattr",	lx_flistxattr,		0,		3}, /* 196 */
	{"removexattr",	lx_removexattr,		0,		2}, /* 197 */
	{"lremovexattr", lx_lremovexattr,	0,		2}, /* 198 */
	{"fremovexattr", lx_fremovexattr,	0,		2}, /* 199 */
	{"tkill",	lx_tkill,		0,		2}, /* 200 */
	{"time",	lx_time,		0,		1}, /* 201 */
	{"futex",	lx_futex,		0,		6}, /* 202 */
	{"sched_setaffinity", lx_sched_setaffinity,	0,	3}, /* 203 */
	{"sched_getaffinity", lx_sched_getaffinity,	0,	3}, /* 204 */
	{"set_thread_area", lx_set_thread_area, 0,		1}, /* 205 */
	{"io_setup",	lx_io_setup,		0,		2}, /* 206 */
	{"io_destroy",	NULL,			0,		1}, /* 207 */
	{"io_getevents", NULL,			0,		5}, /* 208 */
	{"io_submit",	NULL,			0,		3}, /* 209 */
	{"io_cancel",	NULL,			0,		3}, /* 210 */
	{"get_thread_area", lx_get_thread_area,	0,		1}, /* 211 */
	{"lookup_dcookie", NULL,		NOSYS_NO_EQUIV,	0}, /* 212 */
	{"epoll_create", lx_epoll_create,	0,		1}, /* 213 */
	{"epoll_ctl_old", NULL,			NOSYS_NULL,	0}, /* 214 */
	{"epoll_wait_old", NULL,		NOSYS_NULL,	0}, /* 215 */
	{"remap_file_pages", NULL,		NOSYS_NO_EQUIV,	0}, /* 216 */
	{"getdents64",	lx_getdents64,		0,		3}, /* 217 */
	{"set_tid_address", lx_set_tid_address, 0,		1}, /* 218 */
	{"restart_syscall", NULL,		NOSYS_NULL,	0}, /* 219 */
	{"semtimedop",	NULL,			0,		4}, /* 220 */
	{"fadvise64",	lx_fadvise64,		0,		4}, /* 221 */
	{"timer_create", lx_timer_create,	0,		3}, /* 222 */
	{"timer_settime", NULL,			0,		4}, /* 223 */
	{"timer_gettime", NULL,			0,		2}, /* 224 */
	{"timer_getoverrun", NULL,		0,		1}, /* 225 */
	{"timer_delete", NULL,			0,		1}, /* 226 */
	{"clock_settime", lx_clock_settime,	0,		2}, /* 227 */
	{"clock_gettime", lx_clock_gettime,	0,		2}, /* 228 */
	{"clock_getres", lx_clock_getres,	0,		2}, /* 229 */
	{"clock_nanosleep", NULL,		0,		4}, /* 230 */
	{"exit_group",	NULL,			0,		1}, /* 231 */
	{"epoll_wait",	lx_epoll_wait,		0,		4}, /* 232 */
	{"epoll_ctl",	lx_epoll_ctl,		0,		4}, /* 233 */
	{"tgkill",	lx_tgkill,		0,		3}, /* 234 */
	{"utimes",	NULL,			0,		2}, /* 235 */
	{"vserver",	NULL,			NOSYS_NULL,	0}, /* 236 */
	{"mbind",	NULL,			NOSYS_NULL,	0}, /* 237 */
	{"set_mempolicy", NULL,			NOSYS_NULL,	0}, /* 238 */
	{"get_mempolicy", NULL,			NOSYS_NULL,	0}, /* 239 */
	{"mq_open",	NULL,			NOSYS_NULL,	0}, /* 240 */
	{"mq_unlink",	NULL,			NOSYS_NULL,	0}, /* 241 */
	{"mq_timedsend", NULL,			NOSYS_NULL,	0}, /* 242 */
	{"mq_timedreceive", NULL,		NOSYS_NULL,	0}, /* 243 */
	{"mq_notify",	NULL,			NOSYS_NULL,	0}, /* 244 */
	{"mq_getsetattr", NULL,			NOSYS_NULL,	0}, /* 245 */
	{"kexec_load",	NULL,			NOSYS_NULL,	0}, /* 246 */
	{"waitid",	lx_waitid,		0,		4}, /* 247 */
	{"add_key",	NULL,			NOSYS_NULL,	0}, /* 248 */
	{"request_key",	NULL,			NOSYS_NULL,	0}, /* 249 */
	{"keyctl",	NULL,			NOSYS_NULL,	0}, /* 250 */
	{"ioprio_set",	lx_ioprio_set,		0,		3}, /* 251 */
	{"ioprio_get",	lx_ioprio_get,		0,		2}, /* 252 */
	{"inotify_init", NULL,			0,		0}, /* 253 */
	{"inotify_add_watch", NULL,		0,		3}, /* 254 */
	{"inotify_rm_watch", NULL,		0,		2}, /* 255 */
	{"migrate_pages", NULL,			NOSYS_NULL,	0}, /* 256 */
	{"openat",	lx_openat,		0,		4}, /* 257 */
	{"mkdirat",	lx_mkdirat,		0,		3}, /* 258 */
	{"mknodat",	NULL,			0,		4}, /* 259 */
	{"fchownat",	lx_fchownat,		0,		5}, /* 260 */
	{"futimesat",	NULL,			0,		3}, /* 261 */
	{"fstatat64",	lx_fstatat64,		0,		4}, /* 262 */
	{"unlinkat",	lx_unlinkat,		0,		3}, /* 263 */
	{"renameat",	lx_renameat,		0,		4}, /* 264 */
	{"linkat",	lx_linkat,		0,		5}, /* 265 */
	{"symlinkat",	lx_symlinkat,		0,		3}, /* 266 */
	{"readlinkat",	lx_readlinkat,		0,		4}, /* 267 */
	{"fchmodat",	lx_fchmodat,		0,		3}, /* 268 */
	{"faccessat",	lx_faccessat,		0,		4}, /* 269 */
	{"pselect6",	lx_pselect,		0,		6}, /* 270 */
	{"ppoll",	lx_ppoll,		0,		5}, /* 271 */
	{"unshare",	NULL,			NOSYS_NULL,	0}, /* 272 */
	{"set_robust_list", lx_set_robust_list,	0,		2}, /* 273 */
	{"get_robust_list", lx_get_robust_list,	0,		3}, /* 274 */
	{"splice",	NULL,			NOSYS_NULL,	0}, /* 275 */
	{"tee",		NULL,			NOSYS_NULL,	0}, /* 276 */
	{"sync_file_range", lx_sync_file_range,	0,		4}, /* 277 */
	{"vmsplice",	NULL,			NOSYS_NULL,	0}, /* 278 */
	{"move_pages",	NULL,			NOSYS_NULL,	0}, /* 279 */
	{"utimensat",	NULL,			0,		4}, /* 280 */
	{"epoll_pwait",	lx_epoll_pwait,		0,		5}, /* 281 */
	{"signalfd",	NULL,			0,		3}, /* 282 */
	{"timerfd_create", NULL,		0,		2}, /* 283 */
	{"eventfd",	NULL,			0,		1}, /* 284 */
	{"fallocate",	lx_fallocate,		0,		4}, /* 285 */
	{"timerfd_settime", NULL,		0,		4}, /* 286 */
	{"timerfd_gettime", NULL,		0,		2}, /* 287 */
	{"accept4",	lx_accept4,		0,		4}, /* 288 */
	{"signalfd4",	NULL,			0,		4}, /* 289 */
	{"eventfd2",	NULL,			0,		2}, /* 290 */
	{"epoll_create1", lx_epoll_create1,	0,		1}, /* 291 */
	{"dup3",	lx_dup3,		0,		3}, /* 292 */
	{"pipe2",	lx_pipe2,		0,		2}, /* 293 */
	{"inotify_init1", NULL,			0,		1}, /* 294 */
	{"preadv",	lx_preadv,		0,		4}, /* 295 */
	{"pwritev",	lx_pwritev,		0,		4}, /* 296 */
	{"rt_tgsigqueueinfo", NULL, 		0,		4}, /* 297 */
	{"perf_event_open", NULL,		NOSYS_NULL,	0}, /* 298 */
	{"recvmmsg",	NULL,			NOSYS_NULL,	0}, /* 299 */
	{"fanotify_init", NULL,			NOSYS_NULL,	0}, /* 300 */
	{"fanotify_mark", NULL,			NOSYS_NULL,	0}, /* 301 */
	{"prlimit64",	lx_prlimit64,		0,		4}, /* 302 */
	{"name_to_handle_at", NULL,		NOSYS_NULL,	0}, /* 303 */
	{"open_by_handle_at", NULL,		NOSYS_NULL,	0}, /* 304 */
	{"clock_adjtime", NULL,			NOSYS_NULL,	0}, /* 305 */
	{"syncfs",	lx_syncfs,		0,		1}, /* 306 */
	{"sendmmsg",	NULL,			NOSYS_NULL,	0}, /* 307 */
	{"setns",	NULL,			NOSYS_NULL,	0}, /* 309 */
	{"getcpu",	lx_getcpu,		0,		3}, /* 309 */
	{"process_vm_readv", NULL,		NOSYS_NULL,	0}, /* 310 */
	{"process_vm_writev", NULL,		NOSYS_NULL,	0}, /* 311 */
	{"kcmp",	NULL,			NOSYS_NULL,	0}, /* 312 */
	{"finit_module", NULL,			NOSYS_NULL,	0}, /* 313 */
	{"sched_setattr", lx_sched_setattr,	0,		3}, /* 314 */
	{"sched_getattr", lx_sched_getattr,	0,		4}, /* 315 */
	{"renameat2", NULL,			NOSYS_NULL,	0}, /* 316 */
	{"seccomp",	NULL,			NOSYS_NULL,	0}, /* 317 */
	{"getrandom",	lx_getrandom,		0,		3}, /* 318 */
	{"memfd_create", NULL,			NOSYS_NULL,	0}, /* 319 */
	{"kexec_file_load", NULL,		NOSYS_NULL,	0}, /* 320 */
	{"bpf",		NULL,			NOSYS_NULL,	0}, /* 321 */
	{"execveat",	NULL,			NOSYS_NULL,	0}, /* 322 */

	/* XXX TBD gap then x32 syscalls from 512 - 544 */
};
#endif

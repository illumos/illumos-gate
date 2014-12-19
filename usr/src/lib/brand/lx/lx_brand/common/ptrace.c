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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_signal.h>
#include <sys/lx_thread.h>
#include <sys/lwp.h>
#include <unistd.h>
#include <fcntl.h>
#include <procfs.h>
#include <sys/frame.h>
#include <strings.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/auxv.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <elf.h>
#include <ieeefp.h>
#include <assert.h>
#include <libintl.h>

/*
 * Linux ptrace compatibility.
 *
 * The brand support for ptrace(2) is built on top of the Solaris /proc
 * interfaces, mounted at /native/proc in the zone.  This gets quite
 * complicated due to the way ptrace works and the Solaris realization of the
 * Linux threading model.
 *
 * ptrace can only interact with a process if we are tracing it, and it is
 * currently stopped. There are two ways a process can begin tracing another
 * process:
 *
 *   PTRACE_TRACEME
 *
 *   A child process can use PTRACE_TRACEME to indicate that it wants to be
 *   traced by the parent. This sets the ptrace compatibility flag in /proc
 *   which causes ths ptrace consumer to be notified through the wait(2)
 *   system call of events of interest. PTRACE_TRACEME is typically used by
 *   the debugger by forking a process, using PTRACE_TRACEME, and finally
 *   doing an exec of the specified program.
 *
 *
 *   PTRACE_ATTACH
 *
 *   We can attach to a process using PTRACE_ATTACH. This is considerably
 *   more complicated than the previous case. On Linux, the traced process is
 *   effectively reparented to the ptrace consumer so that event notification
 *   can go through the normal wait(2) system call. Solaris has no such
 *   ability to reparent a process (nor should it) so some trickery was
 *   required.
 *
 *   When the ptrace consumer uses PTRACE_ATTACH it forks a monitor child
 *   process. The monitor enables the /proc ptrace flag for itself and uses
 *   the native /proc mechanisms to observe the traced process and wait for
 *   events of interest. When the traced process stops, the monitor process
 *   sends itself a SIGTRAP thus rousting its parent process (the ptrace
 *   consumer) out of wait(2). We then translate the process id and status
 *   code from wait(2) to those of the traced process.
 *
 *   To detach from the process we just have to clean up tracing flags and
 *   clean up the monitor.
 *
 * ptrace can only interact with a process if we have traced it, and it is
 * currently stopped (see is_traced()). For threads, there's no way to
 * distinguish whether ptrace() has been called for all threads or some
 * subset. Since most clients will be tracing all threads, and erroneously
 * allowing ptrace to access a non-traced thread is non-fatal (or at least
 * would be fatal on linux), we ignore this aspect of the problem.
 */

#define	LX_PTRACE_TRACEME	0
#define	LX_PTRACE_PEEKTEXT	1
#define	LX_PTRACE_PEEKDATA	2
#define	LX_PTRACE_PEEKUSER	3
#define	LX_PTRACE_POKETEXT	4
#define	LX_PTRACE_POKEDATA	5
#define	LX_PTRACE_POKEUSER	6
#define	LX_PTRACE_CONT		7
#define	LX_PTRACE_KILL		8
#define	LX_PTRACE_SINGLESTEP	9
#define	LX_PTRACE_GETREGS	12
#define	LX_PTRACE_SETREGS	13
#define	LX_PTRACE_GETFPREGS	14
#define	LX_PTRACE_SETFPREGS	15
#define	LX_PTRACE_ATTACH	16
#define	LX_PTRACE_DETACH	17
#define	LX_PTRACE_GETFPXREGS	18
#define	LX_PTRACE_SETFPXREGS	19
#define	LX_PTRACE_SYSCALL	24
#define	LX_PTRACE_SETOPTIONS	0x4200

/* execve syscall numbers for 64-bit vs. 32-bit */
#if defined(_LP64)
#define	LX_SYS_execve	520
#else
#define	LX_SYS_execve	11
#endif

/*
 * This corresponds to the user_i387_struct Linux structure.
 */
typedef struct lx_user_fpregs {
	long lxuf_cwd;
	long lxuf_swd;
	long lxuf_twd;
	long lxuf_fip;
	long lxuf_fcs;
	long lxuf_foo;
	long lxuf_fos;
	long lxuf_st_space[20];
} lx_user_fpregs_t;

/*
 * This corresponds to the user_fxsr_struct Linux structure.
 */
typedef struct lx_user_fpxregs {
	uint16_t lxux_cwd;
	uint16_t lxux_swd;
	uint16_t lxux_twd;
	uint16_t lxux_fop;
	long lxux_fip;
	long lxux_fcs;
	long lxux_foo;
	long lxux_fos;
	long lxux_mxcsr;
	long lxux_reserved;
	long lxux_st_space[32];
	long lxux_xmm_space[32];
	long lxux_padding[56];
} lx_user_fpxregs_t;

/*
 * This corresponds to the user_regs_struct Linux structure.
 */
#if defined(_LP64)
typedef struct lx_user_regs {
	long lxur_r15;
	long lxur_r14;
	long lxur_r13;
	long lxur_r12;
	long lxur_rbp;
	long lxur_rbx;
	long lxur_r11;
	long lxur_r10;
	long lxur_r9;
	long lxur_r8;
	long lxur_rax;
	long lxur_rcx;
	long lxur_rdx;
	long lxur_rsi;
	long lxur_rdi;
	long lxur_orig_rax;
	long lxur_rip;
	long lxur_xcs;
	long lxur_rflags;
	long lxur_rsp;
	long lxur_xss;
	long lxur_xfs_base;
	long lxur_xgs_base;
	long lxur_xds;
	long lxur_xes;
	long lxur_xfs;
	long lxur_xgs;
} lx_user_regs_t;
#else
typedef struct lx_user_regs {
	long lxur_ebx;
	long lxur_ecx;
	long lxur_edx;
	long lxur_esi;
	long lxur_edi;
	long lxur_ebp;
	long lxur_eax;
	long lxur_xds;
	long lxur_xes;
	long lxur_xfs;
	long lxur_xgs;
	long lxur_orig_eax;
	long lxur_eip;
	long lxur_xcs;
	long lxur_eflags;
	long lxur_esp;
	long lxur_xss;
} lx_user_regs_t;
#endif

typedef struct lx_user {
	lx_user_regs_t lxu_regs;
	int lxu_fpvalid;
	lx_user_fpregs_t lxu_i387;
	ulong_t lxu_tsize;
	ulong_t lxu_dsize;
	ulong_t lxu_ssize;
	ulong_t lxu_start_code;
	ulong_t lxu_start_stack;
	long lxu_signal;
	int lxu_reserved;
	lx_user_regs_t *lxu_ar0;
	lx_user_fpregs_t *lxu_fpstate;
	ulong_t lxu_magic;
	char lxu_comm[32];
	int lxu_debugreg[8];
} lx_user_t;

typedef struct ptrace_monitor_map {
	struct ptrace_monitor_map *pmm_next;	/* next pointer */
	pid_t pmm_monitor;			/* monitor child process */
	pid_t pmm_target;			/* traced Linux pid */
	pid_t pmm_pid;				/* Solaris pid */
	lwpid_t pmm_lwpid;			/* Solaris lwpid */
	uint_t pmm_exiting;			/* detached */
} ptrace_monitor_map_t;

typedef struct ptrace_state_map {
	struct ptrace_state_map *psm_next;	/* next pointer */
	pid_t		psm_pid;		/* Solaris pid */
	uintptr_t	psm_debugreg[8];	/* debug registers */
} ptrace_state_map_t;

static ptrace_monitor_map_t *ptrace_monitor_map = NULL;
static ptrace_state_map_t *ptrace_state_map = NULL;
static mutex_t ptrace_map_mtx = DEFAULTMUTEX;

extern void *_START_;

static sigset_t blockable_sigs;

void
lx_ptrace_init(void)
{
	(void) sigfillset(&blockable_sigs);
	(void) sigdelset(&blockable_sigs, SIGKILL);
	(void) sigdelset(&blockable_sigs, SIGSTOP);
}

/*
 * Given a pid, open the named file under /native/proc/<pid>/name using the
 * given mode.
 */
static int
open_procfile(pid_t pid, int mode, const char *name)
{
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "/native/proc/%d/%s", pid, name);

	return (open(path, mode));
}

/*
 * Given a pid and lwpid, open the named file under
 * /native/proc/<pid>/<lwpid>/name using the given mode.
 */
static int
open_lwpfile(pid_t pid, lwpid_t lwpid, int mode, const char *name)
{
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "/native/proc/%d/lwp/%d/%s",
	    pid, lwpid, name);

	return (open(path, mode));
}

static int
get_status(pid_t pid, pstatus_t *psp)
{
	int fd;

	if ((fd = open_procfile(pid, O_RDONLY, "status")) < 0)
		return (-ESRCH);

	if (read(fd, psp, sizeof (pstatus_t)) != sizeof (pstatus_t)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);

	return (0);
}

static int
get_lwpstatus(pid_t pid, lwpid_t lwpid, lwpstatus_t *lsp)
{
	int fd;

	if ((fd = open_lwpfile(pid, lwpid, O_RDONLY, "lwpstatus")) < 0)
		return (-ESRCH);

	if (read(fd, lsp, sizeof (lwpstatus_t)) != sizeof (lwpstatus_t)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);

	return (0);
}

static uintptr_t
syscall_regs(int fd, uintptr_t fp, pid_t pid)
{
	uintptr_t addr, done;
	struct frame fr;
	auxv_t auxv;
	int afd;
#if defined(_LP64)
	Elf64_Phdr phdr;
#elif defined(_ILP32)
	Elf32_Phdr phdr;
#endif

	/*
	 * Try to walk the stack looking for a return address that corresponds
	 * to the traced process's lx_emulate_done symbol. This relies on the
	 * fact that the brand library in the traced process is the same as the
	 * brand library in this process (indeed, this is true of all processes
	 * in a given branded zone).
	 */

	/*
	 * Find the base address for the brand library in the traced process
	 * by grabbing the AT_PHDR auxv entry, reading in the program header
	 * at that location and subtracting off the p_vaddr member. We use
	 * this to compute the location of lx_emulate done in the traced
	 * process.
	 */
	if ((afd = open_procfile(pid, O_RDONLY, "auxv")) < 0)
		return (0);

	do {
		if (read(afd, &auxv, sizeof (auxv)) != sizeof (auxv)) {
			(void) close(afd);
			return (0);
		}
	} while (auxv.a_type != AT_PHDR);

	(void) close(afd);

	if (pread(fd, &phdr, sizeof (phdr), auxv.a_un.a_val) != sizeof (phdr)) {
		lx_debug("failed to read brand library's phdr");
		return (0);
	}

	addr = auxv.a_un.a_val - phdr.p_vaddr;
	done = (uintptr_t)&lx_emulate_done - (uintptr_t)&_START_ + addr;

	fr.fr_savfp = fp;

	do {
		addr = fr.fr_savfp;
		if (pread(fd, &fr, sizeof (fr), addr) != sizeof (fr)) {
			lx_debug("ptrace read failed for stack walk");
			return (0);
		}

		if (addr >= fr.fr_savfp) {
			lx_debug("ptrace stack not monotonically increasing "
			    "%p %p (%p)", addr, fr.fr_savfp, done);
			return (0);
		}
	} while (fr.fr_savpc != done);

	/*
	 * The first argument to lx_emulate is known to be an lx_regs_t
	 * structure and the ABI specifies that it will be placed on the stack
	 * immediately preceeding the return address.
	 */
	addr += sizeof (fr);

	/*
	 * On i386 we need to perform an additional read as we used the stack
	 * to pass the argument to lx_emulate.  On amd64 we passed the argument
	 * in %rdi so addr already contains the correct address.
	 */
#if defined(_ILP32)
	if (pread(fd, &addr, sizeof (addr), addr) != sizeof (addr)) {
		lx_debug("ptrace stack failed to read register set address");
		return (0);
	}
#endif

	return (addr);
}

static int
getregs(pid_t pid, lwpid_t lwpid, lx_user_regs_t *rp)
{
	lwpstatus_t status;
	uintptr_t addr;
	int fd, ret;

	if ((ret = get_lwpstatus(pid, lwpid, &status)) != 0)
		return (ret);

	if ((fd = open_procfile(pid, O_RDONLY, "as")) < 0)
		return (-ESRCH);

	/*
	 * If we find the syscall regs (and are therefore in an emulated
	 * syscall, use the register set at given address. Otherwise, use the
	 * registers as reported by /proc.
	 */
	if ((addr = syscall_regs(fd, status.pr_reg[REG_FP], pid)) != 0) {
		lx_regs_t regs;

		if (pread(fd, &regs, sizeof (regs), addr) != sizeof (regs)) {
			(void) close(fd);
			lx_debug("ptrace failed to read register set");
			return (-EIO);
		}

		(void) close(fd);

#if defined(_LP64)
		rp->lxur_r15 = regs.lxr_r15;
		rp->lxur_r14 = regs.lxr_r14;
		rp->lxur_r13 = regs.lxr_r13;
		rp->lxur_r12 = regs.lxr_r12;
		rp->lxur_rbp = regs.lxr_rbp;
		rp->lxur_rbx = regs.lxr_rbx;
		rp->lxur_r11 = regs.lxr_r11;
		rp->lxur_r10 = regs.lxr_r10;
		rp->lxur_r9 = regs.lxr_r9;
		rp->lxur_r8 = regs.lxr_r8;
		rp->lxur_rax = regs.lxr_rax;
		rp->lxur_rcx = regs.lxr_rcx;
		rp->lxur_rdx = regs.lxr_rdx;
		rp->lxur_rsi = regs.lxr_rsi;
		rp->lxur_rdi = regs.lxr_rdi;
		rp->lxur_orig_rax = regs.lxr_orig_rax;
		rp->lxur_rip = regs.lxr_rip;
		rp->lxur_xcs = status.pr_reg[REG_CS];
		rp->lxur_rflags = status.pr_reg[REG_RFL];
		rp->lxur_rsp = regs.lxr_rsp;
		rp->lxur_xss = status.pr_reg[REG_SS];
		rp->lxur_xfs_base = status.pr_reg[REG_FSBASE];
		rp->lxur_xgs_base = status.pr_reg[REG_GSBASE];
		rp->lxur_xds = status.pr_reg[REG_DS];
		rp->lxur_xes = status.pr_reg[REG_ES];
		rp->lxur_xfs = regs.lxr_fs;
		rp->lxur_xgs = status.pr_reg[REG_GS];
#elif defined(_ILP32)
		rp->lxur_ebx = regs.lxr_ebx;
		rp->lxur_ecx = regs.lxr_ecx;
		rp->lxur_edx = regs.lxr_edx;
		rp->lxur_esi = regs.lxr_esi;
		rp->lxur_edi = regs.lxr_edi;
		rp->lxur_ebp = regs.lxr_ebp;
		rp->lxur_eax = regs.lxr_eax;
		rp->lxur_xds = status.pr_reg[DS];
		rp->lxur_xes = status.pr_reg[ES];
		rp->lxur_xfs = status.pr_reg[FS];
		rp->lxur_xgs = regs.lxr_gs;
		rp->lxur_orig_eax = regs.lxr_orig_eax;
		rp->lxur_eip = regs.lxr_eip;
		rp->lxur_xcs = status.pr_reg[CS];
		rp->lxur_eflags = status.pr_reg[EFL];
		rp->lxur_esp = regs.lxr_esp;
		rp->lxur_xss = status.pr_reg[SS];
#endif

	} else {
		(void) close(fd);

#if defined(_LP64)
		rp->lxur_r15 = status.pr_reg[REG_R15];
		rp->lxur_r14 = status.pr_reg[REG_R14];
		rp->lxur_r13 = status.pr_reg[REG_R13];
		rp->lxur_r12 = status.pr_reg[REG_R12];
		rp->lxur_rbp = status.pr_reg[REG_RBP];
		rp->lxur_rbx = status.pr_reg[REG_RBX];
		rp->lxur_r11 = status.pr_reg[REG_R11];
		rp->lxur_r10 = status.pr_reg[REG_R10];
		rp->lxur_r9 = status.pr_reg[REG_R9];
		rp->lxur_r8 = status.pr_reg[REG_R8];
		rp->lxur_rax = status.pr_reg[REG_RAX];
		rp->lxur_rcx = status.pr_reg[REG_RCX];
		rp->lxur_rdx = status.pr_reg[REG_RDX];
		rp->lxur_rsi = status.pr_reg[REG_RSI];
		rp->lxur_rdi = status.pr_reg[REG_RDI];
		rp->lxur_orig_rax = 0;
		rp->lxur_rip = status.pr_reg[REG_RIP];
		rp->lxur_xcs = status.pr_reg[REG_CS];
		rp->lxur_rflags = status.pr_reg[REG_RFL];
		rp->lxur_rsp = status.pr_reg[REG_RSP];
		rp->lxur_xss = status.pr_reg[REG_SS];
		rp->lxur_xfs = status.pr_reg[REG_FSBASE];
		rp->lxur_xgs = status.pr_reg[REG_GSBASE];
		rp->lxur_xds = status.pr_reg[REG_DS];
		rp->lxur_xes = status.pr_reg[REG_ES];
		rp->lxur_xfs = status.pr_reg[REG_FSBASE];
		rp->lxur_xgs = status.pr_reg[REG_GSBASE];
#elif defined(_ILP32)
		rp->lxur_ebx = status.pr_reg[EBX];
		rp->lxur_ecx = status.pr_reg[ECX];
		rp->lxur_edx = status.pr_reg[EDX];
		rp->lxur_esi = status.pr_reg[ESI];
		rp->lxur_edi = status.pr_reg[EDI];
		rp->lxur_ebp = status.pr_reg[EBP];
		rp->lxur_eax = status.pr_reg[EAX];
		rp->lxur_xds = status.pr_reg[DS];
		rp->lxur_xes = status.pr_reg[ES];
		rp->lxur_xfs = status.pr_reg[FS];
		rp->lxur_xgs = status.pr_reg[GS];
		rp->lxur_orig_eax = 0;
		rp->lxur_eip = status.pr_reg[EIP];
		rp->lxur_xcs = status.pr_reg[CS];
		rp->lxur_eflags = status.pr_reg[EFL];
		rp->lxur_esp = status.pr_reg[UESP];
		rp->lxur_xss = status.pr_reg[SS];
#endif

		/*
		 * If the target process has just returned from exec, it's not
		 * going to be sitting in the emulation function. In that case
		 * we need to manually fake up the values for %eax and orig_eax
		 * to indicate a successful return and that the traced process
		 * had called execve (respectively).
		 */
		if (status.pr_why == PR_SYSEXIT &&
		    status.pr_what == SYS_execve) {
#if defined(_LP64)
			rp->lxur_rax = 0;
			rp->lxur_orig_rax = LX_SYS_execve;
#elif defined(_ILP32)
			rp->lxur_eax = 0;
			rp->lxur_orig_eax = LX_SYS_execve;
#endif
		}
	}

	return (0);
}

static int
setregs(pid_t pid, lwpid_t lwpid, const lx_user_regs_t *rp)
{
	long ctl[1 + sizeof (prgregset_t) / sizeof (long)];
	lwpstatus_t status;
	uintptr_t addr;
	int fd, ret;

	if ((ret = get_lwpstatus(pid, lwpid, &status)) != 0)
		return (ret);

	if ((fd = open_procfile(pid, O_RDWR, "as")) < 0)
		return (-ESRCH);

	/*
	 * If we find the syscall regs (and are therefore in an emulated
	 * syscall, modify the register set at given address and set the
	 * remaining registers through the /proc interface. Otherwise just use
	 * the /proc interface to set register values;
	 */
	if ((addr = syscall_regs(fd, status.pr_reg[REG_FP], pid)) != 0) {
#if defined(_ILP32)
		lx_regs_t regs;

		regs.lxr_ebx = rp->lxur_ebx;
		regs.lxr_ecx = rp->lxur_ecx;
		regs.lxr_edx = rp->lxur_edx;
		regs.lxr_esi = rp->lxur_esi;
		regs.lxr_edi = rp->lxur_edi;
		regs.lxr_ebp = rp->lxur_ebp;
		regs.lxr_eax = rp->lxur_eax;
		regs.lxr_gs = rp->lxur_xgs;
		regs.lxr_orig_eax = rp->lxur_orig_eax;
		regs.lxr_eip = rp->lxur_eip;
		regs.lxr_esp = rp->lxur_esp;

		if (pwrite(fd, &regs, sizeof (regs), addr) != sizeof (regs)) {
			(void) close(fd);
			lx_debug("ptrace failed to write register set");
			return (-EIO);
		}
#endif

		(void) close(fd);

#if defined(_ILP32)
		status.pr_reg[DS] = rp->lxur_xds;
		status.pr_reg[ES] = rp->lxur_xes;
		status.pr_reg[FS] = rp->lxur_xfs;
		status.pr_reg[CS] = rp->lxur_xcs;
		status.pr_reg[EFL] = rp->lxur_eflags;
		status.pr_reg[SS] = rp->lxur_xss;
#endif

	} else {
		(void) close(fd);

#if defined(_ILP32)
		status.pr_reg[EBX] = rp->lxur_ebx;
		status.pr_reg[ECX] = rp->lxur_ecx;
		status.pr_reg[EDX] = rp->lxur_edx;
		status.pr_reg[ESI] = rp->lxur_esi;
		status.pr_reg[EDI] = rp->lxur_edi;
		status.pr_reg[EBP] = rp->lxur_ebp;
		status.pr_reg[EAX] = rp->lxur_eax;
		status.pr_reg[DS] = rp->lxur_xds;
		status.pr_reg[ES] = rp->lxur_xes;
		status.pr_reg[FS] = rp->lxur_xfs;
		status.pr_reg[GS] = rp->lxur_xgs;
		status.pr_reg[EIP] = rp->lxur_eip;
		status.pr_reg[CS] = rp->lxur_xcs;
		status.pr_reg[EFL] = rp->lxur_eflags;
		status.pr_reg[UESP] = rp->lxur_esp;
		status.pr_reg[SS] = rp->lxur_xss;
		status.pr_reg[SS] = rp->lxur_xss;
#endif
	}

	if ((fd = open_lwpfile(pid, lwpid, O_WRONLY, "lwpctl")) < 0)
		return (-ESRCH);

	ctl[0] = PCSREG;
	bcopy(status.pr_reg, &ctl[1], sizeof (prgregset_t));

	if (write(fd, &ctl, sizeof (ctl)) != sizeof (ctl)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);

	return (0);
}

static int
getfpregs(pid_t pid, lwpid_t lwpid, lx_user_fpregs_t *rp)
{
	lwpstatus_t status;
	struct _fpstate *fp;
#if defined(_ILP32)
	char *data;
	int i;
#endif
	int ret;

	if ((ret = get_lwpstatus(pid, lwpid, &status)) != 0)
		return (ret);

	fp = (struct _fpstate *)&status.pr_fpreg.fp_reg_set.fpchip_state;

#if defined(_ILP32)
	rp->lxuf_cwd = fp->cw;
	rp->lxuf_swd = fp->sw;
	rp->lxuf_twd = fp->tag;
	rp->lxuf_fip = fp->ipoff;
	rp->lxuf_fcs = fp->cssel;
	rp->lxuf_foo = fp->dataoff;
	rp->lxuf_fos = fp->datasel;

	/*
	 * The Linux structure uses 10 bytes per floating-point register.
	 */
	data = (char *)&rp->lxuf_st_space[0];
	for (i = 0; i < 8; i++) {
		bcopy(&fp->_st[i], data, 10);
		data += 10;
	}
#endif

	return (0);
}

static int
setfpregs(pid_t pid, lwpid_t lwpid, const lx_user_fpregs_t *rp)
{
	lwpstatus_t status;
	struct {
		long cmd;
		prfpregset_t regs;
	} ctl;
#if defined(_ILP32)
	struct _fpstate *fp = (struct _fpstate *)&ctl.regs;
	char *data;
	int i;
#endif
	int ret, fd;

	if ((ret = get_lwpstatus(pid, lwpid, &status)) != 0)
		return (ret);

	bcopy(&status.pr_fpreg, &ctl.regs, sizeof (ctl.regs));

#if defined(_ILP32)
	fp->cw = rp->lxuf_cwd;
	fp->sw = rp->lxuf_swd;
	fp->tag = rp->lxuf_twd;
	fp->ipoff = rp->lxuf_fip;
	fp->cssel = rp->lxuf_fcs;
	fp->dataoff = rp->lxuf_foo;
	fp->datasel = rp->lxuf_fos;

	/*
	 * The Linux structure uses 10 bytes per floating-point register.
	 */
	data = (char *)&rp->lxuf_st_space[0];
	for (i = 0; i < 8; i++) {
		bcopy(data, &fp->_st[i], 10);
		data += 10;
	}
#endif

	if ((fd = open_lwpfile(pid, lwpid, O_WRONLY, "lwpctl")) < 0)
		return (-ESRCH);

	ctl.cmd = PCSFPREG;
	if (write(fd, &ctl, sizeof (ctl)) != sizeof (ctl)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);

	return (0);
}


static int
getfpxregs(pid_t pid, lwpid_t lwpid, lx_user_fpxregs_t *rp)
{
#if defined(_ILP32)
	lwpstatus_t status;
	struct _fpstate *fp;
	int ret, i;

	if ((ret = get_lwpstatus(pid, lwpid, &status)) != 0)
		return (ret);

	fp = (struct _fpstate *)&status.pr_fpreg.fp_reg_set.fpchip_state;

	rp->lxux_cwd = (uint16_t)fp->cw;
	rp->lxux_swd = (uint16_t)fp->sw;
	rp->lxux_twd = (uint16_t)fp->tag;
	rp->lxux_fop = (uint16_t)(fp->cssel >> 16);
	rp->lxux_fip = fp->ipoff;
	rp->lxux_fcs = (uint16_t)fp->cssel;
	rp->lxux_foo = fp->dataoff;
	rp->lxux_fos = fp->datasel;
	rp->lxux_mxcsr = status.pr_fpreg.fp_reg_set.fpchip_state.mxcsr;

	bcopy(fp->xmm, rp->lxux_xmm_space, sizeof (rp->lxux_xmm_space));
	bzero(rp->lxux_st_space, sizeof (rp->lxux_st_space));
	for (i = 0; i < 8; i++) {
		bcopy(&fp->_st[i], &rp->lxux_st_space[i * 4],
		    sizeof (fp->_st[i]));
	}
#endif

	return (0);
}

static int
setfpxregs(pid_t pid, lwpid_t lwpid, const lx_user_fpxregs_t *rp)
{
#if defined(_ILP32)
	lwpstatus_t status;
	struct {
		long cmd;
		prfpregset_t regs;
	} ctl;
	struct _fpstate *fp = (struct _fpstate *)&ctl.regs;
	int ret, i, fd;

	if ((ret = get_lwpstatus(pid, lwpid, &status)) != 0)
		return (ret);

	bcopy(&status.pr_fpreg, &ctl.regs, sizeof (ctl.regs));

	fp->cw = rp->lxux_cwd;
	fp->sw = rp->lxux_swd;
	fp->tag = rp->lxux_twd;
	fp->ipoff = rp->lxux_fip;
	fp->cssel = rp->lxux_fcs | (rp->lxux_fop << 16);
	fp->dataoff = rp->lxux_foo;
	fp->datasel = rp->lxux_fos;

	bcopy(rp->lxux_xmm_space, fp->xmm, sizeof (rp->lxux_xmm_space));
	for (i = 0; i < 8; i++) {
		bcopy(&rp->lxux_st_space[i * 4], &fp->_st[i],
		    sizeof (fp->_st[i]));
	}

	if ((fd = open_lwpfile(pid, lwpid, O_WRONLY, "lwpctl")) < 0)
		return (-ESRCH);

	ctl.cmd = PCSFPREG;
	if (write(fd, &ctl, sizeof (ctl)) != sizeof (ctl)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);
#endif

	return (0);
}

/*
 * Solaris does not allow a process to manipulate its own or some
 * other process's debug registers.  Linux ptrace(2) allows this
 * and gdb manipulates them for its watchpoint implementation.
 *
 * We keep a pseudo set of debug registers for each traced process
 * and map their contents into the appropriate PCWATCH /proc
 * operations when they are activated by gdb.
 *
 * To understand how the debug registers work on x86 machines,
 * see section 13.1 of the AMD x86-64 Architecture Programmer's
 * Manual, Volume 2, System Programming.
 */
static uintptr_t *
debug_registers(pid_t pid)
{
	ptrace_state_map_t *p;

	(void) mutex_lock(&ptrace_map_mtx);
	for (p = ptrace_state_map; p != NULL; p = p->psm_next) {
		if (p->psm_pid == pid)
			break;
	}
	if (p == NULL && (p = malloc(sizeof (*p))) != NULL) {
		bzero(p, sizeof (*p));
		p->psm_pid = pid;
		p->psm_next = ptrace_state_map;
		p->psm_debugreg[6] = 0xffff0ff0;	/* read as ones */
		ptrace_state_map = p;
	}
	(void) mutex_unlock(&ptrace_map_mtx);
	return (p != NULL? p->psm_debugreg : NULL);
}

static void
free_debug_registers(pid_t pid)
{
	ptrace_state_map_t **pp;
	ptrace_state_map_t *p;

	/* ASSERT(MUTEX_HELD(&ptrace_map_mtx) */
	for (pp = &ptrace_state_map; (p = *pp) != NULL; pp = &p->psm_next) {
		if (p->psm_pid == pid) {
			*pp = p->psm_next;
			free(p);
			break;
		}
	}
}

static int
setup_watchpoints(pid_t pid, uintptr_t *debugreg)
{
	int dr7 = debugreg[7];
	int lrw;
	int fd;
	size_t size = NULL;
	prwatch_t prwatch[4];
	int nwatch;
	int i;
	int wflags = NULL;
	int error;
	struct {
		long req;
		prwatch_t prwatch;
	} ctl;

	/* find all watched areas */
	if ((fd = open_procfile(pid, O_RDONLY, "watch")) < 0)
		return (-ESRCH);
	nwatch = read(fd, prwatch, sizeof (prwatch)) / sizeof (prwatch_t);
	(void) close(fd);
	if ((fd = open_procfile(pid, O_WRONLY, "ctl")) < 0)
		return (-ESRCH);
	/* clear all watched areas */
	for (i = 0; i < nwatch; i++) {
		ctl.req = PCWATCH;
		ctl.prwatch = prwatch[i];
		ctl.prwatch.pr_wflags = 0;
		if (write(fd, &ctl, sizeof (ctl)) != sizeof (ctl)) {
			error = -errno;
			(void) close(fd);
			return (error);
		}
	}
	/* establish all new watched areas */
	for (i = 0; i < 4; i++) {
		if ((dr7 & (1 << (2 * i))) == 0)	/* enabled? */
			continue;
		lrw = (dr7 >> (16 + (4 * i))) & 0xf;
		switch (lrw >> 2) {	/* length */
		case 0: size = 1; break;
		case 1: size = 2; break;
		case 2: size = 8; break;
		case 3: size = 4; break;
		}
		switch (lrw & 0x3) {	/* mode */
		case 0: wflags = WA_EXEC; break;
		case 1: wflags = WA_WRITE; break;
		case 2: continue;
		case 3: wflags = WA_READ | WA_WRITE; break;
		}
		ctl.req = PCWATCH;
		ctl.prwatch.pr_vaddr = debugreg[i];
		ctl.prwatch.pr_size = size;
		ctl.prwatch.pr_wflags = wflags | WA_TRAPAFTER;
		if (write(fd, &ctl, sizeof (ctl)) != sizeof (ctl)) {
			error = -errno;
			(void) close(fd);
			return (error);
		}
	}
	(void) close(fd);
	return (0);
}

/*
 * Returns TRUE if the process is traced, FALSE otherwise.  This is only true
 * if the process is currently stopped, and has been traced using
 * PTRACE_TRACEME, PTRACE_ATTACH or one of the Linux-specific trace options.
 */
static int
is_traced(pid_t pid)
{
	ptrace_monitor_map_t *p;
	pstatus_t status;
	uint_t curr_opts;

	/*
	 * First get the stop options since that is an indication that the
	 * process is being traced.
	 */
	if (syscall(SYS_brand, B_PTRACE_EXT_OPTS, B_PTRACE_EXT_OPTS_GET, pid,
	    &curr_opts) != 0)
		return (0);

	if (get_status(pid, &status) != 0)
		return (0);

	if ((status.pr_flags & PR_PTRACE || curr_opts != 0) &&
	    (status.pr_ppid == getpid()) &&
	    (status.pr_lwp.pr_flags & PR_ISTOP))
		return (1);

	(void) mutex_lock(&ptrace_map_mtx);
	for (p = ptrace_monitor_map; p != NULL; p = p->pmm_next) {
		if (p->pmm_target == pid) {
			(void) mutex_unlock(&ptrace_map_mtx);
			return (1);
		}
	}
	(void) mutex_unlock(&ptrace_map_mtx);

	return (0);
}

static int
ptrace_trace_common(int fd)
{
	struct {
		long cmd;
		union {
			long flags;
			sigset_t signals;
			fltset_t faults;
		} arg;
	} ctl;
	size_t size;

	ctl.cmd = PCSTRACE;
	prfillset(&ctl.arg.signals);
	size = sizeof (long) + sizeof (sigset_t);
	if (write(fd, &ctl, size) != size)
		return (-1);

	ctl.cmd = PCSFAULT;
	premptyset(&ctl.arg.faults);
	size = sizeof (long) + sizeof (fltset_t);
	if (write(fd, &ctl, size) != size)
		return (-1);

	ctl.cmd = PCUNSET;
	ctl.arg.flags = PR_FORK;
	size = sizeof (long) + sizeof (long);
	if (write(fd, &ctl, size) != size)
		return (-1);

	return (0);
}

/*
 * Notify that parent that we wish to be traced.  This is the equivalent of:
 *
 * 	1. Stop on all signals, and nothing else
 * 	2. Turn off inherit-on-fork flag
 * 	3. Set ptrace compatible flag
 *
 * If we are not the main thread, then the client is trying to request behavior
 * by which one of its own thread is to be traced.  We don't support this mode
 * of operation.
 */
static int
ptrace_traceme(void)
{
	int fd, ret;
	int error;
	long ctl[2];
	pstatus_t status;
	pid_t pid = getpid();

	if (_lwp_self() != 1) {
		lx_unsupported("thread %d calling PTRACE_TRACEME is "
		    "unsupported", _lwp_self());
		return (-ENOTSUP);
	}

	if ((ret = get_status(pid, &status)) != 0)
		return (ret);

	/*
	 * Why would a process try to do this twice? I'm not sure, but there's
	 * a conformance test which wants this to fail just so.
	 */
	if (status.pr_flags & PR_PTRACE)
		return (-EPERM);

	if ((fd = open_procfile(pid, O_WRONLY, "ctl")) < 0)
		return (-errno);

	ctl[0] = PCSET;
	ctl[1] = PR_PTRACE;
	error = 0;
	if (write(fd, ctl, sizeof (ctl)) != sizeof (ctl) ||
	    ptrace_trace_common(fd) != 0)
		error = -errno;

	(void) close(fd);
	return (error);
}

/*
 * Read a word of data from the given address.  Because this is a process-wide
 * action, we don't need the lwpid.
 */
static long
ptrace_peek(pid_t pid, uintptr_t addr, long *ret)
{
	int fd;
	long data;

	if (!is_traced(pid))
		return (-ESRCH);

	if ((fd = open_procfile(pid, O_RDONLY, "as")) < 0)
		return (-ESRCH);

	if (pread(fd, &data, sizeof (data), addr) != sizeof (data)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);

	if (uucopy(&data, ret, sizeof (data)) != 0)
		return (-errno);

	return (0);
}

#define	LX_USER_BOUND(m)	\
(offsetof(lx_user_t, m) + sizeof (((lx_user_t *)NULL)->m))

static int
ptrace_peek_user(pid_t pid, lwpid_t lwpid, uintptr_t off, int *ret)
{
	int err, data;
	uintptr_t *debugreg;
	int dreg;

	if (!is_traced(pid))
		return (-ESRCH);

	/*
	 * The offset specified by the user is an offset into the Linux
	 * user structure (seriously). Rather than constructing a full
	 * user structure, we figure out which part of the user structure
	 * the offset is in, and fill in just that component.
	 */
	if (off < LX_USER_BOUND(lxu_regs)) {
		lx_user_regs_t regs;

		if ((err = getregs(pid, lwpid, &regs)) != 0)
			return (err);

		data = *(int *)((uintptr_t)&regs + off -
		    offsetof(lx_user_t, lxu_regs));

	} else if (off < LX_USER_BOUND(lxu_fpvalid)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_i387)) {
		lx_user_fpregs_t regs;

		if ((err = getfpregs(pid, lwpid, &regs)) != 0)
			return (err);

		data = *(int *)((uintptr_t)&regs + off -
		    offsetof(lx_user_t, lxu_i387));

	} else if (off < LX_USER_BOUND(lxu_tsize)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_dsize)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_ssize)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_start_code)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_start_stack)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_signal)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_reserved)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_ar0)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_fpstate)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_magic)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_comm)) {
		lx_err("offset = %lu\n", off);
		assert(0);
	} else if (off < LX_USER_BOUND(lxu_debugreg)) {
		dreg = (off - offsetof(lx_user_t, lxu_debugreg)) / sizeof (int);
		if (dreg == 4)		/* aliased */
			dreg = 6;
		else if (dreg == 5)	/* aliased */
			dreg = 7;
		if ((debugreg = debug_registers(pid)) != NULL)
			data = debugreg[dreg];
		else
			data = 0;
	} else {
		lx_unsupported("unsupported ptrace peek user offset: 0x%x\n",
		    off);
		assert(0);
		return (-ENOTSUP);
	}

	if (uucopy(&data, ret, sizeof (data)) != 0)
		return (-errno);

	return (0);
}

/*
 * Write a word of data to the given address.  Because this is a process-wide
 * action, we don't need the lwpid.  Returns EINVAL if the address is not
 * word-aligned.
 */
static int
ptrace_poke(pid_t pid, uintptr_t addr, int data)
{
	int fd;

	if (!is_traced(pid))
		return (-ESRCH);

	if (addr & 0x3)
		return (-EINVAL);

	if ((fd = open_procfile(pid, O_WRONLY, "as")) < 0)
		return (-ESRCH);

	if (pwrite(fd, &data, sizeof (data), addr) != sizeof (data)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);
	return (0);
}

static int
ptrace_poke_user(pid_t pid, lwpid_t lwpid, uintptr_t off, int data)
{
	lx_user_regs_t regs;
	int err = 0;
	uintptr_t *debugreg;
	int dreg;

	if (!is_traced(pid))
		return (-ESRCH);

	if (off & 0x3)
		return (-EINVAL);

	if (off < offsetof(lx_user_t, lxu_regs) + sizeof (lx_user_regs_t)) {
		if ((err = getregs(pid, lwpid, &regs)) != 0)
			return (err);
		*(int *)((uintptr_t)&regs + off -
		    offsetof(lx_user_t, lxu_regs)) = data;
		return (setregs(pid, lwpid, &regs));
	}

	if (off >= offsetof(lx_user_t, lxu_debugreg) &&
	    off < offsetof(lx_user_t, lxu_debugreg) + 8 * sizeof (int)) {
		dreg = (off - offsetof(lx_user_t, lxu_debugreg)) / sizeof (int);
		if (dreg == 4)		/* aliased */
			dreg = 6;
		else if (dreg == 5)	/* aliased */
			dreg = 7;
		if ((debugreg = debug_registers(pid)) != NULL) {
			debugreg[dreg] = data;
			if (dreg == 7)
				err = setup_watchpoints(pid, debugreg);
		}
		return (err);
	}

	lx_unsupported("unsupported ptrace poke user offset: 0x%x\n", off);
	assert(0);
	return (-ENOTSUP);
}

static int
ptrace_cont_common(int fd, int sig, int run, int step)
{
	long ctl[1 + 1 + sizeof (siginfo_t) / sizeof (long) + 2];
	long *ctlp = ctl;
	size_t size;

	assert(0 <= sig && sig <= LX_NSIG);
	assert(!step || run);

	/*
	 * Clear the current signal.
	 */
	*ctlp++ = PCCSIG;

	/*
	 * Send a signal if one was specified.
	 */
	if (sig != 0 && sig != LX_SIGSTOP) {
		siginfo_t *infop;

		*ctlp++ = PCSSIG;
		infop = (siginfo_t *)ctlp;
		bzero(infop, sizeof (siginfo_t));
		infop->si_signo = ltos_signo[sig];

		ctlp += sizeof (siginfo_t) / sizeof (long);
	}

	/*
	 * If run is true, set the lwp running.
	 */
	if (run) {
		*ctlp++ = PCRUN;
		*ctlp++ = step ? PRSTEP : 0;
	}

	size = (char *)ctlp - (char *)&ctl[0];
	assert(size <= sizeof (ctl));

	if (write(fd, ctl, size) != size) {
		lx_debug("failed to continue %s", strerror(errno));
		return (-EIO);
	}

	return (0);
}

static int
ptrace_cont_monitor(ptrace_monitor_map_t *p)
{
	long ctl[2];
	int fd;

	fd = open_procfile(p->pmm_monitor, O_WRONLY, "ctl");
	if (fd < 0) {
		lx_debug("failed to open monitor ctl %d",
		    errno);
		return (-EIO);
	}

	ctl[0] = PCRUN;
	ctl[1] = PRCSIG;
	if (write(fd, ctl, sizeof (ctl)) != sizeof (ctl)) {
		(void) close(fd);
		return (-EIO);
	}

	(void) close(fd);

	return (0);
}

static int
ptrace_cont(pid_t lxpid, pid_t pid, lwpid_t lwpid, int sig, int step)
{
	ptrace_monitor_map_t *p;
	uintptr_t *debugreg;
	int fd, ret;

	if (!is_traced(pid))
		return (-ESRCH);

	if (sig < 0 || sig > LX_NSIG)
		return (-EINVAL);

	if ((fd = open_lwpfile(pid, lwpid, O_WRONLY, "lwpctl")) < 0)
		return (-ESRCH);

	if ((ret = ptrace_cont_common(fd, sig, 1, step)) != 0) {
		(void) close(fd);
		return (ret);
	}

	(void) close(fd);

	/* kludge: use debugreg[4] to remember the single-step flag */
	if ((debugreg = debug_registers(pid)) != NULL)
		debugreg[4] = step;

	/*
	 * Check for a monitor and get it moving if we find it. If any of the
	 * /proc operations fail, we're kind of sunk so just return an error.
	 */
	(void) mutex_lock(&ptrace_map_mtx);
	for (p = ptrace_monitor_map; p != NULL; p = p->pmm_next) {
		if (p->pmm_target == lxpid) {
			if ((ret = ptrace_cont_monitor(p)) != 0)
				return (ret);
			break;
		}
	}
	(void) mutex_unlock(&ptrace_map_mtx);

	return (0);
}

/*
 * If a monitor exists for this traced process, dispose of it.
 * First turn off its ptrace flag so we won't be notified of its
 * impending demise.  We ignore errors for this step since they
 * indicate only that the monitor has been damaged due to pilot
 * error.  Then kill the monitor, and wait for it.  If the wait
 * succeeds we can dispose of the corpse, otherwise another thread's
 * wait call has collected it and we need to set a flag in the
 * structure so that if can be picked up in wait.
 */
static void
monitor_kill(pid_t lxpid, pid_t pid)
{
	ptrace_monitor_map_t *p, **pp;
	pid_t mpid;
	int fd;
	long ctl[2];

	(void) mutex_lock(&ptrace_map_mtx);
	free_debug_registers(pid);
	for (pp = &ptrace_monitor_map; (p = *pp) != NULL; pp = &p->pmm_next) {
		if (p->pmm_target == lxpid) {
			mpid = p->pmm_monitor;
			if ((fd = open_procfile(mpid, O_WRONLY, "ctl")) >= 0) {
				ctl[0] = PCUNSET;
				ctl[1] = PR_PTRACE;
				(void) write(fd, ctl, sizeof (ctl));
				(void) close(fd);
			}

			(void) kill(mpid, SIGKILL);

			if (waitpid(mpid, NULL, 0) == mpid) {
				*pp = p->pmm_next;
				free(p);
			} else {
				p->pmm_exiting = 1;
			}

			break;
		}
	}
	(void) mutex_unlock(&ptrace_map_mtx);
}

static int
ptrace_kill(pid_t lxpid, pid_t pid)
{
	int ret;

	if (!is_traced(pid))
		return (-ESRCH);

	ret = kill(pid, SIGKILL);

	/* kill off the monitor process, if any */
	monitor_kill(lxpid, pid);

	return (ret);
}

static int
ptrace_step(pid_t lxpid, pid_t pid, lwpid_t lwpid, int sig)
{
	return (ptrace_cont(lxpid, pid, lwpid, sig, 1));
}

static int
ptrace_getregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_regs_t regs;
	int ret;

	if (!is_traced(pid))
		return (-ESRCH);

	if ((ret = getregs(pid, lwpid, &regs)) != 0)
		return (ret);

	if (uucopy(&regs, (void *)addr, sizeof (regs)) != 0)
		return (-errno);

	return (0);
}

static int
ptrace_setregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_regs_t regs;

	if (!is_traced(pid))
		return (-ESRCH);

	if (uucopy((void *)addr, &regs, sizeof (regs)) != 0)
		return (-errno);

	return (setregs(pid, lwpid, &regs));
}

static int
ptrace_getfpregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_fpregs_t regs;
	int ret;

	if (!is_traced(pid))
		return (-ESRCH);

	if ((ret = getfpregs(pid, lwpid, &regs)) != 0)
		return (ret);

	if (uucopy(&regs, (void *)addr, sizeof (regs)) != 0)
		return (-errno);

	return (0);
}

static int
ptrace_setfpregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_fpregs_t regs;

	if (!is_traced(pid))
		return (-ESRCH);

	if (uucopy((void *)addr, &regs, sizeof (regs)) != 0)
		return (-errno);

	return (setfpregs(pid, lwpid, &regs));
}

static int
ptrace_getfpxregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_fpxregs_t regs;
	int ret;

	if (!is_traced(pid))
		return (-ESRCH);

	if ((ret = getfpxregs(pid, lwpid, &regs)) != 0)
		return (ret);

	if (uucopy(&regs, (void *)addr, sizeof (regs)) != 0)
		return (-errno);

	return (0);
}

static int
ptrace_setfpxregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_fpxregs_t regs;

	if (!is_traced(pid))
		return (-ESRCH);

	if (uucopy((void *)addr, &regs, sizeof (regs)) != 0)
		return (-errno);

	return (setfpxregs(pid, lwpid, &regs));
}

static void __NORETURN
ptrace_monitor(int fd)
{
	struct {
		long cmd;
		union {
			long flags;
			sigset_t signals;
			fltset_t faults;
		} arg;
	} ctl;
	size_t size;
	int monfd;
	int rv;

	monfd = open_procfile(getpid(), O_WRONLY, "ctl");

	ctl.cmd = PCSTRACE;	/* trace only SIGTRAP */
	premptyset(&ctl.arg.signals);
	praddset(&ctl.arg.signals, SIGTRAP);
	size = sizeof (long) + sizeof (sigset_t);
	(void) write(monfd, &ctl, size);	/* can't fail */

	ctl.cmd = PCSFAULT;
	premptyset(&ctl.arg.faults);
	size = sizeof (long) + sizeof (fltset_t);
	(void) write(monfd, &ctl, size);	/* can't fail */

	ctl.cmd = PCUNSET;
	ctl.arg.flags = PR_FORK;
	size = sizeof (long) + sizeof (long);
	(void) write(monfd, &ctl, size);	/* can't fail */

	ctl.cmd = PCSET;	/* wait()able by the parent */
	ctl.arg.flags = PR_PTRACE;
	size = sizeof (long) + sizeof (long);
	(void) write(monfd, &ctl, size);	/* can't fail */

	(void) close(monfd);

	ctl.cmd = PCWSTOP;
	size = sizeof (long);

	for (;;) {
		/*
		 * Wait for the traced process to stop.
		 */
		if (write(fd, &ctl, size) != size) {
			rv = (errno == ENOENT)? 0 : 1;
			lx_debug("monitor failed to wait for LWP to stop: %s",
			    strerror(errno));
			_exit(rv);
		}

		lx_debug("monitor caught traced LWP");

		/*
		 * Pull the ptrace trigger by sending ourself a SIGTRAP. This
		 * will cause this, the monitor process, to stop which will
		 * cause the parent's waitid(2) call to return this process
		 * id. In lx_wait(), we remap the monitor process's pid and
		 * status to those of the traced LWP. When the parent process
		 * uses ptrace to resume the traced LWP, it will additionally
		 * restart this process.
		 */
		(void) _lwp_kill(_lwp_self(), SIGTRAP);

		lx_debug("monitor was resumed");
	}
}

static int
ptrace_attach_common(int fd, pid_t lxpid, pid_t pid, lwpid_t lwpid, int run)
{
	pid_t child;
	ptrace_monitor_map_t *p;
	sigset_t unblock;
	pstatus_t status;
	long ctl[1 + sizeof (sysset_t) / sizeof (long) + 2];
	long *ctlp = ctl;
	size_t size;
	sysset_t *sysp;
	int ret;

	/*
	 * We're going to need this structure so better to fail now before its
	 * too late to turn back.
	 */
	if ((p = malloc(sizeof (ptrace_monitor_map_t))) == NULL)
		return (-EIO);

	if ((ret = get_status(pid, &status)) != 0) {
		free(p);
		return (ret);
	}

	/*
	 * If this process is already traced, bail.
	 */
	if (status.pr_flags & PR_PTRACE) {
		free(p);
		return (-EPERM);
	}

	/*
	 * Turn on the appropriate tracing flags. It's exceedingly unlikely
	 * that this operation will fail; any failure would probably be due
	 * to another /proc consumer mucking around.
	 */
	if (ptrace_trace_common(fd) != 0) {
		free(p);
		return (-EIO);
	}

	/*
	 * Native ptrace automatically catches processes when they exec so we
	 * have to do that explicitly here.
	 */
	*ctlp++ = PCSEXIT;
	sysp = (sysset_t *)ctlp;
	ctlp += sizeof (sysset_t) / sizeof (long);
	premptyset(sysp);
	praddset(sysp, SYS_execve);
	if (run) {
		*ctlp++ = PCRUN;
		*ctlp++ = 0;
	}

	size = (char *)ctlp - (char *)&ctl[0];

	if (write(fd, ctl, size) != size) {
		free(p);
		return (-EIO);
	}

	/*
	 * Spawn the monitor proceses to notify this process of events of
	 * interest in the traced process. We block signals here both so
	 * we're not interrupted during this operation and so that the
	 * monitor process doesn't accept signals.
	 */
	(void) sigprocmask(SIG_BLOCK, &blockable_sigs, &unblock);
	if ((child = fork1()) == 0)
		ptrace_monitor(fd);
	(void) sigprocmask(SIG_SETMASK, &unblock, NULL);

	if (child == -1) {
		lx_debug("failed to fork monitor process\n");
		free(p);
		return (-EIO);
	}

	p->pmm_monitor = child;
	p->pmm_target = lxpid;
	p->pmm_pid = pid;
	p->pmm_lwpid = lwpid;
	p->pmm_exiting = 0;

	(void) mutex_lock(&ptrace_map_mtx);
	p->pmm_next = ptrace_monitor_map;
	ptrace_monitor_map = p;
	(void) mutex_unlock(&ptrace_map_mtx);

	return (0);
}

static int
ptrace_attach(pid_t lxpid, pid_t pid, lwpid_t lwpid)
{
	int fd, ret;
	long ctl;

	/*
	 * Linux doesn't let you trace process 1 -- go figure.
	 */
	if (lxpid == 1)
		return (-EPERM);

	if ((fd = open_lwpfile(pid, lwpid, O_WRONLY | O_EXCL, "lwpctl")) < 0)
		return (errno == EBUSY ? -EPERM : -ESRCH);

	ctl = PCSTOP;
	if (write(fd, &ctl, sizeof (ctl)) != sizeof (ctl)) {
		lx_err("failed to stop %d/%d\n", (int)pid, (int)lwpid);
		assert(0);
	}

	ret = ptrace_attach_common(fd, lxpid, pid, lwpid, 0);

	(void) close(fd);

	return (ret);
}

static int
ptrace_detach(pid_t lxpid, pid_t pid, lwpid_t lwpid, int sig)
{
	long ctl[2];
	int fd, ret;

	if (!is_traced(pid))
		return (-ESRCH);

	if (sig < 0 || sig > LX_NSIG)
		return (-EINVAL);

	if ((fd = open_lwpfile(pid, lwpid, O_WRONLY, "lwpctl")) < 0)
		return (-ESRCH);

	/*
	 * The /proc ptrace flag may not be set, but we clear it
	 * unconditionally since doing so doesn't hurt anything.
	 */
	ctl[0] = PCUNSET;
	ctl[1] = PR_PTRACE;
	if (write(fd, ctl, sizeof (ctl)) != sizeof (ctl)) {
		(void) close(fd);
		return (-EIO);
	}

	/*
	 * Clear the brand-specific system call tracing flag to ensure that
	 * the target doesn't stop unexpectedly some time in the future.
	 */
	if ((ret = syscall(SYS_brand, B_PTRACE_SYSCALL, pid, lwpid, 0)) != 0) {
		(void) close(fd);
		return (-ret);
	}

	/* kill off the monitor process, if any */
	monitor_kill(lxpid, pid);

	/*
	 * Turn on the run-on-last-close flag so that all tracing flags will be
	 * cleared when we close the control file descriptor.
	 */
	ctl[0] = PCSET;
	ctl[1] = PR_RLC;
	if (write(fd, ctl, sizeof (ctl)) != sizeof (ctl)) {
		(void) close(fd);
		return (-EIO);
	}

	/*
	 * Clear the current signal (if any) and possibly send the traced
	 * process a new signal.
	 */
	ret = ptrace_cont_common(fd, sig, 0, 0);

	(void) close(fd);

	return (ret);
}

static int
ptrace_syscall(pid_t lxpid, pid_t pid, lwpid_t lwpid, int sig)
{
	int ret;

	if (!is_traced(pid))
		return (-ESRCH);

	if ((ret = syscall(SYS_brand, B_PTRACE_SYSCALL, pid, lwpid, 1)) != 0)
		return (-ret);

	return (ptrace_cont(lxpid, pid, lwpid, sig, 0));
}

static int
ptrace_setoptions(pid_t pid, int options)
{
	int ret;
	int fd;
	int error = 0;
	struct {
		long cmd;
		union {
			long flags;
			sigset_t signals;
			fltset_t faults;
		} arg;
	} ctl;
	size_t size;
	pstatus_t status;

	if ((ret = get_status(pid, &status)) != 0)
		return (ret);

	if ((fd = open_procfile(pid, O_WRONLY, "ctl")) < 0)
		return (-errno);

	/* since we're doing option tracing now, only catch sigtrap */
	if (error == 0) {
		ctl.cmd = PCSTRACE;
		premptyset(&ctl.arg.signals);
		praddset(&ctl.arg.signals, SIGTRAP);
		size = sizeof (long) + sizeof (sigset_t);
		if (write(fd, &ctl, size) != size)
			error = -errno;
	}

	(void) close(fd);

	if (error != 0)
		return (error);

	ret = syscall(SYS_brand, B_PTRACE_EXT_OPTS, B_PTRACE_EXT_OPTS_SET, pid,
	    options);

	return (-ret);
}

void
lx_ptrace_stop_if_option(int option)
{
	pid_t pid;
	uint_t curr_opts;

	pid = getpid();
	if (pid == 1)
		pid = zoneinit_pid;

	/* first we have to see if the stop option is set for this process */
	if (syscall(SYS_brand, B_PTRACE_EXT_OPTS, B_PTRACE_EXT_OPTS_GET, pid,
	    &curr_opts) != 0)
		return;

	/*
	 * If we just forked/cloned, then the trace flags only carry over to
	 * the child if the specific flag was enabled on the parent. For
	 * example, if only TRACEFORK is enabled and we clone, then we must
	 * clear the trace flags. If TRACEFORK is enabled and we fork, then we
	 * keep the flags.
	 */
	if ((option == LX_PTRACE_O_TRACECLONE ||
	    option == LX_PTRACE_O_TRACEFORK ||
	    option == LX_PTRACE_O_TRACEVFORK) && (curr_opts & option) == 0) {
		(void) syscall(SYS_brand, B_PTRACE_EXT_OPTS,
		    B_PTRACE_EXT_OPTS_SET, pid, 0);
	}

	/* now if the option is/was set, this brand call will stop us */
	if (curr_opts & option)
		(void) syscall(SYS_brand, B_PTRACE_STOP_FOR_OPT, option);
}

long
lx_ptrace(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	pid_t pid, lxpid = (pid_t)p2;
	lwpid_t lwpid;

	if ((p1 != LX_PTRACE_TRACEME) &&
	    (lx_lpid_to_spair(lxpid, &pid, &lwpid) < 0))
		return (-ESRCH);

	switch (p1) {
	case LX_PTRACE_TRACEME:
		return (ptrace_traceme());

	case LX_PTRACE_PEEKTEXT:
	case LX_PTRACE_PEEKDATA:
		return (ptrace_peek(pid, p3, (long *)p4));

	case LX_PTRACE_PEEKUSER:
		return (ptrace_peek_user(pid, lwpid, p3, (int *)p4));

	case LX_PTRACE_POKETEXT:
	case LX_PTRACE_POKEDATA:
		return (ptrace_poke(pid, p3, (int)p4));

	case LX_PTRACE_POKEUSER:
		return (ptrace_poke_user(pid, lwpid, p3, (int)p4));

	case LX_PTRACE_CONT:
		return (ptrace_cont(lxpid, pid, lwpid, (int)p4, 0));

	case LX_PTRACE_KILL:
		return (ptrace_kill(lxpid, pid));

	case LX_PTRACE_SINGLESTEP:
		return (ptrace_step(lxpid, pid, lwpid, (int)p4));

	case LX_PTRACE_GETREGS:
		return (ptrace_getregs(pid, lwpid, p4));

	case LX_PTRACE_SETREGS:
		return (ptrace_setregs(pid, lwpid, p4));

	case LX_PTRACE_GETFPREGS:
		return (ptrace_getfpregs(pid, lwpid, p4));

	case LX_PTRACE_SETFPREGS:
		return (ptrace_setfpregs(pid, lwpid, p4));

	case LX_PTRACE_ATTACH:
		return (ptrace_attach(lxpid, pid, lwpid));

	case LX_PTRACE_DETACH:
		return (ptrace_detach(lxpid, pid, lwpid, (int)p4));

	case LX_PTRACE_GETFPXREGS:
		return (ptrace_getfpxregs(pid, lwpid, p4));

	case LX_PTRACE_SETFPXREGS:
		return (ptrace_setfpxregs(pid, lwpid, p4));

	case LX_PTRACE_SYSCALL:
		return (ptrace_syscall(lxpid, pid, lwpid, (int)p4));

	case LX_PTRACE_SETOPTIONS:
		return (ptrace_setoptions(pid, (int)p4));

	default:
		return (-EINVAL);
	}
}

void
lx_ptrace_fork(void)
{
	/*
	 * Send a special signal (that has no Linux equivalent) to indicate
	 * that we're in this particularly special case. The signal will be
	 * ignored by this process, but noticed by /proc consumers tracing
	 * this process.
	 */
	(void) _lwp_kill(_lwp_self(), SIGWAITING);
}

static void
ptrace_catch_fork(pid_t pid, int monitor)
{
	long ctl[14 + 2 * sizeof (sysset_t) / sizeof (long)];
	long *ctlp;
	sysset_t *sysp;
	size_t size;
	pstatus_t ps;
	pid_t child;
	int fd, err;

	/*
	 * If any of this fails, we're really sunk since the child
	 * will be stuck in the middle of lx_ptrace_fork().
	 * Fortunately it's practically assured to succeed unless
	 * something is seriously wrong on the system.
	 */
	if ((fd = open_procfile(pid, O_WRONLY, "ctl")) < 0) {
		lx_debug("lx_catch_fork: failed to control %d",
		    (int)pid);
		return;
	}

	/*
	 * Turn off the /proc PR_PTRACE flag so the parent doesn't get
	 * spurious wake ups while we're working our dark magic. Arrange to
	 * catch the process when it exits from fork, and turn on the /proc
	 * inherit-on-fork flag so we catcht the child as well. We then run
	 * the process, wait for it to stop on the fork1(2) call and reset
	 * the tracing flags to their original state.
	 */
	ctlp = ctl;
	*ctlp++ = PCCSIG;
	if (!monitor) {
		*ctlp++ = PCUNSET;
		*ctlp++ = PR_PTRACE;
	}
	*ctlp++ = PCSET;
	*ctlp++ = PR_FORK;
	*ctlp++ = PCSEXIT;
	sysp = (sysset_t *)ctlp;
	ctlp += sizeof (sysset_t) / sizeof (long);
	premptyset(sysp);
	praddset(sysp, SYS_forksys);	/* fork1() is forksys(0, 0) */
	*ctlp++ = PCRUN;
	*ctlp++ = 0;
	*ctlp++ = PCWSTOP;
	if (!monitor) {
		*ctlp++ = PCSET;
		*ctlp++ = PR_PTRACE;
	}
	*ctlp++ = PCUNSET;
	*ctlp++ = PR_FORK;
	*ctlp++ = PCSEXIT;
	sysp = (sysset_t *)ctlp;
	ctlp += sizeof (sysset_t) / sizeof (long);
	premptyset(sysp);
	if (monitor)
		praddset(sysp, SYS_execve);

	size = (char *)ctlp - (char *)&ctl[0];
	assert(size <= sizeof (ctl));

	if (write(fd, ctl, size) != size) {
		(void) close(fd);
		lx_debug("lx_catch_fork: failed to set %d running",
		    (int)pid);
		return;
	}

	/*
	 * Get the status so we can find the value returned from fork1() --
	 * the child process's pid.
	 */
	if (get_status(pid, &ps) != 0) {
		(void) close(fd);
		lx_debug("lx_catch_fork: failed to get status for %d",
		    (int)pid);
		return;
	}

	child = (pid_t)ps.pr_lwp.pr_reg[R_R0];

	/*
	 * We're done with the parent -- off you go.
	 */
	ctl[0] = PCRUN;
	ctl[1] = 0;
	size = 2 * sizeof (long);

	if (write(fd, ctl, size) != size) {
		(void) close(fd);
		lx_debug("lx_catch_fork: failed to set %d running",
		    (int)pid);
		return;
	}

	(void) close(fd);

	/*
	 * If fork1(2) failed, we're done.
	 */
	if (child < 0) {
		lx_debug("lx_catch_fork: fork1 failed");
		return;
	}

	/*
	 * Now we need to screw with the child process.
	 */
	if ((fd = open_lwpfile(child, 1, O_WRONLY, "lwpctl")) < 0) {
		lx_debug("lx_catch_fork: failed to control %d",
		    (int)child);
		return;
	}

	ctlp = ctl;
	*ctlp++ = PCUNSET;
	*ctlp++ = PR_FORK;
	*ctlp++ = PCSEXIT;
	sysp = (sysset_t *)ctlp;
	ctlp += sizeof (sysset_t) / sizeof (long);
	premptyset(sysp);
	size = (char *)ctlp - (char *)&ctl[0];

	if (write(fd, ctl, size) != size) {
		(void) close(fd);
		lx_debug("lx_catch_fork: failed to clear trace flags for  %d",
		    (int)child);
		return;
	}

	/*
	 * Now treat the child as though we had attached to it explicitly.
	 */
	err = ptrace_attach_common(fd, child, child, 1, 1);
	assert(err == 0);

	(void) close(fd);
}

static void
set_dr6(pid_t pid, siginfo_t *infop)
{
	uintptr_t *debugreg;
	uintptr_t addr;
	uintptr_t base;
	size_t size = NULL;
	int dr7;
	int lrw;
	int i;

	if ((debugreg = debug_registers(pid)) == NULL)
		return;

	debugreg[6] = 0xffff0ff0;	/* read as ones */
	switch (infop->si_code) {
	case TRAP_TRACE:
		debugreg[6] |= 0x4000;	/* single-step */
		break;
	case TRAP_RWATCH:
	case TRAP_WWATCH:
	case TRAP_XWATCH:
		dr7 = debugreg[7];
		addr = (uintptr_t)infop->si_addr;
		for (i = 0; i < 4; i++) {
			if ((dr7 & (1 << (2 * i))) == 0)	/* enabled? */
				continue;
			lrw = (dr7 >> (16 + (4 * i))) & 0xf;
			switch (lrw >> 2) {	/* length */
			case 0: size = 1; break;
			case 1: size = 2; break;
			case 2: size = 8; break;
			case 3: size = 4; break;
			}
			base = debugreg[i];
			if (addr >= base && addr < base + size)
				debugreg[6] |= (1 << i);
		}
		/*
		 * Were we also attempting a single-step?
		 * (kludge: we use debugreg[4] for this flag.)
		 */
		if (debugreg[4])
			debugreg[6] |= 0x4000;
		break;
	default:
		break;
	}
}

/*
 * This is called from the emulation of the wait4, waitpid and waitid system
 * calls to take into account:
 *  - the monitor processes which we spawn to observe other processes from
 *    ptrace_attach().
 *  - the extended si_status result we can get when extended ptrace options
 *    are enabled.
 */
int
lx_ptrace_wait(siginfo_t *infop)
{
	ptrace_monitor_map_t *p, **pp;
	pid_t lxpid, pid = infop->si_pid;
	lwpid_t lwpid;
	int fd;
	pstatus_t status;

	/*
	 * If the process observed by waitid(2) corresponds to the monitor
	 * process for a traced thread, we need to rewhack the siginfo_t to
	 * look like it came from the traced thread with the flags set
	 * according to the current state.
	 */
	(void) mutex_lock(&ptrace_map_mtx);
	for (pp = &ptrace_monitor_map; (p = *pp) != NULL; pp = &p->pmm_next) {
		if (p->pmm_monitor == pid) {
			assert(infop->si_code == CLD_EXITED ||
			    infop->si_code == CLD_KILLED ||
			    infop->si_code == CLD_DUMPED ||
			    infop->si_code == CLD_TRAPPED);
			goto found;
		}
	}
	(void) mutex_unlock(&ptrace_map_mtx);

	if (infop->si_code == CLD_TRAPPED) {
		/*
		 * If the traced process got a SIGWAITING, we must be in the
		 * middle of a clone(2) with CLONE_PTRACE set.
		 */
		if (infop->si_status == SIGWAITING) {
			ptrace_catch_fork(pid, 0);
			return (-1);
		}

		/*
		 * If the traced process got a SIGTRAP then Linux ptrace
		 * options might have been set, so setup the extended
		 * si_status to contain the (possible) event.
		 */
		if (infop->si_status == SIGTRAP) {
			uint_t event;

			if (syscall(SYS_brand, B_PTRACE_EXT_OPTS,
			    B_PTRACE_EXT_OPTS_EVT, pid, &event) == 0)
				infop->si_status |= event;
		}
	}

	if (get_status(pid, &status) == 0 &&
	    (status.pr_lwp.pr_flags & PR_STOPPED) &&
	    status.pr_lwp.pr_why == PR_SIGNALLED &&
	    status.pr_lwp.pr_info.si_signo == SIGTRAP)
		set_dr6(pid, &status.pr_lwp.pr_info);

	return (0);

found:
	/*
	 * If the monitor is in the exiting state, ignore the event and free
	 * the monitor structure if the monitor has exited. By returning -1 we
	 * indicate to the caller that this was a spurious return from
	 * waitid(2) and that it should ignore the result and try again.
	 */
	if (p->pmm_exiting) {
		if (infop->si_code == CLD_EXITED ||
		    infop->si_code == CLD_KILLED ||
		    infop->si_code == CLD_DUMPED) {
			*pp = p->pmm_next;
			(void) mutex_unlock(&ptrace_map_mtx);
			free(p);
		}
		return (-1);
	}

	lxpid = p->pmm_target;
	pid = p->pmm_pid;
	lwpid = p->pmm_lwpid;
	(void) mutex_unlock(&ptrace_map_mtx);

	/*
	 * If we can't find the traced process, kill off its monitor.
	 */
	if ((fd = open_lwpfile(pid, lwpid, O_RDONLY, "lwpstatus")) < 0) {
		assert(errno == ENOENT);
		monitor_kill(lxpid, pid);
		infop->si_code = CLD_EXITED;
		infop->si_status = 0;
		infop->si_pid = lxpid;
		return (0);
	}

	if (read(fd, &status.pr_lwp, sizeof (status.pr_lwp)) !=
	    sizeof (status.pr_lwp)) {
		lx_err("read lwpstatus failed %d %s", fd, strerror(errno));
		assert(0);
	}

	(void) close(fd);

	/*
	 * If the traced process isn't stopped, this is a truly spurious
	 * event probably caused by another /proc consumer tracing the
	 * monitor.
	 */
	if (!(status.pr_lwp.pr_flags & PR_STOPPED)) {
		(void) ptrace_cont_monitor(p);
		return (-1);
	}

	switch (status.pr_lwp.pr_why) {
	case PR_SIGNALLED:
		/*
		 * If the traced process got a SIGWAITING, we must be in the
		 * middle of a clone(2) with CLONE_PTRACE set.
		 */
		if (status.pr_lwp.pr_what == SIGWAITING) {
			ptrace_catch_fork(lxpid, 1);
			(void) ptrace_cont_monitor(p);
			return (-1);
		}
		infop->si_code = CLD_TRAPPED;
		infop->si_status = status.pr_lwp.pr_what;
		if (status.pr_lwp.pr_info.si_signo == SIGTRAP)
			set_dr6(pid, &status.pr_lwp.pr_info);
		break;

	case PR_REQUESTED:
		/*
		 * Make it look like the traced process stopped on an
		 * event of interest.
		 */
		infop->si_code = CLD_TRAPPED;
		infop->si_status = SIGTRAP;
		break;

	case PR_JOBCONTROL:
		/*
		 * Ignore this as it was probably caused by another /proc
		 * consumer tracing the monitor.
		 */
		(void) ptrace_cont_monitor(p);
		return (-1);

	case PR_SYSEXIT:
		/*
		 * Processes traced via a monitor (rather than using the
		 * native Solaris ptrace support) explicitly trace returns
		 * from exec system calls since it's an implicit ptrace
		 * trace point. Accordingly we need to present a process
		 * in that state as though it had reached the ptrace trace
		 * point.
		 */
		if (status.pr_lwp.pr_what == SYS_execve) {
			infop->si_code = CLD_TRAPPED;
			infop->si_status = SIGTRAP;
			break;
		}

		/*FALLTHROUGH*/

	case PR_SYSENTRY:
	case PR_FAULTED:
	case PR_SUSPENDED:
	default:
		lx_err("didn't expect %d (%d %d)", status.pr_lwp.pr_why,
		    status.pr_lwp.pr_what, status.pr_lwp.pr_flags);
		assert(0);
	}

	infop->si_pid = lxpid;

	return (0);
}

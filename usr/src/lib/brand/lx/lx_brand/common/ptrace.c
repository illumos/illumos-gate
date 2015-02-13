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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
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
#include <lx_syscall.h>

/*
 * Much of the Linux ptrace(2) emulation is performed in the kernel, and there
 * is a block comment in "lx_ptrace.c" that describes the facility in some
 * detail.
 */

/* execve syscall numbers for 64-bit vs. 32-bit */
#if defined(_LP64)
#define	LX_SYS_execve	59
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

typedef struct ptrace_state_map {
	struct ptrace_state_map *psm_next;	/* next pointer */
	pid_t		psm_pid;		/* Solaris pid */
	uintptr_t	psm_debugreg[8];	/* debug registers */
} ptrace_state_map_t;

static ptrace_state_map_t *ptrace_state_map = NULL;
static mutex_t ptrace_map_mtx = DEFAULTMUTEX;

extern void *_START_;

static sigset_t blockable_sigs;

static long lx_ptrace_kernel(int, pid_t, uintptr_t, uintptr_t);

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
 * Returns B_TRUE if the target LWP, identified by its Linux pid, is traced by
 * this LWP and is waiting in "ptrace-stop".  Returns B_FALSE otherwise.
 */
static boolean_t
is_ptrace_stopped(pid_t lxpid)
{
	ulong_t dummy;

	/*
	 * We attempt a PTRACE_GETEVENTMSG request to determine if the tracee
	 * is stopped appropriately.  As we are not in the kernel, this is not
	 * an atomic check; the process is not guaranteed to remain stopped
	 * once we have dropped the locks protecting that state and left the
	 * kernel.
	 */
	if (lx_ptrace_kernel(LX_PTRACE_GETEVENTMSG, lxpid, NULL,
	    (uintptr_t)&dummy) == 0) {
		return (B_TRUE);
	}

	/*
	 * This call should only fail with ESRCH, which tells us that the
	 * a tracee with that pid was not found in the stopped condition.
	 */
	assert(errno == ESRCH);

	return (B_FALSE);
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
ptrace_kill(pid_t pid)
{
	int ret;

	ret = kill(pid, SIGKILL);

	return (ret == 0 ? ret : -errno);
}

static int
ptrace_getregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_regs_t regs;
	int ret;

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

	if (uucopy((void *)addr, &regs, sizeof (regs)) != 0)
		return (-errno);

	return (setregs(pid, lwpid, &regs));
}

static int
ptrace_getfpregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_fpregs_t regs;
	int ret;

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

	if (uucopy((void *)addr, &regs, sizeof (regs)) != 0)
		return (-errno);

	return (setfpregs(pid, lwpid, &regs));
}

static int
ptrace_getfpxregs(pid_t pid, lwpid_t lwpid, uintptr_t addr)
{
	lx_user_fpxregs_t regs;
	int ret;

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

	if (uucopy((void *)addr, &regs, sizeof (regs)) != 0)
		return (-errno);

	return (setfpxregs(pid, lwpid, &regs));
}

void
lx_ptrace_stop_if_option(int option, boolean_t child, ulong_t msg)
{
	/*
	 * We call into the kernel to see if we need to stop for specific
	 * ptrace(2) events.
	 */
	lx_debug("lx_ptrace_stop_if_option(%d, %s, %lu)", option,
	    child ? "TRUE [child]" : "FALSE [parent]", msg);
	if (syscall(SYS_brand, B_PTRACE_STOP_FOR_OPT, option, child,
	    msg) != 0) {
		if (errno != ESRCH) {
			/*
			 * This should _only_ fail if we are not traced, or do
			 * not have this option set.
			 */
			lx_err_fatal("B_PTRACE_STOP_FOR_OPT failed: %s",
			    strerror(errno));
		}
	}
}

/*
 * Signal to the in-kernel ptrace(2) subsystem that the next native fork() or
 * thr_create() is part of an emulated fork(2) or clone(2).  If PTRACE_CLONE
 * was passed to clone(2), inherit_flag should be B_TRUE.
 */
void
lx_ptrace_clone_begin(int option, boolean_t inherit_flag)
{
	lx_debug("lx_ptrace_clone_begin(%d, %sPTRACE_CLONE)", option,
	    inherit_flag ? "" : "!");
	if (syscall(SYS_brand, B_PTRACE_CLONE_BEGIN, option,
	    inherit_flag) != 0) {
		lx_err_fatal("B_PTRACE_CLONE_BEGIN failed: %s",
		    strerror(errno));
	}
}

static long
lx_ptrace_kernel(int ptrace_op, pid_t lxpid, uintptr_t addr, uintptr_t data)
{
	int ret;

	/*
	 * Call into the in-kernel ptrace(2) emulation code.
	 */
	lx_debug("revectoring to B_PTRACE_KERNEL(%d, %d, %p, %p)", ptrace_op,
	    lxpid, addr, data);
	ret = syscall(SYS_brand, B_PTRACE_KERNEL, ptrace_op, lxpid, addr,
	    data);
	if (ret == 0) {
		lx_debug("\t= %d", ret);
	} else {
		lx_debug("\t= %d (%s)", ret, strerror(errno));
	}

	return (ret == 0 ? ret : -errno);
}

long
lx_ptrace(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int ptrace_op = (int)p1;
	pid_t pid, lxpid = (pid_t)p2;
	lwpid_t lwpid;

	/*
	 * Some PTRACE_* requests are emulated entirely in the kernel.
	 */
	switch (ptrace_op) {
	/*
	 * PTRACE_TRACEME and PTRACE_ATTACH operations induce the tracing of
	 * one LWP by another.  The target LWP must not be traced already.
	 * Both `data' and `addr' are ignored in both cases.
	 */
	case LX_PTRACE_TRACEME:
		return (lx_ptrace_kernel(ptrace_op, 0, 0, 0));

	case LX_PTRACE_ATTACH:
		return (lx_ptrace_kernel(ptrace_op, lxpid, 0, 0));

	/*
	 * PTRACE_DETACH, PTRACE_SYSCALL, PTRACE_SINGLESTEP and PTRACE_CONT
	 * are all restarting actions.  They are only allowed when attached
	 * to the target LWP and when that target LWP is in a "ptrace-stop"
	 * condition.
	 */
	case LX_PTRACE_DETACH:
	case LX_PTRACE_SYSCALL:
	case LX_PTRACE_CONT:
	case LX_PTRACE_SINGLESTEP:
	/*
	 * These actions also require the LWP to be traced and stopped, but do
	 * not restart the target LWP.
	 */
	case LX_PTRACE_SETOPTIONS:
	case LX_PTRACE_GETEVENTMSG:
		return (lx_ptrace_kernel(ptrace_op, lxpid, p3, p4));
	}

	/*
	 * The rest of the emulated PTRACE_* actions are emulated in userland.
	 * They require the target LWP to be traced and in currently
	 * "ptrace-stop", but do not subsequently restart the target LWP.
	 */
	if (lx_lpid_to_spair(lxpid, &pid, &lwpid) < 0 ||
	    !is_ptrace_stopped(lxpid)) {
		return (-ESRCH);
	}

	switch (ptrace_op) {
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

	case LX_PTRACE_KILL:
		return (ptrace_kill(pid));

	case LX_PTRACE_GETREGS:
		return (ptrace_getregs(pid, lwpid, p4));

	case LX_PTRACE_SETREGS:
		return (ptrace_setregs(pid, lwpid, p4));

	case LX_PTRACE_GETFPREGS:
		return (ptrace_getfpregs(pid, lwpid, p4));

	case LX_PTRACE_SETFPREGS:
		return (ptrace_setfpregs(pid, lwpid, p4));

	case LX_PTRACE_GETFPXREGS:
		return (ptrace_getfpxregs(pid, lwpid, p4));

	case LX_PTRACE_SETFPXREGS:
		return (ptrace_setfpxregs(pid, lwpid, p4));

	default:
		return (-EINVAL);
	}
}

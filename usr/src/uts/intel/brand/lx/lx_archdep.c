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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * LX brand Intel-specific routines.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/privregs.h>
#include <sys/pcb.h>
#include <sys/archsystm.h>
#include <sys/stack.h>
#include <sys/sdt.h>
#include <sys/sysmacros.h>
#include <lx_errno.h>

#define	LX_REG(ucp, r)	((ucp)->uc_mcontext.gregs[(r)])

extern int getsetcontext(int, void *);
#if defined(_SYSCALL32_IMPL)
extern int getsetcontext32(int, void *);
#endif

#if defined(__amd64)
static int
lx_rw_uc(proc_t *p, void *ucp, void *kucp, size_t ucsz, boolean_t writing)
{
	int error = 0;
	size_t rem = ucsz;
	off_t pos = 0;

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * Grab P_PR_LOCK so that we can drop p_lock while doing I/O.
	 */
	sprlock_proc(p);

	/*
	 * Drop p_lock while we do I/O to avoid deadlock with the clock thread.
	 */
	mutex_exit(&p->p_lock);
	while (rem != 0) {
		uintptr_t addr = (uintptr_t)ucp + pos;
		size_t len = MIN(rem, PAGESIZE - (addr & PAGEOFFSET));

		if (writing) {
			error = uwrite(p, kucp + pos, len, addr);
		} else {
			error = uread(p, kucp + pos, len, addr);
		}

		if (error != 0) {
			break;
		}

		rem -= len;
		pos += len;
	}
	mutex_enter(&p->p_lock);

	sprunlock(p);
	mutex_enter(&p->p_lock);

	return (error);
}

/*
 * Read a ucontext_t from the target process, which may or may not be
 * the current process.
 */
static int
lx_read_uc(proc_t *p, void *ucp, void *kucp, size_t ucsz)
{
	return (lx_rw_uc(p, ucp, kucp, ucsz, B_FALSE));
}

/*
 * Write a ucontext_t to the target process, which may or may not be
 * the current process.
 */
static int
lx_write_uc(proc_t *p, void *ucp, void *kucp, size_t ucsz)
{
	return (lx_rw_uc(p, ucp, kucp, ucsz, B_TRUE));
}
#endif /* __amd64 */

/*
 * Load register state from a usermode "lx_user_regs_t" in the tracer
 * and store it in the tracee ucontext_t.
 */
int
lx_userregs_to_uc(lx_lwp_data_t *lwpd, void *ucp, void *uregsp)
{
#if defined(__amd64)
	klwp_t *lwp = lwpd->br_lwp;
	proc_t *p = lwptoproc(lwp);

	switch (get_udatamodel()) {
	case DATAMODEL_LP64: {
		lx_user_regs_t lxur;

		if (copyin(uregsp, &lxur, sizeof (lxur)) != 0) {
			return (EFAULT);
		}

		switch (lwp_getdatamodel(lwp)) {
		case DATAMODEL_LP64: {
			ucontext_t uc;

			if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
				return (EIO);
			}

			/*
			 * Note: we currently ignore "lxur_orig_rax" here (as
			 * this path should not be used for system call stops)
			 * as well as "lxur_xcs" (lest we get caught up in our
			 * own lies about %cs from lx_uc_to_userregs()).
			 */
			LX_REG(&uc, REG_R15) = lxur.lxur_r15;
			LX_REG(&uc, REG_R14) = lxur.lxur_r14;
			LX_REG(&uc, REG_R13) = lxur.lxur_r13;
			LX_REG(&uc, REG_R12) = lxur.lxur_r12;
			LX_REG(&uc, REG_RBP) = lxur.lxur_rbp;
			LX_REG(&uc, REG_RBX) = lxur.lxur_rbx;
			LX_REG(&uc, REG_R11) = lxur.lxur_r11;
			LX_REG(&uc, REG_R10) = lxur.lxur_r10;
			LX_REG(&uc, REG_R9) = lxur.lxur_r9;
			LX_REG(&uc, REG_R8) = lxur.lxur_r8;
			LX_REG(&uc, REG_RAX) = lxur.lxur_rax;
			LX_REG(&uc, REG_RCX) = lxur.lxur_rcx;
			LX_REG(&uc, REG_RDX) = lxur.lxur_rdx;
			LX_REG(&uc, REG_RSI) = lxur.lxur_rsi;
			LX_REG(&uc, REG_RDI) = lxur.lxur_rdi;
			LX_REG(&uc, REG_RIP) = lxur.lxur_rip;
			LX_REG(&uc, REG_RFL) = lxur.lxur_rflags;
			LX_REG(&uc, REG_RSP) = lxur.lxur_rsp;
			LX_REG(&uc, REG_SS) = lxur.lxur_xss;
			LX_REG(&uc, REG_FSBASE) = lxur.lxur_xfs_base;
			LX_REG(&uc, REG_GSBASE) = lxur.lxur_xgs_base;

			LX_REG(&uc, REG_DS) = lxur.lxur_xds;
			LX_REG(&uc, REG_ES) = lxur.lxur_xes;
			LX_REG(&uc, REG_FS) = lxur.lxur_xfs;
			LX_REG(&uc, REG_GS) = lxur.lxur_xgs;

			if (lx_write_uc(p, ucp, &uc, sizeof (uc)) != 0) {
				return (EIO);
			}

			return (0);
		}

		case DATAMODEL_ILP32: {
			ucontext32_t uc;

			if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
				return (EIO);
			}

			/*
			 * Note: we currently ignore "lxur_orig_eax" here (as
			 * this path should not be used for system call stops)
			 * as well as "lxur_xcs" (lest we get caught up in our
			 * own lies about %cs from lx_uc_to_userregs()).
			 */
			LX_REG(&uc, EBP) = (int32_t)lxur.lxur_rbp;
			LX_REG(&uc, EBX) = (int32_t)lxur.lxur_rbx;
			LX_REG(&uc, EAX) = (int32_t)lxur.lxur_rax;
			LX_REG(&uc, ECX) = (int32_t)lxur.lxur_rcx;
			LX_REG(&uc, EDX) = (int32_t)lxur.lxur_rdx;
			LX_REG(&uc, ESI) = (int32_t)lxur.lxur_rsi;
			LX_REG(&uc, EDI) = (int32_t)lxur.lxur_rdi;
			LX_REG(&uc, EIP) = (int32_t)lxur.lxur_rip;
			LX_REG(&uc, EFL) = (int32_t)lxur.lxur_rflags;
			LX_REG(&uc, UESP) = (int32_t)lxur.lxur_rsp;
			LX_REG(&uc, SS) = (int32_t)lxur.lxur_xss;

			LX_REG(&uc, DS) = (int32_t)lxur.lxur_xds;
			LX_REG(&uc, ES) = (int32_t)lxur.lxur_xes;
			LX_REG(&uc, FS) = (int32_t)lxur.lxur_xfs;
			LX_REG(&uc, GS) = (int32_t)lxur.lxur_xgs;

			if (lx_write_uc(p, ucp, &uc, sizeof (uc)) != 0) {
				return (EIO);
			}

			return (0);
		}

		default:
			return (EIO);
		}

		return (EIO);
	}

	case DATAMODEL_ILP32: {
		lx_user_regs32_t lxur;
		ucontext32_t uc;

		if (lwp_getdatamodel(lwp) != DATAMODEL_ILP32) {
			/*
			 * The target is not a 32-bit LWP.  We refuse to
			 * present truncated 64-bit registers to a 32-bit
			 * tracer.
			 */
			return (EIO);
		}

		if (copyin(uregsp, &lxur, sizeof (lxur)) != 0) {
			return (EFAULT);
		}

		if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (EIO);
		}

		/*
		 * Note: we currently ignore "lxur_orig_eax" here, as
		 * this path should not be used for system call stops.
		 */
		LX_REG(&uc, EBX) = lxur.lxur_ebx;
		LX_REG(&uc, ECX) = lxur.lxur_ecx;
		LX_REG(&uc, EDX) = lxur.lxur_edx;
		LX_REG(&uc, ESI) = lxur.lxur_esi;
		LX_REG(&uc, EDI) = lxur.lxur_edi;
		LX_REG(&uc, EBP) = lxur.lxur_ebp;
		LX_REG(&uc, EAX) = lxur.lxur_eax;
		LX_REG(&uc, EIP) = lxur.lxur_eip;
		LX_REG(&uc, EFL) = lxur.lxur_eflags;
		LX_REG(&uc, UESP) = lxur.lxur_esp;
		LX_REG(&uc, SS) = lxur.lxur_xss;

		LX_REG(&uc, DS) = lxur.lxur_xds;
		LX_REG(&uc, ES) = lxur.lxur_xes;
		LX_REG(&uc, FS) = lxur.lxur_xfs;
		LX_REG(&uc, GS) = lxur.lxur_xgs;

		if (lx_write_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (EIO);
		}

		return (EIO);
	}

	default:
		return (EIO);
	}
#else
	cmn_err(CE_WARN, "%s: no 32-bit kernel support", __FUNCTION__);
	exit(CLD_KILLED, SIGSYS);
	return (EIO);
#endif /* __amd64 */
}

/*
 * Copy register state from a ucontext_t in the tracee to a usermode
 * "lx_user_regs_t" in the tracer.
 */
int
lx_uc_to_userregs(lx_lwp_data_t *lwpd, void *ucp, void *uregsp)
{
#if defined(__amd64)
	klwp_t *lwp = lwpd->br_lwp;
	proc_t *p = lwptoproc(lwp);

	switch (get_udatamodel()) {
	case DATAMODEL_LP64: {
		lx_user_regs_t lxur;

		switch (lwp_getdatamodel(lwp)) {
		case DATAMODEL_LP64: {
			ucontext_t uc;

			if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
				return (EIO);
			}

			lxur.lxur_r15 = LX_REG(&uc, REG_R15);
			lxur.lxur_r14 = LX_REG(&uc, REG_R14);
			lxur.lxur_r13 = LX_REG(&uc, REG_R13);
			lxur.lxur_r12 = LX_REG(&uc, REG_R12);
			lxur.lxur_rbp = LX_REG(&uc, REG_RBP);
			lxur.lxur_rbx = LX_REG(&uc, REG_RBX);
			lxur.lxur_r11 = LX_REG(&uc, REG_R11);
			lxur.lxur_r10 = LX_REG(&uc, REG_R10);
			lxur.lxur_r9 = LX_REG(&uc, REG_R9);
			lxur.lxur_r8 = LX_REG(&uc, REG_R8);
			lxur.lxur_rax = LX_REG(&uc, REG_RAX);
			lxur.lxur_rcx = LX_REG(&uc, REG_RCX);
			lxur.lxur_rdx = LX_REG(&uc, REG_RDX);
			lxur.lxur_rsi = LX_REG(&uc, REG_RSI);
			lxur.lxur_rdi = LX_REG(&uc, REG_RDI);
			lxur.lxur_orig_rax = 0;
			lxur.lxur_rip = LX_REG(&uc, REG_RIP);
			/*
			 * strace on some releases (e.g. centos) uses the %cs
			 * value to determine what kind of process is being
			 * traced. Here is a sample comment:
			 *	Check CS register value. On x86-64 linux it is:
			 *	    0x33	for long mode (64 bit and x32))
			 *	    0x23	for compatibility mode (32 bit)
			 *	%ds = 0x2b for x32 mode (x86-64 in 32 bit)
			 * We can't change the %cs value in the ucp (see
			 * setgregs and _sys_rtt) so we emulate the expected
			 * value for ptrace use.
			 */
			lxur.lxur_xcs = 0x33;
			lxur.lxur_rflags = LX_REG(&uc, REG_RFL);
			lxur.lxur_rsp = LX_REG(&uc, REG_RSP);
			lxur.lxur_xss = LX_REG(&uc, REG_SS);
			lxur.lxur_xfs_base = LX_REG(&uc, REG_FSBASE);
			lxur.lxur_xgs_base = LX_REG(&uc, REG_GSBASE);

			lxur.lxur_xds = LX_REG(&uc, REG_DS);
			lxur.lxur_xes = LX_REG(&uc, REG_ES);
			lxur.lxur_xfs = LX_REG(&uc, REG_FS);
			lxur.lxur_xgs = LX_REG(&uc, REG_GS);

			if (copyout(&lxur, uregsp, sizeof (lxur)) != 0) {
				return (EFAULT);
			}

			return (0);
		}

		case DATAMODEL_ILP32: {
			ucontext32_t uc;

			if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
				return (EIO);
			}

			lxur.lxur_r15 = 0;
			lxur.lxur_r14 = 0;
			lxur.lxur_r13 = 0;
			lxur.lxur_r12 = 0;
			lxur.lxur_rbp = LX_REG(&uc, EBP);
			lxur.lxur_rbx = LX_REG(&uc, EBX);
			lxur.lxur_r11 = 0;
			lxur.lxur_r10 = 0;
			lxur.lxur_r9 = 0;
			lxur.lxur_r8 = 0;
			lxur.lxur_rax = LX_REG(&uc, EAX);
			lxur.lxur_rcx = LX_REG(&uc, ECX);
			lxur.lxur_rdx = LX_REG(&uc, EDX);
			lxur.lxur_rsi = LX_REG(&uc, ESI);
			lxur.lxur_rdi = LX_REG(&uc, EDI);
			lxur.lxur_orig_rax = 0;
			lxur.lxur_rip = LX_REG(&uc, EIP);
			/* See comment above re: %cs register */
			lxur.lxur_xcs = 0x23;
			lxur.lxur_rflags = LX_REG(&uc, EFL);
			lxur.lxur_rsp = LX_REG(&uc, UESP);
			lxur.lxur_xss = LX_REG(&uc, SS);
			lxur.lxur_xfs_base = 0;
			lxur.lxur_xgs_base = 0;

			lxur.lxur_xds = LX_REG(&uc, DS);
			lxur.lxur_xes = LX_REG(&uc, ES);
			lxur.lxur_xfs = LX_REG(&uc, FS);
			lxur.lxur_xgs = LX_REG(&uc, GS);

			if (copyout(&lxur, uregsp, sizeof (lxur)) != 0) {
				return (EFAULT);
			}

			return (0);
		}

		default:
			return (EIO);
		}
	}

	case DATAMODEL_ILP32: {
		lx_user_regs32_t lxur;
		ucontext32_t uc;

		if (lwp_getdatamodel(lwp) != DATAMODEL_ILP32) {
			/*
			 * The target is not a 32-bit LWP.  We refuse to
			 * present truncated 64-bit registers to a 32-bit
			 * tracer.
			 */
			return (EIO);
		}

		if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (EIO);
		}

		lxur.lxur_ebx = LX_REG(&uc, EBX);
		lxur.lxur_ecx = LX_REG(&uc, ECX);
		lxur.lxur_edx = LX_REG(&uc, EDX);
		lxur.lxur_esi = LX_REG(&uc, ESI);
		lxur.lxur_edi = LX_REG(&uc, EDI);
		lxur.lxur_ebp = LX_REG(&uc, EBP);
		lxur.lxur_eax = LX_REG(&uc, EAX);
		lxur.lxur_orig_eax = 0;
		lxur.lxur_eip = LX_REG(&uc, EIP);
		/* See comment above re: %cs register */
		lxur.lxur_xcs = 0x23;
		lxur.lxur_eflags = LX_REG(&uc, EFL);
		lxur.lxur_esp = LX_REG(&uc, UESP);
		lxur.lxur_xss = LX_REG(&uc, SS);

		lxur.lxur_xds = LX_REG(&uc, DS);
		lxur.lxur_xes = LX_REG(&uc, ES);
		lxur.lxur_xfs = LX_REG(&uc, FS);
		lxur.lxur_xgs = LX_REG(&uc, GS);

		if (copyout(&lxur, uregsp, sizeof (lxur)) != 0) {
			return (EFAULT);
		}

		return (0);
	}

	default:
		return (EIO);
	}
#else
	cmn_err(CE_WARN, "%s: no 32-bit kernel support", __FUNCTION__);
	exit(CLD_KILLED, SIGSYS);
	return (EIO);
#endif
}

/*
 * Load a usermode "lx_user_regs_t" into the register state of the target LWP.
 */
int
lx_userregs_to_regs(lx_lwp_data_t *lwpd, void *uregsp)
{
	klwp_t *lwp = lwpd->br_lwp;
	proc_t *p = lwptoproc(lwp);

	VERIFY(MUTEX_HELD(&p->p_lock));

#if defined(__amd64)
	struct regs *rp = lwptoregs(lwp);
	struct pcb *pcb = &lwp->lwp_pcb;

	switch (get_udatamodel()) {
	case DATAMODEL_LP64: {
		lx_user_regs_t lxur;

		if (copyin(uregsp, &lxur, sizeof (lxur)) != 0) {
			return (EFAULT);
		}

		rp->r_r15 = lxur.lxur_r15;
		rp->r_r14 = lxur.lxur_r14;
		rp->r_r13 = lxur.lxur_r13;
		rp->r_r12 = lxur.lxur_r12;
		rp->r_rbp = lxur.lxur_rbp;
		rp->r_rbx = lxur.lxur_rbx;
		rp->r_r11 = lxur.lxur_r11;
		rp->r_r10 = lxur.lxur_r10;
		rp->r_r9 = lxur.lxur_r9;
		rp->r_r8 = lxur.lxur_r8;
		rp->r_rax = lxur.lxur_rax;
		rp->r_rcx = lxur.lxur_rcx;
		rp->r_rdx = lxur.lxur_rdx;
		rp->r_rsi = lxur.lxur_rsi;
		rp->r_rdi = lxur.lxur_rdi;
		lwpd->br_syscall_num = (int)lxur.lxur_orig_rax;
		rp->r_rip = lxur.lxur_rip;
		rp->r_rfl = lxur.lxur_rflags;
		rp->r_rsp = lxur.lxur_rsp;
		rp->r_ss = lxur.lxur_xss;
		pcb->pcb_fsbase = lxur.lxur_xfs_base;
		pcb->pcb_gsbase = lxur.lxur_xgs_base;

		kpreempt_disable();
		pcb->pcb_rupdate = 1;
		pcb->pcb_ds = lxur.lxur_xds;
		pcb->pcb_es = lxur.lxur_xes;
		pcb->pcb_fs = lxur.lxur_xfs;
		pcb->pcb_gs = lxur.lxur_xgs;
		kpreempt_enable();

		return (0);
	}

	case DATAMODEL_ILP32: {
		lx_user_regs32_t lxur;

		if (lwp_getdatamodel(lwp) != DATAMODEL_ILP32) {
			/*
			 * The target is not a 32-bit LWP.  We refuse to
			 * present truncated 64-bit registers to a 32-bit
			 * tracer.
			 */
			return (EIO);
		}

		if (copyin(uregsp, &lxur, sizeof (lxur)) != 0) {
			return (EFAULT);
		}

		rp->r_rbx = lxur.lxur_ebx;
		rp->r_rcx = lxur.lxur_ecx;
		rp->r_rdx = lxur.lxur_edx;
		rp->r_rsi = lxur.lxur_esi;
		rp->r_rdi = lxur.lxur_edi;
		rp->r_rbp = lxur.lxur_ebp;
		rp->r_rax = lxur.lxur_eax;
		lwpd->br_syscall_num = (int)lxur.lxur_orig_eax;
		rp->r_rip = lxur.lxur_eip;
		rp->r_rfl = lxur.lxur_eflags;
		rp->r_rsp = lxur.lxur_esp;
		rp->r_ss = lxur.lxur_xss;

		kpreempt_disable();
		pcb->pcb_rupdate = 1;
		pcb->pcb_ds = lxur.lxur_xds;
		pcb->pcb_es = lxur.lxur_xes;
		pcb->pcb_fs = lxur.lxur_xfs;
		pcb->pcb_gs = lxur.lxur_xgs;
		kpreempt_enable();

		return (0);
	}

	default:
		return (EIO);
	}
#else
	cmn_err(CE_WARN, "%s: no 32-bit kernel support", __FUNCTION__);
	exit(CLD_KILLED, SIGSYS);
	return (EIO);
#endif /* __amd64 */
}

/*
 * Copy the current LWP register state of the target LWP to a usermode
 * "lx_user_regs_t".
 */
int
lx_regs_to_userregs(lx_lwp_data_t *lwpd, void *uregsp)
{
#if defined(__amd64)
	klwp_t *lwp = lwpd->br_lwp;
	struct regs *rp = lwptoregs(lwp);
	proc_t *p = lwptoproc(lwp);

	VERIFY(MUTEX_HELD(&p->p_lock));

	struct pcb *pcb = &lwp->lwp_pcb;
	long r0, orig_r0;

	/*
	 * We must precisely emulate the "syscall-entry-stop" and
	 * "syscall-exit-stop" register appearance from the Linux kernel.
	 */
	switch (lwpd->br_ptrace_whatstop) {
	case LX_PR_SYSENTRY:
		orig_r0 = lwpd->br_syscall_num;
		r0 = -lx_errno(ENOTSUP, EINVAL);
		break;
	case LX_PR_SYSEXIT:
		orig_r0 = lwpd->br_syscall_num;
		r0 = rp->r_rax;
		break;
	default:
		orig_r0 = 0;
		r0 = rp->r_rax;
	}

	switch (get_udatamodel()) {
	case DATAMODEL_LP64: {
		lx_user_regs_t lxur;

		lxur.lxur_r15 = rp->r_r15;
		lxur.lxur_r14 = rp->r_r14;
		lxur.lxur_r13 = rp->r_r13;
		lxur.lxur_r12 = rp->r_r12;
		lxur.lxur_rbp = rp->r_rbp;
		lxur.lxur_rbx = rp->r_rbx;
		lxur.lxur_r11 = rp->r_r11;
		lxur.lxur_r10 = rp->r_r10;
		lxur.lxur_r9 = rp->r_r9;
		lxur.lxur_r8 = rp->r_r8;
		lxur.lxur_rax = r0;
		lxur.lxur_rcx = rp->r_rcx;
		lxur.lxur_rdx = rp->r_rdx;
		lxur.lxur_rsi = rp->r_rsi;
		lxur.lxur_rdi = rp->r_rdi;
		lxur.lxur_orig_rax = orig_r0;
		lxur.lxur_rip = rp->r_rip;
		/*
		 * strace on some releases (e.g. centos) uses the %cs value to
		 * determine what kind of process is being traced. Here is a
		 * sample comment:
		 *	Check CS register value. On x86-64 linux it is:
		 *	    0x33	for long mode (64 bit and x32))
		 *	    0x23	for compatibility mode (32 bit)
		 *	%ds = 0x2b for x32 mode (x86-64 in 32 bit)
		 * We can't change the %cs value in the ucp (see setgregs and
		 * _sys_rtt) so we emulate the expected value for ptrace use.
		 */
		if (lwp_getdatamodel(lwp) == DATAMODEL_ILP32) {
			lxur.lxur_xcs = 0x23;
		} else {
			lxur.lxur_xcs = 0x33;
		}
		lxur.lxur_rflags = rp->r_rfl;
		lxur.lxur_rsp = rp->r_rsp;
		lxur.lxur_xss = rp->r_ss;
		lxur.lxur_xfs_base = pcb->pcb_fsbase;
		lxur.lxur_xgs_base = pcb->pcb_gsbase;

		kpreempt_disable();
		if (pcb->pcb_rupdate == 1) {
			lxur.lxur_xds = pcb->pcb_ds;
			lxur.lxur_xes = pcb->pcb_es;
			lxur.lxur_xfs = pcb->pcb_fs;
			lxur.lxur_xgs = pcb->pcb_gs;
		} else {
			lxur.lxur_xds = rp->r_ds;
			lxur.lxur_xes = rp->r_es;
			lxur.lxur_xfs = rp->r_fs;
			lxur.lxur_xgs = rp->r_gs;
		}
		kpreempt_enable();

		if (copyout(&lxur, uregsp, sizeof (lxur)) != 0) {
			return (EFAULT);
		}

		return (0);
	}

	case DATAMODEL_ILP32: {
		lx_user_regs32_t lxur;

		if (lwp_getdatamodel(lwp) != DATAMODEL_ILP32) {
			/*
			 * The target is not a 32-bit LWP.  We refuse to
			 * present truncated 64-bit registers to a 32-bit
			 * tracer.
			 */
			return (EIO);
		}

		lxur.lxur_ebx = (int32_t)rp->r_rbx;
		lxur.lxur_ecx = (int32_t)rp->r_rcx;
		lxur.lxur_edx = (int32_t)rp->r_rdx;
		lxur.lxur_esi = (int32_t)rp->r_rsi;
		lxur.lxur_edi = (int32_t)rp->r_rdi;
		lxur.lxur_ebp = (int32_t)rp->r_rbp;
		lxur.lxur_eax = (int32_t)r0;
		lxur.lxur_orig_eax = (int32_t)orig_r0;
		lxur.lxur_eip = (int32_t)rp->r_rip;
		/* See comment above for 64-bit datamodel */
		lxur.lxur_xcs = 0x23;
		lxur.lxur_eflags = (int32_t)rp->r_rfl;
		lxur.lxur_esp = (int32_t)rp->r_rsp;
		lxur.lxur_xss = (int32_t)rp->r_ss;

		kpreempt_disable();
		if (pcb->pcb_rupdate == 1) {
			lxur.lxur_xds = pcb->pcb_ds;
			lxur.lxur_xes = pcb->pcb_es;
			lxur.lxur_xfs = pcb->pcb_fs;
			lxur.lxur_xgs = pcb->pcb_gs;
		} else {
			lxur.lxur_xds = rp->r_ds;
			lxur.lxur_xes = rp->r_es;
			lxur.lxur_xfs = rp->r_fs;
			lxur.lxur_xgs = rp->r_gs;
		}
		kpreempt_enable();

		if (copyout(&lxur, uregsp, sizeof (lxur)) != 0) {
			return (EFAULT);
		}

		return (0);
	}

	default:
		return (EIO);
	}
#else
	cmn_err(CE_WARN, "%s: no 32-bit kernel support", __FUNCTION__);
	exit(CLD_KILLED, SIGSYS);
	return (EIO);
#endif /* __amd64 */
}

/*
 * Load registers and repoint the stack and program counter.  This function is
 * used by the B_JUMP_TO_LINUX brand system call to revector to a Linux
 * entrypoint.
 */
int
lx_runexe(klwp_t *lwp, void *ucp)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

	/*
	 * We should only make it here when transitioning to Linux from
	 * the NATIVE or INIT mode.
	 */
	VERIFY(lwpd->br_stack_mode == LX_STACK_MODE_NATIVE ||
	    lwpd->br_stack_mode == LX_STACK_MODE_INIT);

#if defined(__amd64)
	if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
		struct pcb *pcb = &lwp->lwp_pcb;

		/*
		 * Preserve the %fs/%gsbase value for this LWP, as set and used
		 * by native illumos code.
		 */
		lwpd->br_ntv_fsbase = pcb->pcb_fsbase;
		lwpd->br_ntv_gsbase = pcb->pcb_gsbase;

		return (getsetcontext(SETCONTEXT, ucp));
	} else {
		return (getsetcontext32(SETCONTEXT, ucp));
	}
#else
	return (getsetcontext(SETCONTEXT, ucp));
#endif
}

/*
 * The usermode emulation code is illumos library code.  This routine ensures
 * the segment registers are set up correctly for native illumos code.  It
 * should be called _after_ we have stored the outgoing Linux machine state
 * but _before_ we return from the kernel to any illumos native code; e.g. the
 * usermode emulation library, or any interposed signal handlers.
 *
 * See the comment on lwp_segregs_save() for how we handle the usermode
 * registers when we come into the kernel and see update_sregs() for how we
 * restore.
 */
void
lx_switch_to_native(klwp_t *lwp)
{
#if defined(__amd64)
	model_t datamodel = lwp_getdatamodel(lwp);

	switch (datamodel) {
	case DATAMODEL_ILP32: {
		struct pcb *pcb = &lwp->lwp_pcb;

		/*
		 * For 32-bit processes, we ensure that the correct %gs value
		 * is loaded:
		 */
		kpreempt_disable();
		if (pcb->pcb_rupdate == 1) {
			/*
			 * If we are already flushing the segment registers,
			 * then ensure we are flushing the native %gs.
			 */
			pcb->pcb_gs = LWPGS_SEL;
		} else {
			struct regs *rp = lwptoregs(lwp);

			/*
			 * If we are not flushing the segment registers yet,
			 * only do so if %gs is not correct already:
			 */
			if (rp->r_gs != LWPGS_SEL) {
				pcb->pcb_gs = LWPGS_SEL;

				/*
				 * Ensure we go out via update_sregs.
				 */
				pcb->pcb_rupdate = 1;
			}
		}
		kpreempt_enable();
		break;
	}

	case DATAMODEL_LP64: {
		lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

		/*
		 * For 64-bit processes we ensure that the correct %fsbase
		 * value is loaded:
		 */
		if (lwpd->br_ntv_fsbase != 0) {
			struct pcb *pcb = &lwp->lwp_pcb;

			kpreempt_disable();
			if (pcb->pcb_fsbase != lwpd->br_ntv_fsbase) {
				pcb->pcb_fsbase = lwpd->br_ntv_fsbase;

				/*
				 * Ensure we go out via update_sregs.
				 */
				pcb->pcb_rupdate = 1;
			}
			kpreempt_enable();
		}
		/*
		 * ... and the correct %gsbase
		 */
		if (lwpd->br_ntv_gsbase != 0) {
			struct pcb *pcb = &lwp->lwp_pcb;

			kpreempt_disable();
			if (pcb->pcb_gsbase != lwpd->br_ntv_gsbase) {
				pcb->pcb_gsbase = lwpd->br_ntv_gsbase;

				/*
				 * Ensure we go out via update_sregs.
				 */
				pcb->pcb_rupdate = 1;
			}
			kpreempt_enable();
		}
		break;
	}

	default:
		cmn_err(CE_PANIC, "unknown data model: %d", datamodel);
	}
#elif defined(__i386)
	struct regs *rp = lwptoregs(lwp);

	rp->r_gs = LWPGS_SEL;
#else
#error "unknown x86"
#endif
}

#if defined(__amd64)
/*
 * Call frame for the 64-bit usermode emulation handler:
 *    lx_emulate(ucontext_t *ucp, int syscall_num, uintptr_t *args)
 *
 * old sp: --------------------------------------------------------------
 *  |      - ucontext_t              (register state for emulation)
 *  |      - uintptr_t[6]            (system call arguments array)
 *  V      --------------------------------------------------------------
 * new sp: - bogus return address
 *
 * Arguments are passed in registers, per the AMD64 ABI: %rdi, %rsi and %rdx.
 */
void
lx_emulate_user(klwp_t *lwp, int syscall_num, uintptr_t *args)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	label_t lab;
	uintptr_t uc_addr;
	uintptr_t args_addr;
	uintptr_t top;
	/*
	 * Variables used after on_fault() returns for a fault
	 * must be volatile.
	 */
	volatile size_t frsz;
	volatile uintptr_t sp;
	volatile proc_t *p = lwptoproc(lwp);
	volatile int watched;

	/*
	 * We should not be able to get here unless we are running Linux
	 * code for a system call we cannot emulate in the kernel.
	 */
	VERIFY(lwpd->br_stack_mode == LX_STACK_MODE_BRAND);

	/*
	 * The AMD64 ABI requires us to align the return address on the stack
	 * so that when the called function pushes %rbp, the stack is 16-byte
	 * aligned.
	 *
	 * This routine, like the amd64 version of sendsig(), depends on
	 * STACK_ALIGN being 16 and STACK_ENTRY_ALIGN being 8.
	 */
#if STACK_ALIGN != 16 || STACK_ENTRY_ALIGN != 8
#error "lx_emulate_user() amd64 did not find the expected stack alignments"
#endif

	/*
	 * We begin at the current native stack pointer, and reserve space for
	 * the ucontext_t we are copying onto the stack, as well as the call
	 * arguments for the usermode emulation handler.
	 *
	 * We 16-byte align the entire frame, and then unalign it again by
	 * adding space for the return address.
	 */
	frsz = SA(sizeof (ucontext_t)) + SA(6 * sizeof (uintptr_t)) +
	    sizeof (uintptr_t);
	VERIFY((frsz & (STACK_ALIGN - 1UL)) == 8);
	VERIFY((frsz & (STACK_ENTRY_ALIGN - 1UL)) == 0);

	if (lwpd->br_ntv_stack == lwpd->br_ntv_stack_current) {
		/*
		 * Nobody else is using the stack right now, so start at the
		 * top.
		 */
		top = lwpd->br_ntv_stack_current;
	} else {
		/*
		 * Drop below the 128-byte reserved region of the stack frame
		 * we are interrupting.
		 */
		top = lwpd->br_ntv_stack_current - STACK_RESERVE;
	}
	top = top & ~(STACK_ALIGN - 1);
	sp = top - frsz;

	uc_addr = top - SA(sizeof (ucontext_t));
	args_addr = uc_addr - SA(6 * sizeof (uintptr_t));

	watched = watch_disable_addr((caddr_t)sp, frsz, S_WRITE);
	if (on_fault(&lab)) {
		goto badstack;
	}

	/*
	 * Save the register state we preserved on the way into this brand
	 * system call and drop it on the native stack.
	 */
	{
		/*
		 * Note: the amd64 ucontext_t is 864 bytes.
		 */
		ucontext_t uc;

		/*
		 * We do not want to save the signal mask for an emulation
		 * context.  Some emulated system calls alter the signal mask;
		 * restoring it when the emulation is complete would clobber
		 * those intentional side effects.
		 */
		savecontext(&uc, NULL);

		/*
		 * Mark this as a system call emulation context:
		 */
		uc.uc_brand_data[0] = (void *)((uintptr_t)
		    uc.uc_brand_data[0] | LX_UC_FRAME_IS_SYSCALL);

		copyout_noerr(&uc, (void *)(uintptr_t)uc_addr, sizeof (uc));
	}

	DTRACE_PROBE3(oldcontext__set, klwp_t *, lwp,
	    uintptr_t, lwp->lwp_oldcontext, uintptr_t, uc_addr);
	lwp->lwp_oldcontext = (uintptr_t)uc_addr;

	/*
	 * Copy the system call arguments out to userland:
	 */
	copyout_noerr(args, (void *)(uintptr_t)args_addr,
	    6 * sizeof (uintptr_t));

	/*
	 * Drop the bogus return address on the stack.
	 */
	suword64_noerr((void *)sp, 0);

	no_fault();
	if (watched) {
		watch_enable_addr((caddr_t)sp, frsz, S_WRITE);
	}

	/*
	 * Pass the arguments to lx_emulate() in the appropriate registers.
	 */
	rp->r_rdi = uc_addr;
	rp->r_rsi = syscall_num;
	rp->r_rdx = args_addr;

	/*
	 * In order to be able to restore %edx, we need to JUSTRETURN.
	 */
	lwp->lwp_eosys = JUSTRETURN;
	curthread->t_post_sys = 1;
	aston(curthread);

	/*
	 * Set stack pointer and return address to the usermode emulation
	 * handler:
	 */
	lwpd->br_stack_mode = LX_STACK_MODE_NATIVE;
	lx_lwp_set_native_stack_current(lwpd, sp);

	/*
	 * Divert execution, on our return, to the usermode emulation stack
	 * and handler:
	 */
	rp->r_fp = 0;
	rp->r_sp = sp;
	rp->r_pc = ptolxproc(p)->l_handler;

	/*
	 * Fix up segment registers, etc.
	 */
	lx_switch_to_native(lwp);

	return;

badstack:
	no_fault();
	if (watched) {
		watch_enable_addr((caddr_t)sp, frsz, S_WRITE);
	}

#ifdef DEBUG
	printf("lx_emulate_user: bad native stack cmd=%s, pid=%d, sp=0x%lx\n",
	    PTOU(p)->u_comm, p->p_pid, sp);
#endif

	exit(CLD_KILLED, SIGSEGV);
}

#if defined(_SYSCALL32_IMPL)
/*
 * Call frame for the 32-bit usermode emulation handler:
 *    lx_emulate(ucontext_t *ucp, int syscall_num, uintptr_t *args)
 *
 * old sp: --------------------------------------------------------------
 *  |      - ucontext_t              (register state for emulation)
 *  |      - uintptr_t[6]            (system call arguments array)
 *  |      --------------------------------------------------------------
 *  |      - arg2: uintptr_t *       (pointer to arguments array above)
 *  |      - arg1: int               (system call number)
 *  V      - arg0: ucontext_t *      (pointer to context above)
 * new sp: - bogus return address
 */
struct lx_emu_frame32 {
	caddr32_t	retaddr;	/* 0 */
	caddr32_t	ucontextp;	/* 4 */
	int32_t		syscall_num;	/* 8 */
	caddr32_t	argsp;		/* c */
};

/*
 * This function arranges for the lwp to execute the usermode emulation handler
 * for this system call.  The mechanism is similar to signal handling, and this
 * function is modelled on sendsig32().
 */
void
lx_emulate_user32(klwp_t *lwp, int syscall_num, uintptr_t *args)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	struct regs *rp = lwptoregs(lwp);
	label_t lab;
	caddr32_t uc_addr;
	caddr32_t args_addr;
	caddr32_t top;
	/*
	 * Variables used after on_fault() returns for a fault
	 * must be volatile.
	 */
	volatile size_t frsz;
	volatile caddr32_t sp;
	volatile proc_t *p = lwptoproc(lwp);
	volatile int watched;

	/*
	 * We should not be able to get here unless we are running Linux
	 * code for a system call we cannot emulate in the kernel.
	 */
	VERIFY(lwpd->br_stack_mode == LX_STACK_MODE_BRAND);

	/*
	 * We begin at the current native stack pointer, and reserve space for
	 * the ucontext_t we are copying onto the stack, as well as the call
	 * arguments for the usermode emulation handler.
	 */
	frsz = SA32(sizeof (ucontext32_t)) + SA32(6 * sizeof (uint32_t)) +
	    SA32(sizeof (struct lx_emu_frame32));
	VERIFY((frsz & (STACK_ALIGN32 - 1)) == 0);

	top = (caddr32_t)(lwpd->br_ntv_stack_current & ~(STACK_ALIGN32 - 1));
	sp = top - frsz;

	uc_addr = top - SA32(sizeof (ucontext32_t));
	args_addr = uc_addr - SA32(6 * sizeof (uint32_t));

	watched = watch_disable_addr((caddr_t)(uintptr_t)sp, frsz, S_WRITE);
	if (on_fault(&lab)) {
		goto badstack;
	}

	/*
	 * Save the register state we preserved on the way into this brand
	 * system call and drop it on the native stack.
	 */
	{
		/*
		 * Note: ucontext32_t is 512 bytes.
		 */
		ucontext32_t uc;

		/*
		 * We do not want to save the signal mask for an emulation
		 * context.  Some emulated system calls alter the signal mask;
		 * restoring it when the emulation is complete would clobber
		 * those intentional side effects.
		 */
		savecontext32(&uc, NULL);

		/*
		 * Mark this as a system call emulation context:
		 */
		uc.uc_brand_data[0] |= LX_UC_FRAME_IS_SYSCALL;
		copyout_noerr(&uc, (void *)(uintptr_t)uc_addr, sizeof (uc));
	}

	DTRACE_PROBE3(oldcontext__set, klwp_t *, lwp,
	    uintptr_t, lwp->lwp_oldcontext, uintptr_t, uc_addr);
	lwp->lwp_oldcontext = (uintptr_t)uc_addr;

	/*
	 * Copy the system call arguments out to userland:
	 */
	{
		uint32_t args32[6];

		args32[0] = args[0];
		args32[1] = args[1];
		args32[2] = args[2];
		args32[3] = args[3];
		args32[4] = args[4];
		args32[5] = args[5];

		copyout_noerr(&args32, (void *)(uintptr_t)args_addr,
		    sizeof (args32));
	}

	/*
	 * Assemble the call frame on the stack.
	 */
	{
		struct lx_emu_frame32 frm;

		frm.retaddr = 0;
		frm.ucontextp = uc_addr;
		frm.argsp = args_addr;
		frm.syscall_num = syscall_num;

		copyout_noerr(&frm, (void *)(uintptr_t)sp, sizeof (frm));
	}

	no_fault();
	if (watched) {
		watch_enable_addr((caddr_t)(uintptr_t)sp, frsz, S_WRITE);
	}

	/*
	 * Set stack pointer and return address to the usermode emulation
	 * handler:
	 */
	lwpd->br_stack_mode = LX_STACK_MODE_NATIVE;
	lx_lwp_set_native_stack_current(lwpd, sp);

	/*
	 * Divert execution, on our return, to the usermode emulation stack
	 * and handler:
	 */
	rp->r_fp = 0;
	rp->r_sp = sp;
	rp->r_pc = ptolxproc(p)->l_handler;

	/*
	 * Fix up segment registers, etc.
	 */
	lx_switch_to_native(lwp);

	return;

badstack:
	no_fault();
	if (watched) {
		watch_enable_addr((caddr_t)(uintptr_t)sp, frsz, S_WRITE);
	}

#ifdef DEBUG
	printf("lx_emulate_user32: bad native stack cmd=%s, pid=%d, sp=0x%x\n",
	    PTOU(p)->u_comm, p->p_pid, sp);
#endif

	exit(CLD_KILLED, SIGSEGV);
}
#endif	/* _SYSCALL32_IMPL */

#else	/* !__amd64 (__i386) */

void
lx_emulate_user(klwp_t *lwp, int syscall_num, uintptr_t *args)
{
	cmn_err(CE_WARN, "%s: no 32-bit kernel support", __FUNCTION__);
	exit(CLD_KILLED, SIGSYS);
}

#endif	/* __amd64 */

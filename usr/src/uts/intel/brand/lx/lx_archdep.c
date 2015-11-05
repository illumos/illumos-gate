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
#include <sys/lx_misc.h>
#include <sys/privregs.h>
#include <sys/pcb.h>
#include <sys/archsystm.h>
#include <sys/stack.h>
#include <sys/sdt.h>
#include <sys/sysmacros.h>
#include <sys/psw.h>
#include <lx_errno.h>

/*
 * Argument constants for fix_segreg.
 * See usr/src/uts/intel/ia32/os/archdep.c for the originals.
 */
#define	IS_CS		1
#define	IS_NOT_CS	0

extern greg_t fix_segreg(greg_t, int, model_t);


#define	LX_REG(ucp, r)	((ucp)->uc_mcontext.gregs[(r)])

#define	PSLMERGE(oldval, newval)	\
	(((oldval) & ~PSL_USERMASK) | ((newval) & PSL_USERMASK))

#ifdef __amd64
/* 64-bit native user_regs_struct */
typedef struct lx_user_regs64 {
	int64_t	lxur_r15;
	int64_t	lxur_r14;
	int64_t	lxur_r13;
	int64_t	lxur_r12;
	int64_t	lxur_rbp;
	int64_t	lxur_rbx;
	int64_t	lxur_r11;
	int64_t	lxur_r10;
	int64_t	lxur_r9;
	int64_t	lxur_r8;
	int64_t	lxur_rax;
	int64_t	lxur_rcx;
	int64_t	lxur_rdx;
	int64_t	lxur_rsi;
	int64_t	lxur_rdi;
	int64_t	lxur_orig_rax;
	int64_t	lxur_rip;
	int64_t	lxur_xcs;
	int64_t	lxur_rflags;
	int64_t	lxur_rsp;
	int64_t	lxur_xss;
	int64_t	lxur_xfs_base;
	int64_t	lxur_xgs_base;
	int64_t	lxur_xds;
	int64_t	lxur_xes;
	int64_t	lxur_xfs;
	int64_t	lxur_xgs;
} lx_user_regs64_t;

/* 64-bit native user_fpregs_struct */
typedef struct lx_user_fpregs64 {
	uint16_t	lxufp_cwd;
	uint16_t	lxufp_swd;
	uint16_t	lxufp_ftw;
	uint16_t	lxufp_fop;
	uint64_t	lxufp_rip;
	uint64_t	lxufp_rdp;
	uint32_t	lxufp_mxcsr;
	uint32_t	lxufp_mxcr_mask;
	/* 8*16 bytes for each FP-reg = 128 bytes */
	uint32_t	lxufp_st_space[32];
	/* 16*16 bytes for each XMM-reg = 256 bytes */
	uint32_t	lxufp_xmm_space[64];
	uint32_t	lxufp_padding[24];
} lx_user_fpregs64_t;

/* 64-bit native user_struct */
typedef struct lx_user64 {
	lx_user_regs64_t	lxu_regs;
	int32_t			lxu_fpvalid;
	int32_t			lxu_pad0;
	lx_user_fpregs64_t	lxu_i387;
	uint64_t		lxu_tsize;
	uint64_t		lxu_dsize;
	uint64_t		lxu_ssize;
	uint64_t		lxu_start_code;
	uint64_t		lxu_start_stack;
	int64_t			lxu_signal;
	int32_t			lxu_reserved;
	int32_t			lxu_pad1;
	/* help gdb to locate user_regs structure */
	caddr_t			lxu_ar0;
	/* help gdb to locate user_fpregs structure */
	caddr_t			lxu_fpstate;
	uint64_t		lxu_magic;
	char			lxu_comm[32];
	uint64_t		lxu_debugreg[8];
	uint64_t		lxu_error_code;
	uint64_t		lxu_fault_address;
} lx_user64_t;

#endif /* __amd64 */

/* 32-bit native user_regs_struct */
typedef struct lx_user_regs32 {
	int32_t	lxur_ebx;
	int32_t	lxur_ecx;
	int32_t	lxur_edx;
	int32_t	lxur_esi;
	int32_t	lxur_edi;
	int32_t	lxur_ebp;
	int32_t	lxur_eax;
	int32_t	lxur_xds;
	int32_t	lxur_xes;
	int32_t	lxur_xfs;
	int32_t	lxur_xgs;
	int32_t	lxur_orig_eax;
	int32_t	lxur_eip;
	int32_t	lxur_xcs;
	int32_t	lxur_eflags;
	int32_t	lxur_esp;
	int32_t	lxur_xss;
} lx_user_regs32_t;

/* 32-bit native user_fpregs_struct */
typedef struct lx_user_fpregs32 {
	int32_t		lxufp_cwd;
	int32_t		lxufp_swd;
	int32_t		lxufp_twd;
	int32_t		lxufp_fip;
	int32_t		lxufp_fcs;
	int32_t		lxufp_foo;
	int32_t		lxufp_fos;
	int32_t		lxufp_st_space[20];
} lx_user_fpregs32_t;

/* 32-bit native user_fpxregs_struct */
typedef struct lx_user_fpxregs32 {
	uint16_t	lxufpx_cwd;
	uint16_t	lxufpx_swd;
	uint16_t	lxufpx_twd;
	uint16_t	lxufpx_fop;
	int32_t		lxufpx_fip;
	int32_t		lxufpx_fcs;
	int32_t		lxufpx_foo;
	int32_t		lxufpx_fos;
	int32_t		lxufpx_mxcsr;
	int32_t		lxufpx_reserved;
	/* 8*16 bytes for each FP-reg = 128 bytes */
	int32_t		lxufpx_st_space[32];
	/* 8*16 bytes for each XMM-reg = 128 bytes */
	int32_t		lxufpx_xmm_space[32];
	int32_t		lxufpx_padding[56];
} lx_user_fpxregs32_t;

/* 32-bit native user_struct */
typedef struct lx_user32 {
	lx_user_regs32_t	lxu_regs;
	int32_t			lxu_fpvalid;
	lx_user_fpregs32_t	lxu_i387;
	uint32_t		lxu_tsize;
	uint32_t		lxu_dsize;
	uint32_t		lxu_ssize;
	uint32_t		lxu_start_code;
	uint32_t		lxu_start_stack;
	int32_t			lxu_signal;
	int32_t			lxu_reserved;
	caddr32_t		lxu_ar0;
	caddr32_t		lxu_fpstate;
	uint32_t		lxu_magic;
	char			lxu_comm[32];
	int32_t			lxu_debugreg[8];
} lx_user32_t;

/*
 * Certain version of strace (on centos6 for example) use the %cs value to
 * determine what kind of process is being traced. Here is a sample comment:
 *	Check CS register value. On x86-64 linux it is:
 *	    0x33	for long mode (64 bit and x32))
 *	    0x23	for compatibility mode (32 bit)
 *	%ds = 0x2b for x32 mode (x86-64 in 32 bit)
 * We can't change the %cs value in the ucp (see setgregs and _sys_rtt) so we
 * emulate the expected value for ptrace use.
 */
#define	LX_CS_64BIT	0x33
#define	LX_CS_32BIT	0x23

extern int getsetcontext(int, void *);
#if defined(_SYSCALL32_IMPL)
extern int getsetcontext32(int, void *);
#endif

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

static void
lx_getfpregs32(lx_lwp_data_t *lwpd, lx_user_fpregs32_t *lfp)
{
#ifdef __amd64
	fpregset32_t fp;
	getfpregs32(lwpd->br_lwp, &fp);
#else /* __i386 */
	fpregset_t fp;
	getfpregs(lwpd->br_lwp, &fp);
#endif /* __amd64 */

	/*
	 * The fpchip_state.state field should correspond to all 27 fields in
	 * the 32-bit structure.
	 */
	bcopy(&fp.fp_reg_set.fpchip_state.state, lfp, sizeof (*lfp));
}

static void
lx_setfpregs32(lx_lwp_data_t *lwpd, lx_user_fpregs32_t *lfp)
{
#ifdef __amd64
	fpregset32_t fp;
#else /* __i386 */
	fpregset_t fp;
#endif /* __amd64 */

	/*
	 * The fpchip_state field should correspond to all 27 fields in the
	 * native 32-bit structure.
	 */
	bcopy(lfp, &fp.fp_reg_set.fpchip_state.state, sizeof (*lfp));

#ifdef __amd64
	setfpregs32(lwpd->br_lwp, &fp);
#else /* __i386 */
	setfpregs(lwpd->br_lwp, &fp);
#endif /* __amd64 */
}

static int
lx_get_user_regs32_uc(klwp_t *lwp, void *ucp, lx_user_regs32_t *lxrp)
{
	proc_t *p = lwptoproc(lwp);
	ucontext32_t uc;

	if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
		return (-1);
	}

	lxrp->lxur_ebx = LX_REG(&uc, EBX);
	lxrp->lxur_ecx = LX_REG(&uc, ECX);
	lxrp->lxur_edx = LX_REG(&uc, EDX);
	lxrp->lxur_esi = LX_REG(&uc, ESI);
	lxrp->lxur_edi = LX_REG(&uc, EDI);
	lxrp->lxur_ebp = LX_REG(&uc, EBP);
	lxrp->lxur_eax = LX_REG(&uc, EAX);
	lxrp->lxur_orig_eax = 0;

	lxrp->lxur_eip = LX_REG(&uc, EIP);
	lxrp->lxur_eflags = LX_REG(&uc, EFL);
	lxrp->lxur_esp = LX_REG(&uc, UESP);
	lxrp->lxur_xss = LX_REG(&uc, SS);

	/* emulated %cs, see defines */
	lxrp->lxur_xcs = LX_CS_32BIT;
	lxrp->lxur_xds = LX_REG(&uc, DS);
	lxrp->lxur_xes = LX_REG(&uc, ES);
	lxrp->lxur_xfs = LX_REG(&uc, FS);
	lxrp->lxur_xgs = LX_REG(&uc, GS);
	return (0);
}

static int
lx_get_user_regs32(lx_lwp_data_t *lwpd, lx_user_regs32_t *lxrp)
{
	klwp_t *lwp = lwpd->br_lwp;
	struct regs *rp = lwptoregs(lwp);
	void *ucp;
#ifdef __amd64
	struct pcb *pcb = &lwp->lwp_pcb;
#endif

	VERIFY(lwp_getdatamodel(lwp) == DATAMODEL_ILP32);

	switch (lx_regs_location(lwpd, &ucp, B_FALSE)) {
	case LX_REG_LOC_UNAVAIL:
		return (-1);

	case LX_REG_LOC_UCP:
		return (lx_get_user_regs32_uc(lwp, ucp, lxrp));

	case LX_REG_LOC_LWP:
		/* transformation below */
		break;

	default:
		VERIFY(0);
		break;
	}

#ifdef __amd64
	lxrp->lxur_ebx = (int32_t)rp->r_rbx;
	lxrp->lxur_ecx = (int32_t)rp->r_rcx;
	lxrp->lxur_edx = (int32_t)rp->r_rdx;
	lxrp->lxur_esi = (int32_t)rp->r_rsi;
	lxrp->lxur_edi = (int32_t)rp->r_rdi;
	lxrp->lxur_ebp = (int32_t)rp->r_rbp;
	lxrp->lxur_eax = (int32_t)rp->r_rax;
	lxrp->lxur_orig_eax = 0;
	lxrp->lxur_eip = (int32_t)rp->r_rip;
	lxrp->lxur_eflags = (int32_t)rp->r_rfl;
	lxrp->lxur_esp = (int32_t)rp->r_rsp;
	lxrp->lxur_xss = (int32_t)rp->r_ss;

	kpreempt_disable();
	if (pcb->pcb_rupdate == 1) {
		lxrp->lxur_xds = pcb->pcb_ds;
		lxrp->lxur_xes = pcb->pcb_es;
		lxrp->lxur_xfs = pcb->pcb_fs;
		lxrp->lxur_xgs = pcb->pcb_gs;
	} else {
		lxrp->lxur_xds = rp->r_ds;
		lxrp->lxur_xes = rp->r_es;
		lxrp->lxur_xfs = rp->r_fs;
		lxrp->lxur_xgs = rp->r_gs;
	}
	kpreempt_enable();
#else /* __i386 */
	lxrp->lxur_ebx = rp->r_ebx;
	lxrp->lxur_ecx = rp->r_ecx;
	lxrp->lxur_edx = rp->r_edx;
	lxrp->lxur_esi = rp->r_esi;
	lxrp->lxur_edi = rp->r_edi;
	lxrp->lxur_ebp = rp->r_ebp;
	lxrp->lxur_eax = rp->r_eax;
	lxrp->lxur_orig_eax = 0;
	lxrp->lxur_eip = rp->r_eip;
	lxrp->lxur_eflags = rp->r_efl;
	lxrp->lxur_esp = rp->r_esp;
	lxrp->lxur_xss = rp->r_ss;

	lxrp->lxur_xds = rp->r_ds;
	lxrp->lxur_xes = rp->r_es;
	lxrp->lxur_xfs = rp->r_fs;
	lxrp->lxur_xgs = rp->r_gs;
#endif /* __amd64 */

	/* emulated %cs, see defines */
	lxrp->lxur_xcs = LX_CS_32BIT;

	if (lwpd->br_ptrace_whatstop == LX_PR_SYSENTRY) {
		lxrp->lxur_eax = (int32_t)-lx_errno(ENOTSUP, EINVAL);
		lxrp->lxur_orig_eax = (int32_t)lwpd->br_syscall_num;
	} else if (lwpd->br_ptrace_whatstop == LX_PR_SYSEXIT) {
		lxrp->lxur_orig_eax = (int32_t)lwpd->br_syscall_num;
	}

	return (0);
}

static int
lx_set_user_regs32_uc(klwp_t *lwp, void *ucp, lx_user_regs32_t *lxrp)
{
	proc_t *p = lwptoproc(lwp);
	ucontext32_t uc;

	if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
		return (-1);
	}

	/*
	 * Note: we currently ignore "lxur_orig_rax" here since this
	 * path should not be used for system call stops.
	 */
	LX_REG(&uc, EBP) = lxrp->lxur_ebp;
	LX_REG(&uc, EBX) = lxrp->lxur_ebx;
	LX_REG(&uc, EAX) = lxrp->lxur_eax;
	LX_REG(&uc, ECX) = lxrp->lxur_ecx;
	LX_REG(&uc, EDX) = lxrp->lxur_edx;
	LX_REG(&uc, ESI) = lxrp->lxur_esi;
	LX_REG(&uc, EDI) = lxrp->lxur_edi;
	LX_REG(&uc, EIP) = lxrp->lxur_eip;
	LX_REG(&uc, EFL) = PSLMERGE(LX_REG(&uc, EFL), lxrp->lxur_eflags);
	LX_REG(&uc, UESP) = lxrp->lxur_esp;
	LX_REG(&uc, SS) = fix_segreg(lxrp->lxur_xss, IS_NOT_CS,
	    DATAMODEL_ILP32);

	/* %cs is ignored because of our lies */
	LX_REG(&uc, DS) = fix_segreg(lxrp->lxur_xds, IS_NOT_CS,
	    DATAMODEL_ILP32);
	LX_REG(&uc, ES) = fix_segreg(lxrp->lxur_xes, IS_NOT_CS,
	    DATAMODEL_ILP32);
	LX_REG(&uc, FS) = fix_segreg(lxrp->lxur_xfs, IS_NOT_CS,
	    DATAMODEL_ILP32);
	LX_REG(&uc, GS) = fix_segreg(lxrp->lxur_xgs, IS_NOT_CS,
	    DATAMODEL_ILP32);

	if (lx_write_uc(p, ucp, &uc, sizeof (uc)) != 0) {
		return (-1);
	}
	return (0);
}

static int
lx_set_user_regs32(lx_lwp_data_t *lwpd, lx_user_regs32_t *lxrp)
{
	klwp_t *lwp = lwpd->br_lwp;
	struct regs *rp = lwptoregs(lwp);
	void *ucp;
#ifdef __amd64
	struct pcb *pcb = &lwp->lwp_pcb;
#endif

	VERIFY(lwp_getdatamodel(lwp) == DATAMODEL_ILP32);

	switch (lx_regs_location(lwpd, &ucp, B_TRUE)) {
	case LX_REG_LOC_UNAVAIL:
		return (-1);

	case LX_REG_LOC_UCP:
		return (lx_set_user_regs32_uc(lwp, ucp, lxrp));

	case LX_REG_LOC_LWP:
		/* transformation below */
		break;

	default:
		VERIFY(0);
		break;
	}

#ifdef __amd64
	rp->r_rbx = (int32_t)lxrp->lxur_ebx;
	rp->r_rcx = (int32_t)lxrp->lxur_ecx;
	rp->r_rdx = (int32_t)lxrp->lxur_edx;
	rp->r_rsi = (int32_t)lxrp->lxur_esi;
	rp->r_rdi = (int32_t)lxrp->lxur_edi;
	rp->r_rbp = (int32_t)lxrp->lxur_ebp;
	rp->r_rax = (int32_t)lxrp->lxur_eax;
	lwpd->br_syscall_num = (int)lxrp->lxur_orig_eax;
	rp->r_rip = (int32_t)lxrp->lxur_eip;
	rp->r_rfl = (int32_t)PSLMERGE(rp->r_rfl, lxrp->lxur_eflags);
	rp->r_rsp = (int32_t)lxrp->lxur_esp;
	rp->r_ss = (int32_t)fix_segreg(lxrp->lxur_xss, IS_NOT_CS,
	    DATAMODEL_ILP32);

	kpreempt_disable();
	pcb->pcb_rupdate = 1;
	pcb->pcb_ds = fix_segreg(lxrp->lxur_xds, IS_NOT_CS, DATAMODEL_ILP32);
	pcb->pcb_es = fix_segreg(lxrp->lxur_xes, IS_NOT_CS, DATAMODEL_ILP32);
	pcb->pcb_fs = fix_segreg(lxrp->lxur_xfs, IS_NOT_CS, DATAMODEL_ILP32);
	pcb->pcb_gs = fix_segreg(lxrp->lxur_xgs, IS_NOT_CS, DATAMODEL_ILP32);
	kpreempt_enable();
#else /* __i386 */
	rp->r_ebx = lxrp->lxur_ebx;
	rp->r_ecx = lxrp->lxur_ecx;
	rp->r_edx = lxrp->lxur_edx;
	rp->r_esi = lxrp->lxur_esi;
	rp->r_edi = lxrp->lxur_edi;
	rp->r_ebp = lxrp->lxur_ebp;
	rp->r_eax = lxrp->lxur_eax;
	lwpd->br_syscall_num = (int)lxrp->lxur_orig_eax;
	rp->r_eip = lxrp->lxur_eip;
	rp->r_efl = PSLMERGE(rp->r_efl, lxrp->lxur_eflags);
	rp->r_esp = lxrp->lxur_esp;
	rp->r_ss = fix_segreg(lxrp->lxur_xss, IS_NOT_CS, DATAMODEL_ILP32);

	rp->r_ds = fix_segreg(lxrp->lxur_xds, IS_NOT_CS, DATAMODEL_ILP32);
	rp->r_es = fix_segreg(lxrp->lxur_xes, IS_NOT_CS, DATAMODEL_ILP32);
	rp->r_fs = fix_segreg(lxrp->lxur_xfs, IS_NOT_CS, DATAMODEL_ILP32);
	rp->r_gs = fix_segreg(lxrp->lxur_xgs, IS_NOT_CS, DATAMODEL_ILP32);
#endif /* __amd64 */

	return (0);
}

#ifdef __amd64

static void
lx_getfpregs64(lx_lwp_data_t *lwpd, lx_user_fpregs64_t *lfp)
{
	fpregset_t fp;

	getfpregs(lwpd->br_lwp, &fp);
	/* Drop the extra illumos status/xstatus fields when copying state */
	bcopy(&fp.fp_reg_set.fpchip_state, lfp, sizeof (*lfp));
}

static void
lx_setfpregs64(lx_lwp_data_t *lwpd, lx_user_fpregs64_t *lfp)
{
	fpregset_t fp;

	/*
	 * Since the Linux fpregs structure does not contain the same
	 * additional status register which illumos contains, we simply
	 * preserve the existing values when setting fp state.
	 */
	getfpregs(lwpd->br_lwp, &fp);

	/* Copy the identically formatted state */
	bcopy(lfp, &fp.fp_reg_set.fpchip_state, sizeof (*lfp));

	setfpregs(lwpd->br_lwp, &fp);
}

static int
lx_get_user_regs64_uc(klwp_t *lwp, void *ucp, lx_user_regs64_t *lxrp)
{
	proc_t *p = lwptoproc(lwp);

	switch (lwp_getdatamodel(lwp)) {
	case DATAMODEL_LP64: {
		ucontext_t uc;

		if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (-1);
		}

		lxrp->lxur_r15 = LX_REG(&uc, REG_R15);
		lxrp->lxur_r14 = LX_REG(&uc, REG_R14);
		lxrp->lxur_r13 = LX_REG(&uc, REG_R13);
		lxrp->lxur_r12 = LX_REG(&uc, REG_R12);
		lxrp->lxur_rbp = LX_REG(&uc, REG_RBP);
		lxrp->lxur_rbx = LX_REG(&uc, REG_RBX);
		lxrp->lxur_r11 = LX_REG(&uc, REG_R11);
		lxrp->lxur_r10 = LX_REG(&uc, REG_R10);
		lxrp->lxur_r9 = LX_REG(&uc, REG_R9);
		lxrp->lxur_r8 = LX_REG(&uc, REG_R8);
		lxrp->lxur_rax = LX_REG(&uc, REG_RAX);
		lxrp->lxur_rcx = LX_REG(&uc, REG_RCX);
		lxrp->lxur_rdx = LX_REG(&uc, REG_RDX);
		lxrp->lxur_rsi = LX_REG(&uc, REG_RSI);
		lxrp->lxur_rdi = LX_REG(&uc, REG_RDI);
		lxrp->lxur_orig_rax = 0;
		lxrp->lxur_rip = LX_REG(&uc, REG_RIP);
		lxrp->lxur_rflags = LX_REG(&uc, REG_RFL);
		lxrp->lxur_rsp = LX_REG(&uc, REG_RSP);
		lxrp->lxur_xss = LX_REG(&uc, REG_SS);
		lxrp->lxur_xfs_base = LX_REG(&uc, REG_FSBASE);
		lxrp->lxur_xgs_base = LX_REG(&uc, REG_GSBASE);

		lxrp->lxur_xds = LX_REG(&uc, REG_DS);
		lxrp->lxur_xes = LX_REG(&uc, REG_ES);
		lxrp->lxur_xfs = LX_REG(&uc, REG_FS);
		lxrp->lxur_xgs = LX_REG(&uc, REG_GS);

		/* emulated %cs, see defines */
		lxrp->lxur_xcs = LX_CS_64BIT;
		return (0);
	}

	case DATAMODEL_ILP32: {
		ucontext32_t uc;

		if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (-1);
		}

		lxrp->lxur_r15 = 0;
		lxrp->lxur_r14 = 0;
		lxrp->lxur_r13 = 0;
		lxrp->lxur_r12 = 0;
		lxrp->lxur_r11 = 0;
		lxrp->lxur_r10 = 0;
		lxrp->lxur_r9 = 0;
		lxrp->lxur_r8 = 0;
		lxrp->lxur_rbp = LX_REG(&uc, EBP);
		lxrp->lxur_rbx = LX_REG(&uc, EBX);
		lxrp->lxur_rax = LX_REG(&uc, EAX);
		lxrp->lxur_orig_rax = 0;
		lxrp->lxur_rcx = LX_REG(&uc, ECX);
		lxrp->lxur_rdx = LX_REG(&uc, EDX);
		lxrp->lxur_rsi = LX_REG(&uc, ESI);
		lxrp->lxur_rdi = LX_REG(&uc, EDI);
		lxrp->lxur_rip = LX_REG(&uc, EIP);

		lxrp->lxur_rflags = LX_REG(&uc, EFL);
		lxrp->lxur_rsp = LX_REG(&uc, UESP);
		lxrp->lxur_xss = LX_REG(&uc, SS);
		lxrp->lxur_xfs_base = 0;
		lxrp->lxur_xgs_base = 0;

		lxrp->lxur_xds = LX_REG(&uc, DS);
		lxrp->lxur_xes = LX_REG(&uc, ES);
		lxrp->lxur_xfs = LX_REG(&uc, FS);
		lxrp->lxur_xgs = LX_REG(&uc, GS);

		/* See comment above re: %cs register */
		lxrp->lxur_xcs = LX_CS_32BIT;
		return (0);
	}

	default:
		break;
	}

	return (-1);
}

static int
lx_get_user_regs64(lx_lwp_data_t *lwpd, lx_user_regs64_t *lxrp)
{
	klwp_t *lwp = lwpd->br_lwp;
	struct regs *rp = lwptoregs(lwp);
	struct pcb *pcb = &lwp->lwp_pcb;
	void *ucp;

	switch (lx_regs_location(lwpd, &ucp, B_FALSE)) {
	case LX_REG_LOC_UNAVAIL:
		return (-1);

	case LX_REG_LOC_UCP:
		return (lx_get_user_regs64_uc(lwp, ucp, lxrp));

	case LX_REG_LOC_LWP:
		/* transformation below */
		break;

	default:
		VERIFY(0);
		break;
	}

	lxrp->lxur_r15 = rp->r_r15;
	lxrp->lxur_r14 = rp->r_r14;
	lxrp->lxur_r13 = rp->r_r13;
	lxrp->lxur_r12 = rp->r_r12;
	lxrp->lxur_rbp = rp->r_rbp;
	lxrp->lxur_rbx = rp->r_rbx;
	lxrp->lxur_r11 = rp->r_r11;
	lxrp->lxur_r10 = rp->r_r10;
	lxrp->lxur_r9 = rp->r_r9;
	lxrp->lxur_r8 = rp->r_r8;
	lxrp->lxur_rax = rp->r_rax;
	lxrp->lxur_rcx = rp->r_rcx;
	lxrp->lxur_rdx = rp->r_rdx;
	lxrp->lxur_rsi = rp->r_rsi;
	lxrp->lxur_rdi = rp->r_rdi;
	lxrp->lxur_orig_rax = 0;
	lxrp->lxur_rip = rp->r_rip;

	lxrp->lxur_rflags = rp->r_rfl;
	lxrp->lxur_rsp = rp->r_rsp;
	lxrp->lxur_xss = rp->r_ss;
	lxrp->lxur_xfs_base = pcb->pcb_fsbase;
	lxrp->lxur_xgs_base = pcb->pcb_gsbase;

	/* emulated %cs, see defines */
	switch (lwp_getdatamodel(lwp)) {
	case DATAMODEL_LP64:
		lxrp->lxur_xcs = LX_CS_64BIT;
		break;
	case DATAMODEL_ILP32:
		lxrp->lxur_xcs = LX_CS_32BIT;
		break;
	default:
		VERIFY(0);
		break;
	}

	kpreempt_disable();
	if (pcb->pcb_rupdate == 1) {
		lxrp->lxur_xds = pcb->pcb_ds;
		lxrp->lxur_xes = pcb->pcb_es;
		lxrp->lxur_xfs = pcb->pcb_fs;
		lxrp->lxur_xgs = pcb->pcb_gs;
	} else {
		lxrp->lxur_xds = rp->r_ds;
		lxrp->lxur_xes = rp->r_es;
		lxrp->lxur_xfs = rp->r_fs;
		lxrp->lxur_xgs = rp->r_gs;
	}
	kpreempt_enable();

	if (lwpd->br_ptrace_whatstop == LX_PR_SYSENTRY) {
		lxrp->lxur_rax = -lx_errno(ENOTSUP, EINVAL);
		lxrp->lxur_orig_rax = lwpd->br_syscall_num;
	} else if (lwpd->br_ptrace_whatstop == LX_PR_SYSEXIT) {
		lxrp->lxur_orig_rax = lwpd->br_syscall_num;
	}

	return (0);
}

static int
lx_set_user_regs64_uc(klwp_t *lwp, void *ucp, lx_user_regs64_t *lxrp)
{
	proc_t *p = lwptoproc(lwp);

	switch (lwp_getdatamodel(lwp)) {
	case DATAMODEL_LP64: {
		ucontext_t uc;

		if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (-1);
		}

		/*
		 * Note: we currently ignore "lxur_orig_rax" here since this
		 * path should not be used for system call stops.
		 */
		LX_REG(&uc, REG_R15) = lxrp->lxur_r15;
		LX_REG(&uc, REG_R14) = lxrp->lxur_r14;
		LX_REG(&uc, REG_R13) = lxrp->lxur_r13;
		LX_REG(&uc, REG_R12) = lxrp->lxur_r12;
		LX_REG(&uc, REG_RBP) = lxrp->lxur_rbp;
		LX_REG(&uc, REG_RBX) = lxrp->lxur_rbx;
		LX_REG(&uc, REG_R11) = lxrp->lxur_r11;
		LX_REG(&uc, REG_R10) = lxrp->lxur_r10;
		LX_REG(&uc, REG_R9) = lxrp->lxur_r9;
		LX_REG(&uc, REG_R8) = lxrp->lxur_r8;
		LX_REG(&uc, REG_RAX) = lxrp->lxur_rax;
		LX_REG(&uc, REG_RCX) = lxrp->lxur_rcx;
		LX_REG(&uc, REG_RDX) = lxrp->lxur_rdx;
		LX_REG(&uc, REG_RSI) = lxrp->lxur_rsi;
		LX_REG(&uc, REG_RDI) = lxrp->lxur_rdi;
		LX_REG(&uc, REG_RIP) = lxrp->lxur_rip;
		LX_REG(&uc, REG_RFL) = PSLMERGE(LX_REG(&uc, REG_RFL),
		    lxrp->lxur_rflags);
		LX_REG(&uc, REG_RSP) = lxrp->lxur_rsp;
		LX_REG(&uc, REG_SS) = fix_segreg(lxrp->lxur_xss, IS_NOT_CS,
		    DATAMODEL_LP64);
		LX_REG(&uc, REG_FSBASE) = lxrp->lxur_xfs_base;
		LX_REG(&uc, REG_GSBASE) = lxrp->lxur_xgs_base;

		/* %cs is ignored because of our lies */
		LX_REG(&uc, REG_DS) = fix_segreg(lxrp->lxur_xds, IS_NOT_CS,
		    DATAMODEL_LP64);
		LX_REG(&uc, REG_ES) = fix_segreg(lxrp->lxur_xes, IS_NOT_CS,
		    DATAMODEL_LP64);
		LX_REG(&uc, REG_FS) = fix_segreg(lxrp->lxur_xfs, IS_NOT_CS,
		    DATAMODEL_LP64);
		LX_REG(&uc, REG_GS) = fix_segreg(lxrp->lxur_xgs, IS_NOT_CS,
		    DATAMODEL_LP64);

		if (lx_write_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (-1);
		}

		return (0);
	}

	case DATAMODEL_ILP32: {
		ucontext32_t uc;

		if (lx_read_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (-1);
		}

		/*
		 * Note: we currently ignore "lxur_orig_rax" here since this
		 * path should not be used for system call stops.
		 */
		LX_REG(&uc, EBP) = (int32_t)lxrp->lxur_rbp;
		LX_REG(&uc, EBX) = (int32_t)lxrp->lxur_rbx;
		LX_REG(&uc, EAX) = (int32_t)lxrp->lxur_rax;
		LX_REG(&uc, ECX) = (int32_t)lxrp->lxur_rcx;
		LX_REG(&uc, EDX) = (int32_t)lxrp->lxur_rdx;
		LX_REG(&uc, ESI) = (int32_t)lxrp->lxur_rsi;
		LX_REG(&uc, EDI) = (int32_t)lxrp->lxur_rdi;
		LX_REG(&uc, EIP) = (int32_t)lxrp->lxur_rip;
		LX_REG(&uc, EFL) = (int32_t)PSLMERGE(LX_REG(&uc, EFL),
		    lxrp->lxur_rflags);
		LX_REG(&uc, UESP) = (int32_t)lxrp->lxur_rsp;
		LX_REG(&uc, SS) = (int32_t)fix_segreg(lxrp->lxur_xss,
		    IS_NOT_CS, DATAMODEL_ILP32);

		/* %cs is ignored because of our lies */
		LX_REG(&uc, DS) = (int32_t)fix_segreg(lxrp->lxur_xds,
		    IS_NOT_CS, DATAMODEL_ILP32);
		LX_REG(&uc, ES) = (int32_t)fix_segreg(lxrp->lxur_xes,
		    IS_NOT_CS, DATAMODEL_ILP32);
		LX_REG(&uc, FS) = (int32_t)fix_segreg(lxrp->lxur_xfs,
		    IS_NOT_CS, DATAMODEL_ILP32);
		LX_REG(&uc, GS) = (int32_t)fix_segreg(lxrp->lxur_xgs,
		    IS_NOT_CS, DATAMODEL_ILP32);

		if (lx_write_uc(p, ucp, &uc, sizeof (uc)) != 0) {
			return (-1);
		}
		return (0);
	}

	default:
		break;
	}

	return (-1);
}

static int
lx_set_user_regs64(lx_lwp_data_t *lwpd, lx_user_regs64_t *lxrp)
{
	klwp_t *lwp = lwpd->br_lwp;
	struct regs *rp = lwptoregs(lwp);
	struct pcb *pcb = &lwp->lwp_pcb;
	void *ucp;

	VERIFY(lwp_getdatamodel(lwp) == DATAMODEL_LP64);

	switch (lx_regs_location(lwpd, &ucp, B_TRUE)) {
	case LX_REG_LOC_UNAVAIL:
		return (-1);

	case LX_REG_LOC_UCP:
		return (lx_set_user_regs64_uc(lwp, ucp, lxrp));

	case LX_REG_LOC_LWP:
		/* transformation below */
		break;

	default:
		VERIFY(0);
		break;
	}

	rp->r_r15 = lxrp->lxur_r15;
	rp->r_r14 = lxrp->lxur_r14;
	rp->r_r13 = lxrp->lxur_r13;
	rp->r_r12 = lxrp->lxur_r12;
	rp->r_rbp = lxrp->lxur_rbp;
	rp->r_rbx = lxrp->lxur_rbx;
	rp->r_r11 = lxrp->lxur_r11;
	rp->r_r10 = lxrp->lxur_r10;
	rp->r_r9 = lxrp->lxur_r9;
	rp->r_r8 = lxrp->lxur_r8;
	rp->r_rax = lxrp->lxur_rax;
	rp->r_rcx = lxrp->lxur_rcx;
	rp->r_rdx = lxrp->lxur_rdx;
	rp->r_rsi = lxrp->lxur_rsi;
	rp->r_rdi = lxrp->lxur_rdi;
	lwpd->br_syscall_num = (int)lxrp->lxur_orig_rax;
	rp->r_rip = lxrp->lxur_rip;
	rp->r_rfl = PSLMERGE(rp->r_rfl, lxrp->lxur_rflags);
	rp->r_rsp = lxrp->lxur_rsp;
	rp->r_ss = fix_segreg(lxrp->lxur_xss, IS_NOT_CS, DATAMODEL_LP64);
	pcb->pcb_fsbase = lxrp->lxur_xfs_base;
	pcb->pcb_gsbase = lxrp->lxur_xgs_base;

	kpreempt_disable();
	pcb->pcb_rupdate = 1;
	pcb->pcb_ds = fix_segreg(lxrp->lxur_xds, IS_NOT_CS, DATAMODEL_LP64);
	pcb->pcb_es = fix_segreg(lxrp->lxur_xes, IS_NOT_CS, DATAMODEL_LP64);
	pcb->pcb_fs = fix_segreg(lxrp->lxur_xfs, IS_NOT_CS, DATAMODEL_LP64);
	pcb->pcb_gs = fix_segreg(lxrp->lxur_xgs, IS_NOT_CS, DATAMODEL_LP64);
	kpreempt_enable();

	return (0);
}

#endif /* __amd64 */

static int
lx_peekuser32(lx_lwp_data_t *lwpd, uintptr_t offset, uint32_t *res)
{
	lx_user32_t lxu;
	boolean_t valid = B_FALSE;

	bzero(&lxu, sizeof (lxu));
	if (offset < sizeof (lx_user_regs32_t)) {
		if (lx_get_user_regs32(lwpd, &lxu.lxu_regs) == 0) {
			valid = B_TRUE;
		}
	}
	if (valid) {
		uint32_t *data = (uint32_t *)&lxu;
		*res = data[offset / sizeof (uint32_t)];
		return (0);
	}
	return (-1);
}

#ifdef __amd64
static int
lx_peekuser64(lx_lwp_data_t *lwpd, uintptr_t offset, uintptr_t *res)
{
	lx_user64_t lxu;
	boolean_t valid = B_FALSE;

	bzero(&lxu, sizeof (lxu));
	if (offset < sizeof (lx_user_regs64_t)) {
		lx_user_regs64_t regs;
		if (lx_get_user_regs64(lwpd, &regs) == 0) {
			valid = B_TRUE;
		}
	}
	if (valid) {
		uintptr_t *data = (uintptr_t *)&lxu;
		*res = data[offset / sizeof (uintptr_t)];
		return (0);
	}
	return (-1);
}
#endif /* __amd64 */

int
lx_user_regs_copyin(lx_lwp_data_t *lwpd, void *uregsp)
{
	model_t target_model = lwp_getdatamodel(lwpd->br_lwp);

	switch (get_udatamodel()) {
	case DATAMODEL_ILP32:
		if (target_model == DATAMODEL_ILP32) {
			lx_user_regs32_t regs;

			if (copyin(uregsp, &regs, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			if (lx_set_user_regs32(lwpd, &regs) != 0) {
				return (EIO);
			}
			return (0);
		}

#ifdef __amd64
	case DATAMODEL_LP64:
		if (target_model == DATAMODEL_ILP32 ||
		    target_model == DATAMODEL_LP64) {
			lx_user_regs64_t regs;

			if (copyin(uregsp, &regs, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			if (lx_set_user_regs64(lwpd, &regs) != 0) {
				return (EIO);
			}
			return (0);
		}
		break;
#endif /* __amd64 */

	default:
		break;
	}
	return (EIO);
}

int
lx_user_regs_copyout(lx_lwp_data_t *lwpd, void *uregsp)
{
	model_t target_model = lwp_getdatamodel(lwpd->br_lwp);

	switch (get_udatamodel()) {
	case DATAMODEL_ILP32:
		if (target_model == DATAMODEL_ILP32) {
			lx_user_regs32_t regs;

			if (lx_get_user_regs32(lwpd, &regs) != 0) {
				return (EIO);
			}
			if (copyout(&regs, uregsp, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			return (0);
		}

#ifdef __amd64
	case DATAMODEL_LP64:
		if (target_model == DATAMODEL_ILP32 ||
		    target_model == DATAMODEL_LP64) {
			lx_user_regs64_t regs;

			if (lx_get_user_regs64(lwpd, &regs) != 0) {
				return (EIO);
			}
			if (copyout(&regs, uregsp, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			return (0);
		}
		break;
#endif /* __amd64 */

	default:
		break;
	}
	return (EIO);
}

int
lx_user_fpregs_copyin(lx_lwp_data_t *lwpd, void *uregsp)
{
	model_t target_model = lwp_getdatamodel(lwpd->br_lwp);

	switch (get_udatamodel()) {
	case DATAMODEL_ILP32:
		if (target_model == DATAMODEL_ILP32) {
			lx_user_fpregs32_t regs;

			if (copyin(uregsp, &regs, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			lx_setfpregs32(lwpd, &regs);
			return (0);
		}

#ifdef __amd64
	case DATAMODEL_LP64:
		if (target_model == DATAMODEL_ILP32 ||
		    target_model == DATAMODEL_LP64) {
			lx_user_fpregs64_t regs;

			if (copyin(uregsp, &regs, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			lx_setfpregs64(lwpd, &regs);
			return (0);
		}
		break;
#endif /* __amd64 */

	default:
		break;
	}
	return (EIO);
}

int
lx_user_fpregs_copyout(lx_lwp_data_t *lwpd, void *uregsp)
{
	model_t target_model = lwp_getdatamodel(lwpd->br_lwp);

	switch (get_udatamodel()) {
	case DATAMODEL_ILP32:
		if (target_model == DATAMODEL_ILP32) {
			lx_user_fpregs32_t regs;

			lx_getfpregs32(lwpd, &regs);
			if (copyout(&regs, uregsp, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			return (0);
		}

#ifdef __amd64
	case DATAMODEL_LP64:
		if (target_model == DATAMODEL_ILP32 ||
		    target_model == DATAMODEL_LP64) {
			lx_user_fpregs64_t regs;

			lx_getfpregs64(lwpd, &regs);
			if (copyout(&regs, uregsp, sizeof (regs)) != 0) {
				return (EFAULT);
			}
			return (0);
		}
		break;
#endif /* __amd64 */

	default:
		break;
	}
	return (EIO);
}

int
lx_user_fpxregs_copyin(lx_lwp_data_t *lwpd, void *uregsp)
{
	/* Punt on fpxregs for now */
	return (EIO);
}

int
lx_user_fpxregs_copyout(lx_lwp_data_t *lwpd, void *uregsp)
{
	/* Punt on fpxregs for now */
	return (EIO);
}

int
lx_ptrace_peekuser(lx_lwp_data_t *lwpd, uintptr_t offset, void *uptr)
{
	model_t target_model = lwp_getdatamodel(lwpd->br_lwp);

	switch (get_udatamodel()) {
	case DATAMODEL_ILP32:
		if ((offset & (sizeof (uint32_t) - 1)) != 0) {
			/* Must be aligned to 32bit boundary */
			break;
		}
		if (target_model == DATAMODEL_ILP32) {
			uint32_t res;

			if (lx_peekuser32(lwpd, offset, &res) != 0) {
				return (EIO);
			}
			if (copyout(&res, uptr, sizeof (res)) != 0) {
				return (EFAULT);
			}
			return (0);
		}

#ifdef __amd64
	case DATAMODEL_LP64:
		if ((offset & (sizeof (uintptr_t) - 1)) != 0) {
			/* Must be aligned to 64bit boundary */
			break;
		}
		if (target_model == DATAMODEL_ILP32 ||
		    target_model == DATAMODEL_LP64) {
			uintptr_t res;

			if (lx_peekuser64(lwpd, offset, &res) != 0) {
				return (EIO);
			}
			if (copyout(&res, uptr, sizeof (res)) != 0) {
				return (EFAULT);
			}
			return (0);
		}
		break;
#endif /* __amd64 */

	default:
		break;
	}
	return (EIO);
}

int
lx_ptrace_pokeuser(lx_lwp_data_t *lwpd, uintptr_t offset, void *uptr)
{
	return (EIO);
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

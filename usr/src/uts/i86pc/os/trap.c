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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*		All Rights Reserved   				*/
/*								*/
/*	Copyright (c) 1987, 1988 Microsoft Corporation  	*/
/*		All Rights Reserved   				*/
/*								*/

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/core.h>
#include <sys/syscall.h>
#include <sys/cpuvar.h>
#include <sys/vm.h>
#include <sys/sysinfo.h>
#include <sys/fault.h>
#include <sys/stack.h>
#include <sys/psw.h>
#include <sys/regset.h>
#include <sys/fp.h>
#include <sys/trap.h>
#include <sys/kmem.h>
#include <sys/vtrace.h>
#include <sys/cmn_err.h>
#include <sys/prsystm.h>
#include <sys/mutex_impl.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/sdt.h>
#include <sys/avintr.h>
#include <sys/kobj.h>

#include <vm/hat.h>

#include <vm/seg_kmem.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/hat_pte.h>
#include <vm/hat_i86.h>

#include <sys/procfs.h>

#include <sys/reboot.h>
#include <sys/debug.h>
#include <sys/debugreg.h>
#include <sys/modctl.h>
#include <sys/aio_impl.h>
#include <sys/tnf.h>
#include <sys/tnf_probe.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/x86_archext.h>
#include <sys/copyops.h>
#include <c2/audit.h>
#include <sys/ftrace.h>
#include <sys/panic.h>
#include <sys/traptrace.h>
#include <sys/ontrap.h>
#include <sys/cpc_impl.h>
#include <sys/bootconf.h>
#include <sys/bootinfo.h>
#include <sys/promif.h>
#include <sys/mach_mmu.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif
#include <sys/contract/process_impl.h>

#define	USER	0x10000		/* user-mode flag added to trap type */

static const char *trap_type_mnemonic[] = {
	"de",	"db",	"2",	"bp",
	"of",	"br",	"ud",	"nm",
	"df",	"9",	"ts",	"np",
	"ss",	"gp",	"pf",	"15",
	"mf",	"ac",	"mc",	"xf"
};

static const char *trap_type[] = {
	"Divide error",				/* trap id 0 	*/
	"Debug",				/* trap id 1	*/
	"NMI interrupt",			/* trap id 2	*/
	"Breakpoint",				/* trap id 3 	*/
	"Overflow",				/* trap id 4 	*/
	"BOUND range exceeded",			/* trap id 5 	*/
	"Invalid opcode",			/* trap id 6 	*/
	"Device not available",			/* trap id 7 	*/
	"Double fault",				/* trap id 8 	*/
	"Coprocessor segment overrun",		/* trap id 9 	*/
	"Invalid TSS",				/* trap id 10 	*/
	"Segment not present",			/* trap id 11 	*/
	"Stack segment fault",			/* trap id 12 	*/
	"General protection",			/* trap id 13 	*/
	"Page fault",				/* trap id 14 	*/
	"Reserved",				/* trap id 15 	*/
	"x87 floating point error",		/* trap id 16 	*/
	"Alignment check",			/* trap id 17 	*/
	"Machine check",			/* trap id 18	*/
	"SIMD floating point exception",	/* trap id 19	*/
};

#define	TRAP_TYPES	(sizeof (trap_type) / sizeof (trap_type[0]))

#define	SLOW_SCALL_SIZE	2
#define	FAST_SCALL_SIZE	2

int tudebug = 0;
int tudebugbpt = 0;
int tudebugfpe = 0;
int tudebugsse = 0;

#if defined(TRAPDEBUG) || defined(lint)
int tdebug = 0;
int lodebug = 0;
int faultdebug = 0;
#else
#define	tdebug	0
#define	lodebug	0
#define	faultdebug	0
#endif /* defined(TRAPDEBUG) || defined(lint) */

#if defined(TRAPTRACE)
/*
 * trap trace record for cpu0 is allocated here.
 * trap trace records for non-boot cpus are allocated in mp_startup_init().
 */
static trap_trace_rec_t trap_tr0[TRAPTR_NENT];
trap_trace_ctl_t trap_trace_ctl[NCPU] = {
	{
	    (uintptr_t)trap_tr0,			/* next record */
	    (uintptr_t)trap_tr0,			/* first record */
	    (uintptr_t)(trap_tr0 + TRAPTR_NENT),	/* limit */
	    (uintptr_t)0				/* current */
	},
};

/*
 * default trap buffer size
 */
size_t trap_trace_bufsize = TRAPTR_NENT * sizeof (trap_trace_rec_t);
int trap_trace_freeze = 0;
int trap_trace_off = 0;

/*
 * A dummy TRAPTRACE entry to use after death.
 */
trap_trace_rec_t trap_trace_postmort;

static void dump_ttrace(void);
#endif	/* TRAPTRACE */
static void dumpregs(struct regs *);
static void showregs(uint_t, struct regs *, caddr_t);
static int kern_gpfault(struct regs *);

/*ARGSUSED*/
static int
die(uint_t type, struct regs *rp, caddr_t addr, processorid_t cpuid)
{
	struct panic_trap_info ti;
	const char *trap_name, *trap_mnemonic;

	if (type < TRAP_TYPES) {
		trap_name = trap_type[type];
		trap_mnemonic = trap_type_mnemonic[type];
	} else {
		trap_name = "trap";
		trap_mnemonic = "-";
	}

#ifdef TRAPTRACE
	TRAPTRACE_FREEZE;
#endif

	ti.trap_regs = rp;
	ti.trap_type = type & ~USER;
	ti.trap_addr = addr;

	curthread->t_panic_trap = &ti;

	if (type == T_PGFLT && addr < (caddr_t)kernelbase) {
		panic("BAD TRAP: type=%x (#%s %s) rp=%p addr=%p "
		    "occurred in module \"%s\" due to %s",
		    type, trap_mnemonic, trap_name, (void *)rp, (void *)addr,
		    mod_containing_pc((caddr_t)rp->r_pc),
		    addr < (caddr_t)PAGESIZE ?
		    "a NULL pointer dereference" :
		    "an illegal access to a user address");
	} else
		panic("BAD TRAP: type=%x (#%s %s) rp=%p addr=%p",
		    type, trap_mnemonic, trap_name, (void *)rp, (void *)addr);
	return (0);
}

/*
 * Rewrite the instruction at pc to be an int $T_SYSCALLINT instruction.
 *
 * int <vector> is two bytes: 0xCD <vector>
 */

static int
rewrite_syscall(caddr_t pc)
{
	uchar_t instr[SLOW_SCALL_SIZE] = { 0xCD, T_SYSCALLINT };

	if (uwrite(curthread->t_procp, instr, SLOW_SCALL_SIZE,
	    (uintptr_t)pc) != 0)
		return (1);

	return (0);
}

/*
 * Test to see if the instruction at pc is sysenter or syscall. The second
 * argument should be the x86 feature flag corresponding to the expected
 * instruction.
 *
 * sysenter is two bytes: 0x0F 0x34
 * syscall is two bytes:  0x0F 0x05
 * int $T_SYSCALLINT is two bytes: 0xCD 0x91
 */

static int
instr_is_other_syscall(caddr_t pc, int which)
{
	uchar_t instr[FAST_SCALL_SIZE];

	ASSERT(which == X86FSET_SEP || which == X86FSET_ASYSC || which == 0xCD);

	if (copyin_nowatch(pc, (caddr_t)instr, FAST_SCALL_SIZE) != 0)
		return (0);

	switch (which) {
	case X86FSET_SEP:
		if (instr[0] == 0x0F && instr[1] == 0x34)
			return (1);
		break;
	case X86FSET_ASYSC:
		if (instr[0] == 0x0F && instr[1] == 0x05)
			return (1);
		break;
	case 0xCD:
		if (instr[0] == 0xCD && instr[1] == T_SYSCALLINT)
			return (1);
		break;
	}

	return (0);
}

static const char *
syscall_insn_string(int syscall_insn)
{
	switch (syscall_insn) {
	case X86FSET_SEP:
		return ("sysenter");
	case X86FSET_ASYSC:
		return ("syscall");
	case 0xCD:
		return ("int");
	default:
		return ("Unknown");
	}
}

static int
ldt_rewrite_syscall(struct regs *rp, proc_t *p, int syscall_insn)
{
	caddr_t	linearpc;
	int return_code = 0;

	mutex_enter(&p->p_ldtlock);	/* Must be held across linear_pc() */

	if (linear_pc(rp, p, &linearpc) == 0) {

		/*
		 * If another thread beat us here, it already changed
		 * this site to the slower (int) syscall instruction.
		 */
		if (instr_is_other_syscall(linearpc, 0xCD)) {
			return_code = 1;
		} else if (instr_is_other_syscall(linearpc, syscall_insn)) {

			if (rewrite_syscall(linearpc) == 0) {
				return_code = 1;
			}
#ifdef DEBUG
			else
				cmn_err(CE_WARN, "failed to rewrite %s "
				    "instruction in process %d",
				    syscall_insn_string(syscall_insn),
				    p->p_pid);
#endif /* DEBUG */
		}
	}

	mutex_exit(&p->p_ldtlock);	/* Must be held across linear_pc() */

	return (return_code);
}

/*
 * Test to see if the instruction at pc is a system call instruction.
 *
 * The bytes of an lcall instruction used for the syscall trap.
 * static uchar_t lcall[7] = { 0x9a, 0, 0, 0, 0, 0x7, 0 };
 * static uchar_t lcallalt[7] = { 0x9a, 0, 0, 0, 0, 0x27, 0 };
 */

#define	LCALLSIZE	7

static int
instr_is_lcall_syscall(caddr_t pc)
{
	uchar_t instr[LCALLSIZE];

	if (copyin_nowatch(pc, (caddr_t)instr, LCALLSIZE) == 0 &&
	    instr[0] == 0x9a &&
	    instr[1] == 0 &&
	    instr[2] == 0 &&
	    instr[3] == 0 &&
	    instr[4] == 0 &&
	    (instr[5] == 0x7 || instr[5] == 0x27) &&
	    instr[6] == 0)
		return (1);

	return (0);
}

#ifdef __amd64

/*
 * In the first revisions of amd64 CPUs produced by AMD, the LAHF and
 * SAHF instructions were not implemented in 64-bit mode. Later revisions
 * did implement these instructions. An extension to the cpuid instruction
 * was added to check for the capability of executing these instructions
 * in 64-bit mode.
 *
 * Intel originally did not implement these instructions in EM64T either,
 * but added them in later revisions.
 *
 * So, there are different chip revisions by both vendors out there that
 * may or may not implement these instructions. The easy solution is to
 * just always emulate these instructions on demand.
 *
 * SAHF == store %ah in the lower 8 bits of %rflags (opcode 0x9e)
 * LAHF == load the lower 8 bits of %rflags into %ah (opcode 0x9f)
 */

#define	LSAHFSIZE 1

static int
instr_is_lsahf(caddr_t pc, uchar_t *instr)
{
	if (copyin_nowatch(pc, (caddr_t)instr, LSAHFSIZE) == 0 &&
	    (*instr == 0x9e || *instr == 0x9f))
		return (1);
	return (0);
}

/*
 * Emulate the LAHF and SAHF instructions. The reference manuals define
 * these instructions to always load/store bit 1 as a 1, and bits 3 and 5
 * as a 0. The other, defined, bits are copied (the PS_ICC bits and PS_P).
 *
 * Note that %ah is bits 8-15 of %rax.
 */
static void
emulate_lsahf(struct regs *rp, uchar_t instr)
{
	if (instr == 0x9e) {
		/* sahf. Copy bits from %ah to flags. */
		rp->r_ps = (rp->r_ps & ~0xff) |
		    ((rp->r_rax >> 8) & PSL_LSAHFMASK) | PS_MB1;
	} else {
		/* lahf. Copy bits from flags to %ah. */
		rp->r_rax = (rp->r_rax & ~0xff00) |
		    (((rp->r_ps & PSL_LSAHFMASK) | PS_MB1) << 8);
	}
	rp->r_pc += LSAHFSIZE;
}
#endif /* __amd64 */

#ifdef OPTERON_ERRATUM_91

/*
 * Test to see if the instruction at pc is a prefetch instruction.
 *
 * The first byte of prefetch instructions is always 0x0F.
 * The second byte is 0x18 for regular prefetch or 0x0D for AMD 3dnow prefetch.
 * The third byte (ModRM) contains the register field bits (bits 3-5).
 * These bits must be between 0 and 3 inclusive for regular prefetch and
 * 0 and 1 inclusive for AMD 3dnow prefetch.
 *
 * In 64-bit mode, there may be a one-byte REX prefex (0x40-0x4F).
 */

static int
cmp_to_prefetch(uchar_t *p)
{
#ifdef _LP64
	if ((p[0] & 0xF0) == 0x40)	/* 64-bit REX prefix */
		p++;
#endif
	return ((p[0] == 0x0F && p[1] == 0x18 && ((p[2] >> 3) & 7) <= 3) ||
	    (p[0] == 0x0F && p[1] == 0x0D && ((p[2] >> 3) & 7) <= 1));
}

static int
instr_is_prefetch(caddr_t pc)
{
	uchar_t instr[4];	/* optional REX prefix plus 3-byte opcode */

	return (copyin_nowatch(pc, instr, sizeof (instr)) == 0 &&
	    cmp_to_prefetch(instr));
}

#endif /* OPTERON_ERRATUM_91 */

/*
 * Called from the trap handler when a processor trap occurs.
 *
 * Note: All user-level traps that might call stop() must exit
 * trap() by 'goto out' or by falling through.
 * Note Also: trap() is usually called with interrupts enabled, (PS_IE == 1)
 * however, there are paths that arrive here with PS_IE == 0 so special care
 * must be taken in those cases.
 */
void
trap(struct regs *rp, caddr_t addr, processorid_t cpuid)
{
	kthread_t *ct = curthread;
	enum seg_rw rw;
	unsigned type;
	proc_t *p = ttoproc(ct);
	klwp_t *lwp = ttolwp(ct);
	uintptr_t lofault;
	label_t *onfault;
	faultcode_t pagefault(), res, errcode;
	enum fault_type fault_type;
	k_siginfo_t siginfo;
	uint_t fault = 0;
	int mstate;
	int sicode = 0;
	int watchcode;
	int watchpage;
	caddr_t vaddr;
	size_t sz;
	int ta;
#ifdef __amd64
	uchar_t instr;
#endif

	ASSERT_STACK_ALIGNED();

	type = rp->r_trapno;
	CPU_STATS_ADDQ(CPU, sys, trap, 1);
	ASSERT(ct->t_schedflag & TS_DONT_SWAP);

	if (type == T_PGFLT) {

		errcode = rp->r_err;
		if (errcode & PF_ERR_WRITE)
			rw = S_WRITE;
		else if ((caddr_t)rp->r_pc == addr ||
		    (mmu.pt_nx != 0 && (errcode & PF_ERR_EXEC)))
			rw = S_EXEC;
		else
			rw = S_READ;

#if defined(__i386)
		/*
		 * Pentium Pro work-around
		 */
		if ((errcode & PF_ERR_PROT) && pentiumpro_bug4046376) {
			uint_t	attr;
			uint_t	priv_violation;
			uint_t	access_violation;

			if (hat_getattr(addr < (caddr_t)kernelbase ?
			    curproc->p_as->a_hat : kas.a_hat, addr, &attr)
			    == -1) {
				errcode &= ~PF_ERR_PROT;
			} else {
				priv_violation = (errcode & PF_ERR_USER) &&
				    !(attr & PROT_USER);
				access_violation = (errcode & PF_ERR_WRITE) &&
				    !(attr & PROT_WRITE);
				if (!priv_violation && !access_violation)
					goto cleanup;
			}
		}
#endif /* __i386 */

	} else if (type == T_SGLSTP && lwp != NULL)
		lwp->lwp_pcb.pcb_drstat = (uintptr_t)addr;

	if (tdebug)
		showregs(type, rp, addr);

	if (USERMODE(rp->r_cs)) {
		/*
		 * Set up the current cred to use during this trap. u_cred
		 * no longer exists.  t_cred is used instead.
		 * The current process credential applies to the thread for
		 * the entire trap.  If trapping from the kernel, this
		 * should already be set up.
		 */
		if (ct->t_cred != p->p_cred) {
			cred_t *oldcred = ct->t_cred;
			/*
			 * DTrace accesses t_cred in probe context.  t_cred
			 * must always be either NULL, or point to a valid,
			 * allocated cred structure.
			 */
			ct->t_cred = crgetcred();
			crfree(oldcred);
		}
		ASSERT(lwp != NULL);
		type |= USER;
		ASSERT(lwptoregs(lwp) == rp);
		lwp->lwp_state = LWP_SYS;

		switch (type) {
		case T_PGFLT + USER:
			if ((caddr_t)rp->r_pc == addr)
				mstate = LMS_TFAULT;
			else
				mstate = LMS_DFAULT;
			break;
		default:
			mstate = LMS_TRAP;
			break;
		}
		/* Kernel probe */
		TNF_PROBE_1(thread_state, "thread", /* CSTYLED */,
		    tnf_microstate, state, mstate);
		mstate = new_mstate(ct, mstate);

		bzero(&siginfo, sizeof (siginfo));
	}

	switch (type) {
	case T_PGFLT + USER:
	case T_SGLSTP:
	case T_SGLSTP + USER:
	case T_BPTFLT + USER:
		break;

	default:
		FTRACE_2("trap(): type=0x%lx, regs=0x%lx",
		    (ulong_t)type, (ulong_t)rp);
		break;
	}

	switch (type) {
	case T_SIMDFPE:
		/* Make sure we enable interrupts before die()ing */
		sti();	/* The SIMD exception comes in via cmninttrap */
		/*FALLTHROUGH*/
	default:
		if (type & USER) {
			if (tudebug)
				showregs(type, rp, (caddr_t)0);
			printf("trap: Unknown trap type %d in user mode\n",
			    type & ~USER);
			siginfo.si_signo = SIGILL;
			siginfo.si_code  = ILL_ILLTRP;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			siginfo.si_trapno = type & ~USER;
			fault = FLTILL;
		} else {
			(void) die(type, rp, addr, cpuid);
			/*NOTREACHED*/
		}
		break;

	case T_PGFLT:		/* system page fault */
		/*
		 * If we're under on_trap() protection (see <sys/ontrap.h>),
		 * set ot_trap and bounce back to the on_trap() call site
		 * via the installed trampoline.
		 */
		if ((ct->t_ontrap != NULL) &&
		    (ct->t_ontrap->ot_prot & OT_DATA_ACCESS)) {
			ct->t_ontrap->ot_trap |= OT_DATA_ACCESS;
			rp->r_pc = ct->t_ontrap->ot_trampoline;
			goto cleanup;
		}

		/*
		 * If we have an Instruction fault in kernel mode, then that
		 * means we've tried to execute a user page (SMEP) or both of
		 * PAE and NXE are enabled. In either case, given that it's a
		 * kernel fault, we should panic immediately and not try to make
		 * any more forward progress. This indicates a bug in the
		 * kernel, which if execution continued, could be exploited to
		 * wreak havoc on the system.
		 */
		if (errcode & PF_ERR_EXEC) {
			(void) die(type, rp, addr, cpuid);
		}

		/*
		 * We need to check if SMAP is in play. If SMAP is in play, then
		 * any access to a user page will show up as a protection
		 * violation. To see if SMAP is enabled we first check if it's a
		 * user address and whether we have the feature flag set. If we
		 * do and the interrupted registers do not allow for user
		 * accesses (PS_ACHK is not enabled), then we need to die
		 * immediately.
		 */
		if (addr < (caddr_t)kernelbase &&
		    is_x86_feature(x86_featureset, X86FSET_SMAP) == B_TRUE &&
		    (rp->r_ps & PS_ACHK) == 0) {
			(void) die(type, rp, addr, cpuid);
		}

		/*
		 * See if we can handle as pagefault. Save lofault and onfault
		 * across this. Here we assume that an address less than
		 * KERNELBASE is a user fault.  We can do this as copy.s
		 * routines verify that the starting address is less than
		 * KERNELBASE before starting and because we know that we
		 * always have KERNELBASE mapped as invalid to serve as a
		 * "barrier".
		 */
		lofault = ct->t_lofault;
		onfault = ct->t_onfault;
		ct->t_lofault = 0;

		mstate = new_mstate(ct, LMS_KFAULT);

		if (addr < (caddr_t)kernelbase) {
			res = pagefault(addr,
			    (errcode & PF_ERR_PROT)? F_PROT: F_INVAL, rw, 0);
			if (res == FC_NOMAP &&
			    addr < p->p_usrstack &&
			    grow(addr))
				res = 0;
		} else {
			res = pagefault(addr,
			    (errcode & PF_ERR_PROT)? F_PROT: F_INVAL, rw, 1);
		}
		(void) new_mstate(ct, mstate);

		/*
		 * Restore lofault and onfault. If we resolved the fault, exit.
		 * If we didn't and lofault wasn't set, die.
		 */
		ct->t_lofault = lofault;
		ct->t_onfault = onfault;
		if (res == 0)
			goto cleanup;

#if defined(OPTERON_ERRATUM_93) && defined(_LP64)
		if (lofault == 0 && opteron_erratum_93) {
			/*
			 * Workaround for Opteron Erratum 93. On return from
			 * a System Managment Interrupt at a HLT instruction
			 * the %rip might be truncated to a 32 bit value.
			 * BIOS is supposed to fix this, but some don't.
			 * If this occurs we simply restore the high order bits.
			 * The HLT instruction is 1 byte of 0xf4.
			 */
			uintptr_t	rip = rp->r_pc;

			if ((rip & 0xfffffffful) == rip) {
				rip |= 0xfffffffful << 32;
				if (hat_getpfnum(kas.a_hat, (caddr_t)rip) !=
				    PFN_INVALID &&
				    (*(uchar_t *)rip == 0xf4 ||
				    *(uchar_t *)(rip - 1) == 0xf4)) {
					rp->r_pc = rip;
					goto cleanup;
				}
			}
		}
#endif /* OPTERON_ERRATUM_93 && _LP64 */

#ifdef OPTERON_ERRATUM_91
		if (lofault == 0 && opteron_erratum_91) {
			/*
			 * Workaround for Opteron Erratum 91. Prefetches may
			 * generate a page fault (they're not supposed to do
			 * that!). If this occurs we simply return back to the
			 * instruction.
			 */
			caddr_t		pc = (caddr_t)rp->r_pc;

			/*
			 * If the faulting PC is not mapped, this is a
			 * legitimate kernel page fault that must result in a
			 * panic. If the faulting PC is mapped, it could contain
			 * a prefetch instruction. Check for that here.
			 */
			if (hat_getpfnum(kas.a_hat, pc) != PFN_INVALID) {
				if (cmp_to_prefetch((uchar_t *)pc)) {
#ifdef DEBUG
					cmn_err(CE_WARN, "Opteron erratum 91 "
					    "occurred: kernel prefetch"
					    " at %p generated a page fault!",
					    (void *)rp->r_pc);
#endif /* DEBUG */
					goto cleanup;
				}
			}
			(void) die(type, rp, addr, cpuid);
		}
#endif /* OPTERON_ERRATUM_91 */

		if (lofault == 0)
			(void) die(type, rp, addr, cpuid);

		/*
		 * Cannot resolve fault.  Return to lofault.
		 */
		if (lodebug) {
			showregs(type, rp, addr);
			traceregs(rp);
		}
		if (FC_CODE(res) == FC_OBJERR)
			res = FC_ERRNO(res);
		else
			res = EFAULT;
		rp->r_r0 = res;
		rp->r_pc = ct->t_lofault;
		goto cleanup;

	case T_PGFLT + USER:	/* user page fault */
		if (faultdebug) {
			char *fault_str;

			switch (rw) {
			case S_READ:
				fault_str = "read";
				break;
			case S_WRITE:
				fault_str = "write";
				break;
			case S_EXEC:
				fault_str = "exec";
				break;
			default:
				fault_str = "";
				break;
			}
			printf("user %s fault:  addr=0x%lx errcode=0x%x\n",
			    fault_str, (uintptr_t)addr, errcode);
		}

#if defined(OPTERON_ERRATUM_100) && defined(_LP64)
		/*
		 * Workaround for AMD erratum 100
		 *
		 * A 32-bit process may receive a page fault on a non
		 * 32-bit address by mistake. The range of the faulting
		 * address will be
		 *
		 *	0xffffffff80000000 .. 0xffffffffffffffff or
		 *	0x0000000100000000 .. 0x000000017fffffff
		 *
		 * The fault is always due to an instruction fetch, however
		 * the value of r_pc should be correct (in 32 bit range),
		 * so we ignore the page fault on the bogus address.
		 */
		if (p->p_model == DATAMODEL_ILP32 &&
		    (0xffffffff80000000 <= (uintptr_t)addr ||
		    (0x100000000 <= (uintptr_t)addr &&
		    (uintptr_t)addr <= 0x17fffffff))) {
			if (!opteron_erratum_100)
				panic("unexpected erratum #100");
			if (rp->r_pc <= 0xffffffff)
				goto out;
		}
#endif /* OPTERON_ERRATUM_100 && _LP64 */

		ASSERT(!(curthread->t_flag & T_WATCHPT));
		watchpage = (pr_watch_active(p) && pr_is_watchpage(addr, rw));
#ifdef __i386
		/*
		 * In 32-bit mode, the lcall (system call) instruction fetches
		 * one word from the stack, at the stack pointer, because of the
		 * way the call gate is constructed.  This is a bogus
		 * read and should not be counted as a read watchpoint.
		 * We work around the problem here by testing to see if
		 * this situation applies and, if so, simply jumping to
		 * the code in locore.s that fields the system call trap.
		 * The registers on the stack are already set up properly
		 * due to the match between the call gate sequence and the
		 * trap gate sequence.  We just have to adjust the pc.
		 */
		if (watchpage && addr == (caddr_t)rp->r_sp &&
		    rw == S_READ && instr_is_lcall_syscall((caddr_t)rp->r_pc)) {
			extern void watch_syscall(void);

			rp->r_pc += LCALLSIZE;
			watch_syscall();	/* never returns */
			/* NOTREACHED */
		}
#endif /* __i386 */
		vaddr = addr;
		if (!watchpage || (sz = instr_size(rp, &vaddr, rw)) <= 0)
			fault_type = (errcode & PF_ERR_PROT)? F_PROT: F_INVAL;
		else if ((watchcode = pr_is_watchpoint(&vaddr, &ta,
		    sz, NULL, rw)) != 0) {
			if (ta) {
				do_watch_step(vaddr, sz, rw,
				    watchcode, rp->r_pc);
				fault_type = F_INVAL;
			} else {
				bzero(&siginfo, sizeof (siginfo));
				siginfo.si_signo = SIGTRAP;
				siginfo.si_code = watchcode;
				siginfo.si_addr = vaddr;
				siginfo.si_trapafter = 0;
				siginfo.si_pc = (caddr_t)rp->r_pc;
				fault = FLTWATCH;
				break;
			}
		} else {
			/* XXX pr_watch_emul() never succeeds (for now) */
			if (rw != S_EXEC && pr_watch_emul(rp, vaddr, rw))
				goto out;
			do_watch_step(vaddr, sz, rw, 0, 0);
			fault_type = F_INVAL;
		}

		res = pagefault(addr, fault_type, rw, 0);

		/*
		 * If pagefault() succeeded, ok.
		 * Otherwise attempt to grow the stack.
		 */
		if (res == 0 ||
		    (res == FC_NOMAP &&
		    addr < p->p_usrstack &&
		    grow(addr))) {
			lwp->lwp_lastfault = FLTPAGE;
			lwp->lwp_lastfaddr = addr;
			if (prismember(&p->p_fltmask, FLTPAGE)) {
				bzero(&siginfo, sizeof (siginfo));
				siginfo.si_addr = addr;
				(void) stop_on_fault(FLTPAGE, &siginfo);
			}
			goto out;
		} else if (res == FC_PROT && addr < p->p_usrstack &&
		    (mmu.pt_nx != 0 && (errcode & PF_ERR_EXEC))) {
			report_stack_exec(p, addr);
		}

#ifdef OPTERON_ERRATUM_91
		/*
		 * Workaround for Opteron Erratum 91. Prefetches may generate a
		 * page fault (they're not supposed to do that!). If this
		 * occurs we simply return back to the instruction.
		 *
		 * We rely on copyin to properly fault in the page with r_pc.
		 */
		if (opteron_erratum_91 &&
		    addr != (caddr_t)rp->r_pc &&
		    instr_is_prefetch((caddr_t)rp->r_pc)) {
#ifdef DEBUG
			cmn_err(CE_WARN, "Opteron erratum 91 occurred: "
			    "prefetch at %p in pid %d generated a trap!",
			    (void *)rp->r_pc, p->p_pid);
#endif /* DEBUG */
			goto out;
		}
#endif /* OPTERON_ERRATUM_91 */

		if (tudebug)
			showregs(type, rp, addr);
		/*
		 * In the case where both pagefault and grow fail,
		 * set the code to the value provided by pagefault.
		 * We map all errors returned from pagefault() to SIGSEGV.
		 */
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_addr = addr;
		switch (FC_CODE(res)) {
		case FC_HWERR:
		case FC_NOSUPPORT:
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRERR;
			fault = FLTACCESS;
			break;
		case FC_ALIGN:
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRALN;
			fault = FLTACCESS;
			break;
		case FC_OBJERR:
			if ((siginfo.si_errno = FC_ERRNO(res)) != EINTR) {
				siginfo.si_signo = SIGBUS;
				siginfo.si_code = BUS_OBJERR;
				fault = FLTACCESS;
			}
			break;
		default:	/* FC_NOMAP or FC_PROT */
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code =
			    (res == FC_NOMAP)? SEGV_MAPERR : SEGV_ACCERR;
			fault = FLTBOUNDS;
			break;
		}
		break;

	case T_ILLINST + USER:	/* invalid opcode fault */
		/*
		 * If the syscall instruction is disabled due to LDT usage, a
		 * user program that attempts to execute it will trigger a #ud
		 * trap. Check for that case here. If this occurs on a CPU which
		 * doesn't even support syscall, the result of all of this will
		 * be to emulate that particular instruction.
		 */
		if (p->p_ldt != NULL &&
		    ldt_rewrite_syscall(rp, p, X86FSET_ASYSC))
			goto out;

#ifdef __amd64
		/*
		 * Emulate the LAHF and SAHF instructions if needed.
		 * See the instr_is_lsahf function for details.
		 */
		if (p->p_model == DATAMODEL_LP64 &&
		    instr_is_lsahf((caddr_t)rp->r_pc, &instr)) {
			emulate_lsahf(rp, instr);
			goto out;
		}
#endif

		/*FALLTHROUGH*/

		if (tudebug)
			showregs(type, rp, (caddr_t)0);
		siginfo.si_signo = SIGILL;
		siginfo.si_code  = ILL_ILLOPC;
		siginfo.si_addr  = (caddr_t)rp->r_pc;
		fault = FLTILL;
		break;

	case T_ZERODIV + USER:		/* integer divide by zero */
		if (tudebug && tudebugfpe)
			showregs(type, rp, (caddr_t)0);
		siginfo.si_signo = SIGFPE;
		siginfo.si_code  = FPE_INTDIV;
		siginfo.si_addr  = (caddr_t)rp->r_pc;
		fault = FLTIZDIV;
		break;

	case T_OVFLW + USER:	/* integer overflow */
		if (tudebug && tudebugfpe)
			showregs(type, rp, (caddr_t)0);
		siginfo.si_signo = SIGFPE;
		siginfo.si_code  = FPE_INTOVF;
		siginfo.si_addr  = (caddr_t)rp->r_pc;
		fault = FLTIOVF;
		break;

	case T_NOEXTFLT + USER:	/* math coprocessor not available */
		if (tudebug && tudebugfpe)
			showregs(type, rp, addr);
		if (fpnoextflt(rp)) {
			siginfo.si_signo = SIGILL;
			siginfo.si_code  = ILL_ILLOPC;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			fault = FLTILL;
		}
		break;

	case T_EXTOVRFLT:	/* extension overrun fault */
		/* check if we took a kernel trap on behalf of user */
		{
			extern  void ndptrap_frstor(void);
			if (rp->r_pc != (uintptr_t)ndptrap_frstor) {
				sti(); /* T_EXTOVRFLT comes in via cmninttrap */
				(void) die(type, rp, addr, cpuid);
			}
			type |= USER;
		}
		/*FALLTHROUGH*/
	case T_EXTOVRFLT + USER:	/* extension overrun fault */
		if (tudebug && tudebugfpe)
			showregs(type, rp, addr);
		if (fpextovrflt(rp)) {
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code  = SEGV_MAPERR;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			fault = FLTBOUNDS;
		}
		break;

	case T_EXTERRFLT:	/* x87 floating point exception pending */
		/* check if we took a kernel trap on behalf of user */
		{
			extern  void ndptrap_frstor(void);
			if (rp->r_pc != (uintptr_t)ndptrap_frstor) {
				sti(); /* T_EXTERRFLT comes in via cmninttrap */
				(void) die(type, rp, addr, cpuid);
			}
			type |= USER;
		}
		/*FALLTHROUGH*/

	case T_EXTERRFLT + USER: /* x87 floating point exception pending */
		if (tudebug && tudebugfpe)
			showregs(type, rp, addr);
		if (sicode = fpexterrflt(rp)) {
			siginfo.si_signo = SIGFPE;
			siginfo.si_code  = sicode;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			fault = FLTFPE;
		}
		break;

	case T_SIMDFPE + USER:		/* SSE and SSE2 exceptions */
		if (tudebug && tudebugsse)
			showregs(type, rp, addr);
		if (!is_x86_feature(x86_featureset, X86FSET_SSE) &&
		    !is_x86_feature(x86_featureset, X86FSET_SSE2)) {
			/*
			 * There are rumours that some user instructions
			 * on older CPUs can cause this trap to occur; in
			 * which case send a SIGILL instead of a SIGFPE.
			 */
			siginfo.si_signo = SIGILL;
			siginfo.si_code  = ILL_ILLTRP;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			siginfo.si_trapno = type & ~USER;
			fault = FLTILL;
		} else if ((sicode = fpsimderrflt(rp)) != 0) {
			siginfo.si_signo = SIGFPE;
			siginfo.si_code = sicode;
			siginfo.si_addr = (caddr_t)rp->r_pc;
			fault = FLTFPE;
		}

		sti();	/* The SIMD exception comes in via cmninttrap */
		break;

	case T_BPTFLT:	/* breakpoint trap */
		/*
		 * Kernel breakpoint traps should only happen when kmdb is
		 * active, and even then, it'll have interposed on the IDT, so
		 * control won't get here.  If it does, we've hit a breakpoint
		 * without the debugger, which is very strange, and very
		 * fatal.
		 */
		if (tudebug && tudebugbpt)
			showregs(type, rp, (caddr_t)0);

		(void) die(type, rp, addr, cpuid);
		break;

	case T_SGLSTP: /* single step/hw breakpoint exception */

#if !defined(__xpv)
		/*
		 * We'd never normally get here, as kmdb handles its own single
		 * step traps.  There is one nasty exception though, as
		 * described in more detail in sys_sysenter().  Note that
		 * checking for all four locations covers both the KPTI and the
		 * non-KPTI cases correctly: the former will never be found at
		 * (brand_)sys_sysenter, and vice versa.
		 */
		if (lwp != NULL && (lwp->lwp_pcb.pcb_drstat & DR_SINGLESTEP)) {
			if (rp->r_pc == (greg_t)brand_sys_sysenter ||
			    rp->r_pc == (greg_t)sys_sysenter ||
			    rp->r_pc == (greg_t)tr_brand_sys_sysenter ||
			    rp->r_pc == (greg_t)tr_sys_sysenter) {

				rp->r_pc += 0x3; /* sizeof (swapgs) */

				rp->r_ps &= ~PS_T; /* turn off trace */
				lwp->lwp_pcb.pcb_flags |= DEBUG_PENDING;
				ct->t_post_sys = 1;
				aston(curthread);
				goto cleanup;
			} else {
				if (tudebug && tudebugbpt)
					showregs(type, rp, (caddr_t)0);
			}
		}
#endif /* !__xpv */

		if (boothowto & RB_DEBUG)
			debug_enter((char *)NULL);
		else
			(void) die(type, rp, addr, cpuid);
		break;

	case T_NMIFLT:	/* NMI interrupt */
		printf("Unexpected NMI in system mode\n");
		goto cleanup;

	case T_NMIFLT + USER:	/* NMI interrupt */
		printf("Unexpected NMI in user mode\n");
		break;

	case T_GPFLT:	/* general protection violation */
		/*
		 * Any #GP that occurs during an on_trap .. no_trap bracket
		 * with OT_DATA_ACCESS or OT_SEGMENT_ACCESS protection,
		 * or in a on_fault .. no_fault bracket, is forgiven
		 * and we trampoline.  This protection is given regardless
		 * of whether we are 32/64 bit etc - if a distinction is
		 * required then define new on_trap protection types.
		 *
		 * On amd64, we can get a #gp from referencing addresses
		 * in the virtual address hole e.g. from a copyin or in
		 * update_sregs while updating user segment registers.
		 *
		 * On the 32-bit hypervisor we could also generate one in
		 * mfn_to_pfn by reaching around or into where the hypervisor
		 * lives which is protected by segmentation.
		 */

		/*
		 * If we're under on_trap() protection (see <sys/ontrap.h>),
		 * set ot_trap and trampoline back to the on_trap() call site
		 * for OT_DATA_ACCESS or OT_SEGMENT_ACCESS.
		 */
		if (ct->t_ontrap != NULL) {
			int ttype =  ct->t_ontrap->ot_prot &
			    (OT_DATA_ACCESS | OT_SEGMENT_ACCESS);

			if (ttype != 0) {
				ct->t_ontrap->ot_trap |= ttype;
				if (tudebug)
					showregs(type, rp, (caddr_t)0);
				rp->r_pc = ct->t_ontrap->ot_trampoline;
				goto cleanup;
			}
		}

		/*
		 * If we're under lofault protection (copyin etc.),
		 * longjmp back to lofault with an EFAULT.
		 */
		if (ct->t_lofault) {
			/*
			 * Fault is not resolvable, so just return to lofault
			 */
			if (lodebug) {
				showregs(type, rp, addr);
				traceregs(rp);
			}
			rp->r_r0 = EFAULT;
			rp->r_pc = ct->t_lofault;
			goto cleanup;
		}

		/*
		 * We fall through to the next case, which repeats
		 * the OT_SEGMENT_ACCESS check which we've already
		 * done, so we'll always fall through to the
		 * T_STKFLT case.
		 */
		/*FALLTHROUGH*/
	case T_SEGFLT:	/* segment not present fault */
		/*
		 * One example of this is #NP in update_sregs while
		 * attempting to update a user segment register
		 * that points to a descriptor that is marked not
		 * present.
		 */
		if (ct->t_ontrap != NULL &&
		    ct->t_ontrap->ot_prot & OT_SEGMENT_ACCESS) {
			ct->t_ontrap->ot_trap |= OT_SEGMENT_ACCESS;
			if (tudebug)
				showregs(type, rp, (caddr_t)0);
			rp->r_pc = ct->t_ontrap->ot_trampoline;
			goto cleanup;
		}
		/*FALLTHROUGH*/
	case T_STKFLT:	/* stack fault */
	case T_TSSFLT:	/* invalid TSS fault */
		if (tudebug)
			showregs(type, rp, (caddr_t)0);
		if (kern_gpfault(rp))
			(void) die(type, rp, addr, cpuid);
		goto cleanup;

	/*
	 * ONLY 32-bit PROCESSES can USE a PRIVATE LDT! 64-bit apps
	 * should have no need for them, so we put a stop to it here.
	 *
	 * So: not-present fault is ONLY valid for 32-bit processes with
	 * a private LDT trying to do a system call. Emulate it.
	 *
	 * #gp fault is ONLY valid for 32-bit processes also, which DO NOT
	 * have a private LDT, and are trying to do a system call. Emulate it.
	 */

	case T_SEGFLT + USER:	/* segment not present fault */
	case T_GPFLT + USER:	/* general protection violation */
#ifdef _SYSCALL32_IMPL
		if (p->p_model != DATAMODEL_NATIVE) {
#endif /* _SYSCALL32_IMPL */
		if (instr_is_lcall_syscall((caddr_t)rp->r_pc)) {
			if (type == T_SEGFLT + USER)
				ASSERT(p->p_ldt != NULL);

			if ((p->p_ldt == NULL && type == T_GPFLT + USER) ||
			    type == T_SEGFLT + USER) {

			/*
			 * The user attempted a system call via the obsolete
			 * call gate mechanism. Because the process doesn't have
			 * an LDT (i.e. the ldtr contains 0), a #gp results.
			 * Emulate the syscall here, just as we do above for a
			 * #np trap.
			 */

			/*
			 * Since this is a not-present trap, rp->r_pc points to
			 * the trapping lcall instruction. We need to bump it
			 * to the next insn so the app can continue on.
			 */
			rp->r_pc += LCALLSIZE;
			lwp->lwp_regs = rp;

			/*
			 * Normally the microstate of the LWP is forced back to
			 * LMS_USER by the syscall handlers. Emulate that
			 * behavior here.
			 */
			mstate = LMS_USER;

			dosyscall();
			goto out;
			}
		}
#ifdef _SYSCALL32_IMPL
		}
#endif /* _SYSCALL32_IMPL */
		/*
		 * If the current process is using a private LDT and the
		 * trapping instruction is sysenter, the sysenter instruction
		 * has been disabled on the CPU because it destroys segment
		 * registers. If this is the case, rewrite the instruction to
		 * be a safe system call and retry it. If this occurs on a CPU
		 * which doesn't even support sysenter, the result of all of
		 * this will be to emulate that particular instruction.
		 */
		if (p->p_ldt != NULL &&
		    ldt_rewrite_syscall(rp, p, X86FSET_SEP))
			goto out;

		/*FALLTHROUGH*/

	case T_BOUNDFLT + USER:	/* bound fault */
	case T_STKFLT + USER:	/* stack fault */
	case T_TSSFLT + USER:	/* invalid TSS fault */
		if (tudebug)
			showregs(type, rp, (caddr_t)0);
		siginfo.si_signo = SIGSEGV;
		siginfo.si_code  = SEGV_MAPERR;
		siginfo.si_addr  = (caddr_t)rp->r_pc;
		fault = FLTBOUNDS;
		break;

	case T_ALIGNMENT + USER:	/* user alignment error (486) */
		if (tudebug)
			showregs(type, rp, (caddr_t)0);
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_signo = SIGBUS;
		siginfo.si_code = BUS_ADRALN;
		siginfo.si_addr = (caddr_t)rp->r_pc;
		fault = FLTACCESS;
		break;

	case T_SGLSTP + USER: /* single step/hw breakpoint exception */
		if (tudebug && tudebugbpt)
			showregs(type, rp, (caddr_t)0);

		/* Was it single-stepping? */
		if (lwp->lwp_pcb.pcb_drstat & DR_SINGLESTEP) {
			pcb_t *pcb = &lwp->lwp_pcb;

			rp->r_ps &= ~PS_T;
			/*
			 * If both NORMAL_STEP and WATCH_STEP are in effect,
			 * give precedence to WATCH_STEP.  If neither is set,
			 * user must have set the PS_T bit in %efl; treat this
			 * as NORMAL_STEP.
			 */
			if ((fault = undo_watch_step(&siginfo)) == 0 &&
			    ((pcb->pcb_flags & NORMAL_STEP) ||
			    !(pcb->pcb_flags & WATCH_STEP))) {
				siginfo.si_signo = SIGTRAP;
				siginfo.si_code = TRAP_TRACE;
				siginfo.si_addr = (caddr_t)rp->r_pc;
				fault = FLTTRACE;
			}
			pcb->pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
		}
		break;

	case T_BPTFLT + USER:	/* breakpoint trap */
		if (tudebug && tudebugbpt)
			showregs(type, rp, (caddr_t)0);
		/*
		 * int 3 (the breakpoint instruction) leaves the pc referring
		 * to the address one byte after the breakpointed address.
		 * If the P_PR_BPTADJ flag has been set via /proc, We adjust
		 * it back so it refers to the breakpointed address.
		 */
		if (p->p_proc_flag & P_PR_BPTADJ)
			rp->r_pc--;
		siginfo.si_signo = SIGTRAP;
		siginfo.si_code  = TRAP_BRKPT;
		siginfo.si_addr  = (caddr_t)rp->r_pc;
		fault = FLTBPT;
		break;

	case T_AST:
		/*
		 * This occurs only after the cs register has been made to
		 * look like a kernel selector, either through debugging or
		 * possibly by functions like setcontext().  The thread is
		 * about to cause a general protection fault at common_iret()
		 * in locore.  We let that happen immediately instead of
		 * doing the T_AST processing.
		 */
		goto cleanup;

	case T_AST + USER:	/* profiling, resched, h/w error pseudo trap */
		if (lwp->lwp_pcb.pcb_flags & ASYNC_HWERR) {
			proc_t *p = ttoproc(curthread);
			extern void print_msg_hwerr(ctid_t ct_id, proc_t *p);

			lwp->lwp_pcb.pcb_flags &= ~ASYNC_HWERR;
			print_msg_hwerr(p->p_ct_process->conp_contract.ct_id,
			    p);
			contract_process_hwerr(p->p_ct_process, p);
			siginfo.si_signo = SIGKILL;
			siginfo.si_code = SI_NOINFO;
		} else if (lwp->lwp_pcb.pcb_flags & CPC_OVERFLOW) {
			lwp->lwp_pcb.pcb_flags &= ~CPC_OVERFLOW;
			if (kcpc_overflow_ast()) {
				/*
				 * Signal performance counter overflow
				 */
				if (tudebug)
					showregs(type, rp, (caddr_t)0);
				bzero(&siginfo, sizeof (siginfo));
				siginfo.si_signo = SIGEMT;
				siginfo.si_code = EMT_CPCOVF;
				siginfo.si_addr = (caddr_t)rp->r_pc;
				fault = FLTCPCOVF;
			}
		}

		break;
	}

	/*
	 * We can't get here from a system trap
	 */
	ASSERT(type & USER);

	if (fault) {
		/* We took a fault so abort single step. */
		lwp->lwp_pcb.pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
		/*
		 * Remember the fault and fault adddress
		 * for real-time (SIGPROF) profiling.
		 */
		lwp->lwp_lastfault = fault;
		lwp->lwp_lastfaddr = siginfo.si_addr;

		DTRACE_PROC2(fault, int, fault, ksiginfo_t *, &siginfo);

		/*
		 * If a debugger has declared this fault to be an
		 * event of interest, stop the lwp.  Otherwise just
		 * deliver the associated signal.
		 */
		if (siginfo.si_signo != SIGKILL &&
		    prismember(&p->p_fltmask, fault) &&
		    stop_on_fault(fault, &siginfo) == 0)
			siginfo.si_signo = 0;
	}

	if (siginfo.si_signo)
		trapsig(&siginfo, (fault != FLTFPE && fault != FLTCPCOVF));

	if (lwp->lwp_oweupc)
		profil_tick(rp->r_pc);

	if (ct->t_astflag | ct->t_sig_check) {
		/*
		 * Turn off the AST flag before checking all the conditions that
		 * may have caused an AST.  This flag is on whenever a signal or
		 * unusual condition should be handled after the next trap or
		 * syscall.
		 */
		astoff(ct);
		/*
		 * If a single-step trap occurred on a syscall (see above)
		 * recognize it now.  Do this before checking for signals
		 * because deferred_singlestep_trap() may generate a SIGTRAP to
		 * the LWP or may otherwise mark the LWP to call issig(FORREAL).
		 */
		if (lwp->lwp_pcb.pcb_flags & DEBUG_PENDING)
			deferred_singlestep_trap((caddr_t)rp->r_pc);

		ct->t_sig_check = 0;

		/*
		 * As in other code paths that check against TP_CHANGEBIND,
		 * we perform the check first without p_lock held -- only
		 * acquiring p_lock in the unlikely event that it is indeed
		 * set.  This is safe because we are doing this after the
		 * astoff(); if we are racing another thread setting
		 * TP_CHANGEBIND on us, we will pick it up on a subsequent
		 * lap through.
		 */
		if (curthread->t_proc_flag & TP_CHANGEBIND) {
			mutex_enter(&p->p_lock);
			if (curthread->t_proc_flag & TP_CHANGEBIND) {
				timer_lwpbind();
				curthread->t_proc_flag &= ~TP_CHANGEBIND;
			}
			mutex_exit(&p->p_lock);
		}

		/*
		 * for kaio requests that are on the per-process poll queue,
		 * aiop->aio_pollq, they're AIO_POLL bit is set, the kernel
		 * should copyout their result_t to user memory. by copying
		 * out the result_t, the user can poll on memory waiting
		 * for the kaio request to complete.
		 */
		if (p->p_aio)
			aio_cleanup(0);
		/*
		 * If this LWP was asked to hold, call holdlwp(), which will
		 * stop.  holdlwps() sets this up and calls pokelwps() which
		 * sets the AST flag.
		 *
		 * Also check TP_EXITLWP, since this is used by fresh new LWPs
		 * through lwp_rtt().  That flag is set if the lwp_create(2)
		 * syscall failed after creating the LWP.
		 */
		if (ISHOLD(p))
			holdlwp();

		/*
		 * All code that sets signals and makes ISSIG evaluate true must
		 * set t_astflag afterwards.
		 */
		if (ISSIG_PENDING(ct, lwp, p)) {
			if (issig(FORREAL))
				psig();
			ct->t_sig_check = 1;
		}

		if (ct->t_rprof != NULL) {
			realsigprof(0, 0, 0);
			ct->t_sig_check = 1;
		}

		/*
		 * /proc can't enable/disable the trace bit itself
		 * because that could race with the call gate used by
		 * system calls via "lcall". If that happened, an
		 * invalid EFLAGS would result. prstep()/prnostep()
		 * therefore schedule an AST for the purpose.
		 */
		if (lwp->lwp_pcb.pcb_flags & REQUEST_STEP) {
			lwp->lwp_pcb.pcb_flags &= ~REQUEST_STEP;
			rp->r_ps |= PS_T;
		}
		if (lwp->lwp_pcb.pcb_flags & REQUEST_NOSTEP) {
			lwp->lwp_pcb.pcb_flags &= ~REQUEST_NOSTEP;
			rp->r_ps &= ~PS_T;
		}
	}

out:	/* We can't get here from a system trap */
	ASSERT(type & USER);

	if (ISHOLD(p))
		holdlwp();

	/*
	 * Set state to LWP_USER here so preempt won't give us a kernel
	 * priority if it occurs after this point.  Call CL_TRAPRET() to
	 * restore the user-level priority.
	 *
	 * It is important that no locks (other than spinlocks) be entered
	 * after this point before returning to user mode (unless lwp_state
	 * is set back to LWP_SYS).
	 */
	lwp->lwp_state = LWP_USER;

	if (ct->t_trapret) {
		ct->t_trapret = 0;
		thread_lock(ct);
		CL_TRAPRET(ct);
		thread_unlock(ct);
	}
	if (CPU->cpu_runrun || curthread->t_schedflag & TS_ANYWAITQ)
		preempt();
	prunstop();
	(void) new_mstate(ct, mstate);

	/* Kernel probe */
	TNF_PROBE_1(thread_state, "thread", /* CSTYLED */,
	    tnf_microstate, state, LMS_USER);

	return;

cleanup:	/* system traps end up here */
	ASSERT(!(type & USER));
}

/*
 * Patch non-zero to disable preemption of threads in the kernel.
 */
int IGNORE_KERNEL_PREEMPTION = 0;	/* XXX - delete this someday */

struct kpreempt_cnts {		/* kernel preemption statistics */
	int	kpc_idle;	/* executing idle thread */
	int	kpc_intr;	/* executing interrupt thread */
	int	kpc_clock;	/* executing clock thread */
	int	kpc_blocked;	/* thread has blocked preemption (t_preempt) */
	int	kpc_notonproc;	/* thread is surrendering processor */
	int	kpc_inswtch;	/* thread has ratified scheduling decision */
	int	kpc_prilevel;	/* processor interrupt level is too high */
	int	kpc_apreempt;	/* asynchronous preemption */
	int	kpc_spreempt;	/* synchronous preemption */
} kpreempt_cnts;

/*
 * kernel preemption: forced rescheduling, preempt the running kernel thread.
 *	the argument is old PIL for an interrupt,
 *	or the distingished value KPREEMPT_SYNC.
 */
void
kpreempt(int asyncspl)
{
	kthread_t *ct = curthread;

	if (IGNORE_KERNEL_PREEMPTION) {
		aston(CPU->cpu_dispthread);
		return;
	}

	/*
	 * Check that conditions are right for kernel preemption
	 */
	do {
		if (ct->t_preempt) {
			/*
			 * either a privileged thread (idle, panic, interrupt)
			 * or will check when t_preempt is lowered
			 * We need to specifically handle the case where
			 * the thread is in the middle of swtch (resume has
			 * been called) and has its t_preempt set
			 * [idle thread and a thread which is in kpreempt
			 * already] and then a high priority thread is
			 * available in the local dispatch queue.
			 * In this case the resumed thread needs to take a
			 * trap so that it can call kpreempt. We achieve
			 * this by using siron().
			 * How do we detect this condition:
			 * idle thread is running and is in the midst of
			 * resume: curthread->t_pri == -1 && CPU->dispthread
			 * != CPU->thread
			 * Need to ensure that this happens only at high pil
			 * resume is called at high pil
			 * Only in resume_from_idle is the pil changed.
			 */
			if (ct->t_pri < 0) {
				kpreempt_cnts.kpc_idle++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			} else if (ct->t_flag & T_INTR_THREAD) {
				kpreempt_cnts.kpc_intr++;
				if (ct->t_pil == CLOCK_LEVEL)
					kpreempt_cnts.kpc_clock++;
			} else {
				kpreempt_cnts.kpc_blocked++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			}
			aston(CPU->cpu_dispthread);
			return;
		}
		if (ct->t_state != TS_ONPROC ||
		    ct->t_disp_queue != CPU->cpu_disp) {
			/* this thread will be calling swtch() shortly */
			kpreempt_cnts.kpc_notonproc++;
			if (CPU->cpu_thread != CPU->cpu_dispthread) {
				/* already in swtch(), force another */
				kpreempt_cnts.kpc_inswtch++;
				siron();
			}
			return;
		}
		if (getpil() >= DISP_LEVEL) {
			/*
			 * We can't preempt this thread if it is at
			 * a PIL >= DISP_LEVEL since it may be holding
			 * a spin lock (like sched_lock).
			 */
			siron();	/* check back later */
			kpreempt_cnts.kpc_prilevel++;
			return;
		}
		if (!interrupts_enabled()) {
			/*
			 * Can't preempt while running with ints disabled
			 */
			kpreempt_cnts.kpc_prilevel++;
			return;
		}
		if (asyncspl != KPREEMPT_SYNC)
			kpreempt_cnts.kpc_apreempt++;
		else
			kpreempt_cnts.kpc_spreempt++;

		ct->t_preempt++;
		preempt();
		ct->t_preempt--;
	} while (CPU->cpu_kprunrun);
}

/*
 * Print out debugging info.
 */
static void
showregs(uint_t type, struct regs *rp, caddr_t addr)
{
	int s;

	s = spl7();
	type &= ~USER;
	if (PTOU(curproc)->u_comm[0])
		printf("%s: ", PTOU(curproc)->u_comm);
	if (type < TRAP_TYPES)
		printf("#%s %s\n", trap_type_mnemonic[type], trap_type[type]);
	else
		switch (type) {
		case T_SYSCALL:
			printf("Syscall Trap:\n");
			break;
		case T_AST:
			printf("AST\n");
			break;
		default:
			printf("Bad Trap = %d\n", type);
			break;
		}
	if (type == T_PGFLT) {
		printf("Bad %s fault at addr=0x%lx\n",
		    USERMODE(rp->r_cs) ? "user": "kernel", (uintptr_t)addr);
	} else if (addr) {
		printf("addr=0x%lx\n", (uintptr_t)addr);
	}

	printf("pid=%d, pc=0x%lx, sp=0x%lx, eflags=0x%lx\n",
	    (ttoproc(curthread) && ttoproc(curthread)->p_pidp) ?
	    ttoproc(curthread)->p_pid : 0, rp->r_pc, rp->r_sp, rp->r_ps);

#if defined(__lint)
	/*
	 * this clause can be deleted when lint bug 4870403 is fixed
	 * (lint thinks that bit 32 is illegal in a %b format string)
	 */
	printf("cr0: %x  cr4: %b\n",
	    (uint_t)getcr0(), (uint_t)getcr4(), FMT_CR4);
#else
	printf("cr0: %b  cr4: %b\n",
	    (uint_t)getcr0(), FMT_CR0, (uint_t)getcr4(), FMT_CR4);
#endif	/* __lint */

	printf("cr2: %lx  ", getcr2());
#if !defined(__xpv)
	printf("cr3: %lx  ", getcr3());
#if defined(__amd64)
	printf("cr8: %lx\n", getcr8());
#endif
#endif
	printf("\n");

	dumpregs(rp);
	splx(s);
}

static void
dumpregs(struct regs *rp)
{
#if defined(__amd64)
	const char fmt[] = "\t%3s: %16lx %3s: %16lx %3s: %16lx\n";

	printf(fmt, "rdi", rp->r_rdi, "rsi", rp->r_rsi, "rdx", rp->r_rdx);
	printf(fmt, "rcx", rp->r_rcx, " r8", rp->r_r8, " r9", rp->r_r9);
	printf(fmt, "rax", rp->r_rax, "rbx", rp->r_rbx, "rbp", rp->r_rbp);
	printf(fmt, "r10", rp->r_r10, "r11", rp->r_r11, "r12", rp->r_r12);
	printf(fmt, "r13", rp->r_r13, "r14", rp->r_r14, "r15", rp->r_r15);

	printf(fmt, "fsb", rdmsr(MSR_AMD_FSBASE), "gsb", rdmsr(MSR_AMD_GSBASE),
	    " ds", rp->r_ds);
	printf(fmt, " es", rp->r_es, " fs", rp->r_fs, " gs", rp->r_gs);

	printf(fmt, "trp", rp->r_trapno, "err", rp->r_err, "rip", rp->r_rip);
	printf(fmt, " cs", rp->r_cs, "rfl", rp->r_rfl, "rsp", rp->r_rsp);

	printf("\t%3s: %16lx\n", " ss", rp->r_ss);

#elif defined(__i386)
	const char fmt[] = "\t%3s: %8lx %3s: %8lx %3s: %8lx %3s: %8lx\n";

	printf(fmt, " gs", rp->r_gs, " fs", rp->r_fs,
	    " es", rp->r_es, " ds", rp->r_ds);
	printf(fmt, "edi", rp->r_edi, "esi", rp->r_esi,
	    "ebp", rp->r_ebp, "esp", rp->r_esp);
	printf(fmt, "ebx", rp->r_ebx, "edx", rp->r_edx,
	    "ecx", rp->r_ecx, "eax", rp->r_eax);
	printf(fmt, "trp", rp->r_trapno, "err", rp->r_err,
	    "eip", rp->r_eip, " cs", rp->r_cs);
	printf("\t%3s: %8lx %3s: %8lx %3s: %8lx\n",
	    "efl", rp->r_efl, "usp", rp->r_uesp, " ss", rp->r_ss);

#endif	/* __i386 */
}

/*
 * Test to see if the instruction is iret on i386 or iretq on amd64.
 *
 * On the hypervisor we can only test for nopop_sys_rtt_syscall. If true
 * then we are in the context of hypervisor's failsafe handler because it
 * tried to iret and failed due to a bad selector. See xen_failsafe_callback.
 */
static int
instr_is_iret(caddr_t pc)
{

#if defined(__xpv)
	extern void nopop_sys_rtt_syscall(void);
	return ((pc == (caddr_t)nopop_sys_rtt_syscall) ? 1 : 0);

#else

#if defined(__amd64)
	static const uint8_t iret_insn[2] = { 0x48, 0xcf };	/* iretq */

#elif defined(__i386)
	static const uint8_t iret_insn[1] = { 0xcf };		/* iret */
#endif	/* __i386 */
	return (bcmp(pc, iret_insn, sizeof (iret_insn)) == 0);

#endif	/* __xpv */
}

#if defined(__i386)

/*
 * Test to see if the instruction is part of __SEGREGS_POP
 *
 * Note carefully the appallingly awful dependency between
 * the instruction sequence used in __SEGREGS_POP and these
 * instructions encoded here.
 */
static int
instr_is_segregs_pop(caddr_t pc)
{
	static const uint8_t movw_0_esp_gs[4] = { 0x8e, 0x6c, 0x24, 0x0 };
	static const uint8_t movw_4_esp_fs[4] = { 0x8e, 0x64, 0x24, 0x4 };
	static const uint8_t movw_8_esp_es[4] = { 0x8e, 0x44, 0x24, 0x8 };
	static const uint8_t movw_c_esp_ds[4] = { 0x8e, 0x5c, 0x24, 0xc };

	if (bcmp(pc, movw_0_esp_gs, sizeof (movw_0_esp_gs)) == 0 ||
	    bcmp(pc, movw_4_esp_fs, sizeof (movw_4_esp_fs)) == 0 ||
	    bcmp(pc, movw_8_esp_es, sizeof (movw_8_esp_es)) == 0 ||
	    bcmp(pc, movw_c_esp_ds, sizeof (movw_c_esp_ds)) == 0)
		return (1);

	return (0);
}

#endif	/* __i386 */

/*
 * Test to see if the instruction is part of _sys_rtt (or the KPTI trampolines
 * which are used by _sys_rtt).
 *
 * Again on the hypervisor if we try to IRET to user land with a bad code
 * or stack selector we will get vectored through xen_failsafe_callback.
 * In which case we assume we got here via _sys_rtt since we only allow
 * IRET to user land to take place in _sys_rtt.
 */
static int
instr_is_sys_rtt(caddr_t pc)
{
	extern void _sys_rtt(), _sys_rtt_end();

#if !defined(__xpv)
	extern void tr_sysc_ret_start(), tr_sysc_ret_end();
	extern void tr_intr_ret_start(), tr_intr_ret_end();

	if ((uintptr_t)pc >= (uintptr_t)tr_sysc_ret_start &&
	    (uintptr_t)pc <= (uintptr_t)tr_sysc_ret_end)
		return (1);

	if ((uintptr_t)pc >= (uintptr_t)tr_intr_ret_start &&
	    (uintptr_t)pc <= (uintptr_t)tr_intr_ret_end)
		return (1);
#endif

	if ((uintptr_t)pc < (uintptr_t)_sys_rtt ||
	    (uintptr_t)pc > (uintptr_t)_sys_rtt_end)
		return (0);

	return (1);
}

/*
 * Handle #gp faults in kernel mode.
 *
 * One legitimate way this can happen is if we attempt to update segment
 * registers to naughty values on the way out of the kernel.
 *
 * This can happen in a couple of ways: someone - either accidentally or
 * on purpose - creates (setcontext(2), lwp_create(2)) or modifies
 * (signal(2)) a ucontext that contains silly segment register values.
 * Or someone - either accidentally or on purpose - modifies the prgregset_t
 * of a subject process via /proc to contain silly segment register values.
 *
 * (The unfortunate part is that we can end up discovering the bad segment
 * register value in the middle of an 'iret' after we've popped most of the
 * stack.  So it becomes quite difficult to associate an accurate ucontext
 * with the lwp, because the act of taking the #gp trap overwrites most of
 * what we were going to send the lwp.)
 *
 * OTOH if it turns out that's -not- the problem, and we're -not- an lwp
 * trying to return to user mode and we get a #gp fault, then we need
 * to die() -- which will happen if we return non-zero from this routine.
 */
static int
kern_gpfault(struct regs *rp)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	struct regs tmpregs, *trp = NULL;
	caddr_t pc = (caddr_t)rp->r_pc;
	int v;
	uint32_t auditing = AU_AUDITING();

	/*
	 * if we're not an lwp, or in the case of running native the
	 * pc range is outside _sys_rtt, then we should immediately
	 * be die()ing horribly.
	 */
	if (lwp == NULL || !instr_is_sys_rtt(pc))
		return (1);

	/*
	 * So at least we're in the right part of the kernel.
	 *
	 * Disassemble the instruction at the faulting pc.
	 * Once we know what it is, we carefully reconstruct the stack
	 * based on the order in which the stack is deconstructed in
	 * _sys_rtt. Ew.
	 */
	if (instr_is_iret(pc)) {
		/*
		 * We took the #gp while trying to perform the IRET.
		 * This means that either %cs or %ss are bad.
		 * All we know for sure is that most of the general
		 * registers have been restored, including the
		 * segment registers, and all we have left on the
		 * topmost part of the lwp's stack are the
		 * registers that the iretq was unable to consume.
		 *
		 * All the rest of the state was crushed by the #gp
		 * which pushed -its- registers atop our old save area
		 * (because we had to decrement the stack pointer, sigh) so
		 * all that we can try and do is to reconstruct the
		 * crushed frame from the #gp trap frame itself.
		 */
		trp = &tmpregs;
		trp->r_ss = lwptoregs(lwp)->r_ss;
		trp->r_sp = lwptoregs(lwp)->r_sp;
		trp->r_ps = lwptoregs(lwp)->r_ps;
		trp->r_cs = lwptoregs(lwp)->r_cs;
		trp->r_pc = lwptoregs(lwp)->r_pc;
		bcopy(rp, trp, offsetof(struct regs, r_pc));

		/*
		 * Validate simple math
		 */
		ASSERT(trp->r_pc == lwptoregs(lwp)->r_pc);
		ASSERT(trp->r_err == rp->r_err);



	}

#if defined(__amd64)
	if (trp == NULL && lwp->lwp_pcb.pcb_rupdate != 0) {

		/*
		 * This is the common case -- we're trying to load
		 * a bad segment register value in the only section
		 * of kernel code that ever loads segment registers.
		 *
		 * We don't need to do anything at this point because
		 * the pcb contains all the pending segment register
		 * state, and the regs are still intact because we
		 * didn't adjust the stack pointer yet.  Given the fidelity
		 * of all this, we could conceivably send a signal
		 * to the lwp, rather than core-ing.
		 */
		trp = lwptoregs(lwp);
		ASSERT((caddr_t)trp == (caddr_t)rp->r_sp);
	}

#elif defined(__i386)

	if (trp == NULL && instr_is_segregs_pop(pc))
		trp = lwptoregs(lwp);

#endif	/* __i386 */

	if (trp == NULL)
		return (1);

	/*
	 * If we get to here, we're reasonably confident that we've
	 * correctly decoded what happened on the way out of the kernel.
	 * Rewrite the lwp's registers so that we can create a core dump
	 * the (at least vaguely) represents the mcontext we were
	 * being asked to restore when things went so terribly wrong.
	 */

	/*
	 * Make sure that we have a meaningful %trapno and %err.
	 */
	trp->r_trapno = rp->r_trapno;
	trp->r_err = rp->r_err;

	if ((caddr_t)trp != (caddr_t)lwptoregs(lwp))
		bcopy(trp, lwptoregs(lwp), sizeof (*trp));


	mutex_enter(&p->p_lock);
	lwp->lwp_cursig = SIGSEGV;
	mutex_exit(&p->p_lock);

	/*
	 * Terminate all LWPs but don't discard them.  If another lwp beat
	 * us to the punch by calling exit(), evaporate now.
	 */
	proc_is_exiting(p);
	if (exitlwps(1) != 0) {
		mutex_enter(&p->p_lock);
		lwp_exit();
	}

	if (auditing)		/* audit core dump */
		audit_core_start(SIGSEGV);
	v = core(SIGSEGV, B_FALSE);
	if (auditing)		/* audit core dump */
		audit_core_finish(v ? CLD_KILLED : CLD_DUMPED);
	exit(v ? CLD_KILLED : CLD_DUMPED, SIGSEGV);
	return (0);
}

/*
 * dump_tss() - Display the TSS structure
 */

#if !defined(__xpv)
#if defined(__amd64)

static void
dump_tss(void)
{
	const char tss_fmt[] = "tss.%s:\t0x%p\n";  /* Format string */
	tss_t *tss = CPU->cpu_tss;

	printf(tss_fmt, "tss_rsp0", (void *)tss->tss_rsp0);
	printf(tss_fmt, "tss_rsp1", (void *)tss->tss_rsp1);
	printf(tss_fmt, "tss_rsp2", (void *)tss->tss_rsp2);

	printf(tss_fmt, "tss_ist1", (void *)tss->tss_ist1);
	printf(tss_fmt, "tss_ist2", (void *)tss->tss_ist2);
	printf(tss_fmt, "tss_ist3", (void *)tss->tss_ist3);
	printf(tss_fmt, "tss_ist4", (void *)tss->tss_ist4);
	printf(tss_fmt, "tss_ist5", (void *)tss->tss_ist5);
	printf(tss_fmt, "tss_ist6", (void *)tss->tss_ist6);
	printf(tss_fmt, "tss_ist7", (void *)tss->tss_ist7);
}

#elif defined(__i386)

static void
dump_tss(void)
{
	const char tss_fmt[] = "tss.%s:\t0x%p\n";  /* Format string */
	tss_t *tss = CPU->cpu_tss;

	printf(tss_fmt, "tss_link", (void *)(uintptr_t)tss->tss_link);
	printf(tss_fmt, "tss_esp0", (void *)(uintptr_t)tss->tss_esp0);
	printf(tss_fmt, "tss_ss0", (void *)(uintptr_t)tss->tss_ss0);
	printf(tss_fmt, "tss_esp1", (void *)(uintptr_t)tss->tss_esp1);
	printf(tss_fmt, "tss_ss1", (void *)(uintptr_t)tss->tss_ss1);
	printf(tss_fmt, "tss_esp2", (void *)(uintptr_t)tss->tss_esp2);
	printf(tss_fmt, "tss_ss2", (void *)(uintptr_t)tss->tss_ss2);
	printf(tss_fmt, "tss_cr3", (void *)(uintptr_t)tss->tss_cr3);
	printf(tss_fmt, "tss_eip", (void *)(uintptr_t)tss->tss_eip);
	printf(tss_fmt, "tss_eflags", (void *)(uintptr_t)tss->tss_eflags);
	printf(tss_fmt, "tss_eax", (void *)(uintptr_t)tss->tss_eax);
	printf(tss_fmt, "tss_ebx", (void *)(uintptr_t)tss->tss_ebx);
	printf(tss_fmt, "tss_ecx", (void *)(uintptr_t)tss->tss_ecx);
	printf(tss_fmt, "tss_edx", (void *)(uintptr_t)tss->tss_edx);
	printf(tss_fmt, "tss_esp", (void *)(uintptr_t)tss->tss_esp);
}

#endif	/* __amd64 */
#endif	/* !__xpv */

#if defined(TRAPTRACE)

int ttrace_nrec = 10;		/* number of records to dump out */
int ttrace_dump_nregs = 0;	/* dump out this many records with regs too */

/*
 * Dump out the last ttrace_nrec traptrace records on each CPU
 */
static void
dump_ttrace(void)
{
	trap_trace_ctl_t *ttc;
	trap_trace_rec_t *rec;
	uintptr_t current;
	int i, j, k;
	int n = NCPU;
#if defined(__amd64)
	const char banner[] =
	    "CPU          ADDRESS    TIMESTAMP TYPE  VC HANDLER          PC\n";
	/* Define format for the CPU, ADDRESS, and TIMESTAMP fields */
	const char fmt1[] = "%3d %016lx %12llx";
	char data1[34];	/* length of string formatted by fmt1 + 1 */
#elif defined(__i386)
	const char banner[] =
	    "CPU  ADDRESS     TIMESTAMP TYPE  VC HANDLER          PC\n";
	/* Define format for the CPU, ADDRESS, and TIMESTAMP fields */
	const char fmt1[] = "%3d %08lx %12llx";
	char data1[26];	/* length of string formatted by fmt1 + 1 */
#endif
	/* Define format for the TYPE and VC fields */
	const char fmt2[] = "%4s %3x";
	char data2[9];	/* length of string formatted by fmt2 + 1 */
	/*
	 * Define format for the HANDLER field. Width is arbitrary, but should
	 * be enough for common handler's names, and leave enough space for
	 * the PC field, especially when we are in kmdb.
	 */
	const char fmt3h[] = "#%-15s";
	const char fmt3p[] = "%-16p";
	const char fmt3s[] = "%-16s";
	char data3[17];	/* length of string formatted by fmt3* + 1 */

	if (ttrace_nrec == 0)
		return;

	printf("\n");
	printf(banner);

	for (i = 0; i < n; i++) {
		ttc = &trap_trace_ctl[i];
		if (ttc->ttc_first == NULL)
			continue;

		current = ttc->ttc_next - sizeof (trap_trace_rec_t);
		for (j = 0; j < ttrace_nrec; j++) {
			struct sysent	*sys;
			struct autovec	*vec;
			extern struct av_head autovect[];
			int type;
			ulong_t	off;
			char *sym, *stype;

			if (current < ttc->ttc_first)
				current =
				    ttc->ttc_limit - sizeof (trap_trace_rec_t);

			if (current == NULL)
				continue;

			rec = (trap_trace_rec_t *)current;

			if (rec->ttr_stamp == 0)
				break;

			(void) snprintf(data1, sizeof (data1), fmt1, i,
			    (uintptr_t)rec, rec->ttr_stamp);

			switch (rec->ttr_marker) {
			case TT_SYSCALL:
			case TT_SYSENTER:
			case TT_SYSC:
			case TT_SYSC64:
				sys = &sysent32[rec->ttr_sysnum];
				switch (rec->ttr_marker) {
				case TT_SYSC64:
					sys = &sysent[rec->ttr_sysnum];
					/* FALLTHROUGH */
				case TT_SYSC:
					stype = "sysc";	/* syscall */
					break;
				case TT_SYSCALL:
					stype = "lcal";	/* lcall */
					break;
				case TT_SYSENTER:
					stype = "syse";	/* sysenter */
					break;
				default:
					break;
				}
				(void) snprintf(data2, sizeof (data2), fmt2,
				    stype, rec->ttr_sysnum);
				if (sys != NULL) {
					sym = kobj_getsymname(
					    (uintptr_t)sys->sy_callc,
					    &off);
					if (sym != NULL) {
						(void) snprintf(data3,
						    sizeof (data3), fmt3s, sym);
					} else {
						(void) snprintf(data3,
						    sizeof (data3), fmt3p,
						    sys->sy_callc);
					}
				} else {
					(void) snprintf(data3, sizeof (data3),
					    fmt3s, "unknown");
				}
				break;

			case TT_INTERRUPT:
				(void) snprintf(data2, sizeof (data2), fmt2,
				    "intr", rec->ttr_vector);
				if (get_intr_handler != NULL)
					vec = (struct autovec *)
					    (*get_intr_handler)
					    (rec->ttr_cpuid, rec->ttr_vector);
				else
					vec =
					    autovect[rec->ttr_vector].avh_link;

				if (vec != NULL) {
					sym = kobj_getsymname(
					    (uintptr_t)vec->av_vector, &off);
					if (sym != NULL) {
						(void) snprintf(data3,
						    sizeof (data3), fmt3s, sym);
					} else {
						(void) snprintf(data3,
						    sizeof (data3), fmt3p,
						    vec->av_vector);
					}
				} else {
					(void) snprintf(data3, sizeof (data3),
					    fmt3s, "unknown");
				}
				break;

			case TT_TRAP:
			case TT_EVENT:
				type = rec->ttr_regs.r_trapno;
				(void) snprintf(data2, sizeof (data2), fmt2,
				    "trap", type);
				if (type < TRAP_TYPES) {
					(void) snprintf(data3, sizeof (data3),
					    fmt3h, trap_type_mnemonic[type]);
				} else {
					switch (type) {
					case T_AST:
						(void) snprintf(data3,
						    sizeof (data3), fmt3s,
						    "ast");
						break;
					default:
						(void) snprintf(data3,
						    sizeof (data3), fmt3s, "");
						break;
					}
				}
				break;

			default:
				break;
			}

			sym = kobj_getsymname(rec->ttr_regs.r_pc, &off);
			if (sym != NULL) {
				printf("%s %s %s %s+%lx\n", data1, data2, data3,
				    sym, off);
			} else {
				printf("%s %s %s %lx\n", data1, data2, data3,
				    rec->ttr_regs.r_pc);
			}

			if (ttrace_dump_nregs-- > 0) {
				int s;

				if (rec->ttr_marker == TT_INTERRUPT)
					printf(
					    "\t\tipl %x spl %x pri %x\n",
					    rec->ttr_ipl,
					    rec->ttr_spl,
					    rec->ttr_pri);

				dumpregs(&rec->ttr_regs);

				printf("\t%3s: %p\n\n", " ct",
				    (void *)rec->ttr_curthread);

				/*
				 * print out the pc stack that we recorded
				 * at trap time (if any)
				 */
				for (s = 0; s < rec->ttr_sdepth; s++) {
					uintptr_t fullpc;

					if (s >= TTR_STACK_DEPTH) {
						printf("ttr_sdepth corrupt\n");
						break;
					}

					fullpc = (uintptr_t)rec->ttr_stack[s];

					sym = kobj_getsymname(fullpc, &off);
					if (sym != NULL)
						printf("-> %s+0x%lx()\n",
						    sym, off);
					else
						printf("-> 0x%lx()\n", fullpc);
				}
				printf("\n");
			}
			current -= sizeof (trap_trace_rec_t);
		}
	}
}

#endif	/* TRAPTRACE */

void
panic_showtrap(struct panic_trap_info *tip)
{
	showregs(tip->trap_type, tip->trap_regs, tip->trap_addr);

#if defined(TRAPTRACE)
	dump_ttrace();
#endif

#if !defined(__xpv)
	if (tip->trap_type == T_DBLFLT)
		dump_tss();
#endif
}

void
panic_savetrap(panic_data_t *pdp, struct panic_trap_info *tip)
{
	panic_saveregs(pdp, tip->trap_regs);
}

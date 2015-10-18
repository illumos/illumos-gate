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
 */

/*
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 */

#include <sys/mmu.h>
#include <sys/systm.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/vtrace.h>
#include <sys/prsystm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/tnf.h>
#include <sys/tnf_probe.h>
#include <sys/simulate.h>
#include <sys/ftrace.h>
#include <sys/ontrap.h>
#include <sys/kcpc.h>
#include <sys/kobj.h>
#include <sys/procfs.h>
#include <sys/sun4asi.h>
#include <sys/sdt.h>
#include <sys/fpras.h>
#include <sys/contract/process_impl.h>

#ifdef  TRAPTRACE
#include <sys/traptrace.h>
#endif

int tudebug = 0;
static int tudebugbpt = 0;
static int tudebugfpe = 0;

static int alignfaults = 0;

#if defined(TRAPDEBUG) || defined(lint)
static int lodebug = 0;
#else
#define	lodebug	0
#endif /* defined(TRAPDEBUG) || defined(lint) */


int vis1_partial_support(struct regs *rp, k_siginfo_t *siginfo, uint_t *fault);
#pragma weak vis1_partial_support

void showregs(unsigned, struct regs *, caddr_t, uint_t);
#pragma weak showregs

void trap_async_hwerr(void);
#pragma weak trap_async_hwerr

void trap_async_berr_bto(int, struct regs *);
#pragma weak trap_async_berr_bto

static enum seg_rw get_accesstype(struct regs *);
static int nfload(struct regs *, int *);
static int swap_nc(struct regs *, int);
static int ldstub_nc(struct regs *, int);
void	trap_cleanup(struct regs *, uint_t, k_siginfo_t *, int);
void	trap_rtt(void);

static int
die(unsigned type, struct regs *rp, caddr_t addr, uint_t mmu_fsr)
{
	struct panic_trap_info ti;

#ifdef TRAPTRACE
	TRAPTRACE_FREEZE;
#endif

	ti.trap_regs = rp;
	ti.trap_type = type;
	ti.trap_addr = addr;
	ti.trap_mmu_fsr = mmu_fsr;

	curthread->t_panic_trap = &ti;

	if (type == T_DATA_MMU_MISS && addr < (caddr_t)KERNELBASE) {
		panic("BAD TRAP: type=%x rp=%p addr=%p mmu_fsr=%x "
		    "occurred in module \"%s\" due to %s",
		    type, (void *)rp, (void *)addr, mmu_fsr,
		    mod_containing_pc((caddr_t)rp->r_pc),
		    addr < (caddr_t)PAGESIZE ?
		    "a NULL pointer dereference" :
		    "an illegal access to a user address");
	} else {
		panic("BAD TRAP: type=%x rp=%p addr=%p mmu_fsr=%x",
		    type, (void *)rp, (void *)addr, mmu_fsr);
	}

	return (0);	/* avoid optimization of restore in call's delay slot */
}

#if defined(SF_ERRATA_23) || defined(SF_ERRATA_30) /* call ... illegal-insn */
int	ill_calls;
#endif

/*
 * Currently, the only PREFETCH/PREFETCHA instructions which cause traps
 * are the "strong" prefetches (fcn=20-23).  But we check for all flavors of
 * PREFETCH, in case some future variant also causes a DATA_MMU_MISS.
 */
#define	IS_PREFETCH(i)	(((i) & 0xc1780000) == 0xc1680000)

#define	IS_FLUSH(i)	(((i) & 0xc1f80000) == 0x81d80000)
#define	IS_SWAP(i)	(((i) & 0xc1f80000) == 0xc0780000)
#define	IS_LDSTUB(i)	(((i) & 0xc1f80000) == 0xc0680000)
#define	IS_FLOAT(i)	(((i) & 0x1000000) != 0)
#define	IS_STORE(i)	(((i) >> 21) & 1)

/*
 * Called from the trap handler when a processor trap occurs.
 */
/*VARARGS2*/
void
trap(struct regs *rp, caddr_t addr, uint32_t type, uint32_t mmu_fsr)
{
	proc_t *p = ttoproc(curthread);
	klwp_id_t lwp = ttolwp(curthread);
	struct machpcb *mpcb = NULL;
	k_siginfo_t siginfo;
	uint_t op3, fault = 0;
	int stepped = 0;
	greg_t oldpc;
	int mstate;
	char *badaddr;
	faultcode_t res;
	enum fault_type fault_type;
	enum seg_rw rw;
	uintptr_t lofault;
	label_t *onfault;
	int instr;
	int iskernel;
	int watchcode;
	int watchpage;
	extern faultcode_t pagefault(caddr_t, enum fault_type,
	    enum seg_rw, int);
#ifdef sun4v
	extern boolean_t tick_stick_emulation_active;
#endif	/* sun4v */

	CPU_STATS_ADDQ(CPU, sys, trap, 1);

#ifdef SF_ERRATA_23 /* call causes illegal-insn */
	ASSERT((curthread->t_schedflag & TS_DONT_SWAP) ||
	    (type == T_UNIMP_INSTR));
#else
	ASSERT(curthread->t_schedflag & TS_DONT_SWAP);
#endif /* SF_ERRATA_23 */

	if (USERMODE(rp->r_tstate) || (type & T_USER)) {
		/*
		 * Set lwp_state before trying to acquire any
		 * adaptive lock
		 */
		ASSERT(lwp != NULL);
		lwp->lwp_state = LWP_SYS;
		/*
		 * Set up the current cred to use during this trap. u_cred
		 * no longer exists.  t_cred is used instead.
		 * The current process credential applies to the thread for
		 * the entire trap.  If trapping from the kernel, this
		 * should already be set up.
		 */
		if (curthread->t_cred != p->p_cred) {
			cred_t *oldcred = curthread->t_cred;
			/*
			 * DTrace accesses t_cred in probe context.  t_cred
			 * must always be either NULL, or point to a valid,
			 * allocated cred structure.
			 */
			curthread->t_cred = crgetcred();
			crfree(oldcred);
		}
		type |= T_USER;
		ASSERT((type == (T_SYS_RTT_PAGE | T_USER)) ||
		    (type == (T_SYS_RTT_ALIGN | T_USER)) ||
		    lwp->lwp_regs == rp);
		mpcb = lwptompcb(lwp);
		switch (type) {
		case T_WIN_OVERFLOW + T_USER:
		case T_WIN_UNDERFLOW + T_USER:
		case T_SYS_RTT_PAGE + T_USER:
		case T_DATA_MMU_MISS + T_USER:
			mstate = LMS_DFAULT;
			break;
		case T_INSTR_MMU_MISS + T_USER:
			mstate = LMS_TFAULT;
			break;
		default:
			mstate = LMS_TRAP;
			break;
		}
		/* Kernel probe */
		TNF_PROBE_1(thread_state, "thread", /* CSTYLED */,
		    tnf_microstate, state, (char)mstate);
		mstate = new_mstate(curthread, mstate);
		siginfo.si_signo = 0;
		stepped =
		    lwp->lwp_pcb.pcb_step != STEP_NONE &&
		    ((oldpc = rp->r_pc), prundostep()) &&
		    mmu_btop((uintptr_t)addr) == mmu_btop((uintptr_t)oldpc);
		/* this assignment must not precede call to prundostep() */
		oldpc = rp->r_pc;
	}

	TRACE_1(TR_FAC_TRAP, TR_C_TRAP_HANDLER_ENTER,
	    "C_trap_handler_enter:type %x", type);

#ifdef	F_DEFERRED
	/*
	 * Take any pending floating point exceptions now.
	 * If the floating point unit has an exception to handle,
	 * just return to user-level to let the signal handler run.
	 * The instruction that got us to trap() will be reexecuted on
	 * return from the signal handler and we will trap to here again.
	 * This is necessary to disambiguate simultaneous traps which
	 * happen when a floating-point exception is pending and a
	 * machine fault is incurred.
	 */
	if (type & USER) {
		/*
		 * FP_TRAPPED is set only by sendsig() when it copies
		 * out the floating-point queue for the signal handler.
		 * It is set there so we can test it here and in syscall().
		 */
		mpcb->mpcb_flags &= ~FP_TRAPPED;
		syncfpu();
		if (mpcb->mpcb_flags & FP_TRAPPED) {
			/*
			 * trap() has have been called recursively and may
			 * have stopped the process, so do single step
			 * support for /proc.
			 */
			mpcb->mpcb_flags &= ~FP_TRAPPED;
			goto out;
		}
	}
#endif
	switch (type) {
		case T_DATA_MMU_MISS:
		case T_INSTR_MMU_MISS + T_USER:
		case T_DATA_MMU_MISS + T_USER:
		case T_DATA_PROT + T_USER:
		case T_AST + T_USER:
		case T_SYS_RTT_PAGE + T_USER:
		case T_FLUSH_PCB + T_USER:
		case T_FLUSHW + T_USER:
			break;

		default:
			FTRACE_3("trap(): type=0x%lx, regs=0x%lx, addr=0x%lx",
			    (ulong_t)type, (ulong_t)rp, (ulong_t)addr);
			break;
	}

	switch (type) {

	default:
		/*
		 * Check for user software trap.
		 */
		if (type & T_USER) {
			if (tudebug)
				showregs(type, rp, (caddr_t)0, 0);
			if ((type & ~T_USER) >= T_SOFTWARE_TRAP) {
				bzero(&siginfo, sizeof (siginfo));
				siginfo.si_signo = SIGILL;
				siginfo.si_code  = ILL_ILLTRP;
				siginfo.si_addr  = (caddr_t)rp->r_pc;
				siginfo.si_trapno = type &~ T_USER;
				fault = FLTILL;
				break;
			}
		}
		addr = (caddr_t)rp->r_pc;
		(void) die(type, rp, addr, 0);
		/*NOTREACHED*/

	case T_ALIGNMENT:	/* supv alignment error */
		if (nfload(rp, NULL))
			goto cleanup;

		if (curthread->t_lofault) {
			if (lodebug) {
				showregs(type, rp, addr, 0);
				traceback((caddr_t)rp->r_sp);
			}
			rp->r_g1 = EFAULT;
			rp->r_pc = curthread->t_lofault;
			rp->r_npc = rp->r_pc + 4;
			goto cleanup;
		}
		(void) die(type, rp, addr, 0);
		/*NOTREACHED*/

	case T_INSTR_EXCEPTION:		/* sys instruction access exception */
		addr = (caddr_t)rp->r_pc;
		(void) die(type, rp, addr, mmu_fsr);
		/*NOTREACHED*/

	case T_INSTR_MMU_MISS:		/* sys instruction mmu miss */
		addr = (caddr_t)rp->r_pc;
		(void) die(type, rp, addr, 0);
		/*NOTREACHED*/

	case T_DATA_EXCEPTION:		/* system data access exception */
		switch (X_FAULT_TYPE(mmu_fsr)) {
		case FT_RANGE:
			/*
			 * This happens when we attempt to dereference an
			 * address in the address hole.  If t_ontrap is set,
			 * then break and fall through to T_DATA_MMU_MISS /
			 * T_DATA_PROT case below.  If lofault is set, then
			 * honour it (perhaps the user gave us a bogus
			 * address in the hole to copyin from or copyout to?)
			 */

			if (curthread->t_ontrap != NULL)
				break;

			addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);
			if (curthread->t_lofault) {
				if (lodebug) {
					showregs(type, rp, addr, 0);
					traceback((caddr_t)rp->r_sp);
				}
				rp->r_g1 = EFAULT;
				rp->r_pc = curthread->t_lofault;
				rp->r_npc = rp->r_pc + 4;
				goto cleanup;
			}
			(void) die(type, rp, addr, mmu_fsr);
			/*NOTREACHED*/

		case FT_PRIV:
			/*
			 * This can happen if we access ASI_USER from a kernel
			 * thread.  To support pxfs, we need to honor lofault if
			 * we're doing a copyin/copyout from a kernel thread.
			 */

			if (nfload(rp, NULL))
				goto cleanup;
			addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);
			if (curthread->t_lofault) {
				if (lodebug) {
					showregs(type, rp, addr, 0);
					traceback((caddr_t)rp->r_sp);
				}
				rp->r_g1 = EFAULT;
				rp->r_pc = curthread->t_lofault;
				rp->r_npc = rp->r_pc + 4;
				goto cleanup;
			}
			(void) die(type, rp, addr, mmu_fsr);
			/*NOTREACHED*/

		default:
			if (nfload(rp, NULL))
				goto cleanup;
			addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);
			(void) die(type, rp, addr, mmu_fsr);
			/*NOTREACHED*/

		case FT_NFO:
			break;
		}
		/* fall into ... */

	case T_DATA_MMU_MISS:		/* system data mmu miss */
	case T_DATA_PROT:		/* system data protection fault */
		if (nfload(rp, &instr))
			goto cleanup;

		/*
		 * If we're under on_trap() protection (see <sys/ontrap.h>),
		 * set ot_trap and return from the trap to the trampoline.
		 */
		if (curthread->t_ontrap != NULL) {
			on_trap_data_t *otp = curthread->t_ontrap;

			TRACE_0(TR_FAC_TRAP, TR_C_TRAP_HANDLER_EXIT,
			    "C_trap_handler_exit");
			TRACE_0(TR_FAC_TRAP, TR_TRAP_END, "trap_end");

			if (otp->ot_prot & OT_DATA_ACCESS) {
				otp->ot_trap |= OT_DATA_ACCESS;
				rp->r_pc = otp->ot_trampoline;
				rp->r_npc = rp->r_pc + 4;
				goto cleanup;
			}
		}
		lofault = curthread->t_lofault;
		onfault = curthread->t_onfault;
		curthread->t_lofault = 0;

		mstate = new_mstate(curthread, LMS_KFAULT);

		switch (type) {
		case T_DATA_PROT:
			fault_type = F_PROT;
			rw = S_WRITE;
			break;
		case T_INSTR_MMU_MISS:
			fault_type = F_INVAL;
			rw = S_EXEC;
			break;
		case T_DATA_MMU_MISS:
		case T_DATA_EXCEPTION:
			/*
			 * The hardware doesn't update the sfsr on mmu
			 * misses so it is not easy to find out whether
			 * the access was a read or a write so we need
			 * to decode the actual instruction.
			 */
			fault_type = F_INVAL;
			rw = get_accesstype(rp);
			break;
		default:
			cmn_err(CE_PANIC, "trap: unknown type %x", type);
			break;
		}
		/*
		 * We determine if access was done to kernel or user
		 * address space.  The addr passed into trap is really the
		 * tag access register.
		 */
		iskernel = (((uintptr_t)addr & TAGACC_CTX_MASK) == KCONTEXT);
		addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);

		res = pagefault(addr, fault_type, rw, iskernel);
		if (!iskernel && res == FC_NOMAP &&
		    addr < p->p_usrstack && grow(addr))
			res = 0;

		(void) new_mstate(curthread, mstate);

		/*
		 * Restore lofault and onfault.  If we resolved the fault, exit.
		 * If we didn't and lofault wasn't set, die.
		 */
		curthread->t_lofault = lofault;
		curthread->t_onfault = onfault;

		if (res == 0)
			goto cleanup;

		if (IS_PREFETCH(instr)) {
			/* skip prefetch instructions in kernel-land */
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
			goto cleanup;
		}

		if ((lofault == 0 || lodebug) &&
		    (calc_memaddr(rp, &badaddr) == SIMU_SUCCESS))
			addr = badaddr;
		if (lofault == 0)
			(void) die(type, rp, addr, 0);
		/*
		 * Cannot resolve fault.  Return to lofault.
		 */
		if (lodebug) {
			showregs(type, rp, addr, 0);
			traceback((caddr_t)rp->r_sp);
		}
		if (FC_CODE(res) == FC_OBJERR)
			res = FC_ERRNO(res);
		else
			res = EFAULT;
		rp->r_g1 = res;
		rp->r_pc = curthread->t_lofault;
		rp->r_npc = curthread->t_lofault + 4;
		goto cleanup;

	case T_INSTR_EXCEPTION + T_USER: /* user insn access exception */
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_addr = (caddr_t)rp->r_pc;
		siginfo.si_signo = SIGSEGV;
		siginfo.si_code = X_FAULT_TYPE(mmu_fsr) == FT_PRIV ?
		    SEGV_ACCERR : SEGV_MAPERR;
		fault = FLTBOUNDS;
		break;

	case T_WIN_OVERFLOW + T_USER:	/* window overflow in ??? */
	case T_WIN_UNDERFLOW + T_USER:	/* window underflow in ??? */
	case T_SYS_RTT_PAGE + T_USER:	/* window underflow in user_rtt */
	case T_INSTR_MMU_MISS + T_USER:	/* user instruction mmu miss */
	case T_DATA_MMU_MISS + T_USER:	/* user data mmu miss */
	case T_DATA_PROT + T_USER:	/* user data protection fault */
		switch (type) {
		case T_INSTR_MMU_MISS + T_USER:
			addr = (caddr_t)rp->r_pc;
			fault_type = F_INVAL;
			rw = S_EXEC;
			break;

		case T_DATA_MMU_MISS + T_USER:
			addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);
			fault_type = F_INVAL;
			/*
			 * The hardware doesn't update the sfsr on mmu misses
			 * so it is not easy to find out whether the access
			 * was a read or a write so we need to decode the
			 * actual instruction.  XXX BUGLY HW
			 */
			rw = get_accesstype(rp);
			break;

		case T_DATA_PROT + T_USER:
			addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);
			fault_type = F_PROT;
			rw = S_WRITE;
			break;

		case T_WIN_OVERFLOW + T_USER:
			addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);
			fault_type = F_INVAL;
			rw = S_WRITE;
			break;

		case T_WIN_UNDERFLOW + T_USER:
		case T_SYS_RTT_PAGE + T_USER:
			addr = (caddr_t)((uintptr_t)addr & TAGACC_VADDR_MASK);
			fault_type = F_INVAL;
			rw = S_READ;
			break;

		default:
			cmn_err(CE_PANIC, "trap: unknown type %x", type);
			break;
		}

		/*
		 * If we are single stepping do not call pagefault
		 */
		if (stepped) {
			res = FC_NOMAP;
		} else {
			caddr_t vaddr = addr;
			size_t sz;
			int ta;

			ASSERT(!(curthread->t_flag & T_WATCHPT));
			watchpage = (pr_watch_active(p) &&
			    type != T_WIN_OVERFLOW + T_USER &&
			    type != T_WIN_UNDERFLOW + T_USER &&
			    type != T_SYS_RTT_PAGE + T_USER &&
			    pr_is_watchpage(addr, rw));

			if (!watchpage ||
			    (sz = instr_size(rp, &vaddr, rw)) <= 0)
				/* EMPTY */;
			else if ((watchcode = pr_is_watchpoint(&vaddr, &ta,
			    sz, NULL, rw)) != 0) {
				if (ta) {
					do_watch_step(vaddr, sz, rw,
					    watchcode, rp->r_pc);
					fault_type = F_INVAL;
				} else {
					bzero(&siginfo,	sizeof (siginfo));
					siginfo.si_signo = SIGTRAP;
					siginfo.si_code = watchcode;
					siginfo.si_addr = vaddr;
					siginfo.si_trapafter = 0;
					siginfo.si_pc = (caddr_t)rp->r_pc;
					fault = FLTWATCH;
					break;
				}
			} else {
				if (rw != S_EXEC &&
				    pr_watch_emul(rp, vaddr, rw))
					goto out;
				do_watch_step(vaddr, sz, rw, 0, 0);
				fault_type = F_INVAL;
			}

			if (pr_watch_active(p) &&
			    (type == T_WIN_OVERFLOW + T_USER ||
			    type == T_WIN_UNDERFLOW + T_USER ||
			    type == T_SYS_RTT_PAGE + T_USER)) {
				int dotwo = (type == T_WIN_UNDERFLOW + T_USER);
				if (copy_return_window(dotwo))
					goto out;
				fault_type = F_INVAL;
			}

			res = pagefault(addr, fault_type, rw, 0);

			/*
			 * If pagefault succeed, ok.
			 * Otherwise grow the stack automatically.
			 */
			if (res == 0 ||
			    (res == FC_NOMAP &&
			    type != T_INSTR_MMU_MISS + T_USER &&
			    addr < p->p_usrstack &&
			    grow(addr))) {
				int ismem = prismember(&p->p_fltmask, FLTPAGE);

				/*
				 * instr_size() is used to get the exact
				 * address of the fault, instead of the
				 * page of the fault. Unfortunately it is
				 * very slow, and this is an important
				 * code path. Don't call it unless
				 * correctness is needed. ie. if FLTPAGE
				 * is set, or we're profiling.
				 */

				if (curthread->t_rprof != NULL || ismem)
					(void) instr_size(rp, &addr, rw);

				lwp->lwp_lastfault = FLTPAGE;
				lwp->lwp_lastfaddr = addr;

				if (ismem) {
					bzero(&siginfo, sizeof (siginfo));
					siginfo.si_addr = addr;
					(void) stop_on_fault(FLTPAGE, &siginfo);
				}
				goto out;
			}

			if (type != (T_INSTR_MMU_MISS + T_USER)) {
				/*
				 * check for non-faulting loads, also
				 * fetch the instruction to check for
				 * flush
				 */
				if (nfload(rp, &instr))
					goto out;

				/* skip userland prefetch instructions */
				if (IS_PREFETCH(instr)) {
					rp->r_pc = rp->r_npc;
					rp->r_npc += 4;
					goto out;
					/*NOTREACHED*/
				}

				/*
				 * check if the instruction was a
				 * flush.  ABI allows users to specify
				 * an illegal address on the flush
				 * instruction so we simply return in
				 * this case.
				 *
				 * NB: the hardware should set a bit
				 * indicating this trap was caused by
				 * a flush instruction.  Instruction
				 * decoding is bugly!
				 */
				if (IS_FLUSH(instr)) {
					/* skip the flush instruction */
					rp->r_pc = rp->r_npc;
					rp->r_npc += 4;
					goto out;
					/*NOTREACHED*/
				}
			} else if (res == FC_PROT) {
				report_stack_exec(p, addr);
			}

			if (tudebug)
				showregs(type, rp, addr, 0);
		}

		/*
		 * In the case where both pagefault and grow fail,
		 * set the code to the value provided by pagefault.
		 */
		(void) instr_size(rp, &addr, rw);
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_addr = addr;
		if (FC_CODE(res) == FC_OBJERR) {
			siginfo.si_errno = FC_ERRNO(res);
			if (siginfo.si_errno != EINTR) {
				siginfo.si_signo = SIGBUS;
				siginfo.si_code = BUS_OBJERR;
				fault = FLTACCESS;
			}
		} else { /* FC_NOMAP || FC_PROT */
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code = (res == FC_NOMAP) ?
			    SEGV_MAPERR : SEGV_ACCERR;
			fault = FLTBOUNDS;
		}
		/*
		 * If this is the culmination of a single-step,
		 * reset the addr, code, signal and fault to
		 * indicate a hardware trace trap.
		 */
		if (stepped) {
			pcb_t *pcb = &lwp->lwp_pcb;

			siginfo.si_signo = 0;
			fault = 0;
			if (pcb->pcb_step == STEP_WASACTIVE) {
				pcb->pcb_step = STEP_NONE;
				pcb->pcb_tracepc = NULL;
				oldpc = rp->r_pc - 4;
			}
			/*
			 * If both NORMAL_STEP and WATCH_STEP are in
			 * effect, give precedence to WATCH_STEP.
			 * One or the other must be set at this point.
			 */
			ASSERT(pcb->pcb_flags & (NORMAL_STEP|WATCH_STEP));
			if ((fault = undo_watch_step(&siginfo)) == 0 &&
			    (pcb->pcb_flags & NORMAL_STEP)) {
				siginfo.si_signo = SIGTRAP;
				siginfo.si_code = TRAP_TRACE;
				siginfo.si_addr = (caddr_t)rp->r_pc;
				fault = FLTTRACE;
			}
			pcb->pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
		}
		break;

	case T_DATA_EXCEPTION + T_USER:	/* user data access exception */

		if (&vis1_partial_support != NULL) {
			bzero(&siginfo, sizeof (siginfo));
			if (vis1_partial_support(rp,
			    &siginfo, &fault) == 0)
				goto out;
		}

		if (nfload(rp, &instr))
			goto out;
		if (IS_FLUSH(instr)) {
			/* skip the flush instruction */
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
			goto out;
			/*NOTREACHED*/
		}
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_addr = addr;
		switch (X_FAULT_TYPE(mmu_fsr)) {
		case FT_ATOMIC_NC:
			if ((IS_SWAP(instr) && swap_nc(rp, instr)) ||
			    (IS_LDSTUB(instr) && ldstub_nc(rp, instr))) {
				/* skip the atomic */
				rp->r_pc = rp->r_npc;
				rp->r_npc += 4;
				goto out;
			}
			/* fall into ... */
		case FT_PRIV:
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code = SEGV_ACCERR;
			fault = FLTBOUNDS;
			break;
		case FT_SPEC_LD:
		case FT_ILL_ALT:
			siginfo.si_signo = SIGILL;
			siginfo.si_code = ILL_ILLADR;
			fault = FLTILL;
			break;
		default:
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code = SEGV_MAPERR;
			fault = FLTBOUNDS;
			break;
		}
		break;

	case T_SYS_RTT_ALIGN + T_USER:	/* user alignment error */
	case T_ALIGNMENT + T_USER:	/* user alignment error */
		if (tudebug)
			showregs(type, rp, addr, 0);
		/*
		 * If the user has to do unaligned references
		 * the ugly stuff gets done here.
		 */
		alignfaults++;
		if (&vis1_partial_support != NULL) {
			bzero(&siginfo, sizeof (siginfo));
			if (vis1_partial_support(rp,
			    &siginfo, &fault) == 0)
				goto out;
		}

		bzero(&siginfo, sizeof (siginfo));
		if (type == T_SYS_RTT_ALIGN + T_USER) {
			if (nfload(rp, NULL))
				goto out;
			/*
			 * Can't do unaligned stack access
			 */
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRALN;
			siginfo.si_addr = addr;
			fault = FLTACCESS;
			break;
		}

		/*
		 * Try to fix alignment before non-faulting load test.
		 */
		if (p->p_fixalignment) {
			if (do_unaligned(rp, &badaddr) == SIMU_SUCCESS) {
				rp->r_pc = rp->r_npc;
				rp->r_npc += 4;
				goto out;
			}
			if (nfload(rp, NULL))
				goto out;
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code = SEGV_MAPERR;
			siginfo.si_addr = badaddr;
			fault = FLTBOUNDS;
		} else {
			if (nfload(rp, NULL))
				goto out;
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRALN;
			if (rp->r_pc & 3) {	/* offending address, if pc */
				siginfo.si_addr = (caddr_t)rp->r_pc;
			} else {
				if (calc_memaddr(rp, &badaddr) == SIMU_UNALIGN)
					siginfo.si_addr = badaddr;
				else
					siginfo.si_addr = (caddr_t)rp->r_pc;
			}
			fault = FLTACCESS;
		}
		break;

	case T_PRIV_INSTR + T_USER:	/* privileged instruction fault */
		if (tudebug)
			showregs(type, rp, (caddr_t)0, 0);

		bzero(&siginfo, sizeof (siginfo));
#ifdef	sun4v
		/*
		 * If this instruction fault is a non-privileged %tick
		 * or %stick trap, and %tick/%stick user emulation is
		 * enabled as a result of an OS suspend, then simulate
		 * the register read. We rely on simulate_rdtick to fail
		 * if the instruction is not a %tick or %stick read,
		 * causing us to fall through to the normal privileged
		 * instruction handling.
		 */
		if (tick_stick_emulation_active &&
		    (X_FAULT_TYPE(mmu_fsr) == FT_NEW_PRVACT) &&
		    simulate_rdtick(rp) == SIMU_SUCCESS) {
			/* skip the successfully simulated instruction */
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
			goto out;
		}
#endif
		siginfo.si_signo = SIGILL;
		siginfo.si_code = ILL_PRVOPC;
		siginfo.si_addr = (caddr_t)rp->r_pc;
		fault = FLTILL;
		break;

	case T_UNIMP_INSTR:		/* priv illegal instruction fault */
		if (fpras_implemented) {
			/*
			 * Call fpras_chktrap indicating that
			 * we've come from a trap handler and pass
			 * the regs.  That function may choose to panic
			 * (in which case it won't return) or it may
			 * determine that a reboot is desired.  In the
			 * latter case it must alter pc/npc to skip
			 * the illegal instruction and continue at
			 * a controlled address.
			 */
			if (&fpras_chktrap) {
				if (fpras_chktrap(rp))
					goto cleanup;
			}
		}
#if defined(SF_ERRATA_23) || defined(SF_ERRATA_30) /* call ... illegal-insn */
		instr = *(int *)rp->r_pc;
		if ((instr & 0xc0000000) == 0x40000000) {
			long pc;

			rp->r_o7 = (long long)rp->r_pc;
			pc = rp->r_pc + ((instr & 0x3fffffff) << 2);
			rp->r_pc = rp->r_npc;
			rp->r_npc = pc;
			ill_calls++;
			goto cleanup;
		}
#endif /* SF_ERRATA_23 || SF_ERRATA_30 */
		/*
		 * It's not an fpras failure and it's not SF_ERRATA_23 - die
		 */
		addr = (caddr_t)rp->r_pc;
		(void) die(type, rp, addr, 0);
		/*NOTREACHED*/

	case T_UNIMP_INSTR + T_USER:	/* illegal instruction fault */
#if defined(SF_ERRATA_23) || defined(SF_ERRATA_30) /* call ... illegal-insn */
		instr = fetch_user_instr((caddr_t)rp->r_pc);
		if ((instr & 0xc0000000) == 0x40000000) {
			long pc;

			rp->r_o7 = (long long)rp->r_pc;
			pc = rp->r_pc + ((instr & 0x3fffffff) << 2);
			rp->r_pc = rp->r_npc;
			rp->r_npc = pc;
			ill_calls++;
			goto out;
		}
#endif /* SF_ERRATA_23 || SF_ERRATA_30 */
		if (tudebug)
			showregs(type, rp, (caddr_t)0, 0);
		bzero(&siginfo, sizeof (siginfo));
		/*
		 * Try to simulate the instruction.
		 */
		switch (simulate_unimp(rp, &badaddr)) {
		case SIMU_RETRY:
			goto out;	/* regs are already set up */
			/*NOTREACHED*/

		case SIMU_SUCCESS:
			/* skip the successfully simulated instruction */
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
			goto out;
			/*NOTREACHED*/

		case SIMU_FAULT:
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code = SEGV_MAPERR;
			siginfo.si_addr = badaddr;
			fault = FLTBOUNDS;
			break;

		case SIMU_DZERO:
			siginfo.si_signo = SIGFPE;
			siginfo.si_code = FPE_INTDIV;
			siginfo.si_addr = (caddr_t)rp->r_pc;
			fault = FLTIZDIV;
			break;

		case SIMU_UNALIGN:
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRALN;
			siginfo.si_addr = badaddr;
			fault = FLTACCESS;
			break;

		case SIMU_ILLEGAL:
		default:
			siginfo.si_signo = SIGILL;
			op3 = (instr >> 19) & 0x3F;
			if ((IS_FLOAT(instr) && (op3 == IOP_V8_STQFA) ||
			    (op3 == IOP_V8_STDFA)))
				siginfo.si_code = ILL_ILLADR;
			else
				siginfo.si_code = ILL_ILLOPC;
			siginfo.si_addr = (caddr_t)rp->r_pc;
			fault = FLTILL;
			break;
		}
		break;

	case T_UNIMP_LDD + T_USER:
	case T_UNIMP_STD + T_USER:
		if (tudebug)
			showregs(type, rp, (caddr_t)0, 0);
		switch (simulate_lddstd(rp, &badaddr)) {
		case SIMU_SUCCESS:
			/* skip the successfully simulated instruction */
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
			goto out;
			/*NOTREACHED*/

		case SIMU_FAULT:
			if (nfload(rp, NULL))
				goto out;
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code = SEGV_MAPERR;
			siginfo.si_addr = badaddr;
			fault = FLTBOUNDS;
			break;

		case SIMU_UNALIGN:
			if (nfload(rp, NULL))
				goto out;
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRALN;
			siginfo.si_addr = badaddr;
			fault = FLTACCESS;
			break;

		case SIMU_ILLEGAL:
		default:
			siginfo.si_signo = SIGILL;
			siginfo.si_code = ILL_ILLOPC;
			siginfo.si_addr = (caddr_t)rp->r_pc;
			fault = FLTILL;
			break;
		}
		break;

	case T_UNIMP_LDD:
	case T_UNIMP_STD:
		if (simulate_lddstd(rp, &badaddr) == SIMU_SUCCESS) {
			/* skip the successfully simulated instruction */
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
			goto cleanup;
			/*NOTREACHED*/
		}
		/*
		 * A third party driver executed an {LDD,STD,LDDA,STDA}
		 * that we couldn't simulate.
		 */
		if (nfload(rp, NULL))
			goto cleanup;

		if (curthread->t_lofault) {
			if (lodebug) {
				showregs(type, rp, addr, 0);
				traceback((caddr_t)rp->r_sp);
			}
			rp->r_g1 = EFAULT;
			rp->r_pc = curthread->t_lofault;
			rp->r_npc = rp->r_pc + 4;
			goto cleanup;
		}
		(void) die(type, rp, addr, 0);
		/*NOTREACHED*/

	case T_IDIV0 + T_USER:		/* integer divide by zero */
	case T_DIV0 + T_USER:		/* integer divide by zero */
		if (tudebug && tudebugfpe)
			showregs(type, rp, (caddr_t)0, 0);
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_signo = SIGFPE;
		siginfo.si_code = FPE_INTDIV;
		siginfo.si_addr = (caddr_t)rp->r_pc;
		fault = FLTIZDIV;
		break;

	case T_INT_OVERFLOW + T_USER:	/* integer overflow */
		if (tudebug && tudebugfpe)
			showregs(type, rp, (caddr_t)0, 0);
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_signo = SIGFPE;
		siginfo.si_code  = FPE_INTOVF;
		siginfo.si_addr  = (caddr_t)rp->r_pc;
		fault = FLTIOVF;
		break;

	case T_BREAKPOINT + T_USER:	/* breakpoint trap (t 1) */
		if (tudebug && tudebugbpt)
			showregs(type, rp, (caddr_t)0, 0);
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_signo = SIGTRAP;
		siginfo.si_code = TRAP_BRKPT;
		siginfo.si_addr = (caddr_t)rp->r_pc;
		fault = FLTBPT;
		break;

	case T_TAG_OVERFLOW + T_USER:	/* tag overflow (taddcctv, tsubcctv) */
		if (tudebug)
			showregs(type, rp, (caddr_t)0, 0);
		bzero(&siginfo, sizeof (siginfo));
		siginfo.si_signo = SIGEMT;
		siginfo.si_code = EMT_TAGOVF;
		siginfo.si_addr = (caddr_t)rp->r_pc;
		fault = FLTACCESS;
		break;

	case T_FLUSH_PCB + T_USER:	/* finish user window overflow */
	case T_FLUSHW + T_USER:		/* finish user window flush */
		/*
		 * This trap is entered from sys_rtt in locore.s when,
		 * upon return to user is is found that there are user
		 * windows in pcb_wbuf.  This happens because they could
		 * not be saved on the user stack, either because it
		 * wasn't resident or because it was misaligned.
		 */
	{
		int error;
		caddr_t sp;

		error = flush_user_windows_to_stack(&sp);
		/*
		 * Possible errors:
		 *	error copying out
		 *	unaligned stack pointer
		 * The first is given to us as the return value
		 * from flush_user_windows_to_stack().  The second
		 * results in residual windows in the pcb.
		 */
		if (error != 0) {
			/*
			 * EINTR comes from a signal during copyout;
			 * we should not post another signal.
			 */
			if (error != EINTR) {
				/*
				 * Zap the process with a SIGSEGV - process
				 * may be managing its own stack growth by
				 * taking SIGSEGVs on a different signal stack.
				 */
				bzero(&siginfo, sizeof (siginfo));
				siginfo.si_signo = SIGSEGV;
				siginfo.si_code  = SEGV_MAPERR;
				siginfo.si_addr  = sp;
				fault = FLTBOUNDS;
			}
			break;
		} else if (mpcb->mpcb_wbcnt) {
			bzero(&siginfo, sizeof (siginfo));
			siginfo.si_signo = SIGILL;
			siginfo.si_code  = ILL_BADSTK;
			siginfo.si_addr  = (caddr_t)rp->r_pc;
			fault = FLTILL;
			break;
		}
	}

		/*
		 * T_FLUSHW is used when handling a ta 0x3 -- the old flush
		 * window trap -- which is implemented by executing the
		 * flushw instruction. The flushw can trap if any of the
		 * stack pages are not writable for whatever reason. In this
		 * case only, we advance the pc to the next instruction so
		 * that the user thread doesn't needlessly execute the trap
		 * again. Normally this wouldn't be a problem -- we'll
		 * usually only end up here if this is the first touch to a
		 * stack page -- since the second execution won't trap, but
		 * if there's a watchpoint on the stack page the user thread
		 * would spin, continuously executing the trap instruction.
		 */
		if (type == T_FLUSHW + T_USER) {
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
		}
		goto out;

	case T_AST + T_USER:		/* profiling or resched pseudo trap */
		if (lwp->lwp_pcb.pcb_flags & CPC_OVERFLOW) {
			lwp->lwp_pcb.pcb_flags &= ~CPC_OVERFLOW;
			if (kcpc_overflow_ast()) {
				/*
				 * Signal performance counter overflow
				 */
				if (tudebug)
					showregs(type, rp, (caddr_t)0, 0);
				bzero(&siginfo, sizeof (siginfo));
				siginfo.si_signo = SIGEMT;
				siginfo.si_code = EMT_CPCOVF;
				siginfo.si_addr = (caddr_t)rp->r_pc;
				/* for trap_cleanup(), below */
				oldpc = rp->r_pc - 4;
				fault = FLTCPCOVF;
			}
		}

		/*
		 * The CPC_OVERFLOW check above may already have populated
		 * siginfo and set fault, so the checks below must not
		 * touch these and the functions they call must use
		 * trapsig() directly.
		 */

		if (lwp->lwp_pcb.pcb_flags & ASYNC_HWERR) {
			lwp->lwp_pcb.pcb_flags &= ~ASYNC_HWERR;
			trap_async_hwerr();
		}

		if (lwp->lwp_pcb.pcb_flags & ASYNC_BERR) {
			lwp->lwp_pcb.pcb_flags &= ~ASYNC_BERR;
			trap_async_berr_bto(ASYNC_BERR, rp);
		}

		if (lwp->lwp_pcb.pcb_flags & ASYNC_BTO) {
			lwp->lwp_pcb.pcb_flags &= ~ASYNC_BTO;
			trap_async_berr_bto(ASYNC_BTO, rp);
		}

		break;
	}

	if (fault) {
		/* We took a fault so abort single step. */
		lwp->lwp_pcb.pcb_flags &= ~(NORMAL_STEP|WATCH_STEP);
	}
	trap_cleanup(rp, fault, &siginfo, oldpc == rp->r_pc);

out:	/* We can't get here from a system trap */
	ASSERT(type & T_USER);
	trap_rtt();
	(void) new_mstate(curthread, mstate);
	/* Kernel probe */
	TNF_PROBE_1(thread_state, "thread", /* CSTYLED */,
		tnf_microstate, state, LMS_USER);

	TRACE_0(TR_FAC_TRAP, TR_C_TRAP_HANDLER_EXIT, "C_trap_handler_exit");
	return;

cleanup:	/* system traps end up here */
	ASSERT(!(type & T_USER));

	TRACE_0(TR_FAC_TRAP, TR_C_TRAP_HANDLER_EXIT, "C_trap_handler_exit");
}

void
trap_cleanup(
	struct regs *rp,
	uint_t fault,
	k_siginfo_t *sip,
	int restartable)
{
	extern void aio_cleanup();
	proc_t *p = ttoproc(curthread);
	klwp_id_t lwp = ttolwp(curthread);

	if (fault) {
		/*
		 * Remember the fault and fault address
		 * for real-time (SIGPROF) profiling.
		 */
		lwp->lwp_lastfault = fault;
		lwp->lwp_lastfaddr = sip->si_addr;

		DTRACE_PROC2(fault, int, fault, ksiginfo_t *, sip);

		/*
		 * If a debugger has declared this fault to be an
		 * event of interest, stop the lwp.  Otherwise just
		 * deliver the associated signal.
		 */
		if (sip->si_signo != SIGKILL &&
		    prismember(&p->p_fltmask, fault) &&
		    stop_on_fault(fault, sip) == 0)
			sip->si_signo = 0;
	}

	if (sip->si_signo)
		trapsig(sip, restartable);

	if (lwp->lwp_oweupc)
		profil_tick(rp->r_pc);

	if (curthread->t_astflag | curthread->t_sig_check) {
		/*
		 * Turn off the AST flag before checking all the conditions that
		 * may have caused an AST.  This flag is on whenever a signal or
		 * unusual condition should be handled after the next trap or
		 * syscall.
		 */
		astoff(curthread);
		curthread->t_sig_check = 0;

		/*
		 * The following check is legal for the following reasons:
		 *	1) The thread we are checking, is ourselves, so there is
		 *	   no way the proc can go away.
		 *	2) The only time we need to be protected by the
		 *	   lock is if the binding is changed.
		 *
		 *	Note we will still take the lock and check the binding
		 *	if the condition was true without the lock held.  This
		 *	prevents lock contention among threads owned by the
		 *	same proc.
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
		if (ISSIG_PENDING(curthread, lwp, p)) {
			if (issig(FORREAL))
				psig();
			curthread->t_sig_check = 1;
		}

		if (curthread->t_rprof != NULL) {
			realsigprof(0, 0, 0);
			curthread->t_sig_check = 1;
		}
	}
}

/*
 * Called from fp_traps when a floating point trap occurs.
 * Note that the T_DATA_EXCEPTION case does not use X_FAULT_TYPE(mmu_fsr),
 * because mmu_fsr (now changed to code) is always 0.
 * Note that the T_UNIMP_INSTR case does not call simulate_unimp(),
 * because the simulator only simulates multiply and divide instructions,
 * which would not cause floating point traps in the first place.
 * XXX - Supervisor mode floating point traps?
 */
void
fpu_trap(struct regs *rp, caddr_t addr, uint32_t type, uint32_t code)
{
	proc_t *p = ttoproc(curthread);
	klwp_id_t lwp = ttolwp(curthread);
	k_siginfo_t siginfo;
	uint_t op3, fault = 0;
	int mstate;
	char *badaddr;
	kfpu_t *fp;
	struct fpq *pfpq;
	uint32_t inst;
	utrap_handler_t *utrapp;

	CPU_STATS_ADDQ(CPU, sys, trap, 1);

	ASSERT(curthread->t_schedflag & TS_DONT_SWAP);

	if (USERMODE(rp->r_tstate)) {
		/*
		 * Set lwp_state before trying to acquire any
		 * adaptive lock
		 */
		ASSERT(lwp != NULL);
		lwp->lwp_state = LWP_SYS;
		/*
		 * Set up the current cred to use during this trap. u_cred
		 * no longer exists.  t_cred is used instead.
		 * The current process credential applies to the thread for
		 * the entire trap.  If trapping from the kernel, this
		 * should already be set up.
		 */
		if (curthread->t_cred != p->p_cred) {
			cred_t *oldcred = curthread->t_cred;
			/*
			 * DTrace accesses t_cred in probe context.  t_cred
			 * must always be either NULL, or point to a valid,
			 * allocated cred structure.
			 */
			curthread->t_cred = crgetcred();
			crfree(oldcred);
		}
		ASSERT(lwp->lwp_regs == rp);
		mstate = new_mstate(curthread, LMS_TRAP);
		siginfo.si_signo = 0;
		type |= T_USER;
	}

	TRACE_1(TR_FAC_TRAP, TR_C_TRAP_HANDLER_ENTER,
	    "C_fpu_trap_handler_enter:type %x", type);

	if (tudebug && tudebugfpe)
		showregs(type, rp, addr, 0);

	bzero(&siginfo, sizeof (siginfo));
	siginfo.si_code = code;
	siginfo.si_addr = addr;

	switch (type) {

	case T_FP_EXCEPTION_IEEE + T_USER:	/* FPU arithmetic exception */
		/*
		 * FPU arithmetic exception - fake up a fpq if we
		 *	came here directly from _fp_ieee_exception,
		 *	which is indicated by a zero fpu_qcnt.
		 */
		fp = lwptofpu(curthread->t_lwp);
		utrapp = curthread->t_procp->p_utraps;
		if (fp->fpu_qcnt == 0) {
			inst = fetch_user_instr((caddr_t)rp->r_pc);
			lwp->lwp_state = LWP_SYS;
			pfpq = &fp->fpu_q->FQu.fpq;
			pfpq->fpq_addr = (uint32_t *)rp->r_pc;
			pfpq->fpq_instr = inst;
			fp->fpu_qcnt = 1;
			fp->fpu_q_entrysize = sizeof (struct fpq);
#ifdef SF_V9_TABLE_28
			/*
			 * Spitfire and blackbird followed the SPARC V9 manual
			 * paragraph 3 of section 5.1.7.9 FSR_current_exception
			 * (cexc) for setting fsr.cexc bits on underflow and
			 * overflow traps when the fsr.tem.inexact bit is set,
			 * instead of following Table 28. Bugid 1263234.
			 */
			{
				extern int spitfire_bb_fsr_bug;

				if (spitfire_bb_fsr_bug &&
				    (fp->fpu_fsr & FSR_TEM_NX)) {
					if (((fp->fpu_fsr & FSR_TEM_OF) == 0) &&
					    (fp->fpu_fsr & FSR_CEXC_OF)) {
						fp->fpu_fsr &= ~FSR_CEXC_OF;
						fp->fpu_fsr |= FSR_CEXC_NX;
						_fp_write_pfsr(&fp->fpu_fsr);
						siginfo.si_code = FPE_FLTRES;
					}
					if (((fp->fpu_fsr & FSR_TEM_UF) == 0) &&
					    (fp->fpu_fsr & FSR_CEXC_UF)) {
						fp->fpu_fsr &= ~FSR_CEXC_UF;
						fp->fpu_fsr |= FSR_CEXC_NX;
						_fp_write_pfsr(&fp->fpu_fsr);
						siginfo.si_code = FPE_FLTRES;
					}
				}
			}
#endif /* SF_V9_TABLE_28 */
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
		} else if (utrapp && utrapp[UT_FP_EXCEPTION_IEEE_754]) {
			/*
			 * The user had a trap handler installed.  Jump to
			 * the trap handler instead of signalling the process.
			 */
			rp->r_pc = (long)utrapp[UT_FP_EXCEPTION_IEEE_754];
			rp->r_npc = rp->r_pc + 4;
			break;
		}
		siginfo.si_signo = SIGFPE;
		fault = FLTFPE;
		break;

	case T_DATA_EXCEPTION + T_USER:		/* user data access exception */
		siginfo.si_signo = SIGSEGV;
		fault = FLTBOUNDS;
		break;

	case T_LDDF_ALIGN + T_USER: /* 64 bit user lddfa alignment error */
	case T_STDF_ALIGN + T_USER: /* 64 bit user stdfa alignment error */
		alignfaults++;
		lwp->lwp_state = LWP_SYS;
		if (&vis1_partial_support != NULL) {
			bzero(&siginfo, sizeof (siginfo));
			if (vis1_partial_support(rp,
			    &siginfo, &fault) == 0)
				goto out;
		}
		if (do_unaligned(rp, &badaddr) == SIMU_SUCCESS) {
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
			goto out;
		}
		fp = lwptofpu(curthread->t_lwp);
		fp->fpu_qcnt = 0;
		siginfo.si_signo = SIGSEGV;
		siginfo.si_code = SEGV_MAPERR;
		siginfo.si_addr = badaddr;
		fault = FLTBOUNDS;
		break;

	case T_ALIGNMENT + T_USER:		/* user alignment error */
		/*
		 * If the user has to do unaligned references
		 * the ugly stuff gets done here.
		 * Only handles vanilla loads and stores.
		 */
		alignfaults++;
		if (p->p_fixalignment) {
			if (do_unaligned(rp, &badaddr) == SIMU_SUCCESS) {
				rp->r_pc = rp->r_npc;
				rp->r_npc += 4;
				goto out;
			}
			siginfo.si_signo = SIGSEGV;
			siginfo.si_code = SEGV_MAPERR;
			siginfo.si_addr = badaddr;
			fault = FLTBOUNDS;
		} else {
			siginfo.si_signo = SIGBUS;
			siginfo.si_code = BUS_ADRALN;
			if (rp->r_pc & 3) {	/* offending address, if pc */
				siginfo.si_addr = (caddr_t)rp->r_pc;
			} else {
				if (calc_memaddr(rp, &badaddr) == SIMU_UNALIGN)
					siginfo.si_addr = badaddr;
				else
					siginfo.si_addr = (caddr_t)rp->r_pc;
			}
			fault = FLTACCESS;
		}
		break;

	case T_UNIMP_INSTR + T_USER:		/* illegal instruction fault */
		siginfo.si_signo = SIGILL;
		inst = fetch_user_instr((caddr_t)rp->r_pc);
		op3 = (inst >> 19) & 0x3F;
		if ((op3 == IOP_V8_STQFA) || (op3 == IOP_V8_STDFA))
			siginfo.si_code = ILL_ILLADR;
		else
			siginfo.si_code = ILL_ILLTRP;
		fault = FLTILL;
		break;

	default:
		(void) die(type, rp, addr, 0);
		/*NOTREACHED*/
	}

	/*
	 * We can't get here from a system trap
	 * Never restart any instruction which got here from an fp trap.
	 */
	ASSERT(type & T_USER);

	trap_cleanup(rp, fault, &siginfo, 0);
out:
	trap_rtt();
	(void) new_mstate(curthread, mstate);
}

void
trap_rtt(void)
{
	klwp_id_t lwp = ttolwp(curthread);

	/*
	 * Restore register window if a debugger modified it.
	 * Set up to perform a single-step if a debugger requested it.
	 */
	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE)
		xregrestore(lwp, 0);

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
	if (curthread->t_trapret) {
		curthread->t_trapret = 0;
		thread_lock(curthread);
		CL_TRAPRET(curthread);
		thread_unlock(curthread);
	}
	if (CPU->cpu_runrun || curthread->t_schedflag & TS_ANYWAITQ)
		preempt();
	prunstop();
	if (lwp->lwp_pcb.pcb_step != STEP_NONE)
		prdostep();

	TRACE_0(TR_FAC_TRAP, TR_C_TRAP_HANDLER_EXIT, "C_trap_handler_exit");
}

#define	IS_LDASI(o)	\
	((o) == (uint32_t)0xC0C00000 || (o) == (uint32_t)0xC0800000 ||	\
	(o) == (uint32_t)0xC1800000)
#define	IS_IMM_ASI(i)	(((i) & 0x2000) == 0)
#define	IS_ASINF(a)	(((a) & 0xF6) == 0x82)
#define	IS_LDDA(i)	(((i) & 0xC1F80000) == 0xC0980000)

static int
nfload(struct regs *rp, int *instrp)
{
	uint_t	instr, asi, op3, rd;
	size_t	len;
	struct as *as;
	caddr_t addr;
	FPU_DREGS_TYPE zero;
	extern int segnf_create();

	if (USERMODE(rp->r_tstate))
		instr = fetch_user_instr((caddr_t)rp->r_pc);
	else
		instr = *(int *)rp->r_pc;

	if (instrp)
		*instrp = instr;

	op3 = (uint_t)(instr & 0xC1E00000);
	if (!IS_LDASI(op3))
		return (0);
	if (IS_IMM_ASI(instr))
		asi = (instr & 0x1FE0) >> 5;
	else
		asi = (uint_t)((rp->r_tstate >> TSTATE_ASI_SHIFT) &
		    TSTATE_ASI_MASK);
	if (!IS_ASINF(asi))
		return (0);
	if (calc_memaddr(rp, &addr) == SIMU_SUCCESS) {
		len = 1;
		as = USERMODE(rp->r_tstate) ? ttoproc(curthread)->p_as : &kas;
		as_rangelock(as);
		if (as_gap(as, len, &addr, &len, 0, addr) == 0)
			(void) as_map(as, addr, len, segnf_create, NULL);
		as_rangeunlock(as);
	}
	zero = 0;
	rd = (instr >> 25) & 0x1f;
	if (IS_FLOAT(instr)) {
		uint_t dbflg = ((instr >> 19) & 3) == 3;

		if (dbflg) {		/* clever v9 reg encoding */
			if (rd & 1)
				rd = (rd & 0x1e) | 0x20;
			rd >>= 1;
		}
		if (fpu_exists) {
			if (!(_fp_read_fprs() & FPRS_FEF))
				fp_enable();

			if (dbflg)
				_fp_write_pdreg(&zero, rd);
			else
				_fp_write_pfreg((uint_t *)&zero, rd);
		} else {
			kfpu_t *fp = lwptofpu(curthread->t_lwp);

			if (!fp->fpu_en)
				fp_enable();

			if (dbflg)
				fp->fpu_fr.fpu_dregs[rd] = zero;
			else
				fp->fpu_fr.fpu_regs[rd] = 0;
		}
	} else {
		(void) putreg(&zero, rp, rd, &addr);
		if (IS_LDDA(instr))
			(void) putreg(&zero, rp, rd + 1, &addr);
	}
	rp->r_pc = rp->r_npc;
	rp->r_npc += 4;
	return (1);
}

kmutex_t atomic_nc_mutex;

/*
 * The following couple of routines are for userland drivers which
 * do atomics to noncached addresses.  This sort of worked on previous
 * platforms -- the operation really wasn't atomic, but it didn't generate
 * a trap as sun4u systems do.
 */
static int
swap_nc(struct regs *rp, int instr)
{
	uint64_t rdata, mdata;
	caddr_t addr, badaddr;
	uint_t tmp, rd;

	(void) flush_user_windows_to_stack(NULL);
	rd = (instr >> 25) & 0x1f;
	if (calc_memaddr(rp, &addr) != SIMU_SUCCESS)
		return (0);
	if (getreg(rp, rd, &rdata, &badaddr))
		return (0);
	mutex_enter(&atomic_nc_mutex);
	if (fuword32(addr, &tmp) == -1) {
		mutex_exit(&atomic_nc_mutex);
		return (0);
	}
	mdata = (u_longlong_t)tmp;
	if (suword32(addr, (uint32_t)rdata) == -1) {
		mutex_exit(&atomic_nc_mutex);
		return (0);
	}
	(void) putreg(&mdata, rp, rd, &badaddr);
	mutex_exit(&atomic_nc_mutex);
	return (1);
}

static int
ldstub_nc(struct regs *rp, int instr)
{
	uint64_t mdata;
	caddr_t addr, badaddr;
	uint_t rd;
	uint8_t tmp;

	(void) flush_user_windows_to_stack(NULL);
	rd = (instr >> 25) & 0x1f;
	if (calc_memaddr(rp, &addr) != SIMU_SUCCESS)
		return (0);
	mutex_enter(&atomic_nc_mutex);
	if (fuword8(addr, &tmp) == -1) {
		mutex_exit(&atomic_nc_mutex);
		return (0);
	}
	mdata = (u_longlong_t)tmp;
	if (suword8(addr, (uint8_t)0xff) == -1) {
		mutex_exit(&atomic_nc_mutex);
		return (0);
	}
	(void) putreg(&mdata, rp, rd, &badaddr);
	mutex_exit(&atomic_nc_mutex);
	return (1);
}

/*
 * This function helps instr_size() determine the operand size.
 * It is called for the extended ldda/stda asi's.
 */
int
extended_asi_size(int asi)
{
	switch (asi) {
	case ASI_PST8_P:
	case ASI_PST8_S:
	case ASI_PST16_P:
	case ASI_PST16_S:
	case ASI_PST32_P:
	case ASI_PST32_S:
	case ASI_PST8_PL:
	case ASI_PST8_SL:
	case ASI_PST16_PL:
	case ASI_PST16_SL:
	case ASI_PST32_PL:
	case ASI_PST32_SL:
		return (8);
	case ASI_FL8_P:
	case ASI_FL8_S:
	case ASI_FL8_PL:
	case ASI_FL8_SL:
		return (1);
	case ASI_FL16_P:
	case ASI_FL16_S:
	case ASI_FL16_PL:
	case ASI_FL16_SL:
		return (2);
	case ASI_BLK_P:
	case ASI_BLK_S:
	case ASI_BLK_PL:
	case ASI_BLK_SL:
	case ASI_BLK_COMMIT_P:
	case ASI_BLK_COMMIT_S:
		return (64);
	}

	return (0);
}

/*
 * Patch non-zero to disable preemption of threads in the kernel.
 */
int IGNORE_KERNEL_PREEMPTION = 0;	/* XXX - delete this someday */

struct kpreempt_cnts {	/* kernel preemption statistics */
	int	kpc_idle;	/* executing idle thread */
	int	kpc_intr;	/* executing interrupt thread */
	int	kpc_clock;	/* executing clock thread */
	int	kpc_blocked;	/* thread has blocked preemption (t_preempt) */
	int	kpc_notonproc;	/* thread is surrendering processor */
	int	kpc_inswtch;	/* thread has ratified scheduling decision */
	int	kpc_prilevel;	/* processor interrupt level is too high */
	int	kpc_apreempt;	/* asynchronous preemption */
	int	kpc_spreempt;	/* synchronous preemption */
}	kpreempt_cnts;

/*
 * kernel preemption: forced rescheduling
 *	preempt the running kernel thread.
 */
void
kpreempt(int asyncspl)
{
	if (IGNORE_KERNEL_PREEMPTION) {
		aston(CPU->cpu_dispthread);
		return;
	}
	/*
	 * Check that conditions are right for kernel preemption
	 */
	do {
		if (curthread->t_preempt) {
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
			if (curthread->t_pri < 0) {
				kpreempt_cnts.kpc_idle++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			} else if (curthread->t_flag & T_INTR_THREAD) {
				kpreempt_cnts.kpc_intr++;
				if (curthread->t_pil == CLOCK_LEVEL)
					kpreempt_cnts.kpc_clock++;
			} else {
				kpreempt_cnts.kpc_blocked++;
				if (CPU->cpu_dispthread != CPU->cpu_thread)
					siron();
			}
			aston(CPU->cpu_dispthread);
			return;
		}
		if (curthread->t_state != TS_ONPROC ||
		    curthread->t_disp_queue != CPU->cpu_disp) {
			/* this thread will be calling swtch() shortly */
			kpreempt_cnts.kpc_notonproc++;
			if (CPU->cpu_thread != CPU->cpu_dispthread) {
				/* already in swtch(), force another */
				kpreempt_cnts.kpc_inswtch++;
				siron();
			}
			return;
		}

		if (((asyncspl != KPREEMPT_SYNC) ? spltoipl(asyncspl) :
		    getpil()) >= DISP_LEVEL) {
			/*
			 * We can't preempt this thread if it is at
			 * a PIL >= DISP_LEVEL since it may be holding
			 * a spin lock (like sched_lock).
			 */
			siron();	/* check back later */
			kpreempt_cnts.kpc_prilevel++;
			return;
		}

		/*
		 * block preemption so we don't have multiple preemptions
		 * pending on the interrupt stack
		 */
		curthread->t_preempt++;
		if (asyncspl != KPREEMPT_SYNC) {
			splx(asyncspl);
			kpreempt_cnts.kpc_apreempt++;
		} else
			kpreempt_cnts.kpc_spreempt++;

		preempt();
		curthread->t_preempt--;
	} while (CPU->cpu_kprunrun);
}

static enum seg_rw
get_accesstype(struct regs *rp)
{
	uint32_t instr;

	if (USERMODE(rp->r_tstate))
		instr = fetch_user_instr((caddr_t)rp->r_pc);
	else
		instr = *(uint32_t *)rp->r_pc;

	if (IS_FLUSH(instr))
		return (S_OTHER);

	if (IS_STORE(instr))
		return (S_WRITE);
	else
		return (S_READ);
}

/*
 * Handle an asynchronous hardware error.
 * The policy is currently to send a hardware error contract event to
 * the process's process contract and to kill the process.  Eventually
 * we may want to instead send a special signal whose default
 * disposition is to generate the contract event.
 */
void
trap_async_hwerr(void)
{
	k_siginfo_t si;
	proc_t *p = ttoproc(curthread);
	extern void print_msg_hwerr(ctid_t ct_id, proc_t *p);

	errorq_drain(ue_queue); /* flush pending async error messages */

	print_msg_hwerr(p->p_ct_process->conp_contract.ct_id, p);

	contract_process_hwerr(p->p_ct_process, p);

	bzero(&si, sizeof (k_siginfo_t));
	si.si_signo = SIGKILL;
	si.si_code = SI_NOINFO;
	trapsig(&si, 1);
}

/*
 * Handle bus error and bus timeout for a user process by sending SIGBUS
 * The type is either ASYNC_BERR or ASYNC_BTO.
 */
void
trap_async_berr_bto(int type, struct regs *rp)
{
	k_siginfo_t si;

	errorq_drain(ue_queue); /* flush pending async error messages */
	bzero(&si, sizeof (k_siginfo_t));

	si.si_signo = SIGBUS;
	si.si_code = (type == ASYNC_BERR ? BUS_OBJERR : BUS_ADRERR);
	si.si_addr = (caddr_t)rp->r_pc; /* AFAR unavailable - future RFE */
	si.si_errno = ENXIO;

	trapsig(&si, 1);
}

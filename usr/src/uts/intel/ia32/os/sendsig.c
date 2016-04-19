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
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*	All Rights Reserved   */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/class.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/archsystm.h>
#include <sys/vmparam.h>
#include <sys/prsystm.h>
#include <sys/reboot.h>
#include <sys/uadmin.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/session.h>
#include <sys/ucontext.h>
#include <sys/dnlc.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/debugreg.h>
#include <sys/thread.h>
#include <sys/vtrace.h>
#include <sys/consdev.h>
#include <sys/psw.h>
#include <sys/regset.h>

#include <sys/privregs.h>

#include <sys/stack.h>
#include <sys/swap.h>
#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <sys/exec.h>
#include <sys/acct.h>
#include <sys/core.h>
#include <sys/corectl.h>
#include <sys/modctl.h>
#include <sys/tuneable.h>
#include <c2/audit.h>
#include <sys/bootconf.h>
#include <sys/dumphdr.h>
#include <sys/promif.h>
#include <sys/systeminfo.h>
#include <sys/kdi.h>
#include <sys/contract_impl.h>
#include <sys/x86_archext.h>

/*
 * Construct the execution environment for the user's signal
 * handler and arrange for control to be given to it on return
 * to userland.  The library code now calls setcontext() to
 * clean up after the signal handler, so sigret() is no longer
 * needed.
 *
 * (The various 'volatile' declarations are need to ensure that values
 * are correct on the error return from on_fault().)
 */

#if defined(__amd64)

/*
 * An amd64 signal frame looks like this on the stack:
 *
 * old %rsp:
 *		<128 bytes of untouched stack space>
 *		<a siginfo_t [optional]>
 *		<a ucontext_t>
 *		<siginfo_t *>
 *		<signal number>
 * new %rsp:	<return address (deliberately invalid)>
 *
 * The signal number and siginfo_t pointer are only pushed onto the stack in
 * order to allow stack backtraces.  The actual signal handling code expects the
 * arguments in registers.
 */

struct sigframe {
	caddr_t retaddr;
	long	signo;
	siginfo_t *sip;
};

int
sendsig(int sig, k_siginfo_t *sip, void (*hdlr)())
{
	volatile int minstacksz;
	int newstack;
	label_t ljb;
	volatile caddr_t sp;
	caddr_t fp;
	volatile struct regs *rp;
	volatile greg_t upc;
	volatile proc_t *p = ttoproc(curthread);
	struct as *as = p->p_as;
	klwp_t *lwp = ttolwp(curthread);
	ucontext_t *volatile tuc = NULL;
	ucontext_t *uc;
	siginfo_t *sip_addr;
	volatile int watched;

	/*
	 * This routine is utterly dependent upon STACK_ALIGN being
	 * 16 and STACK_ENTRY_ALIGN being 8. Let's just acknowledge
	 * that and require it.
	 */

#if STACK_ALIGN != 16 || STACK_ENTRY_ALIGN != 8
#error "sendsig() amd64 did not find the expected stack alignments"
#endif

	rp = lwptoregs(lwp);
	upc = rp->r_pc;

	/*
	 * Since we're setting up to run the signal handler we have to
	 * arrange that the stack at entry to the handler is (only)
	 * STACK_ENTRY_ALIGN (i.e. 8) byte aligned so that when the handler
	 * executes its push of %rbp, the stack realigns to STACK_ALIGN
	 * (i.e. 16) correctly.
	 *
	 * The new sp will point to the sigframe and the ucontext_t. The
	 * above means that sp (and thus sigframe) will be 8-byte aligned,
	 * but not 16-byte aligned. ucontext_t, however, contains %xmm regs
	 * which must be 16-byte aligned. Because of this, for correct
	 * alignment, sigframe must be a multiple of 8-bytes in length, but
	 * not 16-bytes. This will place ucontext_t at a nice 16-byte boundary.
	 */

	/* LINTED: logical expression always true: op "||" */
	ASSERT((sizeof (struct sigframe) % 16) == 8);

	minstacksz = sizeof (struct sigframe) + SA(sizeof (*uc));
	if (sip != NULL)
		minstacksz += SA(sizeof (siginfo_t));
	ASSERT((minstacksz & (STACK_ENTRY_ALIGN - 1ul)) == 0);

	/*
	 * Figure out whether we will be handling this signal on
	 * an alternate stack specified by the user.  Then allocate
	 * and validate the stack requirements for the signal handler
	 * context.  on_fault will catch any faults.
	 */
	newstack = sigismember(&PTOU(curproc)->u_sigonstack, sig) &&
	    !(lwp->lwp_sigaltstack.ss_flags & (SS_ONSTACK|SS_DISABLE));

	if (newstack) {
		fp = (caddr_t)(SA((uintptr_t)lwp->lwp_sigaltstack.ss_sp) +
		    SA(lwp->lwp_sigaltstack.ss_size) - STACK_ALIGN);
	} else {
		/*
		 * Drop below the 128-byte reserved region of the stack frame
		 * we're interrupting.
		 */
		fp = (caddr_t)rp->r_sp - STACK_RESERVE;
	}

	/*
	 * Force proper stack pointer alignment, even in the face of a
	 * misaligned stack pointer from user-level before the signal.
	 */
	fp = (caddr_t)((uintptr_t)fp & ~(STACK_ENTRY_ALIGN - 1ul));

	/*
	 * Most of the time during normal execution, the stack pointer
	 * is aligned on a STACK_ALIGN (i.e. 16 byte) boundary.  However,
	 * (for example) just after a call instruction (which pushes
	 * the return address), the callers stack misaligns until the
	 * 'push %rbp' happens in the callee prolog.  So while we should
	 * expect the stack pointer to be always at least STACK_ENTRY_ALIGN
	 * aligned, we should -not- expect it to always be STACK_ALIGN aligned.
	 * We now adjust to ensure that the new sp is aligned to
	 * STACK_ENTRY_ALIGN but not to STACK_ALIGN.
	 */
	sp = fp - minstacksz;
	if (((uintptr_t)sp & (STACK_ALIGN - 1ul)) == 0) {
		sp -= STACK_ENTRY_ALIGN;
		minstacksz = fp - sp;
	}

	/*
	 * Now, make sure the resulting signal frame address is sane
	 */
	if (sp >= as->a_userlimit || fp >= as->a_userlimit) {
#ifdef DEBUG
		printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
		    PTOU(p)->u_comm, p->p_pid, sig);
		printf("sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
		    (void *)sp, (void *)hdlr, (uintptr_t)upc);
		printf("sp above USERLIMIT\n");
#endif
		return (0);
	}

	watched = watch_disable_addr((caddr_t)sp, minstacksz, S_WRITE);

	if (on_fault(&ljb))
		goto badstack;

	if (sip != NULL) {
		zoneid_t zoneid;

		fp -= SA(sizeof (siginfo_t));
		uzero(fp, sizeof (siginfo_t));
		if (SI_FROMUSER(sip) &&
		    (zoneid = p->p_zone->zone_id) != GLOBAL_ZONEID &&
		    zoneid != sip->si_zoneid) {
			k_siginfo_t sani_sip = *sip;

			sani_sip.si_pid = p->p_zone->zone_zsched->p_pid;
			sani_sip.si_uid = 0;
			sani_sip.si_ctid = -1;
			sani_sip.si_zoneid = zoneid;
			copyout_noerr(&sani_sip, fp, sizeof (sani_sip));
		} else
			copyout_noerr(sip, fp, sizeof (*sip));
		sip_addr = (siginfo_t *)fp;

		if (sig == SIGPROF &&
		    curthread->t_rprof != NULL &&
		    curthread->t_rprof->rp_anystate) {
			/*
			 * We stand on our head to deal with
			 * the real time profiling signal.
			 * Fill in the stuff that doesn't fit
			 * in a normal k_siginfo structure.
			 */
			int i = sip->si_nsysarg;

			while (--i >= 0)
				sulword_noerr(
				    (ulong_t *)&(sip_addr->si_sysarg[i]),
				    (ulong_t)lwp->lwp_arg[i]);
			copyout_noerr(curthread->t_rprof->rp_state,
			    sip_addr->si_mstate,
			    sizeof (curthread->t_rprof->rp_state));
		}
	} else
		sip_addr = NULL;

	/*
	 * save the current context on the user stack directly after the
	 * sigframe. Since sigframe is 8-byte-but-not-16-byte aligned,
	 * and since sizeof (struct sigframe) is 24, this guarantees
	 * 16-byte alignment for ucontext_t and its %xmm registers.
	 */
	uc = (ucontext_t *)(sp + sizeof (struct sigframe));
	tuc = kmem_alloc(sizeof (*tuc), KM_SLEEP);
	no_fault();
	savecontext(tuc, &lwp->lwp_sigoldmask);
	if (on_fault(&ljb))
		goto badstack;
	copyout_noerr(tuc, uc, sizeof (*tuc));
	kmem_free(tuc, sizeof (*tuc));
	tuc = NULL;

	lwp->lwp_oldcontext = (uintptr_t)uc;

	if (newstack) {
		lwp->lwp_sigaltstack.ss_flags |= SS_ONSTACK;
		if (lwp->lwp_ustack)
			copyout_noerr(&lwp->lwp_sigaltstack,
			    (stack_t *)lwp->lwp_ustack, sizeof (stack_t));
	}

	/*
	 * Set up signal handler return and stack linkage
	 */
	{
		struct sigframe frame;

		/*
		 * ensure we never return "normally"
		 */
		frame.retaddr = (caddr_t)(uintptr_t)-1L;
		frame.signo = sig;
		frame.sip = sip_addr;
		copyout_noerr(&frame, sp, sizeof (frame));
	}

	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);

	/*
	 * Set up user registers for execution of signal handler.
	 */
	rp->r_sp = (greg_t)sp;
	rp->r_pc = (greg_t)hdlr;
	rp->r_ps = PSL_USER | (rp->r_ps & PS_IOPL);

	rp->r_rdi = sig;
	rp->r_rsi = (uintptr_t)sip_addr;
	rp->r_rdx = (uintptr_t)uc;

	if ((rp->r_cs & 0xffff) != UCS_SEL ||
	    (rp->r_ss & 0xffff) != UDS_SEL) {
		/*
		 * Try our best to deliver the signal.
		 */
		rp->r_cs = UCS_SEL;
		rp->r_ss = UDS_SEL;
	}

	/*
	 * Don't set lwp_eosys here.  sendsig() is called via psig() after
	 * lwp_eosys is handled, so setting it here would affect the next
	 * system call.
	 */
	return (1);

badstack:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);
	if (tuc)
		kmem_free(tuc, sizeof (*tuc));
#ifdef DEBUG
	printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
	    PTOU(p)->u_comm, p->p_pid, sig);
	printf("on fault, sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
	    (void *)sp, (void *)hdlr, (uintptr_t)upc);
#endif
	return (0);
}

#ifdef _SYSCALL32_IMPL

/*
 * An i386 SVR4/ABI signal frame looks like this on the stack:
 *
 * old %esp:
 *		<a siginfo32_t [optional]>
 *		<a ucontext32_t>
 *		<pointer to that ucontext32_t>
 *		<pointer to that siginfo32_t>
 *		<signo>
 * new %esp:	<return address (deliberately invalid)>
 */
struct sigframe32 {
	caddr32_t	retaddr;
	uint32_t	signo;
	caddr32_t	sip;
	caddr32_t	ucp;
};

int
sendsig32(int sig, k_siginfo_t *sip, void (*hdlr)())
{
	volatile int minstacksz;
	int newstack;
	label_t ljb;
	volatile caddr_t sp;
	caddr_t fp;
	volatile struct regs *rp;
	volatile greg_t upc;
	volatile proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	ucontext32_t *volatile tuc = NULL;
	ucontext32_t *uc;
	siginfo32_t *sip_addr;
	volatile int watched;

	rp = lwptoregs(lwp);
	upc = rp->r_pc;

	minstacksz = SA32(sizeof (struct sigframe32)) + SA32(sizeof (*uc));
	if (sip != NULL)
		minstacksz += SA32(sizeof (siginfo32_t));
	ASSERT((minstacksz & (STACK_ALIGN32 - 1)) == 0);

	/*
	 * Figure out whether we will be handling this signal on
	 * an alternate stack specified by the user.  Then allocate
	 * and validate the stack requirements for the signal handler
	 * context.  on_fault will catch any faults.
	 */
	newstack = sigismember(&PTOU(curproc)->u_sigonstack, sig) &&
	    !(lwp->lwp_sigaltstack.ss_flags & (SS_ONSTACK|SS_DISABLE));

	if (newstack) {
		fp = (caddr_t)(SA32((uintptr_t)lwp->lwp_sigaltstack.ss_sp) +
		    SA32(lwp->lwp_sigaltstack.ss_size) - STACK_ALIGN32);
	} else if ((rp->r_ss & 0xffff) != UDS_SEL) {
		user_desc_t *ldt;
		/*
		 * If the stack segment selector is -not- pointing at
		 * the UDS_SEL descriptor and we have an LDT entry for
		 * it instead, add the base address to find the effective va.
		 */
		if ((ldt = p->p_ldt) != NULL)
			fp = (caddr_t)rp->r_sp +
			    USEGD_GETBASE(&ldt[SELTOIDX(rp->r_ss)]);
		else
			fp = (caddr_t)rp->r_sp;
	} else
		fp = (caddr_t)rp->r_sp;

	/*
	 * Force proper stack pointer alignment, even in the face of a
	 * misaligned stack pointer from user-level before the signal.
	 * Don't use the SA32() macro because that rounds up, not down.
	 */
	fp = (caddr_t)((uintptr_t)fp & ~(STACK_ALIGN32 - 1));
	sp = fp - minstacksz;

	/*
	 * Make sure lwp hasn't trashed its stack
	 */
	if (sp >= (caddr_t)(uintptr_t)USERLIMIT32 ||
	    fp >= (caddr_t)(uintptr_t)USERLIMIT32) {
#ifdef DEBUG
		printf("sendsig32: bad signal stack cmd=%s, pid=%d, sig=%d\n",
		    PTOU(p)->u_comm, p->p_pid, sig);
		printf("sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
		    (void *)sp, (void *)hdlr, (uintptr_t)upc);
		printf("sp above USERLIMIT\n");
#endif
		return (0);
	}

	watched = watch_disable_addr((caddr_t)sp, minstacksz, S_WRITE);

	if (on_fault(&ljb))
		goto badstack;

	if (sip != NULL) {
		siginfo32_t si32;
		zoneid_t zoneid;

		siginfo_kto32(sip, &si32);
		if (SI_FROMUSER(sip) &&
		    (zoneid = p->p_zone->zone_id) != GLOBAL_ZONEID &&
		    zoneid != sip->si_zoneid) {
			si32.si_pid = p->p_zone->zone_zsched->p_pid;
			si32.si_uid = 0;
			si32.si_ctid = -1;
			si32.si_zoneid = zoneid;
		}
		fp -= SA32(sizeof (si32));
		uzero(fp, sizeof (si32));
		copyout_noerr(&si32, fp, sizeof (si32));
		sip_addr = (siginfo32_t *)fp;

		if (sig == SIGPROF &&
		    curthread->t_rprof != NULL &&
		    curthread->t_rprof->rp_anystate) {
			/*
			 * We stand on our head to deal with
			 * the real-time profiling signal.
			 * Fill in the stuff that doesn't fit
			 * in a normal k_siginfo structure.
			 */
			int i = sip->si_nsysarg;

			while (--i >= 0)
				suword32_noerr(&(sip_addr->si_sysarg[i]),
				    (uint32_t)lwp->lwp_arg[i]);
			copyout_noerr(curthread->t_rprof->rp_state,
			    sip_addr->si_mstate,
			    sizeof (curthread->t_rprof->rp_state));
		}
	} else
		sip_addr = NULL;

	/* save the current context on the user stack */
	fp -= SA32(sizeof (*tuc));
	uc = (ucontext32_t *)fp;
	tuc = kmem_alloc(sizeof (*tuc), KM_SLEEP);
	no_fault();
	savecontext32(tuc, &lwp->lwp_sigoldmask);
	if (on_fault(&ljb))
		goto badstack;
	copyout_noerr(tuc, uc, sizeof (*tuc));
	kmem_free(tuc, sizeof (*tuc));
	tuc = NULL;

	lwp->lwp_oldcontext = (uintptr_t)uc;

	if (newstack) {
		lwp->lwp_sigaltstack.ss_flags |= SS_ONSTACK;
		if (lwp->lwp_ustack) {
			stack32_t stk32;

			stk32.ss_sp = (caddr32_t)(uintptr_t)
			    lwp->lwp_sigaltstack.ss_sp;
			stk32.ss_size = (size32_t)
			    lwp->lwp_sigaltstack.ss_size;
			stk32.ss_flags = (int32_t)
			    lwp->lwp_sigaltstack.ss_flags;
			copyout_noerr(&stk32,
			    (stack32_t *)lwp->lwp_ustack, sizeof (stk32));
		}
	}

	/*
	 * Set up signal handler arguments
	 */
	{
		struct sigframe32 frame32;

		frame32.sip = (caddr32_t)(uintptr_t)sip_addr;
		frame32.ucp = (caddr32_t)(uintptr_t)uc;
		frame32.signo = sig;
		frame32.retaddr = 0xffffffff;	/* never return! */
		copyout_noerr(&frame32, sp, sizeof (frame32));
	}

	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);

	rp->r_sp = (greg_t)(uintptr_t)sp;
	rp->r_pc = (greg_t)(uintptr_t)hdlr;
	rp->r_ps = PSL_USER | (rp->r_ps & PS_IOPL);

	if ((rp->r_cs & 0xffff) != U32CS_SEL ||
	    (rp->r_ss & 0xffff) != UDS_SEL) {
		/*
		 * Try our best to deliver the signal.
		 */
		rp->r_cs = U32CS_SEL;
		rp->r_ss = UDS_SEL;
	}

	/*
	 * Don't set lwp_eosys here.  sendsig() is called via psig() after
	 * lwp_eosys is handled, so setting it here would affect the next
	 * system call.
	 */
	return (1);

badstack:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);
	if (tuc)
		kmem_free(tuc, sizeof (*tuc));
#ifdef DEBUG
	printf("sendsig32: bad signal stack cmd=%s pid=%d, sig=%d\n",
	    PTOU(p)->u_comm, p->p_pid, sig);
	printf("on fault, sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
	    (void *)sp, (void *)hdlr, (uintptr_t)upc);
#endif
	return (0);
}

#endif	/* _SYSCALL32_IMPL */

#elif defined(__i386)

/*
 * An i386 SVR4/ABI signal frame looks like this on the stack:
 *
 * old %esp:
 *		<a siginfo32_t [optional]>
 *		<a ucontext32_t>
 *		<pointer to that ucontext32_t>
 *		<pointer to that siginfo32_t>
 *		<signo>
 * new %esp:	<return address (deliberately invalid)>
 */
struct sigframe {
	void		(*retaddr)();
	uint_t		signo;
	siginfo_t	*sip;
	ucontext_t	*ucp;
};

int
sendsig(int sig, k_siginfo_t *sip, void (*hdlr)())
{
	volatile int minstacksz;
	int newstack;
	label_t ljb;
	volatile caddr_t sp;
	caddr_t fp;
	struct regs *rp;
	volatile greg_t upc;
	volatile proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	ucontext_t *volatile tuc = NULL;
	ucontext_t *uc;
	siginfo_t *sip_addr;
	volatile int watched;

	rp = lwptoregs(lwp);
	upc = rp->r_pc;

	minstacksz = SA(sizeof (struct sigframe)) + SA(sizeof (*uc));
	if (sip != NULL)
		minstacksz += SA(sizeof (siginfo_t));
	ASSERT((minstacksz & (STACK_ALIGN - 1ul)) == 0);

	/*
	 * Figure out whether we will be handling this signal on
	 * an alternate stack specified by the user. Then allocate
	 * and validate the stack requirements for the signal handler
	 * context. on_fault will catch any faults.
	 */
	newstack = sigismember(&PTOU(curproc)->u_sigonstack, sig) &&
	    !(lwp->lwp_sigaltstack.ss_flags & (SS_ONSTACK|SS_DISABLE));

	if (newstack) {
		fp = (caddr_t)(SA((uintptr_t)lwp->lwp_sigaltstack.ss_sp) +
		    SA(lwp->lwp_sigaltstack.ss_size) - STACK_ALIGN);
	} else if ((rp->r_ss & 0xffff) != UDS_SEL) {
		user_desc_t *ldt;
		/*
		 * If the stack segment selector is -not- pointing at
		 * the UDS_SEL descriptor and we have an LDT entry for
		 * it instead, add the base address to find the effective va.
		 */
		if ((ldt = p->p_ldt) != NULL)
			fp = (caddr_t)rp->r_sp +
			    USEGD_GETBASE(&ldt[SELTOIDX(rp->r_ss)]);
		else
			fp = (caddr_t)rp->r_sp;
	} else
		fp = (caddr_t)rp->r_sp;

	/*
	 * Force proper stack pointer alignment, even in the face of a
	 * misaligned stack pointer from user-level before the signal.
	 * Don't use the SA() macro because that rounds up, not down.
	 */
	fp = (caddr_t)((uintptr_t)fp & ~(STACK_ALIGN - 1ul));
	sp = fp - minstacksz;

	/*
	 * Make sure lwp hasn't trashed its stack.
	 */
	if (sp >= (caddr_t)USERLIMIT || fp >= (caddr_t)USERLIMIT) {
#ifdef DEBUG
		printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
		    PTOU(p)->u_comm, p->p_pid, sig);
		printf("sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
		    (void *)sp, (void *)hdlr, (uintptr_t)upc);
		printf("sp above USERLIMIT\n");
#endif
		return (0);
	}

	watched = watch_disable_addr((caddr_t)sp, minstacksz, S_WRITE);

	if (on_fault(&ljb))
		goto badstack;

	if (sip != NULL) {
		zoneid_t zoneid;

		fp -= SA(sizeof (siginfo_t));
		uzero(fp, sizeof (siginfo_t));
		if (SI_FROMUSER(sip) &&
		    (zoneid = p->p_zone->zone_id) != GLOBAL_ZONEID &&
		    zoneid != sip->si_zoneid) {
			k_siginfo_t sani_sip = *sip;

			sani_sip.si_pid = p->p_zone->zone_zsched->p_pid;
			sani_sip.si_uid = 0;
			sani_sip.si_ctid = -1;
			sani_sip.si_zoneid = zoneid;
			copyout_noerr(&sani_sip, fp, sizeof (sani_sip));
		} else
			copyout_noerr(sip, fp, sizeof (*sip));
		sip_addr = (siginfo_t *)fp;

		if (sig == SIGPROF &&
		    curthread->t_rprof != NULL &&
		    curthread->t_rprof->rp_anystate) {
			/*
			 * We stand on our head to deal with
			 * the real time profiling signal.
			 * Fill in the stuff that doesn't fit
			 * in a normal k_siginfo structure.
			 */
			int i = sip->si_nsysarg;

			while (--i >= 0)
				suword32_noerr(&(sip_addr->si_sysarg[i]),
				    (uint32_t)lwp->lwp_arg[i]);
			copyout_noerr(curthread->t_rprof->rp_state,
			    sip_addr->si_mstate,
			    sizeof (curthread->t_rprof->rp_state));
		}
	} else
		sip_addr = NULL;

	/* save the current context on the user stack */
	fp -= SA(sizeof (*tuc));
	uc = (ucontext_t *)fp;
	tuc = kmem_alloc(sizeof (*tuc), KM_SLEEP);
	savecontext(tuc, &lwp->lwp_sigoldmask);
	copyout_noerr(tuc, uc, sizeof (*tuc));
	kmem_free(tuc, sizeof (*tuc));
	tuc = NULL;

	lwp->lwp_oldcontext = (uintptr_t)uc;

	if (newstack) {
		lwp->lwp_sigaltstack.ss_flags |= SS_ONSTACK;
		if (lwp->lwp_ustack)
			copyout_noerr(&lwp->lwp_sigaltstack,
			    (stack_t *)lwp->lwp_ustack, sizeof (stack_t));
	}

	/*
	 * Set up signal handler arguments
	 */
	{
		struct sigframe frame;

		frame.sip = sip_addr;
		frame.ucp = uc;
		frame.signo = sig;
		frame.retaddr = (void (*)())0xffffffff;	/* never return! */
		copyout_noerr(&frame, sp, sizeof (frame));
	}

	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);

	rp->r_sp = (greg_t)sp;
	rp->r_pc = (greg_t)hdlr;
	rp->r_ps = PSL_USER | (rp->r_ps & PS_IOPL);

	if ((rp->r_cs & 0xffff) != UCS_SEL ||
	    (rp->r_ss & 0xffff) != UDS_SEL) {
		rp->r_cs = UCS_SEL;
		rp->r_ss = UDS_SEL;
	}

	/*
	 * Don't set lwp_eosys here.  sendsig() is called via psig() after
	 * lwp_eosys is handled, so setting it here would affect the next
	 * system call.
	 */
	return (1);

badstack:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, minstacksz, S_WRITE);
	if (tuc)
		kmem_free(tuc, sizeof (*tuc));
#ifdef DEBUG
	printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
	    PTOU(p)->u_comm, p->p_pid, sig);
	printf("on fault, sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
	    (void *)sp, (void *)hdlr, (uintptr_t)upc);
#endif
	return (0);
}

#endif	/* __i386 */

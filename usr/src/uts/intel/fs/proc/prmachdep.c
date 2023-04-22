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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/psw.h>
#include <sys/pcb.h>
#include <sys/buf.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/cpuvar.h>
#include <sys/stdalign.h>

#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/cmn_err.h>
#include <sys/stack.h>
#include <sys/debugreg.h>
#include <sys/copyops.h>

#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vmparam.h>
#include <sys/fp.h>
#include <sys/archsystm.h>
#include <sys/vmsystm.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <vm/page.h>

#include <sys/sysi86.h>

#include <fs/proc/prdata.h>

int	prnwatch = 10000;	/* maximum number of watched areas */

/*
 * Force a thread into the kernel if it is not already there.
 * This is a no-op on uniprocessors.
 */
/* ARGSUSED */
void
prpokethread(kthread_t *t)
{
	if (t->t_state == TS_ONPROC && t->t_cpu != CPU)
		poke_cpu(t->t_cpu->cpu_id);
}

/*
 * Return general registers.
 */
void
prgetprregs(klwp_t *lwp, prgregset_t prp)
{
	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	getgregs(lwp, prp);
}

/*
 * Set general registers.
 * (Note: This can be an alias to setgregs().)
 */
void
prsetprregs(klwp_t *lwp, prgregset_t prp, int initial)
{
	if (initial)		/* set initial values */
		lwptoregs(lwp)->r_ps = PSL_USER;
	(void) setgregs(lwp, prp);
}

#ifdef _SYSCALL32_IMPL

/*
 * Convert prgregset32 to native prgregset
 */
void
prgregset_32ton(klwp_t *lwp, prgregset32_t src, prgregset_t dst)
{
	struct regs *rp = lwptoregs(lwp);

	dst[REG_GSBASE] = lwp->lwp_pcb.pcb_gsbase;
	dst[REG_FSBASE] = lwp->lwp_pcb.pcb_fsbase;

	dst[REG_DS] = (uint16_t)src[DS];
	dst[REG_ES] = (uint16_t)src[ES];

	dst[REG_GS] = (uint16_t)src[GS];
	dst[REG_FS] = (uint16_t)src[FS];
	dst[REG_SS] = (uint16_t)src[SS];
	dst[REG_RSP] = (uint32_t)src[UESP];
	dst[REG_RFL] =
	    (rp->r_ps & ~PSL_USERMASK) | (src[EFL] & PSL_USERMASK);
	dst[REG_CS] = (uint16_t)src[CS];
	dst[REG_RIP] = (uint32_t)src[EIP];
	dst[REG_ERR] = (uint32_t)src[ERR];
	dst[REG_TRAPNO] = (uint32_t)src[TRAPNO];
	dst[REG_RAX] = (uint32_t)src[EAX];
	dst[REG_RCX] = (uint32_t)src[ECX];
	dst[REG_RDX] = (uint32_t)src[EDX];
	dst[REG_RBX] = (uint32_t)src[EBX];
	dst[REG_RBP] = (uint32_t)src[EBP];
	dst[REG_RSI] = (uint32_t)src[ESI];
	dst[REG_RDI] = (uint32_t)src[EDI];
	dst[REG_R8] = dst[REG_R9] = dst[REG_R10] = dst[REG_R11] =
	    dst[REG_R12] = dst[REG_R13] = dst[REG_R14] = dst[REG_R15] = 0;
}

/*
 * Return 32-bit general registers
 */
void
prgetprregs32(klwp_t *lwp, prgregset32_t prp)
{
	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));
	getgregs32(lwp, prp);
}

#endif	/* _SYSCALL32_IMPL */

/*
 * Get the syscall return values for the lwp.
 */
int
prgetrvals(klwp_t *lwp, long *rval1, long *rval2)
{
	struct regs *r = lwptoregs(lwp);

	if (r->r_ps & PS_C)
		return (r->r_r0);
	if (lwp->lwp_eosys == JUSTRETURN) {
		*rval1 = 0;
		*rval2 = 0;
	} else if (lwp_getdatamodel(lwp) != DATAMODEL_NATIVE) {
		/*
		 * XX64	Not sure we -really- need to do this, because the
		 *	syscall return already masks off the bottom values ..?
		 */
		*rval1 = r->r_r0 & (uint32_t)0xffffffffu;
		*rval2 = r->r_r1 & (uint32_t)0xffffffffu;
	} else {
		*rval1 = r->r_r0;
		*rval2 = r->r_r1;
	}
	return (0);
}

/*
 * Does the system support floating-point, either through hardware
 * or by trapping and emulating floating-point machine instructions?
 */
int
prhasfp(void)
{
	extern int fp_kind;

	return (fp_kind != FP_NO);
}

/*
 * Get floating-point registers.
 */
void
prgetprfpregs(klwp_t *lwp, prfpregset_t *pfp)
{
	bzero(pfp, sizeof (prfpregset_t));
	getfpregs(lwp, pfp);
}

#if defined(_SYSCALL32_IMPL)
void
prgetprfpregs32(klwp_t *lwp, prfpregset32_t *pfp)
{
	bzero(pfp, sizeof (*pfp));
	getfpregs32(lwp, pfp);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Set floating-point registers.
 * (Note: This can be an alias to setfpregs().)
 */
void
prsetprfpregs(klwp_t *lwp, prfpregset_t *pfp)
{
	setfpregs(lwp, pfp);
}

#if defined(_SYSCALL32_IMPL)
void
prsetprfpregs32(klwp_t *lwp, prfpregset32_t *pfp)
{
	setfpregs32(lwp, pfp);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * This is a general function that the main part of /proc and the rest of the
 * system uses to ask does a given process actually have extended state. Right
 * now, this question is not process-specific, but rather CPU specific. We look
 * at whether xsave has been enabled to determine that. While strictly speaking
 * one could make the argument that all amd64 CPUs support fxsave and we could
 * emulate something that only supports that, we don't think that makes sense.
 */
int
prhasx(proc_t *p)
{
	return (fpu_xsave_enabled());
}

/*
 * Return the minimum size that we need to determine the full size of a
 * prxregset_t.
 */
boolean_t
prwriteminxreg(size_t *sizep)
{
	*sizep = sizeof (prxregset_hdr_t);
	return (B_TRUE);
}

/*
 * This routine services both ILP32 and LP64 callers. We cannot assume anything
 * about the alignment of argp and must bcopy things to known structures that we
 * care about. We are guaranteed to have prxregset_hdr_t bytes because we asked
 * for them above.
 */
boolean_t
prwritesizexreg(const void *argp, size_t *sizep)
{
	prxregset_hdr_t hdr;

	/*
	 * While it's tempting to validate everything here, the only thing we
	 * care about is that we understand the type and the size meets our
	 * constraints:
	 *
	 *  o We actually have an item of type PR_TYPE_XSAVE, otherwise we
	 *    don't know what this is.
	 *  o The indicated size actually contains at least the
	 *    prxregset_hdr_t.
	 *  o The indicated size isn't larger than what the FPU tells us is
	 *    allowed.
	 *
	 * We do not check if the reset of the structure makes semantic sense at
	 * this point. We save all other validation for the normal set function
	 * as that's when we'll have the rest of our data.
	 */
	bcopy(argp, &hdr, sizeof (hdr));
	if (hdr.pr_type != PR_TYPE_XSAVE ||
	    hdr.pr_size > fpu_proc_xregs_max_size() ||
	    hdr.pr_size < sizeof (prxregset_hdr_t)) {
		return (B_FALSE);
	}

	*sizep = hdr.pr_size - sizeof (prxregset_hdr_t);
	return (B_TRUE);
}

/*
 * Get the size of the extra registers. The ultimate size here depends on a
 * combination of a few different things. Right now the xregs always have our
 * header, the illumos-specific XCR information, the xsave information, and then
 * otherwise this varies based on the items that the CPU supports.
 *
 * The ultimate size here is going to be:
 *
 *  o 1x prxregset_hdr_t
 *  o n  prxregset_info_t structures
 *  o The individual data for each one
 */
size_t
prgetprxregsize(proc_t *p)
{
	uint32_t size;

	fpu_proc_xregs_info(p, NULL, &size, NULL);
	return (size);
}

/*
 * Get extra registers.
 */
void
prgetprxregs(klwp_t *lwp, prxregset_t *prx)
{
	fpu_proc_xregs_get(lwp, prx);
}

/*
 * Set extra registers.
 *
 * We've been given a regset to set. Before we hand it off to the FPU, we have
 * to go through and make sure that the different parts of this actually make
 * sense. The kernel has guaranteed us through the functions above that we have
 * the number of bytes that the header indicates are present. In particular we
 * need to validate:
 *
 *   o The information in the header is reasonable: we have a known type, flags
 *     and padding are zero, and there is at least one info structure.
 *   o Each of the info structures has a valid type, size, and fits within the
 *     data we were given.
 *   o We do not validate or modify the actual data in the different pieces for
 *     validity. That is considered something that the FPU does. Similarly if
 *     something is read-only or not used, that is something that it checks.
 *
 * While we would like to return something other than EINVAL, the /proc APIs
 * pretty much lead that to being the primary errno for all sorts of situations.
 */
int
prsetprxregs(klwp_t *lwp, prxregset_t *prx)
{
	size_t infosz;
	prxregset_hdr_t *hdr = (prxregset_hdr_t *)prx;

	if (hdr->pr_type != PR_TYPE_XSAVE || hdr->pr_flags != 0 ||
	    hdr->pr_pad[0] != 0 || hdr->pr_pad[1] != 0 || hdr->pr_pad[2] != 0 ||
	    hdr->pr_pad[3] != 0 || hdr->pr_ninfo == 0) {
		return (EINVAL);
	}

	infosz = hdr->pr_ninfo * sizeof (prxregset_info_t) +
	    sizeof (prxregset_hdr_t);
	if (infosz > hdr->pr_size) {
		return (EINVAL);
	}

	for (uint32_t i = 0; i < hdr->pr_ninfo; i++) {
		uint32_t exp_size;
		size_t need_len, exp_align;
		const prxregset_info_t *info = &hdr->pr_info[i];

		switch (info->pri_type) {
		case PRX_INFO_XCR:
			exp_size = sizeof (prxregset_xcr_t);
			exp_align = alignof (prxregset_xcr_t);
			break;
		case PRX_INFO_XSAVE:
			exp_size = sizeof (prxregset_xsave_t);
			exp_align = alignof (prxregset_xsave_t);
			break;
		case PRX_INFO_YMM:
			exp_size = sizeof (prxregset_ymm_t);
			exp_align = alignof (prxregset_ymm_t);
			break;
		case PRX_INFO_OPMASK:
			exp_size = sizeof (prxregset_opmask_t);
			exp_align = alignof (prxregset_opmask_t);
			break;
		case PRX_INFO_ZMM:
			exp_size = sizeof (prxregset_zmm_t);
			exp_align = alignof (prxregset_zmm_t);
			break;
		case PRX_INFO_HI_ZMM:
			exp_size = sizeof (prxregset_hi_zmm_t);
			exp_align = alignof (prxregset_hi_zmm_t);
			break;
		default:
			return (EINVAL);
		}

		if (info->pri_flags != 0 || info->pri_size != exp_size) {
			return (EINVAL);
		}

		if ((info->pri_offset % exp_align) != 0) {
			return (EINVAL);
		}

		/*
		 * No bytes of this item's entry should overlap with the
		 * information area. If users want to overlap the actual data
		 * information for some odd reason, we don't check that and let
		 * them do what they want. However, the total data for this
		 * region must actually fit. Because exp_size and pri_offset are
		 * uint32_t's, we can sum them without overflow worries in an
		 * LP64 environment.
		 *
		 * While we try to grantee alignment when writing this structure
		 * out to userland, that is in no way a requirement and users
		 * are allowed to start these structures wherever they want.
		 * Hence that is not checked here.
		 */
		need_len = (size_t)exp_size + (size_t)info->pri_offset;
		if (info->pri_offset < infosz ||
		    need_len > (size_t)hdr->pr_size) {
			return (EINVAL);
		}
	}

	return (fpu_proc_xregs_set(lwp, prx));
}

/*
 * Return the base (lower limit) of the process stack.
 */
caddr_t
prgetstackbase(proc_t *p)
{
	return (p->p_usrstack - p->p_stksize);
}

/*
 * Return the "addr" field for pr_addr in prpsinfo_t.
 * This is a vestige of the past, so whatever we return is OK.
 */
caddr_t
prgetpsaddr(proc_t *p)
{
	return ((caddr_t)p);
}

/*
 * Arrange to single-step the lwp.
 */
void
prstep(klwp_t *lwp, int watchstep)
{
	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	/*
	 * flag LWP so that its r_efl trace bit (PS_T) will be set on
	 * next return to usermode.
	 */
	lwp->lwp_pcb.pcb_flags |= REQUEST_STEP;
	lwp->lwp_pcb.pcb_flags &= ~REQUEST_NOSTEP;

	if (watchstep)
		lwp->lwp_pcb.pcb_flags |= WATCH_STEP;
	else
		lwp->lwp_pcb.pcb_flags |= NORMAL_STEP;

	aston(lwptot(lwp));	/* let trap() set PS_T in rp->r_efl */
}

/*
 * Undo prstep().
 */
void
prnostep(klwp_t *lwp)
{
	ASSERT(ttolwp(curthread) == lwp ||
	    MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	/*
	 * flag LWP so that its r_efl trace bit (PS_T) will be cleared on
	 * next return to usermode.
	 */
	lwp->lwp_pcb.pcb_flags |= REQUEST_NOSTEP;

	lwp->lwp_pcb.pcb_flags &=
	    ~(REQUEST_STEP|NORMAL_STEP|WATCH_STEP|DEBUG_PENDING);

	aston(lwptot(lwp));	/* let trap() clear PS_T in rp->r_efl */
}

/*
 * Return non-zero if a single-step is in effect.
 */
int
prisstep(klwp_t *lwp)
{
	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	return ((lwp->lwp_pcb.pcb_flags &
	    (NORMAL_STEP|WATCH_STEP|DEBUG_PENDING)) != 0);
}

/*
 * Set the PC to the specified virtual address.
 */
void
prsvaddr(klwp_t *lwp, caddr_t vaddr)
{
	struct regs *r = lwptoregs(lwp);

	ASSERT(MUTEX_NOT_HELD(&lwptoproc(lwp)->p_lock));

	r->r_pc = (uintptr_t)vaddr;
}

/*
 * Map address "addr" in address space "as" into a kernel virtual address.
 * The memory is guaranteed to be resident and locked down.
 */
caddr_t
prmapin(struct as *as, caddr_t addr, int writing)
{
	page_t *pp;
	caddr_t kaddr;
	pfn_t pfnum;

	/*
	 * XXX - Because of past mistakes, we have bits being returned
	 * by getpfnum that are actually the page type bits of the pte.
	 * When the object we are trying to map is a memory page with
	 * a page structure everything is ok and we can use the optimal
	 * method, ppmapin.  Otherwise, we have to do something special.
	 */
	pfnum = hat_getpfnum(as->a_hat, addr);
	if (pf_is_memory(pfnum)) {
		pp = page_numtopp_nolock(pfnum);
		if (pp != NULL) {
			ASSERT(PAGE_LOCKED(pp));
			kaddr = ppmapin(pp, writing ?
			    (PROT_READ | PROT_WRITE) : PROT_READ, (caddr_t)-1);
			return (kaddr + ((uintptr_t)addr & PAGEOFFSET));
		}
	}

	/*
	 * Oh well, we didn't have a page struct for the object we were
	 * trying to map in; ppmapin doesn't handle devices, but allocating a
	 * heap address allows ppmapout to free virtual space when done.
	 */
	kaddr = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	hat_devload(kas.a_hat, kaddr, MMU_PAGESIZE,  pfnum,
	    writing ? (PROT_READ | PROT_WRITE) : PROT_READ, 0);

	return (kaddr + ((uintptr_t)addr & PAGEOFFSET));
}

/*
 * Unmap address "addr" in address space "as"; inverse of prmapin().
 */
/* ARGSUSED */
void
prmapout(struct as *as, caddr_t addr, caddr_t vaddr, int writing)
{
	extern void ppmapout(caddr_t);

	vaddr = (caddr_t)((uintptr_t)vaddr & PAGEMASK);
	ppmapout(vaddr);
}

/*
 * Make sure the lwp is in an orderly state
 * for inspection by a debugger through /proc.
 *
 * This needs to be called only once while the current thread remains in the
 * kernel and needs to be called while holding no resources (mutex locks, etc).
 *
 * As a hedge against these conditions, if prstop() is called repeatedly
 * before prunstop() is called, it does nothing and just returns.
 *
 * prunstop() must be called before the thread returns to user level.
 */
/* ARGSUSED */
void
prstop(int why, int what)
{
	klwp_t *lwp = ttolwp(curthread);
	struct regs *r = lwptoregs(lwp);

	if (lwp->lwp_pcb.pcb_flags & PRSTOP_CALLED)
		return;

	/*
	 * Make sure we don't deadlock on a recursive call
	 * to prstop().  stop() tests the lwp_nostop flag.
	 */
	ASSERT(lwp->lwp_nostop == 0);
	lwp->lwp_nostop = 1;

	if (copyin_nowatch((caddr_t)r->r_pc, &lwp->lwp_pcb.pcb_instr,
	    sizeof (lwp->lwp_pcb.pcb_instr)) == 0)
		lwp->lwp_pcb.pcb_flags |= INSTR_VALID;
	else {
		lwp->lwp_pcb.pcb_flags &= ~INSTR_VALID;
		lwp->lwp_pcb.pcb_instr = 0;
	}

	(void) save_syscall_args();
	ASSERT(lwp->lwp_nostop == 1);
	lwp->lwp_nostop = 0;

	lwp->lwp_pcb.pcb_flags |= PRSTOP_CALLED;
	aston(curthread);	/* so prunstop() will be called */
}

/*
 * Inform prstop() that it should do its work again
 * the next time it is called.
 */
void
prunstop(void)
{
	ttolwp(curthread)->lwp_pcb.pcb_flags &= ~PRSTOP_CALLED;
}

/*
 * Fetch the user-level instruction on which the lwp is stopped.
 * It was saved by the lwp itself, in prstop().
 * Return non-zero if the instruction is valid.
 */
int
prfetchinstr(klwp_t *lwp, ulong_t *ip)
{
	*ip = (ulong_t)(instr_t)lwp->lwp_pcb.pcb_instr;
	return (lwp->lwp_pcb.pcb_flags & INSTR_VALID);
}

/*
 * Called from trap() when a load or store instruction
 * falls in a watched page but is not a watchpoint.
 * We emulate the instruction in the kernel.
 */
/* ARGSUSED */
int
pr_watch_emul(struct regs *rp, caddr_t addr, enum seg_rw rw)
{
#ifdef SOMEDAY
	int res;
	proc_t *p = curproc;
	char *badaddr = (caddr_t)(-1);
	int mapped;

	/* prevent recursive calls to pr_watch_emul() */
	ASSERT(!(curthread->t_flag & T_WATCHPT));
	curthread->t_flag |= T_WATCHPT;

	watch_disable_addr(addr, 8, rw);
	res = do_unaligned(rp, &badaddr);
	watch_enable_addr(addr, 8, rw);

	curthread->t_flag &= ~T_WATCHPT;
	if (res == SIMU_SUCCESS) {
		/* adjust the pc */
		return (1);
	}
#endif
	return (0);
}

/*
 * Return the number of active entries in the local descriptor table.
 */
int
prnldt(proc_t *p)
{
	int limit, i, n;
	user_desc_t *udp;

	ASSERT(MUTEX_HELD(&p->p_ldtlock));

	/*
	 * Currently 64 bit processes cannot have private LDTs.
	 */
	ASSERT(p->p_model != DATAMODEL_LP64 || p->p_ldt == NULL);

	if (p->p_ldt == NULL)
		return (0);
	n = 0;
	limit = p->p_ldtlimit;
	ASSERT(limit >= 0 && limit < MAXNLDT);

	/*
	 * Count all present user descriptors.
	 */
	for (i = LDT_UDBASE, udp = &p->p_ldt[i]; i <= limit; i++, udp++)
		if (udp->usd_type != 0 || udp->usd_dpl != 0 || udp->usd_p != 0)
			n++;
	return (n);
}

/*
 * Fetch the active entries from the local descriptor table.
 */
void
prgetldt(proc_t *p, struct ssd *ssd)
{
	int i, limit;
	user_desc_t *udp;

	ASSERT(MUTEX_HELD(&p->p_ldtlock));

	if (p->p_ldt == NULL)
		return;

	limit = p->p_ldtlimit;
	ASSERT(limit >= 0 && limit < MAXNLDT);

	/*
	 * All present user descriptors.
	 */
	for (i = LDT_UDBASE, udp = &p->p_ldt[i]; i <= limit; i++, udp++)
		if (udp->usd_type != 0 || udp->usd_dpl != 0 ||
		    udp->usd_p != 0)
			usd_to_ssd(udp, ssd++, SEL_LDT(i));
}

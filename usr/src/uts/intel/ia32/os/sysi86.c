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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/cpuvar.h>
#include <sys/sysi86.h>
#include <sys/psw.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/thread.h>
#include <sys/debug.h>
#include <sys/ontrap.h>
#include <sys/privregs.h>
#include <sys/x86_archext.h>
#include <sys/vmem.h>
#include <sys/kmem.h>
#include <sys/mman.h>
#include <sys/archsystm.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/faultcode.h>
#include <sys/fp.h>
#include <sys/cmn_err.h>
#include <sys/segments.h>
#include <sys/clock.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#include <sys/note.h>
#endif

static void ldt_alloc(proc_t *, uint_t);
static void ldt_free(proc_t *);
static void ldt_dup(proc_t *, proc_t *);
static void ldt_grow(proc_t *, uint_t);

/*
 * sysi86 System Call
 */

/* ARGSUSED */
int
sysi86(short cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	struct ssd ssd;
	int error = 0;
	int c;
	proc_t *pp = curproc;

	switch (cmd) {

	/*
	 * The SI86V86 subsystem call of the SYSI86 system call
	 * supports only one subcode -- V86SC_IOPL.
	 */
	case SI86V86:
		if (arg1 == V86SC_IOPL) {
			struct regs *rp = lwptoregs(ttolwp(curthread));
			greg_t oldpl = rp->r_ps & PS_IOPL;
			greg_t newpl = arg2 & PS_IOPL;

			/*
			 * Must be privileged to run this system call
			 * if giving more io privilege.
			 */
			if (newpl > oldpl && (error =
			    secpolicy_sys_config(CRED(), B_FALSE)) != 0)
				return (set_errno(error));
#if defined(__xpv)
			kpreempt_disable();
			installctx(curthread, NULL, xen_disable_user_iopl,
			    xen_enable_user_iopl, NULL, NULL,
			    xen_disable_user_iopl, NULL);
			xen_enable_user_iopl();
			kpreempt_enable();
#else
			rp->r_ps ^= oldpl ^ newpl;
#endif
		} else
			error = EINVAL;
		break;

	/*
	 * Set a segment descriptor
	 */
	case SI86DSCR:
		/*
		 * There are considerable problems here manipulating
		 * resources shared by many running lwps.  Get everyone
		 * into a safe state before changing the LDT.
		 */
		if (curthread != pp->p_agenttp && !holdlwps(SHOLDFORK1)) {
			error = EINTR;
			break;
		}

		if (get_udatamodel() == DATAMODEL_LP64) {
			error = EINVAL;
			break;
		}

		if (copyin((caddr_t)arg1, &ssd, sizeof (ssd)) < 0) {
			error = EFAULT;
			break;
		}

		error = setdscr(&ssd);

		mutex_enter(&pp->p_lock);
		if (curthread != pp->p_agenttp)
			continuelwps(pp);
		mutex_exit(&pp->p_lock);
		break;

	case SI86FPHW:
		c = fp_kind & 0xff;
		if (suword32((void *)arg1, c) == -1)
			error = EFAULT;
		break;

	case SI86FPSTART:
		/*
		 * arg1 is the address of _fp_hw
		 * arg2 is the desired x87 FCW value
		 * arg3 is the desired SSE MXCSR value
		 * a return value of one means SSE hardware, else none.
		 */
		c = fp_kind & 0xff;
		if (suword32((void *)arg1, c) == -1) {
			error = EFAULT;
			break;
		}
		fpsetcw((uint16_t)arg2, (uint32_t)arg3);
		return ((fp_kind & __FP_SSE) ? 1 : 0);

	/* real time clock management commands */

	case WTODC:
		if ((error = secpolicy_settime(CRED())) == 0) {
			timestruc_t ts;
			mutex_enter(&tod_lock);
			gethrestime(&ts);
			tod_set(ts);
			mutex_exit(&tod_lock);
		}
		break;

/* Give some timezone playing room */
#define	ONEWEEK	(7 * 24 * 60 * 60)

	case SGMTL:
		/*
		 * Called from 32 bit land, negative values
		 * are not sign extended, so we do that here
		 * by casting it to an int and back.  We also
		 * clamp the value to within reason and detect
		 * when a 64 bit call overflows an int.
		 */
		if ((error = secpolicy_settime(CRED())) == 0) {
			int newlag = (int)arg1;

#ifdef _SYSCALL32_IMPL
			if (get_udatamodel() == DATAMODEL_NATIVE &&
			    (long)newlag != (long)arg1) {
				error = EOVERFLOW;
			} else
#endif
			if (newlag >= -ONEWEEK && newlag <= ONEWEEK)
				sgmtl(newlag);
			else
				error = EOVERFLOW;
		}
		break;

	case GGMTL:
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (sulword((void *)arg1, ggmtl()) == -1)
				error = EFAULT;
#ifdef _SYSCALL32_IMPL
		} else {
			time_t gmtl;

			if ((gmtl = ggmtl()) > INT32_MAX) {
				/*
				 * Since gmt_lag can at most be
				 * +/- 12 hours, something is
				 * *seriously* messed up here.
				 */
				error = EOVERFLOW;
			} else if (suword32((void *)arg1, (int32_t)gmtl) == -1)
				error = EFAULT;
#endif
		}
		break;

	case RTCSYNC:
		if ((error = secpolicy_settime(CRED())) == 0)
			rtcsync();
		break;

	/* END OF real time clock management commands */

	default:
		error = EINVAL;
		break;
	}
	return (error == 0 ? 0 : set_errno(error));
}

void
usd_to_ssd(user_desc_t *usd, struct ssd *ssd, selector_t sel)
{
	ssd->bo = USEGD_GETBASE(usd);
	ssd->ls = USEGD_GETLIMIT(usd);
	ssd->sel = sel;

	/*
	 * set type, dpl and present bits.
	 */
	ssd->acc1 = usd->usd_type;
	ssd->acc1 |= usd->usd_dpl << 5;
	ssd->acc1 |= usd->usd_p << (5 + 2);

	/*
	 * set avl, DB and granularity bits.
	 */
	ssd->acc2 = usd->usd_avl;

#if defined(__amd64)
	ssd->acc2 |= usd->usd_long << 1;
#else
	ssd->acc2 |= usd->usd_reserved << 1;
#endif

	ssd->acc2 |= usd->usd_def32 << (1 + 1);
	ssd->acc2 |= usd->usd_gran << (1 + 1 + 1);
}

static void
ssd_to_usd(struct ssd *ssd, user_desc_t *usd)
{

	ASSERT(bcmp(usd, &null_udesc, sizeof (*usd)) == 0);

	USEGD_SETBASE(usd, ssd->bo);
	USEGD_SETLIMIT(usd, ssd->ls);

	/*
	 * set type, dpl and present bits.
	 */
	usd->usd_type = ssd->acc1;
	usd->usd_dpl = ssd->acc1 >> 5;
	usd->usd_p = ssd->acc1 >> (5 + 2);

	ASSERT(usd->usd_type >= SDT_MEMRO);
	ASSERT(usd->usd_dpl == SEL_UPL);

	/*
	 * 64-bit code selectors are never allowed in the LDT.
	 * Reserved bit is always 0 on 32-bit systems.
	 */
#if defined(__amd64)
	usd->usd_long = 0;
#else
	usd->usd_reserved = 0;
#endif

	/*
	 * set avl, DB and granularity bits.
	 */
	usd->usd_avl = ssd->acc2;
	usd->usd_def32 = ssd->acc2 >> (1 + 1);
	usd->usd_gran = ssd->acc2 >> (1 + 1 + 1);
}


#if defined(__i386)

static void
ssd_to_sgd(struct ssd *ssd, gate_desc_t *sgd)
{

	ASSERT(bcmp(sgd, &null_sdesc, sizeof (*sgd)) == 0);

	sgd->sgd_looffset = ssd->bo;
	sgd->sgd_hioffset = ssd->bo >> 16;

	sgd->sgd_selector = ssd->ls;

	/*
	 * set type, dpl and present bits.
	 */
	sgd->sgd_type = ssd->acc1;
	sgd->sgd_dpl = ssd->acc1 >> 5;
	sgd->sgd_p = ssd->acc1 >> 7;
	ASSERT(sgd->sgd_type == SDT_SYSCGT);
	ASSERT(sgd->sgd_dpl == SEL_UPL);
	sgd->sgd_stkcpy = 0;
}

#endif	/* __i386 */

/*
 * Load LDT register with the current process's LDT.
 */
static void
ldt_load(void)
{
#if defined(__xpv)
	xen_set_ldt(get_ssd_base(&curproc->p_ldt_desc),
	    curproc->p_ldtlimit + 1);
#else
	*((system_desc_t *)&CPU->cpu_gdt[GDT_LDT]) = curproc->p_ldt_desc;
	wr_ldtr(ULDT_SEL);
#endif
}

/*
 * Store a NULL selector in the LDTR. All subsequent illegal references to
 * the LDT will result in a #gp.
 */
void
ldt_unload(void)
{
#if defined(__xpv)
	xen_set_ldt(NULL, 0);
#else
	*((system_desc_t *)&CPU->cpu_gdt[GDT_LDT]) = null_sdesc;
	wr_ldtr(0);
#endif
}

/*ARGSUSED*/
static void
ldt_savectx(proc_t *p)
{
	ASSERT(p->p_ldt != NULL);
	ASSERT(p == curproc);

#if defined(__amd64)
	/*
	 * The 64-bit kernel must be sure to clear any stale ldt
	 * selectors when context switching away from a process that
	 * has a private ldt. Consider the following example:
	 *
	 * 	Wine creats a ldt descriptor and points a segment register
	 * 	to it.
	 *
	 *	We then context switch away from wine lwp to kernel
	 *	thread and hit breakpoint in kernel with kmdb
	 *
	 *	When we continue and resume from kmdb we will #gp
	 * 	fault since kmdb will have saved the stale ldt selector
	 *	from wine and will try to restore it but we are no longer in
	 *	the context of the wine process and do not have our
	 *	ldtr register pointing to the private ldt.
	 */
	reset_sregs();
#endif

	ldt_unload();
	cpu_fast_syscall_enable(NULL);
}

static void
ldt_restorectx(proc_t *p)
{
	ASSERT(p->p_ldt != NULL);
	ASSERT(p == curproc);

	ldt_load();
	cpu_fast_syscall_disable(NULL);
}

/*
 * When a process with a private LDT execs, fast syscalls must be enabled for
 * the new process image.
 */
/* ARGSUSED */
static void
ldt_freectx(proc_t *p, int isexec)
{
	ASSERT(p->p_ldt);

	if (isexec) {
		kpreempt_disable();
		cpu_fast_syscall_enable(NULL);
		kpreempt_enable();
	}

	/*
	 * ldt_free() will free the memory used by the private LDT, reset the
	 * process's descriptor, and re-program the LDTR.
	 */
	ldt_free(p);
}

/*
 * Install ctx op that ensures syscall/sysenter are disabled.
 * See comments below.
 *
 * When a thread with a private LDT forks, the new process
 * must have the LDT context ops installed.
 */
/* ARGSUSED */
static void
ldt_installctx(proc_t *p, proc_t *cp)
{
	proc_t		*targ = p;
	kthread_t	*t;

	/*
	 * If this is a fork, operate on the child process.
	 */
	if (cp != NULL) {
		targ = cp;
		ldt_dup(p, cp);
	}

	/*
	 * The process context ops expect the target process as their argument.
	 */
	ASSERT(removepctx(targ, targ, ldt_savectx, ldt_restorectx,
	    ldt_installctx, ldt_savectx, ldt_freectx) == 0);

	installpctx(targ, targ, ldt_savectx, ldt_restorectx,
	    ldt_installctx, ldt_savectx, ldt_freectx);

	/*
	 * We've just disabled fast system call and return instructions; take
	 * the slow path out to make sure we don't try to use one to return
	 * back to user. We must set t_post_sys for every thread in the
	 * process to make sure none of them escape out via fast return.
	 */

	mutex_enter(&targ->p_lock);
	t = targ->p_tlist;
	do {
		t->t_post_sys = 1;
	} while ((t = t->t_forw) != targ->p_tlist);
	mutex_exit(&targ->p_lock);
}

int
setdscr(struct ssd *ssd)
{
	ushort_t seli; 		/* selector index */
	user_desc_t *ldp;	/* descriptor pointer */
	user_desc_t ndesc;	/* new descriptor */
	proc_t	*pp = ttoproc(curthread);
	int	rc = 0;

	/*
	 * LDT segments: executable and data at DPL 3 only.
	 */
	if (!SELISLDT(ssd->sel) || !SELISUPL(ssd->sel))
		return (EINVAL);

	/*
	 * check the selector index.
	 */
	seli = SELTOIDX(ssd->sel);
	if (seli >= MAXNLDT || seli < LDT_UDBASE)
		return (EINVAL);

	ndesc = null_udesc;
	mutex_enter(&pp->p_ldtlock);

	/*
	 * If this is the first time for this process then setup a
	 * private LDT for it.
	 */
	if (pp->p_ldt == NULL) {
		ldt_alloc(pp, seli);

		/*
		 * Now that this process has a private LDT, the use of
		 * the syscall/sysret and sysenter/sysexit instructions
		 * is forbidden for this processes because they destroy
		 * the contents of %cs and %ss segment registers.
		 *
		 * Explicity disable them here and add a context handler
		 * to the process. Note that disabling
		 * them here means we can't use sysret or sysexit on
		 * the way out of this system call - so we force this
		 * thread to take the slow path (which doesn't make use
		 * of sysenter or sysexit) back out.
		 */
		kpreempt_disable();
		ldt_installctx(pp, NULL);
		cpu_fast_syscall_disable(NULL);
		ASSERT(curthread->t_post_sys != 0);
		kpreempt_enable();

	} else if (seli > pp->p_ldtlimit) {

		/*
		 * Increase size of ldt to include seli.
		 */
		ldt_grow(pp, seli);
	}

	ASSERT(seli <= pp->p_ldtlimit);
	ldp = &pp->p_ldt[seli];

	/*
	 * On the 64-bit kernel, this is where things get more subtle.
	 * Recall that in the 64-bit kernel, when we enter the kernel we
	 * deliberately -don't- reload the segment selectors we came in on
	 * for %ds, %es, %fs or %gs. Messing with selectors is expensive,
	 * and the underlying descriptors are essentially ignored by the
	 * hardware in long mode - except for the base that we override with
	 * the gsbase MSRs.
	 *
	 * However, there's one unfortunate issue with this rosy picture --
	 * a descriptor that's not marked as 'present' will still generate
	 * an #np when loading a segment register.
	 *
	 * Consider this case.  An lwp creates a harmless LDT entry, points
	 * one of it's segment registers at it, then tells the kernel (here)
	 * to delete it.  In the 32-bit kernel, the #np will happen on the
	 * way back to userland where we reload the segment registers, and be
	 * handled in kern_gpfault().  In the 64-bit kernel, the same thing
	 * will happen in the normal case too.  However, if we're trying to
	 * use a debugger that wants to save and restore the segment registers,
	 * and the debugger things that we have valid segment registers, we
	 * have the problem that the debugger will try and restore the
	 * segment register that points at the now 'not present' descriptor
	 * and will take a #np right there.
	 *
	 * We should obviously fix the debugger to be paranoid about
	 * -not- restoring segment registers that point to bad descriptors;
	 * however we can prevent the problem here if we check to see if any
	 * of the segment registers are still pointing at the thing we're
	 * destroying; if they are, return an error instead. (That also seems
	 * a lot better failure mode than SIGKILL and a core file
	 * from kern_gpfault() too.)
	 */
	if (SI86SSD_PRES(ssd) == 0) {
		kthread_t *t;
		int bad = 0;

		/*
		 * Look carefully at the segment registers of every lwp
		 * in the process (they're all stopped by our caller).
		 * If we're about to invalidate a descriptor that's still
		 * being referenced by *any* of them, return an error,
		 * rather than having them #gp on their way out of the kernel.
		 */
		ASSERT(pp->p_lwprcnt == 1);

		mutex_enter(&pp->p_lock);
		t = pp->p_tlist;
		do {
			klwp_t *lwp = ttolwp(t);
			struct regs *rp = lwp->lwp_regs;
#if defined(__amd64)
			pcb_t *pcb = &lwp->lwp_pcb;
#endif

			if (ssd->sel == rp->r_cs || ssd->sel == rp->r_ss) {
				bad = 1;
				break;
			}

#if defined(__amd64)
			if (pcb->pcb_rupdate == 1) {
				if (ssd->sel == pcb->pcb_ds ||
				    ssd->sel == pcb->pcb_es ||
				    ssd->sel == pcb->pcb_fs ||
				    ssd->sel == pcb->pcb_gs) {
					bad = 1;
					break;
				}
			} else
#endif
			{
				if (ssd->sel == rp->r_ds ||
				    ssd->sel == rp->r_es ||
				    ssd->sel == rp->r_fs ||
				    ssd->sel == rp->r_gs) {
					bad = 1;
					break;
				}
			}

		} while ((t = t->t_forw) != pp->p_tlist);
		mutex_exit(&pp->p_lock);

		if (bad) {
			mutex_exit(&pp->p_ldtlock);
			return (EBUSY);
		}
	}

	/*
	 * If acc1 is zero, clear the descriptor (including the 'present' bit)
	 */
	if (ssd->acc1 == 0) {
		rc  = ldt_update_segd(ldp, &null_udesc);
		mutex_exit(&pp->p_ldtlock);
		return (rc);
	}

	/*
	 * Check segment type, allow segment not present and
	 * only user DPL (3).
	 */
	if (SI86SSD_DPL(ssd) != SEL_UPL) {
		mutex_exit(&pp->p_ldtlock);
		return (EINVAL);
	}

#if defined(__amd64)
	/*
	 * Do not allow 32-bit applications to create 64-bit mode code
	 * segments.
	 */
	if (SI86SSD_ISUSEG(ssd) && ((SI86SSD_TYPE(ssd) >> 3) & 1) == 1 &&
	    SI86SSD_ISLONG(ssd)) {
		mutex_exit(&pp->p_ldtlock);
		return (EINVAL);
	}
#endif /* __amd64 */

	/*
	 * Set up a code or data user segment descriptor.
	 */
	if (SI86SSD_ISUSEG(ssd)) {
		ssd_to_usd(ssd, &ndesc);
		rc = ldt_update_segd(ldp, &ndesc);
		mutex_exit(&pp->p_ldtlock);
		return (rc);
	}

#if defined(__i386)
	/*
	 * Allow a call gate only if the destination is in the LDT
	 * and the system is running in 32-bit legacy mode.
	 *
	 * In long mode 32-bit call gates are redefined as 64-bit call
	 * gates and the hw enforces that the target code selector
	 * of the call gate must be 64-bit selector. A #gp fault is
	 * generated if otherwise. Since we do not allow 32-bit processes
	 * to switch themselves to 64-bits we never allow call gates
	 * on 64-bit system system.
	 */
	if (SI86SSD_TYPE(ssd) == SDT_SYSCGT && SELISLDT(ssd->ls)) {


		ssd_to_sgd(ssd, (gate_desc_t *)&ndesc);
		rc = ldt_update_segd(ldp, &ndesc);
		mutex_exit(&pp->p_ldtlock);
		return (rc);
	}
#endif	/* __i386 */

	mutex_exit(&pp->p_ldtlock);
	return (EINVAL);
}

/*
 * Allocate new LDT for process just large enough to contain seli.
 * Note we allocate and grow LDT in PAGESIZE chunks. We do this
 * to simplify the implementation and because on the hypervisor it's
 * required, since the LDT must live on pages that have PROT_WRITE
 * removed and which are given to the hypervisor.
 */
static void
ldt_alloc(proc_t *pp, uint_t seli)
{
	user_desc_t	*ldt;
	size_t		ldtsz;
	uint_t		nsels;

	ASSERT(MUTEX_HELD(&pp->p_ldtlock));
	ASSERT(pp->p_ldt == NULL);
	ASSERT(pp->p_ldtlimit == 0);

	/*
	 * Allocate new LDT just large enough to contain seli.
	 */
	ldtsz = P2ROUNDUP((seli + 1) * sizeof (user_desc_t), PAGESIZE);
	nsels = ldtsz / sizeof (user_desc_t);
	ASSERT(nsels >= MINNLDT && nsels <= MAXNLDT);

	ldt = kmem_zalloc(ldtsz, KM_SLEEP);
	ASSERT(IS_P2ALIGNED(ldt, PAGESIZE));

#if defined(__xpv)
	if (xen_ldt_setprot(ldt, ldtsz, PROT_READ))
		panic("ldt_alloc:xen_ldt_setprot(PROT_READ) failed");
#endif

	pp->p_ldt = ldt;
	pp->p_ldtlimit = nsels - 1;
	set_syssegd(&pp->p_ldt_desc, ldt, ldtsz - 1, SDT_SYSLDT, SEL_KPL);

	if (pp == curproc) {
		kpreempt_disable();
		ldt_load();
		kpreempt_enable();
	}
}

static void
ldt_free(proc_t *pp)
{
	user_desc_t	*ldt;
	size_t		ldtsz;

	ASSERT(pp->p_ldt != NULL);

	mutex_enter(&pp->p_ldtlock);
	ldt = pp->p_ldt;
	ldtsz = (pp->p_ldtlimit + 1) * sizeof (user_desc_t);

	ASSERT(IS_P2ALIGNED(ldtsz, PAGESIZE));

	pp->p_ldt = NULL;
	pp->p_ldtlimit = 0;
	pp->p_ldt_desc = null_sdesc;
	mutex_exit(&pp->p_ldtlock);

	if (pp == curproc) {
		kpreempt_disable();
		ldt_unload();
		kpreempt_enable();
	}

#if defined(__xpv)
	/*
	 * We are not allowed to make the ldt writable until after
	 * we tell the hypervisor to unload it.
	 */
	if (xen_ldt_setprot(ldt, ldtsz, PROT_READ | PROT_WRITE))
		panic("ldt_free:xen_ldt_setprot(PROT_READ|PROT_WRITE) failed");
#endif

	kmem_free(ldt, ldtsz);
}

/*
 * On fork copy new ldt for child.
 */
static void
ldt_dup(proc_t *pp, proc_t *cp)
{
	size_t	ldtsz;

	ASSERT(pp->p_ldt != NULL);
	ASSERT(cp != curproc);

	/*
	 * I assume the parent's ldt can't increase since we're in a fork.
	 */
	mutex_enter(&pp->p_ldtlock);
	mutex_enter(&cp->p_ldtlock);

	ldtsz = (pp->p_ldtlimit + 1) * sizeof (user_desc_t);

	ldt_alloc(cp, pp->p_ldtlimit);

#if defined(__xpv)
	/*
	 * Make child's ldt writable so it can be copied into from
	 * parent's ldt. This works since ldt_alloc above did not load
	 * the ldt since its for the child process. If we tried to make
	 * an LDT writable that is loaded in hw the setprot operation
	 * would fail.
	 */
	if (xen_ldt_setprot(cp->p_ldt, ldtsz, PROT_READ | PROT_WRITE))
		panic("ldt_dup:xen_ldt_setprot(PROT_READ|PROT_WRITE) failed");
#endif

	bcopy(pp->p_ldt, cp->p_ldt, ldtsz);

#if defined(__xpv)
	if (xen_ldt_setprot(cp->p_ldt, ldtsz, PROT_READ))
		panic("ldt_dup:xen_ldt_setprot(PROT_READ) failed");
#endif
	mutex_exit(&cp->p_ldtlock);
	mutex_exit(&pp->p_ldtlock);

}

static void
ldt_grow(proc_t *pp, uint_t seli)
{
	user_desc_t	*oldt, *nldt;
	uint_t		nsels;
	size_t		oldtsz, nldtsz;

	ASSERT(MUTEX_HELD(&pp->p_ldtlock));
	ASSERT(pp->p_ldt != NULL);
	ASSERT(pp->p_ldtlimit != 0);

	/*
	 * Allocate larger LDT just large enough to contain seli.
	 */
	nldtsz = P2ROUNDUP((seli + 1) * sizeof (user_desc_t), PAGESIZE);
	nsels = nldtsz / sizeof (user_desc_t);
	ASSERT(nsels >= MINNLDT && nsels <= MAXNLDT);
	ASSERT(nsels > pp->p_ldtlimit);

	oldt = pp->p_ldt;
	oldtsz = (pp->p_ldtlimit + 1) * sizeof (user_desc_t);

	nldt = kmem_zalloc(nldtsz, KM_SLEEP);
	ASSERT(IS_P2ALIGNED(nldt, PAGESIZE));

	bcopy(oldt, nldt, oldtsz);

	/*
	 * unload old ldt.
	 */
	kpreempt_disable();
	ldt_unload();
	kpreempt_enable();

#if defined(__xpv)

	/*
	 * Make old ldt writable and new ldt read only.
	 */
	if (xen_ldt_setprot(oldt, oldtsz, PROT_READ | PROT_WRITE))
		panic("ldt_grow:xen_ldt_setprot(PROT_READ|PROT_WRITE) failed");

	if (xen_ldt_setprot(nldt, nldtsz, PROT_READ))
		panic("ldt_grow:xen_ldt_setprot(PROT_READ) failed");
#endif

	pp->p_ldt = nldt;
	pp->p_ldtlimit = nsels - 1;

	/*
	 * write new ldt segment descriptor.
	 */
	set_syssegd(&pp->p_ldt_desc, nldt, nldtsz - 1, SDT_SYSLDT, SEL_KPL);

	/*
	 * load the new ldt.
	 */
	kpreempt_disable();
	ldt_load();
	kpreempt_enable();

	kmem_free(oldt, oldtsz);
}

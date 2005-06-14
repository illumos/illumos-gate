/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static int setdscr(caddr_t ap);
static void *setup_ldt(proc_t *pp);
static void *ldt_map(proc_t *pp, uint_t seli);

extern void rtcsync(void);
extern long ggmtl(void);
extern void sgmtl(long);

/*
 * sysi86 System Call
 */

/* ARGSUSED */
int
sysi86(short cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
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
			rp->r_ps ^= oldpl ^ newpl;
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
		error = setdscr((caddr_t)arg1);
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
		return (fp_kind == __FP_SSE ? 1 : 0);

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
	 * set avl, DB and granularity bits.
	 */
	usd->usd_avl = ssd->acc2;

#if defined(__amd64)
	usd->usd_long = ssd->acc2 >> 1;
#else
	usd->usd_reserved = ssd->acc2 >> 1;
#endif

	usd->usd_def32 = ssd->acc2 >> (1 + 1);
	usd->usd_gran = ssd->acc2 >> (1 + 1 + 1);
}

static void
ssd_to_sgd(struct ssd *ssd, gate_desc_t *sgd)
{

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

#if defined(__i386)	/* reserved, ignored in amd64 */
	sgd->sgd_stkcpy = 0;
#endif
}

static void ldt_installctx(kthread_t *, kthread_t *);

/*ARGSUSED*/
static void
ldt_savectx(kthread_t *t)
{
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
	clr_ldt_sregs();
#endif

	cpu_fast_syscall_enable(NULL);
}

/*
 * When a thread with a private LDT execs, fast syscalls must be enabled for the
 * new process image.
 */
/* ARGSUSED */
static void
ldt_freectx(kthread_t *t, int isexec)
{
	if (isexec) {
		kpreempt_disable();
		cpu_fast_syscall_enable(NULL);
		kpreempt_enable();
	}
}

/*
 * Install ctx op that ensures syscall/sysenter are disabled.
 * See comments below.
 *
 * When a thread with a private LDT creates a new LWP or forks, the new LWP
 * must have the LDT context ops installed.
 */
/* ARGSUSED */
static void
ldt_installctx(kthread_t *t, kthread_t *ct)
{
	kthread_t *targ = t;

	/*
	 * If this is a fork or an lwp_create, operate on the child thread.
	 */
	if (ct != NULL)
		targ = ct;

	ASSERT(removectx(targ, NULL, ldt_savectx, cpu_fast_syscall_disable,
	    ldt_installctx, ldt_installctx, cpu_fast_syscall_enable,
	    ldt_freectx) == 0);

	installctx(targ, NULL, ldt_savectx, cpu_fast_syscall_disable,
	    ldt_installctx, ldt_installctx, cpu_fast_syscall_enable,
	    ldt_freectx);

	/*
	 * We've just disabled fast system call and return instructions; take
	 * the slow path out to make sure we don't try to use one to return
	 * back to user.
	 */
	targ->t_post_sys = 1;
}

static int
setdscr(caddr_t ap)
{
	struct ssd ssd;		/* request structure buffer */
	ushort_t seli; 		/* selector index */
	user_desc_t *dscrp;	/* descriptor pointer */
	proc_t	*pp = ttoproc(curthread);
	kthread_t *t;

	if (get_udatamodel() == DATAMODEL_LP64)
		return (EINVAL);

	if (copyin(ap, &ssd, sizeof (ssd)) < 0)
		return (EFAULT);

	/*
	 * LDT segments: executable and data at DPL 3 only.
	 */
	if (!SELISLDT(ssd.sel) || !SELISUPL(ssd.sel))
		return (EINVAL);

	/*
	 * check the selector index.
	 */
	seli = SELTOIDX(ssd.sel);
	if (seli >= MAXNLDT || seli <= LDT_UDBASE)
		return (EINVAL);

	mutex_enter(&pp->p_ldtlock);

	/*
	 * If this is the first time for this process then setup a
	 * private LDT for it.
	 */
	if (pp->p_ldt == NULL) {
		if (setup_ldt(pp) == NULL) {
			mutex_exit(&pp->p_ldtlock);
			return (ENOMEM);
		}

		/*
		 * Now that this process has a private LDT, the use of
		 * the syscall/sysret and sysenter/sysexit instructions
		 * is forbidden for this processes because they destroy
		 * the contents of %cs and %ss segment registers.
		 *
		 * Explicity disable them here and add context handlers
		 * to all lwps in the process. Note that disabling
		 * them here means we can't use sysret or sysexit on
		 * the way out of this system call - so we force this
		 * thread to take the slow path (which doesn't make use
		 * of sysenter or sysexit) back out.
		 */

		mutex_enter(&pp->p_lock);
		t = pp->p_tlist;
		do {
			ldt_installctx(t, NULL);
		} while ((t = t->t_forw) != pp->p_tlist);
		mutex_exit(&pp->p_lock);

		kpreempt_disable();
		cpu_fast_syscall_disable(NULL);
		kpreempt_enable();
		ASSERT(curthread->t_post_sys != 0);
		wr_ldtr(ULDT_SEL);
	}

	if (ldt_map(pp, seli) == NULL) {
		mutex_exit(&pp->p_ldtlock);
		return (ENOMEM);
	}

	ASSERT(seli <= pp->p_ldtlimit);
	dscrp = &pp->p_ldt[seli];

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
	if (SI86SSD_PRES(&ssd) == 0) {
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

			if (ssd.sel == rp->r_cs || ssd.sel == rp->r_ss) {
				bad = 1;
				break;
			}

#if defined(__amd64)
			if (pcb->pcb_flags & RUPDATE_PENDING) {
				if (ssd.sel == pcb->pcb_ds ||
				    ssd.sel == pcb->pcb_es ||
				    ssd.sel == pcb->pcb_fs ||
				    ssd.sel == pcb->pcb_gs) {
					bad = 1;
					break;
				}
			} else
#endif
			{
				if (ssd.sel == rp->r_ds ||
				    ssd.sel == rp->r_es ||
				    ssd.sel == rp->r_fs ||
				    ssd.sel == rp->r_gs) {
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
	if (ssd.acc1 == 0) {
		bzero(dscrp, sizeof (*dscrp));
		mutex_exit(&pp->p_ldtlock);
		return (0);
	}

	/*
	 * Check segment type, allow segment not present and
	 * only user DPL (3).
	 */
	if (SI86SSD_DPL(&ssd) != SEL_UPL) {
		mutex_exit(&pp->p_ldtlock);
		return (EINVAL);
	}

#if defined(__amd64)
	/*
	 * Do not allow 32-bit applications to create 64-bit mode code segments.
	 */
	if (SI86SSD_ISUSEG(&ssd) && ((SI86SSD_TYPE(&ssd) >> 3) & 1) == 1 &&
	    SI86SSD_ISLONG(&ssd)) {
		mutex_exit(&pp->p_ldtlock);
		return (EINVAL);
	}
#endif /* __amd64 */

	/*
	 * Set up a code or data user segment descriptor.
	 */
	if (SI86SSD_ISUSEG(&ssd)) {
		ssd_to_usd(&ssd, dscrp);
		mutex_exit(&pp->p_ldtlock);
		return (0);
	}

	/*
	 * Allow a call gate only if the destination is in the LDT.
	 */
	if (SI86SSD_TYPE(&ssd) == SDT_SYSCGT && SELISLDT(ssd.ls)) {
		ssd_to_sgd(&ssd, (gate_desc_t *)dscrp);
		mutex_exit(&pp->p_ldtlock);
		return (0);
	}

	mutex_exit(&pp->p_ldtlock);
	return (EINVAL);
}

/*
 * Allocate a private LDT for this process and initialize it with the
 * default entries. Returns 0 for errors, pointer to LDT for success.
 */
static void *
setup_ldt(proc_t *pp)
{
	user_desc_t *ldtp;	/* descriptor pointer */
	pgcnt_t npages = btopr(MAXNLDT * sizeof (user_desc_t));

	/*
	 * Allocate maximum virtual space we need for this LDT.
	 */
	ldtp = vmem_alloc(heap_arena, ptob(npages), VM_SLEEP);

	/*
	 * Allocate the minimum number of physical pages for LDT.
	 */
	if (segkmem_xalloc(NULL, ldtp, MINNLDT * sizeof (user_desc_t),
	    VM_SLEEP, 0, segkmem_page_create, NULL) == NULL) {
		vmem_free(heap_arena, ldtp, ptob(npages));
		return (0);
	}
	bzero(ldtp, ptob(btopr(MINNLDT * sizeof (user_desc_t))));

	/*
	 * Copy the default LDT entries into the new table.
	 */
	bcopy(ldt0_default, ldtp, MINNLDT * sizeof (user_desc_t));

	kpreempt_disable();

	/* Update proc structure. XXX - need any locks here??? */

	set_syssegd(&pp->p_ldt_desc, ldtp, MINNLDT * sizeof (user_desc_t) - 1,
	    SDT_SYSLDT, SEL_KPL);

	pp->p_ldtlimit = MINNLDT - 1;
	pp->p_ldt = ldtp;
	if (pp == curproc)
		*((system_desc_t *)&CPU->cpu_gdt[GDT_LDT]) = pp->p_ldt_desc;

	kpreempt_enable();

	return (ldtp);
}

/*
 * Load LDT register with the current process's LDT.
 */
void
ldt_load(void)
{
	proc_t *p = curthread->t_procp;

	ASSERT(curthread->t_preempt != 0);

	*((system_desc_t *)&CPU->cpu_gdt[GDT_LDT]) = p->p_ldt_desc;
	wr_ldtr(ULDT_SEL);
}

/*
 * Map the page corresponding to the selector entry. If the page is
 * already mapped then it simply returns with the pointer to the entry.
 * Otherwise it allocates a physical page for it and returns the pointer
 * to the entry.  Returns 0 for errors.
 */
static void *
ldt_map(proc_t *pp, uint_t seli)
{
	caddr_t ent0_addr = (caddr_t)&pp->p_ldt[0];
	caddr_t ent_addr = (caddr_t)&pp->p_ldt[seli];
	volatile caddr_t page = (caddr_t)((uintptr_t)ent0_addr & (~PAGEOFFSET));
	caddr_t epage = (caddr_t)((uintptr_t)ent_addr & (~PAGEOFFSET));
	on_trap_data_t otd;

	ASSERT(pp->p_ldt != NULL);

	if (seli <= pp->p_ldtlimit)
		return (ent_addr);

	/*
	 * We are increasing the size of the process's LDT.
	 * Make sure this and all intervening pages are mapped.
	 */
	while (page <= epage) {
		if (!on_trap(&otd, OT_DATA_ACCESS))
			(void) *(volatile int *)page;	/* peek at the page */
		else {		/* Allocate a physical page */
			if (segkmem_xalloc(NULL, page, PAGESIZE, VM_SLEEP, 0,
			    segkmem_page_create, NULL) == NULL) {
				no_trap();
				return (NULL);
			}
			bzero(page, PAGESIZE);
		}
		no_trap();
		page += PAGESIZE;
	}

	/* XXX - need any locks to update proc_t or gdt ??? */

	ASSERT(curproc == pp);

	kpreempt_disable();
	pp->p_ldtlimit = seli;
	SYSSEGD_SETLIMIT(&pp->p_ldt_desc, (seli+1) * sizeof (user_desc_t) -1);

	ldt_load();
	kpreempt_enable();

	return (ent_addr);
}

/*
 * Free up the kernel memory used for LDT of this process.
 */
void
ldt_free(proc_t *pp)
{
	on_trap_data_t otd;
	caddr_t start, end;
	volatile caddr_t addr;

	ASSERT(pp->p_ldt != NULL);

	mutex_enter(&pp->p_ldtlock);
	start = (caddr_t)pp->p_ldt; /* beginning of the LDT */
	end = start + (pp->p_ldtlimit * sizeof (user_desc_t));

	/* Free the physical page(s) used for mapping LDT */
	for (addr = start; addr <= end; addr += PAGESIZE) {
		if (!on_trap(&otd, OT_DATA_ACCESS)) {
			/* peek at the address */
			(void) *(volatile int *)addr;
			segkmem_free(NULL, addr, PAGESIZE);
		}
	}
	no_trap();

	/* Free up the virtual address space used for this LDT */
	vmem_free(heap_arena, pp->p_ldt,
	    ptob(btopr(MAXNLDT * sizeof (user_desc_t))));
	kpreempt_disable();
	pp->p_ldt = NULL;
	pp->p_ldt_desc = ldt0_default_desc;
	if (pp == curproc)
		ldt_load();
	kpreempt_enable();
	mutex_exit(&pp->p_ldtlock);
}

/*
 * On fork copy new ldt for child.
 */
int
ldt_dup(proc_t *pp, proc_t *cp)
{
	on_trap_data_t otd;
	caddr_t start, end;
	volatile caddr_t addr, caddr;
	int	minsize;

	if (pp->p_ldt == NULL) {
		cp->p_ldt_desc = ldt0_default_desc;
		return (0);
	}

	if (setup_ldt(cp) == NULL) {
		return (ENOMEM);
	}

	mutex_enter(&pp->p_ldtlock);
	cp->p_ldtlimit = pp->p_ldtlimit;
	SYSSEGD_SETLIMIT(&cp->p_ldt_desc,
	    (pp->p_ldtlimit+1) * sizeof (user_desc_t) -1);
	start = (caddr_t)pp->p_ldt; /* beginning of the LDT */
	end = start + (pp->p_ldtlimit * sizeof (user_desc_t));
	caddr = (caddr_t)cp->p_ldt; /* child LDT start */

	minsize = ((MINNLDT * sizeof (user_desc_t)) + PAGESIZE) & ~PAGEOFFSET;
	/* Walk thru the physical page(s) used for parent's LDT */
	for (addr = start; addr <= end; addr += PAGESIZE, caddr += PAGESIZE) {
		if (!on_trap(&otd, OT_DATA_ACCESS)) {
			(void) *(volatile int *)addr; /* peek at the address */
			/* allocate a page if necessary */
			if (caddr >= ((caddr_t)cp->p_ldt + minsize)) {
				if (segkmem_xalloc(NULL, caddr, PAGESIZE,
				    VM_SLEEP, 0, segkmem_page_create, NULL) ==
				    NULL) {
					no_trap();
					ldt_free(cp);
					mutex_exit(&pp->p_ldtlock);
					return (ENOMEM);
				}
			}
			bcopy(addr, caddr, PAGESIZE);
		}
	}
	no_trap();
	mutex_exit(&pp->p_ldtlock);
	return (0);
}

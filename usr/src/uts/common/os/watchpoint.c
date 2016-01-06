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

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/regset.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/prsystm.h>
#include <sys/buf.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/cpuvar.h>

#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/cmn_err.h>
#include <sys/stack.h>
#include <sys/watchpoint.h>
#include <sys/copyops.h>
#include <sys/schedctl.h>

#include <sys/mman.h>
#include <vm/as.h>
#include <vm/seg.h>

/*
 * Copy ops vector for watchpoints.
 */
static int	watch_copyin(const void *, void *, size_t);
static int	watch_xcopyin(const void *, void *, size_t);
static int	watch_copyout(const void *, void *, size_t);
static int	watch_xcopyout(const void *, void *, size_t);
static int	watch_copyinstr(const char *, char *, size_t, size_t *);
static int	watch_copyoutstr(const char *, char *, size_t, size_t *);
static int	watch_fuword8(const void *, uint8_t *);
static int	watch_fuword16(const void *, uint16_t *);
static int	watch_fuword32(const void *, uint32_t *);
static int	watch_suword8(void *, uint8_t);
static int	watch_suword16(void *, uint16_t);
static int	watch_suword32(void *, uint32_t);
static int	watch_physio(int (*)(struct buf *), struct buf *,
    dev_t, int, void (*)(struct buf *), struct uio *);
#ifdef _LP64
static int	watch_fuword64(const void *, uint64_t *);
static int	watch_suword64(void *, uint64_t);
#endif

struct copyops watch_copyops = {
	watch_copyin,
	watch_xcopyin,
	watch_copyout,
	watch_xcopyout,
	watch_copyinstr,
	watch_copyoutstr,
	watch_fuword8,
	watch_fuword16,
	watch_fuword32,
#ifdef _LP64
	watch_fuword64,
#else
	NULL,
#endif
	watch_suword8,
	watch_suword16,
	watch_suword32,
#ifdef _LP64
	watch_suword64,
#else
	NULL,
#endif
	watch_physio
};

/*
 * Map the 'rw' argument to a protection flag.
 */
static int
rw_to_prot(enum seg_rw rw)
{
	switch (rw) {
	case S_EXEC:
		return (PROT_EXEC);
	case S_READ:
		return (PROT_READ);
	case S_WRITE:
		return (PROT_WRITE);
	default:
		return (PROT_NONE);	/* can't happen */
	}
}

/*
 * Map the 'rw' argument to an index into an array of exec/write/read things.
 * The index follows the precedence order:  exec .. write .. read
 */
static int
rw_to_index(enum seg_rw rw)
{
	switch (rw) {
	default:	/* default case "can't happen" */
	case S_EXEC:
		return (0);
	case S_WRITE:
		return (1);
	case S_READ:
		return (2);
	}
}

/*
 * Map an index back to a seg_rw.
 */
static enum seg_rw S_rw[4] = {
	S_EXEC,
	S_WRITE,
	S_READ,
	S_READ,
};

#define	X	0
#define	W	1
#define	R	2
#define	sum(a)	(a[X] + a[W] + a[R])

/*
 * Common code for pr_mappage() and pr_unmappage().
 */
static int
pr_do_mappage(caddr_t addr, size_t size, int mapin, enum seg_rw rw, int kernel)
{
	proc_t *p = curproc;
	struct as *as = p->p_as;
	char *eaddr = addr + size;
	int prot_rw = rw_to_prot(rw);
	int xrw = rw_to_index(rw);
	int rv = 0;
	struct watched_page *pwp;
	struct watched_page tpw;
	avl_index_t where;
	uint_t prot;

	ASSERT(as != &kas);

startover:
	ASSERT(rv == 0);
	if (avl_numnodes(&as->a_wpage) == 0)
		return (0);

	/*
	 * as->a_wpage can only be changed while the process is totally stopped.
	 * Don't grab p_lock here.  Holding p_lock while grabbing the address
	 * space lock leads to deadlocks with the clock thread.
	 *
	 * p_maplock prevents simultaneous execution of this function.  Under
	 * normal circumstances, holdwatch() will stop all other threads, so the
	 * lock isn't really needed.  But there may be multiple threads within
	 * stop() when SWATCHOK is set, so we need to handle multiple threads
	 * at once.  See holdwatch() for the details of this dance.
	 */

	mutex_enter(&p->p_maplock);

	tpw.wp_vaddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	if ((pwp = avl_find(&as->a_wpage, &tpw, &where)) == NULL)
		pwp = avl_nearest(&as->a_wpage, where, AVL_AFTER);

	for (; pwp != NULL && pwp->wp_vaddr < eaddr;
	    pwp = AVL_NEXT(&as->a_wpage, pwp)) {

		/*
		 * If the requested protection has not been
		 * removed, we need not remap this page.
		 */
		prot = pwp->wp_prot;
		if (kernel || (prot & PROT_USER))
			if (prot & prot_rw)
				continue;
		/*
		 * If the requested access does not exist in the page's
		 * original protections, we need not remap this page.
		 * If the page does not exist yet, we can't test it.
		 */
		if ((prot = pwp->wp_oprot) != 0) {
			if (!(kernel || (prot & PROT_USER)))
				continue;
			if (!(prot & prot_rw))
				continue;
		}

		if (mapin) {
			/*
			 * Before mapping the page in, ensure that
			 * all other lwps are held in the kernel.
			 */
			if (p->p_mapcnt == 0) {
				mutex_exit(&p->p_maplock);
				if (holdwatch() != 0) {
					/*
					 * We stopped in holdwatch().
					 * Start all over again because the
					 * watched page list may have changed.
					 */
					goto startover;
				}
				mutex_enter(&p->p_maplock);
			}
			p->p_mapcnt++;
		}

		addr = pwp->wp_vaddr;
		rv++;

		prot = pwp->wp_prot;
		if (mapin) {
			if (kernel)
				pwp->wp_kmap[xrw]++;
			else
				pwp->wp_umap[xrw]++;
			pwp->wp_flags |= WP_NOWATCH;
			if (pwp->wp_kmap[X] + pwp->wp_umap[X])
				/* cannot have exec-only protection */
				prot |= PROT_READ|PROT_EXEC;
			if (pwp->wp_kmap[R] + pwp->wp_umap[R])
				prot |= PROT_READ;
			if (pwp->wp_kmap[W] + pwp->wp_umap[W])
				/* cannot have write-only protection */
				prot |= PROT_READ|PROT_WRITE;
#if 0	/* damned broken mmu feature! */
			if (sum(pwp->wp_umap) == 0)
				prot &= ~PROT_USER;
#endif
		} else {
			ASSERT(pwp->wp_flags & WP_NOWATCH);
			if (kernel) {
				ASSERT(pwp->wp_kmap[xrw] != 0);
				--pwp->wp_kmap[xrw];
			} else {
				ASSERT(pwp->wp_umap[xrw] != 0);
				--pwp->wp_umap[xrw];
			}
			if (sum(pwp->wp_kmap) + sum(pwp->wp_umap) == 0)
				pwp->wp_flags &= ~WP_NOWATCH;
			else {
				if (pwp->wp_kmap[X] + pwp->wp_umap[X])
					/* cannot have exec-only protection */
					prot |= PROT_READ|PROT_EXEC;
				if (pwp->wp_kmap[R] + pwp->wp_umap[R])
					prot |= PROT_READ;
				if (pwp->wp_kmap[W] + pwp->wp_umap[W])
					/* cannot have write-only protection */
					prot |= PROT_READ|PROT_WRITE;
#if 0	/* damned broken mmu feature! */
				if (sum(pwp->wp_umap) == 0)
					prot &= ~PROT_USER;
#endif
			}
		}


		if (pwp->wp_oprot != 0) {	/* if page exists */
			struct seg *seg;
			uint_t oprot;
			int err, retrycnt = 0;

			AS_LOCK_ENTER(as, RW_WRITER);
		retry:
			seg = as_segat(as, addr);
			ASSERT(seg != NULL);
			SEGOP_GETPROT(seg, addr, 0, &oprot);
			if (prot != oprot) {
				err = SEGOP_SETPROT(seg, addr, PAGESIZE, prot);
				if (err == IE_RETRY) {
					ASSERT(retrycnt == 0);
					retrycnt++;
					goto retry;
				}
			}
			AS_LOCK_EXIT(as);
		}

		/*
		 * When all pages are mapped back to their normal state,
		 * continue the other lwps.
		 */
		if (!mapin) {
			ASSERT(p->p_mapcnt > 0);
			p->p_mapcnt--;
			if (p->p_mapcnt == 0) {
				mutex_exit(&p->p_maplock);
				mutex_enter(&p->p_lock);
				continuelwps(p);
				mutex_exit(&p->p_lock);
				mutex_enter(&p->p_maplock);
			}
		}
	}

	mutex_exit(&p->p_maplock);

	return (rv);
}

/*
 * Restore the original page protections on an address range.
 * If 'kernel' is non-zero, just do it for the kernel.
 * pr_mappage() returns non-zero if it actually changed anything.
 *
 * pr_mappage() and pr_unmappage() must be executed in matched pairs,
 * but pairs may be nested within other pairs.  The reference counts
 * sort it all out.  See pr_do_mappage(), above.
 */
static int
pr_mappage(const caddr_t addr, size_t size, enum seg_rw rw, int kernel)
{
	return (pr_do_mappage(addr, size, 1, rw, kernel));
}

/*
 * Set the modified page protections on a watched page.
 * Inverse of pr_mappage().
 * Needs to be called only if pr_mappage() returned non-zero.
 */
static void
pr_unmappage(const caddr_t addr, size_t size, enum seg_rw rw, int kernel)
{
	(void) pr_do_mappage(addr, size, 0, rw, kernel);
}

/*
 * Function called by an lwp after it resumes from stop().
 */
void
setallwatch(void)
{
	proc_t *p = curproc;
	struct as *as = curproc->p_as;
	struct watched_page *pwp, *next;
	struct seg *seg;
	caddr_t vaddr;
	uint_t prot;
	int err, retrycnt;

	if (p->p_wprot == NULL)
		return;

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	AS_LOCK_ENTER(as, RW_WRITER);

	pwp = p->p_wprot;
	while (pwp != NULL) {

		vaddr = pwp->wp_vaddr;
		retrycnt = 0;
	retry:
		ASSERT(pwp->wp_flags & WP_SETPROT);
		if ((seg = as_segat(as, vaddr)) != NULL &&
		    !(pwp->wp_flags & WP_NOWATCH)) {
			prot = pwp->wp_prot;
			err = SEGOP_SETPROT(seg, vaddr, PAGESIZE, prot);
			if (err == IE_RETRY) {
				ASSERT(retrycnt == 0);
				retrycnt++;
				goto retry;
			}
		}

		next = pwp->wp_list;

		if (pwp->wp_read + pwp->wp_write + pwp->wp_exec == 0) {
			/*
			 * No watched areas remain in this page.
			 * Free the watched_page structure.
			 */
			avl_remove(&as->a_wpage, pwp);
			kmem_free(pwp, sizeof (struct watched_page));
		} else {
			pwp->wp_flags &= ~WP_SETPROT;
		}

		pwp = next;
	}
	p->p_wprot = NULL;

	AS_LOCK_EXIT(as);
}



int
pr_is_watchpage_as(caddr_t addr, enum seg_rw rw, struct as *as)
{
	register struct watched_page *pwp;
	struct watched_page tpw;
	uint_t prot;
	int rv = 0;

	switch (rw) {
	case S_READ:
	case S_WRITE:
	case S_EXEC:
		break;
	default:
		return (0);
	}

	/*
	 * as->a_wpage can only be modified while the process is totally
	 * stopped.  We need, and should use, no locks here.
	 */
	if (as != &kas && avl_numnodes(&as->a_wpage) != 0) {
		tpw.wp_vaddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
		pwp = avl_find(&as->a_wpage, &tpw, NULL);
		if (pwp != NULL) {
			ASSERT(addr >= pwp->wp_vaddr &&
			    addr < pwp->wp_vaddr + PAGESIZE);
			if (pwp->wp_oprot != 0) {
				prot = pwp->wp_prot;
				switch (rw) {
				case S_READ:
					rv = ((prot & (PROT_USER|PROT_READ))
					    != (PROT_USER|PROT_READ));
					break;
				case S_WRITE:
					rv = ((prot & (PROT_USER|PROT_WRITE))
					    != (PROT_USER|PROT_WRITE));
					break;
				case S_EXEC:
					rv = ((prot & (PROT_USER|PROT_EXEC))
					    != (PROT_USER|PROT_EXEC));
					break;
				default:
					/* can't happen! */
					break;
				}
			}
		}
	}

	return (rv);
}


/*
 * trap() calls here to determine if a fault is in a watched page.
 * We return nonzero if this is true and the load/store would fail.
 */
int
pr_is_watchpage(caddr_t addr, enum seg_rw rw)
{
	struct as *as = curproc->p_as;

	if ((as == &kas) || avl_numnodes(&as->a_wpage) == 0)
		return (0);

	return (pr_is_watchpage_as(addr, rw, as));
}



/*
 * trap() calls here to determine if a fault is a watchpoint.
 */
int
pr_is_watchpoint(caddr_t *paddr, int *pta, size_t size, size_t *plen,
	enum seg_rw rw)
{
	proc_t *p = curproc;
	caddr_t addr = *paddr;
	caddr_t eaddr = addr + size;
	register struct watched_area *pwa;
	struct watched_area twa;
	int rv = 0;
	int ta = 0;
	size_t len = 0;

	switch (rw) {
	case S_READ:
	case S_WRITE:
	case S_EXEC:
		break;
	default:
		*pta = 0;
		return (0);
	}

	/*
	 * p->p_warea is protected by p->p_lock.
	 */
	mutex_enter(&p->p_lock);

	/* BEGIN CSTYLED */
	/*
	 * This loop is somewhat complicated because the fault region can span
	 * multiple watched areas.  For example:
	 *
	 *            addr              eaddr
	 * 		+-----------------+
	 * 		| fault region    |
	 * 	+-------+--------+----+---+------------+
	 *      | prot not right |    | prot correct   |
	 *      +----------------+    +----------------+
	 *    wa_vaddr	      wa_eaddr
	 *    		      wa_vaddr		wa_eaddr
	 *
	 * We start at the area greater than or equal to the starting address.
	 * As long as some portion of the fault region overlaps the current
	 * area, we continue checking permissions until we find an appropriate
	 * match.
	 */
	/* END CSTYLED */
	twa.wa_vaddr = addr;
	twa.wa_eaddr = eaddr;

	for (pwa = pr_find_watched_area(p, &twa, NULL);
	    pwa != NULL && eaddr > pwa->wa_vaddr && addr < pwa->wa_eaddr;
	    pwa = AVL_NEXT(&p->p_warea, pwa)) {

		switch (rw) {
		case S_READ:
			if (pwa->wa_flags & WA_READ)
				rv = TRAP_RWATCH;
			break;
		case S_WRITE:
			if (pwa->wa_flags & WA_WRITE)
				rv = TRAP_WWATCH;
			break;
		case S_EXEC:
			if (pwa->wa_flags & WA_EXEC)
				rv = TRAP_XWATCH;
			break;
		default:
			/* can't happen */
			break;
		}

		/*
		 * If protections didn't match, check the next watched
		 * area
		 */
		if (rv != 0) {
			if (addr < pwa->wa_vaddr)
				addr = pwa->wa_vaddr;
			len = pwa->wa_eaddr - addr;
			if (pwa->wa_flags & WA_TRAPAFTER)
				ta = 1;
			break;
		}
	}

	mutex_exit(&p->p_lock);

	*paddr = addr;
	*pta = ta;
	if (plen != NULL)
		*plen = len;
	return (rv);
}

/*
 * Set up to perform a single-step at user level for the
 * case of a trapafter watchpoint.  Called from trap().
 */
void
do_watch_step(caddr_t vaddr, size_t sz, enum seg_rw rw,
	int watchcode, greg_t pc)
{
	register klwp_t *lwp = ttolwp(curthread);
	struct lwp_watch *pw = &lwp->lwp_watch[rw_to_index(rw)];

	/*
	 * Check to see if we are already performing this special
	 * watchpoint single-step.  We must not do pr_mappage() twice.
	 */

	/* special check for two read traps on the same instruction */
	if (rw == S_READ && pw->wpaddr != NULL &&
	    !(pw->wpaddr <= vaddr && vaddr < pw->wpaddr + pw->wpsize)) {
		ASSERT(lwp->lwp_watchtrap != 0);
		pw++;	/* use the extra S_READ struct */
	}

	if (pw->wpaddr != NULL) {
		ASSERT(lwp->lwp_watchtrap != 0);
		ASSERT(pw->wpaddr <= vaddr && vaddr < pw->wpaddr + pw->wpsize);
		if (pw->wpcode == 0) {
			pw->wpcode = watchcode;
			pw->wppc = pc;
		}
	} else {
		int mapped = pr_mappage(vaddr, sz, rw, 0);
		prstep(lwp, 1);
		lwp->lwp_watchtrap = 1;
		pw->wpaddr = vaddr;
		pw->wpsize = sz;
		pw->wpcode = watchcode;
		pw->wpmapped = mapped;
		pw->wppc = pc;
	}
}

/*
 * Undo the effects of do_watch_step().
 * Called from trap() after the single-step is finished.
 * Also called from issig_forreal() and stop() with a NULL
 * argument to avoid having these things set more than once.
 */
int
undo_watch_step(k_siginfo_t *sip)
{
	register klwp_t *lwp = ttolwp(curthread);
	int fault = 0;

	if (lwp->lwp_watchtrap) {
		struct lwp_watch *pw = lwp->lwp_watch;
		int i;

		for (i = 0; i < 4; i++, pw++) {
			if (pw->wpaddr == NULL)
				continue;
			if (pw->wpmapped)
				pr_unmappage(pw->wpaddr, pw->wpsize, S_rw[i],
				    0);
			if (pw->wpcode != 0) {
				if (sip != NULL) {
					sip->si_signo = SIGTRAP;
					sip->si_code = pw->wpcode;
					sip->si_addr = pw->wpaddr;
					sip->si_trapafter = 1;
					sip->si_pc = (caddr_t)pw->wppc;
				}
				fault = FLTWATCH;
				pw->wpcode = 0;
			}
			pw->wpaddr = NULL;
			pw->wpsize = 0;
			pw->wpmapped = 0;
		}
		lwp->lwp_watchtrap = 0;
	}

	return (fault);
}

/*
 * Handle a watchpoint that occurs while doing copyin()
 * or copyout() in a system call.
 * Return non-zero if the fault or signal is cleared
 * by a debugger while the lwp is stopped.
 */
static int
sys_watchpoint(caddr_t addr, int watchcode, int ta)
{
	extern greg_t getuserpc(void);	/* XXX header file */
	k_sigset_t smask;
	register proc_t *p = ttoproc(curthread);
	register klwp_t *lwp = ttolwp(curthread);
	register sigqueue_t *sqp;
	int rval;

	/* assert no locks are held */
	/* ASSERT(curthread->t_nlocks == 0); */

	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
	sqp->sq_info.si_signo = SIGTRAP;
	sqp->sq_info.si_code = watchcode;
	sqp->sq_info.si_addr = addr;
	sqp->sq_info.si_trapafter = ta;
	sqp->sq_info.si_pc = (caddr_t)getuserpc();

	mutex_enter(&p->p_lock);

	/* this will be tested and cleared by the caller */
	lwp->lwp_sysabort = 0;

	if (prismember(&p->p_fltmask, FLTWATCH)) {
		lwp->lwp_curflt = (uchar_t)FLTWATCH;
		lwp->lwp_siginfo = sqp->sq_info;
		stop(PR_FAULTED, FLTWATCH);
		if (lwp->lwp_curflt == 0) {
			mutex_exit(&p->p_lock);
			kmem_free(sqp, sizeof (sigqueue_t));
			return (1);
		}
		lwp->lwp_curflt = 0;
	}

	/*
	 * post the SIGTRAP signal.
	 * Block all other signals so we only stop showing SIGTRAP.
	 */
	if (signal_is_blocked(curthread, SIGTRAP) ||
	    sigismember(&p->p_ignore, SIGTRAP)) {
		/* SIGTRAP is blocked or ignored, forget the rest. */
		mutex_exit(&p->p_lock);
		kmem_free(sqp, sizeof (sigqueue_t));
		return (0);
	}
	sigdelq(p, curthread, SIGTRAP);
	sigaddqa(p, curthread, sqp);
	schedctl_finish_sigblock(curthread);
	smask = curthread->t_hold;
	sigfillset(&curthread->t_hold);
	sigdiffset(&curthread->t_hold, &cantmask);
	sigdelset(&curthread->t_hold, SIGTRAP);
	mutex_exit(&p->p_lock);

	rval = ((ISSIG_FAST(curthread, lwp, p, FORREAL))? 0 : 1);

	/* restore the original signal mask */
	mutex_enter(&p->p_lock);
	curthread->t_hold = smask;
	mutex_exit(&p->p_lock);

	return (rval);
}

/*
 * Wrappers for the copyin()/copyout() functions to deal
 * with watchpoints that fire while in system calls.
 */

static int
watch_xcopyin(const void *uaddr, void *kaddr, size_t count)
{
	klwp_t *lwp = ttolwp(curthread);
	caddr_t watch_uaddr = (caddr_t)uaddr;
	caddr_t watch_kaddr = (caddr_t)kaddr;
	int error = 0;
	label_t ljb;
	size_t part;
	int mapped;

	while (count && error == 0) {
		int watchcode;
		caddr_t vaddr;
		size_t len;
		int ta;

		if ((part = PAGESIZE -
		    (((uintptr_t)uaddr) & PAGEOFFSET)) > count)
			part = count;

		if (!pr_is_watchpage(watch_uaddr, S_READ))
			watchcode = 0;
		else {
			vaddr = watch_uaddr;
			watchcode = pr_is_watchpoint(&vaddr, &ta,
			    part, &len, S_READ);
			if (watchcode && ta == 0)
				part = vaddr - watch_uaddr;
		}

		/*
		 * Copy the initial part, up to a watched address, if any.
		 */
		if (part != 0) {
			mapped = pr_mappage(watch_uaddr, part, S_READ, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				copyin_noerr(watch_uaddr, watch_kaddr, part);
			no_fault();
			if (mapped)
				pr_unmappage(watch_uaddr, part, S_READ, 1);
			watch_uaddr += part;
			watch_kaddr += part;
			count -= part;
		}
		/*
		 * If trapafter was specified, then copy through the
		 * watched area before taking the watchpoint trap.
		 */
		while (count && watchcode && ta && len > part && error == 0) {
			len -= part;
			if ((part = PAGESIZE) > count)
				part = count;
			if (part > len)
				part = len;
			mapped = pr_mappage(watch_uaddr, part, S_READ, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				copyin_noerr(watch_uaddr, watch_kaddr, part);
			no_fault();
			if (mapped)
				pr_unmappage(watch_uaddr, part, S_READ, 1);
			watch_uaddr += part;
			watch_kaddr += part;
			count -= part;
		}

error:
		/* if we hit a watched address, do the watchpoint logic */
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			error = EFAULT;
			break;
		}
	}

	return (error);
}

static int
watch_copyin(const void *kaddr, void *uaddr, size_t count)
{
	return (watch_xcopyin(kaddr, uaddr, count) ? -1 : 0);
}


static int
watch_xcopyout(const void *kaddr, void *uaddr, size_t count)
{
	klwp_t *lwp = ttolwp(curthread);
	caddr_t watch_uaddr = (caddr_t)uaddr;
	caddr_t watch_kaddr = (caddr_t)kaddr;
	int error = 0;
	label_t ljb;

	while (count && error == 0) {
		int watchcode;
		caddr_t vaddr;
		size_t part;
		size_t len;
		int ta;
		int mapped;

		if ((part = PAGESIZE -
		    (((uintptr_t)uaddr) & PAGEOFFSET)) > count)
			part = count;

		if (!pr_is_watchpage(watch_uaddr, S_WRITE))
			watchcode = 0;
		else {
			vaddr = watch_uaddr;
			watchcode = pr_is_watchpoint(&vaddr, &ta,
			    part, &len, S_WRITE);
			if (watchcode) {
				if (ta == 0)
					part = vaddr - watch_uaddr;
				else {
					len += vaddr - watch_uaddr;
					if (part > len)
						part = len;
				}
			}
		}

		/*
		 * Copy the initial part, up to a watched address, if any.
		 */
		if (part != 0) {
			mapped = pr_mappage(watch_uaddr, part, S_WRITE, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				copyout_noerr(watch_kaddr, watch_uaddr, part);
			no_fault();
			if (mapped)
				pr_unmappage(watch_uaddr, part, S_WRITE, 1);
			watch_uaddr += part;
			watch_kaddr += part;
			count -= part;
		}

		/*
		 * If trapafter was specified, then copy through the
		 * watched area before taking the watchpoint trap.
		 */
		while (count && watchcode && ta && len > part && error == 0) {
			len -= part;
			if ((part = PAGESIZE) > count)
				part = count;
			if (part > len)
				part = len;
			mapped = pr_mappage(watch_uaddr, part, S_WRITE, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				copyout_noerr(watch_kaddr, watch_uaddr, part);
			no_fault();
			if (mapped)
				pr_unmappage(watch_uaddr, part, S_WRITE, 1);
			watch_uaddr += part;
			watch_kaddr += part;
			count -= part;
		}

		/* if we hit a watched address, do the watchpoint logic */
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			error = EFAULT;
			break;
		}
	}

	return (error);
}

static int
watch_copyout(const void *kaddr, void *uaddr, size_t count)
{
	return (watch_xcopyout(kaddr, uaddr, count) ? -1 : 0);
}

static int
watch_copyinstr(
	const char *uaddr,
	char *kaddr,
	size_t maxlength,
	size_t *lencopied)
{
	klwp_t *lwp = ttolwp(curthread);
	size_t resid;
	int error = 0;
	label_t ljb;

	if ((resid = maxlength) == 0)
		return (ENAMETOOLONG);

	while (resid && error == 0) {
		int watchcode;
		caddr_t vaddr;
		size_t part;
		size_t len;
		size_t size;
		int ta;
		int mapped;

		if ((part = PAGESIZE -
		    (((uintptr_t)uaddr) & PAGEOFFSET)) > resid)
			part = resid;

		if (!pr_is_watchpage((caddr_t)uaddr, S_READ))
			watchcode = 0;
		else {
			vaddr = (caddr_t)uaddr;
			watchcode = pr_is_watchpoint(&vaddr, &ta,
			    part, &len, S_READ);
			if (watchcode) {
				if (ta == 0)
					part = vaddr - uaddr;
				else {
					len += vaddr - uaddr;
					if (part > len)
						part = len;
				}
			}
		}

		/*
		 * Copy the initial part, up to a watched address, if any.
		 */
		if (part != 0) {
			mapped = pr_mappage((caddr_t)uaddr, part, S_READ, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				error = copyinstr_noerr(uaddr, kaddr, part,
				    &size);
			no_fault();
			if (mapped)
				pr_unmappage((caddr_t)uaddr, part, S_READ, 1);
			uaddr += size;
			kaddr += size;
			resid -= size;
			if (error == ENAMETOOLONG && resid > 0)
				error = 0;
			if (error != 0 || (watchcode &&
			    (uaddr < vaddr || kaddr[-1] == '\0')))
				break;	/* didn't reach the watched area */
		}

		/*
		 * If trapafter was specified, then copy through the
		 * watched area before taking the watchpoint trap.
		 */
		while (resid && watchcode && ta && len > part && error == 0 &&
		    size == part && kaddr[-1] != '\0') {
			len -= part;
			if ((part = PAGESIZE) > resid)
				part = resid;
			if (part > len)
				part = len;
			mapped = pr_mappage((caddr_t)uaddr, part, S_READ, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				error = copyinstr_noerr(uaddr, kaddr, part,
				    &size);
			no_fault();
			if (mapped)
				pr_unmappage((caddr_t)uaddr, part, S_READ, 1);
			uaddr += size;
			kaddr += size;
			resid -= size;
			if (error == ENAMETOOLONG && resid > 0)
				error = 0;
		}

		/* if we hit a watched address, do the watchpoint logic */
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			error = EFAULT;
			break;
		}

		if (error == 0 && part != 0 &&
		    (size < part || kaddr[-1] == '\0'))
			break;
	}

	if (error != EFAULT && lencopied)
		*lencopied = maxlength - resid;
	return (error);
}

static int
watch_copyoutstr(
	const char *kaddr,
	char *uaddr,
	size_t maxlength,
	size_t *lencopied)
{
	klwp_t *lwp = ttolwp(curthread);
	size_t resid;
	int error = 0;
	label_t ljb;

	if ((resid = maxlength) == 0)
		return (ENAMETOOLONG);

	while (resid && error == 0) {
		int watchcode;
		caddr_t vaddr;
		size_t part;
		size_t len;
		size_t size;
		int ta;
		int mapped;

		if ((part = PAGESIZE -
		    (((uintptr_t)uaddr) & PAGEOFFSET)) > resid)
			part = resid;

		if (!pr_is_watchpage(uaddr, S_WRITE)) {
			watchcode = 0;
		} else {
			vaddr = uaddr;
			watchcode = pr_is_watchpoint(&vaddr, &ta,
			    part, &len, S_WRITE);
			if (watchcode && ta == 0)
				part = vaddr - uaddr;
		}

		/*
		 * Copy the initial part, up to a watched address, if any.
		 */
		if (part != 0) {
			mapped = pr_mappage(uaddr, part, S_WRITE, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				error = copyoutstr_noerr(kaddr, uaddr, part,
				    &size);
			no_fault();
			if (mapped)
				pr_unmappage(uaddr, part, S_WRITE, 1);
			uaddr += size;
			kaddr += size;
			resid -= size;
			if (error == ENAMETOOLONG && resid > 0)
				error = 0;
			if (error != 0 || (watchcode &&
			    (uaddr < vaddr || kaddr[-1] == '\0')))
				break;	/* didn't reach the watched area */
		}

		/*
		 * If trapafter was specified, then copy through the
		 * watched area before taking the watchpoint trap.
		 */
		while (resid && watchcode && ta && len > part && error == 0 &&
		    size == part && kaddr[-1] != '\0') {
			len -= part;
			if ((part = PAGESIZE) > resid)
				part = resid;
			if (part > len)
				part = len;
			mapped = pr_mappage(uaddr, part, S_WRITE, 1);
			if (on_fault(&ljb))
				error = EFAULT;
			else
				error = copyoutstr_noerr(kaddr, uaddr, part,
				    &size);
			no_fault();
			if (mapped)
				pr_unmappage(uaddr, part, S_WRITE, 1);
			uaddr += size;
			kaddr += size;
			resid -= size;
			if (error == ENAMETOOLONG && resid > 0)
				error = 0;
		}

		/* if we hit a watched address, do the watchpoint logic */
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			error = EFAULT;
			break;
		}

		if (error == 0 && part != 0 &&
		    (size < part || kaddr[-1] == '\0'))
			break;
	}

	if (error != EFAULT && lencopied)
		*lencopied = maxlength - resid;
	return (error);
}

typedef int (*fuword_func)(const void *, void *);

/*
 * Generic form of watch_fuword8(), watch_fuword16(), etc.
 */
static int
watch_fuword(const void *addr, void *dst, fuword_func func, size_t size)
{
	klwp_t *lwp = ttolwp(curthread);
	int watchcode;
	caddr_t vaddr;
	int mapped;
	int rv = 0;
	int ta;
	label_t ljb;

	for (;;) {

		vaddr = (caddr_t)addr;
		watchcode = pr_is_watchpoint(&vaddr, &ta, size, NULL, S_READ);
		if (watchcode == 0 || ta != 0) {
			mapped = pr_mappage((caddr_t)addr, size, S_READ, 1);
			if (on_fault(&ljb))
				rv = -1;
			else
				(*func)(addr, dst);
			no_fault();
			if (mapped)
				pr_unmappage((caddr_t)addr, size, S_READ, 1);
		}
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			rv = -1;
			break;
		}
		if (watchcode == 0 || ta != 0)
			break;
	}

	return (rv);
}

static int
watch_fuword8(const void *addr, uint8_t *dst)
{
	return (watch_fuword(addr, dst, (fuword_func)fuword8_noerr,
	    sizeof (*dst)));
}

static int
watch_fuword16(const void *addr, uint16_t *dst)
{
	return (watch_fuword(addr, dst, (fuword_func)fuword16_noerr,
	    sizeof (*dst)));
}

static int
watch_fuword32(const void *addr, uint32_t *dst)
{
	return (watch_fuword(addr, dst, (fuword_func)fuword32_noerr,
	    sizeof (*dst)));
}

#ifdef _LP64
static int
watch_fuword64(const void *addr, uint64_t *dst)
{
	return (watch_fuword(addr, dst, (fuword_func)fuword64_noerr,
	    sizeof (*dst)));
}
#endif


static int
watch_suword8(void *addr, uint8_t value)
{
	klwp_t *lwp = ttolwp(curthread);
	int watchcode;
	caddr_t vaddr;
	int mapped;
	int rv = 0;
	int ta;
	label_t ljb;

	for (;;) {

		vaddr = (caddr_t)addr;
		watchcode = pr_is_watchpoint(&vaddr, &ta, sizeof (value), NULL,
		    S_WRITE);
		if (watchcode == 0 || ta != 0) {
			mapped = pr_mappage((caddr_t)addr, sizeof (value),
			    S_WRITE, 1);
			if (on_fault(&ljb))
				rv = -1;
			else
				suword8_noerr(addr, value);
			no_fault();
			if (mapped)
				pr_unmappage((caddr_t)addr, sizeof (value),
				    S_WRITE, 1);
		}
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			rv = -1;
			break;
		}
		if (watchcode == 0 || ta != 0)
			break;
	}

	return (rv);
}

static int
watch_suword16(void *addr, uint16_t value)
{
	klwp_t *lwp = ttolwp(curthread);
	int watchcode;
	caddr_t vaddr;
	int mapped;
	int rv = 0;
	int ta;
	label_t ljb;

	for (;;) {

		vaddr = (caddr_t)addr;
		watchcode = pr_is_watchpoint(&vaddr, &ta, sizeof (value), NULL,
		    S_WRITE);
		if (watchcode == 0 || ta != 0) {
			mapped = pr_mappage((caddr_t)addr, sizeof (value),
			    S_WRITE, 1);
			if (on_fault(&ljb))
				rv = -1;
			else
				suword16_noerr(addr, value);
			no_fault();
			if (mapped)
				pr_unmappage((caddr_t)addr, sizeof (value),
				    S_WRITE, 1);
		}
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			rv = -1;
			break;
		}
		if (watchcode == 0 || ta != 0)
			break;
	}

	return (rv);
}

static int
watch_suword32(void *addr, uint32_t value)
{
	klwp_t *lwp = ttolwp(curthread);
	int watchcode;
	caddr_t vaddr;
	int mapped;
	int rv = 0;
	int ta;
	label_t ljb;

	for (;;) {

		vaddr = (caddr_t)addr;
		watchcode = pr_is_watchpoint(&vaddr, &ta, sizeof (value), NULL,
		    S_WRITE);
		if (watchcode == 0 || ta != 0) {
			mapped = pr_mappage((caddr_t)addr, sizeof (value),
			    S_WRITE, 1);
			if (on_fault(&ljb))
				rv = -1;
			else
				suword32_noerr(addr, value);
			no_fault();
			if (mapped)
				pr_unmappage((caddr_t)addr, sizeof (value),
				    S_WRITE, 1);
		}
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			rv = -1;
			break;
		}
		if (watchcode == 0 || ta != 0)
			break;
	}

	return (rv);
}

#ifdef _LP64
static int
watch_suword64(void *addr, uint64_t value)
{
	klwp_t *lwp = ttolwp(curthread);
	int watchcode;
	caddr_t vaddr;
	int mapped;
	int rv = 0;
	int ta;
	label_t ljb;

	for (;;) {

		vaddr = (caddr_t)addr;
		watchcode = pr_is_watchpoint(&vaddr, &ta, sizeof (value), NULL,
		    S_WRITE);
		if (watchcode == 0 || ta != 0) {
			mapped = pr_mappage((caddr_t)addr, sizeof (value),
			    S_WRITE, 1);
			if (on_fault(&ljb))
				rv = -1;
			else
				suword64_noerr(addr, value);
			no_fault();
			if (mapped)
				pr_unmappage((caddr_t)addr, sizeof (value),
				    S_WRITE, 1);
		}
		if (watchcode &&
		    (!sys_watchpoint(vaddr, watchcode, ta) ||
		    lwp->lwp_sysabort)) {
			lwp->lwp_sysabort = 0;
			rv = -1;
			break;
		}
		if (watchcode == 0 || ta != 0)
			break;
	}

	return (rv);
}
#endif /* _LP64 */

/*
 * Check for watched addresses in the given address space.
 * Return 1 if this is true, otherwise 0.
 */
static int
pr_is_watched(caddr_t base, size_t len, int rw)
{
	caddr_t saddr = (caddr_t)((uintptr_t)base & (uintptr_t)PAGEMASK);
	caddr_t eaddr = base + len;
	caddr_t paddr;

	for (paddr = saddr; paddr < eaddr; paddr += PAGESIZE) {
		if (pr_is_watchpage(paddr, rw))
			return (1);
	}

	return (0);
}

/*
 * Wrapper for the physio() function.
 * Splits one uio operation with multiple iovecs into uio operations with
 * only one iovecs to do the watchpoint handling separately for each iovecs.
 */
static int
watch_physio(int (*strat)(struct buf *), struct buf *bp, dev_t dev,
    int rw, void (*mincnt)(struct buf *), struct uio *uio)
{
	struct uio auio;
	struct iovec *iov;
	caddr_t  base;
	size_t len;
	int seg_rw;
	int error = 0;

	if (uio->uio_segflg == UIO_SYSSPACE)
		return (default_physio(strat, bp, dev, rw, mincnt, uio));

	seg_rw = (rw == B_READ) ? S_WRITE : S_READ;

	while (uio->uio_iovcnt > 0) {
		if (uio->uio_resid == 0) {
			/*
			 * Make sure to return the uio structure with the
			 * same values as default_physio() does.
			 */
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}

		iov = uio->uio_iov;
		len = MIN(iov->iov_len, uio->uio_resid);

		auio.uio_iovcnt = 1;
		auio.uio_iov = iov;
		auio.uio_resid = len;
		auio.uio_loffset = uio->uio_loffset;
		auio.uio_llimit = uio->uio_llimit;
		auio.uio_fmode = uio->uio_fmode;
		auio.uio_extflg = uio->uio_extflg;
		auio.uio_segflg = uio->uio_segflg;

		base = iov->iov_base;

		if (!pr_is_watched(base, len, seg_rw)) {
			/*
			 * The given memory references don't cover a
			 * watched page.
			 */
			error = default_physio(strat, bp, dev, rw, mincnt,
			    &auio);

			/* Update uio with values from auio. */
			len -= auio.uio_resid;
			uio->uio_resid -= len;
			uio->uio_loffset += len;

			/*
			 * Return if an error occurred or not all data
			 * was copied.
			 */
			if (auio.uio_resid || error)
				break;
			uio->uio_iov++;
			uio->uio_iovcnt--;
		} else {
			int mapped, watchcode, ta;
			caddr_t vaddr = base;
			klwp_t *lwp = ttolwp(curthread);

			watchcode = pr_is_watchpoint(&vaddr, &ta, len,
			    NULL, seg_rw);

			if (watchcode == 0 || ta != 0) {
				/*
				 * Do the io if the given memory references
				 * don't cover a watched area (watchcode=0)
				 * or if WA_TRAPAFTER was specified.
				 */
				mapped = pr_mappage(base, len, seg_rw, 1);
				error = default_physio(strat, bp, dev, rw,
				    mincnt, &auio);
				if (mapped)
					pr_unmappage(base, len, seg_rw, 1);

				len -= auio.uio_resid;
				uio->uio_resid -= len;
				uio->uio_loffset += len;
			}

			/*
			 * If we hit a watched address, do the watchpoint logic.
			 */
			if (watchcode &&
			    (!sys_watchpoint(vaddr, watchcode, ta) ||
			    lwp->lwp_sysabort)) {
				lwp->lwp_sysabort = 0;
				return (EFAULT);
			}

			/*
			 * Check for errors from default_physio().
			 */
			if (watchcode == 0 || ta != 0) {
				if (auio.uio_resid || error)
					break;
				uio->uio_iov++;
				uio->uio_iovcnt--;
			}
		}
	}

	return (error);
}

int
wa_compare(const void *a, const void *b)
{
	const watched_area_t *pa = a;
	const watched_area_t *pb = b;

	if (pa->wa_vaddr < pb->wa_vaddr)
		return (-1);
	else if (pa->wa_vaddr > pb->wa_vaddr)
		return (1);
	else
		return (0);
}

int
wp_compare(const void *a, const void *b)
{
	const watched_page_t *pa = a;
	const watched_page_t *pb = b;

	if (pa->wp_vaddr < pb->wp_vaddr)
		return (-1);
	else if (pa->wp_vaddr > pb->wp_vaddr)
		return (1);
	else
		return (0);
}

/*
 * Given an address range, finds the first watched area which overlaps some or
 * all of the range.
 */
watched_area_t *
pr_find_watched_area(proc_t *p, watched_area_t *pwa, avl_index_t *where)
{
	caddr_t vaddr = pwa->wa_vaddr;
	caddr_t eaddr = pwa->wa_eaddr;
	watched_area_t *wap;
	avl_index_t real_where;

	/* First, check if there is an exact match.  */
	wap = avl_find(&p->p_warea, pwa, &real_where);


	/* Check to see if we overlap with the previous area.  */
	if (wap == NULL) {
		wap = avl_nearest(&p->p_warea, real_where, AVL_BEFORE);
		if (wap != NULL &&
		    (vaddr >= wap->wa_eaddr || eaddr <= wap->wa_vaddr))
			wap = NULL;
	}

	/* Try the next area.  */
	if (wap == NULL) {
		wap = avl_nearest(&p->p_warea, real_where, AVL_AFTER);
		if (wap != NULL &&
		    (vaddr >= wap->wa_eaddr || eaddr <= wap->wa_vaddr))
			wap = NULL;
	}

	if (where)
		*where = real_where;

	return (wap);
}

void
watch_enable(kthread_id_t t)
{
	t->t_proc_flag |= TP_WATCHPT;
	install_copyops(t, &watch_copyops);
}

void
watch_disable(kthread_id_t t)
{
	t->t_proc_flag &= ~TP_WATCHPT;
	remove_copyops(t);
}

int
copyin_nowatch(const void *uaddr, void *kaddr, size_t len)
{
	int watched, ret;

	watched = watch_disable_addr(uaddr, len, S_READ);
	ret = copyin(uaddr, kaddr, len);
	if (watched)
		watch_enable_addr(uaddr, len, S_READ);

	return (ret);
}

int
copyout_nowatch(const void *kaddr, void *uaddr, size_t len)
{
	int watched, ret;

	watched = watch_disable_addr(uaddr, len, S_WRITE);
	ret = copyout(kaddr, uaddr, len);
	if (watched)
		watch_enable_addr(uaddr, len, S_WRITE);

	return (ret);
}

#ifdef _LP64
int
fuword64_nowatch(const void *addr, uint64_t *value)
{
	int watched, ret;

	watched = watch_disable_addr(addr, sizeof (*value), S_READ);
	ret = fuword64(addr, value);
	if (watched)
		watch_enable_addr(addr, sizeof (*value), S_READ);

	return (ret);
}
#endif

int
fuword32_nowatch(const void *addr, uint32_t *value)
{
	int watched, ret;

	watched = watch_disable_addr(addr, sizeof (*value), S_READ);
	ret = fuword32(addr, value);
	if (watched)
		watch_enable_addr(addr, sizeof (*value), S_READ);

	return (ret);
}

#ifdef _LP64
int
suword64_nowatch(void *addr, uint64_t value)
{
	int watched, ret;

	watched = watch_disable_addr(addr, sizeof (value), S_WRITE);
	ret = suword64(addr, value);
	if (watched)
		watch_enable_addr(addr, sizeof (value), S_WRITE);

	return (ret);
}
#endif

int
suword32_nowatch(void *addr, uint32_t value)
{
	int watched, ret;

	watched = watch_disable_addr(addr, sizeof (value), S_WRITE);
	ret = suword32(addr, value);
	if (watched)
		watch_enable_addr(addr, sizeof (value), S_WRITE);

	return (ret);
}

int
watch_disable_addr(const void *addr, size_t len, enum seg_rw rw)
{
	if (pr_watch_active(curproc))
		return (pr_mappage((caddr_t)addr, len, rw, 1));
	return (0);
}

void
watch_enable_addr(const void *addr, size_t len, enum seg_rw rw)
{
	if (pr_watch_active(curproc))
		pr_unmappage((caddr_t)addr, len, rw, 1);
}

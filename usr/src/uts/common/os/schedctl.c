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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/schedctl.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/class.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/stack.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/sobject.h>
#include <sys/door.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vmsystm.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/swap.h>
#include <sys/lwp.h>
#include <sys/bitmap.h>
#include <sys/atomic.h>
#include <sys/fcntl.h>
#include <vm/seg_kp.h>
#include <vm/seg_vn.h>
#include <vm/as.h>
#include <fs/fs_subr.h>

/*
 * Page handling structures.  This is set up as a list of per-page
 * control structures (sc_page_ctl), with p->p_pagep pointing to
 * the first.  The per-page structures point to the actual pages
 * and contain pointers to the user address for each mapped page.
 *
 * All data is protected by p->p_sc_lock.  Since this lock is
 * held while waiting for memory, schedctl_shared_alloc() should
 * not be called while holding p_lock.
 */

typedef struct sc_page_ctl {
	struct sc_page_ctl *spc_next;
	sc_shared_t	*spc_base;	/* base of kernel page */
	sc_shared_t	*spc_end;	/* end of usable space */
	ulong_t		*spc_map;	/* bitmap of allocated space on page */
	size_t		spc_space;	/* amount of space on page */
	caddr_t		spc_uaddr;	/* user-level address of the page */
	struct anon_map	*spc_amp;	/* anonymous memory structure */
} sc_page_ctl_t;

static size_t	sc_pagesize;		/* size of usable space on page */
static size_t	sc_bitmap_len;		/* # of bits in allocation bitmap */
static size_t	sc_bitmap_words;	/* # of words in allocation bitmap */

/* Context ops */
static void	schedctl_save(sc_shared_t *);
static void	schedctl_restore(sc_shared_t *);
static void	schedctl_fork(kthread_t *, kthread_t *);

/* Functions for handling shared pages */
static int	schedctl_shared_alloc(sc_shared_t **, uintptr_t *);
static sc_page_ctl_t *schedctl_page_lookup(sc_shared_t *);
static int	schedctl_map(struct anon_map *, caddr_t *, caddr_t);
static int	schedctl_getpage(struct anon_map **, caddr_t *);
static void	schedctl_freepage(struct anon_map *, caddr_t);

/*
 * System call interface to scheduler activations.
 * This always operates on the current lwp.
 */
caddr_t
schedctl(void)
{
	kthread_t	*t = curthread;
	sc_shared_t	*ssp;
	uintptr_t	uaddr;
	int		error;

	if (t->t_schedctl == NULL) {
		/*
		 * Allocate and initialize the shared structure.
		 */
		if ((error = schedctl_shared_alloc(&ssp, &uaddr)) != 0)
			return ((caddr_t)(uintptr_t)set_errno(error));
		bzero(ssp, sizeof (*ssp));

		installctx(t, ssp, schedctl_save, schedctl_restore,
		    schedctl_fork, NULL, NULL, NULL);

		thread_lock(t);	/* protect against ts_tick and ts_update */
		t->t_schedctl = ssp;
		t->t_sc_uaddr = uaddr;
		ssp->sc_cid = t->t_cid;
		ssp->sc_cpri = t->t_cpri;
		ssp->sc_priority = DISP_PRIO(t);
		thread_unlock(t);
	}

	return ((caddr_t)t->t_sc_uaddr);
}


/*
 * Clean up scheduler activations state associated with an exiting
 * (or execing) lwp.  t is always the current thread.
 */
void
schedctl_lwp_cleanup(kthread_t *t)
{
	sc_shared_t	*ssp = t->t_schedctl;
	proc_t		*p = ttoproc(t);
	sc_page_ctl_t	*pagep;
	index_t		index;

	ASSERT(MUTEX_NOT_HELD(&p->p_lock));

	thread_lock(t);		/* protect against ts_tick and ts_update */
	t->t_schedctl = NULL;
	t->t_sc_uaddr = 0;
	thread_unlock(t);

	/*
	 * Remove the context op to avoid the final call to
	 * schedctl_save when switching away from this lwp.
	 */
	(void) removectx(t, ssp, schedctl_save, schedctl_restore,
	    schedctl_fork, NULL, NULL, NULL);

	/*
	 * Do not unmap the shared page until the process exits.
	 * User-level library code relies on this for adaptive mutex locking.
	 */
	mutex_enter(&p->p_sc_lock);
	ssp->sc_state = SC_FREE;
	pagep = schedctl_page_lookup(ssp);
	index = (index_t)(ssp - pagep->spc_base);
	BT_CLEAR(pagep->spc_map, index);
	pagep->spc_space += sizeof (sc_shared_t);
	mutex_exit(&p->p_sc_lock);
}


/*
 * Cleanup the list of schedctl shared pages for the process.
 * Called from exec() and exit() system calls.
 */
void
schedctl_proc_cleanup(void)
{
	proc_t *p = curproc;
	sc_page_ctl_t *pagep;
	sc_page_ctl_t *next;

	ASSERT(p->p_lwpcnt == 1);	/* we are single-threaded now */
	ASSERT(curthread->t_schedctl == NULL);

	/*
	 * Since we are single-threaded, we don't have to hold p->p_sc_lock.
	 */
	pagep = p->p_pagep;
	p->p_pagep = NULL;
	while (pagep != NULL) {
		ASSERT(pagep->spc_space == sc_pagesize);
		next = pagep->spc_next;
		/*
		 * Unmap the user space and free the mapping structure.
		 */
		(void) as_unmap(p->p_as, pagep->spc_uaddr, PAGESIZE);
		schedctl_freepage(pagep->spc_amp, (caddr_t)(pagep->spc_base));
		kmem_free(pagep->spc_map, sizeof (ulong_t) * sc_bitmap_words);
		kmem_free(pagep, sizeof (sc_page_ctl_t));
		pagep = next;
	}
}


/*
 * Called by resume just before switching away from the current thread.
 * Save new thread state.
 */
static void
schedctl_save(sc_shared_t *ssp)
{
	ssp->sc_state = curthread->t_state;
}


/*
 * Called by resume after switching to the current thread.
 * Save new thread state and CPU.
 */
static void
schedctl_restore(sc_shared_t *ssp)
{
	ssp->sc_state = SC_ONPROC;
	ssp->sc_cpu = CPU->cpu_id;
}


/*
 * On fork, remove inherited mappings from the child's address space.
 * The child's threads must call schedctl() to get new shared mappings.
 */
static void
schedctl_fork(kthread_t *pt, kthread_t *ct)
{
	proc_t *pp = ttoproc(pt);
	proc_t *cp = ttoproc(ct);
	sc_page_ctl_t *pagep;

	ASSERT(ct->t_schedctl == NULL);

	/*
	 * Do this only once, whether we are doing fork1() or forkall().
	 * Don't do it at all if the child process is a child of vfork()
	 * because a child of vfork() borrows the parent's address space.
	 */
	if (pt != curthread || (cp->p_flag & SVFORK))
		return;

	mutex_enter(&pp->p_sc_lock);
	for (pagep = pp->p_pagep; pagep != NULL; pagep = pagep->spc_next)
		(void) as_unmap(cp->p_as, pagep->spc_uaddr, PAGESIZE);
	mutex_exit(&pp->p_sc_lock);
}


/*
 * Returns non-zero if the specified thread shouldn't be preempted at this time.
 * Called by ts_preempt(), ts_tick(), and ts_update().
 */
int
schedctl_get_nopreempt(kthread_t *t)
{
	ASSERT(THREAD_LOCK_HELD(t));
	return (t->t_schedctl->sc_preemptctl.sc_nopreempt);
}


/*
 * Sets the value of the nopreempt field for the specified thread.
 * Called by ts_preempt() to clear the field on preemption.
 */
void
schedctl_set_nopreempt(kthread_t *t, short val)
{
	ASSERT(THREAD_LOCK_HELD(t));
	t->t_schedctl->sc_preemptctl.sc_nopreempt = val;
}


/*
 * Sets the value of the yield field for the specified thread.
 * Called by ts_preempt() and ts_tick() to set the field, and
 * ts_yield() to clear it.
 * The kernel never looks at this field so we don't need a
 * schedctl_get_yield() function.
 */
void
schedctl_set_yield(kthread_t *t, short val)
{
	ASSERT(THREAD_LOCK_HELD(t));
	t->t_schedctl->sc_preemptctl.sc_yield = val;
}


/*
 * Sets the values of the cid and priority fields for the specified thread.
 * Called from thread_change_pri(), thread_change_epri(), THREAD_CHANGE_PRI().
 * Called following calls to CL_FORKRET() and CL_ENTERCLASS().
 */
void
schedctl_set_cidpri(kthread_t *t)
{
	sc_shared_t *tdp = t->t_schedctl;

	if (tdp != NULL) {
		tdp->sc_cid = t->t_cid;
		tdp->sc_cpri = t->t_cpri;
		tdp->sc_priority = DISP_PRIO(t);
	}
}


/*
 * Returns non-zero if the specified thread has requested that all
 * signals be blocked.  Called by signal-related code that tests
 * the signal mask of a thread that may not be the current thread
 * and where the process's p_lock cannot be acquired.
 */
int
schedctl_sigblock(kthread_t *t)
{
	sc_shared_t *tdp = t->t_schedctl;

	if (tdp != NULL)
		return (tdp->sc_sigblock);
	return (0);
}


/*
 * If the sc_sigblock field is set for the specified thread, set
 * its signal mask to block all maskable signals, then clear the
 * sc_sigblock field.  This finishes what user-level code requested
 * to be done when it set tdp->sc_shared->sc_sigblock non-zero.
 * Called from signal-related code either by the current thread for
 * itself or by a thread that holds the process's p_lock (/proc code).
 */
void
schedctl_finish_sigblock(kthread_t *t)
{
	sc_shared_t *tdp = t->t_schedctl;

	ASSERT(t == curthread || MUTEX_HELD(&ttoproc(t)->p_lock));

	if (tdp != NULL && tdp->sc_sigblock) {
		t->t_hold.__sigbits[0] = FILLSET0 & ~CANTMASK0;
		t->t_hold.__sigbits[1] = FILLSET1 & ~CANTMASK1;
		t->t_hold.__sigbits[2] = FILLSET2 & ~CANTMASK2;
		tdp->sc_sigblock = 0;
	}
}


/*
 * Return non-zero if the current thread has declared that it has
 * a cancellation pending and that cancellation is not disabled.
 * If SIGCANCEL is blocked, we must be going over the wire in an
 * NFS transaction (sigintr() was called); return zero in this case.
 */
int
schedctl_cancel_pending(void)
{
	sc_shared_t *tdp = curthread->t_schedctl;

	if (tdp != NULL &&
	    (tdp->sc_flgs & SC_CANCEL_FLG) &&
	    !tdp->sc_sigblock &&
	    !sigismember(&curthread->t_hold, SIGCANCEL))
		return (1);
	return (0);
}


/*
 * Inform libc that the kernel returned EINTR from some system call
 * due to there being a cancellation pending (SC_CANCEL_FLG set or
 * we received an SI_LWP SIGCANCEL while in a system call), rather
 * than because of some other signal.  User-level code can try to
 * recover from receiving other signals, but it can't recover from
 * being cancelled.
 */
void
schedctl_cancel_eintr(void)
{
	sc_shared_t *tdp = curthread->t_schedctl;

	if (tdp != NULL)
		tdp->sc_flgs |= SC_EINTR_FLG;
}


/*
 * Return non-zero if the current thread has declared that
 * it is calling into the kernel to park, else return zero.
 */
int
schedctl_is_park(void)
{
	sc_shared_t *tdp = curthread->t_schedctl;

	if (tdp != NULL)
		return ((tdp->sc_flgs & SC_PARK_FLG) != 0);
	/*
	 * If we're here and there is no shared memory (how could
	 * that happen?) then just assume we really are here to park.
	 */
	return (1);
}


/*
 * Declare thread is parking.
 *
 * libc will set "sc_flgs |= SC_PARK_FLG" before calling lwpsys_park(0, tid)
 * in order to declare that the thread is calling into the kernel to park.
 *
 * This interface exists ONLY to support older versions of libthread which
 * are not aware of the SC_PARK_FLG flag.
 *
 * Older versions of libthread which are not aware of the SC_PARK_FLG flag
 * need to be modified or emulated to call lwpsys_park(4, ...) instead of
 * lwpsys_park(0, ...).  This will invoke schedctl_set_park() before
 * lwp_park() to declare that the thread is parking.
 */
void
schedctl_set_park(void)
{
	sc_shared_t *tdp = curthread->t_schedctl;
	if (tdp != NULL)
		tdp->sc_flgs |= SC_PARK_FLG;
}


/*
 * Clear the parking flag on return from parking in the kernel.
 */
void
schedctl_unpark(void)
{
	sc_shared_t *tdp = curthread->t_schedctl;

	if (tdp != NULL)
		tdp->sc_flgs &= ~SC_PARK_FLG;
}


/*
 * Page handling code.
 */

void
schedctl_init(void)
{
	/*
	 * Amount of page that can hold sc_shared_t structures.  If
	 * sizeof (sc_shared_t) is a power of 2, this should just be
	 * PAGESIZE.
	 */
	sc_pagesize = PAGESIZE - (PAGESIZE % sizeof (sc_shared_t));

	/*
	 * Allocation bitmap is one bit per struct on a page.
	 */
	sc_bitmap_len = sc_pagesize / sizeof (sc_shared_t);
	sc_bitmap_words = howmany(sc_bitmap_len, BT_NBIPUL);
}


static int
schedctl_shared_alloc(sc_shared_t **kaddrp, uintptr_t *uaddrp)
{
	proc_t		*p = curproc;
	sc_page_ctl_t	*pagep;
	sc_shared_t	*ssp;
	caddr_t		base;
	index_t		index;
	int		error;

	ASSERT(MUTEX_NOT_HELD(&p->p_lock));
	mutex_enter(&p->p_sc_lock);

	/*
	 * Try to find space for the new data in existing pages
	 * within the process's list of shared pages.
	 */
	for (pagep = p->p_pagep; pagep != NULL; pagep = pagep->spc_next)
		if (pagep->spc_space != 0)
			break;

	if (pagep != NULL)
		base = pagep->spc_uaddr;
	else {
		struct anon_map *amp;
		caddr_t kaddr;

		/*
		 * No room, need to allocate a new page.  Also set up
		 * a mapping to the kernel address space for the new
		 * page and lock it in memory.
		 */
		if ((error = schedctl_getpage(&amp, &kaddr)) != 0) {
			mutex_exit(&p->p_sc_lock);
			return (error);
		}
		if ((error = schedctl_map(amp, &base, kaddr)) != 0) {
			schedctl_freepage(amp, kaddr);
			mutex_exit(&p->p_sc_lock);
			return (error);
		}

		/*
		 * Allocate and initialize the page control structure.
		 */
		pagep = kmem_alloc(sizeof (sc_page_ctl_t), KM_SLEEP);
		pagep->spc_amp = amp;
		pagep->spc_base = (sc_shared_t *)kaddr;
		pagep->spc_end = (sc_shared_t *)(kaddr + sc_pagesize);
		pagep->spc_uaddr = base;

		pagep->spc_map = kmem_zalloc(sizeof (ulong_t) * sc_bitmap_words,
		    KM_SLEEP);
		pagep->spc_space = sc_pagesize;

		pagep->spc_next = p->p_pagep;
		p->p_pagep = pagep;
	}

	/*
	 * Got a page, now allocate space for the data.  There should
	 * be space unless something's wrong.
	 */
	ASSERT(pagep != NULL && pagep->spc_space >= sizeof (sc_shared_t));
	index = bt_availbit(pagep->spc_map, sc_bitmap_len);
	ASSERT(index != -1);

	/*
	 * Get location with pointer arithmetic.  spc_base is of type
	 * sc_shared_t *.  Mark as allocated.
	 */
	ssp = pagep->spc_base + index;
	BT_SET(pagep->spc_map, index);
	pagep->spc_space -= sizeof (sc_shared_t);

	mutex_exit(&p->p_sc_lock);

	/*
	 * Return kernel and user addresses.
	 */
	*kaddrp = ssp;
	*uaddrp = (uintptr_t)base + ((uintptr_t)ssp & PAGEOFFSET);
	return (0);
}


/*
 * Find the page control structure corresponding to a kernel address.
 */
static sc_page_ctl_t *
schedctl_page_lookup(sc_shared_t *ssp)
{
	proc_t *p = curproc;
	sc_page_ctl_t *pagep;

	ASSERT(MUTEX_HELD(&p->p_sc_lock));
	for (pagep = p->p_pagep; pagep != NULL; pagep = pagep->spc_next) {
		if (ssp >= pagep->spc_base && ssp < pagep->spc_end)
			return (pagep);
	}
	return (NULL);		/* This "can't happen".  Should we panic? */
}


/*
 * This function is called when a page needs to be mapped into a
 * process's address space.  Allocate the user address space and
 * set up the mapping to the page.  Assumes the page has already
 * been allocated and locked in memory via schedctl_getpage.
 */
static int
schedctl_map(struct anon_map *amp, caddr_t *uaddrp, caddr_t kaddr)
{
	caddr_t addr = NULL;
	struct as *as = curproc->p_as;
	struct segvn_crargs vn_a;
	int error;

	as_rangelock(as);
	/* pass address of kernel mapping as offset to avoid VAC conflicts */
	map_addr(&addr, PAGESIZE, (offset_t)(uintptr_t)kaddr, 1, 0);
	if (addr == NULL) {
		as_rangeunlock(as);
		return (ENOMEM);
	}

	/*
	 * Use segvn to set up the mapping to the page.
	 */
	vn_a.vp = NULL;
	vn_a.offset = 0;
	vn_a.cred = NULL;
	vn_a.type = MAP_SHARED;
	vn_a.prot = vn_a.maxprot = PROT_ALL;
	vn_a.flags = 0;
	vn_a.amp = amp;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;
	error = as_map(as, addr, PAGESIZE, segvn_create, &vn_a);
	as_rangeunlock(as);

	if (error)
		return (error);

	*uaddrp = addr;
	return (0);
}


/*
 * Allocate a new page from anonymous memory.  Also, create a kernel
 * mapping to the page and lock the page in memory.
 */
static int
schedctl_getpage(struct anon_map **newamp, caddr_t *newaddr)
{
	struct anon_map *amp;
	caddr_t kaddr;

	/*
	 * Set up anonymous memory struct.  No swap reservation is
	 * needed since the page will be locked into memory.
	 */
	amp = anonmap_alloc(PAGESIZE, 0, ANON_SLEEP);

	/*
	 * Allocate the page.
	 */
	kaddr = segkp_get_withanonmap(segkp, PAGESIZE,
	    KPD_NO_ANON | KPD_LOCKED | KPD_ZERO, amp);
	if (kaddr == NULL) {
		amp->refcnt--;
		anonmap_free(amp);
		return (ENOMEM);
	}

	/*
	 * The page is left SE_SHARED locked so that it won't be
	 * paged out or relocated (KPD_LOCKED above).
	 */

	*newamp = amp;
	*newaddr = kaddr;
	return (0);
}


/*
 * Take the necessary steps to allow a page to be released.
 * This is called when the process is doing exit() or exec().
 * There should be no accesses to the page after this.
 * The kernel mapping of the page is released and the page is unlocked.
 */
static void
schedctl_freepage(struct anon_map *amp, caddr_t kaddr)
{
	/*
	 * Release the lock on the page and remove the kernel mapping.
	 */
	ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
	segkp_release(segkp, kaddr);

	/*
	 * Decrement the refcnt so the anon_map structure will be freed.
	 */
	if (--amp->refcnt == 0) {
		/*
		 * The current process no longer has the page mapped, so
		 * we have to free everything rather than letting as_free
		 * do the work.
		 */
		anonmap_purge(amp);
		anon_free(amp->ahp, 0, PAGESIZE);
		ANON_LOCK_EXIT(&amp->a_rwlock);
		anonmap_free(amp);
	} else {
		ANON_LOCK_EXIT(&amp->a_rwlock);
	}
}

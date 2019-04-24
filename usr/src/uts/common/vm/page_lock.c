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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */


/*
 * VM - page locking primitives
 */
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/vtrace.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/bitmap.h>
#include <sys/lockstat.h>
#include <sys/sysmacros.h>
#include <sys/condvar_impl.h>
#include <vm/page.h>
#include <vm/seg_enum.h>
#include <vm/vm_dep.h>
#include <vm/seg_kmem.h>

/*
 * This global mutex array is for logical page locking.
 * The following fields in the page structure are protected
 * by this lock:
 *
 *	p_lckcnt
 *	p_cowcnt
 */
pad_mutex_t page_llocks[8 * NCPU_P2];

/*
 * This is a global lock for the logical page free list.  The
 * logical free list, in this implementation, is maintained as two
 * separate physical lists - the cache list and the free list.
 */
kmutex_t  page_freelock;

/*
 * The hash table, page_hash[], the p_selock fields, and the
 * list of pages associated with vnodes are protected by arrays of mutexes.
 *
 * Unless the hashes are changed radically, the table sizes must be
 * a power of two.  Also, we typically need more mutexes for the
 * vnodes since these locks are occasionally held for long periods.
 * And since there seem to be two special vnodes (kvp and swapvp),
 * we make room for private mutexes for them.
 *
 * The pse_mutex[] array holds the mutexes to protect the p_selock
 * fields of all page_t structures.
 *
 * PAGE_SE_MUTEX(pp) returns the address of the appropriate mutex
 * when given a pointer to a page_t.
 *
 * PIO_TABLE_SIZE must be a power of two.  One could argue that we
 * should go to the trouble of setting it up at run time and base it
 * on memory size rather than the number of compile time CPUs.
 *
 * XX64	We should be using physmem size to calculate PIO_SHIFT.
 *
 *	These might break in 64 bit world.
 */
#define	PIO_SHIFT	7	/* log2(sizeof(page_t)) */
#define	PIO_TABLE_SIZE	128	/* number of io mutexes to have */

pad_mutex_t	ph_mutex[PH_TABLE_SIZE];
kmutex_t	pio_mutex[PIO_TABLE_SIZE];

#define	PAGE_IO_MUTEX(pp) \
	    &pio_mutex[(((uintptr_t)pp) >> PIO_SHIFT) & (PIO_TABLE_SIZE - 1)]

/*
 * The pse_mutex[] array is allocated in the platform startup code
 * based on the size of the machine at startup.
 */
extern pad_mutex_t *pse_mutex;		/* Locks protecting pp->p_selock */
extern size_t pse_table_size;		/* Number of mutexes in pse_mutex[] */
extern int pse_shift;			/* log2(pse_table_size) */
#define	PAGE_SE_MUTEX(pp)	&pse_mutex[				\
	((((uintptr_t)(pp) >> pse_shift) ^ ((uintptr_t)(pp))) >> 7) &	\
	(pse_table_size - 1)].pad_mutex

#define	PSZC_MTX_TABLE_SIZE	128
#define	PSZC_MTX_TABLE_SHIFT	7

static pad_mutex_t	pszc_mutex[PSZC_MTX_TABLE_SIZE];

#define	PAGE_SZC_MUTEX(_pp) \
	    &pszc_mutex[((((uintptr_t)(_pp) >> PSZC_MTX_TABLE_SHIFT) ^ \
		((uintptr_t)(_pp) >> (PSZC_MTX_TABLE_SHIFT << 1)) ^ \
		((uintptr_t)(_pp) >> (3 * PSZC_MTX_TABLE_SHIFT))) & \
		(PSZC_MTX_TABLE_SIZE - 1))].pad_mutex

/*
 * The vph_mutex[] array  holds the mutexes to protect the vnode chains,
 * (i.e., the list of pages anchored by v_pages and connected via p_vpprev
 * and p_vpnext).
 *
 * The page_vnode_mutex(vp) function returns the address of the appropriate
 * mutex from this array given a pointer to a vnode.  It is complicated
 * by the fact that the kernel's vnode and the swapfs vnode are referenced
 * frequently enough to warrent their own mutexes.
 *
 * The VP_HASH_FUNC returns the index into the vph_mutex array given
 * an address of a vnode.
 */

#if defined(_LP64)
#define	VPH_TABLE_SIZE  (8 * NCPU_P2)
#else	/* 32 bits */
#define	VPH_TABLE_SIZE	(2 * NCPU_P2)
#endif

#define	VP_HASH_FUNC(vp) \
	((((uintptr_t)(vp) >> 6) + \
	    ((uintptr_t)(vp) >> 8) + \
	    ((uintptr_t)(vp) >> 10) + \
	    ((uintptr_t)(vp) >> 12)) \
	    & (VPH_TABLE_SIZE - 1))

/*
 * Two slots after VPH_TABLE_SIZE are reserved in vph_mutex for kernel vnodes,
 * one for kvps[KV_ZVP], and one for other kvps[] users.
 */

kmutex_t	vph_mutex[VPH_TABLE_SIZE + 2];

/*
 * Initialize the locks used by the Virtual Memory Management system.
 */
void
page_lock_init()
{
}

/*
 * Return a value for pse_shift based on npg (the number of physical pages)
 * and ncpu (the maximum number of CPUs).  This is called by platform startup
 * code.
 *
 * Lockstat data from TPC-H runs showed that contention on the pse_mutex[]
 * locks grew approximately as the square of the number of threads executing.
 * So the primary scaling factor used is NCPU^2.  The size of the machine in
 * megabytes is used as an upper bound, particularly for sun4v machines which
 * all claim to have 256 CPUs maximum, and the old value of PSE_TABLE_SIZE
 * (128) is used as a minimum.  Since the size of the table has to be a power
 * of two, the calculated size is rounded up to the next power of two.
 */
/*ARGSUSED*/
int
size_pse_array(pgcnt_t npg, int ncpu)
{
	size_t size;
	pgcnt_t pp_per_mb = (1024 * 1024) / PAGESIZE;

	size = MAX(128, MIN(npg / pp_per_mb, 2 * ncpu * ncpu));
	size += (1 << (highbit(size) - 1)) - 1;
	return (highbit(size) - 1);
}

/*
 * At present we only use page ownership to aid debugging, so it's
 * OK if the owner field isn't exact.  In the 32-bit world two thread ids
 * can map to the same owner because we just 'or' in 0x80000000 and
 * then clear the second highest bit, so that (for example) 0x2faced00
 * and 0xafaced00 both map to 0xafaced00.
 * In the 64-bit world, p_selock may not be large enough to hold a full
 * thread pointer.  If we ever need precise ownership (e.g. if we implement
 * priority inheritance for page locks) then p_selock should become a
 * uintptr_t and SE_WRITER should be -((uintptr_t)curthread >> 2).
 */
#define	SE_WRITER	(((selock_t)(ulong_t)curthread | INT_MIN) & ~SE_EWANTED)
#define	SE_READER	1

/*
 * A page that is deleted must be marked as such using the
 * page_lock_delete() function. The page must be exclusively locked.
 * The SE_DELETED marker is put in p_selock when this function is called.
 * SE_DELETED must be distinct from any SE_WRITER value.
 */
#define	SE_DELETED	(1 | INT_MIN)

#ifdef VM_STATS
uint_t	vph_kvp_count;
uint_t	vph_swapfsvp_count;
uint_t	vph_other;
#endif /* VM_STATS */

#ifdef VM_STATS
uint_t	page_lock_count;
uint_t	page_lock_miss;
uint_t	page_lock_miss_lock;
uint_t	page_lock_reclaim;
uint_t	page_lock_bad_reclaim;
uint_t	page_lock_same_page;
uint_t	page_lock_upgrade;
uint_t	page_lock_retired;
uint_t	page_lock_upgrade_failed;
uint_t	page_lock_deleted;

uint_t	page_trylock_locked;
uint_t	page_trylock_failed;
uint_t	page_trylock_missed;

uint_t	page_try_reclaim_upgrade;
#endif /* VM_STATS */

/*
 * Acquire the "shared/exclusive" lock on a page.
 *
 * Returns 1 on success and locks the page appropriately.
 *	   0 on failure and does not lock the page.
 *
 * If `lock' is non-NULL, it will be dropped and reacquired in the
 * failure case.  This routine can block, and if it does
 * it will always return a failure since the page identity [vp, off]
 * or state may have changed.
 */

int
page_lock(page_t *pp, se_t se, kmutex_t *lock, reclaim_t reclaim)
{
	return (page_lock_es(pp, se, lock, reclaim, 0));
}

/*
 * With the addition of reader-writer lock semantics to page_lock_es,
 * callers wanting an exclusive (writer) lock may prevent shared-lock
 * (reader) starvation by setting the es parameter to SE_EXCL_WANTED.
 * In this case, when an exclusive lock cannot be acquired, p_selock's
 * SE_EWANTED bit is set. Shared-lock (reader) requests are also denied
 * if the page is slated for retirement.
 *
 * The se and es parameters determine if the lock should be granted
 * based on the following decision table:
 *
 * Lock wanted   es flags     p_selock/SE_EWANTED  Action
 * ----------- -------------- -------------------  ---------
 * SE_EXCL        any [1][2]   unlocked/any        grant lock, clear SE_EWANTED
 * SE_EXCL        SE_EWANTED   any lock/any        deny, set SE_EWANTED
 * SE_EXCL        none         any lock/any        deny
 * SE_SHARED      n/a [2]        shared/0          grant
 * SE_SHARED      n/a [2]      unlocked/0          grant
 * SE_SHARED      n/a            shared/1          deny
 * SE_SHARED      n/a          unlocked/1          deny
 * SE_SHARED      n/a              excl/any        deny
 *
 * Notes:
 * [1] The code grants an exclusive lock to the caller and clears the bit
 *   SE_EWANTED whenever p_selock is unlocked, regardless of the SE_EWANTED
 *   bit's value.  This was deemed acceptable as we are not concerned about
 *   exclusive-lock starvation. If this ever becomes an issue, a priority or
 *   fifo mechanism should also be implemented. Meantime, the thread that
 *   set SE_EWANTED should be prepared to catch this condition and reset it
 *
 * [2] Retired pages may not be locked at any time, regardless of the
 *   dispostion of se, unless the es parameter has SE_RETIRED flag set.
 *
 * Notes on values of "es":
 *
 *   es & 1: page_lookup_create will attempt page relocation
 *   es & SE_EXCL_WANTED: caller wants SE_EWANTED set (eg. delete
 *       memory thread); this prevents reader-starvation of waiting
 *       writer thread(s) by giving priority to writers over readers.
 *   es & SE_RETIRED: caller wants to lock pages even if they are
 *       retired.  Default is to deny the lock if the page is retired.
 *
 * And yes, we know, the semantics of this function are too complicated.
 * It's on the list to be cleaned up.
 */
int
page_lock_es(page_t *pp, se_t se, kmutex_t *lock, reclaim_t reclaim, int es)
{
	int		retval;
	kmutex_t	*pse = PAGE_SE_MUTEX(pp);
	int		upgraded;
	int		reclaim_it;

	ASSERT(lock != NULL ? MUTEX_HELD(lock) : 1);

	VM_STAT_ADD(page_lock_count);

	upgraded = 0;
	reclaim_it = 0;

	mutex_enter(pse);

	ASSERT(((es & SE_EXCL_WANTED) == 0) ||
	    ((es & SE_EXCL_WANTED) && (se == SE_EXCL)));

	if (PP_RETIRED(pp) && !(es & SE_RETIRED)) {
		mutex_exit(pse);
		VM_STAT_ADD(page_lock_retired);
		return (0);
	}

	if (se == SE_SHARED && es == 1 && pp->p_selock == 0) {
		se = SE_EXCL;
	}

	if ((reclaim == P_RECLAIM) && (PP_ISFREE(pp))) {

		reclaim_it = 1;
		if (se == SE_SHARED) {
			/*
			 * This is an interesting situation.
			 *
			 * Remember that p_free can only change if
			 * p_selock < 0.
			 * p_free does not depend on our holding `pse'.
			 * And, since we hold `pse', p_selock can not change.
			 * So, if p_free changes on us, the page is already
			 * exclusively held, and we would fail to get p_selock
			 * regardless.
			 *
			 * We want to avoid getting the share
			 * lock on a free page that needs to be reclaimed.
			 * It is possible that some other thread has the share
			 * lock and has left the free page on the cache list.
			 * pvn_vplist_dirty() does this for brief periods.
			 * If the se_share is currently SE_EXCL, we will fail
			 * to acquire p_selock anyway.  Blocking is the
			 * right thing to do.
			 * If we need to reclaim this page, we must get
			 * exclusive access to it, force the upgrade now.
			 * Again, we will fail to acquire p_selock if the
			 * page is not free and block.
			 */
			upgraded = 1;
			se = SE_EXCL;
			VM_STAT_ADD(page_lock_upgrade);
		}
	}

	if (se == SE_EXCL) {
		if (!(es & SE_EXCL_WANTED) && (pp->p_selock & SE_EWANTED)) {
			/*
			 * if the caller wants a writer lock (but did not
			 * specify exclusive access), and there is a pending
			 * writer that wants exclusive access, return failure
			 */
			retval = 0;
		} else if ((pp->p_selock & ~SE_EWANTED) == 0) {
			/* no reader/writer lock held */
			/* this clears our setting of the SE_EWANTED bit */
			pp->p_selock = SE_WRITER;
			retval = 1;
		} else {
			/* page is locked */
			if (es & SE_EXCL_WANTED) {
				/* set the SE_EWANTED bit */
				pp->p_selock |= SE_EWANTED;
			}
			retval = 0;
		}
	} else {
		retval = 0;
		if (pp->p_selock >= 0) {
			if ((pp->p_selock & SE_EWANTED) == 0) {
				pp->p_selock += SE_READER;
				retval = 1;
			}
		}
	}

	if (retval == 0) {
		if ((pp->p_selock & ~SE_EWANTED) == SE_DELETED) {
			VM_STAT_ADD(page_lock_deleted);
			mutex_exit(pse);
			return (retval);
		}

#ifdef VM_STATS
		VM_STAT_ADD(page_lock_miss);
		if (upgraded) {
			VM_STAT_ADD(page_lock_upgrade_failed);
		}
#endif
		if (lock) {
			VM_STAT_ADD(page_lock_miss_lock);
			mutex_exit(lock);
		}

		/*
		 * Now, wait for the page to be unlocked and
		 * release the lock protecting p_cv and p_selock.
		 */
		cv_wait(&pp->p_cv, pse);
		mutex_exit(pse);

		/*
		 * The page identity may have changed while we were
		 * blocked.  If we are willing to depend on "pp"
		 * still pointing to a valid page structure (i.e.,
		 * assuming page structures are not dynamically allocated
		 * or freed), we could try to lock the page if its
		 * identity hasn't changed.
		 *
		 * This needs to be measured, since we come back from
		 * cv_wait holding pse (the expensive part of this
		 * operation) we might as well try the cheap part.
		 * Though we would also have to confirm that dropping
		 * `lock' did not cause any grief to the callers.
		 */
		if (lock) {
			mutex_enter(lock);
		}
	} else {
		/*
		 * We have the page lock.
		 * If we needed to reclaim the page, and the page
		 * needed reclaiming (ie, it was free), then we
		 * have the page exclusively locked.  We may need
		 * to downgrade the page.
		 */
		ASSERT((upgraded) ?
		    ((PP_ISFREE(pp)) && PAGE_EXCL(pp)) : 1);
		mutex_exit(pse);

		/*
		 * We now hold this page's lock, either shared or
		 * exclusive.  This will prevent its identity from changing.
		 * The page, however, may or may not be free.  If the caller
		 * requested, and it is free, go reclaim it from the
		 * free list.  If the page can't be reclaimed, return failure
		 * so that the caller can start all over again.
		 *
		 * NOTE:page_reclaim() releases the page lock (p_selock)
		 *	if it can't be reclaimed.
		 */
		if (reclaim_it) {
			if (!page_reclaim(pp, lock)) {
				VM_STAT_ADD(page_lock_bad_reclaim);
				retval = 0;
			} else {
				VM_STAT_ADD(page_lock_reclaim);
				if (upgraded) {
					page_downgrade(pp);
				}
			}
		}
	}
	return (retval);
}

/*
 * Clear the SE_EWANTED bit from p_selock.  This function allows
 * callers of page_lock_es and page_try_reclaim_lock to clear
 * their setting of this bit if they decide they no longer wish
 * to gain exclusive access to the page.  Currently only
 * delete_memory_thread uses this when the delete memory
 * operation is cancelled.
 */
void
page_lock_clr_exclwanted(page_t *pp)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);

	mutex_enter(pse);
	pp->p_selock &= ~SE_EWANTED;
	if (CV_HAS_WAITERS(&pp->p_cv))
		cv_broadcast(&pp->p_cv);
	mutex_exit(pse);
}

/*
 * Read the comments inside of page_lock_es() carefully.
 *
 * SE_EXCL callers specifying es == SE_EXCL_WANTED will cause the
 * SE_EWANTED bit of p_selock to be set when the lock cannot be obtained.
 * This is used by threads subject to reader-starvation (eg. memory delete).
 *
 * When a thread using SE_EXCL_WANTED does not obtain the SE_EXCL lock,
 * it is expected that it will retry at a later time.  Threads that will
 * not retry the lock *must* call page_lock_clr_exclwanted to clear the
 * SE_EWANTED bit.  (When a thread using SE_EXCL_WANTED obtains the lock,
 * the bit is cleared.)
 */
int
page_try_reclaim_lock(page_t *pp, se_t se, int es)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);
	selock_t old;

	mutex_enter(pse);

	old = pp->p_selock;

	ASSERT(((es & SE_EXCL_WANTED) == 0) ||
	    ((es & SE_EXCL_WANTED) && (se == SE_EXCL)));

	if (PP_RETIRED(pp) && !(es & SE_RETIRED)) {
		mutex_exit(pse);
		VM_STAT_ADD(page_trylock_failed);
		return (0);
	}

	if (se == SE_SHARED && es == 1 && old == 0) {
		se = SE_EXCL;
	}

	if (se == SE_SHARED) {
		if (!PP_ISFREE(pp)) {
			if (old >= 0) {
				/*
				 * Readers are not allowed when excl wanted
				 */
				if ((old & SE_EWANTED) == 0) {
					pp->p_selock = old + SE_READER;
					mutex_exit(pse);
					return (1);
				}
			}
			mutex_exit(pse);
			return (0);
		}
		/*
		 * The page is free, so we really want SE_EXCL (below)
		 */
		VM_STAT_ADD(page_try_reclaim_upgrade);
	}

	/*
	 * The caller wants a writer lock.  We try for it only if
	 * SE_EWANTED is not set, or if the caller specified
	 * SE_EXCL_WANTED.
	 */
	if (!(old & SE_EWANTED) || (es & SE_EXCL_WANTED)) {
		if ((old & ~SE_EWANTED) == 0) {
			/* no reader/writer lock held */
			/* this clears out our setting of the SE_EWANTED bit */
			pp->p_selock = SE_WRITER;
			mutex_exit(pse);
			return (1);
		}
	}
	if (es & SE_EXCL_WANTED) {
		/* page is locked, set the SE_EWANTED bit */
		pp->p_selock |= SE_EWANTED;
	}
	mutex_exit(pse);
	return (0);
}

/*
 * Acquire a page's "shared/exclusive" lock, but never block.
 * Returns 1 on success, 0 on failure.
 */
int
page_trylock(page_t *pp, se_t se)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);

	mutex_enter(pse);
	if (pp->p_selock & SE_EWANTED || PP_RETIRED(pp) ||
	    (se == SE_SHARED && PP_PR_NOSHARE(pp))) {
		/*
		 * Fail if a thread wants exclusive access and page is
		 * retired, if the page is slated for retirement, or a
		 * share lock is requested.
		 */
		mutex_exit(pse);
		VM_STAT_ADD(page_trylock_failed);
		return (0);
	}

	if (se == SE_EXCL) {
		if (pp->p_selock == 0) {
			pp->p_selock = SE_WRITER;
			mutex_exit(pse);
			return (1);
		}
	} else {
		if (pp->p_selock >= 0) {
			pp->p_selock += SE_READER;
			mutex_exit(pse);
			return (1);
		}
	}
	mutex_exit(pse);
	return (0);
}

/*
 * Variant of page_unlock() specifically for the page freelist
 * code. The mere existence of this code is a vile hack that
 * has resulted due to the backwards locking order of the page
 * freelist manager; please don't call it.
 */
void
page_unlock_nocapture(page_t *pp)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);
	selock_t old;

	mutex_enter(pse);

	old = pp->p_selock;
	if ((old & ~SE_EWANTED) == SE_READER) {
		pp->p_selock = old & ~SE_READER;
		if (CV_HAS_WAITERS(&pp->p_cv))
			cv_broadcast(&pp->p_cv);
	} else if ((old & ~SE_EWANTED) == SE_DELETED) {
		panic("page_unlock_nocapture: page %p is deleted", (void *)pp);
	} else if (old < 0) {
		pp->p_selock &= SE_EWANTED;
		if (CV_HAS_WAITERS(&pp->p_cv))
			cv_broadcast(&pp->p_cv);
	} else if ((old & ~SE_EWANTED) > SE_READER) {
		pp->p_selock = old - SE_READER;
	} else {
		panic("page_unlock_nocapture: page %p is not locked",
		    (void *)pp);
	}

	mutex_exit(pse);
}

/*
 * Release the page's "shared/exclusive" lock and wake up anyone
 * who might be waiting for it.
 */
void
page_unlock(page_t *pp)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);
	selock_t old;

	mutex_enter(pse);

	old = pp->p_selock;
	if ((old & ~SE_EWANTED) == SE_READER) {
		pp->p_selock = old & ~SE_READER;
		if (CV_HAS_WAITERS(&pp->p_cv))
			cv_broadcast(&pp->p_cv);
	} else if ((old & ~SE_EWANTED) == SE_DELETED) {
		panic("page_unlock: page %p is deleted", (void *)pp);
	} else if (old < 0) {
		pp->p_selock &= SE_EWANTED;
		if (CV_HAS_WAITERS(&pp->p_cv))
			cv_broadcast(&pp->p_cv);
	} else if ((old & ~SE_EWANTED) > SE_READER) {
		pp->p_selock = old - SE_READER;
	} else {
		panic("page_unlock: page %p is not locked", (void *)pp);
	}

	if (pp->p_selock == 0) {
		/*
		 * If the T_CAPTURING bit is set, that means that we should
		 * not try and capture the page again as we could recurse
		 * which could lead to a stack overflow panic or spending a
		 * relatively long time in the kernel making no progress.
		 */
		if ((pp->p_toxic & PR_CAPTURE) &&
		    !(curthread->t_flag & T_CAPTURING) &&
		    !PP_RETIRED(pp)) {
			pp->p_selock = SE_WRITER;
			mutex_exit(pse);
			page_unlock_capture(pp);
		} else {
			mutex_exit(pse);
		}
	} else {
		mutex_exit(pse);
	}
}

/*
 * Try to upgrade the lock on the page from a "shared" to an
 * "exclusive" lock.  Since this upgrade operation is done while
 * holding the mutex protecting this page, no one else can acquire this page's
 * lock and change the page. Thus, it is safe to drop the "shared"
 * lock and attempt to acquire the "exclusive" lock.
 *
 * Returns 1 on success, 0 on failure.
 */
int
page_tryupgrade(page_t *pp)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);

	mutex_enter(pse);
	if (!(pp->p_selock & SE_EWANTED)) {
		/* no threads want exclusive access, try upgrade */
		if (pp->p_selock == SE_READER) {
			/* convert to exclusive lock */
			pp->p_selock = SE_WRITER;
			mutex_exit(pse);
			return (1);
		}
	}
	mutex_exit(pse);
	return (0);
}

/*
 * Downgrade the "exclusive" lock on the page to a "shared" lock
 * while holding the mutex protecting this page's p_selock field.
 */
void
page_downgrade(page_t *pp)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);
	int excl_waiting;

	ASSERT((pp->p_selock & ~SE_EWANTED) != SE_DELETED);
	ASSERT(PAGE_EXCL(pp));

	mutex_enter(pse);
	excl_waiting =  pp->p_selock & SE_EWANTED;
	pp->p_selock = SE_READER | excl_waiting;
	if (CV_HAS_WAITERS(&pp->p_cv))
		cv_broadcast(&pp->p_cv);
	mutex_exit(pse);
}

void
page_lock_delete(page_t *pp)
{
	kmutex_t *pse = PAGE_SE_MUTEX(pp);

	ASSERT(PAGE_EXCL(pp));
	ASSERT(pp->p_vnode == NULL);
	ASSERT(pp->p_offset == (u_offset_t)-1);
	ASSERT(!PP_ISFREE(pp));

	mutex_enter(pse);
	pp->p_selock = SE_DELETED;
	if (CV_HAS_WAITERS(&pp->p_cv))
		cv_broadcast(&pp->p_cv);
	mutex_exit(pse);
}

int
page_deleted(page_t *pp)
{
	return (pp->p_selock == SE_DELETED);
}

/*
 * Implement the io lock for pages
 */
void
page_iolock_init(page_t *pp)
{
	pp->p_iolock_state = 0;
	cv_init(&pp->p_io_cv, NULL, CV_DEFAULT, NULL);
}

/*
 * Acquire the i/o lock on a page.
 */
void
page_io_lock(page_t *pp)
{
	kmutex_t *pio;

	pio = PAGE_IO_MUTEX(pp);
	mutex_enter(pio);
	while (pp->p_iolock_state & PAGE_IO_INUSE) {
		cv_wait(&(pp->p_io_cv), pio);
	}
	pp->p_iolock_state |= PAGE_IO_INUSE;
	mutex_exit(pio);
}

/*
 * Release the i/o lock on a page.
 */
void
page_io_unlock(page_t *pp)
{
	kmutex_t *pio;

	pio = PAGE_IO_MUTEX(pp);
	mutex_enter(pio);
	cv_broadcast(&pp->p_io_cv);
	pp->p_iolock_state &= ~PAGE_IO_INUSE;
	mutex_exit(pio);
}

/*
 * Try to acquire the i/o lock on a page without blocking.
 * Returns 1 on success, 0 on failure.
 */
int
page_io_trylock(page_t *pp)
{
	kmutex_t *pio;

	if (pp->p_iolock_state & PAGE_IO_INUSE)
		return (0);

	pio = PAGE_IO_MUTEX(pp);
	mutex_enter(pio);

	if (pp->p_iolock_state & PAGE_IO_INUSE) {
		mutex_exit(pio);
		return (0);
	}
	pp->p_iolock_state |= PAGE_IO_INUSE;
	mutex_exit(pio);

	return (1);
}

/*
 * Wait until the i/o lock is not held.
 */
void
page_io_wait(page_t *pp)
{
	kmutex_t *pio;

	pio = PAGE_IO_MUTEX(pp);
	mutex_enter(pio);
	while (pp->p_iolock_state & PAGE_IO_INUSE) {
		cv_wait(&(pp->p_io_cv), pio);
	}
	mutex_exit(pio);
}

/*
 * Returns 1 on success, 0 on failure.
 */
int
page_io_locked(page_t *pp)
{
	return (pp->p_iolock_state & PAGE_IO_INUSE);
}

/*
 * Assert that the i/o lock on a page is held.
 * Returns 1 on success, 0 on failure.
 */
int
page_iolock_assert(page_t *pp)
{
	return (page_io_locked(pp));
}

/*
 * Wrapper exported to kernel routines that are built
 * platform-independent (the macro is platform-dependent;
 * the size of vph_mutex[] is based on NCPU).
 *
 * Note that you can do stress testing on this by setting the
 * variable page_vnode_mutex_stress to something other than
 * zero in a DEBUG kernel in a debugger after loading the kernel.
 * Setting it after the kernel is running may not work correctly.
 */
#ifdef DEBUG
static int page_vnode_mutex_stress = 0;
#endif

kmutex_t *
page_vnode_mutex(vnode_t *vp)
{
	if (vp == &kvp || vp == &kvps[KV_VVP])
		return (&vph_mutex[VPH_TABLE_SIZE + 0]);

	if (vp == &kvps[KV_ZVP])
		return (&vph_mutex[VPH_TABLE_SIZE + 1]);
#ifdef DEBUG
	if (page_vnode_mutex_stress != 0)
		return (&vph_mutex[0]);
#endif

	return (&vph_mutex[VP_HASH_FUNC(vp)]);
}

kmutex_t *
page_se_mutex(page_t *pp)
{
	return (PAGE_SE_MUTEX(pp));
}

#ifdef VM_STATS
uint_t pszclck_stat[4];
#endif
/*
 * Find, take and return a mutex held by hat_page_demote().
 * Called by page_demote_vp_pages() before hat_page_demote() call and by
 * routines that want to block hat_page_demote() but can't do it
 * via locking all constituent pages.
 *
 * Return NULL if p_szc is 0.
 *
 * It should only be used for pages that can be demoted by hat_page_demote()
 * i.e. non swapfs file system pages.  The logic here is lifted from
 * sfmmu_mlspl_enter() except there's no need to worry about p_szc increase
 * since the page is locked and not free.
 *
 * Hash of the root page is used to find the lock.
 * To find the root in the presense of hat_page_demote() chageing the location
 * of the root this routine relies on the fact that hat_page_demote() changes
 * root last.
 *
 * If NULL is returned pp's p_szc is guaranteed to be 0. If non NULL is
 * returned pp's p_szc may be any value.
 */
kmutex_t *
page_szc_lock(page_t *pp)
{
	kmutex_t	*mtx;
	page_t		*rootpp;
	uint_t		szc;
	uint_t		rszc;
	uint_t		pszc = pp->p_szc;

	ASSERT(pp != NULL);
	ASSERT(PAGE_LOCKED(pp));
	ASSERT(!PP_ISFREE(pp));
	ASSERT(pp->p_vnode != NULL);
	ASSERT(!IS_SWAPFSVP(pp->p_vnode));
	ASSERT(!PP_ISKAS(pp));

again:
	if (pszc == 0) {
		VM_STAT_ADD(pszclck_stat[0]);
		return (NULL);
	}

	/* The lock lives in the root page */

	rootpp = PP_GROUPLEADER(pp, pszc);
	mtx = PAGE_SZC_MUTEX(rootpp);
	mutex_enter(mtx);

	/*
	 * since p_szc can only decrease if pp == rootpp
	 * rootpp will be always the same i.e we have the right root
	 * regardless of rootpp->p_szc.
	 * If location of pp's root didn't change after we took
	 * the lock we have the right root. return mutex hashed off it.
	 */
	if (pp == rootpp || (rszc = rootpp->p_szc) == pszc) {
		VM_STAT_ADD(pszclck_stat[1]);
		return (mtx);
	}

	/*
	 * root location changed because page got demoted.
	 * locate the new root.
	 */
	if (rszc < pszc) {
		szc = pp->p_szc;
		ASSERT(szc < pszc);
		mutex_exit(mtx);
		pszc = szc;
		VM_STAT_ADD(pszclck_stat[2]);
		goto again;
	}

	VM_STAT_ADD(pszclck_stat[3]);
	/*
	 * current hat_page_demote not done yet.
	 * wait for it to finish.
	 */
	mutex_exit(mtx);
	rootpp = PP_GROUPLEADER(rootpp, rszc);
	mtx = PAGE_SZC_MUTEX(rootpp);
	mutex_enter(mtx);
	mutex_exit(mtx);
	ASSERT(rootpp->p_szc < rszc);
	goto again;
}

int
page_szc_lock_assert(page_t *pp)
{
	page_t *rootpp = PP_PAGEROOT(pp);
	kmutex_t *mtx = PAGE_SZC_MUTEX(rootpp);

	return (MUTEX_HELD(mtx));
}

/*
 * memseg locking
 */
static krwlock_t memsegslock;

/*
 * memlist (phys_install, phys_avail) locking.
 */
static krwlock_t memlists_lock;

int
memsegs_trylock(int writer)
{
	return (rw_tryenter(&memsegslock, writer ? RW_WRITER : RW_READER));
}

void
memsegs_lock(int writer)
{
	rw_enter(&memsegslock, writer ? RW_WRITER : RW_READER);
}

/*ARGSUSED*/
void
memsegs_unlock(int writer)
{
	rw_exit(&memsegslock);
}

int
memsegs_lock_held(void)
{
	return (RW_LOCK_HELD(&memsegslock));
}

void
memlist_read_lock(void)
{
	rw_enter(&memlists_lock, RW_READER);
}

void
memlist_read_unlock(void)
{
	rw_exit(&memlists_lock);
}

void
memlist_write_lock(void)
{
	rw_enter(&memlists_lock, RW_WRITER);
}

void
memlist_write_unlock(void)
{
	rw_exit(&memlists_lock);
}

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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/callb.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/systm.h>		/* for bzero */
#include <sys/memlist.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/vmsystm.h>	/* for NOMEMWAIT() */
#include <sys/atomic.h>		/* used to update kcage_freemem */
#include <sys/kmem.h>		/* for kmem_reap */
#include <sys/errno.h>
#include <sys/mem_cage.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <vm/hat.h>
#include <vm/vm_dep.h>
#include <sys/mem_config.h>
#include <sys/lgrp.h>
#include <sys/rwlock.h>
#include <sys/cpupart.h>

extern pri_t maxclsyspri;

#ifdef DEBUG
#define	KCAGE_STATS
#endif

#ifdef KCAGE_STATS

#define	KCAGE_STATS_VERSION 9	/* can help report generators */
#define	KCAGE_STATS_NSCANS 256	/* depth of scan statistics buffer */

struct kcage_stats_scan {
	/* managed by KCAGE_STAT_* macros */
	clock_t	scan_lbolt;
	uint_t	scan_id;

	/* set in kcage_cageout() */
	uint_t	kt_passes;
	clock_t	kt_ticks;
	pgcnt_t	kt_kcage_freemem_start;
	pgcnt_t	kt_kcage_freemem_end;
	pgcnt_t kt_freemem_start;
	pgcnt_t kt_freemem_end;
	uint_t	kt_examined;
	uint_t	kt_cantlock;
	uint_t	kt_gotone;
	uint_t	kt_gotonefree;
	uint_t	kt_skiplevel;
	uint_t	kt_skipshared;
	uint_t	kt_skiprefd;
	uint_t	kt_destroy;

	/* set in kcage_invalidate_page() */
	uint_t	kip_reloclocked;
	uint_t	kip_relocmod;
	uint_t	kip_destroy;
	uint_t	kip_nomem;
	uint_t	kip_demotefailed;

	/* set in kcage_expand() */
	uint_t	ke_wanted;
	uint_t	ke_examined;
	uint_t	ke_lefthole;
	uint_t	ke_gotone;
	uint_t	ke_gotonefree;
};

struct kcage_stats {
	/* managed by KCAGE_STAT_* macros */
	uint_t	version;
	uint_t	size;

	/* set in kcage_cageout */
	uint_t	kt_wakeups;
	uint_t	kt_scans;
	uint_t	kt_cageout_break;

	/* set in kcage_expand */
	uint_t	ke_calls;
	uint_t	ke_nopfn;
	uint_t	ke_nopaget;
	uint_t	ke_isnoreloc;
	uint_t	ke_deleting;
	uint_t	ke_lowfreemem;
	uint_t	ke_terminate;

	/* set in kcage_freemem_add() */
	uint_t	kfa_trottlewake;

	/* set in kcage_freemem_sub() */
	uint_t	kfs_cagewake;

	/* set in kcage_create_throttle */
	uint_t	kct_calls;
	uint_t	kct_cageout;
	uint_t	kct_critical;
	uint_t	kct_exempt;
	uint_t	kct_cagewake;
	uint_t	kct_wait;
	uint_t	kct_progress;
	uint_t	kct_noprogress;
	uint_t	kct_timeout;

	/* set in kcage_cageout_wakeup */
	uint_t	kcw_expandearly;

	/* managed by KCAGE_STAT_* macros */
	uint_t	scan_array_size;
	uint_t	scan_index;
	struct kcage_stats_scan scans[KCAGE_STATS_NSCANS];
};

static struct kcage_stats kcage_stats;
static struct kcage_stats_scan kcage_stats_scan_zero;

/*
 * No real need for atomics here. For the most part the incs and sets are
 * done by the kernel cage thread. There are a few that are done by any
 * number of other threads. Those cases are noted by comments.
 */
#define	KCAGE_STAT_INCR(m)	kcage_stats.m++

#define	KCAGE_STAT_NINCR(m, v) kcage_stats.m += (v)

#define	KCAGE_STAT_INCR_SCAN(m)	\
	KCAGE_STAT_INCR(scans[kcage_stats.scan_index].m)

#define	KCAGE_STAT_NINCR_SCAN(m, v) \
	KCAGE_STAT_NINCR(scans[kcage_stats.scan_index].m, v)

#define	KCAGE_STAT_SET(m, v)	kcage_stats.m = (v)

#define	KCAGE_STAT_SETZ(m, v)	\
	if (kcage_stats.m == 0) kcage_stats.m = (v)

#define	KCAGE_STAT_SET_SCAN(m, v)	\
	KCAGE_STAT_SET(scans[kcage_stats.scan_index].m, v)

#define	KCAGE_STAT_SETZ_SCAN(m, v)	\
	KCAGE_STAT_SETZ(scans[kcage_stats.scan_index].m, v)

#define	KCAGE_STAT_INC_SCAN_INDEX \
	KCAGE_STAT_SET_SCAN(scan_lbolt, lbolt); \
	KCAGE_STAT_SET_SCAN(scan_id, kcage_stats.scan_index); \
	kcage_stats.scan_index = \
	(kcage_stats.scan_index + 1) % KCAGE_STATS_NSCANS; \
	kcage_stats.scans[kcage_stats.scan_index] = kcage_stats_scan_zero

#define	KCAGE_STAT_INIT_SCAN_INDEX \
	kcage_stats.version = KCAGE_STATS_VERSION; \
	kcage_stats.size = sizeof (kcage_stats); \
	kcage_stats.scan_array_size = KCAGE_STATS_NSCANS; \
	kcage_stats.scan_index = 0

#else /* KCAGE_STATS */

#define	KCAGE_STAT_INCR(v)
#define	KCAGE_STAT_NINCR(m, v)
#define	KCAGE_STAT_INCR_SCAN(v)
#define	KCAGE_STAT_NINCR_SCAN(m, v)
#define	KCAGE_STAT_SET(m, v)
#define	KCAGE_STAT_SETZ(m, v)
#define	KCAGE_STAT_SET_SCAN(m, v)
#define	KCAGE_STAT_SETZ_SCAN(m, v)
#define	KCAGE_STAT_INC_SCAN_INDEX
#define	KCAGE_STAT_INIT_SCAN_INDEX

#endif /* KCAGE_STATS */

static kmutex_t kcage_throttle_mutex;	/* protects kcage_throttle_cv */
static kcondvar_t kcage_throttle_cv;

static kmutex_t kcage_cageout_mutex;	/* protects cv and ready flag */
static kcondvar_t kcage_cageout_cv;	/* cageout thread naps here */
static int kcage_cageout_ready;		/* nonzero when cageout thread ready */
kthread_id_t kcage_cageout_thread;	/* to aid debugging */

static krwlock_t kcage_range_rwlock;	/* protects kcage_glist elements */

/*
 * Cage expansion happens within a range.
 */
struct kcage_glist {
	struct kcage_glist	*next;
	pfn_t			base;
	pfn_t			lim;
	pfn_t			curr;
	int			decr;
};

static struct kcage_glist *kcage_glist;
static struct kcage_glist *kcage_current_glist;

/*
 * The firstfree element is provided so that kmem_alloc can be avoided
 * until that cage has somewhere to go. This is not currently a problem
 * as early kmem_alloc's use BOP_ALLOC instead of page_create_va.
 */
static vmem_t *kcage_arena;
static struct kcage_glist kcage_glist_firstfree;
static struct kcage_glist *kcage_glist_freelist = &kcage_glist_firstfree;

/*
 * Miscellaneous forward references
 */
static struct kcage_glist *kcage_glist_alloc(void);
static int kcage_glist_delete(pfn_t, pfn_t, struct kcage_glist **);
static void kcage_cageout(void);
static int kcage_invalidate_page(page_t *, pgcnt_t *);
static int kcage_setnoreloc_pages(page_t *, se_t);
static int kcage_range_add_internal(pfn_t base, pgcnt_t npgs, kcage_dir_t);
static void kcage_init(pgcnt_t preferred_size);
static int kcage_range_delete_internal(pfn_t base, pgcnt_t npgs);

/*
 * Kernel Memory Cage counters and thresholds.
 */
int kcage_on = 0;
pgcnt_t kcage_freemem;
pgcnt_t kcage_needfree;
pgcnt_t kcage_lotsfree;
pgcnt_t kcage_desfree;
pgcnt_t kcage_minfree;
pgcnt_t kcage_throttlefree;
pgcnt_t	kcage_reserve;
int kcage_maxwait = 10;	/* in seconds */

/* when we use lp for kmem we start the cage at a higher initial value */
pgcnt_t kcage_kmemlp_mincage;

#ifdef DEBUG
pgcnt_t	kcage_pagets;
#define	KCAGEPAGETS_INC()	kcage_pagets++
#else
#define	KCAGEPAGETS_INC()
#endif

/* kstats to export what pages are currently caged */
kmutex_t kcage_kstat_lock;
static int kcage_kstat_update(kstat_t *ksp, int rw);
static int kcage_kstat_snapshot(kstat_t *ksp, void *buf, int rw);

/*
 * Startup and Dynamic Reconfiguration interfaces.
 * kcage_range_add()
 * kcage_range_del()
 * kcage_range_delete_post_mem_del()
 * kcage_range_init()
 * kcage_set_thresholds()
 */

/*
 * Called from page_get_contig_pages to get the approximate kcage pfn range
 * for exclusion from search for contiguous pages. This routine is called
 * without kcage_range lock (kcage routines can call page_get_contig_pages
 * through page_relocate) and with the assumption, based on kcage_range_add,
 * that kcage_current_glist always contain a valid pointer.
 */

int
kcage_current_pfn(pfn_t *pfncur)
{
	struct kcage_glist *lp = kcage_current_glist;

	ASSERT(kcage_on);

	ASSERT(lp != NULL);

	*pfncur = lp->curr;

	return (lp->decr);
}

/*
 * Called from vm_pagelist.c during coalesce to find kernel cage regions
 * within an mnode. Looks for the lowest range between lo and hi.
 *
 * Kernel cage memory is defined between kcage_glist and kcage_current_glist.
 * Non-cage memory is defined between kcage_current_glist and list end.
 *
 * If incage is set, returns the lowest kcage range. Otherwise returns lowest
 * non-cage range.
 *
 * Returns zero on success and nlo, nhi:
 * 	lo <= nlo < nhi <= hi
 * Returns non-zero if no overlapping range is found.
 */
int
kcage_next_range(int incage, pfn_t lo, pfn_t hi,
    pfn_t *nlo, pfn_t *nhi)
{
	struct kcage_glist *lp;
	pfn_t tlo = hi;
	pfn_t thi = hi;

	ASSERT(lo <= hi);

	/*
	 * Reader lock protects the list, but kcage_get_pfn
	 * running concurrently may advance kcage_current_glist
	 * and also update kcage_current_glist->curr. Page
	 * coalesce can handle this race condition.
	 */
	rw_enter(&kcage_range_rwlock, RW_READER);

	for (lp = incage ? kcage_glist : kcage_current_glist;
	    lp != NULL; lp = lp->next) {

		pfn_t klo, khi;

		/* find the range limits in this element */
		if ((incage && lp->decr) || (!incage && !lp->decr)) {
			klo = lp->curr;
			khi = lp->lim;
		} else {
			klo = lp->base;
			khi = lp->curr;
		}

		/* handle overlap */
		if (klo < tlo && klo < khi && lo < khi && klo < hi) {
			tlo = MAX(lo, klo);
			thi = MIN(hi, khi);
			if (tlo == lo)
				break;
		}

		/* check end of kcage */
		if (incage && lp == kcage_current_glist) {
			break;
		}
	}

	rw_exit(&kcage_range_rwlock);

	/* return non-zero if no overlapping range found */
	if (tlo == thi)
		return (1);

	ASSERT(lo <= tlo && tlo < thi && thi <= hi);

	/* return overlapping range */
	*nlo = tlo;
	*nhi = thi;
	return (0);
}

void
kcage_range_init(struct memlist *ml, kcage_dir_t d, pgcnt_t preferred_size)
{
	int ret = 0;

	ASSERT(kcage_arena == NULL);
	kcage_arena = vmem_create("kcage_arena", NULL, 0, sizeof (uint64_t),
	    segkmem_alloc, segkmem_free, heap_arena, 0, VM_SLEEP);
	ASSERT(kcage_arena != NULL);

	if (d == KCAGE_DOWN) {
		while (ml->next != NULL)
			ml = ml->next;
	}

	rw_enter(&kcage_range_rwlock, RW_WRITER);

	while (ml != NULL) {
		ret = kcage_range_add_internal(btop(ml->address),
		    btop(ml->size), d);
		if (ret)
			panic("kcage_range_add_internal failed: "
			    "ml=%p, ret=0x%x\n", (void *)ml, ret);

		ml = (d == KCAGE_DOWN ? ml->prev : ml->next);
	}

	rw_exit(&kcage_range_rwlock);

	if (ret == 0)
		kcage_init(preferred_size);
}

/*
 * Third arg controls direction of growth: 0: increasing pfns,
 * 1: decreasing.
 */
static int
kcage_range_add_internal(pfn_t base, pgcnt_t npgs, kcage_dir_t d)
{
	struct kcage_glist *new, **lpp;
	pfn_t lim;

	ASSERT(rw_write_held(&kcage_range_rwlock));

	ASSERT(npgs != 0);
	if (npgs == 0)
		return (EINVAL);

	lim = base + npgs;

	ASSERT(lim > base);
	if (lim <= base)
		return (EINVAL);

	new = kcage_glist_alloc();
	if (new == NULL) {
		return (ENOMEM);
	}

	new->base = base;
	new->lim = lim;
	new->decr = (d == KCAGE_DOWN);
	if (new->decr != 0)
		new->curr = new->lim;
	else
		new->curr = new->base;
	/*
	 * Any overlapping existing ranges are removed by deleting
	 * from the new list as we search for the tail.
	 */
	lpp = &kcage_glist;
	while (*lpp != NULL) {
		int ret;
		ret = kcage_glist_delete((*lpp)->base, (*lpp)->lim, &new);
		if (ret != 0)
			return (ret);
		lpp = &(*lpp)->next;
	}

	*lpp = new;

	if (kcage_current_glist == NULL) {
		kcage_current_glist = kcage_glist;
	}

	return (0);
}

int
kcage_range_add(pfn_t base, pgcnt_t npgs, kcage_dir_t d)
{
	int ret;

	rw_enter(&kcage_range_rwlock, RW_WRITER);
	ret = kcage_range_add_internal(base, npgs, d);
	rw_exit(&kcage_range_rwlock);
	return (ret);
}

/*
 * Calls to add and delete must be protected by kcage_range_rwlock
 */
static int
kcage_range_delete_internal(pfn_t base, pgcnt_t npgs)
{
	struct kcage_glist *lp;
	pfn_t lim;

	ASSERT(rw_write_held(&kcage_range_rwlock));

	ASSERT(npgs != 0);
	if (npgs == 0)
		return (EINVAL);

	lim = base + npgs;

	ASSERT(lim > base);
	if (lim <= base)
		return (EINVAL);

	/*
	 * Check if the delete is OK first as a number of elements
	 * might be involved and it will be difficult to go
	 * back and undo (can't just add the range back in).
	 */
	for (lp = kcage_glist; lp != NULL; lp = lp->next) {
		/*
		 * If there have been no pages allocated from this
		 * element, we don't need to check it.
		 */
		if ((lp->decr == 0 && lp->curr == lp->base) ||
		    (lp->decr != 0 && lp->curr == lp->lim))
			continue;
		/*
		 * If the element does not overlap, its OK.
		 */
		if (base >= lp->lim || lim <= lp->base)
			continue;
		/*
		 * Overlapping element: Does the range to be deleted
		 * overlap the area already used? If so fail.
		 */
		if (lp->decr == 0 && base < lp->curr && lim >= lp->base) {
			return (EBUSY);
		}
		if (lp->decr != 0 && base < lp->lim && lim >= lp->curr) {
			return (EBUSY);
		}
	}
	return (kcage_glist_delete(base, lim, &kcage_glist));
}

int
kcage_range_delete(pfn_t base, pgcnt_t npgs)
{
	int ret;

	rw_enter(&kcage_range_rwlock, RW_WRITER);
	ret = kcage_range_delete_internal(base, npgs);
	rw_exit(&kcage_range_rwlock);
	return (ret);
}

/*
 * Calls to add and delete must be protected by kcage_range_rwlock.
 * This routine gets called after successful Solaris memory
 * delete operation from DR post memory delete routines.
 */
static int
kcage_range_delete_post_mem_del_internal(pfn_t base, pgcnt_t npgs)
{
	pfn_t lim;

	ASSERT(rw_write_held(&kcage_range_rwlock));

	ASSERT(npgs != 0);
	if (npgs == 0)
		return (EINVAL);

	lim = base + npgs;

	ASSERT(lim > base);
	if (lim <= base)
		return (EINVAL);

	return (kcage_glist_delete(base, lim, &kcage_glist));
}

int
kcage_range_delete_post_mem_del(pfn_t base, pgcnt_t npgs)
{
	int ret;

	rw_enter(&kcage_range_rwlock, RW_WRITER);
	ret = kcage_range_delete_post_mem_del_internal(base, npgs);
	rw_exit(&kcage_range_rwlock);
	return (ret);
}

/*
 * No locking is required here as the whole operation is covered
 * by kcage_range_rwlock writer lock.
 */
static struct kcage_glist *
kcage_glist_alloc(void)
{
	struct kcage_glist *new;

	if ((new = kcage_glist_freelist) != NULL) {
		kcage_glist_freelist = new->next;
	} else {
		new = vmem_alloc(kcage_arena, sizeof (*new), VM_NOSLEEP);
	}

	if (new != NULL)
		bzero(new, sizeof (*new));

	return (new);
}

static void
kcage_glist_free(struct kcage_glist *lp)
{
	lp->next = kcage_glist_freelist;
	kcage_glist_freelist = lp;
}

static int
kcage_glist_delete(pfn_t base, pfn_t lim, struct kcage_glist **lpp)
{
	struct kcage_glist *lp, *prev = *lpp;

	while ((lp = *lpp) != NULL) {
		if (lim > lp->base && base < lp->lim) {
			/* The delete range overlaps this element. */
			if (base <= lp->base && lim >= lp->lim) {
				/* Delete whole element. */
				*lpp = lp->next;
				if (lp == kcage_current_glist) {
					/* This can never happen. */
					ASSERT(kcage_current_glist != prev);
					kcage_current_glist = prev;
				}
				kcage_glist_free(lp);
				continue;
			}

			/* Partial delete. */
			if (base > lp->base && lim < lp->lim) {
				struct kcage_glist *new;

				/*
				 * Remove a section from the middle,
				 * need to allocate a new element.
				 */
				new = kcage_glist_alloc();
				if (new == NULL) {
					return (ENOMEM);
				}

				/*
				 * Tranfser unused range to new.
				 * Edit lp in place to preserve
				 * kcage_current_glist.
				 */
				new->decr = lp->decr;
				if (new->decr != 0) {
					new->base = lp->base;
					new->lim = base;
					new->curr = base;

					lp->base = lim;
				} else {
					new->base = lim;
					new->lim = lp->lim;
					new->curr = new->base;

					lp->lim = base;
				}

				/* Insert new. */
				new->next = lp->next;
				lp->next = new;
				lpp = &lp->next;
			} else {
				/* Delete part of current block. */
				if (base > lp->base) {
					ASSERT(lim >= lp->lim);
					ASSERT(base < lp->lim);
					if (lp->decr != 0 &&
					    lp->curr == lp->lim)
						lp->curr = base;
					lp->lim = base;
				} else {
					ASSERT(base <= lp->base);
					ASSERT(lim > lp->base);
					if (lp->decr == 0 &&
					    lp->curr == lp->base)
						lp->curr = lim;
					lp->base = lim;
				}
			}
		}
		prev = *lpp;
		lpp = &(*lpp)->next;
	}

	return (0);
}

/*
 * If lockit is 1, kcage_get_pfn holds the
 * reader lock for kcage_range_rwlock.
 * Changes to lp->curr can cause race conditions, but
 * they are handled by higher level code (see kcage_next_range.)
 */
static pfn_t
kcage_get_pfn(int lockit)
{
	struct kcage_glist *lp;
	pfn_t pfn = PFN_INVALID;

	if (lockit && !rw_tryenter(&kcage_range_rwlock, RW_READER))
		return (pfn);

	lp = kcage_current_glist;
	while (lp != NULL) {
		if (lp->decr != 0) {
			if (lp->curr != lp->base) {
				pfn = --lp->curr;
				break;
			}
		} else {
			if (lp->curr != lp->lim) {
				pfn = lp->curr++;
				break;
			}
		}

		lp = lp->next;
		if (lp)
			kcage_current_glist = lp;
	}

	if (lockit)
		rw_exit(&kcage_range_rwlock);
	return (pfn);
}

/*
 * Walk the physical address space of the cage.
 * This routine does not guarantee to return PFNs in the order
 * in which they were allocated to the cage. Instead, it walks
 * each range as they appear on the growth list returning the PFNs
 * range in ascending order.
 *
 * To begin scanning at lower edge of cage, reset should be nonzero.
 * To step through cage, reset should be zero.
 *
 * PFN_INVALID will be returned when the upper end of the cage is
 * reached -- indicating a full scan of the cage has been completed since
 * previous reset. PFN_INVALID will continue to be returned until
 * kcage_walk_cage is reset.
 *
 * It is possible to receive a PFN_INVALID result on reset if a growth
 * list is not installed or if none of the PFNs in the installed list have
 * been allocated to the cage. In otherwords, there is no cage.
 *
 * Caller need not hold kcage_range_rwlock while calling this function
 * as the front part of the list is static - pages never come out of
 * the cage.
 *
 * The caller is expected to only be kcage_cageout().
 */
static pfn_t
kcage_walk_cage(int reset)
{
	static struct kcage_glist *lp = NULL;
	static pfn_t pfn;

	if (reset)
		lp = NULL;
	if (lp == NULL) {
		lp = kcage_glist;
		pfn = PFN_INVALID;
	}
again:
	if (pfn == PFN_INVALID) {
		if (lp == NULL)
			return (PFN_INVALID);

		if (lp->decr != 0) {
			/*
			 * In this range the cage grows from the highest
			 * address towards the lowest.
			 * Arrange to return pfns from curr to lim-1,
			 * inclusive, in ascending order.
			 */

			pfn = lp->curr;
		} else {
			/*
			 * In this range the cage grows from the lowest
			 * address towards the highest.
			 * Arrange to return pfns from base to curr,
			 * inclusive, in ascending order.
			 */

			pfn = lp->base;
		}
	}

	if (lp->decr != 0) {		/* decrementing pfn */
		if (pfn == lp->lim) {
			/* Don't go beyond the static part of the glist. */
			if (lp == kcage_current_glist)
				lp = NULL;
			else
				lp = lp->next;
			pfn = PFN_INVALID;
			goto again;
		}

		ASSERT(pfn >= lp->curr && pfn < lp->lim);
	} else {			/* incrementing pfn */
		if (pfn == lp->curr) {
			/* Don't go beyond the static part of the glist. */
			if (lp == kcage_current_glist)
				lp = NULL;
			else
				lp = lp->next;
			pfn = PFN_INVALID;
			goto again;
		}

		ASSERT(pfn >= lp->base && pfn < lp->curr);
	}

	return (pfn++);
}

/*
 * Callback functions for to recalc cage thresholds after
 * Kphysm memory add/delete operations.
 */
/*ARGSUSED*/
static void
kcage_kphysm_postadd_cb(void *arg, pgcnt_t delta_pages)
{
	kcage_recalc_thresholds();
}

/*ARGSUSED*/
static int
kcage_kphysm_predel_cb(void *arg, pgcnt_t delta_pages)
{
	/* TODO: when should cage refuse memory delete requests? */
	return (0);
}

/*ARGSUSED*/
static  void
kcage_kphysm_postdel_cb(void *arg, pgcnt_t delta_pages, int cancelled)
{
	kcage_recalc_thresholds();
}

static kphysm_setup_vector_t kcage_kphysm_vectors = {
	KPHYSM_SETUP_VECTOR_VERSION,
	kcage_kphysm_postadd_cb,
	kcage_kphysm_predel_cb,
	kcage_kphysm_postdel_cb
};

/*
 * This is called before a CPR suspend and after a CPR resume.  We have to
 * turn off kcage_cageout_ready before a suspend, and turn it back on after a
 * restart.
 */
/*ARGSUSED*/
static boolean_t
kcage_cageout_cpr(void *arg, int code)
{
	if (code == CB_CODE_CPR_CHKPT) {
		ASSERT(kcage_cageout_ready);
		kcage_cageout_ready = 0;
		return (B_TRUE);
	} else if (code == CB_CODE_CPR_RESUME) {
		ASSERT(kcage_cageout_ready == 0);
		kcage_cageout_ready = 1;
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * kcage_recalc_preferred_size() increases initial cage size to improve large
 * page availability when lp for kmem is enabled and kpr is disabled
 */
static pgcnt_t
kcage_recalc_preferred_size(pgcnt_t preferred_size)
{
	if (SEGKMEM_USE_LARGEPAGES && segkmem_reloc == 0) {
		pgcnt_t lpmincage = kcage_kmemlp_mincage;
		if (lpmincage == 0) {
			lpmincage = MIN(P2ROUNDUP(((physmem * PAGESIZE) / 8),
			    segkmem_heaplp_quantum), 0x40000000UL) / PAGESIZE;
		}
		kcage_kmemlp_mincage = MIN(lpmincage,
		    (segkmem_kmemlp_max / PAGESIZE));
		preferred_size = MAX(kcage_kmemlp_mincage, preferred_size);
	}
	return (preferred_size);
}

/*
 * Kcage_init() builds the cage and initializes the cage thresholds.
 * The size of the cage is determined by the argument preferred_size.
 * or the actual amount of memory, whichever is smaller.
 */
static void
kcage_init(pgcnt_t preferred_size)
{
	pgcnt_t wanted;
	pfn_t pfn;
	page_t *pp;
	kstat_t *ksp;

	extern struct vnode kvp;
	extern void page_list_noreloc_startup(page_t *);

	ASSERT(!kcage_on);

	/* increase preferred cage size for lp for kmem */
	preferred_size = kcage_recalc_preferred_size(preferred_size);

	/* Debug note: initialize this now so early expansions can stat */
	KCAGE_STAT_INIT_SCAN_INDEX;

	/*
	 * Initialize cage thresholds and install kphysm callback.
	 * If we can't arrange to have the thresholds track with
	 * available physical memory, then the cage thresholds may
	 * end up over time at levels that adversly effect system
	 * performance; so, bail out.
	 */
	kcage_recalc_thresholds();
	if (kphysm_setup_func_register(&kcage_kphysm_vectors, NULL)) {
		ASSERT(0);		/* Catch this in DEBUG kernels. */
		return;
	}

	/*
	 * Limit startup cage size within the range of kcage_minfree
	 * and availrmem, inclusively.
	 */
	wanted = MIN(MAX(preferred_size, kcage_minfree), availrmem);

	/*
	 * Construct the cage. PFNs are allocated from the glist. It
	 * is assumed that the list has been properly ordered for the
	 * platform by the platform code. Typically, this is as simple
	 * as calling kcage_range_init(phys_avail, decr), where decr is
	 * 1 if the kernel has been loaded into upper end of physical
	 * memory, or 0 if the kernel has been loaded at the low end.
	 *
	 * Note: it is assumed that we are in the startup flow, so there
	 * is no reason to grab the page lock.
	 */
	kcage_freemem = 0;
	pfn = PFN_INVALID;			/* prime for alignment test */
	while (wanted != 0) {
		if ((pfn = kcage_get_pfn(0)) == PFN_INVALID)
			break;

		if ((pp = page_numtopp_nolock(pfn)) != NULL) {
			KCAGEPAGETS_INC();
			/*
			 * Set the noreloc state on the page.
			 * If the page is free and not already
			 * on the noreloc list then move it.
			 */
			if (PP_ISFREE(pp)) {
				if (PP_ISNORELOC(pp) == 0)
					page_list_noreloc_startup(pp);
			} else {
				ASSERT(pp->p_szc == 0);
				PP_SETNORELOC(pp);
			}
		}
		PLCNT_XFER_NORELOC(pp);
		wanted -= 1;
	}

	/*
	 * Need to go through and find kernel allocated pages
	 * and capture them into the Cage.  These will primarily
	 * be pages gotten through boot_alloc().
	 */
	if (kvp.v_pages) {

		pp = kvp.v_pages;
		do {
			ASSERT(!PP_ISFREE(pp));
			ASSERT(pp->p_szc == 0);
			if (PP_ISNORELOC(pp) == 0) {
				PP_SETNORELOC(pp);
				PLCNT_XFER_NORELOC(pp);
			}
		} while ((pp = pp->p_vpnext) != kvp.v_pages);

	}

	kcage_on = 1;

	/*
	 * CB_CL_CPR_POST_KERNEL is the class that executes from cpr_suspend()
	 * after the cageout thread is blocked, and executes from cpr_resume()
	 * before the cageout thread is restarted.  By executing in this class,
	 * we are assured that the kernel cage thread won't miss wakeup calls
	 * and also CPR's larger kmem_alloc requests will not fail after
	 * CPR shuts down the cageout kernel thread.
	 */
	(void) callb_add(kcage_cageout_cpr, NULL, CB_CL_CPR_POST_KERNEL,
	    "cageout");

	/*
	 * Coalesce pages to improve large page availability. A better fix
	 * would to coalesce pages as they are included in the cage
	 */
	if (SEGKMEM_USE_LARGEPAGES) {
		extern void page_freelist_coalesce_all(int mnode);
		page_freelist_coalesce_all(-1);	/* do all mnodes */
	}

	ksp = kstat_create("kcage", 0, "kcage_page_list", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VAR_SIZE | KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_update = kcage_kstat_update;
		ksp->ks_snapshot = kcage_kstat_snapshot;
		ksp->ks_lock = &kcage_kstat_lock; /* XXX - not really needed */
		kstat_install(ksp);
	}
}

static int
kcage_kstat_update(kstat_t *ksp, int rw)
{
	struct kcage_glist *lp;
	uint_t count;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	count = 0;
	rw_enter(&kcage_range_rwlock, RW_WRITER);
	for (lp = kcage_glist; lp != NULL; lp = lp->next) {
		if (lp->decr) {
			if (lp->curr != lp->lim) {
				count++;
			}
		} else {
			if (lp->curr != lp->base) {
				count++;
			}
		}
	}
	rw_exit(&kcage_range_rwlock);

	ksp->ks_ndata = count;
	ksp->ks_data_size = count * 2 * sizeof (uint64_t);

	return (0);
}

static int
kcage_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	struct kcage_glist *lp;
	struct memunit {
		uint64_t address;
		uint64_t size;
	} *kspmem;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ksp->ks_snaptime = gethrtime();

	kspmem = (struct memunit *)buf;
	rw_enter(&kcage_range_rwlock, RW_WRITER);
	for (lp = kcage_glist; lp != NULL; lp = lp->next, kspmem++) {
		if ((caddr_t)kspmem >= (caddr_t)buf + ksp->ks_data_size)
			break;

		if (lp->decr) {
			if (lp->curr != lp->lim) {
				kspmem->address = ptob(lp->curr);
				kspmem->size = ptob(lp->lim - lp->curr);
			}
		} else {
			if (lp->curr != lp->base) {
				kspmem->address = ptob(lp->base);
				kspmem->size = ptob(lp->curr - lp->base);
			}
		}
	}
	rw_exit(&kcage_range_rwlock);

	return (0);
}

void
kcage_recalc_thresholds()
{
	static int first = 1;
	static pgcnt_t init_lotsfree;
	static pgcnt_t init_desfree;
	static pgcnt_t init_minfree;
	static pgcnt_t init_throttlefree;
	static pgcnt_t init_reserve;

	/* TODO: any reason to take more care than this with live editing? */
	mutex_enter(&kcage_cageout_mutex);
	mutex_enter(&freemem_lock);

	if (first) {
		first = 0;
		init_lotsfree = kcage_lotsfree;
		init_desfree = kcage_desfree;
		init_minfree = kcage_minfree;
		init_throttlefree = kcage_throttlefree;
		init_reserve = kcage_reserve;
	} else {
		kcage_lotsfree = init_lotsfree;
		kcage_desfree = init_desfree;
		kcage_minfree = init_minfree;
		kcage_throttlefree = init_throttlefree;
		kcage_reserve = init_reserve;
	}

	if (kcage_lotsfree == 0)
		kcage_lotsfree = MAX(32, total_pages / 256);

	if (kcage_minfree == 0)
		kcage_minfree = MAX(32, kcage_lotsfree / 2);

	if (kcage_desfree == 0)
		kcage_desfree = MAX(32, kcage_minfree);

	if (kcage_throttlefree == 0)
		kcage_throttlefree = MAX(32, kcage_minfree / 2);

	if (kcage_reserve == 0)
		kcage_reserve = MIN(32, kcage_throttlefree / 2);

	mutex_exit(&freemem_lock);
	mutex_exit(&kcage_cageout_mutex);

	if (kcage_cageout_ready) {
		if (kcage_freemem < kcage_desfree)
			kcage_cageout_wakeup();

		if (kcage_needfree) {
			mutex_enter(&kcage_throttle_mutex);
			cv_broadcast(&kcage_throttle_cv);
			mutex_exit(&kcage_throttle_mutex);
		}
	}
}

/*
 * Pageout interface:
 * kcage_cageout_init()
 */
void
kcage_cageout_init()
{
	if (kcage_on) {

		(void) thread_create(NULL, 0, kcage_cageout,
		    NULL, 0, proc_pageout, TS_RUN, maxclsyspri - 1);
	}
}


/*
 * VM Interfaces:
 * kcage_create_throttle()
 * kcage_freemem_add()
 * kcage_freemem_sub()
 */

/*
 * Wakeup cageout thread and throttle waiting for the number of pages
 * requested to become available.  For non-critical requests, a
 * timeout is added, since freemem accounting is separate from cage
 * freemem accounting: it's possible for us to get stuck and not make
 * forward progress even though there was sufficient freemem before
 * arriving here.
 */
int
kcage_create_throttle(pgcnt_t npages, int flags)
{
	int niter = 0;
	pgcnt_t lastfree;
	int enough = kcage_freemem > kcage_throttlefree + npages;

	KCAGE_STAT_INCR(kct_calls);		/* unprotected incr. */

	kcage_cageout_wakeup();			/* just to be sure */
	KCAGE_STAT_INCR(kct_cagewake);		/* unprotected incr. */

	/*
	 * Obviously, we can't throttle the cageout thread since
	 * we depend on it.  We also can't throttle the panic thread.
	 */
	if (curthread == kcage_cageout_thread || panicstr) {
		KCAGE_STAT_INCR(kct_cageout);	/* unprotected incr. */
		return (KCT_CRIT);
	}

	/*
	 * Don't throttle threads which are critical for proper
	 * vm management if we're above kcage_throttlefree or
	 * if freemem is very low.
	 */
	if (NOMEMWAIT()) {
		if (enough) {
			KCAGE_STAT_INCR(kct_exempt);	/* unprotected incr. */
			return (KCT_CRIT);
		} else if (freemem < minfree) {
			KCAGE_STAT_INCR(kct_critical);  /* unprotected incr. */
			return (KCT_CRIT);
		}
	}

	/*
	 * Don't throttle real-time threads if kcage_freemem > kcage_reserve.
	 */
	if (DISP_PRIO(curthread) > maxclsyspri &&
	    kcage_freemem > kcage_reserve) {
		KCAGE_STAT_INCR(kct_exempt);	/* unprotected incr. */
		return (KCT_CRIT);
	}

	/*
	 * Cause all other threads (which are assumed to not be
	 * critical to cageout) to wait here until their request
	 * can be satisfied. Be a little paranoid and wake the
	 * kernel cage on each loop through this logic.
	 */
	while (kcage_freemem < kcage_throttlefree + npages) {
		ASSERT(kcage_on);

		lastfree = kcage_freemem;

		if (kcage_cageout_ready) {
			mutex_enter(&kcage_throttle_mutex);

			kcage_needfree += npages;
			KCAGE_STAT_INCR(kct_wait);

			kcage_cageout_wakeup();
			KCAGE_STAT_INCR(kct_cagewake);

			cv_wait(&kcage_throttle_cv, &kcage_throttle_mutex);

			kcage_needfree -= npages;

			mutex_exit(&kcage_throttle_mutex);
		} else {
			/*
			 * NOTE: atomics are used just in case we enter
			 * mp operation before the cageout thread is ready.
			 */
			atomic_add_long(&kcage_needfree, npages);

			kcage_cageout_wakeup();
			KCAGE_STAT_INCR(kct_cagewake);	/* unprotected incr. */

			atomic_add_long(&kcage_needfree, -npages);
		}

		if ((flags & PG_WAIT) == 0) {
			if (kcage_freemem > lastfree) {
				KCAGE_STAT_INCR(kct_progress);
				niter = 0;
			} else {
				KCAGE_STAT_INCR(kct_noprogress);
				if (++niter >= kcage_maxwait) {
					KCAGE_STAT_INCR(kct_timeout);
					return (KCT_FAILURE);
				}
			}
		}

		if (NOMEMWAIT() && freemem < minfree) {
			return (KCT_CRIT);
		}

	}
	return (KCT_NONCRIT);
}

void
kcage_freemem_add(pgcnt_t npages)
{
	extern void wakeup_pcgs(void);

	atomic_add_long(&kcage_freemem, npages);

	wakeup_pcgs();  /* wakeup threads in pcgs() */

	if (kcage_needfree != 0 &&
	    kcage_freemem >= (kcage_throttlefree + kcage_needfree)) {

		mutex_enter(&kcage_throttle_mutex);
		cv_broadcast(&kcage_throttle_cv);
		KCAGE_STAT_INCR(kfa_trottlewake);
		mutex_exit(&kcage_throttle_mutex);
	}
}

void
kcage_freemem_sub(pgcnt_t npages)
{
	atomic_add_long(&kcage_freemem, -npages);

	if (kcage_freemem < kcage_desfree) {
		kcage_cageout_wakeup();
		KCAGE_STAT_INCR(kfs_cagewake); /* unprotected incr. */
	}
}

/*
 * return 0 on failure and 1 on success.
 */
static int
kcage_setnoreloc_pages(page_t *rootpp, se_t se)
{
	pgcnt_t npgs, i;
	page_t *pp;
	pfn_t rootpfn = page_pptonum(rootpp);
	uint_t szc;

	ASSERT(!PP_ISFREE(rootpp));
	ASSERT(PAGE_LOCKED_SE(rootpp, se));
	if (!group_page_trylock(rootpp, se)) {
		return (0);
	}
	szc = rootpp->p_szc;
	if (szc == 0) {
		/*
		 * The szc of a locked page can only change for pages that are
		 * non-swapfs (i.e. anonymous memory) file system pages.
		 */
		ASSERT(rootpp->p_vnode != NULL &&
		    !PP_ISKAS(rootpp) &&
		    !IS_SWAPFSVP(rootpp->p_vnode));
		PP_SETNORELOC(rootpp);
		return (1);
	}
	npgs = page_get_pagecnt(szc);
	ASSERT(IS_P2ALIGNED(rootpfn, npgs));
	pp = rootpp;
	for (i = 0; i < npgs; i++, pp++) {
		ASSERT(PAGE_LOCKED_SE(pp, se));
		ASSERT(!PP_ISFREE(pp));
		ASSERT(pp->p_szc == szc);
		PP_SETNORELOC(pp);
	}
	group_page_unlock(rootpp);
	return (1);
}

/*
 * Attempt to convert page to a caged page (set the P_NORELOC flag).
 * If successful and pages is free, move page to the tail of whichever
 * list it is on.
 * Returns:
 *   EBUSY  page already locked, assimilated but not free.
 *   ENOMEM page assimilated, but memory too low to relocate. Page not free.
 *   EAGAIN page not assimilated. Page not free.
 *   ERANGE page assimilated. Page not root.
 *   0      page assimilated. Page free.
 *   *nfreedp number of pages freed.
 * NOTE: With error codes ENOMEM, EBUSY, and 0 (zero), there is no way
 * to distinguish between a page that was already a NORELOC page from
 * those newly converted to NORELOC pages by this invocation of
 * kcage_assimilate_page.
 */
static int
kcage_assimilate_page(page_t *pp, pgcnt_t *nfreedp)
{
	if (page_trylock(pp, SE_EXCL)) {
		if (PP_ISNORELOC(pp)) {
check_free_and_return:
			if (PP_ISFREE(pp)) {
				page_unlock(pp);
				*nfreedp = 0;
				return (0);
			} else {
				page_unlock(pp);
				return (EBUSY);
			}
			/*NOTREACHED*/
		}
	} else {
		if (page_trylock(pp, SE_SHARED)) {
			if (PP_ISNORELOC(pp))
				goto check_free_and_return;
		} else
			return (EAGAIN);

		if (!PP_ISFREE(pp)) {
			page_unlock(pp);
			return (EAGAIN);
		}

		/*
		 * Need to upgrade the lock on it and set the NORELOC
		 * bit. If it is free then remove it from the free
		 * list so that the platform free list code can keep
		 * NORELOC pages where they should be.
		 */
		/*
		 * Before doing anything, get the exclusive lock.
		 * This may fail (eg ISM pages are left shared locked).
		 * If the page is free this will leave a hole in the
		 * cage. There is no solution yet to this.
		 */
		if (!page_tryupgrade(pp)) {
			page_unlock(pp);
			return (EAGAIN);
		}
	}

	ASSERT(PAGE_EXCL(pp));

	if (PP_ISFREE(pp)) {
		int which = PP_ISAGED(pp) ? PG_FREE_LIST : PG_CACHE_LIST;

		page_list_sub(pp, which);
		ASSERT(pp->p_szc == 0);
		PP_SETNORELOC(pp);
		PLCNT_XFER_NORELOC(pp);
		page_list_add(pp, which | PG_LIST_TAIL);

		page_unlock(pp);
		*nfreedp = 1;
		return (0);
	} else {
		if (pp->p_szc != 0) {
			if (!kcage_setnoreloc_pages(pp, SE_EXCL)) {
				page_unlock(pp);
				return (EAGAIN);
			}
			ASSERT(PP_ISNORELOC(pp));
		} else {
			PP_SETNORELOC(pp);
		}
		PLCNT_XFER_NORELOC(pp);
		return (kcage_invalidate_page(pp, nfreedp));
	}
	/*NOTREACHED*/
}

static int
kcage_expand()
{
	int did_something = 0;

	spgcnt_t wanted;
	pfn_t pfn;
	page_t *pp;
	/* TODO: we don't really need n any more? */
	pgcnt_t n;
	pgcnt_t nf, nfreed;

	/*
	 * Expand the cage if available cage memory is really low. Calculate
	 * the amount required to return kcage_freemem to the level of
	 * kcage_lotsfree, or to satisfy throttled requests, whichever is
	 * more.  It is rare for their sum to create an artificial threshold
	 * above kcage_lotsfree, but it is possible.
	 *
	 * Exit early if expansion amount is equal to or less than zero.
	 * (<0 is possible if kcage_freemem rises suddenly.)
	 *
	 * Exit early when the global page pool (apparently) does not
	 * have enough free pages to page_relocate() even a single page.
	 */
	wanted = MAX(kcage_lotsfree, kcage_throttlefree + kcage_needfree)
	    - kcage_freemem;
	if (wanted <= 0)
		return (0);
	else if (freemem < pageout_reserve + 1) {
		KCAGE_STAT_INCR(ke_lowfreemem);
		return (0);
	}

	KCAGE_STAT_INCR(ke_calls);
	KCAGE_STAT_SET_SCAN(ke_wanted, (uint_t)wanted);

	/*
	 * Assimilate more pages from the global page pool into the cage.
	 */
	n = 0;				/* number of pages PP_SETNORELOC'd */
	nf = 0;				/* number of those actually free */
	while (kcage_on && nf < wanted) {
		pfn = kcage_get_pfn(1);
		if (pfn == PFN_INVALID) {	/* eek! no where to grow */
			KCAGE_STAT_INCR(ke_nopfn);
			goto terminate;
		}

		KCAGE_STAT_INCR_SCAN(ke_examined);

		if ((pp = page_numtopp_nolock(pfn)) == NULL) {
			KCAGE_STAT_INCR(ke_nopaget);
			continue;
		}
		KCAGEPAGETS_INC();
		/*
		 * Sanity check. Skip this pfn if it is
		 * being deleted.
		 */
		if (pfn_is_being_deleted(pfn)) {
			KCAGE_STAT_INCR(ke_deleting);
			continue;
		}

		if (PP_ISNORELOC(pp)) {
			KCAGE_STAT_INCR(ke_isnoreloc);
			continue;
		}

		switch (kcage_assimilate_page(pp, &nfreed)) {
			case 0:		/* assimilated, page is free */
				KCAGE_STAT_NINCR_SCAN(ke_gotonefree, nfreed);
				did_something = 1;
				nf += nfreed;
				n++;
				break;

			case EBUSY:	/* assimilated, page not free */
			case ERANGE:	/* assimilated, page not root */
				KCAGE_STAT_INCR_SCAN(ke_gotone);
				did_something = 1;
				n++;
				break;

			case ENOMEM:	/* assimilated, but no mem */
				KCAGE_STAT_INCR(ke_terminate);
				did_something = 1;
				n++;
				goto terminate;

			case EAGAIN:	/* can't assimilate */
				KCAGE_STAT_INCR_SCAN(ke_lefthole);
				break;

			default:	/* catch this with debug kernels */
				ASSERT(0);
				break;
		}
	}

	/*
	 * Realign cage edge with the nearest physical address
	 * boundry for big pages. This is done to give us a
	 * better chance of actually getting usable big pages
	 * in the cage.
	 */

terminate:

	return (did_something);
}

/*
 * Relocate page opp (Original Page Pointer) from cage pool to page rpp
 * (Replacement Page Pointer) in the global pool. Page opp will be freed
 * if relocation is successful, otherwise it is only unlocked.
 * On entry, page opp must be exclusively locked and not free.
 * *nfreedp: number of pages freed.
 */
static int
kcage_relocate_page(page_t *pp, pgcnt_t *nfreedp)
{
	page_t *opp = pp;
	page_t *rpp = NULL;
	spgcnt_t npgs;
	int result;

	ASSERT(!PP_ISFREE(opp));
	ASSERT(PAGE_EXCL(opp));

	result = page_relocate(&opp, &rpp, 1, 1, &npgs, NULL);
	*nfreedp = npgs;
	if (result == 0) {
		while (npgs-- > 0) {
			page_t *tpp;

			ASSERT(rpp != NULL);
			tpp = rpp;
			page_sub(&rpp, tpp);
			page_unlock(tpp);
		}

		ASSERT(rpp == NULL);

		return (0);		/* success */
	}

	page_unlock(opp);
	return (result);
}

/*
 * Based on page_invalidate_pages()
 *
 * Kcage_invalidate_page() uses page_relocate() twice. Both instances
 * of use must be updated to match the new page_relocate() when it
 * becomes available.
 *
 * Return result of kcage_relocate_page or zero if page was directly freed.
 * *nfreedp: number of pages freed.
 */
static int
kcage_invalidate_page(page_t *pp, pgcnt_t *nfreedp)
{
	int result;

#if defined(__sparc)
	extern struct vnode prom_ppages;
	ASSERT(pp->p_vnode != &prom_ppages);
#endif /* __sparc */

	ASSERT(!PP_ISFREE(pp));
	ASSERT(PAGE_EXCL(pp));

	/*
	 * Is this page involved in some I/O? shared?
	 * The page_struct_lock need not be acquired to
	 * examine these fields since the page has an
	 * "exclusive" lock.
	 */
	if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
		result = kcage_relocate_page(pp, nfreedp);
#ifdef KCAGE_STATS
		if (result == 0)
			KCAGE_STAT_INCR_SCAN(kip_reloclocked);
		else if (result == ENOMEM)
			KCAGE_STAT_INCR_SCAN(kip_nomem);
#endif
		return (result);
	}

	ASSERT(pp->p_vnode->v_type != VCHR);

	/*
	 * Unload the mappings and check if mod bit is set.
	 */
	(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);

	if (hat_ismod(pp)) {
		result = kcage_relocate_page(pp, nfreedp);
#ifdef KCAGE_STATS
		if (result == 0)
			KCAGE_STAT_INCR_SCAN(kip_relocmod);
		else if (result == ENOMEM)
			KCAGE_STAT_INCR_SCAN(kip_nomem);
#endif
		return (result);
	}

	if (!page_try_demote_pages(pp)) {
		KCAGE_STAT_INCR_SCAN(kip_demotefailed);
		page_unlock(pp);
		return (EAGAIN);
	}

	/* LINTED: constant in conditional context */
	VN_DISPOSE(pp, B_INVAL, 0, kcred);
	KCAGE_STAT_INCR_SCAN(kip_destroy);
	*nfreedp = 1;
	return (0);
}

static void
kcage_cageout()
{
	pfn_t pfn;
	page_t *pp;
	callb_cpr_t cprinfo;
	int did_something;
	int scan_again;
	pfn_t start_pfn;
	int pass;
	int last_pass;
	int pages_skipped;
	int shared_skipped;
	ulong_t shared_level = 8;
	pgcnt_t nfreed;
#ifdef KCAGE_STATS
	clock_t scan_start;
#endif

	CALLB_CPR_INIT(&cprinfo, &kcage_cageout_mutex,
	    callb_generic_cpr, "cageout");

	mutex_enter(&kcage_cageout_mutex);
	kcage_cageout_thread = curthread;

	pfn = PFN_INVALID;		/* force scan reset */
	start_pfn = PFN_INVALID;	/* force init with 1st cage pfn */
	kcage_cageout_ready = 1;	/* switch kcage_cageout_wakeup mode */

loop:
	/*
	 * Wait here. Sooner or later, kcage_freemem_sub() will notice
	 * that kcage_freemem is less than kcage_desfree. When it does
	 * notice, kcage_freemem_sub() will wake us up via call to
	 * kcage_cageout_wakeup().
	 */
	CALLB_CPR_SAFE_BEGIN(&cprinfo);
	cv_wait(&kcage_cageout_cv, &kcage_cageout_mutex);
	CALLB_CPR_SAFE_END(&cprinfo, &kcage_cageout_mutex);

	KCAGE_STAT_INCR(kt_wakeups);
	KCAGE_STAT_SET_SCAN(kt_freemem_start, freemem);
	KCAGE_STAT_SET_SCAN(kt_kcage_freemem_start, kcage_freemem);
	pass = 0;
	last_pass = 0;

#ifdef KCAGE_STATS
	scan_start = lbolt;
#endif

again:
	if (!kcage_on)
		goto loop;

	KCAGE_STAT_INCR(kt_scans);
	KCAGE_STAT_INCR_SCAN(kt_passes);

	did_something = 0;
	pages_skipped = 0;
	shared_skipped = 0;
	while ((kcage_freemem < kcage_lotsfree || kcage_needfree) &&
	    (pfn = kcage_walk_cage(pfn == PFN_INVALID)) != PFN_INVALID) {

		if (start_pfn == PFN_INVALID)
			start_pfn = pfn;
		else if (start_pfn == pfn) {
			last_pass = pass;
			pass += 1;
			/*
			 * Did a complete walk of kernel cage, but didn't free
			 * any pages.  If only one cpu is active then
			 * stop kernel cage walk and try expanding.
			 */
			if (cp_default.cp_ncpus == 1 && did_something == 0) {
				KCAGE_STAT_INCR(kt_cageout_break);
				break;
			}
		}

		pp = page_numtopp_nolock(pfn);
		if (pp == NULL) {
			continue;
		}

		KCAGE_STAT_INCR_SCAN(kt_examined);

		/*
		 * Do a quick PP_ISNORELOC() and PP_ISFREE test outside
		 * of the lock. If one is missed it will be seen next
		 * time through.
		 *
		 * Skip non-caged-pages. These pages can exist in the cage
		 * because, if during cage expansion, a page is
		 * encountered that is long-term locked the lock prevents the
		 * expansion logic from setting the P_NORELOC flag. Hence,
		 * non-caged-pages surrounded by caged-pages.
		 */
		if (!PP_ISNORELOC(pp)) {
			switch (kcage_assimilate_page(pp, &nfreed)) {
				case 0:
					did_something = 1;
					KCAGE_STAT_NINCR_SCAN(kt_gotonefree,
					    nfreed);
					break;

				case EBUSY:
				case ERANGE:
					did_something = 1;
					KCAGE_STAT_INCR_SCAN(kt_gotone);
					break;

				case EAGAIN:
				case ENOMEM:
					break;

				default:
					/* catch this with debug kernels */
					ASSERT(0);
					break;
			}

			continue;
		} else {
			int prm;

			if (PP_ISFREE(pp)) {
				continue;
			}

			if ((PP_ISKAS(pp) && pp->p_lckcnt > 0) ||
			    !page_trylock(pp, SE_EXCL)) {
				KCAGE_STAT_INCR_SCAN(kt_cantlock);
				continue;
			}

			/* P_NORELOC bit should not have gone away. */
			ASSERT(PP_ISNORELOC(pp));
			if (PP_ISFREE(pp) || (PP_ISKAS(pp) &&
			    pp->p_lckcnt > 0)) {
				page_unlock(pp);
				continue;
			}

			KCAGE_STAT_SET_SCAN(kt_skiplevel, shared_level);
			if (hat_page_checkshare(pp, shared_level)) {
				page_unlock(pp);
				pages_skipped = 1;
				shared_skipped = 1;
				KCAGE_STAT_INCR_SCAN(kt_skipshared);
				continue;
			}

			/*
			 * In pass {0, 1}, skip page if ref bit is set.
			 * In pass {0, 1, 2}, skip page if mod bit is set.
			 */
			prm = hat_pagesync(pp,
			    HAT_SYNC_DONTZERO | HAT_SYNC_STOPON_MOD);

			/* On first pass ignore ref'd pages */
			if (pass <= 1 && (prm & P_REF)) {
				KCAGE_STAT_INCR_SCAN(kt_skiprefd);
				pages_skipped = 1;
				page_unlock(pp);
				continue;
			}

			/* On pass 2, VN_DISPOSE if mod bit is not set */
			if (pass <= 2) {
				if (pp->p_szc != 0 || (prm & P_MOD) ||
				    pp->p_lckcnt || pp->p_cowcnt) {
					pages_skipped = 1;
					page_unlock(pp);
				} else {

					/*
					 * unload the mappings before
					 * checking if mod bit is set
					 */
					(void) hat_pageunload(pp,
					    HAT_FORCE_PGUNLOAD);

					/*
					 * skip this page if modified
					 */
					if (hat_ismod(pp)) {
						pages_skipped = 1;
						page_unlock(pp);
						continue;
					}

					KCAGE_STAT_INCR_SCAN(kt_destroy);
					/* constant in conditional context */
					/* LINTED */
					VN_DISPOSE(pp, B_INVAL, 0, kcred);
					did_something = 1;
				}
				continue;
			}

			if (kcage_invalidate_page(pp, &nfreed) == 0) {
				did_something = 1;
				KCAGE_STAT_NINCR_SCAN(kt_gotonefree, nfreed);
			}

			/*
			 * No need to drop the page lock here.
			 * Kcage_invalidate_page has done that for us
			 * either explicitly or through a page_free.
			 */
		}
	}

	/*
	 * Expand the cage only if available cage memory is really low.
	 * This test is done only after a complete scan of the cage.
	 * The reason for not checking and expanding more often is to
	 * avoid rapid expansion of the cage. Naturally, scanning the
	 * cage takes time. So by scanning first, we use that work as a
	 * delay loop in between expand decisions.
	 */

	scan_again = 0;
	if (kcage_freemem < kcage_minfree || kcage_needfree) {
		/*
		 * Kcage_expand() will return a non-zero value if it was
		 * able to expand the cage -- whether or not the new
		 * pages are free and immediately usable. If non-zero,
		 * we do another scan of the cage. The pages might be
		 * freed during that scan or by time we get back here.
		 * If not, we will attempt another expansion.
		 * However, if kcage_expand() returns zero, then it was
		 * unable to expand the cage. This is the case when the
		 * the growth list is exausted, therefore no work was done
		 * and there is no reason to scan the cage again.
		 * Note: Kernel cage scan is not repeated when only one
		 * cpu is active to avoid kernel cage thread hogging cpu.
		 */
		if (pass <= 3 && pages_skipped && cp_default.cp_ncpus > 1)
			scan_again = 1;
		else
			(void) kcage_expand(); /* don't scan again */
	} else if (kcage_freemem < kcage_lotsfree) {
		/*
		 * If available cage memory is less than abundant
		 * and a full scan of the cage has not yet been completed,
		 * or a scan has completed and some work was performed,
		 * or pages were skipped because of sharing,
		 * or we simply have not yet completed two passes,
		 * then do another scan.
		 */
		if (pass <= 2 && pages_skipped)
			scan_again = 1;
		if (pass == last_pass || did_something)
			scan_again = 1;
		else if (shared_skipped && shared_level < (8<<24)) {
			shared_level <<= 1;
			scan_again = 1;
		}
	}

	if (scan_again && cp_default.cp_ncpus > 1)
		goto again;
	else {
		if (shared_level > 8)
			shared_level >>= 1;

		KCAGE_STAT_SET_SCAN(kt_freemem_end, freemem);
		KCAGE_STAT_SET_SCAN(kt_kcage_freemem_end, kcage_freemem);
		KCAGE_STAT_SET_SCAN(kt_ticks, lbolt - scan_start);
		KCAGE_STAT_INC_SCAN_INDEX;
		goto loop;
	}

	/*NOTREACHED*/
}

void
kcage_cageout_wakeup()
{
	if (mutex_tryenter(&kcage_cageout_mutex)) {
		if (kcage_cageout_ready) {
			cv_signal(&kcage_cageout_cv);
		} else if (kcage_freemem < kcage_minfree || kcage_needfree) {
			/*
			 * Available cage memory is really low. Time to
			 * start expanding the cage. However, the
			 * kernel cage thread is not yet ready to
			 * do the work. Use *this* thread, which is
			 * most likely to be t0, to do the work.
			 */
			KCAGE_STAT_INCR(kcw_expandearly);
			(void) kcage_expand();
			KCAGE_STAT_INC_SCAN_INDEX;
		}

		mutex_exit(&kcage_cageout_mutex);
	}
	/* else, kernel cage thread is already running */
}

void
kcage_tick()
{
	/*
	 * Once per second we wake up all the threads throttled
	 * waiting for cage memory, in case we've become stuck
	 * and haven't made forward progress expanding the cage.
	 */
	if (kcage_on && kcage_cageout_ready)
		cv_broadcast(&kcage_throttle_cv);
}

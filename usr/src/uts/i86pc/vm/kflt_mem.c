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
 * Copyright (c) 2010, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/atomic.h>		/* used to update kflt_freemem */
#include <sys/kmem.h>		/* for kmem_reap */
#include <sys/errno.h>
#include <sys/kflt_mem.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <vm/hat.h>
#include <vm/vm_dep.h>
#include <sys/mem_config.h>
#include <sys/lgrp.h>
#include <sys/rwlock.h>
#include <sys/cpupart.h>

#ifdef DEBUG
#define	KFLT_STATS
#endif

#ifdef KFLT_STATS

#define	KFLT_STATS_VERSION 1	/* can help report generators */
#define	KFLT_STATS_NSCANS 256	/* depth of scan statistics buffer */

struct kflt_stats_scan {
	/* managed by KFLT_STAT_* macros */
	clock_t	scan_lbolt;
	uint_t	scan_id;

	/* set in kflt_user_evict() */
	uint_t	kt_passes;
	clock_t	kt_ticks;
	pgcnt_t	kt_kflt_freemem_start;
	pgcnt_t	kt_kflt_freemem_end;
	pgcnt_t kt_kflt_user_alloc_start;
	pgcnt_t kt_kflt_user_alloc_end;
	pgcnt_t kt_pfn_start;
	pgcnt_t kt_pfn_end;
	pgcnt_t kt_mnode_start;
	pgcnt_t kt_mnode_end;
	uint_t	kt_examined;
	uint_t	kt_cantlock;
	uint_t	kt_skiplevel;
	uint_t	kt_skipshared;
	uint_t	kt_skiprefd;
	uint_t	kt_destroy;

	/* set in kflt_invalidate_page() */
	uint_t	kip_reloclocked;
	uint_t	kip_relocmod;
	uint_t	kip_destroy;
	uint_t	kip_nomem;
	uint_t	kip_demotefailed;

	/* set in kflt_export */
	uint_t	kex_lp;
	uint_t	kex_err;
	uint_t	kex_scan;
};

struct kflt_stats {
	/* managed by KFLT_STAT_* macros */
	uint_t	version;
	uint_t	size;

	/* set in kflt_evict_thread */
	uint_t	kt_wakeups;
	uint_t	kt_scans;
	uint_t	kt_evict_break;

	/* set in kflt_create_throttle */
	uint_t	kft_calls;
	uint_t	kft_user_evict;
	uint_t	kft_critical;
	uint_t	kft_exempt;
	uint_t	kft_wait;
	uint_t	kft_progress;
	uint_t	kft_noprogress;
	uint_t	kft_timeout;

	/* managed by KFLT_STAT_* macros */
	uint_t	scan_array_size;
	uint_t	scan_index;
	struct kflt_stats_scan scans[KFLT_STATS_NSCANS];
};

static struct kflt_stats kflt_stats;
static struct kflt_stats_scan kflt_stats_scan_zero;

/*
 * No real need for atomics here. For the most part the incs and sets are
 * done by the kernel freelist thread. There are a few that are done by any
 * number of other threads. Those cases are noted by comments.
 */
#define	KFLT_STAT_INCR(m)	kflt_stats.m++

#define	KFLT_STAT_NINCR(m, v) kflt_stats.m += (v)

#define	KFLT_STAT_INCR_SCAN(m)	\
	KFLT_STAT_INCR(scans[kflt_stats.scan_index].m)

#define	KFLT_STAT_NINCR_SCAN(m, v) \
	KFLT_STAT_NINCR(scans[kflt_stats.scan_index].m, v)

#define	KFLT_STAT_SET(m, v)	kflt_stats.m = (v)

#define	KFLT_STAT_SETZ(m, v)	\
	if (kflt_stats.m == 0) kflt_stats.m = (v)

#define	KFLT_STAT_SET_SCAN(m, v)	\
	KFLT_STAT_SET(scans[kflt_stats.scan_index].m, v)

#define	KFLT_STAT_SETZ_SCAN(m, v)	\
	KFLT_STAT_SETZ(scans[kflt_stats.scan_index].m, v)

#define	KFLT_STAT_INC_SCAN_INDEX \
	KFLT_STAT_SET_SCAN(scan_lbolt, ddi_get_lbolt()); \
	KFLT_STAT_SET_SCAN(scan_id, kflt_stats.scan_index); \
	kflt_stats.scan_index = \
	(kflt_stats.scan_index + 1) % KFLT_STATS_NSCANS; \
	kflt_stats.scans[kflt_stats.scan_index] = kflt_stats_scan_zero

#define	KFLT_STAT_INIT_SCAN_INDEX \
	kflt_stats.version = KFLT_STATS_VERSION; \
	kflt_stats.size = sizeof (kflt_stats); \
	kflt_stats.scan_array_size = KFLT_STATS_NSCANS; \
	kflt_stats.scan_index = 0

#else /* KFLT_STATS */

#define	KFLT_STAT_INCR(v)
#define	KFLT_STAT_NINCR(m, v)
#define	KFLT_STAT_INCR_SCAN(v)
#define	KFLT_STAT_NINCR_SCAN(m, v)
#define	KFLT_STAT_SET(m, v)
#define	KFLT_STAT_SETZ(m, v)
#define	KFLT_STAT_SET_SCAN(m, v)
#define	KFLT_STAT_SETZ_SCAN(m, v)
#define	KFLT_STAT_INC_SCAN_INDEX
#define	KFLT_STAT_INIT_SCAN_INDEX

#endif /* KFLT_STATS */

/* Internal Routines */
void kflt_init(void);
void kflt_evict_wakeup(void);
static boolean_t kflt_evict_cpr(void *, int);
static void kflt_thread_init(void);
static pfn_t kflt_get_next_pfn(int *, pfn_t);
static void kflt_user_evict(void);
static int kflt_invalidate_page(page_t *, pgcnt_t *);
static int kflt_relocate_page(page_t *, pgcnt_t *);

extern mnoderange_t *mnoderanges;
extern int mnoderangecnt;
void wakeup_pcgs(void);

page_t *page_promote(int, pfn_t, uchar_t, int, int);

static kcondvar_t kflt_evict_cv;	/* evict thread naps here */
static kmutex_t kflt_evict_mutex;	/* protects cv and ready flag */
static int kflt_evict_ready;		/* nonzero when evict thread ready */
kthread_id_t kflt_evict_thread;		/* to aid debugging */
static kmutex_t kflt_throttle_mutex;	/* protects kflt_throttle_cv */
static kcondvar_t kflt_throttle_cv;

/*
 * Statistics used to drive the behavior of the evict demon.
 */
pgcnt_t kflt_freemem;		/* free memory on kernel freelist */
pgcnt_t kflt_needfree;		/* memory requirement for throttled threads */
pgcnt_t kflt_lotsfree;		/* export free kernel memory if > lotsfree */
pgcnt_t kflt_desfree;		/* wakeup evict thread if freemem < desfree */
pgcnt_t kflt_minfree;		/* keep scanning if freemem < minfree */
pgcnt_t kflt_user_alloc;	/* user memory allocated on kernel freelist */
pgcnt_t kflt_throttlefree;	/* throttle non-critical threads */
pgcnt_t kflt_reserve;		/* don't throttle real time if > reserve */
		/* time in seconds to check on throttled threads */
int kflt_maxwait = 10;

int kflt_on = 0;		/* indicates evict thread is initialised */

/*
 * This is called before a CPR suspend and after a CPR resume.  We have to
 * turn off kflt_evict before a suspend, and turn it back on after a
 * restart.
 */
/*ARGSUSED*/
static boolean_t
kflt_evict_cpr(void *arg, int code)
{
	if (code == CB_CODE_CPR_CHKPT) {
		ASSERT(kflt_evict_ready);
		kflt_evict_ready = 0;
		return (B_TRUE);
	} else if (code == CB_CODE_CPR_RESUME) {
		ASSERT(kflt_evict_ready == 0);
		kflt_evict_ready = 1;
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Sets up kernel freelist related statistics and starts the evict thread.
 */
void
kflt_init(void)
{
	ASSERT(!kflt_on);

	if (kflt_disable) {
		return;
	}

	mutex_init(&kflt_evict_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&kflt_evict_cv, NULL,  CV_DEFAULT, NULL);

	if (kflt_lotsfree == 0)
		kflt_lotsfree = MAX(32, total_pages / 128);

	if (kflt_minfree == 0)
		kflt_minfree = MAX(32, kflt_lotsfree / 4);

	if (kflt_desfree == 0)
		kflt_desfree = MAX(32, kflt_minfree);

	if (kflt_throttlefree == 0)
		kflt_throttlefree = MAX(32, kflt_minfree / 2);

	if (kflt_reserve == 0)
		kflt_reserve = MAX(32, kflt_throttlefree / 2);

	(void) callb_add(kflt_evict_cpr, NULL, CB_CL_CPR_POST_KERNEL,
	    "kflt_evict_thread");

	kflt_on = 1;
	kflt_thread_init();
}

/*
 * Wakeup kflt_user_evict thread and throttle waiting for the number of pages
 * requested to become available.  For non-critical requests, a
 * timeout is added, since freemem accounting is separate from kflt
 * freemem accounting: it's possible for us to get stuck and not make
 * forward progress even though there was sufficient freemem before
 * arriving here.
 */
int
kflt_create_throttle(pgcnt_t npages, int flags)
{
	int niter = 0;
	pgcnt_t lastfree;
	int enough = kflt_freemem > kflt_throttlefree + npages;

	KFLT_STAT_INCR(kft_calls);		/* unprotected incr. */

	kflt_evict_wakeup();			/* just to be sure */
	KFLT_STAT_INCR(kft_user_evict);	/* unprotected incr. */

	/*
	 * Obviously, we can't throttle the evict thread since
	 * we depend on it.  We also can't throttle the panic thread.
	 */
	if (curthread == kflt_evict_thread ||
	    !kflt_evict_ready || panicstr) {
		KFLT_STAT_INCR(kft_user_evict);	/* unprotected incr. */
		return (KFT_CRIT);
	}

	/*
	 * Don't throttle threads which are critical for proper
	 * vm management if we're above kfLt_throttlefree or
	 * if freemem is very low.
	 */
	if (NOMEMWAIT()) {
		if (enough) {
			KFLT_STAT_INCR(kft_exempt);	/* unprotected incr. */
			return (KFT_CRIT);
		} else if (freemem < minfree) {
			KFLT_STAT_INCR(kft_critical);  /* unprotected incr. */
			return (KFT_CRIT);
		}
	}

	/*
	 * Don't throttle real-time threads if kflt_freemem > kflt_reserve.
	 */
	if (DISP_PRIO(curthread) > maxclsyspri &&
	    kflt_freemem > kflt_reserve) {
		KFLT_STAT_INCR(kft_exempt);	/* unprotected incr. */
		return (KFT_CRIT);
	}

	/*
	 * Cause all other threads (which are assumed to not be
	 * critical to kflt_user_evict) to wait here until their request
	 * can be satisfied. Be a little paranoid and wake the
	 * kernel evict thread on each loop through this logic.
	 */
	while (kflt_freemem < kflt_throttlefree + npages) {
		ASSERT(kflt_on);

		lastfree = kflt_freemem;

		if (kflt_evict_ready) {
			mutex_enter(&kflt_throttle_mutex);

			kflt_needfree += npages;
			KFLT_STAT_INCR(kft_wait);

			kflt_evict_wakeup();
			KFLT_STAT_INCR(kft_user_evict);

			cv_wait(&kflt_throttle_cv, &kflt_throttle_mutex);

			kflt_needfree -= npages;

			mutex_exit(&kflt_throttle_mutex);
		} else {
			/*
			 * NOTE: atomics are used just in case we enter
			 * mp operation before the evict thread is ready.
			 */
			atomic_add_long(&kflt_needfree, npages);

			kflt_evict_wakeup();
			KFLT_STAT_INCR(kft_user_evict);	/* unprotected incr. */

			atomic_add_long(&kflt_needfree, -npages);
		}

		if ((flags & PG_WAIT) == 0) {
			if (kflt_freemem > lastfree) {
				KFLT_STAT_INCR(kft_progress);
				niter = 0;
			} else {
				KFLT_STAT_INCR(kft_noprogress);
				if (++niter >= kflt_maxwait) {
					KFLT_STAT_INCR(kft_timeout);
					return (KFT_FAILURE);
				}
			}
		}

		if (NOMEMWAIT() && freemem < minfree) {
			return (KFT_CRIT);
		}

	}
	return (KFT_NONCRIT);
}
/*
 * Creates the kernel freelist evict thread.
 */
static void
kflt_thread_init(void)
{
	if (kflt_on) {
		if (thread_create(NULL, 0, kflt_user_evict,
		    NULL, 0, &p0, TS_RUN, maxclsyspri - 1) == NULL) {
			kflt_on = 0;
		}
	}
}

/*
 * This routine is used by the kernel freelist evict thread to iterate over the
 * pfns.
 */
static pfn_t
kflt_get_next_pfn(int *mnode, pfn_t pfn)
{
	ASSERT((*mnode >= 0) && (*mnode <= mnoderangecnt));
	ASSERT((pfn == PFN_INVALID) || (pfn >= mnoderanges[*mnode].mnr_pfnlo));

	if (pfn == PFN_INVALID) {
		*mnode = 0;
		pfn = mnoderanges[0].mnr_pfnlo;
		return (pfn);
	}

	pfn++;
	if (pfn > mnoderanges[*mnode].mnr_pfnhi) {
		(*mnode)++;
		if (*mnode >= mnoderangecnt) {
			return (PFN_INVALID);
		}
		pfn = mnoderanges[*mnode].mnr_pfnlo;
	}
	return (pfn);
}
/*
 * Locks all the kernel page freelist mutexes before promoting a group of pages
 * and returning the large page to the user page freelist.
 */
void
page_kflt_lock(int mnode)
{
	int i;
	for (i = 0; i < NPC_MUTEX; i++) {
		mutex_enter(KFPC_MUTEX(mnode, i));
	}
}

/*
 * Unlocks all the kernel page freelist mutexes after promoting a group of pages
 * and returning the large page to the user page freelist.
 */
void
page_kflt_unlock(int mnode)
{
	int i;
	for (i = 0; i < NPC_MUTEX; i++) {
		mutex_exit(KFPC_MUTEX(mnode, i));
	}
}

/*
 * This routine is called by the kflt_user_evict() thread whenever a free page
 * is found on the kernel page freelist and there is an excess of free memory on
 * the kernel freelist. It determines whether it is possible to promote groups
 * of small free pages into a large page which can then be returned to the
 * user page freelist.
 */
static int
kflt_export(page_t *pp, int init_state)
{
	static page_t *lp_base = 0;
	static pfn_t lp_base_page_num = 0;
	static pgcnt_t lp_count = 0;
	page_t *tpp;
	page_t *lpp;
	pfn_t	lp_page_num;
	int mtype;
	int mnode;
	int bin;
	pgcnt_t pages_left, npgs;
	uchar_t new_szc = KFLT_PAGESIZE;
	int ret;
	kmutex_t *pcm;


	/*
	 * We're not holding any locks yet, so pp state may change.
	 */
	if (init_state || !PP_ISFREE(pp) || !PP_ISKFLT(pp)) {
		lp_base = NULL;
		lp_base_page_num = 0;
		lp_count = 0;
		return (0);
	}

	ret = 0;
	npgs =  page_get_pagecnt(new_szc);
	lp_page_num = PFN_BASE(pp->p_pagenum, new_szc);

	/* Count pages with the same large page base */
	if (lp_page_num == lp_base_page_num) {
		ASSERT((pp->p_pagenum - lp_base_page_num) < npgs);
		ASSERT(lp_count < npgs);
		lp_count++;
		if (lp_count == npgs) {
			KFLT_STAT_INCR_SCAN(kex_lp);
			ASSERT(lp_base != NULL);
			mnode =  PP_2_MEM_NODE(pp);
			page_kflt_lock(mnode);

			/*
			 * Check that all pages are still free and on the kernel
			 * freelist.
			 */
			for (tpp = lp_base, pages_left = npgs; pages_left;
			    tpp++, pages_left--) {
				if (!PP_ISFREE(tpp) || !PP_ISKFLT(tpp)) {
					page_kflt_unlock(mnode);
					KFLT_STAT_INCR_SCAN(kex_err);
					goto out;
				}
			}

			lpp = page_promote(PP_2_MEM_NODE(lp_base),
			    lp_base_page_num, new_szc, PC_KFLT_EXPORT,
			    PP_2_MTYPE(lp_base));
			page_kflt_unlock(mnode);

#ifdef KFLT_STATS
			if (lpp == NULL)
				VM_STAT_ADD(vmm_vmstats.pgexportfail);
#endif
			if (lpp != NULL) {
				VM_STAT_ADD(vmm_vmstats.pgexportok);
				/* clear kflt bit in each page */
				tpp = lpp;
				do {
					ASSERT(PP_ISKFLT(tpp));
					ASSERT(PP_ISFREE(tpp));
					PP_CLRKFLT(tpp);
					tpp = tpp->p_next;
				} while (tpp != lpp);

				/*
				 * Return large page to the user page
				 * freelist
				 */
				atomic_add_long(&kflt_freemem, -npgs);
				bin = PP_2_BIN(lpp);
				mnode = PP_2_MEM_NODE(lpp);
				mtype = PP_2_MTYPE(lpp);
				pcm = PC_FREELIST_BIN_MUTEX(PFLT_USER, mnode,
				    bin, 0);
				mutex_enter(pcm);
				page_vpadd(PAGE_FREELISTP(PFLT_USER, mnode,
				    new_szc, bin, mtype), lpp);
				mutex_exit(pcm);
				ret = 1;
			}
		}
	} else	{
out:
		lp_base = pp;
		lp_base_page_num = lp_page_num;
		lp_count = 1;
	}
	return (ret);
}

/*
 * This thread is woken up whenever pages are added or removed from the kernel
 * page freelist and free memory on this list is low, or when there is excess
 * memory on the kernel freelist. It iterates over the physical pages in the
 * system and has two main tasks:
 *
 *  1) Relocate user pages which have been allocated on the kernel page freelist
 *     wherever this is possible.
 *
 *  2) Identify groups of free pages on the kernel page freelist which can be
 *     promoted to large pages and then exported to the user page freelist.
 */
static void
kflt_user_evict(void)
{
	pfn_t pfn;
	int mnode;
	page_t *pp = NULL;
	callb_cpr_t cprinfo;
	int pass;
	int last_pass;
	int did_something;
	int scan_again;
	int pages_skipped;
	int shared_skipped;
	ulong_t shared_level = 8;
	pgcnt_t nfreed;
	int prm;
	pfn_t start_pfn;
	int pages_scanned;
	int pages_skipped_thresh = 20;
	int shared_skipped_thresh = 20;
	clock_t	kflt_export_scan_start = 0;
	int kflt_export_scan;
	clock_t scan_start;
	int kflt_min_scan_delay = (hz * 60);
	int kflt_max_scan_delay = kflt_min_scan_delay * 5;
	int kflt_scan_delay = kflt_min_scan_delay;

	ASSERT(kflt_on);
	CALLB_CPR_INIT(&cprinfo, &kflt_evict_mutex,
	    callb_generic_cpr, "kflt_user_evict");

	mutex_enter(&kflt_evict_mutex);
	kflt_evict_thread = curthread;

	pfn = PFN_INVALID;		/* force scan reset */
	start_pfn = PFN_INVALID;	/* force init with 1st pfn */
	mnode = 0;
	kflt_evict_ready = 1;

loop:
	CALLB_CPR_SAFE_BEGIN(&cprinfo);
	cv_wait(&kflt_evict_cv, &kflt_evict_mutex);
	CALLB_CPR_SAFE_END(&cprinfo, &kflt_evict_mutex);

	scan_start = ddi_get_lbolt();
	kflt_export_scan = 0;
	if (kflt_freemem > kflt_lotsfree) {
		/* Force a delay between kflt export scans */
		if ((scan_start - kflt_export_scan_start) >
		    kflt_scan_delay) {
			kflt_export_scan = 1;
			kflt_export_scan_start = scan_start;
			KFLT_STAT_SET_SCAN(kex_scan, 1);
		}
	}

	KFLT_STAT_INCR(kt_wakeups);
	KFLT_STAT_SET_SCAN(kt_kflt_user_alloc_start, kflt_user_alloc);
	KFLT_STAT_SET_SCAN(kt_pfn_start, pfn);
	KFLT_STAT_SET_SCAN(kt_kflt_freemem_start, kflt_freemem);
	KFLT_STAT_SET_SCAN(kt_mnode_start, mnode);
	pass = 0;
	last_pass = 0;


again:
	did_something = 0;
	pages_skipped = 0;
	shared_skipped = 0;
	pages_scanned = 0;

	KFLT_STAT_INCR(kt_scans);
	KFLT_STAT_INCR_SCAN(kt_passes);

	/*
	 * There are two conditions which drive the loop -
	 *
	 * 1. If we have too much free memory then it may be possible to
	 * export some large pages back to the user page freelist.
	 *
	 * 2. If a large number of user pages have been allocated from the
	 * kernel freelist then we try to relocate them.
	 */

	while ((kflt_export_scan || kflt_needfree ||
	    (kflt_freemem < kflt_lotsfree && kflt_user_alloc)) &&
	    ((pfn =  kflt_get_next_pfn(&mnode, pfn)) != PFN_INVALID)) {
		if (start_pfn == PFN_INVALID) {
			start_pfn = pfn;
		} else if (start_pfn == pfn) {
			last_pass = pass;
			pass += 1;

			/* initialize internal state in kflt_export() */
			(void) kflt_export(pp, 1);
			/*
			 * Did a complete walk of kernel freelist, but didn't
			 * free any pages.
			 */
			if (cp_default.cp_ncpus == 1 && did_something == 0) {
				KFLT_STAT_INCR(kt_evict_break);
				break;
			}
			did_something = 0;
		}
		pages_scanned = 1;

		pp = page_numtopp_nolock(pfn);
		if (pp == NULL) {
			continue;
		}

		KFLT_STAT_INCR_SCAN(kt_examined);

		if (!PP_ISKFLT(pp))
			continue;

		if (kflt_export_scan) {
			if (PP_ISFREE(pp) && kflt_export(pp, 0)) {
				did_something = 1;
			}
			continue;
		}

		if (!kflt_user_alloc) {
			continue;
		}

		if (PP_ISKAS(pp) || !page_trylock(pp, SE_EXCL)) {
			KFLT_STAT_INCR_SCAN(kt_cantlock);
			continue;
		}

		/* Check that the page is in the same state after locking */
		if (PP_ISFREE(pp) || PP_ISKAS(pp)) {
			page_unlock(pp);
			continue;
		}

		KFLT_STAT_SET_SCAN(kt_skiplevel, shared_level);
		if (hat_page_checkshare(pp, shared_level)) {
			page_unlock(pp);
			pages_skipped++;
			shared_skipped++;
			KFLT_STAT_INCR_SCAN(kt_skipshared);
			continue;
		}

		prm = hat_pagesync(pp,
		    HAT_SYNC_DONTZERO | HAT_SYNC_STOPON_MOD);

		/* On first pass ignore ref'd pages */
		if (pass <= 1 && (prm & P_REF)) {
			page_unlock(pp);
			KFLT_STAT_INCR_SCAN(kt_skiprefd);
			continue;
		}

		/* On pass 2, VN_DISPOSE if mod bit is not set */
		if (pass <= 2) {
			if (pp->p_szc != 0 || (prm & P_MOD) ||
			    pp->p_lckcnt || pp->p_cowcnt) {
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
					pages_skipped++;
					page_unlock(pp);
					continue;
				}

				/* LINTED: constant in conditional context */
				VN_DISPOSE(pp, B_INVAL, 0, kcred);
				KFLT_STAT_INCR_SCAN(kt_destroy);
				did_something = 1;
			}
			continue;
		}

		if (kflt_invalidate_page(pp, &nfreed) == 0) {
			did_something = 1;
		}

		/*
		 * No need to drop the page lock here.
		 * kflt_invalidate_page has done that for us
		 * either explicitly or through a page_free.
		 */
	}

	/*
	 * Scan again if we need more memory from the kernel
	 * freelist or user memory allocations from the kernel freelist
	 * are too high.
	 */
	scan_again = 0;
	if (kflt_freemem < kflt_minfree || kflt_needfree) {
		if (pass <= 3 && kflt_user_alloc && pages_scanned &&
		    pages_skipped > pages_skipped_thresh) {
			scan_again = 1;
		} else {
			/*
			 * We need to allocate more memory to the kernel
			 * freelist.
			 */
			kflt_expand();
		}
	} else if (kflt_freemem < kflt_lotsfree && kflt_user_alloc) {
		ASSERT(pages_scanned);
		if (pass <= 2 && pages_skipped > pages_skipped_thresh)
			scan_again = 1;
		if (pass == last_pass || did_something)
			scan_again = 1;
		else if (shared_skipped > shared_skipped_thresh &&
		    shared_level < (8<<24)) {
			shared_level <<= 1;
			scan_again = 1;
		}
	} else if (kflt_export_scan) {
		/*
		 * The delay between kflt export scans varies between a minimum
		 * of 60 secs and a maximum of 5 mins. The delay is set to the
		 * minimum if a page is promoted during a scan and increased
		 * otherwise.
		 */
		if (did_something) {
			kflt_scan_delay = kflt_min_scan_delay;
		} else if (kflt_scan_delay < kflt_max_scan_delay) {
			kflt_scan_delay += kflt_min_scan_delay;
		}
	}

	if (scan_again && cp_default.cp_ncpus > 1) {
		goto again;
	} else {
		if (shared_level > 8)
			shared_level >>= 1;

		KFLT_STAT_SET_SCAN(kt_pfn_end, pfn);
		KFLT_STAT_SET_SCAN(kt_mnode_end, mnode);
		KFLT_STAT_SET_SCAN(kt_kflt_user_alloc_end, kflt_user_alloc);
		KFLT_STAT_SET_SCAN(kt_kflt_freemem_end, kflt_freemem);
		KFLT_STAT_SET_SCAN(kt_ticks, ddi_get_lbolt() - scan_start);
		KFLT_STAT_INC_SCAN_INDEX;
		goto loop;
	}

}

/*
 * Relocate page opp (Original Page Pointer) from kernel page freelist to page
 * rpp * (Replacement Page Pointer) on the user page freelist. Page opp will be
 * freed  if relocation is successful, otherwise it is only unlocked.
 * On entry, page opp must be exclusively locked and not free.
 * *nfreedp: number of pages freed.
 */
static int
kflt_relocate_page(page_t *pp, pgcnt_t *nfreedp)
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
 * Kflt_invalidate_page() uses page_relocate() twice. Both instances
 * of use must be updated to match the new page_relocate() when it
 * becomes available.
 *
 * Return result of kflt_relocate_page or zero if page was directly freed.
 * *nfreedp: number of pages freed.
 */
static int
kflt_invalidate_page(page_t *pp, pgcnt_t *nfreedp)
{
	int result;

	ASSERT(!PP_ISFREE(pp));
	ASSERT(PAGE_EXCL(pp));

	/*
	 * Is this page involved in some I/O? shared?
	 * The page_struct_lock need not be acquired to
	 * examine these fields since the page has an
	 * "exclusive" lock.
	 */
	if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
		result = kflt_relocate_page(pp, nfreedp);
#ifdef KFLT_STATS
		if (result == 0)
			KFLT_STAT_INCR_SCAN(kip_reloclocked);
		else if (result == ENOMEM)
			KFLT_STAT_INCR_SCAN(kip_nomem);
#endif
		return (result);
	}

	ASSERT(pp->p_vnode->v_type != VCHR);

	/*
	 * Unload the mappings and check if mod bit is set.
	 */
	(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);

	if (hat_ismod(pp)) {
		result = kflt_relocate_page(pp, nfreedp);
#ifdef KFLT_STATS
		if (result == 0)
			KFLT_STAT_INCR_SCAN(kip_relocmod);
		else if (result == ENOMEM)
			KFLT_STAT_INCR_SCAN(kip_nomem);
#endif
		return (result);
	}

	if (!page_try_demote_pages(pp)) {
		KFLT_STAT_INCR_SCAN(kip_demotefailed);
		page_unlock(pp);
		return (EAGAIN);
	}

	/* LINTED: constant in conditional context */
	VN_DISPOSE(pp, B_INVAL, 0, kcred);
	KFLT_STAT_INCR_SCAN(kip_destroy);
	*nfreedp = 1;
	return (0);
}

void
kflt_evict_wakeup(void)
{
	if (mutex_tryenter(&kflt_evict_mutex)) {
		if (kflt_evict_ready && (kflt_freemem > kflt_lotsfree ||
		    (kflt_freemem < kflt_desfree && kflt_user_alloc) ||
		    kflt_needfree)) {
			cv_signal(&kflt_evict_cv);
		}
		mutex_exit(&kflt_evict_mutex);
	}
	/* else, kflt thread is already running */
}

void
kflt_freemem_sub(pgcnt_t npages)
{
	atomic_add_long(&kflt_freemem, -npages);

	ASSERT(kflt_freemem >= 0);

	if (kflt_evict_ready &&
	    (kflt_freemem > kflt_lotsfree ||
	    kflt_freemem < kflt_desfree || kflt_needfree)) {
		kflt_evict_wakeup();
	}
}

void
kflt_freemem_add(pgcnt_t npages)
{
	atomic_add_long(&kflt_freemem, npages);

	wakeup_pcgs();  /* wakeup threads in pcgs() */

	if (kflt_evict_ready && kflt_needfree &&
	    kflt_freemem >= (kflt_throttlefree + kflt_needfree)) {
		mutex_enter(&kflt_throttle_mutex);
		cv_broadcast(&kflt_throttle_cv);
		mutex_exit(&kflt_throttle_mutex);
	}
}

void
kflt_tick()
{
	/*
	 * Once per second we wake up all the threads throttled
	 * waiting for kernel freelist memory, in case we've become stuck
	 * and haven't made forward progress expanding the kernel freelist.
	 */
	if (kflt_on && kflt_evict_ready)
		cv_broadcast(&kflt_throttle_cv);
}

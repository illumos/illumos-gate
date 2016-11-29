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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989  AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * VM - physical page management.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vm.h>
#include <sys/vtrace.h>
#include <sys/swap.h>
#include <sys/cmn_err.h>
#include <sys/tuneable.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/callb.h>
#include <sys/debug.h>
#include <sys/tnf_probe.h>
#include <sys/condvar_impl.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/strlog.h>
#include <sys/mman.h>
#include <sys/ontrap.h>
#include <sys/lgrp.h>
#include <sys/vfs.h>

#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/pvn.h>
#include <vm/seg_kmem.h>
#include <vm/vm_dep.h>
#include <sys/vm_usage.h>
#include <fs/fs_subr.h>
#include <sys/ddi.h>
#include <sys/modctl.h>

static pgcnt_t max_page_get;	/* max page_get request size in pages */
pgcnt_t total_pages = 0;	/* total number of pages (used by /proc) */

/*
 * freemem_lock protects all freemem variables:
 * availrmem. Also this lock protects the globals which track the
 * availrmem changes for accurate kernel footprint calculation.
 * See below for an explanation of these
 * globals.
 */
kmutex_t freemem_lock;
pgcnt_t availrmem;
pgcnt_t availrmem_initial;

/*
 * These globals track availrmem changes to get a more accurate
 * estimate of tke kernel size. Historically pp_kernel is used for
 * kernel size and is based on availrmem. But availrmem is adjusted for
 * locked pages in the system not just for kernel locked pages.
 * These new counters will track the pages locked through segvn and
 * by explicit user locking.
 *
 * pages_locked : How many pages are locked because of user specified
 * locking through mlock or plock.
 *
 * pages_useclaim,pages_claimed : These two variables track the
 * claim adjustments because of the protection changes on a segvn segment.
 *
 * All these globals are protected by the same lock which protects availrmem.
 */
pgcnt_t pages_locked = 0;
pgcnt_t pages_useclaim = 0;
pgcnt_t pages_claimed = 0;


/*
 * new_freemem_lock protects freemem, freemem_wait & freemem_cv.
 */
static kmutex_t	new_freemem_lock;
static uint_t	freemem_wait;	/* someone waiting for freemem */
static kcondvar_t freemem_cv;

/*
 * The logical page free list is maintained as two lists, the 'free'
 * and the 'cache' lists.
 * The free list contains those pages that should be reused first.
 *
 * The implementation of the lists is machine dependent.
 * page_get_freelist(), page_get_cachelist(),
 * page_list_sub(), and page_list_add()
 * form the interface to the machine dependent implementation.
 *
 * Pages with p_free set are on the cache list.
 * Pages with p_free and p_age set are on the free list,
 *
 * A page may be locked while on either list.
 */

/*
 * free list accounting stuff.
 *
 *
 * Spread out the value for the number of pages on the
 * page free and page cache lists.  If there is just one
 * value, then it must be under just one lock.
 * The lock contention and cache traffic are a real bother.
 *
 * When we acquire and then drop a single pcf lock
 * we can start in the middle of the array of pcf structures.
 * If we acquire more than one pcf lock at a time, we need to
 * start at the front to avoid deadlocking.
 *
 * pcf_count holds the number of pages in each pool.
 *
 * pcf_block is set when page_create_get_something() has asked the
 * PSM page freelist and page cachelist routines without specifying
 * a color and nothing came back.  This is used to block anything
 * else from moving pages from one list to the other while the
 * lists are searched again.  If a page is freeed while pcf_block is
 * set, then pcf_reserve is incremented.  pcgs_unblock() takes care
 * of clearning pcf_block, doing the wakeups, etc.
 */

#define	MAX_PCF_FANOUT NCPU
static uint_t pcf_fanout = 1; /* Will get changed at boot time */
static uint_t pcf_fanout_mask = 0;

struct pcf {
	kmutex_t	pcf_lock;	/* protects the structure */
	uint_t		pcf_count;	/* page count */
	uint_t		pcf_wait;	/* number of waiters */
	uint_t		pcf_block; 	/* pcgs flag to page_free() */
	uint_t		pcf_reserve; 	/* pages freed after pcf_block set */
	uint_t		pcf_fill[10];	/* to line up on the caches */
};

/*
 * PCF_INDEX hash needs to be dynamic (every so often the hash changes where
 * it will hash the cpu to).  This is done to prevent a drain condition
 * from happening.  This drain condition will occur when pcf_count decrement
 * occurs on cpu A and the increment of pcf_count always occurs on cpu B.  An
 * example of this shows up with device interrupts.  The dma buffer is allocated
 * by the cpu requesting the IO thus the pcf_count is decremented based on that.
 * When the memory is returned by the interrupt thread, the pcf_count will be
 * incremented based on the cpu servicing the interrupt.
 */
static struct pcf pcf[MAX_PCF_FANOUT];
#define	PCF_INDEX() ((int)(((long)CPU->cpu_seqid) + \
	(randtick() >> 24)) & (pcf_fanout_mask))

static int pcf_decrement_bucket(pgcnt_t);
static int pcf_decrement_multiple(pgcnt_t *, pgcnt_t, int);

kmutex_t	pcgs_lock;		/* serializes page_create_get_ */
kmutex_t	pcgs_cagelock;		/* serializes NOSLEEP cage allocs */
kmutex_t	pcgs_wait_lock;		/* used for delay in pcgs */
static kcondvar_t	pcgs_cv;	/* cv for delay in pcgs */

#ifdef VM_STATS

/*
 * No locks, but so what, they are only statistics.
 */

static struct page_tcnt {
	int	pc_free_cache;		/* free's into cache list */
	int	pc_free_dontneed;	/* free's with dontneed */
	int	pc_free_pageout;	/* free's from pageout */
	int	pc_free_free;		/* free's into free list */
	int	pc_free_pages;		/* free's into large page free list */
	int	pc_destroy_pages;	/* large page destroy's */
	int	pc_get_cache;		/* get's from cache list */
	int	pc_get_free;		/* get's from free list */
	int	pc_reclaim;		/* reclaim's */
	int	pc_abortfree;		/* abort's of free pages */
	int	pc_find_hit;		/* find's that find page */
	int	pc_find_miss;		/* find's that don't find page */
	int	pc_destroy_free;	/* # of free pages destroyed */
#define	PC_HASH_CNT	(4*PAGE_HASHAVELEN)
	int	pc_find_hashlen[PC_HASH_CNT+1];
	int	pc_addclaim_pages;
	int	pc_subclaim_pages;
	int	pc_free_replacement_page[2];
	int	pc_try_demote_pages[6];
	int	pc_demote_pages[2];
} pagecnt;

uint_t	hashin_count;
uint_t	hashin_not_held;
uint_t	hashin_already;

uint_t	hashout_count;
uint_t	hashout_not_held;

uint_t	page_create_count;
uint_t	page_create_not_enough;
uint_t	page_create_not_enough_again;
uint_t	page_create_zero;
uint_t	page_create_hashout;
uint_t	page_create_page_lock_failed;
uint_t	page_create_trylock_failed;
uint_t	page_create_found_one;
uint_t	page_create_hashin_failed;
uint_t	page_create_dropped_phm;

uint_t	page_create_new;
uint_t	page_create_exists;
uint_t	page_create_putbacks;
uint_t	page_create_overshoot;

uint_t	page_reclaim_zero;
uint_t	page_reclaim_zero_locked;

uint_t	page_rename_exists;
uint_t	page_rename_count;

uint_t	page_lookup_cnt[20];
uint_t	page_lookup_nowait_cnt[10];
uint_t	page_find_cnt;
uint_t	page_exists_cnt;
uint_t	page_exists_forreal_cnt;
uint_t	page_lookup_dev_cnt;
uint_t	get_cachelist_cnt;
uint_t	page_create_cnt[10];
uint_t	alloc_pages[9];
uint_t	page_exphcontg[19];
uint_t  page_create_large_cnt[10];

#endif

static inline page_t *
page_hash_search(ulong_t index, vnode_t *vnode, u_offset_t off)
{
	uint_t mylen = 0;
	page_t *page;

	for (page = page_hash[index]; page; page = page->p_hash, mylen++)
		if (page->p_vnode == vnode && page->p_offset == off)
			break;

#ifdef	VM_STATS
	if (page != NULL)
		pagecnt.pc_find_hit++;
	else
		pagecnt.pc_find_miss++;

	pagecnt.pc_find_hashlen[MIN(mylen, PC_HASH_CNT)]++;
#endif

	return (page);
}


#ifdef DEBUG
#define	MEMSEG_SEARCH_STATS
#endif

#ifdef MEMSEG_SEARCH_STATS
struct memseg_stats {
    uint_t nsearch;
    uint_t nlastwon;
    uint_t nhashwon;
    uint_t nnotfound;
} memseg_stats;

#define	MEMSEG_STAT_INCR(v) \
	atomic_inc_32(&memseg_stats.v)
#else
#define	MEMSEG_STAT_INCR(x)
#endif

struct memseg *memsegs;		/* list of memory segments */

/*
 * /etc/system tunable to control large page allocation hueristic.
 *
 * Setting to LPAP_LOCAL will heavily prefer the local lgroup over remote lgroup
 * for large page allocation requests.  If a large page is not readily
 * avaliable on the local freelists we will go through additional effort
 * to create a large page, potentially moving smaller pages around to coalesce
 * larger pages in the local lgroup.
 * Default value of LPAP_DEFAULT will go to remote freelists if large pages
 * are not readily available in the local lgroup.
 */
enum lpap {
	LPAP_DEFAULT,	/* default large page allocation policy */
	LPAP_LOCAL	/* local large page allocation policy */
};

enum lpap lpg_alloc_prefer = LPAP_DEFAULT;

static void page_init_mem_config(void);
static int page_do_hashin(page_t *, vnode_t *, u_offset_t);
static void page_do_hashout(page_t *);
static void page_capture_init();
int page_capture_take_action(page_t *, uint_t, void *);

static void page_demote_vp_pages(page_t *);


void
pcf_init(void)
{
	if (boot_ncpus != -1) {
		pcf_fanout = boot_ncpus;
	} else {
		pcf_fanout = max_ncpus;
	}
#ifdef sun4v
	/*
	 * Force at least 4 buckets if possible for sun4v.
	 */
	pcf_fanout = MAX(pcf_fanout, 4);
#endif /* sun4v */

	/*
	 * Round up to the nearest power of 2.
	 */
	pcf_fanout = MIN(pcf_fanout, MAX_PCF_FANOUT);
	if (!ISP2(pcf_fanout)) {
		pcf_fanout = 1 << highbit(pcf_fanout);

		if (pcf_fanout > MAX_PCF_FANOUT) {
			pcf_fanout = 1 << (highbit(MAX_PCF_FANOUT) - 1);
		}
	}
	pcf_fanout_mask = pcf_fanout - 1;
}

/*
 * vm subsystem related initialization
 */
void
vm_init(void)
{
	boolean_t callb_vm_cpr(void *, int);

	(void) callb_add(callb_vm_cpr, 0, CB_CL_CPR_VM, "vm");
	page_init_mem_config();
	page_retire_init();
	vm_usage_init();
	page_capture_init();
}

/*
 * This function is called at startup and when memory is added or deleted.
 */
void
init_pages_pp_maximum()
{
	static pgcnt_t p_min;
	static pgcnt_t pages_pp_maximum_startup;
	static pgcnt_t avrmem_delta;
	static int init_done;
	static int user_set;	/* true if set in /etc/system */

	if (init_done == 0) {

		/* If the user specified a value, save it */
		if (pages_pp_maximum != 0) {
			user_set = 1;
			pages_pp_maximum_startup = pages_pp_maximum;
		}

		/*
		 * Setting of pages_pp_maximum is based first time
		 * on the value of availrmem just after the start-up
		 * allocations. To preserve this relationship at run
		 * time, use a delta from availrmem_initial.
		 */
		ASSERT(availrmem_initial >= availrmem);
		avrmem_delta = availrmem_initial - availrmem;

		/* The allowable floor of pages_pp_maximum */
		p_min = tune.t_minarmem + 100;

		/* Make sure we don't come through here again. */
		init_done = 1;
	}
	/*
	 * Determine pages_pp_maximum, the number of currently available
	 * pages (availrmem) that can't be `locked'. If not set by
	 * the user, we set it to 4% of the currently available memory
	 * plus 4MB.
	 * But we also insist that it be greater than tune.t_minarmem;
	 * otherwise a process could lock down a lot of memory, get swapped
	 * out, and never have enough to get swapped back in.
	 */
	if (user_set)
		pages_pp_maximum = pages_pp_maximum_startup;
	else
		pages_pp_maximum = ((availrmem_initial - avrmem_delta) / 25)
		    + btop(4 * 1024 * 1024);

	if (pages_pp_maximum <= p_min) {
		pages_pp_maximum = p_min;
	}
}

void
set_max_page_get(pgcnt_t target_total_pages)
{
	max_page_get = target_total_pages / 2;
}

static pgcnt_t pending_delete;

/*ARGSUSED*/
static void
page_mem_config_post_add(
	void *arg,
	pgcnt_t delta_pages)
{
	set_max_page_get(total_pages - pending_delete);
	init_pages_pp_maximum();
}

/*ARGSUSED*/
static int
page_mem_config_pre_del(
	void *arg,
	pgcnt_t delta_pages)
{
	pgcnt_t nv;

	nv = atomic_add_long_nv(&pending_delete, (spgcnt_t)delta_pages);
	set_max_page_get(total_pages - nv);
	return (0);
}

/*ARGSUSED*/
static void
page_mem_config_post_del(
	void *arg,
	pgcnt_t delta_pages,
	int cancelled)
{
	pgcnt_t nv;

	nv = atomic_add_long_nv(&pending_delete, -(spgcnt_t)delta_pages);
	set_max_page_get(total_pages - nv);
	if (!cancelled)
		init_pages_pp_maximum();
}

static kphysm_setup_vector_t page_mem_config_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,
	page_mem_config_post_add,
	page_mem_config_pre_del,
	page_mem_config_post_del,
};

static void
page_init_mem_config(void)
{
	int ret;

	ret = kphysm_setup_func_register(&page_mem_config_vec, (void *)NULL);
	ASSERT(ret == 0);
}

/*
 * Evenly spread out the PCF counters for large free pages
 */
static void
page_free_large_ctr(pgcnt_t npages)
{
	static struct pcf	*p = pcf;
	pgcnt_t			lump;

	freemem += npages;

	lump = roundup(npages, pcf_fanout) / pcf_fanout;

	while (npages > 0) {

		ASSERT(!p->pcf_block);

		if (lump < npages) {
			p->pcf_count += (uint_t)lump;
			npages -= lump;
		} else {
			p->pcf_count += (uint_t)npages;
			npages = 0;
		}

		ASSERT(!p->pcf_wait);

		if (++p > &pcf[pcf_fanout - 1])
			p = pcf;
	}

	ASSERT(npages == 0);
}

/*
 * Add a physical chunk of memory to the system free lists during startup.
 * Platform specific startup() allocates the memory for the page structs.
 *
 * num	- number of page structures
 * base - page number (pfn) to be associated with the first page.
 *
 * Since we are doing this during startup (ie. single threaded), we will
 * use shortcut routines to avoid any locking overhead while putting all
 * these pages on the freelists.
 *
 * NOTE: Any changes performed to page_free(), must also be performed to
 *	 add_physmem() since this is how we initialize all page_t's at
 *	 boot time.
 */
void
add_physmem(
	page_t	*pp,
	pgcnt_t	num,
	pfn_t	pnum)
{
	page_t	*root = NULL;
	uint_t	szc = page_num_pagesizes() - 1;
	pgcnt_t	large = page_get_pagecnt(szc);
	pgcnt_t	cnt = 0;

	TRACE_2(TR_FAC_VM, TR_PAGE_INIT,
	    "add_physmem:pp %p num %lu", pp, num);

	/*
	 * Arbitrarily limit the max page_get request
	 * to 1/2 of the page structs we have.
	 */
	total_pages += num;
	set_max_page_get(total_pages);

	PLCNT_MODIFY_MAX(pnum, (long)num);

	/*
	 * The physical space for the pages array
	 * representing ram pages has already been
	 * allocated.  Here we initialize each lock
	 * in the page structure, and put each on
	 * the free list
	 */
	for (; num; pp++, pnum++, num--) {

		/*
		 * this needs to fill in the page number
		 * and do any other arch specific initialization
		 */
		add_physmem_cb(pp, pnum);

		pp->p_lckcnt = 0;
		pp->p_cowcnt = 0;
		pp->p_slckcnt = 0;

		/*
		 * Initialize the page lock as unlocked, since nobody
		 * can see or access this page yet.
		 */
		pp->p_selock = 0;

		/*
		 * Initialize IO lock
		 */
		page_iolock_init(pp);

		/*
		 * initialize other fields in the page_t
		 */
		PP_SETFREE(pp);
		page_clr_all_props(pp);
		PP_SETAGED(pp);
		pp->p_offset = (u_offset_t)-1;
		pp->p_next = pp;
		pp->p_prev = pp;

		/*
		 * Simple case: System doesn't support large pages.
		 */
		if (szc == 0) {
			pp->p_szc = 0;
			page_free_at_startup(pp);
			continue;
		}

		/*
		 * Handle unaligned pages, we collect them up onto
		 * the root page until we have a full large page.
		 */
		if (!IS_P2ALIGNED(pnum, large)) {

			/*
			 * If not in a large page,
			 * just free as small page.
			 */
			if (root == NULL) {
				pp->p_szc = 0;
				page_free_at_startup(pp);
				continue;
			}

			/*
			 * Link a constituent page into the large page.
			 */
			pp->p_szc = szc;
			page_list_concat(&root, &pp);

			/*
			 * When large page is fully formed, free it.
			 */
			if (++cnt == large) {
				page_free_large_ctr(cnt);
				page_list_add_pages(root, PG_LIST_ISINIT);
				root = NULL;
				cnt = 0;
			}
			continue;
		}

		/*
		 * At this point we have a page number which
		 * is aligned. We assert that we aren't already
		 * in a different large page.
		 */
		ASSERT(IS_P2ALIGNED(pnum, large));
		ASSERT(root == NULL && cnt == 0);

		/*
		 * If insufficient number of pages left to form
		 * a large page, just free the small page.
		 */
		if (num < large) {
			pp->p_szc = 0;
			page_free_at_startup(pp);
			continue;
		}

		/*
		 * Otherwise start a new large page.
		 */
		pp->p_szc = szc;
		cnt++;
		root = pp;
	}
	ASSERT(root == NULL && cnt == 0);
}

/*
 * Find a page representing the specified [vp, offset].
 * If we find the page but it is intransit coming in,
 * it will have an "exclusive" lock and we wait for
 * the i/o to complete.  A page found on the free list
 * is always reclaimed and then locked.  On success, the page
 * is locked, its data is valid and it isn't on the free
 * list, while a NULL is returned if the page doesn't exist.
 */
page_t *
page_lookup(vnode_t *vp, u_offset_t off, se_t se)
{
	return (page_lookup_create(vp, off, se, NULL, NULL, 0));
}

/*
 * Find a page representing the specified [vp, offset].
 * We either return the one we found or, if passed in,
 * create one with identity of [vp, offset] of the
 * pre-allocated page. If we find existing page but it is
 * intransit coming in, it will have an "exclusive" lock
 * and we wait for the i/o to complete.  A page found on
 * the free list is always reclaimed and then locked.
 * On success, the page is locked, its data is valid and
 * it isn't on the free list, while a NULL is returned
 * if the page doesn't exist and newpp is NULL;
 */
page_t *
page_lookup_create(
	vnode_t *vp,
	u_offset_t off,
	se_t se,
	page_t *newpp,
	spgcnt_t *nrelocp,
	int flags)
{
	page_t		*pp;
	kmutex_t	*phm;
	ulong_t		index;
	uint_t		hash_locked;
	uint_t		es;

	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));
	VM_STAT_ADD(page_lookup_cnt[0]);
	ASSERT(newpp ? PAGE_EXCL(newpp) : 1);

	/*
	 * Acquire the appropriate page hash lock since
	 * we have to search the hash list.  Pages that
	 * hash to this list can't change identity while
	 * this lock is held.
	 */
	hash_locked = 0;
	index = PAGE_HASH_FUNC(vp, off);
	phm = NULL;
top:
	pp = page_hash_search(index, vp, off);
	if (pp != NULL) {
		VM_STAT_ADD(page_lookup_cnt[1]);
		es = (newpp != NULL) ? 1 : 0;
		es |= flags;
		if (!hash_locked) {
			VM_STAT_ADD(page_lookup_cnt[2]);
			if (!page_try_reclaim_lock(pp, se, es)) {
				/*
				 * On a miss, acquire the phm.  Then
				 * next time, page_lock() will be called,
				 * causing a wait if the page is busy.
				 * just looping with page_trylock() would
				 * get pretty boring.
				 */
				VM_STAT_ADD(page_lookup_cnt[3]);
				phm = PAGE_HASH_MUTEX(index);
				mutex_enter(phm);
				hash_locked = 1;
				goto top;
			}
		} else {
			VM_STAT_ADD(page_lookup_cnt[4]);
			if (!page_lock_es(pp, se, phm, P_RECLAIM, es)) {
				VM_STAT_ADD(page_lookup_cnt[5]);
				goto top;
			}
		}

		/*
		 * Since `pp' is locked it can not change identity now.
		 * Reconfirm we locked the correct page.
		 *
		 * Both the p_vnode and p_offset *must* be cast volatile
		 * to force a reload of their values: The page_hash_search
		 * function will have stuffed p_vnode and p_offset into
		 * registers before calling page_trylock(); another thread,
		 * actually holding the hash lock, could have changed the
		 * page's identity in memory, but our registers would not
		 * be changed, fooling the reconfirmation.  If the hash
		 * lock was held during the search, the casting would
		 * not be needed.
		 */
		VM_STAT_ADD(page_lookup_cnt[6]);
		if (((volatile struct vnode *)(pp->p_vnode) != vp) ||
		    ((volatile u_offset_t)(pp->p_offset) != off)) {
			VM_STAT_ADD(page_lookup_cnt[7]);
			if (hash_locked) {
				panic("page_lookup_create: lost page %p",
				    (void *)pp);
				/*NOTREACHED*/
			}
			page_unlock(pp);
			phm = PAGE_HASH_MUTEX(index);
			mutex_enter(phm);
			hash_locked = 1;
			goto top;
		}

		/*
		 * If page_trylock() was called, then pp may still be on
		 * the cachelist (can't be on the free list, it would not
		 * have been found in the search).  If it is on the
		 * cachelist it must be pulled now. To pull the page from
		 * the cachelist, it must be exclusively locked.
		 *
		 * The other big difference between page_trylock() and
		 * page_lock(), is that page_lock() will pull the
		 * page from whatever free list (the cache list in this
		 * case) the page is on.  If page_trylock() was used
		 * above, then we have to do the reclaim ourselves.
		 */
		if ((!hash_locked) && (PP_ISFREE(pp))) {
			ASSERT(PP_ISAGED(pp) == 0);
			VM_STAT_ADD(page_lookup_cnt[8]);

			/*
			 * page_relcaim will insure that we
			 * have this page exclusively
			 */

			if (!page_reclaim(pp, NULL)) {
				/*
				 * Page_reclaim dropped whatever lock
				 * we held.
				 */
				VM_STAT_ADD(page_lookup_cnt[9]);
				phm = PAGE_HASH_MUTEX(index);
				mutex_enter(phm);
				hash_locked = 1;
				goto top;
			} else if (se == SE_SHARED && newpp == NULL) {
				VM_STAT_ADD(page_lookup_cnt[10]);
				page_downgrade(pp);
			}
		}

		if (hash_locked) {
			mutex_exit(phm);
		}

		if (newpp != NULL && pp->p_szc < newpp->p_szc &&
		    PAGE_EXCL(pp) && nrelocp != NULL) {
			ASSERT(nrelocp != NULL);
			(void) page_relocate(&pp, &newpp, 1, 1, nrelocp,
			    NULL);
			if (*nrelocp > 0) {
				VM_STAT_COND_ADD(*nrelocp == 1,
				    page_lookup_cnt[11]);
				VM_STAT_COND_ADD(*nrelocp > 1,
				    page_lookup_cnt[12]);
				pp = newpp;
				se = SE_EXCL;
			} else {
				if (se == SE_SHARED) {
					page_downgrade(pp);
				}
				VM_STAT_ADD(page_lookup_cnt[13]);
			}
		} else if (newpp != NULL && nrelocp != NULL) {
			if (PAGE_EXCL(pp) && se == SE_SHARED) {
				page_downgrade(pp);
			}
			VM_STAT_COND_ADD(pp->p_szc < newpp->p_szc,
			    page_lookup_cnt[14]);
			VM_STAT_COND_ADD(pp->p_szc == newpp->p_szc,
			    page_lookup_cnt[15]);
			VM_STAT_COND_ADD(pp->p_szc > newpp->p_szc,
			    page_lookup_cnt[16]);
		} else if (newpp != NULL && PAGE_EXCL(pp)) {
			se = SE_EXCL;
		}
	} else if (!hash_locked) {
		VM_STAT_ADD(page_lookup_cnt[17]);
		phm = PAGE_HASH_MUTEX(index);
		mutex_enter(phm);
		hash_locked = 1;
		goto top;
	} else if (newpp != NULL) {
		/*
		 * If we have a preallocated page then
		 * insert it now and basically behave like
		 * page_create.
		 */
		VM_STAT_ADD(page_lookup_cnt[18]);
		/*
		 * Since we hold the page hash mutex and
		 * just searched for this page, page_hashin
		 * had better not fail.  If it does, that
		 * means some thread did not follow the
		 * page hash mutex rules.  Panic now and
		 * get it over with.  As usual, go down
		 * holding all the locks.
		 */
		ASSERT(MUTEX_HELD(phm));
		if (!page_hashin(newpp, vp, off, phm)) {
			ASSERT(MUTEX_HELD(phm));
			panic("page_lookup_create: hashin failed %p %p %llx %p",
			    (void *)newpp, (void *)vp, off, (void *)phm);
			/*NOTREACHED*/
		}
		ASSERT(MUTEX_HELD(phm));
		mutex_exit(phm);
		phm = NULL;
		page_set_props(newpp, P_REF);
		page_io_lock(newpp);
		pp = newpp;
		se = SE_EXCL;
	} else {
		VM_STAT_ADD(page_lookup_cnt[19]);
		mutex_exit(phm);
	}

	ASSERT(pp ? PAGE_LOCKED_SE(pp, se) : 1);

	ASSERT(pp ? ((PP_ISFREE(pp) == 0) && (PP_ISAGED(pp) == 0)) : 1);

	return (pp);
}

/*
 * Search the hash list for the page representing the
 * specified [vp, offset] and return it locked.  Skip
 * free pages and pages that cannot be locked as requested.
 * Used while attempting to kluster pages.
 */
page_t *
page_lookup_nowait(vnode_t *vp, u_offset_t off, se_t se)
{
	page_t		*pp;
	kmutex_t	*phm;
	ulong_t		index;
	uint_t		locked;

	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));
	VM_STAT_ADD(page_lookup_nowait_cnt[0]);

	index = PAGE_HASH_FUNC(vp, off);
	pp = page_hash_search(index, vp, off);
	locked = 0;
	if (pp == NULL) {
top:
		VM_STAT_ADD(page_lookup_nowait_cnt[1]);
		locked = 1;
		phm = PAGE_HASH_MUTEX(index);
		mutex_enter(phm);
		pp = page_hash_search(index, vp, off);
	}

	if (pp == NULL || PP_ISFREE(pp)) {
		VM_STAT_ADD(page_lookup_nowait_cnt[2]);
		pp = NULL;
	} else {
		if (!page_trylock(pp, se)) {
			VM_STAT_ADD(page_lookup_nowait_cnt[3]);
			pp = NULL;
		} else {
			VM_STAT_ADD(page_lookup_nowait_cnt[4]);
			/*
			 * See the comment in page_lookup()
			 */
			if (((volatile struct vnode *)(pp->p_vnode) != vp) ||
			    ((u_offset_t)(pp->p_offset) != off)) {
				VM_STAT_ADD(page_lookup_nowait_cnt[5]);
				if (locked) {
					panic("page_lookup_nowait %p",
					    (void *)pp);
					/*NOTREACHED*/
				}
				page_unlock(pp);
				goto top;
			}
			if (PP_ISFREE(pp)) {
				VM_STAT_ADD(page_lookup_nowait_cnt[6]);
				page_unlock(pp);
				pp = NULL;
			}
		}
	}
	if (locked) {
		VM_STAT_ADD(page_lookup_nowait_cnt[7]);
		mutex_exit(phm);
	}

	ASSERT(pp ? PAGE_LOCKED_SE(pp, se) : 1);

	return (pp);
}

/*
 * Search the hash list for a page with the specified [vp, off]
 * that is known to exist and is already locked.  This routine
 * is typically used by segment SOFTUNLOCK routines.
 */
page_t *
page_find(vnode_t *vp, u_offset_t off)
{
	page_t		*pp;
	kmutex_t	*phm;
	ulong_t		index;

	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));
	VM_STAT_ADD(page_find_cnt);

	index = PAGE_HASH_FUNC(vp, off);
	phm = PAGE_HASH_MUTEX(index);

	mutex_enter(phm);
	pp = page_hash_search(index, vp, off);
	mutex_exit(phm);

	ASSERT(pp == NULL || PAGE_LOCKED(pp) || panicstr);
	return (pp);
}

/*
 * Determine whether a page with the specified [vp, off]
 * currently exists in the system.  Obviously this should
 * only be considered as a hint since nothing prevents the
 * page from disappearing or appearing immediately after
 * the return from this routine. Subsequently, we don't
 * even bother to lock the list.
 */
page_t *
page_exists(vnode_t *vp, u_offset_t off)
{
	ulong_t		index;

	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));
	VM_STAT_ADD(page_exists_cnt);

	index = PAGE_HASH_FUNC(vp, off);

	return (page_hash_search(index, vp, off));
}

/*
 * Determine if physically contiguous pages exist for [vp, off] - [vp, off +
 * page_size(szc)) range.  if they exist and ppa is not NULL fill ppa array
 * with these pages locked SHARED. If necessary reclaim pages from
 * freelist. Return 1 if contiguous pages exist and 0 otherwise.
 *
 * If we fail to lock pages still return 1 if pages exist and contiguous.
 * But in this case return value is just a hint. ppa array won't be filled.
 * Caller should initialize ppa[0] as NULL to distinguish return value.
 *
 * Returns 0 if pages don't exist or not physically contiguous.
 *
 * This routine doesn't work for anonymous(swapfs) pages.
 */
int
page_exists_physcontig(vnode_t *vp, u_offset_t off, uint_t szc, page_t *ppa[])
{
	pgcnt_t pages;
	pfn_t pfn;
	page_t *rootpp;
	pgcnt_t i;
	pgcnt_t j;
	u_offset_t save_off = off;
	ulong_t index;
	kmutex_t *phm;
	page_t *pp;
	uint_t pszc;
	int loopcnt = 0;

	ASSERT(szc != 0);
	ASSERT(vp != NULL);
	ASSERT(!IS_SWAPFSVP(vp));
	ASSERT(!VN_ISKAS(vp));

again:
	if (++loopcnt > 3) {
		VM_STAT_ADD(page_exphcontg[0]);
		return (0);
	}

	index = PAGE_HASH_FUNC(vp, off);
	phm = PAGE_HASH_MUTEX(index);

	mutex_enter(phm);
	pp = page_hash_search(index, vp, off);
	mutex_exit(phm);

	VM_STAT_ADD(page_exphcontg[1]);

	if (pp == NULL) {
		VM_STAT_ADD(page_exphcontg[2]);
		return (0);
	}

	pages = page_get_pagecnt(szc);
	rootpp = pp;
	pfn = rootpp->p_pagenum;

	if ((pszc = pp->p_szc) >= szc && ppa != NULL) {
		VM_STAT_ADD(page_exphcontg[3]);
		if (!page_trylock(pp, SE_SHARED)) {
			VM_STAT_ADD(page_exphcontg[4]);
			return (1);
		}
		/*
		 * Also check whether p_pagenum was modified by DR.
		 */
		if (pp->p_szc != pszc || pp->p_vnode != vp ||
		    pp->p_offset != off || pp->p_pagenum != pfn) {
			VM_STAT_ADD(page_exphcontg[5]);
			page_unlock(pp);
			off = save_off;
			goto again;
		}
		/*
		 * szc was non zero and vnode and offset matched after we
		 * locked the page it means it can't become free on us.
		 */
		ASSERT(!PP_ISFREE(pp));
		if (!IS_P2ALIGNED(pfn, pages)) {
			page_unlock(pp);
			return (0);
		}
		ppa[0] = pp;
		pp++;
		off += PAGESIZE;
		pfn++;
		for (i = 1; i < pages; i++, pp++, off += PAGESIZE, pfn++) {
			if (!page_trylock(pp, SE_SHARED)) {
				VM_STAT_ADD(page_exphcontg[6]);
				pp--;
				while (i-- > 0) {
					page_unlock(pp);
					pp--;
				}
				ppa[0] = NULL;
				return (1);
			}
			if (pp->p_szc != pszc) {
				VM_STAT_ADD(page_exphcontg[7]);
				page_unlock(pp);
				pp--;
				while (i-- > 0) {
					page_unlock(pp);
					pp--;
				}
				ppa[0] = NULL;
				off = save_off;
				goto again;
			}
			/*
			 * szc the same as for previous already locked pages
			 * with right identity. Since this page had correct
			 * szc after we locked it can't get freed or destroyed
			 * and therefore must have the expected identity.
			 */
			ASSERT(!PP_ISFREE(pp));
			if (pp->p_vnode != vp ||
			    pp->p_offset != off) {
				panic("page_exists_physcontig: "
				    "large page identity doesn't match");
			}
			ppa[i] = pp;
			ASSERT(pp->p_pagenum == pfn);
		}
		VM_STAT_ADD(page_exphcontg[8]);
		ppa[pages] = NULL;
		return (1);
	} else if (pszc >= szc) {
		VM_STAT_ADD(page_exphcontg[9]);
		if (!IS_P2ALIGNED(pfn, pages)) {
			return (0);
		}
		return (1);
	}

	if (!IS_P2ALIGNED(pfn, pages)) {
		VM_STAT_ADD(page_exphcontg[10]);
		return (0);
	}

	if (page_numtomemseg_nolock(pfn) !=
	    page_numtomemseg_nolock(pfn + pages - 1)) {
		VM_STAT_ADD(page_exphcontg[11]);
		return (0);
	}

	/*
	 * We loop up 4 times across pages to promote page size.
	 * We're extra cautious to promote page size atomically with respect
	 * to everybody else.  But we can probably optimize into 1 loop if
	 * this becomes an issue.
	 */

	for (i = 0; i < pages; i++, pp++, off += PAGESIZE, pfn++) {
		if (!page_trylock(pp, SE_EXCL)) {
			VM_STAT_ADD(page_exphcontg[12]);
			break;
		}
		/*
		 * Check whether p_pagenum was modified by DR.
		 */
		if (pp->p_pagenum != pfn) {
			page_unlock(pp);
			break;
		}
		if (pp->p_vnode != vp ||
		    pp->p_offset != off) {
			VM_STAT_ADD(page_exphcontg[13]);
			page_unlock(pp);
			break;
		}
		if (pp->p_szc >= szc) {
			ASSERT(i == 0);
			page_unlock(pp);
			off = save_off;
			goto again;
		}
	}

	if (i != pages) {
		VM_STAT_ADD(page_exphcontg[14]);
		--pp;
		while (i-- > 0) {
			page_unlock(pp);
			--pp;
		}
		return (0);
	}

	pp = rootpp;
	for (i = 0; i < pages; i++, pp++) {
		if (PP_ISFREE(pp)) {
			VM_STAT_ADD(page_exphcontg[15]);
			ASSERT(!PP_ISAGED(pp));
			ASSERT(pp->p_szc == 0);
			if (!page_reclaim(pp, NULL)) {
				break;
			}
		} else {
			ASSERT(pp->p_szc < szc);
			VM_STAT_ADD(page_exphcontg[16]);
			(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
		}
	}
	if (i < pages) {
		VM_STAT_ADD(page_exphcontg[17]);
		/*
		 * page_reclaim failed because we were out of memory.
		 * drop the rest of the locks and return because this page
		 * must be already reallocated anyway.
		 */
		pp = rootpp;
		for (j = 0; j < pages; j++, pp++) {
			if (j != i) {
				page_unlock(pp);
			}
		}
		return (0);
	}

	off = save_off;
	pp = rootpp;
	for (i = 0; i < pages; i++, pp++, off += PAGESIZE) {
		ASSERT(PAGE_EXCL(pp));
		ASSERT(!PP_ISFREE(pp));
		ASSERT(!hat_page_is_mapped(pp));
		ASSERT(pp->p_vnode == vp);
		ASSERT(pp->p_offset == off);
		pp->p_szc = szc;
	}
	pp = rootpp;
	for (i = 0; i < pages; i++, pp++) {
		if (ppa == NULL) {
			page_unlock(pp);
		} else {
			ppa[i] = pp;
			page_downgrade(ppa[i]);
		}
	}
	if (ppa != NULL) {
		ppa[pages] = NULL;
	}
	VM_STAT_ADD(page_exphcontg[18]);
	ASSERT(vp->v_pages != NULL);
	return (1);
}

/*
 * Determine whether a page with the specified [vp, off]
 * currently exists in the system and if so return its
 * size code. Obviously this should only be considered as
 * a hint since nothing prevents the page from disappearing
 * or appearing immediately after the return from this routine.
 */
int
page_exists_forreal(vnode_t *vp, u_offset_t off, uint_t *szc)
{
	page_t		*pp;
	kmutex_t	*phm;
	ulong_t		index;
	int		rc = 0;

	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));
	ASSERT(szc != NULL);
	VM_STAT_ADD(page_exists_forreal_cnt);

	index = PAGE_HASH_FUNC(vp, off);
	phm = PAGE_HASH_MUTEX(index);

	mutex_enter(phm);
	pp = page_hash_search(index, vp, off);
	if (pp != NULL) {
		*szc = pp->p_szc;
		rc = 1;
	}
	mutex_exit(phm);
	return (rc);
}

/* wakeup threads waiting for pages in page_create_get_something() */
void
wakeup_pcgs(void)
{
	if (!CV_HAS_WAITERS(&pcgs_cv))
		return;
	cv_broadcast(&pcgs_cv);
}

/*
 * 'freemem' is used all over the kernel as an indication of how many
 * pages are free (either on the cache list or on the free page list)
 * in the system.  In very few places is a really accurate 'freemem'
 * needed.  To avoid contention of the lock protecting a the
 * single freemem, it was spread out into NCPU buckets.  Set_freemem
 * sets freemem to the total of all NCPU buckets.  It is called from
 * clock() on each TICK.
 */
void
set_freemem()
{
	struct pcf	*p;
	ulong_t		t;
	uint_t		i;

	t = 0;
	p = pcf;
	for (i = 0;  i < pcf_fanout; i++) {
		t += p->pcf_count;
		p++;
	}
	freemem = t;

	/*
	 * Don't worry about grabbing mutex.  It's not that
	 * critical if we miss a tick or two.  This is
	 * where we wakeup possible delayers in
	 * page_create_get_something().
	 */
	wakeup_pcgs();
}

ulong_t
get_freemem()
{
	struct pcf	*p;
	ulong_t		t;
	uint_t		i;

	t = 0;
	p = pcf;
	for (i = 0; i < pcf_fanout; i++) {
		t += p->pcf_count;
		p++;
	}
	/*
	 * We just calculated it, might as well set it.
	 */
	freemem = t;
	return (t);
}

/*
 * Acquire all of the page cache & free (pcf) locks.
 */
void
pcf_acquire_all()
{
	struct pcf	*p;
	uint_t		i;

	p = pcf;
	for (i = 0; i < pcf_fanout; i++) {
		mutex_enter(&p->pcf_lock);
		p++;
	}
}

/*
 * Release all the pcf_locks.
 */
void
pcf_release_all()
{
	struct pcf	*p;
	uint_t		i;

	p = pcf;
	for (i = 0; i < pcf_fanout; i++) {
		mutex_exit(&p->pcf_lock);
		p++;
	}
}

/*
 * Inform the VM system that we need some pages freed up.
 * Calls must be symmetric, e.g.:
 *
 *	page_needfree(100);
 *	wait a bit;
 *	page_needfree(-100);
 */
void
page_needfree(spgcnt_t npages)
{
	mutex_enter(&new_freemem_lock);
	needfree += npages;
	mutex_exit(&new_freemem_lock);
}

/*
 * Throttle for page_create(): try to prevent freemem from dropping
 * below throttlefree.  We can't provide a 100% guarantee because
 * KM_NOSLEEP allocations, page_reclaim(), and various other things
 * nibble away at the freelist.  However, we can block all PG_WAIT
 * allocations until memory becomes available.  The motivation is
 * that several things can fall apart when there's no free memory:
 *
 * (1) If pageout() needs memory to push a page, the system deadlocks.
 *
 * (2) By (broken) specification, timeout(9F) can neither fail nor
 *     block, so it has no choice but to panic the system if it
 *     cannot allocate a callout structure.
 *
 * (3) Like timeout(), ddi_set_callback() cannot fail and cannot block;
 *     it panics if it cannot allocate a callback structure.
 *
 * (4) Untold numbers of third-party drivers have not yet been hardened
 *     against KM_NOSLEEP and/or allocb() failures; they simply assume
 *     success and panic the system with a data fault on failure.
 *     (The long-term solution to this particular problem is to ship
 *     hostile fault-injecting DEBUG kernels with the DDK.)
 *
 * It is theoretically impossible to guarantee success of non-blocking
 * allocations, but in practice, this throttle is very hard to break.
 */
static int
page_create_throttle(pgcnt_t npages, int flags)
{
	ulong_t	fm;
	uint_t	i;
	pgcnt_t tf;	/* effective value of throttlefree */

	/*
	 * Normal priority allocations.
	 */
	if ((flags & (PG_WAIT | PG_NORMALPRI)) == PG_NORMALPRI) {
		ASSERT(!(flags & (PG_PANIC | PG_PUSHPAGE)));
		return (freemem >= npages + throttlefree);
	}

	/*
	 * Never deny pages when:
	 * - it's a thread that cannot block [NOMEMWAIT()]
	 * - the allocation cannot block and must not fail
	 * - the allocation cannot block and is pageout dispensated
	 */
	if (NOMEMWAIT() ||
	    ((flags & (PG_WAIT | PG_PANIC)) == PG_PANIC) ||
	    ((flags & (PG_WAIT | PG_PUSHPAGE)) == PG_PUSHPAGE))
		return (1);

	/*
	 * If the allocation can't block, we look favorably upon it
	 * unless we're below pageout_reserve.  In that case we fail
	 * the allocation because we want to make sure there are a few
	 * pages available for pageout.
	 */
	if ((flags & PG_WAIT) == 0)
		return (freemem >= npages + pageout_reserve);

	/* Calculate the effective throttlefree value */
	tf = throttlefree -
	    ((flags & PG_PUSHPAGE) ? pageout_reserve : 0);

	cv_signal(&proc_pageout->p_cv);

	for (;;) {
		fm = 0;
		pcf_acquire_all();
		mutex_enter(&new_freemem_lock);
		for (i = 0; i < pcf_fanout; i++) {
			fm += pcf[i].pcf_count;
			pcf[i].pcf_wait++;
			mutex_exit(&pcf[i].pcf_lock);
		}
		freemem = fm;
		if (freemem >= npages + tf) {
			mutex_exit(&new_freemem_lock);
			break;
		}
		needfree += npages;
		freemem_wait++;
		cv_wait(&freemem_cv, &new_freemem_lock);
		freemem_wait--;
		needfree -= npages;
		mutex_exit(&new_freemem_lock);
	}
	return (1);
}

/*
 * page_create_wait() is called to either coalesce pages from the
 * different pcf buckets or to wait because there simply are not
 * enough pages to satisfy the caller's request.
 *
 * Sadly, this is called from platform/vm/vm_machdep.c
 */
int
page_create_wait(pgcnt_t npages, uint_t flags)
{
	pgcnt_t		total;
	uint_t		i;
	struct pcf	*p;

	/*
	 * Wait until there are enough free pages to satisfy our
	 * entire request.
	 * We set needfree += npages before prodding pageout, to make sure
	 * it does real work when npages > lotsfree > freemem.
	 */
	VM_STAT_ADD(page_create_not_enough);

	ASSERT(!kcage_on ? !(flags & PG_NORELOC) : 1);
checkagain:
	if ((flags & PG_NORELOC) &&
	    kcage_freemem < kcage_throttlefree + npages)
		(void) kcage_create_throttle(npages, flags);

	if (freemem < npages + throttlefree)
		if (!page_create_throttle(npages, flags))
			return (0);

	if (pcf_decrement_bucket(npages) ||
	    pcf_decrement_multiple(&total, npages, 0))
		return (1);

	/*
	 * All of the pcf locks are held, there are not enough pages
	 * to satisfy the request (npages < total).
	 * Be sure to acquire the new_freemem_lock before dropping
	 * the pcf locks.  This prevents dropping wakeups in page_free().
	 * The order is always pcf_lock then new_freemem_lock.
	 *
	 * Since we hold all the pcf locks, it is a good time to set freemem.
	 *
	 * If the caller does not want to wait, return now.
	 * Else turn the pageout daemon loose to find something
	 * and wait till it does.
	 *
	 */
	freemem = total;

	if ((flags & PG_WAIT) == 0) {
		pcf_release_all();

		TRACE_2(TR_FAC_VM, TR_PAGE_CREATE_NOMEM,
		"page_create_nomem:npages %ld freemem %ld", npages, freemem);
		return (0);
	}

	ASSERT(proc_pageout != NULL);
	cv_signal(&proc_pageout->p_cv);

	TRACE_2(TR_FAC_VM, TR_PAGE_CREATE_SLEEP_START,
	    "page_create_sleep_start: freemem %ld needfree %ld",
	    freemem, needfree);

	/*
	 * We are going to wait.
	 * We currently hold all of the pcf_locks,
	 * get the new_freemem_lock (it protects freemem_wait),
	 * before dropping the pcf_locks.
	 */
	mutex_enter(&new_freemem_lock);

	p = pcf;
	for (i = 0; i < pcf_fanout; i++) {
		p->pcf_wait++;
		mutex_exit(&p->pcf_lock);
		p++;
	}

	needfree += npages;
	freemem_wait++;

	cv_wait(&freemem_cv, &new_freemem_lock);

	freemem_wait--;
	needfree -= npages;

	mutex_exit(&new_freemem_lock);

	TRACE_2(TR_FAC_VM, TR_PAGE_CREATE_SLEEP_END,
	    "page_create_sleep_end: freemem %ld needfree %ld",
	    freemem, needfree);

	VM_STAT_ADD(page_create_not_enough_again);
	goto checkagain;
}
/*
 * A routine to do the opposite of page_create_wait().
 */
void
page_create_putback(spgcnt_t npages)
{
	struct pcf	*p;
	pgcnt_t		lump;
	uint_t		*which;

	/*
	 * When a contiguous lump is broken up, we have to
	 * deal with lots of pages (min 64) so lets spread
	 * the wealth around.
	 */
	lump = roundup(npages, pcf_fanout) / pcf_fanout;
	freemem += npages;

	for (p = pcf; (npages > 0) && (p < &pcf[pcf_fanout]); p++) {
		which = &p->pcf_count;

		mutex_enter(&p->pcf_lock);

		if (p->pcf_block) {
			which = &p->pcf_reserve;
		}

		if (lump < npages) {
			*which += (uint_t)lump;
			npages -= lump;
		} else {
			*which += (uint_t)npages;
			npages = 0;
		}

		if (p->pcf_wait) {
			mutex_enter(&new_freemem_lock);
			/*
			 * Check to see if some other thread
			 * is actually waiting.  Another bucket
			 * may have woken it up by now.  If there
			 * are no waiters, then set our pcf_wait
			 * count to zero to avoid coming in here
			 * next time.
			 */
			if (freemem_wait) {
				if (npages > 1) {
					cv_broadcast(&freemem_cv);
				} else {
					cv_signal(&freemem_cv);
				}
				p->pcf_wait--;
			} else {
				p->pcf_wait = 0;
			}
			mutex_exit(&new_freemem_lock);
		}
		mutex_exit(&p->pcf_lock);
	}
	ASSERT(npages == 0);
}

/*
 * A helper routine for page_create_get_something.
 * The indenting got to deep down there.
 * Unblock the pcf counters.  Any pages freed after
 * pcf_block got set are moved to pcf_count and
 * wakeups (cv_broadcast() or cv_signal()) are done as needed.
 */
static void
pcgs_unblock(void)
{
	int		i;
	struct pcf	*p;

	/* Update freemem while we're here. */
	freemem = 0;
	p = pcf;
	for (i = 0; i < pcf_fanout; i++) {
		mutex_enter(&p->pcf_lock);
		ASSERT(p->pcf_count == 0);
		p->pcf_count = p->pcf_reserve;
		p->pcf_block = 0;
		freemem += p->pcf_count;
		if (p->pcf_wait) {
			mutex_enter(&new_freemem_lock);
			if (freemem_wait) {
				if (p->pcf_reserve > 1) {
					cv_broadcast(&freemem_cv);
					p->pcf_wait = 0;
				} else {
					cv_signal(&freemem_cv);
					p->pcf_wait--;
				}
			} else {
				p->pcf_wait = 0;
			}
			mutex_exit(&new_freemem_lock);
		}
		p->pcf_reserve = 0;
		mutex_exit(&p->pcf_lock);
		p++;
	}
}

/*
 * Called from page_create_va() when both the cache and free lists
 * have been checked once.
 *
 * Either returns a page or panics since the accounting was done
 * way before we got here.
 *
 * We don't come here often, so leave the accounting on permanently.
 */

#define	MAX_PCGS	100

#ifdef	DEBUG
#define	PCGS_TRIES	100
#else	/* DEBUG */
#define	PCGS_TRIES	10
#endif	/* DEBUG */

#ifdef	VM_STATS
uint_t	pcgs_counts[PCGS_TRIES];
uint_t	pcgs_too_many;
uint_t	pcgs_entered;
uint_t	pcgs_entered_noreloc;
uint_t	pcgs_locked;
uint_t	pcgs_cagelocked;
#endif	/* VM_STATS */

static page_t *
page_create_get_something(vnode_t *vp, u_offset_t off, struct seg *seg,
    caddr_t vaddr, uint_t flags)
{
	uint_t		count;
	page_t		*pp;
	uint_t		locked, i;
	struct	pcf	*p;
	lgrp_t		*lgrp;
	int		cagelocked = 0;

	VM_STAT_ADD(pcgs_entered);

	/*
	 * Tap any reserve freelists: if we fail now, we'll die
	 * since the page(s) we're looking for have already been
	 * accounted for.
	 */
	flags |= PG_PANIC;

	if ((flags & PG_NORELOC) != 0) {
		VM_STAT_ADD(pcgs_entered_noreloc);
		/*
		 * Requests for free pages from critical threads
		 * such as pageout still won't throttle here, but
		 * we must try again, to give the cageout thread
		 * another chance to catch up. Since we already
		 * accounted for the pages, we had better get them
		 * this time.
		 *
		 * N.B. All non-critical threads acquire the pcgs_cagelock
		 * to serialize access to the freelists. This implements a
		 * turnstile-type synchornization to avoid starvation of
		 * critical requests for PG_NORELOC memory by non-critical
		 * threads: all non-critical threads must acquire a 'ticket'
		 * before passing through, which entails making sure
		 * kcage_freemem won't fall below minfree prior to grabbing
		 * pages from the freelists.
		 */
		if (kcage_create_throttle(1, flags) == KCT_NONCRIT) {
			mutex_enter(&pcgs_cagelock);
			cagelocked = 1;
			VM_STAT_ADD(pcgs_cagelocked);
		}
	}

	/*
	 * Time to get serious.
	 * We failed to get a `correctly colored' page from both the
	 * free and cache lists.
	 * We escalate in stage.
	 *
	 * First try both lists without worring about color.
	 *
	 * Then, grab all page accounting locks (ie. pcf[]) and
	 * steal any pages that they have and set the pcf_block flag to
	 * stop deletions from the lists.  This will help because
	 * a page can get added to the free list while we are looking
	 * at the cache list, then another page could be added to the cache
	 * list allowing the page on the free list to be removed as we
	 * move from looking at the cache list to the free list. This
	 * could happen over and over. We would never find the page
	 * we have accounted for.
	 *
	 * Noreloc pages are a subset of the global (relocatable) page pool.
	 * They are not tracked separately in the pcf bins, so it is
	 * impossible to know when doing pcf accounting if the available
	 * page(s) are noreloc pages or not. When looking for a noreloc page
	 * it is quite easy to end up here even if the global (relocatable)
	 * page pool has plenty of free pages but the noreloc pool is empty.
	 *
	 * When the noreloc pool is empty (or low), additional noreloc pages
	 * are created by converting pages from the global page pool. This
	 * process will stall during pcf accounting if the pcf bins are
	 * already locked. Such is the case when a noreloc allocation is
	 * looping here in page_create_get_something waiting for more noreloc
	 * pages to appear.
	 *
	 * Short of adding a new field to the pcf bins to accurately track
	 * the number of free noreloc pages, we instead do not grab the
	 * pcgs_lock, do not set the pcf blocks and do not timeout when
	 * allocating a noreloc page. This allows noreloc allocations to
	 * loop without blocking global page pool allocations.
	 *
	 * NOTE: the behaviour of page_create_get_something has not changed
	 * for the case of global page pool allocations.
	 */

	flags &= ~PG_MATCH_COLOR;
	locked = 0;
#if defined(__i386) || defined(__amd64)
	flags = page_create_update_flags_x86(flags);
#endif

	lgrp = lgrp_mem_choose(seg, vaddr, PAGESIZE);

	for (count = 0; kcage_on || count < MAX_PCGS; count++) {
		pp = page_get_freelist(vp, off, seg, vaddr, PAGESIZE,
		    flags, lgrp);
		if (pp == NULL) {
			pp = page_get_cachelist(vp, off, seg, vaddr,
			    flags, lgrp);
		}
		if (pp == NULL) {
			/*
			 * Serialize.  Don't fight with other pcgs().
			 */
			if (!locked && (!kcage_on || !(flags & PG_NORELOC))) {
				mutex_enter(&pcgs_lock);
				VM_STAT_ADD(pcgs_locked);
				locked = 1;
				p = pcf;
				for (i = 0; i < pcf_fanout; i++) {
					mutex_enter(&p->pcf_lock);
					ASSERT(p->pcf_block == 0);
					p->pcf_block = 1;
					p->pcf_reserve = p->pcf_count;
					p->pcf_count = 0;
					mutex_exit(&p->pcf_lock);
					p++;
				}
				freemem = 0;
			}

			if (count) {
				/*
				 * Since page_free() puts pages on
				 * a list then accounts for it, we
				 * just have to wait for page_free()
				 * to unlock any page it was working
				 * with. The page_lock()-page_reclaim()
				 * path falls in the same boat.
				 *
				 * We don't need to check on the
				 * PG_WAIT flag, we have already
				 * accounted for the page we are
				 * looking for in page_create_va().
				 *
				 * We just wait a moment to let any
				 * locked pages on the lists free up,
				 * then continue around and try again.
				 *
				 * Will be awakened by set_freemem().
				 */
				mutex_enter(&pcgs_wait_lock);
				cv_wait(&pcgs_cv, &pcgs_wait_lock);
				mutex_exit(&pcgs_wait_lock);
			}
		} else {
#ifdef VM_STATS
			if (count >= PCGS_TRIES) {
				VM_STAT_ADD(pcgs_too_many);
			} else {
				VM_STAT_ADD(pcgs_counts[count]);
			}
#endif
			if (locked) {
				pcgs_unblock();
				mutex_exit(&pcgs_lock);
			}
			if (cagelocked)
				mutex_exit(&pcgs_cagelock);
			return (pp);
		}
	}
	/*
	 * we go down holding the pcf locks.
	 */
	panic("no %spage found %d",
	    ((flags & PG_NORELOC) ? "non-reloc " : ""), count);
	/*NOTREACHED*/
}

/*
 * Create enough pages for "bytes" worth of data starting at
 * "off" in "vp".
 *
 *	Where flag must be one of:
 *
 *		PG_EXCL:	Exclusive create (fail if any page already
 *				exists in the page cache) which does not
 *				wait for memory to become available.
 *
 *		PG_WAIT:	Non-exclusive create which can wait for
 *				memory to become available.
 *
 *		PG_PHYSCONTIG:	Allocate physically contiguous pages.
 *				(Not Supported)
 *
 * A doubly linked list of pages is returned to the caller.  Each page
 * on the list has the "exclusive" (p_selock) lock and "iolock" (p_iolock)
 * lock.
 *
 * Unable to change the parameters to page_create() in a minor release,
 * we renamed page_create() to page_create_va(), changed all known calls
 * from page_create() to page_create_va(), and created this wrapper.
 *
 * Upon a major release, we should break compatibility by deleting this
 * wrapper, and replacing all the strings "page_create_va", with "page_create".
 *
 * NOTE: There is a copy of this interface as page_create_io() in
 *	 i86/vm/vm_machdep.c. Any bugs fixed here should be applied
 *	 there.
 */
page_t *
page_create(vnode_t *vp, u_offset_t off, size_t bytes, uint_t flags)
{
	caddr_t random_vaddr;
	struct seg kseg;

#ifdef DEBUG
	cmn_err(CE_WARN, "Using deprecated interface page_create: caller %p",
	    (void *)caller());
#endif

	random_vaddr = (caddr_t)(((uintptr_t)vp >> 7) ^
	    (uintptr_t)(off >> PAGESHIFT));
	kseg.s_as = &kas;

	return (page_create_va(vp, off, bytes, flags, &kseg, random_vaddr));
}

#ifdef DEBUG
uint32_t pg_alloc_pgs_mtbf = 0;
#endif

/*
 * Used for large page support. It will attempt to allocate
 * a large page(s) off the freelist.
 *
 * Returns non zero on failure.
 */
int
page_alloc_pages(struct vnode *vp, struct seg *seg, caddr_t addr,
    page_t **basepp, page_t *ppa[], uint_t szc, int anypgsz, int pgflags)
{
	pgcnt_t		npgs, curnpgs, totpgs;
	size_t		pgsz;
	page_t		*pplist = NULL, *pp;
	int		err = 0;
	lgrp_t		*lgrp;

	ASSERT(szc != 0 && szc <= (page_num_pagesizes() - 1));
	ASSERT(pgflags == 0 || pgflags == PG_LOCAL);

	/*
	 * Check if system heavily prefers local large pages over remote
	 * on systems with multiple lgroups.
	 */
	if (lpg_alloc_prefer == LPAP_LOCAL && nlgrps > 1) {
		pgflags = PG_LOCAL;
	}

	VM_STAT_ADD(alloc_pages[0]);

#ifdef DEBUG
	if (pg_alloc_pgs_mtbf && !(gethrtime() % pg_alloc_pgs_mtbf)) {
		return (ENOMEM);
	}
#endif

	/*
	 * One must be NULL but not both.
	 * And one must be non NULL but not both.
	 */
	ASSERT(basepp != NULL || ppa != NULL);
	ASSERT(basepp == NULL || ppa == NULL);

#if defined(__i386) || defined(__amd64)
	while (page_chk_freelist(szc) == 0) {
		VM_STAT_ADD(alloc_pages[8]);
		if (anypgsz == 0 || --szc == 0)
			return (ENOMEM);
	}
#endif

	pgsz = page_get_pagesize(szc);
	totpgs = curnpgs = npgs = pgsz >> PAGESHIFT;

	ASSERT(((uintptr_t)addr & (pgsz - 1)) == 0);

	(void) page_create_wait(npgs, PG_WAIT);

	while (npgs && szc) {
		lgrp = lgrp_mem_choose(seg, addr, pgsz);
		if (pgflags == PG_LOCAL) {
			pp = page_get_freelist(vp, 0, seg, addr, pgsz,
			    pgflags, lgrp);
			if (pp == NULL) {
				pp = page_get_freelist(vp, 0, seg, addr, pgsz,
				    0, lgrp);
			}
		} else {
			pp = page_get_freelist(vp, 0, seg, addr, pgsz,
			    0, lgrp);
		}
		if (pp != NULL) {
			VM_STAT_ADD(alloc_pages[1]);
			page_list_concat(&pplist, &pp);
			ASSERT(npgs >= curnpgs);
			npgs -= curnpgs;
		} else if (anypgsz) {
			VM_STAT_ADD(alloc_pages[2]);
			szc--;
			pgsz = page_get_pagesize(szc);
			curnpgs = pgsz >> PAGESHIFT;
		} else {
			VM_STAT_ADD(alloc_pages[3]);
			ASSERT(npgs == totpgs);
			page_create_putback(npgs);
			return (ENOMEM);
		}
	}
	if (szc == 0) {
		VM_STAT_ADD(alloc_pages[4]);
		ASSERT(npgs != 0);
		page_create_putback(npgs);
		err = ENOMEM;
	} else if (basepp != NULL) {
		ASSERT(npgs == 0);
		ASSERT(ppa == NULL);
		*basepp = pplist;
	}

	npgs = totpgs - npgs;
	pp = pplist;

	/*
	 * Clear the free and age bits. Also if we were passed in a ppa then
	 * fill it in with all the constituent pages from the large page. But
	 * if we failed to allocate all the pages just free what we got.
	 */
	while (npgs != 0) {
		ASSERT(PP_ISFREE(pp));
		ASSERT(PP_ISAGED(pp));
		if (ppa != NULL || err != 0) {
			if (err == 0) {
				VM_STAT_ADD(alloc_pages[5]);
				PP_CLRFREE(pp);
				PP_CLRAGED(pp);
				page_sub(&pplist, pp);
				*ppa++ = pp;
				npgs--;
			} else {
				VM_STAT_ADD(alloc_pages[6]);
				ASSERT(pp->p_szc != 0);
				curnpgs = page_get_pagecnt(pp->p_szc);
				page_list_break(&pp, &pplist, curnpgs);
				page_list_add_pages(pp, 0);
				page_create_putback(curnpgs);
				ASSERT(npgs >= curnpgs);
				npgs -= curnpgs;
			}
			pp = pplist;
		} else {
			VM_STAT_ADD(alloc_pages[7]);
			PP_CLRFREE(pp);
			PP_CLRAGED(pp);
			pp = pp->p_next;
			npgs--;
		}
	}
	return (err);
}

/*
 * Get a single large page off of the freelists, and set it up for use.
 * Number of bytes requested must be a supported page size.
 *
 * Note that this call may fail even if there is sufficient
 * memory available or PG_WAIT is set, so the caller must
 * be willing to fallback on page_create_va(), block and retry,
 * or fail the requester.
 */
page_t *
page_create_va_large(vnode_t *vp, u_offset_t off, size_t bytes, uint_t flags,
    struct seg *seg, caddr_t vaddr, void *arg)
{
	pgcnt_t		npages;
	page_t		*pp;
	page_t		*rootpp;
	lgrp_t		*lgrp;
	lgrp_id_t	*lgrpid = (lgrp_id_t *)arg;

	ASSERT(vp != NULL);

	ASSERT((flags & ~(PG_EXCL | PG_WAIT |
	    PG_NORELOC | PG_PANIC | PG_PUSHPAGE | PG_NORMALPRI)) == 0);
	/* but no others */

	ASSERT((flags & PG_EXCL) == PG_EXCL);

	npages = btop(bytes);

	if (!kcage_on || panicstr) {
		/*
		 * Cage is OFF, or we are single threaded in
		 * panic, so make everything a RELOC request.
		 */
		flags &= ~PG_NORELOC;
	}

	/*
	 * Make sure there's adequate physical memory available.
	 * Note: PG_WAIT is ignored here.
	 */
	if (freemem <= throttlefree + npages) {
		VM_STAT_ADD(page_create_large_cnt[1]);
		return (NULL);
	}

	/*
	 * If cage is on, dampen draw from cage when available
	 * cage space is low.
	 */
	if ((flags & (PG_NORELOC | PG_WAIT)) ==  (PG_NORELOC | PG_WAIT) &&
	    kcage_freemem < kcage_throttlefree + npages) {

		/*
		 * The cage is on, the caller wants PG_NORELOC
		 * pages and available cage memory is very low.
		 * Call kcage_create_throttle() to attempt to
		 * control demand on the cage.
		 */
		if (kcage_create_throttle(npages, flags) == KCT_FAILURE) {
			VM_STAT_ADD(page_create_large_cnt[2]);
			return (NULL);
		}
	}

	if (!pcf_decrement_bucket(npages) &&
	    !pcf_decrement_multiple(NULL, npages, 1)) {
		VM_STAT_ADD(page_create_large_cnt[4]);
		return (NULL);
	}

	/*
	 * This is where this function behaves fundamentally differently
	 * than page_create_va(); since we're intending to map the page
	 * with a single TTE, we have to get it as a physically contiguous
	 * hardware pagesize chunk.  If we can't, we fail.
	 */
	if (lgrpid != NULL && *lgrpid >= 0 && *lgrpid <= lgrp_alloc_max &&
	    LGRP_EXISTS(lgrp_table[*lgrpid]))
		lgrp = lgrp_table[*lgrpid];
	else
		lgrp = lgrp_mem_choose(seg, vaddr, bytes);

	if ((rootpp = page_get_freelist(&kvp, off, seg, vaddr,
	    bytes, flags & ~PG_MATCH_COLOR, lgrp)) == NULL) {
		page_create_putback(npages);
		VM_STAT_ADD(page_create_large_cnt[5]);
		return (NULL);
	}

	/*
	 * if we got the page with the wrong mtype give it back this is a
	 * workaround for CR 6249718. When CR 6249718 is fixed we never get
	 * inside "if" and the workaround becomes just a nop
	 */
	if (kcage_on && (flags & PG_NORELOC) && !PP_ISNORELOC(rootpp)) {
		page_list_add_pages(rootpp, 0);
		page_create_putback(npages);
		VM_STAT_ADD(page_create_large_cnt[6]);
		return (NULL);
	}

	/*
	 * If satisfying this request has left us with too little
	 * memory, start the wheels turning to get some back.  The
	 * first clause of the test prevents waking up the pageout
	 * daemon in situations where it would decide that there's
	 * nothing to do.
	 */
	if (nscan < desscan && freemem < minfree) {
		TRACE_1(TR_FAC_VM, TR_PAGEOUT_CV_SIGNAL,
		    "pageout_cv_signal:freemem %ld", freemem);
		cv_signal(&proc_pageout->p_cv);
	}

	pp = rootpp;
	while (npages--) {
		ASSERT(PAGE_EXCL(pp));
		ASSERT(pp->p_vnode == NULL);
		ASSERT(!hat_page_is_mapped(pp));
		PP_CLRFREE(pp);
		PP_CLRAGED(pp);
		if (!page_hashin(pp, vp, off, NULL))
			panic("page_create_large: hashin failed: page %p",
			    (void *)pp);
		page_io_lock(pp);
		off += PAGESIZE;
		pp = pp->p_next;
	}

	VM_STAT_ADD(page_create_large_cnt[0]);
	return (rootpp);
}

page_t *
page_create_va(vnode_t *vp, u_offset_t off, size_t bytes, uint_t flags,
    struct seg *seg, caddr_t vaddr)
{
	page_t		*plist = NULL;
	pgcnt_t		npages;
	pgcnt_t		found_on_free = 0;
	pgcnt_t		pages_req;
	page_t		*npp = NULL;
	struct pcf	*p;
	lgrp_t		*lgrp;

	TRACE_4(TR_FAC_VM, TR_PAGE_CREATE_START,
	    "page_create_start:vp %p off %llx bytes %lu flags %x",
	    vp, off, bytes, flags);

	ASSERT(bytes != 0 && vp != NULL);

	if ((flags & PG_EXCL) == 0 && (flags & PG_WAIT) == 0) {
		panic("page_create: invalid flags");
		/*NOTREACHED*/
	}
	ASSERT((flags & ~(PG_EXCL | PG_WAIT |
	    PG_NORELOC | PG_PANIC | PG_PUSHPAGE | PG_NORMALPRI)) == 0);
	    /* but no others */

	pages_req = npages = btopr(bytes);
	/*
	 * Try to see whether request is too large to *ever* be
	 * satisfied, in order to prevent deadlock.  We arbitrarily
	 * decide to limit maximum size requests to max_page_get.
	 */
	if (npages >= max_page_get) {
		if ((flags & PG_WAIT) == 0) {
			TRACE_4(TR_FAC_VM, TR_PAGE_CREATE_TOOBIG,
			    "page_create_toobig:vp %p off %llx npages "
			    "%lu max_page_get %lu",
			    vp, off, npages, max_page_get);
			return (NULL);
		} else {
			cmn_err(CE_WARN,
			    "Request for too much kernel memory "
			    "(%lu bytes), will hang forever", bytes);
			for (;;)
				delay(1000000000);
		}
	}

	if (!kcage_on || panicstr) {
		/*
		 * Cage is OFF, or we are single threaded in
		 * panic, so make everything a RELOC request.
		 */
		flags &= ~PG_NORELOC;
	}

	if (freemem <= throttlefree + npages)
		if (!page_create_throttle(npages, flags))
			return (NULL);

	/*
	 * If cage is on, dampen draw from cage when available
	 * cage space is low.
	 */
	if ((flags & PG_NORELOC) &&
	    kcage_freemem < kcage_throttlefree + npages) {

		/*
		 * The cage is on, the caller wants PG_NORELOC
		 * pages and available cage memory is very low.
		 * Call kcage_create_throttle() to attempt to
		 * control demand on the cage.
		 */
		if (kcage_create_throttle(npages, flags) == KCT_FAILURE)
			return (NULL);
	}

	VM_STAT_ADD(page_create_cnt[0]);

	if (!pcf_decrement_bucket(npages)) {
		/*
		 * Have to look harder.  If npages is greater than
		 * one, then we might have to coalesce the counters.
		 *
		 * Go wait.  We come back having accounted
		 * for the memory.
		 */
		VM_STAT_ADD(page_create_cnt[1]);
		if (!page_create_wait(npages, flags)) {
			VM_STAT_ADD(page_create_cnt[2]);
			return (NULL);
		}
	}

	TRACE_2(TR_FAC_VM, TR_PAGE_CREATE_SUCCESS,
	    "page_create_success:vp %p off %llx", vp, off);

	/*
	 * If satisfying this request has left us with too little
	 * memory, start the wheels turning to get some back.  The
	 * first clause of the test prevents waking up the pageout
	 * daemon in situations where it would decide that there's
	 * nothing to do.
	 */
	if (nscan < desscan && freemem < minfree) {
		TRACE_1(TR_FAC_VM, TR_PAGEOUT_CV_SIGNAL,
		    "pageout_cv_signal:freemem %ld", freemem);
		cv_signal(&proc_pageout->p_cv);
	}

	/*
	 * Loop around collecting the requested number of pages.
	 * Most of the time, we have to `create' a new page. With
	 * this in mind, pull the page off the free list before
	 * getting the hash lock.  This will minimize the hash
	 * lock hold time, nesting, and the like.  If it turns
	 * out we don't need the page, we put it back at the end.
	 */
	while (npages--) {
		page_t		*pp;
		kmutex_t	*phm = NULL;
		ulong_t		index;

		index = PAGE_HASH_FUNC(vp, off);
top:
		ASSERT(phm == NULL);
		ASSERT(index == PAGE_HASH_FUNC(vp, off));
		ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));

		if (npp == NULL) {
			/*
			 * Try to get a page from the freelist (ie,
			 * a page with no [vp, off] tag).  If that
			 * fails, use the cachelist.
			 *
			 * During the first attempt at both the free
			 * and cache lists we try for the correct color.
			 */
			/*
			 * XXXX-how do we deal with virtual indexed
			 * caches and and colors?
			 */
			VM_STAT_ADD(page_create_cnt[4]);
			/*
			 * Get lgroup to allocate next page of shared memory
			 * from and use it to specify where to allocate
			 * the physical memory
			 */
			lgrp = lgrp_mem_choose(seg, vaddr, PAGESIZE);
			npp = page_get_freelist(vp, off, seg, vaddr, PAGESIZE,
			    flags | PG_MATCH_COLOR, lgrp);
			if (npp == NULL) {
				npp = page_get_cachelist(vp, off, seg,
				    vaddr, flags | PG_MATCH_COLOR, lgrp);
				if (npp == NULL) {
					npp = page_create_get_something(vp,
					    off, seg, vaddr,
					    flags & ~PG_MATCH_COLOR);
				}

				if (PP_ISAGED(npp) == 0) {
					/*
					 * Since this page came from the
					 * cachelist, we must destroy the
					 * old vnode association.
					 */
					page_hashout(npp, NULL);
				}
			}
		}

		/*
		 * We own this page!
		 */
		ASSERT(PAGE_EXCL(npp));
		ASSERT(npp->p_vnode == NULL);
		ASSERT(!hat_page_is_mapped(npp));
		PP_CLRFREE(npp);
		PP_CLRAGED(npp);

		/*
		 * Here we have a page in our hot little mits and are
		 * just waiting to stuff it on the appropriate lists.
		 * Get the mutex and check to see if it really does
		 * not exist.
		 */
		phm = PAGE_HASH_MUTEX(index);
		mutex_enter(phm);
		pp = page_hash_search(index, vp, off);
		if (pp == NULL) {
			VM_STAT_ADD(page_create_new);
			pp = npp;
			npp = NULL;
			if (!page_hashin(pp, vp, off, phm)) {
				/*
				 * Since we hold the page hash mutex and
				 * just searched for this page, page_hashin
				 * had better not fail.  If it does, that
				 * means somethread did not follow the
				 * page hash mutex rules.  Panic now and
				 * get it over with.  As usual, go down
				 * holding all the locks.
				 */
				ASSERT(MUTEX_HELD(phm));
				panic("page_create: "
				    "hashin failed %p %p %llx %p",
				    (void *)pp, (void *)vp, off, (void *)phm);
				/*NOTREACHED*/
			}
			ASSERT(MUTEX_HELD(phm));
			mutex_exit(phm);
			phm = NULL;

			/*
			 * Hat layer locking need not be done to set
			 * the following bits since the page is not hashed
			 * and was on the free list (i.e., had no mappings).
			 *
			 * Set the reference bit to protect
			 * against immediate pageout
			 *
			 * XXXmh modify freelist code to set reference
			 * bit so we don't have to do it here.
			 */
			page_set_props(pp, P_REF);
			found_on_free++;
		} else {
			VM_STAT_ADD(page_create_exists);
			if (flags & PG_EXCL) {
				/*
				 * Found an existing page, and the caller
				 * wanted all new pages.  Undo all of the work
				 * we have done.
				 */
				mutex_exit(phm);
				phm = NULL;
				while (plist != NULL) {
					pp = plist;
					page_sub(&plist, pp);
					page_io_unlock(pp);
					/* large pages should not end up here */
					ASSERT(pp->p_szc == 0);
					/*LINTED: constant in conditional ctx*/
					VN_DISPOSE(pp, B_INVAL, 0, kcred);
				}
				VM_STAT_ADD(page_create_found_one);
				goto fail;
			}
			ASSERT(flags & PG_WAIT);
			if (!page_lock(pp, SE_EXCL, phm, P_NO_RECLAIM)) {
				/*
				 * Start all over again if we blocked trying
				 * to lock the page.
				 */
				mutex_exit(phm);
				VM_STAT_ADD(page_create_page_lock_failed);
				phm = NULL;
				goto top;
			}
			mutex_exit(phm);
			phm = NULL;

			if (PP_ISFREE(pp)) {
				ASSERT(PP_ISAGED(pp) == 0);
				VM_STAT_ADD(pagecnt.pc_get_cache);
				page_list_sub(pp, PG_CACHE_LIST);
				PP_CLRFREE(pp);
				found_on_free++;
			}
		}

		/*
		 * Got a page!  It is locked.  Acquire the i/o
		 * lock since we are going to use the p_next and
		 * p_prev fields to link the requested pages together.
		 */
		page_io_lock(pp);
		page_add(&plist, pp);
		plist = plist->p_next;
		off += PAGESIZE;
		vaddr += PAGESIZE;
	}

	ASSERT((flags & PG_EXCL) ? (found_on_free == pages_req) : 1);
fail:
	if (npp != NULL) {
		/*
		 * Did not need this page after all.
		 * Put it back on the free list.
		 */
		VM_STAT_ADD(page_create_putbacks);
		PP_SETFREE(npp);
		PP_SETAGED(npp);
		npp->p_offset = (u_offset_t)-1;
		page_list_add(npp, PG_FREE_LIST | PG_LIST_TAIL);
		page_unlock(npp);

	}

	ASSERT(pages_req >= found_on_free);

	{
		uint_t overshoot = (uint_t)(pages_req - found_on_free);

		if (overshoot) {
			VM_STAT_ADD(page_create_overshoot);
			p = &pcf[PCF_INDEX()];
			mutex_enter(&p->pcf_lock);
			if (p->pcf_block) {
				p->pcf_reserve += overshoot;
			} else {
				p->pcf_count += overshoot;
				if (p->pcf_wait) {
					mutex_enter(&new_freemem_lock);
					if (freemem_wait) {
						cv_signal(&freemem_cv);
						p->pcf_wait--;
					} else {
						p->pcf_wait = 0;
					}
					mutex_exit(&new_freemem_lock);
				}
			}
			mutex_exit(&p->pcf_lock);
			/* freemem is approximate, so this test OK */
			if (!p->pcf_block)
				freemem += overshoot;
		}
	}

	return (plist);
}

/*
 * One or more constituent pages of this large page has been marked
 * toxic. Simply demote the large page to PAGESIZE pages and let
 * page_free() handle it. This routine should only be called by
 * large page free routines (page_free_pages() and page_destroy_pages().
 * All pages are locked SE_EXCL and have already been marked free.
 */
static void
page_free_toxic_pages(page_t *rootpp)
{
	page_t	*tpp;
	pgcnt_t	i, pgcnt = page_get_pagecnt(rootpp->p_szc);
	uint_t	szc = rootpp->p_szc;

	for (i = 0, tpp = rootpp; i < pgcnt; i++, tpp = tpp->p_next) {
		ASSERT(tpp->p_szc == szc);
		ASSERT((PAGE_EXCL(tpp) &&
		    !page_iolock_assert(tpp)) || panicstr);
		tpp->p_szc = 0;
	}

	while (rootpp != NULL) {
		tpp = rootpp;
		page_sub(&rootpp, tpp);
		ASSERT(PP_ISFREE(tpp));
		PP_CLRFREE(tpp);
		page_free(tpp, 1);
	}
}

/*
 * Put page on the "free" list.
 * The free list is really two lists maintained by
 * the PSM of whatever machine we happen to be on.
 */
void
page_free(page_t *pp, int dontneed)
{
	struct pcf	*p;
	uint_t		pcf_index;

	ASSERT((PAGE_EXCL(pp) &&
	    !page_iolock_assert(pp)) || panicstr);

	if (PP_ISFREE(pp)) {
		panic("page_free: page %p is free", (void *)pp);
	}

	if (pp->p_szc != 0) {
		if (pp->p_vnode == NULL || IS_SWAPFSVP(pp->p_vnode) ||
		    PP_ISKAS(pp)) {
			panic("page_free: anon or kernel "
			    "or no vnode large page %p", (void *)pp);
		}
		page_demote_vp_pages(pp);
		ASSERT(pp->p_szc == 0);
	}

	/*
	 * The page_struct_lock need not be acquired to examine these
	 * fields since the page has an "exclusive" lock.
	 */
	if (hat_page_is_mapped(pp) || pp->p_lckcnt != 0 || pp->p_cowcnt != 0 ||
	    pp->p_slckcnt != 0) {
		panic("page_free pp=%p, pfn=%lx, lckcnt=%d, cowcnt=%d "
		    "slckcnt = %d", (void *)pp, page_pptonum(pp), pp->p_lckcnt,
		    pp->p_cowcnt, pp->p_slckcnt);
		/*NOTREACHED*/
	}

	ASSERT(!hat_page_getshare(pp));

	PP_SETFREE(pp);
	ASSERT(pp->p_vnode == NULL || !IS_VMODSORT(pp->p_vnode) ||
	    !hat_ismod(pp));
	page_clr_all_props(pp);
	ASSERT(!hat_page_getshare(pp));

	/*
	 * Now we add the page to the head of the free list.
	 * But if this page is associated with a paged vnode
	 * then we adjust the head forward so that the page is
	 * effectively at the end of the list.
	 */
	if (pp->p_vnode == NULL) {
		/*
		 * Page has no identity, put it on the free list.
		 */
		PP_SETAGED(pp);
		pp->p_offset = (u_offset_t)-1;
		page_list_add(pp, PG_FREE_LIST | PG_LIST_TAIL);
		VM_STAT_ADD(pagecnt.pc_free_free);
		TRACE_1(TR_FAC_VM, TR_PAGE_FREE_FREE,
		    "page_free_free:pp %p", pp);
	} else {
		PP_CLRAGED(pp);

		if (!dontneed) {
			/* move it to the tail of the list */
			page_list_add(pp, PG_CACHE_LIST | PG_LIST_TAIL);

			VM_STAT_ADD(pagecnt.pc_free_cache);
			TRACE_1(TR_FAC_VM, TR_PAGE_FREE_CACHE_TAIL,
			    "page_free_cache_tail:pp %p", pp);
		} else {
			page_list_add(pp, PG_CACHE_LIST | PG_LIST_HEAD);

			VM_STAT_ADD(pagecnt.pc_free_dontneed);
			TRACE_1(TR_FAC_VM, TR_PAGE_FREE_CACHE_HEAD,
			    "page_free_cache_head:pp %p", pp);
		}
	}
	page_unlock(pp);

	/*
	 * Now do the `freemem' accounting.
	 */
	pcf_index = PCF_INDEX();
	p = &pcf[pcf_index];

	mutex_enter(&p->pcf_lock);
	if (p->pcf_block) {
		p->pcf_reserve += 1;
	} else {
		p->pcf_count += 1;
		if (p->pcf_wait) {
			mutex_enter(&new_freemem_lock);
			/*
			 * Check to see if some other thread
			 * is actually waiting.  Another bucket
			 * may have woken it up by now.  If there
			 * are no waiters, then set our pcf_wait
			 * count to zero to avoid coming in here
			 * next time.  Also, since only one page
			 * was put on the free list, just wake
			 * up one waiter.
			 */
			if (freemem_wait) {
				cv_signal(&freemem_cv);
				p->pcf_wait--;
			} else {
				p->pcf_wait = 0;
			}
			mutex_exit(&new_freemem_lock);
		}
	}
	mutex_exit(&p->pcf_lock);

	/* freemem is approximate, so this test OK */
	if (!p->pcf_block)
		freemem += 1;
}

/*
 * Put page on the "free" list during intial startup.
 * This happens during initial single threaded execution.
 */
void
page_free_at_startup(page_t *pp)
{
	struct pcf	*p;
	uint_t		pcf_index;

	page_list_add(pp, PG_FREE_LIST | PG_LIST_HEAD | PG_LIST_ISINIT);
	VM_STAT_ADD(pagecnt.pc_free_free);

	/*
	 * Now do the `freemem' accounting.
	 */
	pcf_index = PCF_INDEX();
	p = &pcf[pcf_index];

	ASSERT(p->pcf_block == 0);
	ASSERT(p->pcf_wait == 0);
	p->pcf_count += 1;

	/* freemem is approximate, so this is OK */
	freemem += 1;
}

void
page_free_pages(page_t *pp)
{
	page_t	*tpp, *rootpp = NULL;
	pgcnt_t	pgcnt = page_get_pagecnt(pp->p_szc);
	pgcnt_t	i;
	uint_t	szc = pp->p_szc;

	VM_STAT_ADD(pagecnt.pc_free_pages);
	TRACE_1(TR_FAC_VM, TR_PAGE_FREE_FREE,
	    "page_free_free:pp %p", pp);

	ASSERT(pp->p_szc != 0 && pp->p_szc < page_num_pagesizes());
	if ((page_pptonum(pp) & (pgcnt - 1)) != 0) {
		panic("page_free_pages: not root page %p", (void *)pp);
		/*NOTREACHED*/
	}

	for (i = 0, tpp = pp; i < pgcnt; i++, tpp++) {
		ASSERT((PAGE_EXCL(tpp) &&
		    !page_iolock_assert(tpp)) || panicstr);
		if (PP_ISFREE(tpp)) {
			panic("page_free_pages: page %p is free", (void *)tpp);
			/*NOTREACHED*/
		}
		if (hat_page_is_mapped(tpp) || tpp->p_lckcnt != 0 ||
		    tpp->p_cowcnt != 0 || tpp->p_slckcnt != 0) {
			panic("page_free_pages %p", (void *)tpp);
			/*NOTREACHED*/
		}

		ASSERT(!hat_page_getshare(tpp));
		ASSERT(tpp->p_vnode == NULL);
		ASSERT(tpp->p_szc == szc);

		PP_SETFREE(tpp);
		page_clr_all_props(tpp);
		PP_SETAGED(tpp);
		tpp->p_offset = (u_offset_t)-1;
		ASSERT(tpp->p_next == tpp);
		ASSERT(tpp->p_prev == tpp);
		page_list_concat(&rootpp, &tpp);
	}
	ASSERT(rootpp == pp);

	page_list_add_pages(rootpp, 0);
	page_create_putback(pgcnt);
}

int free_pages = 1;

/*
 * This routine attempts to return pages to the cachelist via page_release().
 * It does not *have* to be successful in all cases, since the pageout scanner
 * will catch any pages it misses.  It does need to be fast and not introduce
 * too much overhead.
 *
 * If a page isn't found on the unlocked sweep of the page_hash bucket, we
 * don't lock and retry.  This is ok, since the page scanner will eventually
 * find any page we miss in free_vp_pages().
 */
void
free_vp_pages(vnode_t *vp, u_offset_t off, size_t len)
{
	page_t *pp;
	u_offset_t eoff;
	extern int swap_in_range(vnode_t *, u_offset_t, size_t);

	eoff = off + len;

	if (free_pages == 0)
		return;
	if (swap_in_range(vp, off, len))
		return;

	for (; off < eoff; off += PAGESIZE) {

		/*
		 * find the page using a fast, but inexact search. It'll be OK
		 * if a few pages slip through the cracks here.
		 */
		pp = page_exists(vp, off);

		/*
		 * If we didn't find the page (it may not exist), the page
		 * is free, looks still in use (shared), or we can't lock it,
		 * just give up.
		 */
		if (pp == NULL ||
		    PP_ISFREE(pp) ||
		    page_share_cnt(pp) > 0 ||
		    !page_trylock(pp, SE_EXCL))
			continue;

		/*
		 * Once we have locked pp, verify that it's still the
		 * correct page and not already free
		 */
		ASSERT(PAGE_LOCKED_SE(pp, SE_EXCL));
		if (pp->p_vnode != vp || pp->p_offset != off || PP_ISFREE(pp)) {
			page_unlock(pp);
			continue;
		}

		/*
		 * try to release the page...
		 */
		(void) page_release(pp, 1);
	}
}

/*
 * Reclaim the given page from the free list.
 * If pp is part of a large pages, only the given constituent page is reclaimed
 * and the large page it belonged to will be demoted.  This can only happen
 * if the page is not on the cachelist.
 *
 * Returns 1 on success or 0 on failure.
 *
 * The page is unlocked if it can't be reclaimed (when freemem == 0).
 * If `lock' is non-null, it will be dropped and re-acquired if
 * the routine must wait while freemem is 0.
 *
 * As it turns out, boot_getpages() does this.  It picks a page,
 * based on where OBP mapped in some address, gets its pfn, searches
 * the memsegs, locks the page, then pulls it off the free list!
 */
int
page_reclaim(page_t *pp, kmutex_t *lock)
{
	struct pcf	*p;
	struct cpu	*cpup;
	int		enough;
	uint_t		i;

	ASSERT(lock != NULL ? MUTEX_HELD(lock) : 1);
	ASSERT(PAGE_EXCL(pp) && PP_ISFREE(pp));

	/*
	 * If `freemem' is 0, we cannot reclaim this page from the
	 * freelist, so release every lock we might hold: the page,
	 * and the `lock' before blocking.
	 *
	 * The only way `freemem' can become 0 while there are pages
	 * marked free (have their p->p_free bit set) is when the
	 * system is low on memory and doing a page_create().  In
	 * order to guarantee that once page_create() starts acquiring
	 * pages it will be able to get all that it needs since `freemem'
	 * was decreased by the requested amount.  So, we need to release
	 * this page, and let page_create() have it.
	 *
	 * Since `freemem' being zero is not supposed to happen, just
	 * use the usual hash stuff as a starting point.  If that bucket
	 * is empty, then assume the worst, and start at the beginning
	 * of the pcf array.  If we always start at the beginning
	 * when acquiring more than one pcf lock, there won't be any
	 * deadlock problems.
	 */

	/* TODO: Do we need to test kcage_freemem if PG_NORELOC(pp)? */

	if (freemem <= throttlefree && !page_create_throttle(1l, 0)) {
		pcf_acquire_all();
		goto page_reclaim_nomem;
	}

	enough = pcf_decrement_bucket(1);

	if (!enough) {
		VM_STAT_ADD(page_reclaim_zero);
		/*
		 * Check again. Its possible that some other thread
		 * could have been right behind us, and added one
		 * to a list somewhere.  Acquire each of the pcf locks
		 * until we find a page.
		 */
		p = pcf;
		for (i = 0; i < pcf_fanout; i++) {
			mutex_enter(&p->pcf_lock);
			if (p->pcf_count >= 1) {
				p->pcf_count -= 1;
				/*
				 * freemem is not protected by any lock. Thus,
				 * we cannot have any assertion containing
				 * freemem here.
				 */
				freemem -= 1;
				enough = 1;
				break;
			}
			p++;
		}

		if (!enough) {
page_reclaim_nomem:
			/*
			 * We really can't have page `pp'.
			 * Time for the no-memory dance with
			 * page_free().  This is just like
			 * page_create_wait().  Plus the added
			 * attraction of releasing whatever mutex
			 * we held when we were called with in `lock'.
			 * Page_unlock() will wakeup any thread
			 * waiting around for this page.
			 */
			if (lock) {
				VM_STAT_ADD(page_reclaim_zero_locked);
				mutex_exit(lock);
			}
			page_unlock(pp);

			/*
			 * get this before we drop all the pcf locks.
			 */
			mutex_enter(&new_freemem_lock);

			p = pcf;
			for (i = 0; i < pcf_fanout; i++) {
				p->pcf_wait++;
				mutex_exit(&p->pcf_lock);
				p++;
			}

			freemem_wait++;
			cv_wait(&freemem_cv, &new_freemem_lock);
			freemem_wait--;

			mutex_exit(&new_freemem_lock);

			if (lock) {
				mutex_enter(lock);
			}
			return (0);
		}

		/*
		 * The pcf accounting has been done,
		 * though none of the pcf_wait flags have been set,
		 * drop the locks and continue on.
		 */
		while (p >= pcf) {
			mutex_exit(&p->pcf_lock);
			p--;
		}
	}


	VM_STAT_ADD(pagecnt.pc_reclaim);

	/*
	 * page_list_sub will handle the case where pp is a large page.
	 * It's possible that the page was promoted while on the freelist
	 */
	if (PP_ISAGED(pp)) {
		page_list_sub(pp, PG_FREE_LIST);
		TRACE_1(TR_FAC_VM, TR_PAGE_UNFREE_FREE,
		    "page_reclaim_free:pp %p", pp);
	} else {
		page_list_sub(pp, PG_CACHE_LIST);
		TRACE_1(TR_FAC_VM, TR_PAGE_UNFREE_CACHE,
		    "page_reclaim_cache:pp %p", pp);
	}

	/*
	 * clear the p_free & p_age bits since this page is no longer
	 * on the free list.  Notice that there was a brief time where
	 * a page is marked as free, but is not on the list.
	 *
	 * Set the reference bit to protect against immediate pageout.
	 */
	PP_CLRFREE(pp);
	PP_CLRAGED(pp);
	page_set_props(pp, P_REF);

	CPU_STATS_ENTER_K();
	cpup = CPU;	/* get cpup now that CPU cannot change */
	CPU_STATS_ADDQ(cpup, vm, pgrec, 1);
	CPU_STATS_ADDQ(cpup, vm, pgfrec, 1);
	CPU_STATS_EXIT_K();
	ASSERT(pp->p_szc == 0);

	return (1);
}

/*
 * Destroy identity of the page and put it back on
 * the page free list.  Assumes that the caller has
 * acquired the "exclusive" lock on the page.
 */
void
page_destroy(page_t *pp, int dontfree)
{
	ASSERT((PAGE_EXCL(pp) &&
	    !page_iolock_assert(pp)) || panicstr);
	ASSERT(pp->p_slckcnt == 0 || panicstr);

	if (pp->p_szc != 0) {
		if (pp->p_vnode == NULL || IS_SWAPFSVP(pp->p_vnode) ||
		    PP_ISKAS(pp)) {
			panic("page_destroy: anon or kernel or no vnode "
			    "large page %p", (void *)pp);
		}
		page_demote_vp_pages(pp);
		ASSERT(pp->p_szc == 0);
	}

	TRACE_1(TR_FAC_VM, TR_PAGE_DESTROY, "page_destroy:pp %p", pp);

	/*
	 * Unload translations, if any, then hash out the
	 * page to erase its identity.
	 */
	(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
	page_hashout(pp, NULL);

	if (!dontfree) {
		/*
		 * Acquire the "freemem_lock" for availrmem.
		 * The page_struct_lock need not be acquired for lckcnt
		 * and cowcnt since the page has an "exclusive" lock.
		 * We are doing a modified version of page_pp_unlock here.
		 */
		if ((pp->p_lckcnt != 0) || (pp->p_cowcnt != 0)) {
			mutex_enter(&freemem_lock);
			if (pp->p_lckcnt != 0) {
				availrmem++;
				pages_locked--;
				pp->p_lckcnt = 0;
			}
			if (pp->p_cowcnt != 0) {
				availrmem += pp->p_cowcnt;
				pages_locked -= pp->p_cowcnt;
				pp->p_cowcnt = 0;
			}
			mutex_exit(&freemem_lock);
		}
		/*
		 * Put the page on the "free" list.
		 */
		page_free(pp, 0);
	}
}

void
page_destroy_pages(page_t *pp)
{

	page_t	*tpp, *rootpp = NULL;
	pgcnt_t	pgcnt = page_get_pagecnt(pp->p_szc);
	pgcnt_t	i, pglcks = 0;
	uint_t	szc = pp->p_szc;

	ASSERT(pp->p_szc != 0 && pp->p_szc < page_num_pagesizes());

	VM_STAT_ADD(pagecnt.pc_destroy_pages);

	TRACE_1(TR_FAC_VM, TR_PAGE_DESTROY, "page_destroy_pages:pp %p", pp);

	if ((page_pptonum(pp) & (pgcnt - 1)) != 0) {
		panic("page_destroy_pages: not root page %p", (void *)pp);
		/*NOTREACHED*/
	}

	for (i = 0, tpp = pp; i < pgcnt; i++, tpp++) {
		ASSERT((PAGE_EXCL(tpp) &&
		    !page_iolock_assert(tpp)) || panicstr);
		ASSERT(tpp->p_slckcnt == 0 || panicstr);
		(void) hat_pageunload(tpp, HAT_FORCE_PGUNLOAD);
		page_hashout(tpp, NULL);
		ASSERT(tpp->p_offset == (u_offset_t)-1);
		if (tpp->p_lckcnt != 0) {
			pglcks++;
			tpp->p_lckcnt = 0;
		} else if (tpp->p_cowcnt != 0) {
			pglcks += tpp->p_cowcnt;
			tpp->p_cowcnt = 0;
		}
		ASSERT(!hat_page_getshare(tpp));
		ASSERT(tpp->p_vnode == NULL);
		ASSERT(tpp->p_szc == szc);

		PP_SETFREE(tpp);
		page_clr_all_props(tpp);
		PP_SETAGED(tpp);
		ASSERT(tpp->p_next == tpp);
		ASSERT(tpp->p_prev == tpp);
		page_list_concat(&rootpp, &tpp);
	}

	ASSERT(rootpp == pp);
	if (pglcks != 0) {
		mutex_enter(&freemem_lock);
		availrmem += pglcks;
		mutex_exit(&freemem_lock);
	}

	page_list_add_pages(rootpp, 0);
	page_create_putback(pgcnt);
}

/*
 * Similar to page_destroy(), but destroys pages which are
 * locked and known to be on the page free list.  Since
 * the page is known to be free and locked, no one can access
 * it.
 *
 * Also, the number of free pages does not change.
 */
void
page_destroy_free(page_t *pp)
{
	ASSERT(PAGE_EXCL(pp));
	ASSERT(PP_ISFREE(pp));
	ASSERT(pp->p_vnode);
	ASSERT(hat_page_getattr(pp, P_MOD | P_REF | P_RO) == 0);
	ASSERT(!hat_page_is_mapped(pp));
	ASSERT(PP_ISAGED(pp) == 0);
	ASSERT(pp->p_szc == 0);

	VM_STAT_ADD(pagecnt.pc_destroy_free);
	page_list_sub(pp, PG_CACHE_LIST);

	page_hashout(pp, NULL);
	ASSERT(pp->p_vnode == NULL);
	ASSERT(pp->p_offset == (u_offset_t)-1);
	ASSERT(pp->p_hash == NULL);

	PP_SETAGED(pp);
	page_list_add(pp, PG_FREE_LIST | PG_LIST_TAIL);
	page_unlock(pp);

	mutex_enter(&new_freemem_lock);
	if (freemem_wait) {
		cv_signal(&freemem_cv);
	}
	mutex_exit(&new_freemem_lock);
}

/*
 * Rename the page "opp" to have an identity specified
 * by [vp, off].  If a page already exists with this name
 * it is locked and destroyed.  Note that the page's
 * translations are not unloaded during the rename.
 *
 * This routine is used by the anon layer to "steal" the
 * original page and is not unlike destroying a page and
 * creating a new page using the same page frame.
 *
 * XXX -- Could deadlock if caller 1 tries to rename A to B while
 * caller 2 tries to rename B to A.
 */
void
page_rename(page_t *opp, vnode_t *vp, u_offset_t off)
{
	page_t		*pp;
	int		olckcnt = 0;
	int		ocowcnt = 0;
	kmutex_t	*phm;
	ulong_t		index;

	ASSERT(PAGE_EXCL(opp) && !page_iolock_assert(opp));
	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));
	ASSERT(PP_ISFREE(opp) == 0);

	VM_STAT_ADD(page_rename_count);

	TRACE_3(TR_FAC_VM, TR_PAGE_RENAME,
	    "page rename:pp %p vp %p off %llx", opp, vp, off);

	/*
	 * CacheFS may call page_rename for a large NFS page
	 * when both CacheFS and NFS mount points are used
	 * by applications. Demote this large page before
	 * renaming it, to ensure that there are no "partial"
	 * large pages left lying around.
	 */
	if (opp->p_szc != 0) {
		vnode_t *ovp = opp->p_vnode;
		ASSERT(ovp != NULL);
		ASSERT(!IS_SWAPFSVP(ovp));
		ASSERT(!VN_ISKAS(ovp));
		page_demote_vp_pages(opp);
		ASSERT(opp->p_szc == 0);
	}

	page_hashout(opp, NULL);
	PP_CLRAGED(opp);

	/*
	 * Acquire the appropriate page hash lock, since
	 * we're going to rename the page.
	 */
	index = PAGE_HASH_FUNC(vp, off);
	phm = PAGE_HASH_MUTEX(index);
	mutex_enter(phm);
top:
	/*
	 * Look for an existing page with this name and destroy it if found.
	 * By holding the page hash lock all the way to the page_hashin()
	 * call, we are assured that no page can be created with this
	 * identity.  In the case when the phm lock is dropped to undo any
	 * hat layer mappings, the existing page is held with an "exclusive"
	 * lock, again preventing another page from being created with
	 * this identity.
	 */
	pp = page_hash_search(index, vp, off);
	if (pp != NULL) {
		VM_STAT_ADD(page_rename_exists);

		/*
		 * As it turns out, this is one of only two places where
		 * page_lock() needs to hold the passed in lock in the
		 * successful case.  In all of the others, the lock could
		 * be dropped as soon as the attempt is made to lock
		 * the page.  It is tempting to add yet another arguement,
		 * PL_KEEP or PL_DROP, to let page_lock know what to do.
		 */
		if (!page_lock(pp, SE_EXCL, phm, P_RECLAIM)) {
			/*
			 * Went to sleep because the page could not
			 * be locked.  We were woken up when the page
			 * was unlocked, or when the page was destroyed.
			 * In either case, `phm' was dropped while we
			 * slept.  Hence we should not just roar through
			 * this loop.
			 */
			goto top;
		}

		/*
		 * If an existing page is a large page, then demote
		 * it to ensure that no "partial" large pages are
		 * "created" after page_rename. An existing page
		 * can be a CacheFS page, and can't belong to swapfs.
		 */
		if (hat_page_is_mapped(pp)) {
			/*
			 * Unload translations.  Since we hold the
			 * exclusive lock on this page, the page
			 * can not be changed while we drop phm.
			 * This is also not a lock protocol violation,
			 * but rather the proper way to do things.
			 */
			mutex_exit(phm);
			(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
			if (pp->p_szc != 0) {
				ASSERT(!IS_SWAPFSVP(vp));
				ASSERT(!VN_ISKAS(vp));
				page_demote_vp_pages(pp);
				ASSERT(pp->p_szc == 0);
			}
			mutex_enter(phm);
		} else if (pp->p_szc != 0) {
			ASSERT(!IS_SWAPFSVP(vp));
			ASSERT(!VN_ISKAS(vp));
			mutex_exit(phm);
			page_demote_vp_pages(pp);
			ASSERT(pp->p_szc == 0);
			mutex_enter(phm);
		}
		page_hashout(pp, phm);
	}
	/*
	 * Hash in the page with the new identity.
	 */
	if (!page_hashin(opp, vp, off, phm)) {
		/*
		 * We were holding phm while we searched for [vp, off]
		 * and only dropped phm if we found and locked a page.
		 * If we can't create this page now, then some thing
		 * is really broken.
		 */
		panic("page_rename: Can't hash in page: %p", (void *)pp);
		/*NOTREACHED*/
	}

	ASSERT(MUTEX_HELD(phm));
	mutex_exit(phm);

	/*
	 * Now that we have dropped phm, lets get around to finishing up
	 * with pp.
	 */
	if (pp != NULL) {
		ASSERT(!hat_page_is_mapped(pp));
		/* for now large pages should not end up here */
		ASSERT(pp->p_szc == 0);
		/*
		 * Save the locks for transfer to the new page and then
		 * clear them so page_free doesn't think they're important.
		 * The page_struct_lock need not be acquired for lckcnt and
		 * cowcnt since the page has an "exclusive" lock.
		 */
		olckcnt = pp->p_lckcnt;
		ocowcnt = pp->p_cowcnt;
		pp->p_lckcnt = pp->p_cowcnt = 0;

		/*
		 * Put the page on the "free" list after we drop
		 * the lock.  The less work under the lock the better.
		 */
		/*LINTED: constant in conditional context*/
		VN_DISPOSE(pp, B_FREE, 0, kcred);
	}

	/*
	 * Transfer the lock count from the old page (if any).
	 * The page_struct_lock need not be acquired for lckcnt and
	 * cowcnt since the page has an "exclusive" lock.
	 */
	opp->p_lckcnt += olckcnt;
	opp->p_cowcnt += ocowcnt;
}

/*
 * low level routine to add page `pp' to the hash and vp chains for [vp, offset]
 *
 * Pages are normally inserted at the start of a vnode's v_pages list.
 * If the vnode is VMODSORT and the page is modified, it goes at the end.
 * This can happen when a modified page is relocated for DR.
 *
 * Returns 1 on success and 0 on failure.
 */
static int
page_do_hashin(page_t *pp, vnode_t *vp, u_offset_t offset)
{
	page_t		**listp;
	page_t		*tp;
	ulong_t		index;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(vp != NULL);
	ASSERT(MUTEX_HELD(page_vnode_mutex(vp)));

	/*
	 * Be sure to set these up before the page is inserted on the hash
	 * list.  As soon as the page is placed on the list some other
	 * thread might get confused and wonder how this page could
	 * possibly hash to this list.
	 */
	pp->p_vnode = vp;
	pp->p_offset = offset;

	/*
	 * record if this page is on a swap vnode
	 */
	if ((vp->v_flag & VISSWAP) != 0)
		PP_SETSWAP(pp);

	index = PAGE_HASH_FUNC(vp, offset);
	ASSERT(MUTEX_HELD(PAGE_HASH_MUTEX(index)));
	listp = &page_hash[index];

	/*
	 * If this page is already hashed in, fail this attempt to add it.
	 */
	for (tp = *listp; tp != NULL; tp = tp->p_hash) {
		if (tp->p_vnode == vp && tp->p_offset == offset) {
			pp->p_vnode = NULL;
			pp->p_offset = (u_offset_t)(-1);
			return (0);
		}
	}
	pp->p_hash = *listp;
	*listp = pp;

	/*
	 * Add the page to the vnode's list of pages
	 */
	if (vp->v_pages != NULL && IS_VMODSORT(vp) && hat_ismod(pp))
		listp = &vp->v_pages->p_vpprev->p_vpnext;
	else
		listp = &vp->v_pages;

	page_vpadd(listp, pp);

	return (1);
}

/*
 * Add page `pp' to both the hash and vp chains for [vp, offset].
 *
 * Returns 1 on success and 0 on failure.
 * If hold is passed in, it is not dropped.
 */
int
page_hashin(page_t *pp, vnode_t *vp, u_offset_t offset, kmutex_t *hold)
{
	kmutex_t	*phm = NULL;
	kmutex_t	*vphm;
	int		rc;

	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));
	ASSERT(pp->p_fsdata == 0 || panicstr);

	TRACE_3(TR_FAC_VM, TR_PAGE_HASHIN,
	    "page_hashin:pp %p vp %p offset %llx",
	    pp, vp, offset);

	VM_STAT_ADD(hashin_count);

	if (hold != NULL)
		phm = hold;
	else {
		VM_STAT_ADD(hashin_not_held);
		phm = PAGE_HASH_MUTEX(PAGE_HASH_FUNC(vp, offset));
		mutex_enter(phm);
	}

	vphm = page_vnode_mutex(vp);
	mutex_enter(vphm);
	rc = page_do_hashin(pp, vp, offset);
	mutex_exit(vphm);
	if (hold == NULL)
		mutex_exit(phm);
	if (rc == 0)
		VM_STAT_ADD(hashin_already);
	return (rc);
}

/*
 * Remove page ``pp'' from the hash and vp chains and remove vp association.
 * All mutexes must be held
 */
static void
page_do_hashout(page_t *pp)
{
	page_t	**hpp;
	page_t	*hp;
	vnode_t	*vp = pp->p_vnode;

	ASSERT(vp != NULL);
	ASSERT(MUTEX_HELD(page_vnode_mutex(vp)));

	/*
	 * First, take pp off of its hash chain.
	 */
	hpp = &page_hash[PAGE_HASH_FUNC(vp, pp->p_offset)];

	for (;;) {
		hp = *hpp;
		if (hp == pp)
			break;
		if (hp == NULL) {
			panic("page_do_hashout");
			/*NOTREACHED*/
		}
		hpp = &hp->p_hash;
	}
	*hpp = pp->p_hash;

	/*
	 * Now remove it from its associated vnode.
	 */
	if (vp->v_pages)
		page_vpsub(&vp->v_pages, pp);

	pp->p_hash = NULL;
	page_clr_all_props(pp);
	PP_CLRSWAP(pp);
	pp->p_vnode = NULL;
	pp->p_offset = (u_offset_t)-1;
	pp->p_fsdata = 0;
}

/*
 * Remove page ``pp'' from the hash and vp chains and remove vp association.
 *
 * When `phm' is non-NULL it contains the address of the mutex protecting the
 * hash list pp is on.  It is not dropped.
 */
void
page_hashout(page_t *pp, kmutex_t *phm)
{
	vnode_t		*vp;
	ulong_t		index;
	kmutex_t	*nphm;
	kmutex_t	*vphm;
	kmutex_t	*sep;

	ASSERT(phm != NULL ? MUTEX_HELD(phm) : 1);
	ASSERT(pp->p_vnode != NULL);
	ASSERT((PAGE_EXCL(pp) && !page_iolock_assert(pp)) || panicstr);
	ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(pp->p_vnode)));

	vp = pp->p_vnode;

	TRACE_2(TR_FAC_VM, TR_PAGE_HASHOUT,
	    "page_hashout:pp %p vp %p", pp, vp);

	/* Kernel probe */
	TNF_PROBE_2(page_unmap, "vm pagefault", /* CSTYLED */,
	    tnf_opaque, vnode, vp,
	    tnf_offset, offset, pp->p_offset);

	/*
	 *
	 */
	VM_STAT_ADD(hashout_count);
	index = PAGE_HASH_FUNC(vp, pp->p_offset);
	if (phm == NULL) {
		VM_STAT_ADD(hashout_not_held);
		nphm = PAGE_HASH_MUTEX(index);
		mutex_enter(nphm);
	}
	ASSERT(phm ? phm == PAGE_HASH_MUTEX(index) : 1);


	/*
	 * grab page vnode mutex and remove it...
	 */
	vphm = page_vnode_mutex(vp);
	mutex_enter(vphm);

	page_do_hashout(pp);

	mutex_exit(vphm);
	if (phm == NULL)
		mutex_exit(nphm);

	/*
	 * Wake up processes waiting for this page.  The page's
	 * identity has been changed, and is probably not the
	 * desired page any longer.
	 */
	sep = page_se_mutex(pp);
	mutex_enter(sep);
	pp->p_selock &= ~SE_EWANTED;
	if (CV_HAS_WAITERS(&pp->p_cv))
		cv_broadcast(&pp->p_cv);
	mutex_exit(sep);
}

/*
 * Add the page to the front of a linked list of pages
 * using the p_next & p_prev pointers for the list.
 * The caller is responsible for protecting the list pointers.
 */
void
page_add(page_t **ppp, page_t *pp)
{
	ASSERT(PAGE_EXCL(pp) || (PAGE_SHARED(pp) && page_iolock_assert(pp)));

	page_add_common(ppp, pp);
}



/*
 *  Common code for page_add() and mach_page_add()
 */
void
page_add_common(page_t **ppp, page_t *pp)
{
	if (*ppp == NULL) {
		pp->p_next = pp->p_prev = pp;
	} else {
		pp->p_next = *ppp;
		pp->p_prev = (*ppp)->p_prev;
		(*ppp)->p_prev = pp;
		pp->p_prev->p_next = pp;
	}
	*ppp = pp;
}


/*
 * Remove this page from a linked list of pages
 * using the p_next & p_prev pointers for the list.
 *
 * The caller is responsible for protecting the list pointers.
 */
void
page_sub(page_t **ppp, page_t *pp)
{
	ASSERT((PP_ISFREE(pp)) ? 1 :
	    (PAGE_EXCL(pp)) || (PAGE_SHARED(pp) && page_iolock_assert(pp)));

	if (*ppp == NULL || pp == NULL) {
		panic("page_sub: bad arg(s): pp %p, *ppp %p",
		    (void *)pp, (void *)(*ppp));
		/*NOTREACHED*/
	}

	page_sub_common(ppp, pp);
}


/*
 *  Common code for page_sub() and mach_page_sub()
 */
void
page_sub_common(page_t **ppp, page_t *pp)
{
	if (*ppp == pp)
		*ppp = pp->p_next;		/* go to next page */

	if (*ppp == pp)
		*ppp = NULL;			/* page list is gone */
	else {
		pp->p_prev->p_next = pp->p_next;
		pp->p_next->p_prev = pp->p_prev;
	}
	pp->p_prev = pp->p_next = pp;		/* make pp a list of one */
}


/*
 * Break page list cppp into two lists with npages in the first list.
 * The tail is returned in nppp.
 */
void
page_list_break(page_t **oppp, page_t **nppp, pgcnt_t npages)
{
	page_t *s1pp = *oppp;
	page_t *s2pp;
	page_t *e1pp, *e2pp;
	long n = 0;

	if (s1pp == NULL) {
		*nppp = NULL;
		return;
	}
	if (npages == 0) {
		*nppp = s1pp;
		*oppp = NULL;
		return;
	}
	for (n = 0, s2pp = *oppp; n < npages; n++) {
		s2pp = s2pp->p_next;
	}
	/* Fix head and tail of new lists */
	e1pp = s2pp->p_prev;
	e2pp = s1pp->p_prev;
	s1pp->p_prev = e1pp;
	e1pp->p_next = s1pp;
	s2pp->p_prev = e2pp;
	e2pp->p_next = s2pp;

	/* second list empty */
	if (s2pp == s1pp) {
		*oppp = s1pp;
		*nppp = NULL;
	} else {
		*oppp = s1pp;
		*nppp = s2pp;
	}
}

/*
 * Concatenate page list nppp onto the end of list ppp.
 */
void
page_list_concat(page_t **ppp, page_t **nppp)
{
	page_t *s1pp, *s2pp, *e1pp, *e2pp;

	if (*nppp == NULL) {
		return;
	}
	if (*ppp == NULL) {
		*ppp = *nppp;
		return;
	}
	s1pp = *ppp;
	e1pp =  s1pp->p_prev;
	s2pp = *nppp;
	e2pp = s2pp->p_prev;
	s1pp->p_prev = e2pp;
	e2pp->p_next = s1pp;
	e1pp->p_next = s2pp;
	s2pp->p_prev = e1pp;
}

/*
 * return the next page in the page list
 */
page_t *
page_list_next(page_t *pp)
{
	return (pp->p_next);
}


/*
 * Add the page to the front of the linked list of pages
 * using p_vpnext/p_vpprev pointers for the list.
 *
 * The caller is responsible for protecting the lists.
 */
void
page_vpadd(page_t **ppp, page_t *pp)
{
	if (*ppp == NULL) {
		pp->p_vpnext = pp->p_vpprev = pp;
	} else {
		pp->p_vpnext = *ppp;
		pp->p_vpprev = (*ppp)->p_vpprev;
		(*ppp)->p_vpprev = pp;
		pp->p_vpprev->p_vpnext = pp;
	}
	*ppp = pp;
}

/*
 * Remove this page from the linked list of pages
 * using p_vpnext/p_vpprev pointers for the list.
 *
 * The caller is responsible for protecting the lists.
 */
void
page_vpsub(page_t **ppp, page_t *pp)
{
	if (*ppp == NULL || pp == NULL) {
		panic("page_vpsub: bad arg(s): pp %p, *ppp %p",
		    (void *)pp, (void *)(*ppp));
		/*NOTREACHED*/
	}

	if (*ppp == pp)
		*ppp = pp->p_vpnext;		/* go to next page */

	if (*ppp == pp)
		*ppp = NULL;			/* page list is gone */
	else {
		pp->p_vpprev->p_vpnext = pp->p_vpnext;
		pp->p_vpnext->p_vpprev = pp->p_vpprev;
	}
	pp->p_vpprev = pp->p_vpnext = pp;	/* make pp a list of one */
}

/*
 * Lock a physical page into memory "long term".  Used to support "lock
 * in memory" functions.  Accepts the page to be locked, and a cow variable
 * to indicate whether a the lock will travel to the new page during
 * a potential copy-on-write.
 */
int
page_pp_lock(
	page_t *pp,			/* page to be locked */
	int cow,			/* cow lock */
	int kernel)			/* must succeed -- ignore checking */
{
	int r = 0;			/* result -- assume failure */

	ASSERT(PAGE_LOCKED(pp));

	page_struct_lock(pp);
	/*
	 * Acquire the "freemem_lock" for availrmem.
	 */
	if (cow) {
		mutex_enter(&freemem_lock);
		if ((availrmem > pages_pp_maximum) &&
		    (pp->p_cowcnt < (ushort_t)PAGE_LOCK_MAXIMUM)) {
			availrmem--;
			pages_locked++;
			mutex_exit(&freemem_lock);
			r = 1;
			if (++pp->p_cowcnt == (ushort_t)PAGE_LOCK_MAXIMUM) {
				cmn_err(CE_WARN,
				    "COW lock limit reached on pfn 0x%lx",
				    page_pptonum(pp));
			}
		} else
			mutex_exit(&freemem_lock);
	} else {
		if (pp->p_lckcnt) {
			if (pp->p_lckcnt < (ushort_t)PAGE_LOCK_MAXIMUM) {
				r = 1;
				if (++pp->p_lckcnt ==
				    (ushort_t)PAGE_LOCK_MAXIMUM) {
					cmn_err(CE_WARN, "Page lock limit "
					    "reached on pfn 0x%lx",
					    page_pptonum(pp));
				}
			}
		} else {
			if (kernel) {
				/* availrmem accounting done by caller */
				++pp->p_lckcnt;
				r = 1;
			} else {
				mutex_enter(&freemem_lock);
				if (availrmem > pages_pp_maximum) {
					availrmem--;
					pages_locked++;
					++pp->p_lckcnt;
					r = 1;
				}
				mutex_exit(&freemem_lock);
			}
		}
	}
	page_struct_unlock(pp);
	return (r);
}

/*
 * Decommit a lock on a physical page frame.  Account for cow locks if
 * appropriate.
 */
void
page_pp_unlock(
	page_t *pp,			/* page to be unlocked */
	int cow,			/* expect cow lock */
	int kernel)			/* this was a kernel lock */
{
	ASSERT(PAGE_LOCKED(pp));

	page_struct_lock(pp);
	/*
	 * Acquire the "freemem_lock" for availrmem.
	 * If cowcnt or lcknt is already 0 do nothing; i.e., we
	 * could be called to unlock even if nothing is locked. This could
	 * happen if locked file pages were truncated (removing the lock)
	 * and the file was grown again and new pages faulted in; the new
	 * pages are unlocked but the segment still thinks they're locked.
	 */
	if (cow) {
		if (pp->p_cowcnt) {
			mutex_enter(&freemem_lock);
			pp->p_cowcnt--;
			availrmem++;
			pages_locked--;
			mutex_exit(&freemem_lock);
		}
	} else {
		if (pp->p_lckcnt && --pp->p_lckcnt == 0) {
			if (!kernel) {
				mutex_enter(&freemem_lock);
				availrmem++;
				pages_locked--;
				mutex_exit(&freemem_lock);
			}
		}
	}
	page_struct_unlock(pp);
}

/*
 * This routine reserves availrmem for npages;
 * 	flags: KM_NOSLEEP or KM_SLEEP
 * 	returns 1 on success or 0 on failure
 */
int
page_resv(pgcnt_t npages, uint_t flags)
{
	mutex_enter(&freemem_lock);
	while (availrmem < tune.t_minarmem + npages) {
		if (flags & KM_NOSLEEP) {
			mutex_exit(&freemem_lock);
			return (0);
		}
		mutex_exit(&freemem_lock);
		page_needfree(npages);
		kmem_reap();
		delay(hz >> 2);
		page_needfree(-(spgcnt_t)npages);
		mutex_enter(&freemem_lock);
	}
	availrmem -= npages;
	mutex_exit(&freemem_lock);
	return (1);
}

/*
 * This routine unreserves availrmem for npages;
 */
void
page_unresv(pgcnt_t npages)
{
	mutex_enter(&freemem_lock);
	availrmem += npages;
	mutex_exit(&freemem_lock);
}

/*
 * See Statement at the beginning of segvn_lockop() regarding
 * the way we handle cowcnts and lckcnts.
 *
 * Transfer cowcnt on 'opp' to cowcnt on 'npp' if the vpage
 * that breaks COW has PROT_WRITE.
 *
 * Note that, we may also break COW in case we are softlocking
 * on read access during physio;
 * in this softlock case, the vpage may not have PROT_WRITE.
 * So, we need to transfer lckcnt on 'opp' to lckcnt on 'npp'
 * if the vpage doesn't have PROT_WRITE.
 *
 * This routine is never called if we are stealing a page
 * in anon_private.
 *
 * The caller subtracted from availrmem for read only mapping.
 * if lckcnt is 1 increment availrmem.
 */
void
page_pp_useclaim(
	page_t *opp,		/* original page frame losing lock */
	page_t *npp,		/* new page frame gaining lock */
	uint_t	write_perm) 	/* set if vpage has PROT_WRITE */
{
	int payback = 0;
	int nidx, oidx;

	ASSERT(PAGE_LOCKED(opp));
	ASSERT(PAGE_LOCKED(npp));

	/*
	 * Since we have two pages we probably have two locks.  We need to take
	 * them in a defined order to avoid deadlocks.  It's also possible they
	 * both hash to the same lock in which case this is a non-issue.
	 */
	nidx = PAGE_LLOCK_HASH(PP_PAGEROOT(npp));
	oidx = PAGE_LLOCK_HASH(PP_PAGEROOT(opp));
	if (nidx < oidx) {
		page_struct_lock(npp);
		page_struct_lock(opp);
	} else if (oidx < nidx) {
		page_struct_lock(opp);
		page_struct_lock(npp);
	} else {	/* The pages hash to the same lock */
		page_struct_lock(npp);
	}

	ASSERT(npp->p_cowcnt == 0);
	ASSERT(npp->p_lckcnt == 0);

	/* Don't use claim if nothing is locked (see page_pp_unlock above) */
	if ((write_perm && opp->p_cowcnt != 0) ||
	    (!write_perm && opp->p_lckcnt != 0)) {

		if (write_perm) {
			npp->p_cowcnt++;
			ASSERT(opp->p_cowcnt != 0);
			opp->p_cowcnt--;
		} else {

			ASSERT(opp->p_lckcnt != 0);

			/*
			 * We didn't need availrmem decremented if p_lckcnt on
			 * original page is 1. Here, we are unlocking
			 * read-only copy belonging to original page and
			 * are locking a copy belonging to new page.
			 */
			if (opp->p_lckcnt == 1)
				payback = 1;

			npp->p_lckcnt++;
			opp->p_lckcnt--;
		}
	}
	if (payback) {
		mutex_enter(&freemem_lock);
		availrmem++;
		pages_useclaim--;
		mutex_exit(&freemem_lock);
	}

	if (nidx < oidx) {
		page_struct_unlock(opp);
		page_struct_unlock(npp);
	} else if (oidx < nidx) {
		page_struct_unlock(npp);
		page_struct_unlock(opp);
	} else {	/* The pages hash to the same lock */
		page_struct_unlock(npp);
	}
}

/*
 * Simple claim adjust functions -- used to support changes in
 * claims due to changes in access permissions.  Used by segvn_setprot().
 */
int
page_addclaim(page_t *pp)
{
	int r = 0;			/* result */

	ASSERT(PAGE_LOCKED(pp));

	page_struct_lock(pp);
	ASSERT(pp->p_lckcnt != 0);

	if (pp->p_lckcnt == 1) {
		if (pp->p_cowcnt < (ushort_t)PAGE_LOCK_MAXIMUM) {
			--pp->p_lckcnt;
			r = 1;
			if (++pp->p_cowcnt == (ushort_t)PAGE_LOCK_MAXIMUM) {
				cmn_err(CE_WARN,
				    "COW lock limit reached on pfn 0x%lx",
				    page_pptonum(pp));
			}
		}
	} else {
		mutex_enter(&freemem_lock);
		if ((availrmem > pages_pp_maximum) &&
		    (pp->p_cowcnt < (ushort_t)PAGE_LOCK_MAXIMUM)) {
			--availrmem;
			++pages_claimed;
			mutex_exit(&freemem_lock);
			--pp->p_lckcnt;
			r = 1;
			if (++pp->p_cowcnt == (ushort_t)PAGE_LOCK_MAXIMUM) {
				cmn_err(CE_WARN,
				    "COW lock limit reached on pfn 0x%lx",
				    page_pptonum(pp));
			}
		} else
			mutex_exit(&freemem_lock);
	}
	page_struct_unlock(pp);
	return (r);
}

int
page_subclaim(page_t *pp)
{
	int r = 0;

	ASSERT(PAGE_LOCKED(pp));

	page_struct_lock(pp);
	ASSERT(pp->p_cowcnt != 0);

	if (pp->p_lckcnt) {
		if (pp->p_lckcnt < (ushort_t)PAGE_LOCK_MAXIMUM) {
			r = 1;
			/*
			 * for availrmem
			 */
			mutex_enter(&freemem_lock);
			availrmem++;
			pages_claimed--;
			mutex_exit(&freemem_lock);

			pp->p_cowcnt--;

			if (++pp->p_lckcnt == (ushort_t)PAGE_LOCK_MAXIMUM) {
				cmn_err(CE_WARN,
				    "Page lock limit reached on pfn 0x%lx",
				    page_pptonum(pp));
			}
		}
	} else {
		r = 1;
		pp->p_cowcnt--;
		pp->p_lckcnt++;
	}
	page_struct_unlock(pp);
	return (r);
}

/*
 * Variant of page_addclaim(), where ppa[] contains the pages of a single large
 * page.
 */
int
page_addclaim_pages(page_t  **ppa)
{
	pgcnt_t	lckpgs = 0, pg_idx;

	VM_STAT_ADD(pagecnt.pc_addclaim_pages);

	/*
	 * Only need to take the page struct lock on the large page root.
	 */
	page_struct_lock(ppa[0]);
	for (pg_idx = 0; ppa[pg_idx] != NULL; pg_idx++) {

		ASSERT(PAGE_LOCKED(ppa[pg_idx]));
		ASSERT(ppa[pg_idx]->p_lckcnt != 0);
		if (ppa[pg_idx]->p_cowcnt == (ushort_t)PAGE_LOCK_MAXIMUM) {
			page_struct_unlock(ppa[0]);
			return (0);
		}
		if (ppa[pg_idx]->p_lckcnt > 1)
			lckpgs++;
	}

	if (lckpgs != 0) {
		mutex_enter(&freemem_lock);
		if (availrmem >= pages_pp_maximum + lckpgs) {
			availrmem -= lckpgs;
			pages_claimed += lckpgs;
		} else {
			mutex_exit(&freemem_lock);
			page_struct_unlock(ppa[0]);
			return (0);
		}
		mutex_exit(&freemem_lock);
	}

	for (pg_idx = 0; ppa[pg_idx] != NULL; pg_idx++) {
		ppa[pg_idx]->p_lckcnt--;
		ppa[pg_idx]->p_cowcnt++;
	}
	page_struct_unlock(ppa[0]);
	return (1);
}

/*
 * Variant of page_subclaim(), where ppa[] contains the pages of a single large
 * page.
 */
int
page_subclaim_pages(page_t  **ppa)
{
	pgcnt_t	ulckpgs = 0, pg_idx;

	VM_STAT_ADD(pagecnt.pc_subclaim_pages);

	/*
	 * Only need to take the page struct lock on the large page root.
	 */
	page_struct_lock(ppa[0]);
	for (pg_idx = 0; ppa[pg_idx] != NULL; pg_idx++) {

		ASSERT(PAGE_LOCKED(ppa[pg_idx]));
		ASSERT(ppa[pg_idx]->p_cowcnt != 0);
		if (ppa[pg_idx]->p_lckcnt == (ushort_t)PAGE_LOCK_MAXIMUM) {
			page_struct_unlock(ppa[0]);
			return (0);
		}
		if (ppa[pg_idx]->p_lckcnt != 0)
			ulckpgs++;
	}

	if (ulckpgs != 0) {
		mutex_enter(&freemem_lock);
		availrmem += ulckpgs;
		pages_claimed -= ulckpgs;
		mutex_exit(&freemem_lock);
	}

	for (pg_idx = 0; ppa[pg_idx] != NULL; pg_idx++) {
		ppa[pg_idx]->p_cowcnt--;
		ppa[pg_idx]->p_lckcnt++;

	}
	page_struct_unlock(ppa[0]);
	return (1);
}

page_t *
page_numtopp(pfn_t pfnum, se_t se)
{
	page_t *pp;

retry:
	pp = page_numtopp_nolock(pfnum);
	if (pp == NULL) {
		return ((page_t *)NULL);
	}

	/*
	 * Acquire the appropriate lock on the page.
	 */
	while (!page_lock(pp, se, (kmutex_t *)NULL, P_RECLAIM)) {
		if (page_pptonum(pp) != pfnum)
			goto retry;
		continue;
	}

	if (page_pptonum(pp) != pfnum) {
		page_unlock(pp);
		goto retry;
	}

	return (pp);
}

page_t *
page_numtopp_noreclaim(pfn_t pfnum, se_t se)
{
	page_t *pp;

retry:
	pp = page_numtopp_nolock(pfnum);
	if (pp == NULL) {
		return ((page_t *)NULL);
	}

	/*
	 * Acquire the appropriate lock on the page.
	 */
	while (!page_lock(pp, se, (kmutex_t *)NULL, P_NO_RECLAIM)) {
		if (page_pptonum(pp) != pfnum)
			goto retry;
		continue;
	}

	if (page_pptonum(pp) != pfnum) {
		page_unlock(pp);
		goto retry;
	}

	return (pp);
}

/*
 * This routine is like page_numtopp, but will only return page structs
 * for pages which are ok for loading into hardware using the page struct.
 */
page_t *
page_numtopp_nowait(pfn_t pfnum, se_t se)
{
	page_t *pp;

retry:
	pp = page_numtopp_nolock(pfnum);
	if (pp == NULL) {
		return ((page_t *)NULL);
	}

	/*
	 * Try to acquire the appropriate lock on the page.
	 */
	if (PP_ISFREE(pp))
		pp = NULL;
	else {
		if (!page_trylock(pp, se))
			pp = NULL;
		else {
			if (page_pptonum(pp) != pfnum) {
				page_unlock(pp);
				goto retry;
			}
			if (PP_ISFREE(pp)) {
				page_unlock(pp);
				pp = NULL;
			}
		}
	}
	return (pp);
}

/*
 * Returns a count of dirty pages that are in the process
 * of being written out.  If 'cleanit' is set, try to push the page.
 */
pgcnt_t
page_busy(int cleanit)
{
	page_t *page0 = page_first();
	page_t *pp = page0;
	pgcnt_t nppbusy = 0;
	u_offset_t off;

	do {
		vnode_t *vp = pp->p_vnode;
		/*
		 * A page is a candidate for syncing if it is:
		 *
		 * (a)	On neither the freelist nor the cachelist
		 * (b)	Hashed onto a vnode
		 * (c)	Not a kernel page
		 * (d)	Dirty
		 * (e)	Not part of a swapfile
		 * (f)	a page which belongs to a real vnode; eg has a non-null
		 *	v_vfsp pointer.
		 * (g)	Backed by a filesystem which doesn't have a
		 *	stubbed-out sync operation
		 */
		if (!PP_ISFREE(pp) && vp != NULL && !VN_ISKAS(vp) &&
		    hat_ismod(pp) && !IS_SWAPVP(vp) && vp->v_vfsp != NULL &&
		    vfs_can_sync(vp->v_vfsp)) {
			nppbusy++;

			if (!cleanit)
				continue;
			if (!page_trylock(pp, SE_EXCL))
				continue;

			if (PP_ISFREE(pp) || vp == NULL || IS_SWAPVP(vp) ||
			    pp->p_lckcnt != 0 || pp->p_cowcnt != 0 ||
			    !(hat_pagesync(pp,
			    HAT_SYNC_DONTZERO | HAT_SYNC_STOPON_MOD) & P_MOD)) {
				page_unlock(pp);
				continue;
			}
			off = pp->p_offset;
			VN_HOLD(vp);
			page_unlock(pp);
			(void) VOP_PUTPAGE(vp, off, PAGESIZE,
			    B_ASYNC | B_FREE, kcred, NULL);
			VN_RELE(vp);
		}
	} while ((pp = page_next(pp)) != page0);

	return (nppbusy);
}

void page_invalidate_pages(void);

/*
 * callback handler to vm sub-system
 *
 * callers make sure no recursive entries to this func.
 */
/*ARGSUSED*/
boolean_t
callb_vm_cpr(void *arg, int code)
{
	if (code == CB_CODE_CPR_CHKPT)
		page_invalidate_pages();
	return (B_TRUE);
}

/*
 * Invalidate all pages of the system.
 * It shouldn't be called until all user page activities are all stopped.
 */
void
page_invalidate_pages()
{
	page_t *pp;
	page_t *page0;
	pgcnt_t nbusypages;
	int retry = 0;
	const int MAXRETRIES = 4;
top:
	/*
	 * Flush dirty pages and destroy the clean ones.
	 */
	nbusypages = 0;

	pp = page0 = page_first();
	do {
		struct vnode	*vp;
		u_offset_t	offset;
		int		mod;

		/*
		 * skip the page if it has no vnode or the page associated
		 * with the kernel vnode or prom allocated kernel mem.
		 */
		if ((vp = pp->p_vnode) == NULL || VN_ISKAS(vp))
			continue;

		/*
		 * skip the page which is already free invalidated.
		 */
		if (PP_ISFREE(pp) && PP_ISAGED(pp))
			continue;

		/*
		 * skip pages that are already locked or can't be "exclusively"
		 * locked or are already free.  After we lock the page, check
		 * the free and age bits again to be sure it's not destroyed
		 * yet.
		 * To achieve max. parallelization, we use page_trylock instead
		 * of page_lock so that we don't get block on individual pages
		 * while we have thousands of other pages to process.
		 */
		if (!page_trylock(pp, SE_EXCL)) {
			nbusypages++;
			continue;
		} else if (PP_ISFREE(pp)) {
			if (!PP_ISAGED(pp)) {
				page_destroy_free(pp);
			} else {
				page_unlock(pp);
			}
			continue;
		}
		/*
		 * Is this page involved in some I/O? shared?
		 *
		 * The page_struct_lock need not be acquired to
		 * examine these fields since the page has an
		 * "exclusive" lock.
		 */
		if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
			page_unlock(pp);
			continue;
		}

		if (vp->v_type == VCHR) {
			panic("vp->v_type == VCHR");
			/*NOTREACHED*/
		}

		if (!page_try_demote_pages(pp)) {
			page_unlock(pp);
			continue;
		}

		/*
		 * Check the modified bit. Leave the bits alone in hardware
		 * (they will be modified if we do the putpage).
		 */
		mod = (hat_pagesync(pp, HAT_SYNC_DONTZERO | HAT_SYNC_STOPON_MOD)
		    & P_MOD);
		if (mod) {
			offset = pp->p_offset;
			/*
			 * Hold the vnode before releasing the page lock
			 * to prevent it from being freed and re-used by
			 * some other thread.
			 */
			VN_HOLD(vp);
			page_unlock(pp);
			/*
			 * No error return is checked here. Callers such as
			 * cpr deals with the dirty pages at the dump time
			 * if this putpage fails.
			 */
			(void) VOP_PUTPAGE(vp, offset, PAGESIZE, B_INVAL,
			    kcred, NULL);
			VN_RELE(vp);
		} else {
			/*LINTED: constant in conditional context*/
			VN_DISPOSE(pp, B_INVAL, 0, kcred);
		}
	} while ((pp = page_next(pp)) != page0);
	if (nbusypages && retry++ < MAXRETRIES) {
		delay(1);
		goto top;
	}
}

/*
 * Replace the page "old" with the page "new" on the page hash and vnode lists
 *
 * the replacement must be done in place, ie the equivalent sequence:
 *
 *	vp = old->p_vnode;
 *	off = old->p_offset;
 *	page_do_hashout(old)
 *	page_do_hashin(new, vp, off)
 *
 * doesn't work, since
 *  1) if old is the only page on the vnode, the v_pages list has a window
 *     where it looks empty. This will break file system assumptions.
 * and
 *  2) pvn_vplist_dirty() can't deal with pages moving on the v_pages list.
 */
static void
page_do_relocate_hash(page_t *new, page_t *old)
{
	page_t	**hash_list;
	vnode_t	*vp = old->p_vnode;
	kmutex_t *sep;

	ASSERT(PAGE_EXCL(old));
	ASSERT(PAGE_EXCL(new));
	ASSERT(vp != NULL);
	ASSERT(MUTEX_HELD(page_vnode_mutex(vp)));
	ASSERT(MUTEX_HELD(PAGE_HASH_MUTEX(PAGE_HASH_FUNC(vp, old->p_offset))));

	/*
	 * First find old page on the page hash list
	 */
	hash_list = &page_hash[PAGE_HASH_FUNC(vp, old->p_offset)];

	for (;;) {
		if (*hash_list == old)
			break;
		if (*hash_list == NULL) {
			panic("page_do_hashout");
			/*NOTREACHED*/
		}
		hash_list = &(*hash_list)->p_hash;
	}

	/*
	 * update new and replace old with new on the page hash list
	 */
	new->p_vnode = old->p_vnode;
	new->p_offset = old->p_offset;
	new->p_hash = old->p_hash;
	*hash_list = new;

	if ((new->p_vnode->v_flag & VISSWAP) != 0)
		PP_SETSWAP(new);

	/*
	 * replace old with new on the vnode's page list
	 */
	if (old->p_vpnext == old) {
		new->p_vpnext = new;
		new->p_vpprev = new;
	} else {
		new->p_vpnext = old->p_vpnext;
		new->p_vpprev = old->p_vpprev;
		new->p_vpnext->p_vpprev = new;
		new->p_vpprev->p_vpnext = new;
	}
	if (vp->v_pages == old)
		vp->v_pages = new;

	/*
	 * clear out the old page
	 */
	old->p_hash = NULL;
	old->p_vpnext = NULL;
	old->p_vpprev = NULL;
	old->p_vnode = NULL;
	PP_CLRSWAP(old);
	old->p_offset = (u_offset_t)-1;
	page_clr_all_props(old);

	/*
	 * Wake up processes waiting for this page.  The page's
	 * identity has been changed, and is probably not the
	 * desired page any longer.
	 */
	sep = page_se_mutex(old);
	mutex_enter(sep);
	old->p_selock &= ~SE_EWANTED;
	if (CV_HAS_WAITERS(&old->p_cv))
		cv_broadcast(&old->p_cv);
	mutex_exit(sep);
}

/*
 * This function moves the identity of page "pp_old" to page "pp_new".
 * Both pages must be locked on entry.  "pp_new" is free, has no identity,
 * and need not be hashed out from anywhere.
 */
void
page_relocate_hash(page_t *pp_new, page_t *pp_old)
{
	vnode_t *vp = pp_old->p_vnode;
	u_offset_t off = pp_old->p_offset;
	kmutex_t *phm, *vphm;

	/*
	 * Rehash two pages
	 */
	ASSERT(PAGE_EXCL(pp_old));
	ASSERT(PAGE_EXCL(pp_new));
	ASSERT(vp != NULL);
	ASSERT(pp_new->p_vnode == NULL);

	/*
	 * hashout then hashin while holding the mutexes
	 */
	phm = PAGE_HASH_MUTEX(PAGE_HASH_FUNC(vp, off));
	mutex_enter(phm);
	vphm = page_vnode_mutex(vp);
	mutex_enter(vphm);

	page_do_relocate_hash(pp_new, pp_old);

	/* The following comment preserved from page_flip(). */
	pp_new->p_fsdata = pp_old->p_fsdata;
	pp_old->p_fsdata = 0;
	mutex_exit(vphm);
	mutex_exit(phm);

	/*
	 * The page_struct_lock need not be acquired for lckcnt and
	 * cowcnt since the page has an "exclusive" lock.
	 */
	ASSERT(pp_new->p_lckcnt == 0);
	ASSERT(pp_new->p_cowcnt == 0);
	pp_new->p_lckcnt = pp_old->p_lckcnt;
	pp_new->p_cowcnt = pp_old->p_cowcnt;
	pp_old->p_lckcnt = pp_old->p_cowcnt = 0;

}

/*
 * Helper routine used to lock all remaining members of a
 * large page. The caller is responsible for passing in a locked
 * pp. If pp is a large page, then it succeeds in locking all the
 * remaining constituent pages or it returns with only the
 * original page locked.
 *
 * Returns 1 on success, 0 on failure.
 *
 * If success is returned this routine guarantees p_szc for all constituent
 * pages of a large page pp belongs to can't change. To achieve this we
 * recheck szc of pp after locking all constituent pages and retry if szc
 * changed (it could only decrease). Since hat_page_demote() needs an EXCL
 * lock on one of constituent pages it can't be running after all constituent
 * pages are locked.  hat_page_demote() with a lock on a constituent page
 * outside of this large page (i.e. pp belonged to a larger large page) is
 * already done with all constituent pages of pp since the root's p_szc is
 * changed last. Therefore no need to synchronize with hat_page_demote() that
 * locked a constituent page outside of pp's current large page.
 */
#ifdef DEBUG
uint32_t gpg_trylock_mtbf = 0;
#endif

int
group_page_trylock(page_t *pp, se_t se)
{
	page_t  *tpp;
	pgcnt_t	npgs, i, j;
	uint_t pszc = pp->p_szc;

#ifdef DEBUG
	if (gpg_trylock_mtbf && !(gethrtime() % gpg_trylock_mtbf)) {
		return (0);
	}
#endif

	if (pp != PP_GROUPLEADER(pp, pszc)) {
		return (0);
	}

retry:
	ASSERT(PAGE_LOCKED_SE(pp, se));
	ASSERT(!PP_ISFREE(pp));
	if (pszc == 0) {
		return (1);
	}
	npgs = page_get_pagecnt(pszc);
	tpp = pp + 1;
	for (i = 1; i < npgs; i++, tpp++) {
		if (!page_trylock(tpp, se)) {
			tpp = pp + 1;
			for (j = 1; j < i; j++, tpp++) {
				page_unlock(tpp);
			}
			return (0);
		}
	}
	if (pp->p_szc != pszc) {
		ASSERT(pp->p_szc < pszc);
		ASSERT(pp->p_vnode != NULL && !PP_ISKAS(pp) &&
		    !IS_SWAPFSVP(pp->p_vnode));
		tpp = pp + 1;
		for (i = 1; i < npgs; i++, tpp++) {
			page_unlock(tpp);
		}
		pszc = pp->p_szc;
		goto retry;
	}
	return (1);
}

void
group_page_unlock(page_t *pp)
{
	page_t *tpp;
	pgcnt_t	npgs, i;

	ASSERT(PAGE_LOCKED(pp));
	ASSERT(!PP_ISFREE(pp));
	ASSERT(pp == PP_PAGEROOT(pp));
	npgs = page_get_pagecnt(pp->p_szc);
	for (i = 1, tpp = pp + 1; i < npgs; i++, tpp++) {
		page_unlock(tpp);
	}
}

/*
 * returns
 * 0 		: on success and *nrelocp is number of relocated PAGESIZE pages
 * ERANGE	: this is not a base page
 * EBUSY	: failure to get locks on the page/pages
 * ENOMEM	: failure to obtain replacement pages
 * EAGAIN	: OBP has not yet completed its boot-time handoff to the kernel
 * EIO		: An error occurred while trying to copy the page data
 *
 * Return with all constituent members of target and replacement
 * SE_EXCL locked. It is the callers responsibility to drop the
 * locks.
 */
int
do_page_relocate(
	page_t **target,
	page_t **replacement,
	int grouplock,
	spgcnt_t *nrelocp,
	lgrp_t *lgrp)
{
	page_t *first_repl;
	page_t *repl;
	page_t *targ;
	page_t *pl = NULL;
	uint_t ppattr;
	pfn_t   pfn, repl_pfn;
	uint_t	szc;
	spgcnt_t npgs, i;
	int repl_contig = 0;
	uint_t flags = 0;
	spgcnt_t dofree = 0;

	*nrelocp = 0;

#if defined(__sparc)
	/*
	 * We need to wait till OBP has completed
	 * its boot-time handoff of its resources to the kernel
	 * before we allow page relocation
	 */
	if (page_relocate_ready == 0) {
		return (EAGAIN);
	}
#endif

	/*
	 * If this is not a base page,
	 * just return with 0x0 pages relocated.
	 */
	targ = *target;
	ASSERT(PAGE_EXCL(targ));
	ASSERT(!PP_ISFREE(targ));
	szc = targ->p_szc;
	ASSERT(szc < mmu_page_sizes);
	VM_STAT_ADD(vmm_vmstats.ppr_reloc[szc]);
	pfn = targ->p_pagenum;
	if (pfn != PFN_BASE(pfn, szc)) {
		VM_STAT_ADD(vmm_vmstats.ppr_relocnoroot[szc]);
		return (ERANGE);
	}

	if ((repl = *replacement) != NULL && repl->p_szc >= szc) {
		repl_pfn = repl->p_pagenum;
		if (repl_pfn != PFN_BASE(repl_pfn, szc)) {
			VM_STAT_ADD(vmm_vmstats.ppr_reloc_replnoroot[szc]);
			return (ERANGE);
		}
		repl_contig = 1;
	}

	/*
	 * We must lock all members of this large page or we cannot
	 * relocate any part of it.
	 */
	if (grouplock != 0 && !group_page_trylock(targ, SE_EXCL)) {
		VM_STAT_ADD(vmm_vmstats.ppr_relocnolock[targ->p_szc]);
		return (EBUSY);
	}

	/*
	 * reread szc it could have been decreased before
	 * group_page_trylock() was done.
	 */
	szc = targ->p_szc;
	ASSERT(szc < mmu_page_sizes);
	VM_STAT_ADD(vmm_vmstats.ppr_reloc[szc]);
	ASSERT(pfn == PFN_BASE(pfn, szc));

	npgs = page_get_pagecnt(targ->p_szc);

	if (repl == NULL) {
		dofree = npgs;		/* Size of target page in MMU pages */
		if (!page_create_wait(dofree, 0)) {
			if (grouplock != 0) {
				group_page_unlock(targ);
			}
			VM_STAT_ADD(vmm_vmstats.ppr_relocnomem[szc]);
			return (ENOMEM);
		}

		/*
		 * seg kmem pages require that the target and replacement
		 * page be the same pagesize.
		 */
		flags = (VN_ISKAS(targ->p_vnode)) ? PGR_SAMESZC : 0;
		repl = page_get_replacement_page(targ, lgrp, flags);
		if (repl == NULL) {
			if (grouplock != 0) {
				group_page_unlock(targ);
			}
			page_create_putback(dofree);
			VM_STAT_ADD(vmm_vmstats.ppr_relocnomem[szc]);
			return (ENOMEM);
		}
	}
#ifdef DEBUG
	else {
		ASSERT(PAGE_LOCKED(repl));
	}
#endif /* DEBUG */

#if defined(__sparc)
	/*
	 * Let hat_page_relocate() complete the relocation if it's kernel page
	 */
	if (VN_ISKAS(targ->p_vnode)) {
		*replacement = repl;
		if (hat_page_relocate(target, replacement, nrelocp) != 0) {
			if (grouplock != 0) {
				group_page_unlock(targ);
			}
			if (dofree) {
				*replacement = NULL;
				page_free_replacement_page(repl);
				page_create_putback(dofree);
			}
			VM_STAT_ADD(vmm_vmstats.ppr_krelocfail[szc]);
			return (EAGAIN);
		}
		VM_STAT_ADD(vmm_vmstats.ppr_relocok[szc]);
		return (0);
	}
#else
#if defined(lint)
	dofree = dofree;
#endif
#endif

	first_repl = repl;

	for (i = 0; i < npgs; i++) {
		ASSERT(PAGE_EXCL(targ));
		ASSERT(targ->p_slckcnt == 0);
		ASSERT(repl->p_slckcnt == 0);

		(void) hat_pageunload(targ, HAT_FORCE_PGUNLOAD);

		ASSERT(hat_page_getshare(targ) == 0);
		ASSERT(!PP_ISFREE(targ));
		ASSERT(targ->p_pagenum == (pfn + i));
		ASSERT(repl_contig == 0 ||
		    repl->p_pagenum == (repl_pfn + i));

		/*
		 * Copy the page contents and attributes then
		 * relocate the page in the page hash.
		 */
		if (ppcopy(targ, repl) == 0) {
			targ = *target;
			repl = first_repl;
			VM_STAT_ADD(vmm_vmstats.ppr_copyfail);
			if (grouplock != 0) {
				group_page_unlock(targ);
			}
			if (dofree) {
				*replacement = NULL;
				page_free_replacement_page(repl);
				page_create_putback(dofree);
			}
			return (EIO);
		}

		targ++;
		if (repl_contig != 0) {
			repl++;
		} else {
			repl = repl->p_next;
		}
	}

	repl = first_repl;
	targ = *target;

	for (i = 0; i < npgs; i++) {
		ppattr = hat_page_getattr(targ, (P_MOD | P_REF | P_RO));
		page_clr_all_props(repl);
		page_set_props(repl, ppattr);
		page_relocate_hash(repl, targ);

		ASSERT(hat_page_getshare(targ) == 0);
		ASSERT(hat_page_getshare(repl) == 0);
		/*
		 * Now clear the props on targ, after the
		 * page_relocate_hash(), they no longer
		 * have any meaning.
		 */
		page_clr_all_props(targ);
		ASSERT(targ->p_next == targ);
		ASSERT(targ->p_prev == targ);
		page_list_concat(&pl, &targ);

		targ++;
		if (repl_contig != 0) {
			repl++;
		} else {
			repl = repl->p_next;
		}
	}
	/* assert that we have come full circle with repl */
	ASSERT(repl_contig == 1 || first_repl == repl);

	*target = pl;
	if (*replacement == NULL) {
		ASSERT(first_repl == repl);
		*replacement = repl;
	}
	VM_STAT_ADD(vmm_vmstats.ppr_relocok[szc]);
	*nrelocp = npgs;
	return (0);
}
/*
 * On success returns 0 and *nrelocp the number of PAGESIZE pages relocated.
 */
int
page_relocate(
	page_t **target,
	page_t **replacement,
	int grouplock,
	int freetarget,
	spgcnt_t *nrelocp,
	lgrp_t *lgrp)
{
	spgcnt_t ret;

	/* do_page_relocate returns 0 on success or errno value */
	ret = do_page_relocate(target, replacement, grouplock, nrelocp, lgrp);

	if (ret != 0 || freetarget == 0) {
		return (ret);
	}
	if (*nrelocp == 1) {
		ASSERT(*target != NULL);
		page_free(*target, 1);
	} else {
		page_t *tpp = *target;
		uint_t szc = tpp->p_szc;
		pgcnt_t npgs = page_get_pagecnt(szc);
		ASSERT(npgs > 1);
		ASSERT(szc != 0);
		do {
			ASSERT(PAGE_EXCL(tpp));
			ASSERT(!hat_page_is_mapped(tpp));
			ASSERT(tpp->p_szc == szc);
			PP_SETFREE(tpp);
			PP_SETAGED(tpp);
			npgs--;
		} while ((tpp = tpp->p_next) != *target);
		ASSERT(npgs == 0);
		page_list_add_pages(*target, 0);
		npgs = page_get_pagecnt(szc);
		page_create_putback(npgs);
	}
	return (ret);
}

/*
 * it is up to the caller to deal with pcf accounting.
 */
void
page_free_replacement_page(page_t *pplist)
{
	page_t *pp;

	while (pplist != NULL) {
		/*
		 * pp_targ is a linked list.
		 */
		pp = pplist;
		if (pp->p_szc == 0) {
			page_sub(&pplist, pp);
			page_clr_all_props(pp);
			PP_SETFREE(pp);
			PP_SETAGED(pp);
			page_list_add(pp, PG_FREE_LIST | PG_LIST_TAIL);
			page_unlock(pp);
			VM_STAT_ADD(pagecnt.pc_free_replacement_page[0]);
		} else {
			spgcnt_t curnpgs = page_get_pagecnt(pp->p_szc);
			page_t *tpp;
			page_list_break(&pp, &pplist, curnpgs);
			tpp = pp;
			do {
				ASSERT(PAGE_EXCL(tpp));
				ASSERT(!hat_page_is_mapped(tpp));
				page_clr_all_props(tpp);
				PP_SETFREE(tpp);
				PP_SETAGED(tpp);
			} while ((tpp = tpp->p_next) != pp);
			page_list_add_pages(pp, 0);
			VM_STAT_ADD(pagecnt.pc_free_replacement_page[1]);
		}
	}
}

/*
 * Relocate target to non-relocatable replacement page.
 */
int
page_relocate_cage(page_t **target, page_t **replacement)
{
	page_t *tpp, *rpp;
	spgcnt_t pgcnt, npgs;
	int result;

	tpp = *target;

	ASSERT(PAGE_EXCL(tpp));
	ASSERT(tpp->p_szc == 0);

	pgcnt = btop(page_get_pagesize(tpp->p_szc));

	do {
		(void) page_create_wait(pgcnt, PG_WAIT | PG_NORELOC);
		rpp = page_get_replacement_page(tpp, NULL, PGR_NORELOC);
		if (rpp == NULL) {
			page_create_putback(pgcnt);
			kcage_cageout_wakeup();
		}
	} while (rpp == NULL);

	ASSERT(PP_ISNORELOC(rpp));

	result = page_relocate(&tpp, &rpp, 0, 1, &npgs, NULL);

	if (result == 0) {
		*replacement = rpp;
		if (pgcnt != npgs)
			panic("page_relocate_cage: partial relocation");
	}

	return (result);
}

/*
 * Release the page lock on a page, place on cachelist
 * tail if no longer mapped. Caller can let us know if
 * the page is known to be clean.
 */
int
page_release(page_t *pp, int checkmod)
{
	int status;

	ASSERT(PAGE_LOCKED(pp) && !PP_ISFREE(pp) &&
	    (pp->p_vnode != NULL));

	if (!hat_page_is_mapped(pp) && !IS_SWAPVP(pp->p_vnode) &&
	    ((PAGE_SHARED(pp) && page_tryupgrade(pp)) || PAGE_EXCL(pp)) &&
	    pp->p_lckcnt == 0 && pp->p_cowcnt == 0 &&
	    !hat_page_is_mapped(pp)) {

		/*
		 * If page is modified, unlock it
		 *
		 * (p_nrm & P_MOD) bit has the latest stuff because:
		 * (1) We found that this page doesn't have any mappings
		 *	_after_ holding SE_EXCL and
		 * (2) We didn't drop SE_EXCL lock after the check in (1)
		 */
		if (checkmod && hat_ismod(pp)) {
			page_unlock(pp);
			status = PGREL_MOD;
		} else {
			/*LINTED: constant in conditional context*/
			VN_DISPOSE(pp, B_FREE, 0, kcred);
			status = PGREL_CLEAN;
		}
	} else {
		page_unlock(pp);
		status = PGREL_NOTREL;
	}
	return (status);
}

/*
 * Given a constituent page, try to demote the large page on the freelist.
 *
 * Returns nonzero if the page could be demoted successfully. Returns with
 * the constituent page still locked.
 */
int
page_try_demote_free_pages(page_t *pp)
{
	page_t *rootpp = pp;
	pfn_t	pfn = page_pptonum(pp);
	spgcnt_t npgs;
	uint_t	szc = pp->p_szc;

	ASSERT(PP_ISFREE(pp));
	ASSERT(PAGE_EXCL(pp));

	/*
	 * Adjust rootpp and lock it, if `pp' is not the base
	 * constituent page.
	 */
	npgs = page_get_pagecnt(pp->p_szc);
	if (npgs == 1) {
		return (0);
	}

	if (!IS_P2ALIGNED(pfn, npgs)) {
		pfn = P2ALIGN(pfn, npgs);
		rootpp = page_numtopp_nolock(pfn);
	}

	if (pp != rootpp && !page_trylock(rootpp, SE_EXCL)) {
		return (0);
	}

	if (rootpp->p_szc != szc) {
		if (pp != rootpp)
			page_unlock(rootpp);
		return (0);
	}

	page_demote_free_pages(rootpp);

	if (pp != rootpp)
		page_unlock(rootpp);

	ASSERT(PP_ISFREE(pp));
	ASSERT(PAGE_EXCL(pp));
	return (1);
}

/*
 * Given a constituent page, try to demote the large page.
 *
 * Returns nonzero if the page could be demoted successfully. Returns with
 * the constituent page still locked.
 */
int
page_try_demote_pages(page_t *pp)
{
	page_t *tpp, *rootpp = pp;
	pfn_t	pfn = page_pptonum(pp);
	spgcnt_t i, npgs;
	uint_t	szc = pp->p_szc;
	vnode_t *vp = pp->p_vnode;

	ASSERT(PAGE_EXCL(pp));

	VM_STAT_ADD(pagecnt.pc_try_demote_pages[0]);

	if (pp->p_szc == 0) {
		VM_STAT_ADD(pagecnt.pc_try_demote_pages[1]);
		return (1);
	}

	if (vp != NULL && !IS_SWAPFSVP(vp) && !VN_ISKAS(vp)) {
		VM_STAT_ADD(pagecnt.pc_try_demote_pages[2]);
		page_demote_vp_pages(pp);
		ASSERT(pp->p_szc == 0);
		return (1);
	}

	/*
	 * Adjust rootpp if passed in is not the base
	 * constituent page.
	 */
	npgs = page_get_pagecnt(pp->p_szc);
	ASSERT(npgs > 1);
	if (!IS_P2ALIGNED(pfn, npgs)) {
		pfn = P2ALIGN(pfn, npgs);
		rootpp = page_numtopp_nolock(pfn);
		VM_STAT_ADD(pagecnt.pc_try_demote_pages[3]);
		ASSERT(rootpp->p_vnode != NULL);
		ASSERT(rootpp->p_szc == szc);
	}

	/*
	 * We can't demote kernel pages since we can't hat_unload()
	 * the mappings.
	 */
	if (VN_ISKAS(rootpp->p_vnode))
		return (0);

	/*
	 * Attempt to lock all constituent pages except the page passed
	 * in since it's already locked.
	 */
	for (tpp = rootpp, i = 0; i < npgs; i++, tpp++) {
		ASSERT(!PP_ISFREE(tpp));
		ASSERT(tpp->p_vnode != NULL);

		if (tpp != pp && !page_trylock(tpp, SE_EXCL))
			break;
		ASSERT(tpp->p_szc == rootpp->p_szc);
		ASSERT(page_pptonum(tpp) == page_pptonum(rootpp) + i);
	}

	/*
	 * If we failed to lock them all then unlock what we have
	 * locked so far and bail.
	 */
	if (i < npgs) {
		tpp = rootpp;
		while (i-- > 0) {
			if (tpp != pp)
				page_unlock(tpp);
			tpp++;
		}
		VM_STAT_ADD(pagecnt.pc_try_demote_pages[4]);
		return (0);
	}

	for (tpp = rootpp, i = 0; i < npgs; i++, tpp++) {
		ASSERT(PAGE_EXCL(tpp));
		ASSERT(tpp->p_slckcnt == 0);
		(void) hat_pageunload(tpp, HAT_FORCE_PGUNLOAD);
		tpp->p_szc = 0;
	}

	/*
	 * Unlock all pages except the page passed in.
	 */
	for (tpp = rootpp, i = 0; i < npgs; i++, tpp++) {
		ASSERT(!hat_page_is_mapped(tpp));
		if (tpp != pp)
			page_unlock(tpp);
	}

	VM_STAT_ADD(pagecnt.pc_try_demote_pages[5]);
	return (1);
}

/*
 * Called by page_free() and page_destroy() to demote the page size code
 * (p_szc) to 0 (since we can't just put a single PAGESIZE page with non zero
 * p_szc on free list, neither can we just clear p_szc of a single page_t
 * within a large page since it will break other code that relies on p_szc
 * being the same for all page_t's of a large page). Anonymous pages should
 * never end up here because anon_map_getpages() cannot deal with p_szc
 * changes after a single constituent page is locked.  While anonymous or
 * kernel large pages are demoted or freed the entire large page at a time
 * with all constituent pages locked EXCL for the file system pages we
 * have to be able to demote a large page (i.e. decrease all constituent pages
 * p_szc) with only just an EXCL lock on one of constituent pages. The reason
 * we can easily deal with anonymous page demotion the entire large page at a
 * time is that those operation originate at address space level and concern
 * the entire large page region with actual demotion only done when pages are
 * not shared with any other processes (therefore we can always get EXCL lock
 * on all anonymous constituent pages after clearing segment page
 * cache). However file system pages can be truncated or invalidated at a
 * PAGESIZE level from the file system side and end up in page_free() or
 * page_destroy() (we also allow only part of the large page to be SOFTLOCKed
 * and therefore pageout should be able to demote a large page by EXCL locking
 * any constituent page that is not under SOFTLOCK). In those cases we cannot
 * rely on being able to lock EXCL all constituent pages.
 *
 * To prevent szc changes on file system pages one has to lock all constituent
 * pages at least SHARED (or call page_szc_lock()). The only subsystem that
 * doesn't rely on locking all constituent pages (or using page_szc_lock()) to
 * prevent szc changes is hat layer that uses its own page level mlist
 * locks. hat assumes that szc doesn't change after mlist lock for a page is
 * taken. Therefore we need to change szc under hat level locks if we only
 * have an EXCL lock on a single constituent page and hat still references any
 * of constituent pages.  (Note we can't "ignore" hat layer by simply
 * hat_pageunload() all constituent pages without having EXCL locks on all of
 * constituent pages). We use hat_page_demote() call to safely demote szc of
 * all constituent pages under hat locks when we only have an EXCL lock on one
 * of constituent pages.
 *
 * This routine calls page_szc_lock() before calling hat_page_demote() to
 * allow segvn in one special case not to lock all constituent pages SHARED
 * before calling hat_memload_array() that relies on p_szc not changing even
 * before hat level mlist lock is taken.  In that case segvn uses
 * page_szc_lock() to prevent hat_page_demote() changing p_szc values.
 *
 * Anonymous or kernel page demotion still has to lock all pages exclusively
 * and do hat_pageunload() on all constituent pages before demoting the page
 * therefore there's no need for anonymous or kernel page demotion to use
 * hat_page_demote() mechanism.
 *
 * hat_page_demote() removes all large mappings that map pp and then decreases
 * p_szc starting from the last constituent page of the large page. By working
 * from the tail of a large page in pfn decreasing order allows one looking at
 * the root page to know that hat_page_demote() is done for root's szc area.
 * e.g. if a root page has szc 1 one knows it only has to lock all constituent
 * pages within szc 1 area to prevent szc changes because hat_page_demote()
 * that started on this page when it had szc > 1 is done for this szc 1 area.
 *
 * We are guaranteed that all constituent pages of pp's large page belong to
 * the same vnode with the consecutive offsets increasing in the direction of
 * the pfn i.e. the identity of constituent pages can't change until their
 * p_szc is decreased. Therefore it's safe for hat_page_demote() to remove
 * large mappings to pp even though we don't lock any constituent page except
 * pp (i.e. we won't unload e.g. kernel locked page).
 */
static void
page_demote_vp_pages(page_t *pp)
{
	kmutex_t *mtx;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(!PP_ISFREE(pp));
	ASSERT(pp->p_vnode != NULL);
	ASSERT(!IS_SWAPFSVP(pp->p_vnode));
	ASSERT(!PP_ISKAS(pp));

	VM_STAT_ADD(pagecnt.pc_demote_pages[0]);

	mtx = page_szc_lock(pp);
	if (mtx != NULL) {
		hat_page_demote(pp);
		mutex_exit(mtx);
	}
	ASSERT(pp->p_szc == 0);
}

/*
 * Mark any existing pages for migration in the given range
 */
void
page_mark_migrate(struct seg *seg, caddr_t addr, size_t len,
    struct anon_map *amp, ulong_t anon_index, vnode_t *vp,
    u_offset_t vnoff, int rflag)
{
	struct anon	*ap;
	vnode_t		*curvp;
	lgrp_t		*from;
	pgcnt_t		nlocked;
	u_offset_t	off;
	pfn_t		pfn;
	size_t		pgsz;
	size_t		segpgsz;
	pgcnt_t		pages;
	uint_t		pszc;
	page_t		*pp0, *pp;
	caddr_t		va;
	ulong_t		an_idx;
	anon_sync_obj_t	cookie;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * Don't do anything if don't need to do lgroup optimizations
	 * on this system
	 */
	if (!lgrp_optimizations())
		return;

	/*
	 * Align address and length to (potentially large) page boundary
	 */
	segpgsz = page_get_pagesize(seg->s_szc);
	addr = (caddr_t)P2ALIGN((uintptr_t)addr, segpgsz);
	if (rflag)
		len = P2ROUNDUP(len, segpgsz);

	/*
	 * Do one (large) page at a time
	 */
	va = addr;
	while (va < addr + len) {
		/*
		 * Lookup (root) page for vnode and offset corresponding to
		 * this virtual address
		 * Try anonmap first since there may be copy-on-write
		 * pages, but initialize vnode pointer and offset using
		 * vnode arguments just in case there isn't an amp.
		 */
		curvp = vp;
		off = vnoff + va - seg->s_base;
		if (amp) {
			ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
			an_idx = anon_index + seg_page(seg, va);
			anon_array_enter(amp, an_idx, &cookie);
			ap = anon_get_ptr(amp->ahp, an_idx);
			if (ap)
				swap_xlate(ap, &curvp, &off);
			anon_array_exit(&cookie);
			ANON_LOCK_EXIT(&amp->a_rwlock);
		}

		pp = NULL;
		if (curvp)
			pp = page_lookup(curvp, off, SE_SHARED);

		/*
		 * If there isn't a page at this virtual address,
		 * skip to next page
		 */
		if (pp == NULL) {
			va += PAGESIZE;
			continue;
		}

		/*
		 * Figure out which lgroup this page is in for kstats
		 */
		pfn = page_pptonum(pp);
		from = lgrp_pfn_to_lgrp(pfn);

		/*
		 * Get page size, and round up and skip to next page boundary
		 * if unaligned address
		 */
		pszc = pp->p_szc;
		pgsz = page_get_pagesize(pszc);
		pages = btop(pgsz);
		if (!IS_P2ALIGNED(va, pgsz) ||
		    !IS_P2ALIGNED(pfn, pages) ||
		    pgsz > segpgsz) {
			pgsz = MIN(pgsz, segpgsz);
			page_unlock(pp);
			pages = btop(P2END((uintptr_t)va, pgsz) -
			    (uintptr_t)va);
			va = (caddr_t)P2END((uintptr_t)va, pgsz);
			lgrp_stat_add(from->lgrp_id, LGRP_PMM_FAIL_PGS, pages);
			continue;
		}

		/*
		 * Upgrade to exclusive lock on page
		 */
		if (!page_tryupgrade(pp)) {
			page_unlock(pp);
			va += pgsz;
			lgrp_stat_add(from->lgrp_id, LGRP_PMM_FAIL_PGS,
			    btop(pgsz));
			continue;
		}

		pp0 = pp++;
		nlocked = 1;

		/*
		 * Lock constituent pages if this is large page
		 */
		if (pages > 1) {
			/*
			 * Lock all constituents except root page, since it
			 * should be locked already.
			 */
			for (; nlocked < pages; nlocked++) {
				if (!page_trylock(pp, SE_EXCL)) {
					break;
				}
				if (PP_ISFREE(pp) ||
				    pp->p_szc != pszc) {
					/*
					 * hat_page_demote() raced in with us.
					 */
					ASSERT(!IS_SWAPFSVP(curvp));
					page_unlock(pp);
					break;
				}
				pp++;
			}
		}

		/*
		 * If all constituent pages couldn't be locked,
		 * unlock pages locked so far and skip to next page.
		 */
		if (nlocked < pages) {
			while (pp0 < pp) {
				page_unlock(pp0++);
			}
			va += pgsz;
			lgrp_stat_add(from->lgrp_id, LGRP_PMM_FAIL_PGS,
			    btop(pgsz));
			continue;
		}

		/*
		 * hat_page_demote() can no longer happen
		 * since last cons page had the right p_szc after
		 * all cons pages were locked. all cons pages
		 * should now have the same p_szc.
		 */

		/*
		 * All constituent pages locked successfully, so mark
		 * large page for migration and unload the mappings of
		 * constituent pages, so a fault will occur on any part of the
		 * large page
		 */
		PP_SETMIGRATE(pp0);
		while (pp0 < pp) {
			(void) hat_pageunload(pp0, HAT_FORCE_PGUNLOAD);
			ASSERT(hat_page_getshare(pp0) == 0);
			page_unlock(pp0++);
		}
		lgrp_stat_add(from->lgrp_id, LGRP_PMM_PGS, nlocked);

		va += pgsz;
	}
}

/*
 * Migrate any pages that have been marked for migration in the given range
 */
void
page_migrate(
	struct seg	*seg,
	caddr_t		addr,
	page_t		**ppa,
	pgcnt_t		npages)
{
	lgrp_t		*from;
	lgrp_t		*to;
	page_t		*newpp;
	page_t		*pp;
	pfn_t		pfn;
	size_t		pgsz;
	spgcnt_t	page_cnt;
	spgcnt_t	i;
	uint_t		pszc;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	while (npages > 0) {
		pp = *ppa;
		pszc = pp->p_szc;
		pgsz = page_get_pagesize(pszc);
		page_cnt = btop(pgsz);

		/*
		 * Check to see whether this page is marked for migration
		 *
		 * Assume that root page of large page is marked for
		 * migration and none of the other constituent pages
		 * are marked.  This really simplifies clearing the
		 * migrate bit by not having to clear it from each
		 * constituent page.
		 *
		 * note we don't want to relocate an entire large page if
		 * someone is only using one subpage.
		 */
		if (npages < page_cnt)
			break;

		/*
		 * Is it marked for migration?
		 */
		if (!PP_ISMIGRATE(pp))
			goto next;

		/*
		 * Determine lgroups that page is being migrated between
		 */
		pfn = page_pptonum(pp);
		if (!IS_P2ALIGNED(pfn, page_cnt)) {
			break;
		}
		from = lgrp_pfn_to_lgrp(pfn);
		to = lgrp_mem_choose(seg, addr, pgsz);

		/*
		 * Need to get exclusive lock's to migrate
		 */
		for (i = 0; i < page_cnt; i++) {
			ASSERT(PAGE_LOCKED(ppa[i]));
			if (page_pptonum(ppa[i]) != pfn + i ||
			    ppa[i]->p_szc != pszc) {
				break;
			}
			if (!page_tryupgrade(ppa[i])) {
				lgrp_stat_add(from->lgrp_id,
				    LGRP_PM_FAIL_LOCK_PGS,
				    page_cnt);
				break;
			}

			/*
			 * Check to see whether we are trying to migrate
			 * page to lgroup where it is allocated already.
			 * If so, clear the migrate bit and skip to next
			 * page.
			 */
			if (i == 0 && to == from) {
				PP_CLRMIGRATE(ppa[0]);
				page_downgrade(ppa[0]);
				goto next;
			}
		}

		/*
		 * If all constituent pages couldn't be locked,
		 * unlock pages locked so far and skip to next page.
		 */
		if (i != page_cnt) {
			while (--i != -1) {
				page_downgrade(ppa[i]);
			}
			goto next;
		}

		(void) page_create_wait(page_cnt, PG_WAIT);
		newpp = page_get_replacement_page(pp, to, PGR_SAMESZC);
		if (newpp == NULL) {
			page_create_putback(page_cnt);
			for (i = 0; i < page_cnt; i++) {
				page_downgrade(ppa[i]);
			}
			lgrp_stat_add(to->lgrp_id, LGRP_PM_FAIL_ALLOC_PGS,
			    page_cnt);
			goto next;
		}
		ASSERT(newpp->p_szc == pszc);
		/*
		 * Clear migrate bit and relocate page
		 */
		PP_CLRMIGRATE(pp);
		if (page_relocate(&pp, &newpp, 0, 1, &page_cnt, to)) {
			panic("page_migrate: page_relocate failed");
		}
		ASSERT(page_cnt * PAGESIZE == pgsz);

		/*
		 * Keep stats for number of pages migrated from and to
		 * each lgroup
		 */
		lgrp_stat_add(from->lgrp_id, LGRP_PM_SRC_PGS, page_cnt);
		lgrp_stat_add(to->lgrp_id, LGRP_PM_DEST_PGS, page_cnt);
		/*
		 * update the page_t array we were passed in and
		 * unlink constituent pages of a large page.
		 */
		for (i = 0; i < page_cnt; ++i, ++pp) {
			ASSERT(PAGE_EXCL(newpp));
			ASSERT(newpp->p_szc == pszc);
			ppa[i] = newpp;
			pp = newpp;
			page_sub(&newpp, pp);
			page_downgrade(pp);
		}
		ASSERT(newpp == NULL);
next:
		addr += pgsz;
		ppa += page_cnt;
		npages -= page_cnt;
	}
}

uint_t page_reclaim_maxcnt = 60; /* max total iterations */
uint_t page_reclaim_nofree_maxcnt = 3; /* max iterations without progress */
/*
 * Reclaim/reserve availrmem for npages.
 * If there is not enough memory start reaping seg, kmem caches.
 * Start pageout scanner (via page_needfree()).
 * Exit after ~ MAX_CNT s regardless of how much memory has been released.
 * Note: There is no guarantee that any availrmem will be freed as
 * this memory typically is locked (kernel heap) or reserved for swap.
 * Also due to memory fragmentation kmem allocator may not be able
 * to free any memory (single user allocated buffer will prevent
 * freeing slab or a page).
 */
int
page_reclaim_mem(pgcnt_t npages, pgcnt_t epages, int adjust)
{
	int	i = 0;
	int	i_nofree = 0;
	int	ret = 0;
	pgcnt_t	deficit;
	pgcnt_t old_availrmem = 0;

	mutex_enter(&freemem_lock);
	while (availrmem < tune.t_minarmem + npages + epages &&
	    i++ < page_reclaim_maxcnt) {
		/* ensure we made some progress in the last few iterations */
		if (old_availrmem < availrmem) {
			old_availrmem = availrmem;
			i_nofree = 0;
		} else if (i_nofree++ >= page_reclaim_nofree_maxcnt) {
			break;
		}

		deficit = tune.t_minarmem + npages + epages - availrmem;
		mutex_exit(&freemem_lock);
		page_needfree(deficit);
		kmem_reap();
		delay(hz);
		page_needfree(-(spgcnt_t)deficit);
		mutex_enter(&freemem_lock);
	}

	if (adjust && (availrmem >= tune.t_minarmem + npages + epages)) {
		availrmem -= npages;
		ret = 1;
	}

	mutex_exit(&freemem_lock);

	return (ret);
}

/*
 * Search the memory segments to locate the desired page.  Within a
 * segment, pages increase linearly with one page structure per
 * physical page frame (size PAGESIZE).  The search begins
 * with the segment that was accessed last, to take advantage of locality.
 * If the hint misses, we start from the beginning of the sorted memseg list
 */


/*
 * Some data structures for pfn to pp lookup.
 */
ulong_t mhash_per_slot;
struct memseg *memseg_hash[N_MEM_SLOTS];

page_t *
page_numtopp_nolock(pfn_t pfnum)
{
	struct memseg *seg;
	page_t *pp;
	vm_cpu_data_t *vc;

	/*
	 * We need to disable kernel preemption while referencing the
	 * cpu_vm_data field in order to prevent us from being switched to
	 * another cpu and trying to reference it after it has been freed.
	 * This will keep us on cpu and prevent it from being removed while
	 * we are still on it.
	 *
	 * We may be caching a memseg in vc_pnum_memseg/vc_pnext_memseg
	 * which is being resued by DR who will flush those references
	 * before modifying the reused memseg.  See memseg_cpu_vm_flush().
	 */
	kpreempt_disable();
	vc = CPU->cpu_vm_data;
	ASSERT(vc != NULL);

	MEMSEG_STAT_INCR(nsearch);

	/* Try last winner first */
	if (((seg = vc->vc_pnum_memseg) != NULL) &&
	    (pfnum >= seg->pages_base) && (pfnum < seg->pages_end)) {
		MEMSEG_STAT_INCR(nlastwon);
		pp = seg->pages + (pfnum - seg->pages_base);
		if (pp->p_pagenum == pfnum) {
			kpreempt_enable();
			return ((page_t *)pp);
		}
	}

	/* Else Try hash */
	if (((seg = memseg_hash[MEMSEG_PFN_HASH(pfnum)]) != NULL) &&
	    (pfnum >= seg->pages_base) && (pfnum < seg->pages_end)) {
		MEMSEG_STAT_INCR(nhashwon);
		vc->vc_pnum_memseg = seg;
		pp = seg->pages + (pfnum - seg->pages_base);
		if (pp->p_pagenum == pfnum) {
			kpreempt_enable();
			return ((page_t *)pp);
		}
	}

	/* Else Brute force */
	for (seg = memsegs; seg != NULL; seg = seg->next) {
		if (pfnum >= seg->pages_base && pfnum < seg->pages_end) {
			vc->vc_pnum_memseg = seg;
			pp = seg->pages + (pfnum - seg->pages_base);
			if (pp->p_pagenum == pfnum) {
				kpreempt_enable();
				return ((page_t *)pp);
			}
		}
	}
	vc->vc_pnum_memseg = NULL;
	kpreempt_enable();
	MEMSEG_STAT_INCR(nnotfound);
	return ((page_t *)NULL);

}

struct memseg *
page_numtomemseg_nolock(pfn_t pfnum)
{
	struct memseg *seg;
	page_t *pp;

	/*
	 * We may be caching a memseg in vc_pnum_memseg/vc_pnext_memseg
	 * which is being resued by DR who will flush those references
	 * before modifying the reused memseg.  See memseg_cpu_vm_flush().
	 */
	kpreempt_disable();
	/* Try hash */
	if (((seg = memseg_hash[MEMSEG_PFN_HASH(pfnum)]) != NULL) &&
	    (pfnum >= seg->pages_base) && (pfnum < seg->pages_end)) {
		pp = seg->pages + (pfnum - seg->pages_base);
		if (pp->p_pagenum == pfnum) {
			kpreempt_enable();
			return (seg);
		}
	}

	/* Else Brute force */
	for (seg = memsegs; seg != NULL; seg = seg->next) {
		if (pfnum >= seg->pages_base && pfnum < seg->pages_end) {
			pp = seg->pages + (pfnum - seg->pages_base);
			if (pp->p_pagenum == pfnum) {
				kpreempt_enable();
				return (seg);
			}
		}
	}
	kpreempt_enable();
	return ((struct memseg *)NULL);
}

/*
 * Given a page and a count return the page struct that is
 * n structs away from the current one in the global page
 * list.
 *
 * This function wraps to the first page upon
 * reaching the end of the memseg list.
 */
page_t *
page_nextn(page_t *pp, ulong_t n)
{
	struct memseg *seg;
	page_t *ppn;
	vm_cpu_data_t *vc;

	/*
	 * We need to disable kernel preemption while referencing the
	 * cpu_vm_data field in order to prevent us from being switched to
	 * another cpu and trying to reference it after it has been freed.
	 * This will keep us on cpu and prevent it from being removed while
	 * we are still on it.
	 *
	 * We may be caching a memseg in vc_pnum_memseg/vc_pnext_memseg
	 * which is being resued by DR who will flush those references
	 * before modifying the reused memseg.  See memseg_cpu_vm_flush().
	 */
	kpreempt_disable();
	vc = (vm_cpu_data_t *)CPU->cpu_vm_data;

	ASSERT(vc != NULL);

	if (((seg = vc->vc_pnext_memseg) == NULL) ||
	    (seg->pages_base == seg->pages_end) ||
	    !(pp >= seg->pages && pp < seg->epages)) {

		for (seg = memsegs; seg; seg = seg->next) {
			if (pp >= seg->pages && pp < seg->epages)
				break;
		}

		if (seg == NULL) {
			/* Memory delete got in, return something valid. */
			/* TODO: fix me. */
			seg = memsegs;
			pp = seg->pages;
		}
	}

	/* check for wraparound - possible if n is large */
	while ((ppn = (pp + n)) >= seg->epages || ppn < pp) {
		n -= seg->epages - pp;
		seg = seg->next;
		if (seg == NULL)
			seg = memsegs;
		pp = seg->pages;
	}
	vc->vc_pnext_memseg = seg;
	kpreempt_enable();
	return (ppn);
}

/*
 * Initialize for a loop using page_next_scan_large().
 */
page_t *
page_next_scan_init(void **cookie)
{
	ASSERT(cookie != NULL);
	*cookie = (void *)memsegs;
	return ((page_t *)memsegs->pages);
}

/*
 * Return the next page in a scan of page_t's, assuming we want
 * to skip over sub-pages within larger page sizes.
 *
 * The cookie is used to keep track of the current memseg.
 */
page_t *
page_next_scan_large(
	page_t		*pp,
	ulong_t		*n,
	void		**cookie)
{
	struct memseg	*seg = (struct memseg *)*cookie;
	page_t		*new_pp;
	ulong_t		cnt;
	pfn_t		pfn;


	/*
	 * get the count of page_t's to skip based on the page size
	 */
	ASSERT(pp != NULL);
	if (pp->p_szc == 0) {
		cnt = 1;
	} else {
		pfn = page_pptonum(pp);
		cnt = page_get_pagecnt(pp->p_szc);
		cnt -= pfn & (cnt - 1);
	}
	*n += cnt;
	new_pp = pp + cnt;

	/*
	 * Catch if we went past the end of the current memory segment. If so,
	 * just move to the next segment with pages.
	 */
	if (new_pp >= seg->epages || seg->pages_base == seg->pages_end) {
		do {
			seg = seg->next;
			if (seg == NULL)
				seg = memsegs;
		} while (seg->pages_base == seg->pages_end);
		new_pp = seg->pages;
		*cookie = (void *)seg;
	}

	return (new_pp);
}


/*
 * Returns next page in list. Note: this function wraps
 * to the first page in the list upon reaching the end
 * of the list. Callers should be aware of this fact.
 */

/* We should change this be a #define */

page_t *
page_next(page_t *pp)
{
	return (page_nextn(pp, 1));
}

page_t *
page_first()
{
	return ((page_t *)memsegs->pages);
}


/*
 * This routine is called at boot with the initial memory configuration
 * and when memory is added or removed.
 */
void
build_pfn_hash()
{
	pfn_t cur;
	pgcnt_t index;
	struct memseg *pseg;
	int	i;

	/*
	 * Clear memseg_hash array.
	 * Since memory add/delete is designed to operate concurrently
	 * with normal operation, the hash rebuild must be able to run
	 * concurrently with page_numtopp_nolock(). To support this
	 * functionality, assignments to memseg_hash array members must
	 * be done atomically.
	 *
	 * NOTE: bzero() does not currently guarantee this for kernel
	 * threads, and cannot be used here.
	 */
	for (i = 0; i < N_MEM_SLOTS; i++)
		memseg_hash[i] = NULL;

	hat_kpm_mseghash_clear(N_MEM_SLOTS);

	/*
	 * Physmax is the last valid pfn.
	 */
	mhash_per_slot = (physmax + 1) >> MEM_HASH_SHIFT;
	for (pseg = memsegs; pseg != NULL; pseg = pseg->next) {
		index = MEMSEG_PFN_HASH(pseg->pages_base);
		cur = pseg->pages_base;
		do {
			if (index >= N_MEM_SLOTS)
				index = MEMSEG_PFN_HASH(cur);

			if (memseg_hash[index] == NULL ||
			    memseg_hash[index]->pages_base > pseg->pages_base) {
				memseg_hash[index] = pseg;
				hat_kpm_mseghash_update(index, pseg);
			}
			cur += mhash_per_slot;
			index++;
		} while (cur < pseg->pages_end);
	}
}

/*
 * Return the pagenum for the pp
 */
pfn_t
page_pptonum(page_t *pp)
{
	return (pp->p_pagenum);
}

/*
 * interface to the referenced and modified etc bits
 * in the PSM part of the page struct
 * when no locking is desired.
 */
void
page_set_props(page_t *pp, uint_t flags)
{
	ASSERT((flags & ~(P_MOD | P_REF | P_RO)) == 0);
	pp->p_nrm |= (uchar_t)flags;
}

void
page_clr_all_props(page_t *pp)
{
	pp->p_nrm = 0;
}

/*
 * Clear p_lckcnt and p_cowcnt, adjusting freemem if required.
 */
int
page_clear_lck_cow(page_t *pp, int adjust)
{
	int	f_amount;

	ASSERT(PAGE_EXCL(pp));

	/*
	 * The page_struct_lock need not be acquired here since
	 * we require the caller hold the page exclusively locked.
	 */
	f_amount = 0;
	if (pp->p_lckcnt) {
		f_amount = 1;
		pp->p_lckcnt = 0;
	}
	if (pp->p_cowcnt) {
		f_amount += pp->p_cowcnt;
		pp->p_cowcnt = 0;
	}

	if (adjust && f_amount) {
		mutex_enter(&freemem_lock);
		availrmem += f_amount;
		mutex_exit(&freemem_lock);
	}

	return (f_amount);
}

/*
 * The following functions is called from free_vp_pages()
 * for an inexact estimate of a newly free'd page...
 */
ulong_t
page_share_cnt(page_t *pp)
{
	return (hat_page_getshare(pp));
}

int
page_isshared(page_t *pp)
{
	return (hat_page_checkshare(pp, 1));
}

int
page_isfree(page_t *pp)
{
	return (PP_ISFREE(pp));
}

int
page_isref(page_t *pp)
{
	return (hat_page_getattr(pp, P_REF));
}

int
page_ismod(page_t *pp)
{
	return (hat_page_getattr(pp, P_MOD));
}

/*
 * The following code all currently relates to the page capture logic:
 *
 * This logic is used for cases where there is a desire to claim a certain
 * physical page in the system for the caller.  As it may not be possible
 * to capture the page immediately, the p_toxic bits are used in the page
 * structure to indicate that someone wants to capture this page.  When the
 * page gets unlocked, the toxic flag will be noted and an attempt to capture
 * the page will be made.  If it is successful, the original callers callback
 * will be called with the page to do with it what they please.
 *
 * There is also an async thread which wakes up to attempt to capture
 * pages occasionally which have the capture bit set.  All of the pages which
 * need to be captured asynchronously have been inserted into the
 * page_capture_hash and thus this thread walks that hash list.  Items in the
 * hash have an expiration time so this thread handles that as well by removing
 * the item from the hash if it has expired.
 *
 * Some important things to note are:
 * - if the PR_CAPTURE bit is set on a page, then the page is in the
 *   page_capture_hash.  The page_capture_hash_head.pchh_mutex is needed
 *   to set and clear this bit, and while the lock is held is the only time
 *   you can add or remove an entry from the hash.
 * - the PR_CAPTURE bit can only be set and cleared while holding the
 *   page_capture_hash_head.pchh_mutex
 * - the t_flag field of the thread struct is used with the T_CAPTURING
 *   flag to prevent recursion while dealing with large pages.
 * - pages which need to be retired never expire on the page_capture_hash.
 */

static void page_capture_thread(void);
static kthread_t *pc_thread_id;
kcondvar_t pc_cv;
static kmutex_t pc_thread_mutex;
static clock_t pc_thread_shortwait;
static clock_t pc_thread_longwait;
static int pc_thread_retry;

struct page_capture_callback pc_cb[PC_NUM_CALLBACKS];

/* Note that this is a circular linked list */
typedef struct page_capture_hash_bucket {
	page_t *pp;
	uchar_t szc;
	uchar_t pri;
	uint_t flags;
	clock_t expires;	/* lbolt at which this request expires. */
	void *datap;		/* Cached data passed in for callback */
	struct page_capture_hash_bucket *next;
	struct page_capture_hash_bucket *prev;
} page_capture_hash_bucket_t;

#define	PC_PRI_HI	0	/* capture now */
#define	PC_PRI_LO	1	/* capture later */
#define	PC_NUM_PRI	2

#define	PAGE_CAPTURE_PRIO(pp) (PP_ISRAF(pp) ? PC_PRI_LO : PC_PRI_HI)


/*
 * Each hash bucket will have it's own mutex and two lists which are:
 * active (0):	represents requests which have not been processed by
 *		the page_capture async thread yet.
 * walked (1):	represents requests which have been processed by the
 *		page_capture async thread within it's given walk of this bucket.
 *
 * These are all needed so that we can synchronize all async page_capture
 * events.  When the async thread moves to a new bucket, it will append the
 * walked list to the active list and walk each item one at a time, moving it
 * from the active list to the walked list.  Thus if there is an async request
 * outstanding for a given page, it will always be in one of the two lists.
 * New requests will always be added to the active list.
 * If we were not able to capture a page before the request expired, we'd free
 * up the request structure which would indicate to page_capture that there is
 * no longer a need for the given page, and clear the PR_CAPTURE flag if
 * possible.
 */
typedef struct page_capture_hash_head {
	kmutex_t pchh_mutex;
	uint_t num_pages[PC_NUM_PRI];
	page_capture_hash_bucket_t lists[2]; /* sentinel nodes */
} page_capture_hash_head_t;

#ifdef DEBUG
#define	NUM_PAGE_CAPTURE_BUCKETS 4
#else
#define	NUM_PAGE_CAPTURE_BUCKETS 64
#endif

page_capture_hash_head_t page_capture_hash[NUM_PAGE_CAPTURE_BUCKETS];

/* for now use a very simple hash based upon the size of a page struct */
#define	PAGE_CAPTURE_HASH(pp)	\
	((int)(((uintptr_t)pp >> 7) & (NUM_PAGE_CAPTURE_BUCKETS - 1)))

extern pgcnt_t swapfs_minfree;

int page_trycapture(page_t *pp, uint_t szc, uint_t flags, void *datap);

/*
 * a callback function is required for page capture requests.
 */
void
page_capture_register_callback(uint_t index, clock_t duration,
    int (*cb_func)(page_t *, void *, uint_t))
{
	ASSERT(pc_cb[index].cb_active == 0);
	ASSERT(cb_func != NULL);
	rw_enter(&pc_cb[index].cb_rwlock, RW_WRITER);
	pc_cb[index].duration = duration;
	pc_cb[index].cb_func = cb_func;
	pc_cb[index].cb_active = 1;
	rw_exit(&pc_cb[index].cb_rwlock);
}

void
page_capture_unregister_callback(uint_t index)
{
	int i, j;
	struct page_capture_hash_bucket *bp1;
	struct page_capture_hash_bucket *bp2;
	struct page_capture_hash_bucket *head = NULL;
	uint_t flags = (1 << index);

	rw_enter(&pc_cb[index].cb_rwlock, RW_WRITER);
	ASSERT(pc_cb[index].cb_active == 1);
	pc_cb[index].duration = 0;	/* Paranoia */
	pc_cb[index].cb_func = NULL;	/* Paranoia */
	pc_cb[index].cb_active = 0;
	rw_exit(&pc_cb[index].cb_rwlock);

	/*
	 * Just move all the entries to a private list which we can walk
	 * through without the need to hold any locks.
	 * No more requests can get added to the hash lists for this consumer
	 * as the cb_active field for the callback has been cleared.
	 */
	for (i = 0; i < NUM_PAGE_CAPTURE_BUCKETS; i++) {
		mutex_enter(&page_capture_hash[i].pchh_mutex);
		for (j = 0; j < 2; j++) {
			bp1 = page_capture_hash[i].lists[j].next;
			/* walk through all but first (sentinel) element */
			while (bp1 != &page_capture_hash[i].lists[j]) {
				bp2 = bp1;
				if (bp2->flags & flags) {
					bp1 = bp2->next;
					bp1->prev = bp2->prev;
					bp2->prev->next = bp1;
					bp2->next = head;
					head = bp2;
					/*
					 * Clear the PR_CAPTURE bit as we
					 * hold appropriate locks here.
					 */
					page_clrtoxic(head->pp, PR_CAPTURE);
					page_capture_hash[i].
					    num_pages[bp2->pri]--;
					continue;
				}
				bp1 = bp1->next;
			}
		}
		mutex_exit(&page_capture_hash[i].pchh_mutex);
	}

	while (head != NULL) {
		bp1 = head;
		head = head->next;
		kmem_free(bp1, sizeof (*bp1));
	}
}


/*
 * Find pp in the active list and move it to the walked list if it
 * exists.
 * Note that most often pp should be at the front of the active list
 * as it is currently used and thus there is no other sort of optimization
 * being done here as this is a linked list data structure.
 * Returns 1 on successful move or 0 if page could not be found.
 */
static int
page_capture_move_to_walked(page_t *pp)
{
	page_capture_hash_bucket_t *bp;
	int index;

	index = PAGE_CAPTURE_HASH(pp);

	mutex_enter(&page_capture_hash[index].pchh_mutex);
	bp = page_capture_hash[index].lists[0].next;
	while (bp != &page_capture_hash[index].lists[0]) {
		if (bp->pp == pp) {
			/* Remove from old list */
			bp->next->prev = bp->prev;
			bp->prev->next = bp->next;

			/* Add to new list */
			bp->next = page_capture_hash[index].lists[1].next;
			bp->prev = &page_capture_hash[index].lists[1];
			page_capture_hash[index].lists[1].next = bp;
			bp->next->prev = bp;

			/*
			 * There is a small probability of page on a free
			 * list being retired while being allocated
			 * and before P_RAF is set on it. The page may
			 * end up marked as high priority request instead
			 * of low priority request.
			 * If P_RAF page is not marked as low priority request
			 * change it to low priority request.
			 */
			page_capture_hash[index].num_pages[bp->pri]--;
			bp->pri = PAGE_CAPTURE_PRIO(pp);
			page_capture_hash[index].num_pages[bp->pri]++;
			mutex_exit(&page_capture_hash[index].pchh_mutex);
			return (1);
		}
		bp = bp->next;
	}
	mutex_exit(&page_capture_hash[index].pchh_mutex);
	return (0);
}

/*
 * Add a new entry to the page capture hash.  The only case where a new
 * entry is not added is when the page capture consumer is no longer registered.
 * In this case, we'll silently not add the page to the hash.  We know that
 * page retire will always be registered for the case where we are currently
 * unretiring a page and thus there are no conflicts.
 */
static void
page_capture_add_hash(page_t *pp, uint_t szc, uint_t flags, void *datap)
{
	page_capture_hash_bucket_t *bp1;
	page_capture_hash_bucket_t *bp2;
	int index;
	int cb_index;
	int i;
	uchar_t pri;
#ifdef DEBUG
	page_capture_hash_bucket_t *tp1;
	int l;
#endif

	ASSERT(!(flags & CAPTURE_ASYNC));

	bp1 = kmem_alloc(sizeof (struct page_capture_hash_bucket), KM_SLEEP);

	bp1->pp = pp;
	bp1->szc = szc;
	bp1->flags = flags;
	bp1->datap = datap;

	for (cb_index = 0; cb_index < PC_NUM_CALLBACKS; cb_index++) {
		if ((flags >> cb_index) & 1) {
			break;
		}
	}

	ASSERT(cb_index != PC_NUM_CALLBACKS);

	rw_enter(&pc_cb[cb_index].cb_rwlock, RW_READER);
	if (pc_cb[cb_index].cb_active) {
		if (pc_cb[cb_index].duration == -1) {
			bp1->expires = (clock_t)-1;
		} else {
			bp1->expires = ddi_get_lbolt() +
			    pc_cb[cb_index].duration;
		}
	} else {
		/* There's no callback registered so don't add to the hash */
		rw_exit(&pc_cb[cb_index].cb_rwlock);
		kmem_free(bp1, sizeof (*bp1));
		return;
	}

	index = PAGE_CAPTURE_HASH(pp);

	/*
	 * Only allow capture flag to be modified under this mutex.
	 * Prevents multiple entries for same page getting added.
	 */
	mutex_enter(&page_capture_hash[index].pchh_mutex);

	/*
	 * if not already on the hash, set capture bit and add to the hash
	 */
	if (!(pp->p_toxic & PR_CAPTURE)) {
#ifdef DEBUG
		/* Check for duplicate entries */
		for (l = 0; l < 2; l++) {
			tp1 = page_capture_hash[index].lists[l].next;
			while (tp1 != &page_capture_hash[index].lists[l]) {
				if (tp1->pp == pp) {
					panic("page pp 0x%p already on hash "
					    "at 0x%p\n",
					    (void *)pp, (void *)tp1);
				}
				tp1 = tp1->next;
			}
		}

#endif
		page_settoxic(pp, PR_CAPTURE);
		pri = PAGE_CAPTURE_PRIO(pp);
		bp1->pri = pri;
		bp1->next = page_capture_hash[index].lists[0].next;
		bp1->prev = &page_capture_hash[index].lists[0];
		bp1->next->prev = bp1;
		page_capture_hash[index].lists[0].next = bp1;
		page_capture_hash[index].num_pages[pri]++;
		if (flags & CAPTURE_RETIRE) {
			page_retire_incr_pend_count(datap);
		}
		mutex_exit(&page_capture_hash[index].pchh_mutex);
		rw_exit(&pc_cb[cb_index].cb_rwlock);
		cv_signal(&pc_cv);
		return;
	}

	/*
	 * A page retire request will replace any other request.
	 * A second physmem request which is for a different process than
	 * the currently registered one will be dropped as there is
	 * no way to hold the private data for both calls.
	 * In the future, once there are more callers, this will have to
	 * be worked out better as there needs to be private storage for
	 * at least each type of caller (maybe have datap be an array of
	 * *void's so that we can index based upon callers index).
	 */

	/* walk hash list to update expire time */
	for (i = 0; i < 2; i++) {
		bp2 = page_capture_hash[index].lists[i].next;
		while (bp2 != &page_capture_hash[index].lists[i]) {
			if (bp2->pp == pp) {
				if (flags & CAPTURE_RETIRE) {
					if (!(bp2->flags & CAPTURE_RETIRE)) {
						page_retire_incr_pend_count(
						    datap);
						bp2->flags = flags;
						bp2->expires = bp1->expires;
						bp2->datap = datap;
					}
				} else {
					ASSERT(flags & CAPTURE_PHYSMEM);
					if (!(bp2->flags & CAPTURE_RETIRE) &&
					    (datap == bp2->datap)) {
						bp2->expires = bp1->expires;
					}
				}
				mutex_exit(&page_capture_hash[index].
				    pchh_mutex);
				rw_exit(&pc_cb[cb_index].cb_rwlock);
				kmem_free(bp1, sizeof (*bp1));
				return;
			}
			bp2 = bp2->next;
		}
	}

	/*
	 * the PR_CAPTURE flag is protected by the page_capture_hash mutexes
	 * and thus it either has to be set or not set and can't change
	 * while holding the mutex above.
	 */
	panic("page_capture_add_hash, PR_CAPTURE flag set on pp %p\n",
	    (void *)pp);
}

/*
 * We have a page in our hands, lets try and make it ours by turning
 * it into a clean page like it had just come off the freelists.
 *
 * Returns 0 on success, with the page still EXCL locked.
 * On failure, the page will be unlocked, and returns EAGAIN
 */
static int
page_capture_clean_page(page_t *pp)
{
	page_t *newpp;
	int skip_unlock = 0;
	spgcnt_t count;
	page_t *tpp;
	int ret = 0;
	int extra;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(!PP_RETIRED(pp));
	ASSERT(curthread->t_flag & T_CAPTURING);

	if (PP_ISFREE(pp)) {
		if (!page_reclaim(pp, NULL)) {
			skip_unlock = 1;
			ret = EAGAIN;
			goto cleanup;
		}
		ASSERT(pp->p_szc == 0);
		if (pp->p_vnode != NULL) {
			/*
			 * Since this page came from the
			 * cachelist, we must destroy the
			 * old vnode association.
			 */
			page_hashout(pp, NULL);
		}
		goto cleanup;
	}

	/*
	 * If we know page_relocate will fail, skip it
	 * It could still fail due to a UE on another page but we
	 * can't do anything about that.
	 */
	if (pp->p_toxic & PR_UE) {
		goto skip_relocate;
	}

	/*
	 * It's possible that pages can not have a vnode as fsflush comes
	 * through and cleans up these pages.  It's ugly but that's how it is.
	 */
	if (pp->p_vnode == NULL) {
		goto skip_relocate;
	}

	/*
	 * Page was not free, so lets try to relocate it.
	 * page_relocate only works with root pages, so if this is not a root
	 * page, we need to demote it to try and relocate it.
	 * Unfortunately this is the best we can do right now.
	 */
	newpp = NULL;
	if ((pp->p_szc > 0) && (pp != PP_PAGEROOT(pp))) {
		if (page_try_demote_pages(pp) == 0) {
			ret = EAGAIN;
			goto cleanup;
		}
	}
	ret = page_relocate(&pp, &newpp, 1, 0, &count, NULL);
	if (ret == 0) {
		page_t *npp;
		/* unlock the new page(s) */
		while (count-- > 0) {
			ASSERT(newpp != NULL);
			npp = newpp;
			page_sub(&newpp, npp);
			page_unlock(npp);
		}
		ASSERT(newpp == NULL);
		/*
		 * Check to see if the page we have is too large.
		 * If so, demote it freeing up the extra pages.
		 */
		if (pp->p_szc > 0) {
			/* For now demote extra pages to szc == 0 */
			extra = page_get_pagecnt(pp->p_szc) - 1;
			while (extra > 0) {
				tpp = pp->p_next;
				page_sub(&pp, tpp);
				tpp->p_szc = 0;
				page_free(tpp, 1);
				extra--;
			}
			/* Make sure to set our page to szc 0 as well */
			ASSERT(pp->p_next == pp && pp->p_prev == pp);
			pp->p_szc = 0;
		}
		goto cleanup;
	} else if (ret == EIO) {
		ret = EAGAIN;
		goto cleanup;
	} else {
		/*
		 * Need to reset return type as we failed to relocate the page
		 * but that does not mean that some of the next steps will not
		 * work.
		 */
		ret = 0;
	}

skip_relocate:

	if (pp->p_szc > 0) {
		if (page_try_demote_pages(pp) == 0) {
			ret = EAGAIN;
			goto cleanup;
		}
	}

	ASSERT(pp->p_szc == 0);

	if (hat_ismod(pp)) {
		ret = EAGAIN;
		goto cleanup;
	}
	if (PP_ISKAS(pp)) {
		ret = EAGAIN;
		goto cleanup;
	}
	if (pp->p_lckcnt || pp->p_cowcnt) {
		ret = EAGAIN;
		goto cleanup;
	}

	(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
	ASSERT(!hat_page_is_mapped(pp));

	if (hat_ismod(pp)) {
		/*
		 * This is a semi-odd case as the page is now modified but not
		 * mapped as we just unloaded the mappings above.
		 */
		ret = EAGAIN;
		goto cleanup;
	}
	if (pp->p_vnode != NULL) {
		page_hashout(pp, NULL);
	}

	/*
	 * At this point, the page should be in a clean state and
	 * we can do whatever we want with it.
	 */

cleanup:
	if (ret != 0) {
		if (!skip_unlock) {
			page_unlock(pp);
		}
	} else {
		ASSERT(pp->p_szc == 0);
		ASSERT(PAGE_EXCL(pp));

		pp->p_next = pp;
		pp->p_prev = pp;
	}
	return (ret);
}

/*
 * Various callers of page_trycapture() can have different restrictions upon
 * what memory they have access to.
 * Returns 0 on success, with the following error codes on failure:
 *      EPERM - The requested page is long term locked, and thus repeated
 *              requests to capture this page will likely fail.
 *      ENOMEM - There was not enough free memory in the system to safely
 *              map the requested page.
 *      ENOENT - The requested page was inside the kernel cage, and the
 *              PHYSMEM_CAGE flag was not set.
 */
int
page_capture_pre_checks(page_t *pp, uint_t flags)
{
	ASSERT(pp != NULL);

#if defined(__sparc)
	if (pp->p_vnode == &promvp) {
		return (EPERM);
	}

	if (PP_ISNORELOC(pp) && !(flags & CAPTURE_GET_CAGE) &&
	    (flags & CAPTURE_PHYSMEM)) {
		return (ENOENT);
	}

	if (PP_ISNORELOCKERNEL(pp)) {
		return (EPERM);
	}
#else
	if (PP_ISKAS(pp)) {
		return (EPERM);
	}
#endif /* __sparc */

	/* only physmem currently has the restrictions checked below */
	if (!(flags & CAPTURE_PHYSMEM)) {
		return (0);
	}

	if (availrmem < swapfs_minfree) {
		/*
		 * We won't try to capture this page as we are
		 * running low on memory.
		 */
		return (ENOMEM);
	}
	return (0);
}

/*
 * Once we have a page in our mits, go ahead and complete the capture
 * operation.
 * Returns 1 on failure where page is no longer needed
 * Returns 0 on success
 * Returns -1 if there was a transient failure.
 * Failure cases must release the SE_EXCL lock on pp (usually via page_free).
 */
int
page_capture_take_action(page_t *pp, uint_t flags, void *datap)
{
	int cb_index;
	int ret = 0;
	page_capture_hash_bucket_t *bp1;
	page_capture_hash_bucket_t *bp2;
	int index;
	int found = 0;
	int i;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(curthread->t_flag & T_CAPTURING);

	for (cb_index = 0; cb_index < PC_NUM_CALLBACKS; cb_index++) {
		if ((flags >> cb_index) & 1) {
			break;
		}
	}
	ASSERT(cb_index < PC_NUM_CALLBACKS);

	/*
	 * Remove the entry from the page_capture hash, but don't free it yet
	 * as we may need to put it back.
	 * Since we own the page at this point in time, we should find it
	 * in the hash if this is an ASYNC call.  If we don't it's likely
	 * that the page_capture_async() thread decided that this request
	 * had expired, in which case we just continue on.
	 */
	if (flags & CAPTURE_ASYNC) {

		index = PAGE_CAPTURE_HASH(pp);

		mutex_enter(&page_capture_hash[index].pchh_mutex);
		for (i = 0; i < 2 && !found; i++) {
			bp1 = page_capture_hash[index].lists[i].next;
			while (bp1 != &page_capture_hash[index].lists[i]) {
				if (bp1->pp == pp) {
					bp1->next->prev = bp1->prev;
					bp1->prev->next = bp1->next;
					page_capture_hash[index].
					    num_pages[bp1->pri]--;
					page_clrtoxic(pp, PR_CAPTURE);
					found = 1;
					break;
				}
				bp1 = bp1->next;
			}
		}
		mutex_exit(&page_capture_hash[index].pchh_mutex);
	}

	/* Synchronize with the unregister func. */
	rw_enter(&pc_cb[cb_index].cb_rwlock, RW_READER);
	if (!pc_cb[cb_index].cb_active) {
		page_free(pp, 1);
		rw_exit(&pc_cb[cb_index].cb_rwlock);
		if (found) {
			kmem_free(bp1, sizeof (*bp1));
		}
		return (1);
	}

	/*
	 * We need to remove the entry from the page capture hash and turn off
	 * the PR_CAPTURE bit before calling the callback.  We'll need to cache
	 * the entry here, and then based upon the return value, cleanup
	 * appropriately or re-add it to the hash, making sure that someone else
	 * hasn't already done so.
	 * It should be rare for the callback to fail and thus it's ok for
	 * the failure path to be a bit complicated as the success path is
	 * cleaner and the locking rules are easier to follow.
	 */

	ret = pc_cb[cb_index].cb_func(pp, datap, flags);

	rw_exit(&pc_cb[cb_index].cb_rwlock);

	/*
	 * If this was an ASYNC request, we need to cleanup the hash if the
	 * callback was successful or if the request was no longer valid.
	 * For non-ASYNC requests, we return failure to map and the caller
	 * will take care of adding the request to the hash.
	 * Note also that the callback itself is responsible for the page
	 * at this point in time in terms of locking ...  The most common
	 * case for the failure path should just be a page_free.
	 */
	if (ret >= 0) {
		if (found) {
			if (bp1->flags & CAPTURE_RETIRE) {
				page_retire_decr_pend_count(datap);
			}
			kmem_free(bp1, sizeof (*bp1));
		}
		return (ret);
	}
	if (!found) {
		return (ret);
	}

	ASSERT(flags & CAPTURE_ASYNC);

	/*
	 * Check for expiration time first as we can just free it up if it's
	 * expired.
	 */
	if (ddi_get_lbolt() > bp1->expires && bp1->expires != -1) {
		kmem_free(bp1, sizeof (*bp1));
		return (ret);
	}

	/*
	 * The callback failed and there used to be an entry in the hash for
	 * this page, so we need to add it back to the hash.
	 */
	mutex_enter(&page_capture_hash[index].pchh_mutex);
	if (!(pp->p_toxic & PR_CAPTURE)) {
		/* just add bp1 back to head of walked list */
		page_settoxic(pp, PR_CAPTURE);
		bp1->next = page_capture_hash[index].lists[1].next;
		bp1->prev = &page_capture_hash[index].lists[1];
		bp1->next->prev = bp1;
		bp1->pri = PAGE_CAPTURE_PRIO(pp);
		page_capture_hash[index].lists[1].next = bp1;
		page_capture_hash[index].num_pages[bp1->pri]++;
		mutex_exit(&page_capture_hash[index].pchh_mutex);
		return (ret);
	}

	/*
	 * Otherwise there was a new capture request added to list
	 * Need to make sure that our original data is represented if
	 * appropriate.
	 */
	for (i = 0; i < 2; i++) {
		bp2 = page_capture_hash[index].lists[i].next;
		while (bp2 != &page_capture_hash[index].lists[i]) {
			if (bp2->pp == pp) {
				if (bp1->flags & CAPTURE_RETIRE) {
					if (!(bp2->flags & CAPTURE_RETIRE)) {
						bp2->szc = bp1->szc;
						bp2->flags = bp1->flags;
						bp2->expires = bp1->expires;
						bp2->datap = bp1->datap;
					}
				} else {
					ASSERT(bp1->flags & CAPTURE_PHYSMEM);
					if (!(bp2->flags & CAPTURE_RETIRE)) {
						bp2->szc = bp1->szc;
						bp2->flags = bp1->flags;
						bp2->expires = bp1->expires;
						bp2->datap = bp1->datap;
					}
				}
				page_capture_hash[index].num_pages[bp2->pri]--;
				bp2->pri = PAGE_CAPTURE_PRIO(pp);
				page_capture_hash[index].num_pages[bp2->pri]++;
				mutex_exit(&page_capture_hash[index].
				    pchh_mutex);
				kmem_free(bp1, sizeof (*bp1));
				return (ret);
			}
			bp2 = bp2->next;
		}
	}
	panic("PR_CAPTURE set but not on hash for pp 0x%p\n", (void *)pp);
	/*NOTREACHED*/
}

/*
 * Try to capture the given page for the caller specified in the flags
 * parameter.  The page will either be captured and handed over to the
 * appropriate callback, or will be queued up in the page capture hash
 * to be captured asynchronously.
 * If the current request is due to an async capture, the page must be
 * exclusively locked before calling this function.
 * Currently szc must be 0 but in the future this should be expandable to
 * other page sizes.
 * Returns 0 on success, with the following error codes on failure:
 *      EPERM - The requested page is long term locked, and thus repeated
 *              requests to capture this page will likely fail.
 *      ENOMEM - There was not enough free memory in the system to safely
 *              map the requested page.
 *      ENOENT - The requested page was inside the kernel cage, and the
 *              CAPTURE_GET_CAGE flag was not set.
 *	EAGAIN - The requested page could not be capturead at this point in
 *		time but future requests will likely work.
 *	EBUSY - The requested page is retired and the CAPTURE_GET_RETIRED flag
 *		was not set.
 */
int
page_itrycapture(page_t *pp, uint_t szc, uint_t flags, void *datap)
{
	int ret;
	int cb_index;

	if (flags & CAPTURE_ASYNC) {
		ASSERT(PAGE_EXCL(pp));
		goto async;
	}

	/* Make sure there's enough availrmem ... */
	ret = page_capture_pre_checks(pp, flags);
	if (ret != 0) {
		return (ret);
	}

	if (!page_trylock(pp, SE_EXCL)) {
		for (cb_index = 0; cb_index < PC_NUM_CALLBACKS; cb_index++) {
			if ((flags >> cb_index) & 1) {
				break;
			}
		}
		ASSERT(cb_index < PC_NUM_CALLBACKS);
		ret = EAGAIN;
		/* Special case for retired pages */
		if (PP_RETIRED(pp)) {
			if (flags & CAPTURE_GET_RETIRED) {
				if (!page_unretire_pp(pp, PR_UNR_TEMP)) {
					/*
					 * Need to set capture bit and add to
					 * hash so that the page will be
					 * retired when freed.
					 */
					page_capture_add_hash(pp, szc,
					    CAPTURE_RETIRE, NULL);
					ret = 0;
					goto own_page;
				}
			} else {
				return (EBUSY);
			}
		}
		page_capture_add_hash(pp, szc, flags, datap);
		return (ret);
	}

async:
	ASSERT(PAGE_EXCL(pp));

	/* Need to check for physmem async requests that availrmem is sane */
	if ((flags & (CAPTURE_ASYNC | CAPTURE_PHYSMEM)) ==
	    (CAPTURE_ASYNC | CAPTURE_PHYSMEM) &&
	    (availrmem < swapfs_minfree)) {
		page_unlock(pp);
		return (ENOMEM);
	}

	ret = page_capture_clean_page(pp);

	if (ret != 0) {
		/* We failed to get the page, so lets add it to the hash */
		if (!(flags & CAPTURE_ASYNC)) {
			page_capture_add_hash(pp, szc, flags, datap);
		}
		return (ret);
	}

own_page:
	ASSERT(PAGE_EXCL(pp));
	ASSERT(pp->p_szc == 0);

	/* Call the callback */
	ret = page_capture_take_action(pp, flags, datap);

	if (ret == 0) {
		return (0);
	}

	/*
	 * Note that in the failure cases from page_capture_take_action, the
	 * EXCL lock will have already been dropped.
	 */
	if ((ret == -1) && (!(flags & CAPTURE_ASYNC))) {
		page_capture_add_hash(pp, szc, flags, datap);
	}
	return (EAGAIN);
}

int
page_trycapture(page_t *pp, uint_t szc, uint_t flags, void *datap)
{
	int ret;

	curthread->t_flag |= T_CAPTURING;
	ret = page_itrycapture(pp, szc, flags, datap);
	curthread->t_flag &= ~T_CAPTURING; /* xor works as we know its set */
	return (ret);
}

/*
 * When unlocking a page which has the PR_CAPTURE bit set, this routine
 * gets called to try and capture the page.
 */
void
page_unlock_capture(page_t *pp)
{
	page_capture_hash_bucket_t *bp;
	int index;
	int i;
	uint_t szc;
	uint_t flags = 0;
	void *datap;
	kmutex_t *mp;
	extern vnode_t retired_pages;

	/*
	 * We need to protect against a possible deadlock here where we own
	 * the vnode page hash mutex and want to acquire it again as there
	 * are locations in the code, where we unlock a page while holding
	 * the mutex which can lead to the page being captured and eventually
	 * end up here.  As we may be hashing out the old page and hashing into
	 * the retire vnode, we need to make sure we don't own them.
	 * Other callbacks who do hash operations also need to make sure that
	 * before they hashin to a vnode that they do not currently own the
	 * vphm mutex otherwise there will be a panic.
	 */
	if (mutex_owned(page_vnode_mutex(&retired_pages))) {
		page_unlock_nocapture(pp);
		return;
	}
	if (pp->p_vnode != NULL && mutex_owned(page_vnode_mutex(pp->p_vnode))) {
		page_unlock_nocapture(pp);
		return;
	}

	index = PAGE_CAPTURE_HASH(pp);

	mp = &page_capture_hash[index].pchh_mutex;
	mutex_enter(mp);
	for (i = 0; i < 2; i++) {
		bp = page_capture_hash[index].lists[i].next;
		while (bp != &page_capture_hash[index].lists[i]) {
			if (bp->pp == pp) {
				szc = bp->szc;
				flags = bp->flags | CAPTURE_ASYNC;
				datap = bp->datap;
				mutex_exit(mp);
				(void) page_trycapture(pp, szc, flags, datap);
				return;
			}
			bp = bp->next;
		}
	}

	/* Failed to find page in hash so clear flags and unlock it. */
	page_clrtoxic(pp, PR_CAPTURE);
	page_unlock(pp);

	mutex_exit(mp);
}

void
page_capture_init()
{
	int i;
	for (i = 0; i < NUM_PAGE_CAPTURE_BUCKETS; i++) {
		page_capture_hash[i].lists[0].next =
		    &page_capture_hash[i].lists[0];
		page_capture_hash[i].lists[0].prev =
		    &page_capture_hash[i].lists[0];
		page_capture_hash[i].lists[1].next =
		    &page_capture_hash[i].lists[1];
		page_capture_hash[i].lists[1].prev =
		    &page_capture_hash[i].lists[1];
	}

	pc_thread_shortwait = 23 * hz;
	pc_thread_longwait = 1201 * hz;
	pc_thread_retry = 3;
	mutex_init(&pc_thread_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pc_cv, NULL, CV_DEFAULT, NULL);
	pc_thread_id = thread_create(NULL, 0, page_capture_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
}

/*
 * It is necessary to scrub any failing pages prior to reboot in order to
 * prevent a latent error trap from occurring on the next boot.
 */
void
page_retire_mdboot()
{
	page_t *pp;
	int i, j;
	page_capture_hash_bucket_t *bp;
	uchar_t pri;

	/* walk lists looking for pages to scrub */
	for (i = 0; i < NUM_PAGE_CAPTURE_BUCKETS; i++) {
		for (pri = 0; pri < PC_NUM_PRI; pri++) {
			if (page_capture_hash[i].num_pages[pri] != 0) {
				break;
			}
		}
		if (pri == PC_NUM_PRI)
			continue;

		mutex_enter(&page_capture_hash[i].pchh_mutex);

		for (j = 0; j < 2; j++) {
			bp = page_capture_hash[i].lists[j].next;
			while (bp != &page_capture_hash[i].lists[j]) {
				pp = bp->pp;
				if (PP_TOXIC(pp)) {
					if (page_trylock(pp, SE_EXCL)) {
						PP_CLRFREE(pp);
						pagescrub(pp, 0, PAGESIZE);
						page_unlock(pp);
					}
				}
				bp = bp->next;
			}
		}
		mutex_exit(&page_capture_hash[i].pchh_mutex);
	}
}

/*
 * Walk the page_capture_hash trying to capture pages and also cleanup old
 * entries which have expired.
 */
void
page_capture_async()
{
	page_t *pp;
	int i;
	int ret;
	page_capture_hash_bucket_t *bp1, *bp2;
	uint_t szc;
	uint_t flags;
	void *datap;
	uchar_t pri;

	/* If there are outstanding pages to be captured, get to work */
	for (i = 0; i < NUM_PAGE_CAPTURE_BUCKETS; i++) {
		for (pri = 0; pri < PC_NUM_PRI; pri++) {
			if (page_capture_hash[i].num_pages[pri] != 0)
				break;
		}
		if (pri == PC_NUM_PRI)
			continue;

		/* Append list 1 to list 0 and then walk through list 0 */
		mutex_enter(&page_capture_hash[i].pchh_mutex);
		bp1 = &page_capture_hash[i].lists[1];
		bp2 = bp1->next;
		if (bp1 != bp2) {
			bp1->prev->next = page_capture_hash[i].lists[0].next;
			bp2->prev = &page_capture_hash[i].lists[0];
			page_capture_hash[i].lists[0].next->prev = bp1->prev;
			page_capture_hash[i].lists[0].next = bp2;
			bp1->next = bp1;
			bp1->prev = bp1;
		}

		/* list[1] will be empty now */

		bp1 = page_capture_hash[i].lists[0].next;
		while (bp1 != &page_capture_hash[i].lists[0]) {
			/* Check expiration time */
			if ((ddi_get_lbolt() > bp1->expires &&
			    bp1->expires != -1) ||
			    page_deleted(bp1->pp)) {
				page_capture_hash[i].lists[0].next = bp1->next;
				bp1->next->prev =
				    &page_capture_hash[i].lists[0];
				page_capture_hash[i].num_pages[bp1->pri]--;

				/*
				 * We can safely remove the PR_CAPTURE bit
				 * without holding the EXCL lock on the page
				 * as the PR_CAPTURE bit requres that the
				 * page_capture_hash[].pchh_mutex be held
				 * to modify it.
				 */
				page_clrtoxic(bp1->pp, PR_CAPTURE);
				mutex_exit(&page_capture_hash[i].pchh_mutex);
				kmem_free(bp1, sizeof (*bp1));
				mutex_enter(&page_capture_hash[i].pchh_mutex);
				bp1 = page_capture_hash[i].lists[0].next;
				continue;
			}
			pp = bp1->pp;
			szc = bp1->szc;
			flags = bp1->flags;
			datap = bp1->datap;
			mutex_exit(&page_capture_hash[i].pchh_mutex);
			if (page_trylock(pp, SE_EXCL)) {
				ret = page_trycapture(pp, szc,
				    flags | CAPTURE_ASYNC, datap);
			} else {
				ret = 1;	/* move to walked hash */
			}

			if (ret != 0) {
				/* Move to walked hash */
				(void) page_capture_move_to_walked(pp);
			}
			mutex_enter(&page_capture_hash[i].pchh_mutex);
			bp1 = page_capture_hash[i].lists[0].next;
		}

		mutex_exit(&page_capture_hash[i].pchh_mutex);
	}
}

/*
 * This function is called by the page_capture_thread, and is needed in
 * in order to initiate aio cleanup, so that pages used in aio
 * will be unlocked and subsequently retired by page_capture_thread.
 */
static int
do_aio_cleanup(void)
{
	proc_t *procp;
	int (*aio_cleanup_dr_delete_memory)(proc_t *);
	int cleaned = 0;

	if (modload("sys", "kaio") == -1) {
		cmn_err(CE_WARN, "do_aio_cleanup: cannot load kaio");
		return (0);
	}
	/*
	 * We use the aio_cleanup_dr_delete_memory function to
	 * initiate the actual clean up; this function will wake
	 * up the per-process aio_cleanup_thread.
	 */
	aio_cleanup_dr_delete_memory = (int (*)(proc_t *))
	    modgetsymvalue("aio_cleanup_dr_delete_memory", 0);
	if (aio_cleanup_dr_delete_memory == NULL) {
		cmn_err(CE_WARN,
	    "aio_cleanup_dr_delete_memory not found in kaio");
		return (0);
	}
	mutex_enter(&pidlock);
	for (procp = practive; (procp != NULL); procp = procp->p_next) {
		mutex_enter(&procp->p_lock);
		if (procp->p_aio != NULL) {
			/* cleanup proc's outstanding kaio */
			cleaned += (*aio_cleanup_dr_delete_memory)(procp);
		}
		mutex_exit(&procp->p_lock);
	}
	mutex_exit(&pidlock);
	return (cleaned);
}

/*
 * helper function for page_capture_thread
 */
static void
page_capture_handle_outstanding(void)
{
	int ntry;

	/* Reap pages before attempting capture pages */
	kmem_reap();

	if ((page_retire_pend_count() > page_retire_pend_kas_count()) &&
	    hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0)) {
		/*
		 * Note: Purging only for platforms that support
		 * ISM hat_pageunload() - mainly SPARC. On x86/x64
		 * platforms ISM pages SE_SHARED locked until destroyed.
		 */

		/* disable and purge seg_pcache */
		(void) seg_p_disable();
		for (ntry = 0; ntry < pc_thread_retry; ntry++) {
			if (!page_retire_pend_count())
				break;
			if (do_aio_cleanup()) {
				/*
				 * allow the apps cleanup threads
				 * to run
				 */
				delay(pc_thread_shortwait);
			}
			page_capture_async();
		}
		/* reenable seg_pcache */
		seg_p_enable();

		/* completed what can be done.  break out */
		return;
	}

	/*
	 * For kernel pages and/or unsupported HAT_DYNAMIC_ISM_UNMAP, reap
	 * and then attempt to capture.
	 */
	seg_preap();
	page_capture_async();
}

/*
 * The page_capture_thread loops forever, looking to see if there are
 * pages still waiting to be captured.
 */
static void
page_capture_thread(void)
{
	callb_cpr_t c;
	int i;
	int high_pri_pages;
	int low_pri_pages;
	clock_t timeout;

	CALLB_CPR_INIT(&c, &pc_thread_mutex, callb_generic_cpr, "page_capture");

	mutex_enter(&pc_thread_mutex);
	for (;;) {
		high_pri_pages = 0;
		low_pri_pages = 0;
		for (i = 0; i < NUM_PAGE_CAPTURE_BUCKETS; i++) {
			high_pri_pages +=
			    page_capture_hash[i].num_pages[PC_PRI_HI];
			low_pri_pages +=
			    page_capture_hash[i].num_pages[PC_PRI_LO];
		}

		timeout = pc_thread_longwait;
		if (high_pri_pages != 0) {
			timeout = pc_thread_shortwait;
			page_capture_handle_outstanding();
		} else if (low_pri_pages != 0) {
			page_capture_async();
		}
		CALLB_CPR_SAFE_BEGIN(&c);
		(void) cv_reltimedwait(&pc_cv, &pc_thread_mutex,
		    timeout, TR_CLOCK_TICK);
		CALLB_CPR_SAFE_END(&c, &pc_thread_mutex);
	}
	/*NOTREACHED*/
}
/*
 * Attempt to locate a bucket that has enough pages to satisfy the request.
 * The initial check is done without the lock to avoid unneeded contention.
 * The function returns 1 if enough pages were found, else 0 if it could not
 * find enough pages in a bucket.
 */
static int
pcf_decrement_bucket(pgcnt_t npages)
{
	struct pcf	*p;
	struct pcf	*q;
	int i;

	p = &pcf[PCF_INDEX()];
	q = &pcf[pcf_fanout];
	for (i = 0; i < pcf_fanout; i++) {
		if (p->pcf_count > npages) {
			/*
			 * a good one to try.
			 */
			mutex_enter(&p->pcf_lock);
			if (p->pcf_count > npages) {
				p->pcf_count -= (uint_t)npages;
				/*
				 * freemem is not protected by any lock.
				 * Thus, we cannot have any assertion
				 * containing freemem here.
				 */
				freemem -= npages;
				mutex_exit(&p->pcf_lock);
				return (1);
			}
			mutex_exit(&p->pcf_lock);
		}
		p++;
		if (p >= q) {
			p = pcf;
		}
	}
	return (0);
}

/*
 * Arguments:
 *	pcftotal_ret:	If the value is not NULL and we have walked all the
 *			buckets but did not find enough pages then it will
 *			be set to the total number of pages in all the pcf
 *			buckets.
 *	npages:		Is the number of pages we have been requested to
 *			find.
 *	unlock:		If set to 0 we will leave the buckets locked if the
 *			requested number of pages are not found.
 *
 * Go and try to satisfy the page request  from any number of buckets.
 * This can be a very expensive operation as we have to lock the buckets
 * we are checking (and keep them locked), starting at bucket 0.
 *
 * The function returns 1 if enough pages were found, else 0 if it could not
 * find enough pages in the buckets.
 *
 */
static int
pcf_decrement_multiple(pgcnt_t *pcftotal_ret, pgcnt_t npages, int unlock)
{
	struct pcf	*p;
	pgcnt_t pcftotal;
	int i;

	p = pcf;
	/* try to collect pages from several pcf bins */
	for (pcftotal = 0, i = 0; i < pcf_fanout; i++) {
		mutex_enter(&p->pcf_lock);
		pcftotal += p->pcf_count;
		if (pcftotal >= npages) {
			/*
			 * Wow!  There are enough pages laying around
			 * to satisfy the request.  Do the accounting,
			 * drop the locks we acquired, and go back.
			 *
			 * freemem is not protected by any lock. So,
			 * we cannot have any assertion containing
			 * freemem.
			 */
			freemem -= npages;
			while (p >= pcf) {
				if (p->pcf_count <= npages) {
					npages -= p->pcf_count;
					p->pcf_count = 0;
				} else {
					p->pcf_count -= (uint_t)npages;
					npages = 0;
				}
				mutex_exit(&p->pcf_lock);
				p--;
			}
			ASSERT(npages == 0);
			return (1);
		}
		p++;
	}
	if (unlock) {
		/* failed to collect pages - release the locks */
		while (--p >= pcf) {
			mutex_exit(&p->pcf_lock);
		}
	}
	if (pcftotal_ret != NULL)
		*pcftotal_ret = pcftotal;
	return (0);
}

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
 * Copyright 2016 PALO, Richard.
 */

#include <sys/balloon_impl.h>
#include <sys/hypervisor.h>
#include <xen/sys/xenbus_impl.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/disp.h>
#include <sys/callb.h>
#include <xen/public/memory.h>
#include <vm/hat.h>
#include <sys/promif.h>
#include <vm/seg_kmem.h>
#include <sys/memnode.h>
#include <sys/param.h>
#include <vm/vm_dep.h>
#include <sys/mman.h>
#include <sys/memlist.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/sdt.h>

/*
 * This file implements a balloon thread, which controls a domain's memory
 * reservation, or the amount of memory a domain is currently allocated.
 * The hypervisor provides the current memory reservation through xenbus,
 * so we register a watch on this.  We will then be signalled when the
 * reservation changes.  If it goes up, we map the new mfn's to our pfn's
 * (allocating page_t's if necessary), and release them into the system.
 * If the reservation goes down, we grab pages and release them back to
 * the hypervisor, saving the page_t's for later use.
 */

/*
 * Various structures needed by the balloon thread
 */
static bln_stats_t bln_stats;
static kthread_t *bln_thread;
static kmutex_t bln_mutex;
static kcondvar_t bln_cv;
static struct xenbus_watch bln_watch;
static mfn_t new_high_mfn;

/*
 * For holding spare page_t structures - keep a singly-linked list.
 * The list may hold both valid (pagenum < mfn_count) and invalid
 * (pagenum >= mfn_count) page_t's.  Valid page_t's should be inserted
 * at the front, and invalid page_t's at the back.  Removal should
 * always be from the front.  This is a singly-linked list using
 * p_next, so p_prev is always NULL.
 */
static page_t *bln_spare_list_front, *bln_spare_list_back;

int balloon_zero_memory = 1;
size_t balloon_minkmem = (8 * 1024 * 1024);

/*
 * reassign_pfn() calls update_contig_pfnlist(), which can cause a large
 * slowdown when calling multiple times.  If we're reassigning less than the
 * quota defined here, we just accept the slowdown.  If the count is greater
 * than the quota, we tell the contig alloc code to stop its accounting until
 * we're done.  Setting the quota to less than 2 is not supported.
 *
 * Note that we define our own wrapper around the external
 * clear_and_lock_contig_pfnlist(), but we just use the version of
 * unlock_contig_pfnlist() in vm_machdep.c.
 */
uint_t bln_contig_list_quota = 50;

extern void clear_and_lock_contig_pfnlist(void);
extern void unlock_contig_pfnlist(void);

/*
 * Lock the pfnlist if necessary (see above), and return whether we locked it.
 */
static int
balloon_lock_contig_pfnlist(int count)
{
	if (count > bln_contig_list_quota) {
		clear_and_lock_contig_pfnlist();
		return (1);
	} else {
		return (0);
	}
}

/*
 * The page represented by pp is being given back to the hypervisor.
 * Add the page_t structure to our spare list.
 */
static void
balloon_page_add(page_t *pp)
{
	/*
	 * We need to keep the page exclusively locked
	 * to prevent swrand from grabbing it.
	 */
	ASSERT(PAGE_EXCL(pp));
	ASSERT(MUTEX_HELD(&bln_mutex));

	pp->p_prev = NULL;
	if (bln_spare_list_front == NULL) {
		bln_spare_list_front = bln_spare_list_back = pp;
		pp->p_next = NULL;
	} else if (pp->p_pagenum >= mfn_count) {
		/*
		 * The pfn is invalid, so add at the end of list.  Since these
		 * adds should *only* be done by balloon_init_new_pages(), and
		 * that does adds in order, the following ASSERT should
		 * never trigger.
		 */
		ASSERT(pp->p_pagenum > bln_spare_list_back->p_pagenum);
		bln_spare_list_back->p_next = pp;
		pp->p_next = NULL;
		bln_spare_list_back = pp;
	} else {
		/* Add at beginning of list */
		pp->p_next = bln_spare_list_front;
		bln_spare_list_front = pp;
	}
}

/*
 * Return a page_t structure from our spare list, or NULL if none are available.
 */
static page_t *
balloon_page_sub(void)
{
	page_t *pp;

	ASSERT(MUTEX_HELD(&bln_mutex));
	if (bln_spare_list_front == NULL) {
		return (NULL);
	}

	pp = bln_spare_list_front;
	ASSERT(PAGE_EXCL(pp));
	ASSERT(pp->p_pagenum <= mfn_count);
	if (pp->p_pagenum == mfn_count) {
		return (NULL);
	}

	bln_spare_list_front = pp->p_next;
	if (bln_spare_list_front == NULL)
		bln_spare_list_back = NULL;
	pp->p_next = NULL;
	return (pp);
}

/*
 * NOTE: We currently do not support growing beyond the boot memory size,
 * so the following function will not be called.  It is left in here with
 * the hope that someday this restriction can be lifted, and this code can
 * be used.
 */

/*
 * This structure is placed at the start of every block of new pages
 */
typedef struct {
	struct memseg	memseg;
	struct memlist	memlist;
	page_t		pages[1];
} mem_structs_t;

/*
 * To make the math below slightly less confusing, we calculate the first
 * two parts here.  page_t's are handled separately, so they are not included.
 */
#define	MEM_STRUCT_SIZE	(sizeof (struct memseg) + sizeof (struct memlist))

/*
 * We want to add memory, but have no spare page_t structures.  Use some of
 * our new memory for the page_t structures.
 *
 * Somewhat similar to kphysm_add_memory_dynamic(), but simpler.
 */
static int
balloon_init_new_pages(mfn_t framelist[], pgcnt_t count)
{
	pgcnt_t	metapgs, totalpgs, num_pages;
	paddr_t	metasz;
	pfn_t	meta_start;
	page_t	*page_array;
	caddr_t	va;
	int	i, rv, locked;
	mem_structs_t *mem;
	struct memseg *segp;

	/* Calculate the number of pages we're going to add */
	totalpgs = bln_stats.bln_new_target - bln_stats.bln_current_pages;

	/*
	 * The following calculates the number of "meta" pages -- the pages
	 * that will be required to hold page_t structures for all new pages.
	 * Proof of this calculation is left up to the reader.
	 */
	metapgs = totalpgs - (((uint64_t)(totalpgs) << PAGESHIFT) /
	    (PAGESIZE + sizeof (page_t)));

	/*
	 * Given the number of page_t structures we need, is there also
	 * room in our meta pages for a memseg and memlist struct?
	 * If not, we'll need one more meta page.
	 */
	if ((metapgs << PAGESHIFT) < (totalpgs * sizeof (page_t) +
	    MEM_STRUCT_SIZE))
		metapgs++;

	/*
	 * metapgs is calculated from totalpgs, which may be much larger than
	 * count.  If we don't have enough pages, all of the pages in this
	 * batch will be made meta pages, and a future trip through
	 * balloon_inc_reservation() will add the rest of the meta pages.
	 */
	if (metapgs > count)
		metapgs = count;

	/*
	 * Figure out the number of page_t structures that can fit in metapgs
	 *
	 * This will cause us to initialize more page_t structures than we
	 * need - these may be used in future memory increases.
	 */
	metasz = pfn_to_pa(metapgs);
	num_pages = (metasz - MEM_STRUCT_SIZE) / sizeof (page_t);

	DTRACE_PROBE3(balloon__alloc__stats, pgcnt_t, totalpgs, pgcnt_t,
	    num_pages, pgcnt_t, metapgs);

	/*
	 * We only increment mfn_count by count, not num_pages, to keep the
	 * space of all valid pfns contiguous.  This means we create page_t
	 * structures with invalid pagenums -- we deal with this situation
	 * in balloon_page_sub.
	 */
	mfn_count += count;

	/*
	 * Get a VA for the pages that will hold page_t and other structures.
	 * The memseg and memlist structures will go at the beginning, with
	 * the page_t structures following.
	 */
	va = (caddr_t)vmem_alloc(heap_arena, metasz, VM_SLEEP);
	/* LINTED: improper alignment */
	mem = (mem_structs_t *)va;
	page_array = mem->pages;

	meta_start = bln_stats.bln_max_pages;

	/*
	 * Set the mfn to pfn mapping for the meta pages.
	 */
	locked = balloon_lock_contig_pfnlist(metapgs);
	for (i = 0; i < metapgs; i++) {
		reassign_pfn(bln_stats.bln_max_pages + i, framelist[i]);
	}
	if (locked)
		unlock_contig_pfnlist();

	/*
	 * For our meta pages, map them in and zero the page.
	 * This will be the first time touching the new pages.
	 */
	hat_devload(kas.a_hat, va, metasz, bln_stats.bln_max_pages,
	    PROT_READ | PROT_WRITE,
	    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
	bzero(va, metasz);

	/*
	 * Initialize the page array for the new pages.
	 */
	for (i = 0; i < metapgs; i++) {
		page_array[i].p_pagenum = bln_stats.bln_max_pages++;
		page_array[i].p_offset = (u_offset_t)-1;
		page_iolock_init(&page_array[i]);
		rv = page_lock(&page_array[i], SE_EXCL, NULL, P_NO_RECLAIM);
		ASSERT(rv == 1);
	}

	/*
	 * For the rest of the pages, initialize the page_t struct and
	 * add them to the free list
	 */
	for (i = metapgs; i < num_pages; i++) {
		page_array[i].p_pagenum = bln_stats.bln_max_pages++;
		page_array[i].p_offset = (u_offset_t)-1;
		page_iolock_init(&page_array[i]);
		rv = page_lock(&page_array[i], SE_EXCL, NULL, P_NO_RECLAIM);
		ASSERT(rv == 1);
		balloon_page_add(&page_array[i]);
	}

	/*
	 * Remember where I said that we don't call this function?  The missing
	 * code right here is why.  We need to set up kpm mappings for any new
	 * pages coming in.  However, if someone starts up a domain with small
	 * memory, then greatly increases it, we could get in some horrible
	 * deadlock situations as we steal page tables for kpm use, and
	 * userland applications take them right back before we can use them
	 * to set up our new memory.  Once a way around that is found, and a
	 * few other changes are made, we'll be able to enable this code.
	 */

	/*
	 * Update kernel structures, part 1: memsegs list
	 */
	mem->memseg.pages_base = meta_start;
	mem->memseg.pages_end = bln_stats.bln_max_pages - 1;
	mem->memseg.pages = &page_array[0];
	mem->memseg.epages = &page_array[num_pages - 1];
	mem->memseg.next = NULL;
	memsegs_lock(1);
	for (segp = memsegs; segp->next != NULL; segp = segp->next)
		;
	segp->next = &mem->memseg;
	memsegs_unlock(1);

	/*
	 * Update kernel structures, part 2: mem_node array
	 */
	mem_node_add_slice(meta_start, bln_stats.bln_max_pages);

	/*
	 * Update kernel structures, part 3: phys_install array
	 * (*sigh* how many of these things do we need?)
	 */
	memlist_write_lock();
	memlist_add(pfn_to_pa(meta_start), num_pages, &mem->memlist,
	    &phys_install);
	memlist_write_unlock();

	build_pfn_hash();

	return (metapgs);
}

/* How many ulong_t's can we fit on a page? */
#define	FRAME_ARRAY_SIZE	(PAGESIZE / sizeof (ulong_t))

/*
 * These are too large to declare on the stack, so we make them static instead
 */
static ulong_t	mfn_frames[FRAME_ARRAY_SIZE];
static pfn_t	pfn_frames[FRAME_ARRAY_SIZE];

/*
 * This function is called when our reservation is increasing.  Make a
 * hypervisor call to get our new pages, then integrate them into the system.
 */
static spgcnt_t
balloon_inc_reservation(ulong_t credit)
{
	int	i, cnt, locked;
	int	meta_pg_start, meta_pg_end;
	long	rv;
	page_t	*pp;
	page_t	*new_list_front, *new_list_back;

	/* Make sure we're single-threaded. */
	ASSERT(MUTEX_HELD(&bln_mutex));

	rv = 0;
	new_list_front = new_list_back = NULL;
	meta_pg_start = meta_pg_end = 0;
	bzero(mfn_frames, PAGESIZE);

	if (credit > FRAME_ARRAY_SIZE)
		credit = FRAME_ARRAY_SIZE;

	xen_block_migrate();
	rv = balloon_alloc_pages(credit, mfn_frames);

	if (rv < 0) {
		xen_allow_migrate();
		return (0);
	}
	for (i = 0; i < rv; i++) {
		if (mfn_frames[i] > new_high_mfn)
			new_high_mfn = mfn_frames[i];

		pp = balloon_page_sub();
		if (pp == NULL) {
			/*
			 * We pass the index into the current mfn array,
			 * then move the counter past the mfns we used
			 */
			meta_pg_start = i;
			cnt = balloon_init_new_pages(&mfn_frames[i], rv - i);
			i += cnt;
			meta_pg_end = i;
			if (i < rv) {
				pp = balloon_page_sub();
			} else {
				ASSERT(i == rv);
			}
		}
		if (pp == NULL) {
			break;
		}

		if (new_list_back == NULL) {
			new_list_front = new_list_back = pp;
		} else {
			new_list_back->p_next = pp;
			new_list_back = pp;
		}
		pp->p_next = NULL;
	}
	cnt = i;
	locked = balloon_lock_contig_pfnlist(cnt);
	for (i = 0, pp = new_list_front; i < meta_pg_start;
	    i++, pp = pp->p_next) {
		reassign_pfn(pp->p_pagenum, mfn_frames[i]);
	}
	for (i = meta_pg_end; i < cnt; i++, pp = pp->p_next) {
		reassign_pfn(pp->p_pagenum, mfn_frames[i]);
	}
	if (locked)
		unlock_contig_pfnlist();

	/*
	 * Make sure we don't allow pages without pfn->mfn mappings
	 * into the system.
	 */
	ASSERT(pp == NULL);

	while (new_list_front != NULL) {
		pp = new_list_front;
		new_list_front = pp->p_next;
		page_free(pp, 1);
	}

	/*
	 * Variable review: at this point, rv contains the number of pages
	 * the hypervisor gave us.  cnt contains the number of pages for which
	 * we had page_t structures.  i contains the number of pages
	 * where we set up pfn <-> mfn mappings.  If this ASSERT trips, that
	 * means we somehow lost page_t's from our local list.
	 */
	ASSERT(cnt == i);
	if (cnt < rv) {
		/*
		 * We couldn't get page structures.
		 *
		 * This shouldn't happen, but causes no real harm if it does.
		 * On debug kernels, we'll flag it.  On all kernels, we'll
		 * give back the pages we couldn't assign.
		 *
		 * Since these pages are new to the system and haven't been
		 * used, we don't bother zeroing them.
		 */
#ifdef DEBUG
		cmn_err(CE_WARN, "Could only assign %d of %ld pages", cnt, rv);
#endif	/* DEBUG */

		(void) balloon_free_pages(rv - cnt, &mfn_frames[i], NULL, NULL);

		rv = cnt;
	}

	xen_allow_migrate();
	page_unresv(rv - (meta_pg_end - meta_pg_start));
	return (rv);
}

/*
 * This function is called when we want to decrease the memory reservation
 * of our domain.  Allocate the memory and make a hypervisor call to give
 * it back.
 */
static spgcnt_t
balloon_dec_reservation(ulong_t debit)
{
	int	i, locked;
	long	rv;
	ulong_t	request;
	page_t	*pp;

	bzero(mfn_frames, sizeof (mfn_frames));
	bzero(pfn_frames, sizeof (pfn_frames));

	if (debit > FRAME_ARRAY_SIZE) {
		debit = FRAME_ARRAY_SIZE;
	}
	request = debit;

	/*
	 * Don't bother if there isn't a safe amount of kmem left.
	 */
	if (kmem_avail() < balloon_minkmem) {
		kmem_reap();
		if (kmem_avail() < balloon_minkmem)
			return (0);
	}

	if (page_resv(request, KM_NOSLEEP) == 0) {
		return (0);
	}
	xen_block_migrate();
	for (i = 0; i < debit; i++) {
		pp = page_get_high_mfn(new_high_mfn);
		new_high_mfn = 0;
		if (pp == NULL) {
			/*
			 * Call kmem_reap(), then try once more,
			 * but only if there is a safe amount of
			 * kmem left.
			 */
			kmem_reap();
			if (kmem_avail() < balloon_minkmem ||
			    (pp = page_get_high_mfn(0)) == NULL) {
				debit = i;
				break;
			}
		}
		ASSERT(PAGE_EXCL(pp));
		ASSERT(!hat_page_is_mapped(pp));

		balloon_page_add(pp);
		pfn_frames[i] = pp->p_pagenum;
		mfn_frames[i] = pfn_to_mfn(pp->p_pagenum);
	}
	if (debit == 0) {
		xen_allow_migrate();
		page_unresv(request);
		return (0);
	}

	/*
	 * We zero all the pages before we start reassigning them in order to
	 * minimize the time spent holding the lock on the contig pfn list.
	 */
	if (balloon_zero_memory) {
		for (i = 0; i < debit; i++) {
			pfnzero(pfn_frames[i], 0, PAGESIZE);
		}
	}

	/*
	 * Remove all mappings for the pfns from the system
	 */
	locked = balloon_lock_contig_pfnlist(debit);
	for (i = 0; i < debit; i++) {
		reassign_pfn(pfn_frames[i], MFN_INVALID);
	}
	if (locked)
		unlock_contig_pfnlist();

	rv = balloon_free_pages(debit, mfn_frames, NULL, NULL);

	if (rv < 0) {
		cmn_err(CE_WARN, "Attempt to return pages to the hypervisor "
		    "failed - up to %lu pages lost (error = %ld)", debit, rv);
		rv = 0;
	} else if (rv != debit) {
		panic("Unexpected return value (%ld) from decrease reservation "
		    "hypervisor call", rv);
	}

	xen_allow_migrate();
	if (debit != request)
		page_unresv(request - debit);
	return (rv);
}

/*
 * This function is the callback which is called when the memory/target
 * node is changed.  When it is fired, we will read a new reservation
 * target for our domain and signal the worker thread to make the change.
 *
 * If the reservation is larger than we can handle, we issue a warning.  dom0
 * does this automatically every boot, so we skip the first warning on dom0.
 */
/*ARGSUSED*/
static void
balloon_handler(struct xenbus_watch *watch, const char **vec, uint_t len)
{
	ulong_t new_target_kb;
	pgcnt_t	new_target_pages;
	int rv;
	static uchar_t warning_cnt = 0;

	rv = xenbus_scanf(0, "memory", "target", "%lu", &new_target_kb);
	if (rv != 0) {
		return;
	}

	/* new_target is in kB - change this to pages */
	new_target_pages = kbtop(new_target_kb);

	DTRACE_PROBE1(balloon__new__target, pgcnt_t, new_target_pages);

	/*
	 * Unfortunately, dom0 may give us a target that is larger than
	 * our max limit.  Re-check the limit, and, if the new target is
	 * too large, adjust it downwards.
	 */
	mutex_enter(&bln_mutex);
	if (new_target_pages > bln_stats.bln_max_pages) {
		DTRACE_PROBE2(balloon__target__too__large, pgcnt_t,
		    new_target_pages, pgcnt_t, bln_stats.bln_max_pages);
		if (!DOMAIN_IS_INITDOMAIN(xen_info) || warning_cnt != 0) {
			cmn_err(CE_WARN, "New balloon target (0x%lx pages) is "
			    "larger than original memory size (0x%lx pages). "
			    "Ballooning beyond original memory size is not "
			    "allowed.",
			    new_target_pages, bln_stats.bln_max_pages);
		}
		warning_cnt = 1;
		bln_stats.bln_new_target = bln_stats.bln_max_pages;
	} else {
		bln_stats.bln_new_target = new_target_pages;
	}

	mutex_exit(&bln_mutex);
	cv_signal(&bln_cv);
}

/*
 * bln_wait_sec can be used to throttle the hv calls, but by default it's
 * turned off.  If a balloon attempt fails, the wait time is forced on, and
 * then is exponentially increased as further attempts fail.
 */
uint_t bln_wait_sec = 0;
uint_t bln_wait_shift = 1;

/*
 * This is the main balloon thread.  Wait on the cv.  When woken, if our
 * reservation has changed, call the appropriate function to adjust the
 * reservation.
 */
static void
balloon_worker_thread(void)
{
	uint_t		bln_wait;
	callb_cpr_t	cprinfo;
	spgcnt_t	rv;

	bln_wait = bln_wait_sec;

	CALLB_CPR_INIT(&cprinfo, &bln_mutex, callb_generic_cpr, "balloon");
	for (;;) {
		rv = 0;

		mutex_enter(&bln_mutex);
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		if (bln_stats.bln_new_target != bln_stats.bln_current_pages) {
			/*
			 * We weren't able to fully complete the request
			 * last time through, so try again.
			 */
			(void) cv_reltimedwait(&bln_cv, &bln_mutex,
			    (bln_wait * hz), TR_CLOCK_TICK);
		} else {
			cv_wait(&bln_cv, &bln_mutex);
		}
		CALLB_CPR_SAFE_END(&cprinfo, &bln_mutex);

		if (bln_stats.bln_new_target != bln_stats.bln_current_pages) {
			if (bln_stats.bln_new_target <
			    bln_stats.bln_current_pages) {
				/* reservation shrunk */
				rv = -balloon_dec_reservation(
				    bln_stats.bln_current_pages -
				    bln_stats.bln_new_target);
			} else if (bln_stats.bln_new_target >
			    bln_stats.bln_current_pages) {
				/* reservation grew */
				rv = balloon_inc_reservation(
				    bln_stats.bln_new_target -
				    bln_stats.bln_current_pages);
			}
		}
		if (rv == 0) {
			if (bln_wait == 0) {
				bln_wait = 1;
			} else {
				bln_wait <<= bln_wait_shift;
			}
		} else {
			bln_stats.bln_current_pages += rv;
			bln_wait = bln_wait_sec;
		}
		if (bln_stats.bln_current_pages < bln_stats.bln_low)
			bln_stats.bln_low = bln_stats.bln_current_pages;
		else if (bln_stats.bln_current_pages > bln_stats.bln_high)
			bln_stats.bln_high = bln_stats.bln_current_pages;
		mutex_exit(&bln_mutex);
	}
}

/*
 * Called after balloon_init(), which is below.  The xenbus thread is up
 * and running, so we can register our watch and create the balloon thread.
 */
static void
balloon_config_watch(int state)
{
	if (state != XENSTORE_UP)
		return;

	bln_watch.node = "memory/target";
	bln_watch.callback = balloon_handler;
	if (register_xenbus_watch(&bln_watch)) {
		cmn_err(CE_WARN, "Failed to register balloon watcher; balloon "
		    "thread will be disabled");
		return;
	}

	if (bln_thread == NULL)
		bln_thread = thread_create(NULL, 0, balloon_worker_thread,
		    NULL, 0, &p0, TS_RUN, minclsyspri);
}

/*
 * Basic initialization of the balloon thread.  Set all of our variables,
 * and register a callback for later when we can register a xenbus watch.
 */
void
balloon_init(pgcnt_t nr_pages)
{
	domid_t domid = DOMID_SELF;

	bln_stats.bln_current_pages = bln_stats.bln_low = nr_pages;
	bln_stats.bln_new_target = bln_stats.bln_high = nr_pages;
	bln_stats.bln_max_pages = nr_pages;
	cv_init(&bln_cv, NULL, CV_DEFAULT, NULL);

	bln_stats.bln_hard_limit = (spgcnt_t)HYPERVISOR_memory_op(
	    XENMEM_maximum_reservation, &domid);

	(void) xs_register_xenbus_callback(balloon_config_watch);
}

/*
 * These functions are called from the network drivers when they gain a page
 * or give one away.  We simply update our count.  Note that the counter
 * tracks the number of pages we give away, so we need to subtract any
 * amount passed to balloon_drv_added.
 */
void
balloon_drv_added(int64_t delta)
{
	atomic_add_long((ulong_t *)&bln_stats.bln_hv_pages, -delta);
}

void
balloon_drv_subtracted(int64_t delta)
{
	atomic_add_long((ulong_t *)&bln_stats.bln_hv_pages, delta);
}

/*
 * balloon_alloc_pages()
 *	Allocate page_cnt mfns.  mfns storage provided by the caller.  Returns
 *	the number of pages allocated, which could be less than page_cnt, or
 *	a negative number if an error occurred.
 */
long
balloon_alloc_pages(uint_t page_cnt, mfn_t *mfns)
{
	xen_memory_reservation_t memres;
	long rv;

	bzero(&memres, sizeof (memres));
	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(memres.extent_start, mfns);
	memres.domid = DOMID_SELF;
	memres.nr_extents = page_cnt;

	rv = HYPERVISOR_memory_op(XENMEM_increase_reservation, &memres);
	if (rv > 0)
		atomic_add_long((ulong_t *)&bln_stats.bln_hv_pages, -rv);
	return (rv);
}

/*
 * balloon_free_pages()
 *    free page_cnt pages, using any combination of mfns, pfns, and kva as long
 *    as they refer to the same mapping.  If an array of mfns is passed in, we
 *    assume they were already cleared.  Otherwise, we need to zero the pages
 *    before giving them back to the hypervisor. kva space is not free'd up in
 *    case the caller wants to re-use it.
 */
long
balloon_free_pages(uint_t page_cnt, mfn_t *mfns, caddr_t kva, pfn_t *pfns)
{
	xen_memory_reservation_t memdec;
	mfn_t mfn;
	pfn_t pfn;
	uint_t i;
	long e;


#if DEBUG
	/* make sure kva is page aligned and maps to first pfn */
	if (kva != NULL) {
		ASSERT(((uintptr_t)kva & PAGEOFFSET) == 0);
		if (pfns != NULL) {
			ASSERT(hat_getpfnum(kas.a_hat, kva) == pfns[0]);
		}
	}
#endif

	/* if we have a kva, we can clean all pages with just one bzero */
	if ((kva != NULL) && balloon_zero_memory) {
		bzero(kva, (page_cnt * PAGESIZE));
	}

	/* if we were given a kva and/or a pfn */
	if ((kva != NULL) || (pfns != NULL)) {

		/*
		 * All the current callers only pass 1 page when using kva or
		 * pfns, and use mfns when passing multiple pages.  If that
		 * assumption is changed, the following code will need some
		 * work.  The following ASSERT() guarantees we're respecting
		 * the io locking quota.
		 */
		ASSERT(page_cnt < bln_contig_list_quota);

		/* go through all the pages */
		for (i = 0; i < page_cnt; i++) {

			/* get the next pfn */
			if (pfns == NULL) {
				pfn = hat_getpfnum(kas.a_hat,
				    (kva + (PAGESIZE * i)));
			} else {
				pfn = pfns[i];
			}

			/*
			 * if we didn't already zero this page, do it now. we
			 * need to do this *before* we give back the MFN
			 */
			if ((kva == NULL) && (balloon_zero_memory)) {
				pfnzero(pfn, 0, PAGESIZE);
			}

			/*
			 * unmap the pfn. We don't free up the kva vmem space
			 * so the caller can re-use it. The page must be
			 * unmapped before it is given back to the hypervisor.
			 */
			if (kva != NULL) {
				hat_unload(kas.a_hat, (kva + (PAGESIZE * i)),
				    PAGESIZE, HAT_UNLOAD_UNMAP);
			}

			/* grab the mfn before the pfn is marked as invalid */
			mfn = pfn_to_mfn(pfn);

			/* mark the pfn as invalid */
			reassign_pfn(pfn, MFN_INVALID);

			/*
			 * if we weren't given an array of MFNs, we need to
			 * free them up one at a time. Otherwise, we'll wait
			 * until later and do it in one hypercall
			 */
			if (mfns == NULL) {
				bzero(&memdec, sizeof (memdec));
				/*LINTED: constant in conditional context*/
				set_xen_guest_handle(memdec.extent_start, &mfn);
				memdec.domid = DOMID_SELF;
				memdec.nr_extents = 1;
				e = HYPERVISOR_memory_op(
				    XENMEM_decrease_reservation, &memdec);
				if (e != 1) {
					cmn_err(CE_PANIC, "balloon: unable to "
					    "give a page back to the "
					    "hypervisor.\n");
				}
			}
		}
	}

	/*
	 * if we were passed in MFNs, we haven't free'd them up yet. We can
	 * do it with one call.
	 */
	if (mfns != NULL) {
		bzero(&memdec, sizeof (memdec));
		/*LINTED: constant in conditional context*/
		set_xen_guest_handle(memdec.extent_start, mfns);
		memdec.domid = DOMID_SELF;
		memdec.nr_extents = page_cnt;
		e = HYPERVISOR_memory_op(XENMEM_decrease_reservation, &memdec);
		if (e != page_cnt) {
			cmn_err(CE_PANIC, "balloon: unable to give pages back "
			    "to the hypervisor.\n");
		}
	}

	atomic_add_long((ulong_t *)&bln_stats.bln_hv_pages, page_cnt);
	return (page_cnt);
}


/*
 * balloon_replace_pages()
 *	Try to replace nextexts blocks of 2^order pages.  addr_bits specifies
 *	how many bits of address the pages must be within (i.e. 16 would mean
 *	that the pages cannot have an address > 64k).  The constrints are on
 *	what the hypervisor gives us -- we are free to give any pages in
 *	exchange.  The array pp is the pages we are giving away.  The caller
 *	provides storage space for mfns, which hold the new physical pages.
 */
long
balloon_replace_pages(uint_t nextents, page_t **pp, uint_t addr_bits,
    uint_t order, mfn_t *mfns)
{
	xen_memory_reservation_t memres;
	long fallback_cnt;
	long cnt;
	uint_t i, j, page_cnt, extlen;
	long e;
	int locked;


	/*
	 * we shouldn't be allocating constrained pages on a guest. It doesn't
	 * make any sense. They won't be constrained after a migration.
	 */
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));

	extlen = 1 << order;
	page_cnt = nextents * extlen;
	/* Give back the current pages to the hypervisor */
	for (i = 0; i < page_cnt; i++) {
		cnt = balloon_free_pages(1, NULL, NULL, &pp[i]->p_pagenum);
		if (cnt != 1) {
			cmn_err(CE_PANIC, "balloon: unable to give a page back "
			    "to the hypervisor.\n");
		}
	}

	/*
	 * try to allocate the new pages using addr_bits and order. If we can't
	 * get all of the pages, try to get the remaining pages with no
	 * constraints and, if that was successful, return the number of
	 * constrained pages we did allocate.
	 */
	bzero(&memres, sizeof (memres));
	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(memres.extent_start, mfns);
	memres.domid = DOMID_SELF;
	memres.nr_extents = nextents;
	memres.mem_flags = XENMEMF_address_bits(addr_bits);
	memres.extent_order = order;
	cnt = HYPERVISOR_memory_op(XENMEM_increase_reservation, &memres);
	/* assign the new MFNs to the current PFNs */
	locked = balloon_lock_contig_pfnlist(cnt * extlen);
	for (i = 0; i < cnt; i++) {
		for (j = 0; j < extlen; j++) {
			reassign_pfn(pp[i * extlen + j]->p_pagenum,
			    mfns[i] + j);
		}
	}
	if (locked)
		unlock_contig_pfnlist();
	if (cnt != nextents) {
		if (cnt < 0) {
			cnt = 0;
		}

		/*
		 * We couldn't get enough memory to satisfy our requirements.
		 * The above loop will assign the parts of the request that
		 * were successful (this part may be 0).  We need to fill
		 * in the rest.  The bzero below clears out extent_order and
		 * address_bits, so we'll take anything from the hypervisor
		 * to replace the pages we gave away.
		 */
		fallback_cnt = page_cnt - cnt * extlen;
		bzero(&memres, sizeof (memres));
		/*LINTED: constant in conditional context*/
		set_xen_guest_handle(memres.extent_start, mfns);
		memres.domid = DOMID_SELF;
		memres.nr_extents = fallback_cnt;
		e = HYPERVISOR_memory_op(XENMEM_increase_reservation, &memres);
		if (e != fallback_cnt) {
			cmn_err(CE_PANIC, "balloon: unable to recover from "
			    "failed increase_reservation.\n");
		}
		locked = balloon_lock_contig_pfnlist(fallback_cnt);
		for (i = 0; i < fallback_cnt; i++) {
			uint_t offset = page_cnt - fallback_cnt;

			/*
			 * We already used pp[0...(cnt * extlen)] before,
			 * so start at the next entry in the pp array.
			 */
			reassign_pfn(pp[i + offset]->p_pagenum, mfns[i]);
		}
		if (locked)
			unlock_contig_pfnlist();
	}

	/*
	 * balloon_free_pages increments our counter.  Decrement it here.
	 */
	atomic_add_long((ulong_t *)&bln_stats.bln_hv_pages, -(long)page_cnt);

	/*
	 * return the number of extents we were able to replace. If we got
	 * this far, we know all the pp's are valid.
	 */
	return (cnt);
}


/*
 * Called from the driver - return the requested stat.
 */
size_t
balloon_values(int cmd)
{
	switch (cmd) {
	case BLN_IOCTL_CURRENT:
		return (ptokb(bln_stats.bln_current_pages));
	case BLN_IOCTL_TARGET:
		return (ptokb(bln_stats.bln_new_target));
	case BLN_IOCTL_LOW:
		return (ptokb(bln_stats.bln_low));
	case BLN_IOCTL_HIGH:
		return (ptokb(bln_stats.bln_high));
	case BLN_IOCTL_LIMIT:
		return (ptokb(bln_stats.bln_hard_limit));
	default:
		panic("Unexpected cmd %d in balloon_values()\n", cmd);
	}
	/*NOTREACHED*/
}

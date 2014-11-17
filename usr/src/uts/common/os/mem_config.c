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
#include <sys/cmn_err.h>
#include <sys/vmem.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/machsystm.h>	/* for page_freelist_coalesce() */
#include <sys/errno.h>
#include <sys/memnode.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/tuneable.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/debug.h>
#include <sys/vm.h>
#include <sys/callb.h>
#include <sys/memlist_plat.h>	/* for installed_top_size() */
#include <sys/condvar_impl.h>	/* for CV_HAS_WAITERS() */
#include <sys/dumphdr.h>	/* for dump_resize() */
#include <sys/atomic.h>		/* for use in stats collection */
#include <sys/rwlock.h>
#include <sys/cpuvar.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#define	SUNDDI_IMPL		/* so sunddi.h will not redefine splx() et al */
#include <sys/sunddi.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>
#include <sys/lgrp.h>
#include <sys/ddi.h>
#include <sys/modctl.h>

extern struct memlist *phys_avail;

extern uint_t page_ctrs_adjust(int);
void page_ctrs_cleanup(void);
static void kphysm_setup_post_add(pgcnt_t);
static int kphysm_setup_pre_del(pgcnt_t);
static void kphysm_setup_post_del(pgcnt_t, int);

static int kphysm_split_memseg(pfn_t base, pgcnt_t npgs);

static int delspan_reserve(pfn_t, pgcnt_t);
static void delspan_unreserve(pfn_t, pgcnt_t);

kmutex_t memseg_lists_lock;
struct memseg *memseg_va_avail;
struct memseg *memseg_alloc(void);
static struct memseg *memseg_delete_junk;
static struct memseg *memseg_edit_junk;
void memseg_remap_init(void);
static void memseg_remap_to_dummy(struct memseg *);
static void kphysm_addmem_error_undospan(pfn_t, pgcnt_t);
static struct memseg *memseg_reuse(pgcnt_t);

static struct kmem_cache *memseg_cache;

/*
 * Interfaces to manage externally allocated
 * page_t memory (metadata) for a memseg.
 */
#pragma weak	memseg_alloc_meta
#pragma weak	memseg_free_meta
#pragma weak	memseg_get_metapfn
#pragma weak	memseg_remap_meta

extern int ppvm_enable;
extern page_t *ppvm_base;
extern int memseg_alloc_meta(pfn_t, pgcnt_t, void **, pgcnt_t *);
extern void memseg_free_meta(void *, pgcnt_t);
extern pfn_t memseg_get_metapfn(void *, pgcnt_t);
extern void memseg_remap_meta(struct memseg *);
static int memseg_is_dynamic(struct memseg *);
static int memseg_includes_meta(struct memseg *);
pfn_t memseg_get_start(struct memseg *);
static void memseg_cpu_vm_flush(void);

int meta_alloc_enable;

#ifdef	DEBUG
static int memseg_debug;
#define	MEMSEG_DEBUG(args...) if (memseg_debug) printf(args)
#else
#define	MEMSEG_DEBUG(...)
#endif

/*
 * Add a chunk of memory to the system.
 * base: starting PAGESIZE page of new memory.
 * npgs: length in PAGESIZE pages.
 *
 * Adding mem this way doesn't increase the size of the hash tables;
 * growing them would be too hard.  This should be OK, but adding memory
 * dynamically most likely means more hash misses, since the tables will
 * be smaller than they otherwise would be.
 */
int
kphysm_add_memory_dynamic(pfn_t base, pgcnt_t npgs)
{
	page_t *pp;
	page_t		*opp, *oepp, *segpp;
	struct memseg	*seg;
	uint64_t	avmem;
	pfn_t		pfn;
	pfn_t		pt_base = base;
	pgcnt_t		tpgs = npgs;
	pgcnt_t		metapgs = 0;
	int		exhausted;
	pfn_t		pnum;
	int		mnode;
	caddr_t		vaddr;
	int		reuse;
	int		mlret;
	int		rv;
	int		flags;
	int		meta_alloc = 0;
	void		*mapva;
	void		*metabase = (void *)base;
	pgcnt_t		nkpmpgs = 0;
	offset_t	kpm_pages_off;

	cmn_err(CE_CONT,
	    "?kphysm_add_memory_dynamic: adding %ldK at 0x%" PRIx64 "\n",
	    npgs << (PAGESHIFT - 10), (uint64_t)base << PAGESHIFT);

	/*
	 * Add this span in the delete list to prevent interactions.
	 */
	if (!delspan_reserve(base, npgs)) {
		return (KPHYSM_ESPAN);
	}
	/*
	 * Check to see if any of the memory span has been added
	 * by trying an add to the installed memory list. This
	 * forms the interlocking process for add.
	 */

	memlist_write_lock();

	mlret = memlist_add_span((uint64_t)(pt_base) << PAGESHIFT,
	    (uint64_t)(tpgs) << PAGESHIFT, &phys_install);

	if (mlret == MEML_SPANOP_OK)
		installed_top_size(phys_install, &physmax, &physinstalled);

	memlist_write_unlock();

	if (mlret != MEML_SPANOP_OK) {
		if (mlret == MEML_SPANOP_EALLOC) {
			delspan_unreserve(pt_base, tpgs);
			return (KPHYSM_ERESOURCE);
		} else if (mlret == MEML_SPANOP_ESPAN) {
			delspan_unreserve(pt_base, tpgs);
			return (KPHYSM_ESPAN);
		} else {
			delspan_unreserve(pt_base, tpgs);
			return (KPHYSM_ERESOURCE);
		}
	}

	if (meta_alloc_enable) {
		/*
		 * Allocate the page_t's from existing memory;
		 * if that fails, allocate from the incoming memory.
		 */
		rv = memseg_alloc_meta(base, npgs, &metabase, &metapgs);
		if (rv == KPHYSM_OK) {
			ASSERT(metapgs);
			ASSERT(btopr(npgs * sizeof (page_t)) <= metapgs);
			meta_alloc = 1;
			goto mapalloc;
		}
	}

	/*
	 * We store the page_t's for this new memory in the first
	 * few pages of the chunk. Here, we go and get'em ...
	 */

	/*
	 * The expression after the '-' gives the number of pages
	 * that will fit in the new memory based on a requirement
	 * of (PAGESIZE + sizeof (page_t)) bytes per page.
	 */
	metapgs = npgs - (((uint64_t)(npgs) << PAGESHIFT) /
	    (PAGESIZE + sizeof (page_t)));

	npgs -= metapgs;
	base += metapgs;

	ASSERT(btopr(npgs * sizeof (page_t)) <= metapgs);

	exhausted = (metapgs == 0 || npgs == 0);

	if (kpm_enable && !exhausted) {
		pgcnt_t start, end, nkpmpgs_prelim;
		size_t	ptsz;

		/*
		 * A viable kpm large page mapping must not overlap two
		 * dynamic memsegs. Therefore the total size is checked
		 * to be at least kpm_pgsz and also whether start and end
		 * points are at least kpm_pgsz aligned.
		 */
		if (ptokpmp(tpgs) < 1 || pmodkpmp(pt_base) ||
		    pmodkpmp(base + npgs)) {

			kphysm_addmem_error_undospan(pt_base, tpgs);

			/*
			 * There is no specific error code for violating
			 * kpm granularity constraints.
			 */
			return (KPHYSM_ENOTVIABLE);
		}

		start = kpmptop(ptokpmp(base));
		end = kpmptop(ptokpmp(base + npgs));
		nkpmpgs_prelim = ptokpmp(end - start);
		ptsz = npgs * sizeof (page_t);
		metapgs = btopr(ptsz + nkpmpgs_prelim * KPMPAGE_T_SZ);
		exhausted = (tpgs <= metapgs);
		if (!exhausted) {
			npgs = tpgs - metapgs;
			base = pt_base + metapgs;

			/* final nkpmpgs */
			start = kpmptop(ptokpmp(base));
			nkpmpgs = ptokpmp(end - start);
			kpm_pages_off = ptsz +
			    (nkpmpgs_prelim - nkpmpgs) * KPMPAGE_T_SZ;
		}
	}

	/*
	 * Is memory area supplied too small?
	 */
	if (exhausted) {
		kphysm_addmem_error_undospan(pt_base, tpgs);
		/*
		 * There is no specific error code for 'too small'.
		 */
		return (KPHYSM_ERESOURCE);
	}

mapalloc:
	/*
	 * We may re-use a previously allocated VA space for the page_ts
	 * eventually, but we need to initialize and lock the pages first.
	 */

	/*
	 * Get an address in the kernel address map, map
	 * the page_t pages and see if we can touch them.
	 */

	mapva = vmem_alloc(heap_arena, ptob(metapgs), VM_NOSLEEP);
	if (mapva == NULL) {
		cmn_err(CE_WARN, "kphysm_add_memory_dynamic:"
		    " Can't allocate VA for page_ts");

		if (meta_alloc)
			memseg_free_meta(metabase, metapgs);
		kphysm_addmem_error_undospan(pt_base, tpgs);

		return (KPHYSM_ERESOURCE);
	}
	pp = mapva;

	if (physmax < (pt_base + tpgs))
		physmax = (pt_base + tpgs);

	/*
	 * In the remapping code we map one page at a time so we must do
	 * the same here to match mapping sizes.
	 */
	pfn = pt_base;
	vaddr = (caddr_t)pp;
	for (pnum = 0; pnum < metapgs; pnum++) {
		if (meta_alloc)
			pfn = memseg_get_metapfn(metabase, (pgcnt_t)pnum);
		hat_devload(kas.a_hat, vaddr, ptob(1), pfn,
		    PROT_READ | PROT_WRITE,
		    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
		pfn++;
		vaddr += ptob(1);
	}

	if (ddi_peek32((dev_info_t *)NULL,
	    (int32_t *)pp, (int32_t *)0) == DDI_FAILURE) {

		cmn_err(CE_WARN, "kphysm_add_memory_dynamic:"
		    " Can't access pp array at 0x%p [phys 0x%lx]",
		    (void *)pp, pt_base);

		hat_unload(kas.a_hat, (caddr_t)pp, ptob(metapgs),
		    HAT_UNLOAD_UNMAP|HAT_UNLOAD_UNLOCK);

		vmem_free(heap_arena, mapva, ptob(metapgs));
		if (meta_alloc)
			memseg_free_meta(metabase, metapgs);
		kphysm_addmem_error_undospan(pt_base, tpgs);

		return (KPHYSM_EFAULT);
	}

	/*
	 * Add this memory slice to its memory node translation.
	 *
	 * Note that right now, each node may have only one slice;
	 * this may change with COD or in larger SSM systems with
	 * nested latency groups, so we must not assume that the
	 * node does not yet exist.
	 *
	 * Note that there may be multiple memory nodes associated with
	 * a single lgrp node on x86 systems.
	 */
	pnum = pt_base + tpgs - 1;
	mem_node_add_range(pt_base, pnum);

	/*
	 * Allocate or resize page counters as necessary to accommodate
	 * the increase in memory pages.
	 */
	mnode = PFN_2_MEM_NODE(pnum);
	PAGE_CTRS_ADJUST(base, npgs, rv);
	if (rv) {

		mem_node_del_range(pt_base, pnum);

		/* cleanup the  page counters */
		page_ctrs_cleanup();

		hat_unload(kas.a_hat, (caddr_t)pp, ptob(metapgs),
		    HAT_UNLOAD_UNMAP|HAT_UNLOAD_UNLOCK);

		vmem_free(heap_arena, mapva, ptob(metapgs));
		if (meta_alloc)
			memseg_free_meta(metabase, metapgs);
		kphysm_addmem_error_undospan(pt_base, tpgs);

		return (KPHYSM_ERESOURCE);
	}

	/*
	 * Update the phys_avail memory list.
	 * The phys_install list was done at the start.
	 */

	memlist_write_lock();

	mlret = memlist_add_span((uint64_t)(base) << PAGESHIFT,
	    (uint64_t)(npgs) << PAGESHIFT, &phys_avail);
	ASSERT(mlret == MEML_SPANOP_OK);

	memlist_write_unlock();

	/* See if we can find a memseg to re-use. */
	if (meta_alloc) {
		seg = memseg_reuse(0);
		reuse = 1;	/* force unmapping of temp mapva */
		flags = MEMSEG_DYNAMIC | MEMSEG_META_ALLOC;
		/*
		 * There is a 1:1 fixed relationship between a pfn
		 * and a page_t VA.  The pfn is used as an index into
		 * the ppvm_base page_t table in order to calculate
		 * the page_t base address for a given pfn range.
		 */
		segpp = ppvm_base + base;
	} else {
		seg = memseg_reuse(metapgs);
		reuse = (seg != NULL);
		flags = MEMSEG_DYNAMIC | MEMSEG_META_INCL;
		segpp = pp;
	}

	/*
	 * Initialize the memseg structure representing this memory
	 * and add it to the existing list of memsegs. Do some basic
	 * initialization and add the memory to the system.
	 * In order to prevent lock deadlocks, the add_physmem()
	 * code is repeated here, but split into several stages.
	 *
	 * If a memseg is reused, invalidate memseg pointers in
	 * all cpu vm caches.  We need to do this this since the check
	 * 	pp >= seg->pages && pp < seg->epages
	 * used in various places is not atomic and so the first compare
	 * can happen before reuse and the second compare after reuse.
	 * The invalidation ensures that a memseg is not deferenced while
	 * it's page/pfn pointers are changing.
	 */
	if (seg == NULL) {
		seg = memseg_alloc();
		ASSERT(seg != NULL);
		seg->msegflags = flags;
		MEMSEG_DEBUG("memseg_get: alloc seg=0x%p, pages=0x%p",
		    (void *)seg, (void *)(seg->pages));
		seg->pages = segpp;
	} else {
		ASSERT(seg->msegflags == flags);
		ASSERT(seg->pages_base == seg->pages_end);
		MEMSEG_DEBUG("memseg_get: reuse seg=0x%p, pages=0x%p",
		    (void *)seg, (void *)(seg->pages));
		if (meta_alloc) {
			memseg_cpu_vm_flush();
			seg->pages = segpp;
		}
	}

	seg->epages = seg->pages + npgs;
	seg->pages_base = base;
	seg->pages_end = base + npgs;

	/*
	 * Initialize metadata. The page_ts are set to locked state
	 * ready to be freed.
	 */
	bzero((caddr_t)pp, ptob(metapgs));

	pfn = seg->pages_base;
	/* Save the original pp base in case we reuse a memseg. */
	opp = pp;
	oepp = opp + npgs;
	for (pp = opp; pp < oepp; pp++) {
		pp->p_pagenum = pfn;
		pfn++;
		page_iolock_init(pp);
		while (!page_lock(pp, SE_EXCL, (kmutex_t *)NULL, P_RECLAIM))
			continue;
		pp->p_offset = (u_offset_t)-1;
	}

	if (reuse) {
		/* Remap our page_ts to the re-used memseg VA space. */
		pfn = pt_base;
		vaddr = (caddr_t)seg->pages;
		for (pnum = 0; pnum < metapgs; pnum++) {
			if (meta_alloc)
				pfn = memseg_get_metapfn(metabase,
				    (pgcnt_t)pnum);
			hat_devload(kas.a_hat, vaddr, ptob(1), pfn,
			    PROT_READ | PROT_WRITE,
			    HAT_LOAD_REMAP | HAT_LOAD | HAT_LOAD_NOCONSIST);
			pfn++;
			vaddr += ptob(1);
		}

		hat_unload(kas.a_hat, (caddr_t)opp, ptob(metapgs),
		    HAT_UNLOAD_UNMAP|HAT_UNLOAD_UNLOCK);

		vmem_free(heap_arena, mapva, ptob(metapgs));
	}

	hat_kpm_addmem_mseg_update(seg, nkpmpgs, kpm_pages_off);

	memsegs_lock(1);

	/*
	 * The new memseg is inserted at the beginning of the list.
	 * Not only does this save searching for the tail, but in the
	 * case of a re-used memseg, it solves the problem of what
	 * happens if some process has still got a pointer to the
	 * memseg and follows the next pointer to continue traversing
	 * the memsegs list.
	 */

	hat_kpm_addmem_mseg_insert(seg);

	seg->next = memsegs;
	membar_producer();

	hat_kpm_addmem_memsegs_update(seg);

	memsegs = seg;

	build_pfn_hash();

	total_pages += npgs;

	/*
	 * Recalculate the paging parameters now total_pages has changed.
	 * This will also cause the clock hands to be reset before next use.
	 */
	setupclock(1);

	memsegs_unlock(1);

	PLCNT_MODIFY_MAX(seg->pages_base, (long)npgs);

	/*
	 * Free the pages outside the lock to avoid locking loops.
	 */
	for (pp = seg->pages; pp < seg->epages; pp++) {
		page_free(pp, 1);
	}

	/*
	 * Now that we've updated the appropriate memory lists we
	 * need to reset a number of globals, since we've increased memory.
	 * Several have already been updated for us as noted above. The
	 * globals we're interested in at this point are:
	 *   physmax - highest page frame number.
	 *   physinstalled - number of pages currently installed (done earlier)
	 *   maxmem - max free pages in the system
	 *   physmem - physical memory pages available
	 *   availrmem - real memory available
	 */

	mutex_enter(&freemem_lock);
	maxmem += npgs;
	physmem += npgs;
	availrmem += npgs;
	availrmem_initial += npgs;

	mutex_exit(&freemem_lock);

	dump_resize();

	page_freelist_coalesce_all(mnode);

	kphysm_setup_post_add(npgs);

	cmn_err(CE_CONT, "?kphysm_add_memory_dynamic: mem = %ldK "
	    "(0x%" PRIx64 ")\n",
	    physinstalled << (PAGESHIFT - 10),
	    (uint64_t)physinstalled << PAGESHIFT);

	avmem = (uint64_t)freemem << PAGESHIFT;
	cmn_err(CE_CONT, "?kphysm_add_memory_dynamic: "
	    "avail mem = %" PRId64 "\n", avmem);

	/*
	 * Update lgroup generation number on single lgroup systems
	 */
	if (nlgrps == 1)
		lgrp_config(LGRP_CONFIG_GEN_UPDATE, 0, 0);

	/*
	 * Inform DDI of update
	 */
	ddi_mem_update((uint64_t)(pt_base) << PAGESHIFT,
	    (uint64_t)(tpgs) << PAGESHIFT);

	delspan_unreserve(pt_base, tpgs);

	return (KPHYSM_OK);		/* Successfully added system memory */
}

/*
 * There are various error conditions in kphysm_add_memory_dynamic()
 * which require a rollback of already changed global state.
 */
static void
kphysm_addmem_error_undospan(pfn_t pt_base, pgcnt_t tpgs)
{
	int mlret;

	/* Unreserve memory span. */
	memlist_write_lock();

	mlret = memlist_delete_span(
	    (uint64_t)(pt_base) << PAGESHIFT,
	    (uint64_t)(tpgs) << PAGESHIFT, &phys_install);

	ASSERT(mlret == MEML_SPANOP_OK);
	phys_install_has_changed();
	installed_top_size(phys_install, &physmax, &physinstalled);

	memlist_write_unlock();
	delspan_unreserve(pt_base, tpgs);
}

/*
 * Only return an available memseg of exactly the right size
 * if size is required.
 * When the meta data area has it's own virtual address space
 * we will need to manage this more carefully and do best fit
 * allocations, possibly splitting an available area.
 */
struct memseg *
memseg_reuse(pgcnt_t metapgs)
{
	int type;
	struct memseg **segpp, *seg;

	mutex_enter(&memseg_lists_lock);

	segpp = &memseg_va_avail;
	for (; (seg = *segpp) != NULL; segpp = &seg->lnext) {
		caddr_t end;

		/*
		 * Make sure we are reusing the right segment type.
		 */
		type = metapgs ? MEMSEG_META_INCL : MEMSEG_META_ALLOC;

		if ((seg->msegflags & (MEMSEG_META_INCL | MEMSEG_META_ALLOC))
		    != type)
			continue;

		if (kpm_enable)
			end = hat_kpm_mseg_reuse(seg);
		else
			end = (caddr_t)seg->epages;

		/*
		 * Check for the right size if it is provided.
		 */
		if (!metapgs || btopr(end - (caddr_t)seg->pages) == metapgs) {
			*segpp = seg->lnext;
			seg->lnext = NULL;
			break;
		}
	}
	mutex_exit(&memseg_lists_lock);

	return (seg);
}

static uint_t handle_gen;

struct memdelspan {
	struct memdelspan *mds_next;
	pfn_t		mds_base;
	pgcnt_t		mds_npgs;
	uint_t		*mds_bitmap;
	uint_t		*mds_bitmap_retired;
};

#define	NBPBMW		(sizeof (uint_t) * NBBY)
#define	MDS_BITMAPBYTES(MDSP) \
	((((MDSP)->mds_npgs + NBPBMW - 1) / NBPBMW) * sizeof (uint_t))

struct transit_list {
	struct transit_list	*trl_next;
	struct memdelspan	*trl_spans;
	int			trl_collect;
};

struct transit_list_head {
	kmutex_t		trh_lock;
	struct transit_list	*trh_head;
};

static struct transit_list_head transit_list_head;

struct mem_handle;
static void transit_list_collect(struct mem_handle *, int);
static void transit_list_insert(struct transit_list *);
static void transit_list_remove(struct transit_list *);

#ifdef DEBUG
#define	MEM_DEL_STATS
#endif /* DEBUG */

#ifdef MEM_DEL_STATS
static int mem_del_stat_print = 0;
struct mem_del_stat {
	uint_t	nloop;
	uint_t	need_free;
	uint_t	free_loop;
	uint_t	free_low;
	uint_t	free_failed;
	uint_t	ncheck;
	uint_t	nopaget;
	uint_t	lockfail;
	uint_t	nfree;
	uint_t	nreloc;
	uint_t	nrelocfail;
	uint_t	already_done;
	uint_t	first_notfree;
	uint_t	npplocked;
	uint_t	nlockreloc;
	uint_t	nnorepl;
	uint_t	nmodreloc;
	uint_t	ndestroy;
	uint_t	nputpage;
	uint_t	nnoreclaim;
	uint_t	ndelay;
	uint_t	demotefail;
	uint64_t nticks_total;
	uint64_t nticks_pgrp;
	uint_t	retired;
	uint_t	toxic;
	uint_t	failing;
	uint_t	modtoxic;
	uint_t	npplkdtoxic;
	uint_t	gptlmodfail;
	uint_t	gptllckfail;
};
/*
 * The stat values are only incremented in the delete thread
 * so no locking or atomic required.
 */
#define	MDSTAT_INCR(MHP, FLD)	(MHP)->mh_delstat.FLD++
#define	MDSTAT_TOTAL(MHP, ntck)	((MHP)->mh_delstat.nticks_total += (ntck))
#define	MDSTAT_PGRP(MHP, ntck)	((MHP)->mh_delstat.nticks_pgrp += (ntck))
static void mem_del_stat_print_func(struct mem_handle *);
#define	MDSTAT_PRINT(MHP)	mem_del_stat_print_func((MHP))
#else /* MEM_DEL_STATS */
#define	MDSTAT_INCR(MHP, FLD)
#define	MDSTAT_TOTAL(MHP, ntck)
#define	MDSTAT_PGRP(MHP, ntck)
#define	MDSTAT_PRINT(MHP)
#endif /* MEM_DEL_STATS */

typedef enum mhnd_state {MHND_FREE = 0, MHND_INIT, MHND_STARTING,
	MHND_RUNNING, MHND_DONE, MHND_RELEASE} mhnd_state_t;

/*
 * mh_mutex must be taken to examine or change mh_exthandle and mh_state.
 * The mutex may not be required for other fields, dependent on mh_state.
 */
struct mem_handle {
	kmutex_t	mh_mutex;
	struct mem_handle *mh_next;
	memhandle_t	mh_exthandle;
	mhnd_state_t	mh_state;
	struct transit_list mh_transit;
	pgcnt_t		mh_phys_pages;
	pgcnt_t		mh_vm_pages;
	pgcnt_t		mh_hold_todo;
	void		(*mh_delete_complete)(void *, int error);
	void		*mh_delete_complete_arg;
	volatile uint_t mh_cancel;
	volatile uint_t mh_dr_aio_cleanup_cancel;
	volatile uint_t mh_aio_cleanup_done;
	kcondvar_t	mh_cv;
	kthread_id_t	mh_thread_id;
	page_t		*mh_deleted;	/* link through p_next */
#ifdef MEM_DEL_STATS
	struct mem_del_stat mh_delstat;
#endif /* MEM_DEL_STATS */
};

static struct mem_handle *mem_handle_head;
static kmutex_t mem_handle_list_mutex;

static struct mem_handle *
kphysm_allocate_mem_handle()
{
	struct mem_handle *mhp;

	mhp = kmem_zalloc(sizeof (struct mem_handle), KM_SLEEP);
	mutex_init(&mhp->mh_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_enter(&mem_handle_list_mutex);
	mutex_enter(&mhp->mh_mutex);
	/* handle_gen is protected by list mutex. */
	mhp->mh_exthandle = (memhandle_t)(uintptr_t)(++handle_gen);
	mhp->mh_next = mem_handle_head;
	mem_handle_head = mhp;
	mutex_exit(&mem_handle_list_mutex);

	return (mhp);
}

static void
kphysm_free_mem_handle(struct mem_handle *mhp)
{
	struct mem_handle **mhpp;

	ASSERT(mutex_owned(&mhp->mh_mutex));
	ASSERT(mhp->mh_state == MHND_FREE);
	/*
	 * Exit the mutex to preserve locking order. This is OK
	 * here as once in the FREE state, the handle cannot
	 * be found by a lookup.
	 */
	mutex_exit(&mhp->mh_mutex);

	mutex_enter(&mem_handle_list_mutex);
	mhpp = &mem_handle_head;
	while (*mhpp != NULL && *mhpp != mhp)
		mhpp = &(*mhpp)->mh_next;
	ASSERT(*mhpp == mhp);
	/*
	 * No need to lock the handle (mh_mutex) as only
	 * mh_next changing and this is the only thread that
	 * can be referncing mhp.
	 */
	*mhpp = mhp->mh_next;
	mutex_exit(&mem_handle_list_mutex);

	mutex_destroy(&mhp->mh_mutex);
	kmem_free(mhp, sizeof (struct mem_handle));
}

/*
 * This function finds the internal mem_handle corresponding to an
 * external handle and returns it with the mh_mutex held.
 */
static struct mem_handle *
kphysm_lookup_mem_handle(memhandle_t handle)
{
	struct mem_handle *mhp;

	mutex_enter(&mem_handle_list_mutex);
	for (mhp = mem_handle_head; mhp != NULL; mhp = mhp->mh_next) {
		if (mhp->mh_exthandle == handle) {
			mutex_enter(&mhp->mh_mutex);
			/*
			 * The state of the handle could have been changed
			 * by kphysm_del_release() while waiting for mh_mutex.
			 */
			if (mhp->mh_state == MHND_FREE) {
				mutex_exit(&mhp->mh_mutex);
				continue;
			}
			break;
		}
	}
	mutex_exit(&mem_handle_list_mutex);
	return (mhp);
}

int
kphysm_del_gethandle(memhandle_t *xmhp)
{
	struct mem_handle *mhp;

	mhp = kphysm_allocate_mem_handle();
	/*
	 * The handle is allocated using KM_SLEEP, so cannot fail.
	 * If the implementation is changed, the correct error to return
	 * here would be KPHYSM_ENOHANDLES.
	 */
	ASSERT(mhp->mh_state == MHND_FREE);
	mhp->mh_state = MHND_INIT;
	*xmhp = mhp->mh_exthandle;
	mutex_exit(&mhp->mh_mutex);
	return (KPHYSM_OK);
}

static int
overlapping(pfn_t b1, pgcnt_t l1, pfn_t b2, pgcnt_t l2)
{
	pfn_t e1, e2;

	e1 = b1 + l1;
	e2 = b2 + l2;

	return (!(b2 >= e1 || b1 >= e2));
}

static int can_remove_pgs(pgcnt_t);

static struct memdelspan *
span_to_install(pfn_t base, pgcnt_t npgs)
{
	struct memdelspan *mdsp;
	struct memdelspan *mdsp_new;
	uint64_t address, size, thislen;
	struct memlist *mlp;

	mdsp_new = NULL;

	address = (uint64_t)base << PAGESHIFT;
	size = (uint64_t)npgs << PAGESHIFT;
	while (size != 0) {
		memlist_read_lock();
		for (mlp = phys_install; mlp != NULL; mlp = mlp->ml_next) {
			if (address >= (mlp->ml_address + mlp->ml_size))
				continue;
			if ((address + size) > mlp->ml_address)
				break;
		}
		if (mlp == NULL) {
			address += size;
			size = 0;
			thislen = 0;
		} else {
			if (address < mlp->ml_address) {
				size -= (mlp->ml_address - address);
				address = mlp->ml_address;
			}
			ASSERT(address >= mlp->ml_address);
			if ((address + size) >
			    (mlp->ml_address + mlp->ml_size)) {
				thislen =
				    mlp->ml_size - (address - mlp->ml_address);
			} else {
				thislen = size;
			}
		}
		memlist_read_unlock();
		/* TODO: phys_install could change now */
		if (thislen == 0)
			continue;
		mdsp = kmem_zalloc(sizeof (struct memdelspan), KM_SLEEP);
		mdsp->mds_base = btop(address);
		mdsp->mds_npgs = btop(thislen);
		mdsp->mds_next = mdsp_new;
		mdsp_new = mdsp;
		address += thislen;
		size -= thislen;
	}
	return (mdsp_new);
}

static void
free_delspans(struct memdelspan *mdsp)
{
	struct memdelspan *amdsp;

	while ((amdsp = mdsp) != NULL) {
		mdsp = amdsp->mds_next;
		kmem_free(amdsp, sizeof (struct memdelspan));
	}
}

/*
 * Concatenate lists. No list ordering is required.
 */

static void
delspan_concat(struct memdelspan **mdspp, struct memdelspan *mdsp)
{
	while (*mdspp != NULL)
		mdspp = &(*mdspp)->mds_next;

	*mdspp = mdsp;
}

/*
 * Given a new list of delspans, check there is no overlap with
 * all existing span activity (add or delete) and then concatenate
 * the new spans to the given list.
 * Return 1 for OK, 0 if overlapping.
 */
static int
delspan_insert(
	struct transit_list *my_tlp,
	struct memdelspan *mdsp_new)
{
	struct transit_list_head *trh;
	struct transit_list *tlp;
	int ret;

	trh = &transit_list_head;

	ASSERT(my_tlp != NULL);
	ASSERT(mdsp_new != NULL);

	ret = 1;
	mutex_enter(&trh->trh_lock);
	/* ASSERT(my_tlp->trl_spans == NULL || tlp_in_list(trh, my_tlp)); */
	for (tlp = trh->trh_head; tlp != NULL; tlp = tlp->trl_next) {
		struct memdelspan *mdsp;

		for (mdsp = tlp->trl_spans; mdsp != NULL;
		    mdsp = mdsp->mds_next) {
			struct memdelspan *nmdsp;

			for (nmdsp = mdsp_new; nmdsp != NULL;
			    nmdsp = nmdsp->mds_next) {
				if (overlapping(mdsp->mds_base, mdsp->mds_npgs,
				    nmdsp->mds_base, nmdsp->mds_npgs)) {
					ret = 0;
					goto done;
				}
			}
		}
	}
done:
	if (ret != 0) {
		if (my_tlp->trl_spans == NULL)
			transit_list_insert(my_tlp);
		delspan_concat(&my_tlp->trl_spans, mdsp_new);
	}
	mutex_exit(&trh->trh_lock);
	return (ret);
}

static void
delspan_remove(
	struct transit_list *my_tlp,
	pfn_t base,
	pgcnt_t npgs)
{
	struct transit_list_head *trh;
	struct memdelspan *mdsp;

	trh = &transit_list_head;

	ASSERT(my_tlp != NULL);

	mutex_enter(&trh->trh_lock);
	if ((mdsp = my_tlp->trl_spans) != NULL) {
		if (npgs == 0) {
			my_tlp->trl_spans = NULL;
			free_delspans(mdsp);
			transit_list_remove(my_tlp);
		} else {
			struct memdelspan **prv;

			prv = &my_tlp->trl_spans;
			while (mdsp != NULL) {
				pfn_t p_end;

				p_end = mdsp->mds_base + mdsp->mds_npgs;
				if (mdsp->mds_base >= base &&
				    p_end <= (base + npgs)) {
					*prv = mdsp->mds_next;
					mdsp->mds_next = NULL;
					free_delspans(mdsp);
				} else {
					prv = &mdsp->mds_next;
				}
				mdsp = *prv;
			}
			if (my_tlp->trl_spans == NULL)
				transit_list_remove(my_tlp);
		}
	}
	mutex_exit(&trh->trh_lock);
}

/*
 * Reserve interface for add to stop delete before add finished.
 * This list is only accessed through the delspan_insert/remove
 * functions and so is fully protected by the mutex in struct transit_list.
 */

static struct transit_list reserve_transit;

static int
delspan_reserve(pfn_t base, pgcnt_t npgs)
{
	struct memdelspan *mdsp;
	int ret;

	mdsp = kmem_zalloc(sizeof (struct memdelspan), KM_SLEEP);
	mdsp->mds_base = base;
	mdsp->mds_npgs = npgs;
	if ((ret = delspan_insert(&reserve_transit, mdsp)) == 0) {
		free_delspans(mdsp);
	}
	return (ret);
}

static void
delspan_unreserve(pfn_t base, pgcnt_t npgs)
{
	delspan_remove(&reserve_transit, base, npgs);
}

/*
 * Return whether memseg was created by kphysm_add_memory_dynamic().
 */
static int
memseg_is_dynamic(struct memseg *seg)
{
	return (seg->msegflags & MEMSEG_DYNAMIC);
}

int
kphysm_del_span(
	memhandle_t handle,
	pfn_t base,
	pgcnt_t npgs)
{
	struct mem_handle *mhp;
	struct memseg *seg;
	struct memdelspan *mdsp;
	struct memdelspan *mdsp_new;
	pgcnt_t phys_pages, vm_pages;
	pfn_t p_end;
	page_t *pp;
	int ret;

	mhp = kphysm_lookup_mem_handle(handle);
	if (mhp == NULL) {
		return (KPHYSM_EHANDLE);
	}
	if (mhp->mh_state != MHND_INIT) {
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ESEQUENCE);
	}

	/*
	 * Intersect the span with the installed memory list (phys_install).
	 */
	mdsp_new = span_to_install(base, npgs);
	if (mdsp_new == NULL) {
		/*
		 * No physical memory in this range. Is this an
		 * error? If an attempt to start the delete is made
		 * for OK returns from del_span such as this, start will
		 * return an error.
		 * Could return KPHYSM_ENOWORK.
		 */
		/*
		 * It is assumed that there are no error returns
		 * from span_to_install() due to kmem_alloc failure.
		 */
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_OK);
	}
	/*
	 * Does this span overlap an existing span?
	 */
	if (delspan_insert(&mhp->mh_transit, mdsp_new) == 0) {
		/*
		 * Differentiate between already on list for this handle
		 * (KPHYSM_EDUP) and busy elsewhere (KPHYSM_EBUSY).
		 */
		ret = KPHYSM_EBUSY;
		for (mdsp = mhp->mh_transit.trl_spans; mdsp != NULL;
		    mdsp = mdsp->mds_next) {
			if (overlapping(mdsp->mds_base, mdsp->mds_npgs,
			    base, npgs)) {
				ret = KPHYSM_EDUP;
				break;
			}
		}
		mutex_exit(&mhp->mh_mutex);
		free_delspans(mdsp_new);
		return (ret);
	}
	/*
	 * At this point the spans in mdsp_new have been inserted into the
	 * list of spans for this handle and thereby to the global list of
	 * spans being processed. Each of these spans must now be checked
	 * for relocatability. As a side-effect segments in the memseg list
	 * may be split.
	 *
	 * Note that mdsp_new can no longer be used as it is now part of
	 * a larger list. Select elements of this larger list based
	 * on base and npgs.
	 */
restart:
	phys_pages = 0;
	vm_pages = 0;
	ret = KPHYSM_OK;
	for (mdsp = mhp->mh_transit.trl_spans; mdsp != NULL;
	    mdsp = mdsp->mds_next) {
		pgcnt_t pages_checked;

		if (!overlapping(mdsp->mds_base, mdsp->mds_npgs, base, npgs)) {
			continue;
		}
		p_end = mdsp->mds_base + mdsp->mds_npgs;
		/*
		 * The pages_checked count is a hack. All pages should be
		 * checked for relocatability. Those not covered by memsegs
		 * should be tested with arch_kphysm_del_span_ok().
		 */
		pages_checked = 0;
		for (seg = memsegs; seg; seg = seg->next) {
			pfn_t mseg_start;

			if (seg->pages_base >= p_end ||
			    seg->pages_end <= mdsp->mds_base) {
				/* Span and memseg don't overlap. */
				continue;
			}
			mseg_start = memseg_get_start(seg);
			/* Check that segment is suitable for delete. */
			if (memseg_includes_meta(seg)) {
				/*
				 * Check that this segment is completely
				 * within the span.
				 */
				if (mseg_start < mdsp->mds_base ||
				    seg->pages_end > p_end) {
					ret = KPHYSM_EBUSY;
					break;
				}
				pages_checked += seg->pages_end - mseg_start;
			} else {
				/*
				 * If this segment is larger than the span,
				 * try to split it. After the split, it
				 * is necessary to restart.
				 */
				if (seg->pages_base < mdsp->mds_base ||
				    seg->pages_end > p_end) {
					pfn_t abase;
					pgcnt_t anpgs;
					int s_ret;

					/* Split required.  */
					if (mdsp->mds_base < seg->pages_base)
						abase = seg->pages_base;
					else
						abase = mdsp->mds_base;
					if (p_end > seg->pages_end)
						anpgs = seg->pages_end - abase;
					else
						anpgs = p_end - abase;
					s_ret = kphysm_split_memseg(abase,
					    anpgs);
					if (s_ret == 0) {
						/* Split failed. */
						ret = KPHYSM_ERESOURCE;
						break;
					}
					goto restart;
				}
				pages_checked +=
				    seg->pages_end - seg->pages_base;
			}
			/*
			 * The memseg is wholly within the delete span.
			 * The individual pages can now be checked.
			 */
			/* Cage test. */
			for (pp = seg->pages; pp < seg->epages; pp++) {
				if (PP_ISNORELOC(pp)) {
					ret = KPHYSM_ENONRELOC;
					break;
				}
			}
			if (ret != KPHYSM_OK) {
				break;
			}
			phys_pages += (seg->pages_end - mseg_start);
			vm_pages += MSEG_NPAGES(seg);
		}
		if (ret != KPHYSM_OK)
			break;
		if (pages_checked != mdsp->mds_npgs) {
			ret = KPHYSM_ENONRELOC;
			break;
		}
	}

	if (ret == KPHYSM_OK) {
		mhp->mh_phys_pages += phys_pages;
		mhp->mh_vm_pages += vm_pages;
	} else {
		/*
		 * Keep holding the mh_mutex to prevent it going away.
		 */
		delspan_remove(&mhp->mh_transit, base, npgs);
	}
	mutex_exit(&mhp->mh_mutex);
	return (ret);
}

int
kphysm_del_span_query(
	pfn_t base,
	pgcnt_t npgs,
	memquery_t *mqp)
{
	struct memdelspan *mdsp;
	struct memdelspan *mdsp_new;
	int done_first_nonreloc;

	mqp->phys_pages = 0;
	mqp->managed = 0;
	mqp->nonrelocatable = 0;
	mqp->first_nonrelocatable = 0;
	mqp->last_nonrelocatable = 0;

	mdsp_new = span_to_install(base, npgs);
	/*
	 * It is OK to proceed here if mdsp_new == NULL.
	 */
	done_first_nonreloc = 0;
	for (mdsp = mdsp_new; mdsp != NULL; mdsp = mdsp->mds_next) {
		pfn_t sbase;
		pgcnt_t snpgs;

		mqp->phys_pages += mdsp->mds_npgs;
		sbase = mdsp->mds_base;
		snpgs = mdsp->mds_npgs;
		while (snpgs != 0) {
			struct memseg *lseg, *seg;
			pfn_t p_end;
			page_t *pp;
			pfn_t mseg_start;

			p_end = sbase + snpgs;
			/*
			 * Find the lowest addressed memseg that starts
			 * after sbase and account for it.
			 * This is to catch dynamic memsegs whose start
			 * is hidden.
			 */
			seg = NULL;
			for (lseg = memsegs; lseg != NULL; lseg = lseg->next) {
				if ((lseg->pages_base >= sbase) ||
				    (lseg->pages_base < p_end &&
				    lseg->pages_end > sbase)) {
					if (seg == NULL ||
					    seg->pages_base > lseg->pages_base)
						seg = lseg;
				}
			}
			if (seg != NULL) {
				mseg_start = memseg_get_start(seg);
				/*
				 * Now have the full extent of the memseg so
				 * do the range check.
				 */
				if (mseg_start >= p_end ||
				    seg->pages_end <= sbase) {
					/* Span does not overlap memseg. */
					seg = NULL;
				}
			}
			/*
			 * Account for gap either before the segment if
			 * there is one or to the end of the span.
			 */
			if (seg == NULL || mseg_start > sbase) {
				pfn_t a_end;

				a_end = (seg == NULL) ? p_end : mseg_start;
				/*
				 * Check with arch layer for relocatability.
				 */
				if (arch_kphysm_del_span_ok(sbase,
				    (a_end - sbase))) {
					/*
					 * No non-relocatble pages in this
					 * area, avoid the fine-grained
					 * test.
					 */
					snpgs -= (a_end - sbase);
					sbase = a_end;
				}
				while (sbase < a_end) {
					if (!arch_kphysm_del_span_ok(sbase,
					    1)) {
						mqp->nonrelocatable++;
						if (!done_first_nonreloc) {
							mqp->
							    first_nonrelocatable
							    = sbase;
							done_first_nonreloc = 1;
						}
						mqp->last_nonrelocatable =
						    sbase;
					}
					sbase++;
					snpgs--;
				}
			}
			if (seg != NULL) {
				ASSERT(mseg_start <= sbase);
				if (seg->pages_base != mseg_start &&
				    seg->pages_base > sbase) {
					pgcnt_t skip_pgs;

					/*
					 * Skip the page_t area of a
					 * dynamic memseg.
					 */
					skip_pgs = seg->pages_base - sbase;
					if (snpgs <= skip_pgs) {
						sbase += snpgs;
						snpgs = 0;
						continue;
					}
					snpgs -= skip_pgs;
					sbase += skip_pgs;
				}
				ASSERT(snpgs != 0);
				ASSERT(seg->pages_base <= sbase);
				/*
				 * The individual pages can now be checked.
				 */
				for (pp = seg->pages +
				    (sbase - seg->pages_base);
				    snpgs != 0 && pp < seg->epages; pp++) {
					mqp->managed++;
					if (PP_ISNORELOC(pp)) {
						mqp->nonrelocatable++;
						if (!done_first_nonreloc) {
							mqp->
							    first_nonrelocatable
							    = sbase;
							done_first_nonreloc = 1;
						}
						mqp->last_nonrelocatable =
						    sbase;
					}
					sbase++;
					snpgs--;
				}
			}
		}
	}

	free_delspans(mdsp_new);

	return (KPHYSM_OK);
}

/*
 * This release function can be called at any stage as follows:
 *	_gethandle only called
 *	_span(s) only called
 *	_start called but failed
 *	delete thread exited
 */
int
kphysm_del_release(memhandle_t handle)
{
	struct mem_handle *mhp;

	mhp = kphysm_lookup_mem_handle(handle);
	if (mhp == NULL) {
		return (KPHYSM_EHANDLE);
	}
	switch (mhp->mh_state) {
	case MHND_STARTING:
	case MHND_RUNNING:
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ENOTFINISHED);
	case MHND_FREE:
		ASSERT(mhp->mh_state != MHND_FREE);
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_EHANDLE);
	case MHND_INIT:
		break;
	case MHND_DONE:
		break;
	case MHND_RELEASE:
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ESEQUENCE);
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "kphysm_del_release(0x%p) state corrupt %d",
		    (void *)mhp, mhp->mh_state);
#endif /* DEBUG */
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_EHANDLE);
	}
	/*
	 * Set state so that we can wait if necessary.
	 * Also this means that we have read/write access to all
	 * fields except mh_exthandle and mh_state.
	 */
	mhp->mh_state = MHND_RELEASE;
	/*
	 * The mem_handle cannot be de-allocated by any other operation
	 * now, so no need to hold mh_mutex.
	 */
	mutex_exit(&mhp->mh_mutex);

	delspan_remove(&mhp->mh_transit, 0, 0);
	mhp->mh_phys_pages = 0;
	mhp->mh_vm_pages = 0;
	mhp->mh_hold_todo = 0;
	mhp->mh_delete_complete = NULL;
	mhp->mh_delete_complete_arg = NULL;
	mhp->mh_cancel = 0;

	mutex_enter(&mhp->mh_mutex);
	ASSERT(mhp->mh_state == MHND_RELEASE);
	mhp->mh_state = MHND_FREE;

	kphysm_free_mem_handle(mhp);

	return (KPHYSM_OK);
}

/*
 * This cancel function can only be called with the thread running.
 */
int
kphysm_del_cancel(memhandle_t handle)
{
	struct mem_handle *mhp;

	mhp = kphysm_lookup_mem_handle(handle);
	if (mhp == NULL) {
		return (KPHYSM_EHANDLE);
	}
	if (mhp->mh_state != MHND_STARTING && mhp->mh_state != MHND_RUNNING) {
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ENOTRUNNING);
	}
	/*
	 * Set the cancel flag and wake the delete thread up.
	 * The thread may be waiting on I/O, so the effect of the cancel
	 * may be delayed.
	 */
	if (mhp->mh_cancel == 0) {
		mhp->mh_cancel = KPHYSM_ECANCELLED;
		cv_signal(&mhp->mh_cv);
	}
	mutex_exit(&mhp->mh_mutex);
	return (KPHYSM_OK);
}

int
kphysm_del_status(
	memhandle_t handle,
	memdelstat_t *mdstp)
{
	struct mem_handle *mhp;

	mhp = kphysm_lookup_mem_handle(handle);
	if (mhp == NULL) {
		return (KPHYSM_EHANDLE);
	}
	/*
	 * Calling kphysm_del_status() is allowed before the delete
	 * is started to allow for status display.
	 */
	if (mhp->mh_state != MHND_INIT && mhp->mh_state != MHND_STARTING &&
	    mhp->mh_state != MHND_RUNNING) {
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ENOTRUNNING);
	}
	mdstp->phys_pages = mhp->mh_phys_pages;
	mdstp->managed = mhp->mh_vm_pages;
	mdstp->collected = mhp->mh_vm_pages - mhp->mh_hold_todo;
	mutex_exit(&mhp->mh_mutex);
	return (KPHYSM_OK);
}

static int mem_delete_additional_pages = 100;

static int
can_remove_pgs(pgcnt_t npgs)
{
	/*
	 * If all pageable pages were paged out, freemem would
	 * equal availrmem.  There is a minimum requirement for
	 * availrmem.
	 */
	if ((availrmem - (tune.t_minarmem + mem_delete_additional_pages))
	    < npgs)
		return (0);
	/* TODO: check swap space, etc. */
	return (1);
}

static int
get_availrmem(pgcnt_t npgs)
{
	int ret;

	mutex_enter(&freemem_lock);
	ret = can_remove_pgs(npgs);
	if (ret != 0)
		availrmem -= npgs;
	mutex_exit(&freemem_lock);
	return (ret);
}

static void
put_availrmem(pgcnt_t npgs)
{
	mutex_enter(&freemem_lock);
	availrmem += npgs;
	mutex_exit(&freemem_lock);
}

#define	FREEMEM_INCR	100
static pgcnt_t freemem_incr = FREEMEM_INCR;
#define	DEL_FREE_WAIT_FRAC	4
#define	DEL_FREE_WAIT_TICKS	((hz+DEL_FREE_WAIT_FRAC-1)/DEL_FREE_WAIT_FRAC)

#define	DEL_BUSY_WAIT_FRAC	20
#define	DEL_BUSY_WAIT_TICKS	((hz+DEL_BUSY_WAIT_FRAC-1)/DEL_BUSY_WAIT_FRAC)

static void kphysm_del_cleanup(struct mem_handle *);

static void page_delete_collect(page_t *, struct mem_handle *);

static pgcnt_t
delthr_get_freemem(struct mem_handle *mhp)
{
	pgcnt_t free_get;
	int ret;

	ASSERT(MUTEX_HELD(&mhp->mh_mutex));

	MDSTAT_INCR(mhp, need_free);
	/*
	 * Get up to freemem_incr pages.
	 */
	free_get = freemem_incr;
	if (free_get > mhp->mh_hold_todo)
		free_get = mhp->mh_hold_todo;
	/*
	 * Take free_get pages away from freemem,
	 * waiting if necessary.
	 */

	while (!mhp->mh_cancel) {
		mutex_exit(&mhp->mh_mutex);
		MDSTAT_INCR(mhp, free_loop);
		/*
		 * Duplicate test from page_create_throttle()
		 * but don't override with !PG_WAIT.
		 */
		if (freemem < (free_get + throttlefree)) {
			MDSTAT_INCR(mhp, free_low);
			ret = 0;
		} else {
			ret = page_create_wait(free_get, 0);
			if (ret == 0) {
				/* EMPTY */
				MDSTAT_INCR(mhp, free_failed);
			}
		}
		if (ret != 0) {
			mutex_enter(&mhp->mh_mutex);
			return (free_get);
		}

		/*
		 * Put pressure on pageout.
		 */
		page_needfree(free_get);
		cv_signal(&proc_pageout->p_cv);

		mutex_enter(&mhp->mh_mutex);
		(void) cv_reltimedwait(&mhp->mh_cv, &mhp->mh_mutex,
		    DEL_FREE_WAIT_TICKS, TR_CLOCK_TICK);
		mutex_exit(&mhp->mh_mutex);
		page_needfree(-(spgcnt_t)free_get);

		mutex_enter(&mhp->mh_mutex);
	}
	return (0);
}

#define	DR_AIO_CLEANUP_DELAY	25000	/* 0.025secs, in usec */
#define	DR_AIO_CLEANUP_MAXLOOPS_NODELAY	100
/*
 * This function is run as a helper thread for delete_memory_thread.
 * It is needed in order to force kaio cleanup, so that pages used in kaio
 * will be unlocked and subsequently relocated by delete_memory_thread.
 * The address of the delete_memory_threads's mem_handle is passed in to
 * this thread function, and is used to set the mh_aio_cleanup_done member
 * prior to calling thread_exit().
 */
static void
dr_aio_cleanup_thread(caddr_t amhp)
{
	proc_t *procp;
	int (*aio_cleanup_dr_delete_memory)(proc_t *);
	int cleaned;
	int n = 0;
	struct mem_handle *mhp;
	volatile uint_t *pcancel;

	mhp = (struct mem_handle *)amhp;
	ASSERT(mhp != NULL);
	pcancel = &mhp->mh_dr_aio_cleanup_cancel;
	if (modload("sys", "kaio") == -1) {
		mhp->mh_aio_cleanup_done = 1;
		cmn_err(CE_WARN, "dr_aio_cleanup_thread: cannot load kaio");
		thread_exit();
	}
	aio_cleanup_dr_delete_memory = (int (*)(proc_t *))
	    modgetsymvalue("aio_cleanup_dr_delete_memory", 0);
	if (aio_cleanup_dr_delete_memory == NULL) {
		mhp->mh_aio_cleanup_done = 1;
		cmn_err(CE_WARN,
	    "aio_cleanup_dr_delete_memory not found in kaio");
		thread_exit();
	}
	do {
		cleaned = 0;
		mutex_enter(&pidlock);
		for (procp = practive; (*pcancel == 0) && (procp != NULL);
		    procp = procp->p_next) {
			mutex_enter(&procp->p_lock);
			if (procp->p_aio != NULL) {
				/* cleanup proc's outstanding kaio */
				cleaned +=
				    (*aio_cleanup_dr_delete_memory)(procp);
			}
			mutex_exit(&procp->p_lock);
		}
		mutex_exit(&pidlock);
		if ((*pcancel == 0) &&
		    (!cleaned || (++n == DR_AIO_CLEANUP_MAXLOOPS_NODELAY))) {
			/* delay a bit before retrying all procs again */
			delay(drv_usectohz(DR_AIO_CLEANUP_DELAY));
			n = 0;
		}
	} while (*pcancel == 0);
	mhp->mh_aio_cleanup_done = 1;
	thread_exit();
}

static void
delete_memory_thread(caddr_t amhp)
{
	struct mem_handle *mhp;
	struct memdelspan *mdsp;
	callb_cpr_t cprinfo;
	page_t *pp_targ;
	spgcnt_t freemem_left;
	void (*del_complete_funcp)(void *, int error);
	void *del_complete_arg;
	int comp_code;
	int ret;
	int first_scan;
	uint_t szc;
#ifdef MEM_DEL_STATS
	uint64_t start_total, ntick_total;
	uint64_t start_pgrp, ntick_pgrp;
#endif /* MEM_DEL_STATS */

	mhp = (struct mem_handle *)amhp;

#ifdef MEM_DEL_STATS
	start_total = ddi_get_lbolt();
#endif /* MEM_DEL_STATS */

	CALLB_CPR_INIT(&cprinfo, &mhp->mh_mutex,
	    callb_generic_cpr, "memdel");

	mutex_enter(&mhp->mh_mutex);
	ASSERT(mhp->mh_state == MHND_STARTING);

	mhp->mh_state = MHND_RUNNING;
	mhp->mh_thread_id = curthread;

	mhp->mh_hold_todo = mhp->mh_vm_pages;
	mutex_exit(&mhp->mh_mutex);

	/* Allocate the remap pages now, if necessary. */
	memseg_remap_init();

	/*
	 * Subtract from availrmem now if possible as availrmem
	 * may not be available by the end of the delete.
	 */
	if (!get_availrmem(mhp->mh_vm_pages)) {
		comp_code = KPHYSM_ENOTVIABLE;
		mutex_enter(&mhp->mh_mutex);
		goto early_exit;
	}

	ret = kphysm_setup_pre_del(mhp->mh_vm_pages);

	mutex_enter(&mhp->mh_mutex);

	if (ret != 0) {
		mhp->mh_cancel = KPHYSM_EREFUSED;
		goto refused;
	}

	transit_list_collect(mhp, 1);

	for (mdsp = mhp->mh_transit.trl_spans; mdsp != NULL;
	    mdsp = mdsp->mds_next) {
		ASSERT(mdsp->mds_bitmap == NULL);
		mdsp->mds_bitmap = kmem_zalloc(MDS_BITMAPBYTES(mdsp), KM_SLEEP);
		mdsp->mds_bitmap_retired = kmem_zalloc(MDS_BITMAPBYTES(mdsp),
		    KM_SLEEP);
	}

	first_scan = 1;
	freemem_left = 0;
	/*
	 * Start dr_aio_cleanup_thread, which periodically iterates
	 * through the process list and invokes aio cleanup.  This
	 * is needed in order to avoid a deadly embrace between the
	 * delete_memory_thread (waiting on writer lock for page, with the
	 * exclusive-wanted bit set), kaio read request threads (waiting for a
	 * reader lock on the same page that is wanted by the
	 * delete_memory_thread), and threads waiting for kaio completion
	 * (blocked on spt_amp->lock).
	 */
	mhp->mh_dr_aio_cleanup_cancel = 0;
	mhp->mh_aio_cleanup_done = 0;
	(void) thread_create(NULL, 0, dr_aio_cleanup_thread,
	    (caddr_t)mhp, 0, &p0, TS_RUN, maxclsyspri - 1);
	while ((mhp->mh_hold_todo != 0) && (mhp->mh_cancel == 0)) {
		pgcnt_t collected;

		MDSTAT_INCR(mhp, nloop);
		collected = 0;
		for (mdsp = mhp->mh_transit.trl_spans; (mdsp != NULL) &&
		    (mhp->mh_cancel == 0); mdsp = mdsp->mds_next) {
			pfn_t pfn, p_end;

			p_end = mdsp->mds_base + mdsp->mds_npgs;
			for (pfn = mdsp->mds_base; (pfn < p_end) &&
			    (mhp->mh_cancel == 0); pfn++) {
				page_t *pp, *tpp, *tpp_targ;
				pgcnt_t bit;
				struct vnode *vp;
				u_offset_t offset;
				int mod, result;
				spgcnt_t pgcnt;

				bit = pfn - mdsp->mds_base;
				if ((mdsp->mds_bitmap[bit / NBPBMW] &
				    (1 << (bit % NBPBMW))) != 0) {
					MDSTAT_INCR(mhp, already_done);
					continue;
				}
				if (freemem_left == 0) {
					freemem_left += delthr_get_freemem(mhp);
					if (freemem_left == 0)
						break;
				}

				/*
				 * Release mh_mutex - some of this
				 * stuff takes some time (eg PUTPAGE).
				 */

				mutex_exit(&mhp->mh_mutex);
				MDSTAT_INCR(mhp, ncheck);

				pp = page_numtopp_nolock(pfn);
				if (pp == NULL) {
					/*
					 * Not covered by a page_t - will
					 * be dealt with elsewhere.
					 */
					MDSTAT_INCR(mhp, nopaget);
					mutex_enter(&mhp->mh_mutex);
					mdsp->mds_bitmap[bit / NBPBMW] |=
					    (1 << (bit % NBPBMW));
					continue;
				}

				if (!page_try_reclaim_lock(pp, SE_EXCL,
				    SE_EXCL_WANTED | SE_RETIRED)) {
					/*
					 * Page in use elsewhere.  Skip it.
					 */
					MDSTAT_INCR(mhp, lockfail);
					mutex_enter(&mhp->mh_mutex);
					continue;
				}
				/*
				 * See if the cage expanded into the delete.
				 * This can happen as we have to allow the
				 * cage to expand.
				 */
				if (PP_ISNORELOC(pp)) {
					page_unlock(pp);
					mutex_enter(&mhp->mh_mutex);
					mhp->mh_cancel = KPHYSM_ENONRELOC;
					break;
				}
				if (PP_RETIRED(pp)) {
					/*
					 * Page has been retired and is
					 * not part of the cage so we
					 * can now do the accounting for
					 * it.
					 */
					MDSTAT_INCR(mhp, retired);
					mutex_enter(&mhp->mh_mutex);
					mdsp->mds_bitmap[bit / NBPBMW]
					    |= (1 << (bit % NBPBMW));
					mdsp->mds_bitmap_retired[bit /
					    NBPBMW] |=
					    (1 << (bit % NBPBMW));
					mhp->mh_hold_todo--;
					continue;
				}
				ASSERT(freemem_left != 0);
				if (PP_ISFREE(pp)) {
					/*
					 * Like page_reclaim() only 'freemem'
					 * processing is already done.
					 */
					MDSTAT_INCR(mhp, nfree);
				free_page_collect:
					if (PP_ISAGED(pp)) {
						page_list_sub(pp,
						    PG_FREE_LIST);
					} else {
						page_list_sub(pp,
						    PG_CACHE_LIST);
					}
					PP_CLRFREE(pp);
					PP_CLRAGED(pp);
					collected++;
					mutex_enter(&mhp->mh_mutex);
					page_delete_collect(pp, mhp);
					mdsp->mds_bitmap[bit / NBPBMW] |=
					    (1 << (bit % NBPBMW));
					freemem_left--;
					continue;
				}
				ASSERT(pp->p_vnode != NULL);
				if (first_scan) {
					MDSTAT_INCR(mhp, first_notfree);
					page_unlock(pp);
					mutex_enter(&mhp->mh_mutex);
					continue;
				}
				/*
				 * Keep stats on pages encountered that
				 * are marked for retirement.
				 */
				if (PP_TOXIC(pp)) {
					MDSTAT_INCR(mhp, toxic);
				} else if (PP_PR_REQ(pp)) {
					MDSTAT_INCR(mhp, failing);
				}
				/*
				 * In certain cases below, special exceptions
				 * are made for pages that are toxic.  This
				 * is because the current meaning of toxic
				 * is that an uncorrectable error has been
				 * previously associated with the page.
				 */
				if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
					if (!PP_TOXIC(pp)) {
						/*
						 * Must relocate locked in
						 * memory pages.
						 */
#ifdef MEM_DEL_STATS
						start_pgrp = ddi_get_lbolt();
#endif /* MEM_DEL_STATS */
						/*
						 * Lock all constituent pages
						 * of a large page to ensure
						 * that p_szc won't change.
						 */
						if (!group_page_trylock(pp,
						    SE_EXCL)) {
							MDSTAT_INCR(mhp,
							    gptllckfail);
							page_unlock(pp);
							mutex_enter(
							    &mhp->mh_mutex);
							continue;
						}
						MDSTAT_INCR(mhp, npplocked);
						pp_targ =
						    page_get_replacement_page(
						    pp, NULL, 0);
						if (pp_targ != NULL) {
#ifdef MEM_DEL_STATS
							ntick_pgrp =
							    (uint64_t)
							    ddi_get_lbolt() -
							    start_pgrp;
#endif /* MEM_DEL_STATS */
							MDSTAT_PGRP(mhp,
							    ntick_pgrp);
							MDSTAT_INCR(mhp,
							    nlockreloc);
							goto reloc;
						}
						group_page_unlock(pp);
						page_unlock(pp);
#ifdef MEM_DEL_STATS
						ntick_pgrp =
						    (uint64_t)ddi_get_lbolt() -
						    start_pgrp;
#endif /* MEM_DEL_STATS */
						MDSTAT_PGRP(mhp, ntick_pgrp);
						MDSTAT_INCR(mhp, nnorepl);
						mutex_enter(&mhp->mh_mutex);
						continue;
					} else {
						/*
						 * Cannot do anything about
						 * this page because it is
						 * toxic.
						 */
						MDSTAT_INCR(mhp, npplkdtoxic);
						page_unlock(pp);
						mutex_enter(&mhp->mh_mutex);
						continue;
					}
				}
				/*
				 * Unload the mappings and check if mod bit
				 * is set.
				 */
				ASSERT(!PP_ISKAS(pp));
				(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
				mod = hat_ismod(pp);

#ifdef MEM_DEL_STATS
				start_pgrp = ddi_get_lbolt();
#endif /* MEM_DEL_STATS */
				if (mod && !PP_TOXIC(pp)) {
					/*
					 * Lock all constituent pages
					 * of a large page to ensure
					 * that p_szc won't change.
					 */
					if (!group_page_trylock(pp, SE_EXCL)) {
						MDSTAT_INCR(mhp, gptlmodfail);
						page_unlock(pp);
						mutex_enter(&mhp->mh_mutex);
						continue;
					}
					pp_targ = page_get_replacement_page(pp,
					    NULL, 0);
					if (pp_targ != NULL) {
						MDSTAT_INCR(mhp, nmodreloc);
#ifdef MEM_DEL_STATS
						ntick_pgrp =
						    (uint64_t)ddi_get_lbolt() -
						    start_pgrp;
#endif /* MEM_DEL_STATS */
						MDSTAT_PGRP(mhp, ntick_pgrp);
						goto reloc;
					}
					group_page_unlock(pp);
				}

				if (!page_try_demote_pages(pp)) {
					MDSTAT_INCR(mhp, demotefail);
					page_unlock(pp);
#ifdef MEM_DEL_STATS
					ntick_pgrp = (uint64_t)ddi_get_lbolt() -
					    start_pgrp;
#endif /* MEM_DEL_STATS */
					MDSTAT_PGRP(mhp, ntick_pgrp);
					mutex_enter(&mhp->mh_mutex);
					continue;
				}

				/*
				 * Regular 'page-out'.
				 */
				if (!mod) {
					MDSTAT_INCR(mhp, ndestroy);
					page_destroy(pp, 1);
					/*
					 * page_destroy was called with
					 * dontfree. As long as p_lckcnt
					 * and p_cowcnt are both zero, the
					 * only additional action of
					 * page_destroy with !dontfree is to
					 * call page_free, so we can collect
					 * the page here.
					 */
					collected++;
#ifdef MEM_DEL_STATS
					ntick_pgrp = (uint64_t)ddi_get_lbolt() -
					    start_pgrp;
#endif /* MEM_DEL_STATS */
					MDSTAT_PGRP(mhp, ntick_pgrp);
					mutex_enter(&mhp->mh_mutex);
					page_delete_collect(pp, mhp);
					mdsp->mds_bitmap[bit / NBPBMW] |=
					    (1 << (bit % NBPBMW));
					continue;
				}
				/*
				 * The page is toxic and the mod bit is
				 * set, we cannot do anything here to deal
				 * with it.
				 */
				if (PP_TOXIC(pp)) {
					page_unlock(pp);
#ifdef MEM_DEL_STATS
					ntick_pgrp = (uint64_t)ddi_get_lbolt() -
					    start_pgrp;
#endif /* MEM_DEL_STATS */
					MDSTAT_PGRP(mhp, ntick_pgrp);
					MDSTAT_INCR(mhp, modtoxic);
					mutex_enter(&mhp->mh_mutex);
					continue;
				}
				MDSTAT_INCR(mhp, nputpage);
				vp = pp->p_vnode;
				offset = pp->p_offset;
				VN_HOLD(vp);
				page_unlock(pp);
				(void) VOP_PUTPAGE(vp, offset, PAGESIZE,
				    B_INVAL|B_FORCE, kcred, NULL);
				VN_RELE(vp);
#ifdef MEM_DEL_STATS
				ntick_pgrp = (uint64_t)ddi_get_lbolt() -
				    start_pgrp;
#endif /* MEM_DEL_STATS */
				MDSTAT_PGRP(mhp, ntick_pgrp);
				/*
				 * Try to get the page back immediately
				 * so that it can be collected.
				 */
				pp = page_numtopp_nolock(pfn);
				if (pp == NULL) {
					MDSTAT_INCR(mhp, nnoreclaim);
					/*
					 * This should not happen as this
					 * thread is deleting the page.
					 * If this code is generalized, this
					 * becomes a reality.
					 */
#ifdef DEBUG
					cmn_err(CE_WARN,
					    "delete_memory_thread(0x%p) "
					    "pfn 0x%lx has no page_t",
					    (void *)mhp, pfn);
#endif /* DEBUG */
					mutex_enter(&mhp->mh_mutex);
					continue;
				}
				if (page_try_reclaim_lock(pp, SE_EXCL,
				    SE_EXCL_WANTED | SE_RETIRED)) {
					if (PP_ISFREE(pp)) {
						goto free_page_collect;
					}
					page_unlock(pp);
				}
				MDSTAT_INCR(mhp, nnoreclaim);
				mutex_enter(&mhp->mh_mutex);
				continue;

			reloc:
				/*
				 * Got some freemem and a target
				 * page, so move the data to avoid
				 * I/O and lock problems.
				 */
				ASSERT(!page_iolock_assert(pp));
				MDSTAT_INCR(mhp, nreloc);
				/*
				 * page_relocate() will return pgcnt: the
				 * number of consecutive pages relocated.
				 * If it is successful, pp will be a
				 * linked list of the page structs that
				 * were relocated. If page_relocate() is
				 * unsuccessful, pp will be unmodified.
				 */
#ifdef MEM_DEL_STATS
				start_pgrp = ddi_get_lbolt();
#endif /* MEM_DEL_STATS */
				result = page_relocate(&pp, &pp_targ, 0, 0,
				    &pgcnt, NULL);
#ifdef MEM_DEL_STATS
				ntick_pgrp = (uint64_t)ddi_get_lbolt() -
				    start_pgrp;
#endif /* MEM_DEL_STATS */
				MDSTAT_PGRP(mhp, ntick_pgrp);
				if (result != 0) {
					MDSTAT_INCR(mhp, nrelocfail);
					/*
					 * We did not succeed. We need
					 * to give the pp_targ pages back.
					 * page_free(pp_targ, 1) without
					 * the freemem accounting.
					 */
					group_page_unlock(pp);
					page_free_replacement_page(pp_targ);
					page_unlock(pp);
					mutex_enter(&mhp->mh_mutex);
					continue;
				}

				/*
				 * We will then collect pgcnt pages.
				 */
				ASSERT(pgcnt > 0);
				mutex_enter(&mhp->mh_mutex);
				/*
				 * We need to make sure freemem_left is
				 * large enough.
				 */
				while ((freemem_left < pgcnt) &&
				    (!mhp->mh_cancel)) {
					freemem_left +=
					    delthr_get_freemem(mhp);
				}

				/*
				 * Do not proceed if mh_cancel is set.
				 */
				if (mhp->mh_cancel) {
					while (pp_targ != NULL) {
						/*
						 * Unlink and unlock each page.
						 */
						tpp_targ = pp_targ;
						page_sub(&pp_targ, tpp_targ);
						page_unlock(tpp_targ);
					}
					/*
					 * We need to give the pp pages back.
					 * page_free(pp, 1) without the
					 * freemem accounting.
					 */
					page_free_replacement_page(pp);
					break;
				}

				/* Now remove pgcnt from freemem_left */
				freemem_left -= pgcnt;
				ASSERT(freemem_left >= 0);
				szc = pp->p_szc;
				while (pp != NULL) {
					/*
					 * pp and pp_targ were passed back as
					 * a linked list of pages.
					 * Unlink and unlock each page.
					 */
					tpp_targ = pp_targ;
					page_sub(&pp_targ, tpp_targ);
					page_unlock(tpp_targ);
					/*
					 * The original page is now free
					 * so remove it from the linked
					 * list and collect it.
					 */
					tpp = pp;
					page_sub(&pp, tpp);
					pfn = page_pptonum(tpp);
					collected++;
					ASSERT(PAGE_EXCL(tpp));
					ASSERT(tpp->p_vnode == NULL);
					ASSERT(!hat_page_is_mapped(tpp));
					ASSERT(tpp->p_szc == szc);
					tpp->p_szc = 0;
					page_delete_collect(tpp, mhp);
					bit = pfn - mdsp->mds_base;
					mdsp->mds_bitmap[bit / NBPBMW] |=
					    (1 << (bit % NBPBMW));
				}
				ASSERT(pp_targ == NULL);
			}
		}
		first_scan = 0;
		if ((mhp->mh_cancel == 0) && (mhp->mh_hold_todo != 0) &&
		    (collected == 0)) {
			/*
			 * This code is needed as we cannot wait
			 * for a page to be locked OR the delete to
			 * be cancelled.  Also, we must delay so
			 * that other threads get a chance to run
			 * on our cpu, otherwise page locks may be
			 * held indefinitely by those threads.
			 */
			MDSTAT_INCR(mhp, ndelay);
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			(void) cv_reltimedwait(&mhp->mh_cv, &mhp->mh_mutex,
			    DEL_BUSY_WAIT_TICKS, TR_CLOCK_TICK);
			CALLB_CPR_SAFE_END(&cprinfo, &mhp->mh_mutex);
		}
	}
	/* stop the dr aio cleanup thread */
	mhp->mh_dr_aio_cleanup_cancel = 1;
	transit_list_collect(mhp, 0);
	if (freemem_left != 0) {
		/* Return any surplus. */
		page_create_putback(freemem_left);
		freemem_left = 0;
	}
#ifdef MEM_DEL_STATS
	ntick_total = (uint64_t)ddi_get_lbolt() - start_total;
#endif /* MEM_DEL_STATS */
	MDSTAT_TOTAL(mhp, ntick_total);
	MDSTAT_PRINT(mhp);

	/*
	 * If the memory delete was cancelled, exclusive-wanted bits must
	 * be cleared. If there are retired pages being deleted, they need
	 * to be unretired.
	 */
	for (mdsp = mhp->mh_transit.trl_spans; mdsp != NULL;
	    mdsp = mdsp->mds_next) {
		pfn_t pfn, p_end;

		p_end = mdsp->mds_base + mdsp->mds_npgs;
		for (pfn = mdsp->mds_base; pfn < p_end; pfn++) {
			page_t *pp;
			pgcnt_t bit;

			bit = pfn - mdsp->mds_base;
			if (mhp->mh_cancel) {
				pp = page_numtopp_nolock(pfn);
				if (pp != NULL) {
					if ((mdsp->mds_bitmap[bit / NBPBMW] &
					    (1 << (bit % NBPBMW))) == 0) {
						page_lock_clr_exclwanted(pp);
					}
				}
			} else {
				pp = NULL;
			}
			if ((mdsp->mds_bitmap_retired[bit / NBPBMW] &
			    (1 << (bit % NBPBMW))) != 0) {
				/* do we already have pp? */
				if (pp == NULL) {
					pp = page_numtopp_nolock(pfn);
				}
				ASSERT(pp != NULL);
				ASSERT(PP_RETIRED(pp));
				if (mhp->mh_cancel != 0) {
					page_unlock(pp);
					/*
					 * To satisfy ASSERT below in
					 * cancel code.
					 */
					mhp->mh_hold_todo++;
				} else {
					(void) page_unretire_pp(pp,
					    PR_UNR_CLEAN);
				}
			}
		}
	}
	/*
	 * Free retired page bitmap and collected page bitmap
	 */
	for (mdsp = mhp->mh_transit.trl_spans; mdsp != NULL;
	    mdsp = mdsp->mds_next) {
		ASSERT(mdsp->mds_bitmap_retired != NULL);
		kmem_free(mdsp->mds_bitmap_retired, MDS_BITMAPBYTES(mdsp));
		mdsp->mds_bitmap_retired = NULL;	/* Paranoia. */
		ASSERT(mdsp->mds_bitmap != NULL);
		kmem_free(mdsp->mds_bitmap, MDS_BITMAPBYTES(mdsp));
		mdsp->mds_bitmap = NULL;	/* Paranoia. */
	}

	/* wait for our dr aio cancel thread to exit */
	while (!(mhp->mh_aio_cleanup_done)) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		delay(drv_usectohz(DR_AIO_CLEANUP_DELAY));
		CALLB_CPR_SAFE_END(&cprinfo, &mhp->mh_mutex);
	}
refused:
	if (mhp->mh_cancel != 0) {
		page_t *pp;

		comp_code = mhp->mh_cancel;
		/*
		 * Go through list of deleted pages (mh_deleted) freeing
		 * them.
		 */
		while ((pp = mhp->mh_deleted) != NULL) {
			mhp->mh_deleted = pp->p_next;
			mhp->mh_hold_todo++;
			mutex_exit(&mhp->mh_mutex);
			/* Restore p_next. */
			pp->p_next = pp->p_prev;
			if (PP_ISFREE(pp)) {
				cmn_err(CE_PANIC,
				    "page %p is free",
				    (void *)pp);
			}
			page_free(pp, 1);
			mutex_enter(&mhp->mh_mutex);
		}
		ASSERT(mhp->mh_hold_todo == mhp->mh_vm_pages);

		mutex_exit(&mhp->mh_mutex);
		put_availrmem(mhp->mh_vm_pages);
		mutex_enter(&mhp->mh_mutex);

		goto t_exit;
	}

	/*
	 * All the pages are no longer in use and are exclusively locked.
	 */

	mhp->mh_deleted = NULL;

	kphysm_del_cleanup(mhp);

	/*
	 * mem_node_del_range needs to be after kphysm_del_cleanup so
	 * that the mem_node_config[] will remain intact for the cleanup.
	 */
	for (mdsp = mhp->mh_transit.trl_spans; mdsp != NULL;
	    mdsp = mdsp->mds_next) {
		mem_node_del_range(mdsp->mds_base,
		    mdsp->mds_base + mdsp->mds_npgs - 1);
	}
	/* cleanup the page counters */
	page_ctrs_cleanup();

	comp_code = KPHYSM_OK;

t_exit:
	mutex_exit(&mhp->mh_mutex);
	kphysm_setup_post_del(mhp->mh_vm_pages,
	    (comp_code == KPHYSM_OK) ? 0 : 1);
	mutex_enter(&mhp->mh_mutex);

early_exit:
	/* mhp->mh_mutex exited by CALLB_CPR_EXIT() */
	mhp->mh_state = MHND_DONE;
	del_complete_funcp = mhp->mh_delete_complete;
	del_complete_arg = mhp->mh_delete_complete_arg;
	CALLB_CPR_EXIT(&cprinfo);
	(*del_complete_funcp)(del_complete_arg, comp_code);
	thread_exit();
	/*NOTREACHED*/
}

/*
 * Start the delete of the memory from the system.
 */
int
kphysm_del_start(
	memhandle_t handle,
	void (*complete)(void *, int),
	void *complete_arg)
{
	struct mem_handle *mhp;

	mhp = kphysm_lookup_mem_handle(handle);
	if (mhp == NULL) {
		return (KPHYSM_EHANDLE);
	}
	switch (mhp->mh_state) {
	case MHND_FREE:
		ASSERT(mhp->mh_state != MHND_FREE);
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_EHANDLE);
	case MHND_INIT:
		break;
	case MHND_STARTING:
	case MHND_RUNNING:
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ESEQUENCE);
	case MHND_DONE:
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ESEQUENCE);
	case MHND_RELEASE:
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ESEQUENCE);
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "kphysm_del_start(0x%p) state corrupt %d",
		    (void *)mhp, mhp->mh_state);
#endif /* DEBUG */
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_EHANDLE);
	}

	if (mhp->mh_transit.trl_spans == NULL) {
		mutex_exit(&mhp->mh_mutex);
		return (KPHYSM_ENOWORK);
	}

	ASSERT(complete != NULL);
	mhp->mh_delete_complete = complete;
	mhp->mh_delete_complete_arg = complete_arg;
	mhp->mh_state = MHND_STARTING;
	/*
	 * Release the mutex in case thread_create sleeps.
	 */
	mutex_exit(&mhp->mh_mutex);

	/*
	 * The "obvious" process for this thread is pageout (proc_pageout)
	 * but this gives the thread too much power over freemem
	 * which results in freemem starvation.
	 */
	(void) thread_create(NULL, 0, delete_memory_thread, mhp, 0, &p0,
	    TS_RUN, maxclsyspri - 1);

	return (KPHYSM_OK);
}

static kmutex_t pp_dummy_lock;		/* Protects init. of pp_dummy. */
static caddr_t pp_dummy;
static pgcnt_t pp_dummy_npages;
static pfn_t *pp_dummy_pfn;	/* Array of dummy pfns. */

static void
memseg_remap_init_pages(page_t *pages, page_t *epages)
{
	page_t *pp;

	for (pp = pages; pp < epages; pp++) {
		pp->p_pagenum = PFN_INVALID;	/* XXXX */
		pp->p_offset = (u_offset_t)-1;
		page_iolock_init(pp);
		while (!page_lock(pp, SE_EXCL, (kmutex_t *)NULL, P_RECLAIM))
			continue;
		page_lock_delete(pp);
	}
}

void
memseg_remap_init()
{
	mutex_enter(&pp_dummy_lock);
	if (pp_dummy == NULL) {
		uint_t dpages;
		int i;

		/*
		 * dpages starts off as the size of the structure and
		 * ends up as the minimum number of pages that will
		 * hold a whole number of page_t structures.
		 */
		dpages = sizeof (page_t);
		ASSERT(dpages != 0);
		ASSERT(dpages <= MMU_PAGESIZE);

		while ((dpages & 1) == 0)
			dpages >>= 1;

		pp_dummy_npages = dpages;
		/*
		 * Allocate pp_dummy pages directly from static_arena,
		 * since these are whole page allocations and are
		 * referenced by physical address.  This also has the
		 * nice fringe benefit of hiding the memory from
		 * ::findleaks since it doesn't deal well with allocated
		 * kernel heap memory that doesn't have any mappings.
		 */
		pp_dummy = vmem_xalloc(static_arena, ptob(pp_dummy_npages),
		    PAGESIZE, 0, 0, NULL, NULL, VM_SLEEP);
		bzero(pp_dummy, ptob(pp_dummy_npages));
		ASSERT(((uintptr_t)pp_dummy & MMU_PAGEOFFSET) == 0);
		pp_dummy_pfn = kmem_alloc(sizeof (*pp_dummy_pfn) *
		    pp_dummy_npages, KM_SLEEP);
		for (i = 0; i < pp_dummy_npages; i++) {
			pp_dummy_pfn[i] = hat_getpfnum(kas.a_hat,
			    &pp_dummy[MMU_PAGESIZE * i]);
			ASSERT(pp_dummy_pfn[i] != PFN_INVALID);
		}
		/*
		 * Initialize the page_t's to a known 'deleted' state
		 * that matches the state of deleted pages.
		 */
		memseg_remap_init_pages((page_t *)pp_dummy,
		    (page_t *)(pp_dummy + ptob(pp_dummy_npages)));
		/* Remove kmem mappings for the pages for safety. */
		hat_unload(kas.a_hat, pp_dummy, ptob(pp_dummy_npages),
		    HAT_UNLOAD_UNLOCK);
		/* Leave pp_dummy pointer set as flag that init is done. */
	}
	mutex_exit(&pp_dummy_lock);
}

/*
 * Remap a page-aglined range of page_t's to dummy pages.
 */
void
remap_to_dummy(caddr_t va, pgcnt_t metapgs)
{
	int phase;

	ASSERT(IS_P2ALIGNED((uint64_t)(uintptr_t)va, PAGESIZE));

	/*
	 * We may start remapping at a non-zero page offset
	 * within the dummy pages since the low/high ends
	 * of the outgoing pp's could be shared by other
	 * memsegs (see memseg_remap_meta).
	 */
	phase = btop((uint64_t)(uintptr_t)va) % pp_dummy_npages;
	/*CONSTCOND*/
	ASSERT(PAGESIZE % sizeof (page_t) || phase == 0);

	while (metapgs != 0) {
		pgcnt_t n;
		int i, j;

		n = pp_dummy_npages;
		if (n > metapgs)
			n = metapgs;
		for (i = 0; i < n; i++) {
			j = (i + phase) % pp_dummy_npages;
			hat_devload(kas.a_hat, va, ptob(1), pp_dummy_pfn[j],
			    PROT_READ,
			    HAT_LOAD | HAT_LOAD_NOCONSIST |
			    HAT_LOAD_REMAP);
			va += ptob(1);
		}
		metapgs -= n;
	}
}

static void
memseg_remap_to_dummy(struct memseg *seg)
{
	caddr_t pp;
	pgcnt_t metapgs;

	ASSERT(memseg_is_dynamic(seg));
	ASSERT(pp_dummy != NULL);


	if (!memseg_includes_meta(seg)) {
		memseg_remap_meta(seg);
		return;
	}

	pp = (caddr_t)seg->pages;
	metapgs = seg->pages_base - memseg_get_start(seg);
	ASSERT(metapgs != 0);

	seg->pages_end = seg->pages_base;

	remap_to_dummy(pp, metapgs);
}

/*
 * Transition all the deleted pages to the deleted state so that
 * page_lock will not wait. The page_lock_delete call will
 * also wake up any waiters.
 */
static void
memseg_lock_delete_all(struct memseg *seg)
{
	page_t *pp;

	for (pp = seg->pages; pp < seg->epages; pp++) {
		pp->p_pagenum = PFN_INVALID;	/* XXXX */
		page_lock_delete(pp);
	}
}

static void
kphysm_del_cleanup(struct mem_handle *mhp)
{
	struct memdelspan	*mdsp;
	struct memseg		*seg;
	struct memseg   	**segpp;
	struct memseg		*seglist;
	pfn_t			p_end;
	uint64_t		avmem;
	pgcnt_t			avpgs;
	pgcnt_t			npgs;

	avpgs = mhp->mh_vm_pages;

	memsegs_lock(1);

	/*
	 * remove from main segment list.
	 */
	npgs = 0;
	seglist = NULL;
	for (mdsp = mhp->mh_transit.trl_spans; mdsp != NULL;
	    mdsp = mdsp->mds_next) {
		p_end = mdsp->mds_base + mdsp->mds_npgs;
		for (segpp = &memsegs; (seg = *segpp) != NULL; ) {
			if (seg->pages_base >= p_end ||
			    seg->pages_end <= mdsp->mds_base) {
				/* Span and memseg don't overlap. */
				segpp = &((*segpp)->next);
				continue;
			}
			ASSERT(seg->pages_base >= mdsp->mds_base);
			ASSERT(seg->pages_end <= p_end);

			PLCNT_MODIFY_MAX(seg->pages_base,
			    seg->pages_base - seg->pages_end);

			/* Hide the memseg from future scans. */
			hat_kpm_delmem_mseg_update(seg, segpp);
			*segpp = seg->next;
			membar_producer();	/* TODO: Needed? */
			npgs += MSEG_NPAGES(seg);

			/*
			 * Leave the deleted segment's next pointer intact
			 * in case a memsegs scanning loop is walking this
			 * segment concurrently.
			 */
			seg->lnext = seglist;
			seglist = seg;
		}
	}

	build_pfn_hash();

	ASSERT(npgs < total_pages);
	total_pages -= npgs;

	/*
	 * Recalculate the paging parameters now total_pages has changed.
	 * This will also cause the clock hands to be reset before next use.
	 */
	setupclock(1);

	memsegs_unlock(1);

	mutex_exit(&mhp->mh_mutex);

	while ((seg = seglist) != NULL) {
		pfn_t mseg_start;
		pfn_t mseg_base, mseg_end;
		pgcnt_t mseg_npgs;
		int mlret;

		seglist = seg->lnext;

		/*
		 * Put the page_t's into the deleted state to stop
		 * cv_wait()s on the pages. When we remap, the dummy
		 * page_t's will be in the same state.
		 */
		memseg_lock_delete_all(seg);
		/*
		 * Collect up information based on pages_base and pages_end
		 * early so that we can flag early that the memseg has been
		 * deleted by setting pages_end == pages_base.
		 */
		mseg_base = seg->pages_base;
		mseg_end = seg->pages_end;
		mseg_npgs = MSEG_NPAGES(seg);
		mseg_start = memseg_get_start(seg);

		if (memseg_is_dynamic(seg)) {
			/* Remap the meta data to our special dummy area. */
			memseg_remap_to_dummy(seg);

			mutex_enter(&memseg_lists_lock);
			seg->lnext = memseg_va_avail;
			memseg_va_avail = seg;
			mutex_exit(&memseg_lists_lock);
		} else {
			/*
			 * For memory whose page_ts were allocated
			 * at boot, we need to find a new use for
			 * the page_t memory.
			 * For the moment, just leak it.
			 * (It is held in the memseg_delete_junk list.)
			 */
			seg->pages_end = seg->pages_base;

			mutex_enter(&memseg_lists_lock);
			seg->lnext = memseg_delete_junk;
			memseg_delete_junk = seg;
			mutex_exit(&memseg_lists_lock);
		}

		/* Must not use seg now as it could be re-used. */

		memlist_write_lock();

		mlret = memlist_delete_span(
		    (uint64_t)(mseg_base) << PAGESHIFT,
		    (uint64_t)(mseg_npgs) << PAGESHIFT,
		    &phys_avail);
		ASSERT(mlret == MEML_SPANOP_OK);

		mlret = memlist_delete_span(
		    (uint64_t)(mseg_start) << PAGESHIFT,
		    (uint64_t)(mseg_end - mseg_start) <<
		    PAGESHIFT,
		    &phys_install);
		ASSERT(mlret == MEML_SPANOP_OK);
		phys_install_has_changed();

		memlist_write_unlock();
	}

	memlist_read_lock();
	installed_top_size(phys_install, &physmax, &physinstalled);
	memlist_read_unlock();

	mutex_enter(&freemem_lock);
	maxmem -= avpgs;
	physmem -= avpgs;
	/* availrmem is adjusted during the delete. */
	availrmem_initial -= avpgs;

	mutex_exit(&freemem_lock);

	dump_resize();

	cmn_err(CE_CONT, "?kphysm_delete: mem = %ldK "
	    "(0x%" PRIx64 ")\n",
	    physinstalled << (PAGESHIFT - 10),
	    (uint64_t)physinstalled << PAGESHIFT);

	avmem = (uint64_t)freemem << PAGESHIFT;
	cmn_err(CE_CONT, "?kphysm_delete: "
	    "avail mem = %" PRId64 "\n", avmem);

	/*
	 * Update lgroup generation number on single lgroup systems
	 */
	if (nlgrps == 1)
		lgrp_config(LGRP_CONFIG_GEN_UPDATE, 0, 0);

	/* Successfully deleted system memory */
	mutex_enter(&mhp->mh_mutex);
}

static uint_t mdel_nullvp_waiter;

static void
page_delete_collect(
	page_t *pp,
	struct mem_handle *mhp)
{
	if (pp->p_vnode) {
		page_hashout(pp, (kmutex_t *)NULL);
		/* do not do PP_SETAGED(pp); */
	} else {
		kmutex_t *sep;

		sep = page_se_mutex(pp);
		mutex_enter(sep);
		if (CV_HAS_WAITERS(&pp->p_cv)) {
			mdel_nullvp_waiter++;
			cv_broadcast(&pp->p_cv);
		}
		mutex_exit(sep);
	}
	ASSERT(pp->p_next == pp->p_prev);
	ASSERT(pp->p_next == NULL || pp->p_next == pp);
	pp->p_next = mhp->mh_deleted;
	mhp->mh_deleted = pp;
	ASSERT(mhp->mh_hold_todo != 0);
	mhp->mh_hold_todo--;
}

static void
transit_list_collect(struct mem_handle *mhp, int v)
{
	struct transit_list_head *trh;

	trh = &transit_list_head;
	mutex_enter(&trh->trh_lock);
	mhp->mh_transit.trl_collect = v;
	mutex_exit(&trh->trh_lock);
}

static void
transit_list_insert(struct transit_list *tlp)
{
	struct transit_list_head *trh;

	trh = &transit_list_head;
	ASSERT(MUTEX_HELD(&trh->trh_lock));
	tlp->trl_next = trh->trh_head;
	trh->trh_head = tlp;
}

static void
transit_list_remove(struct transit_list *tlp)
{
	struct transit_list_head *trh;
	struct transit_list **tlpp;

	trh = &transit_list_head;
	tlpp = &trh->trh_head;
	ASSERT(MUTEX_HELD(&trh->trh_lock));
	while (*tlpp != NULL && *tlpp != tlp)
		tlpp = &(*tlpp)->trl_next;
	ASSERT(*tlpp != NULL);
	if (*tlpp == tlp)
		*tlpp = tlp->trl_next;
	tlp->trl_next = NULL;
}

static struct transit_list *
pfnum_to_transit_list(struct transit_list_head *trh, pfn_t pfnum)
{
	struct transit_list *tlp;

	for (tlp = trh->trh_head; tlp != NULL; tlp = tlp->trl_next) {
		struct memdelspan *mdsp;

		for (mdsp = tlp->trl_spans; mdsp != NULL;
		    mdsp = mdsp->mds_next) {
			if (pfnum >= mdsp->mds_base &&
			    pfnum < (mdsp->mds_base + mdsp->mds_npgs)) {
				return (tlp);
			}
		}
	}
	return (NULL);
}

int
pfn_is_being_deleted(pfn_t pfnum)
{
	struct transit_list_head *trh;
	struct transit_list *tlp;
	int ret;

	trh = &transit_list_head;
	if (trh->trh_head == NULL)
		return (0);

	mutex_enter(&trh->trh_lock);
	tlp = pfnum_to_transit_list(trh, pfnum);
	ret = (tlp != NULL && tlp->trl_collect);
	mutex_exit(&trh->trh_lock);

	return (ret);
}

#ifdef MEM_DEL_STATS
extern int hz;
static void
mem_del_stat_print_func(struct mem_handle *mhp)
{
	uint64_t tmp;

	if (mem_del_stat_print) {
		printf("memory delete loop %x/%x, statistics%s\n",
		    (uint_t)mhp->mh_transit.trl_spans->mds_base,
		    (uint_t)mhp->mh_transit.trl_spans->mds_npgs,
		    (mhp->mh_cancel ? " (cancelled)" : ""));
		printf("\t%8u nloop\n", mhp->mh_delstat.nloop);
		printf("\t%8u need_free\n", mhp->mh_delstat.need_free);
		printf("\t%8u free_loop\n", mhp->mh_delstat.free_loop);
		printf("\t%8u free_low\n", mhp->mh_delstat.free_low);
		printf("\t%8u free_failed\n", mhp->mh_delstat.free_failed);
		printf("\t%8u ncheck\n", mhp->mh_delstat.ncheck);
		printf("\t%8u nopaget\n", mhp->mh_delstat.nopaget);
		printf("\t%8u lockfail\n", mhp->mh_delstat.lockfail);
		printf("\t%8u nfree\n", mhp->mh_delstat.nfree);
		printf("\t%8u nreloc\n", mhp->mh_delstat.nreloc);
		printf("\t%8u nrelocfail\n", mhp->mh_delstat.nrelocfail);
		printf("\t%8u already_done\n", mhp->mh_delstat.already_done);
		printf("\t%8u first_notfree\n", mhp->mh_delstat.first_notfree);
		printf("\t%8u npplocked\n", mhp->mh_delstat.npplocked);
		printf("\t%8u nlockreloc\n", mhp->mh_delstat.nlockreloc);
		printf("\t%8u nnorepl\n", mhp->mh_delstat.nnorepl);
		printf("\t%8u nmodreloc\n", mhp->mh_delstat.nmodreloc);
		printf("\t%8u ndestroy\n", mhp->mh_delstat.ndestroy);
		printf("\t%8u nputpage\n", mhp->mh_delstat.nputpage);
		printf("\t%8u nnoreclaim\n", mhp->mh_delstat.nnoreclaim);
		printf("\t%8u ndelay\n", mhp->mh_delstat.ndelay);
		printf("\t%8u demotefail\n", mhp->mh_delstat.demotefail);
		printf("\t%8u retired\n", mhp->mh_delstat.retired);
		printf("\t%8u toxic\n", mhp->mh_delstat.toxic);
		printf("\t%8u failing\n", mhp->mh_delstat.failing);
		printf("\t%8u modtoxic\n", mhp->mh_delstat.modtoxic);
		printf("\t%8u npplkdtoxic\n", mhp->mh_delstat.npplkdtoxic);
		printf("\t%8u gptlmodfail\n", mhp->mh_delstat.gptlmodfail);
		printf("\t%8u gptllckfail\n", mhp->mh_delstat.gptllckfail);
		tmp = mhp->mh_delstat.nticks_total / hz;  /* seconds */
		printf(
		    "\t%"PRIu64" nticks_total - %"PRIu64" min %"PRIu64" sec\n",
		    mhp->mh_delstat.nticks_total, tmp / 60, tmp % 60);

		tmp = mhp->mh_delstat.nticks_pgrp / hz;  /* seconds */
		printf(
		    "\t%"PRIu64" nticks_pgrp - %"PRIu64" min %"PRIu64" sec\n",
		    mhp->mh_delstat.nticks_pgrp, tmp / 60, tmp % 60);
	}
}
#endif /* MEM_DEL_STATS */

struct mem_callback {
	kphysm_setup_vector_t	*vec;
	void			*arg;
};

#define	NMEMCALLBACKS		100

static struct mem_callback mem_callbacks[NMEMCALLBACKS];
static uint_t nmemcallbacks;
static krwlock_t mem_callback_rwlock;

int
kphysm_setup_func_register(kphysm_setup_vector_t *vec, void *arg)
{
	uint_t i, found;

	/*
	 * This test will become more complicated when the version must
	 * change.
	 */
	if (vec->version != KPHYSM_SETUP_VECTOR_VERSION)
		return (EINVAL);

	if (vec->post_add == NULL || vec->pre_del == NULL ||
	    vec->post_del == NULL)
		return (EINVAL);

	rw_enter(&mem_callback_rwlock, RW_WRITER);
	for (i = 0, found = 0; i < nmemcallbacks; i++) {
		if (mem_callbacks[i].vec == NULL && found == 0)
			found = i + 1;
		if (mem_callbacks[i].vec == vec &&
		    mem_callbacks[i].arg == arg) {
#ifdef DEBUG
			/* Catch this in DEBUG kernels. */
			cmn_err(CE_WARN, "kphysm_setup_func_register"
			    "(0x%p, 0x%p) duplicate registration from 0x%p",
			    (void *)vec, arg, (void *)caller());
#endif /* DEBUG */
			rw_exit(&mem_callback_rwlock);
			return (EEXIST);
		}
	}
	if (found != 0) {
		i = found - 1;
	} else {
		ASSERT(nmemcallbacks < NMEMCALLBACKS);
		if (nmemcallbacks == NMEMCALLBACKS) {
			rw_exit(&mem_callback_rwlock);
			return (ENOMEM);
		}
		i = nmemcallbacks++;
	}
	mem_callbacks[i].vec = vec;
	mem_callbacks[i].arg = arg;
	rw_exit(&mem_callback_rwlock);
	return (0);
}

void
kphysm_setup_func_unregister(kphysm_setup_vector_t *vec, void *arg)
{
	uint_t i;

	rw_enter(&mem_callback_rwlock, RW_WRITER);
	for (i = 0; i < nmemcallbacks; i++) {
		if (mem_callbacks[i].vec == vec &&
		    mem_callbacks[i].arg == arg) {
			mem_callbacks[i].vec = NULL;
			mem_callbacks[i].arg = NULL;
			if (i == (nmemcallbacks - 1))
				nmemcallbacks--;
			break;
		}
	}
	rw_exit(&mem_callback_rwlock);
}

static void
kphysm_setup_post_add(pgcnt_t delta_pages)
{
	uint_t i;

	rw_enter(&mem_callback_rwlock, RW_READER);
	for (i = 0; i < nmemcallbacks; i++) {
		if (mem_callbacks[i].vec != NULL) {
			(*mem_callbacks[i].vec->post_add)
			    (mem_callbacks[i].arg, delta_pages);
		}
	}
	rw_exit(&mem_callback_rwlock);
}

/*
 * Note the locking between pre_del and post_del: The reader lock is held
 * between the two calls to stop the set of functions from changing.
 */

static int
kphysm_setup_pre_del(pgcnt_t delta_pages)
{
	uint_t i;
	int ret;
	int aret;

	ret = 0;
	rw_enter(&mem_callback_rwlock, RW_READER);
	for (i = 0; i < nmemcallbacks; i++) {
		if (mem_callbacks[i].vec != NULL) {
			aret = (*mem_callbacks[i].vec->pre_del)
			    (mem_callbacks[i].arg, delta_pages);
			ret |= aret;
		}
	}

	return (ret);
}

static void
kphysm_setup_post_del(pgcnt_t delta_pages, int cancelled)
{
	uint_t i;

	for (i = 0; i < nmemcallbacks; i++) {
		if (mem_callbacks[i].vec != NULL) {
			(*mem_callbacks[i].vec->post_del)
			    (mem_callbacks[i].arg, delta_pages, cancelled);
		}
	}
	rw_exit(&mem_callback_rwlock);
}

static int
kphysm_split_memseg(
	pfn_t base,
	pgcnt_t npgs)
{
	struct memseg *seg;
	struct memseg **segpp;
	pgcnt_t size_low, size_high;
	struct memseg *seg_low, *seg_mid, *seg_high;

	/*
	 * Lock the memsegs list against other updates now
	 */
	memsegs_lock(1);

	/*
	 * Find boot time memseg that wholly covers this area.
	 */

	/* First find the memseg with page 'base' in it. */
	for (segpp = &memsegs; (seg = *segpp) != NULL;
	    segpp = &((*segpp)->next)) {
		if (base >= seg->pages_base && base < seg->pages_end)
			break;
	}
	if (seg == NULL) {
		memsegs_unlock(1);
		return (0);
	}
	if (memseg_includes_meta(seg)) {
		memsegs_unlock(1);
		return (0);
	}
	if ((base + npgs) > seg->pages_end) {
		memsegs_unlock(1);
		return (0);
	}

	/*
	 * Work out the size of the two segments that will
	 * surround the new segment, one for low address
	 * and one for high.
	 */
	ASSERT(base >= seg->pages_base);
	size_low = base - seg->pages_base;
	ASSERT(seg->pages_end >= (base + npgs));
	size_high = seg->pages_end - (base + npgs);

	/*
	 * Sanity check.
	 */
	if ((size_low + size_high) == 0) {
		memsegs_unlock(1);
		return (0);
	}

	/*
	 * Allocate the new structures. The old memseg will not be freed
	 * as there may be a reference to it.
	 */
	seg_low = NULL;
	seg_high = NULL;

	if (size_low != 0)
		seg_low = memseg_alloc();

	seg_mid = memseg_alloc();

	if (size_high != 0)
		seg_high = memseg_alloc();

	/*
	 * All allocation done now.
	 */
	if (size_low != 0) {
		seg_low->pages = seg->pages;
		seg_low->epages = seg_low->pages + size_low;
		seg_low->pages_base = seg->pages_base;
		seg_low->pages_end = seg_low->pages_base + size_low;
		seg_low->next = seg_mid;
		seg_low->msegflags = seg->msegflags;
	}
	if (size_high != 0) {
		seg_high->pages = seg->epages - size_high;
		seg_high->epages = seg_high->pages + size_high;
		seg_high->pages_base = seg->pages_end - size_high;
		seg_high->pages_end = seg_high->pages_base + size_high;
		seg_high->next = seg->next;
		seg_high->msegflags = seg->msegflags;
	}

	seg_mid->pages = seg->pages + size_low;
	seg_mid->pages_base = seg->pages_base + size_low;
	seg_mid->epages = seg->epages - size_high;
	seg_mid->pages_end = seg->pages_end - size_high;
	seg_mid->next = (seg_high != NULL) ? seg_high : seg->next;
	seg_mid->msegflags = seg->msegflags;

	/*
	 * Update hat_kpm specific info of all involved memsegs and
	 * allow hat_kpm specific global chain updates.
	 */
	hat_kpm_split_mseg_update(seg, segpp, seg_low, seg_mid, seg_high);

	/*
	 * At this point we have two equivalent memseg sub-chains,
	 * seg and seg_low/seg_mid/seg_high, which both chain on to
	 * the same place in the global chain. By re-writing the pointer
	 * in the previous element we switch atomically from using the old
	 * (seg) to the new.
	 */
	*segpp = (seg_low != NULL) ? seg_low : seg_mid;

	membar_enter();

	build_pfn_hash();
	memsegs_unlock(1);

	/*
	 * We leave the old segment, 'seg', intact as there may be
	 * references to it. Also, as the value of total_pages has not
	 * changed and the memsegs list is effectively the same when
	 * accessed via the old or the new pointer, we do not have to
	 * cause pageout_scanner() to re-evaluate its hand pointers.
	 *
	 * We currently do not re-use or reclaim the page_t memory.
	 * If we do, then this may have to change.
	 */

	mutex_enter(&memseg_lists_lock);
	seg->lnext = memseg_edit_junk;
	memseg_edit_junk = seg;
	mutex_exit(&memseg_lists_lock);

	return (1);
}

/*
 * The sfmmu hat layer (e.g.) accesses some parts of the memseg
 * structure using physical addresses. Therefore a kmem_cache is
 * used with KMC_NOHASH to avoid page crossings within a memseg
 * structure. KMC_NOHASH requires that no external (outside of
 * slab) information is allowed. This, in turn, implies that the
 * cache's slabsize must be exactly a single page, since per-slab
 * information (e.g. the freelist for the slab) is kept at the
 * end of the slab, where it is easy to locate. Should be changed
 * when a more obvious kmem_cache interface/flag will become
 * available.
 */
void
mem_config_init()
{
	memseg_cache = kmem_cache_create("memseg_cache", sizeof (struct memseg),
	    0, NULL, NULL, NULL, NULL, static_arena, KMC_NOHASH);
}

struct memseg *
memseg_alloc()
{
	struct memseg *seg;

	seg = kmem_cache_alloc(memseg_cache, KM_SLEEP);
	bzero(seg, sizeof (struct memseg));

	return (seg);
}

/*
 * Return whether the page_t memory for this memseg
 * is included in the memseg itself.
 */
static int
memseg_includes_meta(struct memseg *seg)
{
	return (seg->msegflags & MEMSEG_META_INCL);
}

pfn_t
memseg_get_start(struct memseg *seg)
{
	pfn_t		pt_start;

	if (memseg_includes_meta(seg)) {
		pt_start = hat_getpfnum(kas.a_hat, (caddr_t)seg->pages);

		/* Meta data is required to be at the beginning */
		ASSERT(pt_start < seg->pages_base);
	} else
		pt_start = seg->pages_base;

	return (pt_start);
}

/*
 * Invalidate memseg pointers in cpu private vm data caches.
 */
static void
memseg_cpu_vm_flush()
{
	cpu_t *cp;
	vm_cpu_data_t *vc;

	mutex_enter(&cpu_lock);
	pause_cpus(NULL, NULL);

	cp = cpu_list;
	do {
		vc = cp->cpu_vm_data;
		vc->vc_pnum_memseg = NULL;
		vc->vc_pnext_memseg = NULL;

	} while ((cp = cp->cpu_next) != cpu_list);

	start_cpus();
	mutex_exit(&cpu_lock);
}

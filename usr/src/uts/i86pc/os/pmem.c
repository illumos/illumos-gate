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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PMEM - Direct mapping physical memory pages to userland process
 *
 * Provide functions used for directly (w/o occupying kernel virtual address
 * space) allocating and exporting physical memory pages to userland.
 */

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/sunddi.h>
#include <sys/ddidevmap.h>
#include <sys/vnode.h>
#include <sys/sysmacros.h>
#include <vm/seg_dev.h>
#include <sys/pmem.h>
#include <vm/hat_i86.h>
#include <sys/task.h>
#include <sys/sdt.h>

/*
 * The routines in this file allocate memory which will be accessed through
 * the AGP GART hardware.  The GART is programmed with the PFNs for this
 * memory, and the only mechanism for removing these entries is by an
 * explicit process operation (ioctl/close of the driver, or process exit).
 * As such, the pages need to remain locked to ensure that they won't be
 * relocated or paged out.
 *
 * To prevent these locked pages from getting in the way of page
 * coalescing, we try to allocate large pages from the system, and carve
 * them up to satisfy pmem allocation requests.  This will keep the locked
 * pages within a constrained area of physical memory, limiting the number
 * of large pages that would be pinned by our locked pages.  This is, of
 * course, another take on the infamous kernel cage, and it has many of the
 * downsides of the original cage.  It also interferes with system-wide
 * resource management decisions, as it maintains its own pool of unused
 * pages which can't be easily reclaimed and used during low-memory
 * situations.
 *
 * The right solution is for pmem to register a callback that the VM system
 * could call, which would temporarily remove any GART entries for pages
 * that were being relocated.  This would let us leave the pages unlocked,
 * which would remove the need for using large pages, which would simplify
 * this code a great deal.  Unfortunately, the support for these callbacks
 * only exists on some SPARC platforms right now.
 *
 * Note that this is the *only* reason that large pages are used here.  The
 * GART can't perform large-page translations, and the code appropriately
 * falls back to using small pages if page_create_va_large() fails.
 */

#define	HOLD_DHP_LOCK(dhp)  if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) \
			{ mutex_enter(&dhp->dh_lock); }

#define	RELE_DHP_LOCK(dhp) if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) \
			{ mutex_exit(&dhp->dh_lock); }

#define	FROM_LPG(pp) (pp->p_szc != 0)
#define	PFIND(pp) (page_pptonum(pp) & (pmem_pgcnt - 1))

/*
 * Structs and static variables used for pmem only.
 */
typedef struct pmem_lpg {
	page_t	*pl_pp;		/* start pp */
	ulong_t	*pl_bitmap;	/* allocation status for each page */
	ushort_t pl_pfree;	/* this large page might be fully freed */
	struct pmem_lpg *pl_next;
	struct pmem_lpg *pl_prev;
} pmem_lpg_t;

static size_t	pmem_lpgsize;	/* the size of one large page */
static pgcnt_t	pmem_pgcnt;	/* the number of small pages in a large page */
static uint_t	pmem_lszc;	/* page size code of the large page */
/* The segment to be associated with all the allocated pages. */
static struct seg	pmem_seg;
/* Fully occupied large pages allocated for pmem. */
static pmem_lpg_t *pmem_occ_lpgs;
/* Memory pool to store residual small pages from large pages. */
static page_t	*pmem_mpool = NULL;
/* Number of small pages reside in pmem_mpool currently. */
static pgcnt_t	pmem_nmpages = 0;
/* To protect pmem_nmpages, pmem_mpool and pmem_occ_lpgs. */
kmutex_t	pmem_mutex;

static int lpg_isfree(pmem_lpg_t *);
static void pmem_lpg_sub(pmem_lpg_t **, pmem_lpg_t *);
static void pmem_lpg_concat(pmem_lpg_t **, pmem_lpg_t **);
static pmem_lpg_t *pmem_lpg_get(pmem_lpg_t *, page_t *, pmem_lpg_t **);
static pmem_lpg_t *pmem_lpg_alloc(uint_t);
static void pmem_lpg_free(pmem_lpg_t **, pmem_lpg_t *);
static void lpg_free(page_t *spp);
static pgcnt_t mpool_break(page_t **, pgcnt_t);
static void mpool_append(page_t **, pgcnt_t);
static void lpp_break(page_t **, pgcnt_t, pgcnt_t, pmem_lpg_t *);
static void lpp_free(page_t *, pgcnt_t, pmem_lpg_t **);
static int lpp_create(page_t **, pgcnt_t, pgcnt_t *, pmem_lpg_t **,
    vnode_t *, u_offset_t *, uint_t);
static void tlist_in(page_t *, pgcnt_t, vnode_t *, u_offset_t *);
static void tlist_out(page_t *, pgcnt_t);
static int pmem_cookie_alloc(struct devmap_pmem_cookie **, pgcnt_t, uint_t);
static int pmem_lock(pgcnt_t, proc_t *p);

/*
 * Called by driver devmap routine to pass physical memory mapping info to
 * seg_dev framework, used only for physical memory allocated from
 * devmap_pmem_alloc().
 */
/* ARGSUSED */
int
devmap_pmem_setup(devmap_cookie_t dhc, dev_info_t *dip,
    struct devmap_callback_ctl *callbackops, devmap_pmem_cookie_t cookie,
    offset_t off, size_t len, uint_t maxprot, uint_t flags,
    ddi_device_acc_attr_t *accattrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	struct devmap_pmem_cookie *pcp = (struct devmap_pmem_cookie *)cookie;
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);

	if (pcp == NULL || (off + len) > ptob(pcp->dp_npages))
		return (DDI_FAILURE);

	/*
	 * First to check if this function has been called for this dhp.
	 */
	if (dhp->dh_flags & DEVMAP_SETUP_DONE)
		return (DDI_FAILURE);

	if ((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) != dhp->dh_prot)
		return (DDI_FAILURE);

	/*
	 * Check if the cache attributes are supported. Need to pay
	 * attention that only uncachable or write-combining is
	 * permitted for pmem.
	 */
	if (i_ddi_check_cache_attr(flags) == B_FALSE ||
	    (cache_attr & (IOMEM_DATA_UNCACHED|IOMEM_DATA_UC_WR_COMBINE)) == 0)
		return (DDI_FAILURE);

	if (flags & DEVMAP_MAPPING_INVALID) {
		/*
		 * If DEVMAP_MAPPING_INVALID is specified, we have to grant
		 * remap permission.
		 */
		if (!(flags & DEVMAP_ALLOW_REMAP))
			return (DDI_FAILURE);
	} else {
		dhp->dh_pcookie = (devmap_pmem_cookie_t)pcp;
		/* dh_roff is the offset inside the dh_pcookie. */
		dhp->dh_roff = ptob(btop(off));
		/* Set the cache attributes correctly */
		i_ddi_cacheattr_to_hatacc(cache_attr, &dhp->dh_hat_attr);
	}

	dhp->dh_cookie = DEVMAP_PMEM_COOKIE;
	dhp->dh_flags |= (flags & DEVMAP_SETUP_FLAGS);
	dhp->dh_len = ptob(btopr(len));

	dhp->dh_maxprot = maxprot & dhp->dh_orig_maxprot;
	ASSERT((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) == dhp->dh_prot);

	if (callbackops != NULL) {
		bcopy(callbackops, &dhp->dh_callbackops,
		    sizeof (struct devmap_callback_ctl));
	}

	/*
	 * Initialize dh_lock if we want to do remap.
	 */
	if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) {
		mutex_init(&dhp->dh_lock, NULL, MUTEX_DEFAULT, NULL);
		dhp->dh_flags |= DEVMAP_LOCK_INITED;
	}

	dhp->dh_flags |= DEVMAP_SETUP_DONE;

	return (DDI_SUCCESS);
}

/*
 * Replace existing mapping using a new cookie, mainly gets called when doing
 * fork(). Should be called in associated devmap_dup(9E).
 */
/* ARGSUSED */
int
devmap_pmem_remap(devmap_cookie_t dhc, dev_info_t *dip,
    devmap_pmem_cookie_t cookie, offset_t off, size_t len, uint_t maxprot,
    uint_t flags, ddi_device_acc_attr_t *accattrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	struct devmap_pmem_cookie *pcp = (struct devmap_pmem_cookie *)cookie;
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);

	/*
	 * Reture failure if setup has not been done or no remap permission
	 * has been granted during the setup.
	 */
	if ((dhp->dh_flags & DEVMAP_SETUP_DONE) == 0 ||
	    (dhp->dh_flags & DEVMAP_ALLOW_REMAP) == 0)
		return (DDI_FAILURE);

	/* No flags supported for remap yet. */
	if (flags != 0)
		return (DDI_FAILURE);

	if ((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) != dhp->dh_prot)
		return (DDI_FAILURE);

	if (pcp == NULL || (off + len) > ptob(pcp->dp_npages))
		return (DDI_FAILURE);

	/*
	 * Check if the cache attributes are supported. Need to pay
	 * attention that only uncachable or write-combining is
	 * permitted for pmem.
	 */
	if (i_ddi_check_cache_attr(flags) == B_FALSE ||
	    (cache_attr & (IOMEM_DATA_UNCACHED|IOMEM_DATA_UC_WR_COMBINE)) == 0)
		return (DDI_FAILURE);

	HOLD_DHP_LOCK(dhp);
	/*
	 * Unload the old mapping of pages reloated with this dhp, so next
	 * fault will setup the new mappings. It is in segdev_faultpage that
	 * calls hat_devload to establish the mapping. Do this while holding
	 * the dhp lock so other faults dont reestablish the mappings.
	 */
	hat_unload(dhp->dh_seg->s_as->a_hat, dhp->dh_uvaddr,
	    dhp->dh_len, HAT_UNLOAD|HAT_UNLOAD_OTHER);

	/* Set the cache attributes correctly */
	i_ddi_cacheattr_to_hatacc(cache_attr, &dhp->dh_hat_attr);

	dhp->dh_pcookie = cookie;
	dhp->dh_roff = ptob(btop(off));
	dhp->dh_len = ptob(btopr(len));

	/* Clear the large page size flag. */
	dhp->dh_flags &= ~DEVMAP_FLAG_LARGE;

	dhp->dh_maxprot = maxprot & dhp->dh_orig_maxprot;
	ASSERT((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) == dhp->dh_prot);
	RELE_DHP_LOCK(dhp);
	return (DDI_SUCCESS);
}

/*
 * Directly (i.e., without occupying kernel virtual address space) allocate
 * 'npages' physical memory pages for exporting to user land. The allocated
 * page_t pointer will be recorded in cookie.
 */
int
devmap_pmem_alloc(size_t size, uint_t flags, devmap_pmem_cookie_t *cookiep)
{
	u_offset_t	pmem_off = 0;
	page_t		*pp = NULL;
	page_t		*lpp = NULL;
	page_t		*tlist = NULL;
	pgcnt_t		i = 0;
	pgcnt_t		rpages = 0;
	pgcnt_t		lpages = 0;
	pgcnt_t		tpages = 0;
	pgcnt_t		npages = btopr(size);
	pmem_lpg_t	*plp = NULL;
	struct devmap_pmem_cookie	*pcp;
	uint_t		reserved = 0;
	uint_t		locked = 0;
	uint_t		pflags, kflags;

	*cookiep = NULL;

	/*
	 * Number larger than this will cause page_create_va() to loop
	 * infinitely.
	 */
	if (npages == 0 || npages >= total_pages / 2)
		return (DDI_FAILURE);
	if ((flags & (PMEM_SLEEP | PMEM_NOSLEEP)) == 0)
		return (DDI_FAILURE);
	pflags = flags & PMEM_NOSLEEP ? PG_EXCL : PG_WAIT;
	kflags = flags & PMEM_NOSLEEP ? KM_NOSLEEP : KM_SLEEP;

	/* Allocate pmem cookie. */
	if (pmem_cookie_alloc(&pcp, npages, kflags) == DDI_FAILURE)
		return (DDI_FAILURE);
	pcp->dp_npages = npages;

	/*
	 * See if the requested memory can be locked.
	 */
	pcp->dp_proc = curproc;
	if (pmem_lock(npages, curproc) == DDI_FAILURE)
		goto alloc_fail;
	locked = 1;
	/*
	 * First, grab as many as possible from pmem_mpool. If pages in
	 * pmem_mpool are enough for this request, we are done.
	 */
	mutex_enter(&pmem_mutex);
	tpages = mpool_break(&tlist, npages);
	/* IOlock and hashin them into the new offset. */
	if (tpages)
		tlist_in(tlist, tpages, pcp->dp_vnp, &pmem_off);
	mutex_exit(&pmem_mutex);

	if (tpages == npages)
		goto done;

	rpages = npages - tpages;
	/* Quit now if memory cannot be reserved. */
	if (!page_resv(rpages, kflags))
		goto alloc_fail;
	reserved = 1;

	/* If we have large pages */
	if (pmem_lpgsize > PAGESIZE) {
		/* Try to alloc large pages first to decrease fragmentation. */
		i = (rpages + (pmem_pgcnt - 1)) / pmem_pgcnt;
		if (lpp_create(&lpp, i, &lpages, &plp, pcp->dp_vnp, &pmem_off,
		    kflags) == DDI_FAILURE)
			goto alloc_fail;
		ASSERT(lpages == 0 ? lpp == NULL : 1);
	}

	/*
	 * Pages in large pages is more than the request, put the residual
	 * pages into pmem_mpool.
	 */
	if (lpages >= rpages) {
		lpp_break(&lpp, lpages, lpages - rpages, plp);
		goto done;
	}

	/* Allocate small pages if lpp+tlist cannot satisfy the request. */
	i =  rpages - lpages;
	if ((pp = page_create_va(pcp->dp_vnp, pmem_off, ptob(i),
	    pflags, &pmem_seg, (caddr_t)(uintptr_t)pmem_off)) == NULL)
		goto alloc_fail;

done:
	page_list_concat(&tlist, &lpp);
	page_list_concat(&tlist, &pp);
	/* Set those small pages from large pages as allocated. */
	mutex_enter(&pmem_mutex);
	pmem_lpg_concat(&pmem_occ_lpgs, &plp);
	mutex_exit(&pmem_mutex);

	/*
	 * Now tlist holds all the pages for this cookie. Record these pages in
	 * pmem cookie.
	 */
	for (pp = tlist, i = 0; i < npages; i++) {
		pcp->dp_pparray[i] = pp;
		page_io_unlock(pp);
		pp = pp->p_next;
		page_sub(&tlist, pp->p_prev);
	}
	ASSERT(tlist == NULL);
	*cookiep = (devmap_pmem_cookie_t)pcp;

	return (DDI_SUCCESS);

alloc_fail:
	DTRACE_PROBE(pmem__alloc__fail);
	/* Free large pages and the associated allocation records. */
	if (lpp)
		lpp_free(lpp, lpages / pmem_pgcnt, &plp);
	if (reserved == 1)
		page_unresv(rpages);
	/* Put those pages in tlist back into pmem_mpool. */
	if (tpages != 0) {
		mutex_enter(&pmem_mutex);
		/* IOunlock, hashout and update the allocation records. */
		tlist_out(tlist, tpages);
		mpool_append(&tlist, tpages);
		mutex_exit(&pmem_mutex);
	}
	if (locked == 1)
		i_ddi_decr_locked_memory(pcp->dp_proc, ptob(pcp->dp_npages));
	/* Freeing pmem_cookie. */
	kmem_free(pcp->dp_vnp, sizeof (vnode_t));
	kmem_free(pcp->dp_pparray, npages * sizeof (page_t *));
	kmem_free(pcp, sizeof (struct devmap_pmem_cookie));
	return (DDI_FAILURE);
}

/*
 * Free all small pages inside cookie, and return pages from large pages into
 * mpool, if all the pages from one large page is in mpool, free it as a whole.
 */
void
devmap_pmem_free(devmap_pmem_cookie_t cookie)
{
	struct	devmap_pmem_cookie *pcp = (struct devmap_pmem_cookie *)cookie;
	pgcnt_t		i;
	pgcnt_t		tpages = 0;
	page_t		*pp;
	pmem_lpg_t 	*pl1, *plp;
	pmem_lpg_t	*pf_lpgs = NULL;
	uint_t		npls = 0;
	pmem_lpg_t *last_pl = NULL;
	pmem_lpg_t *plast_pl = NULL;

	ASSERT(pcp);
	mutex_enter(&pmem_mutex);
	/* Free small pages and return them to memory pool. */
	for (i = pcp->dp_npages; i > 0; i--) {
		pp = pcp->dp_pparray[i - 1];
		page_hashout(pp, NULL);
		/*
		 * Remove the mapping of this single page, this mapping is
		 * created using hat_devload() in segdev_faultpage().
		 */
		(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
		if (!FROM_LPG(pp)) {
			/* Normal small page. */
			page_free(pp, 1);
			page_unresv(1);
		} else {
			/* Small page from large pages. */
			plp = pmem_lpg_get(pmem_occ_lpgs, pp, &last_pl);
			if (plp && !(plp->pl_pfree)) {
				/*
				 * Move this record to pf_lpgs list, this large
				 * page may be able to be freed as a whole.
				 */
				pmem_lpg_sub(&pmem_occ_lpgs, plp);
				pmem_lpg_concat(&pf_lpgs, &plp);
				plp->pl_pfree = 1;
				npls++;
				last_pl = NULL;
			} else {
				/* Search in pf_lpgs list. */
				plp = pmem_lpg_get(pf_lpgs, pp, &plast_pl);
			}
			ASSERT(plp);
			/* Mark this page as free. */
			BT_SET(plp->pl_bitmap, PFIND(pp));
			/* Record this page in pmem_mpool. */
			mpool_append(&pp, 1);
		}
	}

	/*
	 * Find out the large pages whose pages have been freed, remove them
	 * from plp list, free them and the associated pmem_lpg struct.
	 */
	for (plp = pf_lpgs; npls != 0; npls--) {
		pl1 = plp;
		plp = plp->pl_next;
		if (lpg_isfree(pl1)) {
			/*
			 * Get one free large page.  Find all pages in this
			 * large page and remove them from pmem_mpool.
			 */
			lpg_free(pl1->pl_pp);
			/* Remove associated allocation records. */
			pmem_lpg_sub(&pf_lpgs, pl1);
			pmem_lpg_free(&pf_lpgs, pl1);
			tpages -= pmem_pgcnt;
		} else
			pl1->pl_pfree = 0;
	}
	/* Update allocation records accordingly. */
	pmem_lpg_concat(&pmem_occ_lpgs, &pf_lpgs);
	mutex_exit(&pmem_mutex);

	if (curproc == pcp->dp_proc)
		i_ddi_decr_locked_memory(curproc, ptob(pcp->dp_npages));
	kmem_free(pcp->dp_vnp, sizeof (vnode_t));
	kmem_free(pcp->dp_pparray, pcp->dp_npages * sizeof (page_t *));
	kmem_free(pcp, sizeof (struct devmap_pmem_cookie));
}

/*
 * To extract page frame number from specified range in a cookie.
 */
int
devmap_pmem_getpfns(devmap_pmem_cookie_t cookie, uint_t start, pgcnt_t npages,
    pfn_t *pfnarray)
{
	struct devmap_pmem_cookie *pcp = (struct devmap_pmem_cookie *)cookie;
	pgcnt_t i;

	if (pcp == NULL || start + npages > pcp->dp_npages)
		return (DDI_FAILURE);

	for (i = start; i < start + npages; i++)
		pfnarray[i - start] = pfn_to_mfn(pcp->dp_pparray[i]->p_pagenum);

	return (DDI_SUCCESS);
}

void
pmem_init()
{
	mutex_init(&pmem_mutex, NULL, MUTEX_DEFAULT, NULL);
	pmem_lszc = MIN(1, page_num_pagesizes() - 1);
	pmem_lpgsize = page_get_pagesize(pmem_lszc);
	pmem_pgcnt = pmem_lpgsize >> PAGESHIFT;
	bzero(&pmem_seg, sizeof (struct seg));
	pmem_seg.s_as = &kas;
}

/* Allocate kernel memory for one pmem cookie with n pages. */
static int
pmem_cookie_alloc(struct devmap_pmem_cookie **pcpp, pgcnt_t n, uint_t kflags)
{
	struct devmap_pmem_cookie *pcp;

	if ((*pcpp = kmem_zalloc(sizeof (struct devmap_pmem_cookie),
	    kflags)) == NULL)
		return (DDI_FAILURE);
	pcp = *pcpp;
	if ((pcp->dp_vnp =
	    kmem_zalloc(sizeof (vnode_t), kflags)) == NULL) {
		kmem_free(pcp, sizeof (struct devmap_pmem_cookie));
		return (DDI_FAILURE);
	}
	if ((pcp->dp_pparray =
	    kmem_zalloc(n * sizeof (page_t *), kflags)) == NULL) {
		kmem_free(pcp->dp_vnp, sizeof (vnode_t));
		kmem_free(pcp, sizeof (struct devmap_pmem_cookie));
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/* Try to lock down n pages resource */
static int
pmem_lock(pgcnt_t n, proc_t *p)
{
	if (i_ddi_incr_locked_memory(p, ptob(n)) != 0) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/* To check if all the pages in a large page are freed. */
static int
lpg_isfree(pmem_lpg_t *plp)
{
	uint_t i;

	for (i = 0; i < BT_BITOUL(pmem_pgcnt); i++)
		if (plp->pl_bitmap[i] != BT_ULMAXMASK)
			return (0);
	/* All 1 means all pages are freed. */
	return (1);
}

/*
 * Using pp to get the associated large page allocation record, searching in
 * the splp linked list with *last as the heuristic pointer. Return NULL if
 * not found.
 */
static pmem_lpg_t *
pmem_lpg_get(pmem_lpg_t *splp, page_t *pp, pmem_lpg_t **last)
{
	pmem_lpg_t *plp;
	pgcnt_t root_pfn;

	ASSERT(pp);
	if (splp == NULL)
		return (NULL);
	root_pfn = page_pptonum(pp) & ~(pmem_pgcnt - 1);

	/* Try last winner first. */
	if (*last && root_pfn == page_pptonum((*last)->pl_pp))
		goto pl_found;

	/* Else search the whole pmem_lpg list. */
	for (plp = splp; root_pfn != page_pptonum(plp->pl_pp); ) {
		plp = plp->pl_next;
		if (plp == splp) {
			plp = NULL;
			break;
		}
		ASSERT(plp->pl_pp);
	}

	*last = plp;

pl_found:
	return (*last);
}

/*
 *  Remove one pmem_lpg plp from the oplpp list.
 */
static void
pmem_lpg_sub(pmem_lpg_t **oplpp, pmem_lpg_t *plp)
{
	if (*oplpp == plp)
		*oplpp = plp->pl_next;		/* go to next pmem_lpg */

	if (*oplpp == plp)
		*oplpp = NULL;			/* pmem_lpg list is gone */
	else {
		plp->pl_prev->pl_next = plp->pl_next;
		plp->pl_next->pl_prev = plp->pl_prev;
	}
	plp->pl_prev = plp->pl_next = plp;	/* make plp a list of one */
}

/*
 * Concatenate page list nplpp onto the end of list plpp.
 */
static void
pmem_lpg_concat(pmem_lpg_t **plpp, pmem_lpg_t **nplpp)
{
	pmem_lpg_t *s1p, *s2p, *e1p, *e2p;

	if (*nplpp == NULL) {
		return;
	}
	if (*plpp == NULL) {
		*plpp = *nplpp;
		return;
	}
	s1p = *plpp;
	e1p =  s1p->pl_prev;
	s2p = *nplpp;
	e2p = s2p->pl_prev;
	s1p->pl_prev = e2p;
	e2p->pl_next = s1p;
	e1p->pl_next = s2p;
	s2p->pl_prev = e1p;
}

/*
 * Allocate and initialize the allocation record of one large page, the init
 * value is 'allocated'.
 */
static pmem_lpg_t *
pmem_lpg_alloc(uint_t kflags)
{
	pmem_lpg_t *plp;

	ASSERT(pmem_pgcnt % BT_NBIPUL == 0);
	plp = kmem_zalloc(sizeof (pmem_lpg_t), kflags);
	if (plp == NULL)
		return (NULL);
	plp->pl_bitmap = kmem_zalloc(BT_SIZEOFMAP(pmem_pgcnt), kflags);
	if (plp->pl_bitmap == NULL) {
		kmem_free(plp, sizeof (*plp));
		return (NULL);
	}
	plp->pl_next = plp->pl_prev = plp;
	return (plp);
}

/* Free one allocation record pointed by oplp. */
static void
pmem_lpg_free(pmem_lpg_t **headp, pmem_lpg_t *plp)
{
	if (*headp == plp)
		*headp = plp->pl_next;		/* go to next pmem_lpg_t */

	if (*headp == plp)
		*headp = NULL;			/* this list is gone */
	else {
		plp->pl_prev->pl_next = plp->pl_next;
		plp->pl_next->pl_prev = plp->pl_prev;
	}
	kmem_free(plp->pl_bitmap, BT_SIZEOFMAP(pmem_pgcnt));
	kmem_free(plp, sizeof (*plp));
}

/* Free one large page headed by spp from pmem_mpool. */
static void
lpg_free(page_t *spp)
{
	page_t *pp1 = spp;
	uint_t i;

	ASSERT(MUTEX_HELD(&pmem_mutex));
	for (i = 0; i < pmem_pgcnt; i++) {
		/* Break pp1 from pmem_mpool. */
		page_sub(&pmem_mpool, pp1);
		pp1++;
	}
	/* Free pages in this large page. */
	page_free_pages(spp);
	page_unresv(pmem_pgcnt);
	pmem_nmpages -= pmem_pgcnt;
	ASSERT((pmem_nmpages && pmem_mpool) || (!pmem_nmpages && !pmem_mpool));
}

/* Put n pages in *ppp list back into pmem_mpool. */
static void
mpool_append(page_t **ppp, pgcnt_t n)
{
	ASSERT(MUTEX_HELD(&pmem_mutex));
	/* Put back pages. */
	page_list_concat(&pmem_mpool, ppp);
	pmem_nmpages += n;
	ASSERT((pmem_nmpages && pmem_mpool) || (!pmem_nmpages && !pmem_mpool));
}

/*
 * Try to grab MIN(pmem_nmpages, n) pages from pmem_mpool, put them into *ppp
 * list, and return the number of grabbed pages.
 */
static pgcnt_t
mpool_break(page_t **ppp, pgcnt_t n)
{
	pgcnt_t i;

	ASSERT(MUTEX_HELD(&pmem_mutex));
	/* Grab the pages. */
	i = MIN(pmem_nmpages, n);
	*ppp = pmem_mpool;
	page_list_break(ppp, &pmem_mpool, i);
	pmem_nmpages -= i;
	ASSERT((pmem_nmpages && pmem_mpool) || (!pmem_nmpages && !pmem_mpool));
	return (i);
}

/*
 * Create n large pages, lpages and plpp contains the number of small pages and
 * allocation records list respectively.
 */
static int
lpp_create(page_t **lppp, pgcnt_t n, pgcnt_t *lpages, pmem_lpg_t **plpp,
    vnode_t *vnp, u_offset_t *offp, uint_t kflags)
{
	pgcnt_t i;
	pmem_lpg_t *plp;
	page_t *pp;

	for (i = 0, *lpages = 0; i < n; i++) {
		/* Allocte one large page each time. */
		pp = page_create_va_large(vnp, *offp, pmem_lpgsize,
		    PG_EXCL, &pmem_seg, (caddr_t)(uintptr_t)*offp, NULL);
		if (pp == NULL)
			break;
		*offp += pmem_lpgsize;
		page_list_concat(lppp, &pp);
		*lpages += pmem_pgcnt;
		/* Add one allocation record for this large page. */
		if ((plp = pmem_lpg_alloc(kflags)) == NULL)
			return (DDI_FAILURE);
		plp->pl_pp = pp;
		pmem_lpg_concat(plpp, &plp);
	}
	return (DDI_SUCCESS);
}

/*
 * Break the last r small pages from the large page list *lppp (with totally n
 * small pages) and put them into pmem_mpool.
 */
static void
lpp_break(page_t **lppp, pgcnt_t n, pgcnt_t r, pmem_lpg_t *oplp)
{
	page_t *pp, *pp1;
	pgcnt_t i;
	pmem_lpg_t *plp;

	if (r == 0)
		return;
	ASSERT(*lppp != NULL && r < pmem_pgcnt);
	page_list_break(lppp, &pp, n - r);

	/* The residual should reside in the last large page.  */
	plp = oplp->pl_prev;
	/* IOunlock and hashout the residual pages. */
	for (pp1 = pp, i = 0; i < r; i++) {
		page_io_unlock(pp1);
		page_hashout(pp1, NULL);
		/* Mark this page as free. */
		BT_SET(plp->pl_bitmap, PFIND(pp1));
		pp1 = pp1->p_next;
	}
	ASSERT(pp1 == pp);
	/* Put these residual pages into memory pool. */
	mutex_enter(&pmem_mutex);
	mpool_append(&pp, r);
	mutex_exit(&pmem_mutex);
}

/* Freeing large pages in lpp and the associated allocation records in plp. */
static void
lpp_free(page_t *lpp, pgcnt_t lpgs, pmem_lpg_t **plpp)
{
	pgcnt_t i, j;
	page_t *pp = lpp, *pp1;
	pmem_lpg_t *plp1, *plp2;

	for (i = 0; i < lpgs; i++) {
		for (j = 0; j < pmem_pgcnt; j++) {
			/* IO unlock and hashout this small page. */
			page_io_unlock(pp);
			page_hashout(pp, NULL);
			pp1 = pp->p_next;
			pp->p_prev = pp->p_next = pp;
			pp = pp1;
		}
		/* Free one large page at one time. */
		page_free_pages(lpp);
		lpp = pp;
	}
	/* Free associate pmem large page allocation records. */
	for (plp1 = *plpp; *plpp; plp1 = plp2) {
		plp2 = plp1->pl_next;
		pmem_lpg_free(plpp, plp1);
	}
}

/*
 * IOlock and hashin all pages in tlist, associate them with vnode *pvnp
 * and offset starting with *poffp. Update allocation records accordingly at
 * the same time.
 */
static void
tlist_in(page_t *tlist, pgcnt_t tpages, vnode_t *pvnp, u_offset_t *poffp)
{
	page_t *pp;
	pgcnt_t i = 0;
	pmem_lpg_t *plp, *last_pl = NULL;

	ASSERT(MUTEX_HELD(&pmem_mutex));
	for (pp = tlist; i < tpages; i++) {
		ASSERT(FROM_LPG(pp));
		page_io_lock(pp);
		(void) page_hashin(pp, pvnp, *poffp, NULL);
		plp = pmem_lpg_get(pmem_occ_lpgs, pp, &last_pl);
		/* Mark this page as allocated. */
		BT_CLEAR(plp->pl_bitmap, PFIND(pp));
		*poffp += PAGESIZE;
		pp = pp->p_next;
	}
	ASSERT(pp == tlist);
}

/*
 * IOunlock and hashout all pages in tlist, update allocation records
 * accordingly at the same time.
 */
static void
tlist_out(page_t *tlist, pgcnt_t tpages)
{
	page_t *pp;
	pgcnt_t i = 0;
	pmem_lpg_t *plp, *last_pl = NULL;

	ASSERT(MUTEX_HELD(&pmem_mutex));
	for (pp = tlist; i < tpages; i++) {
		ASSERT(FROM_LPG(pp));
		page_io_unlock(pp);
		page_hashout(pp, NULL);
		plp = pmem_lpg_get(pmem_occ_lpgs, pp, &last_pl);
		/* Mark this page as free. */
		BT_SET(plp->pl_bitmap, PFIND(pp));
		pp = pp->p_next;
	}
	ASSERT(pp == tlist);
}

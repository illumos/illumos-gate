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
 */

/*
 * Kernel Physical Mapping (segkpm) hat interface routines for sun4u.
 */

#include <sys/types.h>
#include <vm/hat.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/machsystm.h>
#include <vm/seg_kpm.h>
#include <sys/cpu_module.h>
#include <vm/mach_kpm.h>

/* kpm prototypes */
static caddr_t	sfmmu_kpm_mapin(page_t *);
static void	sfmmu_kpm_mapout(page_t *, caddr_t);
static int	sfmmu_kpme_lookup(struct kpme *, page_t *);
static void	sfmmu_kpme_add(struct kpme *, page_t *);
static void	sfmmu_kpme_sub(struct kpme *, page_t *);
static caddr_t	sfmmu_kpm_getvaddr(page_t *, int *);
static int	sfmmu_kpm_fault(caddr_t, struct memseg *, page_t *);
static int	sfmmu_kpm_fault_small(caddr_t, struct memseg *, page_t *);
static void	sfmmu_kpm_vac_conflict(page_t *, caddr_t);
void	sfmmu_kpm_pageunload(page_t *);
void	sfmmu_kpm_vac_unload(page_t *, caddr_t);
static void	sfmmu_kpm_demap_large(caddr_t);
static void	sfmmu_kpm_demap_small(caddr_t);
static void	sfmmu_kpm_demap_tlbs(caddr_t);
void	sfmmu_kpm_hme_unload(page_t *);
kpm_hlk_t *sfmmu_kpm_kpmp_enter(page_t *, pgcnt_t);
void	sfmmu_kpm_kpmp_exit(kpm_hlk_t *kpmp);
void	sfmmu_kpm_page_cache(page_t *, int, int);

extern uint_t vac_colors;

/*
 * Kernel Physical Mapping (kpm) facility
 */

void
mach_kpm_init()
{}

/* -- hat_kpm interface section -- */

/*
 * Mapin a locked page and return the vaddr.
 * When a kpme is provided by the caller it is added to
 * the page p_kpmelist. The page to be mapped in must
 * be at least read locked (p_selock).
 */
caddr_t
hat_kpm_mapin(struct page *pp, struct kpme *kpme)
{
	kmutex_t	*pml;
	caddr_t		vaddr;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapin: kpm_enable not set");
		return ((caddr_t)NULL);
	}

	if (pp == NULL || PAGE_LOCKED(pp) == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapin: pp zero or not locked");
		return ((caddr_t)NULL);
	}

	pml = sfmmu_mlist_enter(pp);
	ASSERT(pp->p_kpmref >= 0);

	vaddr = (pp->p_kpmref == 0) ?
	    sfmmu_kpm_mapin(pp) : hat_kpm_page2va(pp, 1);

	if (kpme != NULL) {
		/*
		 * Tolerate multiple mapins for the same kpme to avoid
		 * the need for an extra serialization.
		 */
		if ((sfmmu_kpme_lookup(kpme, pp)) == 0)
			sfmmu_kpme_add(kpme, pp);

		ASSERT(pp->p_kpmref > 0);

	} else {
		pp->p_kpmref++;
	}

	sfmmu_mlist_exit(pml);
	return (vaddr);
}

/*
 * Mapout a locked page.
 * When a kpme is provided by the caller it is removed from
 * the page p_kpmelist. The page to be mapped out must be at
 * least read locked (p_selock).
 * Note: The seg_kpm layer provides a mapout interface for the
 * case that a kpme is used and the underlying page is unlocked.
 * This can be used instead of calling this function directly.
 */
void
hat_kpm_mapout(struct page *pp, struct kpme *kpme, caddr_t vaddr)
{
	kmutex_t	*pml;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapout: kpm_enable not set");
		return;
	}

	if (IS_KPM_ADDR(vaddr) == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapout: no kpm address");
		return;
	}

	if (pp == NULL || PAGE_LOCKED(pp) == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapout: page zero or not locked");
		return;
	}

	if (kpme != NULL) {
		ASSERT(pp == kpme->kpe_page);
		pp = kpme->kpe_page;
		pml = sfmmu_mlist_enter(pp);

		if (sfmmu_kpme_lookup(kpme, pp) == 0)
			panic("hat_kpm_mapout: kpme not found pp=%p",
			    (void *)pp);

		ASSERT(pp->p_kpmref > 0);
		sfmmu_kpme_sub(kpme, pp);

	} else {
		pml = sfmmu_mlist_enter(pp);
		pp->p_kpmref--;
	}

	ASSERT(pp->p_kpmref >= 0);
	if (pp->p_kpmref == 0)
		sfmmu_kpm_mapout(pp, vaddr);

	sfmmu_mlist_exit(pml);
}

/*
 * hat_kpm_mapin_pfn is used to obtain a kpm mapping for physical
 * memory addresses that are not described by a page_t.  It can
 * only be supported if vac_colors=1, because there is no page_t
 * and corresponding kpm_page_t to track VAC conflicts.  Currently,
 * this may not be used on pfn's backed by page_t's, because the
 * kpm state may not be consistent in hat_kpm_fault if the page is
 * mapped using both this routine and hat_kpm_mapin.  KPM should be
 * cleaned up on sun4u/vac_colors=1 to be minimal as on sun4v.
 * The caller must only pass pfn's for valid physical addresses; violation
 * of this rule will cause panic.
 */
caddr_t
hat_kpm_mapin_pfn(pfn_t pfn)
{
	caddr_t paddr, vaddr;
	tte_t tte;
	uint_t szc = kpm_smallpages ? TTE8K : TTE4M;
	uint_t shift = kpm_smallpages ? MMU_PAGESHIFT : MMU_PAGESHIFT4M;

	if (kpm_enable == 0 || vac_colors > 1 ||
	    page_numtomemseg_nolock(pfn) != NULL)
		return ((caddr_t)NULL);

	paddr = (caddr_t)ptob(pfn);
	vaddr = (uintptr_t)kpm_vbase + paddr;

	KPM_TTE_VCACHED(tte.ll, pfn, szc);
	sfmmu_kpm_load_tsb(vaddr, &tte, shift);

	return (vaddr);
}

/*ARGSUSED*/
void
hat_kpm_mapout_pfn(pfn_t pfn)
{
	/* empty */
}

/*
 * Return the kpm virtual address for the page at pp.
 * If checkswap is non zero and the page is backed by a
 * swap vnode the physical address is used rather than
 * p_offset to determine the kpm region.
 * Note: The function has to be used w/ extreme care. The
 * stability of the page identity is in the responsibility
 * of the caller.
 */
/*ARGSUSED*/
caddr_t
hat_kpm_page2va(struct page *pp, int checkswap)
{
	int		vcolor, vcolor_pa;
	uintptr_t	paddr, vaddr;

	ASSERT(kpm_enable);

	paddr = ptob(pp->p_pagenum);
	vcolor_pa = addr_to_vcolor(paddr);

	if (checkswap && pp->p_vnode && IS_SWAPFSVP(pp->p_vnode))
		vcolor = (PP_ISNC(pp)) ? vcolor_pa : PP_GET_VCOLOR(pp);
	else
		vcolor = addr_to_vcolor(pp->p_offset);

	vaddr = (uintptr_t)kpm_vbase + paddr;

	if (vcolor_pa != vcolor) {
		vaddr += ((uintptr_t)(vcolor - vcolor_pa) << MMU_PAGESHIFT);
		vaddr += (vcolor_pa > vcolor) ?
		    ((uintptr_t)vcolor_pa << kpm_size_shift) :
		    ((uintptr_t)(vcolor - vcolor_pa) << kpm_size_shift);
	}

	return ((caddr_t)vaddr);
}

/*
 * Return the page for the kpm virtual address vaddr.
 * Caller is responsible for the kpm mapping and lock
 * state of the page.
 */
page_t *
hat_kpm_vaddr2page(caddr_t vaddr)
{
	uintptr_t	paddr;
	pfn_t		pfn;

	ASSERT(IS_KPM_ADDR(vaddr));

	SFMMU_KPM_VTOP(vaddr, paddr);
	pfn = (pfn_t)btop(paddr);

	return (page_numtopp_nolock(pfn));
}

/* page to kpm_page */
#define	PP2KPMPG(pp, kp) {						\
	struct memseg	*mseg;						\
	pgcnt_t		inx;						\
	pfn_t		pfn;						\
									\
	pfn = pp->p_pagenum;						\
	mseg = page_numtomemseg_nolock(pfn);				\
	ASSERT(mseg);							\
	inx = ptokpmp(kpmptop(ptokpmp(pfn)) - mseg->kpm_pbase);		\
	ASSERT(inx < mseg->kpm_nkpmpgs);				\
	kp = &mseg->kpm_pages[inx];					\
}

/* page to kpm_spage */
#define	PP2KPMSPG(pp, ksp) {						\
	struct memseg	*mseg;						\
	pgcnt_t		inx;						\
	pfn_t		pfn;						\
									\
	pfn = pp->p_pagenum;						\
	mseg = page_numtomemseg_nolock(pfn);				\
	ASSERT(mseg);							\
	inx = pfn - mseg->kpm_pbase;					\
	ksp = &mseg->kpm_spages[inx];					\
}

/*
 * hat_kpm_fault is called from segkpm_fault when a kpm tsbmiss occurred
 * which could not be resolved by the trap level tsbmiss handler for the
 * following reasons:
 * . The vaddr is in VAC alias range (always PAGESIZE mapping size).
 * . The kpm (s)page range of vaddr is in a VAC alias prevention state.
 * . tsbmiss handling at trap level is not desired (DEBUG kernel only,
 *   kpm_tsbmtl == 0).
 */
int
hat_kpm_fault(struct hat *hat, caddr_t vaddr)
{
	int		error;
	uintptr_t	paddr;
	pfn_t		pfn;
	struct memseg	*mseg;
	page_t	*pp;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "hat_kpm_fault: kpm_enable not set");
		return (ENOTSUP);
	}

	ASSERT(hat == ksfmmup);
	ASSERT(IS_KPM_ADDR(vaddr));

	SFMMU_KPM_VTOP(vaddr, paddr);
	pfn = (pfn_t)btop(paddr);
	if ((mseg = page_numtomemseg_nolock(pfn)) != NULL) {
		pp = &mseg->pages[(pgcnt_t)(pfn - mseg->pages_base)];
		ASSERT((pfn_t)pp->p_pagenum == pfn);
	}

	/*
	 * hat_kpm_mapin_pfn may add a kpm translation for memory that falls
	 * outside of memsegs.  Check for this case and provide the translation
	 * here.
	 */
	if (vac_colors == 1 && mseg == NULL) {
		tte_t tte;
		uint_t szc = kpm_smallpages ? TTE8K : TTE4M;
		uint_t shift = kpm_smallpages ? MMU_PAGESHIFT : MMU_PAGESHIFT4M;

		ASSERT(address_in_memlist(phys_install, paddr, 1));
		KPM_TTE_VCACHED(tte.ll, pfn, szc);
		sfmmu_kpm_load_tsb(vaddr, &tte, shift);
		error = 0;
	} else if (mseg == NULL || !PAGE_LOCKED(pp))
		error = EFAULT;
	else if (kpm_smallpages == 0)
		error = sfmmu_kpm_fault(vaddr, mseg, pp);
	else
		error = sfmmu_kpm_fault_small(vaddr, mseg, pp);

	return (error);
}

/*
 * memseg_hash[] was cleared, need to clear memseg_phash[] too.
 */
void
hat_kpm_mseghash_clear(int nentries)
{
	pgcnt_t i;

	if (kpm_enable == 0)
		return;

	for (i = 0; i < nentries; i++)
		memseg_phash[i] = MSEG_NULLPTR_PA;
}

/*
 * Update memseg_phash[inx] when memseg_hash[inx] was changed.
 */
void
hat_kpm_mseghash_update(pgcnt_t inx, struct memseg *msp)
{
	if (kpm_enable == 0)
		return;

	memseg_phash[inx] = (msp) ? va_to_pa(msp) : MSEG_NULLPTR_PA;
}

/*
 * Update kpm memseg members from basic memseg info.
 */
void
hat_kpm_addmem_mseg_update(struct memseg *msp, pgcnt_t nkpmpgs,
	offset_t kpm_pages_off)
{
	if (kpm_enable == 0)
		return;

	msp->kpm_pages = (kpm_page_t *)((caddr_t)msp->pages + kpm_pages_off);
	msp->kpm_nkpmpgs = nkpmpgs;
	msp->kpm_pbase = kpmptop(ptokpmp(msp->pages_base));
	msp->pagespa = va_to_pa(msp->pages);
	msp->epagespa = va_to_pa(msp->epages);
	msp->kpm_pagespa = va_to_pa(msp->kpm_pages);
}

/*
 * Setup nextpa when a memseg is inserted.
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_addmem_mseg_insert(struct memseg *msp)
{
	if (kpm_enable == 0)
		return;

	ASSERT(memsegs_lock_held());
	msp->nextpa = (memsegs) ? va_to_pa(memsegs) : MSEG_NULLPTR_PA;
}

/*
 * Setup memsegspa when a memseg is (head) inserted.
 * Called before memsegs is updated to complete a
 * memseg insert operation.
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_addmem_memsegs_update(struct memseg *msp)
{
	if (kpm_enable == 0)
		return;

	ASSERT(memsegs_lock_held());
	ASSERT(memsegs);
	memsegspa = va_to_pa(msp);
}

/*
 * Return end of metadata for an already setup memseg.
 *
 * Note: kpm_pages and kpm_spages are aliases and the underlying
 * member of struct memseg is a union, therefore they always have
 * the same address within a memseg. They must be differentiated
 * when pointer arithmetic is used with them.
 */
caddr_t
hat_kpm_mseg_reuse(struct memseg *msp)
{
	caddr_t end;

	if (kpm_smallpages == 0)
		end = (caddr_t)(msp->kpm_pages + msp->kpm_nkpmpgs);
	else
		end = (caddr_t)(msp->kpm_spages + msp->kpm_nkpmpgs);

	return (end);
}

/*
 * Update memsegspa (when first memseg in list
 * is deleted) or nextpa  when a memseg deleted.
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_delmem_mseg_update(struct memseg *msp, struct memseg **mspp)
{
	struct memseg *lmsp;

	if (kpm_enable == 0)
		return;

	ASSERT(memsegs_lock_held());

	if (mspp == &memsegs) {
		memsegspa = (msp->next) ?
		    va_to_pa(msp->next) : MSEG_NULLPTR_PA;
	} else {
		lmsp = (struct memseg *)
		    ((uint64_t)mspp - offsetof(struct memseg, next));
		lmsp->nextpa = (msp->next) ?
		    va_to_pa(msp->next) : MSEG_NULLPTR_PA;
	}
}

/*
 * Update kpm members for all memseg's involved in a split operation
 * and do the atomic update of the physical memseg chain.
 *
 * Note: kpm_pages and kpm_spages are aliases and the underlying member
 * of struct memseg is a union, therefore they always have the same
 * address within a memseg. With that the direct assignments and
 * va_to_pa conversions below don't have to be distinguished wrt. to
 * kpm_smallpages. They must be differentiated when pointer arithmetic
 * is used with them.
 *
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_split_mseg_update(struct memseg *msp, struct memseg **mspp,
	struct memseg *lo, struct memseg *mid, struct memseg *hi)
{
	pgcnt_t start, end, kbase, kstart, num;
	struct memseg *lmsp;

	if (kpm_enable == 0)
		return;

	ASSERT(memsegs_lock_held());
	ASSERT(msp && mid && msp->kpm_pages);

	kbase = ptokpmp(msp->kpm_pbase);

	if (lo) {
		num = lo->pages_end - lo->pages_base;
		start = kpmptop(ptokpmp(lo->pages_base));
		/* align end to kpm page size granularity */
		end = kpmptop(ptokpmp(start + num - 1)) + kpmpnpgs;
		lo->kpm_pbase = start;
		lo->kpm_nkpmpgs = ptokpmp(end - start);
		lo->kpm_pages = msp->kpm_pages;
		lo->kpm_pagespa = va_to_pa(lo->kpm_pages);
		lo->pagespa = va_to_pa(lo->pages);
		lo->epagespa = va_to_pa(lo->epages);
		lo->nextpa = va_to_pa(lo->next);
	}

	/* mid */
	num = mid->pages_end - mid->pages_base;
	kstart = ptokpmp(mid->pages_base);
	start = kpmptop(kstart);
	/* align end to kpm page size granularity */
	end = kpmptop(ptokpmp(start + num - 1)) + kpmpnpgs;
	mid->kpm_pbase = start;
	mid->kpm_nkpmpgs = ptokpmp(end - start);
	if (kpm_smallpages == 0) {
		mid->kpm_pages = msp->kpm_pages + (kstart - kbase);
	} else {
		mid->kpm_spages = msp->kpm_spages + (kstart - kbase);
	}
	mid->kpm_pagespa = va_to_pa(mid->kpm_pages);
	mid->pagespa = va_to_pa(mid->pages);
	mid->epagespa = va_to_pa(mid->epages);
	mid->nextpa = (mid->next) ?  va_to_pa(mid->next) : MSEG_NULLPTR_PA;

	if (hi) {
		num = hi->pages_end - hi->pages_base;
		kstart = ptokpmp(hi->pages_base);
		start = kpmptop(kstart);
		/* align end to kpm page size granularity */
		end = kpmptop(ptokpmp(start + num - 1)) + kpmpnpgs;
		hi->kpm_pbase = start;
		hi->kpm_nkpmpgs = ptokpmp(end - start);
		if (kpm_smallpages == 0) {
			hi->kpm_pages = msp->kpm_pages + (kstart - kbase);
		} else {
			hi->kpm_spages = msp->kpm_spages + (kstart - kbase);
		}
		hi->kpm_pagespa = va_to_pa(hi->kpm_pages);
		hi->pagespa = va_to_pa(hi->pages);
		hi->epagespa = va_to_pa(hi->epages);
		hi->nextpa = (hi->next) ? va_to_pa(hi->next) : MSEG_NULLPTR_PA;
	}

	/*
	 * Atomic update of the physical memseg chain
	 */
	if (mspp == &memsegs) {
		memsegspa = (lo) ? va_to_pa(lo) : va_to_pa(mid);
	} else {
		lmsp = (struct memseg *)
		    ((uint64_t)mspp - offsetof(struct memseg, next));
		lmsp->nextpa = (lo) ? va_to_pa(lo) : va_to_pa(mid);
	}
}

/*
 * Walk the memsegs chain, applying func to each memseg span and vcolor.
 */
void
hat_kpm_walk(void (*func)(void *, void *, size_t), void *arg)
{
	pfn_t	pbase, pend;
	int	vcolor;
	void	*base;
	size_t	size;
	struct memseg *msp;

	for (msp = memsegs; msp; msp = msp->next) {
		pbase = msp->pages_base;
		pend = msp->pages_end;
		for (vcolor = 0; vcolor < vac_colors; vcolor++) {
			base = ptob(pbase) + kpm_vbase + kpm_size * vcolor;
			size = ptob(pend - pbase);
			func(arg, base, size);
		}
	}
}


/* -- sfmmu_kpm internal section -- */

/*
 * Return the page frame number if a valid segkpm mapping exists
 * for vaddr, otherwise return PFN_INVALID. No locks are grabbed.
 * Should only be used by other sfmmu routines.
 */
pfn_t
sfmmu_kpm_vatopfn(caddr_t vaddr)
{
	uintptr_t	paddr;
	pfn_t		pfn;
	page_t	*pp;

	ASSERT(kpm_enable && IS_KPM_ADDR(vaddr));

	SFMMU_KPM_VTOP(vaddr, paddr);
	pfn = (pfn_t)btop(paddr);
	pp = page_numtopp_nolock(pfn);
	if (pp && pp->p_kpmref)
		return (pfn);
	else
		return ((pfn_t)PFN_INVALID);
}

/*
 * Lookup a kpme in the p_kpmelist.
 */
static int
sfmmu_kpme_lookup(struct kpme *kpme, page_t *pp)
{
	struct kpme	*p;

	for (p = pp->p_kpmelist; p; p = p->kpe_next) {
		if (p == kpme)
			return (1);
	}
	return (0);
}

/*
 * Insert a kpme into the p_kpmelist and increment
 * the per page kpm reference count.
 */
static void
sfmmu_kpme_add(struct kpme *kpme, page_t *pp)
{
	ASSERT(pp->p_kpmref >= 0);

	/* head insert */
	kpme->kpe_prev = NULL;
	kpme->kpe_next = pp->p_kpmelist;

	if (pp->p_kpmelist)
		pp->p_kpmelist->kpe_prev = kpme;

	pp->p_kpmelist = kpme;
	kpme->kpe_page = pp;
	pp->p_kpmref++;
}

/*
 * Remove a kpme from the p_kpmelist and decrement
 * the per page kpm reference count.
 */
static void
sfmmu_kpme_sub(struct kpme *kpme, page_t *pp)
{
	ASSERT(pp->p_kpmref > 0);

	if (kpme->kpe_prev) {
		ASSERT(pp->p_kpmelist != kpme);
		ASSERT(kpme->kpe_prev->kpe_page == pp);
		kpme->kpe_prev->kpe_next = kpme->kpe_next;
	} else {
		ASSERT(pp->p_kpmelist == kpme);
		pp->p_kpmelist = kpme->kpe_next;
	}

	if (kpme->kpe_next) {
		ASSERT(kpme->kpe_next->kpe_page == pp);
		kpme->kpe_next->kpe_prev = kpme->kpe_prev;
	}

	kpme->kpe_next = kpme->kpe_prev = NULL;
	kpme->kpe_page = NULL;
	pp->p_kpmref--;
}

/*
 * Mapin a single page, it is called every time a page changes it's state
 * from kpm-unmapped to kpm-mapped. It may not be called, when only a new
 * kpm instance does a mapin and wants to share the mapping.
 * Assumes that the mlist mutex is already grabbed.
 */
static caddr_t
sfmmu_kpm_mapin(page_t *pp)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		vaddr;
	int		kpm_vac_range;
	pfn_t		pfn;
	tte_t		tte;
	kmutex_t	*pmtx;
	int		uncached;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	int		oldval;

	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(pp->p_kpmref == 0);

	vaddr = sfmmu_kpm_getvaddr(pp, &kpm_vac_range);

	ASSERT(IS_KPM_ADDR(vaddr));
	uncached = PP_ISNC(pp);
	pfn = pp->p_pagenum;

	if (kpm_smallpages)
		goto smallpages_mapin;

	PP2KPMPG(pp, kp);

	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	ASSERT(PP_ISKPMC(pp) == 0);
	ASSERT(PP_ISKPMS(pp) == 0);

	if (uncached) {
		/* ASSERT(pp->p_share); XXX use hat_page_getshare */
		if (kpm_vac_range == 0) {
			if (kp->kp_refcnts == 0) {
				/*
				 * Must remove large page mapping if it exists.
				 * Pages in uncached state can only be mapped
				 * small (PAGESIZE) within the regular kpm
				 * range.
				 */
				if (kp->kp_refcntc == -1) {
					/* remove go indication */
					sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
					    &kpmp->khl_lock, KPMTSBM_STOP);
				}
				if (kp->kp_refcnt > 0 && kp->kp_refcntc == 0)
					sfmmu_kpm_demap_large(vaddr);
			}
			ASSERT(kp->kp_refcntc >= 0);
			kp->kp_refcntc++;
		}
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
	}

	if ((kp->kp_refcntc > 0 || kp->kp_refcnts > 0) && kpm_vac_range == 0) {
		/*
		 * Have to do a small (PAGESIZE) mapin within this kpm_page
		 * range since it is marked to be in VAC conflict mode or
		 * when there are still other small mappings around.
		 */

		/* tte assembly */
		if (uncached == 0)
			KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
		else
			KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);

		kp->kp_refcnts++;
		ASSERT(kp->kp_refcnts > 0);
		goto exit;
	}

	if (kpm_vac_range == 0) {
		/*
		 * Fast path / regular case, no VAC conflict handling
		 * in progress within this kpm_page range.
		 */
		if (kp->kp_refcnt == 0) {

			/* tte assembly */
			KPM_TTE_VCACHED(tte.ll, pfn, TTE4M);

			/* tsb dropin */
			sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT4M);

			/* Set go flag for TL tsbmiss handler */
			if (kp->kp_refcntc == 0)
				sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
				    &kpmp->khl_lock, KPMTSBM_START);

			ASSERT(kp->kp_refcntc == -1);
		}
		kp->kp_refcnt++;
		ASSERT(kp->kp_refcnt);

	} else {
		/*
		 * The page is not setup according to the common VAC
		 * prevention rules for the regular and kpm mapping layer
		 * E.g. the page layer was not able to deliver a right
		 * vcolor'ed page for a given vaddr corresponding to
		 * the wanted p_offset. It has to be mapped in small in
		 * within the corresponding kpm vac range in order to
		 * prevent VAC alias conflicts.
		 */

		/* tte assembly */
		if (uncached == 0) {
			KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
		} else {
			KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);
		}

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

		kp->kp_refcnta++;
		if (kp->kp_refcntc == -1) {
			ASSERT(kp->kp_refcnt > 0);

			/* remove go indication */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc, &kpmp->khl_lock,
			    KPMTSBM_STOP);
		}
		ASSERT(kp->kp_refcntc >= 0);
	}
exit:
	mutex_exit(&kpmp->khl_mutex);
	return (vaddr);

smallpages_mapin:
	if (uncached == 0) {
		/* tte assembly */
		KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
	} else {
		/*
		 * Just in case this same page was mapped cacheable prior to
		 * this and the old tte remains in tlb.
		 */
		sfmmu_kpm_demap_small(vaddr);

		/* ASSERT(pp->p_share); XXX use hat_page_getshare */
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		/* tte assembly */
		KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);
	}

	/* tsb dropin */
	sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag, &kpmsp->kshl_lock,
	    (uncached) ? (KPM_MAPPED_GO | KPM_MAPPEDSC) :
	    (KPM_MAPPED_GO | KPM_MAPPEDS));

	if (oldval != 0)
		panic("sfmmu_kpm_mapin: stale smallpages mapping");

	return (vaddr);
}

/*
 * Mapout a single page, it is called every time a page changes it's state
 * from kpm-mapped to kpm-unmapped. It may not be called, when only a kpm
 * instance calls mapout and there are still other instances mapping the
 * page. Assumes that the mlist mutex is already grabbed.
 *
 * Note: In normal mode (no VAC conflict prevention pending) TLB's are
 * not flushed. This is the core segkpm behavior to avoid xcalls. It is
 * no problem because a translation from a segkpm virtual address to a
 * physical address is always the same. The only downside is a slighty
 * increased window of vulnerability for misbehaving _kernel_ modules.
 */
static void
sfmmu_kpm_mapout(page_t *pp, caddr_t vaddr)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	int		alias_range;
	kmutex_t	*pmtx;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	int		oldval;

	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(pp->p_kpmref == 0);

	alias_range = IS_KPM_ALIAS_RANGE(vaddr);

	if (kpm_smallpages)
		goto smallpages_mapout;

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	if (alias_range) {
		ASSERT(PP_ISKPMS(pp) == 0);
		if (kp->kp_refcnta <= 0) {
			panic("sfmmu_kpm_mapout: bad refcnta kp=%p",
			    (void *)kp);
		}

		if (PP_ISTNC(pp))  {
			if (PP_ISKPMC(pp) == 0) {
				/*
				 * Uncached kpm mappings must always have
				 * forced "small page" mode.
				 */
				panic("sfmmu_kpm_mapout: uncached page not "
				    "kpm marked");
			}
			sfmmu_kpm_demap_small(vaddr);

			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);

			/*
			 * Check if we can resume cached mode. This might
			 * be the case if the kpm mapping was the only
			 * mapping in conflict with other non rule
			 * compliant mappings. The page is no more marked
			 * as kpm mapped, so the conv_tnc path will not
			 * change kpm state.
			 */
			conv_tnc(pp, TTE8K);

		} else if (PP_ISKPMC(pp) == 0) {
			/* remove TSB entry only */
			sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT);

		} else {
			/* already demapped */
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);
		}
		kp->kp_refcnta--;
		goto exit;
	}

	if (kp->kp_refcntc <= 0 && kp->kp_refcnts == 0) {
		/*
		 * Fast path / regular case.
		 */
		ASSERT(kp->kp_refcntc >= -1);
		ASSERT(!(pp->p_nrm & (P_KPMC | P_KPMS | P_TNC | P_PNC)));

		if (kp->kp_refcnt <= 0)
			panic("sfmmu_kpm_mapout: bad refcnt kp=%p", (void *)kp);

		if (--kp->kp_refcnt == 0) {
			/* remove go indication */
			if (kp->kp_refcntc == -1) {
				sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
				    &kpmp->khl_lock, KPMTSBM_STOP);
			}
			ASSERT(kp->kp_refcntc == 0);

			/* remove TSB entry */
			sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT4M);
#ifdef	DEBUG
			if (kpm_tlb_flush)
				sfmmu_kpm_demap_tlbs(vaddr);
#endif
		}

	} else {
		/*
		 * The VAC alias path.
		 * We come here if the kpm vaddr is not in any alias_range
		 * and we are unmapping a page within the regular kpm_page
		 * range. The kpm_page either holds conflict pages and/or
		 * is in "small page" mode. If the page is not marked
		 * P_KPMS it couldn't have a valid PAGESIZE sized TSB
		 * entry. Dcache flushing is done lazy and follows the
		 * rules of the regular virtual page coloring scheme.
		 *
		 * Per page states and required actions:
		 *   P_KPMC: remove a kpm mapping that is conflicting.
		 *   P_KPMS: remove a small kpm mapping within a kpm_page.
		 *   P_TNC:  check if we can re-cache the page.
		 *   P_PNC:  we cannot re-cache, sorry.
		 * Per kpm_page:
		 *   kp_refcntc > 0: page is part of a kpm_page with conflicts.
		 *   kp_refcnts > 0: rm a small mapped page within a kpm_page.
		 */

		if (PP_ISKPMS(pp)) {
			if (kp->kp_refcnts < 1) {
				panic("sfmmu_kpm_mapout: bad refcnts kp=%p",
				    (void *)kp);
			}
			sfmmu_kpm_demap_small(vaddr);

			/*
			 * Check if we can resume cached mode. This might
			 * be the case if the kpm mapping was the only
			 * mapping in conflict with other non rule
			 * compliant mappings. The page is no more marked
			 * as kpm mapped, so the conv_tnc path will not
			 * change kpm state.
			 */
			if (PP_ISTNC(pp))  {
				if (!PP_ISKPMC(pp)) {
					/*
					 * Uncached kpm mappings must always
					 * have forced "small page" mode.
					 */
					panic("sfmmu_kpm_mapout: uncached "
					    "page not kpm marked");
				}
				conv_tnc(pp, TTE8K);
			}
			kp->kp_refcnts--;
			kp->kp_refcnt++;
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMS(pp);
			sfmmu_page_exit(pmtx);
		}

		if (PP_ISKPMC(pp)) {
			if (kp->kp_refcntc < 1) {
				panic("sfmmu_kpm_mapout: bad refcntc kp=%p",
				    (void *)kp);
			}
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);
			kp->kp_refcntc--;
		}

		if (kp->kp_refcnt-- < 1)
			panic("sfmmu_kpm_mapout: bad refcnt kp=%p", (void *)kp);
	}
exit:
	mutex_exit(&kpmp->khl_mutex);
	return;

smallpages_mapout:
	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	if (PP_ISKPMC(pp) == 0) {
		oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag,
		    &kpmsp->kshl_lock, 0);

		if (oldval != KPM_MAPPEDS) {
			/*
			 * When we're called after sfmmu_kpm_hme_unload,
			 * KPM_MAPPEDSC is valid too.
			 */
			if (oldval != KPM_MAPPEDSC)
				panic("sfmmu_kpm_mapout: incorrect mapping");
		}

		/* remove TSB entry */
		sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT);
#ifdef	DEBUG
		if (kpm_tlb_flush)
			sfmmu_kpm_demap_tlbs(vaddr);
#endif

	} else if (PP_ISTNC(pp)) {
		oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag,
		    &kpmsp->kshl_lock, 0);

		if (oldval != KPM_MAPPEDSC || PP_ISKPMC(pp) == 0)
			panic("sfmmu_kpm_mapout: inconsistent TNC mapping");

		sfmmu_kpm_demap_small(vaddr);

		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMC(pp);
		sfmmu_page_exit(pmtx);

		/*
		 * Check if we can resume cached mode. This might be
		 * the case if the kpm mapping was the only mapping
		 * in conflict with other non rule compliant mappings.
		 * The page is no more marked as kpm mapped, so the
		 * conv_tnc path will not change the kpm state.
		 */
		conv_tnc(pp, TTE8K);

	} else {
		oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag,
		    &kpmsp->kshl_lock, 0);

		if (oldval != KPM_MAPPEDSC)
			panic("sfmmu_kpm_mapout: inconsistent mapping");

		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMC(pp);
		sfmmu_page_exit(pmtx);
	}
}

#define	abs(x)  ((x) < 0 ? -(x) : (x))

/*
 * Determine appropriate kpm mapping address and handle any kpm/hme
 * conflicts. Page mapping list and its vcolor parts must be protected.
 */
static caddr_t
sfmmu_kpm_getvaddr(page_t *pp, int *kpm_vac_rangep)
{
	int		vcolor, vcolor_pa;
	caddr_t		vaddr;
	uintptr_t	paddr;


	ASSERT(sfmmu_mlist_held(pp));

	paddr = ptob(pp->p_pagenum);
	vcolor_pa = addr_to_vcolor(paddr);

	if (pp->p_vnode && IS_SWAPFSVP(pp->p_vnode)) {
		vcolor = (PP_NEWPAGE(pp) || PP_ISNC(pp)) ?
		    vcolor_pa : PP_GET_VCOLOR(pp);
	} else {
		vcolor = addr_to_vcolor(pp->p_offset);
	}

	vaddr = kpm_vbase + paddr;
	*kpm_vac_rangep = 0;

	if (vcolor_pa != vcolor) {
		*kpm_vac_rangep = abs(vcolor - vcolor_pa);
		vaddr += ((uintptr_t)(vcolor - vcolor_pa) << MMU_PAGESHIFT);
		vaddr += (vcolor_pa > vcolor) ?
		    ((uintptr_t)vcolor_pa << kpm_size_shift) :
		    ((uintptr_t)(vcolor - vcolor_pa) << kpm_size_shift);

		ASSERT(!PP_ISMAPPED_LARGE(pp));
	}

	if (PP_ISNC(pp))
		return (vaddr);

	if (PP_NEWPAGE(pp)) {
		PP_SET_VCOLOR(pp, vcolor);
		return (vaddr);
	}

	if (PP_GET_VCOLOR(pp) == vcolor)
		return (vaddr);

	ASSERT(!PP_ISMAPPED_KPM(pp));
	sfmmu_kpm_vac_conflict(pp, vaddr);

	return (vaddr);
}

/*
 * VAC conflict state bit values.
 * The following defines are used to make the handling of the
 * various input states more concise. For that the kpm states
 * per kpm_page and per page are combined in a summary state.
 * Each single state has a corresponding bit value in the
 * summary state. These defines only apply for kpm large page
 * mappings. Within comments the abbreviations "kc, c, ks, s"
 * are used as short form of the actual state, e.g. "kc" for
 * "kp_refcntc > 0", etc.
 */
#define	KPM_KC	0x00000008	/* kpm_page: kp_refcntc > 0 */
#define	KPM_C	0x00000004	/* page: P_KPMC set */
#define	KPM_KS	0x00000002	/* kpm_page: kp_refcnts > 0 */
#define	KPM_S	0x00000001	/* page: P_KPMS set */

/*
 * Summary states used in sfmmu_kpm_fault (KPM_TSBM_*).
 * See also more detailed comments within in the sfmmu_kpm_fault switch.
 * Abbreviations used:
 * CONFL: VAC conflict(s) within a kpm_page.
 * MAPS:  Mapped small: Page mapped in using a regular page size kpm mapping.
 * RASM:  Re-assembling of a large page mapping possible.
 * RPLS:  Replace: TSB miss due to TSB replacement only.
 * BRKO:  Breakup Other: A large kpm mapping has to be broken because another
 *        page within the kpm_page is already involved in a VAC conflict.
 * BRKT:  Breakup This: A large kpm mapping has to be broken, this page is
 *        is involved in a VAC conflict.
 */
#define	KPM_TSBM_CONFL_GONE	(0)
#define	KPM_TSBM_MAPS_RASM	(KPM_KS)
#define	KPM_TSBM_RPLS_RASM	(KPM_KS | KPM_S)
#define	KPM_TSBM_MAPS_BRKO	(KPM_KC)
#define	KPM_TSBM_MAPS		(KPM_KC | KPM_KS)
#define	KPM_TSBM_RPLS		(KPM_KC | KPM_KS | KPM_S)
#define	KPM_TSBM_MAPS_BRKT	(KPM_KC | KPM_C)
#define	KPM_TSBM_MAPS_CONFL	(KPM_KC | KPM_C | KPM_KS)
#define	KPM_TSBM_RPLS_CONFL	(KPM_KC | KPM_C | KPM_KS | KPM_S)

/*
 * kpm fault handler for mappings with large page size.
 */
int
sfmmu_kpm_fault(caddr_t vaddr, struct memseg *mseg, page_t *pp)
{
	int		error;
	pgcnt_t		inx;
	kpm_page_t	*kp;
	tte_t		tte;
	pfn_t		pfn = pp->p_pagenum;
	kpm_hlk_t	*kpmp;
	kmutex_t	*pml;
	int		alias_range;
	int		uncached = 0;
	kmutex_t	*pmtx;
	int		badstate;
	uint_t		tsbmcase;

	alias_range = IS_KPM_ALIAS_RANGE(vaddr);

	inx = ptokpmp(kpmptop(ptokpmp(pfn)) - mseg->kpm_pbase);
	if (inx >= mseg->kpm_nkpmpgs) {
		cmn_err(CE_PANIC, "sfmmu_kpm_fault: kpm overflow in memseg "
		    "0x%p  pp 0x%p", (void *)mseg, (void *)pp);
	}

	kp = &mseg->kpm_pages[inx];
	kpmp = KPMP_HASH(kp);

	pml = sfmmu_mlist_enter(pp);

	if (!PP_ISMAPPED_KPM(pp)) {
		sfmmu_mlist_exit(pml);
		return (EFAULT);
	}

	mutex_enter(&kpmp->khl_mutex);

	if (alias_range) {
		ASSERT(!PP_ISMAPPED_LARGE(pp));
		if (kp->kp_refcnta > 0) {
			if (PP_ISKPMC(pp)) {
				pmtx = sfmmu_page_enter(pp);
				PP_CLRKPMC(pp);
				sfmmu_page_exit(pmtx);
			}
			/*
			 * Check for vcolor conflicts. Return here
			 * w/ either no conflict (fast path), removed hme
			 * mapping chains (unload conflict) or uncached
			 * (uncache conflict). VACaches are cleaned and
			 * p_vcolor and PP_TNC are set accordingly for the
			 * conflict cases.  Drop kpmp for uncache conflict
			 * cases since it will be grabbed within
			 * sfmmu_kpm_page_cache in case of an uncache
			 * conflict.
			 */
			mutex_exit(&kpmp->khl_mutex);
			sfmmu_kpm_vac_conflict(pp, vaddr);
			mutex_enter(&kpmp->khl_mutex);

			if (PP_ISNC(pp)) {
				uncached = 1;
				pmtx = sfmmu_page_enter(pp);
				PP_SETKPMC(pp);
				sfmmu_page_exit(pmtx);
			}
			goto smallexit;

		} else {
			/*
			 * We got a tsbmiss on a not active kpm_page range.
			 * Let segkpm_fault decide how to panic.
			 */
			error = EFAULT;
		}
		goto exit;
	}

	badstate = (kp->kp_refcnt < 0 || kp->kp_refcnts < 0);
	if (kp->kp_refcntc == -1) {
		/*
		 * We should come here only if trap level tsb miss
		 * handler is disabled.
		 */
		badstate |= (kp->kp_refcnt == 0 || kp->kp_refcnts > 0 ||
		    PP_ISKPMC(pp) || PP_ISKPMS(pp) || PP_ISNC(pp));

		if (badstate == 0)
			goto largeexit;
	}

	if (badstate || kp->kp_refcntc < 0)
		goto badstate_exit;

	/*
	 * Combine the per kpm_page and per page kpm VAC states to
	 * a summary state in order to make the kpm fault handling
	 * more concise.
	 */
	tsbmcase = (((kp->kp_refcntc > 0) ? KPM_KC : 0) |
	    ((kp->kp_refcnts > 0) ? KPM_KS : 0) |
	    (PP_ISKPMC(pp) ? KPM_C : 0) |
	    (PP_ISKPMS(pp) ? KPM_S : 0));

	switch (tsbmcase) {
	case KPM_TSBM_CONFL_GONE:		/* - - - - */
		/*
		 * That's fine, we either have no more vac conflict in
		 * this kpm page or someone raced in and has solved the
		 * vac conflict for us -- call sfmmu_kpm_vac_conflict
		 * to take care for correcting the vcolor and flushing
		 * the dcache if required.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (PP_ISNC(pp) || kp->kp_refcnt <= 0 ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault: inconsistent CONFL_GONE "
			    "state, pp=%p", (void *)pp);
		}
		goto largeexit;

	case KPM_TSBM_MAPS_RASM:		/* - - ks - */
		/*
		 * All conflicts in this kpm page are gone but there are
		 * already small mappings around, so we also map this
		 * page small. This could be the trigger case for a
		 * small mapping reaper, if this is really needed.
		 * For now fall thru to the KPM_TSBM_MAPS handling.
		 */

	case KPM_TSBM_MAPS:			/* kc - ks - */
		/*
		 * Large page mapping is already broken, this page is not
		 * conflicting, so map it small. Call sfmmu_kpm_vac_conflict
		 * to take care for correcting the vcolor and flushing
		 * the dcache if required.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (PP_ISNC(pp) || kp->kp_refcnt <= 0 ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault:  inconsistent MAPS state, "
			    "pp=%p", (void *)pp);
		}
		kp->kp_refcnt--;
		kp->kp_refcnts++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);
		goto smallexit;

	case KPM_TSBM_RPLS_RASM:		/* - - ks s */
		/*
		 * All conflicts in this kpm page are gone but this page
		 * is mapped small. This could be the trigger case for a
		 * small mapping reaper, if this is really needed.
		 * For now we drop it in small again. Fall thru to the
		 * KPM_TSBM_RPLS handling.
		 */

	case KPM_TSBM_RPLS:			/* kc - ks s */
		/*
		 * Large page mapping is already broken, this page is not
		 * conflicting but already mapped small, so drop it in
		 * small again.
		 */
		if (PP_ISNC(pp) ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault:  inconsistent RPLS state, "
			    "pp=%p", (void *)pp);
		}
		goto smallexit;

	case KPM_TSBM_MAPS_BRKO:		/* kc - - - */
		/*
		 * The kpm page where we live in is marked conflicting
		 * but this page is not conflicting. So we have to map it
		 * in small. Call sfmmu_kpm_vac_conflict to take care for
		 * correcting the vcolor and flushing the dcache if required.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (PP_ISNC(pp) || kp->kp_refcnt <= 0 ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault:  inconsistent MAPS_BRKO state, "
			    "pp=%p", (void *)pp);
		}
		kp->kp_refcnt--;
		kp->kp_refcnts++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);
		goto smallexit;

	case KPM_TSBM_MAPS_BRKT:		/* kc c - - */
	case KPM_TSBM_MAPS_CONFL:		/* kc c ks - */
		if (!PP_ISMAPPED(pp)) {
			/*
			 * We got a tsbmiss on kpm large page range that is
			 * marked to contain vac conflicting pages introduced
			 * by hme mappings. The hme mappings are all gone and
			 * must have bypassed the kpm alias prevention logic.
			 */
			panic("sfmmu_kpm_fault: stale VAC conflict, pp=%p",
			    (void *)pp);
		}

		/*
		 * Check for vcolor conflicts. Return here w/ either no
		 * conflict (fast path), removed hme mapping chains
		 * (unload conflict) or uncached (uncache conflict).
		 * Dcache is cleaned and p_vcolor and P_TNC are set
		 * accordingly. Drop kpmp for uncache conflict cases
		 * since it will be grabbed within sfmmu_kpm_page_cache
		 * in case of an uncache conflict.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (kp->kp_refcnt <= 0)
			panic("sfmmu_kpm_fault: bad refcnt kp=%p", (void *)kp);

		if (PP_ISNC(pp)) {
			uncached = 1;
		} else {
			/*
			 * When an unload conflict is solved and there are
			 * no other small mappings around, we can resume
			 * largepage mode. Otherwise we have to map or drop
			 * in small. This could be a trigger for a small
			 * mapping reaper when this was the last conflict
			 * within the kpm page and when there are only
			 * other small mappings around.
			 */
			ASSERT(addr_to_vcolor(vaddr) == PP_GET_VCOLOR(pp));
			ASSERT(kp->kp_refcntc > 0);
			kp->kp_refcntc--;
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);
			ASSERT(PP_ISKPMS(pp) == 0);
			if (kp->kp_refcntc == 0 && kp->kp_refcnts == 0)
				goto largeexit;
		}

		kp->kp_refcnt--;
		kp->kp_refcnts++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);
		goto smallexit;

	case KPM_TSBM_RPLS_CONFL:		/* kc c ks s */
		if (!PP_ISMAPPED(pp)) {
			/*
			 * We got a tsbmiss on kpm large page range that is
			 * marked to contain vac conflicting pages introduced
			 * by hme mappings. They are all gone and must have
			 * somehow bypassed the kpm alias prevention logic.
			 */
			panic("sfmmu_kpm_fault: stale VAC conflict, pp=%p",
			    (void *)pp);
		}

		/*
		 * This state is only possible for an uncached mapping.
		 */
		if (!PP_ISNC(pp)) {
			panic("sfmmu_kpm_fault: page not uncached, pp=%p",
			    (void *)pp);
		}
		uncached = 1;
		goto smallexit;

	default:
badstate_exit:
		panic("sfmmu_kpm_fault: inconsistent VAC state, vaddr=%p kp=%p "
		    "pp=%p", (void *)vaddr, (void *)kp, (void *)pp);
	}

smallexit:
	/* tte assembly */
	if (uncached == 0)
		KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
	else
		KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);

	/* tsb dropin */
	sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

	error = 0;
	goto exit;

largeexit:
	if (kp->kp_refcnt > 0) {

		/* tte assembly */
		KPM_TTE_VCACHED(tte.ll, pfn, TTE4M);

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT4M);

		if (kp->kp_refcntc == 0) {
			/* Set "go" flag for TL tsbmiss handler */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc, &kpmp->khl_lock,
			    KPMTSBM_START);
		}
		ASSERT(kp->kp_refcntc == -1);
		error = 0;

	} else
		error = EFAULT;
exit:
	mutex_exit(&kpmp->khl_mutex);
	sfmmu_mlist_exit(pml);
	return (error);
}

/*
 * kpm fault handler for mappings with small page size.
 */
int
sfmmu_kpm_fault_small(caddr_t vaddr, struct memseg *mseg, page_t *pp)
{
	int		error = 0;
	pgcnt_t		inx;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	kmutex_t	*pml;
	pfn_t		pfn = pp->p_pagenum;
	tte_t		tte;
	kmutex_t	*pmtx;
	int		oldval;

	inx = pfn - mseg->kpm_pbase;
	ksp = &mseg->kpm_spages[inx];
	kpmsp = KPMP_SHASH(ksp);

	pml = sfmmu_mlist_enter(pp);

	if (!PP_ISMAPPED_KPM(pp)) {
		sfmmu_mlist_exit(pml);
		return (EFAULT);
	}

	/*
	 * kp_mapped lookup protected by mlist mutex
	 */
	if (ksp->kp_mapped == KPM_MAPPEDS) {
		/*
		 * Fast path tsbmiss
		 */
		ASSERT(!PP_ISKPMC(pp));
		ASSERT(!PP_ISNC(pp));

		/* tte assembly */
		KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

	} else if (ksp->kp_mapped == KPM_MAPPEDSC) {
		/*
		 * Got here due to existing or gone kpm/hme VAC conflict.
		 * Recheck for vcolor conflicts. Return here w/ either
		 * no conflict, removed hme mapping chain (unload
		 * conflict) or uncached (uncache conflict). VACaches
		 * are cleaned and p_vcolor and PP_TNC are set accordingly
		 * for the conflict cases.
		 */
		sfmmu_kpm_vac_conflict(pp, vaddr);

		if (PP_ISNC(pp)) {
			/* ASSERT(pp->p_share); XXX use hat_page_getshare */

			/* tte assembly */
			KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);

			/* tsb dropin */
			sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

			oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag,
			    &kpmsp->kshl_lock, (KPM_MAPPED_GO | KPM_MAPPEDSC));

			if (oldval != KPM_MAPPEDSC)
				panic("sfmmu_kpm_fault_small: "
				    "stale smallpages mapping");
		} else {
			if (PP_ISKPMC(pp)) {
				pmtx = sfmmu_page_enter(pp);
				PP_CLRKPMC(pp);
				sfmmu_page_exit(pmtx);
			}

			/* tte assembly */
			KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);

			/* tsb dropin */
			sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

			oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag,
			    &kpmsp->kshl_lock, (KPM_MAPPED_GO | KPM_MAPPEDS));

			if (oldval != KPM_MAPPEDSC)
				panic("sfmmu_kpm_fault_small: "
				    "stale smallpages mapping");
		}

	} else {
		/*
		 * We got a tsbmiss on a not active kpm_page range.
		 * Let decide segkpm_fault how to panic.
		 */
		error = EFAULT;
	}

	sfmmu_mlist_exit(pml);
	return (error);
}

/*
 * Check/handle potential hme/kpm mapping conflicts
 */
static void
sfmmu_kpm_vac_conflict(page_t *pp, caddr_t vaddr)
{
	int		vcolor;
	struct sf_hment	*sfhmep;
	struct hat	*tmphat;
	struct sf_hment	*tmphme = NULL;
	struct hme_blk	*hmeblkp;
	tte_t		tte;

	ASSERT(sfmmu_mlist_held(pp));

	if (PP_ISNC(pp))
		return;

	vcolor = addr_to_vcolor(vaddr);
	if (PP_GET_VCOLOR(pp) == vcolor)
		return;

	/*
	 * There could be no vcolor conflict between a large cached
	 * hme page and a non alias range kpm page (neither large nor
	 * small mapped). So if a hme conflict already exists between
	 * a constituent page of a large hme mapping and a shared small
	 * conflicting hme mapping, both mappings must be already
	 * uncached at this point.
	 */
	ASSERT(!PP_ISMAPPED_LARGE(pp));

	if (!PP_ISMAPPED(pp)) {
		/*
		 * Previous hme user of page had a different color
		 * but since there are no current users
		 * we just flush the cache and change the color.
		 */
		SFMMU_STAT(sf_pgcolor_conflict);
		sfmmu_cache_flush(pp->p_pagenum, PP_GET_VCOLOR(pp));
		PP_SET_VCOLOR(pp, vcolor);
		return;
	}

	/*
	 * If we get here we have a vac conflict with a current hme
	 * mapping. This must have been established by forcing a wrong
	 * colored mapping, e.g. by using mmap(2) with MAP_FIXED.
	 */

	/*
	 * Check if any mapping is in same as or if it is locked
	 * since in that case we need to uncache.
	 */
	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = tmphme) {
		tmphme = sfhmep->hme_next;
		if (IS_PAHME(sfhmep))
			continue;
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		tmphat = hblktosfmmu(hmeblkp);
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		ASSERT(TTE_IS_VALID(&tte));
		if ((tmphat == ksfmmup) || hmeblkp->hblk_lckcnt) {
			/*
			 * We have an uncache conflict
			 */
			SFMMU_STAT(sf_uncache_conflict);
			sfmmu_page_cache_array(pp, HAT_TMPNC, CACHE_FLUSH, 1);
			return;
		}
	}

	/*
	 * We have an unload conflict
	 */
	SFMMU_STAT(sf_unload_conflict);

	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = tmphme) {
		tmphme = sfhmep->hme_next;
		if (IS_PAHME(sfhmep))
			continue;
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		(void) sfmmu_pageunload(pp, sfhmep, TTE8K);
	}

	/*
	 * Unloads only does tlb flushes so we need to flush the
	 * dcache vcolor here.
	 */
	sfmmu_cache_flush(pp->p_pagenum, PP_GET_VCOLOR(pp));
	PP_SET_VCOLOR(pp, vcolor);
}

/*
 * Remove all kpm mappings using kpme's for pp and check that
 * all kpm mappings (w/ and w/o kpme's) are gone.
 */
void
sfmmu_kpm_pageunload(page_t *pp)
{
	caddr_t		vaddr;
	struct kpme	*kpme, *nkpme;

	ASSERT(pp != NULL);
	ASSERT(pp->p_kpmref);
	ASSERT(sfmmu_mlist_held(pp));

	vaddr = hat_kpm_page2va(pp, 1);

	for (kpme = pp->p_kpmelist; kpme; kpme = nkpme) {
		ASSERT(kpme->kpe_page == pp);

		if (pp->p_kpmref == 0)
			panic("sfmmu_kpm_pageunload: stale p_kpmref pp=%p "
			    "kpme=%p", (void *)pp, (void *)kpme);

		nkpme = kpme->kpe_next;

		/* Add instance callback here here if needed later */
		sfmmu_kpme_sub(kpme, pp);
	}

	/*
	 * Also correct after mixed kpme/nonkpme mappings. If nonkpme
	 * segkpm clients have unlocked the page and forgot to mapout
	 * we panic here.
	 */
	if (pp->p_kpmref != 0)
		panic("sfmmu_kpm_pageunload: bad refcnt pp=%p", (void *)pp);

	sfmmu_kpm_mapout(pp, vaddr);
}

/*
 * Remove a large kpm mapping from kernel TSB and all TLB's.
 */
static void
sfmmu_kpm_demap_large(caddr_t vaddr)
{
	sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT4M);
	sfmmu_kpm_demap_tlbs(vaddr);
}

/*
 * Remove a small kpm mapping from kernel TSB and all TLB's.
 */
static void
sfmmu_kpm_demap_small(caddr_t vaddr)
{
	sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT);
	sfmmu_kpm_demap_tlbs(vaddr);
}

/*
 * Demap a kpm mapping in all TLB's.
 */
static void
sfmmu_kpm_demap_tlbs(caddr_t vaddr)
{
	cpuset_t cpuset;

	kpreempt_disable();
	cpuset = ksfmmup->sfmmu_cpusran;
	CPUSET_AND(cpuset, cpu_ready_set);
	CPUSET_DEL(cpuset, CPU->cpu_id);
	SFMMU_XCALL_STATS(ksfmmup);

	xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)vaddr,
	    (uint64_t)ksfmmup);
	vtag_flushpage(vaddr, (uint64_t)ksfmmup);

	kpreempt_enable();
}

/*
 * Summary states used in sfmmu_kpm_vac_unload (KPM_VUL__*).
 * See also more detailed comments within in the sfmmu_kpm_vac_unload switch.
 * Abbreviations used:
 * BIG:   Large page kpm mapping in use.
 * CONFL: VAC conflict(s) within a kpm_page.
 * INCR:  Count of conflicts within a kpm_page is going to be incremented.
 * DECR:  Count of conflicts within a kpm_page is going to be decremented.
 * UNMAP_SMALL: A small (regular page size) mapping is going to be unmapped.
 * TNC:   Temporary non cached: a kpm mapped page is mapped in TNC state.
 */
#define	KPM_VUL_BIG		(0)
#define	KPM_VUL_CONFL_INCR1	(KPM_KS)
#define	KPM_VUL_UNMAP_SMALL1	(KPM_KS | KPM_S)
#define	KPM_VUL_CONFL_INCR2	(KPM_KC)
#define	KPM_VUL_CONFL_INCR3	(KPM_KC | KPM_KS)
#define	KPM_VUL_UNMAP_SMALL2	(KPM_KC | KPM_KS | KPM_S)
#define	KPM_VUL_CONFL_DECR1	(KPM_KC | KPM_C)
#define	KPM_VUL_CONFL_DECR2	(KPM_KC | KPM_C | KPM_KS)
#define	KPM_VUL_TNC		(KPM_KC | KPM_C | KPM_KS | KPM_S)

/*
 * Handle VAC unload conflicts introduced by hme mappings or vice
 * versa when a hme conflict mapping is replaced by a non conflict
 * one. Perform actions and state transitions according to the
 * various page and kpm_page entry states. VACache flushes are in
 * the responsibiliy of the caller. We still hold the mlist lock.
 */
void
sfmmu_kpm_vac_unload(page_t *pp, caddr_t vaddr)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		kpmvaddr = hat_kpm_page2va(pp, 1);
	int		newcolor;
	kmutex_t	*pmtx;
	uint_t		vacunlcase;
	int		badstate = 0;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;

	ASSERT(PAGE_LOCKED(pp));
	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(!PP_ISNC(pp));

	newcolor = addr_to_vcolor(kpmvaddr) != addr_to_vcolor(vaddr);
	if (kpm_smallpages)
		goto smallpages_vac_unload;

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	if (IS_KPM_ALIAS_RANGE(kpmvaddr)) {
		if (kp->kp_refcnta < 1) {
			panic("sfmmu_kpm_vac_unload: bad refcnta kpm_page=%p\n",
			    (void *)kp);
		}

		if (PP_ISKPMC(pp) == 0) {
			if (newcolor == 0)
				goto exit;
			sfmmu_kpm_demap_small(kpmvaddr);
			pmtx = sfmmu_page_enter(pp);
			PP_SETKPMC(pp);
			sfmmu_page_exit(pmtx);

		} else if (newcolor == 0) {
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);

		} else {
			badstate++;
		}

		goto exit;
	}

	badstate = (kp->kp_refcnt < 0 || kp->kp_refcnts < 0);
	if (kp->kp_refcntc == -1) {
		/*
		 * We should come here only if trap level tsb miss
		 * handler is disabled.
		 */
		badstate |= (kp->kp_refcnt == 0 || kp->kp_refcnts > 0 ||
		    PP_ISKPMC(pp) || PP_ISKPMS(pp) || PP_ISNC(pp));
	} else {
		badstate |= (kp->kp_refcntc < 0);
	}

	if (badstate)
		goto exit;

	if (PP_ISKPMC(pp) == 0 && newcolor == 0) {
		ASSERT(PP_ISKPMS(pp) == 0);
		goto exit;
	}

	/*
	 * Combine the per kpm_page and per page kpm VAC states
	 * to a summary state in order to make the vac unload
	 * handling more concise.
	 */
	vacunlcase = (((kp->kp_refcntc > 0) ? KPM_KC : 0) |
	    ((kp->kp_refcnts > 0) ? KPM_KS : 0) |
	    (PP_ISKPMC(pp) ? KPM_C : 0) |
	    (PP_ISKPMS(pp) ? KPM_S : 0));

	switch (vacunlcase) {
	case KPM_VUL_BIG:				/* - - - - */
		/*
		 * Have to breakup the large page mapping to be
		 * able to handle the conflicting hme vaddr.
		 */
		if (kp->kp_refcntc == -1) {
			/* remove go indication */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
			    &kpmp->khl_lock, KPMTSBM_STOP);
		}
		sfmmu_kpm_demap_large(kpmvaddr);

		ASSERT(kp->kp_refcntc == 0);
		kp->kp_refcntc++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_UNMAP_SMALL1:			/* -  - ks s */
	case KPM_VUL_UNMAP_SMALL2:			/* kc - ks s */
		/*
		 * New conflict w/ an active kpm page, actually mapped
		 * in by small TSB/TLB entries. Remove the mapping and
		 * update states.
		 */
		ASSERT(newcolor);
		sfmmu_kpm_demap_small(kpmvaddr);
		kp->kp_refcnts--;
		kp->kp_refcnt++;
		kp->kp_refcntc++;
		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMS(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_CONFL_INCR1:			/* -  - ks - */
	case KPM_VUL_CONFL_INCR2:			/* kc - -  - */
	case KPM_VUL_CONFL_INCR3:			/* kc - ks - */
		/*
		 * New conflict on a active kpm mapped page not yet in
		 * TSB/TLB. Mark page and increment the kpm_page conflict
		 * count.
		 */
		ASSERT(newcolor);
		kp->kp_refcntc++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_CONFL_DECR1:			/* kc c -  - */
	case KPM_VUL_CONFL_DECR2:			/* kc c ks - */
		/*
		 * A conflicting hme mapping is removed for an active
		 * kpm page not yet in TSB/TLB. Unmark page and decrement
		 * the kpm_page conflict count.
		 */
		ASSERT(newcolor == 0);
		kp->kp_refcntc--;
		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_TNC:				/* kc c ks s */
		cmn_err(CE_NOTE, "sfmmu_kpm_vac_unload: "
		    "page not in NC state");
		/* FALLTHRU */

	default:
		badstate++;
	}
exit:
	if (badstate) {
		panic("sfmmu_kpm_vac_unload: inconsistent VAC state, "
		    "kpmvaddr=%p kp=%p pp=%p",
		    (void *)kpmvaddr, (void *)kp, (void *)pp);
	}
	mutex_exit(&kpmp->khl_mutex);

	return;

smallpages_vac_unload:
	if (newcolor == 0)
		return;

	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	if (PP_ISKPMC(pp) == 0) {
		if (ksp->kp_mapped == KPM_MAPPEDS) {
			/*
			 * Stop TL tsbmiss handling
			 */
			(void) sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag,
			    &kpmsp->kshl_lock, KPM_MAPPEDSC);

			sfmmu_kpm_demap_small(kpmvaddr);

		} else if (ksp->kp_mapped != KPM_MAPPEDSC) {
			panic("sfmmu_kpm_vac_unload: inconsistent mapping");
		}

		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);

	} else {
		if (ksp->kp_mapped != KPM_MAPPEDSC)
			panic("sfmmu_kpm_vac_unload: inconsistent mapping");
	}
}

/*
 * Page is marked to be in VAC conflict to an existing kpm mapping
 * or is kpm mapped using only the regular pagesize. Called from
 * sfmmu_hblk_unload when a mlist is completely removed.
 */
void
sfmmu_kpm_hme_unload(page_t *pp)
{
	/* tte assembly */
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		vaddr;
	kmutex_t	*pmtx;
	uint_t		flags;
	kpm_spage_t	*ksp;

	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(PP_ISMAPPED_KPM(pp));

	flags = pp->p_nrm & (P_KPMC | P_KPMS);
	if (kpm_smallpages)
		goto smallpages_hme_unload;

	if (flags == (P_KPMC | P_KPMS)) {
		panic("sfmmu_kpm_hme_unload: page should be uncached");

	} else if (flags == P_KPMS) {
		/*
		 * Page mapped small but not involved in VAC conflict
		 */
		return;
	}

	vaddr = hat_kpm_page2va(pp, 1);

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	if (IS_KPM_ALIAS_RANGE(vaddr)) {
		if (kp->kp_refcnta < 1) {
			panic("sfmmu_kpm_hme_unload: bad refcnta kpm_page=%p\n",
			    (void *)kp);
		}
	} else {
		if (kp->kp_refcntc < 1) {
			panic("sfmmu_kpm_hme_unload: bad refcntc kpm_page=%p\n",
			    (void *)kp);
		}
		kp->kp_refcntc--;
	}

	pmtx = sfmmu_page_enter(pp);
	PP_CLRKPMC(pp);
	sfmmu_page_exit(pmtx);

	mutex_exit(&kpmp->khl_mutex);
	return;

smallpages_hme_unload:
	if (flags != P_KPMC)
		panic("sfmmu_kpm_hme_unload: page should be uncached");

	vaddr = hat_kpm_page2va(pp, 1);
	PP2KPMSPG(pp, ksp);

	if (ksp->kp_mapped != KPM_MAPPEDSC)
		panic("sfmmu_kpm_hme_unload: inconsistent mapping");

	/*
	 * Keep KPM_MAPPEDSC until the next kpm tsbmiss where it
	 * prevents TL tsbmiss handling and force a hat_kpm_fault.
	 * There we can start over again.
	 */

	pmtx = sfmmu_page_enter(pp);
	PP_CLRKPMC(pp);
	sfmmu_page_exit(pmtx);
}

/*
 * Special hooks for sfmmu_page_cache_array() when changing the
 * cacheability of a page. It is used to obey the hat_kpm lock
 * ordering (mlist -> kpmp -> spl, and back).
 */
kpm_hlk_t *
sfmmu_kpm_kpmp_enter(page_t *pp, pgcnt_t npages)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;

	ASSERT(sfmmu_mlist_held(pp));

	if (kpm_smallpages || PP_ISMAPPED_KPM(pp) == 0)
		return (NULL);

	ASSERT(npages <= kpmpnpgs);

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	return (kpmp);
}

void
sfmmu_kpm_kpmp_exit(kpm_hlk_t *kpmp)
{
	if (kpm_smallpages || kpmp == NULL)
		return;

	mutex_exit(&kpmp->khl_mutex);
}

/*
 * Summary states used in sfmmu_kpm_page_cache (KPM_*).
 * See also more detailed comments within in the sfmmu_kpm_page_cache switch.
 * Abbreviations used:
 * UNC:     Input state for an uncache request.
 *   BIG:     Large page kpm mapping in use.
 *   SMALL:   Page has a small kpm mapping within a kpm_page range.
 *   NODEMAP: No demap needed.
 *   NOP:     No operation needed on this input state.
 * CACHE:   Input state for a re-cache request.
 *   MAPS:    Page is in TNC and kpm VAC conflict state and kpm mapped small.
 *   NOMAP:   Page is in TNC and kpm VAC conflict state, but not small kpm
 *            mapped.
 *   NOMAPO:  Page is in TNC and kpm VAC conflict state, but not small kpm
 *            mapped. There are also other small kpm mappings within this
 *            kpm_page.
 */
#define	KPM_UNC_BIG		(0)
#define	KPM_UNC_NODEMAP1	(KPM_KS)
#define	KPM_UNC_SMALL1		(KPM_KS | KPM_S)
#define	KPM_UNC_NODEMAP2	(KPM_KC)
#define	KPM_UNC_NODEMAP3	(KPM_KC | KPM_KS)
#define	KPM_UNC_SMALL2		(KPM_KC | KPM_KS | KPM_S)
#define	KPM_UNC_NOP1		(KPM_KC | KPM_C)
#define	KPM_UNC_NOP2		(KPM_KC | KPM_C | KPM_KS)
#define	KPM_CACHE_NOMAP		(KPM_KC | KPM_C)
#define	KPM_CACHE_NOMAPO	(KPM_KC | KPM_C | KPM_KS)
#define	KPM_CACHE_MAPS		(KPM_KC | KPM_C | KPM_KS | KPM_S)

/*
 * This function is called when the virtual cacheability of a page
 * is changed and the page has an actice kpm mapping. The mlist mutex,
 * the spl hash lock and the kpmp mutex (if needed) are already grabbed.
 */
/*ARGSUSED2*/
void
sfmmu_kpm_page_cache(page_t *pp, int flags, int cache_flush_tag)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		kpmvaddr;
	int		badstate = 0;
	uint_t		pgcacase;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	int		oldval;

	ASSERT(PP_ISMAPPED_KPM(pp));
	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(sfmmu_page_spl_held(pp));

	if (flags != HAT_TMPNC && flags != HAT_CACHE)
		panic("sfmmu_kpm_page_cache: bad flags");

	kpmvaddr = hat_kpm_page2va(pp, 1);

	if (flags == HAT_TMPNC && cache_flush_tag == CACHE_FLUSH) {
		pfn_t pfn = pp->p_pagenum;
		int vcolor = addr_to_vcolor(kpmvaddr);
		cpuset_t cpuset = cpu_ready_set;

		/* Flush vcolor in DCache */
		CPUSET_DEL(cpuset, CPU->cpu_id);
		SFMMU_XCALL_STATS(ksfmmup);
		xt_some(cpuset, vac_flushpage_tl1, pfn, vcolor);
		vac_flushpage(pfn, vcolor);
	}

	if (kpm_smallpages)
		goto smallpages_page_cache;

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	ASSERT(MUTEX_HELD(&kpmp->khl_mutex));

	if (IS_KPM_ALIAS_RANGE(kpmvaddr)) {
		if (kp->kp_refcnta < 1) {
			panic("sfmmu_kpm_page_cache: bad refcnta "
			    "kpm_page=%p\n", (void *)kp);
		}
		sfmmu_kpm_demap_small(kpmvaddr);
		if (flags == HAT_TMPNC) {
			PP_SETKPMC(pp);
			ASSERT(!PP_ISKPMS(pp));
		} else {
			ASSERT(PP_ISKPMC(pp));
			PP_CLRKPMC(pp);
		}
		goto exit;
	}

	badstate = (kp->kp_refcnt < 0 || kp->kp_refcnts < 0);
	if (kp->kp_refcntc == -1) {
		/*
		 * We should come here only if trap level tsb miss
		 * handler is disabled.
		 */
		badstate |= (kp->kp_refcnt == 0 || kp->kp_refcnts > 0 ||
		    PP_ISKPMC(pp) || PP_ISKPMS(pp) || PP_ISNC(pp));
	} else {
		badstate |= (kp->kp_refcntc < 0);
	}

	if (badstate)
		goto exit;

	/*
	 * Combine the per kpm_page and per page kpm VAC states to
	 * a summary state in order to make the VAC cache/uncache
	 * handling more concise.
	 */
	pgcacase = (((kp->kp_refcntc > 0) ? KPM_KC : 0) |
	    ((kp->kp_refcnts > 0) ? KPM_KS : 0) |
	    (PP_ISKPMC(pp) ? KPM_C : 0) |
	    (PP_ISKPMS(pp) ? KPM_S : 0));

	if (flags == HAT_CACHE) {
		switch (pgcacase) {
		case KPM_CACHE_MAPS:			/* kc c ks s */
			sfmmu_kpm_demap_small(kpmvaddr);
			if (kp->kp_refcnts < 1) {
				panic("sfmmu_kpm_page_cache: bad refcnts "
				"kpm_page=%p\n", (void *)kp);
			}
			kp->kp_refcnts--;
			kp->kp_refcnt++;
			PP_CLRKPMS(pp);
			/* FALLTHRU */

		case KPM_CACHE_NOMAP:			/* kc c -  - */
		case KPM_CACHE_NOMAPO:			/* kc c ks - */
			kp->kp_refcntc--;
			PP_CLRKPMC(pp);
			break;

		default:
			badstate++;
		}
		goto exit;
	}

	switch (pgcacase) {
	case KPM_UNC_BIG:				/* - - - - */
		if (kp->kp_refcnt < 1) {
			panic("sfmmu_kpm_page_cache: bad refcnt "
			    "kpm_page=%p\n", (void *)kp);
		}

		/*
		 * Have to breakup the large page mapping in preparation
		 * to the upcoming TNC mode handled by small mappings.
		 * The demap can already be done due to another conflict
		 * within the kpm_page.
		 */
		if (kp->kp_refcntc == -1) {
			/* remove go indication */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
			    &kpmp->khl_lock, KPMTSBM_STOP);
		}
		ASSERT(kp->kp_refcntc == 0);
		sfmmu_kpm_demap_large(kpmvaddr);
		kp->kp_refcntc++;
		PP_SETKPMC(pp);
		break;

	case KPM_UNC_SMALL1:				/* -  - ks s */
	case KPM_UNC_SMALL2:				/* kc - ks s */
		/*
		 * Have to demap an already small kpm mapping in preparation
		 * to the upcoming TNC mode. The demap can already be done
		 * due to another conflict within the kpm_page.
		 */
		sfmmu_kpm_demap_small(kpmvaddr);
		kp->kp_refcntc++;
		kp->kp_refcnts--;
		kp->kp_refcnt++;
		PP_CLRKPMS(pp);
		PP_SETKPMC(pp);
		break;

	case KPM_UNC_NODEMAP1:				/* -  - ks - */
		/* fallthru */

	case KPM_UNC_NODEMAP2:				/* kc - -  - */
	case KPM_UNC_NODEMAP3:				/* kc - ks - */
		kp->kp_refcntc++;
		PP_SETKPMC(pp);
		break;

	case KPM_UNC_NOP1:				/* kc c -  - */
	case KPM_UNC_NOP2:				/* kc c ks - */
		break;

	default:
		badstate++;
	}
exit:
	if (badstate) {
		panic("sfmmu_kpm_page_cache: inconsistent VAC state "
		    "kpmvaddr=%p kp=%p pp=%p", (void *)kpmvaddr,
		    (void *)kp, (void *)pp);
	}
	return;

smallpages_page_cache:
	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	/*
	 * marked as nogo for we will fault in and resolve it
	 * through sfmmu_kpm_fault_small
	 */
	oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped_flag, &kpmsp->kshl_lock,
	    KPM_MAPPEDSC);

	if (!(oldval == KPM_MAPPEDS || oldval == KPM_MAPPEDSC))
		panic("smallpages_page_cache: inconsistent mapping");

	sfmmu_kpm_demap_small(kpmvaddr);

	if (flags == HAT_TMPNC) {
		PP_SETKPMC(pp);
		ASSERT(!PP_ISKPMS(pp));

	} else {
		ASSERT(PP_ISKPMC(pp));
		PP_CLRKPMC(pp);
	}

	/*
	 * Keep KPM_MAPPEDSC until the next kpm tsbmiss where it
	 * prevents TL tsbmiss handling and force a hat_kpm_fault.
	 * There we can start over again.
	 */
}

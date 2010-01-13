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

/*
 * Kernel Physical Mapping (segkpm) hat interface routines for sun4v.
 */

#include <sys/types.h>
#include <vm/hat.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <sys/cmn_err.h>
#include <sys/machsystm.h>
#include <vm/seg_kpm.h>
#include <vm/mach_kpm.h>
#include <vm/faultcode.h>

extern pfn_t memseg_get_start(struct memseg *);

/*
 * Kernel Physical Mapping (kpm) facility
 */


void
mach_kpm_init()
{
	uintptr_t start, end;
	struct memlist  *pmem;

	/*
	 * Map each of the memsegs into the kpm segment, coalesing
	 * adjacent memsegs to allow mapping with the largest
	 * possible pages.
	 */
	pmem = phys_install;
	start = pmem->ml_address;
	end = start + pmem->ml_size;
	for (;;) {
		if (pmem == NULL || pmem->ml_address > end) {
			hat_devload(kas.a_hat, kpm_vbase + start,
			    end - start, mmu_btop(start),
			    PROT_READ | PROT_WRITE,
			    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
			if (pmem == NULL)
				break;
			start = pmem->ml_address;
		}
		end = pmem->ml_address + pmem->ml_size;
		pmem = pmem->ml_next;
	}
}

/* -- hat_kpm interface section -- */

/*
 * Mapin a locked page and return the vaddr.
 */
/*ARGSUSED*/
caddr_t
hat_kpm_mapin(struct page *pp, struct kpme *kpme)
{
	caddr_t		vaddr;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapin: kpm_enable not set");
		return ((caddr_t)NULL);
	}

	if (pp == NULL || PAGE_LOCKED(pp) == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapin: pp zero or not locked");
		return ((caddr_t)NULL);
	}

	vaddr = hat_kpm_page2va(pp, 1);

	return (vaddr);
}

/*
 * Mapout a locked page.
 */
/*ARGSUSED*/
void
hat_kpm_mapout(struct page *pp, struct kpme *kpme, caddr_t vaddr)
{
#ifdef DEBUG
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
#endif
}

/*
 * hat_kpm_mapin_pfn is used to obtain a kpm mapping for physical
 * memory addresses that are not described by a page_t.  It can
 * also be used for normal pages that are not locked, but beware
 * this is dangerous - no locking is performed, so the identity of
 * the page could change.  hat_kpm_mapin_pfn is not supported when
 * vac_colors > 1, because the chosen va depends on the page identity,
 * which could change.
 * The caller must only pass pfn's for valid physical addresses; violation
 * of this rule will cause panic.
 */
caddr_t
hat_kpm_mapin_pfn(pfn_t pfn)
{
	caddr_t paddr, vaddr;

	if (kpm_enable == 0)
		return ((caddr_t)NULL);

	paddr = (caddr_t)ptob(pfn);
	vaddr = (uintptr_t)kpm_vbase + paddr;

	return ((caddr_t)vaddr);
}

/*ARGSUSED*/
void
hat_kpm_mapout_pfn(pfn_t pfn)
{
	/* empty */
}

/*
 * Return the kpm virtual address for the page at pp.
 */
/*ARGSUSED*/
caddr_t
hat_kpm_page2va(struct page *pp, int checkswap)
{
	uintptr_t	paddr, vaddr;

	ASSERT(kpm_enable);

	paddr = ptob(pp->p_pagenum);

	vaddr = (uintptr_t)kpm_vbase + paddr;

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

/*
 * hat_kpm_fault is called from segkpm_fault when a kpm tsbmiss occurred.
 * This should never happen on sun4v.
 */
int
hat_kpm_fault(struct hat *hat, caddr_t vaddr)
{
	panic("pagefault in seg_kpm.  hat: 0x%p  vaddr: 0x%p",
	    (void *)hat, (void *)vaddr);

	return (0);
}

/*ARGSUSED*/
void
hat_kpm_mseghash_clear(int nentries)
{}

/*ARGSUSED*/
void
hat_kpm_mseghash_update(pgcnt_t inx, struct memseg *msp)
{}

/*ARGSUSED*/
void
hat_kpm_addmem_mseg_update(struct memseg *msp, pgcnt_t nkpmpgs,
	offset_t kpm_pages_off)
{
	pfn_t base, end;

	/*
	 * kphysm_add_memory_dynamic() does not set nkpmpgs
	 * when page_t memory is externally allocated.  That
	 * code must properly calculate nkpmpgs in all cases
	 * if nkpmpgs needs to be used at some point.
	 */

	/*
	 * The meta (page_t) pages for dynamically added memory are allocated
	 * either from the incoming memory itself or from existing memory.
	 * In the former case the base of the incoming pages will be different
	 * than the base of the dynamic segment so call memseg_get_start() to
	 * get the actual base of the incoming memory for each case.
	 */

	base = memseg_get_start(msp);
	end = msp->pages_end;

	hat_devload(kas.a_hat, kpm_vbase + mmu_ptob(base),
	    mmu_ptob(end - base), base, PROT_READ | PROT_WRITE,
	    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
}

/*
 * Return end of metadata for an already setup memseg.
 */
caddr_t
hat_kpm_mseg_reuse(struct memseg *msp)
{
	return ((caddr_t)msp->epages);
}

/*ARGSUSED*/
void
hat_kpm_addmem_mseg_insert(struct memseg *msp)
{}

/*ARGSUSED*/
void
hat_kpm_addmem_memsegs_update(struct memseg *msp)
{}

/*ARGSUSED*/
void
hat_kpm_delmem_mseg_update(struct memseg *msp, struct memseg **mspp)
{
	pfn_t base, end;

	/*
	 * The meta (page_t) pages for dynamically added memory are allocated
	 * either from the incoming memory itself or from existing memory.
	 * In the former case the base of the incoming pages will be different
	 * than the base of the dynamic segment so call memseg_get_start() to
	 * get the actual base of the incoming memory for each case.
	 */

	base = memseg_get_start(msp);
	end = msp->pages_end;

	hat_unload(kas.a_hat, kpm_vbase +  mmu_ptob(base), mmu_ptob(end - base),
	    HAT_UNLOAD | HAT_UNLOAD_UNLOCK | HAT_UNLOAD_UNMAP);
}

/*ARGSUSED*/
void
hat_kpm_split_mseg_update(struct memseg *msp, struct memseg **mspp,
	struct memseg *lo, struct memseg *mid, struct memseg *hi)
{}

/*
 * Walk the memsegs chain, applying func to each memseg span and vcolor.
 */
void
hat_kpm_walk(void (*func)(void *, void *, size_t), void *arg)
{
	pfn_t	pbase, pend;
	void	*base;
	size_t	size;
	struct memseg *msp;

	for (msp = memsegs; msp; msp = msp->next) {
		pbase = msp->pages_base;
		pend = msp->pages_end;
		base = ptob(pbase) + kpm_vbase;
		size = ptob(pend - pbase);
		func(arg, base, size);
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
	if (pp)
		return (pfn);
	else
		return ((pfn_t)PFN_INVALID);
}

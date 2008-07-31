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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	start = pmem->address;
	end = start + pmem->size;
	for (;;) {
		if (pmem == NULL || pmem->address > end) {
			hat_devload(kas.a_hat, kpm_vbase + start,
			    end - start, mmu_btop(start),
			    PROT_READ | PROT_WRITE,
			    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
			if (pmem == NULL)
				break;
			start = pmem->address;
		}
		end = pmem->address + pmem->size;
		pmem = pmem->next;
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
{}

/*ARGSUSED*/
void
hat_kpm_addmem_mseg_insert(struct memseg *msp)
{}

/*ARGSUSED*/
void
hat_kpm_addmem_memsegs_update(struct memseg *msp)
{}

/*ARGSUSED*/
caddr_t
hat_kpm_mseg_reuse(struct memseg *msp)
{
	return (0);
}

/*ARGSUSED*/
void
hat_kpm_delmem_mseg_update(struct memseg *msp, struct memseg **mspp)
{}

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

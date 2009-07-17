/*
 *
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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/vm.h>
#include <sys/mman.h>
#include <vm/vm_dep.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <sys/mem_config.h>
#include <sys/sysmacros.h>

extern pgcnt_t pp_dummy_npages;
extern pfn_t *pp_dummy_pfn;	/* Array of dummy pfns. */

extern kmutex_t memseg_lists_lock;
extern struct memseg *memseg_va_avail;
extern struct memseg *memseg_alloc();

extern page_t *ppvm_base;
extern pgcnt_t ppvm_size;

static vnode_t pp_vn, rsv_vn;
static pgcnt_t rsv_metapgs;
static int meta_rsv_enable;
static int sun4v_memseg_debug;

extern struct memseg *memseg_reuse(pgcnt_t);
extern void remap_to_dummy(caddr_t, pgcnt_t);

/*
 * The page_t memory for incoming pages is allocated from existing memory
 * which can create a potential situation where memory addition fails
 * because of shortage of existing memory.  To mitigate this situation
 * some memory is always reserved ahead of time for page_t allocation.
 * Each 4MB of reserved page_t's guarantees a 256MB (x64) addition without
 * page_t allocation.  The added 256MB added memory could theoretically
 * allow an addition of 16GB.
 */
#define	RSV_SIZE	0x40000000	/* add size with rsrvd page_t's 1G */

#ifdef	DEBUG
#define	MEMSEG_DEBUG(args...) if (sun4v_memseg_debug) printf(args)
#else
#define	MEMSEG_DEBUG(...)
#endif

/*
 * The page_t's for the incoming memory are allocated from
 * existing pages.
 */
/*ARGSUSED*/
int
memseg_alloc_meta(pfn_t base, pgcnt_t npgs, void **ptp, pgcnt_t *metap)
{
	page_t		*pp, *opp, *epp, *pgpp;
	pgcnt_t		metapgs;
	int		i, rsv;
	struct seg	kseg;
	caddr_t		vaddr;
	u_offset_t	off;

	/*
	 * Verify incoming memory is within supported DR range.
	 */
	if ((base + npgs) * sizeof (page_t) > ppvm_size)
		return (KPHYSM_ENOTSUP);

	opp = pp = ppvm_base + base;
	epp = pp + npgs;
	metapgs = btopr(npgs * sizeof (page_t));

	if (!IS_P2ALIGNED((uint64_t)pp, PAGESIZE) &&
	    page_find(&pp_vn, (u_offset_t)pp)) {
		/*
		 * Another memseg has page_t's in the same
		 * page which 'pp' resides.  This would happen
		 * if PAGESIZE is not an integral multiple of
		 * sizeof (page_t) and therefore 'pp'
		 * does not start on a page boundry.
		 *
		 * Since the other memseg's pages_t's still
		 * map valid pages, skip allocation of this page.
		 * Advance 'pp' to the next page which should
		 * belong only to the incoming memseg.
		 *
		 * If the last page_t in the current page
		 * crosses a page boundary, this should still
		 * work.  The first part of the page_t is
		 * already allocated.  The second part of
		 * the page_t will be allocated below.
		 */
		ASSERT(PAGESIZE % sizeof (page_t));
		pp = (page_t *)P2ROUNDUP((uint64_t)pp, PAGESIZE);
		metapgs--;
	}

	if (!IS_P2ALIGNED((uint64_t)epp, PAGESIZE) &&
	    page_find(&pp_vn, (u_offset_t)epp)) {
		/*
		 * Another memseg has page_t's in the same
		 * page which 'epp' resides.  This would happen
		 * if PAGESIZE is not an integral multiple of
		 * sizeof (page_t) and therefore 'epp'
		 * does not start on a page boundry.
		 *
		 * Since the other memseg's pages_t's still
		 * map valid pages, skip allocation of this page.
		 */
		ASSERT(PAGESIZE % sizeof (page_t));
		metapgs--;
	}

	ASSERT(IS_P2ALIGNED((uint64_t)pp, PAGESIZE));

	/*
	 * Back metadata space with physical pages.
	 */
	kseg.s_as = &kas;
	vaddr = (caddr_t)pp;

	for (i = 0; i < metapgs; i++)
		if (page_find(&pp_vn, (u_offset_t)(vaddr + i * PAGESIZE)))
			panic("page_find(0x%p, %p)\n",
			    (void *)&pp_vn, (void *)(vaddr + i * PAGESIZE));

	/*
	 * Allocate the metadata pages; these are the pages that will
	 * contain the page_t's for the incoming memory.
	 *
	 * If a normal allocation fails, use the reserved metapgs for
	 * a small allocation; otherwise retry with PG_WAIT.
	 */
	rsv = off = 0;
	if (metapgs <= rsv_metapgs) {
		MEMSEG_DEBUG("memseg_get: use rsv 0x%lx metapgs", metapgs);
		ASSERT(meta_rsv_enable);
		rsv = 1;
	} else if ((pgpp = page_create_va(&pp_vn, (u_offset_t)pp, ptob(metapgs),
	    PG_NORELOC | PG_EXCL, &kseg, vaddr)) == NULL) {
		cmn_err(CE_WARN, "memseg_get: can't get 0x%ld metapgs",
		    metapgs);
		return (KPHYSM_ERESOURCE);
	}
	if (rsv) {
		/*
		 * The reseve pages must be hashed out of the reserve vnode
		 * and rehashed by <pp_vn,vaddr>.  The resreved pages also
		 * must be replenished immedidately at the end of the add
		 * processing.
		 */
		for (i = 0; i < metapgs; i++) {
			pgpp = page_find(&rsv_vn, off);
			ASSERT(pgpp);
			page_hashout(pgpp, 0);
			hat_devload(kas.a_hat, vaddr, PAGESIZE,
			    page_pptonum(pgpp), PROT_READ | PROT_WRITE,
			    HAT_LOAD | HAT_LOAD_REMAP | HAT_LOAD_NOCONSIST);
			ASSERT(!page_find(&pp_vn, (u_offset_t)vaddr));
			if (!page_hashin(pgpp, &pp_vn, (u_offset_t)vaddr, 0))
				panic("memseg_get: page_hashin(0x%p, 0x%p)",
				    (void *)pgpp, (void *)vaddr);
			off += PAGESIZE;
			vaddr += PAGESIZE;
			rsv_metapgs--;
		}
	} else {
		for (i = 0; i < metapgs; i++) {
			hat_devload(kas.a_hat, vaddr, PAGESIZE,
			    page_pptonum(pgpp), PROT_READ | PROT_WRITE,
			    HAT_LOAD | HAT_LOAD_REMAP | HAT_LOAD_NOCONSIST);
			pgpp = pgpp->p_next;
			vaddr += PAGESIZE;
		}
	}

	ASSERT(ptp);
	ASSERT(metap);

	*ptp = (void *)opp;
	*metap = metapgs;

	return (KPHYSM_OK);
}

void
memseg_free_meta(void *ptp, pgcnt_t metapgs)
{
	int i;
	page_t *pp;
	u_offset_t off;

	if (!metapgs)
		return;

	off = (u_offset_t)ptp;

	ASSERT(off);
	ASSERT(IS_P2ALIGNED((uint64_t)off, PAGESIZE));

	MEMSEG_DEBUG("memseg_free_meta: off=0x%lx metapgs=0x%lx\n",
	    (uint64_t)off, metapgs);
	/*
	 * Free pages allocated during add.
	 */
	for (i = 0; i < metapgs; i++) {
		pp = page_find(&pp_vn, off);
		ASSERT(pp);
		ASSERT(pp->p_szc == 0);
		page_io_unlock(pp);
		page_destroy(pp, 0);
		off += PAGESIZE;
	}
}

pfn_t
memseg_get_metapfn(void *ptp, pgcnt_t metapg)
{
	page_t *pp;
	u_offset_t off;

	off = (u_offset_t)ptp + ptob(metapg);

	ASSERT(off);
	ASSERT(IS_P2ALIGNED((uint64_t)off, PAGESIZE));

	pp = page_find(&pp_vn, off);
	ASSERT(pp);
	ASSERT(pp->p_szc == 0);
	ASSERT(pp->p_pagenum != PFN_INVALID);

	return (pp->p_pagenum);
}

/*
 * Remap a memseg's page_t's to dummy pages.  Skip the low/high
 * ends of the range if they are already in use.
 */
void
memseg_remap_meta(struct memseg *seg)
{
	int i;
	u_offset_t off;
	page_t *pp;
#if 0
	page_t *epp;
#endif
	pgcnt_t metapgs;

	metapgs = btopr(MSEG_NPAGES(seg) * sizeof (page_t));
	ASSERT(metapgs);
	pp = seg->pages;
	seg->pages_end = seg->pages_base;
#if 0
	epp = seg->epages;

	/*
	 * This code cannot be tested as the kernel does not compile
	 * when page_t size is changed.  It is left here as a starting
	 * point if the unaligned page_t size needs to be supported.
	 */

	if (!IS_P2ALIGNED((uint64_t)pp, PAGESIZE) &&
	    page_find(&pp_vn, (u_offset_t)(pp - 1)) && !page_deleted(pp - 1)) {
		/*
		 * Another memseg has page_t's in the same
		 * page which 'pp' resides.  This would happen
		 * if PAGESIZE is not an integral multiple of
		 * sizeof (page_t) and therefore 'seg->pages'
		 * does not start on a page boundry.
		 *
		 * Since the other memseg's pages_t's still
		 * map valid pages, skip remap of this page.
		 * Advance 'pp' to the next page which should
		 * belong only to the outgoing memseg.
		 *
		 * If the last page_t in the current page
		 * crosses a page boundary, this should still
		 * work.  The first part of the page_t is
		 * valid since memseg_lock_delete_all() has
		 * been called.  The second part of the page_t
		 * will be remapped to the corresponding
		 * dummy page below.
		 */
		ASSERT(PAGESIZE % sizeof (page_t));
		pp = (page_t *)P2ROUNDUP((uint64_t)pp, PAGESIZE);
		metapgs--;
	}

	if (!IS_P2ALIGNED((uint64_t)epp, PAGESIZE) &&
	    page_find(&pp_vn, (u_offset_t)epp) && !page_deleted(epp)) {
		/*
		 * Another memseg has page_t's in the same
		 * page which 'epp' resides.  This would happen
		 * if PAGESIZE is not an integral multiple of
		 * sizeof (page_t) and therefore 'seg->epages'
		 * does not start on a page boundry.
		 *
		 * Since the other memseg's pages_t's still
		 * map valid pages, skip remap of this page.
		 */
		ASSERT(PAGESIZE % sizeof (page_t));
		metapgs--;
	}
#endif
	ASSERT(IS_P2ALIGNED((uint64_t)pp, PAGESIZE));

	remap_to_dummy((caddr_t)pp, metapgs);

	off = (u_offset_t)pp;

	MEMSEG_DEBUG("memseg_remap: off=0x%lx metapgs=0x%lx\n", (uint64_t)off,
	    metapgs);
	/*
	 * Free pages allocated during add.
	 */
	for (i = 0; i < metapgs; i++) {
		pp = page_find(&pp_vn, off);
		ASSERT(pp);
		ASSERT(pp->p_szc == 0);
		page_io_unlock(pp);
		page_destroy(pp, 0);
		off += PAGESIZE;
	}
}

static void
rsv_alloc()
{
	int i;
	page_t *pp;
	pgcnt_t metapgs;
	u_offset_t off;
	struct seg kseg;

	kseg.s_as = &kas;

	/*
	 * Reserve enough page_t pages for an add request of
	 * RSV_SIZE bytes.
	 */
	metapgs = btopr(btop(RSV_SIZE) * sizeof (page_t)) - rsv_metapgs;

	for (i = off = 0; i < metapgs; i++, off += PAGESIZE) {
		(void) page_create_va(&rsv_vn, off, PAGESIZE,
		    PG_NORELOC | PG_WAIT, &kseg, 0);
		pp = page_find(&rsv_vn, off);
		ASSERT(pp);
		ASSERT(PAGE_EXCL(pp));
		page_iolock_init(pp);
		rsv_metapgs++;
	}
}

void
i_dr_mem_init(size_t *hint)
{
	if (meta_rsv_enable) {
		rsv_alloc();
		if (hint)
			*hint = RSV_SIZE;
	}
}

void
i_dr_mem_fini()
{
	int i;
	page_t *pp;
	u_offset_t off;

	for (i = off = 0; i < rsv_metapgs; i++, off += PAGESIZE) {
		if (pp = page_find(&rsv_vn, off)) {
			ASSERT(PAGE_EXCL(pp));
			page_destroy(pp, 0);
		}
		ASSERT(!page_find(&rsv_vn, off));
	}
	rsv_metapgs = 0;
}

void
i_dr_mem_update()
{
	rsv_alloc();
}

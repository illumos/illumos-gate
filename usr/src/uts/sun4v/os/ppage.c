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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/t_lock.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/hat_sfmmu.h>
#include <sys/debug.h>
#include <sys/cpu_module.h>

/*
 * A quick way to generate a cache consistent address to map in a page.
 * users: ppcopy, pagezero, /proc, dev/mem
 *
 * The ppmapin/ppmapout routines provide a quick way of generating a cache
 * consistent address by reserving a given amount of kernel address space.
 * The base is PPMAPBASE and its size is PPMAPSIZE.  This memory is divided
 * into x number of sets, where x is the number of colors for the virtual
 * cache. The number of colors is how many times a page can be mapped
 * simulatenously in the cache.  For direct map caches this translates to
 * the number of pages in the cache.
 * Each set will be assigned a group of virtual pages from the reserved memory
 * depending on its virtual color.
 * When trying to assign a virtual address we will find out the color for the
 * physical page in question (if applicable).  Then we will try to find an
 * available virtual page from the set of the appropiate color.
 */

#define	clsettoarray(color, set) ((color * nsets) + set)

int pp_slots = 4;		/* small default, tuned by cpu module */

/* tuned by cpu module, default is "safe" */
int pp_consistent_coloring = PPAGE_STORES_POLLUTE | PPAGE_LOADS_POLLUTE;

static caddr_t	ppmap_vaddrs[PPMAPSIZE / MMU_PAGESIZE];
static int	nsets;			/* number of sets */
static int	ppmap_pages;		/* generate align mask */
static int	ppmap_shift;		/* set selector */

#ifdef PPDEBUG
#define		MAXCOLORS	16	/* for debug only */
static int	ppalloc_noslot = 0;	/* # of allocations from kernelmap */
static int	align_hits[MAXCOLORS];
static int	pp_allocs;		/* # of ppmapin requests */
#endif /* PPDEBUG */

/*
 * There are only 64 TLB entries on spitfire, 16 on cheetah
 * (fully-associative TLB) so we allow the cpu module to tune the
 * number to use here via pp_slots.
 */
static struct ppmap_va {
	caddr_t	ppmap_slots[MAXPP_SLOTS];
} ppmap_va[NCPU];

void
ppmapinit(void)
{
	int color, nset, setsize;
	caddr_t va;

	ASSERT(pp_slots <= MAXPP_SLOTS);

	va = (caddr_t)PPMAPBASE;
	if (cache & CACHE_VAC) {
		int a;

		ppmap_pages = mmu_btop(shm_alignment);
		nsets = PPMAPSIZE / shm_alignment;
		setsize = shm_alignment;
		ppmap_shift = MMU_PAGESHIFT;
		a = ppmap_pages;
		while (a >>= 1)
			ppmap_shift++;
	} else {
		/*
		 * If we do not have a virtual indexed cache we simply
		 * have only one set containing all pages.
		 */
		ppmap_pages = 1;
		nsets = mmu_btop(PPMAPSIZE);
		setsize = MMU_PAGESIZE;
		ppmap_shift = MMU_PAGESHIFT;
	}
	for (color = 0; color < ppmap_pages; color++) {
		for (nset = 0; nset < nsets; nset++) {
			ppmap_vaddrs[clsettoarray(color, nset)] =
			    (caddr_t)((uintptr_t)va + (nset * setsize));
		}
		va += MMU_PAGESIZE;
	}
}

/*
 * Allocate a cache consistent virtual address to map a page, pp,
 * with protection, vprot; and map it in the MMU, using the most
 * efficient means possible.  The argument avoid is a virtual address
 * hint which when masked yields an offset into a virtual cache
 * that should be avoided when allocating an address to map in a
 * page.  An avoid arg of -1 means you don't care, for instance pagezero.
 *
 * machine dependent, depends on virtual address space layout,
 * understands that all kernel addresses have bit 31 set.
 *
 * NOTE: For sun4 platforms the meaning of the hint argument is opposite from
 * that found in other architectures.  In other architectures the hint
 * (called avoid) was used to ask ppmapin to NOT use the specified cache color.
 * This was used to avoid virtual cache trashing in the bcopy.  Unfortunately
 * in the case of a COW,  this later on caused a cache aliasing conflict.  In
 * sun4, the bcopy routine uses the block ld/st instructions so we don't have
 * to worry about virtual cache trashing.  Actually, by using the hint to choose
 * the right color we can almost guarantee a cache conflict will not occur.
 */

caddr_t
ppmapin(page_t *pp, uint_t vprot, caddr_t hint)
{
	int color, nset, index, start;
	caddr_t va;

#ifdef PPDEBUG
	pp_allocs++;
#endif /* PPDEBUG */
	if (cache & CACHE_VAC) {
		color = sfmmu_get_ppvcolor(pp);
		if (color == -1) {
			if ((intptr_t)hint != -1L) {
				color = addr_to_vcolor(hint);
			} else {
				color = addr_to_vcolor(mmu_ptob(pp->p_pagenum));
			}
		}

	} else {
		/*
		 * For physical caches, we can pick any address we want.
		 */
		color = 0;
	}

	start = color;
	do {
		for (nset = 0; nset < nsets; nset++) {
			index = clsettoarray(color, nset);
			va = ppmap_vaddrs[index];
			if (va != NULL) {
#ifdef PPDEBUG
				align_hits[color]++;
#endif /* PPDEBUG */
				if (casptr(&ppmap_vaddrs[index],
				    va, NULL) == va) {
					hat_memload(kas.a_hat, va, pp,
						vprot | HAT_NOSYNC,
						HAT_LOAD_LOCK);
					return (va);
				}
			}
		}
		/*
		 * first pick didn't succeed, try another
		 */
		if (++color == ppmap_pages)
			color = 0;
	} while (color != start);

#ifdef PPDEBUG
	ppalloc_noslot++;
#endif /* PPDEBUG */

	/*
	 * No free slots; get a random one from the kernel heap area.
	 */
	va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	hat_memload(kas.a_hat, va, pp, vprot | HAT_NOSYNC, HAT_LOAD_LOCK);

	return (va);

}

void
ppmapout(caddr_t va)
{
	int color, nset, index;

	if (va >= kernelheap && va < ekernelheap) {
		/*
		 * Space came from kernelmap, flush the page and
		 * return the space.
		 */
		hat_unload(kas.a_hat, va, PAGESIZE,
		    (HAT_UNLOAD_NOSYNC | HAT_UNLOAD_UNLOCK));
		vmem_free(heap_arena, va, PAGESIZE);
	} else {
		/*
		 * Space came from ppmap_vaddrs[], give it back.
		 */
		color = addr_to_vcolor(va);
		ASSERT((cache & CACHE_VAC)? (color < ppmap_pages) : 1);

		nset = ((uintptr_t)va >> ppmap_shift) & (nsets - 1);
		index = clsettoarray(color, nset);
		hat_unload(kas.a_hat, va, PAGESIZE,
		    (HAT_UNLOAD_NOSYNC | HAT_UNLOAD_UNLOCK));

		ASSERT(ppmap_vaddrs[index] == NULL);
		ppmap_vaddrs[index] = va;
	}
}

#ifdef DEBUG
#define	PP_STAT_ADD(stat)	(stat)++
uint_t pload, ploadfail;
uint_t ppzero, ppzero_short;
#else
#define	PP_STAT_ADD(stat)
#endif /* DEBUG */

static void
pp_unload_tlb(caddr_t *pslot, caddr_t va)
{
	ASSERT(*pslot == va);

	vtag_flushpage(va, KCONTEXT);
	*pslot = NULL;				/* release the slot */
}

/*
 * Routine to copy kernel pages during relocation.  It will copy one
 * PAGESIZE page to another PAGESIZE page.  This function may be called
 * above LOCK_LEVEL so it should not grab any locks.
 */
void
ppcopy_kernel__relocatable(page_t *fm_pp, page_t *to_pp)
{
	uint64_t fm_pa, to_pa;
	size_t nbytes;

	fm_pa = (uint64_t)(fm_pp->p_pagenum) << MMU_PAGESHIFT;
	to_pa = (uint64_t)(to_pp->p_pagenum) << MMU_PAGESHIFT;

	nbytes = MMU_PAGESIZE;

	for (; nbytes > 0; fm_pa += 32, to_pa += 32, nbytes -= 32)
		hw_pa_bcopy32(fm_pa, to_pa);
}

/*
 * Copy the data from the physical page represented by "frompp" to
 * that represented by "topp".
 *
 * Try to use per cpu mapping first, if that fails then call pp_mapin
 * to load it.
 */
void
ppcopy(page_t *fm_pp, page_t *to_pp)
{
	caddr_t fm_va;
	caddr_t to_va;
	boolean_t fast;

	ASSERT(PAGE_LOCKED(fm_pp));
	ASSERT(PAGE_LOCKED(to_pp));

	/*
	 * Try to map using KPM.  If it fails, fall back to
	 * ppmapin/ppmapout.
	 */
	if ((fm_va = hat_kpm_mapin(fm_pp, NULL)) == NULL ||
	    (to_va = hat_kpm_mapin(to_pp, NULL)) == NULL) {
		if (fm_va != NULL)
			hat_kpm_mapout(fm_pp, NULL, fm_va);
		fm_va = ppmapin(fm_pp, PROT_READ, (caddr_t)-1);
		to_va = ppmapin(to_pp, PROT_READ | PROT_WRITE, fm_va);
		fast = B_FALSE;
	} else
		fast = B_TRUE;

	bcopy(fm_va, to_va, PAGESIZE);

	/* Unmap */
	if (fast) {
		hat_kpm_mapout(fm_pp, NULL, fm_va);
		hat_kpm_mapout(to_pp, NULL, to_va);
	} else {
		ppmapout(fm_va);
		ppmapout(to_va);
	}
}

/*
 * Zero the physical page from off to off + len given by `pp'
 * without changing the reference and modified bits of page.
 *
 * Again, we'll try per cpu mapping first.
 */

void
pagezero(page_t *pp, uint_t off, uint_t len)
{
	caddr_t va;
	extern int hwblkclr(void *, size_t);
	extern int use_hw_bzero;
	boolean_t fast;

	ASSERT((int)len > 0 && (int)off >= 0 && off + len <= PAGESIZE);
	ASSERT(PAGE_LOCKED(pp));

	PP_STAT_ADD(ppzero);

	if (len != MMU_PAGESIZE || !use_hw_bzero) {
		PP_STAT_ADD(ppzero_short);
	}

	kpreempt_disable();

	/*
	 * Try to use KPM.  If that fails, fall back to
	 * ppmapin/ppmapout.
	 */
	fast = B_TRUE;
	va = hat_kpm_mapin(pp, NULL);
	if (va == NULL) {
		fast = B_FALSE;
		va = ppmapin(pp, PROT_READ | PROT_WRITE, (caddr_t)-1);
	}

	if (!use_hw_bzero) {
		bzero(va + off, len);
		sync_icache(va + off, len);
	} else if (hwblkclr(va + off, len)) {
		/*
		 * We may not have used block commit asi.
		 * So flush the I-$ manually
		 */
		sync_icache(va + off, len);
	} else {
		/*
		 * We have used blk commit, and flushed the I-$.
		 * However we still may have an instruction in the
		 * pipeline. Only a flush will invalidate that.
		 */
		doflush(va);
	}

	if (fast) {
		hat_kpm_mapout(pp, NULL, va);
	} else {
		ppmapout(va);
	}
	kpreempt_enable();
}

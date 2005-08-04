/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * UNIX machine dependent virtual memory support.
 */

#include <sys/vm.h>
#include <sys/exec.h>
#include <sys/cmn_err.h>
#include <sys/cpu_module.h>
#include <sys/cpu.h>
#include <sys/elf_SPARC.h>
#include <sys/archsystm.h>
#include <vm/hat_sfmmu.h>
#include <sys/memnode.h>
#include <sys/mem_cage.h>
#include <vm/vm_dep.h>
#include <sys/error.h>
#include <sys/machsystm.h>
#include <vm/seg_kmem.h>

uint_t page_colors = 0;
uint_t page_colors_mask = 0;
uint_t page_coloring_shift = 0;
int consistent_coloring;

uint_t mmu_page_sizes = MMU_PAGE_SIZES;
uint_t max_mmu_page_sizes = MMU_PAGE_SIZES;
uint_t mmu_hashcnt = MAX_HASHCNT;
uint_t max_mmu_hashcnt = MAX_HASHCNT;
size_t mmu_ism_pagesize = DEFAULT_ISM_PAGESIZE;

/*
 * A bitmask of the page sizes supported by hardware based upon szc.
 * The base pagesize (p_szc == 0) must always be supported by the hardware.
 */
int mmu_exported_pagesize_mask;
uint_t mmu_exported_page_sizes;

uint_t szc_2_userszc[MMU_PAGE_SIZES];
uint_t userszc_2_szc[MMU_PAGE_SIZES];

extern uint_t vac_colors_mask;
extern int vac_shift;

hw_pagesize_t hw_page_array[] = {
	{MMU_PAGESIZE, MMU_PAGESHIFT, MMU_PAGESIZE >> MMU_PAGESHIFT},
	{MMU_PAGESIZE64K, MMU_PAGESHIFT64K, MMU_PAGESIZE64K >> MMU_PAGESHIFT},
	{MMU_PAGESIZE512K, MMU_PAGESHIFT512K,
	    MMU_PAGESIZE512K >> MMU_PAGESHIFT},
	{MMU_PAGESIZE4M, MMU_PAGESHIFT4M, MMU_PAGESIZE4M >> MMU_PAGESHIFT},
	{MMU_PAGESIZE32M, MMU_PAGESHIFT32M, MMU_PAGESIZE32M >> MMU_PAGESHIFT},
	{MMU_PAGESIZE256M, MMU_PAGESHIFT256M,
	    MMU_PAGESIZE256M >> MMU_PAGESHIFT},
	{0, 0, 0}
};

/*
 * Enable usage of 64k/4M pages for text and 64k pages for initdata for
 * all sun4v platforms. These variables can be overwritten by the platmod
 * or the CPU module. User can also change the setting via /etc/system.
 */

int	use_text_pgsz64k = 1;
int	use_text_pgsz4m = 1;
int	use_initdata_pgsz64k = 1;

/*
 * disable_text_largepages and disable_initdata_largepages bitmaks reflect
 * both unconfigured and undesirable page sizes. Current implementation
 * supports 64K and 4M page sizes for text and only 64K for data. Rest of
 * the page sizes are not currently supported, hence disabled below. In
 * future, when support is added for any other page size, it should be
 * reflected below.
 *
 * Note that these bitmask can be set in platform or CPU specific code to
 * disable page sizes that should not be used. These variables normally
 * shouldn't be changed via /etc/system.
 *
 * These bitmasks are also updated within hat_init to reflect unsupported
 * page sizes on a sun4v processor per mmu_exported_pagesize_mask global
 * variable.
 */

int disable_text_largepages =
	(1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M) | (1 << TTE2G) |
	(1 << TTE16G);
int disable_initdata_largepages =
	(1 << TTE512K) | (1 << TTE4M) | (1 << TTE32M) | (1 << TTE256M) |
	(1 << TTE2G) | (1 << TTE16G);

/*
 * Minimum segment size tunables before 64K or 4M large pages
 * should be used to map it.
 */
size_t text_pgsz64k_minsize = MMU_PAGESIZE64K;
size_t text_pgsz4m_minsize = MMU_PAGESIZE4M;
size_t initdata_pgsz64k_minsize = MMU_PAGESIZE64K;

/*
 * map_addr_proc() is the routine called when the system is to
 * choose an address for the user.  We will pick an address
 * range which is just below the current stack limit.  The
 * algorithm used for cache consistency on machines with virtual
 * address caches is such that offset 0 in the vnode is always
 * on a shm_alignment'ed aligned address.  Unfortunately, this
 * means that vnodes which are demand paged will not be mapped
 * cache consistently with the executable images.  When the
 * cache alignment for a given object is inconsistent, the
 * lower level code must manage the translations so that this
 * is not seen here (at the cost of efficiency, of course).
 *
 * addrp is a value/result parameter.
 *	On input it is a hint from the user to be used in a completely
 *	machine dependent fashion.  For MAP_ALIGN, addrp contains the
 *	minimal alignment.
 *
 *	On output it is NULL if no address can be found in the current
 *	processes address space or else an address that is currently
 *	not mapped for len bytes with a page of red zone on either side.
 *	If vacalign is true, then the selected address will obey the alignment
 *	constraints of a vac machine based on the given off value.
 */
/*ARGSUSED3*/
void
map_addr_proc(caddr_t *addrp, size_t len, offset_t off, int vacalign,
    caddr_t userlimit, struct proc *p, uint_t flags)
{
	struct as *as = p->p_as;
	caddr_t addr;
	caddr_t base;
	size_t slen;
	uintptr_t align_amount;
	int allow_largepage_alignment = 1;

	base = p->p_brkbase;
	if (userlimit < as->a_userlimit) {
		/*
		 * This happens when a program wants to map something in
		 * a range that's accessible to a program in a smaller
		 * address space.  For example, a 64-bit program might
		 * be calling mmap32(2) to guarantee that the returned
		 * address is below 4Gbytes.
		 */
		ASSERT(userlimit > base);
		slen = userlimit - base;
	} else {
		slen = p->p_usrstack - base - (((size_t)rctl_enforced_value(
		    rctlproc_legacy[RLIMIT_STACK], p->p_rctls, p) + PAGEOFFSET)
		    & PAGEMASK);
	}
	len = (len + PAGEOFFSET) & PAGEMASK;

	/*
	 * Redzone for each side of the request. This is done to leave
	 * one page unmapped between segments. This is not required, but
	 * it's useful for the user because if their program strays across
	 * a segment boundary, it will catch a fault immediately making
	 * debugging a little easier.
	 */
	len += (2 * PAGESIZE);

	/*
	 *  If the request is larger than the size of a particular
	 *  mmu level, then we use that level to map the request.
	 *  But this requires that both the virtual and the physical
	 *  addresses be aligned with respect to that level, so we
	 *  do the virtual bit of nastiness here.
	 *
	 *  For 32-bit processes, only those which have specified
	 *  MAP_ALIGN or an addr will be aligned on a page size > 4MB. Otherwise
	 *  we can potentially waste up to 256MB of the 4G process address
	 *  space just for alignment.
	 *
	 * XXXQ Should iterate trough hw_page_array here to catch
	 * all supported pagesizes
	 */
	if (p->p_model == DATAMODEL_ILP32 && ((flags & MAP_ALIGN) == 0 ||
	    ((uintptr_t)*addrp) != 0)) {
		allow_largepage_alignment = 0;
	}
	if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    allow_largepage_alignment &&
		(len >= MMU_PAGESIZE256M)) {	/* 256MB mappings */
		align_amount = MMU_PAGESIZE256M;
	} else if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    allow_largepage_alignment &&
		(len >= MMU_PAGESIZE32M)) {	/* 32MB mappings */
		align_amount = MMU_PAGESIZE32M;
	} else if (len >= MMU_PAGESIZE4M) {  /* 4MB mappings */
		align_amount = MMU_PAGESIZE4M;
	} else if (len >= MMU_PAGESIZE512K) { /* 512KB mappings */
		align_amount = MMU_PAGESIZE512K;
	} else if (len >= MMU_PAGESIZE64K) { /* 64KB mappings */
		align_amount = MMU_PAGESIZE64K;
	} else  {
		/*
		 * Align virtual addresses on a 64K boundary to ensure
		 * that ELF shared libraries are mapped with the appropriate
		 * alignment constraints by the run-time linker.
		 */
		align_amount = ELF_SPARC_MAXPGSZ;
		if ((flags & MAP_ALIGN) && ((uintptr_t)*addrp != 0) &&
			((uintptr_t)*addrp < align_amount))
			align_amount = (uintptr_t)*addrp;
	}

	/*
	 * 64-bit processes require 1024K alignment of ELF shared libraries.
	 */
	if (p->p_model == DATAMODEL_LP64)
		align_amount = MAX(align_amount, ELF_SPARCV9_MAXPGSZ);
#ifdef VAC
	if (vac && vacalign && (align_amount < shm_alignment))
		align_amount = shm_alignment;
#endif

	if ((flags & MAP_ALIGN) && ((uintptr_t)*addrp > align_amount)) {
		align_amount = (uintptr_t)*addrp;
	}
	len += align_amount;

	/*
	 * Look for a large enough hole starting below the stack limit.
	 * After finding it, use the upper part.  Addition of PAGESIZE is
	 * for the redzone as described above.
	 */
	as_purge(as);
	if (as_gap(as, len, &base, &slen, AH_HI, NULL) == 0) {
		caddr_t as_addr;

		addr = base + slen - len + PAGESIZE;
		as_addr = addr;
		/*
		 * Round address DOWN to the alignment amount,
		 * add the offset, and if this address is less
		 * than the original address, add alignment amount.
		 */
		addr = (caddr_t)((uintptr_t)addr & (~(align_amount - 1l)));
		addr += (long)(off & (align_amount - 1l));
		if (addr < as_addr) {
			addr += align_amount;
		}

		ASSERT(addr <= (as_addr + align_amount));
		ASSERT(((uintptr_t)addr & (align_amount - 1l)) ==
		    ((uintptr_t)(off & (align_amount - 1l))));
		*addrp = addr;

	} else {
		*addrp = NULL;	/* no more virtual space */
	}
}

/* Auto large page tunables. */
int auto_lpg_tlb_threshold = 32;
int auto_lpg_minszc = TTE64K;
int auto_lpg_maxszc = TTE256M;
size_t auto_lpg_heap_default = MMU_PAGESIZE64K;
size_t auto_lpg_stack_default = MMU_PAGESIZE64K;
size_t auto_lpg_va_default = MMU_PAGESIZE64K;
size_t auto_lpg_remap_threshold = 0; /* always remap */

size_t
map_pgsz(int maptype, struct proc *p, caddr_t addr, size_t len, int *remap)
{
	uint_t	n;
	size_t	pgsz = 0;

	if (remap)
		*remap = (len > auto_lpg_remap_threshold);

	switch (maptype) {
	case MAPPGSZ_ISM:
		n = hat_preferred_pgsz(p->p_as->a_hat, addr, len, maptype);
		pgsz = hw_page_array[n].hp_size;
		break;

	case MAPPGSZ_VA:
		n = hat_preferred_pgsz(p->p_as->a_hat, addr, len, maptype);
		pgsz = hw_page_array[n].hp_size;
		if ((pgsz <= MMU_PAGESIZE) ||
		    !IS_P2ALIGNED(addr, pgsz) || !IS_P2ALIGNED(len, pgsz))
			pgsz = map_pgszva(p, addr, len);
		break;

	case MAPPGSZ_STK:
		pgsz = map_pgszstk(p, addr, len);
		break;

	case MAPPGSZ_HEAP:
		pgsz = map_pgszheap(p, addr, len);
		break;
	}
	return (pgsz);
}

/*
 * Platform-dependent page scrub call.
 * We call hypervisor to scrub the page.
 */
void
pagescrub(page_t *pp, uint_t off, uint_t len)
{
	uint64_t pa, length;

	pa = (uint64_t)(pp->p_pagenum << MMU_PAGESHIFT + off);
	length = (uint64_t)len;

	(void) mem_scrub(pa, length);
}

void
sync_data_memory(caddr_t va, size_t len)
{
	/* Call memory sync function */
	mem_sync(va, len);
}

size_t
mmu_get_kernel_lpsize(size_t lpsize)
{
	extern int mmu_exported_pagesize_mask;
	uint_t tte;

	if (lpsize == 0) {
		/* no setting for segkmem_lpsize in /etc/system: use default */
		if (mmu_exported_pagesize_mask & (1 << TTE256M)) {
			lpsize = MMU_PAGESIZE256M;
		} else if (mmu_exported_pagesize_mask & (1 << TTE4M)) {
			lpsize = MMU_PAGESIZE4M;
		} else if (mmu_exported_pagesize_mask & (1 << TTE64K)) {
			lpsize = MMU_PAGESIZE64K;
		} else {
			lpsize = MMU_PAGESIZE;
		}

		return (lpsize);
	}

	for (tte = TTE8K; tte <= TTE256M; tte++) {

		if ((mmu_exported_pagesize_mask & (1 << tte)) == 0)
			continue;

		if (lpsize == TTEBYTES(tte))
			return (lpsize);
	}

	lpsize = TTEBYTES(TTE8K);
	return (lpsize);
}

void
mmu_init_kcontext()
{
}

/*ARGSUSED*/
void
mmu_init_kernel_pgsz(struct hat *hat)
{
}

#define	QUANTUM_SIZE	64

static	vmem_t	*contig_mem_slab_arena;
static	vmem_t	*contig_mem_arena;

uint_t contig_mem_slab_size = MMU_PAGESIZE4M;

static void *
contig_mem_span_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	page_t *ppl;
	page_t *rootpp;
	caddr_t addr = NULL;
	pgcnt_t npages = btopr(size);
	page_t **ppa;
	int pgflags;
	int i = 0;


	if ((addr = vmem_xalloc(vmp, size, size, 0, 0,
	    NULL, NULL, vmflag)) == NULL) {
		return (NULL);
	}

	/* If we ever don't want slab-sized pages, this will panic */
	ASSERT(((uintptr_t)addr & (contig_mem_slab_size - 1)) == 0);

	if (page_resv(npages, vmflag & VM_KMFLAGS) == 0) {
		vmem_xfree(vmp, addr, size);
		return (NULL);
	}

	pgflags = PG_EXCL;
	if ((vmflag & VM_NOSLEEP) == 0)
		pgflags |= PG_WAIT;
	if (vmflag & VM_PANIC)
		pgflags |= PG_PANIC;
	if (vmflag & VM_PUSHPAGE)
		pgflags |= PG_PUSHPAGE;

	ppl = page_create_va_large(&kvp, (u_offset_t)(uintptr_t)addr, size,
	    pgflags, &kvseg, addr, NULL);

	if (ppl == NULL) {
		vmem_xfree(vmp, addr, size);
		page_unresv(npages);
		return (NULL);
	}

	rootpp = ppl;
	ppa = kmem_zalloc(npages * sizeof (page_t *), KM_SLEEP);
	while (ppl != NULL) {
		page_t *pp = ppl;
		ppa[i++] = pp;
		page_sub(&ppl, pp);
		ASSERT(page_iolock_assert(pp));
		page_io_unlock(pp);
	}

	/*
	 * Load the locked entry.  It's OK to preload the entry into
	 * the TSB since we now support large mappings in the kernel TSB.
	 */
	hat_memload_array(kas.a_hat, (caddr_t)rootpp->p_offset, size,
	    ppa, (PROT_ALL & ~PROT_USER) | HAT_NOSYNC, HAT_LOAD_LOCK);

	for (--i; i >= 0; --i) {
		(void) page_pp_lock(ppa[i], 0, 1);
		page_unlock(ppa[i]);
	}

	kmem_free(ppa, npages * sizeof (page_t *));
	return (addr);
}

void
contig_mem_span_free(vmem_t *vmp, void *inaddr, size_t size)
{
	page_t *pp;
	caddr_t addr = inaddr;
	caddr_t eaddr;
	pgcnt_t npages = btopr(size);
	pgcnt_t pgs_left = npages;
	page_t *rootpp = NULL;

	ASSERT(((uintptr_t)addr & (contig_mem_slab_size - 1)) == 0);

	hat_unload(kas.a_hat, addr, size, HAT_UNLOAD_UNLOCK);

	for (eaddr = addr + size; addr < eaddr; addr += PAGESIZE) {
		pp = page_lookup(&kvp, (u_offset_t)(uintptr_t)addr, SE_EXCL);
		if (pp == NULL)
			panic("contig_mem_span_free: page not found");

		ASSERT(PAGE_EXCL(pp));
		page_pp_unlock(pp, 0, 1);

		if (rootpp == NULL)
			rootpp = pp;
		if (--pgs_left == 0) {
			/*
			 * similar logic to segspt_free_pages, but we know we
			 * have one large page.
			 */
			page_destroy_pages(rootpp);
		}
	}
	page_unresv(npages);

	if (vmp != NULL)
		vmem_xfree(vmp, inaddr, size);
}

static void *
contig_vmem_xalloc_aligned_wrapper(vmem_t *vmp, size_t size, int vmflag)
{
	return (vmem_xalloc(vmp, size, size, 0, 0, NULL, NULL, vmflag));
}

/*
 * conting_mem_alloc_align allocates real contiguous memory with the specified
 * alignment upto contig_mem_slab_size. The alignment must be a power of 2.
 */
void *
contig_mem_alloc_align(size_t size, size_t align)
{
	if ((align & (align - 1)) != 0)
		return (NULL);

	return (vmem_xalloc(contig_mem_arena, size, align, 0, 0,
	    NULL, NULL, VM_NOSLEEP));
}

/*
 * Allocates size aligned contiguous memory upto contig_mem_slab_size.
 * Size must be a power of 2.
 */
void *
contig_mem_alloc(size_t size)
{
	ASSERT((size & (size - 1)) == 0);
	return (contig_mem_alloc_align(size, size));
}

void
contig_mem_free(void *vaddr, size_t size)
{
	vmem_xfree(contig_mem_arena, vaddr, size);
}

/*
 * We create a set of stacked vmem arenas to enable us to
 * allocate large >PAGESIZE chucks of contiguous Real Address space
 * This is  what the Dynamics TSB support does for TSBs.
 * The contig_mem_arena import functions are exactly the same as the
 * TSB kmem_default arena import functions.
 */
void
contig_mem_init(void)
{

	contig_mem_slab_arena = vmem_create("contig_mem_slab_arena", NULL, 0,
	    contig_mem_slab_size, contig_vmem_xalloc_aligned_wrapper,
	    vmem_xfree, heap_arena, 0, VM_SLEEP);

	contig_mem_arena = vmem_create("contig_mem_arena", NULL, 0,
	    QUANTUM_SIZE, contig_mem_span_alloc, contig_mem_span_free,
	    contig_mem_slab_arena, 0, VM_SLEEP | VM_BESTFIT);

}

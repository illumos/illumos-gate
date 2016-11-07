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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

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
#include <sys/stack.h>
#include <sys/atomic.h>
#include <sys/promif.h>
#include <sys/random.h>

uint_t page_colors = 0;
uint_t page_colors_mask = 0;
uint_t page_coloring_shift = 0;
int consistent_coloring;
int update_proc_pgcolorbase_after_fork = 1;

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
	{MMU_PAGESIZE, MMU_PAGESHIFT, 0, MMU_PAGESIZE >> MMU_PAGESHIFT},
	{MMU_PAGESIZE64K, MMU_PAGESHIFT64K, 0,
	    MMU_PAGESIZE64K >> MMU_PAGESHIFT},
	{MMU_PAGESIZE512K, MMU_PAGESHIFT512K, 0,
	    MMU_PAGESIZE512K >> MMU_PAGESHIFT},
	{MMU_PAGESIZE4M, MMU_PAGESHIFT4M, 0, MMU_PAGESIZE4M >> MMU_PAGESHIFT},
	{MMU_PAGESIZE32M, MMU_PAGESHIFT32M, 0,
	    MMU_PAGESIZE32M >> MMU_PAGESHIFT},
	{MMU_PAGESIZE256M, MMU_PAGESHIFT256M, 0,
	    MMU_PAGESIZE256M >> MMU_PAGESHIFT},
	{0, 0, 0, 0}
};

/*
 * Maximum page size used to map 64-bit memory segment kmem64_base..kmem64_end
 */
int	max_bootlp_tteszc = TTE256M;

/*
 * Maximum and default segment size tunables for user heap, stack, private
 * and shared anonymous memory, and user text and initialized data.
 */
size_t max_uheap_lpsize = MMU_PAGESIZE64K;
size_t default_uheap_lpsize = MMU_PAGESIZE64K;
size_t max_ustack_lpsize = MMU_PAGESIZE64K;
size_t default_ustack_lpsize = MMU_PAGESIZE64K;
size_t max_privmap_lpsize = MMU_PAGESIZE64K;
size_t max_uidata_lpsize = MMU_PAGESIZE64K;
size_t max_utext_lpsize = MMU_PAGESIZE4M;
size_t max_shm_lpsize = MMU_PAGESIZE4M;

/*
 * Contiguous memory allocator data structures and variables.
 *
 * The sun4v kernel must provide a means to allocate physically
 * contiguous, non-relocatable memory. The contig_mem_arena
 * and contig_mem_slab_arena exist for this purpose. Allocations
 * that require physically contiguous non-relocatable memory should
 * be made using contig_mem_alloc() or contig_mem_alloc_align()
 * which return memory from contig_mem_arena or contig_mem_reloc_arena.
 * These arenas import memory from the contig_mem_slab_arena one
 * contiguous chunk at a time.
 *
 * When importing slabs, an attempt is made to allocate a large page
 * to use as backing. As a result of the non-relocatable requirement,
 * slabs are allocated from the kernel cage freelists. If the cage does
 * not contain any free contiguous chunks large enough to satisfy the
 * slab allocation, the slab size will be downsized and the operation
 * retried. Large slab sizes are tried first to minimize cage
 * fragmentation. If the slab allocation is unsuccessful still, the slab
 * is allocated from outside the kernel cage. This is undesirable because,
 * until slabs are freed, it results in non-relocatable chunks scattered
 * throughout physical memory.
 *
 * Allocations from the contig_mem_arena are backed by slabs from the
 * cage. Allocations from the contig_mem_reloc_arena are backed by
 * slabs allocated outside the cage. Slabs are left share locked while
 * in use to prevent non-cage slabs from being relocated.
 *
 * Since there is no guarantee that large pages will be available in
 * the kernel cage, contiguous memory is reserved and added to the
 * contig_mem_arena at boot time, making it available for later
 * contiguous memory allocations. This reserve will be used to satisfy
 * contig_mem allocations first and it is only when the reserve is
 * completely allocated that new slabs will need to be imported.
 */
static	vmem_t		*contig_mem_slab_arena;
static	vmem_t		*contig_mem_arena;
static	vmem_t		*contig_mem_reloc_arena;
static	kmutex_t	contig_mem_lock;
#define	CONTIG_MEM_ARENA_QUANTUM	64
#define	CONTIG_MEM_SLAB_ARENA_QUANTUM	MMU_PAGESIZE64K

/* contig_mem_arena import slab sizes, in decreasing size order */
static size_t contig_mem_import_sizes[] = {
	MMU_PAGESIZE4M,
	MMU_PAGESIZE512K,
	MMU_PAGESIZE64K
};
#define	NUM_IMPORT_SIZES	\
	(sizeof (contig_mem_import_sizes) / sizeof (size_t))
static size_t contig_mem_import_size_max	= MMU_PAGESIZE4M;
size_t contig_mem_slab_size			= MMU_PAGESIZE4M;

/* Boot-time allocated buffer to pre-populate the contig_mem_arena */
static size_t contig_mem_prealloc_size;
static void *contig_mem_prealloc_buf;

/*
 * The maximum amount a randomized mapping will be slewed.  We should perhaps
 * arrange things so these tunables can be separate for mmap, mmapobj, and
 * ld.so
 */
size_t aslr_max_map_skew = 256 * 1024 * 1024; /* 256MB */

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
 * Every mapping will have a redzone of a single page on either side of
 * the request. This is done to leave one page unmapped between segments.
 * This is not required, but it's useful for the user because if their
 * program strays across a segment boundary, it will catch a fault
 * immediately making debugging a little easier.  Currently the redzone
 * is mandatory.
 *
 * addrp is a value/result parameter.
 *	On input it is a hint from the user to be used in a completely
 *	machine dependent fashion.  For MAP_ALIGN, addrp contains the
 *	minimal alignment, which must be some "power of two" multiple of
 *	pagesize.
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
		slen = p->p_usrstack - base -
		    ((p->p_stk_ctl + PAGEOFFSET) & PAGEMASK);
	}
	/* Make len be a multiple of PAGESIZE */
	len = (len + PAGEOFFSET) & PAGEMASK;

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

	ASSERT(ISP2(align_amount));
	ASSERT(align_amount == 0 || align_amount >= PAGESIZE);

	/*
	 * Look for a large enough hole starting below the stack limit.
	 * After finding it, use the upper part.
	 */
	as_purge(as);
	off = off & (align_amount - 1);
	if (as_gap_aligned(as, len, &base, &slen, AH_HI, NULL, align_amount,
	    PAGESIZE, off) == 0) {
		caddr_t as_addr;

		/*
		 * addr is the highest possible address to use since we have
		 * a PAGESIZE redzone at the beginning and end.
		 */
		addr = base + slen - (PAGESIZE + len);
		as_addr = addr;
		/*
		 * Round address DOWN to the alignment amount and
		 * add the offset in.
		 * If addr is greater than as_addr, len would not be large
		 * enough to include the redzone, so we must adjust down
		 * by the alignment amount.
		 */
		addr = (caddr_t)((uintptr_t)addr & (~(align_amount - 1l)));
		addr += (long)off;
		if (addr > as_addr) {
			addr -= align_amount;
		}

		/*
		 * If randomization is requested, slew the allocation
		 * backwards, within the same gap, by a random amount.
		 */
		if (flags & _MAP_RANDOMIZE) {
			uint32_t slew;

			(void) random_get_pseudo_bytes((uint8_t *)&slew,
			    sizeof (slew));

			slew = slew % MIN(aslr_max_map_skew, (addr - base));
			addr -= P2ALIGN(slew, align_amount);
		}

		ASSERT(addr > base);
		ASSERT(addr + len < base + slen);
		ASSERT(((uintptr_t)addr & (align_amount - 1l)) ==
		    ((uintptr_t)(off)));
		*addrp = addr;

	} else {
		*addrp = NULL;	/* no more virtual space */
	}
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
	(void) mem_sync(va, len);
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

static void *
contig_mem_span_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	page_t *ppl;
	page_t *rootpp;
	caddr_t addr = NULL;
	pgcnt_t npages = btopr(size);
	page_t **ppa;
	int pgflags;
	spgcnt_t i = 0;


	ASSERT(size <= contig_mem_import_size_max);
	ASSERT((size & (size - 1)) == 0);

	if ((addr = vmem_xalloc(vmp, size, size, 0, 0,
	    NULL, NULL, vmflag)) == NULL) {
		return (NULL);
	}

	/* The address should be slab-size aligned. */
	ASSERT(((uintptr_t)addr & (size - 1)) == 0);

	if (page_resv(npages, vmflag & VM_KMFLAGS) == 0) {
		vmem_xfree(vmp, addr, size);
		return (NULL);
	}

	pgflags = PG_EXCL;
	if (vmflag & VM_NORELOC)
		pgflags |= PG_NORELOC;

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
		ASSERT(PAGE_EXCL(pp));
		page_io_unlock(pp);
	}

	/*
	 * Load the locked entry.  It's OK to preload the entry into
	 * the TSB since we now support large mappings in the kernel TSB.
	 */
	hat_memload_array(kas.a_hat, (caddr_t)rootpp->p_offset, size,
	    ppa, (PROT_ALL & ~PROT_USER) | HAT_NOSYNC, HAT_LOAD_LOCK);

	ASSERT(i == page_get_pagecnt(ppa[0]->p_szc));
	for (--i; i >= 0; --i) {
		ASSERT(ppa[i]->p_szc == ppa[0]->p_szc);
		ASSERT(page_pptonum(ppa[i]) == page_pptonum(ppa[0]) + i);
		(void) page_pp_lock(ppa[i], 0, 1);
		/*
		 * Leave the page share locked. For non-cage pages,
		 * this would prevent memory DR if it were supported
		 * on sun4v.
		 */
		page_downgrade(ppa[i]);
	}

	kmem_free(ppa, npages * sizeof (page_t *));
	return (addr);
}

/*
 * Allocates a slab by first trying to use the largest slab size
 * in contig_mem_import_sizes and then falling back to smaller slab
 * sizes still large enough for the allocation. The sizep argument
 * is a pointer to the requested size. When a slab is successfully
 * allocated, the slab size, which must be >= *sizep and <=
 * contig_mem_import_size_max, is returned in the *sizep argument.
 * Returns the virtual address of the new slab.
 */
static void *
span_alloc_downsize(vmem_t *vmp, size_t *sizep, size_t align, int vmflag)
{
	int i;

	ASSERT(*sizep <= contig_mem_import_size_max);

	for (i = 0; i < NUM_IMPORT_SIZES; i++) {
		size_t page_size = contig_mem_import_sizes[i];

		/*
		 * Check that the alignment is also less than the
		 * import (large page) size. In the case where the
		 * alignment is larger than the size, a large page
		 * large enough for the allocation is not necessarily
		 * physical-address aligned to satisfy the requested
		 * alignment. Since alignment is required to be a
		 * power-of-2, any large page >= size && >= align will
		 * suffice.
		 */
		if (*sizep <= page_size && align <= page_size) {
			void *addr;
			addr = contig_mem_span_alloc(vmp, page_size, vmflag);
			if (addr == NULL)
				continue;
			*sizep = page_size;
			return (addr);
		}
		return (NULL);
	}

	return (NULL);
}

static void *
contig_mem_span_xalloc(vmem_t *vmp, size_t *sizep, size_t align, int vmflag)
{
	return (span_alloc_downsize(vmp, sizep, align, vmflag | VM_NORELOC));
}

static void *
contig_mem_reloc_span_xalloc(vmem_t *vmp, size_t *sizep, size_t align,
    int vmflag)
{
	ASSERT((vmflag & VM_NORELOC) == 0);
	return (span_alloc_downsize(vmp, sizep, align, vmflag));
}

/*
 * Free a span, which is always exactly one large page.
 */
static void
contig_mem_span_free(vmem_t *vmp, void *inaddr, size_t size)
{
	page_t *pp;
	caddr_t addr = inaddr;
	caddr_t eaddr;
	pgcnt_t npages = btopr(size);
	page_t *rootpp = NULL;

	ASSERT(size <= contig_mem_import_size_max);
	/* All slabs should be size aligned */
	ASSERT(((uintptr_t)addr & (size - 1)) == 0);

	hat_unload(kas.a_hat, addr, size, HAT_UNLOAD_UNLOCK);

	for (eaddr = addr + size; addr < eaddr; addr += PAGESIZE) {
		pp = page_find(&kvp, (u_offset_t)(uintptr_t)addr);
		if (pp == NULL) {
			panic("contig_mem_span_free: page not found");
		}
		if (!page_tryupgrade(pp)) {
			page_unlock(pp);
			pp = page_lookup(&kvp,
			    (u_offset_t)(uintptr_t)addr, SE_EXCL);
			if (pp == NULL)
				panic("contig_mem_span_free: page not found");
		}

		ASSERT(PAGE_EXCL(pp));
		ASSERT(size == page_get_pagesize(pp->p_szc));
		ASSERT(rootpp == NULL || rootpp->p_szc == pp->p_szc);
		ASSERT(rootpp == NULL || (page_pptonum(rootpp) +
		    (pgcnt_t)btop(addr - (caddr_t)inaddr) == page_pptonum(pp)));

		page_pp_unlock(pp, 0, 1);

		if (rootpp == NULL)
			rootpp = pp;
	}
	page_destroy_pages(rootpp);
	page_unresv(npages);

	if (vmp != NULL)
		vmem_xfree(vmp, inaddr, size);
}

static void *
contig_vmem_xalloc_aligned_wrapper(vmem_t *vmp, size_t *sizep, size_t align,
    int vmflag)
{
	ASSERT((align & (align - 1)) == 0);
	return (vmem_xalloc(vmp, *sizep, align, 0, 0, NULL, NULL, vmflag));
}

/*
 * contig_mem_alloc, contig_mem_alloc_align
 *
 * Caution: contig_mem_alloc and contig_mem_alloc_align should be
 * used only when physically contiguous non-relocatable memory is
 * required. Furthermore, use of these allocation routines should be
 * minimized as well as should the allocation size. As described in the
 * contig_mem_arena comment block above, slab allocations fall back to
 * being outside of the cage. Therefore, overuse of these allocation
 * routines can lead to non-relocatable large pages being allocated
 * outside the cage. Such pages prevent the allocation of a larger page
 * occupying overlapping pages. This can impact performance for
 * applications that utilize e.g. 256M large pages.
 */

/*
 * Allocates size aligned contiguous memory up to contig_mem_import_size_max.
 * Size must be a power of 2.
 */
void *
contig_mem_alloc(size_t size)
{
	ASSERT((size & (size - 1)) == 0);
	return (contig_mem_alloc_align(size, size));
}

/*
 * contig_mem_alloc_align allocates real contiguous memory with the
 * specified alignment up to contig_mem_import_size_max. The alignment must
 * be a power of 2 and no greater than contig_mem_import_size_max. We assert
 * the aligment is a power of 2. For non-debug, vmem_xalloc will panic
 * for non power of 2 alignments.
 */
void *
contig_mem_alloc_align(size_t size, size_t align)
{
	void *buf;

	ASSERT(size <= contig_mem_import_size_max);
	ASSERT(align <= contig_mem_import_size_max);
	ASSERT((align & (align - 1)) == 0);

	if (align < CONTIG_MEM_ARENA_QUANTUM)
		align = CONTIG_MEM_ARENA_QUANTUM;

	/*
	 * We take the lock here to serialize span allocations.
	 * We do not lose concurrency for the common case, since
	 * allocations that don't require new span allocations
	 * are serialized by vmem_xalloc. Serializing span
	 * allocations also prevents us from trying to allocate
	 * more spans than necessary.
	 */
	mutex_enter(&contig_mem_lock);

	buf = vmem_xalloc(contig_mem_arena, size, align, 0, 0,
	    NULL, NULL, VM_NOSLEEP | VM_NORELOC);

	if ((buf == NULL) && (size <= MMU_PAGESIZE)) {
		mutex_exit(&contig_mem_lock);
		return (vmem_xalloc(static_alloc_arena, size, align, 0, 0,
		    NULL, NULL, VM_NOSLEEP));
	}

	if (buf == NULL) {
		buf = vmem_xalloc(contig_mem_reloc_arena, size, align, 0, 0,
		    NULL, NULL, VM_NOSLEEP);
	}

	mutex_exit(&contig_mem_lock);

	return (buf);
}

void
contig_mem_free(void *vaddr, size_t size)
{
	if (vmem_contains(contig_mem_arena, vaddr, size)) {
		vmem_xfree(contig_mem_arena, vaddr, size);
	} else if (size > MMU_PAGESIZE) {
		vmem_xfree(contig_mem_reloc_arena, vaddr, size);
	} else {
		vmem_xfree(static_alloc_arena, vaddr, size);
	}
}

/*
 * We create a set of stacked vmem arenas to enable us to
 * allocate large >PAGESIZE chucks of contiguous Real Address space.
 * The vmem_xcreate interface is used to create the contig_mem_arena
 * allowing the import routine to downsize the requested slab size
 * and return a smaller slab.
 */
void
contig_mem_init(void)
{
	mutex_init(&contig_mem_lock, NULL, MUTEX_DEFAULT, NULL);

	contig_mem_slab_arena = vmem_xcreate("contig_mem_slab_arena", NULL, 0,
	    CONTIG_MEM_SLAB_ARENA_QUANTUM, contig_vmem_xalloc_aligned_wrapper,
	    vmem_xfree, heap_arena, 0, VM_SLEEP | VMC_XALIGN);

	contig_mem_arena = vmem_xcreate("contig_mem_arena", NULL, 0,
	    CONTIG_MEM_ARENA_QUANTUM, contig_mem_span_xalloc,
	    contig_mem_span_free, contig_mem_slab_arena, 0,
	    VM_SLEEP | VM_BESTFIT | VMC_XALIGN);

	contig_mem_reloc_arena = vmem_xcreate("contig_mem_reloc_arena", NULL, 0,
	    CONTIG_MEM_ARENA_QUANTUM, contig_mem_reloc_span_xalloc,
	    contig_mem_span_free, contig_mem_slab_arena, 0,
	    VM_SLEEP | VM_BESTFIT | VMC_XALIGN);

	if (contig_mem_prealloc_buf == NULL || vmem_add(contig_mem_arena,
	    contig_mem_prealloc_buf, contig_mem_prealloc_size, VM_SLEEP)
	    == NULL) {
		cmn_err(CE_WARN, "Failed to pre-populate contig_mem_arena");
	}
}

/*
 * In calculating how much memory to pre-allocate, we include a small
 * amount per-CPU to account for per-CPU buffers in line with measured
 * values for different size systems. contig_mem_prealloc_base_size is
 * a cpu specific amount to be pre-allocated before considering per-CPU
 * requirements and memory size. We always pre-allocate a minimum amount
 * of memory determined by PREALLOC_MIN. Beyond that, we take the minimum
 * of contig_mem_prealloc_base_size and a small percentage of physical
 * memory to prevent allocating too much on smaller systems.
 * contig_mem_prealloc_base_size is global, allowing for the CPU module
 * to increase its value if necessary.
 */
#define	PREALLOC_PER_CPU	(256 * 1024)		/* 256K */
#define	PREALLOC_PERCENT	(4)			/* 4% */
#define	PREALLOC_MIN		(16 * 1024 * 1024)	/* 16M */
size_t contig_mem_prealloc_base_size = 0;

/*
 * Called at boot-time allowing pre-allocation of contiguous memory.
 * The argument 'alloc_base' is the requested base address for the
 * allocation and originates in startup_memlist.
 */
caddr_t
contig_mem_prealloc(caddr_t alloc_base, pgcnt_t npages)
{
	caddr_t	chunkp;

	contig_mem_prealloc_size = MIN((PREALLOC_PER_CPU * ncpu_guest_max) +
	    contig_mem_prealloc_base_size,
	    (ptob(npages) * PREALLOC_PERCENT) / 100);
	contig_mem_prealloc_size = MAX(contig_mem_prealloc_size, PREALLOC_MIN);
	contig_mem_prealloc_size = P2ROUNDUP(contig_mem_prealloc_size,
	    MMU_PAGESIZE4M);

	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, MMU_PAGESIZE4M);
	if (prom_alloc(alloc_base, contig_mem_prealloc_size,
	    MMU_PAGESIZE4M) != alloc_base) {

		/*
		 * Failed.  This may mean the physical memory has holes in it
		 * and it will be more difficult to get large contiguous
		 * pieces of memory.  Since we only guarantee contiguous
		 * pieces of memory contig_mem_import_size_max or smaller,
		 * loop, getting contig_mem_import_size_max at a time, until
		 * failure or contig_mem_prealloc_size is reached.
		 */
		for (chunkp = alloc_base;
		    (chunkp - alloc_base) < contig_mem_prealloc_size;
		    chunkp += contig_mem_import_size_max) {

			if (prom_alloc(chunkp, contig_mem_import_size_max,
			    MMU_PAGESIZE4M) != chunkp) {
				break;
			}
		}
		contig_mem_prealloc_size = chunkp - alloc_base;
		ASSERT(contig_mem_prealloc_size != 0);
	}

	if (contig_mem_prealloc_size != 0) {
		contig_mem_prealloc_buf = alloc_base;
	} else {
		contig_mem_prealloc_buf = NULL;
	}
	alloc_base += contig_mem_prealloc_size;

	return (alloc_base);
}

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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/tuneable.h>
#include <sys/systm.h>
#include <sys/vm.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/dumphdr.h>
#include <sys/bootconf.h>
#include <sys/lgrp.h>
#include <vm/seg_kmem.h>
#include <vm/hat.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#include <vm/faultcode.h>
#include <sys/promif.h>
#include <vm/seg_kp.h>
#include <sys/bitmap.h>
#include <sys/mem_cage.h>

#ifdef __sparc
#include <sys/ivintr.h>
#include <sys/panic.h>
#endif

/*
 * seg_kmem is the primary kernel memory segment driver.  It
 * maps the kernel heap [kernelheap, ekernelheap), module text,
 * and all memory which was allocated before the VM was initialized
 * into kas.
 *
 * Pages which belong to seg_kmem are hashed into &kvp vnode at
 * an offset equal to (u_offset_t)virt_addr, and have p_lckcnt >= 1.
 * They must never be paged out since segkmem_fault() is a no-op to
 * prevent recursive faults.
 *
 * Currently, seg_kmem pages are sharelocked (p_sharelock == 1) on
 * __x86 and are unlocked (p_sharelock == 0) on __sparc.  Once __x86
 * supports relocation the #ifdef kludges can be removed.
 *
 * seg_kmem pages may be subject to relocation by page_relocate(),
 * provided that the HAT supports it; if this is so, segkmem_reloc
 * will be set to a nonzero value. All boot time allocated memory as
 * well as static memory is considered off limits to relocation.
 * Pages are "relocatable" if p_state does not have P_NORELOC set, so
 * we request P_NORELOC pages for memory that isn't safe to relocate.
 *
 * The kernel heap is logically divided up into four pieces:
 *
 *   heap32_arena is for allocations that require 32-bit absolute
 *   virtual addresses (e.g. code that uses 32-bit pointers/offsets).
 *
 *   heap_core is for allocations that require 2GB *relative*
 *   offsets; in other words all memory from heap_core is within
 *   2GB of all other memory from the same arena. This is a requirement
 *   of the addressing modes of some processors in supervisor code.
 *
 *   heap_arena is the general heap arena.
 *
 *   static_arena is the static memory arena.  Allocations from it
 *   are not subject to relocation so it is safe to use the memory
 *   physical address as well as the virtual address (e.g. the VA to
 *   PA translations are static).  Caches may import from static_arena;
 *   all other static memory allocations should use static_alloc_arena.
 *
 * On some platforms which have limited virtual address space, seg_kmem
 * may share [kernelheap, ekernelheap) with seg_kp; if this is so,
 * segkp_bitmap is non-NULL, and each bit represents a page of virtual
 * address space which is actually seg_kp mapped.
 */

extern ulong_t *segkp_bitmap;   /* Is set if segkp is from the kernel heap */

char *kernelheap;		/* start of primary kernel heap */
char *ekernelheap;		/* end of primary kernel heap */
struct seg kvseg;		/* primary kernel heap segment */
struct seg kvseg_core;		/* "core" kernel heap segment */
struct seg kzioseg;		/* Segment for zio mappings */
vmem_t *heap_arena;		/* primary kernel heap arena */
vmem_t *heap_core_arena;	/* core kernel heap arena */
char *heap_core_base;		/* start of core kernel heap arena */
char *heap_lp_base;		/* start of kernel large page heap arena */
char *heap_lp_end;		/* end of kernel large page heap arena */
vmem_t *hat_memload_arena;	/* HAT translation data */
struct seg kvseg32;		/* 32-bit kernel heap segment */
vmem_t *heap32_arena;		/* 32-bit kernel heap arena */
vmem_t *heaptext_arena;		/* heaptext arena */
struct as kas;			/* kernel address space */
int segkmem_reloc;		/* enable/disable relocatable segkmem pages */
vmem_t *static_arena;		/* arena for caches to import static memory */
vmem_t *static_alloc_arena;	/* arena for allocating static memory */
vmem_t *zio_arena = NULL;	/* arena for allocating zio memory */
vmem_t *zio_alloc_arena = NULL;	/* arena for allocating zio memory */

/*
 * seg_kmem driver can map part of the kernel heap with large pages.
 * Currently this functionality is implemented for sparc platforms only.
 *
 * The large page size "segkmem_lpsize" for kernel heap is selected in the
 * platform specific code. It can also be modified via /etc/system file.
 * Setting segkmem_lpsize to PAGESIZE in /etc/system disables usage of large
 * pages for kernel heap. "segkmem_lpshift" is adjusted appropriately to
 * match segkmem_lpsize.
 *
 * At boot time we carve from kernel heap arena a range of virtual addresses
 * that will be used for large page mappings. This range [heap_lp_base,
 * heap_lp_end) is set up as a separate vmem arena - "heap_lp_arena". We also
 * create "kmem_lp_arena" that caches memory already backed up by large
 * pages. kmem_lp_arena imports virtual segments from heap_lp_arena.
 */

size_t	segkmem_lpsize;
static  uint_t	segkmem_lpshift = PAGESHIFT;
int	segkmem_lpszc = 0;

size_t  segkmem_kmemlp_quantum = 0x400000;	/* 4MB */
size_t  segkmem_heaplp_quantum;
vmem_t *heap_lp_arena;
static  vmem_t *kmem_lp_arena;
static  vmem_t *segkmem_ppa_arena;
static	segkmem_lpcb_t segkmem_lpcb;

/*
 * We use "segkmem_kmemlp_max" to limit the total amount of physical memory
 * consumed by the large page heap. By default this parameter is set to 1/8 of
 * physmem but can be adjusted through /etc/system either directly or
 * indirectly by setting "segkmem_kmemlp_pcnt" to the percent of physmem
 * we allow for large page heap.
 */
size_t  segkmem_kmemlp_max;
static  uint_t  segkmem_kmemlp_pcnt;

/*
 * Getting large pages for kernel heap could be problematic due to
 * physical memory fragmentation. That's why we allow to preallocate
 * "segkmem_kmemlp_min" bytes at boot time.
 */
static  size_t	segkmem_kmemlp_min;

/*
 * Throttling is used to avoid expensive tries to allocate large pages
 * for kernel heap when a lot of succesive attempts to do so fail.
 */
static  ulong_t segkmem_lpthrottle_max = 0x400000;
static  ulong_t segkmem_lpthrottle_start = 0x40;
static  ulong_t segkmem_use_lpthrottle = 1;

/*
 * Freed pages accumulate on a garbage list until segkmem is ready,
 * at which point we call segkmem_gc() to free it all.
 */
typedef struct segkmem_gc_list {
	struct segkmem_gc_list	*gc_next;
	vmem_t			*gc_arena;
	size_t			gc_size;
} segkmem_gc_list_t;

static segkmem_gc_list_t *segkmem_gc_list;

/*
 * Allocations from the hat_memload arena add VM_MEMLOAD to their
 * vmflags so that segkmem_xalloc() can inform the hat layer that it needs
 * to take steps to prevent infinite recursion.  HAT allocations also
 * must be non-relocatable to prevent recursive page faults.
 */
static void *
hat_memload_alloc(vmem_t *vmp, size_t size, int flags)
{
	flags |= (VM_MEMLOAD | VM_NORELOC);
	return (segkmem_alloc(vmp, size, flags));
}

/*
 * Allocations from static_arena arena (or any other arena that uses
 * segkmem_alloc_permanent()) require non-relocatable (permanently
 * wired) memory pages, since these pages are referenced by physical
 * as well as virtual address.
 */
void *
segkmem_alloc_permanent(vmem_t *vmp, size_t size, int flags)
{
	return (segkmem_alloc(vmp, size, flags | VM_NORELOC));
}

/*
 * Initialize kernel heap boundaries.
 */
void
kernelheap_init(
	void *heap_start,
	void *heap_end,
	char *first_avail,
	void *core_start,
	void *core_end)
{
	uintptr_t textbase;
	size_t core_size;
	size_t heap_size;
	vmem_t *heaptext_parent;
	size_t	heap_lp_size = 0;
#ifdef __sparc
	size_t kmem64_sz = kmem64_aligned_end - kmem64_base;
#endif	/* __sparc */

	kernelheap = heap_start;
	ekernelheap = heap_end;

#ifdef __sparc
	heap_lp_size = (((uintptr_t)heap_end - (uintptr_t)heap_start) / 4);
	/*
	 * Bias heap_lp start address by kmem64_sz to reduce collisions
	 * in 4M kernel TSB between kmem64 area and heap_lp
	 */
	kmem64_sz = P2ROUNDUP(kmem64_sz, MMU_PAGESIZE256M);
	if (kmem64_sz <= heap_lp_size / 2)
		heap_lp_size -= kmem64_sz;
	heap_lp_base = ekernelheap - heap_lp_size;
	heap_lp_end = heap_lp_base + heap_lp_size;
#endif	/* __sparc */

	/*
	 * If this platform has a 'core' heap area, then the space for
	 * overflow module text should be carved out of the end of that
	 * heap.  Otherwise, it gets carved out of the general purpose
	 * heap.
	 */
	core_size = (uintptr_t)core_end - (uintptr_t)core_start;
	if (core_size > 0) {
		ASSERT(core_size >= HEAPTEXT_SIZE);
		textbase = (uintptr_t)core_end - HEAPTEXT_SIZE;
		core_size -= HEAPTEXT_SIZE;
	}
#ifndef __sparc
	else {
		ekernelheap -= HEAPTEXT_SIZE;
		textbase = (uintptr_t)ekernelheap;
	}
#endif

	heap_size = (uintptr_t)ekernelheap - (uintptr_t)kernelheap;
	heap_arena = vmem_init("heap", kernelheap, heap_size, PAGESIZE,
	    segkmem_alloc, segkmem_free);

	if (core_size > 0) {
		heap_core_arena = vmem_create("heap_core", core_start,
		    core_size, PAGESIZE, NULL, NULL, NULL, 0, VM_SLEEP);
		heap_core_base = core_start;
	} else {
		heap_core_arena = heap_arena;
		heap_core_base = kernelheap;
	}

	/*
	 * reserve space for the large page heap. If large pages for kernel
	 * heap is enabled large page heap arean will be created later in the
	 * boot sequence in segkmem_heap_lp_init(). Otherwise the allocated
	 * range will be returned back to the heap_arena.
	 */
	if (heap_lp_size) {
		(void) vmem_xalloc(heap_arena, heap_lp_size, PAGESIZE, 0, 0,
		    heap_lp_base, heap_lp_end,
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
	}

	/*
	 * Remove the already-spoken-for memory range [kernelheap, first_avail).
	 */
	(void) vmem_xalloc(heap_arena, first_avail - kernelheap, PAGESIZE,
	    0, 0, kernelheap, first_avail, VM_NOSLEEP | VM_BESTFIT | VM_PANIC);

#ifdef __sparc
	heap32_arena = vmem_create("heap32", (void *)SYSBASE32,
	    SYSLIMIT32 - SYSBASE32 - HEAPTEXT_SIZE, PAGESIZE, NULL,
	    NULL, NULL, 0, VM_SLEEP);
	/*
	 * Prom claims the physical and virtual resources used by panicbuf
	 * and inter_vec_table. So reserve space for panicbuf, intr_vec_table,
	 * reserved interrupt vector data structures from 32-bit heap.
	 */
	(void) vmem_xalloc(heap32_arena, PANICBUFSIZE, PAGESIZE, 0, 0,
	    panicbuf, panicbuf + PANICBUFSIZE,
	    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);

	(void) vmem_xalloc(heap32_arena, IVSIZE, PAGESIZE, 0, 0,
	    intr_vec_table, (caddr_t)intr_vec_table + IVSIZE,
	    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);

	textbase = SYSLIMIT32 - HEAPTEXT_SIZE;
	heaptext_parent = NULL;
#else	/* __sparc */
	heap32_arena = heap_core_arena;
	heaptext_parent = heap_core_arena;
#endif	/* __sparc */

	heaptext_arena = vmem_create("heaptext", (void *)textbase,
	    HEAPTEXT_SIZE, PAGESIZE, NULL, NULL, heaptext_parent, 0, VM_SLEEP);

	/*
	 * Create a set of arenas for memory with static translations
	 * (e.g. VA -> PA translations cannot change).  Since using
	 * kernel pages by physical address implies it isn't safe to
	 * walk across page boundaries, the static_arena quantum must
	 * be PAGESIZE.  Any kmem caches that require static memory
	 * should source from static_arena, while direct allocations
	 * should only use static_alloc_arena.
	 */
	static_arena = vmem_create("static", NULL, 0, PAGESIZE,
	    segkmem_alloc_permanent, segkmem_free, heap_arena, 0, VM_SLEEP);
	static_alloc_arena = vmem_create("static_alloc", NULL, 0,
	    sizeof (uint64_t), vmem_alloc, vmem_free, static_arena,
	    0, VM_SLEEP);

	/*
	 * Create an arena for translation data (ptes, hmes, or hblks).
	 * We need an arena for this because hat_memload() is essential
	 * to vmem_populate() (see comments in common/os/vmem.c).
	 *
	 * Note: any kmem cache that allocates from hat_memload_arena
	 * must be created as a KMC_NOHASH cache (i.e. no external slab
	 * and bufctl structures to allocate) so that slab creation doesn't
	 * require anything more than a single vmem_alloc().
	 */
	hat_memload_arena = vmem_create("hat_memload", NULL, 0, PAGESIZE,
	    hat_memload_alloc, segkmem_free, heap_arena, 0,
	    VM_SLEEP | VMC_POPULATOR | VMC_DUMPSAFE);
}

void
boot_mapin(caddr_t addr, size_t size)
{
	caddr_t	 eaddr;
	page_t	*pp;
	pfn_t	 pfnum;

	if (page_resv(btop(size), KM_NOSLEEP) == 0)
		panic("boot_mapin: page_resv failed");

	for (eaddr = addr + size; addr < eaddr; addr += PAGESIZE) {
		pfnum = va_to_pfn(addr);
		if (pfnum == PFN_INVALID)
			continue;
		if ((pp = page_numtopp_nolock(pfnum)) == NULL)
			panic("boot_mapin(): No pp for pfnum = %lx", pfnum);

		/*
		 * must break up any large pages that may have constituent
		 * pages being utilized for BOP_ALLOC()'s before calling
		 * page_numtopp().The locking code (ie. page_reclaim())
		 * can't handle them
		 */
		if (pp->p_szc != 0)
			page_boot_demote(pp);

		pp = page_numtopp(pfnum, SE_EXCL);
		if (pp == NULL || PP_ISFREE(pp))
			panic("boot_alloc: pp is NULL or free");

		/*
		 * If the cage is on but doesn't yet contain this page,
		 * mark it as non-relocatable.
		 */
		if (kcage_on && !PP_ISNORELOC(pp)) {
			PP_SETNORELOC(pp);
			PLCNT_XFER_NORELOC(pp);
		}

		(void) page_hashin(pp, &kvp, (u_offset_t)(uintptr_t)addr, NULL);
		pp->p_lckcnt = 1;
#if defined(__x86)
		page_downgrade(pp);
#else
		page_unlock(pp);
#endif
	}
}

/*
 * Get pages from boot and hash them into the kernel's vp.
 * Used after page structs have been allocated, but before segkmem is ready.
 */
void *
boot_alloc(void *inaddr, size_t size, uint_t align)
{
	caddr_t addr = inaddr;

	if (bootops == NULL)
		prom_panic("boot_alloc: attempt to allocate memory after "
		    "BOP_GONE");

	size = ptob(btopr(size));
#ifdef __sparc
	if (bop_alloc_chunk(addr, size, align) != (caddr_t)addr)
		panic("boot_alloc: bop_alloc_chunk failed");
#else
	if (BOP_ALLOC(bootops, addr, size, align) != addr)
		panic("boot_alloc: BOP_ALLOC failed");
#endif
	boot_mapin((caddr_t)addr, size);
	return (addr);
}

static void
segkmem_badop()
{
	panic("segkmem_badop");
}

#define	SEGKMEM_BADOP(t)	(t(*)())segkmem_badop

/*ARGSUSED*/
static faultcode_t
segkmem_fault(struct hat *hat, struct seg *seg, caddr_t addr, size_t size,
	enum fault_type type, enum seg_rw rw)
{
	pgcnt_t npages;
	spgcnt_t pg;
	page_t *pp;
	struct vnode *vp = seg->s_data;

	ASSERT(RW_READ_HELD(&seg->s_as->a_lock));

	if (seg->s_as != &kas || size > seg->s_size ||
	    addr < seg->s_base || addr + size > seg->s_base + seg->s_size)
		panic("segkmem_fault: bad args");

	/*
	 * If it is one of segkp pages, call segkp_fault.
	 */
	if (segkp_bitmap && seg == &kvseg &&
	    BT_TEST(segkp_bitmap, btop((uintptr_t)(addr - seg->s_base))))
		return (SEGOP_FAULT(hat, segkp, addr, size, type, rw));

	if (rw != S_READ && rw != S_WRITE && rw != S_OTHER)
		return (FC_NOSUPPORT);

	npages = btopr(size);

	switch (type) {
	case F_SOFTLOCK:	/* lock down already-loaded translations */
		for (pg = 0; pg < npages; pg++) {
			pp = page_lookup(vp, (u_offset_t)(uintptr_t)addr,
			    SE_SHARED);
			if (pp == NULL) {
				/*
				 * Hmm, no page. Does a kernel mapping
				 * exist for it?
				 */
				if (!hat_probe(kas.a_hat, addr)) {
					addr -= PAGESIZE;
					while (--pg >= 0) {
						pp = page_find(vp, (u_offset_t)
						    (uintptr_t)addr);
						if (pp)
							page_unlock(pp);
						addr -= PAGESIZE;
					}
					return (FC_NOMAP);
				}
			}
			addr += PAGESIZE;
		}
		if (rw == S_OTHER)
			hat_reserve(seg->s_as, addr, size);
		return (0);
	case F_SOFTUNLOCK:
		while (npages--) {
			pp = page_find(vp, (u_offset_t)(uintptr_t)addr);
			if (pp)
				page_unlock(pp);
			addr += PAGESIZE;
		}
		return (0);
	default:
		return (FC_NOSUPPORT);
	}
	/*NOTREACHED*/
}

static int
segkmem_setprot(struct seg *seg, caddr_t addr, size_t size, uint_t prot)
{
	ASSERT(RW_LOCK_HELD(&seg->s_as->a_lock));

	if (seg->s_as != &kas || size > seg->s_size ||
	    addr < seg->s_base || addr + size > seg->s_base + seg->s_size)
		panic("segkmem_setprot: bad args");

	/*
	 * If it is one of segkp pages, call segkp.
	 */
	if (segkp_bitmap && seg == &kvseg &&
	    BT_TEST(segkp_bitmap, btop((uintptr_t)(addr - seg->s_base))))
		return (SEGOP_SETPROT(segkp, addr, size, prot));

	if (prot == 0)
		hat_unload(kas.a_hat, addr, size, HAT_UNLOAD);
	else
		hat_chgprot(kas.a_hat, addr, size, prot);
	return (0);
}

/*
 * This is a dummy segkmem function overloaded to call segkp
 * when segkp is under the heap.
 */
/* ARGSUSED */
static int
segkmem_checkprot(struct seg *seg, caddr_t addr, size_t size, uint_t prot)
{
	ASSERT(RW_LOCK_HELD(&seg->s_as->a_lock));

	if (seg->s_as != &kas)
		segkmem_badop();

	/*
	 * If it is one of segkp pages, call into segkp.
	 */
	if (segkp_bitmap && seg == &kvseg &&
	    BT_TEST(segkp_bitmap, btop((uintptr_t)(addr - seg->s_base))))
		return (SEGOP_CHECKPROT(segkp, addr, size, prot));

	segkmem_badop();
	return (0);
}

/*
 * This is a dummy segkmem function overloaded to call segkp
 * when segkp is under the heap.
 */
/* ARGSUSED */
static int
segkmem_kluster(struct seg *seg, caddr_t addr, ssize_t delta)
{
	ASSERT(RW_LOCK_HELD(&seg->s_as->a_lock));

	if (seg->s_as != &kas)
		segkmem_badop();

	/*
	 * If it is one of segkp pages, call into segkp.
	 */
	if (segkp_bitmap && seg == &kvseg &&
	    BT_TEST(segkp_bitmap, btop((uintptr_t)(addr - seg->s_base))))
		return (SEGOP_KLUSTER(segkp, addr, delta));

	segkmem_badop();
	return (0);
}

static void
segkmem_xdump_range(void *arg, void *start, size_t size)
{
	struct as *as = arg;
	caddr_t addr = start;
	caddr_t addr_end = addr + size;

	while (addr < addr_end) {
		pfn_t pfn = hat_getpfnum(kas.a_hat, addr);
		if (pfn != PFN_INVALID && pfn <= physmax && pf_is_memory(pfn))
			dump_addpage(as, addr, pfn);
		addr += PAGESIZE;
		dump_timeleft = dump_timeout;
	}
}

static void
segkmem_dump_range(void *arg, void *start, size_t size)
{
	caddr_t addr = start;
	caddr_t addr_end = addr + size;

	/*
	 * If we are about to start dumping the range of addresses we
	 * carved out of the kernel heap for the large page heap walk
	 * heap_lp_arena to find what segments are actually populated
	 */
	if (SEGKMEM_USE_LARGEPAGES &&
	    addr == heap_lp_base && addr_end == heap_lp_end &&
	    vmem_size(heap_lp_arena, VMEM_ALLOC) < size) {
		vmem_walk(heap_lp_arena, VMEM_ALLOC | VMEM_REENTRANT,
		    segkmem_xdump_range, arg);
	} else {
		segkmem_xdump_range(arg, start, size);
	}
}

static void
segkmem_dump(struct seg *seg)
{
	/*
	 * The kernel's heap_arena (represented by kvseg) is a very large
	 * VA space, most of which is typically unused.  To speed up dumping
	 * we use vmem_walk() to quickly find the pieces of heap_arena that
	 * are actually in use.  We do the same for heap32_arena and
	 * heap_core.
	 *
	 * We specify VMEM_REENTRANT to vmem_walk() because dump_addpage()
	 * may ultimately need to allocate memory.  Reentrant walks are
	 * necessarily imperfect snapshots.  The kernel heap continues
	 * to change during a live crash dump, for example.  For a normal
	 * crash dump, however, we know that there won't be any other threads
	 * messing with the heap.  Therefore, at worst, we may fail to dump
	 * the pages that get allocated by the act of dumping; but we will
	 * always dump every page that was allocated when the walk began.
	 *
	 * The other segkmem segments are dense (fully populated), so there's
	 * no need to use this technique when dumping them.
	 *
	 * Note: when adding special dump handling for any new sparsely-
	 * populated segments, be sure to add similar handling to the ::kgrep
	 * code in mdb.
	 */
	if (seg == &kvseg) {
		vmem_walk(heap_arena, VMEM_ALLOC | VMEM_REENTRANT,
		    segkmem_dump_range, seg->s_as);
#ifndef __sparc
		vmem_walk(heaptext_arena, VMEM_ALLOC | VMEM_REENTRANT,
		    segkmem_dump_range, seg->s_as);
#endif
	} else if (seg == &kvseg_core) {
		vmem_walk(heap_core_arena, VMEM_ALLOC | VMEM_REENTRANT,
		    segkmem_dump_range, seg->s_as);
	} else if (seg == &kvseg32) {
		vmem_walk(heap32_arena, VMEM_ALLOC | VMEM_REENTRANT,
		    segkmem_dump_range, seg->s_as);
		vmem_walk(heaptext_arena, VMEM_ALLOC | VMEM_REENTRANT,
		    segkmem_dump_range, seg->s_as);
	} else if (seg == &kzioseg) {
		/*
		 * We don't want to dump pages attached to kzioseg since they
		 * contain file data from ZFS.  If this page's segment is
		 * kzioseg return instead of writing it to the dump device.
		 */
		return;
	} else {
		segkmem_dump_range(seg->s_as, seg->s_base, seg->s_size);
	}
}

/*
 * lock/unlock kmem pages over a given range [addr, addr+len).
 * Returns a shadow list of pages in ppp. If there are holes
 * in the range (e.g. some of the kernel mappings do not have
 * underlying page_ts) returns ENOTSUP so that as_pagelock()
 * will handle the range via as_fault(F_SOFTLOCK).
 */
/*ARGSUSED*/
static int
segkmem_pagelock(struct seg *seg, caddr_t addr, size_t len,
	page_t ***ppp, enum lock_type type, enum seg_rw rw)
{
	page_t **pplist, *pp;
	pgcnt_t npages;
	spgcnt_t pg;
	size_t nb;
	struct vnode *vp = seg->s_data;

	ASSERT(ppp != NULL);

	/*
	 * If it is one of segkp pages, call into segkp.
	 */
	if (segkp_bitmap && seg == &kvseg &&
	    BT_TEST(segkp_bitmap, btop((uintptr_t)(addr - seg->s_base))))
		return (SEGOP_PAGELOCK(segkp, addr, len, ppp, type, rw));

	npages = btopr(len);
	nb = sizeof (page_t *) * npages;

	if (type == L_PAGEUNLOCK) {
		pplist = *ppp;
		ASSERT(pplist != NULL);

		for (pg = 0; pg < npages; pg++) {
			pp = pplist[pg];
			page_unlock(pp);
		}
		kmem_free(pplist, nb);
		return (0);
	}

	ASSERT(type == L_PAGELOCK);

	pplist = kmem_alloc(nb, KM_NOSLEEP);
	if (pplist == NULL) {
		*ppp = NULL;
		return (ENOTSUP);	/* take the slow path */
	}

	for (pg = 0; pg < npages; pg++) {
		pp = page_lookup(vp, (u_offset_t)(uintptr_t)addr, SE_SHARED);
		if (pp == NULL) {
			while (--pg >= 0)
				page_unlock(pplist[pg]);
			kmem_free(pplist, nb);
			*ppp = NULL;
			return (ENOTSUP);
		}
		pplist[pg] = pp;
		addr += PAGESIZE;
	}

	*ppp = pplist;
	return (0);
}

/*
 * This is a dummy segkmem function overloaded to call segkp
 * when segkp is under the heap.
 */
/* ARGSUSED */
static int
segkmem_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	ASSERT(RW_LOCK_HELD(&seg->s_as->a_lock));

	if (seg->s_as != &kas)
		segkmem_badop();

	/*
	 * If it is one of segkp pages, call into segkp.
	 */
	if (segkp_bitmap && seg == &kvseg &&
	    BT_TEST(segkp_bitmap, btop((uintptr_t)(addr - seg->s_base))))
		return (SEGOP_GETMEMID(segkp, addr, memidp));

	segkmem_badop();
	return (0);
}

/*ARGSUSED*/
static lgrp_mem_policy_info_t *
segkmem_getpolicy(struct seg *seg, caddr_t addr)
{
	return (NULL);
}

/*ARGSUSED*/
static int
segkmem_capable(struct seg *seg, segcapability_t capability)
{
	if (capability == S_CAPABILITY_NOMINFLT)
		return (1);
	return (0);
}

static struct seg_ops segkmem_ops = {
	SEGKMEM_BADOP(int),		/* dup */
	SEGKMEM_BADOP(int),		/* unmap */
	SEGKMEM_BADOP(void),		/* free */
	segkmem_fault,
	SEGKMEM_BADOP(faultcode_t),	/* faulta */
	segkmem_setprot,
	segkmem_checkprot,
	segkmem_kluster,
	SEGKMEM_BADOP(size_t),		/* swapout */
	SEGKMEM_BADOP(int),		/* sync */
	SEGKMEM_BADOP(size_t),		/* incore */
	SEGKMEM_BADOP(int),		/* lockop */
	SEGKMEM_BADOP(int),		/* getprot */
	SEGKMEM_BADOP(u_offset_t),	/* getoffset */
	SEGKMEM_BADOP(int),		/* gettype */
	SEGKMEM_BADOP(int),		/* getvp */
	SEGKMEM_BADOP(int),		/* advise */
	segkmem_dump,
	segkmem_pagelock,
	SEGKMEM_BADOP(int),		/* setpgsz */
	segkmem_getmemid,
	segkmem_getpolicy,		/* getpolicy */
	segkmem_capable,		/* capable */
	seg_inherit_notsup		/* inherit */
};

int
segkmem_zio_create(struct seg *seg)
{
	ASSERT(seg->s_as == &kas && RW_WRITE_HELD(&kas.a_lock));
	seg->s_ops = &segkmem_ops;
	seg->s_data = &zvp;
	kas.a_size += seg->s_size;
	return (0);
}

int
segkmem_create(struct seg *seg)
{
	ASSERT(seg->s_as == &kas && RW_WRITE_HELD(&kas.a_lock));
	seg->s_ops = &segkmem_ops;
	seg->s_data = &kvp;
	kas.a_size += seg->s_size;
	return (0);
}

/*ARGSUSED*/
page_t *
segkmem_page_create(void *addr, size_t size, int vmflag, void *arg)
{
	struct seg kseg;
	int pgflags;
	struct vnode *vp = arg;

	if (vp == NULL)
		vp = &kvp;

	kseg.s_as = &kas;
	pgflags = PG_EXCL;

	if (segkmem_reloc == 0 || (vmflag & VM_NORELOC))
		pgflags |= PG_NORELOC;
	if ((vmflag & VM_NOSLEEP) == 0)
		pgflags |= PG_WAIT;
	if (vmflag & VM_PANIC)
		pgflags |= PG_PANIC;
	if (vmflag & VM_PUSHPAGE)
		pgflags |= PG_PUSHPAGE;
	if (vmflag & VM_NORMALPRI) {
		ASSERT(vmflag & VM_NOSLEEP);
		pgflags |= PG_NORMALPRI;
	}

	return (page_create_va(vp, (u_offset_t)(uintptr_t)addr, size,
	    pgflags, &kseg, addr));
}

/*
 * Allocate pages to back the virtual address range [addr, addr + size).
 * If addr is NULL, allocate the virtual address space as well.
 */
void *
segkmem_xalloc(vmem_t *vmp, void *inaddr, size_t size, int vmflag, uint_t attr,
	page_t *(*page_create_func)(void *, size_t, int, void *), void *pcarg)
{
	page_t *ppl;
	caddr_t addr = inaddr;
	pgcnt_t npages = btopr(size);
	int allocflag;

	if (inaddr == NULL && (addr = vmem_alloc(vmp, size, vmflag)) == NULL)
		return (NULL);

	ASSERT(((uintptr_t)addr & PAGEOFFSET) == 0);

	if (page_resv(npages, vmflag & VM_KMFLAGS) == 0) {
		if (inaddr == NULL)
			vmem_free(vmp, addr, size);
		return (NULL);
	}

	ppl = page_create_func(addr, size, vmflag, pcarg);
	if (ppl == NULL) {
		if (inaddr == NULL)
			vmem_free(vmp, addr, size);
		page_unresv(npages);
		return (NULL);
	}

	/*
	 * Under certain conditions, we need to let the HAT layer know
	 * that it cannot safely allocate memory.  Allocations from
	 * the hat_memload vmem arena always need this, to prevent
	 * infinite recursion.
	 *
	 * In addition, the x86 hat cannot safely do memory
	 * allocations while in vmem_populate(), because there
	 * is no simple bound on its usage.
	 */
	if (vmflag & VM_MEMLOAD)
		allocflag = HAT_NO_KALLOC;
#if defined(__x86)
	else if (vmem_is_populator())
		allocflag = HAT_NO_KALLOC;
#endif
	else
		allocflag = 0;

	while (ppl != NULL) {
		page_t *pp = ppl;
		page_sub(&ppl, pp);
		ASSERT(page_iolock_assert(pp));
		ASSERT(PAGE_EXCL(pp));
		page_io_unlock(pp);
		hat_memload(kas.a_hat, (caddr_t)(uintptr_t)pp->p_offset, pp,
		    (PROT_ALL & ~PROT_USER) | HAT_NOSYNC | attr,
		    HAT_LOAD_LOCK | allocflag);
		pp->p_lckcnt = 1;
#if defined(__x86)
		page_downgrade(pp);
#else
		if (vmflag & SEGKMEM_SHARELOCKED)
			page_downgrade(pp);
		else
			page_unlock(pp);
#endif
	}

	return (addr);
}

static void *
segkmem_alloc_vn(vmem_t *vmp, size_t size, int vmflag, struct vnode *vp)
{
	void *addr;
	segkmem_gc_list_t *gcp, **prev_gcpp;

	ASSERT(vp != NULL);

	if (kvseg.s_base == NULL) {
#ifndef __sparc
		if (bootops->bsys_alloc == NULL)
			halt("Memory allocation between bop_alloc() and "
			    "kmem_alloc().\n");
#endif

		/*
		 * There's not a lot of memory to go around during boot,
		 * so recycle it if we can.
		 */
		for (prev_gcpp = &segkmem_gc_list; (gcp = *prev_gcpp) != NULL;
		    prev_gcpp = &gcp->gc_next) {
			if (gcp->gc_arena == vmp && gcp->gc_size == size) {
				*prev_gcpp = gcp->gc_next;
				return (gcp);
			}
		}

		addr = vmem_alloc(vmp, size, vmflag | VM_PANIC);
		if (boot_alloc(addr, size, BO_NO_ALIGN) != addr)
			panic("segkmem_alloc: boot_alloc failed");
		return (addr);
	}
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    segkmem_page_create, vp));
}

void *
segkmem_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_alloc_vn(vmp, size, vmflag, &kvp));
}

void *
segkmem_zio_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_alloc_vn(vmp, size, vmflag, &zvp));
}

/*
 * Any changes to this routine must also be carried over to
 * devmap_free_pages() in the seg_dev driver. This is because
 * we currently don't have a special kernel segment for non-paged
 * kernel memory that is exported by drivers to user space.
 */
static void
segkmem_free_vn(vmem_t *vmp, void *inaddr, size_t size, struct vnode *vp,
    void (*func)(page_t *))
{
	page_t *pp;
	caddr_t addr = inaddr;
	caddr_t eaddr;
	pgcnt_t npages = btopr(size);

	ASSERT(((uintptr_t)addr & PAGEOFFSET) == 0);
	ASSERT(vp != NULL);

	if (kvseg.s_base == NULL) {
		segkmem_gc_list_t *gc = inaddr;
		gc->gc_arena = vmp;
		gc->gc_size = size;
		gc->gc_next = segkmem_gc_list;
		segkmem_gc_list = gc;
		return;
	}

	hat_unload(kas.a_hat, addr, size, HAT_UNLOAD_UNLOCK);

	for (eaddr = addr + size; addr < eaddr; addr += PAGESIZE) {
#if defined(__x86)
		pp = page_find(vp, (u_offset_t)(uintptr_t)addr);
		if (pp == NULL)
			panic("segkmem_free: page not found");
		if (!page_tryupgrade(pp)) {
			/*
			 * Some other thread has a sharelock. Wait for
			 * it to drop the lock so we can free this page.
			 */
			page_unlock(pp);
			pp = page_lookup(vp, (u_offset_t)(uintptr_t)addr,
			    SE_EXCL);
		}
#else
		pp = page_lookup(vp, (u_offset_t)(uintptr_t)addr, SE_EXCL);
#endif
		if (pp == NULL)
			panic("segkmem_free: page not found");
		/* Clear p_lckcnt so page_destroy() doesn't update availrmem */
		pp->p_lckcnt = 0;
		if (func)
			func(pp);
		else
			page_destroy(pp, 0);
	}
	if (func == NULL)
		page_unresv(npages);

	if (vmp != NULL)
		vmem_free(vmp, inaddr, size);

}

void
segkmem_xfree(vmem_t *vmp, void *inaddr, size_t size, void (*func)(page_t *))
{
	segkmem_free_vn(vmp, inaddr, size, &kvp, func);
}

void
segkmem_free(vmem_t *vmp, void *inaddr, size_t size)
{
	segkmem_free_vn(vmp, inaddr, size, &kvp, NULL);
}

void
segkmem_zio_free(vmem_t *vmp, void *inaddr, size_t size)
{
	segkmem_free_vn(vmp, inaddr, size, &zvp, NULL);
}

void
segkmem_gc(void)
{
	ASSERT(kvseg.s_base != NULL);
	while (segkmem_gc_list != NULL) {
		segkmem_gc_list_t *gc = segkmem_gc_list;
		segkmem_gc_list = gc->gc_next;
		segkmem_free(gc->gc_arena, gc, gc->gc_size);
	}
}

/*
 * Legacy entry points from here to end of file.
 */
void
segkmem_mapin(struct seg *seg, void *addr, size_t size, uint_t vprot,
    pfn_t pfn, uint_t flags)
{
	hat_unload(seg->s_as->a_hat, addr, size, HAT_UNLOAD_UNLOCK);
	hat_devload(seg->s_as->a_hat, addr, size, pfn, vprot,
	    flags | HAT_LOAD_LOCK);
}

void
segkmem_mapout(struct seg *seg, void *addr, size_t size)
{
	hat_unload(seg->s_as->a_hat, addr, size, HAT_UNLOAD_UNLOCK);
}

void *
kmem_getpages(pgcnt_t npages, int kmflag)
{
	return (kmem_alloc(ptob(npages), kmflag));
}

void
kmem_freepages(void *addr, pgcnt_t npages)
{
	kmem_free(addr, ptob(npages));
}

/*
 * segkmem_page_create_large() allocates a large page to be used for the kmem
 * caches. If kpr is enabled we ask for a relocatable page unless requested
 * otherwise. If kpr is disabled we have to ask for a non-reloc page
 */
static page_t *
segkmem_page_create_large(void *addr, size_t size, int vmflag, void *arg)
{
	int pgflags;

	pgflags = PG_EXCL;

	if (segkmem_reloc == 0 || (vmflag & VM_NORELOC))
		pgflags |= PG_NORELOC;
	if (!(vmflag & VM_NOSLEEP))
		pgflags |= PG_WAIT;
	if (vmflag & VM_PUSHPAGE)
		pgflags |= PG_PUSHPAGE;
	if (vmflag & VM_NORMALPRI)
		pgflags |= PG_NORMALPRI;

	return (page_create_va_large(&kvp, (u_offset_t)(uintptr_t)addr, size,
	    pgflags, &kvseg, addr, arg));
}

/*
 * Allocate a large page to back the virtual address range
 * [addr, addr + size).  If addr is NULL, allocate the virtual address
 * space as well.
 */
static void *
segkmem_xalloc_lp(vmem_t *vmp, void *inaddr, size_t size, int vmflag,
    uint_t attr, page_t *(*page_create_func)(void *, size_t, int, void *),
    void *pcarg)
{
	caddr_t addr = inaddr, pa;
	size_t  lpsize = segkmem_lpsize;
	pgcnt_t npages = btopr(size);
	pgcnt_t nbpages = btop(lpsize);
	pgcnt_t nlpages = size >> segkmem_lpshift;
	size_t  ppasize = nbpages * sizeof (page_t *);
	page_t *pp, *rootpp, **ppa, *pplist = NULL;
	int i;

	vmflag |= VM_NOSLEEP;

	if (page_resv(npages, vmflag & VM_KMFLAGS) == 0) {
		return (NULL);
	}

	/*
	 * allocate an array we need for hat_memload_array.
	 * we use a separate arena to avoid recursion.
	 * we will not need this array when hat_memload_array learns pp++
	 */
	if ((ppa = vmem_alloc(segkmem_ppa_arena, ppasize, vmflag)) == NULL) {
		goto fail_array_alloc;
	}

	if (inaddr == NULL && (addr = vmem_alloc(vmp, size, vmflag)) == NULL)
		goto fail_vmem_alloc;

	ASSERT(((uintptr_t)addr & (lpsize - 1)) == 0);

	/* create all the pages */
	for (pa = addr, i = 0; i < nlpages; i++, pa += lpsize) {
		if ((pp = page_create_func(pa, lpsize, vmflag, pcarg)) == NULL)
			goto fail_page_create;
		page_list_concat(&pplist, &pp);
	}

	/* at this point we have all the resource to complete the request */
	while ((rootpp = pplist) != NULL) {
		for (i = 0; i < nbpages; i++) {
			ASSERT(pplist != NULL);
			pp = pplist;
			page_sub(&pplist, pp);
			ASSERT(page_iolock_assert(pp));
			page_io_unlock(pp);
			ppa[i] = pp;
		}
		/*
		 * Load the locked entry. It's OK to preload the entry into the
		 * TSB since we now support large mappings in the kernel TSB.
		 */
		hat_memload_array(kas.a_hat,
		    (caddr_t)(uintptr_t)rootpp->p_offset, lpsize,
		    ppa, (PROT_ALL & ~PROT_USER) | HAT_NOSYNC | attr,
		    HAT_LOAD_LOCK);

		for (--i; i >= 0; --i) {
			ppa[i]->p_lckcnt = 1;
			page_unlock(ppa[i]);
		}
	}

	vmem_free(segkmem_ppa_arena, ppa, ppasize);
	return (addr);

fail_page_create:
	while ((rootpp = pplist) != NULL) {
		for (i = 0, pp = pplist; i < nbpages; i++, pp = pplist) {
			ASSERT(pp != NULL);
			page_sub(&pplist, pp);
			ASSERT(page_iolock_assert(pp));
			page_io_unlock(pp);
		}
		page_destroy_pages(rootpp);
	}

	if (inaddr == NULL)
		vmem_free(vmp, addr, size);

fail_vmem_alloc:
	vmem_free(segkmem_ppa_arena, ppa, ppasize);

fail_array_alloc:
	page_unresv(npages);

	return (NULL);
}

static void
segkmem_free_one_lp(caddr_t addr, size_t size)
{
	page_t		*pp, *rootpp = NULL;
	pgcnt_t 	pgs_left = btopr(size);

	ASSERT(size == segkmem_lpsize);

	hat_unload(kas.a_hat, addr, size, HAT_UNLOAD_UNLOCK);

	for (; pgs_left > 0; addr += PAGESIZE, pgs_left--) {
		pp = page_lookup(&kvp, (u_offset_t)(uintptr_t)addr, SE_EXCL);
		if (pp == NULL)
			panic("segkmem_free_one_lp: page not found");
		ASSERT(PAGE_EXCL(pp));
		pp->p_lckcnt = 0;
		if (rootpp == NULL)
			rootpp = pp;
	}
	ASSERT(rootpp != NULL);
	page_destroy_pages(rootpp);

	/* page_unresv() is done by the caller */
}

/*
 * This function is called to import new spans into the vmem arenas like
 * kmem_default_arena and kmem_oversize_arena. It first tries to import
 * spans from large page arena - kmem_lp_arena. In order to do this it might
 * have to "upgrade the requested size" to kmem_lp_arena quantum. If
 * it was not able to satisfy the upgraded request it then calls regular
 * segkmem_alloc() that satisfies the request by importing from "*vmp" arena
 */
/*ARGSUSED*/
void *
segkmem_alloc_lp(vmem_t *vmp, size_t *sizep, size_t align, int vmflag)
{
	size_t size;
	kthread_t *t = curthread;
	segkmem_lpcb_t *lpcb = &segkmem_lpcb;

	ASSERT(sizep != NULL);

	size = *sizep;

	if (lpcb->lp_uselp && !(t->t_flag & T_PANIC) &&
	    !(vmflag & SEGKMEM_SHARELOCKED)) {

		size_t kmemlp_qnt = segkmem_kmemlp_quantum;
		size_t asize = P2ROUNDUP(size, kmemlp_qnt);
		void  *addr = NULL;
		ulong_t *lpthrtp = &lpcb->lp_throttle;
		ulong_t lpthrt = *lpthrtp;
		int	dowakeup = 0;
		int	doalloc = 1;

		ASSERT(kmem_lp_arena != NULL);
		ASSERT(asize >= size);

		if (lpthrt != 0) {
			/* try to update the throttle value */
			lpthrt = atomic_inc_ulong_nv(lpthrtp);
			if (lpthrt >= segkmem_lpthrottle_max) {
				lpthrt = atomic_cas_ulong(lpthrtp, lpthrt,
				    segkmem_lpthrottle_max / 4);
			}

			/*
			 * when we get above throttle start do an exponential
			 * backoff at trying large pages and reaping
			 */
			if (lpthrt > segkmem_lpthrottle_start &&
			    !ISP2(lpthrt)) {
				lpcb->allocs_throttled++;
				lpthrt--;
				if (ISP2(lpthrt))
					kmem_reap();
				return (segkmem_alloc(vmp, size, vmflag));
			}
		}

		if (!(vmflag & VM_NOSLEEP) &&
		    segkmem_heaplp_quantum >= (8 * kmemlp_qnt) &&
		    vmem_size(kmem_lp_arena, VMEM_FREE) <= kmemlp_qnt &&
		    asize < (segkmem_heaplp_quantum - kmemlp_qnt)) {

			/*
			 * we are low on free memory in kmem_lp_arena
			 * we let only one guy to allocate heap_lp
			 * quantum size chunk that everybody is going to
			 * share
			 */
			mutex_enter(&lpcb->lp_lock);

			if (lpcb->lp_wait) {

				/* we are not the first one - wait */
				cv_wait(&lpcb->lp_cv, &lpcb->lp_lock);
				if (vmem_size(kmem_lp_arena, VMEM_FREE) <
				    kmemlp_qnt)  {
					doalloc = 0;
				}
			} else if (vmem_size(kmem_lp_arena, VMEM_FREE) <=
			    kmemlp_qnt) {

				/*
				 * we are the first one, make sure we import
				 * a large page
				 */
				if (asize == kmemlp_qnt)
					asize += kmemlp_qnt;
				dowakeup = 1;
				lpcb->lp_wait = 1;
			}

			mutex_exit(&lpcb->lp_lock);
		}

		/*
		 * VM_ABORT flag prevents sleeps in vmem_xalloc when
		 * large pages are not available. In that case this allocation
		 * attempt will fail and we will retry allocation with small
		 * pages. We also do not want to panic if this allocation fails
		 * because we are going to retry.
		 */
		if (doalloc) {
			addr = vmem_alloc(kmem_lp_arena, asize,
			    (vmflag | VM_ABORT) & ~VM_PANIC);

			if (dowakeup) {
				mutex_enter(&lpcb->lp_lock);
				ASSERT(lpcb->lp_wait != 0);
				lpcb->lp_wait = 0;
				cv_broadcast(&lpcb->lp_cv);
				mutex_exit(&lpcb->lp_lock);
			}
		}

		if (addr != NULL) {
			*sizep = asize;
			*lpthrtp = 0;
			return (addr);
		}

		if (vmflag & VM_NOSLEEP)
			lpcb->nosleep_allocs_failed++;
		else
			lpcb->sleep_allocs_failed++;
		lpcb->alloc_bytes_failed += size;

		/* if large page throttling is not started yet do it */
		if (segkmem_use_lpthrottle && lpthrt == 0) {
			lpthrt = atomic_cas_ulong(lpthrtp, lpthrt, 1);
		}
	}
	return (segkmem_alloc(vmp, size, vmflag));
}

void
segkmem_free_lp(vmem_t *vmp, void *inaddr, size_t size)
{
	if (kmem_lp_arena == NULL || !IS_KMEM_VA_LARGEPAGE((caddr_t)inaddr)) {
		segkmem_free(vmp, inaddr, size);
	} else {
		vmem_free(kmem_lp_arena, inaddr, size);
	}
}

/*
 * segkmem_alloc_lpi() imports virtual memory from large page heap arena
 * into kmem_lp arena. In the process it maps the imported segment with
 * large pages
 */
static void *
segkmem_alloc_lpi(vmem_t *vmp, size_t size, int vmflag)
{
	segkmem_lpcb_t *lpcb = &segkmem_lpcb;
	void  *addr;

	ASSERT(size != 0);
	ASSERT(vmp == heap_lp_arena);

	/* do not allow large page heap grow beyound limits */
	if (vmem_size(vmp, VMEM_ALLOC) >= segkmem_kmemlp_max) {
		lpcb->allocs_limited++;
		return (NULL);
	}

	addr = segkmem_xalloc_lp(vmp, NULL, size, vmflag, 0,
	    segkmem_page_create_large, NULL);
	return (addr);
}

/*
 * segkmem_free_lpi() returns virtual memory back into large page heap arena
 * from kmem_lp arena. Beore doing this it unmaps the segment and frees
 * large pages used to map it.
 */
static void
segkmem_free_lpi(vmem_t *vmp, void *inaddr, size_t size)
{
	pgcnt_t		nlpages = size >> segkmem_lpshift;
	size_t		lpsize = segkmem_lpsize;
	caddr_t		addr = inaddr;
	pgcnt_t 	npages = btopr(size);
	int		i;

	ASSERT(vmp == heap_lp_arena);
	ASSERT(IS_KMEM_VA_LARGEPAGE(addr));
	ASSERT(((uintptr_t)inaddr & (lpsize - 1)) == 0);

	for (i = 0; i < nlpages; i++) {
		segkmem_free_one_lp(addr, lpsize);
		addr += lpsize;
	}

	page_unresv(npages);

	vmem_free(vmp, inaddr, size);
}

/*
 * This function is called at system boot time by kmem_init right after
 * /etc/system file has been read. It checks based on hardware configuration
 * and /etc/system settings if system is going to use large pages. The
 * initialiazation necessary to actually start using large pages
 * happens later in the process after segkmem_heap_lp_init() is called.
 */
int
segkmem_lpsetup()
{
	int use_large_pages = 0;

#ifdef __sparc

	size_t memtotal = physmem * PAGESIZE;

	if (heap_lp_base == NULL) {
		segkmem_lpsize = PAGESIZE;
		return (0);
	}

	/* get a platform dependent value of large page size for kernel heap */
	segkmem_lpsize = get_segkmem_lpsize(segkmem_lpsize);

	if (segkmem_lpsize <= PAGESIZE) {
		/*
		 * put virtual space reserved for the large page kernel
		 * back to the regular heap
		 */
		vmem_xfree(heap_arena, heap_lp_base,
		    heap_lp_end - heap_lp_base);
		heap_lp_base = NULL;
		heap_lp_end = NULL;
		segkmem_lpsize = PAGESIZE;
		return (0);
	}

	/* set heap_lp quantum if necessary */
	if (segkmem_heaplp_quantum == 0 || !ISP2(segkmem_heaplp_quantum) ||
	    P2PHASE(segkmem_heaplp_quantum, segkmem_lpsize)) {
		segkmem_heaplp_quantum = segkmem_lpsize;
	}

	/* set kmem_lp quantum if necessary */
	if (segkmem_kmemlp_quantum == 0 || !ISP2(segkmem_kmemlp_quantum) ||
	    segkmem_kmemlp_quantum > segkmem_heaplp_quantum) {
		segkmem_kmemlp_quantum = segkmem_heaplp_quantum;
	}

	/* set total amount of memory allowed for large page kernel heap */
	if (segkmem_kmemlp_max == 0) {
		if (segkmem_kmemlp_pcnt == 0 || segkmem_kmemlp_pcnt > 100)
			segkmem_kmemlp_pcnt = 12;
		segkmem_kmemlp_max = (memtotal * segkmem_kmemlp_pcnt) / 100;
	}
	segkmem_kmemlp_max = P2ROUNDUP(segkmem_kmemlp_max,
	    segkmem_heaplp_quantum);

	/* fix lp kmem preallocation request if necesssary */
	if (segkmem_kmemlp_min) {
		segkmem_kmemlp_min = P2ROUNDUP(segkmem_kmemlp_min,
		    segkmem_heaplp_quantum);
		if (segkmem_kmemlp_min > segkmem_kmemlp_max)
			segkmem_kmemlp_min = segkmem_kmemlp_max;
	}

	use_large_pages = 1;
	segkmem_lpszc = page_szc(segkmem_lpsize);
	segkmem_lpshift = page_get_shift(segkmem_lpszc);

#endif
	return (use_large_pages);
}

void
segkmem_zio_init(void *zio_mem_base, size_t zio_mem_size)
{
	ASSERT(zio_mem_base != NULL);
	ASSERT(zio_mem_size != 0);

	/*
	 * To reduce VA space fragmentation, we set up quantum caches for the
	 * smaller sizes;  we chose 32k because that translates to 128k VA
	 * slabs, which matches nicely with the common 128k zio_data bufs.
	 */
	zio_arena = vmem_create("zfs_file_data", zio_mem_base, zio_mem_size,
	    PAGESIZE, NULL, NULL, NULL, 32 * 1024, VM_SLEEP);

	zio_alloc_arena = vmem_create("zfs_file_data_buf", NULL, 0, PAGESIZE,
	    segkmem_zio_alloc, segkmem_zio_free, zio_arena, 0, VM_SLEEP);

	ASSERT(zio_arena != NULL);
	ASSERT(zio_alloc_arena != NULL);
}

#ifdef __sparc


static void *
segkmem_alloc_ppa(vmem_t *vmp, size_t size, int vmflag)
{
	size_t ppaquantum = btopr(segkmem_lpsize) * sizeof (page_t *);
	void   *addr;

	if (ppaquantum <= PAGESIZE)
		return (segkmem_alloc(vmp, size, vmflag));

	ASSERT((size & (ppaquantum - 1)) == 0);

	addr = vmem_xalloc(vmp, size, ppaquantum, 0, 0, NULL, NULL, vmflag);
	if (addr != NULL && segkmem_xalloc(vmp, addr, size, vmflag, 0,
	    segkmem_page_create, NULL) == NULL) {
		vmem_xfree(vmp, addr, size);
		addr = NULL;
	}

	return (addr);
}

static void
segkmem_free_ppa(vmem_t *vmp, void *addr, size_t size)
{
	size_t ppaquantum = btopr(segkmem_lpsize) * sizeof (page_t *);

	ASSERT(addr != NULL);

	if (ppaquantum <= PAGESIZE) {
		segkmem_free(vmp, addr, size);
	} else {
		segkmem_free(NULL, addr, size);
		vmem_xfree(vmp, addr, size);
	}
}

void
segkmem_heap_lp_init()
{
	segkmem_lpcb_t *lpcb = &segkmem_lpcb;
	size_t heap_lp_size = heap_lp_end - heap_lp_base;
	size_t lpsize = segkmem_lpsize;
	size_t ppaquantum;
	void   *addr;

	if (segkmem_lpsize <= PAGESIZE) {
		ASSERT(heap_lp_base == NULL);
		ASSERT(heap_lp_end == NULL);
		return;
	}

	ASSERT(segkmem_heaplp_quantum >= lpsize);
	ASSERT((segkmem_heaplp_quantum & (lpsize - 1)) == 0);
	ASSERT(lpcb->lp_uselp == 0);
	ASSERT(heap_lp_base != NULL);
	ASSERT(heap_lp_end != NULL);
	ASSERT(heap_lp_base < heap_lp_end);
	ASSERT(heap_lp_arena == NULL);
	ASSERT(((uintptr_t)heap_lp_base & (lpsize - 1)) == 0);
	ASSERT(((uintptr_t)heap_lp_end & (lpsize - 1)) == 0);

	/* create large page heap arena */
	heap_lp_arena = vmem_create("heap_lp", heap_lp_base, heap_lp_size,
	    segkmem_heaplp_quantum, NULL, NULL, NULL, 0, VM_SLEEP);

	ASSERT(heap_lp_arena != NULL);

	/* This arena caches memory already mapped by large pages */
	kmem_lp_arena = vmem_create("kmem_lp", NULL, 0, segkmem_kmemlp_quantum,
	    segkmem_alloc_lpi, segkmem_free_lpi, heap_lp_arena, 0, VM_SLEEP);

	ASSERT(kmem_lp_arena != NULL);

	mutex_init(&lpcb->lp_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&lpcb->lp_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * this arena is used for the array of page_t pointers necessary
	 * to call hat_mem_load_array
	 */
	ppaquantum = btopr(lpsize) * sizeof (page_t *);
	segkmem_ppa_arena = vmem_create("segkmem_ppa", NULL, 0, ppaquantum,
	    segkmem_alloc_ppa, segkmem_free_ppa, heap_arena, ppaquantum,
	    VM_SLEEP);

	ASSERT(segkmem_ppa_arena != NULL);

	/* prealloacate some memory for the lp kernel heap */
	if (segkmem_kmemlp_min) {

		ASSERT(P2PHASE(segkmem_kmemlp_min,
		    segkmem_heaplp_quantum) == 0);

		if ((addr = segkmem_alloc_lpi(heap_lp_arena,
		    segkmem_kmemlp_min, VM_SLEEP)) != NULL) {

			addr = vmem_add(kmem_lp_arena, addr,
			    segkmem_kmemlp_min, VM_SLEEP);
			ASSERT(addr != NULL);
		}
	}

	lpcb->lp_uselp = 1;
}

#endif

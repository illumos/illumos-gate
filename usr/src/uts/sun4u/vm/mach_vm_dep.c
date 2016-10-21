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
#include <sys/random.h>

#if defined(__sparcv9) && defined(SF_ERRATA_57)
caddr_t errata57_limit;
#endif

uint_t page_colors = 0;
uint_t page_colors_mask = 0;
uint_t page_coloring_shift = 0;
int consistent_coloring;
int update_proc_pgcolorbase_after_fork = 0;

uint_t mmu_page_sizes = DEFAULT_MMU_PAGE_SIZES;
uint_t max_mmu_page_sizes = MMU_PAGE_SIZES;
uint_t mmu_hashcnt = DEFAULT_MAX_HASHCNT;
uint_t max_mmu_hashcnt = MAX_HASHCNT;
size_t mmu_ism_pagesize = DEFAULT_ISM_PAGESIZE;

/*
 * The sun4u hardware mapping sizes which will always be supported are
 * 8K, 64K, 512K and 4M.  If sun4u based machines need to support other
 * page sizes, platform or cpu specific routines need to modify the value.
 * The base pagesize (p_szc == 0) must always be supported by the hardware.
 */
int mmu_exported_pagesize_mask = (1 << TTE8K) | (1 << TTE64K) |
	(1 << TTE512K) | (1 << TTE4M);
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
int	max_bootlp_tteszc = TTE4M;

/*
 * use_text_pgsz64k and use_text_pgsz512k allow the user to turn on these
 * additional text page sizes for USIII-IV+ and OPL by changing the default
 * values via /etc/system.
 */
int	use_text_pgsz64K = 0;
int	use_text_pgsz512K = 0;

/*
 * Maximum and default segment size tunables for user heap, stack, private
 * and shared anonymous memory, and user text and initialized data.
 */
size_t max_uheap_lpsize = MMU_PAGESIZE4M;
size_t default_uheap_lpsize = MMU_PAGESIZE;
size_t max_ustack_lpsize = MMU_PAGESIZE4M;
size_t default_ustack_lpsize = MMU_PAGESIZE;
size_t max_privmap_lpsize = MMU_PAGESIZE4M;
size_t max_uidata_lpsize = MMU_PAGESIZE;
size_t max_utext_lpsize = MMU_PAGESIZE4M;
size_t max_shm_lpsize = MMU_PAGESIZE4M;

void
adjust_data_maxlpsize(size_t ismpagesize)
{
	if (max_uheap_lpsize == MMU_PAGESIZE4M) {
		max_uheap_lpsize = ismpagesize;
	}
	if (max_ustack_lpsize == MMU_PAGESIZE4M) {
		max_ustack_lpsize = ismpagesize;
	}
	if (max_privmap_lpsize == MMU_PAGESIZE4M) {
		max_privmap_lpsize = ismpagesize;
	}
	if (max_shm_lpsize == MMU_PAGESIZE4M) {
		max_shm_lpsize = ismpagesize;
	}
}

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
/*ARGSUSED4*/
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
			uint32_t maxslew;

			(void) random_get_pseudo_bytes((uint8_t *)&slew,
			    sizeof (slew));

			maxslew = MIN(aslr_max_map_skew, (addr - base));
			/*
			 * Don't allow ASLR to cause mappings to fail below
			 * because of SF erratum #57
			 */
			maxslew = MIN(maxslew, (addr - errata57_limit));

			slew = slew % maxslew;
			addr -= P2ALIGN(slew, align_amount);
		}

		ASSERT(addr > base);
		ASSERT(addr + len < base + slen);
		ASSERT(((uintptr_t)addr & (align_amount - 1l)) ==
		    ((uintptr_t)(off)));
		*addrp = addr;

#if defined(SF_ERRATA_57)
		if (AS_TYPE_64BIT(as) && addr < errata57_limit) {
			*addrp = NULL;
		}
#endif
	} else {
		*addrp = NULL;	/* no more virtual space */
	}
}

/*
 * Platform-dependent page scrub call.
 */
void
pagescrub(page_t *pp, uint_t off, uint_t len)
{
	/*
	 * For now, we rely on the fact that pagezero() will
	 * always clear UEs.
	 */
	pagezero(pp, off, len);
}

/*ARGSUSED*/
void
sync_data_memory(caddr_t va, size_t len)
{
	cpu_flush_ecache();
}

/*
 * platform specific large pages for kernel heap support
 */
void
mmu_init_kcontext()
{
	extern void set_kcontextreg();

	if (kcontextreg)
		set_kcontextreg();
}

void
contig_mem_init(void)
{
	/* not applicable to sun4u */
}

/*ARGSUSED*/
caddr_t
contig_mem_prealloc(caddr_t alloc_base, pgcnt_t npages)
{
	/* not applicable to sun4u */
	return (alloc_base);
}

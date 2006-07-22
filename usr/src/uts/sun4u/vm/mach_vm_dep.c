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

#if defined(__sparcv9) && defined(SF_ERRATA_57)
caddr_t errata57_limit;
#endif

uint_t page_colors = 0;
uint_t page_colors_mask = 0;
uint_t page_coloring_shift = 0;
int consistent_coloring;

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
 * use_text_pgsz64k, use_initdata_pgsz64k and use_text_pgsz4m
 * can be set in platform or CPU specific code but user can change the
 * default values via /etc/system.
 */

int	use_text_pgsz64k = 0;
int	use_text_pgsz4m = 0;
int	use_initdata_pgsz64k = 0;

/*
 * disable_text_largepages and disable_initdata_largepages bitmaks are set in
 * platform or CPU specific code to disable page sizes that should not be
 * used. These variables normally shouldn't be changed via /etc/system. A
 * particular page size for text or inititialized data will be used by default
 * if both one of use_* variables is set to 1 AND this page size is not
 * disabled in the corresponding disable_* bitmask variable.
 */

int disable_text_largepages = (1 << TTE4M) | (1 << TTE64K);
int disable_initdata_largepages = (1 << TTE64K);

/*
 * Minimum segment size tunables before 64K or 4M large pages
 * should be used to map it.
 */
size_t text_pgsz64k_minsize = MMU_PAGESIZE64K;
size_t text_pgsz4m_minsize = MMU_PAGESIZE4M;
size_t initdata_pgsz64k_minsize = MMU_PAGESIZE64K;

size_t max_shm_lpsize = ULONG_MAX;

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
 * Platforms with smaller or larger TLBs may wish to change this.  Most
 * sun4u platforms can hold 1024 8K entries by default and most processes
 * are observed to be < 6MB on these machines, so we decide to move up
 * here to give ourselves some wiggle room for other, smaller segments.
 */
int auto_lpg_tlb_threshold = 768;
int auto_lpg_minszc = TTE4M;
int auto_lpg_maxszc = TTE4M;
size_t auto_lpg_heap_default = MMU_PAGESIZE;
size_t auto_lpg_stack_default = MMU_PAGESIZE;
size_t auto_lpg_va_default = MMU_PAGESIZE;
size_t auto_lpg_remap_threshold = 0;
/*
 * Number of pages in 1 GB.  Don't enable automatic large pages if we have
 * fewer than this many pages.
 */
pgcnt_t auto_lpg_min_physmem = 1 << (30 - MMU_PAGESHIFT);

/*
 * Suggest a page size to be used to map a segment of type maptype and length
 * len.  Returns a page size (not a size code).
 * If remap is non-NULL, fill in a value suggesting whether or not to remap
 * this segment.
 */
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

		/*
		 * For non-Panther systems, the following code sets the [D]ISM
		 * pagesize to 4M if either of the DTLBs happens to be
		 * programmed to a different large pagesize.
		 * The Panther code might hit this case as well,
		 * if and only if the addr is not aligned to >= 4M.
		 */
		if ((pgsz > 0) && (pgsz < MMU_PAGESIZE4M))
			pgsz = MMU_PAGESIZE4M;
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

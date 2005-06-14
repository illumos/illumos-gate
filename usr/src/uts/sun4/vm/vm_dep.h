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

/*
 * UNIX machine dependent virtual memory support.
 */

#ifndef	_VM_DEP_H
#define	_VM_DEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <vm/hat_sfmmu.h>
#include <sys/archsystm.h>
#include <sys/memnode.h>

#define	GETTICK()	gettick()

/*
 * Per page size free lists. Allocated dynamically.
 */
#define	MAX_MEM_TYPES	2	/* 0 = reloc, 1 = noreloc */
#define	MTYPE_RELOC	0
#define	MTYPE_NORELOC	1

#define	PP_2_MTYPE(pp)	(PP_ISNORELOC(pp) ? MTYPE_NORELOC : MTYPE_RELOC)

#define	MTYPE_INIT(mtype, vp, vaddr, flags)				\
	mtype = (flags & PG_NORELOC) ? MTYPE_NORELOC : MTYPE_RELOC;

/*
 * macros to loop through the mtype range - noops for sparc
 */
#define	MTYPE_START(mnode, mtype, flags)
#define	MTYPE_NEXT(mnode, mtype, flags)		(-1)

/* mtype init for page_get_replacement_page */

#define	MTYPE_PGR_INIT(mtype, flags, pp, mnode)				\
	mtype = (flags & PG_NORELOC) ? MTYPE_NORELOC : MTYPE_RELOC;

#define	MNODETYPE_2_PFN(mnode, mtype, pfnlo, pfnhi)			\
	ASSERT(mtype != MTYPE_NORELOC);					\
	pfnlo = mem_node_config[mnode].physbase;			\
	pfnhi = mem_node_config[mnode].physmax;

/*
 * Internal PG_ flags.
 */
#define	PGI_RELOCONLY	0x10000	/* acts in the opposite sense to PG_NORELOC */
#define	PGI_NOCAGE	0x20000	/* indicates Cage is disabled */
#define	PGI_PGCPHIPRI	0x40000	/* page_get_contig_page priority allocation */
#define	PGI_PGCPSZC0	0x80000	/* relocate base pagesize page */

/*
 * PGI mtype flags - should not overlap PGI flags
 */
#define	PGI_MT_RANGE	0x1000000	/* mtype range */
#define	PGI_MT_NEXT	0x2000000	/* get next mtype */

extern page_t ***page_freelists[MMU_PAGE_SIZES][MAX_MEM_TYPES];
extern page_t ***page_cachelists[MAX_MEM_TYPES];

#define	PAGE_FREELISTS(mnode, szc, color, mtype) \
	(*(page_freelists[szc][mtype][mnode] + (color)))

#define	PAGE_CACHELISTS(mnode, color, mtype) \
	(*(page_cachelists[mtype][mnode] + (color)))

/*
 * There are 'page_colors' colors/bins.  Spread them out under a
 * couple of locks.  There are mutexes for both the page freelist
 * and the page cachelist.  We want enough locks to make contention
 * reasonable, but not too many -- otherwise page_freelist_lock() gets
 * so expensive that it becomes the bottleneck!
 */
#define	NPC_MUTEX	16

extern kmutex_t	*fpc_mutex[NPC_MUTEX];
extern kmutex_t	*cpc_mutex[NPC_MUTEX];

/* Find the bin for the given page if it was of size szc */
#define	PP_2_BIN_SZC(pp, szc)                                           \
	(((pp->p_pagenum) & page_colors_mask) >>                        \
	(hw_page_array[szc].hp_shift - hw_page_array[0].hp_shift))

#define	PP_2_BIN(pp)		(PP_2_BIN_SZC(pp, pp->p_szc))

#define	PP_2_MEM_NODE(pp)	(PFN_2_MEM_NODE(pp->p_pagenum))

#define	PC_BIN_MUTEX(mnode, bin, flags) ((flags & PG_FREE_LIST) ?	\
	&fpc_mutex[(bin) & (NPC_MUTEX - 1)][mnode] :			\
	&cpc_mutex[(bin) & (NPC_MUTEX - 1)][mnode])

#define	FPC_MUTEX(mnode, i)	(&fpc_mutex[i][mnode])
#define	CPC_MUTEX(mnode, i)	(&cpc_mutex[i][mnode])

#define	PFN_BASE(pfnum, szc)	(pfnum & ~((1 << PAGE_BSZS_SHIFT(szc)) - 1))

typedef	char	hpmctr_t;

#ifdef DEBUG
#define	CHK_LPG(pp, szc)	chk_lpg(pp, szc)
extern void	chk_lpg(page_t *, uchar_t);
#else
#define	CHK_LPG(pp, szc)
#endif

#ifdef DEBUG

/* page list count */
typedef	struct {
	pgcnt_t	plc_m_pgmax;
	pgcnt_t	plc_m_pgcnt;
	pgcnt_t	plc_m_clpgcnt;		/* cache list cnt */
	struct {
		pgcnt_t	plc_mt_pgmax;
		pgcnt_t plc_mt_pgcnt;
		struct {
			pgcnt_t plc_mts_pgcnt;
			int	plc_mts_colors;
			pgcnt_t	*plc_mtsc_pgcnt;
		} plc_mts[MMU_PAGE_SIZES];
	} plc_mt[MAX_MEM_TYPES];
} plcnt_t[MAX_MEM_NODES];

extern plcnt_t	plcnt;

#define	PLCNT_SZ(ctrs_sz) {						\
	int	szc;							\
	for (szc = 0; szc <= mmu_page_sizes; szc++) {			\
		int	colors = page_get_pagecolors(szc);		\
		ctrs_sz += (max_mem_nodes * MAX_MEM_TYPES *		\
		    colors * sizeof (pgcnt_t));				\
	}								\
}

#define	PLCNT_INIT(base) {						\
	int	mn, mt, szc, colors;					\
	for (szc = 0; szc < mmu_page_sizes; szc++) {			\
		colors = page_get_pagecolors(szc);			\
		for (mn = 0; mn < max_mem_nodes; mn++) {		\
			for (mt = 0; mt < MAX_MEM_TYPES; mt++) {	\
				plcnt[mn].plc_mt[mt].plc_mts[szc].	\
				    plc_mts_colors = colors;		\
				plcnt[mn].plc_mt[mt].plc_mts[szc].	\
				    plc_mtsc_pgcnt = (pgcnt_t *)base;	\
				base += (colors * sizeof (pgcnt_t));	\
			}						\
		}							\
	}								\
}

#define	PLCNT_DO(pp, mn, szc, cnt, flags) {				\
	int	mtype = PP_2_MTYPE(pp);					\
	int	bin = PP_2_BIN(pp);					\
	if (flags & (PG_LIST_ISINIT | PG_LIST_ISCAGE))			\
		atomic_add_long(&plcnt[mn].plc_mt[mtype].plc_mt_pgmax,	\
		    cnt);						\
	atomic_add_long(&mem_node_config[mn].cursize, cnt);		\
	if (flags & PG_CACHE_LIST)					\
		atomic_add_long(&plcnt[mn].plc_m_clpgcnt, cnt);		\
	atomic_add_long(&plcnt[mn].plc_m_pgcnt, cnt);			\
	atomic_add_long(&plcnt[mn].plc_mt[mtype].plc_mt_pgcnt, cnt);	\
	atomic_add_long(&plcnt[mn].plc_mt[mtype].plc_mts[szc].		\
	    plc_mts_pgcnt, cnt);					\
	atomic_add_long(&plcnt[mn].plc_mt[mtype].plc_mts[szc].		\
	    plc_mtsc_pgcnt[bin], cnt);					\
}

#define	PLCNT_INCR(pp, mn, szc, flags) {				\
	long	cnt = (1 << PAGE_BSZS_SHIFT(szc));			\
	if (flags & PG_LIST_ISINIT)					\
		plcnt[mn].plc_m_pgmax += cnt;				\
	PLCNT_DO(pp, mn, szc, cnt, flags);				\
}

#define	PLCNT_DECR(pp, mn, szc, flags) {				\
	long	cnt = ((-1) << PAGE_BSZS_SHIFT(szc));			\
	PLCNT_DO(pp, mn, szc, cnt, flags);				\
}

#else

#define	PLCNT_SZ(ctrs_sz)

#define	PLCNT_INIT(base)

#define	PLCNT_INCR(pp, mnode, szc, flags) {				\
	long	cnt = (1 << PAGE_BSZS_SHIFT(szc));			\
	atomic_add_long(&mem_node_config[mnode].cursize, cnt);		\
}

#define	PLCNT_DECR(pp, mnode, szc, flags) {				\
	long	cnt = ((-1) << PAGE_BSZS_SHIFT(szc));			\
	atomic_add_long(&mem_node_config[mnode].cursize, cnt);		\
}

#endif

/*
 * get the ecache setsize for the current cpu.
 */
#define	CPUSETSIZE()	(cpunodes[CPU->cpu_id].ecache_setsize)


#define	PAGE_BSZS_SHIFT(szc)	TTE_BSZS_SHIFT(szc)
/*
 * For sfmmu each larger page is 8 times the size of the previous
 * size page.
 */
#define	FULL_REGION_CNT(rg_szc)	(8)

/*
 * The counter base must be per page_counter element to prevent
 * races when re-indexing, and the base page size element should
 * be aligned on a boundary of the given region size.
 *
 * We also round up the number of pages spanned by the counters
 * for a given region to PC_BASE_ALIGN in certain situations to simplify
 * the coding for some non-performance critical routines.
 */
#define	PC_BASE_ALIGN		((pfn_t)1 << PAGE_BSZS_SHIFT(mmu_page_sizes-1))
#define	PC_BASE_ALIGN_MASK	(PC_BASE_ALIGN - 1)

extern int ecache_alignsize;
#define	L2CACHE_ALIGN		ecache_alignsize

extern int consistent_coloring;
extern uint_t vac_colors_mask;
extern int vac_size;
extern int vac_shift;

/*
 * Auto large page selection support variables. Some CPU
 * implementations may differ from the defaults and will need
 * to change these.
 */
extern int auto_lpg_tlb_threshold;
extern int auto_lpg_minszc;
extern int auto_lpg_maxszc;
extern size_t auto_lpg_heap_default;
extern size_t auto_lpg_stack_default;
extern size_t auto_lpg_va_default;
extern size_t auto_lpg_remap_threshold;

/*
 * AS_2_BIN macro controls the page coloring policy.
 * 0 (default) uses various vaddr bits
 * 1 virtual=paddr
 * 2 bin hopping
 */
#define	AS_2_BIN(as, seg, vp, addr, bin)				\
switch (consistent_coloring) {						\
	default:                                                        \
		cmn_err(CE_WARN,					\
			"AS_2_BIN: bad consistent coloring value");	\
		/* assume default algorithm -> continue */		\
	case 0: {                                                       \
		uint32_t ndx, new;					\
		int slew = 0;						\
                                                                        \
		if (vp != NULL && IS_SWAPVP(vp) &&			\
			seg->s_ops == &segvn_ops)			\
			slew = as_color_bin(as);			\
                                                                        \
		bin = (((uintptr_t)addr >> MMU_PAGESHIFT) +		\
			(((uintptr_t)addr >> page_coloring_shift) <<	\
			(vac_shift - MMU_PAGESHIFT)) + slew) &		\
			page_colors_mask;				\
                                                                        \
		break;                                                  \
	}                                                               \
	case 1:                                                         \
		bin = ((uintptr_t)addr >> MMU_PAGESHIFT) &		\
			page_colors_mask;				\
		break;                                                  \
	case 2: {                                                       \
		int cnt = as_color_bin(as);				\
		/* make sure physical color aligns with vac color */	\
		while ((cnt & vac_colors_mask) !=			\
		    addr_to_vcolor(addr)) {				\
			cnt++;						\
		}                                                       \
		bin = cnt = cnt & page_colors_mask;			\
		/* update per as page coloring fields */		\
		cnt = (cnt + 1) & page_colors_mask;			\
		if (cnt == (as_color_start(as) & page_colors_mask)) {	\
			cnt = as_color_start(as) = as_color_start(as) + \
				PGCLR_LOOPFACTOR;			\
		}                                                       \
		as_color_bin(as) = cnt & page_colors_mask;		\
		break;                                                  \
	}								\
}									\
	ASSERT(bin <= page_colors_mask);

/*
 * Function to get an ecache color bin: F(as, cnt, vcolor).
 * the goal of this function is to:
 * - to spread a processes' physical pages across the entire ecache to
 *	maximize its use.
 * - to minimize vac flushes caused when we reuse a physical page on a
 *	different vac color than it was previously used.
 * - to prevent all processes to use the same exact colors and trash each
 *	other.
 *
 * cnt is a bin ptr kept on a per as basis.  As we page_create we increment
 * the ptr so we spread out the physical pages to cover the entire ecache.
 * The virtual color is made a subset of the physical color in order to
 * in minimize virtual cache flushing.
 * We add in the as to spread out different as.	 This happens when we
 * initialize the start count value.
 * sizeof(struct as) is 60 so we shift by 3 to get into the bit range
 * that will tend to change.  For example, on spitfire based machines
 * (vcshft == 1) contigous as are spread bu ~6 bins.
 * vcshft provides for proper virtual color alignment.
 * In theory cnt should be updated using cas only but if we are off by one
 * or 2 it is no big deal.
 * We also keep a start value which is used to randomize on what bin we
 * start counting when it is time to start another loop. This avoids
 * contigous allocations of ecache size to point to the same bin.
 * Why 3? Seems work ok. Better than 7 or anything larger.
 */
#define	PGCLR_LOOPFACTOR 3

/*
 * When a bin is empty, and we can't satisfy a color request correctly,
 * we scan.  If we assume that the programs have reasonable spatial
 * behavior, then it will not be a good idea to use the adjacent color.
 * Using the adjacent color would result in virtually adjacent addresses
 * mapping into the same spot in the cache.  So, if we stumble across
 * an empty bin, skip a bunch before looking.  After the first skip,
 * then just look one bin at a time so we don't miss our cache on
 * every look. Be sure to check every bin.  Page_create() will panic
 * if we miss a page.
 *
 * This also explains the `<=' in the for loops in both page_get_freelist()
 * and page_get_cachelist().  Since we checked the target bin, skipped
 * a bunch, then continued one a time, we wind up checking the target bin
 * twice to make sure we get all of them bins.
 */
#define	BIN_STEP	20

#ifdef VM_STATS
struct vmm_vmstats_str {
	ulong_t pc_list_add_pages[MMU_PAGE_SIZES];
	ulong_t pc_list_sub_pages1[MMU_PAGE_SIZES];
	ulong_t pc_list_sub_pages2[MMU_PAGE_SIZES];
	ulong_t pc_list_sub_pages3[MMU_PAGE_SIZES];
	ulong_t pgf_alloc[MMU_PAGE_SIZES];
	ulong_t pgf_allocok[MMU_PAGE_SIZES];
	ulong_t pgf_allocokrem[MMU_PAGE_SIZES];
	ulong_t pgf_allocfailed[MMU_PAGE_SIZES];
	ulong_t pgf_allocdeferred;
	ulong_t	pgf_allocretry[MMU_PAGE_SIZES];
	ulong_t pgc_alloc;
	ulong_t pgc_allocok;
	ulong_t pgc_allocokrem;
	ulong_t	pgc_allocokdeferred;
	ulong_t pgc_allocfailed;
	ulong_t	pgcp_alloc[MMU_PAGE_SIZES];
	ulong_t	pgcp_allocfailed[MMU_PAGE_SIZES];
	ulong_t	pgcp_allocempty[MMU_PAGE_SIZES];
	ulong_t	pgcp_allocok[MMU_PAGE_SIZES];
	ulong_t	ptcp[MMU_PAGE_SIZES];
	ulong_t	ptcpfreethresh[MMU_PAGE_SIZES];
	ulong_t	ptcpfailexcl[MMU_PAGE_SIZES];
	ulong_t	ptcpfailszc[MMU_PAGE_SIZES];
	ulong_t	ptcpfailcage[MMU_PAGE_SIZES];
	ulong_t	ptcpok[MMU_PAGE_SIZES];
	ulong_t	pgmf_alloc[MMU_PAGE_SIZES];
	ulong_t	pgmf_allocfailed[MMU_PAGE_SIZES];
	ulong_t	pgmf_allocempty[MMU_PAGE_SIZES];
	ulong_t	pgmf_allocok[MMU_PAGE_SIZES];
	ulong_t	pgmc_alloc;
	ulong_t	pgmc_allocfailed;
	ulong_t	pgmc_allocempty;
	ulong_t	pgmc_allocok;
	ulong_t ppr_reloc[MMU_PAGE_SIZES];
	ulong_t ppr_relocok[MMU_PAGE_SIZES];
	ulong_t ppr_relocnoroot[MMU_PAGE_SIZES];
	ulong_t ppr_reloc_replnoroot[MMU_PAGE_SIZES];
	ulong_t ppr_relocnolock[MMU_PAGE_SIZES];
	ulong_t ppr_relocnomem[MMU_PAGE_SIZES];
	ulong_t ppr_krelocfail[MMU_PAGE_SIZES];
	ulong_t	page_ctrs_coalesce;	/* page coalesce counter */
	ulong_t	page_ctrs_cands_skip;	/* candidates useful */
	ulong_t	page_ctrs_changed;	/* ctrs changed after locking */
	ulong_t	page_ctrs_failed;	/* page_freelist_coalesce failed */
	ulong_t	page_ctrs_coalesce_all;	/* page coalesce all counter */
	ulong_t	page_ctrs_cands_skip_all; /* candidates useful for all func */
};
extern struct vmm_vmstats_str vmm_vmstats;
#endif	/* VM_STATS */

/*
 * Used to hold off page relocations into the cage until OBP has completed
 * its boot-time handoff of its resources to the kernel.
 */
extern int page_relocate_ready;

/*
 * cpu/mmu-dependent vm variables may be reset at bootup.
 */
extern uint_t mmu_page_sizes;
extern uint_t max_mmu_page_sizes;
extern uint_t mmu_hashcnt;
extern uint_t max_mmu_hashcnt;
extern size_t mmu_ism_pagesize;
extern int mmu_exported_pagesize_mask;
extern uint_t mmu_exported_page_sizes;
extern uint_t szc_2_userszc[];
extern uint_t userszc_2_szc[];

#define	USERSZC_2_SZC(userszc)	(userszc_2_szc[userszc])
#define	SZC_2_USERSZC(szc)	(szc_2_userszc[szc])

/*
 * Platform specific map_pgsz large page hook routines.
 */
extern size_t map_pgszva(struct proc *p, caddr_t addr, size_t len);
extern size_t map_pgszheap(struct proc *p, caddr_t addr, size_t len);
extern size_t map_pgszstk(struct proc *p, caddr_t addr, size_t len);

/*
 * Platform specific page routines
 */
extern void mach_page_add(page_t **, page_t *);
extern void mach_page_sub(page_t **, page_t *);
extern uint_t page_get_pagecolors(uint_t);
extern void ppcopy_kernel__relocatable(page_t *, page_t *);
#define	ppcopy_kernel(p1, p2)	ppcopy_kernel__relocatable(p1, p2)

/*
 * platform specific large pages for kernel heap support
 */
extern size_t get_segkmem_lpsize(size_t lpsize);
extern size_t mmu_get_kernel_lpsize(size_t lpsize);
extern void mmu_init_kernel_pgsz(struct hat *hat);
extern void mmu_init_kcontext();
extern uint64_t kcontextreg;

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_DEP_H */

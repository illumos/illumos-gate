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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */


/*
 * This file contains common functions to access and manage the page lists.
 * Many of these routines originated from platform dependent modules
 * (sun4/vm/vm_dep.c, i86pc/vm/vm_machdep.c) and modified to function in
 * a platform independent manner.
 *
 * vm/vm_dep.h provides for platform specific support.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <sys/vmsystm.h>
#include <sys/memnode.h>
#include <vm/vm_dep.h>
#include <sys/lgrp.h>
#include <sys/mem_config.h>
#include <sys/callb.h>
#include <sys/mem_cage.h>
#include <sys/sdt.h>
#include <sys/dumphdr.h>
#include <sys/swap.h>

extern uint_t	vac_colors;

#define	MAX_PRAGMA_ALIGN	128

/* vm_cpu_data0 for the boot cpu before kmem is initialized */

#if L2CACHE_ALIGN_MAX <= MAX_PRAGMA_ALIGN
#pragma align	L2CACHE_ALIGN_MAX(vm_cpu_data0)
#else
#pragma align	MAX_PRAGMA_ALIGN(vm_cpu_data0)
#endif
char		vm_cpu_data0[VM_CPU_DATA_PADSIZE];

/*
 * number of page colors equivalent to reqested color in page_get routines.
 * If set, keeps large pages intact longer and keeps MPO allocation
 * from the local mnode in favor of acquiring the 'correct' page color from
 * a demoted large page or from a remote mnode.
 */
uint_t	colorequiv;

/*
 * color equivalency mask for each page size.
 * Mask is computed based on cpu L2$ way sizes and colorequiv global.
 * High 4 bits determine the number of high order bits of the color to ignore.
 * Low 4 bits determines number of low order bits of color to ignore (it's only
 * relevant for hashed index based page coloring).
 */
uchar_t colorequivszc[MMU_PAGE_SIZES];

/*
 * if set, specifies the percentage of large pages that are free from within
 * a large page region before attempting to lock those pages for
 * page_get_contig_pages processing.
 *
 * Should be turned on when kpr is available when page_trylock_contig_pages
 * can be more selective.
 */

int	ptcpthreshold;

/*
 * Limit page get contig page search based on failure cnts in pgcpfailcnt[].
 * Enabled by default via pgcplimitsearch.
 *
 * pgcpfailcnt[] is bounded by PGCPFAILMAX (>= 1/2 of installed
 * memory). When reached, pgcpfailcnt[] is reset to 1/2 of this upper
 * bound. This upper bound range guarantees:
 *    - all large page 'slots' will be searched over time
 *    - the minimum (1) large page candidates considered on each pgcp call
 *    - count doesn't wrap around to 0
 */
pgcnt_t	pgcpfailcnt[MMU_PAGE_SIZES];
int	pgcplimitsearch = 1;

#define	PGCPFAILMAX		(1 << (highbit(physinstalled) - 1))
#define	SETPGCPFAILCNT(szc)						\
	if (++pgcpfailcnt[szc] >= PGCPFAILMAX)				\
		pgcpfailcnt[szc] = PGCPFAILMAX / 2;

#ifdef VM_STATS
struct vmm_vmstats_str  vmm_vmstats;

#endif /* VM_STATS */

#if defined(__sparc)
#define	LPGCREATE	0
#else
/* enable page_get_contig_pages */
#define	LPGCREATE	1
#endif

int pg_contig_disable;
int pg_lpgcreate_nocage = LPGCREATE;

/*
 * page_freelist_split pfn flag to signify no lo or hi pfn requirement.
 */
#define	PFNNULL		0

/* Flags involved in promotion and demotion routines */
#define	PC_FREE		0x1	/* put page on freelist */
#define	PC_ALLOC	0x2	/* return page for allocation */

/*
 * Flag for page_demote to be used with PC_FREE to denote that we don't care
 * what the color is as the color parameter to the function is ignored.
 */
#define	PC_NO_COLOR	(-1)

/* mtype value for page_promote to use when mtype does not matter */
#define	PC_MTYPE_ANY	(-1)

/*
 * page counters candidates info
 * See page_ctrs_cands comment below for more details.
 * fields are as follows:
 *	pcc_pages_free:		# pages which freelist coalesce can create
 *	pcc_color_free:		pointer to page free counts per color
 */
typedef struct pcc_info {
	pgcnt_t	pcc_pages_free;
	pgcnt_t	*pcc_color_free;
	uint_t	pad[12];
} pcc_info_t;

/*
 * On big machines it can take a long time to check page_counters
 * arrays. page_ctrs_cands is a summary array whose elements are a dynamically
 * updated sum of all elements of the corresponding page_counters arrays.
 * page_freelist_coalesce() searches page_counters only if an appropriate
 * element of page_ctrs_cands array is greater than 0.
 *
 * page_ctrs_cands is indexed by mutex (i), region (r), mnode (m), mrange (g)
 */
pcc_info_t **page_ctrs_cands[NPC_MUTEX][MMU_PAGE_SIZES];

/*
 * Return in val the total number of free pages which can be created
 * for the given mnode (m), mrange (g), and region size (r)
 */
#define	PGCTRS_CANDS_GETVALUE(m, g, r, val) {				\
	int i;								\
	val = 0;							\
	for (i = 0; i < NPC_MUTEX; i++) {				\
	    val += page_ctrs_cands[i][(r)][(m)][(g)].pcc_pages_free;	\
	}								\
}

/*
 * Return in val the total number of free pages which can be created
 * for the given mnode (m), mrange (g), region size (r), and color (c)
 */
#define	PGCTRS_CANDS_GETVALUECOLOR(m, g, r, c, val) {			\
	int i;								\
	val = 0;							\
	ASSERT((c) < PAGE_GET_PAGECOLORS(r));				\
	for (i = 0; i < NPC_MUTEX; i++) {				\
	    val +=							\
		page_ctrs_cands[i][(r)][(m)][(g)].pcc_color_free[(c)];	\
	}								\
}

/*
 * We can only allow a single thread to update a counter within the physical
 * range of the largest supported page size. That is the finest granularity
 * possible since the counter values are dependent on each other
 * as you move accross region sizes. PP_CTR_LOCK_INDX is used to determine the
 * ctr_mutex lock index for a particular physical range.
 */
static kmutex_t	*ctr_mutex[NPC_MUTEX];

#define	PP_CTR_LOCK_INDX(pp)						\
	(((pp)->p_pagenum >>						\
	    (PAGE_BSZS_SHIFT(mmu_page_sizes - 1))) & (NPC_MUTEX - 1))

#define	INVALID_COLOR 0xffffffff
#define	INVALID_MASK  0xffffffff

/*
 * Local functions prototypes.
 */

void page_ctr_add(int, int, page_t *, int);
void page_ctr_add_internal(int, int, page_t *, int);
void page_ctr_sub(int, int, page_t *, int);
void page_ctr_sub_internal(int, int, page_t *, int);
void page_freelist_lock(int);
void page_freelist_unlock(int);
page_t *page_promote(int, pfn_t, uchar_t, int, int);
page_t *page_demote(int, pfn_t, pfn_t, uchar_t, uchar_t, int, int);
page_t *page_freelist_split(uchar_t,
    uint_t, int, int, pfn_t, pfn_t, page_list_walker_t *);
page_t *page_get_mnode_cachelist(uint_t, uint_t, int, int);
static int page_trylock_cons(page_t *pp, se_t se);

/*
 * The page_counters array below is used to keep track of free contiguous
 * physical memory.  A hw_page_map_t will be allocated per mnode per szc.
 * This contains an array of counters, the size of the array, a shift value
 * used to convert a pagenum into a counter array index or vice versa, as
 * well as a cache of the last successful index to be promoted to a larger
 * page size.  As an optimization, we keep track of the last successful index
 * to be promoted per page color for the given size region, and this is
 * allocated dynamically based upon the number of colors for a given
 * region size.
 *
 * Conceptually, the page counters are represented as:
 *
 *	page_counters[region_size][mnode]
 *
 *	region_size:	size code of a candidate larger page made up
 *			of contiguous free smaller pages.
 *
 *	page_counters[region_size][mnode].hpm_counters[index]:
 *		represents how many (region_size - 1) pages either
 *		exist or can be created within the given index range.
 *
 * Let's look at a sparc example:
 *	If we want to create a free 512k page, we look at region_size 2
 *	for the mnode we want.  We calculate the index and look at a specific
 *	hpm_counters location.  If we see 8 (FULL_REGION_CNT on sparc) at
 *	this location, it means that 8 64k pages either exist or can be created
 *	from 8K pages in order to make a single free 512k page at the given
 *	index.  Note that when a region is full, it will contribute to the
 *	counts in the region above it.  Thus we will not know what page
 *	size the free pages will be which can be promoted to this new free
 *	page unless we look at all regions below the current region.
 */

/*
 * Note: hpmctr_t is defined in platform vm_dep.h
 * hw_page_map_t contains all the information needed for the page_counters
 * logic. The fields are as follows:
 *
 *	hpm_counters:	dynamically allocated array to hold counter data
 *	hpm_entries:	entries in hpm_counters
 *	hpm_shift:	shift for pnum/array index conv
 *	hpm_base:	PFN mapped to counter index 0
 *	hpm_color_current:	last index in counter array for this color at
 *				which we successfully created a large page
 */
typedef struct hw_page_map {
	hpmctr_t	*hpm_counters;
	size_t		hpm_entries;
	int		hpm_shift;
	pfn_t		hpm_base;
	size_t		*hpm_color_current[MAX_MNODE_MRANGES];
#if defined(__sparc)
	uint_t		pad[4];
#endif
} hw_page_map_t;

/*
 * Element zero is not used, but is allocated for convenience.
 */
static hw_page_map_t *page_counters[MMU_PAGE_SIZES];

/*
 * Cached value of MNODE_RANGE_CNT(mnode).
 * This is a function call in x86.
 */
static int mnode_nranges[MAX_MEM_NODES];
static int mnode_maxmrange[MAX_MEM_NODES];

/*
 * The following macros are convenient ways to get access to the individual
 * elements of the page_counters arrays.  They can be used on both
 * the left side and right side of equations.
 */
#define	PAGE_COUNTERS(mnode, rg_szc, idx)			\
	(page_counters[(rg_szc)][(mnode)].hpm_counters[(idx)])

#define	PAGE_COUNTERS_COUNTERS(mnode, rg_szc) 			\
	(page_counters[(rg_szc)][(mnode)].hpm_counters)

#define	PAGE_COUNTERS_SHIFT(mnode, rg_szc) 			\
	(page_counters[(rg_szc)][(mnode)].hpm_shift)

#define	PAGE_COUNTERS_ENTRIES(mnode, rg_szc) 			\
	(page_counters[(rg_szc)][(mnode)].hpm_entries)

#define	PAGE_COUNTERS_BASE(mnode, rg_szc) 			\
	(page_counters[(rg_szc)][(mnode)].hpm_base)

#define	PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode, rg_szc, g)		\
	(page_counters[(rg_szc)][(mnode)].hpm_color_current[(g)])

#define	PAGE_COUNTERS_CURRENT_COLOR(mnode, rg_szc, color, mrange)	\
	(page_counters[(rg_szc)][(mnode)].				\
	hpm_color_current[(mrange)][(color)])

#define	PNUM_TO_IDX(mnode, rg_szc, pnum)			\
	(((pnum) - PAGE_COUNTERS_BASE((mnode), (rg_szc))) >>	\
		PAGE_COUNTERS_SHIFT((mnode), (rg_szc)))

#define	IDX_TO_PNUM(mnode, rg_szc, index) 			\
	(PAGE_COUNTERS_BASE((mnode), (rg_szc)) +		\
		((index) << PAGE_COUNTERS_SHIFT((mnode), (rg_szc))))

/*
 * Protects the hpm_counters and hpm_color_current memory from changing while
 * looking at page counters information.
 * Grab the write lock to modify what these fields point at.
 * Grab the read lock to prevent any pointers from changing.
 * The write lock can not be held during memory allocation due to a possible
 * recursion deadlock with trying to grab the read lock while the
 * write lock is already held.
 */
krwlock_t page_ctrs_rwlock[MAX_MEM_NODES];


/*
 * initialize cpu_vm_data to point at cache aligned vm_cpu_data_t.
 */
void
cpu_vm_data_init(struct cpu *cp)
{
	if (cp == CPU0) {
		cp->cpu_vm_data = (void *)&vm_cpu_data0;
	} else {
		void	*kmptr;
		int	align;
		size_t	sz;

		align = (L2CACHE_ALIGN) ? L2CACHE_ALIGN : L2CACHE_ALIGN_MAX;
		sz = P2ROUNDUP(sizeof (vm_cpu_data_t), align) + align;
		kmptr = kmem_zalloc(sz, KM_SLEEP);
		cp->cpu_vm_data = (void *) P2ROUNDUP((uintptr_t)kmptr, align);
		((vm_cpu_data_t *)cp->cpu_vm_data)->vc_kmptr = kmptr;
		((vm_cpu_data_t *)cp->cpu_vm_data)->vc_kmsize = sz;
	}
}

/*
 * free cpu_vm_data
 */
void
cpu_vm_data_destroy(struct cpu *cp)
{
	if (cp->cpu_seqid && cp->cpu_vm_data) {
		ASSERT(cp != CPU0);
		kmem_free(((vm_cpu_data_t *)cp->cpu_vm_data)->vc_kmptr,
		    ((vm_cpu_data_t *)cp->cpu_vm_data)->vc_kmsize);
	}
	cp->cpu_vm_data = NULL;
}


/*
 * page size to page size code
 */
int
page_szc(size_t pagesize)
{
	int	i = 0;

	while (hw_page_array[i].hp_size) {
		if (pagesize == hw_page_array[i].hp_size)
			return (i);
		i++;
	}
	return (-1);
}

/*
 * page size to page size code with the restriction that it be a supported
 * user page size.  If it's not a supported user page size, -1 will be returned.
 */
int
page_szc_user_filtered(size_t pagesize)
{
	int szc = page_szc(pagesize);
	if ((szc != -1) && (SZC_2_USERSZC(szc) != -1)) {
		return (szc);
	}
	return (-1);
}

/*
 * Return how many page sizes are available for the user to use.  This is
 * what the hardware supports and not based upon how the OS implements the
 * support of different page sizes.
 *
 * If legacy is non-zero, return the number of pagesizes available to legacy
 * applications. The number of legacy page sizes might be less than the
 * exported user page sizes. This is to prevent legacy applications that
 * use the largest page size returned from getpagesizes(3c) from inadvertantly
 * using the 'new' large pagesizes.
 */
uint_t
page_num_user_pagesizes(int legacy)
{
	if (legacy)
		return (mmu_legacy_page_sizes);
	return (mmu_exported_page_sizes);
}

uint_t
page_num_pagesizes(void)
{
	return (mmu_page_sizes);
}

/*
 * returns the count of the number of base pagesize pages associated with szc
 */
pgcnt_t
page_get_pagecnt(uint_t szc)
{
	if (szc >= mmu_page_sizes)
		panic("page_get_pagecnt: out of range %d", szc);
	return (hw_page_array[szc].hp_pgcnt);
}

size_t
page_get_pagesize(uint_t szc)
{
	if (szc >= mmu_page_sizes)
		panic("page_get_pagesize: out of range %d", szc);
	return (hw_page_array[szc].hp_size);
}

/*
 * Return the size of a page based upon the index passed in.  An index of
 * zero refers to the smallest page size in the system, and as index increases
 * it refers to the next larger supported page size in the system.
 * Note that szc and userszc may not be the same due to unsupported szc's on
 * some systems.
 */
size_t
page_get_user_pagesize(uint_t userszc)
{
	uint_t szc = USERSZC_2_SZC(userszc);

	if (szc >= mmu_page_sizes)
		panic("page_get_user_pagesize: out of range %d", szc);
	return (hw_page_array[szc].hp_size);
}

uint_t
page_get_shift(uint_t szc)
{
	if (szc >= mmu_page_sizes)
		panic("page_get_shift: out of range %d", szc);
	return (PAGE_GET_SHIFT(szc));
}

uint_t
page_get_pagecolors(uint_t szc)
{
	if (szc >= mmu_page_sizes)
		panic("page_get_pagecolors: out of range %d", szc);
	return (PAGE_GET_PAGECOLORS(szc));
}

/*
 * this assigns the desired equivalent color after a split
 */
uint_t
page_correct_color(uchar_t szc, uchar_t nszc, uint_t color,
    uint_t ncolor, uint_t ceq_mask)
{
	ASSERT(nszc > szc);
	ASSERT(szc < mmu_page_sizes);
	ASSERT(color < PAGE_GET_PAGECOLORS(szc));
	ASSERT(ncolor < PAGE_GET_PAGECOLORS(nszc));

	color &= ceq_mask;
	ncolor = PAGE_CONVERT_COLOR(ncolor, szc, nszc);
	return (color | (ncolor & ~ceq_mask));
}

/*
 * The interleaved_mnodes flag is set when mnodes overlap in
 * the physbase..physmax range, but have disjoint slices.
 * In this case hpm_counters is shared by all mnodes.
 * This flag is set dynamically by the platform.
 */
int interleaved_mnodes = 0;

/*
 * Called by startup().
 * Size up the per page size free list counters based on physmax
 * of each node and max_mem_nodes.
 *
 * If interleaved_mnodes is set we need to find the first mnode that
 * exists. hpm_counters for the first mnode will then be shared by
 * all other mnodes. If interleaved_mnodes is not set, just set
 * first=mnode each time. That means there will be no sharing.
 */
size_t
page_ctrs_sz(void)
{
	int	r;		/* region size */
	int	mnode;
	int	firstmn;	/* first mnode that exists */
	int	nranges;
	pfn_t	physbase;
	pfn_t	physmax;
	uint_t	ctrs_sz = 0;
	int 	i;
	pgcnt_t colors_per_szc[MMU_PAGE_SIZES];

	/*
	 * We need to determine how many page colors there are for each
	 * page size in order to allocate memory for any color specific
	 * arrays.
	 */
	for (i = 0; i < mmu_page_sizes; i++) {
		colors_per_szc[i] = PAGE_GET_PAGECOLORS(i);
	}

	for (firstmn = -1, mnode = 0; mnode < max_mem_nodes; mnode++) {

		pgcnt_t r_pgcnt;
		pfn_t   r_base;
		pgcnt_t r_align;

		if (mem_node_config[mnode].exists == 0)
			continue;

		HPM_COUNTERS_LIMITS(mnode, physbase, physmax, firstmn);
		nranges = MNODE_RANGE_CNT(mnode);
		mnode_nranges[mnode] = nranges;
		mnode_maxmrange[mnode] = MNODE_MAX_MRANGE(mnode);

		/*
		 * determine size needed for page counter arrays with
		 * base aligned to large page size.
		 */
		for (r = 1; r < mmu_page_sizes; r++) {
			/* add in space for hpm_color_current */
			ctrs_sz += sizeof (size_t) *
			    colors_per_szc[r] * nranges;

			if (firstmn != mnode)
				continue;

			/* add in space for hpm_counters */
			r_align = page_get_pagecnt(r);
			r_base = physbase;
			r_base &= ~(r_align - 1);
			r_pgcnt = howmany(physmax - r_base + 1, r_align);

			/*
			 * Round up to always allocate on pointer sized
			 * boundaries.
			 */
			ctrs_sz += P2ROUNDUP((r_pgcnt * sizeof (hpmctr_t)),
			    sizeof (hpmctr_t *));
		}
	}

	for (r = 1; r < mmu_page_sizes; r++) {
		ctrs_sz += (max_mem_nodes * sizeof (hw_page_map_t));
	}

	/* add in space for page_ctrs_cands and pcc_color_free */
	ctrs_sz += sizeof (pcc_info_t *) * max_mem_nodes *
	    mmu_page_sizes * NPC_MUTEX;

	for (mnode = 0; mnode < max_mem_nodes; mnode++) {

		if (mem_node_config[mnode].exists == 0)
			continue;

		nranges = mnode_nranges[mnode];
		ctrs_sz += sizeof (pcc_info_t) * nranges *
		    mmu_page_sizes * NPC_MUTEX;
		for (r = 1; r < mmu_page_sizes; r++) {
			ctrs_sz += sizeof (pgcnt_t) * nranges *
			    colors_per_szc[r] * NPC_MUTEX;
		}
	}

	/* ctr_mutex */
	ctrs_sz += (max_mem_nodes * NPC_MUTEX * sizeof (kmutex_t));

	/* size for page list counts */
	PLCNT_SZ(ctrs_sz);

	/*
	 * add some slop for roundups. page_ctrs_alloc will roundup the start
	 * address of the counters to ecache_alignsize boundary for every
	 * memory node.
	 */
	return (ctrs_sz + max_mem_nodes * L2CACHE_ALIGN);
}

caddr_t
page_ctrs_alloc(caddr_t alloc_base)
{
	int	mnode;
	int	mrange, nranges;
	int	r;		/* region size */
	int	i;
	int	firstmn;	/* first mnode that exists */
	pfn_t	physbase;
	pfn_t	physmax;
	pgcnt_t colors_per_szc[MMU_PAGE_SIZES];

	/*
	 * We need to determine how many page colors there are for each
	 * page size in order to allocate memory for any color specific
	 * arrays.
	 */
	for (i = 0; i < mmu_page_sizes; i++) {
		colors_per_szc[i] = PAGE_GET_PAGECOLORS(i);
	}

	for (r = 1; r < mmu_page_sizes; r++) {
		page_counters[r] = (hw_page_map_t *)alloc_base;
		alloc_base += (max_mem_nodes * sizeof (hw_page_map_t));
	}

	/* page_ctrs_cands and pcc_color_free array */
	for (i = 0; i < NPC_MUTEX; i++) {
		for (r = 1; r < mmu_page_sizes; r++) {

			page_ctrs_cands[i][r] = (pcc_info_t **)alloc_base;
			alloc_base += sizeof (pcc_info_t *) * max_mem_nodes;

			for (mnode = 0; mnode < max_mem_nodes; mnode++) {
				pcc_info_t *pi;

				if (mem_node_config[mnode].exists == 0)
					continue;

				nranges = mnode_nranges[mnode];

				pi = (pcc_info_t *)alloc_base;
				alloc_base += sizeof (pcc_info_t) * nranges;
				page_ctrs_cands[i][r][mnode] = pi;

				for (mrange = 0; mrange < nranges; mrange++) {
					pi->pcc_color_free =
					    (pgcnt_t *)alloc_base;
					alloc_base += sizeof (pgcnt_t) *
					    colors_per_szc[r];
					pi++;
				}
			}
		}
	}

	/* ctr_mutex */
	for (i = 0; i < NPC_MUTEX; i++) {
		ctr_mutex[i] = (kmutex_t *)alloc_base;
		alloc_base += (max_mem_nodes * sizeof (kmutex_t));
	}

	/* initialize page list counts */
	PLCNT_INIT(alloc_base);

	for (firstmn = -1, mnode = 0; mnode < max_mem_nodes; mnode++) {

		pgcnt_t r_pgcnt;
		pfn_t	r_base;
		pgcnt_t r_align;
		int	r_shift;
		int	nranges = mnode_nranges[mnode];

		if (mem_node_config[mnode].exists == 0)
			continue;

		HPM_COUNTERS_LIMITS(mnode, physbase, physmax, firstmn);

		for (r = 1; r < mmu_page_sizes; r++) {
			/*
			 * the page_counters base has to be aligned to the
			 * page count of page size code r otherwise the counts
			 * will cross large page boundaries.
			 */
			r_align = page_get_pagecnt(r);
			r_base = physbase;
			/* base needs to be aligned - lower to aligned value */
			r_base &= ~(r_align - 1);
			r_pgcnt = howmany(physmax - r_base + 1, r_align);
			r_shift = PAGE_BSZS_SHIFT(r);

			PAGE_COUNTERS_SHIFT(mnode, r) = r_shift;
			PAGE_COUNTERS_ENTRIES(mnode, r) = r_pgcnt;
			PAGE_COUNTERS_BASE(mnode, r) = r_base;
			for (mrange = 0; mrange < nranges; mrange++) {
				PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode,
				    r, mrange) = (size_t *)alloc_base;
				alloc_base += sizeof (size_t) *
				    colors_per_szc[r];
			}
			for (i = 0; i < colors_per_szc[r]; i++) {
				uint_t color_mask = colors_per_szc[r] - 1;
				pfn_t  pfnum = r_base;
				size_t idx;
				int mrange;
				MEM_NODE_ITERATOR_DECL(it);

				MEM_NODE_ITERATOR_INIT(pfnum, mnode, r, &it);
				if (pfnum == (pfn_t)-1) {
					idx = 0;
				} else {
					PAGE_NEXT_PFN_FOR_COLOR(pfnum, r, i,
					    color_mask, color_mask, &it);
					idx = PNUM_TO_IDX(mnode, r, pfnum);
					idx = (idx >= r_pgcnt) ? 0 : idx;
				}
				for (mrange = 0; mrange < nranges; mrange++) {
					PAGE_COUNTERS_CURRENT_COLOR(mnode,
					    r, i, mrange) = idx;
				}
			}

			/* hpm_counters may be shared by all mnodes */
			if (firstmn == mnode) {
				PAGE_COUNTERS_COUNTERS(mnode, r) =
				    (hpmctr_t *)alloc_base;
				alloc_base +=
				    P2ROUNDUP((sizeof (hpmctr_t) * r_pgcnt),
				    sizeof (hpmctr_t *));
			} else {
				PAGE_COUNTERS_COUNTERS(mnode, r) =
				    PAGE_COUNTERS_COUNTERS(firstmn, r);
			}

			/*
			 * Verify that PNUM_TO_IDX and IDX_TO_PNUM
			 * satisfy the identity requirement.
			 * We should be able to go from one to the other
			 * and get consistent values.
			 */
			ASSERT(PNUM_TO_IDX(mnode, r,
			    (IDX_TO_PNUM(mnode, r, 0))) == 0);
			ASSERT(IDX_TO_PNUM(mnode, r,
			    (PNUM_TO_IDX(mnode, r, r_base))) == r_base);
		}
		/*
		 * Roundup the start address of the page_counters to
		 * cache aligned boundary for every memory node.
		 * page_ctrs_sz() has added some slop for these roundups.
		 */
		alloc_base = (caddr_t)P2ROUNDUP((uintptr_t)alloc_base,
		    L2CACHE_ALIGN);
	}

	/* Initialize other page counter specific data structures. */
	for (mnode = 0; mnode < MAX_MEM_NODES; mnode++) {
		rw_init(&page_ctrs_rwlock[mnode], NULL, RW_DEFAULT, NULL);
	}

	return (alloc_base);
}

/*
 * Functions to adjust region counters for each size free list.
 * Caller is responsible to acquire the ctr_mutex lock if necessary and
 * thus can be called during startup without locks.
 */
/* ARGSUSED */
void
page_ctr_add_internal(int mnode, int mtype, page_t *pp, int flags)
{
	ssize_t		r;	/* region size */
	ssize_t		idx;
	pfn_t		pfnum;
	int		lckidx;

	ASSERT(mnode == PP_2_MEM_NODE(pp));
	ASSERT(mtype == PP_2_MTYPE(pp));

	ASSERT(pp->p_szc < mmu_page_sizes);

	PLCNT_INCR(pp, mnode, mtype, pp->p_szc, flags);

	/* no counter update needed for largest page size */
	if (pp->p_szc >= mmu_page_sizes - 1) {
		return;
	}

	r = pp->p_szc + 1;
	pfnum = pp->p_pagenum;
	lckidx = PP_CTR_LOCK_INDX(pp);

	/*
	 * Increment the count of free pages for the current
	 * region. Continue looping up in region size incrementing
	 * count if the preceeding region is full.
	 */
	while (r < mmu_page_sizes) {
		idx = PNUM_TO_IDX(mnode, r, pfnum);

		ASSERT(idx < PAGE_COUNTERS_ENTRIES(mnode, r));
		ASSERT(PAGE_COUNTERS(mnode, r, idx) < FULL_REGION_CNT(r));

		if (++PAGE_COUNTERS(mnode, r, idx) != FULL_REGION_CNT(r)) {
			break;
		} else {
			int root_mtype = PP_2_MTYPE(PP_GROUPLEADER(pp, r));
			pcc_info_t *cand = &page_ctrs_cands[lckidx][r][mnode]
			    [MTYPE_2_MRANGE(mnode, root_mtype)];

			cand->pcc_pages_free++;
			cand->pcc_color_free[PP_2_BIN_SZC(pp, r)]++;
		}
		r++;
	}
}

void
page_ctr_add(int mnode, int mtype, page_t *pp, int flags)
{
	int		lckidx = PP_CTR_LOCK_INDX(pp);
	kmutex_t	*lock = &ctr_mutex[lckidx][mnode];

	mutex_enter(lock);
	page_ctr_add_internal(mnode, mtype, pp, flags);
	mutex_exit(lock);
}

void
page_ctr_sub_internal(int mnode, int mtype, page_t *pp, int flags)
{
	int		lckidx;
	ssize_t		r;	/* region size */
	ssize_t		idx;
	pfn_t		pfnum;

	ASSERT(mnode == PP_2_MEM_NODE(pp));
	ASSERT(mtype == PP_2_MTYPE(pp));

	ASSERT(pp->p_szc < mmu_page_sizes);

	PLCNT_DECR(pp, mnode, mtype, pp->p_szc, flags);

	/* no counter update needed for largest page size */
	if (pp->p_szc >= mmu_page_sizes - 1) {
		return;
	}

	r = pp->p_szc + 1;
	pfnum = pp->p_pagenum;
	lckidx = PP_CTR_LOCK_INDX(pp);

	/*
	 * Decrement the count of free pages for the current
	 * region. Continue looping up in region size decrementing
	 * count if the preceeding region was full.
	 */
	while (r < mmu_page_sizes) {
		idx = PNUM_TO_IDX(mnode, r, pfnum);

		ASSERT(idx < PAGE_COUNTERS_ENTRIES(mnode, r));
		ASSERT(PAGE_COUNTERS(mnode, r, idx) > 0);

		if (--PAGE_COUNTERS(mnode, r, idx) != FULL_REGION_CNT(r) - 1) {
			break;
		} else {
			int root_mtype = PP_2_MTYPE(PP_GROUPLEADER(pp, r));
			pcc_info_t *cand = &page_ctrs_cands[lckidx][r][mnode]
			    [MTYPE_2_MRANGE(mnode, root_mtype)];

			ASSERT(cand->pcc_pages_free != 0);
			ASSERT(cand->pcc_color_free[PP_2_BIN_SZC(pp, r)] != 0);

			cand->pcc_pages_free--;
			cand->pcc_color_free[PP_2_BIN_SZC(pp, r)]--;
		}
		r++;
	}
}

void
page_ctr_sub(int mnode, int mtype, page_t *pp, int flags)
{
	int		lckidx = PP_CTR_LOCK_INDX(pp);
	kmutex_t	*lock = &ctr_mutex[lckidx][mnode];

	mutex_enter(lock);
	page_ctr_sub_internal(mnode, mtype, pp, flags);
	mutex_exit(lock);
}

/*
 * Adjust page counters following a memory attach, since typically the
 * size of the array needs to change, and the PFN to counter index
 * mapping needs to change.
 *
 * It is possible this mnode did not exist at startup. In that case
 * allocate pcc_info_t and pcc_color_free arrays. Also, allow for nranges
 * to change (a theoretical possibility on x86), which means pcc_color_free
 * arrays must be extended.
 */
uint_t
page_ctrs_adjust(int mnode)
{
	pgcnt_t npgs;
	int	r;		/* region size */
	int	i;
	size_t	pcsz, old_csz;
	hpmctr_t *new_ctr, *old_ctr;
	pfn_t	oldbase, newbase;
	pfn_t	physbase, physmax;
	size_t	old_npgs;
	hpmctr_t *ctr_cache[MMU_PAGE_SIZES];
	size_t	size_cache[MMU_PAGE_SIZES];
	size_t	*color_cache[MMU_PAGE_SIZES][MAX_MNODE_MRANGES];
	size_t	*old_color_array[MAX_MNODE_MRANGES];
	pgcnt_t	colors_per_szc[MMU_PAGE_SIZES];
	pcc_info_t **cands_cache;
	pcc_info_t *old_pi, *pi;
	pgcnt_t *pgcntp;
	int nr, old_nranges, mrange, nranges = MNODE_RANGE_CNT(mnode);
	int cands_cache_nranges;
	int old_maxmrange, new_maxmrange;
	int rc = 0;
	int oldmnode;

	cands_cache = kmem_zalloc(sizeof (pcc_info_t *) * NPC_MUTEX *
	    MMU_PAGE_SIZES, KM_NOSLEEP);
	if (cands_cache == NULL)
		return (ENOMEM);

	i = -1;
	HPM_COUNTERS_LIMITS(mnode, physbase, physmax, i);

	newbase = physbase & ~PC_BASE_ALIGN_MASK;
	npgs = roundup(physmax, PC_BASE_ALIGN) - newbase;

	/* prepare to free non-null pointers on the way out */
	cands_cache_nranges = nranges;
	bzero(ctr_cache, sizeof (ctr_cache));
	bzero(color_cache, sizeof (color_cache));

	/*
	 * We need to determine how many page colors there are for each
	 * page size in order to allocate memory for any color specific
	 * arrays.
	 */
	for (r = 0; r < mmu_page_sizes; r++) {
		colors_per_szc[r] = PAGE_GET_PAGECOLORS(r);
	}

	/*
	 * Preallocate all of the new hpm_counters arrays as we can't
	 * hold the page_ctrs_rwlock as a writer and allocate memory.
	 * If we can't allocate all of the arrays, undo our work so far
	 * and return failure.
	 */
	for (r = 1; r < mmu_page_sizes; r++) {
		pcsz = npgs >> PAGE_BSZS_SHIFT(r);
		size_cache[r] = pcsz;
		ctr_cache[r] = kmem_zalloc(pcsz *
		    sizeof (hpmctr_t), KM_NOSLEEP);
		if (ctr_cache[r] == NULL) {
			rc = ENOMEM;
			goto cleanup;
		}
	}

	/*
	 * Preallocate all of the new color current arrays as we can't
	 * hold the page_ctrs_rwlock as a writer and allocate memory.
	 * If we can't allocate all of the arrays, undo our work so far
	 * and return failure.
	 */
	for (r = 1; r < mmu_page_sizes; r++) {
		for (mrange = 0; mrange < nranges; mrange++) {
			color_cache[r][mrange] = kmem_zalloc(sizeof (size_t) *
			    colors_per_szc[r], KM_NOSLEEP);
			if (color_cache[r][mrange] == NULL) {
				rc = ENOMEM;
				goto cleanup;
			}
		}
	}

	/*
	 * Preallocate all of the new pcc_info_t arrays as we can't
	 * hold the page_ctrs_rwlock as a writer and allocate memory.
	 * If we can't allocate all of the arrays, undo our work so far
	 * and return failure.
	 */
	for (r = 1; r < mmu_page_sizes; r++) {
		for (i = 0; i < NPC_MUTEX; i++) {
			pi = kmem_zalloc(nranges * sizeof (pcc_info_t),
			    KM_NOSLEEP);
			if (pi == NULL) {
				rc = ENOMEM;
				goto cleanup;
			}
			cands_cache[i * MMU_PAGE_SIZES + r] = pi;

			for (mrange = 0; mrange < nranges; mrange++, pi++) {
				pgcntp = kmem_zalloc(colors_per_szc[r] *
				    sizeof (pgcnt_t), KM_NOSLEEP);
				if (pgcntp == NULL) {
					rc = ENOMEM;
					goto cleanup;
				}
				pi->pcc_color_free = pgcntp;
			}
		}
	}

	/*
	 * Grab the write lock to prevent others from walking these arrays
	 * while we are modifying them.
	 */
	PAGE_CTRS_WRITE_LOCK(mnode);

	/*
	 * For interleaved mnodes, find the first mnode
	 * with valid page counters since the current
	 * mnode may have just been added and not have
	 * valid page counters.
	 */
	if (interleaved_mnodes) {
		for (i = 0; i < max_mem_nodes; i++)
			if (PAGE_COUNTERS_COUNTERS(i, 1) != NULL)
				break;
		ASSERT(i < max_mem_nodes);
		oldmnode = i;
	} else
		oldmnode = mnode;

	old_nranges = mnode_nranges[mnode];
	cands_cache_nranges = old_nranges;
	mnode_nranges[mnode] = nranges;
	old_maxmrange = mnode_maxmrange[mnode];
	mnode_maxmrange[mnode] = MNODE_MAX_MRANGE(mnode);
	new_maxmrange = mnode_maxmrange[mnode];

	for (r = 1; r < mmu_page_sizes; r++) {
		PAGE_COUNTERS_SHIFT(mnode, r) = PAGE_BSZS_SHIFT(r);
		old_ctr = PAGE_COUNTERS_COUNTERS(oldmnode, r);
		old_csz = PAGE_COUNTERS_ENTRIES(oldmnode, r);
		oldbase = PAGE_COUNTERS_BASE(oldmnode, r);
		old_npgs = old_csz << PAGE_COUNTERS_SHIFT(oldmnode, r);
		for (mrange = 0; mrange < MAX_MNODE_MRANGES; mrange++) {
			old_color_array[mrange] =
			    PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode,
			    r, mrange);
		}

		pcsz = npgs >> PAGE_COUNTERS_SHIFT(mnode, r);
		new_ctr = ctr_cache[r];
		ctr_cache[r] = NULL;
		if (old_ctr != NULL &&
		    (oldbase + old_npgs > newbase) &&
		    (newbase + npgs > oldbase)) {
			/*
			 * Map the intersection of the old and new
			 * counters into the new array.
			 */
			size_t offset;
			if (newbase > oldbase) {
				offset = (newbase - oldbase) >>
				    PAGE_COUNTERS_SHIFT(mnode, r);
				bcopy(old_ctr + offset, new_ctr,
				    MIN(pcsz, (old_csz - offset)) *
				    sizeof (hpmctr_t));
			} else {
				offset = (oldbase - newbase) >>
				    PAGE_COUNTERS_SHIFT(mnode, r);
				bcopy(old_ctr, new_ctr + offset,
				    MIN(pcsz - offset, old_csz) *
				    sizeof (hpmctr_t));
			}
		}

		PAGE_COUNTERS_COUNTERS(mnode, r) = new_ctr;
		PAGE_COUNTERS_ENTRIES(mnode, r) = pcsz;
		PAGE_COUNTERS_BASE(mnode, r) = newbase;

		/* update shared hpm_counters in other mnodes */
		if (interleaved_mnodes) {
			for (i = 0; i < max_mem_nodes; i++) {
				if ((i == mnode) ||
				    (mem_node_config[i].exists == 0))
					continue;
				ASSERT(
				    PAGE_COUNTERS_COUNTERS(i, r) == old_ctr ||
				    PAGE_COUNTERS_COUNTERS(i, r) == NULL);
				PAGE_COUNTERS_COUNTERS(i, r) = new_ctr;
				PAGE_COUNTERS_ENTRIES(i, r) = pcsz;
				PAGE_COUNTERS_BASE(i, r) = newbase;
			}
		}

		for (mrange = 0; mrange < MAX_MNODE_MRANGES; mrange++) {
			PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode, r, mrange) =
			    color_cache[r][mrange];
			color_cache[r][mrange] = NULL;
		}
		/*
		 * for now, just reset on these events as it's probably
		 * not worthwhile to try and optimize this.
		 */
		for (i = 0; i < colors_per_szc[r]; i++) {
			uint_t color_mask = colors_per_szc[r] - 1;
			int mlo = interleaved_mnodes ? 0 : mnode;
			int mhi = interleaved_mnodes ? max_mem_nodes :
			    (mnode + 1);
			int m;
			pfn_t  pfnum;
			size_t idx;
			MEM_NODE_ITERATOR_DECL(it);

			for (m = mlo; m < mhi; m++) {
				if (mem_node_config[m].exists == 0)
					continue;
				pfnum = newbase;
				MEM_NODE_ITERATOR_INIT(pfnum, m, r, &it);
				if (pfnum == (pfn_t)-1) {
					idx = 0;
				} else {
					PAGE_NEXT_PFN_FOR_COLOR(pfnum, r, i,
					    color_mask, color_mask, &it);
					idx = PNUM_TO_IDX(m, r, pfnum);
					idx = (idx < pcsz) ? idx : 0;
				}
				for (mrange = 0; mrange < nranges; mrange++) {
					if (PAGE_COUNTERS_CURRENT_COLOR_ARRAY(m,
					    r, mrange) != NULL)
						PAGE_COUNTERS_CURRENT_COLOR(m,
						    r, i, mrange) = idx;
				}
			}
		}

		/* cache info for freeing out of the critical path */
		if ((caddr_t)old_ctr >= kernelheap &&
		    (caddr_t)old_ctr < ekernelheap) {
			ctr_cache[r] = old_ctr;
			size_cache[r] = old_csz;
		}
		for (mrange = 0; mrange < MAX_MNODE_MRANGES; mrange++) {
			size_t *tmp = old_color_array[mrange];
			if ((caddr_t)tmp >= kernelheap &&
			    (caddr_t)tmp < ekernelheap) {
				color_cache[r][mrange] = tmp;
			}
		}
		/*
		 * Verify that PNUM_TO_IDX and IDX_TO_PNUM
		 * satisfy the identity requirement.
		 * We should be able to go from one to the other
		 * and get consistent values.
		 */
		ASSERT(PNUM_TO_IDX(mnode, r,
		    (IDX_TO_PNUM(mnode, r, 0))) == 0);
		ASSERT(IDX_TO_PNUM(mnode, r,
		    (PNUM_TO_IDX(mnode, r, newbase))) == newbase);

		/* pcc_info_t and pcc_color_free */
		for (i = 0; i < NPC_MUTEX; i++) {
			pcc_info_t *epi;
			pcc_info_t *eold_pi;

			pi = cands_cache[i * MMU_PAGE_SIZES + r];
			old_pi = page_ctrs_cands[i][r][mnode];
			page_ctrs_cands[i][r][mnode] = pi;
			cands_cache[i * MMU_PAGE_SIZES + r] = old_pi;

			/* preserve old pcc_color_free values, if any */
			if (old_pi == NULL)
				continue;

			/*
			 * when/if x86 does DR, must account for
			 * possible change in range index when
			 * preserving pcc_info
			 */
			epi = &pi[nranges];
			eold_pi = &old_pi[old_nranges];
			if (new_maxmrange > old_maxmrange) {
				pi += new_maxmrange - old_maxmrange;
			} else if (new_maxmrange < old_maxmrange) {
				old_pi += old_maxmrange - new_maxmrange;
			}
			for (; pi < epi && old_pi < eold_pi; pi++, old_pi++) {
				pcc_info_t tmp = *pi;
				*pi = *old_pi;
				*old_pi = tmp;
			}
		}
	}
	PAGE_CTRS_WRITE_UNLOCK(mnode);

	/*
	 * Now that we have dropped the write lock, it is safe to free all
	 * of the memory we have cached above.
	 * We come thru here to free memory when pre-alloc fails, and also to
	 * free old pointers which were recorded while locked.
	 */
cleanup:
	for (r = 1; r < mmu_page_sizes; r++) {
		if (ctr_cache[r] != NULL) {
			kmem_free(ctr_cache[r],
			    size_cache[r] * sizeof (hpmctr_t));
		}
		for (mrange = 0; mrange < MAX_MNODE_MRANGES; mrange++) {
			if (color_cache[r][mrange] != NULL) {
				kmem_free(color_cache[r][mrange],
				    colors_per_szc[r] * sizeof (size_t));
			}
		}
		for (i = 0; i < NPC_MUTEX; i++) {
			pi = cands_cache[i * MMU_PAGE_SIZES + r];
			if (pi == NULL)
				continue;
			nr = cands_cache_nranges;
			for (mrange = 0; mrange < nr; mrange++, pi++) {
				pgcntp = pi->pcc_color_free;
				if (pgcntp == NULL)
					continue;
				if ((caddr_t)pgcntp >= kernelheap &&
				    (caddr_t)pgcntp < ekernelheap) {
					kmem_free(pgcntp,
					    colors_per_szc[r] *
					    sizeof (pgcnt_t));
				}
			}
			pi = cands_cache[i * MMU_PAGE_SIZES + r];
			if ((caddr_t)pi >= kernelheap &&
			    (caddr_t)pi < ekernelheap) {
				kmem_free(pi, nr * sizeof (pcc_info_t));
			}
		}
	}

	kmem_free(cands_cache,
	    sizeof (pcc_info_t *) * NPC_MUTEX * MMU_PAGE_SIZES);
	return (rc);
}

/*
 * Cleanup the hpm_counters field in the page counters
 * array.
 */
void
page_ctrs_cleanup(void)
{
	int r;	/* region size */
	int i;	/* mnode index */

	/*
	 * Get the page counters write lock while we are
	 * setting the page hpm_counters field to NULL
	 * for non-existent mnodes.
	 */
	for (i = 0; i < max_mem_nodes; i++) {
		PAGE_CTRS_WRITE_LOCK(i);
		if (mem_node_config[i].exists) {
			PAGE_CTRS_WRITE_UNLOCK(i);
			continue;
		}
		for (r = 1; r < mmu_page_sizes; r++) {
			PAGE_COUNTERS_COUNTERS(i, r) = NULL;
		}
		PAGE_CTRS_WRITE_UNLOCK(i);
	}
}

#ifdef DEBUG

/*
 * confirm pp is a large page corresponding to szc
 */
void
chk_lpg(page_t *pp, uchar_t szc)
{
	spgcnt_t npgs = page_get_pagecnt(pp->p_szc);
	uint_t noreloc;

	if (npgs == 1) {
		ASSERT(pp->p_szc == 0);
		ASSERT(pp->p_next == pp);
		ASSERT(pp->p_prev == pp);
		return;
	}

	ASSERT(pp->p_vpnext == pp || pp->p_vpnext == NULL);
	ASSERT(pp->p_vpprev == pp || pp->p_vpprev == NULL);

	ASSERT(IS_P2ALIGNED(pp->p_pagenum, npgs));
	ASSERT(pp->p_pagenum == (pp->p_next->p_pagenum - 1));
	ASSERT(pp->p_prev->p_pagenum == (pp->p_pagenum + (npgs - 1)));
	ASSERT(pp->p_prev == (pp + (npgs - 1)));

	/*
	 * Check list of pages.
	 */
	noreloc = PP_ISNORELOC(pp);
	while (npgs--) {
		if (npgs != 0) {
			ASSERT(pp->p_pagenum == pp->p_next->p_pagenum - 1);
			ASSERT(pp->p_next == (pp + 1));
		}
		ASSERT(pp->p_szc == szc);
		ASSERT(PP_ISFREE(pp));
		ASSERT(PP_ISAGED(pp));
		ASSERT(pp->p_vpnext == pp || pp->p_vpnext == NULL);
		ASSERT(pp->p_vpprev == pp || pp->p_vpprev == NULL);
		ASSERT(pp->p_vnode  == NULL);
		ASSERT(PP_ISNORELOC(pp) == noreloc);

		pp = pp->p_next;
	}
}
#endif /* DEBUG */

void
page_freelist_lock(int mnode)
{
	int i;
	for (i = 0; i < NPC_MUTEX; i++) {
		mutex_enter(FPC_MUTEX(mnode, i));
		mutex_enter(CPC_MUTEX(mnode, i));
	}
}

void
page_freelist_unlock(int mnode)
{
	int i;
	for (i = 0; i < NPC_MUTEX; i++) {
		mutex_exit(FPC_MUTEX(mnode, i));
		mutex_exit(CPC_MUTEX(mnode, i));
	}
}

/*
 * add pp to the specified page list. Defaults to head of the page list
 * unless PG_LIST_TAIL is specified.
 */
void
page_list_add(page_t *pp, int flags)
{
	page_t		**ppp;
	kmutex_t	*pcm;
	uint_t		bin, mtype;
	int		mnode;

	ASSERT(PAGE_EXCL(pp) || (flags & PG_LIST_ISINIT));
	ASSERT(PP_ISFREE(pp));
	ASSERT(!hat_page_is_mapped(pp));
	ASSERT(hat_page_getshare(pp) == 0);

	/*
	 * Large pages should be freed via page_list_add_pages().
	 */
	ASSERT(pp->p_szc == 0);

	/*
	 * Don't need to lock the freelist first here
	 * because the page isn't on the freelist yet.
	 * This means p_szc can't change on us.
	 */

	bin = PP_2_BIN(pp);
	mnode = PP_2_MEM_NODE(pp);
	mtype = PP_2_MTYPE(pp);

	if (flags & PG_LIST_ISINIT) {
		/*
		 * PG_LIST_ISINIT is set during system startup (ie. single
		 * threaded), add a page to the free list and add to the
		 * the free region counters w/o any locking
		 */
		ppp = &PAGE_FREELISTS(mnode, 0, bin, mtype);

		/* inline version of page_add() */
		if (*ppp != NULL) {
			pp->p_next = *ppp;
			pp->p_prev = (*ppp)->p_prev;
			(*ppp)->p_prev = pp;
			pp->p_prev->p_next = pp;
		} else
			*ppp = pp;

		page_ctr_add_internal(mnode, mtype, pp, flags);
		VM_STAT_ADD(vmm_vmstats.pladd_free[0]);
	} else {
		pcm = PC_BIN_MUTEX(mnode, bin, flags);

		if (flags & PG_FREE_LIST) {
			VM_STAT_ADD(vmm_vmstats.pladd_free[0]);
			ASSERT(PP_ISAGED(pp));
			ppp = &PAGE_FREELISTS(mnode, 0, bin, mtype);

		} else {
			VM_STAT_ADD(vmm_vmstats.pladd_cache);
			ASSERT(pp->p_vnode);
			ASSERT((pp->p_offset & PAGEOFFSET) == 0);
			ppp = &PAGE_CACHELISTS(mnode, bin, mtype);
		}
		mutex_enter(pcm);
		page_add(ppp, pp);

		if (flags & PG_LIST_TAIL)
			*ppp = (*ppp)->p_next;
		/*
		 * Add counters before releasing pcm mutex to avoid a race with
		 * page_freelist_coalesce and page_freelist_split.
		 */
		page_ctr_add(mnode, mtype, pp, flags);
		mutex_exit(pcm);
	}


#if defined(__sparc)
	if (PP_ISNORELOC(pp)) {
		kcage_freemem_add(1);
	}
#endif
	/*
	 * It is up to the caller to unlock the page!
	 */
	ASSERT(PAGE_EXCL(pp) || (flags & PG_LIST_ISINIT));
}


#ifdef __sparc
/*
 * This routine is only used by kcage_init during system startup.
 * It performs the function of page_list_sub/PP_SETNORELOC/page_list_add
 * without the overhead of taking locks and updating counters.
 */
void
page_list_noreloc_startup(page_t *pp)
{
	page_t		**ppp;
	uint_t		bin;
	int		mnode;
	int		mtype;
	int		flags = 0;

	/*
	 * If this is a large page on the freelist then
	 * break it up into smaller pages.
	 */
	if (pp->p_szc != 0)
		page_boot_demote(pp);

	/*
	 * Get list page is currently on.
	 */
	bin = PP_2_BIN(pp);
	mnode = PP_2_MEM_NODE(pp);
	mtype = PP_2_MTYPE(pp);
	ASSERT(mtype == MTYPE_RELOC);
	ASSERT(pp->p_szc == 0);

	if (PP_ISAGED(pp)) {
		ppp = &PAGE_FREELISTS(mnode, 0, bin, mtype);
		flags |= PG_FREE_LIST;
	} else {
		ppp = &PAGE_CACHELISTS(mnode, bin, mtype);
		flags |= PG_CACHE_LIST;
	}

	ASSERT(*ppp != NULL);

	/*
	 * Delete page from current list.
	 */
	if (*ppp == pp)
		*ppp = pp->p_next;		/* go to next page */
	if (*ppp == pp) {
		*ppp = NULL;			/* page list is gone */
	} else {
		pp->p_prev->p_next = pp->p_next;
		pp->p_next->p_prev = pp->p_prev;
	}

	/*
	 * Decrement page counters
	 */
	page_ctr_sub_internal(mnode, mtype, pp, flags);

	/*
	 * Set no reloc for cage initted pages.
	 */
	PP_SETNORELOC(pp);

	mtype = PP_2_MTYPE(pp);
	ASSERT(mtype == MTYPE_NORELOC);

	/*
	 * Get new list for page.
	 */
	if (PP_ISAGED(pp)) {
		ppp = &PAGE_FREELISTS(mnode, 0, bin, mtype);
	} else {
		ppp = &PAGE_CACHELISTS(mnode, bin, mtype);
	}

	/*
	 * Insert page on new list.
	 */
	if (*ppp == NULL) {
		*ppp = pp;
		pp->p_next = pp->p_prev = pp;
	} else {
		pp->p_next = *ppp;
		pp->p_prev = (*ppp)->p_prev;
		(*ppp)->p_prev = pp;
		pp->p_prev->p_next = pp;
	}

	/*
	 * Increment page counters
	 */
	page_ctr_add_internal(mnode, mtype, pp, flags);

	/*
	 * Update cage freemem counter
	 */
	atomic_inc_ulong(&kcage_freemem);
}
#else	/* __sparc */

/* ARGSUSED */
void
page_list_noreloc_startup(page_t *pp)
{
	panic("page_list_noreloc_startup: should be here only for sparc");
}
#endif

void
page_list_add_pages(page_t *pp, int flags)
{
	kmutex_t *pcm;
	pgcnt_t	pgcnt;
	uint_t	bin, mtype, i;
	int	mnode;

	/* default to freelist/head */
	ASSERT((flags & (PG_CACHE_LIST | PG_LIST_TAIL)) == 0);

	CHK_LPG(pp, pp->p_szc);
	VM_STAT_ADD(vmm_vmstats.pladd_free[pp->p_szc]);

	bin = PP_2_BIN(pp);
	mnode = PP_2_MEM_NODE(pp);
	mtype = PP_2_MTYPE(pp);

	if (flags & PG_LIST_ISINIT) {
		ASSERT(pp->p_szc == mmu_page_sizes - 1);
		page_vpadd(&PAGE_FREELISTS(mnode, pp->p_szc, bin, mtype), pp);
		ASSERT(!PP_ISNORELOC(pp));
		PLCNT_INCR(pp, mnode, mtype, pp->p_szc, flags);
	} else {

		ASSERT(pp->p_szc != 0 && pp->p_szc < mmu_page_sizes);

		pcm = PC_BIN_MUTEX(mnode, bin, PG_FREE_LIST);

		mutex_enter(pcm);
		page_vpadd(&PAGE_FREELISTS(mnode, pp->p_szc, bin, mtype), pp);
		page_ctr_add(mnode, mtype, pp, PG_FREE_LIST);
		mutex_exit(pcm);

		pgcnt = page_get_pagecnt(pp->p_szc);
#if defined(__sparc)
		if (PP_ISNORELOC(pp))
			kcage_freemem_add(pgcnt);
#endif
		for (i = 0; i < pgcnt; i++, pp++)
			page_unlock_nocapture(pp);
	}
}

/*
 * During boot, need to demote a large page to base
 * pagesize pages for seg_kmem for use in boot_alloc()
 */
void
page_boot_demote(page_t *pp)
{
	ASSERT(pp->p_szc != 0);
	ASSERT(PP_ISFREE(pp));
	ASSERT(PP_ISAGED(pp));

	(void) page_demote(PP_2_MEM_NODE(pp),
	    PFN_BASE(pp->p_pagenum, pp->p_szc), 0, pp->p_szc, 0, PC_NO_COLOR,
	    PC_FREE);

	ASSERT(PP_ISFREE(pp));
	ASSERT(PP_ISAGED(pp));
	ASSERT(pp->p_szc == 0);
}

/*
 * Take a particular page off of whatever freelist the page
 * is claimed to be on.
 *
 * NOTE: Only used for PAGESIZE pages.
 */
void
page_list_sub(page_t *pp, int flags)
{
	int		bin;
	uint_t		mtype;
	int		mnode;
	kmutex_t	*pcm;
	page_t		**ppp;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(PP_ISFREE(pp));

	/*
	 * The p_szc field can only be changed by page_promote()
	 * and page_demote(). Only free pages can be promoted and
	 * demoted and the free list MUST be locked during these
	 * operations. So to prevent a race in page_list_sub()
	 * between computing which bin of the freelist lock to
	 * grab and actually grabing the lock we check again that
	 * the bin we locked is still the correct one. Notice that
	 * the p_szc field could have actually changed on us but
	 * if the bin happens to still be the same we are safe.
	 */
try_again:
	bin = PP_2_BIN(pp);
	mnode = PP_2_MEM_NODE(pp);
	pcm = PC_BIN_MUTEX(mnode, bin, flags);
	mutex_enter(pcm);
	if (PP_2_BIN(pp) != bin) {
		mutex_exit(pcm);
		goto try_again;
	}
	mtype = PP_2_MTYPE(pp);

	if (flags & PG_FREE_LIST) {
		VM_STAT_ADD(vmm_vmstats.plsub_free[0]);
		ASSERT(PP_ISAGED(pp));
		ppp = &PAGE_FREELISTS(mnode, pp->p_szc, bin, mtype);
	} else {
		VM_STAT_ADD(vmm_vmstats.plsub_cache);
		ASSERT(!PP_ISAGED(pp));
		ppp = &PAGE_CACHELISTS(mnode, bin, mtype);
	}

	/*
	 * Common PAGESIZE case.
	 *
	 * Note that we locked the freelist. This prevents
	 * any page promotion/demotion operations. Therefore
	 * the p_szc will not change until we drop pcm mutex.
	 */
	if (pp->p_szc == 0) {
		page_sub(ppp, pp);
		/*
		 * Subtract counters before releasing pcm mutex
		 * to avoid race with page_freelist_coalesce.
		 */
		page_ctr_sub(mnode, mtype, pp, flags);
		mutex_exit(pcm);

#if defined(__sparc)
		if (PP_ISNORELOC(pp)) {
			kcage_freemem_sub(1);
		}
#endif
		return;
	}

	/*
	 * Large pages on the cache list are not supported.
	 */
	if (flags & PG_CACHE_LIST)
		panic("page_list_sub: large page on cachelist");

	/*
	 * Slow but rare.
	 *
	 * Somebody wants this particular page which is part
	 * of a large page. In this case we just demote the page
	 * if it's on the freelist.
	 *
	 * We have to drop pcm before locking the entire freelist.
	 * Once we have re-locked the freelist check to make sure
	 * the page hasn't already been demoted or completely
	 * freed.
	 */
	mutex_exit(pcm);
	page_freelist_lock(mnode);
	if (pp->p_szc != 0) {
		/*
		 * Large page is on freelist.
		 */
		(void) page_demote(mnode, PFN_BASE(pp->p_pagenum, pp->p_szc),
		    0, pp->p_szc, 0, PC_NO_COLOR, PC_FREE);
	}
	ASSERT(PP_ISFREE(pp));
	ASSERT(PP_ISAGED(pp));
	ASSERT(pp->p_szc == 0);

	/*
	 * Subtract counters before releasing pcm mutex
	 * to avoid race with page_freelist_coalesce.
	 */
	bin = PP_2_BIN(pp);
	mtype = PP_2_MTYPE(pp);
	ppp = &PAGE_FREELISTS(mnode, pp->p_szc, bin, mtype);

	page_sub(ppp, pp);
	page_ctr_sub(mnode, mtype, pp, flags);
	page_freelist_unlock(mnode);

#if defined(__sparc)
	if (PP_ISNORELOC(pp)) {
		kcage_freemem_sub(1);
	}
#endif
}

void
page_list_sub_pages(page_t *pp, uint_t szc)
{
	kmutex_t *pcm;
	uint_t	bin, mtype;
	int	mnode;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(PP_ISFREE(pp));
	ASSERT(PP_ISAGED(pp));

	/*
	 * See comment in page_list_sub().
	 */
try_again:
	bin = PP_2_BIN(pp);
	mnode = PP_2_MEM_NODE(pp);
	pcm = PC_BIN_MUTEX(mnode, bin, PG_FREE_LIST);
	mutex_enter(pcm);
	if (PP_2_BIN(pp) != bin) {
		mutex_exit(pcm);
		goto	try_again;
	}

	/*
	 * If we're called with a page larger than szc or it got
	 * promoted above szc before we locked the freelist then
	 * drop pcm and re-lock entire freelist. If page still larger
	 * than szc then demote it.
	 */
	if (pp->p_szc > szc) {
		mutex_exit(pcm);
		pcm = NULL;
		page_freelist_lock(mnode);
		if (pp->p_szc > szc) {
			VM_STAT_ADD(vmm_vmstats.plsubpages_szcbig);
			(void) page_demote(mnode,
			    PFN_BASE(pp->p_pagenum, pp->p_szc), 0,
			    pp->p_szc, szc, PC_NO_COLOR, PC_FREE);
		}
		bin = PP_2_BIN(pp);
	}
	ASSERT(PP_ISFREE(pp));
	ASSERT(PP_ISAGED(pp));
	ASSERT(pp->p_szc <= szc);
	ASSERT(pp == PP_PAGEROOT(pp));

	VM_STAT_ADD(vmm_vmstats.plsub_free[pp->p_szc]);

	mtype = PP_2_MTYPE(pp);
	if (pp->p_szc != 0) {
		page_vpsub(&PAGE_FREELISTS(mnode, pp->p_szc, bin, mtype), pp);
		CHK_LPG(pp, pp->p_szc);
	} else {
		VM_STAT_ADD(vmm_vmstats.plsubpages_szc0);
		page_sub(&PAGE_FREELISTS(mnode, pp->p_szc, bin, mtype), pp);
	}
	page_ctr_sub(mnode, mtype, pp, PG_FREE_LIST);

	if (pcm != NULL) {
		mutex_exit(pcm);
	} else {
		page_freelist_unlock(mnode);
	}

#if defined(__sparc)
	if (PP_ISNORELOC(pp)) {
		pgcnt_t	pgcnt;

		pgcnt = page_get_pagecnt(pp->p_szc);
		kcage_freemem_sub(pgcnt);
	}
#endif
}

/*
 * Add the page to the front of a linked list of pages
 * using the p_next & p_prev pointers for the list.
 * The caller is responsible for protecting the list pointers.
 */
void
mach_page_add(page_t **ppp, page_t *pp)
{
	if (*ppp == NULL) {
		pp->p_next = pp->p_prev = pp;
	} else {
		pp->p_next = *ppp;
		pp->p_prev = (*ppp)->p_prev;
		(*ppp)->p_prev = pp;
		pp->p_prev->p_next = pp;
	}
	*ppp = pp;
}

/*
 * Remove this page from a linked list of pages
 * using the p_next & p_prev pointers for the list.
 *
 * The caller is responsible for protecting the list pointers.
 */
void
mach_page_sub(page_t **ppp, page_t *pp)
{
	ASSERT(PP_ISFREE(pp));

	if (*ppp == NULL || pp == NULL)
		panic("mach_page_sub");

	if (*ppp == pp)
		*ppp = pp->p_next;		/* go to next page */

	if (*ppp == pp)
		*ppp = NULL;			/* page list is gone */
	else {
		pp->p_prev->p_next = pp->p_next;
		pp->p_next->p_prev = pp->p_prev;
	}
	pp->p_prev = pp->p_next = pp;		/* make pp a list of one */
}

/*
 * Routine fsflush uses to gradually coalesce the free list into larger pages.
 */
void
page_promote_size(page_t *pp, uint_t cur_szc)
{
	pfn_t pfn;
	int mnode;
	int idx;
	int new_szc = cur_szc + 1;
	int full = FULL_REGION_CNT(new_szc);

	pfn = page_pptonum(pp);
	mnode = PFN_2_MEM_NODE(pfn);

	page_freelist_lock(mnode);

	idx = PNUM_TO_IDX(mnode, new_szc, pfn);
	if (PAGE_COUNTERS(mnode, new_szc, idx) == full)
		(void) page_promote(mnode, pfn, new_szc, PC_FREE, PC_MTYPE_ANY);

	page_freelist_unlock(mnode);
}

static uint_t page_promote_err;
static uint_t page_promote_noreloc_err;

/*
 * Create a single larger page (of szc new_szc) from smaller contiguous pages
 * for the given mnode starting at pfnum. Pages involved are on the freelist
 * before the call and may be returned to the caller if requested, otherwise
 * they will be placed back on the freelist.
 * If flags is PC_ALLOC, then the large page will be returned to the user in
 * a state which is consistent with a page being taken off the freelist.  If
 * we failed to lock the new large page, then we will return NULL to the
 * caller and put the large page on the freelist instead.
 * If flags is PC_FREE, then the large page will be placed on the freelist,
 * and NULL will be returned.
 * The caller is responsible for locking the freelist as well as any other
 * accounting which needs to be done for a returned page.
 *
 * RFE: For performance pass in pp instead of pfnum so
 * 	we can avoid excessive calls to page_numtopp_nolock().
 *	This would depend on an assumption that all contiguous
 *	pages are in the same memseg so we can just add/dec
 *	our pp.
 *
 * Lock ordering:
 *
 *	There is a potential but rare deadlock situation
 *	for page promotion and demotion operations. The problem
 *	is there are two paths into the freelist manager and
 *	they have different lock orders:
 *
 *	page_create()
 *		lock freelist
 *		page_lock(EXCL)
 *		unlock freelist
 *		return
 *		caller drops page_lock
 *
 *	page_free() and page_reclaim()
 *		caller grabs page_lock(EXCL)
 *
 *		lock freelist
 *		unlock freelist
 *		drop page_lock
 *
 *	What prevents a thread in page_create() from deadlocking
 *	with a thread freeing or reclaiming the same page is the
 *	page_trylock() in page_get_freelist(). If the trylock fails
 *	it skips the page.
 *
 *	The lock ordering for promotion and demotion is the same as
 *	for page_create(). Since the same deadlock could occur during
 *	page promotion and freeing or reclaiming of a page on the
 *	cache list we might have to fail the operation and undo what
 *	have done so far. Again this is rare.
 */
page_t *
page_promote(int mnode, pfn_t pfnum, uchar_t new_szc, int flags, int mtype)
{
	page_t		*pp, *pplist, *tpp, *start_pp;
	pgcnt_t		new_npgs, npgs;
	uint_t		bin;
	pgcnt_t		tmpnpgs, pages_left;
	uint_t		noreloc;
	int 		which_list;
	ulong_t		index;
	kmutex_t	*phm;

	/*
	 * General algorithm:
	 * Find the starting page
	 * Walk each page struct removing it from the freelist,
	 * and linking it to all the other pages removed.
	 * Once all pages are off the freelist,
	 * walk the list, modifying p_szc to new_szc and what
	 * ever other info needs to be done to create a large free page.
	 * According to the flags, either return the page or put it
	 * on the freelist.
	 */

	start_pp = page_numtopp_nolock(pfnum);
	ASSERT(start_pp && (start_pp->p_pagenum == pfnum));
	new_npgs = page_get_pagecnt(new_szc);
	ASSERT(IS_P2ALIGNED(pfnum, new_npgs));

	/* don't return page of the wrong mtype */
	if (mtype != PC_MTYPE_ANY && mtype != PP_2_MTYPE(start_pp))
			return (NULL);

	/*
	 * Loop through smaller pages to confirm that all pages
	 * give the same result for PP_ISNORELOC().
	 * We can check this reliably here as the protocol for setting
	 * P_NORELOC requires pages to be taken off the free list first.
	 */
	noreloc = PP_ISNORELOC(start_pp);
	for (pp = start_pp + new_npgs; --pp > start_pp; ) {
		if (noreloc != PP_ISNORELOC(pp)) {
			page_promote_noreloc_err++;
			page_promote_err++;
			return (NULL);
		}
	}

	pages_left = new_npgs;
	pplist = NULL;
	pp = start_pp;

	/* Loop around coalescing the smaller pages into a big page. */
	while (pages_left) {
		/*
		 * Remove from the freelist.
		 */
		ASSERT(PP_ISFREE(pp));
		bin = PP_2_BIN(pp);
		ASSERT(mnode == PP_2_MEM_NODE(pp));
		mtype = PP_2_MTYPE(pp);
		if (PP_ISAGED(pp)) {

			/*
			 * PG_FREE_LIST
			 */
			if (pp->p_szc) {
				page_vpsub(&PAGE_FREELISTS(mnode,
				    pp->p_szc, bin, mtype), pp);
			} else {
				mach_page_sub(&PAGE_FREELISTS(mnode, 0,
				    bin, mtype), pp);
			}
			which_list = PG_FREE_LIST;
		} else {
			ASSERT(pp->p_szc == 0);

			/*
			 * PG_CACHE_LIST
			 *
			 * Since this page comes from the
			 * cachelist, we must destroy the
			 * vnode association.
			 */
			if (!page_trylock(pp, SE_EXCL)) {
				goto fail_promote;
			}

			/*
			 * We need to be careful not to deadlock
			 * with another thread in page_lookup().
			 * The page_lookup() thread could be holding
			 * the same phm that we need if the two
			 * pages happen to hash to the same phm lock.
			 * At this point we have locked the entire
			 * freelist and page_lookup() could be trying
			 * to grab a freelist lock.
			 */
			index = PAGE_HASH_FUNC(pp->p_vnode, pp->p_offset);
			phm = PAGE_HASH_MUTEX(index);
			if (!mutex_tryenter(phm)) {
				page_unlock_nocapture(pp);
				goto fail_promote;
			}

			mach_page_sub(&PAGE_CACHELISTS(mnode, bin, mtype), pp);
			page_hashout(pp, phm);
			mutex_exit(phm);
			PP_SETAGED(pp);
			page_unlock_nocapture(pp);
			which_list = PG_CACHE_LIST;
		}
		page_ctr_sub(mnode, mtype, pp, which_list);

		/*
		 * Concatenate the smaller page(s) onto
		 * the large page list.
		 */
		tmpnpgs = npgs = page_get_pagecnt(pp->p_szc);
		pages_left -= npgs;
		tpp = pp;
		while (npgs--) {
			tpp->p_szc = new_szc;
			tpp = tpp->p_next;
		}
		page_list_concat(&pplist, &pp);
		pp += tmpnpgs;
	}
	CHK_LPG(pplist, new_szc);

	/*
	 * return the page to the user if requested
	 * in the properly locked state.
	 */
	if (flags == PC_ALLOC && (page_trylock_cons(pplist, SE_EXCL))) {
		return (pplist);
	}

	/*
	 * Otherwise place the new large page on the freelist
	 */
	bin = PP_2_BIN(pplist);
	mnode = PP_2_MEM_NODE(pplist);
	mtype = PP_2_MTYPE(pplist);
	page_vpadd(&PAGE_FREELISTS(mnode, new_szc, bin, mtype), pplist);

	page_ctr_add(mnode, mtype, pplist, PG_FREE_LIST);
	return (NULL);

fail_promote:
	/*
	 * A thread must have still been freeing or
	 * reclaiming the page on the cachelist.
	 * To prevent a deadlock undo what we have
	 * done sofar and return failure. This
	 * situation can only happen while promoting
	 * PAGESIZE pages.
	 */
	page_promote_err++;
	while (pplist) {
		pp = pplist;
		mach_page_sub(&pplist, pp);
		pp->p_szc = 0;
		bin = PP_2_BIN(pp);
		mtype = PP_2_MTYPE(pp);
		mach_page_add(&PAGE_FREELISTS(mnode, 0, bin, mtype), pp);
		page_ctr_add(mnode, mtype, pp, PG_FREE_LIST);
	}
	return (NULL);

}

/*
 * Break up a large page into smaller size pages.
 * Pages involved are on the freelist before the call and may
 * be returned to the caller if requested, otherwise they will
 * be placed back on the freelist.
 * The caller is responsible for locking the freelist as well as any other
 * accounting which needs to be done for a returned page.
 * If flags is not PC_ALLOC, the color argument is ignored, and thus
 * technically, any value may be passed in but PC_NO_COLOR is the standard
 * which should be followed for clarity's sake.
 * Returns a page whose pfn is < pfnmax
 */
page_t *
page_demote(int mnode, pfn_t pfnum, pfn_t pfnmax, uchar_t cur_szc,
    uchar_t new_szc, int color, int flags)
{
	page_t	*pp, *pplist, *npplist;
	pgcnt_t	npgs, n;
	uint_t	bin;
	uint_t	mtype;
	page_t	*ret_pp = NULL;

	ASSERT(cur_szc != 0);
	ASSERT(new_szc < cur_szc);

	pplist = page_numtopp_nolock(pfnum);
	ASSERT(pplist != NULL);

	ASSERT(pplist->p_szc == cur_szc);

	bin = PP_2_BIN(pplist);
	ASSERT(mnode == PP_2_MEM_NODE(pplist));
	mtype = PP_2_MTYPE(pplist);
	page_vpsub(&PAGE_FREELISTS(mnode, cur_szc, bin, mtype), pplist);

	CHK_LPG(pplist, cur_szc);
	page_ctr_sub(mnode, mtype, pplist, PG_FREE_LIST);

	/*
	 * Number of PAGESIZE pages for smaller new_szc
	 * page.
	 */
	npgs = page_get_pagecnt(new_szc);

	while (pplist) {
		pp = pplist;

		ASSERT(pp->p_szc == cur_szc);

		/*
		 * We either break it up into PAGESIZE pages or larger.
		 */
		if (npgs == 1) {	/* PAGESIZE case */
			mach_page_sub(&pplist, pp);
			ASSERT(pp->p_szc == cur_szc);
			ASSERT(new_szc == 0);
			ASSERT(mnode == PP_2_MEM_NODE(pp));
			pp->p_szc = new_szc;
			bin = PP_2_BIN(pp);
			if ((bin == color) && (flags == PC_ALLOC) &&
			    (ret_pp == NULL) && (pfnmax == 0 ||
			    pp->p_pagenum < pfnmax) &&
			    page_trylock_cons(pp, SE_EXCL)) {
				ret_pp = pp;
			} else {
				mtype = PP_2_MTYPE(pp);
				mach_page_add(&PAGE_FREELISTS(mnode, 0, bin,
				    mtype), pp);
				page_ctr_add(mnode, mtype, pp, PG_FREE_LIST);
			}
		} else {
			page_t *try_to_return_this_page = NULL;
			int count = 0;

			/*
			 * Break down into smaller lists of pages.
			 */
			page_list_break(&pplist, &npplist, npgs);

			pp = pplist;
			n = npgs;
			while (n--) {
				ASSERT(pp->p_szc == cur_szc);
				/*
				 * Check whether all the pages in this list
				 * fit the request criteria.
				 */
				if (pfnmax == 0 || pp->p_pagenum < pfnmax) {
					count++;
				}
				pp->p_szc = new_szc;
				pp = pp->p_next;
			}

			if (count == npgs &&
			    (pfnmax == 0 || pp->p_pagenum < pfnmax)) {
				try_to_return_this_page = pp;
			}

			CHK_LPG(pplist, new_szc);

			bin = PP_2_BIN(pplist);
			if (try_to_return_this_page)
				ASSERT(mnode ==
				    PP_2_MEM_NODE(try_to_return_this_page));
			if ((bin == color) && (flags == PC_ALLOC) &&
			    (ret_pp == NULL) && try_to_return_this_page &&
			    page_trylock_cons(try_to_return_this_page,
			    SE_EXCL)) {
				ret_pp = try_to_return_this_page;
			} else {
				mtype = PP_2_MTYPE(pp);
				page_vpadd(&PAGE_FREELISTS(mnode, new_szc,
				    bin, mtype), pplist);

				page_ctr_add(mnode, mtype, pplist,
				    PG_FREE_LIST);
			}
			pplist = npplist;
		}
	}
	return (ret_pp);
}

int mpss_coalesce_disable = 0;

/*
 * Coalesce free pages into a page of the given szc and color if possible.
 * Return the pointer to the page created, otherwise, return NULL.
 *
 * If pfnhi is non-zero, search for large page with pfn range less than pfnhi.
 */
page_t *
page_freelist_coalesce(int mnode, uchar_t szc, uint_t color, uint_t ceq_mask,
    int mtype, pfn_t pfnhi)
{
	int 	r = szc;		/* region size */
	int	mrange;
	uint_t 	full, bin, color_mask, wrap = 0;
	pfn_t	pfnum, lo, hi;
	size_t	len, idx, idx0;
	pgcnt_t	cands = 0, szcpgcnt = page_get_pagecnt(szc);
	page_t	*ret_pp;
	MEM_NODE_ITERATOR_DECL(it);
#if defined(__sparc)
	pfn_t pfnum0, nlo, nhi;
#endif

	if (mpss_coalesce_disable) {
		ASSERT(szc < MMU_PAGE_SIZES);
		VM_STAT_ADD(vmm_vmstats.page_ctrs_coalesce[szc][0]);
		return (NULL);
	}

	ASSERT(szc < mmu_page_sizes);
	color_mask = PAGE_GET_PAGECOLORS(szc) - 1;
	ASSERT(ceq_mask <= color_mask);
	ASSERT(color <= color_mask);
	color &= ceq_mask;

	/* Prevent page_counters dynamic memory from being freed */
	rw_enter(&page_ctrs_rwlock[mnode], RW_READER);

	mrange = MTYPE_2_MRANGE(mnode, mtype);
	ASSERT(mrange < mnode_nranges[mnode]);
	VM_STAT_ADD(vmm_vmstats.page_ctrs_coalesce[r][mrange]);

	/* get pfn range for mtype */
	len = PAGE_COUNTERS_ENTRIES(mnode, r);
	MNODETYPE_2_PFN(mnode, mtype, lo, hi);
	hi++;

	/* use lower limit if given */
	if (pfnhi != PFNNULL && pfnhi < hi)
		hi = pfnhi;

	/* round to szcpgcnt boundaries */
	lo = P2ROUNDUP(lo, szcpgcnt);
	MEM_NODE_ITERATOR_INIT(lo, mnode, szc, &it);
	if (lo == (pfn_t)-1) {
		rw_exit(&page_ctrs_rwlock[mnode]);
		return (NULL);
	}
	hi = hi & ~(szcpgcnt - 1);

	/* set lo to the closest pfn of the right color */
	if (((PFN_2_COLOR(lo, szc, &it) ^ color) & ceq_mask) ||
	    (interleaved_mnodes && PFN_2_MEM_NODE(lo) != mnode)) {
		PAGE_NEXT_PFN_FOR_COLOR(lo, szc, color, ceq_mask, color_mask,
		    &it);
	}

	if (hi <= lo) {
		rw_exit(&page_ctrs_rwlock[mnode]);
		return (NULL);
	}

	full = FULL_REGION_CNT(r);

	/* calculate the number of page candidates and initial search index */
	bin = color;
	idx0 = (size_t)(-1);
	do {
		pgcnt_t acand;

		PGCTRS_CANDS_GETVALUECOLOR(mnode, mrange, r, bin, acand);
		if (acand) {
			idx = PAGE_COUNTERS_CURRENT_COLOR(mnode,
			    r, bin, mrange);
			idx0 = MIN(idx0, idx);
			cands += acand;
		}
		bin = ADD_MASKED(bin, 1, ceq_mask, color_mask);
	} while (bin != color);

	if (cands == 0) {
		VM_STAT_ADD(vmm_vmstats.page_ctrs_cands_skip[r][mrange]);
		rw_exit(&page_ctrs_rwlock[mnode]);
		return (NULL);
	}

	pfnum = IDX_TO_PNUM(mnode, r, idx0);
	if (pfnum < lo || pfnum >= hi) {
		pfnum = lo;
	} else {
		MEM_NODE_ITERATOR_INIT(pfnum, mnode, szc, &it);
		if (pfnum == (pfn_t)-1) {
			pfnum = lo;
			MEM_NODE_ITERATOR_INIT(pfnum, mnode, szc, &it);
			ASSERT(pfnum != (pfn_t)-1);
		} else if ((PFN_2_COLOR(pfnum, szc, &it) ^ color) & ceq_mask ||
		    (interleaved_mnodes && PFN_2_MEM_NODE(pfnum) != mnode)) {
			/* invalid color, get the closest correct pfn */
			PAGE_NEXT_PFN_FOR_COLOR(pfnum, szc, color, ceq_mask,
			    color_mask, &it);
			if (pfnum >= hi) {
				pfnum = lo;
				MEM_NODE_ITERATOR_INIT(pfnum, mnode, szc, &it);
			}
		}
	}

	/* set starting index */
	idx0 = PNUM_TO_IDX(mnode, r, pfnum);
	ASSERT(idx0 < len);

#if defined(__sparc)
	pfnum0 = pfnum;		/* page corresponding to idx0 */
	nhi = 0;		/* search kcage ranges */
#endif

	for (idx = idx0; wrap == 0 || (idx < idx0 && wrap < 2); ) {

#if defined(__sparc)
		/*
		 * Find lowest intersection of kcage ranges and mnode.
		 * MTYPE_NORELOC means look in the cage, otherwise outside.
		 */
		if (nhi <= pfnum) {
			if (kcage_next_range(mtype == MTYPE_NORELOC, pfnum,
			    (wrap == 0 ? hi : pfnum0), &nlo, &nhi))
				goto wrapit;

			/* jump to the next page in the range */
			if (pfnum < nlo) {
				pfnum = P2ROUNDUP(nlo, szcpgcnt);
				MEM_NODE_ITERATOR_INIT(pfnum, mnode, szc, &it);
				idx = PNUM_TO_IDX(mnode, r, pfnum);
				if (idx >= len || pfnum >= hi)
					goto wrapit;
				if ((PFN_2_COLOR(pfnum, szc, &it) ^ color) &
				    ceq_mask)
					goto next;
				if (interleaved_mnodes &&
				    PFN_2_MEM_NODE(pfnum) != mnode)
					goto next;
			}
		}
#endif

		if (PAGE_COUNTERS(mnode, r, idx) != full)
			goto next;

		/*
		 * RFE: For performance maybe we can do something less
		 *	brutal than locking the entire freelist. So far
		 * 	this doesn't seem to be a performance problem?
		 */
		page_freelist_lock(mnode);
		if (PAGE_COUNTERS(mnode, r, idx) == full) {
			ret_pp =
			    page_promote(mnode, pfnum, r, PC_ALLOC, mtype);
			if (ret_pp != NULL) {
				VM_STAT_ADD(vmm_vmstats.pfc_coalok[r][mrange]);
				PAGE_COUNTERS_CURRENT_COLOR(mnode, r,
				    PFN_2_COLOR(pfnum, szc, &it), mrange) = idx;
				page_freelist_unlock(mnode);
				rw_exit(&page_ctrs_rwlock[mnode]);
#if defined(__sparc)
				if (PP_ISNORELOC(ret_pp)) {
					pgcnt_t npgs;

					npgs = page_get_pagecnt(ret_pp->p_szc);
					kcage_freemem_sub(npgs);
				}
#endif
				return (ret_pp);
			}
		} else {
			VM_STAT_ADD(vmm_vmstats.page_ctrs_changed[r][mrange]);
		}

		page_freelist_unlock(mnode);
		/*
		 * No point looking for another page if we've
		 * already tried all of the ones that
		 * page_ctr_cands indicated.  Stash off where we left
		 * off.
		 * Note: this is not exact since we don't hold the
		 * page_freelist_locks before we initially get the
		 * value of cands for performance reasons, but should
		 * be a decent approximation.
		 */
		if (--cands == 0) {
			PAGE_COUNTERS_CURRENT_COLOR(mnode, r, color, mrange) =
			    idx;
			break;
		}
next:
		PAGE_NEXT_PFN_FOR_COLOR(pfnum, szc, color, ceq_mask,
		    color_mask, &it);
		idx = PNUM_TO_IDX(mnode, r, pfnum);
		if (idx >= len || pfnum >= hi) {
wrapit:
			pfnum = lo;
			MEM_NODE_ITERATOR_INIT(pfnum, mnode, szc, &it);
			idx = PNUM_TO_IDX(mnode, r, pfnum);
			wrap++;
#if defined(__sparc)
			nhi = 0;	/* search kcage ranges */
#endif
		}
	}

	rw_exit(&page_ctrs_rwlock[mnode]);
	VM_STAT_ADD(vmm_vmstats.page_ctrs_failed[r][mrange]);
	return (NULL);
}

/*
 * For the given mnode, promote as many small pages to large pages as possible.
 * mnode can be -1, which means do them all
 */
void
page_freelist_coalesce_all(int mnode)
{
	int 	r;		/* region size */
	int 	idx, full;
	size_t	len;
	int doall = interleaved_mnodes || mnode < 0;
	int mlo = doall ? 0 : mnode;
	int mhi = doall ? max_mem_nodes : (mnode + 1);

	VM_STAT_ADD(vmm_vmstats.page_ctrs_coalesce_all);

	if (mpss_coalesce_disable) {
		return;
	}

	/*
	 * Lock the entire freelist and coalesce what we can.
	 *
	 * Always promote to the largest page possible
	 * first to reduce the number of page promotions.
	 */
	for (mnode = mlo; mnode < mhi; mnode++) {
		rw_enter(&page_ctrs_rwlock[mnode], RW_READER);
		page_freelist_lock(mnode);
	}
	for (r = mmu_page_sizes - 1; r > 0; r--) {
		for (mnode = mlo; mnode < mhi; mnode++) {
			pgcnt_t cands = 0;
			int mrange, nranges = mnode_nranges[mnode];

			for (mrange = 0; mrange < nranges; mrange++) {
				PGCTRS_CANDS_GETVALUE(mnode, mrange, r, cands);
				if (cands != 0)
					break;
			}
			if (cands == 0) {
				VM_STAT_ADD(vmm_vmstats.
				    page_ctrs_cands_skip_all);
				continue;
			}

			full = FULL_REGION_CNT(r);
			len  = PAGE_COUNTERS_ENTRIES(mnode, r);

			for (idx = 0; idx < len; idx++) {
				if (PAGE_COUNTERS(mnode, r, idx) == full) {
					pfn_t pfnum =
					    IDX_TO_PNUM(mnode, r, idx);
					int tmnode = interleaved_mnodes ?
					    PFN_2_MEM_NODE(pfnum) : mnode;

					ASSERT(pfnum >=
					    mem_node_config[tmnode].physbase &&
					    pfnum <
					    mem_node_config[tmnode].physmax);

					(void) page_promote(tmnode,
					    pfnum, r, PC_FREE, PC_MTYPE_ANY);
				}
			}
			/* shared hpm_counters covers all mnodes, so we quit */
			if (interleaved_mnodes)
				break;
		}
	}
	for (mnode = mlo; mnode < mhi; mnode++) {
		page_freelist_unlock(mnode);
		rw_exit(&page_ctrs_rwlock[mnode]);
	}
}

/*
 * This is where all polices for moving pages around
 * to different page size free lists is implemented.
 * Returns 1 on success, 0 on failure.
 *
 * So far these are the priorities for this algorithm in descending
 * order:
 *
 *	1) When servicing a request try to do so with a free page
 *	   from next size up. Helps defer fragmentation as long
 *	   as possible.
 *
 *	2) Page coalesce on demand. Only when a freelist
 *	   larger than PAGESIZE is empty and step 1
 *	   will not work since all larger size lists are
 *	   also empty.
 *
 * If pfnhi is non-zero, search for large page with pfn range less than pfnhi.
 */

page_t *
page_freelist_split(uchar_t szc, uint_t color, int mnode, int mtype,
    pfn_t pfnlo, pfn_t pfnhi, page_list_walker_t *plw)
{
	uchar_t nszc = szc + 1;
	uint_t 	bin, sbin, bin_prev;
	page_t	*pp, *firstpp;
	page_t	*ret_pp = NULL;
	uint_t  color_mask;

	if (nszc == mmu_page_sizes)
		return (NULL);

	ASSERT(nszc < mmu_page_sizes);
	color_mask = PAGE_GET_PAGECOLORS(nszc) - 1;
	bin = sbin = PAGE_GET_NSZ_COLOR(szc, color);
	bin_prev = (plw->plw_bin_split_prev == color) ? INVALID_COLOR :
	    PAGE_GET_NSZ_COLOR(szc, plw->plw_bin_split_prev);

	VM_STAT_ADD(vmm_vmstats.pfs_req[szc]);
	/*
	 * First try to break up a larger page to fill current size freelist.
	 */
	while (plw->plw_bins[nszc] != 0) {

		ASSERT(nszc < mmu_page_sizes);

		/*
		 * If page found then demote it.
		 */
		if (PAGE_FREELISTS(mnode, nszc, bin, mtype)) {
			page_freelist_lock(mnode);
			firstpp = pp = PAGE_FREELISTS(mnode, nszc, bin, mtype);

			/*
			 * If pfnhi is not PFNNULL, look for large page below
			 * pfnhi. PFNNULL signifies no pfn requirement.
			 */
			if (pp &&
			    ((pfnhi != PFNNULL && pp->p_pagenum >= pfnhi) ||
			    (pfnlo != PFNNULL && pp->p_pagenum < pfnlo))) {
				do {
					pp = pp->p_vpnext;
					if (pp == firstpp) {
						pp = NULL;
						break;
					}
				} while ((pfnhi != PFNNULL &&
				    pp->p_pagenum >= pfnhi) ||
				    (pfnlo != PFNNULL &&
				    pp->p_pagenum < pfnlo));

				if (pfnhi != PFNNULL && pp != NULL)
					ASSERT(pp->p_pagenum < pfnhi);

				if (pfnlo != PFNNULL && pp != NULL)
					ASSERT(pp->p_pagenum >= pfnlo);
			}
			if (pp) {
				uint_t ccolor = page_correct_color(szc, nszc,
				    color, bin, plw->plw_ceq_mask[szc]);

				ASSERT(pp->p_szc == nszc);
				VM_STAT_ADD(vmm_vmstats.pfs_demote[nszc]);
				ret_pp = page_demote(mnode, pp->p_pagenum,
				    pfnhi, pp->p_szc, szc, ccolor, PC_ALLOC);
				if (ret_pp) {
					page_freelist_unlock(mnode);
#if defined(__sparc)
					if (PP_ISNORELOC(ret_pp)) {
						pgcnt_t npgs;

						npgs = page_get_pagecnt(
						    ret_pp->p_szc);
						kcage_freemem_sub(npgs);
					}
#endif
					return (ret_pp);
				}
			}
			page_freelist_unlock(mnode);
		}

		/* loop through next size bins */
		bin = ADD_MASKED(bin, 1, plw->plw_ceq_mask[nszc], color_mask);
		plw->plw_bins[nszc]--;

		if (bin == sbin) {
			uchar_t nnszc = nszc + 1;

			/* we are done with this page size - check next */
			if (plw->plw_bins[nnszc] == 0)
				/* we have already checked next size bins */
				break;

			bin = sbin = PAGE_GET_NSZ_COLOR(nszc, bin);
			if (bin_prev != INVALID_COLOR) {
				bin_prev = PAGE_GET_NSZ_COLOR(nszc, bin_prev);
				if (!((bin ^ bin_prev) &
				    plw->plw_ceq_mask[nnszc]))
					break;
			}
			ASSERT(nnszc < mmu_page_sizes);
			color_mask = PAGE_GET_PAGECOLORS(nnszc) - 1;
			nszc = nnszc;
			ASSERT(nszc < mmu_page_sizes);
		}
	}

	return (ret_pp);
}

/*
 * Helper routine used only by the freelist code to lock
 * a page. If the page is a large page then it succeeds in
 * locking all the constituent pages or none at all.
 * Returns 1 on sucess, 0 on failure.
 */
static int
page_trylock_cons(page_t *pp, se_t se)
{
	page_t	*tpp, *first_pp = pp;

	/*
	 * Fail if can't lock first or only page.
	 */
	if (!page_trylock(pp, se)) {
		return (0);
	}

	/*
	 * PAGESIZE: common case.
	 */
	if (pp->p_szc == 0) {
		return (1);
	}

	/*
	 * Large page case.
	 */
	tpp = pp->p_next;
	while (tpp != pp) {
		if (!page_trylock(tpp, se)) {
			/*
			 * On failure unlock what we have locked so far.
			 * We want to avoid attempting to capture these
			 * pages as the pcm mutex may be held which could
			 * lead to a recursive mutex panic.
			 */
			while (first_pp != tpp) {
				page_unlock_nocapture(first_pp);
				first_pp = first_pp->p_next;
			}
			return (0);
		}
		tpp = tpp->p_next;
	}
	return (1);
}

/*
 * init context for walking page lists
 * Called when a page of the given szc in unavailable. Sets markers
 * for the beginning of the search to detect when search has
 * completed a full cycle. Sets flags for splitting larger pages
 * and coalescing smaller pages. Page walking procedes until a page
 * of the desired equivalent color is found.
 */
void
page_list_walk_init(uchar_t szc, uint_t flags, uint_t bin, int can_split,
    int use_ceq, page_list_walker_t *plw)
{
	uint_t  nszc, ceq_mask, colors;
	uchar_t ceq = use_ceq ? colorequivszc[szc] : 0;

	ASSERT(szc < mmu_page_sizes);
	colors = PAGE_GET_PAGECOLORS(szc);

	plw->plw_colors = colors;
	plw->plw_color_mask = colors - 1;
	plw->plw_bin_marker = plw->plw_bin0 = bin;
	plw->plw_bin_split_prev = bin;
	plw->plw_bin_step = (szc == 0) ? vac_colors : 1;

	/*
	 * if vac aliasing is possible make sure lower order color
	 * bits are never ignored
	 */
	if (vac_colors > 1)
		ceq &= 0xf0;

	/*
	 * calculate the number of non-equivalent colors and
	 * color equivalency mask
	 */
	plw->plw_ceq_dif = colors >> ((ceq >> 4) + (ceq & 0xf));
	ASSERT(szc > 0 || plw->plw_ceq_dif >= vac_colors);
	ASSERT(plw->plw_ceq_dif > 0);
	plw->plw_ceq_mask[szc] = (plw->plw_ceq_dif - 1) << (ceq & 0xf);

	if (flags & PG_MATCH_COLOR) {
		if (cpu_page_colors <  0) {
			/*
			 * this is a heterogeneous machine with different CPUs
			 * having different size e$ (not supported for ni2/rock
			 */
			uint_t cpucolors = CPUSETSIZE() >> PAGE_GET_SHIFT(szc);
			cpucolors = MAX(cpucolors, 1);
			ceq_mask = plw->plw_color_mask & (cpucolors - 1);
			plw->plw_ceq_mask[szc] =
			    MIN(ceq_mask, plw->plw_ceq_mask[szc]);
		}
		plw->plw_ceq_dif = 1;
	}

	/* we can split pages in the freelist, but not the cachelist */
	if (can_split) {
		plw->plw_do_split = (szc + 1 < mmu_page_sizes) ? 1 : 0;

		/* set next szc color masks and number of free list bins */
		for (nszc = szc + 1; nszc < mmu_page_sizes; nszc++, szc++) {
			plw->plw_ceq_mask[nszc] = PAGE_GET_NSZ_MASK(szc,
			    plw->plw_ceq_mask[szc]);
			plw->plw_bins[nszc] = PAGE_GET_PAGECOLORS(nszc);
		}
		plw->plw_ceq_mask[nszc] = INVALID_MASK;
		plw->plw_bins[nszc] = 0;

	} else {
		ASSERT(szc == 0);
		plw->plw_do_split = 0;
		plw->plw_bins[1] = 0;
		plw->plw_ceq_mask[1] = INVALID_MASK;
	}
}

/*
 * set mark to flag where next split should occur
 */
#define	PAGE_SET_NEXT_SPLIT_MARKER(szc, nszc, bin, plw) {		     \
	uint_t bin_nsz = PAGE_GET_NSZ_COLOR(szc, bin);			     \
	uint_t bin0_nsz = PAGE_GET_NSZ_COLOR(szc, plw->plw_bin0);	     \
	uint_t neq_mask = ~plw->plw_ceq_mask[nszc] & plw->plw_color_mask;    \
	plw->plw_split_next =						     \
		INC_MASKED(bin_nsz, neq_mask, plw->plw_color_mask);	     \
	if (!((plw->plw_split_next ^ bin0_nsz) & plw->plw_ceq_mask[nszc])) { \
		plw->plw_split_next =					     \
		INC_MASKED(plw->plw_split_next,				     \
		    neq_mask, plw->plw_color_mask);			     \
	}								     \
}

uint_t
page_list_walk_next_bin(uchar_t szc, uint_t bin, page_list_walker_t *plw)
{
	uint_t  neq_mask = ~plw->plw_ceq_mask[szc] & plw->plw_color_mask;
	uint_t  bin0_nsz, nbin_nsz, nbin0, nbin;
	uchar_t nszc = szc + 1;

	nbin = ADD_MASKED(bin,
	    plw->plw_bin_step, neq_mask, plw->plw_color_mask);

	if (plw->plw_do_split) {
		plw->plw_bin_split_prev = bin;
		PAGE_SET_NEXT_SPLIT_MARKER(szc, nszc, bin, plw);
		plw->plw_do_split = 0;
	}

	if (szc == 0) {
		if (plw->plw_count != 0 || plw->plw_ceq_dif == vac_colors) {
			if (nbin == plw->plw_bin0 &&
			    (vac_colors == 1 || nbin != plw->plw_bin_marker)) {
				nbin = ADD_MASKED(nbin, plw->plw_bin_step,
				    neq_mask, plw->plw_color_mask);
				plw->plw_bin_split_prev = plw->plw_bin0;
			}

			if (vac_colors > 1 && nbin == plw->plw_bin_marker) {
				plw->plw_bin_marker =
				    nbin = INC_MASKED(nbin, neq_mask,
				    plw->plw_color_mask);
				plw->plw_bin_split_prev = plw->plw_bin0;
				/*
				 * large pages all have the same vac color
				 * so by now we should be done with next
				 * size page splitting process
				 */
				ASSERT(plw->plw_bins[1] == 0);
				plw->plw_do_split = 0;
				return (nbin);
			}

		} else {
			uint_t bin_jump = (vac_colors == 1) ?
			    (BIN_STEP & ~3) - (plw->plw_bin0 & 3) : BIN_STEP;

			bin_jump &= ~(vac_colors - 1);

			nbin0 = ADD_MASKED(plw->plw_bin0, bin_jump, neq_mask,
			    plw->plw_color_mask);

			if ((nbin0 ^ plw->plw_bin0) & plw->plw_ceq_mask[szc]) {

				plw->plw_bin_marker = nbin = nbin0;

				if (plw->plw_bins[nszc] != 0) {
					/*
					 * check if next page size bin is the
					 * same as the next page size bin for
					 * bin0
					 */
					nbin_nsz = PAGE_GET_NSZ_COLOR(szc,
					    nbin);
					bin0_nsz = PAGE_GET_NSZ_COLOR(szc,
					    plw->plw_bin0);

					if ((bin0_nsz ^ nbin_nsz) &
					    plw->plw_ceq_mask[nszc])
						plw->plw_do_split = 1;
				}
				return (nbin);
			}
		}
	}

	if (plw->plw_bins[nszc] != 0) {
		nbin_nsz = PAGE_GET_NSZ_COLOR(szc, nbin);
		if (!((plw->plw_split_next ^ nbin_nsz) &
		    plw->plw_ceq_mask[nszc]))
			plw->plw_do_split = 1;
	}

	return (nbin);
}

page_t *
page_get_mnode_freelist(int mnode, uint_t bin, int mtype, uchar_t szc,
    uint_t flags)
{
	kmutex_t		*pcm;
	page_t			*pp, *first_pp;
	uint_t			sbin;
	int			plw_initialized;
	page_list_walker_t	plw;

	ASSERT(szc < mmu_page_sizes);

	VM_STAT_ADD(vmm_vmstats.pgmf_alloc[szc]);

	MTYPE_START(mnode, mtype, flags);
	if (mtype < 0) {	/* mnode does not have memory in mtype range */
		VM_STAT_ADD(vmm_vmstats.pgmf_allocempty[szc]);
		return (NULL);
	}
try_again:

	plw_initialized = 0;
	plw.plw_ceq_dif = 1;

	/*
	 * Only hold one freelist lock at a time, that way we
	 * can start anywhere and not have to worry about lock
	 * ordering.
	 */
	for (plw.plw_count = 0;
	    plw.plw_count < plw.plw_ceq_dif; plw.plw_count++) {
		sbin = bin;
		do {
			if (!PAGE_FREELISTS(mnode, szc, bin, mtype))
				goto bin_empty_1;

			pcm = PC_BIN_MUTEX(mnode, bin, PG_FREE_LIST);
			mutex_enter(pcm);
			pp = PAGE_FREELISTS(mnode, szc, bin, mtype);
			if (pp == NULL)
				goto bin_empty_0;

			/*
			 * These were set before the page
			 * was put on the free list,
			 * they must still be set.
			 */
			ASSERT(PP_ISFREE(pp));
			ASSERT(PP_ISAGED(pp));
			ASSERT(pp->p_vnode == NULL);
			ASSERT(pp->p_hash == NULL);
			ASSERT(pp->p_offset == (u_offset_t)-1);
			ASSERT(pp->p_szc == szc);
			ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) == mnode);

			/*
			 * Walk down the hash chain.
			 * 8k pages are linked on p_next
			 * and p_prev fields. Large pages
			 * are a contiguous group of
			 * constituent pages linked together
			 * on their p_next and p_prev fields.
			 * The large pages are linked together
			 * on the hash chain using p_vpnext
			 * p_vpprev of the base constituent
			 * page of each large page.
			 */
			first_pp = pp;
			while (IS_DUMP_PAGE(pp) || !page_trylock_cons(pp,
			    SE_EXCL)) {
				if (szc == 0) {
					pp = pp->p_next;
				} else {
					pp = pp->p_vpnext;
				}

				ASSERT(PP_ISFREE(pp));
				ASSERT(PP_ISAGED(pp));
				ASSERT(pp->p_vnode == NULL);
				ASSERT(pp->p_hash == NULL);
				ASSERT(pp->p_offset == (u_offset_t)-1);
				ASSERT(pp->p_szc == szc);
				ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) == mnode);

				if (pp == first_pp)
					goto bin_empty_0;
			}

			ASSERT(pp != NULL);
			ASSERT(mtype == PP_2_MTYPE(pp));
			ASSERT(pp->p_szc == szc);
			if (szc == 0) {
				page_sub(&PAGE_FREELISTS(mnode,
				    szc, bin, mtype), pp);
			} else {
				page_vpsub(&PAGE_FREELISTS(mnode,
				    szc, bin, mtype), pp);
				CHK_LPG(pp, szc);
			}
			page_ctr_sub(mnode, mtype, pp, PG_FREE_LIST);

			if ((PP_ISFREE(pp) == 0) || (PP_ISAGED(pp) == 0))
				panic("free page is not. pp %p", (void *)pp);
			mutex_exit(pcm);

#if defined(__sparc)
			ASSERT(!kcage_on || PP_ISNORELOC(pp) ||
			    (flags & PG_NORELOC) == 0);

			if (PP_ISNORELOC(pp))
				kcage_freemem_sub(page_get_pagecnt(szc));
#endif
			VM_STAT_ADD(vmm_vmstats.pgmf_allocok[szc]);
			return (pp);

bin_empty_0:
			mutex_exit(pcm);
bin_empty_1:
			if (plw_initialized == 0) {
				page_list_walk_init(szc, flags, bin, 1, 1,
				    &plw);
				plw_initialized = 1;
				ASSERT(plw.plw_colors <=
				    PAGE_GET_PAGECOLORS(szc));
				ASSERT(plw.plw_colors > 0);
				ASSERT((plw.plw_colors &
				    (plw.plw_colors - 1)) == 0);
				ASSERT(bin < plw.plw_colors);
				ASSERT(plw.plw_ceq_mask[szc] < plw.plw_colors);
			}
			/* calculate the next bin with equivalent color */
			bin = ADD_MASKED(bin, plw.plw_bin_step,
			    plw.plw_ceq_mask[szc], plw.plw_color_mask);
		} while (sbin != bin);

		/*
		 * color bins are all empty if color match. Try and
		 * satisfy the request by breaking up or coalescing
		 * pages from a different size freelist of the correct
		 * color that satisfies the ORIGINAL color requested.
		 * If that fails then try pages of the same size but
		 * different colors assuming we are not called with
		 * PG_MATCH_COLOR.
		 */
		if (plw.plw_do_split &&
		    (pp = page_freelist_split(szc, bin, mnode,
		    mtype, PFNNULL, PFNNULL, &plw)) != NULL)
			return (pp);

		if (szc > 0 && (pp = page_freelist_coalesce(mnode, szc,
		    bin, plw.plw_ceq_mask[szc], mtype, PFNNULL)) !=  NULL)
			return (pp);

		if (plw.plw_ceq_dif > 1)
			bin = page_list_walk_next_bin(szc, bin, &plw);
	}

	/* if allowed, cycle through additional mtypes */
	MTYPE_NEXT(mnode, mtype, flags);
	if (mtype >= 0)
		goto try_again;

	VM_STAT_ADD(vmm_vmstats.pgmf_allocfailed[szc]);

	return (NULL);
}

/*
 * Returns the count of free pages for 'pp' with size code 'szc'.
 * Note: This function does not return an exact value as the page freelist
 * locks are not held and thus the values in the page_counters may be
 * changing as we walk through the data.
 */
static int
page_freecnt(int mnode, page_t *pp, uchar_t szc)
{
	pgcnt_t	pgfree;
	pgcnt_t cnt;
	ssize_t	r = szc;	/* region size */
	ssize_t	idx;
	int	i;
	int	full, range;

	/* Make sure pagenum passed in is aligned properly */
	ASSERT((pp->p_pagenum & (PNUM_SIZE(szc) - 1)) == 0);
	ASSERT(szc > 0);

	/* Prevent page_counters dynamic memory from being freed */
	rw_enter(&page_ctrs_rwlock[mnode], RW_READER);
	idx = PNUM_TO_IDX(mnode, r, pp->p_pagenum);
	cnt = PAGE_COUNTERS(mnode, r, idx);
	pgfree = cnt << PNUM_SHIFT(r - 1);
	range = FULL_REGION_CNT(szc);

	/* Check for completely full region */
	if (cnt == range) {
		rw_exit(&page_ctrs_rwlock[mnode]);
		return (pgfree);
	}

	while (--r > 0) {
		idx = PNUM_TO_IDX(mnode, r, pp->p_pagenum);
		full = FULL_REGION_CNT(r);
		for (i = 0; i < range; i++, idx++) {
			cnt = PAGE_COUNTERS(mnode, r, idx);
			/*
			 * If cnt here is full, that means we have already
			 * accounted for these pages earlier.
			 */
			if (cnt != full) {
				pgfree += (cnt << PNUM_SHIFT(r - 1));
			}
		}
		range *= full;
	}
	rw_exit(&page_ctrs_rwlock[mnode]);
	return (pgfree);
}

/*
 * Called from page_geti_contig_pages to exclusively lock constituent pages
 * starting from 'spp' for page size code 'szc'.
 *
 * If 'ptcpthreshold' is set, the number of free pages needed in the 'szc'
 * region needs to be greater than or equal to the threshold.
 */
static int
page_trylock_contig_pages(int mnode, page_t *spp, uchar_t szc, int flags)
{
	pgcnt_t	pgcnt = PNUM_SIZE(szc);
	pgcnt_t pgfree, i;
	page_t *pp;

	VM_STAT_ADD(vmm_vmstats.ptcp[szc]);


	if ((ptcpthreshold == 0) || (flags & PGI_PGCPHIPRI))
		goto skipptcpcheck;
	/*
	 * check if there are sufficient free pages available before attempting
	 * to trylock. Count is approximate as page counters can change.
	 */
	pgfree = page_freecnt(mnode, spp, szc);

	/* attempt to trylock if there are sufficient already free pages */
	if (pgfree < pgcnt/ptcpthreshold) {
		VM_STAT_ADD(vmm_vmstats.ptcpfreethresh[szc]);
		return (0);
	}

skipptcpcheck:

	for (i = 0; i < pgcnt; i++) {
		pp = &spp[i];
		if (!page_trylock(pp, SE_EXCL)) {
			VM_STAT_ADD(vmm_vmstats.ptcpfailexcl[szc]);
			while (--i != (pgcnt_t)-1) {
				pp = &spp[i];
				ASSERT(PAGE_EXCL(pp));
				page_unlock_nocapture(pp);
			}
			return (0);
		}
		ASSERT(spp[i].p_pagenum == spp->p_pagenum + i);
		if ((pp->p_szc > szc || (szc && pp->p_szc == szc)) &&
		    !PP_ISFREE(pp)) {
			VM_STAT_ADD(vmm_vmstats.ptcpfailszc[szc]);
			ASSERT(i == 0);
			page_unlock_nocapture(pp);
			return (0);
		}

		/*
		 * If a page has been marked non-relocatable or has been
		 * explicitly locked in memory, we don't want to relocate it;
		 * unlock the pages and fail the operation.
		 */
		if (PP_ISNORELOC(pp) ||
		    pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
			VM_STAT_ADD(vmm_vmstats.ptcpfailcage[szc]);
			while (i != (pgcnt_t)-1) {
				pp = &spp[i];
				ASSERT(PAGE_EXCL(pp));
				page_unlock_nocapture(pp);
				i--;
			}
			return (0);
		}
	}
	VM_STAT_ADD(vmm_vmstats.ptcpok[szc]);
	return (1);
}

/*
 * Claim large page pointed to by 'pp'. 'pp' is the starting set
 * of 'szc' constituent pages that had been locked exclusively previously.
 * Will attempt to relocate constituent pages in use.
 */
static page_t *
page_claim_contig_pages(page_t *pp, uchar_t szc, int flags)
{
	spgcnt_t pgcnt, npgs, i;
	page_t *targpp, *rpp, *hpp;
	page_t *replpp = NULL;
	page_t *pplist = NULL;

	ASSERT(pp != NULL);

	pgcnt = page_get_pagecnt(szc);
	while (pgcnt) {
		ASSERT(PAGE_EXCL(pp));
		ASSERT(!PP_ISNORELOC(pp));
		if (PP_ISFREE(pp)) {
			/*
			 * If this is a PG_FREE_LIST page then its
			 * size code can change underneath us due to
			 * page promotion or demotion. As an optimzation
			 * use page_list_sub_pages() instead of
			 * page_list_sub().
			 */
			if (PP_ISAGED(pp)) {
				page_list_sub_pages(pp, szc);
				if (pp->p_szc == szc) {
					return (pp);
				}
				ASSERT(pp->p_szc < szc);
				npgs = page_get_pagecnt(pp->p_szc);
				hpp = pp;
				for (i = 0; i < npgs; i++, pp++) {
					pp->p_szc = szc;
				}
				page_list_concat(&pplist, &hpp);
				pgcnt -= npgs;
				continue;
			}
			ASSERT(!PP_ISAGED(pp));
			ASSERT(pp->p_szc == 0);
			page_list_sub(pp, PG_CACHE_LIST);
			page_hashout(pp, NULL);
			PP_SETAGED(pp);
			pp->p_szc = szc;
			page_list_concat(&pplist, &pp);
			pp++;
			pgcnt--;
			continue;
		}
		npgs = page_get_pagecnt(pp->p_szc);

		/*
		 * page_create_wait freemem accounting done by caller of
		 * page_get_freelist and not necessary to call it prior to
		 * calling page_get_replacement_page.
		 *
		 * page_get_replacement_page can call page_get_contig_pages
		 * to acquire a large page (szc > 0); the replacement must be
		 * smaller than the contig page size to avoid looping or
		 * szc == 0 and PGI_PGCPSZC0 is set.
		 */
		if (pp->p_szc < szc || (szc == 0 && (flags & PGI_PGCPSZC0))) {
			replpp = page_get_replacement_page(pp, NULL, 0);
			if (replpp) {
				npgs = page_get_pagecnt(pp->p_szc);
				ASSERT(npgs <= pgcnt);
				targpp = pp;
			}
		}

		/*
		 * If replacement is NULL or do_page_relocate fails, fail
		 * coalescing of pages.
		 */
		if (replpp == NULL || (do_page_relocate(&targpp, &replpp, 0,
		    &npgs, NULL) != 0)) {
			/*
			 * Unlock un-processed target list
			 */
			while (pgcnt--) {
				ASSERT(PAGE_EXCL(pp));
				page_unlock_nocapture(pp);
				pp++;
			}
			/*
			 * Free the processed target list.
			 */
			while (pplist) {
				pp = pplist;
				page_sub(&pplist, pp);
				ASSERT(PAGE_EXCL(pp));
				ASSERT(pp->p_szc == szc);
				ASSERT(PP_ISFREE(pp));
				ASSERT(PP_ISAGED(pp));
				pp->p_szc = 0;
				page_list_add(pp, PG_FREE_LIST | PG_LIST_TAIL);
				page_unlock_nocapture(pp);
			}

			if (replpp != NULL)
				page_free_replacement_page(replpp);

			return (NULL);
		}
		ASSERT(pp == targpp);

		/* LINTED */
		ASSERT(hpp = pp); /* That's right, it's an assignment */

		pp += npgs;
		pgcnt -= npgs;

		while (npgs--) {
			ASSERT(PAGE_EXCL(targpp));
			ASSERT(!PP_ISFREE(targpp));
			ASSERT(!PP_ISNORELOC(targpp));
			PP_SETFREE(targpp);
			ASSERT(PP_ISAGED(targpp));
			ASSERT(targpp->p_szc < szc || (szc == 0 &&
			    (flags & PGI_PGCPSZC0)));
			targpp->p_szc = szc;
			targpp = targpp->p_next;

			rpp = replpp;
			ASSERT(rpp != NULL);
			page_sub(&replpp, rpp);
			ASSERT(PAGE_EXCL(rpp));
			ASSERT(!PP_ISFREE(rpp));
			page_unlock_nocapture(rpp);
		}
		ASSERT(targpp == hpp);
		ASSERT(replpp == NULL);
		page_list_concat(&pplist, &targpp);
	}
	CHK_LPG(pplist, szc);
	return (pplist);
}

/*
 * Trim kernel cage from pfnlo-pfnhi and store result in lo-hi. Return code
 * of 0 means nothing left after trim.
 */
int
trimkcage(struct memseg *mseg, pfn_t *lo, pfn_t *hi, pfn_t pfnlo, pfn_t pfnhi)
{
	pfn_t	kcagepfn;
	int	decr;
	int	rc = 0;

	if (PP_ISNORELOC(mseg->pages)) {
		if (PP_ISNORELOC(mseg->epages - 1) == 0) {

			/* lower part of this mseg inside kernel cage */
			decr = kcage_current_pfn(&kcagepfn);

			/* kernel cage may have transitioned past mseg */
			if (kcagepfn >= mseg->pages_base &&
			    kcagepfn < mseg->pages_end) {
				ASSERT(decr == 0);
				*lo = MAX(kcagepfn, pfnlo);
				*hi = MIN(pfnhi, (mseg->pages_end - 1));
				rc = 1;
			}
		}
		/* else entire mseg in the cage */
	} else {
		if (PP_ISNORELOC(mseg->epages - 1)) {

			/* upper part of this mseg inside kernel cage */
			decr = kcage_current_pfn(&kcagepfn);

			/* kernel cage may have transitioned past mseg */
			if (kcagepfn >= mseg->pages_base &&
			    kcagepfn < mseg->pages_end) {
				ASSERT(decr);
				*hi = MIN(kcagepfn, pfnhi);
				*lo = MAX(pfnlo, mseg->pages_base);
				rc = 1;
			}
		} else {
			/* entire mseg outside of kernel cage */
			*lo = MAX(pfnlo, mseg->pages_base);
			*hi = MIN(pfnhi, (mseg->pages_end - 1));
			rc = 1;
		}
	}
	return (rc);
}

/*
 * called from page_get_contig_pages to search 'pfnlo' thru 'pfnhi' to claim a
 * page with size code 'szc'. Claiming such a page requires acquiring
 * exclusive locks on all constituent pages (page_trylock_contig_pages),
 * relocating pages in use and concatenating these constituent pages into a
 * large page.
 *
 * The page lists do not have such a large page and page_freelist_split has
 * already failed to demote larger pages and/or coalesce smaller free pages.
 *
 * 'flags' may specify PG_COLOR_MATCH which would limit the search of large
 * pages with the same color as 'bin'.
 *
 * 'pfnflag' specifies the subset of the pfn range to search.
 */

static page_t *
page_geti_contig_pages(int mnode, uint_t bin, uchar_t szc, int flags,
    pfn_t pfnlo, pfn_t pfnhi, pgcnt_t pfnflag)
{
	struct memseg *mseg;
	pgcnt_t	szcpgcnt = page_get_pagecnt(szc);
	pgcnt_t szcpgmask = szcpgcnt - 1;
	pfn_t	randpfn;
	page_t *pp, *randpp, *endpp;
	uint_t colors, ceq_mask;
	/* LINTED : set but not used in function */
	uint_t color_mask;
	pfn_t hi, lo;
	uint_t skip;
	MEM_NODE_ITERATOR_DECL(it);

	ASSERT(szc != 0 || (flags & PGI_PGCPSZC0));

	pfnlo = P2ROUNDUP(pfnlo, szcpgcnt);

	if ((pfnhi - pfnlo) + 1 < szcpgcnt || pfnlo >= pfnhi)
		return (NULL);

	ASSERT(szc < mmu_page_sizes);

	colors = PAGE_GET_PAGECOLORS(szc);
	color_mask = colors - 1;
	if ((colors > 1) && (flags & PG_MATCH_COLOR)) {
		uchar_t ceq = colorequivszc[szc];
		uint_t  ceq_dif = colors >> ((ceq >> 4) + (ceq & 0xf));

		ASSERT(ceq_dif > 0);
		ceq_mask = (ceq_dif - 1) << (ceq & 0xf);
	} else {
		ceq_mask = 0;
	}

	ASSERT(bin < colors);

	/* clear "non-significant" color bits */
	bin &= ceq_mask;

	/*
	 * trim the pfn range to search based on pfnflag. pfnflag is set
	 * when there have been previous page_get_contig_page failures to
	 * limit the search.
	 *
	 * The high bit in pfnflag specifies the number of 'slots' in the
	 * pfn range and the remainder of pfnflag specifies which slot.
	 * For example, a value of 1010b would mean the second slot of
	 * the pfn range that has been divided into 8 slots.
	 */
	if (pfnflag > 1) {
		int	slots = 1 << (highbit(pfnflag) - 1);
		int	slotid = pfnflag & (slots - 1);
		pgcnt_t	szcpages;
		int	slotlen;

		pfnhi = P2ALIGN((pfnhi + 1), szcpgcnt) - 1;
		szcpages = ((pfnhi - pfnlo) + 1) / szcpgcnt;
		slotlen = howmany(szcpages, slots);
		/* skip if 'slotid' slot is empty */
		if (slotid * slotlen >= szcpages)
			return (NULL);
		pfnlo = pfnlo + (((slotid * slotlen) % szcpages) * szcpgcnt);
		ASSERT(pfnlo < pfnhi);
		if (pfnhi > pfnlo + (slotlen * szcpgcnt))
			pfnhi = pfnlo + (slotlen * szcpgcnt) - 1;
	}

	/*
	 * This routine is can be called recursively so we shouldn't
	 * acquire a reader lock if a write request is pending. This
	 * could lead to a deadlock with the DR thread.
	 *
	 * Returning NULL informs the caller that we could not get
	 * a contig page with the required characteristics.
	 */

	if (!memsegs_trylock(0))
		return (NULL);

	/*
	 * loop through memsegs to look for contig page candidates
	 */

	for (mseg = memsegs; mseg != NULL; mseg = mseg->next) {
		if (pfnhi < mseg->pages_base || pfnlo >= mseg->pages_end) {
			/* no overlap */
			continue;
		}

		if (mseg->pages_end - mseg->pages_base < szcpgcnt)
			/* mseg too small */
			continue;

		/*
		 * trim off kernel cage pages from pfn range and check for
		 * a trimmed pfn range returned that does not span the
		 * desired large page size.
		 */
		if (kcage_on) {
			if (trimkcage(mseg, &lo, &hi, pfnlo, pfnhi) == 0 ||
			    lo >= hi || ((hi - lo) + 1) < szcpgcnt)
				continue;
		} else {
			lo = MAX(pfnlo, mseg->pages_base);
			hi = MIN(pfnhi, (mseg->pages_end - 1));
		}

		/* round to szcpgcnt boundaries */
		lo = P2ROUNDUP(lo, szcpgcnt);

		MEM_NODE_ITERATOR_INIT(lo, mnode, szc, &it);
		hi = P2ALIGN((hi + 1), szcpgcnt) - 1;

		if (hi <= lo)
			continue;

		/*
		 * set lo to point to the pfn for the desired bin. Large
		 * page sizes may only have a single page color
		 */
		skip = szcpgcnt;
		if (ceq_mask > 0 || interleaved_mnodes) {
			/* set lo to point at appropriate color */
			if (((PFN_2_COLOR(lo, szc, &it) ^ bin) & ceq_mask) ||
			    (interleaved_mnodes &&
			    PFN_2_MEM_NODE(lo) != mnode)) {
				PAGE_NEXT_PFN_FOR_COLOR(lo, szc, bin, ceq_mask,
				    color_mask, &it);
			}
			if (hi <= lo)
				/* mseg cannot satisfy color request */
				continue;
		}

		/* randomly choose a point between lo and hi to begin search */

		randpfn = (pfn_t)GETTICK();
		randpfn = ((randpfn % (hi - lo)) + lo) & ~(skip - 1);
		MEM_NODE_ITERATOR_INIT(randpfn, mnode, szc, &it);
		if (ceq_mask || interleaved_mnodes || randpfn == (pfn_t)-1) {
			if (randpfn != (pfn_t)-1) {
				PAGE_NEXT_PFN_FOR_COLOR(randpfn, szc, bin,
				    ceq_mask, color_mask, &it);
			}
			if (randpfn >= hi) {
				randpfn = lo;
				MEM_NODE_ITERATOR_INIT(randpfn, mnode, szc,
				    &it);
			}
		}
		randpp = mseg->pages + (randpfn - mseg->pages_base);

		ASSERT(randpp->p_pagenum == randpfn);

		pp = randpp;
		endpp =  mseg->pages + (hi - mseg->pages_base) + 1;

		ASSERT(randpp + szcpgcnt <= endpp);

		do {
			ASSERT(!(pp->p_pagenum & szcpgmask));
			ASSERT(((PP_2_BIN(pp) ^ bin) & ceq_mask) == 0);

			if (page_trylock_contig_pages(mnode, pp, szc, flags)) {
				/* pages unlocked by page_claim on failure */
				if (page_claim_contig_pages(pp, szc, flags)) {
					memsegs_unlock(0);
					return (pp);
				}
			}

			if (ceq_mask == 0 && !interleaved_mnodes) {
				pp += skip;
			} else {
				pfn_t pfn = pp->p_pagenum;

				PAGE_NEXT_PFN_FOR_COLOR(pfn, szc, bin,
				    ceq_mask, color_mask, &it);
				if (pfn == (pfn_t)-1) {
					pp = endpp;
				} else {
					pp = mseg->pages +
					    (pfn - mseg->pages_base);
				}
			}
			if (pp >= endpp) {
				/* start from the beginning */
				MEM_NODE_ITERATOR_INIT(lo, mnode, szc, &it);
				pp = mseg->pages + (lo - mseg->pages_base);
				ASSERT(pp->p_pagenum == lo);
				ASSERT(pp + szcpgcnt <= endpp);
			}
		} while (pp != randpp);
	}
	memsegs_unlock(0);
	return (NULL);
}


/*
 * controlling routine that searches through physical memory in an attempt to
 * claim a large page based on the input parameters.
 * on the page free lists.
 *
 * calls page_geti_contig_pages with an initial pfn range from the mnode
 * and mtype. page_geti_contig_pages will trim off the parts of the pfn range
 * that overlaps with the kernel cage or does not match the requested page
 * color if PG_MATCH_COLOR is set.  Since this search is very expensive,
 * page_geti_contig_pages may further limit the search range based on
 * previous failure counts (pgcpfailcnt[]).
 *
 * for PGI_PGCPSZC0 requests, page_get_contig_pages will relocate a base
 * pagesize page that satisfies mtype.
 */
page_t *
page_get_contig_pages(int mnode, uint_t bin, int mtype, uchar_t szc,
    uint_t flags)
{
	pfn_t		pfnlo, pfnhi;	/* contig pages pfn range */
	page_t		*pp;
	pgcnt_t		pfnflag = 0;	/* no limit on search if 0 */

	VM_STAT_ADD(vmm_vmstats.pgcp_alloc[szc]);

	/* no allocations from cage */
	flags |= PGI_NOCAGE;

	/* LINTED */
	MTYPE_START(mnode, mtype, flags);
	if (mtype < 0) {	/* mnode does not have memory in mtype range */
		VM_STAT_ADD(vmm_vmstats.pgcp_allocempty[szc]);
		return (NULL);
	}

	ASSERT(szc > 0 || (flags & PGI_PGCPSZC0));

	/* do not limit search and ignore color if hi pri */

	if (pgcplimitsearch && ((flags & PGI_PGCPHIPRI) == 0))
		pfnflag = pgcpfailcnt[szc];

	/* remove color match to improve chances */

	if (flags & PGI_PGCPHIPRI || pfnflag)
		flags &= ~PG_MATCH_COLOR;

	do {
		/* get pfn range based on mnode and mtype */
		MNODETYPE_2_PFN(mnode, mtype, pfnlo, pfnhi);

		ASSERT(pfnhi >= pfnlo);

		pp = page_geti_contig_pages(mnode, bin, szc, flags,
		    pfnlo, pfnhi, pfnflag);

		if (pp != NULL) {
			pfnflag = pgcpfailcnt[szc];
			if (pfnflag) {
				/* double the search size */
				pgcpfailcnt[szc] = pfnflag >> 1;
			}
			VM_STAT_ADD(vmm_vmstats.pgcp_allocok[szc]);
			return (pp);
		}
		MTYPE_NEXT(mnode, mtype, flags);
	} while (mtype >= 0);

	VM_STAT_ADD(vmm_vmstats.pgcp_allocfailed[szc]);
	return (NULL);
}

#if defined(__i386) || defined(__amd64)
/*
 * Determine the likelihood of finding/coalescing a szc page.
 * Return 0 if the likelihood is small otherwise return 1.
 *
 * For now, be conservative and check only 1g pages and return 0
 * if there had been previous coalescing failures and the szc pages
 * needed to satisfy request would exhaust most of freemem.
 */
int
page_chk_freelist(uint_t szc)
{
	pgcnt_t		pgcnt;

	if (szc <= 1)
		return (1);

	pgcnt = page_get_pagecnt(szc);
	if (pgcpfailcnt[szc] && pgcnt + throttlefree >= freemem) {
		VM_STAT_ADD(vmm_vmstats.pcf_deny[szc]);
		return (0);
	}
	VM_STAT_ADD(vmm_vmstats.pcf_allow[szc]);
	return (1);
}
#endif

/*
 * Find the `best' page on the freelist for this (vp,off) (as,vaddr) pair.
 *
 * Does its own locking and accounting.
 * If PG_MATCH_COLOR is set, then NULL will be returned if there are no
 * pages of the proper color even if there are pages of a different color.
 *
 * Finds a page, removes it, THEN locks it.
 */

/*ARGSUSED*/
page_t *
page_get_freelist(struct vnode *vp, u_offset_t off, struct seg *seg,
	caddr_t vaddr, size_t size, uint_t flags, struct lgrp *lgrp)
{
	struct as	*as = seg->s_as;
	page_t		*pp = NULL;
	ulong_t		bin;
	uchar_t		szc;
	int		mnode;
	int		mtype;
	page_t		*(*page_get_func)(int, uint_t, int, uchar_t, uint_t);
	lgrp_mnode_cookie_t	lgrp_cookie;

	page_get_func = page_get_mnode_freelist;

	/*
	 * If we aren't passed a specific lgroup, or passed a freed lgrp
	 * assume we wish to allocate near to the current thread's home.
	 */
	if (!LGRP_EXISTS(lgrp))
		lgrp = lgrp_home_lgrp();

	if (kcage_on) {
		if ((flags & (PG_NORELOC | PG_PANIC)) == PG_NORELOC &&
		    kcage_freemem < kcage_throttlefree + btop(size) &&
		    curthread != kcage_cageout_thread) {
			/*
			 * Set a "reserve" of kcage_throttlefree pages for
			 * PG_PANIC and cageout thread allocations.
			 *
			 * Everybody else has to serialize in
			 * page_create_get_something() to get a cage page, so
			 * that we don't deadlock cageout!
			 */
			return (NULL);
		}
	} else {
		flags &= ~PG_NORELOC;
		flags |= PGI_NOCAGE;
	}

	/* LINTED */
	MTYPE_INIT(mtype, vp, vaddr, flags, size);

	/*
	 * Convert size to page size code.
	 */
	if ((szc = page_szc(size)) == (uchar_t)-1)
		panic("page_get_freelist: illegal page size request");
	ASSERT(szc < mmu_page_sizes);

	VM_STAT_ADD(vmm_vmstats.pgf_alloc[szc]);

	/* LINTED */
	AS_2_BIN(as, seg, vp, vaddr, bin, szc);

	ASSERT(bin < PAGE_GET_PAGECOLORS(szc));

	/*
	 * Try to get a local page first, but try remote if we can't
	 * get a page of the right color.
	 */
pgretry:
	LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp, LGRP_SRCH_LOCAL);
	while ((mnode = lgrp_memnode_choose(&lgrp_cookie)) >= 0) {
		pp = page_get_func(mnode, bin, mtype, szc, flags);
		if (pp != NULL) {
			VM_STAT_ADD(vmm_vmstats.pgf_allocok[szc]);
			DTRACE_PROBE4(page__get,
			    lgrp_t *, lgrp,
			    int, mnode,
			    ulong_t, bin,
			    uint_t, flags);
			return (pp);
		}
	}
	ASSERT(pp == NULL);

	/*
	 * for non-SZC0 PAGESIZE requests, check cachelist before checking
	 * remote free lists.  Caller expected to call page_get_cachelist which
	 * will check local cache lists and remote free lists.
	 */
	if (szc == 0 && ((flags & PGI_PGCPSZC0) == 0)) {
		VM_STAT_ADD(vmm_vmstats.pgf_allocdeferred);
		return (NULL);
	}

	ASSERT(szc > 0 || (flags & PGI_PGCPSZC0));

	lgrp_stat_add(lgrp->lgrp_id, LGRP_NUM_ALLOC_FAIL, 1);

	if (!(flags & PG_LOCAL)) {
		/*
		 * Try to get a non-local freelist page.
		 */
		LGRP_MNODE_COOKIE_UPGRADE(lgrp_cookie);
		while ((mnode = lgrp_memnode_choose(&lgrp_cookie)) >= 0) {
			pp = page_get_func(mnode, bin, mtype, szc, flags);
			if (pp != NULL) {
				DTRACE_PROBE4(page__get,
				    lgrp_t *, lgrp,
				    int, mnode,
				    ulong_t, bin,
				    uint_t, flags);
				VM_STAT_ADD(vmm_vmstats.pgf_allocokrem[szc]);
				return (pp);
			}
		}
		ASSERT(pp == NULL);
	}

	/*
	 * when the cage is off chances are page_get_contig_pages() will fail
	 * to lock a large page chunk therefore when the cage is off it's not
	 * called by default.  this can be changed via /etc/system.
	 *
	 * page_get_contig_pages() also called to acquire a base pagesize page
	 * for page_create_get_something().
	 */
	if (!(flags & PG_NORELOC) && (pg_contig_disable == 0) &&
	    (kcage_on || pg_lpgcreate_nocage || szc == 0) &&
	    (page_get_func != page_get_contig_pages)) {

		VM_STAT_ADD(vmm_vmstats.pgf_allocretry[szc]);
		page_get_func = page_get_contig_pages;
		goto pgretry;
	}

	if (!(flags & PG_LOCAL) && pgcplimitsearch &&
	    page_get_func == page_get_contig_pages)
		SETPGCPFAILCNT(szc);

	VM_STAT_ADD(vmm_vmstats.pgf_allocfailed[szc]);
	return (NULL);
}

/*
 * Find the `best' page on the cachelist for this (vp,off) (as,vaddr) pair.
 *
 * Does its own locking.
 * If PG_MATCH_COLOR is set, then NULL will be returned if there are no
 * pages of the proper color even if there are pages of a different color.
 * Otherwise, scan the bins for ones with pages.  For each bin with pages,
 * try to lock one of them.  If no page can be locked, try the
 * next bin.  Return NULL if a page can not be found and locked.
 *
 * Finds a pages, trys to lock it, then removes it.
 */

/*ARGSUSED*/
page_t *
page_get_cachelist(struct vnode *vp, u_offset_t off, struct seg *seg,
    caddr_t vaddr, uint_t flags, struct lgrp *lgrp)
{
	page_t		*pp;
	struct as	*as = seg->s_as;
	ulong_t		bin;
	/*LINTED*/
	int		mnode;
	int		mtype;
	lgrp_mnode_cookie_t	lgrp_cookie;

	/*
	 * If we aren't passed a specific lgroup, or pasased a freed lgrp
	 * assume we wish to allocate near to the current thread's home.
	 */
	if (!LGRP_EXISTS(lgrp))
		lgrp = lgrp_home_lgrp();

	if (!kcage_on) {
		flags &= ~PG_NORELOC;
		flags |= PGI_NOCAGE;
	}

	if ((flags & (PG_NORELOC | PG_PANIC | PG_PUSHPAGE)) == PG_NORELOC &&
	    kcage_freemem <= kcage_throttlefree) {
		/*
		 * Reserve kcage_throttlefree pages for critical kernel
		 * threads.
		 *
		 * Everybody else has to go to page_create_get_something()
		 * to get a cage page, so we don't deadlock cageout.
		 */
		return (NULL);
	}

	/* LINTED */
	AS_2_BIN(as, seg, vp, vaddr, bin, 0);

	ASSERT(bin < PAGE_GET_PAGECOLORS(0));

	/* LINTED */
	MTYPE_INIT(mtype, vp, vaddr, flags, MMU_PAGESIZE);

	VM_STAT_ADD(vmm_vmstats.pgc_alloc);

	/*
	 * Try local cachelists first
	 */
	LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp, LGRP_SRCH_LOCAL);
	while ((mnode = lgrp_memnode_choose(&lgrp_cookie)) >= 0) {
		pp = page_get_mnode_cachelist(bin, flags, mnode, mtype);
		if (pp != NULL) {
			VM_STAT_ADD(vmm_vmstats.pgc_allocok);
			DTRACE_PROBE4(page__get,
			    lgrp_t *, lgrp,
			    int, mnode,
			    ulong_t, bin,
			    uint_t, flags);
			return (pp);
		}
	}

	lgrp_stat_add(lgrp->lgrp_id, LGRP_NUM_ALLOC_FAIL, 1);

	/*
	 * Try freelists/cachelists that are farther away
	 * This is our only chance to allocate remote pages for PAGESIZE
	 * requests.
	 */
	LGRP_MNODE_COOKIE_UPGRADE(lgrp_cookie);
	while ((mnode = lgrp_memnode_choose(&lgrp_cookie)) >= 0) {
		pp = page_get_mnode_freelist(mnode, bin, mtype,
		    0, flags);
		if (pp != NULL) {
			VM_STAT_ADD(vmm_vmstats.pgc_allocokdeferred);
			DTRACE_PROBE4(page__get,
			    lgrp_t *, lgrp,
			    int, mnode,
			    ulong_t, bin,
			    uint_t, flags);
			return (pp);
		}
		pp = page_get_mnode_cachelist(bin, flags, mnode, mtype);
		if (pp != NULL) {
			VM_STAT_ADD(vmm_vmstats.pgc_allocokrem);
			DTRACE_PROBE4(page__get,
			    lgrp_t *, lgrp,
			    int, mnode,
			    ulong_t, bin,
			    uint_t, flags);
			return (pp);
		}
	}

	VM_STAT_ADD(vmm_vmstats.pgc_allocfailed);
	return (NULL);
}

page_t *
page_get_mnode_cachelist(uint_t bin, uint_t flags, int mnode, int mtype)
{
	kmutex_t		*pcm;
	page_t			*pp, *first_pp;
	uint_t			sbin;
	int			plw_initialized;
	page_list_walker_t	plw;

	VM_STAT_ADD(vmm_vmstats.pgmc_alloc);

	/* LINTED */
	MTYPE_START(mnode, mtype, flags);
	if (mtype < 0) {	/* mnode does not have memory in mtype range */
		VM_STAT_ADD(vmm_vmstats.pgmc_allocempty);
		return (NULL);
	}

try_again:

	plw_initialized = 0;
	plw.plw_ceq_dif = 1;

	/*
	 * Only hold one cachelist lock at a time, that way we
	 * can start anywhere and not have to worry about lock
	 * ordering.
	 */

	for (plw.plw_count = 0;
	    plw.plw_count < plw.plw_ceq_dif; plw.plw_count++) {
		sbin = bin;
		do {

			if (!PAGE_CACHELISTS(mnode, bin, mtype))
				goto bin_empty_1;
			pcm = PC_BIN_MUTEX(mnode, bin, PG_CACHE_LIST);
			mutex_enter(pcm);
			pp = PAGE_CACHELISTS(mnode, bin, mtype);
			if (pp == NULL)
				goto bin_empty_0;

			first_pp = pp;
			ASSERT(pp->p_vnode);
			ASSERT(PP_ISAGED(pp) == 0);
			ASSERT(pp->p_szc == 0);
			ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) == mnode);
			while (IS_DUMP_PAGE(pp) || !page_trylock(pp, SE_EXCL)) {
				pp = pp->p_next;
				ASSERT(pp->p_szc == 0);
				if (pp == first_pp) {
					/*
					 * We have searched the complete list!
					 * And all of them (might only be one)
					 * are locked. This can happen since
					 * these pages can also be found via
					 * the hash list. When found via the
					 * hash list, they are locked first,
					 * then removed. We give up to let the
					 * other thread run.
					 */
					pp = NULL;
					break;
				}
				ASSERT(pp->p_vnode);
				ASSERT(PP_ISFREE(pp));
				ASSERT(PP_ISAGED(pp) == 0);
				ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) ==
				    mnode);
			}

			if (pp) {
				page_t	**ppp;
				/*
				 * Found and locked a page.
				 * Pull it off the list.
				 */
				ASSERT(mtype == PP_2_MTYPE(pp));
				ppp = &PAGE_CACHELISTS(mnode, bin, mtype);
				page_sub(ppp, pp);
				/*
				 * Subtract counters before releasing pcm mutex
				 * to avoid a race with page_freelist_coalesce
				 * and page_freelist_split.
				 */
				page_ctr_sub(mnode, mtype, pp, PG_CACHE_LIST);
				mutex_exit(pcm);
				ASSERT(pp->p_vnode);
				ASSERT(PP_ISAGED(pp) == 0);
#if defined(__sparc)
				ASSERT(!kcage_on ||
				    (flags & PG_NORELOC) == 0 ||
				    PP_ISNORELOC(pp));
				if (PP_ISNORELOC(pp)) {
					kcage_freemem_sub(1);
				}
#endif
				VM_STAT_ADD(vmm_vmstats. pgmc_allocok);
				return (pp);
			}
bin_empty_0:
			mutex_exit(pcm);
bin_empty_1:
			if (plw_initialized == 0) {
				page_list_walk_init(0, flags, bin, 0, 1, &plw);
				plw_initialized = 1;
			}
			/* calculate the next bin with equivalent color */
			bin = ADD_MASKED(bin, plw.plw_bin_step,
			    plw.plw_ceq_mask[0], plw.plw_color_mask);
		} while (sbin != bin);

		if (plw.plw_ceq_dif > 1)
			bin = page_list_walk_next_bin(0, bin, &plw);
	}

	MTYPE_NEXT(mnode, mtype, flags);
	if (mtype >= 0)
		goto try_again;

	VM_STAT_ADD(vmm_vmstats.pgmc_allocfailed);
	return (NULL);
}

#ifdef DEBUG
#define	REPL_PAGE_STATS
#endif /* DEBUG */

#ifdef REPL_PAGE_STATS
struct repl_page_stats {
	uint_t	ngets;
	uint_t	ngets_noreloc;
	uint_t	npgr_noreloc;
	uint_t	nnopage_first;
	uint_t	nnopage;
	uint_t	nhashout;
	uint_t	nnofree;
	uint_t	nnext_pp;
} repl_page_stats;
#define	REPL_STAT_INCR(v)	atomic_inc_32(&repl_page_stats.v)
#else /* REPL_PAGE_STATS */
#define	REPL_STAT_INCR(v)
#endif /* REPL_PAGE_STATS */

int	pgrppgcp;

/*
 * The freemem accounting must be done by the caller.
 * First we try to get a replacement page of the same size as like_pp,
 * if that is not possible, then we just get a set of discontiguous
 * PAGESIZE pages.
 */
page_t *
page_get_replacement_page(page_t *orig_like_pp, struct lgrp *lgrp_target,
    uint_t pgrflags)
{
	page_t		*like_pp;
	page_t		*pp, *pplist;
	page_t		*pl = NULL;
	ulong_t		bin;
	int		mnode, page_mnode;
	int		szc;
	spgcnt_t	npgs, pg_cnt;
	pfn_t		pfnum;
	int		mtype;
	int		flags = 0;
	lgrp_mnode_cookie_t	lgrp_cookie;
	lgrp_t		*lgrp;

	REPL_STAT_INCR(ngets);
	like_pp = orig_like_pp;
	ASSERT(PAGE_EXCL(like_pp));

	szc = like_pp->p_szc;
	npgs = page_get_pagecnt(szc);
	/*
	 * Now we reset like_pp to the base page_t.
	 * That way, we won't walk past the end of this 'szc' page.
	 */
	pfnum = PFN_BASE(like_pp->p_pagenum, szc);
	like_pp = page_numtopp_nolock(pfnum);
	ASSERT(like_pp->p_szc == szc);

	if (PP_ISNORELOC(like_pp)) {
		ASSERT(kcage_on);
		REPL_STAT_INCR(ngets_noreloc);
		flags = PGI_RELOCONLY;
	} else if (pgrflags & PGR_NORELOC) {
		ASSERT(kcage_on);
		REPL_STAT_INCR(npgr_noreloc);
		flags = PG_NORELOC;
	}

	/*
	 * Kernel pages must always be replaced with the same size
	 * pages, since we cannot properly handle demotion of kernel
	 * pages.
	 */
	if (PP_ISKAS(like_pp))
		pgrflags |= PGR_SAMESZC;

	/* LINTED */
	MTYPE_PGR_INIT(mtype, flags, like_pp, page_mnode, npgs);

	while (npgs) {
		pplist = NULL;
		for (;;) {
			pg_cnt = page_get_pagecnt(szc);
			bin = PP_2_BIN(like_pp);
			ASSERT(like_pp->p_szc == orig_like_pp->p_szc);
			ASSERT(pg_cnt <= npgs);

			/*
			 * If an lgroup was specified, try to get the
			 * page from that lgroup.
			 * NOTE: Must be careful with code below because
			 *	 lgroup may disappear and reappear since there
			 *	 is no locking for lgroup here.
			 */
			if (LGRP_EXISTS(lgrp_target)) {
				/*
				 * Keep local variable for lgroup separate
				 * from lgroup argument since this code should
				 * only be exercised when lgroup argument
				 * exists....
				 */
				lgrp = lgrp_target;

				/* Try the lgroup's freelists first */
				LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp,
				    LGRP_SRCH_LOCAL);
				while ((pplist == NULL) &&
				    (mnode = lgrp_memnode_choose(&lgrp_cookie))
				    != -1) {
					pplist =
					    page_get_mnode_freelist(mnode, bin,
					    mtype, szc, flags);
				}

				/*
				 * Now try it's cachelists if this is a
				 * small page. Don't need to do it for
				 * larger ones since page_freelist_coalesce()
				 * already failed.
				 */
				if (pplist != NULL || szc != 0)
					break;

				/* Now try it's cachelists */
				LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp,
				    LGRP_SRCH_LOCAL);

				while ((pplist == NULL) &&
				    (mnode = lgrp_memnode_choose(&lgrp_cookie))
				    != -1) {
					pplist =
					    page_get_mnode_cachelist(bin, flags,
					    mnode, mtype);
				}
				if (pplist != NULL) {
					page_hashout(pplist, NULL);
					PP_SETAGED(pplist);
					REPL_STAT_INCR(nhashout);
					break;
				}
				/* Done looking in this lgroup. Bail out. */
				break;
			}

			/*
			 * No lgroup was specified (or lgroup was removed by
			 * DR, so just try to get the page as close to
			 * like_pp's mnode as possible.
			 * First try the local freelist...
			 */
			mnode = PP_2_MEM_NODE(like_pp);
			pplist = page_get_mnode_freelist(mnode, bin,
			    mtype, szc, flags);
			if (pplist != NULL)
				break;

			REPL_STAT_INCR(nnofree);

			/*
			 * ...then the local cachelist. Don't need to do it for
			 * larger pages cause page_freelist_coalesce() already
			 * failed there anyway.
			 */
			if (szc == 0) {
				pplist = page_get_mnode_cachelist(bin, flags,
				    mnode, mtype);
				if (pplist != NULL) {
					page_hashout(pplist, NULL);
					PP_SETAGED(pplist);
					REPL_STAT_INCR(nhashout);
					break;
				}
			}

			/* Now try remote freelists */
			page_mnode = mnode;
			lgrp =
			    lgrp_hand_to_lgrp(MEM_NODE_2_LGRPHAND(page_mnode));
			LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp,
			    LGRP_SRCH_HIER);
			while (pplist == NULL &&
			    (mnode = lgrp_memnode_choose(&lgrp_cookie))
			    != -1) {
				/*
				 * Skip local mnode.
				 */
				if ((mnode == page_mnode) ||
				    (mem_node_config[mnode].exists == 0))
					continue;

				pplist = page_get_mnode_freelist(mnode,
				    bin, mtype, szc, flags);
			}

			if (pplist != NULL)
				break;


			/* Now try remote cachelists */
			LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp,
			    LGRP_SRCH_HIER);
			while (pplist == NULL && szc == 0) {
				mnode = lgrp_memnode_choose(&lgrp_cookie);
				if (mnode == -1)
					break;
				/*
				 * Skip local mnode.
				 */
				if ((mnode == page_mnode) ||
				    (mem_node_config[mnode].exists == 0))
					continue;

				pplist = page_get_mnode_cachelist(bin,
				    flags, mnode, mtype);

				if (pplist != NULL) {
					page_hashout(pplist, NULL);
					PP_SETAGED(pplist);
					REPL_STAT_INCR(nhashout);
					break;
				}
			}

			/*
			 * Break out of while loop under the following cases:
			 * - If we successfully got a page.
			 * - If pgrflags specified only returning a specific
			 *   page size and we could not find that page size.
			 * - If we could not satisfy the request with PAGESIZE
			 *   or larger pages.
			 */
			if (pplist != NULL || szc == 0)
				break;

			if ((pgrflags & PGR_SAMESZC) || pgrppgcp) {
				/* try to find contig page */

				LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp,
				    LGRP_SRCH_HIER);

				while ((pplist == NULL) &&
				    (mnode =
				    lgrp_memnode_choose(&lgrp_cookie))
				    != -1) {
					pplist = page_get_contig_pages(
					    mnode, bin, mtype, szc,
					    flags | PGI_PGCPHIPRI);
				}
				break;
			}

			/*
			 * The correct thing to do here is try the next
			 * page size down using szc--. Due to a bug
			 * with the processing of HAT_RELOAD_SHARE
			 * where the sfmmu_ttecnt arrays of all
			 * hats sharing an ISM segment don't get updated,
			 * using intermediate size pages for relocation
			 * can lead to continuous page faults.
			 */
			szc = 0;
		}

		if (pplist != NULL) {
			DTRACE_PROBE4(page__get,
			    lgrp_t *, lgrp,
			    int, mnode,
			    ulong_t, bin,
			    uint_t, flags);

			while (pplist != NULL && pg_cnt--) {
				ASSERT(pplist != NULL);
				pp = pplist;
				page_sub(&pplist, pp);
				PP_CLRFREE(pp);
				PP_CLRAGED(pp);
				page_list_concat(&pl, &pp);
				npgs--;
				like_pp = like_pp + 1;
				REPL_STAT_INCR(nnext_pp);
			}
			ASSERT(pg_cnt == 0);
		} else {
			break;
		}
	}

	if (npgs) {
		/*
		 * We were unable to allocate the necessary number
		 * of pages.
		 * We need to free up any pl.
		 */
		REPL_STAT_INCR(nnopage);
		page_free_replacement_page(pl);
		return (NULL);
	} else {
		return (pl);
	}
}

/*
 * demote a free large page to it's constituent pages
 */
void
page_demote_free_pages(page_t *pp)
{

	int mnode;

	ASSERT(pp != NULL);
	ASSERT(PAGE_LOCKED(pp));
	ASSERT(PP_ISFREE(pp));
	ASSERT(pp->p_szc != 0 && pp->p_szc < mmu_page_sizes);

	mnode = PP_2_MEM_NODE(pp);
	page_freelist_lock(mnode);
	if (pp->p_szc != 0) {
		(void) page_demote(mnode, PFN_BASE(pp->p_pagenum,
		    pp->p_szc), 0, pp->p_szc, 0, PC_NO_COLOR, PC_FREE);
	}
	page_freelist_unlock(mnode);
	ASSERT(pp->p_szc == 0);
}

/*
 * Factor in colorequiv to check additional 'equivalent' bins.
 * colorequiv may be set in /etc/system
 */
void
page_set_colorequiv_arr(void)
{
	if (colorequiv > 1) {
		int i;
		uint_t sv_a = lowbit(colorequiv) - 1;

		if (sv_a > 15)
			sv_a = 15;

		for (i = 0; i < MMU_PAGE_SIZES; i++) {
			uint_t colors;
			uint_t a = sv_a;

			if ((colors = hw_page_array[i].hp_colors) <= 1) {
				continue;
			}
			while ((colors >> a) == 0)
				a--;
			if ((a << 4) > colorequivszc[i]) {
				colorequivszc[i] = (a << 4);
			}
		}
	}
}

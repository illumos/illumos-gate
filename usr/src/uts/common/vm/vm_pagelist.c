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
#include <sys/memnode.h>
#include <vm/vm_dep.h>
#include <sys/lgrp.h>
#include <sys/mem_config.h>
#include <sys/callb.h>
#include <sys/mem_cage.h>
#include <sys/sdt.h>

extern uint_t	vac_colors;

/* vm_cpu_data for the boot cpu before kmem is initialized */
#pragma align	L2CACHE_ALIGN_MAX(vm_cpu_data0)
char		vm_cpu_data0[VM_CPU_DATA_PADSIZE];

/*
 * number of page colors equivalent to reqested color in page_get routines.
 * If set, keeps large pages intact longer and keeps MPO allocation
 * from the local mnode in favor of acquiring the 'correct' page color from
 * a demoted large page or from a remote mnode.
 */
int	colorequiv;

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
 * use slot 0 (base page size unused) to enable or disable limiting search.
 * Enabled by default.
 */
int	pgcpfailcnt[MMU_PAGE_SIZES];
int	pgcplimitsearch = 1;

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
 * page_freelist_fill pfn flag to signify no hi pfn requirement.
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

/*
 * page counters candidates info
 * See page_ctrs_cands comment below for more details.
 * fields are as follows:
 *	pcc_pages_free:		# pages which freelist coalesce can create
 *	pcc_color_free_len:	number of elements in pcc_color_free array
 *	pcc_color_free:		pointer to page free counts per color
 */
typedef struct pcc_info {
	pgcnt_t	pcc_pages_free;
	int	pcc_color_free_len;
	pgcnt_t	*pcc_color_free;
} pcc_info_t;

/*
 * On big machines it can take a long time to check page_counters
 * arrays. page_ctrs_cands is a summary array whose elements are a dynamically
 * updated sum of all elements of the corresponding page_counters arrays.
 * page_freelist_coalesce() searches page_counters only if an appropriate
 * element of page_ctrs_cands array is greater than 0.
 *
 * An extra dimension is used for page_ctrs_cands to spread the elements
 * over a few e$ cache lines to avoid serialization during the array
 * updates.
 */
#pragma	align 64(page_ctrs_cands)

static pcc_info_t *page_ctrs_cands[NPC_MUTEX][MMU_PAGE_SIZES];

/*
 * Return in val the total number of free pages which can be created
 * for the given mnode (m) and region size (r)
 */
#define	PGCTRS_CANDS_GETVALUE(m, r, val) {				\
	int i;								\
	val = 0;							\
	for (i = 0; i < NPC_MUTEX; i++) {				\
	    val += page_ctrs_cands[i][(r)][(m)].pcc_pages_free;		\
	}								\
}

/*
 * Return in val the total number of free pages which can be created
 * for the given mnode (m), region size (r), and color (c)
 */
#define	PGCTRS_CANDS_GETVALUECOLOR(m, r, c, val) {			\
	int i;								\
	val = 0;							\
	ASSERT((c) < page_ctrs_cands[0][(r)][(m)].pcc_color_free_len);	\
	for (i = 0; i < NPC_MUTEX; i++) {				\
	    val += page_ctrs_cands[i][(r)][(m)].pcc_color_free[(c)];	\
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
	(((pp)->p_pagenum >>					\
	    (PAGE_BSZS_SHIFT(mmu_page_sizes - 1))) & (NPC_MUTEX - 1))

/*
 * Local functions prototypes.
 */

void page_ctr_add(int, int, page_t *, int);
void page_ctr_add_internal(int, int, page_t *, int);
void page_ctr_sub(int, int, page_t *, int);
uint_t  page_convert_color(uchar_t, uchar_t, uint_t);
void page_freelist_lock(int);
void page_freelist_unlock(int);
page_t *page_promote(int, pfn_t, uchar_t, int);
page_t *page_demote(int, pfn_t, uchar_t, uchar_t, int, int);
page_t *page_freelist_fill(uchar_t, int, int, int, pfn_t);
page_t *page_get_mnode_cachelist(uint_t, uint_t, int, int);
static int page_trylock_cons(page_t *pp, se_t se);

#define	PNUM_SIZE(szc)							\
	(hw_page_array[(szc)].hp_size >> hw_page_array[0].hp_shift)
#define	PNUM_SHIFT(szc)							\
	(hw_page_array[(szc)].hp_shift - hw_page_array[0].hp_shift)

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
 *	hpm_color_current_len:	# of elements in hpm_color_current "array" below
 *	hpm_color_current:	last index in counter array for this color at
 *				which we successfully created a large page
 */
typedef struct hw_page_map {
	hpmctr_t	*hpm_counters;
	size_t		hpm_entries;
	int		hpm_shift;
	pfn_t		hpm_base;
	size_t		hpm_color_current_len;
	size_t 		*hpm_color_current;
} hw_page_map_t;

/*
 * Element zero is not used, but is allocated for convenience.
 */
static hw_page_map_t *page_counters[MMU_PAGE_SIZES];

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

#define	PAGE_COUNTERS_CURRENT_COLOR_LEN(mnode, rg_szc)		\
	(page_counters[(rg_szc)][(mnode)].hpm_color_current_len)

#define	PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode, rg_szc)	\
	(page_counters[(rg_szc)][(mnode)].hpm_color_current)

#define	PAGE_COUNTERS_CURRENT_COLOR(mnode, rg_szc, color)	\
	(page_counters[(rg_szc)][(mnode)].hpm_color_current[(color)])

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
	int	align = (L2CACHE_ALIGN) ? L2CACHE_ALIGN : L2CACHE_ALIGN_MAX;

	ASSERT(L2CACHE_ALIGN <= L2CACHE_ALIGN_MAX);

	if (cp == CPU0) {
		cp->cpu_vm_data = (void *)&vm_cpu_data0;
	} else {
		void	*kmptr;

		kmptr = kmem_zalloc(VM_CPU_DATA_PADSIZE + align, KM_SLEEP);
		cp->cpu_vm_data = (void *) P2ROUNDUP((uintptr_t)kmptr, align);
		((vm_cpu_data_t *)cp->cpu_vm_data)->vc_kmptr = kmptr;
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
		    VM_CPU_DATA_PADSIZE);
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
 */
uint_t
page_num_user_pagesizes(void)
{
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
	return (hw_page_array[szc].hp_shift);
}

uint_t
page_get_pagecolors(uint_t szc)
{
	ASSERT(page_colors != 0);
	return (MAX(page_colors >> PAGE_BSZS_SHIFT(szc), 1));
}

/*
 * Called by startup().
 * Size up the per page size free list counters based on physmax
 * of each node and max_mem_nodes.
 */
size_t
page_ctrs_sz(void)
{
	int	r;		/* region size */
	int	mnode;
	uint_t	ctrs_sz = 0;
	int 	i;
	pgcnt_t colors_per_szc[MMU_PAGE_SIZES];

	/*
	 * We need to determine how many page colors there are for each
	 * page size in order to allocate memory for any color specific
	 * arrays.
	 */
	colors_per_szc[0] = page_colors;
	for (i = 1; i < mmu_page_sizes; i++) {
		colors_per_szc[i] =
		    page_convert_color(0, i, page_colors - 1) + 1;
	}

	for (mnode = 0; mnode < max_mem_nodes; mnode++) {

		pgcnt_t r_pgcnt;
		pfn_t   r_base;
		pgcnt_t r_align;

		if (mem_node_config[mnode].exists == 0)
			continue;

		/*
		 * determine size needed for page counter arrays with
		 * base aligned to large page size.
		 */
		for (r = 1; r < mmu_page_sizes; r++) {
			/* add in space for hpm_counters */
			r_align = page_get_pagecnt(r);
			r_base = mem_node_config[mnode].physbase;
			r_base &= ~(r_align - 1);
			r_pgcnt = howmany(mem_node_config[mnode].physmax -
			r_base, r_align);
			/*
			 * Round up to always allocate on pointer sized
			 * boundaries.
			 */
			ctrs_sz += P2ROUNDUP((r_pgcnt * sizeof (hpmctr_t)),
			    sizeof (hpmctr_t *));

			/* add in space for hpm_color_current */
			ctrs_sz += (colors_per_szc[r] *
			    sizeof (size_t));
		}
	}

	for (r = 1; r < mmu_page_sizes; r++) {
		ctrs_sz += (max_mem_nodes * sizeof (hw_page_map_t));

		/* add in space for page_ctrs_cands */
		ctrs_sz += NPC_MUTEX * max_mem_nodes * (sizeof (pcc_info_t));
		ctrs_sz += NPC_MUTEX * max_mem_nodes * colors_per_szc[r] *
		    sizeof (pgcnt_t);
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
	int	r;		/* region size */
	int	i;
	pgcnt_t colors_per_szc[MMU_PAGE_SIZES];

	/*
	 * We need to determine how many page colors there are for each
	 * page size in order to allocate memory for any color specific
	 * arrays.
	 */
	colors_per_szc[0] = page_colors;
	for (i = 1; i < mmu_page_sizes; i++) {
		colors_per_szc[i] =
		    page_convert_color(0, i, page_colors - 1) + 1;
	}

	for (r = 1; r < mmu_page_sizes; r++) {
		page_counters[r] = (hw_page_map_t *)alloc_base;
		alloc_base += (max_mem_nodes * sizeof (hw_page_map_t));
	}

	/* page_ctrs_cands */
	for (r = 1; r < mmu_page_sizes; r++) {
		for (i = 0; i < NPC_MUTEX; i++) {
			page_ctrs_cands[i][r] = (pcc_info_t *)alloc_base;
			alloc_base += max_mem_nodes * (sizeof (pcc_info_t));

		}
	}

	/* page_ctrs_cands pcc_color_free array */
	for (r = 1; r < mmu_page_sizes; r++) {
		for (i = 0; i < NPC_MUTEX; i++) {
			for (mnode = 0; mnode < max_mem_nodes; mnode++) {
				page_ctrs_cands[i][r][mnode].pcc_color_free_len
				    = colors_per_szc[r];
				page_ctrs_cands[i][r][mnode].pcc_color_free =
				    (pgcnt_t *)alloc_base;
				alloc_base += colors_per_szc[r] *
				    sizeof (pgcnt_t);
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

	for (mnode = 0; mnode < max_mem_nodes; mnode++) {

		pgcnt_t r_pgcnt;
		pfn_t	r_base;
		pgcnt_t r_align;
		int	r_shift;

		if (mem_node_config[mnode].exists == 0)
			continue;

		for (r = 1; r < mmu_page_sizes; r++) {
			/*
			 * the page_counters base has to be aligned to the
			 * page count of page size code r otherwise the counts
			 * will cross large page boundaries.
			 */
			r_align = page_get_pagecnt(r);
			r_base = mem_node_config[mnode].physbase;
			/* base needs to be aligned - lower to aligned value */
			r_base &= ~(r_align - 1);
			r_pgcnt = howmany(mem_node_config[mnode].physmax -
			r_base, r_align);
			r_shift = PAGE_BSZS_SHIFT(r);

			PAGE_COUNTERS_SHIFT(mnode, r) = r_shift;
			PAGE_COUNTERS_ENTRIES(mnode, r) = r_pgcnt;
			PAGE_COUNTERS_BASE(mnode, r) = r_base;
			PAGE_COUNTERS_CURRENT_COLOR_LEN(mnode, r) =
			    colors_per_szc[r];
			PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode, r) =
			    (size_t *)alloc_base;
			alloc_base += (sizeof (size_t) * colors_per_szc[r]);
			for (i = 0; i < colors_per_szc[r]; i++) {
				PAGE_COUNTERS_CURRENT_COLOR(mnode, r, i) = i;
			}
			PAGE_COUNTERS_COUNTERS(mnode, r) =
			    (hpmctr_t *)alloc_base;
			/*
			 * Round up to make alloc_base always be aligned on
			 * a pointer boundary.
			 */
			alloc_base += P2ROUNDUP((sizeof (hpmctr_t) * r_pgcnt),
			    sizeof (hpmctr_t *));

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

		if (++PAGE_COUNTERS(mnode, r, idx) != FULL_REGION_CNT(r))
			break;

		page_ctrs_cands[lckidx][r][mnode].pcc_pages_free++;
		page_ctrs_cands[lckidx][r][mnode].
		    pcc_color_free[PP_2_BIN_SZC(pp, r)]++;
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
page_ctr_sub(int mnode, int mtype, page_t *pp, int flags)
{
	int		lckidx;
	kmutex_t	*lock;
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
	lock = &ctr_mutex[lckidx][mnode];

	/*
	 * Decrement the count of free pages for the current
	 * region. Continue looping up in region size decrementing
	 * count if the preceeding region was full.
	 */
	mutex_enter(lock);
	while (r < mmu_page_sizes) {
		idx = PNUM_TO_IDX(mnode, r, pfnum);

		ASSERT(idx < PAGE_COUNTERS_ENTRIES(mnode, r));
		ASSERT(PAGE_COUNTERS(mnode, r, idx) > 0);

		if (--PAGE_COUNTERS(mnode, r, idx) != FULL_REGION_CNT(r) - 1) {
			break;
		}
		ASSERT(page_ctrs_cands[lckidx][r][mnode].pcc_pages_free != 0);
		ASSERT(page_ctrs_cands[lckidx][r][mnode].
		    pcc_color_free[PP_2_BIN_SZC(pp, r)] != 0);

		page_ctrs_cands[lckidx][r][mnode].pcc_pages_free--;
		page_ctrs_cands[lckidx][r][mnode].
		    pcc_color_free[PP_2_BIN_SZC(pp, r)]--;
		r++;
	}
	mutex_exit(lock);
}

/*
 * Adjust page counters following a memory attach, since typically the
 * size of the array needs to change, and the PFN to counter index
 * mapping needs to change.
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
	size_t	old_npgs;
	hpmctr_t *ctr_cache[MMU_PAGE_SIZES];
	size_t	size_cache[MMU_PAGE_SIZES];
	size_t	*color_cache[MMU_PAGE_SIZES];
	size_t	*old_color_array;
	pgcnt_t	colors_per_szc[MMU_PAGE_SIZES];

	newbase = mem_node_config[mnode].physbase & ~PC_BASE_ALIGN_MASK;
	npgs = roundup(mem_node_config[mnode].physmax,
	    PC_BASE_ALIGN) - newbase;

	/*
	 * We need to determine how many page colors there are for each
	 * page size in order to allocate memory for any color specific
	 * arrays.
	 */
	colors_per_szc[0] = page_colors;
	for (r = 1; r < mmu_page_sizes; r++) {
		colors_per_szc[r] =
		    page_convert_color(0, r, page_colors - 1) + 1;
	}

	/*
	 * Preallocate all of the new hpm_counters arrays as we can't
	 * hold the page_ctrs_rwlock as a writer and allocate memory.
	 * If we can't allocate all of the arrays, undo our work so far
	 * and return failure.
	 */
	for (r = 1; r < mmu_page_sizes; r++) {
		pcsz = npgs >> PAGE_BSZS_SHIFT(r);

		ctr_cache[r] = kmem_zalloc(pcsz *
		    sizeof (hpmctr_t), KM_NOSLEEP);
		if (ctr_cache[r] == NULL) {
			while (--r >= 1) {
				kmem_free(ctr_cache[r],
				    size_cache[r] * sizeof (hpmctr_t));
			}
			return (ENOMEM);
		}
		size_cache[r] = pcsz;
	}
	/*
	 * Preallocate all of the new color current arrays as we can't
	 * hold the page_ctrs_rwlock as a writer and allocate memory.
	 * If we can't allocate all of the arrays, undo our work so far
	 * and return failure.
	 */
	for (r = 1; r < mmu_page_sizes; r++) {
		color_cache[r] = kmem_zalloc(sizeof (size_t) *
		    colors_per_szc[r], KM_NOSLEEP);
		if (color_cache[r] == NULL) {
			while (--r >= 1) {
				kmem_free(color_cache[r],
				    colors_per_szc[r] * sizeof (size_t));
			}
			for (r = 1; r < mmu_page_sizes; r++) {
				kmem_free(ctr_cache[r],
				    size_cache[r] * sizeof (hpmctr_t));
			}
			return (ENOMEM);
		}
	}

	/*
	 * Grab the write lock to prevent others from walking these arrays
	 * while we are modifying them.
	 */
	rw_enter(&page_ctrs_rwlock[mnode], RW_WRITER);
	page_freelist_lock(mnode);
	for (r = 1; r < mmu_page_sizes; r++) {
		PAGE_COUNTERS_SHIFT(mnode, r) = PAGE_BSZS_SHIFT(r);
		old_ctr = PAGE_COUNTERS_COUNTERS(mnode, r);
		old_csz = PAGE_COUNTERS_ENTRIES(mnode, r);
		oldbase = PAGE_COUNTERS_BASE(mnode, r);
		old_npgs = old_csz << PAGE_COUNTERS_SHIFT(mnode, r);
		old_color_array = PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode, r);

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
		PAGE_COUNTERS_CURRENT_COLOR_LEN(mnode, r) = colors_per_szc[r];
		PAGE_COUNTERS_CURRENT_COLOR_ARRAY(mnode, r) = color_cache[r];
		color_cache[r] = NULL;
		/*
		 * for now, just reset on these events as it's probably
		 * not worthwhile to try and optimize this.
		 */
		for (i = 0; i < colors_per_szc[r]; i++) {
			PAGE_COUNTERS_CURRENT_COLOR(mnode, r, i) = i;
		}

		/* cache info for freeing out of the critical path */
		if ((caddr_t)old_ctr >= kernelheap &&
		    (caddr_t)old_ctr < ekernelheap) {
			ctr_cache[r] = old_ctr;
			size_cache[r] = old_csz;
		}
		if ((caddr_t)old_color_array >= kernelheap &&
		    (caddr_t)old_color_array < ekernelheap) {
			color_cache[r] = old_color_array;
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
	}
	page_freelist_unlock(mnode);
	rw_exit(&page_ctrs_rwlock[mnode]);

	/*
	 * Now that we have dropped the write lock, it is safe to free all
	 * of the memory we have cached above.
	 */
	for (r = 1; r < mmu_page_sizes; r++) {
		if (ctr_cache[r] != NULL) {
			kmem_free(ctr_cache[r],
			    size_cache[r] * sizeof (hpmctr_t));
		}
		if (color_cache[r] != NULL) {
			kmem_free(color_cache[r],
			    colors_per_szc[r] * sizeof (size_t));
		}
	}
	return (0);
}

/*
 * color contains a valid color index or bin for cur_szc
 */
uint_t
page_convert_color(uchar_t cur_szc, uchar_t new_szc, uint_t color)
{
	uint_t shift;

	if (cur_szc > new_szc) {
		shift = page_get_shift(cur_szc) - page_get_shift(new_szc);
		return (color << shift);
	} else if (cur_szc < new_szc) {
		shift = page_get_shift(new_szc) - page_get_shift(cur_szc);
		return (color >> shift);
	}
	return (color);
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
 * update the page list max counts for already allocated pages that has xfer'ed
 * (kcage_assimilate_page) between different mtypes.
 */
/* ARGSUSED */
void
page_list_xfer(page_t *pp, int to_mtype, int from_mtype)
{
	PLCNT_MAX_INCR(pp, PP_2_MEM_NODE(pp), to_mtype, pp->p_szc);
	PLCNT_MAX_DECR(pp, PP_2_MEM_NODE(pp), from_mtype, pp->p_szc);
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
		 * page_freelist_coalesce and page_freelist_fill.
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
	int		flags = PG_LIST_ISCAGE;

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

	/* LINTED */
	PLCNT_DECR(pp, mnode, mtype, 0, flags);

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

	/* LINTED */
	PLCNT_INCR(pp, mnode, mtype, 0, flags);

	/*
	 * Update cage freemem counter
	 */
	atomic_add_long(&kcage_freemem, 1);
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
			page_unlock(pp);
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
	    PFN_BASE(pp->p_pagenum, pp->p_szc), pp->p_szc, 0, PC_NO_COLOR,
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
		    pp->p_szc, 0, PC_NO_COLOR, PC_FREE);
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
			    PFN_BASE(pp->p_pagenum, pp->p_szc),
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
		(void) page_promote(mnode, pfn, new_szc, PC_FREE);

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
page_promote(int mnode, pfn_t pfnum, uchar_t new_szc, int flags)
{
	page_t		*pp, *pplist, *tpp, *start_pp;
	pgcnt_t		new_npgs, npgs;
	uint_t		bin;
	pgcnt_t		tmpnpgs, pages_left;
	uint_t		mtype;
	uint_t		noreloc;
	uint_t 		i;
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

	/*
	 * Loop through smaller pages to confirm that all pages
	 * give the same result for PP_ISNORELOC().
	 * We can check this reliably here as the protocol for setting
	 * P_NORELOC requires pages to be taken off the free list first.
	 */
	for (i = 0, pp = start_pp; i < new_npgs; i++, pp++) {
		if (pp == start_pp) {
			/* First page, set requirement. */
			noreloc = PP_ISNORELOC(pp);
		} else if (noreloc != PP_ISNORELOC(pp)) {
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
				page_unlock(pp);
				goto fail_promote;
			}

			mach_page_sub(&PAGE_CACHELISTS(mnode, bin, mtype), pp);
			page_hashout(pp, phm);
			mutex_exit(phm);
			PP_SETAGED(pp);
			page_unlock(pp);
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
 */
page_t *
page_demote(int mnode, pfn_t pfnum, uchar_t cur_szc, uchar_t new_szc,
    int color, int flags)
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
			    (ret_pp == NULL) &&
			    page_trylock_cons(pp, SE_EXCL)) {
				ret_pp = pp;
			} else {
				mtype = PP_2_MTYPE(pp);
				mach_page_add(&PAGE_FREELISTS(mnode, 0, bin,
				    mtype), pp);
				page_ctr_add(mnode, mtype, pp, PG_FREE_LIST);
			}
		} else {

			/*
			 * Break down into smaller lists of pages.
			 */
			page_list_break(&pplist, &npplist, npgs);

			pp = pplist;
			n = npgs;
			while (n--) {
				ASSERT(pp->p_szc == cur_szc);
				pp->p_szc = new_szc;
				pp = pp->p_next;
			}

			CHK_LPG(pplist, new_szc);

			bin = PP_2_BIN(pplist);
			ASSERT(mnode == PP_2_MEM_NODE(pp));
			if ((bin == color) && (flags == PC_ALLOC) &&
			    (ret_pp == NULL) &&
			    page_trylock_cons(pp, SE_EXCL)) {
				ret_pp = pp;
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
 */
static page_t *
page_freelist_coalesce(int mnode, uchar_t szc, int color)
{
	int 	r;		/* region size */
	int 	idx, full, i;
	pfn_t	pfnum;
	size_t	len;
	size_t	buckets_to_check;
	pgcnt_t	cands;
	page_t	*ret_pp;
	int	color_stride;

	VM_STAT_ADD(vmm_vmstats.page_ctrs_coalesce);

	if (mpss_coalesce_disable) {
		return (NULL);
	}

	r = szc;
	PGCTRS_CANDS_GETVALUECOLOR(mnode, r, color, cands);
	if (cands == 0) {
		VM_STAT_ADD(vmm_vmstats.page_ctrs_cands_skip);
		return (NULL);
	}
	full = FULL_REGION_CNT(r);
	color_stride = (szc) ? page_convert_color(0, szc, page_colors - 1) + 1 :
	    page_colors;

	/* Prevent page_counters dynamic memory from being freed */
	rw_enter(&page_ctrs_rwlock[mnode], RW_READER);
	len  = PAGE_COUNTERS_ENTRIES(mnode, r);
	buckets_to_check = len / color_stride;
	idx = PAGE_COUNTERS_CURRENT_COLOR(mnode, r, color);
	ASSERT((idx % color_stride) == color);
	idx += color_stride;
	if (idx >= len)
		idx = color;
	for (i = 0; i < buckets_to_check; i++) {
		if (PAGE_COUNTERS(mnode, r, idx) == full) {
			pfnum = IDX_TO_PNUM(mnode, r, idx);
			ASSERT(pfnum >= mem_node_config[mnode].physbase &&
			    pfnum < mem_node_config[mnode].physmax);
			/*
			 * RFE: For performance maybe we can do something less
			 *	brutal than locking the entire freelist. So far
			 * 	this doesn't seem to be a performance problem?
			 */
			page_freelist_lock(mnode);
			if (PAGE_COUNTERS(mnode, r, idx) != full) {
				VM_STAT_ADD(vmm_vmstats.page_ctrs_changed);
				goto skip_this_one;
			}
			ret_pp = page_promote(mnode, pfnum, r, PC_ALLOC);
			if (ret_pp != NULL) {
				PAGE_COUNTERS_CURRENT_COLOR(mnode, r, color) =
				    idx;
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
skip_this_one:
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
				PAGE_COUNTERS_CURRENT_COLOR(mnode, r, color) =
				    idx;
				break;
			}
		}
		idx += color_stride;
		if (idx >= len)
			idx = color;
	}
	rw_exit(&page_ctrs_rwlock[mnode]);
	VM_STAT_ADD(vmm_vmstats.page_ctrs_failed);
	return (NULL);
}

/*
 * For the given mnode, promote as many small pages to large pages as possible.
 */
void
page_freelist_coalesce_all(int mnode)
{
	int 	r;		/* region size */
	int 	idx, full;
	pfn_t	pfnum;
	size_t	len;

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
	rw_enter(&page_ctrs_rwlock[mnode], RW_READER);
	page_freelist_lock(mnode);
	for (r = mmu_page_sizes - 1; r > 0; r--) {
		pgcnt_t cands;

		PGCTRS_CANDS_GETVALUE(mnode, r, cands);
		if (cands == 0) {
			VM_STAT_ADD(vmm_vmstats.page_ctrs_cands_skip_all);
			continue;
		}

		full = FULL_REGION_CNT(r);
		len  = PAGE_COUNTERS_ENTRIES(mnode, r);

		for (idx = 0; idx < len; idx++) {
			if (PAGE_COUNTERS(mnode, r, idx) == full) {
				pfnum = IDX_TO_PNUM(mnode, r, idx);
				ASSERT(pfnum >=
				    mem_node_config[mnode].physbase &&
				    pfnum <
				    mem_node_config[mnode].physmax);
				(void) page_promote(mnode, pfnum, r, PC_FREE);
			}
		}
	}
	page_freelist_unlock(mnode);
	rw_exit(&page_ctrs_rwlock[mnode]);
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
page_freelist_fill(uchar_t szc, int color, int mnode, int mtype, pfn_t pfnhi)
{
	uchar_t nszc = szc + 1;
	int 	bin;
	page_t	*pp, *firstpp;
	page_t	*ret_pp = NULL;

	ASSERT(szc < mmu_page_sizes);

	VM_STAT_ADD(vmm_vmstats.pff_req[szc]);
	/*
	 * First try to break up a larger page to fill
	 * current size freelist.
	 */
	while (nszc < mmu_page_sizes) {
		/*
		 * If page found then demote it.
		 */
		bin = page_convert_color(szc, nszc, color);
		if (PAGE_FREELISTS(mnode, nszc, bin, mtype)) {
			page_freelist_lock(mnode);
			firstpp = pp = PAGE_FREELISTS(mnode, nszc, bin, mtype);

			/*
			 * If pfnhi is not PFNNULL, look for large page below
			 * pfnhi. PFNNULL signifies no pfn requirement.
			 */
			if (pfnhi != PFNNULL && pp->p_pagenum >= pfnhi) {
				do {
					pp = pp->p_vpnext;
					if (pp == firstpp) {
						pp = NULL;
						break;
					}
				} while (pp->p_pagenum >= pfnhi);
			}
			if (pp) {
				ASSERT(pp->p_szc == nszc);
				VM_STAT_ADD(vmm_vmstats.pff_demote[nszc]);
				ret_pp = page_demote(mnode, pp->p_pagenum,
				    pp->p_szc, szc, color, PC_ALLOC);
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
		nszc++;
	}

	/*
	 * Ok that didn't work. Time to coalesce.
	 */
	if (szc != 0) {
		ret_pp = page_freelist_coalesce(mnode, szc, color);
		VM_STAT_COND_ADD(ret_pp, vmm_vmstats.pff_coalok[szc]);
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
			 * On failure unlock what we
			 * have locked so far.
			 */
			while (first_pp != tpp) {
				page_unlock(first_pp);
				first_pp = first_pp->p_next;
			}
			return (0);
		}
		tpp = tpp->p_next;
	}
	return (1);
}

page_t *
page_get_mnode_freelist(int mnode, uint_t bin, int mtype, uchar_t szc,
    uint_t flags)
{
	kmutex_t	*pcm;
	int		i, fill_tried, fill_marker;
	page_t		*pp, *first_pp;
	uint_t		bin_marker;
	int		colors, cpucolors;
	uchar_t		nszc;
	uint_t		nszc_color_shift;
	int		nwaybins = 0, nwaycnt;

	ASSERT(szc < mmu_page_sizes);

	VM_STAT_ADD(vmm_vmstats.pgmf_alloc[szc]);

	MTYPE_START(mnode, mtype, flags);
	if (mtype < 0) {	/* mnode foes not have memory in mtype range */
		VM_STAT_ADD(vmm_vmstats.pgmf_allocempty[szc]);
		return (NULL);
	}

	/*
	 * Set how many physical colors for this page size.
	 */
	colors = (szc) ? page_convert_color(0, szc, page_colors - 1) + 1 :
	    page_colors;

	nszc = MIN(szc + 1, mmu_page_sizes - 1);
	nszc_color_shift = page_get_shift(nszc) - page_get_shift(szc);

	/* cpu_page_colors is non-zero if a page color may be in > 1 bin */
	cpucolors = cpu_page_colors;

	/*
	 * adjust cpucolors to possibly check additional 'equivalent' bins
	 * to try to minimize fragmentation of large pages by delaying calls
	 * to page_freelist_fill.
	 */
	if (colorequiv > 1) {
		int equivcolors = colors / colorequiv;

		if (equivcolors && (cpucolors == 0 || equivcolors < cpucolors))
			cpucolors = equivcolors;
	}

	ASSERT(colors <= page_colors);
	ASSERT(colors);
	ASSERT((colors & (colors - 1)) == 0);

	ASSERT(bin < colors);

	/*
	 * Only hold one freelist lock at a time, that way we
	 * can start anywhere and not have to worry about lock
	 * ordering.
	 */
big_try_again:
	fill_tried = 0;
	nwaycnt = 0;
	for (i = 0; i <= colors; i++) {
try_again:
		ASSERT(bin < colors);
		if (PAGE_FREELISTS(mnode, szc, bin, mtype)) {
			pcm = PC_BIN_MUTEX(mnode, bin, PG_FREE_LIST);
			mutex_enter(pcm);
			pp = PAGE_FREELISTS(mnode, szc, bin, mtype);
			if (pp != NULL) {
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
				while (!page_trylock_cons(pp, SE_EXCL)) {
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
					ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) ==
							mnode);

					if (pp == first_pp) {
						pp = NULL;
						break;
					}
				}

				if (pp) {
					ASSERT(mtype == PP_2_MTYPE(pp));
					ASSERT(pp->p_szc == szc);
					if (szc == 0) {
						page_sub(&PAGE_FREELISTS(mnode,
						    szc, bin, mtype), pp);
					} else {
						page_vpsub(&PAGE_FREELISTS(
						    mnode, szc, bin, mtype),
						    pp);
						CHK_LPG(pp, szc);
					}
					page_ctr_sub(mnode, mtype, pp,
					    PG_FREE_LIST);

					if ((PP_ISFREE(pp) == 0) ||
					    (PP_ISAGED(pp) == 0))
						panic("free page is not. pp %p",
						    (void *)pp);
					mutex_exit(pcm);

#if defined(__sparc)
					ASSERT(!kcage_on || PP_ISNORELOC(pp) ||
					    (flags & PG_NORELOC) == 0);

					if (PP_ISNORELOC(pp)) {
						pgcnt_t	npgs;

						npgs = page_get_pagecnt(szc);
						kcage_freemem_sub(npgs);
					}
#endif
					VM_STAT_ADD(vmm_vmstats.
					    pgmf_allocok[szc]);
					return (pp);
				}
			}
			mutex_exit(pcm);
		}

		/*
		 * Wow! The initial bin is empty.
		 * If specific color is needed, check if page color may be
		 * in other bins. cpucolors is:
		 *   0	if the colors for this cpu is equal to page_colors.
		 *	This means that pages with a particular color are in a
		 *	single bin.
		 *  -1	if colors of cpus (cheetah+) are heterogenous. Need to
		 *	first determine the colors for the current cpu.
		 *  >0	colors of all cpus are homogenous and < page_colors
		 */

		if ((flags & PG_MATCH_COLOR) && (cpucolors != 0)) {
			if (!nwaybins) {
				/*
				 * cpucolors is negative if ecache setsizes
				 * are heterogenous. determine colors for this
				 * particular cpu.
				 */
				if (cpucolors < 0) {
					cpucolors = CPUSETSIZE() / MMU_PAGESIZE;
					ASSERT(cpucolors > 0);
					nwaybins = colors / cpucolors;
				} else {
					nwaybins = colors / cpucolors;
					ASSERT(szc > 0 || nwaybins > 1);
				}
				if (nwaybins < 2)
					cpucolors = 0;
			}

			if (cpucolors && (nwaycnt + 1 <= nwaybins)) {
				nwaycnt++;
				bin = (bin + (colors / nwaybins)) &
				    (colors - 1);
				if (nwaycnt < nwaybins) {
					goto try_again;
				}
			}
			/* back to initial color if fall-thru */
		}

		/*
		 * color bins are all empty if color match. Try and satisfy
		 * the request by breaking up or coalescing pages from
		 * a different size freelist of the correct color that
		 * satisfies the ORIGINAL color requested. If that
		 * fails then try pages of the same size but different
		 * colors assuming we are not called with
		 * PG_MATCH_COLOR.
		 */
		if (!fill_tried) {
			fill_tried = 1;
			fill_marker = bin >> nszc_color_shift;
			pp = page_freelist_fill(szc, bin, mnode, mtype,
			    PFNNULL);
			if (pp != NULL) {
				return (pp);
			}
		}

		if (flags & PG_MATCH_COLOR)
			break;

		/*
		 * Select next color bin to try.
		 */
		if (szc == 0) {
			/*
			 * PAGESIZE page case.
			 */
			if (i == 0) {
				bin = (bin + BIN_STEP) & page_colors_mask;
				bin_marker = bin;
			} else {
				bin = (bin + vac_colors) & page_colors_mask;
				if (bin == bin_marker) {
					bin = (bin + 1) & page_colors_mask;
					bin_marker = bin;
				}
			}
		} else {
			/*
			 * Large page case.
			 */
			bin = (bin + 1) & (colors - 1);
		}
		/*
		 * If bin advanced to the next color bin of the
		 * next larger pagesize, there is a chance the fill
		 * could succeed.
		 */
		if (fill_marker != (bin >> nszc_color_shift))
			fill_tried = 0;
	}

	/* if allowed, cycle through additional mtypes */
	MTYPE_NEXT(mnode, mtype, flags);
	if (mtype >= 0)
		goto big_try_again;

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
				page_unlock(pp);
			}
			return (0);
		}
		ASSERT(spp[i].p_pagenum == spp->p_pagenum + i);
		if ((pp->p_szc > szc || (szc && pp->p_szc == szc)) &&
		    !PP_ISFREE(pp)) {
			VM_STAT_ADD(vmm_vmstats.ptcpfailszc[szc]);
			ASSERT(i == 0);
			page_unlock(pp);
			return (0);
		}
		if (PP_ISNORELOC(pp)) {
			VM_STAT_ADD(vmm_vmstats.ptcpfailcage[szc]);
			while (i != (pgcnt_t)-1) {
				pp = &spp[i];
				ASSERT(PAGE_EXCL(pp));
				page_unlock(pp);
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
				page_unlock(pp);
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
				page_unlock(pp);
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
			page_unlock(rpp);
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
				*lo = kcagepfn;
				*hi = MIN(pfnhi,
				    (mseg->pages_end - 1));
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
				*hi = kcagepfn;
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
 * called from page_get_contig_pages to search 'pfnlo' thru 'pfnhi' to "claim" a
 * page with size code 'szc'. Claiming such a page requires acquiring
 * exclusive locks on all constituent pages (page_trylock_contig_pages),
 * relocating pages in use and concatenating these constituent pages into a
 * large page.
 *
 * The page lists do not have such a large page and page_freelist_fill has
 * already failed to demote larger pages and/or coalesce smaller free pages.
 *
 * 'flags' may specify PG_COLOR_MATCH which would limit the search of large
 * pages with the same color as 'bin'.
 *
 * 'pfnflag' specifies the subset of the pfn range to search.
 */


static page_t *
page_geti_contig_pages(int mnode, uint_t bin, uchar_t szc, int flags,
    pfn_t pfnlo, pfn_t pfnhi, int pfnflag)
{
	struct memseg *mseg;
	pgcnt_t	szcpgcnt = page_get_pagecnt(szc);
	pgcnt_t szcpgmask = szcpgcnt - 1;
	pfn_t	randpfn;
	page_t *pp, *randpp, *endpp;
	uint_t colors;
	pfn_t hi, lo;
	uint_t skip;

	ASSERT(szc != 0 || (flags & PGI_PGCPSZC0));

	if ((pfnhi - pfnlo) + 1 < szcpgcnt)
		return (NULL);

	ASSERT(szc < mmu_page_sizes);

	colors = (szc) ? page_convert_color(0, szc, page_colors - 1) + 1 :
	    page_colors;

	ASSERT(bin < colors);

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

		pfnlo = P2ROUNDUP(pfnlo, szcpgcnt);
		pfnhi = pfnhi & ~(szcpgcnt - 1);

		szcpages = ((pfnhi - pfnlo) + 1) / szcpgcnt;
		slotlen = howmany(szcpages, slots);
		pfnlo = pfnlo + (((slotid * slotlen) % szcpages) * szcpgcnt);
		ASSERT(pfnlo < pfnhi);
		if (pfnhi > pfnlo + (slotlen * szcpgcnt))
			pfnhi = pfnlo + (slotlen * szcpgcnt);
	}

	memsegs_lock(0);

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

		/* trim off kernel cage pages from pfn range */
		if (kcage_on) {
			if (trimkcage(mseg, &lo, &hi, pfnlo, pfnhi) == 0)
				continue;
		} else {
			lo = MAX(pfnlo, mseg->pages_base);
			hi = MIN(pfnhi, (mseg->pages_end - 1));
		}

		/* round to szcpgcnt boundaries */
		lo = P2ROUNDUP(lo, szcpgcnt);
		hi = hi & ~(szcpgcnt - 1);

		if (hi <= lo)
			continue;

		/*
		 * set lo to point to the pfn for the desired bin. Large
		 * page sizes may only have a single page color
		 */
		if ((colors > 1) && (flags & PG_MATCH_COLOR)) {
			uint_t	lobin;

			/*
			 * factor in colorequiv to check additional
			 * 'equivalent' bins.
			 */
			if (colorequiv > 1 && colors > colorequiv)
				colors = colors / colorequiv;

			/* determine bin that lo currently points to */
			lobin = (lo & ((szcpgcnt * colors) - 1)) / szcpgcnt;

			/*
			 * set lo to point at appropriate color and set skip
			 * to arrive at the next szc page of the same color.
			 */
			lo += ((bin - lobin) & (colors - 1)) * szcpgcnt;

			skip = colors * szcpgcnt;
		} else {
			/* check all pages starting from lo */
			skip = szcpgcnt;
		}
		if (hi <= lo)
			/* mseg cannot satisfy color request */
			continue;

		/* randomly choose a point between lo and hi to begin search */

		randpfn = (pfn_t)GETTICK();
		randpfn = ((randpfn % (hi - lo)) + lo) & ~(skip - 1);
		randpp = mseg->pages + (randpfn - mseg->pages_base);

		ASSERT(randpp->p_pagenum == randpfn);

		pp = randpp;
		endpp =  mseg->pages + (hi - mseg->pages_base);

		ASSERT(randpp + szcpgcnt <= endpp);

		do {
			ASSERT(!(pp->p_pagenum & szcpgmask));
			ASSERT((flags & PG_MATCH_COLOR) == 0 ||
			    colorequiv > 1 ||
			    PP_2_BIN(pp) == bin);
			if (page_trylock_contig_pages(mnode, pp, szc, flags)) {
				/* pages unlocked by page_claim on failure */
				if (page_claim_contig_pages(pp, szc, flags)) {
					memsegs_unlock(0);
					return (pp);
				}
			}

			pp += skip;
			if (pp >= endpp) {
				/* start from the beginning */
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
	int		pfnflag = 0;	/* no limit on search if 0 */

	VM_STAT_ADD(vmm_vmstats.pgcp_alloc[szc]);

	/* LINTED */
	MTYPE_START(mnode, mtype, flags);
	if (mtype < 0) {	/* mnode does not have memory in mtype range */
		VM_STAT_ADD(vmm_vmstats.pgcp_allocempty[szc]);
		return (NULL);
	}

	ASSERT(szc > 0 || (flags & PGI_PGCPSZC0));

	/* no allocations from cage */
	flags |= PGI_NOCAGE;

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
	MTYPE_INIT(mtype, vp, vaddr, flags);

	/*
	 * Convert size to page size code.
	 */
	if ((szc = page_szc(size)) == (uchar_t)-1)
		panic("page_get_freelist: illegal page size request");
	ASSERT(szc < mmu_page_sizes);

	VM_STAT_ADD(vmm_vmstats.pgf_alloc[szc]);

	/* LINTED */
	AS_2_BIN(as, seg, vp, vaddr, bin);

	/* bin is for base pagesize color - convert if larger pagesize. */
	if (szc)
		bin = page_convert_color(0, szc, bin);

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

	if (pgcplimitsearch && page_get_func == page_get_contig_pages)
		pgcpfailcnt[szc]++;

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
	AS_2_BIN(as, seg, vp, vaddr, bin);

	ASSERT(bin <= page_colors_mask);

	/* LINTED */
	MTYPE_INIT(mtype, vp, vaddr, flags);

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
	kmutex_t	*pcm;
	int		i;
	page_t		*pp;
	page_t		*first_pp;
	uint_t		bin_marker;
	int		nwaybins, nwaycnt;
	int		cpucolors;

	VM_STAT_ADD(vmm_vmstats.pgmc_alloc);

	/* LINTED */
	MTYPE_START(mnode, mtype, flags);
	if (mtype < 0) {	/* mnode does not have memory in mtype range */
		VM_STAT_ADD(vmm_vmstats.pgmc_allocempty);
		return (NULL);
	}

	nwaybins = 0;
	cpucolors = cpu_page_colors;
	/*
	 * adjust cpucolors to possibly check additional 'equivalent' bins
	 * to try to minimize fragmentation of large pages by delaying calls
	 * to page_freelist_fill.
	 */
	if (colorequiv > 1) {
		int equivcolors = page_colors / colorequiv;

		if (equivcolors && (cpucolors == 0 || equivcolors < cpucolors))
			cpucolors = equivcolors;
	}

	/*
	 * Only hold one cachelist lock at a time, that way we
	 * can start anywhere and not have to worry about lock
	 * ordering.
	 */

big_try_again:
	nwaycnt = 0;
	for (i = 0; i <= page_colors; i++) {
		if (PAGE_CACHELISTS(mnode, bin, mtype)) {
			pcm = PC_BIN_MUTEX(mnode, bin, PG_CACHE_LIST);
			mutex_enter(pcm);
			pp = PAGE_CACHELISTS(mnode, bin, mtype);
			if (pp != NULL) {
				first_pp = pp;
				ASSERT(pp->p_vnode);
				ASSERT(PP_ISAGED(pp) == 0);
				ASSERT(pp->p_szc == 0);
				ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) == mnode);
				while (!page_trylock(pp, SE_EXCL)) {
					pp = pp->p_next;
					ASSERT(pp->p_szc == 0);
					if (pp == first_pp) {
						/*
						 * We have searched the
						 * complete list!
						 * And all of them (might
						 * only be one) are locked.
						 * This can happen since
						 * these pages can also be
						 * found via the hash list.
						 * When found via the hash
						 * list, they are locked
						 * first, then removed.
						 * We give up to let the
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
					ppp = &PAGE_CACHELISTS(mnode, bin,
					    mtype);
					page_sub(ppp, pp);
					/*
					 * Subtract counters before releasing
					 * pcm mutex to avoid a race with
					 * page_freelist_coalesce and
					 * page_freelist_fill.
					 */
					page_ctr_sub(mnode, mtype, pp,
					    PG_CACHE_LIST);
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
					VM_STAT_ADD(vmm_vmstats.
					    pgmc_allocok);
					return (pp);
				}
			}
			mutex_exit(pcm);
		}

		/*
		 * Wow! The initial bin is empty or no page in the bin could
		 * be locked.
		 *
		 * If specific color is needed, check if page color may be in
		 * other bins.
		 */
		if ((flags & PG_MATCH_COLOR) && (cpucolors != 0)) {
			if (!nwaybins) {
				if (cpucolors < 0) {
					cpucolors = CPUSETSIZE() / MMU_PAGESIZE;
					ASSERT(cpucolors > 0);
					nwaybins = page_colors / cpucolors;
					if (nwaybins < 2)
						cpucolors = 0;
				} else {
					nwaybins = page_colors / cpucolors;
					ASSERT(nwaybins > 1);
				}
			}

			if (++nwaycnt >= nwaybins) {
				break;
			}
			bin = (bin + (page_colors / nwaybins)) &
			    page_colors_mask;
			continue;
		}

		if (i == 0) {
			bin = (bin + BIN_STEP) & page_colors_mask;
			bin_marker = bin;
		} else {
			bin = (bin + vac_colors) & page_colors_mask;
			if (bin == bin_marker) {
				bin = (bin + 1) & page_colors_mask;
				bin_marker = bin;
			}
		}
	}

	MTYPE_NEXT(mnode, mtype, flags);
	if (mtype >= 0)
		goto big_try_again;

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
#define	REPL_STAT_INCR(v)	atomic_add_32(&repl_page_stats.v, 1)
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
	if (like_pp->p_vnode == &kvp)
		pgrflags |= PGR_SAMESZC;

	/* LINTED */
	MTYPE_PGR_INIT(mtype, flags, like_pp, page_mnode);

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
					pplist = page_get_mnode_freelist(
						mnode, bin, mtype, szc,
						    flags);
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
					pplist = page_get_mnode_cachelist(
						bin, flags, mnode, mtype);
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
		    pp->p_szc), pp->p_szc, 0, PC_NO_COLOR, PC_FREE);
	}
	page_freelist_unlock(mnode);
	ASSERT(pp->p_szc == 0);
}

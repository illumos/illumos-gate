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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/elf_SPARC.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#include <sys/cpuvar.h>
#include <sys/async.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/cpu_module.h>
#include <sys/prom_debug.h>
#include <sys/vmsystm.h>
#include <sys/prom_plat.h>
#include <sys/sysmacros.h>
#include <sys/intreg.h>
#include <sys/machtrap.h>
#include <sys/ontrap.h>
#include <sys/ivintr.h>
#include <sys/atomic.h>
#include <sys/panic.h>
#include <sys/dtrace.h>
#include <sys/simulate.h>
#include <sys/fault.h>
#include <sys/niagara2regs.h>
#include <sys/hsvc.h>
#include <sys/trapstat.h>
#include <sys/mutex_impl.h>

uint_t root_phys_addr_lo_mask = 0xffffffffU;
#if defined(NIAGARA2_IMPL)
char cpu_module_name[] = "SUNW,UltraSPARC-T2";
#elif defined(VFALLS_IMPL)
char cpu_module_name[] = "SUNW,UltraSPARC-T2+";
#endif

/*
 * Hypervisor services information for the NIAGARA2 and Victoria Falls
 * CPU module
 */
static boolean_t cpu_hsvc_available = B_TRUE;
static uint64_t cpu_sup_minor;		/* Supported minor number */
#if defined(NIAGARA2_IMPL)
static hsvc_info_t cpu_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_NIAGARA2_CPU, NIAGARA2_HSVC_MAJOR,
	NIAGARA2_HSVC_MINOR, cpu_module_name
};
#elif defined(VFALLS_IMPL)
static hsvc_info_t cpu_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_VFALLS_CPU, VFALLS_HSVC_MAJOR,
	VFALLS_HSVC_MINOR, cpu_module_name
};
#endif

void
cpu_setup(void)
{
	extern int mmu_exported_pagesize_mask;
	extern int cpc_has_overflow_intr;
	extern size_t contig_mem_prealloc_base_size;
	int status;

	/*
	 * Negotiate the API version for Niagara2 specific hypervisor
	 * services.
	 */
	status = hsvc_register(&cpu_hsvc, &cpu_sup_minor);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: cannot negotiate hypervisor services "
		    "group: 0x%lx major: 0x%lx minor: 0x%lx errno: %d",
		    cpu_hsvc.hsvc_modname, cpu_hsvc.hsvc_group,
		    cpu_hsvc.hsvc_major, cpu_hsvc.hsvc_minor, status);
		cpu_hsvc_available = B_FALSE;
	}

	/*
	 * The setup common to all CPU modules is done in cpu_setup_common
	 * routine.
	 */
	cpu_setup_common(NULL);

	cache |= (CACHE_PTAG | CACHE_IOCOHERENT);

	if ((mmu_exported_pagesize_mask &
	    DEFAULT_SUN4V_MMU_PAGESIZE_MASK) !=
	    DEFAULT_SUN4V_MMU_PAGESIZE_MASK)
		cmn_err(CE_PANIC, "machine description"
		    " does not have required sun4v page sizes"
		    " 8K, 64K and 4M: MD mask is 0x%x",
		    mmu_exported_pagesize_mask);

	cpu_hwcap_flags = AV_SPARC_VIS | AV_SPARC_VIS2 | AV_SPARC_ASI_BLK_INIT;

	/*
	 * Niagara2 supports a 48-bit subset of the full 64-bit virtual
	 * address space. Virtual addresses between 0x0000800000000000
	 * and 0xffff.7fff.ffff.ffff inclusive lie within a "VA Hole"
	 * and must never be mapped. In addition, software must not use
	 * pages within 4GB of the VA hole as instruction pages to
	 * avoid problems with prefetching into the VA hole.
	 */
	hole_start = (caddr_t)((1ull << (va_bits - 1)) - (1ull << 32));
	hole_end = (caddr_t)((0ull - (1ull << (va_bits - 1))) + (1ull << 32));

	/*
	 * Niagara2 has a performance counter overflow interrupt
	 */
	cpc_has_overflow_intr = 1;

	/*
	 * Enable 4M pages for OOB.
	 */
	max_uheap_lpsize = MMU_PAGESIZE4M;
	max_ustack_lpsize = MMU_PAGESIZE4M;
	max_privmap_lpsize = MMU_PAGESIZE4M;

#ifdef SUN4V_CONTIG_MEM_PREALLOC_SIZE_MB
	/*
	 * Use CPU Makefile specific compile time define (if exists)
	 * to add to the contig preallocation size.
	 */
	contig_mem_prealloc_base_size = MB(SUN4V_CONTIG_MEM_PREALLOC_SIZE_MB);
#endif
}

/*
 * Set the magic constants of the implementation.
 */
void
cpu_fiximp(struct cpu_node *cpunode)
{
	/*
	 * The Cache node is optional in MD. Therefore in case "Cache"
	 * node does not exists in MD, set the default L2 cache associativity,
	 * size, linesize.
	 */
	if (cpunode->ecache_size == 0)
		cpunode->ecache_size = L2CACHE_SIZE;
	if (cpunode->ecache_linesize == 0)
		cpunode->ecache_linesize = L2CACHE_LINESIZE;
	if (cpunode->ecache_associativity == 0)
		cpunode->ecache_associativity = L2CACHE_ASSOCIATIVITY;
}

void
cpu_map_exec_units(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * The cpu_ipipe and cpu_fpu fields are initialized based on
	 * the execution unit sharing information from the MD. They
	 * default to the CPU id in the absence of such information.
	 */
	cp->cpu_m.cpu_ipipe = cpunodes[cp->cpu_id].exec_unit_mapping;
	if (cp->cpu_m.cpu_ipipe == NO_EU_MAPPING_FOUND)
		cp->cpu_m.cpu_ipipe = (id_t)(cp->cpu_id);

	cp->cpu_m.cpu_fpu = cpunodes[cp->cpu_id].fpu_mapping;
	if (cp->cpu_m.cpu_fpu == NO_EU_MAPPING_FOUND)
		cp->cpu_m.cpu_fpu = (id_t)(cp->cpu_id);

	/*
	 * Niagara 2 defines the core to be at the FPU level
	 */
	cp->cpu_m.cpu_core = cp->cpu_m.cpu_fpu;

	/*
	 * The cpu_chip field is initialized based on the information
	 * in the MD and assume that all cpus within a chip
	 * share the same L2 cache. If no such info is available, we
	 * set the cpu to belong to the defacto chip 0.
	 */
	cp->cpu_m.cpu_mpipe = cpunodes[cp->cpu_id].l2_cache_mapping;
	if (cp->cpu_m.cpu_mpipe == NO_L2_CACHE_MAPPING_FOUND)
		cp->cpu_m.cpu_mpipe = CPU_L2_CACHEID_INVALID;

	cp->cpu_m.cpu_chip = cpunodes[cp->cpu_id].l2_cache_mapping;
	if (cp->cpu_m.cpu_chip == NO_L2_CACHE_MAPPING_FOUND)
		cp->cpu_m.cpu_chip = CPU_CHIPID_INVALID;
}

static int cpucnt;

void
cpu_init_private(struct cpu *cp)
{
	extern void niagara_kstat_init(void);

	ASSERT(MUTEX_HELD(&cpu_lock));

	cpu_map_exec_units(cp);

	if ((cpucnt++ == 0) && (cpu_hsvc_available == B_TRUE))
		(void) niagara_kstat_init();

	mutex_delay = rdccr_delay;
}

/*ARGSUSED*/
void
cpu_uninit_private(struct cpu *cp)
{
	extern void niagara_kstat_fini(void);

	ASSERT(MUTEX_HELD(&cpu_lock));
	if ((--cpucnt == 0) && (cpu_hsvc_available == B_TRUE))
		(void) niagara_kstat_fini();
}

/*
 * On Niagara2, any flush will cause all preceding stores to be
 * synchronized wrt the i$, regardless of address or ASI.  In fact,
 * the address is ignored, so we always flush address 0.
 */
/*ARGSUSED*/
void
dtrace_flush_sec(uintptr_t addr)
{
	doflush(0);
}

/*
 * Trapstat support for Niagara2 processor
 * The Niagara2 provides HWTW support for TSB lookup and with HWTW
 * enabled no TSB hit information will be available. Therefore setting
 * the time spent in TLB miss handler for TSB hits to 0.
 */
int
cpu_trapstat_conf(int cmd)
{
	int status = 0;

	switch (cmd) {
	case CPU_TSTATCONF_INIT:
	case CPU_TSTATCONF_FINI:
	case CPU_TSTATCONF_ENABLE:
	case CPU_TSTATCONF_DISABLE:
		break;
	default:
		status = EINVAL;
		break;
	}
	return (status);
}

void
cpu_trapstat_data(void *buf, uint_t tstat_pgszs)
{
	tstat_pgszdata_t	*tstatp = (tstat_pgszdata_t *)buf;
	int	i;

	for (i = 0; i < tstat_pgszs; i++, tstatp++) {
		tstatp->tpgsz_kernel.tmode_itlb.ttlb_tlb.tmiss_count = 0;
		tstatp->tpgsz_kernel.tmode_itlb.ttlb_tlb.tmiss_time = 0;
		tstatp->tpgsz_user.tmode_itlb.ttlb_tlb.tmiss_count = 0;
		tstatp->tpgsz_user.tmode_itlb.ttlb_tlb.tmiss_time = 0;
		tstatp->tpgsz_kernel.tmode_dtlb.ttlb_tlb.tmiss_count = 0;
		tstatp->tpgsz_kernel.tmode_dtlb.ttlb_tlb.tmiss_time = 0;
		tstatp->tpgsz_user.tmode_dtlb.ttlb_tlb.tmiss_count = 0;
		tstatp->tpgsz_user.tmode_dtlb.ttlb_tlb.tmiss_time = 0;
	}
}

/*
 * Page coloring support for hashed cache index mode
 */

/*
 * Node id bits from machine description (MD).  Node id distinguishes
 * local versus remote memory. Because of MPO, page allocation does
 * not cross node boundaries. Therefore, remove the node id bits from
 * the color, since they are fixed. Either bit 30, or 31:30 in
 * Victoria Falls processors.
 * The number of node id bits is always 0 in Niagara2.
 */
typedef struct n2color {
	uchar_t nnbits;	/* number of node id bits */
	uchar_t nnmask; /* mask for node id bits */
	uchar_t	lomask;	/* mask for bits below node id */
	uchar_t lobits;	/* number of bits below node id */
} n2color_t;

n2color_t n2color[MMU_PAGE_SIZES];
static uchar_t nhbits[] = {7, 7, 6, 5, 5, 5};

/*
 * Remove node id bits from color bits 32:28.
 * This will reduce the number of colors.
 * No change if number of node bits is zero.
 */
static inline uint_t
n2_hash2color(uint_t color, uchar_t szc)
{
	n2color_t m = n2color[szc];

	if (m.nnbits > 0) {
		color = ((color >> m.nnbits) & ~m.lomask) | (color & m.lomask);
		ASSERT((color & ~(hw_page_array[szc].hp_colors - 1)) == 0);
	}

	return (color);
}

/*
 * Restore node id bits into page color.
 * This will increase the number of colors to match N2.
 * No change if number of node bits is zero.
 */
static inline uint_t
n2_color2hash(uint_t color, uchar_t szc, uint_t node)
{
	n2color_t m = n2color[szc];

	if (m.nnbits > 0) {
		color = ((color & ~m.lomask) << m.nnbits) | (color & m.lomask);
		color |= (node & m.nnmask) << m.lobits;
	}

	return (color);
}

/* NI2 L2$ index is pa[32:28]^pa[17:13].pa[19:18]^pa[12:11].pa[10:6] */

/*
 * iterator NULL means pfn is VA, do not adjust ra_to_pa
 * iterator (-1) means pfn is RA, need to convert to PA
 * iterator non-null means pfn is RA, use ra_to_pa
 */
uint_t
page_pfn_2_color_cpu(pfn_t pfn, uchar_t szc, void *cookie)
{
	mem_node_iterator_t *it = cookie;
	uint_t color;

	ASSERT(szc <= TTE256M);

	if (it == ((mem_node_iterator_t *)(-1))) {
		pfn = plat_rapfn_to_papfn(pfn);
	} else if (it != NULL) {
		ASSERT(pfn >= it->mi_mblock_base && pfn <= it->mi_mblock_end);
		pfn = pfn + it->mi_ra_to_pa;
	}
	pfn = PFN_BASE(pfn, szc);
	color = ((pfn >> 15) ^ pfn) & 0x1f;
	if (szc < TTE4M) {
		/* 19:18 */
		color = (color << 2) | ((pfn >> 5) & 0x3);
		if (szc > TTE64K)
			color >>= 1;    /* 19 */
	}
	return (n2_hash2color(color, szc));
}

static uint_t
page_papfn_2_color_cpu(pfn_t papfn, uchar_t szc)
{
	uint_t color;

	ASSERT(szc <= TTE256M);

	papfn = PFN_BASE(papfn, szc);
	color = ((papfn >> 15) ^ papfn) & 0x1f;
	if (szc < TTE4M) {
		/* 19:18 */
		color = (color << 2) | ((papfn >> 5) & 0x3);
		if (szc > TTE64K)
			color >>= 1;    /* 19 */
	}
	return (color);
}

#if TTE256M != 5
#error TTE256M is not 5
#endif

uint_t
page_get_nsz_color_mask_cpu(uchar_t szc, uint_t mask)
{
	static uint_t ni2_color_masks[5] = {0x63, 0x1e, 0x3e, 0x1f, 0x1f};
	ASSERT(szc < TTE256M);
	mask = n2_color2hash(mask, szc, 0);
	mask &= ni2_color_masks[szc];
	if (szc == TTE64K || szc == TTE512K)
		mask >>= 1;
	return (n2_hash2color(mask, szc + 1));
}

uint_t
page_get_nsz_color_cpu(uchar_t szc, uint_t color)
{
	ASSERT(szc < TTE256M);
	color = n2_color2hash(color, szc, 0);
	if (szc == TTE64K || szc == TTE512K)
		color >>= 1;
	return (n2_hash2color(color, szc + 1));
}

uint_t
page_get_color_shift_cpu(uchar_t szc, uchar_t nszc)
{
	uint_t s;
	ASSERT(nszc >= szc);
	ASSERT(nszc <= TTE256M);

	s = nhbits[szc] - n2color[szc].nnbits;
	s -= nhbits[nszc] - n2color[nszc].nnbits;

	return (s);
}

uint_t
page_convert_color_cpu(uint_t ncolor, uchar_t szc, uchar_t nszc)
{
	uint_t color;

	ASSERT(nszc > szc);
	ASSERT(nszc <= TTE256M);
	ncolor = n2_color2hash(ncolor, nszc, 0);
	color = ncolor << (nhbits[szc] - nhbits[nszc]);
	color = n2_hash2color(color, szc);
	return (color);
}

#define	PAPFN_2_MNODE(pfn) \
	(((pfn) & it->mi_mnode_pfn_mask) >> it->mi_mnode_pfn_shift)

/*ARGSUSED*/
pfn_t
page_next_pfn_for_color_cpu(pfn_t pfn, uchar_t szc, uint_t color,
    uint_t ceq_mask, uint_t color_mask, void *cookie)
{
	mem_node_iterator_t *it = cookie;
	pfn_t pstep = PNUM_SIZE(szc);
	pfn_t npfn, pfn_ceq_mask, pfn_color;
	pfn_t tmpmask, mask = (pfn_t)-1;
	uint_t pfnmn;

	ASSERT((color & ~ceq_mask) == 0);
	ASSERT(pfn >= it->mi_mblock_base && pfn <= it->mi_mblock_end);

	/* convert RA to PA for accurate color calculation */
	if (it->mi_init) {
		/* first call after it, so cache these values */
		it->mi_hash_ceq_mask =
		    n2_color2hash(ceq_mask, szc, it->mi_mnode_mask);
		it->mi_hash_color =
		    n2_color2hash(color, szc, it->mi_mnode);
		it->mi_init = 0;
	} else {
		ASSERT(it->mi_hash_ceq_mask ==
		    n2_color2hash(ceq_mask, szc, it->mi_mnode_mask));
		ASSERT(it->mi_hash_color ==
		    n2_color2hash(color, szc, it->mi_mnode));
	}
	ceq_mask = it->mi_hash_ceq_mask;
	color = it->mi_hash_color;
	pfn += it->mi_ra_to_pa;

	/* restart here when we switch memblocks */
next_mem_block:
	if (szc <= TTE64K) {
		pfnmn = PAPFN_2_MNODE(pfn);
	}
	if (((page_papfn_2_color_cpu(pfn, szc) ^ color) & ceq_mask) == 0 &&
	    (szc > TTE64K || pfnmn == it->mi_mnode)) {

		/* we start from the page with correct color */
		if (szc >= TTE512K) {
			if (szc >= TTE4M) {
				/* page color is PA[32:28] */
				pfn_ceq_mask = ceq_mask << 15;
			} else {
				/* page color is PA[32:28].PA[19:19] */
				pfn_ceq_mask = ((ceq_mask & 1) << 6) |
				    ((ceq_mask >> 1) << 15);
			}
			npfn = ADD_MASKED(pfn, pstep, pfn_ceq_mask, mask);
			goto done;
		} else {
			/*
			 * We deal 64K or 8K page. Check if we could the
			 * satisfy the request without changing PA[32:28]
			 */
			pfn_ceq_mask = ((ceq_mask & 3) << 5) | (ceq_mask >> 2);
			pfn_ceq_mask |= it->mi_mnode_pfn_mask;
			npfn = ADD_MASKED(pfn, pstep, pfn_ceq_mask, mask);

			if ((((npfn ^ pfn) >> 15) & 0x1f) == 0)
				goto done;

			/*
			 * for next pfn we have to change bits PA[32:28]
			 * set PA[63:28] and PA[19:18] of the next pfn
			 */
			npfn = (pfn >> 15) << 15;
			npfn |= (ceq_mask & color & 3) << 5;
			pfn_ceq_mask = (szc == TTE8K) ? 0 :
			    (ceq_mask & 0x1c) << 13;
			pfn_ceq_mask |= it->mi_mnode_pfn_mask;
			npfn = ADD_MASKED(npfn, (1 << 15), pfn_ceq_mask, mask);

			/*
			 * set bits PA[17:13] to match the color
			 */
			npfn |= ((npfn >> 15) ^ (color >> 2)) & (ceq_mask >> 2);
			goto done;
		}
	}

	/*
	 * we start from the page with incorrect color - rare case
	 */
	if (szc >= TTE512K) {
		if (szc >= TTE4M) {
			/* page color is in bits PA[32:28] */
			npfn = ((pfn >> 20) << 20) | (color << 15);
			pfn_ceq_mask = (ceq_mask << 15) | 0x7fff;
		} else {
			/* try get the right color by changing bit PA[19:19] */
			npfn = pfn + pstep;
			if (((page_papfn_2_color_cpu(npfn, szc) ^ color) &
			    ceq_mask) == 0)
				goto done;

			/* page color is PA[32:28].PA[19:19] */
			pfn_ceq_mask = ((ceq_mask & 1) << 6) |
			    ((ceq_mask >> 1) << 15) | (0xff << 7);
			pfn_color = ((color & 1) << 6) | ((color >> 1) << 15);
			npfn = ((pfn >> 20) << 20) | pfn_color;
		}

		while (npfn <= pfn) {
			npfn = ADD_MASKED(npfn, pstep, pfn_ceq_mask, mask);
		}
		goto done;
	}

	/*
	 *  We deal 64K or 8K page of incorrect color.
	 * Try correcting color without changing PA[32:28]
	 */
	pfn_ceq_mask = ((ceq_mask & 3) << 5) | (ceq_mask >> 2);
	pfn_color = ((color & 3) << 5) | (color >> 2);
	if (pfnmn == it->mi_mnode) {
		npfn = (pfn & ~(pfn_t)0x7f);
		npfn |= (((pfn >> 15) & 0x1f) ^ pfn_color) & pfn_ceq_mask;
		npfn = (szc == TTE64K) ? (npfn & ~(pfn_t)0x7) : npfn;

		if (((page_papfn_2_color_cpu(npfn, szc) ^ color) &
		    ceq_mask) == 0) {
			/* the color is fixed - find the next page */
			pfn_ceq_mask |= it->mi_mnode_pfn_mask;
			while (npfn <= pfn) {
				npfn = ADD_MASKED(npfn, pstep, pfn_ceq_mask,
				    mask);
			}
			if ((((npfn ^ pfn) >> 15) & 0x1f) == 0)
				goto done;
		}
	}

	/* to fix the color need to touch PA[32:28] */
	npfn = (szc == TTE8K) ? ((pfn >> 15) << 15) :
	    (((pfn >> 18) << 18) | ((color & 0x1c) << 13));

	/* fix mnode if input pfn is in the wrong mnode. */
	if ((pfnmn = PAPFN_2_MNODE(npfn)) != it->mi_mnode) {
		npfn += ((it->mi_mnode - pfnmn) & it->mi_mnode_mask) <<
		    it->mi_mnode_pfn_shift;
	}

	tmpmask = (szc == TTE8K) ? 0 : (ceq_mask & 0x1c) << 13;
	tmpmask |= it->mi_mnode_pfn_mask;

	while (npfn <= pfn) {
		npfn = ADD_MASKED(npfn, (1 << 15), tmpmask, mask);
	}

	/* set bits PA[19:13] to match the color */
	npfn |= (((npfn >> 15) & 0x1f) ^ pfn_color) & pfn_ceq_mask;
	npfn = (szc == TTE64K) ? (npfn & ~(pfn_t)0x7) : npfn;

done:
	ASSERT(((page_papfn_2_color_cpu(npfn, szc) ^ color) & ceq_mask) == 0);
	ASSERT(PAPFN_2_MNODE(npfn) == it->mi_mnode);

	/* PA to RA */
	npfn -= it->mi_ra_to_pa;

	/* check for possible memblock switch */
	if (npfn > it->mi_mblock_end) {
		pfn = plat_mem_node_iterator_init(npfn, it->mi_mnode, it, 0);
		if (pfn == (pfn_t)-1)
			return (pfn);
		ASSERT(pfn >= it->mi_mblock_base && pfn <= it->mi_mblock_end);
		pfn += it->mi_ra_to_pa;
		goto next_mem_block;
	}

	return (npfn);
}

/*
 * init page coloring
 * VF encodes node_id for an L-group in either bit 30 or 31:30,
 * which effectively reduces the number of colors available per mnode.
 */
void
page_coloring_init_cpu()
{
	int i;
	uchar_t id;
	uchar_t lo;
	uchar_t hi;
	n2color_t m;
	mem_node_iterator_t it;
	static uchar_t idmask[] = {0, 0x7, 0x1f, 0x1f, 0x1f, 0x1f};

	for (i = 0; i < max_mem_nodes; i++) {
		memset(&it, 0, sizeof (it));
		if (plat_mem_node_iterator_init(0, i, &it, 1) != (pfn_t)-1)
			break;
	}
	ASSERT(i < max_mem_nodes);
	for (i = 0; i < mmu_page_sizes; i++) {
		(void) memset(&m, 0, sizeof (m));
		id = it.mi_mnode_pfn_mask >> 15;	/* node id mask */
		id &= idmask[i];
		lo = lowbit(id);
		if (lo > 0) {
			hi = highbit(id);
			m.nnbits = hi - lo + 1;
			m.nnmask = (1 << m.nnbits) - 1;
			lo += nhbits[i] - 5;
			m.lomask = (1 << (lo - 1)) - 1;
			m.lobits = lo - 1;
		}
		hw_page_array[i].hp_colors = 1 << (nhbits[i] - m.nnbits);
		n2color[i] = m;
	}
}

/*
 * group colorequiv colors on N2 by low order bits of the color first
 */
void
page_set_colorequiv_arr_cpu(void)
{
	static uint_t nequiv_shades_log2[MMU_PAGE_SIZES] = {2, 5, 0, 0, 0, 0};

	nequiv_shades_log2[1] -= n2color[1].nnbits;
	if (colorequiv > 1) {
		int i;
		uint_t sv_a = lowbit(colorequiv) - 1;

		if (sv_a > 15)
			sv_a = 15;

		for (i = 0; i < MMU_PAGE_SIZES; i++) {
			uint_t colors;
			uint_t a = sv_a;

			if ((colors = hw_page_array[i].hp_colors) <= 1)
				continue;
			while ((colors >> a) == 0)
				a--;
			if (a > (colorequivszc[i] & 0xf) +
			    (colorequivszc[i] >> 4)) {
				if (a <= nequiv_shades_log2[i]) {
					colorequivszc[i] = (uchar_t)a;
				} else {
					colorequivszc[i] =
					    ((a - nequiv_shades_log2[i]) << 4) |
					    nequiv_shades_log2[i];
				}
			}
		}
	}
}

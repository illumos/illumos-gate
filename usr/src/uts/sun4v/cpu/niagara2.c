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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
	extern size_t contig_mem_prealloc_base;
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

	contig_mem_prealloc_base = NIAGARA2_PREALLOC_BASE;
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
	cp->cpu_m.cpu_chip = cpunodes[cp->cpu_id].l2_cache_mapping;
	if (cp->cpu_m.cpu_chip == NO_CHIP_MAPPING_FOUND)
		cp->cpu_m.cpu_chip = 0;
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

/* NI2 L2$ index is pa[32:28]^pa[17:13].pa[19:18]^pa[12:11].pa[10:6] */
uint_t
page_pfn_2_color_cpu(pfn_t pfn, uchar_t szc)
{
	uint_t color;

	ASSERT(szc <= TTE256M);

	pfn = PFN_BASE(pfn, szc);
	color = ((pfn >> 15) ^ pfn) & 0x1f;
	if (szc >= TTE4M)
		return (color);

	color = (color << 2) | ((pfn >> 5) & 0x3);

	return (szc <= TTE64K ? color : (color >> 1));
}

#if TTE256M != 5
#error TTE256M is not 5
#endif

uint_t
page_get_nsz_color_mask_cpu(uchar_t szc, uint_t mask)
{
	static uint_t ni2_color_masks[5] = {0x63, 0x1e, 0x3e, 0x1f, 0x1f};
	ASSERT(szc < TTE256M);

	mask &= ni2_color_masks[szc];
	return ((szc == TTE64K || szc == TTE512K) ? (mask >> 1) : mask);
}

uint_t
page_get_nsz_color_cpu(uchar_t szc, uint_t color)
{
	ASSERT(szc < TTE256M);
	return ((szc == TTE64K || szc == TTE512K) ? (color >> 1) : color);
}

uint_t
page_get_color_shift_cpu(uchar_t szc, uchar_t nszc)
{
	ASSERT(nszc >= szc);
	ASSERT(nszc <= TTE256M);

	if (szc == nszc)
		return (0);
	if (szc <= TTE64K)
		return ((nszc >= TTE4M) ? 2 : ((nszc >= TTE512K) ? 1 : 0));
	if (szc == TTE512K)
		return (1);

	return (0);
}

/*ARGSUSED*/
pfn_t
page_next_pfn_for_color_cpu(pfn_t pfn, uchar_t szc, uint_t color,
    uint_t ceq_mask, uint_t color_mask)
{
	pfn_t pstep = PNUM_SIZE(szc);
	pfn_t npfn, pfn_ceq_mask, pfn_color;
	pfn_t tmpmask, mask = (pfn_t)-1;

	ASSERT((color & ~ceq_mask) == 0);

	if (((page_pfn_2_color_cpu(pfn, szc) ^ color) & ceq_mask) == 0) {

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
			pfn = ADD_MASKED(pfn, pstep, pfn_ceq_mask, mask);
			return (pfn);
		} else {
			/*
			 * We deal 64K or 8K page. Check if we could the
			 * satisfy the request without changing PA[32:28]
			 */
			pfn_ceq_mask = ((ceq_mask & 3) << 5) | (ceq_mask >> 2);
			npfn = ADD_MASKED(pfn, pstep, pfn_ceq_mask, mask);

			if ((((npfn ^ pfn) >> 15) & 0x1f) == 0)
				return (npfn);

			/*
			 * for next pfn we have to change bits PA[32:28]
			 * set PA[63:28] and PA[19:18] of the next pfn
			 */
			npfn = (pfn >> 15) << 15;
			npfn |= (ceq_mask & color & 3) << 5;
			pfn_ceq_mask = (szc == TTE8K) ? 0 :
			    (ceq_mask & 0x1c) << 13;
			npfn = ADD_MASKED(npfn, (1 << 15), pfn_ceq_mask, mask);

			/*
			 * set bits PA[17:13] to match the color
			 */
			ceq_mask >>= 2;
			color = (color >> 2) & ceq_mask;
			npfn |= ((npfn >> 15) ^ color) & ceq_mask;
			return (npfn);
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
			if (((page_pfn_2_color_cpu(npfn, szc) ^ color) &
			    ceq_mask) == 0)
				return (npfn);

			/* page color is PA[32:28].PA[19:19] */
			pfn_ceq_mask = ((ceq_mask & 1) << 6) |
			    ((ceq_mask >> 1) << 15) | (0xff << 7);
			pfn_color = ((color & 1) << 6) | ((color >> 1) << 15);
			npfn = ((pfn >> 20) << 20) | pfn_color;
		}

		while (npfn <= pfn) {
			npfn = ADD_MASKED(npfn, pstep, pfn_ceq_mask, mask);
		}
		return (npfn);
	}

	/*
	 * We deal 64K or 8K page of incorrect color.
	 * Try correcting color without changing PA[32:28]
	 */

	pfn_ceq_mask = ((ceq_mask & 3) << 5) | (ceq_mask >> 2);
	pfn_color = ((color & 3) << 5) | (color >> 2);
	npfn = (pfn & ~(pfn_t)0x7f);
	npfn |= (((pfn >> 15) & 0x1f) ^ pfn_color) & pfn_ceq_mask;
	npfn = (szc == TTE64K) ? (npfn & ~(pfn_t)0x7) : npfn;

	if (((page_pfn_2_color_cpu(npfn, szc) ^ color) & ceq_mask) == 0) {

		/* the color is fixed - find the next page */
		while (npfn <= pfn) {
			npfn = ADD_MASKED(npfn, pstep, pfn_ceq_mask, mask);
		}
		if ((((npfn ^ pfn) >> 15) & 0x1f) == 0)
			return (npfn);
	}

	/* to fix the color need to touch PA[32:28] */
	npfn = (szc == TTE8K) ? ((pfn >> 15) << 15) :
	    (((pfn >> 18) << 18) | ((color & 0x1c) << 13));
	tmpmask = (szc == TTE8K) ? 0 : (ceq_mask & 0x1c) << 13;

	while (npfn <= pfn) {
		npfn = ADD_MASKED(npfn, (1 << 15), tmpmask, mask);
	}

	/* set bits PA[19:13] to match the color */
	npfn |= (((npfn >> 15) & 0x1f) ^ pfn_color) & pfn_ceq_mask;
	npfn = (szc == TTE64K) ? (npfn & ~(pfn_t)0x7) : npfn;

	ASSERT(((page_pfn_2_color_cpu(npfn, szc) ^ color) & ceq_mask) == 0);

	return (npfn);
}

/*
 * init page coloring
 */
void
page_coloring_init_cpu()
{
	int i;

	hw_page_array[0].hp_colors = 1 << 7;
	hw_page_array[1].hp_colors = 1 << 7;
	hw_page_array[2].hp_colors = 1 << 6;

	for (i = 3; i < mmu_page_sizes; i++) {
		hw_page_array[i].hp_colors = 1 << 5;
	}
}

/*
 * group colorequiv colors on N2 by low order bits of the color first
 */
void
page_set_colorequiv_arr_cpu(void)
{
	static uint_t nequiv_shades_log2[MMU_PAGE_SIZES] = {2, 5, 0, 0, 0, 0};

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

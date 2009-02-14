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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/cpu.h>
#include <sys/elf_SPARC.h>
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
#include <vm/seg_spt.h>
#include <sys/hypervisor_api.h>
#include <sys/rock_hypervisor_api.h>
#include <sys/hsvc.h>
#include <vm/hat_sfmmu.h>

uint_t root_phys_addr_lo_mask = 0xffffffffU;
uint8_t	enable_tm = 1;

char cpu_module_name[] = "SUNW,UltraSPARC-AT10";
static	boolean_t	hsvc_tm_available = B_TRUE;

static	hsvc_info_t rock_tm_hsvc = {
	HSVC_REV_1,		/* HSVC rev num */
	NULL,			/* Private */
	HSVC_GROUP_TM,		/* Requested API Group */
	ROCK_HSVC_MAJOR,	/* Requested Major */
	ROCK_HSVC_MINOR,	/* Requested Minor */
	cpu_module_name		/* Module name */
};

boolean_t	hsvc_mmu_ext_available = B_TRUE;

static	hsvc_info_t rock_mmu_ext_hsvc = {
	HSVC_REV_1,		/* HSVC rev num */
	NULL,			/* Private */
	HSVC_GROUP_RKMMU_EXT,	/* Requested API Group */
	ROCK_HSVC_MAJOR,	/* Requested Major */
	ROCK_HSVC_MINOR,	/* Requested Minor */
	cpu_module_name		/* Module name */
};

static void encode_pgsz_order(uint64_t, int, int, uint16_t *, uchar_t *);
static void set_pgsz_order(uchar_t, uchar_t, uint64_t *, int *, int *,
    sfmmu_t *);

/*
 * External /etc/system tunable, for controlling whether shared or private pages
 * come first in the pagesize order register.
 */
int pgsz_order_shared_first = 1;

#define	MCOREID_MASK	0x1E
#define	MCOREID_SHIFT	1

static uint_t mmu_disable_large_pages = ((1 << TTE512K) | (1 << TTE32M) |
		(1 << TTE2G) | (1 << TTE16G));
static uint_t mmu_disable_ism_large_pages = ((1 << TTE512K) | (1 << TTE32M) |
	(1 << TTE2G) | (1 << TTE16G));
static uint_t mmu_disable_auto_data_large_pages = ((1 << TTE512K) |
	(1 << TTE32M) | (1 << TTE2G) | (1 << TTE16G));
static uint_t mmu_disable_auto_text_large_pages = ((1 << TTE512K) |
	(1 << TTE32M) | (1 << TTE2G) | (1 << TTE16G));

void
cpu_setup(void)
{
	extern int	cpc_has_overflow_intr;
	uint64_t	sup_minor;
	int		status;

	/*
	 * The setup common to all CPU modules is done in cpu_setup_common
	 * routine.
	 */
	cpu_setup_common(NULL);

	/*
	 * Rock's max nctxs is 64K. Set it accordingly.
	 */
	nctxs = MAX_NCTXS;

	/*
	 * Rock I$ is non-coherent.
	 */
	mach_setup_icache(0);

#ifdef DEBUG
	/*
	 * These should always be present on Rock
	 */
	if (cpu_hwcap_flags == 0)
		cmn_err(CE_WARN, "hwcap-list missing from MD");
#endif

	cache |= (CACHE_PTAG | CACHE_IOCOHERENT);

	if (use_page_coloring) {
		do_pg_coloring = 1;
	}

	/*
	 * Rock generates hpriv performance event trap instead of pic overflow
	 * trap. To get the attention of the guest hv in-turn generates pic
	 * overflow trap. Therefore enable support for that.
	 */
	cpc_has_overflow_intr = 1;

	/*
	 * Enable 4M pages for OOB.
	 */
	max_uheap_lpsize = MMU_PAGESIZE4M;
	max_ustack_lpsize = MMU_PAGESIZE4M;
	max_privmap_lpsize = MMU_PAGESIZE4M;

	/*
	 * hv_tm_enable is a part of TM group. We need to
	 * negotiate that API group before we can use it.
	 */
	status = hsvc_register(&rock_tm_hsvc, &sup_minor);
	if ((status != 0) || (sup_minor < (uint64_t)ROCK_HSVC_MINOR)) {
		cmn_err(CE_WARN, "%s cannot negotiate hypervisor services: "
		    "major: 0x%lx minor: 0x%lx group: 0x%x errno: %d",
		    cpu_module_name, rock_tm_hsvc.hsvc_major,
		    rock_tm_hsvc.hsvc_minor, HSVC_GROUP_TM, status);
		hsvc_tm_available = B_FALSE;
	}

	/*
	 * Negotiate API group for rock mmu extensions.
	 */
	status = hsvc_register(&rock_mmu_ext_hsvc, &sup_minor);
	if ((status != 0) || (sup_minor <
	    (uint64_t)ROCK_HSVC_MINOR)) {
		cmn_err(CE_WARN, "%s cannot negotiate hypervisor services: "
		    "major: 0x%lx minor: 0x%lx group: 0x%x errno: %d",
		    cpu_module_name, rock_mmu_ext_hsvc.hsvc_major,
		    rock_mmu_ext_hsvc.hsvc_minor, HSVC_GROUP_RKMMU_EXT,
		    status);
		hsvc_mmu_ext_available = B_FALSE;
	}
}

/*
 * Set the magic constants of the implementation.
 */
void
cpu_fiximp(struct cpu_node *cpunode)
{
	/*
	 * The Cache node is optional in MD. Therefore in case it
	 * does not exist, use hardcoded values.
	 */
#ifdef DEBUG
	/*
	 * ...that said, we do want this info to come from the MD.
	 */
	if (cpunode->ecache_size == 0 || cpunode->ecache_linesize == 0 ||
	    cpunode->ecache_associativity == 0) {
		cmn_err(CE_WARN, "ecache info missing from MD");
	}
#endif
	if (cpunode->ecache_size == 0)
		cpunode->ecache_size = 2 * 1024 * 1024;
	if (cpunode->ecache_linesize == 0)
		cpunode->ecache_linesize = 64;
	if (cpunode->ecache_associativity == 0)
		cpunode->ecache_associativity = 8;
}

void
dtrace_flush_sec(uintptr_t addr)
{
	pfn_t pfn;
	proc_t *procp = ttoproc(curthread);
	page_t *pp;
	caddr_t va;

	pfn = hat_getpfnum(procp->p_as->a_hat, (void *)addr);
	if (pfn != -1) {
		ASSERT(pf_is_memory(pfn));
		pp = page_numtopp_noreclaim(pfn, SE_SHARED);
		if (pp != NULL) {
			va = ppmapin(pp, PROT_READ | PROT_WRITE, (void *)addr);
			/* sparc needs 8-byte align */
			doflush((caddr_t)((uintptr_t)va & -8l));
			ppmapout(va);
			page_unlock(pp);
		}
	}
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

	cp->cpu_m.cpu_core = (cp->cpu_id & MCOREID_MASK) >> MCOREID_SHIFT;

	/*
	 * The cpu_chip field is initialized based on the information
	 * in the MD and assume that all cpus within a chip
	 * share the same L2 cache. If no such info is available, we
	 * set the cpu to CPU_CHIPID_INVALID.
	 */
	cp->cpu_m.cpu_mpipe = cpunodes[cp->cpu_id].l2_cache_mapping;
	if (cp->cpu_m.cpu_mpipe == NO_L2_CACHE_MAPPING_FOUND)
		cp->cpu_m.cpu_mpipe = CPU_L2_CACHEID_INVALID;

	cp->cpu_m.cpu_chip = cpunodes[cp->cpu_id].l2_cache_mapping;
	if (cp->cpu_m.cpu_chip == NO_L2_CACHE_MAPPING_FOUND)
		cp->cpu_m.cpu_chip = CPU_CHIPID_INVALID;
}

void
cpu_init_private(struct cpu *cp)
{
	cpu_map_exec_units(cp);
}

/*ARGSUSED*/
void
cpu_uninit_private(struct cpu *cp)
{
}

/*
 * cpu_feature_init
 *
 * This function is called once per strand.
 */
void
cpu_feature_init(void)
{
	/*
	 * Enable or disable for each cpu if hypervisor API is negotiated.
	 */
	if (hsvc_tm_available == B_TRUE)
		(void) hv_tm_enable((uint64_t)enable_tm);
}

/*
 * Flush specified address range from I$ via hv_mem_iflush interface
 * Note that the hypervisor interface expects physical address range
 * and can flush less than the requested size.
 */

void
rock_sync_icache(caddr_t addr, size_t size)
{
	uint64_t pa, i, flushlen, flushed;

	if (!force_sync_icache_after_bcopy)
		/*
		 * Do not clear the I-cache after bcopy.
		 * The default value is 0. This flag made be
		 * set via /etc/system.
		 */
		return;

	if (!tba_taken_over)
		/*
		 * Very early in boot, va_to_pa() will try to call back
		 * into OBP.  Very *very* early in boot, this will fail
		 * because we haven't set up the OBP callback handler.
		 * (Without this check, kmdb boot will fail.)
		 */
		return;

	for (i = 0; i < size; i += flushed) {
		pa = va_to_pa(addr + i);
		ASSERT(pa != -1);

		/*
		 * Only flush the required length up to a PAGESIZE.
		 */

		flushlen = MIN((size - i), (PAGESIZE - (pa & MMU_PAGEOFFSET)));

		/*
		 * Flush I$ up to the page bounday. This call should never
		 * fail. If it does, we panic the system as I$ may contain
		 * stale instructions, which can result in silent data
		 * corruption.
		 */

		if (hv_mem_iflush(pa, flushlen, &flushed) != H_EOK) {
			cmn_err(CE_PANIC, "Flushing the Icache failed");
		}

	}
}

/*
 * There are no Hypervisor trapstat(1m) interfaces for Rock
 * If trapstat(1m) wants to do its thing, it will have to
 * take over all TLB miss handling.
 */
int
cpu_trapstat_conf(int cmd)
{
	int status;

	switch (cmd) {
	case CPU_TSTATCONF_INIT:
	case CPU_TSTATCONF_FINI:
	case CPU_TSTATCONF_ENABLE:
	case CPU_TSTATCONF_DISABLE:
		status = ENOTSUP;
		break;
	default:
		status = EINVAL;
		break;
	}
	return (status);
}

/*ARGSUSED*/
void
cpu_trapstat_data(void *buf, uint_t tstat_pgszs)
{
}

#define	MAX_PAGE_COLORS		(1 << MAX_PAGE_COLORS_SHIFT)
#define	MAX_PAGE_COLORS_SHIFT	(5)

/*ARGSUSED*/
uint_t
page_pfn_2_color_cpu(pfn_t pfn, uchar_t szc, void *cookie)
{
	uint_t	color;

	pfn = PFN_BASE(pfn, szc);
	color = pfn ^ (pfn >> 20);
	color = color ^ (color >> 10);
	return ((color ^ (color >> 5)) & 0x1f);
}

/*
 * this macro rotates value "x" n steps to the right
 * mask consists of "n + m" bits
 * ASSERT(x < (1 << (n + m));
 */
#define	ROTATE_BITS(x, n, m) (((x) >> (n)) | (((x) & ((1 << (n)) - 1)) << m))


uchar_t clr2sqnclr_table[MMU_PAGE_SIZES][MAX_PAGE_COLORS];

/*
 * on Rock, the hash cache index is calculated as follows:
 * pa[47:43]^pa[42:38]^pa[37:33]^pa[32:28]^
 * 	pa[27:23]^pa[22:18]^pa[17:13].pa[12:6]
 * That is, every 5 bits is folded and XORd together. Page sizes
 * differ by 3 bits, which is a factor of 8. This function computes
 * the next sequential color by rotating by 3 steps within a field of 5 bits
 * for every page size.
 */
void
clr2sqnclr_table_init()
{
	uchar_t szc;
	uint_t  color;
	uint_t  rot = 0;

	for (szc = 0; szc < MMU_PAGE_SIZES; szc++) {
		rot = (szc * 3) % MAX_PAGE_COLORS_SHIFT;
		for (color = 0; color < MAX_PAGE_COLORS; color++) {
			clr2sqnclr_table[szc][color] =
			    ROTATE_BITS(color, rot,
			    (MAX_PAGE_COLORS_SHIFT - rot));
		}
	}
}

uint_t
clr2sqnclr(uchar_t szc, uint_t color)
{
	ASSERT(szc < MMU_PAGE_SIZES);
	ASSERT(color < MAX_PAGE_COLORS);

	return (clr2sqnclr_table[szc][color]);
}

#if MMU_PAGE_SIZES > 8
#error MMU_PAGE_SIZES can be at most 8
#endif

uint_t
page_get_nsz_color_mask_cpu(uchar_t szc, uint_t mask)
{
	static uint_t rock_color_masks[7] = {0x18, 6, 0x11, 0xc, 3, 0x18, 6};

	ASSERT(szc < MMU_PAGE_SIZES - 1);
	return (mask & rock_color_masks[szc]);
}

/*ARGSUSED*/
uint_t
page_get_nsz_color_cpu(uchar_t szc, uint_t color)
{
	return (color);
}

uint_t
page_get_color_shift_cpu(uchar_t szc, uchar_t nszc)
{
	ASSERT(nszc >= szc);
	return (0);
}

/*ARGSUSED*/
pfn_t
page_next_pfn_for_color_cpu(pfn_t pfn, uchar_t szc, uint_t color,
    uint_t ceq_mask, uint_t color_mask, void *cookie)
{
	uint_t	sqn_ceq_mask = clr2sqnclr(szc, ceq_mask);
	uint_t	sqn_color = clr2sqnclr(szc, color);
	uint_t	pfn_shift = PNUM_SHIFT(szc);
	pfn_t	cpfn, npfn, base_pfn = pfn & (~(pfn_t)color_mask << pfn_shift);
	uint_t  base_sqn_color, nsqn_color, wrap = 0;

	ASSERT((color & ~ceq_mask) == 0);

	base_sqn_color = clr2sqnclr(szc,
	    page_pfn_2_color_cpu(base_pfn, szc, NULL)) ^ sqn_color;
	nsqn_color = base_sqn_color;

	cpfn = (pfn_t)-1L;
	do {
		npfn = base_pfn | (nsqn_color << pfn_shift);

		ASSERT(((page_pfn_2_color_cpu(npfn, szc, NULL) ^ color) &
		    ceq_mask) == 0);

		if (npfn > pfn && npfn < cpfn)
			cpfn = npfn;

		nsqn_color = INC_MASKED(nsqn_color, sqn_ceq_mask, color_mask);
		if (nsqn_color != base_sqn_color)
			continue;

		if (cpfn != (pfn_t)-1L)
			break;

		base_pfn += ((pfn_t)color_mask + 1) << pfn_shift;

		base_sqn_color = clr2sqnclr(szc,
		    page_pfn_2_color_cpu(base_pfn, szc, NULL)) ^ sqn_color;
		nsqn_color = base_sqn_color;
		wrap++;

	} while (nsqn_color != base_sqn_color || wrap < 2);

	ASSERT(cpfn != (pfn_t)-1L);

	return (cpfn);
}

void
page_coloring_init_cpu()
{
	int i;
	uint_t colors = 1 << MAX_PAGE_COLORS_SHIFT;

	for (i = 0; i < mmu_page_sizes; i++) {
		hw_page_array[i].hp_colors = colors;
	}

	/*
	 * initialise conversion table between page colors and
	 * sequential colors
	 */
	clr2sqnclr_table_init();

}

/*
 * group colorequiv colors on Rock by low order bits of the color first
 */
void
page_set_colorequiv_arr_cpu(void)
{
	static uint_t nequiv_shades_log2[MMU_PAGE_SIZES] = {0, 3, 0, 0, 0, 0};

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

/*
 * Calculate the page sizes needed to program Rock TLB page size register.
 * The invctx parameter is a flag which indicates that it will be necessary to
 * synchronize by invalidating contexts if the sfmmu pagesize register is
 * updated.
 */
void
mmu_set_pgsz_order(sfmmu_t *sfmmup, int invctx)
{
	uchar_t private_pgsz_mask;
	uchar_t shared_pgsz_mask;
	uint16_t pgsz_order_hv[MAX_PGSZ_SEARCH_ORDER];
	uint64_t pgsz_order = 0;
	uchar_t pgsz_map = 0;
	int private_pgsz_num = 0;
	int shared_pgsz_num = 0;
	int tot_pgsz_num;
	sf_scd_t *scdp;
	int ret;
	int i;

	/*
	 * The hatlock must be held in all cases except when the sfmmu is
	 * being initialized by hat_alloc() or we are calling hat_dup(), in
	 * these cases no other thread will be using the sfmmu yet.
	 */

	ASSERT(!invctx || sfmmu_hat_lock_held(sfmmup));

	if (pgsz_search_on == 0)
		return;

	/* Always enable 8K private mappings */
	private_pgsz_mask = 1 << TTE8K;

	/* Enable 64K private mappings unless specifically disabled */
	if (!(disable_large_pages & (1 << TTE64K))) {
		private_pgsz_mask |= 1 << TTE64K;
	}

	/*
	 * First check for ISM segments not in an SCD. The algorithm for
	 * creating an SCD is to create one when an (D)ISM segment is attached
	 * unless the process's shared segments are a subset of an SCD which
	 * already exists.
	 *
	 * This situation also arises when we attach to more than the maximum
	 * number of (D)ISM segments defined in the region bit map
	 * (currently 64).
	 *
	 * We have set mmu_disable_ism_large_pages to force ISM segments to use
	 * only 4M and 256M pages.
	 */
	if (SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMNOTINSCD)) {
		private_pgsz_mask |= 1 << TTE4M;
		if (SFMMU_FLAGS_ISSET(sfmmup, HAT_256M_ISM)) {
			private_pgsz_mask |= 1 << TTE256M;
		}
	}

	/* Now check for regions not included in the SCD. */
	if ((scdp = sfmmup->sfmmu_scdp) != NULL) {
		SF_RGNMAP_EQUAL(&scdp->scd_hmeregion_map,
		    &sfmmup->sfmmu_hmeregion_map,
		    SFMMU_HMERGNMAP_WORDS, ret);
		if (!ret) {
			private_pgsz_mask |= sfmmup->sfmmu_rtteflags;
		}
	} else {
		private_pgsz_mask |= sfmmup->sfmmu_rtteflags;
	}

	private_pgsz_mask |= sfmmup->sfmmu_tteflags;

	/*
	 * If the process is part of an SCD then enable 4M and 256M shared
	 * page sizes - unless these are specifically disabled. If the 4M
	 * shared page size is specifically disabled and the process has (D)ISM
	 * segments attached or 4M regions then enable the private 4M page size.
	 * If the 256M shared page size is disabled and the process has a 256M
	 * page size region then enable the 256M private page size. The trap
	 * handler looks at the shared page sizes enabled and if a shared
	 * mapping does not correspond to one these sizes then it is treated
	 * as a private mapping.
	 *
	 * The SCD includes the process's main text segment and (D)ISM segments
	 * but we only enable the 4M shared page size so an 8K main text
	 * segment will be treated as private due to the trap handler support.
	 *
	 * Note that for simplicity the ordering of the shared page sizes is
	 * hard coded.
	 */
	shared_pgsz_mask = 0;
	if (sfmmup->sfmmu_scdp != NULL) {
		if (!(disable_shctx_large_pages  & (1 << TTE4M))) {
			shared_pgsz_mask |= 1 << TTE4M;
		} else if (sfmmup->sfmmu_iblk != NULL ||
		    (sfmmup->sfmmu_rtteflags &
		    (1 << TTE4M))) {
			private_pgsz_mask |= 1 << TTE4M;
		}

		if (SFMMU_FLAGS_ISSET(sfmmup, HAT_256M_ISM) ||
		    (sfmmup->sfmmu_rtteflags & (1 << TTE256M))) {
			if (!(disable_shctx_large_pages  & (1 << TTE256M))) {
				shared_pgsz_mask |= 1 << TTE256M;
			} else {
				private_pgsz_mask |= 1 << TTE256M;
			}
		}
	}

	set_pgsz_order(private_pgsz_mask, shared_pgsz_mask, &pgsz_order,
	    &private_pgsz_num, &shared_pgsz_num, sfmmup);

	encode_pgsz_order(pgsz_order, private_pgsz_num, shared_pgsz_num,
	    pgsz_order_hv, &pgsz_map);

	tot_pgsz_num = private_pgsz_num + shared_pgsz_num;
	ASSERT(tot_pgsz_num <= MAX_PGSZ_SEARCH_ORDER);

	for (i = 0; i < tot_pgsz_num; i++) {
		if (pgsz_order_hv[i] != sfmmup->sfmmu_pgsz_order_hv[i])
			break;
	}

	/*
	 * If either we've reached the maximum number of page sizes or the
	 * next element is 0, indicating the end of the list, then both the
	 * entries and their number in both arrays is the same and we return.
	 */
	if ((i == tot_pgsz_num) && (i == MAX_PGSZ_SEARCH_ORDER ||
	    sfmmup->sfmmu_pgsz_order_hv[i] == 0)) {
		ASSERT(pgsz_map == sfmmup->sfmmu_pgsz_map);
		return;
	}

	/* Otherwise update the sw page size register setting */
	if (invctx) {
		sfmmu_invalidate_ctx(sfmmup);
	}

	for (i = 0; i < tot_pgsz_num; i++) {
		sfmmup->sfmmu_pgsz_order_hv[i] = pgsz_order_hv[i];
	}

	/* Disable next entry in search list to mark the end */
	if (i < MAX_PGSZ_SEARCH_ORDER) {
		sfmmup->sfmmu_pgsz_order_hv[i] = 0;
	}
	sfmmup->sfmmu_pgsz_map = pgsz_map;
}

/*
 * Encode the Rock TLB page size register.
 *
 * Input:
 *        pgsz_order, ordered list of page sizes, private and shared, the order
 *        between these depends on the pgsz_order_shared_first config variable.
 *        private_pgsz_num, number of private page sizes.
 *        shared_pgsz_num, number of shared page sizes.
 * Output:
 *        pgsz_order_hv contains the encoded pagesize search order for the hv
 *	  pgsz_map field contains the page size bit map used by the trap
 *        handler to prevent unauthorized shared page sizes being used.
 */

static void
encode_pgsz_order(uint64_t pgsz_order, int private_pgsz_num,
    int shared_pgsz_num, uint16_t *pgsz_order_hv, uchar_t *pgsz_map)
{
	int i;
	int tot_pgsz_num;
	uint16_t pgsz_entry;
	uint16_t first_entry_mask, second_entry_mask;
	int	first_pgsz_num;

	ASSERT(private_pgsz_num < MMU_PAGE_SIZES);
	ASSERT(shared_pgsz_num < MMU_PAGE_SIZES);
	ASSERT(private_pgsz_num > 0);

	if (pgsz_order_shared_first) {
		first_entry_mask = TLB_PGSZ_CONTEXT1_ENABLE;
		second_entry_mask = TLB_PGSZ_ENABLE;
		first_pgsz_num = shared_pgsz_num;
	} else {
		first_entry_mask = TLB_PGSZ_ENABLE;
		second_entry_mask = TLB_PGSZ_CONTEXT1_ENABLE;
		first_pgsz_num = private_pgsz_num;
	}

	tot_pgsz_num = private_pgsz_num + shared_pgsz_num;
	for (i = 0; i < tot_pgsz_num; i++) {
		pgsz_entry = pgsz_order & TTE_SZ_BITS;
		if (i < first_pgsz_num) {
			if (pgsz_order_shared_first) {
				*pgsz_map |= (1 << pgsz_entry);
			}
			pgsz_entry |= first_entry_mask;
		} else {
			if (!pgsz_order_shared_first) {
				*pgsz_map |= (1 << pgsz_entry);
			}
			pgsz_entry |= second_entry_mask;
		}
		pgsz_order >>= 4;
		pgsz_order_hv[i] = pgsz_entry;
	}
}

/*
 * The function returns the mmu-specific values for the
 * hat's disable_large_pages, disable_ism_large_pages, and
 * disable_auto_data_large_pages and
 * disable_text_data_large_pages variables.
 */
uint_t
mmu_large_pages_disabled(uint_t flag)
{
	uint_t pages_disable = 0;

	if (flag == HAT_LOAD) {
		pages_disable =  mmu_disable_large_pages;
	} else if (flag == HAT_LOAD_SHARE) {
		pages_disable = mmu_disable_ism_large_pages;
	} else if (flag == HAT_AUTO_DATA) {
		pages_disable = mmu_disable_auto_data_large_pages;
	} else if (flag == HAT_AUTO_TEXT) {
		pages_disable = mmu_disable_auto_text_large_pages;
	}
	return (pages_disable);
}

/*
 * Uses private and shared page size bitmaps to produce an ordered list
 * of page sizes and counts to be passed to encode_pgsz_order().
 *
 * Input:
 *        private_pgsz_mask, bit map of private page sizes.
 *        shared_pgsz_mask,  bit map of private page sizes.
 *	  sfmmup, pointer to hat structure.
 *
 * Output:
 *        pgsz_order, ordered list of page sizes.
 *        private_pgsz_num, number of private page sizes in pgsz_order.
 *        shared_pgsz_num, number of shared page sizes in pgsz_order.
 */
static void
set_pgsz_order(uchar_t private_pgsz_mask, uchar_t shared_pgsz_mask,
    uint64_t *pgsz_order, int *private_pgsz_num, int *shared_pgsz_num,
    sfmmu_t *sfmmup)
{
	int64_t sortcnt[MMU_PAGE_SIZES];
	int8_t tmp_pgsz[MMU_PAGE_SIZES];
	ulong_t tmp;
	uint8_t i, j, max;

	*private_pgsz_num = 0;
	*shared_pgsz_num = 0;
	*pgsz_order = 0;

	/* Sort pages by area mapped */
	for (i = 0; i < mmu_page_sizes; i++) {
		tmp = sfmmup->sfmmu_ttecnt[i] + sfmmup->sfmmu_ismttecnt[i];
		sortcnt[i] = tmp << TTE_PAGE_SHIFT(i);
	}

	for (j = 0; j < mmu_page_sizes; j++) {
		for (i = mmu_page_sizes - 1, max = 0; i > 0; i--) {
			if (sortcnt[i] > sortcnt[max])
				max = i;
		}
		tmp_pgsz[j] = max;
		sortcnt[max] = -1;
	}

	/* Add shared page sizes to page order if these come first */
	if (pgsz_order_shared_first) {
		if (shared_pgsz_mask & (1 << TTE256M)) {
			*pgsz_order =  TTE256M;
			(*shared_pgsz_num)++;
		}
		if (shared_pgsz_mask & (1 << TTE4M)) {
			*pgsz_order |= (TTE4M << (*shared_pgsz_num * 4));
			(*shared_pgsz_num)++;
		}
	}


	/* Add private page sizes to page order */
	for (i = 0; i < mmu_page_sizes; i++) {
		if (private_pgsz_mask & (1 << tmp_pgsz[i])) {
			*pgsz_order |= (tmp_pgsz[i] <<
			    ((*private_pgsz_num + *shared_pgsz_num) * 4));
			(*private_pgsz_num)++;
		}
	}

	/* Add shared page sizes to page order if these come last */
	if (!pgsz_order_shared_first) {
		if (shared_pgsz_mask & (1 << TTE256M)) {
			*pgsz_order |=  (TTE256M <<
			    ((*private_pgsz_num + *shared_pgsz_num) * 4));
			(*shared_pgsz_num)++;
		}
		if (shared_pgsz_mask & (1 << TTE4M)) {
			*pgsz_order |= (TTE4M <<
			    ((*private_pgsz_num + *shared_pgsz_num) * 4));
			(*shared_pgsz_num)++;
		}
	}

	ASSERT(*pgsz_order);
	ASSERT(*private_pgsz_num);
	ASSERT((*private_pgsz_num + *shared_pgsz_num)
	    <= MAX_PGSZ_SEARCH_ORDER);
}

/*
 * This routine is called without holding the hat lock to determine
 * whether the process's optimal page size order has changed significantly
 * since the page size register was last set. If it has changed we get the
 * hat lock and call mmu_set_pgsz_order() to update the effective pagesize
 * order.
 */
void
mmu_check_page_sizes(sfmmu_t *sfmmup, uint64_t *ttecnt)
{
	int64_t sortcnt[MMU_PAGE_SIZES];
	int8_t tmp_pgsz[MMU_PAGE_SIZES];
	ulong_t tmp;
	int8_t i, j, max;
	uint_t pgsz;
	uint16_t *pgsz_order_hv;
	int page_order_changed;
	hatlock_t *hatlockp;
	int pgsz_count = 0;

	ASSERT(!sfmmu_hat_lock_held(sfmmup));

	if (pgsz_search_on == 0)
		return;

	/*
	 * Check if ttecnt has changed significantly, since the last time we
	 * were called. If the shared page sizes have changed then this is
	 * handled by mmu_set_pgsz_order() being called directly when we join
	 * the SCD.
	 */
	for (i = 0; i < mmu_page_sizes; i++) {
		if (ttecnt[i] > (sfmmup->sfmmu_mmuttecnt[i] << 1) ||
		    ttecnt[i] < (sfmmup->sfmmu_mmuttecnt[i] >> 1))
			break;
	}

	if (i == mmu_page_sizes) {
		return;
	}

	/* Sort pages by area mapped */
	for (i = 0; i < mmu_page_sizes; i++) {
		tmp = ttecnt[i];
		sortcnt[i] = tmp << TTE_PAGE_SHIFT(i);
	}

	for (j = 0; j < mmu_page_sizes; j++) {
		for (i = mmu_page_sizes - 1, max = 0; i > 0; i--) {
			if (sortcnt[i] > sortcnt[max])
				max = i;
		}
		tmp_pgsz[j] = max;
		sortcnt[max] = -1;
	}

	/*
	 * Check if the order of the private page sizes has changed. We call
	 * mmu_set_pgsz_order() directly if additional page sizes are used,
	 * so we can assume that the number of entries is unchanged.
	 */
	pgsz_order_hv = sfmmup->sfmmu_pgsz_order_hv;
	if (pgsz_order_shared_first) {
		/* skip over shared pgsz entries */
		while ((pgsz_order_hv[pgsz_count] & TLB_PGSZ_CONTEXT1_ENABLE) ==
		    TLB_PGSZ_CONTEXT1_ENABLE) {
			pgsz_count++;
		}
	}

	i = 0;
	page_order_changed = 0;
	while ((pgsz_order_hv[pgsz_count] & TLB_PGSZ_ENABLE) &&
	    !(pgsz_order_hv[pgsz_count] & TLB_PGSZ_CONTEXT1) &&
	    (pgsz_count < MAX_PGSZ_SEARCH_ORDER)) {
		pgsz = (pgsz_order_hv[pgsz_count] & TTE_SZ_BITS);
		ASSERT(pgsz < MMU_PAGE_SIZES);

		if (pgsz != tmp_pgsz[i]) {
			page_order_changed = 1;
			break;
		}
		pgsz_count++;
		i++;
	}

	if (page_order_changed) {
		hatlockp = sfmmu_hat_enter(sfmmup);
		/* Save old values of ttecnt */
		for (i = 0; i < mmu_page_sizes; i++) {
			sfmmup->sfmmu_mmuttecnt[i] = ttecnt[i];
		}
		mmu_set_pgsz_order(sfmmup, 1);
		sfmmu_hat_exit(hatlockp);
	}
}

/*
 * If the mmu extension API is supported and pgsz_search_on is set,
 * patch out the instruction to branch over the hypervisor call in
 * sfmmu_load_mmustate().
 */
void
mmu_enable_pgsz_search()
{
	if ((hsvc_mmu_ext_available == B_TRUE) && pgsz_search_on) {
		/* patch in hcall to set pgsz order */
		sfmmu_patch_pgsz_reg();
	}
}

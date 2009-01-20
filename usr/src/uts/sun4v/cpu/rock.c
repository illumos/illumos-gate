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

#define	MCOREID_MASK	0x1E
#define	MCOREID_SHIFT	1

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

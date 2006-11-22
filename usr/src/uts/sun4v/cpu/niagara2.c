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
char cpu_module_name[] = "SUNW,UltraSPARC-T2";

/*
 * Hypervisor services information for the NIAGARA2 CPU module
 */
static boolean_t niagara2_hsvc_available = B_TRUE;
static uint64_t niagara2_sup_minor;		/* Supported minor number */
static hsvc_info_t niagara2_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_NIAGARA2_CPU, NIAGARA2_HSVC_MAJOR,
	NIAGARA2_HSVC_MINOR, cpu_module_name
};

void
cpu_setup(void)
{
	extern int mmu_exported_pagesize_mask;
	extern int cpc_has_overflow_intr;
	int status;

	/*
	 * Negotiate the API version for Niagara2 specific hypervisor
	 * services.
	 */
	status = hsvc_register(&niagara2_hsvc, &niagara2_sup_minor);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: cannot negotiate hypervisor services "
		    "group: 0x%lx major: 0x%lx minor: 0x%lx errno: %d",
		    niagara2_hsvc.hsvc_modname, niagara2_hsvc.hsvc_group,
		    niagara2_hsvc.hsvc_major, niagara2_hsvc.hsvc_minor, status);
		niagara2_hsvc_available = B_FALSE;
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

static int niagara2_cpucnt;

void
cpu_init_private(struct cpu *cp)
{
	extern int niagara_kstat_init(void);

	/*
	 * The cpu_ipipe field is initialized based on the execution
	 * unit sharing information from the MD. It defaults to the
	 * virtual CPU id in the absence of such information.
	 */
	cp->cpu_m.cpu_ipipe = cpunodes[cp->cpu_id].exec_unit_mapping;
	if (cp->cpu_m.cpu_ipipe == NO_EU_MAPPING_FOUND)
		cp->cpu_m.cpu_ipipe = (id_t)(cp->cpu_id);

	ASSERT(MUTEX_HELD(&cpu_lock));
	if ((niagara2_cpucnt++ == 0) && (niagara2_hsvc_available == B_TRUE))
		(void) niagara_kstat_init();
}

/*ARGSUSED*/
void
cpu_uninit_private(struct cpu *cp)
{
	extern int niagara_kstat_fini(void);

	ASSERT(MUTEX_HELD(&cpu_lock));
	if ((--niagara2_cpucnt == 0) && (niagara2_hsvc_available == B_TRUE))
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

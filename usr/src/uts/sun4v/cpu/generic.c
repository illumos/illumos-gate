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
#include <vm/seg_spt.h>

#define	S_VAC_SIZE	MMU_PAGESIZE /* XXXQ? */

/*
 * Maximum number of contexts
 */
#define	MAX_NCTXS	(1 << 13)

uint_t root_phys_addr_lo_mask = 0xffffffffU;

void
cpu_setup(void)
{
	extern int at_flags;
	extern int disable_delay_tlb_flush, delay_tlb_flush;
	extern int mmu_exported_pagesize_mask;
	extern int get_cpu_pagesizes(void);

	cache |= (CACHE_PTAG | CACHE_IOCOHERENT);

	at_flags = EF_SPARC_32PLUS | EF_SPARC_SUN_US1; /* XXXQ */

	/*
	 * Use the maximum number of contexts available for Spitfire unless
	 * it has been tuned for debugging.
	 * We are checking against 0 here since this value can be patched
	 * while booting.  It can not be patched via /etc/system since it
	 * will be patched too late and thus cause the system to panic.
	 */
	if (nctxs == 0)
		nctxs = MAX_NCTXS;

	if (use_page_coloring) {
		do_pg_coloring = 1;
		if (use_virtual_coloring)
			do_virtual_coloring = 1;
	}
	/*
	 * Initalize supported page sizes information before the PD.
	 * If no information is available, then initialize the
	 * mmu_exported_pagesize_mask to a reasonable value for that processor.
	 */
	mmu_exported_pagesize_mask = get_cpu_pagesizes();
	if (mmu_exported_pagesize_mask <= 0) {
		mmu_exported_pagesize_mask = (1 << TTE8K) | (1 << TTE64K) |
		    (1 << TTE4M);
	}

	/*
	 * Tune pp_slots to use up to 1/8th of the tlb entries.
	 */
	pp_slots = MIN(8, MAXPP_SLOTS);

	/*
	 * Block stores invalidate all pages of the d$ so pagecopy
	 * et. al. do not need virtual translations with virtual
	 * coloring taken into consideration.
	 */
	pp_consistent_coloring = 0;
	isa_list =
	    "sparcv9+vis sparcv9 "
	    "sparcv8plus+vis sparcv8plus "
	    "sparcv8 sparcv8-fsmuld sparcv7 sparc";

	/*
	 * On Spitfire, there's a hole in the address space
	 * that we must never map (the hardware only support 44-bits of
	 * virtual address).  Later CPUs are expected to have wider
	 * supported address ranges.
	 *
	 * See address map on p23 of the UltraSPARC 1 user's manual.
	 */
/* XXXQ get from machine description */
	hole_start = (caddr_t)0x80000000000ull;
	hole_end = (caddr_t)0xfffff80000000000ull;

	/*
	 * The kpm mapping window.
	 * kpm_size:
	 *	The size of a single kpm range.
	 *	The overall size will be: kpm_size * vac_colors.
	 * kpm_vbase:
	 *	The virtual start address of the kpm range within the kernel
	 *	virtual address space. kpm_vbase has to be kpm_size aligned.
	 */
	kpm_size = (size_t)(2ull * 1024 * 1024 * 1024 * 1024); /* 2TB */
	kpm_size_shift = 41;
	kpm_vbase = (caddr_t)0xfffffa0000000000ull; /* 16EB - 6TB */

	/*
	 * The traptrace code uses either %tick or %stick for
	 * timestamping.  We have %stick so we can use it.
	 */
	traptrace_use_stick = 1;

	/*
	 * sun4v provides demap_all
	 */
	if (!disable_delay_tlb_flush)
		delay_tlb_flush = 1;
}

/*
 * Set the magic constants of the implementation.
 */
void
cpu_fiximp(struct cpu_node *cpunode)
{
	extern int vac_size, vac_shift;
	extern uint_t vac_mask;
	int i, a;

	/*
	 * The assumption here is that fillsysinfo will eventually
	 * have code to fill this info in from the PD.
	 * We hard code this for now.
	 * Once the PD access library is done this code
	 * might need to be changed to get the info from the PD
	 */
	/*
	 * Page Coloring defaults for sun4v
	 */
	ecache_setsize = 0x100000;
	ecache_alignsize = 64;
	cpunode->ecache_setsize =  0x100000;

	vac_size = S_VAC_SIZE;
	vac_mask = MMU_PAGEMASK & (vac_size - 1);
	i = 0; a = vac_size;
	while (a >>= 1)
		++i;
	vac_shift = i;
	shm_alignment = vac_size;
	vac = 0;
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
cpu_init_private(struct cpu *cp)
{
	/*
	 * The cpu_ipipe field is initialized based on the execution
	 * unit sharing information from the Machine Description table.
	 * It defaults to the CPU id in the absence of such information.
	 */
	cp->cpu_m.cpu_ipipe = (id_t)(cp->cpu_id);
}

void
cpu_uninit_private(struct cpu *cp)
{
}

/*
 * Invalidate a TSB. Since this needs to work on all sun4v
 * architecture compliant processors, we use the old method of
 * walking the TSB, setting each tag to TSBTAG_INVALID.
 */
void
cpu_inv_tsb(caddr_t tsb_base, uint_t tsb_bytes)
{
	struct tsbe *tsbaddr;

	for (tsbaddr = (struct tsbe *)tsb_base;
	    (uintptr_t)tsbaddr < (uintptr_t)(tsb_base + tsb_bytes);
	    tsbaddr++) {
		tsbaddr->tte_tag.tag_inthi = TSBTAG_INVALID;
	}
}

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
#include <vm/hat.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <sys/pte.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/machparam.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/mmu.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/lgrp.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/bitmap.h>
#include <vm/rm.h>
#include <sys/t_lock.h>
#include <sys/vm_machparam.h>
#include <sys/promif.h>
#include <sys/prom_isa.h>
#include <sys/prom_plat.h>
#include <sys/prom_debug.h>
#include <sys/privregs.h>
#include <sys/bootconf.h>
#include <sys/memlist.h>
#include <sys/memlist_plat.h>
#include <sys/cpu_module.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/fpu/fpusystm.h>

/*
 * External routines and data structures
 */
extern void	sfmmu_cache_flushcolor(int, pfn_t);

/*
 * Static routines
 */
static void	sfmmu_set_tlb(void);

/*
 * Global Data:
 */
caddr_t	textva, datava;
tte_t	ktext_tte, kdata_tte;		/* ttes for kernel text and data */

int	enable_bigktsb = 1;

tte_t bigktsb_ttes[MAX_BIGKTSB_TTES];
int bigktsb_nttes = 0;


/*
 * Controls the logic which enables the use of the
 * QUAD_LDD_PHYS ASI for TSB accesses.
 */
int	ktsb_phys = 0;



/*
 * This routine remaps the kernel using large ttes
 * All entries except locked ones will be removed from the tlb.
 * It assumes that both the text and data segments reside in a separate
 * 4mb virtual and physical contigous memory chunk.  This routine
 * is only executed by the first cpu.  The remaining cpus execute
 * sfmmu_mp_startup() instead.
 * XXX It assumes that the start of the text segment is KERNELBASE.  It should
 * actually be based on start.
 */
void
sfmmu_remap_kernel(void)
{
	pfn_t	pfn;
	uint_t	attr;
	int	flags;

	extern char end[];
	extern struct as kas;

	textva = (caddr_t)(KERNELBASE & MMU_PAGEMASK4M);
	pfn = va_to_pfn(textva);
	if (pfn == PFN_INVALID)
		prom_panic("can't find kernel text pfn");
	pfn &= TTE_PFNMASK(TTE4M);

	attr = PROC_TEXT | HAT_NOSYNC;
	flags = HAT_LOAD_LOCK | SFMMU_NO_TSBLOAD;
	sfmmu_memtte(&ktext_tte, pfn, attr, TTE4M);
	/*
	 * We set the lock bit in the tte to lock the translation in
	 * the tlb. Note we cannot lock Panther 32M/256M pages into the tlb.
	 * This note is here to make sure that no one tries to remap the
	 * kernel using 32M or 256M tte's on Panther cpus.
	 */
	TTE_SET_LOCKED(&ktext_tte);
	sfmmu_tteload(kas.a_hat, &ktext_tte, textva, NULL, flags);

	datava = (caddr_t)((uintptr_t)end & MMU_PAGEMASK4M);
	pfn = va_to_pfn(datava);
	if (pfn == PFN_INVALID)
		prom_panic("can't find kernel data pfn");
	pfn &= TTE_PFNMASK(TTE4M);

	attr = PROC_DATA | HAT_NOSYNC;
	sfmmu_memtte(&kdata_tte, pfn, attr, TTE4M);
	/*
	 * We set the lock bit in the tte to lock the translation in
	 * the tlb.  We also set the mod bit to avoid taking dirty bit
	 * traps on kernel data.
	 */
	TTE_SET_LOCKED(&kdata_tte);
	TTE_SET_LOFLAGS(&kdata_tte, 0, TTE_HWWR_INT);
	sfmmu_tteload(kas.a_hat, &kdata_tte, datava,
	    (struct page *)NULL, flags);

	/*
	 * create bigktsb ttes if necessary.
	 */
	if (enable_bigktsb) {
		int i = 0;
		caddr_t va = ktsb_base;
		size_t tsbsz = ktsb_sz;
		tte_t tte;

		ASSERT(va >= datava + MMU_PAGESIZE4M);
		ASSERT(tsbsz >= MMU_PAGESIZE4M);
		ASSERT(IS_P2ALIGNED(tsbsz, tsbsz));
		ASSERT(IS_P2ALIGNED(va, tsbsz));
		attr = PROC_DATA | HAT_NOSYNC;
		while (tsbsz != 0) {
			ASSERT(i < MAX_BIGKTSB_TTES);
			pfn = va_to_pfn(va);
			ASSERT(pfn != PFN_INVALID);
			ASSERT((pfn & ~TTE_PFNMASK(TTE4M)) == 0);
			sfmmu_memtte(&tte, pfn, attr, TTE4M);
			ASSERT(TTE_IS_MOD(&tte));
			/*
			 * No need to lock if we use physical addresses.
			 * Since we invalidate the kernel TSB using virtual
			 * addresses, it's an optimization to load them now
			 * so that we won't have to load them later.
			 */
			if (!ktsb_phys) {
				TTE_SET_LOCKED(&tte);
			}
			sfmmu_tteload(kas.a_hat, &tte, va, NULL, flags);
			bigktsb_ttes[i] = tte;
			va += MMU_PAGESIZE4M;
			tsbsz -= MMU_PAGESIZE4M;
			i++;
		}
		bigktsb_nttes = i;
	}

	sfmmu_set_tlb();
}

#ifndef UTSB_PHYS
/*
 * Unmap all references to user TSBs from the TLB of the current processor.
 */
static void
sfmmu_clear_user_tsbs()
{
	caddr_t va;
	caddr_t end_va;

	/* Demap all pages in the VA range for the first user TSB */
	va = utsb_vabase;
	end_va = va + tsb_slab_size;
	while (va < end_va) {
		vtag_flushpage(va, (uint64_t)ksfmmup);
		va += MMU_PAGESIZE;
	}

	/* Demap all pages in the VA range for the second user TSB */
	va = utsb4m_vabase;
	end_va = va + tsb_slab_size;
	while (va < end_va) {
		vtag_flushpage(va, (uint64_t)ksfmmup);
		va += MMU_PAGESIZE;
	}
}
#endif /* UTSB_PHYS */

/*
 * Setup the kernel's locked tte's
 */
void
sfmmu_set_tlb(void)
{
	uint_t index;
	struct cpu_node *cpunode;

	cpunode = &cpunodes[getprocessorid()];
	index = cpunode->itlb_size;

	/*
	 * NOTE: the prom will do an explicit unmap of the VAs from the TLBs
	 * in the following functions before loading the new value into the
	 * TLB.  Thus if there was an entry already in the TLB at a different
	 * location, it will get unmapped before we load the entry at the
	 * specified location.
	 */
	(void) prom_itlb_load(index - 1, *(uint64_t *)&ktext_tte, textva);
	index = cpunode->dtlb_size;
	(void) prom_dtlb_load(index - 1, *(uint64_t *)&kdata_tte, datava);
	(void) prom_dtlb_load(index - 2, *(uint64_t *)&ktext_tte, textva);
	index -= 3;

#ifndef UTSB_PHYS
	utsb_dtlb_ttenum = index--;
	utsb4m_dtlb_ttenum = index--;
	sfmmu_clear_user_tsbs();
#endif /* UTSB_PHYS */

	if (!ktsb_phys && enable_bigktsb) {
		int i;
		caddr_t va = ktsb_base;
		uint64_t tte;

		ASSERT(bigktsb_nttes <= MAX_BIGKTSB_TTES);
		for (i = 0; i < bigktsb_nttes; i++) {
			tte = *(uint64_t *)&bigktsb_ttes[i];
			(void) prom_dtlb_load(index, tte, va);
			va += MMU_PAGESIZE4M;
			index--;
		}
	}

	dtlb_resv_ttenum = index + 1;
}

/*
 * This routine is executed by all other cpus except the first one
 * at initialization time.  It is responsible for taking over the
 * mmu from the prom.  We follow these steps.
 * Lock the kernel's ttes in the TLB
 * Initialize the tsb hardware registers
 * Take over the trap table
 * Flush the prom's locked entries from the TLB
 */
void
sfmmu_mp_startup(void)
{
	sfmmu_set_tlb();
	setwstate(WSTATE_KERN);
	prom_set_traptable(&trap_table);
	install_va_to_tte();
}

void
kdi_tlb_page_lock(caddr_t va, int do_dtlb)
{
	tte_t tte;
	pfn_t pfn = va_to_pfn(va);

	tte.tte_inthi = TTE_VALID_INT | TTE_SZ_INT(TTE8K) | TTE_PFN_INTHI(pfn);
	tte.tte_intlo = TTE_PFN_INTLO(pfn) | TTE_LCK_INT | TTE_CP_INT |
	    TTE_PRIV_INT | TTE_HWWR_INT;

	vtag_flushpage(va, (uint64_t)ksfmmup);

	sfmmu_itlb_ld_kva(va, &tte);
	if (do_dtlb)
		sfmmu_dtlb_ld_kva(va, &tte);
}

/*ARGSUSED*/
void
kdi_tlb_page_unlock(caddr_t va, int do_dtlb)
{
	vtag_flushpage(va, (uint64_t)ksfmmup);
}

/* clear user TSB information (applicable to hardware TSB walkers) */
void
sfmmu_clear_utsbinfo()
{
}

/*ARGSUSED*/
void
sfmmu_setup_tsbinfo(sfmmu_t *sfmmup)
{
}

/*
 * Invalidate a TSB.  If floating point is enabled we use
 * a fast block-store routine, otherwise we use the old method
 * of walking the TSB setting each tag to TSBTAG_INVALID.
 */
void
sfmmu_inv_tsb(caddr_t tsb_base, uint_t tsb_bytes)
{
	extern void sfmmu_inv_tsb_fast(caddr_t, uint_t);
	struct tsbe *tsbaddr;

	/* CONSTCOND */
	if (fpu_exists) {
		sfmmu_inv_tsb_fast(tsb_base, tsb_bytes);
		return;
	}

	for (tsbaddr = (struct tsbe *)tsb_base;
	    (uintptr_t)tsbaddr < (uintptr_t)(tsb_base + tsb_bytes);
	    tsbaddr++) {
		tsbaddr->tte_tag.tag_inthi = TSBTAG_INVALID;
	}

	if (ktsb_phys && tsb_base == ktsb_base)
		dcache_flushall();
}

/*
 * Completely flush the D-cache on all cpus.
 */
void
sfmmu_cache_flushall()
{
	int i;

	for (i = 0; i < CACHE_NUM_COLOR; i++)
		sfmmu_cache_flushcolor(i, 0);
}

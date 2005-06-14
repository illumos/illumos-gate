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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Following is STARFIRE specific code
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vm.h>

#include <sys/cmn_err.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/starfire.h>

#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <sys/vtrace.h>
#include <sys/cpu_sgn.h>

/*
 * SIGBCPU represents the cpu maintaining the primary
 * sigblock (bbsram).  This bbsram is used for CVC
 * and maintains the post2obp structure.  It starts
 * out as the bootproc (cpu0).
 */
struct cpu	*SIGBCPU = &cpu0;

cpu_sgnblk_t *cpu_sgnblkp[NCPU];

/*
 * Mapin the the cpu's signature block.
 */
void
cpu_sgn_mapin(int cpuid)
{
	uint64_t bbsram_physaddr;
	uint64_t cpu_sgnblk_physaddr;
	uint32_t cpu_sgnblk_offset;
	caddr_t	cvaddr;
	pgcnt_t	num_pages;
	pfn_t	pfn;

	ASSERT(cpu_sgnblkp[cpuid] == NULL);

	/*
	 * Construct the physical base address of the bbsram
	 * in PSI space associated with this cpu in question.
	 */
	cpu_sgnblk_physaddr = bbsram_physaddr =
				STARFIRE_UPAID2UPS(cpuid) | STARFIRE_PSI_BASE;

	/*
	 * The cpu_sgnblk pointer offsets are stored in the
	 * undefined hardware trap slot 0x7f which is located
	 * at offset 0xfe0. There are 2 of them since the
	 * bbsram is shared among the 2 cpus residing on the
	 * a PC. We need to determine the CPU in question whether
	 * it is in port 0 or 1. CPU on port 0 has its
	 * signature blkptr stored in 0xfe0 while the cpu_sgnblk
	 * ptr of local port 1's CPU is in offset 0xfe8.
	 */
	if (cpuid & 0x1) {
		/* CPU is in local port 1 */
		bbsram_physaddr |= 0xfe8ULL;
	} else {
		/* CPU is in local port 0 */
		bbsram_physaddr |= 0xfe0ULL;
	}

	/*
	 * Read in the cpu_sgnblk pointer offset. Add it to the bbsram
	 * base address to get the base address of the cpu_sgnblk.
	 */
	cpu_sgnblk_offset = ldphysio(bbsram_physaddr);
	cpu_sgnblk_physaddr += cpu_sgnblk_offset;

	pfn = (pfn_t)(cpu_sgnblk_physaddr >> MMU_PAGESHIFT);

	num_pages = mmu_btopr(((cpu_sgnblk_physaddr &
				MMU_PAGEOFFSET) + sizeof (cpu_sgnblk_t)));

	/*
	 * Map in the cpu_sgnblk
	 */
	cvaddr = vmem_alloc(heap_arena, ptob(num_pages), VM_SLEEP);

	hat_devload(kas.a_hat, cvaddr, ptob(num_pages),
	    pfn, PROT_READ | PROT_WRITE, HAT_LOAD_LOCK);

	cpu_sgnblkp[cpuid] = ((cpu_sgnblk_t *)(cvaddr +
	    (uint32_t)(cpu_sgnblk_offset & MMU_PAGEOFFSET)));
}

void
cpu_sgn_mapout(int cpuid)
{
	ulong_t cvaddr, num_pages;
	uint32_t cpu_sgnblk_offset;
	uint64_t cpu_sgnblk_physaddr;
	uint64_t bbsram_physaddr;

	if ((cvaddr = (ulong_t)cpu_sgnblkp[cpuid]) == NULL) {
		cmn_err(CE_WARN, "cpu_sgn_mapout: ERROR: "
			"cpu_sgnblkp[%d] = NULL\n", cpuid);
	} else {
		cvaddr &= ~MMU_PAGEOFFSET;

		/*
		 * Construct the physical base address of the bbsram
		 * in PSI space associated with this cpu in question.
		 */
		bbsram_physaddr = STARFIRE_UPAID2UPS(cpuid) |
					STARFIRE_PSI_BASE;
		cpu_sgnblk_physaddr = bbsram_physaddr;

		/*
		 * The cpu_sgnblk pointer offsets are stored in the
		 * undefined hardware trap slot 0x7f which is located
		 * at offset 0xfe0. There are 2 of them since the
		 * bbsram is shared among the 2 cpus residing on the
		 * a PC. We need to determine the CPU in question whether
		 * it is in port 0 or 1. CPU on port 0 has its
		 * signature blkptr stored in 0xfe0 while the cpu_sgnblk
		 * ptr of local port 1's CPU is in offset 0xfe8.
		 */
		if (cpuid & 0x1) {
			/* CPU is in local port 1 */
			bbsram_physaddr |= 0xfe8ULL;
		} else {
			/* CPU is in local port 0 */
			bbsram_physaddr |= 0xfe0ULL;
		}

		/*
		 * Read in the cpu_sgnblk pointer offset. Add it to the bbsram
		 * base address to get the base address of the cpu_sgnblk.
		 */
		cpu_sgnblk_offset = ldphysio(bbsram_physaddr);
		cpu_sgnblk_physaddr += cpu_sgnblk_offset;

		num_pages = mmu_btopr(((uint_t)(cpu_sgnblk_physaddr &
				MMU_PAGEOFFSET) + sizeof (cpu_sgnblk_t)));

		hat_unload(kas.a_hat, (caddr_t)cvaddr, ptob(num_pages),
		    HAT_UNLOAD_UNLOCK);
		vmem_free(heap_arena, (caddr_t)cvaddr, ptob(num_pages));

		cpu_sgnblkp[cpuid] = NULL;
	}
}

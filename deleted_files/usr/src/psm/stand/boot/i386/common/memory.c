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

/*
 *	i86pc memory routines
 *
 *	This file contains memory management routines to provide
 *	functionality found in proms on Sparc machines
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
struct cpu;	/* get around mmu.h warning */
#include <sys/mmu.h>
#include <sys/promif.h>
#include <sys/memlist.h>
#include "standalloc.h"
#include "util.h"
#include "machine.h"
#include "debug.h"
#include "cpu_id.h"

/*  These are the various memory lists in boot.c */
extern struct memlist 	*pfreelistp,	/* physmem available */
			*vfreelistp,	/* virtmem available */
			*pinstalledp,   /* physmem installed */
			*pbooterp,	/* booter occupied */
			*pramdiskp;	/* ramdisk memory */

extern uint_t magic_phys;
extern uint_t bpd_loc;
extern int use_align;

extern void start_paging(void);
extern int map_phys(int, size_t, caddr_t, uint64_t);

static int global_pages;
static void fiximp(void);

#define	ALIGN(x, a)	((a) == 0 ? (intptr_t)(x) : \
	(((intptr_t)(x) + (intptr_t)(a) - 1l) & ~((intptr_t)(a) - 1l)))

#define	MMU_L1_INDEX(a)	(((uint_t)(a)) >> 22)
#define	MMU_L2_INDEX(a)	((((uint_t)(a)) >> 12) & 0x3ff)

void
init_paging(void)
{
	ptbl_t	*pdp;
	int mode;
	struct memlist *entry;

	fiximp();	/* figure out cpu capabilities */

	/* allocate boot page table directory */
	pdp = (ptbl_t *)resalloc(RES_BOOTSCRATCH, MMU_PAGESIZE, 0, 0);
	if (pdp == (ptbl_t *)0) {
		prom_panic("init_paging dir");
	}
	bpd_loc = (uint_t)pdp;
	(void) bzero(pdp, MMU_PAGESIZE);

	/* map in scratch memory */
	mode = PG_P | PG_RW;
	(void) map_phys(mode, magic_phys, 0, 0);

	/* map in booter occupied memory */
	entry = pbooterp;
	while (entry) {
		(void) map_phys(mode, (size_t)entry->size,
		    (caddr_t)(uintptr_t)entry->address, entry->address);
		entry = entry->next;
	}

	/* map in ramdisk memory: disallow write */
	entry = pramdiskp;
	while (entry) {
		(void) map_phys(PG_P, (size_t)entry->size,
		    (caddr_t)(uintptr_t)entry->address, entry->address);
		entry = entry->next;
	}

	start_paging();
	if (verbosemode)
		printf("start paging\n");
}

static int
map_4m_page(caddr_t vaddr, uint64_t paddr)
{
	ptbl_t *pdp = (ptbl_t *)bpd_loc;
	uint_t pdir = MMU_L1_INDEX(vaddr);

	if (pdp->page[pdir] & PG_P)
		return (-1);	/* already mapped */

	/* don't set global flag for Pentium or earlier */
	pdp->page[pdir] =
	    (FOURMB_PTE | ((uint_t)paddr & FOURMB_PAGEMASK));
	if (global_pages)
		pdp->page[pdir] |= PG_GLOBAL;

	return (0);
}

static int
map_4k_pages(int mode, size_t bytes, caddr_t vaddr, uint64_t paddr)
{
	ptbl_t *pdp, *ptp;
	uint_t v, vaddr_end;

	pdp = (ptbl_t *)bpd_loc;

	v = (uint_t)vaddr;
	vaddr_end = (v + bytes + MMU_PAGESIZE - 1) & MMU_STD_PAGEMASK;

	while (v < vaddr_end) {
		uint_t pdir = MMU_L1_INDEX(v);

		if (pdp->page[pdir] & PG_P) {
			ptp = (ptbl_t *)
			    ((uint_t)pdp->page[pdir] & MMU_STD_PAGEMASK);
		} else {
			/* allocate a new page table */
			ptp = (ptbl_t *)resalloc(RES_BOOTSCRATCH,
				MMU_PAGESIZE, 0, 0);
			pdp->page[pdir] = ((uint_t)ptp | PG_P | PG_RW);
			(void) bzero(ptp, MMU_PAGESIZE);
		}

		/* as long as we are on this page table */
		while ((pdir == MMU_L1_INDEX(v)) && (v < vaddr_end)) {
			uint_t pndx = MMU_L2_INDEX(v);
			if (ptp->page[pndx] & PG_P) {
				/*
				 * If we are already mapped, panic!
				 * This should not happen under the
				 * current memory allocation scheme
				 * where physmem is either mapped 1:1
				 * or mapped above kernelbase.
				 */
				printf("remapping page at 0x%x\n", v);
				prom_panic("remapping unsupported in booter");
				ptp->page[pndx] |= mode;
			} else {
				ptp->page[pndx] =
				    (((uint_t)paddr & MMU_STD_PAGEMASK) | mode);
			}
			paddr += MMU_PAGESIZE;
			v += MMU_PAGESIZE;
		}
	}

	return (0);
}

int
map_phys(int mode, size_t bytes, caddr_t vaddr, uint64_t paddr)
{
	if (paddr >> 32)	/* don't handle PAE */
		return (-1);

	if (use_align && (bytes == FOURMB_PAGESIZE) &&
	    ((uint_t)vaddr & (FOURMB_PAGESIZE - 1)) == 0 &&
	    ((uint_t)paddr & (FOURMB_PAGESIZE - 1)) == 0)
		return (map_4m_page(vaddr, paddr));	/* ignore mode */

	if (mode == 0)
		mode = PG_P | PG_RW;
	return (map_4k_pages(mode, bytes, vaddr, paddr));
}

static void
fiximp(void)
{
	/* need to support at least standard cpuid level 1 to continue */
	(void) enable_cpuid();
	if (max_std_cpuid_level < 1)
		return;

	use_align = largepage_supported();

	if (use_align) {
		(void) enable_large_pages();

		global_pages = global_bit();
	}

	if (global_pages)
		(void) enable_global_pages();
}

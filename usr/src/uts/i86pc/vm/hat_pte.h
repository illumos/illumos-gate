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

#ifndef	_VM_HAT_PTE_H
#define	_VM_HAT_PTE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/types.h>

/*
 * Defines for the bits in X86 and AMD64 Page Tables
 *
 * Notes:
 *
 * Largepages and PAT bits:
 *
 * bit 7 at level 0 is the PAT bit
 * bit 7 above level 0 is the Pagesize bit (set for large page)
 * bit 12 (when a large page) is the PAT bit
 *
 * In Solaris the PAT/PWT/PCD values are set up so that:
 *
 * PAT & PWT -> Write Protected
 * PAT & PCD -> Write Combining
 * PAT by itself (PWT == 0 && PCD == 0) yields uncacheable (same as PCD == 1)
 *
 *
 * Permission bits:
 *
 * - PT_USER must be set in all levels for user pages
 * - PT_WRITE must be set in all levels for user writable pages
 * - PT_NX applies if set at any level
 *
 * For these, we use the "allow" settings in all tables above level 0 and only
 * ever disable things in PTEs.
 *
 * The use of PT_GLOBAL and PT_NX depend on being enabled in processor
 * control registers. Hence, we use a variable to reference these bit
 * masks. During hat_kern_setup() if the feature isn't enabled we
 * clear out the variables.
 */
#define	PT_VALID	(0x001)	/* a valid translation is present */
#define	PT_WRITABLE	(0x002)	/* the page is writable */
#define	PT_USER		(0x004)	/* the page is accessible by user mode */
#define	PT_WRITETHRU	(0x008)	/* write back caching is disabled (non-PAT) */
#define	PT_NOCACHE	(0x010)	/* page is not cacheable (non-PAT) */
#define	PT_REF		(0x020)	/* page was referenced */
#define	PT_MOD		(0x040)	/* page was modified */
#define	PT_PAGESIZE	(0x080)	/* above level 0, indicates a large page */
#define	PT_PAT_4K	(0x080) /* at level 0, used for write combining */
#define	PT_GLOBAL	(0x100)	/* the mapping is global */
#define	PT_SOFTWARE	(0xe00)	/* available for software */

#define	PT_PAT_LARGE	(0x1000)	/* PAT bit for large pages */

#define	PT_PTPBITS	(PT_VALID | PT_USER | PT_WRITABLE | PT_REF)
#define	PT_FLAGBITS	(0xfff)	/* for masking off flag bits */

/*
 * The software bits are used by the HAT to track attributes.
 *
 * PT_NOSYNC - The PT_REF/PT_MOD bits are not sync'd to page_t.
 *             The hat will install them as always set.
 *
 * PT_NOCONSIST - There is no entry for this hment for this mapping.
 */
#define	PT_NOSYNC	(0x200)	/* PTE was created with HAT_NOSYNC */
#define	PT_NOCONSIST	(0x400)	/* PTE was created with HAT_LOAD_NOCONSIST */

/*
 * macros to get/set/clear the PTE fields
 */
#define	PTE_SET(p, f)	((p) |= (f))
#define	PTE_CLR(p, f)	((p) &= ~(x86pte_t)(f))
#define	PTE_GET(p, f)	((p) & (f))

/*
 * Handy macro to check if a pagetable entry or pointer is valid
 */
#define	PTE_ISVALID(p)		PTE_GET(p, PT_VALID)

/*
 * Does a PTE map a large page.
 */
#define	PTE_IS_LGPG(p, l)	((l) > 0 && PTE_GET((p), PT_PAGESIZE))

/*
 * does this PTE represent a page (not a pointer to another page table)?
 */
#define	PTE_ISPAGE(p, l)	\
	(PTE_ISVALID(p) && ((l) == 0 || PTE_GET(p, PT_PAGESIZE)))

/*
 * Handy macro to check if 2 PTE's are the same - ignores REF/MOD bits
 */
#define	PTE_EQUIV(a, b)	 (((a) | PT_REF | PT_MOD) == ((b) | PT_REF | PT_MOD))

/*
 * Shorthand for converting a PTE to it's pfn.
 */
#define	PTE2PFN(p, l)	\
	mmu_btop(PTE_GET((p), PTE_IS_LGPG((p), (l)) ? PT_PADDR_LGPG : PT_PADDR))

/*
 * The software extraction for a single Page Table Entry will always
 * be a 64 bit unsigned int. If running a non-PAE hat, the page table
 * access routines know to extend/shorten it to 32 bits.
 */
typedef uint64_t x86pte_t;
typedef uint32_t x86pte32_t;
#define	PT_NX		(0x8000000000000000ull)
#define	PT_PADDR	(0x00fffffffffff000ull)
#define	PT_PADDR_LGPG	(0x00ffffffffffe000ull)	/* phys addr for large pages */

/*
 * Macros to create a PTP or PTE from the pfn and level
 */
#define	MAKEPTP(pfn, l)	\
	(((x86pte_t)(pfn) << MMU_PAGESHIFT) | mmu.ptp_bits[(l) + 1])
#define	MAKEPTE(pfn, l)	\
	(((x86pte_t)(pfn) << MMU_PAGESHIFT) | mmu.pte_bits[l])

/*
 * The idea of "level" refers to the level where the page table is used in the
 * the hardware address translation steps. The level values correspond to the
 * following names of tables used in AMD/Intel architecture documents:
 *
 *	AMD/INTEL name		Level #
 *	----------------------	-------
 *	Page Map Level 4	   3
 *	Page Directory Pointer	   2
 *	Page Directory		   1
 *	Page Table		   0
 *
 * The numbering scheme is such that the values of 0 and 1 can correspond to
 * the pagesize codes used for MPSS support. For now the Maximum level at
 * which you can have a large page is a constant, that may change in
 * future processors.
 *
 * The type of "level_t" is signed so that it can be used like:
 *	level_t	l;
 *	...
 *	while (--l >= 0)
 *		...
 */
#define	MAX_NUM_LEVEL		4
#define	MAX_PAGE_LEVEL		1			/* for now.. sigh */
typedef	int16_t level_t;
#define	LEVEL_SHIFT(l)	(mmu.level_shift[l])
#define	LEVEL_SIZE(l)	(mmu.level_size[l])
#define	LEVEL_OFFSET(l)	(mmu.level_offset[l])
#define	LEVEL_MASK(l)	(mmu.level_mask[l])

/*
 * Macros to:
 * Check for a PFN above 4Gig and 64Gig for 32 bit PAE support
 */
#define	PFN_4G		(4ull * (1024 * 1024 * 1024 / MMU_PAGESIZE))
#define	PFN_64G		(64ull * (1024 * 1024 * 1024 / MMU_PAGESIZE))
#define	PFN_ABOVE4G(pfn) ((pfn) >= PFN_4G)
#define	PFN_ABOVE64G(pfn) ((pfn) >= PFN_64G)

/*
 * The CR3 register holds the physical address of the top level page table.
 */
#define	MAKECR3(pfn)    mmu_ptob(pfn)

/*
 * HAT/MMU parameters that depend on kernel mode and/or processor type
 */
struct htable;
struct hat_mmu_info {
	x86pte_t pt_nx;		/* either 0 or PT_NX */
	x86pte_t pt_global;	/* either 0 or PT_GLOBAL */

	pfn_t highest_pfn;

	uint_t num_level;	/* number of page table levels in use */
	uint_t max_level;	/* just num_level - 1 */
	uint_t max_page_level;	/* maximum level at which we can map a page */
	uint_t ptes_per_table;	/* # of entries in lower level page tables */
	uint_t top_level_count;	/* # of entries in top most level page table */

	uint_t	hash_cnt;	/* cnt of entries in htable_hash_cache */
	uint_t	vlp_hash_cnt;	/* cnt of entries in vlp htable_hash_cache */

	uint_t pae_hat;		/* either 0 or 1 */

	uintptr_t hole_start;	/* start of VA hole (or -1 if none) */
	uintptr_t hole_end;	/* end of VA hole (or 0 if none) */

	struct htable **kmap_htables; /* htables for segmap + 32 bit heap */
	x86pte_t *kmap_ptes;	/* mapping of pagetables that map kmap */
	uintptr_t kmap_addr;	/* start addr of kmap */
	uintptr_t kmap_eaddr;	/* end addr of kmap */

	uint_t pte_size;	/* either 4 or 8 */
	uint_t pte_size_shift;	/* either 2 or 3 */
	x86pte_t ptp_bits[MAX_NUM_LEVEL];	/* bits set for interior PTP */
	x86pte_t pte_bits[MAX_NUM_LEVEL];	/* bits set for leaf PTE */

	/*
	 * The following tables are equivalent to PAGEXXXXX at different levels
	 * in the page table hierarchy.
	 */
	uint_t level_shift[MAX_NUM_LEVEL];	/* PAGESHIFT for given level */
	uintptr_t level_size[MAX_NUM_LEVEL];	/* PAGESIZE for given level */
	uintptr_t level_offset[MAX_NUM_LEVEL];	/* PAGEOFFSET for given level */
	uintptr_t level_mask[MAX_NUM_LEVEL];	/* PAGEMASK for given level */

	uint_t tlb_entries[MAX_NUM_LEVEL];	/* tlb entries per pagesize */
};


#if defined(_KERNEL)
/*
 * The concept of a VA hole exists in AMD64. This might need to be made
 * model specific eventually.
 */
#if defined(__amd64)

#ifdef lint
#define	IN_VA_HOLE(va)	(__lintzero)
#else
#define	IN_VA_HOLE(va)	(mmu.hole_start <= (va) && (va) < mmu.hole_end)
#endif

#define	FMT_PTE "%lx"

#elif defined(__i386)

#ifdef lint
#define	IN_VA_HOLE(va)	(__lintzero)
#else
#define	IN_VA_HOLE(va)	(0)
#endif

#define	FMT_PTE "%llx"

#endif


extern struct hat_mmu_info mmu;

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_PTE_H */

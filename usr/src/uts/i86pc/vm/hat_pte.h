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

#ifndef	_VM_HAT_PTE_H
#define	_VM_HAT_PTE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/mach_mmu.h>

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
 * Handy macro to check if 2 PTE's are the same - ignores REF/MOD bits.
 * On the 64 bit hypervisor we also have to ignore the high order
 * software bits and the global/user bit which are set/cleared
 * capriciously (by the hypervisor!)
 */
#if defined(__amd64) && defined(__xpv)
#define	PT_IGNORE	((0x7fful << 52) | PT_GLOBAL | PT_USER)
#else
#define	PT_IGNORE	(0)
#endif
#define	PTE_EQUIV(a, b)	 (((a) | (PT_IGNORE | PT_REF | PT_MOD)) == \
	((b) | (PT_IGNORE | PT_REF | PT_MOD)))

/*
 * Shorthand for converting a PTE to it's pfn.
 */
#define	PTE2MFN(p, l)	\
	mmu_btop(PTE_GET((p), PTE_IS_LGPG((p), (l)) ? PT_PADDR_LGPG : PT_PADDR))
#ifdef __xpv
#define	PTE2PFN(p, l) pte2pfn(p, l)
#else
#define	PTE2PFN(p, l) PTE2MFN(p, l)
#endif

#define	PT_NX		(0x8000000000000000ull)
#define	PT_PADDR	(0x000ffffffffff000ull)
#define	PT_PADDR_LGPG	(0x000fffffffffe000ull)	/* phys addr for large pages */

/*
 * Macros to create a PTP or PTE from the pfn and level
 */
#ifdef __xpv

/*
 * we use the highest order bit in physical address pfns to mark foreign mfns
 */
#ifdef _LP64
#define	PFN_IS_FOREIGN_MFN (1ul << 51)
#else
#define	PFN_IS_FOREIGN_MFN (1ul << 31)
#endif

#define	MAKEPTP(pfn, l)	\
	(pa_to_ma(pfn_to_pa(pfn)) | mmu.ptp_bits[(l) + 1])
#define	MAKEPTE(pfn, l) \
	((pfn & PFN_IS_FOREIGN_MFN) ? \
	((pfn_to_pa(pfn & ~PFN_IS_FOREIGN_MFN) | mmu.pte_bits[l]) | \
	PT_FOREIGN | PT_REF | PT_MOD) : \
	(pa_to_ma(pfn_to_pa(pfn)) | mmu.pte_bits[l]))
#else
#define	MAKEPTP(pfn, l)	\
	(pfn_to_pa(pfn) | mmu.ptp_bits[(l) + 1])
#define	MAKEPTE(pfn, l)	\
	(pfn_to_pa(pfn) | mmu.pte_bits[l])
#endif

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
#define	MAX_PAGE_LEVEL		2
typedef	int8_t level_t;
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
#define	MAKECR3(pfn)	mmu_ptob(pfn)

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
	uint_t umax_page_level; /* max user page map level */
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
	 * A range of VA used to window pages in the i86pc/vm code.
	 * See PWIN_XXX macros.
	 */
	caddr_t	pwin_base;
	caddr_t	pwin_pte_va;
	paddr_t	pwin_pte_pa;

	/*
	 * The following tables are equivalent to PAGEXXXXX at different levels
	 * in the page table hierarchy.
	 */
	uint_t level_shift[MAX_NUM_LEVEL];	/* PAGESHIFT for given level */
	uintptr_t level_size[MAX_NUM_LEVEL];	/* PAGESIZE for given level */
	uintptr_t level_offset[MAX_NUM_LEVEL];	/* PAGEOFFSET for given level */
	uintptr_t level_mask[MAX_NUM_LEVEL];	/* PAGEMASK for given level */
};


#if defined(_KERNEL)

/*
 * Macros to access the HAT's private page windows. They're used for
 * accessing pagetables, ppcopy() and page_zero().
 * The 1st two macros are used to get an index for the particular use.
 * The next three give you:
 * - the virtual address of the window
 * - the virtual address of the pte that maps the window
 * - the physical address of the pte that map the window
 */
#define	PWIN_TABLE(cpuid)	((cpuid) * 2)
#define	PWIN_SRC(cpuid)		((cpuid) * 2 + 1)	/* for x86pte_copy() */
#define	PWIN_VA(x)		(mmu.pwin_base + ((x) << MMU_PAGESHIFT))
#define	PWIN_PTE_VA(x)		(mmu.pwin_pte_va + ((x) << mmu.pte_size_shift))
#define	PWIN_PTE_PA(x)		(mmu.pwin_pte_pa + ((x) << mmu.pte_size_shift))

/*
 * The concept of a VA hole exists in AMD64. This might need to be made
 * model specific eventually.
 *
 * In the 64 bit kernel PTE loads are atomic, but need atomic_cas_64 on 32
 * bit kernel.
 */
#if defined(__amd64)

#ifdef lint
#define	IN_VA_HOLE(va)	(__lintzero)
#else
#define	IN_VA_HOLE(va)	(mmu.hole_start <= (va) && (va) < mmu.hole_end)
#endif

#define	FMT_PTE "0x%lx"
#define	GET_PTE(ptr)		(*(x86pte_t *)(ptr))
#define	SET_PTE(ptr, pte)	(*(x86pte_t *)(ptr) = pte)
#define	CAS_PTE(ptr, x, y)	atomic_cas_64(ptr, x, y)

#elif defined(__i386)

#define	IN_VA_HOLE(va)	(__lintzero)

#define	FMT_PTE "0x%llx"

/* on 32 bit kernels, 64 bit loads aren't atomic, use get_pte64() */
extern x86pte_t get_pte64(x86pte_t *ptr);
#define	GET_PTE(ptr)	(mmu.pae_hat ? get_pte64(ptr) : *(x86pte32_t *)(ptr))
#define	SET_PTE(ptr, pte)						\
	((mmu.pae_hat ? ((x86pte32_t *)(ptr))[1] = (pte >> 32) : 0),	\
	*(x86pte32_t *)(ptr) = pte)
#define	CAS_PTE(ptr, x, y)			\
	(mmu.pae_hat ? atomic_cas_64(ptr, x, y) :	\
	atomic_cas_32((uint32_t *)(ptr), (uint32_t)(x), (uint32_t)(y)))

#endif	/* __i386 */

/*
 * Return a pointer to the pte entry at the given index within a page table.
 */
#define	PT_INDEX_PTR(p, x) \
	((x86pte_t *)((uintptr_t)(p) + ((x) << mmu.pte_size_shift)))

/*
 * Return the physical address of the pte entry at the given index within a
 * page table.
 */
#define	PT_INDEX_PHYSADDR(p, x) \
	((paddr_t)(p) + ((x) << mmu.pte_size_shift))

/*
 * From pfn to bytes, careful not to lose bits on PAE.
 */
#define	pfn_to_pa(pfn) (mmu_ptob((paddr_t)(pfn)))

#ifdef __xpv
extern pfn_t pte2pfn(x86pte_t, level_t);
#endif

extern struct hat_mmu_info mmu;

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_PTE_H */

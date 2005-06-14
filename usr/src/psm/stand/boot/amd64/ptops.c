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

#include <amd64/amd64.h>
#include <amd64/print.h>
#include <amd64/debug.h>
#include <amd64/alloc.h>
#include <amd64/cpu.h>
#include <amd64/amd64_page.h>

static amd64_mmumode_t mmus[] = {
	{ 22, 10, 2, 1024 },	/* legacy 32-bit mode */
	{ 39, 9, 4, 512 }	/* long 64-bit mode */
};

uint16_t
amd64_modbits(uint64_t entry)
{
	return ((uint16_t)PA_MODBITS(entry));
}

uint64_t
amd64_legacy_physaddr(uint32_t entry)
{
	return (IS_LARGEMAP(entry) ?
	    ((uint64_t)(entry) & ~0x3fffffULL |
		(((uint64_t)(entry) >> 13) & 0xffULL) << 32)
		: ((uint64_t)(entry) & ~0xfffULL));
}

uint64_t
amd64_long_physaddr(uint64_t entry)
{
	return (IS_LARGEMAP(entry) ? (entry & ~0x1fffffULL) :
	    (entry & ~0xfffULL));
}

uint64_t
amd64_physaddr(uint64_t entry, uint8_t amd64_mmu_mode)
{
	return (amd64_mmu_mode == AMD64_MODE_LONG64) ?
	    amd64_long_physaddr(entry) : amd64_legacy_physaddr((uint32_t)entry);
}

static uint64_t
amd64_tbl_lookup(uint8_t amd64_mmu_mode, uint64_t va, uint32_t tbl_base,
	uint32_t *addr_inc)
{
	uint8_t level;
	uint8_t level_shift = mmus[amd64_mmu_mode].level_shift;
	uint8_t pde_level = mmus[amd64_mmu_mode].map_level - 1;
	uint8_t shift = mmus[amd64_mmu_mode].shift_base;
	uint64_t mask = (1ULL << level_shift) - 1;
	uint64_t entry;

	ASSERT(tbl_base);

	for (level = 1; shift > AMD64_PAGESIZE_OFFSET_NBITS;
	    shift -= level_shift, level++) {
		entry = TBL_ENTRY64(amd64_mmu_mode, tbl_base, va, shift,
		    mask);

		if (!(ENTRY_VALID(entry))) {
			/*
			 * If a page level is empty, set addr_inc to the shift
			 * value because in a sequential search we know the next
			 * (1 << level_shift) bytes are unmapped.
			 */
			while (shift >= 32)
				shift -= level_shift;	/* XXX */

			if (addr_inc)
				*addr_inc = (1 << shift);

			return (0);
		}

		if (((level == pde_level) && (IS_LARGEMAP(entry))) ||
			IS_PTE(level, amd64_mmu_mode))  {
			/* Set addr_inc to pagesize found and return entry. */

			while (shift >= 32)
				shift -= level_shift;	/* XXX */

			if (addr_inc)
				*addr_inc = (1 << shift);

			return (entry);
		}

		tbl_base = (uint32_t)amd64_physaddr(entry, amd64_mmu_mode);
	}

	if (addr_inc)
		*addr_inc = (uint32_t)AMD64_PAGESIZE;

	return (0);
}

uint64_t
amd64_long_lookup(uint64_t va, uint32_t *addr_inc, uint32_t tbl_base)
{
	return (amd64_tbl_lookup(AMD64_MODE_LONG64, va, tbl_base, addr_inc));
}

uint32_t
amd64_legacy_lookup(uint64_t va, uint32_t *addr_inc, uint32_t tbl_base)
{
	return ((uint32_t)amd64_tbl_lookup(AMD64_MODE_LEGACY, va, tbl_base,
		addr_inc));
}

uint64_t
amd64_legacy_lookup_physaddr(uint64_t va, uint32_t tbl_base)
{
	uint32_t entry, pagesize;
	uint64_t offset;

	if (!(entry = amd64_legacy_lookup(va, &pagesize, tbl_base)))
		amd64_panic("legacy lookup failed for va 0x%llx\n!", va);

	offset = va & AMD64_PAGEOFFSET(pagesize);
	return (amd64_legacy_physaddr(entry) + offset);
}

uint64_t
amd64_long_lookup_physaddr(uint64_t va, uint32_t tbl_base)
{
	uint32_t pagesize;
	uint64_t entry, offset;

	if (!(entry = amd64_long_lookup(va, &pagesize, tbl_base)))
		amd64_panic("long lookup failed for va 0x%llx\n!", va);

	offset = va & AMD64_PAGEOFFSET(pagesize);
	return (amd64_long_physaddr(entry) + offset);
}

void
amd64_map_mem(uint64_t va, uint64_t pa, uint32_t len, uint8_t amd64_mmu_mode,
    uint32_t tbl_base, uint16_t page_modbits)
{
	uint64_t parentlvl_entry;
	uint64_t entry;
	uint64_t local_pagebits;

	uint32_t pagesize;
	uint32_t parent_base;
	uint32_t tbl_root = tbl_base;

	uint8_t level_shift = mmus[amd64_mmu_mode].level_shift;
	uint64_t idx_mask = (1ULL << level_shift) - 1;

	uint8_t level, map_level;
	uint8_t shift;

	ASSERT(tbl_base);
	ASSERT(AMD64_PAGEALIGNED(va, AMD64_PAGESIZE));
	ASSERT(AMD64_PAGEALIGNED(pa, AMD64_PAGESIZE));
	ASSERT(AMD64_PAGEALIGNED(len, AMD64_PAGESIZE));

	if ((amd64_mmu_mode == AMD64_MODE_LONG64) && ((va >> 47) & 1) &&
	    ((va >> 48) != 0xffffULL))
		amd64_panic("amd64_map_mem: map attempted into 64-bit VA "
		    "hole (va 0x%llx)\n", va);

	while (len != 0) {
		map_level = mmus[amd64_mmu_mode].map_level;

		/*
		 * Check to see if we're mapping a range that could be
		 * mapped by a large page one page table level up.  If so,
		 * use the larger page for efficiency:
		 *
		 * Long 64-bit mode:   2M PAGE = (AMD64_PAGESIZE << LEVEL_SHIFT)
		 * Legacy 32-bit mode: 4M PAGE = (AMD64_PAGESIZE << LEVEL_SHIFT)
		 */
		pagesize = AMD64_PAGESIZE << level_shift;

		if (AMD64_PAGEALIGNED(va, pagesize) && AMD64_PAGEALIGNED(pa,
		    pagesize) && (len >= pagesize)) {
			map_level--;
			local_pagebits = PDE_PS;
		} else {
			pagesize = AMD64_PAGESIZE;
			local_pagebits = 0;
		}

		level = 1;
		shift = mmus[amd64_mmu_mode].shift_base;

		while ((level <= map_level) && (len >= pagesize)) {
			entry = TBL_ENTRY64(amd64_mmu_mode, tbl_base, va, shift,
			    idx_mask);

			if (level < map_level) {
				if (!(ENTRY_VALID(entry))) {
					uint32_t page;

					/*
					 * Grab an identity-mapped page at this
					 * level for an array of entries.
					 */
					page = (uint32_t)amd64_zalloc_identity(
					    AMD64_PAGESIZE);

					/*
					 * Setup entry pointing to the new array
					 */
					entry = TBL_ENTRY_DEFAULT(page);

					/*
					 * Insert new entry into table
					 */
					SET_TABLEVAL(amd64_mmu_mode, tbl_base,
					    va, shift, idx_mask, entry);

					/*
					 * If we're mapping in 64-bit long mode,
					 * make sure to identity map the
					 * allocation above into the 64-bit
					 * page tables to make sure the kernel
					 * can walk the 64-bit page tables.
					 */
					if (amd64_mmu_mode ==
					    AMD64_MODE_LONG64)
						amd64_map_mem(
						    (uint64_t)page,
						    (uint64_t)page,
						    AMD64_PAGESIZE,
						    amd64_mmu_mode, tbl_root,
						    page_modbits);
				}

				/*
				 * Continue down another level.
				 */
				if ((level + 1) == map_level) {
				    parent_base = tbl_base;
				    parentlvl_entry = entry;
				}

				tbl_base = (uint32_t)amd64_physaddr(entry,
					amd64_mmu_mode);
				shift -= level_shift;
				level++;
				continue;
			}

			do {
				/*
				 * Create mapping entry at this level.
				 */
				entry = TBL_ENTRY_DEFAULT(pa) | page_modbits |
				    local_pagebits;

				/*
				 * Install mapping entry
				 */
				SET_TABLEVAL(amd64_mmu_mode, tbl_base, va,
				    shift, idx_mask, entry);

				va += pagesize;
				pa += pagesize;
				len -= pagesize;
			} while ((TBL_ENTRY64(amd64_mmu_mode, parent_base, va,
			    shift + level_shift,
			    idx_mask) == parentlvl_entry) && (len >= pagesize));

			if (len != 0) {
				/*
				 * We went over a parent's table entry mapping
				 * border, so we need to recalculate where we
				 * should be adding page tables.
				 *
				 * For example, if we are mapping 4K page
				 * tables in long mode, this means we crossed a
				 * 2M boundary. (It would be a 4M boundary for
				 * 32-bit legacy mode.)
				 */
				level = 1;
				tbl_base = tbl_root;
				shift = mmus[amd64_mmu_mode].shift_base;
			}
		}
	}
}

/*
 * Save top of boot's 64-bit page tables for future use.
 */
uint64_t amd64_boot_pml4;

/*
 * Initialize long page tables
 */
uint64_t
amd64_init_longpt(uint32_t cr3)
{
	extern int magic_phys;
	int i;
	uint64_t *pml4, *pdpt, *pdpt_hi, *pdt, *pte_zero;

	pml4 = amd64_zalloc_identity(AMD64_PAGESIZE);
	pdpt = amd64_zalloc_identity(AMD64_PAGESIZE);
	pdpt_hi = amd64_zalloc_identity(AMD64_PAGESIZE);
	pdt = amd64_zalloc_identity(AMD64_PAGESIZE * 4);
	pte_zero = amd64_zalloc_identity(AMD64_PAGESIZE);

	/*
	 * Initialize long mode page tables.
	 *
	 * The only initial mappings are those for the identity mapped boot 4M
	 * (0x01000:0x400000) and those boot has already allocated.
	 */
	*pml4 = TBL_ENTRY_DEFAULT(pdpt);

	/*
	 * Preallocate enough level two and three entries to map the lower 4G
	 * of VA space, which will be reflected to the top 4G of VM space
	 * directly at the level two page tables.
	 */
	*(pml4 + 511) = TBL_ENTRY_DEFAULT(pdpt_hi);

	*pdpt = *(pdpt_hi + 508) = TBL_ENTRY_DEFAULT(pdt);
	*(pdpt + 1) = *(pdpt_hi + 509) = TBL_ENTRY_DEFAULT(pdt + 512);
	*(pdpt + 2) = *(pdpt_hi + 510) = TBL_ENTRY_DEFAULT(pdt + 1024);
	*(pdpt + 3) = *(pdpt_hi + 511) = TBL_ENTRY_DEFAULT(pdt + 1536);

	*pdt = TBL_ENTRY_DEFAULT(pte_zero);	/* leave page zero unmapped */

	/* Identity map VA 0x200000:magic_phys at the PDE level via 2M pages */
	for (i = 1; (i + 1) * 0x200000 < magic_phys; i++)
		*(pdt + i) = TBL_ENTRY_DEFAULT(i * 0x200000) | PDE_PS;

	/*
	 * Copy the balance of boot's initial mappings - this will fill in
	 * mapped entries in the page tables other than the 2M identity mapped
	 * page mentioned above.
	 */
	amd64_xlate_boot_tables(cr3, (uint32_t)pml4);
	amd64_boot_pml4 = UINT64_FROMPTR32(pml4);

	return (amd64_boot_pml4);
}

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/machsystm.h>
#include <sys/mach_mmu.h>
#include <sys/mman.h>
#include <sys/x86_archext.h>
#include <vm/hat_pte.h>

#include <sys/vmm_gpt.h>
#include <sys/vmm_vm.h>

static inline uint64_t
rvi_prot(uint_t prot)
{
	uint64_t bits;

	bits = 0;
	if ((prot & PROT_WRITE) != 0)
		bits |= PT_WRITABLE;
	if ((prot & PROT_EXEC) == 0)
		bits |= PT_NX;

	return (bits);
}

static uint_t
rvi_pte_prot(uint64_t pte)
{
	uint_t prot;

	if ((pte & PT_VALID) == 0)
		return (0);

	prot = PROT_READ;
	if ((pte & PT_NX) == 0)
		prot |= PROT_EXEC;
	if ((pte & PT_WRITABLE) != 0)
		prot |= PROT_WRITE;

	return (prot);
}

/* Make sure that PAT indexes line up as expected */
CTASSERT((PAT_DEFAULT_ATTRIBUTE & 0xf) == MTRR_TYPE_WB);
CTASSERT(((PAT_DEFAULT_ATTRIBUTE >> 24) & 0xf) == MTRR_TYPE_UC);

static inline uint64_t
rvi_attr_to_pat(uint8_t attr)
{

	if (attr == MTRR_TYPE_UC)
		return (PT_NOCACHE | PT_WRITETHRU);
	if (attr == MTRR_TYPE_WB)
		return (0);

	panic("unexpected memattr %x", attr);
}

static uint64_t
rvi_map_table(uint64_t pfn)
{
	const uint64_t paddr = pfn_to_pa(pfn);
	const uint64_t flags = PT_USER | PT_REF | PT_VALID;
	const uint64_t pat = rvi_attr_to_pat(MTRR_TYPE_WB);
	const uint64_t rprot = PT_WRITABLE;
	return (paddr | flags | pat | rprot);
}

static uint64_t
rvi_map_page(uint64_t pfn, uint_t prot, uint8_t attr)
{
	const uint64_t paddr = pfn_to_pa(pfn);
	const uint64_t flags = PT_USER | PT_REF | PT_VALID;
	const uint64_t pat = rvi_attr_to_pat(attr);
	const uint64_t rprot = rvi_prot(prot);
	return (paddr | flags | pat | rprot);
}

static pfn_t
rvi_pte_pfn(uint64_t pte)
{
	return (mmu_btop(pte & PT_PADDR));
}

static bool
rvi_pte_is_present(uint64_t pte)
{
	return ((pte & PT_VALID) == PT_VALID);
}

static uint_t
rvi_reset_bits(volatile uint64_t *entry, uint64_t mask, uint64_t bits)
{
	uint64_t pte, newpte, oldpte = 0;

	/*
	 * We use volatile and atomic ops here because we may be
	 * racing against hardware modifying these bits.
	 */
	VERIFY3P(entry, !=, NULL);
	oldpte = *entry;
	do {
		pte = oldpte;
		newpte = (pte & ~mask) | bits;
		oldpte = atomic_cas_64(entry, pte, newpte);
	} while (oldpte != pte);

	return (oldpte & mask);
}

static uint_t
rvi_reset_dirty(uint64_t *entry, bool on)
{
	return (rvi_reset_bits(entry, PT_MOD, on ? (PT_MOD | PT_REF) : 0));
}

static uint_t
rvi_reset_accessed(uint64_t *entry, bool on)
{
	return (rvi_reset_bits(entry, (PT_MOD | PT_REF), on ? PT_REF : 0));
}

static bool
rvi_query(uint64_t *entry, vmm_gpt_query_t query)
{
	ASSERT(entry != NULL);

	const uint64_t pte = *entry;
	switch (query) {
	case VGQ_ACCESSED:
		return ((pte & PT_REF) != 0);
	case VGQ_DIRTY:
		return ((pte & PT_MOD) != 0);
	default:
		panic("unrecognized query: %d", query);
	}
}

static uint64_t
rvi_get_pmtp(pfn_t root_pfn, bool track_dirty)
{
	return (root_pfn << PAGESHIFT);
}

static bool
rvi_hw_ad_supported(void)
{
	return (true);
}


vmm_pte_ops_t rvi_pte_ops = {
	.vpeo_map_table		= rvi_map_table,
	.vpeo_map_page		= rvi_map_page,
	.vpeo_pte_pfn		= rvi_pte_pfn,
	.vpeo_pte_is_present	= rvi_pte_is_present,
	.vpeo_pte_prot		= rvi_pte_prot,
	.vpeo_reset_dirty	= rvi_reset_dirty,
	.vpeo_reset_accessed	= rvi_reset_accessed,
	.vpeo_query		= rvi_query,
	.vpeo_get_pmtp		= rvi_get_pmtp,
	.vpeo_hw_ad_supported	= rvi_hw_ad_supported,
};

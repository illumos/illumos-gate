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
#include <sys/mman.h>
#include <sys/x86_archext.h>
#include <vm/hat_pte.h>

#include <sys/vmm_gpt.h>
#include <sys/vmm_vm.h>

#define	EPT_R		(1 << 0)
#define	EPT_W		(1 << 1)
#define	EPT_X		(1 << 2)
#define	EPT_RWX		(EPT_R | EPT_W | EPT_X)
#define	EPT_LGPG	(1 << 7)
#define	EPT_ACCESSED	(1 << 8)
#define	EPT_DIRTY	(1 << 9)

#define	EPT_PA_MASK	(0x000ffffffffff000ull)

#define	EPT_MAX_LEVELS	4
CTASSERT(EPT_MAX_LEVELS <= MAX_GPT_LEVEL);

#define	EPTP_FLAG_ACCESSED_DIRTY	(1 << 6)

CTASSERT(EPT_R == PROT_READ);
CTASSERT(EPT_W == PROT_WRITE);
CTASSERT(EPT_X == PROT_EXEC);

static uint_t
ept_pte_prot(uint64_t pte)
{
	return (pte & EPT_RWX);
}

static inline uint64_t
ept_attr_to_pat(uint8_t attr)
{
	uint64_t bits = attr & 0x7;
	return (bits << 3);
}

static uint64_t
ept_map_table(uint64_t pfn)
{
	const uint64_t paddr = pfn_to_pa(pfn) & EPT_PA_MASK;
	return (paddr | EPT_RWX);
}

static uint64_t
ept_map_page(uint64_t pfn, uint_t prot, uint8_t attr)
{
	const uint64_t paddr = pfn_to_pa(pfn) & EPT_PA_MASK;
	const uint64_t pat = ept_attr_to_pat(attr);
	const uint64_t rprot = prot & EPT_RWX;
	return (paddr | pat | rprot);
}

static uint64_t
ept_pte_pfn(uint64_t pte)
{
	return (mmu_btop(pte & PT_PADDR));
}

static bool
ept_pte_is_present(uint64_t pte)
{
	return ((pte & EPT_RWX) != 0);
}

static uint_t
ept_reset_bits(volatile uint64_t *entry, uint64_t mask, uint64_t bits)
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
ept_reset_dirty(uint64_t *entry, bool on)
{
	return (ept_reset_bits(entry, EPT_DIRTY,
	    on ? (EPT_DIRTY | EPT_ACCESSED) : 0));
}

static uint_t
ept_reset_accessed(uint64_t *entry, bool on)
{
	return (ept_reset_bits(entry, EPT_DIRTY | EPT_ACCESSED,
	    on ? EPT_ACCESSED : 0));
}

static bool
ept_query(uint64_t *entry, vmm_gpt_query_t query)
{
	ASSERT(entry != NULL);

	const uint64_t pte = *entry;
	switch (query) {
	case VGQ_ACCESSED:
		return ((pte & EPT_ACCESSED) != 0);
	case VGQ_DIRTY:
		return ((pte & EPT_DIRTY) != 0);
	default:
		panic("unrecognized query: %d", query);
	}
}

static uint64_t
ept_get_pmtp(pfn_t root_pfn, bool track_dirty)
{
	const uint64_t ad_flag = track_dirty ? EPTP_FLAG_ACCESSED_DIRTY : 0;
	return ((root_pfn << PAGESHIFT | ad_flag |
	    (EPT_MAX_LEVELS - 1) << 3 | MTRR_TYPE_WB));
}

static bool
ept_hw_ad_supported(void)
{
	uint64_t ept_caps = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	return ((ept_caps & IA32_VMX_EPT_VPID_HW_AD) != 0);
}

vmm_pte_ops_t ept_pte_ops = {
	.vpeo_map_table		= ept_map_table,
	.vpeo_map_page		= ept_map_page,
	.vpeo_pte_pfn		= ept_pte_pfn,
	.vpeo_pte_is_present	= ept_pte_is_present,
	.vpeo_pte_prot		= ept_pte_prot,
	.vpeo_reset_dirty	= ept_reset_dirty,
	.vpeo_reset_accessed	= ept_reset_accessed,
	.vpeo_query		= ept_query,
	.vpeo_get_pmtp		= ept_get_pmtp,
	.vpeo_hw_ad_supported	= ept_hw_ad_supported,
};

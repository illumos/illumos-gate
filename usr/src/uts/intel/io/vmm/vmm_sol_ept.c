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
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/vmm_gpt_impl.h>
#include <sys/debug.h>

#define	EPT_R		(1 << 0)
#define	EPT_W		(1 << 1)
#define	EPT_X		(1 << 2)
#define	EPT_RWX		(EPT_R | EPT_W | EPT_X)
#define	EPT_LGPG	(1 << 7)
#define	EPT_ACCESSED	(1 << 8)
#define	EPT_DIRTY	(1 << 9)

#define	EPT_PA_MASK	(0x000ffffffffff000ull)

#define	EPT_MAX_LEVELS	4

#define	EPTP_FLAG_ACCESSED_DIRTY	(1 << 6)

CTASSERT(EPT_R == PROT_READ);
CTASSERT(EPT_W == PROT_WRITE);
CTASSERT(EPT_X == PROT_EXEC);

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

static bool
ept_pte_parse(uint64_t pte, pfn_t *pfnp, uint_t *protp)
{
	const uint_t prot = pte & EPT_RWX;

	if (prot == 0) {
		return (false);
	}

	if (pfnp != NULL) {
		*pfnp = (pte & PT_PADDR) >> PAGESHIFT;
	}
	if (protp != NULL) {
		*protp = prot;
	}
	return (true);
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

const struct vmm_pte_impl ept_pte_impl = {
	.vpi_map_table		= ept_map_table,
	.vpi_map_page		= ept_map_page,
	.vpi_pte_parse		= ept_pte_parse,
	.vpi_bit_accessed	= EPT_ACCESSED,
	.vpi_bit_dirty		= EPT_DIRTY,

	.vpi_get_pmtp		= ept_get_pmtp,
	.vpi_hw_ad_supported	= ept_hw_ad_supported,
};

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

static bool
rvi_pte_parse(uint64_t pte, pfn_t *pfnp, uint_t *protp)
{
	if ((pte & PT_VALID) == 0) {
		return (false);
	}

	uint_t prot = PROT_READ;
	if ((pte & PT_NX) == 0)
		prot |= PROT_EXEC;
	if ((pte & PT_WRITABLE) != 0)
		prot |= PROT_WRITE;

	if (pfnp != NULL) {
		*pfnp = (pte & PT_PADDR) >> PAGESHIFT;
	}
	if (protp != NULL) {
		*protp = prot;
	}
	return (true);
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

const struct vmm_pte_impl rvi_pte_impl = {
	.vpi_map_table		= rvi_map_table,
	.vpi_map_page		= rvi_map_page,
	.vpi_pte_parse		= rvi_pte_parse,
	.vpi_bit_accessed	= PT_REF,
	.vpi_bit_dirty		= PT_MOD,

	.vpi_get_pmtp		= rvi_get_pmtp,
	.vpi_hw_ad_supported	= rvi_hw_ad_supported,
};

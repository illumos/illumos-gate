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
 * Copyright 2021 Oxide Computer Company
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

typedef struct rvi_map rvi_map_t;
struct rvi_map {
	vmm_gpt_t	*rm_gpt;
	kmutex_t	rm_lock;
};

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

static vmm_pte_ops_t rvi_pte_ops = {
	.vpeo_map_table		= rvi_map_table,
	.vpeo_map_page		= rvi_map_page,
	.vpeo_pte_pfn		= rvi_pte_pfn,
	.vpeo_pte_is_present	= rvi_pte_is_present,
	.vpeo_pte_prot		= rvi_pte_prot,
	.vpeo_reset_dirty	= rvi_reset_dirty,
	.vpeo_reset_accessed	= rvi_reset_accessed,
};

vmm_gpt_t *
rvi_create(void)
{
	return (vmm_gpt_alloc(&rvi_pte_ops));
}

static void *
rvi_ops_create(uintptr_t *root_kaddr)
{
	rvi_map_t *map;

	map = kmem_zalloc(sizeof (*map), KM_SLEEP);
	mutex_init(&map->rm_lock, NULL, MUTEX_DEFAULT, NULL);
	map->rm_gpt = rvi_create();
	*root_kaddr = (uintptr_t)vmm_gpt_root_kaddr(map->rm_gpt);

	return (map);
}

static void
rvi_ops_destroy(void *arg)
{
	rvi_map_t *map = arg;

	if (map != NULL) {
		vmm_gpt_free(map->rm_gpt);
		mutex_destroy(&map->rm_lock);
		kmem_free(map, sizeof (*map));
	}
}

static uint64_t
rvi_ops_wired_count(void *arg)
{
	rvi_map_t *map = arg;
	uint64_t res;

	mutex_enter(&map->rm_lock);
	res = vmm_gpt_mapped_count(map->rm_gpt);
	mutex_exit(&map->rm_lock);

	return (res);
}

static int
rvi_ops_is_wired(void *arg, uint64_t gpa, uint_t *protp)
{
	rvi_map_t *map = arg;
	bool mapped;

	mutex_enter(&map->rm_lock);
	mapped = vmm_gpt_is_mapped(map->rm_gpt, gpa, protp);
	mutex_exit(&map->rm_lock);

	return (mapped ? 0 : -1);
}

static int
rvi_ops_map(void *arg, uint64_t gpa, pfn_t pfn, uint_t _lvl, uint_t prot,
    uint8_t attr)
{
	rvi_map_t *map = arg;

	ASSERT((prot & PROT_READ) != 0);
	ASSERT3U((prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)), ==, 0);

	mutex_enter(&map->rm_lock);
	vmm_gpt_populate_entry(map->rm_gpt, gpa);
	(void) vmm_gpt_map(map->rm_gpt, gpa, pfn, prot, attr);
	mutex_exit(&map->rm_lock);

	return (0);
}

static uint64_t
rvi_ops_unmap(void *arg, uint64_t start, uint64_t end)
{
	rvi_map_t *map = arg;
	size_t unmapped = 0;

	mutex_enter(&map->rm_lock);
	unmapped = vmm_gpt_unmap_region(map->rm_gpt, start, end);
	vmm_gpt_vacate_region(map->rm_gpt, start, end);
	mutex_exit(&map->rm_lock);

	return ((uint64_t)unmapped);
}

struct vmm_pt_ops rvi_ops = {
	.vpo_init		= rvi_ops_create,
	.vpo_free		= rvi_ops_destroy,
	.vpo_wired_cnt		= rvi_ops_wired_count,
	.vpo_is_wired		= rvi_ops_is_wired,
	.vpo_map		= rvi_ops_map,
	.vpo_unmap		= rvi_ops_unmap,
};

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
#include <sys/mman.h>

#include <sys/vmm_gpt.h>
#include <sys/vmm_vm.h>


typedef struct ept_map ept_map_t;
struct ept_map {
	vmm_gpt_t	*em_gpt;
	kmutex_t	em_lock;
};

#define	EPT_R		(1 << 0)
#define	EPT_W		(1 << 1)
#define	EPT_X		(1 << 2)
#define	EPT_RWX		(EPT_R | EPT_W | EPT_X)
#define	EPT_LGPG	(1 << 7)
#define	EPT_ACCESSED	(1 << 8)
#define	EPT_DIRTY	(1 << 9)

#define	EPT_PA_MASK	(0x000ffffffffff000ull)

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

static vmm_pte_ops_t ept_pte_ops = {
	.vpeo_map_table		= ept_map_table,
	.vpeo_map_page		= ept_map_page,
	.vpeo_pte_pfn		= ept_pte_pfn,
	.vpeo_pte_is_present	= ept_pte_is_present,
	.vpeo_pte_prot		= ept_pte_prot,
	.vpeo_reset_dirty	= ept_reset_dirty,
	.vpeo_reset_accessed	= ept_reset_accessed,
};

vmm_gpt_t *
ept_create(void)
{
	return (vmm_gpt_alloc(&ept_pte_ops));
}

static void *
ept_ops_create(uintptr_t *root_kaddr)
{
	ept_map_t *map;

	map = kmem_zalloc(sizeof (*map), KM_SLEEP);
	mutex_init(&map->em_lock, NULL, MUTEX_DEFAULT, NULL);
	map->em_gpt = ept_create();
	*root_kaddr = (uintptr_t)vmm_gpt_root_kaddr(map->em_gpt);

	return (map);
}

static void
ept_ops_destroy(void *arg)
{
	ept_map_t *map = arg;

	if (map != NULL) {
		vmm_gpt_free(map->em_gpt);
		mutex_destroy(&map->em_lock);
		kmem_free(map, sizeof (*map));
	}
}

static uint64_t
ept_ops_wired_count(void *arg)
{
	ept_map_t *map = arg;
	uint64_t res;

	mutex_enter(&map->em_lock);
	res = vmm_gpt_mapped_count(map->em_gpt);
	mutex_exit(&map->em_lock);

	return (res);
}

static int
ept_ops_is_wired(void *arg, uint64_t gpa, uint_t *protp)
{
	ept_map_t *map = arg;
	bool mapped;

	mutex_enter(&map->em_lock);
	mapped = vmm_gpt_is_mapped(map->em_gpt, gpa, protp);
	mutex_exit(&map->em_lock);

	return (mapped ? 0 : -1);
}

static int
ept_ops_map(void *arg, uint64_t gpa, pfn_t pfn, uint_t _lvl, uint_t prot,
    uint8_t attr)
{
	ept_map_t *map = arg;

	ASSERT((prot & EPT_RWX) != 0 && (prot & ~EPT_RWX) == 0);

	mutex_enter(&map->em_lock);
	vmm_gpt_populate_entry(map->em_gpt, gpa);
	(void) vmm_gpt_map(map->em_gpt, gpa, pfn, prot, attr);
	mutex_exit(&map->em_lock);

	return (0);
}

static uint64_t
ept_ops_unmap(void *arg, uint64_t start, uint64_t end)
{
	ept_map_t *map = arg;
	size_t unmapped = 0;

	mutex_enter(&map->em_lock);
	unmapped = vmm_gpt_unmap_region(map->em_gpt, start, end);
	vmm_gpt_vacate_region(map->em_gpt, start, end);
	mutex_exit(&map->em_lock);

	return ((uint64_t)unmapped);
}

struct vmm_pt_ops ept_ops = {
	.vpo_init		= ept_ops_create,
	.vpo_free		= ept_ops_destroy,
	.vpo_wired_cnt		= ept_ops_wired_count,
	.vpo_is_wired		= ept_ops_is_wired,
	.vpo_map		= ept_ops_map,
	.vpo_unmap		= ept_ops_unmap,
};

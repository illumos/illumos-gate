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

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/machsystm.h>

#include <sys/gipt.h>
#include <vm/vm_glue.h>


struct ept_map {
	gipt_map_t	em_gipt;
	uint64_t	em_wired_page_count;
};
typedef struct ept_map ept_map_t;

#define	EPT_LOCK(m)	(&(m)->em_gipt.giptm_lock)

#define	EPT_MAX_LEVELS	4

CTASSERT(EPT_MAX_LEVELS <= GIPT_MAX_LEVELS);

#define	EPT_R		(0x1 << 0)
#define	EPT_W		(0x1 << 1)
#define	EPT_X		(0x1 << 2)
#define	EPT_RWX		(EPT_R | EPT_W | EPT_X)
#define	EPT_LGPG	(0x1 << 7)

#define	EPT_PA_MASK	(0x000ffffffffff000ull)

CTASSERT(EPT_R == PROT_READ);
CTASSERT(EPT_W == PROT_WRITE);
CTASSERT(EPT_X == PROT_EXEC);


#define	EPT_PAT(attr)	(((attr) & 0x7) << 3)
#define	EPT_PADDR(addr)	((addr) & EPT_PA_MASK)

#define	EPT_IS_ABSENT(pte)	(((pte) & EPT_RWX) == 0)
#define	EPT_PTE_PFN(pte)	mmu_btop(EPT_PADDR(pte))
#define	EPT_PTE_PROT(pte)	((pte) & EPT_RWX)
#define	EPT_MAPS_PAGE(pte, lvl)	\
	(EPT_PTE_PROT(pte) != 0 && (((pte) & EPT_LGPG) != 0 || (lvl) == 0))

/*
 * Only assign EPT_LGPG for levels higher than 0.  Although this bit is defined
 * as being ignored at level 0, some versions of VMWare fail to honor this and
 * report such a PTE as an EPT mis-configuration.
 */
#define	EPT_PTE_ASSIGN_PAGE(lvl, pfn, prot, attr)	\
	(EPT_PADDR(pfn_to_pa(pfn)) |			\
	(((lvl) != 0) ? EPT_LGPG : 0) |			\
	EPT_PAT(attr) | ((prot) & EPT_RWX))
#define	EPT_PTE_ASSIGN_TABLE(pfn)	(EPT_PADDR(pfn_to_pa(pfn)) | EPT_RWX)


static gipt_pte_type_t
ept_pte_type(uint64_t pte, uint_t level)
{
	if (EPT_IS_ABSENT(pte)) {
		return (PTET_EMPTY);
	} else if (EPT_MAPS_PAGE(pte, level)) {
		return (PTET_PAGE);
	} else {
		return (PTET_LINK);
	}
}

static uint64_t
ept_pte_map(uint64_t pfn)
{
	return (EPT_PTE_ASSIGN_TABLE(pfn));
}

static void *
ept_create(uintptr_t *pml4_kaddr)
{
	ept_map_t *emap;
	gipt_map_t *map;
	gipt_t *root;
	struct gipt_cbs cbs = {
		.giptc_pte_type = ept_pte_type,
		.giptc_pte_map = ept_pte_map,
	};

	emap = kmem_zalloc(sizeof (*emap), KM_SLEEP);
	map = &emap->em_gipt;
	root = gipt_alloc();
	root->gipt_level = EPT_MAX_LEVELS - 1;
	gipt_map_init(map, EPT_MAX_LEVELS, GIPT_HASH_SIZE_DEFAULT, &cbs, root);

	*pml4_kaddr = (uintptr_t)root->gipt_kva;
	return (emap);
}

static void
ept_destroy(void *arg)
{
	ept_map_t *emap = arg;

	if (emap != NULL) {
		gipt_map_t *map = &emap->em_gipt;

		gipt_map_fini(map);
		kmem_free(emap, sizeof (*emap));
	}
}

static uint64_t
ept_wired_count(void *arg)
{
	ept_map_t *emap = arg;
	uint64_t res;

	mutex_enter(EPT_LOCK(emap));
	res = emap->em_wired_page_count;
	mutex_exit(EPT_LOCK(emap));

	return (res);
}

static int
ept_is_wired(void *arg, uint64_t va, uint_t *protp)
{
	ept_map_t *emap = arg;
	gipt_t *pt;
	int rv = -1;

	mutex_enter(EPT_LOCK(emap));
	pt = gipt_map_lookup_deepest(&emap->em_gipt, va);
	if (pt != NULL) {
		const uint64_t pte = GIPT_VA2PTE(pt, va);

		if (EPT_MAPS_PAGE(pte, pt->gipt_level)) {
			*protp = EPT_PTE_PROT(pte);
			rv = 0;
		}
	}
	mutex_exit(EPT_LOCK(emap));

	return (rv);
}

static int
ept_map(void *arg, uint64_t va, pfn_t pfn, uint_t lvl, uint_t prot,
    uint8_t attr)
{
	ept_map_t *emap = arg;
	gipt_map_t *map = &emap->em_gipt;
	gipt_t *pt;
	uint64_t *ptep, pte;

	ASSERT((prot & EPT_RWX) != 0 && (prot & ~EPT_RWX) == 0);
	ASSERT3U(lvl, <, EPT_MAX_LEVELS);

	mutex_enter(EPT_LOCK(emap));
	pt = gipt_map_lookup(map, va, lvl);
	if (pt == NULL) {
		/*
		 * A table at the appropriate VA/level that would house this
		 * mapping does not currently exist.  Try to walk down to that
		 * point, creating any necessary parent(s).
		 */
		pt = gipt_map_create_parents(map, va, lvl);

		/*
		 * There was a large page mapping in the way of creating the
		 * necessary parent table(s).
		 */
		if (pt == NULL) {
			panic("unexpected large page @ %08lx", va);
		}
	}
	ptep = GIPT_VA2PTEP(pt, va);

	pte = *ptep;
	if (!EPT_IS_ABSENT(pte)) {
		if (!EPT_MAPS_PAGE(pte, lvl)) {
			panic("unexpected PT link @ %08lx in %p", va, pt);
		} else {
			panic("unexpected page mapped @ %08lx in %p", va, pt);
		}
	}

	pte = EPT_PTE_ASSIGN_PAGE(lvl, pfn, prot, attr);
	*ptep = pte;
	pt->gipt_valid_cnt++;
	emap->em_wired_page_count += gipt_level_count[lvl];

	mutex_exit(EPT_LOCK(emap));
	return (0);
}

static uint64_t
ept_unmap(void *arg, uint64_t va, uint64_t end_va)
{
	ept_map_t *emap = arg;
	gipt_map_t *map = &emap->em_gipt;
	gipt_t *pt;
	uint64_t cur_va = va;
	uint64_t unmapped = 0;

	mutex_enter(EPT_LOCK(emap));

	pt = gipt_map_lookup_deepest(map, cur_va);
	if (pt == NULL) {
		mutex_exit(EPT_LOCK(emap));
		return (0);
	}
	if (!EPT_MAPS_PAGE(GIPT_VA2PTE(pt, cur_va), pt->gipt_level)) {
		cur_va = gipt_map_next_page(map, cur_va, end_va, &pt);
		if (cur_va == 0) {
			mutex_exit(EPT_LOCK(emap));
			return (0);
		}
	}

	while (cur_va < end_va) {
		uint64_t *ptep = GIPT_VA2PTEP(pt, cur_va);
		const uint_t lvl = pt->gipt_level;

		ASSERT(EPT_MAPS_PAGE(*ptep, lvl));
		*ptep = 0;
		pt->gipt_valid_cnt--;
		unmapped += gipt_level_count[pt->gipt_level];

		gipt_t *next_pt = pt;
		uint64_t next_va;
		next_va = gipt_map_next_page(map, cur_va, end_va, &next_pt);

		if (pt->gipt_valid_cnt == 0) {
			gipt_map_clean_parents(map, pt);
		}
		if (next_va == 0) {
			break;
		}
		pt = next_pt;
		cur_va = next_va;
	}
	emap->em_wired_page_count -= unmapped;

	mutex_exit(EPT_LOCK(emap));

	return (unmapped);
}

struct vmm_pt_ops ept_ops = {
	.vpo_init	= ept_create,
	.vpo_free	= ept_destroy,
	.vpo_wired_cnt	= ept_wired_count,
	.vpo_is_wired	= ept_is_wired,
	.vpo_map	= ept_map,
	.vpo_unmap	= ept_unmap,
};

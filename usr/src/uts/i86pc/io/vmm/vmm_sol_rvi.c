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
#include <sys/x86_archext.h>

#include <sys/gipt.h>
#include <vm/vm_glue.h>


struct rvi_map {
	gipt_map_t	rm_gipt;
	uint64_t	rm_wired_page_count;
};
typedef struct rvi_map rvi_map_t;

#define	RVI_LOCK(m)	(&(m)->rm_gipt.giptm_lock)

#define	RVI_MAX_LEVELS	4

CTASSERT(RVI_MAX_LEVELS <= GIPT_MAX_LEVELS);

#define	RVI_PRESENT	PT_VALID
#define	RVI_WRITABLE	PT_WRITABLE
#define	RVI_ACCESSED	PT_REF
#define	RVI_DIRTY	PT_MOD
#define	RVI_LGPG	PT_PAGESIZE
#define	RVI_NX		PT_NX
#define	RVI_USER	PT_USER
#define	RVI_PWT		PT_WRITETHRU
#define	RVI_PCD		PT_NOCACHE

#define	RVI_PA_MASK	PT_PADDR

#define	RVI_PAT(attr)	rvi_attr_to_pat(attr)
#define	RVI_PADDR(addr)	((addr) & RVI_PA_MASK)
#define	RVI_PROT(prot)	\
	((((prot) & PROT_WRITE) != 0 ? RVI_WRITABLE : 0) | \
	(((prot) & PROT_EXEC) == 0 ? RVI_NX : 0))

#define	RVI_IS_ABSENT(pte)	(((pte) & RVI_PRESENT) == 0)
#define	RVI_PTE_PFN(pte)	mmu_btop(RVI_PADDR(pte))
#define	RVI_MAPS_PAGE(pte, lvl)	\
	(!RVI_IS_ABSENT(pte) && (((pte) & RVI_LGPG) != 0 || (lvl) == 0))
#define	RVI_PTE_PROT(pte)	\
	(RVI_IS_ABSENT(pte) ? 0 : (			\
	PROT_READ |					\
	(((pte) & RVI_NX) == 0 ? PROT_EXEC : 0) |	\
	(((pte) & RVI_WRITABLE) != 0 ? PROT_WRITE : 0)))

#define	RVI_PTE_ASSIGN_PAGE(lvl, pfn, prot, attr)	\
	(RVI_PADDR(pfn_to_pa(pfn)) |			\
	(((lvl) != 0) ? RVI_LGPG : 0) |			\
	RVI_USER | RVI_ACCESSED | RVI_PRESENT |		\
	RVI_PAT(attr) |					\
	RVI_PROT(prot))

#define	RVI_PTE_ASSIGN_TABLE(pfn)	\
	(RVI_PADDR(pfn_to_pa(pfn)) |			\
	RVI_USER | RVI_ACCESSED | RVI_PRESENT |		\
	RVI_PAT(MTRR_TYPE_WB) |				\
	RVI_PROT(PROT_READ | PROT_WRITE | PROT_EXEC))


/* Make sure that PAT indexes line up as expected */
CTASSERT((PAT_DEFAULT_ATTRIBUTE & 0xf) == MTRR_TYPE_WB);
CTASSERT(((PAT_DEFAULT_ATTRIBUTE >> 24) & 0xf) == MTRR_TYPE_UC);

static inline uint64_t
rvi_attr_to_pat(const uint8_t attr)
{
	if (attr == MTRR_TYPE_UC) {
		/* !PAT + PCD + PWT -> PAT3 -> MTRR_TYPE_UC */
		return (RVI_PCD|RVI_PWT);
	} else if (attr == MTRR_TYPE_WB) {
		/* !PAT + !PCD + !PWT -> PAT0 -> MTRR_TYPE_WB */
		return (0);
	}

	panic("unexpected memattr %x", attr);
	return (0);
}

static gipt_pte_type_t
rvi_pte_type(uint64_t pte, uint_t level)
{
	if (RVI_IS_ABSENT(pte)) {
		return (PTET_EMPTY);
	} else if (RVI_MAPS_PAGE(pte, level)) {
		return (PTET_PAGE);
	} else {
		return (PTET_LINK);
	}
}

static uint64_t
rvi_pte_map(uint64_t pfn)
{
	return (RVI_PTE_ASSIGN_TABLE(pfn));
}

static void *
rvi_create(uintptr_t *pml4_kaddr)
{
	rvi_map_t *rmap;
	gipt_map_t *map;
	gipt_t *root;
	struct gipt_cbs cbs = {
		.giptc_pte_type = rvi_pte_type,
		.giptc_pte_map = rvi_pte_map,
	};

	rmap = kmem_zalloc(sizeof (*rmap), KM_SLEEP);
	map = &rmap->rm_gipt;
	root = gipt_alloc();
	root->gipt_level = RVI_MAX_LEVELS - 1;
	gipt_map_init(map, RVI_MAX_LEVELS, GIPT_HASH_SIZE_DEFAULT, &cbs, root);

	*pml4_kaddr = (uintptr_t)root->gipt_kva;
	return (rmap);
}

static void
rvi_destroy(void *arg)
{
	rvi_map_t *rmap = arg;

	if (rmap != NULL) {
		gipt_map_t *map = &rmap->rm_gipt;

		gipt_map_fini(map);
		kmem_free(rmap, sizeof (*rmap));
	}
}

static uint64_t
rvi_wired_count(void *arg)
{
	rvi_map_t *rmap = arg;
	uint64_t res;

	mutex_enter(RVI_LOCK(rmap));
	res = rmap->rm_wired_page_count;
	mutex_exit(RVI_LOCK(rmap));

	return (res);
}

static int
rvi_is_wired(void *arg, uint64_t va, uint_t *protp)
{
	rvi_map_t *rmap = arg;
	gipt_t *pt;
	int rv = -1;

	mutex_enter(RVI_LOCK(rmap));
	pt = gipt_map_lookup_deepest(&rmap->rm_gipt, va);
	if (pt != NULL) {
		const uint64_t pte = GIPT_VA2PTE(pt, va);

		if (RVI_MAPS_PAGE(pte, pt->gipt_level)) {
			*protp = RVI_PTE_PROT(pte);
			rv = 0;
		}
	}
	mutex_exit(RVI_LOCK(rmap));

	return (rv);
}

static int
rvi_map(void *arg, uint64_t va, pfn_t pfn, uint_t lvl, uint_t prot,
    uint8_t attr)
{
	rvi_map_t *rmap = arg;
	gipt_map_t *map = &rmap->rm_gipt;
	gipt_t *pt;
	uint64_t *ptep, pte;

	ASSERT((prot & PROT_READ) != 0);
	ASSERT3U((prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)), ==, 0);
	ASSERT3U(lvl, <, RVI_MAX_LEVELS);

	mutex_enter(RVI_LOCK(rmap));
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
	if (!RVI_IS_ABSENT(pte)) {
		if (!RVI_MAPS_PAGE(pte, lvl)) {
			panic("unexpected PT link @ %08lx in %p", va, pt);
		} else {
			panic("unexpected page mapped @ %08lx in %p", va, pt);
		}
	}

	pte = RVI_PTE_ASSIGN_PAGE(lvl, pfn, prot, attr);
	*ptep = pte;
	pt->gipt_valid_cnt++;
	rmap->rm_wired_page_count += gipt_level_count[lvl];

	mutex_exit(RVI_LOCK(rmap));
	return (0);
}

static uint64_t
rvi_unmap(void *arg, uint64_t va, uint64_t end_va)
{
	rvi_map_t *rmap = arg;
	gipt_map_t *map = &rmap->rm_gipt;
	gipt_t *pt;
	uint64_t cur_va = va;
	uint64_t unmapped = 0;

	mutex_enter(RVI_LOCK(rmap));

	pt = gipt_map_lookup_deepest(map, cur_va);
	if (pt == NULL) {
		mutex_exit(RVI_LOCK(rmap));
		return (0);
	}
	if (!RVI_MAPS_PAGE(GIPT_VA2PTE(pt, cur_va), pt->gipt_level)) {
		cur_va = gipt_map_next_page(map, cur_va, end_va, &pt);
		if (cur_va == 0) {
			mutex_exit(RVI_LOCK(rmap));
			return (0);
		}
	}

	while (cur_va < end_va) {
		uint64_t *ptep = GIPT_VA2PTEP(pt, cur_va);
		const uint_t lvl = pt->gipt_level;

		ASSERT(RVI_MAPS_PAGE(*ptep, lvl));
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
	rmap->rm_wired_page_count -= unmapped;

	mutex_exit(RVI_LOCK(rmap));

	return (unmapped);
}

struct vmm_pt_ops rvi_ops = {
	.vpo_init	= rvi_create,
	.vpo_free	= rvi_destroy,
	.vpo_wired_cnt	= rvi_wired_count,
	.vpo_is_wired	= rvi_is_wired,
	.vpo_map	= rvi_map,
	.vpo_unmap	= rvi_unmap,
};

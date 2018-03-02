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
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/list.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/malloc.h>
#include <vm/as.h>
#include <vm/seg_vn.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vmm.h>

#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include "vm/vm_glue.h"

#define	PMAP_TO_VMMAP(pm)	((vm_map_t)		\
	((caddr_t)(pm) - offsetof(struct vmspace, vms_pmap)))
#define	VMMAP_TO_VMSPACE(vmmap)	((struct vmspace *)		\
	((caddr_t)(vmmap) - offsetof(struct vmspace, vm_map)))

/* Similar to htable, but without the bells and whistles */
struct eptable {
	struct eptable	*ept_next;
	uintptr_t	ept_vaddr;
	pfn_t		ept_pfn;
	int16_t		ept_level;
	int16_t		ept_valid_cnt;
	uint32_t	_ept_pad2;
	struct eptable	*ept_prev;
	struct eptable	*ept_parent;
	void		*ept_kva;
};
typedef struct eptable eptable_t;

struct eptable_map {
	kmutex_t		em_lock;
	eptable_t		*em_root;
	eptable_t		**em_hash;
	size_t			em_table_cnt;
	size_t			em_wired;

	/* Protected by eptable_map_lock */
	struct eptable_map	*em_next;
	struct eptable_map	*em_prev;
};
typedef struct eptable_map eptable_map_t;

#define	EPTABLE_HASH(va, lvl, sz)				\
	((((va) >> LEVEL_SHIFT(1)) + ((va) >> 28) + (lvl))	\
	& ((sz) - 1))

#define	EPTABLE_VA2IDX(tbl, va)					\
	(((va) - (tbl)->ept_vaddr) >>				\
	LEVEL_SHIFT((tbl)->ept_level))

#define	EPTABLE_IDX2VA(tbl, idx)				\
	((tbl)->ept_vaddr +					\
	((idx) << LEVEL_SHIFT((tbl)->ept_level)))

#define	EPT_R		(0x1 << 0)
#define	EPT_W		(0x1 << 1)
#define	EPT_X		(0x1 << 2)
#define	EPT_RWX		(EPT_R|EPT_W|EPT_X)
#define	EPT_LGPG	(0x1 << 7)

#define	EPT_PAT(attr)	(((attr) & 0x7) << 3)

#define	EPT_PADDR	(0x000ffffffffff000ull)

#define	EPT_IS_ABSENT(pte)	(((pte) & EPT_RWX) == 0)
#define	EPT_PTE_PFN(pte)	mmu_btop((pte) & EPT_PADDR)
#define	EPT_PTE_PROT(pte)	((pte) & EPT_RWX)
#define	EPT_MAPS_PAGE(lvl, pte)				\
	((lvl) == 0 || ((pte) & EPT_LGPG))

#define	EPT_PTE_ASSIGN_TABLE(pfn)			\
	((pfn_to_pa(pfn) & EPT_PADDR) | EPT_RWX)

/*
 * We only assign EPT_LGPG for levels higher than 0: although this bit is
 * defined as being ignored at level 0, some versions of VMWare fail to honor
 * this and report such a PTE as an EPT mis-configuration.
 */
#define	EPT_PTE_ASSIGN_PAGE(lvl, pfn, prot, attr)	\
	((pfn_to_pa(pfn) & EPT_PADDR) |			\
	(((lvl) != 0) ? EPT_LGPG : 0) |			\
	EPT_PAT(attr) | ((prot) & EPT_RWX))

struct vmspace_mapping {
	list_node_t	vmsm_node;
	vm_object_t	vmsm_object;
	uintptr_t	vmsm_addr;
	size_t		vmsm_len;
	off_t		vmsm_offset;
	uint_t		vmsm_prot;
};
typedef struct vmspace_mapping vmspace_mapping_t;

#define	VMSM_OFFSET(vmsm, addr)	(			\
	    (vmsm)->vmsm_offset +			\
	    ((addr) - (uintptr_t)(vmsm)->vmsm_addr))


/* Private glue interfaces */
static void pmap_free(pmap_t);
static eptable_t *eptable_alloc(void);
static void eptable_free(eptable_t *);
static void eptable_init(eptable_map_t *);
static void eptable_fini(eptable_map_t *);
static eptable_t *eptable_hash_lookup(eptable_map_t *, uintptr_t, level_t);
static void eptable_hash_insert(eptable_map_t *, eptable_t *);
static void eptable_hash_remove(eptable_map_t *, eptable_t *);
static eptable_t *eptable_walk(eptable_map_t *, uintptr_t, level_t, uint_t *,
    boolean_t);
static pfn_t eptable_mapin(eptable_map_t *, uintptr_t, pfn_t, uint_t, uint_t,
    vm_memattr_t);
static void eptable_mapout(eptable_map_t *, uintptr_t);
static int eptable_find(eptable_map_t *, uintptr_t, pfn_t *, uint_t *);
static vmspace_mapping_t *vm_mapping_find(struct vmspace *, uintptr_t, size_t);
static void vm_mapping_remove(struct vmspace *, vmspace_mapping_t *);

static kmutex_t eptable_map_lock;
static struct eptable_map *eptable_map_head = NULL;

static vmem_t *vmm_alloc_arena = NULL;

static void *
vmm_arena_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	return (segkmem_xalloc(vmp, NULL, size, vmflag, 0,
	    segkmem_page_create, &kvps[KV_VVP]));
}

static void
vmm_arena_free(vmem_t *vmp, void *inaddr, size_t size)
{
	segkmem_xfree(vmp, inaddr, size, &kvps[KV_VVP], NULL);
}

void
vmm_arena_init(void)
{
	vmm_alloc_arena = vmem_create("vmm_alloc_arena", NULL, 0, 1024 * 1024,
	    vmm_arena_alloc, vmm_arena_free, kvmm_arena, 0, VM_SLEEP);

	ASSERT(vmm_alloc_arena != NULL);
}

void
vmm_arena_fini(void)
{
	VERIFY(vmem_size(vmm_alloc_arena, VMEM_ALLOC) == 0);
	vmem_destroy(vmm_alloc_arena);
	vmm_alloc_arena = NULL;
}

struct vmspace *
vmspace_alloc(vm_offset_t start, vm_offset_t end, pmap_pinit_t pinit)
{
	struct vmspace *vms;
	const uintptr_t size = end + 1;

	/*
	 * This whole mess is built on the assumption that a 64-bit address
	 * space is available to work with for the various pagetable tricks.
	 */
	VERIFY(ttoproc(curthread)->p_model == DATAMODEL_LP64);
	VERIFY(start == 0 && size > 0 && (size & PAGEOFFSET) == 0 &&
	    size <= (uintptr_t)USERLIMIT);

	vms = kmem_zalloc(sizeof (*vms), KM_SLEEP);
	vms->vms_size = size;
	list_create(&vms->vms_maplist, sizeof (vmspace_mapping_t),
	    offsetof(vmspace_mapping_t, vmsm_node));

	if (pinit(&vms->vms_pmap) == 0) {
		kmem_free(vms, sizeof (*vms));
		return (NULL);
	}

	return (vms);
}

void
vmspace_free(struct vmspace *vms)
{
	VERIFY(list_is_empty(&vms->vms_maplist));

	pmap_free(&vms->vms_pmap);
	kmem_free(vms, sizeof (*vms));
}

pmap_t
vmspace_pmap(struct vmspace *vms)
{
	return (&vms->vms_pmap);
}

long
vmspace_resident_count(struct vmspace *vms)
{
	/* XXXJOY: finish */
	return (0);
}

void *
vmspace_find_kva(struct vmspace *vms, uintptr_t addr, size_t size)
{
	vmspace_mapping_t *vmsm;
	void *result = NULL;

	mutex_enter(&vms->vms_lock);
	vmsm = vm_mapping_find(vms, addr, size);
	if (vmsm != NULL) {
		struct vm_object *vmo = vmsm->vmsm_object;

		switch (vmo->vmo_type) {
		case OBJT_DEFAULT:
			result = (void *)((uintptr_t)vmo->vmo_data +
			    VMSM_OFFSET(vmsm, addr));
			break;
		default:
			break;
		}
	}
	mutex_exit(&vms->vms_lock);

	return (result);
}

static int
vmspace_pmap_wire(struct vmspace *vms, uintptr_t addr, pfn_t pfn, uint_t lvl,
    uint_t prot, vm_memattr_t attr)
{
	enum pmap_type type = vms->vms_pmap.pm_type;

	ASSERT(MUTEX_HELD(&vms->vms_lock));

	switch (type) {
	case PT_EPT: {
		eptable_map_t *map = (eptable_map_t *)vms->vms_pmap.pm_map;

		(void) eptable_mapin(map, addr, pfn, lvl, prot, attr);

		vms->vms_pmap.pm_eptgen++;
		return (0);
	}
	case PT_RVI:
		/* RVI support not yet implemented */
	default:
		panic("unsupported pmap type: %x", type);
		/* NOTREACHED */
		break;
	}
	return (0);
}

static int
vmspace_pmap_iswired(struct vmspace *vms, uintptr_t addr, uint_t *prot)
{
	enum pmap_type type = vms->vms_pmap.pm_type;

	ASSERT(MUTEX_HELD(&vms->vms_lock));

	switch (type) {
	case PT_EPT: {
		eptable_map_t *map = (eptable_map_t *)vms->vms_pmap.pm_map;
		pfn_t pfn;

		return (eptable_find(map, addr, &pfn, prot));
	}
	case PT_RVI:
		/* RVI support not yet implemented */
	default:
		panic("unsupported pmap type: %x", type);
		/* NOTREACHED */
		break;
	}
	return (-1);
}

static int
vmspace_pmap_unmap(struct vmspace *vms, uintptr_t addr, size_t size)
{
	enum pmap_type type = vms->vms_pmap.pm_type;

	ASSERT(MUTEX_HELD(&vms->vms_lock));

	switch (type) {
	case PT_EPT: {
		eptable_map_t *map = (eptable_map_t *)vms->vms_pmap.pm_map;
		uintptr_t maddr = (uintptr_t)addr;
		const ulong_t npages = btop(size);
		ulong_t idx;

		/* XXXJOY: punt on large pages for now */
		for (idx = 0; idx < npages; idx++, maddr += PAGESIZE) {
			eptable_mapout(map, maddr);
		}
		vms->vms_pmap.pm_eptgen++;
		return (0);
	}
		break;
	case PT_RVI:
		/* RVI support not yet implemented */
	default:
		panic("unsupported pmap type: %x", type);
		/* NOTREACHED */
		break;
	}
	return (0);
}

static void
pmap_free(pmap_t pmap)
{
	switch (pmap->pm_type) {
	case PT_EPT: {
		eptable_map_t *map = (eptable_map_t *)pmap->pm_map;

		pmap->pm_pml4 = NULL;
		pmap->pm_map = NULL;

		eptable_fini(map);
		kmem_free(map, sizeof (*map));
		return;
	}
	case PT_RVI:
		/* RVI support not yet implemented */
	default:
		panic("unsupported pmap type: %x", pmap->pm_type);
		/* NOTREACHED */
		break;
	}
}

int
pmap_pinit_type(pmap_t pmap, enum pmap_type type, int flags)
{
	/* For use in vmm only */
	pmap->pm_type = type;
	switch (type) {
	case PT_EPT: {
		eptable_map_t *map;

		map = kmem_zalloc(sizeof (*map), KM_SLEEP);
		eptable_init(map);

		pmap->pm_map = map;
		pmap->pm_pml4 = map->em_root->ept_kva;
		return (1);
	}
	case PT_RVI:
		/* RVI support not yet implemented */
		return (0);
	default:
		panic("unsupported pmap type: %x", type);
		/* NOTREACHED */
		break;
	}

	/* XXXJOY: finish */
	return (1);
}

long
pmap_wired_count(pmap_t pmap)
{
	enum pmap_type type = pmap->pm_type;
	long val = 0L;

	switch (type) {
	case PT_EPT:
		val = ((eptable_map_t *)pmap->pm_map)->em_wired;
		break;
	case PT_RVI:
		/* RVI support not yet implemented */
	default:
		panic("unsupported pmap type: %x", type);
		/* NOTREACHED */
		break;
	}
	return (val);
}

int
pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype)
{
	/* Allow the fallback to vm_fault to handle this */
	return (-1);
}


static eptable_t *
eptable_alloc(void)
{
	eptable_t *ept;
	caddr_t page;

	ept = kmem_zalloc(sizeof (*ept), KM_SLEEP);
	page = kmem_zalloc(PAGESIZE, KM_SLEEP);
	ept->ept_kva = page;
	ept->ept_pfn = hat_getpfnum(kas.a_hat, page);

	return (ept);
}

static void
eptable_free(eptable_t *ept)
{
	void *page = ept->ept_kva;

	ASSERT(ept->ept_pfn != PFN_INVALID);
	ASSERT(ept->ept_kva != NULL);

	ept->ept_pfn = PFN_INVALID;
	ept->ept_kva = NULL;

	kmem_free(page, PAGESIZE);
	kmem_free(ept, sizeof (*ept));
}

static void
eptable_init(eptable_map_t *map)
{
	eptable_t *root;

	VERIFY0(mmu.hash_cnt & (mmu.hash_cnt - 1));

	map->em_table_cnt = mmu.hash_cnt;
	map->em_hash = kmem_zalloc(sizeof (eptable_t *) * map->em_table_cnt,
	    KM_SLEEP);

	root = eptable_alloc();
	root->ept_level = mmu.max_level;
	map->em_root = root;

	/* Insert into global tracking list of eptable maps */
	mutex_enter(&eptable_map_lock);
	map->em_next = eptable_map_head;
	map->em_prev = NULL;
	if (eptable_map_head != NULL) {
		eptable_map_head->em_prev = map;
	}
	eptable_map_head = map;
	mutex_exit(&eptable_map_lock);
}

static void
eptable_fini(eptable_map_t *map)
{
	const uint_t cnt = map->em_table_cnt;

	/* Remove from global tracking list of eptable maps */
	mutex_enter(&eptable_map_lock);
	if (map->em_next != NULL) {
		map->em_next->em_prev = map->em_prev;
	}
	if (map->em_prev != NULL) {
		map->em_prev->em_next = map->em_next;
	} else {
		eptable_map_head = map->em_next;
	}
	mutex_exit(&eptable_map_lock);

	mutex_enter(&map->em_lock);
	/* XXJOY: Should we expect to need this clean-up? */
	for (uint_t i = 0; i < cnt; i++) {
		eptable_t *ept = map->em_hash[i];

		while (ept != NULL) {
			eptable_t *next = ept->ept_next;

			eptable_hash_remove(map, ept);
			eptable_free(ept);
			ept = next;
		}
	}

	kmem_free(map->em_hash, sizeof (eptable_t *) * cnt);
	eptable_free(map->em_root);

	mutex_exit(&map->em_lock);
	mutex_destroy(&map->em_lock);
}

static eptable_t *
eptable_hash_lookup(eptable_map_t *map, uintptr_t va, level_t lvl)
{
	const uint_t hash = EPTABLE_HASH(va, lvl, map->em_table_cnt);
	eptable_t *ept;

	ASSERT(MUTEX_HELD(&map->em_lock));

	for (ept = map->em_hash[hash]; ept != NULL; ept = ept->ept_next) {
		if (ept->ept_vaddr == va && ept->ept_level == lvl)
			break;
	}
	return (ept);
}

static void
eptable_hash_insert(eptable_map_t *map, eptable_t *ept)
{
	const uintptr_t va = ept->ept_vaddr;
	const uint_t lvl = ept->ept_level;
	const uint_t hash = EPTABLE_HASH(va, lvl, map->em_table_cnt);

	ASSERT(MUTEX_HELD(&map->em_lock));
	ASSERT(eptable_hash_lookup(map, va, lvl) == NULL);

	ept->ept_prev = NULL;
	if (map->em_hash[hash] == NULL) {
		ept->ept_next = NULL;
	} else {
		eptable_t *chain = map->em_hash[hash];

		ept->ept_next = chain;
		chain->ept_prev = ept;
	}
	map->em_hash[hash] = ept;
}

static void
eptable_hash_remove(eptable_map_t *map, eptable_t *ept)
{
	const uintptr_t va = ept->ept_vaddr;
	const uint_t lvl = ept->ept_level;
	const uint_t hash = EPTABLE_HASH(va, lvl, map->em_table_cnt);

	ASSERT(MUTEX_HELD(&map->em_lock));

	if (ept->ept_prev == NULL) {
		ASSERT(map->em_hash[hash] == ept);

		map->em_hash[hash] = ept->ept_next;
	} else {
		ept->ept_prev->ept_next = ept->ept_next;
	}
	if (ept->ept_next != NULL) {
		ept->ept_next->ept_prev = ept->ept_prev;
	}
	ept->ept_next = NULL;
	ept->ept_prev = NULL;
}

static eptable_t *
eptable_walk(eptable_map_t *map, uintptr_t va, level_t tgtlvl, uint_t *idxp,
    boolean_t do_create)
{
	eptable_t *ept = map->em_root;
	level_t lvl = ept->ept_level;
	uint_t idx = UINT_MAX;

	ASSERT(MUTEX_HELD(&map->em_lock));

	while (lvl >= tgtlvl) {
		x86pte_t *ptes, entry;
		const uintptr_t masked_va = va & LEVEL_MASK((uint_t)lvl);
		eptable_t *newept = NULL;

		idx = EPTABLE_VA2IDX(ept, va);
		if (lvl == tgtlvl || lvl == 0) {
			break;
		}

		ptes = (x86pte_t *)ept->ept_kva;
		entry = ptes[idx];
		if (EPT_IS_ABSENT(entry)) {
			if (!do_create) {
				break;
			}

			newept = eptable_alloc();
			newept->ept_level = lvl - 1;
			newept->ept_vaddr = masked_va;
			newept->ept_parent = ept;

			eptable_hash_insert(map, newept);
			entry = EPT_PTE_ASSIGN_TABLE(newept->ept_pfn);
			ptes[idx] = entry;
			ept->ept_valid_cnt++;
		} else if (!EPT_MAPS_PAGE(lvl, entry)) {
			/* Do lookup in next level of page table */
			newept = eptable_hash_lookup(map, masked_va, lvl - 1);

			VERIFY(newept);
			VERIFY3P(pfn_to_pa(newept->ept_pfn), ==,
			    (entry & EPT_PADDR));
		} else {
			/*
			 * There is a (large) page mapped here.  Since support
			 * for non-PAGESIZE pages is not yet present, this is a
			 * surprise.
			 */
			panic("unexpected large page in pte %p", &ptes[idx]);
		}
		ept = newept;
		lvl--;
	}

	VERIFY(lvl >= 0 && idx != UINT_MAX);
	*idxp = idx;
	return (ept);
}

static pfn_t
eptable_mapin(eptable_map_t *map, uintptr_t va, pfn_t pfn, uint_t lvl,
    uint_t prot, vm_memattr_t attr)
{
	uint_t idx;
	eptable_t *ept;
	x86pte_t *ptes, entry;
	const size_t pgsize = (size_t)LEVEL_SIZE(lvl);
	pfn_t oldpfn = PFN_INVALID;

	CTASSERT(EPT_R == PROT_READ);
	CTASSERT(EPT_W == PROT_WRITE);
	CTASSERT(EPT_X == PROT_EXEC);
	ASSERT((prot & EPT_RWX) != 0 && (prot & ~EPT_RWX) == 0);

	/* XXXJOY: punt on large pages for now */
	VERIFY(lvl == 0);

	mutex_enter(&map->em_lock);
	ept = eptable_walk(map, va, (level_t)lvl, &idx, B_TRUE);
	ptes = (x86pte_t *)ept->ept_kva;
	entry = ptes[idx];

	if (!EPT_IS_ABSENT(entry)) {
		if (!EPT_MAPS_PAGE(lvl, entry)) {
			panic("unexpected PT link %lx in %p[%d]",
			    entry, ept, idx);
		}

		/*
		 * XXXJOY: Just clean the entry for now. Assume(!) that
		 * invalidation is going to occur anyways.
		 */
		oldpfn = EPT_PTE_PFN(ptes[idx]);
		ept->ept_valid_cnt--;
		ptes[idx] = (x86pte_t)0;
		map->em_wired -= (pgsize >> PAGESHIFT);
	}

	entry = EPT_PTE_ASSIGN_PAGE(lvl, pfn, prot, attr);
	ptes[idx] = entry;
	ept->ept_valid_cnt++;
	map->em_wired += (pgsize >> PAGESHIFT);
	mutex_exit(&map->em_lock);

	return (oldpfn);
}

static void
eptable_mapout(eptable_map_t *map, uintptr_t va)
{
	eptable_t *ept;
	uint_t idx;
	x86pte_t *ptes, entry;

	mutex_enter(&map->em_lock);
	/* Find the lowest level entry at this VA */
	ept = eptable_walk(map, va, -1, &idx, B_FALSE);

	ptes = (x86pte_t *)ept->ept_kva;
	entry = ptes[idx];

	if (EPT_IS_ABSENT(entry)) {
		/*
		 * There is nothing here to free up.  If this was a sparsely
		 * wired mapping, the absence is no concern.
		 */
		mutex_exit(&map->em_lock);
		return;
	} else {
		pfn_t oldpfn;
		const size_t pagesize = LEVEL_SIZE((uint_t)ept->ept_level);

		if (!EPT_MAPS_PAGE(ept->ept_level, entry)) {
			panic("unexpected PT link %lx in %p[%d]",
			    entry, ept, idx);
		}

		/*
		 * XXXJOY: Just clean the entry for now. Assume(!) that
		 * invalidation is going to occur anyways.
		 */
		oldpfn = EPT_PTE_PFN(ptes[idx]);
		ept->ept_valid_cnt--;
		ptes[idx] = (x86pte_t)0;
		map->em_wired -= (pagesize >> PAGESHIFT);
	}

	while (ept->ept_valid_cnt == 0 && ept->ept_parent != NULL) {
		eptable_t *next = ept->ept_parent;

		idx = EPTABLE_VA2IDX(next, va);
		ptes = (x86pte_t *)next->ept_kva;

		entry = ptes[idx];
		ASSERT(!EPT_MAPS_PAGE(next->ept_level, entry));
		ASSERT(EPT_PTE_PFN(entry) == ept->ept_pfn);

		ptes[idx] = (x86pte_t)0;
		next->ept_valid_cnt--;
		eptable_hash_remove(map, ept);
		ept->ept_parent = NULL;
		eptable_free(ept);

		ept = next;
	}
	mutex_exit(&map->em_lock);
}

static int
eptable_find(eptable_map_t *map, uintptr_t va, pfn_t *pfn, uint_t *prot)
{
	eptable_t *ept;
	uint_t idx;
	x86pte_t *ptes, entry;
	int err = -1;

	mutex_enter(&map->em_lock);
	/* Find the lowest level entry at this VA */
	ept = eptable_walk(map, va, -1, &idx, B_FALSE);

	/* XXXJOY: Until large pages are supported, this check is easy */
	if (ept->ept_level != 0) {
		mutex_exit(&map->em_lock);
		return (-1);
	}

	ptes = (x86pte_t *)ept->ept_kva;
	entry = ptes[idx];

	if (!EPT_IS_ABSENT(entry)) {
		if (!EPT_MAPS_PAGE(ept->ept_level, entry)) {
			panic("unexpected PT link %lx in %p[%d]",
			    entry, ept, idx);
		}

		*pfn = EPT_PTE_PFN(entry);
		*prot = EPT_PTE_PROT(entry);
		err = 0;
	}

	mutex_exit(&map->em_lock);
	return (err);
}

struct sglist_ent {
	vm_paddr_t	sge_pa;
	size_t		sge_len;
};
struct sglist {
	kmutex_t		sg_lock;
	uint_t			sg_refcnt;
	uint_t			sg_len;
	uint_t			sg_next;
	struct sglist_ent	sg_entries[];
};

#define	SG_SIZE(cnt)	(sizeof (struct sglist) + \
	(sizeof (struct sglist_ent) * (cnt)))

struct sglist *
sglist_alloc(int nseg, int flags)
{
	const size_t sz = SG_SIZE(nseg);
	const int flag = (flags & M_WAITOK) ? KM_SLEEP : KM_NOSLEEP;
	struct sglist *sg;

	ASSERT(nseg > 0);

	sg = kmem_zalloc(sz, flag);
	if (sg != NULL) {
		sg->sg_len = nseg;
		sg->sg_refcnt = 1;
	}
	return (sg);
}

void
sglist_free(struct sglist *sg)
{
	size_t sz;

	mutex_enter(&sg->sg_lock);
	if (sg->sg_refcnt > 1) {
		sg->sg_refcnt--;
		mutex_exit(&sg->sg_lock);
		return;
	}

	VERIFY(sg->sg_refcnt == 1);
	sg->sg_refcnt = 0;
	sz = SG_SIZE(sg->sg_len);
	mutex_exit(&sg->sg_lock);
	kmem_free(sg, sz);
}

int
sglist_append_phys(struct sglist *sg, vm_paddr_t pa, size_t len)
{
	uint_t idx;
	struct sglist_ent *ent;

	/* Restrict to page-aligned entries */
	if ((pa & PAGEOFFSET) != 0 || (len & PAGEOFFSET) != 0 || len == 0) {
		return (EINVAL);
	}

	mutex_enter(&sg->sg_lock);
	idx = sg->sg_next;
	if (idx >= sg->sg_len) {
		mutex_exit(&sg->sg_lock);
		return (ENOSPC);
	}

	ent = &sg->sg_entries[idx];
	ASSERT(ent->sge_pa == 0 && ent->sge_len == 0);
	ent->sge_pa = pa;
	ent->sge_len = len;
	sg->sg_next++;

	mutex_exit(&sg->sg_lock);
	return (0);
}


static pfn_t
vm_object_pager_none(vm_object_t vmo, uintptr_t off, pfn_t *lpfn, uint_t *lvl)
{
	panic("bad vm_object pager");
	/* NOTREACHED */
	return (PFN_INVALID);
}

static pfn_t
vm_object_pager_heap(vm_object_t vmo, uintptr_t off, pfn_t *lpfn, uint_t *lvl)
{
	const uintptr_t kaddr = ALIGN2PAGE((uintptr_t)vmo->vmo_data + off);
	uint_t idx, level;
	htable_t *ht;
	x86pte_t pte;
	pfn_t top_pfn, pfn;

	ASSERT(vmo->vmo_type == OBJT_DEFAULT);
	ASSERT(off < vmo->vmo_size);

	ht = htable_getpage(kas.a_hat, kaddr, &idx);
	if (ht == NULL) {
		return (PFN_INVALID);
	}
	pte = x86pte_get(ht, idx);
	if (!PTE_ISPAGE(pte, ht->ht_level)) {
		htable_release(ht);
		return (PFN_INVALID);
	}

	pfn = top_pfn = PTE2PFN(pte, ht->ht_level);
	level = ht->ht_level;
	if (ht->ht_level > 0) {
		pfn += mmu_btop(kaddr & LEVEL_OFFSET((uint_t)ht->ht_level));
	}
	htable_release(ht);

	if (lpfn != NULL) {
		*lpfn = top_pfn;
	}
	if (lvl != NULL) {
		*lvl = level;
	}
	return (pfn);
}

static pfn_t
vm_object_pager_sg(vm_object_t vmo, uintptr_t off, pfn_t *lpfn, uint_t *lvl)
{
	const uintptr_t aoff = ALIGN2PAGE(off);
	uint_t level = 0;
	uintptr_t pos = 0;
	struct sglist *sg;
	struct sglist_ent *ent;
	pfn_t pfn = PFN_INVALID;

	ASSERT(vmo->vmo_type == OBJT_SG);
	ASSERT(off < vmo->vmo_size);

	sg = vmo->vmo_data;
	if (sg == NULL) {
		return (PFN_INVALID);
	}

	ent = &sg->sg_entries[0];
	for (uint_t i = 0; i < sg->sg_next; i++, ent++) {
		if (aoff >= pos && aoff < (pos + ent->sge_len)) {
			/* XXXJOY: Punt on large pages for now */
			level = 0;
			pfn = mmu_btop(ent->sge_pa + (aoff - pos));
			break;
		}
		pos += ent->sge_len;
	}

	if (lpfn != 0) {
		*lpfn = pfn;
	}
	if (lvl != 0) {
		*lvl = level;
	}
	return (pfn);
}

vm_object_t
vm_object_allocate(objtype_t type, vm_pindex_t psize)
{
	vm_object_t vmo;
	const size_t size = ptob((size_t)psize);

	vmo = kmem_alloc(sizeof (*vmo), KM_SLEEP);
	mutex_init(&vmo->vmo_lock, NULL, MUTEX_DEFAULT, NULL);

	/* For now, these are to stay fixed after allocation */
	vmo->vmo_type = type;
	vmo->vmo_size = size;
	vmo->vmo_attr = VM_MEMATTR_DEFAULT;

	switch (type) {
	case OBJT_DEFAULT: {
		/* XXXJOY: opt-in to larger pages? */
		vmo->vmo_data = vmem_alloc(vmm_alloc_arena, size, KM_NOSLEEP);
		if (vmo->vmo_data == NULL) {
			mutex_destroy(&vmo->vmo_lock);
			kmem_free(vmo, sizeof (*vmo));
			return (NULL);
		}
		/* XXXJOY: Better zeroing approach? */
		bzero(vmo->vmo_data, size);
		vmo->vmo_pager = vm_object_pager_heap;
	}
		break;
	case OBJT_SG:
		vmo->vmo_data = NULL;
		vmo->vmo_pager = vm_object_pager_sg;
		break;
	default:
		panic("Unsupported vm_object type");
		break;
	}

	vmo->vmo_refcnt = 1;
	return (vmo);
}

vm_object_t
vm_pager_allocate(objtype_t type, void *handle, vm_ooffset_t size,
    vm_prot_t prot, vm_ooffset_t off, void *cred)
{
	struct vm_object *vmo;
	struct sglist *sg = (struct sglist *)handle;

	/* XXXJOY: be very restrictive for now */
	VERIFY(type == OBJT_SG);
	VERIFY(off == 0);

	vmo = vm_object_allocate(type, size);
	vmo->vmo_data = sg;

	mutex_enter(&sg->sg_lock);
	VERIFY(sg->sg_refcnt++ >= 1);
	mutex_exit(&sg->sg_lock);

	return (vmo);
}

void
vm_object_deallocate(vm_object_t vmo)
{
	ASSERT(vmo != NULL);

	mutex_enter(&vmo->vmo_lock);
	VERIFY(vmo->vmo_refcnt);
	vmo->vmo_refcnt--;
	if (vmo->vmo_refcnt != 0) {
		mutex_exit(&vmo->vmo_lock);
		return;
	}

	switch (vmo->vmo_type) {
	case OBJT_DEFAULT:
		vmem_free(vmm_alloc_arena, vmo->vmo_data, vmo->vmo_size);
		break;
	case OBJT_SG:
		sglist_free((struct sglist *)vmo->vmo_data);
		break;
	default:
		panic("Unsupported vm_object type");
		break;
	}

	vmo->vmo_pager = vm_object_pager_none;
	vmo->vmo_data = NULL;
	vmo->vmo_size = 0;
	mutex_exit(&vmo->vmo_lock);
	mutex_destroy(&vmo->vmo_lock);
	kmem_free(vmo, sizeof (*vmo));
}

int
vm_object_set_memattr(vm_object_t vmo, vm_memattr_t attr)
{
	ASSERT(MUTEX_HELD(&vmo->vmo_lock));

	switch (attr) {
	case VM_MEMATTR_UNCACHEABLE:
	case VM_MEMATTR_WRITE_BACK:
		vmo->vmo_attr = attr;
		return (0);
	default:
		break;
	}
	return (EINVAL);
}

void
vm_object_reference(vm_object_t vmo)
{
	ASSERT(vmo != NULL);

	mutex_enter(&vmo->vmo_lock);
	vmo->vmo_refcnt++;
	mutex_exit(&vmo->vmo_lock);
}

static vmspace_mapping_t *
vm_mapping_find(struct vmspace *vms, uintptr_t addr, size_t size)
{
	vmspace_mapping_t *vmsm;
	list_t *ml = &vms->vms_maplist;
	const uintptr_t range_end = addr + size;

	ASSERT(MUTEX_HELD(&vms->vms_lock));
	ASSERT(addr <= range_end);

	if (addr >= vms->vms_size) {
		return (NULL);
	}
	for (vmsm = list_head(ml); vmsm != NULL; vmsm = list_next(ml, vmsm)) {
		const uintptr_t seg_end = vmsm->vmsm_addr + vmsm->vmsm_len;

		if (addr >= vmsm->vmsm_addr && addr < seg_end) {
			if (range_end <= seg_end) {
				return (vmsm);
			} else {
				return (NULL);
			}
		}
	}
	return (NULL);
}

static boolean_t
vm_mapping_gap(struct vmspace *vms, uintptr_t addr, size_t size)
{
	vmspace_mapping_t *vmsm;
	list_t *ml = &vms->vms_maplist;
	const uintptr_t range_end = addr + size;

	ASSERT(MUTEX_HELD(&vms->vms_lock));

	for (vmsm = list_head(ml); vmsm != NULL; vmsm = list_next(ml, vmsm)) {
		const uintptr_t seg_end = vmsm->vmsm_addr + vmsm->vmsm_len;

		if ((vmsm->vmsm_addr >= addr && vmsm->vmsm_addr < range_end) ||
		    (seg_end > addr && seg_end < range_end)) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

static void
vm_mapping_remove(struct vmspace *vms, vmspace_mapping_t *vmsm)
{
	list_t *ml = &vms->vms_maplist;

	ASSERT(MUTEX_HELD(&vms->vms_lock));

	list_remove(ml, vmsm);
	vm_object_deallocate(vmsm->vmsm_object);
	kmem_free(vmsm, sizeof (*vmsm));
}

int
vm_fault(vm_map_t map, vm_offset_t off, vm_prot_t type, int flag)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	const uintptr_t addr = off;
	vmspace_mapping_t *vmsm;
	struct vm_object *vmo;
	uint_t prot, map_lvl;
	pfn_t pfn;
	uintptr_t map_addr;

	mutex_enter(&vms->vms_lock);
	if (vmspace_pmap_iswired(vms, addr, &prot) == 0) {
		int err = 0;

		/*
		 * It is possible that multiple will vCPUs race to fault-in a
		 * given address.  In such cases, the race loser(s) will
		 * encounter the already-mapped page, needing to do nothing
		 * more than consider it a success.
		 *
		 * If the fault exceeds protection, it is an obvious error.
		 */
		if ((prot & type) != type) {
			err = FC_PROT;
		}

		mutex_exit(&vms->vms_lock);
		return (err);
	}

	/* Try to wire up the address */
	if ((vmsm = vm_mapping_find(vms, addr, 0)) == NULL) {
		mutex_exit(&vms->vms_lock);
		return (FC_NOMAP);
	}
	vmo = vmsm->vmsm_object;
	prot = vmsm->vmsm_prot;

	/* XXXJOY: punt on large pages for now */
	pfn = vmo->vmo_pager(vmo, VMSM_OFFSET(vmsm, addr), NULL, NULL);
	map_lvl = 0;
	map_addr = P2ALIGN((uintptr_t)addr, LEVEL_SIZE(map_lvl));
	VERIFY(pfn != PFN_INVALID);

	/*
	 * If pmap failure is to be handled, the previously
	 * acquired page locks would need to be released.
	 */
	VERIFY0(vmspace_pmap_wire(vms, map_addr, pfn, map_lvl, prot,
	    vmo->vmo_attr));

	mutex_exit(&vms->vms_lock);
	return (0);
}

int
vm_fault_quick_hold_pages(vm_map_t map, vm_offset_t addr, vm_size_t len,
    vm_prot_t prot, vm_page_t *ma, int max_count)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	const uintptr_t vaddr = addr;
	vmspace_mapping_t *vmsm;
	struct vm_object *vmo;
	vm_page_t vmp;

	ASSERT0(addr & PAGEOFFSET);
	ASSERT(len == PAGESIZE);
	ASSERT(max_count == 1);

	mutex_enter(&vms->vms_lock);
	if ((vmsm = vm_mapping_find(vms, vaddr, PAGESIZE)) == NULL ||
	    (prot & ~vmsm->vmsm_prot) != 0) {
		mutex_exit(&vms->vms_lock);
		return (-1);
	}

	vmp = kmem_zalloc(sizeof (struct vm_page), KM_SLEEP);

	vmo = vmsm->vmsm_object;
	vm_object_reference(vmo);
	vmp->vmp_obj_held = vmo;
	vmp->vmp_pfn = vmo->vmo_pager(vmo, VMSM_OFFSET(vmsm, vaddr), NULL,
	    NULL);

	mutex_exit(&vms->vms_lock);
	*ma = vmp;
	return (1);
}

/*
 * Find a suitable location for a mapping (and install it).
 */
int
vm_map_find(vm_map_t map, vm_object_t vmo, vm_ooffset_t off, vm_offset_t *addr,
    vm_size_t len, vm_offset_t max_addr, int find_flags, vm_prot_t prot,
    vm_prot_t prot_max, int cow)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	const size_t size = (size_t)len;
	const uintptr_t uoff = (uintptr_t)off;
	uintptr_t base = *addr;
	vmspace_mapping_t *vmsm;
	int res = 0;

	/* For use in vmm only */
	VERIFY(find_flags == VMFS_NO_SPACE); /* essentially MAP_FIXED */
	VERIFY(max_addr == 0);

	if (size == 0 || off < 0 ||
	    uoff >= (uoff + size) || vmo->vmo_size < (uoff + size)) {
		return (EINVAL);
	}

	if (*addr >= vms->vms_size) {
		return (ENOMEM);
	}

	vmsm = kmem_alloc(sizeof (*vmsm), KM_SLEEP);

	mutex_enter(&vms->vms_lock);
	if (!vm_mapping_gap(vms, base, size)) {
		res = ENOMEM;
		goto out;
	}

	if (res == 0) {
		vmsm->vmsm_object = vmo;
		vmsm->vmsm_addr = base;
		vmsm->vmsm_len = len;
		vmsm->vmsm_offset = (off_t)uoff;
		vmsm->vmsm_prot = prot;
		list_insert_tail(&vms->vms_maplist, vmsm);

		/* Communicate out the chosen address. */
		*addr = (vm_offset_t)base;
	}
out:
	mutex_exit(&vms->vms_lock);
	if (res != 0) {
		kmem_free(vmsm, sizeof (*vmsm));
	}
	return (res);
}

int
vm_map_remove(vm_map_t map, vm_offset_t start, vm_offset_t end)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	const uintptr_t addr = start;
	const size_t size = (size_t)(end - start);
	vmspace_mapping_t *vmsm;
	objtype_t type;

	ASSERT(start < end);

	mutex_enter(&vms->vms_lock);
	/* expect to match existing mapping exactly */
	if ((vmsm = vm_mapping_find(vms, addr, size)) == NULL ||
	    vmsm->vmsm_addr != addr || vmsm->vmsm_len != size) {
		mutex_exit(&vms->vms_lock);
		return (ENOENT);
	}

	type = vmsm->vmsm_object->vmo_type;
	switch (type) {
	case OBJT_DEFAULT:
	case OBJT_SG:
		VERIFY0(vmspace_pmap_unmap(vms, addr, size));
		break;
	default:
		panic("unsupported object type: %x", type);
		/* NOTREACHED */
		break;
	}

	vm_mapping_remove(vms, vmsm);
	mutex_exit(&vms->vms_lock);
	return (0);
}

int
vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	const uintptr_t addr = start;
	const size_t size = end - start;
	vmspace_mapping_t *vmsm;
	struct vm_object *vmo;
	uint_t prot;

	mutex_enter(&vms->vms_lock);

	/* For the time being, only exact-match mappings are expected */
	if ((vmsm = vm_mapping_find(vms, addr, size)) == NULL) {
		mutex_exit(&vms->vms_lock);
		return (FC_NOMAP);
	}
	vmo = vmsm->vmsm_object;
	prot = vmsm->vmsm_prot;

	for (uintptr_t pos = addr; pos < end; ) {
		pfn_t pfn;
		uintptr_t pg_size, map_addr;
		uint_t map_lvl = 0;

		/* XXXJOY: punt on large pages for now */
		pfn = vmo->vmo_pager(vmo, VMSM_OFFSET(vmsm, pos), NULL, NULL);
		pg_size = LEVEL_SIZE(map_lvl);
		map_addr = P2ALIGN(pos, pg_size);
		VERIFY(pfn != PFN_INVALID);

		VERIFY0(vmspace_pmap_wire(vms, map_addr, pfn, map_lvl, prot,
		    vmo->vmo_attr));
		pos += pg_size;
	}

	mutex_exit(&vms->vms_lock);

	return (0);
}

/* Provided custom for bhyve 'devmem' segment mapping */
int
vm_segmap_obj(struct vmspace *vms, vm_object_t vmo, struct as *as,
    caddr_t *addrp, uint_t prot, uint_t maxprot, uint_t flags)
{
	const size_t size = vmo->vmo_size;
	int err;

	if (vmo->vmo_type != OBJT_DEFAULT) {
		/* Only support default objects for now */
		return (ENOTSUP);
	}

	as_rangelock(as);

	err = choose_addr(as, addrp, size, 0, ADDR_VACALIGN, flags);
	if (err == 0) {
		segvmm_crargs_t svma;

		svma.kaddr = vmo->vmo_data;
		svma.prot = prot;
		svma.cookie = vmo;
		svma.hold = (segvmm_holdfn_t)vm_object_reference;
		svma.rele = (segvmm_relefn_t)vm_object_deallocate;

		err = as_map(as, *addrp, size, segvmm_create, &svma);
	}

	as_rangeunlock(as);
	return (err);
}

int
vm_segmap_space(struct vmspace *vms, off_t off, struct as *as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags)
{
	const uintptr_t addr = (uintptr_t)off;
	const size_t size = (uintptr_t)len;
	vmspace_mapping_t *vmsm;
	vm_object_t vmo;
	int err;

	if (off < 0 || len <= 0 ||
	    (addr & PAGEOFFSET) != 0 || (size & PAGEOFFSET) != 0) {
		return (EINVAL);
	}

	mutex_enter(&vms->vms_lock);
	if ((vmsm = vm_mapping_find(vms, addr, size)) == NULL) {
		mutex_exit(&vms->vms_lock);
		return (ENXIO);
	}
	if ((prot & ~(vmsm->vmsm_prot | PROT_USER)) != 0) {
		mutex_exit(&vms->vms_lock);
		return (EACCES);
	}
	vmo = vmsm->vmsm_object;
	if (vmo->vmo_type != OBJT_DEFAULT) {
		/* Only support default objects for now */
		mutex_exit(&vms->vms_lock);
		return (ENOTSUP);
	}

	as_rangelock(as);

	err = choose_addr(as, addrp, size, off, ADDR_VACALIGN, flags);
	if (err == 0) {
		segvmm_crargs_t svma;
		const uintptr_t addroff = addr - vmsm->vmsm_addr;
		const uintptr_t mapoff = addroff + vmsm->vmsm_offset;

		VERIFY(addroff < vmsm->vmsm_len);
		VERIFY((vmsm->vmsm_len - addroff) >= size);
		VERIFY(mapoff < vmo->vmo_size);
		VERIFY((mapoff + size) <= vmo->vmo_size);

		svma.kaddr = (void *)((uintptr_t)vmo->vmo_data + mapoff);
		svma.prot = prot;
		svma.cookie = vmo;
		svma.hold = (segvmm_holdfn_t)vm_object_reference;
		svma.rele = (segvmm_relefn_t)vm_object_deallocate;

		err = as_map(as, *addrp, len, segvmm_create, &svma);
	}

	as_rangeunlock(as);
	mutex_exit(&vms->vms_lock);
	return (err);
}

void
vm_page_lock(vm_page_t vmp)
{
	ASSERT(!MUTEX_HELD(&vmp->vmp_lock));

	mutex_enter(&vmp->vmp_lock);
}

void
vm_page_unlock(vm_page_t vmp)
{
	boolean_t purge = (vmp->vmp_pfn == PFN_INVALID);

	ASSERT(MUTEX_HELD(&vmp->vmp_lock));

	mutex_exit(&vmp->vmp_lock);

	if (purge) {
		mutex_destroy(&vmp->vmp_lock);
		kmem_free(vmp, sizeof (*vmp));
	}
}

void
vm_page_unhold(vm_page_t vmp)
{
	ASSERT(MUTEX_HELD(&vmp->vmp_lock));
	VERIFY(vmp->vmp_pfn != PFN_INVALID);

	vm_object_deallocate(vmp->vmp_obj_held);
	vmp->vmp_obj_held = NULL;
	vmp->vmp_pfn = PFN_INVALID;
}

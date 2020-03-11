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

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/list.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/malloc.h>
#include <sys/x86_archext.h>
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
static vmspace_mapping_t *vm_mapping_find(struct vmspace *, uintptr_t, size_t,
    boolean_t);
static void vm_mapping_remove(struct vmspace *, vmspace_mapping_t *);

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

	/*
	 * Since vmspace_find_kva is provided so that vmm_drv consumers can do
	 * GPA2KVA translations, it is expected to be called when there is a
	 * read lock preventing vmspace alterations.  As such, it can do the
	 * lockless vm_mapping_find() lookup.
	 */
	vmsm = vm_mapping_find(vms, addr, size, B_TRUE);
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

	return (result);
}

static int
vmspace_pmap_iswired(struct vmspace *vms, uintptr_t addr, uint_t *prot)
{
	pmap_t pmap = &vms->vms_pmap;
	int rv;

	ASSERT(MUTEX_HELD(&vms->vms_lock));

	rv = pmap->pm_ops->vpo_is_wired(pmap->pm_impl, addr, prot);
	return (rv);
}

static void
pmap_free(pmap_t pmap)
{
	void *pmi = pmap->pm_impl;
	struct vmm_pt_ops *ops = pmap->pm_ops;

	pmap->pm_pml4 = NULL;
	pmap->pm_impl = NULL;
	pmap->pm_ops = NULL;

	ops->vpo_free(pmi);
}

int
pmap_pinit_type(pmap_t pmap, enum pmap_type type, int flags)
{
	/* For use in vmm only */
	pmap->pm_type = type;
	switch (type) {
	case PT_EPT: {
		struct vmm_pt_ops *ops = &ept_ops;
		void *pml4, *pmi;

		pmi = ops->vpo_init((uintptr_t *)&pml4);

		pmap->pm_ops = ops;
		pmap->pm_impl = pmi;
		pmap->pm_pml4 = pml4;
		return (1);
	}
	case PT_RVI: {
		struct vmm_pt_ops *ops = &rvi_ops;
		void *pml4, *pmi;

		pmi = ops->vpo_init((uintptr_t *)&pml4);

		pmap->pm_ops = ops;
		pmap->pm_impl = pmi;
		pmap->pm_pml4 = pml4;
		return (1);
	}
	default:
		panic("unsupported pmap type: %x", type);
		break;
	}

	return (1);
}

long
pmap_wired_count(pmap_t pmap)
{
	long val;

	val = pmap->pm_ops->vpo_wired_cnt(pmap->pm_impl);
	VERIFY3S(val, >=, 0);

	return (val);
}

int
pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype)
{
	/* Allow the fallback to vm_fault to handle this */
	return (-1);
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

static void
vm_reserve_pages(size_t npages)
{
	uint_t retries = 60;
	int rc;

	mutex_enter(&freemem_lock);
	if (availrmem < npages) {
		mutex_exit(&freemem_lock);

		/*
		 * Set needfree and wait for the ZFS ARC reap thread to free up
		 * some memory.
		 */
		page_needfree(npages);

		mutex_enter(&freemem_lock);
		while ((availrmem < npages) && retries-- > 0) {
			mutex_exit(&freemem_lock);
			rc = delay_sig(drv_usectohz(1 * MICROSEC));
			mutex_enter(&freemem_lock);

			if (rc == EINTR)
				break;
		}
		mutex_exit(&freemem_lock);

		page_needfree(-npages);
	} else {
		mutex_exit(&freemem_lock);
	}
}

void
vm_object_clear(vm_object_t vmo)
{
	ASSERT(vmo->vmo_type == OBJT_DEFAULT);

	/* XXXJOY: Better zeroing approach? */
	bzero(vmo->vmo_data, vmo->vmo_size);
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
		vm_reserve_pages(psize);

		/* XXXJOY: opt-in to larger pages? */
		vmo->vmo_data = vmem_alloc(vmm_alloc_arena, size, KM_NOSLEEP);
		if (vmo->vmo_data == NULL) {
			mutex_destroy(&vmo->vmo_lock);
			kmem_free(vmo, sizeof (*vmo));
			return (NULL);
		}
		vm_object_clear(vmo);
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

	uint_t ref = atomic_dec_uint_nv(&vmo->vmo_refcnt);
	/* underflow would be a deadly serious mistake */
	VERIFY3U(ref, !=, UINT_MAX);
	if (ref != 0) {
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
	mutex_destroy(&vmo->vmo_lock);
	kmem_free(vmo, sizeof (*vmo));
}

CTASSERT(VM_MEMATTR_UNCACHEABLE == MTRR_TYPE_UC);
CTASSERT(VM_MEMATTR_WRITE_BACK == MTRR_TYPE_WB);
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

	uint_t ref = atomic_inc_uint_nv(&vmo->vmo_refcnt);
	/* overflow would be a deadly serious mistake */
	VERIFY3U(ref, !=, 0);
}

static vmspace_mapping_t *
vm_mapping_find(struct vmspace *vms, uintptr_t addr, size_t size,
    boolean_t no_lock)
{
	vmspace_mapping_t *vmsm;
	list_t *ml = &vms->vms_maplist;
	const uintptr_t range_end = addr + size;

	ASSERT(addr <= range_end);

	if (no_lock) {
		/*
		 * This check should be superflous with the protections
		 * promised by the bhyve logic which calls into the VM shim.
		 * All the same, it is cheap to be paranoid.
		 */
		VERIFY(!vms->vms_map_changing);
	} else {
		VERIFY(MUTEX_HELD(&vms->vms_lock));
	}

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
	ASSERT(vms->vms_map_changing);

	list_remove(ml, vmsm);
	vm_object_deallocate(vmsm->vmsm_object);
	kmem_free(vmsm, sizeof (*vmsm));
}

int
vm_fault(vm_map_t map, vm_offset_t off, vm_prot_t type, int flag)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	pmap_t pmap = &vms->vms_pmap;
	void *pmi = pmap->pm_impl;
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
		 * It is possible that multiple vCPUs will race to fault-in a
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
	if ((vmsm = vm_mapping_find(vms, addr, 0, B_FALSE)) == NULL) {
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
	 * If pmap failure is to be handled, the previously acquired page locks
	 * would need to be released.
	 */
	VERIFY0(pmap->pm_ops->vpo_map(pmi, map_addr, pfn, map_lvl, prot,
	    vmo->vmo_attr));
	pmap->pm_eptgen++;

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

	/*
	 * Unlike practically all of the other logic that queries or
	 * manipulates vmspace objects, vm_fault_quick_hold_pages() does so
	 * without holding vms_lock.  This is safe because bhyve ensures that
	 * changes to the vmspace map occur only when all other threads have
	 * been excluded from running.
	 *
	 * Since this task can count on vms_maplist remaining static and does
	 * not need to modify the pmap (like vm_fault might), it can proceed
	 * without the lock.  The vm_object has independent refcount and lock
	 * protection, while the vmo_pager methods do not rely on vms_lock for
	 * safety.
	 *
	 * Performing this work without locks is critical in cases where
	 * multiple vCPUs require simultaneous instruction emulation, such as
	 * for frequent guest APIC accesses on a host that lacks hardware
	 * acceleration for that behavior.
	 */
	if ((vmsm = vm_mapping_find(vms, vaddr, PAGESIZE, B_TRUE)) == NULL ||
	    (prot & ~vmsm->vmsm_prot) != 0) {
		return (-1);
	}

	vmp = kmem_zalloc(sizeof (struct vm_page), KM_SLEEP);

	vmo = vmsm->vmsm_object;
	vm_object_reference(vmo);
	vmp->vmp_obj_held = vmo;
	vmp->vmp_pfn = vmo->vmo_pager(vmo, VMSM_OFFSET(vmsm, vaddr), NULL,
	    NULL);

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
	vms->vms_map_changing = B_TRUE;
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
	vms->vms_map_changing = B_FALSE;
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
	pmap_t pmap = &vms->vms_pmap;
	void *pmi = pmap->pm_impl;
	const uintptr_t addr = start;
	const size_t size = (size_t)(end - start);
	vmspace_mapping_t *vmsm;

	ASSERT(start < end);

	mutex_enter(&vms->vms_lock);
	vms->vms_map_changing = B_TRUE;
	/* expect to match existing mapping exactly */
	if ((vmsm = vm_mapping_find(vms, addr, size, B_FALSE)) == NULL ||
	    vmsm->vmsm_addr != addr || vmsm->vmsm_len != size) {
		vms->vms_map_changing = B_FALSE;
		mutex_exit(&vms->vms_lock);
		return (ENOENT);
	}

	(void) pmap->pm_ops->vpo_unmap(pmi, addr, end);
	pmap->pm_eptgen++;

	vm_mapping_remove(vms, vmsm);
	vms->vms_map_changing = B_FALSE;
	mutex_exit(&vms->vms_lock);
	return (0);
}

int
vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	struct vmspace *vms = VMMAP_TO_VMSPACE(map);
	pmap_t pmap = &vms->vms_pmap;
	void *pmi = pmap->pm_impl;
	const uintptr_t addr = start;
	const size_t size = end - start;
	vmspace_mapping_t *vmsm;
	struct vm_object *vmo;
	uint_t prot;

	mutex_enter(&vms->vms_lock);

	/* For the time being, only exact-match mappings are expected */
	if ((vmsm = vm_mapping_find(vms, addr, size, B_FALSE)) == NULL) {
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

		VERIFY0(pmap->pm_ops->vpo_map(pmi, map_addr, pfn, map_lvl,
		    prot, vmo->vmo_attr));
		vms->vms_pmap.pm_eptgen++;

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
	if ((vmsm = vm_mapping_find(vms, addr, size, B_FALSE)) == NULL) {
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
vm_page_unwire(vm_page_t vmp, uint8_t nqueue __unused)
{
	ASSERT(!MUTEX_HELD(&vmp->vmp_lock));
	mutex_enter(&vmp->vmp_lock);

	VERIFY(vmp->vmp_pfn != PFN_INVALID);

	vm_object_deallocate(vmp->vmp_obj_held);
	vmp->vmp_obj_held = NULL;
	vmp->vmp_pfn = PFN_INVALID;

	mutex_exit(&vmp->vmp_lock);

	mutex_destroy(&vmp->vmp_lock);
	kmem_free(vmp, sizeof (*vmp));
}

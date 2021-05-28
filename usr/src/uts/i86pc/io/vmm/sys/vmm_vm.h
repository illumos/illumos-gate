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

#ifndef	_VMM_VM_H
#define	_VMM_VM_H

#include <sys/list.h>
#include <sys/types.h>
#include <vm/hat_pte.h>
#include <machine/pmap.h>

/*
 * vm_map_wire and vm_map_unwire option flags
 */
#define	VM_MAP_WIRE_SYSTEM	0	/* wiring in a kernel map */
#define	VM_MAP_WIRE_USER	1	/* wiring in a user map */

#define	VM_MAP_WIRE_NOHOLES	0	/* region must not have holes */
#define	VM_MAP_WIRE_HOLESOK	2	/* region may have holes */

#define	VM_MAP_WIRE_WRITE	4	/* Validate writable. */

/*
 * The following "find_space" options are supported by vm_map_find().
 *
 * For VMFS_ALIGNED_SPACE, the desired alignment is specified to
 * the macro argument as log base 2 of the desired alignment.
 */
#define	VMFS_NO_SPACE		0	/* don't find; use the given range */
#define	VMFS_ANY_SPACE		1	/* find range with any alignment */
#define	VMFS_OPTIMAL_SPACE	2	/* find range with optimal alignment */
#define	VMFS_SUPER_SPACE	3	/* find superpage-aligned range */
#define	VMFS_ALIGNED_SPACE(x) ((x) << 8) /* find range with fixed alignment */

/*
 * vm_fault option flags
 */
#define	VM_FAULT_NORMAL		0	/* Nothing special */
#define	VM_FAULT_WIRE		1	/* Wire the mapped page */
#define	VM_FAULT_DIRTY		2	/* Dirty the page; use w/PROT_COPY */

/*
 * The VM_MAXUSER_ADDRESS determines the upper size limit of a vmspace.
 * This value is sized well below the host userlimit, halving the
 * available space below the VA hole to avoid Intel EPT limits and
 * leave room available in the usable VA range for other mmap tricks.
 */
#define	VM_MAXUSER_ADDRESS	0x00003ffffffffffful

/*
 * Type definitions used in the hypervisor.
 */
typedef uchar_t vm_prot_t;

/* New type declarations. */
struct vm;
struct vmspace;
struct pmap;

struct vm_object;
typedef struct vm_object *vm_object_t;

struct vmm_pt_ops;

struct vm_page;
typedef struct vm_page *vm_page_t;

enum obj_type { OBJT_DEFAULT, OBJT_SWAP, OBJT_VNODE, OBJT_DEVICE, OBJT_PHYS,
    OBJT_DEAD, OBJT_SG, OBJT_MGTDEVICE };
typedef uchar_t objtype_t;

union vm_map_object;
typedef union vm_map_object vm_map_object_t;

struct vm_map_entry;
typedef struct vm_map_entry *vm_map_entry_t;

struct vm_map;
typedef struct vm_map *vm_map_t;

pmap_t vmspace_pmap(struct vmspace *);

int vm_map_find(vm_map_t, vm_object_t, vm_ooffset_t, vm_offset_t *, vm_size_t,
    vm_offset_t, int, vm_prot_t, vm_prot_t, int);
int vm_map_remove(vm_map_t, vm_offset_t, vm_offset_t);
int vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags);

long vmspace_resident_count(struct vmspace *vmspace);

void	pmap_invalidate_cache(void);
void	pmap_get_mapping(pmap_t pmap, vm_offset_t va, uint64_t *ptr, int *num);
int	pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype);
long	pmap_wired_count(pmap_t pmap);

struct vm_map {
	struct vmspace *vmm_space;
};

struct pmap {
	void		*pm_pml4;
	cpuset_t	pm_active;
	long		pm_eptgen;

	/* Implementation private */
	enum pmap_type	pm_type;
	struct vmm_pt_ops *pm_ops;
	void		*pm_impl;
};

struct vmspace {
	struct vm_map vm_map;

	/* Implementation private */
	kmutex_t	vms_lock;
	boolean_t	vms_map_changing;
	struct pmap	vms_pmap;
	uintptr_t	vms_size;	/* fixed after creation */

	list_t		vms_maplist;
};

typedef pfn_t (*vm_pager_fn_t)(vm_object_t, uintptr_t, pfn_t *, uint_t *);

struct vm_object {
	uint_t		vmo_refcnt;	/* manipulated with atomic ops */

	/* This group of fields are fixed at creation time */
	objtype_t	vmo_type;
	size_t		vmo_size;
	vm_pager_fn_t	vmo_pager;
	void		*vmo_data;

	kmutex_t	vmo_lock;	/* protects fields below */
	vm_memattr_t	vmo_attr;
};

struct vm_page {
	kmutex_t		vmp_lock;
	pfn_t			vmp_pfn;
	struct vm_object	*vmp_obj_held;
};

/* illumos-specific functions for setup and operation */
int vm_segmap_obj(vm_object_t, off_t, size_t, struct as *, caddr_t *, uint_t,
    uint_t, uint_t);
int vm_segmap_space(struct vmspace *, off_t, struct as *, caddr_t *, off_t,
    uint_t, uint_t, uint_t);
void *vmspace_find_kva(struct vmspace *, uintptr_t, size_t);
void vmm_arena_init(void);
void vmm_arena_fini(void);

struct vmm_pt_ops {
	void * (*vpo_init)(uint64_t *);
	void (*vpo_free)(void *);
	uint64_t (*vpo_wired_cnt)(void *);
	int (*vpo_is_wired)(void *, uint64_t, uint_t *);
	int (*vpo_map)(void *, uint64_t, pfn_t, uint_t, uint_t, uint8_t);
	uint64_t (*vpo_unmap)(void *, uint64_t, uint64_t);
};

extern struct vmm_pt_ops ept_ops;
extern struct vmm_pt_ops rvi_ops;

typedef int (*pmap_pinit_t)(struct pmap *pmap);

struct vmspace *vmspace_alloc(vm_offset_t, vm_offset_t, pmap_pinit_t);
void vmspace_free(struct vmspace *);

int vm_fault(vm_map_t, vm_offset_t, vm_prot_t, int);
int vm_fault_quick_hold_pages(vm_map_t map, vm_offset_t addr, vm_size_t len,
    vm_prot_t prot, vm_page_t *ma, int max_count);
void vmm_arena_fini(void);


struct vm_object *vm_object_allocate(objtype_t, vm_pindex_t);
void vm_object_deallocate(vm_object_t);
void vm_object_reference(vm_object_t);
int vm_object_set_memattr(vm_object_t, vm_memattr_t);

#define	VM_OBJECT_WLOCK(vmo)	mutex_enter(&(vmo)->vmo_lock)
#define	VM_OBJECT_WUNLOCK(vmo)	mutex_exit(&(vmo)->vmo_lock)

#define	PQ_ACTIVE	1

void vm_page_unwire(vm_page_t, uint8_t);

#define	VM_PAGE_TO_PHYS(page)	(mmu_ptob((uintptr_t)((page)->vmp_pfn)))

vm_object_t vm_pager_allocate(objtype_t, void *, vm_ooffset_t, vm_prot_t,
    vm_ooffset_t, void *);

#endif /* _VMM_VM_H */

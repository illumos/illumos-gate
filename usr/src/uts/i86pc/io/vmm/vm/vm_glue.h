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

#ifndef	_VM_GLUE_
#define	_VM_GLUE_

#include <vm/pmap.h>
#include <vm/vm.h>
#include <sys/cpuvar.h>

struct vmspace;
struct vm_map;
struct pmap;
struct vm_object;

struct vm_map {
	struct vmspace *vmm_space;
};

struct pmap {
	void		*pm_pml4;
	cpuset_t	pm_active;
	long		pm_eptgen;

	/* Implementation private */
	enum pmap_type	pm_type;
	void		*pm_map;
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

/* Illumos-specific functions for setup and operation */
int vm_segmap_obj(struct vmspace *, vm_object_t, struct as *, caddr_t *,
    uint_t, uint_t, uint_t);
int vm_segmap_space(struct vmspace *, off_t, struct as *, caddr_t *, off_t,
    uint_t, uint_t, uint_t);
void *vmspace_find_kva(struct vmspace *, uintptr_t, size_t);
void vmm_arena_init(void);
void vmm_arena_fini(void);

#endif /* _VM_GLUE_ */

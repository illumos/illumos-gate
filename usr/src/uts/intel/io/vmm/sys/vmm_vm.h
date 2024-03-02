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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef	_VMM_VM_H
#define	_VMM_VM_H

#include <sys/types.h>

typedef struct vmspace vmspace_t;
typedef struct vm_client vm_client_t;
typedef struct vm_page vm_page_t;
typedef struct vm_object vm_object_t;

struct vmm_pte_ops;

typedef void (*vmc_inval_cb_t)(void *, uintptr_t, size_t);

typedef enum vmspace_bit_operation {
	VBO_RESET_DIRTY = 1,
	VBO_SET_DIRTY = 2,
	VBO_GET_DIRTY = 3,

	VBO_FLAG_BITMAP_IN = (1 << 30),
	VBO_FLAG_BITMAP_OUT = (1 << 31),
} vmspace_bit_oper_t;

/* vmspace_t operations */
vmspace_t *vmspace_alloc(size_t, struct vmm_pte_ops *, bool);
void vmspace_destroy(vmspace_t *);
int vmspace_map(vmspace_t *, vm_object_t *, uintptr_t, uintptr_t, size_t,
    uint8_t);
int vmspace_unmap(vmspace_t *, uintptr_t, uintptr_t);
int vmspace_populate(vmspace_t *, uintptr_t, uintptr_t);
vm_client_t *vmspace_client_alloc(vmspace_t *);
uint64_t vmspace_table_root(vmspace_t *);
uint64_t vmspace_table_gen(vmspace_t *);
uint64_t vmspace_resident_count(vmspace_t *);
void vmspace_bits_operate(vmspace_t *, uint64_t, size_t, vmspace_bit_oper_t,
    uint8_t *);
bool vmspace_get_tracking(vmspace_t *);
int vmspace_set_tracking(vmspace_t *, bool);

/* vm_client_t operations */
vm_page_t *vmc_hold(vm_client_t *, uintptr_t, int);
vm_page_t *vmc_hold_ext(vm_client_t *, uintptr_t, int, int);
uint64_t vmc_table_enter(vm_client_t *);
void vmc_table_exit(vm_client_t *);
int vmc_fault(vm_client_t *, uintptr_t, int);
vm_client_t *vmc_clone(vm_client_t *);
int vmc_set_inval_cb(vm_client_t *, vmc_inval_cb_t, void *);
void vmc_destroy(vm_client_t *);

/* vm_object_t operations */
vm_object_t *vm_object_mem_allocate(size_t, bool);
vm_object_t *vmm_mmio_alloc(vmspace_t *, uintptr_t, size_t, uintptr_t);
void vm_object_reference(vm_object_t *);
void vm_object_release(vm_object_t *);
pfn_t vm_object_pfn(vm_object_t *, uintptr_t);

/* vm_page_t operations */
const void *vmp_get_readable(const vm_page_t *);
void *vmp_get_writable(const vm_page_t *);
pfn_t vmp_get_pfn(const vm_page_t *);
void vmp_mark_dirty(vm_page_t *);
void vmp_chain(vm_page_t *, vm_page_t *);
vm_page_t *vmp_next(const vm_page_t *);
bool vmp_release(vm_page_t *);
bool vmp_release_chain(vm_page_t *);

/*
 * Flags for vmc_hold_ext():
 */

/* The default flags are empty */
#define	VPF_DEFAULT		0

/*
 * When a page is held for potential writes, the consumer may not perform those
 * writes immediately, or in some cases ever.  They may wish to defer the page
 * being considered dirty until such a determination is made.  By establishing a
 * page hold with this flag, the consumer commits to a later vmp_mark_dirty()
 * call if they write any data though the vm_page.  Doing so will effectively
 * clear the flag and subject the page to expected dirty-tracking logic.
 */
#define	VPF_DEFER_DIRTY		(1 << 0)

/* seg_vmm mapping */
struct vm;
int vm_segmap_obj(struct vm *, int, off_t, off_t, struct as *, caddr_t *,
    uint_t, uint_t, uint_t);
int vm_segmap_space(struct vm *, off_t, struct as *, caddr_t *, off_t, uint_t,
    uint_t, uint_t);

/* Glue functions */
vm_paddr_t vtophys(void *);
void invalidate_cache_all(void);

/*
 * The VM_MAXUSER_ADDRESS determines the upper size limit of a vmspace.
 * This value is sized well below the host userlimit, halving the
 * available space below the VA hole to avoid Intel EPT limits and
 * leave room available in the usable VA range for other mmap tricks.
 */
#define	VM_MAXUSER_ADDRESS	0x00003ffffffffffful

#endif /* _VMM_VM_H */

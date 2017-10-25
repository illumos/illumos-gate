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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef	_VM_MAP_
#define	_VM_MAP_

#include "vm_glue.h"

/*
 * vm_map_wire and vm_map_unwire option flags
 */
#define VM_MAP_WIRE_SYSTEM	0	/* wiring in a kernel map */
#define VM_MAP_WIRE_USER	1	/* wiring in a user map */

#define VM_MAP_WIRE_NOHOLES	0	/* region must not have holes */
#define VM_MAP_WIRE_HOLESOK	2	/* region may have holes */

#define VM_MAP_WIRE_WRITE	4	/* Validate writable. */

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
#define	VM_FAULT_NORMAL	0	/* Nothing special */
#define	VM_FAULT_WIRE	1	/* Wire the mapped page */
#define	VM_FAULT_DIRTY	2	/* Dirty the page; use w/VM_PROT_COPY */



pmap_t vmspace_pmap(struct vmspace *);

int vm_map_find(vm_map_t, vm_object_t, vm_ooffset_t, vm_offset_t *, vm_size_t,
    vm_offset_t, int, vm_prot_t, vm_prot_t, int);
int vm_map_remove(vm_map_t, vm_offset_t, vm_offset_t);
int vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags);

long vmspace_resident_count(struct vmspace *vmspace);


#endif /* _VM_MAP_ */

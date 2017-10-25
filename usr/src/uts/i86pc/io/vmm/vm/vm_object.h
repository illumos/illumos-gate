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

#ifndef	_VM_OBJECT_
#define	_VM_OBJECT_

#include "vm_glue.h"

vm_object_t vm_object_allocate(objtype_t, vm_pindex_t);
void vm_object_deallocate(vm_object_t);
void vm_object_reference(vm_object_t);
int vm_object_set_memattr(vm_object_t, vm_memattr_t);


#define	VM_OBJECT_WLOCK(vmo)	mutex_enter(&(vmo)->vmo_lock)
#define	VM_OBJECT_WUNLOCK(vmo)	mutex_exit(&(vmo)->vmo_lock)

#endif /* _VM_OBJECT_ */

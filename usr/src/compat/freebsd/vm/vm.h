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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _FREEBSD_VM_VM_H_
#define	_FREEBSD_VM_VM_H_

#include <machine/vm.h>
#include <sys/mman.h>

typedef u_char vm_prot_t;

/*
 * Even though the FreeBSD VM_PROT defines happen to match illumos, this
 * references the native values directly so there's no risk of breakage.
 */
#define	VM_PROT_NONE		((vm_prot_t) 0x00)
#define	VM_PROT_READ		((vm_prot_t) PROT_READ)
#define	VM_PROT_WRITE		((vm_prot_t) PROT_WRITE)
#define	VM_PROT_EXECUTE		((vm_prot_t) PROT_EXEC)

#define	VM_PROT_ALL		(VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)
#define	VM_PROT_RW		(VM_PROT_READ|VM_PROT_WRITE)

struct vm_page;
typedef struct vm_page *vm_page_t;

enum obj_type { OBJT_DEFAULT, OBJT_SWAP, OBJT_VNODE, OBJT_DEVICE, OBJT_PHYS,
    OBJT_DEAD, OBJT_SG, OBJT_MGTDEVICE };
typedef u_char objtype_t;

union vm_map_object;
typedef union vm_map_object vm_map_object_t;

struct vm_map_entry;
typedef struct vm_map_entry *vm_map_entry_t;

struct vm_map;
typedef struct vm_map *vm_map_t;

struct vm_object;
typedef struct vm_object *vm_object_t;

/*
 * <sys/promif.h> contains a troublesome preprocessor define for BYTE.
 * Do this ugly workaround to avoid it.
 */
#define	_SYS_PROMIF_H
#include <vm/hat_i86.h>
#undef	_SYS_PROMIF_H

#endif	/* _FREEBSD_VM_VM_H_ */

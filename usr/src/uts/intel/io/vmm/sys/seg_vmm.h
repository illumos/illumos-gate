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
 * Copyright 2018 Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 */

#ifndef	_VM_SEG_VMM_H
#define	_VM_SEG_VMM_H

#include <sys/vmm_vm.h>

typedef struct segvmm_crargs {
	uchar_t		prot;		/* protection */
	uintptr_t	offset;
	vm_object_t	*vmo;
	vm_client_t	*vmc;
} segvmm_crargs_t;

int segvmm_create(struct seg **, void *);

#endif	/* _VM_SEG_VMM_H */

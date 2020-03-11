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


#ifndef	_VM_PAGE_
#define	_VM_PAGE_

#include "vm_glue.h"

#define	PQ_ACTIVE	1

void vm_page_unwire(vm_page_t , uint8_t);

#define	VM_PAGE_TO_PHYS(page)	(mmu_ptob((uintptr_t)((page)->vmp_pfn)))

#endif /* _VM_PAGE_ */

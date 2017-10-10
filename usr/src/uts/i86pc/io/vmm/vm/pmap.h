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

#ifndef _PMAP_VM_
#define	_PMAP_VM_

#include <machine/pmap.h>
#include "vm_glue.h"

void	pmap_invalidate_cache(void);
void	pmap_get_mapping(pmap_t pmap, vm_offset_t va, uint64_t *ptr, int *num);
int	pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype);
long	pmap_wired_count(pmap_t pmap);

#endif /* _PMAP_VM_ */

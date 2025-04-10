
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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SYS_VMM_RESERVOIR_H
#define	_SYS_VMM_RESERVOIR_H

#include <sys/types.h>
#include <sys/cred.h>

struct vmmr_region;
typedef struct vmmr_region vmmr_region_t;

int vmmr_init();
void vmmr_fini();
bool vmmr_is_empty();

int vmmr_alloc(size_t, bool, vmmr_region_t **);
void *vmmr_region_mem_at(vmmr_region_t *, uintptr_t);
pfn_t vmmr_region_pfn_at(vmmr_region_t *, uintptr_t);
void vmmr_free(vmmr_region_t *);

int vmmr_ioctl(int, intptr_t, int, cred_t *, int *);

#endif /* _SYS_VMM_RESERVOIR_H */

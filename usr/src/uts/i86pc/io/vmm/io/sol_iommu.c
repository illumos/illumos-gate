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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>

/*
 * IOMMU Stub
 *
 * Until proper iommu support can be wired into bhyve, stub out all the
 * functions to either fail, if reasonable, or panic.
 */

void
iommu_cleanup(void)
{
}

void *
iommu_host_domain(void)
{
	return (NULL);
}

/*ARGSUSED*/
void *
iommu_create_domain(vm_paddr_t maxaddr)
{
	return (NULL);
}

/*ARGSUSED*/
void
iommu_destroy_domain(void *dom)
{
	panic("unimplemented");
}

/*ARGSUSED*/
void
iommu_create_mapping(void *dom, vm_paddr_t gpa, vm_paddr_t hpa, size_t len)
{
	panic("unimplemented");
}

/*ARGSUSED*/
void
iommu_remove_mapping(void *dom, vm_paddr_t gpa, size_t len)
{
	panic("unimplemented");
}

/*ARGSUSED*/
void
iommu_add_device(void *dom, uint16_t rid)
{
	panic("unimplemented");
}

/*ARGSUSED*/
void
iommu_remove_device(void *dom, uint16_t rid)
{
	panic("unimplemented");
}

/*ARGSUSED*/
void
iommu_invalidate_tlb(void *domain)
{
	panic("unimplemented");
}


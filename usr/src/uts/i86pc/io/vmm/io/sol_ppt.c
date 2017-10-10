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
#include <sys/errno.h>
#include <sys/cmn_err.h>

#include <sys/vmm.h>

/*
 * PCI Pass-Through Stub
 *
 * Until proper passthrough support can be wired into bhyve, stub out all the
 * functions to either fail or no-op.
 */

int
ppt_unassign_all(struct vm *vm)
{
	return (0);
}

/*ARGSUSED*/
int
ppt_map_mmio(struct vm *vm, int bus, int slot, int func, vm_paddr_t gpa,
    size_t len, vm_paddr_t hpa)
{
	return (ENXIO);
}

/*ARGSUSED*/
int
ppt_setup_msi(struct vm *vm, int vcpu, int bus, int slot, int func,
    uint64_t addr, uint64_t msg, int numvec)
{
	return (ENXIO);
}

/*ARGSUSED*/
int
ppt_setup_msix(struct vm *vm, int vcpu, int bus, int slot, int func, int idx,
    uint64_t addr, uint64_t msg, uint32_t vector_control)
{
	return (ENXIO);
}

/*ARGSUSED*/
int
ppt_assigned_devices(struct vm *vm)
{
	return (0);
}

/*ARGSUSED*/
boolean_t
ppt_is_mmio(struct vm *vm, vm_paddr_t gpa)
{
	return (B_FALSE);
}

/*ARGSUSED*/
int
ppt_avail_devices(void)
{
	return (0);
}

/*ARGSUSED*/
int
ppt_assign_device(struct vm *vm, int bus, int slot, int func)
{
	return (ENOENT);
}

/*ARGSUSED*/
int
ppt_unassign_device(struct vm *vm, int bus, int slot, int func)
{
	return (ENXIO);
}

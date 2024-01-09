/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2022 Oxide Computer Company
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/eventhandler.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <machine/cpu.h>
#include <machine/md_var.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>

#include "vmm_util.h"
#include "iommu.h"


static kmutex_t iommu_lock;

static uint_t iommu_refcnt;
ddi_modhandle_t iommu_modhdl;
static const struct iommu_ops *ops;
static void *host_domain;

static int
iommu_find_device(dev_info_t *dip, void *arg)
{
	boolean_t add = (boolean_t)(uintptr_t)arg;

	if (pcie_is_pci_device(dip)) {
		if (add)
			iommu_add_device(host_domain, pci_get_rid(dip));
		else
			iommu_remove_device(host_domain, pci_get_rid(dip));
	}

	return (DDI_WALK_CONTINUE);
}

static vm_paddr_t
vmm_mem_maxaddr(void)
{
	return (ptoa(physmax + 1));
}

static int
iommu_init(void)
{
	const char *mod_name;
	int error = 0;

	ASSERT(MUTEX_HELD(&iommu_lock));

	if (vmm_is_intel()) {
		mod_name = "misc/vmm_vtd";
	} else if (vmm_is_svm()) {
		/* Use the expected name for if/when this is ported */
		mod_name = "misc/vmm_amdvi";
	} else {
		return (ENXIO);
	}

	/* Load the backend driver */
	iommu_modhdl = ddi_modopen(mod_name, KRTLD_MODE_FIRST, &error);
	if (iommu_modhdl == NULL) {
		return (error);
	}

	/* Locate the iommu_ops struct */
	ops = ddi_modsym(iommu_modhdl, IOMMU_OPS_SYM_NAME, &error);
	if (ops == NULL) {
		goto bail;
	}

	/* Initialize the backend */
	error = ops->init();
	if (error != 0) {
		goto bail;
	}

	/* Create a domain for the devices owned by the host */
	const vm_paddr_t maxaddr = vmm_mem_maxaddr();
	host_domain = ops->create_domain(maxaddr);
	if (host_domain == NULL) {
		goto bail;
	}

	/* ... and populate it with 1:1 mappings for all of physical mem */
	iommu_create_mapping(host_domain, 0, 0, maxaddr);

	ddi_walk_devs(ddi_root_node(), iommu_find_device, (void *)B_TRUE);
	ops->enable();

	return (0);

bail:
	if (ops != NULL) {
		ops->cleanup();
		ops = NULL;
	}
	if (iommu_modhdl != NULL) {
		(void) ddi_modclose(iommu_modhdl);
		iommu_modhdl = NULL;
	}
	return (error);
}

static void
iommu_cleanup(void)
{
	ASSERT(MUTEX_HELD(&iommu_lock));
	ASSERT3P(ops, !=, NULL);
	ASSERT0(iommu_refcnt);

	ops->disable();
	ddi_walk_devs(ddi_root_node(), iommu_find_device, (void *)B_FALSE);

	ops->destroy_domain(host_domain);
	host_domain = NULL;

	ops->cleanup();
	ops = NULL;

	(void) ddi_modclose(iommu_modhdl);
	iommu_modhdl = NULL;
}

static bool
iommu_ref(void)
{
	mutex_enter(&iommu_lock);
	if (ops == NULL) {
		int err = iommu_init();

		if (err != 0) {
			VERIFY3P(ops, ==, NULL);
			mutex_exit(&iommu_lock);
			return (false);
		}
		VERIFY3P(ops, !=, NULL);
	}
	iommu_refcnt++;
	VERIFY3U(iommu_refcnt, <, UINT_MAX);
	mutex_exit(&iommu_lock);

	return (true);
}

static void
iommu_unref(void)
{
	mutex_enter(&iommu_lock);
	VERIFY3U(iommu_refcnt, >, 0);
	iommu_refcnt--;
	if (iommu_refcnt == 0) {
		iommu_cleanup();
		VERIFY3P(ops, ==, NULL);
	}
	mutex_exit(&iommu_lock);
}

void *
iommu_create_domain(vm_paddr_t maxaddr)
{
	if (iommu_ref()) {
		return (ops->create_domain(maxaddr));
	} else {
		return (NULL);
	}
}

void
iommu_destroy_domain(void *domain)
{
	ASSERT3P(domain, !=, NULL);

	ops->destroy_domain(domain);
	iommu_unref();
}

void
iommu_create_mapping(void *domain, vm_paddr_t gpa, vm_paddr_t hpa, size_t len)
{
	uint64_t remaining = len;

	ASSERT3P(domain, !=, NULL);

	while (remaining > 0) {
		uint64_t mapped;

		mapped = ops->create_mapping(domain, gpa, hpa, remaining);
		gpa += mapped;
		hpa += mapped;
		remaining -= mapped;
	}
}

void
iommu_remove_mapping(void *domain, vm_paddr_t gpa, size_t len)
{
	uint64_t remaining = len;

	ASSERT3P(domain, !=, NULL);

	while (remaining > 0) {
		uint64_t unmapped;

		unmapped = ops->remove_mapping(domain, gpa, remaining);
		gpa += unmapped;
		remaining -= unmapped;
	}
}

void *
iommu_host_domain(void)
{
	return (host_domain);
}

void
iommu_add_device(void *domain, uint16_t rid)
{
	ASSERT3P(domain, !=, NULL);

	ops->add_device(domain, rid);
}

void
iommu_remove_device(void *domain, uint16_t rid)
{
	ASSERT3P(domain, !=, NULL);

	ops->remove_device(domain, rid);
}

void
iommu_invalidate_tlb(void *domain)
{
	ASSERT3P(domain, !=, NULL);

	ops->invalidate_tlb(domain);
}

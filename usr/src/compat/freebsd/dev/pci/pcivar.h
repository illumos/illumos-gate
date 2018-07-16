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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_DEV_PCI_PCIVAR_H
#define	_COMPAT_FREEBSD_DEV_PCI_PCIVAR_H

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>

static inline pcie_req_id_t
pci_get_bdf(device_t dev)
{
	pcie_req_id_t bdf;

	VERIFY(pcie_get_bdf_from_dip(dev, &bdf) == DDI_SUCCESS);

	return (bdf);
}

#define	pci_get_rid(dev)	(pci_get_bdf(dev))

#endif /* _COMPAT_FREEBSD_DEV_PCI_PCIVAR_H */

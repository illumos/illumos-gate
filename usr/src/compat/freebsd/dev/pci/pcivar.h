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

#define PCIE_REQ_ID(val, what)	(((val) & PCIE_REQ_ID_##what##_MASK) >>\
    PCIE_REQ_ID_##what##_SHIFT)

#define	pci_get_bus(dev)	(PCIE_REQ_ID(pci_get_bdf(dev), BUS))
#define	pci_get_slot(dev)	(PCIE_REQ_ID(pci_get_bdf(dev), DEV))
#define	pci_get_function(dev)	(PCIE_REQ_ID(pci_get_bdf(dev), FUNC))
#define	pci_get_rid(dev)	(pci_get_bdf(dev))

#define	pci_save_state(dev)	pci_save_config_regs(dev)
#define	pci_restore_state(dev)	pci_restore_config_regs(dev)

bool pcie_flr(device_t, u_int, bool);
int pcie_get_max_completion_timeout(device_t);


#endif /* _COMPAT_FREEBSD_DEV_PCI_PCIVAR_H */

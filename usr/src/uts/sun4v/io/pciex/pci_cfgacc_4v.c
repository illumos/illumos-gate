/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Common PCI configuration space access routines
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/promif.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/kmem.h>
#include <sys/obpdefs.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <sys/spl.h>
#include <sys/pcie_impl.h>
#include <sys/pci_cfgacc_4v.h>

#define	PCIE_CFG_SPACE_SIZE		(PCI_CONF_HDR_SIZE << 4)

/* RC BDF Shift in a Phyiscal Address */
#define	RC_RA_BDF_SHIFT			8

static boolean_t
pci_cfgacc_valid(pci_cfgacc_req_t *req)
{
	int sz = req->size;

	if (IS_P2ALIGNED(req->offset, sz)		&&
	    (req->offset < PCIE_CFG_SPACE_SIZE)		&&
	    ((sz & 0xf) && ISP2(sz)))
		return (B_TRUE);

	cmn_err(CE_WARN, "illegal PCI request: offset = %x, size = %d",
	    req->offset, sz);
	return (B_FALSE);
}

/*
 * Unprotected raw reads/writes of fabric device's config space.
 */
static uint64_t
pci_cfgacc_get(dev_info_t *dip, uint16_t bdf, uint16_t offset, uint8_t size)
{
	pcie_bus_t	*bus_p;
	uint64_t	devhdl;
	uint64_t	devaddr;
	uint64_t 	data = 0;

	bus_p = PCIE_DIP2DOWNBUS(dip);
	ASSERT(bus_p != NULL);

	devhdl = bus_p->bus_cfgacc_base;
	devaddr = ((uint64_t)bdf) << RC_RA_BDF_SHIFT;

	(void) hvio_config_get(devhdl, devaddr,
	    offset, size, (pci_cfg_data_t *)&data);

	return (data);
}

static void
pci_cfgacc_set(dev_info_t *dip, uint16_t bdf, uint16_t offset, uint8_t size,
    uint64_t val)
{
	pcie_bus_t	*bus_p;
	uint64_t	devhdl;
	uint64_t	devaddr;
	pci_cfg_data_t	wdata = { 0 };

	bus_p = PCIE_DIP2DOWNBUS(dip);
	ASSERT(bus_p != NULL);

	devhdl = bus_p->bus_cfgacc_base;
	devaddr = ((uint64_t)bdf) << RC_RA_BDF_SHIFT;

	wdata.qw = val;
	(void) hvio_config_put(devhdl, devaddr, offset, size, wdata);
}

void
pci_cfgacc_acc(pci_cfgacc_req_t *req)
{
	if (!req->write)
		VAL64(req) = (uint64_t)-1;

	if (!pci_cfgacc_valid(req))
		return;

	if (req->write) {
		pci_cfgacc_set(req->rcdip, req->bdf, req->offset,
		    req->size, VAL64(req));
	} else {
		VAL64(req) = pci_cfgacc_get(req->rcdip, req->bdf,
		    req->offset, req->size);
		switch (req->size) {
		case 1:
			VAL8(req) = (uint8_t)VAL64(req);
			break;
		case 2:
			VAL16(req) = (uint16_t)VAL64(req);
			break;
		case 4:
			VAL32(req) = (uint32_t)VAL64(req);
			break;
		case 8:
			/* fall through, no special handling needed */
		default:
			break;
		}
	}
}

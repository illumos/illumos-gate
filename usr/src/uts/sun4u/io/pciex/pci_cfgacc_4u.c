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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/promif.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/pcie_impl.h>
#include <sys/machsystm.h>
#include <sys/byteorder.h>
#include <sys/pci_cfgacc.h>

#define	PCI_CFG_SPACE		(PCI_REG_ADDR_G(PCI_ADDR_CONFIG))
#define	PCIE_CFG_SPACE_SIZE	(PCI_CONF_HDR_SIZE << 4)

/* RC BDF Shift in a Phyiscal Address */
#define	RC_PA_BDF_SHIFT			12
#define	RC_BDF_TO_CFGADDR(bdf, offset) (((bdf) << RC_PA_BDF_SHIFT) + (offset))

static boolean_t
pci_cfgacc_valid(pci_cfgacc_req_t *req)
{
	/* do not support 64 bit pci config space access */
	return (IS_P2ALIGNED(req->offset, req->size)	&&
	    (req->offset < PCIE_CFG_SPACE_SIZE)		&&
	    ((req->size == 1) || (req->size == 2) ||
	    (req->size == 4) || (req->size == 8)));
}

/*
 * Unprotected raw reads/writes of fabric device's config space.
 */
static uint64_t
pci_cfgacc_get(dev_info_t *dip, uint16_t bdf, uint16_t offset, uint8_t size)
{
	pcie_bus_t	*bus_p;
	uint64_t	base_addr;
	uint64_t	val;

	if ((bus_p = PCIE_DIP2DOWNBUS(dip)) == NULL)
		return ((uint64_t)-1);

	base_addr = bus_p->bus_cfgacc_base;
	base_addr += RC_BDF_TO_CFGADDR(bdf, offset);

	switch (size) {
	case 1:
		val = ldbphysio(base_addr);
		break;
	case 2:
		val = ldhphysio(base_addr);
		break;
	case 4:
		val = ldphysio(base_addr);
		break;
	case 8:
		val = lddphysio(base_addr);
		break;
	default:
		return ((uint64_t)-1);
	}

	return (LE_64(val));
}

static void
pci_cfgacc_set(dev_info_t *dip, uint16_t bdf, uint16_t offset, uint8_t size,
    uint64_t val)
{
	pcie_bus_t	*bus_p;
	uint64_t	base_addr;

	if ((bus_p = PCIE_DIP2DOWNBUS(dip)) == NULL)
		return;

	base_addr = bus_p->bus_cfgacc_base;
	base_addr += RC_BDF_TO_CFGADDR(bdf, offset);

	val = LE_64(val);

	switch (size) {
	case 1:
		stbphysio(base_addr, val);
		break;
	case 2:
		sthphysio(base_addr, val);
		break;
	case 4:
		stphysio(base_addr, val);
		break;
	case 8:
		stdphysio(base_addr, val);
		break;
	default:
		break;
	}
}

void
pci_cfgacc_acc(pci_cfgacc_req_t *req)
{
	/* is request valid? */
	if (!pci_cfgacc_valid(req)) {
		if (!req->write)
			VAL64(req) = (uint64_t)-1;
		return;
	}

	if (req->write) {
		pci_cfgacc_set(req->rcdip, req->bdf, req->offset,
		    req->size, VAL64(req));
	} else {
		VAL64(req) = pci_cfgacc_get(req->rcdip, req->bdf,
		    req->offset, req->size);
	}
}

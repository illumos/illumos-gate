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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/async.h>
#include <sys/sunddi.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/vmem.h>
#include <sys/intr.h>
#include <sys/ivintr.h>
#include <sys/errno.h>
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#include <px_obj.h>
#include <sys/machsystm.h>
#include "px_lib4v.h"

#define	MPS_SET		0
#define	MPS_GET		1

static uint64_t hvio_rp_mps(devhandle_t dev_hdl, pci_device_t bdf, int32_t *mps,
	int op);

uint64_t
hvio_get_rp_mps_cap(devhandle_t dev_hdl, pci_device_t bdf, int32_t *mps_cap)
{
	return (hvio_rp_mps(dev_hdl, bdf, mps_cap, MPS_GET));
}

uint64_t
hvio_set_rp_mps(devhandle_t dev_hdl, pci_device_t bdf, int32_t mps)
{
	return (hvio_rp_mps(dev_hdl, bdf, &mps, MPS_SET));
}

uint64_t
hvio_rp_mps(devhandle_t dev_hdl, pci_device_t bdf, int32_t *mps, int op)
{
	uint32_t	data;
	uint32_t	hdr, hdr_next_ptr, hdr_cap_id;
	uint16_t	offset = PCI_CONF_STAT;
	int		deadcount = 0;
	pci_cfg_data_t	dataw;

	if ((hvio_config_get(dev_hdl, bdf, PCI_CONF_VENID, 4,
	    (pci_cfg_data_t *)&data)) != H_EOK)
		return (H_ENOACCESS);

	if ((data & 0xffff) != 0x108e)
		return (H_ENOACCESS);

	if ((hvio_config_get(dev_hdl, bdf, PCI_CONF_COMM, 4,
	    (pci_cfg_data_t *)&hdr)) != H_EOK)
		return (H_ENOACCESS);

	if (!(hdr & (PCI_STAT_CAP << 16)))
		return (H_ENOACCESS);

	(void) hvio_config_get(dev_hdl, bdf, PCI_CONF_CAP_PTR, 4,
	    (pci_cfg_data_t *)&hdr);

	hdr_next_ptr = hdr & 0xFF;
	hdr_cap_id = 0;

	while ((hdr_next_ptr != PCI_CAP_NEXT_PTR_NULL) &&
	    (hdr_cap_id != PCI_CAP_ID_PCI_E)) {

		offset = hdr_next_ptr;

		if (hdr_next_ptr < 0x40)
			break;

		(void) hvio_config_get(dev_hdl, bdf, hdr_next_ptr, 4,
		    (pci_cfg_data_t *)&hdr);

		hdr_next_ptr = (hdr >> 8) & 0xFF;
		hdr_cap_id = hdr & 0xFF;

		if (deadcount++ > 100)
			break;
	}

	if (hdr_cap_id != PCI_CAP_ID_PCI_E)
		return (H_ENOACCESS);

	if (op == MPS_SET) {

		/* Write the MPS */

		(void) hvio_config_get(dev_hdl, bdf, offset + PCIE_DEVCTL,
		    4, (pci_cfg_data_t *)&data);

		data = (data & 0xffffff1f) | (*mps << 5);

		dataw.qw = (uint32_t)data;

		(void) hvio_config_put(dev_hdl, bdf, offset + PCIE_DEVCTL,
		    4, dataw);
	} else {

		/* Read the MPS Capabilities */

		(void) hvio_config_get(dev_hdl, bdf, offset + PCIE_DEVCAP,
		    4, (pci_cfg_data_t *)&data);

		*mps = data & 0x7;
	}

	return (H_EOK);
}

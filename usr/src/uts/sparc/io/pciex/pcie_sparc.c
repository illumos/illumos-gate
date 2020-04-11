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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pcie_impl.h>
#include <sys/pcie_pwr.h>

void
pcie_init_plat(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE_BDG(bus_p)) {
		bus_p->bus_pcie2pci_secbus = bus_p->bus_bdg_secbus;
	} else {
		dev_info_t *pdip;

		for (pdip = ddi_get_parent(dip); pdip;
		    pdip = ddi_get_parent(pdip)) {
			pcie_bus_t *parent_bus_p = PCIE_DIP2BUS(pdip);

			if (parent_bus_p->bus_pcie2pci_secbus) {
				bus_p->bus_pcie2pci_secbus =
				    parent_bus_p->bus_pcie2pci_secbus;
				break;
			}
			if (PCIE_IS_ROOT(parent_bus_p))
				break;
		}
	}
}

void
pcie_fini_plat(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE_BDG(bus_p))
		bus_p->bus_pcie2pci_secbus = 0;
}

int
pcie_plat_pwr_setup(dev_info_t *dip)
{
	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "pm-want-child-notification?", NULL, 0) != DDI_PROP_SUCCESS) {
		PCIE_DBG("%s(%d): can't create pm-want-child-notification \n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Undo whatever is done in pcie_plat_pwr_common_setup
 */
void
pcie_plat_pwr_teardown(dev_info_t *dip)
{
	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
	    "pm-want-child-notification?");
}

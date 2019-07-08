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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * PCIe related dcmds
 */

#include <mdb/mdb_modapi.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/pcie_impl.h>

boolean_t
pcie_bus_match(const struct dev_info *devi, uintptr_t *bus_p)
{
	if (devi->devi_bus.port_up.info.port.type == DEVI_PORT_TYPE_PCI) {
		*bus_p = (uintptr_t)devi->devi_bus.port_up.priv_p;
	} else if (devi->devi_bus.port_down.info.port.type ==
	    DEVI_PORT_TYPE_PCI) {
		*bus_p = (uintptr_t)devi->devi_bus.port_down.priv_p;
	} else {
		return (B_FALSE);
	}

	return (B_TRUE);
}

int
pcie_bus_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("pcie_bus walker doesn't support non-global walks\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("devinfo", wsp) == -1) {
		mdb_warn("couldn't walk \"devinfo\"");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
pcie_bus_walk_step(mdb_walk_state_t *wsp)
{
	const struct dev_info *devi;
	uintptr_t bus_addr;
	struct pcie_bus bus;

	if (wsp->walk_layer == NULL) {
		mdb_warn("missing layered walk info\n");
		return (WALK_ERR);
	}

	devi = wsp->walk_layer;
	if (!pcie_bus_match(devi, &bus_addr)) {
		return (WALK_NEXT);
	}

	if (mdb_vread(&bus, sizeof (bus), bus_addr) == -1) {
		mdb_warn("failed to read pcie_bus_t at %p", bus_addr);
		return (WALK_NEXT);
	}

	return (wsp->walk_callback(bus_addr, &bus, wsp->walk_cbdata));
}

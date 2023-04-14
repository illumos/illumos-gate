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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef	_TOPO_PCIE_H
#define	_TOPO_PCIE_H

#include <fm/topo_hc.h>

/*
 * Common PCIe module header file.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Topology properties.
 * Where they exist, we use the same property names as are used for HC nodes
 * for consistency across the different trees.
 */

/* io group */
#define	TOPO_PCIE_PGROUP_IO		TOPO_PGROUP_IO
#define	TOPO_PCIE_IO_DEV_PATH		TOPO_IO_DEV_PATH
#define	TOPO_PCIE_IO_DRIVER		TOPO_IO_DRIVER
#define	TOPO_PCIE_IO_INSTANCE		TOPO_IO_INSTANCE
#define	TOPO_PCIE_IO_DEVTYPE		TOPO_IO_DEVTYPE

/*
 * pci-cfg
 * Contains properties which relate to data that the OS has programmed into the
 * PCI device, such as its B/D/F.
 */
#define	TOPO_PCIE_PGROUP_PCI_CFG	"pci-cfg"
#define	TOPO_PCIE_PCI_BUS		"bus"
#define	TOPO_PCIE_PCI_DEVICE		"device"
#define	TOPO_PCIE_PCI_FUNCTION		"function"
#define	TOPO_PCIE_PCI_SEGMENT		"segment"
#define	TOPO_PCIE_PCI_BUS_RANGE		"bus-range"
#define	TOPO_PCIE_PCI_ASSIGNED_ADDR	TOPO_PCI_AADDR

/*
 * pci
 * This is used for both PCI and PCIe devices. It contains properties which are
 * obtained from the device itself, and some synthetic ones derived from them
 * such as the strings obtained via lookups in the PCI database.
 */
#define	TOPO_PCIE_PGROUP_PCI		TOPO_PGROUP_PCI
#define	TOPO_PCIE_PCI_TYPE		"type"
#define	TOPO_PCIE_PCI_SLOT		"slot"
#define	TOPO_PCIE_PCI_CLASS		"class"
#define	TOPO_PCIE_PCI_SUBCLASS		"subclass"
#define	TOPO_PCIE_PCI_INTERFACE		"interface"
#define	TOPO_PCIE_PCI_VENDOR_NAME	TOPO_PCI_VENDNM
#define	TOPO_PCIE_PCI_DEV_NAME		TOPO_PCI_DEVNM
#define	TOPO_PCIE_PCI_SUBSYSTEM_NAME	TOPO_PCI_SUBSYSNM
#define	TOPO_PCIE_PCI_VENDOR_ID		TOPO_PCI_VENDID
#define	TOPO_PCIE_PCI_DEV_ID		TOPO_PCI_DEVID
#define	TOPO_PCIE_PCI_SSVENDORID	"subsystem-vendor-id"
#define	TOPO_PCIE_PCI_SSID		"subsystem-id"
#define	TOPO_PCIE_PCI_REVID		"revision-id"
#define	TOPO_PCIE_PCI_CLASS_STRING	"class-string"

/* port group */
#define	TOPO_PCIE_PGROUP_PORT		"port"
#define	TOPO_PCIE_PORT_TYPE		"type"
#define	TOPO_PCIE_PORT_TYPE_US		"upstream"
#define	TOPO_PCIE_PORT_TYPE_DS		"downstream"

/*
 * Link properties.
 *
 * Depending on whether a link is a PCI or PCIe link, one of these property
 * groups will be present. Not all properties apply equally to both link types.
 */
#define	TOPO_PCIE_PGROUP_PCIE_LINK	"pcie-link"
#define	TOPO_PCIE_PGROUP_PCI_LINK	"pci-link"

/* Common properties */
#define	TOPO_PCIE_LINK_STATE		"link-state"
#define	TOPO_PCIE_LINK_SUBSTRATE	"substrate"

/* pcie-specific link properties */
#define	TOPO_PCIE_LINK_CUR_SPEED	TOPO_PCI_CUR_SPEED
#define	TOPO_PCIE_LINK_CUR_WIDTH	TOPO_PCI_CUR_WIDTH
#define	TOPO_PCIE_LINK_MAX_SPEED	TOPO_PCI_MAX_SPEED
#define	TOPO_PCIE_LINK_MAX_WIDTH	TOPO_PCI_MAX_WIDTH
#define	TOPO_PCIE_LINK_SUP_SPEED	TOPO_PCI_SUP_SPEED
#define	TOPO_PCIE_LINK_ADMIN_SPEED	TOPO_PCI_ADMIN_SPEED

/* pci-specific link properties */
#define	TOPO_PCIE_LINK_66MHZ_CAPABLE	"66mhz-capable"

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_PCIE_H */

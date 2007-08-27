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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCIEHPC_ACPI_H
#define	_PCIEHPC_ACPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/hotplug/pci/pciehpc_impl.h>

/* soft state data structure for ACPI hot plug mode */
typedef struct pciehpc_acpi {
	/* handle for the ACPI device for the bus node with HPC */
	ACPI_HANDLE	bus_obj;

	/* handle for the ACPI device for the slot (dev#0,func#0) */
	ACPI_HANDLE	slot_dev_obj;

	/* ACPI control methods present on the bus node */
	uint16_t	bus_methods;

	/* ACPI control methods on the slot device functions */
	uint16_t	slot_methods;
} pciehpc_acpi_t;

/* bit definitions in acpi_bus_methods */
#define	PCIEHPC_ACPI_OSC_PRESENT	0x0001
#define	PCIEHPC_ACPI_OSHP_PRESENT	0x0002
#define	PCIEHPC_ACPI_SUN_PRESENT	0x0004
#define	PCIEHPC_ACPI_STA_PRESENT	0x0008
#define	PCIEHPC_ACPI_EJ0_PRESENT	0x0010
#define	PCIEHPC_ACPI_HPP_PRESENT	0x0020
#define	PCIEHPC_ACPI_HPX_PRESENT	0x0040
#define	PCIEHPC_ACPI_PS0_PRESENT	0x0080
#define	PCIEHPC_ACPI_DSM_PRESENT	0x0080
#define	PCIEHPC_ACPI_STR_PRESENT	0x0100

/* revision id of _OSC for PCI/PCI-X/PCI-Exp hierarchy */
#define	PCIE_OSC_REVISION_ID	1	/* defined in PCI fw ver 3.0 */

/*
 * _OSC method Capabilities buffer bit definitions (from PCI FW 3.0)
 */
/* first DWORD: status from _OSC invocation (except bit 0) */
#define	OSC_STATUS_QUERY_ENABLE	0x1	/* Query Support Flag */
#define	OSC_STATUS_FAILED	0x2	/* _OSC failure */
#define	OSC_STATUS_INV_UUID	0x4	/* invalid UUID */
#define	OSC_STATUS_INV_REVID	0x8	/* invalid revision ID */
#define	OSC_STATUS_CAPS_MASKED	0x10	/* capabilities masked */

#define	OSC_STATUS_ERRORS \
	(OSC_STATUS_FAILED | OSC_STATUS_INV_UUID | OSC_STATUS_INV_REVID)

/* second DWORD: Support Field (set by OS) */
#define	OSC_SUPPORT_EXT_PCI_CFG	0x1	/* Extended PCI Config Ops supported */
#define	OSC_SUPPORT_ACT_PM	0x2	/* Active State PM supported */
#define	OSC_SUPPORT_CLK_PM_CAP	0x4	/* Clock PM Capability supported */
#define	OSC_SUPPORT_PCI_SEGS	0x8	/* PCI Segment Groups supported */
#define	OSC_SUPPORT_MSI		0x10	/* MSI supported */

/* third DWORD: Control Field (set by OS/BIOS) */
#define	OSC_CONTROL_PCIE_NAT_HP	0x1	/* PCI Exp Native Hot Plug control */
#define	OSC_CONTROL_SHPC_NAT_HP	0x2	/* SHPC Native Hot Plug control */
#define	OSC_CONTROL_PCIE_NAT_PM	0x4	/* PCI Exp Native Power Mgmt. control */
#define	OSC_CONTROL_PCIE_ADV_ERR 0x8	/* PCIE Advanced Err. rep. control */
#define	OSC_CONTROL_PCIE_CAPS	0x10	/* PCIE Caps Structure control */

#define	OSC_CONTROL_FIELD_INIT \
	(OSC_CONTROL_PCIE_NAT_PM | OSC_CONTROL_PCIE_NAT_HP | \
	OSC_CONTROL_PCIE_CAPS | OSC_CONTROL_PCIE_ADV_ERR)

#define	OSC_SUPPORT_FIELD_INIT \
	(OSC_SUPPORT_EXT_PCI_CFG | \
	OSC_SUPPORT_ACT_PM | OSC_SUPPORT_CLK_PM_CAP | \
	OSC_SUPPORT_MSI | OSC_SUPPORT_PCI_SEGS)

#define	ACPI_HP_MODE	1
#define	NATIVE_HP_MODE	2

/* Device status bit as returned by _STA method (see 6.3.7 of ACPI 3.0) */
#define	DEV_STS_PRESENT		0x1	/* device is present */
#define	DEV_STS_ENABLED		0x2	/* device is enabled */
#define	DEV_STS_SHOWN_UI	0x4	/* device should be shown in UI */
#define	DEV_STS_FUNC_OK		0x8	/* device functioning normally */
#define	STATUS_NORMAL	\
	(DEV_STS_PRESENT | DEV_STS_ENABLED | DEV_STS_SHOWN_UI | DEV_STS_FUNC_OK)

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIEHPC_ACPI_H */

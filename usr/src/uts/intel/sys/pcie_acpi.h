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

#ifndef	_SYS_PCIE_ACPI_H
#define	_SYS_PCIE_ACPI_H

#ifdef	__cplusplus
extern "C" {
#endif

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
	(OSC_CONTROL_PCIE_CAPS | OSC_CONTROL_PCIE_ADV_ERR)

#define	OSC_SUPPORT_FIELD_INIT \
	(OSC_SUPPORT_EXT_PCI_CFG | \
	OSC_SUPPORT_ACT_PM | OSC_SUPPORT_CLK_PM_CAP | \
	OSC_SUPPORT_MSI | OSC_SUPPORT_PCI_SEGS)

typedef struct pcie_x86_priv {
	/* _OSC related */
	boolean_t	bus_osc;  	/* Has _OSC method been called */
	boolean_t	bus_osc_hp;	/* Was native HP control granted */
	boolean_t	bus_osc_aer;	/* Was AER control granted */
} pcie_x86_priv_t;

extern int pcie_acpi_osc(dev_info_t *dip, uint32_t *osc_flags);
extern boolean_t pcie_is_osc(dev_info_t *dip);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIE_ACPI_H */

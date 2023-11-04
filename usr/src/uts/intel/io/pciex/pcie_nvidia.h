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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_PCIEX_PCI_NVIDIA_H
#define	_PCIEX_PCI_NVIDIA_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCI Configuration (Nvidia, PCIe) related library functions
 */
boolean_t	look_for_any_pciex_device(uchar_t);
boolean_t	check_if_device_is_pciex(dev_info_t *, uchar_t, uchar_t,
		    uchar_t, boolean_t *, ushort_t *, ushort_t *);
boolean_t	create_pcie_root_bus(uchar_t, dev_info_t *);
void		add_nvidia_isa_bridge_props(dev_info_t *, uchar_t, uchar_t,
		    uchar_t);

/* Generic Nvidia chipset IDs and defines */
#define	NVIDIA_VENDOR_ID			0x10de	/* Nvidia Vendor Id */
#define	NVIDIA_INTR_BCR_OFF			0x3C	/* NV_XVR_INTR_BCR */
#define	NVIDIA_INTR_BCR_SERR_FORWARD_BIT	0x02	/* SERR_FORWARD bit */

/* CK8-04 PCIe RC and LPC-PCI Bridge device IDs */
#define	NVIDIA_CK804_DEVICE_ID			0x5d	/* ck8-04 dev id */
#define	NVIDIA_CK804_DEFAULT_ISA_BRIDGE_DEVID	0x50	/* LPC Default Bridge */
#define	NVIDIA_CK804_PRO_ISA_BRIDGE_DEVID	0x51	/* LPC Bridge */
#define	NVIDIA_CK804_SLAVE_ISA_BRIDGE_DEVID	0xd3	/* Slave LPC Bridge */
#define	NVIDIA_CK804_AER_VALID_REVID		0xa3	/* RID w/ AER enabled */

#define	NVIDIA_CK804_LPC2PCI_DEVICE_ID(did) \
	(((did) == NVIDIA_CK804_DEFAULT_ISA_BRIDGE_DEVID) || \
	((did) == NVIDIA_CK804_PRO_ISA_BRIDGE_DEVID) || \
	((did) == NVIDIA_CK804_SLAVE_ISA_BRIDGE_DEVID))

/*
 * Only for Nvidia's CrushK 8-04 chipsets:
 *	To enable hotplug; we need to map in two I/O BARs
 *	from ISA bridge's config space
 */
#define	NVIDIA_CK804_ISA_SYSCTRL_BAR_OFF	0x64	/* System Control BAR */
#define	NVIDIA_CK804_ISA_ANALOG_BAR_OFF		0x68	/* Analog BAR */

/* NV_XVR_VEND_CYA1 related defines */
#define	NVIDIA_CK804_VEND_CYA1_OFF		0xf40	/* NV_XVR_VEND_CYA1 */
#define	NVIDIA_CK804_VEND_CYA1_ERPT_VAL		0x2000	/* enable CYA1 ERPT */
#define	NVIDIA_CK804_VEND_CYA1_ERPT_MASK	0xdfff	/* CYA1 ERPT mask */

/*
 * C51 related defines
 */

/* C51 PCIe Root Complex Device ID defines */
#define	NVIDIA_C51_DEVICE_ID_XVR16		0x2fb
#define	NVIDIA_C51_DEVICE_ID_XVR1_0		0x2fc
#define	NVIDIA_C51_DEVICE_ID_XVR1_1		0x2fd

#define	NVIDIA_C51_DEVICE_ID(did) \
	(((did) == NVIDIA_C51_DEVICE_ID_XVR16) || \
	((did) == NVIDIA_C51_DEVICE_ID_XVR1_0) || \
	((did) == NVIDIA_C51_DEVICE_ID_XVR1_1))

/*
 * MCP55 related defines
 */

/* MCP55 PCIe Root Complex Device ID defines */
#define	NVIDIA_MCP55_DEVICE_ID_XVR4		0x374
#define	NVIDIA_MCP55_DEVICE_ID_XVR8		0x375
#define	NVIDIA_MCP55_DEVICE_ID_XVR8_VC1		0x376
#define	NVIDIA_MCP55_DEVICE_ID_XVR16		0x377
#define	NVIDIA_MCP55_DEVICE_ID_XVR4_VC1		0x378

#define	NVIDIA_MCP55_DEVICE_ID(did) \
	(((did) == NVIDIA_MCP55_DEVICE_ID_XVR4) || \
	((did) == NVIDIA_MCP55_DEVICE_ID_XVR8) || \
	((did) == NVIDIA_MCP55_DEVICE_ID_XVR16) || \
	((did) == NVIDIA_MCP55_DEVICE_ID_XVR4_VC1) || \
	((did) == NVIDIA_MCP55_DEVICE_ID_XVR8_VC1))

/* MCP55 LPC-PCI Bridge Device ID defines */
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP0	0x360
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP1	0x361
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP2	0x362
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP3	0x363
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP4	0x364
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP5	0x365
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP6	0x366
#define	NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP7	0x367

#define	NVIDIA_MCP55_LPC2PCI_DEVICE_ID(did) \
	(((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP0) || \
	((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP1) || \
	((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP2) || \
	((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP3) || \
	((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP4) || \
	((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP5) || \
	((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP6) || \
	((did) == NVIDIA_MCP55_PCI2LPC_DEVICE_ID_OP7))

/*
 * MCP61 related defines
 */

/* MCP61 PCIe Root Complex Device ID defines */
#define	NVIDIA_MCP61_DEVICE_ID_XVR4		0x3e8
#define	NVIDIA_MCP61_DEVICE_ID_XVR8		0x3e9

#define	NVIDIA_MCP61_DEVICE_ID(did) \
	(((did) == NVIDIA_MCP61_DEVICE_ID_XVR4) || \
	((did) == NVIDIA_MCP61_DEVICE_ID_XVR8))

/*
 * MCP65 related defines
 */

/* MCP65 PCIe Root Complex Device ID defines */
#define	NVIDIA_MCP65_DEVICE_ID_XVR4		0x458
#define	NVIDIA_MCP65_DEVICE_ID_XVR8		0x459
#define	NVIDIA_MCP65_DEVICE_ID_XVR16		0x45a

#define	NVIDIA_MCP65_DEVICE_ID(did) \
	(((did) == NVIDIA_MCP65_DEVICE_ID_XVR4) || \
	((did) == NVIDIA_MCP65_DEVICE_ID_XVR8) || \
	((did) == NVIDIA_MCP65_DEVICE_ID_XVR16))

/*
 * Check if the given device is a Nvidia's LPC bridge
 */
#define	NVIDIA_IS_LPC_BRIDGE(vid, did) \
	    (((vid) == NVIDIA_VENDOR_ID) && \
	    (NVIDIA_CK804_LPC2PCI_DEVICE_ID(did) || \
	    NVIDIA_MCP55_LPC2PCI_DEVICE_ID(did)))

/* Check for PCIe RC Device ID */
#define	NVIDIA_PCIE_RC_DEV_ID(did) \
	    (((did) == NVIDIA_CK804_DEVICE_ID) || \
	    NVIDIA_C51_DEVICE_ID(did) || \
	    NVIDIA_MCP55_DEVICE_ID(did) || \
	    NVIDIA_MCP61_DEVICE_ID(did) || \
	    NVIDIA_MCP65_DEVICE_ID(did))

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIEX_PCI_NVIDIA_H */

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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Sun4v Platform header file.
 *
 * 	called when :
 *      machine_type ==  Ontario
 *
 */

#ifndef _ONTARIO_H
#define	_ONTARIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	ONTARIO_PLATFORM		"SUNW,Sun-Fire-T200"
#define	ONTARIO_PLATFORM2		"SUNW,SPARC-Enterprise-T2000"
#define	H20_IMPL			0x5678
#define	IS_H20(impl)			((impl) == H20_IMPL)
#define	PCIE_COMP_NUM			20
#define	PCIX_COMP_NUM			20
#define	IOBOARD				"IOBD"
#define	MOTHERBOARD			"MB"
#define	SWITCH_A			"PCI-SWITCH0"
#define	SWITCH_B			"PCI-SWITCH1"
#define	PCI_BRIDGE			"PCI-BRIDGE"
#define	OPHIR				"GBE"
#define	NETWORK				"network"
#define	PCIE				"/PCIE"
#define	PCIX				"/PCIX"
#define	FIRE_PATH0			"/pci@780"
#define	FIRE_PATH1			"/pci@7c0"
#define	SWITCH_A_PATH			"/pci@780/pci@0"
#define	SWITCH_B_PATH			"/pci@7c0/pci@0"
#define	NETWORK_0_PATH			"/pci@780/pci@0/pci@1/network@0"
#define	NETWORK_1_PATH			"/pci@780/pci@0/pci@1/network@0,1"
#define	NETWORK_2_PATH			"/pci@7c0/pci@0/pci@2/network@0"
#define	NETWORK_3_PATH			"/pci@7c0/pci@0/pci@2/network@0,1"
#define	PCIE_SLOT0			"/pci@780/pci@0/pci@8"
#define	PCIE_SLOT1			"/pci@7c0/pci@0/pci@8"
#define	PCIE_SLOT2			"/pci@7c0/pci@0/pci@9"
#define	PCIX_SLOT0			"/pci@7c0/pci@0/pci@1/pci@0,2"
#define	PCIX_SLOT1			"/pci@7c0/pci@0/pci@1/pci@0,2"
#define	ONT_LSI_PATH	  "/pci@7c0/pci@0/pci@1/pci@0,2/LSILogic,sas@2"

/*
 * Property names
 */
#define	OBP_PROP_REG			"reg"
#define	OBP_PROP_CLOCK_FREQ		"clock-frequency"
#define	OBP_PROP_BOARD_NUM		"board#"
#define	OBP_PROP_REVISION_ID		"revision-id"
#define	OBP_PROP_VERSION_NUM		"version#"
#define	OBP_PROP_BOARD_TYPE		"board_type"
#define	OBP_PROP_ECACHE_SIZE		"ecache-size"
#define	OBP_PROP_IMPLEMENTATION		"implementation#"
#define	OBP_PROP_MASK			"mask#"
#define	OBP_PROP_COMPATIBLE		"compatible"
#define	OBP_PROP_BANNER_NAME		"banner-name"
#define	OBP_PROP_MODEL			"model"
#define	OBP_PROP_66MHZ_CAPABLE		"66mhz-capable"
#define	OBP_PROP_FBC_REG_ID		"fbc_reg_id"
#define	OBP_PROP_VERSION		"version"
#define	OBP_PROP_INSTANCE		"instance"

#ifdef __cplusplus
}
#endif

#endif /* _ONTARIO_H */

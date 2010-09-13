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

/*
 * Sun4v Platform header file.
 *
 * 	called when :
 *      machine_type ==  Montoya
 *
 */

#ifndef _MONZA_H
#define	_MONZA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	MONZA_PLATFORM		"SUNW,Netra-CP3260"
#define	MOTHERBOARD		"MB"
#define	IOBOARD			"IO"
#define	RTM			"RTM"
#define	PCIE_SWITCH		"PCI-SWITCH"
#define	PCI_BRIDGE		"PCI-BRIDGE"
#define	OPHIR			"GBE"
#define	PCIE			"/PCIE"
#define	AMC			"AMC"

#define	NETWORK			"network"
#define	ETHERNET		"ethernet"
#define	PCIEX			"pciex"
#define	PCI			"pci"

#define	MONZA_NIU		"/niu@80"
#define	MONZA_PCIE_SWITCH_PATH	"/pci@0/pci@0"

#define	MONZA_N2_XAUI0	"/niu@80/network@0"
#define	MONZA_N2_XAUI1	"/niu@80/network@1"
#define	MONZA_NETWORK_0	"/pci@0/pci@0/pci@9/network@0,1" /* Mgt. port 1 */
#define	MONZA_NETWORK_1	"/pci@0/pci@0/pci@9/network@0" /* Mgt. port 0 */
#define	MONZA_NETWORK_2	"/pci@0/pci@0/pci@2/network@0,1" /* RTM port 1 */
#define	MONZA_NETWORK_3	"/pci@0/pci@0/pci@2/network@0"	/* RTM port 0 */
#define	MONZA_ENET_2	"/pci@0/pci@0/pci@2/ethernet@0,1" /* RTM port 1 */
#define	MONZA_ENET_3	"/pci@0/pci@0/pci@2/ethernet@0"	/* RTM port 0 */
#define	MONZA_NETWORK_4	"/pci@0/pci@0/pci@1/network@0,1" /* Base port 1 */
#define	MONZA_NETWORK_5	"/pci@0/pci@0/pci@1/network@0" /* Base port 0 */

#define	MONZA_USB_0	"/pci@0/pci@0/pci@a/pci@0/usb@4,2"
#define	MONZA_USB_1	"/pci@0/pci@0/pci@a/pci@0/usb@4,1"
#define	MONZA_USB_2	"/pci@0/pci@0/pci@a/pci@0/usb@4"
#define	MONZA_CF_PATH	"/pci@0/pci@0/pci@a/pci@0/usb@4,2/storage@2/disk"
#define	MONZA_RTM_PATH	"/pci@0/pci@0/pci@8"

#define	MONZA_CF_DEVICE	"DISK"

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

#endif /* _MONZA_H */

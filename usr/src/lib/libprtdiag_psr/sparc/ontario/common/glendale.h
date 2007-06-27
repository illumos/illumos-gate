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
 *      machine_type ==  Glendale
 *
 */

#ifndef _GLENDALE_H
#define	_GLENDALE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	MOTHERBOARD			"MB"
#define	SWITCH				"PCI-SWITCH"
#define	PCI_BRIDGE			"PCI-BRIDGE"
#define	OPHIR				"GBE"
#define	USB_TAG				"USB"
#define	USB				"usb"
#define	LSI_SAS				"LSILogic,sas"
#define	DISPLAY				"display"
#define	NETWORK				"network"

#define	HBA_PATH			"/pci@0"
#define	GLENDALE_NIU			"/niu@80"
#define	GLENDALE_N2_XAUI0		"/niu@80/network@0"
#define	GLENDALE_N2_XAUI1		"/niu@80/network@1"
#define	SWITCH_PATH			"/pci@0/pci@0"
#define	GLENDALE_NETWORK_0_PATH		"/pci@0/pci@0/pci@c/network@0"
#define	GLENDALE_NETWORK_1_PATH		"/pci@0/pci@0/pci@c/network@0,1"
#define	GLENDALE_PCIE_PCIEM0		"/pci@0/pci@0/pci@9/"
#define	GLENDALE_PCIE_PCIEM1		"/pci@0/pci@0/pci@8/"
#define	GLENDALE_PCIE_NEM0		"/pci@0/pci@0/pci@d/"
#define	GLENDALE_PCIE_NEM1		"/pci@0/pci@0/pci@e/"

#define	GLENDALE_PCIE2PCI		"/pci@0/pci@0/pci@1/pci@0"
#define	GLENDALE_USB0_PATH		"/pci@0/pci@0/pci@1/pci@0/usb@1"
#define	GLENDALE_USB1_PATH		"/pci@0/pci@0/pci@1/pci@0/usb@1,1"
#define	GLENDALE_USB2_PATH		"/pci@0/pci@0/pci@1/pci@0/usb@1,2"
#define	GLENDALE_USB3_PATH		"/pci@0/pci@0/pci@1/pci@0/usb@2"
#define	GLENDALE_USB4_PATH		"/pci@0/pci@0/pci@1/pci@0/usb@2,1"
#define	GLENDALE_USB5_PATH		"/pci@0/pci@0/pci@1/pci@0/usb@2,2"
#define	GLENDALE_USB6_PATH		"/pci@0/pci@0/pci@1/pci@0/usb@1,2/hub@3"

#define	GLENDALE_DISPLAY_PATH		"/pci@0/pci@0/pci@1/pci@0,2/pci@1"
#define	GLENDALE_DISPLAY		"DISPLAY"
#define	GLENDALE_LSI_PATH		"/pci@0/pci@0/pci@2/LSILogic,sas@0"
#define	GLENDALE_SAS_HBA		"SAS-SATA-HBA"
#define	GLENDALE_SCSI_TAG		"SAS-SATA"
#define	GLENDALE_REM			"REM"
#define	GLENDALE_PCIEM_TYPE		'P'
#define	GLENDALE_NEM_TYPE		'N'

/*
 * Property names
 */
#define	OBP_PROP_REVISION_ID		"revision-id"
#define	OBP_PROP_VERSION_NUM		"version#"
#define	OBP_PROP_COMPATIBLE		"compatible"
#define	OBP_PROP_MODEL			"model"

#ifdef __cplusplus
}
#endif

#endif /* _GLENDALE_H */

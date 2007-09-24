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

#ifndef	_PCIEHPC_NVIDIA_H
#define	_PCIEHPC_NVIDIA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/hotplug/pci/pciehpc_impl.h>

/* soft state data structure specific to CK8-04 */
typedef struct pciehpc_ck804 {
	dev_info_t		*lpcdev; /* dip for LPC Bridge device */
	ddi_acc_handle_t	analog_bar_hdl; /* acc handle for Analog BAR */
	caddr_t			analog_bar_base; /* Analog BAR base */
} pciehpc_ck804_t;

/* vendor/device ids for CK8-04 */
#define	NVIDIA_VENDOR_ID	0x10de
#define	CK804_DEVICE_ID		0x005d
#define	CK804_LPC_BRIDGE_DEVID	0x0051

/* register offsets in Analog Control BAR */
#define	MCP_NVA_TGIO_CTRL	0xCC

/* extended slot control/status registers in PCI config space */
#define	NV_SVR_SLOT_STATUS_REG	0xA4	/* 2 byte ext. status register */
#define	NV_SVR_SLOT_CONTROL_REG	0xA6	/* 2 byte ext. status register */

/* (Backdoor Strapping) Slot Capability Register (read/write) */
#define	NV_XVR_VEND_SLOT_STRAP		0xF20	/* 4 byte */

/* vendor specific register NV_XVR_VEND_XP (4 bytes) in PCI config space */
#define	NV_XVR_VEND_XP		0xF00

/* bit definitions in NV_XVR_VEND_XP regiser */
#define	NV_XVR_VEND_XP_DL_UP	0x40000000

/* bit definitions in NV_XVR_VEND_XP register */
#define	NV_XVR_VEND_SLOT_STRAP_HP_CAPABLE	0x40 /* hot plug capable slot */
#define	SLOT_STRAP_CAPS		0x5B	/* capabilities/features available */

/* bit definitions in Extended Slot Status register */
#define	NV_SVR_SLOT_STS_PWROK	0x0020	/* POWER OK */

/* bit definitions in Extended Slot Control register */
#define	NV_SVR_SLOT_CTRL_SAFE	0x0001	/* safe to assert/release PERST */

/*
 * bit definitions for Reference Clock Control (MCP_NVA_TGIO_CTRL)
 *
 * PE0_REFCLK is for device #E
 * PE1_REFCLK is for device #D
 * PE2_REFCLK is for device #C
 * PE3_REFCLK is for device #B
 */
#define	DISABLE_PEx_REFCLK_DEV_E	0x01	/* disable REFCLK for dev#E */
#define	DISABLE_PEx_REFCLK_DEV_D	0x02	/* disable REFCLK for dev#D */
#define	DISABLE_PEx_REFCLK_DEV_C	0x04 	/* disable REFCLK for dev#C */
#define	DISABLE_PEx_REFCLK_DEV_B	0x08	/* disable REFCLK for dev#B */

#define	ENABLE_REFCLK	0
#define	DISABLE_REFCLK	1


#ifdef	__cplusplus
}
#endif

#endif	/* _PCIEHPC_NVIDIA_H */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCIEX_PCI_CK804_H
#define	_PCIEX_PCI_CK804_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCI Configuration (ck804, PCIe) related library functions
 */
boolean_t	check_if_device_is_pciex(uchar_t, uchar_t, uchar_t,
		    ushort_t *, ushort_t *);
boolean_t	create_pcie_root_bus(uchar_t, dev_info_t *);
void		add_ck804_isa_bridge_props(dev_info_t *, uchar_t, uchar_t,
		    uchar_t);

/*
 * Only for Nvidia's CrushK 8-04 chipsets:
 *	To enable hotplug; we need to map in two I/O BARs
 *	from ISA bridge's config space
 */
#define	NVIDIA_CK804_VENDOR_ID			0x10de	/* Nvidia ck8-04 vid */
#define	NVIDIA_CK804_DEVICE_ID			0x5d	/* ck8-04 dev id */
#define	NVIDIA_CK804_PRO_ISA_BRIDGE_DEVID	0x51	/* LPC Bridge */
#define	NVIDIA_CK804_SLAVE_ISA_BRIDGE_DEVID	0xd3	/* Slave LPC Bridge */
#define	NVIDIA_CK804_ISA_SYSCTRL_BAR_OFF	0x64	/* System Control BAR */
#define	NVIDIA_CK804_ISA_ANALOG_BAR_OFF		0x68	/* Analog BAR */

#define	NVIDIA_CK804_INTR_BCR_OFF		0x3C	/* NV_XVR_INTR_BCR */
#define	NVIDIA_CK804_INTR_BCR_SERR_ENABLE	0x02	/* SERR_ENABLE bit */

/* NV_XVR_VEND_CYA1 related defines */
#define	NVIDIA_CK804_VEND_CYA1_OFF		0xf40	/* NV_XVR_VEND_CYA1 */
#define	NVIDIA_CK804_VEND_CYA1_ERPT_VAL		0x2000	/* enable CYA1 ERPT */
#define	NVIDIA_CK804_VEND_CYA1_ERPT_MASK	0xdfff	/* CYA1 ERPT mask */

/*
 * Check if the given device is a Nvidia's LPC bridge
 */
#define	NVIDIA_IS_LPC_BRIDGE(vid, did) \
	    (((vid) == NVIDIA_CK804_VENDOR_ID) && \
	    (((did) == NVIDIA_CK804_PRO_ISA_BRIDGE_DEVID) || \
	    ((did) == NVIDIA_CK804_SLAVE_ISA_BRIDGE_DEVID)))

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIEX_PCI_CK804_H */

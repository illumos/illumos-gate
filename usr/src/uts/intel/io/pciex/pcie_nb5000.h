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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCIEX_PCI_INTEL_NB5000_H
#define	_PCIEX_PCI_INTEL_NB5000_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	INTEL_VENDOR_ID	0x8086

/*
 * Note: the Chipset MCH devices (i.e. host bridge/mem ctrl) for the chipsets
 * we recognize here also provide a PCIE port for the interconnect to
 * the south bridge (aka ESI bus) that partially acts like a root port.
 */

/*
 * 25c0	5000X Chipset Memory Controller Hub
 * 25d0	5000Z Chipset Memory Controller Hub
 * 25d4	5000V Chipset Memory Controller Hub
 * 25d8	5000P Chipset Memory Controller Hub
 *
 * 25e2	5000 Series Chipset PCI Express x4 Port 2
 * 25e3	5000 Series Chipset PCI Express x4 Port 3
 * 25e4	5000 Series Chipset PCI Express x4 Port 4
 * 25e5	5000 Series Chipset PCI Express x4 Port 5
 * 25e6	5000 Series Chipset PCI Express x4 Port 6
 * 25e7	5000 Series Chipset PCI Express x4 Port 7
 *
 * 25f7	5000 Series Chipset PCI Express x8 Port 2-3
 * 25f8	5000 Series Chipset PCI Express x8 Port 4-5
 * 25f9	5000 Series Chipset PCI Express x8 Port 6-7
 * 25fa	5000X Chipset PCI Express x16 Port 4-7
 */
#define	INTEL_5000_PCIE_DEV_ID(did) \
	((did) == 0x25c0 || \
	(did) == 0x25d0 || \
	(did) == 0x25d4 || \
	(did) == 0x25d8 || \
	((did) >= 0x25e2 && (did) <= 0x25e7) || \
	((did) >= 0x25f7 && (did) <= 0x25fa))

/*
 * 3600	7300 Chipset Memory Controller Hub
 * 3604	7300 Chipset PCI Express Port 1
 * 3605	7300 Chipset PCI Express Port 2
 * 3606	7300 Chipset PCI Express Port 3
 * 3607	7300 Chipset PCI Express Port 4
 * 3608	7300 Chipset PCI Express Port 5
 * 3609	7300 Chipset PCI Express Port 6
 * 360a	7300 Chipset PCI Express Port 7
 */
#define	INTEL_7300_PCIE_DEV_ID(did) ((did) >= 0x3600 && (did) <= 0x360a)

#define	INTEL_NB5000_PCIE_DEV_ID(did) \
	(INTEL_5000_PCIE_DEV_ID(did) || INTEL_7300_PCIE_DEV_ID(did))

/*
 * Chipset specific registers
 */
#define	INTEL_7300_PEXCTRL		0x48	/* PCIE Control Register */
#define	INTEL_7300_PEXCTRL_HPINB	0x20000000 /* Inband HP msgs */
#define	INTEL_7300_PEXCTRL_MSINFAT	0x40000000 /* nonfatal error MSI */
#define	INTEL_7300_PEXCTRL_MSICOR	0x80000000 /* correctable error MSI */

#define	INTEL_7300_PEXCTRL3		0x4D	/* PCIE Control Register 3 */
#define	INTEL_7300_PEXCTRL3_MSIRAS	0x1	/* MSI for PCIE err enable */

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIEX_PCI_INTEL_NB5000_H */

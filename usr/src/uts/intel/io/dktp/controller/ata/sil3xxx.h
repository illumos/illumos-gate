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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SIL3XXX_H
#define	_SIL3XXX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCI IDs
 */
#define	SILICON_IMAGE_VENDOR_ID	0x1095
#define	SIL3112_DEVICE_ID	0x3112
#define	SIL3114_DEVICE_ID	0x3114
#define	SIL3512_DEVICE_ID	0x3512

/* Base Register 5 Indirect Address Offset */

#define	PCI_CONF_BA5_IND_ADDRESS	0xc0
#define	PCI_CONF_BA5_IND_ACCESS		0xc4

/*
 * FIS Configuration channel offsets
 * Sil3114 has 4 channels
 * Sil3112 has 2 channels
 * Sil3512 has 2 channels
 */
#define	SFISCFG_0	0x14c	/* SFISCfg Channel 0 */
#define	SFISCFG_1	0x1cc	/* SFISCfg Channel 1 */
#define	SFISCFG_2	0x34c	/* SFISCfg Channel 2 */
#define	SFISCFG_3	0x3cc	/* SFISCfg Channel 3 */

/*
 * FIFO count and contrl offsets for channel 0-4
 */
#define	FIFO_CNTCTL_0 0x40
#define	FIFO_CNTCTL_1 0x44
#define	FIFO_CNTCTL_2 0x240
#define	FIFO_CNTCTL_3 0x244

/*
 * Errata Sil-AN-0028-C (Sil3512 Rev 0.3)
 * Errata Sil-AN-0109-B2 (Sil3114 Rev 0.3)
 * To prevent erroneous ERR set for queued DMA transfers
 * greater then 8k, FIS reception for FIS0cfg needs to be set
 * to Accept FIS without Interlock
 * Default SFISCfg value of 0x10401555 in channel SFISCfg
 * register need to be changed to 0x10401554.
 */
#define	SFISCFG_ERRATA	0x10401554


#define	PUT_BAR5_INDIRECT(handle, address, value) \
{\
		pci_config_put32(handle, PCI_CONF_BA5_IND_ADDRESS, address); \
		pci_config_put32(handle, PCI_CONF_BA5_IND_ACCESS, value); \
}

#define	GET_BAR5_INDIRECT(handle, address, rval) \
{\
		pci_config_put32(handle, PCI_CONF_BA5_IND_ADDRESS, address); \
		rval = pci_config_get32(handle, PCI_CONF_BA5_IND_ACCESS); \
}

uint_t	sil3xxx_init_controller(dev_info_t *, ushort_t, ushort_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SIL3XXX_H */

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

#ifndef	_SYS_PCI_CFGACC_X86_H
#define	_SYS_PCI_CFGACC_X86_H

#ifdef	__cplusplus
extern "C" {
#endif

/* AMD's northbridges vendor-id and device-ids */
#define	AMD_NTBRDIGE_VID		0x1022	/* AMD vendor-id */
#define	AMD_HT_NTBRIDGE_DID		0x1100	/* HT Configuration */
#define	AMD_AM_NTBRIDGE_DID		0x1101	/* Address Map */
#define	AMD_DC_NTBRIDGE_DID		0x1102	/* DRAM Controller */
#define	AMD_MC_NTBRIDGE_DID		0x1103	/* Misc Controller */
#define	AMD_K10_NTBRIDGE_DID_0		0x1200
#define	AMD_K10_NTBRIDGE_DID_1		0x1201
#define	AMD_K10_NTBRIDGE_DID_2		0x1202
#define	AMD_K10_NTBRIDGE_DID_3		0x1203
#define	AMD_K10_NTBRIDGE_DID_4		0x1204

/* AMD's 8132 chipset vendor-id and device-ids */
#define	AMD_8132_BRIDGE_DID		0x7458	/* 8132 PCI-X bridge */
#define	AMD_8132_IOAPIC_DID		0x7459	/* 8132 IO APIC */

/*
 * Check if the given device is an AMD northbridge
 */
#define	IS_BAD_AMD_NTBRIDGE(vid, did) \
	    (((vid) == AMD_NTBRDIGE_VID) && \
	    (((did) == AMD_HT_NTBRIDGE_DID) || \
	    ((did) == AMD_AM_NTBRIDGE_DID) || \
	    ((did) == AMD_DC_NTBRIDGE_DID) || \
	    ((did) == AMD_MC_NTBRIDGE_DID)))

#define	IS_K10_AMD_NTBRIDGE(vid, did) \
	    (((vid) == AMD_NTBRDIGE_VID) && \
	    (((did) == AMD_K10_NTBRIDGE_DID_0) || \
	    ((did) == AMD_K10_NTBRIDGE_DID_1) || \
	    ((did) == AMD_K10_NTBRIDGE_DID_2) || \
	    ((did) == AMD_K10_NTBRIDGE_DID_3) || \
	    ((did) == AMD_K10_NTBRIDGE_DID_4)))

#define	IS_AMD_8132_CHIP(vid, did) \
	    (((vid) == AMD_NTBRDIGE_VID) && \
	    (((did) == AMD_8132_BRIDGE_DID)) || \
	    (((did) == AMD_8132_IOAPIC_DID)))

#define	MSR_AMD_NB_MMIO_CFG_BADDR	0xc0010058
#define	AMD_MMIO_CFG_BADDR_ADDR_MASK	0xFFFFFFF00000ULL
#define	AMD_MMIO_CFG_BADDR_ENA_MASK	0x000000000001ULL
#define	AMD_MMIO_CFG_BADDR_ENA_ON	0x000000000001ULL
#define	AMD_MMIO_CFG_BADDR_ENA_OFF	0x000000000000ULL

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_CFGACC_X86_H */

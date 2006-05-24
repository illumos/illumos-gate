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

#ifndef _SYS_PCIPSY_H
#define	_SYS_PCIPSY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Performance counters information.
 */
#define	PSYCHO_SHIFT_PIC0	8
#define	PSYCHO_SHIFT_PIC1	0

/*
 * Psycho-specific register offsets & bit field positions.
 */

/*
 * Offsets of global registers:
 */
#define	PSYCHO_CB_DEVICE_ID_REG_OFFSET		0x00000000
#define	PSYCHO_CB_CONTROL_STATUS_REG_OFFSET	0x00000010

/*
 * psycho performance counters offsets.
 */
#define	PSYCHO_PERF_PCR_OFFSET			0x00000100
#define	PSYCHO_PERF_PIC_OFFSET			0x00000108

/*
 * Offsets of registers in the interrupt block:
 */
#define	PSYCHO_IB_SLOT_INTR_MAP_REG_OFFSET	0x00000C00
#define	PSYCHO_IB_OBIO_INTR_MAP_REG_OFFSET	0x00001000
#define	PSYCHO_IB_OBIO_CLEAR_INTR_REG_OFFSET	0x00001800

/*
 * Offsets of registers in the PBM block:
 */
#define	PSYCHO_PCI_PBM_REG_BASE			0x00002000
#define	PSYCHO_PCI_CTRL_REG_OFFSET		0x00000000
#define	PSYCHO_PCI_ASYNC_FLT_STATUS_REG_OFFSET	0x00000010
#define	PSYCHO_PCI_ASYNC_FLT_ADDR_REG_OFFSET	0x00000018
#define	PSYCHO_PCI_DIAG_REG_OFFSET		0x00000020

/*
 * Offsets of registers in the streaming cache block:
 */
#define	PSYCHO_SC_CTRL_REG_OFFSET		0x00000800
#define	PSYCHO_SC_INVL_REG_OFFSET		0x00000808
#define	PSYCHO_SC_SYNC_REG_OFFSET		0x00000810
#define	PSYCHO_SC_A_DATA_DIAG_OFFSET		0x0000b000
#define	PSYCHO_SC_A_TAG_DIAG_OFFSET		0x0000b800
#define	PSYCHO_SC_A_LTAG_DIAG_OFFSET		0x0000b900
#define	PSYCHO_SC_B_DATA_DIAG_OFFSET		0x0000c000
#define	PSYCHO_SC_B_TAG_DIAG_OFFSET		0x0000c800
#define	PSYCHO_SC_B_LTAG_DIAG_OFFSET		0x0000c900

/*
 * Address space offsets and sizes:
 */
#define	PSYCHO_PCI_CONFIG			0x001000000ull
#define	PSYCHO_PCI_A_IO				0x002000000ull
#define	PSYCHO_PCI_B_IO				0x002010000ull
#define	PSYCHO_PCI_A_MEMORY			0x100000000ull
#define	PSYCHO_PCI_B_MEMORY			0x180000000ull
#define	PSYCHO_PCI_IO_SIZE			0x000010000ull
#define	PSYCHO_PCI_MEM_SIZE			0x080000000ull

/*
 * psycho control register bit definitions:
 */
#define	PSYCHO_CB_CONTROL_STATUS_MODE		0x0000000000000001ull
#define	PSYCHO_CB_CONTROL_STATUS_IMPL		0xf000000000000000ull
#define	PSYCHO_CB_CONTROL_STATUS_IMPL_SHIFT	60
#define	PSYCHO_CB_CONTROL_STATUS_VER		0x0f00000000000000ull
#define	PSYCHO_CB_CONTROL_STATUS_VER_SHIFT	56

/*
 * psycho ECC UE AFSR bit definitions:
 */
#define	PSYCHO_ECC_UE_AFSR_BYTEMASK		0x0000ffff00000000ull
#define	PSYCHO_ECC_UE_AFSR_BYTEMASK_SHIFT	32
#define	PSYCHO_ECC_UE_AFSR_DW_OFFSET		0x00000000e0000000ull
#define	PSYCHO_ECC_UE_AFSR_DW_OFFSET_SHIFT	29
#define	PSYCHO_ECC_UE_AFSR_ID			0x000000001f000000ull
#define	PSYCHO_ECC_UE_AFSR_ID_SHIFT		24
#define	PSYCHO_ECC_UE_AFSR_BLK			0x0000000000800000ull

/*
 * psycho ECC CE AFSR bit definitions:
 */
#define	PSYCHO_ECC_CE_AFSR_SYND			0x00ff000000000000ull
#define	PSYCHO_ECC_CE_AFSR_SYND_SHIFT		48
#define	PSYCHO_ECC_CE_AFSR_BYTEMASK		0x0000ffff00000000ull
#define	PSYCHO_ECC_CE_AFSR_BYTEMASK_SHIFT	32
#define	PSYCHO_ECC_CE_AFSR_DW_OFFSET		0x00000000e0000000ull
#define	PSYCHO_ECC_CE_AFSR_DW_OFFSET_SHIFT	29
#define	PSYCHO_ECC_CE_AFSR_UPA_MID		0x000000001f000000ull
#define	PSYCHO_ECC_CE_AFSR_UPA_MID_SHIFT	24
#define	PSYCHO_ECC_CE_AFSR_BLK			0x0000000000800000ull

/*
 * psycho pci control register bits:
 */
#define	PSYCHO_PCI_CTRL_ARB_PARK		0x0000000000200000ull
#define	PSYCHO_PCI_CTRL_SBH_INT_EN		0x0000000000000400ull
#define	PSYCHO_PCI_CTRL_WAKEUP_EN		0x0000000000000200ull
#define	PSYCHO_PCI_CTRL_ERR_INT_EN		0x0000000000000100ull
#define	PSYCHO_PCI_CTRL_ARB_EN_MASK		0x000000000000000full

/*
 * psycho PCI asynchronous fault status register bit definitions:
 */
#define	PSYCHO_PCI_AFSR_PE_SHIFT		60
#define	PSYCHO_PCI_AFSR_SE_SHIFT		56
#define	PSYCHO_PCI_AFSR_E_MA			0x0000000000000008ull
#define	PSYCHO_PCI_AFSR_E_TA			0x0000000000000004ull
#define	PSYCHO_PCI_AFSR_E_RTRY			0x0000000000000002ull
#define	PSYCHO_PCI_AFSR_E_PERR			0x0000000000000001ull
#define	PSYCHO_PCI_AFSR_E_MASK			0x000000000000000full
#define	PSYCHO_PCI_AFSR_BYTEMASK		0x0000ffff00000000ull
#define	PSYCHO_PCI_AFSR_BYTEMASK_SHIFT		32
#define	PSYCHO_PCI_AFSR_BLK			0x0000000080000000ull
#define	PSYCHO_PCI_AFSR_MID			0x000000003e000000ull
#define	PSYCHO_PCI_AFSR_MID_SHIFT		25

/*
 * psycho PCI diagnostic register bit definitions:
 */
#define	PSYCHO_PCI_DIAG_DIS_DWSYNC		0x0000000000000010ull

#define	PBM_AFSR_TO_PRIERR(afsr)	\
	(afsr >> PSYCHO_PCI_AFSR_PE_SHIFT & PSYCHO_PCI_AFSR_E_MASK)
#define	PBM_AFSR_TO_SECERR(afsr)	\
	(afsr >> PSYCHO_PCI_AFSR_SE_SHIFT & PSYCHO_PCI_AFSR_E_MASK)
#define	PBM_AFSR_TO_BYTEMASK(afsr)	\
	((afsr & PSYCHO_PCI_AFSR_BYTEMASK) >> PSYCHO_PCI_AFSR_BYTEMASK_SHIFT)

#define	PCI_BRIDGE_TYPE(cmn_p) PCI_PSYCHO
/*
 * for sabre
 */
#define	DMA_WRITE_SYNC_REG			0x1C20

extern uint_t cb_thermal_intr(caddr_t a);

#define	PCI_ID_TO_IGN(pci_id)		((pci_ign_t)UPAID_TO_IGN(pci_id))

/*
 * The following macro defines the 40-bit bus width support for UPA bus
 * in DVMA and iommu bypass transfers:
 */

#define	UPA_IOMMU_BYPASS_END		0xFFFC00FFFFFFFFFFull

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIPSY_H */

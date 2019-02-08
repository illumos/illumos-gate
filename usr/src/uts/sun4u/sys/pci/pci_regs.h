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
 * Copyright 2019 Peter Tribble.
 */

#ifndef _SYS_PCI_REGS_H
#define	_SYS_PCI_REGS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Offsets of registers in the interrupt block:
 */

#define	COMMON_IB_UPA0_INTR_MAP_REG_OFFSET	0x6000
#define	COMMON_IB_UPA1_INTR_MAP_REG_OFFSET	0x8000
#define	COMMON_IB_SLOT_INTR_STATE_DIAG_REG	0xA800
#define	COMMON_IB_OBIO_INTR_STATE_DIAG_REG	0xA808
#define	COMMON_IB_SLOT_CLEAR_INTR_REG_OFFSET	0x1400
#define	COMMON_IB_INTR_RETRY_TIMER_OFFSET	0x1A00

/*
 * Offsets of registers in the ECC block:
 */
#define	COMMON_ECC_CSR_OFFSET			0x20
#define	COMMON_UE_AFSR_OFFSET			0x30
#define	COMMON_UE_AFAR_OFFSET			0x38
#define	COMMON_CE_AFSR_OFFSET			0x40
#define	COMMON_CE_AFAR_OFFSET			0x48

/*
 * Offsets of registers in the iommu block:
 */
#define	COMMON_IOMMU_CTRL_REG_OFFSET		0x00000200
#define	COMMON_IOMMU_TSB_BASE_ADDR_REG_OFFSET	0x00000208
#define	COMMON_IOMMU_FLUSH_PAGE_REG_OFFSET	0x00000210

#define	COMMON_IOMMU_TLB_TAG_DIAG_ACC_OFFSET	0x0000A580
#define	COMMON_IOMMU_TLB_DATA_DIAG_ACC_OFFSET	0x0000A600

/*
 * (psycho and schizo) control register bit definitions:
 */
#define	COMMON_CB_CONTROL_STATUS_APCKEN		0x0000000000000008ull
#define	COMMON_CB_CONTROL_STATUS_APERR		0x0000000000000004ull
#define	COMMON_CB_CONTROL_STATUS_IAP		0x0000000000000002ull

/*
 * (psycho and schizo) interrupt mapping register bit definitions:
 */
#define	COMMON_INTR_MAP_REG_VALID		0x0000000080000000ull
#define	COMMON_INTR_MAP_REG_TID			0x000000007C000000ull
#define	COMMON_INTR_MAP_REG_IGN			0x00000000000007C0ull
#define	COMMON_INTR_MAP_REG_INO			0x000000000000003full
#define	COMMON_INTR_MAP_REG_TID_SHIFT		26
#define	COMMON_INTR_MAP_REG_IGN_SHIFT		6

/*
 * psycho clear interrupt register bit definitions:
 */
#define	COMMON_CLEAR_INTR_REG_MASK		0x0000000000000003ull
#define	COMMON_CLEAR_INTR_REG_IDLE		0x0000000000000000ull
#define	COMMON_CLEAR_INTR_REG_RECEIVED		0x0000000000000001ull
#define	COMMON_CLEAR_INTR_REG_RSVD		0x0000000000000002ull
#define	COMMON_CLEAR_INTR_REG_PENDING		0x0000000000000003ull

/*
 * psycho and schizo ECC control register bit definitions:
 */
#define	COMMON_ECC_CTRL_ECC_EN			0x8000000000000000ull
#define	COMMON_ECC_CTRL_UE_INTEN		0x4000000000000000ull
#define	COMMON_ECC_CTRL_CE_INTEN		0x2000000000000000ull

/*
 * sabre ECC UE AFSR bit definitions:
 */
#define	SABRE_UE_AFSR_SDTE_SHIFT		57
#define	SABRE_UE_AFSR_PDTE_SHIFT		56
#define	SABRE_UE_ARSR_DTE_MASK			0x0000000000000003ull
#define	SABRE_UE_AFSR_E_SDTE			0x2
#define	SABRE_UE_AFSR_E_PDTE			0x1

/*
 * psycho and schizo ECC UE AFSR bit definitions:
 */
#define	COMMON_ECC_UE_AFSR_PE_SHIFT		61
#define	COMMON_ECC_UE_AFSR_SE_SHIFT		58
#define	COMMON_ECC_UE_AFSR_E_MASK		0x0000000000000007ull

/*
 * psycho and schizo ECC CE AFSR bit definitions:
 */
#define	COMMON_ECC_CE_AFSR_PE_SHIFT		61
#define	COMMON_ECC_CE_AFSR_SE_SHIFT		58
#define	COMMON_ECC_CE_AFSR_E_MASK		0x0000000000000007ull

/*
 * psycho and schizo ECC CE/UE AFSR bit definitions for error types:
 */
#define	COMMON_ECC_AFSR_E_PIO			0x0000000000000004ull
#define	COMMON_ECC_AFSR_E_DRD			0x0000000000000002ull
#define	COMMON_ECC_AFSR_E_DWR			0x0000000000000001ull

/*
 * psycho and schizo pci control register bits:
 */
#define	COMMON_PCI_CTRL_SBH_ERR			0x0000000800000000ull
#define	COMMON_PCI_CTRL_SERR			0x0000000400000000ull
#define	COMMON_PCI_CTRL_SPEED			0x0000000200000000ull

/*
 * psycho and schizo PCI diagnostic register bit definitions:
 */
#define	COMMON_PCI_DIAG_DIS_RETRY		0x0000000000000040ull
#define	COMMON_PCI_DIAG_DIS_INTSYNC		0x0000000000000020ull

/*
 * psycho and schizo IOMMU control register bit definitions:
 */
#define	COMMON_IOMMU_CTRL_ENABLE	0x0000000000000001ull
#define	COMMON_IOMMU_CTRL_DIAG_ENABLE	0x0000000000000002ull
#define	COMMON_IOMMU_CTRL_TSB_SZ_SHIFT	16
#define	COMMON_IOMMU_CTRL_TBW_SZ_SHIFT	2
#define	COMMON_IOMMU_CTRL_LCK_ENABLE	0x0000000000800000ull

/*
 * psycho and schizo streaming cache control register bit definitions:
 */
#define	COMMON_SC_CTRL_ENABLE		0x0000000000000001ull
#define	COMMON_SC_CTRL_DIAG_ENABLE	0x0000000000000002ull
#define	COMMON_SC_CTRL_RR__DISABLE	0x0000000000000004ull
#define	COMMON_SC_CTRL_LRU_LE		0x0000000000000008ull

/*
 * offsets of PCI address spaces from base address:
 */
#define	PCI_CONFIG			0x001000000ull
#define	PCI_A_IO			0x002000000ull
#define	PCI_B_IO			0x002010000ull
#define	PCI_A_MEMORY			0x100000000ull
#define	PCI_B_MEMORY			0x180000000ull
#define	PCI_IO_SIZE			0x000010000ull
#define	PCI_MEM_SIZE			0x080000000ull

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_REGS_H */

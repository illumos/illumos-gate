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

#ifndef _SYS_PCISCH_H
#define	_SYS_PCISCH_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Performance counters information.
 */
#define	SCHIZO_SHIFT_PIC0	4
#define	SCHIZO_SHIFT_PIC1	11

/*
 * Schizo-specific register offsets & bit field positions.
 */

/*
 * [msb]				[lsb]
 * 0x00 <chip_type> <version#> <module-revision#>
 */
#define	SCHIZO_VER_10		CHIP_ID(PCI_CHIP_SCHIZO, 0x00, 0x00)
#define	SCHIZO_VER_20		CHIP_ID(PCI_CHIP_SCHIZO, 0x02, 0x00)
#define	SCHIZO_VER_21		CHIP_ID(PCI_CHIP_SCHIZO, 0x03, 0x00)
#define	SCHIZO_VER_22		CHIP_ID(PCI_CHIP_SCHIZO, 0x04, 0x00)
#define	SCHIZO_VER_23		CHIP_ID(PCI_CHIP_SCHIZO, 0x05, 0x00)
#define	SCHIZO_VER_24		CHIP_ID(PCI_CHIP_SCHIZO, 0x06, 0x00)
#define	SCHIZO_VER_25		CHIP_ID(PCI_CHIP_SCHIZO, 0x07, 0x00)
#define	XMITS_VER_10		CHIP_ID(PCI_CHIP_XMITS, 0x05, 0x01)
#define	XMITS_VER_21		CHIP_ID(PCI_CHIP_XMITS, 0x05, 0x03)
#define	XMITS_VER_30		CHIP_ID(PCI_CHIP_XMITS, 0x05, 0x04)
#define	TOMATILLO_VER_10	CHIP_ID(PCI_CHIP_TOMATILLO, 0x00, 0x00)
#define	TOMATILLO_VER_20	CHIP_ID(PCI_CHIP_TOMATILLO, 0x01, 0x00)
#define	TOMATILLO_VER_21	CHIP_ID(PCI_CHIP_TOMATILLO, 0x02, 0x00)
#define	TOMATILLO_VER_22	CHIP_ID(PCI_CHIP_TOMATILLO, 0x03, 0x00)
#define	TOMATILLO_VER_23	CHIP_ID(PCI_CHIP_TOMATILLO, 0x04, 0x00)
#define	TOMATILLO_VER_24	CHIP_ID(PCI_CHIP_TOMATILLO, 0X05, 0X00)

/*
 * Offsets of Control Block registers ("reg" property 2nd entry)
 */
#define	SCHIZO_CB_CSR_OFFSET			0x0	/* reg 1 */
#define	SCHIZO_CB_ERRCTRL_OFFSET		0x8
#define	SCHIZO_CB_INTCTRL_OFFSET		0x10
#define	SCHIZO_CB_ERRLOG_OFFSET			0x18
#define	SCHIZO_CB_ECCCTRL_OFFSET		0x20
#define	SCHIZO_CB_UEAFSR_OFFSET			0x30
#define	SCHIZO_CB_UEAFAR_OFFSET			0x38
#define	SCHIZO_CB_CEAFSR_OFFSET			0x40
#define	SCHIZO_CB_CEAFAR_OFFSET			0x48
#define	SCHIZO_CB_ESTRCTRL_OFFSET		0x50
#define	XMITS_CB_SOFT_PAUSE_OFFSET		0x58
#define	XMITS_CB_IO_LOOPBACK_CONTROL_OFFSET	0x60
#define	XMITS_CB_SAF_PED_CONTROL_OFFSET		0x68
#define	XMITS_CB_SAF_PED_LOG_OFFSET		0x70
#define	XMITS_CB_SAF_PAR_INJECT_IMM_OFFSET	0x78
#define	XMITS_CB_SAF_PAR_INJECT_1_OFFSET	0x80
#define	XMITS_CB_SAF_PAR_INJECT_0_OFFSET	0x88
#define	XMITS_CB_FIRST_ERROR_LOG		0x90
#define	XMITS_CB_FIRST_ERROR_ADDR		0x98
#define	XMITS_CB_PCI_LEAF_STATUS		0xA0

/*
 * Tomatillo only bits in IOMMU control registers.
 */
#define	TOMATILLO_IOMMU_SEG_DISP_SHIFT		4
#define	TOMATILLO_IOMMU_TSB_MAX			7
#define	TOMATIILO_IOMMU_ERR_REG_SHIFT		24
#define	TOMATILLO_IOMMU_ERRSTS_SHIFT		25
#define	TOMATILLO_IOMMU_ERR			(1ull << 24)
#define	TOMATILLO_IOMMU_ERRSTS			(3ull << 25)
#define	TOMATILLO_IOMMU_ERR_ILLTSBTBW		(1ull << 27)
#define	TOMATILLO_IOMMU_ERR_BAD_VA		(1ull << 28)

#define	TOMATILLO_IOMMU_PROTECTION_ERR		0x0
#define	TOMATILLO_IOMMU_INVALID_ERR		0x1
#define	TOMATILLO_IOMMU_TIMEOUT_ERR		0x2
#define	TOMATILLO_IOMMU_ECC_ERR			0x3

/*
 * Offsets of performance monitoring registers.
 */
#define	SCHIZO_PERF_PCI_PCR_OFFSET		0x00000100
#define	SCHIZO_PERF_PCI_PIC_OFFSET		0x00000108
#define	SCHIZO_PERF_PCI_ICD_OFFSET		0x00000110
#define	SCHIZO_PERF_SAF_PCR_OFFSET		0x00007000
#define	SCHIZO_PERF_SAF_PIC_OFFSET		0x00007008

/*
 * Offsets of registers in the PBM block:
 */
#define	SCHIZO_PCI_CTRL_REG_OFFSET		0x2000
#define	SCHIZO_PCI_ASYNC_FLT_STATUS_REG_OFFSET	0x2010
#define	SCHIZO_PCI_ASYNC_FLT_ADDR_REG_OFFSET	0x2018
#define	SCHIZO_PCI_DIAG_REG_OFFSET		0x2020
#define	SCHIZO_PCI_ESTAR_REG_OFFSET		0x2028
#define	TOMATILLO_TGT_ADDR_SPACE_OFFSET		0x2490
#define	TOMATILLO_TGT_ERR_VALOG_OFFSET		0x2498

#define	XMITS10_PCI_X_ERROR_STATUS_REG_OFFSET	0x2030
#define	XMITS10_PCI_X_DIAG_REG_OFFSET		0x2038
#define	XMITS_PCI_X_ERROR_STATUS_REG_OFFSET	0x2300
#define	XMITS_PCI_X_DIAG_REG_OFFSET		0x2308
#define	XMITS_PARITY_DETECT_REG_OFFSET		0x2040
#define	XMITS_PARITY_LOG_REG_OFFSET		0x2048
#define	XMITS_PARITY_INJECT_REG_OFFSET		0x2050
#define	XMITS_PARITY_INJECT_1_REG_OFFSET	0x2058
#define	XMITS_PARITY_INJECT_0_REG_OFFSET	0x2060
#define	XMITS_UPPER_RETRY_COUNTER_REG_OFFSET	0x2310

/*
 * Offsets of IO Cache Registers:
 */
#define	TOMATILLO_IOC_CSR_OFF			0x2248
#define	TOMATILLO_IOC_TAG_OFF			0x2250
#define	TOMATIILO_IOC_DAT_OFF			0x2290

/*
 * Offsets of registers in the iommu block:
 */
#define	SCHIZO_IOMMU_FLUSH_CTX_REG_OFFSET	0x00000218
#define	TOMATILLO_IOMMU_ERR_TFAR_OFFSET		0x0220

/*
 * Offsets of registers in the streaming cache block:
 */
#define	SCHIZO_SC_CTRL_REG_OFFSET		0x00002800
#define	SCHIZO_SC_INVL_REG_OFFSET		0x00002808
#define	SCHIZO_SC_SYNC_REG_OFFSET		0x00002810
#define	SCHIZO_SC_CTX_INVL_REG_OFFSET		0x00002818
#define	SCHIZO_SC_CTX_MATCH_REG_OFFSET		0x00010000
#define	SCHIZO_SC_DATA_DIAG_OFFSET		0x0000b000
#define	SCHIZO_SC_TAG_DIAG_OFFSET		0x0000ba00
#define	SCHIZO_SC_LTAG_DIAG_OFFSET		0x0000bb00

/*
 * MAX_PRF when enabled will always prefetch the max of 8
 * prefetches if possible.
 */
#define	XMITS_SC_MAX_PRF			(0x1ull << 7)

/*
 * Offsets of registers in the PCI Idle Check Diagnostics Register.
 */
#define	SCHIZO_PERF_PCI_ICD_DMAW_PARITY_INT_ENABLE	0x4000
#define	SCHIZO_PERF_PCI_ICD_PCI_2_0_COMPATIBLE		0x8000

/*
 * Offsets of registers in the interrupt block:
 */
#define	SCHIZO_IB_SLOT_INTR_MAP_REG_OFFSET	0x1100
#define	SCHIZO_IB_INTR_MAP_REG_OFFSET		0x1000
#define	SCHIZO_IB_CLEAR_INTR_REG_OFFSET		0x1400
#define	SCHIZO_PBM_DMA_SYNC_REG_OFFSET		0x1A08
#define	PBM_DMA_SYNC_COMP_REG_OFFSET		0x1A10
#define	PBM_DMA_SYNC_PEND_REG_OFFSET		0x1A18

/*
 * Address space offsets and sizes:
 */
#define	SCHIZO_SIZE				0x0000800000000000ull

/*
 * Schizo-specific fields of interrupt mapping register:
 */
#define	SCHIZO_INTR_MAP_REG_NID			0x0000000003E00000ull
#define	SCHIZO_INTR_MAP_REG_NID_SHIFT		21

/*
 * schizo ECC UE AFSR bit definitions:
 */
#define	SCHIZO_ECC_UE_AFSR_ERRPNDG		0x0300000000000000ull
#define	SCHIZO_ECC_UE_AFSR_MASK			0x000003ff00000000ull
#define	SCHIZO_ECC_UE_AFSR_MASK_SHIFT		32
#define	SCHIZO_ECC_UE_AFSR_QW_OFFSET		0x00000000C0000000ull
#define	SCHIZO_ECC_UE_AFSR_QW_OFFSET_SHIFT	30
#define	SCHIZO_ECC_UE_AFSR_AGENT_MID		0x000000001f000000ull
#define	SCHIZO_ECC_UE_AFSR_AGENT_MID_SHIFT	24
#define	SCHIZO_ECC_UE_AFSR_PARTIAL		0x0000000000800000ull
#define	SCHIZO_ECC_UE_AFSR_OWNED_IN		0x0000000000400000ull
#define	SCHIZO_ECC_UE_AFSR_MTAG_SYND		0x00000000000f0000ull
#define	SCHIZO_ECC_UE_AFSR_MTAG_SYND_SHIFT	16
#define	SCHIZO_ECC_UE_AFSR_MTAG			0x000000000000e000ull
#define	SCHIZO_ECC_UE_AFSR_MTAG_SHIFT		13
#define	SCHIZO_ECC_UE_AFSR_SYND			0x00000000000001ffull
#define	SCHIZO_ECC_UE_AFSR_SYND_SHIFT		0

/*
 * schizo ECC CE AFSR bit definitions:
 */
#define	SCHIZO_ECC_CE_AFSR_ERRPNDG		0x0300000000000000ull
#define	SCHIZO_ECC_CE_AFSR_MASK			0x000003ff00000000ull
#define	SCHIZO_ECC_CE_AFSR_MASK_SHIFT		32
#define	SCHIZO_ECC_CE_AFSR_QW_OFFSET		0x00000000C0000000ull
#define	SCHIZO_ECC_CE_AFSR_QW_OFFSET_SHIFT	30
#define	SCHIZO_ECC_CE_AFSR_AGENT_MID		0x000000001f000000ull
#define	SCHIZO_ECC_CE_AFSR_AGENT_MID_SHIFT	24
#define	SCHIZO_ECC_CE_AFSR_PARTIAL		0x0000000000800000ull
#define	SCHIZO_ECC_CE_AFSR_OWNED_IN		0x0000000000400000ull
#define	SCHIZO_ECC_CE_AFSR_MTAG_SYND		0x00000000000f0000ull
#define	SCHIZO_ECC_CE_AFSR_MTAG_SYND_SHIFT	16
#define	SCHIZO_ECC_CE_AFSR_MTAG			0x000000000000e000ull
#define	SCHIZO_ECC_CE_AFSR_MTAG_SHIFT		13
#define	SCHIZO_ECC_CE_AFSR_SYND			0x00000000000001ffull
#define	SCHIZO_ECC_CE_AFSR_SYND_SHIFT		0

/*
 * schizo ECC UE/CE AFAR bit definitions:
 */
#define	SCHIZO_ECC_AFAR_IO_TXN			0x0000080000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_MASK		0x0000078000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_UPA64S		0x0000078000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_NL_REG		0x0000040000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_NL			0x0000050000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_NL_ALT		0x0000051000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_PCIA_REG		0x0000020000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_PCIA_MEM		0x0000030000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_PCIA_CFGIO		0x0000031000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_PCIB_REG		0x0000000000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_PCIB_MEM		0x0000010000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_PCIB_CFGIO		0x0000011000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_SAFARI_REGS	0x0000060000000000ull
#define	SCHIZO_ECC_AFAR_PIOW_ADDR_MASK		0x0000000fffffffffull
#define	SCHIZO_ECC_AFAR_ADDR_MASK		0x000007ffffffffffull

/*
 * schizo pci control register bits:
 */
#define	SCHIZO_PCI_CTRL_BUS_UNUSABLE		(1ull << 63)
#define	TOMATILLO_PCI_CTRL_PCI_DTO_ERR		(1ull << 62)
#define	TOMATILLO_PCI_CTRL_DTO_INT_EN		(1ull << 61)
#define	SCHIZO_PCI_CTRL_ERR_SLOT_LOCK		(1ull << 51)
#define	SCHIZO_PCI_CTRL_ERR_SLOT		(7ull << 48)
#define	SCHIZO_PCI_CTRL_ERR_SLOT_SHIFT		48
#define	SCHIZO_PCI_CTRL_PCI_TTO_ERR		(1ull << 38)
#define	SCHIZO_PCI_CTRL_PCI_RTRY_ERR		(1ull << 37)
#define	SCHIZO_PCI_CTRL_PCI_MMU_ERR		(1ull << 36)
#define	TOMATILLO_PCI_CTRL_PEN_RD_MLTPL		(1ull << 30)
#define	TOMATILLO_PCI_CTRL_PEN_RD_ONE		(1ull << 29)
#define	TOMATILLO_PCI_CTRL_PEN_RD_LINE		(1ull << 28)
#define	TOMATILLO_PCI_CTRL_FRC_TRGT_ABRT	(1ull << 27)
#define	TOMATILLO_PCI_CTRL_FRC_TRGT_RTRY	(1ull << 26)
#define	SCHIZO_PCI_CTRL_PTO			(3ull << 24)
#define	SCHIZO_PCI_CTRL_PTO_SHIFT		24
#define	TOMATILLO_PCI_CTRL_TRGT_RW_STL_WT	(3ull << 21)
#define	TOMATILLO_PCI_CTRL_TRGT_RW_STL_WT_SHIFT	21
#define	SCHIZO_PCI_CTRL_MMU_INT_EN		(1ull << 19)
#define	SCHIZO_PCI_CTRL_SBH_INT_EN		(1ull << 18)
#define	SCHIZO_PCI_CTRL_ERR_INT_EN		(1ull << 17)
#define	SCHIZO_PCI_CTRL_ARB_PARK		(1ull << 16)
#define	SCHIZO_PCI_CTRL_RST			(1ull << 8)
#define	SCHIZO_PCI_CTRL_ARB_EN_MASK		0xffull

#define	XMITS10_PCI_CTRL_ARB_EN_MASK		0x0full
#define	XMITS_PCI_CTRL_X_MODE			(0x1ull << 32)
#define	XMITS_PCI_CTRL_X_ERRINT_EN		(0x1ull << 20)
#define	XMITS_PCI_CTRL_DMA_WR_PERR		(0x1ull << 51)

/*
 * schizo PCI asynchronous fault status register bit definitions:
 */
#define	SCHIZO_PCI_AFSR_PE_SHIFT		58
#define	SCHIZO_PCI_AFSR_SE_SHIFT		52
#define	SCHIZO_PCI_AFSR_E_MA			0x0000000000000020ull
#define	SCHIZO_PCI_AFSR_E_TA			0x0000000000000010ull
#define	SCHIZO_PCI_AFSR_E_RTRY			0x0000000000000008ull
#define	SCHIZO_PCI_AFSR_E_PERR			0x0000000000000004ull
#define	SCHIZO_PCI_AFSR_E_TTO			0x0000000000000002ull
#define	SCHIZO_PCI_AFSR_E_UNUSABLE		0x0000000000000001ull
#define	SCHIZO_PCI_AFSR_E_MASK			0x000000000000003full
#define	SCHIZO_PCI_AFSR_DWORDMASK		0x0000030000000000ull
#define	SCHIZO_PCI_AFSR_DWORDMASK_SHIFT		40
#define	SCHIZO_PCI_AFSR_BYTEMASK		0x000000ff00000000ull
#define	SCHIZO_PCI_AFSR_BYTEMASK_SHIFT		32
#define	SCHIZO_PCI_AFSR_BLK			0x0000000080000000ull
#define	SCHIZO_PCI_AFSR_CONF_SPACE		0x0000000040000000ull
#define	SCHIZO_PCI_AFSR_MEM_SPACE		0x0000000020000000ull
#define	SCHIZO_PCI_AFSR_IO_SPACE		0x0000000010000000ull

/* Schizo/Xmits control block Safari Error log bits */
#define	SCHIZO_CB_ELOG_BAD_CMD			(0x1ull << 62)
#define	SCHIZO_CB_ELOG_SSM_DIS			(0x1ull << 61)
#define	SCHIZO_CB_ELOG_BAD_CMD_PCIA		(0x1ull << 60)
#define	SCHIZO_CB_ELOG_BAD_CMD_PCIB		(0x1ull << 59)
#define	XMITS_CB_ELOG_PAR_ERR_INT_PCIB		(0x1ull << 19)
#define	XMITS_CB_ELOG_PAR_ERR_INT_PCIA		(0x1ull << 18)
#define	XMITS_CB_ELOG_PAR_ERR_INT_SAF		(0x1ull << 17)
#define	XMITS_CB_ELOG_PLL_ERR_PCIB		(0x1ull << 16)
#define	XMITS_CB_ELOG_PLL_ERR_PCIA		(0x1ull << 15)
#define	XMITS_CB_ELOG_PLL_ERR_SAF		(0x1ull << 14)
#define	SCHIZO_CB_ELOG_CPU1_PAR_SINGLE		(0x1ull << 13)
#define	SCHIZO_CB_ELOG_CPU1_PAR_BIDI		(0x1ull << 12)
#define	SCHIZO_CB_ELOG_CPU0_PAR_SINGLE		(0x1ull << 11)
#define	SCHIZO_CB_ELOG_CPU0_PAR_BIDI		(0x1ull << 10)
#define	SCHIZO_CB_ELOG_SAF_CIQ_TO		(0x1ull << 9)
#define	SCHIZO_CB_ELOG_SAF_LPQ_TO		(0x1ull << 8)
#define	SCHIZO_CB_ELOG_SAF_SFPQ_TO		(0x1ull << 7)
#define	SCHIZO_CB_ELOG_SAF_UFPQ_TO		(0x1ull << 6)
#define	SCHIZO_CB_ELOG_ADDR_PAR_ERR		(0x1ull << 5)
#define	SCHIZO_CB_ELOG_UNMAP_ERR		(0x1ull << 4)
#define	SCHIZO_CB_ELOG_BUS_ERR			(0x1ull << 2)
#define	SCHIZO_CB_ELOG_TO_ERR			(0x1ull << 1)
#define	SCHIZO_CB_ELOG_DSTAT_ERR		0x1ull

/* Used for the tomatillo micro tlb bug. errata #82 */
#define	SCHIZO_VPN_MASK			((1 << 19) - 1)

/* Tomatillo control block JBUS error log bits */
#define	TOMATILLO_CB_ELOG_SNOOP_ERR_GR		(0x1ull << 21)
#define	TOMATILLO_CB_ELOG_SNOOP_ERR_PCI		(0x1ull << 20)
#define	TOMATILLO_CB_ELOG_SNOOP_ERR_RD		(0x1ull << 19)
#define	TOMATILLO_CB_ELOG_SNOOP_ERR_RDS		(0x1ull << 17)
#define	TOMATILLO_CB_ELOG_SNOOP_ERR_RDSA	(0x1ull << 16)
#define	TOMATILLO_CB_ELOG_SNOOP_ERR_OWN		(0x1ull << 15)
#define	TOMATILLO_CB_ELOG_SNOOP_ERR_RDO		(0x1ull << 14)
#define	TOMATILLO_CB_ELOG_WR_DATA_PAR_ERR	(0x1ull << 13)
#define	TOMATILLO_CB_ELOG_CTL_PAR_ERR		(0x1ull << 12)
#define	TOMATILLO_CB_ELOG_SNOOP_ERR		(0x1ull << 11)
#define	TOMATILLO_CB_ELOG_ILL_BYTE_EN		(0x1ull << 10)
#define	TOMATILLO_CB_ELOG_ILL_COH_IN		(0x1ull << 8)
#define	TOMATILLO_CB_ELOG_RD_DATA_PAR_ERR	(0x1ull << 6)
#define	TOMATILLO_CB_ELOG_TO_EXP_ERR		(0x1ull << 3)

/* Tomatillo control block JBUS control/status bits */
#define	TOMATILLO_CB_CSR_CTRL_PERR_GEN		(0x1ull << 29)

#define	XMITS_PCI_X_AFSR_P_SC_ERR		(0x1ull << 51)
#define	XMITS_PCI_X_AFSR_S_SC_ERR		(0x1ull << 50)

#define	XMITS_PCIX_MSG_CLASS_MASK		0xf00
#define	XMITS_PCIX_MSG_INDEX_MASK		0xff
#define	XMITS_PCIX_MSG_MASK	\
		(XMITS_PCIX_MSG_CLASS_MASK | XMITS_PCIX_MSG_INDEX_MASK)

#define	XMITS_PCI_X_P_MSG_SHIFT			16
#define	XMITS_PCI_X_S_MSG_SHIFT			4

#define	PBM_AFSR_TO_PRIERR(afsr)	\
	(afsr >> SCHIZO_PCI_AFSR_PE_SHIFT & SCHIZO_PCI_AFSR_E_MASK)
#define	PBM_AFSR_TO_SECERR(afsr)	\
	(afsr >> SCHIZO_PCI_AFSR_SE_SHIFT & SCHIZO_PCI_AFSR_E_MASK)
#define	PBM_AFSR_TO_BYTEMASK(afsr)	\
	((afsr & SCHIZO_PCI_AFSR_BYTEMASK) >> SCHIZO_PCI_AFSR_BYTEMASK_SHIFT)
#define	PBM_AFSR_TO_DWORDMASK(afsr)	\
	((afsr & SCHIZO_PCI_AFSR_DWORDMASK) >>	\
		SCHIZO_PCI_AFSR_DWORDMASK_SHIFT)

/*
 * XMITS Upper Retry Counter Register (bits 15:0)
 */
#define	XMITS_UPPER_RETRY_MASK			0xFFFF

/*
 * XMITS PCI-X Diagnostic Register bit definitions
 */
#define	XMITS_PCI_X_DIAG_DIS_FAIR		(0x1ull << 19)
#define	XMITS_PCI_X_DIAG_CRCQ_VALID		(0x1ull << 18)
#define	XMITS_PCI_X_DIAG_SRCQ_VALID_SHIFT	10
#define	XMITS_PCI_X_DIAG_SRCQ_ONE		(0x1ull << 9)
#define	XMITS_PCI_X_DIAG_CRCQ_FLUSH		(0x1ull << 8)
#define	XMITS_PCI_X_DIAG_SRCQ_FLUSH_SHIFT	0
#define	XMITS_PCI_X_DIAG_BUGCNTL_MASK		0xFFFF  /* bits 47:32 */
#define	XMITS_PCI_X_DIAG_BUGCNTL_SHIFT		32

#define	XMITS_PCI_X_DIAG_SRCQ_MASK		0xff

/*
 * XMITS PCI-X Error Status Register bit definitions
 */

#define	XMITS_PCI_X_STATUS_PE_SHIFT		58
#define	XMITS_PCI_X_STATUS_SE_SHIFT		50
#define	XMITS_PCI_X_STATUS_E_MASK		0x3f
#define	XMITS_PCI_X_STATUS_PFAR_MASK		0xffffffff
#define	XMITS_PCIX_STAT_SC_DSCRD		0x20ull
#define	XMITS_PCIX_STAT_SC_TTO			0x10ull
/*
 * As a workaround for an XMITS ASIC bug, the following PCI-X errors are
 * assigned new bit positions within the PCI-X Error Status Register to
 * match what is actually implemented in the XMITS ASIC:
 *
 *      			Spec		New
 * Error			Bit Position	Bit Position
 * --------------------		------------	------------
 * XMITS_PCIX_STAT_SMMU		0x8ull		0x4ull
 * XMITS_PCIX_STAT_SDSTAT	0x4ull		0x8ull
 * XMITS_PCIX_STAT_CMMU		0x2ull		0x1ull
 * XMITS_PCIX_STAT_CDSTAT	0x1ull		0x2ull
 *
 */
#define	XMITS_PCIX_STAT_SMMU			0x4ull
#define	XMITS_PCIX_STAT_SDSTAT			0x8ull
#define	XMITS_PCIX_STAT_CMMU			0x1ull
#define	XMITS_PCIX_STAT_CDSTAT			0x2ull

#define	XMITS_PCIX_STAT_SERR_ON_PERR		(1ull << 32)
#define	XMITS_PCIX_STAT_PERR_RECOV_INT_EN	(1ull << 33)
#define	XMITS_PCIX_STAT_PERR_RECOV_INT		(1ull << 34)

/*
 * PCI-X Message Classes and Indexes
 */
#define	PCIX_CLASS_WRITE_COMPLETION		0x000
#define	PCIX_WRITE_COMPLETION_NORMAL		0x00

#define	PCIX_CLASS_BRIDGE			0x100
#define	PCIX_BRIDGE_MASTER_ABORT		0x00
#define	PCIX_BRIDGE_TARGET_ABORT		0x01
#define	PCIX_BRIDGE_WRITE_DATA_PARITY		0x02

#define	PCIX_CLASS_CPLT				0x200
#define	PCIX_CPLT_OUT_OF_RANGE			0x00
#define	PCIX_CPLT_SPLIT_WRITE_DATA		0x01
#define	XMITS_CPLT_NO_ERROR			0x80
#define	XMITS_CPLT_STREAM_DSTAT			0x81
#define	XMITS_CPLT_STREAM_MMU			0x82
#define	XMITS_CPLT_CONSIST_DSTAT		0x85
#define	XMITS_CPLT_CONSIST_MMU			0x86

#define	PCIX_NO_CLASS				0x999
#define	PCIX_MULTI_ERR	1
#define	PCIX_SINGLE_ERR	0

#define	PBM_PCIX_TO_PRIERR(pcix_stat)   \
	(pcix_stat >> XMITS_PCI_X_STATUS_PE_SHIFT & XMITS_PCI_X_STATUS_E_MASK)
#define	PBM_PCIX_TO_SECERR(pcix_stat)   \
	(pcix_stat >> XMITS_PCI_X_STATUS_SE_SHIFT & XMITS_PCI_X_STATUS_E_MASK)
#define	PBM_AFSR_TO_PRISPLIT(afsr)      \
	((afsr >> XMITS_PCI_X_P_MSG_SHIFT) & XMITS_PCIX_MSG_MASK)
#define	PBM_AFSR_TO_SECSPLIT(afsr)      \
	((afsr >> XMITS_PCI_X_S_MSG_SHIFT) & XMITS_PCIX_MSG_MASK)

#define	PCIX_ERRREG_OFFSET (XMITS_PCI_X_ERROR_STATUS_REG_OFFSET -\
		SCHIZO_PCI_CTRL_REG_OFFSET)

/*
 * Nested message structure to allow for storing all the PCI-X
 * split completion messages in tabular form.
 */
typedef struct pcix_err_msg_rec {
	uint32_t msg_key;
	char	*msg_class;
	char    *msg_str;
} pcix_err_msg_rec_t;

typedef struct pcix_err_tbl {
	uint32_t err_class;
	uint32_t err_rec_num;
	pcix_err_msg_rec_t *err_msg_tbl;
} pcix_err_tbl_t;


/*
 * Tomatillo IO Cache CSR bit definitions:
 */

#define	TOMATILLO_WRT_PEN		(1ull << 19)
#define	TOMATILLO_NC_PEN_RD_MLTPL	(1ull << 18)
#define	TOMATILLO_NC_PEN_RD_ONE		(1ull << 17)
#define	TOMATILLO_NC_PEN_RD_LINE	(1ull << 16)
#define	TOMATILLO_PLEN_RD_MTLPL		(3ull << 14)
#define	TOMATILLO_PLEN_RD_ONE		(3ull << 12)
#define	TOMATILLO_PLEN_RD_LINE		(3ull << 10)
#define	TOMATILLO_POFFSET_SHIFT		3
#define	TOMATILLO_POFFSET		(0x7full << TOMATILLO_POFFSET_SHIFT)
#define	TOMATILLO_C_PEN_RD_MLTPL	(1ull << 2)
#define	TOMATILLO_C_PEN_RD_ONE		(1ull << 1)
#define	TOMATILLO_C_PEN_RD_LINE		(1ull << 0)

/*
 * schizo PCI diagnostic register bit definitions:
 */
#define	SCHIZO_PCI_DIAG_DIS_RTRY_ARB		0x0000000000000080ull

/*
 * schizo IOMMU TLB TAG diagnostic register bits
 */
#define	TLBTAG_CONTEXT_SHIFT		25
#define	TLBTAG_ERRSTAT_SHIFT		23
#define	TLBTAG_CONTEXT_BITS		(0xffful << TLBTAG_CONTEXT_SHIFT)
#define	TLBTAG_ERRSTAT_BITS		(0x3ul << TLBTAG_ERRSTAT_SHIFT)
#define	TLBTAG_ERR_BIT			(0x1ul << 22)
#define	TLBTAG_WRITABLE_BIT		(0x1ul << 21)
#define	TLBTAG_STREAM_BIT		(0x1ul << 20)
#define	TLBTAG_PGSIZE_BIT		(0x1ul << 19)
#define	TLBTAG_PCIVPN_BITS		0x7fffful

#define	TLBTAG_ERRSTAT_PROT		0
#define	TLBTAG_ERRSTAT_INVALID		1
#define	TLBTAG_ERRSTAT_TIMEOUT		2
#define	TLBTAG_ERRSTAT_ECCUE		3

/*
 * schizo IOMMU TLB Data RAM diagnostic register bits
 */
#define	TLBDATA_VALID_BIT			(0x1ull << 32)
#define	TLBDATA_CACHE_BIT			(0x1ull << 30)
#define	TLBDATA_MEMPA_BITS			((0x1ull << 30) - 1)

extern uint_t cb_buserr_intr(caddr_t a);

/*
 * pbm_cdma_flag(schizo only): consistent dma sync handshake
 */
#define	PBM_CDMA_DONE	0xcc /* arbitrary pattern set by interrupt handler */
#define	PBM_CDMA_PEND	0x55 /* arbitrary pattern set by sync requester */
#define	PBM_CDMA_INO_BASE	0x35    /* ino can be used for cdma sync */

/*
 * Estar control bit for schizo estar reg
 */
#define	SCHIZO_PCI_CTRL_BUS_SPEED		0x0000000000000001ull

#define	PCI_CMN_ID(chip_type, id) \
	((chip_type) == PCI_CHIP_TOMATILLO ? ((id) >> 1) << 1 : (id))
#define	PCI_ID_TO_IGN(pci_id)		((pci_ign_t)((pci_id) & 0x1f))
#define	PCI_ID_TO_NODEID(pci_id)	((cb_nid_t)((pci_id) >> PCI_IGN_BITS))

#define	PCI_BRIDGE_TYPE(cmn_p) \
	(((cmn_p->pci_chip_id >> 16) == PCI_CHIP_SCHIZO) ? PCI_SCHIZO : \
	((cmn_p->pci_chip_id >> 16) == PCI_CHIP_TOMATILLO) ? PCI_TOMATILLO : \
	((cmn_p->pci_chip_id >> 16) == PCI_CHIP_XMITS) ? PCI_XMITS : "")
/*
 * Tomatillo only
 */
#define	NBIGN(ib_p)			((ib_p)->ib_ign ^ 1)
#define	IB_INO_TO_NBMONDO(ib_p, ino)	IB_IGN_TO_MONDO(NBIGN(ib_p), ino)

/*
 * Mask to tell which PCI Side we are on
 */
#define	PCI_SIDE_ADDR_MASK			0x100000ull

/*
 * Offset from Schizo Base of Schizo CSR Base
 */
#define	PBM_CTRL_OFFSET				0x410000ull

/*
 * The following macro defines the 42-bit bus width support for SAFARI bus
 * and JBUS in DVMA and iommu bypass transfers:
 */

#define	SAFARI_JBUS_IOMMU_BYPASS_END		0xFFFC03FFFFFFFFFFull

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCISCH_H */

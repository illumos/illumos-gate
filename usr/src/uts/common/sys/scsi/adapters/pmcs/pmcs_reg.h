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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * PMC 8x6G register definitions
 */
#ifndef	_PMCS_REG_H
#define	_PMCS_REG_H
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCI Constants
 */
#define	PMCS_VENDOR_ID	0x11F8
#define	PMCS_DEVICE_ID	0x8001

#define	PMCS_PM8001_REV_A	0
#define	PMCS_PM8001_REV_B	1
#define	PMCS_PM8001_REV_C	2

#define	PMCS_REGSET_0		1
#define	PMCS_REGSET_1		2
#define	PMCS_REGSET_2		3
#define	PMCS_REGSET_3		4


/*
 * PCIe BARs - 4 64KB memory regions
 *
 *	BAR0-1	64KiB
 *	BAR2-3	64KiB
 *	BAR4	64KiB
 *	BAR5	64KiB
 */

/*
 * The PMC 8x6G registers are defined by BARs in PCIe space.
 *
 * Four memory region BARS are used.
 *
 * The first is for the Messaging Unit.
 *
 * The second 64KiB region contains the PCS/PMA registers and some of the
 * Top-Level registers.
 *
 * The third 64KiB region is a 64KiB window on the rest of the chip registers
 * which can be shifted by writing a register in the second region.
 *
 * The fourth 64KiB region is for the message passing area.
 */

/*
 * Messaging Unit Register Offsets
 */
#define	PMCS_MSGU_IBDB		0x04	/* Inbound Doorbell */
#define	PMCS_MSGU_IBDB_CLEAR	0x20	/* InBound Doorbell Clear */
#define	PMCS_MSGU_OBDB		0x3c	/* OutBound Doorbell */
#define	PMCS_MSGU_OBDB_CLEAR	0x40	/* OutBound Doorbell Clear */
#define	PMCS_MSGU_SCRATCH0	0x44	/* Scratchpad 0 */
#define	PMCS_MSGU_SCRATCH1	0x48	/* Scratchpad 1 */
#define	PMCS_MSGU_SCRATCH2	0x4C	/* Scratchpad 2 */
#define	PMCS_MSGU_SCRATCH3	0x50	/* Scratchpad 3 */
#define	PMCS_MSGU_HOST_SCRATCH0	0x54	/* Host Scratchpad 0 */
#define	PMCS_MSGU_HOST_SCRATCH1	0x58	/* Host Scratchpad 1 */
#define	PMCS_MSGU_HOST_SCRATCH2	0x5C	/* Host Scratchpad 2 */
#define	PMCS_MSGU_HOST_SCRATCH3	0x60	/* Host Scratchpad 3 */
#define	PMCS_MSGU_HOST_SCRATCH4	0x64	/* Host Scratchpad 4 */
#define	PMCS_MSGU_HOST_SCRATCH5	0x68	/* Host Scratchpad 5 */
#define	PMCS_MSGU_HOST_SCRATCH6	0x6C	/* Host Scratchpad 6 */
#define	PMCS_MSGU_HOST_SCRATCH7	0x70	/* Host Scratchpad 7 */
#define	PMCS_MSGU_OBDB_MASK	0x74	/* Outbound Doorbell Mask */

/*
 * Inbound Doorbell and Doorbell Clear Definitions
 * NB: The Doorbell Clear register is only used on RevA/8000 parts.
 */
#define	PMCS_MSGU_IBDB_MPIIU	0x08	/* Initiate Unfreeze */
#define	PMCS_MSGU_IBDB_MPIIF	0x04	/* Initiate Freeze */
#define	PMCS_MSGU_IBDB_MPICTU	0x02	/* Initiate MPI Termination */
#define	PMCS_MSGU_IBDB_MPIINI	0x01	/* Initiate MPI */

/*
 * Outbound Doorbell and Doorbell Clear Register
 *
 * The Doorbell Clear register is only used on RevA/8000 parts.
 *
 * Each bit of the ODR is mapped 1-to-1 to a MSI or MSI-X vector
 * table entry. There are 32 MSI and 16 MSI-X entries. The top
 * 16 bits are mapped to the low 16 bits for MSI-X. For legacy
 * INT-X, any bit will generate a host interrupt.
 *
 * Each bit in the Outbound Doorbell Clear is used to clear the
 * corresponding bit in the ODR. For INT-X it also then deasserts
 * any interrupt condition.
 */
#define	PMCS_MSI_INTS	32
#define	PMCS_MSIX_INTS	16

/*
 * Scratchpad 0 Definitions
 *
 * When the AAP is ready state (see Scratchpad 1), bits 31:26 is the offset
 * within PCIe space for another BAR that, when mapped, will point to a region
 * that conains the MPI Configuration table (the offset of which is in bits
 * 25:0 of this register)
 *
 * When the AAP is in error state, this register contains additional error
 * information.
 */
#define	PMCS_MSGU_MPI_BAR_SHIFT		26
#define	PMCS_MSGU_MPI_OFFSET_MASK	((1 << PMCS_MSGU_MPI_BAR_SHIFT) - 1)

/*
 * Scratchpad 1 Definitions
 *
 * The bottom two bits are the AAP state of the 8x6G.
 *
 * When the AAP is in error state, bits 31:10 contain the error indicator.
 *
 */
#define	PMCS_MSGU_AAP_STATE_MASK	0x03
#define	PMCS_MSGU_AAP_STATE_POR		0
#define	PMCS_MSGU_AAP_STATE_SOFT_RESET	1
#define	PMCS_MSGU_AAP_STATE_ERROR	2
#define	PMCS_MSGU_AAP_STATE_READY	3
#define	PMCS_MSGU_AAP_SFR_PROGRESS	0x04
#define	PMCS_MSGU_AAP_ERROR_MASK	0xfffffc00

/*
 * Scratchpad 2 Definitions
 *
 * Bits 31:10 contain error information if the IOP is in error state.
 */
#define	PMCS_MSGU_IOP_STATE_MASK	0x03
#define	PMCS_MSGU_IOP_STATE_POR		0
#define	PMCS_MSGU_IOP_STATE_SOFT_RESET	1
#define	PMCS_MSGU_IOP_STATE_ERROR	2
#define	PMCS_MSGU_IOP_STATE_READY	3

#define	PMCS_MSGU_HOST_SOFT_RESET_READY	0x04
#define	PMCS_MSGU_CPU_SOFT_RESET_READY	0x08

/*
 * Scratchpad 3 Definitions
 *
 * Contains additional error information if the IOP is in error state
 * (see Scratchpad 2)
 */

/*
 * Host Scratchpad 0
 * Soft Reset Signature
 */
#define	HST_SFT_RESET_SIG		0x252ACBCD

/*
 * Host Scratchpad 1
 *
 * This is a bit mask for freeze or unfreeze operations for IQs 0..31
 */

/*
 * Host Scratchpad 2
 *
 * This is a bit mask for freeze or unfreeze operations for IQs 32..63
 */

/*
 * Outbound Doorbell Mask Register
 *
 * Each bit set here masks bits and interrupt assertion for the corresponding
 * bit (and vector) in the ODR.
 */

/*
 * GSM Registers
 */
#define	GSM_BASE_MASK				0x00ffff
#define	NMI_EN_VPE0_IOP				0x60418
#define	NMI_EN_VPE0_AAP1			0x70418
#define	RB6_ACCESS				0x6A80C0
#define	GSM_CFG_AND_RESET			0x700000
#define	RAM_ECC_DOUBLE_ERROR_INDICATOR		0x700018
#define	READ_ADR_PARITY_CHK_EN			0x700038
#define	WRITE_ADR_PARITY_CHK_EN			0x700040
#define	WRITE_DATA_PARITY_CHK_EN		0x700048
#define	READ_ADR_PARITY_ERROR_INDICATOR		0x700058
#define	WRITE_ADR_PARITY_ERROR_INDICATOR	0x700060
#define	WRITE_DATA_PARITY_ERROR_INDICATOR	0x700068

#define	GSM_FLASH_BASE_UPPER			0x18
#define	GSM_FLASH_BASE				0x40000000
#define	GSM_FLASH_ILA				GSM_FLASH_BASE
#define	GSM_FLASH_IMG_FLAGS			(GSM_FLASH_BASE + 0x400000)

#define	PMCS_IMG_FLAG_A				0x01

/*
 * GSM Share Memory, IO Status Table and Ring Buffer
 */
#define	GSM_SM_BLKSZ				0x10000
#define	GSM_SM_BASE				0x400000
#define	IO_STATUS_TABLE_BASE			0x640000
#define	RING_BUF_STORAGE_0			0x680000
#define	RING_BUF_STORAGE_1			0x690000
#define	RING_BUF_PTR_ACC_BASE			0x6A0000

#define	IO_STATUS_TABLE_BLKNM			0x4
#define	GSM_SM_BLKNM				0x10
#define	RING_BUF_PTR_OFF			0x1000
#define	RING_BUF_PTR_SIZE			0xFF8
#define	RING_BUF_ACC_OFF			0x8000
#define	RING_BUF_ACC_SIZE			0xFF8

/*
 * GSM Configuration and Reset Bits
 */
#define	MST_XCBI_SW_RSTB		(1 << 14)
#define	COM_SLV_SW_RSTB			(1 << 13)
#define	QSSP_SW_RSTB			(1 << 12)
#define	RAAE_SW_RSTB			(1 << 11)
#define	RB_1_SW_RSTB			(1 << 9)
#define	SM_SW_RSTB			(1 << 8)

#define	COHERENCY_GAP_SHIFT		4
#define	COHERENCY_GAP_MASK		0xf0
#define	COHERENCY_GAP_DEFAULT		(8 << COHERENCY_GAP_SHIFT)

#define	COHERENCY_MODE			(1 << 3)
#define	RB_WSTRB_ERRCHK_EN		(1 << 2)
#define	RAAE_PORT2_EN			(1 << 1)
#define	GSM_WCI_MODE			(1 << 0)
#define	PMCS_SOFT_RESET_BITS		\
	(COM_SLV_SW_RSTB|QSSP_SW_RSTB|RAAE_SW_RSTB|RB_1_SW_RSTB|SM_SW_RSTB)

#define	RB6_NMI_SIGNATURE		0x00001234

/*
 * PMCS PCI Configuration Registers
 */
#define	PMCS_PCI_PMC			0x40
#define	PMCS_PCI_PMCSR			0x44
#define	PMCS_PCI_MSI			0x50
#define	PMCS_PCI_MAL			0x54
#define	PMCS_PCI_MAU			0x58
#define	PMCS_PCI_MD			0x5C
#define	PMCS_PCI_PCIE			0x70
#define	PMCS_PCI_DEV_CAP		0x74
#define	PMCS_PCI_DEV_CTRL		0x78
#define	PMCS_PCI_LINK_CAP		0x7C
#define	PMCS_PCI_LINK_CTRL		0x80
#define	PMCS_PCI_MSIX_CAP		0xAC
#define	PMCS_PCI_TBL_OFFSET		0xB0
#define	PMCS_PCI_PBA_OFFSET		0xB4
#define	PMCS_PCI_PCIE_CAP_HD		0x100
#define	PMCS_PCI_UE_STAT		0x104
#define	PMCS_PCI_UE_MASK		0x108
#define	PMCS_PCI_UE_SEV			0x10C
#define	PMCS_PCI_CE_STAT		0x110
#define	PMCS_PCI_CE_MASK		0x114
#define	PMCS_PCI_ADV_ERR_CTRL		0x118
#define	PMCS_PCI_HD_LOG_DW		0x11C

/*
 * Top Level Registers
 */
/* these registers are in MEMBASE-III */
#define	PMCS_SPC_RESET			0x0
#define	PMCS_SPC_BOOT_STRAP		0x8
#define	PMCS_SPC_DEVICE_ID		0x20
#define	PMCS_DEVICE_REVISION		0x24
/* these registers are in MEMBASE-II */
#define	PMCS_EVENT_INT_ENABLE		0x3040
#define	PMCS_EVENT_INT_STAT		0x3044
#define	PMCS_ERROR_INT_ENABLE		0x3048
#define	PMCS_ERROR_INT_STAT		0x304C
#define	PMCS_AXI_TRANS			0x3258
#define	PMCS_AXI_TRANS_UPPER		0x3268
#define	PMCS_OBDB_AUTO_CLR		0x335C
#define	PMCS_INT_COALESCING_TIMER	0x33C0
#define	PMCS_INT_COALESCING_CONTROL	0x33C4


/*
 * Chip Reset Register Bits (PMCS_SPC_RESET)
 *
 * NB: all bits are inverted. That is, the normal state is '1'.
 * When '0' is set, the action is taken.
 */
#define	PMCS_SPC_HARD_RESET		0x00
#define	PMCS_SPC_HARD_RESET_CLR		0xffffffff


#define	SW_DEVICE_RSTB			(1 << 31)
#define	PCIE_PC_SXCBI_ARESETN		(1 << 26)
#define	PMIC_CORE_RSTB			(1 << 25)
#define	PMIC_SXCBI_ARESETN		(1 << 24)
#define	LMS_SXCBI_ARESETN		(1 << 23)
#define	PCS_SXCBI_ARESETN		(1 << 22)
#define	PCIE_SFT_RSTB			(1 << 21)
#define	PCIE_PWR_RSTB			(1 << 20)
#define	PCIE_AL_SXCBI_ARESETN		(1 << 19)
#define	BDMA_SXCBI_ARESETN		(1 << 18)
#define	BDMA_CORE_RSTB			(1 << 17)
#define	DDR2_RSTB			(1 << 16)
#define	GSM_RSTB			(1 << 8)
#define	PCS_RSTB			(1 << 7)
#define	PCS_LM_RSTB			(1 << 6)
#define	PCS_AAP2_SS_RSTB		(1 << 5)
#define	PCS_AAP1_SS_RSTB		(1 << 4)
#define	PCS_IOP_SS_RSTB			(1 << 3)
#define	PCS_SPBC_RSTB			(1 << 2)
#define	RAAE_RSTB			(1 << 1)
#define	OSSP_RSTB			(1 << 0)


/*
 * Timer Enables Register
 */
#define	PMCS_TENABLE_WINDOW_OFFSET	0x30000
#define	PMCS_TENABLE_BASE		0x0209C
#define	PMCS_TENABLE_MULTIPLIER		0x04000

/*
 * Special register (MEMBASE-III) for Step 5.5 in soft reset sequence to set
 * GPIO into tri-state mode (temporary workaround for 1.07.xx beta firmware)
 */
#define	PMCS_GPIO_TRISTATE_MODE_ADDR	0x9010C
#define	PMCS_GPIO_TSMODE_BIT0		(1 << 0)
#define	PMCS_GPIO_TSMODE_BIT1		(1 << 1)

/*
 * SAS/SATA PHY Layer Registers
 * These are in MEMBASE-III (i.e. in GSM space)
 */
#define	OPEN_RETRY_INTERVAL(phy)	\
	(phy < 4) ? (0x330B4 + (0x4000 * (phy))) : \
	(0x430B4 + (0x4000 * (phy - 4)))

#define	OPEN_RETRY_INTERVAL_DEF		20
#define	OPEN_RETRY_INTERVAL_MAX		0x7FFF

/*
 * Register Access Inline Functions
 */
uint32_t pmcs_rd_msgunit(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_gsm_reg(pmcs_hw_t *, uint8_t, uint32_t);
uint32_t pmcs_rd_topunit(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_mpi_tbl(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_gst_tbl(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_iqc_tbl(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_oqc_tbl(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_iqci(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_iqpi(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_oqci(pmcs_hw_t *, uint32_t);
uint32_t pmcs_rd_oqpi(pmcs_hw_t *, uint32_t);

void pmcs_wr_msgunit(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_gsm_reg(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_topunit(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_mpi_tbl(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_gst_tbl(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_iqc_tbl(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_oqc_tbl(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_iqci(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_iqpi(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_oqci(pmcs_hw_t *, uint32_t, uint32_t);
void pmcs_wr_oqpi(pmcs_hw_t *, uint32_t, uint32_t);

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_REG_H */

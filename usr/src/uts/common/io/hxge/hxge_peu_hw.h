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

#ifndef	_HXGE_PEU_HW_H
#define	_HXGE_PEU_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PIO_LDSV_BASE_ADDR			0X800000
#define	PIO_BASE_ADDR				0X000000
#define	PIO_LDMASK_BASE_ADDR			0XA00000

#define	DEVICE_VENDOR_ID			(PIO_BASE_ADDR + 0x0)
#define	STATUS_COMMAND				(PIO_BASE_ADDR + 0x4)
#define	CLASSCODE_REV_ID			(PIO_BASE_ADDR + 0x8)
#define	BIST_HDRTYP_LATTMR_CASHLSZ		(PIO_BASE_ADDR + 0xC)
#define	PIO_BAR0				(PIO_BASE_ADDR + 0x10)
#define	PIO_BAR1				(PIO_BASE_ADDR + 0x14)
#define	MSIX_BAR0				(PIO_BASE_ADDR + 0x18)
#define	MSIX_BAR1				(PIO_BASE_ADDR + 0x1C)
#define	VIRT_BAR0				(PIO_BASE_ADDR + 0x20)
#define	VIRT_BAR1				(PIO_BASE_ADDR + 0x24)
#define	CIS_PTR					(PIO_BASE_ADDR + 0x28)
#define	SUB_VENDOR_ID				(PIO_BASE_ADDR + 0x2C)
#define	EXP_ROM_BAR				(PIO_BASE_ADDR + 0x30)
#define	CAP_PTR					(PIO_BASE_ADDR + 0x34)
#define	INT_LINE				(PIO_BASE_ADDR + 0x3C)
#define	PM_CAP					(PIO_BASE_ADDR + 0x40)
#define	PM_CTRL_STAT				(PIO_BASE_ADDR + 0x44)
#define	MSI_CAP					(PIO_BASE_ADDR + 0x50)
#define	MSI_LO_ADDR				(PIO_BASE_ADDR + 0x54)
#define	MSI_HI_ADDR				(PIO_BASE_ADDR + 0x58)
#define	MSI_DATA				(PIO_BASE_ADDR + 0x5C)
#define	MSI_MASK				(PIO_BASE_ADDR + 0x60)
#define	MSI_PEND				(PIO_BASE_ADDR + 0x64)
#define	MSIX_CAP				(PIO_BASE_ADDR + 0x70)
#define	MSIX_TAB_OFF				(PIO_BASE_ADDR + 0x74)
#define	MSIX_PBA_OFF				(PIO_BASE_ADDR + 0x78)
#define	PCIE_CAP				(PIO_BASE_ADDR + 0x80)
#define	DEV_CAP					(PIO_BASE_ADDR + 0x84)
#define	DEV_STAT_CTRL				(PIO_BASE_ADDR + 0x88)
#define	LNK_CAP					(PIO_BASE_ADDR + 0x8C)
#define	LNK_STAT_CTRL				(PIO_BASE_ADDR + 0x90)
#define	VEN_CAP_HDR				(PIO_BASE_ADDR + 0x94)
#define	VEN_CTRL				(PIO_BASE_ADDR + 0x98)
#define	VEN_PRT_HDR				(PIO_BASE_ADDR + 0x9C)
#define	ACKLAT_REPLAY				(PIO_BASE_ADDR + 0xA0)
#define	OTH_MSG					(PIO_BASE_ADDR + 0xA4)
#define	FORCE_LINK				(PIO_BASE_ADDR + 0xA8)
#define	ACK_FREQ				(PIO_BASE_ADDR + 0xAC)
#define	LINK_CTRL				(PIO_BASE_ADDR + 0xB0)
#define	LANE_SKEW				(PIO_BASE_ADDR + 0xB4)
#define	SYMBOL_NUM				(PIO_BASE_ADDR + 0xB8)
#define	SYMB_TIM_RADM_FLT1			(PIO_BASE_ADDR + 0xBC)
#define	RADM_FLT2				(PIO_BASE_ADDR + 0xC0)
#define	CASCADE_DEB_REG0			(PIO_BASE_ADDR + 0xC8)
#define	CASCADE_DEB_REG1			(PIO_BASE_ADDR + 0xCC)
#define	TXP_FC_CREDIT_STAT			(PIO_BASE_ADDR + 0xD0)
#define	TXNP_FC_CREDIT_STAT			(PIO_BASE_ADDR + 0xD4)
#define	TXCPL_FC_CREDIT_STAT			(PIO_BASE_ADDR + 0xD8)
#define	QUEUE_STAT				(PIO_BASE_ADDR + 0xDC)
#define	GBT_DEBUG0				(PIO_BASE_ADDR + 0xE0)
#define	GBT_DEBUG1				(PIO_BASE_ADDR + 0xE4)
#define	GBT_DEBUG2				(PIO_BASE_ADDR + 0xE8)
#define	GBT_DEBUG3				(PIO_BASE_ADDR + 0xEC)
#define	PIPE_DEBUG0				(PIO_BASE_ADDR + 0xF0)
#define	PIPE_DEBUG1				(PIO_BASE_ADDR + 0xF4)
#define	PIPE_DEBUG2				(PIO_BASE_ADDR + 0xF8)
#define	PIPE_DEBUG3				(PIO_BASE_ADDR + 0xFC)
#define	PCIE_ENH_CAP_HDR			(PIO_BASE_ADDR + 0x100)
#define	UNC_ERR_STAT				(PIO_BASE_ADDR + 0x104)
#define	UNC_ERR_MASK				(PIO_BASE_ADDR + 0x108)
#define	UNC_ERR_SVRTY				(PIO_BASE_ADDR + 0x10C)
#define	CORR_ERR_STAT				(PIO_BASE_ADDR + 0x110)
#define	CORR_ERR_MASK				(PIO_BASE_ADDR + 0x114)
#define	ADV_CAP_CTRL				(PIO_BASE_ADDR + 0x118)
#define	HDR_LOG0				(PIO_BASE_ADDR + 0x11C)
#define	HDR_LOG1				(PIO_BASE_ADDR + 0x120)
#define	HDR_LOG2				(PIO_BASE_ADDR + 0x124)
#define	HDR_LOG3				(PIO_BASE_ADDR + 0x128)
#define	PIPE_RX_TX_CONTROL			(PIO_BASE_ADDR + 0x1000)
#define	PIPE_RX_TX_STATUS			(PIO_BASE_ADDR + 0x1004)
#define	PIPE_RX_TX_PWR_CNTL			(PIO_BASE_ADDR + 0x1008)
#define	PIPE_RX_TX_PARAM			(PIO_BASE_ADDR + 0x1010)
#define	PIPE_RX_TX_CLOCK			(PIO_BASE_ADDR + 0x1014)
#define	PIPE_GLUE_CNTL0				(PIO_BASE_ADDR + 0x1018)
#define	PIPE_GLUE_CNTL1				(PIO_BASE_ADDR + 0x101C)
#define	HCR_REG					(PIO_BASE_ADDR + 0x2000)
#define	BLOCK_RESET				(PIO_BASE_ADDR + 0x8000)
#define	TIMEOUT_CFG				(PIO_BASE_ADDR + 0x8004)
#define	HEART_CFG				(PIO_BASE_ADDR + 0x8008)
#define	HEART_TIMER				(PIO_BASE_ADDR + 0x800C)
#define	CIP_GP_CTRL				(PIO_BASE_ADDR + 0x8010)
#define	CIP_STATUS				(PIO_BASE_ADDR + 0x8014)
#define	CIP_LINK_STAT				(PIO_BASE_ADDR + 0x801C)
#define	EPC_STAT				(PIO_BASE_ADDR + 0x8020)
#define	EPC_DATA				(PIO_BASE_ADDR + 0x8024)
#define	SPC_STAT				(PIO_BASE_ADDR + 0x8030)
#define	HOST2SPI_INDACC_ADDR			(PIO_BASE_ADDR + 0x8050)
#define	HOST2SPI_INDACC_CTRL			(PIO_BASE_ADDR + 0x8054)
#define	HOST2SPI_INDACC_DATA			(PIO_BASE_ADDR + 0x8058)
#define	BT_CTRL0				(PIO_BASE_ADDR + 0x8080)
#define	BT_DATA0				(PIO_BASE_ADDR + 0x8084)
#define	BT_INTMASK0				(PIO_BASE_ADDR + 0x8088)
#define	BT_CTRL1				(PIO_BASE_ADDR + 0x8090)
#define	BT_DATA1				(PIO_BASE_ADDR + 0x8094)
#define	BT_INTMASK1				(PIO_BASE_ADDR + 0x8098)
#define	BT_CTRL2				(PIO_BASE_ADDR + 0x80A0)
#define	BT_DATA2				(PIO_BASE_ADDR + 0x80A4)
#define	BT_INTMASK2				(PIO_BASE_ADDR + 0x80A8)
#define	BT_CTRL3				(PIO_BASE_ADDR + 0x80B0)
#define	BT_DATA3				(PIO_BASE_ADDR + 0x80B4)
#define	BT_INTMASK3				(PIO_BASE_ADDR + 0x80B8)
#define	DEBUG_SEL				(PIO_BASE_ADDR + 0x80C0)
#define	INDACC_MEM0_CTRL			(PIO_BASE_ADDR + 0x80C4)
#define	INDACC_MEM0_DATA0			(PIO_BASE_ADDR + 0x80C8)
#define	INDACC_MEM0_DATA1			(PIO_BASE_ADDR + 0x80CC)
#define	INDACC_MEM0_DATA2			(PIO_BASE_ADDR + 0x80D0)
#define	INDACC_MEM0_DATA3			(PIO_BASE_ADDR + 0x80D4)
#define	INDACC_MEM0_PRTY			(PIO_BASE_ADDR + 0x80D8)
#define	INDACC_MEM1_CTRL			(PIO_BASE_ADDR + 0x80DC)
#define	INDACC_MEM1_DATA0			(PIO_BASE_ADDR + 0x80E0)
#define	INDACC_MEM1_DATA1			(PIO_BASE_ADDR + 0x80E4)
#define	INDACC_MEM1_DATA2			(PIO_BASE_ADDR + 0x80E8)
#define	INDACC_MEM1_DATA3			(PIO_BASE_ADDR + 0x80EC)
#define	INDACC_MEM1_PRTY			(PIO_BASE_ADDR + 0x80F0)
#define	PHY_DEBUG_TRAINING_VEC			(PIO_BASE_ADDR + 0x80F4)
#define	PEU_DEBUG_TRAINING_VEC			(PIO_BASE_ADDR + 0x80F8)
#define	PIPE_CFG0				(PIO_BASE_ADDR + 0x8120)
#define	PIPE_CFG1				(PIO_BASE_ADDR + 0x8124)
#define	CIP_BAR_MASK_CFG			(PIO_BASE_ADDR + 0x8134)
#define	CIP_BAR_MASK				(PIO_BASE_ADDR + 0x8138)
#define	CIP_LDSV0_STAT				(PIO_BASE_ADDR + 0x8140)
#define	CIP_LDSV1_STAT				(PIO_BASE_ADDR + 0x8144)
#define	PEU_INTR_STAT				(PIO_BASE_ADDR + 0x8148)
#define	PEU_INTR_MASK				(PIO_BASE_ADDR + 0x814C)
#define	PEU_INTR_STAT_MIRROR			(PIO_BASE_ADDR + 0x8150)
#define	CPL_HDRQ_PERR_LOC			(PIO_BASE_ADDR + 0x8154)
#define	CPL_DATAQ_PERR_LOC			(PIO_BASE_ADDR + 0x8158)
#define	RETR_PERR_LOC				(PIO_BASE_ADDR + 0x815C)
#define	RETR_SOT_PERR_LOC			(PIO_BASE_ADDR + 0x8160)
#define	P_HDRQ_PERR_LOC				(PIO_BASE_ADDR + 0x8164)
#define	P_DATAQ_PERR_LOC			(PIO_BASE_ADDR + 0x8168)
#define	NP_HDRQ_PERR_LOC			(PIO_BASE_ADDR + 0x816C)
#define	NP_DATAQ_PERR_LOC			(PIO_BASE_ADDR + 0x8170)
#define	MSIX_PERR_LOC				(PIO_BASE_ADDR + 0x8174)
#define	HCR_PERR_LOC				(PIO_BASE_ADDR + 0x8178)
#define	TDC_PIOACC_ERR_LOG			(PIO_BASE_ADDR + 0x8180)
#define	RDC_PIOACC_ERR_LOG			(PIO_BASE_ADDR + 0x8184)
#define	PFC_PIOACC_ERR_LOG			(PIO_BASE_ADDR + 0x8188)
#define	VMAC_PIOACC_ERR_LOG			(PIO_BASE_ADDR + 0x818C)
#define	LD_GRP_CTRL				(PIO_BASE_ADDR + 0x8300)
#define	DEV_ERR_STAT				(PIO_BASE_ADDR + 0x8380)
#define	DEV_ERR_MASK				(PIO_BASE_ADDR + 0x8384)
#define	LD_INTR_TIM_RES				(PIO_BASE_ADDR + 0x8390)
#define	LDSV0					(PIO_LDSV_BASE_ADDR + 0x0)
#define	LDSV1					(PIO_LDSV_BASE_ADDR + 0x4)
#define	LD_INTR_MASK				(PIO_LDMASK_BASE_ADDR + 0x0)
#define	LD_INTR_MGMT				(PIO_LDMASK_BASE_ADDR + 0x4)
#define	SID					(PIO_LDMASK_BASE_ADDR + 0x8)


/*
 * Register: DeviceVendorId
 * Device ID and Vendor ID
 * Description: Device ID/Vendor ID
 * Fields:
 *     Device ID Register: dbi writeable
 *     Vendor ID Register (Sun Microsystem): dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	device_id:16;
		uint32_t	vendor_id:16;
#else
		uint32_t	vendor_id:16;
		uint32_t	device_id:16;
#endif
	} bits;
} device_vendor_id_t;


/*
 * Register: StatusCommand
 * Status and Command
 * Description: Status/Command
 * Fields:
 *     The device detected a parity error. The device detects
 *     Poisoned TLP received regardless of Command Register Parity
 *     Error Enable/Response bit.
 *     The device signaled a system error with SERR#. The device
 *     detects a UE, is about to send a F/NF error message; and if
 *     the Command Register SERR# enable is set.
 *     A transaction initiated by this device was terminated due to a
 *     Master Abort (i.e. Unsupported Request Completion Status was
 *     received).
 *     A transaction initiated by this device was terminated due to a
 *     Target Abort (i.e. Completer Abort Completion Status was
 *     received).
 *     Set when Completer Abort Completion Status is sent back to the
 *     RC. The request violated hydra's programming rules.
 *     The slowest DEVSEL# timing for this target device (N/A in
 *     PCIE)
 *     Master Data Parity Error - set if all the following conditions
 *     are true: received a poisoned TLP header or sending a poisoned
 *     write request; and the parity error response bit in the
 *     command register is set.
 *     Fast Back-to-Back Capable (N/A in PCIE)
 *     66 MHz Capable (N/A in PCIE)
 *     Capabilities List - presence of extended capability item.
 *     INTx Status
 *     INTx Assertion Disable
 *     Fast Back-to-Back Enable (N/A in PCIE)
 *     This device can drive the SERR# line.
 *     IDSEL Stepping/Wait Cycle Control (N/A in PCIE)
 *     This device can drive the PERR# line.
 *     VGA Palette Snoop (N/A in PCIE)
 *     The device can issue Memory Write-and-Invalidate commands (N/A
 *     in PCIE)
 *     This device monitors for PCI Special Cycles (N/A in PCIE)
 *     This device's bus master capability is enabled.
 *     This device responds to PCI memory accesses.
 *     This device responds to PCI IO accesses (No I/O space used in
 *     Hydra)
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	det_par_err:1;
		uint32_t	sig_serr:1;
		uint32_t	rcv_mstr_abrt:1;
		uint32_t	rcv_tgt_abrt:1;
		uint32_t	sig_tgt_abrt:1;
		uint32_t	devsel_timing:2;
		uint32_t	mstr_dpe:1;
		uint32_t	fast_b2b_cap:1;
		uint32_t	rsrvd:1;
		uint32_t	mhz_cap:1;
		uint32_t	cap_list:1;
		uint32_t	intx_stat:1;
		uint32_t	rsrvd1:3;
		uint32_t	rsrvd2:5;
		uint32_t	intx_dis:1;
		uint32_t	fast_b2b_en:1;
		uint32_t	serr_en:1;
		uint32_t	idsel_step:1;
		uint32_t	par_err_en:1;
		uint32_t	vga_snoop:1;
		uint32_t	mwi_en:1;
		uint32_t	special_cycle:1;
		uint32_t	bm_en:1;
		uint32_t	mem_sp_en:1;
		uint32_t	io_sp_en:1;
#else
		uint32_t	io_sp_en:1;
		uint32_t	mem_sp_en:1;
		uint32_t	bm_en:1;
		uint32_t	special_cycle:1;
		uint32_t	mwi_en:1;
		uint32_t	vga_snoop:1;
		uint32_t	par_err_en:1;
		uint32_t	idsel_step:1;
		uint32_t	serr_en:1;
		uint32_t	fast_b2b_en:1;
		uint32_t	intx_dis:1;
		uint32_t	rsrvd2:5;
		uint32_t	rsrvd1:3;
		uint32_t	intx_stat:1;
		uint32_t	cap_list:1;
		uint32_t	mhz_cap:1;
		uint32_t	rsrvd:1;
		uint32_t	fast_b2b_cap:1;
		uint32_t	mstr_dpe:1;
		uint32_t	devsel_timing:2;
		uint32_t	sig_tgt_abrt:1;
		uint32_t	rcv_tgt_abrt:1;
		uint32_t	rcv_mstr_abrt:1;
		uint32_t	sig_serr:1;
		uint32_t	det_par_err:1;
#endif
	} bits;
} status_command_t;


/*
 * Register: ClasscodeRevId
 * Class Code, and Revision ID
 * Description: Class Code/Revision ID
 * Fields:
 *     Base Class (Network Controller): dbi writeable
 *     Sub Class (Ethernet Controller): dbi writeable
 *     Programming Interface: dbi writeable
 *     Revision ID: dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_class:8;
		uint32_t	sub_class:8;
		uint32_t	prog_if:8;
		uint32_t	rev_id:8;
#else
		uint32_t	rev_id:8;
		uint32_t	prog_if:8;
		uint32_t	sub_class:8;
		uint32_t	base_class:8;
#endif
	} bits;
} classcode_rev_id_t;


/*
 * Register: BistHdrtypLattmrCashlsz
 * BIST, Header Type, Latency Timer, and Cache Line Size
 * Description: BIST, Latency Timer etc
 * Fields:
 *     BIST is not supported. Header Type Fields
 *     Multi-Function Device: dbi writeable
 *     Configuration Header Format. 0 = Type 0.
 *     Master Latency Timer. (N/A in PCIE)
 *     Cache line size for legacy compatibility (N/A in PCIE)
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	value:8;
		uint32_t	mult_func_dev:1;
		uint32_t	cfg_hdr_fmt:7;
		uint32_t	timer:8;
		uint32_t	cache_line_sz:8;
#else
		uint32_t	cache_line_sz:8;
		uint32_t	timer:8;
		uint32_t	cfg_hdr_fmt:7;
		uint32_t	mult_func_dev:1;
		uint32_t	value:8;
#endif
	} bits;
} bist_hdrtyp_lattmr_cashlsz_t;


/*
 * Register: PioBar0
 * PIO BAR0
 * Description: PIO BAR0 - For Hydra PIO space PIO BAR1 & PIO BAR0
 * are together configured as a 64b BAR register (Synopsys core
 * implementation dependent) where PIO BAR1 handles the upper address
 * bits and PIO BAR0 handles the lower address bits.
 * Fields:
 *     Base Address Relocation : indirect dbi writeable via bar0Mask
 *     register in EP core
 *     Base Address for PIO (16MB space) : indirect dbi writeable via
 *     bar0Mask register in EP core
 *     Prefetchable if memory BAR (PIOs not prefetchable): dbi
 *     writeable
 *     If memory BAR, then 32 or 64 bit BAR (00 = 32 bit, 10 = 64
 *     bit): dbi writeable
 *     I/O or Memory space indicator (0 = memory BAR): dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_addr_rel_lo:8;
		uint32_t	base_addr:20;
		uint32_t	pftch:1;
		uint32_t	type:2;
		uint32_t	mem_sp_ind:1;
#else
		uint32_t	mem_sp_ind:1;
		uint32_t	type:2;
		uint32_t	pftch:1;
		uint32_t	base_addr:20;
		uint32_t	base_addr_rel_lo:8;
#endif
	} bits;
} pio_bar0_t;


/*
 * Register: PioBar1
 * PIO BAR1
 * Description: PIO BAR1
 * Fields:
 *     Base Address Relocation : indirect dbi writeable via bar0Mask
 *     register in EP core
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_addr_rel_hi:32;
#else
		uint32_t	base_addr_rel_hi:32;
#endif
	} bits;
} pio_bar1_t;


/*
 * Register: MsixBar0
 * MSIX BAR0
 * Description: MSIX BAR0 - For MSI-X Tables and PBA MSIX BAR1 & MSIX
 * BAR0 are together configured as a 64b BAR register (Synopsys core
 * implementation dependent) where MSIX BAR1 handles the upper
 * address bits and MSIX BAR0 handles the lower address bits.
 * Fields:
 *     Base Address Relocation : indirect dbi writeable via bar2Mask
 *     register in EP core
 *     Base Address for MSIX (16KB space) : indirect dbi writeable
 *     via bar2Mask register in EP core
 *     Prefetchable if memory BAR (Not prefetchable) : dbi writeable
 *     If memory BAR, then 32 or 64 bit BAR (00 = 32 bit, 10 = 64
 *     bit): dbi writeable
 *     I/O or Memory space indicator (0 = memory BAR) : dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_addr_rel_lo:18;
		uint32_t	base_addr:10;
		uint32_t	pftch:1;
		uint32_t	type:2;
		uint32_t	mem_sp_ind:1;
#else
		uint32_t	mem_sp_ind:1;
		uint32_t	type:2;
		uint32_t	pftch:1;
		uint32_t	base_addr:10;
		uint32_t	base_addr_rel_lo:18;
#endif
	} bits;
} msix_bar0_t;


/*
 * Register: MsixBar1
 * MSIX BAR1
 * Description: MSIX BAR1
 * Fields:
 *     Base Address Relocation : indirect dbi writeable via bar2Mask
 *     register in EP core
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_addr_rel_hi:32;
#else
		uint32_t	base_addr_rel_hi:32;
#endif
	} bits;
} msix_bar1_t;


/*
 * Register: VirtBar0
 * Virtualization BAR0
 * Description: Virtualization BAR0 - Previously for Hydra
 * Virtualization space This bar is no longer enabled and is not dbi
 * writeable. VIRT BAR1 & VIRT BAR0 could be configured as a 64b BAR
 * register (Synopsys core implementation dependent), but this is not
 * used in hydra.
 * Fields:
 *     Base Address Relocation
 *     Base Address for Virtualization (64KB space)
 *     Prefetchable if memory BAR (Not prefetchable)
 *     If memory BAR, then 32 or 64 bit BAR (00 = 32 bit, 10 = 64
 *     bit)
 *     I/O or Memory space indicator (0 = memory BAR)
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_addr_rel_lo:17;
		uint32_t	base_addr:11;
		uint32_t	pftch:1;
		uint32_t	type:2;
		uint32_t	mem_sp_ind:1;
#else
		uint32_t	mem_sp_ind:1;
		uint32_t	type:2;
		uint32_t	pftch:1;
		uint32_t	base_addr:11;
		uint32_t	base_addr_rel_lo:17;
#endif
	} bits;
} virt_bar0_t;


/*
 * Register: VirtBar1
 * Virtualization BAR1
 * Description: Previously for Virtualization BAR1 This bar is no
 * longer enabled and is not dbi writeable.
 * Fields:
 *     Base Address Relocation
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_addr_rel_hi:32;
#else
		uint32_t	base_addr_rel_hi:32;
#endif
	} bits;
} virt_bar1_t;


/*
 * Register: CisPtr
 * CardBus CIS Pointer
 * Description: CardBus CIS Pointer
 * Fields:
 *     CardBus CIS Pointer: dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	cis_ptr:32;
#else
		uint32_t	cis_ptr:32;
#endif
	} bits;
} cis_ptr_t;


/*
 * Register: SubVendorId
 * Subsystem ID and Vendor ID
 * Description: Subsystem ID and Vendor ID
 * Fields:
 *     Subsystem ID as assigned by PCI-SIG : dbi writeable
 *     Subsystem Vendor ID as assigned by PCI-SIG : dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	dev_id:16;
		uint32_t	vendor_id:16;
#else
		uint32_t	vendor_id:16;
		uint32_t	dev_id:16;
#endif
	} bits;
} sub_vendor_id_t;


/*
 * Register: ExpRomBar
 * Expansion ROM BAR
 * Description: Expansion ROM BAR - For Hydra EEPROM space
 * Fields:
 *     Base Address Relocatable : indirect dbi writeable via
 *     romBarMask register in EP core
 *     Base Address for ROM (2MB) : indirect dbi writeable via
 *     romBarMask register in EP core
 *     ROM Enable: dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	base_addr_rel:11;
		uint32_t	base_addr:10;
		uint32_t	rsrvd:10;
		uint32_t	rom_en:1;
#else
		uint32_t	rom_en:1;
		uint32_t	rsrvd:10;
		uint32_t	base_addr:10;
		uint32_t	base_addr_rel:11;
#endif
	} bits;
} exp_rom_bar_t;


/*
 * Register: CapPtr
 * Capabilities Pointer
 * Description: Capabilities Pointer
 * Fields:
 *     Pointer to PM Capability structure : dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	pm_ptr:8;
#else
		uint32_t	pm_ptr:8;
		uint32_t	rsrvd:24;
#endif
	} bits;
} cap_ptr_t;


/*
 * Register: IntLine
 * Interrupt Line
 * Description: Interrupt Line
 * Fields:
 *     Max Latency (N/A in PCIE)
 *     Minimum Grant (N/A in PCIE)
 *     Interrupt pin: dbi writeable
 *     Interrupt Line
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	max_lat:8;
		uint32_t	min_gnt:8;
		uint32_t	int_pin:8;
		uint32_t	int_line:8;
#else
		uint32_t	int_line:8;
		uint32_t	int_pin:8;
		uint32_t	min_gnt:8;
		uint32_t	max_lat:8;
#endif
	} bits;
} int_line_t;


/*
 * Register: PmCap
 * Power Management Capability
 * Description: Power Management Capability
 * Fields:
 *     PME Support (N/A in Hydra): dbi writeable
 *     D2 Support (N/A in Hydra): dbi writeable
 *     D1 Support (N/A in Hydra): dbi writeable
 *     Aux Current (N/A in Hydra): dbi writeable
 *     Device Specific Initialization: dbi writeable
 *     PME Clock (N/A in PCIE)
 *     PM Spec Version: dbi writeable
 *     Next Capability Pointer: dbi writeable
 *     Power Management Capability ID: dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	pme_supt:5;
		uint32_t	d2_supt:1;
		uint32_t	d1_supt:1;
		uint32_t	aux_curr:3;
		uint32_t	dev_spec_init:1;
		uint32_t	rsrvd:1;
		uint32_t	pme_clk:1;
		uint32_t	pm_ver:3;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	pm_id:8;
#else
		uint32_t	pm_id:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	pm_ver:3;
		uint32_t	pme_clk:1;
		uint32_t	rsrvd:1;
		uint32_t	dev_spec_init:1;
		uint32_t	aux_curr:3;
		uint32_t	d1_supt:1;
		uint32_t	d2_supt:1;
		uint32_t	pme_supt:5;
#endif
	} bits;
} pm_cap_t;


/*
 * Register: PmCtrlStat
 * Power Management Control and Status
 * Description: Power Management Control and Status
 * Fields:
 *     Data for additional info (N/A)
 *     Bus Power and Clock Control Enable (N/A in PCIE)
 *     B2/B3 Support (N/A in PCIE)
 *     Indicates if PME event occured
 *     Data Scale (N/A)
 *     Data Select (N/A)
 *     PME Enable (Sticky)
 *     Power State
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	pwr_data:8;
		uint32_t	pwr_clk_en:1;
		uint32_t	b2_b3_supt:1;
		uint32_t	rsrvd:6;
		uint32_t	pme_stat:1;
		uint32_t	data_scale:2;
		uint32_t	data_sel:4;
		uint32_t	pme_en:1;
		uint32_t	rsrvd1:6;
		uint32_t	pwr_st:2;
#else
		uint32_t	pwr_st:2;
		uint32_t	rsrvd1:6;
		uint32_t	pme_en:1;
		uint32_t	data_sel:4;
		uint32_t	data_scale:2;
		uint32_t	pme_stat:1;
		uint32_t	rsrvd:6;
		uint32_t	b2_b3_supt:1;
		uint32_t	pwr_clk_en:1;
		uint32_t	pwr_data:8;
#endif
	} bits;
} pm_ctrl_stat_t;


/*
 * Register: MsiCap
 * MSI Capability
 * Description: MSI Capability
 * Fields:
 *     Mask and Pending bits available
 *     64-bit Address Capable
 *     Multiple Messages Enabled
 *     Multiple Message Capable (32 messages = 0x5)
 *     MSI Enabled (if enabled, INTx must be diabled)
 *     Next Capability Pointer: dbi writeable
 *     MSI Capability ID
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:7;
		uint32_t	vect_mask:1;
		uint32_t	msi64_en:1;
		uint32_t	mult_msg_en:3;
		uint32_t	mult_msg_cap:3;
		uint32_t	msi_en:1;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	msi_cap_id:8;
#else
		uint32_t	msi_cap_id:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	msi_en:1;
		uint32_t	mult_msg_cap:3;
		uint32_t	mult_msg_en:3;
		uint32_t	msi64_en:1;
		uint32_t	vect_mask:1;
		uint32_t	rsrvd:7;
#endif
	} bits;
} msi_cap_t;


/*
 * Register: MsiLoAddr
 * MSI Low Address
 * Description: MSI Low Address
 * Fields:
 *     Lower 32 bit Address
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	lo_addr:30;
		uint32_t	rsrvd:2;
#else
		uint32_t	rsrvd:2;
		uint32_t	lo_addr:30;
#endif
	} bits;
} msi_lo_addr_t;


/*
 * Register: MsiHiAddr
 * MSI High Address
 * Description: MSI High Address
 * Fields:
 *     Upper 32 bit Address (only if msi64En = 1)
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	hi_addr:32;
#else
		uint32_t	hi_addr:32;
#endif
	} bits;
} msi_hi_addr_t;


/*
 * Register: MsiData
 * MSI Data
 * Description: MSI Data
 * Fields:
 *     MSI Data. Depending on the value for multMsgEn in the MSI
 *     Capability Register which determines the number of allocated
 *     vectors, bits [4:0] may be replaced with msiVector[4:0] bits
 *     to generate up to 32 MSI messages. # allocated vectors Actual
 *     messageData[4:0] ------------------- ------------------------
 *     1 DATA[4:0] (no replacement) 2 {DATA[4:1], msiVector[0]} 4
 *     {DATA[4:2], msiVector[1:0]} 8 {DATA[4:3], msiVector[2:0]} 16
 *     {DATA[4], msiVector[3:0]} 32 msiVector[4:0] (full replacement)
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	data:16;
#else
		uint32_t	data:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} msi_data_t;


/*
 * Register: MsiMask
 * MSI Mask
 * Description: MSI Mask
 * Fields:
 *     per vector MSI Mask bits
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mask:32;
#else
		uint32_t	mask:32;
#endif
	} bits;
} msi_mask_t;


/*
 * Register: MsiPend
 * MSI Pending
 * Description: MSI Pending
 * Fields:
 *     per vector MSI Pending bits
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	pend:32;
#else
		uint32_t	pend:32;
#endif
	} bits;
} msi_pend_t;


/*
 * Register: MsixCap
 * MSIX Capability
 * Description: MSIX Capability
 * Fields:
 *     MSIX Enable (if enabled, MSI and INTx must be disabled)
 *     Function Mask (1 = all vectors masked regardless of per vector
 *     mask, 0 = each vector's mask
 *     Table Size (0x1F = 32 entries): dbi writeable
 *     Next Capability Pointer: dbi writeable
 *     MSIX Capability ID
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	msix_en:1;
		uint32_t	func_mask:1;
		uint32_t	rsrvd:3;
		uint32_t	tab_sz:11;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	msix_cap_id:8;
#else
		uint32_t	msix_cap_id:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	tab_sz:11;
		uint32_t	rsrvd:3;
		uint32_t	func_mask:1;
		uint32_t	msix_en:1;
#endif
	} bits;
} msix_cap_t;


/*
 * Register: MsixTabOff
 * MSIX Table Offset
 * Description: MSIX Table Offset
 * Fields:
 *     Table Offset (Base address of MSIX Table = msixTabBir.BAR +
 *     msixTabOff) : dbi writeable
 *     Table BAR Indicator (0x2 = BAR2 at loc 0x18) : dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	msix_tab_off:29;
		uint32_t	msix_tab_bir:3;
#else
		uint32_t	msix_tab_bir:3;
		uint32_t	msix_tab_off:29;
#endif
	} bits;
} msix_tab_off_t;


/*
 * Register: MsixPbaOff
 * MSIX PBA Offset
 * Description: MSIX PBA Offset
 * Fields:
 *     Pending Bit Array (PBA) Offset (Base address of MSIX Table =
 *     msixTabBir.BAR + msixPbaOff); msixPbaOff is quad-aligned, i.e.
 *     starts at 0x2000 (half-way in MSI-X bar space. : dbi writeable
 *     Pending Bit Array (PBA) BAR Indicator (0x2 = BAR2 at loc 0x18)
 *     : dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	msix_pba_off:29;
		uint32_t	msix_pba_bir:3;
#else
		uint32_t	msix_pba_bir:3;
		uint32_t	msix_pba_off:29;
#endif
	} bits;
} msix_pba_off_t;


/*
 * Register: PcieCap
 * PCIE Capability
 * Description: PCIE Capability
 * Fields:
 *     Interrupt Message Number (updated by HW)
 *     Slot Implemented (Endpoint must be 0)
 *     PCIE Express Device Port Type (Endpoint)
 *     PCIE Express Capability Version
 *     Next Capability Pointer: dbi writeable
 *     PCI Express Capability ID
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:2;
		uint32_t	int_msg_num:5;
		uint32_t	pcie_slt_imp:1;
		uint32_t	pcie_dev_type:4;
		uint32_t	pcie_cap_ver:4;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	pcie_cap_id:8;
#else
		uint32_t	pcie_cap_id:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	pcie_cap_ver:4;
		uint32_t	pcie_dev_type:4;
		uint32_t	pcie_slt_imp:1;
		uint32_t	int_msg_num:5;
		uint32_t	rsrvd:2;
#endif
	} bits;
} pcie_cap_t;


/*
 * Register: DevCap
 * Device Capability
 * Description: Device Capability
 * Fields:
 *     Slot Power Limit Scale (Msg from RC) Hydra can capture
 *     Received setSlotPowerLimit message; values in this field are
 *     ignored as no power scaling is possible.
 *     Slot Power Limit Value (Msg from RC) Hydra can capture
 *     Received setSlotPowerLimit message; values in this field are
 *     ignored as no power scaling is possible.
 *     Introduced in PCIe 1.1 specification. : dbi writeable
 *     L1 Acceptable Latency (4 - 8 us) : dbi writeable
 *     LOs Acceptable Latency (2 - 4 us) : dbi writeable
 *     Extended Tag Field Support (N/A) : dbi writeable
 *     Phantom Function Supported (N/A) : dbi writeable
 *     Maximum Payload Size supported (Hydra = 1KB) : dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:4;
		uint32_t	slt_pwr_lmt_scle:2;
		uint32_t	slt_pwr_lmt_val:8;
		uint32_t	rsrvd1:2;
		uint32_t	role_based_err:1;
		uint32_t	rsrvd2:3;
		uint32_t	l1_lat:3;
		uint32_t	los_lat:3;
		uint32_t	ext_tag:1;
		uint32_t	phant_func:2;
		uint32_t	max_mtu:3;
#else
		uint32_t	max_mtu:3;
		uint32_t	phant_func:2;
		uint32_t	ext_tag:1;
		uint32_t	los_lat:3;
		uint32_t	l1_lat:3;
		uint32_t	rsrvd2:3;
		uint32_t	role_based_err:1;
		uint32_t	rsrvd1:2;
		uint32_t	slt_pwr_lmt_val:8;
		uint32_t	slt_pwr_lmt_scle:2;
		uint32_t	rsrvd:4;
#endif
	} bits;
} dev_cap_t;


/*
 * Register: DevStatCtrl
 * Device Status and Control
 * Description: Device Control
 * Fields:
 *     Transaction Pending (1 if NP request not completed)
 *     Auxilliary Power Detected (1 if detected)
 *     Unsupported Request Detect
 *     Fatal Error Detected
 *     Non-Fatal Error Detected
 *     Correctable Error Detected ----- Control Fields
 *     Introduced in PCIe 1.1 specification.
 *     Maximum Read Request Size (default = 512B) for the device as a
 *     requester. 3'b000: 128 Bytes 3'b001: 256 Bytes 3'b010: 512
 *     Bytes 3'b011: 1K Bytes 3'b100: 2K Bytes 3'b101: 4K Bytes
 *     3'b110: Reserved 3'b111: Reserved
 *     No Snoop Enable This bit indicates the device "could", not
 *     that it does. Both this bit and the hydra specific peuCip
 *     register bit must be set for the value of this bit to impact
 *     the TLP header no snoop attribute. When both are set, hydra
 *     sets the no snoop attribute on all initiated TLPs. Software
 *     must guarantee the No Snoop attribute is used in the system
 *     correctly.
 *     Auxilliary Power PM Enable
 *     Phantom Function enable
 *     Extended Tag Field Enable
 *     Maximum Payload Size. 3-bit value has the same encodings as
 *     the maxRdSz field.
 *     Relaxed Ordering Enable This bit indicates the device "could",
 *     not that it does. Both this bit and the hydra specific peuCip
 *     register bit must be set for the value of this bit to impact
 *     the TLP header relaxed ordering attribute. When both are set,
 *     packet operations set the relaxed ordering attribute. Mailbox
 *     updates always set the relaxed ordering attribute to 0,
 *     regardless of this bit. When this bit is 0, the default
 *     Sun4u/Sun4v ordering model is used.
 *     Unsupported Request Report Enable
 *     Fatal Error Report Enable
 *     Non-Fatal Error Report Enable
 *     Correctable Error Report Enable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:10;
		uint32_t	trans_pend:1;
		uint32_t	aux_pwr_det:1;
		uint32_t	unsup_req_det:1;
		uint32_t	fat_err_det:1;
		uint32_t	nf_err_det:1;
		uint32_t	corr_err_det:1;
		uint32_t	pcie2pcix_brdg:1;
		uint32_t	max_rd_sz:3;
		uint32_t	no_snoop_en:1;
		uint32_t	aux_pwr_pm_en:1;
		uint32_t	phant_func_en:1;
		uint32_t	ext_tag_en:1;
		uint32_t	max_pld_sz:3;
		uint32_t	rlx_ord_en:1;
		uint32_t	unsup_req_en:1;
		uint32_t	fat_err_en:1;
		uint32_t	nf_err_en:1;
		uint32_t	corr_err_en:1;
#else
		uint32_t	corr_err_en:1;
		uint32_t	nf_err_en:1;
		uint32_t	fat_err_en:1;
		uint32_t	unsup_req_en:1;
		uint32_t	rlx_ord_en:1;
		uint32_t	max_pld_sz:3;
		uint32_t	ext_tag_en:1;
		uint32_t	phant_func_en:1;
		uint32_t	aux_pwr_pm_en:1;
		uint32_t	no_snoop_en:1;
		uint32_t	max_rd_sz:3;
		uint32_t	pcie2pcix_brdg:1;
		uint32_t	corr_err_det:1;
		uint32_t	nf_err_det:1;
		uint32_t	fat_err_det:1;
		uint32_t	unsup_req_det:1;
		uint32_t	aux_pwr_det:1;
		uint32_t	trans_pend:1;
		uint32_t	rsrvd:10;
#endif
	} bits;
} dev_stat_ctrl_t;


/*
 * Register: LnkCap
 * Link Capability
 * Description: Link Capability
 * Fields:
 *     Port Number : dbi writeable
 *     Introduced in PCIe 1.1 specification.
 *     Introduced in PCIe 1.1 specification.
 *     Default Clock Power Management (N/A) Introduced in PCIe 1.1
 *     specification. : dbi writeable
 *     Default L1 Exit Latency (32us to 64us => 0x6) : dbi writeable
 *     Default L0s Exit Latency (1us to 2us => 0x5) : dbi writeable
 *     Active Link PM Support (only L0s = 1) : dbi writeable
 *     Maximum Link Width (x8) : dbi writeable
 *     Maximum Link Speed (2.5 Gbps = 1) : dbi writeable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	prt_num:8;
		uint32_t	rsrvd:3;
		uint32_t	def_dll_act_rptg:1;
		uint32_t	def_surpise_down:1;
		uint32_t	def_clk_pm_cap:1;
		uint32_t	def_l1_lat:3;
		uint32_t	def_l0s_lat:3;
		uint32_t	as_lnk_pm_supt:2;
		uint32_t	max_lnk_wid:6;
		uint32_t	max_lnk_spd:4;
#else
		uint32_t	max_lnk_spd:4;
		uint32_t	max_lnk_wid:6;
		uint32_t	as_lnk_pm_supt:2;
		uint32_t	def_l0s_lat:3;
		uint32_t	def_l1_lat:3;
		uint32_t	def_clk_pm_cap:1;
		uint32_t	def_surpise_down:1;
		uint32_t	def_dll_act_rptg:1;
		uint32_t	rsrvd:3;
		uint32_t	prt_num:8;
#endif
	} bits;
} lnk_cap_t;


/*
 * Register: LnkStatCtrl
 * Link Status and Control
 * Description: Link Control
 * Fields:
 *     Slot Clock Configuration (0 = using independent clock; pg 266
 *     PCIe 1.1) : dbi writeable
 *     Link Training (N/A for EP)
 *     Training Error (N/A for EP)
 *     Negotiated Link Width (Max negotiated: x8)
 *     Negotiated Link Speed (Max negotiated: 1 = 2.5 Gbps) -----
 *     Control Fields
 *     Introduced in PCIe 1.1.
 *     Extended Synch
 *     Common Clock Configuration
 *     Retrain Link (N/A for EP)
 *     Link Disable (N/A for EP)
 *     Read Completion Boundary (128B)
 *     Active State Link PM Control
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:2;
		uint32_t	dll_active:1;
		uint32_t	slt_clk_cfg:1;
		uint32_t	lnk_train:1;
		uint32_t	train_err:1;
		uint32_t	lnk_wid:6;
		uint32_t	lnk_spd:4;
		uint32_t	rsrvd1:7;
		uint32_t	en_clkpwr_mg:1;
		uint32_t	ext_sync:1;
		uint32_t	com_clk_cfg:1;
		uint32_t	retrain_lnk:1;
		uint32_t	lnk_dis:1;
		uint32_t	rd_cmpl_bndy:1;
		uint32_t	rsrvd2:1;
		uint32_t	aspm_ctrl:2;
#else
		uint32_t	aspm_ctrl:2;
		uint32_t	rsrvd2:1;
		uint32_t	rd_cmpl_bndy:1;
		uint32_t	lnk_dis:1;
		uint32_t	retrain_lnk:1;
		uint32_t	com_clk_cfg:1;
		uint32_t	ext_sync:1;
		uint32_t	en_clkpwr_mg:1;
		uint32_t	rsrvd1:7;
		uint32_t	lnk_spd:4;
		uint32_t	lnk_wid:6;
		uint32_t	train_err:1;
		uint32_t	lnk_train:1;
		uint32_t	slt_clk_cfg:1;
		uint32_t	dll_active:1;
		uint32_t	rsrvd:2;
#endif
	} bits;
} lnk_stat_ctrl_t;


/*
 * Register: VenCapHdr
 * Vendor Specific Capability Header
 * Description: Vendor Specific Capability Header
 * Fields:
 *     Length
 *     Next Capbility Pointer
 *     Vendor Specific Capbility ID
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:8;
		uint32_t	len:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	ven_cap_id:8;
#else
		uint32_t	ven_cap_id:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	len:8;
		uint32_t	rsrvd:8;
#endif
	} bits;
} ven_cap_hdr_t;


/*
 * Register: VenCtrl
 * Vendor Specific Control
 * Description: Vendor Specific Control
 * Fields:
 *     PCIe spec absolute minimum is 50usec - (likely ~10ms). PCIe
 *     spec absolute max is 50msec. Default set for 22.2 msec via
 *     adding time as follows: Bit 23: 3.21 secs <---POR 0 Bit 22:
 *     201.3 msec <---POR 0 Bit 21: 100.8 msec <---POR 0 Bit 20: 25.2
 *     msec <---POR 0 Bit 19: 12.6 msec <---POR 1 Bit 18: 6.3 msec
 *     <---POR 1 Bit 17: 3.3 msec <---POR 1 Bit 16: if 0:
 *     Baseline0=50usec; else Baseline1(use for
 *     simulation-only)=804nsec
 *     Interrupt Control Mode (00 = Reserved, 01 = INTx emulation, 10
 *     = Reserved [Neptune INTx pins], 11 = Reserved [Neptune INTx
 *     emulation + pins]
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:8;
		uint32_t	eic_xtd_cpl_timout:8;
		uint32_t	rsrvd1:14;
		uint32_t	legacy_int_ctrl:2;
#else
		uint32_t	legacy_int_ctrl:2;
		uint32_t	rsrvd1:14;
		uint32_t	eic_xtd_cpl_timout:8;
		uint32_t	rsrvd:8;
#endif
	} bits;
} ven_ctrl_t;


/*
 * Register: VenPrtHdr
 * Vendor Specific Port Logic Header
 * Description: Vendor Specific Port Logic Header
 * Fields:
 *     Length
 *     Next Capbility Pointer (END, no more)
 *     Vendor Specific Capbility ID
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:8;
		uint32_t	len:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	ven_cap_id:8;
#else
		uint32_t	ven_cap_id:8;
		uint32_t	nxt_cap_ptr:8;
		uint32_t	len:8;
		uint32_t	rsrvd:8;
#endif
	} bits;
} ven_prt_hdr_t;


/*
 * Register: AcklatReplay
 * Ack Latency and Replay Timer register
 * Description: Ack Latency/Replay Timer
 * Fields:
 *     Replay Time limit = 16'd12429/`cxNb where cxNb=1.
 *     Round Trip Latency Time limit = 9d'4143/`cxNb where cxNb=1.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rep_tim:16;
		uint32_t	ack_tim:16;
#else
		uint32_t	ack_tim:16;
		uint32_t	rep_tim:16;
#endif
	} bits;
} acklat_replay_t;


/*
 * Register: OthMsg
 * Other Message Register
 * Description: Other Message Register
 * Fields:
 *     Message to send/Data to corrupt LCRC
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	oth_msg:32;
#else
		uint32_t	oth_msg:32;
#endif
	} bits;
} oth_msg_t;


/*
 * Register: ForceLink
 * Port Force Link
 * Description: Other Message Register
 * Fields:
 *     LinkState that the EP core will be forced to when ForceLink
 *     (bit[15]) is set
 *     Forces Link to the specified LinkState field below. Write this
 *     bit to generate a pulse to the ltssm. It clears itself once
 *     the pulse is generated. Read will always return 0.
 *     Link Number - N/A for Endpoint
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:10;
		uint32_t	link_state:6;
		uint32_t	force_link:1;
		uint32_t	rsrvd1:7;
		uint32_t	link_num:8;
#else
		uint32_t	link_num:8;
		uint32_t	rsrvd1:7;
		uint32_t	force_link:1;
		uint32_t	link_state:6;
		uint32_t	rsrvd:10;
#endif
	} bits;
} force_link_t;


/*
 * Register: AckFreq
 * ACK Frequency Register
 * Description: ACK Frequency Register
 * Fields:
 *     NFTS = 115.
 *     NFTS = 115.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:2;
		uint32_t	l1_entr_latency:3;
		uint32_t	los_entr_latency:3;
		uint32_t	cx_comm_nfts:8;
		uint32_t	nfts:8;
		uint32_t	def_ack_freq:8;
#else
		uint32_t	def_ack_freq:8;
		uint32_t	nfts:8;
		uint32_t	cx_comm_nfts:8;
		uint32_t	los_entr_latency:3;
		uint32_t	l1_entr_latency:3;
		uint32_t	rsrvd:2;
#endif
	} bits;
} ack_freq_t;


/*
 * Register: LinkCtrl
 * Port Link Control
 * Description: Port Link Control
 * Fields:
 *     8 lanes
 *     When set, this bit is only set for 1 cycle. A write of 0 has
 *     no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:4;
		uint32_t	rsrvd1:2;
		uint32_t	corrupt_lcrc:1;
		uint32_t	rsrvd2:1;
		uint32_t	rsrvd3:2;
		uint32_t	link_mode_en:6;
		uint32_t	rsrvd4:4;
		uint32_t	rsrvd5:4;
		uint32_t	fast_link_mode:1;
		uint32_t	rsrvd6:1;
		uint32_t	dll_link_en:1;
		uint32_t	rsrvd7:1;
		uint32_t	reset_assert:1;
		uint32_t	lpbk_en:1;
		uint32_t	scram_dis:1;
		uint32_t	oth_msg_req:1;
#else
		uint32_t	oth_msg_req:1;
		uint32_t	scram_dis:1;
		uint32_t	lpbk_en:1;
		uint32_t	reset_assert:1;
		uint32_t	rsrvd7:1;
		uint32_t	dll_link_en:1;
		uint32_t	rsrvd6:1;
		uint32_t	fast_link_mode:1;
		uint32_t	rsrvd5:4;
		uint32_t	rsrvd4:4;
		uint32_t	link_mode_en:6;
		uint32_t	rsrvd3:2;
		uint32_t	rsrvd2:1;
		uint32_t	corrupt_lcrc:1;
		uint32_t	rsrvd1:2;
		uint32_t	rsrvd:4;
#endif
	} bits;
} link_ctrl_t;


/*
 * Register: LaneSkew
 * Lane Skew Register
 * Description: Lane Skew Register
 * Fields:
 *     prevents EP core from sending Ack/Nack DLLPs
 *     prevents EP core from sending FC DLLPs
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	dis_lane_to_lane_deskew:1;
		uint32_t	rsrvd:5;
		uint32_t	ack_nack_dis:1;
		uint32_t	flow_control_dis:1;
		uint32_t	tx_lane_skew:24;
#else
		uint32_t	tx_lane_skew:24;
		uint32_t	flow_control_dis:1;
		uint32_t	ack_nack_dis:1;
		uint32_t	rsrvd:5;
		uint32_t	dis_lane_to_lane_deskew:1;
#endif
	} bits;
} lane_skew_t;


/*
 * Register: SymbolNum
 * Symbol Number Register
 * Description: Symbol Number Register
 * Fields:
 *     Timer modifier for Flow control Watch Dog timer
 *     Timer modifier for Ack/Nack latency timer
 *     Timer modifier for Replay timer
 *     Note: rtl uses defaultNSkipSymbols
 *     Note: rtl initialized using defaultNTs1Symbols
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:3;
		uint32_t	fc_wdog_tim_mod:5;
		uint32_t	ack_nack_tim_mod:5;
		uint32_t	rep_tim_mod:5;
		uint32_t	rsrvd1:3;
		uint32_t	num_skip_symb:3;
		uint32_t	rsrvd2:4;
		uint32_t	num_ts_symb:4;
#else
		uint32_t	num_ts_symb:4;
		uint32_t	rsrvd2:4;
		uint32_t	num_skip_symb:3;
		uint32_t	rsrvd1:3;
		uint32_t	rep_tim_mod:5;
		uint32_t	ack_nack_tim_mod:5;
		uint32_t	fc_wdog_tim_mod:5;
		uint32_t	rsrvd:3;
#endif
	} bits;
} symbol_num_t;


/*
 * Register: SymbTimRadmFlt1
 * Symbol Timer Register / RADM Filter Mask Register 1
 * Description: Symbol Timer / RADM Filter Mask 1
 * Fields:
 *     No masking errors while filtering
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mask_radm_flt:16;
		uint32_t	dis_fc_wdog:1;
		uint32_t	rsrvd:4;
		uint32_t	skip_interval:11;
#else
		uint32_t	skip_interval:11;
		uint32_t	rsrvd:4;
		uint32_t	dis_fc_wdog:1;
		uint32_t	mask_radm_flt:16;
#endif
	} bits;
} symb_tim_radm_flt1_t;


/*
 * Register: RadmFlt2
 * RADM Filter Mask Register 2
 * Description: RADM Filter Mask Register 2
 * Fields:
 *     [31:2] = Reserved [1]=0=Vendor MSG Type0 dropped & treated as
 *     UR, [0]=0=Vendor MSG Type1 silently dropped.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mask_radm_flt:32;
#else
		uint32_t	mask_radm_flt:32;
#endif
	} bits;
} radm_flt2_t;


/*
 * Register: CascadeDebReg0
 * Cascade core (EP) Debug Register 0
 * Description: Debug Register 0 EP Core SII Interface bus :
 * cxplDebugInfo[31:0]
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rmlh_ts_link_ctrl:4;
		uint32_t	rmlh_ts_lane_num_is_k237:1;
		uint32_t	rmlh_ts_link_num_is_k237:1;
		uint32_t	rmlh_rcvd_idle_bit0:1;
		uint32_t	rmlh_rcvd_idle_bit1:1;
		uint32_t	mac_phy_txdata:16;
		uint32_t	mac_phy_txdatak:2;
		uint32_t	rsrvd:1;
		uint32_t	xmlh_ltssm_state:5;
#else
		uint32_t	xmlh_ltssm_state:5;
		uint32_t	rsrvd:1;
		uint32_t	mac_phy_txdatak:2;
		uint32_t	mac_phy_txdata:16;
		uint32_t	rmlh_rcvd_idle_bit1:1;
		uint32_t	rmlh_rcvd_idle_bit0:1;
		uint32_t	rmlh_ts_link_num_is_k237:1;
		uint32_t	rmlh_ts_lane_num_is_k237:1;
		uint32_t	rmlh_ts_link_ctrl:4;
#endif
	} bits;
} cascade_deb_reg0_t;


/*
 * Register: CascadeDebReg1
 * Cascade Core (EP) Debug Register 1
 * Description: Debug Register 1 EP Core SII Interface bus :
 * cxplDebugInfo[63:32]
 * Fields:
 *     PCIe Link status. 0=down, 1=up
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	xmlh_scrambler_disable:1;
		uint32_t	xmlh_link_disable:1;
		uint32_t	xmlh_link_in_training:1;
		uint32_t	xmlh_rcvr_revrs_pol_en:1;
		uint32_t	xmlh_training_rst_n:1;
		uint32_t	rsrvd:4;
		uint32_t	mac_phy_txdetectrx_loopback:1;
		uint32_t	mac_phy_txelecidle_bit0:1;
		uint32_t	mac_phy_txcompliance_bit0:1;
		uint32_t	app_init_rst:1;
		uint32_t	rsrvd1:3;
		uint32_t	rmlh_rs_link_num:8;
		uint32_t	rmlh_link_mode:3;
		uint32_t	xmlh_link_up:1;
		uint32_t	rmlh_inskip_rcv:1;
		uint32_t	rmlh_ts1_rcvd:1;
		uint32_t	rmlh_ts2_rcvd:1;
		uint32_t	rmlh_rcvd_lane_rev:1;
#else
		uint32_t	rmlh_rcvd_lane_rev:1;
		uint32_t	rmlh_ts2_rcvd:1;
		uint32_t	rmlh_ts1_rcvd:1;
		uint32_t	rmlh_inskip_rcv:1;
		uint32_t	xmlh_link_up:1;
		uint32_t	rmlh_link_mode:3;
		uint32_t	rmlh_rs_link_num:8;
		uint32_t	rsrvd1:3;
		uint32_t	app_init_rst:1;
		uint32_t	mac_phy_txcompliance_bit0:1;
		uint32_t	mac_phy_txelecidle_bit0:1;
		uint32_t	mac_phy_txdetectrx_loopback:1;
		uint32_t	rsrvd:4;
		uint32_t	xmlh_training_rst_n:1;
		uint32_t	xmlh_rcvr_revrs_pol_en:1;
		uint32_t	xmlh_link_in_training:1;
		uint32_t	xmlh_link_disable:1;
		uint32_t	xmlh_scrambler_disable:1;
#endif
	} bits;
} cascade_deb_reg1_t;


/*
 * Register: TxpFcCreditStat
 * Transmit Posted FC Credit Status
 * Description: Transmit Posted FC Credit Status
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:12;
		uint32_t	txp_fc_hdr_credit_stat:8;
		uint32_t	txp_fc_data_credit_stat:12;
#else
		uint32_t	txp_fc_data_credit_stat:12;
		uint32_t	txp_fc_hdr_credit_stat:8;
		uint32_t	rsrvd:12;
#endif
	} bits;
} txp_fc_credit_stat_t;


/*
 * Register: TxnpFcCreditStat
 * Transmit Non-Posted FC Credit Status
 * Description: Transmit Non-Posted FC Credit Status
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:12;
		uint32_t	txnp_fc_hdr_credit_stat:8;
		uint32_t	txnp_fc_data_credit_stat:12;
#else
		uint32_t	txnp_fc_data_credit_stat:12;
		uint32_t	txnp_fc_hdr_credit_stat:8;
		uint32_t	rsrvd:12;
#endif
	} bits;
} txnp_fc_credit_stat_t;


/*
 * Register: TxcplFcCreditStat
 * Transmit Completion FC Credit Status
 * Description: Transmit Completion FC Credit Status
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:12;
		uint32_t	txcpl_fc_hdr_credit_stat:8;
		uint32_t	txcpl_fc_data_credit_stat:12;
#else
		uint32_t	txcpl_fc_data_credit_stat:12;
		uint32_t	txcpl_fc_hdr_credit_stat:8;
		uint32_t	rsrvd:12;
#endif
	} bits;
} txcpl_fc_credit_stat_t;


/*
 * Register: QueueStat
 * Queue Status
 * Description: Queue Status
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:29;
		uint32_t	rx_queue_not_empty:1;
		uint32_t	tx_rbuf_not_empty:1;
		uint32_t	tx_fc_credit_not_ret:1;
#else
		uint32_t	tx_fc_credit_not_ret:1;
		uint32_t	tx_rbuf_not_empty:1;
		uint32_t	rx_queue_not_empty:1;
		uint32_t	rsrvd:29;
#endif
	} bits;
} queue_stat_t;


/*
 * Register: GbtDebug0
 * GBT Debug, Status register
 * Description: This register returns bits [31:0] of the PIPE core's
 * gbtDebug bus
 * Fields:
 *     [6] & [22] = rxclkO will always read 1'b0 [7] & [23] =
 *     tbcout10O will always read 1'b0
 * The value specified here is the Power On Reset value as given
 *     in spec. except for the clock bits which are hardwired to
 *     1'b0.
 * The gbtDebug[0:15] bus is provided for each lane as an output
 *     from the pcieGbtopWrapper.v module. These signals are not
 *     required for manufacturing test and may be left unconnected.
 *     The cw00041130PipeParam.vh bus width is the number of lanes
 *     multiplied by 16. lane0 is bits[15:0], lane1 is bits[31:16],
 *     lane2 is bits[47:32], lane3 is bits[63:48], lane4 is
 *     bits[79:64], lane5 is bits[95:80], lane6 is bits[111:96],
 *     lane7 is bits[127:112].
 * Refer to section 4.2.2.4, Gigablaze Debug Signals section.
 *     (pgs 4.27 - 4.28) in the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 *     lane0 is bits[15:0], which is gbtDebug0[15:0] lane1 is
 *     bits[31:16], which is gbtDebug0[31:16]
 *
 *     -------------------------------------------------------------------------
 *     Signal Bit Reset Description
 *     -------------------------------------------------------------------------
 *     gbtResetRbcI [16n+15] [15] 1 Reset receiver bit clock
 *     gbtResetTbc20I [16n+14] [14] 1 Reset transmit 20-bit clock
 *     gbtResetRI [16n+13] [13] 1 Reset receiver logic gbtResetTI
 *     [16n+12] [12] 1 Reset transmit logic reserved [16n+11:16n+8]
 *     [11:8] 0 reserved gbtTbcout10 [16n+7] [7] 1 transmit clock
 *     10-bit gbtRxclkO [16n+6] [6] 0 receiver PLL clock gbtRxpresO
 *     [16n+5] [5] 0 receiver detect present gbtRxpresvalidO [16n+4]
 *     [4] 0 gbtRxpresO is valid gbtRxlosO [16n+3] [3] 1 raw receiver
 *     loss-of-signal gbtPassnO [16n+2] [2] 1 GigaBlaze BIST pass
 *     active low reserved [16n+1] [1] 0 reserved reserved [16n] [0]
 *     0 reserved
 *     -------------------------------------------------------------------------
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} gbt_debug0_t;


/*
 * Register: GbtDebug1
 * GBT Debug, Status register
 * Description: This register returns bits [63:32] of the PIPE core's
 * gbtDebug bus
 * Fields:
 *     [6] & [22] = rxclkO will always read 1'b0 [7] & [23] =
 *     tbcout10O will always read 1'b0
 * The value specified here is the Power On Reset value as given
 *     in spec. except for the clock bits which are hardwired to
 *     1'b0.
 * The gbtDebug[0:15] bus is provided for each lane as an output
 *     from the pcieGbtopWrapper.v module. These signals are not
 *     required for manufacturing test and may be left unconnected.
 *     The cw00041130PipeParam.vh bus width is the number of lanes
 *     multiplied by 16.
 * Refer to section 4.2.2.4, Gigablaze Debug Signals section.
 *     (pgs 4.27 - 4.28) in the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 *     lane2 is bits[47:32], which is gbtDebug1[15:0] lane3 is
 *     bits[63:48], which is gbtDebug1[31:16]
 *
 *     -------------------------------------------------------------------------
 *     Signal Bit Reset Description
 *     -------------------------------------------------------------------------
 *     gbtResetRbcI [16n+15] [15] 1 Reset receiver bit clock
 *     gbtResetTbc20I [16n+14] [14] 1 Reset transmit 20-bit clock
 *     gbtResetRI [16n+13] [13] 1 Reset receiver logic gbtResetTI
 *     [16n+12] [12] 1 Reset transmit logic reserved [16n+11:16n+8]
 *     [11:8] 0 reserved gbtTbcout10 [16n+7] [7] 1 transmit clock
 *     10-bit gbtRxclkO [16n+6] [6] 0 receiver PLL clock gbtRxpresO
 *     [16n+5] [5] 0 receiver detect present gbtRxpresvalidO [16n+4]
 *     [4] 0 gbtRxpresO is valid gbtRxlosO [16n+3] [3] 1 raw receiver
 *     loss-of-signal gbtPassnO [16n+2] [2] 1 GigaBlaze BIST pass
 *     active low reserved [16n+1] [1] 0 reserved reserved [16n] [0]
 *     0 reserved
 *     -------------------------------------------------------------------------
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} gbt_debug1_t;


/*
 * Register: GbtDebug2
 * GBT Debug, Status register
 * Description: This register returns bits [95:64] of the PIPE core's
 * gbtDebug bus
 * Fields:
 *     [6] & [22] = rxclkO will always read 1'b0 [7] & [23] =
 *     tbcout10O will always read 1'b0
 * The value specified here is the Power On Reset value as given
 *     in spec. except for the clock bits which are hardwired to
 *     1'b0.
 * The gbtDebug[0:15] bus is provided for each lane as an output
 *     from the pcieGbtopWrapper.v module. These signals are not
 *     required for manufacturing test and may be left unconnected.
 *     The cw00041130PipeParam.vh bus width is the number of lanes
 *     multiplied by 16.
 * Refer to section 4.2.2.4, Gigablaze Debug Signals section.
 *     (pgs 4.27 - 4.28) in the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 *     lane4 is bits[79:64], which is gbtDebug2[15:0] lane5 is
 *     bits[95:80], which is gbtDebug2[31:16]
 *
 *     -------------------------------------------------------------------------
 *     Signal Bit Reset Description
 *     -------------------------------------------------------------------------
 *     gbtResetRbcI [16n+15] [15] 1 Reset receiver bit clock
 *     gbtResetTbc20I [16n+14] [14] 1 Reset transmit 20-bit clock
 *     gbtResetRI [16n+13] [13] 1 Reset receiver logic gbtResetTI
 *     [16n+12] [12] 1 Reset transmit logic reserved [16n+11:16n+8]
 *     [11:8] 0 reserved gbtTbcout10 [16n+7] [7] 1 transmit clock
 *     10-bit gbtRxclkO [16n+6] [6] 0 receiver PLL clock gbtRxpresO
 *     [16n+5] [5] 0 receiver detect present gbtRxpresvalidO [16n+4]
 *     [4] 0 gbtRxpresO is valid gbtRxlosO [16n+3] [3] 1 raw receiver
 *     loss-of-signal gbtPassnO [16n+2] [2] 1 GigaBlaze BIST pass
 *     active low reserved [16n+1] [1] 0 reserved reserved [16n] [0]
 *     0 reserved
 *     -------------------------------------------------------------------------
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} gbt_debug2_t;


/*
 * Register: GbtDebug3
 * GBT Debug, Status register
 * Description: This register returns bits [127:96] of the PIPE
 * core's gbtDebug bus
 * Fields:
 *     [6] & [22] = rxclkO will always read 1'b0 [7] & [23] =
 *     tbcout10O will always read 1'b0
 * The value specified here is the Power On Reset value as given
 *     in spec. except for the clock bits which are hardwired to
 *     1'b0.
 * The gbtDebug[0:15] bus is provided for each lane as an output
 *     from the pcieGbtopWrapper.v module. These signals are not
 *     required for manufacturing test and may be left unconnected.
 *     The cw00041130PipeParam.vh bus width is the number of lanes
 *     multiplied by 16.
 * Refer to section 4.2.2.4, Gigablaze Debug Signals section.
 *     (pgs 4.27 - 4.28) in the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 *     lane6 is bits[111:96], which is gbtDebug3[15:0] lane7 is
 *     bits[127:112], which is gbtDebug3[31:16]
 *
 *     -------------------------------------------------------------------------
 *     Signal Bit Reset Description
 *     -------------------------------------------------------------------------
 *     gbtResetRbcI [16n+15] [15] 1 Reset receiver bit clock
 *     gbtResetTbc20I [16n+14] [14] 1 Reset transmit 20-bit clock
 *     gbtResetRI [16n+13] [13] 1 Reset receiver logic gbtResetTI
 *     [16n+12] [12] 1 Reset transmit logic reserved [16n+11:16n+8]
 *     [11:8] 0 reserved gbtTbcout10 [16n+7] [7] 1 transmit clock
 *     10-bit gbtRxclkO [16n+6] [6] 0 receiver PLL clock gbtRxpresO
 *     [16n+5] [5] 0 receiver detect present gbtRxpresvalidO [16n+4]
 *     [4] 0 gbtRxpresO is valid gbtRxlosO [16n+3] [3] 1 raw receiver
 *     loss-of-signal gbtPassnO [16n+2] [2] 1 GigaBlaze BIST pass
 *     active low reserved [16n+1] [1] 0 reserved reserved [16n] [0]
 *     0 reserved
 *     -------------------------------------------------------------------------
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} gbt_debug3_t;


/*
 * Register: PipeDebug0
 * PIPE Debug, status register
 * Description: This register returns bits [31:0] of the PIPE core's
 * gbtDebug bus
 * Fields:
 *     The value specified here is the Power On Reset value as given
 *     in spec.
 * This 16-bit debug bus reports operating conditions for the
 *     PIPE. The pipeDebug[0:15] bus is provided for each lane. lane0
 *     is bits[15:0], lane1 is bits[31:16], lane2 is bits[47:32],
 *     lane3 is bits[63:48], lane4 is bits[79:64], lane5 is
 *     bits[95:80], lane6 is bits[111:96], lane7 is bits[127:112].
 * Refer to section 4.2.1.5 Single-Lane PIPE Debug Signals in
 *     the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 *     lane0 is bit[15:0], which is pipeDebug0[15:0] lane1 is
 *     bit[31:16], which is pipeDebug0[31:16]
 *
 *     -------------------------------------------------------------------------
 *     pipeDebug Signal or Condition Description Reset
 *     -------------------------------------------------------------------------
 *     [15] efifoOverflow or EFIFO overflow or 0 efifoUnderflow EFIFO
 *     underflow occurred
 * [14] skipInsert or EFIFO skip inserted or 0 skipDelete
 *     deleted 0
 * [13] fifordData[12] == Skip flag read by EFIFO. 0 skipFlag
 *     Used with skipcharflag to verify EFIFO depth.
 * [12] skipcharflag Skip flag written by EFIFO 0
 * [11:8] efifoDepth[3:0] Indicates EFIFO depth 0000
 * [7] efifoEios Detected EFIFO 0 electrical-idle ordered-set
 *     output
 * [6] efifoBytesync EFIFO output byte 0 synchronization
 * [5] rxinvalid 8b/10b error or 0 or code violation
 * [4] rxinitdone Receiver bit-init done. 0 Synchronous with
 *     pipeClk.
 * [3] txinitdone Transmitter-bit init done. 0 Synchronous with
 *     pipeClk.
 * [2] filteredrxlos Filtered loss of signal used 1 to generate
 *     p2lRxelectidle. Synchronous with pipeClk.
 * [1] rxdetectInt Receiver detected 0
 * [0] pipeMasterDoneOut Receiver detection valid 0
 *
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} pipe_debug0_t;


/*
 * Register: PipeDebug1
 * PIPE Debug, status register
 * Description: This register returns bits [63:32] of the PIPE core's
 * gbtDebug bus
 * Fields:
 *     The value specified here is the Power On Reset value as given
 *     in spec.
 * This 16-bit debug bus reports operating conditions for the
 *     PIPE. The pipeDebug[0:15] bus is provided for each lane. lane0
 *     is bits[15:0], lane1 is bits[31:16], lane2 is bits[47:32],
 *     lane3 is bits[63:48], lane4 is bits[79:64], lane5 is
 *     bits[95:80], lane6 is bits[111:96], lane7 is bits[127:112].
 * Refer to section 4.2.1.5 Single-Lane PIPE Debug Signals in
 *     the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 * lane2 is bits[47:32], which is pipeDebug1[15:0] lane3 is
 *     bits[63:48], which is pipeDebug1[31:16]
 *
 *     -------------------------------------------------------------------------
 *     pipeDebug Signal or Condition Description Reset
 *     -------------------------------------------------------------------------
 *     [15] efifoOverflow or EFIFO overflow or 0 efifoUnderflow EFIFO
 *     underflow occurred
 * [14] skipInsert or EFIFO skip inserted or 0 skipDelete
 *     deleted 0
 * [13] fifordData[12] == Skip flag read by EFIFO. 0 skipFlag
 *     Used with skipcharflag to verify EFIFO depth.
 * [12] skipcharflag Skip flag written by EFIFO 0
 * [11:8] efifoDepth[3:0] Indicates EFIFO depth 0000
 * [7] efifoEios Detected EFIFO 0 electrical-idle ordered-set
 *     output
 * [6] efifoBytesync EFIFO output byte 0 synchronization
 * [5] rxinvalid 8b/10b error or 0 or code violation
 * [4] rxinitdone Receiver bit-init done. 0 Synchronous with
 *     pipeClk.
 * [3] txinitdone Transmitter-bit init done. 0 Synchronous with
 *     pipeClk.
 * [2] filteredrxlos Filtered loss of signal used 1 to generate
 *     p2lRxelectidle. Synchronous with pipeClk.
 * [1] rxdetectInt Receiver detected 0
 * [0] pipeMasterDoneOut Receiver detection valid 0
 *
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} pipe_debug1_t;


/*
 * Register: PipeDebug2
 * PIPE Debug, status register
 *     The value specified here is the Power On Reset value as given
 *     in spec.
 * This 16-bit debug bus reports operating conditions for the
 *     PIPE. The pipeDebug[0:15] bus is provided for each lane. lane0
 *     is bits[15:0], lane1 is bits[31:16], lane2 is bits[47:32],
 *     lane3 is bits[63:48], lane4 is bits[79:64], lane5 is
 *     bits[95:80], lane6 is bits[111:96], lane7 is bits[127:112].
 * Refer to section 4.2.1.5 Single-Lane PIPE Debug Signals in
 *     the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 * lane4 is bits[79:64], which is pipeDebug2[15:0] lane5 is
 *     bits[95:80], which is pipeDebug2[31:16]
 *
 *     -------------------------------------------------------------------------
 *     pipeDebug Signal or Condition Description Reset
 *     -------------------------------------------------------------------------
 *     [15] efifoOverflow or EFIFO overflow or 0 efifoUnderflow EFIFO
 *     underflow occurred
 * [14] skipInsert or EFIFO skip inserted or 0 skipDelete
 *     deleted 0
 * [13] fifordData[12] == Skip flag read by EFIFO. 0 skipFlag
 *     Used with skipcharflag to verify EFIFO depth.
 * [12] skipcharflag Skip flag written by EFIFO 0
 * [11:8] efifoDepth[3:0] Indicates EFIFO depth 0000
 * [7] efifoEios Detected EFIFO 0 electrical-idle ordered-set
 *     output
 * [6] efifoBytesync EFIFO output byte 0 synchronization
 * [5] rxinvalid 8b/10b error or 0 or code violation
 * [4] rxinitdone Receiver bit-init done. 0 Synchronous with
 *     pipeClk.
 * [3] txinitdone Transmitter-bit init done. 0 Synchronous with
 *     pipeClk.
 * [2] filteredrxlos Filtered loss of signal used 1 to generate
 *     p2lRxelectidle. Synchronous with pipeClk.
 * [1] rxdetectInt Receiver detected 0
 * [0] pipeMasterDoneOut Receiver detection valid 0
 *
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} pipe_debug2_t;


/*
 * Register: PipeDebug3
 * PIPE Debug, status register
 * Description: This register returns bits [127:96] of the PIPE
 * core's gbtDebug bus
 * Fields:
 *     The value specified here is the Power On Reset value as given
 *     in spec.
 * This 16-bit debug bus reports operating conditions for the
 *     PIPE. The pipeDebug[0:15] bus is provided for each lane. lane0
 *     is bits[15:0], lane1 is bits[31:16], lane2 is bits[47:32],
 *     lane3 is bits[63:48], lane4 is bits[79:64], lane5 is
 *     bits[95:80], lane6 is bits[111:96], lane7 is bits[127:112].
 * Refer to section 4.2.1.5 Single-Lane PIPE Debug Signals in
 *     the following document :
 *     /home/cadtools/cores/lsi/cw000411/cw00041131/prod/docs/manuals/
 *     cw000411TechMan.pdf
 * lane6 is bits[111:96], which is pipeDebug3[15:0] lane7 is
 *     bits[127:112], which is pipeDebug3[31:16]
 *
 *     -------------------------------------------------------------------------
 *     pipeDebug Signal or Condition Description Reset
 *     -------------------------------------------------------------------------
 *     [15] efifoOverflow or EFIFO overflow or 0 efifoUnderflow EFIFO
 *     underflow occurred
 * [14] skipInsert or EFIFO skip inserted or 0 skipDelete
 *     deleted 0
 * [13] fifordData[12] == Skip flag read by EFIFO. 0 skipFlag
 *     Used with skipcharflag to verify EFIFO depth.
 * [12] skipcharflag Skip flag written by EFIFO 0
 * [11:8] efifoDepth[3:0] Indicates EFIFO depth 0000
 * [7] efifoEios Detected EFIFO 0 electrical-idle ordered-set
 *     output
 * [6] efifoBytesync EFIFO output byte 0 synchronization
 * [5] rxinvalid 8b/10b error or 0 or code violation
 * [4] rxinitdone Receiver bit-init done. 0 Synchronous with
 *     pipeClk.
 * [3] txinitdone Transmitter-bit init done. 0 Synchronous with
 *     pipeClk.
 * [2] filteredrxlos Filtered loss of signal used 1 to generate
 *     p2lRxelectidle. Synchronous with pipeClk.
 * [1] rxdetectInt Receiver detected 0
 * [0] pipeMasterDoneOut Receiver detection valid 0
 *
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} pipe_debug3_t;


/*
 * Register: PcieEnhCapHdr
 * PCIE Enhanced Capability Header
 * Description: PCIE Enhanced Capability Header
 * Fields:
 *     Next Capability Offset (END, no more)
 *     Capability Version
 *     PCI Express Enhanced Capability ID (0x1 = Advanced Error
 *     Reporting)
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	nxt_cap_offset:12;
		uint32_t	cap_ver:4;
		uint32_t	pcie_enh_cap_id:16;
#else
		uint32_t	pcie_enh_cap_id:16;
		uint32_t	cap_ver:4;
		uint32_t	nxt_cap_offset:12;
#endif
	} bits;
} pcie_enh_cap_hdr_t;


/*
 * Register: UncErrStat
 * Uncorrectable Error Status
 * Description: Uncorrectable Error Status
 * Fields:
 *     Unsupported Request Error
 *     ECRC Error
 *     Malformed TLP
 *     Reciever Overflow
 *     Unexpected Completion
 *     Completion Abort
 *     Completion Timeout
 *     Flow Control Protocol Error
 *     Poisoned TLP
 *     Introduced in PCIe 1.1 specification.
 *     Data Link Protocol Error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	unsup_req_err:1;
		uint32_t	ecrc_err:1;
		uint32_t	bad_tlp:1;
		uint32_t	rcv_ovfl:1;
		uint32_t	unexp_cpl:1;
		uint32_t	cpl_abrt:1;
		uint32_t	cpl_tmout:1;
		uint32_t	fc_err:1;
		uint32_t	psn_tlp:1;
		uint32_t	rsrvd1:6;
		uint32_t	surprise_down_err:1;
		uint32_t	dlp_err:1;
		uint32_t	rsrvd2:4;
#else
		uint32_t	rsrvd2:4;
		uint32_t	dlp_err:1;
		uint32_t	surprise_down_err:1;
		uint32_t	rsrvd1:6;
		uint32_t	psn_tlp:1;
		uint32_t	fc_err:1;
		uint32_t	cpl_tmout:1;
		uint32_t	cpl_abrt:1;
		uint32_t	unexp_cpl:1;
		uint32_t	rcv_ovfl:1;
		uint32_t	bad_tlp:1;
		uint32_t	ecrc_err:1;
		uint32_t	unsup_req_err:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} unc_err_stat_t;


/*
 * Register: UncErrMask
 * Uncorrectable Error Mask
 * Description: Uncorrectable Error Mask
 * Fields:
 *     Unsupported Request Error
 *     ECRC Error
 *     Malformed TLP
 *     Reciever Overflow
 *     Unexpected Completion
 *     Completion Abort
 *     Completion Timeout
 *     Flow Control Protocol Error
 *     Poisoned TLP
 *     Introduced in PCIe 1.1
 *     Data Link Protocol Error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	unsup_req_err:1;
		uint32_t	ecrc_err:1;
		uint32_t	bad_tlp:1;
		uint32_t	rcv_ovfl:1;
		uint32_t	unexp_cpl:1;
		uint32_t	cpl_abrt:1;
		uint32_t	cpl_tmout:1;
		uint32_t	fc_err:1;
		uint32_t	psn_tlp:1;
		uint32_t	rsrvd1:6;
		uint32_t	surprise_down_err:1;
		uint32_t	dlp_err:1;
		uint32_t	rsrvd2:4;
#else
		uint32_t	rsrvd2:4;
		uint32_t	dlp_err:1;
		uint32_t	surprise_down_err:1;
		uint32_t	rsrvd1:6;
		uint32_t	psn_tlp:1;
		uint32_t	fc_err:1;
		uint32_t	cpl_tmout:1;
		uint32_t	cpl_abrt:1;
		uint32_t	unexp_cpl:1;
		uint32_t	rcv_ovfl:1;
		uint32_t	bad_tlp:1;
		uint32_t	ecrc_err:1;
		uint32_t	unsup_req_err:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} unc_err_mask_t;


/*
 * Register: UncErrSvrty
 * Uncorrectable Error Severity
 * Description: Uncorrectable Error Severity
 * Fields:
 *     Unsupported Request Error
 *     ECRC Error
 *     Malformed TLP
 *     Reciever Overflow
 *     Unexpected Completion
 *     Completion Abort
 *     Completion Timeout
 *     Flow Control Protocol Error
 *     Poisoned TLP
 *     Introduced in PCIe 1.1 specification. Not supported; use PCIe
 *     default.
 *     Data Link Protocol Error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	unsup_req_err:1;
		uint32_t	ecrc_err:1;
		uint32_t	bad_tlp:1;
		uint32_t	rcv_ovfl:1;
		uint32_t	unexp_cpl:1;
		uint32_t	cpl_abrt:1;
		uint32_t	cpl_tmout:1;
		uint32_t	fc_err:1;
		uint32_t	psn_tlp:1;
		uint32_t	rsrvd1:6;
		uint32_t	surprise_down_err:1;
		uint32_t	dlp_err:1;
		uint32_t	rsrvd2:4;
#else
		uint32_t	rsrvd2:4;
		uint32_t	dlp_err:1;
		uint32_t	surprise_down_err:1;
		uint32_t	rsrvd1:6;
		uint32_t	psn_tlp:1;
		uint32_t	fc_err:1;
		uint32_t	cpl_tmout:1;
		uint32_t	cpl_abrt:1;
		uint32_t	unexp_cpl:1;
		uint32_t	rcv_ovfl:1;
		uint32_t	bad_tlp:1;
		uint32_t	ecrc_err:1;
		uint32_t	unsup_req_err:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} unc_err_svrty_t;


/*
 * Register: CorrErrStat
 * Correctable Error Status
 * Description: Correctable Error Status
 * Fields:
 *     Advisory Non-Fatal Error Introduced in PCIe 1.1 specification.
 *     Reply Timer Timeout
 *     Replay Number Rollover
 *     Bad DLLP
 *     Bad TLP
 *     Receive Error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:18;
		uint32_t	adv_nf_err:1;
		uint32_t	rply_tmr_tmout:1;
		uint32_t	rsrvd1:3;
		uint32_t	rply_rlovr:1;
		uint32_t	bad_dllp:1;
		uint32_t	bad_tlp:1;
		uint32_t	rsrvd2:5;
		uint32_t	rcv_err:1;
#else
		uint32_t	rcv_err:1;
		uint32_t	rsrvd2:5;
		uint32_t	bad_tlp:1;
		uint32_t	bad_dllp:1;
		uint32_t	rply_rlovr:1;
		uint32_t	rsrvd1:3;
		uint32_t	rply_tmr_tmout:1;
		uint32_t	adv_nf_err:1;
		uint32_t	rsrvd:18;
#endif
	} bits;
} corr_err_stat_t;


/*
 * Register: CorrErrMask
 * Correctable Error Mask
 * Description: Correctable Error Mask
 * Fields:
 *     Advisory Non Fatal Error Mask
 *     Reply Timer Timeout
 *     Replay Number Rollover
 *     Bad DLLP
 *     Bad TLP
 *     Receive Error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:18;
		uint32_t	adv_nf_err_mask:1;
		uint32_t	rply_tmr_tmout:1;
		uint32_t	rsrvd1:3;
		uint32_t	rply_rlovr:1;
		uint32_t	bad_dllp:1;
		uint32_t	bad_tlp:1;
		uint32_t	rsrvd2:5;
		uint32_t	rcv_err:1;
#else
		uint32_t	rcv_err:1;
		uint32_t	rsrvd2:5;
		uint32_t	bad_tlp:1;
		uint32_t	bad_dllp:1;
		uint32_t	rply_rlovr:1;
		uint32_t	rsrvd1:3;
		uint32_t	rply_tmr_tmout:1;
		uint32_t	adv_nf_err_mask:1;
		uint32_t	rsrvd:18;
#endif
	} bits;
} corr_err_mask_t;


/*
 * Register: AdvCapCtrl
 * Advanced Capability and Control
 * Description: Advanced Capability and Control
 * Fields:
 *     ECRC Check Enable
 *     ECRC Check Capable
 *     ECRC Generation Enable
 *     ECRC Generation Capability
 *     First Error Pointer
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:23;
		uint32_t	ecrc_chk_en:1;
		uint32_t	ecrc_chk_cap:1;
		uint32_t	ecrc_gen_en:1;
		uint32_t	ecrc_gen_cap:1;
		uint32_t	st_err_ptr:5;
#else
		uint32_t	st_err_ptr:5;
		uint32_t	ecrc_gen_cap:1;
		uint32_t	ecrc_gen_en:1;
		uint32_t	ecrc_chk_cap:1;
		uint32_t	ecrc_chk_en:1;
		uint32_t	rsrvd:23;
#endif
	} bits;
} adv_cap_ctrl_t;


/*
 * Register: HdrLog0
 * Header Log0
 * Description: Header Log0
 * Fields:
 *     First DW of TLP header with error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} hdr_log0_t;


/*
 * Register: HdrLog1
 * Header Log1
 * Description: Header Log1
 * Fields:
 *     Second DW of TLP header with error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} hdr_log1_t;


/*
 * Register: HdrLog2
 * Header Log2
 * Description: Header Log2
 * Fields:
 *     Third DW of TLP header with error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} hdr_log2_t;


/*
 * Register: HdrLog3
 * Header Log3
 * Description: Header Log3
 * Fields:
 *     Fourth DW of TLP header with error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} hdr_log3_t;


/*
 * Register: PipeRxTxControl
 * Pipe Rx/Tx Control
 *     00 : ewrap : Enable wrapback test mode 01 : padLoopback :
 *     Enable Pad Serial Loopback test mode 10 : revLoopback : Enable
 *     Reverse Loopback test mode 11 : efifoLoopback : Enable PCI
 *     Express Slave loop back
 *     100 : Clock generator test x10 : Vil/Vih test x01 : Vih/Vil
 *     test x11 : No-error test. A full test of the transceiver 111 :
 *     Forced-error test. A full test of the transceiver with forced
 *     errors
 *     1 : selects 20-bit mode 0 : selects 10-bit mode
 *     1 : selects Tx 20-bit fifo mode
 *     00 : 52 us (470 cycles) 01 : 53 us (720 cycles) 10 : 54 us
 *     (970 cycles) 11 : 55 us (1220 cycles)
 *     1 : selects 20-bit mode 0 : selects 10-bit mode
 *     1 : Enable receiver reference clocks
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:1;
		uint32_t	loopback:1;
		uint32_t	loopback_mode_sel:2;
		uint32_t	rsrvd1:1;
		uint32_t	en_bist:3;
		uint32_t	tdws20:1;
		uint32_t	tdenfifo:1;
		uint32_t	rxpreswin:2;
		uint32_t	rdws20:1;
		uint32_t	enstretch:1;
		uint32_t	rsrvd2:18;
#else
		uint32_t	rsrvd2:18;
		uint32_t	enstretch:1;
		uint32_t	rdws20:1;
		uint32_t	rxpreswin:2;
		uint32_t	tdenfifo:1;
		uint32_t	tdws20:1;
		uint32_t	en_bist:3;
		uint32_t	rsrvd1:1;
		uint32_t	loopback_mode_sel:2;
		uint32_t	loopback:1;
		uint32_t	rsrvd:1;
#endif
	} bits;
} pipe_rx_tx_control_t;


/*
 * Register: PipeRxTxStatus
 * Pipe Rx/Tx Status
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:32;
#else
		uint32_t	rsrvd:32;
#endif
	} bits;
} pipe_rx_tx_status_t;


/*
 * Register: PipeRxTxPwrCntl
 * Pipe Rx/Tx Power Control
 *     1 : power down termination trimming circuit 0 : normal
 *     operation
 *     Power down PECL Clock buffer 1 : when a bit is 1, power down
 *     associated clock buffer cell 0 : normal operation
 *     Power down Transmit PLL 1 : when a bit is 1, power down
 *     associated Tx PLL circuit 0 : normal operation
 *     Power down Differential O/P Clock buffer 1 : when a bit is 1,
 *     power down associated differntial clock buffer that drives
 *     gbtClkoutN/p 0 : normal operation
 *     Power down Transmitter Analog section 1 : when a bit is 1,
 *     power down analog section of the associated Transmitter and
 *     the Tx buffer 0 : normal operation
 *     Power down RxLOS 1 : when a bit is 1, it powers down the Rx
 *     LOS circuitry for the associated serdes lanes 0 : normal
 *     operation
 *     Power down Receiver Analog section 1 : when a bit is 1, power
 *     down analog section of the associated Receiver and the Tx
 *     buffer 0 : normal operation
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:1;
		uint32_t	pdrtrim:1;
		uint32_t	pdownpecl:2;
		uint32_t	pdownpll:2;
		uint32_t	pdclkout:2;
		uint32_t	pdownt:8;
		uint32_t	pdrxlos:8;
		uint32_t	pdownr:8;
#else
		uint32_t	pdownr:8;
		uint32_t	pdrxlos:8;
		uint32_t	pdownt:8;
		uint32_t	pdclkout:2;
		uint32_t	pdownpll:2;
		uint32_t	pdownpecl:2;
		uint32_t	pdrtrim:1;
		uint32_t	rsrvd:1;
#endif
	} bits;
} pipe_rx_tx_pwr_cntl_t;


/*
 * Register: PipeRxTxParam
 * Pipe Rx/Tx Parameter
 *     Tx Driver Emphasis
 *     Serial output Slew Rate Control
 *     Tx Voltage Mux control
 *     Tx Voltage Pulse control
 *     Output Swing setting
 *     Transmitter Clock generator pole adjust
 *     Transmitter Clock generator zero adjust
 *     Receiver Clock generator pole adjust
 *     Receiver Clock generator zero adjust
 *     Bias Control for factory testing and debugging
 *     Receiver LOS Threshold adjustment. This value is determined by
 *     LSI.
 *     Receiver Input Equalizer control
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:1;
		uint32_t	emph:3;
		uint32_t	rsrvd1:1;
		uint32_t	risefall:3;
		uint32_t	vmuxlo:2;
		uint32_t	vpulselo:2;
		uint32_t	vtxlo:4;
		uint32_t	tp:2;
		uint32_t	tz:2;
		uint32_t	rp:2;
		uint32_t	rz:2;
		uint32_t	biascntl:1;
		uint32_t	losadj:3;
		uint32_t	rxeq:4;
#else
		uint32_t	rxeq:4;
		uint32_t	losadj:3;
		uint32_t	biascntl:1;
		uint32_t	rz:2;
		uint32_t	rp:2;
		uint32_t	tz:2;
		uint32_t	tp:2;
		uint32_t	vtxlo:4;
		uint32_t	vpulselo:2;
		uint32_t	vmuxlo:2;
		uint32_t	risefall:3;
		uint32_t	rsrvd1:1;
		uint32_t	emph:3;
		uint32_t	rsrvd:1;
#endif
	} bits;
} pipe_rx_tx_param_t;


/*
 * Register: PipeRxTxClock
 * Pipe Rx/Tx Clock
 *     Reverse Loopback clock select 00 : gbtRbcAO 01 : gbtRbcBO 10 :
 *     gbtRbcCO 11 : gbtRbcDO
 *     Select Master Clock 100 : All lanes 000 : Lane A 001 : Lane B
 *     010 : Lane C 011 : Lane D
 *     Transmit PLL Divider control
 *     Transmit Data rate control
 *     Receiver PLL Frequency control
 *     Bit rate control to enable bit doubling feature
 *     Reset Transmitter lane
 *     Reset Receiver lane
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:2;
		uint32_t	revlbrefsel:2;
		uint32_t	rsrvd1:1;
		uint32_t	tdmaster:3;
		uint32_t	fbdivt:3;
		uint32_t	half_ratet:1;
		uint32_t	fbdivr:3;
		uint32_t	half_rater:1;
		uint32_t	txreset:8;
		uint32_t	rxreset:8;
#else
		uint32_t	rxreset:8;
		uint32_t	txreset:8;
		uint32_t	half_rater:1;
		uint32_t	fbdivr:3;
		uint32_t	half_ratet:1;
		uint32_t	fbdivt:3;
		uint32_t	tdmaster:3;
		uint32_t	rsrvd1:1;
		uint32_t	revlbrefsel:2;
		uint32_t	rsrvd:2;
#endif
	} bits;
} pipe_rx_tx_clock_t;


/*
 * Register: PipeGlueCntl0
 * Pipe Glue Control 0
 *     Lock to Bitstream Initialization Time
 *     RXLOS Test bit
 *     Electrical Idle Ordered set enable
 *     Enable RxLOS
 *     Enable Fast resync
 *     RxLOS Sample Interval
 *     RxLOS threshold
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	bitlocktime:16;
		uint32_t	rxlos_test:1;
		uint32_t	eiosenable:1;
		uint32_t	rxlosenable:1;
		uint32_t	fastresync:1;
		uint32_t	samplerate:4;
		uint32_t	thresholdcount:8;
#else
		uint32_t	thresholdcount:8;
		uint32_t	samplerate:4;
		uint32_t	fastresync:1;
		uint32_t	rxlosenable:1;
		uint32_t	eiosenable:1;
		uint32_t	rxlos_test:1;
		uint32_t	bitlocktime:16;
#endif
	} bits;
} pipe_glue_cntl0_t;


/*
 * Register: PipeGlueCntl1
 * Pipe Glue Control 1
 *     Receiver Trim Resistance Configuration
 *     Transmitter Trim Resistance Configuration
 *     Auto Trim Enable
 *     50 Ohm Termination Enable
 *     Customer select for reference clock frequency
 *     EFIFO Same clock select
 *     EFIFO start depth
 *     Lock to refclk initialization time
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	termrcfg:2;
		uint32_t	termtcfg:2;
		uint32_t	rtrimen:1;
		uint32_t	ref50:1;
		uint32_t	freq_sel:1;
		uint32_t	same_sel:1;
		uint32_t	rsrvd:1;
		uint32_t	start_efifo:3;
		uint32_t	rsrvd1:2;
		uint32_t	inittime:18;
#else
		uint32_t	inittime:18;
		uint32_t	rsrvd1:2;
		uint32_t	start_efifo:3;
		uint32_t	rsrvd:1;
		uint32_t	same_sel:1;
		uint32_t	freq_sel:1;
		uint32_t	ref50:1;
		uint32_t	rtrimen:1;
		uint32_t	termtcfg:2;
		uint32_t	termrcfg:2;
#endif
	} bits;
} pipe_glue_cntl1_t;


/*
 * Register: HcrReg
 * HCR Registers
 * Description: Hydra Specific Configuration Registers for use by
 * software. These registers are loaded with the SPROM contents at
 * power on. A maximum of 128 DWords has been assigned for s/w to
 * use. This space generally stores the following informations : MAC
 * Address Number of MAC addresses MAC Phy Type Other data fields are
 * upto the software to use.
 *
 * Fields:
 *     Hydra specific configuration controlled by software
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	hcr_val:32;
#else
		uint32_t	hcr_val:32;
#endif
	} bits;
} hcr_reg_t;


/*
 * Register: BlockReset
 * Block Reset
 * Description: Soft resets to modules. Blade domain modules are
 * reset by setting the corresponding block reset to 1. Shared domain
 * resets are sent to SPI for processing and corresponding action by
 * SPI. Shared domains are reset only if all the blades have
 * requested a reset for that block. Below is an example scenario :
 * s/w initiates the reset by writing '1' to the dpmRst bit dpmRst
 * bit remains '1' until dpmRstStat is detected to be 1. Once
 * dpmRstStat is detected to be 1, even if s/w writes 1 to this bit
 * again no new reset will be initiated to the shared domain, ie,
 * DPM. dpmRstStat is driven by external i/f (shared domain status
 * provided by SPI) dpmRstStat bit will show '1' as long as the input
 * stays at 1 or until s/w reads the status and is cleared only after
 * s/w reads it and if dpmRstStat is 0 by then.
 * If Host wants to reset entire Hydra it should do so through the
 * mailbox. In this case, the message interprettation is upto the
 * software. Writing a '1' to any of these bits generates a single
 * pulse to the SP module which then controls the reset of the
 * respective block.
 *
 * Fields:
 *     1 : indicates that an active reset has been applied to the SP
 *     based on the request from all of the blades. Clears on Read
 *     provided the reset to SP has been deasserted by then by SPI.
 *     Setting to 1 allows this blade to request Service Processor
 *     (Shared) reset. However, SP reset can only occur if all blades
 *     agree. The success of reset request is indicated by spRstStat
 *     = 1 which is wired-AND of request from all the blades. Current
 *     request can be removed by writing a '0' to this bit. This bit
 *     clears automatically on detecting spRstStat = 1.
 *     Enable blade to service processor (Shared) reset voter
 *     registration = 1, disabled = 0
 *     Issue power reset to the EP Core Clears to 0, writing 0 has no
 *     effect.
 *     Issue core reset to the EP Core Clears to 0, writing 0 has no
 *     effect.
 *     Issue system reset (sysPor) to the PIPE Core This issues reset
 *     to the EP core, PCIe domains of Tdc, Rdc, and CIP. This shuts
 *     down the PCIe clock until Pipe core comes out of reset. The
 *     status of the Pipe core can be read by reading out the
 *     cipLinkStat register's pipe core status and pcie reset status
 *     bits. Clears to 0, writing 0 has no effect.
 *     1 : indicates that an active reset has been applied to the
 *     NMAC based on the request from all of the blades. Clears on
 *     Read provided the reset to NMAC has been deasserted by then by
 *     SPI.
 *     1 : indicates that an active reset has been applied to the TDP
 *     based on the request from all of the blades. Clears on Read
 *     provided the reset to TDP has been deasserted by then by SPI.
 *     1 : indicates that an active reset has been applied to the DPM
 *     based on the request from all of the blades. Clears on Read
 *     provided the reset to DPM has been deasserted by then by SPI.
 *     This bit is effective only if sharedVoterEn (bit 24 of this
 *     reg) has been enabled. Writing '1' sends a request to SP to
 *     reset NMAC if sharedVoterEn=1. Intended for backdoor access.
 *     The success of reset request is indicated by nmacRstStat = 1
 *     which is wired-AND of request from all the blades. This also
 *     means that the reset request is successful only if all the
 *     blades requested for reset of this block. Current request can
 *     be removed by writing a '0' to this bit. This bit clears
 *     automatically on detecting nmacRstStat = 1.
 *     This bit is effective only if sharedVoterEn (bit 24 of this
 *     reg) has been enabled. Writing '1' sends a request to SP to
 *     reset TDP if sharedVoterEn=1. Intended for backdoor access.
 *     Intended for backdoor access. The success of reset request is
 *     indicated by tdpRstStat = 1 which is wired-AND of request from
 *     all the blades. This also means that the reset request is
 *     successful only if all the blades requested for reset of this
 *     block. Current request can be removed by writing a '0' to this
 *     bit. This bit clears automatically on detecting tdpRstStat =
 *     1.
 *     This bit is effective only if sharedVoterEn (bit 24 of this
 *     reg) has been enabled. Writing '1' sends a request to SP to
 *     reset DPM if sharedVoterEn=1. Intended for backdoor access.
 *     Intended for backdoor access. The success of reset request is
 *     indicated by dpmRstStat = 1 which is wired-AND of request from
 *     all the blades. This also means that the reset request is
 *     successful only if all the blades requested for reset of this
 *     block. Current request can be removed by writing a '0' to this
 *     bit. This bit clears automatically on detecting dpmRstStat =
 *     1.
 *     Setting to 1 generates tdcCoreReset and tdcPcieReset to the
 *     TDC block. The reset will stay asserted for atleast 4 clock
 *     cycles. Clears to 0, writing 0 has no effect.
 *     Setting to 1 generates rdcCoreReset and rdcPcieReset to the
 *     RDC block. The reset will stay asserted for atleast 4 clock
 *     cycles. Clears to 0, writing 0 has no effect.
 *     Setting to 1 generates reset to the PFC block. The reset will
 *     stay asserted for atleast 4 clock cycles. Clears to 0, writing
 *     0 has no effect.
 *     Setting to 1 generates reset to the VMAC block. The reset will
 *     stay asserted for atleast 4 clock cycles. Clears to 0, writing
 *     0 has no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:13;
		uint32_t	sp_rst_stat:1;
		uint32_t	sp_rst:1;
		uint32_t	shared_voter_en:1;
		uint32_t	epcore_pwr_rst:1;
		uint32_t	epcore_core_rst:1;
		uint32_t	pipe_sys_rst:1;
		uint32_t	nmac_rst_stat:1;
		uint32_t	tdp_rst_stat:1;
		uint32_t	dpm_rst_stat:1;
		uint32_t	rsrvd1:1;
		uint32_t	nmac_rst:1;
		uint32_t	tdp_rst:1;
		uint32_t	dpm_rst:1;
		uint32_t	rsrvd2:1;
		uint32_t	tdc_rst:1;
		uint32_t	rdc_rst:1;
		uint32_t	pfc_rst:1;
		uint32_t	vmac_rst:1;
		uint32_t	rsrvd3:1;
#else
		uint32_t	rsrvd3:1;
		uint32_t	vmac_rst:1;
		uint32_t	pfc_rst:1;
		uint32_t	rdc_rst:1;
		uint32_t	tdc_rst:1;
		uint32_t	rsrvd2:1;
		uint32_t	dpm_rst:1;
		uint32_t	tdp_rst:1;
		uint32_t	nmac_rst:1;
		uint32_t	rsrvd1:1;
		uint32_t	dpm_rst_stat:1;
		uint32_t	tdp_rst_stat:1;
		uint32_t	nmac_rst_stat:1;
		uint32_t	pipe_sys_rst:1;
		uint32_t	epcore_core_rst:1;
		uint32_t	epcore_pwr_rst:1;
		uint32_t	shared_voter_en:1;
		uint32_t	sp_rst:1;
		uint32_t	sp_rst_stat:1;
		uint32_t	rsrvd:13;
#endif
	} bits;
} block_reset_t;


/*
 * Register: TimeoutCfg
 * PIO Timeout Configuration
 * Description: PIO Timeout Configuration register to control wait
 * time for a PIO access to complete. The timer resolution is in 250
 * MHz clock.
 * Fields:
 *     Programmable timeout counter value for PIO clients who did not
 *     ack a transaction in time. Minimum value should be 64.
 *     Timeout enable for PIO access to clients. 1 = enable.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:21;
		uint32_t	tmout_cnt:10;
		uint32_t	tmout_en:1;
#else
		uint32_t	tmout_en:1;
		uint32_t	tmout_cnt:10;
		uint32_t	rsrvd:21;
#endif
	} bits;
} timeout_cfg_t;


/*
 * Register: HeartCfg
 * PIO Heartbeat Config
 * Description: PIO Blade presence indication : Heartbeat
 * configuration The timer resolution is in 250 MHz clock.
 * Fields:
 *     Heartbeat countdown 250Mhz clock divider which serves as
 *     resolution for the heartTimer.
 *     Heartbeat countdown enable
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	divider:28;
		uint32_t	rsrvd:3;
		uint32_t	en:1;
#else
		uint32_t	en:1;
		uint32_t	rsrvd:3;
		uint32_t	divider:28;
#endif
	} bits;
} heart_cfg_t;


/*
 * Register: HeartTimer
 * PIO Heartbeat Timer
 * Description: PIO Blade presence indication : Heartbeat timer The
 * timer resolution is in 250 MHz clock.
 * Fields:
 *     Number of heartCfg.divider ticks of the 250Mhz clock before
 *     blade presence expires. This register decrements for every
 *     heartCfg.divider number of 250MHz clock cycles. It expires to
 *     0 and so must be written periodically to reset the timer back
 *     to the required value. This counter does not have any effect
 *     on CIP functionality.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	timer:32;
#else
		uint32_t	timer:32;
#endif
	} bits;
} heart_timer_t;


/*
 * Register: CipGpCtrl
 * CIP General Purpose Control Register
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:30;
		uint32_t	dma_override_relaxord:1;
		uint32_t	dma_override_nosnoop:1;
#else
		uint32_t	dma_override_nosnoop:1;
		uint32_t	dma_override_relaxord:1;
		uint32_t	rsrvd:30;
#endif
	} bits;
} cip_gp_ctrl_t;


/*
 * Register: CipStatus
 * CIP Status
 * Description: This register returns CIP block's current logic
 * status
 * Fields:
 *     Current state of the cipEpc state machine 00 : epIdle ( wait
 *     for EEPROM request from SP or Host ) 01 : waitAck0 ( wait for
 *     ack from EEPROM for the first 16 bit read of the DW access )
 *     11 : waitAck1 ( wait for ack from EEPROM for the second 16 bit
 *     read of the DW access ) 10 : UNDEFINED ( Undefined/Unused
 *     state; EPC is never expected to be in this state )
 *     Current state of the cipSpc state machine 000 : spReset ( wait
 *     for Power-On SPROM download to start) 001 : getAddr ( Get
 *     CfgReg Address ) 010 : getData ( Get CfgReg Data ) 011 :
 *     ignoreData ( Address phase had an error, so ignore the Data
 *     coming in ) 100 : idleCyc ( Idle cycle following an AHB
 *     Address phase ) 101 : waitAck0 ( Wait for ack from EP Core
 *     during SPROM Download ) 110 : waitAck1 ( Wait for ack from EP
 *     Core during register read/write ) 111 : NORMAL ( SPROM
 *     Download/Register read/write access completed and wait for
 *     SP/Host initiated PCI/AHB/HCR read/write )
 *     PCI Bus Number as reported by EP core
 *     PCI Bus Device Number as reported by EP core
 *     1: current csr access in progress is Local CIP csr access
 *     1: current csr access in progress is Blade Domain csr access
 *     1: a 64 bit blade domain access is in progress as two 32 bit
 *     accesses
 *     1: indicates config values were downloaded from SPROM
 *     1: indicates non-zero number of HCR config values downloaded
 *     from SPROM
 *     1: indicates non-zero number of PCI config values downloaded
 *     from SPROM
 *     1: indicates non-zero number of Pipe config values downloaded
 *     from SPROM
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:7;
		uint32_t	cip_epc_sm:2;
		uint32_t	cip_spc_sm:3;
		uint32_t	pbus_num:8;
		uint32_t	pbus_dev_num:5;
		uint32_t	loc_csr_access:1;
		uint32_t	bd_csr_access:1;
		uint32_t	d64_in_progress:1;
		uint32_t	spc_dnld_done:1;
		uint32_t	hcr_nz_cfg:1;
		uint32_t	pci_nz_cfg:1;
		uint32_t	pipe_nz_cfg:1;
#else
		uint32_t	pipe_nz_cfg:1;
		uint32_t	pci_nz_cfg:1;
		uint32_t	hcr_nz_cfg:1;
		uint32_t	spc_dnld_done:1;
		uint32_t	d64_in_progress:1;
		uint32_t	bd_csr_access:1;
		uint32_t	loc_csr_access:1;
		uint32_t	pbus_dev_num:5;
		uint32_t	pbus_num:8;
		uint32_t	cip_spc_sm:3;
		uint32_t	cip_epc_sm:2;
		uint32_t	rsrvd:7;
#endif
	} bits;
} cip_status_t;


/*
 * Register: CipLinkStat
 * Link Status Register
 * Description: This register returns the Link status
 * Fields:
 *     NMAC XPCS-2 Link Status
 *     NMAC XPCS-1 Link Status
 *     NMAC XPCS-0 Link Status
 *     '1' indicates that pipe core went down suddenly when its reset
 *     sources are at deactivated level. When this happens, the PCIe
 *     domain logics are reset including the EP core, TDC/RDC PCIe
 *     domains. All these logics, EP Core, and the pipe core are held
 *     at reset until s/w writes 1 to this bit to clear status which
 *     will also bring the PCIe domain out of reset
 *     pipe core clock & reset status 1: core is up & running, ie,
 *     PIPE core is out of reset and clock is ON
 *     PCIe domain reset status 1: PCIe domain logics including EP
 *     core are out of reset; This also implies that PCIe clock is up
 *     and running
 *     EP Core XDM Link State
 *     EP Core RDM Link State
 *     EP Core LTSSM State
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:13;
		uint32_t	xpcs2_link_up:1;
		uint32_t	xpcs1_link_up:1;
		uint32_t	xpcs0_link_up:1;
		uint32_t	rsrvd1:6;
		uint32_t	surprise_pipedn:1;
		uint32_t	pipe_core_stable:1;
		uint32_t	pcie_domain_stable:1;
		uint32_t	xmlh_link_up:1;
		uint32_t	rdlh_link_up:1;
		uint32_t	xmlh_ltssm_state:5;
#else
		uint32_t	xmlh_ltssm_state:5;
		uint32_t	rdlh_link_up:1;
		uint32_t	xmlh_link_up:1;
		uint32_t	pcie_domain_stable:1;
		uint32_t	pipe_core_stable:1;
		uint32_t	surprise_pipedn:1;
		uint32_t	rsrvd1:6;
		uint32_t	xpcs0_link_up:1;
		uint32_t	xpcs1_link_up:1;
		uint32_t	xpcs2_link_up:1;
		uint32_t	rsrvd:13;
#endif
	} bits;
} cip_link_stat_t;


/*
 * Register: EpcStat
 * EEPROM PIO Status
 * Description: EEPROM PIO Status The Host may initiate access to the
 * EEPROM either thru this register or directly by TRGT1 interfaces
 * using ROM BAR access. Note that since the EEPROM can be accessed
 * by either Host or SP, access must be granted to the PEU using the
 * SPI PROM Control Register eepromPeuEn bit for proper operation.
 * All EEPROM accesses initiated from either the Host or SP are
 * always acknowledged. If a Host access is not acknowledged, then
 * check the SPI PROM Control Register eepromPeuEn bit to make sure
 * the PEU to EEPROM access has been enabled. Meanwhile, Host read
 * and write accesses through the TRGT1 interface may be held up
 * waiting for the acknowledgement. Thus, in order to recover from
 * any faulty/stuck condition due to the blocked EEPROM accesses, the
 * SP should configure the epcGotoNormal bit in the epcStat register.
 * When Host accesses are stuck, only the SP can write into this bit
 * to recover from this condition.
 * The EEPROM is 1M x 16 bits or 2M bytes. The read address in bits
 * [22:2] is byte address. The EEPROM access can only be DW access.
 * While accessing through these registers, the lower 2 bits of the
 * specified address is ignored resulting in a DW access to the
 * EEPROM controller. While accessing through the ROM BAR range, only
 * DW accesses are accepted and all other accesses will result in
 * error status returned to the host.
 * The read will initiate two reads to the EPC and the accumulated
 * 32 bit data is returned to the Host either via the Client2 bus or
 * in the epcData register depending on the cause of the transaction.
 * This means, a read addr=0,1,2,3 will return data from EPC
 * locations 0 & 1 which are 16 bits each, and a read to addr=4,5,6,7
 * will return data from EPC locations 2,3 which are 16 bits each.
 * Some examples for the address translation : 1) when Host gives
 * address 0x0000, it means to get bytes 0,1,2, and 3 from the
 * EEPROM. These bytes are stored at locations 0x0000 (bytes 0,1) and
 * 0x0001 (bytes 2,3) in EEPROM. Hence PEU will present address
 * 0x0000 followed by 0x0001 to the EEPROM.
 * 2) when Host gives address 0x0004, it means to get bytes 4,5,6,
 * and 7 from the EEPROM. These bytes are stored at locations 0x0002
 * (bytes 4,5) and 0x0003 (bytes 6,7) in EEPROM. Hence PEU will
 * present address 0x0002 followed by 0x0003 to the EEPROM.
 * etc ..
 *
 * Fields:
 *     Force the EPC state machine to go to epIdle state. This bit is
 *     used to force the EPC to skip the reading of the EEPROM and
 *     goto the epIdle state which is normal state for EPC. The bit
 *     is auto-cleared after switching to the epIdle state. Both SP
 *     and HOST can write into this bit. However care must be taken
 *     writing '1' into this bit since setting this bit will flush
 *     out any pending EEPROM access request from Host. Hence, this
 *     bit should be used only if the EPC State machine (cipEpcSm
 *     bits in cipStatus register) is stuck at a non-zero state.
 *     EEPROM Byte Address for read operation This field can be
 *     updated only if there is no pending EEPROM read access.
 *     Software should poll bit 0 of this register (epcRdInit) to
 *     make sure that it is '0' before writing into this. If polled
 *     epcRdInit value is '1', then write to epcAddr field is
 *     ignored. This is to safe-guard the epcAddr value which is
 *     being read out the EEPROM.
 *     Read access completion status; set to '0' for successful
 *     completion by EPC set to '1' to indicate read access error
 *     from EPC
 * Note: Currently, the EEPROM controller in Hydra does not
 *     return any error condition, ie, epcPeuErr = 1'b0 always. And
 *     so, for the PIO read access by the Host, the epcStat register
 *     in PEU will always show that the access was successful. For
 *     EEPROM read initiated through the ROM BAR by the Host, CIP
 *     will always return Successful Completion status to the Host.
 *     Any error situation is reported only in the Status Register
 *     within the EEPROM device. For access information about this
 *     register, please refer to the EEPROM/SPI PRMs.
 *
 *     Read Initiate. SW writes 1 to this bit to initiate a EEPROM
 *     read. Clears to 0 on updating the epcData reg. Writing 0 has
 *     no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	epc_goto_normal:1;
		uint32_t	rsrvd:8;
		uint32_t	epc_addr:21;
		uint32_t	epc_cpl_stat:1;
		uint32_t	epc_rd_init:1;
#else
		uint32_t	epc_rd_init:1;
		uint32_t	epc_cpl_stat:1;
		uint32_t	epc_addr:21;
		uint32_t	rsrvd:8;
		uint32_t	epc_goto_normal:1;
#endif
	} bits;
} epc_stat_t;


/*
 * Register: EpcData
 * EEPROM PIO Data
 * Description: EEPROM PIO Data The data returned from EEPROM
 * controller for the EEPROM access initiated by the EEPROM PIO
 * Status register is returned in this register.
 * Fields:
 *     EEPROM Read Data; valid when rdInit transitioned from 1 to 0.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	eeprom_data:32;
#else
		uint32_t	eeprom_data:32;
#endif
	} bits;
} epc_data_t;


/*
 * Register: SpcStat
 * SPROM PIO Status
 * Description: SPROM PIO Status
 * Fields:
 *     Force the SPC state machine to go to NORMAL state. This bit is
 *     used to force the SPC to skip the downloading of the SPROM
 *     contents into the EP/Pipe/Hcr registers. Setting this bit will
 *     make CIP to drop any pending requests to the DBI/AHB buses.
 *     The bit is auto-cleared after switching to the Normal state.
 *     This bit can not be used to terminate a pio access to
 *     PCI/PIPE/HCR registers. If a pio access to these registers is
 *     not responded to, by the respective block, then the pio access
 *     will automatically timeout. The timeout value is specified by
 *     the timeoutCfg:tmoutCnt value
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:29;
		uint32_t	spc_goto_normal:1;
		uint32_t	rsrvd1:2;
#else
		uint32_t	rsrvd1:2;
		uint32_t	spc_goto_normal:1;
		uint32_t	rsrvd:29;
#endif
	} bits;
} spc_stat_t;


/*
 * Register: Host2spiIndaccAddr
 * HOST -> SPI Shared Domain Read Address
 * Description: Read address set by Host for indirect access to
 * shared domain address space The decoding of the address is as
 * follows: [23:20] - block select [19:0] - register offset from base
 * address of block
 * Fields:
 *     Address in Shared domain
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:8;
		uint32_t	addr:24;
#else
		uint32_t	addr:24;
		uint32_t	rsrvd:8;
#endif
	} bits;
} host2spi_indacc_addr_t;


/*
 * Register: Host2spiIndaccCtrl
 * HOST -> SPI Shared Domain Read Control
 * Description: Control word set by Host for indirect access to the
 * shared domain address space Writing to this register initiates the
 * indirect access to the shared domain.
 * The Host may read or write to a shared domain region data as
 * below : Host updates the host2spiIndaccAddr register with address
 * of the shared domain reg. For writes, Host updates the
 * host2spiIndaccData register with write data Host then writes to
 * bit 0 of host2spiIndaccCtrl register to '1' or '0' to initiate the
 * read or write access; 1 : write command, 0 : read command Host
 * should then poll bit 1 of host2spiIndaccCtrl register for the
 * access status. 1 : access is done, 0 : access is in progress
 * (busy) Host should then check bit 2 of host2spiIndaccCtrl register
 * to know if the command was successful; 1 : access error, 0 :
 * access successful For reads, Host then reads the
 * host2spiIndaccData register for the read data.
 * This register can be written into only when there is no pending
 * access, ie, indaccCtrl.cplStat=1. Writes when indaccCtrl.cplStat=0
 * is ignored.
 *
 * Fields:
 *     command completion status; 0 : successful completion of
 *     command by SPI 1 : access error from SPI
 *     command progress status; 0 : access is in progress (busy) 1 :
 *     access is done
 *     1 : Initiate a write access 0 : Initiate a read access
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:29;
		uint32_t	err_stat:1;
		uint32_t	cpl_stat:1;
		uint32_t	rd_wr_cmd:1;
#else
		uint32_t	rd_wr_cmd:1;
		uint32_t	cpl_stat:1;
		uint32_t	err_stat:1;
		uint32_t	rsrvd:29;
#endif
	} bits;
} host2spi_indacc_ctrl_t;


/*
 * Register: Host2spiIndaccData
 * HOST -> SPI Shared Domain Read/Write Data
 * Description: For indirect read access by the Host, this register
 * returns the data returned from the Shared Domain For indirect
 * write access by the Host, the host should update this register
 * with the writeData for the Shared Domain, before writing to the
 * host2spiIndaccCtrl register to initiate the access.
 * This register can be written into only when there is no pending
 * access, ie, indaccCtrl.cplStat=1. Writes when indaccCtrl.cplStat=0
 * is ignored.
 *
 * Fields:
 *     Shared domain read/write data
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} host2spi_indacc_data_t;


/*
 * Register: BtCtrl0
 * Mailbox Control & Access status 0
 * Description: Host (blade) <-> SP Block Transfer mailbox control
 * and access status register 0.
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btCtrl0 address, data on
 * hostDataBus[7:0], and assert hostBen[0], SPI is allowed 8 bits
 * read/write access to this register ; To do the same, it should
 * provide the btCtrl0 address, data on spiDataBus[7:0], and no need
 * of spiBen
 *
 * Fields:
 *     The SP sets/clears this bit to indicate if it is busy and can
 *     not accept any other request; write 1 to toggle the bit; Read
 *     Only by Host.
 *     The Host sets/clears this bit to indicate if it is busy and
 *     can not accept any other request; Read Only by SP.
 *     Reserved for definition by platform. Typical usage could be
 *     "heartbeat" mechanism from/to the host. The host sets OEM0 to
 *     interrupt the SP and then polls it to be cleared by SP
 *     The SP sets this bit when it has detected and queued an SMS
 *     message in the SP2HOST buffer that must be reported to the
 *     HOST. The Host clears this bit by writing a 1 to it. This bit
 *     may generate an intrpt to Host depending on the sp2hostIntEn
 *     bit. Writing 0 has no effect
 *     The SP writes 1 to this bit after it has finished writing a
 *     message into the SP2HOST buffer. The Host clears this bit by
 *     writing 1 to it after it has set the hostBusy bit This bit may
 *     generate an intrpt to Host depending on the sp2hostIntEn bit.
 *     Writing 0 has no effect
 *     The Host writes 1 to this bit to generate an interrupt to SP
 *     after it has finished writing a message into the HOST2SP
 *     buffer. The SP clears this bit by writing 1 to it after it has
 *     set the spBusy bit. Writing 0 has no effect
 *     The host writes 1 to clear the read pointer to the BT SP2HOST
 *     buffer; the SP writes 1 to clear the read pointer to the BT
 *     HOST2SP buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 *     The host writes 1 to clear the write pointer to the BT HOST2SP
 *     buffer; the SP writes 1 to clear the write pointer to the BT
 *     SP2HOST buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	sp_busy:1;
		uint32_t	host_busy:1;
		uint32_t	oem0:1;
		uint32_t	sms_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	host2sp_atn:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	clr_wr_ptr:1;
#else
		uint32_t	clr_wr_ptr:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	host2sp_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	sms_atn:1;
		uint32_t	oem0:1;
		uint32_t	host_busy:1;
		uint32_t	sp_busy:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_ctrl0_t;


/*
 * Register: BtData0
 * Mailbox Data 0
 * Description: Host (blade) <-> SP mailbox data register 0.
 * Host is allowed a 32 bits read/write access to this register ; To
 * do the same, it should provide the btData0 address, data on
 * hostDataBus[31:0], and assert hostBen[1], SPI is allowed only 8
 * bits read/write access to this register ; To do the same, it
 * should provide the btData0 address, data on spiDataBus[7:0], and
 * no need of spiBen
 * All references to the mail box control bits in this register
 * refer to btCtrl0. When spBusy=0 && host2spAtn=0, data is written
 * by the host and read by the SP. When hostBusy=0 && sp2hostAtn=0,
 * data is written by the SP and read by the Host.
 *
 * Fields:
 *     Bits 7:0 of message data to send to SP/HOST
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	data:8;
#else
		uint32_t	data:8;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_data0_t;


/*
 * Register: BtIntmask0
 * Mailbox Interrupt Mask & Status 0
 * Description: Host (blade) <-> SP Block Transfer Interrupt Mask and
 * Status register 0
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btIntmask0 address, data on
 * hostDataBus[23:16], and assert hostBen[2], SPI is allowed 8 bits
 * read only access to this register ; To do the same, it should
 * provide the btIntmask0 address and no need of spiBen
 * All references to the mail box control bits in this register
 * refer to btCtrl0
 * Fields:
 *     The host writes 1 to reset the entire mailbox 0 accesses for
 *     error recovery; resets both SP and HOST write and read
 *     pointers. Writing 0 has no effect. This is non-sticky. Always
 *     read back as 0.
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     SP to HOST Interrupt status This bit reflects the state of the
 *     intrpt line to the Host. O/S driver should write 1 to clear.
 *     SP to HOST Interrupt Enable The interrupt is generated if
 *     sp2hIrqEn is 1 and either sp2hostAtn or smsAtn is 1
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd1:2;
		uint32_t	oem3:1;
		uint32_t	oem2:1;
		uint32_t	oem1:1;
		uint32_t	sp2h_irq:1;
		uint32_t	sp2h_irq_en:1;
#else
		uint32_t	sp2h_irq_en:1;
		uint32_t	sp2h_irq:1;
		uint32_t	oem1:1;
		uint32_t	oem2:1;
		uint32_t	oem3:1;
		uint32_t	rsrvd1:2;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_intmask0_t;


/*
 * Register: BtCtrl1
 * Mailbox Control & Access status 1
 * Description: Host (blade) <-> SP Block Transfer mailbox control
 * and access status register 1.
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btCtrl1 address, data on
 * hostDataBus[7:0], and assert hostBen[0], SPI is allowed 8 bits
 * read/write access to this register ; To do the same, it should
 * provide the btCtrl1 address, data on spiDataBus[7:0], and no need
 * of spiBen
 *
 * Fields:
 *     The SP sets/clears this bit to indicate that it is busy and
 *     can not accept any other request; write 1 to toggle the bit;
 *     Read only by Host.
 *     The Host sets/clears this bit to indicate that it is busy and
 *     can not accept any other request; Read only by SP.
 *     Reserved for definition by platform. Typical usage could be
 *     "heartbeat" mechanism from/to the host. The host sets OEM0 to
 *     interrupt the SP and then polls it to be cleared by SP
 *     The SP sets this bit when it has detected and queued an SMS
 *     message in the SP2HOST buffer that must be reported to the
 *     HOST. The Host clears this bit by writing a 1 to it. This bit
 *     may generate an intrpt to Host depending on the sp2hostIntEn
 *     bit. Writing 0 has no effect
 *     The SP writes 1 to this bit after it has finished writing a
 *     message into the SP2HOST buffer. The Host clears this bit by
 *     writing 1 to it after it has set the hostBusy bit This bit may
 *     generate an intrpt to Host depending on the sp2hostIntEn bit.
 *     Writing 0 has no effect
 *     The Host writes 1 to this bit to generate an interrupt to SP
 *     after it has finished writing a message into the HOST2SP
 *     buffer. The SP clears this bit by writing 1 to it after it has
 *     set the spBusy bit. Writing 0 has no effect
 *     The host writes 1 to clear the read pointer to the BT SP2HOST
 *     buffer; the SP writes 1 to clear the read pointer to the BT
 *     HOST2SP buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 *     The host writes 1 to clear the write pointer to the BT HOST2SP
 *     buffer; the SP writes 1 to clear the write pointer to the BT
 *     SP2HOST buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	sp_busy:1;
		uint32_t	host_busy:1;
		uint32_t	oem0:1;
		uint32_t	sms_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	host2sp_atn:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	clr_wr_ptr:1;
#else
		uint32_t	clr_wr_ptr:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	host2sp_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	sms_atn:1;
		uint32_t	oem0:1;
		uint32_t	host_busy:1;
		uint32_t	sp_busy:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_ctrl1_t;


/*
 * Register: BtData1
 * Mailbox Data 1
 * Description: Host (blade) <-> SP mailbox data register 1.
 * Host is allowed a 32 bits read/write access to this register ; To
 * do the same, it should provide the btData1 address, data on
 * hostDataBus[31:0], and assert hostBen[1], SPI is allowed only 8
 * bits read/write access to this register ; To do the same, it
 * should provide the btData1 address, data on spiDataBus[7:0], and
 * no need of spiBen
 * All references to the mail box control bits in this register
 * refer to btCtrl1. When spBusy=0 && host2spAtn=0, data is written
 * by the host and read by the SP. When hostBusy=0 && sp2hostAtn=0,
 * data is written by the SP and read by the Host.
 * Fields:
 *     Bits 31:0 of message data to send to SP/HOST
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	data:8;
#else
		uint32_t	data:8;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_data1_t;


/*
 * Register: BtIntmask1
 * Mailbox Interrupt Mask & Status 1
 * Description: Host (blade) <-> SP Block Transfer Interrupt Mask and
 * Status register 1
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btIntmask1 address, data on
 * hostDataBus[23:16], and assert hostBen[2], SPI is allowed 8 bits
 * read only access to this register ; To do the same, it should
 * provide the btIntmask1 address and no need of spiBen
 * All references to the mail box control bits in this register
 * refer to btCtrl1
 * Fields:
 *     The host writes 1 to reset the entire mailbox 1 accesses for
 *     error recovery; resets both SP and HOST write and read
 *     pointers. Writing 0 has no effect. This is non-sticky. Always
 *     read back as 0.
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     SP to HOST Interrupt status This bit reflects the state of the
 *     intrpt line to the Host. O/S driver should write 1 to clear.
 *     SP to HOST Interrupt Enable The interrupt is generated if
 *     sp2hIrqEn is 1 and either sp2hostAtn or smsAtn is 1
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd1:2;
		uint32_t	oem3:1;
		uint32_t	oem2:1;
		uint32_t	oem1:1;
		uint32_t	sp2h_irq:1;
		uint32_t	sp2h_irq_en:1;
#else
		uint32_t	sp2h_irq_en:1;
		uint32_t	sp2h_irq:1;
		uint32_t	oem1:1;
		uint32_t	oem2:1;
		uint32_t	oem3:1;
		uint32_t	rsrvd1:2;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_intmask1_t;


/*
 * Register: BtCtrl2
 * Mailbox Control & Access status 2
 * Description: Host (blade) <-> SP Block Transfer mailbox control
 * and access status register 2.
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btCtrl2 address, data on
 * hostDataBus[7:0], and assert hostBen[0], SPI is allowed 8 bits
 * read/write access to this register ; To do the same, it should
 * provide the btCtrl2 address, data on spiDataBus[7:0], and no need
 * of spiBen
 *
 * Fields:
 *     The SP sets/clears this bit to indicate that it is busy and
 *     can not accept any other request; write 1 to toggle the bit;
 *     Read only by Host.
 *     The Host sets/clears this bit to indicate that it is busy and
 *     can not accept any other request; Read only by SP.
 *     Reserved for definition by platform. Typical usage could be
 *     "heartbeat" mechanism from/to the host. The host sets OEM0 to
 *     interrupt the SP and then polls it to be cleared by SP
 *     The SP sets this bit when it has detected and queued an SMS
 *     message in the SP2HOST buffer that must be reported to the
 *     HOST. The Host clears this bit by writing a 1 to it. This bit
 *     may generate an intrpt to Host depending on the sp2hostIntEn
 *     bit. Writing 0 has no effect
 *     The SP writes 1 to this bit after it has finished writing a
 *     message into the SP2HOST buffer. The Host clears this bit by
 *     writing 1 to it after it has set the hostBusy bit This bit may
 *     generate an intrpt to Host depending on the sp2hostIntEn bit.
 *     Writing 0 has no effect
 *     The Host writes 1 to this bit to generate an interrupt to SP
 *     after it has finished writing a message into the HOST2SP
 *     buffer. The SP clears this bit by writing 1 to it after it has
 *     set the spBusy bit. Writing 0 has no effect
 *     The host writes 1 to clear the read pointer to the BT SP2HOST
 *     buffer; the SP writes 1 to clear the read pointer to the BT
 *     HOST2SP buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 *     The host writes 1 to clear the write pointer to the BT HOST2SP
 *     buffer; the SP writes 1 to clear the write pointer to the BT
 *     SP2HOST buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	sp_busy:1;
		uint32_t	host_busy:1;
		uint32_t	oem0:1;
		uint32_t	sms_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	host2sp_atn:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	clr_wr_ptr:1;
#else
		uint32_t	clr_wr_ptr:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	host2sp_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	sms_atn:1;
		uint32_t	oem0:1;
		uint32_t	host_busy:1;
		uint32_t	sp_busy:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_ctrl2_t;


/*
 * Register: BtData2
 * Mailbox Data 2
 * Description: Host (blade) <-> SP mailbox data register 2. All
 * references to the mail box control bits in this register refer to
 * btCtrl2.
 * Host is allowed a 32 bits read/write access to this register ; To
 * do the same, it should provide the btData2 address, data on
 * hostDataBus[31:0], and assert hostBen[1], SPI is allowed only 8
 * bits read/write access to this register ; To do the same, it
 * should provide the btData2 address, data on spiDataBus[7:0], and
 * no need of spiBen
 * When spBusy=0 && host2spAtn=0, data is written by the host and
 * read by the SP. When hostBusy=0 && sp2hostAtn=0, data is written
 * by the SP and read by the Host.
 * Fields:
 *     Bits 31:0 of message data to send to SP/HOST
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	data:8;
#else
		uint32_t	data:8;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_data2_t;


/*
 * Register: BtIntmask2
 * Mailbox Interrupt Mask & Status 2
 * Description: Host (blade) <-> SP Block Transfer Interrupt Mask and
 * Status register 2
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btIntmask2 address, data on
 * hostDataBus[23:16], and assert hostBen[2], SPI is allowed 8 bits
 * read only access to this register ; To do the same, it should
 * provide the btIntmask2 address and no need of spiBen
 * All references to the mail box control bits in this register
 * refer to btCtrl2
 * Fields:
 *     The host writes 1 to reset the entire mailbox 2 accesses for
 *     error recovery; resets both SP and HOST write and read
 *     pointers. Writing 0 has no effect. This is non-sticky. Always
 *     read back as 0.
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     SP to HOST Interrupt status This bit reflects the state of the
 *     intrpt line to the Host. O/S driver should write 1 to clear.
 *     SP to HOST Interrupt Enable The interrupt is generated if
 *     sp2hIrqEn is 1 and either sp2hostAtn or smsAtn is 1
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd1:2;
		uint32_t	oem3:1;
		uint32_t	oem2:1;
		uint32_t	oem1:1;
		uint32_t	sp2h_irq:1;
		uint32_t	sp2h_irq_en:1;
#else
		uint32_t	sp2h_irq_en:1;
		uint32_t	sp2h_irq:1;
		uint32_t	oem1:1;
		uint32_t	oem2:1;
		uint32_t	oem3:1;
		uint32_t	rsrvd1:2;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_intmask2_t;


/*
 * Register: BtCtrl3
 * Mailbox Control & Access status 3
 * Description: Host (blade) <-> SP Block Transfer mailbox control
 * and access status register 3.
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btCtrl3 address, data on
 * hostDataBus[7:0], and assert hostBen[0], SPI is allowed 8 bits
 * read/write access to this register ; To do the same, it should
 * provide the btCtrl3 address, data on spiDataBus[7:0], and no need
 * of spiBen
 *
 * Fields:
 *     The SP sets/clears this bit to indicate that it is busy and
 *     can not accept any other request; write 1 to toggle the bit;
 *     Read only by Host.
 *     The Host sets/clears this bit to indicate that it is busy and
 *     can not accept any other request; Read only by SP.
 *     Reserved for definition by platform. Typical usage could be
 *     "heartbeat" mechanism from/to the host. The host sets OEM0 to
 *     interrupt the SP and then polls it to be cleared by SP
 *     The SP sets this bit when it has detected and queued an SMS
 *     message in the SP2HOST buffer that must be reported to the
 *     HOST. The Host clears this bit by writing a 1 to it. This bit
 *     may generate an intrpt to Host depending on the sp2hostIntEn
 *     bit. Writing 0 has no effect
 *     The SP writes 1 to this bit after it has finished writing a
 *     message into the SP2HOST buffer. The Host clears this bit by
 *     writing 1 to it after it has set the hostBusy bit This bit may
 *     generate an intrpt to Host depending on the sp2hostIntEn bit.
 *     Writing 0 has no effect
 *     The Host writes 1 to this bit to generate an interrupt to SP
 *     after it has finished writing a message into the HOST2SP
 *     buffer. The SP clears this bit by writing 1 to it after it has
 *     set the spBusy bit. Writing 0 has no effect
 *     The host writes 1 to clear the read pointer to the BT SP2HOST
 *     buffer; the SP writes 1 to clear the read pointer to the BT
 *     HOST2SP buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 *     The host writes 1 to clear the write pointer to the BT HOST2SP
 *     buffer; the SP writes 1 to clear the write pointer to the BT
 *     SP2HOST buffer. This bit is always read back as 0; writing 0
 *     has no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	sp_busy:1;
		uint32_t	host_busy:1;
		uint32_t	oem0:1;
		uint32_t	sms_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	host2sp_atn:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	clr_wr_ptr:1;
#else
		uint32_t	clr_wr_ptr:1;
		uint32_t	clr_rd_ptr:1;
		uint32_t	host2sp_atn:1;
		uint32_t	sp2host_atn:1;
		uint32_t	sms_atn:1;
		uint32_t	oem0:1;
		uint32_t	host_busy:1;
		uint32_t	sp_busy:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_ctrl3_t;


/*
 * Register: BtData3
 * Mailbox Data 3
 * Description: Host (blade) <-> SP mailbox data register 3.
 * Host is allowed a 32 bits read/write access to this register ; To
 * do the same, it should provide the btData3 address, data on
 * hostDataBus[31:0], and assert hostBen[1], SPI is allowed only 8
 * bits read/write access to this register ; To do the same, it
 * should provide the btData3 address, data on spiDataBus[7:0], and
 * no need of spiBen
 * All references to the mail box control bits in this register
 * refer to btCtrl3. When spBusy=0 && host2spAtn=0, data is written
 * by the host and read by the SP. When hostBusy=0 && sp2hostAtn=0,
 * data is written by the SP and read by the Host.
 * Fields:
 *     Bits 31:0 of message data to send to SP/HOST
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	data:8;
#else
		uint32_t	data:8;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_data3_t;


/*
 * Register: BtIntmask3
 * Mailbox Interrupt Mask & Status 3
 * Description: Host (blade) <-> SP Block Transfer Interrupt Mask and
 * Status register 3
 * Host is allowed 8 bits read/write access to this register ; To do
 * the same, it should provide the btIntmask3 address, data on
 * hostDataBus[23:16], and assert hostBen[2], SPI is allowed 8 bits
 * read only access to this register ; To do the same, it should
 * provide the btIntmask3 address and no need of spiBen
 * All references to the mail box control bits in this register
 * refer to btCtrl3
 * Fields:
 *     The host writes 1 to reset the entire mailbox 3 accesses for
 *     error recovery; resets both SP and HOST write and read
 *     pointers. Writing 0 has no effect. This is non-sticky. Always
 *     read back as 0.
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     Reserved for definition by platform manufacturer for BIOS/SMI
 *     Handler use. Generic IPMI software must write this bit as 0
 *     and ignore the value on read
 *     SP to HOST Interrupt status This bit reflects the state of the
 *     intrpt line to the Host. O/S driver should write 1 to clear.
 *     SP to HOST Interrupt Enable The interrupt is generated if
 *     sp2hIrqEn is 1 and either sp2hostAtn or smsAtn is 1
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:24;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd1:2;
		uint32_t	oem3:1;
		uint32_t	oem2:1;
		uint32_t	oem1:1;
		uint32_t	sp2h_irq:1;
		uint32_t	sp2h_irq_en:1;
#else
		uint32_t	sp2h_irq_en:1;
		uint32_t	sp2h_irq:1;
		uint32_t	oem1:1;
		uint32_t	oem2:1;
		uint32_t	oem3:1;
		uint32_t	rsrvd1:2;
		uint32_t	mb_master_reset:1;
		uint32_t	rsrvd:24;
#endif
	} bits;
} bt_intmask3_t;


/*
 * Register: DebugSel
 * CIP Debug Data Select
 * Description: Selects the debug data signals from the CIP blocks
 * Fields:
 *     Selects up to 16 groups of gbtDebug/pipeDebug on
 *     peuPhyVdbgDebugPort[31:0]
 *     Selects the high DW of the debug data - default is PCIe link
 *     status
 *     Selects the low DW of the debug data
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:12;
		uint32_t	phy_dbug_sel:4;
		uint32_t	rsrvd1:3;
		uint32_t	cip_hdbug_sel:5;
		uint32_t	rsrvd2:3;
		uint32_t	cip_ldbug_sel:5;
#else
		uint32_t	cip_ldbug_sel:5;
		uint32_t	rsrvd2:3;
		uint32_t	cip_hdbug_sel:5;
		uint32_t	rsrvd1:3;
		uint32_t	phy_dbug_sel:4;
		uint32_t	rsrvd:12;
#endif
	} bits;
} debug_sel_t;


/*
 * Register: IndaccMem0Ctrl
 * CIP Mem0 Debug ctrl
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     1: rd/wr access is done 0: rd/wr access is in progress
 *     1: pkt injection is done 0: pkt injection is in progress
 *     Ingress pkt injection enable: write to 1 for single pkt
 *     injection. Must be 0 when enabling diagnostic rd/wr access to
 *     memories.
 *     1: Diagnostic rd/wr access to memories enabled 0: Diagnostic
 *     rd/wr access to memories disabled Must be 0 when enabling pkt
 *     injection.
 *     1: read, 0: write
 *     This bit is read/writable only if mem0Diagen=1 or if
 *     mem0Diagen bit is also written with '1' along with enabling
 *     this bit. Else, the write will not have any effect. 1: Apply
 *     the parity mask provided in the Prty register 0: Do not apply
 *     the parity mask provided in the Prty register
 *     0 : select npdataq memory 1 : select nphdrq memory 2 : select
 *     pdataq memory 3 : select phdrq memory 4 : select cpldataq
 *     memory 5 : select cplhdrq memory
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem0_access_status:1;
		uint32_t	rsrvd:5;
		uint32_t	mem0_pktinj_stat:1;
		uint32_t	mem0_pktinj_en:1;
		uint32_t	rsrvd1:1;
		uint32_t	mem0_diagen:1;
		uint32_t	mem0_command:1;
		uint32_t	mem0_prty_wen:1;
		uint32_t	rsrvd2:1;
		uint32_t	mem0_sel:3;
		uint32_t	mem0_addr:16;
#else
		uint32_t	mem0_addr:16;
		uint32_t	mem0_sel:3;
		uint32_t	rsrvd2:1;
		uint32_t	mem0_prty_wen:1;
		uint32_t	mem0_command:1;
		uint32_t	mem0_diagen:1;
		uint32_t	rsrvd1:1;
		uint32_t	mem0_pktinj_en:1;
		uint32_t	mem0_pktinj_stat:1;
		uint32_t	rsrvd:5;
		uint32_t	mem0_access_status:1;
#endif
	} bits;
} indacc_mem0_ctrl_t;


/*
 * Register: IndaccMem0Data0
 * CIP Mem0 Debug Data0
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[31:0] from/for the memory
 *     selected by mem0Sel bits from mem0Ctrl This data is written to
 *     the memory when indaccMem0Ctrl register is written with the
 *     write command When indaccMem0Ctrl register is written with the
 *     read command, this register will hold the Data[31:0] returned
 *     from the memory When pktInjectionEnable is 1:
 *     debugData0Reg[31:0] is used in the following ways: [17:16] =
 *     radmTrgt1Fmt[1:0]: 2'b00 3DW MRd 2'b01 4DW MRd 2'b10 3DW MWr
 *     2'b11 4DW MWr [13:12] = radmTrgt1DwLen[1:0]: 2'b01 1DW 2'b10
 *     2DW [11:8] = radmTrgt1LastBe[3:0]: 4'b0000 1DW 4'b1111 2DW [7]
 *     = radmTrgt1RomInRange 1'b0 PIO Access 1'b1 EEPROM Access [6:4]
 *     = radmTrgt1InMembarRange[2:0] 3'b000 PIO Access 3'b010 MSIX
 *     Ram/PBA Table Access [1:0] = radmTrgt1Dwen[1:0] 2'b01
 *     1DW->last DW is at radmTrgt1Data[31:0] 2'b11 2DW->last DW is
 *     at radmTrgt1Data[63:32]
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem0_data0:32;
#else
		uint32_t	mem0_data0:32;
#endif
	} bits;
} indacc_mem0_data0_t;


/*
 * Register: IndaccMem0Data1
 * CIP Mem0 Debug Data1
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[63:32] from/for the memory
 *     selected by mem0Sel bits from mem0Ctrl This data is written to
 *     the memory when indaccMem0Ctrl register is written with the
 *     write command When indaccMem0Ctrl register is written with the
 *     read command, this register will hold the Data[63:32] returned
 *     from the memory When pktInjectionEnable is 1:
 *     debugData1Reg[31:0] is used as radmTrgt1Addr[31:0].
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem0_data1:32;
#else
		uint32_t	mem0_data1:32;
#endif
	} bits;
} indacc_mem0_data1_t;


/*
 * Register: IndaccMem0Data2
 * CIP Mem0 Debug Data2
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[95:64] from/for the memory
 *     selected by mem0Sel bits from mem0Ctrl This data is written to
 *     the memory when indaccMem0Ctrl register is written with the
 *     write command When indaccMem0Ctrl register is written with the
 *     read command, this register will hold the Data[95:64] returned
 *     from the memory When pktInjectionEnable is 1:
 *     debugData2Reg[31:0] is used as radmTrgt1Data[63:32]. Allows up
 *     to QW=2DW access.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem0_data2:32;
#else
		uint32_t	mem0_data2:32;
#endif
	} bits;
} indacc_mem0_data2_t;


/*
 * Register: IndaccMem0Data3
 * CIP Mem0 Debug Data3
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[127:96] from/for the memory
 *     selected by mem0Sel bits from mem0Ctrl This data is written to
 *     the memory when indaccMem0Ctrl register is written with the
 *     write command When indaccMem0Ctrl register is written with the
 *     read command, this register will hold the Data[127:96]
 *     returned from the memory When pktInjectionEnable is 1:
 *     debugData3Reg[31:0] is used as radmTrgt1Data[31:0].
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem0_data3:32;
#else
		uint32_t	mem0_data3:32;
#endif
	} bits;
} indacc_mem0_data3_t;


/*
 * Register: IndaccMem0Prty
 * CIP Mem0 Debug Parity
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     parity mask bits for the memory selected by mem0Sel bits from
 *     mem0Ctrl to inject parity error These bits serve two purposes
 *     regarding memory parity : - During indirect write access to
 *     the memories, the value in this register is applied as mask to
 *     the actual parity if prtyWen bit of the indaccCtrl register
 *     has been enabled. The masked parity and data are written into
 *     the specified memory location. - During indirect read access
 *     to the memories, the value in this register is overwritten
 *     with the parity value read from the memory location. If the
 *     parity mask had been set and enabled to be written into this
 *     location it will generate parity error for that memory
 *     location
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:18;
		uint32_t	mem0_parity:14;
#else
		uint32_t	mem0_parity:14;
		uint32_t	rsrvd:18;
#endif
	} bits;
} indacc_mem0_prty_t;


/*
 * Register: IndaccMem1Ctrl
 * CIP Mem1 Debug ctrl
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     1: rd/wr access is done 0: rd/wr access is in progress
 *     1: client pkt injection is done 0: client pkt injection is in
 *     progress
 *     1: client1 pkt injection 0: client0 pkt injection
 *     Mutually exclusive: Either client0 or client1 egress pkt
 *     injection enable: write to 1 for single pkt injection. Must be
 *     0 when enabling diagnostic rd/wr access to memories.
 *     1: Diagnostic rd/wr access enabled 0: Diagnostic rd/wr access
 *     disabled Must be 0 when enabling pkt injection.
 *     1: read, 0: write
 *     This bit is read/writable only if mem1Diagen=1 or if
 *     mem1Diagen bit is also written with '1' along with enabling
 *     this bit. Else, the write will not have any effect. 1: Apply
 *     the parity mask provided in the Prty register 0: Do not apply
 *     the parity mask provided in the Prty register
 *     0 : select retry sot memory 1 : select retry buffer memory 2 :
 *     select msix memory 3 : select hcr cfg memory
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem1_access_status:1;
		uint32_t	rsrvd:4;
		uint32_t	mem1_pktinj_stat:1;
		uint32_t	mem1_pktinj_client:1;
		uint32_t	mem1_pktinj_en:1;
		uint32_t	rsrvd1:1;
		uint32_t	mem1_diagen:1;
		uint32_t	mem1_command:1;
		uint32_t	mem1_prty_wen:1;
		uint32_t	rsrvd2:2;
		uint32_t	mem1_sel:2;
		uint32_t	mem1_addr:16;
#else
		uint32_t	mem1_addr:16;
		uint32_t	mem1_sel:2;
		uint32_t	rsrvd2:2;
		uint32_t	mem1_prty_wen:1;
		uint32_t	mem1_command:1;
		uint32_t	mem1_diagen:1;
		uint32_t	rsrvd1:1;
		uint32_t	mem1_pktinj_en:1;
		uint32_t	mem1_pktinj_client:1;
		uint32_t	mem1_pktinj_stat:1;
		uint32_t	rsrvd:4;
		uint32_t	mem1_access_status:1;
#endif
	} bits;
} indacc_mem1_ctrl_t;


/*
 * Register: IndaccMem1Data0
 * CIP Mem1 Debug Data0
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[31:0] from/for the memory
 *     selected by mem1Sel bits from mem1Ctrl This data is written to
 *     the memory when indaccMem1Ctrl register is written with the
 *     write command When indaccMem1Ctrl register is written with the
 *     read command, this register will hold the Data[31:0] returned
 *     from the memory
 * When pktInjectionEnable is 1: debugData0Reg[31:0] is used in
 *     the following ways: [27:26] = tdcPeuTlp0[or
 *     rdcPeuTlp1]_fmt[1:0]: 2'b00 3DW MRd 2'b01 4DW MRd 2'b10 3DW
 *     MWr 2'b11 4DW MWr [25:13] = tdcPeuTlp0[or
 *     rdcPeuTlp1]_byteLen[12:0]: Note MWr must be limited to 4B =
 *     13'b0000000000001. [12:8] = tdcPeuTlp0[or
 *     rdcPeuTlp1]_tid[4:0]: 5 lsb of tid (TAG ID) [7:0] =
 *     tdcPeuTlp0[or rdcPeuTlp1]_byteEn[7:0]: [7:4] = last DW byte
 *     enables [3:0] = first DW byte enables
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem1_data0:32;
#else
		uint32_t	mem1_data0:32;
#endif
	} bits;
} indacc_mem1_data0_t;


/*
 * Register: IndaccMem1Data1
 * CIP Mem1 Debug Data1
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[63:32] from/for the memory
 *     selected by mem1Sel bits from mem1Ctrl This data is written to
 *     the memory when indaccMem1Ctrl register is written with the
 *     write command When indaccMem1Ctrl register is written with the
 *     read command, this register will hold the Data[63:32] returned
 *     from the memory
 * When pktInjectionEnable is 1: debugData1Reg[31:0] is used as
 *     tdcPeuTlp0[or rdcPeuTlp1]_addr[63:32] high address bits.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem1_data1:32;
#else
		uint32_t	mem1_data1:32;
#endif
	} bits;
} indacc_mem1_data1_t;


/*
 * Register: IndaccMem1Data2
 * CIP Mem1 Debug Data2
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[95:64] from/for the memory
 *     selected by mem1Sel bits from mem1Ctrl This data is written to
 *     the memory when indaccMem1Ctrl register is written with the
 *     write command When indaccMem1Ctrl register is written with the
 *     read command, this register will hold the Data[95:64] returned
 *     from the memory
 * When pktInjectionEnable is 1: debugData2Reg[31:0] is used as
 *     tdcPeuTlp0[or rdcPeuTlp1]_addr[31:0] low address bits.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem1_data2:32;
#else
		uint32_t	mem1_data2:32;
#endif
	} bits;
} indacc_mem1_data2_t;


/*
 * Register: IndaccMem1Data3
 * CIP Mem1 Debug Data3
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     When pktInjectionEnable is 0: Data[127:96] from/for the memory
 *     selected by mem1Sel bits from mem1Ctrl This data is written to
 *     the memory when indaccMem1Ctrl register is written with the
 *     write command When indaccMem1Ctrl register is written with the
 *     read command, this register will hold the Data[127:96]
 *     returned from the memory
 * When pktInjectionEnable is 1: debugData3Reg[31:0] is used as
 *     tdcPeuTlp0[or rdcPeuTlp1]_data[31:0] Limited for MWr to 1 DW.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	mem1_data3:32;
#else
		uint32_t	mem1_data3:32;
#endif
	} bits;
} indacc_mem1_data3_t;


/*
 * Register: IndaccMem1Prty
 * CIP Mem1 Debug Parity
 * Description: Debug data signals from the CIP blocks
 * Fields:
 *     parity mask bits for the memory selected by mem1Sel bits from
 *     mem1Ctrl to inject parity error These bits serve two purposes
 *     regarding memory parity : - During indirect write access to
 *     the memories, the value in this register is applied as mask to
 *     the actual parity if prtyWen bit of the indaccCtrl register
 *     has been enabled. The masked parity and data are written into
 *     the specified memory location. - During indirect read access
 *     to the memories, the value in this register is overwritten
 *     with the parity value read from the memory location. If the
 *     parity mask had been set and enabled to be written into this
 *     location it will generate parity error for that memory
 *     location
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:20;
		uint32_t	mem1_parity:12;
#else
		uint32_t	mem1_parity:12;
		uint32_t	rsrvd:20;
#endif
	} bits;
} indacc_mem1_prty_t;


/*
 * Register: PhyDebugTrainingVec
 * peuPhy Debug Training Vector
 * Description: peuPhy Debug Training Vector register.
 * Fields:
 *     Hard-coded value for peuPhy wrt global debug training block
 *     signatures.
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	dbg_msb:1;
		uint32_t	bld_num:3;
		uint32_t	phydbg_training_vec:28;
#else
		uint32_t	phydbg_training_vec:28;
		uint32_t	bld_num:3;
		uint32_t	dbg_msb:1;
#endif
	} bits;
} phy_debug_training_vec_t;


/*
 * Register: PeuDebugTrainingVec
 * PEU Debug Training Vector
 * Description: PEU Debug Training Vector register.
 * Fields:
 *     Hard-coded value for PEU (VNMy - core clk domain) wrt global
 *     debug training block signatures.
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 *     Hard-coded value for PEU (VNMy - core clk domain) wrt global
 *     debug training block signatures.
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	dbgmsb_upper:1;
		uint32_t	bld_num_upper:3;
		uint32_t	peudbg_upper_training_vec:12;
		uint32_t	dbgmsb_lower:1;
		uint32_t	bld_num_lower:3;
		uint32_t	peudbg_lower_training_vec:12;
#else
		uint32_t	peudbg_lower_training_vec:12;
		uint32_t	bld_num_lower:3;
		uint32_t	dbgmsb_lower:1;
		uint32_t	peudbg_upper_training_vec:12;
		uint32_t	bld_num_upper:3;
		uint32_t	dbgmsb_upper:1;
#endif
	} bits;
} peu_debug_training_vec_t;


/*
 * Register: PipeCfg0
 * PIPE Configuration
 * Description: These are controls signals for the pipe core and are
 * used to define the PIPE core configuration with PipeCfg1 reg value
 * (0x08124)
 * Fields:
 *     If this bit is 1 when pipe reset is released, then the value
 *     on the pipe core's input port 'pipeParameter' is loaded into
 *     the Pipe Core's internal Rx/Tx Parameter register which is
 *     pipeRxTxParam at addr 0x01010. Note that it is software's
 *     responsibility to program the pipeParameter (Pipe Cfg1)
 *     register correctly: e.g. LOSADJ must be 0x1.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:21;
		uint32_t	pipe_serdes_x1:1;
		uint32_t	pipe_force_ewrap:1;
		uint32_t	pipe_force_loopback:1;
		uint32_t	pipe_force_parm:1;
		uint32_t	pipe_freq_sel:1;
		uint32_t	pipe_p1_pdown:1;
		uint32_t	pipe_p1_pdtx:1;
		uint32_t	pipe_same_sel:1;
		uint32_t	pipe_system_clk:1;
		uint32_t	gbt_term_i:2;
#else
		uint32_t	gbt_term_i:2;
		uint32_t	pipe_system_clk:1;
		uint32_t	pipe_same_sel:1;
		uint32_t	pipe_p1_pdtx:1;
		uint32_t	pipe_p1_pdown:1;
		uint32_t	pipe_freq_sel:1;
		uint32_t	pipe_force_parm:1;
		uint32_t	pipe_force_loopback:1;
		uint32_t	pipe_force_ewrap:1;
		uint32_t	pipe_serdes_x1:1;
		uint32_t	rsrvd:21;
#endif
	} bits;
} pipe_cfg0_t;


/*
 * Register: PipeCfg1
 * PIPE Configuration
 * Description: These values define the PIPE core configuration and
 * is presented on the Pipe core's input port 'pipeParameter'.
 * The value on the pipe core's input 'pipeParameter' is loaded into
 * the pipe core's internal Rx/Tx Parameter register, which is
 * pipeRxTxParam at addr 0x01010, by forcing the pipeForceParm bit of
 * the Pipe Cfg0 Register at address 0x08120.
 *
 * Fields:
 *     Tx Driver Emphasis
 *     Serial output Slew Rate Control
 *     Tx Voltage Mux control
 *     Tx Voltage Pulse control
 *     Output Swing setting
 *     Transmitter Clock generator pole adjust
 *     Transmitter Clock generator zero adjust
 *     Receiver Clock generator pole adjust
 *     Receiver Clock generator zero adjust
 *     Bias Control for factory testing and debugging
 *     Receiver LOS Threshold adjustment. LSI suggests this POR
 *     default value must be 0x1 (which is the POR default value of
 *     the Pipe Rx/Tx Parameter Register).
 *     Receiver Input Equalizer control
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:1;
		uint32_t	emph:3;
		uint32_t	rsrvd1:1;
		uint32_t	risefall:3;
		uint32_t	vmuxlo:2;
		uint32_t	vpulselo:2;
		uint32_t	vtxlo:4;
		uint32_t	tp:2;
		uint32_t	tz:2;
		uint32_t	rp:2;
		uint32_t	rz:2;
		uint32_t	biascntl:1;
		uint32_t	losadj:3;
		uint32_t	rxeq:4;
#else
		uint32_t	rxeq:4;
		uint32_t	losadj:3;
		uint32_t	biascntl:1;
		uint32_t	rz:2;
		uint32_t	rp:2;
		uint32_t	tz:2;
		uint32_t	tp:2;
		uint32_t	vtxlo:4;
		uint32_t	vpulselo:2;
		uint32_t	vmuxlo:2;
		uint32_t	risefall:3;
		uint32_t	rsrvd1:1;
		uint32_t	emph:3;
		uint32_t	rsrvd:1;
#endif
	} bits;
} pipe_cfg1_t;


/*
 * Register: CipBarMaskCfg
 * BAR Mask Config
 * Description: To write to the BAR MASK registers in the EP Core PCI
 * Config registers This register should be initialised before
 * writing the value to into the cipBarMask register. The lower 3
 * bits define the BAR register number whose mask value has to be
 * over written with the values that will be written into the
 * cipBarMask register. [2:0] = 0 thru 5 selects bar0Mask thru
 * bar5Mask registers = 6,7 selects Expansion romBarMask register
 * Hydra's configuration for the BARs is as below : BAR1, BAR0 :
 * Forms 64 bit PIO BAR. BAR1 handles the upper address bits BAR0
 * handles the lower address bits BAR3, BAR2 : Forms 64 bit MSIX BAR
 * BAR3 handles the upper address bits BAR2 handles the lower address
 * bits BAR5, BAR4 : Not used and so disabled. Hence, user writes
 * will not have any effect. romBar : Expansion romBar
 *
 * Fields:
 *     0 : bar0Mask 1 : bar1Mask 2 : bar2Mask 3 : bar3Mask 4 :
 *     bar4Mask 5 : bar5Mask 6, 7 ; romBarMask
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:29;
		uint32_t	data:3;
#else
		uint32_t	data:3;
		uint32_t	rsrvd:29;
#endif
	} bits;
} cip_bar_mask_cfg_t;


/*
 * Register: CipBarMask
 * BAR Mask
 * Description: Value to write to the BAR MASK registers in the EP
 * Core PCI Config registers The lower 3 bits of cipMaskCfg register
 * define the BAR register number Write to this register will
 * initiate the DBI access to the EP Core. The cipBarMaskCfg register
 * should be setup before writing to this register. [31:1] = Mask
 * value [0] = 1: BAR is enabled; 0: BAR is disabled. Note that the
 * BAR must be enabled ([0] == 1) before the Mask value will be
 * written into the actual bar mask register. If the BAR is disabled
 * ([0]==0), two writes to this register are required before the Mask
 * value is written into the actual bar mask register. Refer to EP
 * core data book for more details.
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} cip_bar_mask_t;


/*
 * Register: CipLdsv0Stat
 * LDSV0 Status (for debug purpose)
 * Description: Returns the status of LDSV0 Flags regardless of their
 * group
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} cip_ldsv0_stat_t;


/*
 * Register: CipLdsv1Stat
 * LDSV1 Status (for debug purpose)
 * Description: Returns the status of LDSV1 Flags regardless of their
 * group
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	data:32;
#else
		uint32_t	data:32;
#endif
	} bits;
} cip_ldsv1_stat_t;


/*
 * Register: PeuIntrStat
 * PEU Interrupt Status
 * Description: Returns the parity error status of all of the PEU
 * RAMs, and external (to peu) block pio access errors. External
 * block pio access errors could be due to either host or SPI
 * initiated accesses. These fields are RO and can be cleared only
 * through a cip reset All these errors feed to devErrStat.peuErr1
 * which in turn feed to LDSV1.devErr1
 * Partity Error bits: These bits log the very first parity error
 * detected in a particular memory. The corresponding memory location
 * is logged in respective perrLoc registers. External Block PIO
 * Access Error bits: These bits log the very first error that
 * resulted in access error. The corresponding address is logged in
 * respective accErrLog registers.
 * These bits can be set by writing a '1' to the corresponding
 * mirror bit in the peuIntrStatMirror register.
 * Note: PEU RAM Parity Errors and their corresponding interrupt:
 * When these bits are set and the device error status interrupt is
 * not masked, the PEU attempts to send the corresponding interrupt
 * back to the RC. Depending on which ram is impacted and the
 * corresponding logic impacted in the EP core, a coherent interrupt
 * message may not be sent in all cases. For the times when the EP
 * core is unable to send an interrupt, the SPI interface is to be
 * used for error diagnosis as the PEU interrupt status is logged
 * regardless of whether the interrupt is sent to the RC. The
 * following data was collected via simulation: -Parity error
 * impacted rams that likely will be able to send an interrupt:
 * npDataq, pDataq, cplDataq, hcr. -Parity error impacted rams that
 * may not be able to send an interrupt: npHdrq, pHdrq, cplHdrq, MSIx
 * table, retryram, retrysot.
 *
 * Fields:
 *     Error indication from SPROM Controller for Sprom Download
 *     access This error indicates that a parity error was detected
 *     from SRAM. For more details, please refer to SPROM Controller
 *     PRM.
 *     Error indication from TDC for PIO access The error location
 *     and type are logged in tdcPioaccErrLog
 *     Error indication from RDC for PIO access The error location
 *     and type are logged in rdcPioaccErrLog
 *     Error indication from PFC for PIO access The error location
 *     and type are logged in pfcPioaccErrLog
 *     Error indication from VMAC for PIO access The error location
 *     and type are logged in vmacPioaccErrLog
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	spc_acc_err:1;
		uint32_t	tdc_pioacc_err:1;
		uint32_t	rdc_pioacc_err:1;
		uint32_t	pfc_pioacc_err:1;
		uint32_t	vmac_pioacc_err:1;
		uint32_t	rsrvd1:6;
		uint32_t	cpl_hdrq_parerr:1;
		uint32_t	cpl_dataq_parerr:1;
		uint32_t	retryram_xdlh_parerr:1;
		uint32_t	retrysotram_xdlh_parerr:1;
		uint32_t	p_hdrq_parerr:1;
		uint32_t	p_dataq_parerr:1;
		uint32_t	np_hdrq_parerr:1;
		uint32_t	np_dataq_parerr:1;
		uint32_t	eic_msix_parerr:1;
		uint32_t	hcr_parerr:1;
#else
		uint32_t	hcr_parerr:1;
		uint32_t	eic_msix_parerr:1;
		uint32_t	np_dataq_parerr:1;
		uint32_t	np_hdrq_parerr:1;
		uint32_t	p_dataq_parerr:1;
		uint32_t	p_hdrq_parerr:1;
		uint32_t	retrysotram_xdlh_parerr:1;
		uint32_t	retryram_xdlh_parerr:1;
		uint32_t	cpl_dataq_parerr:1;
		uint32_t	cpl_hdrq_parerr:1;
		uint32_t	rsrvd1:6;
		uint32_t	vmac_pioacc_err:1;
		uint32_t	pfc_pioacc_err:1;
		uint32_t	rdc_pioacc_err:1;
		uint32_t	tdc_pioacc_err:1;
		uint32_t	spc_acc_err:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} peu_intr_stat_t;


/*
 * Register: PeuIntrMask
 * Parity Error Status Mask
 * Description: Masks for interrupt generation for block and parity
 * error in the PEU RAMs For the VNM errors (spc, tdc, rdc, pfc, &
 * vmac), note that the interrupt message to the host will be delayed
 * from the actual moment that the error is detected until the host
 * does a PIO access and this mask is cleared.
 *
 * Fields:
 *     1: Mask interrupt generation for access error from SPROM
 *     Controller
 *     1: Mask interrupt generation for PIO access error from TDC
 *     1: Mask interrupt generation for PIO access error from RDC
 *     1: Mask interrupt generation for PIO access error from PFC
 *     1: Mask interrupt generation for PIO access error from VMAC
 *     1: Mask interrupt generation for parity error from Completion
 *     Header Q memory
 *     1: Mask interrupt generation for parity error from Completion
 *     Data Q memory
 *     1: Mask interrupt generation for parity error from Retry
 *     memory
 *     1: Mask interrupt generation for parity error from Retry SOT
 *     memory
 *     1: Mask interrupt generation for parity error from Posted
 *     Header Q memory
 *     1: Mask interrupt generation for parity error from Posted Data
 *     Q memory
 *     1: Mask interrupt generation for parity error from Non-Posted
 *     Header Q memory
 *     1: Mask interrupt generation for parity error from Non-Posted
 *     Data Q memory
 *     1: Mask interrupt generation for parity error from MSIX memory
 *     1: Mask interrupt generation for parity error from HCR memory
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	spc_acc_err_mask:1;
		uint32_t	tdc_pioacc_err_mask:1;
		uint32_t	rdc_pioacc_err_mask:1;
		uint32_t	pfc_pioacc_err_mask:1;
		uint32_t	vmac_pioacc_err_mask:1;
		uint32_t	rsrvd1:6;
		uint32_t	cpl_hdrq_parerr_mask:1;
		uint32_t	cpl_dataq_parerr_mask:1;
		uint32_t	retryram_xdlh_parerr_mask:1;
		uint32_t	retrysotram_xdlh_parerr_mask:1;
		uint32_t	p_hdrq_parerr_mask:1;
		uint32_t	p_dataq_parerr_mask:1;
		uint32_t	np_hdrq_parerr_mask:1;
		uint32_t	np_dataq_parerr_mask:1;
		uint32_t	eic_msix_parerr_mask:1;
		uint32_t	hcr_parerr_mask:1;
#else
		uint32_t	hcr_parerr_mask:1;
		uint32_t	eic_msix_parerr_mask:1;
		uint32_t	np_dataq_parerr_mask:1;
		uint32_t	np_hdrq_parerr_mask:1;
		uint32_t	p_dataq_parerr_mask:1;
		uint32_t	p_hdrq_parerr_mask:1;
		uint32_t	retrysotram_xdlh_parerr_mask:1;
		uint32_t	retryram_xdlh_parerr_mask:1;
		uint32_t	cpl_dataq_parerr_mask:1;
		uint32_t	cpl_hdrq_parerr_mask:1;
		uint32_t	rsrvd1:6;
		uint32_t	vmac_pioacc_err_mask:1;
		uint32_t	pfc_pioacc_err_mask:1;
		uint32_t	rdc_pioacc_err_mask:1;
		uint32_t	tdc_pioacc_err_mask:1;
		uint32_t	spc_acc_err_mask:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} peu_intr_mask_t;


/*
 * Register: PeuIntrStatMirror
 * Parity Error Status Mirror
 * Description: Mirror bits for Parity error generation in the PEU
 * RAMs When set, the corresponding parity error is generated ; this
 * will cause an interrupt to occur if the respective mask bit is not
 * set. As the mirror of the Parity Error Status Register, clearing
 * of the status bits is controlled by how the Parity Error Status
 * Register is cleared. These bits cannot be cleared by writing 0 to
 * this register.
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	spc_acc_err_mirror:1;
		uint32_t	tdc_pioacc_err_mirror:1;
		uint32_t	rdc_pioacc_err_mirror:1;
		uint32_t	pfc_pioacc_err_mirror:1;
		uint32_t	vmac_pioacc_err_mirror:1;
		uint32_t	rsrvd1:6;
		uint32_t	cpl_hdrq_parerr_mirror:1;
		uint32_t	cpl_dataq_parerr_mirror:1;
		uint32_t	retryram_xdlh_parerr_mirror:1;
		uint32_t	retrysotram_xdlh_parerr_mirror:1;
		uint32_t	p_hdrq_parerr_mirror:1;
		uint32_t	p_dataq_parerr_mirror:1;
		uint32_t	np_hdrq_parerr_mirror:1;
		uint32_t	np_dataq_parerr_mirror:1;
		uint32_t	eic_msix_parerr_mirror:1;
		uint32_t	hcr_parerr_mirror:1;
#else
		uint32_t	hcr_parerr_mirror:1;
		uint32_t	eic_msix_parerr_mirror:1;
		uint32_t	np_dataq_parerr_mirror:1;
		uint32_t	np_hdrq_parerr_mirror:1;
		uint32_t	p_dataq_parerr_mirror:1;
		uint32_t	p_hdrq_parerr_mirror:1;
		uint32_t	retrysotram_xdlh_parerr_mirror:1;
		uint32_t	retryram_xdlh_parerr_mirror:1;
		uint32_t	cpl_dataq_parerr_mirror:1;
		uint32_t	cpl_hdrq_parerr_mirror:1;
		uint32_t	rsrvd1:6;
		uint32_t	vmac_pioacc_err_mirror:1;
		uint32_t	pfc_pioacc_err_mirror:1;
		uint32_t	rdc_pioacc_err_mirror:1;
		uint32_t	tdc_pioacc_err_mirror:1;
		uint32_t	spc_acc_err_mirror:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} peu_intr_stat_mirror_t;


/*
 * Register: CplHdrqPerrLoc
 * Completion Header Queue Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Completion Header Q
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	cpl_hdrq_parerr_loc:16;
#else
		uint32_t	cpl_hdrq_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} cpl_hdrq_perr_loc_t;


/*
 * Register: CplDataqPerrLoc
 * Completion Data Queue Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Completion Data Q
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	cpl_dataq_parerr_loc:16;
#else
		uint32_t	cpl_dataq_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} cpl_dataq_perr_loc_t;


/*
 * Register: RetrPerrLoc
 * Retry RAM Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Retry RAM
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	retr_parerr_loc:16;
#else
		uint32_t	retr_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} retr_perr_loc_t;


/*
 * Register: RetrSotPerrLoc
 * Retry SOT RAM Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Retry RAM SOT
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	retr_sot_parerr_loc:16;
#else
		uint32_t	retr_sot_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} retr_sot_perr_loc_t;


/*
 * Register: PHdrqPerrLoc
 * Posted Header Queue Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Posted Header Q
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	p_hdrq_parerr_loc:16;
#else
		uint32_t	p_hdrq_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} p_hdrq_perr_loc_t;


/*
 * Register: PDataqPerrLoc
 * Posted Data Queue Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Posted Data Q
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	p_dataq_parerr_loc:16;
#else
		uint32_t	p_dataq_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} p_dataq_perr_loc_t;


/*
 * Register: NpHdrqPerrLoc
 * Non-Posted Header Queue Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Non-Posted Header Q
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	np_hdrq_parerr_loc:16;
#else
		uint32_t	np_hdrq_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} np_hdrq_perr_loc_t;


/*
 * Register: NpDataqPerrLoc
 * Non-Posted Data Queue Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in Non-Posted Data Q
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	np_dataq_parerr_loc:16;
#else
		uint32_t	np_dataq_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} np_dataq_perr_loc_t;


/*
 * Register: MsixPerrLoc
 * MSIX Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in MSIX memory
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	eic_msix_parerr_loc:16;
#else
		uint32_t	eic_msix_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} msix_perr_loc_t;


/*
 * Register: HcrPerrLoc
 * HCR Memory Parity Error Location
 * Description: Returns the location of the first parity error
 * detected in HCR Memory
 *
 * Fields:
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:16;
		uint32_t	hcr_parerr_loc:16;
#else
		uint32_t	hcr_parerr_loc:16;
		uint32_t	rsrvd:16;
#endif
	} bits;
} hcr_perr_loc_t;


/*
 * Register: TdcPioaccErrLog
 * TDC PIO Access Error Location
 * Description: Returns the location of the first transaction
 * location that resulted in error
 *
 * Fields:
 *     Type of access error 0 : Block returned error condition 1 :
 *     Transaction resulted in time out by CIP
 *     Transaction Location that resulted in error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	tdc_pioacc_err_type:1;
		uint32_t	tdc_pioacc_err_loc:20;
#else
		uint32_t	tdc_pioacc_err_loc:20;
		uint32_t	tdc_pioacc_err_type:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} tdc_pioacc_err_log_t;


/*
 * Register: RdcPioaccErrLog
 * RDC PIO Access Error Location
 * Description: Returns the location of the first transaction
 * location that resulted in error
 *
 * Fields:
 *     Type of access error 0 : Block returned error condition 1 :
 *     Transaction resulted in time out by CIP
 *     Transaction Location that resulted in error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	rdc_pioacc_err_type:1;
		uint32_t	rdc_pioacc_err_loc:20;
#else
		uint32_t	rdc_pioacc_err_loc:20;
		uint32_t	rdc_pioacc_err_type:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} rdc_pioacc_err_log_t;


/*
 * Register: PfcPioaccErrLog
 * PFC PIO Access Error Location
 * Description: Returns the location of the first transaction
 * location that resulted in error
 *
 * Fields:
 *     Type of access error 0 : Block returned error condition 1 :
 *     Transaction resulted in time out by CIP
 *     Transaction Location that resulted in error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	pfc_pioacc_err_type:1;
		uint32_t	pfc_pioacc_err_loc:20;
#else
		uint32_t	pfc_pioacc_err_loc:20;
		uint32_t	pfc_pioacc_err_type:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} pfc_pioacc_err_log_t;


/*
 * Register: VmacPioaccErrLog
 * VMAC PIO Access Error Location
 * Description: Returns the location of the first transaction
 * location that resulted in error
 *
 * Fields:
 *     Type of access error 0 : Block returned error condition 1 :
 *     Transaction resulted in time out by CIP
 *     Transaction Location that resulted in error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	vmac_pioacc_err_type:1;
		uint32_t	vmac_pioacc_err_loc:20;
#else
		uint32_t	vmac_pioacc_err_loc:20;
		uint32_t	vmac_pioacc_err_type:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} vmac_pioacc_err_log_t;


/*
 * Register: LdGrpCtrl
 * Logical Device Group Control
 * Description: LD Group assignment
 * Fields:
 *     Logical device group number of this logical device
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:27;
		uint32_t	num:5;
#else
		uint32_t	num:5;
		uint32_t	rsrvd:27;
#endif
	} bits;
} ld_grp_ctrl_t;


/*
 * Register: DevErrStat
 * Device Error Status
 * Description: Device Error Status logs errors that cannot be
 * attributed to a given dma channel. It does not duplicate errors
 * already observable via specific block logical device groups.
 * Device Error Status bits [31:16] feed LDSV0.devErr0 Device Error
 * Status bits [15:0] feed LDSV1.devErr1
 * Fields:
 *     Set to 1 if Reorder Buffer/Reorder Table has a single bit
 *     ecc/parity error. This error condition is asserted by TDC to
 *     PEU.
 *     Set to 1 if RX Ctrl or Data FIFO has a single bit ecc error.
 *     This error condition is asserted by RDC to PEU.
 *     Set to 1 if any of the external block accesses have resulted
 *     in error or if a parity error was detected in the SPROM
 *     internal ram. Refer to peuIntrStat for the errors that
 *     contribute to this bit.
 *     Set to 1 if Reorder Buffer/Reorder Table has a double bit
 *     ecc/parity error. This error condition is asserted by TDC to
 *     PEU.
 *     Set to 1 if RX Ctrl or Data FIFO has a double bit ecc error.
 *     This error condition is asserted by RDC to PEU.
 *     Set to 1 if any PEU ram (MSI-X, retrybuf/sot, p/np/cpl queues)
 *     has a parity error Refer to peuIntrStat for the errors that
 *     contribute to this bit.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:13;
		uint32_t	tdc_err0:1;
		uint32_t	rdc_err0:1;
		uint32_t	rsrvd1:1;
		uint32_t	rsrvd2:12;
		uint32_t	vnm_pio_err1:1;
		uint32_t	tdc_err1:1;
		uint32_t	rdc_err1:1;
		uint32_t	peu_err1:1;
#else
		uint32_t	peu_err1:1;
		uint32_t	rdc_err1:1;
		uint32_t	tdc_err1:1;
		uint32_t	vnm_pio_err1:1;
		uint32_t	rsrvd2:12;
		uint32_t	rsrvd1:1;
		uint32_t	rdc_err0:1;
		uint32_t	tdc_err0:1;
		uint32_t	rsrvd:13;
#endif
	} bits;
} dev_err_stat_t;


/*
 * Register: DevErrMask
 * Device Error Mask
 * Description: Device Error Mask (gates devErrStat)
 * Fields:
 *     Mask for TDC error0
 *     Mask for RDC error0
 *     Mask for VNM PIO Access error
 *     Mask for TDC error1
 *     Mask for RDC error1
 *     Mask for PEU memories parity error
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:13;
		uint32_t	tdc_mask0:1;
		uint32_t	rdc_mask0:1;
		uint32_t	rsrvd1:1;
		uint32_t	rsrvd2:12;
		uint32_t	vnm_pio_mask1:1;
		uint32_t	tdc_mask1:1;
		uint32_t	rdc_mask1:1;
		uint32_t	peu_mask1:1;
#else
		uint32_t	peu_mask1:1;
		uint32_t	rdc_mask1:1;
		uint32_t	tdc_mask1:1;
		uint32_t	vnm_pio_mask1:1;
		uint32_t	rsrvd2:12;
		uint32_t	rsrvd1:1;
		uint32_t	rdc_mask0:1;
		uint32_t	tdc_mask0:1;
		uint32_t	rsrvd:13;
#endif
	} bits;
} dev_err_mask_t;


/*
 * Register: LdIntrTimRes
 * Logical Device Interrupt Timer Resolution
 * Description: Logical Device Interrupt Timer Resolution
 * Fields:
 *     Timer resolution in 250 MHz cycles
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:12;
		uint32_t	res:20;
#else
		uint32_t	res:20;
		uint32_t	rsrvd:12;
#endif
	} bits;
} ld_intr_tim_res_t;


/*
 * Register: LDSV0
 * Logical Device State Vector 0
 * Description: Logical Device State Vector 0
 * Fields:
 *     Interrupt from mail box3 to HOST
 *     Interrupt from mail box2 to HOST
 *     Interrupt from mail box1 to HOST
 *     Interrupt from mail box0 to HOST
 *     Flag0 bits for Network MAC
 *     Flag0 bits for Virtual MAC
 *     Flag0 bits for Tx DMA channels 3-0
 *     Flag0 bits for Rx DMA channels 3-0
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	dev_err0:1;
		uint32_t	rsrvd:7;
		uint32_t	mbox3_irq:1;
		uint32_t	mbox2_irq:1;
		uint32_t	mbox1_irq:1;
		uint32_t	mbox0_irq:1;
		uint32_t	rsrvd1:1;
		uint32_t	nmac_f0:1;
		uint32_t	pfc_f0:1;
		uint32_t	vmac_f0:1;
		uint32_t	rsrvd2:4;
		uint32_t	tdc_f0:4;
		uint32_t	rsrvd3:4;
		uint32_t	rdc_f0:4;
#else
		uint32_t	rdc_f0:4;
		uint32_t	rsrvd3:4;
		uint32_t	tdc_f0:4;
		uint32_t	rsrvd2:4;
		uint32_t	vmac_f0:1;
		uint32_t	pfc_f0:1;
		uint32_t	nmac_f0:1;
		uint32_t	rsrvd1:1;
		uint32_t	mbox0_irq:1;
		uint32_t	mbox1_irq:1;
		uint32_t	mbox2_irq:1;
		uint32_t	mbox3_irq:1;
		uint32_t	rsrvd:7;
		uint32_t	dev_err0:1;
#endif
	} bits;
} ldsv0_t;


/*
 * Register: LDSV1
 * Logical Device State Vector 1
 * Description: Logical Device State Vector 1
 * Fields:
 *     Flag1 bits for Network MAC
 *     Flag1 bits for Tx DMA channels 3-0
 *     Flag1 bits for Rx DMA channels 3-0
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	dev_err1:1;
		uint32_t	rsrvd:7;
		uint32_t	rsrvd1:5;
		uint32_t	nmac_f1:1;
		uint32_t	rsrvd2:1;
		uint32_t	rsrvd3:1;
		uint32_t	rsrvd4:4;
		uint32_t	tdc_f1:4;
		uint32_t	rsrvd5:4;
		uint32_t	rdc_f1:4;
#else
		uint32_t	rdc_f1:4;
		uint32_t	rsrvd5:4;
		uint32_t	tdc_f1:4;
		uint32_t	rsrvd4:4;
		uint32_t	rsrvd3:1;
		uint32_t	rsrvd2:1;
		uint32_t	nmac_f1:1;
		uint32_t	rsrvd1:5;
		uint32_t	rsrvd:7;
		uint32_t	dev_err1:1;
#endif
	} bits;
} ldsv1_t;


/*
 * Register: LdIntrMask
 * Logical Device Interrupt Mask
 * Description: Logical Device Interrupt Mask
 * Fields:
 *     Flag1 mask for logical device N (0-31)
 *     Flag0 mask for logical device N (0-31)
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:30;
		uint32_t	ldf1_mask:1;
		uint32_t	ldf0_mask:1;
#else
		uint32_t	ldf0_mask:1;
		uint32_t	ldf1_mask:1;
		uint32_t	rsrvd:30;
#endif
	} bits;
} ld_intr_mask_t;


/*
 * Register: LdIntrMgmt
 * Logical Device Interrupt Management
 * Description: Logical Device Interrupt Management
 * Fields:
 *     SW arms the logical device for interrupt. Cleared by HW after
 *     interrupt issued. (1 = arm)
 *     Timer set by SW. Hardware counts down.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	arm:1;
		uint32_t	rsrvd:25;
		uint32_t	timer:6;
#else
		uint32_t	timer:6;
		uint32_t	rsrvd:25;
		uint32_t	arm:1;
#endif
	} bits;
} ld_intr_mgmt_t;


/*
 * Register: SID
 * System Interrupt Data
 * Description: System Interrupt Data (MSI Vectors)
 * Fields:
 *     Data sent along with the interrupt
 */
typedef union {
	uint32_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	rsrvd:27;
		uint32_t	data:5;
#else
		uint32_t	data:5;
		uint32_t	rsrvd:27;
#endif
	} bits;
} sid_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _HXGE_PEU_HW_H */

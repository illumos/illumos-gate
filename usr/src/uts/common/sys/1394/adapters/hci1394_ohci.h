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

#ifndef _SYS_1394_ADAPTERS_HCI1394_OHCI_H
#define	_SYS_1394_ADAPTERS_HCI1394_OHCI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_ohci.h
 *    Provides access macros and routines to the OpenHCI HW.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/note.h>

#include <sys/1394/adapters/hci1394_def.h>
#include <sys/1394/adapters/hci1394_buf.h>


#define	OHCI_MAX_SELFID_SIZE		2048
#define	OHCI_BUSGEN_MAX			0xFF


/* Misc */
#define	OHCI_REG_SET			1 	/* ddi_regs_map_setup */
#define	OHCI_CHIP_RESET_TIME_IN_uSEC	((clock_t)100)    /* 100uS */
#define	OHCI_BUS_RESET_TIME_IN_uSEC	((clock_t)100000) /* 100mS */
#define	OHCI_MAX_COOKIE			16
#define	OHCI_uS_PER_BUS_CYCLE		125
#define	OHCI_nS_PER_BUS_CYCLE		125000
#define	OHCI_BUS_CYCLE_TO_uS(cycles)	(cycles * OHCI_uS_PER_BUS_CYCLE)
#define	OHCI_BUS_CYCLE_TO_nS(cycles)	(cycles * OHCI_nS_PER_BUS_CYCLE)
#define	OHCI_CYCLE_SEC_SHIFT		13
#define	OHCI_CYCLE_SEC_MASK		0xE000
#define	OHCI_CYCLE_CNT_MASK		0x1FFF
#define	OHCI_MAX_CYCLE_CNT		8000
#define	OHCI_TIMESTAMP_MASK		0xFFFF
#define	OHCI_REG_ADDR_MASK		0x7FC

/* OpenHCI Global Swap location in PCI space */
#define	OHCI_PCI_HCI_CONTROL_REG	((off_t)0x40)
#define	OHCI_PCI_GLOBAL_SWAP		0x00000001


/* PHY Register #1 */
#define	OHCI_PHY_RHB			0x80
#define	OHCI_PHY_IBR			0x40
#define	OHCI_PHY_MAX_GAP		0x3F

/* PHY Register #4 */
#define	OHCI_PHY_EXTND_MASK		0xE0
#define	OHCI_PHY_EXTND			0xE0

/* PHY Register #4 */
#define	OHCI_PHY_CNTDR			0x40

/* PHY Register #5 */
#define	OHCI_PHY_ISBR			0x40
#define	OHCI_PHY_LOOP_ERR		0x20
#define	OHCI_PHY_PWRFAIL_ERR		0x10
#define	OHCI_PHY_TIMEOUT_ERR		0x08
#define	OHCI_PHY_PORTEVT_ERR		0x04
#define	OHCI_PHY_ENBL_ACCEL		0x02
#define	OHCI_PHY_ENBL_MULTI		0x01

/* OpenHCI Event Codes.  Refer to OHCI 1.0 section 3.1.1 */
#define	OHCI_EVT_NO_STATUS		0x0
#define	OHCI_EVT_LONG_PACKET		0x2
#define	OHCI_EVT_MISSING_ACK		0x3
#define	OHCI_EVT_UNDERRUN		0x4
#define	OHCI_EVT_OVERRUN		0x5
#define	OHCI_EVT_DESCRIPTOR_READ	0x6
#define	OHCI_EVT_DATA_READ		0x7
#define	OHCI_EVT_DATA_WRITE		0x8
#define	OHCI_EVT_BUS_RESET		0x9
#define	OHCI_EVT_TIMEOUT		0xA
#define	OHCI_EVT_TCODE_ERR		0xB
#define	OHCI_EVT_UNKNOWN		0xE
#define	OHCI_EVT_FLUSHED		0xF
#define	OHCI_ACK_COMPLETE		0x11
#define	OHCI_ACK_PENDING		0x12
#define	OHCI_ACK_BUSY_X			0x14
#define	OHCI_ACK_BUSY_A			0x15
#define	OHCI_ACK_BUSY_B			0x16
#define	OHCI_ACK_TARDY			0x1B
#define	OHCI_ACK_CONFLICT_ERROR		0x1C
#define	OHCI_ACK_DATA_ERROR		0x1D
#define	OHCI_ACK_TYPE_ERROR		0x1E
#define	OHCI_ACK_ADDRESS_ERROR		0x1F

#define	OHCI_REG_NODEID_ROOT		0x40000000
#define	OHCI_REG_BUSOPTIONS_CMC		0x40000000

/* hci_regs_s.ir_ctxt_regs.ctxt_match */
#define	OHCI_MTC_TAG3_MASK		0x80000000
#define	OHCI_MTC_TAG3_SHIFT		31
#define	OHCI_MTC_TAG2_MASK		0x40000000
#define	OHCI_MTC_TAG2_SHIFT		30
#define	OHCI_MTC_TAG1_MASK		0x20000000
#define	OHCI_MTC_TAG1_SHIFT		29
#define	OHCI_MTC_TAG0_MASK		0x10000000
#define	OHCI_MTC_TAG0_SHIFT		28
#define	OHCI_MTC_MATCH_MASK		0x07FFF000
#define	OHCI_MTC_MATCH_SHIFT		12
#define	OHCI_MTC_SYNC_MASK		0x00000F00
#define	OHCI_MTC_SYNC_SHIFT		8
#define	OHCI_MTC_TAG1SY_MASK		0x00000040
#define	OHCI_MTC_TAG1SY_SHIFT		6
#define	OHCI_MTC_CHAN_MASK		0x0000003F
#define	OHCI_MTC_CHAN_SHIFT		0

/* hci_regs_s.self_id_buflo - See OpenHCI 1.00 section 11.1 */
#define	OHCI_SLF_BUF_LO			0xFFFFF800

/* hci_regs_s.self_id_count - See OpenHCI 1.00 section 11.2 */
#define	OHCI_SLFC_ERROR			0x80000000
#define	OHCI_SLFC_GEN_MASK		0x00FF0000
#define	OHCI_SLFC_GEN_SHIFT		16
#define	OHCI_SLFC_NUM_QUADS_MASK	0x00001FFC


/*
 * hci_regs_s.int_event_* and hci_regs_s.int_mask_*
 * See OpenHCI 1.00 section 6
 */
#define	OHCI_INTR_REQ_TX_CMPLT		0x00000001
#define	OHCI_INTR_RESP_TX_CMPLT		0x00000002
#define	OHCI_INTR_ARRQ			0x00000004
#define	OHCI_INTR_ARRS			0x00000008
#define	OHCI_INTR_RQPKT			0x00000010
#define	OHCI_INTR_RSPKT			0x00000020
#define	OHCI_INTR_ISOCH_TX		0x00000040	/* RO */
#define	OHCI_INTR_ISOCH_RX		0x00000080	/* RO */
#define	OHCI_INTR_POST_WR_ERR		0x00000100
#define	OHCI_INTR_LOCK_RESP_ERR		0x00000200
#define	OHCI_INTR_SELFID_CMPLT		0x00010000
#define	OHCI_INTR_BUS_RESET		0x00020000
#define	OHCI_INTR_PHY			0x00080000
#define	OHCI_INTR_CYC_SYNCH		0x00100000
#define	OHCI_INTR_CYC_64_SECS		0x00200000
#define	OHCI_INTR_CYC_LOST		0x00400000
#define	OHCI_INTR_CYC_INCONSISTENT	0x00800000
#define	OHCI_INTR_UNRECOVERABLE_ERR	0x01000000
#define	OHCI_INTR_CYC_TOO_LONG		0x02000000
#define	OHCI_INTR_PHY_REG_RCVD		0x04000000
#define	OHCI_INTR_VENDOR_SPECIFIC	0x40000000
#define	OHCI_INTR_MASTER_INTR_ENBL	0x80000000	/* int_mask_* only */

/* hci_regs_s.fairness_ctrl - See OpenHCI 1.00 section 5.8 */
#define	OHCI_FAIR_PRI_REQ		0x000000FF

/* hci_regs_s.link_ctrl_set/clr - See OpenHCI 1.00 section 5.9 */
#define	OHCI_LC_CYC_SRC			0x00400000
#define	OHCI_LC_CYC_MAST		0x00200000
#define	OHCI_LC_CTIME_ENBL		0x00100000
#define	OHCI_LC_RCV_PHY			0x00000400
#define	OHCI_LC_RCV_SELF		0x00000200
#define	OHCI_LC_CYC_SYNC		0x00000010

/* Defines for registers in HCI register space */
/* Note: bits are read/write unless otherwise noted (RO-read only) */

/* hci_regs_s.version - See OpenHCI 1.00 section 5.2 */
#define	OHCI_VER_GUID_ROM		0x01000000
#define	OHCI_VER_VERSION_MASK		0x00FF0000
#define	OHCI_VER_VERSION_SHIFT		16
#define	OHCI_VER_REVISION_MASK		0x000000FF
#define	OHCI_VERSION(version) \
	((version & OHCI_VER_VERSION_MASK) >> OHCI_VER_VERSION_SHIFT)
#define	OHCI_REVISION(revision) \
	(revision & OHCI_VER_REVISION_MASK)

/* hci_regs_s.guid_rom - See OpenHCI 1.00 section 5.3 */
#define	OHCI_GROM_ADDR_RESET		0x80000000	/* 1-initiate reset */
#define	OHCI_GROM_RD_START		0x02000000	/* 1-start byte read */
#define	OHCI_GROM_RD_DATA		0x00FF0000	/* RO */

/* hci_regs_s.at_retries - See OpenHCI 1.00 section 5.4 */
#define	OHCI_RET_SECLIM_MASK		0xE0000000	/* dual-phase retry */
#define	OHCI_RET_SECLIM_SHIFT		29
#define	OHCI_RET_CYCLLIM_MASK		0xFFFF0000	/* dual-phase retry */
#define	OHCI_RET_CYCLLIM_SHIFT		16
#define	OHCI_RET_MAX_PHYS_RESP_MASK	0x00000F00	/* physical resp rtry */
#define	OHCI_RET_MAX_PHYS_RESP_SHIFT	8
#define	OHCI_RET_MAX_ATRESP_MASK	0x000000F0	/* AT response retry */
#define	OHCI_RET_MAX_ATRESP_SHIFT	4
#define	OHCI_RET_MAX_ATREQ_MASK		0x0000000F	/* AT request retry */
#define	OHCI_RET_MAX_ATREQ_SHIFT	0

/* hci_regs_s.csr_ctrl - See OpenHCI 1.00 section 5.5.1 */
#define	OHCI_CSR_DONE		0x80000000	/* RO 1-cmp_swap complete */
#define	OHCI_CSR_SELECT		0x00000003

#define	OHCI_CSR_SEL_BUS_MGR_ID		0	/* bus manager ID register */
#define	OHCI_CSR_SEL_BANDWIDTH_AVAIL	1	/* bandwidth available reg */
#define	OHCI_CSR_SEL_CHANS_AVAIL_HI	2	/* channels_available_hi reg */
#define	OHCI_CSR_SEL_CHANS_AVAIL_LO	3	/* channels_available_lo reg */

/* hci_regs_s.config_rom_hdr - See OpenHCI 1.00 section 5.5.6 */
#define	OHCI_CROM_INFO_LEN	0xFF000000
#define	OHCI_CROM_CRC_LEN	0x00FF0000
#define	OHCI_CROM_ROM_CRC_VAL	0x0000FFFF

/* hci_regs_s.bus_options - See OpenHCI 1.00 section 5.5.4 */
#define	OHCI_BOPT_IRMC		0x80000000	/* Isoch resrce mgr capable */
#define	OHCI_BOPT_CMC		0x40000000	/* cycle master capable */
#define	OHCI_BOPT_ISC		0x20000000	/* isochronous data capable */
#define	OHCI_BOPT_BMC		0x10000000	/* bus manager capable */
#define	OHCI_BOPT_PMC		0x80000000	/* power manager capable */
#define	OHCI_BOPT_CYC_CLK_ACC	0x00FF0000
#define	OHCI_BOPT_MAX_REC	0x0000F000
#define	OHCI_BOPT_GEN		0x000000C0
#define	OHCI_BOPT_LINK_SPD	0x00000007

/* hci_regs_s.guid_hi - See OpenHCI 1.00 section 5.5.5 */
#define	OHCI_GUID_NODE_VENDOR_ID	0xFFFFFF00
#define	OHCI_GUID_CHIP_ID_HI		0x000000FF

/* hci_regs_s.config_rom_maplo - See OpenHCI 1.00 section 5.5.6 */
#define	OHCI_CMAP_ADDR			0xFFFFFF00	/* 1k aligned */

/* hci_regs_s.posted_write_addrhi - See OpenHCI 1.00 section 13.2.8.1 */
#define	OHCI_POST_SOURCE_ID		0xFFFF0000
#define	OHCI_POST_OFFSET_HI		0x0000FFFF

/* hci_regs_s.vendor_id - See OpenHCI 1.00 section 5.2 */
#define	OHCI_VEND_ID			0x00FFFFFF
#define	OHCI_VEND_UNIQUE		0xFF000000

/* hci_regs_s.hc_ctrl_set/clr - See OpenHCI 1.00 section 5.7 */
#define	OHCI_HC_NO_BSWAP	0x40000000	/* 1-big endian,0-little end */
#define	OHCI_HC_PROG_PHY_ENBL	0x00800000	/* 1-prog phy capabilities */
#define	OHCI_HC_APHY_ENBL	0x00040000	/* 1-Aphy enhancements enbld */
#define	OHCI_HC_LPS		0x00080000	/* 1-link pwr on, 0-off */
#define	OHCI_HC_POSTWR_ENBL	0x00040000	/* 1-enabled, 0-disabled */
#define	OHCI_HC_LINK_ENBL	0x00020000	/* 1-enabled, 0-disabled */
#define	OHCI_HC_SOFT_RESET	0x00010000	/* 1-reset in prog, 0-done */

/* hci_regs_s.node_id - See OpenHCI 1.00 section 5.10 */
#define	OHCI_NDID_IDVALID		0x80000000
#define	OHCI_NDID_ROOT_MASK		0x40000000
#define	OHCI_NDID_ROOT_SHIFT		30
#define	OHCI_NDID_CPS_MASK		0x08000000
#define	OHCI_NDID_CPS_SHIFT		27
#define	OHCI_NDID_BUSNUM_MASK		0x0000FFC0
#define	OHCI_NDID_BUSNUM_SHIFT		6
#define	OHCI_NDID_NODENUM_MASK		0x0000003F
#define	OHCI_NDID_NODENUM_SHIFT		0

/* hci_regs_s.phy_ctrl - See OpenHCI 1.00 section 5.11, 1394-1994 J.4.1 */
#define	OHCI_PHYC_RDDONE		0x80000000
#define	OHCI_PHYC_RDREG			0x00008000
#define	OHCI_PHYC_WRREG			0x00004000
#define	OHCI_PHYC_RDADDR_MASK		0x0F000000
#define	OHCI_PHYC_RDADDR_SHIFT		24
#define	OHCI_PHYC_RDDATA_MASK		0x00FF0000
#define	OHCI_PHYC_RDDATA_SHIFT		16
#define	OHCI_PHYC_REGADDR_MASK		0x00000F00
#define	OHCI_PHYC_REGADDR_SHIFT		8
#define	OHCI_PHYC_WRDATA_MASK		0x000000FF
#define	OHCI_PHYC_WRDATA_SHIFT		0

/* hci_regs_s.context_ctrl -- several contexts */
#define	OHCI_CC_RUN_MASK		0x00008000
#define	OHCI_CC_RUN_SHIFT		15
#define	OHCI_CC_WAKE_MASK		0x00001000
#define	OHCI_CC_WAKE_SHIFT		12
#define	OHCI_CC_DEAD_MASK		0x00000800
#define	OHCI_CC_DEAD_SHIFT		11
#define	OHCI_CC_ACTIVE_MASK		0x00000400
#define	OHCI_CC_ACTIVE_SHIFT		10

#define	OHCI_CC_SPD_MASK		0x000000E0
#define	OHCI_CC_SPD_SHIFT		5
#define	OHCI_CC_EVT_MASK		0x0000001F
#define	OHCI_CC_EVT_SHIFT		0

/* hci_regs context_ctrl for IR */
#define	OHCI_IRCTL_BFILL_MASK		0x80000000
#define	OHCI_IRCTL_BFILL_SHIFT		31
#define	OHCI_IRCTL_IHDR_MASK		0x40000000
#define	OHCI_IRCTL_IHDR_SHIFT		30
#define	OHCI_IRCTL_MTC_ENBL_MASK	0x20000000
#define	OHCI_IRCTL_MTC_ENBL_SHIFT	29
#define	OHCI_IRCTL_MULTI_MASK		0x10000000
#define	OHCI_IRCTL_MULTI_SHIFT		28

/* hci_regs context_ctrl for IT */
#define	OHCI_ITCTL_MTC_ENBL_MASK	0x80000000
#define	OHCI_ITCTL_MTC_ENBL_SHIFT	31
#define	OHCI_ITCTL_MATCH_MASK		0x7FFF0000
#define	OHCI_ITCTL_MATCH_SHIFT		16


#define	HCI1394_IS_ARRESP(tcode) \
	((tcode == IEEE1394_TCODE_WRITE_RESP) || \
	(tcode == IEEE1394_TCODE_READ_QUADLET_RESP) || \
	(tcode == IEEE1394_TCODE_READ_BLOCK_RESP) || \
	(tcode == IEEE1394_TCODE_LOCK_RESP))

#define	HCI1394_IS_ARREQ(tcode) \
	((tcode == IEEE1394_TCODE_READ_QUADLET) || \
	(tcode == IEEE1394_TCODE_WRITE_QUADLET) || \
	(tcode == IEEE1394_TCODE_READ_BLOCK) || \
	(tcode == IEEE1394_TCODE_WRITE_BLOCK) || \
	(tcode == IEEE1394_TCODE_LOCK) || \
	(tcode == IEEE1394_TCODE_PHY))

#define	HCI1394_IRCTXT_CTRL_SET(HCIP, I, BFFILL, IHDR, MATCHENBL, MULTI, RUN, \
	WAKE)	(ddi_put32((HCIP)->ohci->ohci_reg_handle, \
	&(HCIP)->ohci->ohci_regs->ir[(I)].ctxt_ctrl_set, \
	0 | (((BFFILL) << OHCI_IRCTL_BFILL_SHIFT) & OHCI_IRCTL_BFILL_MASK) | \
	(((IHDR) << OHCI_IRCTL_IHDR_SHIFT) & OHCI_IRCTL_IHDR_MASK) | \
	(((MATCHENBL) << OHCI_IRCTL_MTC_ENBL_SHIFT) & \
	    OHCI_IRCTL_MTC_ENBL_MASK) | \
	(((MULTI) << OHCI_IRCTL_MULTI_SHIFT) & OHCI_IRCTL_MULTI_MASK) | \
	(((RUN) << OHCI_CC_RUN_SHIFT) & OHCI_CC_RUN_MASK) | \
	(((WAKE) << OHCI_CC_WAKE_SHIFT) & OHCI_CC_WAKE_MASK)))

#define	HCI1394_IRCTXT_CTRL_CLR(HCIP, I, BFFILL, IHDR, MATCHENBL, MULTI, RUN) \
	(ddi_put32((HCIP)->ohci->ohci_reg_handle, \
	&(HCIP)->ohci->ohci_regs->ir[(I)].ctxt_ctrl_clr, \
	0 | (((BFFILL) << OHCI_IRCTL_BFILL_SHIFT) & OHCI_IRCTL_BFILL_MASK) | \
	(((IHDR) << OHCI_IRCTL_IHDR_SHIFT) & OHCI_IRCTL_IHDR_MASK) | \
	(((MATCHENBL) << OHCI_IRCTL_MTC_ENBL_SHIFT) & \
	    OHCI_IRCTL_MTC_ENBL_MASK) | \
	(((MULTI) << OHCI_IRCTL_MULTI_SHIFT) & OHCI_IRCTL_MULTI_MASK) | \
	(((RUN) << OHCI_CC_RUN_SHIFT) & OHCI_CC_RUN_MASK)))

#define	HCI1394_ITCTXT_CTRL_SET(HCIP, I, MATCHENBL, MATCH, RUN, WAKE) \
	(ddi_put32((HCIP)->ohci->ohci_reg_handle, \
	&(HCIP)->ohci->ohci_regs->it[(I)].ctxt_ctrl_set, 0 | \
	(((MATCHENBL) << OHCI_ITCTL_MTC_ENBL_SHIFT) & \
	    OHCI_ITCTL_MTC_ENBL_MASK) | \
	(((MATCH) << OHCI_ITCTL_MATCH_SHIFT) & OHCI_ITCTL_MATCH_MASK) | \
	(((RUN) << OHCI_CC_RUN_SHIFT) & OHCI_CC_RUN_MASK) | \
	(((WAKE) << OHCI_CC_WAKE_SHIFT) & OHCI_CC_WAKE_MASK)))

#define	HCI1394_ITCTXT_CTRL_CLR(HCIP, I, MATCHENBL, MATCH, RUN) \
	(ddi_put32((HCIP)->ohci->ohci_reg_handle, \
	&(HCIP)->ohci->ohci_regs->it[(I)].ctxt_ctrl_clr, 0 | \
	(((MATCHENBL) << OHCI_ITCTL_MTC_ENBL_SHIFT) & \
	    OHCI_ITCTL_MTC_ENBL_MASK) | \
	(((MATCH) << OHCI_ITCTL_MATCH_SHIFT) & OHCI_ITCTL_MATCH_MASK) | \
	(((RUN) << OHCI_CC_RUN_SHIFT) & OHCI_CC_RUN_MASK)))


#define	HCI1394_IRCTXT_MATCH_WRITE(HCIP, I, TAG3, TAG2, TAG1, TAG0, MATCH, \
	SYNC, TAG1SYNC, CHAN)	(ddi_put32((HCIP)->ohci->ohci_reg_handle, \
	&(HCIP)->ohci->ohci_regs->ir[(I)].ctxt_match, 0 | \
	(((TAG3) << OHCI_MTC_TAG3_SHIFT) & OHCI_MTC_TAG3_MASK) | \
	(((TAG2) << OHCI_MTC_TAG2_SHIFT) & OHCI_MTC_TAG2_MASK) | \
	(((TAG1) << OHCI_MTC_TAG1_SHIFT) & OHCI_MTC_TAG1_MASK) | \
	(((TAG0) << OHCI_MTC_TAG0_SHIFT) & OHCI_MTC_TAG0_MASK) | \
	(((MATCH) << OHCI_MTC_MATCH_SHIFT) & OHCI_MTC_MATCH_MASK) | \
	(((SYNC) << OHCI_MTC_SYNC_SHIFT) & OHCI_MTC_SYNC_MASK) | \
	(((TAG1SYNC) << OHCI_MTC_TAG1SY_SHIFT) & OHCI_MTC_TAG1SY_MASK) | \
	(((CHAN) << OHCI_MTC_CHAN_SHIFT) & OHCI_MTC_CHAN_MASK)))

#define	HCI1394_ISOCH_CTXT_ACTIVE(SOFTSTATEP, CTXTP) \
	(ddi_get32((SOFTSTATEP)->ohci->ohci_reg_handle, \
	&(CTXTP)->ctxt_regsp->ctxt_ctrl_set) & OHCI_CC_ACTIVE_MASK)

#define	HCI1394_ISOCH_CTXT_RUN(SOFTSTATEP, CTXTP) \
	(ddi_get32((SOFTSTATEP)->ohci->ohci_reg_handle, \
	&(CTXTP)->ctxt_regsp->ctxt_ctrl_set) & OHCI_CC_RUN_MASK)

#define	HCI1394_ISOCH_CTXT_CMD_PTR(SOFTSTATEP, CTXTP) \
	(ddi_get32((SOFTSTATEP)->ohci->ohci_reg_handle, \
	&(CTXTP)->ctxt_regsp->cmd_ptrlo))

/*
 * 1394 OpenHCI 1.0 general context register layout
 *    All contexts except for Isoch Receive have the following layout
 *    See the OpenHCI v1.0 specification for register definitions.
 */
typedef struct hci1394_ctxt_regs_s {
	uint32_t	ctxt_ctrl_set;
	uint32_t 	ctxt_ctrl_clr;
	uint32_t 	reserved;
	uint32_t 	cmd_ptrlo;
} hci1394_ctxt_regs_t;

/*
 * 1394 OpenHCI 1.0 Isochronous Receive context register layout
 *    See the OpenHCI v1.0 specification for register definitions.
 */
typedef struct hci1394_ir_ctxt_regs_s {
	uint32_t	ctxt_ctrl_set;
	uint32_t	ctxt_ctrl_clr;
	uint32_t	reserved0;
	uint32_t	cmd_ptrlo;
	uint32_t	ctxt_match;
	uint32_t	reserved1[3];
} hci1394_ir_ctxt_regs_t;

/*
 * 1394 OpenHCI 1.0 registers
 *    See the OpenHCI v1.0 specification for register definitions.
 */
typedef struct hci1394_regs_s {
	uint32_t		version;
	uint32_t		guid_rom;
	uint32_t		at_retries;
	uint32_t		csr_data;
	uint32_t		csr_compare_data;
	uint32_t		csr_ctrl;
	uint32_t		config_rom_hdr;
	uint32_t		bus_id;
	uint32_t		bus_options;
	uint32_t		guid_hi;
	uint32_t		guid_lo;
	uint32_t		reserved01;
	uint32_t		reserved02;
	uint32_t		config_rom_maplo;
	uint32_t		posted_write_addrlo;
	uint32_t		posted_write_addrhi;
	uint32_t		vendor_id;
	uint32_t		reserved03[3];
	uint32_t		hc_ctrl_set;
	uint32_t		hc_ctrl_clr;
	uint32_t		reserved06[2];
	uint32_t		reserved08;
	uint32_t		self_id_buflo;
	uint32_t		self_id_count;
	uint32_t		reserved09;
	uint32_t		ir_multi_maskhi_set;
	uint32_t		ir_multi_maskhi_clr;
	uint32_t		ir_multi_masklo_set;
	uint32_t		ir_multi_masklo_clr;
	uint32_t		intr_event_set;
	uint32_t		intr_event_clr;
	uint32_t		intr_mask_set;
	uint32_t		intr_mask_clr;
	uint32_t		it_intr_event_set;
	uint32_t		it_intr_event_clr;
	uint32_t		it_intr_mask_set;
	uint32_t		it_intr_mask_clr;
	uint32_t		ir_intr_event_set;
	uint32_t		ir_intr_event_clr;
	uint32_t		ir_intr_mask_set;
	uint32_t		ir_intr_mask_clr;
	uint32_t		reserved10[11];
	uint32_t		fairness_ctrl;
	uint32_t		link_ctrl_set;
	uint32_t		link_ctrl_clr;
	uint32_t		node_id;
	uint32_t		phy_ctrl;
	uint32_t		isoch_cycle_timer;
	uint32_t		reserved21[3];
	uint32_t		ar_req_filterhi_set;
	uint32_t		ar_req_filterhi_clr;
	uint32_t		ar_req_filterlo_set;
	uint32_t		ar_req_filterlo_clr;
	uint32_t		phys_req_filterhi_set;
	uint32_t		phys_req_filterhi_clr;
	uint32_t		phys_req_filterlo_set;
	uint32_t		phys_req_filterlo_clr;
	uint32_t		phys_upper_bound;
	uint32_t		reserved24[23];
	hci1394_ctxt_regs_t 	at_req;
	uint32_t		reserved47[4];
	hci1394_ctxt_regs_t	at_resp;
	uint32_t		reserved51[4];
	hci1394_ctxt_regs_t	ar_req;
	uint32_t		reserved55[4];
	hci1394_ctxt_regs_t	ar_resp;
	uint32_t		reserved59[4];
	hci1394_ctxt_regs_t	it[HCI1394_MAX_ISOCH_CONTEXTS];
	hci1394_ir_ctxt_regs_t	ir[HCI1394_MAX_ISOCH_CONTEXTS];
} hci1394_regs_t;


/* private structure to keep track of OpenHCI */
typedef struct hci1394_ohci_s {
	/* config ROM and selfid buffers */
	hci1394_buf_handle_t	ohci_cfgrom_handle;
	hci1394_buf_handle_t	ohci_selfid_handle;

	/*
	 * Phy register #1 cached settings.  These are only used for 1394-1995
	 * phy's.  When setting the root holdoff bit and gap count in 1394,
	 * you send out a PHY configuration packet.  The 1995 PHY's will
	 * not look at the PHY packet if we sent it out which means we have
	 * to write directly to PHY register 1.  This creates some ugly race
	 * conditions.  Since we will be following up these settings with a bus
	 * reset shortly, we "cache" them until we generate the bus reset. This
	 * solution is not perfect, but it is the best of a bad thing.
	 */
	boolean_t		ohci_set_root_holdoff;
	boolean_t		ohci_set_gap_count;
	uint_t			ohci_gap_count;

	/*
	 * The bus time is kept using the cycle timer and then counting the
	 * rollovers via the cycle 64 seconds interrupt. (NOTE: every 2
	 * interrupts is one rollover)  We do not wish to be interrupting
	 * the CPU if there is nothing plugged into the bus (since bus time
	 * really isn't used for anything yet (maybe when bridges come out?)).
	 * We will start with the interrupt disabled, if the bus master writes
	 * to the CSR bus time register, we will enable the interrupt.  These
	 * fields keep track of the rollover and whether or not the interrupt
	 * is enabled.
	 */
	volatile uint_t		ohci_bustime_count;
	boolean_t		ohci_bustime_enabled;

	/* whether we have a 1394-1995 or 1394A phy */
	h1394_phy_t		ohci_phy;

	/* General Driver Info */
	hci1394_drvinfo_t	*ohci_drvinfo;

	/*
	 * self id buffer and config rom info.  These are towards bottom of the
	 * structure to make debugging easier.
	 */
	hci1394_buf_info_t	ohci_selfid;
	hci1394_buf_info_t	ohci_cfgrom;

	/* OpenHCI registers */
	ddi_acc_handle_t	ohci_reg_handle;
	hci1394_regs_t		*ohci_regs;

	/*
	 * This mutex is used to protect "atomic" operations to the OpenHCI
	 * hardware.  This includes reads and writes to the PHY, cswap
	 * operations to the HW implemented CSR registers, and any read/modify/
	 * write operations such as updating atreq retries.
	 */
	kmutex_t		ohci_mutex;

	hci1394_state_t		*soft_state;
} hci1394_ohci_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	hci1394_ohci_s::ohci_bustime_count \
	hci1394_ohci_s::ohci_bustime_enabled \
	hci1394_ohci_s::ohci_gap_count \
	hci1394_ohci_s::ohci_set_gap_count \
	hci1394_ohci_s::ohci_set_root_holdoff))

/* handle passed back from init() and used for rest of functions */
typedef hci1394_ohci_t *hci1394_ohci_handle_t;


int hci1394_ohci_init(hci1394_state_t *soft_state, hci1394_drvinfo_t *drvinfo,
    hci1394_ohci_handle_t *ohci_hdl);
void hci1394_ohci_fini(hci1394_ohci_handle_t *ohci_hdl);

void hci1394_ohci_reg_read(hci1394_ohci_handle_t ohci_hdl, uint_t offset,
    uint32_t *data);
void hci1394_ohci_reg_write(hci1394_ohci_handle_t ohci_hdl, uint_t offset,
    uint32_t data);
int hci1394_ohci_phy_init(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_phy_set(hci1394_ohci_handle_t ohci_hdl, uint_t regAddr,
    uint_t bits);
int hci1394_ohci_phy_clr(hci1394_ohci_handle_t ohci_hdl, uint_t regAddr,
    uint_t bits);
int hci1394_ohci_phy_read(hci1394_ohci_handle_t ohci_hdl, uint_t regAddr,
    uint_t *rdData);
int hci1394_ohci_phy_write(hci1394_ohci_handle_t ohci_hdl, uint_t regAddr,
    uint_t wrData);
int hci1394_ohci_phy_info(hci1394_ohci_handle_t ohci_hdl, uint32_t *info);
void hci1394_ohci_intr_master_enable(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_intr_master_disable(hci1394_ohci_handle_t ohci_hdl);
uint32_t hci1394_ohci_intr_asserted(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_intr_enable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
void hci1394_ohci_intr_disable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
void hci1394_ohci_intr_clear(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
uint32_t hci1394_ohci_it_intr_asserted(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_it_intr_enable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
void hci1394_ohci_it_intr_disable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
void hci1394_ohci_it_intr_clear(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
int hci1394_ohci_it_ctxt_count_get(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_it_cmd_ptr_set(hci1394_ohci_handle_t ohci_hdl,
    uint_t context_number, uint32_t io_addr);
uint32_t hci1394_ohci_ir_intr_asserted(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_ir_intr_enable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
void hci1394_ohci_ir_intr_disable(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
void hci1394_ohci_ir_intr_clear(hci1394_ohci_handle_t ohci_hdl,
    uint32_t intr_mask);
int hci1394_ohci_ir_ctxt_count_get(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_ir_cmd_ptr_set(hci1394_ohci_handle_t ohci_hdl,
    uint_t context_number, uint32_t io_addr);
void hci1394_ohci_link_enable(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_link_disable(hci1394_ohci_handle_t ohci_hdl);
uint_t hci1394_ohci_current_busgen(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_soft_reset(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_startup(hci1394_ohci_handle_t ohci_hdl);
uint64_t hci1394_ohci_guid(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_csr_read(hci1394_ohci_handle_t ohci_hdl, uint_t offset,
    uint32_t *data);
int hci1394_ohci_csr_cswap(hci1394_ohci_handle_t ohci_hdl, uint_t generation,
    uint_t offset, uint32_t compare, uint32_t swap, uint32_t *old);
int hci1394_ohci_bus_reset(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_bus_reset_nroot(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_bus_reset_short(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_postwr_addr(hci1394_ohci_handle_t ohci_hdl, uint64_t *addr);
int hci1394_ohci_contender_enable(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_root_holdoff_enable(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_gap_count_set(hci1394_ohci_handle_t ohci_hdl,
    uint_t gap_count);
int hci1394_ohci_phy_filter_set(hci1394_ohci_handle_t ohci_hdl,
    uint64_t mask, uint_t generation);
int hci1394_ohci_phy_filter_clr(hci1394_ohci_handle_t ohci_hdl,
    uint64_t mask, uint_t generation);
void hci1394_ohci_cfgrom_update(hci1394_ohci_handle_t ohci_hdl,
    void *local_buf, uint_t quadlet_count);
void hci1394_ohci_selfid_enable(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_selfid_read(hci1394_ohci_handle_t ohci_hdl, uint_t offset,
    uint32_t *data);
void hci1394_ohci_selfid_info(hci1394_ohci_handle_t ohci_hdl, uint_t *busgen,
    uint_t *size, boolean_t *error);
boolean_t hci1394_ohci_selfid_buf_current(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_selfid_sync(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_nodeid_set(hci1394_ohci_handle_t ohci_hdl, uint_t nodeid);
void hci1394_ohci_nodeid_get(hci1394_ohci_handle_t ohci_hdl, uint_t *nodeid);
void hci1394_ohci_nodeid_info(hci1394_ohci_handle_t ohci_hdl,
    uint_t *nodeid, boolean_t *error);
void hci1394_ohci_cycletime_get(hci1394_ohci_handle_t ohci_hdl,
    uint32_t *cycle_time);
void hci1394_ohci_cycletime_set(hci1394_ohci_handle_t ohci_hdl,
    uint32_t cycle_time);
void hci1394_ohci_bustime_get(hci1394_ohci_handle_t ohci_hdl,
    uint32_t *bus_time);
void hci1394_ohci_bustime_set(hci1394_ohci_handle_t ohci_hdl,
    uint32_t bus_time);
void hci1394_ohci_atreq_retries_get(hci1394_ohci_handle_t ohci_hdl,
    uint_t *atreq_retries);
void hci1394_ohci_atreq_retries_set(hci1394_ohci_handle_t ohci_hdl,
    uint_t atreq_retries);
void hci1394_ohci_isr_cycle64seconds(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_isr_phy(hci1394_ohci_handle_t ohci_hdl);
boolean_t hci1394_ohci_root_check(hci1394_ohci_handle_t ohci_hdl);
boolean_t hci1394_ohci_cmc_check(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_cycle_master_enable(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_cycle_master_disable(hci1394_ohci_handle_t ohci_hdl);
int hci1394_ohci_resume(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_bus_capabilities(hci1394_ohci_handle_t ohci_hdl,
    uint32_t *bus_capabilities);
boolean_t hci1394_ohci_at_active(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_atreq_start(hci1394_ohci_handle_t ohci_hdl,
    uint32_t cmdptr);
void hci1394_ohci_atreq_wake(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_atreq_stop(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_arresp_start(hci1394_ohci_handle_t ohci_hdl,
    uint32_t cmdptr);
void hci1394_ohci_arresp_wake(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_arresp_stop(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_arreq_start(hci1394_ohci_handle_t ohci_hdl,
    uint32_t cmdptr);
void hci1394_ohci_arreq_wake(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_arreq_stop(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_atresp_start(hci1394_ohci_handle_t ohci_hdl,
    uint32_t cmdptr);
void hci1394_ohci_atresp_wake(hci1394_ohci_handle_t ohci_hdl);
void hci1394_ohci_atresp_stop(hci1394_ohci_handle_t ohci_hdl);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_OHCI_H */

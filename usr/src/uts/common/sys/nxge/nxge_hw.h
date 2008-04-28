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

#ifndef	_SYS_NXGE_NXGE_HW_H
#define	_SYS_NXGE_NXGE_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if	!defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN) && \
		!defined(__BIG_ENDIAN) && !defined(__LITTLE_ENDIAN)
#error	Host endianness not defined
#endif

#if	!defined(_BIT_FIELDS_HTOL) && !defined(_BIT_FIELDS_LTOH) && \
		!defined(__BIT_FIELDS_HTOL) && !defined(__BIT_FIELDS_LTOH)
#error	Bit ordering not defined
#endif

#include <nxge_fflp_hw.h>
#include <nxge_ipp_hw.h>
#include <nxge_mac_hw.h>
#include <nxge_rxdma_hw.h>
#include <nxge_txc_hw.h>
#include <nxge_txdma_hw.h>
#include <nxge_zcp_hw.h>
#include <nxge_espc_hw.h>
#include <nxge_n2_esr_hw.h>
#include <nxge_sr_hw.h>
#include <nxge_phy_hw.h>


/*
 * The Neptune chip has 16 Receive DMA channels, but no more than
 * 24 Transmit DMA channels.
 */
typedef uint32_t dc_map_t;

/*
 * The logical group map is a Crossbow addition.
 */
typedef uint32_t lg_map_t;

/* Modes of NXGE core */
typedef	enum nxge_mode_e {
	NXGE_MODE_NE		= 1,
	NXGE_MODE_N2		= 2
} nxge_mode_t;

/*
 * Function control Register
 * (bit 31 is reset to 0. Read back 0 then free to use it.
 * (once done with it, bit 0:15 can be used to store SW status)
 */
#define	DEV_FUNC_SR_REG			(PIO + 0x10000)
#define	DEV_FUNC_SR_SR_SHIFT		0
#define	DEV_FUNC_SR_SR_MASK		0x000000000000FFFFULL
#define	DEV_FUNC_SR_FUNCID_SHIFT	16
#define	DEV_FUNC_SR_FUNCID_MASK		0x0000000000030000ULL
#define	DEV_FUNC_SR_TAS_SHIFT		31
#define	DEV_FUNC_SR_TAS_MASK		0x0000000080000000ULL

typedef union _dev_func_sr_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t tas:1;
			uint32_t res2:13;
			uint32_t funcid:2;
			uint32_t sr:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sr:16;
			uint32_t funcid:2;
			uint32_t res2:13;
			uint32_t tas:1;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} dev_func_sr_t, *p_dev_func_sr_t;


/*
 * Multi Parition Control Register (partitiion manager)
 */
#define	MULTI_PART_CTL_REG	(FZC_PIO + 0x00000)
#define	MULTI_PART_CTL_MPC	0x0000000000000001ULL

typedef union _multi_part_ctl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1:31;
			uint32_t mpc:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t mpc:1;
			uint32_t res1:31;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} multi_part_ctl_t, *p_multi_part_ctl_t;

/*
 * Virtual DMA CSR Address (partition manager)
 */
#define	VADDR_REG		(PIO_VADDR + 0x00000)

/*
 * DMA Channel Binding Register (partition manager)
 */
#define	DMA_BIND_REG		(FZC_PIO + 0x10000)
#define	DMA_BIND_RX_SHIFT	0
#define	DMA_BIND_RX_MASK	0x000000000000001FULL
#define	DMA_BIND_RX_BIND_SHIFT	5
#define	DMA_BIND_RX_BIND_SET	0x0000000000000020ULL
#define	DMA_BIND_RX_BIND_MASK	0x0000000000000020ULL
#define	DMA_BIND_TX_SHIFT	8
#define	DMA_BIND_TX_MASK	0x0000000000001f00ULL
#define	DMA_BIND_TX_BIND_SHIFT	13
#define	DMA_BIND_TX_BIND_SET	0x0000000000002000ULL
#define	DMA_BIND_TX_BIND_MASK	0x0000000000002000ULL

typedef union _dma_bind_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:16;
			uint32_t tx_bind:1;
			uint32_t tx:5;
			uint32_t res2:2;
			uint32_t rx_bind:1;
			uint32_t rx:5;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t rx:5;
			uint32_t rx_bind:1;
			uint32_t res2:2;
			uint32_t tx:5;
			uint32_t tx_bind:1;
			uint32_t res1_1:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
}  dma_bind_t, *p_dma_bind_t;

/*
 * System interrupts:
 *	Logical device and group definitions.
 */
#define	NXGE_INT_MAX_LDS		69
#define	NXGE_INT_MAX_LDGS		64
#define	NXGE_LDGRP_PER_NIU_PORT		(NXGE_INT_MAX_LDGS/2)
#define	NXGE_LDGRP_PER_NEP_PORT		(NXGE_INT_MAX_LDGS/4)
#define	NXGE_LDGRP_PER_2PORTS		(NXGE_INT_MAX_LDGS/2)
#define	NXGE_LDGRP_PER_4PORTS		(NXGE_INT_MAX_LDGS/4)

#define	NXGE_RDMA_LD_START		0
#define	NXGE_TDMA_LD_START		32
#define	NXGE_MIF_LD			63
#define	NXGE_MAC_LD_START		64
#define	NXGE_MAC_LD_PORT0		64
#define	NXGE_MAC_LD_PORT1		65
#define	NXGE_MAC_LD_PORT2		66
#define	NXGE_MAC_LD_PORT3		67
#define	NXGE_SYS_ERROR_LD		68

/*
 * Logical Device Group Number
 */
#define	LDG_NUM_REG		(FZC_PIO + 0x20000)
#define	LDG_NUM_NUM_SHIFT	0
#define	LDG_NUM_NUM_MASK	0x000000000000001FULL

typedef union _ldg_num_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:26;
			uint32_t num:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t num:6;
			uint32_t res1_1:26;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} ldg_num_t, *p_ldg_num_t;

/*
 * Logical Device State Vector
 */
#define	LDSV0_REG		(PIO_LDSV + 0x00000)
#define	LDSV0_LDF_SHIFT		0
#define	LDSV0_LDF_MASK		0x00000000000003FFULL
#define	LDG_NUM_NUM_MASK	0x000000000000001FULL
#define	LDSV_MASK_ALL		0x0000000000000001ULL

/*
 * Logical Device State Vector 1
 */
#define	LDSV1_REG		(PIO_LDSV + 0x00008)

/*
 * Logical Device State Vector 2
 */
#define	LDSV2_REG		(PIO_LDSV + 0x00010)

/* For Logical Device State Vector 0 and 1 */
typedef union _ldsv_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		uint32_t ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} ldsv_t, *p_ldsv_t;

#define	LDSV2_LDF0_SHIFT		0
#define	LDSV2_LDF0_MASK			0x000000000000001FULL
#define	LDSV2_LDF1_SHIFT		5
#define	LDSV2_LDF1_MASK			0x00000000000001E0ULL

typedef union _ldsv2_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:22;
			uint32_t ldf1:5;
			uint32_t ldf0:5;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ldf0:5;
			uint32_t ldf1:5;
			uint32_t res1_1:22;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} ldsv2_t, *p_ldsv2_t;

/*
 * Logical Device Interrupt Mask 0
 */
#define	LD_IM0_REG		(PIO_IMASK0 + 0x00000)
#define	LD_IM0_SHIFT		0
#define	LD_IM0_MASK		0x0000000000000003ULL
#define	LD_IM_MASK		0x0000000000000003ULL

/*
 * Logical Device Interrupt Mask 1
 */
#define	LD_IM1_REG		(PIO_IMASK1 + 0x00000)
#define	LD_IM1_SHIFT		0
#define	LD_IM1_MASK		0x0000000000000003ULL

/* For Lofical Device Interrupt Mask 0 and 1 */
typedef union _ld_im_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {

#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:30;
			uint32_t ldf_mask:2;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ldf_mask:2;
			uint32_t res1_1:30;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} ld_im_t, *p_ld_im_t;

/*
 * Logical Device Group Interrupt Management
 */
#define	LDGIMGN_REG		(PIO_LDSV + 0x00018)
#define	LDGIMGN_TIMER_SHIFT	0
#define	LDGIMGM_TIMER_MASK	0x000000000000003FULL
#define	LDGIMGN_ARM_SHIFT	31
#define	LDGIMGM_ARM		0x0000000080000000ULL
#define	LDGIMGM_ARM_MASK	0x0000000080000000ULL

typedef union _ldgimgm_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t arm:1;
		uint32_t res2:25;
		uint32_t timer:6;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t timer:6;
		uint32_t res2:25;
		uint32_t arm:1;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} ldgimgm_t, *p_ldgimgm_t;

/*
 * Logical Device Group Interrupt Timer Resolution
 */
#define	LDGITMRES_REG		(FZC_PIO + 0x00008)
#define	LDGTITMRES_RES_SHIFT	0			/* bits 19:0 */
#define	LDGTITMRES_RES_MASK	0x00000000000FFFFFULL
typedef union _ldgitmres_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1_1:12;
		uint32_t res:20;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t res:20;
		uint32_t res1_1:12;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} ldgitmres_t, *p_ldgitmres_t;

/*
 * System Interrupt Data
 */
#define	SID_REG			(FZC_PIO + 0x10200)
#define	SID_DATA_SHIFT		0			/* bits 6:0 */
#define	SID_DATA_MASK		0x000000000000007FULL
#define	SID_DATA_INTNUM_SHIFT	0			/* bits 4:0 */
#define	SID_DATA_INTNUM_MASK	0x000000000000001FULL
#define	SID_DATA_FUNCNUM_SHIFT	5			/* bits 6:5 */
#define	SID_DATA_FUNCNUM_MASK	0x0000000000000060ULL
#define	SID_PCI_FUNCTION_SHIFT	(1 << 5)
#define	SID_N2_INDEX		(1 << 6)

#define	SID_DATA(f, v)		((f << SID_DATA_FUNCNUM_SHIFT) |	\
				((v << SID_DATA_SHIFT) & SID_DATA_INTNUM_MASK))

#define	SID_DATA_N2(v)		(v | SID_N2_INDEX)

typedef union _sid_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1_1:25;
		uint32_t data:7;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t data:7;
		uint32_t res1_1:25;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} sid_t, *p_sid_t;

/*
 * Reset Control
 */
#define	RST_CTL_REG		(FZC_PIO + 0x00038)
#define	RST_CTL_MAC_RST3	0x0000000000400000ULL
#define	RST_CTL_MAC_RST3_SHIFT	22
#define	RST_CTL_MAC_RST2	0x0000000000200000ULL
#define	RST_CTL_MAC_RST2_SHIFT	21
#define	RST_CTL_MAC_RST1	0x0000000000100000ULL
#define	RST_CTL_MAC_RST1_SHIFT	20
#define	RST_CTL_MAC_RST0	0x0000000000080000ULL
#define	RST_CTL_MAC_RST0_SHIFT	19
#define	RST_CTL_EN_ACK_TO	0x0000000000000800ULL
#define	RST_CTL_EN_ACK_TO_SHIFT	11
#define	RST_CTL_ACK_TO_MASK	0x00000000000007FEULL
#define	RST_CTL_ACK_TO_SHIFT	1


typedef union _rst_ctl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1:9;
		uint32_t mac_rst3:1;
		uint32_t mac_rst2:1;
		uint32_t mac_rst1:1;
		uint32_t mac_rst0:1;
		uint32_t res2:7;
		uint32_t ack_to_en:1;
		uint32_t ack_to_val:10;
		uint32_t res3:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t res3:1;
		uint32_t ack_to_val:10;
		uint32_t ack_to_en:1;
		uint32_t res2:7;
		uint32_t mac_rst0:1;
		uint32_t mac_rst1:1;
		uint32_t mac_rst2:1;
		uint32_t mac_rst3:1;
		uint32_t res1:9;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rst_ctl_t, *p_rst_ctl_t;

/*
 * System Error Mask
 */
#define	SYS_ERR_MASK_REG	(FZC_PIO + 0x00090)

/*
 * System Error Status
 */
#define	SYS_ERR_STAT_REG	(FZC_PIO + 0x00098)


#define	SYS_ERR_META2_MASK	0x0000000000000400ULL
#define	SYS_ERR_META2_SHIFT	10
#define	SYS_ERR_META1_MASK	0x0000000000000200ULL
#define	SYS_ERR_META1_SHIFT	9
#define	SYS_ERR_PEU_MASK	0x0000000000000100ULL
#define	SYS_ERR_PEU_SHIFT	8
#define	SYS_ERR_TXC_MASK	0x0000000000000080ULL
#define	SYS_ERR_TXC_SHIFT	7
#define	SYS_ERR_RDMC_MASK	0x0000000000000040ULL
#define	SYS_ERR_RDMC_SHIFT	6
#define	SYS_ERR_TDMC_MASK	0x0000000000000020ULL
#define	SYS_ERR_TDMC_SHIFT	5
#define	SYS_ERR_ZCP_MASK	0x0000000000000010ULL
#define	SYS_ERR_ZCP_SHIFT	4
#define	SYS_ERR_FFLP_MASK	0x0000000000000008ULL
#define	SYS_ERR_FFLP_SHIFT	3
#define	SYS_ERR_IPP_MASK	0x0000000000000004ULL
#define	SYS_ERR_IPP_SHIFT	2
#define	SYS_ERR_MAC_MASK	0x0000000000000002ULL
#define	SYS_ERR_MAC_SHIFT	1
#define	SYS_ERR_SMX_MASK	0x0000000000000001ULL
#define	SYS_ERR_SMX_SHIFT	0
#define	SYS_ERR_MASK_ALL	(SYS_ERR_SMX_MASK | SYS_ERR_MAC_MASK | \
				SYS_ERR_IPP_MASK | SYS_ERR_FFLP_MASK | \
				SYS_ERR_ZCP_MASK | SYS_ERR_TDMC_MASK | \
				SYS_ERR_RDMC_MASK | SYS_ERR_TXC_MASK | \
				SYS_ERR_PEU_MASK | SYS_ERR_META1_MASK | \
				SYS_ERR_META2_MASK)


typedef union _sys_err_mask_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res:21;
		uint32_t meta2:1;
		uint32_t meta1:1;
		uint32_t peu:1;
		uint32_t txc:1;
		uint32_t rdmc:1;
		uint32_t tdmc:1;
		uint32_t zcp:1;
		uint32_t fflp:1;
		uint32_t ipp:1;
		uint32_t mac:1;
		uint32_t smx:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t smx:1;
		uint32_t mac:1;
		uint32_t ipp:1;
		uint32_t fflp:1;
		uint32_t zcp:1;
		uint32_t tdmc:1;
		uint32_t rdmc:1;
		uint32_t txc:1;
		uint32_t peu:1;
		uint32_t meta1:1;
		uint32_t meta2:1;
		uint32_t res:21;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} sys_err_mask_t, sys_err_stat_t, *p_sys_err_mask_t, *p_sys_err_stat_t;


/*
 * Meta Arbiter Dirty Transaction ID Control
 */

#define	DIRTY_TID_CTL_REG		(FZC_PIO + 0x0010)
#define	DIRTY_TID_CTL_WR_THRES_MASK	0x00000000003F0000ULL
#define	DIRTY_TID_CTL_WR_THRES_SHIFT    16
#define	DIRTY_TID_CTL_RD_THRES_MASK	0x00000000000003F0ULL
#define	DIRTY_TID_CTL_RD_THRES_SHIFT	4
#define	DIRTY_TID_CTL_DTID_CLR		0x0000000000000002ULL
#define	DIRTY_TID_CTL_DTID_CLR_SHIFT	1
#define	DIRTY_TID_CTL_DTID_EN		0x0000000000000001ULL
#define	DIRTY_TID_CTL_DTID_EN_SHIFT	0

typedef union _dty_tid_ctl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1:10;
		uint32_t np_wr_thres_val:6;
		uint32_t res2:6;
		uint32_t np_rd_thres_val:6;
		uint32_t res3:2;
		uint32_t dty_tid_clr:1;
		uint32_t dty_tid_en:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t dty_tid_en:1;
		uint32_t dty_tid_clr:1;
		uint32_t res3:2;
		uint32_t np_rd_thres_val:6;
		uint32_t res2:6;
		uint32_t np_wr_thres_val:6;
		uint32_t res1:10;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} dty_tid_ctl_t, *p_dty_tid_ctl_t;


/*
 * Meta Arbiter Dirty Transaction ID Status
 */
#define	DIRTY_TID_STAT_REG			(FZC_PIO + 0x0018)
#define	DIRTY_TID_STAT_WR_TID_DTY_CNT_MASK	0x0000000000003F00ULL
#define	DIRTY_TID_STAT_WR_TID_DTY_CNT_SHIFT	8
#define	DIRTY_TID_STAT_RD_TID_DTY_CNT_MASK	0x000000000000003FULL
#define	DIRTY_TID_STAT_RD_TID_DTY_CNT_SHIFT	0

typedef union _dty_tid_stat_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1:18;
		uint32_t wr_tid_dirty_cnt:6;
		uint32_t res2:2;
		uint32_t rd_tid_dirty_cnt:6;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t rd_tid_dirty_cnt:6;
		uint32_t res2:2;
		uint32_t wr_tid_dirty_cnt:6;
		uint32_t res1:18;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} dty_tid_stat_t, *p_dty_tid_stat_t;


/*
 * SMX Registers
 */
#define	SMX_CFIG_DAT_REG		(FZC_PIO + 0x00040)
#define	SMX_CFIG_DAT_RAS_DET_EN_MASK	0x0000000080000000ULL
#define	SMX_CFIG_DAT_RAS_DET_EN_SHIFT	31
#define	SMX_CFIG_DAT_RAS_INJ_EN_MASK	0x0000000040000000ULL
#define	SMX_CFIG_DAT_RAS_INJ_EN_SHIFT	30
#define	SMX_CFIG_DAT_TRANS_TO_MASK	0x000000000FFFFFFFULL
#define	SMX_CFIG_DAT_TRANS_TO_SHIFT	0

typedef union _smx_cfg_dat_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res_err_det:1;
		uint32_t ras_err_inj_en:1;
		uint32_t res:2;
		uint32_t trans_to_val:28;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t trans_to_val:28;
		uint32_t res:2;
		uint32_t ras_err_inj_en:1;
		uint32_t res_err_det:1;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} smx_cfg_dat_t, *p_smx_cfg_dat_t;


#define	SMX_INT_STAT_REG	(FZC_PIO + 0x00048)
#define	SMX_INT_STAT_SM_MASK	0x00000000FFFFFFC0ULL
#define	SMX_INT_STAT_SM_SHIFT	6

typedef union _smx_int_stat_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t st_mc_stat:26;
		uint32_t res:6;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t res:6;
		uint32_t st_mc_stat:26;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} smx_int_stat_t, *p_smx_int_stat_t;


#define		SMX_CTL_REG	(FZC_PIO + 0x00050)

typedef union _smx_ctl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1:21;
		uint32_t resp_err_inj:3;
		uint32_t res2:1;
		uint32_t xtb_err_inj:3;
		uint32_t res3:1;
		uint32_t dbg_sel:3;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t dbg_sel:3;
		uint32_t res3:1;
		uint32_t xtb_err_inj:3;
		uint32_t res2:1;
		uint32_t resp_err_inj:3;
		uint32_t res1:21;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} smx_ctl_t, *p_smx_ctl_t;


#define	SMX_DBG_VEC_REG	(FZC_PIO + 0x00058)

typedef union _smx_dbg_vec_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
		uint32_t dbg_tng_vec;
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} smx_dbg_vec_t, *p_smx_dbg_vec_t;


/*
 * Debug registers
 */

#define	PIO_DBG_SEL_REG	(FZC_PIO + 0x00060)

typedef union _pio_dbg_sel_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
		uint32_t sel;
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} pio_dbg_sel_t, *p_pio_dbg_sel_t;


#define	PIO_TRAIN_VEC_REG	(FZC_PIO + 0x00068)

typedef union _pio_tng_vec_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
		uint32_t training_vec;
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} pio_tng_vec_t, *p_pio_tng_vec_t;

#define	PIO_ARB_CTL_REG	(FZC_PIO + 0x00070)

typedef union _pio_arb_ctl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
		uint32_t ctl;
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} pio_arb_ctl_t, *p_pio_arb_ctl_t;

#define	PIO_ARB_DBG_VEC_REG	(FZC_PIO + 0x00078)

typedef union _pio_arb_dbg_vec_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
		uint32_t dbg_vector;
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} pio_arb_dbg_vec_t, *p_pio_arb_dbg_vec_t;


/*
 * GPIO Registers
 */

#define	GPIO_EN_REG	(FZC_PIO + 0x00028)
#define	GPIO_EN_ENABLE_MASK	 0x000000000000FFFFULL
#define	GPIO_EN_ENABLE_SHIFT	 0
typedef union _gpio_en_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res:16;
		uint32_t enable:16;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t enable:16;
		uint32_t res:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} gpio_en_t, *p_gpio_en_t;

#define	GPIO_DATA_IN_REG	(FZC_PIO + 0x00030)
#define	GPIO_DATA_IN_MASK	0x000000000000FFFFULL
#define	GPIO_DATA_IN_SHIFT	0
typedef union _gpio_data_in_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res:16;
		uint32_t data_in:16;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t data_in:16;
		uint32_t res:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} gpio_data_in_t, *p_gpio_data_in_t;


/*
 * PCI Express Interface Module (PIM) registers
 */
#define	PIM_CONTROL_REG	(FZC_PIM + 0x0)
#define	PIM_CONTROL_DBG_SEL_MASK 0x000000000000000FULL
#define	PIM_CONTROL_DBG_SEL_SHIFT	0
typedef union _pim_ctl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res:28;
		uint32_t dbg_sel:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t dbg_sel:4;
		uint32_t res:28;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} pim_ctl_t, *p_pim_ctl_t;

#define	PIM_DBG_TRAINING_VEC_REG	(FZC_PIM + 0x00008)
#define	PIM_DBG_TRAINING_VEC_MASK	0x00000000FFFFFFFFULL

#define	PIM_INTR_STATUS_REG		(FZC_PIM + 0x00010)
#define	PIM_INTR_STATUS_MASK		0x00000000FFFFFFFFULL

#define	PIM_INTERNAL_STATUS_REG		(FZC_PIM + 0x00018)
#define	PIM_INTERNAL_STATUS_MASK	0x00000000FFFFFFFFULL

#define	PIM_INTR_MASK_REG		(FZC_PIM + 0x00020)
#define	PIM_INTR_MASK_MASK		0x00000000FFFFFFFFULL

/*
 * Partitioning Logical pages Definition registers.
 * (used by both receive and transmit DMA channels)
 */

/* Logical page definitions */
typedef union _log_page_vld_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:28;
			uint32_t func:2;
			uint32_t page1:1;
			uint32_t page0:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t page0:1;
			uint32_t page1:1;
			uint32_t func:2;
			uint32_t res1_1:28;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} log_page_vld_t, *p_log_page_vld_t;


#define	DMA_LOG_PAGE_MASK_SHIFT		0
#define	DMA_LOG_PAGE_MASK_MASK		0x00000000ffffffffULL

/* Receive Logical Page Mask */
typedef union _log_page_mask_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t mask:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t mask:32;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} log_page_mask_t, *p_log_page_mask_t;


/* Receive Logical Page Value */
#define	DMA_LOG_PAGE_VALUE_SHIFT	0
#define	DMA_LOG_PAGE_VALUE_MASK		0x00000000ffffffffULL

/* Receive Logical Page Value */
typedef union _log_page_value_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t value:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t value:32;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} log_page_value_t, *p_log_page_value_t;

/* Receive Logical Page Relocation */
#define	DMA_LOG_PAGE_RELO_SHIFT		0			/* bits 31:0 */
#define	DMA_LOG_PAGE_RELO_MASK		0x00000000ffffffffULL

/* Receive Logical Page Relocation */
typedef union _log_page_relo_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t relo:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t relo:32;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} log_page_relo_t, *p_log_page_relo_t;


/* Receive Logical Page Handle */
#define	DMA_LOG_PAGE_HANDLE_SHIFT	0			/* bits 19:0 */
#define	DMA_LOG_PAGE_HANDLE_MASK	0x00000000ffffffffULL

/* Receive Logical Page Handle */
typedef union _log_page_hdl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:12;
			uint32_t handle:20;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t handle:20;
			uint32_t res1_1:12;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} log_page_hdl_t, *p_log_page_hdl_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_HW_H */

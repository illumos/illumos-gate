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

#ifndef	_SYS_NXGE_NXGE_RXDMA_HW_H
#define	_SYS_NXGE_NXGE_RXDMA_HW_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>
#include <nxge_hw.h>

/*
 * NIU: Receive DMA Channels
 */
/* Receive DMA Clock Divider */
#define	RX_DMA_CK_DIV_REG	(FZC_DMC + 0x00000)
#define	RX_DMA_CK_DIV_SHIFT	0			/* bits 15:0 */
#define	RX_DMA_CK_DIV_MASK	0x000000000000FFFFULL

typedef union _rx_dma_ck_div_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:16;
			uint32_t cnt:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cnt:16;
			uint32_t res1_1:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_dma_ck_div_t, *p_rx_dma_ck_div_t;


/*
 * Default Port Receive DMA Channel (RDC)
 */
#define	DEF_PT_RDC_REG(port)	(FZC_DMC + 0x00008 * (port + 1))
#define	DEF_PT0_RDC_REG		(FZC_DMC + 0x00008)
#define	DEF_PT1_RDC_REG		(FZC_DMC + 0x00010)
#define	DEF_PT2_RDC_REG		(FZC_DMC + 0x00018)
#define	DEF_PT3_RDC_REG		(FZC_DMC + 0x00020)
#define	DEF_PT_RDC_SHIFT	0			/* bits 4:0 */
#define	DEF_PT_RDC_MASK		0x000000000000001FULL


#define	RDC_TBL_REG		(FZC_ZCP + 0x10000)
#define	RDC_TBL_SHIFT		0			/* bits 4:0 */
#define	RDC_TBL_MASK		0x000000000000001FULL

/* For the default port RDC and RDC table */
typedef union _def_pt_rdc_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:27;
			uint32_t rdc:5;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t rdc:5;
			uint32_t res1_1:27;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} def_pt_rdc_t, *p_def_pt_rdc_t;

typedef union _rdc_tbl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:28;
			uint32_t rdc:4;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t rdc:4;
			uint32_t res1_1:28;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rdc_tbl_t, *p_rdc_tbl_t;

/*
 * RDC: 32 bit Addressing mode
 */
#define	RX_ADDR_MD_REG		(FZC_DMC + 0x00070)
#define	RX_ADDR_MD_SHIFT	0			/* bits 0:0 */
#define	RX_ADDR_MD_SET_32	0x0000000000000001ULL	/* 1 to select 32 bit */
#define	RX_ADDR_MD_MASK		0x0000000000000001ULL

typedef union _rx_addr_md_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:28;
			uint32_t dbg_pt_mux_sel:2;
			uint32_t ram_acc:1;
			uint32_t mode32:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t mode32:1;
			uint32_t ram_acc:1;
			uint32_t dbg_pt_mux_sel:2;
			uint32_t res1_1:28;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_addr_md_t, *p_rx_addr_md_t;

/*
 * RDC: Port Scheduler
 */

#define	PT_DRR_WT_REG(portnm)		((FZC_DMC + 0x00028) + (portnm * 8))
#define	PT_DRR_WT0_REG		(FZC_DMC + 0x00028)
#define	PT_DRR_WT1_REG		(FZC_DMC + 0x00030)
#define	PT_DRR_WT2_REG		(FZC_DMC + 0x00038)
#define	PT_DRR_WT3_REG		(FZC_DMC + 0x00040)
#define	PT_DRR_WT_SHIFT		0
#define	PT_DRR_WT_MASK		0x000000000000FFFFULL	/* bits 15:0 */
#define	PT_DRR_WT_DEFAULT_10G	0x0400
#define	PT_DRR_WT_DEFAULT_1G	0x0066
typedef union _pt_drr_wt_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:16;
			uint32_t wt:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t wt:16;
			uint32_t res1_1:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} pt_drr_wt_t, *p_pt_drr_wt_t;

#define	NXGE_RX_DRR_WT_10G	0x400
#define	NXGE_RX_DRR_WT_1G	0x066

/* Port FIFO Usage */
#define	PT_USE_REG(portnum)		((FZC_DMC + 0x00048) + (portnum * 8))
#define	PT_USE0_REG		(FZC_DMC + 0x00048)
#define	PT_USE1_REG		(FZC_DMC + 0x00050)
#define	PT_USE2_REG		(FZC_DMC + 0x00058)
#define	PT_USE3_REG		(FZC_DMC + 0x00060)
#define	PT_USE_SHIFT		0			/* bits 19:0 */
#define	PT_USE_MASK		0x00000000000FFFFFULL

typedef union _pt_use_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:12;
			uint32_t cnt:20;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cnt:20;
			uint32_t res1_1:12;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} pt_use_t, *p_pt_use_t;

/*
 * RDC: Partitioning Support
 *	(Each of the following registers is for each RDC)
 * Please refer to nxge_hw.h for the common logical
 * page configuration register definitions.
 */
#define	RX_LOG_REG_SIZE			0x40
#define	RX_LOG_DMA_OFFSET(channel)	(channel * RX_LOG_REG_SIZE)

#define	RX_LOG_PAGE_VLD_REG	(FZC_DMC + 0x20000)
#define	RX_LOG_PAGE_MASK1_REG	(FZC_DMC + 0x20008)
#define	RX_LOG_PAGE_VAL1_REG	(FZC_DMC + 0x20010)
#define	RX_LOG_PAGE_MASK2_REG	(FZC_DMC + 0x20018)
#define	RX_LOG_PAGE_VAL2_REG	(FZC_DMC + 0x20020)
#define	RX_LOG_PAGE_RELO1_REG	(FZC_DMC + 0x20028)
#define	RX_LOG_PAGE_RELO2_REG	(FZC_DMC + 0x20030)
#define	RX_LOG_PAGE_HDL_REG	(FZC_DMC + 0x20038)

/* RX and TX have the same definitions */
#define	RX_LOG_PAGE1_VLD_SHIFT	1			/* bit 1 */
#define	RX_LOG_PAGE0_VLD_SHIFT	0			/* bit 0 */
#define	RX_LOG_PAGE1_VLD	0x0000000000000002ULL
#define	RX_LOG_PAGE0_VLD	0x0000000000000001ULL
#define	RX_LOG_PAGE1_VLD_MASK	0x0000000000000002ULL
#define	RX_LOG_PAGE0_VLD_MASK	0x0000000000000001ULL
#define	RX_LOG_FUNC_VLD_SHIFT	2			/* bit 3:2 */
#define	RX_LOG_FUNC_VLD_MASK	0x000000000000000CULL

#define	LOG_PAGE_ADDR_SHIFT	12	/* bits[43:12] --> bits[31:0] */

/* RDC: Weighted Random Early Discard */
#define	RED_RAN_INIT_REG	(FZC_DMC + 0x00068)

#define	RED_RAN_INIT_SHIFT	0			/* bits 15:0 */
#define	RED_RAN_INIT_MASK	0x000000000000ffffULL

/* Weighted Random */
typedef union _red_ran_init_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:15;
			uint32_t enable:1;
			uint32_t init:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t init:16;
			uint32_t enable:1;
			uint32_t res1_1:15;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} red_ran_init_t, *p_red_ran_init_t;

/*
 * Buffer block descriptor
 */
typedef struct _rx_desc_t {
	uint32_t	block_addr;
} rx_desc_t, *p_rx_desc_t;

/*
 * RDC: RED Parameter
 *	(Each DMC has one RED register)
 */
#define	RDC_RED_CHANNEL_SIZE		(0x40)
#define	RDC_RED_CHANNEL_OFFSET(channel)	(channel * RDC_RED_CHANNEL_SIZE)

#define	RDC_RED_PARA_REG		(FZC_DMC + 0x30000)
#define	RDC_RED_RDC_PARA_REG(rdc)	\
	(RDC_RED_PARA_REG + (rdc * RDC_RED_CHANNEL_SIZE))

/* the layout of this register is  rx_disc_cnt_t */
#define	RDC_RED_DISC_CNT_REG		(FZC_DMC + 0x30008)
#define	RDC_RED_RDC_DISC_REG(rdc)	\
	(RDC_RED_DISC_CNT_REG + (rdc * RDC_RED_CHANNEL_SIZE))


#define	RDC_RED_PARA1_RBR_SCL_SHIFT	0			/* bits 2:0 */
#define	RDC_RED_PARA1_RBR_SCL_MASK	0x0000000000000007ULL
#define	RDC_RED_PARA1_ENB_SHIFT		3			/* bit 3 */
#define	RDC_RED_PARA1_ENB		0x0000000000000008ULL
#define	RDC_RED_PARA1_ENB_MASK		0x0000000000000008ULL

#define	RDC_RED_PARA_WIN_SHIFT		0			/* bits 3:0 */
#define	RDC_RED_PARA_WIN_MASK		0x000000000000000fULL
#define	RDC_RED_PARA_THRE_SHIFT	4			/* bits 15:4 */
#define	RDC_RED_PARA_THRE_MASK		0x00000000000000f0ULL
#define	RDC_RED_PARA_WIN_SYN_SHIFT	16			/* bits 19:16 */
#define	RDC_RED_PARA_WIN_SYN_MASK	0x00000000000000f0ULL
#define	RDC_RED_PARA_THRE_SYN_SHIFT	20			/* bits 31:20 */
#define	RDC_RED_PARA_THRE_SYN_MASK	0x00000000000fff00ULL

/* RDC:  RED parameters  */
typedef union _rdc_red_para_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t thre_sync:12;
		uint32_t win_syn:4;
		uint32_t thre:12;
		uint32_t win:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t win:4;
		uint32_t thre:12;
		uint32_t win_syn:4;
		uint32_t thre_sync:12;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rdc_red_para_t, *p_rdc_red_para_t;

/*
 * RDC: Receive DMA Datapath Configuration
 *	The following register definitions are for
 *	each DMA channel. Each DMA CSR is 512 bytes
 *	(0x200).
 */
#define	RXDMA_CFIG1_REG			(DMC + 0x00000)
#define	RXDMA_CFIG2_REG			(DMC + 0x00008)

#define	RXDMA_CFIG1_MBADDR_H_SHIFT	0			/* bits 11:0 */
#define	RXDMA_CFIG1_MBADDR_H_MASK	0x0000000000000fc0ULL
#define	RXDMA_CFIG1_RST_SHIFT		30			/* bit 30 */
#define	RXDMA_CFIG1_RST			0x0000000040000000ULL
#define	RXDMA_CFIG1_RST_MASK		0x0000000040000000ULL
#define	RXDMA_CFIG1_EN_SHIFT		31
#define	RXDMA_CFIG1_EN			0x0000000080000000ULL
#define	RXDMA_CFIG1_EN_MASK		0x0000000080000000ULL

typedef union _rxdma_cfig1_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t en:1;
			uint32_t rst:1;
			uint32_t qst:1;
			uint32_t res2:17;
			uint32_t mbaddr_h:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t mbaddr_h:12;
			uint32_t res2:17;
			uint32_t qst:1;
			uint32_t rst:1;
			uint32_t en:1;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rxdma_cfig1_t, *p_rxdma_cfig1_t;

#define	RXDMA_HDR_SIZE_DEFAULT		2
#define	RXDMA_HDR_SIZE_FULL		18

#define	RXDMA_CFIG2_FULL_HDR_SHIFT	0			/* Set to 1 */
#define	RXDMA_CFIG2_FULL_HDR		0x0000000000000001ULL
#define	RXDMA_CFIG2_FULL_HDR_MASK	0x0000000000000001ULL
#define	RXDMA_CFIG2_OFFSET_SHIFT		1		/* bit 3:1 */
#define	RXDMA_CFIG2_OFFSET_MASK		0x000000004000000eULL
#define	RXDMA_CFIG2_MBADDR_L_SHIFT	6			/* bit 31:6 */
#define	RXDMA_CFIG2_MBADDR_L_MASK	0x00000000ffffffc0ULL

/* NOTE: offset256 valid only for Neptune-L and RF-NIU */
typedef union _rxdma_cfig2_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t mbaddr:26;
			uint32_t res2:2;
			uint32_t offset256:1;
			uint32_t offset:2;
			uint32_t full_hdr:1;

#elif defined(_BIT_FIELDS_LTOH)
			uint32_t full_hdr:1;
			uint32_t offset:2;
			uint32_t offset256:1;
			uint32_t res2:2;
			uint32_t mbaddr:26;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rxdma_cfig2_t, *p_rxdma_cfig2_t;

/*
 * RDC: Receive Block Ring Configuration
 *	The following register definitions are for
 *	each DMA channel.
 */
#define	RBR_CFIG_A_REG			(DMC + 0x00010)
#define	RBR_CFIG_B_REG			(DMC + 0x00018)
#define	RBR_KICK_REG			(DMC + 0x00020)
#define	RBR_STAT_REG			(DMC + 0x00028)
#define	RBR_HDH_REG			(DMC + 0x00030)
#define	RBR_HDL_REG			(DMC + 0x00038)

#define	RBR_CFIG_A_STADDR_SHIFT		6			/* bits 17:6 */
#define	RBR_CFIG_A_STDADDR_MASK		0x000000000003ffc0ULL
#define	RBR_CFIG_A_STADDR_BASE_SHIFT	18			/* bits 43:18 */
#define	RBR_CFIG_A_STDADDR_BASE_MASK	0x00000ffffffc0000ULL
#define	RBR_CFIG_A_LEN_SHIFT		48			/* bits 63:48 */
#define	RBR_CFIG_A_LEN_MASK		0xFFFF000000000000ULL

typedef union _rbr_cfig_a_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t len:16;
			uint32_t res1:4;
			uint32_t staddr_base:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t staddr_base:12;
			uint32_t res1:4;
			uint32_t len:16;
#endif
		} hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t staddr_base:14;
			uint32_t staddr:12;
			uint32_t res2:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:6;
			uint32_t staddr:12;
			uint32_t staddr_base:14;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t len:16;
			uint32_t res1:4;
			uint32_t staddr_base:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t staddr_base:12;
			uint32_t res1:4;
			uint32_t len:16;
#endif
		} hdw;
#endif
	} bits;
} rbr_cfig_a_t, *p_rbr_cfig_a_t;


#define	RBR_CFIG_B_BUFSZ0_SHIFT		0			/* bit 1:0 */
#define	RBR_CFIG_B_BUFSZ0_MASK		0x0000000000000001ULL
#define	RBR_CFIG_B_VLD0_SHIFT		7			/* bit 7 */
#define	RBR_CFIG_B_VLD0			0x0000000000000008ULL
#define	RBR_CFIG_B_VLD0_MASK		0x0000000000000008ULL
#define	RBR_CFIG_B_BUFSZ1_SHIFT		8			/* bit 9:8 */
#define	RBR_CFIG_B_BUFSZ1_MASK		0x0000000000000300ULL
#define	RBR_CFIG_B_VLD1_SHIFT		15			/* bit 15 */
#define	RBR_CFIG_B_VLD1			0x0000000000008000ULL
#define	RBR_CFIG_B_VLD1_MASK		0x0000000000008000ULL
#define	RBR_CFIG_B_BUFSZ2_SHIFT		16			/* bit 17:16 */
#define	RBR_CFIG_B_BUFSZ2_MASK		0x0000000000030000ULL
#define	RBR_CFIG_B_VLD2_SHIFT		23			/* bit 23 */
#define	RBR_CFIG_B_VLD2			0x0000000000800000ULL
#define	RBR_CFIG_B_BKSIZE_SHIFT		24			/* bit 25:24 */
#define	RBR_CFIG_B_BKSIZE_MASK		0x0000000003000000ULL


typedef union _rbr_cfig_b_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:6;
			uint32_t bksize:2;
			uint32_t vld2:1;
			uint32_t res2:5;
			uint32_t bufsz2:2;
			uint32_t vld1:1;
			uint32_t res3:5;
			uint32_t bufsz1:2;
			uint32_t vld0:1;
			uint32_t res4:5;
			uint32_t bufsz0:2;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t bufsz0:2;
			uint32_t res4:5;
			uint32_t vld0:1;
			uint32_t bufsz1:2;
			uint32_t res3:5;
			uint32_t vld1:1;
			uint32_t bufsz2:2;
			uint32_t res2:5;
			uint32_t vld2:1;
			uint32_t bksize:2;
			uint32_t res1_1:6;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rbr_cfig_b_t, *p_rbr_cfig_b_t;


#define	RBR_KICK_SHIFT			0			/* bit 15:0 */
#define	RBR_KICK_MASK			0x00000000000ffff1ULL


typedef union _rbr_kick_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:16;
			uint32_t bkadd:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t bkadd:16;
			uint32_t res1_1:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rbr_kick_t, *p_rbr_kick_t;

#define	RBR_STAT_QLEN_SHIFT		0		/* bit bit 15:0 */
#define	RBR_STAT_QLEN_MASK		0x000000000000ffffULL
#define	RBR_STAT_OFLOW_SHIFT		16		/* bit 16 */
#define	RBR_STAT_OFLOW			0x0000000000010000ULL
#define	RBR_STAT_OFLOW_MASK		0x0000000000010000ULL

typedef union _rbr_stat_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:15;
			uint32_t oflow:1;
			uint32_t qlen:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t qlen:16;
			uint32_t oflow:1;
			uint32_t res1_1:15;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rbr_stat_t, *p_rbr_stat_t;


#define	RBR_HDH_HEAD_H_SHIFT		0			/* bit 11:0 */
#define	RBR_HDH_HEAD_H_MASK		0x0000000000000fffULL
typedef union _rbr_hdh_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:20;
			uint32_t head_h:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t head_h:12;
			uint32_t res1_1:20;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rbr_hdh_t, *p_rbr_hdh_t;

#define	RBR_HDL_HEAD_L_SHIFT		2			/* bit 31:2 */
#define	RBR_HDL_HEAD_L_MASK		0x00000000FFFFFFFCULL

typedef union _rbr_hdl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t head_l:30;
			uint32_t res2:2;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:2;
			uint32_t head_l:30;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rbr_hdl_t, *p_rbr_hdl_t;

/*
 * Receive Completion Ring (RCR)
 */
#define	RCR_PKT_BUF_ADDR_SHIFT		0			/* bit 37:0 */
#define	RCR_PKT_BUF_ADDR_SHIFT_FULL	6	/* fulll buffer address */
#define	RCR_PKT_BUF_ADDR_MASK		0x0000003FFFFFFFFFULL
#define	RCR_PKTBUFSZ_SHIFT		38			/* bit 39:38 */
#define	RCR_PKTBUFSZ_MASK		0x000000C000000000ULL
#define	RCR_L2_LEN_SHIFT		40			/* bit 39:38 */
#define	RCR_L2_LEN_MASK			0x003fff0000000000ULL
#define	RCR_DCF_ERROR_SHIFT		54			/* bit 54 */
#define	RCR_DCF_ERROR_MASK		0x0040000000000000ULL
#define	RCR_ERROR_SHIFT			55			/* bit 57:55 */
#define	RCR_ERROR_MASK			0x0380000000000000ULL
#define	RCR_PROMIS_SHIFT		58			/* bit 58 */
#define	RCR_PROMIS_MASK			0x0400000000000000ULL
#define	RCR_FRAG_SHIFT			59			/* bit 59 */
#define	RCR_FRAG_MASK			0x0800000000000000ULL
#define	RCR_ZERO_COPY_SHIFT		60			/* bit 60 */
#define	RCR_ZERO_COPY_MASK		0x1000000000000000ULL
#define	RCR_PKT_TYPE_SHIFT		61			/* bit 62:61 */
#define	RCR_PKT_TYPE_MASK		0x6000000000000000ULL
#define	RCR_MULTI_SHIFT			63			/* bit 63 */
#define	RCR_MULTI_MASK			0x8000000000000000ULL

#define	RCR_PKTBUFSZ_0			0x00
#define	RCR_PKTBUFSZ_1			0x01
#define	RCR_PKTBUFSZ_2			0x02
#define	RCR_SINGLE_BLOCK		0x03
#define	RCR_N_PKTBUF_SZ			0x04

#define	RCR_NO_ERROR			0x0
#define	RCR_L2_ERROR			0x1
#define	RCR_L4_CSUM_ERROR		0x3
#define	RCR_FFLP_SOFT_ERROR		0x4
#define	RCR_ZCP_SOFT_ERROR		0x5
#define	RCR_ERROR_RESERVE		0x6
#define	RCR_ERROR_RESERVE_END	0x7

#define	RCR_PKT_TYPE_UDP		0x1
#define	RCR_PKT_TYPE_TCP		0x2
#define	RCR_PKT_TYPE_SCTP		0x3
#define	RCR_PKT_TYPE_OTHERS		0x0
#define	RCR_PKT_IS_TCP			0x2000000000000000ULL
#define	RCR_PKT_IS_UDP			0x4000000000000000ULL
#define	RCR_PKT_IS_SCTP			0x6000000000000000ULL


typedef union _rcr_entry_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t multi:1;
			uint32_t pkt_type:2;
			uint32_t zero_copy:1;
			uint32_t noport:1;
			uint32_t promis:1;
			uint32_t error:3;
			uint32_t dcf_err:1;
			uint32_t l2_len:14;
			uint32_t pktbufsz:2;
			uint32_t pkt_buf_addr:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkt_buf_addr:6;
			uint32_t pktbufsz:2;
			uint32_t l2_len:14;
			uint32_t dcf_err:1;
			uint32_t error:3;
			uint32_t promis:1;
			uint32_t noport:1;
			uint32_t zero_copy:1;
			uint32_t pkt_type:2;
			uint32_t multi:1;
#endif
		} hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t pkt_buf_addr:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkt_buf_addr:32;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t multi:1;
			uint32_t pkt_type:2;
			uint32_t zero_copy:1;
			uint32_t noport:1;
			uint32_t promis:1;
			uint32_t error:3;
			uint32_t dcf_err:1;
			uint32_t l2_len:14;
			uint32_t pktbufsz:2;
			uint32_t pkt_buf_addr:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkt_buf_addr:6;
			uint32_t pktbufsz:2;
			uint32_t l2_len:14;
			uint32_t dcf_err:1;
			uint32_t error:3;
			uint32_t promis:1;
			uint32_t noport:1;
			uint32_t zero_copy:1;
			uint32_t pkt_type:2;
			uint32_t multi:1;
#endif
		} hdw;
#endif
	} bits;
} rcr_entry_t, *p_rcr_entry_t;

/*
 * Receive Completion Ring Configuration.
 * (for each DMA channel)
 */
#define	RCRCFIG_A_REG			(DMC + 0x00040)
#define	RCRCFIG_B_REG			(DMC + 0x00048)
#define	RCRSTAT_A_REG			(DMC + 0x00050)
#define	RCRSTAT_B_REG			(DMC + 0x00058)
#define	RCRSTAT_C_REG			(DMC + 0x00060)
#define	RX_DMA_ENT_MSK_REG		(DMC + 0x00068)
#define	RX_DMA_CTL_STAT_REG		(DMC + 0x00070)
#define	RCR_FLSH_REG			(DMC + 0x00078)
#if OLD
#define	RX_DMA_LOGA_REG			(DMC + 0x00080)
#define	RX_DMA_LOGB_REG			(DMC + 0x00088)
#endif
#define	RX_DMA_CTL_STAT_DBG_REG		(DMC + 0x00098)

/* (DMC + 0x00050) */
#define	RCRCFIG_A_STADDR_SHIFT		6	/* bit 18:6 */
#define	RCRCFIG_A_STADDR_MASK		0x000000000007FFC0ULL
#define	RCRCFIG_A_STADDR_BASE_SHIF	19	/* bit 43:19 */
#define	RCRCFIG_A_STADDR_BASE_MASK	0x00000FFFFFF80000ULL
#define	RCRCFIG_A_LEN_SHIF		48	/* bit 63:48 */
#define	RCRCFIG_A_LEN__MASK		0xFFFF000000000000ULL

/* (DMC + 0x00058) */
#define	RCRCFIG_B_TIMEOUT_SHIFT		0		/* bit 5:0 */
#define	RCRCFIG_B_TIMEOUT_MASK		0x000000000000003FULL
#define	RCRCFIG_B_ENTOUT_SHIFT		15		/* bit  15 */
#define	RCRCFIG_B_TIMEOUT		0x0000000000008000ULL
#define	RCRCFIG_B_PTHRES_SHIFT		16		/* bit 31:16 */
#define	RCRCFIG_B_PTHRES_MASK		0x00000000FFFF0000ULL

/* (DMC + 0x00060) */
#define	RCRSTAT_A_QLEN_SHIFT		0		/* bit 15:0 */
#define	RCRSTAT_A_QLEN_MASK		0x000000000000FFFFULL
#define	RCRSTAT_A_PKT_OFL_SHIFT		16		/* bit 16 */
#define	RCRSTAT_A_PKT_OFL_MASK		0x0000000000010000ULL
#define	RCRSTAT_A_ENT_OFL_SHIFT		17		/* bit 17 */
#define	RCRSTAT_A_ENT_QFL_MASK		0x0000000000020000ULL

#define	RCRSTAT_C_TLPTR_H_SHIFT		0		/* bit 11:0 */
#define	RCRSTAT_C_TLPTR_H_MASK		0x0000000000000FFFULL

#define	RCRSTAT_D_TLPTR_L_SHIFT		3		/* bit 31:3 */
#define	RCRSTAT_D_TLPTR_L_MASK		0x00000000FFFFFFF8ULL

/* Receive DMA Interrupt Behavior: Event Mask  (DMC + 0x00068) */
#define	RX_DMA_ENT_MSK_CFIGLOGPGE_SHIFT	0		/* bit 0: 0 to flag */
#define	RX_DMA_ENT_MSK_CFIGLOGPGE_MASK	0x0000000000000001ULL
#define	RX_DMA_ENT_MSK_RBRLOGPGE_SHIFT	1		/* bit 1: 0 to flag */
#define	RX_DMA_ENT_MSK_RBRLOGPGE_MASK	0x0000000000000002ULL
#define	RX_DMA_ENT_MSK_RBRFULL_SHIFT	2		/* bit 2: 0 to flag */
#define	RX_DMA_ENT_MSK_RBRFULL_MASK	0x0000000000000004ULL
#define	RX_DMA_ENT_MSK_RBREMPTY_SHIFT	3		/* bit 3: 0 to flag */
#define	RX_DMA_ENT_MSK_RBREMPTY_MASK	0x0000000000000008ULL
#define	RX_DMA_ENT_MSK_RCRFULL_SHIFT	4		/* bit 4: 0 to flag */
#define	RX_DMA_ENT_MSK_RCRFULL_MASK	0x0000000000000010ULL
#define	RX_DMA_ENT_MSK_RCRINCON_SHIFT	5		/* bit 5: 0 to flag */
#define	RX_DMA_ENT_MSK_RCRINCON_MASK	0x0000000000000020ULL
#define	RX_DMA_ENT_MSK_CONFIG_ERR_SHIFT	6		/* bit 6: 0 to flag */
#define	RX_DMA_ENT_MSK_CONFIG_ERR_MASK	0x0000000000000040ULL
#define	RX_DMA_ENT_MSK_RCRSH_FULL_SHIFT	7		/* bit 7: 0 to flag */
#define	RX_DMA_ENT_MSK_RCRSH_FULL_MASK	0x0000000000000080ULL
#define	RX_DMA_ENT_MSK_RBR_PRE_EMPTY_SHIFT	8	/* bit 8: 0 to flag */
#define	RX_DMA_ENT_MSK_RBR_PRE_EMPTY_MASK	0x0000000000000100ULL
#define	RX_DMA_ENT_MSK_WRED_DROP_SHIFT	9		/* bit 9: 0 to flag */
#define	RX_DMA_ENT_MSK_WRED_DROP_MASK	0x0000000000000200ULL
#define	RX_DMA_ENT_MSK_PTDROP_PKT_SHIFT	10		/* bit 10: 0 to flag */
#define	RX_DMA_ENT_MSK_PTDROP_PKT_MASK	0x0000000000000400ULL
#define	RX_DMA_ENT_MSK_RBR_PRE_PAR_SHIFT	11	/* bit 11: 0 to flag */
#define	RX_DMA_ENT_MSK_RBR_PRE_PAR_MASK	0x0000000000000800ULL
#define	RX_DMA_ENT_MSK_RCR_SHA_PAR_SHIFT	12	/* bit 12: 0 to flag */
#define	RX_DMA_ENT_MSK_RCR_SHA_PAR_MASK	0x0000000000001000ULL
#define	RX_DMA_ENT_MSK_RCRTO_SHIFT	13		/* bit 13: 0 to flag */
#define	RX_DMA_ENT_MSK_RCRTO_MASK	0x0000000000002000ULL
#define	RX_DMA_ENT_MSK_THRES_SHIFT	14		/* bit 14: 0 to flag */
#define	RX_DMA_ENT_MSK_THRES_MASK	0x0000000000004000ULL
#define	RX_DMA_ENT_MSK_DC_FIFO_ERR_SHIFT	16	/* bit 16: 0 to flag */
#define	RX_DMA_ENT_MSK_DC_FIFO_ERR_MASK	0x0000000000010000ULL
#define	RX_DMA_ENT_MSK_RCR_ACK_ERR_SHIFT	17	/* bit 17: 0 to flag */
#define	RX_DMA_ENT_MSK_RCR_ACK_ERR_MASK	0x0000000000020000ULL
#define	RX_DMA_ENT_MSK_RSP_DAT_ERR_SHIFT	18	/* bit 18: 0 to flag */
#define	RX_DMA_ENT_MSK_RSP_DAT_ERR_MASK	0x0000000000040000ULL
#define	RX_DMA_ENT_MSK_BYTE_EN_BUS_SHIFT	19	/* bit 19: 0 to flag */
#define	RX_DMA_ENT_MSK_BYTE_EN_BUS_MASK	0x0000000000080000ULL
#define	RX_DMA_ENT_MSK_RSP_CNT_ERR_SHIFT	20	/* bit 20: 0 to flag */
#define	RX_DMA_ENT_MSK_RSP_CNT_ERR_MASK	0x0000000000100000ULL
#define	RX_DMA_ENT_MSK_RBR_TMOUT_SHIFT	21		/* bit 21: 0 to flag */
#define	RX_DMA_ENT_MSK_RBR_TMOUT_MASK	0x0000000000200000ULL
#define	RX_DMA_ENT_MSK_ALL	(RX_DMA_ENT_MSK_CFIGLOGPGE_MASK |	\
				RX_DMA_ENT_MSK_RBRLOGPGE_MASK |	\
				RX_DMA_ENT_MSK_RBRFULL_MASK |		\
				RX_DMA_ENT_MSK_RBREMPTY_MASK |		\
				RX_DMA_ENT_MSK_RCRFULL_MASK |		\
				RX_DMA_ENT_MSK_RCRINCON_MASK |		\
				RX_DMA_ENT_MSK_CONFIG_ERR_MASK |	\
				RX_DMA_ENT_MSK_RCRSH_FULL_MASK |	\
				RX_DMA_ENT_MSK_RBR_PRE_EMPTY_MASK |	\
				RX_DMA_ENT_MSK_WRED_DROP_MASK |	\
				RX_DMA_ENT_MSK_PTDROP_PKT_MASK |	\
				RX_DMA_ENT_MSK_PTDROP_PKT_MASK |	\
				RX_DMA_ENT_MSK_RBR_PRE_PAR_MASK |	\
				RX_DMA_ENT_MSK_RCR_SHA_PAR_MASK |	\
				RX_DMA_ENT_MSK_RCRTO_MASK |		\
				RX_DMA_ENT_MSK_THRES_MASK |		\
				RX_DMA_ENT_MSK_DC_FIFO_ERR_MASK |	\
				RX_DMA_ENT_MSK_RCR_ACK_ERR_MASK |	\
				RX_DMA_ENT_MSK_RSP_DAT_ERR_MASK |	\
				RX_DMA_ENT_MSK_BYTE_EN_BUS_MASK |	\
				RX_DMA_ENT_MSK_RSP_CNT_ERR_MASK |	\
				RX_DMA_ENT_MSK_RBR_TMOUT_MASK)

/* Receive DMA Control and Status  (DMC + 0x00070) */
#define	RX_DMA_CTL_STAT_PKTREAD_SHIFT	0	/* WO, bit 15:0 */
#define	RX_DMA_CTL_STAT_PKTREAD_MASK	0x000000000000ffffULL
#define	RX_DMA_CTL_STAT_PTRREAD_SHIFT	16	/* WO, bit 31:16 */
#define	RX_DMA_CTL_STAT_PTRREAD_MASK	0x00000000FFFF0000ULL
#define	RX_DMA_CTL_STAT_CFIGLOGPG_SHIFT 32	/* RO, bit 32 */
#define	RX_DMA_CTL_STAT_CFIGLOGPG	0x0000000100000000ULL
#define	RX_DMA_CTL_STAT_CFIGLOGPG_MASK	0x0000000100000000ULL
#define	RX_DMA_CTL_STAT_RBRLOGPG_SHIFT	33	/* RO, bit 33 */
#define	RX_DMA_CTL_STAT_RBRLOGPG	0x0000000200000000ULL
#define	RX_DMA_CTL_STAT_RBRLOGPG_MASK	0x0000000200000000ULL
#define	RX_DMA_CTL_STAT_RBRFULL_SHIFT	34	/* RO, bit 34 */
#define	RX_DMA_CTL_STAT_RBRFULL		0x0000000400000000ULL
#define	RX_DMA_CTL_STAT_RBRFULL_MASK	0x0000000400000000ULL
#define	RX_DMA_CTL_STAT_RBREMPTY_SHIFT	35	/* RW1C, bit 35 */
#define	RX_DMA_CTL_STAT_RBREMPTY	0x0000000800000000ULL
#define	RX_DMA_CTL_STAT_RBREMPTY_MASK	0x0000000800000000ULL
#define	RX_DMA_CTL_STAT_RCRFULL_SHIFT	36	/* RW1C, bit 36 */
#define	RX_DMA_CTL_STAT_RCRFULL		0x0000001000000000ULL
#define	RX_DMA_CTL_STAT_RCRFULL_MASK	0x0000001000000000ULL
#define	RX_DMA_CTL_STAT_RCRINCON_SHIFT	37	/* RO, bit 37 */
#define	RX_DMA_CTL_STAT_RCRINCON	0x0000002000000000ULL
#define	RX_DMA_CTL_STAT_RCRINCON_MASK	0x0000002000000000ULL
#define	RX_DMA_CTL_STAT_CONFIG_ERR_SHIFT 38	/* RO, bit 38 */
#define	RX_DMA_CTL_STAT_CONFIG_ERR	0x0000004000000000ULL
#define	RX_DMA_CTL_STAT_CONFIG_ERR_MASK	0x0000004000000000ULL
#define	RX_DMA_CTL_STAT_RCR_SHDW_FULL_SHIFT 39	/* RO, bit 39 */
#define	RX_DMA_CTL_STAT_RCR_SHDW_FULL 0x0000008000000000ULL
#define	RX_DMA_CTL_STAT_RCR_SHDW_FULL_MASK 0x0000008000000000ULL
#define	RX_DMA_CTL_STAT_RBR_PRE_EMTY_MASK  0x0000010000000000ULL
#define	RX_DMA_CTL_STAT_RBR_PRE_EMTY_SHIFT 40	/* RO, bit 40 */
#define	RX_DMA_CTL_STAT_RBR_PRE_EMTY 0x0000010000000000ULL
#define	RX_DMA_CTL_STAT_RBR_PRE_EMTY_MASK  0x0000010000000000ULL
#define	RX_DMA_CTL_STAT_WRED_DROP_SHIFT 41	/* RO, bit 41 */
#define	RX_DMA_CTL_STAT_WRED_DROP 0x0000020000000000ULL
#define	RX_DMA_CTL_STAT_WRED_DROP_MASK  0x0000020000000000ULL
#define	RX_DMA_CTL_STAT_PORT_DROP_PKT_SHIFT 42	/* RO, bit 42 */
#define	RX_DMA_CTL_STAT_PORT_DROP_PKT 0x0000040000000000ULL
#define	RX_DMA_CTL_STAT_PORT_DROP_PKT_MASK  0x0000040000000000ULL
#define	RX_DMA_CTL_STAT_RBR_PRE_PAR_SHIFT 43	/* RO, bit 43 */
#define	RX_DMA_CTL_STAT_RBR_PRE_PAR 0x0000080000000000ULL
#define	RX_DMA_CTL_STAT_RBR_PRE_PAR_MASK  0x0000080000000000ULL
#define	RX_DMA_CTL_STAT_RCR_SHA_PAR_SHIFT 44	/* RO, bit 44 */
#define	RX_DMA_CTL_STAT_RCR_SHA_PAR 0x0000100000000000ULL
#define	RX_DMA_CTL_STAT_RCR_SHA_PAR_MASK  0x0000100000000000ULL
#define	RX_DMA_CTL_STAT_RCRTO_SHIFT	45	/* RW1C, bit 45 */
#define	RX_DMA_CTL_STAT_RCRTO		0x0000200000000000ULL
#define	RX_DMA_CTL_STAT_RCRTO_MASK	0x0000200000000000ULL
#define	RX_DMA_CTL_STAT_RCRTHRES_SHIFT	46	/* RO, bit 46 */
#define	RX_DMA_CTL_STAT_RCRTHRES	0x0000400000000000ULL
#define	RX_DMA_CTL_STAT_RCRTHRES_MASK	0x0000400000000000ULL
#define	RX_DMA_CTL_STAT_MEX_SHIFT	47	/* RW, bit 47 */
#define	RX_DMA_CTL_STAT_MEX		0x0000800000000000ULL
#define	RX_DMA_CTL_STAT_MEX_MASK	0x0000800000000000ULL
#define	RX_DMA_CTL_STAT_DC_FIFO_ERR_SHIFT	48	/* RW1C, bit 48 */
#define	RX_DMA_CTL_STAT_DC_FIFO_ERR		0x0001000000000000ULL
#define	RX_DMA_CTL_STAT_DC_FIFO_ERR_MASK	0x0001000000000000ULL
#define	RX_DMA_CTL_STAT_RCR_ACK_ERR_SHIFT	49	/* RO, bit 49 */
#define	RX_DMA_CTL_STAT_RCR_ACK_ERR		0x0002000000000000ULL
#define	RX_DMA_CTL_STAT_RCR_ACK_ERR_MASK	0x0002000000000000ULL
#define	RX_DMA_CTL_STAT_RSP_DAT_ERR_SHIFT	50	/* RO, bit 50 */
#define	RX_DMA_CTL_STAT_RSP_DAT_ERR		0x0004000000000000ULL
#define	RX_DMA_CTL_STAT_RSP_DAT_ERR_MASK	0x0004000000000000ULL

#define	RX_DMA_CTL_STAT_BYTE_EN_BUS_SHIFT	51	/* RO, bit 51 */
#define	RX_DMA_CTL_STAT_BYTE_EN_BUS		0x0008000000000000ULL
#define	RX_DMA_CTL_STAT_BYTE_EN_BUS_MASK	0x0008000000000000ULL

#define	RX_DMA_CTL_STAT_RSP_CNT_ERR_SHIFT	52	/* RO, bit 52 */
#define	RX_DMA_CTL_STAT_RSP_CNT_ERR		0x0010000000000000ULL
#define	RX_DMA_CTL_STAT_RSP_CNT_ERR_MASK	0x0010000000000000ULL

#define	RX_DMA_CTL_STAT_RBR_TMOUT_SHIFT	53	/* RO, bit 53 */
#define	RX_DMA_CTL_STAT_RBR_TMOUT		0x0020000000000000ULL
#define	RX_DMA_CTL_STAT_RBR_TMOUT_MASK	0x0020000000000000ULL
#define	RX_DMA_CTRL_STAT_ENT_MASK_SHIFT 32
#define	RX_DMA_CTL_STAT_ERROR 			(RX_DMA_ENT_MSK_ALL << \
						RX_DMA_CTRL_STAT_ENT_MASK_SHIFT)

/* the following are write 1 to clear bits */
#define	RX_DMA_CTL_STAT_WR1C	RX_DMA_CTL_STAT_RBREMPTY | \
				RX_DMA_CTL_STAT_RCR_SHDW_FULL | \
				RX_DMA_CTL_STAT_RBR_PRE_EMTY | \
				RX_DMA_CTL_STAT_WRED_DROP | \
				RX_DMA_CTL_STAT_PORT_DROP_PKT | \
				RX_DMA_CTL_STAT_RCRTO | \
				RX_DMA_CTL_STAT_RCRTHRES | \
				RX_DMA_CTL_STAT_DC_FIFO_ERR

/* Receive DMA Interrupt Behavior: Force an update to RCR  (DMC + 0x00078 */
#define	RCR_FLSH_SHIFT			0	/* RW, bit 0:0 */
#define	RCR_FLSH_SET			0x0000000000000001ULL
#define	RCR_FLSH_MASK			0x0000000000000001ULL

/* Receive DMA Interrupt Behavior: the first error log  (DMC + 0x00080 */
#define	RX_DMA_LOGA_ADDR_SHIFT		0	/* RO, bit 11:0 */
#define	RX_DMA_LOGA_ADDR		0x0000000000000FFFULL
#define	RX_DMA_LOGA_ADDR_MASK		0x0000000000000FFFULL
#define	RX_DMA_LOGA_TYPE_SHIFT		28	/* RO, bit 30:28 */
#define	RX_DMA_LOGA_TYPE		0x0000000070000000ULL
#define	RX_DMA_LOGA_TYPE_MASK		0x0000000070000FFFULL
#define	RX_DMA_LOGA_MULTI_SHIFT		28	/* RO, bit 30:28 */
#define	RX_DMA_LOGA_MULTI		0x0000000080000000ULL
#define	RX_DMA_LOGA_MULTI_MASK		0x0000000080000FFFULL

/* Receive DMA Interrupt Behavior: the first error log  (DMC + 0x00088 */
#define	RX_DMA_LOGA_ADDR_L_SHIFT	0	/* RO, bit 31:0 */
#define	RX_DMA_LOGA_ADDRL_L		0x00000000FFFFFFFFULL
#define	RX_DMA_LOGA_ADDR_LMASK		0x00000000FFFFFFFFULL

typedef union _rcrcfig_a_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t len:16;
			uint32_t res1:4;
			uint32_t staddr_base:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t staddr_base:12;
			uint32_t res1:4;
			uint32_t len:16;
#endif
		} hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t staddr_base:13;
			uint32_t staddr:13;
			uint32_t res2:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:6;
			uint32_t staddr:13;
			uint32_t staddr_base:13;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t len:16;
			uint32_t res1:4;
			uint32_t staddr_base:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t staddr_base:12;
			uint32_t res1:4;
			uint32_t len:16;
#endif
		} hdw;
#endif
	} bits;
} rcrcfig_a_t, *p_rcrcfig_a_t;


typedef union _rcrcfig_b_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t pthres:16;
			uint32_t entout:1;
			uint32_t res1:9;
			uint32_t timeout:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t timeout:6;
			uint32_t res1:9;
			uint32_t entout:1;
			uint32_t pthres:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rcrcfig_b_t, *p_rcrcfig_b_t;


typedef union _rcrstat_a_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1:16;
			uint32_t qlen:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t qlen:16;
			uint32_t res1:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rcrstat_a_t, *p_rcrstat_a_t;


typedef union _rcrstat_b_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1:20;
			uint32_t tlptr_h:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t tlptr_h:12;
			uint32_t res1:20;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rcrstat_b_t, *p_rcrstat_b_t;


typedef union _rcrstat_c_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t tlptr_l:29;
			uint32_t res1:3;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res1:3;
			uint32_t tlptr_l:29;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rcrstat_c_t, *p_rcrstat_c_t;


/* Receive DMA Event Mask */
typedef union _rx_dma_ent_msk_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsrvd2:10;
			uint32_t rbr_tmout:1;
			uint32_t rsp_cnt_err:1;
			uint32_t byte_en_bus:1;
			uint32_t rsp_dat_err:1;
			uint32_t rcr_ack_err:1;
			uint32_t dc_fifo_err:1;
			uint32_t rsrvd:1;
			uint32_t rcrthres:1;
			uint32_t rcrto:1;
			uint32_t rcr_sha_par:1;
			uint32_t rbr_pre_par:1;
			uint32_t port_drop_pkt:1;
			uint32_t wred_drop:1;
			uint32_t rbr_pre_empty:1;
			uint32_t rcr_shadow_full:1;
			uint32_t config_err:1;
			uint32_t rcrincon:1;
			uint32_t rcrfull:1;
			uint32_t rbr_empty:1;
			uint32_t rbrfull:1;
			uint32_t rbrlogpage:1;
			uint32_t cfiglogpage:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cfiglogpage:1;
			uint32_t rbrlogpage:1;
			uint32_t rbrfull:1;
			uint32_t rbr_empty:1;
			uint32_t rcrfull:1;
			uint32_t rcrincon:1;
			uint32_t config_err:1;
			uint32_t rcr_shadow_full:1;
			uint32_t rbr_pre_empty:1;
			uint32_t wred_drop:1;
			uint32_t port_drop_pkt:1;
			uint32_t rbr_pre_par:1;
			uint32_t rcr_sha_par:1;
			uint32_t rcrto:1;
			uint32_t rcrthres:1;
			uint32_t rsrvd:1;
			uint32_t dc_fifo_err:1;
			uint32_t rcr_ack_err:1;
			uint32_t rsp_dat_err:1;
			uint32_t byte_en_bus:1;
			uint32_t rsp_cnt_err:1;
			uint32_t rbr_tmout:1;
			uint32_t rsrvd2:10;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_dma_ent_msk_t, *p_rx_dma_ent_msk_t;


/* Receive DMA Control and Status */
typedef union _rx_dma_ctl_stat_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsrvd:10;
			uint32_t rbr_tmout:1;
			uint32_t rsp_cnt_err:1;
			uint32_t byte_en_bus:1;
			uint32_t rsp_dat_err:1;
			uint32_t rcr_ack_err:1;
			uint32_t dc_fifo_err:1;
			uint32_t mex:1;
			uint32_t rcrthres:1;
			uint32_t rcrto:1;
			uint32_t rcr_sha_par:1;
			uint32_t rbr_pre_par:1;
			uint32_t port_drop_pkt:1;
			uint32_t wred_drop:1;
			uint32_t rbr_pre_empty:1;
			uint32_t rcr_shadow_full:1;
			uint32_t config_err:1;
			uint32_t rcrincon:1;
			uint32_t rcrfull:1;
			uint32_t rbr_empty:1;
			uint32_t rbrfull:1;
			uint32_t rbrlogpage:1;
			uint32_t cfiglogpage:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cfiglogpage:1;
			uint32_t rbrlogpage:1;
			uint32_t rbrfull:1;
			uint32_t rbr_empty:1;
			uint32_t rcrfull:1;
			uint32_t rcrincon:1;
			uint32_t config_err:1;
			uint32_t rcr_shadow_full:1;
			uint32_t rbr_pre_empty:1;
			uint32_t wred_drop:1;
			uint32_t port_drop_pkt:1;
			uint32_t rbr_pre_par:1;
			uint32_t rcr_sha_par:1;
			uint32_t rcrto:1;
			uint32_t rcrthres:1;
			uint32_t mex:1;
			uint32_t dc_fifo_err:1;
			uint32_t rcr_ack_err:1;
			uint32_t rsp_dat_err:1;
			uint32_t byte_en_bus:1;
			uint32_t rsp_cnt_err:1;
			uint32_t rbr_tmout:1;
			uint32_t rsrvd:10;
#endif
		} hdw;

#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ptrread:16;
			uint32_t pktread:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pktread:16;
			uint32_t ptrread:16;

#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsrvd:10;
			uint32_t rbr_tmout:1;
			uint32_t rsp_cnt_err:1;
			uint32_t byte_en_bus:1;
			uint32_t rsp_dat_err:1;
			uint32_t rcr_ack_err:1;
			uint32_t dc_fifo_err:1;
			uint32_t mex:1;
			uint32_t rcrthres:1;
			uint32_t rcrto:1;
			uint32_t rcr_sha_par:1;
			uint32_t rbr_pre_par:1;
			uint32_t port_drop_pkt:1;
			uint32_t wred_drop:1;
			uint32_t rbr_pre_empty:1;
			uint32_t rcr_shadow_full:1;
			uint32_t config_err:1;
			uint32_t rcrincon:1;
			uint32_t rcrfull:1;
			uint32_t rbr_empty:1;
			uint32_t rbrfull:1;
			uint32_t rbrlogpage:1;
			uint32_t cfiglogpage:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cfiglogpage:1;
			uint32_t rbrlogpage:1;
			uint32_t rbrfull:1;
			uint32_t rbr_empty:1;
			uint32_t rcrfull:1;
			uint32_t rcrincon:1;
			uint32_t config_err:1;
			uint32_t rcr_shadow_full:1;
			uint32_t rbr_pre_empty:1;
			uint32_t wred_drop:1;
			uint32_t port_drop_pkt:1;
			uint32_t rbr_pre_par:1;
			uint32_t rcr_sha_par:1;
			uint32_t rcrto:1;
			uint32_t rcrthres:1;
			uint32_t mex:1;
			uint32_t dc_fifo_err:1;
			uint32_t rcr_ack_err:1;
			uint32_t rsp_dat_err:1;
			uint32_t byte_en_bus:1;
			uint32_t rsp_cnt_err:1;
			uint32_t rbr_tmout:1;
			uint32_t rsrvd:10;
#endif
		} hdw;
#endif
	} bits;
} rx_dma_ctl_stat_t, *p_rx_dma_ctl_stat_t;

typedef union _rcr_flsh_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:31;
			uint32_t flsh:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t flsh:1;
			uint32_t res1_1:31;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rcr_flsh_t, *p_rcr_flsh_t;


typedef union _rx_dma_loga_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t multi:1;
			uint32_t type:3;
			uint32_t res1:16;
			uint32_t addr:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t addr:12;
			uint32_t res1:16;
			uint32_t type:3;
			uint32_t multi:1;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_dma_loga_t, *p_rx_dma_loga_t;


typedef union _rx_dma_logb_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t addr_l:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t addr_l:32;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_dma_logb_t, *p_rx_dma_logb_t;


#define	RX_DMA_MAILBOX_BYTE_LENGTH	64
#define	RX_DMA_MBOX_UNUSED_1		8
#define	RX_DMA_MBOX_UNUSED_2		16

typedef struct _rxdma_mailbox_t {
	rx_dma_ctl_stat_t	rxdma_ctl_stat;		/* 8 bytes */
	rbr_stat_t		rbr_stat;		/* 8 bytes */
	uint32_t		rbr_hdl;		/* 4 bytes (31:0) */
	uint32_t		rbr_hdh;		/* 4 bytes (31:0) */
	uint32_t		resv_1[RX_DMA_MBOX_UNUSED_1];
	uint32_t		rcrstat_c;		/* 4 bytes (31:0) */
	uint32_t		rcrstat_b;		/* 4 bytes (31:0) */
	rcrstat_a_t		rcrstat_a;		/* 8 bytes */
	uint32_t		resv_2[RX_DMA_MBOX_UNUSED_2];
} rxdma_mailbox_t, *p_rxdma_mailbox_t;



typedef union _rx_disc_cnt_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res_1:15;
			uint32_t oflow:1;
			uint32_t count:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t count:16;
			uint32_t oflow:1;
			uint32_t res_1:15;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_disc_cnt_t, *p_rx_disc_cnt_t;

#define	RXMISC_DISCARD_REG		(DMC + 0x00090)

#if OLD
/*
 * RBR Empty: If the RBR is empty or the prefetch buffer is empty,
 * packets will be discarded (Each RBR has one).
 * (16 channels, 0x200)
 */
#define	RDC_PRE_EMPTY_REG		(DMC + 0x000B0)
#define	RDC_PRE_EMPTY_OFFSET(channel)	(RDC_PRE_EMPTY_REG + \
						(DMC_OFFSET(channel))

typedef union _rdc_pre_empty_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res_1:15;
			uint32_t oflow:1;
			uint32_t count:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t count:16;
			uint32_t oflow:1;
			uint32_t res_1:15;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rdc_pre_empty_t, *p_rdc_pre_empty_t;
#endif


#define	FZC_DMC_REG_SIZE		0x20
#define	FZC_DMC_OFFSET(channel)		(FZC_DMC_REG_SIZE * channel)

/* WRED discard count register (16, 0x40) */
#define	RED_DIS_CNT_REG			(FZC_DMC + 0x30008)
#define	RED_DMC_OFFSET(channel)		(0x40 * channel)
#define	RDC_DIS_CNT_OFFSET(rdc)	(RED_DIS_CNT_REG + RED_DMC_OFFSET(rdc))

typedef union _red_disc_cnt_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res_1:15;
			uint32_t oflow:1;
			uint32_t count:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t count:16;
			uint32_t oflow:1;
			uint32_t res_1:15;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} red_disc_cnt_t, *p_red_disc_cnt_t;


#define	RDMC_PRE_PAR_ERR_REG			(FZC_DMC + 0x00078)
#define	RDMC_SHA_PAR_ERR_REG			(FZC_DMC + 0x00080)

typedef union _rdmc_par_err_log {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res_1:16;
			uint32_t err:1;
			uint32_t merr:1;
			uint32_t res:6;
			uint32_t addr:8;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t addr:8;
			uint32_t res:6;
			uint32_t merr:1;
			uint32_t err:1;
			uint32_t res_1:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rdmc_par_err_log_t, *p_rdmc_par_err_log_t;


/* Used for accessing RDMC Memory */
#define	RDMC_MEM_ADDR_REG			(FZC_DMC + 0x00088)


typedef union _rdmc_mem_addr {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif

#define	RDMC_MEM_ADDR_PREFETCH 0
#define	RDMC_MEM_ADDR_SHADOW 1

		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res_1:23;
			uint32_t pre_shad:1;
			uint32_t addr:8;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t addr:8;
			uint32_t pre_shad:1;
			uint32_t res_1:23;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rdmc_mem_addr_t, *p_rdmc_mem_addr_t;


#define	RDMC_MEM_DATA0_REG			(FZC_DMC + 0x00090)
#define	RDMC_MEM_DATA1_REG			(FZC_DMC + 0x00098)
#define	RDMC_MEM_DATA2_REG			(FZC_DMC + 0x000A0)
#define	RDMC_MEM_DATA3_REG			(FZC_DMC + 0x000A8)
#define	RDMC_MEM_DATA4_REG			(FZC_DMC + 0x000B0)

typedef union _rdmc_mem_data {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif

		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t data;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t data;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rdmc_mem_data_t, *p_rdmc_mem_data_t;


typedef union _rdmc_mem_access {
#define	RDMC_MEM_READ 1
#define	RDMC_MEM_WRITE 2
	uint32_t data[5];
	uint8_t addr;
	uint8_t location;
} rdmc_mem_access_t, *p_rdmc_mem_access_t;


#define	RX_CTL_DAT_FIFO_STAT_REG			(FZC_DMC + 0x000B8)
#define	RX_CTL_DAT_FIFO_MASK_REG			(FZC_DMC + 0x000C0)
#define	RX_CTL_DAT_FIFO_STAT_DBG_REG		(FZC_DMC + 0x000D0)

typedef union _rx_ctl_dat_fifo {
#define	FIFO_EOP_PORT0 0x1
#define	FIFO_EOP_PORT1 0x2
#define	FIFO_EOP_PORT2 0x4
#define	FIFO_EOP_PORT3 0x8
#define	FIFO_EOP_ALL 0xF
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res_1:23;
			uint32_t id_mismatch:1;
			uint32_t zcp_eop_err:4;
			uint32_t ipp_eop_err:4;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ipp_eop_err:4;
			uint32_t zcp_eop_err:4;
			uint32_t id_mismatch:1;
			uint32_t res_1:23;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_ctl_dat_fifo_mask_t, rx_ctl_dat_fifo_stat_t,
	rx_ctl_dat_fifo_stat_dbg_t, *p_rx_ctl_dat_fifo_t;



#define	RDMC_TRAINING_VECTOR_REG		(FZC_DMC + 0x000C8)

typedef union _rx_training_vect {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
			uint32_t tv;
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} rx_training_vect_t, *p_rx_training_vect_t;

#define	RXCTL_IPP_EOP_ERR_MASK	0x0000000FULL
#define	RXCTL_IPP_EOP_ERR_SHIFT	0x0
#define	RXCTL_ZCP_EOP_ERR_MASK	0x000000F0ULL
#define	RXCTL_ZCP_EOP_ERR_SHIFT	0x4
#define	RXCTL_ID_MISMATCH_MASK	0x00000100ULL
#define	RXCTL_ID_MISMATCH_SHIFT	0x8


/*
 * Receive Packet Header Format
 * Packet header before the packet.
 * The minimum is 2 bytes and the max size is 18 bytes.
 */
/*
 * Packet header format 0 (2 bytes).
 */
typedef union _rx_pkt_hdr0_t {
	uint16_t value;
	struct {
#if	defined(_BIT_FIELDS_HTOL)
		uint16_t inputport:2;
		uint16_t maccheck:1;
		uint16_t class:5;
		uint16_t vlan:1;
		uint16_t llcsnap:1;
		uint16_t noport:1;
		uint16_t badip:1;
		uint16_t tcamhit:1;
		uint16_t tres:2;
		uint16_t tzfvld:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t tzfvld:1;
		uint16_t tres:2;
		uint16_t tcamhit:1;
		uint16_t badip:1;
		uint16_t noport:1;
		uint16_t llcsnap:1;
		uint16_t vlan:1;
		uint16_t class:5;
		uint16_t maccheck:1;
		uint16_t inputport:2;
#endif
	} bits;
} rx_pkt_hdr0_t, *p_rx_pkt_hdr0_t;


/*
 * Packet header format 1.
 */
typedef union _rx_pkt_hdr1_b0_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t hwrsvd:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t hwrsvd:8;
#endif
	} bits;
} rx_pkt_hdr1_b0_t, *p_rx_pkt_hdr1_b0_t;

typedef union _rx_pkt_hdr1_b1_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t tcammatch:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t tcammatch:8;
#endif
	} bits;
} rx_pkt_hdr1_b1_t, *p_rx_pkt_hdr1_b1_t;

typedef union _rx_pkt_hdr1_b2_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t resv:2;
		uint8_t hashhit:1;
		uint8_t exact:1;
		uint8_t hzfvld:1;
		uint8_t hashidx:3;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t hashidx:3;
		uint8_t hzfvld:1;
		uint8_t exact:1;
		uint8_t hashhit:1;
		uint8_t resv:2;
#endif
	} bits;
} rx_pkt_hdr1_b2_t, *p_rx_pkt_hdr1_b2_t;

typedef union _rx_pkt_hdr1_b3_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t zc_resv:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t zc_resv:8;
#endif
	} bits;
} rx_pkt_hdr1_b3_t, *p_rx_pkt_hdr1_b3_t;

typedef union _rx_pkt_hdr1_b4_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t resv:4;
		uint8_t zflowid:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t zflowid:4;
		uint8_t resv:4;
#endif
	} bits;
} rx_pkt_hdr1_b4_t, *p_rx_pkt_hdr1_b4_t;

typedef union _rx_pkt_hdr1_b5_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t zflowid:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t zflowid:8;
#endif
	} bits;
} rx_pkt_hdr1_b5_t, *p_rx_pkt_hdr1_b5_t;

typedef union _rx_pkt_hdr1_b6_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t hashval2:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t hashval2:8;
#endif
	} bits;
} rx_pkt_hdr1_b6_t, *p_rx_pkt_hdr1_b6_t;

typedef union _rx_pkt_hdr1_b7_t {
	uint8_t value;
	struct  {
#if	defined(_BIT_FIELDS_HTOL)
		uint8_t hashval2:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t hashval2:8;
#endif
	} bits;
} rx_pkt_hdr1_b7_t, *p_rx_pkt_hdr1_b7_t;

typedef union _rx_pkt_hdr1_b8_t {
	uint8_t value;
	struct  {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t resv:4;
		uint8_t h1:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t h1:4;
		uint8_t resv:4;
#endif
	} bits;
} rx_pkt_hdr1_b8_t, *p_rx_pkt_hdr1_b8_t;

typedef union _rx_pkt_hdr1_b9_t {
	uint8_t value;
	struct  {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t h1:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t h1:8;
#endif
	} bits;
} rx_pkt_hdr1_b9_t, *p_rx_pkt_hdr1_b9_t;

typedef union _rx_pkt_hdr1_b10_t {
	uint8_t value;
	struct  {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t resv:4;
		uint8_t h1:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t h1:4;
		uint8_t resv:4;
#endif
	} bits;
} rx_pkt_hdr1_b10_t, *p_rx_pkt_hdr1_b10_t;

typedef union _rx_pkt_hdr1_b11_b12_t {
	uint16_t value;
	struct {
#if	defined(_BIT_FIELDS_HTOL)
		uint16_t h1_1:8;
		uint16_t h1_2:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t h1_2:8;
		uint16_t h1_1:8;
#endif
	} bits;
} rx_pkt_hdr1_b11_b12_t, *p_rx_pkt_hdr1_b11_b12_t;

typedef union _rx_pkt_hdr1_b13_t {
	uint8_t value;
	struct  {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t usr_data:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t usr_data:8;
#endif
	} bits;
} rx_pkt_hdr1_b13_t, *p_rx_pkt_hdr1_b13_t;

typedef union _rx_pkt_hdr1_b14_b17_t {
	uint32_t value;
	struct  {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t usr_data_1:8;
		uint32_t usr_data_2:8;
		uint32_t usr_data_3:8;
		uint32_t usr_data_4:8;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t usr_data_4:8;
		uint32_t usr_data_3:8;
		uint32_t usr_data_2:8;
		uint32_t usr_data_1:8;
#endif
	} bits;
} rx_pkt_hdr1_b14_b17_t, *p_rx_pkt_hdr1_b14_b17_t;

/* Receive packet header 1 format (18 bytes) */
typedef struct _rx_pkt_hdr_t {
	rx_pkt_hdr1_b0_t		rx_hdr1_b0;
	rx_pkt_hdr1_b1_t		rx_hdr1_b1;
	rx_pkt_hdr1_b2_t		rx_hdr1_b2;
	rx_pkt_hdr1_b3_t		rx_hdr1_b3;
	rx_pkt_hdr1_b4_t		rx_hdr1_b4;
	rx_pkt_hdr1_b5_t		rx_hdr1_b5;
	rx_pkt_hdr1_b6_t		rx_hdr1_b6;
	rx_pkt_hdr1_b7_t		rx_hdr1_b7;
	rx_pkt_hdr1_b8_t		rx_hdr1_b8;
	rx_pkt_hdr1_b9_t		rx_hdr1_b9;
	rx_pkt_hdr1_b10_t		rx_hdr1_b10;
	rx_pkt_hdr1_b11_b12_t		rx_hdr1_b11_b12;
	rx_pkt_hdr1_b13_t		rx_hdr1_b13;
	rx_pkt_hdr1_b14_b17_t		rx_hdr1_b14_b17;
} rx_pkt_hdr1_t, *p_rx_pkt_hdr1_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_RXDMA_HW_H */

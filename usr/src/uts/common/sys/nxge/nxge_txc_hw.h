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

#ifndef	_SYS_NXGE_NXGE_TXC_HW_H
#define	_SYS_NXGE_NXGE_TXC_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>

/* Transmit Ring Scheduler Registers */
#define	TXC_PORT_DMA_ENABLE_REG		(FZC_TXC + 0x20028)
#define	TXC_PORT_DMA_LIST		0	/* RW bit 23:0 */
#define	TXC_DMA_DMA_LIST_MASK		0x0000000000FFFFFFULL
#define	TXC_DMA_DMA_LIST_MASK_N2	0x000000000000FFFFULL

typedef union _txc_port_enable_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:8;
			uint32_t port_dma_list:24;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port_dma_list:24;
			uint32_t res:8;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_port_enable_t, *p_txc_port_enable_t;

typedef union _txc_port_enable_n2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:16;
			uint32_t port_dma_list:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port_dma_list:16;
			uint32_t res:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_port_enable_n2_t, *p_txc_port_enable_n2_t;

/* Transmit Controller - Registers */
#define	TXC_FZC_OFFSET			0x1000
#define	TXC_FZC_PORT_OFFSET(port)	(port * TXC_FZC_OFFSET)
#define	TXC_FZC_CHANNEL_OFFSET(channel)	(channel * TXC_FZC_OFFSET)
#define	TXC_FZC_REG_CN_OFFSET(x, cn)	(x + TXC_FZC_CHANNEL_OFFSET(cn))

#define	TXC_FZC_CONTROL_OFFSET		0x100
#define	TXC_FZC_CNTL_PORT_OFFSET(port)	(port * TXC_FZC_CONTROL_OFFSET)
#define	TXC_FZC_REG_PT_OFFSET(x, pt)	(x + TXC_FZC_CNTL_PORT_OFFSET(pt))

#define	TXC_DMA_MAX_BURST_REG		(FZC_TXC + 0x00000)
#define	TXC_DMA_MAX_BURST_SHIFT		0	/* RW bit 19:0 */
#define	TXC_DMA_MAX_BURST_MASK		0x00000000000FFFFFULL

#define	TXC_MAX_BURST_OFFSET(channel)	(TXC_DMA_MAX_BURST_REG + \
					(channel * TXC_FZC_OFFSET))

typedef union _txc_dma_max_burst_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:12;
			uint32_t dma_max_burst:20;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t dma_max_burst:20;
			uint32_t res:12;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_dma_max_burst_t, *p_txc_dma_max_burst_t;

/* DRR Performance Monitoring Register */
#define	TXC_DMA_MAX_LENGTH_REG		(FZC_TXC + 0x00008)
#define	TXC_DMA_MAX_LENGTH_SHIFT	/* RW bit 27:0 */
#define	TXC_DMA_MAX_LENGTH_MASK		0x000000000FFFFFFFULL

#define	TXC_DMA_MAX_LEN_OFFSET(channel)	(TXC_DMA_MAX_LENGTH_REG + \
					(channel * TXC_FZC_OFFSET))

typedef union _txc_dma_max_length_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:4;
			uint32_t dma_length:28;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t dma_length:28;
			uint32_t res:4;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_dma_max_length_t, *p_txc_dma_max_length_t;


#define	TXC_CONTROL_REG			(FZC_TXC + 0x20000)
#define	TXC_DMA_LENGTH_SHIFT		0	/* RW bit 27:0 */
#define	TXC_DMA_LENGTH_MASK		0x000000000FFFFFFFULL

typedef union _txc_control_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:27;
			uint32_t txc_enabled:1;
			uint32_t port3_enabled:1;
			uint32_t port2_enabled:1;
			uint32_t port1_enabled:1;
			uint32_t port0_enabled:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port0_enabled:1;
			uint32_t port1_enabled:1;
			uint32_t port2_enabled:1;
			uint32_t port3_enabled:1;
			uint32_t txc_enabled:1;
			uint32_t res:27;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_control_t, *p_txc_control_t;

typedef union _txc_control_n2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:27;
			uint32_t txc_enabled:1;
			uint32_t res1:2;
			uint32_t port1_enabled:1;
			uint32_t port0_enabled:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port0_enabled:1;
			uint32_t port1_enabled:1;
			uint32_t res1:2;
			uint32_t txc_enabled:1;
			uint32_t res:27;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_control_n2_t, *p_txc_control_n2_t;


#define	TXC_TRAINING_REG		(FZC_TXC + 0x20008)
#define	TXC_TRAINING_VECTOR		0	/* RW bit 32:0 */
#define	TXC_TRAINING_VECTOR_MASK	0x00000000FFFFFFFFULL

typedef union _txc_training_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t txc_training_vector:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t txc_training_vector:32;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_training_t, *p_txc_training_t;


#define	TXC_DEBUG_SELECT_REG		(FZC_TXC + 0x20010)
#define	TXC_DEBUG_SELECT_SHIFT		0	/* WO bit 5:0 */
#define	TXC_DEBUG_SELECT_MASK		0x000000000000003FULL

typedef union _txc_debug_select_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:26;
			uint32_t debug_select:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t debug_select:6;
			uint32_t res:26;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_debug_select_t, *p_txc_debug_select_t;


#define	TXC_MAX_REORDER_REG		(FZC_TXC + 0x20018)
#define	TXC_MAX_REORDER_MASK_2		(0xf)
#define	TXC_MAX_REORDER_MASK_4		(0x7)
#define	TXC_MAX_REORDER_SHIFT_BITS	8
#define	TXC_MAX_REORDER_SHIFT(port)	(port * (TXC_MAX_REORDER_SHIFT_BITS))

typedef union _txc_max_reorder_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t resv3:4;
			uint32_t port3:4;
			uint32_t resv2:4;
			uint32_t port2:4;
			uint32_t resv1:4;
			uint32_t port1:4;
			uint32_t resv0:4;
			uint32_t port0:4;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port0:4;
			uint32_t resv0:4;
			uint32_t port1:4;
			uint32_t resv1:4;
			uint32_t port2:4;
			uint32_t resv2:4;
			uint32_t port3:4;
			uint32_t resv3:4;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_max_reorder_t, *p_txc_max_reorder_t;


#define	TXC_PORT_CTL_REG		(FZC_TXC + 0x20020)	/* RO */
#define	TXC_PORT_CTL_OFFSET(port)	(TXC_PORT_CTL_REG + \
					(port * TXC_FZC_CONTROL_OFFSET))
#define	TXC_PORT_CNTL_CLEAR		0x1

typedef union _txc_port_ctl_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd:31;
			uint32_t clr_all_stat:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t clr_all_stat:1;
			uint32_t rsvd:31;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_port_ctl_t, *p_txc_port_ctl_t;

#define	TXC_PKT_STUFFED_REG		(FZC_TXC + 0x20030)
#define	TXC_PKT_STUFF_PKTASY_SHIFT	16	/* RW bit 16:0 */
#define	TXC_PKT_STUFF_PKTASY_MASK	0x000000000000FFFFULL
#define	TXC_PKT_STUFF_REORDER_SHIFT	0	/* RW bit 31:16 */
#define	TXC_PKT_STUFF_REORDER_MASK	0x00000000FFFF0000ULL

typedef union _txc_pkt_stuffed_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t pkt_pro_reorder:16;
			uint32_t pkt_proc_pktasy:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkt_proc_pktasy:16;
			uint32_t pkt_pro_reorder:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_pkt_stuffed_t, *p_txc_pkt_stuffed_t;


#define	TXC_PKT_XMIT_REG		(FZC_TXC + 0x20038)
#define	TXC_PKTS_XMIT_SHIFT		0	/* RW bit 15:0 */
#define	TXC_PKTS_XMIT_MASK		0x000000000000FFFFULL
#define	TXC_BYTES_XMIT_SHIFT		16	/* RW bit 31:16 */
#define	TXC_BYTES_XMIT_MASK		0x00000000FFFF0000ULL

typedef union _txc_pkt_xmit_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t bytes_transmitted:16;
			uint32_t pkts_transmitted:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkts_transmitted:16;
			uint32_t bytes_transmitted:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_pkt_xmit, *p_txc_pkt_xmit;


/* count 4 step 0x00100 */
#define	TXC_ROECC_CTL_REG		(FZC_TXC + 0x20040)
#define	TXC_ROECC_CTL_OFFSET(port)	(TXC_ROECC_CTL_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_roecc_ctl_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t disable_ue_error:1;
			uint32_t rsvd:13;
			uint32_t double_bit_err:1;
			uint32_t single_bit_err:1;
			uint32_t rsvd_2:5;
			uint32_t all_pkts:1;
			uint32_t alternate_pkts:1;
			uint32_t one_pkt:1;
			uint32_t rsvd_3:5;
			uint32_t last_line_pkt:1;
			uint32_t second_line_pkt:1;
			uint32_t firstd_line_pkt:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t firstd_line_pkt:1;
			uint32_t second_line_pkt:1;
			uint32_t last_line_pkt:1;
			uint32_t rsvd_3:5;
			uint32_t one_pkt:1;
			uint32_t alternate_pkts:1;
			uint32_t all_pkts:1;
			uint32_t rsvd_2:5;
			uint32_t single_bit_err:1;
			uint32_t double_bit_err:1;
			uint32_t rsvd:13;
			uint32_t disable_ue_error:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_roecc_ctl_t, *p_txc_roecc_ctl_t;


#define	TXC_ROECC_ST_REG		(FZC_TXC + 0x20048)

#define	TXC_ROECC_ST_OFFSET(port)	(TXC_ROECC_ST_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_roecc_st_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t clr_st:1;
			uint32_t res:13;
			uint32_t correct_error:1;
			uint32_t uncorrect_error:1;
			uint32_t rsvd:6;
			uint32_t ecc_address:10;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ecc_address:10;
			uint32_t rsvd:6;
			uint32_t uncorrect_error:1;
			uint32_t correct_error:1;
			uint32_t res:13;
			uint32_t clr_st:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_roecc_st_t, *p_txc_roecc_st_t;


#define	TXC_RO_DATA0_REG		(FZC_TXC + 0x20050)
#define	TXC_RO_DATA0_OFFSET(port)	(TXC_RO_DATA0_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_ro_data0_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_ecc_data0:32;	/* ro_ecc_data[31:0] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_ecc_data0:32;	/* ro_ecc_data[31:0] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_data0_t, *p_txc_ro_data0_t;

#define	TXC_RO_DATA1_REG		(FZC_TXC + 0x20058)
#define	TXC_RO_DATA1_OFFSET(port)	(TXC_RO_DATA1_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_ro_data1_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_ecc_data1:32;	/* ro_ecc_data[63:32] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_ecc_data1:32;	/* ro_ecc_data[31:32] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_data1_t, *p_txc_ro_data1_t;


#define	TXC_RO_DATA2_REG		(FZC_TXC + 0x20060)

#define	TXC_RO_DATA2_OFFSET(port)	(TXC_RO_DATA2_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_ro_data2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_ecc_data2:32;	/* ro_ecc_data[95:64] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_ecc_data2:32;	/* ro_ecc_data[95:64] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_data2_t, *p_txc_ro_data2_t;

#define	TXC_RO_DATA3_REG		(FZC_TXC + 0x20068)
#define	TXC_RO_DATA3_OFFSET(port)	(TXC_RO_DATA3_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_ro_data3_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_ecc_data3:32; /* ro_ecc_data[127:96] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_ecc_data3:32; /* ro_ecc_data[127:96] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_data3_t, *p_txc_ro_data3_t;

#define	TXC_RO_DATA4_REG		(FZC_TXC + 0x20070)
#define	TXC_RO_DATA4_OFFSET(port)	(TXC_RO_DATA4_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_ro_data4_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_ecc_data4:32; /* ro_ecc_data[151:128] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_ecc_data4:32; /* ro_ecc_data[151:128] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_data4_t, *p_txc_ro_data4_t;

/* count 4 step 0x00100 */
#define	TXC_SFECC_CTL_REG		(FZC_TXC + 0x20078)
#define	TXC_SFECC_CTL_OFFSET(port)	(TXC_SFECC_CTL_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_sfecc_ctl_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t disable_ue_error:1;
			uint32_t rsvd:13;
			uint32_t double_bit_err:1;
			uint32_t single_bit_err:1;
			uint32_t rsvd_2:5;
			uint32_t all_pkts:1;
			uint32_t alternate_pkts:1;
			uint32_t one_pkt:1;
			uint32_t rsvd_3:5;
			uint32_t last_line_pkt:1;
			uint32_t second_line_pkt:1;
			uint32_t firstd_line_pkt:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t firstd_line_pkt:1;
			uint32_t second_line_pkt:1;
			uint32_t last_line_pkt:1;
			uint32_t rsvd_3:5;
			uint32_t one_pkt:1;
			uint32_t alternate_pkts:1;
			uint32_t all_pkts:1;
			uint32_t rsvd_2:5;
			uint32_t single_bit_err:1;
			uint32_t double_bit_err:1;
			uint32_t rsvd:13;
			uint32_t disable_ue_error:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_sfecc_ctl_t, *p_txc_sfecc_ctl_t;

#define	TXC_SFECC_ST_REG		(FZC_TXC + 0x20080)
#define	TXC_SFECC_ST_OFFSET(port)	(TXC_SFECC_ST_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_sfecc_st_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t clr_st:1;
			uint32_t res:13;
			uint32_t correct_error:1;
			uint32_t uncorrect_error:1;
			uint32_t rsvd:6;
			uint32_t ecc_address:10;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ecc_address:10;
			uint32_t rsvd:6;
			uint32_t uncorrect_error:1;
			uint32_t correct_error:1;
			uint32_t res:13;
			uint32_t clr_st:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_sfecc_st_t, *p_txc_sfecc_st_t;

#define	TXC_SF_DATA0_REG		(FZC_TXC + 0x20088)
#define	TXC_SF_DATA0_OFFSET(port)	(TXC_SF_DATA0_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_sf_data0_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t sf_ecc_data0:32;	/* sf_ecc_data[31:0] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sf_ecc_data0:32;	/* sf_ecc_data[31:0] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_sf_data0_t, *p_txc_sf_data0_t;

#define	TXC_SF_DATA1_REG		(FZC_TXC + 0x20090)
#define	TXC_SF_DATA1_OFFSET(port)	(TXC_SF_DATA1_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_sf_data1_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t sf_ecc_data1:32;	/* sf_ecc_data[63:32] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sf_ecc_data1:32;	/* sf_ecc_data[31:32] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_sf_data1_t, *p_txc_sf_data1_t;


#define	TXC_SF_DATA2_REG		(FZC_TXC + 0x20098)
#define	TXC_SF_DATA2_OFFSET(port)	(TXC_SF_DATA2_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_sf_data2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t sf_ecc_data2:32;	/* sf_ecc_data[95:64] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sf_ecc_data2:32;	/* sf_ecc_data[95:64] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_sf_data2_t, *p_txc_sf_data2_t;

#define	TXC_SF_DATA3_REG		(FZC_TXC + 0x200A0)
#define	TXC_SF_DATA3_OFFSET(port)	(TXC_SF_DATA3_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_sf_data3_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t sf_ecc_data3:32; /* sf_ecc_data[127:96] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sf_ecc_data3:32; /* sf_ecc_data[127:96] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_sf_data3_t, *p_txc_sf_data3_t;

#define	TXC_SF_DATA4_REG		(FZC_TXC + 0x200A8)
#define	TXC_SF_DATA4_OFFSET(port)	(TXC_SF_DATA4_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_sf_data4_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t sf_ecc_data4:32; /* sf_ecc_data[151:128] */
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sf_ecc_data4:32; /* sf_ecc_data[151:128] */
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_sf_data4_t, *p_txc_sf_data4_t;

#define	TXC_RO_TIDS_REG			(FZC_TXC + 0x200B0)
#define	TXC_RO_TIDS_OFFSET(port)	(TXC_RO_TIDS_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_TIDS_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_tids_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t tids_in_use:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t tids_in_use:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_tids_t, *p_txc_ro_tids_t;

#define	TXC_RO_STATE0_REG		(FZC_TXC + 0x200B8)
#define	TXC_RO_STATE0_OFFSET(port)	(TXC_STATE0_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_STATE0_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_state0_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t duplicate_tid:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t duplicate_tid:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_state0_t, *p_txc_ro_state0_t;

#define	TXC_RO_STATE1_REG		(FZC_TXC + 0x200C0)
#define	TXC_RO_STATE1_OFFSET(port)	(TXC_STATE1_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_STATE1_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_state1_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t unused_tid:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t unused_tid:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_state1_t, *p_txc_ro_state1_t;

#define	TXC_RO_STATE2_REG		(FZC_TXC + 0x200C8)
#define	TXC_RO_STATE2_OFFSET(port)	(TXC_STATE2_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_STATE2_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_state2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t transaction_timeout:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t transaction_timeout:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_state2_t, *p_txc_ro_state2_t;

#define	TXC_RO_STATE3_REG		(FZC_TXC + 0x200D0)
#define	TXC_RO_STATE3_OFFSET(port)	(TXC_RO_STATE3_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_ro_state3_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t enable_spacefilled_watermark:1;
			uint32_t ro_spacefilled_watermask:10;
			uint32_t ro_fifo_spaceavailable:10;
			uint32_t rsv:2;
			uint32_t enable_ro_watermark:1;
			uint32_t highest_reorder_used:4;
			uint32_t num_reorder_used:4;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t num_reorder_used:4;
			uint32_t highest_reorder_used:4;
			uint32_t enable_ro_watermark:1;
			uint32_t rsv:2;
			uint32_t ro_fifo_spaceavailable:10;
			uint32_t ro_spacefilled_watermask:10;
			uint32_t enable_spacefilled_watermark:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_state3_t, *p_txc_ro_state3_t;

#define	TXC_RO_CTL_REG			(FZC_TXC + 0x200D8)
#define	TXC_RO_CTL_OFFSET(port)		(TXC_RO_CTL_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))

typedef union _txc_ro_ctl_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t clr_fail_state:1;
			uint32_t rsvd3:3;
			uint32_t ro_addr1:4;
			uint32_t rsvd2:1;
			uint32_t address_failed:1;
			uint32_t dma_failed:1;
			uint32_t length_failed:1;
			uint32_t rsv:1;
			uint32_t capture_address_fail:1;
			uint32_t capture_dma_fail:1;
			uint32_t capture_length_fail:1;
			uint32_t rsvd:8;
			uint32_t ro_state_rd_done:1;
			uint32_t ro_state_wr_done:1;
			uint32_t ro_state_rd:1;
			uint32_t ro_state_wr:1;
			uint32_t ro_state_addr:4;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_state_addr:4;
			uint32_t ro_state_wr:1;
			uint32_t ro_state_rd:1;
			uint32_t ro_state_wr_done:1;
			uint32_t ro_state_rd_done:1;
			uint32_t rsvd:8;
			uint32_t capture_length_fail:1;
			uint32_t capture_dma_fail:1;
			uint32_t capture_address_fail:1;
			uint32_t rsv:1;
			uint32_t length_failed:1;
			uint32_t dma_failed:1;
			uint32_t address_failed:1;
			uint32_t rsvd2:1;
			uint32_t ro_addr1:4;
			uint32_t rsvd3:3;
			uint32_t clr_fail_state:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_ctl_t, *p_txc_ro_ctl_t;


#define	TXC_RO_ST_DATA0_REG		(FZC_TXC + 0x200E0)
#define	TXC_RO_ST_DATA0_OFFSET(port)	(TXC_RO_ST_DATA0_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_ST_DATA0_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_st_data0_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_st_dat0:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_st_dat0:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_st_data0_t, *p_txc_ro_st_data0_t;


#define	TXC_RO_ST_DATA1_REG		(FZC_TXC + 0x200E8)
#define	TXC_RO_ST_DATA1_OFFSET(port)	(TXC_RO_ST_DATA1_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_ST_DATA1_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_st_data1_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_st_dat1:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_st_dat1:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_st_data1_t, *p_txc_ro_st_data1_t;


#define	TXC_RO_ST_DATA2_REG		(FZC_TXC + 0x200F0)
#define	TXC_RO_ST_DATA2_OFFSET(port)	(TXC_RO_ST_DATA2_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_ST_DATA2_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_st_data2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_st_dat2:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_st_dat2:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_st_data2_t, *p_txc_ro_st_data2_t;

#define	TXC_RO_ST_DATA3_REG		(FZC_TXC + 0x200F8)
#define	TXC_RO_ST_DATA3_OFFSET(port)	(TXC_RO_ST_DATA3_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_RO_ST_DATA3_MASK		0x00000000FFFFFFFFULL

typedef union _txc_ro_st_data3_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t ro_st_dat3:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t ro_st_dat3:32;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_ro_st_data3_t, *p_txc_ro_st_data3_t;

#define	TXC_PORT_PACKET_REQ_REG		(FZC_TXC + 0x20100)
#define	TXC_PORT_PACKET_REQ_OFFSET(port) (TXC_PORT_PACKET_REQ_REG + \
					(TXC_FZC_CNTL_PORT_OFFSET(port)))
#define	TXC_PORT_PACKET_REQ_MASK	0x00000000FFFFFFFFULL

typedef union _txc_port_packet_req_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t gather_req:4;
			uint32_t packet_eq:12;
			uint32_t pkterr_abort:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkterr_abort:16;
			uint32_t packet_eq:12;
			uint32_t gather_req:4;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_port_packet_req_t, *p_txc_port_packet_req_t;

/* Reorder error bits in interrupt registers  */
#define	TXC_INT_STAT_SF_CORR_ERR	0x01
#define	TXC_INT_STAT_SF_UNCORR_ERR	0x02
#define	TXC_INT_STAT_RO_CORR_ERR	0x04
#define	TXC_INT_STAT_RO_UNCORR_ERR	0x08
#define	TXC_INT_STAT_REORDER_ERR	0x10
#define	TXC_INT_STAT_PKTASSYDEAD	0x20

#define	TXC_INT_STAT_DBG_REG		(FZC_TXC + 0x20420)
#define	TXC_INT_STAT_DBG_MASK		0x00000000FFFFFFFFULL

typedef union _txc_int_stat_dbg_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd3:2;
			uint32_t port3_int_status:6;
			uint32_t rsvd2:2;
			uint32_t port2_int_status:6;
			uint32_t rsvd1:2;
			uint32_t port1_int_status:6;
			uint32_t rsvd:2;
			uint32_t port0_int_status:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port0_int_status:6;
			uint32_t rsvd:2;
			uint32_t port1_int_status:6;
			uint32_t rsvd1:2;
			uint32_t port2_int_status:6;
			uint32_t rsvd2:2;
			uint32_t port3_int_status:6;
			uint32_t rsvd3:2;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_int_stat_dbg_t, *p_txc_int_stat_dbg_t;


#define	TXC_INT_STAT_REG		(FZC_TXC + 0x20428)
#define	TXC_INT_STAT_MASK		0x00000000FFFFFFFFULL

typedef union _txc_int_stat_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd3:2;
			uint32_t port3_int_status:6;
			uint32_t rsvd2:2;
			uint32_t port2_int_status:6;
			uint32_t rsvd1:2;
			uint32_t port1_int_status:6;
			uint32_t rsvd:2;
			uint32_t port0_int_status:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port0_int_status:6;
			uint32_t rsvd:2;
			uint32_t port1_int_status:6;
			uint32_t rsvd1:2;
			uint32_t port2_int_status:6;
			uint32_t rsvd2:2;
			uint32_t port3_int_status:6;
			uint32_t rsvd3:2;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_int_stat_t, *p_txc_int_stat_t;

#define	TXC_INT_MASK_REG		(FZC_TXC + 0x20430)
#define	TXC_INT_MASK_MASK		0x00000000FFFFFFFFULL
#define	TXC_INT_MASK_IVAL		0x3f

typedef union _txc_int_mask_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd3:2;
			uint32_t port3_int_mask:6;
			uint32_t rsvd2:2;
			uint32_t port2_int_mask:6;
			uint32_t rsvd1:2;
			uint32_t port1_int_mask:6;
			uint32_t rsvd:2;
			uint32_t port0_int_mask:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port0_int_mask:6;
			uint32_t rsvd:2;
			uint32_t port1_int_mask:6;
			uint32_t rsvd1:2;
			uint32_t port2_int_mask:6;
			uint32_t rsvd2:2;
			uint32_t port3_int_mask:6;
			uint32_t rsvd3:2;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_int_mask_t, *p_txc_int_mask_t;

/* 2 ports */
typedef union _txc_int_mask_n2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd1:18;
			uint32_t port1_int_mask:6;
			uint32_t rsvd:2;
			uint32_t port0_int_mask:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t port0_int_mask:6;
			uint32_t rsvd:2;
			uint32_t port1_int_mask:6;
			uint32_t rsvd1:18;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txc_int_mask_n2_t, *p_txc_int_mask_n2_t;

typedef	struct _txc_ro_states {
	txc_roecc_st_t		roecc;
	txc_ro_data0_t		d0;
	txc_ro_data1_t		d1;
	txc_ro_data2_t		d2;
	txc_ro_data3_t		d3;
	txc_ro_data4_t		d4;
	txc_ro_tids_t		tids;
	txc_ro_state0_t		st0;
	txc_ro_state1_t		st1;
	txc_ro_state2_t		st2;
	txc_ro_state3_t		st3;
	txc_ro_ctl_t		ctl;
} txc_ro_states_t, *p_txc_ro_states_t;

typedef	struct _txc_sf_states {
	txc_sfecc_st_t		sfecc;
	txc_sf_data0_t		d0;
	txc_sf_data1_t		d1;
	txc_sf_data2_t		d2;
	txc_sf_data3_t		d3;
	txc_sf_data4_t		d4;
} txc_sf_states_t, *p_txc_sf_states_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_TXC_HW_H */

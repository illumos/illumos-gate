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

#ifndef _SYS_NXGE_NXGE_IPP_HW_H
#define	_SYS_NXGE_NXGE_IPP_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>

/* IPP Registers */
#define	IPP_CONFIG_REG				0x000
#define	IPP_DISCARD_PKT_CNT_REG			0x020
#define	IPP_BAD_CKSUM_ERR_CNT_REG		0x028
#define	IPP_ECC_ERR_COUNTER_REG			0x030
#define	IPP_INT_STATUS_REG			0x040
#define	IPP_INT_MASK_REG			0x048

#define	IPP_PFIFO_RD_DATA0_REG			0x060
#define	IPP_PFIFO_RD_DATA1_REG			0x068
#define	IPP_PFIFO_RD_DATA2_REG			0x070
#define	IPP_PFIFO_RD_DATA3_REG			0x078
#define	IPP_PFIFO_RD_DATA4_REG			0x080
#define	IPP_PFIFO_WR_DATA0_REG			0x088
#define	IPP_PFIFO_WR_DATA1_REG			0x090
#define	IPP_PFIFO_WR_DATA2_REG			0x098
#define	IPP_PFIFO_WR_DATA3_REG			0x0a0
#define	IPP_PFIFO_WR_DATA4_REG			0x0a8
#define	IPP_PFIFO_RD_PTR_REG			0x0b0
#define	IPP_PFIFO_WR_PTR_REG			0x0b8
#define	IPP_DFIFO_RD_DATA0_REG			0x0c0
#define	IPP_DFIFO_RD_DATA1_REG			0x0c8
#define	IPP_DFIFO_RD_DATA2_REG			0x0d0
#define	IPP_DFIFO_RD_DATA3_REG			0x0d8
#define	IPP_DFIFO_RD_DATA4_REG			0x0e0
#define	IPP_DFIFO_WR_DATA0_REG			0x0e8
#define	IPP_DFIFO_WR_DATA1_REG			0x0f0
#define	IPP_DFIFO_WR_DATA2_REG			0x0f8
#define	IPP_DFIFO_WR_DATA3_REG			0x100
#define	IPP_DFIFO_WR_DATA4_REG			0x108
#define	IPP_DFIFO_RD_PTR_REG			0x110
#define	IPP_DFIFO_WR_PTR_REG			0x118
#define	IPP_STATE_MACHINE_REG			0x120
#define	IPP_CKSUM_STATUS_REG			0x128
#define	IPP_FFLP_CKSUM_INFO_REG			0x130
#define	IPP_DEBUG_SELECT_REG			0x138
#define	IPP_DFIFO_ECC_SYNDROME_REG		0x140
#define	IPP_DFIFO_EOPM_RD_PTR_REG		0x148
#define	IPP_ECC_CTRL_REG			0x150

#define	IPP_PORT_OFFSET				0x4000
#define	IPP_PORT0_OFFSET			0
#define	IPP_PORT1_OFFSET			0x8000
#define	IPP_PORT2_OFFSET			0x4000
#define	IPP_PORT3_OFFSET			0xc000
#define	IPP_REG_ADDR(port_num, reg)\
	((port_num == 0) ? FZC_IPP + reg : \
	FZC_IPP + reg + (((port_num % 2) * IPP_PORT_OFFSET) + \
	((port_num / 3) * IPP_PORT_OFFSET) + IPP_PORT_OFFSET))
#define	IPP_PORT_ADDR(port_num)\
	((port_num == 0) ? FZC_IPP: \
	FZC_IPP + (((port_num % 2) * IPP_PORT_OFFSET) + \
	((port_num / 3) * IPP_PORT_OFFSET) + IPP_PORT_OFFSET))

/* IPP Configuration Register */

#define	IPP_SOFT_RESET				(1ULL << 31)
#define	IPP_IP_MAX_PKT_BYTES_SHIFT		8
#define	IPP_IP_MAX_PKT_BYTES_MASK		0x1FFFF
#define	IPP_FFLP_CKSUM_INFO_PIO_WR_EN		(1 << 7)
#define	IPP_PRE_FIFO_PIO_WR_EN			(1 << 6)
#define	IPP_DFIFO_PIO_WR_EN			(1 << 5)
#define	IPP_TCP_UDP_CKSUM_EN			(1 << 4)
#define	IPP_DROP_BAD_CRC_EN			(1 << 3)
#define	IPP_DFIFO_ECC_CORRECT_EN		(1 << 2)
#define	IPP_EN					(1 << 0)

/* IPP Interrupt Status Registers */

#define	IPP_DFIFO_MISSED_SOP			(1ULL << 31)
#define	IPP_DFIFO_MISSED_EOP			(1 << 30)
#define	IPP_DFIFO_ECC_UNCORR_ERR_MASK		0x3
#define	IPP_DFIFO_ECC_UNCORR_ERR_SHIFT		28
#define	IPP_DFIFO_ECC_CORR_ERR_MASK		0x3
#define	IPP_DFIFO_ECC_CORR_ERR_SHIFT		26
#define	IPP_DFIFO_ECC_ERR_MASK			0x3
#define	IPP_DFIFO_ECC_ERR_SHIFT			24
#define	IPP_DFIFO_NO_ECC_ERR			(1 << 23)
#define	IPP_DFIFO_ECC_ERR_ENTRY_INDEX_MASK	0x7FF
#define	IPP_DFIFO_ECC_ERR_ENTRY_INDEX_SHIFT	12
#define	IPP_PRE_FIFO_PERR			(1 << 11)
#define	IPP_ECC_ERR_CNT_MAX			(1 << 10)
#define	IPP_PRE_FIFO_PERR_ENTRY_INDEX_MASK	0x3F
#define	IPP_PRE_FIFO_PERR_ENTRY_INDEX_SHIFT	4
#define	IPP_PRE_FIFO_OVERRUN			(1 << 3)
#define	IPP_PRE_FIFO_UNDERRUN			(1 << 2)
#define	IPP_BAD_TCPIP_CHKSUM_CNT_MAX		(1 << 1)
#define	IPP_PKT_DISCARD_CNT_MAX			(1 << 0)

#define	IPP_P0_P1_DFIFO_ENTRIES			2048
#define	IPP_P2_P3_DFIFO_ENTRIES			1024
#define	IPP_NIU_DFIFO_ENTRIES			1024

typedef	union _ipp_status {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t dfifo_missed_sop	: 1;
		uint32_t dfifo_missed_eop	: 1;
		uint32_t dfifo_uncorr_ecc_err	: 2;
		uint32_t dfifo_corr_ecc_err	: 2;
		uint32_t dfifo_ecc_err		: 2;
		uint32_t dfifo_no_ecc_err	: 1;
		uint32_t dfifo_ecc_err_idx	: 11;
		uint32_t pre_fifo_perr		: 1;
		uint32_t ecc_err_cnt_ovfl	: 1;
		uint32_t pre_fifo_perr_idx	: 6;
		uint32_t pre_fifo_overrun	: 1;
		uint32_t pre_fifo_underrun	: 1;
		uint32_t bad_cksum_cnt_ovfl	: 1;
		uint32_t pkt_discard_cnt_ovfl	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t pkt_discard_cnt_ovfl	: 1;
		uint32_t bad_cksum_cnt_ovfl	: 1;
		uint32_t pre_fifo_underrun	: 1;
		uint32_t pre_fifo_overrun	: 1;
		uint32_t pre_fifo_perr_idx	: 6;
		uint32_t ecc_err_cnt_ovfl	: 1;
		uint32_t pre_fifo_perr		: 1;
		uint32_t dfifo_ecc_err_idx	: 11;
		uint32_t dfifo_no_ecc_err	: 1;
		uint32_t dfifo_ecc_err		: 2;
		uint32_t dfifo_corr_ecc_err	: 2;
		uint32_t dfifo_uncorr_ecc_err	: 2;
		uint32_t dfifo_missed_eop	: 1;
		uint32_t dfifo_missed_sop	: 1;
#else
#error	one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} w0;

#if !defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} ipp_status_t;

typedef	union _ipp_ecc_ctrl {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t dis_dbl	: 1;
		uint32_t res3		: 13;
		uint32_t cor_dbl	: 1;
		uint32_t cor_sng	: 1;
		uint32_t rsvd		: 5;
		uint32_t cor_all	: 1;
		uint32_t res2		: 1;
		uint32_t cor_1		: 1;
		uint32_t res1		: 5;
		uint32_t cor_lst	: 1;
		uint32_t cor_snd	: 1;
		uint32_t cor_fst	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t cor_fst	: 1;
		uint32_t cor_snd	: 1;
		uint32_t cor_lst	: 1;
		uint32_t res1		: 5;
		uint32_t cor_1		: 1;
		uint32_t res2		: 1;
		uint32_t cor_all	: 1;
		uint32_t rsvd		: 5;
		uint32_t cor_sng	: 1;
		uint32_t cor_dbl	: 1;
		uint32_t res3		: 13;
		uint32_t dis_dbl	: 1;
#else
#error	one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} w0;

#if !defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} ipp_ecc_ctrl_t;


/* IPP Interrupt Mask Registers */

#define	IPP_ECC_ERR_CNT_MAX_INTR_DIS		(1 << 7)
#define	IPP_DFIFO_MISSING_EOP_SOP_INTR_DIS	(1 << 6)
#define	IPP_DFIFO_ECC_UNCORR_ERR_INTR_DIS	(1 << 5)
#define	IPP_PRE_FIFO_PERR_INTR_DIS		(1 << 4)
#define	IPP_PRE_FIFO_OVERRUN_INTR_DIS		(1 << 3)
#define	IPP_PRE_FIFO_UNDERRUN_INTR_DIS		(1 << 2)
#define	IPP_BAD_TCPIP_CKSUM_CNT_INTR_DIS	(1 << 1)
#define	IPP_PKT_DISCARD_CNT_INTR_DIS		(1 << 0)

#define	IPP_RESET_WAIT				10

/* DFIFO RD/WR pointers mask */

#define	IPP_XMAC_DFIFO_PTR_MASK			0x7FF
#define	IPP_BMAC_DFIFO_PTR_MASK			0x3FF

#define	IPP_ECC_CNT_MASK			0xFF
#define	IPP_BAD_CS_CNT_MASK			0x3FFF
#define	IPP_PKT_DIS_CNT_MASK			0x3FFF

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_IPP_HW_H */

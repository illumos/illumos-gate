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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2009, Pyun YongHyeon <yongari@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _ATGE_L1C_REG_H
#define	_ATGE_L1C_REG_H

#ifdef __cplusplus
	extern "C" {
#endif

#pragma	pack(1)
typedef	struct	l1c_cmb {
	uint32_t	intr_status;
	uint32_t	rx_prod_cons;
	uint32_t	tx_prod_cons;
} l1c_cmb_t;

typedef	struct	l1c_rx_desc {
	uint64_t	addr;
	/* No length field. */
} l1c_rx_desc_t;

typedef	struct	l1c_rx_rdesc {
	uint32_t	rdinfo;	/* word 0 */
	uint32_t	rss;	/* word 1 */
	uint32_t	vtag;	/* word 2 */
	uint32_t	status;	/* word 3 */
} l1c_rx_rdesc_t;

/*
 * Statistics counters collected by the MAC
 */
typedef	struct l1c_smb {
	/* Rx stats. */
	uint32_t rx_frames;
	uint32_t rx_bcast_frames;
	uint32_t rx_mcast_frames;
	uint32_t rx_pause_frames;
	uint32_t rx_control_frames;
	uint32_t rx_crcerrs;
	uint32_t rx_lenerrs;
	uint32_t rx_bytes;
	uint32_t rx_runts;
	uint32_t rx_fragments;
	uint32_t rx_pkts_64;
	uint32_t rx_pkts_65_127;
	uint32_t rx_pkts_128_255;
	uint32_t rx_pkts_256_511;
	uint32_t rx_pkts_512_1023;
	uint32_t rx_pkts_1024_1518;
	uint32_t rx_pkts_1519_max;
	uint32_t rx_pkts_truncated;
	uint32_t rx_fifo_oflows;
	uint32_t rx_desc_oflows;
	uint32_t rx_alignerrs;
	uint32_t rx_bcast_bytes;
	uint32_t rx_mcast_bytes;
	uint32_t rx_pkts_filtered;
	/* Tx stats. */
	uint32_t tx_frames;
	uint32_t tx_bcast_frames;
	uint32_t tx_mcast_frames;
	uint32_t tx_pause_frames;
	uint32_t tx_excess_defer;
	uint32_t tx_control_frames;
	uint32_t tx_deferred;
	uint32_t tx_bytes;
	uint32_t tx_pkts_64;
	uint32_t tx_pkts_65_127;
	uint32_t tx_pkts_128_255;
	uint32_t tx_pkts_256_511;
	uint32_t tx_pkts_512_1023;
	uint32_t tx_pkts_1024_1518;
	uint32_t tx_pkts_1519_max;
	uint32_t tx_single_colls;
	uint32_t tx_multi_colls;
	uint32_t tx_late_colls;
	uint32_t tx_excess_colls;
	uint32_t tx_underrun;
	uint32_t tx_desc_underrun;
	uint32_t tx_lenerrs;
	uint32_t tx_pkts_truncated;
	uint32_t tx_bcast_bytes;
	uint32_t tx_mcast_bytes;
	uint32_t updated;
} atge_l1c_smb_t;
#pragma	pack()

#define	L1C_RX_RING_CNT		256
#define	L1C_RR_RING_CNT		L1C_RX_RING_CNT
#define	L1C_HEADROOM		6  /* Must be divisible by 2, but not 4. */

#define	L1C_RING_ALIGN		16
#define	L1C_TX_RING_ALIGN	16
#define	L1C_RX_RING_ALIGN	16
#define	L1C_RR_RING_ALIGN	16
#define	L1C_CMB_ALIGN		16
#define	L1C_SMB_ALIGN		16

#define	L1C_CMB_BLOCK_SZ	sizeof (struct l1c_cmb)
#define	L1C_SMB_BLOCK_SZ	sizeof (struct l1c_smb)

#define	L1C_RX_RING_SZ		\
	(sizeof (struct l1c_rx_desc) * L1C_RX_RING_CNT)

#define	L1C_RR_RING_SZ		\
	(sizeof (struct l1c_rx_rdesc) * L1C_RR_RING_CNT)

/*
 * For RX
 */
/* word 0 */
#define	L1C_RRD_CSUM_MASK		0x0000FFFF
#define	L1C_RRD_RD_CNT_MASK		0x000F0000
#define	L1C_RRD_RD_IDX_MASK		0xFFF00000
#define	L1C_RRD_CSUM_SHIFT		0
#define	L1C_RRD_RD_CNT_SHIFT		16
#define	L1C_RRD_RD_IDX_SHIFT		20
#define	L1C_RRD_CSUM(x)			\
	(((x) & L1C_RRD_CSUM_MASK) >> L1C_RRD_CSUM_SHIFT)
#define	L1C_RRD_RD_CNT(x)			\
	(((x) & L1C_RRD_RD_CNT_MASK) >> L1C_RRD_RD_CNT_SHIFT)
#define	L1C_RRD_RD_IDX(x)			\
	(((x) & L1C_RRD_RD_IDX_MASK) >> L1C_RRD_RD_IDX_SHIFT)

/* word 2 */
#define	L1C_RRD_VLAN_MASK		0x0000FFFF
#define	L1C_RRD_HEAD_LEN_MASK		0x00FF0000
#define	L1C_RRD_HDS_MASK		0x03000000
#define	L1C_RRD_HDS_NONE		0x00000000
#define	L1C_RRD_HDS_HEAD		0x01000000
#define	L1C_RRD_HDS_DATA		0x02000000
#define	L1C_RRD_CPU_MASK		0x0C000000
#define	L1C_RRD_HASH_FLAG_MASK		0xF0000000
#define	L1C_RRD_VLAN_SHIFT		0
#define	L1C_RRD_HEAD_LEN_SHIFT		16
#define	L1C_RRD_HDS_SHIFT		24
#define	L1C_RRD_CPU_SHIFT		26
#define	L1C_RRD_HASH_FLAG_SHIFT		28
#define	L1C_RRD_VLAN(x)			\
	(((x) & L1C_RRD_VLAN_MASK) >> L1C_RRD_VLAN_SHIFT)
#define	L1C_RRD_HEAD_LEN(x)			\
	(((x) & L1C_RRD_HEAD_LEN_MASK) >> L1C_RRD_HEAD_LEN_SHIFT)
#define	L1C_RRD_CPU(x)			\
	(((x) & L1C_RRD_CPU_MASK) >> L1C_RRD_CPU_SHIFT)

	/* word3 */
#define	L1C_RRD_LEN_MASK		0x00003FFF
#define	L1C_RRD_LEN_SHIFT		0
#define	L1C_RRD_TCP_UDPCSUM_NOK		0x00004000
#define	L1C_RRD_IPCSUM_NOK		0x00008000
#define	L1C_RRD_VLAN_TAG		0x00010000
#define	L1C_RRD_PROTO_MASK		0x000E0000
#define	L1C_RRD_PROTO_IPV4		0x00020000
#define	L1C_RRD_PROTO_IPV6		0x000C0000
#define	L1C_RRD_ERR_SUM			0x00100000
#define	L1C_RRD_ERR_CRC			0x00200000
#define	L1C_RRD_ERR_ALIGN		0x00400000
#define	L1C_RRD_ERR_TRUNC		0x00800000
#define	L1C_RRD_ERR_RUNT		0x01000000
#define	L1C_RRD_ERR_ICMP		0x02000000
#define	L1C_RRD_BCAST			0x04000000
#define	L1C_RRD_MCAST			0x08000000
#define	L1C_RRD_SNAP_LLC		0x10000000
#define	L1C_RRD_ETHER			0x00000000
#define	L1C_RRD_FIFO_FULL		0x20000000
#define	L1C_RRD_ERR_LENGTH		0x40000000
#define	L1C_RRD_VALID			0x80000000
#define	L1C_RRD_BYTES(x)			\
	(((x) & L1C_RRD_LEN_MASK) >> L1C_RRD_LEN_SHIFT)
#define	L1C_RRD_IPV4(x)			\
	(((x) & L1C_RRD_PROTO_MASK) == L1C_RRD_PROTO_IPV4)

#define	RRD_PROD_MASK			0x0000FFFF
#define	TPD_CONS_MASK			0xFFFF0000
#define	TPD_CONS_SHIFT			16
#define	CMB_UPDATED			0x00000001
#define	RRD_PROD_SHIFT			0

#pragma	pack(1)
typedef struct l1c_tx_desc {
	uint32_t len;
#define	L1C_TD_BUFLEN_MASK		0x00003FFF
#define	L1C_TD_VLAN_MASK		0xFFFF0000
#define	L1C_TD_BUFLEN_SHIFT		0
#define	L1C_TX_BYTES(x)			\
	(((x) << L1C_TD_BUFLEN_SHIFT) & L1C_TD_BUFLEN_MASK)
#define	L1C_TD_VLAN_SHIFT		16

	uint32_t flags;
#define	L1C_TD_L4HDR_OFFSET_MASK	0x000000FF	/* byte unit */
#define	L1C_TD_TCPHDR_OFFSET_MASK	0x000000FF	/* byte unit */
#define	L1C_TD_PLOAD_OFFSET_MASK	0x000000FF	/* 2 bytes unit */
#define	L1C_TD_CUSTOM_CSUM		0x00000100
#define	L1C_TD_IPCSUM			0x00000200
#define	L1C_TD_TCPCSUM			0x00000400
#define	L1C_TD_UDPCSUM			0x00000800
#define	L1C_TD_TSO			0x00001000
#define	L1C_TD_TSO_DESCV1		0x00000000
#define	L1C_TD_TSO_DESCV2		0x00002000
#define	L1C_TD_CON_VLAN_TAG		0x00004000
#define	L1C_TD_INS_VLAN_TAG		0x00008000
#define	L1C_TD_IPV4_DESCV2		0x00010000
#define	L1C_TD_LLC_SNAP			0x00020000
#define	L1C_TD_ETHERNET			0x00000000
#define	L1C_TD_CUSTOM_CSUM_OFFSET_MASK	0x03FC0000	/* 2 bytes unit */
#define	L1C_TD_CUSTOM_CSUM_EVEN_PAD	0x40000000
#define	L1C_TD_MSS_MASK			0x7FFC0000
#define	L1C_TD_EOP			0x80000000
#define	L1C_TD_L4HDR_OFFSET_SHIFT	0
#define	L1C_TD_TCPHDR_OFFSET_SHIFT	0
#define	L1C_TD_PLOAD_OFFSET_SHIFT	0
#define	L1C_TD_CUSTOM_CSUM_OFFSET_SHIFT	18
#define	L1C_TD_MSS_SHIFT		18

	uint64_t addr;
} l1c_tx_desc_t;
#pragma	pack()

/*
 * All descriptors and CMB/SMB share the same high address.
 */

/* From Freebsd if_alcreg.h */
#define	L1C_RSS_IDT_TABLE0		0x14E0

#define	L1C_RX_BASE_ADDR_HI		0x1540

#define	L1C_TX_BASE_ADDR_HI		0x1544

#define	L1C_SMB_BASE_ADDR_HI		0x1548

#define	L1C_SMB_BASE_ADDR_LO		0x154C

#define	L1C_RD0_HEAD_ADDR_LO		0x1550

#define	L1C_RD1_HEAD_ADDR_LO		0x1554

#define	L1C_RD2_HEAD_ADDR_LO		0x1558

#define	L1C_RD3_HEAD_ADDR_LO		0x155C

#define	L1C_RD_RING_CNT			0x1560
#define	RD_RING_CNT_MASK		0x00000FFF
#define	RD_RING_CNT_SHIFT		0

#define	L1C_RX_BUF_SIZE			0x1564
#define	RX_BUF_SIZE_MASK		0x0000FFFF
/*
 * If larger buffer size than 1536 is specified the controller
 * will be locked up. This is hardware limitation.
 */
#define	RX_BUF_SIZE_MAX			1536

#define	L1C_RRD0_HEAD_ADDR_LO		0x1568

#define	L1C_RRD1_HEAD_ADDR_LO		0x156C

#define	L1C_RRD2_HEAD_ADDR_LO		0x1570

#define	L1C_RRD3_HEAD_ADDR_LO		0x1574

#define	L1C_RRD_RING_CNT		0x1578
#define	RRD_RING_CNT_MASK		0x00000FFF
#define	RRD_RING_CNT_SHIFT		0

#define	L1C_TDH_HEAD_ADDR_LO		0x157C

#define	L1C_TDL_HEAD_ADDR_LO		0x1580

#define	L1C_TD_RING_CNT			0x1584
#define	TD_RING_CNT_MASK		0x0000FFFF
#define	TD_RING_CNT_SHIFT		0

#define	L1C_CMB_BASE_ADDR_LO		0x1588

#define	L1C_RXQ_CFG			0x15A0
#define	RXQ_CFG_ASPM_THROUGHPUT_LIMIT_MASK	0x00000003
#define	RXQ_CFG_ASPM_THROUGHPUT_LIMIT_NONE	0x00000000
#define	RXQ_CFG_ASPM_THROUGHPUT_LIMIT_1M	0x00000001
#define	RXQ_CFG_ASPM_THROUGHPUT_LIMIT_10M	0x00000002
#define	RXQ_CFG_ASPM_THROUGHPUT_LIMIT_100M	0x00000003

#define	L1C_RSS_CPU			0x15B8

/* End of Freebsd if_alcreg.h */

/*
 * PHY registers.
 */
#define	PHY_CDTS_STAT_OK	0x0000
#define	PHY_CDTS_STAT_SHORT	0x0100
#define	PHY_CDTS_STAT_OPEN	0x0200
#define	PHY_CDTS_STAT_INVAL	0x0300
#define	PHY_CDTS_STAT_MASK	0x0300

/*
 * MAC CFG registers (L1C specific)
 */
#define	L1C_CFG_SINGLE_PAUSE_ENB	0x10000000

/*
 * DMA CFG registers (L1C specific)
 */
#define	DMA_CFG_RD_ENB			0x00000400
#define	DMA_CFG_WR_ENB			0x00000800
#define	DMA_CFG_RD_BURST_MASK		0x07
#define	DMA_CFG_RD_BURST_SHIFT		4
#define	DMA_CFG_WR_BURST_MASK		0x07
#define	DMA_CFG_WR_BURST_SHIFT		7
#define	DMA_CFG_SMB_DIS			0x01000000

#define	L1C_RD_LEN_MASK			0x0000FFFF
#define	L1C_RD_LEN_SHIFT		0

#define	L1C_SRAM_RD_ADDR		0x1500
#define	L1C_SRAM_RD_LEN			0x1504
#define	L1C_SRAM_RRD_ADDR		0x1508
#define	L1C_SRAM_RRD_LEN		0x150C
#define	L1C_SRAM_TPD_ADDR		0x1510
#define	L1C_SRAM_TPD_LEN		0x1514
#define	L1C_SRAM_TRD_ADDR		0x1518
#define	L1C_SRAM_TRD_LEN		0x151C
#define	L1C_SRAM_RX_FIFO_ADDR		0x1520
#define	L1C_SRAM_RX_FIFO_LEN		0x1524
#define	L1C_SRAM_TX_FIFO_ADDR		0x1528
#define	L1C_SRAM_TX_FIFO_LEN		0x152C

#define	L1C_RXQ_CFG_RD_BURST_MASK	0x03f00000
#define	L1C_RXQ_CFG_RD_BURST_SHIFT	20

#define	L1C_TXQ_CFG			0x1590
#define	TXQ_CFG_TPD_FETCH_THRESH_MASK	0x00003F00
#define	L1C_TXQ_CFG_TPD_BURST_DEFAULT	5
#define	TXQ_CFG_TPD_FETCH_THRESH_SHIFT	8
#define	TXQ_CFG_TPD_FETCH_DEFAULT	16

#define	L1C_TXF_WATER_MARK		0x1598	/* 8 bytes unit */
#define	TXF_WATER_MARK_HI_MASK		0x00000FFF
#define	TXF_WATER_MARK_LO_MASK		0x0FFF0000
#define	TXF_WATER_MARK_BURST_ENB	0x80000000
#define	TXF_WATER_MARK_LO_SHIFT		0
#define	TXF_WATER_MARK_HI_SHIFT		16

#define	L1C_RD_DMA_CFG			0x15AC
#define	RD_DMA_CFG_THRESH_MASK		0x00000FFF	/* 8 bytes unit */
#define	RD_DMA_CFG_TIMER_MASK		0xFFFF0000
#define	RD_DMA_CFG_THRESH_SHIFT		0
#define	RD_DMA_CFG_TIMER_SHIFT		16
#define	RD_DMA_CFG_THRESH_DEFAULT	0x100
#define	RD_DMA_CFG_TIMER_DEFAULT	0
#define	RD_DMA_CFG_TICK_USECS		8
#define	L1C_RD_DMA_CFG_USECS(x)		((x) / RD_DMA_CFG_TICK_USECS)

/* CMB DMA Write Threshold Register */
#define	L1C_CMB_WR_THRESH		0x15D4
#define	CMB_WR_THRESH_RRD_MASK		0x000007FF
#define	CMB_WR_THRESH_TPD_MASK		0x07FF0000
#define	CMB_WR_THRESH_RRD_SHIFT		0
#define	CMB_WR_THRESH_RRD_DEFAULT	4
#define	CMB_WR_THRESH_TPD_SHIFT		16
#define	CMB_WR_THRESH_TPD_DEFAULT	4

/* SMB auto DMA timer register */
#define	L1C_SMB_TIMER			0x15E4

#define	L1C_CSMB_CTRL			0x15D0
#define	CSMB_CTRL_CMB_KICK		0x00000001
#define	CSMB_CTRL_SMB_KICK		0x00000002
#define	CSMB_CTRL_CMB_ENB		0x00000004
#define	CSMB_CTRL_SMB_ENB		0x00000008

/* From Freebsd if_alcreg.h */
#define	L1C_INTR_SMB			0x00000001
#define	L1C_INTR_TIMER			0x00000002
#define	L1C_INTR_MANUAL_TIMER		0x00000004
#define	L1C_INTR_RX_FIFO_OFLOW		0x00000008
#define	L1C_INTR_RD0_UNDERRUN		0x00000010
#define	L1C_INTR_RD1_UNDERRUN		0x00000020
#define	L1C_INTR_RD2_UNDERRUN		0x00000040
#define	L1C_INTR_RD3_UNDERRUN		0x00000080
#define	L1C_INTR_TX_FIFO_UNDERRUN	0x00000100
#define	L1C_INTR_DMA_RD_TO_RST		0x00000200
#define	L1C_INTR_DMA_WR_TO_RST		0x00000400
#define	L1C_INTR_TX_CREDIT		0x00000800
#define	L1C_INTR_GPHY			0x00001000
#define	L1C_INTR_GPHY_LOW_PW		0x00002000
#define	L1C_INTR_TXQ_TO_RST		0x00004000
#define	L1C_INTR_TX_PKT			0x00008000
#define	L1C_INTR_RX_PKT0		0x00010000
#define	L1C_INTR_RX_PKT1		0x00020000
#define	L1C_INTR_RX_PKT2		0x00040000
#define	L1C_INTR_RX_PKT3		0x00080000
#define	L1C_INTR_MAC_RX			0x00100000
#define	L1C_INTR_MAC_TX			0x00200000
#define	L1C_INTR_UNDERRUN		0x00400000
#define	L1C_INTR_FRAME_ERROR		0x00800000
#define	L1C_INTR_FRAME_OK		0x01000000
#define	L1C_INTR_CSUM_ERROR		0x02000000
#define	L1C_INTR_PHY_LINK_DOWN		0x04000000
#define	L1C_INTR_DIS_INT		0x80000000

#define	L1C_INTR_RX_PKT			L1C_INTR_RX_PKT0
#define	L1C_INTR_RD_UNDERRUN		L1C_INTR_RD0_UNDERRUN

#define	L1C_INTRS				\
	(L1C_INTR_DMA_RD_TO_RST | L1C_INTR_DMA_WR_TO_RST | \
	L1C_INTR_TXQ_TO_RST| L1C_INTR_RX_PKT | L1C_INTR_TX_PKT | \
	L1C_INTR_RX_FIFO_OFLOW | L1C_INTR_RD_UNDERRUN | \
	L1C_INTR_TX_FIFO_UNDERRUN)

#define	L1C_RXQ_RRD_PAUSE_THRESH	0x15AC
#define	RXQ_RRD_PAUSE_THRESH_HI_MASK	0x00000FFF
#define	RXQ_RRD_PAUSE_THRESH_LO_MASK	0x0FFF0000
#define	RXQ_RRD_PAUSE_THRESH_HI_SHIFT	0
#define	RXQ_RRD_PAUSE_THRESH_LO_SHIFT	16

/* RX/TX count-down timer to trigger CMB-write. */
#define	L1C_CMB_WR_TIMER			0x15D8
#define	CMB_WR_TIMER_RX_MASK		0x0000FFFF
#define	CMB_WR_TIMER_TX_MASK		0xFFFF0000
#define	CMB_WR_TIMER_RX_SHIFT		0
#define	CMB_WR_TIMER_TX_SHIFT		16

/*
 * Useful macros.
 */
#define	L1C_RX_NSEGS(x)	\
	(((x) & L1C_RRD_NSEGS_MASK) >> L1C_RRD_NSEGS_SHIFT)
#define	L1C_RX_CONS(x)	\
	(((x) & L1C_RRD_CONS_MASK) >> L1C_RRD_CONS_SHIFT)
#define	L1C_RX_CSUM(x)	\
	(((x) & L1C_RRD_CSUM_MASK) >> L1C_RRD_CSUM_SHIFT)
#define	L1C_RX_BYTES(x)	\
	(((x) & L1C_RRD_LEN_MASK) >> L1C_RRD_LEN_SHIFT)


#ifdef __cplusplus
}
#endif

#endif	/* _ATGE_L1C_REG_H */

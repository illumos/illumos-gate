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

#ifndef _ATGE_L1E_REG_H
#define	_ATGE_L1E_REG_H

#ifdef __cplusplus
	extern "C" {
#endif

/*
 * Number of RX Rings (or pages) we use.
 */
#define	L1E_RX_PAGES		2

#pragma	pack(1)
typedef	struct	rx_rs	{
	uint32_t	seqno;
	uint32_t	length;
	uint32_t	flags;
	uint32_t	vtags;
} rx_rs_t;

typedef	struct	rx_cmb {
	uint32_t	cmb[L1E_RX_PAGES];
} rx_cmb_t;
#pragma	pack()

/* Master configuration */
#define	L1E_MASTER_CFG			0x1400
#define	L1E_MASTER_RESET		0x00000001
#define	L1E_MASTER_MTIMER_ENB		0x00000002
#define	L1E_MASTER_IM_TX_TIMER_ENB	0x00000004
#define	L1E_MASTER_MANUAL_INT_ENB	0x00000008
#define	L1E_MASTER_IM_RX_TIMER_ENB	0x00000020
#define	L1E_MASTER_CHIP_REV_MASK	0x00FF0000
#define	L1E_MASTER_CHIP_ID_MASK		0xFF000000
#define	L1E_MASTER_CHIP_REV_SHIFT	16
#define	L1E_MASTER_CHIP_ID_SHIFT	24


/*
 * DMA CFG registers (L1E specific).
 */
#define	DMA_CFG_RD_REQ_PRI		0x00000400
#define	DMA_CFG_TXCMB_ENB		0x00100000
#define	DMA_CFG_RD_BURST_MASK		0x07
#define	DMA_CFG_RD_BURST_SHIFT		4
#define	DMA_CFG_WR_BURST_MASK		0x07
#define	DMA_CFG_WR_BURST_SHIFT		7

#define	L1E_TX_RING_CNT_MIN		32
#define	L1E_TX_RING_CNT_MAX		1020
#define	L1E_TX_RING_ALIGN		8
#define	L1E_RX_PAGE_ALIGN		32
#define	L1E_CMB_ALIGN			32
#define	L1E_MAX_FRAMELEN		ETHERMAX

#define	L1E_RX_PAGE_SZ_MIN		(8 * 1024)
#define	L1E_RX_PAGE_SZ_MAX		(1024 * 1024)
#define	L1E_RX_FRAMES_PAGE		128
#define	L1E_RX_PAGE_SZ	\
	(ROUNDUP(L1E_MAX_FRAMELEN, L1E_RX_PAGE_ALIGN) * L1E_RX_FRAMES_PAGE)
#define	L1E_TX_CMB_SZ			(sizeof (uint32_t))
#define	L1E_RX_CMB_SZ			(sizeof (uint32_t))

#define	L1E_PROC_MAX	\
	((L1E_RX_PAGE_SZ * L1E_RX_PAGES) / ETHERMAX)
#define	L1E_PROC_DEFAULT		(L1E_PROC_MAX / 4)

#define	L1E_INTRS                                               \
	(INTR_DMA_RD_TO_RST | INTR_DMA_WR_TO_RST |              \
	INTR_RX_PKT | INTR_TX_PKT | INTR_RX_FIFO_OFLOW |        \
	INTR_TX_FIFO_UNDERRUN | INTR_SMB)

#define	L1E_RSS_IDT_TABLE0		0x1560
#define	L1E_RSS_CPU			0x157C

#define	L1E_SRAM_RX_FIFO_LEN		0x1524

#define	L1E_PHY_STATUS			0x1418
#define	PHY_STATUS_100M			0x00020000

#define	L1E_SMB_STAT_TIMER		0x15C4

#define	GPHY_CTRL_EXT_RESET		0x0001
#define	GPHY_CTRL_PIPE_MOD		0x0002
#define	GPHY_CTRL_BERT_START		0x0010
#define	GPHY_CTRL_GL1E_25M_ENB		0x0020
#define	GPHY_CTRL_LPW_EXIT		0x0040
#define	GPHY_CTRL_PHY_IDDQ		0x0080
#define	GPHY_CTRL_PHY_IDDQ_DIS		0x0100
#define	GPHY_CTRL_PCLK_SEL_DIS		0x0200
#define	GPHY_CTRL_HIB_EN		0x0400
#define	GPHY_CTRL_HIB_PULSE		0x0800
#define	GPHY_CTRL_SEL_ANA_RESET		0x1000
#define	GPHY_CTRL_PHY_PLL_ON		0x2000
#define	GPHY_CTRL_PWDOWN_HW		0x4000

#define	RXF_VALID			0x01

#define	L1E_RXF0_PAGE0			0x15F4
#define	L1E_RXF0_PAGE1			0x15F5

#define	L1E_RXF0_PAGE0_ADDR_LO		0x1544
#define	L1E_RXF0_PAGE1_ADDR_LO		0x1548

#define	L1E_RXF_PAGE_SIZE		0x1558

#define	L1E_INT_TRIG_THRESH		0x15C8
#define	INT_TRIG_TX_THRESH_MASK		0x0000FFFF
#define	INT_TRIG_RX_THRESH_MASK		0xFFFF0000
#define	INT_TRIG_TX_THRESH_SHIFT	0
#define	INT_TRIG_RX_THRESH_SHIFT	16

#define	L1E_INT_TRIG_TIMER		0x15CC
#define	INT_TRIG_TX_TIMER_MASK		0x0000FFFF
#define	INT_TRIG_RX_TIMER_MASK		0x0000FFFF
#define	INT_TRIG_TX_TIMER_SHIFT		0
#define	INT_TRIG_RX_TIMER_SHIFT		16

#define	TX_COALSC_PKT_1e		0x15C8  /* W: L1E */
#define	RX_COALSC_PKT_1e		0x15CA  /* W: L1E */
#define	TX_COALSC_TO_1e			0x15CC  /* W: L1E */
#define	RX_COALSC_TO_1e			0x15CE  /* W: L1E */

#define	L1E_HOST_RXF0_PAGEOFF		0x1800
#define	L1E_TPD_CONS_IDX		0x1804
#define	L1E_HOST_RXF1_PAGEOFF		0x1808
#define	L1E_HOST_RXF2_PAGEOFF		0x180C
#define	L1E_HOST_RXF3_PAGEOFF		0x1810
#define	L1E_RXF0_CMB0_ADDR_LO		0x1820
#define	L1E_RXF0_CMB1_ADDR_LO		0x1824
#define	L1E_RXF1_CMB0_ADDR_LO		0x1828
#define	L1E_RXF1_CMB1_ADDR_LO		0x182C
#define	L1E_RXF2_CMB0_ADDR_LO		0x1830
#define	L1E_RXF2_CMB1_ADDR_LO		0x1834
#define	L1E_RXF3_CMB0_ADDR_LO		0x1838
#define	L1E_RXF3_CMB1_ADDR_LO		0x183C
#define	L1E_TX_CMB_ADDR_LO		0x1840
#define	L1E_SMB_ADDR_LO			0x1844

#define	L1E_RD_SEQNO_MASK		0x0000FFFF
#define	L1E_RD_HASH_MASK		0xFFFF0000
#define	L1E_RD_SEQNO_SHIFT		0
#define	L1E_RD_HASH_SHIFT		16
#define	L1E_RX_SEQNO(x)		\
	(((x) & L1E_RD_SEQNO_MASK) >> L1E_RD_SEQNO_SHIFT)
#define	L1E_RD_CSUM_MASK		0x0000FFFF
#define	L1E_RD_LEN_MASK			0x3FFF0000
#define	L1E_RD_CPU_MASK			0xC0000000
#define	L1E_RD_CSUM_SHIFT		0
#define	L1E_RD_LEN_SHIFT		16
#define	L1E_RD_CPU_SHIFT		30
#define	L1E_RX_CSUM(x)	\
	(((x) & L1E_RD_CSUM_MASK) >> L1E_RD_CSUM_SHIFT)
#define	L1E_RX_BYTES(x)	\
	(((x) & L1E_RD_LEN_MASK) >> L1E_RD_LEN_SHIFT)
#define	L1E_RX_CPU(x)	\
	(((x) & L1E_RD_CPU_MASK) >> L1E_RD_CPU_SHIFT)

#define	L1E_RD_RSS_IPV4			0x00000001
#define	L1E_RD_RSS_IPV4_TCP		0x00000002
#define	L1E_RD_RSS_IPV6			0x00000004
#define	L1E_RD_RSS_IPV6_TCP		0x00000008
#define	L1E_RD_IPV6			0x00000010
#define	L1E_RD_IPV4_FRAG		0x00000020
#define	L1E_RD_IPV4_DF			0x00000040
#define	L1E_RD_802_3			0x00000080
#define	L1E_RD_VLAN			0x00000100
#define	L1E_RD_ERROR			0x00000200
#define	L1E_RD_IPV4			0x00000400
#define	L1E_RD_UDP			0x00000800
#define	L1E_RD_TCP			0x00001000
#define	L1E_RD_BCAST			0x00002000
#define	L1E_RD_MCAST			0x00004000
#define	L1E_RD_PAUSE			0x00008000
#define	L1E_RD_CRC			0x00010000
#define	L1E_RD_CODE			0x00020000
#define	L1E_RD_DRIBBLE			0x00040000
#define	L1E_RD_RUNT			0x00080000
#define	L1E_RD_OFLOW			0x00100000
#define	L1E_RD_TRUNC			0x00200000
#define	L1E_RD_IPCSUM_NOK		0x00400000
#define	L1E_RD_TCP_UDPCSUM_NOK		0x00800000
#define	L1E_RD_LENGTH_NOK		0x01000000
#define	L1E_RD_DES_ADDR_FILTERED	0x02000000

/* TX descriptor fields */
#define	L1E_TD_VLAN_MASK		0xFFFF0000
#define	L1E_TD_PKT_INT			0x00008000
#define	L1E_TD_DMA_INT			0x00004000
#define	L1E_TD_VLAN_SHIFT		16
#define	L1E_TX_VLAN_TAG(x)	\
	(((x) << 4) | ((x) >> 13) | (((x) >> 9) & 8))
#define	L1E_TD_BUFLEN_SHIFT		0
#define	L1E_TD_MSS			0xFFF80000
#define	L1E_TD_TSO_HDR			0x00040000
#define	L1E_TD_TCPHDR_LEN		0x0003C000
#define	L1E_TD_IPHDR_LEN		0x00003C00
#define	L1E_TD_IPV6HDR_LEN2		0x00003C00
#define	L1E_TD_LLC_SNAP			0x00000200
#define	L1E_TD_VLAN_TAGGED		0x00000100
#define	L1E_TD_UDPCSUM			0x00000080
#define	L1E_TD_TCPCSUM			0x00000040
#define	L1E_TD_IPCSUM			0x00000020
#define	L1E_TD_IPV6HDR_LEN1		0x000000E0
#define	L1E_TD_TSO			0x00000010
#define	L1E_TD_CXSUM			0x00000008
#define	L1E_TD_INSERT_VLAN_TAG		0x00000004
#define	L1E_TD_IPV6			0x00000002

#define	L1E_TD_CSUM_PLOADOFFSET		0x00FF0000
#define	L1E_TD_CSUM_XSUMOFFSET		0xFF000000
#define	L1E_TD_CSUM_XSUMOFFSET_SHIFT	24
#define	L1E_TD_CSUM_PLOADOFFSET_SHIFT	16
#define	L1E_TD_MSS_SHIFT		19
#define	L1E_TD_TCPHDR_LEN_SHIFT		14
#define	L1E_TD_IPHDR_LEN_SHIFT		10

#define	L1E_JUMBO_FRAMELEN		8132

#define	L1E_TX_JUMBO_THRESH		0x1584
#define	TX_JUMBO_THRESH_MASK		0x000007FF
#define	TX_JUMBO_THRESH_SHIFT		0
#define	TX_JUMBO_THRESH_UNIT		8
#define	TX_JUMBO_THRESH_UNIT_SHIFT	3

/*
 * Statistics counters collected by the MAC.
 * AR81xx requires register access to get MAC statistics
 * and the format of statistics seems to be the same of L1
 * except for tx_abort field in TX stats. So keep it separate for simplicity.
 */
#define	L1E_RX_MIB_BASE			0x1700
#define	L1E_TX_MIB_BASE			0x1760

#pragma	pack(1)
typedef	struct smb {
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
	uint32_t rx_rrs_errs;
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
	uint32_t tx_abort;
	uint32_t tx_underrun;
	uint32_t tx_desc_underrun;
	uint32_t tx_lenerrs;
	uint32_t tx_pkts_truncated;
	uint32_t tx_bcast_bytes;
	uint32_t tx_mcast_bytes;
} atge_l1e_smb_t;
#pragma	pack()

#ifdef __cplusplus
}
#endif

#endif	/* _ATGE_L1E_REG_H */

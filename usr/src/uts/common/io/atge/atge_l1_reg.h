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
 * Copyright (c) 2012 Gary Mills
 */

#ifndef _ATGE_L1_REG_H
#define	_ATGE_L1_REG_H

#ifdef __cplusplus
	extern "C" {
#endif

#pragma	pack(1)
typedef	struct	l1_cmb {
	uint32_t	intr_status;
	uint32_t	rx_prod_cons;
	uint32_t	tx_prod_cons;
} l1_cmb_t;

typedef	struct	l1_rx_desc {
	uint64_t	addr;
	uint32_t	len;
} l1_rx_desc_t;

typedef	struct	l1_rx_rdesc {
	uint32_t	index;
	uint32_t	len;
	uint32_t	flags;
	uint32_t	vtags;
} l1_rx_rdesc_t;

/*
 * Statistics counters collected by the MAC
 */
typedef	struct l1_smb {
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
} atge_l1_smb_t;
#pragma	pack()

#define	L1_RX_RING_CNT		256
#define	L1_RR_RING_CNT		(ATGE_TX_RING_CNT + L1_RX_RING_CNT)

#define	L1_RING_ALIGN		16
#define	L1_TX_RING_ALIGN	16
#define	L1_RX_RING_ALIGN	16
#define	L1_RR_RING_ALIGN	16
#define	L1_CMB_ALIGN		16
#define	L1_SMB_ALIGN		16

#define	L1_CMB_BLOCK_SZ	sizeof (struct l1_cmb)
#define	L1_SMB_BLOCK_SZ	sizeof (struct l1_smb)

#define	L1_RX_RING_SZ		\
	(sizeof (struct l1_rx_desc) * L1_RX_RING_CNT)

#define	L1_RR_RING_SZ		\
	(sizeof (struct l1_rx_rdesc) * L1_RR_RING_CNT)

/*
 * For RX
 */
#define	L1_RRD_CONS_SHIFT		16
#define	L1_RRD_NSEGS_MASK		0x000000FF
#define	L1_RRD_CONS_MASK		0xFFFF0000
#define	L1_RRD_NSEGS_SHIFT		0
#define	L1_RRD_LEN_MASK			0xFFFF0000
#define	L1_RRD_CSUM_MASK		0x0000FFFF
#define	L1_RRD_CSUM_SHIFT		0
#define	L1_RRD_LEN_SHIFT		16
#define	L1_RRD_ETHERNET			0x00000080
#define	L1_RRD_VLAN			0x00000100
#define	L1_RRD_ERROR			0x00000200
#define	L1_RRD_IPV4			0x00000400
#define	L1_RRD_UDP			0x00000800
#define	L1_RRD_TCP			0x00001000
#define	L1_RRD_BCAST			0x00002000
#define	L1_RRD_MCAST			0x00004000
#define	L1_RRD_PAUSE			0x00008000
#define	L1_RRD_CRC			0x00010000
#define	L1_RRD_CODE			0x00020000
#define	L1_RRD_DRIBBLE			0x00040000
#define	L1_RRD_RUNT			0x00080000
#define	L1_RRD_OFLOW			0x00100000
#define	L1_RRD_TRUNC			0x00200000
#define	L1_RRD_IPCSUM_NOK		0x00400000
#define	L1_RRD_TCP_UDPCSUM_NOK		0x00800000
#define	L1_RRD_LENGTH_NOK		0x01000000
#define	L1_RRD_DES_ADDR_FILTERED	0x02000000
#define	RRD_PROD_MASK			0x0000FFFF
#define	TPD_CONS_MASK			0xFFFF0000
#define	TPD_CONS_SHIFT			16
#define	CMB_UPDATED			0x00000001
#define	RRD_PROD_SHIFT			0

/*
 * All descriptors and CMB/SMB share the same high address.
 */
#define	L1_DESC_ADDR_HI	0x1540
#define	L1_DESC_RD_ADDR_LO	0x1544
#define	L1_DESC_RRD_ADDR_LO	0x1548
#define	L1_DESC_TPD_ADDR_LO	0x154C
#define	L1_DESC_CMB_ADDR_LO	0x1550
#define	L1_DESC_SMB_ADDR_LO	0x1554
#define	L1_DESC_RRD_RD_CNT	0x1558
#define	DESC_RRD_CNT_SHIFT	16
#define	DESC_RRD_CNT_MASK	0x07FF0000
#define	DESC_RD_CNT_SHIFT	0
#define	DESC_RD_CNT_MASK	0x000007FF

/*
 * PHY registers.
 */
#define	PHY_CDTS_STAT_OK	0x0000
#define	PHY_CDTS_STAT_SHORT	0x0100
#define	PHY_CDTS_STAT_OPEN	0x0200
#define	PHY_CDTS_STAT_INVAL	0x0300
#define	PHY_CDTS_STAT_MASK	0x0300

/*
 * DMA CFG registers (L1 specific)
 */
#define	DMA_CFG_RD_ENB		0x00000400
#define	DMA_CFG_WR_ENB		0x00000800
#define	DMA_CFG_RD_BURST_MASK	0x07
#define	DMA_CFG_RD_BURST_SHIFT	4
#define	DMA_CFG_WR_BURST_MASK	0x07
#define	DMA_CFG_WR_BURST_SHIFT	7

#define	L1_RD_LEN_MASK		0x0000FFFF
#define	L1_RD_LEN_SHIFT	0

#define	L1_SRAM_RD_ADDR		0x1500
#define	L1_SRAM_RD_LEN			0x1504
#define	L1_SRAM_RRD_ADDR		0x1508
#define	L1_SRAM_RRD_LEN		0x150C
#define	L1_SRAM_TPD_ADDR		0x1510
#define	L1_SRAM_TPD_LEN		0x1514
#define	L1_SRAM_TRD_ADDR		0x1518
#define	L1_SRAM_TRD_LEN		0x151C
#define	L1_SRAM_RX_FIFO_ADDR		0x1520
#define	L1_SRAM_RX_FIFO_LEN		0x1524
#define	L1_SRAM_TX_FIFO_ADDR		0x1528
#define	L1_SRAM_TX_FIFO_LEN		0x152C

#define	RXQ_CFG_RD_BURST_MASK		0x000000FF
#define	RXQ_CFG_RRD_BURST_THRESH_MASK	0x0000FF00
#define	RXQ_CFG_RD_PREF_MIN_IPG_MASK	0x001F0000
#define	RXQ_CFG_RD_BURST_SHIFT		0
#define	RXQ_CFG_RD_BURST_DEFAULT	8
#define	RXQ_CFG_RRD_BURST_THRESH_SHIFT	8
#define	RXQ_CFG_RRD_BURST_THRESH_DEFAULT 8
#define	RXQ_CFG_RD_PREF_MIN_IPG_SHIFT	16
#define	RXQ_CFG_RD_PREF_MIN_IPG_DEFAULT	1

#define	TXQ_CFG_TPD_FETCH_THRESH_MASK	0x00003F00
#define	TXQ_CFG_TPD_FETCH_THRESH_SHIFT	8
#define	TXQ_CFG_TPD_FETCH_DEFAULT	16

#define	L1_TX_JUMBO_TPD_TH_IPG		0x1584
#define	TX_JUMBO_TPD_TH_MASK		0x000007FF
#define	TX_JUMBO_TPD_IPG_MASK		0x001F0000
#define	TX_JUMBO_TPD_TH_SHIFT		0
#define	TX_JUMBO_TPD_IPG_SHIFT		16
#define	TX_JUMBO_TPD_IPG_DEFAULT	1

/* CMB DMA Write Threshold Register */
#define	L1_CMB_WR_THRESH		0x15D4
#define	CMB_WR_THRESH_RRD_MASK		0x000007FF
#define	CMB_WR_THRESH_TPD_MASK		0x07FF0000
#define	CMB_WR_THRESH_RRD_SHIFT		0
#define	CMB_WR_THRESH_RRD_DEFAULT	4
#define	CMB_WR_THRESH_TPD_SHIFT		16
#define	CMB_WR_THRESH_TPD_DEFAULT	4

/* SMB auto DMA timer register */
#define	L1_SMB_TIMER			0x15E4

#define	L1_CSMB_CTRL			0x15D0
#define	CSMB_CTRL_CMB_KICK		0x00000001
#define	CSMB_CTRL_SMB_KICK		0x00000002
#define	CSMB_CTRL_CMB_ENB		0x00000004
#define	CSMB_CTRL_SMB_ENB		0x00000008

#define	INTR_RX_DMA			0x00080000
#define	INTR_CMB_RX			0x00100000
#define	INTR_CMB_TX			0x00200000
#define	INTR_DIS_SMB			0x20000000

#define	L1_INTRS	\
	(INTR_SMB | INTR_DMA_RD_TO_RST | INTR_DMA_WR_TO_RST |	\
	INTR_CMB_TX | INTR_CMB_RX | INTR_RX_FIFO_OFLOW | INTR_TX_FIFO_UNDERRUN)

#define	L1_RXQ_RRD_PAUSE_THRESH	0x15AC
#define	RXQ_RRD_PAUSE_THRESH_HI_MASK	0x00000FFF
#define	RXQ_RRD_PAUSE_THRESH_LO_MASK	0x0FFF0000
#define	RXQ_RRD_PAUSE_THRESH_HI_SHIFT	0
#define	RXQ_RRD_PAUSE_THRESH_LO_SHIFT	16

/* RX/TX count-down timer to trigger CMB-write. */
#define	L1_CMB_WR_TIMER			0x15D8
#define	CMB_WR_TIMER_RX_MASK		0x0000FFFF
#define	CMB_WR_TIMER_TX_MASK		0xFFFF0000
#define	CMB_WR_TIMER_RX_SHIFT		0
#define	CMB_WR_TIMER_TX_SHIFT		16

/*
 * Useful macros.
 */
#define	L1_RX_NSEGS(x)	\
	(((x) & L1_RRD_NSEGS_MASK) >> L1_RRD_NSEGS_SHIFT)
#define	L1_RX_CONS(x)	\
	(((x) & L1_RRD_CONS_MASK) >> L1_RRD_CONS_SHIFT)
#define	L1_RX_CSUM(x)	\
	(((x) & L1_RRD_CSUM_MASK) >> L1_RRD_CSUM_SHIFT)
#define	L1_RX_BYTES(x)	\
	(((x) & L1_RRD_LEN_MASK) >> L1_RRD_LEN_SHIFT)


#ifdef __cplusplus
}
#endif

#endif	/* _ATGE_L1_REG_H */

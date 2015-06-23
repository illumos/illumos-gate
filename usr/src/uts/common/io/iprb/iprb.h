/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _IPRB_H
#define	_IPRB_H

/*
 * iprb - Intel Pro/100B Ethernet Driver
 */

/*
 * Tunables.
 */
#define	NUM_TX		128	/* outstanding tx queue */
#define	NUM_RX		128	/* outstanding rx queue */

/* timeouts for the rx and tx watchdogs (nsec) */
#define	RX_WATCHDOG	(15 * NANOSEC)
#define	TX_WATCHDOG	(15 * NANOSEC)

/*
 * Driver structures.
 */
typedef struct {
	ddi_acc_handle_t	acch;
	ddi_dma_handle_t	dmah;
	caddr_t			vaddr;
	uint32_t		paddr;
} iprb_dma_t;

typedef struct iprb_mcast {
	list_node_t		node;
	uint8_t			addr[6];
} iprb_mcast_t;

typedef struct iprb {
	dev_info_t		*dip;
	ddi_acc_handle_t	pcih;
	ddi_acc_handle_t	regsh;
	caddr_t			regs;

	uint16_t		devid;
	uint8_t			revid;

	mac_handle_t		mach;
	mii_handle_t		miih;

	ddi_intr_handle_t	intrh;

	ddi_periodic_t		perh;

	kmutex_t		culock;
	kmutex_t		rulock;

	uint8_t			factaddr[6];
	uint8_t			curraddr[6];

	int			nmcast;
	list_t			mcast;
	boolean_t		promisc;
	iprb_dma_t		cmds[NUM_TX];
	iprb_dma_t		rxb[NUM_RX];
	iprb_dma_t		stats;
	hrtime_t		stats_time;

	uint16_t		cmd_head;
	uint16_t		cmd_last;
	uint16_t		cmd_tail;
	uint16_t		cmd_count;

	uint16_t		rx_index;
	uint16_t		rx_last;
	hrtime_t		rx_wdog;
	hrtime_t		rx_timeout;
	hrtime_t		tx_wdog;
	hrtime_t		tx_timeout;

	uint16_t		eeprom_bits;

	boolean_t		running;
	boolean_t		suspended;
	boolean_t		wantw;
	boolean_t		rxhangbug;
	boolean_t		resumebug;
	boolean_t		is557;
	boolean_t		canpause;
	boolean_t		canmwi;

	/*
	 * Statistics
	 */
	uint64_t		ipackets;
	uint64_t		rbytes;
	uint64_t		multircv;
	uint64_t		brdcstrcv;
	uint64_t		opackets;
	uint64_t		obytes;
	uint64_t		multixmt;
	uint64_t		brdcstxmt;
	uint64_t		ex_coll;
	uint64_t		late_coll;
	uint64_t		uflo;
	uint64_t		defer_xmt;
	uint64_t		one_coll;
	uint64_t		multi_coll;
	uint64_t		collisions;
	uint64_t		fcs_errs;
	uint64_t		align_errs;
	uint64_t		norcvbuf;
	uint64_t		oflo;
	uint64_t		runt;
	uint64_t		nocarrier;
	uint64_t		toolong;
	uint64_t		macxmt_errs;
	uint64_t		macrcv_errs;
} iprb_t;

/*
 * Idenfication values.
 */
#define	REV_82557	1
#define	REV_82558_A4	4
#define	REV_82558_B0	5
#define	REV_82559_A0	8
#define	REV_82559S_A	9
#define	REV_82550	12
#define	REV_82550_C	13
#define	REV_82551_E	14
#define	REV_82551_F	15
#define	REV_82551_10	16

/*
 * Device registers.
 */
#define	CSR_STATE	0x00
#define	CSR_STS		0x01
#define	CSR_CMD		0x02
#define	CSR_INTCTL	0x03
#define	CSR_GEN_PTR	0x04
#define	CSR_PORT	0x08
#define	CSR_EECTL	0x0e
#define	CSR_MDICTL	0x10

#define	STATE_CUS	0xc0	/* CU state (mask) */
#define	STATE_CUS_IDLE	0x00	/* CU idle */
#define	STATE_CUS_SUSP	0x40	/* CU suspended */
#define	STATE_CUS_LPQA	0x80	/* LPQ active */
#define	STATE_CUS_HQPA	0xc0	/* HQP active */
#define	STATE_RUS	0x3c	/* RU state (mask) */
#define	STATE_RUS_IDLE	0x00	/* RU idle */
#define	STATE_RUS_SUSP	0x04	/* RU suspended */
#define	STATE_RUS_NORES	0x08	/* RU no resources */
#define	STATE_RUS_READY	0x10	/* RU ready */

#define	STS_FCP		0x01	/* flow control pause */
#define	STS_RSVD	0x02	/* reserved bit */
#define	STS_SWI		0x04	/* software interrupt */
#define	STS_MDI		0x08	/* MDI read/write done */
#define	STS_RNR		0x10	/* RU not ready */
#define	STS_CNA		0x20	/* CU state change */
#define	STS_FR		0x40	/* frame receive */
#define	STS_CX		0x80	/* cmd exec done */

#define	CMD_CUC		0xf0	/* CU command (mask) */
#define	CUC_NOP		0x00	/* no operation */
#define	CUC_START	0x10	/* start CU */
#define	CUC_RESUME	0x20	/* resume CU */
#define	CUC_STATSBASE	0x40	/* load statistics address */
#define	CUC_STATS	0x50	/* dump statistics */
#define	CUC_CUBASE	0x60	/* load CU base address */
#define	CUC_STATS_RST	0x70	/* dump statistics and reset */
#define	CUC_SRES	0xa0	/* static resume CU */
#define	CMD_RUC		0x07	/* RU command (mask) */
#define	RUC_NOP		0x00	/* no operation */
#define	RUC_START	0x01	/* start RU */
#define	RUC_RESUME	0x02	/* resume RU */
#define	RUC_DMAREDIR	0x03	/* receive DMA redirect */
#define	RUC_ABORT	0x40	/* abort RU */
#define	RUC_HDRSZ	0x50	/* load header data size */
#define	RUC_RUBASE	0x60	/* load RU base address */

#define	INTCTL_MASK	0x01	/* disable all interrupts */
#define	INTCTL_SI	0x02	/* generate software interrupt */
#define	INTCTL_FCP	0x04	/* flow control pause */
#define	INTCTL_ER	0x08	/* early receive */
#define	INTCTL_RNR	0x10	/* RU not ready */
#define	INTCTL_CNA	0x20	/* CU state change */
#define	INTCTL_FR	0x40	/* frame receive */
#define	INTCTL_CX	0x80	/* cmd exec done */

#define	PORT_SW_RESET	0x00
#define	PORT_SELF_TEST	0x01
#define	PORT_SEL_RESET	0x02

#define	EEPROM_EEDO	0x0008	/* data out */
#define	EEPROM_EEDI	0x0004	/* data in */
#define	EEPROM_EECS	0x0002	/* chip select */
#define	EEPROM_EESK	0x0001	/* clock */

#define	EEPROM_OP_RD	0x06
#define	EEPROM_OP_WR	0x05
#define	EEPROM_OP_WE	0x13	/* write enable */
#define	EEPROM_OP_WD	0x13	/* write disable */

#define	MDI_IE		0x20000000	/* interrupt enable */
#define	MDI_R		0x10000000	/* ready */
#define	MDI_OP_RD	0x08000000	/* read */
#define	MDI_OP_WR	0x04000000	/* write */
#define	MDI_PHYAD_SHIFT	21
#define	MDI_REGAD_SHIFT	16

#define	GET8(ip, offset)					\
	ddi_get8(ip->regsh, (void *)(ip->regs + (offset)))
#define	GET16(ip, offset)					\
	ddi_get16(ip->regsh, (void *)(ip->regs + (offset)))
#define	GET32(ip, offset)					\
	ddi_get32(ip->regsh, (void *)(ip->regs + (offset)))
#define	PUT8(ip, offset, val)						\
	ddi_put8(ip->regsh, (void *)(ip->regs + (offset)), (val))
#define	PUT16(ip, offset, val)						\
	ddi_put16(ip->regsh, (void *)(ip->regs + (offset)), (val))
#define	PUT32(ip, offset, val)						\
	ddi_put32(ip->regsh, (void *)(ip->regs + (offset)), (val))


#define	PUTDMA8(d, off, val)					\
	ddi_put8(d->acch, (void *)(d->vaddr + (off)), LE_8(val))
#define	PUTDMA16(d, off, val)						\
	ddi_put16(d->acch, (void *)(d->vaddr + (off)), LE_16(val))
#define	PUTDMA32(d, off, val)						\
	ddi_put32(d->acch, (void *)(d->vaddr + (off)), LE_32(val))
#define	GETDMA8(d, off)						\
	LE_8(ddi_get8(d->acch, (void *)(d->vaddr + (off))))
#define	GETDMA16(d, off)					\
	LE_16(ddi_get16(d->acch, (void *)(d->vaddr + (off))))
#define	GETDMA32(d, off)					\
	LE_32(ddi_get32(d->acch, (void *)(d->vaddr + (off))))
#define	SYNCDMA(d, off, size, dir)			\
	(void) ddi_dma_sync(d->dmah, off, size, dir)

/*
 * Command block offsets.
 */
#define	CB_STS_OFFSET		0
#define	CB_CMD_OFFSET		2
#define	CB_LNK_OFFSET		4
#define	CB_SIZE			2048	/* size of cmd blk */

#define	CB_IAS_ADR_OFFSET	8

#define	CB_MCS_CNT_OFFSET	8
#define	CB_MCS_ADR_OFFSET	10
#define	CB_MCS_CNT_MAX		((CB_SIZE - CB_MCS_ADR_OFFSET) / 6)

#define	CB_UCODE_OFFSET		8

#define	CB_CONFIG_OFFSET	8

#define	CB_TX_TBD_OFFSET	8
#define	CB_TX_COUNT_OFFSET	12
#define	CB_TX_EOF		0x8000
#define	CB_TX_THRESH_OFFSET	14
#define	CB_TX_NUMBER_OFFSET	15
#define	CB_TX_DATA_OFFSET	16

#define	PUTCB8(cb, o, v)	PUTDMA8(cb, o, v)
#define	PUTCB16(cb, o, v)	PUTDMA16(cb, o, v)
#define	PUTCB32(cb, o, v)	PUTDMA32(cb, o, v)
#define	PUTCBEA(cb, o, enet)						\
	ddi_rep_put8(cb->acch, enet, (void *)(cb->vaddr + (o)), 6,	\
	DDI_DEV_AUTOINCR);
#define	GETCB8(cb, o)		GETDMA8(cb, o)
#define	GETCB16(cb, o)		GETDMA16(cb, o)
#define	GETCB32(cb, o)		GETDMA32(cb, o)
#define	SYNCCB(cb, o, s, dir)	SYNCDMA(cb, o, s, dir)
/*
 * CB status bits.
 */
#define	CB_STS_OK		0x2000
#define	CB_STS_C		0x8000

/*
 * Commands.
 */
#define	CB_CMD_NOP		0x0
#define	CB_CMD_IAS		0x1
#define	CB_CMD_CONFIG		0x2
#define	CB_CMD_MCS		0x3
#define	CB_CMD_TX		0x4
#define	CB_CMD_UCODE		0x5
/* and flags to go with */
#define	CB_CMD_SF		0x0008	/* simple/flex */
#define	CB_CMD_I		0x2000	/* generate an interrupt */
#define	CB_CMD_S		0x4000	/* suspend on completion */
#define	CB_CMD_EL		0x8000	/* end of list */

/*
 * RFD offsets.
 */
#define	GETRFD16(r, o)		GETDMA16(r, o)
#define	PUTRFD16(r, o, v)	PUTDMA16(r, o, v)
#define	PUTRFD32(r, o, v)	PUTDMA32(r, o, v)
#define	SYNCRFD(r, o, s, dir)	SYNCDMA(r, o, s, dir)

#define	RFD_STS_OFFSET		0x00
#define	RFD_CTL_OFFSET		0x02
#define	RFD_LNK_OFFSET		0x04
#define	RFD_CNT_OFFSET		0x0c	/* bytes received */
#define	RFD_SIZ_OFFSET		0x0e	/* size of packet area */
#define	RFD_PKT_OFFSET		0x10
#define	RFD_SIZE		2048

#define	RFD_CTL_EL		0x8000
#define	RFD_CTL_S		0x4000
#define	RFD_CTL_H		0x0010
#define	RFD_CTL_SF		0x0008

#define	RFD_STS_C		0x8000
#define	RFD_STS_OK		0x2000
#define	RFD_STS_FCS		0x0800
#define	RFD_STS_ALIGN		0x0400
#define	RFD_STS_TOOBIG		0x0200
#define	RFD_STS_DMAOFLO		0x0100
#define	RFD_STS_TOOSHORT	0x0080
#define	RFD_STS_802		0x0020
#define	RFD_STS_RXERR		0x0010
#define	RFD_STS_NOMATCH		0x0004
#define	RFD_STS_IAMATCH		0x0002
#define	RFD_STS_COLL_TCO	0x0001
#define	RFD_STS_ERRS		0x0d90

#define	RFD_CNT_EOF		0x8000
#define	RFD_CNT_F		0x4000

/*
 * Stats offsets.
 */
#define	STATS_TX_GOOD_OFFSET	0
#define	STATS_TX_MAXCOL_OFFSET	4
#define	STATS_TX_LATECOL_OFFSET	8
#define	STATS_TX_UFLO_OFFSET	16
#define	STATS_TX_DEFER_OFFSET	20
#define	STATS_TX_ONECOL_OFFSET	24
#define	STATS_TX_MULTCOL_OFFSET	28
#define	STATS_TX_TOTCOL_OFFSET	32
#define	STATS_RX_GOOD_OFFSET	36
#define	STATS_RX_FCS_OFFSET	40
#define	STATS_RX_ALIGN_OFFSET	44
#define	STATS_RX_NOBUF_OFFSET	48
#define	STATS_RX_OFLO_OFFSET	52
#define	STATS_RX_COL_OFFSET	56
#define	STATS_RX_SHORT_OFFSET	60
#define	STATS_DONE_OFFSET	64
#define	STATS_SIZE		68
#define	STATS_DONE		0xa005
#define	STATS_RST_DONE		0xa007

#define	SYNCSTATS(sp, o, s, dir)	SYNCDMA(sp, o, s, dir)
#define	PUTSTAT(sp, o, v)		PUTDMA32(sp, o, v)
#define	GETSTAT(sp, o)			GETDMA32(sp, o)

#endif /* _IPRB_H */

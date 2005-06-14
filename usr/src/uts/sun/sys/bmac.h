/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_BMAC_H
#define	_SYS_BMAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Declarations and definitions specific to the BigMAC chip.
 *
 * The BigMAC chip will provide the MAC functons for 10 or 100 Mbps CSMA/CD
 * protocol based interface. The QEC will control the transfer of data
 * between the host memory, buffer memory and the BigMAC. When transmitting
 * a frame will be moved from the Sbus to buffer memory. When an entire
 * frame is present in the buffer memory, the QEC will move the data from
 * the buffer memory to BigMAC. Same is the case while receiving. When the
 * entire frame is present in the buffer memory, QEC will move frame from
 * buffer memory to  host's memory.
 *
 */

/*
 * BigMAC Register Set.
 * BigMAC addresses map on a SBus word boundry. So all registers are
 * declared for a size of 32 bits. Registers that use fewer than 32
 * bits will return 0 in the bits not used.
 * XXX Do spaces between registers need to be paded.
 */
struct	bmac {
	uint_t	xifc;		/* XIF Configuration register [3-0] (RW) */
	uchar_t	pad2[252];	/* XXX h/w team to confirm */
	uint_t	stat;		/* status register [15-0] (R-auto clear) */
	uint_t	mask;		/* interrupt mask register [15-0] (RW) */
	uchar_t	pad3[256];
	uint_t	txrst;		/* tx software reset (RW) */
	uint_t	txcfg;		/* tx configuration register [9-0] (RW) */
	uint_t	ipg1;		/* Inter Packet Gap 1 [7-0] (RW) */
	uint_t	ipg2;		/* Inter Packet Gap 2 [7-0] (RW) */
	uint_t	alimit;		/* attempt limit register [7-0] (RW) */
	uint_t	slot;		/* slot time register [7-0] (RW) */
	uint_t	palen;		/* preamble length register [7-0] (RW) */
	uint_t	papat;		/* preamble pattern register [7-0] (RW) */
	uint_t	txsfd;		/* tx start frame delimiter [7-0] (RW) */
	uint_t	jam;		/* jam size register [7-0] (RW) */
	uint_t	txmax;		/* tx maximum packet size [12-0] (RW) */
	uint_t	txmin;		/* tx minimum frame size [7-0] (RW) */
	uint_t	parg;		/* peak attempt count [7-0] (RW) */
	uint_t	dcnt;		/* defer timer counter [15-0] (RW) */
	uint_t	nccnt;		/* normal collision counter [15-0] (RW) */
	uint_t	ntcnt;		/* network collision counter [15-0] (RW) */
	uint_t	excnt;		/* excess collision counter [7-0] (RW) */
	uint_t	ltcnt;		/* late collision counter [7-0] (RW) */
	uint_t	rseed;		/* random number seed [9-0] (RW) */
	uint_t	txsm;		/* tx state machine register [8-0] (R) */
	uchar_t	pad4[176];
	uint_t	rxrst;		/* rx software reset register (RW) */
	uint_t	rxcfg;		/* rx configuration register [11-0] (RW) */
	uint_t	rxmax;		/* rx maximum packet size [12-0] (RW) */
	uint_t	rxmin;		/* rx minimum frame size [7-0] (RW) */
	uint_t	madd2;		/* mac address register 2 [47-32] (RW) */
	uint_t	madd1;		/* mac address register 1 [31-16] (RW) */
	uint_t	madd0;		/* mac address register 0 [15-0] (RW) */
	uint_t	frcnt;		/* receive frame count [15-0] (RW) */
	uint_t	lecnt;		/* rx giant length error count [7-0] (RW) */
	uint_t	aecnt;		/* rx alignment error count [7-0] (RW) */
	uint_t	fecnt;		/* receive crc error count [7-0] (RW) */
	uint_t	rxsm;		/* rx state machine register (R) */
	uint_t	rxcv;		/* rx code voilation register (R) */
	uchar_t	pad5[4];
	uint_t	hash3;		/* hash table 3 [63-48] (RW) */
	uint_t	hash2;		/* hash table 2 [47-32] (RW) */
	uint_t	hash1;		/* hash table 1 [31-16] (RW) */
	uint_t	hash0;		/* hash table 0 [15-0] (RW) */
	uint_t	afr2;		/* addr filter register 0_2 [15-0] (RW) */
	uint_t	afr1;		/* addr filter register 0_1 [15-0] (RW) */
	uint_t	afr0;		/* addr filter register 0_0 [15-0] (RW) */
	uint_t	afmr;		/* addr filter mask reg 0 [15-0] (RW) */
};

/*
 * BigMAC Register Bit Masks.
 * XXX add right-shift values later.
 */

#define	BMAC_XIFC_MODE_SERIAL	(0x08)	/* Mode strapp(1==serial, 0==nibble */
#define	BMAC_XIFC_LPBK		(0x04)	/* Enable Loopback mode */
#define	BMAC_XIFC_RSVD		(0x02)	/* reserved, should be written as 1 */
#define	BMAC_XIFC_ENAB		(0x01)	/* Enable output drivers */

#define	BMAC_STAT_DEFER		(0x8000)	/* Defer Timer */
#define	BMAC_STAT_NETCOLL	(0x4000)	/* network collision */
#define	BMAC_STAT_LCOL		(0x2000)	/* late collision */
#define	BMAC_STAT_EXCCOLL	(0x1000)	/* excessive collision */
#define	BMAC_STAT_NORCOLL	(0x0800)	/* normal collision */
#define	BMAC_STAT_MAXPKT	(0x0400)	/* giant pkt err */
#define	BMAC_STAT_UFLO		(0x0200)	/* tx fifo underflow */
#define	BMAC_STAT_TXINTR	(0x0100)	/* tx interrupt */
#define	BMAC_STAT_RXCV		(0x0040)	/* rx code voilation */
#define	BMAC_STAT_OFLO		(0x0020)	/* rx fifo overflow */
#define	BMAC_STAT_LENGTH	(0x0010)	/* rx length error */
#define	BMAC_STAT_CRC		(0x0008)	/* crc error */
#define	BMAC_STAT_ALNERR	(0x0004)	/* alignment error */
#define	BMAC_STAT_RXFRMC	(0x0002)	/* rx frame counter */
#define	BMAC_STAT_RXINTR	(0x0001)	/* rx interrupt */

#define	BMAC_MASK_DEFERM	(0x8000)	/* Defer Timer Mask */
#define	BMAC_MASK_NETCOLLM	(0x4000)	/* network collision mask */
#define	BMAC_MASK_LCOLM		(0x2000)	/* late collision mask */
#define	BMAC_MASK_EXCCOLLM	(0x1000)	/* excessive collision mask */
#define	BMAC_MASK_NORCOLLM	(0x0800)	/* normal collision mask */
#define	BMAC_MASK_MAXPKTM	(0x0400)	/* max packet size mask */
#define	BMAC_MASK_UFLOM		(0x0200)	/* tx fifo underflow mask */
#define	BMAC_MASK_TXINTRM	(0x0100)	/* tx interrupt mask */
#define	BMAC_MASK_RXCV		(0x0040)	/* rx code voilation mask */
#define	BMAC_MASK_OFLOM		(0x0020)	/* rx fifo overflow mask */
#define	BMAC_MASK_LENGTH	(0x0010)	/* rx length error mask */
#define	BMAC_MASK_CRCM		(0x0008)	/* crc error mask */
#define	BMAC_MASK_ALNERRM	(0x0004)	/* alignment error mask */
#define	BMAC_MASK_RXFRMCM	(0x0002)	/* rx frame counter mask */
#define	BMAC_MASK_RXINTRM	(0x0001)	/* rx interrupt mask */
#define	BMAC_MASK_OTHER		(0x7e7e)	/* other than TINT RINT DEFER */
#define	BMAC_MASK_TINT_RINT	(0x0101)	/* TINT and RINT */

#define	BMAC_TXCFG_FDUP		(0x0200)	/* Full Duplex */
#define	BMAC_TXCFG_NGU		(0x0100)	/* Never Give Up/No Backoff */
#define	BMAC_TXCFG_NFCS		(0x0080)	/* no FCS will be generated */
#define	BMAC_TXCFG_IGCOLL	(0x0040)	/* tx ignore collision */
#define	BMAC_TXCFG_SLOW		(0x0020)	/* carrier detect before tx */
#define	BMAC_TXCFG_FIFO		(0x0010)	/* default tx fifo threshold */
#define	BMAC_TXCFG_ENAB		(0x0001)	/* tx enable */

#define	BMAC_RXCFG_ADDR		(0x1000)	/* rx enable address filter */
#define	BMAC_RXCFG_HASH		(0x0800)	/* rx enable hash filter */
#define	BMAC_RXCFG_GRPROM	(0x0400)	/* rx promiscuous group mode */
#define	BMAC_RXCFG_MYOWN	(0x0200)	/* rx filter own packets */
#define	BMAC_RXCFG_CRC		(0x0100)	/* rx disable CRC stripping */
#define	BMAC_RXCFG_ERR		(0x0080)	/* rx disable error checking */
#define	BMAC_RXCFG_PROMIS	(0x0040)	/* rx enable promiscous */
#define	BMAC_RXCFG_STRIP	(0x0020)	/* rx strip pad bytes */
#define	BMAC_RXCFG_FIFO		(0x000e)	/* default rx fifo threshold */
#define	BMAC_RXCFG_ENAB		(0x0001)	/* rx enable */

#define	BMACTXRSTDELAY		(125)		/* 125 us wait period */
#define	BMACRXRSTDELAY		(40)		/* 3.2 us wait period */

struct	bmactcvr {
	uint_t	pal1;				/* trasnceiver pal */
	uint_t	pal2;				/* management pal */
};

#define	BMACLNKTIME		(500000)	/* Length of time pulses send */

/* P1 Board */
#define	BMAC_TPAL1_XM_SERIAL	(1 << 0)	/* XIF mode 0=nibble 1=serial */
#define	BMAC_TPAL1_LB			(1 << 1)	/* External loopback */
#define	BMAC_TPAL1_MS			(1 << 2)	/* Media Sense */
#define	BMAC_TPAL1_LINKTESTEN	(1 << 3)	/* Link Test Enable */
#define	BMAC_TPAL1_LINKSTATUS	(1 << 4)	/* Link Test Status */

/* P1.5 Board */
#define	BMAC_TPAL1_PGYBAC_DIS	(1 << 0)	/* XIF mode 0=nibble 1=serial */
#define	BMAC_TPAL1_LOOP_EN		(1 << 1)	/* External loopback */
#define	BMAC_TPAL1_CLK_LOOP_EN	(1 << 2)	/* Media Sense */
#define	BMAC_TPAL1_CLK_FSTSLW	(1 << 3)	/* Link Test Enable */

#define	BMAC_TPAL2_MDC_BIT_POS			0	/* Mgmt. data clock */
#define	BMAC_TPAL2_MDIO_EN_BIT_POS	1	/* Mgmt. data output enable */
#define	BMAC_TPAL2_MII_MDIO_BIT_POS		2	/* Management data */
#define	BMAC_TPAL2_PGYBAC_MDIO_BIT_POS	3	/* Tx enable timeout error */

#define	BMAC_TPAL2_MDC			(1 << BMAC_TPAL2_MDC_BIT_POS)
#define	BMAC_TPAL2_MDIO_EN		(1 << BMAC_TPAL2_MDIO_EN_BIT_POS)
#define	BMAC_TPAL2_MII_MDIO		(1 << BMAC_TPAL2_MII_MDIO_BIT_POS)
#define	BMAC_TPAL2_PGYBAC_MDIO	(1 << BMAC_TPAL2_PGYBAC_MDIO_BIT_POS)

/*
 * Management Frame Structure:
 * <IDLE> <ST><OP><PHYAD><REGAD><TA>	 <DATA>		   <IDLE>
 * READ:  <01><10><AAAAA><RRRRR><Z0><DDDDDDDDDDDDDDDD>
 * WRITE: <01><01><AAAAA><RRRRR><10><DDDDDDDDDDDDDDDD>
 */
#define	BMAC_EXTERNAL_PHYAD	0x0
#define	BMAC_INTERNAL_PHYAD	0x1
#define	BMAC_MII_CTLREG		0x0
#define	BMAC_MII_STATREG	0x1

/* Control Register Bit Definitions */
#define	BMAC_MII_CTL_RESET		(1 << 15)	/* PHY Reset */
#define	BMAC_MII_CTL_LOOPBACK	(1 << 14)	/* Loopback Mode */
#define	BMAC_MII_CTL_SPEED_100	(1 << 13)	/* 1=100Mbps; 0=10Mbps */
#define	BMAC_MII_CTL_AUTO_SPEED	(1 << 12)
#define	BMAC_MII_CTL_POWER_DOWN	(1 << 11)
#define	BMAC_MII_CTL_ISOLATE	(1 << 10)	/* Isolate PHY from MII */

/* Status Register Bit Definitions */
#define	BMAC_MII_STAT_LINKUP	(1 << 2)
#define	BMAC_MII_STAT_JABBER	(1 << 1)
#define	BMAC_MII_STAT_EXT_CAP	(1 << 0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BMAC_H */

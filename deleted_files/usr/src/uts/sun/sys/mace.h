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

#ifndef	_SYS_MACE_H
#define	_SYS_MACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Declarations and definitions specific to the Am79C940 MACE
 * Media Access Controller for Ethernet
 *
 * The MACE is a slave register-based Ethernet (IEEE 802.3)
 * controller chip combining MAC core, Manchester endec, and SIA
 * for AUI (10BASE5), DAI (10BASET), and GPSI network interfaces.
 * All registers are 8bits wide externally except Transmit
 * and Receive FIFO registers which are 16bits wide externally.
 * Some registers are internally wider than 8bits, these
 * have bit width denoted [xx-yy], and are accessed by
 * multiple reads/writes to the external register.
 */

/*
 * MACE Register Set.
 */
struct	mace {
	uchar_t	rcvfifo;	/* R0 receive FIFO [15-00] (R) */
	uchar_t	xmtfifo;	/* R1 transmit FIFO [15-00] (W) */
	uchar_t	xmtfc;		/* R2 transmit frame control (RW) */
	uchar_t	xmtfs;		/* R3 transmit frame status (R) */
	uchar_t	xmtrc;		/* R4 transmit retry count (R) */
	uchar_t	rcvfc;		/* R5 receive frame control (RW) */
	uchar_t	rcvfs;		/* R6 receive frame status [31-00] (RO) */
	uchar_t	fifofc;		/* R7 FIFO frame count (R) */
	uchar_t	ir;		/* R8 interrupt register (R) */
	uchar_t	imr;		/* R9 interrupt mask register (RW) */
	uchar_t	pr;		/* R10 poll register (R) */
	uchar_t	biucc;		/* R11 BIU configuration control (RW) */
	uchar_t	fifocc;		/* R12 FIFO configuration control (RW) */
	uchar_t	maccc;		/* R13 MAC configuration control (RW) */
	uchar_t	plscc;		/* R14 PLS configuration control (RW) */
	uchar_t	phycc;		/* R15 PHY configuration control (RW) */
	uchar_t	chipidlo;	/* R16 chip id register [07-00] (R) */
	uchar_t	chipidhi;	/* R17 chip id register [15-08] (R) */
	uchar_t	iac;		/* R18 internal address configuration (RW) */
	uchar_t	reserved0;	/* R19 reserved */
	uchar_t	ladrf;		/* R20 logical address filter [63-00] (RW) */
	uchar_t	padr;		/* R21 physical address [47-00] (RW) */
	uchar_t	reserved1;	/* R22 reserved */
	uchar_t	reserved2;	/* R23 reserved */
	uchar_t	mpc;		/* R24 missed packet count (R) */
	uchar_t	reserved3;	/* R25 reserved */
	uchar_t	rntpc;		/* R26 runt packet count (R) */
	uchar_t	rcvcc;		/* R27 receive collision count (R) */
	uchar_t	reserved4;	/* R28 reserved */
	uchar_t	utr;		/* R29 user test register (RW) */
	uchar_t	rtr1;		/* R30 reserved test register 1 */
	uchar_t	rtr2;		/* R31 reserved test register 2 */
};

/*
 * MACE Register Bit Masks.
 * XXX add right-shift values later.
 */

#define	MACE_XMTFC_DRTRY	(0x80)	/* disable retry */
#define	MACE_XMTFC_DXMTFCS	(0x08)	/* disable transmit fcs */
#define	MACE_XMTFC_APADXMT	(0x01)	/* auto pad transmit */

#define	MACE_XMTFS_XMTSV	(0x80)	/* transmit status valid */
#define	MACE_XMTFS_UFLO		(0x40)	/* underflow */
#define	MACE_XMTFS_LCOL		(0x20)	/* late collision */
#define	MACE_XMTFS_MORE		(0x10)	/* more than one retry */
#define	MACE_XMTFS_ONE		(0x08)	/* one retry */
#define	MACE_XMTFS_DEFER	(0x04)	/* defer */
#define	MACE_XMTFS_LCAR		(0x02)	/* loss of carrier */
#define	MACE_XMTFS_RTRY		(0x01)	/* retry error */

#define	MACE_XMTRC_EXDEF	(0x80)	/* excessive defer */
#define	MACE_XMTRC_XMTRC	(0x0f)	/* transmit retry count */

#define	MACE_RCVFC_LLRCV	(0x08)	/* low latency receive */
#define	MACE_RCVFC_MR		(0x04)	/* external address match/reject */
#define	MACE_RCVFC_ASTRPRCV	(0x01)	/* auto strip receive */

#define	MACE_RCVFS_OFLO		(0x80)	/* RFS1 overflow */
#define	MACE_RCVFS_CLSN		(0x40)	/* RFS1 receive late collision */
#define	MACE_RCVFS_FRAM		(0x20)	/* RFS1 framing error */
#define	MACE_RCVFS_FCS		(0x10)	/* RFS1 FCS error */
#define	MACE_RCVFS_RCVCNT	(0x0f)	/* RFS1 receive message byte count */

#define	MACE_FIFOFC_RCVFC	(0xf0)	/* receive FIFO frame count */
#define	MACE_FIFOFC_XMTFC	(0x0f)	/* transmit FIFO frame count */

#define	MACE_IR_JAB		(0x80)	/* jabber error */
#define	MACE_IR_BABL		(0x40)	/* babble error */
#define	MACE_IR_CERR		(0x20)	/* collision error */
#define	MACE_IR_RCVCCO		(0x10)	/* receive collision count overflow */
#define	MACE_IR_RPCO		(0x08)	/* runt packet count overflow */
#define	MACE_IR_MPCO		(0x04)	/* missed packet count overflow */
#define	MACE_IR_RCVINT		(0x02)	/* receive interrupt */
#define	MACE_IR_XMTINT		(0x01)	/* transmit interrupt */

#define	MACE_IMR_BABLM		(0x40)	/* babble error mask */
#define	MACE_IMR_CERRM		(0x20)	/* collision error mask */
#define	MACE_IMR_MPCOM		(0x04)	/* missed packet count overflow mask */
#define	MACE_IMR_RCVINTM	(0x02)	/* receive interrupt mask */
#define	MACE_IMR_XMTINTM	(0x01)	/* transmit interrupt mask */

#define	MACE_PR_XMTSV		(0x80)	/* transmit status valid */
#define	MACE_PR_TDTREQ		(0x40)	/* transmit data transfer request */
#define	MACE_PR_RDTREQ		(0x20)	/* receive data transfer request */

#define	MACE_BIU_BSWP		(0x40)	/* byte swap */
#define	MACE_BIU_XMTSP		(0x30)	/* transmit start point */
#define	MACE_BIU_XMTSPSHIFTL	(4)	/* shift left value into this field */
#define	MACE_BIU_XMTSP4		(0)	/* 4byte transmit start */
#define	MACE_BIU_XMTSP16	(1)	/* 16byte transmit start */
#define	MACE_BIU_XMTSP64	(2)	/* 64byte transmit start */
#define	MACE_BIU_XMTSP112	(3)	/* 112byte transmit start */
#define	MACE_BIU_SWSRT		(0x01)	/* software reset */

#define	MACE_FIFOCC_XMTFW	(0xc0)	/* transmit fifo watermark */
#define	MACE_FIFOCC_XMTFW8	(0x00)	/* transmit fifo 8 write cycles */
#define	MACE_FIFOCC_XMTFW16	(0x40)	/* transmit fifo 16 write cycles */
#define	MACE_FIFOCC_XMTFW32	(0x80)	/* transmit fifo 32 write cycles */
#define	MACE_FIFOCC_RCVFW	(0x30)	/* receive fifo watermark */
#define	MACE_FIFOCC_RCVFW16	(0x00)	/* receive fifo 16bytes */
#define	MACE_FIFOCC_RCVFW32	(0x10)	/* receive fifo 32bytes */
#define	MACE_FIFOCC_RCVFW64	(0x20)	/* receive fifo 64bytes */
#define	MACE_FIFOCC_XMTFWU	(0x08)	/* transmit fifo watermark update */
#define	MACE_FIFOCC_RCVFWU	(0x04)	/* receive fifo watermark update */
#define	MACE_FIFOCC_XMTBRST	(0x02)	/* transmit burst enable/disable */
#define	MACE_FIFOCC_RCVBRST	(0x01)	/* receive burst enable/disable */

#define	MACE_MACCC_PROM		(0x80)	/* promiscuous mode */
#define	MACE_MACCC_DXMT2PD	(0x40)	/* disable transmit two part deferral */
#define	MACE_MACCC_EMBA		(0x20)	/* enable modified back-off algorithm */
#define	MACE_MACCC_DRCVPA	(0x08)	/* disable receive physical address */
#define	MACE_MACCC_DRCVBC	(0x04)	/* disable receive broadcast */
#define	MACE_MACCC_ENXMT	(0x02)	/* enable transmit */
#define	MACE_MACCC_ENRCV	(0x01)	/* enable receive */

#define	MACE_PLSCC_XMTSEL	(0x08)	/* transmit mode select */
#define	MACE_PLSCC_PORTSEL	(0x06)	/* port select */
#define	MACE_PLSCC_PORTSELAUI	(0x00)	/* port select:  AUI */
#define	MACE_PLSCC_PORTSELTP	(0x02)	/* port select:  TP */
#define	MACE_PLSCC_PORTSELDAI	(0x04)	/* port select:  DAI */
#define	MACE_PLSCC_PORTSELGPSI	(0x06)	/* port select:  GPSI */
#define	MACE_PLSCC_ENPLSIO	(0x01)	/* enable PLS I/O */

#define	MACE_PHYCC_LNKST	(0x80)	/* link integrity test status */
#define	MACE_PHYCC_DLNKTST	(0x40)	/* disable link test */
#define	MACE_PHYCC_RCVPOL	(0x20)	/* receive polarity */
#define	MACE_PHYCC_DAPC		(0x10)	/* disable auto polarity correction */
#define	MACE_PHYCC_LTS		(0x08)	/* low threshold select */
#define	MACE_PHYCC_ASEL		(0x04)	/* port auto select */
#define	MACE_PHYCC_RWAKE	(0x02)	/* remote wakeup */
#define	MACE_PHYCC_AWAKE	(0x01)	/* auto wake */

#define	MACE_CHIPID0_MAGIC	(0x41)	/* chip id is 0xX941 where X=version */
#define	MACE_CHIPID1_MAGIC	(0x09)

#define	MACE_IAC_ADDRCHG	(0x80)	/* address change */
#define	MACE_IAC_PHYADDR	(0x04)	/* physical address reset */
#define	MACE_IAC_LOGADDR	(0x02)	/* logical address reset */

#define	MACE_UTR_RTRE		(0x80)	/* reserved test register enable */
#define	MACE_UTR_RTRD		(0x40)	/* reserved test register disable */
#define	MACE_UTR_RPA		(0x20)	/* runt packet accept */
#define	MACE_UTR_FCOLL		(0x10)	/* force collision */
#define	MACE_UTR_RCVFCSE	(0x08)	/* receive FCS enable */
#define	MACE_UTR_LOOP		(0x06)	/* loopback control */
#define	MACE_UTR_LOOPNO		(0x00)	/* loopback control:  no loopback */
#define	MACE_UTR_LOOPEXT	(0x02)	/* loopback control:  ext. */
#define	MACE_UTR_LOOPINT	(0x04)	/* loopback control:  int. */
#define	MACE_UTR_LOOPINTMENDEC	(0x06)	/* loopback control:  int. w/MENDEC */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACE_H */

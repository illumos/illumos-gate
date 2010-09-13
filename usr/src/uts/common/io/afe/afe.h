/*
 * Solaris DLPI driver for ethernet cards based on the ADMtek Centaur
 *
 * Copyright (c) 2007 by Garrett D'Amore <garrett@damore.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AFE_H
#define	_AFE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Registers and values are here, becuase they can be exported to userland
 * via the AFEIOC_GETCSR and friends ioctls.  These are private to this
 * driver and the bundled diagnostic utility, and should not be used by
 * end user application programs.
 */

/*
 * AFE register definitions.
 */
/* PCI configuration registers */
#define	PCI_VID		0x00	/* Loaded vendor ID */
#define	PCI_DID		0x02	/* Loaded device ID */
#define	PCI_CMD		0x04	/* Configuration command register */
#define	PCI_STAT	0x06	/* Configuration status register */
#define	PCI_RID		0x08	/* Revision ID */
#define	PCI_CLS		0x0c	/* Cache line size */
#define	PCI_SVID	0x2c	/* Subsystem vendor ID */
#define	PCI_SSID	0x2e	/* Subsystem ID */
#define	PCI_MINGNT	0x3e	/* Minimum Grant */
#define	PCI_MAXLAT	0x3f	/* Maximum latency */
#define	PCI_SIG		0x80	/* Signature of AN983 */
#define	PCI_PMR0	0xc0	/* Power Management Register 0 */
#define	PCI_PMR1	0xc4	/* Power Management Register 1 */

/*
 * Bits for PCI command register.
 */
#define	PCI_CMD_MWIE	0x0010	/* memory write-invalidate enable */
#define	PCI_CMD_BME	0x0004	/* bus master enable */
#define	PCI_CMD_MAE	0x0002	/* memory access enable */
#define	PCI_CMD_IOE	0x0001	/* I/O access enable */

/*
 * Signature values for PCI_SIG
 */
#define	SIG_AN983	0x09811317
#define	SIG_AN985	0x09851317
#define	SIG_ADM9511	0x69851317

/* Ordinary control/status registers */
#define	CSR_PAR		0x00	/* PCI access register */
#define	CSR_TDR		0x08	/* Transmit demand register */
#define	CSR_RDR		0x10	/* Receive demand register */
#define	CSR_RDB		0x18	/* Receive descriptor base address */
#define	CSR_TDB		0x20	/* Transmit descriptor base address */
#define	CSR_SR		0x28	/* Status register */
#define	CSR_NAR		0x30	/* Network access register */
#define	CSR_IER		0x38	/* Interrupt enable register */
#define	CSR_LPC		0x40	/* Lost packet counter */
#define	CSR_SPR		0x48	/* Serial port register */
#define	CSR_TIMER	0x58	/* Timer */
#define	CSR_SR2		0x80	/* Status register 2 */
#define	CSR_IER2	0x84	/* Interrupt enable register 2 */
#define	CSR_CR		0x88	/* Command register */
#define	CSR_PMCSR	0x90	/* Power Management Command and Status */
#define	CSR_PAR0	0xa4	/* Physical address register 0 */
#define	CSR_PAR1	0xa8	/* Physical address register 1 */
#define	CSR_MAR0	0xac	/* Multicast address hash table register 0 */
#define	CSR_MAR1	0xb0	/* Multicast address hash table register 1 */
#define	CSR_BMCR	0xb4	/* PHY BMCR (comet only) */
#define	CSR_BMSR	0xb8	/* PHY BMSR (comet only) */
#define	CSR_PHYIDR1	0xbc	/* PHY PHYIDR1 (comet only) */
#define	CSR_PHYIDR2	0xc0	/* PHY PHYIDR2 (comet only) */
#define	CSR_ANAR	0xc4	/* PHY ANAR (comet only) */
#define	CSR_ANLPAR	0xc8	/* PHY ANLPAR (comet only) */
#define	CSR_ANER	0xcc	/* PHY ANER (comet only) */
#define	CSR_XMC		0xd0	/* XCVR mode control (comet only) */
#define	CSR_XCIIS	0xd4	/* XCVR config info/int status (comet only) */
#define	CSR_XIE		0xd8	/* XCVR interupt enable (comet only) */
#define	CSR_OPM		0xfc	/* Opmode register (centaur only) */

/*
 * Bits for PCI access register.
 */
#define	PAR_RESET	0x00000001U	/* Reset the entire chip */
#define	PAR_MWIE	0x01000000U	/* PCI memory-write-invalidate */
#define	PAR_MRLE	0x00800000U	/* PCI memory-read-line */
#define	PAR_MRME	0x00200000U	/* PCI memory-read-multiple */
#define	PAR_TXHIPRI	0x00000002U	/* Transmit higher priority */
#define	PAR_DESCSKIP	0x0000007cU	/* Descriptor skip length in DW */
#define	PAR_BIGENDIAN	0x00000080U	/* Use big endian data buffers */
#define	PAR_TXAUTOPOLL	0x00060000U	/* Programmable TX autopoll interval */
#define	PAR_RXFIFO_100	0x00009000U	/* RX FIFO control, Centaur only */
#define	PAR_RXFIFO_10	0x00002800U	/* RX FIFO control, Centaur only */
#define	PAR_CALIGN_NONE	0x00000000U	/* No cache alignment, Comet */
#define	PAR_CALIGN_8	0x00004000U	/* 8 DW cache alignment, Comet */
#define	PAR_CALIGN_16	0x00008000U	/* 16 DW cache alignment, Comet */
#define	PAR_CALIGN_32	0x0000c000U	/* 32 DW cache alignment, Comet */
#define	PAR_BURSTLEN	0x00003F00U	/* Programmable burst length, Comet */
#define	PAR_BURSTUNL	0x00000000U	/* Unlimited burst length, Comet */
#define	PAR_BURST_1	0x00000100U	/* 1 DW burst length, Comet */
#define	PAR_BURST_2	0x00000200U	/* 2 DW burst length, Comet */
#define	PAR_BURST_4	0x00000400U	/* 4 DW burst length, Comet */
#define	PAR_BURST_8	0x00000800U	/* 8 DW burst length, Comet */
#define	PAR_BURST_16	0x00001000U	/* 16 DW burst length, Comet */
#define	PAR_BURST_32	0x00002000U	/* 32 DW burst length, Comet */

/*
 * Bits for status register.
 */
#define	SR_BERR_TYPE		0x03800000U	/* bus error type */
#define	SR_BERR_PARITY		0x00000000U	/* parity error */
#define	SR_BERR_TARGET_ABORT	0x01000000U	/* target abort */
#define	SR_BERR_MASTER_ABORT	0x00800000U	/* master abort */
#define	SR_TX_STATE		0x00700000U	/* transmit state */
#define	SR_RX_STATE		0x000E0000U	/* receive state */

/*
 * Interrupts.  These are in IER2 and SR2.  Some of them also appear
 * in SR and IER, but we only use the ADMtek specific IER2 and SR2.
 */
#define	INT_TXEARLY		0x80000000U	/* transmit early interrupt */
#define	INT_RXEARLY		0x40000000U	/* receive early interrupt */
#define	INT_LINKCHG		0x20000000U	/* link status changed */
#define	INT_TXDEFER		0x10000000U	/* transmit defer interrupt */
#define	INT_PAUSE		0x04000000U	/* pause frame received */
#define	INT_NORMAL		0x00010000U	/* normal interrupt */
#define	INT_ABNORMAL		0x00008000U	/* abnormal interrupt */
#define	INT_BUSERR		0x00002000U	/* fatal bus error */
#define	INT_TIMER		0x00000800U	/* onboard timer */
#define	INT_RXJABBER		0x00000200U	/* receive watchdog */
#define	INT_RXSTOPPED		0x00000100U	/* receive stopped */
#define	INT_RXNOBUF		0x00000080U	/* no rcv descriptor */
#define	INT_RXOK		0x00000040U	/* receive complete */
#define	INT_TXUNDERFLOW		0x00000020U	/* transmit underflow */
#define	INT_TXJABBER		0x00000008U	/* transmit jabber timeout */
#define	INT_TXNOBUF		0x00000004U	/* no xmt descriptor */
#define	INT_TXSTOPPED		0x00000002U	/* transmit stopped */
#define	INT_TXOK		0x00000001U	/* transmit ok interrupt */

#define	INT_NONE		0x00000000U	/* no interrupts */
#define	INT_ALL			0xf401abefU	/* all interrupts */
#define	INT_WANTED		(INT_NORMAL | INT_ABNORMAL | \
				INT_BUSERR | INT_RXJABBER | \
				INT_RXOK | INT_RXNOBUF | \
				INT_TIMER | INT_LINKCHG | \
				INT_RXSTOPPED | INT_TXSTOPPED | \
				INT_TXUNDERFLOW | INT_TXJABBER)

/*
 * Bits for network access register.
 */
#define	NAR_TX_ENABLE	0x00002000U	/* Enable transmit */
#define	NAR_RX_MULTI	0x00000080U	/* Receive all multicast packets */
#define	NAR_RX_PROMISC	0x00000040U	/* Receive any good packet */
#define	NAR_RX_BAD	0x00000008U	/* Pass bad packets */
#define	NAR_RX_ENABLE	0x00000002U	/* Enable receive */
#define	NAR_TR		0x0000c000U	/* Transmit threshold mask */
#define	NAR_TR_72	0x00000000U	/* 72 B (128 @ 100Mbps) tx thresh */
#define	NAR_TR_96	0x00004000U	/* 96 B (256 @ 100Mbps) tx thresh */
#define	NAR_TR_128	0x00008000U	/* 128 B (512 @ 100Mbps) tx thresh */
#define	NAR_TR_160	0x0000c000U	/* 160 B (1K @ 100Mbsp) tx thresh */
#define	NAR_SF		0x00200000U	/* store and forward */
#define	NAR_HBD		0x00080000U	/* Disable SQE heartbeat */
#define	NAR_FCOLL	0x00001000U	/* force collision */
#define	NAR_MODE	0x00000c00U	/* mode (loopback, etc.) */
#define	NAR_MACLOOP	0x00000400U	/* mac loop back */

/*
 * Bits for lost packet counter.
 */
#define	LPC_COUNT	0x0000FFFFU	/* Count of missed frames */
#define	LPC_OFLOW	0x00010000U	/* Counter overflow bit */

/*
 * Bits for CSR_SPR (MII and SROM access)
 */
#define	SPR_MII_DIN	0x00080000U	/* MII data input */
#define	SPR_MII_CTRL	0x00040000U	/* MII management control, 1=read */
#define	SPR_MII_DOUT	0x00020000U	/* MII data output */
#define	SPR_MII_CLOCK	0x00010000U	/* MII data clock */
#define	SPR_SROM_READ	0x00004000U	/* Serial EEPROM read control */
#define	SPR_SROM_WRITE	0x00002000U	/* Serial EEPROM write control */
#define	SPR_SROM_SEL	0x00000800U	/* Serial EEPROM select */
#define	SPR_SROM_DOUT	0x00000008U	/* Serial EEPROM data out */
#define	SPR_SROM_DIN	0x00000004U	/* Serial EEPROM data in */
#define	SPR_SROM_CLOCK	0x00000002U	/* Serial EEPROM clock */
#define	SPR_SROM_CHIP	0x00000001U	/* Serial EEPROM chip select */
#define	SROM_ENADDR		0x4	/* Offset of ethernet address */
#define	SROM_READCMD		0x6	/* command to read SROM */

/*
 * Bits for CSR_TIMER
 */
#define	TIMER_LOOP	0x00010000U	/* continuous operating mode */
#define	TIMER_USEC		204		/* usecs per timer count */

/*
 * Bits for CSR_CR
 */
#define	CR_PAUSE	0x00000020U	/* enable pause flow control */
#define	CR_TXURAUTOR	0x00000001U	/* transmit underrun auto recovery */

/*
 * Bits for XMC (Comet specific)
 */
#define	XMC_LDIS	0x0800		/* long distance 10Base-T cable */

/*
 * Bits for XCIIS (Comet specific)
 */
#define	XCIIS_SPEED		0x0200	/* 100 Mbps mode */
#define	XCIIS_DUPLEX		0x0100	/* full duplex mode */
#define	XCIIS_FLOWCTL		0x0080	/* flow control support */
#define	XCIIS_ANC		0x0040	/* autonegotiation complete */
#define	XCIIS_RF		0x0020	/* remote fault detected */
#define	XCIIS_LFAIL		0x0010	/* link fail */
#define	XCIIS_ANLPAR		0x0008	/* anar received from link partner */
#define	XCIIS_PDF		0x0004	/* parallel detection fault */
#define	XCIIS_ANPR		0x0002	/* autoneg. page received */
#define	XCIIS_REF		0x0001	/* receive error counter full */

/*
 * Bits for XIE (Comet specific)
 */
#define	XIE_ANCE		0x0040	/* aneg complete interrupt enable */
#define	XIE_RFE			0x0020	/* remote fault interrupt enable */
#define	XIE_LDE			0x0010	/* link fail interrupt enable */
#define	XIE_ANAE		0x0008	/* aneg. ack. interrupt enable */
#define	XIE_PDFE		0x0004	/* parallel det. fault int. enable */
#define	XIE_ANPE		0x0002	/* autoneg. page rec'd int. enable */
#define	XIE_REFE		0x0001	/* receive error full int. enable */

/*
 * Centaur 1.1 extensions to MII.
 */
#define	PHY_PILR	0x10		/* an983b 1.1 - polarity/int lvl */
#define	PHY_MCR		0x15		/* an983b 1.1 - mode control */

#define	PILR_NOSQE	0x0800		/* disable 10BaseT SQE */
#define	MCR_FIBER	0x0001		/* enable fiber */

/*
 * Bits for Opmode (Centaur specific)
 */
#define	OPM_SPEED	0x80000000U	/* 100 Mbps */
#define	OPM_DUPLEX	0x40000000U	/* full duplex */
#define	OPM_LINK	0x20000000U	/* link up? */
#define	OPM_MODE	0x00000007U	/* mode mask */
#define	OPM_INTPHY	0x00000007U	/* single chip mode, internal PHY */
#define	OPM_MACONLY	0x00000004U	/* MAC ony mode, external PHY */

#ifdef	_KERNEL
/*
 * Put exported kernel interfaces here.  (There should be none.)
 */
#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _AFE_H */

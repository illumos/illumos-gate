/*
 * Solaris driver for ethernet cards based on the Macronix 98715
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

#ifndef	_MXFE_H
#define	_MXFE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * These are conveniently defined to have the same values
 * as are used by the NDD utility, which is an undocumented
 * interface.  YMMV.
 */
#define	NDIOC	('N' << 8)
#define	NDIOC_GET	(NDIOC|0)
#define	NDIOC_SET	(NDIOC|1)

/*
 * Registers and values are here, becuase they can be exported to userland
 * via the MXFEIOC_GETCSR and friends ioctls.  These are private to this
 * driver and the bundled diagnostic utility, and should not be used by
 * end user application programs.
 */

/*
 * MXFE register definitions.
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

/*
 * Bits for PCI command register.
 */
#define	PCI_CMD_MWIE	0x0010	/* memory write-invalidate enable */
#define	PCI_CMD_BME	0x0004	/* bus master enable */
#define	PCI_CMD_MAE	0x0002	/* memory access enable */
#define	PCI_CMD_IOE	0x0001	/* I/O access enable */

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
#define	CSR_TSTAT	0x60	/* 10Base-T status */
#define	CSR_SIA		0x68	/* SIA reset register */
#define	CSR_TCTL	0x70	/* 10Base-T control */
#define	CSR_WTMR	0x78	/* Watchdog timer */
#define	CSR_MXMAGIC	0x80	/* MXIC magic register */
#define	CSR_PMCSR	0x90	/* Power Management Command and Status */
#define	CSR_TXBR	0x9c	/* Transmit burst counter/time-out register */
#define	CSR_FROM	0xa0	/* Flash(boot) ROM port */
#define	CSR_ACOMP	0xa0	/* Autocompensation */
#define	CSR_FLOW	0xa8	/* Flow control (newer parts only) */

/*
 * Bits for PCI access register.
 */
#define	PAR_RESET	0x00000001U	/* Reset the entire chip */
#define	PAR_MWIE	0x01000000U	/* PCI memory-write-invalidate */
#define	PAR_MRLE	0x00800000U	/* PCI memory-read-line */
#define	PAR_MRME	0x00200000U	/* PCI memory-read-multiple */
#define	PAR_BAR		0x00000002U	/* Bus arbitration */
#define	PAR_DESCSKIP	0x0000007cU	/* Descriptor skip length in DW */
#define	PAR_BIGENDIAN	0x00000080U	/* Use big endian data buffers */
#define	PAR_TXAUTOPOLL	0x00060000U	/* Programmable TX autopoll interval */
#define	PAR_CALIGN_NONE	0x00000000U	/* No cache alignment */
#define	PAR_CALIGN_8	0x00004000U	/* 8 DW cache alignment */
#define	PAR_CALIGN_16	0x00008000U	/* 16 DW cache alignment */
#define	PAR_CALIGN_32	0x0000c000U	/* 32 DW cache alignment */
#define	PAR_BURSTLEN	0x00003F00U	/* Programmable burst length */
#define	PAR_BURSTUNL	0x00000000U	/* Unlimited burst length */
#define	PAR_BURST_1	0x00000100U	/* 1 DW burst length */
#define	PAR_BURST_2	0x00000200U	/* 2 DW burst length */
#define	PAR_BURST_4	0x00000400U	/* 4 DW burst length */
#define	PAR_BURST_8	0x00000800U	/* 8 DW burst length */
#define	PAR_BURST_16	0x00001000U	/* 16 DW burst length */
#define	PAR_BURST_32	0x00002000U	/* 32 DW burst length */

/*
 * Bits for status register.  Interrupt bits are also used by
 * the interrupt enable register.
 */
#define	SR_BERR_TYPE		0x03800000U	/* bus error type */
#define	SR_BERR_PARITY		0x00000000U	/* parity error */
#define	SR_BERR_TARGET_ABORT	0x01000000U	/* target abort */
#define	SR_BERR_MASTER_ABORT	0x00800000U	/* master abort */
#define	SR_TX_STATE		0x00700000U	/* transmit state */
#define	SR_RX_STATE		0x000E0000U	/* transmit state */
#define	INT_100LINK		0x08000000U	/* 100 Base-T link */
#define	INT_NORMAL		0x00010000U	/* normal interrupt */
#define	INT_ABNORMAL		0x00008000U	/* abnormal interrupt */
#define	INT_EARLYRX		0x00004000U	/* early receive interrupt */
#define	INT_BUSERR		0x00002000U	/* fatal bus error interrupt */
#define	INT_10LINK		0x00001000U	/* 10 Base-T link */
#define	INT_TIMER		0x00000800U	/* onboard timer interrupt */
#define	INT_EARLYTX		0x00000400U	/* early transmit interrupt */
#define	INT_RXJABBER		0x00000200U	/* receive watchdog timeout */
#define	INT_RXSTOPPED		0x00000100U	/* receive stopped */
#define	INT_RXNOBUF		0x00000080U	/* no rcv descriptor */
#define	INT_RXOK		0x00000040U	/* rcv complete interrupt */
#define	INT_TXUNDERFLOW		0x00000020U	/* transmit underflow */
#define	INT_ANEG		0x00000010U	/* autonegotiation */
#define	INT_TXJABBER		0x00000008U	/* transmit jabber timeout */
#define	INT_TXNOBUF		0x00000004U	/* no xmt descriptor */
#define	INT_TXSTOPPED		0x00000002U	/* transmit stopped */
#define	INT_TXOK		0x00000001U	/* transmit ok interrupt */

#define	INT_NONE		0x00000000U	/* no interrupts */
#define	INT_WANTED		(INT_BUSERR | INT_RXJABBER | \
				INT_RXOK | INT_TXUNDERFLOW | \
				INT_RXNOBUF | INT_TXJABBER | \
				INT_RXSTOPPED | INT_TXSTOPPED | \
				INT_TIMER | \
				INT_ABNORMAL | INT_NORMAL)

#define	INT_LINKSTATUS		(INT_ANEG | INT_100LINK | INT_10LINK)
#define	INT_ALL			(INT_WANTED | INT_TXOK | \
				INT_TXNOBUF | INT_LINKSTATUS)

/*
 * Bits for network access register.
 */
#define	NAR_TX_ENABLE	0x00002000U	/* Enable transmit */
#define	NAR_RX_MULTI	0x00000080U	/* Receive all multicast packets */
#define	NAR_RX_PROMISC	0x00000040U	/* Receive any good packet */
#define	NAR_RX_BAD	0x00000008U	/* Pass bad packets */
#define	NAR_RX_HO	0x00000004U	/* Hash only receive */
#define	NAR_RX_ENABLE	0x00000002U	/* Enable receive */
#define	NAR_RX_HP	0x00000001U	/* Hash perfect receive */
#define	NAR_TR		0x0000c000U	/* Transmit threshold mask */
#define	NAR_TR_72	0x00000000U	/* 72 B (128 @ 100Mbps) tx thresh */
#define	NAR_TR_96	0x00004000U	/* 96 B (256 @ 100Mbps) tx thresh */
#define	NAR_TR_128	0x00008000U	/* 128 B (512 @ 100Mbps) tx thresh */
#define	NAR_TR_160	0x0000c000U	/* 160 B (1K @ 100Mbsp) tx thresh */
#define	NAR_SCR		0x01000000U	/* scrambler mode */
#define	NAR_PCS		0x00800000U	/* set for forced 100 mbit */
#define	NAR_SPEED	0x00400000U	/* transmit threshold, set for 10bt */
#define	NAR_SF		0x00200000U	/* store and forward */
#define	NAR_HBD		0x00080000U	/* Disable SQE heartbeat */
#define	NAR_COE		0x00020000U	/* collision offset enable */
#define	NAR_PORTSEL	0x00040000U	/* 1 = 100 mbit */
#define	NAR_FDX		0x00000200U	/* 1 = full duplex */

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
#define	SROM_ENADDR		0x70	/* Ethernet address pointer! */
#define	SROM_READCMD		0x6	/* command to read SROM */

/*
 * Bits for CSR_TIMER
 */
#define	TIMER_LOOP	0x00010000U	/* continuous operating mode */
#define	TIMER_USEC	204		/* usecs per timer count */

/*
 * Bits for TSTAT
 */
#define	TSTAT_LPC	0xFFFF0000U	/* link partner's code word */
#define	TSTAT_LPN	0x00008000U	/* link partner supports nway */
#define	TSTAT_ANS	0x00007000U	/* autonegotiation state mask */
#define	TSTAT_TRF	0x00000800U	/* transmit remote fault */
#define	TSTAT_APS	0x00000008U	/* autopolarity state */
#define	TSTAT_10F	0x00000004U	/* 10Base-T link failure */
#define	TSTAT_100F	0x00000002U	/* 100Base-T link failure */
#define	TSTAT_ANS_DIS	0x00000000U	/* autonegotiation disabled */
#define	TSTAT_ANS_OK	0x00005000U	/* autonegotiation complete */
#define	TSTAT_ANS_START	0x00001000U	/* restart autonegotiation */

/* macro to convert TSTAT link partner's code word to MII equivalents */
#define	TSTAT_LPAR(x)	((x & TSTAT_LPC) >> 16)

/*
 * Bits for SIA reset
 */
#define	SIA_RESET	0x00000001U	/* reset 100 PHY */
#define	SIA_NRESET	0x00000002U	/* reset NWay */

/*
 * Bits for TCTL
 */
#define	TCTL_PAUSE	0x00080000U	/* Pause enable */
#define	TCTL_100BT4	0x00040000U	/* 100 BaseT4 enable */
#define	TCTL_100FDX	0x00020000U	/* 100 BaseT fdx enable */
#define	TCTL_100HDX	0x00010000U	/* 100 BaseT hdx enable */
#define	TCTL_LTE	0x00001000U	/* link test enable */
#define	TCTL_RSQ	0x00000100U	/* receive squelch enable */
#define	TCTL_ANE	0x00000080U	/* autoneg. enable */
#define	TCTL_HDX	0x00000040U	/* half-duplex enable */
#define	TCTL_PWR	0x00000004U	/* supply power to 10BaseT */

/*
 * Bits for flow control
 */
#define	FLOW_TMVAL		0xffff0000U	/* flow timer value */
#define	FLOW_TEST		0x00008000U	/* test flow control timer */
#define	FLOW_RESTART		0x00004000U	/* re-start mode */
#define	FLOW_RESTOP		0x00002000U	/* re-stop mode */
#define	FLOW_TXFCEN		0x00001000U	/* tx flow control enable */
#define	FLOW_RXFCEN		0x00000800U	/* rx flow control enable */
#define	FLOW_RUFCEN		0x00000400U	/* send pause when rxnobuf */
#define	FLOW_STOPTX		0x00000200U	/* tx flow status */
#define	FLOW_REJECTFC		0x00000100U	/* abort rx flow when set */
#define	FLOW_RXFCTH1		0x00000080U	/* rx flow threshold 1 */
#define	FLOW_RXFCTH0		0x00000040U	/* rx flow threshold 0 */
#define	FLOW_NFCEN		0x00000020U	/* accept nway flow control */


#endif	/* _MXFE_H */

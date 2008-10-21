/*
 *  sfereg.h: SiS900/DP83815 register definition
 *
 * Copyright (c) 2002-2007 Masayuki Murayama.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef	_SFEREG_H_
#define	_SFEREG_H_
/*
 * Tx/Rx descriptor
 */
struct sfe_desc {
	volatile uint32_t	d_link;		/* link to the next */
	volatile uint32_t	d_cmdsts;	/* command/status field */
	volatile uint32_t	d_bufptr;	/* ptr to the first fragment */
};

/* CMDSTS common Bit Definition */
#define	CMDSTS_OWN	0x80000000U	/* 1: data consumer owns */
#define	CMDSTS_MORE	0x40000000U	/* Not the last descriptor */
#define	CMDSTS_INTR	0x20000000U
#define	CMDSTS_SUPCRC	0x10000000U
#define	CMDSTS_INCCRC	CMDSTS_SUPCRC
#define	CMDSTS_OK	0x08000000U	/* Packet is OK */
#define	CMDSTS_SIZE	0x00000fffU	/* Descriptor byte count */

/* Transmit Status Bit Definition */
#define	CMDSTS_TXA	0x04000000U	/* Transmit abort */
#define	CMDSTS_TFU	0x02000000U	/* Transmit FIFO Underrun */
#define	CMDSTS_CRS	0x01000000U	/* Carrier sense lost */
#define	CMDSTS_TD	0x00800000U	/* Transmit deferred */
#define	CMDSTS_ED	0x00400000U	/* Exessive deferrral */
#define	CMDSTS_OWC	0x00200000U	/* Out of window collision */
#define	CMDSTS_EC	0x00100000U	/* Excessive collision */
#define	CMDSTS_CCNT	0x000f0000U	/* Collision count */
#define	CMDSTS_CCNT_SHIFT	(16)
#define		CCNT_MASK	0xfU	/* Collision count mask */

#define	TXSTAT_BITS	\
	"\020"		\
	"\040Own"	\
	"\037More"	\
	"\036Intr"	\
	"\035SupCrc"	\
	"\034Ok"	\
	"\033Abort"	\
	"\032UnderRun"	\
	"\031NoCarrier"	\
	"\030Deferd"	\
	"\027ExcDefer"	\
	"\026OWColl"	\
	"\025ExcColl"

#define	RXSTAT_BITS	\
	"\020"		\
	"\040Own"	\
	"\037More"	\
	"\036Intr"	\
	"\035IncCrc"	\
	"\034Ok"	\
	"\032OverRun"	\
	"\031MCast"	\
	"\030UniMatch"	\
	"\027TooLong"	\
	"\026Runt"	\
	"\025RxISErr"	\
	"\024CrcErr"	\
	"\023FaErr"	\
	"\022LoopBk"	\
	"\021RxCol"


/* Receive Status Bit Definitions */
#define	CMDSTS_RXA	0x04000000U	/* Receive abort */
#define	CMDSTS_RXO	0x02000000U	/* Receive overrun */
#define	CMDSTS_DEST	0x01800000U	/* Destination class */
#define	CMDSTS_DEST_SHIFT	23	/* Destination class */
#define		DEST_REJECT	0U
#define		DEST_NODE	1U
#define		DEST_MULTI	2U
#define		DEST_BROAD	3U
#define	CMDSTS_LONG	0x00400000U	/* Too long packet received */
#define	CMDSTS_RUNT	0x00200000U	/* Runt packet received */
#define	CMDSTS_ISE	0x00100000U	/* Invalid symbol error */
#define	CMDSTS_CRCE	0x00080000U	/* CRC error */
#define	CMDSTS_FAE	0x00040000U	/* Frame alignment */
#define	CMDSTS_LBP	0x00020000U	/* Loopback packet */
#define	CMDSTS_COL	0x00010000U	/* Collision activety */

/*
 * Offsets of MAC Operational Registers
 */
#define	CR		0x00	/* Command register */
#define	CFG		0x04	/* Configuration register */
#define	EROMAR		0x08	/* EEPROM access register */
#define	MEAR		0x08	/* alias for MII access register (sis900) */
#define	PTSCR		0x0c	/* PCI test control register */
#define	ISR		0x10	/* Interrupt status register */
#define	IMR		0x14	/* Interrupt mask register */
#define	IER		0x18	/* Interrupt enable register */
#define	ENPHY		0x1c	/* Enhanced PHY access register */
#define	TXDP		0x20	/* Transmit descriptor pointer reg */
#define	TXCFG		0x24	/* Transmit configuration register */
#define	RXDP		0x30	/* Receive descriptor pointer reg */
#define	RXCFG		0x34	/* Receive configration register */
#define	FLOWCTL		0x38	/* Flow control register (sis900) */
#define	CCSR		0x3c	/* Clock run status register (dp83815) */
#define	PCR		0x44	/* Pause control register (dp83815) */
#define	RFCR		0x48	/* Receive filter control register */
#define	RFDR		0x4c	/* Receive filter data register */
#define	SRR		0x58	/* silicon revision register */
#define	MII_REGS_BASE	0x80	/* DP83815 only */
#define	PMCTL		0xb0	/* Power management control register */
#define	PMEVT		0xb4	/* Power management wake-up event reg */
#define	WAKECRC		0xbc	/* Wake-up sample frame CRC register */
#define	WAKEMASK	0xc0	/* Wake-up sample frame mask register */


/* Command register */
#define	CR_RELOAD	0x0400U		/* reload mac address */
#define	CR_ACCESSMODE	0x0200U		/* mii access mode */
#define	CR_RST		0x0100U		/* Reset */
#define	CR_SWI		0x0080U		/* Software interrupt */
#define	CR_RXR		0x0020U		/* Receiver reset */
#define	CR_TXR		0x0010U		/* Transmit reset */
#define	CR_RXD		0x0008U		/* Receiver disable */
#define	CR_RXE		0x0004U		/* Receiver enable */
#define	CR_TXD		0x0002U		/* Transmit disable */
#define	CR_TXE		0x0001U		/* Transmit enable */

#define	CR_BITS	\
	"\020"		\
	"\011Reset"	\
	"\010SWI"	\
	"\006RxReset"	\
	"\005TxReset"	\
	"\004RxDisable"	\
	"\003RxEnable"	\
	"\002TxDisable"	\
	"\001TxEnable"

/* Configration register */
#define	CFG_LNKSTS	0x80000000U	/* Link up (83815) */
#define	CFG_SPEED100	0x40000000U	/* 100Mbps (83815) */
#define	CFG_FDUP	0x20000000U	/* full duplex (83815) */
#define	CFG_POL		0x10000000U	/* 10Mbps polarity indication (83815) */
#define	CFG_ANEG_DN	0x08000000U	/* auto negotiation done (83815) */
#define	CFG_PHY_CFG	0x00fc0000U	/* internal PHY configuration (83815) */
#define	CFG_PINT_ACEN	0x00020000U	/* PHY interrupt auto clear (83815) */
#define	CFG_PAUSE_ADV	0x00010000U	/* Advertise pause (83815) */
#define	CFG_ANEG_SEL	0x0000e000U	/* Auto-nego default (83815) */
#define	CFG_EDB_MASTER	0x00002000U	/* sis635, sis900B, sis96x */
#define	CFG_EXT_PHY	0x00001000U	/* External PHY support (83815) */
#define	CFG_PHY_RST	0x00000400U	/* Internal PHY reset (83815) */
#define	CFG_RND_CNT	0x00000400U	/* sis635 & 900B */
#define	CFG_PHY_DIS	0x00000200U	/* Internal PHY disable (83815) */
#define	CFG_FAIR_BCKOFF	0x00000200U	/* sis635 & 900B */
#define	CFG_EUPHCOMP	0x00000100U	/* DP83810 compatibility (83815) */
#define	CFG_DESCRFMT	0x00000100U	/* sis7016 */
#define	CFG_REQALG	0x00000080U	/* PCI Bus request algorithm */
#define	CFG_SB		0x00000040U	/* Single backoff */
#define	CFG_POW		0x00000020U	/* Program out of window timer */
#define	CFG_EXD		0x00000010U	/* Excessive deferral timer disable */
#define	CFG_PESEL	0x00000008U	/* Parity error detection action */
#define	CFG_BROM_DIS	0x00000004U	/* BootRom disable (83815) */
#define	CFG_BEM		0x00000001U	/* Big endian mode */

#define	CFG_BITS_DP83815	\
	"\020"	\
	"\040CFG_LNKSTS"	\
	"\037SPEED100"	\
	"\036FDUP"	\
	"\035POL"	\
	"\034ANEG_DN"	\
	"\022PINT_ACEN"	\
	"\021PAUSE_ADV"	\
	"\015EXT_PHY"	\
	"\013PHY_RST"	\
	"\012PHY_DIS"	\
	"\011EUPHCOMP"	\
	"\010REQALG"	\
	"\007SB"	\
	"\006POW"	\
	"\005EXD"	\
	"\004PESEL"	\
	"\003BROM_DIS"	\
	"\001BEM"

#define	CFG_BITS_SIS900	\
	"\020"	\
	"\016EDB_EN"	\
	"\013RND_CNT"	\
	"\010REQALG"	\
	"\007SB"	\
	"\006POW"	\
	"\005EXD"	\
	"\004PESEL"	\
	"\001BEM"

/* Serial EEPROM access register */
#define	EROMAR_EECS	0x00000008U	/* EEPROM chip select */
#define	EROMAR_EESK	0x00000004U	/* EEPROM serial clock */
#define	EROMAR_EEDO	0x00000002U	/* EEPROM data out */
#define	EROMAR_EEDO_SHIFT	1
#define	EROMAR_EEDI	0x00000001U	/* EEPROM data in + */
#define	EROMAR_EEDI_SHIFT	0
#define	EROMAR_EEREQ	0x00000400U	/* for sis963 eeprom mamagement */
#define	EROMAR_EEDONE	0x00000200U	/* for sis963 eeprom mamagement */
#define	EROMAR_EEGNT	0x00000100U	/* for sis963 eeprom mamagement */

#define	MEAR_MDC	0x00000040U
#define	MEAR_MDDIR	0x00000020U
#define	MEAR_MDIO	0x00000010U
#define	MEAR_MDIO_SHIFT	4

/* PCI Test Control register */
#define	DISCARD_TEST	0x40000000U	/* Discard timer test mode */

/* Interrupt status register */
#define	ISR_WAKEEVT	0x10000000U	/* sis900 */
#define	ISR_PAUSE_END	0x08000000U	/* sis900 */
#define	ISR_PAUSE_ST	0x04000000U	/* sis900 */
#define	ISR_TXRCMP	0x02000000U
#define	ISR_RXRCMP	0x01000000U
#define	ISR_DPERR	0x00800000U	/* Detected parity error */
#define	ISR_SSERR	0x00400000U	/* Signaled system error */
#define	ISR_RMABT	0x00200000U	/* Received master abort */
#define	ISR_RTABT	0x00100000U	/* Received target abort */
#define	ISR_RXSOVR	0x00010000U	/* Received status FIFO overrun */
#define	ISR_HIBERR	0x00008000U
#define	ISR_SWI		0x00001000U
#define	ISR_TXURN	0x00000400U
#define	ISR_TXIDLE	0x00000200U
#define	ISR_TXERR	0x00000100U
#define	ISR_TXDESC	0x00000080U
#define	ISR_TXOK	0x00000040U
#define	ISR_RXORN	0x00000020U
#define	ISR_RXIDLE	0x00000010U
#define	ISR_RXEARLY	0x00000008U
#define	ISR_RXERR	0x00000004U
#define	ISR_RXDESC	0x00000002U
#define	ISR_RXOK	0x00000001U

#define	INTR_BITS	\
	"\020"		\
	"\035WakeEvt"	\
	"\034PauseEnd"	\
	"\033PauseST"	\
	"\032TXRCMP"	\
	"\031RXRCMP"	\
	"\030DPErr"	\
	"\027SSErr"	\
	"\026RMAbt"	\
	"\025RTAbt"	\
	"\021RxSOVR"	\
	"\020HIBErr"	\
	"\015SWI"	\
	"\013TxUrn"	\
	"\012TxIdle"	\
	"\011TxErr"	\
	"\010TxDesc"	\
	"\007TxOk"	\
	"\006RxORN"	\
	"\005RxIdle"	\
	"\004RxEarly"	\
	"\003RxErr"	\
	"\002RxDesc"	\
	"\001RxOk"


/* Interrupt enable reigster */
#define	IER_IE		0x00000001	/* Interrupt enable */

/* Enhanced PHY acces register */
#define	ENPHY_DATA		0xffff0000U	/* data */
#define		ENPHY_DATA_SHIFT	16
#define	ENPHY_ADDR		0x0000f800U	/* phy address */
#define		ENPHY_ADDR_SHIFT	11
#define	ENPHY_OFFSET		0x000007c0U	/* offset */
#define		ENPHY_OFFSET_SHIFT	6
#define	ENPHY_RDCMD		0x00000020U	/* read */
#define	ENPHY_ACCESS		0x00000010U	/* busy */


/* Transmit configuration register */
#define	TXCFG_CSI		0x80000000U	/* carrier sense ignore */
#define	TXCFG_HBI		0x40000000U	/* heart beat ignore */
#define	TXCFG_MLB		0x20000000U	/* MAC loop back */
#define	TXCFG_ATP		0x10000000U	/* Automatic transmit padding */
#define	TXCFG_MXDMA		0x00700000U	/* max dma burst size */
#define		TXCFG_MXDMA_SHIFT	20
#define		TXCFG_MXDMA_512		(0U << TXCFG_MXDMA_SHIFT)
#define		TXCFG_MXDMA_4		(1U << TXCFG_MXDMA_SHIFT)
#define		TXCFG_MXDMA_8		(2U << TXCFG_MXDMA_SHIFT)
#define		TXCFG_MXDMA_16		(3U << TXCFG_MXDMA_SHIFT)
#define		TXCFG_MXDMA_32		(4U << TXCFG_MXDMA_SHIFT)
#define		TXCFG_MXDMA_64		(5U << TXCFG_MXDMA_SHIFT)
#define		TXCFG_MXDMA_128		(6U << TXCFG_MXDMA_SHIFT)
#define		TXCFG_MXDMA_256		(7U << TXCFG_MXDMA_SHIFT)
#define	TXCFG_FLTH		0x00003f00U	/* Tx fill threshold */
#define		TXCFG_FLTH_SHIFT	8
#define	TXCFG_DRTH		0x0000003fU	/* Tx drain threshold */

#define	TXFIFOSIZE	2048U
#define	TXCFG_FIFO_UNIT	32U

#define	TXCFG_BITS	"\020\040CSI\037HBI\036MLB\035ATP"

/* RXCFG:43 Reveive configuration register */
#define	RXCFG_AEP		0x80000000U	/* accept error packets */
#define	RXCFG_ARP		0x40000000U	/* accept runt packets */
#define	RXCFG_ATX		0x10000000U	/* accept transmit packets */
#define	RXCFG_AJAB		0x08000000U	/* accept jabber packets */
#define	RXCFG_ALP_DP83815	0x08000000U	/* accept long pakets */
#define	RXCFG_MXDMA		0x00700000U	/* max dma burst size */
#define		RXCFG_MXDMA_SHIFT	(20)
#define		RXCFG_MXDMA_512	(0U << RXCFG_MXDMA_SHIFT)
#define		RXCFG_MXDMA_4	(1U << RXCFG_MXDMA_SHIFT)
#define		RXCFG_MXDMA_8	(2U << RXCFG_MXDMA_SHIFT)
#define		RXCFG_MXDMA_16	(3U << RXCFG_MXDMA_SHIFT)
#define		RXCFG_MXDMA_32	(4U << RXCFG_MXDMA_SHIFT)
#define		RXCFG_MXDMA_64	(5U << RXCFG_MXDMA_SHIFT)
#define		RXCFG_MXDMA_128	(6U << RXCFG_MXDMA_SHIFT)
#define		RXCFG_MXDMA_256	(7U << RXCFG_MXDMA_SHIFT)
#define	RXCFG_DRTH		0x0000003eU	/* Rx drain threshold */
#define		RXCFG_DRTH_SHIFT	1

#define	RXFIFOSIZE	2048U
#define	RXCFG_FIFO_UNIT	8U

#define	RXCFG_BITS	"\020\040AEP\037ARP\035ATX\034AJAB"


/* FLWCRL:0x38 Flow Control register */
#define	FLOWCTL_PAUSE		0x00000002U	/* PAUSE flag */
#define	FLOWCTL_FLOWEN		0x00000001U	/* flow control enable */

#define	FLOWCTL_BITS	"\020\002PAUSE\001FLOWEN"

/* CCSR:0x3c Clock run Control status register */
#define	CCSR_PMESTS	0x00008000U
#define	CCSR_PMEEN	0x00000100U
#define	CCSR_CLKRUN_EN	0x00000001U

/* PCR:0x44 Pause control/status register (DP83815) */
#define	PCR_PSEN		0x80000000U	/* Pause Enable */
#define	PCR_PS_MCAST		0x40000000U	/* Pause on multicast */
#define	PCR_PS_DA		0x20000000U	/* Pause on DA */
#define	PCR_PS_ACT		0x00800000U	/* Pause active */
#define	PCR_PS_RCVD		0x00400000U	/* Pause frame receved */
#define	PCR_PSNEG		0x00200000U	/* Pause negotiated */
#define	PCR_MLD_EN		0x00010000U	/* Manual load enable */
#define	PCR_PAUSE_CNT		0x0000ffffU	/* Pause counter value */

#define	PCR_BITS	\
	"\020" \
	"\040PCR_PSEN" \
	"\037PCR_PS_MCAST" \
	"\036PCR_PS_DA" \
	"\030PCR_PS_ACT" \
	"\027PCR_PS_RCVD" \
	"\026PCR_PSNEG" \
	"\021PCR_MLD_EN"

/* RFCR:0x48 Receive filter control register */
#define	RFCR_RFEN		0x80000000U	/* receive filter enable */
#define	RFCR_AAB		0x40000000U	/* accept all broadcast */
#define	RFCR_AAM		0x20000000U	/* accept all multicast */
#define	RFCR_AAP		0x10000000U	/* accept all physical */
#define	RFCR_APM_DP83815	0x08000000U	/* accept perfect match */
#define	RFCR_APAT_DP83815	0x07800000U	/* accept on pattern match */
#define	RFCR_APAT_SHIFT		23		/* pattern match base */
#define	RFCR_AARP_DP83815	0x00400000U	/* accept arp packets */
#define	RFCR_MHEN_DP83815	0x00200000U	/* multicast hash enable */
#define	RFCR_UHEN_DP83815	0x00100000U	/* unicast hash enable */
#define	RFCR_ULM_DP83815	0x00080000U	/* U/L bit mask */
#define	RFCR_RFADDR_SIS900	0x000f0000U	/* receive filter address */
#define	RFCR_RFADDR_SHIFT_SIS900	16
#define	RFCR_RFADDR_DP83815	0x000003ffU
#define	RFCR_RFADDR_SHIFT_DP83815	0

/* Receive filter offset */
#define	RFADDR_MAC_SIS900		0U
#define	RFADDR_MULTICAST_SIS900		4U

#define	RFADDR_MAC_DP83815		0x000U
#define	RFADDR_PCOUNT01_DP83815		0x006U
#define	RFADDR_PCOUNT23_DP83815		0x008U
#define	RFADDR_MULTICAST_DP83815	0x200U
#define	RFADDR_PMATCH0_DP83815		0x280U
#define	RFADDR_PMATCH1_DP83815		0x282U
#define	RFADDR_PMATCH2_DP83815		0x300U
#define	RFADDR_PMATCH3_DP83815		0x302U

/* Receive filter data register */

/* dp83815 Silicon revision register */
#define	SRR_REV			0x0000ffffU
#define	SRR_REV_DP83815CVNG	0x0302U
#define	SRR_REV_DP83815DVNG	0x0403U
#define	SRR_REV_DP83816AVNG	0x0505U

/* sis900 revisions */
#define	SIS630A_900_REV		0x80
#define	SIS630E_900_REV		0x81
#define	SIS630S_900_REV		0x82
#define	SIS630EA1_900_REV	0x83
#define	SIS630ET_900_REV	0x84
#define	SIS635A_900_REV		0x90
#define	SIS962_900_REV		0X91
#define	SIS900B_900_REV		0x03

#define	SIS630A0	0x00
#define	SIS630A1	0x01
#define	SIS630B0	0x10
#define	SIS630B1	0x11


#endif	/* _SFEREG_H_ */

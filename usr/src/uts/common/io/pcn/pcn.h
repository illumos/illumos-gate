/*
 * Copyright 2011 Jason King.
 * Copyright (c) 2000 Berkeley Software Design, Inc.
 * Copyright (c) 1997, 1998, 1999, 2000
 *	Bill Paul <wpaul@ee.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef	_PCN_H
#define	_PCN_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * 16-bit I/O map
 * To switch to 32-bit mode, write to RDP.
 */
#define	PCN_IO16_APROM00	0x00
#define	PCN_IO16_APROM01	0x02
#define	PCN_IO16_APROM02	0x04
#define	PCN_IO16_APROM03	0x06
#define	PCN_IO16_APROM04	0x08
#define	PCN_IO16_APROM05	0x0A
#define	PCN_IO16_APROM06	0x0C
#define	PCN_IO16_APROM07	0x0E
#define	PCN_IO16_RDP		0x10
#define	PCN_IO16_RAP		0x12
#define	PCN_IO16_RESET		0x14
#define	PCN_IO16_BDP		0x16

/*
 * 32-bit I/O map
 */
#define	PCN_IO32_APROM00	0x00
#define	PCN_IO32_APROM01	0x04
#define	PCN_IO32_APROM02	0x08
#define	PCN_IO32_APROM03	0x0C
#define	PCN_IO32_RDP		0x10
#define	PCN_IO32_RAP		0x14
#define	PCN_IO32_RESET		0x18
#define	PCN_IO32_BDP		0x1C

/*
 * CSR registers
 */
#define	PCN_CSR_CSR		0x00
#define	PCN_CSR_IAB0		0x01
#define	PCN_CSR_IAB1		0x02
#define	PCN_CSR_IMR		0x03
#define	PCN_CSR_TFEAT		0x04
#define	PCN_CSR_EXTCTL1		0x05
#define	PCN_CSR_DTBLLEN		0x06
#define	PCN_CSR_EXTCTL2		0x07
#define	PCN_CSR_MAR0		0x08
#define	PCN_CSR_MAR1		0x09
#define	PCN_CSR_MAR2		0x0A
#define	PCN_CSR_MAR3		0x0B
#define	PCN_CSR_PAR0		0x0C
#define	PCN_CSR_PAR1		0x0D
#define	PCN_CSR_PAR2		0x0E
#define	PCN_CSR_MODE		0x0F
#define	PCN_CSR_RXADDR0		0x18
#define	PCN_CSR_RXADDR1		0x19
#define	PCN_CSR_TXADDR0		0x1E
#define	PCN_CSR_TXADDR1		0x1F
#define	PCN_CSR_TXPOLL		0x2F
#define	PCN_CSR_RXPOLL		0x31
#define	PCN_CSR_RXRINGLEN	0x4C
#define	PCN_CSR_TXRINGLEN	0x4E
#define	PCN_CSR_DMACTL		0x50
#define	PCN_CSR_BUSTIMER	0x52
#define	PCN_CSR_MEMERRTIMEO	0x64
#define	PCN_CSR_ONNOWMISC	0x74
#define	PCN_CSR_ADVFEAT		0x7A
#define	PCN_CSR_MACCFG		0x7D
#define	PCN_CSR_CHIPID0		0x58
#define	PCN_CSR_CHIPID1		0x59


#define	PCN_CSR_INIT		0x0001
#define	PCN_CSR_START		0x0002
#define	PCN_CSR_STOP		0x0004
#define	PCN_CSR_TX		0x0008
#define	PCN_CSR_TXON		0x0010
#define	PCN_CSR_RXON		0x0020
#define	PCN_CSR_INTEN		0x0040
#define	PCN_CSR_INTR		0x0080
#define	PCN_CSR_IDONE		0x0100
#define	PCN_CSR_TINT		0x0200
#define	PCN_CSR_RINT		0x0400
#define	PCN_CSR_MERR		0x0800
#define	PCN_CSR_MISS		0x1000
#define	PCN_CSR_CERR		0x2000
#define	PCN_CSR_ERR		0x8000
#define	PCN_CSR_STR \
	"\020" \
	"\001INIT" \
	"\002START" \
	"\003STOP" \
	"\004TX" \
	"\005TXON" \
	"\006RXON" \
	"\007INTEN" \
	"\010INTR" \
	"\011IDONE" \
	"\012TINT" \
	"\013RINT" \
	"\014MERR" \
	"\015MISS" \
	"\016CERR" \
	"\017ERR"

/*
 * Interrupt masks and deferral control (CSR3)
 */
#define	PCN_IMR_BSWAP		0x0004
#define	PCN_IMR_ENMBA		0x0008	/* enable modified backoff alg */
#define	PCN_IMR_DXMT2PD		0x0010
#define	PCN_IMR_LAPPEN		0x0020	/* lookahead packet processing enb */
#define	PCN_IMR_DXSUFLO		0x0040	/* disable TX stop on underflow */
#define	PCN_IMR_IDONE		0x0100
#define	PCN_IMR_TINT		0x0200
#define	PCN_IMR_RINT		0x0400
#define	PCN_IMR_MERR		0x0800
#define	PCN_IMR_MISS		0x1000
#define	PCN_IMR_STR \
	"\020" \
	"\003BSWAP" \
	"\004ENMBA" \
	"\005DXMT2PD" \
	"\006LAPPEN" \
	"\007DXSUFLO" \
	"\010IDONE" \
	"\011TINT" \
	"\012RINT" \
	"\013MERR" \
	"\014MISS"

/*
 * Test and features control (CSR4)
 */
#define	PCN_TFEAT_TXSTRTMASK	0x0004
#define	PCN_TFEAT_TXSTRT	0x0008
#define	PCN_TFEAT_RXCCOFLOWM	0x0010	/* Rx collision counter oflow */
#define	PCN_TFEAT_RXCCOFLOW	0x0020
#define	PCN_TFEAT_UINT		0x0040
#define	PCN_TFEAT_UINTREQ	0x0080
#define	PCN_TFEAT_MISSOFLOWM	0x0100
#define	PCN_TFEAT_MISSOFLOW	0x0200
#define	PCN_TFEAT_STRIP_FCS	0x0400
#define	PCN_TFEAT_PAD_TX	0x0800
#define	PCN_TFEAT_TXDPOLL	0x1000
#define	PCN_TFEAT_DMAPLUS	0x4000

/*
 * Extended control and interrupt 1 (CSR5)
 */
#define	PCN_EXTCTL1_SPND	0x0001	/* suspend */
#define	PCN_EXTCTL1_MPMODE	0x0002	/* magic packet mode */
#define	PCN_EXTCTL1_MPENB	0x0004	/* magic packet enable */
#define	PCN_EXTCTL1_MPINTEN	0x0008	/* magic packet interrupt enable */
#define	PCN_EXTCTL1_MPINT	0x0010	/* magic packet interrupt */
#define	PCN_EXTCTL1_MPPLBA	0x0020	/* magic packet phys. logical bcast */
#define	PCN_EXTCTL1_EXDEFEN	0x0040	/* excessive deferral interrupt enb. */
#define	PCN_EXTCTL1_EXDEF	0x0080	/* excessive deferral interrupt */
#define	PCN_EXTCTL1_SINTEN	0x0400	/* system interrupt enable */
#define	PCN_EXTCTL1_SINT	0x0800	/* system interrupt */
#define	PCN_EXTCTL1_LTINTEN	0x4000	/* last TX interrupt enb */
#define	PCN_EXTCTL1_TXOKINTD	0x8000	/* TX OK interrupt disable */
#define	PCN_EXTCTL1_STR \
	"\020" \
	"\001SPND" \
	"\002MPMODE" \
	"\003MPENB" \
	"\004MPINTEN" \
	"\005MPINT" \
	"\006MPPLB" \
	"\007EXDEFEN" \
	"\010EXDEF" \
	"\013SINTEN" \
	"\014SINT" \
	"\017LTINTEN" \
	"\020TXOKINTD"

/*
 * RX/TX descriptor len (CSR6)
 */
#define	PCN_DTBLLEN_RLEN	0x0F00
#define	PCN_DTBLLEN_TLEN	0xF000

/*
 * Extended control and interrupt 2 (CSR7)
 */
#define	PCN_EXTCTL2_MIIPDTINTE	0x0001
#define	PCN_EXTCTL2_MIIPDTINT	0x0002
#define	PCN_EXTCTL2_MCCIINTE	0x0004
#define	PCN_EXTCTL2_MCCIINT	0x0008
#define	PCN_EXTCTL2_MCCINTE	0x0010
#define	PCN_EXTCTL2_MCCINT	0x0020
#define	PCN_EXTCTL2_MAPINTE	0x0040
#define	PCN_EXTCTL2_MAPINT	0x0080
#define	PCN_EXTCTL2_MREINTE	0x0100
#define	PCN_EXTCTL2_MREINT	0x0200
#define	PCN_EXTCTL2_STINTE	0x0400
#define	PCN_EXTCTL2_STINT	0x0800
#define	PCN_EXTCTL2_RXDPOLL	0x1000
#define	PCN_EXTCTL2_RDMD	0x2000
#define	PCN_EXTCTL2_RXFRTG	0x4000
#define	PCN_EXTCTL2_FASTSPNDE	0x8000
#define	PCN_EXTCTL2_STR \
	"\020" \
	"\001MIIPDTINTE" \
	"\002MIIPDTINT" \
	"\003MCCIINTTE" \
	"\004MCCIINT" \
	"\005MCCINTE" \
	"\006MCCINT" \
	"\007MAPINTE" \
	"\010MAPINT" \
	"\011MRTINTE" \
	"\012MREINT" \
	"\013STINTE" \
	"\014STINT" \
	"\015RXDPOLL" \
	"\016RDMD" \
	"\017RXFRTG" \
	"\020FASTSPNDE"

/*
 * Mode (CSR15)
 */
#define	PCN_MODE_RXD		0x0001	/* RX disable */
#define	PCN_MODE_TXD		0x0002	/* TX disable */
#define	PCN_MODE_LOOP		0x0004	/* loopback enable */
#define	PCN_MODE_TXCRCD		0x0008
#define	PCN_MODE_FORCECOLL	0x0010
#define	PCN_MODE_RETRYD		0x0020
#define	PCN_MODE_INTLOOP	0x0040
#define	PCN_MODE_PORTSEL	0x0180
#define	PCN_MODE_RXVPAD		0x2000
#define	PCN_MODE_RXNOBROAD	0x4000
#define	PCN_MODE_PROMISC	0x8000
#define	PCN_MODE_STR \
	"\020" \
	"\001RXD" \
	"\002TXD" \
	"\003LOOP" \
	"\004TXCRCD" \
	"\005FORCECOLL" \
	"\006RETRYD" \
	"\007INTLOOP" \
	"\016RXVPAD" \
	"\017RXNOBROAD" \
	"\020PROMISC"

/* Settings for PCN_MODE_PORTSEL when ASEL (BCR2[1]) is 0 */
#define	PCN_PORT_AUI		0x0000
#define	PCN_PORT_10BASET	0x0080
#define	PCN_PORT_GPSI		0x0100
#define	PCN_PORT_MII		0x0180

/*
 * Chip ID values.
 */

#define	CHIPID_MANFID(x)	(((x) >> 1) & 0x3ff)
#define	CHIPID_PARTID(x)	(((x) >> 12) & 0xffff)
#define	CHIPID_VER(x)		(((x) >> 28) & 0x7)

/* CSR88-89: Chip ID masks */
#define	Am79C970  0x0003
#define	Am79C970A 0x2621
#define	Am79C971  0x2623
#define	Am79C972  0x2624
#define	Am79C973  0x2625
#define	Am79C978  0x2626
#define	Am79C975  0x2627
#define	Am79C976  0x2628

/*
 * Advanced feature control (CSR122)
 */
#define	PCN_AFC_RXALIGN		0x0001

/*
 * BCR (bus control) registers
 */
#define	PCN_BCR_MMRA		0x00	/* Master Mode Read Active */
#define	PCN_BCR_MMW		0x01	/* Master Mode Write Active */
#define	PCN_BCR_MISCCFG		0x02
#define	PCN_BCR_LED0		0x04
#define	PCN_BCR_LED1		0x05
#define	PCN_BCR_LED2		0x06
#define	PCN_BCR_LED3		0x07
#define	PCN_BCR_DUPLEX		0x09
#define	PCN_BCR_BUSCTL		0x12
#define	PCN_BCR_EECTL		0x13
#define	PCN_BCR_SSTYLE		0x14
#define	PCN_BCR_PCILAT		0x16
#define	PCN_BCR_PCISUBVENID	0x17
#define	PCN_BCR_PCISUBSYSID	0x18
#define	PCN_BCR_SRAMSIZE	0x19
#define	PCN_BCR_SRAMBOUND	0x1A
#define	PCN_BCR_SRAMCTL		0x1B
#define	PCN_BCR_TIMER		0x1F
#define	PCN_BCR_MIICTL		0x20
#define	PCN_BCR_MIIADDR		0x21
#define	PCN_BCR_MIIDATA		0x22
#define	PCN_BCR_PCIVENID	0x23
#define	PCN_BCR_PCIPCAP		0x24
#define	PCN_BCR_DATA0		0x25
#define	PCN_BCR_DATA1		0x26
#define	PCN_BCR_DATA2		0x27
#define	PCN_BCR_DATA3		0x28
#define	PCN_BCR_DATA4		0x29
#define	PCN_BCR_DATA5		0x2A
#define	PCN_BCR_DATA6		0x2B
#define	PCN_BCR_DATA7		0x2C
#define	PCN_BCR_ONNOWPAT0	0x2D
#define	PCN_BCR_ONNOWPAT1	0x2E
#define	PCN_BCR_ONNOWPAT2	0x2F
#define	PCN_BCR_PHYSEL		0x31

/*
 * Miscellaneous Configuration (BCR2)
 */
#define	PCN_MISC_TMAULOOP	1<<14	/* T-MAU Loopback packet enable. */
#define	PCN_MISC_LEDPE		1<<12	/* LED Program Enable */
#define	PCN_MISC_APROMWE	1<<8	/* Address PROM Write Enable */
#define	PCN_MISC_INTLEVEL	1<<7	/* Interrupt level */
#define	PCN_MISC_EADISEL	1<<3	/* EADI Select */
#define	PCN_MISC_AWAKE		1<<2	/* Power saving mode select */
#define	PCN_MISC_ASEL		1<<1	/* Auto Select */
#define	PCN_MISC_XMAUSEL	1<<0	/* Reserved. */

/*
 * Full duplex control (BCR9)
 */
#define	PCN_DUPLEX_FDEN		0x0001	/* Full-duplex enable */
#define	PCN_DUPLEX_AUI		0x0002	/* AUI full-duplex */
#define	PCN_DUPLEX_FDRPAD	0x0004	/* Full-duplex runt pkt accept dis. */

/*
 * Burst and bus control register (BCR18)
 */
#define	PCN_BUSCTL_BWRITE	0x0020
#define	PCN_BUSCTL_BREAD	0x0040
#define	PCN_BUSCTL_DWIO		0x0080
#define	PCN_BUSCTL_EXTREQ	0x0100
#define	PCN_BUSCTL_MEMCMD	0x0200
#define	PCN_BUSCTL_NOUFLOW	0x0800
#define	PCN_BUSCTL_ROMTMG	0xF000

/*
 * EEPROM control (BCR19)
 */
#define	PCN_EECTL_EDATA		0x0001
#define	PCN_EECTL_ECLK		0x0002
#define	PCN_EECTL_EECS		0x0004
#define	PCN_EECTL_EEN		0x0100
#define	PCN_EECTL_EEDET		0x2000
#define	PCN_EECTL_PREAD		0x4000
#define	PCN_EECTL_PVALID	0x8000

/*
 * Software style (BCR20)
 */
#define	PCN_SSTYLE_APERREN	0x0400	/* advanced parity error checking */
#define	PCN_SSTYLE_SSIZE32	0x0100
#define	PCN_SSTYLE_SWSTYLE	0x00FF

#define	PCN_SWSTYLE_LANCE		0x0000
#define	PCN_SWSTYLE_PCNETPCI		0x0102
#define	PCN_SWSTYLE_PCNETPCI_BURST	0x0103

/*
 * MII control and status (BCR32)
 */
#define	PCN_MIICTL_MIILP	0x0002	/* MII internal loopback */
#define	PCN_MIICTL_XPHYSP	0x0008	/* external PHY speed */
#define	PCN_MIICTL_XPHYFD	0x0010	/* external PHY full duplex */
#define	PCN_MIICTL_XPHYANE	0x0020	/* external phy auto-neg enable */
#define	PCN_MIICTL_XPHYRST	0x0040	/* external PHY reset */
#define	PCN_MIICTL_DANAS	0x0080	/* disable auto-neg auto-setup */
#define	PCN_MIICTL_APDW		0x0700	/* auto-poll dwell time */
#define	PCN_MIICTL_APEP		0x0100	/* auto-poll external PHY */
#define	PCN_MIICTL_FMDC		0x3000	/* data clock speed */
#define	PCN_MIICTL_MIIPD	0x4000	/* PHY detect */
#define	PCN_MIICTL_ANTST	0x8000	/* Manufacturing test */

/*
 * MII address register (BCR33)
 */
#define	PCN_MIIADDR_REGAD	0x001F
#define	PCN_MIIADDR_PHYAD	0x03E0

/* addresses of internal PHYs */
#define	PCN_PHYAD_100BTX	30
#define	PCN_PHYAD_10BT		31

/*
 * MII data register (BCR34)
 */
#define	PCN_MIIDATA_MIIMD	0xFFFF

/*
 * PHY selection (BCR49) (HomePNA NIC only)
 */
#define	PCN_PHYSEL_PHYSEL	0x0003
#define	PCN_PHYSEL_DEFAULT	0x0300
#define	PCN_PHYSEL_PCNET	0x8000

#define	PCN_PHY_10BT		0x0000
#define	PCN_PHY_HOMEPNA		0x0001
#define	PCN_PHY_EXTERNAL	0x0002

#ifdef	__cplusplus
}
#endif

#endif /* _PCN_H */

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
 */

/*
 * Register definitions for the VIA Rhine ethernet adapters
 */
#ifndef _VRREG_H
#define	_VRREG_H

#ifdef __cplusplus
	extern "C" {
#endif

/*
 * MAC address
 */
#define	VR_ETHERADDR	0x00

/*
 * Receive Configuration
 * The thresholds denote the level in the FIFO before transmission
 * to host memory starts.
 */
#define	VR_RXCFG			0x06
#define	VR_RXCFG_ACCEPTERROR		(1 << 0)
#define	VR_RXCFG_ACCEPTRUNT		(1 << 1)
#define	VR_RXCFG_ACCEPTMULTI		(1 << 2)
#define	VR_RXCFG_ACCEPTBROAD		(1 << 3)
#define	VR_RXCFG_PROMISC		(1 << 4)
#define	VR_RXCFG_FIFO_THRESHOLD_0	(1 << 5)
#define	VR_RXCFG_FIFO_THRESHOLD_1	(1 << 6)
#define	VR_RXCFG_FIFO_THRESHOLD_2	(1 << 7)
#define	VR_RXCFG_FIFO_THRESHOLD_BITS	(VR_RXCFG_FIFO_THRESHOLD_0 | \
					    VR_RXCFG_FIFO_THRESHOLD_1 | \
					    VR_RXCFG_FIFO_THRESHOLD_2)
#define	VR_RXCFG_FIFO_THRESHOLD_64	(0)
#define	VR_RXCFG_FIFO_THRESHOLD_32	(VR_RXCFG_FIFO_THRESHOLD_0)
#define	VR_RXCFG_FIFO_THRESHOLD_128	(VR_RXCFG_FIFO_THRESHOLD_1)
#define	VR_RXCFG_FIFO_THRESHOLD_256	(VR_RXCFG_FIFO_THRESHOLD_0 | \
					    VR_RXCFG_FIFO_THRESHOLD_1)
#define	VR_RXCFG_FIFO_THRESHOLD_512	(VR_RXCFG_FIFO_THRESHOLD_2)
#define	VR_RXCFG_FIFO_THRESHOLD_768	(VR_RXCFG_FIFO_THRESHOLD_0 | \
					    VR_RXCFG_FIFO_THRESHOLD_2)
#define	VR_RXCFG_FIFO_THRESHOLD_1024	(VR_RXCFG_FIFO_THRESHOLD_2 | \
					    VR_RXCFG_FIFO_THRESHOLD_1)
#define	VR_RXCFG_FIFO_THRESHOLD_STFW	(VR_RXCFG_FIFO_THRESHOLD_BITS)

/*
 * Transmit Configuration
 * The transmission starts when the data in the FIFO reaches the threshold.
 * Store and Forward means that a transmission starts when a complete frame
 * is in the FIFO.
 */
#define	VR_TXCFG			0x07
#define	VR_TXCFG_8021PQ_EN		(1 << 0)	/* VT6105M */
#define	VR_TXCFG_LOOPBACK_0		(1 << 1)
#define	VR_TXCFG_LOOPBACK_1		(2 << 2)
#define	VR_TXCFG_BACKOFF_NATIONAL	(1 << 3)	/* < VT6105M */
#define	VR_TXCFG_FIFO_THRESHOLD_0	(1 << 5)
#define	VR_TXCFG_FIFO_THRESHOLD_1	(1 << 6)
#define	VR_TXCFG_FIFO_THRESHOLD_2	(1 << 7)
#define	VR_TXCFG_FIFO_THRESHOLD_BITS	(VR_TXCFG_FIFO_THRESHOLD_0 | \
					    VR_TXCFG_FIFO_THRESHOLD_1 | \
					    VR_TXCFG_FIFO_THRESHOLD_2)
#define	VR_TXCFG_FIFO_THRESHOLD_128	(0)
#define	VR_TXCFG_FIFO_THRESHOLD_256	(VR_TXCFG_FIFO_THRESHOLD_0)
#define	VR_TXCFG_FIFO_THRESHOLD_512	(VR_TXCFG_FIFO_THRESHOLD_1)
#define	VR_TXCFG_FIFO_THRESHOLD_1024	(VR_TXCFG_FIFO_THRESHOLD_0 | \
					    VR_TXCFG_FIFO_THRESHOLD_1)
#define	VR_TXCFG_FIFO_THRESHOLD_STFW	(VR_TXCFG_FIFO_THRESHOLD_BITS)

/*
 * Chip control
 */
#define	VR_CTRL0			0x08
#define	VR_CTRL0_RESERVED		(1 << 0)
#define	VR_CTRL0_DMA_ENABLE		(1 << 1)
#define	VR_CTRL0_DMA_STOP		(1 << 2)
#define	VR_CTRL0_RX_DMA_ENABLE		(1 << 3)
#define	VR_CTRL0_TX_DMA_ENABLE		(1 << 4)
#define	VR_CTRL0_TXPOLL			(1 << 5)	/* < 6105M */
#define	VR_CTRL0_RXPOLL			(1 << 6)	/* < 6105M */

#define	VR_CTRL0_DMA_GO			(VR_CTRL0_DMA_ENABLE | \
					    VR_CTRL0_RX_DMA_ENABLE | \
					    VR_CTRL0_TX_DMA_ENABLE | \
					    VR_CTRL0_TXPOLL)
#define	VR_CTRL1			0x09
#define	VR_CTRL1_RESERVED		(1 << 0)
#define	VR_CTRL1_UNICAST_EN		(1 << 1)
#define	VR_CTRL1_MACFULLDUPLEX		(1 << 2)
#define	VR_CTRL1_NOAUTOPOLL		(1 << 3)
#define	VR_CTRL1_RESERVED2		(1 << 4)
#define	VR_CTRL1_TXPOLL			(1 << 5)	/* VT6105M */
#define	VR_CTRL1_RXPOLL			(1 << 6)	/* VT6105M */
#define	VR_CTRL1_RESET			(1 << 7)

#define	VR_T_XQNWAKE			0x0a		/* VT6105M */

/*
 * Interrupt Status
 * This register reflects NIC status
 * The host reads it to determine the cause of the interrupt
 * This register must be cleared after power-up
 */
#define	VR_ISR0			0x0C
#define	VR_ISR0_RX_DONE		(1 << 0)
#define	VR_ISR0_TX_DONE		(1 << 1)
#define	VR_ISR0_RX_ERR		(1 << 2)
#define	VR_ISR0_TX_ERR		(1 << 3)
#define	VR_ISR0_TX_BUF_UFLOW	(1 << 4)
#define	VR_ISR0_RX_LINKERR	(1 << 5)
#define	VR_ISR0_BUSERR		(1 << 6)
#define	VR_ISR0_STATSMAX	(1 << 7)
#define	VR_ISR0_RX_EARLY	(1 << 8)
#define	VR_ISR0_TX_FIFO_UFLOW	(1 << 9)
#define	VR_ISR0_RX_FIFO_OFLOW	(1 << 10)
#define	VR_ISR0_RX_DROPPED	(1 << 11)
#define	VR_ISR0_RX_NOBUF	(1 << 12)
#define	VR_ISR0_TX_ABORT	(1 << 13)
#define	VR_ISR0_LINKSTATUS	(1 << 14)
#define	VR_ISR0_GENERAL		(1 << 15)

/*
 * Interrupt Configuration
 * All bits in this register correspond to the bits in the Interrupt Status
 * register Setting individual bits will enable the corresponding interrupt
 * This register defaults to all zeros on power up
 */
#define	VR_ICR0			0x0E
#define	VR_ICR0_RX_DONE		VR_ISR0_RX_DONE
#define	VR_ICR0_TX_DONE		VR_ISR0_TX_DONE
#define	VR_ICR0_RX_ERR		VR_ISR0_RX_ERR
#define	VR_ICR0_TX_ERR		VR_ISR0_TX_ERR
#define	VR_ICR0_TX_BUF_UFLOW	VR_ISR0_TX_BUF_UFLOW
#define	VR_ICR0_RX_LINKERR	VR_ISR0_RX_LINKERR
#define	VR_ICR0_BUSERR		VR_ISR0_BUSERR
#define	VR_ICR0_STATSMAX	VR_ISR0_STATSMAX
#define	VR_ICR0_RX_EARLY	VR_ISR0_RX_EARLY
#define	VR_ICR0_TX_FIFO_UFLOW	VR_ISR0_TX_FIFO_UFLOW
#define	VR_ICR0_RX_FIFO_OFLOW	VR_ISR0_RX_FIFO_OFLOW
#define	VR_ICR0_RX_DROPPED	VR_ISR0_RX_DROPPED
#define	VR_ICR0_RX_NOBUF	VR_ISR0_RX_NOBUF
#define	VR_ICR0_TX_ABORT	VR_ISR0_TX_ABORT
#define	VR_ICR0_LINKSTATUS	VR_ISR0_LINKSTATUS
#define	VR_ICR0_GENERAL		VR_ISR0_GENERAL

/*
 * Mulicast address registers (MAR), 8 bytes
 */
#define	VR_MAR0				0x10	/* - 0x13 */
#define	VR_MAR1				0x14	/* - 0x17 */

/*
 * VT6105M has a multicast/vlan filter and the hash bits are also used as
 * CAM data port
 */
#define	VR_MCAM0			0x10	/* VT6105M */
#define	VR_MCAM1			0x11
#define	VR_MCAM2			0x12
#define	VR_MCAM3			0x13
#define	VR_MCAM4			0x14
#define	VR_MCAM5			0x15
#define	VR_VCAM0			0x16
#define	VR_VCAM1			0x17

/*
 * Start addresses of receive and transmit ring
 */
#define	VR_RXADDR			0x18	/* - 0x1B */
#define	VR_TXADDR			0x1C	/* - 0x1F */

/*
 * VT6105M has 8 TX queues
 */
#define	VR_TX7_ADDR			0x1C
#define	VR_TX6_ADDR			0x20
#define	VR_TX5_ADDR			0x24
#define	VR_TX4_ADDR			0x28
#define	VR_TX3_ADDR			0x2C
#define	VR_TX2_ADDR			0x30
#define	VR_TX1_ADDR			0x34
#define	VR_TX0_ADDR			0x38

/*
 * Current and receive- and transmit descriptors.
 * These are listed in the VT6102 manual but not in the VT6105.
 */
#define	VR_RXCUR_DES0			0x20	/* - 0x23 */
#define	VR_RXCUR_DES1			0x24	/* - 0x27 */
#define	VR_RXCUR_DES2			0x28	/* - 0x2B */
#define	VR_RXCUR_DES3			0x2C	/* - 0x2F */

/* VIA secrets here */

#define	VR_INTRLINE			0x3c
#define	VR_INTRPIN			0x3d

/* VIA secrets here */

#define	VR_TXCUR_DES0			0x40	/* - 0x43 */
#define	VR_TXCUR_DES1			0x44	/* - 0x47 */
#define	VR_TXCUR_DES2			0x48	/* - 0x4B */
#define	VR_TXCUR_DES3			0x4C	/* - 0x4F */

#define	VR_MODE0			0x50
#define	VR_MODE0_QPKTDS			0x80

#define	VR_MODE1			0x51
#define	VR_FIFOTST			0x51

/*
 * These are not in the datasheet but used in the 'fet' driver
 */
#define	VR_MODE2			0x52
#define	VR_MODE2_PCEROPT		0x80	/* VT6102 only */
#define	VR_MODE2_DISABT			0x40
#define	VR_MODE2_MRDPL			0x08	/* VT6107A1 and above */
#define	VR_MODE2_MODE10T		0x02

#define	VR_MODE3			0x53
#define	VR_MODE3_XONOPT			0x80
#define	VR_MODE3_TPACEN			0x40
#define	VR_MODE3_BACKOPT		0x20
#define	VR_MODE3_DLTSEL			0x10
#define	VR_MODE3_MIIDMY			0x08
#define	VR_MODE3_MIION			0x04

#define	VR_PCI_DELAY_TIMER		0x54
#define	VR_FIFOCMD			0x56
#define	VR_FIFOSTA			0x57

/* VIA secrets here */

/*
 * MII Configuration
 */
#define	VR_MIIPHYADDR			0x6C
#define	VR_MIIPHYADDR_ADDR0		(1 << 0)
#define	VR_MIIPHYADDR_ADDR1		(1 << 1)
#define	VR_MIIPHYADDR_ADDR2		(1 << 2)
#define	VR_MIIPHYADDR_ADDR3		(1 << 3)
#define	VR_MIIPHYADDR_ADDR4		(1 << 4)
#define	VR_MIIPHYADDR_ADDRBITS		(VR_MIIPHYADDR_ADDR0 | \
					    VR_MIIPHYADDR_ADDR1 | \
					    VR_MIIPHYADDR_ADDR2 | \
					    VR_MIIPHYADDR_ADDR3 | \
					    VR_MIIPHYADDR_ADDR4)
#define	VR_MIIPHYADDR_MD_CLOCK_FAST	(1 << 5)
#define	VR_MIIPHYADDR_POLLBITS		((1 << 7) | (1 << 6))
#define	VR_MIIPHYADDR_POLL1024		((0 << 7) | (0 << 6))
#define	VR_MIIPHYADDR_POLL512		((0 << 7) | (1 << 6))
#define	VR_MIIPHYADDR_POLL128		((1 << 7) | (0 << 6))
#define	VR_MIIPHYADDR_POLL64		((1 << 7) | (1 << 6))

/*
 * MII status
 */
#define	VR_MIISR			0x6D
#define	VR_MIISR_SPEED			(1 << 0) /* VT6102 and VT6105 */
#define	VR_MIISR_LINKFAIL		(1 << 1) /* VT6102 and VT6105 */
#define	VR_MIISR_DUPLEX			(1 << 2) /* VT6105 only */
#define	VR_MIISR_PHYERR			(1 << 3) /* VT6102 and VT6105 */
#define	VR_MIISR_PHYOPT			(1 << 4) /* VT6102 only */
#define	VR_MIISR_NWAYLINKOK		(1 << 4) /* VT6105 only */
#define	VR_MIISR_NWAYPAUSE		(1 << 5) /* VT6105M */
#define	VR_MIISR_NWAYASMPAUSE		(1 << 6) /* VT6105M */
#define	VR_MIISR_PHYRST			(1 << 7)

/*
 * Bus control
 */
#define	VR_BCR0				0x6E		/* receive */
#define	VR_BCR0_DMA0			(1 << 0)
#define	VR_BCR0_DMA1			(1 << 1)
#define	VR_BCR0_DMA2			(1 << 2)
#define	VR_BCR0_DMABITS			(VR_BCR0_DMA0|VR_BCR0_DMA1 | \
					    VR_BCR0_DMA2)
#define	VR_BCR0_DMA32			(0)
#define	VR_BCR0_DMA64			(VR_BCR0_DMA0)
#define	VR_BCR0_DMA128			(VR_BCR0_DMA1)
#define	VR_BCR0_DMA256			(VR_BCR0_DMA0|VR_BCR0_DMA1)
#define	VR_BCR0_DMA512			(VR_BCR0_DMA2)
#define	VR_BCR0_DMA1024			(VR_BCR0_DMA0|VR_BCR0_DMA2)
#define	VR_BCR0_DMASTFW			(VR_BCR0_DMABITS)
#define	VR_BCR0_RX_FIFO_THRESHOLD_0	(1 << 3)
#define	VR_BCR0_RX_FIFO_THRESHOLD_1	(1 << 4)
#define	VR_BCR0_RX_FIFO_THRESHOLD_2	(1 << 5)
#define	VR_BCR0_RX_FIFO_THRESHOLD_BITS	(VR_BCR0_RX_FIFO_THRESHOLD_0 | \
					    VR_BCR0_RX_FIFO_THRESHOLD_1 | \
					    VR_BCR0_RX_FIFO_THRESHOLD_2)
#define	VR_BCR0_RX_FIFO_THRESHOLD_64	(0)
#define	VR_BCR0_RX_FIFO_THRESHOLD_32	(VR_BCR0_RX_FIFO_THRESHOLD_0)
#define	VR_BCR0_RX_FIFO_THRESHOLD_128	(VR_BCR0_RX_FIFO_THRESHOLD_1)
#define	VR_BCR0_RX_FIFO_THRESHOLD_256	(VR_BCR0_RX_FIFO_THRESHOLD_0 | \
					    VR_BCR0_RX_FIFO_THRESHOLD_1)
#define	VR_BCR0_RX_FIFO_THRESHOLD_512	(VR_BCR0_RX_FIFO_THRESHOLD_2)
#define	VR_BCR0_RX_FIFO_THRESHOLD_768	(VR_BCR0_RX_FIFO_THRESHOLD_0 | \
					    VR_BCR0_RX_FIFO_THRESHOLD_2)
#define	VR_BCR0_RX_FIFO_THRESHOLD_1024	(VR_BCR0_RX_FIFO_THRESHOLD_1 | \
					    VR_BCR0_RX_FIFO_THRESHOLD_2)
#define	VR_BCR0_RX_FIFO_THRESHOLD_STFW	(VR_BCR0_RX_FIFO_THRESHOLD_BITS)
#define	VR_BCR0_LEDCR			(1 << 6)
#define	VR_BCR0_MSEL			(1 << 7)

#define	VR_BCR1				0x6F		/* transmit */
#define	VR_BCR1_POLLT_0			(1 << 0)
#define	VR_BCR1_POLLT_1			(1 << 1)
#define	VR_BCR1_POLLT_2			(1 << 2)
#define	VR_BCR1_TX_FIFO_THRESHOLD_0	(1 << 3)
#define	VR_BCR1_TX_FIFO_THRESHOLD_1	(1 << 4)
#define	VR_BCR1_TX_FIFO_THRESHOLD_2	(1 << 5)
#define	VR_BCR1_TX_FIFO_THRESHOLD_BITS	(VR_BCR1_TX_FIFO_THRESHOLD_0 | \
					    VR_BCR1_TX_FIFO_THRESHOLD_1 | \
					    VR_BCR1_TX_FIFO_THRESHOLD_2)
#define	VR_BCR1_TX_FIFO_THRESHOLD_128	(0)
#define	VR_BCR1_TX_FIFO_THRESHOLD_256	(VR_BCR1_TX_FIFO_THRESHOLD_0)
#define	VR_BCR1_TX_FIFO_THRESHOLD_512	(VR_BCR1_TX_FIFO_THRESHOLD_1)
#define	VR_BCR1_TX_FIFO_THRESHOLD_1024	(VR_BCR1_TX_FIFO_THRESHOLD_0 | \
					    VR_BCR1_FIFO_THRESHOLD_1)
#define	VR_BCR1_TX_FIFO_THRESHOLD_STFW	(VR_BCR1_FIFO_THRESHOLD_BITS)
#define	VR_BCR1_TXQPRIO			(1 << 6)	/* VT6105M */
#define	VR_BCR1_VLANFILTER		(1 << 7)	/* VT6105M */

/*
 * MII Configuration
 */
#define	VR_MIICMD			0x70
#define	VR_MIICMD_MD_CLOCK		(1 << 0)
#define	VR_MIICMD_MD_CLOCK_READ		(1 << 1)
#define	VR_MIICMD_MD_CLOCK_WRITE	(1 << 2)
#define	VR_MIICMD_MD_OUT		(1 << 3)
#define	VR_MIICMD_MD_MODE_AUTO		(1 << 4)
#define	VR_MIICMD_MD_WRITE		(1 << 5)
#define	VR_MIICMD_MD_READ		(1 << 6)
#define	VR_MIICMD_MD_AUTO		(1 << 7)

#define	VR_MIIADDR			0x71
#define	VR_MIIADDR_MAD0			(1 << 0)
#define	VR_MIIADDR_MAD1			(1 << 1)
#define	VR_MIIADDR_MAD2			(1 << 2)
#define	VR_MIIADDR_MAD3			(1 << 3)
#define	VR_MIIADDR_MAD4			(1 << 4)
#define	VR_MIIADDR_BITS			(VR_MIIADDR_MAD0 | \
					    VR_MIIADDR_MAD1 | \
					    VR_MIIADDR_MAD2 | \
					    VR_MIIADDR_MAD3 | \
					    VR_MIIADDR_MAD4)
#define	VR_MIIADDR_MDONE		(1 << 5)
#define	VR_MIIADDR_MAUTO		(1 << 6)
#define	VR_MIIADDR_MIDLE		(1 << 7)

#define	VR_MIIDATA			0x72
#define	VR_MIIDATA_1			0x72
#define	VR_MIIDATA_2			0x73

/*
 * EEPROM Config / Status
 */
#define	VR_PROMCTL			0x74
#define	VR_PROMCTL_DATAOUT		(1 << 0)
#define	VR_PROMCTL_DATAIN		(1 << 1)
#define	VR_PROMCTL_CLOCK		(1 << 2)
#define	VR_PROMCTL_CHIPSELECT		(1 << 3)
#define	VR_PROMCTL_DIRPROG		(1 << 4)
#define	VR_PROMCTL_RELOAD		(1 << 5)
#define	VR_PROMCTL_PROGRAM		(1 << 6)
#define	VR_PROMCTL_PRGSTATUS		(1 << 7)

/*
 * Chip Configuration A
 */
#define	VR_CFGA				0x78
#define	VR_CFGA_PRE_ACPI_WAKEUP		(1 << 0)	/* VT6105M */
#define	VR_CFGA_WAKEUP_PANIC		(1 << 1)	/* VT6105M */
#define	VR_CFGA_VLANTAG_INCRC		(1 << 5)	/* VT6105M */
#define	VR_CFGA_MIIOPT			(1 << 6)
#define	VR_CFGA_EELOAD			(1 << 7)

/*
 * Chip Configuration B
 */
#define	VR_CFGB				0x79
#define	VR_CFGB_LATENCYTIMER		(1 << 0)
#define	VR_CFGB_WWAIT			(1 << 1)
#define	VR_CFGB_RWAIT			(1 << 2)
#define	VR_CFGB_RXARBIT			(1 << 3)
#define	VR_CFGB_TXARBIT			(1 << 4)
#define	VR_CFGB_MRLDIS			(1 << 5)
#define	VR_CFGB_PERRDIS			(1 << 6)
#define	VR_CFGB_QPKTDIS			(1 << 7)

/*
 * Chip Configuration C
 */
#define	VR_CFGC				0x7A
#define	VR_CFGC_BPS0			(1 << 0)
#define	VR_CFGC_BPS1			(1 << 1)
#define	VR_CFGC_BPS2			(1 << 2)
#define	VR_CFGC_BTSEL			(1 << 3)
#define	VR_CFGC_DLYEN			(1 << 5)
#define	VR_CFGC_BROPT			(1 << 6)
#define	VR_CFGC_MED3			(1 << 7) /* VT6102 */

/*
 * Chip Configuration D
 */
#define	VR_CFGD				0x7B
#define	VR_CFGD_BAKOPT			(1 << 0)
#define	VR_CFGD_MBA			(1 << 1)
#define	VR_CFGD_CAP			(1 << 2)
#define	VR_CFGD_CRADOM			(1 << 3)
#define	VR_CFGD_PMCDIG			(1 << 4)
#define	VR_CFGD_MRLEN			(1 << 5)
#define	VR_CFGD_TAG_ON_SNAP		(1 << 5)	/* VT6105M */
#define	VR_CFGD_DIAG			(1 << 6)
#define	VR_CFGD_MMIOEN			(1 << 7)

/*
 * Tally counters
 */
#define	VR_TALLY_MPA			0x7c	/* 16 bits */
#define	VR_TALLY_CRC			0x7e	/* 16 bits */

/*
 * Misceleneous register 0
 */
#define	VR_MISC0			0x80
#define	VR_MISC0_TIMER0_EN		(1 << 0)
#define	VR_MISC0_TIMER0_SUSP		(1 << 1)
#define	VR_MISC0_HDXFEN			(1 << 2)
#define	VR_MISC0_FDXRFEN		(1 << 3)
#define	VR_MISC0_FDXTFEN		(1 << 4)
#define	VR_MISC0_TIMER0_USEC_EN		(1 << 5)

/*
 * Misceleneous register 1
 */
#define	VR_MISC1			0x81
#define	VR_MISC1_TIMER1_EN		(1 << 0)
#define	VR_MISC1_VAXJMP			(1 << 5)
#define	VR_MISC1_RESET			(1 << 6)

/*
 * Power management
 */
#define	VR_PWR				0x83
#define	VR_PWR_DS0			(1 << 0)
#define	VR_PWR_DS1			(1 << 1)
#define	VR_PWR_WOLEN			(1 << 2)
#define	VR_PWR_WOLSR			(1 << 3)
#define	VR_PWR_LGWOL			(1 << 7)

/*
 * Second interrupt register status
 */
#define	VR_ISR1				0x84
#define	VR_ISR1_TIMER0			(1 << 0)
#define	VR_ISR1_TIMER1			(1 << 1)
#define	VR_ISR1_PHYEVENT		(1 << 2)
#define	VR_ISR1_TDERR			(1 << 3)
#define	VR_ISR1_SSRCI			(1 << 4)
#define	VR_ISR1_UINTR_SET		(1 << 5)
#define	VR_ISR1_UINTR_CLR		(1 << 6)
#define	VR_ISR1_PWEI			(1 << 7)

/*
 * Second interrupt register configuration
 */
#define	VR_ICR1				0x86
#define	VR_ICR1_TIMER0			VR_ISR1_TIMER0
#define	VR_ICR1_TIMER1			VR_ISR1_TIMER1
#define	VR_ICR1_PHYEVENT		VR_ISR1_PHYEVENT
#define	VR_ICR1_TDERR			VR_ISR1_TDERR
#define	VR_ICR1_SSRCI			VR_ISR1_SSRCI
#define	VR_ICR1_UINTR_SET		VR_ISR1_UINTR_SET
#define	VR_ICR1_UINTR_CLR		VR_ISR1_UINTR_CLR
#define	VR_ICR1_PWEI			VR_ISR1_PWEI

/*
 * Content Addressable Memory (CAM) stuff for the VT6105M
 */
#define	VR_CAM_MASK			0x88

#define	VR_CAM_CTRL			0x92
#define	VR_CAM_CTRL_RD			(1 << 3)
#define	VR_CAM_CTRL_WR			(1 << 2)
#define	VR_CAM_CTRL_SELECT_VLAN		(1 << 1)
#define	VR_CAM_CTRL_ENABLE		(1 << 0)
#define	VR_CAM_CTRL_WRITE		(VR_CAM_CTRL_ENABLE | VR_CAM_CTRL_WR)
#define	VR_CAM_CTRL_READ		(VR_CAM_CTRL_ENABLE | VR_CAM_CTRL_RD)
#define	VR_CAM_CTRL_RW			(VR_CAM_CTRL_ENABLE | \
					    VR_CAM_CTRL_RD | VR_CAM_CTRL_WR)
#define	VR_CAM_CTRL_DONE		(0)

#define	VR_CAM_ADDR			0x93

/*
 * MIB Control register
 */
#define	VR_MIB_CTRL			0x94
#define	VR_MIB_CTRL_ENABLE		(1 << 4)
#define	VR_MIB_CTRL_HDUPLEX		(1 << 5)
#define	VR_MIB_CTRL_INCR		(1 << 6)
#define	VR_MIB_CTRL_RTN			(1 << 7)

/*
 * MIB port
 */
#define	VR_MIB_PORT			0x96

/*
 * MIB data
 */
#define	VR_MIB_DATA			0x97


/*
 * Power configuration
 */
#define	VR_PWRCFG			0xA1		/* VT6105LOM */
#define	VR_PWRCFG_WOLEN			(1 << 0)
#define	VR_PWRCFG_WOLSR			(1 << 1)
#define	VR_PWRCFG_PHYPOWERDOWN		(7 << 1)

/*
 * Flow control, VT6105 and above
 */
#define	VR_FCR0				0x98
#define	VR_FCR0_RXBUFCOUNT		VR_FCR0

#define	VR_FCR1				0x99
#define	VR_FCR1_HD_EN			(1 << 0)
#define	VR_FCR1_FD_RX_EN		(1 << 1)
#define	VR_FCR1_FD_TX_EN		(1 << 2)
#define	VR_FCR1_XONXOFF_EN		(1 << 3)

#define	VR_FCR1_PAUSEOFFBITS		((1 << 5) | (1 << 4))
#define	VR_FCR1_PAUSEOFF_24		((0 << 5) | (0 << 4))
#define	VR_FCR1_PAUSEOFF_32		((0 << 5) | (1 << 4))
#define	VR_FCR1_PAUSEOFF_48		((1 << 5) | (0 << 4))
#define	VR_FCR1_PAUSEOFF_64		((1 << 5) | (1 << 4))

#define	VR_FCR1_PAUSEONBITS		((1 << 7) | (1 << 6))
#define	VR_FCR1_PAUSEON_04		((0 << 7) | (0 << 6))
#define	VR_FCR1_PAUSEON_08		((0 << 7) | (1 << 6))
#define	VR_FCR1_PAUSEON_16		((1 << 7) | (0 << 6))
#define	VR_FCR1_PAUSEON_24		((1 << 7) | (1 << 6))

#define	VR_FCR2				0x9a
#define	VR_FCR2_PAUSE			(VR_FCR2)

#define	VR_TIMER0			0x9c
#define	VR_TIMER0_TIMEOUT		VR_TIMER0	/* 16 bits */

#define	VR_TIMER1			0x9e
#define	VR_TIMER1_TIMEOUT		VR_TIMER1	/* 16 bits */

#define	VR_CRC_PATTERN0			0xb0		/* 32 bits, VT6105M */
#define	VR_CRC_PATTERN1			0xb4		/* 32 bits, VT6105M */
#define	VR_CRC_PATTERN2			0xb8		/* 32 bits, VT6105M */
#define	VR_CRC_PATTERN3			0xbC		/* 32 bits, VT6105M */

/*
 * Receive desctriptor
 */
#define	VR_RDES0_RXERR		(1 << 0)
#define	VR_RDES0_CRCERR		(1 << 1)
#define	VR_RDES0_FAE		(1 << 2)
#define	VR_RDES0_FOV		(1 << 3)
#define	VR_RDES0_LONG		(1 << 4)
#define	VR_RDES0_RUNT		(1 << 5)
#define	VR_RDES0_SERR		(1 << 6)
#define	VR_RDES0_BUFF		(1 << 7)

#define	VR_RDES0_EDP		(1 << 8)
#define	VR_RDES0_STP		(1 << 9)
#define	VR_RDES0_CHN		(1 << 10)
#define	VR_RDES0_PHY		(1 << 11)
#define	VR_RDES0_BAR		(1 << 12)
#define	VR_RDES0_MAR		(1 << 13)
#define	VR_RDES0_VIDHIT		(1 << 14)	/* VT6105M or reserved */
#define	VR_RDES0_RXOK		(1 << 15)

#define	VR_RDES0_ABN		((1 << 27) | (1 << 28) | (1 << 29) | (1 << 30))
#define	VR_RDES0_OWN		(1U << 31)

/*
 * Transmit descriptor
 */
#define	VR_TDES0_NCR		((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3))
#define	VR_TDES0_COL		(1 << 4)
#define	VR_TDES0_CDH		(1 << 7)
#define	VR_TDES0_ABT		(1 << 8)
#define	VR_TDES0_OWC		(1 << 9)
#define	VR_TDES0_CRS		(1 << 10)
#define	VR_TDES0_UDF		(1 << 11)
#define	VR_TDES0_TERR		(1 << 15)
/* VLAN stuff is for VT6105M only */
#define	VR_TDES0_VLANID		((1 << 27) | (1 << 26) | (1 << 25) | (1 << 24) \
				    (1 << 23) | (1 << 22) | (1 << 21) | \
				    (1 << 20) | (1 << 19) | (1 << 18) | \
				    (1 << 17) | (1 << 16))
#define	VR_TDES0_VLANPRI	((1 << 30) | (1 << 29) | (1 << 28))
#define	VR_TDES0_OWN		(1U << 31)

#define	VR_TDES1_LEN		((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | \
				    (1 << 4) | (1 << 5) | (1 << 6) | \
				    (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10))

#define	VR_TDES1_CHN		(1 << 15)
#define	VR_TDES1_CRC		(1 << 16)
#define	VR_TDES1_STP		(1 << 21) /* EDP/STP are flipped in DS6105! */
#define	VR_TDES1_EDP		(1 << 22)
#define	VR_TDES1_INTR		(1 << 23)

#define	VR_TDES3_SUPPRESS_INTR	(1 << 0)

#endif	/* _VRREG_H */

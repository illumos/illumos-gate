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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef AMD8111S_HW_H
#define	AMD8111S_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 2001-2006 Advanced Micro Devices, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * + Redistributions of source code must retain the above copyright notice,
 * + this list of conditions and the following disclaimer.
 *
 * + Redistributions in binary form must reproduce the above copyright
 * + notice, this list of conditions and the following disclaimer in the
 * + documentation and/or other materials provided with the distribution.
 *
 * + Neither the name of Advanced Micro Devices, Inc. nor the names of its
 * + contributors may be used to endorse or promote products derived from
 * + this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ADVANCED MICRO DEVICES, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Import/Export/Re-Export/Use/Release/Transfer Restrictions and
 * Compliance with Applicable Laws.  Notice is hereby given that
 * the software may be subject to restrictions on use, release,
 * transfer, importation, exportation and/or re-exportation under
 * the laws and regulations of the United States or other
 * countries ("Applicable Laws"), which include but are not
 * limited to U.S. export control laws such as the Export
 * Administration Regulations and national security controls as
 * defined thereunder, as well as State Department controls under
 * the U.S. Munitions List.  Permission to use and/or
 * redistribute the software is conditioned upon compliance with
 * all Applicable Laws, including U.S. export control laws
 * regarding specifically designated persons, countries and
 * nationals of countries subject to national security controls.
 */


/* Definitions for the type of Memory allocations needed */

#define	ETH_LENGTH_OF_ADDRESS		6
#define	ETH_MAC_HDR_SIZE		14


#define	ADD_MULTICAST			1

#define	ENABLE_MULTICAST		2
#define	DISABLE_MULTICAST		3

#define	ENABLE_ALL_MULTICAST		4
#define	DISABLE_ALL_MULTICAST		5

#define	ENABLE_BROADCAST		6
#define	DISABLE_BROADCAST		7

#define	ADD_WAKE_UP_PATTERN		8
#define	REMOVE_WAKE_UP_PATTERN		9
#define	ENABLE_MAGIC_PACKET_WAKE_UP	10

#define	SET_SINGLE_MULTICAST		11
#define	UNSET_SINGLE_MULTICAST		12
#define	DELETE_MULTICAST		13

#define	LINK_DOWN		1
#define	LINK_UP			2
#define	LINK_UNKNOWN		3

/* Setting the MODE */
#define	PROMISCOUS	1
#define	DISABLE_PROM	2

#define	VIRTUAL		1

#define	ALIGNMENT	0x0f

#define	TX_RING_LEN_BITS		10	/* 1024 descriptors */
#define	RX_RING_LEN_BITS		10	/* 1024 descriptors */
#define	TX_BUF_SIZE			2048
#define	RX_BUF_SIZE			2048

#define	TX_RING_SIZE			(1 << (TX_RING_LEN_BITS))
#define	TX_COALESC_SIZE			(1 << 11)
#define	TX_RING_MOD_MASK		(2 * TX_RING_SIZE - 1)

#define	TX_RESCHEDULE_THRESHOLD		(TX_RING_SIZE >> 1)

#define	RX_RING_SIZE			(1 << (RX_RING_LEN_BITS))
#define	RX_RING_MOD_MASK		(RX_RING_SIZE - 1)

#define	MAX_MULTICAST_ADDRESSES		32
#define	JUMBO_ENABLED			0
#define	JUMBO_DISABLED			1

/* Default value of IPG convergence time */
#define	MIN_IPG_DEFAULT			96
#define	MAX_IPG_DEFAULT			255
#define	MAX_BUFFER_COUNT		8 /* full coalesce */

#define	ULONG unsigned long
#define	UCHAR unsigned char

/* Generic MII registers. */
#define	MII_BMCR	0x00	/* Basic mode control register */
#define	MII_BMSR	0x01	/* Basic mode status register */
#define	MII_PHYSID1	0x02	/* PHYS ID 1 */
#define	MII_PHYSID2	0x03	/* PHYS ID 2 */
#define	MII_ADVERTISE	0x04	/* Advertisement control reg */
#define	MII_LPA		0x05	/* Link partner ability reg */
#define	MII_EXPANSION	0x06	/* Expansion register */
#define	MII_DCOUNTER	0x12	/* Disconnect counter */
#define	MII_FCSCOUNTER	0x13	/* False carrier counter */
#define	MII_NWAYTEST	0x14	/* N-way auto-neg test reg */
#define	MII_RERRCOUNTER	0x15	/* Receive error counter */
#define	MII_SREVISION	0x16	/* Silicon revision */
#define	MII_RESV1	0x17	/* Reserved... */
#define	MII_LBRERROR	0x18	/* Lpback, rx, bypass error */
#define	MII_PHYADDR	0x19	/* PHY address */
#define	MII_RESV2	0x1a	/* Reserved... */
#define	MII_TPISTATUS	0x1b	/* TPI status for 10mbps */
#define	MII_NCONFIG	0x1c	/* Network interface config */


#define	DEVICE_ID 0x744b
#define	VENDOR_ID 0x1022

/* L4 Chip Name  */
#define	DEVICE_CHIPNAME			"Memory_Map_L7 AMDIDC"

/* Error Status Registers */
#define	MIB_OFFSET		0x28

/*
 *	MIB counter definitions
 */
#define	RcvMissPkts		0x00
#define	RcvOctets		0x01
#define	RcvBroadCastPkts	0x02
#define	RcvMultiCastPkts	0x03
#define	RcvUndersizePkts	0x04
#define	RcvOversizePkts		0x05
#define	RcvFragments		0x06
#define	RcvJabbers		0x07
#define	RcvUniCastPkts		0x08
#define	RcvAlignmentErrors	0x09
#define	RcvFCSErrors		0x0a
#define	RcvGoodOctets		0x0b
#define	RcvMACCtrl		0x0c
#define	RcvFlowCtrl		0x0d
#define	RcvPkts64Octets		0x0e
#define	RcvPkts65to127Octets	0x0f
#define	RcvPkts128to255Octets	0x10
#define	RcvPkts256to511Octets	0x11
#define	RcvPkts512to1023Octets	0x12
#define	RcvPkts1024to1518Octets	0x13
#define	RcvUnsupportedOpcode	0x14
#define	RcvSymbolErrors		0x15
#define	RcvDropPktsRing0	0x16

#define	XmtUnderrunPkts		0x20
#define	XmtOctets		0x21
#define	XmtPackets		0x22
#define	XmtBroadCastPkts	0x23
#define	XmtMultiCastPkts	0x24
#define	XmtCollisions		0x25
#define	XmtUniCastPkts		0x26
#define	XmtOneCollision		0x27
#define	XmtMultipleCollision	0x28
#define	XmtDeferredTransmit	0x29
#define	XmtLateCollision	0x2a
#define	XmtExcessiveDefer	0x2b
#define	XmtLossCarrier		0x2c
#define	XmtExcessiveCollision	0x2d
#define	XmtBackPressure		0x2e
#define	XmtFlowCtrl		0x2f
#define	XmtPkts64Octets		0x30
#define	XmtPkts65to127Octets	0x31
#define	XmtPkts128to255Octets	0x32
#define	XmtPkts256to511Octets	0x33
#define	XmtPkts512to1023Octets	0x34
#define	XmtPkts1024to1518Octets	0x35
#define	XmtOversizePkts		0x36

/* Link Status  */
#define	SPEED_MASK		0x0380	/* B9 .. B7 */
#define	SPEED_100Mbps		0x0180
#define	SPEED_10Mbps		0x0100


/* PMR (Pattern Match RAM) */
#define	MAX_ALLOWED_PATTERNS	8
#define	MAX_PATTERNS		1024
#define	ALL_MULTI		B16_MASK
#define	ONLY_MULTI		B15_MASK

#define	B31_MASK	0x80000000
#define	B30_MASK	0x40000000
#define	B29_MASK	0x20000000
#define	B28_MASK	0x10000000
#define	B27_MASK	0x08000000
#define	B26_MASK	0x04000000
#define	B25_MASK	0x02000000
#define	B24_MASK	0x01000000
#define	B23_MASK	0x00800000
#define	B22_MASK	0x00400000
#define	B21_MASK	0x00200000
#define	B20_MASK	0x00100000
#define	B19_MASK	0x00080000
#define	B18_MASK	0x00040000
#define	B17_MASK	0x00020000
#define	B16_MASK	0x00010000

#define	B15_MASK	0x8000
#define	B14_MASK	0x4000
#define	B13_MASK	0x2000
#define	B12_MASK	0x1000
#define	B11_MASK	0x0800
#define	B10_MASK	0x0400
#define	B9_MASK		0x0200
#define	B8_MASK		0x0100
#define	B7_MASK		0x0080
#define	B6_MASK		0x0040
#define	B5_MASK		0x0020
#define	B4_MASK		0x0010
#define	B3_MASK		0x0008
#define	B2_MASK		0x0004
#define	B1_MASK		0x0002
#define	B0_MASK		0x0001

/* PCI register offset */
/* required by odl in getting the Memory Base Address */
#define	MEMBASE_MASK		0xFFFFF000
#define	PCI_CAP_ID_REG_OFFSET	0x34
#define	PCI_PMC_REG_OFFSET	0x36
#define	PCI_PMCSR_REG_OFFSET	0x38
#define	MIB_OFFSET		0x28
#define	STAT_ASF		0x00	/* 32bit register */

#define	FORCED_PHY_MASK		0xFF07

/* Offset of Drifrent Registers */
#define	AP_VALUE		0x98	/* 32bit register */
#define	AUTOPOLL0		0x88	/* 16bit register */
#define	AUTOPOLL1		0x8A	/* 16bit register */
#define	AUTOPOLL2		0x8C	/* 16bit register */
#define	AUTOPOLL3		0x8E	/* 16bit register */
#define	AUTOPOLL4		0x90	/* 16bit register */
#define	AUTOPOLL5		0x92	/* 16bit register */
/* Receive Ring Base Address Registers . */
#define	RCV_RING_BASE_ADDR0	0x120	/* 64bit register */
/* Transmit Ring Base Address */
#define	XMT_RING_BASE_ADDR0	0x100	/* 64bit register */
#define	XMT_RING_BASE_ADDR1	0x108	/* 64bit register */
#define	XMT_RING_BASE_ADDR2	0x110	/* 64bit register */
#define	XMT_RING_BASE_ADDR3	0x118	/* 64bit register */
/* CAM ADDRESS */
#define	CAM_ADDR		0x1A0	/* 16bit register */
#define	CAM_DATA		0x198	/* 64bit register */
/* CHIP ID */
#define	CHIPID			0x004	/* 32bit register */
/* COMMAND STYLE REGISTERS */
#define	CMD0			0x48	/* 32bit register */
#define	CMD2			0x50	/* 32bit register */
#define	CMD3			0x54	/* 32bit register */
#define	CMD7			0x64	/* 32bit register */
/* CONTRIOL REGISTER */
#define	CTRL1 			0x6C	/* 32bit register */
#define	CTRL2 			0x70	/* 32bit register */
/* DELAY INTERRUPT REGISTER */
#define	DLY_INT_A		0xA8	/* 32bit register */
#define	DLY_INT_B		0xAC	/* 32bit register */
/* FLOW CONTROL REGISTER */
#define	FLOW_CONTROL		0xC8	/* 32bit register */
/* INTER FRAME SPACING */
#define	IFS			0x18E	/* 16bit register */
#define	IFS1			0x18C	/* 8bit register */
/* INTERRUPT REGISTER */
#define	INT0			0x38	/* 32bit register */
#define	INTEN0			0x40	/* 32bit register */
/* LOGICAL ADDRESS */
#define	LADRF1			0x168	/* 64bit register */
/* MIB ADDRESS REGISTER */
#define	MIB_ADDR		0x14	/* 16bit register */
#define	MIB_DATA		0x10	/* 32bit register */
/* MAC ADDRESS */
#define	PADR			0x160	/* 48bit register */
/* PHY ADDRESS */
#define	PHY_ACCESS		0xD0	/* 32bit register */
/* PATTERN REGISTER */
#define	PMAT0			0x190	/* 32bit register */
#define	PMAT1			0x194	/* 32bit register */
/* RECEIVE RING LENGTH OFFSET */
#define	RCV_RING_LEN0		0x150	/* 16bit register */
/* SRAM BOUNDARY */
#define	SRAM_BOUNDARY		0x17A	/* 16bit register */
#define	SRAM_SIZE		0x178	/* 16bit register */
/* STATUS REGISTER */
#define	STAT0			0x30	/* 32bit register */
#define	STVAL			0xD8	/* 32bit register */
#define	TEST0			0x1A8	/* 32bit register */
#define	XMT_RING_LEN0		0x140	/* 16bit register */
#define	XMT_RING_LEN1		0x144	/* 16bit register */
#define	XMT_RING_LEN2		0x148	/* 16bit register */
#define	XMT_RING_LEN3		0x14C	/* 16bit register */
#define	XMT_RING_LIMIT		0x7C	/* 32bit register */



#define	RCV_RING_LEN1		0x154	/* 16bit register */
#define	RCV_RING_LEN2		0x158	/* 16bit register */
#define	RCV_RING_LEN3		0x15C	/* 16bit register */
#define	FFC_THRESH		0xCC	/* 32bit register */
#define	RCV_RING_BASE_ADDR1	0x128	/* 64bit register */
#define	RCV_RING_BASE_ADDR2	0x130	/* 64bit register */
#define	RCV_RING_BASE_ADDR3	0x138	/* 64bit register */
#define	RCV_RING_CFG		0x78	/* 16bit register */
#define	PCS_ANEG		0x9C	/* 32bit register */
#define	PCS_RCFG		0xA0	/* 32bit register */
#define	PCS_XCFG		0xA4	/* 32bit register */
#define	DFC_INDEX2		0xB8	/* 16bit register */
#define	DFC_INDEX3		0xBA	/* 16bit register */
#define	DFC_INDEX0		0xBC	/* 16bit register */
#define	DFC_INDEX1		0xBE	/* 16bit register */
#define	DFC_THRESH2		0xC0	/* 16bit register */
#define	DFC_THRESH3		0xC2	/* 16bit register */
#define	DFC_THRESH0		0xC4	/* 16bit register */
#define	DFC_THRESH1		0xC6	/* 16bit register */
#define	PAUSE_CNT		0xDE	/* 32bit register */
#define	LED0			0xE0	/* 16bit register */
#define	LED1			0xE2	/* 16bit register */
#define	LED2			0xE4	/* 16bit register */
#define	LED3			0xE6	/* 16bit register */


#define	EEPROM_ACC		0x17C	/* 16bit register */


/* Register Bit Definitions */
/* STAT_ASF			0x00, 32bit register */
#define	ASF_INIT_DONE		B1_MASK
#define	ASF_INIT_PRESENT	B0_MASK

/* MIB_ADDR			0x14, 16bit register */
#define	MIB_CMD_ACTIVE		B15_MASK
#define	MIB_RD_CMD		B13_MASK
#define	MIB_CLEAR		B12_MASK
#define	MIB_ADDRESS		0x0000003F	/* 5:0 */

/* QOS_ADDR			0x1C, 16bit register */
#define	QOS_CMD_ACTIVE		B15_MASK
#define	QOS_WR_CMD		B14_MASK
#define	QOS_RD_CMD		B13_MASK
#define	QOS_ADDRESS		0x0000001F	/* 4:0 */

/* STAT0			0x30, 32bit register */
#define	PAUSE_PEND		B14_MASK
#define	PAUSING			B13_MASK
#define	PMAT_DET		B12_MASK
#define	MP_DET			B11_MASK
#define	LC_DET			B10_MASK
#define	SPEED_MASK		0x0380		/* 9:7 */
#define	FULL_DPLX		B6_MASK
#define	LINK_STAT		B5_MASK
#define	AUTONEG_COMPLETE	B4_MASK
/* #define	MIIPD			B3_MASK */
#define	RX_SUSPENDED		B2_MASK
#define	TX_SUSPENDED		B1_MASK
#define	RUNNING			B0_MASK


/* INTEN0			0x40, 32bit register */

#define	VAL3			B31_MASK
#define	VAL2			B23_MASK
#define	VAL1			B15_MASK
#define	VAL0			B7_MASK

/* VAL3 */
#define	PSCINTEN		B28_MASK
#define	LCINTEN			B27_MASK
#define	APINT5EN		B26_MASK
#define	APINT4EN		B25_MASK
#define	APINT3EN		B24_MASK

/* VAL2 */
#define	APINT2EN		B22_MASK
#define	APINT1EN		B21_MASK
#define	APINT0EN		B20_MASK
#define	MIIPDTINTEN		B19_MASK
#define	MCCIINTEN		B18_MASK
#define	MCCINTEN		B17_MASK
#define	MREINTEN		B16_MASK

/* VAL1 */
#define	SPNDINTEN		B14_MASK
#define	MPINTEN			B13_MASK
#define	SINTEN			B12_MASK
#define	TINTEN3			B11_MASK
#define	TINTEN2			B10_MASK
#define	TINTEN1			B9_MASK
#define	TINTEN0			B8_MASK

/* VAL0 */
#define	STINTEN			B4_MASK
#define	RINTEN3			B3_MASK
#define	RINTEN2			B2_MASK
#define	RINTEN1			B1_MASK
#define	RINTEN0			B0_MASK

/* CMD0				0x48, 32bit register */
/* VAL2 */
#define	RDMD3			B19_MASK
#define	RDMD2			B18_MASK
#define	RDMD1			B17_MASK
#define	RDMD0			B16_MASK

/* VAL1 */
#define	TDMD3			B11_MASK
#define	TDMD2			B10_MASK
#define	TDMD1			B9_MASK
#define	TDMD0			B8_MASK

/* VAL0 */
#define	UINTCMD			B6_MASK
#define	RX_FAST_SPND		B5_MASK
#define	TX_FAST_SPND		B4_MASK
#define	RX_SPND			B3_MASK
#define	TX_SPND			B2_MASK
#define	INTREN			B1_MASK
#define	RUN			B0_MASK

/* CMD2 			0x50, 32bit register */
/* VAL3 */
#define	CONDUIT_MODE		B29_MASK
#define	PREF_QTAG		B28_MASK
#define	ALT_PRI_OK		B27_MASK

/* VAL2 */
#define	CAM_ENABLE		B22_MASK
#define	QOS_ENABLE		B21_MASK
#define	HASH_ENABLE		B20_MASK
#define	RPA			B19_MASK
#define	DRCVPA			B18_MASK
#define	DRCVBC			B17_MASK
#define	PROM			B16_MASK

/* VAL1 */
#define	ASTRIP_RCV		B13_MASK
#define	CMD2_RCV_DROP0			B12_MASK
#define	EMBA			B11_MASK
#define	DXMT2PD			B10_MASK
#define	LTINTEN			B9_MASK
#define	DXMTFCS			B8_MASK

/* VAL0 */
#define	APAD_XMT		B6_MASK
#define	DRTY			B5_MASK
#define	INLOOP			B4_MASK
#define	EXLOOP			B3_MASK
#define	REX_RTRY		B2_MASK
#define	REX_UFLO		B1_MASK
#define	REX_LCOL		B0_MASK

/* CMD3				0x54, 32bit register */

/* VAL3 */
#define	ASF_INIT_DONE_ALIAS	B29_MASK

/* VAL2 */
#define	JUMBO			B21_MASK
#define	VSIZE			B20_MASK
#define	VLONLY			B19_MASK
#define	VL_TAG_DEL		B18_MASK

/* VAL1 */
#define	EN_PMGR			B14_MASK
#define	INTLEVEL		B13_MASK
#define	FORCE_FULL_DUPLEX	B12_MASK
#define	FORCE_LINK_STATUS	B11_MASK
#define	APEP			B10_MASK
#define	MPPLBA			B9_MASK

/* VAL0 */
#define	RESET_PHY_PULSE		B2_MASK
#define	RESET_PHY		B1_MASK
#define	PHY_RST_POL		B0_MASK

/* CMD7				0x64, 32bit register */
/* VAL0 */
#define	PMAT_SAVE_MATCH		B4_MASK
#define	PMAT_MODE		B3_MASK
#define	MPEN_SW			B1_MASK
#define	LCMODE_SW		B0_MASK

/* CTRL0			0x68, 32bit register */
#define	PHY_SEL			0x03000000	/* 25:24 */
#define	RESET_PHY_WIDTH		0x00FF0000	/* 23:16 */
#define	BSWP_REGS		B10_MASK
#define	BSWP_DESC		B9_MASK
#define	BSWP_DATA		B8_MASK
#define	CACHE_ALIGN		B4_MASK
#define	BURST_LIMIT		0x0000000F	/* 3:0 */

/* CTRL1			0x6C, 32bit register */
#define	SLOTMOD_MASK		0x03000000	/* 25:24 */
#define	XMTSP_MASK		0x300		/* 17:16 */
#define	XMTSP_128		0x200
#define	XMTSP_64		0x100

/* CTRL2			0x70, 32bit register */
#define	FS_MASK			0x00070000	/* 18:16 */
#define	FMDC_MASK		0x00000300	/* 9:8 */
#define	XPHYRST			B7_MASK
#define	XPHYANE			B6_MASK
#define	XPHYFD			B5_MASK
#define	XPHYSP_100		B3_MASK		/* 4:3, 100 Mbps */
#define	APDW_MASK		0x00000007	/* 2:0 */

/* RCV_RING_CFG			0x78, 16bit register */
#define	RCV_DROP3		B11_MASK
#define	RCV_DROP2		B10_MASK
#define	RCV_DROP1		B9_MASK
#define	RCV_DROP0		B8_MASK
#define	RCV_RING_DEFAULT	0x0030		/* 5:4 */
#define	RCV_RING3_EN		B3_MASK
#define	RCV_RING2_EN		B2_MASK
#define	RCV_RING1_EN		B1_MASK
#define	RCV_RING0_EN		B0_MASK

/* XMT_RING_LIMIT		0x7C, 32bit register */
#define	XMT_RING2_LIMIT		0x00FF0000	/* 23:16 */
#define	XMT_RING1_LIMIT		0x0000FF00	/* 15:8 */
#define	XMT_RING0_LIMIT		0x000000FF	/* 7:0 */

/* AUTOPOLL0			0x88, 16bit register */
#define	AP_REG0_EN		B15_MASK
#define	AP_REG0_ADDR_MASK	0x1F00	/* 12:8 */
#define	AP_PHY0_ADDR_MASK	0x001F	/* 4:0 */

/* AUTOPOLL1			0x8A, 16bit register */
#define	AP_REG1_EN		B15_MASK
#define	AP_REG1_ADDR_MASK	0x1F00	/* 12:8 */
#define	AP_PRE_SUP1		B6_MASK
#define	AP_PHY1_DFLT		B5_MASK
#define	AP_PHY1_ADDR_MASK	0x001F	/* 4:0 */

/* AUTOPOLL2			0x8C, 16bit register */
#define	AP_REG2_EN		B15_MASK
#define	AP_REG2_ADDR_MASK	0x1F00	/* 12:8 */
#define	AP_PRE_SUP2		B6_MASK
#define	AP_PHY2_DFLT		B5_MASK
#define	AP_PHY2_ADDR_MASK	0x001F	/* 4:0 */

/* AUTOPOLL3			0x8E, 16bit register */
#define	AP_REG3_EN		B15_MASK
#define	AP_REG3_ADDR_MASK	0x1F00	/* 12:8 */
#define	AP_PRE_SUP3		B6_MASK
#define	AP_PHY3_DFLT		B5_MASK
#define	AP_PHY3_ADDR_MASK	0x001F	/* 4:0 */

/* AUTOPOLL4			0x90, 16bit register */
#define	AP_REG4_EN		B15_MASK
#define	AP_REG4_ADDR_MASK	0x1F00	/* 12:8 */
#define	AP_PRE_SUP4		B6_MASK
#define	AP_PHY4_DFLT		B5_MASK
#define	AP_PHY4_ADDR_MASK	0x001F	/* 4:0 */

/* AUTOPOLL5			0x92, 16bit register */
#define	AP_REG5_EN		B15_MASK
#define	AP_REG5_ADDR_MASK	0x1F00	/* 12:8 */
#define	AP_PRE_SUP5		B6_MASK
#define	AP_PHY5_DFLT		B5_MASK
#define	AP_PHY5_ADDR_MASK	0x001F	/* 4:0 */

/* AP_VALUE 			0x98, 32bit ragister */
#define	AP_VAL_ACTIVE		B31_MASK
#define	AP_VAL_RD_CMD		B29_MASK
#define	AP_ADDR			0x00070000	/* 18:16 */
#define	AP_VAL			0x0000FFFF	/* 15:0 */

/* PCS_ANEG			0x9C, 32bit register */
#define	SYNC_LOST		B10_MASK
#define	IMATCH			B9_MASK
#define	CMATCH			B8_MASK
#define	PCS_AN_IDLE		B1_MASK
#define	PCS_AN_CFG		B0_MASK

/* DLY_INT_A			0xA8, 32bit register */
#define	DLY_INT_A_R3		B31_MASK
#define	DLY_INT_A_R2		B30_MASK
#define	DLY_INT_A_R1		B29_MASK
#define	DLY_INT_A_R0		B28_MASK
#define	DLY_INT_A_T3		B27_MASK
#define	DLY_INT_A_T2		B26_MASK
#define	DLY_INT_A_T1		B25_MASK
#define	DLY_INT_A_T0		B24_MASK
#define	EVENT_COUNT_A		0x00FF0000	/* 20:16 */
#define	MAX_DELAY_TIME_A	0x000007FF	/* 10:0 */

/* DLY_INT_B			0xAC, 32bit register */
#define	DLY_INT_B_R3		B31_MASK
#define	DLY_INT_B_R2		B30_MASK
#define	DLY_INT_B_R1		B29_MASK
#define	DLY_INT_B_R0		B28_MASK
#define	DLY_INT_B_T3		B27_MASK
#define	DLY_INT_B_T2		B26_MASK
#define	DLY_INT_B_T1		B25_MASK
#define	DLY_INT_B_T0		B24_MASK
#define	EVENT_COUNT_B		0x00FF0000	/* 20:16 */
#define	MAX_DELAY_TIME_B	0x000007FF	/* 10:0 */

/* DFC_THRESH2			0xC0, 16bit register */
#define	DFC_THRESH2_HIGH	0xFF00		/* 15:8 */
#define	DFC_THRESH2_LOW		0x00FF		/* 7:0 */

/* DFC_THRESH3			0xC2, 16bit register */
#define	DFC_THRESH3_HIGH	0xFF00		/* 15:8 */
#define	DFC_THRESH3_LOW		0x00FF		/* 7:0 */

/* DFC_THRESH0			0xC4, 16bit register */
#define	DFC_THRESH0_HIGH	0xFF00		/* 15:8 */
#define	DFC_THRESH0_LOW		0x00FF		/* 7:0 */

/* DFC_THRESH1			0xC6, 16bit register */
#define	DFC_THRESH1_HIGH	0xFF00		/* 15:8 */
#define	DFC_THRESH1_LOW		0x00FF		/* 7:0 */

/* FLOW_CONTROL 		0xC8, 32bit register */
#define	PAUSE_LEN_CHG		B30_MASK
#define	FFC_EN			B28_MASK
#define	DFC_RING3_EN		B27_MASK
#define	DFC_RING2_EN		B26_MASK
#define	DFC_RING1_EN		B25_MASK
#define	DFC_RING0_EN		B24_MASK
#define	FIXP_CONGEST		B21_MASK
#define	NAPA			B20_MASK
#define	NPA			B19_MASK
#define	FIXP			B18_MASK
#define	FCPEN			B17_MASK
#define	FCCMD			B16_MASK
#define	PAUSE_LEN		0x0000FFFF	/* 15:0 */

/* FFC THRESH			0xCC, 32bit register */
#define	FFC_HIGH		0xFFFF0000	/* 31:16 */
#define	FFC_LOW			0x0000FFFF	/* 15:0 */

/* PHY_ACCESS			0xD0, 32bit register */
#define	PHY_CMD_ACTIVE		B31_MASK
#define	PHY_WR_CMD		B30_MASK
#define	PHY_RD_CMD		B29_MASK
#define	PHY_RD_ERR		B28_MASK
#define	PHY_PRE_SUP		B27_MASK
#define	PHY_ADDR		0x03E00000	/* 25:21 */
#define	PHY_REG_ADDR		0x001F0000	/* 20:16 */
#define	PHY_DATA		0x0000FFFF	/* 15:0 */
#define	PHY_ADDR_SHIFT		21
#define	PHY_REG_ADDR_SHIFT	16

#define	PHY_MAX_RETRY		30


/* EEPROM_ACC			0x17C, 16bit register */
#define	PVALID			B15_MASK
#define	PREAD			B14_MASK
#define	EEDET			B13_MASK
#define	EEN			B4_MASK
#define	ECS			B2_MASK
#define	EESK			B1_MASK
#define	EDI_EDO			B0_MASK

/* PMAT0			0x190,	 32bit register */
#define	PMR_ACTIVE		B31_MASK
#define	PMR_WR_CMD		B30_MASK
#define	PMR_RD_CMD		B29_MASK
#define	PMR_BANK		B28_MASK
#define	PMR_ADDR		0x007F0000	/* 22:16 */
#define	PMR_B4			0x000000FF	/* 15:0 */

/* PMAT1			0x194,	 32bit register */
#define	PMR_B3			0xFF000000	/* 31:24 */
#define	PMR_B2			0x00FF0000	/* 23:16 */
#define	PMR_B1			0x0000FF00	/* 15:8 */
#define	PMR_B0			0x000000FF	/* 7:0 */

/* CAMDATA			0x198, 16bit register */
#define	CAM_DATA_MASK		0x000000FFFFFFFFFFFF

/* CAM_ADDR			0x1A0, 16bit register */
#define	CAM_CMD_ACTIVE		B15_MASK
#define	CAM_WR_CMD		B14_MASK
#define	CAM_RD_CMD		B13_MASK
#define	CAM_CLEAR		B12_MASK
#define	CAM_ADDRESS		0x001F

/* INT0				0x38, 32bit register */
#define	INTR			B31_MASK
#define	LCINT			B27_MASK
#define	TINT0			B8_MASK
#define	STINT			B4_MASK
#define	RINT0			B0_MASK

/* TEST0			0x1A8, 32bit register */

/* VAL1 */
#define	MFSM_RESET		B10_MASK
#define	BFD_SCALE_DOWN		B9_MASK

/* VAL0 */
#define	LEDCNTTST		B5_MASK
#define	RTYTST_RANGEN		B2_MASK
#define	RTYTST_SLOT		B1_MASK
#define	SERRLEVEL		B0_MASK

#define	CABLE_CHK_TIME		100

#define	PCI_IOMAP_BASE_REG	0x00
#define	PCI_MEM_BASE_REG	0x10

#define	XPHYFD			B5_MASK
#define	XPHYSP			B3_MASK		/* 4:3 */

#define	TX_RATE		0x1
#define	RX_RATE		0x2
#define	RX_BYTES	0xb
#define	TX_BYTES	0xc

#define	LOW_COALESC	1
#define	MEDIUM_COALESC	2
#define	HIGH_COALESC	3
#define	NO_COALESC	4

#define	CLIENT	0x1
#define	SERVER  0x2
#define	DISABLE 0x3
#define	PCI_OPT 0x4

#define	MULTICAST_BITMAP_ARRAY_SIZE		64

#define	PHY_AUTO_NEGOTIATION	0
#define	PHY_FORCE_HD_100	1	/* HD: Half Duplex */
#define	PHY_FORCE_FD_100	2	/* FD: Full Duplex */
#define	PHY_FORCE_HD_10		3
#define	PHY_FORCE_FD_10		4

struct tx_desc {
	unsigned int Tx_BCNT	:16;	/* Buffer Byte Count */
	unsigned int Tx_RES4	:6;	/* RESVERD 6 bits */
	/*
	 * This bit causes the transmission of the corresponding frame to be
	 * aborted. If the transmitter has not started sending the frame at the
	 * time that the descriptor
	 */
	unsigned int KILL	:1;
	unsigned int Tx_RES3	:1;	/* RESVERD 1 bits */
	/* End Of packet to indicates the last Buffer */
	unsigned int Tx_EOP	:1;
	unsigned int Tx_SOP	:1;	/* Defer to Transmit */
	unsigned int Tx_RES2	:2;
	unsigned int Tx_LTINT	:1;	/* Start of packet for the Buffer */
	/*
	 * ADD_FCS dynamically controls the generation of FCS on a frame by
	 * frame basis.
	 */
	unsigned int Tx_ADD_FCS	:1;
	unsigned int Tx_RES1	:1;	/* Reserved Location */
	unsigned int Tx_OWN	:1;	/* Own Bit for the Transmit */
	unsigned int TCI 	:16;	/* VLAN Tag Control Command. */
	unsigned int TCC	:2;	/* Tag Control Information. */
	unsigned int Tx_RES0	:14;	/* Resvered Location */
	/*
	 * TBADR[31:0] Transmit Buffer Address. This field contains the address
	 * of the Transmit buffer that is associated with this descriptor
	 */
	unsigned int Tx_Base_Addr	:32;
	unsigned int Tx_USPACE		:32;	/* User Space */
};

/* Receive Descriptor For the L7 */
struct rx_desc {

	/* User Reserved amar - Its just reservered. */
	unsigned int Rx_USPACE	:32;
	/*
	 * Message Byte Count is the number of bytes of the received message
	 * written
	 */
	unsigned int Rx_MCNT	:16;
	unsigned int TCI	:16;
	/*
	 * Buffer Byte Count is the length of the buffer pointed to by this
	 * descriptor
	 */
	unsigned int Rx_BCNT	:16;
	unsigned int Rx_RES1	:2;	/* Reserved Location */
	/*
	 * VLAN Tag Type. Indicates what type of VLAN tag, if any, is included
	 * in the received
	 */
	unsigned int TT		:2;
	/*
	 * Broadcast Address Match is set by the Am79C976 controller when it
	 * accepts the reveice buffer
	 */
	unsigned int Rx_BAM	:1;
	/*
	 * Logical Address Filter Match is set by the Am79C976 controller
	 * to the Receive Buffer
	 */
	unsigned int Rx_LAFM	:1;
	/* Physical Address Match is set by the Am79C976 controller */
	unsigned int Rx_PAM	:1;
	unsigned int Rx_RES0	:1;	/* Resvered  Location */
	/* End Of packet to indicates the last Buffer */
	unsigned int Rx_EOP	:1;
	unsigned int Rx_SOP	:1;	/* Start of packet for the Buffer */
	unsigned int Rx_BUFF	:1;	/* Reserved location */
	/*
	 * CRC indicates that the receiver has detected a CRC (FCS) error on the
	 * incoming frame.
	 */
	unsigned int Rx_CRC	:1;
	/*
	 * Overflow error indicates that the receiver has lost all or part of
	 * the incoming frame.
	 */
	unsigned int Rx_OFLO	:1;
	unsigned int Rx_FRAM	:1;	/* Framing Error */
	unsigned int Rx_ERR	:1;	/* Error is Set By the Controller */
	unsigned int Rx_OWN	:1;	/* Own Bit of Descriptor */
	/*
	 * RBADR[31:0] Receive Buffer Address. This field contains the address
	 * of the receive buffer that is associated with this descriptor.
	 */
	unsigned int Rx_Base_Addr:32;
};


/* Initialization Block (SSIZE32 = 1) */
struct init_block {
	unsigned int MODE	:16;	/* Mode */
	unsigned int RES1	:4;		/* Reserved Location */
	/* Receive software structure is defined for 16 bit */
	unsigned int RLEN	:4;
	unsigned int RES2	:4;		/* Reserved bits */
	/* Transmit software structure is defined for the 16 bit */
	unsigned int TLEN	:4;
	unsigned int PADDR0	:8;
	unsigned int PADDR1	:8;
	unsigned int PADDR2	:8;
	unsigned int PADDR3	:8;
	unsigned int PADDR4	:8;
	unsigned int PADDR5	:8;
	unsigned int RES3	:16;
	unsigned char LADRF[8];
	/* RDRA indicate where the receive  descriptor ring begins */
	unsigned int RDRA	:32;
	/* TDRA indicate where the transmit descriptor ring begins */
	unsigned int TDRA	:32;
};

/* MDL Physical and Normal Structure */
struct mdl {
	ULONG Io_Address;
	ULONG Mem_Address;

	volatile int CSR;
	volatile int CardStatus;

	/* PMR (Pattern Match RAM) */
	/*
	 * An array to store the indexes of each of the patterns in
	 * Pattern List.
	 */
	unsigned int *PMR_PtrList;
	/* An array of pattern controls and pattern data bytes */
	unsigned char *PatternList;
	unsigned int *PatternLength;
	int EnableMulticast;
	/* The begining of the free area in the PatternList array */
	unsigned short PatternList_FreeIndex;
	/* The total number of patterns present in the PMR */
	unsigned short TotalPatterns;
	unsigned short PatternEnableBit;

	unsigned char Mac[6];
	unsigned char TEMP_MAC[6];
	unsigned int FLAGS;
	unsigned char TempLADRF[8];

	ULONG Speed;
	ULONG FullDuplex;

	struct init_block *init_blk;

	int tmpPtrArray[8];

	int MulticastBitMapArray[MULTICAST_BITMAP_ARRAY_SIZE];
	int External_Phy;
	unsigned int phy_id;

	/* For interrupt delay */
	/* Unit is 10 us. Its value must < 0x800 (2^11) */
	unsigned int rx_intrcoalesc_time;
	/* Its value must < 32 (2^5) */
	unsigned int rx_intrcoalesc_events;
	unsigned int tx_intrcoalesc_time;
	unsigned int tx_intrcoalesc_events;
	int IntrCoalescFlag;

	int RxRingLenBits;
	int TxRingLenBits;
	int TxRingSize;
	int RxRingSize;

	int IpgValue;
};

struct Rx_Buf_Desc {
	struct rx_desc *descriptor;
	long *USpaceMap;
};

struct nonphysical
{
	/* Tx descriptors queue */
	struct tx_desc *TxDescQRead;	/* The next ring entry to be freed */
	struct tx_desc *TxDescQWrite;	/* The next free ring entry */
	struct tx_desc *TxDescQStart;	/* The start of the ring entries */
	struct tx_desc *TxDescQEnd;	/* The end of the ring entries */

	/* struct Rx_Buf_Desc * queue */
	struct Rx_Buf_Desc *RxBufDescQRead;
	struct Rx_Buf_Desc *RxBufDescQStart;
	struct Rx_Buf_Desc *RxBufDescQEnd;

};

struct  mil
{
	/*
	 *	1) For memory allocation and free
	 */

	/*
	 * Tx_desc: address of all tx descriptors block
	 * Tx_desc_pa: physical address of Tx_desc
	 */
	struct tx_desc *Tx_desc;
	unsigned int Tx_desc_pa;
	/* Original address, because Tx_desc needs 16 bytes alignment */
	ULONG Tx_desc_original;

	struct rx_desc *Rx_desc;
	unsigned int Rx_desc_pa;
	/* Original address, because Rx_desc needs 16 bytes alignment */
	ULONG Rx_desc_original;

	long *USpaceMapArray;	/* Queue of struct rxBufInfo * */

	/*
	 *	2) For descriptor queue/buffer queue operation
	 */
	struct nonphysical *pNonphysical;

	/*
	 *	3) Parameters
	 */
	int RxRingSize;
	int TxRingSize;
	int RxBufSize;

	/*
	 *	4) Other
	 */
	int tx_reschedule;
	char *name;
};

struct LayerPointers
{
	struct odl *pOdl;
	struct mil *pMil;
	struct mdl *pMdl;

	int instance;
	int attach_progress;
	int run;	/* B_TRUE on plumb; B_FALSE on unplumb */
};

/* MIL Function Prototypes. */

/*
 * Initialisation of MIL data structures and External Interface Function
 * Pointers.
 */
void milInitGlbds(struct LayerPointers *);

void milInitRxQ(struct LayerPointers *);

void milResetTxQ(struct LayerPointers *);

void milFreeResources(struct LayerPointers *, ULONG *);

void milRequestResources(ULONG *);
void milSetResources(struct LayerPointers *, ULONG *);

/* Open Functions. */
void mdlOpen(struct LayerPointers *);

void mdlHWReset(struct LayerPointers *);

/* Multicast */
void mdlDeleteMulticastAddress(struct LayerPointers *, UCHAR *);
void mdlAddMulticastAddress(struct LayerPointers *, UCHAR *);

/* Transmit/Receive Interface provided by MDL */
void mdlTransmit(struct LayerPointers *);
void mdlReceive(struct LayerPointers *);

unsigned int mdlReadMib(struct LayerPointers *, char);

/* Read Link Status */
int mdlReadLink(struct LayerPointers *);

/* Interrupt Handling */
unsigned int mdlReadInterrupt(struct LayerPointers *);

void mdlEnableInterrupt(struct LayerPointers *);
void mdlDisableInterrupt(struct LayerPointers *);

void mdlGetActiveMediaInfo(struct LayerPointers *);

void mdlStartChip(struct LayerPointers *);
void mdlStopChip(struct LayerPointers *);

void mdlGetMacAddress(struct LayerPointers *, unsigned char *);
void mdlSetMacAddress(struct LayerPointers *, unsigned char *);

void mdlAddMulticastAddresses(struct LayerPointers *, int, unsigned char *);

void mdlSetPromiscuous(struct LayerPointers *);
void mdlDisablePromiscuous(struct LayerPointers *);

void mdlSendPause(struct LayerPointers *);

void SetIntrCoalesc(struct LayerPointers *, boolean_t);
void mdlPHYAutoNegotiation(struct LayerPointers *, unsigned int);
void mdlRxFastSuspend(struct LayerPointers *);
void mdlRxFastSuspendClear(struct LayerPointers *);

/* Externs */

/* ODL functions */
extern void amd8111s_reset(struct LayerPointers *);
extern unsigned char READ_REG8(struct LayerPointers *, long);
extern void WRITE_REG8(struct LayerPointers *, long, int);
extern int READ_REG16(struct LayerPointers *, long);
extern void WRITE_REG16(struct LayerPointers *, long, int);
extern long READ_REG32(struct LayerPointers *, long);
extern void WRITE_REG32(struct LayerPointers *, long, int);
extern void WRITE_REG64(struct LayerPointers *, long, char *);

#endif	/* AMD8111S_HW_H */

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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RGE_HW_H
#define	_RGE_HW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>


/*
 * First section:
 *	Identification of the various Realtek GigE chips
 */

/*
 * Driver support device
 */
#define	VENDOR_ID_REALTECK		0x10EC
#define	DEVICE_ID_8169			0x8169	/* PCI */
#define	DEVICE_ID_8110			0x8169	/* PCI */
#define	DEVICE_ID_8168			0x8168	/* PCI-E */
#define	DEVICE_ID_8111			0x8168	/* PCI-E */
#define	DEVICE_ID_8169SC		0x8167	/* PCI */
#define	DEVICE_ID_8110SC		0x8167	/* PCI */
#define	DEVICE_ID_8101E			0x8136	/* 10/100M PCI-E */

#define	RGE_REGISTER_MAX		0x0100


/*
 * Second section:
 *	Offsets of important registers & definitions for bits therein
 */
/*
 * MAC address register, initial value is autoloaded from the
 * EEPROM EthernetID field
 */
#define	ID_0_REG			0x0000
#define	ID_1_REG			0x0001
#define	ID_2_REG			0x0002
#define	ID_3_REG			0x0003
#define	ID_4_REG			0x0004
#define	ID_5_REG			0x0005

/*
 * Multicast register
 */
#define	MULTICAST_0_REG			0x0008
#define	MULTICAST_1_REG			0x0009
#define	MULTICAST_2_REG			0x000a
#define	MULTICAST_3_REG			0x000b
#define	MULTICAST_4_REG			0x000c
#define	MULTICAST_5_REG			0x000d
#define	MULTICAST_6_REG			0x000e
#define	MULTICAST_7_REG			0x000f
#define	RGE_MCAST_NUM			8 /* total 8 registers: MAR0 - MAR7 */

/*
 * Dump Tally Counter Command register
 */
#define	DUMP_COUNTER_REG_0		0x0010
#define	DUMP_COUNTER_REG_RESV		0x00000037
#define	DUMP_START			0x00000008
#define	DUMP_COUNTER_REG_1		0x0014

/*
 * Register for start address of transmit descriptors
 */
#define	NORMAL_TX_RING_ADDR_LO_REG	0x0020
#define	NORMAL_TX_RING_ADDR_HI_REG	0x0024
#define	HIGH_TX_RING_ADDR_LO_REG	0x0028
#define	HIGH_TX_RING_ADDR_HI_REG	0x002c

/*
 * Commond register
 */
#define	RT_COMMAND_REG			0x0037
#define	RT_COMMAND_RESV			0xe3
#define	RT_COMMAND_RESET		0x10
#define	RT_COMMAND_RX_ENABLE		0x08
#define	RT_COMMAND_TX_ENABLE		0x04

/*
 * Transmit priority polling register
 */
#define	TX_RINGS_POLL_REG		0x0038
#define	HIGH_TX_RING_POLL		0x80
#define	NORMAL_TX_RING_POLL		0x40
#define	FORCE_SW_INT			0x01

/*
 * Interrupt mask & status register
 */
#define	INT_MASK_REG			0x003c
#define	INT_STATUS_REG			0x003e
#define	SYS_ERR_INT			0x8000
#define	TIME_OUT_INT			0x4000
#define	SW_INT				0x0100
#define	NO_TXDESC_INT			0x0080
#define	RX_FIFO_OVERFLOW_INT		0x0040
#define	LINK_CHANGE_INT			0x0020
#define	NO_RXDESC_INT			0x0010
#define	TX_ERR_INT			0x0008
#define	TX_OK_INT			0x0004
#define	RX_ERR_INT			0x0002
#define	RX_OK_INT			0x0001

#define	INT_REG_RESV			0x3e00
#define	INT_MASK_ALL			0xffff
#define	INT_MASK_NONE			0x0000
#define	RGE_RX_INT			(RX_OK_INT | RX_ERR_INT | \
					    NO_RXDESC_INT)
#define	RGE_INT_MASK			(RGE_RX_INT | LINK_CHANGE_INT)

/*
 * Transmit configuration register
 */
#define	TX_CONFIG_REG			0x0040
#define	TX_CONFIG_REG_RESV		0x8070f8ff
#define	HW_VERSION_ID_0			0x7c000000
#define	INTER_FRAME_GAP_BITS		0x03080000
#define	TX_INTERFRAME_GAP_802_3		0x03000000
#define	HW_VERSION_ID_1			0x00800000
#define	MAC_LOOPBACK_ENABLE		0x00060000
#define	CRC_APPEND_ENABLE		0x00010000
#define	TX_DMA_BURST_BITS		0x00000700

#define	TX_DMA_BURST_UNLIMIT		0x00000700
#define	TX_DMA_BURST_1024B		0x00000600
#define	TX_DMA_BURST_512B		0x00000500
#define	TX_DMA_BURST_256B		0x00000400
#define	TX_DMA_BURST_128B		0x00000300
#define	TX_DMA_BURST_64B		0x00000200
#define	TX_DMA_BURST_32B		0x00000100
#define	TX_DMA_BURST_16B		0x00000000

#define	MAC_VER_8169			0x00000000
#define	MAC_VER_8169S_D			0x00800000
#define	MAC_VER_8169S_E			0x04000000
#define	MAC_VER_8169SB			0x10000000
#define	MAC_VER_8169SC			0x18000000
#define	MAC_VER_8168			0x20000000
#define	MAC_VER_8168B_B			0x30000000
#define	MAC_VER_8168B_C			0x38000000
#define	MAC_VER_8168B_D			0x3c000000
#define	MAC_VER_8101E			0x34000000
#define	MAC_VER_8101E_B			0x24800000
#define	MAC_VER_8101E_C			0x34800000

#define	TX_CONFIG_DEFAULT		(TX_INTERFRAME_GAP_802_3 | \
					    TX_DMA_BURST_1024B)
/*
 * Receive configuration register
 */
#define	RX_CONFIG_REG			0x0044
#define	RX_CONFIG_REG_RESV		0xfffe1880
#define	RX_RER8_ENABLE			0x00010000
#define	RX_FIFO_THRESHOLD_BITS		0x0000e000
#define	RX_FIFO_THRESHOLD_NONE		0x0000e000
#define	RX_FIFO_THRESHOLD_1024B		0x0000c000
#define	RX_FIFO_THRESHOLD_512B		0x0000a000
#define	RX_FIFO_THRESHOLD_256B		0x00008000
#define	RX_FIFO_THRESHOLD_128B		0x00006000
#define	RX_FIFO_THRESHOLD_64B		0x00004000
#define	RX_DMA_BURST_BITS		0x00000700
#define	RX_DMA_BURST_UNLIMITED		0x00000700
#define	RX_DMA_BURST_1024B		0x00000600
#define	RX_DMA_BURST_512B		0x00000500
#define	RX_DMA_BURST_256B		0x00000400
#define	RX_DMA_BURST_128B		0x00000300
#define	RX_DMA_BURST_64B		0x00000200
#define	RX_EEPROM_9356			0x00000040
#define	RX_ACCEPT_ERR_PKT		0x00000020
#define	RX_ACCEPT_RUNT_PKT		0x00000010
#define	RX_ACCEPT_BROADCAST_PKT		0x000000008
#define	RX_ACCEPT_MULTICAST_PKT		0x000000004
#define	RX_ACCEPT_MAC_MATCH_PKT		0x000000002
#define	RX_ACCEPT_ALL_PKT		0x000000001

#define	RX_CONFIG_DEFAULT		(RX_FIFO_THRESHOLD_NONE | \
					    RX_DMA_BURST_1024B | \
					    RX_ACCEPT_BROADCAST_PKT | \
					    RX_ACCEPT_MULTICAST_PKT | \
					    RX_ACCEPT_MAC_MATCH_PKT)

/*
 * Timer count register
 */
#define	TIMER_COUNT_REG			0x0048

/*
 * Missed packet counter: indicates the number of packets
 * discarded due to Rx FIFO overflow
 */
#define	RX_PKT_MISS_COUNT_REG		0x004c

/*
 * 93c46(93c56) commond register:
 */
#define	RT_93c46_COMMOND_REG		0x0050
#define	RT_93c46_MODE_BITS		0xc0
#define	RT_93c46_MODE_NORMAL		0x00
#define	RT_93c46_MODE_AUTOLOAD		0x40
#define	RT_93c46_MODE_PROGRAM		0x80
#define	RT_93c46_MODE_CONFIG		0xc0

#define	RT_93c46_EECS			0x08
#define	RT_93c46_EESK			0x04
#define	RT_93c46_EEDI			0x02
#define	RT_93c46_EEDO			0x01

/*
 * Configuration registers
 */
#define	RT_CONFIG_0_REG			0x0051
#define	RT_CONFIG_1_REG			0x0052
#define	RT_CONFIG_2_REG			0x0053
#define	RT_CONFIG_3_REG			0x0054
#define	RT_CONFIG_4_REG			0x0055
#define	RT_CONFIG_5_REG			0x0056

/*
 * Timer interrupt register
 */
#define	TIMER_INT_REG			0x0058
#define	TIMER_INT_NONE			0x00000000

/*
 * PHY access register
 */
#define	PHY_ACCESS_REG			0x0060
#define	PHY_ACCESS_WR_FLAG		0x80000000
#define	PHY_ACCESS_REG_BITS		0x001f0000
#define	PHY_ACCESS_DATA_BITS		0x0000ffff
#define	PHY_DATA_MASK			0xffff
#define	PHY_REG_MASK			0x1f
#define	PHY_REG_SHIFT			16

/*
 * CSI data register (for PCIE chipset)
 */
#define	RT_CSI_DATA_REG			0x0064

/*
 * CSI access register  (for PCIE chipset)
 */
#define	RT_CSI_ACCESS_REG		0x0068

/*
 * PHY status register
 */
#define	PHY_STATUS_REG			0x006c
#define	PHY_STATUS_TBI			0x80
#define	PHY_STATUS_TX_FLOW		0x40
#define	PHY_STATUS_RX_FLOW		0x20
#define	PHY_STATUS_1000MF		0x10
#define	PHY_STATUS_100M			0x08
#define	PHY_STATUS_10M			0x04
#define	PHY_STATUS_LINK_UP		0x02
#define	PHY_STATUS_DUPLEX_FULL		0x01

#define	RGE_SPEED_1000M			1000
#define	RGE_SPEED_100M			100
#define	RGE_SPEED_10M			10
#define	RGE_SPEED_UNKNOWN		0

/*
 * EPHY access register (for PCIE chipset)
 */
#define	EPHY_ACCESS_REG			0x0080
#define	EPHY_ACCESS_WR_FLAG		0x80000000
#define	EPHY_ACCESS_REG_BITS		0x001f0000
#define	EPHY_ACCESS_DATA_BITS		0x0000ffff
#define	EPHY_DATA_MASK			0xffff
#define	EPHY_REG_MASK			0x1f
#define	EPHY_REG_SHIFT			16

/*
 * Receive packet maximum size register
 * -- the maximum rx size supported is (16K - 1) bytes
 */
#define	RX_MAX_PKTSIZE_REG		0x00da
#define	RX_PKTSIZE_JUMBO		0x1bfa	/* 7K bytes */
#define	RX_PKTSIZE_STD			0x05fa	/* 1530 bytes */
#define	RX_PKTSIZE_STD_8101E		0x3fff

/*
 * C+ command register
 */
#define	CPLUS_COMMAND_REG		0x00e0
#define	CPLUS_RESERVE			0xfd87
#define	CPLUS_BIT14			0x4000
#define	CPLUS_BIG_ENDIAN		0x0400
#define	RX_VLAN_DETAG			0x0040
#define	RX_CKSM_OFFLOAD			0x0020
#define	DUAL_PCI_CYCLE			0x0010
#define	MUL_PCI_RW_ENABLE		0x0008

/*
 * Receive descriptor start address
 */
#define	RX_RING_ADDR_LO_REG		0x00e4
#define	RX_RING_ADDR_HI_REG		0x00e8

/*
 * Max transmit packet size register
 */
#define	TX_MAX_PKTSIZE_REG		0x00ec
#define	TX_MAX_PKTSIZE_REG_RESV		0xc0
#define	TX_PKTSIZE_JUMBO		0x3b	/* Realtek suggested value */
#define	TX_PKTSIZE_STD			0x32	/* document suggested value */
#define	TX_PKTSIZE_STD_8101E		0x3f

#define	RESV_82_REG			0x0082
#define	RESV_E2_REG			0x00e2

/*
 * PHY registers
 */
/*
 * Basic mode control register
 */
#define	PHY_BMCR_REG			0x00
#define	PHY_RESET			0x8000
#define	PHY_LOOPBACK			0x4000
#define	PHY_SPEED_0			0x2000
#define	PHY_SPEED_1			0x0040
#define	PHY_SPEED_BITS			(PHY_SPEED_0 | PHY_SPEED_1)
#define	PHY_SPEED_1000M			PHY_SPEED_1
#define	PHY_SPEED_100M			PHY_SPEED_0
#define	PHY_SPEED_10M			0x0000
#define	PHY_SPEED_RES			(PHY_SPEED_0 | PHY_SPEED_1)
#define	PHY_AUTO_NEGO			0x1000
#define	PHY_RESTART_ANTO_NEGO		0x0200
#define	PHY_DUPLEX_FULL			0x0100
#define	PHY_BMCR_CLEAR			0xff40

/*
 * Basic mode status register
 */
#define	PHY_BMSR_REG			0x01
#define	PHY_100BASE_T4			0x8000
#define	PHY_100BASE_TX_FULL		0x4000
#define	PHY_100BASE_TX_HALF		0x2000
#define	PHY_10BASE_T_FULL		0x1000
#define	PHY_10BASE_T_HALF		0x0800
#define	PHY_100BASE_T2_FULL		0x0400
#define	PHY_100BASE_T2_HALF		0x0200
#define	PHY_1000BASE_T_EXT		0x0100
#define	PHY_AUTO_NEGO_END		0x0020
#define	PHY_REMOTE_FAULT		0x0010
#define	PHY_AUTO_NEGO_ABLE		0x0008
#define	PHY_LINK_UP			0x0004
#define	PHY_JABBER_DETECT		0x0002
#define	PHY_EXT_ABLE			0x0001

/*
 * PHY identifier register
 */
#define	PHY_ID_REG_1			0x02
#define	PHY_ID_REG_2			0x03
#define	PHY_VER_MASK			0x000f
#define	PHY_VER_S			0x0000
#define	PHY_VER_SB			0x0010

/*
 * Auto-negotiation advertising register
 */
#define	PHY_ANAR_REG			0x04
#define	ANAR_NEXT_PAGE			0x8000
#define	ANAR_REMOTE_FAULT		0x2000
#define	ANAR_ASY_PAUSE			0x0800
#define	ANAR_PAUSE			0x0400
#define	ANAR_100BASE_T4			0x0200
#define	ANAR_100BASE_TX_FULL		0x0100
#define	ANAR_100BASE_TX_HALF		0x0080
#define	ANAR_10BASE_T_FULL		0x0040
#define	ANAR_10BASE_T_HALF		0x0020
#define	ANAR_RESV_BITS			0x501f

/*
 * Auto-negotiation link partner ability register
 */
#define	PHY_ANLPAR_REG			0x05

/*
 * Auto-negotiation expansion register
 */
#define	PHY_ANER_REG			0x06

/*
 * Auto-negotiation next page transmit register
 */
#define	PHY_ANNPTR_REG			0x07

/*
 * Auto-negotiation next page receive register
 */
#define	PHY_ANNPRR_REG			0x08

/*
 * 1000Base-T control register
 */
#define	PHY_GBCR_REG			0x09
#define	GBCR_MODE_JITTER		0x2000
#define	GBCR_MODE_MASTER		0x4000
#define	GBCR_MODE_SLAVE			0x6000
#define	GBCR_1000BASE_T_FULL		0x0200
#define	GBCR_1000BASE_T_HALF		0x0100
#define	GBCR_DEFAULT			0x273a

/*
 * 1000Base-T status register
 */
#define	PHY_GBSR_REG			0x0a
#define	LP_1000BASE_T_FULL		0x0800
#define	LP_1000BASE_T_HALF		0x0400

/*
 * 1000Base-T extended status register
 */
#define	PHY_GBESR_REG			0x0f

#define	PHY_1F_REG			0x1f
#define	PHY_1D_REG			0x1d
#define	PHY_1C_REG			0x1c
#define	PHY_1B_REG			0x1b
#define	PHY_18_REG			0x18
#define	PHY_15_REG			0x15
#define	PHY_13_REG			0x13
#define	PHY_12_REG			0x12
#define	PHY_0E_REG			0x0e
#define	PHY_0C_REG			0x0c
#define	PHY_0B_REG			0x0b

/*
 * MII (PHY) registers, beyond those already defined in <sys/miiregs.h>
 */

#define	MII_AN_LPNXTPG			8
#define	MII_1000BASE_T_CONTROL		9
#define	MII_1000BASE_T_STATUS		10
#define	MII_IEEE_EXT_STATUS		15

/*
 * New bits in the MII_CONTROL register
 */
#define	MII_CONTROL_1000MB		0x0040

/*
 * New bits in the MII_AN_ADVERT register
 */
#define	MII_ABILITY_ASYM_PAUSE		0x0800
#define	MII_ABILITY_PAUSE		0x0400

/*
 * Values for the <selector> field of the MII_AN_ADVERT register
 */
#define	MII_AN_SELECTOR_8023		0x0001

/*
 * Bits in the MII_1000BASE_T_CONTROL register
 *
 * The MASTER_CFG bit enables manual configuration of Master/Slave mode
 * (otherwise, roles are automatically negotiated).  When this bit is set,
 * the MASTER_SEL bit forces Master mode, otherwise Slave mode is forced.
 */
#define	MII_1000BT_CTL_MASTER_CFG	0x1000	/* enable role select	*/
#define	MII_1000BT_CTL_MASTER_SEL	0x0800	/* role select bit	*/
#define	MII_1000BT_CTL_ADV_FDX		0x0200
#define	MII_1000BT_CTL_ADV_HDX		0x0100

/*
 * Vendor-specific MII registers
 */
#define	MII_EXT_CONTROL			MII_VENDOR(0)
#define	MII_EXT_STATUS			MII_VENDOR(1)
#define	MII_RCV_ERR_COUNT		MII_VENDOR(2)
#define	MII_FALSE_CARR_COUNT		MII_VENDOR(3)
#define	MII_RCV_NOT_OK_COUNT		MII_VENDOR(4)
#define	MII_AUX_CONTROL			MII_VENDOR(8)
#define	MII_AUX_STATUS			MII_VENDOR(9)
#define	MII_INTR_STATUS			MII_VENDOR(10)
#define	MII_INTR_MASK			MII_VENDOR(11)
#define	MII_HCD_STATUS			MII_VENDOR(13)

#define	MII_MAXREG			MII_VENDOR(15)	/* 31, 0x1f	*/

/*
 * Bits in the MII_AUX_STATUS register
 */
#define	MII_AUX_STATUS_MODE_MASK	0x0700
#define	MII_AUX_STATUS_MODE_1000_F	0x0700
#define	MII_AUX_STATUS_MODE_1000_H	0x0600
#define	MII_AUX_STATUS_MODE_100_F	0x0500
#define	MII_AUX_STATUS_MODE_100_4	0x0400
#define	MII_AUX_STATUS_MODE_100_H	0x0300
#define	MII_AUX_STATUS_MODE_10_F	0x0200
#define	MII_AUX_STATUS_MODE_10_H	0x0100
#define	MII_AUX_STATUS_MODE_NONE	0x0000
#define	MII_AUX_STATUS_MODE_SHIFT	8

#define	MII_AUX_STATUS_PAR_FAULT	0x0080
#define	MII_AUX_STATUS_REM_FAULT	0x0040
#define	MII_AUX_STATUS_LP_ANEG_ABLE	0x0010
#define	MII_AUX_STATUS_LP_NP_ABLE	0x0008

#define	MII_AUX_STATUS_LINKUP		0x0004
#define	MII_AUX_STATUS_RX_PAUSE		0x0002
#define	MII_AUX_STATUS_TX_PAUSE		0x0001

/*
 * Third section:
 * 	Hardware-defined data structures
 *
 * Note that the chip is naturally little-endian, so, for a little-endian
 * host, the structures defined below match those descibed in the PRM.
 * For big-endian hosts, some structures have to be swapped around.
 */

#if	!defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
#error	Host endianness not defined
#endif

/*
 * Architectural constants: absolute maximum numbers of each type of ring
 */

#define	RGE_SEND_SLOTS			1024
#define	RGE_RECV_SLOTS			1024
#define	RGE_BUFF_SIZE_STD		1536	/* 1536 bytes */
#define	RGE_BUFF_SIZE_JUMBO		7168	/* maximum 7K */
#define	RGE_JUMBO_SIZE			7014
#define	RGE_JUMBO_MTU			7000
#define	RGE_STATS_DUMP_SIZE		64

typedef struct rge_bd {
	volatile uint32_t	flags_len;
	volatile uint32_t	vlan_tag;
	volatile uint32_t	host_buf_addr;
	volatile uint32_t	host_buf_addr_hi;
} rge_bd_t;

#define	BD_FLAG_HW_OWN			0x80000000
#define	BD_FLAG_EOR			0x40000000
#define	BD_FLAG_PKT_START		0x20000000
#define	BD_FLAG_PKT_END			0x10000000

#define	RBD_FLAG_MULTICAST		0x08000000
#define	RBD_FLAG_UNICAST		0x04000000
#define	RBD_FLAG_BROADCAST		0x02000000
#define	RBD_FLAG_PKT_4096		0x00400000
#define	RBD_FLAG_ERROR			0x00200000
#define	RBD_FLAG_RUNT			0x00100000
#define	RBD_FLAG_CRC_ERR		0x00080000
#define	RBD_FLAG_PROTOCOL		0x00060000
#define	RBD_FLAG_IP			0x00060000
#define	RBD_FLAG_UDP			0x00040000
#define	RBD_FLAG_TCP			0x00020000
#define	RBD_FLAG_NONE_IP		0x00000000
#define	RBD_IP_CKSUM_ERR		0x00010000
#define	RBD_UDP_CKSUM_ERR		0x00008000
#define	RBD_TCP_CKSUM_ERR		0x00004000
#define	RBD_CKSUM_ERR			0x0001c000
#define	RBD_FLAGS_MASK			0xffffc000
#define	RBD_LEN_MASK			0x00003fff

#define	RBD_VLAN_PKT			0x00010000
#define	RBD_VLAN_TAG			0x0000ffff


#define	SBD_FLAG_LARGE_SEND		0x08000000
#define	SBD_FLAG_SEG_MAX		0x07ff0000
#define	SBD_FLAG_IP_CKSUM		0x00040000
#define	SBD_FLAG_UDP_CKSUM		0x00020000
#define	SBD_FLAG_TCP_CKSUM		0x00010000
#define	SBD_FLAG_TCP_UDP_CKSUM		0x00030000
#define	SBD_LEN_MASK			0x0000ffff

#define	SBD_VLAN_PKT			0x00020000
#define	SBD_VLAN_TAG			0x0000ffff

#define	SBD_FLAG_TX_PKT			(BD_FLAG_HW_OWN | BD_FLAG_PKT_START | \
					    BD_FLAG_PKT_END)

/*
 * Chip VLAN TCI format
 *	bit0-3: VIDH The high 4 bits of a 12-bit VLAN ID
 *	bit4: CFI Canonical format indicator
 *	bit5-7: 3-bit 8-level priority
 *	bit8-15: The low 8 bits of a 12-bit VLAN ID
 */
#define	TCI_OS2CHIP(tci)		(((tci & 0xff) << 8) | (tci >> 8))
#define	TCI_CHIP2OS(tci)		(((tci & 0xff00) >> 8) | (tci << 8))

/*
 * Hardware-defined Status Block
 */
typedef struct rge_hw_stats {
	uint64_t	xmt_ok;
	uint64_t	rcv_ok;
	uint64_t	xmt_err;
	uint32_t	rcv_err;
	uint16_t	in_discards;
	uint16_t	frame_err;
	uint32_t	xmt_1col;
	uint32_t	xmt_mcol;
	uint64_t	unicast_rcv;
	uint64_t	brdcst_rcv;
	uint32_t	multi_rcv;
	uint16_t	xmt_abt;
	uint16_t	xmt_undrn;
} rge_hw_stats_t;	/* total 64 bytes */

#ifdef __cplusplus
}
#endif

#endif	/* _RGE_HW_H */

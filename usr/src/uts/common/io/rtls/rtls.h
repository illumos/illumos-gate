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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * rtls -- REALTEK 8139-serials PCI Fast Ethernet Driver.
 *
 * This product is covered by one or more of the following patents:
 * US5,307,459, US5,434,872, US5,732,094, US6,570,884, US6,115,776, and
 * US6,327,625.
 *
 * Currently supports:
 *	RTL8139
 */


#ifndef _SYS_RTLS_H
#define	_SYS_RTLS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Debug flags */
#define	RTLS_TRACE		0x01
#define	RTLS_ERRS		0x02
#define	RTLS_RECV		0x04
#define	RTLS_DDI		0x08
#define	RTLS_SEND		0x10
#define	RTLS_INT		0x20
#define	RTLS_SENSE		0x40
#define	RTLS_REGCFG		0x80

#ifdef DEBUG
#define	RTLS_DEBUG		1
#endif

/*
 * Driver support device
 */
#define	RT_VENDOR_ID		0x10EC	/* RealTek */
#define	RT_DEVICE_8139		0x8139
#define	RTLS_SUPPORT_DEVICE_1	((RT_VENDOR_ID << 16) | RT_DEVICE_8139)
	/* bind vendor and device id together */

#define	RTLS_VENDOR_ID_2	0x1186	/* D-link */
#define	RTLS_DEVICE_ID_2	0x1301
#define	RTLS_SUPPORT_DEVICE_2	((RTLS_VENDOR_ID_2 << 16) | RTLS_DEVICE_ID_2)

#define	RTLS_VENDOR_ID_3	0x1113	/* Accton */
#define	RTLS_DEVICE_ID_3	0x1211
#define	RTLS_SUPPORT_DEVICE_3	((RTLS_VENDOR_ID_3 << 16) | RTLS_DEVICE_ID_3)

#define	RTLS_VENDOR_ID_4	0x1186	/* D-link */
#define	RTLS_DEVICE_ID_4	0x1300
#define	RTLS_SUPPORT_DEVICE_4	((RTLS_VENDOR_ID_4 << 16) | RTLS_DEVICE_ID_4)

/*
 * Driver tx/rx parameters
 */
#define	RTLS_MAX_TX_DESC	4
#define	RTLS_TX_BUF_COUNT	8
#define	RTLS_TX_BUF_SIZE	2048
#define	RTLS_RX_BUF_RING	(32*1024)	/* 32K */
#define	RTLS_RX_BUF_SIZE	(RTLS_RX_BUF_RING + 2*1024)
#define	RTLS_MCAST_BUF_SIZE	64	/* multicast hash table size in bits */

/*
 * RTL8139 CRC poly
 */
#define	RTLS_HASH_POLY		0x04C11DB7	/* 0x04C11DB6 */
#define	RTLS_HASH_CRC		0xFFFFFFFFU

/*
 * STREAMS parameters
 */
#define	RTLS_HIWAT		(RTLS_MAX_TX_DESC * ETHERMAX)
					/* driver flow control high water */
#define	RTLS_LOWAT		1	/* driver flow control low water */
#define	RTLS_IDNUM		0	/* RTL Id; zero works */

/*
 * Helpful defines for register access
 */
#define	REG32(reg, off)		((uint32_t *)((uintptr_t)(reg) + off))
#define	REG16(reg, off)		((uint16_t *)((uintptr_t)(reg) + off))
#define	REG8(reg, off)		((uint8_t *)((uintptr_t)(reg) + off))

typedef struct {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory */
	void			*mem_va;	/* CPU VA of memory */
	size_t			alength;	/* allocated size */
	ddi_dma_handle_t	dma_hdl;	/* DMA handle */
	ddi_dma_cookie_t	cookie;		/* associated cookie */
	uint32_t		ncookies;	/* must be 1 */
} dma_area_t;

typedef struct rtls_stats {
	uint64_t	ipackets;
	uint64_t	multi_rcv;	/* ifInMulticastPkts */
	uint64_t	brdcst_rcv;	/* ifInBroadcastPkts */
	uint64_t	rbytes;
	uint64_t	opackets;
	uint64_t	multi_xmt;
	uint64_t	brdcst_xmt;
	uint64_t	obytes;
	uint32_t	collisions;
	uint32_t	firstcol;
	uint32_t	multicol;
	uint32_t	rcv_err;	/* ifInErrors */
	uint32_t	xmt_err;	/* ifOutErrors */
	uint32_t	mac_rcv_err;
	uint32_t	mac_xmt_err;
	uint32_t	overflow;
	uint32_t	underflow;
	uint32_t	no_carrier;	/* dot3StatsCarrierSenseErrors */
	uint32_t	xmt_latecoll;	/* dot3StatsLateCollisions */
	uint32_t	defer;		/* dot3StatsDeferredTransmissions */
	uint32_t	frame_err;	/* dot3StatsAlignErrors */
	uint32_t	crc_err;	/* dot3StatsFCSErrors */
	uint32_t	in_short;
	uint32_t	too_long;
	uint32_t	no_rcvbuf;	/* ifInDiscards */
} rtls_stats_t;

typedef struct rtls_instance {
	mac_handle_t	mh;
	mii_handle_t	mii;
	dev_info_t	*devinfo;	/* device instance */
	int32_t		instance;

	caddr_t		io_reg;		/* mapped chip register address */


	/* io handle & iblock */
	ddi_acc_handle_t	io_handle;	/* ddi I/O handle */
	ddi_iblock_cookie_t	iblk;

	/* dma buffer alloc used */
	dma_area_t		dma_area_rx;	/* receive dma area */
	dma_area_t		dma_area_tx[RTLS_MAX_TX_DESC];
						/* transmit dma area */

	uint8_t		netaddr[ETHERADDRL];	/* mac address */
	uint16_t	int_mask;		/* interrupt mask */

	/* used for multicast set */
	char		multicast_cnt[RTLS_MCAST_BUF_SIZE];
	uint32_t	multi_hash[2];

	boolean_t	promisc;		/* promisc state flag */

	/* used for send */
	uint8_t		*tx_buf[RTLS_MAX_TX_DESC];
	uint16_t	tx_current_desc;	/* Current Tx page */
	uint16_t	tx_first_loop;

	uint32_t	tx_retry;

	/* used for recv */
	uint8_t		*rx_ring;
	uint32_t	cur_rx;

	/* mutex */
	kmutex_t	rtls_io_lock;	/* i/o reg access */
	kmutex_t	rtls_tx_lock;	/* send access */
	kmutex_t	rtls_rx_lock;	/* receive access */

	/* send reschedule used */
	boolean_t	need_sched;

	boolean_t	chip_error;	/* chip error flag */

	/* current MAC state */
	boolean_t	rtls_running;
	boolean_t	rtls_suspended;

	/* rtls statistics */
	rtls_stats_t	stats;
} rtls_t;

#define	RTLS_TX_RETRY_NUM	16
#define	RTLS_TX_WAIT_TIMEOUT	(void) (drv_usectohz(100 * 1000)) /* 100ms */
#define	RTLS_RESET_WAIT_NUM	0x100
#define	RTLS_RESET_WAIT_INTERVAL	(void) (drv_usecwait(100))
#define	RTLS_RX_ADDR_ALIGNED(addr)	(((addr + 3) & ~3) % RTLS_RX_BUF_RING)
		/* 4-bytes aligned, also with RTLS_RX_BUF_RING boundary */

/* parameter definition in rtls.conf file */
#define	FOECE_NONE		0	/* no force */
#define	FORCE_AUTO_NEGO		5	/* auto negotioation mode */
#define	FORCE_100_FDX		4	/* 100 full_duplex mode */
#define	FORCE_100_HDX		3	/* 100 half_duplex mode */
#define	FORCE_10_FDX		2	/* 10 full_duplex mode */
#define	FORCE_10_HDX		1	/* 10 half_duplex mode */

/*
 * RealTek 8129/8139 register offsets definition
 */

/*
 * MAC address register, initial value isautoloaded from the
 * EEPROM EthernetID field
 */
#define	ID_0_REG	0x0000
#define	ID_1_REG	0x0001
#define	ID_2_REG	0x0002
#define	ID_3_REG	0x0003
#define	ID_4_REG	0x0004
#define	ID_5_REG	0x0005

/*
 * Multicast register
 */
#define	MULTICAST_0_REG 	0x0008
#define	MULTICAST_1_REG 	0x0009
#define	MULTICAST_2_REG		0x000a
#define	MULTICAST_3_REG		0x000b
#define	MULTICAST_4_REG		0x000c
#define	MULTICAST_5_REG		0x000d
#define	MULTICAST_6_REG		0x000e
#define	MULTICAST_7_REG		0x000f

#define	RCV_ALL_MULTI_PACKETS	0xffffffff

/*
 * Transmit status register
 */
#define	TX_STATUS_DESC0_REG	0x0010
#define	TX_STATUS_DESC1_REG	0x0014
#define	TX_STATUS_DESC2_REG	0x0018
#define	TX_STATUS_DESC3_REG	0x001c
#define	TX_STATUS_CS_LOST	0x80000000	/* Carrier Sense Lost */
#define	TX_STATUS_TX_ABORT	0x40000000	/* Transmit Abort */
#define	TX_STATUS_OWC		0x20000000	/* Out of Window Collision */
#define	TX_STATUS_CDH		0x10000000	/* CD Heart Beat */
#define	TX_STATUS_NCC		0x0f000000	/* Number of Collision Count */
#define	TX_STATUS_NCC_SHIFT	24
#define	TX_STATUS_TX_THRESHOLD	0x003f0000	/* Early Tx Threshold */
#define	TX_STATUS_TX_THRESHOLD_SHIFT	16
#define	TX_STATUS_TX_THRESHOLD_MAX	0x3f	/* 0x3f * 32 Bytes */
#define	TX_STATUS_TX_OK		0x00008000	/* Transmit OK */
#define	TX_STATUS_TX_UNDERRUN	0x00004000	/* Transmit FIFO Underrun */
#define	TX_STATUS_OWN		0x00002000	/* RTL8139 Own bit */
#define	TX_STATUS_PACKET_SIZE	0x00001fff
	/* The total size in bytes of the data in this descriptor */

/*
 * The read-only bits (CRS, TABT, OWC, CDH, NCC3-0, TOK, TUN) will be cleared
 * by the RTL8139 when the Transmit Byte Count (bit12-0) in the corresponding
 * Tx descriptor is written. If h/w transmit finish, at least some of these
 * bits are none zero.
 */
#define	TX_COMPLETE_FLAG	(TX_STATUS_TX_ABORT | TX_STATUS_TX_OK | \
				    TX_STATUS_TX_UNDERRUN)
#define	TX_ERR_FLAG		(TX_STATUS_TX_ABORT | TX_STATUS_TX_UNDERRUN | \
				    TX_STATUS_CS_LOST | TX_STATUS_OWC)

/*
 * Transmit start address of descriptors
 */
#define	TX_ADDR_DESC0_REG	0x0020
#define	TX_ADDR_DESC1_REG	0x0024
#define	TX_ADDR_DESC2_REG	0x0028
#define	TX_ADDR_DESC3_REG	0x002c

/*
 * Receive buffer start address
 */
#define	RX_BUFF_ADDR_REG	0x0030

/*
 * Early receive byte count register
 */
#define	RX_STATUS_REG		0x0036
#define	RX_STATUS_GOOD		0x08
#define	RX_STARUS_BAD		0x04
#define	RX_STATUS_COVERWRITE	0x02
#define	RX_STATUS_OK		0x01

/*
 * Commond register
 */
#define	RT_COMMAND_REG		0x0037
#define	RT_COMMAND_REG_RESERVE	0xe0
#define	RT_COMMAND_RESET	0x10
#define	RT_COMMAND_RX_ENABLE	0x08
#define	RT_COMMAND_TX_ENABLE	0x04
#define	RT_COMMAND_BUFF_EMPTY	0x01

/*
 * Rx current read address register
 */
#define	RX_CURRENT_READ_ADDR_REG	0x0038
#define	RX_READ_RESET_VAL		0xfff0
/*
 * Value in RX_CURRENT_READ_ADDR_REG is 16 less than
 * the actual rx read address
 */
#define	READ_ADDR_GAP			16

#define	RX_CURRENT_BUFF_ADDR_REG	0x003a

/*
 * Interrupt register
 */
#define	RT_INT_MASK_REG		0x003c
#define	RT_INT_STATUS_REG	0x003e
#define	RT_INT_STATUS_INTS	0xe07f
#define	SYS_ERR_INT		0x8000
#define	TIME_OUT_INT		0x4000
#define	CABLE_LEN_CHANGE_INT	0x2000
#define	RX_FIFO_OVERFLOW_INT	0x0040
#define	LINK_CHANGE_INT		0x0020
#define	RX_BUF_OVERFLOW_INT	0x0010
#define	TX_ERR_INT		0x0008
#define	TX_OK_INT		0x0004
#define	RX_ERR_INT		0x0002
#define	RX_OK_INT		0x0001

#define	RTLS_INT_MASK_ALL	0xe07f
#define	RTLS_INT_MASK_NONE	0x0000
#define	RTLS_RX_INT	(RX_OK_INT | RX_ERR_INT | \
			    RX_BUF_OVERFLOW_INT | RX_FIFO_OVERFLOW_INT)
#define	RX_OVERFLOW_INT	(RX_BUF_OVERFLOW_INT | RX_FIFO_OVERFLOW_INT)
#define	RTLS_INT_MASK	(LINK_CHANGE_INT | TX_ERR_INT | TX_OK_INT | \
			    RX_BUF_OVERFLOW_INT | RX_FIFO_OVERFLOW_INT | \
			    RX_ERR_INT | RX_OK_INT)

/*
 * Transmit configuration register
 */
#define	TX_CONFIG_REG		0x0040
#define	TX_CONSIG_REG_RESERVE	0x8078f80e
#define	HW_VERSION_ID_5		0x7c000000
#define	TX_INTERFRAME_GAP_BITS	0x03000000
#define	TX_INTERFRAME_GAP_SHIFT	24
#define	TX_INTERFRAME_GAP_802_3	0x03000000
#define	HW_VERSION_ID_1		0x00800000
#define	LOOPBACK_MODE_ENABLE	0x00060000
#define	CRC_APPEND_ENABLE	0x00010000
#define	TX_DMA_BURST_BYTES	0x00000700
#define	TX_DMA_BURST_2048B	0x00000700
#define	TX_DMA_BURST_1024B	0x00000600
#define	TX_RETRY_COUNT_BITS	0x000000f0
#define	TX_RETRY_COUNT_DEFUALT	0x00000010
	/* re-transmit count (16 + 1 * 16) = 32 times before aborting */
#define	TX_CLEAR_ABORT		0x00000001

#define	TX_CONFIG_DEFAULT	(TX_INTERFRAME_GAP_802_3 | \
				    TX_DMA_BURST_1024B | \
				    TX_RETRY_COUNT_DEFUALT)
#define	TX_FIFO_THRESHHOLD	1024
/*
 * Receive configuration register
 */
#define	RX_CONFIG_REG		0x0044
#define	RX_CONSIG_REG_RESERVE	0xf0fc0000

#define	RX_THRESHOLD_BITS	0x0f000000
#define	RX_EARLY_INT_SEL	0x00020000
#define	RX_RER8_ENABLE		0x00010000

#define	RX_FIFO_THRESHOLD_BITS	0x0000e000
#define	RX_FIFO_THRESHOLD_16B	0x00000000
#define	RX_FIFO_THRESHOLD_32B	0x00002000
#define	RX_FIFO_THRESHOLD_64B	0x00004000
#define	RX_FIFO_THRESHOLD_128B	0x00006000
#define	RX_FIFO_THRESHOLD_256B	0x00008000
#define	RX_FIFO_THRESHOLD_512B	0x0000a000
#define	RX_FIFO_THRESHOLD_1024B	0x0000c000
#define	RX_FIFO_THRESHOLD_NONE	0x0000e000

#define	RX_BUF_LEN_BITS		0x00001800
#define	RX_BUF_LEN_8K		0x00000000
#define	RX_BUF_LEN_16K		0x00000800
#define	RX_BUF_LEN_32K		0x00001000
#define	RX_BUF_LEN_64K		0x00001800

#define	RX_DMA_BURST_BYTES	0x00000700
#define	RX_DMA_BURST_16B	0x00000000
#define	RX_DMA_BURST_32B	0x00000100
#define	RX_DMA_BURST_64B	0x00000200
#define	RX_DMA_BURST_128B	0x00000300
#define	RX_DMA_BURST_256B	0x00000400
#define	RX_DMA_BURST_512B	0x00000500
#define	RX_DMA_BURST_1024B	0x00000600
#define	RX_DMA_BURST_UNLIMITED	0x00000700

#define	RX_NOWRAP_ENABLE	0x00000080
#define	RX_EEPROM_9356		0x00000040
#define	RX_ACCEPT_ERR_PACKET	0x00000020
#define	RX_ACCEPT_RUNT_PACKET	0x00000010
#define	RX_ACCEPT_BROADCAST_PACKET	0x000000008
#define	RX_ACCEPT_MULTICAST_PACKET	0x000000004
#define	RX_ACCEPT_MAC_MATCH_PACKET	0x000000002
#define	RX_ACCEPT_ALL_PACKET		0x000000001

#define	RX_CONFIG_DEFAULT	(RX_FIFO_THRESHOLD_NONE | \
				    RX_BUF_LEN_32K | \
				    RX_DMA_BURST_1024B | \
				    RX_ACCEPT_BROADCAST_PACKET | \
				    RX_ACCEPT_MULTICAST_PACKET | \
				    RX_ACCEPT_MAC_MATCH_PACKET)
/*
 * Missed packet counter: indicates the number of packets
 * discarded due to rx FIFO overflow
 */
#define	RX_PACKET_MISS_COUNT_REG	0x004c

/*
 * 93c46(93c56) commond register:
 */
#define	RT_93c46_COMMAND_REG	0x0050
#define	RT_93c46_MODE_BITS	0xc0
#define	RT_93c46_MODE_NORMAL	0x00
#define	RT_93c46_MODE_AUTOLOAD	0x40
#define	RT_93c46_MODE_PROGRAM	0x80
#define	RT_93c46_MODE_CONFIG	0xc0

#define	RT_93c46_EECS		0x08
#define	RT_93c46_EESK		0x04
#define	RT_93c46_EEDI		0x02
#define	RT_93c46_EEDO		0x01

/*
 * Configuration registers
 */
#define	RT_CONFIG_0_REG		0x0051
#define	RT_CONFIG_1_REG		0x0052
#define	RT_CONFIG_3_REG		0x0059
#define	RT_CONFIG_4_REG		0x005a

/*
 * Media status register
 */
#define	MEDIA_STATUS_REG	0x0058
#define	MEDIA_STATUS_LINK	0x04
#define	MEDIA_STATUS_SPEED	0x08

#define	RTLS_SPEED_100M		100000000
#define	RTLS_SPEED_10M		10000000
#define	RTLS_SPEED_UNKNOWN	0
/*
 * Multiple interrupt select register
 */
#define	RT_MUL_INTSEL_REG	0x005c
#define	RT_MUL_INTSEL_BITS	0x0fff

/*
 * Transmit status of all descriptor registers register
 */
#define	TX_DESC_STAUS_REG		0x0060
#define	TX_DESC_STAUS_OWN_0		0x0001
#define	TX_DESC_STAUS_ABORT_0		0x0010
#define	TX_DESC_STAUS_UNDERRUN_0	0x0100
#define	TX_DESC_STAUS_TXOK_0		0x1000
#define	TX_DESC_STAUS_OWN_1		0x0002
#define	TX_DESC_STAUS_ABORT_1		0x0020
#define	TX_DESC_STAUS_UNDERRUN_1	0x0200
#define	TX_DESC_STAUS_TXOK_1		0x2000
#define	TX_DESC_STAUS_OWN_2		0x0004
#define	TX_DESC_STAUS_ABORT_2		0x0040
#define	TX_DESC_STAUS_UNDERRUN_2	0x0400
#define	TX_DESC_STAUS_TXOK_2		0x4000
#define	TX_DESC_STAUS_OWN_3		0x0008
#define	TX_DESC_STAUS_ABORT_3		0x0080
#define	TX_DESC_STAUS_UNDERRUN_3	0x0800
#define	TX_DESC_STAUS_TXOK_3		0x8000

/*
 * Basic mode control register
 */
#define	BASIC_MODE_CONTROL_REG		0x0062
#define	BASIC_MODE_CONTROL_BITS		0x3300

#define	BASIC_MODE_SPEED		0x2000
#define	BASIC_MODE_SPEED_100		0x2000

#define	BASIC_MODE_AUTONEGO		0x1000

#define	BASIC_MODE_RESTAR_AUTONEGO	0x0200

#define	BASIC_MODE_DUPLEX		0x0100
#define	BASIC_MODE_DUPLEX_FULL		0x0100

/*
 * Basic mode status register
 */
#define	BASIC_MODE_STATUS_REG		0x0064
#define	BASIC_MODE_STATUS_AUTONEGO_DONE	0x0020
#define	BASIC_MODE_STATUS_REMOTE_FAULT	0x0010

/*
 * Auto-negotiation advertisement register
 */
#define	AUTO_NEGO_AD_REG		0x0066
#define	AUTO_NEGO_MODE_BITS		0x01e0
#define	AUTO_NEGO_100FULL		0x0100
#define	AUTO_NEGO_100HALF		0x0080
#define	AUTO_NEGO_10FULL		0x0040
#define	AUTO_NEGO_10HALF		0x0020

/*
 * Auto-negotiation link partner ability register
 */
#define	AUTO_NEGO_LP_REG		0x0068

/*
 * Auto-negotiation expansion register
 */
#define	AUTO_NEGO_EXP_REG		0x006a
#define	AUTO_NEGO_EXP_LPCANAN		0x0001

/*
 * Receive status in rx packet header
 */
#define	RX_HEADER_SIZE			4

#define	RX_HEADER_LEN_BITS		0xffff0000
#define	RX_HEADER_STATUS_BITS		0x0000ffff
#define	RX_STATUS_DMA_BUSY		0xfff0
#define	RX_HEADER_STATUS_MULTI		0x8000
#define	RX_HEADER_STATUS_PAM		0x4000
#define	RX_HEADER_STATUS_BCAST		0x2000

#define	RX_HEADER_STATUS_ISE		0x0020
#define	RX_HEADER_STATUS_RUNT		0x0010
#define	RX_HEADER_STATUS_LONG		0x0008
#define	RX_HEADER_STATUS_CRC		0x0004
#define	RX_HEADER_STATUS_FAE		0x0002
#define	RX_HEADER_STATUS_ROK		0x0001

#define	RX_ERR_FLAGS	(RX_HEADER_STATUS_ISE | RX_HEADER_STATUS_RUNT | \
			RX_HEADER_STATUS_FAE | RX_HEADER_STATUS_CRC)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_RTLS_H */

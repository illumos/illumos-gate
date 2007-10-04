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

#ifndef _SYS_DMFE_H
#define	_SYS_DMFE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Chip ID */
#define	DAVICOM_VENDOR_ID	0x1282
#define	DEVICE_ID_9100		0x9100
#define	DEVICE_ID_9132		0x9132
/* The 9102 and 9102A are distinguished by revision ID */
#define	DEVICE_ID_9102		0x9102
#define	DEVICE_ID_9102A		0x9102

/* Streams */
#define	DMFEHIWAT		32768	/* driver flow control high water */
#define	DMFELOWAT		4096	/* driver flow control low water */
#define	DMFEIDNUM		0	/* DMFE Id; zero works */

/* Size/count parameters */
#define	SROM_SIZE		128
#define	SETUPBUF_SIZE		192	/* Setup buffer size in bytes */
#define	MCASTBUF_SIZE		512	/* multicast hash table size in bits */
#define	HASH_POLY		0x04C11DB6
#define	HASH_CRC		0xFFFFFFFFU
#define	SETUPBUF_PHYS		39	/* word offset of station physical */
					/* address within setup buffer */


/*
 * Tx/Rx descriptor ring entry formats
 *
 * These structures are not actually used; they are just here to show
 * the layout of the descriptor entries used by the DMFE chip hardware
 * (we do use "sizeof" these structures).  The code uses the #defined
 * offsets below to access the various members of the descriptors, via
 * the DDI access functions (remember the DMFE h/w is little-endian).
 */

struct rx_desc_type {
	uint32_t	desc0;
	uint32_t	desc1;
	uint32_t	buffer1;
	uint32_t	rd_next;
};

struct tx_desc_type {
	uint32_t	desc0;
	uint32_t	desc1;
	uint32_t	buffer1;
	uint32_t	td_next;
};

/*
 * Offsets & sizes for tx/rx descriptors, expressed in (d)words
 */
#define	DESC0			0
#define	DESC1			1
#define	BUFFER1			2
#define	RD_NEXT			3
#define	TD_NEXT			3
#define	DESC_SIZE		4

/*
 * Receive descriptor description
 */
/* desc0 bit definitions */
#define	RX_OVERFLOW		(1UL<<0)
#define	RX_CRC			(1UL<<1)
#define	RX_DRIBBLING		(1UL<<2)
#define	RX_MII_ERR		(1UL<<3)
#define	RX_RCV_WD_TO		(1UL<<4)
#define	RX_FRAME_TYPE		(1UL<<5)
#define	RX_COLLISION		(1UL<<6)
#define	RX_FRAME2LONG		(1UL<<7)
#define	RX_LAST_DESC		(1UL<<8)
#define	RX_FIRST_DESC		(1UL<<9)
#define	RX_MULTI_FRAME		(1UL<<10)
#define	RX_RUNT_FRAME		(1UL<<11)
#define	RX_LOOP_MODE		(3UL<<12)
#define	RX_DESC_ERR		(1UL<<14)
#define	RX_ERR_SUMMARY		(1UL<<15)
#define	RX_FRAME_LEN		(0x3fffUL<<16)
#define	RX_FILTER_FAIL		(1UL<<30)
#define	RX_OWN			(1UL<<31)

/* desc1 bit definitions */
#define	RX_BUFFER_SIZE		(0x7ff)
#define	RX_CHAINING		(1UL<<24)
#define	RX_END_OF_RING		(1UL<<25)

/*
 * Transmit descriptor description
 */
/* desc0 bit definitions */
#define	TX_DEFERRED		(1UL<<0)
#define	TX_UNDERFLOW		(1UL<<1)
#define	TX_LINK_FAIL		(1UL<<2)
#define	TX_COLL_COUNT		(0xfUL<<3)
#define	TX_HEARTBEAT_FAIL	(1UL<<7)
#define	TX_EXCESS_COLL		(1UL<<8)
#define	TX_LATE_COLL		(1UL<<9)
#define	TX_NO_CARRIER		(1UL<<10)
#define	TX_CARRIER_LOSS		(1UL<<11)
#define	TX_JABBER_TO		(1UL<<14)
#define	TX_ERR_SUMMARY		(1UL<<15)
#define	TX_SPARE		(0x7fffUL<<16)
#define	TX_OWN			(1UL<<31)

/* desc1 bit definitions */
#define	TX_BUFFER_SIZE1		(0x7ffUL<<0)
#define	TX_BUFFER_SIZE2		(0x7ffUL<<11)
#define	TX_FILTER_TYPE0		(1UL<<22)
#define	TX_DISABLE_PAD		(1UL<<23)
#define	TX_CHAINING		(1UL<<24)
#define	TX_END_OF_RING		(1UL<<25)
#define	TX_CRC_DISABLE		(1UL<<26)
#define	TX_SETUP_PACKET		(1UL<<27)
#define	TX_FILTER_TYPE1		(1UL<<28)
#define	TX_FIRST_DESC		(1UL<<29)
#define	TX_LAST_DESC		(1UL<<30)
#define	TX_INT_ON_COMP		(1UL<<31)


/* Device-defined PCI config space registers */
#define	PCI_DMFE_CONF_CFDD	0x40
#define	CFDD_SNOOZE		(1UL<<30)
#define	CFDD_SLEEP		(1UL<<31)


/* Operating registers in I/O or MEMORY space */
#define	BUS_MODE_REG		0x00
#define	TX_POLL_REG		0x08
#define	RX_POLL_REG		0x10
#define	RX_BASE_ADDR_REG	0x18
#define	TX_BASE_ADDR_REG	0x20
#define	STATUS_REG		0x28
#define	OPN_MODE_REG		0x30
#define	INT_MASK_REG		0x38
#define	MISSED_FRAME_REG	0x40
#define	ETHER_ROM_REG		0x48
#define	BOOT_ROM_REG		0x50
#define	GP_TIMER_REG		0x58
#define	PHY_STATUS_REG		0x60
#define	FRAME_ACCESS_REG	0x68
#define	FRAME_DATA_REG		0x70
#define	W_J_TIMER_REG		0x78


/* Bit descriptions of CSR registers */

/* BUS_MODE_REG, CSR0 */
#define	SW_RESET		0x00000001
#define	BURST_SIZE		0		/* unlimited burst length */
#define	CACHE_ALIGN		(3 << 14)	/* 32 Dwords		*/
#define	TX_POLL_INTVL		(1 << 17)	/* 200us polling	*/
#define	READ_MULTIPLE		(1 << 21) 	/* use Memory Read	*/
						/* Multiple PCI cycles	*/

/* STATUS_REG, CSR5 */
#define	TX_PKTDONE_INT		0x00000001UL
#define	TX_STOPPED_INT		0x00000002UL
#define	TX_ALLDONE_INT		0x00000004UL
#define	TX_JABBER_INT		0x00000008UL
#define	TX_RESERVED_INT		0x00000010UL
#define	TX_UNDERFLOW_INT	0x00000020UL

#define	RX_PKTDONE_INT		0x00000040UL
#define	RX_UNAVAIL_INT		0x00000080UL
#define	RX_STOPPED_INT		0x00000100UL
#define	RX_WATCHDOG_INT		0x00000200UL

#define	TX_EARLY_INT		0x00000400UL
#define	GP_TIMER_INT		0x00000800UL
#define	LINK_STATUS_INT		0x00001000UL
#define	SYSTEM_ERR_INT		0x00002000UL
#define	RX_EARLY_INT		0x00004000UL

#define	ABNORMAL_SUMMARY_INT	0x00008000UL
#define	NORMAL_SUMMARY_INT	0x00010000UL
#define	INT_STATUS_MASK		0x0001ffffUL

#define	RX_PROCESS_STOPPED	0x00000000UL
#define	RX_PROCESS_FETCH_DESC	0x00020000UL
#define	RX_PROCESS_WAIT_PKT	0x00040000UL
#define	RX_PROCESS_STORE_DATA	0x00060000UL
#define	RX_PROCESS_CLOSE_OWNER	0x00080000UL
#define	RX_PROCESS_CLOSE_STATUS	0x000a0000UL
#define	RX_PROCESS_SUSPEND	0x000c0000UL
#define	RX_PROCESS_PURGE	0x000e0000UL
#define	RX_PROCESS_STATE_MASK	0x000e0000UL
#define	TX_PROCESS_STOPPED	0x00000000UL
#define	TX_PROCESS_FETCH_DESC	0x00100000UL
#define	TX_PROCESS_FETCH_SETUP	0x00200000UL
#define	TX_PROCESS_FETCH_DATA	0x00300000UL
#define	TX_PROCESS_CLOSE_OWNER	0x00400000UL
#define	TX_PROCESS_WAIT_END	0x00500000UL
#define	TX_PROCESS_CLOSE_STATUS	0x00600000UL
#define	TX_PROCESS_SUSPEND	0x00700000UL
#define	TX_PROCESS_STATE_MASK	0x00700000UL
#define	SYSTEM_ERR_BITS		0x03800000UL
#define	SYSTEM_ERR_PARITY	0x00000000UL
#define	SYSTEM_ERR_M_ABORT	0x00800000UL
#define	SYSTEM_ERR_T_ABORT	0x01000000UL

#define	RX_PROCESS_STATE(csr5)	(((csr5) & RX_PROCESS_STATE_MASK) >> 17)
#define	RX_PROCESS_MAX_STATE	7
#define	TX_PROCESS_STATE(csr5)	(((csr5) & TX_PROCESS_STATE_MASK) >> 20)
#define	TX_PROCESS_MAX_STATE	7

/* OPN_REG , CSR6 */
#define	HASH_FILTERING		(1UL<<0)
#define	START_RECEIVE		(1UL<<1)
#define	HASH_ONLY		(1UL<<2)
#define	PASSBAD			(1UL<<3)
#define	INV_FILTER		(1UL<<4)
#define	PROMISC_MODE		(1UL<<6)
#define	PASS_MULTICAST		(1UL<<7)
#define	FULL_DUPLEX		(1UL<<9)
#define	LOOPBACK_OFF		(0UL<<10)
#define	LOOPBACK_INTERNAL	(1UL<<10)
#define	LOOPBACK_PHY_D		(2UL<<10)
#define	LOOPBACK_PHY_A		(3UL<<10)
#define	LOOPBACK_MODE_MASK	(3UL<<10)
#define	FORCE_COLLISION		(1UL<<12)
#define	START_TRANSMIT 		(1UL<<13)
#define	TX_THRESHOLD_LOW	(0UL<<14)
#define	TX_THRESHOLD_MID	(1UL<<14)
#define	TX_THRESHOLD_HI		(2UL<<14)
#define	TX_THRESHOLD_MASK	(3UL<<14)
#define	ONE_PKT_MODE		(1UL<<16)
#define	EXT_MII_IF		(1UL<<18)
#define	START_TX_IMMED		(1UL<<20)
#define	STORE_AND_FORWARD	(1UL<<21)
#define	TX_THRESHOLD_MODE	(1UL<<22)
#define	OPN_25_MB1		(1UL<<25)
#define	NO_RX_PURGE		(1UL<<29)
#define	RECEIVEALL		(1UL<<30)

/* INT_MASK_REG , CSR7 */
/*
 * Use the values defined for the INT_STATUS_MASK bits (0..16)
 * of CSR5.  The remaining bits (17..31) are not used.
 */

/* MISSED_FRAME_REG, CSR8 */
#define	MISSED_FRAME_MASK	0x00000ffffUL
#define	MISSED_OVERFLOW		0x000010000UL
#define	PURGED_PACKET_MASK	0x07ffe0000UL
#define	PURGED_OVERFLOW		0x080000000UL

/* Serial ROM/MII Register CSR9 */
#define	SEL_CHIP		0x00000001UL
#define	SEL_CLK			0x00000002UL
#define	DATA_IN			0x00000004UL
#define	DATA_OUT		0x00000008UL
#define	SER_8_MB1		0x00000300UL
#define	SEL_XRS			0x00000400UL
#define	SEL_EEPROM		0x00000800UL
#define	SEL_BOOTROM		0x00001000UL
#define	WRITE_OP		0x00002000UL
#define	READ_OP			0x00004000UL
#define	SER_15_MB1		0x00008000UL
#define	READ_EEPROM		(READ_OP | SEL_EEPROM)
#define	READ_EEPROM_CS		(READ_OP | SEL_EEPROM | SEL_CHIP)

#define	MII_CLOCK		0x00010000UL
#define	MII_DATA_OUT		0x00020000UL
#define	MII_DATA_OUT_SHIFT	17
#define	MII_READ		0x00040000UL
#define	MII_TRISTATE		0x00040000UL
#define	MII_WRITE		0x00000000UL
#define	MII_DATA_IN		0x00080000UL
#define	MII_DATA_IN_SHIFT	19

#define	RELOAD_EEPROM		0x00100000UL
#define	LOADED_EEPROM		0x00200000UL

/* GPR Timer reg, CSR11 */
#define	GPTIMER_CONT		(1UL<<16)

/* PHY Status reg, CSR12 */
#define	GPS_LINK_10		0x00000001UL
#define	GPS_LINK_100		0x00000002UL
#define	GPS_FULL_DUPLEX		0x00000004UL
#define	GPS_LINK_STATUS		0x00000008UL
#define	GPS_RX_LOCK		0x00000010UL
#define	GPS_SIGNAL_DETECT	0x00000020UL
#define	GPS_UTP_SIG		0x00000040UL
#define	GPS_PHY_RESET		0x00000080UL
#define	GPS_WRITE_ENABLE	0x00000100UL

/* Sample Frame Access reg, CSR13 */
#define	TX_FIFO_ACCESS		(0x32<<3)
#define	RX_FIFO_ACCESS		(0x35<<3)
#define	DIAG_RESET		(0x38<<3)

/* Sample Frame Data reg, CSR14, when CSR13 is set to DIAG_RESET */
#define	DIAG_TX_FIFO_WRITE_0	0x00000001UL
#define	DIAG_TX_FIFO_READ_0	0x00000002UL
#define	DIAG_RX_FIFO_WRITE_0	0x00000004UL
#define	DIAG_RX_FIFO_READ_0	0x00000008UL
#define	DIAG_TX_FIFO_WRITE_100	0x00000020UL
#define	DIAG_RX_FIFO_WRITE_100	0x00000040UL

/* CSR15 */
#define	TX_JABBER_DISABLE	0x00000001UL
#define	UNJABBER_INTERVAL	0x00000002UL
#define	JABBER_CLOCK		0x00000004UL
#define	WD_TIMER_DISABLE	0x00000010UL
#define	WD_TIMER_RELEASE	0x00000020UL
#define	VLAN_ENABLE		0x00000040UL
#define	PAUSE_STATUS_1		0x00000080UL
#define	PAUSE_STATUS_2		0x00000200UL
#define	FLOW_CONTROL		0x00000400UL
#define	PAUSE_ENABLE_1		0x00000800UL
#define	PAUSE_ENABLE_2		0x00001000UL
#define	PAUSE_TX_FFFF		0x00002000UL
#define	PAUSE_TX_0000		0x00004000UL
#define	PAUSE_CONDITION		0x00008000UL
#define	RX_FIFO_THRES_MASK	0x003f0000UL
#define	RX_EARLY_THRES_MASK	0x01c00000UL


/* SROM access definitions */
#define	HIGH_ADDRESS_BIT	0x20			/* 6 bits */
#define	HIGH_CMD_BIT		0x4			/* 3 bits */
#define	HIGH_DATA_BIT		0x8000			/* 16 bits */
#define	SROM_DELAY		5			/* 5 microseconds */
#define	EEPROM_READ_CMD		6
#define	EEPROM_EN_ADDR		20

/* MII access definitions */
#define	MII_REG_ADDR_SHIFT	18
#define	MII_PHY_ADDR_SHIFT	23
#define	MII_DELAY		1			/* 1 microsecond */
#define	MII_PREAMBLE		0xffffffffUL
#define	MII_READ_FRAME		0x60000000UL
#define	MII_WRITE_FRAME		0x50020000UL


/* DMFE IOCTLS */
#define	ND_BASE			('N' << 8)	/* base */
#define	ND_GET			(ND_BASE + 0)	/* Get a value */
#define	ND_SET			(ND_BASE + 1)	/* Set a value */

#define	DMFE_ND_GET		ND_GET
#define	DMFE_ND_SET		ND_SET

#define	DMFEIOC			('G' << 8)
#define	DMFE_SET_LOOP_MODE	(DMFEIOC|1)
#define	DMFE_GET_LOOP_MODE	(DMFEIOC|2)

/* argument structure for above */
typedef struct {
	int loopback;
} loopback_t;

#define	DMFE_LOOPBACK_OFF	0
#define	DMFE_PHY_A_LOOPBACK_ON	1
#define	DMFE_PHY_D_LOOPBACK_ON	2
#define	DMFE_INT_LOOPBACK_ON	4
#define	DMFE_LOOPBACK_MODES	7	/* Bitwise OR of above	*/

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DMFE_H */

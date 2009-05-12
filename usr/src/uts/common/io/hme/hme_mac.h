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

#ifndef	HME_MAC_H
#define	HME_MAC_H

/*
 * HOST MEMORY DATA STRUCTURES
 */

/* The pointers to the Descriptor Ring base Addresses must be 2K-byte aligned */

#define	HME_HMDALIGN	(2048)

/*
 * The transmit and receiver Descriptor Rings are organized as "wrap-around
 * descriptors of programmable size.
 */
#define	HME_TMDMAX	(64)	/* Transmit descriptor ring size */
#define	HME_RMDMAX	(64)	/* Receive descriptor ring size */

/* Transmit descriptor structure */

struct hme_tmd {
	uint_t	tmd_flags;	/* OWN, SOP, EOP, cksum ctl and bufize */
	uint_t	tmd_addr;	/* 8-bye aligned buffer address */
};

/* fields in the tmd_flags */

#define	HMETMD_BUFSIZE	(0x3fff << 0)	/* 0-13 : Tx Data buffer size */
#define	HMETMD_CSSTART	(0x3f << 14)	/* 14-19 : Checksum start offset */
#define	HMETMD_CSSTUFF	(0xff << 20)	/* 20-27 : Checksum stuff offset */
#define	HMETMD_CSENABL	(1 << 28)	/* 28 : Enable checksum computation */
#define	HMETMD_EOP	(1 << 29)	/* 29 : End Of Packet flag */
#define	HMETMD_SOP	(1 << 30)	/* 30 : Start Of Packet flag */
#define	HMETMD_OWN	(0x80000000)	/* 31 : Ownership flag */
					/* 0 - owned by software */
					/* 1 - owned by hardware */

#define	HMETMD_CSSTART_SHIFT 14	/* checksum start bit position */
#define	HMETMD_CSSTUFF_SHIFT 20	/* checksum stuff bit position */

/*
 *	Programming Notes:
 *
 *	1. If a packet occupies more than one descriptor, the software must
 *	turn over the ownership of the descriptors to the hardware
 *	"last-to-first", in order to avoid race conditions.
 *
 *	2. If a packet resides in more than one buffer, the Checksum_Enable,
 *	Checksum_Stuff_Offset and Checksum_Start_Offset fields must have the
 *	same values in all the descriptors that were allocated to the packet.
 *
 *	3. The hardware implementation relies on the fact that if a buffer
 *	starts at an "odd" boundary, the DMA state machine can "rewind"
 *	to the nearest burst boundary and execute a full DVMA burst Read.
 *
 *	There is no other alignment restriction for the transmit data buffer.
 */

/* Receive Descriptor structure */

struct hme_rmd {
	uint_t	rmd_flags;	/* OWN, OVFLOW, buf/data size, cksum */
	uint_t	rmd_addr;	/* 8-byte aligned buffer address */
};

/* fields in the rmd_flags */

#define	HMERMD_CKSUM	(0xffff << 0)	/* 0-15 : checksum computed */
#define	HMERMD_BUFSIZE	(0x3fff << 16)	/* 16-29 : buffer/data size */
#define	HMERMD_OVFLOW	(1 << 30)	/* 30 : Rx buffer overflow */
#define	HMERMD_OWN	(0x80000000)	/* 31 : Ownership flag */
					/* 0 - owned by software */
					/* 1 - owned by hardware */

#define	HMERMD_BUFSIZE_SHIFT 16	/* buffer/data size bit position */

/* ************************************************************************* */

/* Global Register set in SEB (Shared Ethernet Block) */

struct hme_global {
    uint_t reset;		/* Global Software Reset Command */
    uint_t config;		/* Global Configuration Register */
    uint_t reserved[62];
    uint_t status;		/* Global Status Register */
    uint_t intmask;		/* Global Interrupt Mask Register */
};


/*
 * Global Software Reset Command Register - RW
 * These bits become "self cleared" after the corresponding reset command
 * has been executed. After a reset, the software must poll this register
 * till both the bits are read as 0's.
 */

#define	HMEG_RESET_ETX	(1 << 0)	/* Reset ETX */
#define	HMEG_RESET_ERX	(1 << 1)	/* Reset ERX */

#define	HMEG_RESET_GLOBAL HMEG_RESET_ETX | HMEG_RESET_ERX


/* Global Configuration Register - RW */

#define	HMEG_CONFIG_BURSTSZ	(0x3 << 0)	/* sbus max burst size */
#define	HMEG_CONFIG_64BIT_XFER	(1 << 2)	/* Extended transfer mode */
#define	HMEG_CONFIG_PARITY	(1 << 3)	/* sbus parity enable */
#define	HMEG_CONFIG_RES1	(1 << 4)	/* reserved, should be 0 */

#define	HMEG_CONFIG_BURST16	0x00	/* sbus max burst size 16 */
#define	HMEG_CONFIG_BURST32	0x01	/* sbus max burst size 32 */
#define	HMEG_CONFIG_BURST64	0x02	/* sbus max burst size 64 */
#define	HMEG_CONFIG_BURST_RES	0x03	/* sbus max burst size - reserved */

#define	HMEG_CONFIG_64BIT_SHIFT	2
/*
 * Global Status Register - R-AC
 *
 * All the bits in the Global Status Register are automatically cleared when
 * read with the exception of bit 23. The MIF status bit will be cleared after
 * the MIF Status Register is read.
 */


#define	HMEG_STATUS_FRAME_RCVD	(1 << 0)	/* from RX_MAC to RxFIFO */
#define	HMEG_STATUS_RXF_CNT_EXP	(1 << 1)	/* Rx_frame_counter expired */
#define	HMEG_STATUS_ALN_CNT_EXP	(1 << 2)	/* Alignment_Error_cntr exp */
#define	HMEG_STATUS_CRC_CNT_EXP	(1 << 3)	/* CRC_Error_counter expired */
#define	HMEG_STATUS_LEN_CNT_EXP	(1 << 4)	/* Length_Error_counter exp */
#define	HMEG_STATUS_RXFIFO_OVFL	(1 << 5)	/* RxFIFO_Overflow in RX_MAC */
#define	HMEG_STATUS_RCV_CNT_EXP	(1 << 6)	/* Code_Violation_counter exp */
#define	HMEG_STATUS_SQE_TST_ERR	(1 << 7)	/* SQE Test error in XIF */

#define	HMEG_STATUS_FRAME_SENT	(1 << 8)	/* Frame sent from TX_MAC */
#define	HMEG_STATUS_TXFIFO_UNDR	(1 << 9)	/* TxFIFO Underrun in TX_MAC */
#define	HMEG_STATUS_MXPKTSZ_ERR	(1 << 10)	/* Maximum_Packet_Size error */
#define	HMEG_STATUS_NRMCOLC_EXP	(1 << 11)	/* Normal_collision_cntr exp */
#define	HMEG_STATUS_EXCOLC_EXP	(1 << 12)	/* Excessive_coll_cntr exp */
#define	HMEG_STATUS_LATCOLC_EXP	(1 << 13)	/* Late_Collision_cntr exp */
#define	HMEG_STATUS_FSTCOLC_EXP	(1 << 14)	/* First_Coll_cntr expired */
#define	HMEG_STATUS_DEFTIMR_EXP	(1 << 15)	/* Defer_Timer expired */

#define	HMEG_STATUS_RINT	(1 << 16)	/* from RxFIFO to host memory */
#define	HMEG_STATUS_RX_DROP	(1 << 17)	/* No free Rx descriptors */
#define	HMEG_STATUS_RX_ERR_ACK	(1 << 18)	/* Error Ack in Rx DMA cycle */
#define	HMEG_STATUS_RX_LATE_ERR	(1 << 19)	/* Late Error in Rx DMA cycle */
#define	HMEG_STATUS_RX_PAR_ERR	(1 << 20)	/* Parity error in Rx DMA */
#define	HMEG_STATUS_RX_TAG_ERR	(1 << 21)	/* No two consecutiv tag bits */
#define	HMEG_STATUS_EOP_ERR	(1 << 22)	/* EOP not set in Tx desc */
#define	HMEG_STATUS_MIF_INTR	(1 << 23)	/* MIF interrupt */

#define	HMEG_STATUS_TINT	(1 << 24)	/* from host mem to TxFIFO */
#define	HMEG_STATUS_TX_ALL	(1 << 25)	/* TxFIFO empty */
#define	HMEG_STATUS_TX_ERR_ACK	(1 << 26)	/* Error Ack in Tx DMA cycle */
#define	HMEG_STATUS_TX_LATE_ERR	(1 << 27)	/* Late error in Tx DMA cycle */
#define	HMEG_STATUS_TX_PAR_ERR	(1 << 28)	/* Parity error in Tx DMA */
#define	HMEG_STATUS_TX_TAG_ERR	(1 << 29)	/* No two consecutiv tag bits */
#define	HMEG_STATUS_SLV_ERR_ACK	(1 << 30)	/* Error Ack in PIO cycle */
#define	HMEG_STATUS_SLV_PAR_ERR	(0x80000000)	/* Parity error in PIO write */

#define	HMEG_STATUS_FATAL_ERR	 0xfc7c0000	/* all fatal errors */
#define	HMEG_STATUS_NONFATAL_ERR 0x0002fefc	/* all non-fatal errors */
#define	HMEG_STATUS_NORMAL_INT	 0x01810000	/* normal interrupts */

#define	HMEG_STATUS_INTR	 0xfefffefc 	/* All interesting interrupts */

/*
 * Global Interrupt Mask register
 *
 * There is one-to-one correspondence between the bits in this register and
 * the Global Status register.
 *
 * The MIF interrupt [bit 23] is not maskable here. It should be masked at the
 * source of the interrupt in the MIF.
 *
 * Default value of the Global Interrupt Mask register is 0xFF7FFFFF.
 */

#define	HMEG_MASK_FRAME_RCVD	(1 << 0)	/* from RX_MAC to RxFIFO */
#define	HMEG_MASK_RXF_CNT_EXP	(1 << 1)	/* Rx_frame_counter expired */
#define	HMEG_MASK_ALN_CNT_EXP	(1 << 2)	/* Alignment_Error_cntr exp */
#define	HMEG_MASK_CRC_CNT_EXP	(1 << 3)	/* CRC_Error_counter expired */
#define	HMEG_MASK_LEN_CNT_EXP	(1 << 4)	/* Length_Error_counter exp */
#define	HMEG_MASK_RXFIFO_OVFL	(1 << 5)	/* RxFIFO_Overflow in RX_MAC */
#define	HMEG_MASK_RCV_CNT_EXP	(1 << 6)	/* Code_Violation_counter exp */
#define	HMEG_MASK_SQE_TST_ERR	(1 << 7)	/* SQE Test error in XIF */

#define	HMEG_MASK_FRAME_SENT	(1 << 8)	/* Frame sent from TX_MAC */
#define	HMEG_MASK_TXFIFO_UNDR	(1 << 9)	/* TxFIFO Underrun in TX_MAC */
#define	HMEG_MASK_MXPKTSZ_ERR	(1 << 10)	/* Maximum_Packet_Size error */
#define	HMEG_MASK_NRMCOLC_EXP	(1 << 11)	/* Normal_collision_cntr exp */
#define	HMEG_MASK_EXECOLC_EXP	(1 << 12)	/* Excessive_coll_cntr exp */
#define	HMEG_MASK_LATCOLC_EXP	(1 << 13)	/* Late_Collision_cntr exp */
#define	HMEG_MASK_FSTCOLC_EXP	(1 << 14)	/* First_Coll_cntr expired */
#define	HMEG_MASK_DEFTIMR_EXP	(1 << 15)	/* Defer_Timer expired */

#define	HMEG_MASK_RINT		(1 << 16)	/* from RxFIFO to host memory */
#define	HMEG_MASK_RX_DROP	(1 << 17)	/* No free Rx descriptors */
#define	HMEG_MASK_RX_ERR_ACK	(1 << 18)	/* Error Ack in Rx DMA cycle */
#define	HMEG_MASK_RX_LATE_ERR	(1 << 19)	/* Late Error in Rx DMA cycle */
#define	HMEG_MASK_RX_PAR_ERR	(1 << 20)	/* Parity error in Rx DMA */
#define	HMEG_MASK_RX_TAG_ERR	(1 << 21)	/* No two consecutiv tag bits */
#define	HMEG_MASK_EOP_ERR	(1 << 22)	/* EOP not set in Tx desc */
#define	HMEG_MASK_MIF_INTR	(1 << 23)	/* MIF interrupt */

#define	HMEG_MASK_TINT		(1 << 24)	/* from host mem to TxFIFO */
#define	HMEG_MASK_TX_ALL	(1 << 25)	/* TxFIFO empty */
#define	HMEG_MASK_TX_ERR_ACK	(1 << 26)	/* Error Ack in Tx DMA cycle */
#define	HMEG_MASK_TX_LATE_ERR	(1 << 27)	/* Late error in Tx DMA cycle */
#define	HMEG_MASK_TX_PAR_ERR	(1 << 28)	/* Parity error in Tx DMA */
#define	HMEG_MASK_TX_TAG_ERR	(1 << 29)	/* No two consecutiv tag bits */
#define	HMEG_MASK_SLV_ERR_ACK	(1 << 30)	/* Error Ack in PIO cycle */
#define	HMEG_MASK_SLV_PAR_ERR	(0x80000000)	/* Parity error in PIO write */

#define	HMEG_MASK_INTR		(~HMEG_STATUS_INTR)
						/* uninteresting interrupts */

/*
 *	Interrupts which are not interesting are:
 *	HMEG_MASK_FRAME_SENT
 *	HMEG_MASK_RXF_CNT_EXP
 *	HMEG_MASK_FRAME_RCVD
 */

/* ************************************************************************* */

/* ETX Register set */

struct hme_etx {
    uint_t txpend;		/* Transmit Pending Command */
    uint_t config;		/* ETX Configuration Register */
    uint_t txring;		/* Transmit Descriptor Ring Pointer */
    uint_t txbuf_base;		/* Transmit Data Buffer Base Address */
    uint_t txbuf_disp;		/* Transmit Data Buffer Displacement */
    uint_t txfifo_wr_ptr;	/* TxFIFO Write Pointer */
    uint_t txfifo_sdwr_ptr;	/* TxFIFO Shadow Write Pointer */
    uint_t txfifo_rd_ptr;	/* TxFIFO Read pointer */
    uint_t txfifo_sdrd_ptr;	/* TxFIFO Shadow Read pointer */
    uint_t txfifo_pkt_cnt;	/* TxFIFO Packet Counter */
    uint_t state_mach;		/* ETX State Machine Register */
    uint_t txring_size;		/* Descriptor Ring Size */
    uint_t txbuf_ptr;		/* Transmit Data Buffer Pointer */
};

/*
 * ETX Transmit Pending Command Register - RW
 * This 1-bit command must be issued by the software for every packet that the
 * driver posts to the hardware.
 * This bit becomes "self-cleared" after the command is executed.
 */

#define	HMET_TXPEND_TDMD	(1 << 0)	/* wake up Tx DMA engine */

/*
 * ETX Configuration Register
 * If the desire is to buffer an entire standard Ethernet frame before its
 * transmission is enabled, the Tx-FIFO-Threshold field has to be proframmed
 * to "0x1ff".
 * The default value for the register is 0x3fe.
 * Bit 10 is used to modify the functionality of the Tx_All interrupt.
 * If it is 0, Tx_All interrupt is generated after processing the last
 * transmit descriptor with the OWN bit set. This only implies that the
 * data has been copied to the FIFO.
 * If it is 1, Tx_All interrupt is generated only after the entire
 * Transmit FIFO has been drained.
 */

#define	HMET_CONFIG_TXDMA_EN	(1 << 0)	/* Enable Tx DMA */
#define	HMET_CONFIG_TXFIFOTH	(0x1ff << 1)	/* 1-9 : TX FIFO Threshold */
#define	HMET_CONFIG_DRAIN_INT	(1 << 10)	/* TX_all_int modifier */

/*
 * Transmit Descriptor Pointer
 *
 * This 29-bit register points to the next descriptor in the ring. The 21 most
 * significant bits are used as the base address for the desriptor ring,
 * and the 8 least significant bits are used as a displacement for the current
 * descriptor.
 *
 * This register should be initialized to a 2KByte-aligned value after power-on
 * or Software Reset.
 *
 */

/*
 * ETX TX ring size register
 * This is a 4-bit register to determine the no. of descriptor entries in the
 * TX-ring. The number of entries can vary from 16 through 256 in increments of
 * 16.
 */

#define	HMET_RINGSZ_SHIFT	4

/* ************************************************************************* */

/* ERX Register Set */

struct hme_erx {
    uint_t config;		/* ERX Configuration Register */
    uint_t rxring;		/* Receive Descriptor Ring Pointer */
    uint_t rxbuf_ptr;		/* Receive Data Buffer Pointer */
    uint_t rxfifo_wr_ptr;	/* RxFIFO Write Pointer */
    uint_t rxfifo_sdwr_ptr;	/* RxFIFO Shadow Write Pointer */
    uint_t rxfifo_rd_ptr;	/* RxFIFO Read pointer */
    uint_t rxfifo_pkt_cnt;	/* RxFIFO Packet Counter */
    uint_t state_mach;		/* ERX State Machine Register */
};

/*
 * ERX Configuration Register - RW
 * This 23-bit register determines the ERX-specific parameters that control the
 * operation of the receive DMA channel.
 */

#define	HMER_CONFIG_RXDMA_EN	(1 << 0)	/* 0 : Enable Rx DMA */
#define	HMER_CONFIG_RES1	(0x3 << 1)	/* 1,2 : reserverd */
#define	HMER_CONFIG_FBOFFSET	(0x7 << 3)	/* 3-5 : First Byte Offset */
#define	HMER_CONFIG_RES2	(0x7 << 6)	/* 6-8 : reserverd */
#define	HMER_CONFIG_RXRINGSZ	(0x3 << 9)	/* 9,10 : RX desc. ring size */
#define	HMER_CONFIG_RES3	(0x1f << 11)	/* 11-15 : reserverd */
#define	HMER_CONFIG_RX_CSSTART	(0x7f << 16)	/* 16-22 : cksum start offset */

#define	HMER_CONFIG_RXRINGSZ32	(0x0 << 9)	/* Rx descr. ring size 32 */
#define	HMER_CONFIG_RXRINGSZ64	(0x1 << 9)	/* Rx descr. ring size 64 */
#define	HMER_CONFIG_RXRINGSZ128	(0x2 << 9)	/* Rx descr. ring size 128 */
#define	HMER_CONFIG_RXRINGSZ256	(0x3 << 9)	/* Rx descr. ring size 256 */

#define	HMER_CONFIG_FBO_SHIFT	3
#define	HMER_RXRINGSZ_SHIFT 	9
#define	HMER_RX_CSSTART_SHIFT	16

/*
 * Receive Descriptor Pointer
 *
 * This 29-bit register points to the next descriptor in the ring. The 21 most
 * significant bits are used as the base address for the desriptor ring,
 * and the 8 least significant bits are used as a displacement for the current
 * descriptor.
 *
 * This register should be initialized to a 2KByte-aligned value after power-on
 * or Software Reset.
 *
 */

/* ************************************************************************* */



/*
 * Declarations and definitions specific to the BigMAC functional block.
 *
 * The BigMAC block will provide the MAC functons for 10 or 100 Mbps CSMA/CD
 * protocol based interface.
 *
 */

/*
 * BigMAC Register Set.
 * BigMAC addresses map on a SBus word boundry. So all registers are
 * declared for a size of 32 bits. Registers that use fewer than 32
 * bits will return 0 in the bits not used.
 */
struct	hme_bmac {
	uint_t	xifc;		/* XIF Configuration register [9-0] (RW) */
	uint_t	pad1[129];	/* XXX unused */
	uint_t	txrst;		/* tx software reset (RW) */
	uint_t	txcfg;		/* tx configuration register [9-0] (RW) */
	uint_t	ipg1;		/* Inter Packet Gap 1 [7-0] (RW) */
	uint_t	ipg2;		/* Inter Packet Gap 2 [7-0] (RW) */
	uint_t	alimit;		/* attempt limit register [7-0] (RW) */
	uint_t	slot;		/* slot time register [7-0] (RW) */
	uint_t	palen;		/* preamble length register [7-0] (RW) */
	uint_t	papat;		/* preamble pattern register [7-0] (RW) */
	uint_t	txsfd;		/* tx start frame delimiter [7-0] (RW) */
	uint_t	jam;		/* jam size register [7-0] (RW) */
	uint_t	txmax;		/* tx maximum packet size [12-0] (RW) */
	uint_t	txmin;		/* tx minimum frame size [7-0] (RW) */
	uint_t	parg;		/* peak attempt count [7-0] (RW) */
	uint_t	dcnt;		/* defer timer counter [15-0] (RW) */
	uint_t	nccnt;		/* normal collision counter [15-0] (RW) */
	uint_t	fccnt;		/* first succesful coll. counter [15-0] (RW) */
	uint_t	excnt;		/* excess collision counter [7-0] (RW) */
	uint_t	ltcnt;		/* late collision counter [7-0] (RW) */
	uint_t	rseed;		/* random number seed [9-0] (RW) */
	uint_t	txsm;		/* tx state machine register [8-0] (R) */
	uint_t	pad2[44];	/* XXX Unused */
	uint_t	rxrst;		/* rx software reset register (RW) */
	uint_t	rxcfg;		/* rx configuration register [12-0] (RW) */
	uint_t	rxmax;		/* rx maximum packet size [12-0] (RW) */
	uint_t	rxmin;		/* rx minimum frame size [7-0] (RW) */
	uint_t	madd2;		/* mac address register 2 [47-32] (RW) */
	uint_t	madd1;		/* mac address register 1 [31-16] (RW) */
	uint_t	madd0;		/* mac address register 0 [15-0] (RW) */
	uint_t	frcnt;		/* receive frame count [15-0] (RW) */
	uint_t	lecnt;		/* rx giant length error count [7-0] (RW) */
	uint_t	aecnt;		/* rx alignment error count [7-0] (RW) */
	uint_t	fecnt;		/* receive crc error count [7-0] (RW) */
	uint_t	rxsm;		/* rx state machine register (R) */
	uint_t	rxcv;		/* rx code voilation register (R) */
	uchar_t	pad3[4];
	uint_t	hash3;		/* hash table 3 [63-48] (RW) */
	uint_t	hash2;		/* hash table 2 [47-32] (RW) */
	uint_t	hash1;		/* hash table 1 [31-16] (RW) */
	uint_t	hash0;		/* hash table 0 [15-0] (RW) */
	uint_t	afr2;		/* addr filter register 0_2 [15-0] (RW) */
	uint_t	afr1;		/* addr filter register 0_1 [15-0] (RW) */
	uint_t	afr0;		/* addr filter register 0_0 [15-0] (RW) */
	uint_t	afmr;		/* addr filter mask reg 0 [15-0] (RW) */
};

/*
 * BigMAC Register Bit Masks.
 */

/* XIF Configuration Register */

#define	BMAC_XIFC_ENAB		(1 << 0)	/* Enable XIF output drivers */
#define	BMAC_XIFC_XIFLPBK	(1 << 1)	/* Enable XIF Loopback mode */
#define	BMAC_XIFC_MIILPBK	(1 << 2)	/* Enable MII Loopback mode */
#define	BMAC_XIFC_MIIBUFDIS	(1 << 3)	/* Disable MII Recv Buffers */

/* IN FEPS 2.1 or earlier rev */
#define	BMAC_XIFC_SQETSTENB	(1 << 4)	/* Enable SQE Test */
#define	BMAC_XIFC_SQETSTWIN	(0x1f << 5)	/* SQE Test time window */

/* IN FEPS 2.2 or later rev */
#define	BMAC_XIFC_LANCE_ENAB	(1 << 4)	/* Enable  LANCE mode */
#define	BMAC_XIFC_LANCE_IPG0	(0x1f << 5)	/* IPG0 for LANCE mode */

#define	BMAC_XIFC_IPG0_SHIFT	5

/*
 * TX_MAC Software Reset Command Register
 * This bit is set to 1 when a PIO write is done. This bit becomes self-cleared.
 * after the command has been executed.
 */

#define	BMAC_TX_RESET		(1 << 0)	/* TX_MAC Reset Command */

/*
 * TX_MAC Configuration Register
 * To Ensure proper operation of the TX_MAC, the TX_MAC_Enable bit must always
 * be cleared to 0 and a delay imposed before a PIO write to any of the other
 * bits in the TX_MAC Configuration register or any of the MAC parameter
 * registers is done.
 *
 * The amount of delay required depends on the time required to transmit a max.
 * size frame.
 */

#define	BMACTXRSTDELAY		(125)		/* 125 us wait period */

#define	BMAC_TXCFG_ENAB		(1 << 0)	/* tx enable */
#define	BMAC_TXCFG_RES1		(0xf << 1)	/* 1-4 : reserved */
#define	BMAC_TXCFG_SLOW		(1 << 5)	/* carrier detect before tx */
#define	BMAC_TXCFG_IGCOLL	(1 << 6)	/* tx ignore collision */
#define	BMAC_TXCFG_NFCS		(1 << 7)	/* no FCS will be generated */
#define	BMAC_TXCFG_NBKOFF	(1 << 8)	/* No Backoff */
#define	BMAC_TXCFG_FDX		(1 << 9)	/* Full Duplex */
#define	BMAC_TXCFG_NGU		(1 << 10)	/* Never Give Up */

/*
 * RX_MAC Configuration Register
 * A delay of 3.2 us should be allowed after clearing Rx_MAC_Enable or
 * Hash_Filter_enable or Address_Filter_Enable bits.
 */

#define	BMACRXRSTDELAY		(40)		/* 3.2 us wait period */

#define	BMAC_RXCFG_ENAB		(1 << 0)	/* rx enable */
#define	BMAC_RXCFG_RES1		(0xf << 1)	/* 1-4 : reserved */
#define	BMAC_RXCFG_STRIP	(1 << 5)	/* rx strip pad bytes */
#define	BMAC_RXCFG_PROMIS	(1 << 6)	/* rx enable promiscous */
#define	BMAC_RXCFG_ERR		(1 << 7)	/* rx disable error checking */
#define	BMAC_RXCFG_CRC		(1 << 8)	/* rx disable CRC stripping */
#define	BMAC_RXCFG_MYOWN	(1 << 9)	/* rx filter own packets */
#define	BMAC_RXCFG_GRPROM	(1 << 10)	/* rx promiscuous group mode */
#define	BMAC_RXCFG_HASH		(1 << 11)	/* rx enable hash filter */
#define	BMAC_RXCFG_ADDR		(1 << 12)	/* rx enable address filter */



/* ************************************************************************* */

/*
 * MII Transceiver Interface
 *
 * The Management Interface (MIF) allows the host to program and collect status
 * from two transceivers connected to the MII. MIF supports three modes of
 * operation:
 *	1. Bit-Bang Mode
 *	   This mode is imlemented using three 1-bit registers: data, clock,
 *	   and output_enable.
 *
 *	2. Frame Mode
 *	   This mode is supported using one 32-bit register: Frame register.
 *	   The software loads the Frame Register with avalid instaruction
 *	   ("frame"), and polls the Valid Bit for completion.
 *
 *	3. Polling Mode
 *	   The Polling mechanism is used for detecting a status change in the
 *	   transceiver. When this mode is enabled, the MIF will continuously
 *	   poll a specified transceiver register and generate a maskable
 *	   interrupt when a status change is detected. This mode of operation
 *	   can only be used when the MIF is in the "Frame mode".
 *
 */

struct hme_mif {
	uint_t mif_bbclk;	/* MIF Bit Bang Clock */
	uint_t mif_bbdata;	/* MIF Bit Bang Data */
	uint_t mif_bbopenb;	/* MIF Bit Bang Output Enable */
	uint_t mif_frame;	/* MIF Frame - ctl and data */
	uint_t mif_cfg;		/* MIF Configuration */
	uint_t mif_imask;	/* MIF Interrupt mask */
	uint_t mif_bsts;	/* MIF Basic/Status register */
	uint_t mif_fsm;		/* MIF State machine register */
};

/* mif_bbc - Bit Bang Clock register */
#define	HME_MIF_BBCLK	(1 << 0);	/* Bit Babg Clock */

#define	HME_BBCLK_LOW 0
#define	HME_BBCLK_HIGH 1

/* mif_bbdata - bit Bang Data register */
#define	HME_MIF_BBDATA	(1 << 0);	/* Bit Bang Data */

/* mif_bbopenb - Bit Bang oOutput Enable register */
#define	HME_MIF_BBOPENB	(1 << 0);	/* Bit Bang output Enable */

/*
 * Management Frame Structure:
 * <IDLE> <ST><OP><PHYAD><REGAD><TA>	 <DATA>		   <IDLE>
 * READ:  <01><10><AAAAA><RRRRR><Z0><DDDDDDDDDDDDDDDD>
 * WRITE: <01><01><AAAAA><RRRRR><10><DDDDDDDDDDDDDDDD>
 */

/* mif_frame - MIF control and data register */

#define	HME_MIF_FRDATA	(0xffff << 0)	/* 0-15 : data bits */
#define	HME_MIF_FRTA0	(0x1 << 16)	/* 16 : TA bit, 1 for completion */
#define	HME_MIF_FRTA1	(0x1 << 17)	/* 16-17 : TA bits */
#define	HME_MIF_FRREGAD	(0x1f << 18)	/* 18-22 : register address bits */
#define	HME_MIF_FRPHYAD	(0x1f << 23)	/* 23-27 : PHY ad, should be 0 */
#define	HME_MIF_FROP	(0x3 << 28)	/* 28-29 : Operation - Write/Read */
#define	HME_MIF_FRST	(0xc0000000)	/* 30-31 : START bits */

#define	HME_MIF_FRREGAD_SHIFT	18
#define	HME_MIF_FRPHYAD_SHIFT	23
#define	HME_MIF_FRREAD		0x60020000
#define	HME_MIF_FRWRITE		0x50020000

/* maximum delay for MIF Register Read/Write operation */
#define	HMEMAXMIFDELAY	(100)

/* maximum delay for Transceiver Reset */
#define	HME_PHYRST_MAXDELAY	(500)

/* mif_cfg - MIF Configuration Register */

#define	HME_MIF_CFGPS	(1 << 0)	/* PHY Select */
#define	HME_MIF_CFGPE	(1 << 1)	/* Poll Enable */
#define	HME_MIF_CFGBB	(1 << 2)	/* Bit Bang Enable */
#define	HME_MIF_CFGPR	(0x1f << 3)	/* Poll Register address */
#define	HME_MIF_CFGM0	(1 << 8)	/* MDIO_0 Data / MDIO_0 attached */
#define	HME_MIF_CFGM1	(1 << 9)	/* MDIO_1 Data / MDIO_1 attached */
#define	HME_MIF_CFGPD	(0x1f << 10)	/* Poll Device PHY address */

#define	HME_MIF_CFGPR_SHIFT	3
#define	HME_MIF_CFGPD_SHIFT	10
#define	HME_MIF_POLL_DELAY	200

/*
 * MDIO_0 corresponds to the On Board Transceiver.
 * MDIO_1 corresponds to the External Transceiver.
 * The PHYAD for both is 0.
 */

#define	HME_INTERNAL_PHYAD	1	/* PHY address for int. transceiver */
#define	HME_EXTERNAL_PHYAD	0	/* PHY address for ext. transceiver */


/* mif_imask - MIF Interrupt Mask Register */
/*
 * This register is bit-to-bit same as Basic/Status Register
 */
#define	HME_MIF_INTMASK	(0xffff << 0)	/* 0-15 : Interrupt mask */

/* mif_bassts - MIF Basic / Status register */
/*
 * The Basic portion of this register indicates the last value of the register
 * read indicated in the POLL REG field of the Configuration Register.
 * The Status portion indicates bit(s) that have changed.
 * The MIF Mask register is corresponding to this register in terms of the
 * bit(s) that need to be masked for generating interrupt on the MIF Interrupt
 * Bit of the Global Status Rgister.
 */

#define	HME_MIF_STATUS	(0xffff << 0)	/* 0-15 : Status */
#define	HME_MIF_BASIC	(0xffff << 16)	/* 16-31 : Basic register */

/* mif_fsm - MIF State Machine register */

#define	HME_MIF_FSM	(0x3ff << 0)	/* 0-9 : MIF state */

/* ************************************************************************ */


/*
 * Definition for the time required to wait after a software
 * reset has been issued.
 */
#define	HMEMAXRSTDELAY	(200)
#define	HMEPERIOD	(20)	/* period to wait */
#define	HMEWAITPERIOD	HMEPERIOD

#define	HMEDELAY(c, n) \
	{ \
		register int N = n / HMEWAITPERIOD; \
		while (--N > 0) { \
			if (c) \
				break; \
			drv_usecwait(HMEWAITPERIOD); \
		} \
	}

#endif	/* HME_MAC_H */

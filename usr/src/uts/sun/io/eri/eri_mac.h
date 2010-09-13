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

#ifndef	_SYS_ERI_MAC_H
#define	_SYS_ERI_MAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * HOST MEMORY DATA STRUCTURES
 * Transmit and Receive Descriptor Rings
 */

/* The Descriptor Ring base Addresses must be 2K-byte aligned */

#define	ERI_GMDALIGN	(2048)

/*
 * The transmit and receiver Descriptor Rings are organized as "wrap-around
 * descriptors and are of programmable size.
 * Each descriptor consists of two double-word entries: a control/status entry
 * and a pointer to a data buffer.
 * The no. of entries is programmable in binary increments, from 32 to 8192.
 * TBD: Even though the Receive Desriptor ring size is 8k, provide for a user
 * configurable variable to specify the max.no. of Rx buffers posted.
 */

#define	ERI_TMDMAX	(4096)	/* Transmit descriptor ring size */
#define	ERI_RMDMAX	(4096)	/* Receive descriptor ring size */

/*
 * -----------------------------
 * Transmit descriptor structure
 * -----------------------------
 */

struct eri_tmd {
	uint64_t	tmd_flags;	/* INTME, SOP, EOP, cksum, bufsize */
	uint64_t	tmd_addr;	/* buffer address */
};

/* fields in the tmd_flags */

#define	ERI_TMD_BUFSIZE	(0x7fff << 0)	/* 0-14 : Tx Data buffer size */
					/* valid values in range 0 - 17k */
#define	ERI_TMD_CSSTART	(0x3f << 15)	/* 15-20 : Checksum start offset */
					/* value must be even */
#define	ERI_TMD_CSSTUFF	(0xff << 21)	/* 21-28 : Checksum stuff offset */
					/* value must be even */
#define	ERI_TMD_CSENABL	(1 << 29)	/* 29 : Enable checksum computation */
#define	ERI_TMD_EOP	(1 << 30)	/* 30 : End Of Packet flag */
#define	ERI_TMD_SOP	((uint64_t)1 << 31)	/* 31 : Packet Start flag */
#define	ERI_TMD_INTME	((uint64_t)1 << 32)	/* 32 : Interrupt me now */
#define	ERI_TMD_NOCRC	((uint64_t)1 << 33)	/* 33 : Do not insert CRC */

#define	ERI_TMD_CSSTART_SHIFT 15	/* checksum start bit position */
#define	ERI_TMD_CSSTUFF_SHIFT 21	/* checksum stuff bit position */

/*
 * TCP Header offset within Ethernet Packet:
 * 14 Bytes Ethernet Header + 20 IP Header.
 */

#define	ERI_TCPHDR_OFFSET	34
#define	ERI_IPHDR_OFFSET 	20

/*
 * TCP Checksum stuff offset within Ethernet packet:
 * 34 Bytes up to TCP Header + 16 Bytes within TCP header
 */

#define	ERI_TCPCSUM_OFFSET	50
#define	ERI_TMDCSUM_CTL		(ERI_TMD_CSENABL | \
				(ERI_TCPHDR_OFFSET << ERI_TMD_CSSTART_SHIFT) | \
				(ERI_TCPCSUM_OFFSET << ERI_TMD_CSSTUFF_SHIFT))
/*
 *	Programming Notes:
 *
 *	1. TX Kick Register is used to hand over TX descriptors to the hardware.
 *	TX Completion Register is used by hardware to handover TX descriptors
 *	back to the software.
 *
 *	2. ERI never writes back TX descriptors.
 *
 *	2. If a packet resides in more than one buffer, the Checksum_Enable,
 *	Checksum_Stuff_Offset, Checksum_Start_Offset and Int_me fields need to
 *	be set only in the first descriptor for the packet.
 *
 *	3. The hardware implementation relies on the fact that if a buffer
 *	starts at an "odd" boundary, the DMA state machine can "rewind"
 *	to the nearest burst boundary and execute a full DVMA burst Read.
 *
 *	There is no other alignment restriction for the transmit data buffer.
 */

/*
 * -----------------------------
 * Receive Descriptor structure
 * ----------------------------
 */

struct rmd {
	uint64_t	rmd_flags;
		/* hash_val, hash_pass, bad, OWN, buf/data size, cksum */
	uint64_t	rmd_addr;	/* 8-byte aligned buffer address */
};

/*
 * fields in the rmd_flags
 */
#define	ERI_RMD_CKSUM	(0xffff << 0)	/* 0-15 : checksum computed */
#define	ERI_RMD_BUFSIZE	(0x7fff << 16)	/* 16-30 : buffer/frame size */
#define	ERI_RMD_OWN	((uint64_t)1 << 31)	/* 31 : Ownership flag */
					/* 0 - owned by software */
					/* 1 - owned by hardware */
#define	ERI_RMD_RESERVED1	((uint64_t)0xfff << 32)	/* 32-43 : Reserved */
#define	ERI_RMD_HASHVAL	((uint64_t)0xffff << 44)	/* 44-59 : hash value */
#define	ERI_RMD_HASHPASS ((uint64_t)1 << 60)	/* 60 : pass hash filter */
#define	ERI_RMD_ALTERNATE	((uint64_t)1 << 61)
					/* 61 : matched alternate MAC adrs */
#define	ERI_RMD_BAD	((uint64_t)1 << 62)	/* 62 : bad CRC frame */
#define	ERI_RMD_RESERVED2	((uint64_t)1 << 63)	/* 63 : Reserved */

#define	ERI_RMD_BUFSIZE_SHIFT 16	/* buffer/data size bit position */

#define	ERI__RMD_BUFALIGN	8

/*
 * ERI REGISTER SPACE
 * The comments are in the following format:
 * Addres_Offset R/W Default Actual_size(bits) Description
 */

/*
 * Global Register Space : Paritally Modified for ERI
 */
struct global {
    uint32_t seb_state;	/* 0x0000 RO   0x00000000 03 SEB State Register */
    uint32_t config;	/* 0x0004 RW   0x00000000 17 Configuration Register */
    uint32_t reserved2;	/* 0x0008 */
    uint32_t status;	/* 0x000C R-AC 0x00000000 25 Int. Status Register */
    uint32_t intmask;	/* 0x0010 RW   0xFFFFFFFF 12 Interrupt Mask Reg */
    uint32_t intack;	/* 0x0014 WO   0x00000000 06 Interrupt Ack Register */
    uint32_t reserved3;	/* 0x0018 */
    uint32_t status_alias; /* 0x001C RO   0x00000000 25 Int. Stat Reg Alias */
    uint32_t reserved4[1016];	/* To skip to 0x1000 */
    uint32_t err_status; /* 0x1000 R-AC 0x00000000 03 PCI Error Status Reg. */
    uint32_t reset;	/* 0x1010 RW-AC 0x00	  3  Software Reset Reg */
};

/*
 *
 * SBus IO configuration (RW)
 * To configure parameters that define the DMA burst and internal arbitration.
 */
#define	ERI_SIOCFG_BSIZE32	(0x1 << 0) /* 32 byte burst sizeb state */
#define	ERI_SIOCFG_BSIZE64	(0x1 << 1) /* 64 byte burst sizeb state */
#define	ERI_SIOCFG_BSIZE128	(0x1 << 2) /* 128 byte burst sizeb state */
#define	ERI_SIOCFG_BMODE64	(0x1 << 3) /* Sbus 64 bit mode */
#define	ERI_SIOCFG_PARITY	(0x1 << 9) /* Sbus Parity enabled. */

/*
 * SEB State Register (RO)
 * Reflects the internal state of the arbitration between TX and RX
 * DMA Channels. Used for diagnostics only
 */
#define	ERI_SEB_ARBSTS	(0x2 << 0)	/* Arbiter state */
#define	ERI_SEB_RXWON	(1 << 2)	/* RX won the arbitration */

/*
 * Global Configuration Register (RW)
 * To configure parameters that define the DMA burst and internal arbitration.
 * TX/RX_DMA_LIMIT: No. of data transfers in 64-byte multiples
 *			0 - peririty changes at packet boundaries
 * default:	0x042
 */
#define	ERI_G_CONFIG_BURST_SIZE	(0x1 << 0)	/* 0:infinite/64-byte burst */
#define	ERI_G_CONFIG_TX_DMA_LIM	(0x1f << 1)	/* 5-1: TX_DMA_Limit */
#define	ERI_G_CONFIG_RX_DMA_LIM	(0x1f << 6)	/* 10-6: RX_DMA_Limit */

#define	ERI_G_CONFIG_BURST_64	0x0	/* max burst size 64 */
#define	ERI_G_CONFIG_BURST_INF	0x1	/* infinite burst for whole pkt len */

#define	ERI_G_CONFIG_TX_DMA_LIM_SHIFT	1
#define	ERI_G_CONFIG_RX_DMA_LIM_SHIFT	6

/*
 * Global Interrupt Status Register (R-AC)
 * size:	32 bits: 0-31
 * default:	0x00000000
 * This is the top level register used to communicate to the software events
 * that were detected by the hardware.
 * Top level bits 0-6 are automatically cleared to 0 when the Status Register
 * is read.
 * Second level interrupts reported by bits 13-18 are cleared at the source.
 * The value of the TX Completion Register is replicated in bits 19-31.
 */
#define	ERI_G_STATUS_TX_INT_ME	(1 << 0)
	/* 0 - set when a frame with INT_ME bit set is transferred to FIFO */
#define	ERI_G_STATUS_TX_ALL	(1 << 1)	/* 1 - TX desc. ring empty */
#define	ERI_G_STATUS_TX_DONE	(1 << 2)	/* 2 - from host to TX FIFO */
#define	ERI_G_STATUS_RES1	(1 << 3)	/* 3 - reserved */
#define	ERI_G_STATUS_RX_DONE	(1 << 4)	/* 4 - from RXFIFO to host */
#define	ERI_G_STATUS_RX_NO_BUF	(1 << 5)	/* 5 - no RX buff available */
#define	ERI_G_STATUS_RX_TAG_ERR	(1 << 6)	/* 6 - RX tag error */
#define	ERI_G_STATUS_PERR_INT	(1 << 7)	/* 7 - Parity Err sts reg */
#define	ERI_G_STATUS_RES2	(0x3f << 7)	/* 7-12 : reserved */
#define	ERI_G_STATUS_PCS_INT	(1 << 13)	/* 13 - PCS Interrupt */
#define	ERI_G_STATUS_TX_MAC_INT	(1 << 14)	/* 14 - TX MAC stat reg set */
#define	ERI_G_STATUS_RX_MAC_INT	(1 << 15)	/* 15 - RX MAC stat reg set */
#define	ERI_G_STATUS_MAC_CTRL_INT	(1 << 16) /* 16 - MAC control reg  */
#define	ERI_G_STATUS_MIF_INT	(1 << 17)	/* 17 - MIF status reg set */
#define	ERI_G_STATUS_BUS_ERR_INT	(1 << 18) /* 18 - BUS Err sts reg */
#define	ERI_G_STATUS_TX_COMPL	(0xfff80000)	/* 19-31: TX Completion reg */

#define	ERI_G_STATUS_INTR	(0xffffffff & ~(ERI_G_STATUS_TX_DONE |\
	ERI_G_STATUS_TX_ALL |\
	ERI_G_STATUS_MAC_CTRL_INT | ERI_G_STATUS_TX_COMPL))

#define	ERI_G_STATUS_TX_INT	(ERI_G_STATUS_TX_DONE | ERI_G_STATUS_TX_ALL)
#define	ERI_G_STATUS_RX_INT	(~ERI_G_STATUS_TX_COMPL & ~ERI_G_STATUS_TX_INT)

#define	ERI_G_STATUS_FATAL_ERR		(ERI_G_STATUS_RX_TAG_ERR | \
					ERI_G_STATUS_PERR_INT | \
					ERI_G_STATUS_BUS_ERR_INT)

#define	ERI_G_STATUS_NONFATAL_ERR	(ERI_G_STATUS_TX_MAC_INT | \
					ERI_G_STATUS_RX_MAC_INT | \
					ERI_G_STATUS_MAC_CTRL_INT)

#define	ERI_G_STATUS_TX_COMPL_SHIFT	19
#define	ERI_G_STATUS_TX_COMPL_MASK	0x1fff

/*
 * Global Interrupt Mask register (RW)
 * size:	32 bits
 * default:	0xFFFFFFFF
 * There is one-to-one correspondence between the bits in this register and
 * the Global Status register.
 * If a mask bit is 0, the corresponding event causes an interrupt.
 */


#define	ERI_G_MASK_TX_INT_ME	(1 << 0)
	/* 0 - set when a frame with INT_ME bit set is transferred to FIFO */
#define	ERI_G_MASK_TX_ALL	(1 << 1)	/* 1 - TX desc. ring empty */
#define	ERI_G_MASK_TX_DONE	(1 << 2)	/* 2 - from host to TX FIFO */
#define	ERI_G_MASK_RES1		(1 << 3)	/* 3 - reserved */
#define	ERI_G_MASK_RX_DONE	(1 << 4)	/* 4 - from RXFIFO to host */
#define	ERI_G_MASK_RX_NO_BUF	(1 << 5)	/* 5 - no RX bufer available */
#define	ERI_G_MASK_RX_TAG_ERR	(1 << 6)	/* 6 - RX tag error */
#define	ERI_G_MASK_RES2		(0x3f << 7)	/* 7-13 : reserved */
#define	ERI_G_MASK_PCS_INT	(1 << 13)	/* 13 - PCS Interrupt */
#define	ERI_G_MASK_TX_MAC_INT	(1 << 14)	/* 14 - TX MAC status reg set */
#define	ERI_G_MASK_RX_MAC_INT	(1 << 15)	/* 15 - RX MAC status reg set */
#define	ERI_G_MASK_MAC_CTRL_INT	(1 << 16)	/* 16 - MAC control reg set */
#define	ERI_G_MASK_MIF_INT	(1 << 17)	/* 17 - MIF status reg set */
#define	ERI_G_MASK_BUS_ERR_INT	(1 << 18)	/* 18 - BUS Error sts reg set */

#define	ERI_G_MASK_INTR		(~ERI_G_STATUS_INTR | ERI_G_MASK_PCS_INT)
#define	ERI_G_MASK_ALL		(0xffffffffu)


/*
 * Interrupt Ack Register (WO)
 * Its layout corresponds to the layout of the top level bits of the Interrupt
 * Status register.
 * Bit positions written high will be cleared, while bit positions written low
 * have no effect on the Interrupt Status Register.
 */

/*
 * Status Register Alias (RO)
 * This location presents the same view as the Interrupt Status Register, except
 * that reading from this location does not automatically clear any of the
 * register bits.
 */

/*
 * PCI Error Status Register (R-AC)
 * Other PCI bus errors : The specific error may be read from
 * the PCI Status Register in PCI Configuration space
 */
#define	ERI_G_STS_BADACK	(1 << 0)	/* no ACK64# during ABS64 */
#define	ERI_G_STS_DTRTO		(1 << 1)	/* Delayed trans timeout */
#define	ERI_G_STS_OTHERS	(1 << 2)

/*
 * PCI Error Mask Register (RW)
 * size: 	32 bits
 * default:	0xffffffff
 * Same layout as the PCI Error Status Register
 */
#define	ERI_G_PCI_ERROR_MASK	0x00

/*
 * BIF Configuration Register
 * default: 0x0
 * Used to configure specific system information for the BIF block to optimize.
 * Default values indicate no special knowledge is assumed by BIF.
 * M66EN is RO bit.
 * 66 MHz operation (RO) May be used by the driver to sense
 * whether ERI is operating in a 66MHz or 33 MHz PCI segment
 */
#define	ERI_G_BIFCFG_SLOWCLK	(1 << 0)	/* for parity error timing */
#define	ERI_G_BIFCFG_HOST_64	(1 << 1)	/* 64-bit host */
#define	ERI_G_BIFCFG_B64D_DIS	(1 << 2)	/* no 64-bit wide data */
#define	ERI_G_BIFCFG_M66EN	(1 << 3)

/*
 * BIF Diagnostic register (RW)
 * TBD
 */

/*
 * Global Software Reset Register - RW-AC
 * The lower 2bits are used to perform an individual Software Reset to the
 * TX or RX functions (when the corresponding bit is set), or
 * a Global Software Reset to the ERI (when both bits are set).
 * These bits become "self cleared" after the corresponding reset command
 * has been executed. After a reset, the software must poll this register
 * till both the bits are read as 0's.
 * The third bit (RSTOUT) is not self clearing and is used to activate
 * the RSTOUT# pin, when set. When clear, RSTOUT# follows the level of the
 * PCI reset input pin.
 */
#define	ERI_G_RESET_ETX	(1 << 0)	/* Reset ETX */
#define	ERI_G_RESET_ERX	(1 << 1)	/* Reset ERX */
#define	ERI_G_RESET_RSTOUT (1 << 2)	/* force the RSTOUT# pin active */
#define	ERI_G_CACHE_BIT	16
#define	ERI_G_CACHE_LINE_SIZE_16 16	/* cache line size of 64 bytes  */
#define	ERI_G_CACHE_LINE_SIZE_32 32	/* cache line size of 128 bytes  */
#define	ERI_G_CACHE_16 (ERI_G_CACHE_LINE_SIZE_16 << ERI_G_CACHE_BIT)
#define	ERI_G_CACHE_32 (ERI_G_CACHE_LINE_SIZE_32 << ERI_G_CACHE_BIT)

#define	ERI_G_RESET_GLOBAL (ERI_G_RESET_ETX | ERI_G_RESET_ERX)

/*
 * Transmit DMA Register set
 * tx_kick and tx_completion registers are set to 0 when ETX is reset.
 */

struct etx {
    uint32_t tx_kick;		/* 0x2000 RW Transmit Kick Register */
    uint32_t config;		/* 0x2004 RW ETX Configuration Register */
    uint32_t txring_lo;		/* 0x2008 RW Transmit Descriptor Base Low */
    uint32_t txring_hi;		/* 0x200C RW Transmit Descriptor Base Low */
    uint32_t reserved1;		/* 0x2010 */
    uint32_t txfifo_wr_ptr;	/* 0x2014 RW TxFIFO Write Pointer */
    uint32_t txfifo_sdwr_ptr;	/* 0x2018 RW TxFIFO Shadow Write Pointer */
    uint32_t txfifo_rd_ptr;	/* 0x201C RW TxFIFO Read Pointer */
    uint32_t txfifo_sdrd_ptr;	/* 0x2020 RW TxFIFO Shadow Read Pointer */
    uint32_t txfifo_pkt_cnt;	/* 0x2024 RO TxFIFO Packet Counter */
    uint32_t state_mach;	/* 0x2028 RO ETX State Machine Reg */
    uint32_t reserved2;		/* 0x202C */
    uint32_t txdata_ptr_lo;	/* 0x2030 RO ETX State Machine Register */
    uint32_t txdata_ptr_hi;	/* 0x2034 RO ETX State Machine Register */
    uint32_t reserved3[50];	/* 0x2038 - 0x20FC */

    uint32_t tx_completion;	/* 0x2100 RO ETX Completion Register */
    uint32_t txfifo_adrs;	/* 0x2104 RW ETX FIFO address */
    uint32_t txfifo_tag;	/* 0x2108 RO ETX FIFO tag */
    uint32_t txfifo_data_lo;	/* 0x210C RW ETX FIFO data low */
    uint32_t txfifo_data_hi_T1;	/* 0x2110 RW ETX FIFO data high T1 */
    uint32_t txfifo_data_hi_T0;	/* 0x2114 RW ETX FIFO data high T0 */
    uint32_t txfifo_size;	/* 0x2118 RO ETX FIFO size */

    uint32_t reserved4[964];	/* 0x211C - 0x3024 */

    uint32_t txdebug;		/* 0x3028 RW ETX Debug Register */
};


/*
 * TX Kick Register (RW)
 * size:	13-bits
 * default:	0x0
 * Written by the host CPU with the descriptor value that follows the last
 * valid Transmit descriptor.
 */

/*
 * TX Completion Register
 * size:	13-bits
 * default:	0x0
 * This register stores the descriptor value that follows the last descriptor
 * already processed by ERI.
 *
 */
#define	ETX_COMPLETION_MASK	0x1fff

/*
 * ETX Configuration Register
 * default: 0x118010
 * This register stores parameters that control the operation of the transmit
 * DMA channel.
 * If the desire is to buffer an entire standard Ethernet frame before its
 * transmission is enabled, the Tx-FIFO-Threshold field has to be programmed
 * to a value = > 0xC8. (CHECK). Default value is 0x460.
 * Matewos: Changed the above to 0x400. Getting FIFO Underflow in the
 * case if Giga bit speed.
 * Bit 21 is used to modify the functionality of the Tx_All interrupt.
 * If it is 0, Tx_All interrupt is generated after processing the last
 * transmit descriptor.
 * If it is 1, Tx_All interrupt is generated only after the entire
 * Transmit FIFO has been drained.
 */

#define	GET_CONFIG_TXDMA_EN	(1 << 0)	/* 0 - Enable Tx DMA */
#define	GET_CONFIG_TXRING_SZ	(0xf << 1)	/* 1-4:Tx desc ring size */
#define	GET_CONFIG_RESERVED	(0x1f << 5)	/* 5-9: Reserved */
#define	GET_CONFIG_TXFIFOTH	(0x7ff << 10)	/* 10-20 :TX FIFO Threshold */
/*
 * RIO specific value: TXFIFO threshold needs to be set to 1518/8.
 *			It was set to (0x4FF << 10) for GEM.
 *			set it back to 0x4ff.
 *			set it to 190 receive TXMAC underrun and hang
 *			try 0x100
 *			try 0x4ff
 *			try 0x100
 */
#define	ETX_ERI_THRESHOLD	0x100
#define	ETX_CONFIG_THRESHOLD	(ETX_ERI_THRESHOLD << 10)

#define	GET_CONFIG_PACED_MODE	(1 << 21)	/* 21 - TX_all_int mod */

#define	GET_CONFIG_THRESHOLD	(0x400 << 10)	/* For Ethernet Packets */
#define	GET_CONFIG_RINGSZ	(ERI_TMDMAX << 1) /* for 2048 descriptors */
/*
 * ETX TX ring size
 * This is a 4-bit value to determine the no. of descriptor entries in the
 * TX-ring. The number of entries can vary from 32 through 8192 in multiples
 * of 2.
 */
#define	ERI_TX_RINGSZ_SHIFT	1

#define	ETX_RINGSZ_32	0
#define	ETX_RINGSZ_64	1
#define	ETX_RINGSZ_128	2
#define	ETX_RINGSZ_256	3
#define	ETX_RINGSZ_512	4
#define	ETX_RINGSZ_1024	5
#define	ETX_RINGSZ_2048	6
#define	ETX_RINGSZ_4096	7
#define	ETX_RINGSZ_8192	8
/* values 9-15 are reserved. */

/*
 * Transmit Descriptor Base Low and High (RW)
 * The 53 most significant bits are used as the base address for the TX
 * descriptor ring. The 11 least significant bits are not stored and assumed
 * to be 0.
 * This register should be initialized to a 2KByte-aligned value after power-on
 * or Software Reset.
 */


/*
 * TX FIFO size (RO)
 * This 11-bit RO register indicates the size, in 64 byte multiples, of the
 * TX FIFO.
 * The value of this register is 0x90, indicating a 9Kbyte TX FIFO.
 */


/*
 * ERX Register Set
 */

struct erx {
    uint32_t config;		/* 0x4000 RW ERX Configuration Register */
    uint32_t rxring_lo;		/* 0x4004 RW Receive Descriptor Base low */
    uint32_t rxring_hi;		/* 0x4008 RW Receive Descriptor Base high */
    uint32_t rxfifo_wr_ptr;	/* 0x400C RW RxFIFO Write Pointer */
    uint32_t rxfifo_sdwr_ptr;	/* 0x4010 RW RxFIFO Shadow Write Pointer */
    uint32_t rxfifo_rd_ptr;	/* 0x4014 RW RxFIFO Read pointer */
    uint32_t rxfifo_pkt_cnt;	/* 0x4018 RO RxFIFO Packet Counter */
    uint32_t state_mach;	/* 0x401C RO ERX State Machine Register */
    uint32_t rx_pause_threshold; /* 0x4020 RW ERX Pause thresholds */
    uint32_t rxdata_ptr_lo;	/* 0x4024 RO ERX Data Pointer low */
    uint32_t rxdata_ptr_hi;	/* 0x4028 RO ERX Data Pointer high */
    uint32_t reserved1[53];	/* 0x402C - 0x40FC */

    uint32_t rx_kick;		/* 0x4100 RW ERX Kick Register */
    uint32_t rx_completion;	/* 0x4104 RO ERX Completion Register */
    uint32_t rx_blanking;	/* 0x4108 RO ERX Blanking Register */
    uint32_t rxfifo_adrs;	/* 0x410C RW ERX FIFO address */
    uint32_t rxfifo_tag;	/* 0x4110 RO ERX FIFO tag */
    uint32_t rxfifo_data_lo;	/* 0x4114 RW ERX FIFO data low */
    uint32_t rxfifo_data_hi_T0;	/* 0x4118 RW ERX FIFO data high T0 */
    uint32_t rxfifo_data_hi_T1;	/* 0x411C RW ERX FIFO data high T1 */
    uint32_t rxfifo_size;	/* 0x4120 RW ERX FIFO size */
};

/*
 * ERX Configuration Register - RW
 * This 27-bit register determines the ERX-specific parameters that control the
 * operation of the receive DMA channel.
 * Default : 0x1000010
 */

#define	GET_CONFIG_RXDMA_EN	(1 << 0)	/* 0 : Enable Rx DMA */
#define	ERI_RX_CONFIG_RXRING_SZ	(0xf << 1)	/* 1-4 : RX ring size */
#define	ERI_RX_CONFIG_BATDIS	(1 << 5)	/* Disable RX desc batching */
#define	ERI_RX_CONFIG_RES1	(0xf << 6)	/* 6-9 : reserverd */
#define	ERI_RX_CONFIG_FBOFFSET	(0x7 << 10)	/* 10-12 : 1st Byte Offset */
#define	ERI_RX_CONFIG_RX_CSSTART (0x7f << 13)	/* 13-19:cksum start offset */
#define	ERI_RX_CONFIG_RES2	(0xf << 20)	/* 20-23 : reserve */
#define	ERI_RX_CONFIG_RXFIFOTH	(0x7 << 24)	/* 24-26:RX DMA threshold */

#define	ERI_RX_RINGSZ_SHIFT	1
#define	ERI_RX_CONFIG_FBO_SHIFT	10
#define	ERI_RX_CONFIG_RX_CSSTART_SHIFT	13
#define	ERI_RX_CONFIG_RXFIFOTH_SHIFT	24

#define	ERX_RINGSZ_32	0
#define	ERX_RINGSZ_64	1
#define	ERX_RINGSZ_128	2
#define	ERX_RINGSZ_256	3
#define	ERX_RINGSZ_512	4
#define	ERX_RINGSZ_1024	5
#define	ERX_RINGSZ_2048	6
#define	ERX_RINGSZ_4096	7
#define	ERX_RINGSZ_8192	8
/* values 9-15 are reserved. */


#define	ERI_RX_FIFOTH_64	0
#define	ERI_RX_FIFOTH_128	1
#define	ERI_RX_FIFOTH_256	2
#define	ERI_RX_FIFOTH_512	3
#define	ERI_RX_FIFOTH_1024	4
#define	ERI_RX_FIFOTH_2048	5
/* 6 & 7 are reserved values */

/*
 * Receive Descriptor Base Low and High (RW)
 * The 53 most significant bits are used as the base address for the RX
 * descriptor ring. The 11 least significant bits are not stored and assumed
 * to be 0.
 * This register should be initialized to a 2KByte-aligned value after power-on
 * or Software Reset.
 */


/*
 * Pause Thresholds Register (RW)
 * default: 0x000f8
 * Two PAUSE thresholds are used to define when PAUSE flow control frames are
 * emitted by ERI. The granularity of these thresholds is in 64 byte increments.
 * XOFF PAUSE frames use the pause_time value pre-programmed in the
 * Send PAUSE MAC Register.
 * XON PAUSE frames use a pause_time of 0.
 */

#define	ERI_RX_PTH_OFFTH	(0x1ff << 0)
			/*
			 * 0-8: XOFF PAUSE emitted when RX FIFO
			 * occupancy rises above this value (times 64 bytes)
			 */
#define	ERI_RX_PTH_RES	(0x7 << 9)	/* 9-11: reserved */
#define	ERI_RX_PTH_ONTH	(0x1ff << 12)
			/*
			 * 12-20: XON PAUSE emitted when RX FIFO
			 * occupancy falls below this value (times 64 bytes)
			 */

#define	ERI_RX_PTH_ONTH_SHIFT	12

/*
 * ------------------------------------------------------------------------
 * RX Kick Register (RW)
 * This is a 13-bit register written by the host CPU.
 * The last valid RX descriptor is the one right before the value of the
 * register.
 * Initially set to 0 on reset.
 * RX descriptors must be posted in multiples of 4.
 * The first descriptor should be cache-line aligned for best performance.
 * -------------------------------------------------------------------------
 */

/*
 * RX Completion Register (RO)
 * This 13-bit register indicates which descriptors are already used by ERI
 * for receive frames.
 * All descriptors upto but excluding the register value are ready to be
 * processed by the host.
 */

/*
 * RX Blanking Register (RW)
 * Defines the values used for receive interrupt blanking.
 * For INTR_TIME field, every count is 2048 PCI clock time. For 66 Mhz, each
 * count is about 16 us.
 */
#define	ERI_RX_BLNK_INTR_PACKETS	(0x1ff << 0)
			/*
			 * 0-8:no.of pkts to be recvd since the last RX_DONE
			 * interrupt, before a new interrupt
			 */
#define	ERI_RX_BLNK_RESERVED	(0x7 << 9)	/* 9-11 : reserved */
#define	ERI_RX_BLNK_INTR_TIME	(0xff << 12)
			/*
			 * 12-19 : no. of clocks to be counted since the last
			 * RX_DONE interrupt, before a new interrupt
			 */

#define	ERI_RX_BLNK_INTR_TIME_SHIFT	12

/*
 * RX FIFO Size (RO)
 * This 11-bit RO register indicates the size, in 64-bit multiples, of the
 * RX FIFO. Software should use it to properly configure the PAUSE thresholds.
 * The value read is 0x140, indicating a 20kbyte RX FIFO.
 */


/*
 * Declarations and definitions specific to the ERI MAC functional block.
 *
 * The ERI MAC block will provide the MAC functons for 10 or 100 Mbps or
 * 1 Gbps CSMA/CD-protocol-based or full-duplex interface.
 */

/*
 * ERI MAC Register Set.
 * ERI MAC addresses map on a word boundry. So all registers are
 * declared for a size of 32 bits. Registers that use fewer than 32
 * bits will return 0 in the bits not used.
 * TBD: Define the constant values which should be used for initializing
 * these registers.
 */
struct	bmac {
	uint32_t	txrst;	/* 0x6000 tx software reset (RW) */
	uint32_t	rxrst;	/* 0x6004 rx software reset Reg (RW) */
	uint32_t	spcmd;	/* 0x6008 Send Pause Command Reg (RW) */
	uint32_t	res1;	/* 0x600C reserved */
	uint32_t	txsts;	/* 0x6010 tx MAC status reg (R-AC) */
	uint32_t	rxsts;	/* 0x6014 rx MAC status reg (R-AC) */
	uint32_t	macctl_sts; /* 0x6018 MAC Control Stat Reg (R-AC) */
	uint32_t	res2;	/* 0x601C reserved */
	uint32_t	txmask;	/* 0x6020 tx MAC Mask Register (RW) */
	uint32_t	rxmask;	/* 0x6024 rx MAC Mask register (RW) */
	uint32_t	macctl_mask; /* 0x6028 MAC Control Mask Reg (RW) */
	uint32_t	res3;	/* 0x602C reserved */
	uint32_t	txcfg;	/* 0x6030 tx config reg [8-0] (RW) */
	uint32_t	rxcfg;	/* 0x6034 rx config reg [7-0] (RW) */
	uint32_t	macctl_cfg; /* 0x6038 MAC Control Config Reg (RW) */
	uint32_t	xifc;	/* 0x603C XIF Config. reg [7-0] (RW) */
	uint32_t	ipg0;	/* 0x6040 Inter pkt Gap 0 [7-0] (RW) */
	uint32_t	ipg1;	/* 0x6044 Inter pkt Gap 1 [7-0] (RW) */
	uint32_t	ipg2;	/* 0x6048 Inter pkt Gap 2 [7-0] (RW) */
	uint32_t	slot;	/* 0x604C slot time reg [7-0] (RW) */
	uint32_t	macmin;	/* 0x6050 MAC min frame sze [9-0](RW) */
	uint32_t	macmax;	/* 0x6054 MAC max pkt sze [14-0] (RW) */
	uint32_t	palen;	/* 0x6058 preamble len reg [9-0] (RW) */
	uint32_t	jam;	/* 0x605C jam size reg [3-0] (RW) */
	uint32_t	alimit;	/* 0x6060 attempt limit reg [7-0](RW) */
	uint32_t	macctl_type; /* 0x6064 MAC Control Type Reg (RW) */
	uint32_t	res4[6]; /* reserved 0x6068 - 0x607C	*/
	uint32_t	madd0;	/* 0x6080 Norm MAC adrs 0 [15-0] (RW) */
	uint32_t	madd1;	/* 0x6084 Norm MAC adrs 1 [31-16](RW) */
	uint32_t	madd2;	/* 0x6088 Norm MAC adrs 2 [47-32](RW) */
	uint32_t	madd3;	/* 0x608C Alt. MAC adrs 0 [15-0](RW) */
	uint32_t	madd4;	/* 0x6090 Alt. MAC adrs 1 [31-16](RW) */
	uint32_t	madd5;	/* 0x6094 Alt. MAC adrs 2 [47-32](RW) */
	uint32_t	madd6;	/* 0x6098 Control MAC adrs 0 [15-0](RW) */
	uint32_t	madd7;	/* 0x609C Control MAC adrs 1 [31-16](RW) */
	uint32_t	madd8;	/* 0x60A0 Control MAC adrs 2 [47-32](RW) */
	uint32_t	afr0;	/* 0x60A4 addr filt reg 0_0 [15-0](RW) */
	uint32_t	afr1;	/* 0x60A8 addr filt reg 0_1 [15-0](RW) */
	uint32_t	afr2;	/* 0x60AC addr filt reg 0_2 [15-0](RW) */
	uint32_t	afmr1_2; /* 0x60B0 addr filt msk reg 1,2 [8-0](RW) */
	uint32_t	afmr0;	/* 0x60B4 addr filt msk reg 0 [15-0](RW) */
	uint32_t	res5[2]; /* 0x60B8 - 0x60BC Reserved	*/
	uint32_t	hash0;	/* 0x60C0 h-table 0 [15-0] (RW) */
	uint32_t	hash1;	/* 0x60C4 h-table 1 [31-16] (RW) */
	uint32_t	hash2;	/* 0x60C8 h-table 2 [47-32] (RW) */
	uint32_t	hash3;	/* 0x60CC h-table 3 [63-48] (RW) */
	uint32_t	hash4;	/* 0x60D0 h-table  4 [79-64] (RW) */
	uint32_t	hash5;	/* 0x60D4 h-table  5 [95-80] (RW) */
	uint32_t	hash6;	/* 0x60D8 h-table  6 [111-96] (RW) */
	uint32_t	hash7;	/* 0x60DC h-table  7 [127-112] (RW) */
	uint32_t	hash8;	/* 0x60E0 h-table  8 [143-128] (RW) */
	uint32_t	hash9;	/* 0x60E4 h-table  9 [159-144] (RW) */
	uint32_t	hash10;	/* 0x60E8 h-table 10 [175-160] (RW) */
	uint32_t	hash11;	/* 0x60EC h-table 11 [191-176] (RW) */
	uint32_t	hash12;	/* 0x60F0 h-table 12 [207-192] (RW) */
	uint32_t	hash13;	/* 0x60F4 h-table 13 [223-208] (RW) */
	uint32_t	hash14;	/* 0x60F8 h-table 14 [239-224] (RW) */
	uint32_t	hash15;	/* 0x60FC h-table 15 [255-240] (RW) */
	uint32_t	nccnt;	/* 0x6100 normal coll cnt [15-0] (RW) */
	uint32_t	fccnt;	/* 0x6104 1st succes coll [15-0] (RW) */
	uint32_t	excnt;	/* 0x6108 excess coll cnt[15-0] (RW) */
	uint32_t	ltcnt;	/* 0x610C late coll cnt [15-0] (RW) */
	uint32_t	dcnt;	/* 0x6110 defer timer cnt [15-0] (RW) */
	uint32_t	pattempts; /* 0x6114 peak attempt reg [7-0] (RW) */
	uint32_t	frcnt;	/* 0x6118 rcv frame cnt [15-0] (RW) */
	uint32_t	lecnt;	/* 0x611C rx len err cnt [15-0] (RW) */
	uint32_t	aecnt;	/* 0x6120 rx align err cnt[15-0] (RW) */
	uint32_t	fecnt;	/* 0x6124 rcv crc err cnt [15-0] (RW) */
	uint32_t	rxcv;	/* 0x6128 rx code viol reg [15-0](RW) */
	uint32_t	res6;	/* 0x612C Reserved */
	uint32_t	rseed;	/* 0x6130 random num seed [9-0] (RW) */
	uint32_t	macsm;	/* 0x6134 MAC state mach reg [7-0](R) */
};

#define	BMAC_OVERFLOW_STATE	0x03800000

/*
 * Constants used for initializing the MAC registers
 */

#define	BMAC_SEND_PAUSE_CMD	0x1BF0
#define	BMAC_IPG0		0x00
#define	BMAC_IPG1		0x08
#define	BMAC_IPG2		0x04
#define	BMAC_SLOT_TIME		0x40
#define	BMAC_EXT_SLOT_TIME	0x200
#define	BMAC_MIN_FRAME_SIZE	0x40
#define	BMAC_MAX_FRAME_SIZE	(ETHERMTU + 18 + 4)	/* enet + vlan */

/*
 *	Hardware bug: set MAC_FRAME_SIZE to 0x7fff to
 *	get around the problem of tag errors
 */
#ifdef	ERI_RX_TAG_ERROR_WORKAROUND
#define	BMAC_MAX_FRAME_SIZE_TAG	0x7fff
#endif

#define	BMAC_MAX_BURST		(0x2000 << 16)
#define	BMAC_PREAMBLE_SIZE	0x07
#define	BMAC_JAM_SIZE		0x04
#define	BMAC_ATTEMPT_LIMIT	0x10
#define	BMAC_CONTROL_TYPE	0x8808
#define	BMAC_ADDRESS_3		0x0000
#define	BMAC_ADDRESS_4		0x0000
#define	BMAC_ADDRESS_5		0x0000
#define	BMAC_ADDRESS_6		0x0001
#define	BMAC_ADDRESS_7		0xC200
#define	BMAC_ADDRESS_8		0x0180
#define	BMAC_AF_0		0x0000
#define	BMAC_AF_1		0x0000
#define	BMAC_AF_2		0x0000
#define	BMAC_AF21_MASK		0x00
#define	BMAC_AF0_MASK		0x0000
#define	BMAC_COUNTER		0x0000	/* for all MAC Counters */

/*
 * ERI MAC Register Bit Masks.
 */

/*
 * TX_MAC Software Reset Command Register (RW)
 * This bit is set to 1 when a PIO write is done. This bit becomes self-cleared.
 * after the command has been executed.
 */

#define	BMAC_TX_RESET		(1 << 0)	/* TX_MAC Reset Command */


/*
 * RX_MAC Software Reset Command Register (RW)
 * This bit is set to 1 when a PIO write is done. This bit becomes self-cleared.
 * after the command has been executed.
 */

#define	BMAC_RX_RESET		(1 << 0)	/* RX_MAC Reset Command */

/*
 * Send Pause Command Register (RW)
 * This command register executes a Pause Flow Control frame transmission.
 * Pause_Time_Sent field indicates to the MAC the value of the pause_time
 * operand that should be sent on the network using either the Send_Pause
 * Command bit or the flow control handshake on the RxDMA < - > MAC interface.
 * The pause-time is interpreted in terms of Slot times.
 */

/*
 * 0-15: value of pause_time operand
 * in terms of slot time
 */

#define	ERI_MCTLSP_TIME	(0xffff << 0)
#define	ERI_MCTLSP_SEND	(1 << 16)	/* send Pause flow control frame */


/*
 * TX_MAC Status Register (R-AC)
 */

#define	BMAC_TXSTS_XMIT_DONE	(1 << 0)	/* Frame transmitted */
#define	BMAC_TXSTS_TX_URUN	(1 << 1)	/* TX MAC Underrun */
#define	BMAC_TXSTS_MAXPKT_ERR	(1 << 2)	/* packet len exceeds max len */
#define	BMAC_TXSTS_NCC_EXP	(1 << 3)	/* Normal Collision cnt exp */
#define	BMAC_TXSTS_ECC_EXP	(1 << 4)	/* Excess Collision cnt exp */
#define	BMAC_TXSTS_LCC_EXP	(1 << 5)	/* Late Collision cnt exp */
#define	BMAC_TXSTS_FCC_EXP	(1 << 6)	/* First Collision cnt exp */
#define	BMAC_TXSTS_DEFER_EXP	(1 << 7)	/* Defer Timer exp */
#define	BMAC_TXSTS_PEAK_EXP	(1 << 8)	/* Peak attempts cnt exp */

/*
 * TX_MAC Mask Register (RW)
 */

#define	BMAC_TXMASK_XMIT_DONE	(1 << 0)	/* Frame transmitted */
#define	BMAC_TXMASK_TX_URUN	(1 << 1)	/* TX MAC Underrun */
#define	BMAC_TXMASK_MAXPKT_ERR	(1 << 2)	/* packet len exceeds max len */
#define	BMAC_TXMASK_NCC_EXP	(1 << 3)	/* Normal Collision cnt exp */
#define	BMAC_TXMASK_ECC_EXP	(1 << 4)	/* Excess Collision cnt exp */
#define	BMAC_TXMASK_LCC_EXP	(1 << 5)	/* Late Collision cnt exp */
#define	BMAC_TXMASK_FCC_EXP	(1 << 6)	/* First Collision cnt exp */
#define	BMAC_TXMASK_DEFER_EXP	(1 << 7)	/* Defer Timer exp */
#define	BMAC_TXMASK_PEAK_EXP	(1 << 8)	/* Peak attempts cnt exp */
/* Matewos added defer counter */
#define	BMAC_TXINTR_MASK	(BMAC_TXMASK_XMIT_DONE | BMAC_TXMASK_DEFER_EXP)

/*
 * RX_MAC Status Register (R-AC)
 */
#define	BMAC_RXSTS_RX_DONE	(1 << 0)	/* Frame Received */
#define	BMAC_RXSTS_RX_OVF	(1 << 1)	/* RX MAC data path overflow */
#define	BMAC_RXSTS_FRMCNT_EXP	(1 << 2)	/* RX Frame counter exp */
#define	BMAC_RXSTS_ALE_EXP	(1 << 3)	/* RX Alignment error cnt exp */
#define	BMAC_RXSTS_CRC_EXP	(1 << 4)	/* RX CRC error cnt exp */
#define	BMAC_RXSTS_LEN_EXP	(1 << 5)	/* RX Length error cnt exp */
#define	BMAC_RXSTS_CVI_EXP	(1 << 6)    /* RX Code violate err cnt exp */

/*
 * RX_MAC Mask Register (R-AC)
 */
#define	BMAC_RXMASK_RX_DONE	(1 << 0)	/* Frame Received */
#define	BMAC_RXMASK_RX_OVF	(1 << 1)	/* RX MAC data path overflow */
#define	BMAC_RXMASK_FRMCNT_EXP	(1 << 2)	/* RX Frame counter exp */
#define	BMAC_RXMASK_ALE_EXP	(1 << 3)	/* RX Alignment error cnt exp */
#define	BMAC_RXMASK_CRC_EXP	(1 << 4)	/* RX CRC error cnt exp */
#define	BMAC_RXMASK_LEN_EXP	(1 << 5)	/* RX Length error cnt exp */
#define	BMAC_RXMASK_CVI_EXP	(1 << 6)    /* RX Code violate err cnt exp */

#define	BMAC_RXINTR_MASK	(BMAC_RXMASK_RX_DONE | BMAC_RXMASK_FRMCNT_EXP)

/*
 * MAC Control Status Register (R-AC)
 */
#define	ERI_MCTLSTS_PAUSE_RCVD	(1 << 0)	/* PAUSE received */
#define	ERI_MCTLSTS_PAUSE_STATE	(1 << 1)	/* transition to PAUSE state */
#define	ERI_MCTLSTS_NONPAUSE	(1 << 2)	/* change to non-PAUSE state */
#define	ERI_MCTLSTS_RESERVED	(0x1fff << 3)	/* 3-15: reserved */
#define	ERI_MCTLSTS_PAUSE_TIME	(0xffff0000)	/* 16-31: Pause time recvd */

#define	ERI_MCTLSTS_PAUSE_TIME_SHIFT	16

/*
 * MAC Control Mask Register (RW)
 * pause time is in slot-time units.
 */
#define	ERI_MCTLMASK_PAUSE_RCVD	(1 << 0)	/* PAUSE received */
#define	ERI_MCTLMASK_PAUSE_STATE (1 << 1)	/* transition to PAUSE state */
#define	ERI_MCTLMASK_NONPAUSE	(1 << 2)	/* change to non-PAUSE state */
#define	ERI_MCTLMASK_RESERVED	(0x1fff << 3)	/* 3-15: reserved */
#define	ERI_MCTLMASK_PAUSE_TIME	(0xffff << 16)	/* 16-31: Pause time recvd */

#define	ERI_MACCTL_INTR_MASK	0x00000000

/*
 * XIF Configuration Register
 * This register determines the parameters that control the operation of the
 * transceiver interface.
 * The Disable-echo bit should be 0 for full-duplex mode.
 * Default: 0x00
 */

#define	BMAC_XIFC_TX_MII_OE	(1 << 0)	/* Enable XIF output drivers */
#define	BMAC_XIFC_MIILPBK	(1 << 1)	/* Enable MII Loopback mode */
#define	BMAC_XIFC_DIS_ECHO	(1 << 2)	/* Disable echo */
#define	BMAC_XIFC_MII_MODE	(1 << 3)	/* Selects GMII/MII mode */
#define	BMAC_XIFC_MIIBUF_OE	(1 << 4)	/* Enable MII Recv Buffers */
#define	BMAC_XIFC_LINK_LED	(1 << 5)	/* force LINKLED# active */
#define	BMAC_XIFC_FDPLX_LED	(1 << 6)	/* force FDPLXLED# active */

/*
 * TX_MAC Configuration Register
 * Ignore_Carrier_Sense should be set to 1 for full-duplex operation and
 * cleared to 0 for half-duplex operation..
 * Ignore_collisions should be set to 1 for full-duplex operation and cleared
 * to 0 for half-duplex operation..
 * To Ensure proper operation of the TX_MAC, the TX_MAC_Enable bit must always
 * be cleared to 0 and a delay imposed before a PIO write to any of the other
 * bits in the TX_MAC Configuration register or any of the MAC parameter
 * registers is done.
 * The amount of delay required depends on the time required to transmit a max.
 * size frame.
 * Default: TBD
 */

#define	BMACTXRSTDELAY		(125)		/* 125 us wait period */
/* CHECK */

#define	BMAC_TXCFG_ENAB		(1 << 0)	/* tx enable */
#define	BMAC_TXCFG_IGNCS	(1 << 1)	/* Ignore carrier sense */
#define	BMAC_TXCFG_IGCOLL	(1 << 2)	/* Ignore collisions */
#define	BMAC_TXCFG_ENIPG0	(1 << 3)	/* Extend Rx-to-Tx IPG */
#define	BMAC_TXCFG_NGU		(1 << 4)	/* Never Give Up */
#define	BMAC_TXCFG_NGU_LIMIT	(1 << 5)	/* Never Give Up limit */
#define	BMAC_TXCFG_NBKOFF	(1 << 6)	/* No Backoff */
#define	BMAC_TXCFG_SLOWDOWN	(1 << 7)	/* Slow down */
#define	BMAC_TXCFG_NFCS		(1 << 8)	/* no FCS will be generated */
#define	BMAC_TXCFG_CARR_EXT	(1 << 9)
			/*
			 * Enable TX Carrier Extension Carrier Extension is
			 * required for half-duplex operation at Gbps
			 */

#define	BMAC_TXCFG_FDX	(BMAC_TXCFG_IGNCS | BMAC_TXCFG_IGCOLL)

/*
 * RX_MAC Configuration Register
 * A delay of 3.2 ms should be allowed after clearing Rx_MAC_Enable or
 * Hash_Filter_enable or Address_Filter_Enable bits.
 * Default: TBD
 */
/* CHECK 3ms or us */
/* GEM specification: 3.2msec (3200 usec) */

#define	BMACRXRSTDELAY		(3200)		/* 3.2 ms wait period */

#define	BMAC_RXCFG_ENAB		(1 << 0)	/* rx enable */
#define	BMAC_RXCFG_STRIP_PAD	(1 << 1)	/* rx strip pad bytes */
#define	BMAC_RXCFG_STRIP_CRC	(1 << 2)	/* rx enable CRC stripping */
#define	BMAC_RXCFG_PROMIS	(1 << 3)	/* rx enable promiscous */
#define	BMAC_RXCFG_GRPROM	(1 << 4)	/* rx promiscuous group mode */
#define	BMAC_RXCFG_HASH		(1 << 5)	/* rx enable hash filter */
#define	BMAC_RXCFG_ADDR		(1 << 6)	/* rx enable address filter */
#define	BMAC_RXCFG_ERR		(1 << 7)	/* rx disable error checking */
#define	BMAC_RXCFG_CARR_EXT	(1 << 8)
			/*
			 * Enable RX Carrier Extension.
			 * Enables the reception of packet bursts
			 * generated by Carrier Extension with
			 * packet bursting senders
			 */

/*
 * MAC Control Configuration Register (RW)
 * Default: 0x00
 */

#define	ERI_MCTLCFG_TXPAUSE	(1 << 0)	/* Send_PAUSE Enable */
#define	ERI_MCTLCFG_RXPAUSE	(1 << 1)	/* Receive_PAUSE Enable */
#define	ERI_MCTLCFG_PASSPAUSE	(1 << 2)	/* Pass PAUSE up */

/*
 * MAC Control Type Register (RW)
 * This 16-bit register specifies the "type" field for the MAC Control frame.
 * Default: 0x8808
 */


/*
 * MAC Address Registers 0, 1, 2
 * Station's Normal peririty MAC address which must be a unicast address.
 * 0 - [15:0], 1 - [31:16], 2 - [47:32]
 */

/*
 * MAC Address Registers 3, 4, 5
 * Station's Alternate MAC address which may be a unicast or multicast address.
 * 3 - [15:0], 4 - [31:16], 5 - [47:32]
 */

/*
 * MAC Address Registers 6, 7, 8
 * Station's Control MAC address which must be the reserved multicast
 * address for MAC Control frames.
 * 6 - [15:0], 7 - [31:16], 8 - [47:32]
 */

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

struct mif {
	uint32_t mif_bbclk;	/* 0x6200 (RW) MIF Bit Bang Clock */
	uint32_t mif_bbdata;	/* 0x6204 (RW) MIF Bit Bang Data */
	uint32_t mif_bbopenb;	/* 0x6208 (RW) MIF Bit Bang Output Enable */
	uint32_t mif_frame;	/* 0x620C (RW) MIF Frame - ctl and data */
	uint32_t mif_cfg;	/* 0x6210 (RW) MIF Configuration */
	uint32_t mif_imask;	/* 0x6214 (RW) MIF Interrupt mask */
	uint32_t mif_bsts;	/* 0x6218 (R-AC) MIF Basic/Status register */
	uint32_t mif_fsm;	/* 0x621C (RO) MIF State machine register */
};

/*
 * mif_bbclk - Bit Bang Clock register
 */
#define	ERI_MIF_BBCLK	(1 << 0);	/* Bit Babg Clock */

#define	ERI_BBCLK_LOW 0
#define	ERI_BBCLK_HIGH 1

/* mif_bbdata - bit Bang Data register */
#define	ERI_MIF_BBDATA	(1 << 0);	/* Bit Bang Data */

/* mif_bbopenb - Bit Bang oOutput Enable register */
#define	ERI_MIF_BBOPENB	(1 << 0);	/* Bit Bang output Enable */

/*
 * Management Frame Structure:
 * <IDLE> <ST><OP><PHYAD><REGAD><TA>	 <DATA>		   <IDLE>
 * READ:  <01><10><AAAAA><RRRRR><Z0><DDDDDDDDDDDDDDDD>
 * WRITE: <01><01><AAAAA><RRRRR><10><DDDDDDDDDDDDDDDD>
 */

/*
 * mif_frame - MIF control and data register
 */
#define	ERI_MIF_FRDATA	(0xffff << 0)	/* 0-15 : data bits */
#define	ERI_MIF_FRTA0	(0x1 << 16)	/* 16 : TA bit, 1 for completion */
#define	ERI_MIF_FRTA1	(0x1 << 17)	/* 16-17 : TA bits */
#define	ERI_MIF_FRREGAD	(0x1f << 18)	/* 18-22 : register address bits */
#define	ERI_MIF_FRPHYAD	(0x1f << 23)	/* 23-27 : PHY ad, should be 0 */
#define	ERI_MIF_FROP	(0x3 << 28)	/* 28-29 : Operation - Write/Read */
#define	ERI_MIF_FRST	(0xc0000000)	/* 30-31 : START bits */

#define	ERI_MIF_FRREGAD_SHIFT	18
#define	ERI_MIF_FRPHYAD_SHIFT	23
#define	ERI_MIF_FRREAD		0x60020000
#define	ERI_MIF_FRWRITE		0x50020000

/*
 * maximum delay for MIF Register Read/Write operation
 */
#define	ERI_MAX_MIF_DELAY	(100)

/*
 * maximum delay for Transceiver Reset
 */
#define	ERI_PHYRST_MAXDELAY	(500)
#define	ERI_PCS_PHYRST_MAXDELAY	(500)

/*
 * mif_cfg - MIF Configuration Register
 */
#define	ERI_MIF_CFGPS	(1 << 0)	/* PHY Select */
#define	ERI_MIF_CFGPE	(1 << 1)	/* Poll Enable */
#define	ERI_MIF_CFGBB	(1 << 2)	/* Bit Bang Enable */
#define	ERI_MIF_CFGPR	(0x1f << 3)	/* Poll Register address */
#define	ERI_MIF_CFGM0	(1 << 8)	/* MDIO_0 Data / MDIO_0 attached */
#define	ERI_MIF_CFGM1	(1 << 9)	/* MDIO_1 Data / MDIO_1 attached */
#define	ERI_MIF_CFGPD	(0x1f << 10)	/* Poll Device PHY address */

#define	ERI_MIF_CFGPR_SHIFT	3
#define	ERI_MIF_CFGPD_SHIFT	10
#define	ERI_MIF_POLL_DELAY	200

/*
 * MDIO_0 corresponds to the On Board Transceiver.
 * MDIO_1 corresponds to the External Transceiver.
 * The PHYAD for both is 0.
 */
#define	ERI_INTERNAL_PHYAD	1	/* PHY address for int. transceiver */
#define	ERI_EXTERNAL_PHYAD	0	/* PHY address for ext. transceiver */
#define	ERI_NOXCVR_PHYAD	99	/* PHY address for no   transceiver */


/* mif_imask - MIF Interrupt Mask Register */
/*
 * This register is bit-to-bit same as Basic/Status Register
 */
#define	ERI_MIF_INTMASK	(0xffff << 0)	/* 0-15 : Interrupt mask */

/* mif_bassts - MIF Basic - Status register */
/*
 * The Basic portion of this register indicates the last value of the register
 * read indicated in the POLL REG field of the Configuration Register.
 * The Status portion indicates bit(s) that have changed.
 * The MIF Mask register is corresponding to this register in terms of the
 * bit(s) that need to be masked for generating interrupt on the MIF Interrupt
 * Bit of the Global Status Rgister.
 */

#define	ERI_MIF_STATUS	(0xffff << 0)	/* 0-15 : Status */
#define	ERI_MIF_BASIC	(0xffff << 16)	/* 16-31 : Basic register */

/* mif_fsm - MIF State Machine register */

#define	ERI_MIF_FSM	(0x3ff << 0)  /* 0-9 : MIF state */

/*
 * ERI PCS/Serial-Link
 */
struct pcslink {
	uint32_t pcs_ctl;	/* 0x9000 (RW) PCS MII Control Reg */
	uint32_t pcs_sts;	/* 0x9004 (RO) PCS MII Status Register */
	uint32_t pcs_anar;	/* 0x9008 (RW) PCS MII Avertisement Reg */
	uint32_t pcs_anlpar;    /* 0x900C (RW) PCS MII LP Ability Reg */
	uint32_t pcs_cfg;	/* 0x9010 (RW) PCS Configuration Register */
	uint32_t pcs_smr;	/* 0x9014 (RW) PCS State Machine Reg */
	uint32_t pcs_intsts;    /* 0x9018 (R-AC) PCS Interrupt Status Reg */
	uint32_t res1[13];	/* 0x901C - 0x904C Reserved */
	uint32_t pcs_dmode;	/* 0x9050 (RW) Datapath mode register */
	uint32_t slink_ctl;	/* 0x9054 (RW) Serial Link Control register */
	uint32_t pcs_opsel;	/* 0x9058 (RW) Shared Output Select register */
	uint32_t slink_sts;	/* 0x905C (RO) Serial Link Status register */
};

/*
 *  PCS MII	 Basic Mode Control Register
 * Auto-Negotiation should always be used for 802.3z 8B/10B
 * link configuration. May be cleared for diagnostic purposes, or
 * as a workaround for possible early product interoperability problems.
 */

#define	PCS_BMCR_RESET	(1 << 15)	/* Resets the PCS when set */
#define	PCS_BMCR_LPBK	(1 << 14)	/* Loopback of the 10-bit i/f */
#define	PCS_BMCR_1000M	(1 << 13)	/* Speed selection, always 0 */
#define	PCS_BMCR_ANE	(1 << 12)	/* Auto Negotiation Enabled when set */
#define	PCS_BMCR_PWRDN	(1 << 11)	/* Power down, always 0 */
#define	PCS_BMCR_ISOLATE (1 << 10)	/* Isolate PHY from MII, always 0 */
#define	PCS_BMCR_RAN	(1 << 9)	/* Set to Restart Auto Negotiation */
#define	PCS_BMCR_FDX	(1 << 8)	/* Full Duplex, always 0 */
#define	PCS_BMCR_COLTST	(1 << 7)	/* Collision Test */
#define	PCS_BMCR_RES1	(0x7f << 0)	/* 0-6 Reserved */

#define	PCS_AUTONEG_DISABLE	0

/*
 * ------------------------------------------------------------------------
 * PCS MII	 Basic Mode Status Register
 * -------------------------------------------------------------------------
 */


#define	PCS_BMSR_RES2	(0x1f << 11)	/* 11-15 reserved, always 0 */
#define	PCS_BMSR_GBFDX	(1 << 10)	/* PCS able to perform GBit FDX */
#define	PCS_BMSR_GBHDX	(1 << 9)	/* PCS able to perform Gbit HDX */
#define	PCS_BMSR_RES1	(0x7 << 6)	/* 6-8 reserved */
#define	PCS_BMSR_ANC	(1 << 5)	/* Auto Negotiation Completed */
#define	PCS_BMSR_REMFLT	(1 << 4)	/* Remote Fault detected */
#define	PCS_BMSR_ACFG	(1 << 3)	/* Able to do Auto Link Negotiation,1 */
#define	PCS_BMSR_LNKSTS	(1 << 2)	/* Link Status */
#define	PCS_BMSR_JABDET	(1 << 1)	/* Jabber Condition Detected, 0 */
#define	PCS_BMSR_EXTCAP	(1 << 0)	/* Extended Register Capability, 0 */

#define	PCS_CAPABILITY_MASK (PCS_BMSR_GBFDX | PCS_BMSR_GBHDX)


/*
 * ------------------------------------------------------------------------
 * PCS MII	Auto-Negotiation Advertisement Register (nway1Reg)
 * This register will hold the different modes of operation to be advertised to
 * the far-end PHY.
 * -------------------------------------------------------------------------
 */

#define	PCS_ANAR_NP	(1 << 15)	/* Next Page bit, RO, always 0 */
#define	PCS_ANAR_ACK	(1 << 14)	/* Acks reception of Link Partner */
					/* Capability word  */
#define	PCS_ANAR_RF	(0x2 << 12)	/* Advertise Remote Fault det. cap. */
#define	PCS_ANAR_RES1	(0x7 << 9)	/* 9-11 reserved */
#define	PCS_ANAR_PTX	(1 << 8)	/* Pause TX */
#define	PCS_ANAR_PRX	(1 << 7)	/* Pause RX */
#define	PCS_ANAR_PAUSE	(1 << 7)	/* Pause  */
#define	PCS_ANAR_ASM_DIR	(1 << 8)	/* Asymetric Direction */
#define	PCS_ANAR_GBFDX	(1 << 5)	/* Advertise Gbit FDX Capability */
#define	PCS_ANAR_GBHDX	(1 << 6)	/* Advertise Gbit HDX Capability */
#define	PCS_ANAR_RES	(0x1f << 0)	/* 0-5 Reserved */


/* ************************************************************************ */
/*
 * PCS MII	 Auto-Negotiation Link Partner Ability Reg
 * This register contains the Link Partners capabilities after NWay
 * Auto-Negotiation is complete.
 */

#define	PCS_ANLPAR_NP	(1 << 15)	/* Next Page bit, RO, always 0 */
#define	PCS_ANLPAR_ACK	(1 << 14)	/* Acks reception of Link Partner */
					/* Capability word  */
#define	PCS_ANLPAR_RF	(0x2 << 12)	/* Advertise Remote Fault det. cap. */
#define	PCS_ANLPAR_RES1	(0x7 << 9)	/* 9-11 reserved */
#define	PCS_ANLPAR_PTX	(1 << 8)	/* Pause TX */
#define	PCS_ANLPAR_PRX	(1 << 7)	/* Pause RX */
#define	PCS_ANLPAR_GBFDX (1 << 5)	/* Advertise Gbit FDX Capability */
#define	PCS_ANLPAR_GBHDX (1 << 6)	/* Advertise Gbit HDX Capability */
#define	PCS_ANLPAR_RES	(0x1f << 0)	/* 0-5 Reserved */


/*
 * ------------------------------------------------------------------------
 * PCS Configuration Register
 * Default = 0x8
 * -------------------------------------------------------------------------
 */

#define	PCS_CFG_RES	(0xfff << 4)	/* 4-15 Reserved */
#define	PCS_CFG_TIMER	(0x7 << 1)
	/* Timer values used for the 802.3z Clause 36 Link Monitor s/m timers */
#define	PCS_CFG_ENABLE	(1 << 0)	/* Enable PCS, when set to 1 */


/*
 * ------------------------------------------------------------------------
 * PCS Interrupt State Register
 * Presently only one bit is implemented, reflecting transitions on the link
 * status. Note that there is no mask register at this level.
 * THe PCS_INT bit may be masked at the Interrupt Status Register level.
 * -------------------------------------------------------------------------
 */

#define	PCS_STS_LNKSTS	2	/* Link Status Change */


/*
 * ------------------------------------------------------------------------
 * Datapath Mode Register (RW)
 * This register controls which network interface is used.
 * Only one bit should be set in this register.
 * Default: 0x1
 * -------------------------------------------------------------------------
 */
/*
 * Select MII/GMII and not PCS.
 * Selection between MII and GMII is
 * controlled by the XIF register
 */
#define	ERI_PCS_MII	(1 << 2)
/*
 * Applicable only in Serial Mode
 * When set, makes the 10-bit Xmit data
 * visible at the GMII
 */
#define	ERI_PCS_GMIIOUTEN (1 << 3)


/*
 * ------------------------------------------------------------------------
 * Serial Link Control register (RW)
 * This register controls the Serial link
 * Default: 0x000
 * -------------------------------------------------------------------------
 */
#define	ERI_SLC_LOOPBACK (1 << 0)	/* Enables loopback at the SL o/p */
#define	ERI_SLC_ENSYNCDT (1 << 1)	/* Enable Sync char detection */
#define	ERI_SLC_LOCKREF	(1 << 2)	/* Lock to reference clock */
#define	ERI_SLC_EMP	(0x2 << 3)	/* Control o/p driver emphasis */
#define	ERI_SLC_RES	(1 << 5)	/* Reserved */
#define	ERI_SLC_SELFTEST (0x7 << 6)	/* To select built-in self tests */
#define	ERI_SLC_SW_PDOWN (1 << 9)	/* Power down Serial link block */

/*
 * ------------------------------------------------------------------------
 * Shared Output Select Register (RW)
 * Default: 0x00
 * -------------------------------------------------------------------------
 */

/*
 * ------------------------------------------------------------------------
 * Serial Link State Register (RO)
 * Indicates the progress of the Serial link boot up
 * 00 - Undergoing test
 * 01 - Waiting 500us while lockrefn is asserted
 * 10 - Waiting for comma detect
 * 11 - Receive Data is synchronized
 * -------------------------------------------------------------------------
 */
#define	ERI_SLS_STATE	(0x2 << 0)	/* state */



/* ************************************************************************ */
/*
 * Definition for the time required to wait after a software
 * reset has been issued.
 */
#define	ERI_MAX_RST_DELAY	(200)
#define	ERI_PERIOD	(20)	/* period to wait */
#define	ERI_WAITPERIOD	ERI_PERIOD

#define	ERI_DELAY(c, n) \
	{ \
		register int N = n / ERI_WAITPERIOD; \
		while (--N > 0) { \
			if (c) \
				break; \
			drv_usecwait(ERI_WAITPERIOD); \
		} \
	}

#define	MIF_ERIDELAY(n, phyad, regad) \
	{ \
		register int N = n / ERI_WAITPERIOD; \
		PUT_MIFREG(mif_frame, \
			(ERI_MIF_FRREAD | (phyad << ERI_MIF_FRPHYAD_SHIFT) | \
			(regad << ERI_MIF_FRREGAD_SHIFT))); \
		while (--N > 0) { \
			if (GET_MIFREG(mif_frame) & ERI_MIF_FRTA0) \
				break; \
			drv_usecwait(ERI_WAITPERIOD); \
		} \
	}


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ERI_MAC_H */

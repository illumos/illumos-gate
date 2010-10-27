/*
 * Copyright (c) 2010 Steven Stallion.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials provided
 *        with the distribution.
 *     3. Neither the name of the copyright owner nor the names of any
 *        contributors may be used to endorse or promote products derived
 *        from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_EFE_H
#define	_EFE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	VENDOR_ID		0x10B8
#define	DEVICE_ID		0x0005

#define	RESET_DELAY		1
#define	RESET_TEST_CYCLES	16

#define	STOP_DELAY		10
#define	STOP_DELAY_CYCLES	160

#define	MII_DELAY		1
#define	MII_DELAY_CYCLES	16

#define	EEPROM_DELAY		3
#define	EEPROM_WORDSZ		16

#define	AT93C46_ADDRLEN		6
#define	AT93C56_ADDRLEN		8

#define	FLAG_RUNNING		(1UL << 0)
#define	FLAG_SUSPENDED		(1UL << 1)

#define	MCHASHL			64
#define	MCHASHSZ		16

#define	BURSTLEN		0x3F

#define	RXDESCL			128
#define	TXDESCL			128

#define	BUFSZ			1536

/*
 * Control/Status registers.
 */
#define	CSR_COMMAND	0x00	/* Control Register */
#define	CSR_INTSTAT	0x04	/* Interrupt Status Register */
#define	CSR_INTMASK	0x08	/* Interrupt Mask Register */
#define	CSR_GENCTL	0x0C	/* General Control Register */
#define	CSR_NVCTL	0x10	/* Non-volatile Control Register */
#define	CSR_EECTL	0x14	/* EEPROM Control Register */
#define	CSR_PBLCNT	0x18	/* Programmable Burst Length Counter */
#define	CSR_TEST	0x1C	/* Test Register */
#define	CSR_CRCCNT	0x20	/* CRC Error Counter */
#define	CSR_ALICNT	0x24	/* Frame Alignment Error Counter */
#define	CSR_MPCNT	0x28	/* Missed Packet Counter */
#define	CSR_RXFIFO	0x2C	/* Receive FIFO Contents */
#define	CSR_MMCTL	0x30	/* MII Control Register */
#define	CSR_MMDATA	0x34	/* MII Interface Register */
#define	CSR_MMCFG	0x38	/* MII Configuration Register */
#define	CSR_IPG		0x3C	/* Interpacket Gap Register */
#define	CSR_LAN0	0x40	/* LAN Address Register 0 */
#define	CSR_LAN1	0x44	/* LAN Address Register 1 */
#define	CSR_LAN2	0x48	/* LAN Address Register 2 */
#define	CSR_IDCHK	0x4C	/* Board ID/Checksum Register */
#define	CSR_MC0		0x50	/* Multicast Address Register 0 */
#define	CSR_MC1		0x54	/* Multicast Address Register 1 */
#define	CSR_MC2		0x58	/* Multicast Address Register 2 */
#define	CSR_MC3		0x5C	/* Multicast Address Register 3 */
#define	CSR_RXCON	0x60	/* Receive Control Register */
#define	CSR_RXSTAT	0x64	/* Receive Status Register */
#define	CSR_RXCNT	0x68	/* Receive Byte Count */
#define	CSR_RXTEST	0x6C	/* Receive Test */
#define	CSR_TXCON	0x70	/* Transmit Control Register */
#define	CSR_TXSTAT	0x74	/* Transmit Status Register */
#define	CSR_TDPAR	0x78	/* Transmit Packet Address */
#define	CSR_TXTEST	0x7C	/* Transmit Test */
#define	CSR_PRFDAR	0x80	/* PCI Receive First Descriptor Address */
#define	CSR_PRCDAR	0x84	/* PCI Receive Current Descriptor Address */
#define	CSR_PRHDAR	0x88	/* PCI Receive Host Data Address */
#define	CSR_PRFLAR	0x8C	/* PCI Receive Fragment List Address */
#define	CSR_PRDLGTH	0x90	/* PCI Receive DMA Length/Control */
#define	CSR_PRFCNT	0x94	/* PCI Receive Fragment Count */
#define	CSR_PRLCAR	0x98	/* PCI Receive RAM Current Address */
#define	CSR_PRLPAR	0x9C	/* PCI Receive RAM Packet Address */
#define	CSR_PREFAR	0xA0	/* PCI Receive End of Frame Address */
#define	CSR_PRSTAT	0xA4	/* PCI Receive DMA Status Register */
#define	CSR_PRBUF	0xA8	/* Receive RAM Buffer */
#define	CSR_RDNCAR	0xAC	/* Receive MTU Current Address */
#define	CSR_PRCPTHR	0xB0	/* PCI Receive Copy Threshold Register */
#define	CSR_ROMDATA	0xB4	/* ROMDATA */
#define	CSR_PREEMPR	0xBC	/* Preemptive Interrupt */
#define	CSR_PTFDAR	0xC0	/* PCI Transmit First Descriptor Address */
#define	CSR_PTCDAR	0xC4	/* PCI Transmit Current Descriptor Address */
#define	CSR_PTHDAR	0xC8	/* PCI Transmit Host Data Address */
#define	CSR_PTFLAR	0xCC	/* PCI Transmit Fragment List Address */
#define	CSR_PTDLGTH	0xD0	/* PCI Transmit DMA Length/Control */
#define	CSR_PTFCNT	0xD4	/* PCI Transmit Fragment Count */
#define	CSR_PTLCAR	0xD8	/* PCI Transmit RAM Current Address */
#define	CSR_ETXTHR	0xDC	/* PCI Early Transmit Threshold Register */
#define	CSR_PTETXC	0xE0	/* PCI Early Transmit Count */
#define	CSR_PTSTAT	0xE4	/* PCI Transmit DMA Status */
#define	CSR_PTBUF	0xE8	/* Transmit RAM Buffer */
#define	CSR_PTFDAR2	0xEC	/* PCI Transmit 2 First Descriptor Address */
#define	CSR_FEVTR	0xF0	/* CardBus (UNUSED) */
#define	CSR_FEVTRMSKR	0xF4	/* CardBus (UNUSED) */
#define	CSR_FPRSTSTR	0xF8	/* CardBus (UNUSED) */
#define	CSR_FFRCEVTR	0xFF	/* CardBus (UNUSED) */

/*
 * Register fields.
 */
#define	COMMAND_STOP_RX		(1UL << 0)	/* Stop Receiver */
#define	COMMAND_START_RX	(1UL << 1)	/* Start Receiver */
#define	COMMAND_TXQUEUED	(1UL << 2)	/* Queue TX Descriptor */
#define	COMMAND_RXQUEUED	(1UL << 3)	/* Queue RX Descriptor */
#define	COMMAND_NEXTFRAME	(1UL << 4)	/* Release RX Frame */
#define	COMMAND_STOP_TDMA	(1UL << 5)	/* Stop TX DMA */
#define	COMMAND_STOP_RDMA	(1UL << 6)	/* Stop RX DMA */
#define	COMMAND_TXUGO		(1UL << 7)	/* Restart Transmission */

#define	INTSTAT_RCC	(1UL << 0)	/* Receive Copy Complete */
#define	INTSTAT_HCC	(1UL << 1)	/* Header Copy Complete */
#define	INTSTAT_RQE	(1UL << 2)	/* Receive Queue Empty */
#define	INTSTAT_OVW	(1UL << 3)	/* Receive Overflow */
#define	INTSTAT_RXE	(1UL << 4)	/* Receive Error */
#define	INTSTAT_TXC	(1UL << 5)	/* Transmit Complete */
#define	INTSTAT_TCC	(1UL << 6)	/* Transmit Chain Complete */
#define	INTSTAT_TQE	(1UL << 7)	/* Transmit Queue Empty */
#define	INTSTAT_TXU	(1UL << 8)	/* Transmit Underrun */
#define	INTSTAT_CNT	(1UL << 9)	/* Counter Overflow */
#define	INTSTAT_PREI	(1UL << 10)	/* Preemptive Interrupt */
#define	INTSTAT_RCT	(1UL << 11)	/* Receive Copy Threshold */
#define	INTSTAT_FATAL	(1UL << 12)	/* Fatal Error */
#define	INTSTAT_PME	(1UL << 14)	/* Power Management Event */
#define	INTSTAT_GP2	(1UL << 15)	/* GPIO Event */
#define	INTSTAT_ACTV	(1UL << 16)	/* Interrupt Active */
#define	INTSTAT_RXIDLE	(1UL << 17)	/* Receive Idle */
#define	INTSTAT_TXIDLE	(1UL << 18)	/* Transmit Idle */
#define	INTSTAT_RCIP	(1UL << 19)	/* Receive Copy in Progress */
#define	INTSTAT_TCIP	(1UL << 20)	/* Transmit Copy in Progress */
#define	INTSTAT_RBE	(1UL << 21)	/* Receive Buffers Empty */
#define	INTSTAT_RCTS	(1UL << 22)	/* Receive Copy Threshold Status */
#define	INTSTAT_RSV	(1UL << 23)	/* Receive Status Valid */
#define	INTSTAT_DPE	(1UL << 24)	/* PCI Data Parity Error */
#define	INTSTAT_APE	(1UL << 25)	/* PCI Address Parity Error */
#define	INTSTAT_PMA	(1UL << 26)	/* PCI Master Abort */
#define	INTSTAT_PTA	(1UL << 27)	/* PCI Target Abort */

#define	INTMASK_RCC	(1UL << 0)	/* Receive Copy Complete */
#define	INTMASK_HCC	(1UL << 1)	/* Header Copy Complete */
#define	INTMASK_RQE	(1UL << 2)	/* Receive Queue Empty */
#define	INTMASK_OVW	(1UL << 3)	/* Receive Overflow */
#define	INTMASK_RXE	(1UL << 4)	/* Receive Error */
#define	INTMASK_TXC	(1UL << 5)	/* Transmit Complete */
#define	INTMASK_TCC	(1UL << 6)	/* Transmit Chain Complete */
#define	INTMASK_TQE	(1UL << 7)	/* Transmit Queue Empty */
#define	INTMASK_TXU	(1UL << 8)	/* Transmit Underrun */
#define	INTMASK_CNT	(1UL << 9)	/* Counter Overflow */
#define	INTMASK_PREI	(1UL << 10)	/* Preemptive Interrupt */
#define	INTMASK_RCT	(1UL << 11)	/* Receive Copy Threshold */
#define	INTMASK_FATAL	(1UL << 12)	/* Fatal Error */
#define	INTMASK_PME	(1UL << 14)	/* Power Management Event */
#define	INTMASK_GP2	(1UL << 15)	/* GPIO Event */

#define	GENCTL_RESET	(1UL << 0)	/* Soft Reset */
#define	GENCTL_INT	(1UL << 1)	/* Interrupt Enable */
#define	GENCTL_SWINT	(1UL << 2)	/* Software Interrupt */
#define	GENCTL_PWRDWN	(1UL << 3)	/* Power Down */
#define	GENCTL_ONECOPY	(1UL << 4)	/* One Copy per Receive Frame */
#define	GENCTL_BE	(1UL << 5)	/* Big Endian */
#define	GENCTL_RDP	(1UL << 6)	/* Receive DMA Priority */
#define	GENCTL_TDP	(1UL << 7)	/* Transmit DMA Priority */
#define	GENCTL_RFT_32	(0UL << 8)	/* Receive FIFO Threshold (1/4) */
#define	GENCTL_RFT_64	(1UL << 8)	/* Receive FIFO Threshold (1/2) */
#define	GENCTL_RFT_96	(2UL << 8)	/* Receive FIFO Threshold (3/4) */
#define	GENCTL_RFT_128	(3UL << 8)	/* Receive FIFO Threshold (FULL) */
#define	GENCTL_MRM	(1UL << 10)	/* Memory Read Multiple */
#define	GENCTL_MRL	(1UL << 11)	/* Memory Read Line */
#define	GENCTL_SOFT0	(1UL << 12)	/* Software Bit 0 */
#define	GENCTL_SOFT1	(1UL << 13)	/* Software Bit 1 */
#define	GENCTL_RSTPHY	(1UL << 14)	/* PHY Reset */
#define	GENCTL_SCLK	(1UL << 16)	/* System Clock */
#define	GENCTL_RD	(1UL << 17)	/* Reset Disable */
#define	GENCTL_MPE	(1UL << 18)	/* Magic Packet Enable */
#define	GENCTL_PME	(1UL << 19)	/* PME Interrupt Enable */
#define	GENCTL_PS_00	(0UL << 20)	/* Power State "00" */
#define	GENCTL_PS_01	(1UL << 20)	/* Power State "01" */
#define	GENCTL_PS_10	(2UL << 20)	/* Power State "10" */
#define	GENCTL_PS_11	(3UL << 20)	/* Power State "11" */
#define	GENCTL_OPLE	(1UL << 22)	/* On Power Loss Enable */

#define	NVCTL_EMM	(1UL << 0)	/* Enable Memory Map */
#define	NVCTL_CRS	(1UL << 1)	/* Clock Run Supported */
#define	NVCTL_GPOE1	(1UL << 2)	/* General Purpose Output Enable 1 */
#define	NVCTL_GPOE2	(1UL << 3)	/* General Purpose Output Enable 2 */
#define	NVCTL_GPIO1	(1UL << 4)	/* General Purpose I/O 1 */
#define	NVCTL_GPIO2	(1UL << 5)	/* General Purpose I/O 2 */
#define	NVCTL_CB_MODE	(1UL << 6)	/* CardBus (UNUSED) */
#define	NVCTL_IPG_DLY	7		/* Inter-packet Gap Timer Delay */

#define	EECTL_ENABLE	(1UL << 0)	/* EEPROM Enable */
#define	EECTL_EECS	(1UL << 1)	/* EEPROM Chip Select */
#define	EECTL_EESK	(1UL << 2)	/* EEPROM Clock */
#define	EECTL_EEDI	(1UL << 3)	/* EEPROM Data Input */
#define	EECTL_EEDO	(1UL << 4)	/* EEPROM Data Output */
#define	EECTL_EERDY	(1UL << 5)	/* EEPROM Ready */
#define	EECTL_SIZE	(1UL << 6)	/* EEPROM Size */

#define	TEST_CLOCK	(1UL << 3)	/* Clock Test */

#define	MMCTL_READ	(1UL << 0)	/* MII Read */
#define	MMCTL_WRITE	(1UL << 1)	/* MII Write */
#define	MMCTL_RESPONDER	(1UL << 3)	/* MII Responder */
#define	MMCTL_PHYREG	4		/* PHY Address */
#define	MMCTL_PHYADDR	9		/* PHY Register Address */

#define	MMCFG_SME	(1UL << 0)	/* Serial Mode Enable */
#define	MMCFG_EN694	(1UL << 1)	/* EN694 Pin */
#define	MMCFG_694LNK	(1UL << 2)	/* 694LNK Pin */
#define	MMCFG_PHY	(1UL << 3)	/* PHY Present */
#define	MMCFG_SMI	(1UL << 4)	/* Enable Serial Management */
#define	MMCFG_ALTCS	(1UL << 5)	/* Alternate Clock Source */
#define	MMCFG_ALTDATA	(1UL << 6)	/* Alternate Data */
#define	MMCFG_STXC	(1UL << 14)	/* Select TX Clock */
#define	MMCFG_SNTXC	(1UL << 15)	/* Set No TX Clock */

#define	RXCON_SEP	(1UL << 0)	/* Save Errored Packets */
#define	RXCON_RRF	(1UL << 1)	/* Receive Runt Frames */
#define	RXCON_RBF	(1UL << 2)	/* Receive Broadcast Frames */
#define	RXCON_RMF	(1UL << 3)	/* Receive Multicast Frames */
#define	RXCON_RIIA	(1UL << 4)	/* Receive Inverse Addresses */
#define	RXCON_PROMISC	(1UL << 5)	/* Promiscuous Mode */
#define	RXCON_MONITOR	(1UL << 6)	/* Monitor Mode */
#define	RXCON_ERE	(1UL << 7)	/* Early Receive Enable */
#define	RXCON_EB_INT	(0UL << 8)	/* External Buffer (Inernal) */
#define	RXCON_EB_16K	(1UL << 8)	/* External Buffer (16K) */
#define	RXCON_EB_32K	(2UL << 8)	/* External Buffer (32K) */
#define	RXCON_EB_128K	(3UL << 8)	/* External Buffer (128K) */

#define	RXSTAT_PRI	(1UL << 0)	/* Packet Received Intact */
#define	RXSTAT_FAE	(1UL << 1)	/* Frame Alignment Error */
#define	RXSTAT_CRC	(1UL << 2)	/* CRC Error */
#define	RXSTAT_MP	(1UL << 3)	/* Missed Packet */
#define	RXSTAT_MAR	(1UL << 4)	/* Multicast Address Recognized */
#define	RXSTAT_BAR	(1UL << 5)	/* Broadcast Address Recognized */
#define	RXSTAT_RD	(1UL << 6)	/* Receiver Disabled */
#define	RXSTAT_NSV	(1UL << 12)	/* Network Status Valid */
#define	RXSTAT_FLE	(1UL << 13)	/* Fragment List Error */
#define	RXSTAT_HC	(1UL << 14)	/* Header Copied */
#define	RXSTAT_OWNER	(1UL << 15)	/* Descriptor Ownership Bit */

#define	RXCTL_FRAGLIST	(1UL << 0)	/* Fragment List */
#define	RXCTL_LFFORM	(1UL << 1)	/* Fragment List Format */
#define	RXCTL_HEADER	(1UL << 2)	/* Header Copy */

#define	TXCON_ETE	(1UL << 0)	/* Early Transmit Enable */
#define	TXCON_LB_0	(0UL << 1)	/* Normal Operation */
#define	TXCON_LB_1	(1UL << 1)	/* Internal Loopback */
#define	TXCON_LB_2	(2UL << 1)	/* External Loopback */
#define	TXCON_LB_3	(3UL << 1)	/* Full Duplex Mode */
#define	TXCON_SLOT	3		/* Slot Time */

#define	TXSTAT_PTX	(1UL << 0)	/* Packet Transmitted */
#define	TXSTAT_ND	(1UL << 1)	/* Non-deferred Transmission */
#define	TXSTAT_COLL	(1UL << 2)	/* Transmitted w/Collisions */
#define	TXSTAT_CSL	(1UL << 3)	/* Carrier Sense Lost */
#define	TXSTAT_UFLO	(1UL << 4)	/* TX Underrun */
#define	TXSTAT_CDH	(1UL << 5)	/* Collision Detect Heartbeat */
#define	TXSTAT_OWC	(1UL << 6)	/* Out of Window Collision */
#define	TXSTAT_DEFER	(1UL << 7)	/* IGP Deferring */
#define	TXSTAT_CCNT	8		/* Collision Count */
#define	TXSTAT_CCNTMASK	0x1F		/* Collision Count Mask */
#define	TXSTAT_EXCOLL	(1UL << 12)	/* Excessive Collisions */
#define	TXSTAT_OWNER	(1UL << 15)	/* Descriptor Ownership Bit */

#define	TXCTL_FRAGLIST	(1UL << 0)	/* Fragment List */
#define	TXCTL_LFFORM	(1UL << 1)	/* Fragment List Format */
#define	TXCTL_IAF	(1UL << 2)	/* Interrupt After Frame */
#define	TXCTL_NOCRC	(1UL << 3)	/* Disable CRC Generation */
#define	TXCTL_LASTDESCR	(1UL << 4)	/* Last Transmit Descriptor */

/*
 * Register access.
 */
#define	GETCSR(efep, reg) \
	ddi_get32((efep)->efe_regs_acch, \
	    (efep)->efe_regs + ((reg) / sizeof (uint32_t)))

#define	PUTCSR(efep, reg, val) \
	ddi_put32((efep)->efe_regs_acch, \
	    (efep)->efe_regs + ((reg) / sizeof (uint32_t)), (val))

#define	CLRBIT(efep, reg, bit) \
	PUTCSR(efep, reg, (GETCSR(efep, reg) & ~(bit)))

#define	SETBIT(efep, reg, bit) \
	PUTCSR(efep, reg, (GETCSR(efep, reg) | (bit)))

/*
 * DMA access.
 */
#define	DESCSZ(x)		(sizeof (efe_desc_t) * (x))
#define	BUFPSZ(x)		(sizeof (efe_buf_t *) * (x))

#define	DESCADDR(rp, x)		((rp)->r_dmac.dmac_address + DESCSZ(x))
#define	DESCLEN(rp)		((rp)->r_len)

#define	BUFADDR(bp)		((bp)->b_dmac.dmac_address)
#define	BUFLEN(bp)		((bp)->b_len)

#define	NEXTDESC(rp, x)		(((x) + 1) % (rp)->r_len)
#define	NEXTDESCADDR(rp, x)	DESCADDR(rp, NEXTDESC(rp, x))

#define	GETDESC(rp, x) 		(&(rp)->r_descp[(x)])

#define	GETDESC16(rp, addr) \
	ddi_get16((rp)->r_acch, (addr))

#define	PUTDESC16(rp, addr, val) \
	ddi_put16((rp)->r_acch, (addr), (val))

#define	GETDESC32(rp, addr) \
	ddi_get32((rp)->r_acch, (addr))

#define	PUTDESC32(rp, addr, val) \
	ddi_put32((rp)->r_acch, (addr), (val))

#define	SYNCDESC(rp, x, type) \
	(void) ddi_dma_sync((rp)->r_dmah, DESCSZ(x), \
	    sizeof (efe_desc_t), (type))

#define	GETBUF(rp, x)		((rp)->r_bufpp[(x)])

#define	SYNCBUF(bp, type) \
	(void) ddi_dma_sync((bp)->b_dmah, 0, (bp)->b_len, (type))

/*
 * Soft state.
 */
typedef struct {
	uint16_t		d_status;
	uint16_t		d_len;
	uint32_t		d_bufaddr;
	uint16_t		d_buflen;
	uint16_t		d_control;
	uint32_t		d_next;
} efe_desc_t;

typedef struct {
	ddi_dma_handle_t	b_dmah;
	ddi_acc_handle_t	b_acch;
	ddi_dma_cookie_t	b_dmac;
	size_t			b_len;
	caddr_t			b_kaddr;
} efe_buf_t;

typedef struct {
	ddi_dma_handle_t	r_dmah;
	ddi_acc_handle_t	r_acch;
	ddi_dma_cookie_t	r_dmac;
	size_t			r_len;
	efe_desc_t		*r_descp;
	efe_buf_t		**r_bufpp;
} efe_ring_t;

typedef struct {
	dev_info_t		*efe_dip;

	mii_handle_t		efe_miih;
	mac_handle_t		efe_mh;

	uint32_t		*efe_regs;
	ddi_acc_handle_t	efe_regs_acch;

	ddi_intr_handle_t	efe_intrh;

	kmutex_t		efe_intrlock;
	kmutex_t		efe_txlock;

	int			efe_flags;
	boolean_t		efe_promisc;

	uint8_t			efe_macaddr[ETHERADDRL];

	uint_t			efe_mccount[MCHASHL];
	uint16_t		efe_mchash[MCHASHL / MCHASHSZ];

	efe_ring_t		*efe_rx_ring;
	uint_t			efe_rx_desc;

	efe_ring_t		*efe_tx_ring;
	uint_t			efe_tx_desc;
	uint_t			efe_tx_sent;

	/*
	 * Driver statistics.
	 */
	uint64_t		efe_multircv;
	uint64_t		efe_brdcstrcv;
	uint64_t		efe_multixmt;
	uint64_t		efe_brdcstxmt;
	uint64_t		efe_norcvbuf;
	uint64_t		efe_ierrors;
	uint64_t		efe_noxmtbuf;
	uint64_t		efe_oerrors;
	uint64_t		efe_collisions;
	uint64_t		efe_rbytes;
	uint64_t		efe_ipackets;
	uint64_t		efe_obytes;
	uint64_t		efe_opackets;
	uint64_t		efe_uflo;
	uint64_t		efe_oflo;
	uint64_t		efe_align_errors;
	uint64_t		efe_fcs_errors;
	uint64_t		efe_first_collisions;
	uint64_t		efe_tx_late_collisions;
	uint64_t		efe_defer_xmts;
	uint64_t		efe_ex_collisions;
	uint64_t		efe_macxmt_errors;
	uint64_t		efe_carrier_errors;
	uint64_t		efe_toolong_errors;
	uint64_t		efe_macrcv_errors;
	uint64_t		efe_runt_errors;
	uint64_t		efe_jabber_errors;
} efe_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EFE_H */

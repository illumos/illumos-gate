/*
 * Solaris driver for ethernet cards based on the ADMtek Centaur
 *
 * Copyright (c) 2007 by Garrett D'Amore <garrett@damore.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AFEIMPL_H
#define	_AFEIMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	_KERNEL

/*
 * Compile time tunables.
 */
#define	AFE_RXRING	128	/* number of rcv buffers */
#define	AFE_TXRING	128	/* number of xmt buffers */
#define	AFE_TXRECLAIM	8	/* when to reclaim tx buffers (txavail) */
#define	AFE_TXRESCHED	120	/* when to resched (txavail) */
#define	AFE_LINKTIMER	5000	/* how often we check link state (in msec) */
#define	AFE_HEADROOM	34	/* headroom in packet (should be 2 modulo 4) */

/*
 * Constants, do not change.
 */
#define	AFE_BUFSZ	(1664)	/* big enough for a vlan frame */
#define	AFE_MCHASH	(64)

typedef struct afe afe_t;
typedef struct afe_card afe_card_t;
typedef struct afe_rxbuf afe_rxbuf_t;
typedef struct afe_txbuf afe_txbuf_t;
typedef struct afe_desc afe_desc_t;

/*
 * Card models.
 */
typedef enum {
	MODEL_CENTAUR = 1,
	MODEL_COMET,
} afe_model_t;

struct afe_card {
	uint16_t	card_venid;	/* PCI vendor id */
	uint16_t	card_devid;	/* PCI device id */
	char		*card_cardname;	/* Description of the card */
	afe_model_t	card_model;	/* Card specific flags */
};

/*
 * Device instance structure, one per PCI card.
 */
struct afe {
	dev_info_t		*afe_dip;
	mac_handle_t		afe_mh;
	afe_card_t		*afe_cardp;
	uint16_t		afe_cachesize;
	uint8_t			afe_sromwidth;
	int			afe_flags;
	kmutex_t		afe_xmtlock;
	kmutex_t		afe_intrlock;
	ddi_iblock_cookie_t	afe_icookie;

	/*
	 * Register and DMA access.
	 */
	uintptr_t		afe_regs;
	ddi_acc_handle_t	afe_regshandle;

	/*
	 * Receive descriptors.
	 */
	int			afe_rxhead;
	struct afe_desc		*afe_rxdescp;
	ddi_dma_handle_t	afe_rxdesc_dmah;
	ddi_acc_handle_t	afe_rxdesc_acch;
	uint32_t		afe_rxdesc_paddr;
	struct afe_rxbuf	**afe_rxbufs;

	/*
	 * Transmit descriptors.
	 */
	int			afe_txreclaim;
	int			afe_txsend;
	int			afe_txavail;
	struct afe_desc		*afe_txdescp;
	ddi_dma_handle_t	afe_txdesc_dmah;
	ddi_acc_handle_t	afe_txdesc_acch;
	uint32_t		afe_txdesc_paddr;
	struct afe_txbuf	**afe_txbufs;
	hrtime_t		afe_txstall_time;
	boolean_t		afe_wantw;

	/*
	 * Link state.
	 */
	uint64_t		afe_lastifspeed;
	link_state_t		afe_linkup;
	link_duplex_t		afe_lastduplex;
	link_duplex_t		afe_duplex;
	uint64_t		afe_ifspeed;
	boolean_t		afe_resetting;	/* no link warning */

	/*
	 * Transceiver stuff.
	 */
	int			afe_phyaddr;
	int			afe_phyid;
	int			afe_phyinuse;

	uint8_t			afe_adv_aneg;
	uint8_t			afe_adv_100T4;
	uint8_t			afe_adv_100fdx;
	uint8_t			afe_adv_100hdx;
	uint8_t			afe_adv_10fdx;
	uint8_t			afe_adv_10hdx;
	uint8_t			afe_cap_aneg;
	uint8_t			afe_cap_100T4;
	uint8_t			afe_cap_100fdx;
	uint8_t			afe_cap_100hdx;
	uint8_t			afe_cap_10fdx;
	uint8_t			afe_cap_10hdx;

	int			afe_forcefiber;

	/*
	 * Address management.
	 */
	uchar_t			afe_curraddr[ETHERADDRL];
	boolean_t		afe_promisc;
	uint16_t		afe_mccount[AFE_MCHASH];
	uint32_t		afe_mctab[AFE_MCHASH / 32];	/* Centaur */

	/*
	 * Kstats.
	 */
	kstat_t			*afe_intrstat;
	uint64_t		afe_ipackets;
	uint64_t		afe_opackets;
	uint64_t		afe_rbytes;
	uint64_t		afe_obytes;
	uint64_t		afe_brdcstxmt;
	uint64_t		afe_multixmt;
	uint64_t		afe_brdcstrcv;
	uint64_t		afe_multircv;
	unsigned		afe_norcvbuf;
	unsigned		afe_errrcv;
	unsigned		afe_errxmt;
	unsigned		afe_missed;
	unsigned		afe_underflow;
	unsigned		afe_overflow;
	unsigned		afe_align_errors;
	unsigned		afe_fcs_errors;
	unsigned		afe_carrier_errors;
	unsigned		afe_collisions;
	unsigned		afe_ex_collisions;
	unsigned		afe_tx_late_collisions;
	unsigned		afe_defer_xmts;
	unsigned		afe_first_collisions;
	unsigned		afe_multi_collisions;
	unsigned		afe_sqe_errors;
	unsigned		afe_macxmt_errors;
	unsigned		afe_macrcv_errors;
	unsigned		afe_toolong_errors;
	unsigned		afe_runt;
	unsigned		afe_jabber;
};

struct afe_rxbuf {
	caddr_t			rxb_buf;
	ddi_dma_handle_t	rxb_dmah;
	ddi_acc_handle_t	rxb_acch;
	uint32_t		rxb_paddr;
};

struct afe_txbuf {
	caddr_t			txb_buf;
	uint32_t		txb_paddr;
	ddi_dma_handle_t	txb_dmah;
	ddi_acc_handle_t	txb_acch;
};

/*
 * Descriptor.  We use rings rather than chains.
 */
struct afe_desc {
	unsigned	desc_status;
	unsigned	desc_control;
	unsigned	desc_buffer1;
	unsigned	desc_buffer2;
};

#define	PUTTXDESC(afep, member, val)	\
	ddi_put32(afep->afe_txdesc_acch, &member, val)

#define	PUTRXDESC(afep, member, val)	\
	ddi_put32(afep->afe_rxdesc_acch, &member, val)

#define	GETTXDESC(afep, member)	\
	ddi_get32(afep->afe_txdesc_acch, &member)

#define	GETRXDESC(afep, member)	\
	ddi_get32(afep->afe_rxdesc_acch, &member)

/*
 * Receive descriptor fields.
 */
#define	RXSTAT_OWN		0x80000000U	/* ownership */
#define	RXSTAT_RXLEN		0x3FFF0000U	/* frame length, incl. crc */
#define	RXSTAT_RXERR		0x00008000U	/* error summary */
#define	RXSTAT_DESCERR		0x00004000U	/* descriptor error */
#define	RXSTAT_RXTYPE		0x00003000U	/* data type */
#define	RXSTAT_RUNT		0x00000800U	/* runt frame */
#define	RXSTAT_GROUP		0x00000400U	/* multicast/brdcast frame */
#define	RXSTAT_FIRST		0x00000200U	/* first descriptor */
#define	RXSTAT_LAST		0x00000100U	/* last descriptor */
#define	RXSTAT_TOOLONG		0x00000080U	/* frame too long */
#define	RXSTAT_COLLSEEN		0x00000040U	/* late collision seen */
#define	RXSTAT_FRTYPE		0x00000020U	/* frame type */
#define	RXSTAT_WATCHDOG		0x00000010U	/* receive watchdog */
#define	RXSTAT_DRIBBLE		0x00000004U	/* dribbling bit */
#define	RXSTAT_CRCERR		0x00000002U	/* crc error */
#define	RXSTAT_OFLOW		0x00000001U	/* fifo overflow */
#define	RXSTAT_ERRS		(RXSTAT_DESCERR | RXSTAT_RUNT | \
				RXSTAT_COLLSEEN | RXSTAT_DRIBBLE | \
				RXSTAT_CRCERR | RXSTAT_OFLOW)
#define	RXLENGTH(x)		((x & RXSTAT_RXLEN) >> 16)

#define	RXCTL_ENDRING		0x02000000U	/* end of ring */
#define	RXCTL_CHAIN		0x01000000U	/* chained descriptors */
#define	RXCTL_BUFLEN2		0x003FF800U	/* buffer 2 length */
#define	RXCTL_BUFLEN1		0x000007FFU	/* buffer 1 length */

/*
 * Transmit descriptor fields.
 */
#define	TXSTAT_OWN		0x80000000U	/* ownership */
#define	TXSTAT_URCNT		0x00C00000U	/* underrun count */
#define	TXSTAT_TXERR		0x00008000U	/* error summary */
#define	TXSTAT_JABBER		0x00004000U	/* jabber timeout */
#define	TXSTAT_CARRLOST		0x00000800U	/* lost carrier */
#define	TXSTAT_NOCARR		0x00000400U	/* no carrier */
#define	TXSTAT_LATECOL		0x00000200U	/* late collision */
#define	TXSTAT_EXCOLL		0x00000100U	/* excessive collisions */
#define	TXSTAT_SQE		0x00000080U	/* heartbeat failure */
#define	TXSTAT_COLLCNT		0x00000078U	/* collision count */
#define	TXSTAT_UFLOW		0x00000002U	/* underflow */
#define	TXSTAT_DEFER		0x00000001U	/* deferred */
#define	TXCOLLCNT(x)		((x & TXSTAT_COLLCNT) >> 3)
#define	TXUFLOWCNT(x)		((x & TXSTAT_URCNT) >> 22)

#define	TXCTL_INTCMPLTE		0x80000000U	/* interrupt completed */
#define	TXCTL_LAST		0x40000000U	/* last descriptor */
#define	TXCTL_FIRST		0x20000000U	/* first descriptor */
#define	TXCTL_NOCRC		0x04000000U	/* disable crc */
#define	TXCTL_ENDRING		0x02000000U	/* end of ring */
#define	TXCTL_CHAIN		0x01000000U	/* chained descriptors */
#define	TXCTL_NOPAD		0x00800000U	/* disable padding */
#define	TXCTL_HASHPERF		0x00400000U	/* hash perfect mode */
#define	TXCTL_BUFLEN2		0x003FF800U	/* buffer length 2 */
#define	TXCTL_BUFLEN1		0x000007FFU	/* buffer length 1 */


/*
 * Interface flags.
 */
#define	AFE_RUNNING	0x1	/* chip is initialized */
#define	AFE_SUSPENDED	0x2	/* interface is suspended */
#define	AFE_HASFIBER	0x4	/* internal phy supports fiber (AFE_PHY_MCR) */

#define	AFE_MODEL(afep)		((afep)->afe_cardp->card_model)


/*
 * Register definitions located in afe.h exported header file.
 */

/*
 * Macros to simplify hardware access.
 */
#define	GETCSR(afep, reg)	\
	ddi_get32(afep->afe_regshandle, (uint32_t *)(afep->afe_regs + reg))

#define	GETCSR16(afep, reg)	\
	ddi_get16(afep->afe_regshandle, (uint16_t *)(afep->afe_regs + reg))

#define	PUTCSR(afep, reg, val)	\
	ddi_put32(afep->afe_regshandle, (uint32_t *)(afep->afe_regs + reg), val)

#define	PUTCSR16(afep, reg, val)	\
	ddi_put16(afep->afe_regshandle, (uint16_t *)(afep->afe_regs + reg), val)

#define	SETBIT(afep, reg, val)	PUTCSR(afep, reg, GETCSR(afep, reg) | (val))

#define	CLRBIT(afep, reg, val)	PUTCSR(afep, reg, GETCSR(afep, reg) & ~(val))

#define	SYNCTXDESC(afep, index, who)	\
	(void) ddi_dma_sync(afep->afe_txdesc_dmah, \
	    (index * sizeof (afe_desc_t)), sizeof (afe_desc_t), who)

#define	SYNCTXBUF(txb, len, who)	\
	(void) ddi_dma_sync(txb->txb_dmah, 0, len, who)

#define	SYNCRXDESC(afep, index, who)	\
	(void) ddi_dma_sync(afep->afe_rxdesc_dmah, \
	    (index * sizeof (afe_desc_t)), sizeof (afe_desc_t), who)

#define	SYNCRXBUF(rxb, len, who)	\
	(void) ddi_dma_sync(rxb->rxb_dmah, 0, len, who)

/*
 * Debugging flags.
 */
#define	DWARN	0x0001
#define	DINTR	0x0002
#define	DMACID	0x0008
#define	DPHY	0x0020
#define	DPCI	0x0040
#define	DCHATTY	0x0080
#define	DDMA	0x0100
#define	DLINK	0x0200
#define	DSROM	0x0400
#define	DRECV	0x0800
#define	DXMIT	0x1000

#ifdef	DEBUG
#define	DBG(lvl, ...)	afe_dprintf(afep, __func__, lvl, __VA_ARGS__)
#else
#define	DBG(lvl, ...)
#endif

#endif	/* _KERNEL */

#endif	/* _AFEIMPL_H */

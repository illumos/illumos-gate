/*
 * Solaris driver for ethernet cards based on the Macronix 98715
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

#ifndef	_MXFEIMPL_H
#define	_MXFEIMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This entire file is private to the MXFE driver.
 */

#ifdef	_KERNEL

/*
 * Compile time tunables.
 */
#define	MXFE_TXRING	128	/* number of xmt buffers */
#define	MXFE_RXRING	256	/* number of rcv buffers */
#define	MXFE_TXRECLAIM	32	/* when to reclaim tx buffers (txavail) */
#define	MXFE_TXRESCHED	120	/* when to resched (txavail) */
#define	MXFE_LINKTIMER	5000	/* how often we check link state (msec) */
#define	MXFE_HEADROOM	34	/* headroom in packet (should be 2 modulo 4) */

/*
 * Constants, do not change.  The bufsize is setup to make sure it comes
 * in at a whole number of cache lines, even for 32-long-word aligned
 * caches.
 */
#define	MXFE_BUFSZ	(1664)		/* big enough for a vlan frame */
#define	MXFE_SETUP_LEN	192		/* size of a setup frame */

typedef struct mxfe mxfe_t;
typedef struct mxfe_card mxfe_card_t;
typedef struct mxfe_rxbuf mxfe_rxbuf_t;
typedef struct mxfe_txbuf mxfe_txbuf_t;
typedef struct mxfe_desc mxfe_desc_t;

struct mxfe_card {
	uint16_t	card_venid;	/* PCI vendor id */
	uint16_t	card_devid;	/* PCI device id */
	uint16_t	card_revid;	/* PCI revision id */
	uint16_t	card_revmask;
	char		*card_cardname;	/* Description of the card */
	unsigned	card_model;	/* Card specific flags */
};

/*
 * Device instance structure, one per PCI card.
 */
struct mxfe {
	dev_info_t		*mxfe_dip;
	mac_handle_t		mxfe_mh;
	mxfe_card_t		*mxfe_cardp;
	ushort_t		mxfe_cachesize;
	ushort_t		mxfe_sromwidth;
	int			mxfe_flags;
	kmutex_t		mxfe_xmtlock;
	kmutex_t		mxfe_intrlock;
	ddi_iblock_cookie_t	mxfe_icookie;

	/*
	 * Register access.
	 */
	uint32_t		*mxfe_regs;
	ddi_acc_handle_t	mxfe_regshandle;

	/*
	 * Receive descriptors.
	 */
	int			mxfe_rxhead;
	struct mxfe_desc	*mxfe_rxdescp;
	ddi_dma_handle_t	mxfe_rxdesc_dmah;
	ddi_acc_handle_t	mxfe_rxdesc_acch;
	uint32_t		mxfe_rxdesc_paddr;
	struct mxfe_rxbuf	**mxfe_rxbufs;

	/*
	 * Transmit descriptors.
	 */
	int			mxfe_txreclaim;
	int			mxfe_txsend;
	int			mxfe_txavail;
	struct mxfe_desc	*mxfe_txdescp;
	ddi_dma_handle_t	mxfe_txdesc_dmah;
	ddi_acc_handle_t	mxfe_txdesc_acch;
	uint32_t		mxfe_txdesc_paddr;
	struct mxfe_txbuf	**mxfe_txbufs;
	hrtime_t		mxfe_txstall_time;
	boolean_t		mxfe_wantw;

	/*
	 * Address management.
	 */
	uchar_t			mxfe_curraddr[ETHERADDRL];
	boolean_t		mxfe_promisc;

	/*
	 * Link state.
	 */
	int			mxfe_nwaystate;
	uint64_t		mxfe_lastifspeed;
	link_duplex_t		mxfe_lastduplex;
	link_state_t		mxfe_lastlinkup;
	link_state_t		mxfe_linkup;
	link_duplex_t		mxfe_duplex;
	uint64_t		mxfe_ifspeed;
	boolean_t		mxfe_resetting;	/* no link warning */

	/*
	 * Transceiver stuff.
	 */
	int			mxfe_phyaddr;
	int			mxfe_phyid;
	int			mxfe_phyinuse;
	uint8_t			mxfe_adv_aneg;
	uint8_t			mxfe_adv_100T4;
	uint8_t			mxfe_adv_100fdx;
	uint8_t			mxfe_adv_100hdx;
	uint8_t			mxfe_adv_10fdx;
	uint8_t			mxfe_adv_10hdx;
	uint8_t			mxfe_cap_aneg;
	uint8_t			mxfe_cap_100T4;
	uint8_t			mxfe_cap_100fdx;
	uint8_t			mxfe_cap_100hdx;
	uint8_t			mxfe_cap_10fdx;
	uint8_t			mxfe_cap_10hdx;
	int			mxfe_forcephy;
	uint16_t		mxfe_bmsr;
	uint16_t		mxfe_anlpar;
	uint16_t		mxfe_aner;

	/*
	 * Kstats.
	 */
	kstat_t			*mxfe_intrstat;
	uint64_t		mxfe_ipackets;
	uint64_t		mxfe_opackets;
	uint64_t		mxfe_rbytes;
	uint64_t		mxfe_obytes;
	uint64_t		mxfe_brdcstrcv;
	uint64_t		mxfe_multircv;
	uint64_t		mxfe_brdcstxmt;
	uint64_t		mxfe_multixmt;

	unsigned		mxfe_norcvbuf;
	unsigned		mxfe_noxmtbuf;
	unsigned		mxfe_errrcv;
	unsigned		mxfe_errxmt;
	unsigned		mxfe_missed;
	unsigned		mxfe_underflow;
	unsigned		mxfe_overflow;
	unsigned		mxfe_align_errors;
	unsigned		mxfe_fcs_errors;
	unsigned		mxfe_carrier_errors;
	unsigned		mxfe_collisions;
	unsigned		mxfe_ex_collisions;
	unsigned		mxfe_tx_late_collisions;
	unsigned		mxfe_defer_xmts;
	unsigned		mxfe_first_collisions;
	unsigned		mxfe_multi_collisions;
	unsigned		mxfe_sqe_errors;
	unsigned		mxfe_macxmt_errors;
	unsigned		mxfe_macrcv_errors;
	unsigned		mxfe_toolong_errors;
	unsigned		mxfe_runt;
	unsigned		mxfe_jabber;
};

struct mxfe_rxbuf {
	caddr_t			rxb_buf;
	ddi_dma_handle_t	rxb_dmah;
	ddi_acc_handle_t	rxb_acch;
	uint32_t		rxb_paddr;
};

struct mxfe_txbuf {
	/* bcopy version of tx */
	caddr_t			txb_buf;
	uint32_t		txb_paddr;
	ddi_dma_handle_t	txb_dmah;
	ddi_acc_handle_t	txb_acch;
};

/*
 * Descriptor.  We use rings rather than chains.
 */
struct mxfe_desc {
	unsigned	desc_status;
	unsigned	desc_control;
	unsigned	desc_buffer1;
	unsigned	desc_buffer2;
};

#define	PUTTXDESC(mxfep, member, val)	\
	ddi_put32(mxfep->mxfe_txdesc_acch, &member, val)

#define	PUTRXDESC(mxfep, member, val)	\
	ddi_put32(mxfep->mxfe_rxdesc_acch, &member, val)

#define	GETTXDESC(mxfep, member)	\
	ddi_get32(mxfep->mxfe_txdesc_acch, &member)

#define	GETRXDESC(mxfep, member)	\
	ddi_get32(mxfep->mxfe_rxdesc_acch, &member)

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
#define	TXCTL_SETUP		0x08000000U	/* setup frame */
#define	TXCTL_ENDRING		0x02000000U	/* end of ring */
#define	TXCTL_CHAIN		0x01000000U	/* chained descriptors */
#define	TXCTL_NOPAD		0x00800000U	/* disable padding */
#define	TXCTL_HASHPERF		0x00400000U	/* hash perfect mode */
#define	TXCTL_BUFLEN2		0x003FF800U	/* buffer length 2 */
#define	TXCTL_BUFLEN1		0x000007FFU	/* buffer length 1 */

/*
 * Interface flags.
 */
#define	MXFE_RUNNING	0x1	/* chip is initialized */
#define	MXFE_SUSPENDED	0x2	/* interface is suspended */
#define	MXFE_SYMBOL	0x8	/* use symbol mode */

/*
 * Link flags...
 */
#define	MXFE_NOLINK	0x0	/* initial link state, no timer */
#define	MXFE_NWAYCHECK	0x2	/* checking for NWay support */
#define	MXFE_NWAYRENEG	0x3	/* renegotiating NWay mode */
#define	MXFE_GOODLINK	0x4	/* detected link is good */

/*
 * Card models.
 */
#define	MXFE_MODEL(mxfep)	((mxfep)->mxfe_cardp->card_model)
#define	MXFE_98715	0x1
#define	MXFE_98715A	0x2
#define	MXFE_98715AEC	0x3
#define	MXFE_98715B	0x4
#define	MXFE_98725	0x5
#define	MXFE_98713	0x6
#define	MXFE_98713A	0x7
#define	MXFE_PNICII	0x8

/*
 * Register definitions located in mxfe.h exported header file.
 */

/*
 * Macros to simplify hardware access.  Note that the reg/4 is used to
 * help with pointer arithmetic.
 */
#define	GETCSR(mxfep, reg)	\
	ddi_get32(mxfep->mxfe_regshandle, mxfep->mxfe_regs + (reg/4))

#define	PUTCSR(mxfep, reg, val)	\
	ddi_put32(mxfep->mxfe_regshandle, mxfep->mxfe_regs + (reg/4), val)

#define	SETBIT(mxfep, reg, val)	\
	PUTCSR(mxfep, reg, GETCSR(mxfep, reg) | (val))

#define	CLRBIT(mxfep, reg, val)	\
	PUTCSR(mxfep, reg, GETCSR(mxfep, reg) & ~(val))

#define	SYNCTXDESC(mxfep, index, who)	\
	(void) ddi_dma_sync(mxfep->mxfe_txdesc_dmah, \
	    (index * sizeof (mxfe_desc_t)), sizeof (mxfe_desc_t), who)

#define	SYNCTXBUF(txb, len, who)	\
	(void) (ddi_dma_sync(txb->txb_dmah, 0, len, who))

#define	SYNCRXDESC(mxfep, index, who)	\
	(void) ddi_dma_sync(mxfep->mxfe_rxdesc_dmah, \
	    (index * sizeof (mxfe_desc_t)), sizeof (mxfe_desc_t), who)

#define	SYNCRXBUF(rxb, len, who)	\
	(void) (ddi_dma_sync(rxb->rxb_dmah, 0, len, who))

/*
 * Debugging flags.
 */
#define	DWARN	0x0001
#define	DINTR	0x0002
#define	DWSRV	0x0004
#define	DMACID	0x0008
#define	DDLPI	0x0010
#define	DPHY	0x0020
#define	DPCI	0x0040
#define	DCHATTY	0x0080
#define	DDMA	0x0100
#define	DLINK	0x0200
#define	DSROM	0x0400
#define	DRECV	0x0800
#define	DXMIT	0x1000

#ifdef	DEBUG
#define	DBG(lvl, ...)	mxfe_dprintf(mxfep, __func__, lvl, __VA_ARGS__);
#else
#define	DBG(lvl, ...)
#endif

#endif	/* _KERNEL */

#endif	/* _MXFEIMPL_H */

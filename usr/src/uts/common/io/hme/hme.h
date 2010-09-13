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

#ifndef	_SYS_HME_H
#define	_SYS_HME_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/* default IPG settings */
#define	IPG1	8
#define	IPG2	4

/*
 * Declarations and definitions specific to the
 * FEPS 10/100 Mbps Ethernet (hme) device.
 */

/*
 * Per-Stream instance state information.
 *
 * Each instance is dynamically allocated at open() and free'd
 * at close().  Each per-Stream instance points to at most one
 * per-device structure using the sb_hmep field.  All instances
 * are threaded together into one list of active instances
 * ordered on minor device number.
 */

#define	HME_2P0_REVID		0xa0 /* hme - feps. */
#define	HME_2P1_REVID		0x20
#define	HME_2P1_REVID_OBP	0x21
#define	HME_1C0_REVID		0xc0 /* cheerio 1.0, hme 2.0 equiv. */
#define	HME_2C0_REVID		0xc1 /* cheerio 2.0, hme 2.2 equiv. */
#define	HME_REV_VERS_MASK	0x0f /* Mask to retain bits for cheerio ver */

typedef struct {
	ddi_dma_handle_t	dmah;
	ddi_acc_handle_t	acch;
	caddr_t			kaddr;
	uint32_t		paddr;
} hmebuf_t;

/*
 * HME Device Channel instance state information.
 *
 * Each instance is dynamically allocated on first attach.
 */
struct	hme {
	mac_handle_t		hme_mh;		/* GLDv3 handle */
	mii_handle_t		hme_mii;
	dev_info_t		*dip;		/* associated dev_info */
	int			instance;	/* instance */
	ulong_t			pagesize;	/* btop(9F) */

	int			hme_mifpoll_enable;
	int			hme_frame_enable;
	int			hme_lance_mode_enable;
	int			hme_rxcv_enable;

	uint32_t		hme_lance_mode;
	uint32_t		hme_ipg0;
	uint32_t		hme_ipg1;
	uint32_t		hme_ipg2;

	uint_t			hme_burstsizes; /* binary encoded val */
	uint32_t		hme_config;	/* Config reg store */

	int			hme_phy_failure; /* phy failure type */

	int			hme_64bit_xfer;	/* 64-bit Sbus xfers */
	int			hme_phyad;

	int			hme_nlasttries;
	int			hme_cheerio_mode;

	struct	ether_addr	hme_factaddr;	/* factory mac address */
	struct	ether_addr	hme_ouraddr;	/* individual address */
	uint32_t		hme_addrflags;	/* address flags */
	uint32_t		hme_flags;	/* misc. flags */
	boolean_t		hme_wantw;	/* xmit: out of resources */
	boolean_t		hme_started;	/* mac layer started */

	uint8_t			hme_devno;

	uint16_t		hme_ladrf[4];	/* 64 bit multicast filter */
	uint32_t		hme_ladrf_refcnt[64];
	boolean_t		hme_promisc;
	uint32_t		hme_multi;	/* refcount on mcast addrs */

	struct	hme_global	*hme_globregp;	/* HME global regs */
	struct	hme_etx		*hme_etxregp;	/* HME ETX regs */
	struct	hme_erx		*hme_erxregp;	/* HME ERX regs */
	struct	hme_bmac	*hme_bmacregp;	/* BigMAC registers */
	struct	hme_mif		*hme_mifregp;	/* HME transceiver */
	unsigned char		*hme_romp;	/* fcode rom pointer */

	kmutex_t	hme_xmitlock;		/* protect xmit-side fields */
	kmutex_t	hme_intrlock;		/* protect intr-side fields */
	ddi_iblock_cookie_t	hme_cookie;	/* interrupt cookie */

	struct	hme_rmd	*hme_rmdp;	/* receive descriptor ring start */
	struct	hme_tmd	*hme_tmdp;	/* transmit descriptor ring start */

	ddi_dma_handle_t	hme_rmd_dmah;
	ddi_acc_handle_t	hme_rmd_acch;
	caddr_t			hme_rmd_kaddr;
	uint32_t		hme_rmd_paddr;

	ddi_dma_handle_t	hme_tmd_dmah;
	ddi_acc_handle_t	hme_tmd_acch;
	caddr_t			hme_tmd_kaddr;
	uint32_t		hme_tmd_paddr;

	uint64_t		hme_rxindex;
	uint64_t		hme_txindex;
	uint64_t		hme_txreclaim;

	hmebuf_t		*hme_tbuf;	/* hmebuf associated with TMD */
	hmebuf_t		*hme_rbuf;	/* hmebuf associated with RMD */

	ddi_device_acc_attr_t	hme_dev_attr;
	ddi_acc_handle_t	hme_globregh;   /* HME global regs */
	ddi_acc_handle_t	hme_etxregh;    /* HME ETX regs */
	ddi_acc_handle_t	hme_erxregh;    /* HME ERX regs */
	ddi_acc_handle_t	hme_bmacregh;   /* BigMAC registers */
	ddi_acc_handle_t	hme_mifregh;    /* HME transceiver */
	ddi_acc_handle_t	hme_romh;	/* rom handle */

	ddi_acc_handle_t	pci_config_handle; /* HME PCI config */

	/*
	 * DDI dma handle, kernel virtual base,
	 * and io virtual base of IOPB area.
	 */
	ddi_dma_handle_t	hme_iopbhandle;
	ulong_t			hme_iopbkbase;
	uint32_t		hme_iopbiobase;

	kstat_t	*hme_ksp;	/* kstat pointer */
	kstat_t	*hme_intrstats;	/* kstat interrupt counter */

	uint64_t hme_ipackets;
	uint64_t hme_rbytes;
	uint64_t hme_ierrors;
	uint64_t hme_opackets;
	uint64_t hme_obytes;
	uint64_t hme_oerrors;
	uint64_t hme_multircv;		/* # multicast packets received */
	uint64_t hme_multixmt;		/* # multicast packets for xmit */
	uint64_t hme_brdcstrcv;		/* # broadcast packets received */
	uint64_t hme_brdcstxmt;		/* # broadcast packets for xmit */
	uint64_t hme_oflo;
	uint64_t hme_uflo;
	uint64_t hme_norcvbuf;		/* # rcv packets discarded */
	uint64_t hme_noxmtbuf;		/* # xmit packets discarded */
	uint64_t hme_duplex;
	uint64_t hme_align_errors;
	uint64_t hme_coll;
	uint64_t hme_fcs_errors;
	uint64_t hme_defer_xmts;
	uint64_t hme_sqe_errors;
	uint64_t hme_excol;
	uint64_t hme_fstcol;
	uint64_t hme_tlcol;
	uint64_t hme_toolong_errors;
	uint64_t hme_runt;
	uint64_t hme_carrier_errors;
	uint64_t hme_jab;

	uint32_t hme_cvc;
	uint32_t hme_lenerr;
	uint32_t hme_buff;
	uint32_t hme_missed;
	uint32_t hme_nocanput;
	uint32_t hme_allocbfail;
	uint32_t hme_babl;
	uint32_t hme_tmder;
	uint32_t hme_txlaterr;
	uint32_t hme_rxlaterr;
	uint32_t hme_slvparerr;
	uint32_t hme_txparerr;
	uint32_t hme_rxparerr;
	uint32_t hme_slverrack;
	uint32_t hme_txerrack;
	uint32_t hme_rxerrack;
	uint32_t hme_txtagerr;
	uint32_t hme_rxtagerr;
	uint32_t hme_eoperr;
	uint32_t hme_notmds;
	uint32_t hme_notbufs;
	uint32_t hme_norbufs;

	/*
	 * check if transmitter is hung
	 */
	uint32_t hme_starts;
	uint32_t hme_txhung;
	time_t hme_msg_time;

	/*
	 * Debuging kstats
	 */
	uint32_t inits;
	uint32_t phyfail;
	uint32_t asic_rev;
};

/* flags */
#define	HMERUNNING	0x01	/* chip is initialized */
#define	HMESUSPENDED	0x08	/* suspended interface */
#define	HMEINITIALIZED	0x10	/* interface initialized */

/* Mac address flags */

#define	HME_FACTADDR_PRESENT	0x01	/* factory MAC id present */
#define	HME_FACTADDR_USE	0x02	/* use factory MAC id */

struct	hmekstat {
	struct kstat_named	hk_cvc;		/* code violation  errors */
	struct kstat_named	hk_lenerr;	/* rx len errors */
	struct kstat_named	hk_buff;	/* buff errors */
	struct kstat_named	hk_missed;	/* missed/dropped packets */
	struct kstat_named	hk_nocanput;	/* nocanput errors */
	struct kstat_named	hk_allocbfail;	/* allocb failures */
	struct kstat_named	hk_babl;	/* runt errors */
	struct kstat_named	hk_tmder;	/* tmd errors */
	struct kstat_named	hk_txlaterr;	/* tx late errors */
	struct kstat_named	hk_rxlaterr;	/* rx late errors */
	struct kstat_named	hk_slvparerr;	/* slave parity errors */
	struct kstat_named	hk_txparerr;	/* tx parity errors */
	struct kstat_named	hk_rxparerr;	/* rx parity errors */
	struct kstat_named	hk_slverrack;	/* slave error acks */
	struct kstat_named	hk_txerrack;	/* tx error acks */
	struct kstat_named	hk_rxerrack;	/* rx error acks */
	struct kstat_named	hk_txtagerr;	/* tx tag error */
	struct kstat_named	hk_rxtagerr;	/* rx tag error */
	struct kstat_named	hk_eoperr;	/* eop error */
	struct kstat_named	hk_notmds;	/* tmd errors */
	struct kstat_named	hk_notbufs;	/* tx buf errors */
	struct kstat_named	hk_norbufs;	/* rx buf errors */

	struct kstat_named	hk_inits;		/* global inits */
	struct	kstat_named	hk_phyfail;		/* phy failures */

	struct	kstat_named	hk_asic_rev;		/* asic_rev */
};

#define	HMEDRAINTIME	(400000)	/* # microseconds xmit drain */

#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	ROUNDUP2(a, n)	(uchar_t *)((((uintptr_t)(a)) + ((n) - 1)) & ~((n) - 1))

/*
 * Xmit/receive buffer structure.
 * This structure is organized to meet the following requirements:
 * - bb_buf starts on an HMEBURSTSIZE boundary.
 * - hmebuf is an even multiple of HMEBURSTSIZE
 * - bb_buf[] is large enough to contain max VLAN frame (1522) plus
 *   (3 x HMEBURSTSIZE) rounded up to the next HMEBURSTSIZE
 * XXX What about another 128 bytes (HMEC requirement).
 * Fast aligned copy requires both the source and destination
 * addresses have the same offset from some N-byte boundary.
 */
#define		HMEBURSTSIZE	(64)
#define		HMEBURSTMASK	(HMEBURSTSIZE - 1)
#define		HMEBUFSIZE	(1728)

/*
 * Define offset from start of bb_buf[] to point receive descriptor.
 * Requirements:
 * - must be 14 bytes back of a 4-byte boundary so the start of
 *   the network packet is 4-byte aligned.
 * - leave some headroom for others
 */
#define		HMEHEADROOM	(34)

/* Offset for the first byte in the receive buffer */
#define	HME_FSTBYTE_OFFSET	2

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HME_H */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_HME_H
#define	_SYS_HME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	HME_IOC		0x60201ae1	/* random */
typedef struct {
	int		cmd;
	int		reserved[4];
} hme_ioc_hdr_t;

/* cmd */
#define	HME_IOC_GET_SPEED	0x100
#define	HME_IOC_SET_SPEED	0x110

/* mode */
#define	HME_AUTO_SPEED	0
#define	HME_FORCE_SPEED	1

/* speed */
#define	HME_SPEED_10		10
#define	HME_SPEED_100	100

typedef struct {
	hme_ioc_hdr_t	hdr;
	int		mode;
	int		speed;
} hme_ioc_cmd_t;

/* half-duplex or full-duplex mode */

#define	HME_HALF_DUPLEX	0
#define	HME_FULL_DUPLEX	1

#ifdef _KERNEL

/* Named Dispatch Parameter Management Structure */
typedef struct	hmeparam_s {
	uint32_t hme_param_min;
	uint32_t hme_param_max;
	uint32_t hme_param_val;
	char	*hme_param_name;
} hmeparam_t;


static hmeparam_t	hme_param_arr[] = {
	/* min		max		value		name */
	{  0,		1,		1,		"transceiver_inuse"},
	{  0,		1,		0,		"link_status"},
	{  0,		1,		0,		"link_speed"},
	{  0,		1,		0,		"link_mode"},
	{  0,		255,		8,		"ipg1"},
	{  0,		255,		4,		"ipg2"},
	{  0,		1,		0,		"use_int_xcvr"},
	{  0,		255,		0,		"pace_size"},
	{  0,		1,		1,		"adv_autoneg_cap"},
	{  0,		1,		1,		"adv_100T4_cap"},
	{  0,		1,		1,		"adv_100fdx_cap"},
	{  0,		1,		1,		"adv_100hdx_cap"},
	{  0,		1,		1,		"adv_10fdx_cap"},
	{  0,		1,		1,		"adv_10hdx_cap"},
	{  0,		1,		1,		"autoneg_cap"},
	{  0,		1,		1,		"100T4_cap"},
	{  0,		1,		1,		"100fdx_cap"},
	{  0,		1,		1,		"100hdx_cap"},
	{  0,		1,		1,		"10fdx_cap"},
	{  0,		1,		1,		"10hdx_cap"},
	{  0,		1,		0,		"lp_autoneg_cap"},
	{  0,		1,		0,		"lp_100T4_cap"},
	{  0,		1,		0,		"lp_100fdx_cap"},
	{  0,		1,		0,		"lp_100hdx_cap"},
	{  0,		1,		0,		"lp_10fdx_cap"},
	{  0,		1,		0,		"lp_10hdx_cap"},
	{  0,		255,		0,		"instance"},
	{  0,		1,		1,		"lance_mode"},
	{  0,		31,		16,		"ipg0"},
};


#define	hme_param_transceiver	(hmep->hme_param_arr[0].hme_param_val)
#define	hme_param_linkup	(hmep->hme_param_arr[1].hme_param_val)
#define	hme_param_speed		(hmep->hme_param_arr[2].hme_param_val)
#define	hme_param_mode		(hmep->hme_param_arr[3].hme_param_val)
#define	hme_param_ipg1		(hmep->hme_param_arr[4].hme_param_val)
#define	hme_param_ipg2		(hmep->hme_param_arr[5].hme_param_val)
#define	hme_param_use_intphy	(hmep->hme_param_arr[6].hme_param_val)
#define	hme_param_pace_count	(hmep->hme_param_arr[7].hme_param_val)
#define	hme_param_autoneg	(hmep->hme_param_arr[8].hme_param_val)
#define	hme_param_anar_100T4	(hmep->hme_param_arr[9].hme_param_val)
#define	hme_param_anar_100fdx	(hmep->hme_param_arr[10].hme_param_val)
#define	hme_param_anar_100hdx	(hmep->hme_param_arr[11].hme_param_val)
#define	hme_param_anar_10fdx	(hmep->hme_param_arr[12].hme_param_val)
#define	hme_param_anar_10hdx	(hmep->hme_param_arr[13].hme_param_val)
#define	hme_param_bmsr_ancap	(hmep->hme_param_arr[14].hme_param_val)
#define	hme_param_bmsr_100T4	(hmep->hme_param_arr[15].hme_param_val)
#define	hme_param_bmsr_100fdx	(hmep->hme_param_arr[16].hme_param_val)
#define	hme_param_bmsr_100hdx	(hmep->hme_param_arr[17].hme_param_val)
#define	hme_param_bmsr_10fdx	(hmep->hme_param_arr[18].hme_param_val)
#define	hme_param_bmsr_10hdx	(hmep->hme_param_arr[19].hme_param_val)
#define	hme_param_aner_lpancap	(hmep->hme_param_arr[20].hme_param_val)
#define	hme_param_anlpar_100T4	(hmep->hme_param_arr[21].hme_param_val)
#define	hme_param_anlpar_100fdx	(hmep->hme_param_arr[22].hme_param_val)
#define	hme_param_anlpar_100hdx	(hmep->hme_param_arr[23].hme_param_val)
#define	hme_param_anlpar_10fdx	(hmep->hme_param_arr[24].hme_param_val)
#define	hme_param_anlpar_10hdx	(hmep->hme_param_arr[25].hme_param_val)
#define	hme_param_device	(hmep->hme_param_arr[26].hme_param_val)
#define	hme_param_lance_mode	(hmep->hme_param_arr[27].hme_param_val)
#define	hme_param_ipg0		(hmep->hme_param_arr[28].hme_param_val)

#define	HME_PARAM_CNT	29


/* command */

#define	HME_ND_GET	ND_GET
#define	HME_ND_SET	ND_SET

/* default IPG settings */
#define	IPG1	8
#define	IPG2	4

/*
 * Declarations and definitions specific to the
 * FEPS 10/100 Mbps Ethernet (hme) device.
 */

/*
 * Definitions for module_info.
 */
#define		HMEIDNUM	(109)		/* module ID number */
#define		HMENAME		"hme"		/* module name */
#define		HMEMINPSZ	(0)		/* min packet size */
#define		HMEMAXPSZ	1514		/* max packet size */
#define		HMEHIWAT	(128 * 1024)	/* hi-water mark */
#define		HMELOWAT	(1)		/* lo-water mark */

/*
 * Per-Stream instance state information.
 *
 * Each instance is dynamically allocated at open() and free'd
 * at close().  Each per-Stream instance points to at most one
 * per-device structure using the sb_hmep field.  All instances
 * are threaded together into one list of active instances
 * ordered on minor device number.
 */


#define	NMCHASH	64			/* # of multicast hash buckets */
#define	INIT_BUCKET_SIZE	16	/* Initial Hash Bucket Size */

struct	hmestr {
	struct	hmestr	*sb_nextp;	/* next in list */
	queue_t	*sb_rq;			/* pointer to our rq */
	struct	hme *sb_hmep;		/* attached device */
	t_uscalar_t sb_state;		/* current DL state */
	t_scalar_t sb_sap;		/* bound sap */
	uint32_t sb_flags;		/* misc. flags */
	minor_t	sb_minor;		/* minor device number */

	struct	ether_addr
		*sb_mctab[NMCHASH];	/* Hash table of multicast addrs */
	uint32_t sb_mccount[NMCHASH];	/* # valid addresses in mctab[i] */
	uint32_t sb_mcsize[NMCHASH];	/* Allocated size of mctab[i] */

	uint16_t sb_ladrf[4];		/* Multicast filter bits */
	uint16_t sb_ladrf_refcnt[64];	/* Reference count for filter bits */

	kmutex_t	sb_lock;	/* protect this structure */
	uint32_t	sb_notifications;	/* DLPI notifications */
};


#define	MCHASH(a)	((*(((uchar_t *)(a)) + 0) ^		\
			*(((uchar_t *)(a)) + 1) ^		\
			*(((uchar_t *)(a)) + 2) ^		\
			*(((uchar_t *)(a)) + 3) ^		\
			*(((uchar_t *)(a)) + 4) ^		\
			*(((uchar_t *)(a)) + 5)) % (uint_t)NMCHASH)


/* per-stream flags */
#define	HMESFAST	0x01	/* "M_DATA fastpath" mode */
#define	HMESRAW		0x02	/* M_DATA plain raw mode */
#define	HMESALLPHYS	0x04	/* "promiscuous mode" */
#define	HMESALLMULTI	0x08	/* enable all multicast addresses */
#define	HMESALLSAP	0x10	/* enable all ether type values */

/*
 * Maximum # of multicast addresses per Stream.
 */
#define	HMEMAXMC	64
#define	HMEMCALLOC	(HMEMAXMC * sizeof (struct ether_addr))

/*
 * Maximum number of receive descriptors posted to the chip.
 */
#define	HMERPENDING	64

/*
 * Maximum number of transmit descriptors for lazy reclaim.
 */
#define	HMETPENDING	64

/*
 * Full DLSAP address length (in struct dladdr format).
 */
#define	HMEADDRL	(sizeof (ushort_t) + ETHERADDRL)

/*
 * Return the address of an adjacent descriptor in the given ring.
 */
#define	NEXTRMD(hmep, rmdp)	(((rmdp) + 1) == (hmep)->hme_rmdlimp	\
	? (hmep)->hme_rmdp : ((rmdp) + 1))
#define	NEXTTMD(hmep, tmdp)	(((tmdp) + 1) == (hmep)->hme_tmdlimp	\
	? (hmep)->hme_tmdp : ((tmdp) + 1))
#define	PREVTMD(hmep, tmdp)	((tmdp) == (hmep)->hme_tmdp		\
	? ((hmep)->hme_tmdlimp - 1) : ((tmdp) - 1))

#define	MSECOND(t)	t
#define	SECOND(t)	t*1000
#define	HME_TICKS	MSECOND(100)

#define	HME_LINKCHECK_TIMER	SECOND(30)

#define	HME_2P0_REVID		0xa0 /* hme - feps. */
#define	HME_2P1_REVID		0x20
#define	HME_2P1_REVID_OBP	0x21
#define	HME_1C0_REVID		0xc0 /* cheerio 1.0, hme 2.0 equiv. */
#define	HME_2C0_REVID		0xc1 /* cheerio 2.0, hme 2.2 equiv. */
#define	HME_REV_VERS_MASK	0x0f /* Mask to retain bits for cheerio ver */

#define	HME_NTRIES_LOW		(SECOND(5)/HME_TICKS)	/* 5 Seconds */
#define	HME_NTRIES_HIGH		(SECOND(5)/HME_TICKS)	/* 5 Seconds */
#define	HME_NTRIES_LOW_10	(SECOND(2)/HME_TICKS)	/* 2 Seconds */
#define	HME_LINKDOWN_TIME	(SECOND(2)/HME_TICKS)	/* 2 Seconds */

#define	HME_LINKDOWN_OK		0
#define	HME_FORCE_LINKDOWN	1
#define	HME_LINKDOWN_STARTED	2
#define	HME_LINKDOWN_DONE	3

#define	P1_0    0x100

#define	HME_EXTERNAL_TRANSCEIVER	0
#define	HME_INTERNAL_TRANSCEIVER	1
#define	HME_NO_TRANSCEIVER		2

#define	HME_HWAN_TRY		0 /* Try Hardware autonegotiation */
#define	HME_HWAN_INPROGRESS	1 /* Hardware autonegotiation in progress */
#define	HME_HWAN_SUCCESFUL	2 /* Hardware autonegotiation succesful */
#define	HME_HWAN_FAILED		3 /* Hardware autonegotiation failed */

#define	RESET_TO_BE_ISSUED	0 /* Reset command to be issued to the PHY */
#define	RESET_ISSUED		1 /* Reset command has been issued */
#define	ISOLATE_ISSUED		2 /* Isolate-remove command has been issued */
#define	POWER_OFF_ISSUED	3 /* The QSI Phy may have problems with */
					/* Power rampup. Issue powerdown in   */
					/* the driver to insure good reset.   */
struct	hmesave {
	ulong_t		hme_starts;
	uint32_t	hme_opackets;
};

/*
 * HME Device Channel instance state information.
 *
 * Each instance is dynamically allocated on first attach.
 */
struct	hme {
	struct	hme		*hme_nextp;	/* next in a linked list */
	dev_info_t		*dip;		/* associated dev_info */
	int			instance;	/* instance */
	ulong_t			pagesize;	/* btop(9F) */

	/*
	 * xcvr information
	 */
	uint16_t		xcvr_dev_id;	/* Device Model */
	uint16_t		xcvr_dev_rev;	/* Device Rev.  */
	uint16_t		hme_idr1;	/* PHY IDR1 register */
	uint16_t		hme_idr2;	/* PHY IDR2 register */
	uint16_t		hme_anar;	/* PHY ANAR register */
	uint16_t		hme_anlpar;	/* PHY ANLPAR register */
	uint16_t		hme_aner;	/* PHY ANER register */

	uint32_t		promisc_phys_cnt;  /* Promiscous streams open */
	uint32_t		promisc_multi_cnt;
	int			hme_mifpoll_enable;
	int			hme_frame_enable;
	int			hme_lance_mode_enable;
	int			hme_rxcv_enable;

	uint_t			hme_burstsizes; /* binary encoded val */
	uint32_t		hme_config;	/* Config reg store */

	int			hme_phy_retries; /* phy reset failures */
	int			hme_phy_failure; /* phy failure type */

	int			hme_64bit_xfer;	/* 64-bit Sbus xfers */
	int			hme_phyad;
	int			hme_autoneg;

	caddr_t			hme_g_nd;	/* head of the */
						/* named dispatch table */
	hmeparam_t		hme_param_arr[HME_PARAM_CNT];
	int			hme_transceiver;  /* current PHY in use */
	int			hme_link_pulse_disabled;
	uint16_t		hme_bmcr;	/* PHY control register */
	uint16_t		hme_bmsr;	/* PHY status register */
	int			hme_mode;	/* auto/forced mode */
	int			hme_linkup;	/* link status */
	int			hme_xcvr_state; /* transceiver status */
	int			hme_forcespeed; /* speed in forced mode */
	int			hme_tryspeed;	/* speed in auto mode */
	int			hme_fdx;	/* full-duplex mode */
	int			hme_pace_count;	/* pacing pkt count */

	int			hme_macfdx;
	int			hme_linkcheck;
	int			hme_linkup_msg;
	int			hme_force_linkdown;
	int			hme_nlasttries;
	int			hme_ntries;
	int			hme_delay;
	int			hme_linkup_10;
	int			hme_linkup_cnt;
	timeout_id_t		hme_timerid;
	int			hme_cheerio_mode;
	int			hme_polling_on;
	int			hme_mifpoll_data;
	int			hme_mifpoll_flag;

	/*
	 * This is part of the hardening of the hme driver
	 * (following x fields)
	 */
	ushort_t		hme_disabled;

	struct	ether_addr	hme_factaddr;	/* factory mac address */
	struct	ether_addr	hme_ouraddr;	/* individual address */
	uint32_t		hme_addrflags;	/* address flags */
	uint32_t		hme_flags;	/* misc. flags */
	uint32_t		hme_wantw;	/* xmit: out of resources */

	volatile struct	hme_global	*hme_globregp;	/* HME global regs */
	volatile struct	hme_etx		*hme_etxregp;	/* HME ETX regs */
	volatile struct	hme_erx		*hme_erxregp;	/* HME ERX regs */
	volatile struct	hme_bmac	*hme_bmacregp;	/* BigMAC registers */
	volatile struct	hme_mif		*hme_mifregp;	/* HME transceiver */
	unsigned char		*hme_romp;	/* fcode rom pointer */

	kmutex_t	hme_xmitlock;		/* protect xmit-side fields */
	kmutex_t	hme_intrlock;		/* protect intr-side fields */
	kmutex_t	hme_linklock;		/* protect link-side fields */
	ddi_iblock_cookie_t	hme_cookie;	/* interrupt cookie */

	struct	hme_rmd	*hme_rmdp;	/* receive descriptor ring start */
	struct	hme_rmd	*hme_rmdlimp;	/* receive descriptor ring end */
	struct	hme_tmd	*hme_tmdp;	/* transmit descriptor ring start */
	struct	hme_tmd	*hme_tmdlimp;	/* transmit descriptor ring end */
	volatile struct	hme_rmd	*hme_rnextp;	/* next chip rmd */
	volatile struct	hme_rmd	*hme_rlastp;	/* last free rmd */
	volatile struct	hme_tmd	*hme_tnextp;	/* next free tmd */
	volatile struct	hme_tmd	*hme_tcurp;	/* next tmd to reclaim (used) */

	mblk_t	*hme_tmblkp[HME_TMDMAX];	/* hmebuf associated with TMD */
	mblk_t	*hme_rmblkp[HME_RMDMAX];	/* hmebuf associated with RMD */

	queue_t	*hme_ip4q;		/* IPv4 read queue */
	queue_t	*hme_ip6q;		/* IPv6 read queue */

	ddi_device_acc_attr_t	hme_dev_attr;
	ddi_acc_handle_t	hme_globregh;   /* HME global regs */
	ddi_acc_handle_t	hme_etxregh;    /* HME ETX regs */
	ddi_acc_handle_t	hme_erxregh;    /* HME ERX regs */
	ddi_acc_handle_t	hme_bmacregh;   /* BigMAC registers */
	ddi_acc_handle_t	hme_mifregh;    /* HME transceiver */
	ddi_dma_cookie_t	hme_md_c;	/* trmd dma cookie */
	ddi_acc_handle_t	hme_mdm_h;	/* trmd memory handle */
	ddi_dma_handle_t	hme_md_h;	/* trmdp dma handle */
	ddi_acc_handle_t	hme_romh;	/* rom handle */

	ddi_acc_handle_t	pci_config_handle; /* HME PCI config */

	/*
	 * DDI dma handle, kernel virtual base,
	 * and io virtual base of IOPB area.
	 */
	ddi_dma_handle_t	hme_iopbhandle;
	ulong_t			hme_iopbkbase;
	ulong_t			hme_iopbiobase;

	/*
	 * these are handles for the dvma resources reserved
	 * by dvma_reserve
	 */
	ddi_dma_handle_t	hme_dvmarh;	/* dvma recv handle */
	ddi_dma_handle_t	hme_dvmaxh;	/* dvma xmit handle */

	/*
	 * these are used if dvma reserve fails, and we have to fall
	 * back on the older ddi_dma_addr_setup routines
	 */
	ddi_dma_handle_t	*hme_dmarh;
	ddi_dma_handle_t	*hme_dmaxh;

	kstat_t	*hme_ksp;	/* kstat pointer */
	kstat_t	*hme_intrstats;	/* kstat interrupt counter */
	uint32_t intr_mask;	/* Interrupt mask. */
	uint32_t hme_iipackets;	/* Used to store the Count of packets */
				/* recieved at the start of 'hme_check_link' */
				/* watch dog interval. */

	uint32_t hme_ipackets;
	uint32_t hme_ierrors;
	uint32_t hme_opackets;
	uint32_t hme_oerrors;
	uint32_t hme_coll;
	uint32_t hme_defer;
	uint32_t hme_fram;
	uint32_t hme_crc;
	uint32_t hme_sqerr;
	uint32_t hme_cvc;
	uint32_t hme_lenerr;
	uint64_t hme_ifspeed;	/* ifspeed is now in bits/sec	*/
	uint32_t hme_buff;
	uint32_t hme_oflo;
	uint32_t hme_uflo;
	uint32_t hme_missed;
	uint32_t hme_tlcol;
	uint32_t hme_trtry;
	uint32_t hme_fstcol;
	uint32_t hme_nocanput;
	uint32_t hme_allocbfail;
	uint32_t hme_runt;
	uint32_t hme_jab;
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
	uint32_t hme_clsn;

	/*
	 * check if transmitter is hung
	 */
	uint32_t hme_starts;
	uint32_t hme_txhung;
	time_t hme_msg_time;
	struct hmesave hmesave;

	/*
	 * MIB II variables
	 */
	uint32_t hme_rcvbytes;		/* # bytes received */
	uint32_t hme_xmtbytes;		/* # bytes transmitted */
	uint32_t hme_multircv;		/* # multicast packets received */
	uint32_t hme_multixmt;		/* # multicast packets for xmit */
	uint32_t hme_brdcstrcv;		/* # broadcast packets received */
	uint32_t hme_brdcstxmt;		/* # broadcast packets for xmit */
	uint32_t hme_norcvbuf;		/* # rcv packets discarded */
	uint32_t hme_noxmtbuf;		/* # xmit packets discarded */
	uint32_t hme_newfree;

	/*
	 * PSARC 1997/198 : 64bit kstats
	 */
	uint64_t hme_ipackets64;
	uint64_t hme_opackets64;
	uint64_t hme_rbytes64;
	uint64_t hme_obytes64;

	/*
	 * PSARC 1997/247 : RFC 1643
	 */
	uint32_t hme_align_errors;
	uint32_t hme_fcs_errors;
	uint32_t hme_multi_collisions;
	uint32_t hme_sqe_errors;
	uint32_t hme_defer_xmts;
	uint32_t hme_ex_collisions;
	uint32_t hme_macxmt_errors;
	uint32_t hme_carrier_errors;
	uint32_t hme_toolong_errors;
	uint32_t hme_macrcv_errors;

	/*
	 * RFE's (Request for Enhancements)
	 */
	uint32_t link_duplex;
	/*
	 * Debuging kstats
	 */
	uint32_t inits;
	uint32_t rxinits;
	uint32_t txinits;
	uint32_t dmarh_init;
	uint32_t dmaxh_init;
	uint32_t link_down_cnt;
	uint32_t phyfail;
	uint32_t xcvr_vendor_id;	/* Vendor ID    */
	uint32_t asic_rev;

	/* Link Status */
	uint32_t hme_link_up;
};

/* flags */
#define	HMERUNNING	0x01	/* chip is initialized */
#define	HMEPROMISC	0x02	/* promiscuous mode enabled */
#define	HMESUSPENDED	0x08	/* suspended interface */
#define	HMEINITIALIZED	0x10	/* interface initialized */
#define	HMENOTIMEOUTS	0x20	/* disallow timeout rescheduling */

/* Mac address flags */

#define	HME_FACTADDR_PRESENT	0x01	/* factory MAC id present */
#define	HME_FACTADDR_USE	0x02	/* use factory MAC id */

struct	hmekstat {
	struct kstat_named	hk_ipackets;	/* packets received */
	struct kstat_named	hk_ierrors;	/* input errors */
	struct kstat_named	hk_opackets;	/* packets transmitted */
	struct kstat_named	hk_oerrors;	/* output errors */
	struct kstat_named	hk_coll;	/* collisions encountered */
	struct kstat_named	hk_defer;	/* slots deferred */
	struct kstat_named	hk_fram;	/* framing errors */
	struct kstat_named	hk_crc;		/* crc errors */
	struct kstat_named	hk_sqerr;	/* SQE test  errors */
	struct kstat_named	hk_cvc;		/* code violation  errors */
	struct kstat_named	hk_lenerr;	/* rx len errors */
	struct kstat_named	hk_ifspeed;	/* interface speed */
	struct kstat_named	hk_buff;	/* buff errors */
	struct kstat_named	hk_oflo;	/* overflow errors */
	struct kstat_named	hk_uflo;	/* underflow errors */
	struct kstat_named	hk_missed;	/* missed/dropped packets */
	struct kstat_named	hk_tlcol;	/* late collisions */
	struct kstat_named	hk_trtry;	/* retry errors */
	struct kstat_named	hk_fstcol;	/* first collisions */
	struct kstat_named	hk_nocanput;	/* nocanput errors */
	struct kstat_named	hk_allocbfail;	/* allocb failures */
	struct kstat_named	hk_runt;	/* runt errors */
	struct kstat_named	hk_jab;		/* jabber errors */
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
	struct kstat_named	hk_clsn;	/* clsn errors */

	/*
	 * required by kstat for MIB II objects (RFC 1213)
	 */
	struct  kstat_named	hk_rcvbytes; 	/* # octets received */
						/* MIB - ifInOctets */
	struct  kstat_named	hk_xmtbytes; 	/* # octets transmitted */
						/* MIB - ifOutOctets */
	struct  kstat_named	hk_multircv; 	/* # multicast packets */
						/* delivered to upper layer */
						/* MIB - ifInNUcastPkts */
	struct  kstat_named	hk_multixmt; 	/* # multicast packets */
						/* requested to be sent */
						/* MIB - ifOutNUcastPkts */
	struct  kstat_named	hk_brdcstrcv;	/* # broadcast packets */
						/* delivered to upper layer */
						/* MIB - ifInNUcastPkts */
	struct  kstat_named	hk_brdcstxmt;	/* # broadcast packets */
						/* requested to be sent */
						/* MIB - ifOutNUcastPkts */
	struct  kstat_named	hk_norcvbuf; 	/* # rcv packets discarded */
						/* MIB - ifInDiscards */
	struct  kstat_named	hk_noxmtbuf; 	/* # xmt packets discarded */
						/* MIB - ifOutDiscards */


	struct	kstat_named	hk_newfree;	/* new freemsg */

	/*
	 * PSARC 1997/198
	 */
	struct kstat_named	hk_ipackets64;	/* packets received */
	struct kstat_named	hk_opackets64;	/* packets transmitted */
	struct kstat_named	hk_rbytes64;	/* bytes received */
	struct kstat_named	hk_obytes64;	/* bytes transmitted */

	/*
	 * PSARC 1997/247 : RFC 1643
	 *						SNMP Variables
	 *						dot3Stats
	 */
	struct	kstat_named	hk_align_errors;	/* AlignErr */
	struct	kstat_named	hk_fcs_errors;		/* StatsFCSErr */
	/* first_collisions */
	struct	kstat_named	hk_multi_collisions;	/* MultiCollFrames */
	struct	kstat_named	hk_sqe_errors;		/* QETestErrors	*/
	struct	kstat_named	hk_defer_xmts;		/* Deferred Xmits */
	/* tx_late_collisions */
	struct	kstat_named	hk_ex_collisions;	/* ExcessiveColls */
	struct	kstat_named	hk_macxmt_errors;	/* InternMacXmitErr */
	struct	kstat_named	hk_carrier_errors;	/* CarrierSenseErr */
	struct	kstat_named	hk_toolong_errors;	/* FrameTooLongs */
	struct	kstat_named	hk_macrcv_errors;	/* InternalMacRcvErr */
	struct kstat_named	hk_link_duplex;		/* link_duplex */
	struct kstat_named	hk_inits;		/* global inits */
	struct kstat_named	hk_rxinits;		/* recv inits */
	struct kstat_named	hk_txinits;		/* xmit inits */
	struct	kstat_named	hk_dmarh_inits;	/* dma read handle inits */
	struct	kstat_named	hk_dmaxh_inits;	/* dma xmit handle inits */
	struct	kstat_named	hk_link_down_cnt;	/* link down count */
	struct	kstat_named	hk_phyfail;		/* phy failures */

	struct	kstat_named	hk_xcvr_vendor_id;	/* xcvr_vendor_id */
	struct	kstat_named	hk_asic_rev;		/* asic_rev */
	struct	kstat_named	hk_link_up;		/* Link Status */
};

#define	HMEDRAINTIME	(400000)	/* # microseconds xmit drain */

#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	ROUNDUP2(a, n)	(uchar_t *)((((uintptr_t)(a)) + ((n) - 1)) & ~((n) - 1))

/*
 * Xmit/receive buffer structure.
 * This structure is organized to meet the following requirements:
 * - bb_buf starts on an HMEBURSTSIZE boundary.
 * - hmebuf is an even multiple of HMEBURSTSIZE
 * - bb_buf[] is large enough to contain max frame (1518) plus
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

/*
 * Private DLPI full dlsap address format.
 */
struct	hmedladdr {
	struct	ether_addr	dl_phys;
	ushort_t		dl_sap;
};
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HME_H */

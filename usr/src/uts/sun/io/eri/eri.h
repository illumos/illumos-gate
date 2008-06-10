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

#ifndef	_SYS_ERI_H
#define	_SYS_ERI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef _KERNEL

/* Named Dispatch Parameter Management Structure */
typedef struct param_s {
	uint32_t param_min;
	uint32_t param_max;
	uint32_t param_val;
	char   *param_name;
} param_t;

#define	ERI_PARAM_CNT	51

typedef enum  {
	MIF_POLL_STOP,
	MIF_POLL_START
} soft_mif_enable_t;


/*
 * kstats
 */
typedef struct stats {
	/*
	 * Link Input/Output stats
	 * ifspeed is now in bits/second.
	 */
	uint64_t	ipackets64;
	uint64_t	iipackets64;
	uint32_t	ierrors;
	uint64_t	opackets64;
	uint64_t	oerrors;
	uint32_t	collisions;
	uint64_t	ifspeed;

	/*
	 * MAC TX Event stats
	 */
	uint32_t	txmac_urun;
	uint32_t	txmac_maxpkt_err;
	uint32_t	excessive_coll;
	uint32_t	late_coll;
	uint32_t	first_coll;
	uint32_t	defer_timer_exp;
	uint32_t	peak_attempt_cnt;
	uint32_t	tx_hang;

	/*
	 * MAC RX Event stats
	 */
	uint32_t	rx_corr;
	uint32_t	no_free_rx_desc;	/* no free rx desc. */
	uint32_t	rx_overflow;
	uint32_t	rx_ovrflpkts;
	uint32_t	rx_hang;
	uint32_t	rx_align_err;
	uint32_t	rx_crc_err;
	uint32_t	rx_length_err;
	uint32_t	rx_code_viol_err;

	/*
	 * MAC Control event stats
	 */
	uint32_t	pause_rxcount;	/* PAUSE Receive cnt */
	uint32_t	pause_oncount;
	uint32_t	pause_offcount;
	uint32_t	pause_time_count;
	uint32_t	pausing;

	/*
	 * Software event stats
	 */
	uint32_t	inits;
	uint32_t	rx_inits;
	uint32_t	tx_inits;
	uint32_t	tnocar;	/* Link down counter */

	uint32_t	jab;
	uint32_t	notmds;
	uint32_t	nocanput;
	uint32_t	allocbfail;
	uint32_t	drop;
	uint32_t	rx_corrupted;
	uint32_t	rx_bad_pkts;
	uint32_t	rx_runt;
	uint32_t	rx_toolong_pkts;


	/*
	 * Fatal errors
	 */
	uint32_t	rxtag_err;

	/*
	 * parity error
	 */
	uint32_t	parity_error;

	/*
	 * Fatal error stats
	 */
	uint32_t	pci_error_int;	/* PCI error interrupt */
	uint32_t	unknown_fatal;	/* unknown fatal errors */

	/*
	 * PCI Configuration space staus register
	 */
	uint32_t	pci_data_parity_err;	/* Data parity err */
	uint32_t	pci_signal_target_abort;
	uint32_t	pci_rcvd_target_abort;
	uint32_t	pci_rcvd_master_abort;
	uint32_t	pci_signal_system_err;
	uint32_t	pci_det_parity_err;

	/*
	 * MIB II variables
	 */
	uint64_t	rbytes64;	/* # bytes received */
	uint64_t	obytes64;	/* # bytes transmitted */
	uint32_t	multircv;	/* # multicast packets received */
	uint32_t	multixmt;	/* # multicast packets for xmit */
	uint32_t	brdcstrcv;	/* # broadcast packets received */
	uint32_t	brdcstxmt;	/* # broadcast packets for xmit */
	uint32_t	norcvbuf;	/* # rcv packets discarded */
	uint32_t	noxmtbuf;	/* # xmit packets discarded */

	uint32_t	pmcap;		/* power management */

	/*
	 * Link Status
	 */
	uint32_t	link_up;
	uint32_t	link_duplex;
} stats_t;

#define	HSTAT(erip, x)		erip->stats.x++;
#define	HSTATN(erip, x, n)	erip->stats.x += n;


#define	TX_BCOPY_MAX		704	/* bcopy for packets < 704 bytes */
#define	RX_BCOPY_MAX		704	/* bcopy for packets < 704 bytes */
#define	TX_STREAM_MIN		512

/*
 * Per-Stream instance state information.
 *
 * Each instance is dynamically allocated at open() and free'd
 * at close().  Each per-Stream instance points to at most one
 * per-device structure using the sb_erip field.  All instances
 * are threaded together into one list of active instances
 * ordered on minor device number.
 */

#define	NMCFILTER_BITS	256		/* # of multicast filter bits */


/*
 * Maximum number of receive descriptors posted to the chip.
 */
#define	ERI_RPENDING		(erip->rpending)

/*
 * Maximum number of transmit descriptors for lazy reclaim.
 */
#define	ERI_TPENDING	(erip->tpending)

/*
 * Return the address of an adjacent descriptor in the given ring.
 */
#define	NEXTRMD(erip, rmdp)	(((rmdp) + 1) == (erip)->rmdlimp ?	\
	(erip)->rmdp : ((rmdp) + 1))
#define	NEXTTMD(erip, tmdp)	(((tmdp) + 1) == (erip)->eri_tmdlimp ?	\
	(erip)->eri_tmdp : ((tmdp) + 1))
#define	PREVTMD(erip, tmdp)	((tmdp) == (erip)->eri_tmdp ?		\
	((erip)->eri_tmdlimp - 1) : ((tmdp) - 1))

#define	MSECOND(t)	t
#define	SECOND(t)	t*1000
#define	ERI_TICKS	MSECOND(100)

#define	ERI_NTRIES_LOW		(SECOND(5)/ERI_TICKS)   /* 5 Seconds */
#define	ERI_NTRIES_HIGH		(SECOND(5)/ERI_TICKS)   /* 5 Seconds */
#define	ERI_NTRIES_LOW_10	(SECOND(2)/ERI_TICKS)   /* 2 Seconds */
#define	ERI_LINKDOWN_TIME	(SECOND(2)/ERI_TICKS)   /* 2 Seconds */


/*
 * ERI ASIC Revision Numbers
 */
#define	ERI_ERIREV_1_0	0x1

/*
 * Link poll interval for detecting change of transceivers
 */
#define	ERI_LINKCHECK_TIMER	SECOND(3)

/*
 * Parallel detection Fault restart timer
 */
#define	ERI_P_FAULT_TIMER	SECOND(3)

/*
 * Check rmac hang restart timer
 */
#define	ERI_CHECK_HANG_TIMER	MSECOND(400)
#define	ERI_RMAC_HANG_WORKAROUND

/*
 * undefine ERI_PM_WORKAROUND this time. With ERI_PM_WORKAROUND defined,
 * each non_fatal error causes pci clock to go up for 30 seconds. Therefore,
 * no TXMAC_UNDERRUN or excessive RXFIFO_OVERFLOW should happen.
 */


/*
 * Link bringup modes
 */
#define	ERI_AUTO_BRINGUP	0
#define	ERI_FORCED_BRINGUP	1

/*
 * Transceivers selected for use by the driver.
 */
#define	NO_XCVR		2
#define	INTERNAL_XCVR	0
#define	EXTERNAL_XCVR	1

/*
 * states for manually creating the link down condition
 */
#define	ERI_LINKDOWN_OK		0
#define	ERI_FORCE_LINKDOWN	1
#define	ERI_LINKDOWN_STARTED	2
#define	ERI_LINKDOWN_DONE	3

/*
 * states for bringing up the link in auto-negotiation mode
 */
#define	ERI_HWAN_TRY		0 /* Try Hardware autonegotiation */
#define	ERI_HWAN_INPROGRESS	1 /* Hardware autonegotiation in progress */
#define	ERI_HWAN_SUCCESFUL	2 /* Hardware autonegotiation succesful */
#define	ERI_HWAN_FAILED		3 /* Hardware autonegotiation failed */

/*
 * states for resetting the transceiver
 */
#define	RESET_TO_BE_ISSUED	0 /* Reset command to be issued to the PHY */
#define	RESET_ISSUED		1 /* Reset command has been issued */
#define	ISOLATE_ISSUED		2 /* Isolate-remove command has been issued */

/*
 * ERI Supported PHY devices
 * ERI ASIC supports a built in Gigabit Serial LInk Interface and MII
 * External SERDES interfaces with shared pins.
 * On some product implementations, the built-in Serial Link may not be present
 * either because the Serial Link circuitry does not work or because the product
 * needs to use only the MII interface.
 * When both the Serial Link and MII PHY's are present, the driver normally
 * tries to bring up both the links. If both of them come up, it will select the
 * link defined by the "eri_default_link" variable by default.
 * The user may use the configuration variable
 * eri_select_link to manually select
 * either the Serial Link or the MII PHY to be used.
 */

/*
 * Values for the eri_serial_link field
 */
#define	ERI_SERIAL_LINK_NOT_PRESENT	0
#define	ERI_SERIAL_LINK_PRESENT		1

/*
 * Values for the eri_non-serial-link field
 */
#define	ERI_NO_SHARED_PIN_PHY		0
#define	ERI_MII_PRESENT			1
#define	ERI_SERDES_PRESENT		2

/*
 * Values for the default selection when both the serial link and
 * the MII links are present.
 */
#define	ERI_DEFAULT_SERIAL_LINK	0
#define	ERI_DEFAULT_MII_LINK	1

/*
 * Values for the eri_select_link field to manually select the PHY
 */
#define	ERI_AUTO_PHY			0	/* Select PHY automatically */
#define	ERI_USE_SERIAL_LINK		1	/* Select serial-link */
#define	ERI_USE_NON_SERIAL_LINK		2	/* Select non-serial-link */

/*
 * eri_linkup_state" definitions
 */
#define	ERI_START_LINK_BRINGUP	0
#define	ERI_SERIAL_LINK_BRINGUP	1
#define	ERI_SERDES_LINK_BRINGUP	2
#define	ERI_MII_LINK_BRINGUP	3
#define	ERI_DEFAULT_LINK_BRINGUP	4
#define	ERI_ALT_LINK_BRINGUP	5

/*
 * structure used to detect tx hang condition
 */
struct	erisave {
	ulong_t	starts;		  /* # of tx packets posted to the hw */
	uint64_t reclaim_opackets; /* # of tx packets reclaimed */
};

/*
 * ERI Device Channel instance state information.
 *
 * Each instance is dynamically allocated on first attach.
 */
struct	eri {
	mac_handle_t		mh;		/* GLDv3 handle */
	dev_info_t		*dip;		/* associated dev_info */
	uint_t			instance;	/* instance */

	int			pci_mode;	/* sbus/pci device (future) */
	int			cpci_mode;	/* compact pci dev (future) */
	int			low_power_mode; /* E* (low power) */
	int			asic_rev;	/* ERI ASIC rev no. */
	int			board_rev;	/* ERI ASIC rev no. */
	int			burstsizes;	/* binary encoded val */
	int			pagesize;	/* btop(9f) */
	uint32_t		rxfifo_size;	/* RX FIFO size */

	int			rpending;	/* Max.no. of RX bufs post */
	int			tpending;	/* Max.no. of tX bufs post */
	int			tx_cur_cnt;	/* # of packets for int_me */

	uint_t			multi_refcnt;
	boolean_t		promisc;

	int			mifpoll_enable;
	int			frame_enable;
	int			lance_mode_enable;
	int			ngu_enable;
	int			link_pulse_disabled;
	int			xmit_dma_mode;
	int			rcv_dma_mode;
	uint8_t			ouraddr[ETHERADDRL];	/* unicast address */
	uint32_t		flags;		/* misc. flags */
	uint32_t		alloc_flag;	/* Buff alloc. status flags */
	boolean_t		wantw;		/* xmit: out of resources */

	uint16_t		ladrf[NMCFILTER_BITS/16]; /* Multicast filter */
	uint16_t		ladrf_refcnt[NMCFILTER_BITS];

	volatile struct	global	*globregp;	/* ERI global regs */
	volatile struct	etx	*etxregp;	/* ERI ETX regs */
	volatile struct	erx	*erxregp;	/* ERI ERX regs */

	volatile struct	bmac	*bmacregp;	/* MAC regs */
	volatile struct	mif	*mifregp;	/* ERI transceiver */
	volatile struct	pcslink	*pcsregp;	/* ERI PCS regs */

	uint32_t		*sw_reset_reg;

	uint32_t		rx_kick;	/* RX kick register val */
	uint32_t		rx_completion;	/* RX completion reg val */
#ifdef	RCV_OVRFLOW_CORRUPTION_BUG
	uint32_t		rx_ovrflpks;	/* RX recompute checksum */
#endif
	uint32_t		tx_kick;	/* TX kick register val */
	uint32_t		tx_completion;	/* TX completion reg val */

	struct	rmd		*rmdp;		/* rcv descript  ring start */
	struct	rmd		*rmdlimp;	/* rcv  descript ring end */
	struct	eri_tmd		*eri_tmdp;	/* xmit descript ring start */
	struct	eri_tmd		*eri_tmdlimp;	/* xmit descript ring end */
	volatile struct	rmd	*rnextp;	/* next chip rmd */
	volatile struct	rmd	*rlastp;	/* last free rmd */
	volatile struct	eri_tmd	*tnextp;	/* next free tmd */

	volatile struct	eri_tmd	*tcurp;	/* nxt tmd to reclaim(used) */
	/*
	 * these are handles for the dvma resources reserved
	 * by dvma_reserve
	 */
	ddi_dma_handle_t	eri_dvmarh;	/* dvma recv handle */
	ddi_dma_handle_t	eri_dvmaxh;	/* dvma xmit handle */

	/*
	 * these are used if dvma reserve fails, and we have to fall
	 * back on the older ddi_dma_addr_setup routines
	 */
	ddi_dma_handle_t	ndmarh[ERI_RMDMAX];
	ddi_dma_handle_t	ndmaxh[ERI_TMDMAX];

	ddi_dma_handle_t	tbuf_handle;
	caddr_t			tbuf_kaddr;
	uint32_t		tbuf_ioaddr;

	int			rcv_handle_cnt;
	int			xmit_handle_cnt;

	int			rx_reset_issued;
	int			tx_reset_issued;
	int			rxmac_reset_issued;
	int			txmac_reset_issued;

	int			global_reset_issued;
	uint32_t		rpending_mask;
	int			rmdmax_mask;
	int			init_macregs;

	int			phyad;	/* addr of the PHY in use */
	int			xcvr;  /* current PHY in use */

	int			openloop_autoneg;

	uint16_t		mif_config;
	uint16_t		mif_mask;

	uint32_t		tx_config;

	uint32_t		vendor_id;	/* Vendor ID	*/
	uint16_t		device_id;	/* Device Model	*/
	uint16_t		device_rev;	/* Device Rev.	*/
	uint32_t		phy_address;	/* PHY Address	*/
	uint32_t		xcvr_status;	/* xcvr_status	*/
	uint32_t		xcvr_state;	/* xcvr_state	*/
	uint32_t		bringup_mode;	/* Bringup Mode	*/
	uint32_t		speed;		/* Current speed */
	uint32_t		duplex;		/* Xcvr Duplex	*/
	uint32_t		capability;	/* Xcvr Capability */

	uint16_t		mii_control;
	uint16_t		mii_status;
	uint16_t		mii_anar;
	uint16_t		mii_lpanar;

	int			autoneg;
	int			force_linkdown;
	int			mode;

	int			linkup_10;
	int			pace_count;	/* pacing pkt count */

	int			nlasttries;
	int			ntries;
	int			delay;
	int			linkup_attempts;

	int			polling_on;
	int			mifpoll_data;
	int			mifpoll_flag; /* indicates MIF intr */

	int			pauseTX;	/* pcs link-pause TX enable */
	int			pauseRX;	/* pcs link-pause RX enable */
	int			macfdx;	/* mac full-duplex mode */
	timeout_id_t		timerid;	/* timer id for links */
	int			linkup_cnt;

	uint16_t		aner;	/* MII ANER register */

	int			linkup;		/* selected link status */
	int			linkup_state; /* link bringup state */
	int			linkup_changed; /* link bringup state */

	int			linkcheck;
	caddr_t			g_nd;	/* head of the */
						/* named dispatch table */

	ddi_device_acc_attr_t	dev_attr;
	ddi_iblock_cookie_t	cookie;	/* interrupt cookie */
	ddi_acc_handle_t	globregh;   /* ERI global regs */
	ddi_acc_handle_t	etxregh;    /* ERI ETX regs */
	ddi_acc_handle_t	erxregh;    /* ERI ERX regs */
	ddi_acc_handle_t	bmacregh;   /* BigMAC registers */
	ddi_acc_handle_t	mifregh;    /* ERI transceiver */
	ddi_acc_handle_t	pcsregh;    /* ERI PCS regs */

	ddi_acc_handle_t	sw_reset_regh;	/* ERI Reset Reg */

	ddi_dma_cookie_t	md_c;	/* trmd dma cookie */
	ddi_acc_handle_t	mdm_h;	/* trmd memory handle */
	ddi_dma_handle_t	md_h;	/* trmdp dma handle */

	ddi_acc_handle_t	pci_config_handle; /* ERI PCI config */

	/*
	 * DDI dma handle, kernel virtual base,
	 * and io virtual base of IOPB area.
	 */
	ddi_dma_handle_t	iopbhandle;
	uintptr_t		iopbkbase;
	uintptr_t		iopbiobase;
	kstat_t			*ksp;		/* kstat pointer */

	kmutex_t		xmitlock;	/* protect xmit-side fields */
	kmutex_t		xcvrlock;	/* */
	kmutex_t		intrlock;	/* protect intr-side fields */
	kmutex_t		linklock;	/* protect link-side fields */

	mblk_t		*tmblkp[ERI_TMDMAX]; /* mblks assoc with TMD */
	mblk_t		*rmblkp[ERI_RMDMAX]; /* mblks assoc with RMD */
	param_t		param_arr[ERI_PARAM_CNT];

	struct	stats stats;	/* kstats */

	/*
	 * Check if transmitter is hung
	 */
	uint32_t	starts;
	uint32_t	txhung;
	struct		erisave erisave;

	uint64_t	ifspeed_old;

#ifdef ERI_RMAC_HANG_WORKAROUND
	uint32_t	check_rmac_hang;
	uint32_t	check2_rmac_hang;
	uint32_t	rxfifo_wr_ptr;
	uint32_t	rxfifo_rd_ptr;
	uint32_t	rxfifo_wr_ptr_c;
	uint32_t	rxfifo_rd_ptr_c;
#endif
	uint32_t	tx_int_me;
};

/*
 * LADRF bit array manipulation macros.  These are for working within the
 * array of words defined by erip->ladrf, converting a bit (0-255) into
 * the index and offset in the ladrf bit array.  Note that the array is
 * provided in "Big Endian" order.
 */
#define	LADRF_MASK(bit)		(1 << ((bit) % 16))
#define	LADRF_WORD(erip, bit)	erip->ladrf[(15 - ((bit) / 16))]
#define	LADRF_SET(erip, bit)	(LADRF_WORD(erip, bit) |= LADRF_MASK(bit))
#define	LADRF_CLR(erip, bit)	(LADRF_WORD(erip, bit) &= ~LADRF_MASK(bit))

/*
 * ERI IOCTLS.
 * Change : TODO : MBE
 */
#define	ERIIOC		('G' << 8)
#define	ERI_SET_LOOP_MODE	(ERIIOC|1)	/* Set Rio Loopback mode */
#define	ERI_GET_LOOP_MODE	(ERIIOC|2)	/* Get Rio Loopback modes */
#define	ERI_GET_LOOP_IFCNT	(ERIIOC|4)	/* Get Rio IF Count */

/*
 * Loopback modes: For diagnostic testing purposes the ERI card
 * can be placed in loopback mode.
 * There are three modes of loopback provided by the driver,
 * Mac loopback, PCS loopback and Serdes loopback.
 */
#define	ERI_LOOPBACK_OFF		0
#define	ERI_MAC_LOOPBACK_ON		1
#define	ERI_PCS_LOOPBACK_ON 		2
#define	ERI_SER_LOOPBACK_ON 		4
typedef struct {
	int loopback;
} loopback_t;


/*
 * flags
 * TODO : MBE
 */
#define	ERI_UNKOWN	0x00	/* unknown state	*/
#define	ERI_RUNNING	0x01	/* chip is initialized	*/
#define	ERI_STARTED	0x02	/* mac layer started */
#define	ERI_SUSPENDED	0x08	/* suspended interface	*/
#define	ERI_INITIALIZED	0x10	/* interface initialized */
#define	ERI_NOTIMEOUTS	0x20	/* disallow timeout rescheduling */
#define	ERI_TXINIT	0x40	/* TX Portion Init'ed	*/
#define	ERI_RXINIT	0x80	/* RX Portion Init'ed	*/
#define	ERI_MACLOOPBACK	0x100	/* device has MAC int lpbk (DIAG) */
#define	ERI_SERLOOPBACK	0x200	/* device has SERDES int lpbk (DIAG) */
#define	ERI_DLPI_LINKUP	0x400	/* */

/*
 * Mac address flags
 */
#define	ERI_FACTADDR_PRESENT	0x01	/* factory MAC id present */
#define	ERI_FACTADDR_USE	0x02	/* use factory MAC id */

struct erikstat {
	/*
	 * Software event stats
	 */
	struct kstat_named	erik_inits;
	struct kstat_named	erik_rx_inits;
	struct kstat_named	erik_tx_inits;

	struct kstat_named	erik_allocbfail;
	struct kstat_named	erik_drop;

	/*
	 * MAC Control event stats
	 */
	struct kstat_named	erik_pause_rxcount; /* PAUSE Receive count */
	struct kstat_named	erik_pause_oncount;
	struct kstat_named	erik_pause_offcount;
	struct kstat_named	erik_pause_time_count;

	/*
	 * MAC TX Event stats
	 */
	struct kstat_named	erik_txmac_maxpkt_err;
	struct kstat_named	erik_defer_timer_exp;
	struct kstat_named	erik_peak_attempt_cnt;
	struct kstat_named	erik_jab;
	struct kstat_named	erik_notmds;
	struct kstat_named	erik_tx_hang;

	/*
	 * MAC RX Event stats
	 */
	struct kstat_named	erik_no_free_rx_desc; /* no free rx desc. */
	struct kstat_named	erik_rx_hang;
	struct kstat_named	erik_rx_length_err;
	struct kstat_named	erik_rx_code_viol_err;
	struct kstat_named	erik_rx_bad_pkts;

	/*
	 * Fatal errors
	 */
	struct kstat_named	erik_rxtag_err;

	/*
	 * Parity error
	 */
	struct kstat_named	erik_parity_error;

	/*
	 * PCI fatal error stats
	 */
	struct kstat_named	erik_pci_error_int;  /* PCI error interrupt */
	struct kstat_named	erik_unknown_fatal;	/* unknow fatal error */

	/*
	 * PCI Configuration space staus register
	 */
	struct kstat_named	erik_pci_data_parity_err; /* dparity err */
	struct kstat_named	erik_pci_signal_target_abort;
	struct kstat_named	erik_pci_rcvd_target_abort;
	struct kstat_named	erik_pci_rcvd_master_abort;
	struct kstat_named	erik_pci_signal_system_err;
	struct kstat_named	erik_pci_det_parity_err;


	struct kstat_named	erik_pmcap;	/* Power management */
};

/* TBD: new value ? */
#define	ERI_DRAINTIME	(400000)	/* # microseconds xmit drain */

#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	ROUNDUP2(a, n)	(uchar_t *)((((uintptr_t)(a)) + ((n) - 1)) & ~((n) - 1))

/*
 * Xmit/receive buffer structure.
 * This structure is organized to meet the following requirements:
 * - hb_buf starts on an ERI_BURSTSIZE boundary.
 * - eribuf is an even multiple of ERI_BURSTSIZE
 * - hb_buf[] is large enough to contain max frame (1518) plus
 *   (3 x ERI_BURSTSIZE) rounded up to the next ERI_BURSTSIZE
 */
/*
 * #define		ERI_BURSTSIZE	(64)
 */
#define		ERI_BURSTSIZE	(128)
#define		ERI_BURSTMASK	(ERIBURSTSIZE - 1)
#define		ERI_BUFSIZE	(1728)	/* (ETHERMTU + 228) */
#define		ERI_HEADROOM	(34)

/* Offset for the first byte in the receive buffer */
#define	ERI_FSTBYTE_OFFSET	2
#define	ERI_CKSUM_OFFSET	14


#define	ERI_PMCAP_NONE	0
#define	ERI_PMCAP_4MHZ	4

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ERI_H */

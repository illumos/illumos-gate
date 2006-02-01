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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SunOS MT STREAMS ERI(PCI) 10/100 Mb Ethernet Device Driver
 */

#include	<sys/types.h>
#include	<sys/debug.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/strlog.h>
#include	<sys/strsubr.h>
#include	<sys/vtrace.h>
#include	<sys/kmem.h>
#include	<sys/crc32.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/strsun.h>
#include	<sys/stat.h>
#include	<sys/cpu.h>
#include	<sys/kstat.h>
#include	<inet/common.h>
#include	<sys/dlpi.h>
#include	<sys/pattr.h>
#include	<inet/mi.h>
#include	<inet/nd.h>
#include	<sys/ethernet.h>
#include	<sys/policy.h>

#include	<sys/pci.h>

#include	<sys/eri_phy.h>
#include	<sys/eri_mac.h>
#include	<sys/eri.h>
#include	<sys/eri_common.h>

#include	<sys/eri_msg.h>

#ifdef	DEBUG
#include	<sys/spl.h>
#endif
/*
 *  **** Function Prototypes *****
 */
/*
 * Entry points (man9e)
 */
static	int	eri_attach(dev_info_t *, ddi_attach_cmd_t);
static	int	eri_close(queue_t *);
static	int	eri_detach(dev_info_t *, ddi_detach_cmd_t);
static	uint_t	eri_intr();
static	int	eri_open(queue_t *, dev_t *, int, int, cred_t *);
#ifdef	 ERI_SERVICE_ROUTINE
static	int	eri_rsrv(queue_t *);
#endif
static	int	eri_wput(queue_t *, mblk_t *);
static	int	eri_wsrv(queue_t *);
static	void	eri_wenable(struct eri *);
static	void 	eri_sendup(struct eri *, mblk_t *, struct eristr *(*)());

/*
 * I/O (Input/Output) Functions
 */
static	int	eri_start(queue_t *, mblk_t *, struct eri *);
static  void    eri_read_dma(struct eri *, volatile struct rmd *,
			volatile int, uint64_t flags);

/*
 * Initialization Functions
 */
static  int	eri_init(struct eri *);
static	int	eri_allocthings(struct eri *);
static  int	eri_init_xfer_params(struct eri *);
static  void	eri_statinit(struct eri *);
static	int	eri_burstsize(struct eri *);

static	void	eri_setup_mac_address(struct eri *, dev_info_t *);
static 	char	*eri_ether_sprintf(struct ether_addr *);

static	uint32_t eri_init_rx_channel(struct eri *);
static	void	eri_init_rx(struct eri *);
#ifdef	LATER_SPLIT_TX_RX
static	void	eri_init_tx_channel(struct eri *);
#endif
static	void	eri_init_txmac(struct eri *);

/*
 * Un-init Functions
 */
static	uint32_t eri_txmac_disable(struct eri *);
static	uint32_t eri_rxmac_disable(struct eri *);
static	int	eri_stop(struct eri *);
static	void	eri_uninit(struct eri *erip);
static	int	eri_freebufs(struct eri *);
static	uint_t	eri_reclaim(struct eri *, uint32_t);

/*
 * Transceiver (xcvr) Functions
 */
#ifdef	XCVR
static	int	eri_init_xcvr_info(struct eri *, int);
#endif
static	int	eri_new_xcvr(struct eri *); /* Initializes & detects xcvrs */
static	int	eri_reset_xcvr(struct eri *);

#ifdef	ERI_10_10_FORCE_SPEED_WORKAROUND
static	void	eri_xcvr_force_mode(struct eri *, uint32_t *);
#endif

static	void	eri_mif_poll(struct eri *, soft_mif_enable_t);
static	void	eri_check_link(struct eri *);
static	void	eri_display_link_status(struct eri *);
static	void	eri_mif_check(struct eri *, uint16_t, uint16_t);
static	void    eri_mii_write(struct eri *, uint8_t, uint16_t);
static	uint32_t eri_mii_read(struct eri *, uint8_t, uint16_t *);

/*
 * Reset Functions
 */
static	uint32_t eri_etx_reset(struct eri *);
static	uint32_t eri_erx_reset(struct eri *);

/*
 * Error Functions
 */
static	void eri_fatal_err(struct eri *, uint32_t);
static	void eri_nonfatal_err(struct eri *, uint32_t);

#ifdef	ERI_TX_HUNG
static	int eri_check_txhung(struct eri *);
#endif

/*
 * Hardening Functions
 */
static void eri_fault_msg(char *, uint_t, struct eri *, uint_t,
			    msg_t, char *, ...);

/*
 * Misc Functions
 */
static void	eri_savecntrs(struct eri *);

static	void	eri_stop_timer(struct eri *erip);
static	void	eri_start_timer(struct eri *erip, fptrv_t func, clock_t msec);

static	void eri_bb_force_idle(struct eri *);
static	int eri_mcmatch(struct eristr *, struct ether_addr *);
static	struct eristr *eri_paccept(struct eristr *, struct eri *, int,
	struct	ether_addr *);

static	struct eristr *eri_accept(struct eristr *, struct eri *, int,
	struct ether_addr *);

static	mblk_t *eri_addudind(struct eri *, mblk_t *, struct ether_addr *,
	struct ether_addr *, int, uint32_t);

/*
 * Utility Functions
 */
static	mblk_t *eri_allocb(size_t size);
static	mblk_t *eri_allocb_sp(size_t size);
static	int	eri_param_get(queue_t *q, mblk_t *mp, caddr_t cp);
static	int	eri_param_set(queue_t *, mblk_t *, char *, caddr_t);
static	long	eri_strtol(char *, char **, int);

/*
 * Functions to support ndd
 */
static	void	eri_nd_free(caddr_t *nd_pparam);

static	boolean_t	eri_nd_load(caddr_t *nd_pparam, char *name,
				pfi_t get_pfi, pfi_t set_pfi, caddr_t data);

static	int	eri_nd_getset(queue_t *q, caddr_t nd_param, MBLKP mp);
static	void	eri_param_cleanup(struct eri *);
static	int	eri_param_register(struct eri *, param_t *, int);
static	void	eri_process_ndd_ioctl(queue_t *wq, mblk_t *mp, int cmd);

static	void    eri_cable_down_msg(struct eri *);

/*
 * DLPI Functions
 */

static	void eri_proto(queue_t *, mblk_t *);
static	void eri_ioctl(queue_t *, mblk_t *);
static	void eri_loopback(queue_t *, mblk_t *);
static	void eri_mctl(queue_t *q, MBLKP mp);
static	void eri_dodetach(struct eristr *);

static	void eri_dl_ioc_hdr_info(queue_t *, mblk_t *);

static	void eri_areq(queue_t *, mblk_t *);
static	void eri_dreq(queue_t *, mblk_t *);
static	void eri_breq(queue_t *, mblk_t *);
static	void eri_ubreq(queue_t *, mblk_t *);
static	void eri_ireq(queue_t *, mblk_t *);
static	void eri_ponreq(queue_t *, mblk_t *);
static	void eri_poffreq(queue_t *, mblk_t *);
static	void eri_emreq(queue_t *, mblk_t *);
static	void eri_dmreq(queue_t *, mblk_t *);
static	void eri_pareq(queue_t *, mblk_t *);
static	void eri_spareq(queue_t *, mblk_t *);
static	void eri_udreq(queue_t *, mblk_t *);
static	void eri_nreq(queue_t *, mblk_t *);
static	void eri_dlcap_req(queue_t *, mblk_t *);
static	mblk_t *eri_dlcap_all(queue_t *);
static	void eri_dlcap_enable(queue_t *, mblk_t *);

static	void eri_notify_ind(struct eri *, uint32_t);

static	void eri_setipq(struct eri *);

static uint32_t	eri_ladrf_bit(struct ether_addr *addr);

static	void 	eri_process_ndd_ioctl(queue_t *wq, mblk_t *mp, int cmd);

static	int eri_mk_mblk_tail_space(mblk_t *, mblk_t **, size_t);


/*
 * Define PHY Vendors: Matches to IEEE
 * Organizationally Unique Identifier (OUI)
 */
/*
 * The first two are supported as Internal XCVRs
 */
#define	PHY_VENDOR_LUCENT	0x601d

#define	PHY_LINK_NONE		0	/* Not attempted yet or retry */
#define	PHY_LINK_DOWN		1	/* Not being used	*/
#define	PHY_LINK_UP		2	/* Not being used	*/

#define	AUTO_SPEED		0
#define	FORCE_SPEED		1

/*
 * link_up kstat variable states
 */
#define	ERI_LINK_DOWN		0
#define	ERI_LINK_UP		1

/*
 * States for kstat variable link_duplex
 */
#define	ERI_UNKNOWN_DUPLEX	0
#define	ERI_HALF_DUPLEX		1
#define	ERI_FULL_DUPLEX		2

/*
 * tcp and ip data structures used to grab some length
 * and type information in eri_read_dma().
 */
#ifdef ERI_RCV_CKSUM
typedef struct ip {
	uint8_t		ip_v:4;		/* version */
	uint8_t		ip_hl:4;	/* header length */
	uint8_t		ip_tos;		/* type of service */
	int16_t		ip_len;		/* total length */
	uint16_t	ip_id;		/* identification */
	int16_t		ip_off;		/* fragment offset field */
	uint8_t		ip_ttl;		/* time to live */
	uint8_t		ip_p;		/* protocol */
	uint16_t	ip_sum;		/* checksum */
	uint32_t	ip_src;		/* src address */
	uint32_t	ip_dst;		/* dest address */
} ip_t;

typedef struct tcphdr {
	uint16_t	th_sport;	/* source port */
	uint16_t	th_dport;	/* destination port */
	uint32_t	th_seq;		/* sequence number */
	uint32_t	th_ack;		/* acknowledgement number */
	uint8_t		th_off:4,	/* data offset */
			th_x2:4;	/* (unused) */
	uint8_t		th_flags;
	uint16_t	th_win;		/* window */
	uint16_t	th_sum;		/* checksum */
	uint16_t	th_urp;		/* urgent pointer */
} tcp_t;

#endif

/*
 * MIB II broadcast/multicast packets
 */
#define	IS_NOT_MULTICAST(ehp) \
		((ehp->ether_dhost.ether_addr_octet[0] & 01) == 0)

#define	IS_BROADCAST(ehp) \
		(ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
		((ehp->ether_dhost.ether_addr_octet[0] & 01) == 1)
#define	BUMP_InNUcast(erip, ehp) \
		if (IS_BROADCAST(ehp)) { \
			HSTAT(erip, brdcstrcv); \
		} else if (IS_MULTICAST(ehp)) { \
			HSTAT(erip, multircv); \
		}

#define	BUMP_OutNUcast(erip, ehp) \
		if (IS_BROADCAST(ehp)) { \
			HSTAT(erip, brdcstxmt); \
		} else if (IS_MULTICAST(ehp)) { \
			HSTAT(erip, multixmt); \
		}

	/*
	 * ERI 1.0 has a bug  in which  the last byte of the MAC address is
	 * ehp->ether_dhost.ether_addr_octet[5]
	 * not filtered thus accepting all the packets with the first five bytes
	 * match. Here we filter out the packets which are not intended for us.
	 *
	 *  !(ehp->ether_dhost.ether_addr_octet[0] & 0x1) checks if the packet
	 * is not mutlicast.
	 *
	 * (ehp->ether_dhost.ether_addr_octet[1] &
	 * ehp->ether_dhost.ether_addr_octet[5]) != 0xff ), checks if the
	 * the packet could be a broadcast. If it were broadcast, both bytes
	 * would be 0xff. This could be never true for unicast because
	 * the vendor portion for Sun would 8:0:20.
	 */

#define	INVALID_MAC_ADDRESS(erip, ehp) \
		(!(erip->flags & ERI_PROMISC) && \
		(IS_NOT_MULTICAST(ehp) && ~IS_BROADCAST(ehp) && \
		(erip->ouraddr.ether_addr_octet[5] != \
		ehp->ether_dhost.ether_addr_octet[5])))


#define	NEXTTMDP(tbasep, tmdlimp, tmdp)	(((tmdp) + 1) == tmdlimp	\
	? tbasep : ((tmdp) + 1))

#define	ETHERHEADER_SIZE (sizeof (struct ether_header))

#ifdef	ERI_RCV_CKSUM
#define	ERI_PROCESS_READ(erip, bp, sum)				\
{								\
	queue_t *ipq;						\
	t_uscalar_t	type;					\
	struct	ether_header *ehp;				\
	uint_t	sb_flags;					\
	uint_t	start_offset, end_offset;			\
	ehp = (struct ether_header *)bp->b_rptr;		\
								\
	*(bp->b_wptr) = 0;	/* pad byte */			\
								\
	/*							\
	 * update MIB II statistics				\
	 */							\
	HSTAT(erip, ipackets64);				\
	HSTATN(erip, rbytes64, len);				\
	BUMP_InNUcast(erip, ehp);				\
	type = get_ether_type(ehp);				\
	ipq = erip->ip4q;					\
	if (type == ETHERTYPE_IPV6)				\
		ipq = erip->ip6q;				\
	if ((type == ETHERTYPE_IPV4 || type == ETHERTYPE_IPV6) && \
		(IS_NOT_MULTICAST(ehp)) && (ipq)) {		\
		bp->b_rptr += ETHERHEADER_SIZE;			\
		start_offset = 0;				\
		end_offset = bp->b_wptr - bp->b_rptr;		\
		sb_flags = ((struct eristr *)ipq->q_ptr)->sb_flags;\
		if ((sb_flags & ERI_SCKSUM) &&			\
			(sb_flags & ERI_SFAST)) {		\
				(void) hcksum_assoc(bp, NULL, 	\
				    NULL, start_offset, 0, 	\
				    end_offset, sum, 		\
				    HCK_PARTIALCKSUM, 0);	\
		}						\
		if (canputnext(ipq))				\
			(void) putnext(ipq, bp);		\
		else {						\
			freemsg(bp);				\
			HSTAT(erip, nocanput);			\
			HSTAT(erip, ierrors);			\
		}						\
	} else {						\
		/*						\
		 * Strip the PADS for 802.3			\
		 */						\
		if (type <= ETHERMTU)				\
			bp->b_wptr = bp->b_rptr +		\
				ETHERHEADER_SIZE + type;	\
		eri_sendup(erip, bp, eri_accept);		\
	}							\
}
#else

#define	ERI_PROCESS_READ(erip, bp)				\
{								\
	queue_t *ipq;						\
	t_uscalar_t	type;					\
	struct	ether_header *ehp;				\
	uint_t	sb_flags;					\
	ehp = (struct ether_header *)bp->b_rptr;		\
	type = get_ether_type(ehp);				\
	ipq = erip->ip4q;					\
	if (type == ETHERTYPE_IPV6)				\
		ipq = erip->ip6q;				\
	if ((type == ETHERTYPE_IPV4 || type == ETHERTYPE_IPV6) && \
		(IS_NOT_MULTICAST(ehp)) && (ipq)) {		\
		bp->b_rptr += ETHERHEADER_SIZE;			\
		if (canputnext(ipq))				\
			(void) putnext(ipq, bp);		\
		else {						\
			freemsg(bp);				\
			HSTAT(erip, nocanput);			\
			HSTAT(erip, ierrors);			\
		}						\
	} else {						\
		/*						\
		 * Strip the PADS for 802.3			\
		 */						\
		if (type <= ETHERMTU)				\
			bp->b_wptr = bp->b_rptr +		\
				ETHERHEADER_SIZE + type;	\
		eri_sendup(erip, bp, eri_accept);		\
	}							\
}
#endif  /* ERI_RCV_CKSUM */

/*
 * TX Interrupt Rate
 */
static	int	tx_interrupt_rate = 16;

/*
 * Ethernet broadcast address definition.
 */
static struct ether_addr	etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#define	ERI_SAPMATCH(sap, type, flags) ((sap == type)? 1 : \
	((flags & ERI_SALLSAP)? 1 : \
	((sap <= ETHERMTU) && (sap >= (t_uscalar_t)0) && \
	(type <= ETHERMTU))? 1 : 0))

/*
 * Linked list of active (inuse) driver Streams.
 */
static	struct	eristr	*eristrup = NULL;
static	krwlock_t	eristruplock;

/*
 * Single private "global" lock for the few rare conditions
 * we want single-threaded.
 */
static	kmutex_t	erilock;
static	kmutex_t	eriwenlock;
static	struct eri *eriup = NULL;

/*
 * The following variables are used for configuring various features
 */
#define	ERI_DESC_HANDLE_ALLOC	0x0001
#define	ERI_DESC_MEM_ALLOC	0x0002
#define	ERI_DESC_MEM_MAP	0x0004
#define	ERI_XMIT_HANDLE_ALLOC	0x0008
#define	ERI_XMIT_HANDLE_BIND	0x0010
#define	ERI_RCV_HANDLE_ALLOC	0x0020
#define	ERI_RCV_HANDLE_BIND	0x0040
#define	ERI_XMIT_DVMA_ALLOC	0x0100
#define	ERI_RCV_DVMA_ALLOC	0x0200
#define	ERI_XBUFS_HANDLE_ALLOC  0x0400
#define	ERI_XBUFS_KMEM_ALLOC    0x0800
#define	ERI_XBUFS_KMEM_DMABIND  0x1000


#define	ERI_DONT_STRIP_CRC
/*
 * Translate a kernel virtual address to i/o address.
 */
#define	ERI_IOPBIOADDR(erip, a) \
	((erip)->iopbiobase + ((uintptr_t)a - (erip)->iopbkbase))

/*
 * ERI Configuration Register Value
 * Used to configure parameters that define DMA burst
 * and internal arbitration behavior.
 * for equal TX and RX bursts, set the following in global
 * configuration register.
 * static	int	global_config = 0x42;
 */

/*
 * ERI ERX Interrupt Blanking Time
 * Each count is about 16 us (2048 clocks) for 66 MHz PCI.
 */
static	int	intr_blank_time = 6;	/* for about 96 us */
static	int	intr_blank_packets = 8;	/*  */

/*
 * ERX PAUSE Threshold Register value
 * The following value is for an OFF Threshold of about 15.5 Kbytes
 * and an ON Threshold of 4K bytes.
 */
static	int rx_pause_threshold = 0xf8 | (0x40 << 12);
static	int eri_reinit_fatal = 0;
#ifdef	DEBUG
static	int noteri = 0;
#endif

#ifdef	ERI_TX_HUNG
static	int eri_reinit_txhung = 0;
#endif

#ifdef ERI_HDX_BUG_WORKAROUND
/*
 * By default enable padding in hdx mode to 97 bytes.
 * To disabled, in /etc/system:
 * set eri:eri_hdx_pad_enable=0
 */
static	uchar_t eri_hdx_pad_enable = 1;
#endif

/*
 * Default values to initialize the cache line size and latency timer
 * registers in the PCI configuration space.
 * ERI_G_CACHE_LINE_SIZE_16 is defined as 16 since RIO expects in units
 * of 4 bytes.
 */
#ifdef ERI_PM_WORKAROUND_PCI
static int eri_pci_cache_line = ERI_G_CACHE_LINE_SIZE_32; /* 128 bytes */
static int eri_pci_latency_timer = 0xff;		/* 255 PCI cycles */
#else
static int eri_pci_cache_line = ERI_G_CACHE_LINE_SIZE_16; /* 64 bytes */
static int eri_pci_latency_timer = 0x40;		/* 64 PCI cycles */
#endif
#define	ERI_CACHE_LINE_SIZE	(eri_pci_cache_line << ERI_G_CACHE_BIT)

/*
 * Claim the device is ultra-capable of burst in the beginning.  Use
 * the value returned by ddi_dma_burstsizes() to actually set the ERI
 * global configuration register later.
 *
 * PCI_ERI supports Infinite burst or 64-byte-multiple bursts.
 */
#define	ERI_LIMADDRLO	((uint64_t)0x00000000)
#define	ERI_LIMADDRHI	((uint64_t)0xffffffff)

static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	(uint64_t)ERI_LIMADDRLO, /* low address */
	(uint64_t)ERI_LIMADDRHI, /* high address */
	(uint64_t)0x00ffffff,	/* address counter max */
	(uint64_t)1,		/* alignment */
	(uint_t)0xe000e0,	/* dlim_burstsizes for 32 4 bit xfers */
	(uint32_t)0x1,		/* minimum transfer size */
	(uint64_t)0x7fffffff,	/* maximum transfer size */
	(uint64_t)0x00ffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	(uint32_t)1,		/* granularity */
	(uint_t)0		/* attribute flags */
};

static ddi_dma_attr_t desc_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	(uint64_t)ERI_LIMADDRLO, /* low address */
	(uint64_t)ERI_LIMADDRHI, /* high address */
	(uint64_t)0x00ffffff,	/* address counter max */
	(uint64_t)8,		/* alignment */
	(uint_t)0xe000e0,	/* dlim_burstsizes for 32 4 bit xfers */
	(uint32_t)0x1,		/* minimum transfer size */
	(uint64_t)0x7fffffff,	/* maximum transfer size */
	(uint64_t)0x00ffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	16,			/* granularity */
	0			/* attribute flags */
};

ddi_dma_lim_t eri_dma_limits = {
	(uint64_t)ERI_LIMADDRLO, /* dlim_addr_lo */
	(uint64_t)ERI_LIMADDRHI, /* dlim_addr_hi */
	(uint64_t)ERI_LIMADDRHI, /* dlim_cntr_max */
	(uint_t)0x00e000e0,	/* dlim_burstsizes for 32 and 64 bit xfers */
	(uint32_t)0x1,		/* dlim_minxfer */
	1024			/* dlim_speed */
};

/*
 * Link Configuration variables
 *
 * On Motherboard implementations, 10/100 Mbps speeds may be supported
 * by using both the Serial Link and the MII on Non-serial-link interface.
 * When both links are present, the driver automatically tries to bring up
 * both. If both are up, the Gigabit Serial Link is selected for use, by
 * default. The following configuration variable is used to force the selection
 * of one of the links when both are up.
 * To change the default selection to the MII link when both the Serial
 * Link and the MII link are up, change eri_default_link to 1.
 *
 * Once a link is in use, the driver will continue to use that link till it
 * goes down. When it goes down, the driver will look at the status of both the
 * links again for link selection.
 *
 * Currently the standard is not stable w.r.t. gigabit link configuration
 * using auto-negotiation procedures. Meanwhile, the link may be configured
 * in "forced" mode using the "autonegotiation enable" bit (bit-12) in the
 * PCS MII Command Register. In this mode the PCS sends "idles" until sees
 * "idles" as initialization instead of the Link Configuration protocol
 * where a Config register is exchanged. In this mode, the ERI is programmed
 * for full-duplex operation with both pauseTX and pauseRX (for flow control)
 * enabled.
 */

static	int	select_link = 0; /* automatic selection */
static	int	default_link = 0; /* Select Serial link if both are up */

/*
 * The following variables are used for configuring link-operation
 * for all the "eri" interfaces in the system.
 * Later these parameters may be changed per interface using "ndd" command
 * These parameters may also be specified as properties using the .conf
 * file mechanism for each interface.
 */

/*
 * The following variable value will be overridden by "link-pulse-disabled"
 * property which may be created by OBP or eri.conf file. This property is
 * applicable only for 10 Mbps links.
 */
static	int	link_pulse_disabled = 0;	/* link pulse disabled */

/* For MII-based FastEthernet links */
static	int	adv_autoneg_cap = 1;
static	int	adv_100T4_cap = 0;
static	int	adv_100fdx_cap = 1;
static	int	adv_100hdx_cap = 1;
static	int	adv_10fdx_cap = 1;
static	int	adv_10hdx_cap = 1;
static	int	adv_pauseTX_cap =  0;
static	int	adv_pauseRX_cap =  0;

/*
 * The following gap parameters are in terms of byte times.
 */
static	int	ipg0 = 8;
static	int	ipg1 = 8;
static	int	ipg2 = 4;

static	int	lance_mode = 1;		/* to enable LANCE mode */
static	int	mifpoll_enable = 0;	/* to enable mif poll */
static	int	ngu_enable = 0;		/* to enable Never Give Up mode */

static	int	eri_force_mlf = 0; 	/* to enable mif poll */
static	int	eri_phy_mintrans = 1;	/* Lu3X31T mintrans algorithm */
static	int	eri_hash_filter = 1;	/* use hash filter vs group bit */
/*
 * For the MII interface, the External Transceiver is selected when present.
 * The following variable is used to select the Internal Transceiver even
 * when the External Transceiver is present.
 */
static	int	use_int_xcvr = 0;
static	int	pace_size = 0;	/* Do not use pacing for now */
static	int	device = -1;

static	int	eri_use_dvma_rx = 0;	/* =1:use dvma */
static	int	eri_use_dvma_tx = 1;	/* =1:use dvma */
static	int	eri_rx_bcopy_max = RX_BCOPY_MAX;	/* =1:use bcopy() */
static	int	eri_tx_bcopy_max = TX_BCOPY_MAX;	/* =1:use bcopy() */
static	int	eri_overflow_reset = 1;	/* global reset if rx_fifo_overflow */
static	int	eri_tx_ring_size = 2048; /* number of entries in tx ring */
static	int	eri_rx_ring_size = 1024; /* number of entries in rx ring */
/*
 * The following parameters may be configured by the user. If they are not
 * configured by the user, the values will be based on the capabilities of
 * the transceiver.
 * The value "ERI_NOTUSR" is ORed with the parameter value to indicate values
 * which are NOT configured by the user.
 */

#define	ERI_NOTUSR	0x0f000000
#define	ERI_MASK_1BIT	0x1
#define	ERI_MASK_2BIT	0x3
#define	ERI_MASK_8BIT	0xff


/*
 * Note:
 * ERI has all of the above capabilities.
 * Only when an External Transceiver is selected for MII-based FastEthernet
 * link operation, the capabilities depend upon the capabilities of the
 * External Transceiver.
 */

/* ------------------------------------------------------------------------- */

static  param_t	param_arr[] = {
	/* min		max		value		name */
	{  0,		2,		2,		"transceiver_inuse"},
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
	{  0,		31,		8,		"ipg0"},
	{  0,		127,		6,		"intr_blank_time"},
	{  0,		255,		8,		"intr_blank_packets"},
	{  0,		1,		1,		"serial-link"},
	{  0,		2,		1,		"non-serial-link"},
	{  0,		1,		0,		"select-link"},
	{  0,		1,		0,		"default-link"},
	{  0,		2,		0,		"link-in-use"},
	{  0,		1,		1,		"adv_1000autoneg_cap"},
	{  0,		1,		1,		"adv_1000fdx_cap"},
	{  0,		1,		1,		"adv_1000hdx_cap"},
	{  0,		1,		1,		"adv_asm_dir_cap"},
	{  0,		1,		1,		"adv_pause_cap"},
	{  0,		1,		0,		"1000autoneg_cap"},
	{  0,		1,		0,		"1000fdx_cap"},
	{  0,		1,		0,		"1000hdx_cap"},
	{  0,		1,		0,		"asm_dir_cap"},
	{  0,		1,		0,		"pause_cap"},
	{  0,		1,		0,		"lp_1000autoneg_cap"},
	{  0,		1,		0,		"lp_1000fdx_cap"},
	{  0,		1,		0,		"lp_1000hdx_cap"},
	{  0,		1,		0,		"lp_asm_dir_cap"},
	{  0,		1,		0,		"lp_pause_cap"},
};

#define	DISPLAY_PARAM	1
#define	DONT_DISPLAY	0


static  uint32_t	param_display_mii[] = {
/* DISPLAY */
DISPLAY_PARAM,		/* transceiver_inuse */
DISPLAY_PARAM,		/* link_status */
DISPLAY_PARAM,		/* link_speed */
DISPLAY_PARAM,		/* link_mode */
DISPLAY_PARAM,		/* ipg1 */
DISPLAY_PARAM,		/* ipg2 */
DISPLAY_PARAM,		/* use_int_xcvr */
DISPLAY_PARAM,		/* pace_size */
DISPLAY_PARAM,		/* adv_autoneg_cap */
DISPLAY_PARAM,		/* adv_100T4_cap */
DISPLAY_PARAM,		/* adv_100fdx_cap */
DISPLAY_PARAM,		/* adv_100hdx_cap */
DISPLAY_PARAM,		/* adv_10fdx_cap */
DISPLAY_PARAM,		/* adv_10hdx_cap */
DISPLAY_PARAM,		/* autoneg_cap */
DISPLAY_PARAM,		/* 100T4_cap */
DISPLAY_PARAM,		/* 100fdx_cap */
DISPLAY_PARAM,		/* 100hdx_cap */
DISPLAY_PARAM,		/* 10fdx_cap */
DISPLAY_PARAM,		/* 10hdx_cap */
DISPLAY_PARAM,		/* lp_autoneg_cap */
DISPLAY_PARAM,		/* lp_100T4_cap */
DISPLAY_PARAM,		/* lp_100fdx_cap */
DISPLAY_PARAM,		/* lp_100hdx_cap */
DISPLAY_PARAM,		/* lp_10fdx_cap */
DISPLAY_PARAM,		/* lp_10hdx_cap */
DISPLAY_PARAM,		/* instance */
DISPLAY_PARAM,		/* lance_mode */
DISPLAY_PARAM,		/* ipg0 */
DISPLAY_PARAM,		/* intr_blank_time */
DISPLAY_PARAM,		/* intr_blank_packets */
DONT_DISPLAY,		/* serial-link */
DONT_DISPLAY,		/* non-serial-link */
DONT_DISPLAY,		/* select-link */
DONT_DISPLAY,		/* default-link */
DONT_DISPLAY,		/* link-in-use */
DONT_DISPLAY,		/* adv_1000autoneg_cap */
DONT_DISPLAY,		/* adv_1000fdx_cap */
DONT_DISPLAY,		/* adv_1000hdx_cap */
DONT_DISPLAY,		/* adv_asm_dir */
DONT_DISPLAY,		/* adv_pause */
DONT_DISPLAY,		/* 1000autoneg_cap */
DONT_DISPLAY,		/* 1000fdx_cap */
DONT_DISPLAY,		/* 1000hdx_cap */
DONT_DISPLAY,		/* asm_dir_cap */
DONT_DISPLAY,		/* pause_cap */
DONT_DISPLAY,		/* lp_1000autoneg_cap */
DONT_DISPLAY,		/* lp_1000fdx_cap */
DONT_DISPLAY,		/* lp_1000hdx_cap */
DONT_DISPLAY,		/* lp_asm_dir */
DONT_DISPLAY,		/* lp_pause */
};


static	struct	module_info	eriinfo = {
	ERI_IDNUM,	/* mi_idnum */
	ERI_NAME,	/* mi_idname */
	ERI_MINPSZ,	/* mi_minpsz */
	ERI_MAXPSZ,	/* mi_maxpsz */
	ERI_HIWAT,	/* mi_hiwat */
	ERI_LOWAT	/* mi_lowat */
};

static	struct	qinit	eri_rinit = {
	NULL,		/* qi_putp */
#ifdef ERI_SERVICE_ROUTINE
	eri_rsrv,	/* qi_srvp */
#else
	NULL,		/* qi_srvp */
#endif
	eri_open,	/* qi_qopen */
	eri_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&eriinfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static	struct	qinit	eri_winit = {
	eri_wput,	/* qi_putp */
	eri_wsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&eriinfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct	streamtab	er_info = {
	&eri_rinit,	/* st_rdinit */
	&eri_winit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

static	struct	cb_ops	cb_eri_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&er_info,		/* cb_stream */
	D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread() */
	nodev			/* int (*cb_awrite() */
};

static	struct	dev_ops	eri_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ddi_no_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	eri_attach,		/* devo_attach */
	eri_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_eri_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL			/* devo_power */
};

#ifndef lint
char _depends_on[] = "drv/ip";
#endif

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	"10/100 Mb Ethernet Driver v%I% ",
	&eri_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * XXX Autoconfiguration lock:  We want to initialize all the global
 * locks at _init().  However, we do not have the cookie required which
 * is returned in ddi_add_intr(), which in turn is usually called at attach
 * time.
 */

static	kmutex_t	eriautolock;

/*
 * Hardware Independent Functions
 * New Section
 */

int
_init(void)
{
	int	status;

	mutex_init(&eriautolock, NULL, MUTEX_DRIVER, NULL);

	status = mod_install(&modlinkage);
	if (status != 0)
		mutex_destroy(&eriautolock);

	ERI_DEBUG_MSG2(NULL, MODCTL_MSG,
			"_init status = 0x%X", status);
	return (status);
}

int
_fini(void)
{
	int	status;

	status = mod_remove(&modlinkage);
	if (status != 0)
		goto _fini_exit;

	mutex_destroy(&erilock);
	mutex_destroy(&eriwenlock);
	rw_destroy(&eristruplock);
	mutex_destroy(&eriautolock);

_fini_exit:
	ERI_DEBUG_MSG2(NULL, MODCTL_MSG,
			"_fini status = 0x%X", status);
	return (status);
}


int
_info(struct modinfo *modinfop)
{
	int	status;

	status = mod_info(&modlinkage, modinfop);
	ERI_DEBUG_MSG2(NULL, MODCTL_MSG,
			"_info status = 0x%X", status);
	return (status);
}


/*
 * Interface exists: make available by filling in network interface
 * record.  System will initialize the interface when it is ready
 * to accept packets.
 */
static int
eri_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct eri *erip;
	static int	once = 1;
	int	regno;

	uint8_t	mutex_inited = 0;
	uint8_t intr_add = 0;
	uint8_t minor_node_created = 0;

	ERI_DEBUG_MSG1(NULL, AUTOCONFIG_MSG, "eri_attach");

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((erip = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		erip->flags &= ~ERI_SUSPENDED;
		erip->init_macregs = 1;
		param_linkup = 0;
		erip->stats.link_up = ERI_LINK_DOWN;
		erip->linkcheck = 0;
		{
			struct eristr	*sqp;
			int doeriinit = 0;
			rw_enter(&eristruplock, RW_READER);
			/*
			 * Do eri_init() only for active interface
			 */
			for (sqp = eristrup; sqp; sqp = sqp->sb_nextp)
				if (sqp->sb_erip == erip) {
					doeriinit = 1;
					break;
				}

			rw_exit(&eristruplock);
			if (doeriinit)
				(void) eri_init(erip);
		}
		return (DDI_SUCCESS);

	default:
		ERI_DEBUG_MSG1(NULL, DEFAULT_MSG,
				attach_bad_cmd_msg);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft device data structure
	 */
	erip = GETSTRUCT(struct eri, 1);

	/*
	 * Initialize as many elements as possible.
	 */
	ddi_set_driver_private(dip, erip);
	erip->dip = dip;			/* dip	*/
	erip->instance = ddi_get_instance(dip);	/* instance */
	erip->flags = 0;
	erip->promisc_cnt = 0;
	erip->all_multi_cnt = 0;
	erip->all_sap_cnt = 0;

	/*
	 * Map in the device registers.
	 * Separate pointers will be set up for the following
	 * register groups within the GEM Register Space:
	 * 	Global register set
	 * 	ETX register set
	 * 	ERX register set
	 * 	BigMAC register set.
	 * 	MIF register set
	 */

	if (ddi_dev_nregs(dip, &regno) != (DDI_SUCCESS)) {
		ERI_FAULT_MSG2(erip, SEVERITY_HIGH, ERI_VERB_MSG,
				"ddi_dev_nregs failed, returned %d", regno);
		goto attach_fail;
	}

	/*
	 * Map the PCI config space
	 */
	if (pci_config_setup(dip, &erip->pci_config_handle) !=
		DDI_SUCCESS) {
		ERI_FAULT_MSG2(erip, SEVERITY_HIGH, ERI_VERB_MSG,
			"%s pci_config_setup()",
			config_space_fatal_msg);
		goto attach_fail;
	}

	/*
	 * Initialize device attributes structure
	 */
	erip->dev_attr.devacc_attr_version =	DDI_DEVICE_ATTR_V0;
	erip->dev_attr.devacc_attr_dataorder =	DDI_STRICTORDER_ACC;
	erip->dev_attr.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC;

	if (ddi_regs_map_setup(dip, 1,
			(caddr_t *)&(erip->globregp), 0, 0,
			&erip->dev_attr, &erip->globregh)) {
			    ERI_DEBUG_MSG1(erip, AUTOCONFIG_MSG,
						mregs_4global_reg_fail_msg);
				goto attach_fail;
	}
	erip->etxregh =		erip->globregh;
	erip->erxregh =		erip->globregh;
	erip->bmacregh =	erip->globregh;
	erip->mifregh =		erip->globregh;

	erip->etxregp =  (void *)(((caddr_t)erip->globregp) + 0x2000);
	erip->erxregp =  (void *)(((caddr_t)erip->globregp) + 0x4000);
	erip->bmacregp = (void *)(((caddr_t)erip->globregp) + 0x6000);
	erip->mifregp =  (void *)(((caddr_t)erip->globregp) + 0x6200);

	ERI_DEBUG_MSG4(erip, AUTOCONFIG_MSG,
		"eri_attach: gloregp %p alias %X gintmask %X",
		erip->globregp, GET_GLOBREG(status_alias),
			GET_GLOBREG(intmask));
	/*
	 * Map the software reset register.
	 */
	if (ddi_regs_map_setup(dip, 1,
		(caddr_t *)&(erip->sw_reset_reg), 0x1010, 4,
		&erip->dev_attr, &erip->sw_reset_regh)) {
		ERI_FAULT_MSG1(erip, SEVERITY_MID, ERI_VERB_MSG,
				mregs_4soft_reset_fail_msg);
			goto attach_fail;
	}

	/*
	 * Try and stop the device.
	 * This is done until we want to handle interrupts.
	 */
	if (eri_stop(erip))
		goto attach_fail;

	/*
	 * set PCI latency timer register.
	 */
	pci_config_put8(erip->pci_config_handle, PCI_CONF_LATENCY_TIMER,
		(uchar_t)eri_pci_latency_timer);

	ERI_DEBUG_MSG4(erip, AUTOCONFIG_MSG,
		"eri_attach: gloregp %p alias %X gintmask %X",
		erip->globregp, GET_GLOBREG(status_alias),
		GET_GLOBREG(intmask));

	if (ddi_intr_hilevel(dip, 0)) {
		ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
		    " high-level interrupts are not supported");
		goto attach_fail;
	}

	/*
	 * Get the interrupt cookie so the mutexes can be
	 * Initialized.
	 */
	if (ddi_get_iblock_cookie(dip, 0, &erip->cookie) != DDI_SUCCESS)
		goto attach_fail;

	/*
	 * Initialize mutex's for this device.
	 */
	mutex_init(&erip->xmitlock, NULL, MUTEX_DRIVER, (void *)erip->cookie);
	mutex_init(&erip->intrlock, NULL, MUTEX_DRIVER, (void *)erip->cookie);
	mutex_init(&erip->linklock, NULL, MUTEX_DRIVER, (void *)erip->cookie);
	mutex_init(&erip->xcvrlock, NULL, MUTEX_DRIVER, (void *)erip->cookie);

#ifdef XMIT_SERIAL_QUEUE
	/*
	 * A syncq implementation.
	 */
	mutex_init(&erip->sqlock, NULL, MUTEX_DRIVER, (void *)erip->cookie);
#endif
	mutex_inited = 1;

	/*
	 * Add interrupt to system
	 */
	ERI_DEBUG_MSG1(erip, AUTOCONFIG_MSG,
			"eri_att: add intr");
	if (ddi_add_intr(dip, 0, &erip->cookie, 0, eri_intr,
			(caddr_t)erip) == DDI_SUCCESS)
		intr_add = 1;
	else {
		ERI_DEBUG_MSG1(erip, AUTOCONFIG_MSG,
				add_intr_fail_msg);
		goto attach_fail;
	}

	ERI_DEBUG_MSG1(erip, AUTOCONFIG_MSG,
			"eri_att: DONE: add intr");
	/*
	 * Set up the ethernet mac address.
	 */
	(void) eri_setup_mac_address(erip, dip);

	/*
	 * Create the filesystem device node.
	 */
	if (ddi_create_minor_node(dip, "eri", S_IFCHR, erip->instance,
				DDI_NT_NET, CLONE_DEV) == DDI_SUCCESS)
		minor_node_created = 1;
	else {
		ERI_DEBUG_MSG1(erip, AUTOCONFIG_MSG,
				create_minor_node_fail_msg);
		goto attach_fail;
	}

	mutex_enter(&eriautolock);
	if (once) {
		once = 0;
		rw_init(&eristruplock, NULL, RW_DRIVER, (void *)erip->cookie);
		mutex_init(&erilock, NULL, MUTEX_DRIVER,
		    (void *)erip->cookie);
		mutex_init(&eriwenlock, NULL, MUTEX_DRIVER,
		    (void *)erip->cookie);
	}
	mutex_exit(&eriautolock);

	if (eri_init_xfer_params(erip))
		goto attach_fail;

	if (eri_burstsize(erip) == DDI_FAILURE) {
		ERI_DEBUG_MSG1(erip, INIT_MSG, burst_size_msg);
		goto attach_fail;
	}

	/*
	 * Setup fewer receive bufers.
	 */
	ERI_RPENDING = eri_rx_ring_size;
	ERI_TPENDING = eri_tx_ring_size;

	erip->rpending_mask = ERI_RPENDING - 1;
	erip->rmdmax_mask = ERI_RPENDING - 1;
	erip->mif_config = (ERI_PHY_BMSR << ERI_MIF_CFGPR_SHIFT);

	erip->stats.pmcap = ERI_PMCAP_NONE;
	if (pci_report_pmcap(dip, PCI_PM_IDLESPEED, (void *)4000) ==
		DDI_SUCCESS)
		erip->stats.pmcap = ERI_PMCAP_4MHZ;

	ERI_DEBUG_MSG2(erip, AUTOCONFIG_MSG,
		"eri_attach: PMCAP %d", erip->stats.pmcap);

	/*
	 * lock eri structure while manipulating link list of eri structs
	 */
	mutex_enter(&erilock);
	erip->nextp = eriup;
	eriup = erip;
	mutex_exit(&erilock);

	ddi_report_dev(dip);

	ERI_DEBUG_MSG1(erip, EXIT_MSG, "eri_attach pass");
	return (DDI_SUCCESS);

attach_fail:
	if (erip->pci_config_handle)
		(void) pci_config_teardown(&erip->pci_config_handle);

	if (minor_node_created)
		ddi_remove_minor_node(dip, NULL);

	if (mutex_inited) {
		mutex_destroy(&erip->xmitlock);
		mutex_destroy(&erip->intrlock);
		mutex_destroy(&erip->linklock);
		mutex_destroy(&erip->xcvrlock);
#ifdef XMIT_SERIAL_QUEUE
		mutex_destroy(&erip->sqlock);
#endif
	}

	ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
			attach_fail_msg);

	if (intr_add)
		ddi_remove_intr(dip, 0, erip->cookie);

	if (erip->globregh)
		ddi_regs_map_free(&erip->globregh);

	erip->etxregh =		NULL;
	erip->erxregh =		NULL;
	erip->bmacregh =	NULL;
	erip->mifregh =		NULL;
	erip->globregh =	NULL;

	if (erip)
		kmem_free((caddr_t)erip, sizeof (*erip));

	ERI_DEBUG_MSG1(NULL, EXIT_MSG, "eri_attach: !Success");
	return (DDI_FAILURE);
}

static int
eri_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct eri 	*erip, *eritmp, **eripp;
	int i;

	if (dip == NULL) {
		ERI_DEBUG_MSG1(NULL, AUTOCONFIG_MSG,
				"detach: dip == NULL");
		return (DDI_FAILURE);
	}

	if ((erip = ddi_get_driver_private(dip)) == NULL) {
		/*
		 * No resources allocated.
		 */
		ERI_DEBUG_MSG1(NULL, AUTOCONFIG_MSG,
				"detach: !erip ");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		erip->flags |= ERI_SUSPENDED;
		eri_uninit(erip);
		return (DDI_SUCCESS);

	default:
		ERI_DEBUG_MSG1(erip, DEFAULT_MSG,
				detach_bad_cmd_msg);
		return (DDI_FAILURE);
	}

	if (erip->flags & (ERI_RUNNING | ERI_SUSPENDED)) {
		ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG, busy_msg);
		return (DDI_FAILURE);
	}

	/*
	 * Make the device quiescent
	 */
	(void) eri_stop(erip);

	ddi_remove_minor_node(dip, NULL);

	/*
	 * Remove instance of the intr
	 */
	ddi_remove_intr(dip, 0, erip->cookie);

	if (erip->pci_config_handle)
		(void) pci_config_teardown(&erip->pci_config_handle);

	/*
	 * Remove erip from the linked list of device structures
	 */
	mutex_enter(&erilock);
	for (eripp = &eriup; (eritmp = *eripp) != NULL;
	    eripp = &eritmp->nextp)
		if (eritmp == erip) {
			*eripp = eritmp->nextp;
			break;
		}
	mutex_exit(&erilock);

	/*
	 * Destroy all mutexes and data structures allocated during
	 * attach time.
	 */

	if (erip->globregh)
		ddi_regs_map_free(&erip->globregh);

	erip->etxregh =		NULL;
	erip->erxregh =		NULL;
	erip->bmacregh =	NULL;
	erip->mifregh =		NULL;
	erip->globregh =	NULL;

	if (erip->sw_reset_regh)
		ddi_regs_map_free(&erip->sw_reset_regh);

	if (erip->ksp)
		kstat_delete(erip->ksp);

	eri_stop_timer(erip); /* acquire linklock */
	eri_start_timer(erip, eri_check_link, 0);
	mutex_destroy(&erip->xmitlock);
	mutex_destroy(&erip->intrlock);
	mutex_destroy(&erip->linklock);
	mutex_destroy(&erip->xcvrlock);

#ifdef XMIT_SERIAL_QUEUE
	mutex_destroy(&erip->sqlock);
#endif
	if (erip->md_h) {
		if (ddi_dma_unbind_handle(erip->md_h) ==
		    DDI_FAILURE)
			return (DDI_FAILURE);
		ddi_dma_mem_free(&erip->mdm_h);
		ddi_dma_free_handle(&erip->md_h);
	}

	if (eri_freebufs(erip))
		return (DDI_FAILURE);

	/* dvma handle case */
	if (erip->eri_dvmaxh) {
		(void) dvma_release(erip->eri_dvmaxh);
		erip->eri_dvmaxh = NULL;
	}

	if (erip->eri_dvmarh) {
		(void) dvma_release(erip->eri_dvmarh);
		erip->eri_dvmarh = NULL;
	}
/*
 *	xmit_dma_mode, erip->ndmaxh[i]=NULL for dvma
 */
	else {
		for (i = 0; i < ERI_TPENDING; i++)
			if (erip->ndmaxh[i])
				ddi_dma_free_handle(&erip->ndmaxh[i]);
		for (i = 0; i < ERI_RPENDING; i++)
			if (erip->ndmarh[i])
				ddi_dma_free_handle(&erip->ndmarh[i]);
	}
/*
 *	Release tiny TX buffers
 */
	if (erip->tbuf_ioaddr != 0) {
		(void) ddi_dma_unbind_handle(erip->tbuf_handle);
		erip->tbuf_ioaddr = 0;
	}
	if (erip->tbuf_kaddr != NULL) {
		kmem_free(erip->tbuf_kaddr, ERI_TPENDING * eri_tx_bcopy_max);
		erip->tbuf_kaddr = NULL;
	}
	if (erip->tbuf_handle != NULL) {
		ddi_dma_free_handle(&erip->tbuf_handle);
		erip->tbuf_handle = NULL;
	}

	eri_param_cleanup(erip);

	ddi_set_driver_private(dip, NULL);
	kmem_free((caddr_t)erip, sizeof (struct eri));

	return (DDI_SUCCESS);
}

/*
 * To set up the mac address for the network interface:
 * The adapter card may support a local mac address which is published
 * in a device node property "local-mac-address". This mac address is
 * treated as the factory-installed mac address for DLPI interface.
 * If the adapter firmware has used the device for diskless boot
 * operation it publishes a property called "mac-address" for use by
 * inetboot and the device driver.
 * If "mac-address" is not found, the system options property
 * "local-mac-address" is used to select the mac-address. If this option
 * is set to "true", and "local-mac-address" has been found, then
 * local-mac-address is used; otherwise the system mac address is used
 * by calling the "localetheraddr()" function.
 */

static void
eri_setup_mac_address(struct eri *erip, dev_info_t *dip)
{
	char	*prop;
	int	prop_len = sizeof (int);

	erip->addrflags = 0;

	/*
	 * Check if it is an adapter with its own local mac address
	 * If it is present, save it as the "factory-address"
	 * for this adapter.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS, "local-mac-address",
		(caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len == ETHERADDRL) {
			erip->addrflags = ERI_FACTADDR_PRESENT;
			ether_bcopy((caddr_t)prop, &erip->factaddr);
			ERI_FAULT_MSG2(erip, SEVERITY_NONE, ERI_VERB_MSG,
				lether_addr_msg,
				eri_ether_sprintf(&erip->factaddr));
		}
		kmem_free(prop, prop_len);
	}
	/*
	 * Check if the adapter has published "mac-address" property.
	 * If it is present, use it as the mac address for this device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS, "mac-address",
		(caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len >= ETHERADDRL) {
			ether_bcopy((caddr_t)prop, &erip->ouraddr);
			kmem_free(prop, prop_len);
			return;
		}
		kmem_free(prop, prop_len);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, 0, "local-mac-address?",
		(caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if ((strncmp("true", prop, prop_len) == 0) &&
			(erip->addrflags & ERI_FACTADDR_PRESENT)) {
			erip->addrflags |= ERI_FACTADDR_USE;
			ether_bcopy(&erip->factaddr, &erip->ouraddr);
			kmem_free(prop, prop_len);
			ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
					lmac_addr_msg);
			return;
		}
		kmem_free(prop, prop_len);
	}

	/*
	 * Get the system ethernet address.
	 */
	(void) localetheraddr((struct ether_addr *)NULL, &erip->ouraddr);
}

/*
 * Convert Ethernet address to printable (loggable) representation.
 */
static char *
eri_ether_sprintf(struct ether_addr *addr)
{
	uint8_t *ap = (uint8_t *)addr;
	int i;
	static char etherbuf[18];
	char *cp = etherbuf;
	static char digits[] = "0123456789abcdef";

	for (i = 0; i < 6; i++) {
		if (*ap > 0x0f)
			*cp++ = digits[*ap >> 4];
		*cp++ = digits[*ap++ & 0xf];
		*cp++ = ':';
	}
	*--cp = 0;
	return (etherbuf);
}


/*
 * DLPI (Data Link Provider Interface) Functions
 * New Section
 */
/*
 * Our DL_INFO_ACK template.
 */
static	dl_info_ack_t infoack = {
	DL_INFO_ACK,				/* dl_primitive */
	ETHERMTU,				/* dl_max_sdu */
	0,					/* dl_min_sdu */
	ERI_ADDRL,				/* dl_addr_length */
	DL_ETHER,				/* dl_mac_type */
	0,					/* dl_reserved */
	0,					/* dl_current_state */
	-2,					/* dl_sap_length */
	DL_CLDLS,				/* dl_service_mode */
	0,					/* dl_qos_length */
	0,					/* dl_qos_offset */
	0,					/* dl_range_length */
	0,					/* dl_range_offset */
	DL_STYLE2,				/* dl_provider_style */
	sizeof (dl_info_ack_t),			/* dl_addr_offset */
	DL_VERSION_2,				/* dl_version */
	ETHERADDRL,				/* dl_brdcst_addr_length */
	sizeof (dl_info_ack_t) + ERI_ADDRL,	/* dl_brdcst_addr_offset */
	0					/* dl_growth */
};



/*
 * Calculate the bit in the multicast address filter that selects the given
 * address.
 * Note: For ERI, the last 8-bits are used.
 */

static uint32_t
eri_ladrf_bit(struct ether_addr *addr)
{
	uint32_t crc;

	CRC32(crc, addr, ETHERADDRL, -1U, crc32_table);

	/*
	 * Just want the 8 most significant bits.
	 */
	return ((~crc) >> 24);
}


/*
 * Assorted DLPI V2 routines.
 */

static void
eri_proto(queue_t *wq, mblk_t *mp)
{
	union	DL_primitives	*dlp;
	struct	eristr	*sbp;
	uint32_t	prim;

	sbp = (struct eristr *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;

	ERI_DEBUG_MSG1(NULL, PROTO_MSG,
			"eri_proto Entered");
	mutex_enter(&sbp->sb_lock);

	switch (prim) {
	case	DL_UNITDATA_REQ:
		eri_udreq(wq, mp);
		break;

	case	DL_ATTACH_REQ:
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_proto : ATTACH_REQ");
		eri_areq(wq, mp);
		break;

	case	DL_DETACH_REQ:
		eri_dreq(wq, mp);
		break;

	case	DL_BIND_REQ:
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_proto : BIND_REQ");
		eri_breq(wq, mp);
		break;

	case	DL_UNBIND_REQ:
		eri_ubreq(wq, mp);
		break;

	case	DL_INFO_REQ:
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_proto : INFO_REQ");
		eri_ireq(wq, mp);
		break;

	case	DL_PROMISCON_REQ:
		eri_ponreq(wq, mp);
		break;

	case	DL_PROMISCOFF_REQ:
		eri_poffreq(wq, mp);
		break;

	case	DL_ENABMULTI_REQ:
		eri_emreq(wq, mp);
		break;

	case	DL_DISABMULTI_REQ:
		eri_dmreq(wq, mp);
		break;

	case	DL_PHYS_ADDR_REQ:
		eri_pareq(wq, mp);
		break;

	case	DL_SET_PHYS_ADDR_REQ:
		eri_spareq(wq, mp);
		break;

	case	DL_NOTIFY_REQ:
		eri_nreq(wq, mp);
		break;

	case DL_CAPABILITY_REQ:
		eri_dlcap_req(wq, mp);
		break;

	default:
		dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;
	}
	mutex_exit(&sbp->sb_lock);
}

/*ARGSUSED*/
static int
eri_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	struct	eristr	*sbp;
	struct	eristr	**prevsbp;
	minor_t	minordev;
	int	rc = 0;

	ASSERT(sflag != MODOPEN);
	ERI_DEBUG_MSG1(NULL, INIT_MSG,
			"eri_open Entered");

	/*
	 * Serialize all driver open and closes.
	 */
	rw_enter(&eristruplock, RW_WRITER);
	mutex_enter(&eriwenlock);

	/*
	 * Determine minor device number.
	 */
	prevsbp = &eristrup;
	if (sflag == CLONEOPEN) {
		minordev = 0;
		for (; (sbp = *prevsbp) != NULL; prevsbp = &sbp->sb_nextp) {
			if (minordev < sbp->sb_minor)
				break;
			minordev++;
		}
		*devp = makedevice(getmajor(*devp), minordev);
	} else
		minordev = getminor(*devp);

	if (rq->q_ptr)
		goto done;

	sbp = GETSTRUCT(struct eristr, 1);

	ERI_DEBUG_MSG2(NULL, INIT_MSG,
			"eri_open: sbp = %X\n", sbp);

	sbp->sb_minor = minordev;
	sbp->sb_rq = rq;
	sbp->sb_state = DL_UNATTACHED;
	sbp->sb_sap = 0;
	sbp->sb_flags = 0;
	sbp->sb_erip = NULL;

	mutex_init(&sbp->sb_lock, NULL, MUTEX_DRIVER, (void *)0);

	/*
	 * Link new entry into the list of active entries.
	 */
	sbp->sb_nextp = *prevsbp;
	*prevsbp = sbp;

	rq->q_ptr = WR(rq)->q_ptr = (char *)sbp;

	/*
	 * Disable automatic enabling of our write service procedure.
	 * We control this explicitly.
	 */
	noenable(WR(rq));

done:
	mutex_exit(&eriwenlock);
	rw_exit(&eristruplock);

	/* inform framework that we are a good citizen */
	(void) qassociate(rq, -1);

	qprocson(rq);
	return (rc);
}

static int
eri_close(queue_t *rq)
{
	struct	eristr	*sbp;
	struct	eristr	**prevsbp;
	int	promisc_cnt = 0;
	int	sap_cnt = 0;
	int	all_multi_cnt = 0;
	struct eri	*erip;

	ASSERT(rq->q_ptr);

	qprocsoff(rq);

	sbp = (struct eristr *)rq->q_ptr;

	/*
	 * If the stream was closed without calling eripoffreq,
	 * update the counters.
	 */
	if (sbp->sb_flags & ERI_SALLPHYS) {
		sbp->sb_flags &= ~ERI_SALLPHYS;
		++promisc_cnt;
	}
	if (sbp->sb_flags & ERI_SALLSAP) {
		sbp->sb_flags &= ~ERI_SALLSAP;
		++sap_cnt;
	}
	if (sbp->sb_flags & ERI_SALLMULTI) {
		sbp->sb_flags &= ~ERI_SALLMULTI;
		++all_multi_cnt;
	}

	erip = sbp->sb_erip;
	if (erip) {
		mutex_enter(&erip->intrlock);
		erip->promisc_cnt -= promisc_cnt;
		erip->all_sap_cnt -= sap_cnt;
		erip->all_multi_cnt -= all_multi_cnt;
		mutex_exit(&erip->intrlock);
	}

	/*
	 * Implicit detach Stream from interface.
	 */
	if (sbp->sb_erip)
		eri_dodetach(sbp);

	/* dissociate queue */
	(void) qassociate(rq, -1);

	rw_enter(&eristruplock, RW_WRITER);
	mutex_enter(&eriwenlock);

	/*
	 * Unlink the per-Stream entry from the active list and free it.
	 */
	for (prevsbp = &eristrup; (sbp = *prevsbp) != NULL;
		prevsbp = &sbp->sb_nextp)
		if (sbp == (struct eristr *)rq->q_ptr)
			break;
	ASSERT(sbp);
	*prevsbp = sbp->sb_nextp;

	mutex_destroy(&sbp->sb_lock);
	kmem_free((char *)sbp, sizeof (struct eristr));

	rq->q_ptr = WR(rq)->q_ptr = NULL;

	mutex_exit(&eriwenlock);
	rw_exit(&eristruplock);
	return (0);
}

/*
 * Enqueue M_PROTO/M_PCPROTO (always) and M_DATA (sometimes) on the wq.
 *
 * Processing of some of the M_PROTO/M_PCPROTO msgs involves acquiring
 * internal locks that are held across upstream putnext calls.
 * Specifically there's the problem of eri_intr() holding eri_intrlock
 * and eristruplock when it calls putnext() and that thread looping
 * back around to call eri_wput() and, eventually, eri_init() to create a
 * recursive lock panic.  There are two obvious ways of solving this
 * problem: (1) have eri_intr() do putq instead of putnext which provides
 * the loopback "cutout" right at the rq, or (2) allow eri_intr() to putnext
 * and put the loopback "cutout" around eri_proto().  We choose the latter
 * for performance reasons.
 *
 * M_DATA messages are enqueued on the wq *only* when the xmit side
 * is out of tbufs or tmds.  Once the xmit resource is available again,
 * wsrv() is enabled and tries to xmit all the messages on the wq.
 */
static int
eri_wsrv(queue_t *wq)
{
	mblk_t	*mp;
	struct	eristr	*sbp;
	struct	eri	*erip;

	sbp = (struct eristr *)wq->q_ptr;
	erip = sbp->sb_erip;
	while (mp = getq(wq))
		switch (DB_TYPE(mp)) {
		case	M_DATA:
			if (erip) {
				if (eri_start(wq, mp, erip))
					goto done;
			} else
				freemsg(mp);
			break;

		case	M_PROTO:
		case	M_PCPROTO:
			eri_proto(wq, mp);
			break;

		default:
			ASSERT(0);
			break;
		}
done:
	return (0);
}

#ifdef XMIT_SERIAL_QUEUE
static int
eri_wput_serialize(queue_t *wq, mblk_t *mp, struct eri *erip)
{

	mblk_t *smp;
	int	refed;
	int	ret = 0;

	mutex_enter(&erip->sqlock);
	if (erip->sqrefcnt) {
		smp = mp;
		mp = NULL;
		refed = 0;
		goto last;
	}
	erip->sqrefcnt++;
next:
	refed = 1;
	if (erip->sqfirst) {
		/*
		 * Mblk chain on syncq, so just add ours, if any
		 * to the end and get the first one.
		 */
		smp = mp;
		mp = erip->sqfirst;
		if ((erip->sqfirst = mp->b_next) == NULL)
			erip->sqlast = NULL;
		else
			mp->b_next = NULL;
	} else
		smp = NULL;

last:
	if (smp) {
		/*
		 * Mblk chain to save, so just add it to
		 * the end of the sycnq.
		 */
		smp->b_next = NULL;
		if (erip->sqlast)
			erip->sqlast->b_next = smp;
		else
			erip->sqfirst = smp;
		erip->sqlast = smp;
	}

	if (mp == NULL) {
		/*
		 * Nothing more todo ...
		 */
		if (refed)
			erip->sqrefcnt--;

		mutex_exit(&erip->sqlock);
		return (ret);
	}

	mutex_exit(&erip->sqlock);
	ret = eri_start(wq, mp, erip);
	mp = NULL;
	mutex_enter(&erip->sqlock);
	goto next;
no_bwg:
	HSTAT(erip, oerrors);
	freemsg(mp);
	return (0);
}

#endif


static int
eri_wput(queue_t *wq, mblk_t *mp)
{
	struct	eristr	*sbp = (struct eristr *)wq->q_ptr;
	struct	eri	*erip;

	switch (DB_TYPE(mp)) {
	case M_DATA:		/* "fastpath" */
		erip = sbp->sb_erip;

		if (((sbp->sb_flags & (ERI_SFAST | ERI_SRAW)) == 0) ||
			(sbp->sb_state != DL_IDLE) ||
			(erip == NULL)) {
			merror(wq, mp, EPROTO);
			break;
		}

		/*
		 * If any msgs already enqueued or the interface will
		 * loop back up the message (due to ERI_PROMISC), then
		 * enqueue the msg.  Otherwise just xmit it directly.
		 */
		if (wq->q_first) {
			(void) putq(wq, mp);
			erip->wantw = 1;
			qenable(wq);
		} else if (erip->flags & ERI_PROMISC) {
			(void) putq(wq, mp);
			qenable(wq);
		} else
#ifdef XMIT_SERIAL_QUEUE
			(void) eri_wput_serialize(wq, mp, erip);
#else
			(void) eri_start(wq, mp, erip);
#endif

		break;

	case M_PROTO:
	case M_PCPROTO:
		/*
		 * Break the association between the current thread
		 * and the thread that calls eri_proto() to resolve the
		 * problem of eri_intr() threads which loop back around
		 * to call eri_proto() and try to recursively acquire
		 * internal locks.
		 */
		(void) putq(wq, mp);
		qenable(wq);
		break;

	case M_IOCTL:
		eri_ioctl(wq, mp);
		break;

	case M_CTL:
		eri_mctl(wq, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(wq, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}

		if (*mp->b_rptr & FLUSHR) {
#ifdef ERI_SERVICE_ROUTINE
			flushq(RD(wq), FLUSHALL);
#endif
			qreply(wq, mp);
		} else
			freemsg(mp);
		break;

	default:
		freemsg(mp);
		break;
	}
	return (0);
}

static void
eri_ioctl(queue_t *wq, mblk_t *mp)
{
	struct	iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	struct	eristr	*sbp = (struct eristr *)wq->q_ptr;
	struct	eri	*erip = sbp->sb_erip;

	ERI_DEBUG_MSG1(NULL, IOCTL_MSG,
			"eri_ioctl Entered");
	switch (iocp->ioc_cmd) {
	case DLIOCRAW:		/* raw M_DATA mode */
		sbp = (struct eristr *)wq->q_ptr;
		sbp->sb_flags |= ERI_SRAW;
		miocack(wq, mp, 0, 0);
		break;

	case DL_IOC_HDR_INFO:	/* M_DATA "fastpath" info request */
		eri_dl_ioc_hdr_info(wq, mp);
		break;

	case ERI_ND_GET:
	case ERI_ND_SET:
		eri_process_ndd_ioctl(wq, mp, iocp->ioc_cmd);
		break;

	case ERI_SET_LOOP_MODE:
	case ERI_GET_LOOP_MODE:
		if (erip == NULL)
			miocnak(wq, mp, 0, EPROTO);
		else
			eri_loopback(wq, mp);
		break;

	default:
		miocnak(wq, mp, 0, EINVAL);
		break;
	}

	if (erip)
		ASSERT(!MUTEX_HELD(&erip->linklock));
}

static void
eri_loopback(queue_t *wq, mblk_t *mp)
{
	struct  eristr	*sbp = (struct eristr *)wq->q_ptr;
	struct	eri	*erip = sbp->sb_erip;
	struct	iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	loopback_t	*al;

	ERI_DEBUG_MSG1(NULL, LOOPBACK_MSG,
			"eri_loopback Entered");

	if (mp->b_cont == NULL ||
		MBLKL(mp->b_cont) < sizeof (loopback_t)) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	al = (loopback_t *)mp->b_cont->b_rptr;

	switch (iocp->ioc_cmd) {
	case ERI_SET_LOOP_MODE:
		ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
				"ERI_SET_LOOP_MODE\n");
		switch (al->loopback) {
		case ERI_LOOPBACK_OFF:
			ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
					"ERI_LOOPBACK_OFF\n");
			sbp->sb_flags &= (~ERI_SMACLPBK & ~ERI_SSERLPBK);
			erip->flags &= (~ERI_MACLOOPBACK &
					~ERI_SERLOOPBACK);
			/* force link status to go down */
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			(void) eri_init(erip);
			break;

		case ERI_MAC_LOOPBACK_ON:
			ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
					"ERI_MAC_LOOPBACK_ON\n");
			sbp->sb_flags |= ERI_SMACLPBK;
			erip->flags |= ERI_MACLOOPBACK;
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			(void) eri_init(erip);
			break;

		case ERI_PCS_LOOPBACK_ON:
			ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
					"ERI_PCS_LOOPBACK_ON\n");
			break;

		case ERI_SER_LOOPBACK_ON:
			ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
					"ERI_SER_LOOPBACK_ON\n");
			sbp->sb_flags |= ERI_SSERLPBK;
			erip->flags |= ERI_SERLOOPBACK;
			/* force link status to go down */
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			(void) eri_init(erip);
			break;

		default:
			ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
					loopback_val_default);
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		miocnak(wq, mp, 0, 0);
		break;

	case ERI_GET_LOOP_MODE:
		ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
				"ERI_GET_LOOP_MODE\n");
		al->loopback =	ERI_MAC_LOOPBACK_ON |
				ERI_PCS_LOOPBACK_ON |
				ERI_SER_LOOPBACK_ON;
		miocack(wq, mp, sizeof (loopback_t), 0);
		break;

	default:
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				loopback_cmd_default);
	}
}

/*
 * M_DATA "fastpath" info request.
 * Following the M_IOCTL mblk should come a DL_UNITDATA_REQ mblk.
 * We ack with an M_IOCACK pointing to the original DL_UNITDATA_REQ mblk
 * followed by an mblk containing the raw ethernet header corresponding
 * to the destination address.  Subsequently, we may receive M_DATA
 * msgs which start with this header and may send up
 * up M_DATA msgs with b_rptr pointing to a (uint32_t) group address
 * indicator followed by the network-layer data (IP packet header).
 * This is all selectable on a per-Stream basis.
 */
static void
eri_dl_ioc_hdr_info(queue_t *wq, mblk_t *mp)
{
	mblk_t			*nmp;
	struct	eristr		*sbp;
	struct	eridladdr	*dlap;
	dl_unitdata_req_t	*dludp;
	struct	ether_header	*headerp;
	struct	eri		*erip;
	t_uscalar_t		off, len;
	int			error;

	sbp = (struct eristr *)wq->q_ptr;
	erip = sbp->sb_erip;
	if (erip == NULL) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	error = miocpullup(mp, sizeof (dl_unitdata_req_t) + ERI_ADDRL);
	if (error != 0) {
		miocnak(wq, mp, 0, error);
		return;
	}

	/*
	 * Sanity check the DL_UNITDATA_REQ destination address
	 * offset and length values.
	 */
	dludp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;
	if (dludp->dl_primitive != DL_UNITDATA_REQ ||
	    !MBLKIN(mp->b_cont, off, len) || len != ERI_ADDRL) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	dlap = (struct eridladdr *)(mp->b_cont->b_rptr + off);

	/*
	 * Allocate a new mblk to hold the ether header.
	 */
	if ((nmp = allocb(ETHERHEADER_SIZE, BPRI_MED)) == NULL) {
		miocnak(wq, mp, 0, ENOMEM);
		return;
	}
	nmp->b_wptr += ETHERHEADER_SIZE;

	/*
	 * Fill in the ether header.
	 */
	headerp = (struct ether_header *)nmp->b_rptr;
	ether_bcopy(&dlap->dl_phys, &headerp->ether_dhost);
	ether_bcopy(&erip->ouraddr, &headerp->ether_shost);
	put_ether_type(headerp, dlap->dl_sap);

	/*
	 * Link new mblk in after the "request" mblks.
	 */
	linkb(mp, nmp);

	sbp->sb_flags |= ERI_SFAST;
	miocack(wq, mp, msgsize(mp->b_cont), 0);
}

/* ARGSUSED */
static void
eri_mctl(queue_t *wq, mblk_t  *mp)
{
	freemsg(mp);
} /* eri_mctl */

static void
eri_areq(queue_t *wq, mblk_t *mp)
{
	struct	eristr		*sbp;
	union	DL_primitives	*dlp;
	struct	eri		*erip = NULL;
	t_uscalar_t 		ppa;
	uint32_t		promisc = 0;
	uint32_t		all_multi = 0;
	uint32_t		all_sap = 0;
	int			init = B_FALSE;

	sbp = (struct eristr *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;

	if (MBLKL(mp) < DL_ATTACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_BADPRIM, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_areq: Bad REQ Size");
		return;
	}

	if (sbp->sb_state != DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_OUTSTATE, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_areq: DL_OUTSTATE");
		return;
	}

	/*
	 * Count the number of snoop/promisc modes.
	 */
	if (sbp->sb_flags & ERI_SALLPHYS) {
		promisc++;
		init = B_TRUE;
	}
	if (sbp->sb_flags & ERI_SALLSAP) {
		all_sap++;
		init = B_TRUE;
	}
	if (sbp->sb_flags & ERI_SALLMULTI) {
		all_multi++;
		init = B_TRUE;
	}

	ppa = dlp->attach_req.dl_ppa;

	/*
	 * Valid ppa?
	 */
	if (ppa == -1 || qassociate(wq, ppa) != 0) {
		dlerrorack(wq, mp, dlp->dl_primitive, DL_BADPPA, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_areq: erip == NULL");
		return;
	}
	mutex_enter(&erilock);
	for (erip = eriup; erip; erip = erip->nextp)
		if (ppa == erip->instance) {
			ERI_DEBUG_MSG1(erip, PROTO_MSG,
				"got instance");
			break;
		}
	mutex_exit(&erilock);
	ASSERT(erip != NULL);

	/* Set link to device and update our state. */
	sbp->sb_erip = erip;
	sbp->sb_state = DL_UNBOUND;

	/*
	 * Has device been initialized?  Do so if necessary.
	 * Also check if promiscuous mode is set via the ALLPHYS and
	 * ALLMULTI flags, for the stream.  If so, initialize the
	 * interface.
	 */
	if ((erip->flags & ERI_RUNNING) == 0) {
		if (eri_init(erip)) {
			dlerrorack(wq, mp, dlp->dl_primitive, DL_INITFAILED, 0);
			sbp->sb_erip = NULL;
			sbp->sb_state = DL_UNATTACHED;
			ERI_DEBUG_MSG1(NULL, PROTO_MSG,
					"eri_areq: eri_init FAILED");
			(void) qassociate(wq, -1);
			return;
		}

	} else {
		if (init) {
			mutex_enter(&erip->intrlock);
			erip->promisc_cnt += promisc;
			erip->all_multi_cnt += all_multi;
			erip->all_sap_cnt += all_sap;
			/*
			 * Reinitialize rx mac
			 */
			eri_init_rx(erip);
			mutex_exit(&erip->intrlock);
		}
		if (erip->promisc_cnt == 1)
			eri_notify_ind(erip, DL_NOTE_PROMISC_ON_PHYS);
	}

	dlokack(wq, mp, DL_ATTACH_REQ);
	ERI_DEBUG_MSG1(NULL, PROTO_MSG, "eri_areq: Normal exit");
}

static void
eri_dreq(queue_t *wq, mblk_t *mp)
{
	struct	eristr	*sbp;

	sbp = (struct eristr *)wq->q_ptr;
	if (MBLKL(mp) < DL_DETACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	eri_dodetach(sbp);

	/* dissociate queue */
	(void) qassociate(wq, -1);

	dlokack(wq, mp, DL_DETACH_REQ);
}

/*
 * Detach a Stream from an interface.
 */
static void
eri_dodetach(struct eristr *sbp)
{
	struct	eristr	*tsbp;
	struct	eri	*erip;
	int	reinit = 0, i;
	uint32_t promisc = 0;
	uint32_t all_multi = 0;
	uint32_t all_sap = 0;

	ASSERT(sbp->sb_erip);

	erip = sbp->sb_erip;
	sbp->sb_erip = NULL;

	/* Disable promiscuous mode if on. */
	if (sbp->sb_flags & ERI_SALLPHYS) {
		sbp->sb_flags &= ~ERI_SALLPHYS;
		promisc++;
		reinit = 1;
	}

	/* Disable ALLSAP mode if on. */
	if (sbp->sb_flags & ERI_SALLSAP) {
		sbp->sb_flags &= ~ERI_SALLSAP;
		all_sap++;
	}

	/* Disable ALLMULTI mode if on. */
	if (sbp->sb_flags & ERI_SALLMULTI) {
		sbp->sb_flags &= ~ERI_SALLMULTI;
		all_multi++;
		reinit = 1;
	}

	/* Disable MULTI mode if on. */
	if (sbp->sb_flags & ERI_SMULTI) {
		sbp->sb_flags &= ~ERI_SMULTI;
		reinit = 2;
	}

	/* Disable any Multicast Addresses. */

	for (i = 0; i < NMCHASH; i++) {
		if (sbp->sb_mctab[i]) {
			reinit = 2;
			kmem_free(sbp->sb_mctab[i], sbp->sb_mcsize[i] *
			    sizeof (struct ether_addr));
			sbp->sb_mctab[i] = NULL;
		}
		sbp->sb_mccount[i] = sbp->sb_mcsize[i] = 0;
	}

	for (i = 0; i < NMCFILTER_BITS/16; i++)
		sbp->sb_ladrf[i] = 0;

	for (i = 0; i < NMCFILTER_BITS; i++)
		sbp->sb_ladrf_refcnt[i] = 0;

	sbp->sb_state = DL_UNATTACHED;

	/*
	 * Detach from device structure.
	 * Uninit the device and update power management property
	 * when no other streams are attached to it.
	 */

	rw_enter(&eristruplock, RW_READER);

	for (tsbp = eristrup; tsbp; tsbp = tsbp->sb_nextp)
		if (tsbp->sb_erip == erip)
			break;

	rw_exit(&eristruplock);

	if (tsbp == NULL)
		eri_uninit(erip);
	else if (reinit) {
		mutex_enter(&erip->intrlock);
		erip->promisc_cnt -= promisc;
		erip->all_multi_cnt -= all_multi;
		erip->all_sap_cnt -= all_sap;
		if (erip->promisc_cnt == 0 || erip->all_multi_cnt == 0 ||
		    reinit == 2)
			eri_init_rx(erip);

		if (erip->promisc_cnt == 0)
			eri_notify_ind(erip, DL_NOTE_PROMISC_OFF_PHYS);

		mutex_exit(&erip->intrlock);
	}
	eri_setipq(erip);
}

static void
eri_breq(queue_t *wq, mblk_t *mp)
{
	struct	eristr		*sbp;
	union	DL_primitives	*dlp;
	struct	eri		*erip;
	struct	eridladdr	eriaddr;
	t_uscalar_t sap;
	t_uscalar_t xidtest;

	sbp = (struct eristr *)wq->q_ptr;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_breq: Bad REQ Size");
		return;
	}

	if (sbp->sb_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_breq: Bad DL_OUTSTATE");
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	erip = sbp->sb_erip;
	sap = dlp->bind_req.dl_sap;
	xidtest = dlp->bind_req.dl_xidtest_flg;

	ASSERT(erip);

	if (xidtest) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_NOAUTO, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_breq: Bad DL_NOAUTO");
		return;
	}

	if (sap > ETHERTYPE_MAX) {
		dlerrorack(wq, mp, dlp->dl_primitive, DL_BADSAP, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_breq: DL_BADSAP");
		return;
	}

	/*
	 * Save SAP value for this Stream and change state.
	 */
	sbp->sb_sap = sap;
	sbp->sb_state = DL_IDLE;

	eriaddr.dl_sap = sap;
	ether_bcopy(&erip->ouraddr, &eriaddr.dl_phys);
	dlbindack(wq, mp, sap, &eriaddr, ERI_ADDRL, 0, 0);

	eri_setipq(erip);

}

static void
eri_ubreq(queue_t *wq, mblk_t *mp)
{
	struct	eristr	*sbp;

	sbp = (struct eristr *)wq->q_ptr;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	sbp->sb_state = DL_UNBOUND;
	sbp->sb_sap = 0;

	dlokack(wq, mp, DL_UNBIND_REQ);

	eri_setipq(sbp->sb_erip);
}

static void
eri_ireq(queue_t *wq, mblk_t *mp)
{
	struct	eristr	*sbp;
	dl_info_ack_t	*dlip;
	struct	eridladdr	*dlap;
	struct	ether_addr	*ep;
	size_t	size;

	sbp = (struct eristr *)wq->q_ptr;

	if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
		dlerrorack(wq, mp, DL_INFO_REQ, DL_BADPRIM, 0);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_ireq: < DL_INFO_REQ_SIZE");
		return;
	}

	/* Exchange current msg for a DL_INFO_ACK. */
	size = sizeof (dl_info_ack_t) + ERI_ADDRL + ETHERADDRL;
	mp = mexchange(wq, mp, size, M_PCPROTO, DL_INFO_ACK);
	if (mp == NULL) {
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_ireq: mp == NULL");
		return;
	}

	/* Fill in the DL_INFO_ACK fields and reply. */
	dlip = (dl_info_ack_t *)mp->b_rptr;
	*dlip = infoack;
	dlip->dl_current_state = sbp->sb_state;
	dlap = (struct eridladdr *)(mp->b_rptr + dlip->dl_addr_offset);
	dlap->dl_sap = sbp->sb_sap;

	if (sbp->sb_erip) {
		ether_bcopy(&sbp->sb_erip->ouraddr, &dlap->dl_phys);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_ireq: sbp->sb_erip");
	} else {
		bzero((caddr_t)&dlap->dl_phys, ETHERADDRL);
		ERI_DEBUG_MSG1(NULL, PROTO_MSG,
				"eri_ireq: !sbp->sb_erip");
	}

	ep = (struct ether_addr *)(mp->b_rptr + dlip->dl_brdcst_addr_offset);
	ether_bcopy(&etherbroadcastaddr, ep);

	qreply(wq, mp);
}

static void
eri_ponreq(queue_t *wq, mblk_t *mp)
{
	struct	eri	*erip;
	struct	eristr	*sbp;
	int	phy_flag = 0;
	int	sap_flag = 0;
	int	allmulti_flag = 0;

	sbp = (struct eristr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCON_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		return;
	}

	/*
	 * Do not increment counter if already set.
	 */
	if (sbp->sb_flags & ERI_SALLPHYS)
		phy_flag = 1;
	if (sbp->sb_flags & ERI_SALLSAP)
		sap_flag = 1;
	if (sbp->sb_flags & ERI_SALLMULTI)
		allmulti_flag = 1;

	switch (((dl_promiscon_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		sbp->sb_flags |= ERI_SALLPHYS;
		break;

	case DL_PROMISC_SAP:
		sbp->sb_flags |= ERI_SALLSAP;
		break;

	case DL_PROMISC_MULTI:
		sbp->sb_flags |= ERI_SALLMULTI;
		break;

	default:
		dlerrorack(wq, mp, DL_PROMISCON_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	erip = sbp->sb_erip;
	if (erip) {
		mutex_enter(&erip->intrlock);
		if ((sbp->sb_flags & ERI_SALLPHYS) && (phy_flag == 0))
			erip->promisc_cnt++;
		if ((sbp->sb_flags & ERI_SALLSAP) && (sap_flag == 0))
			erip->all_sap_cnt++;
		if ((sbp->sb_flags & ERI_SALLMULTI) && (allmulti_flag == 0))
			erip->all_multi_cnt++;
		if (erip->promisc_cnt == 1 || erip->all_multi_cnt == 1) {
			eri_init_rx(sbp->sb_erip);
			eri_notify_ind(erip, DL_NOTE_PROMISC_ON_PHYS);
		}
		mutex_exit(&erip->intrlock);

		eri_setipq(sbp->sb_erip);
	}
	dlokack(wq, mp, DL_PROMISCON_REQ);
}

static void
eri_poffreq(queue_t *wq, mblk_t *mp)
{
	struct	eri	*erip;
	struct	eristr	*sbp;
	int	flag;

	sbp = (struct eristr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCOFF_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		return;
	}

	switch (((dl_promiscoff_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		flag = ERI_SALLPHYS;
		sbp->sb_flags &= ~ERI_SALLPHYS;
		break;

	case DL_PROMISC_SAP:
		flag = ERI_SALLSAP;
		sbp->sb_flags &= ~ERI_SALLSAP;
		break;

	case DL_PROMISC_MULTI:
		flag = ERI_SALLMULTI;
		sbp->sb_flags &= ~ERI_SALLMULTI;
		break;

	default:
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	if ((sbp->sb_flags & flag) == 0) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
		return;
	}

	erip = sbp->sb_erip;
	if (erip) {
		mutex_enter(&erip->intrlock);
		if (flag == ERI_SALLPHYS)
			erip->promisc_cnt--;
		if (flag == ERI_SALLSAP)
			erip->all_sap_cnt--;
		if (flag == ERI_SALLMULTI)
			erip->all_multi_cnt--;
		if (((flag == ERI_SALLPHYS) && (erip->promisc_cnt == 0)) ||
		    ((flag == ERI_SALLMULTI) && (erip->all_multi_cnt == 0))) {
			eri_init_rx(sbp->sb_erip);
			if (flag == ERI_SALLPHYS)
				eri_notify_ind(erip, DL_NOTE_PROMISC_OFF_PHYS);
		}
		mutex_exit(&erip->intrlock);

		eri_setipq(sbp->sb_erip);
	}
	dlokack(wq, mp, DL_PROMISCOFF_REQ);
}

/*
 * This is to support unlimited number of members
 * in Multicast.
 */
static void
eri_emreq(queue_t	*wq, mblk_t *mp)
{
	struct	eristr	*sbp;
	union	DL_primitives	*dlp;
	struct	ether_addr	*addrp;
	t_uscalar_t off;
	t_uscalar_t len;
	uint32_t mchash;
	struct	ether_addr	*mcbucket;
	uint32_t ladrf_bit;

	sbp = (struct eristr *)wq->q_ptr;
	if (MBLKL(mp) < DL_ENABMULTI_REQ_SIZE) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state == DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->enabmulti_req.dl_addr_length;
	off = dlp->enabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) ||
		!MBLKIN(mp, off, len) ||
		((addrp->ether_addr_octet[0] & 01) == 0)) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Calculate hash value and bucket.
	 */

	mchash = MCHASH(addrp);
	mcbucket = sbp->sb_mctab[mchash];

	/*
	 * Allocate hash bucket if it's not there.
	 */

	if (mcbucket == NULL) {
		sbp->sb_mctab[mchash] = mcbucket =
			kmem_alloc(INIT_BUCKET_SIZE *
				sizeof (struct ether_addr),
				KM_SLEEP);
		sbp->sb_mcsize[mchash] = INIT_BUCKET_SIZE;
	}

	/*
	 * We no longer bother checking to see if the address is already
	 * in the table.  We won't reinitialize the
	 * hardware, since we'll find the mc bit is already set.
	 */

	/*
	 * Expand table if necessary.
	 */
	if (sbp->sb_mccount[mchash] >= sbp->sb_mcsize[mchash]) {
		struct	ether_addr	*newbucket;
		int		newsize;

		newsize = sbp->sb_mcsize[mchash] * 2;

		newbucket = kmem_alloc(newsize * sizeof (struct ether_addr),
			KM_SLEEP);
		bcopy(mcbucket, newbucket,
		    sbp->sb_mcsize[mchash] * sizeof (struct ether_addr));
		kmem_free(mcbucket, sbp->sb_mcsize[mchash] *
		    sizeof (struct ether_addr));

		sbp->sb_mctab[mchash] = mcbucket = newbucket;
		sbp->sb_mcsize[mchash] = newsize;
	}

	/*
	 * Add address to the table.
	 */
	mcbucket[sbp->sb_mccount[mchash]++] = *addrp;

	/*
	 * If this address's bit was not already set in the local address
	 * filter, add it and re-initialize the Hardware.
	 */
	ladrf_bit = eri_ladrf_bit(addrp);

	if (sbp->sb_ladrf_refcnt[ladrf_bit] == 0) {
		sbp->sb_ladrf[15-(ladrf_bit/16)] |=
		    1 << (ladrf_bit % 16);
		sbp->sb_flags |= ERI_SMULTI;
		mutex_enter(&sbp->sb_erip->intrlock);
		eri_init_rx(sbp->sb_erip);
		mutex_exit(&sbp->sb_erip->intrlock);
	}
	sbp->sb_ladrf_refcnt[ladrf_bit]++;

	dlokack(wq, mp, DL_ENABMULTI_REQ);
}

static void
eri_dmreq(queue_t *wq, mblk_t *mp)
{
	struct	eristr	*sbp;
	union	DL_primitives	*dlp;
	struct	ether_addr	*addrp;
	t_uscalar_t off;
	t_uscalar_t len;
	int	i;
	uint32_t mchash;
	struct	ether_addr	*mcbucket;

	sbp = (struct eristr *)wq->q_ptr;
	if (MBLKL(mp) < DL_DISABMULTI_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state == DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->disabmulti_req.dl_addr_length;
	off = dlp->disabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) || !MBLKIN(mp, off, len)) {
		dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Calculate hash value, get pointer to hash bucket for this address.
	 */

	mchash = MCHASH(addrp);
	mcbucket = sbp->sb_mctab[mchash];

	/*
	 * Try and delete the address if we can find it.
	 */
	if (mcbucket) {
		for (i = 0; i < sbp->sb_mccount[mchash]; i++) {
			if (ether_cmp(addrp, &mcbucket[i]) == 0) {
				uint32_t ladrf_bit;

				/*
				 * If there's more than one address in this
				 * bucket, delete the unwanted one by moving
				 * the last one in the list over top of it;
				 * otherwise, just free the bucket.
				 */
				if (sbp->sb_mccount[mchash] > 1) {
					mcbucket[i] =
					    mcbucket[sbp->sb_mccount[mchash]-1];
				} else {
					kmem_free(mcbucket,
					    sbp->sb_mcsize[mchash] *
					    sizeof (struct ether_addr));
					sbp->sb_mctab[mchash] = NULL;
				}
				sbp->sb_mccount[mchash]--;

				/*
				 * If this address's bit should no longer be
				 * set in the local address filter, clear it and
				 * re-initialize the Hardware
				 */

				ladrf_bit = eri_ladrf_bit(addrp);
				sbp->sb_ladrf_refcnt[ladrf_bit]--;

				if (sbp->sb_ladrf_refcnt[ladrf_bit] == 0) {
					sbp->sb_ladrf[15-(ladrf_bit/16)] &=
						~(1 << (ladrf_bit % 16));
					mutex_enter(&sbp->sb_erip->intrlock);
					eri_init_rx(sbp->sb_erip);
					mutex_exit(&sbp->sb_erip->intrlock);
				}

				dlokack(wq, mp, DL_DISABMULTI_REQ);
				return;
			}
		}
	}
	dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_NOTENAB, 0);
}

static void
eri_pareq(queue_t *wq, mblk_t *mp)
{
	struct	eristr		*sbp;
	union	DL_primitives	*dlp;
	uint32_t type;
	struct	eri		*erip;
	struct	ether_addr	addr;

	sbp = (struct eristr *)wq->q_ptr;
	if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	type = dlp->physaddr_req.dl_addr_type;
	erip = sbp->sb_erip;
	if (erip == NULL) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	switch (type) {
	case	DL_FACT_PHYS_ADDR:
		if (erip->addrflags & ERI_FACTADDR_PRESENT)
			ether_bcopy(&erip->factaddr, &addr);
		else
			(void) localetheraddr((struct ether_addr *)NULL, &addr);
		break;

	case	DL_CURR_PHYS_ADDR:
		ether_bcopy(&erip->ouraddr, &addr);
		break;

	default:
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	dlphysaddrack(wq, mp, &addr, ETHERADDRL);
}

static void
eri_spareq(queue_t *wq, mblk_t *mp)
{
	struct	eristr		*sbp;
	union	DL_primitives	*dlp;
	t_uscalar_t off;
	t_uscalar_t len;
	struct	ether_addr	*addrp;
	struct	eri		*erip;

	sbp = (struct eristr *)wq->q_ptr;

	if (MBLKL(mp) < DL_SET_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->set_physaddr_req.dl_addr_length;
	off = dlp->set_physaddr_req.dl_addr_offset;

	if (!MBLKIN(mp, off, len)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	addrp = (struct ether_addr *)(mp->b_rptr + off);

	/*
	 * Error if length of address isn't right or the address
	 * specified is a multicast or broadcast address.
	 */
	if ((len != ETHERADDRL) ||
		((addrp->ether_addr_octet[0] & 01) == 1) ||
		(ether_cmp(addrp, &etherbroadcastaddr) == 0)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Error if this stream is not attached to a device.
	 */
	if ((erip = sbp->sb_erip) == NULL) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	/*
	 * Set new interface local address and re-init device.
	 * This is destructive to any other streams attached
	 * to this device.
	 */
	ether_bcopy(addrp, &erip->ouraddr);
	mutex_enter(&erip->intrlock);
	eri_init_rx(sbp->sb_erip);
	mutex_exit(&erip->intrlock);

	dlokack(wq, mp, DL_SET_PHYS_ADDR_REQ);
}

static void
eri_udreq(queue_t *wq, mblk_t *mp)
{
	struct	eristr		*sbp;
	struct	eri		*erip;
	dl_unitdata_req_t	*dludp;
	mblk_t	*nmp;
	struct	eridladdr	*dlap;
	struct	ether_header	*headerp;
	t_uscalar_t off, len, sap;
	uint_t	start_offset = 0;
	uint_t	stuff_offset = 0;
	uint_t	end_offset = 0;
	uint_t	value = 0;
	uint_t	flags = 0;

	sbp = (struct eristr *)wq->q_ptr;
	erip = sbp->sb_erip;
	if (sbp->sb_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return;
	}

	dludp = (dl_unitdata_req_t *)mp->b_rptr;

	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;

	/*
	 * Validate destination address format.
	 */
	if (!MBLKIN(mp, off, len) || (len != ERI_ADDRL)) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADADDR, 0);
		return;
	}

	/*
	 * Error if no M_DATA follows.
	 */
	nmp = mp->b_cont;
	if (nmp == NULL) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADDATA, 0);
		return;
	}

	dlap = (struct eridladdr *)(mp->b_rptr + off);

	/*
	 * Create ethernet header by either prepending it onto the
	 * next mblk if possible, or reusing the M_PROTO block if not.
	 */
	if ((DB_REF(nmp) == 1) &&
	    (MBLKHEAD(nmp) >= sizeof (struct ether_header)) &&
	    (((uintptr_t)nmp->b_rptr & 0x1) == 0)) {
		nmp->b_rptr -= sizeof (struct ether_header);
		headerp = (struct ether_header *)nmp->b_rptr;
		ether_bcopy(&dlap->dl_phys, &headerp->ether_dhost);
		ether_bcopy(&erip->ouraddr, &headerp->ether_shost);
		sap = (uint16_t)((((uchar_t *)(&dlap->dl_sap))[0] << 8) |
			((uchar_t *)(&dlap->dl_sap))[1]);
		freeb(mp);
		mp = nmp;
	} else {
		DB_TYPE(mp) = M_DATA;
		headerp = (struct ether_header *)mp->b_rptr;
		mp->b_wptr = mp->b_rptr + sizeof (struct ether_header);
		ether_bcopy(&dlap->dl_phys, &headerp->ether_dhost);
		ether_bcopy(&erip->ouraddr, &headerp->ether_shost);
		sap = (uint16_t)((((uchar_t *)(&dlap->dl_sap))[0] << 8) |
			((uchar_t *)(&dlap->dl_sap))[1]);
#ifdef ERI_HWCSUM
		if (sbp->sb_flags & ERI_SCKSUM) {
			hcksum_retrieve(nmp, NULL, NULL, &start_offset,
			    &stuff_offset, &end_offset, &value, &flags);

			if (flags & HCK_PARTIALCKSUM) {
				(void) hcksum_assoc(mp, NULL, NULL,
				    start_offset, stuff_offset, end_offset,
				    0, flags, 0);
				ERI_DEBUG_MSG1(erip, HWCSUM_MSG,
				    "eri_udreq: added new buffer\n");
			}
		}
#endif /* ERI_HWCSUM */
	}

	/*
	 * In 802.3 mode, the driver looks at the
	 * sap field of the DL_BIND_REQ being 0 in addition to the destination
	 * sap field in the range [0-1500]. If either is true, then the driver
	 * computes the length of the message, not including initial M_PROTO
	 * mblk (message block), of all subsequent DL_UNITDATA_REQ messages and
	 * transmits 802.3 frames that have this value in the MAC frame header
	 * length field.
	 */
	if (sap <= ETHERMTU || (sbp->sb_sap == 0)) {
		put_ether_type(headerp,
			(msgsize(mp) - sizeof (struct ether_header)));
	} else {
		put_ether_type(headerp, sap);
	}
	(void) eri_start(wq, mp, erip);
}

static void
eri_nreq(queue_t *wq, mblk_t *mp)
{
	struct eristr	*sbp;
	dl_notify_req_t	*dlip;
	dl_notify_ind_t	*dlnip;
	struct eri	*erip = NULL;
	mblk_t		*nmp;
	uint32_t	dl_notification;

	if (MBLKL(mp) < DL_NOTIFY_REQ_SIZE) {
		dlerrorack(wq, mp, DL_NOTIFY_ACK, DL_BADPRIM, 0);
		return;
	}

	dlip = (dl_notify_req_t *)mp->b_rptr;

	dl_notification = dlip->dl_notifications & (DL_NOTE_PROMISC_ON_PHYS |
						DL_NOTE_PROMISC_OFF_PHYS |
						DL_NOTE_LINK_DOWN |
						DL_NOTE_LINK_UP |
						DL_NOTE_SPEED);

	sbp = (struct eristr *)wq->q_ptr;

	if (sbp->sb_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_NOTIFY_ACK, DL_OUTSTATE, 0);
		return;
	}

	erip = sbp->sb_erip;

	sbp->sb_notifications |= dl_notification;

	dlip->dl_notifications = DL_NOTE_PROMISC_ON_PHYS |
				DL_NOTE_PROMISC_OFF_PHYS |
				DL_NOTE_LINK_DOWN |
				DL_NOTE_LINK_UP |
				DL_NOTE_SPEED;

	dlip->dl_primitive = DL_NOTIFY_ACK;
	mp->b_wptr = mp->b_rptr + DL_NOTIFY_ACK_SIZE;
	qreply(wq, mp);

	while (dl_notification) {
		if ((nmp = allocb(DL_NOTIFY_IND_SIZE, BPRI_HI)) == NULL)
			break;
		nmp->b_datap->db_type = M_PROTO;
		dlnip = (dl_notify_ind_t *)nmp->b_rptr;
		dlnip->dl_primitive = DL_NOTIFY_IND;
		dlnip->dl_notification = 0;
		dlnip->dl_data = 0;
		dlnip->dl_addr_length = 0;
		dlnip->dl_addr_offset = 0;
		if (dl_notification & DL_NOTE_PROMISC_ON_PHYS) {
			dl_notification &= ~DL_NOTE_PROMISC_ON_PHYS;
			if (erip->promisc_cnt)
				dlnip->dl_notification =
					DL_NOTE_PROMISC_ON_PHYS;
		} else if (dl_notification & DL_NOTE_PROMISC_OFF_PHYS) {
			dl_notification &= ~DL_NOTE_PROMISC_OFF_PHYS;
			if (erip->promisc_cnt == 0)
				dlnip->dl_notification =
					DL_NOTE_PROMISC_OFF_PHYS;
		} else if (dl_notification & DL_NOTE_LINK_DOWN) {
			dl_notification &= ~DL_NOTE_LINK_DOWN;
			if (!param_linkup)
				dlnip->dl_notification = DL_NOTE_LINK_DOWN;
		} else if (dl_notification & DL_NOTE_LINK_UP) {
			dl_notification &= ~DL_NOTE_LINK_UP;
			if (param_linkup)
				dlnip->dl_notification = DL_NOTE_LINK_UP;
		} else if (dl_notification & DL_NOTE_SPEED) {
			dl_notification &= ~DL_NOTE_SPEED;
			dlnip->dl_data = erip->stats.ifspeed * 1000;
			dlnip->dl_notification = DL_NOTE_SPEED;
		}
		if (dlnip->dl_notification) {
			nmp->b_wptr = nmp->b_rptr + DL_NOTIFY_IND_SIZE;
			qreply(wq, nmp);
		} else
			freemsg(nmp);
	}
}

static void
eri_notify_ind(struct eri *erip, uint32_t notification)
{
	struct eristr	*sbp;
	mblk_t		*mp;
	dl_notify_ind_t	*dlnip;

	for (sbp = eristrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_erip != erip)
			continue;
		if (notification & sbp->sb_notifications) {
			if ((mp = allocb(DL_NOTIFY_IND_SIZE, BPRI_HI))
			    == NULL) {
				HSTAT(erip, allocbfail);
				break;
			}
			mp->b_datap->db_type = M_PROTO;
			dlnip = (dl_notify_ind_t *)mp->b_rptr;
			dlnip->dl_primitive = DL_NOTIFY_IND;
			dlnip->dl_notification = notification;
			if (notification == DL_NOTE_SPEED)
				dlnip->dl_data = erip->stats.ifspeed * 1000;
			else
				dlnip->dl_data = 0;
			dlnip->dl_addr_length = 0;
			dlnip->dl_addr_offset = 0;
			mp->b_wptr = mp->b_rptr + DL_NOTIFY_IND_SIZE;
			qreply(WR(sbp->sb_rq), mp);
		}
	}
}

/*
 * Set or clear the device ipq pointer.
 * XXX Assumes IPv4 and IPv6 are ERIFAST.
 */
static void
eri_setipq(struct eri *erip)
{
	struct	eristr	*sbp;
	int	ok4 = 1;
	int	ok6 = 1;
	queue_t	*ip4q = NULL;
	queue_t	*ip6q = NULL;

	rw_enter(&eristruplock, RW_READER);

	for (sbp = eristrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_erip == erip) {
			if (sbp->sb_flags & (ERI_SALLPHYS|ERI_SALLSAP)) {
				ok4 = 0;
				ok6 = 0;
				break;
			}
			if (sbp->sb_sap == ETHERTYPE_IPV4) {
				if (ip4q == NULL)
					ip4q = sbp->sb_rq;
				else
					ok4 = 0;
			}
			if (sbp->sb_sap == ETHERTYPE_IPV6) {
				if (ip6q == NULL)
					ip6q = sbp->sb_rq;
				else
					ok6 = 0;
			}
		}
	}

	if (ok4)
		erip->ip4q = ip4q;
	else
		erip->ip4q = NULL;

	if (ok6)
		erip->ip6q = ip6q;
	else
		erip->ip6q = NULL;

	rw_exit(&eristruplock);
}


/*
 * Hardware Functions
 * New Section
 */

/*
 * Initialize the MAC registers. Some of of the MAC  registers are initialized
 * just once since  Global Reset or MAC reset doesn't clear them. Others (like
 * Host MAC Address Registers) are cleared on every reset and have to be
 * reinitialized.
 */
static void
eri_init_macregs_generic(struct eri *erip)

{
	struct	eristr	*sbp;
	uint16_t	ladrf[NMCFILTER_BITS/16];
	int i;

	/*
	 * set up the MAC parameter registers once
	 * after power cycle. SUSPEND/RESUME also requires
	 * setting these registers.
	 */
	if ((erip->stats.inits == 1) || (erip->init_macregs)) {
		erip->init_macregs = 0;
		PUT_MACREG(ipg0, param_ipg0);
		PUT_MACREG(ipg1, param_ipg1);
		PUT_MACREG(ipg2, param_ipg2);
		PUT_MACREG(macmin, BMAC_MIN_FRAME_SIZE);
#ifdef	ERI_RX_TAG_ERROR_WORKAROUND
		PUT_MACREG(macmax, BMAC_MAX_FRAME_SIZE_TAG | BMAC_MAX_BURST);
#else
		PUT_MACREG(macmax, BMAC_MAX_FRAME_SIZE | BMAC_MAX_BURST);
#endif
		PUT_MACREG(palen, BMAC_PREAMBLE_SIZE);
		PUT_MACREG(jam, BMAC_JAM_SIZE);
		PUT_MACREG(alimit, BMAC_ATTEMPT_LIMIT);
		PUT_MACREG(macctl_type, BMAC_CONTROL_TYPE);
		PUT_MACREG(rseed,
			((erip->ouraddr.ether_addr_octet[0] & 0x3) << 8) |
			erip->ouraddr.ether_addr_octet[1]);

		PUT_MACREG(madd3, BMAC_ADDRESS_3);
		PUT_MACREG(madd4, BMAC_ADDRESS_4);
		PUT_MACREG(madd5, BMAC_ADDRESS_5);

		/* Program MAC Control address */
		PUT_MACREG(madd6, BMAC_ADDRESS_6);
		PUT_MACREG(madd7, BMAC_ADDRESS_7);
		PUT_MACREG(madd8, BMAC_ADDRESS_8);

		PUT_MACREG(afr0, BMAC_AF_0);
		PUT_MACREG(afr1, BMAC_AF_1);
		PUT_MACREG(afr2, BMAC_AF_2);
		PUT_MACREG(afmr1_2, BMAC_AF21_MASK);
		PUT_MACREG(afmr0, BMAC_AF0_MASK);
	}

	/* The counters need to be zeroed */
	PUT_MACREG(nccnt, 0);
	PUT_MACREG(fccnt, 0);
	PUT_MACREG(excnt, 0);
	PUT_MACREG(ltcnt, 0);
	PUT_MACREG(dcnt,  0);
	PUT_MACREG(frcnt, 0);
	PUT_MACREG(lecnt, 0);
	PUT_MACREG(aecnt, 0);
	PUT_MACREG(fecnt, 0);
	PUT_MACREG(rxcv,  0);

	if (erip->pauseTX)
		PUT_MACREG(spcmd, BMAC_SEND_PAUSE_CMD);
	else
		PUT_MACREG(spcmd, 0);
	/*
	 * Program BigMAC with local individual ethernet address.
	 */
	PUT_MACREG(madd0, (erip->ouraddr.ether_addr_octet[4] << 8) |
		erip->ouraddr.ether_addr_octet[5]);
	PUT_MACREG(madd1, (erip->ouraddr.ether_addr_octet[2] << 8) |
		erip->ouraddr.ether_addr_octet[3]);
	PUT_MACREG(madd2, (erip->ouraddr.ether_addr_octet[0] << 8) |
		erip->ouraddr.ether_addr_octet[1]);

	/*
	 * Set up multicast address filter by passing all multicast
	 * addresses through a crc generator, and then using the
	 * low order 8 bits as a index into the 256 bit logical
	 * address filter. The high order four bits select the word,
	 * while the rest of the bits select the bit within the word.
	 */

	bzero((caddr_t)ladrf, NMCFILTER_BITS/16 * sizeof (uint16_t));

	/*
	 * Here we initialize the MC Hash bits
	 */
	for (sbp = eristrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_erip == erip) {
			if (sbp->sb_flags & ERI_SALLMULTI) {
				for (i = 0; i < NMCFILTER_BITS/16; i++) {
					ladrf[i] = 0xffff;
				}
				break;	/* All bits are already on */
			}
			for (i = 0; i < NMCFILTER_BITS/16; i++)
				ladrf[i] |= sbp->sb_ladrf[i];
		}
	}

	PUT_MACREG(hash0, ladrf[0]);
	PUT_MACREG(hash1, ladrf[1]);
	PUT_MACREG(hash2, ladrf[2]);
	PUT_MACREG(hash3, ladrf[3]);
	PUT_MACREG(hash4, ladrf[4]);
	PUT_MACREG(hash5, ladrf[5]);
	PUT_MACREG(hash6, ladrf[6]);
	PUT_MACREG(hash7, ladrf[7]);
	PUT_MACREG(hash8, ladrf[8]);
	PUT_MACREG(hash9, ladrf[9]);
	PUT_MACREG(hash10, ladrf[10]);
	PUT_MACREG(hash11, ladrf[11]);
	PUT_MACREG(hash12, ladrf[12]);
	PUT_MACREG(hash13, ladrf[13]);
	PUT_MACREG(hash14, ladrf[14]);
	PUT_MACREG(hash15, ladrf[15]);

}

static int
eri_flush_txbufs(struct eri *erip)
{
	uint_t	i;
	int	status = 0;
	/*
	 * Free and dvma_unload pending xmit  buffers.
	 * Maintaining the 1-to-1 ordered sequence of
	 * dvma_load() followed by dvma_unload() is critical.
	 * Always unload anything before loading it again.
	 * Never unload anything twice.  Always unload
	 * before freeing the buffer.  We satisfy these
	 * requirements by unloading only those descriptors
	 * which currently have an mblk associated with them.
	 */
	for (i = 0; i < ERI_TPENDING; i++) {
		if (erip->tmblkp[i]) {
			if (erip->eri_dvmaxh)
				dvma_unload(erip->eri_dvmaxh, 2*i, DONT_FLUSH);
			else if ((ddi_dma_unbind_handle(erip->ndmaxh[i]) ==
			    DDI_FAILURE))
				status = -1;
			freeb(erip->tmblkp[i]);
			erip->tmblkp[i] = NULL;
		}
	}
	return (status);
}

static int
eri_flush_rxbufs(struct eri *erip)
{
	uint_t	i;
	int	status = 0;
	/*
	 * Free and dvma_unload pending recv buffers.
	 * Maintaining the 1-to-1 ordered sequence of
	 * dvma_load() followed by dvma_unload() is critical.
	 * Always unload anything before loading it again.
	 * Never unload anything twice.  Always unload
	 * before freeing the buffer.  We satisfy these
	 * requirements by unloading only those descriptors
	 * which currently have an mblk associated with them.
	 */
	for (i = 0; i < ERI_RPENDING; i++) {
		if (erip->rmblkp[i]) {
			if (erip->eri_dvmarh)
				dvma_unload(erip->eri_dvmarh, 2 * i,
						DDI_DMA_SYNC_FORCPU);
			else if ((ddi_dma_unbind_handle(erip->ndmarh[i]) ==
			    DDI_FAILURE))
				status = -1;
			freeb(erip->rmblkp[i]);
			erip->rmblkp[i] = NULL;
		}
	}
	return (status);
}

static void
eri_init_txbufs(struct eri *erip)
{
	/*
	 * Clear TX descriptors.
	 */
	bzero((caddr_t)erip->eri_tmdp, ERI_TPENDING * sizeof (struct eri_tmd));

	/*
	 * sync TXDMA descriptors.
	 */
	ERI_SYNCIOPB(erip, erip->eri_tmdp,
	    (ERI_TPENDING * sizeof (struct eri_tmd)), DDI_DMA_SYNC_FORDEV);
	/*
	 * Reset TMD 'walking' pointers.
	 */
	erip->tcurp = erip->eri_tmdp;
	erip->tnextp = erip->eri_tmdp;
	erip->tx_cur_cnt = 0;
	erip->tx_kick = 0;
	erip->tx_completion = 0;
}

static int
eri_init_rxbufs(struct eri *erip)
{

	ddi_dma_cookie_t	dma_cookie;
	mblk_t			*bp;
	int			i, status = 0;
	uint32_t		ccnt;

	/*
	 * clear rcv descriptors
	 */
	bzero((caddr_t)erip->rmdp, ERI_RPENDING * sizeof (struct rmd));

	for (i = 0; i < ERI_RPENDING; i++) {
		if ((bp = eri_allocb(ERI_BUFSIZE)) == NULL) {
			status = -1;
			ERI_DEBUG_MSG1(erip, RESOURCE_MSG,
					"eri_init_rxbufs allocb failed");
			continue;
		}
		/* Load data buffer to DVMA space */
		if (erip->eri_dvmarh)
			(void) dvma_kaddr_load(erip->eri_dvmarh,
			(caddr_t)bp->b_rptr, ERI_BUFSIZE,
			2 * i, &dma_cookie);
/*
 *		Bind data buffer to DMA handle
 */
		else if (ddi_dma_addr_bind_handle(erip->ndmarh[i], NULL,
			(caddr_t)bp->b_rptr, ERI_BUFSIZE,
			DDI_DMA_READ | DDI_DMA_CONSISTENT,
			DDI_DMA_DONTWAIT, 0,
			&dma_cookie, &ccnt) != DDI_DMA_MAPPED)
				status = -1;

		PUT_RMD((&erip->rmdp[i]), dma_cookie);
		erip->rmblkp[i] = bp;	/* save for later use */
	}

	/*
	 * sync RXDMA descriptors.
	 */
	ERI_SYNCIOPB(erip, erip->rmdp,
		(ERI_RPENDING * sizeof (struct rmd)), DDI_DMA_SYNC_FORDEV);
	/*
	 * Reset RMD 'walking' pointers.
	 */
	erip->rnextp = erip->rmdp;
	erip->rx_completion = 0;
	erip->rx_kick = ERI_RPENDING - 4;
	return (status);
}

static uint32_t
eri_txmac_disable(struct eri *erip)
{
	int	n;

	PUT_MACREG(txcfg, GET_MACREG(txcfg) & ~BMAC_TXCFG_ENAB);
	n = (BMACTXRSTDELAY * 10) / ERI_WAITPERIOD;

	while (--n > 0) {
		drv_usecwait(ERI_WAITPERIOD);
		if ((GET_MACREG(txcfg) & 1) == 0)
			return (0);
	}
	return (1);
}

static uint32_t
eri_rxmac_disable(struct eri *erip)
{
	int	n;
	PUT_MACREG(rxcfg, GET_MACREG(rxcfg) & ~BMAC_RXCFG_ENAB);
	n = BMACRXRSTDELAY / ERI_WAITPERIOD;

	while (--n > 0) {
		drv_usecwait(ERI_WAITPERIOD);
		if ((GET_MACREG(rxcfg) & 1) == 0)
			return (0);
	}
	return (1);
}

/*
 * Return 0 upon success, 1 on failure.
 */
static int
eri_stop(struct eri *erip)
{
	ERI_DEBUG_MSG1(erip, INIT_MSG,
			"eri_stop");
	(void) eri_erx_reset(erip);
	(void) eri_etx_reset(erip);

	/*
	 * set up cache line to 16 for 64 bytes of pci burst size
	 */
	PUT_SWRSTREG(reset, ERI_G_RESET_GLOBAL | ERI_CACHE_LINE_SIZE);

	if (erip->linkcheck) {
		erip->linkcheck = 0;
		erip->global_reset_issued = 2;
	} else {
		param_linkup = 0;
		erip->stats.link_up = ERI_LINK_DOWN;
		erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
		erip->global_reset_issued = -1;
		eri_notify_ind(erip, DL_NOTE_LINK_DOWN);
	}

	ERI_DELAY((GET_SWRSTREG(reset) == ERI_CACHE_LINE_SIZE),
			ERI_MAX_RST_DELAY);
	erip->rx_reset_issued = -1;
	erip->tx_reset_issued = -1;

	/*
	 * workaround for RIO not resetting the interrupt mask
	 * register to default value 0xffffffff.
	 */
	PUT_GLOBREG(intmask, ERI_G_MASK_ALL);

	if (GET_SWRSTREG(reset) == ERI_CACHE_LINE_SIZE) {
		return (0);
	} else {
		ERI_DEBUG_MSG1(erip, XCVR_MSG,
			"cannot stop eri");
		return (1);
	}
}

/*
 * Reset Just the RX Portion
 * Return 0 upon success, 1 on failure.
 *
 * Resetting the rxdma while there is a rx dma transaction going on the
 * bus, will cause bus hang or parity errors. To avoid this, we would first
 * disable the rxdma by clearing the ENABLE bit (bit 0). To make sure it is
 * disabled, we will poll it until it realy clears. Furthermore, to verify
 * any RX DMA activity is subsided, we delay for 5 msec.
 */
static uint32_t
eri_erx_reset(struct eri *erip)
{
	(void) eri_rxmac_disable(erip); /* Disable the RX MAC */

	PUT_ERXREG(config, 0); /* Disable the RX DMA */
	ERI_DELAY(((GET_ERXREG(config) &  1) == 0), ERI_MAX_RST_DELAY);
	if ((GET_ERXREG(config) & 1) != 0)
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				disable_erx_msg);

	drv_usecwait(5000); /* Delay to insure no RX DMA activity */

	PUT_SWRSTREG(reset, ERI_G_RESET_ERX | ERI_CACHE_LINE_SIZE);
	/*
	 * Wait until the reset is completed which is indicated by
	 * the reset bit cleared or time out..
	 */
	ERI_DELAY(((GET_SWRSTREG(reset) &  (ERI_G_RESET_ERX)) ==
		ERI_CACHE_LINE_SIZE), ERI_MAX_RST_DELAY);
	erip->rx_reset_issued = -1;

	if (GET_SWRSTREG(reset) & (ERI_G_RESET_ERX)) {
		ERI_DEBUG_MSG1(erip, INIT_MSG,
				"Can not reset erx");
		return (1);
	} else
		return (0);
}

/*
 * Reset Just the TX Portion
 * Return 0 upon success, 1 on failure.
 * Resetting the txdma while there is a tx dma transaction on the bus, may cause
 * bus hang or parity errors. To avoid this we would first disable the txdma by
 * clearing the ENABLE bit (bit 0). To make sure it is disabled, we will poll
 * it until it realy clears. Furthermore, to any TX DMA activity is subsided,
 * we delay for 1 msec.
 */
static uint32_t
eri_etx_reset(struct eri *erip)
{
	(void) eri_txmac_disable(erip);
	PUT_ETXREG(config, 0); /* Disable the TX DMA */
#ifdef ORIG
	ERI_DELAY(((GET_ETXREG(config) &  1) == 0), ERI_MAX_RST_DELAY);
	if ((GET_ETXREG(config) &  1) != 0)
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				disable_etx_msg);
	drv_usecwait(5000); /* Delay  to ensure DMA completed (if any). */
#endif
	drv_usecwait(5000); /* Delay  to ensure DMA completed (if any). */
	ERI_DELAY(((GET_ETXREG(config) &  1) == 0), ERI_MAX_RST_DELAY);
	if ((GET_ETXREG(config) &  1) != 0)
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				disable_etx_msg);

	PUT_SWRSTREG(reset, ERI_G_RESET_ETX | ERI_CACHE_LINE_SIZE);

	/*
	 * Wait until the reset is completed which is indicated by the reset bit
	 * cleared or time out..
	 */
	ERI_DELAY(((GET_SWRSTREG(reset) & (ERI_G_RESET_ETX)) ==
		ERI_CACHE_LINE_SIZE), ERI_MAX_RST_DELAY);
	erip->tx_reset_issued = -1;

	if (GET_SWRSTREG(reset) &  (ERI_G_RESET_ETX)) {
		ERI_DEBUG_MSG1(erip, INIT_MSG,
				"cannot reset eri etx");
		return (1);
	} else
		return (0);
}


/*
 * Initialize the TX DMA registers and Enable the TX DMA.
 */
static uint32_t
eri_init_txregs(struct eri *erip)
{

	uint32_t	i;
	uint64_t	tx_ring;
#ifdef	DEBUG
	uint32_t	txfifoth = ETX_CONFIG_THRESHOLD;
#endif

	/*
	 * Initialize ETX Registers:
	 * config, txring_lo, txring_hi
	 */
	tx_ring = ERI_IOPBIOADDR(erip, erip->eri_tmdp);
	PUT_ETXREG(txring_lo, (uint32_t)(tx_ring));
	PUT_ETXREG(txring_hi, (uint32_t)(tx_ring >> 32));

	/*
	 * Get TX Ring Size Masks.
	 * The ring size ERI_TPENDING is defined in eri_mac.h.
	 */
	switch (ERI_TPENDING) {
	case 32: i = ETX_RINGSZ_32;
		break;
	case 64: i = ETX_RINGSZ_64;
		break;
	case 128: i = ETX_RINGSZ_128;
		break;
	case 256: i = ETX_RINGSZ_256;
		break;
	case 512: i = ETX_RINGSZ_512;
		break;
	case 1024: i = ETX_RINGSZ_1024;
		break;
	case 2048: i = ETX_RINGSZ_2048;
		break;
	case 4096: i = ETX_RINGSZ_4096;
		break;
	default:
		ERI_FAULT_MSG2(erip, SEVERITY_HIGH, ERI_VERB_MSG,
			unk_tx_descr_sze_msg, ERI_TPENDING);
		return (1);
	}

	ERI_DEBUG_MSG2(erip, INIT_MSG,
		"eri_init_txregs: tx fifo threshold %X",
		txfifoth);

	i <<= ERI_TX_RINGSZ_SHIFT;
	PUT_ETXREG(config, ETX_CONFIG_THRESHOLD | i);
	ENABLE_TXDMA(erip);
	ENABLE_MAC(erip);
	return (0);
}


/*
 * Initialize the RX DMA registers and Enable the RX DMA.
 */
static uint32_t
eri_init_rxregs(struct eri *erip)
{
	int i;
	uint64_t	rx_ring;

	/*
	 * Initialize ERX Registers:
	 * rxring_lo, rxring_hi, config, rx_blanking, rx_pause_threshold.
	 * Also, rx_kick
	 * Read and save rxfifo_size.
	 * XXX: Use this to properly configure PAUSE threshold values.
	 */
	rx_ring = ERI_IOPBIOADDR(erip, erip->rmdp);
	PUT_ERXREG(rxring_lo, (uint32_t)(rx_ring));
	PUT_ERXREG(rxring_hi, (uint32_t)(rx_ring >> 32));
	PUT_ERXREG(rx_kick, erip->rx_kick);

	/*
	 * The Max ring size, ERI_RMDMAX is defined in eri_mac.h.
	 * More ERI_RPENDING will provide better performance but requires more
	 * system DVMA memory.
	 * eri_rx_ring_size can be used to tune this value from /etc/system
	 * eri_rx_ring_size cannot be NDD'able due to non-recoverable errors
	 * which cannot be detected from NDD operations
	 */

	/*
	 * get the rxring size bits
	 */
	switch (ERI_RPENDING) {
	case 32: i = ERX_RINGSZ_32;
		break;
	case 64: i = ERX_RINGSZ_64;
		break;
	case 128: i = ERX_RINGSZ_128;
		break;
	case 256: i = ERX_RINGSZ_256;
		break;
	case 512: i = ERX_RINGSZ_512;
		break;
	case 1024: i = ERX_RINGSZ_1024;
		break;
	case 2048: i = ERX_RINGSZ_2048;
		break;
	case 4096: i = ERX_RINGSZ_4096;
		break;
	default:
		ERI_FAULT_MSG2(erip, SEVERITY_HIGH, ERI_VERB_MSG,
			unk_rx_descr_sze_msg, ERI_RPENDING);
		return (1);
	}

	i <<= ERI_RX_RINGSZ_SHIFT;
	i |=  (ERI_FSTBYTE_OFFSET << ERI_RX_CONFIG_FBO_SHIFT) |
		(sizeof (struct ether_header) <<
			ERI_RX_CONFIG_RX_CSSTART_SHIFT) |
		(ERI_RX_FIFOTH_1024 << ERI_RX_CONFIG_RXFIFOTH_SHIFT);

	PUT_ERXREG(config, i);
	PUT_ERXREG(rx_blanking,
		(param_intr_blank_time << ERI_RX_BLNK_INTR_TIME_SHIFT) |
		param_intr_blank_packets);

	PUT_ERXREG(rx_pause_threshold, rx_pause_threshold);
	erip->rxfifo_size = GET_ERXREG(rxfifo_size);
	ENABLE_RXDMA(erip);
	return (0);
}

static int
eri_freebufs(struct eri *erip)
{
	int status = 0;

	status = eri_flush_rxbufs(erip) | eri_flush_txbufs(erip);
	return (status);
}

static void
eri_update_rxbufs(struct eri *erip)
{
	int		i;
	volatile struct rmd  *rmdp, *rmdpbase;

	/*
	 * Hang out receive buffers.
	 */
	rmdpbase = erip->rmdp;
	for (i = 0; i < ERI_RPENDING; i++) {
		rmdp = rmdpbase + i;
		UPDATE_RMD(rmdp);
	}

	/*
	 * sync RXDMA descriptors.
	 */
	ERI_SYNCIOPB(erip, erip->rmdp,
		    (ERI_RPENDING * sizeof (struct rmd)),
		    DDI_DMA_SYNC_FORDEV);
	/*
	 * Reset RMD 'walking' pointers.
	 */
	erip->rnextp =	erip->rmdp;
	erip->rx_completion = 0;
	erip->rx_kick =	ERI_RPENDING - 4;
}

/*
 * This routine is used to reset the RX DMA only. In the case of RX
 * failures such as RX Tag Error, RX hang etc... we don't want to
 * do global reset which takes down the link and clears the FIFO's
 * By doing RX only reset, we leave the TX and the link intact.
 */
static uint32_t
eri_init_rx_channel(struct eri *erip)
{
	erip->flags &= ~ERI_RXINIT;
	(void) eri_erx_reset(erip);
	eri_update_rxbufs(erip);
	if (eri_init_rxregs(erip))
		return (1);
	PUT_MACREG(rxmask, BMAC_RXINTR_MASK);
	PUT_MACREG(rxcfg, GET_MACREG(rxcfg) | BMAC_RXCFG_ENAB);
	erip->rx_reset_issued = 0;
	HSTAT(erip, rx_inits);
	erip->flags |= ERI_RXINIT;
	return (0);
}

static void
eri_init_rx(struct eri *erip)
{
	struct  eristr  *sbp;
	uint16_t	ladrf[NMCFILTER_BITS/16];
	int i;

	/*
	 * First of all make sure the Receive MAC is stop.
	 */
	(void) eri_rxmac_disable(erip); /* Disable the RX MAC */

	/*
	 * Program BigMAC with local individual ethernet address.
	 */

	PUT_MACREG(madd0, (erip->ouraddr.ether_addr_octet[4] << 8) |
	    erip->ouraddr.ether_addr_octet[5]);
	PUT_MACREG(madd1, (erip->ouraddr.ether_addr_octet[2] << 8) |
	    erip->ouraddr.ether_addr_octet[3]);
	PUT_MACREG(madd2, (erip->ouraddr.ether_addr_octet[0] << 8) |
	    erip->ouraddr.ether_addr_octet[1]);

	/*
	 * XXX moved here setting erip->flags from end of this fn.
	 */
	if (erip->promisc_cnt)
		erip->flags |= ERI_PROMISC;
	else
		erip->flags &= ~ERI_PROMISC;
	if (erip->all_multi_cnt)
		erip->flags |= ERI_ALLMULTI;
	else
		erip->flags &= ~ERI_ALLMULTI;

	/*
	 * Set up multicast address filter by passing all multicast
	 * addresses through a crc generator, and then using the
	 * low order 8 bits as a index into the 256 bit logical
	 * address filter. The high order four bits select the word,
	 * while the rest of the bits select the bit within the word.
	 */

	bzero(ladrf, sizeof (ladrf));

	rw_enter(&eristruplock, RW_READER);

	/*
	 * Here we initialize the MC Hash bits
	 */
	for (sbp = eristrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_erip == erip) {
			if (sbp->sb_flags & ERI_SALLMULTI) {
				for (i = 0; i < NMCFILTER_BITS/16; i++) {
					ladrf[i] = 0xffff;
				}
				break;	/* All bits are already on */
			}
			for (i = 0; i < NMCFILTER_BITS/16; i++)
				ladrf[i] |= sbp->sb_ladrf[i];
		}
	}

	/*
	 * Determine if Multicast mode.
	 */
	for (sbp = eristrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_erip == erip) {
			if (sbp->sb_flags & ERI_SMULTI)
				erip->flags |= ERI_MULTICAST;
			else
				erip->flags &= ~ERI_MULTICAST;
			break;
		}
	}

	rw_exit(&eristruplock);

	PUT_MACREG(hash0, ladrf[0]);
	PUT_MACREG(hash1, ladrf[1]);
	PUT_MACREG(hash2, ladrf[2]);
	PUT_MACREG(hash3, ladrf[3]);
	PUT_MACREG(hash4, ladrf[4]);
	PUT_MACREG(hash5, ladrf[5]);
	PUT_MACREG(hash6, ladrf[6]);
	PUT_MACREG(hash7, ladrf[7]);
	PUT_MACREG(hash8, ladrf[8]);
	PUT_MACREG(hash9, ladrf[9]);
	PUT_MACREG(hash10, ladrf[10]);
	PUT_MACREG(hash11, ladrf[11]);
	PUT_MACREG(hash12, ladrf[12]);
	PUT_MACREG(hash13, ladrf[13]);
	PUT_MACREG(hash14, ladrf[14]);
	PUT_MACREG(hash15, ladrf[15]);

#ifdef ERI_DONT_STRIP_CRC
	PUT_MACREG(rxcfg,
	    ((erip->flags & ERI_PROMISC ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->flags & ERI_MULTICAST ? BMAC_RXCFG_HASH : 0) |
	    (erip->flags & ERI_ALLMULTI ? BMAC_RXCFG_GRPROM : 0) |
	    BMAC_RXCFG_ENAB));
#else
	PUT_MACREG(rxcfg,
	    ((erip->flag & ERI_PROMISC ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->flags & ERI_MULTICAST ? BMAC_RXCFG_HASH : 0) |
	    (erip->flags & ERI_ALLMULTI ? BMAC_RXCFG_GRPROM : 0) |
	    BMAC_RXCFG_ENAB | BMAC_RXCFG_STRIP_CRC));
#endif
	/* wait after setting Hash Enable bit */
	/* drv_usecwait(10); */

	HSTAT(erip, rx_inits);

#if 0
	/*
	 * XXX why is this here?
	 * should be moved before setting h/w register.
	 */

	if (erip->promisc_cnt)
		erip->flags |= ERI_PROMISC;
	else
		erip->flags &= ~ERI_PROMISC;
	if (erip->all_multi)
		erip->flags |= ERI_ALLMULTI;
	else
		erip->flags &= ~ERI_ALLMULTI;
#endif

}

#ifdef	LATER_SPLIT_TX_RX
/*
 * This routine is used to reset the TX DMA only.
 *	&erip->xmitlock is held before calling this routine.
 */
void
eri_init_tx_channel(struct eri *erip)
{
	uint32_t	carrier_ext = 0;

	erip->flags &= ~ERI_TXINIT;
	(void) eri_etx_reset(erip);
	PUT_MACREG(txmask, BMAC_TXINTR_MASK);
	(void) eri_init_txregs(erip);
	if (erip->ngu_enable)
		PUT_MACREG(txcfg,
		((param_mode ? BMAC_TXCFG_FDX: 0) |
		((param_lance_mode && (erip->lance_mode_enable)) ?
		BMAC_TXCFG_ENIPG0 : 0) |
		(carrier_ext ? BMAC_TXCFG_CARR_EXT : 0) |
		BMAC_TXCFG_NGU));
	else
		PUT_MACREG(txcfg,
		((param_mode ? BMAC_TXCFG_FDX: 0) |
		((param_lance_mode && (erip->lance_mode_enable)) ?
		BMAC_TXCFG_ENIPG0 : 0) |
		(carrier_ext ? BMAC_TXCFG_CARR_EXT : 0)));

	erip->tx_reset_issued = 0;
	HSTAT(erip, tx_inits);
	erip->flags |= ERI_TXINIT;

}

#endif

/*
 * This routine is used to init the TX MAC only.
 *	&erip->xmitlock is held before calling this routine.
 */
void
eri_init_txmac(struct eri *erip)
{
	uint32_t carrier_ext = 0;

	erip->flags &= ~ERI_TXINIT;
	/*
	 * Stop the Transmit MAC.
	 */
	(void) eri_txmac_disable(erip);

	/*
	 * Must be Internal Transceiver
	 */
	if (param_mode)
		PUT_MACREG(xifc, ((param_transceiver == EXTERNAL_XCVR ?
		    BMAC_XIFC_MIIBUF_OE : 0) | BMAC_XIFC_TX_MII_OE));
	else
		PUT_MACREG(xifc, ((param_transceiver == EXTERNAL_XCVR ?
		    BMAC_XIFC_MIIBUF_OE : 0) | BMAC_XIFC_TX_MII_OE |
		    BMAC_XIFC_DIS_ECHO));

	/*
	 * Initialize the interpacket gap registers
	 */
	PUT_MACREG(ipg1, param_ipg1);
	PUT_MACREG(ipg2, param_ipg2);

	if (erip->ngu_enable)
		PUT_MACREG(txcfg,
		((param_mode ? BMAC_TXCFG_FDX: 0) |
		((param_lance_mode && (erip->lance_mode_enable)) ?
		BMAC_TXCFG_ENIPG0 : 0) |
		(carrier_ext ? BMAC_TXCFG_CARR_EXT : 0) |
		BMAC_TXCFG_NGU));
	else
		PUT_MACREG(txcfg,
		((param_mode ? BMAC_TXCFG_FDX: 0) |
		((param_lance_mode && (erip->lance_mode_enable)) ?
		BMAC_TXCFG_ENIPG0 : 0) |
		(carrier_ext ? BMAC_TXCFG_CARR_EXT : 0)));

	ENABLE_TXDMA(erip);
	ENABLE_TXMAC(erip);

	HSTAT(erip, tx_inits);
	erip->flags |= ERI_TXINIT;
}
/*
 * Start xmit on any msgs previously enqueued on any write queues.
 */
static void
eri_wenable(struct eri *erip)
{
	struct	eristr	*sbp;
	queue_t	*wq;

	/*
	 * Order of wantw accesses is important.
	 */
	do {
		erip->wantw = 0;
		for (sbp = eristrup; sbp; sbp = sbp->sb_nextp)
			if ((wq = WR(sbp->sb_rq))->q_first)
				qenable(wq);
	} while (erip->wantw);
}

static void
eri_unallocthings(struct eri *erip)
{


	uint32_t	flag;
	uint32_t	i;

	flag = erip->alloc_flag;

	if (flag & ERI_DESC_MEM_MAP)
		(void) ddi_dma_unbind_handle(erip->md_h);

	if (flag & ERI_DESC_MEM_ALLOC) {
		ddi_dma_mem_free(&erip->mdm_h);
		erip->rmdp = NULL;
		erip->eri_tmdp = NULL;
	}

	if (flag & ERI_DESC_HANDLE_ALLOC)
		ddi_dma_free_handle(&erip->md_h);

	(void) eri_freebufs(erip);

	if (flag & ERI_XMIT_HANDLE_ALLOC)
		for (i = 0; i < erip->xmit_handle_cnt; i++)
			ddi_dma_free_handle(&erip->ndmaxh[i]);

	if (flag & ERI_XMIT_DVMA_ALLOC) {
		(void) dvma_release(erip->eri_dvmaxh);
		erip->eri_dvmaxh = NULL;
	}

	if (flag & ERI_RCV_HANDLE_ALLOC)
		for (i = 0; i < erip->rcv_handle_cnt; i++)
			ddi_dma_free_handle(&erip->ndmarh[i]);

	if (flag & ERI_RCV_DVMA_ALLOC) {
		(void) dvma_release(erip->eri_dvmarh);
		erip->eri_dvmarh = NULL;
	}

	if (flag & ERI_XBUFS_KMEM_DMABIND) {
		(void) ddi_dma_unbind_handle(erip->tbuf_handle);
		erip->tbuf_ioaddr = 0;
	}

	if (flag & ERI_XBUFS_KMEM_ALLOC) {
		kmem_free(erip->tbuf_kaddr, ERI_TPENDING * eri_tx_bcopy_max);
		erip->tbuf_kaddr = NULL;
	}

	if (flag & ERI_XBUFS_HANDLE_ALLOC) {
		ddi_dma_free_handle(&erip->tbuf_handle);
		erip->tbuf_handle = NULL;
	}

}

/*
 * Initialize channel.
 * Return 0 on success, nonzero on error.
 *
 * The recommended sequence for initialization is:
 * 1. Issue a Global Reset command to the Ethernet Channel.
 * 2. Poll the Global_Reset bits until the execution of the reset has been
 *    completed.
 * 2(a). Use the MIF Frame/Output register to reset the transceiver.
 *	 Poll Register 0 to till the Resetbit is 0.
 * 2(b). Use the MIF Frame/Output register to set the PHY in in Normal-Op,
 *	 100Mbps and Non-Isolated mode. The main point here is to bring the
 *	 PHY out of Isolate mode so that it can generate the rx_clk and tx_clk
 *	 to the MII interface so that the Bigmac core can correctly reset
 *	 upon a software reset.
 * 2(c).  Issue another Global Reset command to the Ethernet Channel and poll
 *	  the Global_Reset bits till completion.
 * 3. Set up all the data structures in the host memory.
 * 4. Program the TX_MAC registers/counters (excluding the TX_MAC Configuration
 *    Register).
 * 5. Program the RX_MAC registers/counters (excluding the RX_MAC Configuration
 *    Register).
 * 6. Program the Transmit Descriptor Ring Base Address in the ETX.
 * 7. Program the Receive Descriptor Ring Base Address in the ERX.
 * 8. Program the Global Configuration and the Global Interrupt Mask Registers.
 * 9. Program the ETX Configuration register (enable the Transmit DMA channel).
 * 10. Program the ERX Configuration register (enable the Receive DMA channel).
 * 11. Program the XIF Configuration Register (enable the XIF).
 * 12. Program the RX_MAC Configuration Register (Enable the RX_MAC).
 * 13. Program the TX_MAC Configuration Register (Enable the TX_MAC).
 */
/*
 * lock order:
 *	intrlock->linklock->eristruplock->xmitlock->xcvrlock
 */
static int
eri_init(struct eri *erip)
{
	struct	eristr	*sbp;
	uint32_t	init_stat = 0;
	uint32_t	partial_init = 0;
	uint32_t	carrier_ext = 0;
	uint32_t	mac_ctl = 0;
	uint_t		ret;
	uint32_t link_timeout	= ERI_LINKCHECK_TIMER;

	ERI_DEBUG_MSG1(erip, INIT_MSG,
			"eri_init: Entered");

	/*
	 * Just return if device is suspended.
	 * eri_init() will be called again from resume.
	 */
	if (erip == NULL) {
		ERI_DEBUG_MSG1(NULL, INIT_MSG,
				"eri_init: erip == NULL");
		ret = 1;
		goto init_exit;
	} else if (erip->flags & ERI_SUSPENDED) {
		ERI_DEBUG_MSG1(NULL, INIT_MSG,
				"eri_init: erip->flags & ERI_SUSPENDED");
		ret = 1;
		goto init_exit;
	}

	ERI_DEBUG_MSG1(erip, INIT_MSG,
			"eri_init: Entered erip");

	mutex_enter(&erip->intrlock);
	eri_stop_timer(erip);	/* acquire linklock */
	rw_enter(&eristruplock, RW_WRITER);
	mutex_enter(&erip->xmitlock);
	erip->flags &= ERI_DLPI_LINKUP;
	erip->wantw = 0;
	HSTAT(erip, inits);
	erip->txhung = 0;

	if (erip->stats.inits > 1)
		eri_savecntrs(erip);

	mutex_enter(&erip->xcvrlock);
	if (!param_linkup || erip->linkcheck) {
		(void) eri_stop(erip);
	}
	if (!(erip->flags & ERI_DLPI_LINKUP) || !param_linkup) {
		erip->flags |= ERI_DLPI_LINKUP;
		eri_mif_poll(erip, MIF_POLL_STOP);
		(void) eri_new_xcvr(erip);
		ERI_DEBUG_MSG1(erip, XCVR_MSG,
				"New transceiver detected.");
		if (param_transceiver != NO_XCVR) {
			/*
			 * Reset the new PHY and bring up the
			 * link
			 */
			if (eri_reset_xcvr(erip)) {
				ERI_FAULT_MSG1(erip, SEVERITY_NONE,
				    ERI_VERB_MSG, "In Init after reset");
				mutex_exit(&erip->xcvrlock);
				link_timeout = 0;
				goto done;
			}
		} else {
			erip->flags |= (ERI_RUNNING | ERI_INITIALIZED);
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			eri_notify_ind(erip, DL_NOTE_LINK_DOWN);
			/*
			 * Still go on and complete the MAC initialization as
			 * xcvr might show up later.
			 * you must return to their mutex ordering.
			 */
		}
		eri_mif_poll(erip, MIF_POLL_START);
	}

	mutex_exit(&erip->xcvrlock);

	/*
	 * Allocate data structures.
	 */
	if (erip->global_reset_issued) {
		if (erip->global_reset_issued == 2) { /* fast path */
			if (eri_flush_txbufs(erip))
				goto done;
			/*
			 * Hang out/Initialize descriptors and buffers.
			 */
			eri_init_txbufs(erip);

			eri_update_rxbufs(erip);
		} else {
			init_stat = eri_allocthings(erip);
			if (init_stat)
				goto done;

			if (eri_freebufs(erip))
				goto done;
			/*
			 * Hang out/Initialize descriptors and buffers.
			 */
			eri_init_txbufs(erip);
			if (eri_init_rxbufs(erip))
				goto done;
		}
	}

	/*
	 * Determine if promiscuous mode or multicast mode.
	 */
	for (sbp = eristrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_erip == erip) {
			if (sbp->sb_flags & ERI_SALLPHYS)
				erip->flags |= ERI_PROMISC;
			if (sbp->sb_flags & ERI_SALLMULTI)
				erip->flags |= ERI_ALLMULTI;
			if (sbp->sb_flags & ERI_SMULTI)
				erip->flags |= ERI_MULTICAST;
			break;
		}
	}


	/*
	 * Determine which internal loopback mode, if any
	 * only one internal loopback mode is set, the checking order is
	 * SERDES/SERIAL_LINK, PCS, and MAC
	 */
	for (sbp = eristrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_erip == erip) {
			if (sbp->sb_flags & ERI_SSERLPBK) {
				erip->flags |= ERI_SERLOOPBACK;
				ERI_DEBUG_MSG2(erip, INIT_MSG,
						"init(): flags = 0x%x\n",
						erip->flags);
				break;
			}

			if (sbp->sb_flags & ERI_SMACLPBK) {
				erip->flags |= ERI_MACLOOPBACK;
				ERI_DEBUG_MSG2(erip, LOOPBACK_MSG,
						"init(): flags = 0x%x\n",
						erip->flags);
				break;
			}
		}
	}

	/*
	 * BigMAC requires that we confirm that tx, rx and hash are in
	 * quiescent state.
	 * MAC will not reset successfully if the transceiver is not reset and
	 * brought out of Isolate mode correctly. TXMAC reset may fail if the
	 * ext. transceiver is just disconnected. If it fails, try again by
	 * checking the transceiver.
	 */
	if (eri_txmac_disable(erip)) {
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				disable_txmac_msg);
		param_linkup = 0;	/* force init again */
		erip->stats.link_up = ERI_LINK_DOWN;
		erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
		eri_notify_ind(erip, DL_NOTE_LINK_DOWN);
		goto done;
	}

	if (eri_rxmac_disable(erip)) {
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				disable_rxmac_msg);
		param_linkup = 0;	/* force init again */
		erip->stats.link_up = ERI_LINK_DOWN;
		erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
		eri_notify_ind(erip, DL_NOTE_LINK_DOWN);
		goto done;
	}

	eri_init_macregs_generic(erip);

	/*
	 * Initialize ERI Global registers :
	 * config
	 * For PCI :  err_mask, bif_cfg
	 *
	 * Use user-configurable parameter for enabling 64-bit transfers.
	 * Note:For PCI, burst sizes are in multiples of 64-bytes.
	 */

	/*
	 * Significant performance improvements can be achieved by
	 * disabling transmit interrupt. Thus TMD's are reclaimed
	 * only very infrequently.
	 * The PCS Interrupt is masked here. It is enabled only when
	 * a PCS link is brought up because there is no second level
	 * mask for this interrupt..
	 * Init GLOBAL, TXMAC, RXMAC and MACCTL interrupt masks here.
	 */
	if (! partial_init) {
		PUT_GLOBREG(intmask, ERI_G_MASK_INTR);
		erip->tx_int_me = 0;
		PUT_MACREG(txmask, BMAC_TXINTR_MASK);
		PUT_MACREG(rxmask, BMAC_RXINTR_MASK);
		PUT_MACREG(macctl_mask, ERI_MACCTL_INTR_MASK);
	}

	if (erip->global_reset_issued) {
		/*
		 * Initialize ETX Registers:
		 * config, txring_lo, txring_hi
		 */
		if (eri_init_txregs(erip))
				goto done;
		/*
		 * Initialize ERX Registers:
		 * rxring_lo, rxring_hi, config, rx_blanking,
		 * rx_pause_threshold.  Also, rx_kick
		 * Read and save rxfifo_size.
		 */
		if (eri_init_rxregs(erip))
			goto done;
	}

	PUT_MACREG(macctl_mask, ERI_MACCTL_INTR_MASK);

	/*
	 * Set up the slottime,and  rxconfig, txconfig without enabling
	 * the latter two at this time
	 */
	PUT_MACREG(slot, BMAC_SLOT_TIME);
	carrier_ext = 0;

#ifdef ERI_DONT_STRIP_CRC
	PUT_MACREG(rxcfg,
	    ((erip->flags & ERI_PROMISC ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->flags & ERI_MULTICAST ? BMAC_RXCFG_HASH : 0) |
	    (erip->flags & ERI_ALLMULTI ? BMAC_RXCFG_GRPROM : 0) |
	    (carrier_ext ? BMAC_RXCFG_CARR_EXT : 0)));
#else
	PUT_MACREG(rxcfg,
	    ((erip->flags & ERI_PROMISC ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->flags & ERI_MULTICAST ? BMAC_RXCFG_HASH : 0) |
	    (erip->flags & ERI_ALLMULTI ? BMAC_RXCFG_GRPROM : 0) |
	    BMAC_RXCFG_STRIP_CRC |
	    (carrier_ext ? BMAC_RXCFG_CARR_EXT : 0)));
#endif
	drv_usecwait(10);	/* wait after setting Hash Enable bit */

	if (erip->ngu_enable)
		PUT_MACREG(txcfg,
		    ((param_mode ? BMAC_TXCFG_FDX: 0) |
		    ((param_lance_mode && (erip->lance_mode_enable)) ?
		    BMAC_TXCFG_ENIPG0 : 0) |
		    (carrier_ext ? BMAC_TXCFG_CARR_EXT : 0) |
		    BMAC_TXCFG_NGU));
	else
		PUT_MACREG(txcfg,
		    ((param_mode ? BMAC_TXCFG_FDX: 0) |
		    ((param_lance_mode && (erip->lance_mode_enable)) ?
		    BMAC_TXCFG_ENIPG0 : 0) |
		    (carrier_ext ? BMAC_TXCFG_CARR_EXT : 0)));

	if (erip->pauseRX)
		mac_ctl = ERI_MCTLCFG_RXPAUSE;
	if (erip->pauseTX)
		mac_ctl |= ERI_MCTLCFG_TXPAUSE;

	PUT_MACREG(macctl_cfg, mac_ctl);

	/*
	 * Must be Internal Transceiver
	 */
	if (param_mode)
		PUT_MACREG(xifc, ((param_transceiver == EXTERNAL_XCVR ?
		    BMAC_XIFC_MIIBUF_OE : 0) | BMAC_XIFC_TX_MII_OE));
	else {
		PUT_MACREG(xifc, ((param_transceiver == EXTERNAL_XCVR ?
		    BMAC_XIFC_MIIBUF_OE : 0) | BMAC_XIFC_TX_MII_OE |
		    BMAC_XIFC_DIS_ECHO));

		link_timeout = ERI_CHECK_HANG_TIMER;
	}

	/*
	 * if MAC int loopback flag is set, put xifc reg in mii loopback
	 * mode {DIAG}
	 */
	if (erip->flags & ERI_MACLOOPBACK) {
		PUT_MACREG(xifc, GET_MACREG(xifc) | BMAC_XIFC_MIILPBK);
		ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
		    "eri_init(): put in MAC int loopback mode\n");
	} else {
		ERI_DEBUG_MSG1(erip, LOOPBACK_MSG,
		    "init(): internal loopback mode not set\n");
	}

	/*
	 * Enable TX and RX MACs.
	 */
	ENABLE_MAC(erip);
	erip->flags |= (ERI_RUNNING | ERI_INITIALIZED |
			    ERI_TXINIT | ERI_RXINIT);
	eri_wenable(erip);
	erip->global_reset_issued = 0;

#ifdef	ERI_10_10_FORCE_SPEED_WORKAROUND
	eri_xcvr_force_mode(erip, &link_timeout);
#endif

done:
	if (init_stat)
		eri_unallocthings(erip);

	mutex_exit(&erip->xmitlock);
	rw_exit(&eristruplock);
	eri_start_timer(erip, eri_check_link, link_timeout);
	mutex_exit(&erip->intrlock);

	ret = !(erip->flags & ERI_RUNNING);
	if (ret) {
		ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
				"eri_init failed");
	}

init_exit:
	ASSERT(!MUTEX_HELD(&erip->linklock));
	return (ret);
}

/*
 * 0 as burstsize upon failure as it signifies no burst size.
 */
static int
eri_burstsize(struct eri *erip)
{
	ddi_dma_handle_t handle;

	if (ddi_dma_alloc_handle(erip->dip, &dma_attr,
				DDI_DMA_DONTWAIT, (caddr_t)0, &handle))
		return (DDI_FAILURE);

	erip->burstsizes = ddi_dma_burstsizes(handle);
	ddi_dma_free_handle(&handle);
	ERI_DEBUG_MSG2(erip, INIT_MSG,
			"burstsize %X", erip->burstsizes);

	if (erip->burstsizes)
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}

/*
 * Un-initialize (STOP) ERI channel.
 */
static void
eri_uninit(struct eri *erip)
{
	/*
	 * Allow up to 'ERI_DRAINTIME' for pending xmit's to complete.
	 */
	ERI_DELAY((erip->tcurp == erip->tnextp), ERI_DRAINTIME);

	mutex_enter(&erip->intrlock);
	eri_stop_timer(erip);   /* acquire linklock */
	mutex_enter(&erip->xmitlock);
	mutex_enter(&erip->xcvrlock);
	eri_mif_poll(erip, MIF_POLL_STOP);
	erip->flags &= ~ERI_DLPI_LINKUP;
	mutex_exit(&erip->xcvrlock);

	(void) eri_stop(erip);
	erip->flags &= ~ERI_RUNNING;

	mutex_exit(&erip->xmitlock);
	eri_start_timer(erip, eri_check_link, 0);
	mutex_exit(&erip->intrlock);
}

/*
 * Allocate CONSISTENT memory for rmds and tmds with appropriate alignment and
 * map it in IO space.
 *
 * The driver allocates STREAMS buffers which will be mapped in DVMA
 * space using DDI DMA resources.
 *
 */
static int
eri_allocthings(struct eri *erip)
{

	uintptr_t	a;
	int		size;
	uint32_t	rval;
	int		i;
	size_t		real_len;
	uint32_t	cookiec;
	int		alloc_stat = 0;
	ddi_dma_cookie_t dma_cookie;

	/*
	 * Return if resources are already allocated.
	 */
	if (erip->rmdp)
		return (alloc_stat);

	erip->alloc_flag = 0;

	/*
	 * Allocate the TMD and RMD descriptors and extra for alignments.
	 */
	size = (ERI_RPENDING * sizeof (struct rmd)
		+ ERI_TPENDING * sizeof (struct eri_tmd)) + ERI_GMDALIGN;

	rval = ddi_dma_alloc_handle(erip->dip, &desc_dma_attr,
			DDI_DMA_DONTWAIT, 0, &erip->md_h);
	if (rval != DDI_SUCCESS) {
		return (++alloc_stat);
	}
	erip->alloc_flag |= ERI_DESC_HANDLE_ALLOC;

	rval = ddi_dma_mem_alloc(erip->md_h, size, &erip->dev_attr,
			DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, 0,
			(caddr_t *)&erip->iopbkbase, &real_len,
			&erip->mdm_h);
	if (rval != DDI_SUCCESS) {
		return (++alloc_stat);
	}
	erip->alloc_flag |= ERI_DESC_MEM_ALLOC;

	rval = ddi_dma_addr_bind_handle(erip->md_h, NULL,
			(caddr_t)erip->iopbkbase, size,
			DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			DDI_DMA_DONTWAIT, 0,
			&erip->md_c, &cookiec);

	if (rval != DDI_DMA_MAPPED)
		return (++alloc_stat);

	erip->alloc_flag |= ERI_DESC_MEM_MAP;

	if (cookiec != 1)
		return (++alloc_stat);

	erip->iopbiobase = erip->md_c.dmac_address;

	a = erip->iopbkbase;
	a = ROUNDUP(a, ERI_GMDALIGN);
	erip->rmdp = (struct rmd *)a;
	a += ERI_RPENDING * sizeof (struct rmd);
	erip->eri_tmdp = (struct eri_tmd *)a;
/*
 *	Specifically we reserve n (ERI_TPENDING + ERI_RPENDING)
 *	pagetable entries. Therefore we have 2 ptes for each
 *	descriptor. Since the ethernet buffers are 1518 bytes
 *	so they can at most use 2 ptes.
 * 	Will do a ddi_dma_addr_setup for each bufer
 */
	/*
	 * In the current implementation, we use the ddi compliant
	 * dma interface. We allocate ERI_TPENDING dma handles for
	 * Transmit  activity and ERI_RPENDING dma handles for receive
	 * activity. The actual dma mapping is done in the io functions
	 * eri_start() and eri_read_dma(),
	 * by calling the ddi_dma_addr_bind_handle.
	 * Dma resources are deallocated by calling ddi_dma_unbind_handle
	 * in eri_reclaim() for transmit and eri_read_dma(), for receive io.
	 */

	if (eri_use_dvma_tx &&
	    (dvma_reserve(erip->dip, &eri_dma_limits, (ERI_TPENDING * 2),
	    &erip->eri_dvmaxh)) == DDI_SUCCESS) {
		erip->alloc_flag |= ERI_XMIT_DVMA_ALLOC;
	} else {
		erip->eri_dvmaxh = NULL;
		for (i = 0; i < ERI_TPENDING; i++) {
			rval = ddi_dma_alloc_handle(erip->dip,
			    &dma_attr, DDI_DMA_DONTWAIT, 0,
			    &erip->ndmaxh[i]);

			if (rval != DDI_SUCCESS) {
				ERI_FAULT_MSG1(erip, SEVERITY_HIGH,
				    ERI_VERB_MSG, alloc_tx_dmah_msg);
				alloc_stat++;
				break;
			}
		}

		erip->xmit_handle_cnt = i;

		if (i)
			erip->alloc_flag |= ERI_XMIT_HANDLE_ALLOC;

		if (alloc_stat)
			return (alloc_stat);
	}

	if (eri_use_dvma_rx &&
	    (dvma_reserve(erip->dip, &eri_dma_limits, (ERI_RPENDING * 2),
	    &erip->eri_dvmarh)) == DDI_SUCCESS) {
		erip->alloc_flag |= ERI_RCV_DVMA_ALLOC;
	} else {
		erip->eri_dvmarh = NULL;

		for (i = 0; i < ERI_RPENDING; i++) {
			rval = ddi_dma_alloc_handle(erip->dip,
			    &dma_attr, DDI_DMA_DONTWAIT,
			    0, &erip->ndmarh[i]);

			if (rval != DDI_SUCCESS) {
				ERI_FAULT_MSG1(erip, SEVERITY_HIGH,
				    ERI_VERB_MSG, alloc_rx_dmah_msg);
				alloc_stat++;
				break;
			}
		}

		erip->rcv_handle_cnt = i;

		if (i)
			erip->alloc_flag |= ERI_RCV_HANDLE_ALLOC;

		if (alloc_stat)
			return (alloc_stat);

	}

/*
 *	Allocate tiny TX buffers
 *	Note: tinybufs must always be allocated in the native
 *	ordering of the CPU (always big-endian for Sparc).
 *	ddi_dma_mem_alloc returns memory in the native ordering
 *	of the bus (big endian for SBus, little endian for PCI).
 *	So we cannot use ddi_dma_mem_alloc(, &erip->ge_dev_attr)
 *	because we'll get little endian memory on PCI.
 */
	if (ddi_dma_alloc_handle(erip->dip, &desc_dma_attr,
		DDI_DMA_DONTWAIT, 0,
		&erip->tbuf_handle) != DDI_SUCCESS) {
			ERI_FAULT_MSG1(erip, SEVERITY_HIGH, ERI_VERB_MSG,
			alloc_tx_dmah_msg);
			return (++alloc_stat);
	}
	erip->alloc_flag |= ERI_XBUFS_HANDLE_ALLOC;
	size = ERI_TPENDING * eri_tx_bcopy_max;
	erip->tbuf_kaddr = (caddr_t)kmem_alloc(size, KM_NOSLEEP);
	if (erip->tbuf_kaddr == NULL) {
		ERI_FAULT_MSG1(erip, SEVERITY_HIGH, ERI_VERB_MSG,
			alloc_tx_dmah_msg);
		return (++alloc_stat);
	}
	erip->alloc_flag |= ERI_XBUFS_KMEM_ALLOC;
	if (ddi_dma_addr_bind_handle(erip->tbuf_handle, NULL,
		erip->tbuf_kaddr, size,
		DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
		DDI_DMA_DONTWAIT, 0,
		&dma_cookie, &cookiec) != DDI_DMA_MAPPED) {
			return (++alloc_stat);
	}
	erip->tbuf_ioaddr = dma_cookie.dmac_address;
	erip->alloc_flag |= ERI_XBUFS_KMEM_DMABIND;
	if (cookiec != 1)
		return (++alloc_stat);

	/*
	 * Keep handy limit values for RMD, TMD, and Buffers.
	 */
	erip->rmdlimp = &((erip->rmdp)[ERI_RPENDING]);
	erip->eri_tmdlimp = &((erip->eri_tmdp)[ERI_TPENDING]);

	/*
	 * Zero out xmit and RCV holders.
	 */
	bzero((caddr_t)erip->tmblkp, sizeof (erip->tmblkp));
	bzero((caddr_t)erip->rmblkp, sizeof (erip->rmblkp));
	return (alloc_stat);
}

/* <<<<<<<<<<<<<<<<<	INTERRUPT HANDLING FUNCTION	>>>>>>>>>>>>>>>>>>>> */
/*
 *	First check to see if it is our device interrupting.
 */
static uint_t
eri_intr(struct eri *erip)
{
	uint32_t erisbits;
	uint32_t mif_status;
	uint32_t serviced = DDI_INTR_UNCLAIMED;
	mutex_enter(&erip->intrlock);

	erisbits = GET_GLOBREG(status);

	ERI_DEBUG_MSG5(erip, DIAG_MSG,
		"eri_intr: start: erip %p gloregp %p status %X intmask %X",
		erip, erip->globregp, erisbits, GET_GLOBREG(intmask));
	/*
	 * Check if it is only the RX_DONE interrupt, which is
	 * the most frequent one.
	 */
	if (((erisbits & ERI_G_STATUS_RX_INT) == ERI_G_STATUS_RX_DONE) &&
			(erip->flags & ERI_RUNNING)) {
		ERI_DEBUG_MSG5(erip, INTR_MSG,
		"eri_intr:(RX_DONE)erip %p gloregp %p status %X intmask %X",
		erip, erip->globregp, erisbits, GET_GLOBREG(intmask));
		serviced = DDI_INTR_CLAIMED;
		goto rx_done_int;
	}

	/* Claim the first interrupt after initialization */
	if (erip->flags & ERI_INITIALIZED) {
		erip->flags &= ~ERI_INITIALIZED;
		serviced = DDI_INTR_CLAIMED;
	}

	/* Check for interesting events */
	if ((erisbits & ERI_G_STATUS_INTR) == 0) {
		ERI_DEBUG_MSG2(erip, DIAG_MSG,
			"eri_intr: Interrupt Not Claimed gsbits  %X", erisbits);
#ifdef	DEBUG
		noteri++;
#endif
		ERI_DEBUG_MSG2(erip, DIAG_MSG,
			"eri_intr:MIF Config = 0x%X",
			GET_MIFREG(mif_cfg));
		ERI_DEBUG_MSG2(erip, DIAG_MSG,
			"eri_intr:MIF imask = 0x%X",
			GET_MIFREG(mif_imask));
		ERI_DEBUG_MSG2(erip, DIAG_MSG,
			"eri_intr:INT imask = 0x%X",
			GET_GLOBREG(intmask));
		ERI_DEBUG_MSG2(erip, DIAG_MSG,
			"eri_intr:alias %X",
			GET_GLOBREG(status_alias));
#ifdef	ESTAR_WORKAROUND
		eri_check_link(erip);
#endif
		mutex_exit(&erip->intrlock);
		return (serviced);
	}
	serviced = DDI_INTR_CLAIMED;

	if (!(erip->flags & ERI_RUNNING)) {
		mutex_exit(&erip->intrlock);
		eri_uninit(erip);
		ERI_DEBUG_MSG1(erip, INTR_MSG,
				"eri_intr: eri not running");
		return (serviced);
	}

	if (erisbits & ERI_G_STATUS_FATAL_ERR) {
		ERI_DEBUG_MSG2(erip, INTR_MSG,
				"eri_intr: fatal error: erisbits = %X",
				erisbits);
		(void) eri_fatal_err(erip, erisbits);
		eri_reinit_fatal++;

		if (erip->rx_reset_issued) {
			erip->rx_reset_issued = 0;
			(void) eri_init_rx_channel(erip);
			mutex_exit(&erip->intrlock);
		} else {
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			DISABLE_MAC(erip);
			mutex_exit(&erip->intrlock);
			(void) eri_init(erip);
		}
		return (serviced);
	}

	if (erisbits & ERI_G_STATUS_NONFATAL_ERR) {
		ERI_DEBUG_MSG2(erip, INTR_MSG,
			"eri_intr: non-fatal error: erisbits = %X", erisbits);
		(void) eri_nonfatal_err(erip, erisbits);
		if (erip->linkcheck) {
			mutex_exit(&erip->intrlock);
			(void) eri_init(erip);
			return (serviced);
		}
	}

	if (erisbits & ERI_G_STATUS_MIF_INT) {
		uint16_t stat;
		ERI_DEBUG_MSG2(erip, XCVR_MSG,
			"eri_intr:MIF Interrupt:mii_status %X",
			erip->mii_status);
		eri_stop_timer(erip);   /* acquire linklock */

		mutex_enter(&erip->xmitlock);
		mutex_enter(&erip->xcvrlock);
#ifdef	ERI_MIF_POLL_STATUS_WORKAROUND
		mif_status = GET_MIFREG(mif_bsts);
		eri_mif_poll(erip, MIF_POLL_STOP);
		ERI_DEBUG_MSG3(erip, XCVR_MSG,
			"eri_intr: new MIF interrupt status %X XCVR status %X",
			mif_status, erip->mii_status);
		(void) eri_mii_read(erip, ERI_PHY_BMSR, &stat);
		eri_mif_check(erip, stat, stat);

#else
		mif_status = GET_MIFREG(mif_bsts);
		eri_mif_poll(erip, MIF_POLL_STOP);
		eri_mif_check(erip, (uint16_t)mif_status,
			(uint16_t)(mif_status >> 16));
#endif
		eri_mif_poll(erip, MIF_POLL_START);
		mutex_exit(&erip->xcvrlock);
		mutex_exit(&erip->xmitlock);

		if (!erip->openloop_autoneg)
			eri_start_timer(erip, eri_check_link,
				ERI_LINKCHECK_TIMER);
		else
			eri_start_timer(erip, eri_check_link,
				ERI_P_FAULT_TIMER);
	}

	ERI_DEBUG_MSG2(erip, INTR_MSG,
		"eri_intr:May have Read Interrupt status:status %X",
			erisbits);

rx_done_int:
	if ((erisbits & (ERI_G_STATUS_TX_INT_ME)) ||
	    (erip->tx_cur_cnt >= tx_interrupt_rate)) {
		mutex_enter(&erip->xmitlock);
		erip->tx_completion = (uint32_t)(GET_ETXREG(tx_completion) &
		    ETX_COMPLETION_MASK);

		(void) eri_reclaim(erip, erip->tx_completion);
		mutex_exit(&erip->xmitlock);
	}

	if (erisbits & ERI_G_STATUS_RX_DONE) {
		volatile struct	rmd	*rmdp, *rmdpbase;
		volatile uint32_t rmdi;
		uint8_t loop_limit = 0x20;
		uint64_t flags;
		uint32_t rmdmax_mask = erip->rmdmax_mask;

		rmdpbase = erip->rmdp;
		rmdi = erip->rx_completion;
		rmdp = rmdpbase + rmdi;

		ERI_DEBUG_MSG3(erip, INTR_MSG,
			"eri_intr: packet received: rmdp = %X status %X",
				rmdp, erisbits);
		/*
		 * Sync RMD before looking at it.
		 */
		ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
			DDI_DMA_SYNC_FORCPU);
		/*
		 * Loop through each RMD.
		 */

		flags = GET_RMD_FLAGS(rmdp);
		while (((flags & ERI_RMD_OWN) == 0) && (loop_limit)) {
			/* process one packet */
			eri_read_dma(erip, rmdp, rmdi, flags);
			rmdi =  (rmdi + 1) & rmdmax_mask;
			rmdp = rmdpbase + rmdi;

			/*
			 * ERI RCV DMA fetches or updates four descriptors
			 * a time. Also we don't want to update the desc.
			 * batch we just received packet on. So we update
			 * descriptors for every 4 packets and we update
			 * the group of 4 after the current batch.
			 */

			if (!(rmdi % 4)) {
				if (eri_overflow_reset &&
				    (GET_GLOBREG(status_alias) &
				    ERI_G_STATUS_NONFATAL_ERR)) {
					loop_limit = 1;
				} else {
					erip->rx_kick =
						(rmdi + ERI_RPENDING - 4) &
						rmdmax_mask;
					PUT_ERXREG(rx_kick, erip->rx_kick);
				}
			}

			/*
			 * Sync the next RMD before looking at it.
			 */
			ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
				DDI_DMA_SYNC_FORCPU);
			flags = GET_RMD_FLAGS(rmdp);
			loop_limit--;
		}
		erip->rx_completion = rmdi;
	}
	mutex_exit(&erip->intrlock);

	return (serviced);
}

/*
 * Handle interrupts for fatal errors
 * Need reinitialization.
 */
#define	PCI_DATA_PARITY_REP	(1 << 8)
#define	PCI_SING_TARGET_ABORT	(1 << 11)
#define	PCI_RCV_TARGET_ABORT	(1 << 12)
#define	PCI_RCV_MASTER_ABORT	(1 << 13)
#define	PCI_SING_SYSTEM_ERR	(1 << 14)
#define	PCI_DATA_PARITY_ERR	(1 << 15)

/* called with intrlock held */
static void
eri_fatal_err(struct eri *erip, uint32_t erisbits)
{
	uint16_t	pci_status;
	uint32_t	pci_error_int = 0;

	if (erisbits & ERI_G_STATUS_RX_TAG_ERR) {
		ERI_DEBUG_MSG1(erip, FATAL_ERR_MSG,
				"ERI RX Tag Error");
		erip->rx_reset_issued = 1;
		HSTAT(erip, rxtag_err);
	} else {
		erip->global_reset_issued = 1;
		if (erisbits & ERI_G_STATUS_BUS_ERR_INT) {
			pci_error_int = 1;
			HSTAT(erip, pci_error_int);
		} else if (erisbits & ERI_G_STATUS_PERR_INT) {
			HSTAT(erip, parity_error);
		} else {
			HSTAT(erip, unknown_fatal);
			ERI_DEBUG_MSG1(erip, FATAL_ERR_MSG,
				"ERI Unknown fatal error");
		}
	}

	/*
	 * PCI bus error
	 */
	if (pci_error_int && erip->pci_config_handle) {
		pci_status = pci_config_get16(erip->pci_config_handle,
			PCI_CONF_STAT);
		ERI_DEBUG_MSG2(erip, FATAL_ERR_MSG,
			"Bus Error Status %x", pci_status);
		if (pci_status & PCI_DATA_PARITY_REP)
			HSTAT(erip, pci_data_parity_err);
		if (pci_status & PCI_SING_TARGET_ABORT)
			HSTAT(erip, pci_signal_target_abort);
		if (pci_status & PCI_RCV_TARGET_ABORT)
			HSTAT(erip, pci_rcvd_target_abort);
		if (pci_status & PCI_RCV_MASTER_ABORT)
			HSTAT(erip, pci_rcvd_master_abort);
		if (pci_status & PCI_SING_SYSTEM_ERR)
			HSTAT(erip, pci_signal_system_err);
		if (pci_status & PCI_DATA_PARITY_ERR)
			HSTAT(erip, pci_signal_system_err);
		/*
		 * clear it by writing the value that was read back.
		 */
		pci_config_put16(erip->pci_config_handle,
			PCI_CONF_STAT, pci_status);
	}
}

/*
 * Handle interrupts regarding non-fatal events.
 * TXMAC, RXMAC and MACCTL events
 */
static void
eri_nonfatal_err(struct eri *erip, uint32_t erisbits)
{

	uint32_t	txmac_sts, rxmac_sts, macctl_sts, pause_time;

#ifdef ERI_PM_WORKAROUND
	if (pci_report_pmcap(erip->dip, PCI_PM_IDLESPEED,
	    PCI_PM_IDLESPEED_NONE) == DDI_SUCCESS)
		erip->stats.pmcap = ERI_PMCAP_NONE;
#endif

	if (erisbits & ERI_G_STATUS_TX_MAC_INT) {
		txmac_sts = GET_MACREG(txsts);
		if (txmac_sts & BMAC_TXSTS_TX_URUN) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"tx fifo underrun");
			erip->linkcheck = 1;
			HSTAT(erip, txmac_urun);
			HSTAT(erip, oerrors);
		}

		if (txmac_sts & BMAC_TXSTS_MAXPKT_ERR) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"tx max pkt size error");
			erip->linkcheck = 1;
			HSTAT(erip, txmac_maxpkt_err);
			HSTAT(erip, oerrors);
		}
		if (txmac_sts & BMAC_TXSTS_NCC_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"Normal collisions counter expired");
			erip->stats.collisions += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_ECC_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"Excessive collisions counter expired");
			erip->stats.excessive_coll += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_LCC_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"Late collisions counter expired");
			erip->stats.late_coll += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_FCC_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"first collisions counter expired");
			erip->stats.first_coll += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_DEFER_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"defer timer expired");
			HSTAT(erip, defer_timer_exp);
		}

		if (txmac_sts & BMAC_TXSTS_PEAK_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"peak attempts counter expired");
			erip->stats.peak_attempt_cnt += 0x100;
		}
	}

	if (erisbits & ERI_G_STATUS_RX_NO_BUF) {
		ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
				"rx pkt dropped/no free descriptor error");

		if (eri_overflow_reset)
			erip->linkcheck = 1;

		HSTAT(erip, no_free_rx_desc);
		HSTAT(erip, ierrors);
	}
	if (erisbits & ERI_G_STATUS_RX_MAC_INT) {
		rxmac_sts = GET_MACREG(rxsts);
		if (rxmac_sts & BMAC_RXSTS_RX_OVF) {
#ifndef ERI_RMAC_HANG_WORKAROUND
			eri_stop_timer(erip);   /* acquire linklock */
			erip->check_rmac_hang ++;
			erip->check2_rmac_hang = 0;
			erip->rxfifo_wr_ptr = GET_ERXREG(rxfifo_wr_ptr);
			erip->rxfifo_rd_ptr = GET_ERXREG(rxfifo_rd_ptr);

			ERI_DEBUG_MSG5(erip,
			    NONFATAL_MSG,
			    "overflow intr %d: %8x wr:%2x rd:%2x",
			    erip->check_rmac_hang,
			    GET_MACREG(macsm),
			    GET_ERXREG(rxfifo_wr_ptr),
			    GET_ERXREG(rxfifo_rd_ptr));

			eri_start_timer(erip, eri_check_link,
				ERI_CHECK_HANG_TIMER);
#endif
			if (eri_overflow_reset)
				erip->linkcheck = 1;

			HSTAT(erip, rx_overflow);
			HSTAT(erip, ierrors);
		}

		if (rxmac_sts & BMAC_RXSTS_ALE_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"RX Alignment Error Counter Expired");
			erip->stats.rx_align_err += 0x10000;
			erip->stats.ierrors += 0x10000;
		}

		if (rxmac_sts & BMAC_RXSTS_CRC_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"RX CRC Error Counter Expired");
			erip->stats.rx_crc_err += 0x10000;
			erip->stats.ierrors += 0x10000;
		}

		if (rxmac_sts & BMAC_RXSTS_LEN_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"RX Length Error Counter Expired");
			erip->stats.rx_length_err += 0x10000;
			erip->stats.ierrors += 0x10000;
		}

		if (rxmac_sts & BMAC_RXSTS_CVI_EXP) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"Rx Code Violation Err Count Expired");
			erip->stats.rx_code_viol_err += 0x10000;
			erip->stats.ierrors += 0x10000;
		}
	}

	if (erisbits & ERI_G_STATUS_MAC_CTRL_INT) {

		macctl_sts = GET_MACREG(macctl_sts);
		if (macctl_sts & ERI_MCTLSTS_PAUSE_RCVD) {
			pause_time = ((macctl_sts &
					ERI_MCTLSTS_PAUSE_TIME) >> 16);
			ERI_DEBUG_MSG2(erip, NONFATAL_MSG,
				"PAUSE Received. pause time = %X slot_times",
								pause_time);
			HSTAT(erip, pause_rxcount);
			erip->stats.pause_time_count += pause_time;
		}

		if (macctl_sts & ERI_MCTLSTS_PAUSE_STATE) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"Transition to PAUSE state");
			HSTAT(erip, pause_oncount);
		}

		if (macctl_sts & ERI_MCTLSTS_NONPAUSE) {
			ERI_DEBUG_MSG1(erip, NONFATAL_MSG,
					"Transition to non-PAUSE state");
			HSTAT(erip, pause_offcount);

		}
	}

}

/*
 * if this is the first init do not bother to save the
 * counters.
 */
static void
eri_savecntrs(struct eri *erip)
{
	uint32_t	fecnt, aecnt, lecnt, rxcv;
	uint32_t	ltcnt, excnt, fccnt;

	/* XXX What all gets added in ierrors and oerrors? */
	fecnt = GET_MACREG(fecnt);
	HSTATN(erip, rx_crc_err, fecnt);
	PUT_MACREG(fecnt, 0);

	aecnt = GET_MACREG(aecnt);
	HSTATN(erip, rx_align_err, aecnt);
	PUT_MACREG(aecnt, 0);

	lecnt = GET_MACREG(lecnt);
	HSTATN(erip, rx_length_err, lecnt);
	PUT_MACREG(lecnt, 0);

	rxcv = GET_MACREG(rxcv);
	HSTATN(erip, rx_code_viol_err, rxcv);
	PUT_MACREG(rxcv, 0);

	ltcnt = GET_MACREG(ltcnt);
	HSTATN(erip, late_coll, ltcnt);
	PUT_MACREG(ltcnt, 0);

	erip->stats.collisions += (GET_MACREG(nccnt) + ltcnt);
	PUT_MACREG(nccnt, 0);

	excnt = GET_MACREG(excnt);
	HSTATN(erip, excessive_coll, excnt);
	PUT_MACREG(excnt, 0);

	fccnt = GET_MACREG(fccnt);
	HSTATN(erip, first_coll, fccnt);
	PUT_MACREG(fccnt, 0);

	/*
	 * Do not add code violations to input errors.
	 * They are already counted in CRC errors
	 */
	HSTATN(erip, ierrors, (fecnt + aecnt + lecnt));
	HSTATN(erip, oerrors, (ltcnt + excnt));
}

mblk_t *
eri_allocb_sp(size_t size)
{
	mblk_t  *mp;

	size += 128;
	if ((mp = allocb(size + 3 * ERI_BURSTSIZE, BPRI_HI)) == NULL) {
		return (NULL);
	}
	mp->b_wptr += 128;
	mp->b_wptr = (uint8_t *)ROUNDUP2(mp->b_wptr, ERI_BURSTSIZE);
	mp->b_rptr = mp->b_wptr;

	return (mp);
}

mblk_t *
eri_allocb(size_t size)
{
	mblk_t  *mp;

	if ((mp = allocb(size + 3 * ERI_BURSTSIZE, BPRI_HI)) == NULL) {
		return (NULL);
	}
	mp->b_wptr = (uint8_t *)ROUNDUP2(mp->b_wptr, ERI_BURSTSIZE);
	mp->b_rptr = mp->b_wptr;

	return (mp);
}

/*
 * Hardware Dependent Functions
 * New Section.
 */

/* <<<<<<<<<<<<<<<< Fast Ethernet PHY Bit Bang Operations >>>>>>>>>>>>>>>>>> */

static void
send_bit(struct eri *erip, uint32_t x)
{
	PUT_MIFREG(mif_bbdata, x);
	PUT_MIFREG(mif_bbclk, ERI_BBCLK_LOW);
	PUT_MIFREG(mif_bbclk, ERI_BBCLK_HIGH);
}

/*
 * To read the MII register bits according to the IEEE Standard
 */
static uint32_t
get_bit_std(struct eri *erip)
{
	uint32_t	x;

	PUT_MIFREG(mif_bbclk, ERI_BBCLK_LOW);
	drv_usecwait(1);	/* wait for  >330 ns for stable data */
	if (param_transceiver == INTERNAL_XCVR)
		x = (GET_MIFREG(mif_cfg) & ERI_MIF_CFGM0) ? 1 : 0;
	else
		x = (GET_MIFREG(mif_cfg) & ERI_MIF_CFGM1) ? 1 : 0;
	PUT_MIFREG(mif_bbclk, ERI_BBCLK_HIGH);
	return (x);
}

#define	SEND_BIT(x)		send_bit(erip, x)
#define	GET_BIT_STD(x)		x = get_bit_std(erip)


static void
eri_bb_mii_write(struct eri *erip, uint8_t regad, uint16_t data)
{
	uint8_t	phyad;
	int		i;

	PUT_MIFREG(mif_bbopenb, 1);	/* Enable the MII driver */
	phyad = erip->phyad;
	(void) eri_bb_force_idle(erip);
	SEND_BIT(0); SEND_BIT(1);	/* <ST> */
	SEND_BIT(0); SEND_BIT(1);	/* <OP> */
	for (i = 4; i >= 0; i--) {		/* <AAAAA> */
		SEND_BIT((phyad >> i) & 1);
	}
	for (i = 4; i >= 0; i--) {		/* <RRRRR> */
		SEND_BIT((regad >> i) & 1);
	}
	SEND_BIT(1); SEND_BIT(0);	/* <TA> */
	for (i = 0xf; i >= 0; i--) {	/* <DDDDDDDDDDDDDDDD> */
		SEND_BIT((data >> i) & 1);
	}
	PUT_MIFREG(mif_bbopenb, 0);	/* Disable the MII driver */
}

/* Return 0 if OK, 1 if error (Transceiver does not talk management) */
static uint32_t
eri_bb_mii_read(struct eri *erip, uint8_t regad, uint16_t *datap)
{
	uint8_t	phyad;
	int	i;
	uint32_t	x;
	uint32_t	y;

	*datap = 0;

	PUT_MIFREG(mif_bbopenb, 1);	/* Enable the MII driver */
	phyad = erip->phyad;
	(void) eri_bb_force_idle(erip);
	SEND_BIT(0); SEND_BIT(1);	/* <ST> */
	SEND_BIT(1); SEND_BIT(0);	/* <OP> */
	for (i = 4; i >= 0; i--) {		/* <AAAAA> */
		SEND_BIT((phyad >> i) & 1);
	}
	for (i = 4; i >= 0; i--) {		/* <RRRRR> */
		SEND_BIT((regad >> i) & 1);
	}

	PUT_MIFREG(mif_bbopenb, 0);	/* Disable the MII driver */

	GET_BIT_STD(x);
	GET_BIT_STD(y);		/* <TA> */
	for (i = 0xf; i >= 0; i--) {	/* <DDDDDDDDDDDDDDDD> */
		GET_BIT_STD(x);
		*datap += (x << i);
	}
	/* Kludge to get the Transceiver out of hung mode */
	/* XXX: Test if this is still needed */
	GET_BIT_STD(x);
	GET_BIT_STD(x);
	GET_BIT_STD(x);

	return (y);
}

static void
eri_bb_force_idle(struct eri *erip)
{
	int		i;

	for (i = 0; i < 33; i++) {
		SEND_BIT(1);
	}
}

/* <<<<<<<<<<<<<<<<<<<<End of Bit Bang Operations >>>>>>>>>>>>>>>>>>>>>>>> */


/* <<<<<<<<<<<<< Frame Register used for MII operations >>>>>>>>>>>>>>>>>>>> */

#ifdef ERI_FRM_DEBUG
int frame_flag = 0;
#endif

/* Return 0 if OK, 1 if error (Transceiver does not talk management) */
static uint32_t
eri_mii_read(struct eri	*erip, uint8_t regad, uint16_t *datap)
{
	uint32_t frame;
	uint8_t phyad;

	if (param_transceiver == NO_XCVR)
		return (1);	/* No xcvr present */

	if (!erip->frame_enable)
		return (eri_bb_mii_read(erip, regad, datap));

	phyad = erip->phyad;
#ifdef ERI_FRM_DEBUG
	if (!frame_flag) {
		eri_errror(erip->dip, "Frame Register used for MII");
		frame_flag = 1;
	}
#endif
	ERI_DEBUG_MSG3(erip, FRM_MSG,
			"Frame Reg :mii_read: phyad = %X reg = %X ",
			phyad, regad);

	PUT_MIFREG(mif_frame, ERI_MIF_FRREAD |
				(phyad << ERI_MIF_FRPHYAD_SHIFT) |
				(regad << ERI_MIF_FRREGAD_SHIFT));
	MIF_ERIDELAY(300,  phyad, regad);
	frame = GET_MIFREG(mif_frame);
	if ((frame & ERI_MIF_FRTA0) == 0) {
		ERI_DEBUG_MSG2(erip, FRM_MSG,
				"MIF Read failure: data = %X", frame);
		return (1);
	} else {
		*datap = (uint16_t)(frame & ERI_MIF_FRDATA);
		ERI_DEBUG_MSG2(erip, FRM_MSG,
				"Frame Reg :mii_read: successful:data = %X ",
				*datap);
		return (0);
	}

}

static void
eri_mii_write(struct eri *erip, uint8_t regad, uint16_t data)
{
	uint32_t frame;
	uint8_t	phyad;

	if (!erip->frame_enable) {
		eri_bb_mii_write(erip, regad, data);
		return;
	}

	phyad = erip->phyad;

	ERI_DEBUG_MSG4(erip, FRM_MSG,
			"Frame Reg:eri_mii_write: phyad = %X \
			reg = %X data = %X", phyad, regad, data);

	PUT_MIFREG(mif_frame, (ERI_MIF_FRWRITE |
				(phyad << ERI_MIF_FRPHYAD_SHIFT) |
				(regad << ERI_MIF_FRREGAD_SHIFT) | data));
	MIF_ERIDELAY(300,  phyad, regad);
	frame = GET_MIFREG(mif_frame);
	if ((frame & ERI_MIF_FRTA0) == 0) {
		ERI_DEBUG_MSG1(erip, MIF_MSG,
		    mif_write_fail_msg);
	} else {
		ERI_DEBUG_MSG1(erip, FRM_MSG,
				"Frame Reg:eri_mii_write: successful");
		return;
	}
}

/*
 * Return TRUE if the given multicast address is one
 * of those that this particular Stream is interested in.
 */
static int
eri_mcmatch(struct eristr *sbp, struct ether_addr *addrp)
{
	struct	ether_addr *mcbucket;
	int	mccount;
	int	i;
	int	mchash;

	/*
	 * Return FALSE if not a multicast address.
	 */
	if (!(addrp->ether_addr_octet[0] & 01))
		return (0);

	/*
	 * Check if all multicasts have been enabled for this Stream
	 */
	if (sbp->sb_flags & ERI_SALLMULTI)
		return (1);

	/*
	 * Compute the hash value for the address and
	 * grab the bucket and the number of entries in the
	 * bucket.
	 */
	mchash = MCHASH(addrp);
	mcbucket = sbp->sb_mctab[mchash];
	mccount = sbp->sb_mccount[mchash];

	/*
	 * Return FALSE if no multicast addresses enabled for this Stream.
	 */
	if (mccount == 0)
		return (0);

	/*
	 * Otherwise, find it in the table.
	 */
	if (mcbucket)
		for (i = 0; i < mccount; i++)
			if (!ether_cmp(addrp, &mcbucket[i]))
				return (1);
	return (0);
}

/*
 * Send packet upstream.
 * Assume mp->b_rptr points to ether_header.
 */
static void
eri_sendup(struct eri *erip, mblk_t *mp, struct eristr *(*acceptfunc)())
{
	struct	ether_addr	*dhostp, *shostp;
	struct	eristr	*sbp, *nsbp;
	mblk_t	*nmp;
	uint32_t isgroupaddr;
	int	type;

	ERI_DEBUG_MSG1(erip, ENTER_MSG, "eri_sendup");
	dhostp = &((struct ether_header *)mp->b_rptr)->ether_dhost;
	shostp = &((struct ether_header *)mp->b_rptr)->ether_shost;
	type = get_ether_type(mp->b_rptr);

	isgroupaddr = dhostp->ether_addr_octet[0] & 01;

	/*
	 * While holding a reader lock on the linked list of streams structures,
	 * attempt to match the address criteria for each stream
	 * and pass up the raw M_DATA ("fastpath") or a DL_UNITDATA_IND.
	 */

	rw_enter(&eristruplock, RW_READER);

	if ((sbp = (*acceptfunc)(eristrup, erip, type, dhostp)) == NULL) {
		rw_exit(&eristruplock);
		freemsg(mp);
		return;
	}

	/*
	 * Loop on matching open streams until (*acceptfunc)() returns NULL.
	 */
	for (; nsbp = (*acceptfunc)(sbp->sb_nextp, erip, type, dhostp);
		sbp = nsbp)
		if (canputnext(sbp->sb_rq))
			if (nmp = dupmsg(mp)) {
				if ((sbp->sb_flags & ERI_SFAST) &&
							!isgroupaddr) {
					nmp->b_rptr +=
						sizeof (struct ether_header);
					putnext(sbp->sb_rq, nmp);
				} else if (sbp->sb_flags & ERI_SRAW)
					putnext(sbp->sb_rq, nmp);
				else if ((nmp = eri_addudind(erip, nmp, shostp,
						dhostp, type, isgroupaddr)))
						putnext(sbp->sb_rq, nmp);
			} else {
				HSTAT(erip, allocbfail);
		} else {
			HSTAT(erip, nocanput);
		}

	/*
	 * Do the last one.
	 */
	if (canputnext(sbp->sb_rq)) {
		if ((sbp->sb_flags & ERI_SFAST) && !isgroupaddr) {
			mp->b_rptr += sizeof (struct ether_header);
			putnext(sbp->sb_rq, mp);
		} else if (sbp->sb_flags & ERI_SRAW)
			putnext(sbp->sb_rq, mp);
		else if ((mp = eri_addudind(erip, mp, shostp, dhostp,
			type, isgroupaddr)))
			putnext(sbp->sb_rq, mp);
	} else {
		freemsg(mp);
		HSTAT(erip, nocanput);
		HSTAT(erip, norcvbuf);
	}

	rw_exit(&eristruplock);
}

/*
 * Prefix msg with a DL_UNITDATA_IND mblk and return the new msg.
 */
static mblk_t *
eri_addudind(struct eri *erip, mblk_t *mp, struct ether_addr *shostp,
    struct ether_addr *dhostp, int type, uint32_t isgroupaddr)
{
	dl_unitdata_ind_t	*dludindp;
	struct	eridladdr	*dlap;
	mblk_t	*nmp;
	int	size;

	mp->b_rptr += sizeof (struct ether_header);

	/*
	 * Allocate an M_PROTO mblk for the DL_UNITDATA_IND.
	 */
	size = sizeof (dl_unitdata_ind_t) + ERI_ADDRL + ERI_ADDRL;
	if ((nmp = eri_allocb(ERI_HEADROOM + size)) == NULL) {
		HSTAT(erip, allocbfail);
		HSTAT(erip, ierrors);
		ERI_DEBUG_MSG1(erip, RESOURCE_MSG,
				"allocb failed");
		freemsg(mp);
		return (NULL);
	}
	DB_TYPE(nmp) = M_PROTO;
	nmp->b_wptr = nmp->b_datap->db_lim;
	nmp->b_rptr = nmp->b_wptr - size;

	/*
	 * Construct a DL_UNITDATA_IND primitive.
	 */
	dludindp = (dl_unitdata_ind_t *)nmp->b_rptr;
	dludindp->dl_primitive = DL_UNITDATA_IND;
	dludindp->dl_dest_addr_length = ERI_ADDRL;
	dludindp->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
	dludindp->dl_src_addr_length = ERI_ADDRL;
	dludindp->dl_src_addr_offset = sizeof (dl_unitdata_ind_t) + ERI_ADDRL;
	dludindp->dl_group_address = isgroupaddr;

	dlap = (struct eridladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t));
	ether_bcopy(dhostp, &dlap->dl_phys);
	dlap->dl_sap = (uint16_t)type;

	dlap = (struct eridladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t)
		+ ERI_ADDRL);
	ether_bcopy(shostp, &dlap->dl_phys);
	dlap->dl_sap = (uint16_t)type;

	/*
	 * Link the M_PROTO and M_DATA together.
	 */
	nmp->b_cont = mp;
	return (nmp);
}

/*
 * Test upstream destination sap and address match.
 */
static struct eristr *
eri_accept(struct eristr *sbp, struct eri *erip, int type,
    struct ether_addr *addrp)
{
	t_uscalar_t sap;
	uint32_t flags;
	for (; sbp; sbp = sbp->sb_nextp) {
		sap = sbp->sb_sap;
		flags = sbp->sb_flags;

		if ((sbp->sb_erip == erip) && ERI_SAPMATCH(sap, type, flags))
			if ((ether_cmp(addrp, &erip->ouraddr) == 0) ||
				(ether_cmp(addrp, &etherbroadcastaddr) == 0) ||
				(flags & ERI_SALLPHYS) ||
				eri_mcmatch(sbp, addrp) ||
				((addrp->ether_addr_octet[0] & 0x01) &&
				flags & ERI_SALLMULTI))
				return (sbp);
	}
	return (NULL);
}

/*
 * Test upstream destination sap and address match for ERI_SALLPHYS only.
 */
/* ARGSUSED3 */
struct eristr *
eri_paccept(struct eristr *sbp, struct eri *erip,
    int type, struct ether_addr *addrp)
{
	t_uscalar_t sap;
	uint32_t flags;

	for (; sbp; sbp = sbp->sb_nextp) {
		sap = sbp->sb_sap;
		flags = sbp->sb_flags;

		if ((sbp->sb_erip == erip) &&
			ERI_SAPMATCH(sap, type, flags) &&
			((flags & ERI_SALLPHYS) ||
			(addrp->ether_addr_octet[0] & 0x01) &&
			(flags & ERI_SALLMULTI)))
			return (sbp);
	}
	return (NULL);
}



/* <<<<<<<<<<<<<<<<<	PACKET TRANSMIT FUNCTIONS	>>>>>>>>>>>>>>>>>>>> */

#define	ERI_CROSS_PAGE_BOUNDRY(i, size, pagesize) \
	((i & pagesize) != ((i + size) & pagesize))

static int
eri_start(queue_t *wq, mblk_t *mp, struct eri *erip)
{
	volatile struct	eri_tmd	*tmdp = NULL;
	volatile struct	eri_tmd	*tbasep = NULL;
	mblk_t		*nmp, *pmp = NULL;
	uint32_t	len = 0, len_msg = 0, xover_len = TX_STREAM_MIN;
	uint32_t	nmblks = 0;
	uint32_t	i, j;
	uint64_t	int_me = 0;
	uint_t		tmdcsum = 0;
	uint_t		start_offset = 0;
	uint_t		stuff_offset = 0;
	uint_t		flags = 0;
	struct ether_header *ehp;

	caddr_t	ptr;
	uint32_t	offset;
	uint64_t	ctrl;
	uint32_t	count;
	uint32_t	flag_dma;
	ddi_dma_cookie_t	c;

	if (!param_linkup) {
		eri_cable_down_msg(erip);
		freemsg(mp);
		HSTAT(erip, oerrors);
		return (0);
	}

	if (erip->flags & ERI_PROMISC)
		if ((pmp = copymsg(mp)) == NULL) { /* copy now, freemsg later */
			HSTAT(erip, allocbfail);
			HSTAT(erip, noxmtbuf);
		}

	nmp = mp;

#ifdef ERI_HWCSUM
	if (((struct eristr *)wq->q_ptr)->sb_flags & ERI_SCKSUM) {
		hcksum_retrieve(mp, NULL, NULL, &start_offset, &stuff_offset,
		    NULL, NULL, &flags);

		if (flags & HCK_PARTIALCKSUM) {
			start_offset += sizeof (*ehp);
			stuff_offset += sizeof (*ehp);
			tmdcsum = ERI_TMD_CSENABL;
		}
	}
#endif /* ERI_HWCSUM */
	while (nmp != NULL) {
		ASSERT(nmp->b_wptr >= nmp->b_rptr);
		nmblks++; /* # of mbs */
		nmp = nmp->b_cont;
	}
	len_msg = msgsize(mp);

	/*
	 * update MIB II statistics
	 */
	ehp = (struct ether_header *)mp->b_rptr;
	BUMP_OutNUcast(erip, ehp);

/*
 * 	----------------------------------------------------------------------
 *	here we deal with 3 cases.
 * 	1. pkt has exactly one mblk
 * 	2. pkt has exactly two mblks
 * 	3. pkt has more than 2 mblks. Since this almost
 *	   always never happens, we copy all of them into
 *	   a msh with one mblk.
 * 	for each mblk in the message, we allocate a tmd and
 * 	figure out the tmd index and tmblkp index.
 * 	----------------------------------------------------------------------
 */
	if (nmblks > 2) { /* more than 2 mbs */
		if ((nmp = eri_allocb(len_msg)) == NULL) {
			HSTAT(erip, allocbfail);
			HSTAT(erip, noxmtbuf);
			freemsg(mp);
			if (pmp)
				freemsg(pmp);
			return (1); /* bad case */
		}
		mcopymsg(mp, nmp->b_rptr);
		nmp->b_wptr = nmp->b_rptr + len_msg;
		mp = nmp;
		nmblks = 1; /* make it one mb */
	} else
		nmp = mp;

	mutex_enter(&erip->xmitlock);

	tbasep = erip->eri_tmdp;

	/* Check if there are enough descriptors for this packet */
	tmdp = erip->tnextp;

	if (tmdp >=  erip->tcurp) /* check notmds */
		i = tmdp - erip->tcurp;
	else
		i = tmdp + ERI_TPENDING - erip->tcurp;

	if (i > (ERI_TPENDING - 4))
		goto notmds;

	if (i >= (ERI_TPENDING >> 1) && !(erip->starts & 0x7))
		int_me = ERI_TMD_INTME;

	for (j = 0; j < nmblks; j++) { /* for one or two mb cases */

		len = nmp->b_wptr - nmp->b_rptr;
		i = tmdp - tbasep; /* index */

		if (len_msg < eri_tx_bcopy_max) { /* tb-all mb */

			offset = (i * eri_tx_bcopy_max);
			ptr = erip->tbuf_kaddr + offset;

			mcopymsg(mp, ptr);

#ifdef	ERI_HDX_BUG_WORKAROUND
			if ((param_mode) || (eri_hdx_pad_enable == 0)) {
				if (len_msg < ETHERMIN) {
					bzero((ptr + len_msg),
					    (ETHERMIN - len_msg));
					len_msg = ETHERMIN;
				}
			} else {
				if (len_msg < 97) {
					bzero((ptr + len_msg), (97 - len_msg));
					len_msg = 97;
				}
			}
#endif
			len = len_msg;
			c.dmac_address = erip->tbuf_ioaddr + offset;
			(void) ddi_dma_sync(erip->tbuf_handle,
					(off_t)offset, len_msg,
					DDI_DMA_SYNC_FORDEV);
			nmblks = 1; /* exit this for loop */
		} else if ((!j) && (len < eri_tx_bcopy_max)) { /* tb-1st mb */

			offset = (i * eri_tx_bcopy_max);
			ptr = erip->tbuf_kaddr + offset;

			bcopy(mp->b_rptr, ptr, len);

			c.dmac_address = erip->tbuf_ioaddr + offset;
			(void) ddi_dma_sync(erip->tbuf_handle,
					(off_t)offset, len,
					DDI_DMA_SYNC_FORDEV);
			nmp = mp->b_cont;
			mp->b_cont = NULL;
			freeb(mp);
		} else if (erip->eri_dvmaxh != NULL) { /* fast DVMA */

			(void) dvma_kaddr_load(erip->eri_dvmaxh,
				(caddr_t)nmp->b_rptr, len, 2 * i, &c);
			(void) dvma_sync(erip->eri_dvmaxh,
				2 * i, DDI_DMA_SYNC_FORDEV);

			erip->tmblkp[i] = nmp;
			if (!j) {
				nmp = mp->b_cont;
				mp->b_cont = NULL;
			}

		} else { /* DDI DMA */
			if (len < xover_len)
				flag_dma = DDI_DMA_WRITE | DDI_DMA_CONSISTENT;
			else
				flag_dma = DDI_DMA_WRITE | DDI_DMA_STREAMING;

			if (ddi_dma_addr_bind_handle(erip->ndmaxh[i],
			    NULL, (caddr_t)nmp->b_rptr, len,
			    flag_dma, DDI_DMA_DONTWAIT, NULL, &c,
			    &count) != DDI_DMA_MAPPED) {
				if (j) { /* free previous DMV resources */
					i = erip->tnextp - tbasep;
					if (erip->ndmaxh[i]) { /* DDI DMA */
						(void) ddi_dma_unbind_handle(
						    erip->ndmaxh[i]);
						erip->ndmaxh[i] = NULL;
						freeb(mp);
					}
					freeb(nmp);
				} else {
					freemsg(mp);
				}

				mutex_exit(&erip->xmitlock);
				HSTAT(erip, noxmtbuf);

				if (pmp)
					freemsg(pmp);

				return (1); /* bad case */
			}

			erip->tmblkp[i] = nmp;
			if (!j) {
				nmp = mp->b_cont;
				mp->b_cont = NULL;
			}
		}

		ctrl = 0;
		/* first descr of packet */
		if (!j) {
			ctrl = ERI_TMD_SOP| int_me | tmdcsum |
				(start_offset << ERI_TMD_CSSTART_SHIFT) |
				(stuff_offset << ERI_TMD_CSSTUFF_SHIFT);
		}

		/* last descr of packet */
		if ((j + 1) == nmblks) {
			ctrl |= ERI_TMD_EOP;
		}

		PUT_TMD(tmdp, c, len, ctrl);
		ERI_SYNCIOPB(erip, tmdp, sizeof (struct eri_tmd),
				DDI_DMA_SYNC_FORDEV);

		tmdp = NEXTTMD(erip, tmdp);
		erip->tx_cur_cnt++;
	} /* for each nmp */

	erip->tx_kick = tmdp - tbasep;
	PUT_ETXREG(tx_kick, erip->tx_kick);
	erip->tnextp = tmdp;

	erip->starts++;

	if (erip->tx_cur_cnt >= tx_interrupt_rate) {
		erip->tx_completion = (uint32_t)(GET_ETXREG(tx_completion) &
		    ETX_COMPLETION_MASK);
		(void) eri_reclaim(erip, erip->tx_completion);
	}
	mutex_exit(&erip->xmitlock);

	if (pmp != NULL) {	/* pmp is copied at the beginning */
		if (erip->flags & (ERI_PROMISC | ERI_ALLMULTI)) {
			/* will hold reader lock */
			eri_sendup(erip, pmp, eri_paccept);
		} else
			freemsg(pmp);
	}

	return (0);

notmds:
	HSTAT(erip, notmds);
	erip->wantw = 1;

	(void) putbq(wq, mp); /* no qenable, avoid spinning at no-tmds */

	if (!erip->tx_int_me) {
		PUT_GLOBREG(intmask, GET_GLOBREG(intmask) &
		    ~(ERI_G_MASK_TX_INT_ME));
		erip->tx_int_me = 1;
	}

	if (erip->tx_cur_cnt >= tx_interrupt_rate) {
		erip->tx_completion = (uint32_t)(GET_ETXREG(tx_completion) &
		    ETX_COMPLETION_MASK);
		(void) eri_reclaim(erip, erip->tx_completion); /* qenable */
	}

	mutex_exit(&erip->xmitlock);

	if (pmp)
		freemsg(pmp);

	return (1);
}

/*
 * Transmit completion reclaiming.
 */
static uint_t
eri_reclaim(struct eri *erip, uint32_t tx_completion)
{
	volatile struct	eri_tmd	*tmdp;
	struct	eri_tmd	*tcomp;
	struct	eri_tmd	*tbasep;
	struct	eri_tmd	*tlimp;
	mblk_t *bp;
	int	i;
	uint64_t	flags;
	uint_t reclaimed = 0;

	tbasep = erip->eri_tmdp;
	tlimp = erip->eri_tmdlimp;

	tmdp = erip->tcurp;
	tcomp = tbasep + tx_completion; /* pointer to completion tmd */

	/*
	 * Loop through each TMD starting from tcurp and upto tcomp.
	 */
	while (tmdp != tcomp) {
		flags = GET_TMD_FLAGS(tmdp);
		if (flags & (ERI_TMD_SOP))
			HSTAT(erip, opackets64);

		HSTATN(erip, obytes64, (flags & ERI_TMD_BUFSIZE));

		i = tmdp - tbasep;
		bp = erip->tmblkp[i];

		/* dvma handle case */

		if (bp) {
			if (erip->eri_dvmaxh) {
				(void) dvma_unload(erip->eri_dvmaxh, 2 * i,
						(uint_t)DONT_FLUSH);
			} else

			/* dma handle case. */
				(void) ddi_dma_unbind_handle(erip->ndmaxh[i]);

			freeb(bp);
			erip->tmblkp[i] = NULL;

		}
		tmdp = NEXTTMDP(tbasep, tlimp, tmdp);
		reclaimed++;
	}

	erip->tcurp = tmdp;
	erip->tx_cur_cnt -= reclaimed;

	if (reclaimed) {
		if (erip->wantw) {
			mutex_enter(&eriwenlock);
			eri_wenable(erip);
			mutex_exit(&eriwenlock);
		}
	}

	return (reclaimed);
}


/* <<<<<<<<<<<<<<<<<<<	PACKET RECEIVE FUNCTIONS	>>>>>>>>>>>>>>>>>>> */
static void
eri_read_dma(struct eri *erip, volatile struct rmd *rmdp,
	int rmdi, uint64_t flags)
{
	mblk_t	*bp, *nbp;
	int	len;
	uint_t ccnt;
	ddi_dma_cookie_t	c;
#ifdef ERI_RCV_CKSUM
	ushort_t sum;
#endif /* ERI_RCV_CKSUM */

	ERI_DEBUG_MSG1(erip, ENTER_MSG, "eri_read_dma");

	bp = erip->rmblkp[rmdi];
	len = (flags & ERI_RMD_BUFSIZE) >> ERI_RMD_BUFSIZE_SHIFT;
#ifdef	ERI_DONT_STRIP_CRC
	len -= 4;
#endif
	/*
	 * In the event of RX FIFO overflow error, ERI REV 1.0 ASIC can
	 * corrupt packets following the descriptor corresponding the
	 * overflow. To detect the corrupted packets, we disable the
	 * dropping of the "bad" packets at the MAC. The descriptor
	 * then would have the "BAD" bit set. We drop the overflowing
	 * packet and the packet following it. We could have done some sort
	 * of checking to determine if the second packet was indeed bad
	 * (using CRC or checksum) but it would be expensive in this
	 * routine, since it is run in interrupt context.
	 */
	if ((flags & ERI_RMD_BAD) || (len  < ETHERMIN) || (len > ETHERMAX)) {
		ERI_DEBUG_MSG3(erip, CORRUPTION_MSG,
		"eri_read_dma: Corrupted Packet is Recieved flags %p length %d",
			flags, len);

		HSTAT(erip, rx_bad_pkts);
		if ((flags & ERI_RMD_BAD) == 0)
			HSTAT(erip, ierrors);
		if (len < ETHERMIN) {
			HSTAT(erip, rx_runt);
		} else if (len > ETHERMAX) {
			HSTAT(erip, rx_toolong_pkts);
		}
		HSTAT(erip, drop);
		UPDATE_RMD(rmdp);

		ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
					DDI_DMA_SYNC_FORDEV);
		return;
	}
#ifdef  ERI_DONT_STRIP_CRC
	{
		uint32_t hw_fcs, tail_fcs;
		/*
		 * since we don't let the hardware strip the CRC in hdx
		 * then the driver needs to do it.
		 * this is to workaround a hardware bug
		 */
		bp->b_wptr = bp->b_rptr + ERI_FSTBYTE_OFFSET + len;
		/*
		 * Get the Checksum calculated by the hardware.
		 */
		hw_fcs = flags & ERI_RMD_CKSUM;
		/*
		 * Catch the case when the CRC starts on an odd
		 * boundary.
		 */
		tail_fcs = bp->b_wptr[0] << 8 | bp->b_wptr[1];
		tail_fcs += bp->b_wptr[2] << 8 | bp->b_wptr[3];
		tail_fcs = (tail_fcs & 0xffff) + (tail_fcs >> 16);
		if ((uintptr_t)(bp->b_wptr) & 1) {
			tail_fcs = (tail_fcs << 8) & 0xffff  | (tail_fcs >> 8);
		}
		hw_fcs += tail_fcs;
		hw_fcs = (hw_fcs & 0xffff) + (hw_fcs >> 16);
		hw_fcs &= 0xffff;
		/*
		 * Now we can replace what the hardware wrote, make believe
		 * it got it right in the first place.
		 */
		flags = (flags & ~(uint64_t)ERI_RMD_CKSUM) | hw_fcs;
	}
#endif
	/*
	 * Packet Processing
	 * Once we get a packet bp, we try allocate a new mblk, nbp
	 * to replace this one. If we succeed, we map it to the current
	 * dma handle and update the descriptor with the new cookie. We
	 * then put bp in our read service queue erip->ipq, if it exists
	 * or we just bp to the streams expecting it.
	 * If allocation of the new mblk fails, we implicitly drop the
	 * current packet, i.e do not pass up the mblk and re-use it.
	 * Re-mapping is not required.
	 */

	if (len < eri_rx_bcopy_max) {
		if ((nbp = eri_allocb_sp(len + ERI_FSTBYTE_OFFSET))) {
			(void) ddi_dma_sync(erip->ndmarh[rmdi], 0,
				len+ERI_FSTBYTE_OFFSET, DDI_DMA_SYNC_FORCPU);
			DB_TYPE(nbp) = M_DATA;
			bcopy(bp->b_rptr, nbp->b_rptr,
				len + ERI_FSTBYTE_OFFSET);
			UPDATE_RMD(rmdp);
			ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
				DDI_DMA_SYNC_FORDEV);

			/* Add the First Byte offset to the b_rptr */
			nbp->b_rptr += ERI_FSTBYTE_OFFSET;
			nbp->b_wptr = nbp->b_rptr + len;

#ifdef ERI_RCV_CKSUM
			sum = ~(uint16_t)(flags & ERI_RMD_CKSUM);
			ERI_PROCESS_READ(erip, nbp, sum);
#else
			ERI_PROCESS_READ(erip, nbp);
#endif
		} else {

			/*
			 * mblk allocation has failed. Re-use the old mblk for
			 * the next packet. Re-mapping is not required since
			 * the same mblk and dma cookie is to be used again.
			 */
			HSTAT(erip, ierrors);
			HSTAT(erip, allocbfail);
			HSTAT(erip, norcvbuf);

			UPDATE_RMD(rmdp);
			ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
					DDI_DMA_SYNC_FORDEV);
			ERI_DEBUG_MSG1(erip, RESOURCE_MSG,
				"allocb fail");
		}
	} else {
		/* Use dma unmap/map */
		if ((nbp = eri_allocb_sp(ERI_BUFSIZE))) {
			/*
			 * How do we harden this, specially if unbind
			 * succeeds and then bind fails?
			 *  If Unbind fails, we can leave without updating
			 * the descriptor but would it continue to work on
			 * next round?
			 */
			(void) ddi_dma_unbind_handle(erip->ndmarh[rmdi]);
			(void) ddi_dma_addr_bind_handle(erip->ndmarh[rmdi],
				    NULL, (caddr_t)nbp->b_rptr, ERI_BUFSIZE,
				    DDI_DMA_READ | DDI_DMA_CONSISTENT,
				    DDI_DMA_DONTWAIT, 0, &c, &ccnt);

				erip->rmblkp[rmdi] = nbp;
				PUT_RMD(rmdp, c);
				ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
					DDI_DMA_SYNC_FORDEV);

				/* Add the First Byte offset to the b_rptr */

				bp->b_rptr += ERI_FSTBYTE_OFFSET;
				bp->b_wptr = bp->b_rptr + len;

#ifdef ERI_RCV_CKSUM
				sum = ~(uint16_t)(flags & ERI_RMD_CKSUM);
				ERI_PROCESS_READ(erip, bp, sum);
#else
				ERI_PROCESS_READ(erip, bp);
#endif
		} else {

			/*
			 * mblk allocation has failed. Re-use the old mblk for
			 * the next packet. Re-mapping is not required since
			 * the same mblk and dma cookie is to be used again.
			 */
			HSTAT(erip, ierrors);
			HSTAT(erip, allocbfail);
			HSTAT(erip, norcvbuf);

			UPDATE_RMD(rmdp);
			ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
					DDI_DMA_SYNC_FORDEV);
			ERI_DEBUG_MSG1(erip, RESOURCE_MSG,
				"allocb fail");
		}
	}
}

#ifdef	 ERI_SERVICE_ROUTINE
static int
eri_rsrv(queue_t *q)
{
	mblk_t *mp;
	struct  eristr	*sbp = (struct eristr *)q->q_ptr;
	struct  eri	*erip;
	struct		ether_header	*ehp;
	t_uscalar_t	type;
	int		len;

	/*
	 * First check if the stream is still there.
	 * If the stream is detached free all the mblks
	 */
	erip = sbp->sb_erip;
	if (erip == NULL) {
		while (mp = getq(q)) {
			mp->b_wptr = mp->b_rptr;
			freemsg(mp);
		}
		return (-1);
	}

	while (mp = getq(q)) {
		len = mp->b_wptr - mp->b_rptr;
		if ((len  < 0x3c) || (len > 0x5ea)) {
			erip->drop++;
			erip->ierrors++;

			ERI_DEBUG_MSG2(erip, CORRUPTION_MSG,
			    "eri_rsrv: Illegal Size Recieved len %x ", len);

			mp->b_wptr = mp->b_rptr;
		    freemsg(mp);
		    continue;
		}
		ehp = (struct ether_header *)mp->b_rptr;
		type = get_ether_type(ehp);
		/*
		 * ERI 1.0 has an address filtering bug in which
		 * it doesn't do any filtering for the last byte of
		 * the destination MAC address. Thus packets which
		 * are not intended for us can go thu. Here we filter
		 * out these packets. This bug will be fixed in the
		 * next Spin of the ERI ASIC.
		 */

#ifdef ERI_MAC_ADDR_FLTR_BUG
		if (INVALID_MAC_ADDRESS(erip, ehp)) {
			erip->drop++;
			erip->ierrors++;
			ERI_DEBUG_MSG1(erip, CORRUPTION_MSG,
				"Host/Destination MAC address mismatch ");
			mp->b_wptr = mp->b_rptr;
			freemsg(mp);
			continue;
		}
#endif
		/*
		 * update MIB II statistics
		 */
		HSTAT(erip, ipackets64);
		HSTATN(erip, rbytes64, len);

		if ((type == ETHERTYPE_IPV4) && (IS_NOT_MULTICAST(ehp))) {
			mp->b_rptr += sizeof (struct ether_header);
#ifdef ERI_RCV_CKSUM
			if ((sbp->sb_flags & ERI_SCKSUM) &&
			    (sbp->sb_flags & ERI_SFAST)) {
				mp->b_ick_flag = ICK_VALID;
				mp->b_ick_start = mp->b_rptr +
					ERI_IPHDR_OFFSET;
				mp->b_ick_end = mp->b_wptr;
			    }
#endif /* ERI_RCV_CKSUM */
			if (canputnext(q))
				(void) putnext(q, mp);
			else {
				freemsg(mp);
				HSTAT(erip, nocanput);
				HSTAT(erip, ierrors);
			}

		} else if ((type == ETHERTYPE_IPV6) &&
			IS_NOT_MULTICAST(ehp)) {
			mp->b_rptr += sizeof (struct ether_header);
#ifdef ERI_RCV_CKSUM
			if ((sbp->sb_flags & ERI_SCKSUM) &&
			    (sbp->sb_flags & ERI_SFAST)) {
				mp->b_ick_flag = ICK_VALID;
				mp->b_ick_start = mp->b_rptr +
					ERI_IPHDR_OFFSET;
				mp->b_ick_end = mp->b_wptr;
			    }
#endif /* ERI_RCV_CKSUM */
			if (canputnext(q))
				(void) putnext(q, mp);
			else {
				freemsg(mp);
				HSTAT(erip, nocanput);
				HSTAT(erip, ierrors);
			}
		} else {

		/*
		 * Strip the PADs for 802.3
		 */
		if (type <= ETHERMTU)
			mp->b_wptr = mp->b_rptr
			    + sizeof (struct ether_header) + type;
			BUMP_InNUcast(erip, ehp);

			eri_sendup(erip, mp, eri_accept);
		}
	}
	return (0);
}

#endif /*  ERI_SERVICE_ROUTINE */


#define	LINK_STAT_DISPLAY_TIME	20

static void
eri_cable_down_msg(struct eri *erip)
{
	time_t	now = gethrestime_sec();

	if ((erip->linksts_msg) &&
	    ((now - erip->msg_time) > LINK_STAT_DISPLAY_TIME)) {
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_CON_MSG,
				link_down_msg);
		erip->msg_time = now;
	}
}

static int
eri_init_xfer_params(struct eri *erip)
{
	int	prop_len = sizeof (int);
	int	i;
	int	ipg1_conf, ipg2_conf;
	int	use_int_xcvr_conf, pace_count_conf;
	int	autoneg_conf;
	int	anar_100T4_conf;
	int	anar_100fdx_conf, anar_100hdx_conf;
	int	anar_10fdx_conf, anar_10hdx_conf;
	int	ipg0_conf, lance_mode_conf;
	int	intr_blank_time_conf, intr_blank_packets_conf;
	int	anar_pauseTX_conf, anar_pauseRX_conf;
	int	select_link_conf, default_link_conf;
	dev_info_t *dip;

	dip = erip->dip;

	for (i = 0; i < A_CNT(param_arr); i++)
		erip->param_arr[i] = param_arr[i];

	param_device = erip->instance;

	erip->xmit_dma_mode = 0;
	erip->rcv_dma_mode = 0;
	erip->mifpoll_enable = mifpoll_enable;
	erip->lance_mode_enable = lance_mode;
	erip->frame_enable = 1;
	erip->ngu_enable = ngu_enable;

	for (i = 0; i <  A_CNT(param_arr); i++)
		erip->param_display[i] = param_display_mii[i];

	if (!erip->g_nd && !eri_param_register(erip,
	    erip->param_arr, A_CNT(param_arr))) {
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				param_reg_fail_msg);
			return (-1);
		}

	/*
	 * Set up the start-up values for user-configurable parameters
	 * Get the values from the global variables first.
	 * Use the MASK to limit the value to allowed maximum.
	 */
	param_ipg1 = ipg1 & ERI_MASK_8BIT;
	param_ipg2 = ipg2 & ERI_MASK_8BIT;
	param_use_intphy = use_int_xcvr & ERI_MASK_1BIT;
	param_pace_count = pace_size & ERI_MASK_8BIT;
	param_autoneg = adv_autoneg_cap;
	param_anar_100T4 = adv_100T4_cap;
	param_anar_100fdx = adv_100fdx_cap;
	param_anar_100hdx = adv_100hdx_cap;
	param_anar_10fdx = adv_10fdx_cap;
	param_anar_10hdx = adv_10hdx_cap;
	param_ipg0 = ipg0 & ERI_MASK_8BIT;
	param_intr_blank_time = intr_blank_time & ERI_MASK_8BIT;
	param_intr_blank_packets = intr_blank_packets & ERI_MASK_8BIT;
	param_lance_mode = lance_mode & ERI_MASK_1BIT;

	param_select_link = select_link & ERI_MASK_1BIT;
	param_default_link = default_link & ERI_MASK_1BIT;

	param_anar_asm_dir = adv_pauseTX_cap;
	param_anar_pause = adv_pauseRX_cap;
	param_transceiver = NO_XCVR;

/*
 * The link speed may be forced to either 10 Mbps or 100 Mbps using the
 * property "transfer-speed". This may be done in OBP by using the command
 * "apply transfer-speed=<speed> <device>". The speed may be either 10 or 100.
 */
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0,
			"transfer-speed", (caddr_t)&i, &prop_len)
				== DDI_PROP_SUCCESS) {
		ERI_DEBUG_MSG2(erip, PROP_MSG,
		    "eri_init_xfer_params:  transfer-speed property = %X", i);
		param_autoneg = 0;	/* force speed */
		param_anar_100T4 = 0;
		param_anar_10fdx = 0;
		param_anar_10hdx = 0;
		param_anar_100fdx = 0;
		param_anar_100hdx = 0;
		param_anar_asm_dir = 0;
		param_anar_pause = 0;

		if (i == 10)
			param_anar_10hdx = 1;
		else if (i == 100)
			param_anar_100hdx = 1;
	}

	/*
	 * Get the parameter values configured in .conf file.
	 */
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg1",
				(caddr_t)&ipg1_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		ERI_DEBUG_MSG2(erip, PROP_MSG,
			"eri_init_xfer_params: ipg1 property %X", ipg1_conf);
		param_ipg1 = ipg1_conf & ERI_MASK_8BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg2",
				(caddr_t)&ipg2_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_ipg2 = ipg2_conf & ERI_MASK_8BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "use_int_xcvr",
				(caddr_t)&use_int_xcvr_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_use_intphy = use_int_xcvr_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "pace_size",
				(caddr_t)&pace_count_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_pace_count = pace_count_conf & ERI_MASK_8BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_autoneg_cap",
				(caddr_t)&autoneg_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_autoneg = autoneg_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_100T4_cap",
				(caddr_t)&anar_100T4_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_anar_100T4 = anar_100T4_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_100fdx_cap",
				(caddr_t)&anar_100fdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_anar_100fdx = anar_100fdx_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_100hdx_cap",
				(caddr_t)&anar_100hdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_anar_100hdx = anar_100hdx_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_10fdx_cap",
				(caddr_t)&anar_10fdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_anar_10fdx = anar_10fdx_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_10hdx_cap",
				(caddr_t)&anar_10hdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_anar_10hdx = anar_10hdx_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg0",
				(caddr_t)&ipg0_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_ipg0 = ipg0_conf & ERI_MASK_8BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "intr_blank_time",
				(caddr_t)&intr_blank_time_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_intr_blank_time = intr_blank_time_conf & ERI_MASK_8BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "intr_blank_packets",
				(caddr_t)&intr_blank_packets_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_intr_blank_packets =
		    intr_blank_packets_conf & ERI_MASK_8BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "lance_mode",
				(caddr_t)&lance_mode_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_lance_mode = lance_mode_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "select_link",
				(caddr_t)&select_link_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_select_link = select_link_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "default_link",
				(caddr_t)&default_link_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_default_link = default_link_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_asm_dir_cap",
				(caddr_t)&anar_pauseTX_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_anar_asm_dir = anar_pauseTX_conf & ERI_MASK_1BIT;
	}
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_pause_cap",
				(caddr_t)&anar_pauseRX_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		param_anar_pause = anar_pauseRX_conf & ERI_MASK_1BIT;
	}

	if (link_pulse_disabled)
		erip->link_pulse_disabled = 1;
	else if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0,
			"link-pulse-disabled", (caddr_t)&i, &prop_len)
				== DDI_PROP_SUCCESS) {
		ERI_DEBUG_MSG1(erip, PROP_MSG,
				"eri_init_xfer_params: dis link-pulse prop.");
		erip->link_pulse_disabled = 1;
	}
	eri_statinit(erip);
	return (0);

}

static struct eri *
eri_set_ppa(struct eristr *sbp, queue_t *wq)
{
	struct	eri	*erip = NULL;
	int instance;

	if (sbp->sb_erip)	/* ppa has been selected */
		return (sbp->sb_erip);

	instance = device;
	if (device == -1) {	/* select the first one found */
		mutex_enter(&erilock);
		if (eriup)
			instance = eriup->instance;
		mutex_exit(&erilock);
	}
	if (instance == -1 || qassociate(wq, instance) != 0) {
		return (NULL);
	}

	mutex_enter(&erilock);
	for (erip = eriup; erip; erip = erip->nextp)
		if (instance == erip->instance)
			break;
	ASSERT(erip != NULL);
	mutex_exit(&erilock);

	sbp->sb_erip = erip;
	return (erip);
}

static void
eri_process_ndd_ioctl(queue_t *wq, mblk_t *mp, int cmd)
{

	struct	eristr	*sbp = (struct eristr *)wq->q_ptr;
	struct	eri		*erip = sbp->sb_erip;
	struct	eri		*erip1;

	uint32_t old_ipg1, old_ipg2, old_use_int_xcvr, old_autoneg;
	int32_t old_device;
	int32_t new_device;
	uint32_t old_100T4;
	uint32_t old_100fdx, old_100hdx, old_10fdx, old_10hdx;
	uint32_t old_ipg0, old_lance_mode;
	uint32_t old_intr_blank_time, old_intr_blank_packets;
	uint32_t old_asm_dir, old_pause;
	uint32_t old_select_link, old_default_link;

	erip = eri_set_ppa(sbp, wq);

	if (erip == NULL) {	/* no device present */
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	switch (cmd) {
	case ERI_ND_GET:

		ERI_DEBUG_MSG1(erip, NDD_MSG,
				"eri_process_ndd_ioctl:ND_GET");
		mutex_enter(&erilock);
		old_autoneg =	param_autoneg;
		old_100T4 =	param_anar_100T4;
		old_100fdx =	param_anar_100fdx;
		old_100hdx =	param_anar_100hdx;
		old_10fdx =	param_anar_10fdx;
		old_10hdx =	param_anar_10hdx;
		old_asm_dir =	param_anar_asm_dir;
		old_pause =	param_anar_pause;

		param_autoneg = old_autoneg & ~ERI_NOTUSR;
		param_anar_100T4 = old_100T4 & ~ERI_NOTUSR;
		param_anar_100fdx = old_100fdx & ~ERI_NOTUSR;
		param_anar_100hdx = old_100hdx & ~ERI_NOTUSR;
		param_anar_10fdx = old_10fdx & ~ERI_NOTUSR;
		param_anar_10hdx = old_10hdx & ~ERI_NOTUSR;
		param_anar_asm_dir = old_asm_dir & ~ERI_NOTUSR;
		param_anar_pause = old_pause & ~ERI_NOTUSR;

		if (!eri_nd_getset(wq, erip->g_nd, mp)) {
			param_autoneg = old_autoneg;
			param_anar_100T4 = old_100T4;
			param_anar_100fdx = old_100fdx;
			param_anar_100hdx = old_100hdx;
			param_anar_10fdx = old_10fdx;
			param_anar_10hdx = old_10hdx;
			param_anar_asm_dir = old_asm_dir;
			param_anar_pause = old_pause;
			mutex_exit(&erilock);
			ERI_DEBUG_MSG1(erip, NDD_MSG,
					"ndd_ioctl: _nd_getset nak");
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		param_autoneg = old_autoneg;
		param_anar_100T4 = old_100T4;
		param_anar_100fdx = old_100fdx;
		param_anar_100hdx = old_100hdx;
		param_anar_10fdx = old_10fdx;
		param_anar_10hdx = old_10hdx;
		param_anar_asm_dir = old_asm_dir;
		param_anar_pause = old_pause;

		mutex_exit(&erilock);
		ERI_DEBUG_MSG1(erip, NDD_MSG,
				"ndd_ioctl: _nd_getset ack");
		qreply(wq, mp);
		break;

	case ERI_ND_SET:
		ERI_DEBUG_MSG1(erip, NDD_MSG,
				"eri_process_ndd_ioctl:ND_SET");
		old_device = param_device;
		old_ipg0 = param_ipg0;
		old_intr_blank_time = param_intr_blank_time;
		old_intr_blank_packets = param_intr_blank_packets;
		old_lance_mode = param_lance_mode;
		old_ipg1 = param_ipg1;
		old_ipg2 = param_ipg2;
		old_use_int_xcvr = param_use_intphy;
		old_autoneg = param_autoneg;
		old_100T4 =	param_anar_100T4;
		old_100fdx =	param_anar_100fdx;
		old_100hdx =	param_anar_100hdx;
		old_10fdx =	param_anar_10fdx;
		old_10hdx =	param_anar_10hdx;
		param_autoneg = 0xff;
		old_asm_dir = param_anar_asm_dir;
		param_anar_asm_dir = 0xff;
		old_pause = param_anar_pause;
		param_anar_pause = 0xff;
		old_select_link = param_select_link;
		old_default_link = param_default_link;

		mutex_enter(&erilock);
		if (!eri_nd_getset(wq, erip->g_nd, mp)) {
			param_autoneg = old_autoneg;
			mutex_exit(&erilock);
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		mutex_exit(&erilock);

		if (old_device != param_device) {
			new_device = param_device;
			param_device = old_device;
			param_autoneg = old_autoneg;
			if (new_device != -1 &&
			    qassociate(wq, new_device) == 0) {
				mutex_enter(&erilock);
				for (erip1 = eriup; erip1; erip1 = erip1->nextp)
					if (new_device == erip1->instance)
						break;
				mutex_exit(&erilock);
				ASSERT(erip1 != NULL);
			}

			if (erip1 == NULL) {
				miocnak(wq, mp, 0, EINVAL);
				return;
			}
			device = new_device;
			sbp->sb_erip = erip1;
			qreply(wq, mp);
			return;
		}

		qreply(wq, mp);

		if (param_autoneg != 0xff) {
			ERI_DEBUG_MSG2(erip, NDD_MSG,
				"ndd_ioctl: new param_autoneg %d",
				param_autoneg);
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			(void) eri_init(erip);
		} else {
			param_autoneg = old_autoneg;
			if ((old_use_int_xcvr != param_use_intphy) ||
				(old_default_link != param_default_link) ||
				(old_select_link != param_select_link)) {
				param_linkup = 0;
				erip->stats.link_up = ERI_LINK_DOWN;
				erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
				(void) eri_init(erip);
			} else if ((old_ipg1 != param_ipg1) ||
			    (old_ipg2 != param_ipg2) ||
			    (old_ipg0 != param_ipg0) ||
			    (old_intr_blank_time != param_intr_blank_time) ||
			    (old_intr_blank_packets !=
			    param_intr_blank_packets) ||
				(old_lance_mode != param_lance_mode)) {
				param_linkup = 0;
				erip->stats.link_up = ERI_LINK_DOWN;
				erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
				(void) eri_init(erip);
			}
		}
		break;
	default:
		break;
	}
}


static int
eri_stat_kstat_update(kstat_t *ksp, int rw)
{
	struct eri *erip;
	struct erikstat *erikp;
	struct stats *esp;

	erip = (struct eri *)ksp->ks_private;
	erikp = (struct erikstat *)ksp->ks_data;

	/*
	 * Update all the stats by reading all the counter registers.
	 * Counter register stats are not updated till they overflow
	 * and interrupt.
	 */

	mutex_enter(&erip->xmitlock);
	if ((erip->flags & ERI_RUNNING) && (erip->flags & ERI_TXINIT)) {
		erip->tx_completion =
			GET_ETXREG(tx_completion) & ETX_COMPLETION_MASK;
		(void) eri_reclaim(erip, erip->tx_completion);
	}
	mutex_exit(&erip->xmitlock);

	eri_savecntrs(erip);

	esp = &erip->stats;

	if (rw == KSTAT_WRITE) {
		esp->ipackets64	= erikp->erik_ipackets64.value.ull;
		esp->ierrors	= erikp->erik_ierrors.value.ul;
		esp->opackets64	= erikp->erik_opackets64.value.ull;
		esp->oerrors	= erikp->erik_oerrors.value.ul;

		/*
		 * MIB II kstat variables
		 */
		esp->rbytes64	= erikp->erik_rbytes64.value.ull;
		esp->obytes64	= erikp->erik_obytes64.value.ull;
		esp->multircv	= erikp->erik_multircv.value.ul;
		esp->multixmt	= erikp->erik_multixmt.value.ul;
		esp->brdcstrcv	= erikp->erik_brdcstrcv.value.ul;
		esp->brdcstxmt	= erikp->erik_brdcstxmt.value.ul;
		esp->norcvbuf	= erikp->erik_norcvbuf.value.ul;
		esp->noxmtbuf	= erikp->erik_noxmtbuf.value.ul;

#ifdef	kstat
		esp->ifspeed	= erikp->erik_ifspeed.value.ull;
		esp->txmac_urun	= erikp->erik_txmac_urun.value.ul;
		esp->txmac_maxpkt_err =
					erikp->erik_txmac_maxpkt_err.value.ul;

		esp->excessive_coll = erikp->erik_excessive_coll.value.ul;
		esp->late_coll	= erikp->erik_late_coll.value.ul;
		esp->first_coll	= erikp->erik_first_coll.value.ul;
		esp->defer_timer_exp =
					erikp->erik_defer_timer_exp.value.ul;

		esp->peak_attempt_cnt =
					erikp->erik_peak_attempt_cnt.value.ul;
		esp->tx_hang 	= erikp->erik_tx_hang.value.ul;

		esp->rx_corr 	= erikp->erik_rx_corr.value.ul;
		esp->no_free_rx_desc =
					erikp->erik_no_free_rx_desc.value.ul;

		esp->rx_overflow	= erikp->erik_rx_overflow.value.ul;
		esp->rx_hang 	= erikp->erik_rx_hang.value.ul;
		esp->rx_align_err	= erikp->erik_rx_align_err.value.ul;
		esp->rx_crc_err	= erikp->erik_rx_crc_err.value.ul;
		esp->rx_length_err	= erikp->erik_rx_length_err.value.ul;
		esp->rx_code_viol_err =
					erikp->erik_rx_code_viol_err.value.ul;

		esp->pause_rxcount	= erikp->erik_pause_rxcount.value.ul;
		esp->pause_oncount	= erikp->erik_pause_oncount.value.ul;
		esp->pause_offcount = erikp->erik_pause_offcount.value.ul;
		esp->pause_time_count =
					erikp->erik_pause_time_count.value.ul;

		esp->inits		= erikp->erik_inits.value.ul;
		esp->rx_inits	= erikp->erik_rx_inits.value.ul;
		esp->tx_inits	= erikp->erik_tx_inits.value.ul;
		esp->tnocar	= erikp->erik_tnocar.value.ul;
		esp->jab		= erikp->erik_jab.value.ul;
		esp->notmds	= erikp->erik_notmds.value.ul;
		esp->nocanput	= erikp->erik_nocanput.value.ul;
		esp->allocbfail	= erikp->erik_allocbfail.value.ul;
		esp->drop		= erikp->erik_drop.value.ul;
		esp->rx_bad_pkts	= erikp->erik_rx_bad_pkts.value.ul;
		esp->rx_runt		= erikp->erik_rx_runt.value.ul;
		esp->rx_toolong_pkts	= erikp->erik_rx_toolong_pkts.value.ul;

		esp->rxtag_err	= erikp->erik_rxtag_err.value.ul;

		esp->parity_error	= erikp->erik_parity_error.value.ul;

		esp->eri_pci_error_int	= erikp->erik_pci_error_int.value.ul;
		esp->unknown_fatal	= erikp->erik_unknown_fatal.value.ul;
		esp->pci_data_parity_err
				= erikp->erik_pci_data_parity_err.value.ul;
		esp->pci_signal_target_abort
				= erikp->erik_pci_signal_target_abort.value.ul;
		esp->pci_rcvd_target_abort
				= erikp->erik_pci_rcvd_target_abort.value.ul;
		esp->pci_rcvd_master_abort
				= erikp->erik_pci_rcvd_master_abort.value.ul;
		esp->pci_signal_system_err
				= erikp->erik_pci_signal_system_err.value.ul;
		esp->pci_det_parity_err
				= erikp->erik_pci_det_parity_err.value.ul;

		esp->pmcap	= erikp->erik_pmcap.value.ul;

		esp->link_up	= erikp->erik_link_up.value.ul;

		esp->link_duplex = erikp->erik_link_duplex.value.ul;

#endif	/* kstat */
		return (0);
	} else {
		erikp->erik_ipackets64.value.ull	= esp->ipackets64;
		erikp->erik_ipackets.value.ul		= esp->ipackets64;
		erikp->erik_ierrors.value.ul		= esp->ierrors;
		erikp->erik_opackets64.value.ull	= esp->opackets64;
		erikp->erik_opackets.value.ul		= esp->opackets64;
		erikp->erik_oerrors.value.ul		= esp->oerrors;
		erikp->erik_collisions.value.ul		= esp->collisions;
		erikp->erik_ifspeed.value.ull = esp->ifspeed * 1000000ULL;

		/*
		 * MIB II kstat variables
		 */
		erikp->erik_rbytes64.value.ull		= esp->rbytes64;
		erikp->erik_rbytes.value.ul		= esp->rbytes64;
		erikp->erik_obytes64.value.ull		= esp->obytes64;
		erikp->erik_obytes.value.ul		= esp->obytes64;

		erikp->erik_multircv.value.ul		= esp->multircv;
		erikp->erik_multixmt.value.ul		= esp->multixmt;
		erikp->erik_brdcstrcv.value.ul		= esp->brdcstrcv;
		erikp->erik_brdcstxmt.value.ul		= esp->brdcstxmt;
		erikp->erik_norcvbuf.value.ul		= esp->norcvbuf;
		erikp->erik_noxmtbuf.value.ul		= esp->noxmtbuf;

		erikp->erik_txmac_urun.value.ul		= esp->txmac_urun;
		erikp->erik_txmac_maxpkt_err.value.ul
					= esp->txmac_maxpkt_err;
		erikp->erik_excessive_coll.value.ul
					= esp->excessive_coll;
		erikp->erik_late_coll.value.ul		= esp->late_coll;
		erikp->erik_first_coll.value.ul		= esp->first_coll;
		erikp->erik_defer_timer_exp.value.ul
					= esp->defer_timer_exp;
		erikp->erik_peak_attempt_cnt.value.ul
					= esp->peak_attempt_cnt;
		erikp->erik_tx_hang.value.ul	= esp->tx_hang;

		erikp->erik_rx_corr.value.ul	= esp->rx_corr;
		erikp->erik_no_free_rx_desc.value.ul
					= esp->no_free_rx_desc;

		erikp->erik_rx_overflow.value.ul = esp->rx_overflow;
		erikp->erik_rx_hang.value.ul	= esp->rx_hang;
		erikp->erik_rx_align_err.value.ul = esp->rx_align_err;
		erikp->erik_rx_crc_err.value.ul	= esp->rx_crc_err;
		erikp->erik_rx_length_err.value.ul
					= esp->rx_length_err;
		erikp->erik_rx_code_viol_err.value.ul
					= esp->rx_code_viol_err;
		erikp->erik_pause_rxcount.value.ul
					= esp->pause_rxcount;
		erikp->erik_pause_oncount.value.ul
					= esp->pause_oncount;
		erikp->erik_pause_offcount.value.ul
					= esp->pause_offcount;
		erikp->erik_pause_time_count.value.ul
					= esp->pause_time_count;

		erikp->erik_inits.value.ul	= esp->inits;
		erikp->erik_tnocar.value.ul	= esp->tnocar;
		erikp->erik_jab.value.ul	= esp->jab;
		erikp->erik_notmds.value.ul	= esp->notmds;
		erikp->erik_nocanput.value.ul	= esp->nocanput;
		erikp->erik_allocbfail.value.ul	= esp->allocbfail;
		erikp->erik_drop.value.ul	= esp->drop;
		erikp->erik_rx_bad_pkts.value.ul = esp->rx_bad_pkts;
		erikp->erik_rx_runt.value.ul    = esp->rx_runt;
		erikp->erik_rx_toolong_pkts.value.ul
					= esp->rx_toolong_pkts;
		erikp->erik_rx_inits.value.ul
					= esp->rx_inits;
		erikp->erik_tx_inits.value.ul
					= esp->tx_inits;

		erikp->erik_rxtag_err.value.ul	= esp->rxtag_err;

		erikp->erik_parity_error.value.ul = esp->parity_error;

		erikp->erik_pci_error_int.value.ul = esp->pci_error_int;
		erikp->erik_unknown_fatal.value.ul = esp->unknown_fatal;
		erikp->erik_pci_data_parity_err.value.ul
					= esp->pci_data_parity_err;
		erikp->erik_pci_signal_target_abort.value.ul
					= esp->pci_signal_target_abort;
		erikp->erik_pci_rcvd_target_abort.value.ul
					= esp->pci_rcvd_target_abort;
		erikp->erik_pci_rcvd_master_abort.value.ul
					= esp->pci_rcvd_master_abort;
		erikp->erik_pci_signal_system_err.value.ul
					= esp->pci_signal_system_err;
		erikp->erik_pci_det_parity_err.value.ul
					= esp->pci_det_parity_err;

		erikp->erik_pmcap.value.ul		= esp->pmcap;

		erikp->erik_link_up.value.ul		= esp->link_up;

		erikp->erik_link_duplex.value.ul	= esp->link_duplex;
	}
	return (0);
}

static void
eri_statinit(struct eri *erip)
{
	struct	kstat	*ksp;
	struct	erikstat	*erikp;

#ifdef	kstat
	if ((ksp = kstat_create("eri", erip->instance,
		NULL, "net", KSTAT_TYPE_NAMED,
		sizeof (struct erikstat) / sizeof (kstat_named_t),
		KSTAT_FLAG_PERSISTENT)) == NULL) {
#else
	if ((ksp = kstat_create("eri", erip->instance,
	    NULL, "net", KSTAT_TYPE_NAMED,
	    sizeof (struct erikstat) / sizeof (kstat_named_t), 0)) == NULL) {
#endif	/* kstat */
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
				kstat_create_fail_msg);
		return;
	}

	erip->ksp = ksp;
	erikp = (struct erikstat *)(ksp->ks_data);
	kstat_named_init(&erikp->erik_ipackets,		"ipackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_ierrors,		"ierrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_opackets,		"opackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_oerrors,		"oerrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_collisions,	"collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_ifspeed,		"ifspeed",
		KSTAT_DATA_ULONGLONG);

	/*
	 * MIB II kstat variables
	 */
	kstat_named_init(&erikp->erik_rbytes,		"rbytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_obytes,		"obytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_multircv,		"multircv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_multixmt,		"multixmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_brdcstrcv,	"brdcstrcv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_brdcstxmt,	"brdcstxmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_norcvbuf,		"norcvbuf",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_noxmtbuf,		"noxmtbuf",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_inits,		"inits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_tnocar,		"nocarrier",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_txmac_urun,	"txmac_urun",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_txmac_maxpkt_err,	"txmac_maxpkt_err",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_excessive_coll,	"excessive_coll",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_late_coll,	"late_coll",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_first_coll,	"first_coll",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_defer_timer_exp,	"defer_timer_exp",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_peak_attempt_cnt,	"peak_attempt_cnt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_tx_hang,		"tx_hang",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rx_corr,		"rx_corr",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_no_free_rx_desc,	"no_free_rx_desc",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_overflow,	"rx_overflow",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_hang,		"rx_hang",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_align_err,	"rx_align_err",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_crc_err,	"rx_crc_err",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_length_err,	"rx_length_err",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_code_viol_err,	"rx_code_viol_err",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pause_rxcount,	"pause_rcv_cnt",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pause_oncount,	"pause_on_cnt",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pause_offcount,	"pause_off_cnt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pause_time_count,	"pause_time_cnt",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_jab, "jabber",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_notmds, "no_tmds",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_nocanput,	"nocanput",
		KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_allocbfail, "allocbfail",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_drop, "drop",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rx_bad_pkts, "bad_pkts",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rx_runt, "runt",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rx_toolong_pkts, "toolong_pkts",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rx_inits, "rx_inits",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_tx_inits, "tx_inits",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rxtag_err, "rxtag_error",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_parity_error,
			"parity_error",
			KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pci_error_int,
			"pci_error_interrupt",
			KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_unknown_fatal, "unknown_fatal",
			KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pci_data_parity_err,
			"pci_data_parity_err", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pci_signal_target_abort,
			"pci_signal_target_abort", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pci_rcvd_target_abort,
			"pci_rcvd_target_abort", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pci_rcvd_master_abort,
			"pci_rcvd_master_abort", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pci_signal_system_err,
			"pci_signal_system_err", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pci_det_parity_err,
			"pci_det_parity_err", KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pmcap,		"pmcap",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_link_up,		"link_up",
		KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_link_duplex,	"link_duplex",
		KSTAT_DATA_ULONG);
	/*
	 * 64-bit kstats : PSARC 1997/198
	 */
	kstat_named_init(&erikp->erik_ipackets64,	"ipackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&erikp->erik_opackets64,	"opackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&erikp->erik_rbytes64,		"rbytes64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&erikp->erik_obytes64,		"obytes64",
		KSTAT_DATA_ULONGLONG);

	ksp->ks_update = eri_stat_kstat_update;
	ksp->ks_private = (void *) erip;
	kstat_install(ksp);
}

/* <<<<<<<<<<<<<<<<<<<	PERFORMANCE MEASUREMENT FUNCTIONS	>>>>>>>>>>> */

/* The following code is used for performance metering and debugging; */
/* This routine is invoked via "TIME_POINT(label)" macros, which will */
/* store the label and a timestamp. This allows to execution sequences */
/* and timestamps associated with them. */


#ifdef TPOINTS
/* Time trace points */
int time_point_active;
static int time_point_offset, time_point_loc;
hrtime_t last_time_point;
#define	POINTS 1024
int time_points[POINTS];
#define	TPOINT(x) if (time_point_active) eri_time_point(x);
void
eri_time_point(int loc)
{
	static hrtime_t time_point_base;

	hrtime_t now;

	now = gethrtime();
	if (time_point_base == 0) {
		time_point_base = now;
		time_point_loc = loc;
		time_point_offset = 0;
	} else {
		time_points[time_point_offset] = loc;
		time_points[time_point_offset+1] =
		    (now - last_time_point) / 1000;
		time_point_offset += 2;
		if (time_point_offset >= POINTS)
		    time_point_offset = 0; /* wrap at end */
		/* time_point_active = 0;  disable at end */
	}
	last_time_point = now;
}
#else
#define	TPOINT(x)
#endif

/* <<<<<<<<<<<<<<<<<<<<<<< NDD SUPPORT FUNCTIONS	>>>>>>>>>>>>>>>>>>> */
/*
 * ndd support functions to get/set parameters
 */
/* Free the Named Dispatch Table by calling eri_nd_free */
static void
eri_param_cleanup(struct eri *erip)
{
	if (erip->g_nd)
		(void) eri_nd_free(&erip->g_nd);
}

/*
 * Extracts the value from the eri parameter array and prints the
 * parameter value. cp points to the required parameter.
 */
/* ARGSUSED */
static int
eri_param_get(queue_t *q, mblk_t *mp, caddr_t cp)
{
	param_t		*eripa = (param_t *)cp;
	int		param_len = 1;
	uint32_t	param_val;
	mblk_t		*nmp;
	int		ok;

	param_val = eripa->param_val;
	/*
	 * Calculate space required in mblk.
	 * Remember to include NULL terminator.
	 */
	do {
		param_len++;
		param_val /= 10;
	} while (param_val);

	ok = eri_mk_mblk_tail_space(mp, &nmp, param_len);
	if (ok == 0) {
		(void) sprintf((char *)nmp->b_wptr, "%d", eripa->param_val);
		nmp->b_wptr += param_len;
	}

	return (ok);
}

/*
 * Check if there is space for p_val at the end if mblk.
 * If not, allocate new 1k mblk.
 */
static int
eri_mk_mblk_tail_space(mblk_t *mp, mblk_t **nmp, size_t sz)
{
	mblk_t *tmp = mp;

	while (tmp->b_cont)
		tmp = tmp->b_cont;

	if (MBLKTAIL(tmp) < sz) {
		if ((tmp->b_cont = allocb(1024, BPRI_HI)) == NULL)
			return (ENOMEM);
		tmp = tmp->b_cont;
	}
	*nmp = tmp;
	return (0);
}

/*
 * Register each element of the parameter array with the
 * named dispatch handler. Each element is loaded using
 * eri_nd_load()
 */
/* ARGSUSED */
static int
eri_param_register(struct eri *erip, param_t *eripa, int cnt)
	/* cnt gives the count of the number of */
	/* elements present in the parameter array */
{
	int i, k;

	/* First 4 elements are read-only */
	for (i = 0, k = 0; i < 4; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (!eri_nd_load(&erip->g_nd,
			    eripa->param_name, (pfi_t)eri_param_get,
			    (pfi_t)0, (caddr_t)eripa)) {
				(void) eri_nd_free(&erip->g_nd);
				return (B_FALSE);
		}

	/* Next 10 elements are read and write */
	for (i = 0; i < 10; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (eripa->param_name && eripa->param_name[0]) {
				if (!eri_nd_load(&erip->g_nd,
				    eripa->param_name, (pfi_t)eri_param_get,
				    (pfi_t)eri_param_set, (caddr_t)eripa)) {
					(void) eri_nd_free(&erip->g_nd);
					return (B_FALSE);
			}
		}

	/* next 12 elements are read-only */
	for (i = 0; i < 12; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (!eri_nd_load(&erip->g_nd, eripa->param_name,
			    (pfi_t)eri_param_get, (pfi_t)0, (caddr_t)eripa)) {
				(void) eri_nd_free(&erip->g_nd);
				return (B_FALSE);
		}

	/* Next 5 elements are read and write */
	for (i = 0; i < 5; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (eripa->param_name && eripa->param_name[0]) {
				if (!eri_nd_load(&erip->g_nd,
				    eripa->param_name, (pfi_t)eri_param_get,
				    (pfi_t)eri_param_set, (caddr_t)eripa)) {
					(void) eri_nd_free(&erip->g_nd);
					return (B_FALSE);
			}
		}
	/* next 2 elements are read-only */
	for (i = 0; i < 2; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (!eri_nd_load(&erip->g_nd, eripa->param_name,
			    (pfi_t)eri_param_get, (pfi_t)0, (caddr_t)eripa)) {
				(void) eri_nd_free(&erip->g_nd);
				return (B_FALSE);
		}
	/* Next 2   element is read and write */
	for (i = 0; i < 2; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (eripa->param_name && eripa->param_name[0]) {
				if (!eri_nd_load(&erip->g_nd,
				    eripa->param_name, (pfi_t)eri_param_get,
				    (pfi_t)eri_param_set, (caddr_t)eripa)) {
					(void) eri_nd_free(&erip->g_nd);
					return (B_FALSE);
			}
		}
	/* next 1 element is read-only */
	for (i = 0; i < 1; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (!eri_nd_load(&erip->g_nd, eripa->param_name,
			    (pfi_t)eri_param_get, (pfi_t)0, (caddr_t)eripa)) {
				(void) eri_nd_free(&erip->g_nd);
				return (B_FALSE);
		}
	/* Next 5   elements are read and write */
	for (i = 0; i < 5; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (eripa->param_name && eripa->param_name[0]) {
				if (!eri_nd_load(&erip->g_nd,
				    eripa->param_name, (pfi_t)eri_param_get,
				    (pfi_t)eri_param_set, (caddr_t)eripa)) {
					(void) eri_nd_free(&erip->g_nd);
					return (B_FALSE);
			}
		}
	/* next 10 elements are read-only */
	for (i = 0; i < 10; i++, k++, eripa++)
		if (erip->param_display[k] == DISPLAY_PARAM)
			if (!eri_nd_load(&erip->g_nd, eripa->param_name,
			    (pfi_t)eri_param_get, (pfi_t)0, (caddr_t)eripa)) {
				(void) eri_nd_free(&erip->g_nd);
				return (B_FALSE);
		}

	return (B_TRUE);
}

/*
 * Sets the eri parameter to the value in the param_register using
 * eri_nd_load().
 */
/* ARGSUSED */
static int
eri_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp)
{
	char *end;
	size_t new_value;
	param_t	*eripa = (param_t *)cp;

	new_value = eri_strtol(value, &end, 10);
	if (end == value || new_value < eripa->param_min ||
	    new_value > eripa->param_max) {
			return (EINVAL);
	}
	eripa->param_val = new_value;
	return (0);

}

/* Free the table pointed to by 'ndp' */
static void
eri_nd_free(caddr_t *nd_pparam)
{
	ND	*nd;

	if ((nd = (ND *)(*nd_pparam)) != NULL) {
		if (nd->nd_tbl)
			kmem_free((char *)nd->nd_tbl, nd->nd_size);
		kmem_free((char *)nd, sizeof (ND));
		*nd_pparam = NULL;
	}
}

static int
eri_nd_getset(queue_t *q, caddr_t nd_param, MBLKP mp)
{
	int	err;
	IOCP	iocp;
	MBLKP	mp1;
	ND	*nd;
	NDE	*nde;
	char	*valp;
	size_t	avail;
	mblk_t	*nmp;

	if (!nd_param)
		return (B_FALSE);

	nd = (ND *)nd_param;
	iocp = (IOCP)mp->b_rptr;
	if ((iocp->ioc_count == 0) || !(mp1 = mp->b_cont)) {
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = 0;
		iocp->ioc_error = EINVAL;
		return (B_TRUE);
	}
	/*
	 * NOTE - logic throughout nd_xxx assumes single data block for ioctl.
	 *	However, existing code sends in some big buffers.
	 */
	avail = iocp->ioc_count;
	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	mp1->b_datap->db_lim[-1] = '\0';	/* Force null termination */
	valp = (char *)mp1->b_rptr;

	for (nde = nd->nd_tbl; /* */; nde++) {
		if (!nde->nde_name)
			return (B_FALSE);
		if (strcmp(nde->nde_name, valp) == 0)
			break;
	}
	err = EINVAL;

	while (*valp++)
		;

	if (!*valp || valp >= (char *)mp1->b_wptr)
		valp = NULL;

	switch (iocp->ioc_cmd) {
	case ND_GET:
	/*
	 * (XXX) hack: "*valp" is size of user buffer for copyout. If result
	 * of action routine is too big, free excess and return ioc_rval as buf
	 * size needed.  Return as many mblocks as will fit, free the rest.  For
	 * backward compatibility, assume size of orig ioctl buffer if "*valp"
	 * bad or not given.
	 */
		if (valp)
			avail = eri_strtol(valp, (char **)0, 10);
		/* We overwrite the name/value with the reply data */
		{
			mblk_t *mp2 = mp1;

			while (mp2) {
				mp2->b_wptr = mp2->b_rptr;
				mp2 = mp2->b_cont;
			}
		}
		err = (*nde->nde_get_pfi)(q, mp1, nde->nde_data, iocp->ioc_cr);
		if (!err) {
			size_t	size_out;
			ssize_t	excess;

			iocp->ioc_rval = 0;

			/* Tack on the null */
			err = eri_mk_mblk_tail_space(mp1, &nmp, 1);
			if (!err) {
				*nmp->b_wptr++ = '\0';
				size_out = msgdsize(mp1);
				excess = size_out - avail;
				if (excess > 0) {
					iocp->ioc_rval = size_out;
					size_out -= excess;
					(void) adjmsg(mp1, -(excess + 1));
					err = eri_mk_mblk_tail_space(mp1,
						&nmp, 1);
					if (!err)
						*nmp->b_wptr++ = '\0';
					else
						size_out = 0;
				}

			} else
				size_out = 0;

			iocp->ioc_count = size_out;
		}
		break;

	case ND_SET:
		if (valp) {
			if ((iocp->ioc_cr != NULL) &&
			    ((err = secpolicy_net_config(iocp->ioc_cr, B_FALSE))
			    == 0)) {
				err = (*nde->nde_set_pfi)(q, mp1, valp,
				    nde->nde_data, iocp->ioc_cr);
			}
			iocp->ioc_count = 0;
			freemsg(mp1);
			mp->b_cont = NULL;
		}
		break;

	default:
		ERI_DEBUG_MSG1(NULL, DEFAULT_MSG,
		    "nd_getset: cmd is default");
		break;
	}
	iocp->ioc_error = err;
	mp->b_datap->db_type = M_IOCACK;
	return (B_TRUE);
}

/*
 * Load 'name' into the named dispatch table pointed to by 'ndp'.
 * 'ndp' should be the address of a char pointer cell.  If the table
 * does not exist (*ndp == 0), a new table is allocated and 'ndp'
 * is stuffed.  If there is not enough space in the table for a new
 * entry, more space is allocated.
 */
static boolean_t
eri_nd_load(caddr_t *nd_pparam, char *name, pfi_t get_pfi,
    pfi_t set_pfi, caddr_t data)
{
	ND	*nd;
	NDE	*nde;

	if (!nd_pparam)
		return (B_FALSE);

	if ((nd = (ND *)(*nd_pparam)) == NULL) {
		if ((nd = (ND *)kmem_zalloc(sizeof (ND), KM_NOSLEEP))
		    == NULL)
			return (B_FALSE);
		*nd_pparam = (caddr_t)nd;
	}
	if (nd->nd_tbl) {
		for (nde = nd->nd_tbl; nde->nde_name; nde++) {
			if (strcmp(name, nde->nde_name) == 0)
				goto fill_it;
		}
	}
	if (nd->nd_free_count <= 1) {
		if ((nde = (NDE *)kmem_zalloc(nd->nd_size +
		    NDE_ALLOC_SIZE, KM_NOSLEEP)) == NULL)
			return (B_FALSE);

		nd->nd_free_count += NDE_ALLOC_COUNT;
		if (nd->nd_tbl) {
			bcopy((char *)nd->nd_tbl, (char *)nde, nd->nd_size);
			kmem_free((char *)nd->nd_tbl, nd->nd_size);
		} else {
			nd->nd_free_count--;
			nde->nde_name = "?";
			nde->nde_get_pfi = nd_get_names;
			nde->nde_set_pfi = nd_set_default;
		}
		nde->nde_data = (caddr_t)nd;
		nd->nd_tbl = nde;
		nd->nd_size += NDE_ALLOC_SIZE;
	}
	for (nde = nd->nd_tbl; nde->nde_name; nde++)
		;
	nd->nd_free_count--;
fill_it:
	nde->nde_name = name;
	nde->nde_get_pfi = get_pfi ? get_pfi : nd_get_default;
	nde->nde_set_pfi = set_pfi ? set_pfi : nd_set_default;
	nde->nde_data = data;
	return (B_TRUE);
}

/*
 * Hardening Functions
 * New Section
 */
#ifdef  DEBUG
/*VARARGS*/
/* ARGSUSED */
static void
eri_debug_msg(
	char *file,
	int line,
	struct eri *erip,
	debug_msg_t type,
	char *fmt, ...)
{
	char	msg_buffer[255];
	va_list ap;

	static kmutex_t eridebuglock;
	static int eri_debug_init = 0;

	if (!eri_debug_level)
		return;
	if (eri_debug_init == 0) {
		/*
		 * Block I/O interrupts
		 */
		mutex_init(&eridebuglock, NULL, MUTEX_DRIVER, (void *)SPL3);
		eri_debug_init = 1;
	}

	mutex_enter(&eridebuglock);
	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);
	va_end(ap);

	if (eri_msg_out & ERI_CON_MSG) {
		if (((type <= eri_debug_level) && eri_debug_all) ||
			((type == eri_debug_level) && !eri_debug_all)) {
			if (erip)
				cmn_err(CE_CONT, "D: %s %s(%d):(%s%d) %s\n",
					debug_msg_string[type], file, line,
					DEVICE_NAME(erip->dip), erip->instance,
					msg_buffer);
			else
				cmn_err(CE_CONT, "D: %s %s(%d): %s\n",
					debug_msg_string[type], file,
					line, msg_buffer);
		}
	}
	mutex_exit(&eridebuglock);
}
#endif


/* VARARGS  */
/* ARGSUSED */
static void
eri_fault_msg(char *file, uint_t line, struct eri *erip, uint_t severity,
		msg_t type, char *fmt, ...)
{
	char	msg_buffer[255];
	va_list	ap;

	mutex_enter(&erilock);

	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);
	va_end(ap);

	if (erip == NULL) {
		cmn_err(CE_NOTE, "eri : %s", msg_buffer);
		mutex_exit(&erilock);
		return;
	}

	if (severity == SEVERITY_HIGH) {
		cmn_err(CE_WARN, "%s%d : %s", DEVICE_NAME(erip->dip),
		    erip->instance, msg_buffer);
	} else switch (type) {
	case ERI_VERB_MSG:
		cmn_err(CE_CONT, "?%s%d : %s", DEVICE_NAME(erip->dip),
		    erip->instance, msg_buffer);
		break;
	case ERI_LOG_MSG:
		cmn_err(CE_NOTE, "^%s%d : %s", DEVICE_NAME(erip->dip),
		    erip->instance, msg_buffer);
		break;
	case ERI_BUF_MSG:
		cmn_err(CE_NOTE, "!%s%d : %s", DEVICE_NAME(erip->dip),
		    erip->instance, msg_buffer);
		break;
	case ERI_CON_MSG:
		cmn_err(CE_CONT, "%s%d : %s", DEVICE_NAME(erip->dip),
		    erip->instance, msg_buffer);
	default:
		break;
	}

	mutex_exit(&erilock);
}

/*
 * Transceiver (xcvr) Functions
 * New Section
 */
/*
 * eri_stop_timer function is used by a function before doing link-related
 * processing. It locks the "linklock" to protect the link-related data
 * structures. This lock will be subsequently released in eri_start_timer().
 */
static void
eri_stop_timer(struct eri *erip)
{
	timeout_id_t id;
	ERI_DEBUG_MSG1(erip, XCVR_MSG, "stop timer");
	mutex_enter(&erip->linklock);
	if (erip->timerid) {
		erip->flags |= ERI_NOTIMEOUTS; /* prevent multiple timeout */
		id = erip->timerid;
		erip->timerid = 0; /* prevent other thread do untimeout */
		mutex_exit(&erip->linklock); /* no mutex across untimeout() */

		(void) untimeout(id);
		mutex_enter(&erip->linklock); /* acquire mutex again */
		erip->flags &= ~ERI_NOTIMEOUTS;
	}
}

/*
 * If msec parameter is zero, just release "linklock".
 */
static void
eri_start_timer(struct eri *erip, fptrv_t func, clock_t msec)
{
	ERI_DEBUG_MSG1(erip, XCVR_MSG, "start timer");

	if (msec) {
		if (!(erip->flags & ERI_NOTIMEOUTS) &&
			(erip->flags & ERI_RUNNING)) {
				erip->timerid = timeout(func, (caddr_t)erip,
					drv_usectohz(1000*msec));
		}
	}

	mutex_exit(&erip->linklock);
}

static int
eri_new_xcvr(struct eri *erip)
{
	int		status;
	uint32_t 	cfg;
	int		old_transceiver;

	if (pci_report_pmcap(erip->dip, PCI_PM_IDLESPEED,
	    PCI_PM_IDLESPEED_NONE) == DDI_SUCCESS)
		erip->stats.pmcap = ERI_PMCAP_NONE;

	status = B_FALSE;			/* no change */
	cfg = GET_MIFREG(mif_cfg);
	ERI_DEBUG_MSG2(erip, MIF_MSG,
			"cfg value = %X", cfg);
	old_transceiver = param_transceiver;

	if ((cfg & ERI_MIF_CFGM1) && !use_int_xcvr) {
		ERI_DEBUG_MSG1(erip, PHY_MSG, "Found External XCVR");
		/*
		 * An External Transceiver was found and it takes priority
		 * over an internal, given the use_int_xcvr flag
		 * is false.
		 */
		if (old_transceiver != EXTERNAL_XCVR) {
			/*
			 * External transceiver has just been plugged
			 * in. Isolate the internal Transceiver.
			 */
			if (old_transceiver == INTERNAL_XCVR) {
				eri_mii_write(erip, ERI_PHY_BMCR,
					(PHY_BMCR_ISOLATE | PHY_BMCR_PWRDN |
					PHY_BMCR_LPBK));
			}
			status = B_TRUE;
		}
		/*
		 * Select the external Transceiver.
		 */
		erip->phyad = ERI_EXTERNAL_PHYAD;
		param_transceiver = EXTERNAL_XCVR;
		erip->mif_config &= ~ERI_MIF_CFGPD;
		erip->mif_config |= (erip->phyad << ERI_MIF_CFGPD_SHIFT);
		erip->mif_config |= ERI_MIF_CFGPS;
		PUT_MIFREG(mif_cfg, erip->mif_config);

		PUT_MACREG(xifc, GET_MACREG(xifc) | BMAC_XIFC_MIIBUF_OE);
		drv_usecwait(ERI_MIF_POLL_DELAY);
	} else if (cfg & ERI_MIF_CFGM0) {
		ERI_DEBUG_MSG1(erip, PHY_MSG, "Found Internal XCVR");
		/*
		 * An Internal Transceiver was found or the
		 * use_int_xcvr flag is true.
		 */
		if (old_transceiver != INTERNAL_XCVR) {
			/*
			 * The external transceiver has just been
			 * disconnected or we're moving from a no
			 * transceiver state.
			 */
			if ((old_transceiver == EXTERNAL_XCVR) &&
				(cfg & ERI_MIF_CFGM0)) {
				eri_mii_write(erip, ERI_PHY_BMCR,
					(PHY_BMCR_ISOLATE | PHY_BMCR_PWRDN |
					PHY_BMCR_LPBK));
			}
			status = B_TRUE;
		}
		/*
		 * Select the internal transceiver.
		 */
		erip->phyad = ERI_INTERNAL_PHYAD;
		param_transceiver = INTERNAL_XCVR;
		erip->mif_config &= ~ERI_MIF_CFGPD;
		erip->mif_config |= (erip->phyad << ERI_MIF_CFGPD_SHIFT);
		erip->mif_config &= ~ERI_MIF_CFGPS;
		PUT_MIFREG(mif_cfg, erip->mif_config);

		PUT_MACREG(xifc, GET_MACREG(xifc) & ~ BMAC_XIFC_MIIBUF_OE);
		drv_usecwait(ERI_MIF_POLL_DELAY);
	} else {
		/*
		 * Did not find a valid xcvr.
		 */
	    ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
		"Eri_new_xcvr : Select None");
	    param_transceiver = NO_XCVR;
	    erip->xcvr_status = PHY_LINK_DOWN;
	}

	if (erip->stats.pmcap == ERI_PMCAP_NONE) {
		if (pci_report_pmcap(erip->dip, PCI_PM_IDLESPEED,
		    (void *)4000) == DDI_SUCCESS)
			erip->stats.pmcap = ERI_PMCAP_4MHZ;
	}

	return (status);
}

/*
 * Compare our xcvr in our structure to the xcvr that we get from
 * eri_check_mii_xcvr(). If they are different then mark the
 * link down, reset xcvr, and return.
 *
 * Note without the MII connector, conditions can not change that
 * will then use a external phy, thus this code has been cleaned
 * to not even call the function or to possibly change the xcvr.
 */
/* ARGSUSED */
static void
eri_check_link(struct eri *erip)
{
	uint16_t stat, control, mif_ints;
	uint32_t link_timeout	= ERI_LINKCHECK_TIMER;

	ERI_DEBUG_MSG1(erip, XCVR_MSG, "eri_check_link_enter");
	eri_stop_timer(erip);	/* acquire linklock */

	mutex_enter(&erip->xmitlock);
	mutex_enter(&erip->xcvrlock);
	eri_mif_poll(erip, MIF_POLL_STOP);

	(void) eri_mii_read(erip, ERI_PHY_BMSR, &stat);
	mif_ints = erip->mii_status ^ stat;

	if (erip->openloop_autoneg) {
		(void) eri_mii_read(erip, ERI_PHY_BMSR, &stat);
		ERI_DEBUG_MSG3(erip, XCVR_MSG,
			"eri_check_link:openloop stat %X mii_status %X",
			stat, erip->mii_status);
		(void) eri_mii_read(erip, ERI_PHY_BMCR, &control);
		if (!(stat & PHY_BMSR_LNKSTS) &&
			(erip->openloop_autoneg < 2)) {
			if (param_speed) {
				control &= ~PHY_BMCR_100M;
				param_anlpar_100hdx = 0;
				param_anlpar_10hdx = 1;
				param_speed = 0;
				erip->stats.ifspeed = SPEED_10;

			} else {
				control |= PHY_BMCR_100M;
				param_anlpar_100hdx = 1;
				param_anlpar_10hdx = 0;
				param_speed = 1;
				erip->stats.ifspeed = SPEED_100;
			}
			ERI_DEBUG_MSG3(erip, XCVR_MSG,
				"eri_check_link: trying speed %X stat %X",
					param_speed, stat);

			erip->openloop_autoneg ++;
			eri_mii_write(erip, ERI_PHY_BMCR, control);
			link_timeout = ERI_P_FAULT_TIMER;
		} else {
			erip->openloop_autoneg = 0;
			eri_mif_check(erip, stat, stat);
			if (erip->openloop_autoneg)
				link_timeout = ERI_P_FAULT_TIMER;
		}
		eri_mif_poll(erip, MIF_POLL_START);
		mutex_exit(&erip->xcvrlock);
		mutex_exit(&erip->xmitlock);

		eri_start_timer(erip, eri_check_link, link_timeout);
		return;
	}

	eri_mif_check(erip, mif_ints, stat);
	eri_mif_poll(erip, MIF_POLL_START);
	mutex_exit(&erip->xcvrlock);
	mutex_exit(&erip->xmitlock);

#ifdef ERI_RMAC_HANG_WORKAROUND
	/*
	 * Check if rx hung.
	 */
	if ((erip->flags & ERI_RUNNING) && param_linkup) {
		if (erip->check_rmac_hang) {
			ERI_DEBUG_MSG5(erip,
			    NONFATAL_MSG,
			    "check1 %d: macsm:%8x wr:%2x rd:%2x",
			    erip->check_rmac_hang,
			    GET_MACREG(macsm),
			    GET_ERXREG(rxfifo_wr_ptr),
			    GET_ERXREG(rxfifo_rd_ptr));

			erip->check_rmac_hang = 0;
			erip->check2_rmac_hang ++;

			erip->rxfifo_wr_ptr_c = GET_ERXREG(rxfifo_wr_ptr);
			erip->rxfifo_rd_ptr_c = GET_ERXREG(rxfifo_rd_ptr);

			eri_start_timer(erip, eri_check_link,
			    ERI_CHECK_HANG_TIMER);
			return;
		}

		if (erip->check2_rmac_hang) {
			ERI_DEBUG_MSG5(erip,
			    NONFATAL_MSG,
			    "check2 %d: macsm:%8x wr:%2x rd:%2x",
			    erip->check2_rmac_hang,
			    GET_MACREG(macsm),
			    GET_ERXREG(rxfifo_wr_ptr),
			    GET_ERXREG(rxfifo_rd_ptr));

			erip->check2_rmac_hang = 0;

			erip->rxfifo_wr_ptr = GET_ERXREG(rxfifo_wr_ptr);
			erip->rxfifo_rd_ptr = GET_ERXREG(rxfifo_rd_ptr);

			if (((GET_MACREG(macsm) & BMAC_OVERFLOW_STATE) ==
			    BMAC_OVERFLOW_STATE) &&
			    ((erip->rxfifo_wr_ptr_c == erip->rxfifo_rd_ptr_c) ||
			    ((erip->rxfifo_rd_ptr == erip->rxfifo_rd_ptr_c) &&
			    (erip->rxfifo_wr_ptr == erip->rxfifo_wr_ptr_c)))) {
				ERI_DEBUG_MSG1(erip,
				    NONFATAL_MSG,
				    "RX hang: Reset mac");

				HSTAT(erip, rx_hang);
				erip->linkcheck = 1;

				eri_start_timer(erip, eri_check_link,
				    ERI_LINKCHECK_TIMER);
				(void) eri_init(erip);
				return;
			}
		}
	}
#endif

	/*
	 * Check if tx hung.
	 */
#ifdef	ERI_TX_HUNG
	if ((erip->flags & ERI_RUNNING) &&
		param_linkup && (eri_check_txhung(erip))) {
		HSTAT(erip, tx_hang);
		eri_reinit_txhung++;
#ifdef	LATER_SPLIT_TX_RX
		mutex_enter(&erip->xmitlock);
		eri_init_tx(erip);
		mutex_exit(&erip->xmitlock);
#endif
		erip->linkcheck = 1;
		eri_start_timer(erip, eri_check_link, ERI_CHECK_HANG_TIMER);
		(void) eri_init(erip);
		return;
	}
#endif

#ifdef ERI_PM_WORKAROUND
	if (erip->stats.pmcap == ERI_PMCAP_NONE) {
		if (pci_report_pmcap(erip->dip, PCI_PM_IDLESPEED,
		    (void *)4000) == DDI_SUCCESS)
			erip->stats.pmcap = ERI_PMCAP_4MHZ;

		ERI_DEBUG_MSG2(erip, NONFATAL_MSG,
		    "eri_check_link: PMCAP %d", erip->stats.pmcap);
	}
#endif
	if ((!param_mode) && (param_transceiver != NO_XCVR))
		eri_start_timer(erip, eri_check_link, ERI_CHECK_HANG_TIMER);
	else
		eri_start_timer(erip, eri_check_link, ERI_LINKCHECK_TIMER);
}

static void
eri_mif_check(struct eri *erip, uint16_t mif_ints, uint16_t mif_data)
{
	uint16_t control, aner, anlpar, anar, an_common;
	uint16_t old_mintrans;
	int restart_autoneg = 0;

	ERI_DEBUG_MSG4(erip, XCVR_MSG,
		"eri_mif_check: mif_mask: %X, %X, %X",
		erip->mif_mask, mif_ints, mif_data);

	mif_ints &= ~erip->mif_mask;
	erip->mii_status = mif_data;
	/*
	 * Now check if someone has pulled the xcvr or
	 * a new xcvr has shown up
	 * If so try to find out what the new xcvr setup is.
	 */
	if (((mif_ints & PHY_BMSR_RES1) && (mif_data == 0xFFFF)) ||
			(param_transceiver == NO_XCVR)) {
		ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
				"No status transceiver gone");
		if (eri_new_xcvr(erip)) {
			if (param_transceiver != NO_XCVR) {
				/*
				 * Reset the new PHY and bring up the link
				 */
				(void) eri_reset_xcvr(erip);
			}
		}
		return;
	}

	if (param_autoneg && (mif_ints & PHY_BMSR_LNKSTS) &&
		(mif_data & PHY_BMSR_LNKSTS) && (mif_data & PHY_BMSR_ANC)) {
		mif_ints |= PHY_BMSR_ANC;
		ERI_DEBUG_MSG3(erip, PHY_MSG,
			"eri_mif_check: Set ANC bit mif_data %X mig_ints %X",
			mif_data, mif_ints);
	}

	if ((mif_ints & PHY_BMSR_ANC) && (mif_data & PHY_BMSR_ANC)) {
		ERI_DEBUG_MSG1(erip, PHY_MSG,
				"Auto-negotiation interrupt.");

		/*
		 * Switch off Auto-negotiation interrupts and switch on
		 * Link ststus interrupts.
		 */
		erip->mif_mask |= PHY_BMSR_ANC;
		erip->mif_mask &= ~PHY_BMSR_LNKSTS;
		(void) eri_mii_read(erip, ERI_PHY_ANER, &aner);
		param_aner_lpancap = 1 && (aner & PHY_ANER_LPNW);
		if ((aner & PHY_ANER_MLF) || (eri_force_mlf)) {
			ERI_DEBUG_MSG1(erip, XCVR_MSG,
					"parallel detection fault");
			/*
			 * Consider doing open loop auto-negotiation.
			 */
			ERI_DEBUG_MSG1(erip, XCVR_MSG,
					"Going into Open loop Auto-neg");
			(void) eri_mii_read(erip, ERI_PHY_BMCR, &control);

			control &= ~(PHY_BMCR_ANE | PHY_BMCR_RAN |
					PHY_BMCR_FDX);
			if (param_anar_100fdx || param_anar_100hdx) {
				control |= PHY_BMCR_100M;
				param_anlpar_100hdx = 1;
				param_anlpar_10hdx = 0;
				param_speed = 1;
				erip->stats.ifspeed = SPEED_100;

			} else if (param_anar_10fdx ||
					param_anar_10hdx) {
					control &= ~PHY_BMCR_100M;
					param_anlpar_100hdx = 0;
					param_anlpar_10hdx = 1;
					param_speed = 0;
					erip->stats.ifspeed = SPEED_10;
			} else {
				ERI_FAULT_MSG1(erip, SEVERITY_NONE,
					ERI_VERB_MSG,
					"Transceiver speed set incorrectly.");
				return;
			}

			(void) eri_mii_write(erip, ERI_PHY_BMCR, control);
			param_anlpar_100fdx = 0;
			param_anlpar_10fdx = 0;
			param_mode = 0;
			erip->openloop_autoneg = 1;
			return;
		}
		(void) eri_mii_read(erip, ERI_PHY_ANLPAR, &anlpar);
		(void) eri_mii_read(erip, ERI_PHY_ANAR, &anar);
		an_common = anar & anlpar;

		ERI_DEBUG_MSG2(erip, XCVR_MSG,
				"an_common = 0x%X", an_common);

		if (an_common & (PHY_ANLPAR_TXFDX | PHY_ANLPAR_TX)) {
			param_speed = 1;
			erip->stats.ifspeed = SPEED_100;
			param_mode = 1 && (an_common & PHY_ANLPAR_TXFDX);

		} else if (an_common & (PHY_ANLPAR_10FDX | PHY_ANLPAR_10)) {
			param_speed = 0;
			erip->stats.ifspeed = SPEED_10;
			param_mode = 1 && (an_common & PHY_ANLPAR_10FDX);

		} else an_common = 0x0;

		if (!an_common) {
			ERI_FAULT_MSG1(erip, SEVERITY_MID, ERI_VERB_MSG,
					"Transceiver: anar"
					" not set with speed selection");
		}
		param_anlpar_100T4 = 1 && (anlpar & PHY_ANLPAR_T4);
		param_anlpar_100fdx = 1 && (anlpar & PHY_ANLPAR_TXFDX);
		param_anlpar_100hdx = 1 && (anlpar & PHY_ANLPAR_TX);
		param_anlpar_10fdx = 1 && (anlpar & PHY_ANLPAR_10FDX);
		param_anlpar_10hdx = 1 && (anlpar & PHY_ANLPAR_10);

		ERI_DEBUG_MSG2(erip, PHY_MSG,
				"Link duplex = 0x%X", param_mode);
		ERI_DEBUG_MSG2(erip, PHY_MSG,
				"Link speed = 0x%X", param_speed);
	/*	mif_ints |= PHY_BMSR_LNKSTS; prevent double msg */
	/*	mif_data |= PHY_BMSR_LNKSTS; prevent double msg */
	}
	if (mif_ints & PHY_BMSR_LNKSTS) {
		if (mif_data & PHY_BMSR_LNKSTS) {
			ERI_DEBUG_MSG1(erip, PHY_MSG, "Link Up");
			/*
			 * Program Lu3X31T for mininum transition
			 */
			if (eri_phy_mintrans) {
				eri_mii_write(erip, 31, 0x8000);
				(void) eri_mii_read(erip, 0, &old_mintrans);
				eri_mii_write(erip, 0, 0x00F1);
				eri_mii_write(erip, 31, 0x0000);
			}
			/*
			 * The link is up.
			 */
			eri_init_txmac(erip);
			param_linkup = 1;
			erip->stats.link_up = ERI_LINK_UP;
			if (param_mode)
				erip->stats.link_duplex = ERI_FULL_DUPLEX;
			else
				erip->stats.link_duplex = ERI_HALF_DUPLEX;

			eri_notify_ind(erip, DL_NOTE_LINK_UP);
			eri_notify_ind(erip, DL_NOTE_SPEED);
			eri_display_link_status(erip);
		} else {
			ERI_DEBUG_MSG1(erip, PHY_MSG,
					"Link down.");
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			eri_notify_ind(erip, DL_NOTE_LINK_DOWN);
			if (param_autoneg) {
				restart_autoneg = 1;
			}
		}
	} else {
		if (mif_data & PHY_BMSR_LNKSTS) {
			if (!param_linkup) {
				ERI_DEBUG_MSG1(erip, PHY_MSG,
					"eri_mif_check: MIF data link up");
				/*
				 * Program Lu3X31T for minimum transition
				 */
				if (eri_phy_mintrans) {
					eri_mii_write(erip, 31, 0x8000);
					(void) eri_mii_read(erip, 0,
						&old_mintrans);
					eri_mii_write(erip, 0, 0x00F1);
					eri_mii_write(erip, 31, 0x0000);
				}
				/*
				 * The link is up.
				 */
				eri_init_txmac(erip);

				param_linkup = 1;
				erip->stats.link_up = ERI_LINK_UP;
				if (param_mode)
					erip->stats.link_duplex =
					    ERI_FULL_DUPLEX;
				else
					erip->stats.link_duplex =
					    ERI_HALF_DUPLEX;

				eri_notify_ind(erip, DL_NOTE_LINK_UP);
				eri_notify_ind(erip, DL_NOTE_SPEED);
				eri_display_link_status(erip);
			}
		} else if (param_linkup) {
			/*
			 * The link is down now.
			 */
			ERI_DEBUG_MSG1(erip, PHY_MSG,
				"eri_mif_check:Link was up and went down");
			param_linkup = 0;
			erip->stats.link_up = ERI_LINK_DOWN;
			erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
			eri_notify_ind(erip, DL_NOTE_LINK_DOWN);
			if (param_autoneg)
				restart_autoneg = 1;
		}
	}
	if (restart_autoneg) {
		/*
		 * Restart normal auto-negotiation.
		 */
		ERI_DEBUG_MSG1(erip, PHY_MSG,
			"eri_mif_check:Restart AUto Negotiation");
		erip->openloop_autoneg = 0;
		param_mode = 0;
		param_speed = 0;
		param_anlpar_100T4 = 0;
		param_anlpar_100fdx = 0;
		param_anlpar_100hdx = 0;
		param_anlpar_10fdx = 0;
		param_anlpar_10hdx = 0;
		param_aner_lpancap = 0;
		(void) eri_mii_read(erip, ERI_PHY_BMCR,
				    &control);
		control |= (PHY_BMCR_ANE | PHY_BMCR_RAN);
		eri_mii_write(erip, ERI_PHY_BMCR, control);
	}
	if (mif_ints & PHY_BMSR_JABDET) {
		if (mif_data & PHY_BMSR_JABDET) {
			ERI_DEBUG_MSG1(erip, PHY_MSG,
					"Jabber detected.");
			HSTAT(erip, jab);
			/*
			 * Reset the new PHY and bring up the link
			 */
			(void) eri_reset_xcvr(erip);
				/*
				 * eri_FAULT_MSG1(erip, SEVERITY_NONE, XCVR_MSG,
				 * 		"Unable to reset transceiver.");
				 */
		}
	}
}

#define	PHYRST_PERIOD 500
static int
eri_reset_xcvr(struct eri *erip)
{
	uint16_t	stat;
	uint16_t	anar;
	uint16_t	control;
	uint16_t	idr1;
	uint16_t	idr2;
	uint16_t	nicr;
	uint32_t	speed_100;
	uint32_t	speed_10;
	int n;

	ERI_DEBUG_MSG4(erip, XCVR_MSG,
		"eri_reset_xcvr:ifspeed %X param_speed %X mif_mask %X",
		erip->stats.ifspeed, param_speed, erip->mif_mask);

#ifdef	ERI_10_10_FORCE_SPEED_WORKAROUND
	erip->ifspeed_old = erip->stats.ifspeed;
#endif
	/*
	 * Reset Open loop auto-negotiation this means you can try
	 * Normal auto-negotiation, until you get a Multiple Link fault
	 * at which point you try 100M half duplex then 10M half duplex
	 * until you get a Link up.
	 */
	erip->openloop_autoneg = 0;

	/*
	 * Reset the xcvr.
	 */
	eri_mii_write(erip, ERI_PHY_BMCR, PHY_BMCR_RESET);

	/* Check for transceiver reset completion */

	n = 1000;
	while (--n > 0) {
		drv_usecwait((clock_t)PHYRST_PERIOD);
		if (eri_mii_read(erip, ERI_PHY_BMCR, &control) == 1) {
			/* Transceiver does not talk MII */
			ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
				"eri_reset_xcvr: no mii");
		}
		if ((control & PHY_BMCR_RESET) == 0)
			goto reset_done;
	}
	ERI_FAULT_MSG2(erip, SEVERITY_NONE, ERI_VERB_MSG,
		"eri_reset_xcvr:reset_failed n == 0, control %x",
		control);
	goto eri_reset_xcvr_failed;

reset_done:

	ERI_DEBUG_MSG2(erip, AUTOCONFIG_MSG,
		"eri_reset_xcvr: reset complete in %d us",
		(1000 - n) * PHYRST_PERIOD);

	(void) eri_mii_read(erip, ERI_PHY_BMSR, &stat);
	(void) eri_mii_read(erip, ERI_PHY_ANAR, &anar);
	(void) eri_mii_read(erip, ERI_PHY_IDR1, &idr1);
	(void) eri_mii_read(erip, ERI_PHY_IDR2, &idr2);

	ERI_DEBUG_MSG4(erip, XCVR_MSG,
		"eri_reset_xcvr: control %x stat %x anar %x",
		control, stat, anar);

	/*
	 * Initialize the read only transceiver ndd information
	 * the values are either 0 or 1.
	 */
	param_bmsr_ancap = 1 && (stat & PHY_BMSR_ACFG);
	param_bmsr_100T4 = 1 && (stat & PHY_BMSR_100T4);
	param_bmsr_100fdx = 1 && (stat & PHY_BMSR_100FDX);
	param_bmsr_100hdx = 1 && (stat & PHY_BMSR_100HDX);
	param_bmsr_10fdx = 1 && (stat & PHY_BMSR_10FDX);
	param_bmsr_10hdx = 1 && (stat & PHY_BMSR_10HDX);

	/*
	 * Match up the ndd capabilities with the transceiver.
	 */
	param_autoneg &= param_bmsr_ancap;
	param_anar_100fdx &= param_bmsr_100fdx;
	param_anar_100hdx &= param_bmsr_100hdx;
	param_anar_10fdx &= param_bmsr_10fdx;
	param_anar_10hdx &= param_bmsr_10hdx;

	/*
	 * Select the operation mode of the transceiver.
	 */
	if (param_autoneg) {
		ERI_DEBUG_MSG1(erip, PHY_MSG,
			"Phy Supports Auto-negotiation.");
		/*
		 * Initialize our auto-negotiation capabilities.
		 */
		anar = PHY_SELECTOR;
		if (param_anar_100T4)
			anar |= PHY_ANAR_T4;
		if (param_anar_100fdx)
			anar |= PHY_ANAR_TXFDX;
		if (param_anar_100hdx)
			anar |= PHY_ANAR_TX;
		if (param_anar_10fdx)
			anar |= PHY_ANAR_10FDX;
		if (param_anar_10hdx)
			anar |= PHY_ANAR_10;
		ERI_DEBUG_MSG2(erip, XCVR_MSG,
				"anar = %x", anar);
		eri_mii_write(erip, ERI_PHY_ANAR, anar);
	} else {
		ERI_DEBUG_MSG1(erip, PHY_MSG,
			"Phy Doesn't support Auto-negotiation.");
	}

	/* Place the Transceiver in normal operation mode */
	if ((control & PHY_BMCR_ISOLATE) || (control & PHY_BMCR_LPBK)) {
		control &= ~(PHY_BMCR_ISOLATE | PHY_BMCR_LPBK);
		eri_mii_write(erip, ERI_PHY_BMCR,
				(control & ~PHY_BMCR_ISOLATE));
	}

	/*
	 * If Lu3X31T then allow nonzero eri_phy_mintrans
	 */
	if (eri_phy_mintrans &&
	    (idr1 != 0x43 || (idr2 & 0xFFF0) != 0x7420)) {
		eri_phy_mintrans = 0;
	}
	/*
	 * Initialize the mif interrupt mask.
	 */
	erip->mif_mask = (uint16_t)(~PHY_BMSR_RES1);

	/*
	 * Establish link speeds and do necessary special stuff based
	 * in the speed.
	 */
	speed_100 = param_anar_100fdx | param_anar_100hdx;
	speed_10 = param_anar_10fdx | param_anar_10hdx;

	ERI_DEBUG_MSG5(erip, XCVR_MSG, "eri_reset_xcvr: %d %d %d %d",
		param_anar_100fdx, param_anar_100hdx, param_anar_10fdx,
		param_anar_10hdx);

	ERI_DEBUG_MSG3(erip, XCVR_MSG,
		"eri_reset_xcvr: speed_100 %d speed_10 %d",
		speed_100, speed_10);

	if ((!speed_100) && (speed_10)) {
		erip->mif_mask &= ~PHY_BMSR_JABDET;
		if (!(param_anar_10fdx) &&
		    (param_anar_10hdx) &&
		    (erip->link_pulse_disabled)) {
			param_speed = 0;
			param_mode = 0;
			(void) eri_mii_read(erip, ERI_PHY_NICR, &nicr);
			nicr &= ~PHY_NICR_LD;
			eri_mii_write(erip, ERI_PHY_NICR, nicr);
			param_linkup = 1;
			erip->stats.link_up = ERI_LINK_UP;
			if (param_mode)
				erip->stats.link_duplex = ERI_FULL_DUPLEX;
			else
				erip->stats.link_duplex = ERI_HALF_DUPLEX;

			eri_notify_ind(erip, DL_NOTE_LINK_UP);
			eri_notify_ind(erip, DL_NOTE_SPEED);
			eri_display_link_status(erip);
		}
	}

	/*
	 * Clear the autonegotitation before re-starting
	 */
	control = PHY_BMCR_100M | PHY_BMCR_FDX;
/*	eri_mii_write(erip, ERI_PHY_BMCR, control); */
	if (param_autoneg) {
		/*
		 * Setup the transceiver for autonegotiation.
		 */
		ERI_DEBUG_MSG1(erip, PHY_MSG,
				"Setup for Auto-negotiation");
		erip->mif_mask &= ~PHY_BMSR_ANC;

		/*
		 * Clear the Auto-negotiation before re-starting
		 */
		eri_mii_write(erip, ERI_PHY_BMCR, control & ~PHY_BMCR_ANE);

		/*
		 * Switch on auto-negotiation.
		 */
		control |= (PHY_BMCR_ANE | PHY_BMCR_RAN);

		eri_mii_write(erip, ERI_PHY_BMCR, control);
	} else {
		/*
		 * Force the transceiver.
		 */
		ERI_DEBUG_MSG1(erip, PHY_MSG,
				"Setup for forced mode");
		erip->mif_mask &= ~PHY_BMSR_LNKSTS;

		/*
		 * Switch off auto-negotiation.
		 */
		control &= ~(PHY_BMCR_FDX | PHY_BMCR_ANE | PHY_BMCR_RAN);

		if (speed_100) {
			control |= PHY_BMCR_100M;
			param_aner_lpancap = 0; /* Clear LP nway */
			param_anlpar_10fdx = 0;
			param_anlpar_10hdx = 0;
			param_anlpar_100T4 = param_anar_100T4;
			param_anlpar_100fdx = param_anar_100fdx;
			param_anlpar_100hdx = param_anar_100hdx;
			param_speed = 1;
			erip->stats.ifspeed = SPEED_100;
			param_mode = param_anar_100fdx;
			if (param_mode) {
				param_anlpar_100hdx = 0;
				erip->stats.link_duplex = ERI_FULL_DUPLEX;
			} else {
				erip->stats.link_duplex = ERI_HALF_DUPLEX;
			}
		} else if (speed_10) {
			control &= ~PHY_BMCR_100M;
			param_aner_lpancap = 0; /* Clear LP nway */
			param_anlpar_100fdx = 0;
			param_anlpar_100hdx = 0;
			param_anlpar_100T4 = 0;
			param_anlpar_10fdx = param_anar_10fdx;
			param_anlpar_10hdx = param_anar_10hdx;
			param_speed = 0;
			erip->stats.ifspeed = SPEED_10;
			param_mode = param_anar_10fdx;
			if (param_mode) {
				param_anlpar_10hdx = 0;
				erip->stats.link_duplex = ERI_FULL_DUPLEX;
			} else {
				erip->stats.link_duplex = ERI_HALF_DUPLEX;
			}
		} else {
			ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
					"Transceiver speed set incorrectly.");
		}

		if (param_mode) {
			control |= PHY_BMCR_FDX;
		}

		ERI_DEBUG_MSG4(erip, PHY_MSG,
			"control = %x status = %x param_mode %d",
			control, stat, param_mode);

		eri_mii_write(erip, ERI_PHY_BMCR, control);
/*
 *		if (param_mode) {
 *			control |= PHY_BMCR_FDX;
 *		}
 *		control &= ~(PHY_BMCR_FDX | PHY_BMCR_ANE | PHY_BMCR_RAN);
 *		eri_mii_write(erip, ERI_PHY_BMCR, control);
 */
	}

#ifdef DEBUG
	(void) eri_mii_read(erip, ERI_PHY_BMCR, &control);
	(void) eri_mii_read(erip, ERI_PHY_BMSR, &stat);
	(void) eri_mii_read(erip, ERI_PHY_ANAR, &anar);
#endif
	ERI_DEBUG_MSG4(erip, PHY_MSG,
		"control %X status %X anar %X", control, stat, anar);

eri_reset_xcvr_exit:
	return (0);

eri_reset_xcvr_failed:
	return (1);
}

#ifdef	ERI_10_10_FORCE_SPEED_WORKAROUND

static void
eri_xcvr_force_mode(struct eri *erip, uint32_t *link_timeout)
{

	if (!param_autoneg && !param_linkup &&
		(erip->stats.ifspeed == SPEED_10) &&
		(param_anar_10fdx | param_anar_10hdx)) {
		*link_timeout = SECOND(1);
		return;
	}

	if (!param_autoneg && !param_linkup &&
		(erip->ifspeed_old == SPEED_10) &&
		(param_anar_100fdx | param_anar_100hdx)) {
		/*
		 * May have to set link partner's speed and mode.
		 */
		ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_LOG_MSG,
		"May have to set link partner's speed and duplex mode.");
	}
}
#endif

static void
eri_display_link_status(struct eri *erip)
{
	char link_up_msg[64];

	ERI_DEBUG_MSG3(erip, PHY_MSG,
		"eri_display_link_status: ifspeed %X param_mode %d",
		erip->stats.ifspeed, param_mode);
	switch (erip->stats.ifspeed) {
	case SPEED_100:
		(void) sprintf(link_up_msg, "100 Mbps ");
		break;
	case SPEED_10:
		(void) sprintf(link_up_msg, "10 Mbps ");
		break;
	default:
		link_up_msg[0] = '\0';
	}

	if (param_mode)
		(void) strcat(link_up_msg, "full duplex link up");
	else
		(void) strcat(link_up_msg, "half duplex link up");

	ERI_FAULT_MSG2(erip, SEVERITY_NONE, ERI_CON_MSG, "%s\n", link_up_msg);

	erip->linksts_msg = ERI_VERB_MSG;
	HSTAT(erip, tnocar);
}

static void
eri_mif_poll(struct eri *erip, soft_mif_enable_t enable)
{
	if (enable == MIF_POLL_START) {
		if (erip->mifpoll_enable &&
			!erip->openloop_autoneg) {
			ERI_DEBUG_MSG1(erip, XCVR_MSG,
				"Starting mif poll: normal start");
			erip->mif_config |= ERI_MIF_CFGPE;
			PUT_MIFREG(mif_cfg, erip->mif_config);
			drv_usecwait(ERI_MIF_POLL_DELAY);
			PUT_GLOBREG(intmask, GET_GLOBREG(intmask) &
				~ERI_G_MASK_MIF_INT);
			PUT_MIFREG(mif_imask, erip->mif_mask);
		} else {
			ERI_DEBUG_MSG1(erip, XCVR_MSG,
				"Starting mif poll:fault start");
		}
	} else if (enable == MIF_POLL_STOP) {
			ERI_DEBUG_MSG1(erip, XCVR_MSG,
				"Stopping mif poll");
			erip->mif_config &= ~ERI_MIF_CFGPE;
			PUT_MIFREG(mif_cfg, erip->mif_config);
			drv_usecwait(ERI_MIF_POLL_DELAY);
			PUT_GLOBREG(intmask, GET_GLOBREG(intmask) |
				ERI_G_MASK_MIF_INT);
			PUT_MIFREG(mif_imask, ERI_MIF_INTMASK);
	}
	ERI_DEBUG_MSG2(erip, XCVR_MSG, "MIF Config = 0x%X",
			GET_MIFREG(mif_cfg));
	ERI_DEBUG_MSG2(erip, XCVR_MSG, "MIF imask = 0x%X",
			GET_MIFREG(mif_imask));
	ERI_DEBUG_MSG2(erip, XCVR_MSG, "INT imask = 0x%X",
			GET_GLOBREG(intmask));
	ERI_DEBUG_MSG1(erip, XCVR_MSG, "<== mif_poll");
}

/*
 * This function is cut&pasted from mi.c, part of IP source base.
 * By defining this function in eri, we remove dependency from ip module.
 * This function can be removed once kernel level 'strtol' becomes available.
 */
static long
eri_strtol(char *str, char **ptr, int base)
{
	char *cp;
	int digits;
	long value;
	boolean_t is_negative;

	cp = str;
	while (*cp == ' ' || *cp == '\t' || *cp == '\n')
		cp++;
	is_negative = (*cp == '-');
	if (is_negative)
		cp++;
	if (base == 0) {
		base = 10;
		if (*cp == '0') {
			base = 8;
			cp++;
			if (*cp == 'x' || *cp == 'X') {
				base = 16;
				cp++;
			}
		}
	}
	value = 0;
	for (; *cp != '\0'; cp++) {
		if (*cp >= '0' && *cp <= '9')
			digits = *cp - '0';
		else if (*cp >= 'a' && *cp <= 'f')
			digits = *cp - 'a' + 10;
		else if (*cp >= 'A' && *cp <= 'F')
			digits = *cp - 'A' + 10;
		else
			break;
		if (digits >= base)
			break;
		value = (value * base) + digits;
	}

	/*
	 * Note: we cast away const here deliberately
	 */
	if (ptr != NULL)
		*ptr = (char *)cp;
	if (is_negative)
		value = -value;
	return (value);
}


#ifdef	XCVR
static int
eri_init_xcvr_info(struct eri *erip, int display_msg)
{
	uint16_t phy_id1, phy_id2;
	uint32_t vendor_id;
	uint16_t device_id;
	uint16_t device_rev;

	(void) eri_mii_read(erip, ERI_PHY_IDR1, &phy_id1);
	(void) eri_mii_read(erip, ERI_PHY_IDR2, &phy_id2);

	vendor_id = ((phy_id1 << 0x6) | (phy_id2 >> 10));
	device_id = (phy_id2 >>4) & 0x3f;
	device_rev =  (phy_id2 & 0xf);

	switch (vendor_id) {
	case  PHY_VENDOR_LUCENT:
		if (display_msg)
			ERI_FAULT_MSG2(erip, SEVERITY_NONE, ERI_VERB_MSG,
					lucent_phy_msg, vendor_id);
		break;

	/*
	 * No Phy/xcvrs are executed as default.
	 * This can happen if the xcvr is changed after the attach of a
	 * I/O board or a future NIC.
	 */
	default:
		ERI_FAULT_MSG2(erip, SEVERITY_HIGH, ERI_VERB_MSG,
				unk_phy_msg, vendor_id);
		erip->vendor_id = 0;
		erip->device_id = 0;
		erip->device_rev = 0;
		param_linkup = 0;
		erip->stats.link_up = ERI_LINK_DOWN;
		erip->stats.link_duplex = ERI_UNKNOWN_DUPLEX;
		eri_notify_ind(erip, DL_NOTE_LINK_DOWN);
		return (1);
	}
	erip->vendor_id = vendor_id;
	erip->device_id = device_id;
	erip->device_rev = device_rev;
	return (0);
}
#endif

/* Decide if transmitter went dead and reinitialize everything */
#ifdef	ERI_TX_HUNG
static int eri_txhung_limit = 2;
static int
eri_check_txhung(struct eri *erip)
{
	mutex_enter(&erip->xmitlock);
	if (erip->flags & ERI_RUNNING)
		erip->tx_completion = (uint32_t)(GET_ETXREG(tx_completion)
				& ETX_COMPLETION_MASK);
		(void) eri_reclaim(erip, erip->tx_completion);

	/* Something needs to be sent out but it is not going out */
	if ((erip->tcurp != erip->tnextp) &&
	    (erip->stats.opackets64 == erip->erisave.reclaim_opackets) &&
	    (erip->stats.collisions == erip->erisave.starts))
		erip->txhung++;
	else
		erip->txhung = 0;

	erip->erisave.reclaim_opackets = erip->stats.opackets64;
	erip->erisave.starts = erip->stats.collisions;
	mutex_exit(&erip->xmitlock);

	return (erip->txhung >= eri_txhung_limit);
}
#endif

/* Process a DL_CAPABILITY_REQ */
static void
eri_dlcap_req(queue_t *wq, mblk_t *mp)
{
	struct eristr *sbp;
	struct eri *erip;
	dl_capability_req_t *icap;
	int prim;
	mblk_t *nmp;

	sbp = (struct eristr *)wq->q_ptr;
	erip = sbp->sb_erip;
	icap = (dl_capability_req_t *)mp->b_rptr;
	prim = icap->dl_primitive;

	ASSERT(prim == DL_CAPABILITY_REQ);

	ERI_DEBUG_MSG2(erip, DLCAPAB_MSG, "eri_dlcap_req: DL_CAPABILITY for "
	    "instance=%d\n", erip->instance);

	if (icap->dl_sub_length == 0) {
		/* IP wants to have a list of the capabilities we support. */
		ERI_DEBUG_MSG1(erip, DLCAPAB_MSG, "eri_dlcap_req: got request "
		    "for all capabilities");

		nmp = eri_dlcap_all(wq);
		if (nmp == NULL) {
			dlerrorack(wq, mp, prim, DL_SYSERR, ENOSR);
			return;
		}
		freemsg(mp);
	} else {
		/*
		 * IP is probably trying to enable or disable one or more
		 * capabilities. Reuse received mp to construct reply.
		 */
		ERI_DEBUG_MSG1(erip, DLCAPAB_MSG, "eri_dlcap_req: got len!=0 "
		    "DL_CAPABILITY_REQ\n");
		eri_dlcap_enable(wq, mp);
		nmp = mp;
	}
	ASSERT(nmp != NULL);

	/* send reply back up */
	ERI_DEBUG_MSG1(erip, DLCAPAB_MSG, "eri_dlcap_req: sending ACK\n");
	qreply(wq, nmp);
}

static mblk_t *
eri_dlcap_all(queue_t *wq)
{
	mblk_t *nmp;
	dl_capability_ack_t *ocap;
	dl_capability_sub_t *osub;
	dl_capab_hcksum_t *ocksum;
	uint_t size;

	/* Size of reply to send back up, say we support hardware checksum */
	size = sizeof (dl_capability_ack_t) +
	    sizeof (dl_capability_sub_t) +
	    sizeof (dl_capab_hcksum_t);

	/* allocate result mblk and get it started */
	if ((nmp = allocb(size, BPRI_MED)) == NULL)
		return (NULL);

	/* update mblk info */
	nmp->b_datap->db_type = M_PROTO;

	/* dl_capability_ack_t, one per message */
	ocap = (dl_capability_ack_t *)nmp->b_rptr;
	ocap->dl_primitive = DL_CAPABILITY_ACK;
	ocap->dl_sub_length = size - sizeof (dl_capability_ack_t);
	ocap->dl_sub_offset = sizeof (dl_capability_ack_t);
	nmp->b_wptr += sizeof (dl_capability_ack_t);

	/* dl_capability_sub_t for hardware checksum offload */
	osub = (dl_capability_sub_t *)nmp->b_wptr;
	osub->dl_cap = DL_CAPAB_HCKSUM;
	osub->dl_length = sizeof (dl_capab_hcksum_t);
	nmp->b_wptr += sizeof (dl_capability_sub_t);

	/* dl_capab_hcksum_t */
	ocksum = (dl_capab_hcksum_t *)nmp->b_wptr;
	ocksum->hcksum_version = HCKSUM_VERSION_1;
	/* tell ip that we're capable, but don't enable until ip says so */
	ocksum->hcksum_txflags = HCKSUM_INET_PARTIAL;
	dlcapabsetqid(&ocksum->hcksum_mid, RD(wq));
	nmp->b_wptr += sizeof (dl_capab_hcksum_t);

	return (nmp);
}

/* Process a non-zero length DL_CAPABILITY_REQ message */
static void
eri_dlcap_enable(queue_t *wq, mblk_t *mp)
{
	struct eristr *sbp;
	struct eri *erip;
	dl_capability_req_t *icap;
	dl_capability_sub_t *isub, *endp;
	dl_capab_hcksum_t *icksum;

	sbp = (struct eristr *)wq->q_ptr;
	ASSERT(MUTEX_HELD(&sbp->sb_lock));
	erip = sbp->sb_erip;
	icap = (dl_capability_req_t *)mp->b_rptr;
	icap->dl_primitive = DL_CAPABILITY_ACK;

	/* Make sure that IP supplied correct dl_sub_length */
	if ((sizeof (*icap) + icap->dl_sub_length) > MBLKL(mp)) {
		ERI_DEBUG_MSG2(erip, DLCAPAB_MSG, "eri_dlcap_enable: bad "
		    "DL_CAPABILITY_REQ, invalid dl_sub_length (%d)\n",
		    icap->dl_sub_length);
		return;
	}

#define	SC(base, offset) (dl_capability_sub_t *)(((uchar_t *)(base))+(offset))
	/*
	 * There are sub-capabilities. Process the ones we know about.
	 * Loop until we don't have room for another sub-cap header..
	 */
	for (isub = SC(icap, icap->dl_sub_offset),
	    endp = SC(isub, icap->dl_sub_length - sizeof (*isub));
	    isub <= endp; isub = SC(isub,
	    sizeof (dl_capability_sub_t) + isub->dl_length)) {

		switch (isub->dl_cap) {
		case DL_CAPAB_HCKSUM:
			if ((uint8_t *)(isub + 1) + isub->dl_length >
			    mp->b_wptr) {
				ERI_DEBUG_MSG1(erip, DLCAPAB_MSG,
				    "eri_dlcap_enable: malformed "
				    "sub-capability too long for mblk");
				break;
			}
			icksum = (dl_capab_hcksum_t *)(isub + 1);

			if (icksum->hcksum_txflags & HCKSUM_ENABLE)
				sbp->sb_flags |= ERI_SCKSUM;
			else
				sbp->sb_flags &= ~ERI_SCKSUM;
			dlcapabsetqid(&icksum->hcksum_mid, RD(wq));
			break;

		default:
			/* Unknown sub-capability; ignore it */
			break;
		}
	}
#undef SC
}

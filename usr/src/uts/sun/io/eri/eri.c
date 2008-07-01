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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include	<sys/strsubr.h>
#include	<sys/kmem.h>
#include	<sys/crc32.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/strsun.h>
#include	<sys/stat.h>
#include	<sys/cpu.h>
#include	<sys/kstat.h>
#include	<inet/common.h>
#include	<sys/pattr.h>
#include	<inet/mi.h>
#include	<inet/nd.h>
#include	<sys/ethernet.h>
#include	<sys/vlan.h>
#include	<sys/policy.h>
#include	<sys/mac.h>
#include	<sys/mac_ether.h>
#include	<sys/dlpi.h>

#include	<sys/pci.h>

#include	"eri_phy.h"
#include	"eri_mac.h"
#include	"eri.h"
#include	"eri_common.h"

#include	"eri_msg.h"

/*
 *  **** Function Prototypes *****
 */
/*
 * Entry points (man9e)
 */
static	int	eri_attach(dev_info_t *, ddi_attach_cmd_t);
static	int	eri_detach(dev_info_t *, ddi_detach_cmd_t);
static	uint_t	eri_intr(caddr_t);

/*
 * I/O (Input/Output) Functions
 */
static	boolean_t	eri_send_msg(struct eri *, mblk_t *);
static  mblk_t		*eri_read_dma(struct eri *, volatile struct rmd *,
			    volatile int, uint64_t flags);

/*
 * Initialization Functions
 */
static  boolean_t	eri_init(struct eri *);
static	int	eri_allocthings(struct eri *);
static  int	eri_init_xfer_params(struct eri *);
static  void	eri_statinit(struct eri *);
static	int	eri_burstsize(struct eri *);

static	void	eri_setup_mac_address(struct eri *, dev_info_t *);

static	uint32_t eri_init_rx_channel(struct eri *);
static	void	eri_init_rx(struct eri *);
static	void	eri_init_txmac(struct eri *);

/*
 * Un-init Functions
 */
static	uint32_t eri_txmac_disable(struct eri *);
static	uint32_t eri_rxmac_disable(struct eri *);
static	int	eri_stop(struct eri *);
static	void	eri_uninit(struct eri *erip);
static	int	eri_freebufs(struct eri *);
static	boolean_t	eri_reclaim(struct eri *, uint32_t);

/*
 * Transceiver (xcvr) Functions
 */
static	int	eri_new_xcvr(struct eri *); /* Initializes & detects xcvrs */
static	int	eri_reset_xcvr(struct eri *);

#ifdef	ERI_10_10_FORCE_SPEED_WORKAROUND
static	void	eri_xcvr_force_mode(struct eri *, uint32_t *);
#endif

static	void	eri_mif_poll(struct eri *, soft_mif_enable_t);
static	void	eri_check_link(struct eri *);
static	uint32_t eri_check_link_noind(struct eri *);
static	link_state_t eri_mif_check(struct eri *, uint16_t, uint16_t);
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
static void eri_fault_msg(struct eri *, uint_t, msg_t, const char *, ...);

/*
 * Misc Functions
 */
static void	eri_savecntrs(struct eri *);

static	void	eri_stop_timer(struct eri *erip);
static	void	eri_start_timer(struct eri *erip, fptrv_t func, clock_t msec);

static	void eri_bb_force_idle(struct eri *);

/*
 * Utility Functions
 */
static	mblk_t *eri_allocb(size_t size);
static	mblk_t *eri_allocb_sp(size_t size);
static	int	eri_param_get(queue_t *q, mblk_t *mp, caddr_t cp);
static	int	eri_param_set(queue_t *, mblk_t *, char *, caddr_t);

/*
 * Functions to support ndd
 */
static	void	eri_nd_free(caddr_t *nd_pparam);

static	boolean_t	eri_nd_load(caddr_t *nd_pparam, char *name,
				pfi_t get_pfi, pfi_t set_pfi, caddr_t data);

static	int	eri_nd_getset(queue_t *q, caddr_t nd_param, MBLKP mp);
static	void	eri_param_cleanup(struct eri *);
static	int	eri_param_register(struct eri *, param_t *, int);
static	void	eri_process_ndd_ioctl(struct eri *, queue_t *, mblk_t *, int);
static	int	eri_mk_mblk_tail_space(mblk_t *, mblk_t **, size_t);


static	void eri_loopback(struct eri *, queue_t *, mblk_t *);

static uint32_t	eri_ladrf_bit(const uint8_t *);


/*
 * Nemo (GLDv3) Functions.
 */
static	int		eri_m_stat(void *, uint_t, uint64_t *);
static	int		eri_m_start(void *);
static	void		eri_m_stop(void *);
static	int		eri_m_promisc(void *, boolean_t);
static	int		eri_m_multicst(void *, boolean_t, const uint8_t *);
static	int		eri_m_unicst(void *, const uint8_t *);
static	void		eri_m_ioctl(void *, queue_t *, mblk_t *);
static	boolean_t	eri_m_getcapab(void *, mac_capab_t, void *);
static	mblk_t		*eri_m_tx(void *, mblk_t *);

static mac_callbacks_t eri_m_callbacks = {
	MC_IOCTL | MC_GETCAPAB,
	eri_m_stat,
	eri_m_start,
	eri_m_stop,
	eri_m_promisc,
	eri_m_multicst,
	eri_m_unicst,
	eri_m_tx,
	NULL,
	eri_m_ioctl,
	eri_m_getcapab
};

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
 * MIB II broadcast/multicast packets
 */

#define	IS_BROADCAST(pkt) (bcmp(pkt, &etherbroadcastaddr, ETHERADDRL) == 0)
#define	IS_MULTICAST(pkt) ((pkt[0] & 01) == 1)

#define	BUMP_InNUcast(erip, pkt) \
		if (IS_BROADCAST(pkt)) { \
			HSTAT(erip, brdcstrcv); \
		} else if (IS_MULTICAST(pkt)) { \
			HSTAT(erip, multircv); \
		}

#define	BUMP_OutNUcast(erip, pkt) \
		if (IS_BROADCAST(pkt)) { \
			HSTAT(erip, brdcstxmt); \
		} else if (IS_MULTICAST(pkt)) { \
			HSTAT(erip, multixmt); \
		}

#define	NEXTTMDP(tbasep, tmdlimp, tmdp)	(((tmdp) + 1) == tmdlimp	\
	? tbasep : ((tmdp) + 1))

#define	ETHERHEADER_SIZE (sizeof (struct ether_header))

#ifdef	ERI_RCV_CKSUM
#define	ERI_PROCESS_READ(erip, bp, sum)				\
{								\
	t_uscalar_t	type;					\
	uint_t	start_offset, end_offset;			\
								\
	*(bp->b_wptr) = 0;	/* pad byte */			\
								\
	/*							\
	 * update MIB II statistics				\
	 */							\
	HSTAT(erip, ipackets64);				\
	HSTATN(erip, rbytes64, len);				\
	BUMP_InNUcast(erip, bp->b_rptr);			\
	type = get_ether_type(bp->b_rptr);			\
	if (type == ETHERTYPE_IP || type == ETHERTYPE_IPV6) {	\
		start_offset = 0;				\
		end_offset = MBLKL(bp) - ETHERHEADER_SIZE;	\
		(void) hcksum_assoc(bp, NULL, NULL,		\
			start_offset, 0, end_offset, sum, 	\
			HCK_PARTIALCKSUM, 0);			\
	} else {						\
		/*						\
		 * Strip the PADS for 802.3			\
		 */						\
		if (type <= ETHERMTU)				\
			bp->b_wptr = bp->b_rptr +		\
				ETHERHEADER_SIZE + type;	\
	}							\
}
#else

#define	ERI_PROCESS_READ(erip, bp)				\
{								\
	t_uscalar_t	type;					\
	type = get_ether_type(bp->b_rptr);			\
								\
	/*							\
	 * update MIB II statistics				\
	 */							\
	HSTAT(erip, ipackets64);				\
	HSTATN(erip, rbytes64, len);				\
	BUMP_InNUcast(erip, bp->b_rptr);			\
	/*							\
	 * Strip the PADS for 802.3				\
	 */							\
	if (type <= ETHERMTU)					\
		bp->b_wptr = bp->b_rptr + ETHERHEADER_SIZE + 	\
			type;					\
}
#endif  /* ERI_RCV_CKSUM */

/*
 * TX Interrupt Rate
 */
static	int	tx_interrupt_rate = 16;

/*
 * Ethernet broadcast address definition.
 */
static uint8_t	etherbroadcastaddr[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

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
/*
 * For the MII interface, the External Transceiver is selected when present.
 * The following variable is used to select the Internal Transceiver even
 * when the External Transceiver is present.
 */
static	int	use_int_xcvr = 0;
static	int	pace_size = 0;	/* Do not use pacing for now */

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
	/* min		max		value	r/w/hidden+name */
	{  0,		2,		2,	"-transceiver_inuse"},
	{  0,		1,		0,	"-link_status"},
	{  0,		1,		0,	"-link_speed"},
	{  0,		1,		0,	"-link_mode"},
	{  0,		255,		8,	"+ipg1"},
	{  0,		255,		4,	"+ipg2"},
	{  0,		1,		0,	"+use_int_xcvr"},
	{  0,		255,		0,	"+pace_size"},
	{  0,		1,		1,	"+adv_autoneg_cap"},
	{  0,		1,		1,	"+adv_100T4_cap"},
	{  0,		1,		1,	"+adv_100fdx_cap"},
	{  0,		1,		1,	"+adv_100hdx_cap"},
	{  0,		1,		1,	"+adv_10fdx_cap"},
	{  0,		1,		1,	"+adv_10hdx_cap"},
	{  0,		1,		1,	"-autoneg_cap"},
	{  0,		1,		1,	"-100T4_cap"},
	{  0,		1,		1,	"-100fdx_cap"},
	{  0,		1,		1,	"-100hdx_cap"},
	{  0,		1,		1,	"-10fdx_cap"},
	{  0,		1,		1,	"-10hdx_cap"},
	{  0,		1,		0,	"-lp_autoneg_cap"},
	{  0,		1,		0,	"-lp_100T4_cap"},
	{  0,		1,		0,	"-lp_100fdx_cap"},
	{  0,		1,		0,	"-lp_100hdx_cap"},
	{  0,		1,		0,	"-lp_10fdx_cap"},
	{  0,		1,		0,	"-lp_10hdx_cap"},
	{  0,		1,		1,	"+lance_mode"},
	{  0,		31,		8,	"+ipg0"},
	{  0,		127,		6,	"+intr_blank_time"},
	{  0,		255,		8,	"+intr_blank_packets"},
	{  0,		1,		1,	"!serial-link"},
	{  0,		2,		1,	"!non-serial-link"},
	{  0,		1,		0,	"%select-link"},
	{  0,		1,		0,	"%default-link"},
	{  0,		2,		0,	"!link-in-use"},
	{  0,		1,		1,	"%adv_asm_dir_cap"},
	{  0,		1,		1,	"%adv_pause_cap"},
	{  0,		1,		0,	"!asm_dir_cap"},
	{  0,		1,		0,	"!pause_cap"},
	{  0,		1,		0,	"!lp_asm_dir_cap"},
	{  0,		1,		0,	"!lp_pause_cap"},
};

DDI_DEFINE_STREAM_OPS(eri_dev_ops, nulldev, nulldev, eri_attach, eri_detach,
	nodev, NULL, D_MP, NULL);

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	"Sun RIO 10/100 Mb Ethernet",
	&eri_dev_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * Hardware Independent Functions
 * New Section
 */

int
_init(void)
{
	int	status;

	mac_init_ops(&eri_dev_ops, "eri");
	if ((status = mod_install(&modlinkage)) != 0) {
		mac_fini_ops(&eri_dev_ops);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&eri_dev_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Interface exists: make available by filling in network interface
 * record.  System will initialize the interface when it is ready
 * to accept packets.
 */
static int
eri_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct eri *erip = NULL;
	mac_register_t *macp = NULL;
	int	regno;
	boolean_t	doinit;
	boolean_t	mutex_inited = B_FALSE;
	boolean_t	intr_add = B_FALSE;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((erip = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		mutex_enter(&erip->intrlock);
		erip->flags &= ~ERI_SUSPENDED;
		erip->init_macregs = 1;
		param_linkup = 0;
		erip->stats.link_up = LINK_STATE_DOWN;
		erip->linkcheck = 0;

		doinit =  (erip->flags & ERI_STARTED) ? B_TRUE : B_FALSE;
		mutex_exit(&erip->intrlock);

		if (doinit && !eri_init(erip)) {
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft device data structure
	 */
	erip = kmem_zalloc(sizeof (struct eri), KM_SLEEP);

	/*
	 * Initialize as many elements as possible.
	 */
	ddi_set_driver_private(dip, erip);
	erip->dip = dip;			/* dip	*/
	erip->instance = ddi_get_instance(dip);	/* instance */
	erip->flags = 0;
	erip->multi_refcnt = 0;
	erip->promisc = B_FALSE;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		ERI_FAULT_MSG1(erip, SEVERITY_HIGH, ERI_VERB_MSG,
		    "mac_alloc failed");
		goto attach_fail;
	}
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = erip;
	macp->m_dip = dip;
	macp->m_src_addr = erip->ouraddr;
	macp->m_callbacks = &eri_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

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
	if (pci_config_setup(dip, &erip->pci_config_handle) != DDI_SUCCESS) {
		ERI_FAULT_MSG2(erip, SEVERITY_HIGH, ERI_VERB_MSG,
		    "%s pci_config_setup()", config_space_fatal_msg);
		goto attach_fail;
	}

	/*
	 * Initialize device attributes structure
	 */
	erip->dev_attr.devacc_attr_version =	DDI_DEVICE_ATTR_V0;
	erip->dev_attr.devacc_attr_dataorder =	DDI_STRICTORDER_ACC;
	erip->dev_attr.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC;

	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&(erip->globregp), 0, 0,
	    &erip->dev_attr, &erip->globregh)) {
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

	/*
	 * Map the software reset register.
	 */
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&(erip->sw_reset_reg),
	    0x1010, 4, &erip->dev_attr, &erip->sw_reset_regh)) {
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

	mutex_inited = B_TRUE;

	/*
	 * Add interrupt to system
	 */
	if (ddi_add_intr(dip, 0, &erip->cookie, 0, eri_intr, (caddr_t)erip) ==
	    DDI_SUCCESS)
		intr_add = B_TRUE;
	else {
		goto attach_fail;
	}

	/*
	 * Set up the ethernet mac address.
	 */
	(void) eri_setup_mac_address(erip, dip);

	if (eri_init_xfer_params(erip))
		goto attach_fail;

	if (eri_burstsize(erip) == DDI_FAILURE) {
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

	if (mac_register(macp, &erip->mh) != 0)
		goto attach_fail;

	mac_free(macp);

	return (DDI_SUCCESS);

attach_fail:
	if (erip->pci_config_handle)
		(void) pci_config_teardown(&erip->pci_config_handle);

	if (mutex_inited) {
		mutex_destroy(&erip->xmitlock);
		mutex_destroy(&erip->intrlock);
		mutex_destroy(&erip->linklock);
		mutex_destroy(&erip->xcvrlock);
	}

	ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG, attach_fail_msg);

	if (intr_add)
		ddi_remove_intr(dip, 0, erip->cookie);

	if (erip->globregh)
		ddi_regs_map_free(&erip->globregh);

	if (macp != NULL)
		mac_free(macp);
	if (erip != NULL)
		kmem_free(erip, sizeof (*erip));

	return (DDI_FAILURE);
}

static int
eri_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct eri 	*erip;
	int i;

	if ((erip = ddi_get_driver_private(dip)) == NULL) {
		/*
		 * No resources allocated.
		 */
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
		return (DDI_FAILURE);
	}

	if (erip->flags & (ERI_RUNNING | ERI_SUSPENDED)) {
		ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG, busy_msg);
		return (DDI_FAILURE);
	}

	if (mac_unregister(erip->mh) != 0) {
		return (DDI_FAILURE);
	}

	/*
	 * Make the device quiescent
	 */
	(void) eri_stop(erip);

	/*
	 * Remove instance of the intr
	 */
	ddi_remove_intr(dip, 0, erip->cookie);

	if (erip->pci_config_handle)
		(void) pci_config_teardown(&erip->pci_config_handle);

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
	uchar_t			*prop;
	char			*uselocal;
	unsigned		prop_len;
	uint32_t		addrflags = 0;
	struct ether_addr	factaddr;

	/*
	 * Check if it is an adapter with its own local mac address
	 * If it is present, save it as the "factory-address"
	 * for this adapter.
	 */
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "local-mac-address", &prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len == ETHERADDRL) {
			addrflags = ERI_FACTADDR_PRESENT;
			bcopy(prop, &factaddr, ETHERADDRL);
			ERI_FAULT_MSG2(erip, SEVERITY_NONE, ERI_VERB_MSG,
			    lether_addr_msg, ether_sprintf(&factaddr));
		}
		ddi_prop_free(prop);
	}
	/*
	 * Check if the adapter has published "mac-address" property.
	 * If it is present, use it as the mac address for this device.
	 */
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "mac-address", &prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len >= ETHERADDRL) {
			bcopy(prop, erip->ouraddr, ETHERADDRL);
			ddi_prop_free(prop);
			return;
		}
		ddi_prop_free(prop);
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0, "local-mac-address?",
	    &uselocal) == DDI_PROP_SUCCESS) {
		if ((strcmp("true", uselocal) == 0) &&
		    (addrflags & ERI_FACTADDR_PRESENT)) {
			addrflags |= ERI_FACTADDR_USE;
			bcopy(&factaddr, erip->ouraddr, ETHERADDRL);
			ddi_prop_free(uselocal);
			ERI_FAULT_MSG1(erip, SEVERITY_NONE, ERI_VERB_MSG,
			    lmac_addr_msg);
			return;
		}
		ddi_prop_free(uselocal);
	}

	/*
	 * Get the system ethernet address.
	 */
	(void) localetheraddr(NULL, &factaddr);
	bcopy(&factaddr, erip->ouraddr, ETHERADDRL);
}


/*
 * Calculate the bit in the multicast address filter that selects the given
 * address.
 * Note: For ERI, the last 8-bits are used.
 */

static uint32_t
eri_ladrf_bit(const uint8_t *addr)
{
	uint32_t crc;

	CRC32(crc, addr, ETHERADDRL, -1U, crc32_table);

	/*
	 * Just want the 8 most significant bits.
	 */
	return ((~crc) >> 24);
}

static void
eri_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct	eri	*erip = arg;
	struct	iocblk	*iocp = (void *)mp->b_rptr;
	int	err;

	ASSERT(erip != NULL);

	/*
	 * Privilege checks.
	 */
	switch (iocp->ioc_cmd) {
	case ERI_SET_LOOP_MODE:
	case ERI_ND_SET:
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (err != 0) {
			miocnak(wq, mp, 0, err);
			return;
		}
		break;
	default:
		break;
	}

	switch (iocp->ioc_cmd) {
	case ERI_ND_GET:
	case ERI_ND_SET:
		eri_process_ndd_ioctl(erip, wq, mp, iocp->ioc_cmd);
		break;

	case ERI_SET_LOOP_MODE:
	case ERI_GET_LOOP_MODE:
		/*
		 * XXX: Consider updating this to the new netlb ioctls.
		 */
		eri_loopback(erip, wq, mp);
		break;

	default:
		miocnak(wq, mp, 0, EINVAL);
		break;
	}

	ASSERT(!MUTEX_HELD(&erip->linklock));
}

static void
eri_loopback(struct eri *erip, queue_t *wq, mblk_t *mp)
{
	struct	iocblk	*iocp = (void *)mp->b_rptr;
	loopback_t	*al;

	if (mp->b_cont == NULL || MBLKL(mp->b_cont) < sizeof (loopback_t)) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	al = (void *)mp->b_cont->b_rptr;

	switch (iocp->ioc_cmd) {
	case ERI_SET_LOOP_MODE:
		switch (al->loopback) {
		case ERI_LOOPBACK_OFF:
			erip->flags &= (~ERI_MACLOOPBACK & ~ERI_SERLOOPBACK);
			/* force link status to go down */
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
			(void) eri_init(erip);
			break;

		case ERI_MAC_LOOPBACK_ON:
			erip->flags |= ERI_MACLOOPBACK;
			erip->flags &= ~ERI_SERLOOPBACK;
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
			(void) eri_init(erip);
			break;

		case ERI_PCS_LOOPBACK_ON:
			break;

		case ERI_SER_LOOPBACK_ON:
			erip->flags |= ERI_SERLOOPBACK;
			erip->flags &= ~ERI_MACLOOPBACK;
			/* force link status to go down */
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
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
		al->loopback =	ERI_MAC_LOOPBACK_ON | ERI_PCS_LOOPBACK_ON |
		    ERI_SER_LOOPBACK_ON;
		miocack(wq, mp, sizeof (loopback_t), 0);
		break;

	default:
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
		    loopback_cmd_default);
	}
}

static int
eri_m_promisc(void *arg, boolean_t on)
{
	struct	eri	*erip = arg;

	mutex_enter(&erip->intrlock);
	erip->promisc = on;
	eri_init_rx(erip);
	mutex_exit(&erip->intrlock);
	return (0);
}

/*
 * This is to support unlimited number of members
 * in Multicast.
 */
static int
eri_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	struct eri		*erip = arg;
	uint32_t 		ladrf_bit;

	/*
	 * If this address's bit was not already set in the local address
	 * filter, add it and re-initialize the Hardware.
	 */
	ladrf_bit = eri_ladrf_bit(mca);

	mutex_enter(&erip->intrlock);
	if (add) {
		erip->ladrf_refcnt[ladrf_bit]++;
		if (erip->ladrf_refcnt[ladrf_bit] == 1) {
			LADRF_SET(erip, ladrf_bit);
			erip->multi_refcnt++;
			eri_init_rx(erip);
		}
	} else {
		erip->ladrf_refcnt[ladrf_bit]--;
		if (erip->ladrf_refcnt[ladrf_bit] == 0) {
			LADRF_CLR(erip, ladrf_bit);
			erip->multi_refcnt--;
			eri_init_rx(erip);
		}
	}
	mutex_exit(&erip->intrlock);
	return (0);
}

static int
eri_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct	eri	*erip = arg;

	/*
	 * Set new interface local address and re-init device.
	 * This is destructive to any other streams attached
	 * to this device.
	 */
	mutex_enter(&erip->intrlock);
	bcopy(macaddr, &erip->ouraddr, ETHERADDRL);
	eri_init_rx(erip);
	mutex_exit(&erip->intrlock);
	return (0);
}

/*ARGSUSED*/
static boolean_t
eri_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *hcksum_txflags = cap_data;
		*hcksum_txflags = HCKSUM_INET_PARTIAL;
		return (B_TRUE);
	}
	case MAC_CAPAB_POLL:
	default:
		return (B_FALSE);
	}
}

static int
eri_m_start(void *arg)
{
	struct eri	*erip = arg;

	mutex_enter(&erip->intrlock);
	erip->flags |= ERI_STARTED;
	mutex_exit(&erip->intrlock);

	if (!eri_init(erip)) {
		mutex_enter(&erip->intrlock);
		erip->flags &= ~ERI_STARTED;
		mutex_exit(&erip->intrlock);
		return (EIO);
	}
	return (0);
}

static void
eri_m_stop(void *arg)
{
	struct eri	*erip = arg;

	mutex_enter(&erip->intrlock);
	erip->flags &= ~ERI_STARTED;
	mutex_exit(&erip->intrlock);
	eri_uninit(erip);
}

static int
eri_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct eri	*erip = arg;
	struct stats	*esp;
	boolean_t	macupdate = B_FALSE;

	esp = &erip->stats;

	mutex_enter(&erip->xmitlock);
	if ((erip->flags & ERI_RUNNING) && (erip->flags & ERI_TXINIT)) {
		erip->tx_completion =
		    GET_ETXREG(tx_completion) & ETX_COMPLETION_MASK;
		macupdate |= eri_reclaim(erip, erip->tx_completion);
	}
	mutex_exit(&erip->xmitlock);
	if (macupdate)
		mac_tx_update(erip->mh);

	eri_savecntrs(erip);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = esp->ifspeed * 1000000ULL;
		break;
	case MAC_STAT_MULTIRCV:
		*val = esp->multircv;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = esp->brdcstrcv;
		break;
	case MAC_STAT_IPACKETS:
		*val = esp->ipackets64;
		break;
	case MAC_STAT_RBYTES:
		*val = esp->rbytes64;
		break;
	case MAC_STAT_OBYTES:
		*val = esp->obytes64;
		break;
	case MAC_STAT_OPACKETS:
		*val = esp->opackets64;
		break;
	case MAC_STAT_IERRORS:
		*val = esp->ierrors;
		break;
	case MAC_STAT_OERRORS:
		*val = esp->oerrors;
		break;
	case MAC_STAT_MULTIXMT:
		*val = esp->multixmt;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = esp->brdcstxmt;
		break;
	case MAC_STAT_NORCVBUF:
		*val = esp->norcvbuf;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = esp->noxmtbuf;
		break;
	case MAC_STAT_UNDERFLOWS:
		*val = esp->txmac_urun;
		break;
	case MAC_STAT_OVERFLOWS:
		*val = esp->rx_overflow;
		break;
	case MAC_STAT_COLLISIONS:
		*val = esp->collisions;
		break;
	case ETHER_STAT_ALIGN_ERRORS:
		*val = esp->rx_align_err;
		break;
	case ETHER_STAT_FCS_ERRORS:
		*val = esp->rx_crc_err;
		break;
	case ETHER_STAT_EX_COLLISIONS:
		*val = esp->excessive_coll;
		break;
	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = esp->late_coll;
		break;
	case ETHER_STAT_FIRST_COLLISIONS:
		*val = esp->first_coll;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = esp->link_duplex;
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		*val = esp->rx_toolong_pkts;
		break;
	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = esp->rx_runt;
		break;

	case ETHER_STAT_XCVR_ADDR:
		*val = erip->phyad;
		break;

	case ETHER_STAT_XCVR_INUSE:
		*val = XCVR_100X;	/* should always be 100X for now */
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = param_bmsr_100fdx;
		break;
	case ETHER_STAT_CAP_100HDX:
		*val = param_bmsr_100hdx;
		break;
	case ETHER_STAT_CAP_10FDX:
		*val = param_bmsr_10fdx;
		break;
	case ETHER_STAT_CAP_10HDX:
		*val = param_bmsr_10hdx;
		break;
	case ETHER_STAT_CAP_AUTONEG:
		*val = param_bmsr_ancap;
		break;
	case ETHER_STAT_CAP_ASMPAUSE:
		*val = param_bmsr_asm_dir;
		break;
	case ETHER_STAT_CAP_PAUSE:
		*val = param_bmsr_pause;
		break;
	case ETHER_STAT_ADV_CAP_100FDX:
		*val = param_anar_100fdx;
		break;
	case ETHER_STAT_ADV_CAP_100HDX:
		*val = param_anar_100hdx;
		break;
	case ETHER_STAT_ADV_CAP_10FDX:
		*val = param_anar_10fdx;
		break;
	case ETHER_STAT_ADV_CAP_10HDX:
		*val = param_anar_10hdx;
		break;
	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = param_autoneg;
		break;
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = param_anar_asm_dir;
		break;
	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = param_anar_pause;
		break;
	case ETHER_STAT_LP_CAP_100FDX:
		*val = param_anlpar_100fdx;
		break;
	case ETHER_STAT_LP_CAP_100HDX:
		*val = param_anlpar_100hdx;
		break;
	case ETHER_STAT_LP_CAP_10FDX:
		*val = param_anlpar_10fdx;
		break;
	case ETHER_STAT_LP_CAP_10HDX:
		*val = param_anlpar_10hdx;
		break;
	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = param_aner_lpancap;
		break;
	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*val = param_anlpar_pauseTX;
		break;
	case ETHER_STAT_LP_CAP_PAUSE:
		*val = param_anlpar_pauseRX;
		break;
	case ETHER_STAT_LINK_PAUSE:
		*val = esp->pausing;
		break;
	case ETHER_STAT_LINK_ASMPAUSE:
		*val = param_anar_asm_dir &&
		    param_anlpar_pauseTX &&
		    (param_anar_pause != param_anlpar_pauseRX);
		break;
	case ETHER_STAT_LINK_AUTONEG:
		*val = param_autoneg && param_aner_lpancap;
		break;
	}
	return (0);
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
		    ((erip->ouraddr[0] & 0x3) << 8) | erip->ouraddr[1]);

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

	PUT_MACREG(madd0, (erip->ouraddr[4] << 8) | erip->ouraddr[5]);
	PUT_MACREG(madd1, (erip->ouraddr[2] << 8) | erip->ouraddr[3]);
	PUT_MACREG(madd2, (erip->ouraddr[0] << 8) | erip->ouraddr[1]);

	/*
	 * Install multicast address filter.
	 */

	PUT_MACREG(hash0, erip->ladrf[0]);
	PUT_MACREG(hash1, erip->ladrf[1]);
	PUT_MACREG(hash2, erip->ladrf[2]);
	PUT_MACREG(hash3, erip->ladrf[3]);
	PUT_MACREG(hash4, erip->ladrf[4]);
	PUT_MACREG(hash5, erip->ladrf[5]);
	PUT_MACREG(hash6, erip->ladrf[6]);
	PUT_MACREG(hash7, erip->ladrf[7]);
	PUT_MACREG(hash8, erip->ladrf[8]);
	PUT_MACREG(hash9, erip->ladrf[9]);
	PUT_MACREG(hash10, erip->ladrf[10]);
	PUT_MACREG(hash11, erip->ladrf[11]);
	PUT_MACREG(hash12, erip->ladrf[12]);
	PUT_MACREG(hash13, erip->ladrf[13]);
	PUT_MACREG(hash14, erip->ladrf[14]);
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
			continue;
		}
		/* Load data buffer to DVMA space */
		if (erip->eri_dvmarh)
			dvma_kaddr_load(erip->eri_dvmarh,
			    (caddr_t)bp->b_rptr, ERI_BUFSIZE,
			    2 * i, &dma_cookie);
/*
 *		Bind data buffer to DMA handle
 */
		else if (ddi_dma_addr_bind_handle(erip->ndmarh[i], NULL,
		    (caddr_t)bp->b_rptr, ERI_BUFSIZE,
		    DDI_DMA_READ | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, 0,
		    &dma_cookie, &ccnt) != DDI_DMA_MAPPED)
			status = -1;

		PUT_RMD((&erip->rmdp[i]), dma_cookie);
		erip->rmblkp[i] = bp;	/* save for later use */
	}

	/*
	 * sync RXDMA descriptors.
	 */
	ERI_SYNCIOPB(erip, erip->rmdp, (ERI_RPENDING * sizeof (struct rmd)),
	    DDI_DMA_SYNC_FORDEV);
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
		erip->stats.link_up = LINK_STATE_DOWN;
		erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
		erip->global_reset_issued = -1;
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

	/* Disable the RX DMA */
	PUT_ERXREG(config, GET_ERXREG(config) & ~GET_CONFIG_RXDMA_EN);
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
	ERI_DELAY(((GET_SWRSTREG(reset) & (ERI_G_RESET_ERX)) ==
	    ERI_CACHE_LINE_SIZE), ERI_MAX_RST_DELAY);
	erip->rx_reset_issued = -1;

	return ((GET_SWRSTREG(reset) & (ERI_G_RESET_ERX)) ? 1 : 0);
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

	/* Disable the TX DMA */
	PUT_ETXREG(config, GET_ETXREG(config) & ~GET_CONFIG_TXDMA_EN);
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
	    (ETHERHEADER_SIZE << ERI_RX_CONFIG_RX_CSSTART_SHIFT) |
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
	ERI_SYNCIOPB(erip, erip->rmdp, (ERI_RPENDING * sizeof (struct rmd)),
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
	uint16_t	*ladrf;

	/*
	 * First of all make sure the Receive MAC is stop.
	 */
	(void) eri_rxmac_disable(erip); /* Disable the RX MAC */

	/*
	 * Program BigMAC with local individual ethernet address.
	 */

	PUT_MACREG(madd0, (erip->ouraddr[4] << 8) | erip->ouraddr[5]);
	PUT_MACREG(madd1, (erip->ouraddr[2] << 8) | erip->ouraddr[3]);
	PUT_MACREG(madd2, (erip->ouraddr[0] << 8) | erip->ouraddr[1]);

	/*
	 * Set up multicast address filter by passing all multicast
	 * addresses through a crc generator, and then using the
	 * low order 8 bits as a index into the 256 bit logical
	 * address filter. The high order four bits select the word,
	 * while the rest of the bits select the bit within the word.
	 */

	ladrf = erip->ladrf;

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
	    ((erip->promisc ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->multi_refcnt ? BMAC_RXCFG_HASH : 0) |
	    BMAC_RXCFG_ENAB));
#else
	PUT_MACREG(rxcfg,
	    ((erip->promisc ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->multi_refcnt ? BMAC_RXCFG_HASH : 0) |
	    BMAC_RXCFG_ENAB | BMAC_RXCFG_STRIP_CRC));
#endif
	/* wait after setting Hash Enable bit */
	/* drv_usecwait(10); */

	HSTAT(erip, rx_inits);
}

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
		PUT_MACREG(txcfg, ((param_mode ? BMAC_TXCFG_FDX: 0) |
		    ((param_lance_mode && (erip->lance_mode_enable)) ?
		    BMAC_TXCFG_ENIPG0 : 0) |
		    (carrier_ext ? BMAC_TXCFG_CARR_EXT : 0) |
		    BMAC_TXCFG_NGU));
	else
		PUT_MACREG(txcfg, ((param_mode ? BMAC_TXCFG_FDX: 0) |
		    ((param_lance_mode && (erip->lance_mode_enable)) ?
		    BMAC_TXCFG_ENIPG0 : 0) |
		    (carrier_ext ? BMAC_TXCFG_CARR_EXT : 0)));

	ENABLE_TXDMA(erip);
	ENABLE_TXMAC(erip);

	HSTAT(erip, tx_inits);
	erip->flags |= ERI_TXINIT;
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
 * Return true on success, false on error.
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
 *	intrlock->linklock->xmitlock->xcvrlock
 */
static boolean_t
eri_init(struct eri *erip)
{
	uint32_t	init_stat = 0;
	uint32_t	partial_init = 0;
	uint32_t	carrier_ext = 0;
	uint32_t	mac_ctl = 0;
	boolean_t	ret;
	uint32_t 	link_timeout = ERI_LINKCHECK_TIMER;
	link_state_t	linkupdate = LINK_STATE_UNKNOWN;

	/*
	 * Just return successfully if device is suspended.
	 * eri_init() will be called again from resume.
	 */
	ASSERT(erip != NULL);

	if (erip->flags & ERI_SUSPENDED) {
		ret = B_TRUE;
		goto init_exit;
	}

	mutex_enter(&erip->intrlock);
	eri_stop_timer(erip);	/* acquire linklock */
	mutex_enter(&erip->xmitlock);
	erip->flags &= (ERI_DLPI_LINKUP | ERI_STARTED);
	erip->wantw = B_FALSE;
	HSTAT(erip, inits);
	erip->txhung = 0;

	if ((erip->stats.inits > 1) && (erip->init_macregs == 0))
		eri_savecntrs(erip);

	mutex_enter(&erip->xcvrlock);
	if (!param_linkup || erip->linkcheck) {
		if (!erip->linkcheck)
			linkupdate = LINK_STATE_DOWN;
		(void) eri_stop(erip);
	}
	if (!(erip->flags & ERI_DLPI_LINKUP) || !param_linkup) {
		erip->flags |= ERI_DLPI_LINKUP;
		eri_mif_poll(erip, MIF_POLL_STOP);
		(void) eri_new_xcvr(erip);
		ERI_DEBUG_MSG1(erip, XCVR_MSG, "New transceiver detected.");
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
			if (erip->stats.link_up == LINK_STATE_UP)
				linkupdate = LINK_STATE_UP;
		} else {
			erip->flags |= (ERI_RUNNING | ERI_INITIALIZED);
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
			linkupdate = LINK_STATE_DOWN;
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
		erip->stats.link_up = LINK_STATE_DOWN;
		erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
		linkupdate = LINK_STATE_DOWN;
		goto done;
	}

	if (eri_rxmac_disable(erip)) {
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
		    disable_rxmac_msg);
		param_linkup = 0;	/* force init again */
		erip->stats.link_up = LINK_STATE_DOWN;
		erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
		linkupdate = LINK_STATE_DOWN;
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
	    ((erip->promisc ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->multi_refcnt ? BMAC_RXCFG_HASH : 0) |
	    (carrier_ext ? BMAC_RXCFG_CARR_EXT : 0)));
#else
	PUT_MACREG(rxcfg,
	    ((erip->promisc ? BMAC_RXCFG_PROMIS : 0) |
	    (erip->multi_refcnt ? BMAC_RXCFG_HASH : 0) |
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
	}

	/*
	 * Enable TX and RX MACs.
	 */
	ENABLE_MAC(erip);
	erip->flags |= (ERI_RUNNING | ERI_INITIALIZED |
	    ERI_TXINIT | ERI_RXINIT);
	mac_tx_update(erip->mh);
	erip->global_reset_issued = 0;

#ifdef	ERI_10_10_FORCE_SPEED_WORKAROUND
	eri_xcvr_force_mode(erip, &link_timeout);
#endif

done:
	if (init_stat)
		eri_unallocthings(erip);

	mutex_exit(&erip->xmitlock);
	eri_start_timer(erip, eri_check_link, link_timeout);
	mutex_exit(&erip->intrlock);

	if (linkupdate != LINK_STATE_UNKNOWN)
		mac_link_update(erip->mh, linkupdate);

	ret = (erip->flags & ERI_RUNNING) ? B_TRUE : B_FALSE;
	if (!ret) {
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

	if (ddi_dma_alloc_handle(erip->dip, &dma_attr, DDI_DMA_DONTWAIT,
	    NULL, &handle))
		return (DDI_FAILURE);

	erip->burstsizes = ddi_dma_burstsizes(handle);
	ddi_dma_free_handle(&handle);

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
	boolean_t needind;

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

	needind = !erip->linkcheck;
	(void) eri_stop(erip);
	erip->flags &= ~ERI_RUNNING;

	mutex_exit(&erip->xmitlock);
	eri_start_timer(erip, eri_check_link, 0);
	mutex_exit(&erip->intrlock);

	if (needind)
		mac_link_update(erip->mh, LINK_STATE_DOWN);
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
	size = (ERI_RPENDING * sizeof (struct rmd) +
	    ERI_TPENDING * sizeof (struct eri_tmd)) + ERI_GMDALIGN;

	rval = ddi_dma_alloc_handle(erip->dip, &desc_dma_attr,
	    DDI_DMA_DONTWAIT, 0, &erip->md_h);
	if (rval != DDI_SUCCESS) {
		return (++alloc_stat);
	}
	erip->alloc_flag |= ERI_DESC_HANDLE_ALLOC;

	rval = ddi_dma_mem_alloc(erip->md_h, size, &erip->dev_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, 0,
	    (caddr_t *)&erip->iopbkbase, &real_len, &erip->mdm_h);
	if (rval != DDI_SUCCESS) {
		return (++alloc_stat);
	}
	erip->alloc_flag |= ERI_DESC_MEM_ALLOC;

	rval = ddi_dma_addr_bind_handle(erip->md_h, NULL,
	    (caddr_t)erip->iopbkbase, size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0, &erip->md_c, &cookiec);

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
	if (ddi_dma_alloc_handle(erip->dip, &desc_dma_attr, DDI_DMA_DONTWAIT,
	    0, &erip->tbuf_handle) != DDI_SUCCESS) {
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
	    erip->tbuf_kaddr, size, DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0, &dma_cookie, &cookiec) != DDI_DMA_MAPPED) {
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
eri_intr(caddr_t arg)
{
	struct eri *erip = (void *)arg;
	uint32_t erisbits;
	uint32_t mif_status;
	uint32_t serviced = DDI_INTR_UNCLAIMED;
	link_state_t linkupdate = LINK_STATE_UNKNOWN;
	boolean_t macupdate = B_FALSE;
	mblk_t *mp;
	mblk_t *head;
	mblk_t **tail;

	head = NULL;
	tail = &head;

	mutex_enter(&erip->intrlock);

	erisbits = GET_GLOBREG(status);

	/*
	 * Check if it is only the RX_DONE interrupt, which is
	 * the most frequent one.
	 */
	if (((erisbits & ERI_G_STATUS_RX_INT) == ERI_G_STATUS_RX_DONE) &&
	    (erip->flags & ERI_RUNNING)) {
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
#ifdef	ESTAR_WORKAROUND
		uint32_t linkupdate;
#endif

		ERI_DEBUG_MSG2(erip, DIAG_MSG,
		    "eri_intr: Interrupt Not Claimed gsbits  %X", erisbits);
#ifdef	DEBUG
		noteri++;
#endif
		ERI_DEBUG_MSG2(erip, DIAG_MSG, "eri_intr:MIF Config = 0x%X",
		    GET_MIFREG(mif_cfg));
		ERI_DEBUG_MSG2(erip, DIAG_MSG, "eri_intr:MIF imask = 0x%X",
		    GET_MIFREG(mif_imask));
		ERI_DEBUG_MSG2(erip, DIAG_MSG, "eri_intr:INT imask = 0x%X",
		    GET_GLOBREG(intmask));
		ERI_DEBUG_MSG2(erip, DIAG_MSG, "eri_intr:alias %X",
		    GET_GLOBREG(status_alias));
#ifdef	ESTAR_WORKAROUND
		linkupdate = eri_check_link_noind(erip);
#endif
		mutex_exit(&erip->intrlock);
#ifdef	ESTAR_WORKAROUND
		if (linkupdate != LINK_STATE_UNKNOWN)
			mac_link_update(erip->mh, linkupdate);
#endif
		return (serviced);
	}
	serviced = DDI_INTR_CLAIMED;

	if (!(erip->flags & ERI_RUNNING)) {
		mutex_exit(&erip->intrlock);
		eri_uninit(erip);
		return (serviced);
	}

	if (erisbits & ERI_G_STATUS_FATAL_ERR) {
		ERI_DEBUG_MSG2(erip, INTR_MSG,
		    "eri_intr: fatal error: erisbits = %X", erisbits);
		(void) eri_fatal_err(erip, erisbits);
		eri_reinit_fatal++;

		if (erip->rx_reset_issued) {
			erip->rx_reset_issued = 0;
			(void) eri_init_rx_channel(erip);
			mutex_exit(&erip->intrlock);
		} else {
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
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
		    "eri_intr:MIF Interrupt:mii_status %X", erip->mii_status);
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
		linkupdate = eri_mif_check(erip, stat, stat);

#else
		mif_status = GET_MIFREG(mif_bsts);
		eri_mif_poll(erip, MIF_POLL_STOP);
		linkupdate = eri_mif_check(erip, (uint16_t)mif_status,
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
	    "eri_intr:May have Read Interrupt status:status %X", erisbits);

rx_done_int:
	if ((erisbits & (ERI_G_STATUS_TX_INT_ME)) ||
	    (erip->tx_cur_cnt >= tx_interrupt_rate)) {
		mutex_enter(&erip->xmitlock);
		erip->tx_completion = (uint32_t)(GET_ETXREG(tx_completion) &
		    ETX_COMPLETION_MASK);

		macupdate |= eri_reclaim(erip, erip->tx_completion);
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
			mp = eri_read_dma(erip, rmdp, rmdi, flags);
			rmdi =  (rmdi + 1) & rmdmax_mask;
			rmdp = rmdpbase + rmdi;

			if (mp != NULL) {
				*tail = mp;
				tail = &mp->b_next;
			}

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

	erip->wantw = B_FALSE;

	mutex_exit(&erip->intrlock);

	if (head)
		mac_rx(erip->mh, NULL, head);

	if (macupdate)
		mac_tx_update(erip->mh);

	if (linkupdate != LINK_STATE_UNKNOWN)
		mac_link_update(erip->mh, linkupdate);

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
		}
	}

	/*
	 * PCI bus error
	 */
	if (pci_error_int && erip->pci_config_handle) {
		pci_status = pci_config_get16(erip->pci_config_handle,
		    PCI_CONF_STAT);
		ERI_DEBUG_MSG2(erip, FATAL_ERR_MSG, "Bus Error Status %x",
		    pci_status);
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
		pci_config_put16(erip->pci_config_handle, PCI_CONF_STAT,
		    pci_status);
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
			erip->linkcheck = 1;
			HSTAT(erip, txmac_urun);
			HSTAT(erip, oerrors);
		}

		if (txmac_sts & BMAC_TXSTS_MAXPKT_ERR) {
			erip->linkcheck = 1;
			HSTAT(erip, txmac_maxpkt_err);
			HSTAT(erip, oerrors);
		}
		if (txmac_sts & BMAC_TXSTS_NCC_EXP) {
			erip->stats.collisions += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_ECC_EXP) {
			erip->stats.excessive_coll += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_LCC_EXP) {
			erip->stats.late_coll += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_FCC_EXP) {
			erip->stats.first_coll += 0x10000;
		}

		if (txmac_sts & BMAC_TXSTS_DEFER_EXP) {
			HSTAT(erip, defer_timer_exp);
		}

		if (txmac_sts & BMAC_TXSTS_PEAK_EXP) {
			erip->stats.peak_attempt_cnt += 0x100;
		}
	}

	if (erisbits & ERI_G_STATUS_RX_NO_BUF) {
		ERI_DEBUG_MSG1(erip, NONFATAL_MSG, "rx dropped/no free desc");

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

			ERI_DEBUG_MSG5(erip, NONFATAL_MSG,
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
			erip->stats.rx_align_err += 0x10000;
			erip->stats.ierrors += 0x10000;
		}

		if (rxmac_sts & BMAC_RXSTS_CRC_EXP) {
			erip->stats.rx_crc_err += 0x10000;
			erip->stats.ierrors += 0x10000;
		}

		if (rxmac_sts & BMAC_RXSTS_LEN_EXP) {
			erip->stats.rx_length_err += 0x10000;
			erip->stats.ierrors += 0x10000;
		}

		if (rxmac_sts & BMAC_RXSTS_CVI_EXP) {
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
			HSTAT(erip, pause_oncount);
			erip->stats.pausing = 1;
		}

		if (macctl_sts & ERI_MCTLSTS_NONPAUSE) {
			HSTAT(erip, pause_offcount);
			erip->stats.pausing = 0;
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
	    "Frame Reg :mii_read: phyad = %X reg = %X ", phyad, regad);

	PUT_MIFREG(mif_frame, ERI_MIF_FRREAD |
	    (phyad << ERI_MIF_FRPHYAD_SHIFT) |
	    (regad << ERI_MIF_FRREGAD_SHIFT));
	MIF_ERIDELAY(300,  phyad, regad);
	frame = GET_MIFREG(mif_frame);
	if ((frame & ERI_MIF_FRTA0) == 0) {
		return (1);
	} else {
		*datap = (uint16_t)(frame & ERI_MIF_FRDATA);
		return (0);
	}

}

static void
eri_mii_write(struct eri *erip, uint8_t regad, uint16_t data)
{
	uint8_t	phyad;

	if (!erip->frame_enable) {
		eri_bb_mii_write(erip, regad, data);
		return;
	}

	phyad = erip->phyad;

	PUT_MIFREG(mif_frame, (ERI_MIF_FRWRITE |
	    (phyad << ERI_MIF_FRPHYAD_SHIFT) |
	    (regad << ERI_MIF_FRREGAD_SHIFT) | data));
	MIF_ERIDELAY(300,  phyad, regad);
	(void) GET_MIFREG(mif_frame);
}


/* <<<<<<<<<<<<<<<<<	PACKET TRANSMIT FUNCTIONS	>>>>>>>>>>>>>>>>>>>> */

#define	ERI_CROSS_PAGE_BOUNDRY(i, size, pagesize) \
	((i & pagesize) != ((i + size) & pagesize))

/*
 * Send a single mblk.  Returns B_TRUE if the packet is sent, or disposed of
 * by freemsg.  Returns B_FALSE if the packet was not sent or queued, and
 * should be retried later (due to tx resource exhaustion.)
 */
static boolean_t
eri_send_msg(struct eri *erip, mblk_t *mp)
{
	volatile struct	eri_tmd	*tmdp = NULL;
	volatile struct	eri_tmd	*tbasep = NULL;
	mblk_t		*nmp;
	uint32_t	len = 0, len_msg = 0, xover_len = TX_STREAM_MIN;
	uint32_t	nmblks = 0;
	uint32_t	i, j;
	uint64_t	int_me = 0;
	uint_t		tmdcsum = 0;
	uint_t		start_offset = 0;
	uint_t		stuff_offset = 0;
	uint_t		flags = 0;
	boolean_t	macupdate = B_FALSE;

	caddr_t	ptr;
	uint32_t	offset;
	uint64_t	ctrl;
	uint32_t	count;
	uint32_t	flag_dma;
	ddi_dma_cookie_t	c;

	if (!param_linkup) {
		freemsg(mp);
		HSTAT(erip, tnocar);
		HSTAT(erip, oerrors);
		return (B_TRUE);
	}

	nmp = mp;

#ifdef ERI_HWCSUM
	hcksum_retrieve(mp, NULL, NULL, &start_offset, &stuff_offset,
	    NULL, NULL, &flags);

	if (flags & HCK_PARTIALCKSUM) {
		if (get_ether_type(mp->b_rptr) == ETHERTYPE_VLAN) {
			start_offset += ETHERHEADER_SIZE + 4;
			stuff_offset += ETHERHEADER_SIZE + 4;
		} else {
			start_offset += ETHERHEADER_SIZE;
			stuff_offset += ETHERHEADER_SIZE;
		}
		tmdcsum = ERI_TMD_CSENABL;
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
	BUMP_OutNUcast(erip, mp->b_rptr);

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
			return (B_TRUE); /* bad case */
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

		len = MBLKL(nmp);
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
			    (off_t)offset, len_msg, DDI_DMA_SYNC_FORDEV);
			nmblks = 1; /* exit this for loop */
		} else if ((!j) && (len < eri_tx_bcopy_max)) { /* tb-1st mb */

			offset = (i * eri_tx_bcopy_max);
			ptr = erip->tbuf_kaddr + offset;

			bcopy(mp->b_rptr, ptr, len);

			c.dmac_address = erip->tbuf_ioaddr + offset;
			(void) ddi_dma_sync(erip->tbuf_handle,
			    (off_t)offset, len, DDI_DMA_SYNC_FORDEV);
			nmp = mp->b_cont;
			mp->b_cont = NULL;
			freeb(mp);
		} else if (erip->eri_dvmaxh != NULL) { /* fast DVMA */

			dvma_kaddr_load(erip->eri_dvmaxh,
			    (caddr_t)nmp->b_rptr, len, 2 * i, &c);
			dvma_sync(erip->eri_dvmaxh,
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

				return (B_TRUE); /* bad case */
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
		macupdate |= eri_reclaim(erip, erip->tx_completion);
	}
	mutex_exit(&erip->xmitlock);

	if (macupdate)
		mac_tx_update(erip->mh);

	return (B_TRUE);

notmds:
	HSTAT(erip, notmds);
	erip->wantw = B_TRUE;

	if (!erip->tx_int_me) {
		PUT_GLOBREG(intmask, GET_GLOBREG(intmask) &
		    ~(ERI_G_MASK_TX_INT_ME));
		erip->tx_int_me = 1;
	}

	if (erip->tx_cur_cnt >= tx_interrupt_rate) {
		erip->tx_completion = (uint32_t)(GET_ETXREG(tx_completion) &
		    ETX_COMPLETION_MASK);
		macupdate |= eri_reclaim(erip, erip->tx_completion);
	}

	mutex_exit(&erip->xmitlock);

	if (macupdate)
		mac_tx_update(erip->mh);

	return (B_FALSE);
}

static mblk_t *
eri_m_tx(void *arg, mblk_t *mp)
{
	struct eri *erip = arg;
	mblk_t *next;

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (!eri_send_msg(erip, mp)) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	return (mp);
}

/*
 * Transmit completion reclaiming.
 */
static boolean_t
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
				dvma_unload(erip->eri_dvmaxh, 2 * i,
				    (uint_t)DONT_FLUSH);
			} else {
				/* dma handle case. */
				(void) ddi_dma_unbind_handle(erip->ndmaxh[i]);
			}

			freeb(bp);
			erip->tmblkp[i] = NULL;

		}
		tmdp = NEXTTMDP(tbasep, tlimp, tmdp);
		reclaimed++;
	}

	erip->tcurp = tmdp;
	erip->tx_cur_cnt -= reclaimed;

	return (erip->wantw && reclaimed ? B_TRUE : B_FALSE);
}


/* <<<<<<<<<<<<<<<<<<<	PACKET RECEIVE FUNCTIONS	>>>>>>>>>>>>>>>>>>> */
static mblk_t *
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
	mblk_t *retmp = NULL;

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
	if ((flags & ERI_RMD_BAD) || (len  < ETHERMIN) || (len > ETHERMAX+4)) {

		HSTAT(erip, rx_bad_pkts);
		if ((flags & ERI_RMD_BAD) == 0)
			HSTAT(erip, ierrors);
		if (len < ETHERMIN) {
			HSTAT(erip, rx_runt);
		} else if (len > ETHERMAX+4) {
			HSTAT(erip, rx_toolong_pkts);
		}
		HSTAT(erip, drop);
		UPDATE_RMD(rmdp);

		ERI_SYNCIOPB(erip, rmdp, sizeof (struct rmd),
		    DDI_DMA_SYNC_FORDEV);
		return (NULL);
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
			    len + ERI_FSTBYTE_OFFSET, DDI_DMA_SYNC_FORCPU);
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
			retmp = nbp;
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
			ERI_DEBUG_MSG1(erip, RESOURCE_MSG, "allocb fail");
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
			retmp = bp;
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
			ERI_DEBUG_MSG1(erip, RESOURCE_MSG, "allocb fail");
		}
	}

	return (retmp);
}

#define	LINK_STAT_DISPLAY_TIME	20

static int
eri_init_xfer_params(struct eri *erip)
{
	int	i;
	dev_info_t *dip;

	dip = erip->dip;

	for (i = 0; i < A_CNT(param_arr); i++)
		erip->param_arr[i] = param_arr[i];

	erip->xmit_dma_mode = 0;
	erip->rcv_dma_mode = 0;
	erip->mifpoll_enable = mifpoll_enable;
	erip->lance_mode_enable = lance_mode;
	erip->frame_enable = 1;
	erip->ngu_enable = ngu_enable;

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

	param_transceiver = NO_XCVR;

/*
 * The link speed may be forced to either 10 Mbps or 100 Mbps using the
 * property "transfer-speed". This may be done in OBP by using the command
 * "apply transfer-speed=<speed> <device>". The speed may be either 10 or 100.
 */
	i = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "transfer-speed", 0);
	if (i != 0) {
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
	param_ipg1 = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "ipg1", ipg1) &
	    ERI_MASK_8BIT;

	param_ipg2 = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "ipg2", ipg2) &
	    ERI_MASK_8BIT;

	param_use_intphy = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "use_int_xcvr", use_int_xcvr) & ERI_MASK_1BIT;

	param_use_intphy = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "pace_size", pace_size) & ERI_MASK_8BIT;

	param_autoneg = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_autoneg_cap", adv_autoneg_cap) & ERI_MASK_1BIT;

	param_autoneg = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_autoneg_cap", adv_autoneg_cap) & ERI_MASK_1BIT;

	param_anar_100T4 = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_100T4_cap", adv_100T4_cap) & ERI_MASK_1BIT;

	param_anar_100fdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_100fdx_cap", adv_100fdx_cap) & ERI_MASK_1BIT;

	param_anar_100hdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_100hdx_cap", adv_100hdx_cap) & ERI_MASK_1BIT;

	param_anar_10fdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_10fdx_cap", adv_10fdx_cap) & ERI_MASK_1BIT;

	param_anar_10hdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_10hdx_cap", adv_10hdx_cap) & ERI_MASK_1BIT;

	param_ipg0 = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "ipg0", ipg0) &
	    ERI_MASK_8BIT;

	param_intr_blank_time = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "intr_blank_time", intr_blank_time) & ERI_MASK_8BIT;

	param_intr_blank_packets = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "intr_blank_packets", intr_blank_packets) & ERI_MASK_8BIT;

	param_lance_mode = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "lance_mode", lance_mode) & ERI_MASK_1BIT;

	param_select_link = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "select_link", select_link) & ERI_MASK_1BIT;

	param_default_link = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "default_link", default_link) & ERI_MASK_1BIT;

	param_anar_asm_dir = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_asm_dir_cap", adv_pauseTX_cap) & ERI_MASK_1BIT;

	param_anar_pause = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_pause_cap", adv_pauseRX_cap) & ERI_MASK_1BIT;

	if (link_pulse_disabled)
		erip->link_pulse_disabled = 1;
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, 0, "link-pulse-disabled"))
		erip->link_pulse_disabled = 1;

	eri_statinit(erip);
	return (0);

}

static void
eri_process_ndd_ioctl(struct eri *erip, queue_t *wq, mblk_t *mp, int cmd)
{

	uint32_t old_ipg1, old_ipg2, old_use_int_xcvr, old_autoneg;
	uint32_t old_100T4;
	uint32_t old_100fdx, old_100hdx, old_10fdx, old_10hdx;
	uint32_t old_ipg0, old_lance_mode;
	uint32_t old_intr_blank_time, old_intr_blank_packets;
	uint32_t old_asm_dir, old_pause;
	uint32_t old_select_link, old_default_link;

	switch (cmd) {
	case ERI_ND_GET:

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

		qreply(wq, mp);
		break;

	case ERI_ND_SET:
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

		if (!eri_nd_getset(wq, erip->g_nd, mp)) {
			param_autoneg = old_autoneg;
			miocnak(wq, mp, 0, EINVAL);
			return;
		}

		qreply(wq, mp);

		if (param_autoneg != 0xff) {
			ERI_DEBUG_MSG2(erip, NDD_MSG,
			    "ndd_ioctl: new param_autoneg %d", param_autoneg);
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
			(void) eri_init(erip);
		} else {
			param_autoneg = old_autoneg;
			if ((old_use_int_xcvr != param_use_intphy) ||
			    (old_default_link != param_default_link) ||
			    (old_select_link != param_select_link)) {
				param_linkup = 0;
				erip->stats.link_up = LINK_STATE_DOWN;
				erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
				(void) eri_init(erip);
			} else if ((old_ipg1 != param_ipg1) ||
			    (old_ipg2 != param_ipg2) ||
			    (old_ipg0 != param_ipg0) ||
			    (old_intr_blank_time != param_intr_blank_time) ||
			    (old_intr_blank_packets !=
			    param_intr_blank_packets) ||
			    (old_lance_mode != param_lance_mode)) {
				param_linkup = 0;
				erip->stats.link_up = LINK_STATE_DOWN;
				erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
				(void) eri_init(erip);
			}
		}
		break;
	}
}


static int
eri_stat_kstat_update(kstat_t *ksp, int rw)
{
	struct eri *erip;
	struct erikstat *erikp;
	struct stats *esp;
	boolean_t macupdate = B_FALSE;

	erip = (struct eri *)ksp->ks_private;
	erikp = (struct erikstat *)ksp->ks_data;

	if (rw != KSTAT_READ)
		return (EACCES);
	/*
	 * Update all the stats by reading all the counter registers.
	 * Counter register stats are not updated till they overflow
	 * and interrupt.
	 */

	mutex_enter(&erip->xmitlock);
	if ((erip->flags & ERI_RUNNING) && (erip->flags & ERI_TXINIT)) {
		erip->tx_completion =
		    GET_ETXREG(tx_completion) & ETX_COMPLETION_MASK;
		macupdate |= eri_reclaim(erip, erip->tx_completion);
	}
	mutex_exit(&erip->xmitlock);
	if (macupdate)
		mac_tx_update(erip->mh);

	eri_savecntrs(erip);

	esp = &erip->stats;

	erikp->erik_txmac_maxpkt_err.value.ul = esp->txmac_maxpkt_err;
	erikp->erik_defer_timer_exp.value.ul = esp->defer_timer_exp;
	erikp->erik_peak_attempt_cnt.value.ul = esp->peak_attempt_cnt;
	erikp->erik_tx_hang.value.ul	= esp->tx_hang;

	erikp->erik_no_free_rx_desc.value.ul	= esp->no_free_rx_desc;

	erikp->erik_rx_hang.value.ul		= esp->rx_hang;
	erikp->erik_rx_length_err.value.ul	= esp->rx_length_err;
	erikp->erik_rx_code_viol_err.value.ul	= esp->rx_code_viol_err;
	erikp->erik_pause_rxcount.value.ul	= esp->pause_rxcount;
	erikp->erik_pause_oncount.value.ul	= esp->pause_oncount;
	erikp->erik_pause_offcount.value.ul	= esp->pause_offcount;
	erikp->erik_pause_time_count.value.ul	= esp->pause_time_count;

	erikp->erik_inits.value.ul		= esp->inits;
	erikp->erik_jab.value.ul		= esp->jab;
	erikp->erik_notmds.value.ul		= esp->notmds;
	erikp->erik_allocbfail.value.ul		= esp->allocbfail;
	erikp->erik_drop.value.ul		= esp->drop;
	erikp->erik_rx_bad_pkts.value.ul	= esp->rx_bad_pkts;
	erikp->erik_rx_inits.value.ul		= esp->rx_inits;
	erikp->erik_tx_inits.value.ul		= esp->tx_inits;
	erikp->erik_rxtag_err.value.ul		= esp->rxtag_err;
	erikp->erik_parity_error.value.ul	= esp->parity_error;
	erikp->erik_pci_error_int.value.ul	= esp->pci_error_int;
	erikp->erik_unknown_fatal.value.ul	= esp->unknown_fatal;
	erikp->erik_pci_data_parity_err.value.ul = esp->pci_data_parity_err;
	erikp->erik_pci_signal_target_abort.value.ul =
	    esp->pci_signal_target_abort;
	erikp->erik_pci_rcvd_target_abort.value.ul =
	    esp->pci_rcvd_target_abort;
	erikp->erik_pci_rcvd_master_abort.value.ul =
	    esp->pci_rcvd_master_abort;
	erikp->erik_pci_signal_system_err.value.ul =
	    esp->pci_signal_system_err;
	erikp->erik_pci_det_parity_err.value.ul = esp->pci_det_parity_err;

	erikp->erik_pmcap.value.ul = esp->pmcap;

	return (0);
}

static void
eri_statinit(struct eri *erip)
{
	struct	kstat	*ksp;
	struct	erikstat	*erikp;

	if ((ksp = kstat_create("eri", erip->instance, "driver_info", "net",
	    KSTAT_TYPE_NAMED,
	    sizeof (struct erikstat) / sizeof (kstat_named_t), 0)) == NULL) {
		ERI_FAULT_MSG1(erip, SEVERITY_LOW, ERI_VERB_MSG,
		    kstat_create_fail_msg);
		return;
	}

	erip->ksp = ksp;
	erikp = (struct erikstat *)(ksp->ks_data);
	/*
	 * MIB II kstat variables
	 */

	kstat_named_init(&erikp->erik_inits, "inits", KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_txmac_maxpkt_err,	"txmac_maxpkt_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_defer_timer_exp, "defer_timer_exp",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_peak_attempt_cnt,	"peak_attempt_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_tx_hang, "tx_hang", KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_no_free_rx_desc, "no_free_rx_desc",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_hang, "rx_hang", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_length_err, "rx_length_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_rx_code_viol_err,	"rx_code_viol_err",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pause_rxcount, "pause_rcv_cnt",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pause_oncount, "pause_on_cnt",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pause_offcount, "pause_off_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_pause_time_count,	"pause_time_cnt",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_jab, "jabber", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_notmds, "no_tmds", KSTAT_DATA_ULONG);
	kstat_named_init(&erikp->erik_allocbfail, "allocbfail",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_drop, "drop", KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rx_bad_pkts, "bad_pkts",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rx_inits, "rx_inits", KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_tx_inits, "tx_inits", KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_rxtag_err, "rxtag_error",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_parity_error, "parity_error",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&erikp->erik_pci_error_int, "pci_error_interrupt",
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

	kstat_named_init(&erikp->erik_pmcap, "pmcap", KSTAT_DATA_ULONG);


	ksp->ks_update = eri_stat_kstat_update;
	ksp->ks_private = (void *) erip;
	kstat_install(ksp);
}


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
	param_t		*eripa = (void *)cp;
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
static int
eri_param_register(struct eri *erip, param_t *eripa, int cnt)
{
	/* cnt gives the count of the number of */
	/* elements present in the parameter array */

	int i;

	for (i = 0; i < cnt; i++, eripa++) {
		pfi_t	setter = (pfi_t)eri_param_set;

		switch (eripa->param_name[0]) {
		case '+':	/* read-write */
			setter = (pfi_t)eri_param_set;
			break;

		case '-':	/* read-only */
			setter = NULL;
			break;

		case '!':	/* read-only, not displayed */
		case '%':	/* read-write, not displayed */
			continue;
		}

		if (!eri_nd_load(&erip->g_nd, eripa->param_name + 1,
		    (pfi_t)eri_param_get, setter, (caddr_t)eripa)) {
			(void) eri_nd_free(&erip->g_nd);
			return (B_FALSE);
		}
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
	long new_value;
	param_t	*eripa = (void *)cp;

	if (ddi_strtol(value, &end, 10, &new_value) != 0)
		return (EINVAL);
	if (end == value || new_value < eripa->param_min ||
	    new_value > eripa->param_max) {
			return (EINVAL);
	}
	eripa->param_val = (uint32_t)new_value;
	return (0);

}

/* Free the table pointed to by 'ndp' */
static void
eri_nd_free(caddr_t *nd_pparam)
{
	ND	*nd;

	if ((nd = (void *)(*nd_pparam)) != NULL) {
		if (nd->nd_tbl)
			kmem_free(nd->nd_tbl, nd->nd_size);
		kmem_free(nd, sizeof (ND));
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

	nd = (void *)nd_param;
	iocp = (void *)mp->b_rptr;
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
			(void) ddi_strtol(valp, NULL, 10, (long *)&avail);
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
					iocp->ioc_rval = (unsigned)size_out;
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
			err = (*nde->nde_set_pfi)(q, mp1, valp,
			    nde->nde_data, iocp->ioc_cr);
			iocp->ioc_count = 0;
			freemsg(mp1);
			mp->b_cont = NULL;
		}
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

	if ((nd = (void *)(*nd_pparam)) == NULL) {
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
/*PRINTFLIKE5*/
static void
eri_debug_msg(const char *file, int line, struct eri *erip,
    debug_msg_t type, const char *fmt, ...)
{
	char	msg_buffer[255];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);
	va_end(ap);

	if (eri_msg_out & ERI_CON_MSG) {
		if (((type <= eri_debug_level) && eri_debug_all) ||
		    ((type == eri_debug_level) && !eri_debug_all)) {
			if (erip)
				cmn_err(CE_CONT, "D: %s %s%d:(%s%d) %s\n",
				    debug_msg_string[type], file, line,
				    ddi_driver_name(erip->dip), erip->instance,
				    msg_buffer);
			else
				cmn_err(CE_CONT, "D: %s %s(%d): %s\n",
				    debug_msg_string[type], file,
				    line, msg_buffer);
		}
	}
}
#endif


/*PRINTFLIKE4*/
static void
eri_fault_msg(struct eri *erip, uint_t severity, msg_t type,
	const char *fmt, ...)
{
	char	msg_buffer[255];
	va_list	ap;

	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);
	va_end(ap);

	if (erip == NULL) {
		cmn_err(CE_NOTE, "eri : %s", msg_buffer);
		return;
	}

	if (severity == SEVERITY_HIGH) {
		cmn_err(CE_WARN, "%s%d : %s", ddi_driver_name(erip->dip),
		    erip->instance, msg_buffer);
	} else switch (type) {
	case ERI_VERB_MSG:
		cmn_err(CE_CONT, "?%s%d : %s", ddi_driver_name(erip->dip),
		    erip->instance, msg_buffer);
		break;
	case ERI_LOG_MSG:
		cmn_err(CE_NOTE, "^%s%d : %s", ddi_driver_name(erip->dip),
		    erip->instance, msg_buffer);
		break;
	case ERI_BUF_MSG:
		cmn_err(CE_NOTE, "!%s%d : %s", ddi_driver_name(erip->dip),
		    erip->instance, msg_buffer);
		break;
	case ERI_CON_MSG:
		cmn_err(CE_CONT, "%s%d : %s", ddi_driver_name(erip->dip),
		    erip->instance, msg_buffer);
	default:
		break;
	}
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
	ERI_DEBUG_MSG2(erip, MIF_MSG, "cfg value = %X", cfg);
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
 * This function is used for timers.  No locks are held on timer expiry.
 */
static void
eri_check_link(struct eri *erip)
{
	link_state_t	linkupdate = eri_check_link_noind(erip);

	if (linkupdate != LINK_STATE_UNKNOWN)
		mac_link_update(erip->mh, linkupdate);
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
static uint32_t
eri_check_link_noind(struct eri *erip)
{
	uint16_t stat, control, mif_ints;
	uint32_t link_timeout	= ERI_LINKCHECK_TIMER;
	uint32_t linkupdate = 0;

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
				erip->stats.ifspeed = 10;

			} else {
				control |= PHY_BMCR_100M;
				param_anlpar_100hdx = 1;
				param_anlpar_10hdx = 0;
				param_speed = 1;
				erip->stats.ifspeed = 100;
			}
			ERI_DEBUG_MSG3(erip, XCVR_MSG,
			    "eri_check_link: trying speed %X stat %X",
			    param_speed, stat);

			erip->openloop_autoneg ++;
			eri_mii_write(erip, ERI_PHY_BMCR, control);
			link_timeout = ERI_P_FAULT_TIMER;
		} else {
			erip->openloop_autoneg = 0;
			linkupdate = eri_mif_check(erip, stat, stat);
			if (erip->openloop_autoneg)
				link_timeout = ERI_P_FAULT_TIMER;
		}
		eri_mif_poll(erip, MIF_POLL_START);
		mutex_exit(&erip->xcvrlock);
		mutex_exit(&erip->xmitlock);

		eri_start_timer(erip, eri_check_link, link_timeout);
		return (linkupdate);
	}

	linkupdate = eri_mif_check(erip, mif_ints, stat);
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
			return (linkupdate);
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
				return (linkupdate);
			}
		}
	}
#endif

	/*
	 * Check if tx hung.
	 */
#ifdef	ERI_TX_HUNG
	if ((erip->flags & ERI_RUNNING) && param_linkup &&
	    (eri_check_txhung(erip))) {
		HSTAT(erip, tx_hang);
		eri_reinit_txhung++;
		erip->linkcheck = 1;
		eri_start_timer(erip, eri_check_link, ERI_CHECK_HANG_TIMER);
		(void) eri_init(erip);
		return (linkupdate);
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
	return (linkupdate);
}

static link_state_t
eri_mif_check(struct eri *erip, uint16_t mif_ints, uint16_t mif_data)
{
	uint16_t control, aner, anlpar, anar, an_common;
	uint16_t old_mintrans;
	int restart_autoneg = 0;
	link_state_t retv;

	ERI_DEBUG_MSG4(erip, XCVR_MSG, "eri_mif_check: mif_mask: %X, %X, %X",
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
		return (LINK_STATE_UNKNOWN);
	}

	if (param_autoneg && (mif_ints & PHY_BMSR_LNKSTS) &&
	    (mif_data & PHY_BMSR_LNKSTS) && (mif_data & PHY_BMSR_ANC)) {
		mif_ints |= PHY_BMSR_ANC;
		ERI_DEBUG_MSG3(erip, PHY_MSG,
		    "eri_mif_check: Set ANC bit mif_data %X mig_ints %X",
		    mif_data, mif_ints);
	}

	if ((mif_ints & PHY_BMSR_ANC) && (mif_data & PHY_BMSR_ANC)) {
		ERI_DEBUG_MSG1(erip, PHY_MSG, "Auto-negotiation interrupt.");

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
				erip->stats.ifspeed = 100;

			} else if (param_anar_10fdx || param_anar_10hdx) {
				control &= ~PHY_BMCR_100M;
				param_anlpar_100hdx = 0;
				param_anlpar_10hdx = 1;
				param_speed = 0;
				erip->stats.ifspeed = 10;
			} else {
				ERI_FAULT_MSG1(erip, SEVERITY_NONE,
				    ERI_VERB_MSG,
				    "Transceiver speed set incorrectly.");
				return (0);
			}

			(void) eri_mii_write(erip, ERI_PHY_BMCR, control);
			param_anlpar_100fdx = 0;
			param_anlpar_10fdx = 0;
			param_mode = 0;
			erip->openloop_autoneg = 1;
			return (0);
		}
		(void) eri_mii_read(erip, ERI_PHY_ANLPAR, &anlpar);
		(void) eri_mii_read(erip, ERI_PHY_ANAR, &anar);
		an_common = anar & anlpar;

		ERI_DEBUG_MSG2(erip, XCVR_MSG, "an_common = 0x%X", an_common);

		if (an_common & (PHY_ANLPAR_TXFDX | PHY_ANLPAR_TX)) {
			param_speed = 1;
			erip->stats.ifspeed = 100;
			param_mode = 1 && (an_common & PHY_ANLPAR_TXFDX);

		} else if (an_common & (PHY_ANLPAR_10FDX | PHY_ANLPAR_10)) {
			param_speed = 0;
			erip->stats.ifspeed = 10;
			param_mode = 1 && (an_common & PHY_ANLPAR_10FDX);

		} else an_common = 0x0;

		if (!an_common) {
			ERI_FAULT_MSG1(erip, SEVERITY_MID, ERI_VERB_MSG,
			    "Transceiver: anar not set with speed selection");
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
	retv = LINK_STATE_UNKNOWN;
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
			erip->stats.link_up = LINK_STATE_UP;
			if (param_mode)
				erip->stats.link_duplex = LINK_DUPLEX_FULL;
			else
				erip->stats.link_duplex = LINK_DUPLEX_HALF;

			retv = LINK_STATE_UP;
		} else {
			ERI_DEBUG_MSG1(erip, PHY_MSG, "Link down.");
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
			retv = LINK_STATE_DOWN;
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
				erip->stats.link_up = LINK_STATE_UP;
				if (param_mode)
					erip->stats.link_duplex =
					    LINK_DUPLEX_FULL;
				else
					erip->stats.link_duplex =
					    LINK_DUPLEX_HALF;

				retv = LINK_STATE_UP;
			}
		} else if (param_linkup) {
			/*
			 * The link is down now.
			 */
			ERI_DEBUG_MSG1(erip, PHY_MSG,
			    "eri_mif_check:Link was up and went down");
			param_linkup = 0;
			erip->stats.link_up = LINK_STATE_DOWN;
			erip->stats.link_duplex = LINK_DUPLEX_UNKNOWN;
			retv = LINK_STATE_DOWN;
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
		(void) eri_mii_read(erip, ERI_PHY_BMCR, &control);
		control |= (PHY_BMCR_ANE | PHY_BMCR_RAN);
		eri_mii_write(erip, ERI_PHY_BMCR, control);
	}
	if (mif_ints & PHY_BMSR_JABDET) {
		if (mif_data & PHY_BMSR_JABDET) {
			ERI_DEBUG_MSG1(erip, PHY_MSG, "Jabber detected.");
			HSTAT(erip, jab);
			/*
			 * Reset the new PHY and bring up the link
			 * (Check for failure?)
			 */
			(void) eri_reset_xcvr(erip);
		}
	}
	return (retv);
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
	    "eri_reset_xcvr:reset_failed n == 0, control %x", control);
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
	    "eri_reset_xcvr: control %x stat %x anar %x", control, stat, anar);

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
		ERI_DEBUG_MSG2(erip, XCVR_MSG, "anar = %x", anar);
		eri_mii_write(erip, ERI_PHY_ANAR, anar);
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
	    "eri_reset_xcvr: speed_100 %d speed_10 %d", speed_100, speed_10);

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
			erip->stats.link_up = LINK_STATE_UP;
			if (param_mode)
				erip->stats.link_duplex = LINK_DUPLEX_FULL;
			else
				erip->stats.link_duplex = LINK_DUPLEX_HALF;
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
			erip->stats.ifspeed = 100;
			param_mode = param_anar_100fdx;
			if (param_mode) {
				param_anlpar_100hdx = 0;
				erip->stats.link_duplex = LINK_DUPLEX_FULL;
			} else {
				erip->stats.link_duplex = LINK_DUPLEX_HALF;
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
			erip->stats.ifspeed = 10;
			param_mode = param_anar_10fdx;
			if (param_mode) {
				param_anlpar_10hdx = 0;
				erip->stats.link_duplex = LINK_DUPLEX_FULL;
			} else {
				erip->stats.link_duplex = LINK_DUPLEX_HALF;
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

	if (!param_autoneg && !param_linkup && (erip->stats.ifspeed == 10) &&
	    (param_anar_10fdx | param_anar_10hdx)) {
		*link_timeout = SECOND(1);
		return;
	}

	if (!param_autoneg && !param_linkup && (erip->ifspeed_old == 10) &&
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
eri_mif_poll(struct eri *erip, soft_mif_enable_t enable)
{
	if (enable == MIF_POLL_START) {
		if (erip->mifpoll_enable && !erip->openloop_autoneg) {
			erip->mif_config |= ERI_MIF_CFGPE;
			PUT_MIFREG(mif_cfg, erip->mif_config);
			drv_usecwait(ERI_MIF_POLL_DELAY);
			PUT_GLOBREG(intmask, GET_GLOBREG(intmask) &
			    ~ERI_G_MASK_MIF_INT);
			PUT_MIFREG(mif_imask, erip->mif_mask);
		}
	} else if (enable == MIF_POLL_STOP) {
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

/* Decide if transmitter went dead and reinitialize everything */
#ifdef	ERI_TX_HUNG
static int eri_txhung_limit = 2;
static int
eri_check_txhung(struct eri *erip)
{
	boolean_t	macupdate = B_FALSE;

	mutex_enter(&erip->xmitlock);
	if (erip->flags & ERI_RUNNING)
		erip->tx_completion = (uint32_t)(GET_ETXREG(tx_completion) &
		    ETX_COMPLETION_MASK);
		macupdate |= eri_reclaim(erip, erip->tx_completion);

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

	if (macupdate)
		mac_tx_update(erip->mh);

	return (erip->txhung >= eri_txhung_limit);
}
#endif

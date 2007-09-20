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

#ifndef _RGE_H
#define	_RGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/errno.h>
#include <sys/dlpi.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/conf.h>

#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/pattr.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/mac.h>
#include <sys/mac_ether.h>

/*
 * Reconfiguring the network devices requires the net_config privilege
 * in Solaris 10+.
 */
extern int secpolicy_net_config(const cred_t *, boolean_t);

#include <sys/netlb.h>			/* originally from cassini	*/
#include <sys/miiregs.h>		/* by fjlite out of intel 	*/

#include "rge_hw.h"

/*
 * Name of the driver
 */
#define	RGE_DRIVER_NAME		"rge"

/*
 * The driver supports the NDD ioctls ND_GET/ND_SET, and the loopback
 * ioctls LB_GET_INFO_SIZE/LB_GET_INFO/LB_GET_MODE/LB_SET_MODE
 *
 * These are the values to use with LD_SET_MODE.
 */
#define	RGE_LOOP_NONE		0
#define	RGE_LOOP_INTERNAL_PHY	1
#define	RGE_LOOP_INTERNAL_MAC	2

/*
 * RGE-specific ioctls ...
 */
#define	RGE_IOC			((((('R' << 8) + 'G') << 8) + 'E') << 8)

/*
 * PHY register read/write ioctls, used by cable test software
 */
#define	RGE_MII_READ		(RGE_IOC|1)
#define	RGE_MII_WRITE		(RGE_IOC|2)

struct rge_mii_rw {
	uint32_t	mii_reg;	/* PHY register number [0..31]	*/
	uint32_t	mii_data;	/* data to write/data read	*/
};

/*
 * These diagnostic IOCTLS are enabled only in DEBUG drivers
 */
#define	RGE_DIAG		(RGE_IOC|10)	/* currently a no-op	*/
#define	RGE_PEEK		(RGE_IOC|11)
#define	RGE_POKE		(RGE_IOC|12)
#define	RGE_PHY_RESET		(RGE_IOC|13)
#define	RGE_SOFT_RESET		(RGE_IOC|14)
#define	RGE_HARD_RESET		(RGE_IOC|15)

typedef struct {
	uint64_t		pp_acc_size;	/* in bytes: 1,2,4,8	*/
	uint64_t		pp_acc_space;	/* See #defines below	*/
	uint64_t		pp_acc_offset;
	uint64_t		pp_acc_data;	/* output for peek	*/
						/* input for poke	*/
} rge_peekpoke_t;

#define	RGE_PP_SPACE_CFG	0		/* PCI config space	*/
#define	RGE_PP_SPACE_REG	1		/* PCI memory space	*/
#define	RGE_PP_SPACE_MII	2		/* PHY's MII registers	*/
#define	RGE_PP_SPACE_RGE	3		/* driver's soft state	*/
#define	RGE_PP_SPACE_TXDESC	4		/* TX descriptors	*/
#define	RGE_PP_SPACE_TXBUFF	5		/* TX buffers		*/
#define	RGE_PP_SPACE_RXDESC	6		/* RX descriptors	*/
#define	RGE_PP_SPACE_RXBUFF	7		/* RX buffers		*/
#define	RGE_PP_SPACE_STATISTICS	8		/* statistics block	*/

/*
 * RTL8169 CRC poly
 */
#define	RGE_HASH_POLY		0x04C11DB7	/* 0x04C11DB6 */
#define	RGE_HASH_CRC		0xFFFFFFFFU
#define	RGE_MCAST_BUF_SIZE	64	/* multicast hash table size in bits */

/*
 * Rx/Tx buffer parameters
 */
#define	RGE_BUF_SLOTS		2048
#define	RGE_RECV_COPY_SIZE	256
#define	RGE_HEADROOM		6

/*
 * Driver chip operation parameters
 */
#define	RGE_CYCLIC_PERIOD	(1000000000)	/* ~1s */
#define	CHIP_RESET_LOOP		1000
#define	PHY_RESET_LOOP		10
#define	STATS_DUMP_LOOP		1000
#define	RXBUFF_FREE_LOOP	1000
#define	RGE_RX_INT_TIME		128
#define	RGE_RX_INT_PKTS		8

/*
 * Named Data (ND) Parameter Management Structure
 */
typedef struct {
	int			ndp_info;
	int			ndp_min;
	int			ndp_max;
	int			ndp_val;
	char			*ndp_name;
} nd_param_t;				/* 0x18 (24) bytes	*/

/*
 * NDD parameter indexes, divided into:
 *
 *	read-only parameters describing the hardware's capabilities
 *	read-write parameters controlling the advertised capabilities
 *	read-only parameters describing the partner's capabilities
 *	read-only parameters describing the link state
 */
enum {
	PARAM_AUTONEG_CAP = 0,
	PARAM_PAUSE_CAP,
	PARAM_ASYM_PAUSE_CAP,
	PARAM_1000FDX_CAP,
	PARAM_1000HDX_CAP,
	PARAM_100T4_CAP,
	PARAM_100FDX_CAP,
	PARAM_100HDX_CAP,
	PARAM_10FDX_CAP,
	PARAM_10HDX_CAP,

	PARAM_ADV_AUTONEG_CAP,
	PARAM_ADV_PAUSE_CAP,
	PARAM_ADV_ASYM_PAUSE_CAP,
	PARAM_ADV_1000FDX_CAP,
	PARAM_ADV_1000HDX_CAP,
	PARAM_ADV_100T4_CAP,
	PARAM_ADV_100FDX_CAP,
	PARAM_ADV_100HDX_CAP,
	PARAM_ADV_10FDX_CAP,
	PARAM_ADV_10HDX_CAP,

	PARAM_LINK_STATUS,
	PARAM_LINK_SPEED,
	PARAM_LINK_DUPLEX,

	PARAM_LOOP_MODE,

	PARAM_COUNT
};

enum rge_chip_state {
	RGE_CHIP_FAULT = -2,			/* fault, need reset	*/
	RGE_CHIP_ERROR,				/* error, want reset	*/
	RGE_CHIP_INITIAL,			/* Initial state only	*/
	RGE_CHIP_RESET,				/* reset, need init	*/
	RGE_CHIP_STOPPED,			/* Tx/Rx stopped	*/
	RGE_CHIP_RUNNING			/* with interrupts	*/
};

enum rge_mac_state {
	RGE_MAC_ATTACH = 0,
	RGE_MAC_STOPPED,
	RGE_MAC_STARTED,
	RGE_MAC_UNATTACH
};

enum rge_sync_op {
	RGE_OP_NULL,
	RGE_GET_MAC,				/* get mac address operation */
	RGE_SET_MAC,				/* set mac address operation */
	RGE_SET_MUL,				/* set multicast address op */
	RGE_SET_PROMISC				/* set promisc mode */
};

/*
 * (Internal) return values from ioctl subroutines
 */
enum ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_RESTART_ACK,			/* OK, restart & ACK	*/
	IOC_RESTART_REPLY			/* OK, restart & reply	*/
};

/*
 * (Internal) enumeration of this driver's kstats
 */
enum {
	RGE_KSTAT_DRIVER = 0,
	RGE_KSTAT_COUNT
};

/*
 * Basic data types, for clarity in distinguishing 'numbers'
 * used for different purposes ...
 *
 * A <rge_regno_t> is a register 'address' (offset) in any one of
 * various address spaces (PCI config space, PCI memory-mapped I/O
 * register space, MII registers, etc).  None of these exceeds 64K,
 * so we could use a 16-bit representation but pointer-sized objects
 * are more "natural" in most architectures; they seem to be handled
 * more efficiently on SPARC and no worse on x86.
 *
 * RGE_REGNO_NONE represents the non-existent value in this space.
 */
typedef uintptr_t rge_regno_t;			/* register # (offset)	*/
#define	RGE_REGNO_NONE		(~(uintptr_t)0u)

/*
 * Describes one chunk of allocated DMA-able memory
 *
 * In some cases, this is a single chunk as allocated from the system;
 * but we also use this structure to represent slices carved off such
 * a chunk.  Even when we don't really need all the information, we
 * use this structure as a convenient way of correlating the various
 * ways of looking at a piece of memory (kernel VA, IO space DVMA,
 * handle+offset, etc).
 */
typedef struct {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory	*/
	void			*mem_va;	/* CPU VA of memory	*/
	uint32_t		nslots;		/* number of slots	*/
	uint32_t		size;		/* size per slot	*/
	size_t			alength;	/* allocated size */
	ddi_dma_handle_t	dma_hdl;	/* DMA handle */
	offset_t		offset;		/* relative to handle	*/
	ddi_dma_cookie_t	cookie;		/* associated cookie */
	uint32_t		ncookies;	/* must be 1 */
	uint32_t		token;		/* arbitrary identifier	*/
} dma_area_t;

/*
 * Software version of the Receive Buffer Descriptor
 */
typedef struct {
	caddr_t			private;	/* pointer to rge */
	dma_area_t		pbuf;		/* (const) related	*/
						/* buffer area		*/
	frtn_t			rx_recycle;	/* recycle function */
	mblk_t			*mp;
} dma_buf_t;

typedef struct sw_rbd {
	dma_buf_t		*rx_buf;
	uint8_t			flags;
} sw_rbd_t;

/*
 * Software version of the Send Buffer Descriptor
 */
typedef struct sw_sbd {
	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	dma_area_t		pbuf;		/* (const) related	*/
						/* buffer area		*/
} sw_sbd_t;


#define	HW_RBD_INIT(rbd, slot)					\
	rbd->flags_len |= RGE_BSWAP_32(BD_FLAG_HW_OWN);		\
	rbd->vlan_tag = 0;					\
	if (slot == (RGE_RECV_SLOTS -1))			\
		rbd->flags_len |= RGE_BSWAP_32(BD_FLAG_EOR);
#define	HW_SBD_INIT(sbd, slot)					\
	sbd->flags_len = 0;					\
	if (slot == (RGE_SEND_SLOTS -1))			\
		sbd->flags_len |= RGE_BSWAP_32(BD_FLAG_EOR);
#define	HW_SBD_SET(sbd, slot)					\
	sbd->flags_len |= RGE_BSWAP_32(SBD_FLAG_TX_PKT);	\
	if (slot == (RGE_SEND_SLOTS -1))			\
		sbd->flags_len |= RGE_BSWAP_32(BD_FLAG_EOR);

/*
 * Describes the characteristics of a specific chip
 */
typedef struct {
	uint16_t		command;	/* saved during attach	*/
	uint16_t		vendor;		/* vendor-id		*/
	uint16_t		device;		/* device-id		*/
	uint16_t		subven;		/* subsystem-vendor-id	*/
	uint16_t		subdev;		/* subsystem-id		*/
	uint8_t			revision;	/* revision-id		*/
	uint8_t			clsize;		/* cache-line-size	*/
	uint8_t			latency;	/* latency-timer	*/
	boolean_t		is_pcie;
	uint32_t		mac_ver;
	uint32_t		phy_ver;
	uint32_t		rxconfig;
	uint32_t		txconfig;
} chip_id_t;

typedef struct rge_stats {
	uint64_t	rbytes;
	uint64_t	obytes;
	uint32_t	overflow;
	uint32_t	defer;		/* dot3StatsDeferredTransmissions */
	uint32_t	crc_err;	/* dot3StatsFCSErrors */
	uint32_t	in_short;
	uint32_t	no_rcvbuf;	/* ifInDiscards */
	uint32_t	intr;		/* interrupt count */
	uint16_t	chip_reset;
	uint16_t	phy_reset;
} rge_stats_t;

/*
 * Per-instance soft-state structure
 */
typedef struct rge {
	dev_info_t		*devinfo;	/* device instance	*/
	mac_handle_t		mh;		/* mac module handle	*/
	ddi_acc_handle_t	cfg_handle;	/* DDI I/O handle	*/
	ddi_acc_handle_t	io_handle;	/* DDI I/O handle	*/
	caddr_t			io_regs;	/* mapped registers	*/
	ddi_periodic_t		periodic_id;	/* periodical callback	*/
	ddi_softint_handle_t	resched_hdl;	/* reschedule callback	*/
	ddi_softint_handle_t	factotum_hdl;	/* factotum callback	*/
	uint_t			soft_pri;
	ddi_intr_handle_t 	*htable;	/* For array of interrupts */
	int			intr_type;	/* What type of interrupt */
	int			intr_rqst;	/* # of request intrs count */
	int			intr_cnt;	/* # of intrs count returned */
	uint_t			intr_pri;	/* Interrupt priority	*/
	int			intr_cap;	/* Interrupt capabilities */
	boolean_t		msi_enable;

	uint32_t		ethmax_size;
	uint32_t		default_mtu;
	uint32_t		rxbuf_size;
	uint32_t		txbuf_size;
	uint32_t		chip_flags;
	uint32_t		head_room;
	char			ifname[8];	/* "rge0" ... "rge999"	*/
	int32_t			instance;
	uint32_t		progress;	/* attach tracking	*/
	uint32_t		debug;		/* per-instance debug	*/
	chip_id_t		chipid;

	/*
	 * These structures describe the blocks of memory allocated during
	 * attach().  They remain unchanged thereafter, although the memory
	 * they describe is carved up into various separate regions and may
	 * therefore be described by other structures as well.
	 */
	dma_area_t		dma_area_rxdesc;
	dma_area_t		dma_area_txdesc;
	dma_area_t		dma_area_stats;
				/* describes hardware statistics area	*/

	uint8_t			netaddr[ETHERADDRL];	/* mac address	*/
	uint16_t		int_mask;	/* interrupt mask	*/

	/* used for multicast/promisc mode set */
	char			mcast_refs[RGE_MCAST_BUF_SIZE];
	uint8_t			mcast_hash[RGE_MCAST_NUM];
	boolean_t		promisc;	/* promisc state flag	*/

	/* used for recv */
	rge_bd_t		*rx_ring;
	dma_area_t		rx_desc;
	boolean_t		rx_bcopy;
	uint32_t		rx_next;	/* current rx bd index	*/
	sw_rbd_t		*sw_rbds;
	sw_rbd_t		*free_srbds;
	uint32_t		rf_next;	/* current free buf index */
	uint32_t		rc_next;	/* current recycle buf index */
	uint32_t		rx_free;	/* number of rx free buf */
	mac_resource_handle_t	handle;

	/* used for send */
	rge_bd_t		*tx_ring;
	dma_area_t		tx_desc;
	uint32_t		tx_free;	/* number of free tx bd */
	uint32_t		tx_next;	/* current tx bd index	*/
	uint32_t		tc_next;	/* current tx recycle index */
	uint32_t		tx_flow;
	uint32_t		tc_tail;
	sw_sbd_t		*sw_sbds;

	/* mutex */
	kmutex_t		genlock[1];	/* i/o reg access	*/
	krwlock_t		errlock[1];	/* rge restart */
	kmutex_t		tx_lock[1];	/* send access		*/
	kmutex_t		tc_lock[1];	/* send recycle access */
	kmutex_t		rx_lock[1];	/* receive access	*/
	kmutex_t		rc_lock[1];	/* receive recycle access */

	/*
	 * Miscellaneous operating variables (not synchronised)
	 */
	uint32_t		watchdog;	/* watches for Tx stall	*/
	boolean_t		resched_needed;
	uint32_t		factotum_flag;	/* softint pending	*/

	/*
	 * Physical layer
	 */
	rge_regno_t		phy_mii_addr;	/* should be (const) 1!	*/
	uint16_t		link_down_count;

	/*
	 * NDD parameters (protected by genlock)
	 */
	caddr_t			nd_data_p;
	nd_param_t		nd_params[PARAM_COUNT];

	/*
	 * Driver kstats, protected by <genlock> where necessary
	 */
	kstat_t			*rge_kstats[RGE_KSTAT_COUNT];

	/* H/W statistics */
	rge_hw_stats_t		*hw_stats;
	rge_stats_t		stats;
	enum rge_mac_state	rge_mac_state;	/* definitions above	*/
	enum rge_chip_state	rge_chip_state;	/* definitions above	*/
} rge_t;

/*
 * 'Progress' bit flags ...
 */
#define	PROGRESS_CFG		0x0001	/* config space mapped		*/
#define	PROGRESS_REGS		0x0002	/* registers mapped		*/
#define	PROGRESS_RESCHED	0x0010	/* resched softint registered	*/
#define	PROGRESS_FACTOTUM	0x0020	/* factotum softint registered	*/
#define	PROGRESS_INTR		0X0040	/* h/w interrupt registered	*/
					/* and mutexen initialised	*/
#define	PROGRESS_INIT		0x0080	/* rx/buf/tx ring initialised	*/
#define	PROGRESS_PHY		0x0100	/* PHY initialised		*/
#define	PROGRESS_NDD		0x1000	/* NDD parameters set up	*/
#define	PROGRESS_KSTATS		0x2000	/* kstats created		*/
#define	PROGRESS_READY		0x8000	/* ready for work		*/

/*
 * Special chip flags
 */
#define	CHIP_FLAG_FORCE_BCOPY	0x10000000

/*
 * Shorthand for the NDD parameters
 */
#define	param_adv_autoneg	nd_params[PARAM_ADV_AUTONEG_CAP].ndp_val
#define	param_adv_pause		nd_params[PARAM_ADV_PAUSE_CAP].ndp_val
#define	param_adv_asym_pause	nd_params[PARAM_ADV_ASYM_PAUSE_CAP].ndp_val
#define	param_adv_1000fdx	nd_params[PARAM_ADV_1000FDX_CAP].ndp_val
#define	param_adv_1000hdx	nd_params[PARAM_ADV_1000HDX_CAP].ndp_val
#define	param_adv_100fdx	nd_params[PARAM_ADV_100FDX_CAP].ndp_val
#define	param_adv_100hdx	nd_params[PARAM_ADV_100HDX_CAP].ndp_val
#define	param_adv_10fdx		nd_params[PARAM_ADV_10FDX_CAP].ndp_val
#define	param_adv_10hdx		nd_params[PARAM_ADV_10HDX_CAP].ndp_val

#define	param_link_up		nd_params[PARAM_LINK_STATUS].ndp_val
#define	param_link_speed	nd_params[PARAM_LINK_SPEED].ndp_val
#define	param_link_duplex	nd_params[PARAM_LINK_DUPLEX].ndp_val

#define	param_loop_mode		nd_params[PARAM_LOOP_MODE].ndp_val

/*
 * Sync a DMA area described by a dma_area_t
 */
#define	DMA_SYNC(area, flag)	((void) ddi_dma_sync((area).dma_hdl,	\
				    (area).offset, (area).alength, (flag)))

/*
 * Find the (kernel virtual) address of block of memory
 * described by a dma_area_t
 */
#define	DMA_VPTR(area)		((area).mem_va)

/*
 * Zero a block of memory described by a dma_area_t
 */
#define	DMA_ZERO(area)		bzero(DMA_VPTR(area), (area).alength)

/*
 * Next/Last value of a cyclic index
 */
#define	NEXT(index, limit)	((index)+1 < (limit) ? (index)+1 : 0);
#define	LAST(index, limit)	((index) ? (index)-1 : (limit - 1));
/*
 * Property lookups
 */
#define	RGE_PROP_EXISTS(d, n)	ddi_prop_exists(DDI_DEV_T_ANY, (d),	\
					DDI_PROP_DONTPASS, (n))
#define	RGE_PROP_GET_INT(d, n)	ddi_prop_get_int(DDI_DEV_T_ANY, (d),	\
					DDI_PROP_DONTPASS, (n), -1)

/*
 * Endian swap
 */
#ifdef	_BIG_ENDIAN
#define	RGE_BSWAP_16(x)		((((x) & 0xff00) >> 8)	|		\
				    (((x) & 0x00ff) << 8))
#define	RGE_BSWAP_32(x)		((((x) & 0xff000000) >> 24)	|	\
				    (((x) & 0x00ff0000) >> 8)	|	\
				    (((x) & 0x0000ff00) << 8)	|	\
				    (((x) & 0x000000ff) << 24))
#define	RGE_BSWAP_64(x)		(RGE_BSWAP_32((x) >> 32)	|	\
				    (RGE_BSWAP_32(x) << 32))
#else
#define	RGE_BSWAP_16(x)		(x)
#define	RGE_BSWAP_32(x)		(x)
#define	RGE_BSWAP_64(x)		(x)
#endif

/*
 * Bit test macros, returning boolean_t values
 */
#define	BIS(w, b)	(((w) & (b)) ? B_TRUE : B_FALSE)
#define	BIC(w, b)	(((w) & (b)) ? B_FALSE : B_TRUE)
#define	UPORDOWN(x)	((x) ? "up" : "down")

/*
 * Bit flags in the 'debug' word ...
 */
#define	RGE_DBG_STOP		0x00000001	/* early debug_enter()	*/
#define	RGE_DBG_TRACE		0x00000002	/* general flow tracing	*/

#define	RGE_DBG_REGS		0x00000010	/* low-level accesses	*/
#define	RGE_DBG_MII		0x00000020	/* low-level MII access	*/
#define	RGE_DBG_SEEPROM		0x00000040	/* low-level SEEPROM IO	*/
#define	RGE_DBG_CHIP		0x00000080	/* low(ish)-level code	*/

#define	RGE_DBG_RECV		0x00000100	/* receive-side code	*/
#define	RGE_DBG_SEND		0x00000200	/* packet-send code	*/

#define	RGE_DBG_INT		0x00001000	/* interrupt handler	*/
#define	RGE_DBG_FACT		0x00002000	/* factotum (softint)	*/

#define	RGE_DBG_PHY		0x00010000	/* Copper PHY code	*/
#define	RGE_DBG_SERDES		0x00020000	/* SerDes code		*/
#define	RGE_DBG_PHYS		0x00040000	/* Physical layer code	*/
#define	RGE_DBG_LINK		0x00080000	/* Link status check	*/

#define	RGE_DBG_INIT		0x00100000	/* initialisation	*/
#define	RGE_DBG_NEMO		0x00200000	/* nemo interaction	*/
#define	RGE_DBG_ADDR		0x00400000	/* address-setting code	*/
#define	RGE_DBG_STATS		0x00800000	/* statistics		*/

#define	RGE_DBG_IOCTL		0x01000000	/* ioctl handling	*/
#define	RGE_DBG_LOOP		0x02000000	/* loopback ioctl code	*/
#define	RGE_DBG_PPIO		0x04000000	/* Peek/poke ioctls	*/
#define	RGE_DBG_BADIOC		0x08000000	/* unknown ioctls	*/

#define	RGE_DBG_MCTL		0x10000000	/* mctl (csum) code	*/
#define	RGE_DBG_NDD		0x20000000	/* NDD operations	*/

/*
 * Debugging ...
 */
#ifdef	DEBUG
#define	RGE_DEBUGGING		1
#else
#define	RGE_DEBUGGING		0
#endif	/* DEBUG */


/*
 * 'Do-if-debugging' macro.  The parameter <command> should be one or more
 * C statements (but without the *final* semicolon), which will either be
 * compiled inline or completely ignored, depending on the RGE_DEBUGGING
 * compile-time flag.
 *
 * You should get a compile-time error (at least on a DEBUG build) if
 * your statement isn't actually a statement, rather than unexpected
 * run-time behaviour caused by unintended matching of if-then-elses etc.
 *
 * Note that the RGE_DDB() macro itself can only be used as a statement,
 * not an expression, and should always be followed by a semicolon.
 */
#if	RGE_DEBUGGING
#define	RGE_DDB(command)	do {					\
					{ command; }			\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)
#else 	/* RGE_DEBUGGING */
#define	RGE_DDB(command)	do {					\
					{ _NOTE(EMPTY); }		\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)
#endif	/* RGE_DEBUGGING */

/*
 * 'Internal' macros used to construct the TRACE/DEBUG macros below.
 * These provide the primitive conditional-call capability required.
 * Note: the parameter <args> is a parenthesised list of the actual
 * printf-style arguments to be passed to the debug function ...
 */
#define	RGE_XDB(b, w, f, args)	RGE_DDB(if ((b) & (w)) f args)
#define	RGE_GDB(b, args)	RGE_XDB(b, rge_debug, (*rge_gdb()), args)
#define	RGE_LDB(b, args)	RGE_XDB(b, rgep->debug, (*rge_db(rgep)), args)
#define	RGE_CDB(f, args)	RGE_XDB(RGE_DBG, rgep->debug, f, args)

/*
 * Conditional-print macros.
 *
 * Define RGE_DBG to be the relevant member of the set of RGE_DBG_* values
 * above before using the RGE_GDEBUG() or RGE_DEBUG() macros.  The 'G'
 * versions look at the Global debug flag word (rge_debug); the non-G
 * versions look in the per-instance data (rgep->debug) and so require a
 * variable called 'rgep' to be in scope (and initialised!) before use.
 *
 * You could redefine RGE_TRC too if you really need two different
 * flavours of debugging output in the same area of code, but I don't
 * really recommend it.
 *
 * Note: the parameter <args> is a parenthesised list of the actual
 * arguments to be passed to the debug function, usually a printf-style
 * format string and corresponding values to be formatted.
 */

#define	RGE_TRC			RGE_DBG_TRACE	/* default 'trace' bit	*/
#define	RGE_GTRACE(args)	RGE_GDB(RGE_TRC, args)
#define	RGE_GDEBUG(args)	RGE_GDB(RGE_DBG, args)
#define	RGE_TRACE(args)		RGE_LDB(RGE_TRC, args)
#define	RGE_DEBUG(args)		RGE_LDB(RGE_DBG, args)

/*
 * Debug-only action macros
 */
#define	RGE_BRKPT(rgep, s)	RGE_DDB(rge_dbg_enter(rgep, s))
#define	RGE_MARK(rgep)		RGE_DDB(rge_led_mark(rgep))
#define	RGE_PCICHK(rgep)	RGE_DDB(rge_pci_check(rgep))
#define	RGE_PKTDUMP(args)	RGE_DDB(rge_pkt_dump args)
#define	RGE_REPORT(args)	RGE_DDB(rge_log args)

/*
 * Inter-source-file linkage ...
 */

/* rge_chip.c */
uint16_t rge_mii_get16(rge_t *rgep, uintptr_t mii);
void rge_mii_put16(rge_t *rgep, uintptr_t mii, uint16_t data);
void rge_chip_cfg_init(rge_t *rgep, chip_id_t *cidp);
void rge_chip_ident(rge_t *rgep);
int rge_chip_reset(rge_t *rgep);
void rge_chip_init(rge_t *rgep);
void rge_chip_start(rge_t *rgep);
void rge_chip_stop(rge_t *rgep, boolean_t fault);
void rge_chip_sync(rge_t *rgep, enum rge_sync_op todo);
void rge_chip_blank(void *arg, time_t ticks, uint_t count);
void rge_tx_trigger(rge_t *rgep);
void rge_hw_stats_dump(rge_t *rgep);
uint_t rge_intr(caddr_t arg1, caddr_t arg2);
uint_t rge_chip_factotum(caddr_t arg1, caddr_t arg2);
void rge_chip_cyclic(void *arg);
enum ioc_reply rge_chip_ioctl(rge_t *rgep, queue_t *wq, mblk_t *mp,
	struct iocblk *iocp);
boolean_t rge_phy_reset(rge_t *rgep);
void rge_phy_init(rge_t *rgep);
void rge_phy_update(rge_t *rgep);

/* rge_kstats.c */
void rge_init_kstats(rge_t *rgep, int instance);
void rge_fini_kstats(rge_t *rgep);
int rge_m_stat(void *arg, uint_t stat, uint64_t *val);

/* rge_log.c */
#if	RGE_DEBUGGING
void (*rge_db(rge_t *rgep))(const char *fmt, ...);
void (*rge_gdb(void))(const char *fmt, ...);
void rge_pkt_dump(rge_t *rgep, rge_bd_t *hbp, sw_rbd_t *sdp, const char *msg);
void rge_dbg_enter(rge_t *rgep, const char *msg);
#endif	/* RGE_DEBUGGING */
void rge_problem(rge_t *rgep, const char *fmt, ...);
void rge_notice(rge_t *rgep, const char *fmt, ...);
void rge_log(rge_t *rgep, const char *fmt, ...);
void rge_error(rge_t *rgep, const char *fmt, ...);
extern kmutex_t rge_log_mutex[1];
extern uint32_t rge_debug;

/* rge_main.c */
void rge_restart(rge_t *rgep);

/* rge_ndd.c */
int rge_nd_init(rge_t *rgep);
enum ioc_reply rge_nd_ioctl(rge_t *rgep, queue_t *wq, mblk_t *mp,
	struct iocblk *iocp);
void rge_nd_cleanup(rge_t *rgep);

/* rge_rxtx.c */
void rge_rx_recycle(caddr_t arg);
void rge_receive(rge_t *rgep);
mblk_t *rge_m_tx(void *arg, mblk_t *mp);
uint_t rge_reschedule(caddr_t arg1, caddr_t arg2);

#ifdef __cplusplus
}
#endif

#endif	/* _RGE_H */

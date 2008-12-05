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

#ifndef _SYS_DMFE_IMPL_H
#define	_SYS_DMFE_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/conf.h>

#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>

#include <sys/vlan.h>

#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/miiregs.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include "dmfe.h"

#define	DMFE_MAX_PKT_SIZE	(VLAN_TAGSZ + ETHERMAX + ETHERFCSL)


#define	DRIVER_NAME		"dmfe"

/*
 * Describes the identity of a specific chip
 */
typedef struct {
	uint16_t		vendor;
	uint16_t		device;
	uint8_t			revision;
	uint8_t			spare;
} chip_id_t;

/*
 * Describes the state of a descriptor ring
 *
 * NOTE: n_free and next_busy are only used for the Tx descriptors
 * and are not valid on the receive side.
 */
typedef struct {
	uint32_t		n_desc;		/* # of descriptors	    */
	uint32_t		n_free;		/* # of free descriptors    */
	uint32_t		next_free;	/* next index to use/check  */
	uint32_t		next_busy;	/* next index to reclaim    */
} desc_state_t;

/*
 * Describes one chunk of allocated DMA-able memory
 */
typedef struct {
	ddi_dma_handle_t	dma_hdl;
	ddi_acc_handle_t	acc_hdl;
	size_t			alength;	/* allocated size	*/
	caddr_t			mem_va;		/* CPU VA of memory	*/
	uint32_t		spare1;
	uint32_t		mem_dvma;	/* DVMA addr of memory	*/
	caddr_t			setup_va;
	uint32_t		spare2;
	uint32_t		setup_dvma;
	int			spare3;
	int			ncookies;
} dma_area_t;

/*
 * Named Data (ND) Parameter Management Structure
 */
typedef struct {
	uint32_t		ndp_info;
	uint32_t		ndp_min;
	uint32_t		ndp_max;
	uint32_t		ndp_val;
	char			*ndp_name;
	struct dmfe		*ndp_dmfe;
} nd_param_t;

/*
 * NDD parameter indexes, divided into:
 *
 *	read-only parameters describing the link state
 *	read-write parameters controlling the advertised link capabilities
 *	read-only parameters describing the device link capabilities
 *	read-only parameters describing the link-partner's link capabilities
 */
enum {
	PARAM_LINK_STATUS,
	PARAM_LINK_SPEED,
	PARAM_LINK_MODE,

	PARAM_ADV_AUTONEG_CAP,
	PARAM_ADV_100T4_CAP,
	PARAM_ADV_100FDX_CAP,
	PARAM_ADV_100HDX_CAP,
	PARAM_ADV_10FDX_CAP,
	PARAM_ADV_10HDX_CAP,
	PARAM_ADV_REMFAULT,

	PARAM_BMSR_AUTONEG_CAP,
	PARAM_BMSR_100T4_CAP,
	PARAM_BMSR_100FDX_CAP,
	PARAM_BMSR_100HDX_CAP,
	PARAM_BMSR_10FDX_CAP,
	PARAM_BMSR_10HDX_CAP,
	PARAM_BMSR_REMFAULT,

	PARAM_LP_AUTONEG_CAP,
	PARAM_LP_100T4_CAP,
	PARAM_LP_100FDX_CAP,
	PARAM_LP_100HDX_CAP,
	PARAM_LP_10FDX_CAP,
	PARAM_LP_10HDX_CAP,
	PARAM_LP_REMFAULT,

	PARAM_COUNT
};

/*
 * Indexes into the driver-specific kstats, divided into:
 *
 *	cyclic activity
 *	reasons for waking the factotum
 *	the factotum's activities
 *      link state updates
 *      MII-level register values
 */
enum {
	KS_CYCLIC_RUN,

	KS_TICK_LINK_STATE,
	KS_TICK_LINK_POLL,
	KS_INTERRUPT,
	KS_TX_STALL,
	KS_CHIP_ERROR,

	KS_FACTOTUM_RUN,
	KS_RECOVERY,
	KS_LINK_CHECK,

	KS_LINK_UP_CNT,
	KS_LINK_DROP_CNT,

	KS_MIIREG_BMSR,
	KS_MIIREG_ANAR,
	KS_MIIREG_ANLPAR,
	KS_MIIREG_ANER,
	KS_MIIREG_DSCSR,

	KS_DRV_COUNT
};

/*
 * Actual state of the DM9102A chip
 */
enum chip_state {
	CHIP_ERROR = -1,			/* error, need reset	*/
	CHIP_UNKNOWN,				/* Initial state only	*/
	CHIP_RESET,				/* reset, need init	*/
	CHIP_STOPPED,				/* Tx/Rx stopped	*/
	CHIP_TX_ONLY,				/* Tx (re)started	*/
	CHIP_TX_RX,				/* Tx & Rx (re)started	*/
	CHIP_RUNNING				/* with interrupts	*/
};

/*
 * Required state according to MAC
 */
enum mac_state {
	DMFE_MAC_UNKNOWN,
	DMFE_MAC_RESET,
	DMFE_MAC_STOPPED,
	DMFE_MAC_STARTED
};

/*
 * (Internal) return values from ioctl subroutines
 */
enum ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_RESTART,				/* OK, restart & reply	*/
	IOC_RESTART_ACK				/* OK, restart & ACK	*/
};

/*
 * Per-instance soft-state structure
 */
typedef struct dmfe {
	/*
	 * These fields are set by attach() and unchanged thereafter ...
	 */
	dev_info_t		*devinfo;	/* device instance	*/
	mac_handle_t		mh;		/* MAC instance data	*/
	ddi_acc_handle_t	io_handle;	/* DDI I/O handle	*/
	caddr_t			io_reg;		/* mapped registers	*/

	uint32_t		debug;		/* per-instance debug	*/
	uint32_t		progress;	/* attach tracking	*/
	chip_id_t		chipid;
	uint8_t			vendor_addr[ETHERADDRL];
	char			ifname[12];	/* "dmfeXXXX"		*/

	dma_area_t		tx_desc;	/* transmit descriptors	*/
	dma_area_t		tx_buff;	/* transmit buffers	*/
	dma_area_t		rx_desc;	/* receive descriptors	*/
	dma_area_t		rx_buff;	/* receive buffers	*/

	ddi_periodic_t		cycid;		/* periodical callback 	*/
	ddi_softintr_t		factotum_id;	/* identity of factotum	*/
	ddi_iblock_cookie_t	iblk;

	/*
	 * Locks:
	 *
	 * <milock> is used only by the MII (PHY) level code, to ensure
	 *	exclusive access during the bit-twiddling needed to send
	 *	signals along the MII serial bus.  These operations are
	 *	--S--L--O--W-- so we keep this lock separate, so that
	 *	faster operations (e.g. interrupts) aren't delayed by
	 *	waiting for it.
	 *
	 * <oplock> is a general "outer" lock, protecting most r/w data
	 *	and chip state.  It is also acquired by the interrupt
	 *	handler.
	 *
	 * <rxlock> is used to protect the Rx-side buffers, descriptors,
	 *	and statistics during a single call to dmfe_getp().
	 *	This is called from inside the interrupt handler, but
	 *	<oplock> is not held across this call.
	 *
	 * <txlock> is an "inner" lock, and protects only the Tx-side
	 *	data below and in the ring buffers/descriptors.  The
	 *	Tx-side code uses only this lock, avoiding contention
	 *	with the receive-side code.
	 *
	 * Any of the locks can be acquired singly, but where multiple
	 * locks are acquired, they *must* be in the order:
	 *
	 *	milock >>> oplock >>> rxlock >>> txlock.
	 *
	 * *None* of these locks may be held across calls out to the
	 * MAC routines mac_rx() or mac_tx_notify(); MAC locks must
	 * be regarded as *outermost* locks in all cases, as they will
	 * already be held before calling the ioctl() or get_stats()
	 * entry points - which then have to acquire multiple locks, in
	 * the order described here.
	 */
	kmutex_t		milock[1];
	kmutex_t		oplock[1];
	kmutex_t		rxlock[1];
	kmutex_t		txlock[1];

	/*
	 * DMFE Extended kstats, protected by <oplock>
	 */
	kstat_t			*ksp_drv;
	kstat_named_t		*knp_drv;

	/*
	 * GLD statistics; the prefix tells which lock each is protected by.
	 */
	uint64_t		op_stats_speed;
	uint64_t		op_stats_duplex;

	uint64_t		rx_stats_ipackets;
	uint64_t		rx_stats_multi;
	uint64_t		rx_stats_bcast;
	uint64_t		rx_stats_ierrors;
	uint64_t		rx_stats_norcvbuf;
	uint64_t		rx_stats_rbytes;
	uint64_t		rx_stats_missed;
	uint64_t		rx_stats_align;
	uint64_t		rx_stats_fcs;
	uint64_t		rx_stats_toolong;
	uint64_t		rx_stats_macrcv_errors;
	uint64_t		rx_stats_overflow;
	uint64_t		rx_stats_short;

	uint64_t		tx_stats_oerrors;
	uint64_t		tx_stats_opackets;
	uint64_t		tx_stats_multi;
	uint64_t		tx_stats_bcast;
	uint64_t		tx_stats_obytes;
	uint64_t		tx_stats_collisions;
	uint64_t		tx_stats_nocarrier;
	uint64_t		tx_stats_xmtlatecoll;
	uint64_t		tx_stats_excoll;
	uint64_t		tx_stats_macxmt_errors;
	uint64_t		tx_stats_jabber;
	uint64_t		tx_stats_defer;
	uint64_t		tx_stats_first_coll;
	uint64_t		tx_stats_multi_coll;
	uint64_t		tx_stats_underflow;

	/*
	 * These two sets of desciptors are manipulated during
	 * packet receive/transmit respectively.
	 */
	desc_state_t		rx;		/* describes Rx ring	*/
	desc_state_t		tx;		/* describes Tx ring	*/

	/*
	 * Miscellaneous Tx-side variables (protected by txlock)
	 */
	uint32_t		tx_pending_tix;	/* tix since reclaim	*/
	uint8_t			*tx_mcast;	/* bitmask: pkt is mcast */
	uint8_t			*tx_bcast;	/* bitmask: pkt is bcast */

	/*
	 * Miscellaneous operating variables (protected by oplock)
	 */
	uint32_t		link_poll_tix;	/* tix until link poll	 */
	uint16_t		factotum_flag;	/* callback pending	 */
	uint16_t		need_setup;	/* send-setup pending	 */
	uint32_t		opmode;		/* operating mode shadow */
	uint32_t		imask;		/* interrupt mask shadow */
	enum mac_state		mac_state;	/* RESET/STOPPED/STARTED */
	enum chip_state		chip_state;	/* see above		 */
	boolean_t		link_reset;	/* ndd needs link reset  */

	/*
	 * Physical link state data (protected by oplock)
	 */
	link_state_t		link_state;	/* See above		*/

	/*
	 * PHYceiver state data (protected by milock)
	 */
	int			phy_inuse;
	int			phy_addr;	/* should be -1!	*/
	uint16_t		phy_control;	/* last value written	*/
	uint16_t		phy_anar_w;	/* last value written	*/
	uint16_t		phy_anar_r;	/* latest value read	*/
	uint16_t		phy_anlpar;	/* latest value read	*/
	uint16_t		phy_aner;
	uint16_t		phy_dscsr;	/* latest value read	*/
	uint16_t		phy_bmsr;	/* latest value read	*/
	uint16_t		rsvd;		/* reserved for future use */
	uint32_t		phy_bmsr_lbolt;	/* time of BMSR change	*/
	uint32_t		phy_id; 	/* vendor+device (OUI)	*/

	/*
	 * Current Ethernet address & multicast map ...
	 */
	uint8_t			curr_addr[ETHERADDRL];
	uint8_t			mcast_refs[MCASTBUF_SIZE];
	boolean_t		addr_set;
	boolean_t		update_phy;	/* Need to update_phy? */

	/*
	 * NDD parameters
	 */
	caddr_t			nd_data_p;
	nd_param_t		nd_params[PARAM_COUNT];

	/*
	 * Guard element used to check data integrity
	 */
	uint64_t		dmfe_guard;
} dmfe_t;

/*
 * 'Progress' bit flags ...
 */
#define	PROGRESS_CONFIG		0x0001	/* config space initialised	*/
#define	PROGRESS_NDD		0x0002	/* NDD parameters set up	*/
#define	PROGRESS_REGS		0x0004	/* registers mapped		*/
#define	PROGRESS_BUFS		0x0008	/* buffers allocated		*/
#define	PROGRESS_SOFTINT	0x0010	/* softint registered		*/
#define	PROGRESS_HWINT		0x0020	/* h/w interrupt registered	*/

/*
 * Type of transceiver currently in use
 */
#define	PHY_TYPE_UNDEFINED	0
#define	PHY_TYPE_10BASE_MNCHSTR	2
#define	PHY_TYPE_100BASE_X	4

/*
 * Shorthand for the NDD parameters
 */
#define	param_linkup		nd_params[PARAM_LINK_STATUS].ndp_val
#define	param_speed		nd_params[PARAM_LINK_SPEED].ndp_val
#define	param_duplex		nd_params[PARAM_LINK_MODE].ndp_val
#define	param_autoneg		nd_params[PARAM_ADV_AUTONEG_CAP].ndp_val
#define	param_anar_100T4	nd_params[PARAM_ADV_100T4_CAP].ndp_val
#define	param_anar_100fdx	nd_params[PARAM_ADV_100FDX_CAP].ndp_val
#define	param_anar_100hdx	nd_params[PARAM_ADV_100HDX_CAP].ndp_val
#define	param_anar_10fdx	nd_params[PARAM_ADV_10FDX_CAP].ndp_val
#define	param_anar_10hdx	nd_params[PARAM_ADV_10HDX_CAP].ndp_val
#define	param_anar_remfault	nd_params[PARAM_ADV_REMFAULT].ndp_val
#define	param_bmsr_autoneg	nd_params[PARAM_BMSR_AUTONEG_CAP].ndp_val
#define	param_bmsr_100T4	nd_params[PARAM_BMSR_100T4_CAP].ndp_val
#define	param_bmsr_100fdx	nd_params[PARAM_BMSR_100FDX_CAP].ndp_val
#define	param_bmsr_100hdx	nd_params[PARAM_BMSR_100HDX_CAP].ndp_val
#define	param_bmsr_10fdx	nd_params[PARAM_BMSR_10FDX_CAP].ndp_val
#define	param_bmsr_10hdx	nd_params[PARAM_BMSR_10HDX_CAP].ndp_val
#define	param_bmsr_remfault	nd_params[PARAM_BMSR_REMFAULT].ndp_val
#define	param_lp_autoneg	nd_params[PARAM_LP_AUTONEG_CAP].ndp_val
#define	param_lp_100T4		nd_params[PARAM_LP_100T4_CAP].ndp_val
#define	param_lp_100fdx		nd_params[PARAM_LP_100FDX_CAP].ndp_val
#define	param_lp_100hdx		nd_params[PARAM_LP_100HDX_CAP].ndp_val
#define	param_lp_10fdx		nd_params[PARAM_LP_10FDX_CAP].ndp_val
#define	param_lp_10hdx		nd_params[PARAM_LP_10HDX_CAP].ndp_val
#define	param_lp_remfault	nd_params[PARAM_LP_REMFAULT].ndp_val

/*
 * Sync a DMA area described by a dma_area_t
 */
#define	DMA_SYNC(descp, flag)	((void) ddi_dma_sync((descp)->dma_hdl,	\
					0, (descp)->alength, flag))

/*
 * Next value of a cyclic index
 */
#define	NEXT(index, limit)	((index)+1 < (limit) ? (index)+1 : 0);

/*
 * Utility Macros
 */
#define	U32TOPTR(x)		((void *)(uintptr_t)(uint32_t)(x))
#define	PTRTOU32(x)		((uint32_t)(uintptr_t)(void *)(x))

/*
 * Copy an ethernet address
 */
#define	ethaddr_copy(src, dst)	bcopy((src), (dst), ETHERADDRL)
#define	MII_KS_GET(dmfep, id)						\
	(((dmfep)->knp_mii) ? ((dmfep)->knp_mii)[id].value.ui32 : 0)

#define	MII_KS_SET(dmfep, id, val)					\
	do {								\
		if ((dmfep)->knp_mii != NULL)				\
			((dmfep)->knp_mii)[id].value.ui32 = (val);	\
		_NOTE(CONSTANTCONDITION)				\
	} while (0)

#define	MII_KS_INC(dmfep, id)						\
	do {								\
		if ((dmfep)->knp_mii != NULL)				\
			((dmfep)->knp_mii)[id].value.ui32 += 1;		\
		_NOTE(CONSTANTCONDITION)				\
	} while (0)

/*
 * Get/set/increment a (64-bit) driver-private kstat
 */
#define	DRV_KS_GET(dmfep, id)						\
	(((dmfep)->knp_drv) ? ((dmfep)->knp_drv)[id].value.ui64 : 0)

#define	DRV_KS_SET(dmfep, id, val)					\
	do {								\
		if ((dmfep)->knp_drv)					\
			((dmfep)->knp_drv)[id].value.ui64 = (val);	\
		_NOTE(CONSTANTCONDITION)				\
	} while (0)

#define	DRV_KS_INC(dmfep, id)						\
	do {								\
		if ((dmfep)->knp_drv)					\
			((dmfep)->knp_drv)[id].value.ui64 += 1;		\
		_NOTE(CONSTANTCONDITION)				\
	} while (0)

/*
 * Bit test macros, returning boolean_t values
 */
#define	BIS(w, b)		(((w) & (b)) != 0)
#define	BIC(w, b)		!BIS(w, b)

#define	DMFE_GUARD		0x1919603003090218

/*
 * 'Debug' bit flags ...
 */
#define	DMFE_DBG_TRACE		0x0001		/* general flow tracing	*/
#define	DMFE_DBG_REGS		0x0002		/* low-level accesses	*/
#define	DMFE_DBG_RECV		0x0004		/* receive-side code	*/
#define	DMFE_DBG_SEND		0x0008		/* packet-send code	*/
#define	DMFE_DBG_ADDR		0x0010		/* address-setting code	*/
#define	DMFE_DBG_GLD		0x0020		/* GLD entry points	*/
#define	DMFE_DBG_FACT		0x0040		/* factotum (softint)	*/
#define	DMFE_DBG_TICK		0x0080		/* GPT ticker		*/
#define	DMFE_DBG_INT		0x0100		/* interrupt handler	*/
#define	DMFE_DBG_STATS		0x0200		/* statistics		*/
#define	DMFE_DBG_IOCTL		0x0400		/* ioctl/loopback code	*/
#define	DMFE_DBG_INIT		0x0800		/* initialisation	*/
#define	DMFE_DBG_MII		0x1000		/* low-level MII/PHY	*/
#define	DMFE_DBG_LINK		0x2000		/* Link status check	*/
#define	DMFE_DBG_NDD		0x4000		/* NDD parameters	*/

/*
 * Debugging ...
 */
#if defined(DEBUG) || defined(lint)
#define	DMFEDEBUG		1
#else
#define	DMFEDEBUG		0
#endif

#if	DMFEDEBUG

extern uint32_t dmfe_debug;
extern void (*dmfe_gdb())(const char *fmt, ...);
extern void (*dmfe_db(dmfe_t *dmfep))(const char *fmt, ...);

/*
 * Define DMFE_DBG to be the relevant flag from the set above before
 * using the DMFE_GDEBUG() or DMFE_DEBUG() macros.  The 'G' versions
 * look at the Global debug flag word (dmfe_debug); the non-G versions
 * look in the per-instance data (dmfep->debug) and so require a variable
 * called 'dmfep' to be in scope (and initialised!)
 *
 * You could redefine DMFE_TRC too if you really need two different
 * flavours of debugging output in the same area of code, but I don't
 * really recommend it.
 */

#define	DMFE_TRC		DMFE_DBG_TRACE	/* default 'trace' bit	*/

#define	DMFE_GDEBUG(args)	do {					\
					if (dmfe_debug & (DMFE_DBG))	\
						(*dmfe_gdb()) args;	\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)

#define	DMFE_GTRACE(args)	do {					\
					if (dmfe_debug & (DMFE_TRC))	\
						(*dmfe_gdb()) args;	\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)

#define	DMFE_DEBUG(args)	do {					\
					if (dmfep->debug & (DMFE_DBG))	\
						(*dmfe_db(dmfep)) args;	\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)

#define	DMFE_TRACE(args)	do {					\
					if (dmfep->debug & (DMFE_TRC))	\
						(*dmfe_db(dmfep)) args;	\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)

#else

#define	DMFE_DEBUG(args)	do ; _NOTE(CONSTANTCONDITION) while (0)
#define	DMFE_TRACE(args)	do ; _NOTE(CONSTANTCONDITION) while (0)
#define	DMFE_GDEBUG(args)	do ; _NOTE(CONSTANTCONDITION) while (0)
#define	DMFE_GTRACE(args)	do ; _NOTE(CONSTANTCONDITION) while (0)

#endif	/* DMFEDEBUG */


/*
 * Inter-source-file linkage ...
 */

/* dmfe_log.c */
void dmfe_warning(dmfe_t *dmfep, const char *fmt, ...);
void dmfe_error(dmfe_t *dmfep, const char *fmt, ...);
void dmfe_notice(dmfe_t *dmfep, const char *fmt, ...);
void dmfe_log(dmfe_t *dmfep, const char *fmt, ...);
void dmfe_log_init(void);
void dmfe_log_fini(void);

/* dmfe_main.c */
uint32_t dmfe_chip_get32(dmfe_t *dmfep, off_t offset);
void dmfe_chip_put32(dmfe_t *dmfep, off_t offset, uint32_t value);

/* dmfe_mii.c */
void dmfe_read_eeprom(dmfe_t *dmfep, uint16_t addr, uint8_t *ptr, int cnt);
boolean_t dmfe_init_phy(dmfe_t *dmfep);
void dmfe_update_phy(dmfe_t *dmfep);
boolean_t dmfe_check_link(dmfe_t *dmfep);
void dmfe_recheck_link(dmfe_t *dmfep, boolean_t ioctl);

/* dmfe_ndd.c */
int dmfe_nd_init(dmfe_t *dmfep);
enum ioc_reply dmfe_nd_ioctl(dmfe_t *dmfep, queue_t *wq, mblk_t *mp, int cmd);
void dmfe_nd_cleanup(dmfe_t *dmfep);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DMFE_IMPL_H */

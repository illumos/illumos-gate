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

#ifndef _SYS_DMFE_IMPL_H
#define	_SYS_DMFE_IMPL_H

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

#include <sys/vlan.h>

#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/mii.h>
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
 * Indexes into the driver-specific kstats, divided into:
 *
 *	cyclic activity
 *	reasons for waking the factotum
 *	the factotum's activities
 */
enum {
	KS_CYCLIC_RUN,

	KS_INTERRUPT,
	KS_TX_STALL,
	KS_CHIP_ERROR,

	KS_FACTOTUM_RUN,
	KS_RECOVERY,

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
	mii_handle_t		mii;		/* MII handle		*/
	ddi_acc_handle_t	io_handle;	/* DDI I/O handle	*/
	caddr_t			io_reg;		/* mapped registers	*/
	boolean_t		suspended;

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
	uint16_t		factotum_flag;	/* callback pending	 */
	uint16_t		need_setup;	/* send-setup pending	 */
	uint32_t		opmode;		/* operating mode shadow */
	uint32_t		imask;		/* interrupt mask shadow */
	enum mac_state		mac_state;	/* RESET/STOPPED/STARTED */
	enum chip_state		chip_state;	/* see above		 */

	/*
	 * Current Ethernet address & multicast map ...
	 */
	uint8_t			curr_addr[ETHERADDRL];
	uint8_t			mcast_refs[MCASTBUF_SIZE];
	boolean_t		addr_set;

	/*
	 * Guard element used to check data integrity
	 */
	uint64_t		dmfe_guard;
} dmfe_t;

/*
 * 'Progress' bit flags ...
 */
#define	PROGRESS_CONFIG		0x0001	/* config space initialised	*/
#define	PROGRESS_MUTEX		0x0002	/* mutexes initialized		*/
#define	PROGRESS_REGS		0x0004	/* registers mapped		*/
#define	PROGRESS_BUFS		0x0008	/* buffers allocated		*/
#define	PROGRESS_SOFTINT	0x0010	/* softint registered		*/
#define	PROGRESS_HWINT		0x0020	/* h/w interrupt registered	*/

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
 * Copy an ethernet address
 */
#define	ethaddr_copy(src, dst)	bcopy((src), (dst), ETHERADDRL)

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


#define	DMFE_GUARD		0x1919603003090218

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

#endif	/* _SYS_DMFE_IMPL_H */

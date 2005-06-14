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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dmfe_impl.h>

/*
 * This is the string displayed by modinfo, etc.
 * Make sure you keep the version ID up to date!
 */
static char dmfe_ident[] = "Davicom DM9102 v2.4";


/*
 * NOTES:
 *
 * #defines:
 *
 *	DMFE_PCI_RNUMBER is the register-set number to use for the operating
 *	registers.  On an OBP-based machine, regset 0 refers to CONFIG space,
 *	regset 1 will be the operating registers in I/O space, and regset 2
 *	will be the operating registers in MEMORY space (preferred).  If an
 *	expansion ROM is fitted, it may appear as a further register set.
 *
 *	DMFE_SLOP defines the amount by which the chip may read beyond
 *	the end of a buffer or descriptor, apparently 6-8 dwords :(
 *	We have to make sure this doesn't cause it to access unallocated
 *	or unmapped memory.
 *
 *	DMFE_BUF_SIZE must be at least (ETHERMAX + ETHERFCSL + DMFE_SLOP)
 *	rounded up to a multiple of 4.  Here we choose a power of two for
 *	speed & simplicity at the cost of a bit more memory.
 *
 *	However, the buffer length field in the TX/RX descriptors is only
 *	eleven bits, so even though we allocate DMFE_BUF_SIZE (2048) bytes
 *	per buffer, we tell the chip that they're only DMFE_BUF_SIZE_1
 *	(2000) bytes each.
 *
 *	DMFE_DMA_MODE defines the mode (STREAMING/CONSISTENT) used for
 *	the data buffers.  The descriptors are always set up in CONSISTENT
 *	mode.
 *
 *	DMFE_HEADROOM defines how much space we'll leave in allocated
 *	mblks before the first valid data byte.  This should be chosen
 *	to be 2 modulo 4, so that once the ethernet header (14 bytes)
 *	has been stripped off, the packet data will be 4-byte aligned.
 *	The remaining space can be used by upstream modules to prepend
 *	any headers required.
 *
 * Patchable globals:
 *
 *	dmfe_bus_modes: the bus mode bits to be put into CSR0.
 *		Setting READ_MULTIPLE in this register seems to cause
 *		the chip to generate a READ LINE command with a parity
 *		error!  Don't do it!
 *
 *	dmfe_setup_desc1: the value to be put into descriptor word 1
 *		when sending a SETUP packet.
 *
 *		Setting TX_LAST_DESC in desc1 in a setup packet seems
 *		to make the chip spontaneously reset internally - it
 *		attempts to give back the setup packet descriptor by
 *		writing to PCI address 00000000 - which may or may not
 *		get a MASTER ABORT - after which most of its registers
 *		seem to have either default values or garbage!
 *
 *		TX_FIRST_DESC doesn't seem to have the same effect but
 *		it isn't needed on a setup packet so we'll leave it out
 *		too, just in case it has some other wierd side-effect.
 *
 *		The default hardware packet filtering mode is now
 *		HASH_AND_PERFECT (imperfect filtering of multicast
 *		packets and perfect filtering of unicast packets).
 *		If this is found not to work reliably, setting the
 *		TX_FILTER_TYPE1 bit will cause a switchover to using
 *		HASH_ONLY mode (imperfect filtering of *all* packets).
 *		Software will then perform the additional filtering
 *		as required.
 */

#define	DMFE_PCI_RNUMBER	2
#define	DMFE_SLOP		(8*sizeof (uint32_t))
#define	DMFE_BUF_SIZE		2048
#define	DMFE_BUF_SIZE_1		2000
#define	DMFE_DMA_MODE		DDI_DMA_STREAMING
#define	DMFE_HEADROOM		34

static uint32_t dmfe_bus_modes = TX_POLL_INTVL | CACHE_ALIGN;
static uint32_t dmfe_setup_desc1 = TX_SETUP_PACKET | SETUPBUF_SIZE |
					TX_FILTER_TYPE0;

/*
 * Some tunable parameters ...
 *	Number of RX/TX ring entries (32/32)
 *	Minimum number of TX ring slots to keep free (1)
 *	Low-water mark at which to try to reclaim TX ring slots (1)
 *	How often to take a TX-done interrupt (twice per ring cycle)
 *	Whether to reclaim TX ring entries on a TX-done interrupt (no)
 */

#define	DMFE_TX_DESC		32	/* Should be a multiple of 4 <= 256 */
#define	DMFE_RX_DESC		32	/* Should be a multiple of 4 <= 256 */

static uint32_t dmfe_rx_desc = DMFE_RX_DESC;
static uint32_t dmfe_tx_desc = DMFE_TX_DESC;
static uint32_t dmfe_tx_min_free = 1;
static uint32_t dmfe_tx_reclaim_level = 1;
static uint32_t dmfe_tx_int_factor = (DMFE_TX_DESC / 2) - 1;
static boolean_t dmfe_reclaim_on_done = B_FALSE;

/*
 * Time-related parameters:
 *
 *	We use a cyclic to provide a periodic callback; this is then used
 * 	to check for TX-stall and poll the link status register.
 *
 *	DMFE_TICK is the interval between cyclic callbacks, in microseconds.
 *
 *	TX_STALL_TIME_100 is the timeout in microseconds between passing
 *	a packet to the chip for transmission and seeing that it's gone,
 *	when running at 100Mb/s.  If we haven't reclaimed at least one
 *	descriptor in this time we assume the transmitter has stalled
 *	and reset the chip.
 *
 *	TX_STALL_TIME_10 is the equivalent timeout when running at 10Mb/s.
 *
 *	LINK_POLL_TIME is the interval between checks on the link state
 *	when nothing appears to have happened (this is in addition to the
 *	case where we think we've detected a link change, and serves as a
 *	backup in case the quick link check doesn't work properly).
 *
 * Patchable globals:
 *
 *	dmfe_tick_us:		DMFE_TICK
 *	dmfe_tx100_stall_us:	TX_STALL_TIME_100
 *	dmfe_tx10_stall_us:	TX_STALL_TIME_10
 *	dmfe_link_poll_us:	LINK_POLL_TIME
 *
 * These are then used in _init() to calculate:
 *
 *	stall_100_tix[]: number of consecutive cyclic callbacks without a
 *			 reclaim before the TX process is considered stalled,
 *			 when running at 100Mb/s.  The elements are indexed
 *			 by transmit-engine-state.
 *	stall_10_tix[]:	 number of consecutive cyclic callbacks without a
 *			 reclaim before the TX process is considered stalled,
 *			 when running at 10Mb/s.  The elements are indexed
 *			 by transmit-engine-state.
 *	factotum_tix:	 number of consecutive cyclic callbacks before waking
 *			 up the factotum even though there doesn't appear to
 *			 be anything for it to do
 */

#define	DMFE_TICK		25000		/* microseconds		*/
#define	TX_STALL_TIME_100	50000		/* microseconds		*/
#define	TX_STALL_TIME_10	200000		/* microseconds		*/
#define	LINK_POLL_TIME		5000000		/* microseconds		*/

static uint32_t dmfe_tick_us = DMFE_TICK;
static uint32_t dmfe_tx100_stall_us = TX_STALL_TIME_100;
static uint32_t dmfe_tx10_stall_us = TX_STALL_TIME_10;
static uint32_t dmfe_link_poll_us = LINK_POLL_TIME;

/*
 * Calculated from above in _init()
 */

static uint32_t stall_100_tix[TX_PROCESS_MAX_STATE+1];
static uint32_t stall_10_tix[TX_PROCESS_MAX_STATE+1];
static uint32_t factotum_tix;
static uint32_t factotum_fast_tix;
static uint32_t factotum_start_tix;

/*
 * Versions of the O/S up to Solaris 8 didn't support network booting
 * from any network interface except the first (NET0).  Patching this
 * flag to a non-zero value will tell the driver to work around this
 * limitation by creating an extra (internal) pathname node.  To do
 * this, just add a line like the following to the CLIENT'S etc/system
 * file ON THE ROOT FILESYSTEM SERVER before booting the client:
 *
 *	set dmfe:dmfe_net1_boot_support = 1;
 */
static uint32_t dmfe_net1_boot_support = 0;

/*
 * Property names
 */
static char localmac_propname[] = "local-mac-address";
static char opmode_propname[] = "opmode-reg-value";
static char debug_propname[] = "dmfe-debug-flags";

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,		/* dma_attr version */
	0,			/* dma_attr_addr_lo */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	0x0FFFFFF,		/* dma_attr_count_max */
	0x20,			/* dma_attr_align */
	0x7F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * DMA access attributes for registers and descriptors
 */
static ddi_device_acc_attr_t dmfe_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA access attributes for data: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t dmfe_data_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static uchar_t dmfe_broadcast_addr[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};


/*
 * ========== Lowest-level chip register & ring access routines ==========
 */

/*
 * I/O register get/put routines
 */
uint32_t
dmfe_chip_get32(dmfe_t *dmfep, off_t offset)
{
	caddr_t addr;

	addr = dmfep->io_reg + offset;
	return (ddi_get32(dmfep->io_handle, (uint32_t *)addr));
}

void
dmfe_chip_put32(dmfe_t *dmfep, off_t offset, uint32_t value)
{
	caddr_t addr;

	addr = dmfep->io_reg + offset;
	ddi_put32(dmfep->io_handle, (uint32_t *)addr, value);
}

/*
 * TX/RX ring get/put routines
 */
static uint32_t
dmfe_ring_get32(dma_area_t *dma_p, uint_t index, uint_t offset)
{
	uint32_t *addr;

	addr = (uint32_t *)dma_p->mem_va;
	return (ddi_get32(dma_p->acc_hdl, addr + index*DESC_SIZE + offset));
}

static void
dmfe_ring_put32(dma_area_t *dma_p, uint_t index, uint_t offset, uint32_t value)
{
	uint32_t *addr;

	addr = (uint32_t *)dma_p->mem_va;
	ddi_put32(dma_p->acc_hdl, addr + index*DESC_SIZE + offset, value);
}

/*
 * Setup buffer get/put routines
 */
static uint32_t
dmfe_setup_get32(dma_area_t *dma_p, uint_t index)
{
	uint32_t *addr;

	addr = (uint32_t *)dma_p->setup_va;
	return (ddi_get32(dma_p->acc_hdl, addr + index));
}

static void
dmfe_setup_put32(dma_area_t *dma_p, uint_t index, uint32_t value)
{
	uint32_t *addr;

	addr = (uint32_t *)dma_p->setup_va;
	ddi_put32(dma_p->acc_hdl, addr + index, value);
}


/*
 * ========== Low-level chip & ring buffer manipulation ==========
 */

#define	DMFE_DBG	DMFE_DBG_REGS	/* debug flag for this code	*/

/*
 * dmfe_set_opmode() -- function to set operating mode
 */
static void
dmfe_set_opmode(dmfe_t *dmfep)
{
	DMFE_DEBUG(("dmfe_set_opmode: opmode 0x%x", dmfep->opmode));

	ASSERT(mutex_owned(dmfep->oplock));

	dmfe_chip_put32(dmfep, OPN_MODE_REG, dmfep->opmode);
	drv_usecwait(10);
}

/*
 * dmfe_stop_chip() -- stop all chip processing & optionally reset the h/w
 */
static void
dmfe_stop_chip(dmfe_t *dmfep, enum chip_state newstate)
{
	DMFE_TRACE(("dmfe_stop_chip($%p, %d)", (void *)dmfep, newstate));

	ASSERT(mutex_owned(dmfep->oplock));

	/*
	 * Stop the chip:
	 *	disable all interrupts
	 *	stop TX/RX processes
	 *	clear the status bits for TX/RX stopped
	 * If required, reset the chip
	 * Record the new state
	 */
	dmfe_chip_put32(dmfep, INT_MASK_REG, 0);
	dmfep->opmode &= ~(START_TRANSMIT | START_RECEIVE);
	dmfe_set_opmode(dmfep);
	dmfe_chip_put32(dmfep, STATUS_REG, TX_STOPPED_INT | RX_STOPPED_INT);

	switch (newstate) {
	default:
		ASSERT(!"can't get here");
		return;

	case CHIP_STOPPED:
	case CHIP_ERROR:
		break;

	case CHIP_RESET:
		dmfe_chip_put32(dmfep, BUS_MODE_REG, SW_RESET);
		drv_usecwait(10);
		dmfe_chip_put32(dmfep, BUS_MODE_REG, 0);
		drv_usecwait(10);
		dmfe_chip_put32(dmfep, BUS_MODE_REG, dmfe_bus_modes);
		break;
	}

	dmfep->chip_state = newstate;
}

/*
 * Initialize transmit and receive descriptor rings, and
 * set the chip to point to the first entry in each ring
 */
static void
dmfe_init_rings(dmfe_t *dmfep)
{
	dma_area_t *descp;
	uint32_t pstart;
	uint32_t pnext;
	uint32_t pbuff;
	uint32_t desc1;
	int i;

	/*
	 * You need all the locks in order to rewrite the descriptor rings
	 */
	ASSERT(mutex_owned(dmfep->oplock));
	ASSERT(mutex_owned(dmfep->rxlock));
	ASSERT(mutex_owned(dmfep->txlock));

	/*
	 * Program the RX ring entries
	 */
	descp = &dmfep->rx_desc;
	pstart = descp->mem_dvma;
	pnext = pstart + sizeof (struct rx_desc_type);
	pbuff = dmfep->rx_buff.mem_dvma;
	desc1 = RX_CHAINING | DMFE_BUF_SIZE_1;

	for (i = 0; i < dmfep->rx.n_desc; ++i) {
		dmfe_ring_put32(descp, i, RD_NEXT, pnext);
		dmfe_ring_put32(descp, i, BUFFER1, pbuff);
		dmfe_ring_put32(descp, i, DESC1, desc1);
		dmfe_ring_put32(descp, i, DESC0, RX_OWN);

		pnext += sizeof (struct rx_desc_type);
		pbuff += DMFE_BUF_SIZE;
	}

	/*
	 * Fix up last entry & sync
	 */
	dmfe_ring_put32(descp, --i, RD_NEXT, pstart);
	DMA_SYNC(descp, DDI_DMA_SYNC_FORDEV);
	dmfep->rx.next_free = 0;

	/*
	 * Set the base address of the RX descriptor list in CSR3
	 */
	DMFE_DEBUG(("RX descriptor VA: $%p (DVMA $%p)",
		    (void *)descp->mem_va, (void *)descp->mem_dvma));
	dmfe_chip_put32(dmfep, RX_BASE_ADDR_REG, descp->mem_dvma);

	/*
	 * Program the TX ring entries
	 */
	descp = &dmfep->tx_desc;
	pstart = descp->mem_dvma;
	pnext = pstart + sizeof (struct tx_desc_type);
	pbuff = dmfep->tx_buff.mem_dvma;
	desc1 = TX_CHAINING;

	for (i = 0; i < dmfep->tx.n_desc; ++i) {
		dmfe_ring_put32(descp, i, TD_NEXT, pnext);
		dmfe_ring_put32(descp, i, BUFFER1, pbuff);
		dmfe_ring_put32(descp, i, DESC1, desc1);
		dmfe_ring_put32(descp, i, DESC0, 0);

		pnext += sizeof (struct tx_desc_type);
		pbuff += DMFE_BUF_SIZE;
	}

	/*
	 * Fix up last entry & sync
	 */
	dmfe_ring_put32(descp, --i, TD_NEXT, pstart);
	DMA_SYNC(descp, DDI_DMA_SYNC_FORDEV);
	dmfep->tx.n_free = dmfep->tx.n_desc;
	dmfep->tx.next_free = dmfep->tx.next_busy = 0;

	/*
	 * Set the base address of the TX descrptor list in CSR4
	 */
	DMFE_DEBUG(("TX descriptor VA: $%p (DVMA $%p)",
		    (void *)descp->mem_va, (void *)descp->mem_dvma));
	dmfe_chip_put32(dmfep, TX_BASE_ADDR_REG, descp->mem_dvma);
}

/*
 * dmfe_start_chip() -- start the chip transmitting and/or receiving
 */
static void
dmfe_start_chip(dmfe_t *dmfep, int mode)
{
	DMFE_TRACE(("dmfe_start_chip($%p, %d)", (void *)dmfep, mode));

	ASSERT(mutex_owned(dmfep->oplock));

	dmfep->opmode |= mode;
	dmfe_set_opmode(dmfep);

	dmfe_chip_put32(dmfep, W_J_TIMER_REG, 0);
#if	defined(VLAN_VID_NONE)
	/*
	 * Enable VLAN length mode (allows packets to be 4 bytes Longer).
	 */
	if (gld_recv_tagged != NULL)
		dmfe_chip_put32(dmfep, W_J_TIMER_REG, VLAN_ENABLE);
#endif
	/*
	 * Clear any pending process-stopped interrupts
	 */
	dmfe_chip_put32(dmfep, STATUS_REG, TX_STOPPED_INT | RX_STOPPED_INT);
	dmfep->chip_state = mode & START_RECEIVE ? CHIP_TX_RX :
		mode & START_TRANSMIT ? CHIP_TX_ONLY : CHIP_STOPPED;
}

/*
 * dmfe_enable_interrupts() -- enable our favourite set of interrupts.
 *
 * Normal interrupts:
 *	We always enable:
 *		RX_PKTDONE_INT		(packet received)
 *		TX_PKTDONE_INT		(TX complete)
 *	We never enable:
 *		TX_ALLDONE_INT		(next TX buffer not ready)
 *
 * Abnormal interrupts:
 *	We always enable:
 *		RX_STOPPED_INT
 *		TX_STOPPED_INT
 *		SYSTEM_ERR_INT
 *		RX_UNAVAIL_INT
 *	We never enable:
 *		RX_EARLY_INT
 *		RX_WATCHDOG_INT
 *		TX_JABBER_INT
 *		TX_EARLY_INT
 *		TX_UNDERFLOW_INT
 *		GP_TIMER_INT		(not valid in -9 chips)
 *		LINK_STATUS_INT		(not valid in -9 chips)
 */
static void
dmfe_enable_interrupts(dmfe_t *dmfep)
{
	ASSERT(mutex_owned(dmfep->oplock));

	/*
	 * Put 'the standard set of interrupts' in the interrupt mask register
	 */
	dmfep->imask =	RX_PKTDONE_INT | TX_PKTDONE_INT |
			RX_STOPPED_INT | TX_STOPPED_INT |
			RX_UNAVAIL_INT | SYSTEM_ERR_INT;

	dmfe_chip_put32(dmfep, INT_MASK_REG,
		NORMAL_SUMMARY_INT | ABNORMAL_SUMMARY_INT | dmfep->imask);
	dmfep->chip_state = CHIP_RUNNING;

	DMFE_DEBUG(("dmfe_enable_interrupts: imask 0x%x", dmfep->imask));
}

#undef	DMFE_DBG


/*
 * ========== RX side routines ==========
 */

#define	DMFE_DBG	DMFE_DBG_RECV	/* debug flag for this code	*/

/*
 * Function to update receive statistics on various errors
 */
static void
dmfe_update_rx_stats(dmfe_t *dmfep, uint32_t desc0)
{
	ASSERT(mutex_owned(dmfep->rxlock));

	/*
	 * The error summary bit and the error bits that it summarises
	 * are only valid if this is the last fragment.  Therefore, a
	 * fragment only contributes to the error statistics if both
	 * the last-fragment and error summary bits are set.
	 */
	if (((RX_LAST_DESC | RX_ERR_SUMMARY) & ~desc0) == 0) {
		dmfep->rx_stats_errrcv += 1;

		/*
		 * There are some other error bits in the descriptor for
		 * which there don't seem to be appropriate GLD statistics,
		 * notably RX_COLLISION and perhaps RX_DESC_ERR.  The
		 * latter may not be possible if it is supposed to indicate
		 * that one buffer has been filled with a partial packet
		 * and the next buffer required for the rest of the packet
		 * was not available, as all our buffers are more than large
		 * enough for a whole packet without fragmenting.
		 */

		if (desc0 & RX_OVERFLOW)
			dmfep->rx_stats_overflow += 1;
		else if (desc0 & RX_RUNT_FRAME)
			dmfep->rx_stats_short += 1;

		if (desc0 & RX_CRC)
			dmfep->rx_stats_crc += 1;

		if (desc0 & RX_FRAME2LONG)
			dmfep->rx_stats_frame_too_long += 1;
	}

	/*
	 * A receive watchdog timeout is counted as a MAC-level receive
	 * error.  Strangely, it doesn't set the packet error summary bit,
	 * according to the chip data sheet :-?
	 */
	if (desc0 & RX_RCV_WD_TO)
		dmfep->rx_stats_mac_rcv_error += 1;

	if (desc0 & RX_DRIBBLING)
		dmfep->rx_stats_frame += 1;
	if (desc0 & RX_MII_ERR)
		dmfep->rx_stats_mac_rcv_error += 1;
}

/*
 * Ethernet packet-checking macros used in the receive code below.
 * The <eap> parameter should be a pointer to the destination address found
 * at the start of a received packet (an array of 6 (ETHERADDRL) bytes).
 *
 * A packet is intended for this station if the destination address exactly
 * matches our own physical (unicast) address.
 *
 * A packet is a multicast (including broadcast) packet if the low-order bit
 * of the first byte of the destination address is set (unicast addresses
 * always have a zero in this bit).
 *
 * A packet should be passed up to GLD if it's multicast OR addressed to us
 * OR if the device is in promiscuous mode, when all packets are passed up
 * anyway.
 */
#define	PKT_IS_MINE(eap, dmfep)	(ether_cmp(eap,	dmfep->curr_addr) == 0)
#define	PKT_IS_MULTICAST(eap)	(eap[0] & 1)
#define	DEV_IS_PROMISC(dmfep)	((dmfep->opmode & PROMISC_MODE) != 0)

#define	PKT_WANTED(eap, dmfep)	(PKT_IS_MULTICAST(eap) 		||	\
				    PKT_IS_MINE(eap, dmfep)	||	\
				    DEV_IS_PROMISC(dmfep))

/*
 * Receive incoming packet(s) and pass them up ...
 */
static mblk_t *
dmfe_getp(dmfe_t *dmfep)
{
	struct ether_header *ehp;
	dma_area_t *descp;
	mblk_t **tail;
	mblk_t *head;
	mblk_t *mp;
	char *rxb;
	uchar_t *dp;
	uint32_t desc0;
	uint32_t misses;
	int packet_length;
	int index;

	DMFE_TRACE(("dmfe_getp($%p)", (void *)dmfep));

	mutex_enter(dmfep->rxlock);

	/*
	 * Update the missed frame statistic from the on-chip counter.
	 */
	misses = dmfe_chip_get32(dmfep, MISSED_FRAME_REG);
	dmfep->rx_stats_missed += (misses & MISSED_FRAME_MASK);

	/*
	 * sync (all) receive descriptors before inspecting them
	 */
	descp = &dmfep->rx_desc;
	DMA_SYNC(descp, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * We should own at least one RX entry, since we've had a
	 * receive interrupt, but let's not be dogmatic about it.
	 */
	index = dmfep->rx.next_free;
	desc0 = dmfe_ring_get32(descp, index, DESC0);
	if (desc0 & RX_OWN)
		DMFE_DEBUG(("dmfe_getp: no work, desc0 0x%x", desc0));

	for (head = NULL, tail = &head; (desc0 & RX_OWN) == 0; ) {
		/*
		 * Maintain statistics for every descriptor returned
		 * to us by the chip ...
		 */
		DMFE_DEBUG(("dmfe_getp: desc0 0x%x", desc0));
		dmfe_update_rx_stats(dmfep, desc0);

		/*
		 * Check that the entry has both "packet start" and
		 * "packet end" flags.  We really shouldn't get packet
		 * fragments, 'cos all the RX buffers are bigger than
		 * the largest valid packet.  So we'll just drop any
		 * fragments we find & skip on to the next entry.
		 */
		if (((RX_FIRST_DESC | RX_LAST_DESC) & ~desc0) != 0) {
			DMFE_DEBUG(("dmfe_getp: dropping fragment"));
			goto skip;
		}

		/*
		 * A whole packet in one buffer.  We have to check error
		 * status and packet length before forwarding it upstream.
		 */
		if (desc0 & RX_ERR_SUMMARY) {
			DMFE_DEBUG(("dmfe_getp: dropping errored packet"));
			goto skip;
		}

		packet_length = (desc0 >> 16) & 0x3fff;
		if (packet_length > DMFE_MAX_PKT_SIZE) {
			DMFE_DEBUG(("dmfe_getp: dropping oversize packet, "
				"length %d", packet_length));
			goto skip;
		} else if (packet_length < ETHERMIN) {
			DMFE_DEBUG(("dmfe_getp: dropping undersize packet, "
				"length %d", packet_length));
			goto skip;
		}

		/*
		 * Sync the data, so we can examine it; then check that
		 * the packet is really intended for us (remember that
		 * if we're using Imperfect Filtering, then the chip will
		 * receive unicast packets sent to stations whose addresses
		 * just happen to hash to the same value as our own; we
		 * discard these here so they don't get sent upstream ...)
		 */
		(void) ddi_dma_sync(dmfep->rx_buff.dma_hdl,
			index*DMFE_BUF_SIZE, DMFE_BUF_SIZE,
			DDI_DMA_SYNC_FORKERNEL);
		rxb = &dmfep->rx_buff.mem_va[index*DMFE_BUF_SIZE];
		ehp = (struct ether_header *)rxb;
		if (!PKT_WANTED(ehp->ether_dhost.ether_addr_octet, dmfep)) {
			DMFE_DEBUG(("dmfe_getp: dropping aliased packet"));
			goto skip;
		}

		/*
		 * Packet looks good; get a buffer to copy it into.  We
		 * allow some space at the front of the allocated buffer
		 * (HEADROOM) in case any upstream modules want to prepend
		 * some sort of header.  The value has been carefully chosen
		 * So that it also has the side-effect of making the packet
		 * *contents* 4-byte aligned, as required by NCA!
		 */
		mp = allocb(DMFE_HEADROOM + packet_length, 0);
		if (mp == NULL) {
			DMFE_DEBUG(("dmfe_getp: no buffer - dropping packet"));
			dmfep->rx_stats_norcvbuf += 1;
			goto skip;
		}

		/*
		 * Copy the packet into the STREAMS buffer
		 */
		dp = mp->b_rptr += DMFE_HEADROOM;
		mp->b_cont = mp->b_next = NULL;
#if	!defined(VLAN_VID_NONE)
		bcopy(rxb, dp, packet_length);
#else
		if (ehp->ether_type != VLAN_TPID || gld_recv_tagged == NULL) {
			/*
			 * An untagged packet (or, there's no runtime support
			 * for tagging so we treat all packets as untagged).
			 * Just copy the contents verbatim.
			 */
			bcopy(rxb, dp, packet_length);
		} else {
			/*
			 * A tagged packet. Extract the vtag & stash it in
			 * the b_cont field (we know that it's safe to grab
			 * the vtag directly because the way buffers are
			 * allocated guarantees their alignment). Copy the
			 * rest of the packet data to the mblk, dropping the
			 * vtag in the process.
			 *
			 * The magic number (2*ETHERADDRL) appears quite a
			 * lot here, because the vtag comes immediately after
			 * the destination & source Ethernet addresses in
			 * the packet header ...
			 */
			bcopy(rxb, dp, 2*ETHERADDRL);
			rxb += 2*ETHERADDRL;
			dp += 2*ETHERADDRL;

			mp->b_cont = U32TOPTR(*(uint32_t *)rxb);
			rxb += VTAG_SIZE;
			packet_length -= VTAG_SIZE;

			bcopy(rxb, dp, packet_length - 2*ETHERADDRL);
		}
#endif	/* defined(VLAN_VID_NONE) */

		/*
		 * Fix up the packet length, and link it to the chain
		 */
		mp->b_wptr = mp->b_rptr + packet_length - ETHERFCSL;
		*tail = mp;
		tail = &mp->b_next;

	skip:
		/*
		 * Return ownership of ring entry & advance to next
		 */
		dmfe_ring_put32(descp, index, DESC0, RX_OWN);
		index = NEXT(index, dmfep->rx.n_desc);
		desc0 = dmfe_ring_get32(descp, index, DESC0);
	}

	/*
	 * Remember where to start looking next time ...
	 */
	dmfep->rx.next_free = index;

	/*
	 * sync the receive descriptors that we've given back
	 * (actually, we sync all of them for simplicity), and
	 * wake the chip in case it had suspended receive
	 */
	DMA_SYNC(descp, DDI_DMA_SYNC_FORDEV);
	dmfe_chip_put32(dmfep, RX_POLL_REG, 0);

	mutex_exit(dmfep->rxlock);
	return (head);
}

/*
 * Take a chain of mblks (as returned by dmfe_getp() above) and pass
 * them up to gld_recv() one at a time. This function should be called
 * with *no* driver-defined locks held.
 *
 * If the driver is compiled with VLAN support enabled, this function
 * also deals with routing vlan-tagged packets to the appropriate GLD
 * entry point (gld_recv_tagged()).
 */
static void
dmfe_passup_chain(gld_mac_info_t  *macinfo, mblk_t *mp)
{
	mblk_t *next;
	uint32_t vtag;

	ASSERT(mp != NULL);

	do {
		next = mp->b_next;
		mp->b_next = NULL;
#if	!defined(VLAN_VID_NONE)
		gld_recv(macinfo, mp);
#else
		vtag = PTRTOU32(mp->b_cont);
		mp->b_cont = NULL;
		if (vtag != VLAN_VTAG_NONE && gld_recv_tagged != NULL)
			gld_recv_tagged(macinfo, mp, vtag);
		else
			gld_recv(macinfo, mp);
#endif	/* defined(VLAN_VID_NONE) */
		mp = next;
	} while (mp != NULL);
}

#undef	DMFE_DBG


/*
 * ========== Primary TX side routines ==========
 */

#define	DMFE_DBG	DMFE_DBG_SEND	/* debug flag for this code	*/

/*
 *	TX ring management:
 *
 *	There are <tx.n_desc> entries in the ring, of which those from
 *	<tx.next_free> round to but not including <tx.next_busy> must
 *	be owned by the CPU.  The number of such entries should equal
 *	<tx.n_free>; but there may also be some more entries which the
 *	chip has given back but which we haven't yet accounted for.
 *	The routine dmfe_reclaim_tx_desc() adjusts the indexes & counts
 *	as it discovers such entries.
 *
 *	Initially, or when the ring is entirely free:
 *		C = Owned by CPU
 *		D = Owned by Davicom (DMFE) chip
 *
 *	tx.next_free					tx.n_desc = 16
 *	  |
 *	  v
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	| C | C | C | C | C | C | C | C | C | C | C | C | C | C | C | C |
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	  ^
 *	  |
 *	tx.next_busy					tx.n_free = 16
 *
 *	On entry to reclaim() during normal use:
 *
 *					tx.next_free	tx.n_desc = 16
 *					      |
 *					      v
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	| C | C | C | C | C | C | D | D | D | C | C | C | C | C | C | C |
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *		  ^
 *		  |
 *		tx.next_busy				tx.n_free = 9
 *
 *	On exit from reclaim():
 *
 *					tx.next_free	tx.n_desc = 16
 *					      |
 *					      v
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	| C | C | C | C | C | C | D | D | D | C | C | C | C | C | C | C |
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *				  ^
 *				  |
 *			     tx.next_busy		tx.n_free = 13
 *
 *	The ring is considered "full" when only one entry is owned by
 *	the CPU; thus <tx.n_free> should always be >= 1.
 *
 *			tx.next_free			tx.n_desc = 16
 *			      |
 *			      v
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	| D | D | D | D | D | C | D | D | D | D | D | D | D | D | D | D |
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *				  ^
 *				  |
 *			     tx.next_busy		tx.n_free = 1
 */

/*
 * Function to update transmit statistics on various errors
 */
static void
dmfe_update_tx_stats(dmfe_t *dmfep, uint32_t desc0)
{
	uint32_t collisions;
	uint32_t errbits;
	uint32_t errsum;

	ASSERT(mutex_owned(dmfep->txlock));

	collisions = ((desc0 >> 3) & 0x0f);
	errsum = desc0 & TX_ERR_SUMMARY;
	errbits = desc0 & (TX_UNDERFLOW | TX_LATE_COLL | TX_CARRIER_LOSS |
				TX_NO_CARRIER | TX_EXCESS_COLL | TX_JABBER_TO);
	if ((errsum == 0) != (errbits == 0)) {
		dmfe_log(dmfep, "dubious TX error status 0x%x", desc0);
		desc0 |= TX_ERR_SUMMARY;
	}

	if (desc0 & TX_ERR_SUMMARY) {
		dmfep->tx_stats_errxmt += 1;

		/*
		 * If we ever see a transmit jabber timeout, we count it
		 * as a MAC-level transmit error; but we probably won't
		 * see it as it causes an Abnormal interrupt and we reset
		 * the chip in order to recover
		 */
		if (desc0 & TX_JABBER_TO)
			dmfep->tx_stats_mac_xmt_error += 1;

		if (desc0 & TX_UNDERFLOW)
			dmfep->tx_stats_underflow += 1;
		else if (desc0 & TX_LATE_COLL)
			dmfep->tx_stats_xmtlatecoll += 1;

		if (desc0 & (TX_CARRIER_LOSS | TX_NO_CARRIER))
			dmfep->tx_stats_nocarrier += 1;

		if (desc0 & TX_EXCESS_COLL) {
			dmfep->tx_stats_excoll += 1;
			collisions = 16;
		}
	}

	if (collisions == 1)
		dmfep->tx_stats_first_coll += 1;
	else if (collisions != 0)
		dmfep->tx_stats_multi_coll += 1;
	dmfep->tx_stats_collisions += collisions;

	if (desc0 & TX_DEFERRED)
		dmfep->tx_stats_defer += 1;
}

/*
 * Reclaim all the ring entries that the chip has returned to us ...
 *
 * Returns B_FALSE if no entries could be reclaimed.  Otherwise, reclaims
 * as many as possible, restarts the TX stall timeout, and returns B_TRUE.
 */
static boolean_t
dmfe_reclaim_tx_desc(dmfe_t *dmfep)
{
	dma_area_t *descp;
	uint32_t desc0;
	uint32_t desc1;
	int nfree;
	int i;

	DMFE_TRACE(("dmfe_reclaim_tx_desc($%p)", (void *)dmfep));

	ASSERT(mutex_owned(dmfep->txlock));

	/*
	 * sync transmit descriptor ring before looking at it
	 */
	descp = &dmfep->tx_desc;
	DMA_SYNC(descp, DDI_DMA_SYNC_FORKERNEL);

#if	DMFEDEBUG
	/*
	 * check that we own all descriptors from next_free to next_used-1
	 */
	nfree = 0;
	i = dmfep->tx.next_free;
	do {
		ASSERT((dmfe_ring_get32(descp, i, DESC0) & TX_OWN) == 0);
		nfree += 1;
		i = NEXT(i, dmfep->tx.n_desc);
	} while (i != dmfep->tx.next_busy);
	ASSERT(nfree == dmfep->tx.n_free);
#endif	/* DMFEDEBUG */

	/*
	 * Early exit if there are no descriptors to reclaim, either
	 * because they're all reclaimed already, or because the next
	 * one is still owned by the chip ...
	 */
	i = dmfep->tx.next_busy;
	if (i == dmfep->tx.next_free)
		return (B_FALSE);
	desc0 = dmfe_ring_get32(descp, i, DESC0);
	if (desc0 & TX_OWN)
		return (B_FALSE);

	/*
	 * Reclaim as many descriptors as possible ...
	 */
	for (;;) {
		desc1 = dmfe_ring_get32(descp, i, DESC1);
		ASSERT((desc1 & (TX_SETUP_PACKET | TX_LAST_DESC)) != 0);

		if (desc1 & TX_SETUP_PACKET) {
			/*
			 * Setup packet - restore buffer address
			 */
			ASSERT(dmfe_ring_get32(descp, i, BUFFER1) ==
			    descp->setup_dvma);
			dmfe_ring_put32(descp, i, BUFFER1,
			    dmfep->tx_buff.mem_dvma + i*DMFE_BUF_SIZE);
		} else {
			/*
			 * Regular packet - just update stats
			 */
			ASSERT(dmfe_ring_get32(descp, i, BUFFER1) ==
			    dmfep->tx_buff.mem_dvma + i*DMFE_BUF_SIZE);
			dmfe_update_tx_stats(dmfep, desc0);
		}

#if	DMFEDEBUG
		/*
		 * We can use one of the SPARE bits in the TX descriptor
		 * to track when a ring buffer slot is reclaimed.  Then
		 * we can deduce the last operation on a slot from the
		 * top half of DESC0:
		 *
		 *	0x8000 xxxx	given to DMFE chip (TX_OWN)
		 *	0x7fff xxxx	returned but not yet reclaimed
		 *	0x3fff xxxx	reclaimed
		 */
#define	TX_PEND_RECLAIM		(1UL<<30)
		dmfe_ring_put32(descp, i, DESC0, desc0 & ~TX_PEND_RECLAIM);
#endif	/* DMFEDEBUG */

		/*
		 * Update count & index; we're all done if the ring is
		 * now fully reclaimed, or the next entry if still owned
		 * by the chip ...
		 */
		dmfep->tx.n_free += 1;
		i = NEXT(i, dmfep->tx.n_desc);
		if (i == dmfep->tx.next_free)
			break;
		desc0 = dmfe_ring_get32(descp, i, DESC0);
		if (desc0 & TX_OWN)
			break;
	}

	dmfep->tx.next_busy = i;
	dmfep->tx_pending_tix = 0;
	return (B_TRUE);
}

/*
 * Send the message in the message block chain <mp>.
 *
 * The message is freed if and only if its contents are successfully copied
 * and queued for transmission (so that the return value is GLD_SUCCESS).
 * If we can't queue the message, the return value is GLD_NORESOURCES and
 * the message is *not* freed.
 *
 * This routine handles the special case of <mp> == NULL, which indicates
 * that we want to "send" the special "setup packet" allocated during
 * startup.  We have to use some different flags in the packet descriptor
 * to say its a setup packet (from the global <dmfe_setup_desc1>), and the
 * setup packet *isn't* freed after use.
 */
static int
dmfe_send_msg(dmfe_t *dmfep, mblk_t *mp, uint32_t vtag)
{
	dma_area_t *descp;
	mblk_t *bp;
	char *txb;
	uint32_t desc1;
	uint32_t index;
	size_t totlen;
	size_t mblen;

	DMFE_TRACE(("dmfe_send_msg($%p, $%p, 0x%x)",
		(void *)dmfep, (void *)mp, vtag));

	/*
	 * If the number of free slots is below the reclaim threshold
	 * (soft limit), we'll try to reclaim some.  If we fail, and
	 * the number of free slots is also below the minimum required
	 * (the hard limit, usually 1), then we can't send the packet.
	 */
	mutex_enter(dmfep->txlock);
	if (dmfep->tx.n_free <= dmfe_tx_reclaim_level &&
	    dmfe_reclaim_tx_desc(dmfep) == B_FALSE &&
	    dmfep->tx.n_free <= dmfe_tx_min_free) {
		/*
		 * Resource shortage - return the proper GLD code,
		 * so the packet will be queued for retry after the
		 * next TX-done interrupt.
		 */
		mutex_exit(dmfep->txlock);
		DMFE_DEBUG(("dmfe_send_msg: no free descriptors"));
		return (GLD_NORESOURCES);
	}

	/*
	 * There's a slot available, so claim it by incrementing
	 * the next-free index and decrementing the free count.
	 * If the ring is currently empty, we also restart the
	 * stall-detect timer.  The ASSERTions check that our
	 * invariants still hold:
	 *	the next-free index must not match the next-busy index
	 *	there must still be at least one free entry
	 * After this, we now have exclusive ownership of the ring
	 * entry (and matching buffer) indicated by <index>, so we
	 * don't need to hold the TX lock any longer
	 */
	index = dmfep->tx.next_free;
	dmfep->tx.next_free = NEXT(index, dmfep->tx.n_desc);
	ASSERT(dmfep->tx.next_free != dmfep->tx.next_busy);
	if (dmfep->tx.n_free-- == dmfep->tx.n_desc)
		dmfep->tx_pending_tix = 0;
	ASSERT(dmfep->tx.n_free >= 1);
	mutex_exit(dmfep->txlock);

	/*
	 * Check the ownership of the ring entry ...
	 */
	descp = &dmfep->tx_desc;
	ASSERT((dmfe_ring_get32(descp, index, DESC0) & TX_OWN) == 0);

	if (mp == NULL) {
		/*
		 * Indicates we should send a SETUP packet, which we do by
		 * temporarily switching the BUFFER1 pointer in the ring
		 * entry.  The reclaim routine will restore BUFFER1 to its
		 * usual value.
		 *
		 * Note that as the setup packet is tagged on the end of
		 * the TX ring, when we sync the descriptor we're also
		 * implicitly syncing the setup packet - hence, we don't
		 * need a separate ddi_dma_sync() call here.
		 */
		desc1 = dmfe_setup_desc1;
		dmfe_ring_put32(descp, index, BUFFER1, descp->setup_dvma);
	} else {
		/*
		 * A regular packet; we copy the data into a pre-mapped
		 * buffer, which avoids the overhead (and complication)
		 * of mapping/unmapping STREAMS buffers and keeping hold
		 * of them until the DMA has completed.
		 *
		 * Because all buffers are the same size, and larger
		 * than the longest single valid message, we don't have
		 * to bother about splitting the message across multiple
		 * buffers.
		 */
		txb = &dmfep->tx_buff.mem_va[index*DMFE_BUF_SIZE];
		totlen = 0;
		bp = mp;

#if	defined(VLAN_VID_NONE)
		if (vtag != VLAN_VTAG_NONE) {
			/*
			 * A tagged packet.  While copying the data from
			 * the first mblk into the Tx buffer, insert the
			 * vtag.  IP and/or GLD have already guaranteed
			 * that the entire struct ether_header (14 bytes)
			 * at the start of the packet can be found in the
			 * first mblk, so we don't have to worry about it
			 * being split into multiple fragments.
			 *
			 * The magic number (2*ETHERADDRL) appears quite a
			 * lot here, because the vtag comes immediately after
			 * the destination & source Ethernet addresses in
			 * the packet header.
			 *
			 * The way we allocated the buffers guarantees
			 * their alignment, so it's safe to stash the vtag
			 * directly into the buffer at the proper offset
			 * (4 bytes, 12 bytes into the frame).
			 *
			 * Once we have copied the data from the first mblk,
			 * we can fall through to the untagged packet code
			 * to handle the rest of the chain, if any.
			 */
			mblen = bp->b_wptr - bp->b_rptr;
			ASSERT(mblen >= sizeof (struct ether_header));

			bcopy(bp->b_rptr, txb, 2*ETHERADDRL);
			txb += 2*ETHERADDRL;
			totlen += 2*ETHERADDRL;
			mblen -= 2*ETHERADDRL;

			*(uint32_t *)txb = vtag;
			txb += VTAG_SIZE;
			totlen += VTAG_SIZE;

			bcopy(bp->b_rptr + 2*ETHERADDRL, txb, mblen);
			txb += mblen;
			totlen += mblen;

			bp = bp->b_cont;
		}
#endif	/* defined(VLAN_VID_NONE) */

		/*
		 * Copy all (remaining) mblks in the message ...
		 */
		for (; bp != NULL; bp = bp->b_cont) {
			mblen = bp->b_wptr - bp->b_rptr;
			if ((totlen += mblen) <= DMFE_MAX_PKT_SIZE) {
				bcopy(bp->b_rptr, txb, mblen);
				txb += mblen;
			}
		}

		/*
		 * We'e reached the end of the chain; and we should have
		 * collected no more than DMFE_MAX_PKT_SIZE bytes into our
		 * buffer.  Note that the <size> field in the descriptor is
		 * only 11 bits, so bigger packets would be a problem!
		 */
		ASSERT(bp == NULL);
		ASSERT(totlen <= DMFE_MAX_PKT_SIZE);
		totlen &= TX_BUFFER_SIZE1;
		desc1 = TX_FIRST_DESC | TX_LAST_DESC | totlen;

		(void) ddi_dma_sync(dmfep->tx_buff.dma_hdl,
			index*DMFE_BUF_SIZE, DMFE_BUF_SIZE,
			DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Update ring descriptor entries, sync them, and wake up the
	 * transmit process
	 */
	if ((index & dmfe_tx_int_factor) == 0)
		desc1 |= TX_INT_ON_COMP;
	desc1 |= TX_CHAINING;
	dmfe_ring_put32(descp, index, DESC1, desc1);
	dmfe_ring_put32(descp, index, DESC0, TX_OWN);
	DMA_SYNC(descp, DDI_DMA_SYNC_FORDEV);
	dmfe_chip_put32(dmfep, TX_POLL_REG, 0);

	/*
	 * Finally, free the message & return success
	 */
	if (mp)
		freemsg(mp);
	return (GLD_SUCCESS);
}

/*
 *	dmfe_gld_send() -- send a packet
 *
 *	Called when a packet is ready to be transmitted. A pointer to an
 *	M_DATA message that contains the packet is passed to this routine.
 *	The complete LLC header is contained in the message's first message
 *	block, and the remainder of the packet is contained within
 *	additional M_DATA message blocks linked to the first message block.
 */
static int
dmfe_gld_send(gld_mac_info_t *macinfo, mblk_t *mp)
{
	dmfe_t *dmfep;			/* private device info	*/

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_send($%p, $%p)",
		(void *)macinfo, (void *)mp));

	ASSERT(mp != NULL);
	ASSERT(dmfep->gld_state == GLD_STARTED);

	if (dmfep->chip_state != CHIP_RUNNING)
		return (GLD_NORESOURCES);

	return (dmfe_send_msg(dmfep, mp, VLAN_VTAG_NONE));
}

#if	defined(VLAN_VID_NONE)
/*
 *	dmfe_gld_send_tagged() -- send a tagged packet
 *
 *	Called when a packet is ready to be transmitted. A pointer to an
 *	M_DATA message that contains the packet is passed to this routine.
 *	The complete LLC header is contained in the message's first message
 *	block, and the remainder of the packet is contained within
 *	additional M_DATA message blocks linked to the first message block.
 */
static int
dmfe_gld_send_tagged(gld_mac_info_t *macinfo, mblk_t *mp, uint32_t vtag)
{
	dmfe_t *dmfep;			/* private device info	*/

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_send_vtag($%p, $%p, $%x)",
		(void *)macinfo, (void *)mp, vtag));

	ASSERT(mp != NULL);
	ASSERT(dmfep->gld_state == GLD_STARTED);

	if (dmfep->chip_state != CHIP_RUNNING)
		return (GLD_NORESOURCES);

	return (dmfe_send_msg(dmfep, mp, vtag));
}
#endif	/* defined(VLAN_VID_NONE) */


#undef	DMFE_DBG


/*
 * ========== Address-setting routines (TX-side) ==========
 */

#define	DMFE_DBG	DMFE_DBG_ADDR	/* debug flag for this code	*/

/*
 * Find the index of the relevant bit in the setup packet.
 * This must mirror the way the hardware will actually calculate it!
 */
static uint32_t
dmfe_hash_index(uchar_t *address)
{
	uint32_t const POLY = HASH_POLY;
	uint32_t crc = HASH_CRC;
	uint32_t index;
	uint32_t msb;
	uchar_t currentbyte;
	int byteslength;
	int shift;
	int bit;

	for (byteslength = 0; byteslength < ETHERADDRL; ++byteslength) {
		currentbyte = address[byteslength];
		for (bit = 0; bit < 8; ++bit) {
			msb = crc >> 31;
			crc <<= 1;
			if (msb ^ (currentbyte & 1)) {
				crc ^= POLY;
				crc |= 0x00000001;
			}
			currentbyte >>= 1;
		}
	}

	for (index = 0, bit = 23, shift = 8; shift >= 0; ++bit, --shift)
		index |= (((crc >> bit) & 1) << shift);

	return (index);
}

/*
 * Find and set/clear the relevant bit in the setup packet hash table
 * This must mirror the way the hardware will actually interpret it!
 */
static void
dmfe_update_hash(dmfe_t *dmfep, uint32_t index, boolean_t val)
{
	dma_area_t *descp;
	uint32_t tmp;

	ASSERT(mutex_owned(dmfep->oplock));

	descp = &dmfep->tx_desc;
	tmp = dmfe_setup_get32(descp, index/16);
	if (val)
		tmp |= 1 << (index%16);
	else
		tmp &= ~(1 << (index%16));
	dmfe_setup_put32(descp, index/16, tmp);
}

/*
 * Update the refcount for the bit in the setup packet corresponding
 * to the specified address; if it changes between zero & nonzero,
 * also update the bitmap itself & return B_TRUE, so that the caller
 * knows to re-send the setup packet.  Otherwise (only the refcount
 * changed), return B_FALSE
 */
static boolean_t
dmfe_update_mcast(dmfe_t *dmfep, uchar_t *mca, boolean_t val, const char *what)
{
	uint32_t index;
	uint8_t *refp;
	uint8_t oldref;
	boolean_t change;

	index = dmfe_hash_index(mca);
	refp = &dmfep->mcast_refs[index];
	oldref = *refp;
	change = (val ? (*refp)++ : --(*refp)) == 0;

	DMFE_DEBUG(("dmfe_update_mcast: %s %s %s index %d ref %d->%d%s",
		ether_sprintf((void *)mca), val ? "ON" : "OFF", what,
		index, oldref, *refp, change ? " (CHANGED)" : ""));

	if (change)
		dmfe_update_hash(dmfep, index, val);

	return (change);
}

/*
 * "Transmit" the (possibly updated) magic setup packet
 */
static int
dmfe_send_setup(dmfe_t *dmfep)
{
	int status;

	DMFE_TRACE(("dmfe_send_setup($%p)", (void *)dmfep));

	ASSERT(mutex_owned(dmfep->oplock));

	/*
	 * If the chip isn't running, we can't really send the setup frame
	 * now but it doesn't matter, 'cos it will be sent when the transmit
	 * process is restarted (see dmfe_start()).  It isn't an error; in
	 * fact, GLD v2 will always call dmfe_gld_set_mac_addr() after a
	 * reset, so that the address can be set up before the chip is
	 * started.  In this context, the return code GLD_NOTSUPPORTED is
	 * taken as success!
	 */
	if ((dmfep->opmode & START_TRANSMIT) == 0)
		return (GLD_NOTSUPPORTED);

	/*
	 * "Send" the setup frame.  If it fails (e.g. no resources),
	 * set a flag; then the factotum will retry the "send".  Once
	 * it works, we can clear the flag no matter how many attempts
	 * had previously failed.  We tell the caller that it worked
	 * whether it did or not; after all, it *will* work eventually.
	 */
	status = dmfe_send_msg(dmfep, NULL, VLAN_VTAG_NONE);
	dmfep->need_setup = status != GLD_SUCCESS;
	return (GLD_SUCCESS);
}

/*
 *	dmfe_gld_set_mac_addr() -- set the physical network address
 */
static int
dmfe_gld_set_mac_addr(gld_mac_info_t *macinfo, uchar_t *macaddr)
{
	dmfe_t *dmfep;			/* private device info	*/
	int status;
	int index;

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_set_mac_addr($%p, %s)",
		(void *)macinfo, ether_sprintf((void *)macaddr)));

	/*
	 * Update our current address and send out a new setup packet
	 *
	 * Here we accommodate the use of HASH_ONLY or HASH_AND_PERFECT
	 * filtering modes (we don't support PERFECT_ONLY or INVERSE modes).
	 *
	 * It is said that there is a bug in the 21140 where it fails to
	 * receive packes addresses to the specified perfect filter address.
	 * If the same bug is present in the DM9102A, the TX_FILTER_TYPE1
	 * bit should be set in the module variable dmfe_setup_desc1.
	 *
	 * If TX_FILTER_TYPE1 is set, we will use HASH_ONLY filtering.
	 * In this mode, *all* incoming addresses are hashed and looked
	 * up in the bitmap described by the setup packet.  Therefore,
	 * the bit representing the station address has to be added to
	 * the table before sending it out.  If the address is changed,
	 * the old entry should be removed before the new entry is made.
	 *
	 * NOTE: in this mode, unicast packets that are not intended for
	 * this station may be received; it is up to software to filter
	 * them out afterwards!
	 *
	 * If TX_FILTER_TYPE1 is *not* set, we will use HASH_AND_PERFECT
	 * filtering.  In this mode, multicast addresses are hashed and
	 * checked against the bitmap, while unicast addresses are simply
	 * matched against the one physical address specified in the setup
	 * packet.  This means that we shouldn't receive unicast packets
	 * that aren't intended for us (but software still has to filter
	 * multicast packets just the same).
	 *
	 * Whichever mode we're using, we have to enter the broadcast
	 * address into the multicast filter map too, so we do this on
	 * the first time through after attach or reset.
	 */
	mutex_enter(dmfep->oplock);

	if (dmfep->addr_set && dmfe_setup_desc1 & TX_FILTER_TYPE1)
		(void) dmfe_update_mcast(dmfep, dmfep->curr_addr, B_FALSE,
			    "xaddr");
	if (dmfe_setup_desc1 & TX_FILTER_TYPE1)
		(void) dmfe_update_mcast(dmfep, macaddr, B_TRUE, "saddr");
	if (!dmfep->addr_set)
		(void) dmfe_update_mcast(dmfep, dmfe_broadcast_addr, B_TRUE,
			    "bcast");

	/*
	 * Remember the new current address
	 */
	ethaddr_copy(macaddr, dmfep->curr_addr);
	dmfep->addr_set = B_TRUE;

	/*
	 * Install the new physical address into the proper position in
	 * the setup frame; this is only used if we select hash+perfect
	 * filtering, but we'll put it in anyway.  The ugliness here is
	 * down to the usual war of the egg :(
	 */
	for (index = 0; index < ETHERADDRL; index += 2)
		dmfe_setup_put32(&dmfep->tx_desc, SETUPBUF_PHYS+index/2,
			(macaddr[index+1] << 8) | macaddr[index]);

	/*
	 * Finally, we're ready to "transmit" the setup frame
	 */
	status = dmfe_send_setup(dmfep);
	mutex_exit(dmfep->oplock);

	return (status);
}

/*
 *	dmfe_gld_set_multicast() -- enable or disable a multicast address
 *
 *	Program the hardware to enable/disable the multicast address
 *	in "mca" (enable if "flag" is GLD_MULTI_ENABLE, otherwise disable).
 *	We keep a refcount for each bit in the map, so that it still
 *	works out properly if multiple addresses hash to the same bit.
 *	dmfe_update_mcast() tells us whether the map actually changed;
 *	if so, we have to re-"transmit" the magic setup packet.
 */
static int
dmfe_gld_set_multicast(gld_mac_info_t *macinfo, uchar_t *mca, int flag)
{
	dmfe_t *dmfep;			/* private device info	*/
	int status;

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_set_multicast($%p, %s, %d)",
		(void *)macinfo, ether_sprintf((void *)mca), flag));

	status = GLD_SUCCESS;
	mutex_enter(dmfep->oplock);
	if (dmfe_update_mcast(dmfep, mca, flag == GLD_MULTI_ENABLE, "mcast"))
		status = dmfe_send_setup(dmfep);
	mutex_exit(dmfep->oplock);

	return (status);
}

#undef	DMFE_DBG


/*
 * ========== Internal state management entry points ==========
 */

#define	DMFE_DBG	DMFE_DBG_GLD	/* debug flag for this code	*/

/*
 * These routines provide all the functionality required by the
 * corresponding GLD entry points, but don't update the GLD state
 * so they can be called internally without disturbing our record
 * of what GLD thinks we should be doing ...
 */

/*
 *	dmfe_stop() -- stop processing, don't reset h/w or rings
 */
static void
dmfe_stop(dmfe_t *dmfep)
{
	DMFE_TRACE(("dmfe_stop($%p)", (void *)dmfep));

	ASSERT(mutex_owned(dmfep->oplock));

	dmfe_stop_chip(dmfep, CHIP_STOPPED);
}

/*
 *	dmfe_reset() -- stop processing, reset h/w & rings to initial state
 */
static void
dmfe_reset(dmfe_t *dmfep)
{
	DMFE_TRACE(("dmfe_reset($%p)", (void *)dmfep));

	ASSERT(mutex_owned(dmfep->oplock));
	ASSERT(mutex_owned(dmfep->rxlock));
	ASSERT(mutex_owned(dmfep->txlock));

	dmfe_stop_chip(dmfep, CHIP_RESET);
	dmfe_init_rings(dmfep);
}

/*
 *	dmfe_start() -- start transmitting/receiving
 */
static void
dmfe_start(dmfe_t *dmfep)
{
	uint32_t gpsr;

	DMFE_TRACE(("dmfe_start($%p)", (void *)dmfep));

	ASSERT(mutex_owned(dmfep->oplock));

	ASSERT(dmfep->chip_state == CHIP_RESET ||
		dmfep->chip_state == CHIP_STOPPED);

	/*
	 * Make opmode consistent with PHY duplex setting
	 */
	gpsr = dmfe_chip_get32(dmfep, PHY_STATUS_REG);
	if (gpsr & GPS_FULL_DUPLEX)
		dmfep->opmode |= FULL_DUPLEX;
	else
		dmfep->opmode &= ~FULL_DUPLEX;

	/*
	 * Start transmit processing
	 * Set up the address filters
	 * Start receive processing
	 * Enable interrupts
	 */
	dmfe_start_chip(dmfep, START_TRANSMIT);
	(void) dmfe_send_setup(dmfep);
	drv_usecwait(10);
	dmfe_start_chip(dmfep, START_RECEIVE);
	dmfe_enable_interrupts(dmfep);
}

/*
 * dmfe_restart - restart transmitting/receiving after error or suspend
 */
static void
dmfe_restart(dmfe_t *dmfep)
{
	ASSERT(mutex_owned(dmfep->oplock));

	/*
	 * You need not only <oplock>, but also <rxlock> AND <txlock>
	 * in order to reset the rings, but then <txlock> *mustn't*
	 * be held across the call to dmfe_start()
	 */
	mutex_enter(dmfep->rxlock);
	mutex_enter(dmfep->txlock);
	dmfe_reset(dmfep);
	mutex_exit(dmfep->txlock);
	mutex_exit(dmfep->rxlock);
	if (dmfep->gld_state == GLD_STARTED)
		dmfe_start(dmfep);
}


/*
 * ========== GLD-required management entry points ==========
 */

/*
 *	dmfe_gld_reset() -- reset to initial state
 */
static int
dmfe_gld_reset(gld_mac_info_t *macinfo)
{
	dmfe_t *dmfep;			/* private device info	*/

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_reset($%p)", (void *)macinfo));

	/*
	 * Reset chip & rings to initial state; also reset address
	 * filtering & record new GLD state.  You need *all* the locks
	 * in order to stop all other activity while doing this!
	 */
	mutex_enter(dmfep->oplock);
	mutex_enter(dmfep->rxlock);
	mutex_enter(dmfep->txlock);

	dmfe_reset(dmfep);
	bzero(dmfep->tx_desc.setup_va, SETUPBUF_SIZE);
	bzero(dmfep->mcast_refs, MCASTBUF_SIZE);
	dmfep->addr_set = B_FALSE;
	dmfep->opmode &= ~(PROMISC_MODE | PASS_MULTICAST);
	dmfep->gld_state = GLD_RESET;

	mutex_exit(dmfep->txlock);
	mutex_exit(dmfep->rxlock);
	mutex_exit(dmfep->oplock);

	return (0);
}

/*
 *	dmfe_gld_stop() -- stop transmitting/receiving
 */
static int
dmfe_gld_stop(gld_mac_info_t *macinfo)
{
	dmfe_t *dmfep;			/* private device info	*/

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_stop($%p)", (void *)macinfo));

	/*
	 * Just stop processing, then record new GLD state
	 */
	mutex_enter(dmfep->oplock);
	dmfe_stop(dmfep);
	dmfep->gld_state = GLD_STOPPED;
	mutex_exit(dmfep->oplock);

	return (0);
}

/*
 *	dmfe_gld_start() -- start transmitting/receiving
 */
static int
dmfe_gld_start(gld_mac_info_t *macinfo)
{
	dmfe_t *dmfep;			/* private device info	*/

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_start($%p)", (void *)macinfo));

	/*
	 * Start processing and record new GLD state
	 */
	mutex_enter(dmfep->oplock);
	dmfe_start(dmfep);
	dmfep->gld_state = GLD_STARTED;
	mutex_exit(dmfep->oplock);

	return (0);
}

/*
 * dmfe_gld_set_promiscuous() -- set or reset promiscuous mode on the board
 *
 *	Program the hardware to enable/disable promiscuous and/or
 *	receive-all-multicast modes.  Davicom don't document this
 *	clearly, but it looks like we can do this on-the-fly (i.e.
 *	without stopping & restarting the TX/RX processes).
 */
static int
dmfe_gld_set_promiscuous(gld_mac_info_t *macinfo, int mode)
{
	dmfe_t *dmfep;
	uint32_t pmode;

	dmfep = DMFE_STATE(macinfo);
	DMFE_TRACE(("dmfe_gld_set_promiscuous($%p, %d)",
		(void *)macinfo, mode));

	/*
	 * Convert GLD-specified mode to DMFE opmode setting
	 */
	switch (mode) {
	case GLD_MAC_PROMISC_NONE:
		pmode = 0;
		break;

	case GLD_MAC_PROMISC_MULTI:
		pmode = PASS_MULTICAST;
		break;

	case GLD_MAC_PROMISC_PHYS:
		pmode = PROMISC_MODE;
		break;

	default:
		return (GLD_NOTSUPPORTED);
	}

	mutex_enter(dmfep->oplock);
	dmfep->opmode &= ~(PROMISC_MODE | PASS_MULTICAST);
	dmfep->opmode |= pmode;
	dmfe_set_opmode(dmfep);
	pmode = dmfep->opmode;
	mutex_exit(dmfep->oplock);

	DMFE_DEBUG(("dmfe_gld_set_promiscuous: mode %d => opmode 0x%x",
		mode, pmode));

	return (GLD_SUCCESS);
}

#undef	DMFE_DBG


/*
 * ========== Factotum, implemented as a softint handler ==========
 */

#define	DMFE_DBG	DMFE_DBG_FACT	/* debug flag for this code	*/

/*
 * The factotum is woken up when there's something to do that we'd rather
 * not do from inside a (high-level?) hardware interrupt handler.  Its
 * two main tasks are:
 *	reset & restart the chip after an error
 *	update & restart the chip after a link status change
 */
static uint_t
dmfe_factotum(caddr_t arg)
{
	dmfe_t *dmfep;

	dmfep = (dmfe_t *)arg;
	ASSERT(dmfep->dmfe_guard == DMFE_GUARD);

	mutex_enter(dmfep->oplock);

	dmfep->factotum_flag = 0;
	DRV_KS_INC(dmfep, KS_FACTOTUM_RUN);

	/*
	 * Check for chip error ...
	 */
	if (dmfep->chip_state == CHIP_ERROR) {
		/*
		 * Error recovery required: reset the chip and the rings,
		 * then, if it's supposed to be running, kick it off again.
		 */
		DRV_KS_INC(dmfep, KS_RECOVERY);
		dmfe_restart(dmfep);
	} else if (dmfep->need_setup) {
		(void) dmfe_send_setup(dmfep);
	}
	mutex_exit(dmfep->oplock);

	/*
	 * Then, check the link state.  We need <milock> but not <oplock>
	 * to do this, but if something's changed, we need <oplock> as well
	 * in order to stop/restart the chip!  Note: we could simply hold
	 * <oplock> right through here, but we'd rather not 'cos checking
	 * the link state involves reading over the bit-serial MII bus,
	 * which takes ~500us even when nothing's changed.  Holding <oplock>
	 * would lock out the interrupt handler for the duration, so it's
	 * better to release it first and reacquire it only if needed.
	 */
	mutex_enter(dmfep->milock);
	if (dmfe_check_link(dmfep)) {
		mutex_enter(dmfep->oplock);
		dmfe_stop(dmfep);
		DRV_KS_INC(dmfep, KS_LINK_CHECK);
		if (dmfep->update_phy) {
			/*
			 *  The chip may reset itself for some unknown
			 * reason.  If this happens, the chip will use
			 * default settings (for speed, duplex, and autoneg),
			 * which possibly aren't the user's desired settings.
			 */
			dmfe_update_phy(dmfep);
			dmfep->update_phy = B_FALSE;
		}
		dmfe_recheck_link(dmfep, B_FALSE);
		if (dmfep->gld_state == GLD_STARTED)
			dmfe_start(dmfep);
		mutex_exit(dmfep->oplock);
	}
	mutex_exit(dmfep->milock);

	/*
	 * Keep GLD up-to-date about the state of the link ...
	 */
	if (gld_linkstate != NULL)
		gld_linkstate(DMFE_MACINFO(dmfep),
			dmfep->link_state == LINK_UP ?
				GLD_LINKSTATE_UP : GLD_LINKSTATE_DOWN);

	return (DDI_INTR_CLAIMED);
}

static void
dmfe_wake_factotum(dmfe_t *dmfep, int ks_id, const char *why)
{
	DMFE_DEBUG(("dmfe_wake_factotum: %s [%d] flag %d",
		why, ks_id, dmfep->factotum_flag));

	ASSERT(mutex_owned(dmfep->oplock));
	DRV_KS_INC(dmfep, ks_id);

	if (dmfep->factotum_flag++ == 0)
		ddi_trigger_softintr(dmfep->factotum_id);
}

#undef	DMFE_DBG


/*
 * ========== Periodic Tasks (Cyclic handler & friends) ==========
 */

#define	DMFE_DBG	DMFE_DBG_TICK	/* debug flag for this code	*/

/*
 * Periodic tick tasks, run from the cyclic handler
 *
 * Check the state of the link and wake the factotum if necessary
 */
static void
dmfe_tick_link_check(dmfe_t *dmfep, uint32_t gpsr, uint32_t istat)
{
	link_state_t phy_state;
	link_state_t utp_state;
	const char *why;
	int ks_id;

	_NOTE(ARGUNUSED(istat))

	ASSERT(mutex_owned(dmfep->oplock));

	/*
	 * Is it time to wake the factotum?  We do so periodically, in
	 * case the fast check below doesn't always reveal a link change
	 */
	if (dmfep->link_poll_tix-- == 0) {
		dmfep->link_poll_tix = factotum_tix;
		why = "tick (link poll)";
		ks_id = KS_TICK_LINK_POLL;
	} else {
		why = NULL;
		ks_id = KS_TICK_LINK_STATE;
	}

	/*
	 * Has the link status changed?  If so, we might want to wake
	 * the factotum to deal with it.
	 */
	phy_state = (gpsr & GPS_LINK_STATUS) ? LINK_UP : LINK_DOWN;
	utp_state = (gpsr & GPS_UTP_SIG) ? LINK_UP : LINK_DOWN;
	if (phy_state != utp_state)
		why = "tick (phy <> utp)";
	else if (dmfep->link_state == LINK_UP && phy_state == LINK_DOWN)
		why = "tick (UP -> DOWN)";
	else if (phy_state != dmfep->link_state) {
		if (dmfep->link_poll_tix > factotum_fast_tix)
			dmfep->link_poll_tix = factotum_fast_tix;
	}

	if (why != NULL) {
		DMFE_DEBUG(("dmfe_%s: link %d phy %d utp %d",
			why, dmfep->link_state, phy_state, utp_state));
		dmfe_wake_factotum(dmfep, ks_id, why);
	}
}

/*
 * Periodic tick tasks, run from the cyclic handler
 *
 * Check for TX stall; flag an error and wake the factotum if so.
 */
static void
dmfe_tick_stall_check(dmfe_t *dmfep, uint32_t gpsr, uint32_t istat)
{
	boolean_t tx_stall;
	uint32_t tx_state;
	uint32_t limit;

	ASSERT(mutex_owned(dmfep->oplock));

	/*
	 * Check for transmit stall ...
	 *
	 * IF there's at least one packet in the ring, AND the timeout
	 * has elapsed, AND we can't reclaim any descriptors, THEN we've
	 * stalled; we return B_TRUE to trigger a reset-and-recover cycle.
	 *
	 * Note that the timeout limit is based on the transmit engine
	 * state; we allow the transmitter longer to make progress in
	 * some states than in others, based on observations of this
	 * chip's actual behaviour in the lab.
	 *
	 * By observation, we find that on about 1 in 10000 passes through
	 * here, the TX lock is already held.  In that case, we'll skip
	 * the check on this pass rather than wait.  Most likely, the send
	 * routine was holding the lock when the interrupt happened, and
	 * we'll succeed next time through.  In the event of a real stall,
	 * the TX ring will fill up, after which the send routine won't be
	 * called any more and then we're sure to get in.
	 */
	tx_stall = B_FALSE;
	if (mutex_tryenter(dmfep->txlock)) {
		if (dmfep->tx.n_free < dmfep->tx.n_desc) {
			tx_state = TX_PROCESS_STATE(istat);
			if (gpsr & GPS_LINK_100)
				limit = stall_100_tix[tx_state];
			else
				limit = stall_10_tix[tx_state];
			if (++dmfep->tx_pending_tix >= limit &&
			    dmfe_reclaim_tx_desc(dmfep) == B_FALSE) {
				dmfe_log(dmfep, "TX stall detected "
				    "after %d ticks in state %d; "
				    "automatic recovery initiated",
					dmfep->tx_pending_tix, tx_state);
				tx_stall = B_TRUE;
			}
		}
		mutex_exit(dmfep->txlock);
	}

	if (tx_stall) {
		dmfe_stop_chip(dmfep, CHIP_ERROR);
		dmfe_wake_factotum(dmfep, KS_TX_STALL, "tick (TX stall)");
	}
}

/*
 * Cyclic callback handler
 */
static void
dmfe_cyclic(void *arg)
{
	dmfe_t *dmfep = arg;			/* private device info */
	uint32_t istat;
	uint32_t gpsr;

	/*
	 * If the chip's not RUNNING, there's nothing to do.
	 * If we can't get the mutex straight away, we'll just
	 * skip this pass; we'll back back soon enough anyway.
	 */
	if (dmfep->chip_state != CHIP_RUNNING)
		return;
	if (mutex_tryenter(dmfep->oplock) == 0)
		return;

	/*
	 * Recheck chip state (it might have been stopped since we
	 * checked above).  If still running, call each of the *tick*
	 * tasks.  They will check for link change, TX stall, etc ...
	 */
	if (dmfep->chip_state == CHIP_RUNNING) {
		istat = dmfe_chip_get32(dmfep, STATUS_REG);
		gpsr = dmfe_chip_get32(dmfep, PHY_STATUS_REG);
		dmfe_tick_link_check(dmfep, gpsr, istat);
		dmfe_tick_stall_check(dmfep, gpsr, istat);
	}

	DRV_KS_INC(dmfep, KS_CYCLIC_RUN);
	mutex_exit(dmfep->oplock);
}

#undef	DMFE_DBG


/*
 * ========== Hardware interrupt handler ==========
 */

#define	DMFE_DBG	DMFE_DBG_INT	/* debug flag for this code	*/

/*
 *	dmfe_interrupt() -- handle chip interrupts
 */
static uint_t
dmfe_interrupt(caddr_t arg)
{
	dmfe_t *dmfep;			/* private device info */
	uint32_t interrupts;
	uint32_t istat;
	const char *msg;
	mblk_t *mp;
	boolean_t warning_msg = B_TRUE;

	dmfep = (dmfe_t *)arg;

	/*
	 * A quick check as to whether the interrupt was from this
	 * device, before we even finish setting up all our local
	 * variables.  Note that reading the interrupt status register
	 * doesn't have any unpleasant side effects such as clearing
	 * the bits read, so it's quite OK to re-read it once we have
	 * determined that we are going to service this interrupt and
	 * grabbed the mutexen.
	 */
	istat = dmfe_chip_get32(dmfep, STATUS_REG);
	if ((istat & (NORMAL_SUMMARY_INT | ABNORMAL_SUMMARY_INT)) == 0)
		return (DDI_INTR_UNCLAIMED);

	/*
	 * Unfortunately, there can be a race condition between attach()
	 * adding the interrupt handler and initialising the mutexen,
	 * and the handler itself being called because of a pending
	 * interrupt.  So, we check <imask>; if it shows that interrupts
	 * haven't yet been enabled (and therefore we shouldn't really
	 * be here at all), we will just write back the value read from
	 * the status register, thus acknowledging (and clearing) *all*
	 * pending conditions without really servicing them, and claim
	 * the interrupt.
	 */
	if (dmfep->imask == 0) {
		DMFE_DEBUG(("dmfe_interrupt: early interrupt 0x%x", istat));
		dmfe_chip_put32(dmfep, STATUS_REG, istat);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * We're committed to servicing this interrupt, but we
	 * need to get the lock before going any further ...
	 */
	mutex_enter(dmfep->oplock);
	dmfep->op_stats_intr += 1;

	/*
	 * Identify bits that represent enabled interrupts ...
	 */
	istat |= dmfe_chip_get32(dmfep, STATUS_REG);
	interrupts = istat & dmfep->imask;
	ASSERT(interrupts != 0);

	DMFE_DEBUG(("dmfe_interrupt: istat 0x%x -> 0x%x", istat, interrupts));

	/*
	 * Check for any interrupts other than TX/RX done.
	 * If there are any, they are considered Abnormal
	 * and will cause the chip to be reset.
	 */
	if (interrupts & ~(RX_PKTDONE_INT | TX_PKTDONE_INT)) {
		if (istat & ABNORMAL_SUMMARY_INT) {
			/*
			 * Any Abnormal interrupts will lead to us
			 * resetting the chip, so we don't bother
			 * to clear each interrupt individually.
			 *
			 * Our main task here is to identify the problem,
			 * by pointing out the most significant unexpected
			 * bit.  Additional bits may well be consequences
			 * of the first problem, so we consider the possible
			 * causes in order of severity.
			 */
			if (interrupts & SYSTEM_ERR_INT) {
				switch (istat & SYSTEM_ERR_BITS) {
				case SYSTEM_ERR_M_ABORT:
					msg = "Bus Master Abort";
					break;

				case SYSTEM_ERR_T_ABORT:
					msg = "Bus Target Abort";
					break;

				case SYSTEM_ERR_PARITY:
					msg = "Parity Error";
					break;

				default:
					msg = "Unknown System Bus Error";
					break;
				}
			} else if (interrupts & RX_STOPPED_INT) {
				msg = "RX process stopped";
			} else if (interrupts & RX_UNAVAIL_INT) {
				msg = "RX buffer unavailable";
				warning_msg = B_FALSE;
			} else if (interrupts & RX_WATCHDOG_INT) {
				msg = "RX watchdog timeout?";
			} else if (interrupts & RX_EARLY_INT) {
				msg = "RX early interrupt?";
			} else if (interrupts & TX_STOPPED_INT) {
				msg = "TX process stopped";
			} else if (interrupts & TX_JABBER_INT) {
				msg = "TX jabber timeout";
			} else if (interrupts & TX_UNDERFLOW_INT) {
				msg = "TX underflow?";
			} else if (interrupts & TX_EARLY_INT) {
				msg = "TX early interrupt?";

			} else if (interrupts & LINK_STATUS_INT) {
				msg = "Link status change?";
			} else if (interrupts & GP_TIMER_INT) {
				msg = "Timer expired?";
			}

			if (warning_msg)
				dmfe_warning(dmfep, "abnormal interrupt, "
					"status 0x%x: %s", istat, msg);

			/*
			 * We don't want to run the entire reinitialisation
			 * code out of this (high-level?) interrupt, so we
			 * simply STOP the chip, and wake up the factotum
			 * to reinitalise it ...
			 */
			dmfe_stop_chip(dmfep, CHIP_ERROR);
			dmfe_wake_factotum(dmfep, KS_CHIP_ERROR,
			    "interrupt (error)");
		} else {
			/*
			 * We shouldn't really get here (it would mean
			 * there were some unprocessed enabled bits but
			 * they weren't Abnormal?), but we'll check just
			 * in case ...
			 */
			DMFE_DEBUG(("unexpected interrupt bits: 0x%x",
				istat));
		}
	}

	/*
	 * Acknowledge all the original bits - except in the case of an
	 * error, when we leave them unacknowledged so that the recovery
	 * code can see what was going on when the problem occurred ...
	 */
	if (dmfep->chip_state != CHIP_ERROR) {
		(void) dmfe_chip_put32(dmfep, STATUS_REG, istat);
		/*
		 * Read-after-write forces completion on PCI bus.
		 *
		 */
		(void) dmfe_chip_get32(dmfep, STATUS_REG);
	}


	/*
	 * We've finished talking to the chip, so we can drop <oplock>
	 * before handling the normal interrupts, which only involve
	 * manipulation of descriptors ...
	 */
	mutex_exit(dmfep->oplock);

	if (interrupts & RX_PKTDONE_INT)
		if ((mp = dmfe_getp(dmfep)) != NULL)
			dmfe_passup_chain(DMFE_MACINFO(dmfep), mp);

	if (interrupts & TX_PKTDONE_INT) {
		/*
		 * The only reason for taking this interrupt is to give
		 * GLD a chance to schedule queued packets after a
		 * ring-full condition.  To minimise the number of
		 * redundant TX-Done interrupts, we only mark two of the
		 * ring descriptors as 'interrupt-on-complete' - all the
		 * others are simply handed back without an interrupt.
		 */
		if (dmfe_reclaim_on_done && mutex_tryenter(dmfep->txlock)) {
			(void) dmfe_reclaim_tx_desc(dmfep);
			mutex_exit(dmfep->txlock);
		}
		gld_sched(DMFE_MACINFO(dmfep));
	}

	return (DDI_INTR_CLAIMED);
}

#undef	DMFE_DBG


/*
 * ========== Statistics update handler ==========
 */

#define	DMFE_DBG	DMFE_DBG_STATS	/* debug flag for this code	*/

static int
dmfe_gld_get_stats(gld_mac_info_t *macinfo, struct gld_stats *sp)
{
	dmfe_t *dmfep;

	dmfep = DMFE_STATE(macinfo);

	mutex_enter(dmfep->oplock);
	mutex_enter(dmfep->rxlock);
	mutex_enter(dmfep->txlock);

	sp->glds_speed = dmfep->op_stats_speed;
	sp->glds_duplex = dmfep->op_stats_duplex;
	sp->glds_media = dmfep->op_stats_media;
	sp->glds_intr = dmfep->op_stats_intr;

	sp->glds_errrcv = dmfep->rx_stats_errrcv;
	sp->glds_overflow = dmfep->rx_stats_overflow;
	sp->glds_short = dmfep->rx_stats_short;
	sp->glds_crc = dmfep->rx_stats_crc;
	sp->glds_dot3_frame_too_long = dmfep->rx_stats_frame_too_long;
	sp->glds_dot3_mac_rcv_error = dmfep->rx_stats_mac_rcv_error;
	sp->glds_frame = dmfep->rx_stats_frame;
	sp->glds_missed = dmfep->rx_stats_missed;
	sp->glds_norcvbuf = dmfep->rx_stats_norcvbuf;

	sp->glds_errxmt = dmfep->tx_stats_errxmt;
	sp->glds_dot3_mac_xmt_error = dmfep->tx_stats_mac_xmt_error;
	sp->glds_underflow = dmfep->tx_stats_underflow;
	sp->glds_xmtlatecoll = dmfep->tx_stats_xmtlatecoll;
	sp->glds_nocarrier = dmfep->tx_stats_nocarrier;
	sp->glds_excoll = dmfep->tx_stats_excoll;
	sp->glds_dot3_first_coll = dmfep->tx_stats_first_coll;
	sp->glds_dot3_multi_coll = dmfep->tx_stats_multi_coll;
	sp->glds_collisions = dmfep->tx_stats_collisions;
	sp->glds_defer = dmfep->tx_stats_defer;

	mutex_exit(dmfep->txlock);
	mutex_exit(dmfep->rxlock);
	mutex_exit(dmfep->oplock);

	return (GLD_SUCCESS);
}

#undef	DMFE_DBG


/*
 * ========== Ioctl handler & subfunctions ==========
 */

#define	DMFE_DBG	DMFE_DBG_IOCTL	/* debug flag for this code	*/

/*
 * Loopback operation
 *
 * Support access to the internal loopback and external loopback
 * functions selected via the Operation Mode Register (OPR).
 * These will be used by netlbtest (see BugId 4370609)
 *
 * Note that changing the loopback mode causes a stop/restart cycle
 */
static enum ioc_reply
dmfe_loop_ioctl(dmfe_t *dmfep, queue_t *wq, mblk_t *mp, int cmd)
{
	loopback_t *loop_req_p;
	uint32_t loopmode;

	if (mp->b_cont == NULL || MBLKL(mp->b_cont) < sizeof (loopback_t))
		return (IOC_INVAL);

	loop_req_p = (loopback_t *)mp->b_cont->b_rptr;

	switch (cmd) {
	default:
		/*
		 * This should never happen ...
		 */
		dmfe_error(dmfep, "dmfe_loop_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case DMFE_GET_LOOP_MODE:
		/*
		 * This doesn't return the current loopback mode - it
		 * returns a bitmask :-( of all possible loopback modes
		 */
		DMFE_DEBUG(("dmfe_loop_ioctl: GET_LOOP_MODE"));
		loop_req_p->loopback = DMFE_LOOPBACK_MODES;
		miocack(wq, mp, sizeof (loopback_t), 0);
		return (IOC_DONE);

	case DMFE_SET_LOOP_MODE:
		/*
		 * Select any of the various loopback modes
		 */
		DMFE_DEBUG(("dmfe_loop_ioctl: SET_LOOP_MODE %d",
			loop_req_p->loopback));
		switch (loop_req_p->loopback) {
		default:
			return (IOC_INVAL);

		case DMFE_LOOPBACK_OFF:
			dmfep->link_up_msg = " (loopback off)";
			loopmode = LOOPBACK_OFF;
			break;

		case DMFE_PHY_A_LOOPBACK_ON:
			dmfep->link_up_msg = " (analog loopback on)";
			loopmode = LOOPBACK_PHY_A;
			break;

		case DMFE_PHY_D_LOOPBACK_ON:
			dmfep->link_up_msg = " (digital loopback on)";
			loopmode = LOOPBACK_PHY_D;
			break;

		case DMFE_INT_LOOPBACK_ON:
			dmfep->link_up_msg = " (MAC loopback on)";
			loopmode = LOOPBACK_INTERNAL;
			break;
		}

		if ((dmfep->opmode & LOOPBACK_MODE_MASK) != loopmode) {
			dmfep->opmode &= ~LOOPBACK_MODE_MASK;
			dmfep->opmode |= loopmode;
			dmfep->link_down_msg = " (loopback changed)";
			return (IOC_RESTART_ACK);
		}

		return (IOC_ACK);
	}
}

/*
 * Specific dmfe IOCTLs, the gld module handles the generic ones.
 */
static int
dmfe_gld_ioctl(gld_mac_info_t *macinfo, queue_t *wq, mblk_t *mp)
{
	dmfe_t *dmfep;
	struct iocblk *iocp;
	enum ioc_reply status;
	int cmd;

	dmfep = DMFE_STATE(macinfo);

	DMFE_TRACE(("dmfe_gld_ioctl($%p, $%p, $%p)",
		(void *)macinfo, (void *)wq, (void *)mp));

	/*
	 * Validate the command before bothering with the mutexen ...
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		DMFE_DEBUG(("dmfe_gld_ioctl: unknown cmd 0x%x", cmd));
		miocnak(wq, mp, 0, EINVAL);
		return (GLD_SUCCESS);

	case DMFE_SET_LOOP_MODE:
	case DMFE_GET_LOOP_MODE:
	case DMFE_ND_GET:
	case DMFE_ND_SET:
		break;
	}

	mutex_enter(dmfep->milock);
	mutex_enter(dmfep->oplock);

	switch (cmd) {
	default:
		_NOTE(NOTREACHED)
		status = IOC_INVAL;
		break;

	case DMFE_SET_LOOP_MODE:
	case DMFE_GET_LOOP_MODE:
		status = dmfe_loop_ioctl(dmfep, wq, mp, cmd);
		break;

	case DMFE_ND_GET:
	case DMFE_ND_SET:
		status = dmfe_nd_ioctl(dmfep, wq, mp, cmd);
		break;
	}

	/*
	 * Do we need to restart?
	 */
	switch (status) {
	default:
		break;

	case IOC_RESTART_ACK:
	case IOC_RESTART:
		/*
		 * PHY parameters changed; we need to stop, update the
		 * PHY layer and restart before sending the reply or ACK
		 */
		dmfe_stop(dmfep);
		dmfe_update_phy(dmfep);
		dmfep->update_phy = B_FALSE;

		/*
		 * The link will now most likely go DOWN and UP, because
		 * we've changed the loopback state or the link parameters
		 * or autonegotiation.  So we have to check that it's
		 * settled down before we restart the TX/RX processes.
		 * The ioctl code will have planted some reason strings
		 * to explain what's happening, so the link state change
		 * messages won't be printed on the console . We wake the
		 * factotum to deal with link notifications, if any ...
		 */
		if (dmfe_check_link(dmfep)) {
			dmfe_recheck_link(dmfep, B_TRUE);
			dmfe_wake_factotum(dmfep, KS_LINK_CHECK, "ioctl");
		}

		if (dmfep->gld_state == GLD_STARTED)
			dmfe_start(dmfep);
		break;
	}

	/*
	 * The 'reasons-for-link-change', if any, don't apply any more
	 */
	dmfep->link_up_msg = dmfep->link_down_msg = "";
	mutex_exit(dmfep->oplock);
	mutex_exit(dmfep->milock);

	/*
	 * Finally, decide how to reply
	 */
	switch (status) {
	default:
		/*
		 * Error, reply with a NAK and EINVAL
		 */
		miocnak(wq, mp, 0, EINVAL);
		break;

	case IOC_RESTART_ACK:
	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(wq, mp, 0, 0);
		break;

	case IOC_RESTART:
	case IOC_REPLY:
		/*
		 * OK, send prepared reply
		 */
		qreply(wq, mp);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;
	}

	return (GLD_SUCCESS);
}

#undef	DMFE_DBG


/*
 * ========== Per-instance setup/teardown code ==========
 */

#define	DMFE_DBG	DMFE_DBG_INIT	/* debug flag for this code	*/

/*
 * Determine local MAC address & broadcast address for this interface
 */
static void
dmfe_find_mac_address(dmfe_t *dmfep)
{
	uchar_t *prop;
	uint_t propsize;
	int err;

	/*
	 * We have to find the "vendor's factory-set address".  This is
	 * the value of the property "local-mac-address", as set by OBP
	 * (or a .conf file!)
	 */
	bzero(dmfep->vendor_addr, sizeof (dmfep->vendor_addr));
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dmfep->devinfo,
		DDI_PROP_DONTPASS, localmac_propname, &prop, &propsize);
	if (err == DDI_PROP_SUCCESS) {
		if (propsize == ETHERADDRL)
			ethaddr_copy(prop, dmfep->vendor_addr);
		ddi_prop_free(prop);
	}

	DMFE_DEBUG(("dmfe_setup_mac_address: factory %s",
		ether_sprintf((void *)dmfep->vendor_addr)));
}

static int
dmfe_alloc_dma_mem(dmfe_t *dmfep, size_t memsize,
	size_t setup, size_t slop, ddi_device_acc_attr_t *attr_p,
	uint_t dma_flags, dma_area_t *dma_p)
{
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(dmfep->devinfo, &dma_attr,
		DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize + setup + slop,
		attr_p, dma_flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
		DDI_DMA_SLEEP, NULL,
		&dma_p->mem_va, &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Bind the two together
	 */
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
		dma_p->mem_va, dma_p->alength, dma_flags,
		DDI_DMA_SLEEP, NULL, &dma_cookie, &ncookies);
	if (err != DDI_DMA_MAPPED)
		return (DDI_FAILURE);
	if ((dma_p->ncookies = ncookies) != 1)
		return (DDI_FAILURE);

	dma_p->mem_dvma = dma_cookie.dmac_address;
	if (setup > 0) {
		dma_p->setup_dvma = dma_p->mem_dvma + memsize;
		dma_p->setup_va = dma_p->mem_va + memsize;
	} else {
		dma_p->setup_dvma = 0;
		dma_p->setup_va = NULL;
	}

	return (DDI_SUCCESS);
}

/*
 * This function allocates the transmit and receive buffers and descriptors.
 */
static int
dmfe_alloc_bufs(dmfe_t *dmfep)
{
	size_t memsize;
	int err;

	/*
	 * Allocate memory & handles for TX descriptor ring
	 */
	memsize = dmfep->tx.n_desc*sizeof (struct tx_desc_type);
	err = dmfe_alloc_dma_mem(dmfep, memsize, SETUPBUF_SIZE, DMFE_SLOP,
		&dmfe_reg_accattr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		&dmfep->tx_desc);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory & handles for TX buffers
	 */
	memsize = dmfep->tx.n_desc*DMFE_BUF_SIZE,
	err = dmfe_alloc_dma_mem(dmfep, memsize, 0, 0,
		&dmfe_data_accattr, DDI_DMA_WRITE | DMFE_DMA_MODE,
		&dmfep->tx_buff);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory & handles for RX descriptor ring
	 */
	memsize = dmfep->rx.n_desc*sizeof (struct rx_desc_type);
	err = dmfe_alloc_dma_mem(dmfep, memsize, 0, DMFE_SLOP,
		&dmfe_reg_accattr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		&dmfep->rx_desc);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory & handles for RX buffers
	 */
	memsize = dmfep->rx.n_desc*DMFE_BUF_SIZE,
	err = dmfe_alloc_dma_mem(dmfep, memsize, 0, 0,
		&dmfe_data_accattr, DDI_DMA_READ | DMFE_DMA_MODE,
		&dmfep->rx_buff);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static void
dmfe_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
			dma_p->ncookies = 0;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
		dma_p->mem_dvma = 0;
		dma_p->setup_dvma = 0;
	}

	if (dma_p->acc_hdl != NULL) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		dma_p->acc_hdl = NULL;
		dma_p->mem_va = NULL;
		dma_p->setup_va = NULL;
	}
}

/*
 * This routine frees the transmit and receive buffers and descriptors.
 * Make sure the chip is stopped before calling it!
 */
static void
dmfe_free_bufs(dmfe_t *dmfep)
{
	dmfe_free_dma_mem(&dmfep->rx_buff);
	dmfe_free_dma_mem(&dmfep->rx_desc);
	dmfe_free_dma_mem(&dmfep->tx_buff);
	dmfe_free_dma_mem(&dmfep->tx_desc);
}

static void
dmfe_unattach(dmfe_t *dmfep)
{
	/*
	 * Clean up and free all DMFE data structures
	 */
	if (dmfep->cycid != CYCLIC_NONE) {
		mutex_enter(&cpu_lock);
		cyclic_remove(dmfep->cycid);
		mutex_exit(&cpu_lock);
		dmfep->cycid = CYCLIC_NONE;
	}
	if (dmfep->ksp_mii != NULL)
		kstat_delete(dmfep->ksp_mii);
	if (dmfep->ksp_drv != NULL)
		kstat_delete(dmfep->ksp_drv);
	if (dmfep->progress & PROGRESS_HWINT) {
		ddi_remove_intr(dmfep->devinfo, 0, dmfep->iblk);
		mutex_destroy(dmfep->txlock);
		mutex_destroy(dmfep->rxlock);
		mutex_destroy(dmfep->oplock);
	}
	if (dmfep->progress & PROGRESS_SOFTINT)
		ddi_remove_softintr(dmfep->factotum_id);
	if (dmfep->progress & PROGRESS_BUFS)
		dmfe_free_bufs(dmfep);
	if (dmfep->progress & PROGRESS_REGS)
		ddi_regs_map_free(&dmfep->io_handle);
	if (dmfep->progress & PROGRESS_NDD)
		dmfe_nd_cleanup(dmfep);

	gld_mac_free(DMFE_MACINFO(dmfep));
	kmem_free(dmfep, sizeof (*dmfep));
}

static int
dmfe_config_init(dmfe_t *dmfep, chip_id_t *idp)
{
	ddi_acc_handle_t handle;
	uint32_t regval;

	if (pci_config_setup(dmfep->devinfo, &handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Get vendor/device/revision.  We expect (but don't check) that
	 * (vendorid == DAVICOM_VENDOR_ID) && (deviceid == DEVICE_ID_9102)
	 */
	idp->vendor = pci_config_get16(handle, PCI_CONF_VENID);
	idp->device = pci_config_get16(handle, PCI_CONF_DEVID);
	idp->revision = pci_config_get8(handle, PCI_CONF_REVID);

	/*
	 * Turn on Bus Master Enable bit and ensure the device is not asleep
	 */
	regval = pci_config_get32(handle, PCI_CONF_COMM);
	pci_config_put32(handle, PCI_CONF_COMM, (regval | PCI_COMM_ME));

	regval = pci_config_get32(handle, PCI_DMFE_CONF_CFDD);
	pci_config_put32(handle, PCI_DMFE_CONF_CFDD,
		regval & ~(CFDD_SLEEP | CFDD_SNOOZE));

	pci_config_teardown(&handle);
	return (DDI_SUCCESS);
}

struct ks_index {
	int index;
	char *name;
};

static const struct ks_index ks_mii_names[] = {
	{	KS_MII_XCVR_ADDR,		"xcvr_addr"		},
	{	KS_MII_XCVR_ID,			"xcvr_id"		},
	{	KS_MII_XCVR_INUSE,		"xcvr_inuse"		},

	{	KS_MII_LINK_UP,			"link_up"		},
	{	KS_MII_LINK_DUPLEX,		"link_duplex"		},

	{	KS_MII_CAP_100FDX,		"cap_100fdx"		},
	{	KS_MII_CAP_100HDX,		"cap_100hdx"		},
	{	KS_MII_CAP_10FDX,		"cap_10fdx"		},
	{	KS_MII_CAP_10HDX,		"cap_10hdx"		},
	{	KS_MII_CAP_REMFAULT,		"cap_rem_fault"		},
	{	KS_MII_CAP_AUTONEG,		"cap_autoneg"		},

	{	KS_MII_ADV_CAP_100FDX,		"adv_cap_100fdx"	},
	{	KS_MII_ADV_CAP_100HDX,		"adv_cap_100hdx"	},
	{	KS_MII_ADV_CAP_10FDX,		"adv_cap_10fdx"		},
	{	KS_MII_ADV_CAP_10HDX,		"adv_cap_10hdx"		},
	{	KS_MII_ADV_CAP_REMFAULT,	"adv_rem_fault"		},
	{	KS_MII_ADV_CAP_AUTONEG,		"adv_cap_autoneg"	},

	{	KS_MII_LP_CAP_100FDX,		"lp_cap_100fdx"		},
	{	KS_MII_LP_CAP_100HDX,		"lp_cap_100hdx"		},
	{	KS_MII_LP_CAP_10FDX,		"lp_cap_10fdx"		},
	{	KS_MII_LP_CAP_10HDX,		"lp_cap_10hdx"		},
	{	KS_MII_LP_CAP_REMFAULT,		"lp_cap_rem_fault"	},
	{	KS_MII_LP_CAP_AUTONEG,		"lp_cap_autoneg"	},

	{	-1,				NULL			}
};

static const struct ks_index ks_drv_names[] = {
	{	KS_CYCLIC_RUN,			"cyclic_run"		},

	{	KS_TICK_LINK_STATE,		"link_state_change"	},
	{	KS_TICK_LINK_POLL,		"link_state_poll"	},
	{	KS_LINK_INTERRUPT,		"link_state_interrupt"	},
	{	KS_TX_STALL,			"tx_stall_detect"	},
	{	KS_CHIP_ERROR,			"chip_error_interrupt"	},

	{	KS_FACTOTUM_RUN,		"factotum_run"		},
	{	KS_RECOVERY,			"factotum_recover"	},
	{	KS_LINK_CHECK,			"factotum_link_check"	},

	{	KS_LINK_UP_CNT,			"link_up_cnt"		},
	{	KS_LINK_DROP_CNT,		"link_drop_cnt"		},
	{	KS_LINK_CYCLE_UP_CNT,		"link_cycle_up_cnt"	},
	{	KS_LINK_CYCLE_DOWN_CNT,		"link_cycle_down_cnt"	},

	{	KS_MIIREG_BMSR,			"mii_status"		},
	{	KS_MIIREG_ANAR,			"mii_advert_cap"	},
	{	KS_MIIREG_ANLPAR,		"mii_partner_cap"	},
	{	KS_MIIREG_ANER,			"mii_expansion_cap"	},
	{	KS_MIIREG_DSCSR,		"mii_dscsr"		},

	{	-1,				NULL			}
};

static void
dmfe_init_kstats(dmfe_t *dmfep, int instance)
{
	kstat_t *ksp;
	kstat_named_t *knp;
	const struct ks_index *ksip;

	/* Create and initialise standard "mii" kstats */
	ksp = kstat_create(DRIVER_NAME, instance, "mii", "net",
		KSTAT_TYPE_NAMED, KS_MII_COUNT, KSTAT_FLAG_PERSISTENT);
	if (ksp != NULL) {
		for (knp = ksp->ks_data, ksip = ks_mii_names;
			ksip->name != NULL; ++ksip) {
			kstat_named_init(&knp[ksip->index], ksip->name,
				KSTAT_DATA_UINT32);
		}
		dmfep->ksp_mii = ksp;
		dmfep->knp_mii = knp;
		kstat_install(ksp);
	} else {
		dmfe_error(dmfep, "kstat_create() for mii failed");
	}

	/* Create and initialise driver-defined kstats */
	ksp = kstat_create(DRIVER_NAME, instance, "dmfe_events", "net",
		KSTAT_TYPE_NAMED, KS_DRV_COUNT, KSTAT_FLAG_PERSISTENT);
	if (ksp != NULL) {
		for (knp = ksp->ks_data, ksip = ks_drv_names;
			ksip->name != NULL; ++ksip) {
			kstat_named_init(&knp[ksip->index], ksip->name,
				KSTAT_DATA_UINT64);
		}
		dmfep->ksp_drv = ksp;
		dmfep->knp_drv = knp;
		kstat_install(ksp);
	} else {
		dmfe_error(dmfep, "kstat_create() for dmfe_events failed");
	}
}

static int
dmfe_resume(dev_info_t *devinfo)
{
	gld_mac_info_t *macinfo;		/* GLD structure	*/
	dmfe_t *dmfep;				/* Our private data	*/
	chip_id_t chipid;

	macinfo = (gld_mac_info_t *)ddi_get_driver_private(devinfo);
	if (macinfo == NULL)
		return (DDI_FAILURE);

	/*
	 * Refuse to resume if the data structures aren't consistent
	 */
	dmfep = DMFE_STATE(macinfo);
	if (dmfep->devinfo != devinfo || dmfep->macinfo != macinfo)
		return (DDI_FAILURE);

	/*
	 * Refuse to resume if the chip's changed its identity (*boggle*)
	 */
	if (dmfe_config_init(dmfep, &chipid) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if (chipid.vendor != dmfep->chipid.vendor)
		return (DDI_FAILURE);
	if (chipid.device != dmfep->chipid.device)
		return (DDI_FAILURE);
	if (chipid.revision != dmfep->chipid.revision)
		return (DDI_FAILURE);

	/*
	 * All OK, reinitialise h/w & kick off GLD scheduling
	 */
	mutex_enter(dmfep->oplock);
	dmfe_restart(dmfep);
	mutex_exit(dmfep->oplock);
	gld_sched(macinfo);
	return (DDI_SUCCESS);
}

/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board successfully probed.
 */
static int
dmfe_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	gld_mac_info_t *macinfo;		/* GLD structure	*/
	cyc_handler_t cychand;
	cyc_time_t cyctime;
	dmfe_t *dmfep;				/* Our private data	*/
	uint32_t csr6;
	int instance;
	int err;

	instance = ddi_get_instance(devinfo);

	DMFE_GTRACE(("dmfe_attach($%p, %d) instance %d",
		(void *)devinfo, cmd, instance));

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		return (dmfe_resume(devinfo));

	case DDI_ATTACH:
		break;
	}

	/*
	 * Allocate GLD macinfo and DMFE private structures, and
	 * cross-link them so that given either one of these or
	 * the devinfo the others can be derived.
	 */
	macinfo = gld_mac_alloc(devinfo);
	ddi_set_driver_private(devinfo, (caddr_t)macinfo);
	if (macinfo == NULL)
		return (DDI_FAILURE);

	dmfep = kmem_zalloc(sizeof (*dmfep), KM_SLEEP);
	dmfep->dmfe_guard = DMFE_GUARD;
	dmfep->devinfo = devinfo;
	dmfep->macinfo = macinfo;
	macinfo->gldm_private = (caddr_t)dmfep;

	/*
	 * Initialize more fields in DMFE private data
	 * Determine the local MAC address
	 */
#if	DMFEDEBUG
	dmfep->debug = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo, 0,
		debug_propname, dmfe_debug);
#endif	/* DMFEDEBUG */
	dmfep->cycid = CYCLIC_NONE;
	(void) snprintf(dmfep->ifname, sizeof (dmfep->ifname), "dmfe%d",
			    instance);
	dmfe_find_mac_address(dmfep);

	/*
	 * Check for custom "opmode-reg-value" property;
	 * if none, use the defaults below for CSR6 ...
	 */
	csr6 = TX_THRESHOLD_HI | STORE_AND_FORWARD | EXT_MII_IF | OPN_25_MB1;
	dmfep->opmode = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
		DDI_PROP_DONTPASS, opmode_propname, csr6);

	/*
	 * Read chip ID & set up config space command register(s)
	 */
	if (dmfe_config_init(dmfep, &dmfep->chipid) != DDI_SUCCESS) {
		dmfe_error(dmfep, "dmfe_config_init() failed");
		goto attach_fail;
	}
	dmfep->progress |= PROGRESS_CONFIG;

	/*
	 * Register NDD-tweakable parameters
	 */
	if (dmfe_nd_init(dmfep)) {
		dmfe_error(dmfep, "dmfe_nd_init() failed");
		goto attach_fail;
	}
	dmfep->progress |= PROGRESS_NDD;

	/*
	 * Map operating registers
	 */
	err = ddi_regs_map_setup(devinfo, DMFE_PCI_RNUMBER,
		&dmfep->io_reg, 0, 0, &dmfe_reg_accattr, &dmfep->io_handle);
	if (err != DDI_SUCCESS) {
		dmfe_error(dmfep, "ddi_regs_map_setup() failed");
		goto attach_fail;
	}
	dmfep->progress |= PROGRESS_REGS;

	/*
	 * Allocate the TX and RX descriptors/buffers.
	 */
	dmfep->tx.n_desc = dmfe_tx_desc;
	dmfep->rx.n_desc = dmfe_rx_desc;
	err = dmfe_alloc_bufs(dmfep);
	if (err != DDI_SUCCESS) {
		dmfe_error(dmfep, "DMA buffer allocation failed");
		goto attach_fail;
	}
	dmfep->progress |= PROGRESS_BUFS;

	/*
	 * Add the softint handler
	 */
	dmfep->link_poll_tix = factotum_start_tix;
	if (ddi_add_softintr(devinfo, DDI_SOFTINT_LOW, &dmfep->factotum_id,
		NULL, NULL, dmfe_factotum, (caddr_t)dmfep) != DDI_SUCCESS) {
		dmfe_error(dmfep, "ddi_add_softintr() failed");
		goto attach_fail;
	}
	dmfep->progress |= PROGRESS_SOFTINT;

	/*
	 * Add the h/w interrupt handler & initialise mutexen
	 */
	if (ddi_add_intr(devinfo, 0, &dmfep->iblk, NULL,
		dmfe_interrupt, (caddr_t)dmfep) != DDI_SUCCESS) {
		dmfe_error(dmfep, "ddi_add_intr() failed");
		goto attach_fail;
	}
	mutex_init(dmfep->milock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(dmfep->oplock, NULL, MUTEX_DRIVER, dmfep->iblk);
	mutex_init(dmfep->rxlock, NULL, MUTEX_DRIVER, dmfep->iblk);
	mutex_init(dmfep->txlock, NULL, MUTEX_DRIVER, dmfep->iblk);
	dmfep->progress |= PROGRESS_HWINT;

	/*
	 * Create & initialise named kstats
	 */
	dmfe_init_kstats(dmfep, instance);

	/*
	 * Reset & initialise the chip and the ring buffers
	 * Initialise the (internal) PHY
	 */
	(void) dmfe_gld_reset(macinfo);
	dmfep->link_state = LINK_UNKNOWN;
	dmfep->link_up_msg = dmfep->link_down_msg = " (initialised)";
	if (dmfe_init_phy(dmfep) != B_TRUE)
		goto attach_fail;
	dmfep->update_phy = B_TRUE;

	/*
	 * Initialize pointers to device specific functions which
	 * will be used by the generic layer.
	 */
	macinfo->gldm_reset		= dmfe_gld_reset;
	macinfo->gldm_start		= dmfe_gld_start;
	macinfo->gldm_stop		= dmfe_gld_stop;
	macinfo->gldm_set_mac_addr	= dmfe_gld_set_mac_addr;
	macinfo->gldm_set_multicast 	= dmfe_gld_set_multicast;
	macinfo->gldm_set_promiscuous	= dmfe_gld_set_promiscuous;
	macinfo->gldm_ioctl		= dmfe_gld_ioctl;
	macinfo->gldm_get_stats		= dmfe_gld_get_stats;
	macinfo->gldm_intr		= NULL;
	macinfo->gldm_send		= dmfe_gld_send;
#if	defined(VLAN_VID_NONE)
	/*
	 * This assignment wouldn't be safe if running a new DMFE binary
	 * against an old GLD, because <gldm_send_tagged> extends the
	 * macinfo structure.  So we need a runtime test as well as the
	 * compile-time one if we want full compatibility ...
	 */
	if (gld_recv_tagged != NULL)
		macinfo->gldm_send_tagged = dmfe_gld_send_tagged;
#endif	/* defined(VLAN_VID_NONE) */

	/*
	 * Initialize board characteristics needed by the generic layer.
	 */
	macinfo->gldm_ident		= dmfe_ident;
	macinfo->gldm_type		= DL_ETHER;
	macinfo->gldm_minpkt		= 0;	/* no padding required	*/
	macinfo->gldm_maxpkt		= ETHERMTU;
	macinfo->gldm_addrlen		= ETHERADDRL;
	macinfo->gldm_saplen		= -2;
	macinfo->gldm_broadcast_addr	= dmfe_broadcast_addr;
	macinfo->gldm_vendor_addr	= dmfep->vendor_addr;
	macinfo->gldm_ppa		= instance;
	macinfo->gldm_devinfo		= devinfo;
	macinfo->gldm_cookie		= dmfep->iblk;
#if	defined(GLD_CAP_LINKSTATE)
	/*
	 * This is safe even when running a new DMFE binary against an
	 * old GLD, because <gldm_capabilities> replaces a reserved
	 * field, rather than extending the macinfo structure
	 */
	macinfo->gldm_capabilities	= GLD_CAP_LINKSTATE;
#endif	/* defined(GLD_CAP_LINKSTATE) */

	/*
	 * Workaround for booting from NET1 on early versions of Solaris,
	 * enabled by patching the global variable (dmfe_net1_boot_support)
	 * to non-zero.
	 *
	 * Up to Solaris 8, strplumb() assumed that PPA == minor number,
	 * which is not (and never has been) true for any GLD-based driver.
	 * In later versions, strplumb() and GLD have been made to cooperate
	 * so this isn't necessary; specifically, strplumb() has been changed
	 * to assume PPA == instance (rather than minor number), which *is*
	 * true for GLD v2 drivers, and GLD also specifically tells it the
	 * PPA for legacy (v0) drivers.
	 *
	 * The workaround creates an internal minor node with a minor number
	 * equal to the PPA; this node shouldn't ever appear under /devices
	 * in userland, but can be found internally when setting up the root
	 * (NFS) filesystem.
	 */
	if (dmfe_net1_boot_support) {
		extern int ddi_create_internal_pathname(dev_info_t *dip,
			char *name, int spec_type, minor_t minor_num);

		(void) ddi_create_internal_pathname(devinfo, DRIVER_NAME,
			S_IFCHR, macinfo->gldm_ppa);
	}

	/*
	 * Finally, we're ready to register ourselves with the GLD
	 * interface; if this succeeds, we're all ready to start()
	 */
	if (gld_register(devinfo, DRIVER_NAME, macinfo) != DDI_SUCCESS)
		goto attach_fail;
	ASSERT(dmfep->dmfe_guard == DMFE_GUARD);

	/*
	 * Install the cyclic callback that we use to check for link
	 * status, transmit stall, etc.  We ASSERT that this can't fail
	 */
	cychand.cyh_func = dmfe_cyclic;
	cychand.cyh_arg = dmfep;
	cychand.cyh_level = CY_LOW_LEVEL;
	cyctime.cyt_when = 0;
	cyctime.cyt_interval = dmfe_tick_us*1000;	/* ns */
	ASSERT(dmfep->cycid == CYCLIC_NONE);
	mutex_enter(&cpu_lock);
	dmfep->cycid = cyclic_add(&cychand, &cyctime);
	mutex_exit(&cpu_lock);
	ASSERT(dmfep->cycid != CYCLIC_NONE);

	return (DDI_SUCCESS);

attach_fail:
	dmfe_unattach(dmfep);
	return (DDI_FAILURE);
}

/*
 *	dmfe_suspend() -- suspend transmit/receive for powerdown
 */
static int
dmfe_suspend(dmfe_t *dmfep)
{
	/*
	 * Just stop processing ...
	 */
	mutex_enter(dmfep->oplock);
	dmfe_stop(dmfep);
	mutex_exit(dmfep->oplock);

	return (DDI_SUCCESS);
}

/*
 * detach(9E) -- Detach a device from the system
 */
static int
dmfe_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	gld_mac_info_t *macinfo;	/* GLD structure */
	dmfe_t *dmfep;

	DMFE_GTRACE(("dmfe_detach($%p, %d)", (void *)devinfo, cmd));

	/*
	 * Get the GLD (macinfo) data from the devinfo and
	 * derive the driver's own state structure from that
	 */
	macinfo = (gld_mac_info_t *)ddi_get_driver_private(devinfo);
	dmfep = DMFE_STATE(macinfo);

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (dmfe_suspend(dmfep));

	case DDI_DETACH:
		break;
	}

	/*
	 * Unregister from the GLD subsystem.  This can fail, in
	 * particular if there are DLPI style-2 streams still open -
	 * in which case we just return failure without shutting
	 * down chip operations.
	 */
	if (gld_unregister(macinfo) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * All activity stopped, so we can clean up & exit
	 */
	dmfe_unattach(dmfep);
	return (DDI_SUCCESS);
}


/*
 * ========== Module Loading Data & Entry Points ==========
 */

static struct module_info dmfe_module_info = {
	DMFEIDNUM,
	DRIVER_NAME,
	0,
	INFPSZ,
	DMFEHIWAT,
	DMFELOWAT
};

static struct qinit dmfe_r_qinit = {	/* read queues */
	NULL,
	gld_rsrv,
	gld_open,
	gld_close,
	NULL,
	&dmfe_module_info,
	NULL
};

static struct qinit dmfe_w_qinit = {	/* write queues */
	gld_wput,
	gld_wsrv,
	NULL,
	NULL,
	NULL,
	&dmfe_module_info,
	NULL
};

static struct streamtab dmfe_streamtab = {
	&dmfe_r_qinit,
	&dmfe_w_qinit,
	NULL,
	NULL
};

static struct cb_ops dmfe_cb_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
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
	&dmfe_streamtab,	/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops dmfe_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	gld_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	dmfe_attach,		/* devo_attach */
	dmfe_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&dmfe_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL			/* devo_power */
};

static struct modldrv dmfe_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	dmfe_ident,		/* short description */
	&dmfe_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&dmfe_modldrv, NULL
};

int
_info(struct modinfo *modinfop)
{
	DMFE_GTRACE(("_info called"));

	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	uint32_t tmp100;
	uint32_t tmp10;
	int i;
	int status;

	DMFE_GTRACE(("_init called"));

	/* Calculate global timing parameters */
	tmp100 = (dmfe_tx100_stall_us+dmfe_tick_us-1)/dmfe_tick_us;
	tmp10 = (dmfe_tx10_stall_us+dmfe_tick_us-1)/dmfe_tick_us;

	for (i = 0; i <= TX_PROCESS_MAX_STATE; ++i) {
		switch (i) {
		case TX_PROCESS_STATE(TX_PROCESS_FETCH_DATA):
		case TX_PROCESS_STATE(TX_PROCESS_WAIT_END):
			/*
			 * The chip doesn't spontaneously recover from
			 * a stall in these states, so we reset early
			 */
			stall_100_tix[i] = tmp100;
			stall_10_tix[i] = tmp10;
			break;

		case TX_PROCESS_STATE(TX_PROCESS_SUSPEND):
		default:
			/*
			 * The chip has been seen to spontaneously recover
			 * after an apparent stall in the SUSPEND state,
			 * so we'll allow it rather longer to do so.  As
			 * stalls in other states have not been observed,
			 * we'll use long timeouts for them too ...
			 */
			stall_100_tix[i] = tmp100 * 20;
			stall_10_tix[i] = tmp10 * 20;
			break;
		}
	}

	factotum_tix = (dmfe_link_poll_us+dmfe_tick_us-1)/dmfe_tick_us;
	factotum_fast_tix = 1+(factotum_tix/5);
	factotum_start_tix = 1+(factotum_tix*2);

	status = mod_install(&modlinkage);
	if (status == 0)
		dmfe_log_init();

	return (status);
}

int
_fini(void)
{
	int status;

	DMFE_GTRACE(("_fini called"));

	status = mod_remove(&modlinkage);
	if (status == 0)
		dmfe_log_fini();

	return (status);
}

#undef	DMFE_DBG

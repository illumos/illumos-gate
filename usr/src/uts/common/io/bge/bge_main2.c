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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "bge_impl.h"
#include <sys/sdt.h>

/*
 * This is the string displayed by modinfo, etc.
 * Make sure you keep the version ID up to date!
 */
static char bge_ident[] = "Broadcom Gb Ethernet v0.60";

/*
 * Property names
 */
static char debug_propname[] = "bge-debug-flags";
static char clsize_propname[] = "cache-line-size";
static char latency_propname[] = "latency-timer";
static char localmac_boolname[] = "local-mac-address?";
static char localmac_propname[] = "local-mac-address";
static char macaddr_propname[] = "mac-address";
static char subdev_propname[] = "subsystem-id";
static char subven_propname[] = "subsystem-vendor-id";
static char rxrings_propname[] = "bge-rx-rings";
static char txrings_propname[] = "bge-tx-rings";
static char fm_cap[] = "fm-capable";
static char default_mtu[] = "default_mtu";

static int bge_add_intrs(bge_t *, int);
static void bge_rem_intrs(bge_t *);

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x00000000FFFFFFFFull,		/* dma_attr_count_max	*/
	0x0000000000000001ull,		/* dma_attr_align	*/
	0x00000FFF,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x000000000000FFFFull,		/* dma_attr_maxxfer	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg		*/
	1,				/* dma_attr_sgllen 	*/
	0x00000001,			/* dma_attr_granular 	*/
	DDI_DMA_FLAGERR			/* dma_attr_flags */
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t bge_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

/*
 * DMA access attributes for descriptors: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t bge_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

/*
 * DMA access attributes for data: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t bge_data_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Versions of the O/S up to Solaris 8 didn't support network booting
 * from any network interface except the first (NET0).  Patching this
 * flag to a non-zero value will tell the driver to work around this
 * limitation by creating an extra (internal) pathname node.  To do
 * this, just add a line like the following to the CLIENT'S etc/system
 * file ON THE ROOT FILESYSTEM SERVER before booting the client:
 *
 *	set bge:bge_net1_boot_support = 1;
 */
static uint32_t bge_net1_boot_support = 1;

static int		bge_m_start(void *);
static void		bge_m_stop(void *);
static int		bge_m_promisc(void *, boolean_t);
static int		bge_m_multicst(void *, boolean_t, const uint8_t *);
static int		bge_m_unicst(void *, const uint8_t *);
static void		bge_m_resources(void *);
static void		bge_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t	bge_m_getcapab(void *, mac_capab_t, void *);
static int		bge_unicst_set(void *, const uint8_t *,
    mac_addr_slot_t);
static int		bge_m_unicst_add(void *, mac_multi_addr_t *);
static int		bge_m_unicst_remove(void *, mac_addr_slot_t);
static int		bge_m_unicst_modify(void *, mac_multi_addr_t *);
static int		bge_m_unicst_get(void *, mac_multi_addr_t *);

#define	BGE_M_CALLBACK_FLAGS	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t bge_m_callbacks = {
	BGE_M_CALLBACK_FLAGS,
	bge_m_stat,
	bge_m_start,
	bge_m_stop,
	bge_m_promisc,
	bge_m_multicst,
	bge_m_unicst,
	bge_m_tx,
	bge_m_resources,
	bge_m_ioctl,
	bge_m_getcapab
};

/*
 * ========== Transmit and receive ring reinitialisation ==========
 */

/*
 * These <reinit> routines each reset the specified ring to an initial
 * state, assuming that the corresponding <init> routine has already
 * been called exactly once.
 */

static void
bge_reinit_send_ring(send_ring_t *srp)
{
	bge_queue_t *txbuf_queue;
	bge_queue_item_t *txbuf_head;
	sw_txbuf_t *txbuf;
	sw_sbd_t *ssbdp;
	uint32_t slot;

	/*
	 * Reinitialise control variables ...
	 */
	srp->tx_flow = 0;
	srp->tx_next = 0;
	srp->txfill_next = 0;
	srp->tx_free = srp->desc.nslots;
	ASSERT(mutex_owned(srp->tc_lock));
	srp->tc_next = 0;
	srp->txpkt_next = 0;
	srp->tx_block = 0;
	srp->tx_nobd = 0;
	srp->tx_nobuf = 0;

	/*
	 * Initialize the tx buffer push queue
	 */
	mutex_enter(srp->freetxbuf_lock);
	mutex_enter(srp->txbuf_lock);
	txbuf_queue = &srp->freetxbuf_queue;
	txbuf_queue->head = NULL;
	txbuf_queue->count = 0;
	txbuf_queue->lock = srp->freetxbuf_lock;
	srp->txbuf_push_queue = txbuf_queue;

	/*
	 * Initialize the tx buffer pop queue
	 */
	txbuf_queue = &srp->txbuf_queue;
	txbuf_queue->head = NULL;
	txbuf_queue->count = 0;
	txbuf_queue->lock = srp->txbuf_lock;
	srp->txbuf_pop_queue = txbuf_queue;
	txbuf_head = srp->txbuf_head;
	txbuf = srp->txbuf;
	for (slot = 0; slot < srp->tx_buffers; ++slot) {
		txbuf_head->item = txbuf;
		txbuf_head->next = txbuf_queue->head;
		txbuf_queue->head = txbuf_head;
		txbuf_queue->count++;
		txbuf++;
		txbuf_head++;
	}
	mutex_exit(srp->txbuf_lock);
	mutex_exit(srp->freetxbuf_lock);

	/*
	 * Zero and sync all the h/w Send Buffer Descriptors
	 */
	DMA_ZERO(srp->desc);
	DMA_SYNC(srp->desc, DDI_DMA_SYNC_FORDEV);
	bzero(srp->pktp, BGE_SEND_BUF_MAX * sizeof (*srp->pktp));
	ssbdp = srp->sw_sbds;
	for (slot = 0; slot < srp->desc.nslots; ++ssbdp, ++slot)
		ssbdp->pbuf = NULL;
}

static void
bge_reinit_recv_ring(recv_ring_t *rrp)
{
	/*
	 * Reinitialise control variables ...
	 */
	rrp->rx_next = 0;
}

static void
bge_reinit_buff_ring(buff_ring_t *brp, uint32_t ring)
{
	bge_rbd_t *hw_rbd_p;
	sw_rbd_t *srbdp;
	uint32_t bufsize;
	uint32_t nslots;
	uint32_t slot;

	static uint16_t ring_type_flag[BGE_BUFF_RINGS_MAX] = {
		RBD_FLAG_STD_RING,
		RBD_FLAG_JUMBO_RING,
		RBD_FLAG_MINI_RING
	};

	/*
	 * Zero, initialise and sync all the h/w Receive Buffer Descriptors
	 * Note: all the remaining fields (<type>, <flags>, <ip_cksum>,
	 * <tcp_udp_cksum>, <error_flag>, <vlan_tag>, and <reserved>)
	 * should be zeroed, and so don't need to be set up specifically
	 * once the whole area has been cleared.
	 */
	DMA_ZERO(brp->desc);

	hw_rbd_p = DMA_VPTR(brp->desc);
	nslots = brp->desc.nslots;
	ASSERT(brp->buf[0].nslots == nslots/BGE_SPLIT);
	bufsize = brp->buf[0].size;
	srbdp = brp->sw_rbds;
	for (slot = 0; slot < nslots; ++hw_rbd_p, ++srbdp, ++slot) {
		hw_rbd_p->host_buf_addr = srbdp->pbuf.cookie.dmac_laddress;
		hw_rbd_p->index = slot;
		hw_rbd_p->len = bufsize;
		hw_rbd_p->opaque = srbdp->pbuf.token;
		hw_rbd_p->flags |= ring_type_flag[ring];
	}

	DMA_SYNC(brp->desc, DDI_DMA_SYNC_FORDEV);

	/*
	 * Finally, reinitialise the ring control variables ...
	 */
	brp->rf_next = (nslots != 0) ? (nslots-1) : 0;
}

/*
 * Reinitialize all rings
 */
static void
bge_reinit_rings(bge_t *bgep)
{
	uint32_t ring;

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Send Rings ...
	 */
	for (ring = 0; ring < bgep->chipid.tx_rings; ++ring)
		bge_reinit_send_ring(&bgep->send[ring]);

	/*
	 * Receive Return Rings ...
	 */
	for (ring = 0; ring < bgep->chipid.rx_rings; ++ring)
		bge_reinit_recv_ring(&bgep->recv[ring]);

	/*
	 * Receive Producer Rings ...
	 */
	for (ring = 0; ring < BGE_BUFF_RINGS_USED; ++ring)
		bge_reinit_buff_ring(&bgep->buff[ring], ring);
}

/*
 * ========== Internal state management entry points ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_NEMO	/* debug flag for this code	*/

/*
 * These routines provide all the functionality required by the
 * corresponding GLD entry points, but don't update the GLD state
 * so they can be called internally without disturbing our record
 * of what GLD thinks we should be doing ...
 */

/*
 *	bge_reset() -- reset h/w & rings to initial state
 */
static int
#ifdef BGE_IPMI_ASF
bge_reset(bge_t *bgep, uint_t asf_mode)
#else
bge_reset(bge_t *bgep)
#endif
{
	uint32_t	ring;
	int retval;

	BGE_TRACE(("bge_reset($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Grab all the other mutexes in the world (this should
	 * ensure no other threads are manipulating driver state)
	 */
	for (ring = 0; ring < BGE_RECV_RINGS_MAX; ++ring)
		mutex_enter(bgep->recv[ring].rx_lock);
	for (ring = 0; ring < BGE_BUFF_RINGS_MAX; ++ring)
		mutex_enter(bgep->buff[ring].rf_lock);
	rw_enter(bgep->errlock, RW_WRITER);
	for (ring = 0; ring < BGE_SEND_RINGS_MAX; ++ring)
		mutex_enter(bgep->send[ring].tx_lock);
	for (ring = 0; ring < BGE_SEND_RINGS_MAX; ++ring)
		mutex_enter(bgep->send[ring].tc_lock);

#ifdef BGE_IPMI_ASF
	retval = bge_chip_reset(bgep, B_TRUE, asf_mode);
#else
	retval = bge_chip_reset(bgep, B_TRUE);
#endif
	bge_reinit_rings(bgep);

	/*
	 * Free the world ...
	 */
	for (ring = BGE_SEND_RINGS_MAX; ring-- > 0; )
		mutex_exit(bgep->send[ring].tc_lock);
	for (ring = 0; ring < BGE_SEND_RINGS_MAX; ++ring)
		mutex_exit(bgep->send[ring].tx_lock);
	rw_exit(bgep->errlock);
	for (ring = BGE_BUFF_RINGS_MAX; ring-- > 0; )
		mutex_exit(bgep->buff[ring].rf_lock);
	for (ring = BGE_RECV_RINGS_MAX; ring-- > 0; )
		mutex_exit(bgep->recv[ring].rx_lock);

	BGE_DEBUG(("bge_reset($%p) done", (void *)bgep));
	return (retval);
}

/*
 *	bge_stop() -- stop processing, don't reset h/w or rings
 */
static void
bge_stop(bge_t *bgep)
{
	BGE_TRACE(("bge_stop($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		bgep->asf_pseudostop = B_TRUE;
	} else {
#endif
		bge_chip_stop(bgep, B_FALSE);
#ifdef BGE_IPMI_ASF
	}
#endif

	BGE_DEBUG(("bge_stop($%p) done", (void *)bgep));
}

/*
 *	bge_start() -- start transmitting/receiving
 */
static int
bge_start(bge_t *bgep, boolean_t reset_phys)
{
	int retval;

	BGE_TRACE(("bge_start($%p, %d)", (void *)bgep, reset_phys));

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Start chip processing, including enabling interrupts
	 */
	retval = bge_chip_start(bgep, reset_phys);

	BGE_DEBUG(("bge_start($%p, %d) done", (void *)bgep, reset_phys));
	return (retval);
}

/*
 * bge_restart - restart transmitting/receiving after error or suspend
 */
int
bge_restart(bge_t *bgep, boolean_t reset_phys)
{
	int retval = DDI_SUCCESS;
	ASSERT(mutex_owned(bgep->genlock));

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		if (bge_reset(bgep, ASF_MODE_POST_INIT) != DDI_SUCCESS)
			retval = DDI_FAILURE;
	} else
		if (bge_reset(bgep, ASF_MODE_NONE) != DDI_SUCCESS)
			retval = DDI_FAILURE;
#else
	if (bge_reset(bgep) != DDI_SUCCESS)
		retval = DDI_FAILURE;
#endif
	if (bgep->bge_mac_state == BGE_MAC_STARTED) {
		if (bge_start(bgep, reset_phys) != DDI_SUCCESS)
			retval = DDI_FAILURE;
		bgep->watchdog = 0;
		ddi_trigger_softintr(bgep->drain_id);
	}

	BGE_DEBUG(("bge_restart($%p, %d) done", (void *)bgep, reset_phys));
	return (retval);
}


/*
 * ========== Nemo-required management entry points ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_NEMO	/* debug flag for this code	*/

/*
 *	bge_m_stop() -- stop transmitting/receiving
 */
static void
bge_m_stop(void *arg)
{
	bge_t *bgep = arg;		/* private device info	*/
	send_ring_t *srp;
	uint32_t ring;

	BGE_TRACE(("bge_m_stop($%p)", arg));

	/*
	 * Just stop processing, then record new GLD state
	 */
	mutex_enter(bgep->genlock);
	if (!(bgep->progress & PROGRESS_INTR)) {
		/* can happen during autorecovery */
		mutex_exit(bgep->genlock);
		return;
	}
	bge_stop(bgep);
	/*
	 * Free the possible tx buffers allocated in tx process.
	 */
#ifdef BGE_IPMI_ASF
	if (!bgep->asf_pseudostop)
#endif
	{
		rw_enter(bgep->errlock, RW_WRITER);
		for (ring = 0; ring < bgep->chipid.tx_rings; ++ring) {
			srp = &bgep->send[ring];
			mutex_enter(srp->tx_lock);
			if (srp->tx_array > 1)
				bge_free_txbuf_arrays(srp);
			mutex_exit(srp->tx_lock);
		}
		rw_exit(bgep->errlock);
	}
	bgep->bge_mac_state = BGE_MAC_STOPPED;
	BGE_DEBUG(("bge_m_stop($%p) done", arg));
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_UNAFFECTED);
	mutex_exit(bgep->genlock);
}

/*
 *	bge_m_start() -- start transmitting/receiving
 */
static int
bge_m_start(void *arg)
{
	bge_t *bgep = arg;		/* private device info	*/

	BGE_TRACE(("bge_m_start($%p)", arg));

	/*
	 * Start processing and record new GLD state
	 */
	mutex_enter(bgep->genlock);
	if (!(bgep->progress & PROGRESS_INTR)) {
		/* can happen during autorecovery */
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		if ((bgep->asf_status == ASF_STAT_RUN) &&
		    (bgep->asf_pseudostop)) {
			bgep->bge_mac_state = BGE_MAC_STARTED;
			mutex_exit(bgep->genlock);
			return (0);
		}
	}
	if (bge_reset(bgep, ASF_MODE_INIT) != DDI_SUCCESS) {
#else
	if (bge_reset(bgep) != DDI_SUCCESS) {
#endif
		(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	if (bge_start(bgep, B_TRUE) != DDI_SUCCESS) {
		(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	bgep->bge_mac_state = BGE_MAC_STARTED;
	BGE_DEBUG(("bge_m_start($%p) done", arg));

	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		if (bgep->asf_status != ASF_STAT_RUN) {
			/* start ASF heart beat */
			bgep->asf_timeout_id = timeout(bge_asf_heartbeat,
			    (void *)bgep,
			    drv_usectohz(BGE_ASF_HEARTBEAT_INTERVAL));
			bgep->asf_status = ASF_STAT_RUN;
		}
	}
#endif
	mutex_exit(bgep->genlock);

	return (0);
}

/*
 *	bge_m_unicst() -- set the physical network address
 */
static int
bge_m_unicst(void *arg, const uint8_t *macaddr)
{
	/*
	 * Request to set address in
	 * address slot 0, i.e., default address
	 */
	return (bge_unicst_set(arg, macaddr, 0));
}

/*
 *	bge_unicst_set() -- set the physical network address
 */
static int
bge_unicst_set(void *arg, const uint8_t *macaddr, mac_addr_slot_t slot)
{
	bge_t *bgep = arg;		/* private device info	*/

	BGE_TRACE(("bge_m_unicst_set($%p, %s)", arg,
	    ether_sprintf((void *)macaddr)));
	/*
	 * Remember the new current address in the driver state
	 * Sync the chip's idea of the address too ...
	 */
	mutex_enter(bgep->genlock);
	if (!(bgep->progress & PROGRESS_INTR)) {
		/* can happen during autorecovery */
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	ethaddr_copy(macaddr, bgep->curr_addr[slot].addr);
#ifdef BGE_IPMI_ASF
	if (bge_chip_sync(bgep, B_FALSE) == DDI_FAILURE) {
#else
	if (bge_chip_sync(bgep) == DDI_FAILURE) {
#endif
		(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		/*
		 * The above bge_chip_sync() function wrote the ethernet MAC
		 * addresses registers which destroyed the IPMI/ASF sideband.
		 * Here, we have to reset chip to make IPMI/ASF sideband work.
		 */
		if (bgep->asf_status == ASF_STAT_RUN) {
			/*
			 * We must stop ASF heart beat before bge_chip_stop(),
			 * otherwise some computers (ex. IBM HS20 blade server)
			 * may crash.
			 */
			bge_asf_update_status(bgep);
			bge_asf_stop_timer(bgep);
			bgep->asf_status = ASF_STAT_STOP;

			bge_asf_pre_reset_operations(bgep, BGE_INIT_RESET);
		}
		bge_chip_stop(bgep, B_FALSE);

		if (bge_restart(bgep, B_FALSE) == DDI_FAILURE) {
			(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
			(void) bge_check_acc_handle(bgep, bgep->io_handle);
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_DEGRADED);
			mutex_exit(bgep->genlock);
			return (EIO);
		}

		/*
		 * Start our ASF heartbeat counter as soon as possible.
		 */
		if (bgep->asf_status != ASF_STAT_RUN) {
			/* start ASF heart beat */
			bgep->asf_timeout_id = timeout(bge_asf_heartbeat,
			    (void *)bgep,
			    drv_usectohz(BGE_ASF_HEARTBEAT_INTERVAL));
			bgep->asf_status = ASF_STAT_RUN;
		}
	}
#endif
	BGE_DEBUG(("bge_m_unicst_set($%p) done", arg));
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	mutex_exit(bgep->genlock);

	return (0);
}

/*
 * The following four routines are used as callbacks for multiple MAC
 * address support:
 *    -  bge_m_unicst_add(void *, mac_multi_addr_t *);
 *    -  bge_m_unicst_remove(void *, mac_addr_slot_t);
 *    -  bge_m_unicst_modify(void *, mac_multi_addr_t *);
 *    -  bge_m_unicst_get(void *, mac_multi_addr_t *);
 */

/*
 * bge_m_unicst_add() - will find an unused address slot, set the
 * address value to the one specified, reserve that slot and enable
 * the NIC to start filtering on the new MAC address.
 * address slot. Returns 0 on success.
 */
static int
bge_m_unicst_add(void *arg, mac_multi_addr_t *maddr)
{
	bge_t *bgep = arg;		/* private device info	*/
	mac_addr_slot_t slot;
	int err;

	if (mac_unicst_verify(bgep->mh,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE)
		return (EINVAL);

	mutex_enter(bgep->genlock);
	if (bgep->unicst_addr_avail == 0) {
		/* no slots available */
		mutex_exit(bgep->genlock);
		return (ENOSPC);
	}

	/*
	 * Primary/default address is in slot 0. The next three
	 * addresses are the multiple MAC addresses. So multiple
	 * MAC address 0 is in slot 1, 1 in slot 2, and so on.
	 * So the first multiple MAC address resides in slot 1.
	 */
	for (slot = 1; slot < bgep->unicst_addr_total; slot++) {
		if (bgep->curr_addr[slot].set == B_FALSE) {
			bgep->curr_addr[slot].set = B_TRUE;
			break;
		}
	}

	ASSERT(slot < bgep->unicst_addr_total);
	bgep->unicst_addr_avail--;
	mutex_exit(bgep->genlock);
	maddr->mma_slot = slot;

	if ((err = bge_unicst_set(bgep, maddr->mma_addr, slot)) != 0) {
		mutex_enter(bgep->genlock);
		bgep->curr_addr[slot].set = B_FALSE;
		bgep->unicst_addr_avail++;
		mutex_exit(bgep->genlock);
	}
	return (err);
}

/*
 * bge_m_unicst_remove() - removes a MAC address that was added by a
 * call to bge_m_unicst_add(). The slot number that was returned in
 * add() is passed in the call to remove the address.
 * Returns 0 on success.
 */
static int
bge_m_unicst_remove(void *arg, mac_addr_slot_t slot)
{
	bge_t *bgep = arg;		/* private device info	*/

	if (slot <= 0 || slot >= bgep->unicst_addr_total)
		return (EINVAL);

	mutex_enter(bgep->genlock);
	if (bgep->curr_addr[slot].set == B_TRUE) {
		bgep->curr_addr[slot].set = B_FALSE;
		bgep->unicst_addr_avail++;
		mutex_exit(bgep->genlock);
		/*
		 * Copy the default address to the passed slot
		 */
		return (bge_unicst_set(bgep, bgep->curr_addr[0].addr, slot));
	}
	mutex_exit(bgep->genlock);
	return (EINVAL);
}

/*
 * bge_m_unicst_modify() - modifies the value of an address that
 * has been added by bge_m_unicst_add(). The new address, address
 * length and the slot number that was returned in the call to add
 * should be passed to bge_m_unicst_modify(). mma_flags should be
 * set to 0. Returns 0 on success.
 */
static int
bge_m_unicst_modify(void *arg, mac_multi_addr_t *maddr)
{
	bge_t *bgep = arg;		/* private device info	*/
	mac_addr_slot_t slot;

	if (mac_unicst_verify(bgep->mh,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE)
		return (EINVAL);

	slot = maddr->mma_slot;

	if (slot <= 0 || slot >= bgep->unicst_addr_total)
		return (EINVAL);

	mutex_enter(bgep->genlock);
	if (bgep->curr_addr[slot].set == B_TRUE) {
		mutex_exit(bgep->genlock);
		return (bge_unicst_set(bgep, maddr->mma_addr, slot));
	}
	mutex_exit(bgep->genlock);

	return (EINVAL);
}

/*
 * bge_m_unicst_get() - will get the MAC address and all other
 * information related to the address slot passed in mac_multi_addr_t.
 * mma_flags should be set to 0 in the call.
 * On return, mma_flags can take the following values:
 * 1) MMAC_SLOT_UNUSED
 * 2) MMAC_SLOT_USED | MMAC_VENDOR_ADDR
 * 3) MMAC_SLOT_UNUSED | MMAC_VENDOR_ADDR
 * 4) MMAC_SLOT_USED
 */
static int
bge_m_unicst_get(void *arg, mac_multi_addr_t *maddr)
{
	bge_t *bgep = arg;		/* private device info	*/
	mac_addr_slot_t slot;

	slot = maddr->mma_slot;

	if (slot <= 0 || slot >= bgep->unicst_addr_total)
		return (EINVAL);

	mutex_enter(bgep->genlock);
	if (bgep->curr_addr[slot].set == B_TRUE) {
		ethaddr_copy(bgep->curr_addr[slot].addr,
		    maddr->mma_addr);
		maddr->mma_flags = MMAC_SLOT_USED;
	} else {
		maddr->mma_flags = MMAC_SLOT_UNUSED;
	}
	mutex_exit(bgep->genlock);

	return (0);
}

/*
 * Compute the index of the required bit in the multicast hash map.
 * This must mirror the way the hardware actually does it!
 * See Broadcom document 570X-PG102-R page 125.
 */
static uint32_t
bge_hash_index(const uint8_t *mca)
{
	uint32_t hash;

	CRC32(hash, mca, ETHERADDRL, -1U, crc32_table);

	return (hash);
}

/*
 *	bge_m_multicst_add() -- enable/disable a multicast address
 */
static int
bge_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	bge_t *bgep = arg;		/* private device info	*/
	uint32_t hash;
	uint32_t index;
	uint32_t word;
	uint32_t bit;
	uint8_t *refp;

	BGE_TRACE(("bge_m_multicst($%p, %s, %s)", arg,
	    (add) ? "add" : "remove", ether_sprintf((void *)mca)));

	/*
	 * Precalculate all required masks, pointers etc ...
	 */
	hash = bge_hash_index(mca);
	index = hash % BGE_HASH_TABLE_SIZE;
	word = index/32u;
	bit = 1 << (index % 32u);
	refp = &bgep->mcast_refs[index];

	BGE_DEBUG(("bge_m_multicst: hash 0x%x index %d (%d:0x%x) = %d",
	    hash, index, word, bit, *refp));

	/*
	 * We must set the appropriate bit in the hash map (and the
	 * corresponding h/w register) when the refcount goes from 0
	 * to >0, and clear it when the last ref goes away (refcount
	 * goes from >0 back to 0).  If we change the hash map, we
	 * must also update the chip's hardware map registers.
	 */
	mutex_enter(bgep->genlock);
	if (!(bgep->progress & PROGRESS_INTR)) {
		/* can happen during autorecovery */
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	if (add) {
		if ((*refp)++ == 0) {
			bgep->mcast_hash[word] |= bit;
#ifdef BGE_IPMI_ASF
			if (bge_chip_sync(bgep, B_TRUE) == DDI_FAILURE) {
#else
			if (bge_chip_sync(bgep) == DDI_FAILURE) {
#endif
				(void) bge_check_acc_handle(bgep,
				    bgep->cfg_handle);
				(void) bge_check_acc_handle(bgep,
				    bgep->io_handle);
				ddi_fm_service_impact(bgep->devinfo,
				    DDI_SERVICE_DEGRADED);
				mutex_exit(bgep->genlock);
				return (EIO);
			}
		}
	} else {
		if (--(*refp) == 0) {
			bgep->mcast_hash[word] &= ~bit;
#ifdef BGE_IPMI_ASF
			if (bge_chip_sync(bgep, B_TRUE) == DDI_FAILURE) {
#else
			if (bge_chip_sync(bgep) == DDI_FAILURE) {
#endif
				(void) bge_check_acc_handle(bgep,
				    bgep->cfg_handle);
				(void) bge_check_acc_handle(bgep,
				    bgep->io_handle);
				ddi_fm_service_impact(bgep->devinfo,
				    DDI_SERVICE_DEGRADED);
				mutex_exit(bgep->genlock);
				return (EIO);
			}
		}
	}
	BGE_DEBUG(("bge_m_multicst($%p) done", arg));
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	mutex_exit(bgep->genlock);

	return (0);
}

/*
 * bge_m_promisc() -- set or reset promiscuous mode on the board
 *
 *	Program the hardware to enable/disable promiscuous and/or
 *	receive-all-multicast modes.
 */
static int
bge_m_promisc(void *arg, boolean_t on)
{
	bge_t *bgep = arg;

	BGE_TRACE(("bge_m_promisc_set($%p, %d)", arg, on));

	/*
	 * Store MAC layer specified mode and pass to chip layer to update h/w
	 */
	mutex_enter(bgep->genlock);
	if (!(bgep->progress & PROGRESS_INTR)) {
		/* can happen during autorecovery */
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	bgep->promisc = on;
#ifdef BGE_IPMI_ASF
	if (bge_chip_sync(bgep, B_TRUE) == DDI_FAILURE) {
#else
	if (bge_chip_sync(bgep) == DDI_FAILURE) {
#endif
		(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	BGE_DEBUG(("bge_m_promisc_set($%p) done", arg));
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	mutex_exit(bgep->genlock);
	return (0);
}

/*ARGSUSED*/
static boolean_t
bge_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	bge_t *bgep = arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		*txflags = HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM;
		break;
	}

	case MAC_CAPAB_POLL:
		/*
		 * There's nothing for us to fill in, simply returning
		 * B_TRUE stating that we support polling is sufficient.
		 */
		break;

	case MAC_CAPAB_MULTIADDRESS: {
		multiaddress_capab_t	*mmacp = cap_data;

		mutex_enter(bgep->genlock);
		/*
		 * The number of MAC addresses made available by
		 * this capability is one less than the total as
		 * the primary address in slot 0 is counted in
		 * the total.
		 */
		mmacp->maddr_naddr = bgep->unicst_addr_total - 1;
		mmacp->maddr_naddrfree = bgep->unicst_addr_avail;
		/* No multiple factory addresses, set mma_flag to 0 */
		mmacp->maddr_flag = 0;
		mmacp->maddr_handle = bgep;
		mmacp->maddr_add = bge_m_unicst_add;
		mmacp->maddr_remove = bge_m_unicst_remove;
		mmacp->maddr_modify = bge_m_unicst_modify;
		mmacp->maddr_get = bge_m_unicst_get;
		mmacp->maddr_reserve = NULL;
		mutex_exit(bgep->genlock);
		break;
	}

	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Loopback ioctl code
 */

static lb_property_t loopmodes[] = {
	{ normal,	"normal",	BGE_LOOP_NONE		},
	{ external,	"1000Mbps",	BGE_LOOP_EXTERNAL_1000	},
	{ external,	"100Mbps",	BGE_LOOP_EXTERNAL_100	},
	{ external,	"10Mbps",	BGE_LOOP_EXTERNAL_10	},
	{ internal,	"PHY",		BGE_LOOP_INTERNAL_PHY	},
	{ internal,	"MAC",		BGE_LOOP_INTERNAL_MAC	}
};

static enum ioc_reply
bge_set_loop_mode(bge_t *bgep, uint32_t mode)
{
	/*
	 * If the mode isn't being changed, there's nothing to do ...
	 */
	if (mode == bgep->param_loop_mode)
		return (IOC_ACK);

	/*
	 * Validate the requested mode and prepare a suitable message
	 * to explain the link down/up cycle that the change will
	 * probably induce ...
	 */
	switch (mode) {
	default:
		return (IOC_INVAL);

	case BGE_LOOP_NONE:
	case BGE_LOOP_EXTERNAL_1000:
	case BGE_LOOP_EXTERNAL_100:
	case BGE_LOOP_EXTERNAL_10:
	case BGE_LOOP_INTERNAL_PHY:
	case BGE_LOOP_INTERNAL_MAC:
		break;
	}

	/*
	 * All OK; tell the caller to reprogram
	 * the PHY and/or MAC for the new mode ...
	 */
	bgep->param_loop_mode = mode;
	return (IOC_RESTART_ACK);
}

static enum ioc_reply
bge_loop_ioctl(bge_t *bgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;
	uint32_t *lbmp;
	int cmd;

	_NOTE(ARGUNUSED(wq))

	/*
	 * Validate format of ioctl
	 */
	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		bge_error(bgep, "bge_loop_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case LB_GET_INFO_SIZE:
		if (iocp->ioc_count != sizeof (lb_info_sz_t))
			return (IOC_INVAL);
		lbsp = (lb_info_sz_t *)mp->b_cont->b_rptr;
		*lbsp = sizeof (loopmodes);
		return (IOC_REPLY);

	case LB_GET_INFO:
		if (iocp->ioc_count != sizeof (loopmodes))
			return (IOC_INVAL);
		lbpp = (lb_property_t *)mp->b_cont->b_rptr;
		bcopy(loopmodes, lbpp, sizeof (loopmodes));
		return (IOC_REPLY);

	case LB_GET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (uint32_t *)mp->b_cont->b_rptr;
		*lbmp = bgep->param_loop_mode;
		return (IOC_REPLY);

	case LB_SET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (uint32_t *)mp->b_cont->b_rptr;
		return (bge_set_loop_mode(bgep, *lbmp));
	}
}

/*
 * Specific bge IOCTLs, the gld module handles the generic ones.
 */
static void
bge_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	bge_t *bgep = arg;
	struct iocblk *iocp;
	enum ioc_reply status;
	boolean_t need_privilege;
	int err;
	int cmd;

	/*
	 * Validate the command before bothering with the mutex ...
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	need_privilege = B_TRUE;
	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		miocnak(wq, mp, 0, EINVAL);
		return;

	case BGE_MII_READ:
	case BGE_MII_WRITE:
	case BGE_SEE_READ:
	case BGE_SEE_WRITE:
	case BGE_FLASH_READ:
	case BGE_FLASH_WRITE:
	case BGE_DIAG:
	case BGE_PEEK:
	case BGE_POKE:
	case BGE_PHY_RESET:
	case BGE_SOFT_RESET:
	case BGE_HARD_RESET:
		break;

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
		need_privilege = B_FALSE;
		/* FALLTHRU */
	case LB_SET_MODE:
		break;

	case ND_GET:
		need_privilege = B_FALSE;
		/* FALLTHRU */
	case ND_SET:
		break;
	}

	if (need_privilege) {
		/*
		 * Check for specific net_config privilege on Solaris 10+.
		 */
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (err != 0) {
			miocnak(wq, mp, 0, err);
			return;
		}
	}

	mutex_enter(bgep->genlock);
	if (!(bgep->progress & PROGRESS_INTR)) {
		/* can happen during autorecovery */
		mutex_exit(bgep->genlock);
		miocnak(wq, mp, 0, EIO);
		return;
	}

	switch (cmd) {
	default:
		_NOTE(NOTREACHED)
		status = IOC_INVAL;
		break;

	case BGE_MII_READ:
	case BGE_MII_WRITE:
	case BGE_SEE_READ:
	case BGE_SEE_WRITE:
	case BGE_FLASH_READ:
	case BGE_FLASH_WRITE:
	case BGE_DIAG:
	case BGE_PEEK:
	case BGE_POKE:
	case BGE_PHY_RESET:
	case BGE_SOFT_RESET:
	case BGE_HARD_RESET:
		status = bge_chip_ioctl(bgep, wq, mp, iocp);
		break;

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = bge_loop_ioctl(bgep, wq, mp, iocp);
		break;

	case ND_GET:
	case ND_SET:
		status = bge_nd_ioctl(bgep, wq, mp, iocp);
		break;
	}

	/*
	 * Do we need to reprogram the PHY and/or the MAC?
	 * Do it now, while we still have the mutex.
	 *
	 * Note: update the PHY first, 'cos it controls the
	 * speed/duplex parameters that the MAC code uses.
	 */
	switch (status) {
	case IOC_RESTART_REPLY:
	case IOC_RESTART_ACK:
		if (bge_phys_update(bgep) != DDI_SUCCESS) {
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_DEGRADED);
			status = IOC_INVAL;
		}
#ifdef BGE_IPMI_ASF
		if (bge_chip_sync(bgep, B_TRUE) == DDI_FAILURE) {
#else
		if (bge_chip_sync(bgep) == DDI_FAILURE) {
#endif
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_DEGRADED);
			status = IOC_INVAL;
		}
		if (bgep->intr_type == DDI_INTR_TYPE_MSI)
			bge_chip_msi_trig(bgep);
		break;
	}

	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		status = IOC_INVAL;
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		status = IOC_INVAL;
	}
	mutex_exit(bgep->genlock);

	/*
	 * Finally, decide how to reply
	 */
	switch (status) {
	default:
	case IOC_INVAL:
		/*
		 * Error, reply with a NAK and EINVAL or the specified error
		 */
		miocnak(wq, mp, 0, iocp->ioc_error == 0 ?
		    EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;

	case IOC_RESTART_ACK:
	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(wq, mp, 0, 0);
		break;

	case IOC_RESTART_REPLY:
	case IOC_REPLY:
		/*
		 * OK, send prepared reply as ACK or NAK
		 */
		mp->b_datap->db_type = iocp->ioc_error == 0 ?
		    M_IOCACK : M_IOCNAK;
		qreply(wq, mp);
		break;
	}
}

static void
bge_m_resources(void *arg)
{
	bge_t *bgep = arg;
	recv_ring_t *rrp;
	mac_rx_fifo_t mrf;
	int ring;

	mutex_enter(bgep->genlock);

	/*
	 * Register Rx rings as resources and save mac
	 * resource id for future reference
	 */
	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = bge_chip_blank;
	mrf.mrf_arg = (void *)bgep;
	mrf.mrf_normal_blank_time = bge_rx_ticks_norm;
	mrf.mrf_normal_pkt_count = bge_rx_count_norm;

	for (ring = 0; ring < bgep->chipid.rx_rings; ring++) {
		rrp = &bgep->recv[ring];
		rrp->handle = mac_resource_add(bgep->mh,
		    (mac_resource_t *)&mrf);
	}

	mutex_exit(bgep->genlock);
}

/*
 * ========== Per-instance setup/teardown code ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_INIT	/* debug flag for this code	*/
/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
bge_alloc_dma_mem(bge_t *bgep, size_t memsize, ddi_device_acc_attr_t *attr_p,
	uint_t dma_flags, dma_area_t *dma_p)
{
	caddr_t va;
	int err;

	BGE_TRACE(("bge_alloc_dma_mem($%p, %ld, $%p, 0x%x, $%p)",
	    (void *)bgep, memsize, attr_p, dma_flags, dma_p));

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(bgep->devinfo, &dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    dma_flags, DDI_DMA_DONTWAIT, NULL, &va, &dma_p->alength,
	    &dma_p->acc_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Bind the two together
	 */
	dma_p->mem_va = va;
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    va, dma_p->alength, dma_flags, DDI_DMA_DONTWAIT, NULL,
	    &dma_p->cookie, &dma_p->ncookies);

	BGE_DEBUG(("bge_alloc_dma_mem(): bind %d bytes; err %d, %d cookies",
	    dma_p->alength, err, dma_p->ncookies));

	if (err != DDI_DMA_MAPPED || dma_p->ncookies != 1)
		return (DDI_FAILURE);

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->token = ~0U;
	dma_p->offset = 0;
	return (DDI_SUCCESS);
}

/*
 * Free one allocated area of DMAable memory
 */
static void
bge_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
			dma_p->ncookies = 0;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
	}

	if (dma_p->acc_hdl != NULL) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		dma_p->acc_hdl = NULL;
	}
}
/*
 * Utility routine to carve a slice off a chunk of allocated memory,
 * updating the chunk descriptor accordingly.  The size of the slice
 * is given by the product of the <qty> and <size> parameters.
 */
static void
bge_slice_chunk(dma_area_t *slice, dma_area_t *chunk,
	uint32_t qty, uint32_t size)
{
	static uint32_t sequence = 0xbcd5704a;
	size_t totsize;

	totsize = qty*size;
	ASSERT(size >= 0);
	ASSERT(totsize <= chunk->alength);

	*slice = *chunk;
	slice->nslots = qty;
	slice->size = size;
	slice->alength = totsize;
	slice->token = ++sequence;

	chunk->mem_va = (caddr_t)chunk->mem_va + totsize;
	chunk->alength -= totsize;
	chunk->offset += totsize;
	chunk->cookie.dmac_laddress += totsize;
	chunk->cookie.dmac_size -= totsize;
}

/*
 * Initialise the specified Receive Producer (Buffer) Ring, using
 * the information in the <dma_area> descriptors that it contains
 * to set up all the other fields. This routine should be called
 * only once for each ring.
 */
static void
bge_init_buff_ring(bge_t *bgep, uint64_t ring)
{
	buff_ring_t *brp;
	bge_status_t *bsp;
	sw_rbd_t *srbdp;
	dma_area_t pbuf;
	uint32_t bufsize;
	uint32_t nslots;
	uint32_t slot;
	uint32_t split;

	static bge_regno_t nic_ring_addrs[BGE_BUFF_RINGS_MAX] = {
		NIC_MEM_SHADOW_BUFF_STD,
		NIC_MEM_SHADOW_BUFF_JUMBO,
		NIC_MEM_SHADOW_BUFF_MINI
	};
	static bge_regno_t mailbox_regs[BGE_BUFF_RINGS_MAX] = {
		RECV_STD_PROD_INDEX_REG,
		RECV_JUMBO_PROD_INDEX_REG,
		RECV_MINI_PROD_INDEX_REG
	};
	static bge_regno_t buff_cons_xref[BGE_BUFF_RINGS_MAX] = {
		STATUS_STD_BUFF_CONS_INDEX,
		STATUS_JUMBO_BUFF_CONS_INDEX,
		STATUS_MINI_BUFF_CONS_INDEX
	};

	BGE_TRACE(("bge_init_buff_ring($%p, %d)",
	    (void *)bgep, ring));

	brp = &bgep->buff[ring];
	nslots = brp->desc.nslots;
	ASSERT(brp->buf[0].nslots == nslots/BGE_SPLIT);
	bufsize = brp->buf[0].size;

	/*
	 * Set up the copy of the h/w RCB
	 *
	 * Note: unlike Send & Receive Return Rings, (where the max_len
	 * field holds the number of slots), in a Receive Buffer Ring
	 * this field indicates the size of each buffer in the ring.
	 */
	brp->hw_rcb.host_ring_addr = brp->desc.cookie.dmac_laddress;
	brp->hw_rcb.max_len = bufsize;
	brp->hw_rcb.flags = nslots > 0 ? 0 : RCB_FLAG_RING_DISABLED;
	brp->hw_rcb.nic_ring_addr = nic_ring_addrs[ring];

	/*
	 * Other one-off initialisation of per-ring data
	 */
	brp->bgep = bgep;
	bsp = DMA_VPTR(bgep->status_block);
	brp->cons_index_p = &bsp->buff_cons_index[buff_cons_xref[ring]];
	brp->chip_mbx_reg = mailbox_regs[ring];
	mutex_init(brp->rf_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));

	/*
	 * Allocate the array of s/w Receive Buffer Descriptors
	 */
	srbdp = kmem_zalloc(nslots*sizeof (*srbdp), KM_SLEEP);
	brp->sw_rbds = srbdp;

	/*
	 * Now initialise each array element once and for all
	 */
	for (split = 0; split < BGE_SPLIT; ++split) {
		pbuf = brp->buf[split];
		for (slot = 0; slot < nslots/BGE_SPLIT; ++srbdp, ++slot)
			bge_slice_chunk(&srbdp->pbuf, &pbuf, 1, bufsize);
		ASSERT(pbuf.alength == 0);
	}
}

/*
 * Clean up initialisation done above before the memory is freed
 */
static void
bge_fini_buff_ring(bge_t *bgep, uint64_t ring)
{
	buff_ring_t *brp;
	sw_rbd_t *srbdp;

	BGE_TRACE(("bge_fini_buff_ring($%p, %d)",
	    (void *)bgep, ring));

	brp = &bgep->buff[ring];
	srbdp = brp->sw_rbds;
	kmem_free(srbdp, brp->desc.nslots*sizeof (*srbdp));

	mutex_destroy(brp->rf_lock);
}

/*
 * Initialise the specified Receive (Return) Ring, using the
 * information in the <dma_area> descriptors that it contains
 * to set up all the other fields. This routine should be called
 * only once for each ring.
 */
static void
bge_init_recv_ring(bge_t *bgep, uint64_t ring)
{
	recv_ring_t *rrp;
	bge_status_t *bsp;
	uint32_t nslots;

	BGE_TRACE(("bge_init_recv_ring($%p, %d)",
	    (void *)bgep, ring));

	/*
	 * The chip architecture requires that receive return rings have
	 * 512 or 1024 or 2048 elements per ring.  See 570X-PG108-R page 103.
	 */
	rrp = &bgep->recv[ring];
	nslots = rrp->desc.nslots;
	ASSERT(nslots == 0 || nslots == 512 ||
	    nslots == 1024 || nslots == 2048);

	/*
	 * Set up the copy of the h/w RCB
	 */
	rrp->hw_rcb.host_ring_addr = rrp->desc.cookie.dmac_laddress;
	rrp->hw_rcb.max_len = nslots;
	rrp->hw_rcb.flags = nslots > 0 ? 0 : RCB_FLAG_RING_DISABLED;
	rrp->hw_rcb.nic_ring_addr = 0;

	/*
	 * Other one-off initialisation of per-ring data
	 */
	rrp->bgep = bgep;
	bsp = DMA_VPTR(bgep->status_block);
	rrp->prod_index_p = RECV_INDEX_P(bsp, ring);
	rrp->chip_mbx_reg = RECV_RING_CONS_INDEX_REG(ring);
	mutex_init(rrp->rx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));
}


/*
 * Clean up initialisation done above before the memory is freed
 */
static void
bge_fini_recv_ring(bge_t *bgep, uint64_t ring)
{
	recv_ring_t *rrp;

	BGE_TRACE(("bge_fini_recv_ring($%p, %d)",
	    (void *)bgep, ring));

	rrp = &bgep->recv[ring];
	if (rrp->rx_softint)
		ddi_remove_softintr(rrp->rx_softint);
	mutex_destroy(rrp->rx_lock);
}

/*
 * Initialise the specified Send Ring, using the information in the
 * <dma_area> descriptors that it contains to set up all the other
 * fields. This routine should be called only once for each ring.
 */
static void
bge_init_send_ring(bge_t *bgep, uint64_t ring)
{
	send_ring_t *srp;
	bge_status_t *bsp;
	sw_sbd_t *ssbdp;
	dma_area_t desc;
	dma_area_t pbuf;
	uint32_t nslots;
	uint32_t slot;
	uint32_t split;
	sw_txbuf_t *txbuf;

	BGE_TRACE(("bge_init_send_ring($%p, %d)",
	    (void *)bgep, ring));

	/*
	 * The chip architecture requires that host-based send rings
	 * have 512 elements per ring.  See 570X-PG102-R page 56.
	 */
	srp = &bgep->send[ring];
	nslots = srp->desc.nslots;
	ASSERT(nslots == 0 || nslots == 512);

	/*
	 * Set up the copy of the h/w RCB
	 */
	srp->hw_rcb.host_ring_addr = srp->desc.cookie.dmac_laddress;
	srp->hw_rcb.max_len = nslots;
	srp->hw_rcb.flags = nslots > 0 ? 0 : RCB_FLAG_RING_DISABLED;
	srp->hw_rcb.nic_ring_addr = NIC_MEM_SHADOW_SEND_RING(ring, nslots);

	/*
	 * Other one-off initialisation of per-ring data
	 */
	srp->bgep = bgep;
	bsp = DMA_VPTR(bgep->status_block);
	srp->cons_index_p = SEND_INDEX_P(bsp, ring);
	srp->chip_mbx_reg = SEND_RING_HOST_INDEX_REG(ring);
	mutex_init(srp->tx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));
	mutex_init(srp->txbuf_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));
	mutex_init(srp->freetxbuf_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));
	mutex_init(srp->tc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));
	if (nslots == 0)
		return;

	/*
	 * Allocate the array of s/w Send Buffer Descriptors
	 */
	ssbdp = kmem_zalloc(nslots*sizeof (*ssbdp), KM_SLEEP);
	txbuf = kmem_zalloc(BGE_SEND_BUF_MAX*sizeof (*txbuf), KM_SLEEP);
	srp->txbuf_head =
	    kmem_zalloc(BGE_SEND_BUF_MAX*sizeof (bge_queue_item_t), KM_SLEEP);
	srp->pktp = kmem_zalloc(BGE_SEND_BUF_MAX*sizeof (send_pkt_t), KM_SLEEP);
	srp->sw_sbds = ssbdp;
	srp->txbuf = txbuf;
	srp->tx_buffers = BGE_SEND_BUF_NUM;
	srp->tx_buffers_low = srp->tx_buffers / 4;
	if (bgep->chipid.snd_buff_size > BGE_SEND_BUFF_SIZE_DEFAULT)
		srp->tx_array_max = BGE_SEND_BUF_ARRAY_JUMBO;
	else
		srp->tx_array_max = BGE_SEND_BUF_ARRAY;
	srp->tx_array = 1;

	/*
	 * Chunk tx desc area
	 */
	desc = srp->desc;
	for (slot = 0; slot < nslots; ++ssbdp, ++slot) {
		bge_slice_chunk(&ssbdp->desc, &desc, 1,
		    sizeof (bge_sbd_t));
	}
	ASSERT(desc.alength == 0);

	/*
	 * Chunk tx buffer area
	 */
	for (split = 0; split < BGE_SPLIT; ++split) {
		pbuf = srp->buf[0][split];
		for (slot = 0; slot < BGE_SEND_BUF_NUM/BGE_SPLIT; ++slot) {
			bge_slice_chunk(&txbuf->buf, &pbuf, 1,
			    bgep->chipid.snd_buff_size);
			txbuf++;
		}
		ASSERT(pbuf.alength == 0);
	}
}

/*
 * Clean up initialisation done above before the memory is freed
 */
static void
bge_fini_send_ring(bge_t *bgep, uint64_t ring)
{
	send_ring_t *srp;
	uint32_t array;
	uint32_t split;
	uint32_t nslots;

	BGE_TRACE(("bge_fini_send_ring($%p, %d)",
	    (void *)bgep, ring));

	srp = &bgep->send[ring];
	mutex_destroy(srp->tc_lock);
	mutex_destroy(srp->freetxbuf_lock);
	mutex_destroy(srp->txbuf_lock);
	mutex_destroy(srp->tx_lock);
	nslots = srp->desc.nslots;
	if (nslots == 0)
		return;

	for (array = 1; array < srp->tx_array; ++array)
		for (split = 0; split < BGE_SPLIT; ++split)
			bge_free_dma_mem(&srp->buf[array][split]);
	kmem_free(srp->sw_sbds, nslots*sizeof (*srp->sw_sbds));
	kmem_free(srp->txbuf_head, BGE_SEND_BUF_MAX*sizeof (*srp->txbuf_head));
	kmem_free(srp->txbuf, BGE_SEND_BUF_MAX*sizeof (*srp->txbuf));
	kmem_free(srp->pktp, BGE_SEND_BUF_MAX*sizeof (*srp->pktp));
	srp->sw_sbds = NULL;
	srp->txbuf_head = NULL;
	srp->txbuf = NULL;
	srp->pktp = NULL;
}

/*
 * Initialise all transmit, receive, and buffer rings.
 */
void
bge_init_rings(bge_t *bgep)
{
	uint32_t ring;

	BGE_TRACE(("bge_init_rings($%p)", (void *)bgep));

	/*
	 * Perform one-off initialisation of each ring ...
	 */
	for (ring = 0; ring < BGE_SEND_RINGS_MAX; ++ring)
		bge_init_send_ring(bgep, ring);
	for (ring = 0; ring < BGE_RECV_RINGS_MAX; ++ring)
		bge_init_recv_ring(bgep, ring);
	for (ring = 0; ring < BGE_BUFF_RINGS_MAX; ++ring)
		bge_init_buff_ring(bgep, ring);
}

/*
 * Undo the work of bge_init_rings() above before the memory is freed
 */
void
bge_fini_rings(bge_t *bgep)
{
	uint32_t ring;

	BGE_TRACE(("bge_fini_rings($%p)", (void *)bgep));

	for (ring = 0; ring < BGE_BUFF_RINGS_MAX; ++ring)
		bge_fini_buff_ring(bgep, ring);
	for (ring = 0; ring < BGE_RECV_RINGS_MAX; ++ring)
		bge_fini_recv_ring(bgep, ring);
	for (ring = 0; ring < BGE_SEND_RINGS_MAX; ++ring)
		bge_fini_send_ring(bgep, ring);
}

/*
 * Called from the bge_m_stop() to free the tx buffers which are
 * allocated from the tx process.
 */
void
bge_free_txbuf_arrays(send_ring_t *srp)
{
	uint32_t array;
	uint32_t split;

	ASSERT(mutex_owned(srp->tx_lock));

	/*
	 * Free the extra tx buffer DMA area
	 */
	for (array = 1; array < srp->tx_array; ++array)
		for (split = 0; split < BGE_SPLIT; ++split)
			bge_free_dma_mem(&srp->buf[array][split]);

	/*
	 * Restore initial tx buffer numbers
	 */
	srp->tx_array = 1;
	srp->tx_buffers = BGE_SEND_BUF_NUM;
	srp->tx_buffers_low = srp->tx_buffers / 4;
	srp->tx_flow = 0;
	bzero(srp->pktp, BGE_SEND_BUF_MAX * sizeof (*srp->pktp));
}

/*
 * Called from tx process to allocate more tx buffers
 */
bge_queue_item_t *
bge_alloc_txbuf_array(bge_t *bgep, send_ring_t *srp)
{
	bge_queue_t *txbuf_queue;
	bge_queue_item_t *txbuf_item_last;
	bge_queue_item_t *txbuf_item;
	bge_queue_item_t *txbuf_item_rtn;
	sw_txbuf_t *txbuf;
	dma_area_t area;
	size_t txbuffsize;
	uint32_t slot;
	uint32_t array;
	uint32_t split;
	uint32_t err;

	ASSERT(mutex_owned(srp->tx_lock));

	array = srp->tx_array;
	if (array >= srp->tx_array_max)
		return (NULL);

	/*
	 * Allocate memory & handles for TX buffers
	 */
	txbuffsize = BGE_SEND_BUF_NUM*bgep->chipid.snd_buff_size;
	ASSERT((txbuffsize % BGE_SPLIT) == 0);
	for (split = 0; split < BGE_SPLIT; ++split) {
		err = bge_alloc_dma_mem(bgep, txbuffsize/BGE_SPLIT,
		    &bge_data_accattr, DDI_DMA_WRITE | BGE_DMA_MODE,
		    &srp->buf[array][split]);
		if (err != DDI_SUCCESS) {
			/* Free the last already allocated OK chunks */
			for (slot = 0; slot <= split; ++slot)
				bge_free_dma_mem(&srp->buf[array][slot]);
			srp->tx_alloc_fail++;
			return (NULL);
		}
	}

	/*
	 * Chunk tx buffer area
	 */
	txbuf = srp->txbuf + array*BGE_SEND_BUF_NUM;
	for (split = 0; split < BGE_SPLIT; ++split) {
		area = srp->buf[array][split];
		for (slot = 0; slot < BGE_SEND_BUF_NUM/BGE_SPLIT; ++slot) {
			bge_slice_chunk(&txbuf->buf, &area, 1,
			    bgep->chipid.snd_buff_size);
			txbuf++;
		}
	}

	/*
	 * Add above buffers to the tx buffer pop queue
	 */
	txbuf_item = srp->txbuf_head + array*BGE_SEND_BUF_NUM;
	txbuf = srp->txbuf + array*BGE_SEND_BUF_NUM;
	txbuf_item_last = NULL;
	for (slot = 0; slot < BGE_SEND_BUF_NUM; ++slot) {
		txbuf_item->item = txbuf;
		txbuf_item->next = txbuf_item_last;
		txbuf_item_last = txbuf_item;
		txbuf++;
		txbuf_item++;
	}
	txbuf_item = srp->txbuf_head + array*BGE_SEND_BUF_NUM;
	txbuf_item_rtn = txbuf_item;
	txbuf_item++;
	txbuf_queue = srp->txbuf_pop_queue;
	mutex_enter(txbuf_queue->lock);
	txbuf_item->next = txbuf_queue->head;
	txbuf_queue->head = txbuf_item_last;
	txbuf_queue->count += BGE_SEND_BUF_NUM - 1;
	mutex_exit(txbuf_queue->lock);

	srp->tx_array++;
	srp->tx_buffers += BGE_SEND_BUF_NUM;
	srp->tx_buffers_low = srp->tx_buffers / 4;

	return (txbuf_item_rtn);
}

/*
 * This function allocates all the transmit and receive buffers
 * and descriptors, in four chunks.
 */
int
bge_alloc_bufs(bge_t *bgep)
{
	dma_area_t area;
	size_t rxbuffsize;
	size_t txbuffsize;
	size_t rxbuffdescsize;
	size_t rxdescsize;
	size_t txdescsize;
	uint32_t ring;
	uint32_t rx_rings = bgep->chipid.rx_rings;
	uint32_t tx_rings = bgep->chipid.tx_rings;
	int split;
	int err;

	BGE_TRACE(("bge_alloc_bufs($%p)",
	    (void *)bgep));

	rxbuffsize = BGE_STD_SLOTS_USED*bgep->chipid.std_buf_size;
	rxbuffsize += bgep->chipid.jumbo_slots*bgep->chipid.recv_jumbo_size;
	rxbuffsize += BGE_MINI_SLOTS_USED*BGE_MINI_BUFF_SIZE;

	txbuffsize = BGE_SEND_BUF_NUM*bgep->chipid.snd_buff_size;
	txbuffsize *= tx_rings;

	rxdescsize = rx_rings*bgep->chipid.recv_slots;
	rxdescsize *= sizeof (bge_rbd_t);

	rxbuffdescsize = BGE_STD_SLOTS_USED;
	rxbuffdescsize += bgep->chipid.jumbo_slots;
	rxbuffdescsize += BGE_MINI_SLOTS_USED;
	rxbuffdescsize *= sizeof (bge_rbd_t);

	txdescsize = tx_rings*BGE_SEND_SLOTS_USED;
	txdescsize *= sizeof (bge_sbd_t);
	txdescsize += sizeof (bge_statistics_t);
	txdescsize += sizeof (bge_status_t);
	txdescsize += BGE_STATUS_PADDING;

	/*
	 * Enable PCI relaxed ordering only for RX/TX data buffers
	 */
	if (bge_relaxed_ordering)
		dma_attr.dma_attr_flags |= DDI_DMA_RELAXED_ORDERING;

	/*
	 * Allocate memory & handles for RX buffers
	 */
	ASSERT((rxbuffsize % BGE_SPLIT) == 0);
	for (split = 0; split < BGE_SPLIT; ++split) {
		err = bge_alloc_dma_mem(bgep, rxbuffsize/BGE_SPLIT,
		    &bge_data_accattr, DDI_DMA_READ | BGE_DMA_MODE,
		    &bgep->rx_buff[split]);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	/*
	 * Allocate memory & handles for TX buffers
	 */
	ASSERT((txbuffsize % BGE_SPLIT) == 0);
	for (split = 0; split < BGE_SPLIT; ++split) {
		err = bge_alloc_dma_mem(bgep, txbuffsize/BGE_SPLIT,
		    &bge_data_accattr, DDI_DMA_WRITE | BGE_DMA_MODE,
		    &bgep->tx_buff[split]);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	dma_attr.dma_attr_flags &= ~DDI_DMA_RELAXED_ORDERING;

	/*
	 * Allocate memory & handles for receive return rings
	 */
	ASSERT((rxdescsize % rx_rings) == 0);
	for (split = 0; split < rx_rings; ++split) {
		err = bge_alloc_dma_mem(bgep, rxdescsize/rx_rings,
		    &bge_desc_accattr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    &bgep->rx_desc[split]);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	/*
	 * Allocate memory & handles for buffer (producer) descriptor rings
	 */
	err = bge_alloc_dma_mem(bgep, rxbuffdescsize, &bge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &bgep->rx_desc[split]);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory & handles for TX descriptor rings,
	 * status block, and statistics area
	 */
	err = bge_alloc_dma_mem(bgep, txdescsize, &bge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &bgep->tx_desc);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Now carve up each of the allocated areas ...
	 */
	for (split = 0; split < BGE_SPLIT; ++split) {
		area = bgep->rx_buff[split];
		bge_slice_chunk(&bgep->buff[BGE_STD_BUFF_RING].buf[split],
		    &area, BGE_STD_SLOTS_USED/BGE_SPLIT,
		    bgep->chipid.std_buf_size);
		bge_slice_chunk(&bgep->buff[BGE_JUMBO_BUFF_RING].buf[split],
		    &area, bgep->chipid.jumbo_slots/BGE_SPLIT,
		    bgep->chipid.recv_jumbo_size);
		bge_slice_chunk(&bgep->buff[BGE_MINI_BUFF_RING].buf[split],
		    &area, BGE_MINI_SLOTS_USED/BGE_SPLIT,
		    BGE_MINI_BUFF_SIZE);
		ASSERT(area.alength >= 0);
	}

	for (split = 0; split < BGE_SPLIT; ++split) {
		area = bgep->tx_buff[split];
		for (ring = 0; ring < tx_rings; ++ring)
			bge_slice_chunk(&bgep->send[ring].buf[0][split],
			    &area, BGE_SEND_BUF_NUM/BGE_SPLIT,
			    bgep->chipid.snd_buff_size);
		for (; ring < BGE_SEND_RINGS_MAX; ++ring)
			bge_slice_chunk(&bgep->send[ring].buf[0][split],
			    &area, 0, bgep->chipid.snd_buff_size);
		ASSERT(area.alength >= 0);
	}

	for (ring = 0; ring < rx_rings; ++ring)
		bge_slice_chunk(&bgep->recv[ring].desc, &bgep->rx_desc[ring],
		    bgep->chipid.recv_slots, sizeof (bge_rbd_t));

	area = bgep->rx_desc[rx_rings];
	for (; ring < BGE_RECV_RINGS_MAX; ++ring)
		bge_slice_chunk(&bgep->recv[ring].desc, &area,
		    0, sizeof (bge_rbd_t));
	bge_slice_chunk(&bgep->buff[BGE_STD_BUFF_RING].desc, &area,
	    BGE_STD_SLOTS_USED, sizeof (bge_rbd_t));
	bge_slice_chunk(&bgep->buff[BGE_JUMBO_BUFF_RING].desc, &area,
	    bgep->chipid.jumbo_slots, sizeof (bge_rbd_t));
	bge_slice_chunk(&bgep->buff[BGE_MINI_BUFF_RING].desc, &area,
	    BGE_MINI_SLOTS_USED, sizeof (bge_rbd_t));
	ASSERT(area.alength == 0);

	area = bgep->tx_desc;
	for (ring = 0; ring < tx_rings; ++ring)
		bge_slice_chunk(&bgep->send[ring].desc, &area,
		    BGE_SEND_SLOTS_USED, sizeof (bge_sbd_t));
	for (; ring < BGE_SEND_RINGS_MAX; ++ring)
		bge_slice_chunk(&bgep->send[ring].desc, &area,
		    0, sizeof (bge_sbd_t));
	bge_slice_chunk(&bgep->statistics, &area, 1, sizeof (bge_statistics_t));
	bge_slice_chunk(&bgep->status_block, &area, 1, sizeof (bge_status_t));
	ASSERT(area.alength == BGE_STATUS_PADDING);
	DMA_ZERO(bgep->status_block);

	return (DDI_SUCCESS);
}

/*
 * This routine frees the transmit and receive buffers and descriptors.
 * Make sure the chip is stopped before calling it!
 */
void
bge_free_bufs(bge_t *bgep)
{
	int split;

	BGE_TRACE(("bge_free_bufs($%p)",
	    (void *)bgep));

	bge_free_dma_mem(&bgep->tx_desc);
	for (split = 0; split < BGE_RECV_RINGS_SPLIT; ++split)
		bge_free_dma_mem(&bgep->rx_desc[split]);
	for (split = 0; split < BGE_SPLIT; ++split)
		bge_free_dma_mem(&bgep->tx_buff[split]);
	for (split = 0; split < BGE_SPLIT; ++split)
		bge_free_dma_mem(&bgep->rx_buff[split]);
}

/*
 * Determine (initial) MAC address ("BIA") to use for this interface
 */

static void
bge_find_mac_address(bge_t *bgep, chip_id_t *cidp)
{
	struct ether_addr sysaddr;
	char propbuf[8];		/* "true" or "false", plus NUL	*/
	uchar_t *bytes;
	int *ints;
	uint_t nelts;
	int err;

	BGE_TRACE(("bge_find_mac_address($%p)",
	    (void *)bgep));

	BGE_DEBUG(("bge_find_mac_address: hw_mac_addr %012llx, => %s (%sset)",
	    cidp->hw_mac_addr,
	    ether_sprintf((void *)cidp->vendor_addr.addr),
	    cidp->vendor_addr.set ? "" : "not "));

	/*
	 * The "vendor's factory-set address" may already have
	 * been extracted from the chip, but if the property
	 * "local-mac-address" is set we use that instead.  It
	 * will normally be set by OBP, but it could also be
	 * specified in a .conf file(!)
	 *
	 * There doesn't seem to be a way to define byte-array
	 * properties in a .conf, so we check whether it looks
	 * like an array of 6 ints instead.
	 *
	 * Then, we check whether it looks like an array of 6
	 * bytes (which it should, if OBP set it).  If we can't
	 * make sense of it either way, we'll ignore it.
	 */
	err = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, bgep->devinfo,
	    DDI_PROP_DONTPASS, localmac_propname, &ints, &nelts);
	if (err == DDI_PROP_SUCCESS) {
		if (nelts == ETHERADDRL) {
			while (nelts--)
				cidp->vendor_addr.addr[nelts] = ints[nelts];
			cidp->vendor_addr.set = B_TRUE;
		}
		ddi_prop_free(ints);
	}

	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, bgep->devinfo,
	    DDI_PROP_DONTPASS, localmac_propname, &bytes, &nelts);
	if (err == DDI_PROP_SUCCESS) {
		if (nelts == ETHERADDRL) {
			while (nelts--)
				cidp->vendor_addr.addr[nelts] = bytes[nelts];
			cidp->vendor_addr.set = B_TRUE;
		}
		ddi_prop_free(bytes);
	}

	BGE_DEBUG(("bge_find_mac_address: +local %s (%sset)",
	    ether_sprintf((void *)cidp->vendor_addr.addr),
	    cidp->vendor_addr.set ? "" : "not "));

	/*
	 * Look up the OBP property "local-mac-address?".  Note that even
	 * though its value is a string (which should be "true" or "false"),
	 * it can't be decoded by ddi_prop_lookup_string(9F).  So, we zero
	 * the buffer first and then fetch the property as an untyped array;
	 * this may or may not include a final NUL, but since there will
	 * always be one left at the end of the buffer we can now treat it
	 * as a string anyway.
	 */
	nelts = sizeof (propbuf);
	bzero(propbuf, nelts--);
	err = ddi_getlongprop_buf(DDI_DEV_T_ANY, bgep->devinfo,
	    DDI_PROP_CANSLEEP, localmac_boolname, propbuf, (int *)&nelts);

	/*
	 * Now, if the address still isn't set from the hardware (SEEPROM)
	 * or the OBP or .conf property, OR if the user has foolishly set
	 * 'local-mac-address? = false', use "the system address" instead
	 * (but only if it's non-null i.e. has been set from the IDPROM).
	 */
	if (cidp->vendor_addr.set == B_FALSE || strcmp(propbuf, "false") == 0)
		if (localetheraddr(NULL, &sysaddr) != 0) {
			ethaddr_copy(&sysaddr, cidp->vendor_addr.addr);
			cidp->vendor_addr.set = B_TRUE;
		}

	BGE_DEBUG(("bge_find_mac_address: +system %s (%sset)",
	    ether_sprintf((void *)cidp->vendor_addr.addr),
	    cidp->vendor_addr.set ? "" : "not "));

	/*
	 * Finally(!), if there's a valid "mac-address" property (created
	 * if we netbooted from this interface), we must use this instead
	 * of any of the above to ensure that the NFS/install server doesn't
	 * get confused by the address changing as Solaris takes over!
	 */
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, bgep->devinfo,
	    DDI_PROP_DONTPASS, macaddr_propname, &bytes, &nelts);
	if (err == DDI_PROP_SUCCESS) {
		if (nelts == ETHERADDRL) {
			while (nelts--)
				cidp->vendor_addr.addr[nelts] = bytes[nelts];
			cidp->vendor_addr.set = B_TRUE;
		}
		ddi_prop_free(bytes);
	}

	BGE_DEBUG(("bge_find_mac_address: =final %s (%sset)",
	    ether_sprintf((void *)cidp->vendor_addr.addr),
	    cidp->vendor_addr.set ? "" : "not "));
}


/*ARGSUSED*/
int
bge_check_acc_handle(bge_t *bgep, ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (de.fme_status);
}

/*ARGSUSED*/
int
bge_check_dma_handle(bge_t *bgep, ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ASSERT(bgep->progress & PROGRESS_BUFS);
	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

/*
 * The IO fault service error handling callback function
 */
/*ARGSUSED*/
static int
bge_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
bge_fm_init(bge_t *bgep)
{
	ddi_iblock_cookie_t iblk;

	/* Only register with IO Fault Services if we have some capability */
	if (bgep->fm_capabilities) {
		bge_reg_accattr.devacc_attr_access = DDI_FLAGERR_ACC;
		bge_desc_accattr.devacc_attr_access = DDI_FLAGERR_ACC;
		dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;

		/* Register capabilities with IO Fault Services */
		ddi_fm_init(bgep->devinfo, &bgep->fm_capabilities, &iblk);

		/*
		 * Initialize pci ereport capabilities if ereport capable
		 */
		if (DDI_FM_EREPORT_CAP(bgep->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(bgep->fm_capabilities))
			pci_ereport_setup(bgep->devinfo);

		/*
		 * Register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(bgep->fm_capabilities))
			ddi_fm_handler_register(bgep->devinfo,
			    bge_fm_error_cb, (void*) bgep);
	} else {
		/*
		 * These fields have to be cleared of FMA if there are no
		 * FMA capabilities at runtime.
		 */
		bge_reg_accattr.devacc_attr_access = DDI_DEFAULT_ACC;
		bge_desc_accattr.devacc_attr_access = DDI_DEFAULT_ACC;
		dma_attr.dma_attr_flags = 0;
	}
}

static void
bge_fm_fini(bge_t *bgep)
{
	/* Only unregister FMA capabilities if we registered some */
	if (bgep->fm_capabilities) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(bgep->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(bgep->fm_capabilities))
			pci_ereport_teardown(bgep->devinfo);

		/*
		 * Un-register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(bgep->fm_capabilities))
			ddi_fm_handler_unregister(bgep->devinfo);

		/* Unregister from IO Fault Services */
		ddi_fm_fini(bgep->devinfo);
	}
}

static void
#ifdef BGE_IPMI_ASF
bge_unattach(bge_t *bgep, uint_t asf_mode)
#else
bge_unattach(bge_t *bgep)
#endif
{
	BGE_TRACE(("bge_unattach($%p)",
		(void *)bgep));

	/*
	 * Flag that no more activity may be initiated
	 */
	bgep->progress &= ~PROGRESS_READY;

	/*
	 * Quiesce the PHY and MAC (leave it reset but still powered).
	 * Clean up and free all BGE data structures
	 */
	if (bgep->periodic_id != NULL) {
		ddi_periodic_delete(bgep->periodic_id);
		bgep->periodic_id = NULL;
	}
	if (bgep->progress & PROGRESS_KSTATS)
		bge_fini_kstats(bgep);
	if (bgep->progress & PROGRESS_NDD)
		bge_nd_cleanup(bgep);
	if (bgep->progress & PROGRESS_PHY)
		bge_phys_reset(bgep);
	if (bgep->progress & PROGRESS_HWINT) {
		mutex_enter(bgep->genlock);
#ifdef BGE_IPMI_ASF
		if (bge_chip_reset(bgep, B_FALSE, asf_mode) != DDI_SUCCESS)
#else
		if (bge_chip_reset(bgep, B_FALSE) != DDI_SUCCESS)
#endif
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);
#ifdef BGE_IPMI_ASF
		if (bgep->asf_enabled) {
			/*
			 * This register has been overlaid. We restore its
			 * initial value here.
			 */
			bge_nic_put32(bgep, BGE_NIC_DATA_SIG_ADDR,
			    BGE_NIC_DATA_SIG);
		}
#endif
		if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK)
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);
		if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);
		mutex_exit(bgep->genlock);
	}
	if (bgep->progress & PROGRESS_INTR) {
		bge_intr_disable(bgep);
		bge_fini_rings(bgep);
	}
	if (bgep->progress & PROGRESS_HWINT) {
		bge_rem_intrs(bgep);
		rw_destroy(bgep->errlock);
		mutex_destroy(bgep->softintrlock);
		mutex_destroy(bgep->genlock);
	}
	if (bgep->progress & PROGRESS_FACTOTUM)
		ddi_remove_softintr(bgep->factotum_id);
	if (bgep->progress & PROGRESS_RESCHED)
		ddi_remove_softintr(bgep->drain_id);
	if (bgep->progress & PROGRESS_BUFS)
		bge_free_bufs(bgep);
	if (bgep->progress & PROGRESS_REGS)
		ddi_regs_map_free(&bgep->io_handle);
	if (bgep->progress & PROGRESS_CFG)
		pci_config_teardown(&bgep->cfg_handle);

	bge_fm_fini(bgep);

	ddi_remove_minor_node(bgep->devinfo, NULL);
	kmem_free(bgep->pstats, sizeof (bge_statistics_reg_t));
	kmem_free(bgep->nd_params, PARAM_COUNT * sizeof (nd_param_t));
	kmem_free(bgep, sizeof (*bgep));
}

static int
bge_resume(dev_info_t *devinfo)
{
	bge_t *bgep;				/* Our private data	*/
	chip_id_t *cidp;
	chip_id_t chipid;

	bgep = ddi_get_driver_private(devinfo);
	if (bgep == NULL)
		return (DDI_FAILURE);

	/*
	 * Refuse to resume if the data structures aren't consistent
	 */
	if (bgep->devinfo != devinfo)
		return (DDI_FAILURE);

#ifdef BGE_IPMI_ASF
	/*
	 * Power management hasn't been supported in BGE now. If you
	 * want to implement it, please add the ASF/IPMI related
	 * code here.
	 */

#endif

	/*
	 * Read chip ID & set up config space command register(s)
	 * Refuse to resume if the chip has changed its identity!
	 */
	cidp = &bgep->chipid;
	mutex_enter(bgep->genlock);
	bge_chip_cfg_init(bgep, &chipid, B_FALSE);
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		mutex_exit(bgep->genlock);
		return (DDI_FAILURE);
	}
	mutex_exit(bgep->genlock);
	if (chipid.vendor != cidp->vendor)
		return (DDI_FAILURE);
	if (chipid.device != cidp->device)
		return (DDI_FAILURE);
	if (chipid.revision != cidp->revision)
		return (DDI_FAILURE);
	if (chipid.asic_rev != cidp->asic_rev)
		return (DDI_FAILURE);

	/*
	 * All OK, reinitialise h/w & kick off GLD scheduling
	 */
	mutex_enter(bgep->genlock);
	if (bge_restart(bgep, B_TRUE) != DDI_SUCCESS) {
		(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		mutex_exit(bgep->genlock);
		return (DDI_FAILURE);
	}
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		mutex_exit(bgep->genlock);
		return (DDI_FAILURE);
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		mutex_exit(bgep->genlock);
		return (DDI_FAILURE);
	}
	mutex_exit(bgep->genlock);
	return (DDI_SUCCESS);
}

/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board successfully probed.
 */
static int
bge_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	bge_t *bgep;				/* Our private data	*/
	mac_register_t *macp;
	chip_id_t *cidp;
	caddr_t regs;
	int instance;
	int err;
	int intr_types;
#ifdef BGE_IPMI_ASF
	uint32_t mhcrValue;
#ifdef __sparc
	uint16_t value16;
#endif
#ifdef BGE_NETCONSOLE
	int retval;
#endif
#endif

	instance = ddi_get_instance(devinfo);

	BGE_GTRACE(("bge_attach($%p, %d) instance %d",
	    (void *)devinfo, cmd, instance));
	BGE_BRKPT(NULL, "bge_attach");

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		return (bge_resume(devinfo));

	case DDI_ATTACH:
		break;
	}

	bgep = kmem_zalloc(sizeof (*bgep), KM_SLEEP);
	bgep->pstats = kmem_zalloc(sizeof (bge_statistics_reg_t), KM_SLEEP);
	bgep->nd_params =
	    kmem_zalloc(PARAM_COUNT * sizeof (nd_param_t), KM_SLEEP);
	ddi_set_driver_private(devinfo, bgep);
	bgep->bge_guard = BGE_GUARD;
	bgep->devinfo = devinfo;

	/*
	 * Initialize more fields in BGE private data
	 */
	bgep->debug = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, debug_propname, bge_debug);
	(void) snprintf(bgep->ifname, sizeof (bgep->ifname), "%s%d",
	    BGE_DRIVER_NAME, instance);

	/*
	 * Initialize for fma support
	 */
	bgep->fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, fm_cap,
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);
	BGE_DEBUG(("bgep->fm_capabilities = %d", bgep->fm_capabilities));
	bge_fm_init(bgep);

	/*
	 * Look up the IOMMU's page size for DVMA mappings (must be
	 * a power of 2) and convert to a mask.  This can be used to
	 * determine whether a message buffer crosses a page boundary.
	 * Note: in 2s complement binary notation, if X is a power of
	 * 2, then -X has the representation "11...1100...00".
	 */
	bgep->pagemask = dvma_pagesize(devinfo);
	ASSERT(ddi_ffs(bgep->pagemask) == ddi_fls(bgep->pagemask));
	bgep->pagemask = -bgep->pagemask;

	/*
	 * Map config space registers
	 * Read chip ID & set up config space command register(s)
	 *
	 * Note: this leaves the chip accessible by Memory Space
	 * accesses, but with interrupts and Bus Mastering off.
	 * This should ensure that nothing untoward will happen
	 * if it has been left active by the (net-)bootloader.
	 * We'll re-enable Bus Mastering once we've reset the chip,
	 * and allow interrupts only when everything else is set up.
	 */
	err = pci_config_setup(devinfo, &bgep->cfg_handle);
#ifdef BGE_IPMI_ASF
#ifdef __sparc
	value16 = pci_config_get16(bgep->cfg_handle, PCI_CONF_COMM);
	value16 = value16 | (PCI_COMM_MAE | PCI_COMM_ME);
	pci_config_put16(bgep->cfg_handle, PCI_CONF_COMM, value16);
	mhcrValue = MHCR_ENABLE_INDIRECT_ACCESS |
	    MHCR_ENABLE_TAGGED_STATUS_MODE |
	    MHCR_MASK_INTERRUPT_MODE |
	    MHCR_MASK_PCI_INT_OUTPUT |
	    MHCR_CLEAR_INTERRUPT_INTA |
	    MHCR_ENABLE_ENDIAN_WORD_SWAP |
	    MHCR_ENABLE_ENDIAN_BYTE_SWAP;
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR, mhcrValue);
	bge_ind_put32(bgep, MEMORY_ARBITER_MODE_REG,
	    bge_ind_get32(bgep, MEMORY_ARBITER_MODE_REG) |
	    MEMORY_ARBITER_ENABLE);
#else
	mhcrValue = pci_config_get32(bgep->cfg_handle, PCI_CONF_BGE_MHCR);
#endif
	if (mhcrValue & MHCR_ENABLE_ENDIAN_WORD_SWAP) {
		bgep->asf_wordswapped = B_TRUE;
	} else {
		bgep->asf_wordswapped = B_FALSE;
	}
	bge_asf_get_config(bgep);
#endif
	if (err != DDI_SUCCESS) {
		bge_problem(bgep, "pci_config_setup() failed");
		goto attach_fail;
	}
	bgep->progress |= PROGRESS_CFG;
	cidp = &bgep->chipid;
	bzero(cidp, sizeof (*cidp));
	bge_chip_cfg_init(bgep, cidp, B_FALSE);
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		goto attach_fail;
	}

#ifdef BGE_IPMI_ASF
	if (DEVICE_5721_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
		bgep->asf_newhandshake = B_TRUE;
	} else {
		bgep->asf_newhandshake = B_FALSE;
	}
#endif

	/*
	 * Update those parts of the chip ID derived from volatile
	 * registers with the values seen by OBP (in case the chip
	 * has been reset externally and therefore lost them).
	 */
	cidp->subven = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, subven_propname, cidp->subven);
	cidp->subdev = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, subdev_propname, cidp->subdev);
	cidp->clsize = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, clsize_propname, cidp->clsize);
	cidp->latency = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, latency_propname, cidp->latency);
	cidp->rx_rings = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, rxrings_propname, cidp->rx_rings);
	cidp->tx_rings = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, txrings_propname, cidp->tx_rings);

	if (bge_jumbo_enable == B_TRUE) {
		cidp->default_mtu = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
		    DDI_PROP_DONTPASS, default_mtu, BGE_DEFAULT_MTU);
		if ((cidp->default_mtu < BGE_DEFAULT_MTU)||
		    (cidp->default_mtu > BGE_MAXIMUM_MTU)) {
			cidp->default_mtu = BGE_DEFAULT_MTU;
		}
	}
	/*
	 * Map operating registers
	 */
	err = ddi_regs_map_setup(devinfo, BGE_PCI_OPREGS_RNUMBER,
	    &regs, 0, 0, &bge_reg_accattr, &bgep->io_handle);
	if (err != DDI_SUCCESS) {
		bge_problem(bgep, "ddi_regs_map_setup() failed");
		goto attach_fail;
	}
	bgep->io_regs = regs;
	bgep->progress |= PROGRESS_REGS;

	/*
	 * Characterise the device, so we know its requirements.
	 * Then allocate the appropriate TX and RX descriptors & buffers.
	 */
	if (bge_chip_id_init(bgep) == EIO) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		goto attach_fail;
	}
	err = bge_alloc_bufs(bgep);
	if (err != DDI_SUCCESS) {
		bge_problem(bgep, "DMA buffer allocation failed");
		goto attach_fail;
	}
	bgep->progress |= PROGRESS_BUFS;

	/*
	 * Add the softint handlers:
	 *
	 * Both of these handlers are used to avoid restrictions on the
	 * context and/or mutexes required for some operations.  In
	 * particular, the hardware interrupt handler and its subfunctions
	 * can detect a number of conditions that we don't want to handle
	 * in that context or with that set of mutexes held.  So, these
	 * softints are triggered instead:
	 *
	 * the <resched> softint is triggered if we have previously
	 * had to refuse to send a packet because of resource shortage
	 * (we've run out of transmit buffers), but the send completion
	 * interrupt handler has now detected that more buffers have
	 * become available.
	 *
	 * the <factotum> is triggered if the h/w interrupt handler
	 * sees the <link state changed> or <error> bits in the status
	 * block.  It's also triggered periodically to poll the link
	 * state, just in case we aren't getting link status change
	 * interrupts ...
	 */
	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW, &bgep->drain_id,
	    NULL, NULL, bge_send_drain, (caddr_t)bgep);
	if (err != DDI_SUCCESS) {
		bge_problem(bgep, "ddi_add_softintr() failed");
		goto attach_fail;
	}
	bgep->progress |= PROGRESS_RESCHED;
	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW, &bgep->factotum_id,
	    NULL, NULL, bge_chip_factotum, (caddr_t)bgep);
	if (err != DDI_SUCCESS) {
		bge_problem(bgep, "ddi_add_softintr() failed");
		goto attach_fail;
	}
	bgep->progress |= PROGRESS_FACTOTUM;

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(devinfo, &intr_types) != DDI_SUCCESS) {
		bge_error(bgep, "ddi_intr_get_supported_types failed\n");

		goto attach_fail;
	}

	BGE_DEBUG(("%s: ddi_intr_get_supported_types() returned: %x",
	    bgep->ifname, intr_types));

	if ((intr_types & DDI_INTR_TYPE_MSI) && bgep->chipid.msi_enabled) {
		if (bge_add_intrs(bgep, DDI_INTR_TYPE_MSI) != DDI_SUCCESS) {
			bge_error(bgep, "MSI registration failed, "
			    "trying FIXED interrupt type\n");
		} else {
			BGE_DEBUG(("%s: Using MSI interrupt type",
			    bgep->ifname));
			bgep->intr_type = DDI_INTR_TYPE_MSI;
			bgep->progress |= PROGRESS_HWINT;
		}
	}

	if (!(bgep->progress & PROGRESS_HWINT) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		if (bge_add_intrs(bgep, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS) {
			bge_error(bgep, "FIXED interrupt "
			    "registration failed\n");
			goto attach_fail;
		}

		BGE_DEBUG(("%s: Using FIXED interrupt type", bgep->ifname));

		bgep->intr_type = DDI_INTR_TYPE_FIXED;
		bgep->progress |= PROGRESS_HWINT;
	}

	if (!(bgep->progress & PROGRESS_HWINT)) {
		bge_error(bgep, "No interrupts registered\n");
		goto attach_fail;
	}

	/*
	 * Note that interrupts are not enabled yet as
	 * mutex locks are not initialized. Initialize mutex locks.
	 */
	mutex_init(bgep->genlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));
	mutex_init(bgep->softintrlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));
	rw_init(bgep->errlock, NULL, RW_DRIVER,
	    DDI_INTR_PRI(bgep->intr_pri));

	/*
	 * Initialize rings.
	 */
	bge_init_rings(bgep);

	/*
	 * Now that mutex locks are initialized, enable interrupts.
	 */
	bge_intr_enable(bgep);
	bgep->progress |= PROGRESS_INTR;

	/*
	 * Initialise link state variables
	 * Stop, reset & reinitialise the chip.
	 * Initialise the (internal) PHY.
	 */
	bgep->link_state = LINK_STATE_UNKNOWN;

	mutex_enter(bgep->genlock);

	/*
	 * Reset chip & rings to initial state; also reset address
	 * filtering, promiscuity, loopback mode.
	 */
#ifdef BGE_IPMI_ASF
#ifdef BGE_NETCONSOLE
	if (bge_reset(bgep, ASF_MODE_INIT) != DDI_SUCCESS) {
#else
	if (bge_reset(bgep, ASF_MODE_SHUTDOWN) != DDI_SUCCESS) {
#endif
#else
	if (bge_reset(bgep) != DDI_SUCCESS) {
#endif
		(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		mutex_exit(bgep->genlock);
		goto attach_fail;
	}

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		bgep->asf_status = ASF_STAT_RUN_INIT;
	}
#endif

	bzero(bgep->mcast_hash, sizeof (bgep->mcast_hash));
	bzero(bgep->mcast_refs, sizeof (bgep->mcast_refs));
	bgep->promisc = B_FALSE;
	bgep->param_loop_mode = BGE_LOOP_NONE;
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		mutex_exit(bgep->genlock);
		goto attach_fail;
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		mutex_exit(bgep->genlock);
		goto attach_fail;
	}

	mutex_exit(bgep->genlock);

	if (bge_phys_init(bgep) == EIO) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_LOST);
		goto attach_fail;
	}
	bgep->progress |= PROGRESS_PHY;

	/*
	 * Register NDD-tweakable parameters
	 */
	if (bge_nd_init(bgep)) {
		bge_problem(bgep, "bge_nd_init() failed");
		goto attach_fail;
	}
	bgep->progress |= PROGRESS_NDD;

	/*
	 * Create & initialise named kstats
	 */
	bge_init_kstats(bgep, instance);
	bgep->progress |= PROGRESS_KSTATS;

	/*
	 * Determine whether to override the chip's own MAC address
	 */
	bge_find_mac_address(bgep, cidp);
	ethaddr_copy(cidp->vendor_addr.addr, bgep->curr_addr[0].addr);
	bgep->curr_addr[0].set = B_TRUE;

	bgep->unicst_addr_total = MAC_ADDRESS_REGS_MAX;
	/*
	 * Address available is one less than MAX
	 * as primary address is not advertised
	 * as a multiple MAC address.
	 */
	bgep->unicst_addr_avail = MAC_ADDRESS_REGS_MAX - 1;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		goto attach_fail;
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = bgep;
	macp->m_dip = devinfo;
	macp->m_src_addr = bgep->curr_addr[0].addr;
	macp->m_callbacks = &bge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = cidp->ethmax_size - sizeof (struct ether_header);
	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're all ready to start()
	 */
	err = mac_register(macp, &bgep->mh);
	mac_free(macp);
	if (err != 0)
		goto attach_fail;

	/*
	 * Register a periodical handler.
	 * bge_chip_cyclic() is invoked in kernel context.
	 */
	bgep->periodic_id = ddi_periodic_add(bge_chip_cyclic, bgep,
	    BGE_CYCLIC_PERIOD, DDI_IPL_0);

	bgep->progress |= PROGRESS_READY;
	ASSERT(bgep->bge_guard == BGE_GUARD);
#ifdef BGE_IPMI_ASF
#ifdef BGE_NETCONSOLE
	if (bgep->asf_enabled) {
		mutex_enter(bgep->genlock);
		retval = bge_chip_start(bgep, B_TRUE);
		mutex_exit(bgep->genlock);
		if (retval != DDI_SUCCESS)
			goto attach_fail;
	}
#endif
#endif
	return (DDI_SUCCESS);

attach_fail:
#ifdef BGE_IPMI_ASF
	bge_unattach(bgep, ASF_MODE_SHUTDOWN);
#else
	bge_unattach(bgep);
#endif
	return (DDI_FAILURE);
}

/*
 *	bge_suspend() -- suspend transmit/receive for powerdown
 */
static int
bge_suspend(bge_t *bgep)
{
	/*
	 * Stop processing and idle (powerdown) the PHY ...
	 */
	mutex_enter(bgep->genlock);
#ifdef BGE_IPMI_ASF
	/*
	 * Power management hasn't been supported in BGE now. If you
	 * want to implement it, please add the ASF/IPMI related
	 * code here.
	 */
#endif
	bge_stop(bgep);
	if (bge_phys_idle(bgep) != DDI_SUCCESS) {
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (DDI_FAILURE);
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (DDI_FAILURE);
	}
	mutex_exit(bgep->genlock);

	return (DDI_SUCCESS);
}

/*
 * detach(9E) -- Detach a device from the system
 */
static int
bge_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	bge_t *bgep;
#ifdef BGE_IPMI_ASF
	uint_t asf_mode;
	asf_mode = ASF_MODE_NONE;
#endif

	BGE_GTRACE(("bge_detach($%p, %d)", (void *)devinfo, cmd));

	bgep = ddi_get_driver_private(devinfo);

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (bge_suspend(bgep));

	case DDI_DETACH:
		break;
	}

#ifdef BGE_IPMI_ASF
	mutex_enter(bgep->genlock);
	if (bgep->asf_enabled && ((bgep->asf_status == ASF_STAT_RUN) ||
	    (bgep->asf_status == ASF_STAT_RUN_INIT))) {

		bge_asf_update_status(bgep);
		if (bgep->asf_status == ASF_STAT_RUN) {
			bge_asf_stop_timer(bgep);
		}
		bgep->asf_status = ASF_STAT_STOP;

		bge_asf_pre_reset_operations(bgep, BGE_SHUTDOWN_RESET);

		if (bgep->asf_pseudostop) {
			bge_chip_stop(bgep, B_FALSE);
			bgep->bge_mac_state = BGE_MAC_STOPPED;
			bgep->asf_pseudostop = B_FALSE;
		}

		asf_mode = ASF_MODE_POST_SHUTDOWN;

		if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK)
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);
		if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);
	}
	mutex_exit(bgep->genlock);
#endif

	/*
	 * Unregister from the GLD subsystem.  This can fail, in
	 * particular if there are DLPI style-2 streams still open -
	 * in which case we just return failure without shutting
	 * down chip operations.
	 */
	if (mac_unregister(bgep->mh) != 0)
		return (DDI_FAILURE);

	/*
	 * All activity stopped, so we can clean up & exit
	 */
#ifdef BGE_IPMI_ASF
	bge_unattach(bgep, asf_mode);
#else
	bge_unattach(bgep);
#endif
	return (DDI_SUCCESS);
}


/*
 * ========== Module Loading Data & Entry Points ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_INIT	/* debug flag for this code	*/

DDI_DEFINE_STREAM_OPS(bge_dev_ops, nulldev, nulldev, bge_attach, bge_detach,
    nodev, NULL, D_MP, NULL);

static struct modldrv bge_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	bge_ident,		/* short description */
	&bge_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&bge_modldrv, NULL
};


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	mac_init_ops(&bge_dev_ops, "bge");
	status = mod_install(&modlinkage);
	if (status == DDI_SUCCESS)
		mutex_init(bge_log_mutex, NULL, MUTEX_DRIVER, NULL);
	else
		mac_fini_ops(&bge_dev_ops);
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&bge_dev_ops);
		mutex_destroy(bge_log_mutex);
	}
	return (status);
}


/*
 * bge_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
static int
bge_add_intrs(bge_t *bgep, int	intr_type)
{
	dev_info_t	*dip = bgep->devinfo;
	int		avail, actual, intr_size, count = 0;
	int		i, flag, ret;

	BGE_DEBUG(("bge_add_intrs($%p, 0x%x)", (void *)bgep, intr_type));

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		bge_error(bgep, "ddi_intr_get_nintrs() failure, ret: %d, "
		    "count: %d", ret, count);

		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		bge_error(bgep, "ddi_intr_get_navail() failure, "
		    "ret: %d, avail: %d\n", ret, avail);

		return (DDI_FAILURE);
	}

	if (avail < count) {
		BGE_DEBUG(("%s: nintrs() returned %d, navail returned %d",
		    bgep->ifname, count, avail));
	}

	/*
	 * BGE hardware generates only single MSI even though it claims
	 * to support multiple MSIs. So, hard code MSI count value to 1.
	 */
	if (intr_type == DDI_INTR_TYPE_MSI) {
		count = 1;
		flag = DDI_INTR_ALLOC_STRICT;
	} else {
		flag = DDI_INTR_ALLOC_NORMAL;
	}

	/* Allocate an array of interrupt handles */
	intr_size = count * sizeof (ddi_intr_handle_t);
	bgep->htable = kmem_alloc(intr_size, KM_SLEEP);

	/* Call ddi_intr_alloc() */
	ret = ddi_intr_alloc(dip, bgep->htable, intr_type, 0,
	    count, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		bge_error(bgep, "ddi_intr_alloc() failed %d\n", ret);

		kmem_free(bgep->htable, intr_size);
		return (DDI_FAILURE);
	}

	if (actual < count) {
		BGE_DEBUG(("%s: Requested: %d, Received: %d",
		    bgep->ifname, count, actual));
	}

	bgep->intr_cnt = actual;

	/*
	 * Get priority for first msi, assume remaining are all the same
	 */
	if ((ret = ddi_intr_get_pri(bgep->htable[0], &bgep->intr_pri)) !=
	    DDI_SUCCESS) {
		bge_error(bgep, "ddi_intr_get_pri() failed %d\n", ret);

		/* Free already allocated intr */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(bgep->htable[i]);
		}

		kmem_free(bgep->htable, intr_size);
		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(bgep->htable[i], bge_intr,
		    (caddr_t)bgep, (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			bge_error(bgep, "ddi_intr_add_handler() "
			    "failed %d\n", ret);

			/* Free already allocated intr */
			for (i = 0; i < actual; i++) {
				(void) ddi_intr_free(bgep->htable[i]);
			}

			kmem_free(bgep->htable, intr_size);
			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(bgep->htable[0], &bgep->intr_cap))
	    != DDI_SUCCESS) {
		bge_error(bgep, "ddi_intr_get_cap() failed %d\n", ret);

		for (i = 0; i < actual; i++) {
			(void) ddi_intr_remove_handler(bgep->htable[i]);
			(void) ddi_intr_free(bgep->htable[i]);
		}

		kmem_free(bgep->htable, intr_size);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * bge_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
bge_rem_intrs(bge_t *bgep)
{
	int	i;

	BGE_DEBUG(("bge_rem_intrs($%p)", (void *)bgep));

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < bgep->intr_cnt; i++) {
		(void) ddi_intr_remove_handler(bgep->htable[i]);
		(void) ddi_intr_free(bgep->htable[i]);
	}

	kmem_free(bgep->htable, bgep->intr_cnt * sizeof (ddi_intr_handle_t));
}


void
bge_intr_enable(bge_t *bgep)
{
	int i;

	if (bgep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(bgep->htable, bgep->intr_cnt);
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < bgep->intr_cnt; i++) {
			(void) ddi_intr_enable(bgep->htable[i]);
		}
	}
}


void
bge_intr_disable(bge_t *bgep)
{
	int i;

	if (bgep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		(void) ddi_intr_block_disable(bgep->htable, bgep->intr_cnt);
	} else {
		for (i = 0; i < bgep->intr_cnt; i++) {
			(void) ddi_intr_disable(bgep->htable[i]);
		}
	}
}

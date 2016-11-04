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
 * Copyright (c) 2010-2013, by Broadcom, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates.
 * All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include "bge_impl.h"
#include <sys/sdt.h>
#include <sys/mac_provider.h>
#include <sys/mac.h>
#include <sys/mac_flow.h>


#ifndef STRINGIFY
#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)
#endif

/*
 * This is the string displayed by modinfo, etc.
 */
static char bge_ident[] = "Broadcom Gb Ethernet";

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
static char eee_propname[] = "bge-eee";
static char fm_cap[] = "fm-capable";
static char default_mtu[] = "default_mtu";

static int bge_add_intrs(bge_t *, int);
static void bge_rem_intrs(bge_t *);
static int bge_unicst_set(void *, const uint8_t *, int);
static int bge_addmac(void *, const uint8_t *);
static int bge_remmac(void *, const uint8_t *);

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x00000000FFFFFFFFull,		/* dma_attr_count_max	*/
	0x0000000000000001ull,		/* dma_attr_align	*/
	0x00000FFF,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x000000000000FFFFull,		/* dma_attr_maxxfer	*/
	0x00000000FFFFFFFFull,		/* dma_attr_seg		*/
	1,				/* dma_attr_sgllen 	*/
	0x00000001,			/* dma_attr_granular 	*/
	DDI_DMA_FLAGERR			/* dma_attr_flags */
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t bge_reg_accattr = {
	DDI_DEVICE_ATTR_V1,
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
	DDI_STRICTORDER_ACC
};

/*
 * DMA access attributes for data: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t bge_data_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static int		bge_m_start(void *);
static void		bge_m_stop(void *);
static int		bge_m_promisc(void *, boolean_t);
static int		bge_m_unicst(void * pArg, const uint8_t *);
static int		bge_m_multicst(void *, boolean_t, const uint8_t *);
static void		bge_m_resources(void * arg);
static void		bge_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t	bge_m_getcapab(void *, mac_capab_t, void *);
static int		bge_unicst_set(void *, const uint8_t *,
    int);
static int		bge_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int		bge_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void		bge_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int		bge_set_priv_prop(bge_t *, const char *, uint_t,
    const void *);
static int		bge_get_priv_prop(bge_t *, const char *, uint_t,
    void *);
static void		bge_priv_propinfo(const char *,
    mac_prop_info_handle_t);

static mac_callbacks_t bge_m_callbacks = {
    MC_IOCTL
#ifdef MC_RESOURCES
  | MC_RESOURCES
#endif
#ifdef MC_SETPROP
  | MC_SETPROP
#endif
#ifdef MC_GETPROP
  | MC_GETPROP
#endif
#ifdef MC_PROPINFO
  | MC_PROPINFO
#endif
  | MC_GETCAPAB,
	bge_m_stat,
	bge_m_start,
	bge_m_stop,
	bge_m_promisc,
	bge_m_multicst,
	bge_m_unicst,
	bge_m_tx,
#ifdef MC_RESOURCES
	bge_m_resources,
#else
	NULL,
#endif
	bge_m_ioctl,
	bge_m_getcapab,
#ifdef MC_OPEN
	NULL,
	NULL,
#endif
#ifdef MC_SETPROP
	bge_m_setprop,
#endif
#ifdef MC_GETPROP
	bge_m_getprop,
#endif
#ifdef MC_PROPINFO
	bge_m_propinfo
#endif
};

char *bge_priv_prop[] = {
	"_adv_asym_pause_cap",
	"_adv_pause_cap",
	"_drain_max",
	"_msi_cnt",
	"_rx_intr_coalesce_blank_time",
	"_tx_intr_coalesce_blank_time",
	"_rx_intr_coalesce_pkt_cnt",
	"_tx_intr_coalesce_pkt_cnt",
	NULL
};

uint8_t zero_addr[6] = {0, 0, 0, 0, 0, 0};
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
		hw_rbd_p->index = (uint16_t)slot;
		hw_rbd_p->len = (uint16_t)bufsize;
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
		bgep->bge_chip_state = BGE_CHIP_STOPPED;
	} else
		bge_stop(bgep);

	bgep->link_state = LINK_STATE_UNKNOWN;
	mac_link_update(bgep->mh, bgep->link_state);

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
			/* forcing a mac link update here */
			bge_phys_check(bgep);
			bgep->link_state = (bgep->param_link_up) ? LINK_STATE_UP :
			                                           LINK_STATE_DOWN;
			mac_link_update(bgep->mh, bgep->link_state);
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
	bgep->watchdog = 0;
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
 *	bge_unicst_set() -- set the physical network address
 */
static int
bge_unicst_set(void *arg, const uint8_t *macaddr, int slot)
{
	bge_t *bgep = arg;		/* private device info	*/

	BGE_TRACE(("bge_unicst_set($%p, %s)", arg,
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
	BGE_DEBUG(("bge_unicst_set($%p) done", arg));
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

extern void bge_wake_factotum(bge_t *);

static boolean_t
bge_param_locked(mac_prop_id_t pr_num)
{
	/*
	 * All adv_* parameters are locked (read-only) while
	 * the device is in any sort of loopback mode ...
	 */
	switch (pr_num) {
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_EN_10HDX_CAP:
		case MAC_PROP_AUTONEG:
		case MAC_PROP_FLOWCTRL:
			return (B_TRUE);
	}
	return (B_FALSE);
}
/*
 * callback functions for set/get of properties
 */
static int
bge_m_setprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	bge_t *bgep = barg;
	int err = 0;
	uint32_t cur_mtu, new_mtu;
	link_flowctrl_t fl;

	mutex_enter(bgep->genlock);
	if (bgep->param_loop_mode != BGE_LOOP_NONE &&
	    bge_param_locked(pr_num)) {
		/*
		 * All adv_* parameters are locked (read-only)
		 * while the device is in any sort of loopback mode.
		 */
		mutex_exit(bgep->genlock);
		return (EBUSY);
	}
	if ((bgep->chipid.flags & CHIP_FLAG_SERDES) &&
	    ((pr_num == MAC_PROP_EN_100FDX_CAP) ||
	    (pr_num == MAC_PROP_EN_100HDX_CAP) ||
	    (pr_num == MAC_PROP_EN_10FDX_CAP) ||
	    (pr_num == MAC_PROP_EN_10HDX_CAP))) {
		/*
		 * these properties are read/write on copper,
		 * read-only and 0 on serdes
		 */
		mutex_exit(bgep->genlock);
		return (ENOTSUP);
	}
	if (DEVICE_5906_SERIES_CHIPSETS(bgep) &&
	    ((pr_num == MAC_PROP_EN_1000FDX_CAP) ||
	    (pr_num == MAC_PROP_EN_1000HDX_CAP))) {
		mutex_exit(bgep->genlock);
		return (ENOTSUP);
	}

	switch (pr_num) {
		case MAC_PROP_EN_1000FDX_CAP:
			bgep->param_en_1000fdx = *(uint8_t *)pr_val;
			bgep->param_adv_1000fdx = *(uint8_t *)pr_val;
			goto reprogram;
		case MAC_PROP_EN_1000HDX_CAP:
			bgep->param_en_1000hdx = *(uint8_t *)pr_val;
			bgep->param_adv_1000hdx = *(uint8_t *)pr_val;
			goto reprogram;
		case MAC_PROP_EN_100FDX_CAP:
			bgep->param_en_100fdx = *(uint8_t *)pr_val;
			bgep->param_adv_100fdx = *(uint8_t *)pr_val;
			goto reprogram;
		case MAC_PROP_EN_100HDX_CAP:
			bgep->param_en_100hdx = *(uint8_t *)pr_val;
			bgep->param_adv_100hdx = *(uint8_t *)pr_val;
			goto reprogram;
		case MAC_PROP_EN_10FDX_CAP:
			bgep->param_en_10fdx = *(uint8_t *)pr_val;
			bgep->param_adv_10fdx = *(uint8_t *)pr_val;
			goto reprogram;
		case MAC_PROP_EN_10HDX_CAP:
			bgep->param_en_10hdx = *(uint8_t *)pr_val;
			bgep->param_adv_10hdx = *(uint8_t *)pr_val;
reprogram:
			if (err == 0 && bge_reprogram(bgep) == IOC_INVAL)
				err = EINVAL;
			break;
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_STATUS:
		case MAC_PROP_SPEED:
		case MAC_PROP_DUPLEX:
			err = ENOTSUP; /* read-only prop. Can't set this */
			break;
		case MAC_PROP_AUTONEG:
			bgep->param_adv_autoneg = *(uint8_t *)pr_val;
			if (bge_reprogram(bgep) == IOC_INVAL)
				err = EINVAL;
			break;
		case MAC_PROP_MTU:
			cur_mtu = bgep->chipid.default_mtu;
			bcopy(pr_val, &new_mtu, sizeof (new_mtu));

			if (new_mtu == cur_mtu) {
				err = 0;
				break;
			}
			if (new_mtu < BGE_DEFAULT_MTU ||
			    new_mtu > BGE_MAXIMUM_MTU) {
				err = EINVAL;
				break;
			}
			if ((new_mtu > BGE_DEFAULT_MTU) &&
			    (bgep->chipid.flags & CHIP_FLAG_NO_JUMBO)) {
				err = EINVAL;
				break;
			}
			if (bgep->bge_mac_state == BGE_MAC_STARTED) {
				err = EBUSY;
				break;
			}
			bgep->chipid.default_mtu = new_mtu;
			if (bge_chip_id_init(bgep)) {
				err = EINVAL;
				break;
			}
			bgep->bge_dma_error = B_TRUE;
			bgep->manual_reset = B_TRUE;
			bge_chip_stop(bgep, B_TRUE);
			bge_wake_factotum(bgep);
			err = 0;
			break;
		case MAC_PROP_FLOWCTRL:
			bcopy(pr_val, &fl, sizeof (fl));
			switch (fl) {
			default:
				err = ENOTSUP;
				break;
			case LINK_FLOWCTRL_NONE:
				bgep->param_adv_pause = 0;
				bgep->param_adv_asym_pause = 0;

				bgep->param_link_rx_pause = B_FALSE;
				bgep->param_link_tx_pause = B_FALSE;
				break;
			case LINK_FLOWCTRL_RX:
				bgep->param_adv_pause = 1;
				bgep->param_adv_asym_pause = 1;

				bgep->param_link_rx_pause = B_TRUE;
				bgep->param_link_tx_pause = B_FALSE;
				break;
			case LINK_FLOWCTRL_TX:
				bgep->param_adv_pause = 0;
				bgep->param_adv_asym_pause = 1;

				bgep->param_link_rx_pause = B_FALSE;
				bgep->param_link_tx_pause = B_TRUE;
				break;
			case LINK_FLOWCTRL_BI:
				bgep->param_adv_pause = 1;
				bgep->param_adv_asym_pause = 0;

				bgep->param_link_rx_pause = B_TRUE;
				bgep->param_link_tx_pause = B_TRUE;
				break;
			}

			if (err == 0) {
				if (bge_reprogram(bgep) == IOC_INVAL)
					err = EINVAL;
			}

			break;
		case MAC_PROP_PRIVATE:
			err = bge_set_priv_prop(bgep, pr_name, pr_valsize,
			    pr_val);
			break;
		default:
			err = ENOTSUP;
			break;
	}
	mutex_exit(bgep->genlock);
	return (err);
}

/* ARGSUSED */
static int
bge_m_getprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	bge_t *bgep = barg;
	int err = 0;

	switch (pr_num) {
		case MAC_PROP_DUPLEX:
			ASSERT(pr_valsize >= sizeof (link_duplex_t));
			bcopy(&bgep->param_link_duplex, pr_val,
			    sizeof (link_duplex_t));
			break;
		case MAC_PROP_SPEED: {
			uint64_t speed = bgep->param_link_speed * 1000000ull;

			ASSERT(pr_valsize >= sizeof (speed));
			bcopy(&speed, pr_val, sizeof (speed));
			break;
		}
		case MAC_PROP_STATUS:
			ASSERT(pr_valsize >= sizeof (link_state_t));
			bcopy(&bgep->link_state, pr_val,
			    sizeof (link_state_t));
			break;
		case MAC_PROP_AUTONEG:
			*(uint8_t *)pr_val = bgep->param_adv_autoneg;
			break;
		case MAC_PROP_FLOWCTRL: {
			link_flowctrl_t fl;

			ASSERT(pr_valsize >= sizeof (fl));

			if (bgep->param_link_rx_pause &&
			    !bgep->param_link_tx_pause)
				fl = LINK_FLOWCTRL_RX;

			if (!bgep->param_link_rx_pause &&
			    !bgep->param_link_tx_pause)
				fl = LINK_FLOWCTRL_NONE;

			if (!bgep->param_link_rx_pause &&
			    bgep->param_link_tx_pause)
				fl = LINK_FLOWCTRL_TX;

			if (bgep->param_link_rx_pause &&
			    bgep->param_link_tx_pause)
				fl = LINK_FLOWCTRL_BI;
			bcopy(&fl, pr_val, sizeof (fl));
			break;
		}
		case MAC_PROP_ADV_1000FDX_CAP:
			*(uint8_t *)pr_val = bgep->param_adv_1000fdx;
			break;
		case MAC_PROP_EN_1000FDX_CAP:
			*(uint8_t *)pr_val = bgep->param_en_1000fdx;
			break;
		case MAC_PROP_ADV_1000HDX_CAP:
			*(uint8_t *)pr_val = bgep->param_adv_1000hdx;
			break;
		case MAC_PROP_EN_1000HDX_CAP:
			*(uint8_t *)pr_val = bgep->param_en_1000hdx;
			break;
		case MAC_PROP_ADV_100FDX_CAP:
			*(uint8_t *)pr_val = bgep->param_adv_100fdx;
			break;
		case MAC_PROP_EN_100FDX_CAP:
			*(uint8_t *)pr_val = bgep->param_en_100fdx;
			break;
		case MAC_PROP_ADV_100HDX_CAP:
			*(uint8_t *)pr_val = bgep->param_adv_100hdx;
			break;
		case MAC_PROP_EN_100HDX_CAP:
			*(uint8_t *)pr_val = bgep->param_en_100hdx;
			break;
		case MAC_PROP_ADV_10FDX_CAP:
			*(uint8_t *)pr_val = bgep->param_adv_10fdx;
			break;
		case MAC_PROP_EN_10FDX_CAP:
			*(uint8_t *)pr_val = bgep->param_en_10fdx;
			break;
		case MAC_PROP_ADV_10HDX_CAP:
			*(uint8_t *)pr_val = bgep->param_adv_10hdx;
			break;
		case MAC_PROP_EN_10HDX_CAP:
			*(uint8_t *)pr_val = bgep->param_en_10hdx;
			break;
		case MAC_PROP_ADV_100T4_CAP:
		case MAC_PROP_EN_100T4_CAP:
			*(uint8_t *)pr_val = 0;
			break;
		case MAC_PROP_PRIVATE:
			err = bge_get_priv_prop(bgep, pr_name,
			    pr_valsize, pr_val);
			return (err);
		default:
			return (ENOTSUP);
	}
	return (0);
}

static void
bge_m_propinfo(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	bge_t *bgep = barg;
	int flags = bgep->chipid.flags;

	/*
	 * By default permissions are read/write unless specified
	 * otherwise by the driver.
	 */

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_100T4_CAP:
	case MAC_PROP_EN_100T4_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_1000FDX_CAP:
	case MAC_PROP_EN_1000HDX_CAP:
		if (DEVICE_5906_SERIES_CHIPSETS(bgep))
			mac_prop_info_set_default_uint8(prh, 0);
		else
			mac_prop_info_set_default_uint8(prh, 1);
		break;

	case MAC_PROP_EN_100FDX_CAP:
	case MAC_PROP_EN_100HDX_CAP:
	case MAC_PROP_EN_10FDX_CAP:
	case MAC_PROP_EN_10HDX_CAP:
		mac_prop_info_set_default_uint8(prh,
		    (flags & CHIP_FLAG_SERDES) ? 0 : 1);
		break;

	case MAC_PROP_AUTONEG:
		mac_prop_info_set_default_uint8(prh, 1);
		break;

	case MAC_PROP_FLOWCTRL:
		mac_prop_info_set_default_link_flowctrl(prh,
		    LINK_FLOWCTRL_BI);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh, BGE_DEFAULT_MTU,
		    (flags & CHIP_FLAG_NO_JUMBO) ?
		    BGE_DEFAULT_MTU : BGE_MAXIMUM_MTU);
		break;

	case MAC_PROP_PRIVATE:
		bge_priv_propinfo(pr_name, prh);
		break;
	}

	mutex_enter(bgep->genlock);
	if ((bgep->param_loop_mode != BGE_LOOP_NONE &&
	    bge_param_locked(pr_num)) ||
	    ((bgep->chipid.flags & CHIP_FLAG_SERDES) &&
	    ((pr_num == MAC_PROP_EN_100FDX_CAP) ||
	    (pr_num == MAC_PROP_EN_100HDX_CAP) ||
	    (pr_num == MAC_PROP_EN_10FDX_CAP) ||
	    (pr_num == MAC_PROP_EN_10HDX_CAP))) ||
	    (DEVICE_5906_SERIES_CHIPSETS(bgep) &&
	    ((pr_num == MAC_PROP_EN_1000FDX_CAP) ||
	    (pr_num == MAC_PROP_EN_1000HDX_CAP))))
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
	mutex_exit(bgep->genlock);
}

/* ARGSUSED */
static int
bge_set_priv_prop(bge_t *bgep, const char *pr_name, uint_t pr_valsize,
    const void *pr_val)
{
	int err = 0;
	long result;

	if (strcmp(pr_name, "_adv_pause_cap") == 0) {
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result > 1 || result < 0) {
			err = EINVAL;
		} else {
			bgep->param_adv_pause = (uint32_t)result;
			if (bge_reprogram(bgep) == IOC_INVAL)
				err = EINVAL;
		}
		return (err);
	}
	if (strcmp(pr_name, "_adv_asym_pause_cap") == 0) {
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result > 1 || result < 0) {
			err = EINVAL;
		} else {
			bgep->param_adv_asym_pause = (uint32_t)result;
			if (bge_reprogram(bgep) == IOC_INVAL)
				err = EINVAL;
		}
		return (err);
	}
	if (strcmp(pr_name, "_drain_max") == 0) {

		/*
		 * on the Tx side, we need to update the h/w register for
		 * real packet transmission per packet. The drain_max parameter
		 * is used to reduce the register access. This parameter
		 * controls the max number of packets that we will hold before
		 * updating the bge h/w to trigger h/w transmit. The bge
		 * chipset usually has a max of 512 Tx descriptors, thus
		 * the upper bound on drain_max is 512.
		 */
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result > 512 || result < 1)
			err = EINVAL;
		else {
			bgep->param_drain_max = (uint32_t)result;
			if (bge_reprogram(bgep) == IOC_INVAL)
				err = EINVAL;
		}
		return (err);
	}
	if (strcmp(pr_name, "_msi_cnt") == 0) {

		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result > 7 || result < 0)
			err = EINVAL;
		else {
			bgep->param_msi_cnt = (uint32_t)result;
			if (bge_reprogram(bgep) == IOC_INVAL)
				err = EINVAL;
		}
		return (err);
	}
	if (strcmp(pr_name, "_rx_intr_coalesce_blank_time") == 0) {
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result) != 0)
			return (EINVAL);
		if (result < 0)
			err = EINVAL;
		else {
			bgep->chipid.rx_ticks_norm = (uint32_t)result;
			bge_chip_coalesce_update(bgep);
		}
		return (err);
	}

	if (strcmp(pr_name, "_rx_intr_coalesce_pkt_cnt") == 0) {
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result) != 0)
			return (EINVAL);

		if (result < 0)
			err = EINVAL;
		else {
			bgep->chipid.rx_count_norm = (uint32_t)result;
			bge_chip_coalesce_update(bgep);
		}
		return (err);
	}
	if (strcmp(pr_name, "_tx_intr_coalesce_blank_time") == 0) {
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result) != 0)
			return (EINVAL);
		if (result < 0)
			err = EINVAL;
		else {
			bgep->chipid.tx_ticks_norm = (uint32_t)result;
			bge_chip_coalesce_update(bgep);
		}
		return (err);
	}

	if (strcmp(pr_name, "_tx_intr_coalesce_pkt_cnt") == 0) {
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result) != 0)
			return (EINVAL);

		if (result < 0)
			err = EINVAL;
		else {
			bgep->chipid.tx_count_norm = (uint32_t)result;
			bge_chip_coalesce_update(bgep);
		}
		return (err);
	}
	return (ENOTSUP);
}

static int
bge_get_priv_prop(bge_t *bge, const char *pr_name, uint_t pr_valsize,
    void *pr_val)
{
	int value;

	if (strcmp(pr_name, "_adv_pause_cap") == 0)
		value = bge->param_adv_pause;
	else if (strcmp(pr_name, "_adv_asym_pause_cap") == 0)
		value = bge->param_adv_asym_pause;
	else if (strcmp(pr_name, "_drain_max") == 0)
		value = bge->param_drain_max;
	else if (strcmp(pr_name, "_msi_cnt") == 0)
		value = bge->param_msi_cnt;
	else if (strcmp(pr_name, "_rx_intr_coalesce_blank_time") == 0)
		value = bge->chipid.rx_ticks_norm;
	else if (strcmp(pr_name, "_tx_intr_coalesce_blank_time") == 0)
		value = bge->chipid.tx_ticks_norm;
	else if (strcmp(pr_name, "_rx_intr_coalesce_pkt_cnt") == 0)
		value = bge->chipid.rx_count_norm;
	else if (strcmp(pr_name, "_tx_intr_coalesce_pkt_cnt") == 0)
		value = bge->chipid.tx_count_norm;
	else
		return (ENOTSUP);

	(void) snprintf(pr_val, pr_valsize, "%d", value);
	return (0);
}

static void
bge_priv_propinfo(const char *pr_name, mac_prop_info_handle_t mph)
{
	char valstr[64];
	int value;

	if (strcmp(pr_name, "_adv_pause_cap") == 0)
		value = 1;
	else if (strcmp(pr_name, "_adv_asym_pause_cap") == 0)
		value = 1;
	else if (strcmp(pr_name, "_drain_max") == 0)
		value = 64;
	else if (strcmp(pr_name, "_msi_cnt") == 0)
		value = 0;
	else if (strcmp(pr_name, "_rx_intr_coalesce_blank_time") == 0)
		value = bge_rx_ticks_norm;
	else if (strcmp(pr_name, "_tx_intr_coalesce_blank_time") == 0)
		value = bge_tx_ticks_norm;
	else if (strcmp(pr_name, "_rx_intr_coalesce_pkt_cnt") == 0)
		value = bge_rx_count_norm;
	else if (strcmp(pr_name, "_tx_intr_coalesce_pkt_cnt") == 0)
		value = bge_tx_count_norm;
	else
		return;

	(void) snprintf(valstr, sizeof (valstr), "%d", value);
	mac_prop_info_set_default_str(mph, valstr);
}


static int
bge_m_unicst(void * arg, const uint8_t * mac_addr)
{
	bge_t *bgep = arg;
	int i;

	/* XXX sets the mac address for all ring slots... OK? */
	for (i = 0; i < MIN(bgep->chipid.rx_rings, MAC_ADDRESS_REGS_MAX); i++)
		bge_addmac(&bgep->recv[i], mac_addr);

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

#ifdef MC_RESOURCES

static void
bge_blank(void * arg, time_t tick_cnt, uint_t pkt_cnt)
{
	(void)arg;
	(void)tick_cnt;
	(void)pkt_cnt;
}

static void
bge_m_resources(void * arg)
{
	bge_t *bgep = arg;
	mac_rx_fifo_t mrf;
	int i;

	mrf.mrf_type              = MAC_RX_FIFO;
	mrf.mrf_blank             = bge_blank;
	mrf.mrf_arg               = (void *)bgep;
	mrf.mrf_normal_blank_time = 25;
	mrf.mrf_normal_pkt_count  = 8;

	for (i = 0; i < BGE_RECV_RINGS_MAX; i++) {
		bgep->macRxResourceHandles[i] =
		    mac_resource_add(bgep->mh, (mac_resource_t *)&mrf);
	}
}

#endif /* MC_RESOURCES */

/*
 * Find the slot for the specified unicast address
 */
int
bge_unicst_find(bge_t *bgep, const uint8_t *mac_addr)
{
	int slot;

	ASSERT(mutex_owned(bgep->genlock));

	for (slot = 0; slot < bgep->unicst_addr_total; slot++) {
		if (bcmp(bgep->curr_addr[slot].addr, mac_addr, ETHERADDRL) == 0)
			return (slot);
	}

	return (-1);
}

/*
 * Programs the classifier to start steering packets matching 'mac_addr' to the
 * specified ring 'arg'.
 */
static int
bge_addmac(void *arg, const uint8_t * mac_addr)
{
	recv_ring_t *rrp = (recv_ring_t *)arg;
	bge_t		*bgep = rrp->bgep;
	bge_recv_rule_t	*rulep = bgep->recv_rules;
	bge_rule_info_t	*rinfop = NULL;
	uint8_t		ring = (uint8_t)(rrp - bgep->recv) + 1;
	int		i;
	uint16_t	tmp16;
	uint32_t	tmp32;
	int		slot;
	int		err;

	mutex_enter(bgep->genlock);
	if (bgep->unicst_addr_avail == 0) {
		mutex_exit(bgep->genlock);
		return (ENOSPC);
	}

	/*
	 * First add the unicast address to a available slot.
	 */
	slot = bge_unicst_find(bgep, mac_addr);
	ASSERT(slot == -1);

	for (slot = 0; slot < bgep->unicst_addr_total; slot++) {
		if (!bgep->curr_addr[slot].set) {
			bgep->curr_addr[slot].set = B_TRUE;
			break;
		}
	}

	ASSERT(slot < bgep->unicst_addr_total);
	bgep->unicst_addr_avail--;
	mutex_exit(bgep->genlock);

	if ((err = bge_unicst_set(bgep, mac_addr, slot)) != 0)
		goto fail;

	/* A rule is already here. Deny this.  */
	if (rrp->mac_addr_rule != NULL) {
		err = ether_cmp(mac_addr, rrp->mac_addr_val) ? EEXIST : EBUSY;
		goto fail;
	}

	/*
	 * Allocate a bge_rule_info_t to keep track of which rule slots
	 * are being used.
	 */
	rinfop = kmem_zalloc(sizeof (bge_rule_info_t), KM_NOSLEEP);
	if (rinfop == NULL) {
		err = ENOMEM;
		goto fail;
	}

	/*
	 * Look for the starting slot to place the rules.
	 * The two slots we reserve must be contiguous.
	 */
	for (i = 0; i + 1 < RECV_RULES_NUM_MAX; i++)
		if ((rulep[i].control & RECV_RULE_CTL_ENABLE) == 0 &&
		    (rulep[i+1].control & RECV_RULE_CTL_ENABLE) == 0)
			break;

	ASSERT(i + 1 < RECV_RULES_NUM_MAX);

	bcopy(mac_addr, &tmp32, sizeof (tmp32));
	rulep[i].mask_value = ntohl(tmp32);
	rulep[i].control = RULE_DEST_MAC_1(ring) | RECV_RULE_CTL_AND;
	bge_reg_put32(bgep, RECV_RULE_MASK_REG(i), rulep[i].mask_value);
	bge_reg_put32(bgep, RECV_RULE_CONTROL_REG(i), rulep[i].control);

	bcopy(mac_addr + 4, &tmp16, sizeof (tmp16));
	rulep[i+1].mask_value = 0xffff0000 | ntohs(tmp16);
	rulep[i+1].control = RULE_DEST_MAC_2(ring);
	bge_reg_put32(bgep, RECV_RULE_MASK_REG(i+1), rulep[i+1].mask_value);
	bge_reg_put32(bgep, RECV_RULE_CONTROL_REG(i+1), rulep[i+1].control);
	rinfop->start = i;
	rinfop->count = 2;

	rrp->mac_addr_rule = rinfop;
	bcopy(mac_addr, rrp->mac_addr_val, ETHERADDRL);

	return (0);

fail:
	/* Clear the address just set */
	(void) bge_unicst_set(bgep, zero_addr, slot);
	mutex_enter(bgep->genlock);
	bgep->curr_addr[slot].set = B_FALSE;
	bgep->unicst_addr_avail++;
	mutex_exit(bgep->genlock);

	return (err);
}

/*
 * Stop classifying packets matching the MAC address to the specified ring.
 */
static int
bge_remmac(void *arg, const uint8_t *mac_addr)
{
	recv_ring_t	*rrp = (recv_ring_t *)arg;
	bge_t		*bgep = rrp->bgep;
	bge_recv_rule_t *rulep = bgep->recv_rules;
	bge_rule_info_t *rinfop = rrp->mac_addr_rule;
	int		start;
	int		slot;
	int		err;

	/*
	 * Remove the MAC address from its slot.
	 */
	mutex_enter(bgep->genlock);
	slot = bge_unicst_find(bgep, mac_addr);
	if (slot == -1) {
		mutex_exit(bgep->genlock);
		return (EINVAL);
	}

	ASSERT(bgep->curr_addr[slot].set);
	mutex_exit(bgep->genlock);

	if ((err = bge_unicst_set(bgep, zero_addr, slot)) != 0)
		return (err);

	if (rinfop == NULL || ether_cmp(mac_addr, rrp->mac_addr_val) != 0)
		return (EINVAL);

	start = rinfop->start;
	rulep[start].mask_value = 0;
	rulep[start].control = 0;
	bge_reg_put32(bgep, RECV_RULE_MASK_REG(start), rulep[start].mask_value);
	bge_reg_put32(bgep, RECV_RULE_CONTROL_REG(start), rulep[start].control);
	start++;
	rulep[start].mask_value = 0;
	rulep[start].control = 0;
	bge_reg_put32(bgep, RECV_RULE_MASK_REG(start), rulep[start].mask_value);
	bge_reg_put32(bgep, RECV_RULE_CONTROL_REG(start), rulep[start].control);

	kmem_free(rinfop, sizeof (bge_rule_info_t));
	rrp->mac_addr_rule = NULL;
	bzero(rrp->mac_addr_val, ETHERADDRL);

	mutex_enter(bgep->genlock);
	bgep->curr_addr[slot].set = B_FALSE;
	bgep->unicst_addr_avail++;
	mutex_exit(bgep->genlock);

	return (0);
}


static int
bge_flag_intr_enable(mac_ring_driver_t ih)
{
	recv_ring_t *rrp = (recv_ring_t *)ih;
	bge_t *bgep = rrp->bgep;

	mutex_enter(bgep->genlock);
	rrp->poll_flag = 0;
	mutex_exit(bgep->genlock);

	return (0);
}

static int
bge_flag_intr_disable(mac_ring_driver_t ih)
{
	recv_ring_t *rrp = (recv_ring_t *)ih;
	bge_t *bgep = rrp->bgep;

	mutex_enter(bgep->genlock);
	rrp->poll_flag = 1;
	mutex_exit(bgep->genlock);

	return (0);
}

static int
bge_ring_start(mac_ring_driver_t rh, uint64_t mr_gen_num)
{
	recv_ring_t *rx_ring;

	rx_ring = (recv_ring_t *)rh;
	mutex_enter(rx_ring->rx_lock);
	rx_ring->ring_gen_num = mr_gen_num;
	mutex_exit(rx_ring->rx_lock);
	return (0);
}


/*
 * Callback funtion for MAC layer to register all rings
 * for given ring_group, noted by rg_index.
 */
void
bge_fill_ring(void *arg, mac_ring_type_t rtype, const int rg_index,
    const int index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	bge_t *bgep = arg;
	mac_intr_t *mintr;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		recv_ring_t *rx_ring;
		ASSERT(rg_index >= 0 && rg_index < MIN(bgep->chipid.rx_rings,
		    MAC_ADDRESS_REGS_MAX) && index == 0);

		rx_ring = &bgep->recv[rg_index];
		rx_ring->ring_handle = rh;

		infop->mri_driver = (mac_ring_driver_t)rx_ring;
		infop->mri_start = bge_ring_start;
		infop->mri_stop = NULL;
		infop->mri_poll = bge_poll_ring;
		infop->mri_stat = bge_rx_ring_stat;

		mintr = &infop->mri_intr;
		mintr->mi_enable = (mac_intr_enable_t)bge_flag_intr_enable;
		mintr->mi_disable = (mac_intr_disable_t)bge_flag_intr_disable;

		break;
	}
	case MAC_RING_TYPE_TX:
	default:
		ASSERT(0);
		break;
	}
}

/*
 * Fill infop passed as argument
 * fill in respective ring_group info
 * Each group has a single ring in it. We keep it simple
 * and use the same internal handle for rings and groups.
 */
void
bge_fill_group(void *arg, mac_ring_type_t rtype, const int rg_index,
    mac_group_info_t * infop, mac_group_handle_t gh)
{
	bge_t *bgep = arg;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		recv_ring_t *rx_ring;

		ASSERT(rg_index >= 0 && rg_index < MIN(bgep->chipid.rx_rings,
		    MAC_ADDRESS_REGS_MAX));
		rx_ring = &bgep->recv[rg_index];
		rx_ring->ring_group_handle = gh;

		infop->mgi_driver = (mac_group_driver_t)rx_ring;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = bge_addmac;
		infop->mgi_remmac = bge_remmac;
		infop->mgi_count = 1;
		break;
	}
	case MAC_RING_TYPE_TX:
	default:
		ASSERT(0);
		break;
	}
}


/*ARGSUSED*/
static boolean_t
bge_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	bge_t *bgep = arg;
	mac_capab_rings_t *cap_rings;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		*txflags = HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM;
		break;
	}

	case MAC_CAPAB_RINGS:
		cap_rings = (mac_capab_rings_t *)cap_data;

		/* Temporarily disable multiple tx rings. */
		if (cap_rings->mr_type != MAC_RING_TYPE_RX)
			return (B_FALSE);

		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		cap_rings->mr_rnum =
		cap_rings->mr_gnum =
		    MIN(bgep->chipid.rx_rings, MAC_ADDRESS_REGS_MAX);
		cap_rings->mr_rget = bge_fill_ring;
		cap_rings->mr_gget = bge_fill_group;
		break;

	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

#ifdef NOT_SUPPORTED_XXX

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
		lbsp = (void *)mp->b_cont->b_rptr;
		*lbsp = sizeof (loopmodes);
		return (IOC_REPLY);

	case LB_GET_INFO:
		if (iocp->ioc_count != sizeof (loopmodes))
			return (IOC_INVAL);
		lbpp = (void *)mp->b_cont->b_rptr;
		bcopy(loopmodes, lbpp, sizeof (loopmodes));
		return (IOC_REPLY);

	case LB_GET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (void *)mp->b_cont->b_rptr;
		*lbmp = bgep->param_loop_mode;
		return (IOC_REPLY);

	case LB_SET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (void *)mp->b_cont->b_rptr;
		return (bge_set_loop_mode(bgep, *lbmp));
	}
}

#endif /* NOT_SUPPORTED_XXX */

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
	iocp = (void *)mp->b_rptr;
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

#ifdef NOT_SUPPORTED_XXX
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
		need_privilege = B_FALSE;
		/* FALLTHRU */
	case LB_SET_MODE:
		break;
#endif

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

#ifdef NOT_SUPPORTED_XXX
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = bge_loop_ioctl(bgep, wq, mp, iocp);
		break;
#endif

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
		if (bge_reprogram(bgep) == IOC_INVAL)
			status = IOC_INVAL;
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

/*
 * ========== Per-instance setup/teardown code ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_MEM	/* debug flag for this code	*/
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
	brp->hw_rcb.max_len = (uint16_t)bufsize;
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
	rrp->hw_rcb.max_len = (uint16_t)nslots;
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
	srp->hw_rcb.max_len = (uint16_t)nslots;
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
	if (!(DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep))) {
		if (bge_relaxed_ordering)
			dma_attr.dma_attr_flags |= DDI_DMA_RELAXED_ORDERING;
	}

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
	BGE_DEBUG(("DMA ALLOC: allocated %d chunks for Rx Buffers (rxbuffsize = %d)",
	           rxbuffsize/BGE_SPLIT,
	           rxbuffsize));

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
	BGE_DEBUG(("DMA ALLOC: allocated %d chunks for Tx Buffers (txbuffsize = %d)",
	           txbuffsize/BGE_SPLIT,
	           txbuffsize));

	if (!(DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep))) {
		/* no relaxed ordering for descriptors rings? */
		dma_attr.dma_attr_flags &= ~DDI_DMA_RELAXED_ORDERING;
	}

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
	BGE_DEBUG(("DMA ALLOC: allocated %d chunks for Rx Descs cons (rx_rings = %d, rxdescsize = %d)",
	           rxdescsize/rx_rings,
	           rx_rings,
	           rxdescsize));

	/*
	 * Allocate memory & handles for buffer (producer) descriptor rings.
	 * Note that split=rx_rings.
	 */
	err = bge_alloc_dma_mem(bgep, rxbuffdescsize, &bge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &bgep->rx_desc[split]);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);
	BGE_DEBUG(("DMA ALLOC: allocated 1 chunks for Rx Descs prod (rxbuffdescsize = %d)",
	           rxdescsize));

	/*
	 * Allocate memory & handles for TX descriptor rings,
	 * status block, and statistics area
	 */
	err = bge_alloc_dma_mem(bgep, txdescsize, &bge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &bgep->tx_desc);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);
	BGE_DEBUG(("DMA ALLOC: allocated 1 chunks for Tx Descs / Status Block / Stats (txdescdize = %d)",
               txdescsize));

	/*
	 * Now carve up each of the allocated areas ...
	 */

	/* rx buffers */
	for (split = 0; split < BGE_SPLIT; ++split) {
		area = bgep->rx_buff[split];

		BGE_DEBUG(("RXB CHNK %d INIT: va=%p alen=%d off=%d pa=%llx psz=%d",
		           split,
		           area.mem_va,
		           area.alength,
		           area.offset,
		           area.cookie.dmac_laddress,
		           area.cookie.dmac_size));

		bge_slice_chunk(&bgep->buff[BGE_STD_BUFF_RING].buf[split],
		    &area, BGE_STD_SLOTS_USED/BGE_SPLIT,
		    bgep->chipid.std_buf_size);

		BGE_DEBUG(("RXB SLCE %d STND: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
		           split,
		           bgep->buff[BGE_STD_BUFF_RING].buf[split].mem_va,
		           bgep->buff[BGE_STD_BUFF_RING].buf[split].alength,
		           bgep->buff[BGE_STD_BUFF_RING].buf[split].offset,
		           bgep->buff[BGE_STD_BUFF_RING].buf[split].cookie.dmac_laddress,
		           bgep->buff[BGE_STD_BUFF_RING].buf[split].cookie.dmac_size,
		           BGE_STD_SLOTS_USED/BGE_SPLIT,
		           bgep->chipid.std_buf_size));

		bge_slice_chunk(&bgep->buff[BGE_JUMBO_BUFF_RING].buf[split],
		    &area, bgep->chipid.jumbo_slots/BGE_SPLIT,
		    bgep->chipid.recv_jumbo_size);

		if ((bgep->chipid.jumbo_slots / BGE_SPLIT) > 0)
		{
			BGE_DEBUG(("RXB SLCE %d JUMB: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
			           split,
			           bgep->buff[BGE_JUMBO_BUFF_RING].buf[split].mem_va,
			           bgep->buff[BGE_JUMBO_BUFF_RING].buf[split].alength,
			           bgep->buff[BGE_JUMBO_BUFF_RING].buf[split].offset,
			           bgep->buff[BGE_JUMBO_BUFF_RING].buf[split].cookie.dmac_laddress,
			           bgep->buff[BGE_JUMBO_BUFF_RING].buf[split].cookie.dmac_size,
			           bgep->chipid.jumbo_slots/BGE_SPLIT,
			           bgep->chipid.recv_jumbo_size));
		}

		bge_slice_chunk(&bgep->buff[BGE_MINI_BUFF_RING].buf[split],
		    &area, BGE_MINI_SLOTS_USED/BGE_SPLIT,
		    BGE_MINI_BUFF_SIZE);

		if ((BGE_MINI_SLOTS_USED / BGE_SPLIT) > 0)
		{
			BGE_DEBUG(("RXB SLCE %d MINI: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
			           split,
			           bgep->buff[BGE_MINI_BUFF_RING].buf[split].mem_va,
			           bgep->buff[BGE_MINI_BUFF_RING].buf[split].alength,
			           bgep->buff[BGE_MINI_BUFF_RING].buf[split].offset,
			           bgep->buff[BGE_MINI_BUFF_RING].buf[split].cookie.dmac_laddress,
			           bgep->buff[BGE_MINI_BUFF_RING].buf[split].cookie.dmac_size,
			           BGE_MINI_SLOTS_USED/BGE_SPLIT,
			           BGE_MINI_BUFF_SIZE));
		}

		BGE_DEBUG(("RXB CHNK %d DONE: va=%p alen=%d off=%d pa=%llx psz=%d",
		           split,
		           area.mem_va,
		           area.alength,
		           area.offset,
		           area.cookie.dmac_laddress,
		           area.cookie.dmac_size));
	}

	/* tx buffers */
	for (split = 0; split < BGE_SPLIT; ++split) {
		area = bgep->tx_buff[split];

		BGE_DEBUG(("TXB CHNK %d INIT: va=%p alen=%d off=%d pa=%llx psz=%d",
		           split,
		           area.mem_va,
		           area.alength,
		           area.offset,
		           area.cookie.dmac_laddress,
		           area.cookie.dmac_size));

		for (ring = 0; ring < tx_rings; ++ring) {
			bge_slice_chunk(&bgep->send[ring].buf[0][split],
			    &area, BGE_SEND_BUF_NUM/BGE_SPLIT,
			    bgep->chipid.snd_buff_size);

			BGE_DEBUG(("TXB SLCE %d RING %d: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
			           split, ring,
			           bgep->send[ring].buf[0][split].mem_va,
			           bgep->send[ring].buf[0][split].alength,
			           bgep->send[ring].buf[0][split].offset,
			           bgep->send[ring].buf[0][split].cookie.dmac_laddress,
			           bgep->send[ring].buf[0][split].cookie.dmac_size,
			           BGE_SEND_BUF_NUM/BGE_SPLIT,
			           bgep->chipid.snd_buff_size));
		}

		for (; ring < BGE_SEND_RINGS_MAX; ++ring) {
			bge_slice_chunk(&bgep->send[ring].buf[0][split],
			    &area, 0, bgep->chipid.snd_buff_size);
		}

		BGE_DEBUG(("TXB CHNK %d DONE: va=%p alen=%d off=%d pa=%llx psz=%d",
		           split,
		           area.mem_va,
		           area.alength,
		           area.offset,
		           area.cookie.dmac_laddress,
		           area.cookie.dmac_size));
	}

	for (ring = 0; ring < rx_rings; ++ring) {
		bge_slice_chunk(&bgep->recv[ring].desc, &bgep->rx_desc[ring],
		    bgep->chipid.recv_slots, sizeof (bge_rbd_t));

		BGE_DEBUG(("RXD CONS RING %d: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
		           ring,
		           bgep->recv[ring].desc.mem_va,
		           bgep->recv[ring].desc.alength,
		           bgep->recv[ring].desc.offset,
		           bgep->recv[ring].desc.cookie.dmac_laddress,
		           bgep->recv[ring].desc.cookie.dmac_size,
		           bgep->chipid.recv_slots,
		           sizeof(bge_rbd_t)));
	}

	/* dma alloc for rxbuffdescsize is located at bgep->rx_desc[#rings] */
	area = bgep->rx_desc[rx_rings]; /* note rx_rings = one beyond rings */

	for (; ring < BGE_RECV_RINGS_MAX; ++ring) /* skip unused rings */
		bge_slice_chunk(&bgep->recv[ring].desc, &area,
		    0, sizeof (bge_rbd_t));

	BGE_DEBUG(("RXD PROD INIT: va=%p alen=%d off=%d pa=%llx psz=%d",
	           area.mem_va,
	           area.alength,
	           area.offset,
	           area.cookie.dmac_laddress,
	           area.cookie.dmac_size));

	bge_slice_chunk(&bgep->buff[BGE_STD_BUFF_RING].desc, &area,
	    BGE_STD_SLOTS_USED, sizeof (bge_rbd_t));
	BGE_DEBUG(("RXD PROD STND: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
	           bgep->buff[BGE_STD_BUFF_RING].desc.mem_va,
	           bgep->buff[BGE_STD_BUFF_RING].desc.alength,
	           bgep->buff[BGE_STD_BUFF_RING].desc.offset,
	           bgep->buff[BGE_STD_BUFF_RING].desc.cookie.dmac_laddress,
	           bgep->buff[BGE_STD_BUFF_RING].desc.cookie.dmac_size,
	           BGE_STD_SLOTS_USED,
	           sizeof(bge_rbd_t)));

	bge_slice_chunk(&bgep->buff[BGE_JUMBO_BUFF_RING].desc, &area,
	    bgep->chipid.jumbo_slots, sizeof (bge_rbd_t));
	BGE_DEBUG(("RXD PROD JUMB: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
	           bgep->buff[BGE_JUMBO_BUFF_RING].desc.mem_va,
	           bgep->buff[BGE_JUMBO_BUFF_RING].desc.alength,
	           bgep->buff[BGE_JUMBO_BUFF_RING].desc.offset,
	           bgep->buff[BGE_JUMBO_BUFF_RING].desc.cookie.dmac_laddress,
	           bgep->buff[BGE_JUMBO_BUFF_RING].desc.cookie.dmac_size,
	           bgep->chipid.jumbo_slots,
	           sizeof(bge_rbd_t)));

	bge_slice_chunk(&bgep->buff[BGE_MINI_BUFF_RING].desc, &area,
	    BGE_MINI_SLOTS_USED, sizeof (bge_rbd_t));
	BGE_DEBUG(("RXD PROD MINI: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
	           bgep->buff[BGE_MINI_BUFF_RING].desc.mem_va,
	           bgep->buff[BGE_MINI_BUFF_RING].desc.alength,
	           bgep->buff[BGE_MINI_BUFF_RING].desc.offset,
	           bgep->buff[BGE_MINI_BUFF_RING].desc.cookie.dmac_laddress,
	           bgep->buff[BGE_MINI_BUFF_RING].desc.cookie.dmac_size,
	           BGE_MINI_SLOTS_USED,
	           sizeof(bge_rbd_t)));

	BGE_DEBUG(("RXD PROD DONE: va=%p alen=%d off=%d pa=%llx psz=%d",
	           area.mem_va,
	           area.alength,
	           area.offset,
	           area.cookie.dmac_laddress,
	           area.cookie.dmac_size));

	ASSERT(area.alength == 0);

	area = bgep->tx_desc;

	BGE_DEBUG(("TXD INIT: va=%p alen=%d off=%d pa=%llx psz=%d",
	           area.mem_va,
	           area.alength,
	           area.offset,
	           area.cookie.dmac_laddress,
	           area.cookie.dmac_size));

	for (ring = 0; ring < tx_rings; ++ring) {
		bge_slice_chunk(&bgep->send[ring].desc, &area,
		    BGE_SEND_SLOTS_USED, sizeof (bge_sbd_t));

		BGE_DEBUG(("TXD RING %d: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
		           ring,
		           bgep->send[ring].desc.mem_va,
		           bgep->send[ring].desc.alength,
		           bgep->send[ring].desc.offset,
		           bgep->send[ring].desc.cookie.dmac_laddress,
		           bgep->send[ring].desc.cookie.dmac_size,
		           BGE_SEND_SLOTS_USED,
		           sizeof(bge_sbd_t)));
	}

	for (; ring < BGE_SEND_RINGS_MAX; ++ring) /* skip unused rings */
		bge_slice_chunk(&bgep->send[ring].desc, &area,
		    0, sizeof (bge_sbd_t));

	bge_slice_chunk(&bgep->statistics, &area, 1, sizeof (bge_statistics_t));
	BGE_DEBUG(("TXD STATISTICS: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
	           bgep->statistics.mem_va,
	           bgep->statistics.alength,
	           bgep->statistics.offset,
	           bgep->statistics.cookie.dmac_laddress,
	           bgep->statistics.cookie.dmac_size,
	           1,
	           sizeof(bge_statistics_t)));

	bge_slice_chunk(&bgep->status_block, &area, 1, sizeof (bge_status_t));
	BGE_DEBUG(("TXD STATUS BLOCK: va=%p alen=%d off=%d pa=%llx psz=%d (nslots=%d slotlen=%d)",
	           bgep->status_block.mem_va,
	           bgep->status_block.alength,
	           bgep->status_block.offset,
	           bgep->status_block.cookie.dmac_laddress,
	           bgep->status_block.cookie.dmac_size,
	           1,
	           sizeof(bge_status_t)));

	BGE_DEBUG(("TXD DONE: va=%p alen=%d off=%d pa=%llx psz=%d",
	           area.mem_va,
	           area.alength,
	           area.offset,
	           area.cookie.dmac_laddress,
	           area.cookie.dmac_size));

	ASSERT(area.alength == BGE_STATUS_PADDING);

	DMA_ZERO(bgep->status_block);

	return (DDI_SUCCESS);
}

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_INIT	/* debug flag for this code	*/

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
	if (bgep->progress & PROGRESS_REGS) {
		ddi_regs_map_free(&bgep->io_handle);
		if (bgep->ape_enabled)
			ddi_regs_map_free(&bgep->ape_handle);
	}
	if (bgep->progress & PROGRESS_CFG)
		pci_config_teardown(&bgep->cfg_handle);

	bge_fm_fini(bgep);

	ddi_remove_minor_node(bgep->devinfo, NULL);
	kmem_free(bgep->pstats, sizeof (bge_statistics_reg_t));
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

static int
bge_fw_img_is_valid(bge_t *bgep, uint32_t offset)
{
	uint32_t val;

	if (bge_nvmem_read32(bgep, offset, &val) ||
	    (val & 0xfc000000) != 0x0c000000 ||
	    bge_nvmem_read32(bgep, offset + 4, &val) ||
	    val != 0)
		return (0);

	return (1);
}

static void
bge_read_mgmtfw_ver(bge_t *bgep)
{
	uint32_t val;
	uint32_t offset;
	uint32_t start;
	int i, vlen;

	for (offset = NVM_DIR_START;
	     offset < NVM_DIR_END;
	     offset += NVM_DIRENT_SIZE) {
		if (bge_nvmem_read32(bgep, offset, &val))
			return;

		if ((val >> NVM_DIRTYPE_SHIFT) == NVM_DIRTYPE_ASFINI)
			break;
	}

	if (offset == NVM_DIR_END)
		return;

	if (bge_nvmem_read32(bgep, offset - 4, &start))
		return;

	if (bge_nvmem_read32(bgep, offset + 4, &offset) ||
	    !bge_fw_img_is_valid(bgep, offset) ||
	    bge_nvmem_read32(bgep, offset + 8, &val))
		return;

	offset += val - start;

	vlen = strlen(bgep->fw_version);

	bgep->fw_version[vlen++] = ',';
	bgep->fw_version[vlen++] = ' ';

	for (i = 0; i < 4; i++) {
		uint32_t v;

		if (bge_nvmem_read32(bgep, offset, &v))
			return;

		v = BE_32(v);

		offset += sizeof(v);

		if (vlen > BGE_FW_VER_SIZE - sizeof(v)) {
			memcpy(&bgep->fw_version[vlen], &v, BGE_FW_VER_SIZE - vlen);
			break;
		}

		memcpy(&bgep->fw_version[vlen], &v, sizeof(v));
		vlen += sizeof(v);
	}
}

static void
bge_read_dash_ver(bge_t *bgep)
{
	int vlen;
	uint32_t apedata;
	char *fwtype;

	if (!bgep->ape_enabled || !bgep->asf_enabled)
		return;

	apedata = bge_ape_get32(bgep, BGE_APE_SEG_SIG);
	if (apedata != APE_SEG_SIG_MAGIC)
		return;

	apedata = bge_ape_get32(bgep, BGE_APE_FW_STATUS);
	if (!(apedata & APE_FW_STATUS_READY))
		return;

	apedata = bge_ape_get32(bgep, BGE_APE_FW_VERSION);

	if (bge_ape_get32(bgep, BGE_APE_FW_FEATURES) &
	    BGE_APE_FW_FEATURE_NCSI) {
		bgep->ape_has_ncsi = B_TRUE;
		fwtype = "NCSI";
	} else if ((bgep->chipid.device == DEVICE_ID_5725) ||
	    (bgep->chipid.device == DEVICE_ID_5727)) {
		fwtype = "SMASH";
	} else {
		fwtype = "DASH";
	}

	vlen = strlen(bgep->fw_version);

	snprintf(&bgep->fw_version[vlen], BGE_FW_VER_SIZE - vlen,
	    " %s v%d.%d.%d.%d", fwtype,
	    (apedata & APE_FW_VERSION_MAJMSK) >> APE_FW_VERSION_MAJSFT,
	    (apedata & APE_FW_VERSION_MINMSK) >> APE_FW_VERSION_MINSFT,
	    (apedata & APE_FW_VERSION_REVMSK) >> APE_FW_VERSION_REVSFT,
	    (apedata & APE_FW_VERSION_BLDMSK));
}

static void
bge_read_bc_ver(bge_t *bgep)
{
	uint32_t val;
	uint32_t offset;
	uint32_t start;
	uint32_t ver_offset;
	int i, dst_off;
	uint32_t major;
	uint32_t minor;
	boolean_t newver = B_FALSE;

	if (bge_nvmem_read32(bgep, 0xc, &offset) ||
	    bge_nvmem_read32(bgep, 0x4, &start))
		return;

	if (bge_nvmem_read32(bgep, offset, &val))
		return;

	if ((val & 0xfc000000) == 0x0c000000) {
		if (bge_nvmem_read32(bgep, offset + 4, &val))
			return;

		if (val == 0)
			newver = B_TRUE;
	}

	dst_off = strlen(bgep->fw_version);

	if (newver) {
		if (((BGE_FW_VER_SIZE - dst_off) < 16) ||
		    bge_nvmem_read32(bgep, offset + 8, &ver_offset))
			return;

		offset = offset + ver_offset - start;
		for (i = 0; i < 16; i += 4) {
			if (bge_nvmem_read32(bgep, offset + i, &val))
				return;
			val = BE_32(val);
			memcpy(bgep->fw_version + dst_off + i, &val,
			    sizeof(val));
		}
	} else {
		if (bge_nvmem_read32(bgep, NVM_PTREV_BCVER, &ver_offset))
			return;

		major = (ver_offset & NVM_BCVER_MAJMSK) >> NVM_BCVER_MAJSFT;
		minor = ver_offset & NVM_BCVER_MINMSK;
		snprintf(&bgep->fw_version[dst_off], BGE_FW_VER_SIZE - dst_off,
		    "v%d.%02d", major, minor);
	}
}

static void
bge_read_fw_ver(bge_t *bgep)
{
	uint32_t val;
	uint32_t magic;

	*bgep->fw_version = 0;

	if ((bgep->chipid.nvtype == BGE_NVTYPE_NONE) ||
	    (bgep->chipid.nvtype == BGE_NVTYPE_UNKNOWN)) {
		snprintf(bgep->fw_version, sizeof(bgep->fw_version), "sb");
		return;
	}

	mutex_enter(bgep->genlock);

	bge_nvmem_read32(bgep, 0, &magic);

	if (magic == EEPROM_MAGIC) {
		bge_read_bc_ver(bgep);
	} else {
		/* ignore other configs for now */
		mutex_exit(bgep->genlock);
		return;
	}

	if (bgep->ape_enabled) {
		if (bgep->asf_enabled) {
			bge_read_dash_ver(bgep);
		}
	} else if (bgep->asf_enabled) {
		bge_read_mgmtfw_ver(bgep);
	}

	mutex_exit(bgep->genlock);

	bgep->fw_version[BGE_FW_VER_SIZE - 1] = 0; /* safety */
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
	int *props = NULL;
	uint_t numProps;
	uint32_t regval;
	uint32_t pci_state_reg;
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
	ddi_set_driver_private(devinfo, bgep);
	bgep->bge_guard = BGE_GUARD;
	bgep->devinfo = devinfo;
	bgep->param_drain_max = 64;
	bgep->param_msi_cnt = 0;
	bgep->param_loop_mode = 0;

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

	bgep->ape_enabled = B_FALSE;
	bgep->ape_regs = NULL;

	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		err = ddi_regs_map_setup(devinfo, BGE_PCI_APEREGS_RNUMBER,
		    &regs, 0, 0, &bge_reg_accattr, &bgep->ape_handle);
		if (err != DDI_SUCCESS) {
			ddi_regs_map_free(&bgep->io_handle);
			bge_problem(bgep, "ddi_regs_map_setup() failed");
			goto attach_fail;
		}
		bgep->ape_regs    = regs;
		bgep->ape_enabled = B_TRUE;

		/*
		 * Allow reads and writes to the
		 * APE register and memory space.
		 */

		pci_state_reg = pci_config_get32(bgep->cfg_handle,
		    PCI_CONF_BGE_PCISTATE);
		pci_state_reg |= PCISTATE_ALLOW_APE_CTLSPC_WR |
		    PCISTATE_ALLOW_APE_SHMEM_WR | PCISTATE_ALLOW_APE_PSPACE_WR;
		pci_config_put32(bgep->cfg_handle,
		    PCI_CONF_BGE_PCISTATE, pci_state_reg);
		bge_ape_lock_init(bgep);
	}

#ifdef BGE_IPMI_ASF
#ifdef __sparc
	/*
	 * We need to determine the type of chipset for accessing some configure
	 * registers. (This information will be used by bge_ind_put32,
	 * bge_ind_get32 and bge_nic_read32)
	 */
	bgep->chipid.device = pci_config_get16(bgep->cfg_handle,
	    PCI_CONF_DEVID);
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
	/*
	 * For some chipsets (e.g., BCM5718), if MHCR_ENABLE_ENDIAN_BYTE_SWAP
	 * has been set in PCI_CONF_COMM already, we need to write the
	 * byte-swapped value to it. So we just write zero first for simplicity.
	 */
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep))
		pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR, 0);
#else
	mhcrValue = MHCR_ENABLE_INDIRECT_ACCESS |
	    MHCR_ENABLE_TAGGED_STATUS_MODE |
	    MHCR_MASK_INTERRUPT_MODE |
	    MHCR_MASK_PCI_INT_OUTPUT |
	    MHCR_CLEAR_INTERRUPT_INTA;
#endif
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR, mhcrValue);
	bge_ind_put32(bgep, MEMORY_ARBITER_MODE_REG,
	    bge_ind_get32(bgep, MEMORY_ARBITER_MODE_REG) |
	    MEMORY_ARBITER_ENABLE);
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
	bzero(cidp, sizeof(*cidp));
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
	cidp->eee = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, eee_propname, cidp->eee);

	cidp->default_mtu = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, default_mtu, BGE_DEFAULT_MTU);
	if ((cidp->default_mtu < BGE_DEFAULT_MTU) ||
	    (cidp->default_mtu > BGE_MAXIMUM_MTU)) {
		cidp->default_mtu = BGE_DEFAULT_MTU;
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

	err = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, bgep->devinfo,
	    0, "reg", &props, &numProps);
	if ((err == DDI_PROP_SUCCESS) && (numProps > 0)) {
		bgep->pci_bus  = PCI_REG_BUS_G(props[0]);
		bgep->pci_dev  = PCI_REG_DEV_G(props[0]);
		bgep->pci_func = PCI_REG_FUNC_G(props[0]);
		ddi_prop_free(props);
	}

	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		regval = bge_reg_get32(bgep, CPMU_STATUS_REG);
		if ((bgep->chipid.device == DEVICE_ID_5719) ||
		    (bgep->chipid.device == DEVICE_ID_5720)) {
			bgep->pci_func =
			    ((regval & CPMU_STATUS_FUNC_NUM_5719) >>
			    CPMU_STATUS_FUNC_NUM_5719_SHIFT);
		} else {
			bgep->pci_func = ((regval & CPMU_STATUS_FUNC_NUM) >>
			    CPMU_STATUS_FUNC_NUM_SHIFT);
		}
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
	 * initialize NDD-tweakable parameters
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
	{
		int slot;
		for (slot = 0; slot < MAC_ADDRESS_REGS_MAX; slot++) {
			ethaddr_copy(cidp->vendor_addr.addr,
			    bgep->curr_addr[slot].addr);
			bgep->curr_addr[slot].set = 1;
		}
	}

	bge_read_fw_ver(bgep);

	bgep->unicst_addr_total = MAC_ADDRESS_REGS_MAX;
	bgep->unicst_addr_avail = MAC_ADDRESS_REGS_MAX;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		goto attach_fail;
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = bgep;
	macp->m_dip = devinfo;
	macp->m_src_addr = cidp->vendor_addr.addr;
	macp->m_callbacks = &bge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = cidp->ethmax_size - sizeof (struct ether_header);
	macp->m_margin = VLAN_TAGSZ;
	macp->m_priv_props = bge_priv_prop;

#if defined(ILLUMOS)
	bge_m_unicst(bgep, cidp->vendor_addr.addr);
#endif

	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're all ready to start()
	 */
	err = mac_register(macp, &bgep->mh);
	mac_free(macp);
	if (err != 0)
		goto attach_fail;

	mac_link_update(bgep->mh, LINK_STATE_UNKNOWN);

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

	ddi_report_dev(devinfo);

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
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
#ifdef	__sparc
#define	bge_quiesce	ddi_quiesce_not_supported
#else
static int
bge_quiesce(dev_info_t *devinfo)
{
	bge_t *bgep = ddi_get_driver_private(devinfo);

	if (bgep == NULL)
		return (DDI_FAILURE);

	if (bgep->intr_type == DDI_INTR_TYPE_FIXED) {
		bge_reg_set32(bgep, PCI_CONF_BGE_MHCR,
		    MHCR_MASK_PCI_INT_OUTPUT);
	} else {
		bge_reg_clr32(bgep, MSI_MODE_REG, MSI_MSI_ENABLE);
	}

	/* Stop the chip */
	bge_chip_stop_nonblocking(bgep);

	return (DDI_SUCCESS);
}
#endif

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

DDI_DEFINE_STREAM_OPS(bge_dev_ops,
	nulldev,	/* identify */
	nulldev,	/* probe */
	bge_attach,	/* attach */
	bge_detach,	/* detach */
	nodev,		/* reset */
	NULL,		/* cb_ops */
	D_MP,		/* bus_ops */
	NULL,		/* power */
	bge_quiesce	/* quiesce */
);

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

int
bge_reprogram(bge_t *bgep)
{
	int status = 0;

	ASSERT(mutex_owned(bgep->genlock));

	if (bge_phys_update(bgep) != DDI_SUCCESS) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		status = IOC_INVAL;
	}
#ifdef BGE_IPMI_ASF
	if (bge_chip_sync(bgep, B_TRUE) == DDI_FAILURE) {
#else
	if (bge_chip_sync(bgep) == DDI_FAILURE) {
#endif
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		status = IOC_INVAL;
	}
	if (bgep->intr_type == DDI_INTR_TYPE_MSI)
		bge_chip_msi_trig(bgep);
	return (status);
}

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

#ifdef DEBUG
#define	XNB_DEBUG 1
#endif /* DEBUG */

#include "xnb.h"

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/mac.h>
#include <sys/dlpi.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <vm/seg_kmem.h>
#include <vm/hat_i86.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xendev.h>
#include <sys/balloon_impl.h>
#include <sys/evtchn_impl.h>
#include <sys/gnttab.h>
#include <vm/vm_dep.h>

#include <sys/gld.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <sys/vnic_impl.h> /* blech. */

/*
 * The terms "transmit" and "receive" are used in their traditional
 * sense here - packets from other parts of this system are
 * "transmitted" to the peer domain and those originating from the
 * peer are "received".
 *
 * In some cases this can be confusing, because various data
 * structures are shared with the domU driver, which has the opposite
 * view of what constitutes "transmit" and "receive".  In naming the
 * shared structures the domU driver always wins.
 */

/*
 * XXPV dme: things to do, as well as various things indicated
 * throughout the source:
 * - copy avoidance outbound.
 * - copy avoidance inbound.
 * - transfer credit limiting.
 * - MAC address based filtering.
 */

/*
 * Linux expects to have some headroom in received buffers.  The Linux
 * frontend driver (netfront) checks to see if the headroom is
 * available and will re-allocate the buffer to make room if
 * necessary.  To avoid this we add TX_BUFFER_HEADROOM bytes of
 * headroom to each packet we pass to the peer.
 */
#define	TX_BUFFER_HEADROOM	16

static boolean_t	xnb_cksum_offload = B_TRUE;

static boolean_t	xnb_connect_rings(dev_info_t *);
static void		xnb_disconnect_rings(dev_info_t *);
static void		xnb_oe_state_change(dev_info_t *, ddi_eventcookie_t,
    void *, void *);
static void		xnb_hp_state_change(dev_info_t *, ddi_eventcookie_t,
    void *, void *);

static int	xnb_rxbuf_constructor(void *, void *, int);
static void	xnb_rxbuf_destructor(void *, void *);
static xnb_rxbuf_t *xnb_rxbuf_get(xnb_t *, int);
static void	xnb_rxbuf_put(xnb_t *, xnb_rxbuf_t *);
static void	xnb_rx_notify_peer(xnb_t *);
static void	xnb_rx_complete(xnb_rxbuf_t *);
static void	xnb_rx_mark_complete(xnb_t *, RING_IDX, int16_t);
static void	xnb_rx_schedule_unmop(xnb_t *, gnttab_map_grant_ref_t *);
static void	xnb_rx_perform_pending_unmop(xnb_t *);

#ifdef XNB_DEBUG
#define	NR_GRANT_ENTRIES \
	(NR_GRANT_FRAMES * PAGESIZE / sizeof (grant_entry_t))
#endif /* XNB_DEBUG */

/* XXPV dme: are these really invalid? */
#define	INVALID_GRANT_HANDLE	((grant_handle_t)-1)
#define	INVALID_GRANT_REF	((grant_ref_t)-1)

static kmem_cache_t *xnb_rxbuf_cachep;
static kmutex_t	xnb_alloc_page_lock;

/*
 * Statistics.
 */
static char *aux_statistics[] = {
	"tx_cksum_deferred",
	"rx_cksum_no_need",
	"tx_notify_deferred",
	"tx_notify_sent",
	"rx_notify_deferred",
	"rx_notify_sent",
	"tx_too_early",
	"rx_too_early",
	"rx_allocb_failed",
	"mac_full",
	"spurious_intr",
	"allocation_success",
	"allocation_failure",
	"small_allocation_success",
	"small_allocation_failure",
	"csum_hardware",
	"csum_software",
};

static int
xnb_ks_aux_update(kstat_t *ksp, int flag)
{
	xnb_t *xnbp;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	xnbp = ksp->ks_private;
	knp = ksp->ks_data;

	/*
	 * Assignment order should match that of the names in
	 * aux_statistics.
	 */
	(knp++)->value.ui64 = xnbp->x_stat_tx_cksum_deferred;
	(knp++)->value.ui64 = xnbp->x_stat_rx_cksum_no_need;
	(knp++)->value.ui64 = xnbp->x_stat_tx_notify_deferred;
	(knp++)->value.ui64 = xnbp->x_stat_tx_notify_sent;
	(knp++)->value.ui64 = xnbp->x_stat_rx_notify_deferred;
	(knp++)->value.ui64 = xnbp->x_stat_rx_notify_sent;
	(knp++)->value.ui64 = xnbp->x_stat_tx_too_early;
	(knp++)->value.ui64 = xnbp->x_stat_rx_too_early;
	(knp++)->value.ui64 = xnbp->x_stat_rx_allocb_failed;
	(knp++)->value.ui64 = xnbp->x_stat_mac_full;
	(knp++)->value.ui64 = xnbp->x_stat_spurious_intr;
	(knp++)->value.ui64 = xnbp->x_stat_allocation_success;
	(knp++)->value.ui64 = xnbp->x_stat_allocation_failure;
	(knp++)->value.ui64 = xnbp->x_stat_small_allocation_success;
	(knp++)->value.ui64 = xnbp->x_stat_small_allocation_failure;
	(knp++)->value.ui64 = xnbp->x_stat_csum_hardware;
	(knp++)->value.ui64 = xnbp->x_stat_csum_software;

	return (0);
}

static boolean_t
xnb_ks_init(xnb_t *xnbp)
{
	int nstat = sizeof (aux_statistics) /
	    sizeof (aux_statistics[0]);
	char **cp = aux_statistics;
	kstat_named_t *knp;

	/*
	 * Create and initialise kstats.
	 */
	xnbp->x_kstat_aux = kstat_create(ddi_driver_name(xnbp->x_devinfo),
	    ddi_get_instance(xnbp->x_devinfo), "aux_statistics", "net",
	    KSTAT_TYPE_NAMED, nstat, 0);
	if (xnbp->x_kstat_aux == NULL)
		return (B_FALSE);

	xnbp->x_kstat_aux->ks_private = xnbp;
	xnbp->x_kstat_aux->ks_update = xnb_ks_aux_update;

	knp = xnbp->x_kstat_aux->ks_data;
	while (nstat > 0) {
		kstat_named_init(knp, *cp, KSTAT_DATA_UINT64);

		knp++;
		cp++;
		nstat--;
	}

	kstat_install(xnbp->x_kstat_aux);

	return (B_TRUE);
}

static void
xnb_ks_free(xnb_t *xnbp)
{
	kstat_delete(xnbp->x_kstat_aux);
}

/*
 * Software checksum calculation and insertion for an arbitrary packet.
 */
/*ARGSUSED*/
static mblk_t *
xnb_software_csum(xnb_t *xnbp, mblk_t *mp)
{
	/*
	 * XXPV dme: shouldn't rely on vnic_fix_cksum(), not least
	 * because it doesn't cover all of the interesting cases :-(
	 */
	(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0,
	    HCK_FULLCKSUM, KM_NOSLEEP);

	return (vnic_fix_cksum(mp));
}

mblk_t *
xnb_process_cksum_flags(xnb_t *xnbp, mblk_t *mp, uint32_t capab)
{
	struct ether_header *ehp;
	uint16_t sap;
	uint32_t offset;
	ipha_t *ipha;

	ASSERT(mp->b_next == NULL);

	/*
	 * Check that the packet is contained in a single mblk.  In
	 * the "from peer" path this is true today, but will change
	 * when scatter gather support is added.  In the "to peer"
	 * path we cannot be sure, but in most cases it will be true
	 * (in the xnbo case the packet has come from a MAC device
	 * which is unlikely to split packets).
	 */
	if (mp->b_cont != NULL)
		goto software;

	/*
	 * If the MAC has no hardware capability don't do any further
	 * checking.
	 */
	if (capab == 0)
		goto software;

	ASSERT(MBLKL(mp) >= sizeof (struct ether_header));
	ehp = (struct ether_header *)mp->b_rptr;

	if (ntohs(ehp->ether_type) == VLAN_TPID) {
		struct ether_vlan_header *evhp;

		ASSERT(MBLKL(mp) >= sizeof (struct ether_vlan_header));
		evhp = (struct ether_vlan_header *)mp->b_rptr;
		sap = ntohs(evhp->ether_type);
		offset = sizeof (struct ether_vlan_header);
	} else {
		sap = ntohs(ehp->ether_type);
		offset = sizeof (struct ether_header);
	}

	/*
	 * We only attempt to do IPv4 packets in hardware.
	 */
	if (sap != ETHERTYPE_IP)
		goto software;

	/*
	 * We know that this is an IPv4 packet.
	 */
	ipha = (ipha_t *)(mp->b_rptr + offset);

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/*
		 * This is a TCP/IPv4 or UDP/IPv4 packet.
		 *
		 * If the capabilities indicate that full checksum
		 * offload is available, use it.
		 */
		if ((capab & HCKSUM_INET_FULL_V4) != 0) {
			(void) hcksum_assoc(mp, NULL, NULL,
			    0, 0, 0, 0,
			    HCK_FULLCKSUM, KM_NOSLEEP);

			xnbp->x_stat_csum_hardware++;

			return (mp);
		}

		/*
		 * XXPV dme: If the capabilities indicate that partial
		 * checksum offload is available, we should use it.
		 */

		break;

	default:
		/* Use software. */
		break;
	}

software:
	/*
	 * We are not able to use any offload so do the whole thing in
	 * software.
	 */
	xnbp->x_stat_csum_software++;

	return (xnb_software_csum(xnbp, mp));
}

int
xnb_attach(dev_info_t *dip, xnb_flavour_t *flavour, void *flavour_data)
{
	xnb_t *xnbp;
	char *xsname, mac[ETHERADDRL * 3];

	xnbp = kmem_zalloc(sizeof (*xnbp), KM_SLEEP);

	xnbp->x_flavour = flavour;
	xnbp->x_flavour_data = flavour_data;
	xnbp->x_devinfo = dip;
	xnbp->x_evtchn = INVALID_EVTCHN;
	xnbp->x_irq = B_FALSE;
	xnbp->x_tx_ring_handle = INVALID_GRANT_HANDLE;
	xnbp->x_rx_ring_handle = INVALID_GRANT_HANDLE;
	xnbp->x_cksum_offload = xnb_cksum_offload;
	xnbp->x_connected = B_FALSE;
	xnbp->x_hotplugged = B_FALSE;
	xnbp->x_detachable = B_FALSE;
	xnbp->x_peer = xvdi_get_oeid(dip);
	xnbp->x_rx_pages_writable = B_FALSE;

	xnbp->x_rx_buf_count = 0;
	xnbp->x_rx_unmop_count = 0;

	xnbp->x_tx_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	ASSERT(xnbp->x_tx_va != NULL);

	if (ddi_get_iblock_cookie(dip, 0, &xnbp->x_icookie)
	    != DDI_SUCCESS)
		goto failure;

	mutex_init(&xnbp->x_tx_lock, NULL, MUTEX_DRIVER, xnbp->x_icookie);
	mutex_init(&xnbp->x_rx_lock, NULL, MUTEX_DRIVER, xnbp->x_icookie);

	/* set driver private pointer now */
	ddi_set_driver_private(dip, xnbp);

	if (!xnb_ks_init(xnbp))
		goto late_failure;

	/*
	 * Receive notification of changes in the state of the
	 * driver in the guest domain.
	 */
	if (xvdi_add_event_handler(dip, XS_OE_STATE,
	    xnb_oe_state_change) != DDI_SUCCESS)
		goto very_late_failure;

	/*
	 * Receive notification of hotplug events.
	 */
	if (xvdi_add_event_handler(dip, XS_HP_STATE,
	    xnb_hp_state_change) != DDI_SUCCESS)
		goto very_late_failure;

	xsname = xvdi_get_xsname(dip);

	if (xenbus_printf(XBT_NULL, xsname,
	    "feature-no-csum-offload", "%d",
	    xnbp->x_cksum_offload ? 0 : 1) != 0)
		goto very_very_late_failure;

	if (xenbus_scanf(XBT_NULL, xsname,
	    "mac", "%s", mac) != 0) {
		cmn_err(CE_WARN, "xnb_attach: "
		    "cannot read mac address from %s",
		    xsname);
		goto very_very_late_failure;
	}

	if (ether_aton(mac, xnbp->x_mac_addr) != ETHERADDRL) {
		cmn_err(CE_WARN,
		    "xnb_attach: cannot parse mac address %s",
		    mac);
		goto very_very_late_failure;
	}

	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateInitWait);
	(void) xvdi_post_event(dip, XEN_HP_ADD);

	return (DDI_SUCCESS);

very_very_late_failure: /* not that the naming is getting silly or anything */
	xvdi_remove_event_handler(dip, NULL);

very_late_failure:
	xnb_ks_free(xnbp);

late_failure:
	mutex_destroy(&xnbp->x_rx_lock);
	mutex_destroy(&xnbp->x_tx_lock);

failure:
	vmem_free(heap_arena, xnbp->x_tx_va, PAGESIZE);
	kmem_free(xnbp, sizeof (*xnbp));
	return (DDI_FAILURE);
}

/*ARGSUSED*/
void
xnb_detach(dev_info_t *dip)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);

	ASSERT(xnbp != NULL);
	ASSERT(!xnbp->x_connected);
	ASSERT(xnbp->x_rx_buf_count == 0);

	xnb_disconnect_rings(dip);

	xvdi_remove_event_handler(dip, NULL);

	xnb_ks_free(xnbp);

	ddi_set_driver_private(dip, NULL);

	mutex_destroy(&xnbp->x_tx_lock);
	mutex_destroy(&xnbp->x_rx_lock);

	ASSERT(xnbp->x_tx_va != NULL);
	vmem_free(heap_arena, xnbp->x_tx_va, PAGESIZE);

	kmem_free(xnbp, sizeof (*xnbp));
}


static mfn_t
xnb_alloc_page(xnb_t *xnbp)
{
#define	WARNING_RATE_LIMIT 100
#define	BATCH_SIZE 256
	static mfn_t mfns[BATCH_SIZE];	/* common across all instances */
	static int nth = BATCH_SIZE;
	mfn_t mfn;

	mutex_enter(&xnb_alloc_page_lock);
	if (nth == BATCH_SIZE) {
		if (balloon_alloc_pages(BATCH_SIZE, mfns) != BATCH_SIZE) {
			xnbp->x_stat_allocation_failure++;
			mutex_exit(&xnb_alloc_page_lock);

			/*
			 * Try for a single page in low memory situations.
			 */
			if (balloon_alloc_pages(1, &mfn) != 1) {
				xnbp->x_stat_small_allocation_failure++;
				if ((xnbp->x_stat_small_allocation_failure
				    % WARNING_RATE_LIMIT) == 0) {
					cmn_err(CE_WARN, "xnb_alloc_page: "
					    "Cannot allocate memory to "
					    "transfer packets to peer.");
				}
				return (0);
			} else {
				xnbp->x_stat_small_allocation_success++;
				return (mfn);
			}
		}

		nth = 0;
		xnbp->x_stat_allocation_success++;
	}

	mfn = mfns[nth++];
	mutex_exit(&xnb_alloc_page_lock);

	ASSERT(mfn != 0);

	return (mfn);
#undef BATCH_SIZE
#undef WARNING_RATE_LIMIT
}

/*ARGSUSED*/
static void
xnb_free_page(xnb_t *xnbp, mfn_t mfn)
{
	int r;
	pfn_t pfn;

	pfn = xen_assign_pfn(mfn);
	pfnzero(pfn, 0, PAGESIZE);
	xen_release_pfn(pfn);

	/*
	 * This happens only in the error path, so batching is
	 * not worth the complication.
	 */
	if ((r = balloon_free_pages(1, &mfn, NULL, NULL)) != 1) {
		cmn_err(CE_WARN, "free_page: cannot decrease memory "
		    "reservation (%d): page kept but unusable (mfn = 0x%lx).",
		    r, mfn);
	}
}

mblk_t *
xnb_to_peer(xnb_t *xnbp, mblk_t *mp)
{
	mblk_t *free = mp, *prev = NULL;
	size_t len;
	gnttab_transfer_t *gop;
	boolean_t notify;
	RING_IDX loop, prod, end;

	/*
	 * For each packet the sequence of operations is:
	 *
	 * 1. get a new page from the hypervisor.
	 * 2. get a request slot from the ring.
	 * 3. copy the data into the new page.
	 * 4. transfer the page to the peer.
	 * 5. update the request slot.
	 * 6. kick the peer.
	 * 7. free mp.
	 *
	 * In order to reduce the number of hypercalls, we prepare
	 * several packets for the peer and perform a single hypercall
	 * to transfer them.
	 */

	mutex_enter(&xnbp->x_tx_lock);

	/*
	 * If we are not connected to the peer or have not yet
	 * finished hotplug it is too early to pass packets to the
	 * peer.
	 */
	if (!(xnbp->x_connected && xnbp->x_hotplugged)) {
		mutex_exit(&xnbp->x_tx_lock);
		xnbp->x_stat_tx_too_early++;
		return (mp);
	}

	loop = xnbp->x_rx_ring.req_cons;
	prod = xnbp->x_rx_ring.rsp_prod_pvt;
	gop = xnbp->x_tx_top;

	/*
	 * Similar to RING_HAS_UNCONSUMED_REQUESTS(&xnbp->x_rx_ring) but
	 * using local variables.
	 */
#define	XNB_RING_HAS_UNCONSUMED_REQUESTS(_r)		\
	((((_r)->sring->req_prod - loop) <		\
		(RING_SIZE(_r) - (loop - prod))) ?	\
	    ((_r)->sring->req_prod - loop) :		\
	    (RING_SIZE(_r) - (loop - prod)))

	while ((mp != NULL) &&
	    XNB_RING_HAS_UNCONSUMED_REQUESTS(&xnbp->x_rx_ring)) {

		mfn_t mfn;
		pfn_t pfn;
		netif_rx_request_t *rxreq;
		netif_rx_response_t *rxresp;
		char *valoop;
		size_t offset;
		mblk_t *ml;
		uint16_t cksum_flags;

		/* 1 */
		if ((mfn = xnb_alloc_page(xnbp)) == 0) {
			xnbp->x_stat_xmit_defer++;
			break;
		}

		/* 2 */
		rxreq = RING_GET_REQUEST(&xnbp->x_rx_ring, loop);

#ifdef XNB_DEBUG
		if (!(rxreq->id < NET_RX_RING_SIZE))
			cmn_err(CE_PANIC, "xnb_to_peer: "
			    "id %d out of range in request 0x%p",
			    rxreq->id, (void *)rxreq);
		if (rxreq->gref >= NR_GRANT_ENTRIES)
			cmn_err(CE_PANIC, "xnb_to_peer: "
			    "grant ref %d out of range in request 0x%p",
			    rxreq->gref, (void *)rxreq);
#endif /* XNB_DEBUG */

		/* Assign a pfn and map the new page at the allocated va. */
		pfn = xen_assign_pfn(mfn);
		hat_devload(kas.a_hat, xnbp->x_tx_va, PAGESIZE,
		    pfn, PROT_READ | PROT_WRITE, HAT_LOAD);

		offset = TX_BUFFER_HEADROOM;

		/* 3 */
		len = 0;
		valoop = xnbp->x_tx_va + offset;
		for (ml = mp; ml != NULL; ml = ml->b_cont) {
			size_t chunk = ml->b_wptr - ml->b_rptr;

			bcopy(ml->b_rptr, valoop, chunk);
			valoop += chunk;
			len += chunk;
		}

		ASSERT(len + offset < PAGESIZE);

		/* Release the pfn. */
		hat_unload(kas.a_hat, xnbp->x_tx_va, PAGESIZE,
		    HAT_UNLOAD_UNMAP);
		xen_release_pfn(pfn);

		/* 4 */
		gop->mfn = mfn;
		gop->domid = xnbp->x_peer;
		gop->ref = rxreq->gref;

		/* 5.1 */
		rxresp = RING_GET_RESPONSE(&xnbp->x_rx_ring, prod);
		rxresp->offset = offset;
		rxresp->flags = 0;

		cksum_flags = xnbp->x_flavour->xf_cksum_to_peer(xnbp, mp);
		if (cksum_flags != 0)
			xnbp->x_stat_tx_cksum_deferred++;
		rxresp->flags |= cksum_flags;

		rxresp->id = RING_GET_REQUEST(&xnbp->x_rx_ring, prod)->id;
		rxresp->status = len;

		loop++;
		prod++;
		gop++;
		prev = mp;
		mp = mp->b_next;
	}

	/*
	 * Did we actually do anything?
	 */
	if (loop == xnbp->x_rx_ring.req_cons) {
		mutex_exit(&xnbp->x_tx_lock);
		return (mp);
	}

	end = loop;

	/*
	 * Unlink the end of the 'done' list from the remainder.
	 */
	ASSERT(prev != NULL);
	prev->b_next = NULL;

	if (HYPERVISOR_grant_table_op(GNTTABOP_transfer, xnbp->x_tx_top,
	    loop - xnbp->x_rx_ring.req_cons) != 0) {
		cmn_err(CE_WARN, "xnb_to_peer: transfer operation failed");
	}

	loop = xnbp->x_rx_ring.req_cons;
	prod = xnbp->x_rx_ring.rsp_prod_pvt;
	gop = xnbp->x_tx_top;

	while (loop < end) {
		int16_t status = NETIF_RSP_OKAY;

		if (gop->status != 0) {
			status = NETIF_RSP_ERROR;

			/*
			 * If the status is anything other than
			 * GNTST_bad_page then we don't own the page
			 * any more, so don't try to give it back.
			 */
			if (gop->status != GNTST_bad_page)
				gop->mfn = 0;
		} else {
			/* The page is no longer ours. */
			gop->mfn = 0;
		}

		if (gop->mfn != 0)
			/*
			 * Give back the page, as we won't be using
			 * it.
			 */
			xnb_free_page(xnbp, gop->mfn);
		else
			/*
			 * We gave away a page, update our accounting
			 * now.
			 */
			balloon_drv_subtracted(1);

		/* 5.2 */
		if (status != NETIF_RSP_OKAY) {
			RING_GET_RESPONSE(&xnbp->x_rx_ring, prod)->status =
			    status;
		} else {
			xnbp->x_stat_opackets++;
			xnbp->x_stat_obytes += len;
		}

		loop++;
		prod++;
		gop++;
	}

	xnbp->x_rx_ring.req_cons = loop;
	xnbp->x_rx_ring.rsp_prod_pvt = prod;

	/* 6 */
	/*LINTED: constant in conditional context*/
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&xnbp->x_rx_ring, notify);
	if (notify) {
		ec_notify_via_evtchn(xnbp->x_evtchn);
		xnbp->x_stat_tx_notify_sent++;
	} else {
		xnbp->x_stat_tx_notify_deferred++;
	}

	if (mp != NULL)
		xnbp->x_stat_xmit_defer++;

	mutex_exit(&xnbp->x_tx_lock);

	/* Free mblk_t's that we consumed. */
	freemsgchain(free);

	return (mp);
}

/*ARGSUSED*/
static int
xnb_rxbuf_constructor(void *buf, void *arg, int kmflag)
{
	xnb_rxbuf_t *rxp = buf;

	bzero(rxp, sizeof (*rxp));

	rxp->xr_free_rtn.free_func = xnb_rx_complete;
	rxp->xr_free_rtn.free_arg = (caddr_t)rxp;

	rxp->xr_mop.host_addr =
	    (uint64_t)(uintptr_t)vmem_alloc(heap_arena, PAGESIZE,
	    ((kmflag & KM_NOSLEEP) == KM_NOSLEEP) ?
	    VM_NOSLEEP : VM_SLEEP);

	if (rxp->xr_mop.host_addr == NULL) {
		cmn_err(CE_WARN, "xnb_rxbuf_constructor: "
		    "cannot get address space");
		return (-1);
	}

	/*
	 * Have the hat ensure that page table exists for the VA.
	 */
	hat_prepare_mapping(kas.a_hat,
	    (caddr_t)(uintptr_t)rxp->xr_mop.host_addr);

	return (0);
}

/*ARGSUSED*/
static void
xnb_rxbuf_destructor(void *buf, void *arg)
{
	xnb_rxbuf_t *rxp = buf;

	ASSERT(rxp->xr_mop.host_addr != NULL);
	ASSERT((rxp->xr_flags & XNB_RXBUF_INUSE) == 0);

	hat_release_mapping(kas.a_hat,
	    (caddr_t)(uintptr_t)rxp->xr_mop.host_addr);
	vmem_free(heap_arena,
	    (caddr_t)(uintptr_t)rxp->xr_mop.host_addr, PAGESIZE);
}

static void
xnb_rx_notify_peer(xnb_t *xnbp)
{
	boolean_t notify;

	ASSERT(MUTEX_HELD(&xnbp->x_rx_lock));

	/*LINTED: constant in conditional context*/
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&xnbp->x_tx_ring, notify);
	if (notify) {
		ec_notify_via_evtchn(xnbp->x_evtchn);
		xnbp->x_stat_rx_notify_sent++;
	} else {
		xnbp->x_stat_rx_notify_deferred++;
	}
}

static void
xnb_rx_complete(xnb_rxbuf_t *rxp)
{
	xnb_t *xnbp = rxp->xr_xnbp;

	ASSERT((rxp->xr_flags & XNB_RXBUF_INUSE) == XNB_RXBUF_INUSE);

	mutex_enter(&xnbp->x_rx_lock);

	xnb_rx_schedule_unmop(xnbp, &rxp->xr_mop);
	xnb_rx_perform_pending_unmop(xnbp);

	if (xnbp->x_connected) {
		xnb_rx_mark_complete(xnbp, rxp->xr_id, rxp->xr_status);
		xnb_rx_notify_peer(xnbp);
	}

	xnb_rxbuf_put(xnbp, rxp);

	mutex_exit(&xnbp->x_rx_lock);
}

static void
xnb_rx_mark_complete(xnb_t *xnbp, RING_IDX id, int16_t status)
{
	RING_IDX i;
	netif_tx_response_t *txresp;

	ASSERT(MUTEX_HELD(&xnbp->x_rx_lock));

	i = xnbp->x_tx_ring.rsp_prod_pvt;

	txresp = RING_GET_RESPONSE(&xnbp->x_tx_ring, i);
	txresp->id = id;
	txresp->status = status;

	xnbp->x_tx_ring.rsp_prod_pvt = i + 1;

	/*
	 * Note that we don't push the change to the peer here - that
	 * is the callers responsibility.
	 */
}

/*
 * XXPV dme: currently pending unmap operations are stored on a
 * per-instance basis.  Should they be per-driver?  The locking would
 * have to change (obviously), but there might be an improvement from
 * batching more together.  Right now they are all 'done' either at
 * the tail of each receive operation (copy case) or on each
 * completion (non-copy case).  Should that be changed to some
 * interval (watermark?) to improve the chance of batching?
 */
static void
xnb_rx_schedule_unmop(xnb_t *xnbp, gnttab_map_grant_ref_t *mop)
{
	gnttab_unmap_grant_ref_t *unmop;

	ASSERT(MUTEX_HELD(&xnbp->x_rx_lock));
	ASSERT(xnbp->x_rx_unmop_count <= NET_TX_RING_SIZE);

	unmop = &xnbp->x_rx_unmop[xnbp->x_rx_unmop_count];
	xnbp->x_rx_unmop_count++;

	unmop->host_addr = mop->host_addr;
	unmop->dev_bus_addr = mop->dev_bus_addr;
	unmop->handle = mop->handle;

#ifdef XNB_DEBUG
	if (xnbp->x_rx_unmop_count <= NET_TX_RING_SIZE)
		ASSERT(xnbp->x_rx_unmop[xnbp->x_rx_unmop_count].host_addr
		    == NULL);
#endif /* XNB_DEBUG */

}

static void
xnb_rx_perform_pending_unmop(xnb_t *xnbp)
{
#ifdef XNB_DEBUG
	RING_IDX loop;
	gnttab_unmap_grant_ref_t *unmop;
#endif /* XNB_DEBUG */

	ASSERT(MUTEX_HELD(&xnbp->x_rx_lock));

	if (xnbp->x_rx_unmop_count == 0)
		return;

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
	    xnbp->x_rx_unmop, xnbp->x_rx_unmop_count) < 0) {
		cmn_err(CE_WARN, "xnb_rx_perform_pending_unmop: "
		    "unmap grant operation failed, "
		    "%d pages lost", xnbp->x_rx_unmop_count);
	}

#ifdef XNB_DEBUG
	for (loop = 0, unmop = xnbp->x_rx_unmop;
	    loop < xnbp->x_rx_unmop_count;
	    loop++, unmop++) {
		if (unmop->status != 0) {
			cmn_err(CE_WARN, "xnb_rx_perform_pending_unmop: "
			    "unmap grant reference failed (%d)",
			    unmop->status);
		}
	}
#endif /* XNB_DEBUG */

	xnbp->x_rx_unmop_count = 0;

#ifdef XNB_DEBUG
	bzero(xnbp->x_rx_unmop, sizeof (xnbp->x_rx_unmop));
#endif /* XNB_DEBUG */
}

static xnb_rxbuf_t *
xnb_rxbuf_get(xnb_t *xnbp, int flags)
{
	xnb_rxbuf_t *rxp;

	ASSERT(MUTEX_HELD(&xnbp->x_rx_lock));

	rxp = kmem_cache_alloc(xnb_rxbuf_cachep, flags);
	if (rxp != NULL) {
		ASSERT((rxp->xr_flags & XNB_RXBUF_INUSE) == 0);
		rxp->xr_flags |= XNB_RXBUF_INUSE;

		rxp->xr_xnbp = xnbp;
		rxp->xr_mop.dom = xnbp->x_peer;

		rxp->xr_mop.flags = GNTMAP_host_map;
		if (!xnbp->x_rx_pages_writable)
			rxp->xr_mop.flags |= GNTMAP_readonly;

		xnbp->x_rx_buf_count++;
	}

	return (rxp);
}

static void
xnb_rxbuf_put(xnb_t *xnbp, xnb_rxbuf_t *rxp)
{
	ASSERT(MUTEX_HELD(&xnbp->x_rx_lock));
	ASSERT((rxp->xr_flags & XNB_RXBUF_INUSE) == XNB_RXBUF_INUSE);

	rxp->xr_flags &= ~XNB_RXBUF_INUSE;
	xnbp->x_rx_buf_count--;

	kmem_cache_free(xnb_rxbuf_cachep, rxp);
}

static mblk_t *
xnb_recv(xnb_t *xnbp)
{
	RING_IDX start, end, loop;
	gnttab_map_grant_ref_t *mop;
	xnb_rxbuf_t **rxpp;
	netif_tx_request_t *txreq;
	boolean_t work_to_do;
	mblk_t *head, *tail;
	/*
	 * If the peer granted a read-only mapping to the page then we
	 * must copy the data, as the local protocol stack (should the
	 * packet be destined for this host) will modify the packet
	 * 'in place'.
	 */
	boolean_t copy = !xnbp->x_rx_pages_writable;

	/*
	 * For each individual request, the sequence of actions is:
	 *
	 * 1. get the request.
	 * 2. map the page based on the grant ref.
	 * 3. allocate an mblk, copy the data to it.
	 * 4. release the grant.
	 * 5. update the ring.
	 * 6. pass the packet upward.
	 * 7. kick the peer.
	 *
	 * In fact, we try to perform the grant operations in batches,
	 * so there are two loops.
	 */

	head = tail = NULL;
around:
	ASSERT(MUTEX_HELD(&xnbp->x_rx_lock));

	/*LINTED: constant in conditional context*/
	RING_FINAL_CHECK_FOR_REQUESTS(&xnbp->x_tx_ring, work_to_do);
	if (!work_to_do) {
finished:
		xnb_rx_notify_peer(xnbp);

		return (head);
	}

	start = xnbp->x_tx_ring.req_cons;
	end = xnbp->x_tx_ring.sring->req_prod;

	for (loop = start, mop = xnbp->x_rx_mop, rxpp = xnbp->x_rx_bufp;
	    loop != end;
	    loop++, mop++, rxpp++) {
		xnb_rxbuf_t *rxp;

		rxp = xnb_rxbuf_get(xnbp, KM_NOSLEEP);
		if (rxp == NULL)
			break;

		ASSERT(xnbp->x_rx_pages_writable ||
		    ((rxp->xr_mop.flags & GNTMAP_readonly)
		    == GNTMAP_readonly));

		rxp->xr_mop.ref =
		    RING_GET_REQUEST(&xnbp->x_tx_ring, loop)->gref;

		ASSERT(rxp->xr_mop.ref < NR_GRANT_ENTRIES);

		*mop = rxp->xr_mop;
		*rxpp = rxp;
	}

	if ((loop - start) == 0)
		goto finished;

	end = loop;

	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
	    xnbp->x_rx_mop, end - start) != 0) {

		cmn_err(CE_WARN, "xnb_recv: map grant operation failed");

		loop = start;
		rxpp = xnbp->x_rx_bufp;

		while (loop != end) {
			xnb_rxbuf_put(xnbp, *rxpp);

			loop++;
			rxpp++;
		}

		goto finished;
	}

	for (loop = start, mop = xnbp->x_rx_mop, rxpp = xnbp->x_rx_bufp;
	    loop != end;
	    loop++, mop++, rxpp++) {
		mblk_t *mp = NULL;
		int16_t status = NETIF_RSP_OKAY;
		xnb_rxbuf_t *rxp = *rxpp;

		if (mop->status != 0) {
			cmn_err(CE_WARN, "xnb_recv: "
			    "failed to map buffer: %d",
			    mop->status);
			status = NETIF_RSP_ERROR;
		}

		txreq = RING_GET_REQUEST(&xnbp->x_tx_ring, loop);

		if (status == NETIF_RSP_OKAY) {
			if (copy) {
				mp = allocb(txreq->size, BPRI_MED);
				if (mp == NULL) {
					status = NETIF_RSP_ERROR;
					xnbp->x_stat_rx_allocb_failed++;
				} else {
					bcopy((caddr_t)(uintptr_t)
					    mop->host_addr + txreq->offset,
					    mp->b_wptr, txreq->size);
					mp->b_wptr += txreq->size;
				}
			} else {
				mp = desballoc((unsigned char *)(uintptr_t)
				    mop->host_addr + txreq->offset,
				    txreq->size, 0, &rxp->xr_free_rtn);
				if (mp == NULL) {
					status = NETIF_RSP_ERROR;
					xnbp->x_stat_rx_allocb_failed++;
				} else {
					rxp->xr_id = txreq->id;
					rxp->xr_status = status;
					rxp->xr_mop = *mop;

					mp->b_wptr += txreq->size;
				}
			}

			/*
			 * If we have a buffer and there are checksum
			 * flags, process them appropriately.
			 */
			if ((mp != NULL) &&
			    ((txreq->flags &
			    (NETTXF_csum_blank | NETTXF_data_validated))
			    != 0)) {
				mp = xnbp->x_flavour->xf_cksum_from_peer(xnbp,
				    mp, txreq->flags);
				xnbp->x_stat_rx_cksum_no_need++;
			}
		}

		if (copy || (mp == NULL)) {
			xnb_rx_mark_complete(xnbp, txreq->id, status);
			xnb_rx_schedule_unmop(xnbp, mop);
		}

		if (mp != NULL) {
			xnbp->x_stat_ipackets++;
			xnbp->x_stat_rbytes += txreq->size;

			mp->b_next = NULL;
			if (head == NULL) {
				ASSERT(tail == NULL);
				head = mp;
			} else {
				ASSERT(tail != NULL);
				tail->b_next = mp;
			}
			tail = mp;
		}
	}

	/*
	 * This has to be here rather than in the 'finished' code
	 * because we can only handle NET_TX_RING_SIZE pending unmap
	 * operations, which may be exceeded by multiple trips around
	 * the receive loop during heavy load (one trip around the
	 * loop cannot generate more than NET_TX_RING_SIZE unmap
	 * operations).
	 */
	xnb_rx_perform_pending_unmop(xnbp);
	if (copy) {
		for (loop = start, rxpp = xnbp->x_rx_bufp;
		    loop != end;
		    loop++, rxpp++)
			xnb_rxbuf_put(xnbp, *rxpp);
	}

	xnbp->x_tx_ring.req_cons = loop;

	goto around;
	/* NOTREACHED */
}

/*
 *  intr() -- ring interrupt service routine
 */
static uint_t
xnb_intr(caddr_t arg)
{
	xnb_t *xnbp = (xnb_t *)arg;
	mblk_t *mp;

	xnbp->x_stat_intr++;

	mutex_enter(&xnbp->x_rx_lock);

	ASSERT(xnbp->x_connected);

	mp = xnb_recv(xnbp);

	mutex_exit(&xnbp->x_rx_lock);

	if (!xnbp->x_hotplugged) {
		xnbp->x_stat_rx_too_early++;
		goto fail;
	}
	if (mp == NULL) {
		xnbp->x_stat_spurious_intr++;
		goto fail;
	}

	xnbp->x_flavour->xf_recv(xnbp, mp);

	return (DDI_INTR_CLAIMED);

fail:
	freemsgchain(mp);
	return (DDI_INTR_CLAIMED);
}

static boolean_t
xnb_connect_rings(dev_info_t *dip)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);
	char *oename;
	struct gnttab_map_grant_ref map_op;
	evtchn_port_t evtchn;
	int i;

	/*
	 * Cannot attempt to connect the rings if already connected.
	 */
	ASSERT(!xnbp->x_connected);

	oename = xvdi_get_oename(dip);

	if (xenbus_gather(XBT_NULL, oename,
	    "event-channel", "%u", &evtchn,
	    "tx-ring-ref", "%lu", &xnbp->x_tx_ring_ref,
	    "rx-ring-ref", "%lu", &xnbp->x_rx_ring_ref,
	    NULL) != 0) {
		cmn_err(CE_WARN, "xnb_connect_rings: "
		    "cannot read other-end details from %s",
		    oename);
		goto fail;
	}

	if (xenbus_scanf(XBT_NULL, oename,
	    "feature-tx-writable", "%d", &i) != 0)
		i = 0;
	if (i != 0)
		xnbp->x_rx_pages_writable = B_TRUE;

	if (xenbus_scanf(XBT_NULL, oename,
	    "feature-no-csum-offload", "%d", &i) != 0)
		i = 0;
	if ((i == 1) || !xnbp->x_cksum_offload)
		xnbp->x_cksum_offload = B_FALSE;

	/*
	 * 1. allocate a vaddr for the tx page, one for the rx page.
	 * 2. call GNTTABOP_map_grant_ref to map the relevant pages
	 *    into the allocated vaddr (one for tx, one for rx).
	 * 3. call EVTCHNOP_bind_interdomain to have the event channel
	 *    bound to this domain.
	 * 4. associate the event channel with an interrupt.
	 * 5. declare ourselves connected.
	 * 6. enable the interrupt.
	 */

	/* 1.tx */
	xnbp->x_tx_ring_addr = vmem_xalloc(heap_arena, PAGESIZE, PAGESIZE,
	    0, 0, 0, 0, VM_SLEEP);
	ASSERT(xnbp->x_tx_ring_addr != NULL);

	/* 2.tx */
	map_op.host_addr = (uint64_t)((long)xnbp->x_tx_ring_addr);
	map_op.flags = GNTMAP_host_map;
	map_op.ref = xnbp->x_tx_ring_ref;
	map_op.dom = xnbp->x_peer;
	hat_prepare_mapping(kas.a_hat, xnbp->x_tx_ring_addr);
	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
	    &map_op, 1) != 0 || map_op.status != 0) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot map tx-ring page.");
		goto fail;
	}
	xnbp->x_tx_ring_handle = map_op.handle;

	/*LINTED: constant in conditional context*/
	BACK_RING_INIT(&xnbp->x_tx_ring,
	    (netif_tx_sring_t *)xnbp->x_tx_ring_addr, PAGESIZE);

	/* 1.rx */
	xnbp->x_rx_ring_addr = vmem_xalloc(heap_arena, PAGESIZE, PAGESIZE,
	    0, 0, 0, 0, VM_SLEEP);
	ASSERT(xnbp->x_rx_ring_addr != NULL);

	/* 2.rx */
	map_op.host_addr = (uint64_t)((long)xnbp->x_rx_ring_addr);
	map_op.flags = GNTMAP_host_map;
	map_op.ref = xnbp->x_rx_ring_ref;
	map_op.dom = xnbp->x_peer;
	hat_prepare_mapping(kas.a_hat, xnbp->x_rx_ring_addr);
	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
	    &map_op, 1) != 0 || map_op.status != 0) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot map rx-ring page.");
		goto fail;
	}
	xnbp->x_rx_ring_handle = map_op.handle;

	/*LINTED: constant in conditional context*/
	BACK_RING_INIT(&xnbp->x_rx_ring,
	    (netif_rx_sring_t *)xnbp->x_rx_ring_addr, PAGESIZE);

	/* 3 */
	if (xvdi_bind_evtchn(dip, evtchn) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xnb_connect_rings: "
		    "cannot bind event channel %d", xnbp->x_evtchn);
		xnbp->x_evtchn = INVALID_EVTCHN;
		goto fail;
	}
	xnbp->x_evtchn = xvdi_get_evtchn(dip);

	/*
	 * It would be good to set the state to XenbusStateConnected
	 * here as well, but then what if ddi_add_intr() failed?
	 * Changing the state in the store will be noticed by the peer
	 * and cannot be "taken back".
	 */
	mutex_enter(&xnbp->x_tx_lock);
	mutex_enter(&xnbp->x_rx_lock);

	/* 5.1 */
	xnbp->x_connected = B_TRUE;

	mutex_exit(&xnbp->x_rx_lock);
	mutex_exit(&xnbp->x_tx_lock);

	/* 4, 6 */
	if (ddi_add_intr(dip, 0, NULL, NULL, xnb_intr, (caddr_t)xnbp)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot add interrupt");
		goto fail;
	}
	xnbp->x_irq = B_TRUE;

	/* 5.2 */
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateConnected);

	return (B_TRUE);

fail:
	mutex_enter(&xnbp->x_tx_lock);
	mutex_enter(&xnbp->x_rx_lock);

	xnbp->x_connected = B_FALSE;

	mutex_exit(&xnbp->x_rx_lock);
	mutex_exit(&xnbp->x_tx_lock);

	return (B_FALSE);
}

static void
xnb_disconnect_rings(dev_info_t *dip)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);

	if (xnbp->x_irq) {
		ddi_remove_intr(dip, 0, NULL);
		xnbp->x_irq = B_FALSE;
	}

	if (xnbp->x_evtchn != INVALID_EVTCHN) {
		xvdi_free_evtchn(dip);
		xnbp->x_evtchn = INVALID_EVTCHN;
	}

	if (xnbp->x_rx_ring_handle != INVALID_GRANT_HANDLE) {
		struct gnttab_unmap_grant_ref unmap_op;

		unmap_op.host_addr = (uint64_t)(uintptr_t)xnbp->x_rx_ring_addr;
		unmap_op.dev_bus_addr = 0;
		unmap_op.handle = xnbp->x_rx_ring_handle;
		if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
		    &unmap_op, 1) != 0)
			cmn_err(CE_WARN, "xnb_disconnect_rings: "
			    "cannot unmap rx-ring page (%d)",
			    unmap_op.status);

		xnbp->x_rx_ring_handle = INVALID_GRANT_HANDLE;
	}

	if (xnbp->x_rx_ring_addr != NULL) {
		hat_release_mapping(kas.a_hat, xnbp->x_rx_ring_addr);
		vmem_free(heap_arena, xnbp->x_rx_ring_addr, PAGESIZE);
		xnbp->x_rx_ring_addr = NULL;
	}

	if (xnbp->x_tx_ring_handle != INVALID_GRANT_HANDLE) {
		struct gnttab_unmap_grant_ref unmap_op;

		unmap_op.host_addr = (uint64_t)(uintptr_t)xnbp->x_tx_ring_addr;
		unmap_op.dev_bus_addr = 0;
		unmap_op.handle = xnbp->x_tx_ring_handle;
		if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
		    &unmap_op, 1) != 0)
			cmn_err(CE_WARN, "xnb_disconnect_rings: "
			    "cannot unmap tx-ring page (%d)",
			    unmap_op.status);

		xnbp->x_tx_ring_handle = INVALID_GRANT_HANDLE;
	}

	if (xnbp->x_tx_ring_addr != NULL) {
		hat_release_mapping(kas.a_hat, xnbp->x_tx_ring_addr);
		vmem_free(heap_arena, xnbp->x_tx_ring_addr, PAGESIZE);
		xnbp->x_tx_ring_addr = NULL;
	}
}

/*ARGSUSED*/
static void
xnb_oe_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);
	XenbusState new_state = *(XenbusState *)impl_data;

	ASSERT(xnbp != NULL);

	switch (new_state) {
	case XenbusStateConnected:
		if (xnb_connect_rings(dip)) {
			xnbp->x_flavour->xf_peer_connected(xnbp);
		} else {
			xnbp->x_flavour->xf_peer_disconnected(xnbp);
			xnb_disconnect_rings(dip);
			(void) xvdi_switch_state(dip, XBT_NULL,
			    XenbusStateClosed);
			(void) xvdi_post_event(dip, XEN_HP_REMOVE);
		}

		/*
		 * Now that we've attempted to connect it's reasonable
		 * to allow an attempt to detach.
		 */
		xnbp->x_detachable = B_TRUE;

		break;

	case XenbusStateClosing:
		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosing);

		break;

	case XenbusStateClosed:
		xnbp->x_flavour->xf_peer_disconnected(xnbp);

		mutex_enter(&xnbp->x_tx_lock);
		mutex_enter(&xnbp->x_rx_lock);

		xnb_disconnect_rings(dip);
		xnbp->x_connected = B_FALSE;

		mutex_exit(&xnbp->x_rx_lock);
		mutex_exit(&xnbp->x_tx_lock);

		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosed);
		(void) xvdi_post_event(dip, XEN_HP_REMOVE);
		/*
		 * In all likelyhood this is already set (in the above
		 * case), but if the peer never attempted to connect
		 * and the domain is destroyed we get here without
		 * having been through the case above, so we set it to
		 * be sure.
		 */
		xnbp->x_detachable = B_TRUE;

		break;

	default:
		break;
	}
}

/*ARGSUSED*/
static void
xnb_hp_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);
	xendev_hotplug_state_t state = *(xendev_hotplug_state_t *)impl_data;
	boolean_t success;

	ASSERT(xnbp != NULL);

	switch (state) {
	case Connected:

		success = xnbp->x_flavour->xf_hotplug_connected(xnbp);

		mutex_enter(&xnbp->x_tx_lock);
		mutex_enter(&xnbp->x_rx_lock);

		xnbp->x_hotplugged = success;

		mutex_exit(&xnbp->x_rx_lock);
		mutex_exit(&xnbp->x_tx_lock);
		break;

	default:
		break;
	}
}

static struct modldrv modldrv = {
	&mod_miscops, "xnb module %I%",
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int i;

	mutex_init(&xnb_alloc_page_lock, NULL, MUTEX_DRIVER, NULL);

	xnb_rxbuf_cachep = kmem_cache_create("xnb_rxbuf_cachep",
	    sizeof (xnb_rxbuf_t), 0, xnb_rxbuf_constructor,
	    xnb_rxbuf_destructor, NULL, NULL, NULL, 0);
	ASSERT(xnb_rxbuf_cachep != NULL);

	i = mod_install(&modlinkage);
	if (i != DDI_SUCCESS) {
		kmem_cache_destroy(xnb_rxbuf_cachep);
		mutex_destroy(&xnb_alloc_page_lock);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int i;

	i = mod_remove(&modlinkage);
	if (i == DDI_SUCCESS) {
		kmem_cache_destroy(xnb_rxbuf_cachep);
		mutex_destroy(&xnb_alloc_page_lock);
	}
	return (i);
}

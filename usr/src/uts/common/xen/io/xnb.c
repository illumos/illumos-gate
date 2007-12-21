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
#include <sys/types.h>
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
static void 	xnb_rx_schedule_unmop(xnb_t *, gnttab_map_grant_ref_t *,
    xnb_rxbuf_t *);
static void	xnb_rx_perform_pending_unmop(xnb_t *);
mblk_t		*xnb_copy_to_peer(xnb_t *, mblk_t *);

int		xnb_unmop_lowwat = NET_TX_RING_SIZE >> 2;
int		xnb_unmop_hiwat = NET_TX_RING_SIZE - (NET_TX_RING_SIZE >> 2);


boolean_t	xnb_hv_copy = B_TRUE;
boolean_t	xnb_explicit_pageflip_set = B_FALSE;

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
	"tx_allocb_failed",
	"tx_foreign_page",
	"mac_full",
	"spurious_intr",
	"allocation_success",
	"allocation_failure",
	"small_allocation_success",
	"small_allocation_failure",
	"other_allocation_failure",
	"tx_pageboundary_crossed",
	"tx_cpoparea_grown",
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
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_cksum_deferred;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_cksum_no_need;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_notify_deferred;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_notify_sent;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_notify_deferred;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_notify_sent;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_too_early;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_too_early;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_allocb_failed;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_allocb_failed;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_foreign_page;
	(knp++)->value.ui64 = xnbp->xnb_stat_mac_full;
	(knp++)->value.ui64 = xnbp->xnb_stat_spurious_intr;
	(knp++)->value.ui64 = xnbp->xnb_stat_allocation_success;
	(knp++)->value.ui64 = xnbp->xnb_stat_allocation_failure;
	(knp++)->value.ui64 = xnbp->xnb_stat_small_allocation_success;
	(knp++)->value.ui64 = xnbp->xnb_stat_small_allocation_failure;
	(knp++)->value.ui64 = xnbp->xnb_stat_other_allocation_failure;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_pagebndry_crossed;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_cpoparea_grown;
	(knp++)->value.ui64 = xnbp->xnb_stat_csum_hardware;
	(knp++)->value.ui64 = xnbp->xnb_stat_csum_software;

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
	xnbp->xnb_kstat_aux = kstat_create(ddi_driver_name(xnbp->xnb_devinfo),
	    ddi_get_instance(xnbp->xnb_devinfo), "aux_statistics", "net",
	    KSTAT_TYPE_NAMED, nstat, 0);
	if (xnbp->xnb_kstat_aux == NULL)
		return (B_FALSE);

	xnbp->xnb_kstat_aux->ks_private = xnbp;
	xnbp->xnb_kstat_aux->ks_update = xnb_ks_aux_update;

	knp = xnbp->xnb_kstat_aux->ks_data;
	while (nstat > 0) {
		kstat_named_init(knp, *cp, KSTAT_DATA_UINT64);

		knp++;
		cp++;
		nstat--;
	}

	kstat_install(xnbp->xnb_kstat_aux);

	return (B_TRUE);
}

static void
xnb_ks_free(xnb_t *xnbp)
{
	kstat_delete(xnbp->xnb_kstat_aux);
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

			xnbp->xnb_stat_csum_hardware++;

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
	xnbp->xnb_stat_csum_software++;

	return (xnb_software_csum(xnbp, mp));
}

int
xnb_attach(dev_info_t *dip, xnb_flavour_t *flavour, void *flavour_data)
{
	xnb_t *xnbp;
	char *xsname, mac[ETHERADDRL * 3];

	xnbp = kmem_zalloc(sizeof (*xnbp), KM_SLEEP);

	xnbp->xnb_flavour = flavour;
	xnbp->xnb_flavour_data = flavour_data;
	xnbp->xnb_devinfo = dip;
	xnbp->xnb_evtchn = INVALID_EVTCHN;
	xnbp->xnb_irq = B_FALSE;
	xnbp->xnb_tx_ring_handle = INVALID_GRANT_HANDLE;
	xnbp->xnb_rx_ring_handle = INVALID_GRANT_HANDLE;
	xnbp->xnb_cksum_offload = xnb_cksum_offload;
	xnbp->xnb_connected = B_FALSE;
	xnbp->xnb_hotplugged = B_FALSE;
	xnbp->xnb_detachable = B_FALSE;
	xnbp->xnb_peer = xvdi_get_oeid(dip);
	xnbp->xnb_rx_pages_writable = B_FALSE;

	xnbp->xnb_rx_buf_count = 0;
	xnbp->xnb_rx_unmop_count = 0;

	xnbp->xnb_hv_copy = B_FALSE;

	xnbp->xnb_tx_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	ASSERT(xnbp->xnb_tx_va != NULL);

	if (ddi_get_iblock_cookie(dip, 0, &xnbp->xnb_icookie)
	    != DDI_SUCCESS)
		goto failure;

	/* allocated on demand, when/if we enter xnb_copy_to_peer() */
	xnbp->xnb_tx_cpop = NULL;
	xnbp->xnb_cpop_sz = 0;

	mutex_init(&xnbp->xnb_tx_lock, NULL, MUTEX_DRIVER,
	    xnbp->xnb_icookie);
	mutex_init(&xnbp->xnb_rx_lock, NULL, MUTEX_DRIVER,
	    xnbp->xnb_icookie);

	/* set driver private pointer now */
	ddi_set_driver_private(dip, xnbp);

	if (!xnb_ks_init(xnbp))
		goto failure_1;

	/*
	 * Receive notification of changes in the state of the
	 * driver in the guest domain.
	 */
	if (xvdi_add_event_handler(dip, XS_OE_STATE,
	    xnb_oe_state_change) != DDI_SUCCESS)
		goto failure_2;

	/*
	 * Receive notification of hotplug events.
	 */
	if (xvdi_add_event_handler(dip, XS_HP_STATE,
	    xnb_hp_state_change) != DDI_SUCCESS)
		goto failure_2;

	xsname = xvdi_get_xsname(dip);

	if (xenbus_printf(XBT_NULL, xsname,
	    "feature-no-csum-offload", "%d",
	    xnbp->xnb_cksum_offload ? 0 : 1) != 0)
		goto failure_3;

	/*
	 * Use global xnb_hv_copy to export this feature. This means that
	 * we have to decide what to do before starting up a guest domain
	 */
	if (xenbus_printf(XBT_NULL, xsname,
	    "feature-rx-copy", "%d", xnb_hv_copy ? 1 : 0) != 0)
		goto failure_3;
	/*
	 * Linux domUs seem to depend on "feature-rx-flip" being 0
	 * in addition to "feature-rx-copy" being 1. It seems strange
	 * to use four possible states to describe a binary decision,
	 * but we might as well play nice.
	 */
	if (xenbus_printf(XBT_NULL, xsname,
	    "feature-rx-flip", "%d", xnb_explicit_pageflip_set ? 1 : 0) != 0)
		goto failure_3;

	if (xenbus_scanf(XBT_NULL, xsname,
	    "mac", "%s", mac) != 0) {
		cmn_err(CE_WARN, "xnb_attach: "
		    "cannot read mac address from %s",
		    xsname);
		goto failure_3;
	}

	if (ether_aton(mac, xnbp->xnb_mac_addr) != ETHERADDRL) {
		cmn_err(CE_WARN,
		    "xnb_attach: cannot parse mac address %s",
		    mac);
		goto failure_3;
	}

	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateInitWait);
	(void) xvdi_post_event(dip, XEN_HP_ADD);

	return (DDI_SUCCESS);

failure_3:
	xvdi_remove_event_handler(dip, NULL);

failure_2:
	xnb_ks_free(xnbp);

failure_1:
	mutex_destroy(&xnbp->xnb_rx_lock);
	mutex_destroy(&xnbp->xnb_tx_lock);

failure:
	vmem_free(heap_arena, xnbp->xnb_tx_va, PAGESIZE);
	kmem_free(xnbp, sizeof (*xnbp));
	return (DDI_FAILURE);
}

/*ARGSUSED*/
void
xnb_detach(dev_info_t *dip)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);

	ASSERT(xnbp != NULL);
	ASSERT(!xnbp->xnb_connected);
	ASSERT(xnbp->xnb_rx_buf_count == 0);

	xnb_disconnect_rings(dip);

	xvdi_remove_event_handler(dip, NULL);

	xnb_ks_free(xnbp);

	ddi_set_driver_private(dip, NULL);

	mutex_destroy(&xnbp->xnb_tx_lock);
	mutex_destroy(&xnbp->xnb_rx_lock);

	if (xnbp->xnb_cpop_sz > 0)
		kmem_free(xnbp->xnb_tx_cpop, sizeof (*xnbp->xnb_tx_cpop)
		    * xnbp->xnb_cpop_sz);

	ASSERT(xnbp->xnb_tx_va != NULL);
	vmem_free(heap_arena, xnbp->xnb_tx_va, PAGESIZE);

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
			xnbp->xnb_stat_allocation_failure++;
			mutex_exit(&xnb_alloc_page_lock);

			/*
			 * Try for a single page in low memory situations.
			 */
			if (balloon_alloc_pages(1, &mfn) != 1) {
				if ((xnbp->xnb_stat_small_allocation_failure++
				    % WARNING_RATE_LIMIT) == 0)
					cmn_err(CE_WARN, "xnb_alloc_page: "
					    "Cannot allocate memory to "
					    "transfer packets to peer.");
				return (0);
			} else {
				xnbp->xnb_stat_small_allocation_success++;
				return (mfn);
			}
		}

		nth = 0;
		xnbp->xnb_stat_allocation_success++;
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

/*
 * Similar to RING_HAS_UNCONSUMED_REQUESTS(&xnbp->rx_ring) but
 * using local variables.
 */
#define	XNB_RING_HAS_UNCONSUMED_REQUESTS(_r)		\
	((((_r)->sring->req_prod - loop) <		\
		(RING_SIZE(_r) - (loop - prod))) ?	\
	    ((_r)->sring->req_prod - loop) :		\
	    (RING_SIZE(_r) - (loop - prod)))

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

	mutex_enter(&xnbp->xnb_tx_lock);

	/*
	 * If we are not connected to the peer or have not yet
	 * finished hotplug it is too early to pass packets to the
	 * peer.
	 */
	if (!(xnbp->xnb_connected && xnbp->xnb_hotplugged)) {
		mutex_exit(&xnbp->xnb_tx_lock);
		DTRACE_PROBE(flip_tx_too_early);
		xnbp->xnb_stat_tx_too_early++;
		return (mp);
	}

	loop = xnbp->xnb_rx_ring.req_cons;
	prod = xnbp->xnb_rx_ring.rsp_prod_pvt;
	gop = xnbp->xnb_tx_top;

	while ((mp != NULL) &&
	    XNB_RING_HAS_UNCONSUMED_REQUESTS(&xnbp->xnb_rx_ring)) {

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
			xnbp->xnb_stat_xmit_defer++;
			break;
		}

		/* 2 */
		rxreq = RING_GET_REQUEST(&xnbp->xnb_rx_ring, loop);

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
		hat_devload(kas.a_hat, xnbp->xnb_tx_va, PAGESIZE,
		    pfn, PROT_READ | PROT_WRITE, HAT_LOAD);

		offset = TX_BUFFER_HEADROOM;

		/* 3 */
		len = 0;
		valoop = xnbp->xnb_tx_va + offset;
		for (ml = mp; ml != NULL; ml = ml->b_cont) {
			size_t chunk = ml->b_wptr - ml->b_rptr;

			bcopy(ml->b_rptr, valoop, chunk);
			valoop += chunk;
			len += chunk;
		}

		ASSERT(len + offset < PAGESIZE);

		/* Release the pfn. */
		hat_unload(kas.a_hat, xnbp->xnb_tx_va, PAGESIZE,
		    HAT_UNLOAD_UNMAP);
		xen_release_pfn(pfn);

		/* 4 */
		gop->mfn = mfn;
		gop->domid = xnbp->xnb_peer;
		gop->ref = rxreq->gref;

		/* 5.1 */
		rxresp = RING_GET_RESPONSE(&xnbp->xnb_rx_ring, prod);
		rxresp->offset = offset;
		rxresp->flags = 0;

		cksum_flags = xnbp->xnb_flavour->xf_cksum_to_peer(xnbp, mp);
		if (cksum_flags != 0)
			xnbp->xnb_stat_tx_cksum_deferred++;
		rxresp->flags |= cksum_flags;

		rxresp->id = RING_GET_REQUEST(&xnbp->xnb_rx_ring, prod)->id;
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
	if (loop == xnbp->xnb_rx_ring.req_cons) {
		mutex_exit(&xnbp->xnb_tx_lock);
		return (mp);
	}

	end = loop;

	/*
	 * Unlink the end of the 'done' list from the remainder.
	 */
	ASSERT(prev != NULL);
	prev->b_next = NULL;

	if (HYPERVISOR_grant_table_op(GNTTABOP_transfer, xnbp->xnb_tx_top,
	    loop - xnbp->xnb_rx_ring.req_cons) != 0) {
		cmn_err(CE_WARN, "xnb_to_peer: transfer operation failed");
	}

	loop = xnbp->xnb_rx_ring.req_cons;
	prod = xnbp->xnb_rx_ring.rsp_prod_pvt;
	gop = xnbp->xnb_tx_top;

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
			RING_GET_RESPONSE(&xnbp->xnb_rx_ring, prod)->status =
			    status;
		} else {
			xnbp->xnb_stat_opackets++;
			xnbp->xnb_stat_obytes += len;
		}

		loop++;
		prod++;
		gop++;
	}

	xnbp->xnb_rx_ring.req_cons = loop;
	xnbp->xnb_rx_ring.rsp_prod_pvt = prod;

	/* 6 */
	/* LINTED: constant in conditional context */
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&xnbp->xnb_rx_ring, notify);
	if (notify) {
		ec_notify_via_evtchn(xnbp->xnb_evtchn);
		xnbp->xnb_stat_tx_notify_sent++;
	} else {
		xnbp->xnb_stat_tx_notify_deferred++;
	}

	if (mp != NULL)
		xnbp->xnb_stat_xmit_defer++;

	mutex_exit(&xnbp->xnb_tx_lock);

	/* Free mblk_t's that we consumed. */
	freemsgchain(free);

	return (mp);
}

/* helper functions for xnb_copy_to_peer */

/*
 * Grow the array of copy operation descriptors.
 * Returns a pointer to the next available entry.
 */
gnttab_copy_t *
grow_cpop_area(xnb_t *xnbp, gnttab_copy_t *o_cpop)
{
	/*
	 * o_cpop (arg.1) is a ptr to the area we would like to copy
	 * something into but cannot, because we haven't alloc'ed it
	 * yet, or NULL.
	 * old_cpop and new_cpop (local) are pointers to old/new
	 * versions of xnbp->xnb_tx_cpop.
	 */
	gnttab_copy_t	*new_cpop, *old_cpop, *ret_cpop;
	size_t		newcount;

	ASSERT(MUTEX_HELD(&xnbp->xnb_tx_lock));

	old_cpop = xnbp->xnb_tx_cpop;
	/*
	 * o_cpop is a pointer into the array pointed to by old_cpop;
	 * it would be an error for exactly one of these pointers to be NULL.
	 * We shouldn't call this function if xnb_tx_cpop has already
	 * been allocated, but we're starting to fill it from the beginning
	 * again.
	 */
	ASSERT((o_cpop == NULL && old_cpop == NULL) ||
	    (o_cpop != NULL && old_cpop != NULL && o_cpop != old_cpop));

	newcount = xnbp->xnb_cpop_sz + CPOP_DEFCNT;

	new_cpop = kmem_alloc(sizeof (*new_cpop) * newcount, KM_NOSLEEP);
	if (new_cpop == NULL) {
		xnbp->xnb_stat_other_allocation_failure++;
		return (NULL);
	}

	if (o_cpop != NULL) {
		size_t	 offset = (o_cpop - old_cpop);

		/* we only need to move the parts in use ... */
		(void) memmove(new_cpop, old_cpop, xnbp->xnb_cpop_sz *
		    (sizeof (*old_cpop)));

		kmem_free(old_cpop, xnbp->xnb_cpop_sz * sizeof (*old_cpop));

		ret_cpop = new_cpop + offset;
	} else {
		ret_cpop = new_cpop;
	}

	xnbp->xnb_tx_cpop = new_cpop;
	xnbp->xnb_cpop_sz = newcount;

	xnbp->xnb_stat_tx_cpoparea_grown++;

	return (ret_cpop);
}

/*
 * Check whether an address is on a page that's foreign to this domain.
 */
static boolean_t
is_foreign(void *addr)
{
	pfn_t	pfn = hat_getpfnum(kas.a_hat, addr);

	return (pfn & PFN_IS_FOREIGN_MFN ? B_TRUE : B_FALSE);
}

/*
 * Insert a newly allocated mblk into a chain, replacing the old one.
 */
static mblk_t *
replace_msg(mblk_t *mp, size_t len, mblk_t *mp_prev, mblk_t *ml_prev)
{
	uint32_t	start, stuff, end, value, flags;
	mblk_t		*new_mp;

	new_mp = copyb(mp);
	if (new_mp == NULL)
		cmn_err(CE_PANIC, "replace_msg: cannot alloc new message"
		    "for %p, len %lu", (void *) mp, len);

	hcksum_retrieve(mp, NULL, NULL, &start, &stuff, &end, &value, &flags);
	(void) hcksum_assoc(new_mp, NULL, NULL, start, stuff, end, value,
	    flags, KM_NOSLEEP);

	new_mp->b_next = mp->b_next;
	new_mp->b_prev = mp->b_prev;
	new_mp->b_cont = mp->b_cont;

	/* Make sure we only overwrite pointers to the mblk being replaced. */
	if (mp_prev != NULL && mp_prev->b_next == mp)
		mp_prev->b_next = new_mp;

	if (ml_prev != NULL && ml_prev->b_cont == mp)
		ml_prev->b_cont = new_mp;

	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	freemsg(mp);

	return (new_mp);
}

/*
 * Set all the fields in a gnttab_copy_t.
 */
static void
setup_gop(xnb_t *xnbp, gnttab_copy_t *gp, uchar_t *rptr,
    size_t s_off, size_t d_off, size_t len, grant_ref_t d_ref)
{
	ASSERT(xnbp != NULL && gp != NULL);

	gp->source.offset = s_off;
	gp->source.u.gmfn = pfn_to_mfn(hat_getpfnum(kas.a_hat, (caddr_t)rptr));
	gp->source.domid = DOMID_SELF;

	gp->len = (uint16_t)len;
	gp->flags = GNTCOPY_dest_gref;
	gp->status = 0;

	gp->dest.u.ref = d_ref;
	gp->dest.offset = d_off;
	gp->dest.domid = xnbp->xnb_peer;
}

mblk_t *
xnb_copy_to_peer(xnb_t *xnbp, mblk_t *mp)
{
	mblk_t		*free = mp, *mp_prev = NULL, *saved_mp = mp;
	mblk_t		*ml, *ml_prev;
	gnttab_copy_t	*gop_cp;
	boolean_t	notify;
	RING_IDX	loop, prod;
	int		i;

	if (!xnbp->xnb_hv_copy)
		return (xnb_to_peer(xnbp, mp));

	/*
	 * For each packet the sequence of operations is:
	 *
	 *  1. get a request slot from the ring.
	 *  2. set up data for hypercall (see NOTE below)
	 *  3. have the hypervisore copy the data
	 *  4. update the request slot.
	 *  5. kick the peer.
	 *
	 * NOTE ad 2.
	 *  In order to reduce the number of hypercalls, we prepare
	 *  several packets (mp->b_cont != NULL) for the peer and
	 *  perform a single hypercall to transfer them.
	 *  We also have to set up a seperate copy operation for
	 *  every page.
	 *
	 * If we have more than one message (mp->b_next != NULL),
	 * we do this whole dance repeatedly.
	 */

	mutex_enter(&xnbp->xnb_tx_lock);

	if (!(xnbp->xnb_connected && xnbp->xnb_hotplugged)) {
		mutex_exit(&xnbp->xnb_tx_lock);
		DTRACE_PROBE(copy_tx_too_early);
		xnbp->xnb_stat_tx_too_early++;
		return (mp);
	}

	loop = xnbp->xnb_rx_ring.req_cons;
	prod = xnbp->xnb_rx_ring.rsp_prod_pvt;

	while ((mp != NULL) &&
	    XNB_RING_HAS_UNCONSUMED_REQUESTS(&xnbp->xnb_rx_ring)) {
		netif_rx_request_t	*rxreq;
		netif_rx_response_t	*rxresp;
		size_t			offset, d_offset;
		size_t			len;
		uint16_t		cksum_flags;
		int16_t			status = NETIF_RSP_OKAY;
		int			item_count;

		/* 1 */
		rxreq = RING_GET_REQUEST(&xnbp->xnb_rx_ring, loop);

#ifdef XNB_DEBUG
		if (!(rxreq->id < NET_RX_RING_SIZE))
			cmn_err(CE_PANIC, "xnb_copy_to_peer: "
			    "id %d out of range in request 0x%p",
			    rxreq->id, (void *)rxreq);
		if (rxreq->gref >= NR_GRANT_ENTRIES)
			cmn_err(CE_PANIC, "xnb_copy_to_peer: "
			    "grant ref %d out of range in request 0x%p",
			    rxreq->gref, (void *)rxreq);
#endif /* XNB_DEBUG */

		/* 2 */
		d_offset = offset = TX_BUFFER_HEADROOM;
		len = 0;
		item_count = 0;

		gop_cp = xnbp->xnb_tx_cpop;

		/*
		 * We walk the b_cont pointers and set up a gop_cp
		 * structure for every page in every data block we have.
		 */
		/* 2a */
		for (ml = mp, ml_prev = NULL; ml != NULL; ml = ml->b_cont) {
			size_t	chunk = ml->b_wptr - ml->b_rptr;
			uchar_t	*r_tmp,	*rpt_align;
			size_t	r_offset;

			/*
			 * If we get an mblk on a page that doesn't belong to
			 * this domain, get a new mblk to replace the old one.
			 */
			if (is_foreign(ml->b_rptr) || is_foreign(ml->b_wptr)) {
				mblk_t *ml_new = replace_msg(ml, chunk,
				    mp_prev, ml_prev);

				/* We can still use old ml, but not *ml! */
				if (free == ml)
					free = ml_new;
				if (mp == ml)
					mp = ml_new;
				ml = ml_new;

				xnbp->xnb_stat_tx_foreign_page++;
			}

			rpt_align = (uchar_t *)ALIGN2PAGE(ml->b_rptr);
			r_offset = (uint16_t)(ml->b_rptr - rpt_align);
			r_tmp = ml->b_rptr;

			if (d_offset + chunk > PAGESIZE)
				cmn_err(CE_PANIC, "xnb_copy_to_peer: mp %p "
				    "(svd: %p), ml %p,rpt_alg. %p, d_offset "
				    "(%lu) + chunk (%lu) > PAGESIZE %d!",
				    (void *)mp, (void *)saved_mp, (void *)ml,
				    (void *)rpt_align,
				    d_offset, chunk, (int)PAGESIZE);

			while (chunk > 0) {
				size_t part_len;

				item_count++;
				if (item_count > xnbp->xnb_cpop_sz) {
					gop_cp = grow_cpop_area(xnbp, gop_cp);
					if (gop_cp == NULL)
						goto failure;
				}
				/*
				 * If our mblk crosses a page boundary, we need
				 * to do a seperate copy for every page.
				 */
				if (r_offset + chunk > PAGESIZE) {
					part_len = PAGESIZE - r_offset;

					DTRACE_PROBE3(mblk_page_crossed,
					    (mblk_t *), ml, int, chunk, int,
					    (int)r_offset);

					xnbp->xnb_stat_tx_pagebndry_crossed++;
				} else {
					part_len = chunk;
				}

				setup_gop(xnbp, gop_cp, r_tmp, r_offset,
				    d_offset, part_len, rxreq->gref);

				chunk -= part_len;

				len += part_len;
				d_offset += part_len;
				r_tmp += part_len;
				/*
				 * The 2nd, 3rd ... last copies will always
				 * start at r_tmp, therefore r_offset is 0.
				 */
				r_offset = 0;
				gop_cp++;
			}
			ml_prev = ml;
			DTRACE_PROBE4(mblk_loop_end, (mblk_t *), ml, int,
			    chunk, int, len, int, item_count);
		}
		/* 3 */
		if (HYPERVISOR_grant_table_op(GNTTABOP_copy, xnbp->xnb_tx_cpop,
		    item_count) != 0) {
			cmn_err(CE_WARN, "xnb_copy_to_peer: copy op. failed");
			DTRACE_PROBE(HV_granttableopfailed);
		}

		/* 4 */
		rxresp = RING_GET_RESPONSE(&xnbp->xnb_rx_ring, prod);
		rxresp->offset = offset;

		rxresp->flags = 0;

		DTRACE_PROBE4(got_RX_rsp, int, (int)rxresp->id, int,
		    (int)rxresp->offset, int, (int)rxresp->flags, int,
		    (int)rxresp->status);

		cksum_flags = xnbp->xnb_flavour->xf_cksum_to_peer(xnbp, mp);
		if (cksum_flags != 0)
			xnbp->xnb_stat_tx_cksum_deferred++;
		rxresp->flags |= cksum_flags;

		rxresp->id = RING_GET_REQUEST(&xnbp->xnb_rx_ring, prod)->id;
		rxresp->status = len;

		DTRACE_PROBE4(RX_rsp_set, int, (int)rxresp->id, int,
		    (int)rxresp->offset, int, (int)rxresp->flags, int,
		    (int)rxresp->status);

		for (i = 0; i < item_count; i++) {
			if (xnbp->xnb_tx_cpop[i].status != 0) {
				DTRACE_PROBE2(cpop__status__nonnull, int,
				    (int)xnbp->xnb_tx_cpop[i].status,
				    int, i);
				status = NETIF_RSP_ERROR;
			}
		}

		/* 5.2 */
		if (status != NETIF_RSP_OKAY) {
			RING_GET_RESPONSE(&xnbp->xnb_rx_ring, prod)->status =
			    status;
		} else {
			xnbp->xnb_stat_opackets++;
			xnbp->xnb_stat_obytes += len;
		}

		loop++;
		prod++;
		mp_prev = mp;
		mp = mp->b_next;
	}
failure:
	/*
	 * Did we actually do anything?
	 */
	if (loop == xnbp->xnb_rx_ring.req_cons) {
		mutex_exit(&xnbp->xnb_tx_lock);
		return (mp);
	}

	/*
	 * Unlink the end of the 'done' list from the remainder.
	 */
	ASSERT(mp_prev != NULL);
	mp_prev->b_next = NULL;

	xnbp->xnb_rx_ring.req_cons = loop;
	xnbp->xnb_rx_ring.rsp_prod_pvt = prod;

	/* 6 */
	/* LINTED: constant in conditional context */
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&xnbp->xnb_rx_ring, notify);
	if (notify) {
		ec_notify_via_evtchn(xnbp->xnb_evtchn);
		xnbp->xnb_stat_tx_notify_sent++;
	} else {
		xnbp->xnb_stat_tx_notify_deferred++;
	}

	if (mp != NULL)
		xnbp->xnb_stat_xmit_defer++;

	mutex_exit(&xnbp->xnb_tx_lock);

	/* Free mblk_t structs we have consumed. */
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

	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));

	/* LINTED: constant in conditional context */
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&xnbp->xnb_tx_ring, notify);
	if (notify) {
		ec_notify_via_evtchn(xnbp->xnb_evtchn);
		xnbp->xnb_stat_rx_notify_sent++;
	} else {
		xnbp->xnb_stat_rx_notify_deferred++;
	}
}

static void
xnb_rx_complete(xnb_rxbuf_t *rxp)
{
	xnb_t *xnbp = rxp->xr_xnbp;

	ASSERT((rxp->xr_flags & XNB_RXBUF_INUSE) == XNB_RXBUF_INUSE);

	mutex_enter(&xnbp->xnb_rx_lock);
	xnb_rx_schedule_unmop(xnbp, &rxp->xr_mop, rxp);
	mutex_exit(&xnbp->xnb_rx_lock);
}

static void
xnb_rx_mark_complete(xnb_t *xnbp, RING_IDX id, int16_t status)
{
	RING_IDX i;
	netif_tx_response_t *txresp;

	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));

	i = xnbp->xnb_tx_ring.rsp_prod_pvt;

	txresp = RING_GET_RESPONSE(&xnbp->xnb_tx_ring, i);
	txresp->id = id;
	txresp->status = status;

	xnbp->xnb_tx_ring.rsp_prod_pvt = i + 1;

	/*
	 * Note that we don't push the change to the peer here - that
	 * is the callers responsibility.
	 */
}

static void
xnb_rx_schedule_unmop(xnb_t *xnbp, gnttab_map_grant_ref_t *mop,
    xnb_rxbuf_t *rxp)
{
	gnttab_unmap_grant_ref_t	*unmop;
	int				u_count;
	int				reqs_on_ring;

	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));
	ASSERT(xnbp->xnb_rx_unmop_count < NET_TX_RING_SIZE);

	u_count = xnbp->xnb_rx_unmop_count++;

	/* Cache data for the time when we actually unmap grant refs */
	xnbp->xnb_rx_unmop_rxp[u_count] = rxp;

	unmop = &xnbp->xnb_rx_unmop[u_count];
	unmop->host_addr = mop->host_addr;
	unmop->dev_bus_addr = mop->dev_bus_addr;
	unmop->handle = mop->handle;

	/*
	 * We cannot check the ring once we're disconnected from it. Batching
	 * doesn't seem to be a useful optimisation in this case either,
	 * so we directly call into the actual unmap function.
	 */
	if (xnbp->xnb_connected) {
		reqs_on_ring = RING_HAS_UNCONSUMED_REQUESTS(&xnbp->xnb_rx_ring);

		/*
		 * By tuning xnb_unmop_hiwat to N, we can emulate "N per batch"
		 * or (with N == 1) "immediate unmop" behaviour.
		 * The "> xnb_unmop_lowwat" is a guard against ring exhaustion.
		 */
		if (xnbp->xnb_rx_unmop_count < xnb_unmop_hiwat &&
		    reqs_on_ring > xnb_unmop_lowwat)
			return;
	}

	xnb_rx_perform_pending_unmop(xnbp);
}

/*
 * Here we perform the actual unmapping of the data that was
 * accumulated in xnb_rx_schedule_unmop().
 * Note that it is the caller's responsibility to make sure that
 * there's actually something there to unmop.
 */
static void
xnb_rx_perform_pending_unmop(xnb_t *xnbp)
{
	RING_IDX loop;
#ifdef XNB_DEBUG
	gnttab_unmap_grant_ref_t *unmop;
#endif /* XNB_DEBUG */

	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));
	ASSERT(xnbp->xnb_rx_unmop_count > 0);

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
	    xnbp->xnb_rx_unmop, xnbp->xnb_rx_unmop_count) < 0) {
		cmn_err(CE_WARN, "xnb_rx_perform_pending_unmop: "
		    "unmap grant operation failed, "
		    "%d pages lost", xnbp->xnb_rx_unmop_count);
	}

#ifdef XNB_DEBUG
	for (loop = 0, unmop = xnbp->xnb_rx_unmop;
	    loop < xnbp->xnb_rx_unmop_count;
	    loop++, unmop++) {
		if (unmop->status != 0) {
			cmn_err(CE_WARN, "xnb_rx_perform_pending_unmop: "
			    "unmap grant reference failed (%d)",
			    unmop->status);
		}
	}
#endif /* XNB_DEBUG */

	for (loop = 0; loop < xnbp->xnb_rx_unmop_count; loop++) {
		xnb_rxbuf_t	*rxp = xnbp->xnb_rx_unmop_rxp[loop];

		if (rxp == NULL)
			cmn_err(CE_PANIC,
			    "xnb_rx_perform_pending_unmop: "
			    "unexpected NULL rxp (loop %d; count %d)!",
			    loop, xnbp->xnb_rx_unmop_count);

		if (xnbp->xnb_connected)
			xnb_rx_mark_complete(xnbp, rxp->xr_id, rxp->xr_status);
		xnb_rxbuf_put(xnbp, rxp);
	}
	if (xnbp->xnb_connected)
		xnb_rx_notify_peer(xnbp);

	xnbp->xnb_rx_unmop_count = 0;

#ifdef XNB_DEBUG
	bzero(xnbp->xnb_rx_unmop, sizeof (xnbp->xnb_rx_unmop));
	bzero(xnbp->xnb_rx_unmop_rxp, sizeof (xnbp->xnb_rx_unmop_rxp));
#endif /* XNB_DEBUG */
}

static xnb_rxbuf_t *
xnb_rxbuf_get(xnb_t *xnbp, int flags)
{
	xnb_rxbuf_t *rxp;

	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));

	rxp = kmem_cache_alloc(xnb_rxbuf_cachep, flags);
	if (rxp != NULL) {
		ASSERT((rxp->xr_flags & XNB_RXBUF_INUSE) == 0);
		rxp->xr_flags |= XNB_RXBUF_INUSE;

		rxp->xr_xnbp = xnbp;
		rxp->xr_mop.dom = xnbp->xnb_peer;

		rxp->xr_mop.flags = GNTMAP_host_map;
		if (!xnbp->xnb_rx_pages_writable)
			rxp->xr_mop.flags |= GNTMAP_readonly;

		xnbp->xnb_rx_buf_count++;
	}

	return (rxp);
}

static void
xnb_rxbuf_put(xnb_t *xnbp, xnb_rxbuf_t *rxp)
{
	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));
	ASSERT((rxp->xr_flags & XNB_RXBUF_INUSE) == XNB_RXBUF_INUSE);

	rxp->xr_flags &= ~XNB_RXBUF_INUSE;
	xnbp->xnb_rx_buf_count--;

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
	boolean_t copy = !xnbp->xnb_rx_pages_writable;

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
	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));

	/* LINTED: constant in conditional context */
	RING_FINAL_CHECK_FOR_REQUESTS(&xnbp->xnb_tx_ring, work_to_do);
	if (!work_to_do) {
finished:
		return (head);
	}

	start = xnbp->xnb_tx_ring.req_cons;
	end = xnbp->xnb_tx_ring.sring->req_prod;

	for (loop = start, mop = xnbp->xnb_rx_mop, rxpp = xnbp->xnb_rx_bufp;
	    loop != end;
	    loop++, mop++, rxpp++) {
		xnb_rxbuf_t *rxp;

		rxp = xnb_rxbuf_get(xnbp, KM_NOSLEEP);
		if (rxp == NULL)
			break;

		ASSERT(xnbp->xnb_rx_pages_writable ||
		    ((rxp->xr_mop.flags & GNTMAP_readonly)
		    == GNTMAP_readonly));

		rxp->xr_mop.ref =
		    RING_GET_REQUEST(&xnbp->xnb_tx_ring, loop)->gref;

		ASSERT(rxp->xr_mop.ref < NR_GRANT_ENTRIES);

		*mop = rxp->xr_mop;
		*rxpp = rxp;
	}

	if ((loop - start) == 0)
		goto finished;

	end = loop;

	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
	    xnbp->xnb_rx_mop, end - start) != 0) {

		cmn_err(CE_WARN, "xnb_recv: map grant operation failed");

		loop = start;
		rxpp = xnbp->xnb_rx_bufp;

		while (loop != end) {
			xnb_rxbuf_put(xnbp, *rxpp);

			loop++;
			rxpp++;
		}

		goto finished;
	}

	for (loop = start, mop = xnbp->xnb_rx_mop, rxpp = xnbp->xnb_rx_bufp;
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

		txreq = RING_GET_REQUEST(&xnbp->xnb_tx_ring, loop);

		if (status == NETIF_RSP_OKAY) {
			if (copy) {
				mp = allocb(txreq->size, BPRI_MED);
				if (mp == NULL) {
					status = NETIF_RSP_ERROR;
					xnbp->xnb_stat_rx_allocb_failed++;
				} else {
					bcopy((caddr_t)(uintptr_t)
					    mop->host_addr + txreq->offset,
					    mp->b_wptr, txreq->size);
					mp->b_wptr += txreq->size;
				}
			} else {
				mp = desballoc((uchar_t *)(uintptr_t)
				    mop->host_addr + txreq->offset,
				    txreq->size, 0, &rxp->xr_free_rtn);
				if (mp == NULL) {
					status = NETIF_RSP_ERROR;
					xnbp->xnb_stat_rx_allocb_failed++;
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
				mp = xnbp->xnb_flavour->xf_cksum_from_peer(xnbp,
				    mp, txreq->flags);
				xnbp->xnb_stat_rx_cksum_no_need++;
			}
		}

		if (copy || (mp == NULL)) {
			rxp->xr_status = status;
			rxp->xr_id = txreq->id;
			xnb_rx_schedule_unmop(xnbp, mop, rxp);
		}

		if (mp != NULL) {
			xnbp->xnb_stat_ipackets++;
			xnbp->xnb_stat_rbytes += txreq->size;

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

	xnbp->xnb_tx_ring.req_cons = loop;

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

	xnbp->xnb_stat_intr++;

	mutex_enter(&xnbp->xnb_rx_lock);

	ASSERT(xnbp->xnb_connected);

	mp = xnb_recv(xnbp);

	mutex_exit(&xnbp->xnb_rx_lock);

	if (!xnbp->xnb_hotplugged) {
		xnbp->xnb_stat_rx_too_early++;
		goto fail;
	}
	if (mp == NULL) {
		xnbp->xnb_stat_spurious_intr++;
		goto fail;
	}

	xnbp->xnb_flavour->xf_recv(xnbp, mp);

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
	ASSERT(!xnbp->xnb_connected);

	oename = xvdi_get_oename(dip);

	if (xenbus_gather(XBT_NULL, oename,
	    "event-channel", "%u", &evtchn,
	    "tx-ring-ref", "%lu", &xnbp->xnb_tx_ring_ref,
	    "rx-ring-ref", "%lu", &xnbp->xnb_rx_ring_ref,
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
		xnbp->xnb_rx_pages_writable = B_TRUE;

	if (xenbus_scanf(XBT_NULL, oename,
	    "feature-no-csum-offload", "%d", &i) != 0)
		i = 0;
	if ((i == 1) || !xnbp->xnb_cksum_offload)
		xnbp->xnb_cksum_offload = B_FALSE;

	/* Check whether our peer knows and requests hypervisor copy */
	if (xenbus_scanf(XBT_NULL, oename, "request-rx-copy", "%d", &i)
	    != 0)
		i = 0;
	if (i != 0)
		xnbp->xnb_hv_copy = B_TRUE;

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
	xnbp->xnb_tx_ring_addr = vmem_xalloc(heap_arena, PAGESIZE, PAGESIZE,
	    0, 0, 0, 0, VM_SLEEP);
	ASSERT(xnbp->xnb_tx_ring_addr != NULL);

	/* 2.tx */
	map_op.host_addr = (uint64_t)((long)xnbp->xnb_tx_ring_addr);
	map_op.flags = GNTMAP_host_map;
	map_op.ref = xnbp->xnb_tx_ring_ref;
	map_op.dom = xnbp->xnb_peer;
	hat_prepare_mapping(kas.a_hat, xnbp->xnb_tx_ring_addr);
	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
	    &map_op, 1) != 0 || map_op.status != 0) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot map tx-ring page.");
		goto fail;
	}
	xnbp->xnb_tx_ring_handle = map_op.handle;

	/* LINTED: constant in conditional context */
	BACK_RING_INIT(&xnbp->xnb_tx_ring,
	    (netif_tx_sring_t *)xnbp->xnb_tx_ring_addr, PAGESIZE);

	/* 1.rx */
	xnbp->xnb_rx_ring_addr = vmem_xalloc(heap_arena, PAGESIZE, PAGESIZE,
	    0, 0, 0, 0, VM_SLEEP);
	ASSERT(xnbp->xnb_rx_ring_addr != NULL);

	/* 2.rx */
	map_op.host_addr = (uint64_t)((long)xnbp->xnb_rx_ring_addr);
	map_op.flags = GNTMAP_host_map;
	map_op.ref = xnbp->xnb_rx_ring_ref;
	map_op.dom = xnbp->xnb_peer;
	hat_prepare_mapping(kas.a_hat, xnbp->xnb_rx_ring_addr);
	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
	    &map_op, 1) != 0 || map_op.status != 0) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot map rx-ring page.");
		goto fail;
	}
	xnbp->xnb_rx_ring_handle = map_op.handle;

	/* LINTED: constant in conditional context */
	BACK_RING_INIT(&xnbp->xnb_rx_ring,
	    (netif_rx_sring_t *)xnbp->xnb_rx_ring_addr, PAGESIZE);

	/* 3 */
	if (xvdi_bind_evtchn(dip, evtchn) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xnb_connect_rings: "
		    "cannot bind event channel %d", xnbp->xnb_evtchn);
		xnbp->xnb_evtchn = INVALID_EVTCHN;
		goto fail;
	}
	xnbp->xnb_evtchn = xvdi_get_evtchn(dip);

	/*
	 * It would be good to set the state to XenbusStateConnected
	 * here as well, but then what if ddi_add_intr() failed?
	 * Changing the state in the store will be noticed by the peer
	 * and cannot be "taken back".
	 */
	mutex_enter(&xnbp->xnb_tx_lock);
	mutex_enter(&xnbp->xnb_rx_lock);

	/* 5.1 */
	xnbp->xnb_connected = B_TRUE;

	mutex_exit(&xnbp->xnb_rx_lock);
	mutex_exit(&xnbp->xnb_tx_lock);

	/* 4, 6 */
	if (ddi_add_intr(dip, 0, NULL, NULL, xnb_intr, (caddr_t)xnbp)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot add interrupt");
		goto fail;
	}
	xnbp->xnb_irq = B_TRUE;

	/* 5.2 */
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateConnected);

	return (B_TRUE);

fail:
	mutex_enter(&xnbp->xnb_tx_lock);
	mutex_enter(&xnbp->xnb_rx_lock);

	xnbp->xnb_connected = B_FALSE;
	mutex_exit(&xnbp->xnb_rx_lock);
	mutex_exit(&xnbp->xnb_tx_lock);

	return (B_FALSE);
}

static void
xnb_disconnect_rings(dev_info_t *dip)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);

	if (xnbp->xnb_irq) {
		ddi_remove_intr(dip, 0, NULL);
		xnbp->xnb_irq = B_FALSE;
	}

	if (xnbp->xnb_rx_unmop_count > 0)
		xnb_rx_perform_pending_unmop(xnbp);

	if (xnbp->xnb_evtchn != INVALID_EVTCHN) {
		xvdi_free_evtchn(dip);
		xnbp->xnb_evtchn = INVALID_EVTCHN;
	}

	if (xnbp->xnb_rx_ring_handle != INVALID_GRANT_HANDLE) {
		struct gnttab_unmap_grant_ref unmap_op;

		unmap_op.host_addr = (uint64_t)(uintptr_t)
		    xnbp->xnb_rx_ring_addr;
		unmap_op.dev_bus_addr = 0;
		unmap_op.handle = xnbp->xnb_rx_ring_handle;
		if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
		    &unmap_op, 1) != 0)
			cmn_err(CE_WARN, "xnb_disconnect_rings: "
			    "cannot unmap rx-ring page (%d)",
			    unmap_op.status);

		xnbp->xnb_rx_ring_handle = INVALID_GRANT_HANDLE;
	}

	if (xnbp->xnb_rx_ring_addr != NULL) {
		hat_release_mapping(kas.a_hat, xnbp->xnb_rx_ring_addr);
		vmem_free(heap_arena, xnbp->xnb_rx_ring_addr, PAGESIZE);
		xnbp->xnb_rx_ring_addr = NULL;
	}

	if (xnbp->xnb_tx_ring_handle != INVALID_GRANT_HANDLE) {
		struct gnttab_unmap_grant_ref unmap_op;

		unmap_op.host_addr = (uint64_t)(uintptr_t)
		    xnbp->xnb_tx_ring_addr;
		unmap_op.dev_bus_addr = 0;
		unmap_op.handle = xnbp->xnb_tx_ring_handle;
		if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
		    &unmap_op, 1) != 0)
			cmn_err(CE_WARN, "xnb_disconnect_rings: "
			    "cannot unmap tx-ring page (%d)",
			    unmap_op.status);

		xnbp->xnb_tx_ring_handle = INVALID_GRANT_HANDLE;
	}

	if (xnbp->xnb_tx_ring_addr != NULL) {
		hat_release_mapping(kas.a_hat, xnbp->xnb_tx_ring_addr);
		vmem_free(heap_arena, xnbp->xnb_tx_ring_addr, PAGESIZE);
		xnbp->xnb_tx_ring_addr = NULL;
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
			xnbp->xnb_flavour->xf_peer_connected(xnbp);
		} else {
			xnbp->xnb_flavour->xf_peer_disconnected(xnbp);
			xnb_disconnect_rings(dip);
			(void) xvdi_switch_state(dip, XBT_NULL,
			    XenbusStateClosed);
			(void) xvdi_post_event(dip, XEN_HP_REMOVE);
		}

		/*
		 * Now that we've attempted to connect it's reasonable
		 * to allow an attempt to detach.
		 */
		xnbp->xnb_detachable = B_TRUE;

		break;

	case XenbusStateClosing:
		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosing);

		break;

	case XenbusStateClosed:
		xnbp->xnb_flavour->xf_peer_disconnected(xnbp);

		mutex_enter(&xnbp->xnb_tx_lock);
		mutex_enter(&xnbp->xnb_rx_lock);

		xnb_disconnect_rings(dip);
		xnbp->xnb_connected = B_FALSE;

		mutex_exit(&xnbp->xnb_rx_lock);
		mutex_exit(&xnbp->xnb_tx_lock);

		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosed);
		(void) xvdi_post_event(dip, XEN_HP_REMOVE);
		/*
		 * In all likelyhood this is already set (in the above
		 * case), but if the peer never attempted to connect
		 * and the domain is destroyed we get here without
		 * having been through the case above, so we set it to
		 * be sure.
		 */
		xnbp->xnb_detachable = B_TRUE;

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

		success = xnbp->xnb_flavour->xf_hotplug_connected(xnbp);

		mutex_enter(&xnbp->xnb_tx_lock);
		mutex_enter(&xnbp->xnb_rx_lock);

		xnbp->xnb_hotplugged = success;

		mutex_exit(&xnbp->xnb_rx_lock);
		mutex_exit(&xnbp->xnb_tx_lock);
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

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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifdef DEBUG
#define	XNB_DEBUG 1
#endif /* DEBUG */

#include "xnb.h"

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/mac.h>
#include <sys/mac_impl.h> /* For mac_fix_cksum(). */
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
#include <sys/note.h>
#include <sys/gld.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>

/*
 * The terms "transmit" and "receive" are used in alignment with domU,
 * which means that packets originating from the peer domU are "transmitted"
 * to other parts of the system and packets are "received" from them.
 */

/*
 * Should we allow guests to manipulate multicast group membership?
 */
static boolean_t	xnb_multicast_control = B_TRUE;

static boolean_t	xnb_connect_rings(dev_info_t *);
static void		xnb_disconnect_rings(dev_info_t *);
static void		xnb_oe_state_change(dev_info_t *, ddi_eventcookie_t,
    void *, void *);
static void		xnb_hp_state_change(dev_info_t *, ddi_eventcookie_t,
    void *, void *);

static int	xnb_txbuf_constructor(void *, void *, int);
static void	xnb_txbuf_destructor(void *, void *);
static void	xnb_tx_notify_peer(xnb_t *, boolean_t);
static void	xnb_tx_mark_complete(xnb_t *, RING_IDX, int16_t);

mblk_t		*xnb_to_peer(xnb_t *, mblk_t *);
mblk_t		*xnb_copy_to_peer(xnb_t *, mblk_t *);

static void		setup_gop(xnb_t *, gnttab_copy_t *, uchar_t *,
    size_t, size_t, size_t, grant_ref_t);
#pragma inline(setup_gop)
static boolean_t	is_foreign(void *);
#pragma inline(is_foreign)

#define	INVALID_GRANT_HANDLE	((grant_handle_t)-1)
#define	INVALID_GRANT_REF	((grant_ref_t)-1)

static kmutex_t	xnb_alloc_page_lock;

/*
 * On a 32 bit PAE system physical and machine addresses are larger
 * than 32 bits.  ddi_btop() on such systems take an unsigned long
 * argument, and so addresses above 4G are truncated before ddi_btop()
 * gets to see them.  To avoid this, code the shift operation here.
 */
#define	xnb_btop(addr)	((addr) >> PAGESHIFT)

/* DMA attributes for transmit and receive data */
static ddi_dma_attr_t buf_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	MMU_PAGESIZE,		/* alignment in bytes */
	0x7ff,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

/* DMA access attributes for data: NOT to be byte swapped. */
static ddi_device_acc_attr_t data_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Statistics.
 */
static const char * const aux_statistics[] = {
	"rx_cksum_deferred",
	"tx_cksum_no_need",
	"rx_rsp_notok",
	"tx_notify_deferred",
	"tx_notify_sent",
	"rx_notify_deferred",
	"rx_notify_sent",
	"tx_too_early",
	"rx_too_early",
	"rx_allocb_failed",
	"tx_allocb_failed",
	"rx_foreign_page",
	"mac_full",
	"spurious_intr",
	"allocation_success",
	"allocation_failure",
	"small_allocation_success",
	"small_allocation_failure",
	"other_allocation_failure",
	"rx_pageboundary_crossed",
	"rx_cpoparea_grown",
	"csum_hardware",
	"csum_software",
	"tx_overflow_page",
	"tx_unexpected_flags",
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
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_cksum_deferred;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_cksum_no_need;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_rsp_notok;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_notify_deferred;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_notify_sent;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_notify_deferred;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_notify_sent;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_too_early;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_too_early;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_allocb_failed;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_allocb_failed;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_foreign_page;
	(knp++)->value.ui64 = xnbp->xnb_stat_mac_full;
	(knp++)->value.ui64 = xnbp->xnb_stat_spurious_intr;
	(knp++)->value.ui64 = xnbp->xnb_stat_allocation_success;
	(knp++)->value.ui64 = xnbp->xnb_stat_allocation_failure;
	(knp++)->value.ui64 = xnbp->xnb_stat_small_allocation_success;
	(knp++)->value.ui64 = xnbp->xnb_stat_small_allocation_failure;
	(knp++)->value.ui64 = xnbp->xnb_stat_other_allocation_failure;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_pagebndry_crossed;
	(knp++)->value.ui64 = xnbp->xnb_stat_rx_cpoparea_grown;
	(knp++)->value.ui64 = xnbp->xnb_stat_csum_hardware;
	(knp++)->value.ui64 = xnbp->xnb_stat_csum_software;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_overflow_page;
	(knp++)->value.ui64 = xnbp->xnb_stat_tx_unexpected_flags;

	return (0);
}

static boolean_t
xnb_ks_init(xnb_t *xnbp)
{
	int nstat = sizeof (aux_statistics) /
	    sizeof (aux_statistics[0]);
	const char * const *cp = aux_statistics;
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
 * Calculate and insert the transport checksum for an arbitrary packet.
 */
static mblk_t *
xnb_software_csum(xnb_t *xnbp, mblk_t *mp)
{
	_NOTE(ARGUNUSED(xnbp));

	/*
	 * XXPV dme: shouldn't rely on mac_fix_cksum(), not least
	 * because it doesn't cover all of the interesting cases :-(
	 */
	mac_hcksum_set(mp, 0, 0, 0, 0, HCK_FULLCKSUM);

	return (mac_fix_cksum(mp));
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
	 * the "from peer" path this is true today, but may change
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
	case IPPROTO_UDP: {
		uint32_t start, length, stuff, cksum;
		uint16_t *stuffp;

		/*
		 * This is a TCP/IPv4 or UDP/IPv4 packet, for which we
		 * can use full IPv4 and partial checksum offload.
		 */
		if ((capab & (HCKSUM_INET_FULL_V4|HCKSUM_INET_PARTIAL)) == 0)
			break;

		start = IP_SIMPLE_HDR_LENGTH;
		length = ntohs(ipha->ipha_length);
		if (ipha->ipha_protocol == IPPROTO_TCP) {
			stuff = start + TCP_CHECKSUM_OFFSET;
			cksum = IP_TCP_CSUM_COMP;
		} else {
			stuff = start + UDP_CHECKSUM_OFFSET;
			cksum = IP_UDP_CSUM_COMP;
		}
		stuffp = (uint16_t *)(mp->b_rptr + offset + stuff);

		if (capab & HCKSUM_INET_FULL_V4) {
			/*
			 * Some devices require that the checksum
			 * field of the packet is zero for full
			 * offload.
			 */
			*stuffp = 0;

			mac_hcksum_set(mp, 0, 0, 0, 0, HCK_FULLCKSUM);

			xnbp->xnb_stat_csum_hardware++;

			return (mp);
		}

		if (capab & HCKSUM_INET_PARTIAL) {
			if (*stuffp == 0) {
				ipaddr_t src, dst;

				/*
				 * Older Solaris guests don't insert
				 * the pseudo-header checksum, so we
				 * calculate it here.
				 */
				src = ipha->ipha_src;
				dst = ipha->ipha_dst;

				cksum += (dst >> 16) + (dst & 0xFFFF);
				cksum += (src >> 16) + (src & 0xFFFF);
				cksum += length - IP_SIMPLE_HDR_LENGTH;

				cksum = (cksum >> 16) + (cksum & 0xFFFF);
				cksum = (cksum >> 16) + (cksum & 0xFFFF);

				ASSERT(cksum <= 0xFFFF);

				*stuffp = (uint16_t)(cksum ? cksum : ~cksum);
			}

			mac_hcksum_set(mp, start, stuff, length, 0,
			    HCK_PARTIALCKSUM);

			xnbp->xnb_stat_csum_hardware++;

			return (mp);
		}

		/* NOTREACHED */
		break;
	}

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
	char *xsname;
	char cachename[32];

	xnbp = kmem_zalloc(sizeof (*xnbp), KM_SLEEP);

	xnbp->xnb_flavour = flavour;
	xnbp->xnb_flavour_data = flavour_data;
	xnbp->xnb_devinfo = dip;
	xnbp->xnb_evtchn = INVALID_EVTCHN;
	xnbp->xnb_irq = B_FALSE;
	xnbp->xnb_tx_ring_handle = INVALID_GRANT_HANDLE;
	xnbp->xnb_rx_ring_handle = INVALID_GRANT_HANDLE;
	xnbp->xnb_connected = B_FALSE;
	xnbp->xnb_hotplugged = B_FALSE;
	xnbp->xnb_detachable = B_FALSE;
	xnbp->xnb_peer = xvdi_get_oeid(dip);
	xnbp->xnb_be_status = XNB_STATE_INIT;
	xnbp->xnb_fe_status = XNB_STATE_INIT;

	xnbp->xnb_tx_buf_count = 0;

	xnbp->xnb_rx_hv_copy = B_FALSE;
	xnbp->xnb_multicast_control = B_FALSE;

	xnbp->xnb_rx_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	ASSERT(xnbp->xnb_rx_va != NULL);

	if (ddi_get_iblock_cookie(dip, 0, &xnbp->xnb_icookie)
	    != DDI_SUCCESS)
		goto failure;

	/* Allocated on demand, when/if we enter xnb_copy_to_peer(). */
	xnbp->xnb_rx_cpop = NULL;
	xnbp->xnb_rx_cpop_count = 0;

	mutex_init(&xnbp->xnb_tx_lock, NULL, MUTEX_DRIVER,
	    xnbp->xnb_icookie);
	mutex_init(&xnbp->xnb_rx_lock, NULL, MUTEX_DRIVER,
	    xnbp->xnb_icookie);
	mutex_init(&xnbp->xnb_state_lock, NULL, MUTEX_DRIVER,
	    xnbp->xnb_icookie);

	/* Set driver private pointer now. */
	ddi_set_driver_private(dip, xnbp);

	(void) sprintf(cachename, "xnb_tx_buf_cache_%d", ddi_get_instance(dip));
	xnbp->xnb_tx_buf_cache = kmem_cache_create(cachename,
	    sizeof (xnb_txbuf_t), 0,
	    xnb_txbuf_constructor, xnb_txbuf_destructor,
	    NULL, xnbp, NULL, 0);
	if (xnbp->xnb_tx_buf_cache == NULL)
		goto failure_0;

	if (!xnb_ks_init(xnbp))
		goto failure_1;

	/*
	 * Receive notification of changes in the state of the
	 * driver in the guest domain.
	 */
	if (xvdi_add_event_handler(dip, XS_OE_STATE, xnb_oe_state_change,
	    NULL) != DDI_SUCCESS)
		goto failure_2;

	/*
	 * Receive notification of hotplug events.
	 */
	if (xvdi_add_event_handler(dip, XS_HP_STATE, xnb_hp_state_change,
	    NULL) != DDI_SUCCESS)
		goto failure_2;

	xsname = xvdi_get_xsname(dip);

	if (xenbus_printf(XBT_NULL, xsname,
	    "feature-multicast-control", "%d",
	    xnb_multicast_control ? 1 : 0) != 0)
		goto failure_3;

	if (xenbus_printf(XBT_NULL, xsname,
	    "feature-rx-copy", "%d",  1) != 0)
		goto failure_3;
	/*
	 * Linux domUs seem to depend on "feature-rx-flip" being 0
	 * in addition to "feature-rx-copy" being 1. It seems strange
	 * to use four possible states to describe a binary decision,
	 * but we might as well play nice.
	 */
	if (xenbus_printf(XBT_NULL, xsname,
	    "feature-rx-flip", "%d", 0) != 0)
		goto failure_3;

	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateInitWait);
	(void) xvdi_post_event(dip, XEN_HP_ADD);

	return (DDI_SUCCESS);

failure_3:
	xvdi_remove_event_handler(dip, NULL);

failure_2:
	xnb_ks_free(xnbp);

failure_1:
	kmem_cache_destroy(xnbp->xnb_tx_buf_cache);

failure_0:
	mutex_destroy(&xnbp->xnb_state_lock);
	mutex_destroy(&xnbp->xnb_rx_lock);
	mutex_destroy(&xnbp->xnb_tx_lock);

failure:
	vmem_free(heap_arena, xnbp->xnb_rx_va, PAGESIZE);
	kmem_free(xnbp, sizeof (*xnbp));
	return (DDI_FAILURE);
}

void
xnb_detach(dev_info_t *dip)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);

	ASSERT(xnbp != NULL);
	ASSERT(!xnbp->xnb_connected);
	ASSERT(xnbp->xnb_tx_buf_count == 0);

	xnb_disconnect_rings(dip);

	xvdi_remove_event_handler(dip, NULL);

	xnb_ks_free(xnbp);

	kmem_cache_destroy(xnbp->xnb_tx_buf_cache);

	ddi_set_driver_private(dip, NULL);

	mutex_destroy(&xnbp->xnb_state_lock);
	mutex_destroy(&xnbp->xnb_rx_lock);
	mutex_destroy(&xnbp->xnb_tx_lock);

	if (xnbp->xnb_rx_cpop_count > 0)
		kmem_free(xnbp->xnb_rx_cpop, sizeof (xnbp->xnb_rx_cpop[0])
		    * xnbp->xnb_rx_cpop_count);

	ASSERT(xnbp->xnb_rx_va != NULL);
	vmem_free(heap_arena, xnbp->xnb_rx_va, PAGESIZE);

	kmem_free(xnbp, sizeof (*xnbp));
}

/*
 * Allocate a page from the hypervisor to be flipped to the peer.
 *
 * Try to get pages in batches to reduce the overhead of calls into
 * the balloon driver.
 */
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

/*
 * Free a page back to the hypervisor.
 *
 * This happens only in the error path, so batching is not worth the
 * complication.
 */
static void
xnb_free_page(xnb_t *xnbp, mfn_t mfn)
{
	_NOTE(ARGUNUSED(xnbp));
	int r;
	pfn_t pfn;

	pfn = xen_assign_pfn(mfn);
	pfnzero(pfn, 0, PAGESIZE);
	xen_release_pfn(pfn);

	if ((r = balloon_free_pages(1, &mfn, NULL, NULL)) != 1) {
		cmn_err(CE_WARN, "free_page: cannot decrease memory "
		    "reservation (%d): page kept but unusable (mfn = 0x%lx).",
		    r, mfn);
	}
}

/*
 * Similar to RING_HAS_UNCONSUMED_REQUESTS(&xnbp->rx_ring) but using
 * local variables. Used in both xnb_to_peer() and xnb_copy_to_peer().
 */
#define	XNB_RING_HAS_UNCONSUMED_REQUESTS(_r)		\
	((((_r)->sring->req_prod - loop) <		\
		(RING_SIZE(_r) - (loop - prod))) ?	\
	    ((_r)->sring->req_prod - loop) :		\
	    (RING_SIZE(_r) - (loop - prod)))

/*
 * Pass packets to the peer using page flipping.
 */
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

	mutex_enter(&xnbp->xnb_rx_lock);

	/*
	 * If we are not connected to the peer or have not yet
	 * finished hotplug it is too early to pass packets to the
	 * peer.
	 */
	if (!(xnbp->xnb_connected && xnbp->xnb_hotplugged)) {
		mutex_exit(&xnbp->xnb_rx_lock);
		DTRACE_PROBE(flip_rx_too_early);
		xnbp->xnb_stat_rx_too_early++;
		return (mp);
	}

	loop = xnbp->xnb_rx_ring.req_cons;
	prod = xnbp->xnb_rx_ring.rsp_prod_pvt;
	gop = xnbp->xnb_rx_top;

	while ((mp != NULL) &&
	    XNB_RING_HAS_UNCONSUMED_REQUESTS(&xnbp->xnb_rx_ring)) {

		mfn_t mfn;
		pfn_t pfn;
		netif_rx_request_t *rxreq;
		netif_rx_response_t *rxresp;
		char *valoop;
		mblk_t *ml;
		uint16_t cksum_flags;

		/* 1 */
		if ((mfn = xnb_alloc_page(xnbp)) == 0) {
			xnbp->xnb_stat_rx_defer++;
			break;
		}

		/* 2 */
		rxreq = RING_GET_REQUEST(&xnbp->xnb_rx_ring, loop);

#ifdef XNB_DEBUG
		if (!(rxreq->id < NET_RX_RING_SIZE))
			cmn_err(CE_PANIC, "xnb_to_peer: "
			    "id %d out of range in request 0x%p",
			    rxreq->id, (void *)rxreq);
#endif /* XNB_DEBUG */

		/* Assign a pfn and map the new page at the allocated va. */
		pfn = xen_assign_pfn(mfn);
		hat_devload(kas.a_hat, xnbp->xnb_rx_va, PAGESIZE,
		    pfn, PROT_READ | PROT_WRITE, HAT_LOAD);

		/* 3 */
		len = 0;
		valoop = xnbp->xnb_rx_va;
		for (ml = mp; ml != NULL; ml = ml->b_cont) {
			size_t chunk = ml->b_wptr - ml->b_rptr;

			bcopy(ml->b_rptr, valoop, chunk);
			valoop += chunk;
			len += chunk;
		}

		ASSERT(len < PAGESIZE);

		/* Release the pfn. */
		hat_unload(kas.a_hat, xnbp->xnb_rx_va, PAGESIZE,
		    HAT_UNLOAD_UNMAP);
		xen_release_pfn(pfn);

		/* 4 */
		gop->mfn = mfn;
		gop->domid = xnbp->xnb_peer;
		gop->ref = rxreq->gref;

		/* 5.1 */
		rxresp = RING_GET_RESPONSE(&xnbp->xnb_rx_ring, prod);
		rxresp->offset = 0;
		rxresp->flags = 0;

		cksum_flags = xnbp->xnb_flavour->xf_cksum_to_peer(xnbp, mp);
		if (cksum_flags != 0)
			xnbp->xnb_stat_rx_cksum_deferred++;
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
		mutex_exit(&xnbp->xnb_rx_lock);
		return (mp);
	}

	end = loop;

	/*
	 * Unlink the end of the 'done' list from the remainder.
	 */
	ASSERT(prev != NULL);
	prev->b_next = NULL;

	if (HYPERVISOR_grant_table_op(GNTTABOP_transfer, xnbp->xnb_rx_top,
	    loop - xnbp->xnb_rx_ring.req_cons) != 0) {
		cmn_err(CE_WARN, "xnb_to_peer: transfer operation failed");
	}

	loop = xnbp->xnb_rx_ring.req_cons;
	prod = xnbp->xnb_rx_ring.rsp_prod_pvt;
	gop = xnbp->xnb_rx_top;

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
			xnbp->xnb_stat_ipackets++;
			xnbp->xnb_stat_rbytes += len;
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
		xnbp->xnb_stat_rx_notify_sent++;
	} else {
		xnbp->xnb_stat_rx_notify_deferred++;
	}

	if (mp != NULL)
		xnbp->xnb_stat_rx_defer++;

	mutex_exit(&xnbp->xnb_rx_lock);

	/* Free mblk_t's that we consumed. */
	freemsgchain(free);

	return (mp);
}

/* Helper functions for xnb_copy_to_peer(). */

/*
 * Grow the array of copy operation descriptors.
 */
static boolean_t
grow_cpop_area(xnb_t *xnbp)
{
	size_t count;
	gnttab_copy_t *new;

	ASSERT(MUTEX_HELD(&xnbp->xnb_rx_lock));

	count = xnbp->xnb_rx_cpop_count + CPOP_DEFCNT;

	if ((new = kmem_alloc(sizeof (new[0]) * count, KM_NOSLEEP)) == NULL) {
		xnbp->xnb_stat_other_allocation_failure++;
		return (B_FALSE);
	}

	bcopy(xnbp->xnb_rx_cpop, new,
	    sizeof (xnbp->xnb_rx_cpop[0]) * xnbp->xnb_rx_cpop_count);

	kmem_free(xnbp->xnb_rx_cpop,
	    sizeof (xnbp->xnb_rx_cpop[0]) * xnbp->xnb_rx_cpop_count);

	xnbp->xnb_rx_cpop = new;
	xnbp->xnb_rx_cpop_count = count;

	xnbp->xnb_stat_rx_cpoparea_grown++;

	return (B_TRUE);
}

/*
 * Check whether an address is on a page that's foreign to this domain.
 */
static boolean_t
is_foreign(void *addr)
{
	pfn_t pfn = hat_getpfnum(kas.a_hat, addr);

	return ((pfn & PFN_IS_FOREIGN_MFN) == PFN_IS_FOREIGN_MFN);
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
	if (new_mp == NULL) {
		cmn_err(CE_PANIC, "replace_msg: cannot alloc new message"
		    "for %p, len %lu", (void *) mp, len);
	}

	mac_hcksum_get(mp, &start, &stuff, &end, &value, &flags);
	mac_hcksum_set(new_mp, start, stuff, end, value, flags);

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

/*
 * Pass packets to the peer using hypervisor copy operations.
 */
mblk_t *
xnb_copy_to_peer(xnb_t *xnbp, mblk_t *mp)
{
	mblk_t		*free = mp, *mp_prev = NULL, *saved_mp = mp;
	mblk_t		*ml, *ml_prev;
	boolean_t	notify;
	RING_IDX	loop, prod;
	int		i;

	/*
	 * If the peer does not pre-post buffers for received packets,
	 * use page flipping to pass packets to it.
	 */
	if (!xnbp->xnb_rx_hv_copy)
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
	 *  several mblks (mp->b_cont != NULL) for the peer and
	 *  perform a single hypercall to transfer them.  We also have
	 *  to set up a seperate copy operation for every page.
	 *
	 * If we have more than one packet (mp->b_next != NULL), we do
	 * this whole dance repeatedly.
	 */

	mutex_enter(&xnbp->xnb_rx_lock);

	if (!(xnbp->xnb_connected && xnbp->xnb_hotplugged)) {
		mutex_exit(&xnbp->xnb_rx_lock);
		DTRACE_PROBE(copy_rx_too_early);
		xnbp->xnb_stat_rx_too_early++;
		return (mp);
	}

	loop = xnbp->xnb_rx_ring.req_cons;
	prod = xnbp->xnb_rx_ring.rsp_prod_pvt;

	while ((mp != NULL) &&
	    XNB_RING_HAS_UNCONSUMED_REQUESTS(&xnbp->xnb_rx_ring)) {
		netif_rx_request_t	*rxreq;
		size_t			d_offset, len;
		int			item_count;
		gnttab_copy_t		*gop_cp;
		netif_rx_response_t	*rxresp;
		uint16_t		cksum_flags;
		int16_t			status = NETIF_RSP_OKAY;

		/* 1 */
		rxreq = RING_GET_REQUEST(&xnbp->xnb_rx_ring, loop);

#ifdef XNB_DEBUG
		if (!(rxreq->id < NET_RX_RING_SIZE))
			cmn_err(CE_PANIC, "xnb_copy_to_peer: "
			    "id %d out of range in request 0x%p",
			    rxreq->id, (void *)rxreq);
#endif /* XNB_DEBUG */

		/* 2 */
		d_offset = 0;
		len = 0;
		item_count = 0;

		gop_cp = xnbp->xnb_rx_cpop;

		/*
		 * We walk the b_cont pointers and set up a
		 * gnttab_copy_t for each sub-page chunk in each data
		 * block.
		 */
		/* 2a */
		for (ml = mp, ml_prev = NULL; ml != NULL; ml = ml->b_cont) {
			size_t	chunk = ml->b_wptr - ml->b_rptr;
			uchar_t	*r_tmp,	*rpt_align;
			size_t	r_offset;

			/*
			 * The hypervisor will not allow us to
			 * reference a foreign page (e.g. one
			 * belonging to another domain) by mfn in the
			 * copy operation. If the data in this mblk is
			 * on such a page we must copy the data into a
			 * local page before initiating the hypervisor
			 * copy operation.
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

				xnbp->xnb_stat_rx_foreign_page++;
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

				if (item_count == xnbp->xnb_rx_cpop_count) {
					if (!grow_cpop_area(xnbp))
						goto failure;
					gop_cp = &xnbp->xnb_rx_cpop[item_count];
				}
				/*
				 * If our mblk crosses a page boundary, we need
				 * to do a seperate copy for each page.
				 */
				if (r_offset + chunk > PAGESIZE) {
					part_len = PAGESIZE - r_offset;

					DTRACE_PROBE3(mblk_page_crossed,
					    (mblk_t *), ml, int, chunk, int,
					    (int)r_offset);

					xnbp->xnb_stat_rx_pagebndry_crossed++;
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
				item_count++;
			}
			ml_prev = ml;

			DTRACE_PROBE4(mblk_loop_end, (mblk_t *), ml, int,
			    chunk, int, len, int, item_count);
		}
		/* 3 */
		if (HYPERVISOR_grant_table_op(GNTTABOP_copy, xnbp->xnb_rx_cpop,
		    item_count) != 0) {
			cmn_err(CE_WARN, "xnb_copy_to_peer: copy op. failed");
			DTRACE_PROBE(HV_granttableopfailed);
		}

		/* 4 */
		rxresp = RING_GET_RESPONSE(&xnbp->xnb_rx_ring, prod);
		rxresp->offset = 0;

		rxresp->flags = 0;

		DTRACE_PROBE4(got_RX_rsp, int, (int)rxresp->id, int,
		    (int)rxresp->offset, int, (int)rxresp->flags, int,
		    (int)rxresp->status);

		cksum_flags = xnbp->xnb_flavour->xf_cksum_to_peer(xnbp, mp);
		if (cksum_flags != 0)
			xnbp->xnb_stat_rx_cksum_deferred++;
		rxresp->flags |= cksum_flags;

		rxresp->id = RING_GET_REQUEST(&xnbp->xnb_rx_ring, prod)->id;
		rxresp->status = len;

		DTRACE_PROBE4(RX_rsp_set, int, (int)rxresp->id, int,
		    (int)rxresp->offset, int, (int)rxresp->flags, int,
		    (int)rxresp->status);

		for (i = 0; i < item_count; i++) {
			if (xnbp->xnb_rx_cpop[i].status != 0) {
				DTRACE_PROBE2(cpop_status_nonnull, int,
				    (int)xnbp->xnb_rx_cpop[i].status,
				    int, i);
				status = NETIF_RSP_ERROR;
			}
		}

		/* 5.2 */
		if (status != NETIF_RSP_OKAY) {
			RING_GET_RESPONSE(&xnbp->xnb_rx_ring, prod)->status =
			    status;
			xnbp->xnb_stat_rx_rsp_notok++;
		} else {
			xnbp->xnb_stat_ipackets++;
			xnbp->xnb_stat_rbytes += len;
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
		mutex_exit(&xnbp->xnb_rx_lock);
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
		xnbp->xnb_stat_rx_notify_sent++;
	} else {
		xnbp->xnb_stat_rx_notify_deferred++;
	}

	if (mp != NULL)
		xnbp->xnb_stat_rx_defer++;

	mutex_exit(&xnbp->xnb_rx_lock);

	/* Free mblk_t structs we have consumed. */
	freemsgchain(free);

	return (mp);
}


static void
xnb_tx_notify_peer(xnb_t *xnbp, boolean_t force)
{
	boolean_t notify;

	ASSERT(MUTEX_HELD(&xnbp->xnb_tx_lock));

	/* LINTED: constant in conditional context */
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&xnbp->xnb_tx_ring, notify);
	if (notify || force) {
		ec_notify_via_evtchn(xnbp->xnb_evtchn);
		xnbp->xnb_stat_tx_notify_sent++;
	} else {
		xnbp->xnb_stat_tx_notify_deferred++;
	}
}

static void
xnb_tx_mark_complete(xnb_t *xnbp, RING_IDX id, int16_t status)
{
	RING_IDX i;
	netif_tx_response_t *txresp;

	ASSERT(MUTEX_HELD(&xnbp->xnb_tx_lock));

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
xnb_txbuf_recycle(xnb_txbuf_t *txp)
{
	xnb_t *xnbp = txp->xt_xnbp;

	kmem_cache_free(xnbp->xnb_tx_buf_cache, txp);

	xnbp->xnb_tx_buf_outstanding--;
}

static int
xnb_txbuf_constructor(void *buf, void *arg, int kmflag)
{
	_NOTE(ARGUNUSED(kmflag));
	xnb_txbuf_t *txp = buf;
	xnb_t *xnbp = arg;
	size_t len;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;

	txp->xt_free_rtn.free_func = xnb_txbuf_recycle;
	txp->xt_free_rtn.free_arg = (caddr_t)txp;
	txp->xt_xnbp = xnbp;
	txp->xt_next = NULL;

	if (ddi_dma_alloc_handle(xnbp->xnb_devinfo, &buf_dma_attr,
	    0, 0, &txp->xt_dma_handle) != DDI_SUCCESS)
		goto failure;

	if (ddi_dma_mem_alloc(txp->xt_dma_handle, PAGESIZE, &data_accattr,
	    DDI_DMA_STREAMING, 0, 0, &txp->xt_buf, &len,
	    &txp->xt_acc_handle) != DDI_SUCCESS)
		goto failure_1;

	if (ddi_dma_addr_bind_handle(txp->xt_dma_handle, NULL, txp->xt_buf,
	    len, DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
	    &dma_cookie, &ncookies)
	    != DDI_DMA_MAPPED)
		goto failure_2;
	ASSERT(ncookies == 1);

	txp->xt_mfn = xnb_btop(dma_cookie.dmac_laddress);
	txp->xt_buflen = dma_cookie.dmac_size;

	DTRACE_PROBE(txbuf_allocated);

	atomic_inc_32(&xnbp->xnb_tx_buf_count);
	xnbp->xnb_tx_buf_outstanding++;

	return (0);

failure_2:
	ddi_dma_mem_free(&txp->xt_acc_handle);

failure_1:
	ddi_dma_free_handle(&txp->xt_dma_handle);

failure:

	return (-1);
}

static void
xnb_txbuf_destructor(void *buf, void *arg)
{
	xnb_txbuf_t *txp = buf;
	xnb_t *xnbp = arg;

	(void) ddi_dma_unbind_handle(txp->xt_dma_handle);
	ddi_dma_mem_free(&txp->xt_acc_handle);
	ddi_dma_free_handle(&txp->xt_dma_handle);

	atomic_dec_32(&xnbp->xnb_tx_buf_count);
}

/*
 * Take packets from the peer and deliver them onward.
 */
static mblk_t *
xnb_from_peer(xnb_t *xnbp)
{
	RING_IDX start, end, loop;
	gnttab_copy_t *cop;
	xnb_txbuf_t **txpp;
	netif_tx_request_t *txreq;
	boolean_t work_to_do, need_notify = B_FALSE;
	mblk_t *head, *tail;
	int n_data_req, i;

	ASSERT(MUTEX_HELD(&xnbp->xnb_tx_lock));

	head = tail = NULL;
around:

	/* LINTED: constant in conditional context */
	RING_FINAL_CHECK_FOR_REQUESTS(&xnbp->xnb_tx_ring, work_to_do);
	if (!work_to_do) {
finished:
		xnb_tx_notify_peer(xnbp, need_notify);

		return (head);
	}

	start = xnbp->xnb_tx_ring.req_cons;
	end = xnbp->xnb_tx_ring.sring->req_prod;

	if ((end - start) > NET_TX_RING_SIZE) {
		/*
		 * This usually indicates that the frontend driver is
		 * misbehaving, as it's not possible to have more than
		 * NET_TX_RING_SIZE ring elements in play at any one
		 * time.
		 *
		 * We reset the ring pointers to the state declared by
		 * the frontend and try to carry on.
		 */
		cmn_err(CE_WARN, "xnb_from_peer: domain %d tried to give us %u "
		    "items in the ring, resetting and trying to recover.",
		    xnbp->xnb_peer, (end - start));

		/* LINTED: constant in conditional context */
		BACK_RING_ATTACH(&xnbp->xnb_tx_ring,
		    (netif_tx_sring_t *)xnbp->xnb_tx_ring_addr, PAGESIZE);

		goto around;
	}

	loop = start;
	cop = xnbp->xnb_tx_cop;
	txpp = xnbp->xnb_tx_bufp;
	n_data_req = 0;

	while (loop < end) {
		static const uint16_t acceptable_flags =
		    NETTXF_csum_blank |
		    NETTXF_data_validated |
		    NETTXF_extra_info;
		uint16_t unexpected_flags;

		txreq = RING_GET_REQUEST(&xnbp->xnb_tx_ring, loop);

		unexpected_flags = txreq->flags & ~acceptable_flags;
		if (unexpected_flags != 0) {
			/*
			 * The peer used flag bits that we do not
			 * recognize.
			 */
			cmn_err(CE_WARN, "xnb_from_peer: "
			    "unexpected flag bits (0x%x) from peer "
			    "in transmit request",
			    unexpected_flags);
			xnbp->xnb_stat_tx_unexpected_flags++;

			/* Mark this entry as failed. */
			xnb_tx_mark_complete(xnbp, txreq->id, NETIF_RSP_ERROR);
			need_notify = B_TRUE;

		} else if (txreq->flags & NETTXF_extra_info) {
			struct netif_extra_info *erp;
			boolean_t status;

			loop++; /* Consume another slot in the ring. */
			ASSERT(loop <= end);

			erp = (struct netif_extra_info *)
			    RING_GET_REQUEST(&xnbp->xnb_tx_ring, loop);

			switch (erp->type) {
			case XEN_NETIF_EXTRA_TYPE_MCAST_ADD:
				ASSERT(xnbp->xnb_multicast_control);
				status = xnbp->xnb_flavour->xf_mcast_add(xnbp,
				    &erp->u.mcast.addr);
				break;
			case XEN_NETIF_EXTRA_TYPE_MCAST_DEL:
				ASSERT(xnbp->xnb_multicast_control);
				status = xnbp->xnb_flavour->xf_mcast_del(xnbp,
				    &erp->u.mcast.addr);
				break;
			default:
				status = B_FALSE;
				cmn_err(CE_WARN, "xnb_from_peer: "
				    "unknown extra type %d", erp->type);
				break;
			}

			xnb_tx_mark_complete(xnbp, txreq->id,
			    status ? NETIF_RSP_OKAY : NETIF_RSP_ERROR);
			need_notify = B_TRUE;

		} else if ((txreq->offset > PAGESIZE) ||
		    (txreq->offset + txreq->size > PAGESIZE)) {
			/*
			 * Peer attempted to refer to data beyond the
			 * end of the granted page.
			 */
			cmn_err(CE_WARN, "xnb_from_peer: "
			    "attempt to refer beyond the end of granted "
			    "page in txreq (offset %d, size %d).",
			    txreq->offset, txreq->size);
			xnbp->xnb_stat_tx_overflow_page++;

			/* Mark this entry as failed. */
			xnb_tx_mark_complete(xnbp, txreq->id, NETIF_RSP_ERROR);
			need_notify = B_TRUE;

		} else {
			xnb_txbuf_t *txp;

			txp = kmem_cache_alloc(xnbp->xnb_tx_buf_cache,
			    KM_NOSLEEP);
			if (txp == NULL)
				break;

			txp->xt_mblk = desballoc((unsigned char *)txp->xt_buf,
			    txp->xt_buflen, 0, &txp->xt_free_rtn);
			if (txp->xt_mblk == NULL) {
				kmem_cache_free(xnbp->xnb_tx_buf_cache, txp);
				break;
			}

			txp->xt_idx = loop;
			txp->xt_id = txreq->id;

			cop->source.u.ref = txreq->gref;
			cop->source.domid = xnbp->xnb_peer;
			cop->source.offset = txreq->offset;

			cop->dest.u.gmfn = txp->xt_mfn;
			cop->dest.domid = DOMID_SELF;
			cop->dest.offset = 0;

			cop->len = txreq->size;
			cop->flags = GNTCOPY_source_gref;
			cop->status = 0;

			*txpp = txp;

			txpp++;
			cop++;
			n_data_req++;

			ASSERT(n_data_req <= NET_TX_RING_SIZE);
		}

		loop++;
	}

	xnbp->xnb_tx_ring.req_cons = loop;

	if (n_data_req == 0)
		goto around;

	if (HYPERVISOR_grant_table_op(GNTTABOP_copy,
	    xnbp->xnb_tx_cop, n_data_req) != 0) {

		cmn_err(CE_WARN, "xnb_from_peer: copy operation failed");

		txpp = xnbp->xnb_tx_bufp;
		i = n_data_req;
		while (i > 0) {
			kmem_cache_free(xnbp->xnb_tx_buf_cache, *txpp);
			txpp++;
			i--;
		}

		goto finished;
	}

	txpp = xnbp->xnb_tx_bufp;
	cop = xnbp->xnb_tx_cop;
	i = n_data_req;

	while (i > 0) {
		xnb_txbuf_t *txp = *txpp;

		txreq = RING_GET_REQUEST(&xnbp->xnb_tx_ring, txp->xt_idx);

		if (cop->status != 0) {
#ifdef XNB_DEBUG
			cmn_err(CE_WARN, "xnb_from_peer: "
			    "txpp 0x%p failed (%d)",
			    (void *)*txpp, cop->status);
#endif /* XNB_DEBUG */
			xnb_tx_mark_complete(xnbp, txp->xt_id, NETIF_RSP_ERROR);
			freemsg(txp->xt_mblk);
		} else {
			mblk_t *mp;

			mp = txp->xt_mblk;
			mp->b_rptr = mp->b_wptr = (unsigned char *)txp->xt_buf;
			mp->b_wptr += txreq->size;
			mp->b_next = NULL;

			/*
			 * If there are checksum flags, process them
			 * appropriately.
			 */
			if ((txreq->flags &
			    (NETTXF_csum_blank | NETTXF_data_validated))
			    != 0) {
				mp = xnbp->xnb_flavour->xf_cksum_from_peer(xnbp,
				    mp, txreq->flags);
				xnbp->xnb_stat_tx_cksum_no_need++;

				txp->xt_mblk = mp;
			}

			if (head == NULL) {
				ASSERT(tail == NULL);
				head = mp;
			} else {
				ASSERT(tail != NULL);
				tail->b_next = mp;
			}
			tail = mp;

			xnbp->xnb_stat_opackets++;
			xnbp->xnb_stat_obytes += txreq->size;

			xnb_tx_mark_complete(xnbp, txp->xt_id, NETIF_RSP_OKAY);
		}

		txpp++;
		cop++;
		i--;
	}

	goto around;
	/* NOTREACHED */
}

static uint_t
xnb_intr(caddr_t arg)
{
	xnb_t *xnbp = (xnb_t *)arg;
	mblk_t *mp;

	xnbp->xnb_stat_intr++;

	mutex_enter(&xnbp->xnb_tx_lock);

	ASSERT(xnbp->xnb_connected);

	mp = xnb_from_peer(xnbp);

	mutex_exit(&xnbp->xnb_tx_lock);

	if (!xnbp->xnb_hotplugged) {
		xnbp->xnb_stat_tx_too_early++;
		goto fail;
	}
	if (mp == NULL) {
		xnbp->xnb_stat_spurious_intr++;
		goto fail;
	}

	xnbp->xnb_flavour->xf_from_peer(xnbp, mp);

	return (DDI_INTR_CLAIMED);

fail:
	freemsgchain(mp);
	return (DDI_INTR_CLAIMED);
}

/*
 * Read our configuration from xenstore.
 */
boolean_t
xnb_read_xs_config(xnb_t *xnbp)
{
	char *xsname;
	char mac[ETHERADDRL * 3];

	xsname = xvdi_get_xsname(xnbp->xnb_devinfo);

	if (xenbus_scanf(XBT_NULL, xsname,
	    "mac", "%s", mac) != 0) {
		cmn_err(CE_WARN, "xnb_attach: "
		    "cannot read mac address from %s",
		    xsname);
		return (B_FALSE);
	}

	if (ether_aton(mac, xnbp->xnb_mac_addr) != ETHERADDRL) {
		cmn_err(CE_WARN,
		    "xnb_attach: cannot parse mac address %s",
		    mac);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Read the configuration of the peer from xenstore.
 */
boolean_t
xnb_read_oe_config(xnb_t *xnbp)
{
	char *oename;
	int i;

	oename = xvdi_get_oename(xnbp->xnb_devinfo);

	if (xenbus_gather(XBT_NULL, oename,
	    "event-channel", "%u", &xnbp->xnb_fe_evtchn,
	    "tx-ring-ref", "%lu", &xnbp->xnb_tx_ring_ref,
	    "rx-ring-ref", "%lu", &xnbp->xnb_rx_ring_ref,
	    NULL) != 0) {
		cmn_err(CE_WARN, "xnb_read_oe_config: "
		    "cannot read other-end details from %s",
		    oename);
		return (B_FALSE);
	}

	/*
	 * Check whether our peer requests receive side hypervisor
	 * copy.
	 */
	if (xenbus_scanf(XBT_NULL, oename,
	    "request-rx-copy", "%d", &i) != 0)
		i = 0;
	if (i != 0)
		xnbp->xnb_rx_hv_copy = B_TRUE;

	/*
	 * Check whether our peer requests multicast_control.
	 */
	if (xenbus_scanf(XBT_NULL, oename,
	    "request-multicast-control", "%d", &i) != 0)
		i = 0;
	if (i != 0)
		xnbp->xnb_multicast_control = B_TRUE;

	/*
	 * The Linux backend driver here checks to see if the peer has
	 * set 'feature-no-csum-offload'. This is used to indicate
	 * that the guest cannot handle receiving packets without a
	 * valid checksum. We don't check here, because packets passed
	 * to the peer _always_ have a valid checksum.
	 *
	 * There are three cases:
	 *
	 * - the NIC is dedicated: packets from the wire should always
	 *   have a valid checksum. If the hardware validates the
	 *   checksum then the relevant bit will be set in the packet
	 *   attributes and we will inform the peer. It can choose to
	 *   ignore the hardware verification.
	 *
	 * - the NIC is shared (VNIC) and a packet originates from the
	 *   wire: this is the same as the case above - the packets
	 *   will have a valid checksum.
	 *
	 * - the NIC is shared (VNIC) and a packet originates from the
	 *   host: the MAC layer ensures that all such packets have a
	 *   valid checksum by calculating one if the stack did not.
	 */

	return (B_TRUE);
}

void
xnb_start_connect(xnb_t *xnbp)
{
	dev_info_t  *dip = xnbp->xnb_devinfo;

	if (!xnb_connect_rings(dip)) {
		cmn_err(CE_WARN, "xnb_start_connect: "
		    "cannot connect rings");
		goto failed;
	}

	if (!xnbp->xnb_flavour->xf_start_connect(xnbp)) {
		cmn_err(CE_WARN, "xnb_start_connect: "
		    "flavour failed to connect");
		goto failed;
	}

	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateConnected);
	return;

failed:
	xnbp->xnb_flavour->xf_peer_disconnected(xnbp);
	xnb_disconnect_rings(dip);
	(void) xvdi_switch_state(dip, XBT_NULL,
	    XenbusStateClosed);
	(void) xvdi_post_event(dip, XEN_HP_REMOVE);
}

static boolean_t
xnb_connect_rings(dev_info_t *dip)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);
	struct gnttab_map_grant_ref map_op;

	/*
	 * Cannot attempt to connect the rings if already connected.
	 */
	ASSERT(!xnbp->xnb_connected);

	/*
	 * 1. allocate a vaddr for the tx page, one for the rx page.
	 * 2. call GNTTABOP_map_grant_ref to map the relevant pages
	 *    into the allocated vaddr (one for tx, one for rx).
	 * 3. call EVTCHNOP_bind_interdomain to have the event channel
	 *    bound to this domain.
	 * 4. associate the event channel with an interrupt.
	 * 5. enable the interrupt.
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
	hat_prepare_mapping(kas.a_hat, xnbp->xnb_tx_ring_addr, NULL);
	if (xen_map_gref(GNTTABOP_map_grant_ref, &map_op, 1, B_FALSE) != 0 ||
	    map_op.status != 0) {
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
	hat_prepare_mapping(kas.a_hat, xnbp->xnb_rx_ring_addr, NULL);
	if (xen_map_gref(GNTTABOP_map_grant_ref, &map_op, 1, B_FALSE) != 0 ||
	    map_op.status != 0) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot map rx-ring page.");
		goto fail;
	}
	xnbp->xnb_rx_ring_handle = map_op.handle;

	/* LINTED: constant in conditional context */
	BACK_RING_INIT(&xnbp->xnb_rx_ring,
	    (netif_rx_sring_t *)xnbp->xnb_rx_ring_addr, PAGESIZE);

	/* 3 */
	if (xvdi_bind_evtchn(dip, xnbp->xnb_fe_evtchn) != DDI_SUCCESS) {
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

	xnbp->xnb_connected = B_TRUE;

	mutex_exit(&xnbp->xnb_rx_lock);
	mutex_exit(&xnbp->xnb_tx_lock);

	/* 4, 5 */
	if (ddi_add_intr(dip, 0, NULL, NULL, xnb_intr, (caddr_t)xnbp)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xnb_connect_rings: cannot add interrupt");
		goto fail;
	}
	xnbp->xnb_irq = B_TRUE;

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

static void
xnb_oe_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data)
{
	_NOTE(ARGUNUSED(id, arg));
	xnb_t *xnbp = ddi_get_driver_private(dip);
	XenbusState new_state = *(XenbusState *)impl_data;

	ASSERT(xnbp != NULL);

	switch (new_state) {
	case XenbusStateConnected:
		/* spurious state change */
		if (xnbp->xnb_connected)
			return;

		if (!xnb_read_oe_config(xnbp) ||
		    !xnbp->xnb_flavour->xf_peer_connected(xnbp)) {
			cmn_err(CE_WARN, "xnb_oe_state_change: "
			    "read otherend config error");
			(void) xvdi_switch_state(dip, XBT_NULL,
			    XenbusStateClosed);
			(void) xvdi_post_event(dip, XEN_HP_REMOVE);

			break;
		}


		mutex_enter(&xnbp->xnb_state_lock);
		xnbp->xnb_fe_status = XNB_STATE_READY;
		if (xnbp->xnb_be_status == XNB_STATE_READY)
			xnb_start_connect(xnbp);
		mutex_exit(&xnbp->xnb_state_lock);

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

static void
xnb_hp_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data)
{
	_NOTE(ARGUNUSED(id, arg));
	xnb_t *xnbp = ddi_get_driver_private(dip);
	xendev_hotplug_state_t state = *(xendev_hotplug_state_t *)impl_data;

	ASSERT(xnbp != NULL);

	switch (state) {
	case Connected:
		/* spurious hotplug event */
		if (xnbp->xnb_hotplugged)
			break;

		if (!xnb_read_xs_config(xnbp))
			break;

		if (!xnbp->xnb_flavour->xf_hotplug_connected(xnbp))
			break;

		mutex_enter(&xnbp->xnb_tx_lock);
		mutex_enter(&xnbp->xnb_rx_lock);

		xnbp->xnb_hotplugged = B_TRUE;

		mutex_exit(&xnbp->xnb_rx_lock);
		mutex_exit(&xnbp->xnb_tx_lock);

		mutex_enter(&xnbp->xnb_state_lock);
		xnbp->xnb_be_status = XNB_STATE_READY;
		if (xnbp->xnb_fe_status == XNB_STATE_READY)
			xnb_start_connect(xnbp);
		mutex_exit(&xnbp->xnb_state_lock);

		break;

	default:
		break;
	}
}

static struct modldrv modldrv = {
	&mod_miscops, "xnb",
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int i;

	mutex_init(&xnb_alloc_page_lock, NULL, MUTEX_DRIVER, NULL);

	i = mod_install(&modlinkage);
	if (i != DDI_SUCCESS)
		mutex_destroy(&xnb_alloc_page_lock);

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
	if (i == DDI_SUCCESS)
		mutex_destroy(&xnb_alloc_page_lock);

	return (i);
}

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

/*
 *
 * Copyright (c) 2004 Christian Limpach.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. This section intentionally left blank.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Section 3 of the above license was updated in response to bug 6379571.
 */

/*
 * xnf.c - GLDv3 network driver for domU.
 */

/*
 * This driver uses four per-instance locks:
 *
 * xnf_gref_lock:
 *
 *    Protects access to the grant reference list stored in
 *    xnf_gref_head. Grant references should be acquired and released
 *    using gref_get() and gref_put() respectively.
 *
 * xnf_schedlock:
 *
 *    Protects:
 *    xnf_need_sched - used to record that a previous transmit attempt
 *       failed (and consequently it will be necessary to call
 *       mac_tx_update() when transmit resources are available).
 *    xnf_pending_multicast - the number of multicast requests that
 *       have been submitted to the backend for which we have not
 *       processed responses.
 *
 * xnf_txlock:
 *
 *    Protects the transmit ring (xnf_tx_ring) and associated
 *    structures (notably xnf_tx_pkt_id and xnf_tx_pkt_id_head).
 *
 * xnf_rxlock:
 *
 *    Protects the receive ring (xnf_rx_ring) and associated
 *    structures (notably xnf_rx_pkt_info).
 *
 * If driver-global state that affects both the transmit and receive
 * rings is manipulated, both xnf_txlock and xnf_rxlock should be
 * held, in that order.
 *
 * xnf_schedlock is acquired both whilst holding xnf_txlock and
 * without. It should always be acquired after xnf_txlock if both are
 * held.
 *
 * Notes:
 * - atomic_add_64() is used to manipulate counters where we require
 *   accuracy. For counters intended only for observation by humans,
 *   post increment/decrement are used instead.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <sys/gld.h>
#include <sys/modctl.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/bootinfo.h>
#include <sys/mach_mmu.h>
#ifdef	XPV_HVM_DRIVER
#include <sys/xpv_support.h>
#include <sys/hypervisor.h>
#else
#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#include <sys/balloon_impl.h>
#endif
#include <xen/public/io/netif.h>
#include <sys/gnttab.h>
#include <xen/sys/xendev.h>
#include <sys/sdt.h>
#include <sys/note.h>
#include <sys/debug.h>

#include <io/xnf.h>

#if defined(DEBUG) || defined(__lint)
#define	XNF_DEBUG
#endif

#ifdef XNF_DEBUG
int xnf_debug = 0;
xnf_t *xnf_debug_instance = NULL;
#endif

/*
 * On a 32 bit PAE system physical and machine addresses are larger
 * than 32 bits.  ddi_btop() on such systems take an unsigned long
 * argument, and so addresses above 4G are truncated before ddi_btop()
 * gets to see them.  To avoid this, code the shift operation here.
 */
#define	xnf_btop(addr)	((addr) >> PAGESHIFT)

unsigned int	xnf_max_tx_frags = 1;

/*
 * Should we use the multicast control feature if the backend provides
 * it?
 */
boolean_t xnf_multicast_control = B_TRUE;

/*
 * Received packets below this size are copied to a new streams buffer
 * rather than being desballoc'ed.
 *
 * This value is chosen to accommodate traffic where there are a large
 * number of small packets. For data showing a typical distribution,
 * see:
 *
 * Sinha07a:
 *	Rishi Sinha, Christos Papadopoulos, and John
 *	Heidemann. Internet Packet Size Distributions: Some
 *	Observations. Technical Report ISI-TR-2007-643,
 *	USC/Information Sciences Institute, May, 2007. Orignally
 *	released October 2005 as web page
 *	http://netweb.usc.edu/~sinha/pkt-sizes/.
 *	<http://www.isi.edu/~johnh/PAPERS/Sinha07a.html>.
 */
size_t xnf_rx_copy_limit = 64;

#define	INVALID_GRANT_HANDLE	((grant_handle_t)-1)
#define	INVALID_GRANT_REF	((grant_ref_t)-1)
#define	INVALID_TX_ID		((uint16_t)-1)

#define	TX_ID_TO_TXID(p, id) (&((p)->xnf_tx_pkt_id[(id)]))
#define	TX_ID_VALID(i) (((i) != INVALID_TX_ID) && ((i) < NET_TX_RING_SIZE))

/* Required system entry points */
static int	xnf_attach(dev_info_t *, ddi_attach_cmd_t);
static int	xnf_detach(dev_info_t *, ddi_detach_cmd_t);

/* Required driver entry points for Nemo */
static int	xnf_start(void *);
static void	xnf_stop(void *);
static int	xnf_set_mac_addr(void *, const uint8_t *);
static int	xnf_set_multicast(void *, boolean_t, const uint8_t *);
static int	xnf_set_promiscuous(void *, boolean_t);
static mblk_t	*xnf_send(void *, mblk_t *);
static uint_t	xnf_intr(caddr_t);
static int	xnf_stat(void *, uint_t, uint64_t *);
static boolean_t xnf_getcapab(void *, mac_capab_t, void *);

/* Driver private functions */
static int xnf_alloc_dma_resources(xnf_t *);
static void xnf_release_dma_resources(xnf_t *);
static void xnf_release_mblks(xnf_t *);

static int xnf_buf_constructor(void *, void *, int);
static void xnf_buf_destructor(void *, void *);
static xnf_buf_t *xnf_buf_get(xnf_t *, int, boolean_t);
#pragma inline(xnf_buf_get)
static void xnf_buf_put(xnf_t *, xnf_buf_t *, boolean_t);
#pragma inline(xnf_buf_put)
static void xnf_buf_refresh(xnf_buf_t *);
#pragma inline(xnf_buf_refresh)
static void xnf_buf_recycle(xnf_buf_t *);

static int xnf_tx_buf_constructor(void *, void *, int);
static void xnf_tx_buf_destructor(void *, void *);

static grant_ref_t gref_get(xnf_t *);
#pragma inline(gref_get)
static void gref_put(xnf_t *, grant_ref_t);
#pragma inline(gref_put)

static xnf_txid_t *txid_get(xnf_t *);
#pragma inline(txid_get)
static void txid_put(xnf_t *, xnf_txid_t *);
#pragma inline(txid_put)

void xnf_send_driver_status(int, int);
static void xnf_rxbuf_hang(xnf_t *, xnf_buf_t *);
static int xnf_tx_clean_ring(xnf_t  *);
static void oe_state_change(dev_info_t *, ddi_eventcookie_t,
    void *, void *);
static boolean_t xnf_kstat_init(xnf_t *);
static void xnf_rx_collect(xnf_t *);

static mac_callbacks_t xnf_callbacks = {
	MC_GETCAPAB,
	xnf_stat,
	xnf_start,
	xnf_stop,
	xnf_set_promiscuous,
	xnf_set_multicast,
	xnf_set_mac_addr,
	xnf_send,
	NULL,
	NULL,
	xnf_getcapab
};

/* DMA attributes for network ring buffer */
static ddi_dma_attr_t ringbuf_dma_attr = {
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

/* DMA access attributes for registers and descriptors */
static ddi_device_acc_attr_t accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,	/* This is a little-endian device */
	DDI_STRICTORDER_ACC
};

/* DMA access attributes for data: NOT to be byte swapped. */
static ddi_device_acc_attr_t data_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

DDI_DEFINE_STREAM_OPS(xnf_dev_ops, nulldev, nulldev, xnf_attach, xnf_detach,
    nodev, NULL, D_MP, NULL, ddi_quiesce_not_supported);

static struct modldrv xnf_modldrv = {
	&mod_driverops,
	"Virtual Ethernet driver",
	&xnf_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &xnf_modldrv, NULL
};

int
_init(void)
{
	int r;

	mac_init_ops(&xnf_dev_ops, "xnf");
	r = mod_install(&modlinkage);
	if (r != DDI_SUCCESS)
		mac_fini_ops(&xnf_dev_ops);

	return (r);
}

int
_fini(void)
{
	return (EBUSY); /* XXPV should be removable */
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Acquire a grant reference.
 */
static grant_ref_t
gref_get(xnf_t *xnfp)
{
	grant_ref_t gref;

	mutex_enter(&xnfp->xnf_gref_lock);

	do {
		gref = gnttab_claim_grant_reference(&xnfp->xnf_gref_head);

	} while ((gref == INVALID_GRANT_REF) &&
	    (gnttab_alloc_grant_references(16, &xnfp->xnf_gref_head) == 0));

	mutex_exit(&xnfp->xnf_gref_lock);

	if (gref == INVALID_GRANT_REF) {
		xnfp->xnf_stat_gref_failure++;
	} else {
		atomic_inc_64(&xnfp->xnf_stat_gref_outstanding);
		if (xnfp->xnf_stat_gref_outstanding > xnfp->xnf_stat_gref_peak)
			xnfp->xnf_stat_gref_peak =
			    xnfp->xnf_stat_gref_outstanding;
	}

	return (gref);
}

/*
 * Release a grant reference.
 */
static void
gref_put(xnf_t *xnfp, grant_ref_t gref)
{
	ASSERT(gref != INVALID_GRANT_REF);

	mutex_enter(&xnfp->xnf_gref_lock);
	gnttab_release_grant_reference(&xnfp->xnf_gref_head, gref);
	mutex_exit(&xnfp->xnf_gref_lock);

	atomic_dec_64(&xnfp->xnf_stat_gref_outstanding);
}

/*
 * Acquire a transmit id.
 */
static xnf_txid_t *
txid_get(xnf_t *xnfp)
{
	xnf_txid_t *tidp;

	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));

	if (xnfp->xnf_tx_pkt_id_head == INVALID_TX_ID)
		return (NULL);

	ASSERT(TX_ID_VALID(xnfp->xnf_tx_pkt_id_head));

	tidp = TX_ID_TO_TXID(xnfp, xnfp->xnf_tx_pkt_id_head);
	xnfp->xnf_tx_pkt_id_head = tidp->next;
	tidp->next = INVALID_TX_ID;

	ASSERT(tidp->txbuf == NULL);

	return (tidp);
}

/*
 * Release a transmit id.
 */
static void
txid_put(xnf_t *xnfp, xnf_txid_t *tidp)
{
	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));
	ASSERT(TX_ID_VALID(tidp->id));
	ASSERT(tidp->next == INVALID_TX_ID);

	tidp->txbuf = NULL;
	tidp->next = xnfp->xnf_tx_pkt_id_head;
	xnfp->xnf_tx_pkt_id_head = tidp->id;
}

/*
 * Get `wanted' slots in the transmit ring, waiting for at least that
 * number if `wait' is B_TRUE. Force the ring to be cleaned by setting
 * `wanted' to zero.
 *
 * Return the number of slots available.
 */
static int
tx_slots_get(xnf_t *xnfp, int wanted, boolean_t wait)
{
	int slotsfree;
	boolean_t forced_clean = (wanted == 0);

	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));

	/* LINTED: constant in conditional context */
	while (B_TRUE) {
		slotsfree = RING_FREE_REQUESTS(&xnfp->xnf_tx_ring);

		if ((slotsfree < wanted) || forced_clean)
			slotsfree = xnf_tx_clean_ring(xnfp);

		/*
		 * If there are more than we need free, tell other
		 * people to come looking again. We hold txlock, so we
		 * are able to take our slots before anyone else runs.
		 */
		if (slotsfree > wanted)
			cv_broadcast(&xnfp->xnf_cv_tx_slots);

		if (slotsfree >= wanted)
			break;

		if (!wait)
			break;

		cv_wait(&xnfp->xnf_cv_tx_slots, &xnfp->xnf_txlock);
	}

	ASSERT(slotsfree <= RING_SIZE(&(xnfp->xnf_tx_ring)));

	return (slotsfree);
}

static int
xnf_setup_rings(xnf_t *xnfp)
{
	domid_t			oeid;
	struct xenbus_device	*xsd;
	RING_IDX		i;
	int			err;
	xnf_txid_t		*tidp;
	xnf_buf_t **bdescp;

	oeid = xvdi_get_oeid(xnfp->xnf_devinfo);
	xsd = xvdi_get_xsd(xnfp->xnf_devinfo);

	if (xnfp->xnf_tx_ring_ref != INVALID_GRANT_REF)
		gnttab_end_foreign_access(xnfp->xnf_tx_ring_ref, 0, 0);

	err = gnttab_grant_foreign_access(oeid,
	    xnf_btop(pa_to_ma(xnfp->xnf_tx_ring_phys_addr)), 0);
	if (err <= 0) {
		err = -err;
		xenbus_dev_error(xsd, err, "granting access to tx ring page");
		goto out;
	}
	xnfp->xnf_tx_ring_ref = (grant_ref_t)err;

	if (xnfp->xnf_rx_ring_ref != INVALID_GRANT_REF)
		gnttab_end_foreign_access(xnfp->xnf_rx_ring_ref, 0, 0);

	err = gnttab_grant_foreign_access(oeid,
	    xnf_btop(pa_to_ma(xnfp->xnf_rx_ring_phys_addr)), 0);
	if (err <= 0) {
		err = -err;
		xenbus_dev_error(xsd, err, "granting access to rx ring page");
		goto out;
	}
	xnfp->xnf_rx_ring_ref = (grant_ref_t)err;

	mutex_enter(&xnfp->xnf_txlock);

	/*
	 * Setup/cleanup the TX ring.  Note that this can lose packets
	 * after a resume, but we expect to stagger on.
	 */
	xnfp->xnf_tx_pkt_id_head = INVALID_TX_ID; /* I.e. emtpy list. */
	for (i = 0, tidp = &xnfp->xnf_tx_pkt_id[0];
	    i < NET_TX_RING_SIZE;
	    i++, tidp++) {
		xnf_txbuf_t *txp;

		tidp->id = i;

		txp = tidp->txbuf;
		if (txp == NULL) {
			tidp->next = INVALID_TX_ID; /* Appease txid_put(). */
			txid_put(xnfp, tidp);
			continue;
		}

		ASSERT(txp->tx_txreq.gref != INVALID_GRANT_REF);
		ASSERT(txp->tx_mp != NULL);

		switch (txp->tx_type) {
		case TX_DATA:
			VERIFY(gnttab_query_foreign_access(txp->tx_txreq.gref)
			    == 0);

			if (txp->tx_bdesc == NULL) {
				(void) gnttab_end_foreign_access_ref(
				    txp->tx_txreq.gref, 1);
				gref_put(xnfp, txp->tx_txreq.gref);
				(void) ddi_dma_unbind_handle(
				    txp->tx_dma_handle);
			} else {
				xnf_buf_put(xnfp, txp->tx_bdesc, B_TRUE);
			}

			freemsg(txp->tx_mp);
			txid_put(xnfp, tidp);
			kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);

			break;

		case TX_MCAST_REQ:
			txp->tx_type = TX_MCAST_RSP;
			txp->tx_status = NETIF_RSP_DROPPED;
			cv_broadcast(&xnfp->xnf_cv_multicast);

			/*
			 * The request consumed two slots in the ring,
			 * yet only a single xnf_txid_t is used. Step
			 * over the empty slot.
			 */
			i++;
			ASSERT(i < NET_TX_RING_SIZE);

			break;

		case TX_MCAST_RSP:
			break;
		}
	}

	/* LINTED: constant in conditional context */
	SHARED_RING_INIT(xnfp->xnf_tx_ring.sring);
	/* LINTED: constant in conditional context */
	FRONT_RING_INIT(&xnfp->xnf_tx_ring,
	    xnfp->xnf_tx_ring.sring, PAGESIZE);

	mutex_exit(&xnfp->xnf_txlock);

	mutex_enter(&xnfp->xnf_rxlock);

	/*
	 * Clean out any buffers currently posted to the receive ring
	 * before we reset it.
	 */
	for (i = 0, bdescp = &xnfp->xnf_rx_pkt_info[0];
	    i < NET_RX_RING_SIZE;
	    i++, bdescp++) {
		if (*bdescp != NULL) {
			xnf_buf_put(xnfp, *bdescp, B_FALSE);
			*bdescp = NULL;
		}
	}

	/* LINTED: constant in conditional context */
	SHARED_RING_INIT(xnfp->xnf_rx_ring.sring);
	/* LINTED: constant in conditional context */
	FRONT_RING_INIT(&xnfp->xnf_rx_ring,
	    xnfp->xnf_rx_ring.sring, PAGESIZE);

	/*
	 * Fill the ring with buffers.
	 */
	for (i = 0; i < NET_RX_RING_SIZE; i++) {
		xnf_buf_t *bdesc;

		bdesc = xnf_buf_get(xnfp, KM_SLEEP, B_FALSE);
		VERIFY(bdesc != NULL);
		xnf_rxbuf_hang(xnfp, bdesc);
	}

	/* LINTED: constant in conditional context */
	RING_PUSH_REQUESTS(&xnfp->xnf_rx_ring);

	mutex_exit(&xnfp->xnf_rxlock);

	return (0);

out:
	if (xnfp->xnf_tx_ring_ref != INVALID_GRANT_REF)
		gnttab_end_foreign_access(xnfp->xnf_tx_ring_ref, 0, 0);
	xnfp->xnf_tx_ring_ref = INVALID_GRANT_REF;

	if (xnfp->xnf_rx_ring_ref != INVALID_GRANT_REF)
		gnttab_end_foreign_access(xnfp->xnf_rx_ring_ref, 0, 0);
	xnfp->xnf_rx_ring_ref = INVALID_GRANT_REF;

	return (err);
}

/*
 * Connect driver to back end, called to set up communication with
 * back end driver both initially and on resume after restore/migrate.
 */
void
xnf_be_connect(xnf_t *xnfp)
{
	const char	*message;
	xenbus_transaction_t xbt;
	struct		xenbus_device *xsd;
	char		*xsname;
	int		err;

	ASSERT(!xnfp->xnf_connected);

	xsd = xvdi_get_xsd(xnfp->xnf_devinfo);
	xsname = xvdi_get_xsname(xnfp->xnf_devinfo);

	err = xnf_setup_rings(xnfp);
	if (err != 0) {
		cmn_err(CE_WARN, "failed to set up tx/rx rings");
		xenbus_dev_error(xsd, err, "setting up ring");
		return;
	}

again:
	err = xenbus_transaction_start(&xbt);
	if (err != 0) {
		xenbus_dev_error(xsd, EIO, "starting transaction");
		return;
	}

	err = xenbus_printf(xbt, xsname, "tx-ring-ref", "%u",
	    xnfp->xnf_tx_ring_ref);
	if (err != 0) {
		message = "writing tx ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "rx-ring-ref", "%u",
	    xnfp->xnf_rx_ring_ref);
	if (err != 0) {
		message = "writing rx ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "event-channel", "%u",
	    xnfp->xnf_evtchn);
	if (err != 0) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "feature-rx-notify", "%d", 1);
	if (err != 0) {
		message = "writing feature-rx-notify";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "request-rx-copy", "%d", 1);
	if (err != 0) {
		message = "writing request-rx-copy";
		goto abort_transaction;
	}

	if (xnfp->xnf_be_mcast_control) {
		err = xenbus_printf(xbt, xsname, "request-multicast-control",
		    "%d", 1);
		if (err != 0) {
			message = "writing request-multicast-control";
			goto abort_transaction;
		}
	}

	err = xvdi_switch_state(xnfp->xnf_devinfo, xbt, XenbusStateConnected);
	if (err != 0) {
		message = "switching state to XenbusStateConnected";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err != 0) {
		if (err == EAGAIN)
			goto again;
		xenbus_dev_error(xsd, err, "completing transaction");
	}

	return;

abort_transaction:
	(void) xenbus_transaction_end(xbt, 1);
	xenbus_dev_error(xsd, err, "%s", message);
}

/*
 * Read configuration information from xenstore.
 */
void
xnf_read_config(xnf_t *xnfp)
{
	int err, be_cap;
	char mac[ETHERADDRL * 3];
	char *oename = xvdi_get_oename(xnfp->xnf_devinfo);

	err = xenbus_scanf(XBT_NULL, oename, "mac",
	    "%s", (char *)&mac[0]);
	if (err != 0) {
		/*
		 * bad: we're supposed to be set up with a proper mac
		 * addr. at this point
		 */
		cmn_err(CE_WARN, "%s%d: no mac address",
		    ddi_driver_name(xnfp->xnf_devinfo),
		    ddi_get_instance(xnfp->xnf_devinfo));
			return;
	}
	if (ether_aton(mac, xnfp->xnf_mac_addr) != ETHERADDRL) {
		err = ENOENT;
		xenbus_dev_error(xvdi_get_xsd(xnfp->xnf_devinfo), ENOENT,
		    "parsing %s/mac", xvdi_get_xsname(xnfp->xnf_devinfo));
		return;
	}

	err = xenbus_scanf(XBT_NULL, oename,
	    "feature-rx-copy", "%d", &be_cap);
	/*
	 * If we fail to read the store we assume that the key is
	 * absent, implying an older domain at the far end.  Older
	 * domains cannot do HV copy.
	 */
	if (err != 0)
		be_cap = 0;
	xnfp->xnf_be_rx_copy = (be_cap != 0);

	err = xenbus_scanf(XBT_NULL, oename,
	    "feature-multicast-control", "%d", &be_cap);
	/*
	 * If we fail to read the store we assume that the key is
	 * absent, implying an older domain at the far end.  Older
	 * domains do not support multicast control.
	 */
	if (err != 0)
		be_cap = 0;
	xnfp->xnf_be_mcast_control = (be_cap != 0) && xnf_multicast_control;
}

/*
 *  attach(9E) -- Attach a device to the system
 */
static int
xnf_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	mac_register_t *macp;
	xnf_t *xnfp;
	int err;
	char cachename[32];

#ifdef XNF_DEBUG
	if (xnf_debug & XNF_DEBUG_DDI)
		printf("xnf%d: attach(0x%p)\n", ddi_get_instance(devinfo),
		    (void *)devinfo);
#endif

	switch (cmd) {
	case DDI_RESUME:
		xnfp = ddi_get_driver_private(devinfo);
		xnfp->xnf_gen++;

		(void) xvdi_resume(devinfo);
		(void) xvdi_alloc_evtchn(devinfo);
		xnfp->xnf_evtchn = xvdi_get_evtchn(devinfo);
#ifdef XPV_HVM_DRIVER
		ec_bind_evtchn_to_handler(xnfp->xnf_evtchn, IPL_VIF, xnf_intr,
		    xnfp);
#else
		(void) ddi_add_intr(devinfo, 0, NULL, NULL, xnf_intr,
		    (caddr_t)xnfp);
#endif
		return (DDI_SUCCESS);

	case DDI_ATTACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	/*
	 *  Allocate gld_mac_info_t and xnf_instance structures
	 */
	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL)
		return (DDI_FAILURE);
	xnfp = kmem_zalloc(sizeof (*xnfp), KM_SLEEP);

	macp->m_dip = devinfo;
	macp->m_driver = xnfp;
	xnfp->xnf_devinfo = devinfo;

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_src_addr = xnfp->xnf_mac_addr;
	macp->m_callbacks = &xnf_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = XNF_MAXPKT;

	xnfp->xnf_running = B_FALSE;
	xnfp->xnf_connected = B_FALSE;
	xnfp->xnf_be_rx_copy = B_FALSE;
	xnfp->xnf_be_mcast_control = B_FALSE;
	xnfp->xnf_need_sched = B_FALSE;

	xnfp->xnf_rx_head = NULL;
	xnfp->xnf_rx_tail = NULL;
	xnfp->xnf_rx_new_buffers_posted = B_FALSE;

#ifdef XPV_HVM_DRIVER
	/*
	 * Report our version to dom0.
	 */
	if (xenbus_printf(XBT_NULL, "guest/xnf", "version", "%d",
	    HVMPV_XNF_VERS))
		cmn_err(CE_WARN, "xnf: couldn't write version\n");
#endif

	/*
	 * Get the iblock cookie with which to initialize the mutexes.
	 */
	if (ddi_get_iblock_cookie(devinfo, 0, &xnfp->xnf_icookie)
	    != DDI_SUCCESS)
		goto failure;

	mutex_init(&xnfp->xnf_txlock,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);
	mutex_init(&xnfp->xnf_rxlock,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);
	mutex_init(&xnfp->xnf_schedlock,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);
	mutex_init(&xnfp->xnf_gref_lock,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);

	cv_init(&xnfp->xnf_cv_state, NULL, CV_DEFAULT, NULL);
	cv_init(&xnfp->xnf_cv_multicast, NULL, CV_DEFAULT, NULL);
	cv_init(&xnfp->xnf_cv_tx_slots, NULL, CV_DEFAULT, NULL);

	(void) sprintf(cachename, "xnf_buf_cache_%d",
	    ddi_get_instance(devinfo));
	xnfp->xnf_buf_cache = kmem_cache_create(cachename,
	    sizeof (xnf_buf_t), 0,
	    xnf_buf_constructor, xnf_buf_destructor,
	    NULL, xnfp, NULL, 0);
	if (xnfp->xnf_buf_cache == NULL)
		goto failure_0;

	(void) sprintf(cachename, "xnf_tx_buf_cache_%d",
	    ddi_get_instance(devinfo));
	xnfp->xnf_tx_buf_cache = kmem_cache_create(cachename,
	    sizeof (xnf_txbuf_t), 0,
	    xnf_tx_buf_constructor, xnf_tx_buf_destructor,
	    NULL, xnfp, NULL, 0);
	if (xnfp->xnf_tx_buf_cache == NULL)
		goto failure_1;

	xnfp->xnf_gref_head = INVALID_GRANT_REF;

	if (xnf_alloc_dma_resources(xnfp) == DDI_FAILURE) {
		cmn_err(CE_WARN, "xnf%d: failed to allocate and initialize "
		    "driver data structures",
		    ddi_get_instance(xnfp->xnf_devinfo));
		goto failure_2;
	}

	xnfp->xnf_rx_ring.sring->rsp_event =
	    xnfp->xnf_tx_ring.sring->rsp_event = 1;

	xnfp->xnf_tx_ring_ref = INVALID_GRANT_REF;
	xnfp->xnf_rx_ring_ref = INVALID_GRANT_REF;

	/* set driver private pointer now */
	ddi_set_driver_private(devinfo, xnfp);

	if (!xnf_kstat_init(xnfp))
		goto failure_3;

	/*
	 * Allocate an event channel, add the interrupt handler and
	 * bind it to the event channel.
	 */
	(void) xvdi_alloc_evtchn(devinfo);
	xnfp->xnf_evtchn = xvdi_get_evtchn(devinfo);
#ifdef XPV_HVM_DRIVER
	ec_bind_evtchn_to_handler(xnfp->xnf_evtchn, IPL_VIF, xnf_intr, xnfp);
#else
	(void) ddi_add_intr(devinfo, 0, NULL, NULL, xnf_intr, (caddr_t)xnfp);
#endif

	err = mac_register(macp, &xnfp->xnf_mh);
	mac_free(macp);
	macp = NULL;
	if (err != 0)
		goto failure_4;

	if (xvdi_add_event_handler(devinfo, XS_OE_STATE, oe_state_change, NULL)
	    != DDI_SUCCESS)
		goto failure_5;

#ifdef XPV_HVM_DRIVER
	/*
	 * In the HVM case, this driver essentially replaces a driver for
	 * a 'real' PCI NIC. Without the "model" property set to
	 * "Ethernet controller", like the PCI code does, netbooting does
	 * not work correctly, as strplumb_get_netdev_path() will not find
	 * this interface.
	 */
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, devinfo, "model",
	    "Ethernet controller");
#endif

#ifdef XNF_DEBUG
	if (xnf_debug_instance == NULL)
		xnf_debug_instance = xnfp;
#endif

	return (DDI_SUCCESS);

failure_5:
	(void) mac_unregister(xnfp->xnf_mh);

failure_4:
#ifdef XPV_HVM_DRIVER
	ec_unbind_evtchn(xnfp->xnf_evtchn);
	xvdi_free_evtchn(devinfo);
#else
	ddi_remove_intr(devinfo, 0, xnfp->xnf_icookie);
#endif
	xnfp->xnf_evtchn = INVALID_EVTCHN;
	kstat_delete(xnfp->xnf_kstat_aux);

failure_3:
	xnf_release_dma_resources(xnfp);

failure_2:
	kmem_cache_destroy(xnfp->xnf_tx_buf_cache);

failure_1:
	kmem_cache_destroy(xnfp->xnf_buf_cache);

failure_0:
	cv_destroy(&xnfp->xnf_cv_tx_slots);
	cv_destroy(&xnfp->xnf_cv_multicast);
	cv_destroy(&xnfp->xnf_cv_state);

	mutex_destroy(&xnfp->xnf_gref_lock);
	mutex_destroy(&xnfp->xnf_schedlock);
	mutex_destroy(&xnfp->xnf_rxlock);
	mutex_destroy(&xnfp->xnf_txlock);

failure:
	kmem_free(xnfp, sizeof (*xnfp));
	if (macp != NULL)
		mac_free(macp);

	return (DDI_FAILURE);
}

/*  detach(9E) -- Detach a device from the system */
static int
xnf_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	xnf_t *xnfp;		/* Our private device info */

#ifdef XNF_DEBUG
	if (xnf_debug & XNF_DEBUG_DDI)
		printf("xnf_detach(0x%p)\n", (void *)devinfo);
#endif

	xnfp = ddi_get_driver_private(devinfo);

	switch (cmd) {
	case DDI_SUSPEND:
#ifdef XPV_HVM_DRIVER
		ec_unbind_evtchn(xnfp->xnf_evtchn);
		xvdi_free_evtchn(devinfo);
#else
		ddi_remove_intr(devinfo, 0, xnfp->xnf_icookie);
#endif

		xvdi_suspend(devinfo);

		mutex_enter(&xnfp->xnf_rxlock);
		mutex_enter(&xnfp->xnf_txlock);

		xnfp->xnf_evtchn = INVALID_EVTCHN;
		xnfp->xnf_connected = B_FALSE;
		mutex_exit(&xnfp->xnf_txlock);
		mutex_exit(&xnfp->xnf_rxlock);

		/* claim link to be down after disconnect */
		mac_link_update(xnfp->xnf_mh, LINK_STATE_DOWN);
		return (DDI_SUCCESS);

	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	if (xnfp->xnf_connected)
		return (DDI_FAILURE);

	/*
	 * Cannot detach if we have xnf_buf_t outstanding.
	 */
	if (xnfp->xnf_stat_buf_allocated > 0)
		return (DDI_FAILURE);

	if (mac_unregister(xnfp->xnf_mh) != 0)
		return (DDI_FAILURE);

	kstat_delete(xnfp->xnf_kstat_aux);

	/* Stop the receiver */
	xnf_stop(xnfp);

	xvdi_remove_event_handler(devinfo, XS_OE_STATE);

	/* Remove the interrupt */
#ifdef XPV_HVM_DRIVER
	ec_unbind_evtchn(xnfp->xnf_evtchn);
	xvdi_free_evtchn(devinfo);
#else
	ddi_remove_intr(devinfo, 0, xnfp->xnf_icookie);
#endif

	/* Release any pending xmit mblks */
	xnf_release_mblks(xnfp);

	/* Release all DMA resources */
	xnf_release_dma_resources(xnfp);

	cv_destroy(&xnfp->xnf_cv_tx_slots);
	cv_destroy(&xnfp->xnf_cv_multicast);
	cv_destroy(&xnfp->xnf_cv_state);

	kmem_cache_destroy(xnfp->xnf_tx_buf_cache);
	kmem_cache_destroy(xnfp->xnf_buf_cache);

	mutex_destroy(&xnfp->xnf_gref_lock);
	mutex_destroy(&xnfp->xnf_schedlock);
	mutex_destroy(&xnfp->xnf_rxlock);
	mutex_destroy(&xnfp->xnf_txlock);

	kmem_free(xnfp, sizeof (*xnfp));

	return (DDI_SUCCESS);
}

/*
 *  xnf_set_mac_addr() -- set the physical network address on the board.
 */
static int
xnf_set_mac_addr(void *arg, const uint8_t *macaddr)
{
	_NOTE(ARGUNUSED(arg, macaddr));

	/*
	 * We can't set our macaddr.
	 */
	return (ENOTSUP);
}

/*
 *  xnf_set_multicast() -- set (enable) or disable a multicast address.
 *
 *  Program the hardware to enable/disable the multicast address
 *  in "mca".  Enable if "add" is true, disable if false.
 */
static int
xnf_set_multicast(void *arg, boolean_t add, const uint8_t *mca)
{
	xnf_t *xnfp = arg;
	xnf_txbuf_t *txp;
	int n_slots;
	RING_IDX slot;
	xnf_txid_t *tidp;
	netif_tx_request_t *txrp;
	struct netif_extra_info *erp;
	boolean_t notify, result;

	/*
	 * If the backend does not support multicast control then we
	 * must assume that the right packets will just arrive.
	 */
	if (!xnfp->xnf_be_mcast_control)
		return (0);

	txp = kmem_cache_alloc(xnfp->xnf_tx_buf_cache, KM_SLEEP);

	mutex_enter(&xnfp->xnf_txlock);

	/*
	 * If we're not yet connected then claim success. This is
	 * acceptable because we refresh the entire set of multicast
	 * addresses when we get connected.
	 *
	 * We can't wait around here because the MAC layer expects
	 * this to be a non-blocking operation - waiting ends up
	 * causing a deadlock during resume.
	 */
	if (!xnfp->xnf_connected) {
		mutex_exit(&xnfp->xnf_txlock);
		return (0);
	}

	/*
	 * 1. Acquire two slots in the ring.
	 * 2. Fill in the slots.
	 * 3. Request notification when the operation is done.
	 * 4. Kick the peer.
	 * 5. Wait for the response via xnf_tx_clean_ring().
	 */

	n_slots = tx_slots_get(xnfp, 2, B_TRUE);
	ASSERT(n_slots >= 2);

	slot = xnfp->xnf_tx_ring.req_prod_pvt;
	tidp = txid_get(xnfp);
	VERIFY(tidp != NULL);

	txp->tx_type = TX_MCAST_REQ;
	txp->tx_slot = slot;

	txrp = RING_GET_REQUEST(&xnfp->xnf_tx_ring, slot);
	erp = (struct netif_extra_info *)
	    RING_GET_REQUEST(&xnfp->xnf_tx_ring, slot + 1);

	txrp->gref = 0;
	txrp->size = 0;
	txrp->offset = 0;
	/* Set tx_txreq.id to appease xnf_tx_clean_ring(). */
	txrp->id = txp->tx_txreq.id = tidp->id;
	txrp->flags = NETTXF_extra_info;

	erp->type = add ? XEN_NETIF_EXTRA_TYPE_MCAST_ADD :
	    XEN_NETIF_EXTRA_TYPE_MCAST_DEL;
	bcopy((void *)mca, &erp->u.mcast.addr, ETHERADDRL);

	tidp->txbuf = txp;

	xnfp->xnf_tx_ring.req_prod_pvt = slot + 2;

	mutex_enter(&xnfp->xnf_schedlock);
	xnfp->xnf_pending_multicast++;
	mutex_exit(&xnfp->xnf_schedlock);

	/* LINTED: constant in conditional context */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xnfp->xnf_tx_ring,
	    notify);
	if (notify)
		ec_notify_via_evtchn(xnfp->xnf_evtchn);

	while (txp->tx_type == TX_MCAST_REQ)
		cv_wait(&xnfp->xnf_cv_multicast,
		    &xnfp->xnf_txlock);

	ASSERT(txp->tx_type == TX_MCAST_RSP);

	mutex_enter(&xnfp->xnf_schedlock);
	xnfp->xnf_pending_multicast--;
	mutex_exit(&xnfp->xnf_schedlock);

	result = (txp->tx_status == NETIF_RSP_OKAY);

	txid_put(xnfp, tidp);

	mutex_exit(&xnfp->xnf_txlock);

	kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);

	return (result ? 0 : 1);
}

/*
 * xnf_set_promiscuous() -- set or reset promiscuous mode on the board
 *
 *  Program the hardware to enable/disable promiscuous mode.
 */
static int
xnf_set_promiscuous(void *arg, boolean_t on)
{
	_NOTE(ARGUNUSED(arg, on));

	/*
	 * We can't really do this, but we pretend that we can in
	 * order that snoop will work.
	 */
	return (0);
}

/*
 * Clean buffers that we have responses for from the transmit ring.
 */
static int
xnf_tx_clean_ring(xnf_t *xnfp)
{
	boolean_t work_to_do;

	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));

loop:
	while (RING_HAS_UNCONSUMED_RESPONSES(&xnfp->xnf_tx_ring)) {
		RING_IDX cons, prod, i;

		cons = xnfp->xnf_tx_ring.rsp_cons;
		prod = xnfp->xnf_tx_ring.sring->rsp_prod;
		membar_consumer();
		/*
		 * Clean tx requests from ring that we have responses
		 * for.
		 */
		DTRACE_PROBE2(xnf_tx_clean_range, int, cons, int, prod);
		for (i = cons; i != prod; i++) {
			netif_tx_response_t *trp;
			xnf_txid_t *tidp;
			xnf_txbuf_t *txp;

			trp = RING_GET_RESPONSE(&xnfp->xnf_tx_ring, i);
			ASSERT(TX_ID_VALID(trp->id));

			tidp = TX_ID_TO_TXID(xnfp, trp->id);
			ASSERT(tidp->id == trp->id);
			ASSERT(tidp->next == INVALID_TX_ID);

			txp = tidp->txbuf;
			ASSERT(txp != NULL);
			ASSERT(txp->tx_txreq.id == trp->id);

			switch (txp->tx_type) {
			case TX_DATA:
				if (gnttab_query_foreign_access(
				    txp->tx_txreq.gref) != 0)
					cmn_err(CE_PANIC,
					    "tx grant %d still in use by "
					    "backend domain",
					    txp->tx_txreq.gref);

				if (txp->tx_bdesc == NULL) {
					(void) gnttab_end_foreign_access_ref(
					    txp->tx_txreq.gref, 1);
					gref_put(xnfp, txp->tx_txreq.gref);
					(void) ddi_dma_unbind_handle(
					    txp->tx_dma_handle);
				} else {
					xnf_buf_put(xnfp, txp->tx_bdesc,
					    B_TRUE);
				}

				freemsg(txp->tx_mp);
				txid_put(xnfp, tidp);
				kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);

				break;

			case TX_MCAST_REQ:
				txp->tx_type = TX_MCAST_RSP;
				txp->tx_status = trp->status;
				cv_broadcast(&xnfp->xnf_cv_multicast);

				break;

			case TX_MCAST_RSP:
				break;

			default:
				cmn_err(CE_PANIC, "xnf_tx_clean_ring: "
				    "invalid xnf_txbuf_t type: %d",
				    txp->tx_type);
				break;
			}
		}
		/*
		 * Record the last response we dealt with so that we
		 * know where to start next time around.
		 */
		xnfp->xnf_tx_ring.rsp_cons = prod;
		membar_enter();
	}

	/* LINTED: constant in conditional context */
	RING_FINAL_CHECK_FOR_RESPONSES(&xnfp->xnf_tx_ring, work_to_do);
	if (work_to_do)
		goto loop;

	return (RING_FREE_REQUESTS(&xnfp->xnf_tx_ring));
}

/*
 * Allocate and fill in a look-aside buffer for the packet `mp'. Used
 * to ensure that the packet is physically contiguous and contained
 * within a single page.
 */
static xnf_buf_t *
xnf_tx_pullup(xnf_t *xnfp, mblk_t *mp)
{
	xnf_buf_t *bd;
	caddr_t bp;

	bd = xnf_buf_get(xnfp, KM_SLEEP, B_TRUE);
	if (bd == NULL)
		return (NULL);

	bp = bd->buf;
	while (mp != NULL) {
		size_t len = MBLKL(mp);

		bcopy(mp->b_rptr, bp, len);
		bp += len;

		mp = mp->b_cont;
	}

	ASSERT((bp - bd->buf) <= PAGESIZE);

	xnfp->xnf_stat_tx_pullup++;

	return (bd);
}

/*
 * Insert the pseudo-header checksum into the packet `buf'.
 */
void
xnf_pseudo_cksum(caddr_t buf, int length)
{
	struct ether_header *ehp;
	uint16_t sap, len, *stuff;
	uint32_t cksum;
	size_t offset;
	ipha_t *ipha;
	ipaddr_t src, dst;

	ASSERT(length >= sizeof (*ehp));
	ehp = (struct ether_header *)buf;

	if (ntohs(ehp->ether_type) == VLAN_TPID) {
		struct ether_vlan_header *evhp;

		ASSERT(length >= sizeof (*evhp));
		evhp = (struct ether_vlan_header *)buf;
		sap = ntohs(evhp->ether_type);
		offset = sizeof (*evhp);
	} else {
		sap = ntohs(ehp->ether_type);
		offset = sizeof (*ehp);
	}

	ASSERT(sap == ETHERTYPE_IP);

	/* Packet should have been pulled up by the caller. */
	if ((offset + sizeof (ipha_t)) > length) {
		cmn_err(CE_WARN, "xnf_pseudo_cksum: no room for checksum");
		return;
	}

	ipha = (ipha_t *)(buf + offset);

	ASSERT(IPH_HDR_LENGTH(ipha) == IP_SIMPLE_HDR_LENGTH);

	len = ntohs(ipha->ipha_length) - IP_SIMPLE_HDR_LENGTH;

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP:
		stuff = IPH_TCPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);
		cksum = IP_TCP_CSUM_COMP;
		break;
	case IPPROTO_UDP:
		stuff = IPH_UDPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);
		cksum = IP_UDP_CSUM_COMP;
		break;
	default:
		cmn_err(CE_WARN, "xnf_pseudo_cksum: unexpected protocol %d",
		    ipha->ipha_protocol);
		return;
	}

	src = ipha->ipha_src;
	dst = ipha->ipha_dst;

	cksum += (dst >> 16) + (dst & 0xFFFF);
	cksum += (src >> 16) + (src & 0xFFFF);
	cksum += htons(len);

	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum = (cksum >> 16) + (cksum & 0xFFFF);

	ASSERT(cksum <= 0xFFFF);

	*stuff = (uint16_t)(cksum ? cksum : ~cksum);
}

/*
 * Push a list of prepared packets (`txp') into the transmit ring.
 */
static xnf_txbuf_t *
tx_push_packets(xnf_t *xnfp, xnf_txbuf_t *txp)
{
	int slots_free;
	RING_IDX slot;
	boolean_t notify;

	mutex_enter(&xnfp->xnf_txlock);

	ASSERT(xnfp->xnf_running);

	/*
	 * Wait until we are connected to the backend.
	 */
	while (!xnfp->xnf_connected)
		cv_wait(&xnfp->xnf_cv_state, &xnfp->xnf_txlock);

	slots_free = tx_slots_get(xnfp, 1, B_FALSE);
	DTRACE_PROBE1(xnf_send_slotsfree, int, slots_free);

	slot = xnfp->xnf_tx_ring.req_prod_pvt;

	while ((txp != NULL) && (slots_free > 0)) {
		xnf_txid_t *tidp;
		netif_tx_request_t *txrp;

		tidp = txid_get(xnfp);
		VERIFY(tidp != NULL);

		txrp = RING_GET_REQUEST(&xnfp->xnf_tx_ring, slot);

		txp->tx_slot = slot;
		txp->tx_txreq.id = tidp->id;
		*txrp = txp->tx_txreq;

		tidp->txbuf = txp;

		xnfp->xnf_stat_opackets++;
		xnfp->xnf_stat_obytes += txp->tx_txreq.size;

		txp = txp->tx_next;
		slots_free--;
		slot++;

	}

	xnfp->xnf_tx_ring.req_prod_pvt = slot;

	/*
	 * Tell the peer that we sent something, if it cares.
	 */
	/* LINTED: constant in conditional context */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xnfp->xnf_tx_ring,
	    notify);
	if (notify)
		ec_notify_via_evtchn(xnfp->xnf_evtchn);

	mutex_exit(&xnfp->xnf_txlock);

	return (txp);
}

/*
 * Send the chain of packets `mp'. Called by the MAC framework.
 */
static mblk_t *
xnf_send(void *arg, mblk_t *mp)
{
	xnf_t *xnfp = arg;
	domid_t oeid;
	xnf_txbuf_t *head, *tail;
	mblk_t *ml;
	int prepared;

	oeid = xvdi_get_oeid(xnfp->xnf_devinfo);

	/*
	 * Prepare packets for transmission.
	 */
	head = tail = NULL;
	prepared = 0;
	while (mp != NULL) {
		xnf_txbuf_t *txp;
		int n_chunks, length;
		boolean_t page_oops;
		uint32_t pflags;

		for (ml = mp, n_chunks = length = 0, page_oops = B_FALSE;
		    ml != NULL;
		    ml = ml->b_cont, n_chunks++) {

			/*
			 * Test if this buffer includes a page
			 * boundary. The test assumes that the range
			 * b_rptr...b_wptr can include only a single
			 * boundary.
			 */
			if (xnf_btop((size_t)ml->b_rptr) !=
			    xnf_btop((size_t)ml->b_wptr)) {
				xnfp->xnf_stat_tx_pagebndry++;
				page_oops = B_TRUE;
			}

			length += MBLKL(ml);
		}
		DTRACE_PROBE1(xnf_send_b_cont, int, n_chunks);

		/*
		 * Make sure packet isn't too large.
		 */
		if (length > XNF_FRAMESIZE) {
			cmn_err(CE_WARN,
			    "xnf%d: oversized packet (%d bytes) dropped",
			    ddi_get_instance(xnfp->xnf_devinfo), length);
			freemsg(mp);
			continue;
		}

		txp = kmem_cache_alloc(xnfp->xnf_tx_buf_cache, KM_SLEEP);

		txp->tx_type = TX_DATA;

		if ((n_chunks > xnf_max_tx_frags) || page_oops) {
			/*
			 * Loan a side buffer rather than the mblk
			 * itself.
			 */
			txp->tx_bdesc = xnf_tx_pullup(xnfp, mp);
			if (txp->tx_bdesc == NULL) {
				kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);
				break;
			}

			txp->tx_bufp = txp->tx_bdesc->buf;
			txp->tx_mfn = txp->tx_bdesc->buf_mfn;
			txp->tx_txreq.gref = txp->tx_bdesc->grant_ref;

		} else {
			int rc;
			ddi_dma_cookie_t dma_cookie;
			uint_t ncookies;

			rc = ddi_dma_addr_bind_handle(txp->tx_dma_handle,
			    NULL, (char *)mp->b_rptr, length,
			    DDI_DMA_WRITE | DDI_DMA_STREAMING,
			    DDI_DMA_DONTWAIT, 0, &dma_cookie,
			    &ncookies);
			if (rc != DDI_DMA_MAPPED) {
				ASSERT(rc != DDI_DMA_INUSE);
				ASSERT(rc != DDI_DMA_PARTIAL_MAP);

#ifdef XNF_DEBUG
				if (rc != DDI_DMA_NORESOURCES)
					cmn_err(CE_WARN,
					    "xnf%d: bind_handle failed (%x)",
					    ddi_get_instance(xnfp->xnf_devinfo),
					    rc);
#endif
				kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);
				break;
			}
			ASSERT(ncookies == 1);

			txp->tx_bdesc = NULL;
			txp->tx_bufp = (caddr_t)mp->b_rptr;
			txp->tx_mfn =
			    xnf_btop(pa_to_ma(dma_cookie.dmac_laddress));
			txp->tx_txreq.gref = gref_get(xnfp);
			if (txp->tx_txreq.gref == INVALID_GRANT_REF) {
				(void) ddi_dma_unbind_handle(
				    txp->tx_dma_handle);
				kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);
				break;
			}
			gnttab_grant_foreign_access_ref(txp->tx_txreq.gref,
			    oeid, txp->tx_mfn, 1);
		}

		txp->tx_next = NULL;
		txp->tx_mp = mp;
		txp->tx_txreq.size = length;
		txp->tx_txreq.offset = (uintptr_t)txp->tx_bufp & PAGEOFFSET;
		txp->tx_txreq.flags = 0;
		mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &pflags);
		if (pflags != 0) {
			/*
			 * If the local protocol stack requests checksum
			 * offload we set the 'checksum blank' flag,
			 * indicating to the peer that we need the checksum
			 * calculated for us.
			 *
			 * We _don't_ set the validated flag, because we haven't
			 * validated that the data and the checksum match.
			 */
			xnf_pseudo_cksum(txp->tx_bufp, length);
			txp->tx_txreq.flags |= NETTXF_csum_blank;

			xnfp->xnf_stat_tx_cksum_deferred++;
		}

		if (head == NULL) {
			ASSERT(tail == NULL);

			head = txp;
		} else {
			ASSERT(tail != NULL);

			tail->tx_next = txp;
		}
		tail = txp;

		mp = mp->b_next;
		prepared++;

		/*
		 * There is no point in preparing more than
		 * NET_TX_RING_SIZE, as we won't be able to push them
		 * into the ring in one go and would hence have to
		 * un-prepare the extra.
		 */
		if (prepared == NET_TX_RING_SIZE)
			break;
	}

	DTRACE_PROBE1(xnf_send_prepared, int, prepared);

	if (mp != NULL) {
#ifdef XNF_DEBUG
		int notprepared = 0;
		mblk_t *l = mp;

		while (l != NULL) {
			notprepared++;
			l = l->b_next;
		}

		DTRACE_PROBE1(xnf_send_notprepared, int, notprepared);
#else /* !XNF_DEBUG */
		DTRACE_PROBE1(xnf_send_notprepared, int, -1);
#endif /* XNF_DEBUG */
	}

	/*
	 * Push the packets we have prepared into the ring. They may
	 * not all go.
	 */
	if (head != NULL)
		head = tx_push_packets(xnfp, head);

	/*
	 * If some packets that we prepared were not sent, unprepare
	 * them and add them back to the head of those we didn't
	 * prepare.
	 */
	{
		xnf_txbuf_t *loop;
		mblk_t *mp_head, *mp_tail;
		int unprepared = 0;

		mp_head = mp_tail = NULL;
		loop = head;

		while (loop != NULL) {
			xnf_txbuf_t *next = loop->tx_next;

			if (loop->tx_bdesc == NULL) {
				(void) gnttab_end_foreign_access_ref(
				    loop->tx_txreq.gref, 1);
				gref_put(xnfp, loop->tx_txreq.gref);
				(void) ddi_dma_unbind_handle(
				    loop->tx_dma_handle);
			} else {
				xnf_buf_put(xnfp, loop->tx_bdesc, B_TRUE);
			}

			ASSERT(loop->tx_mp != NULL);
			if (mp_head == NULL)
				mp_head = loop->tx_mp;
			mp_tail = loop->tx_mp;

			kmem_cache_free(xnfp->xnf_tx_buf_cache, loop);
			loop = next;
			unprepared++;
		}

		if (mp_tail == NULL) {
			ASSERT(mp_head == NULL);
		} else {
			ASSERT(mp_head != NULL);

			mp_tail->b_next = mp;
			mp = mp_head;
		}

		DTRACE_PROBE1(xnf_send_unprepared, int, unprepared);
	}

	/*
	 * If any mblks are left then we have deferred for some reason
	 * and need to ask for a re-schedule later. This is typically
	 * due to the ring filling.
	 */
	if (mp != NULL) {
		mutex_enter(&xnfp->xnf_schedlock);
		xnfp->xnf_need_sched = B_TRUE;
		mutex_exit(&xnfp->xnf_schedlock);

		xnfp->xnf_stat_tx_defer++;
	}

	return (mp);
}

/*
 * Notification of RX packets. Currently no TX-complete interrupt is
 * used, as we clean the TX ring lazily.
 */
static uint_t
xnf_intr(caddr_t arg)
{
	xnf_t *xnfp = (xnf_t *)arg;
	mblk_t *mp;
	boolean_t need_sched, clean_ring;

	mutex_enter(&xnfp->xnf_rxlock);

	/*
	 * Interrupts before we are connected are spurious.
	 */
	if (!xnfp->xnf_connected) {
		mutex_exit(&xnfp->xnf_rxlock);
		xnfp->xnf_stat_unclaimed_interrupts++;
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Receive side processing.
	 */
	do {
		/*
		 * Collect buffers from the ring.
		 */
		xnf_rx_collect(xnfp);

		/*
		 * Interrupt me when the next receive buffer is consumed.
		 */
		xnfp->xnf_rx_ring.sring->rsp_event =
		    xnfp->xnf_rx_ring.rsp_cons + 1;
		xen_mb();

	} while (RING_HAS_UNCONSUMED_RESPONSES(&xnfp->xnf_rx_ring));

	if (xnfp->xnf_rx_new_buffers_posted) {
		boolean_t notify;

		/*
		 * Indicate to the peer that we have re-filled the
		 * receive ring, if it cares.
		 */
		/* LINTED: constant in conditional context */
		RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xnfp->xnf_rx_ring, notify);
		if (notify)
			ec_notify_via_evtchn(xnfp->xnf_evtchn);
		xnfp->xnf_rx_new_buffers_posted = B_FALSE;
	}

	mp = xnfp->xnf_rx_head;
	xnfp->xnf_rx_head = xnfp->xnf_rx_tail = NULL;

	xnfp->xnf_stat_interrupts++;
	mutex_exit(&xnfp->xnf_rxlock);

	if (mp != NULL)
		mac_rx(xnfp->xnf_mh, NULL, mp);

	/*
	 * Transmit side processing.
	 *
	 * If a previous transmit attempt failed or we have pending
	 * multicast requests, clean the ring.
	 *
	 * If we previously stalled transmission and cleaning produces
	 * some free slots, tell upstream to attempt sending again.
	 *
	 * The odd style is to avoid acquiring xnf_txlock unless we
	 * will actually look inside the tx machinery.
	 */
	mutex_enter(&xnfp->xnf_schedlock);
	need_sched = xnfp->xnf_need_sched;
	clean_ring = need_sched || (xnfp->xnf_pending_multicast > 0);
	mutex_exit(&xnfp->xnf_schedlock);

	if (clean_ring) {
		int free_slots;

		mutex_enter(&xnfp->xnf_txlock);
		free_slots = tx_slots_get(xnfp, 0, B_FALSE);

		if (need_sched && (free_slots > 0)) {
			mutex_enter(&xnfp->xnf_schedlock);
			xnfp->xnf_need_sched = B_FALSE;
			mutex_exit(&xnfp->xnf_schedlock);

			mac_tx_update(xnfp->xnf_mh);
		}
		mutex_exit(&xnfp->xnf_txlock);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 *  xnf_start() -- start the board receiving and enable interrupts.
 */
static int
xnf_start(void *arg)
{
	xnf_t *xnfp = arg;

#ifdef XNF_DEBUG
	if (xnf_debug & XNF_DEBUG_TRACE)
		printf("xnf%d start(0x%p)\n",
		    ddi_get_instance(xnfp->xnf_devinfo), (void *)xnfp);
#endif

	mutex_enter(&xnfp->xnf_rxlock);
	mutex_enter(&xnfp->xnf_txlock);

	/* Accept packets from above. */
	xnfp->xnf_running = B_TRUE;

	mutex_exit(&xnfp->xnf_txlock);
	mutex_exit(&xnfp->xnf_rxlock);

	return (0);
}

/* xnf_stop() - disable hardware */
static void
xnf_stop(void *arg)
{
	xnf_t *xnfp = arg;

#ifdef XNF_DEBUG
	if (xnf_debug & XNF_DEBUG_TRACE)
		printf("xnf%d stop(0x%p)\n",
		    ddi_get_instance(xnfp->xnf_devinfo), (void *)xnfp);
#endif

	mutex_enter(&xnfp->xnf_rxlock);
	mutex_enter(&xnfp->xnf_txlock);

	xnfp->xnf_running = B_FALSE;

	mutex_exit(&xnfp->xnf_txlock);
	mutex_exit(&xnfp->xnf_rxlock);
}

/*
 * Hang buffer `bdesc' on the RX ring.
 */
static void
xnf_rxbuf_hang(xnf_t *xnfp, xnf_buf_t *bdesc)
{
	netif_rx_request_t *reqp;
	RING_IDX hang_ix;

	ASSERT(MUTEX_HELD(&xnfp->xnf_rxlock));

	reqp = RING_GET_REQUEST(&xnfp->xnf_rx_ring,
	    xnfp->xnf_rx_ring.req_prod_pvt);
	hang_ix = (RING_IDX) (reqp - RING_GET_REQUEST(&xnfp->xnf_rx_ring, 0));
	ASSERT(xnfp->xnf_rx_pkt_info[hang_ix] == NULL);

	reqp->id = bdesc->id = hang_ix;
	reqp->gref = bdesc->grant_ref;

	xnfp->xnf_rx_pkt_info[hang_ix] = bdesc;
	xnfp->xnf_rx_ring.req_prod_pvt++;

	xnfp->xnf_rx_new_buffers_posted = B_TRUE;
}

/*
 * Collect packets from the RX ring, storing them in `xnfp' for later
 * use.
 */
static void
xnf_rx_collect(xnf_t *xnfp)
{
	mblk_t *head, *tail;

	ASSERT(MUTEX_HELD(&xnfp->xnf_rxlock));

	/*
	 * Loop over unconsumed responses:
	 * 1. get a response
	 * 2. take corresponding buffer off recv. ring
	 * 3. indicate this by setting slot to NULL
	 * 4. create a new message and
	 * 5. copy data in, adjust ptr
	 */

	head = tail = NULL;

	while (RING_HAS_UNCONSUMED_RESPONSES(&xnfp->xnf_rx_ring)) {
		netif_rx_response_t *rxpkt;
		xnf_buf_t *bdesc;
		ssize_t len;
		size_t off;
		mblk_t *mp = NULL;
		boolean_t hwcsum = B_FALSE;
		grant_ref_t ref;

		/* 1. */
		rxpkt = RING_GET_RESPONSE(&xnfp->xnf_rx_ring,
		    xnfp->xnf_rx_ring.rsp_cons);

		DTRACE_PROBE4(xnf_rx_got_rsp, int, (int)rxpkt->id,
		    int, (int)rxpkt->offset,
		    int, (int)rxpkt->flags,
		    int, (int)rxpkt->status);

		/*
		 * 2.
		 */
		bdesc = xnfp->xnf_rx_pkt_info[rxpkt->id];

		/*
		 * 3.
		 */
		xnfp->xnf_rx_pkt_info[rxpkt->id] = NULL;
		ASSERT(bdesc->id == rxpkt->id);

		ref = bdesc->grant_ref;
		off = rxpkt->offset;
		len = rxpkt->status;

		if (!xnfp->xnf_running) {
			DTRACE_PROBE4(xnf_rx_not_running,
			    int, rxpkt->status,
			    char *, bdesc->buf, int, rxpkt->offset,
			    char *, ((char *)bdesc->buf) + rxpkt->offset);

			xnfp->xnf_stat_drop++;

		} else if (len <= 0) {
			DTRACE_PROBE4(xnf_rx_pkt_status_negative,
			    int, rxpkt->status,
			    char *, bdesc->buf, int, rxpkt->offset,
			    char *, ((char *)bdesc->buf) + rxpkt->offset);

			xnfp->xnf_stat_errrx++;

			switch (len) {
			case 0:
				xnfp->xnf_stat_runt++;
				break;
			case NETIF_RSP_ERROR:
				xnfp->xnf_stat_mac_rcv_error++;
				break;
			case NETIF_RSP_DROPPED:
				xnfp->xnf_stat_norxbuf++;
				break;
			}

		} else if (bdesc->grant_ref == INVALID_GRANT_REF) {
			cmn_err(CE_WARN, "Bad rx grant reference %d "
			    "from domain %d", ref,
			    xvdi_get_oeid(xnfp->xnf_devinfo));

		} else if ((off + len) > PAGESIZE) {
			cmn_err(CE_WARN, "Rx packet overflows page "
			    "(offset %ld, length %ld) from domain %d",
			    off, len, xvdi_get_oeid(xnfp->xnf_devinfo));
		} else {
			xnf_buf_t *nbuf = NULL;

			DTRACE_PROBE4(xnf_rx_packet, int, len,
			    char *, bdesc->buf, int, off,
			    char *, ((char *)bdesc->buf) + off);

			ASSERT(off + len <= PAGEOFFSET);

			if (rxpkt->flags & NETRXF_data_validated)
				hwcsum = B_TRUE;

			/*
			 * If the packet is below a pre-determined
			 * size we will copy data out rather than
			 * replace it.
			 */
			if (len > xnf_rx_copy_limit)
				nbuf = xnf_buf_get(xnfp, KM_NOSLEEP, B_FALSE);

			/*
			 * If we have a replacement buffer, attempt to
			 * wrap the existing one with an mblk_t in
			 * order that the upper layers of the stack
			 * might use it directly.
			 */
			if (nbuf != NULL) {
				mp = desballoc((unsigned char *)bdesc->buf,
				    bdesc->len, 0, &bdesc->free_rtn);
				if (mp == NULL) {
					xnfp->xnf_stat_rx_desballoc_fail++;
					xnfp->xnf_stat_norxbuf++;

					xnf_buf_put(xnfp, nbuf, B_FALSE);
					nbuf = NULL;
				} else {
					mp->b_rptr = mp->b_rptr + off;
					mp->b_wptr = mp->b_rptr + len;

					/*
					 * Release the grant reference
					 * associated with this buffer
					 * - they are scarce and the
					 * upper layers of the stack
					 * don't need it.
					 */
					(void) gnttab_end_foreign_access_ref(
					    bdesc->grant_ref, 0);
					gref_put(xnfp, bdesc->grant_ref);
					bdesc->grant_ref = INVALID_GRANT_REF;

					bdesc = nbuf;
				}
			}

			if (nbuf == NULL) {
				/*
				 * No replacement buffer allocated -
				 * attempt to copy the data out and
				 * re-hang the existing buffer.
				 */

				/* 4. */
				mp = allocb(len, BPRI_MED);
				if (mp == NULL) {
					xnfp->xnf_stat_rx_allocb_fail++;
					xnfp->xnf_stat_norxbuf++;
				} else {
					/* 5. */
					bcopy(bdesc->buf + off, mp->b_wptr,
					    len);
					mp->b_wptr += len;
				}
			}
		}

		/* Re-hang the buffer. */
		xnf_rxbuf_hang(xnfp, bdesc);

		if (mp != NULL) {
			if (hwcsum) {
				/*
				 * If the peer says that the data has
				 * been validated then we declare that
				 * the full checksum has been
				 * verified.
				 *
				 * We don't look at the "checksum
				 * blank" flag, and hence could have a
				 * packet here that we are asserting
				 * is good with a blank checksum.
				 */
				mac_hcksum_set(mp, 0, 0, 0, 0,
				    HCK_FULLCKSUM_OK);
				xnfp->xnf_stat_rx_cksum_no_need++;
			}
			if (head == NULL) {
				ASSERT(tail == NULL);

				head = mp;
			} else {
				ASSERT(tail != NULL);

				tail->b_next = mp;
			}
			tail = mp;

			ASSERT(mp->b_next == NULL);

			xnfp->xnf_stat_ipackets++;
			xnfp->xnf_stat_rbytes += len;
		}

		xnfp->xnf_rx_ring.rsp_cons++;
	}

	/*
	 * Store the mblks we have collected.
	 */
	if (head != NULL) {
		ASSERT(tail != NULL);

		if (xnfp->xnf_rx_head == NULL) {
			ASSERT(xnfp->xnf_rx_tail == NULL);

			xnfp->xnf_rx_head = head;
		} else {
			ASSERT(xnfp->xnf_rx_tail != NULL);

			xnfp->xnf_rx_tail->b_next = head;
		}
		xnfp->xnf_rx_tail = tail;
	}
}

/*
 *  xnf_alloc_dma_resources() -- initialize the drivers structures
 */
static int
xnf_alloc_dma_resources(xnf_t *xnfp)
{
	dev_info_t 		*devinfo = xnfp->xnf_devinfo;
	size_t			len;
	ddi_dma_cookie_t	dma_cookie;
	uint_t			ncookies;
	int			rc;
	caddr_t			rptr;

	/*
	 * The code below allocates all the DMA data structures that
	 * need to be released when the driver is detached.
	 *
	 * Allocate page for the transmit descriptor ring.
	 */
	if (ddi_dma_alloc_handle(devinfo, &ringbuf_dma_attr,
	    DDI_DMA_SLEEP, 0, &xnfp->xnf_tx_ring_dma_handle) != DDI_SUCCESS)
		goto alloc_error;

	if (ddi_dma_mem_alloc(xnfp->xnf_tx_ring_dma_handle,
	    PAGESIZE, &accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &rptr, &len,
	    &xnfp->xnf_tx_ring_dma_acchandle) != DDI_SUCCESS) {
		ddi_dma_free_handle(&xnfp->xnf_tx_ring_dma_handle);
		xnfp->xnf_tx_ring_dma_handle = NULL;
		goto alloc_error;
	}

	if ((rc = ddi_dma_addr_bind_handle(xnfp->xnf_tx_ring_dma_handle, NULL,
	    rptr, PAGESIZE, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies)) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&xnfp->xnf_tx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_tx_ring_dma_handle);
		xnfp->xnf_tx_ring_dma_handle = NULL;
		xnfp->xnf_tx_ring_dma_acchandle = NULL;
		if (rc == DDI_DMA_NORESOURCES)
			goto alloc_error;
		else
			goto error;
	}

	ASSERT(ncookies == 1);
	bzero(rptr, PAGESIZE);
	/* LINTED: constant in conditional context */
	SHARED_RING_INIT((netif_tx_sring_t *)rptr);
	/* LINTED: constant in conditional context */
	FRONT_RING_INIT(&xnfp->xnf_tx_ring, (netif_tx_sring_t *)rptr, PAGESIZE);
	xnfp->xnf_tx_ring_phys_addr = dma_cookie.dmac_laddress;

	/*
	 * Allocate page for the receive descriptor ring.
	 */
	if (ddi_dma_alloc_handle(devinfo, &ringbuf_dma_attr,
	    DDI_DMA_SLEEP, 0, &xnfp->xnf_rx_ring_dma_handle) != DDI_SUCCESS)
		goto alloc_error;

	if (ddi_dma_mem_alloc(xnfp->xnf_rx_ring_dma_handle,
	    PAGESIZE, &accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &rptr, &len,
	    &xnfp->xnf_rx_ring_dma_acchandle) != DDI_SUCCESS) {
		ddi_dma_free_handle(&xnfp->xnf_rx_ring_dma_handle);
		xnfp->xnf_rx_ring_dma_handle = NULL;
		goto alloc_error;
	}

	if ((rc = ddi_dma_addr_bind_handle(xnfp->xnf_rx_ring_dma_handle, NULL,
	    rptr, PAGESIZE, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies)) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&xnfp->xnf_rx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_rx_ring_dma_handle);
		xnfp->xnf_rx_ring_dma_handle = NULL;
		xnfp->xnf_rx_ring_dma_acchandle = NULL;
		if (rc == DDI_DMA_NORESOURCES)
			goto alloc_error;
		else
			goto error;
	}

	ASSERT(ncookies == 1);
	bzero(rptr, PAGESIZE);
	/* LINTED: constant in conditional context */
	SHARED_RING_INIT((netif_rx_sring_t *)rptr);
	/* LINTED: constant in conditional context */
	FRONT_RING_INIT(&xnfp->xnf_rx_ring, (netif_rx_sring_t *)rptr, PAGESIZE);
	xnfp->xnf_rx_ring_phys_addr = dma_cookie.dmac_laddress;

	return (DDI_SUCCESS);

alloc_error:
	cmn_err(CE_WARN, "xnf%d: could not allocate enough DMA memory",
	    ddi_get_instance(xnfp->xnf_devinfo));
error:
	xnf_release_dma_resources(xnfp);
	return (DDI_FAILURE);
}

/*
 * Release all DMA resources in the opposite order from acquisition
 */
static void
xnf_release_dma_resources(xnf_t *xnfp)
{
	int i;

	/*
	 * Free receive buffers which are currently associated with
	 * descriptors.
	 */
	mutex_enter(&xnfp->xnf_rxlock);
	for (i = 0; i < NET_RX_RING_SIZE; i++) {
		xnf_buf_t *bp;

		if ((bp = xnfp->xnf_rx_pkt_info[i]) == NULL)
			continue;
		xnfp->xnf_rx_pkt_info[i] = NULL;
		xnf_buf_put(xnfp, bp, B_FALSE);
	}
	mutex_exit(&xnfp->xnf_rxlock);

	/* Free the receive ring buffer. */
	if (xnfp->xnf_rx_ring_dma_acchandle != NULL) {
		(void) ddi_dma_unbind_handle(xnfp->xnf_rx_ring_dma_handle);
		ddi_dma_mem_free(&xnfp->xnf_rx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_rx_ring_dma_handle);
		xnfp->xnf_rx_ring_dma_acchandle = NULL;
	}
	/* Free the transmit ring buffer. */
	if (xnfp->xnf_tx_ring_dma_acchandle != NULL) {
		(void) ddi_dma_unbind_handle(xnfp->xnf_tx_ring_dma_handle);
		ddi_dma_mem_free(&xnfp->xnf_tx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_tx_ring_dma_handle);
		xnfp->xnf_tx_ring_dma_acchandle = NULL;
	}

}

/*
 * Release any packets and associated structures used by the TX ring.
 */
static void
xnf_release_mblks(xnf_t *xnfp)
{
	RING_IDX i;
	xnf_txid_t *tidp;

	for (i = 0, tidp = &xnfp->xnf_tx_pkt_id[0];
	    i < NET_TX_RING_SIZE;
	    i++, tidp++) {
		xnf_txbuf_t *txp = tidp->txbuf;

		if (txp != NULL) {
			ASSERT(txp->tx_mp != NULL);
			freemsg(txp->tx_mp);

			txid_put(xnfp, tidp);
			kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);
		}
	}
}

static int
xnf_buf_constructor(void *buf, void *arg, int kmflag)
{
	int (*ddiflags)(caddr_t) = DDI_DMA_SLEEP;
	xnf_buf_t *bdesc = buf;
	xnf_t *xnfp = arg;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	size_t len;

	if (kmflag & KM_NOSLEEP)
		ddiflags = DDI_DMA_DONTWAIT;

	/* Allocate a DMA access handle for the buffer. */
	if (ddi_dma_alloc_handle(xnfp->xnf_devinfo, &buf_dma_attr,
	    ddiflags, 0, &bdesc->dma_handle) != DDI_SUCCESS)
		goto failure;

	/* Allocate DMA-able memory for buffer. */
	if (ddi_dma_mem_alloc(bdesc->dma_handle,
	    PAGESIZE, &data_accattr, DDI_DMA_STREAMING, ddiflags, 0,
	    &bdesc->buf, &len, &bdesc->acc_handle) != DDI_SUCCESS)
		goto failure_1;

	/* Bind to virtual address of buffer to get physical address. */
	if (ddi_dma_addr_bind_handle(bdesc->dma_handle, NULL,
	    bdesc->buf, len, DDI_DMA_RDWR | DDI_DMA_STREAMING,
	    ddiflags, 0, &dma_cookie, &ncookies) != DDI_DMA_MAPPED)
		goto failure_2;
	ASSERT(ncookies == 1);

	bdesc->free_rtn.free_func = xnf_buf_recycle;
	bdesc->free_rtn.free_arg = (caddr_t)bdesc;
	bdesc->xnfp = xnfp;
	bdesc->buf_phys = dma_cookie.dmac_laddress;
	bdesc->buf_mfn = pfn_to_mfn(xnf_btop(bdesc->buf_phys));
	bdesc->len = dma_cookie.dmac_size;
	bdesc->grant_ref = INVALID_GRANT_REF;
	bdesc->gen = xnfp->xnf_gen;

	atomic_inc_64(&xnfp->xnf_stat_buf_allocated);

	return (0);

failure_2:
	ddi_dma_mem_free(&bdesc->acc_handle);

failure_1:
	ddi_dma_free_handle(&bdesc->dma_handle);

failure:

	ASSERT(kmflag & KM_NOSLEEP); /* Cannot fail for KM_SLEEP. */
	return (-1);
}

static void
xnf_buf_destructor(void *buf, void *arg)
{
	xnf_buf_t *bdesc = buf;
	xnf_t *xnfp = arg;

	(void) ddi_dma_unbind_handle(bdesc->dma_handle);
	ddi_dma_mem_free(&bdesc->acc_handle);
	ddi_dma_free_handle(&bdesc->dma_handle);

	atomic_dec_64(&xnfp->xnf_stat_buf_allocated);
}

static xnf_buf_t *
xnf_buf_get(xnf_t *xnfp, int flags, boolean_t readonly)
{
	grant_ref_t gref;
	xnf_buf_t *bufp;

	/*
	 * Usually grant references are more scarce than memory, so we
	 * attempt to acquire a grant reference first.
	 */
	gref = gref_get(xnfp);
	if (gref == INVALID_GRANT_REF)
		return (NULL);

	bufp = kmem_cache_alloc(xnfp->xnf_buf_cache, flags);
	if (bufp == NULL) {
		gref_put(xnfp, gref);
		return (NULL);
	}

	ASSERT(bufp->grant_ref == INVALID_GRANT_REF);

	bufp->grant_ref = gref;

	if (bufp->gen != xnfp->xnf_gen)
		xnf_buf_refresh(bufp);

	gnttab_grant_foreign_access_ref(bufp->grant_ref,
	    xvdi_get_oeid(bufp->xnfp->xnf_devinfo),
	    bufp->buf_mfn, readonly ? 1 : 0);

	atomic_inc_64(&xnfp->xnf_stat_buf_outstanding);

	return (bufp);
}

static void
xnf_buf_put(xnf_t *xnfp, xnf_buf_t *bufp, boolean_t readonly)
{
	if (bufp->grant_ref != INVALID_GRANT_REF) {
		(void) gnttab_end_foreign_access_ref(
		    bufp->grant_ref, readonly ? 1 : 0);
		gref_put(xnfp, bufp->grant_ref);
		bufp->grant_ref = INVALID_GRANT_REF;
	}

	kmem_cache_free(xnfp->xnf_buf_cache, bufp);

	atomic_dec_64(&xnfp->xnf_stat_buf_outstanding);
}

/*
 * Refresh any cached data about a buffer after resume.
 */
static void
xnf_buf_refresh(xnf_buf_t *bdesc)
{
	bdesc->buf_mfn = pfn_to_mfn(xnf_btop(bdesc->buf_phys));
	bdesc->gen = bdesc->xnfp->xnf_gen;
}

/*
 * Streams `freeb' routine for `xnf_buf_t' when used as transmit
 * look-aside buffers.
 */
static void
xnf_buf_recycle(xnf_buf_t *bdesc)
{
	xnf_t *xnfp = bdesc->xnfp;

	xnf_buf_put(xnfp, bdesc, B_TRUE);
}

static int
xnf_tx_buf_constructor(void *buf, void *arg, int kmflag)
{
	int (*ddiflags)(caddr_t) = DDI_DMA_SLEEP;
	xnf_txbuf_t *txp = buf;
	xnf_t *xnfp = arg;

	if (kmflag & KM_NOSLEEP)
		ddiflags = DDI_DMA_DONTWAIT;

	if (ddi_dma_alloc_handle(xnfp->xnf_devinfo, &buf_dma_attr,
	    ddiflags, 0, &txp->tx_dma_handle) != DDI_SUCCESS) {
		ASSERT(kmflag & KM_NOSLEEP); /* Cannot fail for KM_SLEEP. */
		return (-1);
	}

	return (0);
}

static void
xnf_tx_buf_destructor(void *buf, void *arg)
{
	_NOTE(ARGUNUSED(arg));
	xnf_txbuf_t *txp = buf;

	ddi_dma_free_handle(&txp->tx_dma_handle);
}

/*
 * Statistics.
 */
static char *xnf_aux_statistics[] = {
	"tx_cksum_deferred",
	"rx_cksum_no_need",
	"interrupts",
	"unclaimed_interrupts",
	"tx_pullup",
	"tx_pagebndry",
	"tx_attempt",
	"buf_allocated",
	"buf_outstanding",
	"gref_outstanding",
	"gref_failure",
	"gref_peak",
	"rx_allocb_fail",
	"rx_desballoc_fail",
};

static int
xnf_kstat_aux_update(kstat_t *ksp, int flag)
{
	xnf_t *xnfp;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	xnfp = ksp->ks_private;
	knp = ksp->ks_data;

	/*
	 * Assignment order must match that of the names in
	 * xnf_aux_statistics.
	 */
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_cksum_deferred;
	(knp++)->value.ui64 = xnfp->xnf_stat_rx_cksum_no_need;

	(knp++)->value.ui64 = xnfp->xnf_stat_interrupts;
	(knp++)->value.ui64 = xnfp->xnf_stat_unclaimed_interrupts;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_pullup;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_pagebndry;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_attempt;

	(knp++)->value.ui64 = xnfp->xnf_stat_buf_allocated;
	(knp++)->value.ui64 = xnfp->xnf_stat_buf_outstanding;
	(knp++)->value.ui64 = xnfp->xnf_stat_gref_outstanding;
	(knp++)->value.ui64 = xnfp->xnf_stat_gref_failure;
	(knp++)->value.ui64 = xnfp->xnf_stat_gref_peak;
	(knp++)->value.ui64 = xnfp->xnf_stat_rx_allocb_fail;
	(knp++)->value.ui64 = xnfp->xnf_stat_rx_desballoc_fail;

	return (0);
}

static boolean_t
xnf_kstat_init(xnf_t *xnfp)
{
	int nstat = sizeof (xnf_aux_statistics) /
	    sizeof (xnf_aux_statistics[0]);
	char **cp = xnf_aux_statistics;
	kstat_named_t *knp;

	/*
	 * Create and initialise kstats.
	 */
	if ((xnfp->xnf_kstat_aux = kstat_create("xnf",
	    ddi_get_instance(xnfp->xnf_devinfo),
	    "aux_statistics", "net", KSTAT_TYPE_NAMED,
	    nstat, 0)) == NULL)
		return (B_FALSE);

	xnfp->xnf_kstat_aux->ks_private = xnfp;
	xnfp->xnf_kstat_aux->ks_update = xnf_kstat_aux_update;

	knp = xnfp->xnf_kstat_aux->ks_data;
	while (nstat > 0) {
		kstat_named_init(knp, *cp, KSTAT_DATA_UINT64);

		knp++;
		cp++;
		nstat--;
	}

	kstat_install(xnfp->xnf_kstat_aux);

	return (B_TRUE);
}

static int
xnf_stat(void *arg, uint_t stat, uint64_t *val)
{
	xnf_t *xnfp = arg;

	mutex_enter(&xnfp->xnf_rxlock);
	mutex_enter(&xnfp->xnf_txlock);

#define	mac_stat(q, r)				\
	case (MAC_STAT_##q):			\
		*val = xnfp->xnf_stat_##r;	\
		break

#define	ether_stat(q, r)			\
	case (ETHER_STAT_##q):			\
		*val = xnfp->xnf_stat_##r;	\
		break

	switch (stat) {

	mac_stat(IPACKETS, ipackets);
	mac_stat(OPACKETS, opackets);
	mac_stat(RBYTES, rbytes);
	mac_stat(OBYTES, obytes);
	mac_stat(NORCVBUF, norxbuf);
	mac_stat(IERRORS, errrx);
	mac_stat(NOXMTBUF, tx_defer);

	ether_stat(MACRCV_ERRORS, mac_rcv_error);
	ether_stat(TOOSHORT_ERRORS, runt);

	/* always claim to be in full duplex mode */
	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;

	/* always claim to be at 1Gb/s link speed */
	case MAC_STAT_IFSPEED:
		*val = 1000000000ull;
		break;

	default:
		mutex_exit(&xnfp->xnf_txlock);
		mutex_exit(&xnfp->xnf_rxlock);

		return (ENOTSUP);
	}

#undef mac_stat
#undef ether_stat

	mutex_exit(&xnfp->xnf_txlock);
	mutex_exit(&xnfp->xnf_rxlock);

	return (0);
}

static boolean_t
xnf_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	_NOTE(ARGUNUSED(arg));

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *capab = cap_data;

		/*
		 * Whilst the flag used to communicate with the IO
		 * domain is called "NETTXF_csum_blank", the checksum
		 * in the packet must contain the pseudo-header
		 * checksum and not zero.
		 *
		 * To help out the IO domain, we might use
		 * HCKSUM_INET_PARTIAL. Unfortunately our stack will
		 * then use checksum offload for IPv6 packets, which
		 * the IO domain can't handle.
		 *
		 * As a result, we declare outselves capable of
		 * HCKSUM_INET_FULL_V4. This means that we receive
		 * IPv4 packets from the stack with a blank checksum
		 * field and must insert the pseudo-header checksum
		 * before passing the packet to the IO domain.
		 */
		*capab = HCKSUM_INET_FULL_V4;
		break;
	}
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * The state of the peer has changed - react accordingly.
 */
static void
oe_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data)
{
	_NOTE(ARGUNUSED(id, arg));
	xnf_t *xnfp = ddi_get_driver_private(dip);
	XenbusState new_state = *(XenbusState *)impl_data;

	ASSERT(xnfp != NULL);

	switch (new_state) {
	case XenbusStateUnknown:
	case XenbusStateInitialising:
	case XenbusStateInitialised:
	case XenbusStateClosing:
	case XenbusStateClosed:
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
		break;

	case XenbusStateInitWait:
		xnf_read_config(xnfp);

		if (!xnfp->xnf_be_rx_copy) {
			cmn_err(CE_WARN,
			    "The xnf driver requires a dom0 that "
			    "supports 'feature-rx-copy'.");
			(void) xvdi_switch_state(xnfp->xnf_devinfo,
			    XBT_NULL, XenbusStateClosed);
			break;
		}

		/*
		 * Connect to the backend.
		 */
		xnf_be_connect(xnfp);

		/*
		 * Our MAC address as discovered by xnf_read_config().
		 */
		mac_unicst_update(xnfp->xnf_mh, xnfp->xnf_mac_addr);

		break;

	case XenbusStateConnected:
		mutex_enter(&xnfp->xnf_rxlock);
		mutex_enter(&xnfp->xnf_txlock);

		xnfp->xnf_connected = B_TRUE;
		/*
		 * Wake up any threads waiting to send data to
		 * backend.
		 */
		cv_broadcast(&xnfp->xnf_cv_state);

		mutex_exit(&xnfp->xnf_txlock);
		mutex_exit(&xnfp->xnf_rxlock);

		/*
		 * Kick the peer in case it missed any transmits
		 * request in the TX ring.
		 */
		ec_notify_via_evtchn(xnfp->xnf_evtchn);

		/*
		 * There may already be completed receive requests in
		 * the ring sent by backend after it gets connected
		 * but before we see its state change here, so we call
		 * xnf_intr() to handle them, if any.
		 */
		(void) xnf_intr((caddr_t)xnfp);

		/*
		 * Mark the link up now that we are connected.
		 */
		mac_link_update(xnfp->xnf_mh, LINK_STATE_UP);

		/*
		 * Tell the backend about the multicast addresses in
		 * which we are interested.
		 */
		mac_multicast_refresh(xnfp->xnf_mh, NULL, xnfp, B_TRUE);

		break;

	default:
		break;
	}
}

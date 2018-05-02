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
 * Copyright (c) 2014, 2017 by Delphix. All rights reserved.
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
#include <inet/tcp.h>
#include <netinet/udp.h>
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

/*
 * The parameters below should only be changed in /etc/system, never in mdb.
 */

/*
 * Should we use the multicast control feature if the backend provides
 * it?
 */
boolean_t xnf_multicast_control = B_TRUE;

/*
 * Should we allow scatter-gather for tx if backend allows it?
 */
boolean_t xnf_enable_tx_sg = B_TRUE;

/*
 * Should we allow scatter-gather for rx if backend allows it?
 */
boolean_t xnf_enable_rx_sg = B_TRUE;

/*
 * Should we allow lso for tx sends if backend allows it?
 * Requires xnf_enable_tx_sg to be also set to TRUE.
 */
boolean_t xnf_enable_lso = B_TRUE;

/*
 * Should we allow lro on rx if backend supports it?
 * Requires xnf_enable_rx_sg to be also set to TRUE.
 *
 * !! WARNING !!
 * LRO is not yet supported in the OS so this should be left as FALSE.
 * !! WARNING !!
 */
boolean_t xnf_enable_lro = B_FALSE;

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
#define	TX_ID_VALID(i) \
	(((i) != INVALID_TX_ID) && ((i) < NET_TX_RING_SIZE))

/*
 * calculate how many pages are spanned by an mblk fragment
 */
#define	xnf_mblk_pages(mp)	(MBLKL(mp) == 0 ? 0 : \
    xnf_btop((uintptr_t)mp->b_wptr - 1) - xnf_btop((uintptr_t)mp->b_rptr) + 1)

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
static int xnf_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static int xnf_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void xnf_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

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

static grant_ref_t xnf_gref_get(xnf_t *);
#pragma inline(xnf_gref_get)
static void xnf_gref_put(xnf_t *, grant_ref_t);
#pragma inline(xnf_gref_put)

static xnf_txid_t *xnf_txid_get(xnf_t *);
#pragma inline(xnf_txid_get)
static void xnf_txid_put(xnf_t *, xnf_txid_t *);
#pragma inline(xnf_txid_put)

static void xnf_rxbuf_hang(xnf_t *, xnf_buf_t *);
static int xnf_tx_clean_ring(xnf_t  *);
static void oe_state_change(dev_info_t *, ddi_eventcookie_t,
    void *, void *);
static boolean_t xnf_kstat_init(xnf_t *);
static void xnf_rx_collect(xnf_t *);

#define	XNF_CALLBACK_FLAGS	(MC_GETCAPAB | MC_PROPERTIES)

static mac_callbacks_t xnf_callbacks = {
	.mc_callbacks = XNF_CALLBACK_FLAGS,
	.mc_getstat = xnf_stat,
	.mc_start = xnf_start,
	.mc_stop = xnf_stop,
	.mc_setpromisc = xnf_set_promiscuous,
	.mc_multicst = xnf_set_multicast,
	.mc_unicst = xnf_set_mac_addr,
	.mc_tx = xnf_send,
	.mc_getcapab = xnf_getcapab,
	.mc_setprop = xnf_setprop,
	.mc_getprop = xnf_getprop,
	.mc_propinfo = xnf_propinfo,
};

/* DMA attributes for network ring buffer */
static ddi_dma_attr_t ringbuf_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = 0xffffffffffffffffULL,
	.dma_attr_count_max = 0x7fffffff,
	.dma_attr_align = MMU_PAGESIZE,
	.dma_attr_burstsizes = 0x7ff,
	.dma_attr_minxfer = 1,
	.dma_attr_maxxfer = 0xffffffffU,
	.dma_attr_seg = 0xffffffffffffffffULL,
	.dma_attr_sgllen = 1,
	.dma_attr_granular = 1,
	.dma_attr_flags = 0
};

/* DMA attributes for receive data */
static ddi_dma_attr_t rx_buf_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = 0xffffffffffffffffULL,
	.dma_attr_count_max = MMU_PAGEOFFSET,
	.dma_attr_align = MMU_PAGESIZE, /* allocation alignment */
	.dma_attr_burstsizes = 0x7ff,
	.dma_attr_minxfer = 1,
	.dma_attr_maxxfer = 0xffffffffU,
	.dma_attr_seg = 0xffffffffffffffffULL,
	.dma_attr_sgllen = 1,
	.dma_attr_granular = 1,
	.dma_attr_flags = 0
};

/* DMA attributes for transmit data */
static ddi_dma_attr_t tx_buf_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = 0xffffffffffffffffULL,
	.dma_attr_count_max = MMU_PAGEOFFSET,
	.dma_attr_align = 1,
	.dma_attr_burstsizes = 0x7ff,
	.dma_attr_minxfer = 1,
	.dma_attr_maxxfer = 0xffffffffU,
	.dma_attr_seg = XEN_DATA_BOUNDARY - 1, /* segment boundary */
	.dma_attr_sgllen = XEN_MAX_TX_DATA_PAGES, /* max number of segments */
	.dma_attr_granular = 1,
	.dma_attr_flags = 0
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
xnf_gref_get(xnf_t *xnfp)
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
xnf_gref_put(xnf_t *xnfp, grant_ref_t gref)
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
xnf_txid_get(xnf_t *xnfp)
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
xnf_txid_put(xnf_t *xnfp, xnf_txid_t *tidp)
{
	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));
	ASSERT(TX_ID_VALID(tidp->id));
	ASSERT(tidp->next == INVALID_TX_ID);

	tidp->txbuf = NULL;
	tidp->next = xnfp->xnf_tx_pkt_id_head;
	xnfp->xnf_tx_pkt_id_head = tidp->id;
}

static void
xnf_data_txbuf_free(xnf_t *xnfp, xnf_txbuf_t *txp)
{
	ASSERT3U(txp->tx_type, ==, TX_DATA);

	/*
	 * We are either using a lookaside buffer or we are mapping existing
	 * buffers.
	 */
	if (txp->tx_bdesc != NULL) {
		ASSERT(!txp->tx_handle_bound);
		xnf_buf_put(xnfp, txp->tx_bdesc, B_TRUE);
	} else {
		if (txp->tx_txreq.gref != INVALID_GRANT_REF) {
			if (gnttab_query_foreign_access(txp->tx_txreq.gref) !=
			    0) {
				cmn_err(CE_PANIC, "tx grant %d still in use by "
				    "backend domain", txp->tx_txreq.gref);
			}
			(void) gnttab_end_foreign_access_ref(
			    txp->tx_txreq.gref, 1);
			xnf_gref_put(xnfp, txp->tx_txreq.gref);
		}

		if (txp->tx_handle_bound)
			(void) ddi_dma_unbind_handle(txp->tx_dma_handle);
	}

	if (txp->tx_mp != NULL)
		freemsg(txp->tx_mp);

	if (txp->tx_prev != NULL) {
		ASSERT3P(txp->tx_prev->tx_next, ==, txp);
		txp->tx_prev->tx_next = NULL;
	}

	if (txp->tx_txreq.id != INVALID_TX_ID) {
		/*
		 * This should be only possible when resuming from a suspend.
		 */
		ASSERT(!xnfp->xnf_connected);
		xnf_txid_put(xnfp, TX_ID_TO_TXID(xnfp, txp->tx_txreq.id));
		txp->tx_txreq.id = INVALID_TX_ID;
	}

	kmem_cache_free(xnfp->xnf_tx_buf_cache, txp);
}

static void
xnf_data_txbuf_free_chain(xnf_t *xnfp, xnf_txbuf_t *txp)
{
	if (txp == NULL)
		return;

	while (txp->tx_next != NULL)
		txp = txp->tx_next;

	/*
	 * We free the chain in reverse order so that grants can be released
	 * for all dma chunks before unbinding the dma handles. The mblk is
	 * freed last, after all its fragments' dma handles are unbound.
	 */
	xnf_txbuf_t *prev;
	for (; txp != NULL; txp = prev) {
		prev = txp->tx_prev;
		xnf_data_txbuf_free(xnfp, txp);
	}
}

static xnf_txbuf_t *
xnf_data_txbuf_alloc(xnf_t *xnfp)
{
	xnf_txbuf_t *txp = kmem_cache_alloc(xnfp->xnf_tx_buf_cache, KM_SLEEP);
	txp->tx_type = TX_DATA;
	txp->tx_next = NULL;
	txp->tx_prev = NULL;
	txp->tx_head = txp;
	txp->tx_frags_to_ack = 0;
	txp->tx_mp = NULL;
	txp->tx_bdesc = NULL;
	txp->tx_handle_bound = B_FALSE;
	txp->tx_txreq.gref = INVALID_GRANT_REF;
	txp->tx_txreq.id = INVALID_TX_ID;

	return (txp);
}

/*
 * Get `wanted' slots in the transmit ring, waiting for at least that
 * number if `wait' is B_TRUE. Force the ring to be cleaned by setting
 * `wanted' to zero.
 *
 * Return the number of slots available.
 */
static int
xnf_tx_slots_get(xnf_t *xnfp, int wanted, boolean_t wait)
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
	 * We first cleanup the TX ring in case we are doing a resume.
	 * Note that this can lose packets, but we expect to stagger on.
	 */
	xnfp->xnf_tx_pkt_id_head = INVALID_TX_ID; /* I.e. emtpy list. */
	for (i = 0, tidp = &xnfp->xnf_tx_pkt_id[0];
	    i < NET_TX_RING_SIZE;
	    i++, tidp++) {
		xnf_txbuf_t *txp = tidp->txbuf;
		if (txp == NULL)
			continue;

		switch (txp->tx_type) {
		case TX_DATA:
			/*
			 * txid_put() will be called for each txbuf's txid in
			 * the chain which will result in clearing tidp->txbuf.
			 */
			xnf_data_txbuf_free_chain(xnfp, txp);

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
			ASSERT3U(i, <, NET_TX_RING_SIZE);
			break;

		case TX_MCAST_RSP:
			break;
		}
	}

	/*
	 * Now purge old list and add each txid to the new free list.
	 */
	xnfp->xnf_tx_pkt_id_head = INVALID_TX_ID; /* I.e. emtpy list. */
	for (i = 0, tidp = &xnfp->xnf_tx_pkt_id[0];
	    i < NET_TX_RING_SIZE;
	    i++, tidp++) {
		tidp->id = i;
		ASSERT3P(tidp->txbuf, ==, NULL);
		tidp->next = INVALID_TX_ID; /* Appease txid_put(). */
		xnf_txid_put(xnfp, tidp);
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

	/*
	 * Tell backend if we support scatter-gather lists on the rx side.
	 */
	err = xenbus_printf(xbt, xsname, "feature-sg", "%d",
	    xnf_enable_rx_sg ? 1 : 0);
	if (err != 0) {
		message = "writing feature-sg";
		goto abort_transaction;
	}

	/*
	 * Tell backend if we support LRO for IPv4. Scatter-gather on rx is
	 * a prerequisite.
	 */
	err = xenbus_printf(xbt, xsname, "feature-gso-tcpv4", "%d",
	    (xnf_enable_rx_sg && xnf_enable_lro) ? 1 : 0);
	if (err != 0) {
		message = "writing feature-gso-tcpv4";
		goto abort_transaction;
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

	/*
	 * See if back-end supports scatter-gather for transmits. If not,
	 * we will not support LSO and limit the mtu to 1500.
	 */
	err = xenbus_scanf(XBT_NULL, oename, "feature-sg", "%d", &be_cap);
	if (err != 0) {
		be_cap = 0;
		dev_err(xnfp->xnf_devinfo, CE_WARN, "error reading "
		    "'feature-sg' from backend driver");
	}
	if (be_cap == 0) {
		dev_err(xnfp->xnf_devinfo, CE_WARN, "scatter-gather is not "
		    "supported for transmits in the backend driver. LSO is "
		    "disabled and MTU is restricted to 1500 bytes.");
	}
	xnfp->xnf_be_tx_sg = (be_cap != 0) && xnf_enable_tx_sg;

	if (xnfp->xnf_be_tx_sg) {
		/*
		 * Check if LSO is supported. Currently we only check for
		 * IPv4 as Illumos doesn't support LSO for IPv6.
		 */
		err = xenbus_scanf(XBT_NULL, oename, "feature-gso-tcpv4", "%d",
		    &be_cap);
		if (err != 0) {
			be_cap = 0;
			dev_err(xnfp->xnf_devinfo, CE_WARN, "error reading "
			    "'feature-gso-tcpv4' from backend driver");
		}
		if (be_cap == 0) {
			dev_err(xnfp->xnf_devinfo, CE_WARN, "LSO is not "
			    "supported by the backend driver. Performance "
			    "will be affected.");
		}
		xnfp->xnf_be_lso = (be_cap != 0) && xnf_enable_lso;
	}
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

	xnfp->xnf_tx_pkt_id =
	    kmem_zalloc(sizeof (xnf_txid_t) * NET_TX_RING_SIZE, KM_SLEEP);

	xnfp->xnf_rx_pkt_info =
	    kmem_zalloc(sizeof (xnf_buf_t *) * NET_RX_RING_SIZE, KM_SLEEP);

	macp->m_dip = devinfo;
	macp->m_driver = xnfp;
	xnfp->xnf_devinfo = devinfo;

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_src_addr = xnfp->xnf_mac_addr;
	macp->m_callbacks = &xnf_callbacks;
	macp->m_min_sdu = 0;
	xnfp->xnf_mtu = ETHERMTU;
	macp->m_max_sdu = xnfp->xnf_mtu;

	xnfp->xnf_running = B_FALSE;
	xnfp->xnf_connected = B_FALSE;
	xnfp->xnf_be_rx_copy = B_FALSE;
	xnfp->xnf_be_mcast_control = B_FALSE;
	xnfp->xnf_need_sched = B_FALSE;

	xnfp->xnf_rx_head = NULL;
	xnfp->xnf_rx_tail = NULL;
	xnfp->xnf_rx_new_buffers_posted = B_FALSE;

#ifdef XPV_HVM_DRIVER
	/* Report our version to dom0 */
	(void) xenbus_printf(XBT_NULL, "guest/xnf", "version", "%d",
	    HVMPV_XNF_VERS);
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

	n_slots = xnf_tx_slots_get(xnfp, 2, B_TRUE);
	ASSERT(n_slots >= 2);

	slot = xnfp->xnf_tx_ring.req_prod_pvt;
	tidp = xnf_txid_get(xnfp);
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
		cv_wait(&xnfp->xnf_cv_multicast, &xnfp->xnf_txlock);

	ASSERT3U(txp->tx_type, ==, TX_MCAST_RSP);

	mutex_enter(&xnfp->xnf_schedlock);
	xnfp->xnf_pending_multicast--;
	mutex_exit(&xnfp->xnf_schedlock);

	result = (txp->tx_status == NETIF_RSP_OKAY);

	xnf_txid_put(xnfp, tidp);

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
			/*
			 * if this slot was occupied by netif_extra_info_t,
			 * then the response will be NETIF_RSP_NULL. In this
			 * case there are no resources to clean up.
			 */
			if (trp->status == NETIF_RSP_NULL)
				continue;

			ASSERT(TX_ID_VALID(trp->id));

			tidp = TX_ID_TO_TXID(xnfp, trp->id);
			ASSERT3U(tidp->id, ==, trp->id);
			ASSERT3U(tidp->next, ==, INVALID_TX_ID);

			txp = tidp->txbuf;
			ASSERT(txp != NULL);
			ASSERT3U(txp->tx_txreq.id, ==, trp->id);

			switch (txp->tx_type) {
			case TX_DATA:
				/*
				 * We must put the txid for each response we
				 * acknowledge to make sure that we never have
				 * more free slots than txids. Because of this
				 * we do it here instead of waiting for it to
				 * be done in xnf_data_txbuf_free_chain().
				 */
				xnf_txid_put(xnfp, tidp);
				txp->tx_txreq.id = INVALID_TX_ID;
				ASSERT3S(txp->tx_head->tx_frags_to_ack, >, 0);
				txp->tx_head->tx_frags_to_ack--;

				/*
				 * We clean the whole chain once we got a
				 * response for each fragment.
				 */
				if (txp->tx_head->tx_frags_to_ack == 0)
					xnf_data_txbuf_free_chain(xnfp, txp);

				break;

			case TX_MCAST_REQ:
				txp->tx_type = TX_MCAST_RSP;
				txp->tx_status = trp->status;
				cv_broadcast(&xnfp->xnf_cv_multicast);

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
xnf_tx_get_lookaside(xnf_t *xnfp, mblk_t *mp, size_t *plen)
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

	*plen = bp - bd->buf;
	ASSERT3U(*plen, <=, PAGESIZE);

	xnfp->xnf_stat_tx_lookaside++;

	return (bd);
}

/*
 * Insert the pseudo-header checksum into the packet.
 * Assumes packet is IPv4, TCP/UDP since we only advertised support for
 * HCKSUM_INET_FULL_V4.
 */
int
xnf_pseudo_cksum(mblk_t *mp)
{
	struct ether_header *ehp;
	uint16_t sap, iplen, *stuff;
	uint32_t cksum;
	size_t len;
	ipha_t *ipha;
	ipaddr_t src, dst;
	uchar_t *ptr;

	ptr = mp->b_rptr;
	len = MBLKL(mp);

	/* Each header must fit completely in an mblk. */
	ASSERT3U(len, >=, sizeof (*ehp));

	ehp = (struct ether_header *)ptr;

	if (ntohs(ehp->ether_type) == VLAN_TPID) {
		struct ether_vlan_header *evhp;
		ASSERT3U(len, >=, sizeof (*evhp));
		evhp = (struct ether_vlan_header *)ptr;
		sap = ntohs(evhp->ether_type);
		ptr += sizeof (*evhp);
		len -= sizeof (*evhp);
	} else {
		sap = ntohs(ehp->ether_type);
		ptr += sizeof (*ehp);
		len -= sizeof (*ehp);
	}

	ASSERT3U(sap, ==, ETHERTYPE_IP);

	/*
	 * Ethernet and IP headers may be in different mblks.
	 */
	ASSERT3P(ptr, <=, mp->b_wptr);
	if (ptr == mp->b_wptr) {
		mp = mp->b_cont;
		ptr = mp->b_rptr;
		len = MBLKL(mp);
	}

	ASSERT3U(len, >=, sizeof (ipha_t));
	ipha = (ipha_t *)ptr;

	/*
	 * We assume the IP header has no options. (This is enforced in
	 * ire_send_wire_v4() -- search for IXAF_NO_HW_CKSUM).
	 */
	ASSERT3U(IPH_HDR_LENGTH(ipha), ==, IP_SIMPLE_HDR_LENGTH);
	iplen = ntohs(ipha->ipha_length) - IP_SIMPLE_HDR_LENGTH;

	ptr += IP_SIMPLE_HDR_LENGTH;
	len -= IP_SIMPLE_HDR_LENGTH;

	/*
	 * IP and L4 headers may be in different mblks.
	 */
	ASSERT3P(ptr, <=, mp->b_wptr);
	if (ptr == mp->b_wptr) {
		mp = mp->b_cont;
		ptr = mp->b_rptr;
		len = MBLKL(mp);
	}

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP:
		ASSERT3U(len, >=, sizeof (tcph_t));
		stuff = (uint16_t *)(ptr + TCP_CHECKSUM_OFFSET);
		cksum = IP_TCP_CSUM_COMP;
		break;
	case IPPROTO_UDP:
		ASSERT3U(len, >=, sizeof (struct udphdr));
		stuff = (uint16_t *)(ptr + UDP_CHECKSUM_OFFSET);
		cksum = IP_UDP_CSUM_COMP;
		break;
	default:
		cmn_err(CE_WARN, "xnf_pseudo_cksum: unexpected protocol %d",
		    ipha->ipha_protocol);
		return (EINVAL);
	}

	src = ipha->ipha_src;
	dst = ipha->ipha_dst;

	cksum += (dst >> 16) + (dst & 0xFFFF);
	cksum += (src >> 16) + (src & 0xFFFF);
	cksum += htons(iplen);

	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum = (cksum >> 16) + (cksum & 0xFFFF);

	ASSERT(cksum <= 0xFFFF);

	*stuff = (uint16_t)(cksum ? cksum : ~cksum);

	return (0);
}

/*
 * Push a packet into the transmit ring.
 *
 * Note: the format of a tx packet that spans multiple slots is similar to
 * what is described in xnf_rx_one_packet().
 */
static void
xnf_tx_push_packet(xnf_t *xnfp, xnf_txbuf_t *head)
{
	int nslots = 0;
	int extras = 0;
	RING_IDX slot;
	boolean_t notify;

	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));
	ASSERT(xnfp->xnf_running);

	slot = xnfp->xnf_tx_ring.req_prod_pvt;

	/*
	 * The caller has already checked that we have enough slots to proceed.
	 */
	for (xnf_txbuf_t *txp = head; txp != NULL; txp = txp->tx_next) {
		xnf_txid_t *tidp;
		netif_tx_request_t *txrp;

		tidp = xnf_txid_get(xnfp);
		VERIFY(tidp != NULL);
		txrp = RING_GET_REQUEST(&xnfp->xnf_tx_ring, slot);

		txp->tx_slot = slot;
		txp->tx_txreq.id = tidp->id;
		*txrp = txp->tx_txreq;

		tidp->txbuf = txp;
		slot++;
		nslots++;

		/*
		 * When present, LSO info is placed in a slot after the first
		 * data segment, and doesn't require a txid.
		 */
		if (txp->tx_txreq.flags & NETTXF_extra_info) {
			netif_extra_info_t *extra;
			ASSERT3U(nslots, ==, 1);

			extra = (netif_extra_info_t *)
			    RING_GET_REQUEST(&xnfp->xnf_tx_ring, slot);
			*extra = txp->tx_extra;
			slot++;
			nslots++;
			extras = 1;
		}
	}

	ASSERT3U(nslots, <=, XEN_MAX_SLOTS_PER_TX);

	/*
	 * Store the number of data fragments.
	 */
	head->tx_frags_to_ack = nslots - extras;

	xnfp->xnf_tx_ring.req_prod_pvt = slot;

	/*
	 * Tell the peer that we sent something, if it cares.
	 */
	/* LINTED: constant in conditional context */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xnfp->xnf_tx_ring, notify);
	if (notify)
		ec_notify_via_evtchn(xnfp->xnf_evtchn);
}

static xnf_txbuf_t *
xnf_mblk_copy(xnf_t *xnfp, mblk_t *mp)
{
	xnf_txbuf_t *txp = xnf_data_txbuf_alloc(xnfp);
	size_t length;

	txp->tx_bdesc = xnf_tx_get_lookaside(xnfp, mp, &length);
	if (txp->tx_bdesc == NULL) {
		xnf_data_txbuf_free(xnfp, txp);
		return (NULL);
	}
	txp->tx_mfn = txp->tx_bdesc->buf_mfn;
	txp->tx_txreq.gref = txp->tx_bdesc->grant_ref;
	txp->tx_txreq.size = length;
	txp->tx_txreq.offset = (uintptr_t)txp->tx_bdesc->buf & PAGEOFFSET;
	txp->tx_txreq.flags = 0;

	return (txp);
}

static xnf_txbuf_t *
xnf_mblk_map(xnf_t *xnfp, mblk_t *mp, int *countp)
{
	xnf_txbuf_t *head = NULL;
	xnf_txbuf_t *tail = NULL;
	domid_t oeid;
	int nsegs = 0;

	oeid = xvdi_get_oeid(xnfp->xnf_devinfo);

	for (mblk_t *ml = mp; ml != NULL; ml = ml->b_cont) {
		ddi_dma_handle_t dma_handle;
		ddi_dma_cookie_t dma_cookie;
		uint_t ncookies;
		xnf_txbuf_t *txp;

		if (MBLKL(ml) == 0)
			continue;

		txp = xnf_data_txbuf_alloc(xnfp);

		if (head == NULL) {
			head = txp;
		} else {
			ASSERT(tail != NULL);
			TXBUF_SETNEXT(tail, txp);
			txp->tx_head = head;
		}

		/*
		 * The necessary segmentation rules (e.g. not crossing a page
		 * boundary) are enforced by the dma attributes of the handle.
		 */
		dma_handle = txp->tx_dma_handle;
		int ret = ddi_dma_addr_bind_handle(dma_handle,
		    NULL, (char *)ml->b_rptr, MBLKL(ml),
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT, 0, &dma_cookie,
		    &ncookies);
		if (ret != DDI_DMA_MAPPED) {
			if (ret != DDI_DMA_NORESOURCES) {
				dev_err(xnfp->xnf_devinfo, CE_WARN,
				    "ddi_dma_addr_bind_handle() failed "
				    "[dma_error=%d]", ret);
			}
			goto error;
		}
		txp->tx_handle_bound = B_TRUE;

		ASSERT(ncookies > 0);
		for (int i = 0; i < ncookies; i++) {
			if (nsegs == XEN_MAX_TX_DATA_PAGES) {
				dev_err(xnfp->xnf_devinfo, CE_WARN,
				    "xnf_dmamap_alloc() failed: "
				    "too many segments");
				goto error;
			}
			if (i > 0) {
				txp = xnf_data_txbuf_alloc(xnfp);
				ASSERT(tail != NULL);
				TXBUF_SETNEXT(tail, txp);
				txp->tx_head = head;
			}

			txp->tx_mfn =
			    xnf_btop(pa_to_ma(dma_cookie.dmac_laddress));
			txp->tx_txreq.gref = xnf_gref_get(xnfp);
			if (txp->tx_txreq.gref == INVALID_GRANT_REF) {
				dev_err(xnfp->xnf_devinfo, CE_WARN,
				    "xnf_dmamap_alloc() failed: "
				    "invalid grant ref");
				goto error;
			}
			gnttab_grant_foreign_access_ref(txp->tx_txreq.gref,
			    oeid, txp->tx_mfn, 1);
			txp->tx_txreq.offset =
			    dma_cookie.dmac_laddress & PAGEOFFSET;
			txp->tx_txreq.size = dma_cookie.dmac_size;
			txp->tx_txreq.flags = 0;

			ddi_dma_nextcookie(dma_handle, &dma_cookie);
			nsegs++;

			if (tail != NULL)
				tail->tx_txreq.flags = NETTXF_more_data;
			tail = txp;
		}
	}

	*countp = nsegs;
	return (head);

error:
	xnf_data_txbuf_free_chain(xnfp, head);
	return (NULL);
}

static void
xnf_tx_setup_offload(xnf_t *xnfp, xnf_txbuf_t *head,
    uint32_t cksum_flags, uint32_t lso_flags, uint32_t mss)
{
	if (lso_flags != 0) {
		ASSERT3U(lso_flags, ==, HW_LSO);
		ASSERT3P(head->tx_bdesc, ==, NULL);

		head->tx_txreq.flags |= NETTXF_extra_info;
		netif_extra_info_t *extra = &head->tx_extra;
		extra->type = XEN_NETIF_EXTRA_TYPE_GSO;
		extra->flags = 0;
		extra->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
		extra->u.gso.size = mss;
		extra->u.gso.features = 0;
		extra->u.gso.pad = 0;
	} else if (cksum_flags != 0) {
		ASSERT3U(cksum_flags, ==, HCK_FULLCKSUM);
		/*
		 * If the local protocol stack requests checksum
		 * offload we set the 'checksum blank' flag,
		 * indicating to the peer that we need the checksum
		 * calculated for us.
		 *
		 * We _don't_ set the validated flag, because we haven't
		 * validated that the data and the checksum match.
		 *
		 * Note: we already called xnf_pseudo_cksum() in
		 * xnf_send(), so we just set the txreq flag here.
		 */
		head->tx_txreq.flags |= NETTXF_csum_blank;
		xnfp->xnf_stat_tx_cksum_deferred++;
	}
}

/*
 * Send packet mp. Called by the MAC framework.
 */
static mblk_t *
xnf_send(void *arg, mblk_t *mp)
{
	xnf_t *xnfp = arg;
	xnf_txbuf_t *head;
	mblk_t *ml;
	int length;
	int pages, chunks, slots, slots_free;
	uint32_t cksum_flags, lso_flags, mss;
	boolean_t pulledup = B_FALSE;
	boolean_t force_copy = B_FALSE;

	ASSERT3P(mp->b_next, ==, NULL);

	mutex_enter(&xnfp->xnf_txlock);

	/*
	 * Wait until we are connected to the backend.
	 */
	while (!xnfp->xnf_connected)
		cv_wait(&xnfp->xnf_cv_state, &xnfp->xnf_txlock);

	/*
	 * To simplify logic and be in sync with the rescheduling mechanism,
	 * we require the maximum amount of slots that could be used by a
	 * transaction to be free before proceeding. The only downside of doing
	 * this is that it slightly reduces the effective size of the ring.
	 */
	slots_free = xnf_tx_slots_get(xnfp, XEN_MAX_SLOTS_PER_TX, B_FALSE);
	if (slots_free < XEN_MAX_SLOTS_PER_TX) {
		/*
		 * We need to ask for a re-schedule later as the ring is full.
		 */
		mutex_enter(&xnfp->xnf_schedlock);
		xnfp->xnf_need_sched = B_TRUE;
		mutex_exit(&xnfp->xnf_schedlock);

		xnfp->xnf_stat_tx_defer++;
		mutex_exit(&xnfp->xnf_txlock);
		return (mp);
	}

	/*
	 * Get hw offload parameters.
	 * This must be done before pulling up the mp as those parameters
	 * are not copied over.
	 */
	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &cksum_flags);
	mac_lso_get(mp, &mss, &lso_flags);

	/*
	 * XXX: fix MAC framework so that we can advertise support for
	 * partial checksum for IPv4 only. This way we won't need to calculate
	 * the pseudo header checksum ourselves.
	 */
	if (cksum_flags != 0) {
		ASSERT3U(cksum_flags, ==, HCK_FULLCKSUM);
		(void) xnf_pseudo_cksum(mp);
	}

pulledup:
	for (ml = mp, pages = 0, chunks = 0, length = 0; ml != NULL;
	    ml = ml->b_cont, chunks++) {
		pages += xnf_mblk_pages(ml);
		length += MBLKL(ml);
	}
	DTRACE_PROBE3(packet, int, length, int, chunks, int, pages);
	DTRACE_PROBE3(lso, int, length, uint32_t, lso_flags, uint32_t, mss);

	/*
	 * If the ethernet header crosses a page boundary the packet
	 * will be dropped by the backend. In practice it seems like
	 * this happens fairly rarely so we'll do nothing unless the
	 * packet is small enough to fit in a look-aside buffer.
	 */
	if (((uintptr_t)mp->b_rptr & PAGEOFFSET) +
	    sizeof (struct ether_header) > PAGESIZE) {
		xnfp->xnf_stat_tx_eth_hdr_split++;
		if (length <= PAGESIZE)
			force_copy = B_TRUE;
	}

	if (force_copy || (pages > 1 && !xnfp->xnf_be_tx_sg)) {
		/*
		 * If the packet spans several pages and scatter-gather is not
		 * supported then use a look-aside buffer.
		 */
		ASSERT3U(length, <=, PAGESIZE);
		head = xnf_mblk_copy(xnfp, mp);
		if (head == NULL) {
			dev_err(xnfp->xnf_devinfo, CE_WARN,
			    "xnf_mblk_copy() failed");
			goto drop;
		}
	} else {
		/*
		 * There's a limit for how many pages can be passed to the
		 * backend. If we pass that limit, the packet will be dropped
		 * and some backend implementations (e.g. Linux) could even
		 * offline the interface.
		 */
		if (pages > XEN_MAX_TX_DATA_PAGES) {
			if (pulledup) {
				dev_err(xnfp->xnf_devinfo, CE_WARN,
				    "too many pages, even after pullup: %d.",
				    pages);
				goto drop;
			}

			/*
			 * Defragment packet if it spans too many pages.
			 */
			mblk_t *newmp = msgpullup(mp, -1);
			freemsg(mp);
			mp = newmp;
			xnfp->xnf_stat_tx_pullup++;
			pulledup = B_TRUE;
			goto pulledup;
		}

		head = xnf_mblk_map(xnfp, mp, &slots);
		if (head == NULL)
			goto drop;

		IMPLY(slots > 1, xnfp->xnf_be_tx_sg);
	}

	/*
	 * Set tx_mp so that mblk is freed when the txbuf chain is freed.
	 */
	head->tx_mp = mp;

	xnf_tx_setup_offload(xnfp, head, cksum_flags, lso_flags, mss);

	/*
	 * The first request must store the total length of the packet.
	 */
	head->tx_txreq.size = length;

	/*
	 * Push the packet we have prepared into the ring.
	 */
	xnf_tx_push_packet(xnfp, head);
	xnfp->xnf_stat_opackets++;
	xnfp->xnf_stat_obytes += length;

	mutex_exit(&xnfp->xnf_txlock);
	return (NULL);

drop:
	freemsg(mp);
	xnfp->xnf_stat_tx_drop++;
	mutex_exit(&xnfp->xnf_txlock);
	return (NULL);
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
		free_slots = xnf_tx_slots_get(xnfp, 0, B_FALSE);

		if (need_sched && (free_slots >= XEN_MAX_SLOTS_PER_TX)) {
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
 * Receive an entire packet from the ring, starting from slot *consp.
 * prod indicates the slot of the latest response.
 * On return, *consp will point to the head of the next packet.
 *
 * Note: If slot prod was reached before we could gather a full packet, we will
 * drop the partial packet; this would most likely indicate a bug in either
 * the front-end or the back-end driver.
 *
 * An rx packet can consist of several fragments and thus span multiple slots.
 * Each fragment can contain up to 4k of data.
 *
 * A typical 9000 MTU packet with look like this:
 * +------+---------------------+-------------------+-----------------------+
 * | SLOT | TYPE                | CONTENTS          | FLAGS                 |
 * +------+---------------------+-------------------+-----------------------+
 * | 1    | netif_rx_response_t | 1st data fragment | more_data             |
 * +------+---------------------+-------------------+-----------------------+
 * | 2    | netif_rx_response_t | 2nd data fragment | more_data             |
 * +------+---------------------+-------------------+-----------------------+
 * | 3    | netif_rx_response_t | 3rd data fragment | [none]                |
 * +------+---------------------+-------------------+-----------------------+
 *
 * Fragments are chained by setting NETRXF_more_data in the previous
 * response's flags. If there are additional flags, such as
 * NETRXF_data_validated or NETRXF_extra_info, those should be set on the
 * first fragment.
 *
 * Sometimes extra info can be present. If so, it will follow the first
 * fragment, and NETRXF_extra_info flag will be set on the first response.
 * If LRO is set on a packet, it will be stored in the extra info. Conforming
 * to the spec, extra info can also be chained, but must all be present right
 * after the first fragment.
 *
 * Example of a packet with 2 extra infos:
 * +------+---------------------+-------------------+-----------------------+
 * | SLOT | TYPE                | CONTENTS          | FLAGS                 |
 * +------+---------------------+-------------------+-----------------------+
 * | 1    | netif_rx_response_t | 1st data fragment | extra_info, more_data |
 * +------+---------------------+-------------------+-----------------------+
 * | 2    | netif_extra_info_t  | 1st extra info    | EXTRA_FLAG_MORE       |
 * +------+---------------------+-------------------+-----------------------+
 * | 3    | netif_extra_info_t  | 2nd extra info    | [none]                |
 * +------+---------------------+-------------------+-----------------------+
 * | 4    | netif_rx_response_t | 2nd data fragment | more_data             |
 * +------+---------------------+-------------------+-----------------------+
 * | 5    | netif_rx_response_t | 3rd data fragment | more_data             |
 * +------+---------------------+-------------------+-----------------------+
 * | 6    | netif_rx_response_t | 4th data fragment | [none]                |
 * +------+---------------------+-------------------+-----------------------+
 *
 * In practice, the only extra we expect is for LRO, but only if we advertise
 * that we support it to the backend (xnf_enable_lro == TRUE).
 */
static int
xnf_rx_one_packet(xnf_t *xnfp, RING_IDX prod, RING_IDX *consp, mblk_t **mpp)
{
	mblk_t *head = NULL;
	mblk_t *tail = NULL;
	mblk_t *mp;
	int error = 0;
	RING_IDX cons = *consp;
	netif_extra_info_t lro;
	boolean_t is_lro = B_FALSE;
	boolean_t is_extra = B_FALSE;

	netif_rx_response_t rsp = *RING_GET_RESPONSE(&xnfp->xnf_rx_ring, cons);

	boolean_t hwcsum = (rsp.flags & NETRXF_data_validated) != 0;
	boolean_t more_data = (rsp.flags & NETRXF_more_data) != 0;
	boolean_t more_extra = (rsp.flags & NETRXF_extra_info) != 0;

	IMPLY(more_data, xnf_enable_rx_sg);

	while (cons != prod) {
		xnf_buf_t *bdesc;
		int len, off;
		int rxidx = cons & (NET_RX_RING_SIZE - 1);

		bdesc = xnfp->xnf_rx_pkt_info[rxidx];
		xnfp->xnf_rx_pkt_info[rxidx] = NULL;

		if (is_extra) {
			netif_extra_info_t *extra = (netif_extra_info_t *)&rsp;
			/*
			 * The only extra we expect is for LRO, and it should
			 * only be present once.
			 */
			if (extra->type == XEN_NETIF_EXTRA_TYPE_GSO &&
			    !is_lro) {
				ASSERT(xnf_enable_lro);
				lro = *extra;
				is_lro = B_TRUE;
				DTRACE_PROBE1(lro, netif_extra_info_t *, &lro);
			} else {
				dev_err(xnfp->xnf_devinfo, CE_WARN, "rx packet "
				    "contains unexpected extra info of type %d",
				    extra->type);
				error = EINVAL;
			}
			more_extra =
			    (extra->flags & XEN_NETIF_EXTRA_FLAG_MORE) != 0;

			goto hang_buf;
		}

		ASSERT3U(bdesc->id, ==, rsp.id);

		/*
		 * status stores packet length when >= 0, or errors when < 0.
		 */
		len = rsp.status;
		off = rsp.offset;
		more_data = (rsp.flags & NETRXF_more_data) != 0;

		/*
		 * sanity checks.
		 */
		if (!xnfp->xnf_running) {
			error = EBUSY;
		} else if (len <= 0) {
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
			error = EINVAL;
		} else if (bdesc->grant_ref == INVALID_GRANT_REF) {
			dev_err(xnfp->xnf_devinfo, CE_WARN,
			    "Bad rx grant reference, rsp id %d", rsp.id);
			error = EINVAL;
		} else if ((off + len) > PAGESIZE) {
			dev_err(xnfp->xnf_devinfo, CE_WARN, "Rx packet crosses "
			    "page boundary (offset %d, length %d)", off, len);
			error = EINVAL;
		}

		if (error != 0) {
			/*
			 * If an error has been detected, we do not attempt
			 * to read the data but we still need to replace
			 * the rx bufs.
			 */
			goto hang_buf;
		}

		xnf_buf_t *nbuf = NULL;

		/*
		 * If the packet is below a pre-determined size we will
		 * copy data out of the buf rather than replace it.
		 */
		if (len > xnf_rx_copy_limit)
			nbuf = xnf_buf_get(xnfp, KM_NOSLEEP, B_FALSE);

		if (nbuf != NULL) {
			mp = desballoc((unsigned char *)bdesc->buf,
			    bdesc->len, 0, &bdesc->free_rtn);

			if (mp == NULL) {
				xnfp->xnf_stat_rx_desballoc_fail++;
				xnfp->xnf_stat_norxbuf++;
				error = ENOMEM;
				/*
				 * we free the buf we just allocated as we
				 * will re-hang the old buf.
				 */
				xnf_buf_put(xnfp, nbuf, B_FALSE);
				goto hang_buf;
			}

			mp->b_rptr = mp->b_rptr + off;
			mp->b_wptr = mp->b_rptr + len;

			/*
			 * Release the grant as the backend doesn't need to
			 * access this buffer anymore and grants are scarce.
			 */
			(void) gnttab_end_foreign_access_ref(bdesc->grant_ref,
			    0);
			xnf_gref_put(xnfp, bdesc->grant_ref);
			bdesc->grant_ref = INVALID_GRANT_REF;

			bdesc = nbuf;
		} else {
			/*
			 * We failed to allocate a new buf or decided to reuse
			 * the old one. In either case we copy the data off it
			 * and put it back into the ring.
			 */
			mp = allocb(len, 0);
			if (mp == NULL) {
				xnfp->xnf_stat_rx_allocb_fail++;
				xnfp->xnf_stat_norxbuf++;
				error = ENOMEM;
				goto hang_buf;
			}
			bcopy(bdesc->buf + off, mp->b_wptr, len);
			mp->b_wptr += len;
		}

		if (head == NULL)
			head = mp;
		else
			tail->b_cont = mp;
		tail = mp;

hang_buf:
		/*
		 * No matter what happens, for each response we need to hang
		 * a new buf on the rx ring. Put either the old one, or a new
		 * one if the old one is borrowed by the kernel via desballoc().
		 */
		xnf_rxbuf_hang(xnfp, bdesc);
		cons++;

		/* next response is an extra */
		is_extra = more_extra;

		if (!more_data && !more_extra)
			break;

		/*
		 * Note that since requests and responses are union'd on the
		 * same ring, we copy the response to a local variable instead
		 * of keeping a pointer. Otherwise xnf_rxbuf_hang() would have
		 * overwritten contents of rsp.
		 */
		rsp = *RING_GET_RESPONSE(&xnfp->xnf_rx_ring, cons);
	}

	/*
	 * Check that we do not get stuck in a loop.
	 */
	ASSERT3U(*consp, !=, cons);
	*consp = cons;

	/*
	 * We ran out of responses but the flags indicate there is more data.
	 */
	if (more_data) {
		dev_err(xnfp->xnf_devinfo, CE_WARN, "rx: need more fragments.");
		error = EINVAL;
	}
	if (more_extra) {
		dev_err(xnfp->xnf_devinfo, CE_WARN, "rx: need more fragments "
		    "(extras).");
		error = EINVAL;
	}

	/*
	 * An error means the packet must be dropped. If we have already formed
	 * a partial packet, then discard it.
	 */
	if (error != 0) {
		if (head != NULL)
			freemsg(head);
		xnfp->xnf_stat_rx_drop++;
		return (error);
	}

	ASSERT(head != NULL);

	if (hwcsum) {
		/*
		 * If the peer says that the data has been validated then we
		 * declare that the full checksum has been verified.
		 *
		 * We don't look at the "checksum blank" flag, and hence could
		 * have a packet here that we are asserting is good with
		 * a blank checksum.
		 */
		mac_hcksum_set(head, 0, 0, 0, 0, HCK_FULLCKSUM_OK);
		xnfp->xnf_stat_rx_cksum_no_need++;
	}

	/* XXX: set lro info for packet once LRO is supported in OS. */

	*mpp = head;

	return (0);
}

/*
 * Collect packets from the RX ring, storing them in `xnfp' for later use.
 */
static void
xnf_rx_collect(xnf_t *xnfp)
{
	RING_IDX prod;

	ASSERT(MUTEX_HELD(&xnfp->xnf_rxlock));

	prod = xnfp->xnf_rx_ring.sring->rsp_prod;
	/*
	 * Ensure we see queued responses up to 'prod'.
	 */
	membar_consumer();

	while (xnfp->xnf_rx_ring.rsp_cons != prod) {
		mblk_t *mp;

		/*
		 * Collect a packet.
		 * rsp_cons is updated inside xnf_rx_one_packet().
		 */
		int error = xnf_rx_one_packet(xnfp, prod,
		    &xnfp->xnf_rx_ring.rsp_cons, &mp);
		if (error == 0) {
			xnfp->xnf_stat_ipackets++;
			xnfp->xnf_stat_rbytes += xmsgsize(mp);

			/*
			 * Append the mblk to the rx list.
			 */
			if (xnfp->xnf_rx_head == NULL) {
				ASSERT3P(xnfp->xnf_rx_tail, ==, NULL);
				xnfp->xnf_rx_head = mp;
			} else {
				ASSERT(xnfp->xnf_rx_tail != NULL);
				xnfp->xnf_rx_tail->b_next = mp;
			}
			xnfp->xnf_rx_tail = mp;
		}
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

			xnf_txid_put(xnfp, tidp);
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
	if (ddi_dma_alloc_handle(xnfp->xnf_devinfo, &rx_buf_dma_attr,
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
	gref = xnf_gref_get(xnfp);
	if (gref == INVALID_GRANT_REF)
		return (NULL);

	bufp = kmem_cache_alloc(xnfp->xnf_buf_cache, flags);
	if (bufp == NULL) {
		xnf_gref_put(xnfp, gref);
		return (NULL);
	}

	ASSERT3U(bufp->grant_ref, ==, INVALID_GRANT_REF);

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
		xnf_gref_put(xnfp, bufp->grant_ref);
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

	if (ddi_dma_alloc_handle(xnfp->xnf_devinfo, &tx_buf_dma_attr,
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
	"tx_lookaside",
	"tx_drop",
	"tx_eth_hdr_split",
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
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_lookaside;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_drop;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_eth_hdr_split;

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

static int
xnf_change_mtu(xnf_t *xnfp, uint32_t mtu)
{
	if (mtu > ETHERMTU) {
		if (!xnf_enable_tx_sg) {
			dev_err(xnfp->xnf_devinfo, CE_WARN, "MTU limited to %d "
			    "because scatter-gather is disabled for transmit "
			    "in driver settings", ETHERMTU);
			return (EINVAL);
		} else if (!xnf_enable_rx_sg) {
			dev_err(xnfp->xnf_devinfo, CE_WARN, "MTU limited to %d "
			    "because scatter-gather is disabled for receive "
			    "in driver settings", ETHERMTU);
			return (EINVAL);
		} else if (!xnfp->xnf_be_tx_sg) {
			dev_err(xnfp->xnf_devinfo, CE_WARN, "MTU limited to %d "
			    "because backend doesn't support scatter-gather",
			    ETHERMTU);
			return (EINVAL);
		}
		if (mtu > XNF_MAXPKT)
			return (EINVAL);
	}
	int error = mac_maxsdu_update(xnfp->xnf_mh, mtu);
	if (error == 0)
		xnfp->xnf_mtu = mtu;

	return (error);
}

/*ARGSUSED*/
static int
xnf_getprop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size, void *prop_val)
{
	xnf_t *xnfp = data;

	switch (prop_id) {
	case MAC_PROP_MTU:
		ASSERT(prop_val_size >= sizeof (uint32_t));
		bcopy(&xnfp->xnf_mtu, prop_val, sizeof (uint32_t));
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

/*ARGSUSED*/
static int
xnf_setprop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size, const void *prop_val)
{
	xnf_t *xnfp = data;
	uint32_t new_mtu;
	int error;

	switch (prop_id) {
	case MAC_PROP_MTU:
		ASSERT(prop_val_size >= sizeof (uint32_t));
		bcopy(prop_val, &new_mtu, sizeof (new_mtu));
		error = xnf_change_mtu(xnfp, new_mtu);
		break;
	default:
		return (ENOTSUP);
	}

	return (error);
}

/*ARGSUSED*/
static void
xnf_propinfo(void *data, const char *prop_name, mac_prop_id_t prop_id,
    mac_prop_info_handle_t prop_handle)
{
	switch (prop_id) {
	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prop_handle, 0, XNF_MAXPKT);
		break;
	default:
		break;
	}
}

static boolean_t
xnf_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	xnf_t *xnfp = arg;

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

		/*
		 * TODO: query the "feature-ipv6-csum-offload" capability.
		 * If enabled, that could allow us to use HCKSUM_INET_PARTIAL.
		 */

		break;
	}
	case MAC_CAPAB_LSO: {
		if (!xnfp->xnf_be_lso)
			return (B_FALSE);

		mac_capab_lso_t *lso = cap_data;
		lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		lso->lso_basic_tcp_ipv4.lso_max = IP_MAXPACKET;
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

		/*
		 * We do not know if some features such as LSO are supported
		 * until we connect to the backend. We request the MAC layer
		 * to poll our capabilities again.
		 */
		mac_capab_update(xnfp->xnf_mh);

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

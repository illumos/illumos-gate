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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>

#include <sys/ib/clients/eoib/eib_impl.h>

/*
 * Declarations private to this file
 */
static int eib_rsrc_setup_txbufs(eib_t *, int *);
static int eib_rsrc_setup_rxbufs(eib_t *, int *);
static int eib_rsrc_setup_lsobufs(eib_t *, int *);
static void eib_rsrc_init_wqe_pool(eib_t *, eib_wqe_pool_t **,
    ib_memlen_t, int);
static void eib_rsrc_fini_wqe_pool(eib_t *, eib_wqe_pool_t **);
static boolean_t eib_rsrc_ok_to_free_pool(eib_t *, eib_wqe_pool_t *, boolean_t);
static int eib_rsrc_grab_wqes(eib_t *, eib_wqe_pool_t *, eib_wqe_t **, uint_t,
    uint_t *, int);
static void eib_rsrc_return_wqes(eib_t *, eib_wqe_pool_t *, eib_wqe_t **,
    uint_t);

static void eib_rb_rsrc_setup_txbufs(eib_t *, boolean_t);
static void eib_rb_rsrc_setup_rxbufs(eib_t *, boolean_t);
static void eib_rb_rsrc_setup_lsobufs(eib_t *, boolean_t);

/*
 * Definitions private to this file
 */
static uint_t eib_lso_num_bufs = EIB_LSO_NUM_BUFS;	/* tunable? */

int
eib_rsrc_setup_bufs(eib_t *ss, int *err)
{
	if (eib_rsrc_setup_txbufs(ss, err) != EIB_E_SUCCESS)
		return (EIB_E_FAILURE);

	if (ss->ei_caps->cp_lso_maxlen && ss->ei_caps->cp_cksum_flags &&
	    ss->ei_caps->cp_resv_lkey_capab) {
		if (eib_rsrc_setup_lsobufs(ss, err) != EIB_E_SUCCESS) {
			eib_rb_rsrc_setup_txbufs(ss, B_FALSE);
			return (EIB_E_FAILURE);
		}
	}

	if (eib_rsrc_setup_rxbufs(ss, err) != EIB_E_SUCCESS) {
		eib_rb_rsrc_setup_lsobufs(ss, B_FALSE);
		eib_rb_rsrc_setup_txbufs(ss, B_FALSE);
		return (EIB_E_FAILURE);
	}

	return (EIB_E_SUCCESS);
}

int
eib_rsrc_grab_swqes(eib_t *ss, eib_wqe_t **wqes, uint_t n_req, uint_t *actual,
    int pri)
{
	eib_wqe_t *wqe;
	uint32_t *encap_hdr;
	int ret;
	int i;

	ASSERT(ss->ei_tx != NULL);

	ret = eib_rsrc_grab_wqes(ss, ss->ei_tx, wqes, n_req, actual, pri);
	if (ret != EIB_E_SUCCESS)
		return (EIB_E_FAILURE);

	/*
	 * See note for eib_rsrc_grab_swqe()
	 */
	for (i = 0; i < (*actual); i++) {
		wqe = wqes[i];
		wqe->qe_wr.send.wr_flags = IBT_WR_NO_FLAGS;
		wqe->qe_wr.send.wr.ud.udwr_dest = wqe->qe_dest;
		wqe->qe_wr.send.wr_opcode = IBT_WRC_SEND;
		wqe->qe_wr.send.wr_nds = 1;
		wqe->qe_wr.send.wr_sgl = &wqe->qe_sgl;
		wqe->qe_nxt_post = NULL;
		wqe->qe_iov_hdl = NULL;

		encap_hdr = (uint32_t *)(void *)wqe->qe_payload_hdr;
		*encap_hdr = htonl(EIB_TX_ENCAP_HDR);
	}

	return (EIB_E_SUCCESS);
}

int
eib_rsrc_grab_rwqes(eib_t *ss, eib_wqe_t **wqes, uint_t n_req, uint_t *actual,
    int pri)
{
	ASSERT(ss->ei_rx != NULL);

	return (eib_rsrc_grab_wqes(ss, ss->ei_rx, wqes, n_req, actual, pri));
}

int
eib_rsrc_grab_lsobufs(eib_t *ss, uint_t req_sz, ibt_wr_ds_t *sgl, uint32_t *nds)
{
	eib_lsobkt_t *bkt = ss->ei_lso;
	eib_lsobuf_t *elem;
	eib_lsobuf_t *nxt;
	uint_t frag_sz;
	uint_t num_needed;
	int i;

	ASSERT(req_sz != 0);
	ASSERT(sgl != NULL);
	ASSERT(nds != NULL);

	/*
	 * Determine how many bufs we'd need for the size requested
	 */
	num_needed = req_sz / EIB_LSO_BUFSZ;
	if ((frag_sz = req_sz % EIB_LSO_BUFSZ) != 0)
		num_needed++;

	if (bkt == NULL)
		return (EIB_E_FAILURE);

	/*
	 * If we don't have enough lso bufs, return failure
	 */
	mutex_enter(&bkt->bk_lock);
	if (bkt->bk_nfree < num_needed) {
		mutex_exit(&bkt->bk_lock);
		return (EIB_E_FAILURE);
	}

	/*
	 * Pick the first "num_needed" bufs from the free list
	 */
	elem = bkt->bk_free_head;
	for (i = 0; i < num_needed; i++) {
		ASSERT(elem->lb_isfree != 0);
		ASSERT(elem->lb_buf != NULL);

		nxt = elem->lb_next;

		sgl[i].ds_va = (ib_vaddr_t)(uintptr_t)elem->lb_buf;
		sgl[i].ds_key = bkt->bk_lkey;
		sgl[i].ds_len = EIB_LSO_BUFSZ;

		elem->lb_isfree = 0;
		elem->lb_next = NULL;

		elem = nxt;
	}
	bkt->bk_free_head = elem;

	/*
	 * If the requested size is not a multiple of EIB_LSO_BUFSZ, we need
	 * to adjust the last sgl entry's length. Since we know we need atleast
	 * one, the i-1 use below is ok.
	 */
	if (frag_sz) {
		sgl[i-1].ds_len = frag_sz;
	}

	/*
	 * Update nfree count and return
	 */
	bkt->bk_nfree -= num_needed;

	mutex_exit(&bkt->bk_lock);

	*nds = num_needed;

	return (EIB_E_SUCCESS);
}

eib_wqe_t *
eib_rsrc_grab_swqe(eib_t *ss, int pri)
{
	eib_wqe_t *wqe = NULL;
	uint32_t *encap_hdr;

	ASSERT(ss->ei_tx != NULL);
	(void) eib_rsrc_grab_wqes(ss, ss->ei_tx, &wqe, 1, NULL, pri);

	/*
	 * Let's reset the swqe basic wr parameters to default. We need
	 * to do this because this swqe could've previously been used
	 * for a checksum offload (when the flags would've been set)
	 * or for an LSO send (in which case the opcode would've been set
	 * to a different value), or been iov mapped (in which case the
	 * sgl/nds could've been set to different values).  We'll make
	 * it easy and initialize it here, so simple transactions can
	 * go through without any special effort by the caller.
	 *
	 * Note that even though the wqe structure is common for both
	 * send and recv, they're in two independent pools and the wqe
	 * type remains the same throughout its lifetime. So we don't
	 * have to worry about resetting any other field.
	 */
	if (wqe) {
		wqe->qe_wr.send.wr_flags = IBT_WR_NO_FLAGS;
		wqe->qe_wr.send.wr.ud.udwr_dest = wqe->qe_dest;
		wqe->qe_wr.send.wr_opcode = IBT_WRC_SEND;
		wqe->qe_wr.send.wr_nds = 1;
		wqe->qe_wr.send.wr_sgl = &wqe->qe_sgl;
		wqe->qe_nxt_post = NULL;
		wqe->qe_iov_hdl = NULL;

		encap_hdr = (uint32_t *)(void *)wqe->qe_payload_hdr;
		*encap_hdr = htonl(EIB_TX_ENCAP_HDR);
	}

	return (wqe);
}

eib_wqe_t *
eib_rsrc_grab_rwqe(eib_t *ss, int pri)
{
	eib_wqe_t *wqe = NULL;

	ASSERT(ss->ei_rx != NULL);
	(void) eib_rsrc_grab_wqes(ss, ss->ei_rx, &wqe, 1, NULL, pri);

	return (wqe);
}

void
eib_rsrc_return_swqe(eib_t *ss, eib_wqe_t *wqe, eib_chan_t *chan)
{
	ASSERT(ss->ei_tx != NULL);

	eib_rsrc_return_wqes(ss, ss->ei_tx, &wqe, 1);
	if (chan) {
		eib_rsrc_decr_posted_swqe(ss, chan);
	}
}


void
eib_rsrc_return_rwqe(eib_t *ss, eib_wqe_t *wqe, eib_chan_t *chan)
{
	ASSERT(ss->ei_rx != NULL);

	eib_rsrc_return_wqes(ss, ss->ei_rx, &wqe, 1);
	if (chan) {
		eib_rsrc_decr_posted_rwqe(ss, chan);
	}
}

void
eib_rsrc_return_lsobufs(eib_t *ss, ibt_wr_ds_t *sgl_p, uint32_t nds)
{
	eib_lsobkt_t *bkt = ss->ei_lso;
	eib_lsobuf_t *elem;
	uint8_t *va;
	ptrdiff_t ndx;
	int i;

	/*
	 * Nowhere to return the buffers to ??
	 */
	if (bkt == NULL)
		return;

	mutex_enter(&bkt->bk_lock);

	for (i = 0; i < nds; i++) {
		va = (uint8_t *)(uintptr_t)sgl_p[i].ds_va;

		ASSERT(va >= bkt->bk_mem);
		ASSERT(va < (bkt->bk_mem + bkt->bk_nelem * EIB_LSO_BUFSZ));

		/*
		 * Figure out the buflist element this sgl buffer corresponds
		 * to and put it back at the head
		 */
		ndx = ((uintptr_t)va - (uintptr_t)bkt->bk_mem) / EIB_LSO_BUFSZ;
		elem = bkt->bk_bufl + ndx;

		ASSERT(elem->lb_isfree == 0);
		ASSERT(elem->lb_buf == va);

		elem->lb_isfree = 1;
		elem->lb_next = bkt->bk_free_head;
		bkt->bk_free_head = elem;
	}
	bkt->bk_nfree += nds;

	/*
	 * If the number of available lso buffers just crossed the
	 * threshold, wakeup anyone who may be sleeping on the event.
	 */
	if (((bkt->bk_nfree - nds) < EIB_LSO_FREE_BUFS_THRESH) &&
	    (bkt->bk_nfree >= EIB_LSO_FREE_BUFS_THRESH)) {
		cv_broadcast(&bkt->bk_cv);
	}

	mutex_exit(&bkt->bk_lock);
}

/*ARGSUSED*/
void
eib_rsrc_decr_posted_swqe(eib_t *ss, eib_chan_t *chan)
{
	ASSERT(chan != NULL);

	mutex_enter(&chan->ch_tx_lock);

	chan->ch_tx_posted--;
	if ((chan->ch_tear_down) && (chan->ch_tx_posted == 0)) {
		cv_signal(&chan->ch_tx_cv);
	}

	mutex_exit(&chan->ch_tx_lock);
}

void
eib_rsrc_decr_posted_rwqe(eib_t *ss, eib_chan_t *chan)
{
	eib_chan_t *tail;
	boolean_t queue_for_refill = B_FALSE;

	ASSERT(chan != NULL);

	/*
	 * Decrement the ch_rx_posted count. If we are tearing this channel
	 * down, signal the waiter when the count reaches 0.  If we aren't
	 * tearing the channel down, see if the count has gone below the low
	 * water mark.  If it has, and if this channel isn't already being
	 * refilled, queue the channel up with the service thread for a
	 * rwqe refill.
	 */
	mutex_enter(&chan->ch_rx_lock);
	chan->ch_rx_posted--;
	if (chan->ch_tear_down) {
		if (chan->ch_rx_posted == 0)
			cv_signal(&chan->ch_rx_cv);
	} else if (chan->ch_rx_posted < chan->ch_lwm_rwqes) {
		if (chan->ch_rx_refilling == B_FALSE) {
			chan->ch_rx_refilling = B_TRUE;
			queue_for_refill = B_TRUE;
		}
	}
	mutex_exit(&chan->ch_rx_lock);

	if (queue_for_refill) {
		mutex_enter(&ss->ei_rxpost_lock);

		chan->ch_rxpost_next = NULL;
		for (tail = ss->ei_rxpost; tail; tail = tail->ch_rxpost_next) {
			if (tail->ch_rxpost_next == NULL)
				break;
		}
		if (tail) {
			tail->ch_rxpost_next = chan;
		} else {
			ss->ei_rxpost = chan;
		}

		cv_signal(&ss->ei_rxpost_cv);
		mutex_exit(&ss->ei_rxpost_lock);
	}
}

void
eib_rsrc_txwqes_needed(eib_t *ss)
{
	eib_wqe_pool_t *wp = ss->ei_tx;

	EIB_INCR_COUNTER(&ss->ei_stats->st_noxmitbuf);

	mutex_enter(&wp->wp_lock);
	if ((wp->wp_status & EIB_TXWQE_SHORT) == 0) {
		wp->wp_status |= EIB_TXWQE_SHORT;
		cv_broadcast(&wp->wp_cv);
	}
	mutex_exit(&wp->wp_lock);
}

void
eib_rsrc_lsobufs_needed(eib_t *ss)
{
	eib_lsobkt_t *bkt = ss->ei_lso;

	EIB_INCR_COUNTER(&ss->ei_stats->st_noxmitbuf);

	if (bkt == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance,
		    "eib_rsrc_lsobufs_needed: "
		    "lso bufs seem to be needed even though "
		    "LSO support was not advertised");
		return;
	}

	mutex_enter(&bkt->bk_lock);
	if ((bkt->bk_status & EIB_LBUF_SHORT) == 0) {
		bkt->bk_status |= EIB_LBUF_SHORT;
		cv_broadcast(&bkt->bk_cv);
	}
	mutex_exit(&bkt->bk_lock);
}

boolean_t
eib_rsrc_rxpool_low(eib_wqe_t *wqe)
{
	eib_wqe_pool_t *wp = wqe->qe_pool;
	boolean_t ret = B_FALSE;

	/*
	 * Set the EIB_RXWQE_SHORT flag when the number of free wqes
	 * in the rx pool falls below the low threshold for rwqes and
	 * clear it only when the number of free wqes gets back above
	 * the high water mark.
	 */
	mutex_enter(&wp->wp_lock);

	if (wp->wp_nfree <= EIB_NFREE_RWQES_LOW) {
		wp->wp_status |= (EIB_RXWQE_SHORT);
	} else if (wp->wp_nfree >= EIB_NFREE_RWQES_HWM) {
		wp->wp_status &= (~EIB_RXWQE_SHORT);
	}

	if ((wp->wp_status & EIB_RXWQE_SHORT) == EIB_RXWQE_SHORT)
		ret = B_TRUE;

	mutex_exit(&wp->wp_lock);

	return (ret);
}

void
eib_rb_rsrc_setup_bufs(eib_t *ss, boolean_t force)
{
	eib_rb_rsrc_setup_rxbufs(ss, force);
	eib_rb_rsrc_setup_lsobufs(ss, force);
	eib_rb_rsrc_setup_txbufs(ss, force);
}

static int
eib_rsrc_setup_txbufs(eib_t *ss, int *err)
{
	eib_wqe_pool_t *tx;
	eib_wqe_t *wqe;
	ibt_ud_dest_hdl_t dest;
	ibt_mr_attr_t attr;
	ibt_mr_desc_t desc;
	ibt_status_t ret;
	kthread_t *kt;
	uint32_t *encap_hdr;
	uint8_t	*buf;
	uint_t mtu = ss->ei_props->ep_mtu;
	uint_t tx_bufsz;
	uint_t blk;
	uint_t ndx;
	uint_t i;
	int lso_enabled;

	/*
	 * Try to allocate and initialize the tx wqe pool
	 */
	if (ss->ei_tx != NULL)
		return (EIB_E_SUCCESS);

	/*
	 * If we keep the tx buffers as mtu-sized, then potentially every
	 * LSO request that cannot be satisfactorily mapped, will use up
	 * the 8K large (default size) lso buffers. This may be inadvisable
	 * given that lso buffers are a scarce resource.  Instead, we'll
	 * slightly raise the size of the copy buffers in the send wqes
	 * (say to EIB_TX_COPY_THRESH) so that requests that cannot be
	 * mapped could still avoid using the 8K LSO buffers if they're
	 * less than the copy threshold size.
	 */
	lso_enabled = ss->ei_caps->cp_lso_maxlen &&
	    ss->ei_caps->cp_cksum_flags && ss->ei_caps->cp_resv_lkey_capab;
	tx_bufsz = ((lso_enabled) && (EIB_TX_COPY_THRESH > mtu)) ?
	    EIB_TX_COPY_THRESH : mtu;

	eib_rsrc_init_wqe_pool(ss, &ss->ei_tx, tx_bufsz, EIB_WP_TYPE_TX);
	tx = ss->ei_tx;

	/*
	 * Register the TX memory region with IBTF for use
	 */
	attr.mr_vaddr = tx->wp_vaddr;
	attr.mr_len = tx->wp_memsz;
	attr.mr_as = NULL;
	attr.mr_flags = IBT_MR_SLEEP;

	ret = ibt_register_mr(ss->ei_hca_hdl, ss->ei_pd_hdl, &attr,
	    &tx->wp_mr, &desc);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_rsrc_setup_txbufs: "
		    "ibt_register_mr() failed for tx "
		    "region (0x%llx, 0x%llx) with ret=%d",
		    attr.mr_vaddr, attr.mr_len, ret);

		*err = EINVAL;
		goto rsrc_setup_txbufs_fail;
	}
	tx->wp_lkey = desc.md_lkey;

	/*
	 * Now setup the tx wqes
	 */
	buf = (uint8_t *)(uintptr_t)(tx->wp_vaddr);
	for (i = 0, blk = 0; blk < EIB_BLKS_PER_POOL; blk++) {
		for (ndx = 0; ndx < EIB_WQES_PER_BLK; ndx++, i++) {
			wqe = &tx->wp_wqe[i];
			/*
			 * Allocate a UD destination handle
			 */
			ret = ibt_alloc_ud_dest(ss->ei_hca_hdl,
			    IBT_UD_DEST_NO_FLAGS, ss->ei_pd_hdl, &dest);
			if (ret != IBT_SUCCESS) {
				EIB_DPRINTF_ERR(ss->ei_instance,
				    "eib_rsrc_setup_txbufs: "
				    "ibt_alloc_ud_dest(hca_hdl=0x%llx) "
				    "failed, ret=%d", ss->ei_hca_hdl, ret);

				*err = ENOMEM;
				goto rsrc_setup_txbufs_fail;
			}

			/*
			 * These parameters should remain fixed throughout the
			 * lifetime of this wqe.
			 */
			wqe->qe_pool = tx;
			wqe->qe_cpbuf = buf;
			wqe->qe_bufsz = tx_bufsz;

			/*
			 * The qe_dest and qe_payload_hdr are specific to tx
			 * only, but remain unchanged throughout the lifetime
			 * of the wqe.
			 *
			 * The payload header is normally used when we have an
			 * LSO packet to send.  Since the EoIB encapsulation
			 * header won't be part of the message we get from the
			 * network layer, we'll need to copy the lso header into
			 * a new buffer every time before we hand over the LSO
			 * send request to the hca driver.
			 */
			wqe->qe_dest = dest;
			wqe->qe_payload_hdr =
			    kmem_zalloc(EIB_MAX_PAYLOAD_HDR_SZ, KM_SLEEP);

			/*
			 * The encapsulation header is at the start of the
			 * payload header and is initialized to the default
			 * encapsulation header we use (no multiple segments,
			 * no FCS). This part of the header is not expected
			 * to change.
			 */
			encap_hdr = (uint32_t *)(void *)wqe->qe_payload_hdr;
			*encap_hdr = htonl(EIB_TX_ENCAP_HDR);

			/*
			 * The parameter set below are used in tx and rx paths.
			 * These parameters (except ds_key) are reset to these
			 * default values in eib_rsrc_return_wqes().
			 */
			wqe->qe_sgl.ds_key = tx->wp_lkey;
			wqe->qe_sgl.ds_va = (ib_vaddr_t)(uintptr_t)buf;
			wqe->qe_sgl.ds_len = wqe->qe_bufsz;
			wqe->qe_mp = NULL;
			wqe->qe_info =
			    ((blk & EIB_WQEBLK_MASK) << EIB_WQEBLK_SHIFT) |
			    ((ndx & EIB_WQENDX_MASK) << EIB_WQENDX_SHIFT) |
			    ((uint_t)EIB_WQE_TX << EIB_WQETYP_SHIFT);

			/*
			 * These tx-specific parameters (except wr_id and
			 * wr_trans) are reset in eib_rsrc_grab_swqes() to make
			 * sure any freshly acquired swqe from the pool has
			 * these default settings for the caller.
			 */
			wqe->qe_wr.send.wr_id = (ibt_wrid_t)(uintptr_t)wqe;
			wqe->qe_wr.send.wr_trans = IBT_UD_SRV;
			wqe->qe_wr.send.wr_flags = IBT_WR_NO_FLAGS;
			wqe->qe_wr.send.wr.ud.udwr_dest = wqe->qe_dest;
			wqe->qe_wr.send.wr_opcode = IBT_WRC_SEND;
			wqe->qe_wr.send.wr_nds = 1;
			wqe->qe_wr.send.wr_sgl = &wqe->qe_sgl;
			wqe->qe_nxt_post = NULL;
			wqe->qe_iov_hdl = NULL;

			buf += wqe->qe_bufsz;
		}
	}

	/*
	 * Before returning, create a kernel thread to monitor the status
	 * of wqes in the tx wqe pool.  Note that this thread cannot be
	 * created from eib_state_init() during attach(), since the thread
	 * expects the wqe pool to be allocated and ready when it starts,
	 * and the tx bufs initialization only happens during eib_m_start().
	 */
	kt = thread_create(NULL, 0, eib_monitor_tx_wqes, ss, 0,
	    &p0, TS_RUN, minclsyspri);
	ss->ei_txwqe_monitor = kt->t_did;

	return (EIB_E_SUCCESS);

rsrc_setup_txbufs_fail:
	eib_rb_rsrc_setup_txbufs(ss, B_FALSE);
	return (EIB_E_FAILURE);
}

static int
eib_rsrc_setup_rxbufs(eib_t *ss, int *err)
{
	eib_wqe_pool_t *rx;
	eib_wqe_t *wqe;
	ibt_mr_attr_t attr;
	ibt_mr_desc_t desc;
	ibt_status_t ret;
	uint8_t	*buf;
	uint_t mtu = ss->ei_props->ep_mtu;
	uint_t blk;
	uint_t ndx;
	uint_t i;

	/*
	 * Try to allocate and initialize the wqe pool. When this is called
	 * during a plumb via the mac m_start callback, we need to make
	 * sure there is a need to allocate a wqe pool afresh.  If during a
	 * previous unplumb we didn't free the wqe pool because the nw layer
	 * was holding on to some rx buffers, we don't need to allocate new
	 * pool and set up the buffers again; we'll just start re-using the
	 * previous one.
	 */
	if (ss->ei_rx != NULL)
		return (EIB_E_SUCCESS);

	/*
	 * The receive buffer has to work for all channels, specifically the
	 * data qp of the vnics.  This means that the buffer must be large
	 * enough to hold MTU sized IB payload (including the EoIB and ethernet
	 * headers) plus the GRH. In addition, because the ethernet header is
	 * either 14 or 18 bytes (tagless or vlan tagged), we should have the
	 * buffer filled in such a way that the IP header starts at atleast a
	 * 4-byte aligned address.  In order to do this, we need to have some
	 * additional room.
	 */
	eib_rsrc_init_wqe_pool(ss, &ss->ei_rx,
	    mtu + EIB_GRH_SZ + EIB_IPHDR_ALIGN_ROOM, EIB_WP_TYPE_RX);
	rx = ss->ei_rx;

	/*
	 * Register the RX memory region with IBTF for use
	 */
	attr.mr_vaddr = rx->wp_vaddr;
	attr.mr_len = rx->wp_memsz;
	attr.mr_as = NULL;
	attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;

	ret = ibt_register_mr(ss->ei_hca_hdl, ss->ei_pd_hdl, &attr,
	    &rx->wp_mr, &desc);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_rsrc_setup_rxbufs: "
		    "ibt_register_mr() failed for rx "
		    "region (0x%llx, 0x%llx) with ret=%d",
		    attr.mr_vaddr, attr.mr_len, ret);

		*err = EINVAL;
		goto rsrc_setup_rxbufs_fail;
	}
	rx->wp_lkey = desc.md_lkey;

	/*
	 * Now setup the rx wqes
	 */
	buf = (uint8_t *)(uintptr_t)(rx->wp_vaddr);
	for (i = 0, blk = 0; blk < EIB_BLKS_PER_POOL; blk++) {
		for (ndx = 0; ndx < EIB_WQES_PER_BLK; ndx++, i++) {
			wqe = &rx->wp_wqe[i];

			/*
			 * These parameters should remain fixed throughout the
			 * lifetime of this recv wqe. The qe_frp will only be
			 * used by the data channel of vnics and will remain
			 * unused by other channels.
			 */
			wqe->qe_pool = rx;
			wqe->qe_cpbuf = buf;
			wqe->qe_bufsz = mtu + EIB_GRH_SZ + EIB_IPHDR_ALIGN_ROOM;
			wqe->qe_wr.recv.wr_id = (ibt_wrid_t)(uintptr_t)wqe;
			wqe->qe_wr.recv.wr_nds = 1;
			wqe->qe_wr.recv.wr_sgl = &wqe->qe_sgl;
			wqe->qe_frp.free_func = eib_data_rx_recycle;
			wqe->qe_frp.free_arg = (caddr_t)wqe;

			/*
			 * The parameter set below are used in tx and rx paths.
			 * These parameters (except ds_key) are reset to these
			 * default values in eib_rsrc_return_wqes().
			 */
			wqe->qe_sgl.ds_key = rx->wp_lkey;
			wqe->qe_sgl.ds_va = (ib_vaddr_t)(uintptr_t)buf;
			wqe->qe_sgl.ds_len = wqe->qe_bufsz;
			wqe->qe_mp = NULL;
			wqe->qe_info =
			    ((blk & EIB_WQEBLK_MASK) << EIB_WQEBLK_SHIFT) |
			    ((ndx & EIB_WQENDX_MASK) << EIB_WQENDX_SHIFT) |
			    ((uint_t)EIB_WQE_RX << EIB_WQETYP_SHIFT);

			/*
			 * These rx-specific parameters are also reset to
			 * these default values in eib_rsrc_return_wqes().
			 */
			wqe->qe_chan = NULL;
			wqe->qe_vnic_inst = -1;

			buf += (mtu + EIB_GRH_SZ + EIB_IPHDR_ALIGN_ROOM);
		}
	}

	return (EIB_E_SUCCESS);

rsrc_setup_rxbufs_fail:
	eib_rb_rsrc_setup_rxbufs(ss, B_FALSE);
	return (EIB_E_FAILURE);
}

static int
eib_rsrc_setup_lsobufs(eib_t *ss, int *err)
{
	eib_lsobkt_t *bkt;
	eib_lsobuf_t *elem;
	eib_lsobuf_t *tail;
	ibt_mr_attr_t attr;
	ibt_mr_desc_t desc;
	kthread_t *kt;

	uint8_t *lsomem;
	uint8_t *memp;
	ibt_status_t ret;
	int i;

	/*
	 * Allocate the lso bucket and space for buffers
	 */
	bkt = kmem_zalloc(sizeof (eib_lsobkt_t), KM_SLEEP);
	lsomem = kmem_zalloc(eib_lso_num_bufs * EIB_LSO_BUFSZ, KM_SLEEP);

	/*
	 * Register lso memory and save the lkey
	 */
	attr.mr_vaddr = (uint64_t)(uintptr_t)lsomem;
	attr.mr_len = eib_lso_num_bufs * EIB_LSO_BUFSZ;
	attr.mr_as = NULL;
	attr.mr_flags = IBT_MR_SLEEP;

	ret = ibt_register_mr(ss->ei_hca_hdl, ss->ei_pd_hdl, &attr,
	    &bkt->bk_mr_hdl, &desc);
	if (ret != IBT_SUCCESS) {
		*err = EINVAL;
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_rsrc_setup_lsobufs: "
		    "ibt_register_mr() failed for LSO "
		    "region (0x%llx, 0x%llx) with ret=%d",
		    attr.mr_vaddr, attr.mr_len, ret);

		kmem_free(lsomem, eib_lso_num_bufs * EIB_LSO_BUFSZ);
		kmem_free(bkt, sizeof (eib_lsobkt_t));

		return (EIB_E_FAILURE);
	}
	bkt->bk_lkey = desc.md_lkey;

	/*
	 * Now allocate the buflist.  Note that the elements in the buflist and
	 * the buffers in the lso memory have a permanent 1-1 relation, so we
	 * can always derive the address of a buflist entry from the address of
	 * an lso buffer.
	 */
	bkt->bk_bufl = kmem_zalloc(eib_lso_num_bufs * sizeof (eib_lsobuf_t),
	    KM_SLEEP);

	/*
	 * Set up the lso buf chain
	 */
	memp = lsomem;
	elem = bkt->bk_bufl;
	for (i = 0; i < eib_lso_num_bufs; i++) {
		elem->lb_isfree = 1;
		elem->lb_buf = memp;
		elem->lb_next = elem + 1;

		tail = elem;

		memp += EIB_LSO_BUFSZ;
		elem++;
	}
	tail->lb_next = NULL;

	/*
	 * Set up the LSO buffer information in eib state
	 */
	bkt->bk_free_head = bkt->bk_bufl;
	bkt->bk_mem = lsomem;
	bkt->bk_nelem = eib_lso_num_bufs;
	bkt->bk_nfree = bkt->bk_nelem;

	mutex_init(&bkt->bk_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&bkt->bk_cv, NULL, CV_DEFAULT, NULL);

	ss->ei_lso = bkt;

	/*
	 * Before returning, create a kernel thread to monitor the status
	 * of lso bufs
	 */
	kt = thread_create(NULL, 0, eib_monitor_lso_bufs, ss, 0,
	    &p0, TS_RUN, minclsyspri);
	ss->ei_lsobufs_monitor = kt->t_did;

	return (EIB_E_SUCCESS);
}

static void
eib_rsrc_init_wqe_pool(eib_t *ss, eib_wqe_pool_t **wpp, ib_memlen_t bufsz,
    int wp_type)
{
	eib_wqe_pool_t *wp;
	uint_t wp_wqesz;
	int i;

	ASSERT(wpp != NULL);
	ASSERT(*wpp == NULL);

	/*
	 * Allocate the wqe pool, wqes and bufs
	 */
	wp = kmem_zalloc(sizeof (eib_wqe_pool_t), KM_SLEEP);
	wp_wqesz = EIB_WQES_PER_POOL * sizeof (eib_wqe_t);
	wp->wp_wqe = (eib_wqe_t *)kmem_zalloc(wp_wqesz, KM_SLEEP);
	wp->wp_memsz = EIB_WQES_PER_POOL * bufsz;
	wp->wp_vaddr = (ib_vaddr_t)(uintptr_t)kmem_zalloc(wp->wp_memsz,
	    KM_SLEEP);
	wp->wp_ss = ss;
	wp->wp_type = wp_type;
	wp->wp_nfree_lwm = (wp_type == EIB_WP_TYPE_TX) ?
	    EIB_NFREE_SWQES_LWM : EIB_NFREE_RWQES_LWM;

	/*
	 * Initialize the lock and bitmaps: everything is available at first,
	 * but note that if the number of blocks per pool is less than 64, we
	 * need to initialize those extra bits as "unavailable" - these will
	 * remain unavailable throughout.
	 */
	mutex_init(&wp->wp_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&wp->wp_cv, NULL, CV_DEFAULT, NULL);

	wp->wp_nfree = EIB_WQES_PER_POOL;
	wp->wp_free_blks = (EIB_BLKS_PER_POOL >= 64) ? (~0) :
	    (((uint64_t)1 << EIB_BLKS_PER_POOL) - 1);
	for (i = 0; i < EIB_BLKS_PER_POOL; i++)
		wp->wp_free_wqes[i] = ~0;

	*wpp = wp;
}

/*ARGSUSED*/
static void
eib_rsrc_fini_wqe_pool(eib_t *ss, eib_wqe_pool_t **wpp)
{
	eib_wqe_pool_t *wp;

	ASSERT(wpp != NULL);

	wp = *wpp;
	ASSERT(*wpp != NULL);

	cv_destroy(&wp->wp_cv);
	mutex_destroy(&wp->wp_lock);

	kmem_free((void *)(uintptr_t)(wp->wp_vaddr), wp->wp_memsz);
	kmem_free(wp->wp_wqe, EIB_WQES_PER_POOL * sizeof (eib_wqe_t));
	kmem_free(wp, sizeof (eib_wqe_pool_t));

	*wpp = NULL;
}

/*ARGSUSED*/
static boolean_t
eib_rsrc_ok_to_free_pool(eib_t *ss, eib_wqe_pool_t *wp, boolean_t force)
{
	uint64_t free_blks;
	int i;

	/*
	 * See if we can release all memory allocated for buffers, wqes and
	 * the pool.  Note that in the case of data channel rx buffers, some
	 * of the buffers may not be free if the nw layer is holding on to
	 * them still.  If this is the case, we cannot free the wqe pool now
	 * or a subsequent access by the nw layer to the buffers will cause
	 * a panic.
	 */
	ASSERT(wp != NULL);

	/*
	 * If force-free flag is set, we can always release the memory.
	 * Note that this flag is unused currently, and should be removed.
	 */
	if (force == B_TRUE)
		return (B_TRUE);

	mutex_enter(&wp->wp_lock);

	/*
	 * If a whole block remains allocated, obviously we cannot free
	 * the pool
	 */
	free_blks = (EIB_BLKS_PER_POOL >= 64) ? (~0) :
	    (((uint64_t)1 << EIB_BLKS_PER_POOL) - 1);
	if (wp->wp_free_blks != free_blks) {
		mutex_exit(&wp->wp_lock);
		return (B_FALSE);
	}

	/*
	 * If even a single wqe within any one block remains in-use, we
	 * cannot free the pool
	 */
	for (i = 0; i < EIB_BLKS_PER_POOL; i++) {
		if (wp->wp_free_wqes[i] != (~0)) {
			mutex_exit(&wp->wp_lock);
			return (B_FALSE);
		}
	}

	mutex_exit(&wp->wp_lock);

	return (B_TRUE);
}

/*ARGSUSED*/
static int
eib_rsrc_grab_wqes(eib_t *ss, eib_wqe_pool_t *wp, eib_wqe_t **wqes,
    uint_t n_req, uint_t *actual, int pri)
{
	uint_t n_allocd = 0;
	int blk;
	int ndx;
	int wqe_ndx;

	ASSERT(wp != NULL);
	ASSERT(wqes != NULL);

	mutex_enter(&wp->wp_lock);

	/*
	 * If this is a low priority request, adjust the number requested
	 * so we don't allocate beyond the low-water-mark
	 */
	if (pri == EIB_WPRI_LO) {
		if (wp->wp_nfree <= wp->wp_nfree_lwm)
			n_req = 0;
		else if ((wp->wp_nfree - n_req) < wp->wp_nfree_lwm)
			n_req = wp->wp_nfree - wp->wp_nfree_lwm;
	}

	for (n_allocd = 0;  n_allocd < n_req; n_allocd++) {
		/*
		 * If the entire pool is unavailable, quit
		 */
		if (wp->wp_free_blks == 0)
			break;

		/*
		 * Find the first wqe that's available
		 */
		blk = EIB_FIND_LSB_SET(wp->wp_free_blks);
		ASSERT(blk != -1);
		ndx = EIB_FIND_LSB_SET(wp->wp_free_wqes[blk]);
		ASSERT(ndx != -1);

		/*
		 * Mark the wqe as allocated
		 */
		wp->wp_free_wqes[blk] &= (~((uint64_t)1 << ndx));

		/*
		 * If this was the last free wqe in this block, mark
		 * the block itself as unavailable
		 */
		if (wp->wp_free_wqes[blk] == 0)
			wp->wp_free_blks &= (~((uint64_t)1 << blk));

		/*
		 * Return this wqe to the caller
		 */
		wqe_ndx = blk * EIB_WQES_PER_BLK + ndx;
		wqes[n_allocd] = &(wp->wp_wqe[wqe_ndx]);
	}

	wp->wp_nfree -= n_allocd;

	mutex_exit(&wp->wp_lock);

	if (n_allocd == 0)
		return (EIB_E_FAILURE);

	if (actual) {
		*actual = n_allocd;
	}

	return (EIB_E_SUCCESS);
}

/*ARGSUSED*/
static void
eib_rsrc_return_wqes(eib_t *ss, eib_wqe_pool_t *wp, eib_wqe_t **wqes,
    uint_t n_wqes)
{
	eib_wqe_t *wqe;
	uint_t n_freed = 0;
	uint_t blk;
	uint_t ndx;

	ASSERT(wp != NULL);
	ASSERT(wqes != NULL);

	mutex_enter(&wp->wp_lock);
	for (n_freed = 0;  n_freed < n_wqes; n_freed++) {
		wqe = wqes[n_freed];

		/*
		 * This wqe is being returned back to the pool, so clear
		 * any wqe flags and reset buffer address and size in the
		 * single segment sgl back to what they were initially.
		 * Also erase any mblk pointer and callback function ptrs.
		 */
		wqe->qe_sgl.ds_va = (ib_vaddr_t)(uintptr_t)wqe->qe_cpbuf;
		wqe->qe_sgl.ds_len = wqe->qe_bufsz;
		wqe->qe_mp = NULL;
		wqe->qe_chan = NULL;
		wqe->qe_vnic_inst = -1;
		wqe->qe_info &= (~EIB_WQEFLGS_MASK);

		/*
		 * Mark the wqe free in its block
		 */
		blk = EIB_WQE_BLK(wqe->qe_info);
		ndx = EIB_WQE_NDX(wqe->qe_info);

		wp->wp_free_wqes[blk] |= ((uint64_t)1 << ndx);

		/*
		 * This block now has atleast one wqe free, so mark
		 * the block itself as available and move on to the
		 * next wqe to free
		 */
		wp->wp_free_blks |= ((uint64_t)1 << blk);
	}

	wp->wp_nfree += n_freed;

	/*
	 * If the number of available wqes in the pool has just crossed
	 * the high-water-mark, wakeup anyone who may be sleeping on it.
	 */
	if ((wp->wp_type == EIB_WP_TYPE_TX) &&
	    ((wp->wp_nfree - n_freed) < EIB_NFREE_SWQES_HWM) &&
	    (wp->wp_nfree >= EIB_NFREE_SWQES_HWM)) {
		cv_broadcast(&wp->wp_cv);
	}

	mutex_exit(&wp->wp_lock);
}

static void
eib_rb_rsrc_setup_txbufs(eib_t *ss, boolean_t force)
{
	eib_wqe_pool_t *wp = ss->ei_tx;
	eib_wqe_t *wqe;
	ibt_ud_dest_hdl_t dest;
	ibt_status_t ret;
	uint8_t *plhdr;
	int i;

	if (wp == NULL)
		return;

	/*
	 * Check if it's ok to free the tx wqe pool (i.e. all buffers have
	 * been reclaimed) and if so, stop the txwqe monitor thread (and wait
	 * for it to die), release the UD destination handles, deregister
	 * memory and fini the wqe pool.
	 */
	if (eib_rsrc_ok_to_free_pool(ss, wp, force)) {
		eib_stop_monitor_tx_wqes(ss);

		for (i = 0; i < EIB_WQES_PER_POOL; i++) {
			wqe = &wp->wp_wqe[i];
			if ((plhdr = wqe->qe_payload_hdr) != NULL) {
				kmem_free(plhdr, EIB_MAX_PAYLOAD_HDR_SZ);
			}
			if ((dest = wqe->qe_dest) != NULL) {
				ret = ibt_free_ud_dest(dest);
				if (ret != IBT_SUCCESS) {
					EIB_DPRINTF_WARN(ss->ei_instance,
					    "eib_rb_rsrc_setup_txbufs: "
					    "ibt_free_ud_dest() failed, ret=%d",
					    ret);
				}
			}
		}
		if (wp->wp_mr) {
			if ((ret = ibt_deregister_mr(ss->ei_hca_hdl,
			    wp->wp_mr)) != IBT_SUCCESS) {
				EIB_DPRINTF_WARN(ss->ei_instance,
				    "eib_rb_rsrc_setup_txbufs: "
				    "ibt_deregister_mr() failed, ret=%d", ret);
			}
			wp->wp_mr = NULL;
		}
		eib_rsrc_fini_wqe_pool(ss, &ss->ei_tx);
	}
}

void
eib_rb_rsrc_setup_rxbufs(eib_t *ss, boolean_t force)
{
	eib_wqe_pool_t *rx = ss->ei_rx;
	ibt_status_t ret;

	if (rx == NULL)
		return;

	/*
	 * Check if it's ok to free the rx wqe pool (i.e. all buffers have
	 * been reclaimed) and if so, deregister memory and fini the wqe pool.
	 */
	if (eib_rsrc_ok_to_free_pool(ss, rx, force)) {
		if (rx->wp_mr) {
			if ((ret = ibt_deregister_mr(ss->ei_hca_hdl,
			    rx->wp_mr)) != IBT_SUCCESS) {
				EIB_DPRINTF_WARN(ss->ei_instance,
				    "eib_rb_rsrc_setup_rxbufs: "
				    "ibt_deregister_mr() failed, ret=%d", ret);
			}
			rx->wp_mr = NULL;
		}

		eib_rsrc_fini_wqe_pool(ss, &ss->ei_rx);
	}
}

static void
eib_rb_rsrc_setup_lsobufs(eib_t *ss, boolean_t force)
{
	eib_lsobkt_t *bkt;
	ibt_status_t ret;

	/*
	 * Remove the lso bucket from the state
	 */
	if ((bkt = ss->ei_lso) == NULL)
		return;

	/*
	 * Try to stop the lso bufs monitor thread. If we fail, we simply
	 * return.  We'll have another shot at it later from detach() with
	 * the force flag set.
	 */
	if (eib_stop_monitor_lso_bufs(ss, force) != EIB_E_SUCCESS)
		return;

	/*
	 * Free the buflist
	 */
	if (bkt->bk_bufl) {
		kmem_free(bkt->bk_bufl, bkt->bk_nelem * sizeof (eib_lsobuf_t));
		bkt->bk_bufl = NULL;
	}

	/*
	 * Deregister LSO memory and free it
	 */
	if (bkt->bk_mr_hdl) {
		if ((ret = ibt_deregister_mr(ss->ei_hca_hdl,
		    bkt->bk_mr_hdl)) != IBT_SUCCESS) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_rb_rsrc_setup_lsobufs: "
			    "ibt_deregister_mr() failed, ret=%d", ret);
		}
		bkt->bk_mr_hdl = NULL;
	}
	if (bkt->bk_mem) {
		kmem_free(bkt->bk_mem, bkt->bk_nelem * EIB_LSO_BUFSZ);
		bkt->bk_mem = NULL;
	}

	/*
	 * Destroy the mutex and condvar
	 */
	cv_destroy(&bkt->bk_cv);
	mutex_destroy(&bkt->bk_lock);

	/*
	 * Finally, free the lso bucket itself
	 */
	kmem_free(bkt, sizeof (eib_lsobkt_t));
	ss->ei_lso = NULL;
}

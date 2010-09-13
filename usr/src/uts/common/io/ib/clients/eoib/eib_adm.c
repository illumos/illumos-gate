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
static int eib_adm_setup_cq(eib_t *);
static int eib_adm_setup_ud_channel(eib_t *);
static void eib_adm_comp_intr(ibt_cq_hdl_t, void *);
static void eib_adm_rx_comp(eib_t *, eib_wqe_t *);
static void eib_adm_tx_comp(eib_t *, eib_wqe_t *);
static void eib_adm_err_comp(eib_t *, eib_wqe_t *, ibt_wc_t *);
static void eib_rb_adm_setup_cq(eib_t *);
static void eib_rb_adm_setup_ud_channel(eib_t *);

int
eib_adm_setup_qp(eib_t *ss, int *err)
{
	eib_chan_t *chan;
	ibt_status_t ret;
	uint16_t pkey_ix;

	/*
	 * Verify pkey
	 */
	ret = ibt_pkey2index(ss->ei_hca_hdl, ss->ei_props->ep_port_num,
	    EIB_ADMIN_PKEY, &pkey_ix);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_qp: "
		    "ibt_pkey2index() failed, port_num=0x%x, "
		    "pkey=0x%x, ret=%d", ss->ei_props->ep_port_num,
		    EIB_ADMIN_PKEY, ret);
		*err = ENONET;
		goto adm_setup_qp_fail;
	}

	/*
	 * Allocate a eib_chan_t to store stuff about admin qp and
	 * initialize some basic stuff
	 */
	ss->ei_admin_chan = eib_chan_init();

	chan = ss->ei_admin_chan;
	chan->ch_pkey = EIB_ADMIN_PKEY;
	chan->ch_pkey_ix = pkey_ix;
	chan->ch_vnic_inst = -1;

	/*
	 * Setup a combined CQ and completion handler
	 */
	if (eib_adm_setup_cq(ss) != EIB_E_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_qp: "
		    "eib_adm_setup_cq() failed");
		*err = ENOMEM;
		goto adm_setup_qp_fail;
	}

	/*
	 * Setup UD channel
	 */
	if (eib_adm_setup_ud_channel(ss) != EIB_E_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_qp: "
		    "eib_adm_setup_ud_channel() failed");
		*err = ENOMEM;
		goto adm_setup_qp_fail;
	}

	/*
	 * Post initial set of rx buffers to the HCA
	 */
	if (eib_chan_post_rx(ss, chan, NULL) != EIB_E_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_qp: "
		    "eib_chan_post_rx() failed");
		*err = ENOMEM;
		goto adm_setup_qp_fail;
	}

	return (EIB_E_SUCCESS);

adm_setup_qp_fail:
	eib_rb_adm_setup_qp(ss);
	return (EIB_E_FAILURE);
}

/*ARGSUSED*/
uint_t
eib_adm_comp_handler(caddr_t arg1, caddr_t arg2)
{
	eib_t *ss = (eib_t *)(void *)arg1;
	eib_chan_t *chan = ss->ei_admin_chan;
	ibt_wc_t *wc;
	eib_wqe_t *wqe;
	ibt_status_t ret;
	uint_t polled;
	int i;

	/*
	 * Re-arm the notification callback before we start polling
	 * the completion queue.  There's nothing much we can do if the
	 * enable_cq_notify fails - we issue a warning and move on.
	 */
	ret = ibt_enable_cq_notify(chan->ch_cq_hdl, IBT_NEXT_COMPLETION);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_adm_comp_handler: "
		    "ibt_enable_cq_notify() failed, ret=%d", ret);
	}

	/*
	 * Handle tx and rx completions
	 */
	while ((ret = ibt_poll_cq(chan->ch_cq_hdl, chan->ch_wc, chan->ch_cq_sz,
	    &polled)) == IBT_SUCCESS) {
		for (wc = chan->ch_wc, i = 0; i < polled; i++, wc++) {
			wqe = (eib_wqe_t *)(uintptr_t)wc->wc_id;
			if (wc->wc_status != IBT_WC_SUCCESS) {
				eib_adm_err_comp(ss, wqe, wc);
			} else if (EIB_WQE_TYPE(wqe->qe_info) == EIB_WQE_RX) {
				eib_adm_rx_comp(ss, wqe);
			} else {
				eib_adm_tx_comp(ss, wqe);
			}
		}
	}

	return (DDI_INTR_CLAIMED);
}

void
eib_rb_adm_setup_qp(eib_t *ss)
{
	eib_rb_adm_setup_ud_channel(ss);

	eib_rb_adm_setup_cq(ss);

	eib_chan_fini(ss->ei_admin_chan);
	ss->ei_admin_chan = NULL;
}

static int
eib_adm_setup_cq(eib_t *ss)
{
	eib_chan_t *chan = ss->ei_admin_chan;
	ibt_cq_attr_t cq_attr;
	ibt_status_t ret;
	uint_t sz;
	int rv;

	/*
	 * Allocate the admin completion queue for sending vnic logins and
	 * logouts and receiving vnic login acks.
	 */
	cq_attr.cq_sched = NULL;
	cq_attr.cq_flags = IBT_CQ_NO_FLAGS;
	if (ss->ei_hca_attrs->hca_max_cq_sz < EIB_ADMIN_CQ_SIZE)
		cq_attr.cq_size = ss->ei_hca_attrs->hca_max_cq_sz;
	else
		cq_attr.cq_size = EIB_ADMIN_CQ_SIZE;

	ret = ibt_alloc_cq(ss->ei_hca_hdl, &cq_attr, &chan->ch_cq_hdl, &sz);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_cq: "
		    "ibt_alloc_cq(cq_sz=0x%lx) failed, ret=%d",
		    cq_attr.cq_size, ret);
		goto adm_setup_cq_fail;
	}

	/*
	 * Set up other parameters for collecting completion information
	 */
	chan->ch_cq_sz = sz;
	chan->ch_wc = kmem_zalloc(sizeof (ibt_wc_t) * sz, KM_SLEEP);

	/*
	 * Allocate soft interrupt for the admin channel cq handler and
	 * set up the handler as well.
	 */
	if ((rv = ddi_intr_add_softint(ss->ei_dip, &ss->ei_admin_si_hdl,
	    EIB_SOFTPRI_ADM, eib_adm_comp_handler, ss)) != DDI_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_cq: "
		    "ddi_intr_add_softint() failed for adm qp, ret=%d", rv);
		goto adm_setup_cq_fail;
	}

	/*
	 * Now, set up the admin completion queue handler.
	 */
	ibt_set_cq_handler(chan->ch_cq_hdl, eib_adm_comp_intr, ss);

	ret = ibt_enable_cq_notify(chan->ch_cq_hdl, IBT_NEXT_COMPLETION);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_cq: "
		    "ibt_enable_cq_notify() failed, ret=%d", ret);
		goto adm_setup_cq_fail;
	}

	return (EIB_E_SUCCESS);

adm_setup_cq_fail:
	eib_rb_adm_setup_cq(ss);
	return (EIB_E_FAILURE);
}

static int
eib_adm_setup_ud_channel(eib_t *ss)
{
	eib_chan_t *chan = ss->ei_admin_chan;
	ibt_ud_chan_alloc_args_t alloc_attr;
	ibt_ud_chan_query_attr_t query_attr;
	ibt_status_t ret;

	bzero(&alloc_attr, sizeof (ibt_ud_chan_alloc_args_t));
	bzero(&query_attr, sizeof (ibt_ud_chan_query_attr_t));

	alloc_attr.ud_flags = IBT_ALL_SIGNALED;
	alloc_attr.ud_hca_port_num = ss->ei_props->ep_port_num;
	alloc_attr.ud_pkey_ix = chan->ch_pkey_ix;
	alloc_attr.ud_sizes.cs_sq = EIB_ADMIN_MAX_SWQE;
	alloc_attr.ud_sizes.cs_rq = EIB_ADMIN_MAX_RWQE;
	alloc_attr.ud_sizes.cs_sq_sgl = 1;
	alloc_attr.ud_sizes.cs_rq_sgl = 1;
	alloc_attr.ud_sizes.cs_inline = 0;

	alloc_attr.ud_qkey = EIB_FIP_QKEY;
	alloc_attr.ud_scq = chan->ch_cq_hdl;
	alloc_attr.ud_rcq = chan->ch_cq_hdl;
	alloc_attr.ud_pd = ss->ei_pd_hdl;

	ret = ibt_alloc_ud_channel(ss->ei_hca_hdl, IBT_ACHAN_NO_FLAGS,
	    &alloc_attr, &chan->ch_chan, NULL);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_ud_channel: "
		    "ibt_alloc_ud_channel(port=0x%x, pkey_ix=0x%x) "
		    "failed, ret=%d", alloc_attr.ud_hca_port_num,
		    chan->ch_pkey_ix, ret);
		goto adm_setup_ud_channel_fail;
	}

	ret = ibt_query_ud_channel(chan->ch_chan, &query_attr);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_setup_ud_channel: "
		    "ibt_query_ud_channel() failed, ret=%d", ret);
		goto adm_setup_ud_channel_fail;
	}

	chan->ch_qpn = query_attr.ud_qpn;
	chan->ch_max_swqes = query_attr.ud_chan_sizes.cs_sq;
	chan->ch_max_rwqes = query_attr.ud_chan_sizes.cs_rq;
	chan->ch_lwm_rwqes = chan->ch_max_rwqes >> 2;
	chan->ch_rwqe_bktsz = chan->ch_max_rwqes;
	chan->ch_ip_hdr_align = 0;
	chan->ch_alloc_mp = B_FALSE;
	chan->ch_tear_down = B_FALSE;

	return (EIB_E_SUCCESS);

adm_setup_ud_channel_fail:
	eib_rb_adm_setup_ud_channel(ss);
	return (EIB_E_FAILURE);
}

static void
eib_adm_comp_intr(ibt_cq_hdl_t cq_hdl, void *arg)
{
	eib_t *ss = arg;
	eib_chan_t *chan = ss->ei_admin_chan;

	if (cq_hdl != chan->ch_cq_hdl) {
		EIB_DPRINTF_DEBUG(ss->ei_instance, "eib_adm_comp_intr: "
		    "cq_hdl(0x%llx) != chan->ch_cq_hdl(0x%llx), "
		    "ignoring completion", cq_hdl, chan->ch_cq_hdl);
		return;
	}

	ASSERT(ss->ei_admin_si_hdl != NULL);

	(void) ddi_intr_trigger_softint(ss->ei_admin_si_hdl, NULL);
}

static void
eib_adm_rx_comp(eib_t *ss, eib_wqe_t *wqe)
{
	eib_chan_t *chan = ss->ei_admin_chan;
	eib_login_data_t ld;
	uint8_t *pkt = (uint8_t *)(uintptr_t)(wqe->qe_sgl.ds_va);
	ibt_status_t ret;

	/*
	 * Skip the GRH and parse the login ack message in the packet
	 */
	if (eib_fip_parse_login_ack(ss, pkt + EIB_GRH_SZ, &ld) == EIB_E_SUCCESS)
		eib_vnic_login_ack(ss, &ld);

	/*
	 * Try to repost the rwqe.  For admin channel, we can take the shortcut
	 * and not go through eib_chan_post_recv(), since we know that the
	 * qe_info flag, qe_chan and qe_vinst are all already set correctly; we
	 * just took this out of the rx queue, so the ch_rx_posted will be ok
	 * if we just posted it back. And there are no mblk allocation or
	 * buffer alignment restrictions for this channel as well.
	 */
	if (chan->ch_tear_down) {
		eib_rsrc_return_rwqe(ss, wqe, chan);
	} else {
		ret = ibt_post_recv(chan->ch_chan, &(wqe->qe_wr.recv), 1, NULL);
		if (ret != IBT_SUCCESS) {
			EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_rx_comp: "
			    "ibt_post_recv() failed, ret=%d", ret);
			eib_rsrc_return_rwqe(ss, wqe, chan);
		}
	}
}

static void
eib_adm_tx_comp(eib_t *ss, eib_wqe_t *wqe)
{
	eib_rsrc_return_swqe(ss, wqe, ss->ei_admin_chan);
}

/*ARGSUSED*/
static void
eib_adm_err_comp(eib_t *ss, eib_wqe_t *wqe, ibt_wc_t *wc)
{
	/*
	 * Currently, all we do is report
	 */
	switch (wc->wc_status) {
	case IBT_WC_WR_FLUSHED_ERR:
		break;

	case IBT_WC_LOCAL_CHAN_OP_ERR:
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_err_comp: "
		    "IBT_WC_LOCAL_CHAN_OP_ERR seen, wqe_info=0x%lx ",
		    wqe->qe_info);
		break;

	case IBT_WC_LOCAL_PROTECT_ERR:
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_adm_err_comp: "
		    "IBT_WC_LOCAL_PROTECT_ERR seen, wqe_info=0x%lx ",
		    wqe->qe_info);
		break;
	}

	/*
	 * When a wc indicates error, we do not attempt to repost but
	 * simply return it to the wqe pool.
	 */
	if (EIB_WQE_TYPE(wqe->qe_info) == EIB_WQE_RX)
		eib_rsrc_return_rwqe(ss, wqe, ss->ei_admin_chan);
	else
		eib_rsrc_return_swqe(ss, wqe, ss->ei_admin_chan);
}

static void
eib_rb_adm_setup_cq(eib_t *ss)
{
	eib_chan_t *chan = ss->ei_admin_chan;
	ibt_status_t ret;

	if (chan == NULL)
		return;

	/*
	 * Reset any completion handler we may have set up
	 */
	if (chan->ch_cq_hdl)
		ibt_set_cq_handler(chan->ch_cq_hdl, NULL, NULL);

	/*
	 * Remove any softint we may have allocated for the admin cq
	 */
	if (ss->ei_admin_si_hdl) {
		(void) ddi_intr_remove_softint(ss->ei_admin_si_hdl);
		ss->ei_admin_si_hdl = NULL;
	}

	/*
	 * Release any work completion buffers we may have allocated
	 */
	if (chan->ch_wc && chan->ch_cq_sz)
		kmem_free(chan->ch_wc, sizeof (ibt_wc_t) * chan->ch_cq_sz);

	chan->ch_cq_sz = 0;
	chan->ch_wc = NULL;

	/*
	 * Free any completion queue we may have allocated
	 */
	if (chan->ch_cq_hdl) {
		ret = ibt_free_cq(chan->ch_cq_hdl);
		if (ret != IBT_SUCCESS) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_rb_adm_setup_cq: "
			    "ibt_free_cq() failed, ret=%d", ret);
		}
		chan->ch_cq_hdl = NULL;
	}
}

static void
eib_rb_adm_setup_ud_channel(eib_t *ss)
{
	eib_chan_t *chan = ss->ei_admin_chan;
	ibt_status_t ret;

	if (chan == NULL)
		return;

	if (chan->ch_chan) {
		/*
		 * We're trying to tear down this UD channel. Make sure that
		 * we don't attempt to refill (repost) at any point from now on.
		 */
		chan->ch_tear_down = B_TRUE;
		if ((ret = ibt_flush_channel(chan->ch_chan)) != IBT_SUCCESS) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_rb_adm_setup_ud_channel: "
			    "ibt_flush_channel() failed, ret=%d", ret);
		}

		/*
		 * Wait until all posted tx wqes on this channel are back with
		 * the wqe pool.
		 */
		mutex_enter(&chan->ch_tx_lock);
		while (chan->ch_tx_posted > 0)
			cv_wait(&chan->ch_tx_cv, &chan->ch_tx_lock);
		mutex_exit(&chan->ch_tx_lock);

		/*
		 * Wait until all posted rx wqes on this channel are back with
		 * the wqe pool.
		 */
		mutex_enter(&chan->ch_rx_lock);
		while (chan->ch_rx_posted > 0)
			cv_wait(&chan->ch_rx_cv, &chan->ch_rx_lock);
		mutex_exit(&chan->ch_rx_lock);

		/*
		 * Now we're ready to free this channel
		 */
		if ((ret = ibt_free_channel(chan->ch_chan)) != IBT_SUCCESS) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_rb_adm_setup_ud_channel: "
			    "ibt_free_channel() failed, ret=%d", ret);
		}

		chan->ch_alloc_mp = B_FALSE;
		chan->ch_ip_hdr_align = 0;
		chan->ch_rwqe_bktsz = 0;
		chan->ch_lwm_rwqes = 0;
		chan->ch_max_rwqes = 0;
		chan->ch_max_swqes = 0;
		chan->ch_qpn = 0;
		chan->ch_chan = NULL;
	}
}

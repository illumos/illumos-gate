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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ibtl_chan.c
 *
 * This file contains Transport API functions related to Channel Functions
 * and internal Protection Domain and Address Handle Verbs functions.
 */

#include <sys/ib/ibtl/impl/ibtl.h>
#include <sys/ib/ibtl/impl/ibtl_cm.h>
#include <sys/ib/ib_pkt_hdrs.h>

static char ibtl_chan[] = "ibtl_chan";

/*
 * RC Channel.
 */
/*
 * Function:
 *	ibt_alloc_rc_channel
 * Input:
 *	hca_hdl		HCA Handle.
 *	flags		Channel allocate flags.
 *	args		A pointer to an ibt_rc_chan_alloc_args_t struct that
 *			specifies required channel attributes.
 * Output:
 *	rc_chan_p	The returned RC Channel handle.
 *	sizes		NULL or a pointer to ibt_chan_sizes_s struct where
 *			new SendQ/RecvQ, and WR SGL sizes are returned.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 * Description:
 *	Allocates a RC communication channels that satisfy the specified
 *	channel attributes.
 */
ibt_status_t
ibt_alloc_rc_channel(ibt_hca_hdl_t hca_hdl, ibt_chan_alloc_flags_t flags,
    ibt_rc_chan_alloc_args_t *args, ibt_channel_hdl_t *rc_chan_p,
    ibt_chan_sizes_t *sizes)
{
	ibt_status_t		retval;
	ibt_qp_alloc_attr_t	qp_attr;
	ibt_qp_info_t		qp_modify_attr;
	ibt_channel_hdl_t	chanp;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_rc_channel(%p, %x, %p, %p)",
	    hca_hdl, flags, args, sizes);

	bzero(&qp_modify_attr, sizeof (ibt_qp_info_t));

	qp_attr.qp_alloc_flags = IBT_QP_NO_FLAGS;
	if (flags & IBT_ACHAN_USER_MAP)
		qp_attr.qp_alloc_flags |= IBT_QP_USER_MAP;

	if (flags & IBT_ACHAN_DEFER_ALLOC)
		qp_attr.qp_alloc_flags |= IBT_QP_DEFER_ALLOC;

	if (flags & IBT_ACHAN_USES_SRQ) {
		if (args->rc_srq == NULL) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_rc_channel: "
			    "NULL SRQ Handle specified.");
			return (IBT_INVALID_PARAM);
		}
		qp_attr.qp_alloc_flags |= IBT_QP_USES_SRQ;
	}

	/*
	 * Check if this request is to clone the channel, or to allocate a
	 * fresh one.
	 */
	if (flags & IBT_ACHAN_CLONE) {

		ibt_rc_chan_query_attr_t	chan_attrs;

		if (args->rc_clone_chan == NULL) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_rc_channel: "
			    "Clone Channel info not available.");
			return (IBT_INVALID_PARAM);
		} else if (args->rc_clone_chan->ch_qp.qp_hca != hca_hdl) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_rc_channel: "
			    "Clone Channel's & requested HCA Handle mismatch");
			return (IBT_INVALID_PARAM);
		}

		IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_rc_channel: "
		    "Clone <%p> - RC Channel", args->rc_clone_chan);

		/*
		 * Query the source channel, to obtained the attributes
		 * so that the new channel share the same attributes.
		 */
		retval = ibt_query_rc_channel(args->rc_clone_chan, &chan_attrs);
		if (retval != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_rc_channel: "
			    "Failed to query the source channel: %d", retval);
			return (retval);
		}

		/* Setup QP alloc attributes. */
		qp_attr.qp_scq_hdl = chan_attrs.rc_scq;
		qp_attr.qp_rcq_hdl = chan_attrs.rc_rcq;
		qp_attr.qp_pd_hdl = chan_attrs.rc_pd;
		qp_attr.qp_flags = chan_attrs.rc_flags;
		qp_attr.qp_srq_hdl = chan_attrs.rc_srq;

		bcopy(&chan_attrs.rc_chan_sizes, &qp_attr.qp_sizes,
		    sizeof (ibt_chan_sizes_t));

		qp_modify_attr.qp_flags = chan_attrs.rc_control;
		qp_modify_attr.qp_transport.rc.rc_path.cep_hca_port_num =
		    chan_attrs.rc_prim_path.cep_hca_port_num;
		qp_modify_attr.qp_transport.rc.rc_path.cep_pkey_ix =
		    chan_attrs.rc_prim_path.cep_pkey_ix;

	} else {

		/* Setup QP alloc attributes. */
		qp_attr.qp_scq_hdl = args->rc_scq;
		qp_attr.qp_rcq_hdl = args->rc_rcq;
		qp_attr.qp_pd_hdl = args->rc_pd;
		qp_attr.qp_flags = args->rc_flags;
		qp_attr.qp_srq_hdl = args->rc_srq;

		bcopy(&args->rc_sizes, &qp_attr.qp_sizes,
		    sizeof (ibt_chan_sizes_t));

		qp_modify_attr.qp_flags = args->rc_control;

		if ((args->rc_hca_port_num == 0) ||
		    (args->rc_hca_port_num > IBTL_HCA2NPORTS(hca_hdl))) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_rc_channel: "
			    "Invalid port_num %d, range is (1 to %d)",
			    args->rc_hca_port_num, IBTL_HCA2NPORTS(hca_hdl));
			return (IBT_HCA_PORT_INVALID);
		}
		qp_modify_attr.qp_transport.rc.rc_path.cep_hca_port_num =
		    args->rc_hca_port_num;

		/*
		 * We allocate the Channel initially with the default PKey,
		 * and later client can update this when the channel is opened
		 * with the pkey returned from a path record lookup.
		 */
		mutex_enter(&ibtl_clnt_list_mutex);
		qp_modify_attr.qp_transport.rc.rc_path.cep_pkey_ix =
		    hca_hdl->ha_hca_devp->
		    hd_portinfop[args->rc_hca_port_num - 1].p_def_pkey_ix;
		mutex_exit(&ibtl_clnt_list_mutex);
	}

	/* Allocate Channel and Initialize the channel. */
	retval = ibt_alloc_qp(hca_hdl, IBT_RC_RQP, &qp_attr, sizes, NULL,
	    &chanp);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_rc_channel: "
		    "Failed to allocate QP: %d", retval);
		*rc_chan_p = NULL;
		return (retval);
	}

	qp_modify_attr.qp_trans = IBT_RC_SRV;

	/* Initialize RC Channel by transitioning it to INIT State. */
	retval = ibt_initialize_qp(chanp, &qp_modify_attr);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_rc_channel: "
		    "Failed to Initialize QP: %d", retval);

		/* Free the QP as we failed to initialize it. */
		(void) ibt_free_qp(chanp);

		*rc_chan_p = NULL;
		return (retval);
	}

	/*
	 * The IBTA spec does not include the signal type or PD on a QP
	 * query operation. In order to implement the "CLONE" feature
	 * we need to cache these values.
	 */
	chanp->ch_qp.qp_flags = qp_attr.qp_flags;
	chanp->ch_qp.qp_pd_hdl = qp_attr.qp_pd_hdl;
	*rc_chan_p = chanp;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_rc_channel(%p): - SUCCESS (%p)",
	    hca_hdl, chanp);

	return (IBT_SUCCESS);
}


/*
 * Function:
 *	ibt_query_rc_channel
 * Input:
 *	rc_chan		A previously allocated channel handle.
 *	chan_attrs	A pointer to an ibt_rc_chan_query_args_t struct where
 *			Channel's current attributes are returned.
 * Output:
 *	chan_attrs	A pointer to an ibt_rc_chan_query_args_t struct where
 *			Channel's current attributes are returned.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Query an RC channel's attributes.
 */
ibt_status_t
ibt_query_rc_channel(ibt_channel_hdl_t rc_chan,
    ibt_rc_chan_query_attr_t *chan_attrs)
{
	ibt_status_t		retval;
	ibt_qp_query_attr_t	qp_attr;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_query_rc_channel(%p, %p)",
	    rc_chan, chan_attrs);

	if (rc_chan->ch_qp.qp_type != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_query_rc_channel: "
		    "type of channel (%d) is not RC", rc_chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	bzero(&qp_attr, sizeof (ibt_qp_query_attr_t));

	/* Query the channel (QP) */
	retval = ibt_query_qp(rc_chan, &qp_attr);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_query_rc_channel: "
		    "ibt_query_qp failed on QP %p: %d", rc_chan, retval);
		return (retval);
	}

	chan_attrs->rc_hca_guid = IBTL_HCA2HCAGUID(IBTL_CHAN2HCA(rc_chan));

	chan_attrs->rc_scq = qp_attr.qp_sq_cq;
	chan_attrs->rc_rcq = qp_attr.qp_rq_cq;
	chan_attrs->rc_pd = rc_chan->ch_qp.qp_pd_hdl;
	chan_attrs->rc_state = qp_attr.qp_info.qp_state;
	chan_attrs->rc_path_mtu = qp_attr.qp_info.qp_transport.rc.rc_path_mtu;
	chan_attrs->rc_path_retry_cnt =
	    qp_attr.qp_info.qp_transport.rc.rc_retry_cnt;
	chan_attrs->rc_path_rnr_retry_cnt =
	    qp_attr.qp_info.qp_transport.rc.rc_rnr_retry_cnt;
	chan_attrs->rc_min_rnr_nak =
	    qp_attr.qp_info.qp_transport.rc.rc_min_rnr_nak;

	chan_attrs->rc_prim_path = qp_attr.qp_info.qp_transport.rc.rc_path;
	chan_attrs->rc_alt_path = qp_attr.qp_info.qp_transport.rc.rc_alt_path;

	chan_attrs->rc_chan_sizes.cs_sq = qp_attr.qp_info.qp_sq_sz;
	chan_attrs->rc_chan_sizes.cs_rq = qp_attr.qp_info.qp_rq_sz;
	chan_attrs->rc_chan_sizes.cs_sq_sgl = qp_attr.qp_sq_sgl;
	chan_attrs->rc_chan_sizes.cs_rq_sgl = qp_attr.qp_rq_sgl;
	chan_attrs->rc_srq = qp_attr.qp_srq;

	chan_attrs->rc_rdma_ra_out =
	    qp_attr.qp_info.qp_transport.rc.rc_rdma_ra_out;
	chan_attrs->rc_rdma_ra_in =
	    qp_attr.qp_info.qp_transport.rc.rc_rdma_ra_in;

	chan_attrs->rc_flags = rc_chan->ch_qp.qp_flags;
	chan_attrs->rc_control = qp_attr.qp_info.qp_flags;
	chan_attrs->rc_mig_state = qp_attr.qp_info.qp_transport.rc.rc_mig_state;

	chan_attrs->rc_qpn = qp_attr.qp_qpn & IB_QPN_MASK;
	chan_attrs->rc_dst_qpn =
	    qp_attr.qp_info.qp_transport.rc.rc_dst_qpn & IB_QPN_MASK;

	return (retval);
}


/*
 * Function:
 *	ibt_modify_rc_channel
 * Input:
 *	rc_chan		A previously allocated channel handle.
 *	flags		Specifies which attributes in ibt_rc_chan_modify_attr_t
 *			are to be modified.
 *	attrs		Attributes to be modified.
 * Output:
 *	actual_sz	On return contains the new send and receive queue sizes.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Modifies an RC channel's attributes, as specified by a
 *	ibt_cep_modify_flags_t parameter to those specified in the
 *	ibt_rc_chan_modify_attr_t structure.
 */
ibt_status_t
ibt_modify_rc_channel(ibt_channel_hdl_t rc_chan, ibt_cep_modify_flags_t flags,
    ibt_rc_chan_modify_attr_t *attrs, ibt_queue_sizes_t *actual_sz)
{
	ibt_status_t		retval;
	ibt_qp_info_t		qp_info;
	int			retries = 1;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_modify_rc_channel(%p, %x, %p, %p)",
	    rc_chan, flags, attrs, actual_sz);

	if (rc_chan->ch_qp.qp_type != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_rc_channel: "
		    "type of channel (%d) is not RC", rc_chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

retry:
	bzero(&qp_info, sizeof (ibt_qp_info_t));

	if (flags & IBT_CEP_SET_ADDS_VECT) {
		bcopy(&attrs->rc_prim_adds_vect,
		    &qp_info.qp_transport.rc.rc_path.cep_adds_vect,
		    sizeof (ibt_adds_vect_t));
	}

	qp_info.qp_trans = IBT_RC_SRV;
	qp_info.qp_transport.rc.rc_path.cep_hca_port_num =
	    attrs->rc_prim_port_num;
	qp_info.qp_transport.rc.rc_retry_cnt = attrs->rc_path_retry_cnt;
	qp_info.qp_transport.rc.rc_rnr_retry_cnt =
	    attrs->rc_path_rnr_retry_cnt;
	qp_info.qp_transport.rc.rc_rdma_ra_out = attrs->rc_rdma_ra_out;
	qp_info.qp_transport.rc.rc_rdma_ra_in = attrs->rc_rdma_ra_in;

	/* Current channel state must be either SQD or RTS. */
	qp_info.qp_current_state = rc_chan->ch_current_state;
	qp_info.qp_state = rc_chan->ch_current_state;	/* No Change in State */

	qp_info.qp_flags = attrs->rc_control;
	qp_info.qp_sq_sz = attrs->rc_sq_sz;
	qp_info.qp_rq_sz = attrs->rc_rq_sz;
	qp_info.qp_transport.rc.rc_min_rnr_nak = attrs->rc_min_rnr_nak;

	if (flags & IBT_CEP_SET_ALT_PATH) {
		bcopy(&attrs->rc_alt_adds_vect,
		    &qp_info.qp_transport.rc.rc_alt_path.cep_adds_vect,
		    sizeof (ibt_adds_vect_t));
		qp_info.qp_transport.rc.rc_alt_path.cep_hca_port_num =
		    attrs->rc_alt_port_num;
	}

	flags |= IBT_CEP_SET_STATE;

	retval = ibt_modify_qp(rc_chan, flags, &qp_info, actual_sz);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_rc_channel: "
		    "ibt_modify_qp failed on QP %p: %d", rc_chan, retval);
		/* give it one more shot if the old current state was stale */
		if (qp_info.qp_current_state != rc_chan->ch_current_state &&
		    --retries >= 0 &&
		    (qp_info.qp_current_state == IBT_STATE_RTS ||
		    qp_info.qp_current_state == IBT_STATE_SQD))
			goto retry;
	}

	return (retval);
}


/*
 * UD Channel.
 */
/*
 * Function:
 *	ibt_alloc_ud_channel
 * Input:
 *	hca_hdl		HCA Handle.
 *	flags		Channel allocate flags.
 *	args		A pointer to an ibt_ud_chan_alloc_args_t struct that
 *			specifies required channel attributes.
 * Output:
 *	ud_chan_p	The returned UD Channel handle.
 *	sizes		NULL or a pointer to ibt_chan_sizes_s struct where
 *			new SendQ/RecvQ, and WR SGL sizes are returned.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 * Description:
 *	Allocate UD channels that satisfy the specified channel attributes.
 */
ibt_status_t
ibt_alloc_ud_channel(ibt_hca_hdl_t hca_hdl, ibt_chan_alloc_flags_t flags,
    ibt_ud_chan_alloc_args_t *args, ibt_channel_hdl_t *ud_chan_p,
    ibt_chan_sizes_t *sizes)
{
	ibt_status_t		retval;
	ibt_qp_alloc_attr_t	qp_attr;
	ibt_qp_info_t		qp_modify_attr;
	ibt_channel_hdl_t	chanp;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_ud_channel(%p, %x, %p, %p)",
	    hca_hdl, flags, args, sizes);

	bzero(&qp_modify_attr, sizeof (ibt_qp_info_t));

	qp_attr.qp_alloc_flags = IBT_QP_NO_FLAGS;
	if (flags & IBT_ACHAN_USER_MAP)
		qp_attr.qp_alloc_flags |= IBT_QP_USER_MAP;

	if (flags & IBT_ACHAN_DEFER_ALLOC)
		qp_attr.qp_alloc_flags |= IBT_QP_DEFER_ALLOC;

	if (flags & IBT_ACHAN_USES_SRQ) {
		if (args->ud_srq == NULL) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_channel: "
			    "NULL SRQ Handle specified.");
			return (IBT_INVALID_PARAM);
		}
		qp_attr.qp_alloc_flags |= IBT_QP_USES_SRQ;
	}

	/*
	 * Check if this request is to clone the channel, or to allocate a
	 * fresh one.
	 */
	if (flags & IBT_ACHAN_CLONE) {

		ibt_ud_chan_query_attr_t	chan_attrs;

		if (args->ud_clone_chan == NULL) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_channel: "
			    "Clone Channel info not available.");
			return (IBT_INVALID_PARAM);
		} else if (args->ud_clone_chan->ch_qp.qp_hca != hca_hdl) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_channel: "
			    "Clone Channel and HCA Handle mismatch");
			return (IBT_INVALID_PARAM);
		}

		IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_ud_channel: "
		    "Clone <%p> - UD Channel", args->ud_clone_chan);

		retval = ibt_query_ud_channel(args->ud_clone_chan, &chan_attrs);
		if (retval != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_channel: "
			    "Failed to Query the source channel: %d", retval);
			return (retval);
		}

		/* Setup QP alloc attributes. */
		qp_attr.qp_scq_hdl = chan_attrs.ud_scq;
		qp_attr.qp_rcq_hdl = chan_attrs.ud_rcq;
		qp_attr.qp_pd_hdl = chan_attrs.ud_pd;
		qp_attr.qp_flags = chan_attrs.ud_flags;
		qp_attr.qp_srq_hdl = chan_attrs.ud_srq;

		bcopy(&chan_attrs.ud_chan_sizes, &qp_attr.qp_sizes,
		    sizeof (ibt_chan_sizes_t));

		qp_modify_attr.qp_transport.ud.ud_port =
		    chan_attrs.ud_hca_port_num;
		qp_modify_attr.qp_transport.ud.ud_qkey = chan_attrs.ud_qkey;
		qp_modify_attr.qp_transport.ud.ud_pkey_ix =
		    chan_attrs.ud_pkey_ix;
	} else {
		ib_pkey_t	tmp_pkey;

		/* Setup QP alloc attributes. */
		qp_attr.qp_scq_hdl = args->ud_scq;
		qp_attr.qp_rcq_hdl = args->ud_rcq;
		qp_attr.qp_pd_hdl = args->ud_pd;
		qp_attr.qp_flags = args->ud_flags;
		qp_attr.qp_srq_hdl = args->ud_srq;

		bcopy(&args->ud_sizes, &qp_attr.qp_sizes,
		    sizeof (ibt_chan_sizes_t));

		qp_modify_attr.qp_transport.ud.ud_port = args->ud_hca_port_num;
		qp_modify_attr.qp_transport.ud.ud_qkey = args->ud_qkey;

		/* Validate input hca_port_num and pkey_ix values. */
		if ((retval = ibt_index2pkey(hca_hdl, args->ud_hca_port_num,
		    args->ud_pkey_ix, &tmp_pkey)) != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_channel: "
			    "ibt_index2pkey failed, status: %d", retval);
			*ud_chan_p = NULL;
			return (retval);
		}
		qp_modify_attr.qp_transport.ud.ud_pkey_ix = args->ud_pkey_ix;
	}

	/* Allocate Channel and Initialize the channel. */
	retval = ibt_alloc_qp(hca_hdl, IBT_UD_RQP, &qp_attr, sizes, NULL,
	    &chanp);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_channel: "
		    "Failed to allocate QP: %d", retval);
		*ud_chan_p = NULL;
		return (retval);
	}

	/* Initialize UD Channel by transitioning it to RTS State. */
	qp_modify_attr.qp_trans = IBT_UD_SRV;
	qp_modify_attr.qp_flags = IBT_CEP_NO_FLAGS;
	qp_modify_attr.qp_transport.ud.ud_sq_psn = 0;

	retval = ibt_initialize_qp(chanp, &qp_modify_attr);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_channel: "
		    "Failed to Initialize QP: %d", retval);

		/* Free the QP as we failed to initialize it. */
		(void) ibt_free_qp(chanp);

		*ud_chan_p = NULL;
		return (retval);
	}

	/*
	 * The IBTA spec does not include the signal type or PD on a QP
	 * query operation. In order to implement the "CLONE" feature
	 * we need to cache these values.
	 */
	chanp->ch_qp.qp_flags = qp_attr.qp_flags;
	chanp->ch_qp.qp_pd_hdl = qp_attr.qp_pd_hdl;
	*ud_chan_p = chanp;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_ud_channel(%p): - SUCCESS (%p)",
	    hca_hdl, chanp);

	return (IBT_SUCCESS);
}


/*
 * Function:
 *	ibt_query_ud_channel
 * Input:
 *	ud_chan		A previously allocated UD channel handle.
 * Output:
 *	chan_attrs	Channel's current attributes.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Query a UD channel's attributes.
 */
ibt_status_t
ibt_query_ud_channel(ibt_channel_hdl_t ud_chan,
    ibt_ud_chan_query_attr_t *ud_chan_attrs)
{
	ibt_status_t		retval;
	ibt_qp_query_attr_t	qp_attr;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_query_ud_channel(%p, %p)",
	    ud_chan, ud_chan_attrs);

	if (ud_chan->ch_qp.qp_type != IBT_UD_SRV) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_query_ud_channel: "
		    "type of channel (%d) is not UD", ud_chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	bzero(&qp_attr, sizeof (ibt_qp_query_attr_t));

	/* Query the channel (QP) */
	retval = ibt_query_qp(ud_chan, &qp_attr);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_query_ud_channel: "
		    "ibt_query_qp failed on QP %p: %d", ud_chan, retval);
		return (retval);
	}

	ud_chan_attrs->ud_qpn = qp_attr.qp_qpn & IB_QPN_MASK;
	ud_chan_attrs->ud_hca_guid = IBTL_HCA2HCAGUID(IBTL_CHAN2HCA(ud_chan));

	ud_chan_attrs->ud_scq = qp_attr.qp_sq_cq;
	ud_chan_attrs->ud_rcq = qp_attr.qp_rq_cq;
	ud_chan_attrs->ud_pd = ud_chan->ch_qp.qp_pd_hdl;

	ud_chan_attrs->ud_hca_port_num =
	    qp_attr.qp_info.qp_transport.ud.ud_port;

	ud_chan_attrs->ud_state = qp_attr.qp_info.qp_state;
	ud_chan_attrs->ud_pkey_ix = qp_attr.qp_info.qp_transport.ud.ud_pkey_ix;
	ud_chan_attrs->ud_qkey = qp_attr.qp_info.qp_transport.ud.ud_qkey;

	ud_chan_attrs->ud_chan_sizes.cs_sq = qp_attr.qp_info.qp_sq_sz;
	ud_chan_attrs->ud_chan_sizes.cs_rq = qp_attr.qp_info.qp_rq_sz;
	ud_chan_attrs->ud_chan_sizes.cs_sq_sgl = qp_attr.qp_sq_sgl;
	ud_chan_attrs->ud_chan_sizes.cs_rq_sgl = qp_attr.qp_rq_sgl;
	ud_chan_attrs->ud_srq = qp_attr.qp_srq;

	ud_chan_attrs->ud_flags = ud_chan->ch_qp.qp_flags;

	return (retval);
}


/*
 * Function:
 *	ibt_modify_ud_channel
 * Input:
 *	ud_chan		A previously allocated UD channel handle.
 *	flags		Specifies which attributes in ibt_ud_chan_modify_attr_t
 *			are to be modified.
 *	attrs		Attributes to be modified.
 * Output:
 *	actual_sz	On return contains the new send and receive queue sizes.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Modifies an UD channel's attributes, as specified by a
 *	ibt_cep_modify_flags_t parameter to those specified in the
 *	ibt_ud_chan_modify_attr_t structure.
 */
ibt_status_t
ibt_modify_ud_channel(ibt_channel_hdl_t ud_chan, ibt_cep_modify_flags_t flags,
    ibt_ud_chan_modify_attr_t *attrs, ibt_queue_sizes_t *actual_sz)
{
	ibt_status_t		retval;
	ibt_qp_info_t		qp_info;
	ibt_cep_modify_flags_t	good_flags;
	int			retries = 1;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_modify_ud_channel(%p, %x, %p, %p)",
	    ud_chan, flags, attrs, actual_sz);

	if (ud_chan->ch_qp.qp_type != IBT_UD_SRV) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_ud_channel: "
		    "type of channel (%d) is not UD", ud_chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	good_flags = IBT_CEP_SET_SQ_SIZE | IBT_CEP_SET_RQ_SIZE |
	    IBT_CEP_SET_QKEY;

	if (flags & ~good_flags) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_ud_channel: "
		    "Invalid Modify Flags: %x", flags);
		return (IBT_INVALID_PARAM);
	}

retry:
	bzero(&qp_info, sizeof (ibt_qp_info_t));

	qp_info.qp_state = ud_chan->ch_current_state;	/* No Change in State */
	qp_info.qp_current_state = ud_chan->ch_current_state;
	qp_info.qp_flags = IBT_CEP_NO_FLAGS;

	qp_info.qp_sq_sz = attrs->ud_sq_sz;
	qp_info.qp_rq_sz = attrs->ud_rq_sz;
	qp_info.qp_trans = IBT_UD_SRV;
	qp_info.qp_transport.ud.ud_qkey = attrs->ud_qkey;

	flags |= IBT_CEP_SET_STATE;

	retval = ibt_modify_qp(ud_chan, flags, &qp_info, actual_sz);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_ud_channel: "
		    "ibt_modify_qp failed on QP %p: %d", ud_chan, retval);
		/* give it one more shot if the old current state was stale */
		if (qp_info.qp_current_state != ud_chan->ch_current_state &&
		    --retries >= 0 &&
		    (qp_info.qp_current_state == IBT_STATE_RTS ||
		    qp_info.qp_current_state == IBT_STATE_SQD))
			goto retry;
	}

	return (retval);
}


/*
 * Function:
 *	ibt_recover_ud_channel
 * Input:
 *	ud_chan		An UD channel handle which is in SQError state.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_CHAN_SRV_TYPE_INVALID
 *	IBT_CHAN_STATE_INVALID
 * Description:
 *	Recover an UD Channel which has transitioned to SQ Error state. The
 *	ibt_recover_ud_channel() transitions the channel from SQ Error state
 *	to Ready-To-Send channel state.
 *
 *	If a work request posted to a UD channel's send queue completes with
 *	an error (see ibt_wc_status_t), the channel gets transitioned to SQ
 *	Error state. In order to reuse this channel, ibt_recover_ud_channel()
 *	can be used to recover the channel to a usable (Ready-to-Send) state.
 */
ibt_status_t
ibt_recover_ud_channel(ibt_channel_hdl_t ud_chan)
{
	ibt_qp_info_t		modify_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_recover_ud_channel(%p)", ud_chan);

	if (ud_chan->ch_qp.qp_type != IBT_UD_SRV) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_recover_ud_channel: "
		    "Called for non-UD channels<%d>", ud_chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	bzero(&modify_attr, sizeof (ibt_qp_info_t));

	/* Set the channel state to RTS, to activate the send processing. */
	modify_attr.qp_state = IBT_STATE_RTS;
	modify_attr.qp_trans = ud_chan->ch_qp.qp_type;
	modify_attr.qp_current_state = IBT_STATE_SQE;

	retval = ibt_modify_qp(ud_chan, IBT_CEP_SET_STATE, &modify_attr, NULL);

	if (retval != IBT_SUCCESS)
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_recover_ud_channel: "
		    "ibt_modify_qp failed on qp %p: status = %d",
		    ud_chan, retval);

	return (retval);
}


/*
 * Function:
 *	ibt_flush_channel
 * Input:
 *	chan		The opaque channel handle returned in a previous call
 *			to ibt_alloc_ud_channel() or ibt_alloc_rc_channel().
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Flush the specified channel. Outstanding work requests are flushed
 *	so that the client can do the associated clean up. After that, the
 *	client will usually deregister the previously registered memory,
 *	then free the channel by calling ibt_free_channel().  This function
 *	applies to UD channels, or to RC channels that have not successfully
 *	been opened.
 */
ibt_status_t
ibt_flush_channel(ibt_channel_hdl_t chan)
{
	ibt_status_t retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_flush_channel(%p)", chan);

	retval = ibt_flush_qp(chan);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_flush_channel: "
		    "ibt_flush_qp failed on QP %p: %d", chan, retval);
	}

	return (retval);
}


/*
 * Function:
 *	ibt_free_channel
 * Input:
 *	chan		The opaque channel handle returned in a previous
 *			call to ibt_alloc_{ud,rc}_channel().
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Releases the resources associated with the specified channel.
 *	It is well assumed that channel has been closed before this.
 */
ibt_status_t
ibt_free_channel(ibt_channel_hdl_t chan)
{
	return (ibt_free_qp(chan));
}


/*
 * UD Destination.
 */
/*
 * Function:
 *	ibt_alloc_ud_dest
 * Input:
 *	hca_hdl		HCA Handle.
 *	pd		Protection Domain
 * Output:
 *	ud_dest_p	Address to store the returned UD destination handle.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Allocate a UD destination handle. The returned UD destination handle
 *	has no useful contents, but is usable after calling ibt_modify_ud_dest,
 *	ibt_modify_reply_ud_dest, or ibt_open_ud_dest.
 */
ibt_status_t
ibt_alloc_ud_dest(ibt_hca_hdl_t hca_hdl, ibt_ud_dest_flags_t flags,
    ibt_pd_hdl_t pd, ibt_ud_dest_hdl_t *ud_dest_p)
{
	ibt_status_t	retval;
	ibt_ud_dest_t	*ud_destp;
	ibt_ah_hdl_t	ah;
	ibt_adds_vect_t adds_vect;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_ud_dest(%p, %x, %p)",
	    hca_hdl, flags, pd);

	bzero(&adds_vect, sizeof (adds_vect));
	adds_vect.av_port_num = 1;
	adds_vect.av_srate = IBT_SRATE_1X;	/* assume the minimum */
	retval = ibt_alloc_ah(hca_hdl, flags, pd, &adds_vect, &ah);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ud_dest: "
		    "Address Handle Allocation failed: %d", retval);
		*ud_dest_p = NULL;
		return (retval);
	}
	ud_destp = kmem_alloc(sizeof (*ud_destp), KM_SLEEP);
	ud_destp->ud_ah = ah;
	ud_destp->ud_dest_hca = hca_hdl;
	ud_destp->ud_dst_qpn = 0;
	ud_destp->ud_qkey = 0;
	*ud_dest_p = ud_destp;
	return (IBT_SUCCESS);
}

/*
 * Function:
 *	ibt_query_ud_dest
 * Input:
 *	ud_dest		A previously allocated UD destination handle.
 * Output:
 *	dest_attrs	UD destination's current attributes.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Query a UD destination's attributes.
 */
ibt_status_t
ibt_query_ud_dest(ibt_ud_dest_hdl_t ud_dest,
    ibt_ud_dest_query_attr_t *dest_attrs)
{
	ibt_status_t	retval;

	ASSERT(dest_attrs != NULL);

	/* Query Address Handle */
	retval = ibt_query_ah(ud_dest->ud_dest_hca, ud_dest->ud_ah,
	    &dest_attrs->ud_pd, &dest_attrs->ud_addr_vect);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_query_ud_dest: "
		    "Failed to Query Address Handle: %d", retval);
		return (retval);
	}

	/* Update the return struct. */
	dest_attrs->ud_hca_hdl = ud_dest->ud_dest_hca;
	dest_attrs->ud_dst_qpn = ud_dest->ud_dst_qpn;
	dest_attrs->ud_qkey = ud_dest->ud_qkey;

	return (retval);
}

/*
 * Function:
 *	ibt_modify_ud_dest
 * Input:
 *	ud_dest		A previously allocated UD destination handle
 *			as returned by ibt_alloc_ud_dest().
 *	qkey		QKey of the destination.
 *	dest_qpn	QPN of the destination.
 *	adds_vect	NULL or Address Vector for the destination.
 *
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Modify a previously allocated UD destination handle from the
 *	arguments supplied by the caller.
 */
ibt_status_t
ibt_modify_ud_dest(ibt_ud_dest_hdl_t ud_dest, ib_qkey_t qkey,
    ib_qpn_t dest_qpn, ibt_adds_vect_t *adds_vect)
{
	ibt_status_t	retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_modify_ud_dest(%p, %x, %x, %p) ",
	    ud_dest, qkey, dest_qpn, adds_vect);

	if ((adds_vect != NULL) &&
	    (retval = ibt_modify_ah(ud_dest->ud_dest_hca, ud_dest->ud_ah,
	    adds_vect)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_ud_dest: "
		    "ibt_modify_ah() failed: status = %d", retval);
		return (retval);
	}
	ud_dest->ud_dst_qpn = dest_qpn;
	ud_dest->ud_qkey = qkey;
	return (IBT_SUCCESS);
}

/*
 * Function:
 *	ibt_free_ud_dest
 * Input:
 *	ud_dest		The opaque destination handle returned in a previous
 *			call to ibt_alloc_ud_dest() or ibt_alloc_mcg_dest().
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Releases the resources associated with the specified destination
 *	handle.
 */
ibt_status_t
ibt_free_ud_dest(ibt_ud_dest_hdl_t ud_dest)
{
	ibt_status_t	retval;

	retval = ibt_free_ah(ud_dest->ud_dest_hca, ud_dest->ud_ah);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_free_ud_dest: "
		    "Address Handle free failed: %d", retval);
		return (retval);
	}
	kmem_free(ud_dest, sizeof (*ud_dest));
	return (IBT_SUCCESS);
}

static ibt_status_t
ibtl_find_sgid_ix(ib_gid_t *sgid, ibt_channel_hdl_t ud_chan, uint8_t port,
    uint_t *sgid_ix_p)
{
	ibtl_hca_devinfo_t *hca_devp = ud_chan->ch_qp.qp_hca->ha_hca_devp;
	ib_gid_t *sgidp;
	uint_t i;
	uint_t sgid_tbl_sz;

	if (port == 0 || port > hca_devp->hd_hca_attr->hca_nports ||
	    sgid->gid_prefix == 0 || sgid->gid_guid == 0) {
		*sgid_ix_p = 0;
		return (IBT_INVALID_PARAM);
	}
	mutex_enter(&ibtl_clnt_list_mutex);
	sgidp = &hca_devp->hd_portinfop[port - 1].p_sgid_tbl[0];
	sgid_tbl_sz = hca_devp->hd_portinfop[port - 1].p_sgid_tbl_sz;
	for (i = 0; i < sgid_tbl_sz; i++, sgidp++) {
		if ((sgid->gid_guid != sgidp->gid_guid) ||
		    (sgid->gid_prefix != sgidp->gid_prefix))
			continue;
		mutex_exit(&ibtl_clnt_list_mutex);
		*sgid_ix_p = i;
		return (IBT_SUCCESS);
	}
	mutex_exit(&ibtl_clnt_list_mutex);
	*sgid_ix_p = 0;
	return (IBT_INVALID_PARAM);
}

/*
 * Function:
 *	ibt_modify_reply_ud_dest
 * Input:
 *	ud_dest		A previously allocated UD reply destination handle
 *			as returned by ibt_alloc_ud_dest().
 *	qkey		Qkey.  0 means "not specified", so use the Q_Key
 *			in the QP context.
 *	recv_buf	Pointer to the first data buffer associated with the
 *			receive work request.
 * Output:
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Modify a previously allocated UD destination handle, so that it
 *	can be used to reply to the sender of the datagram contained in the
 *	specified work request completion.  If the qkey is not supplied (0),
 *	then use the qkey in the QP (we just set qkey to a privileged QKEY).
 */
ibt_status_t
ibt_modify_reply_ud_dest(ibt_channel_hdl_t ud_chan, ibt_ud_dest_hdl_t ud_dest,
    ib_qkey_t qkey, ibt_wc_t *wc, ib_vaddr_t recv_buf)
{
	ibt_status_t		retval;
	ibt_adds_vect_t		adds_vect;
	ib_grh_t		*grh;
	uint8_t			port;
	uint32_t		ver_tc_flow;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_modify_reply_ud_dest(%p, %p, %x, %p, "
	    "%llx)", ud_chan, ud_dest, qkey, wc, recv_buf);

	if (ud_chan->ch_qp.qp_type != IBT_UD_SRV) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_reply_ud_dest: "
		    "type of channel (%d) is not UD",
		    ud_chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}
	if (qkey == 0)
		qkey = ud_chan->ch_transport.ud.ud_qkey;
	port = ud_chan->ch_transport.ud.ud_port_num;

	if (wc->wc_flags & IBT_WC_GRH_PRESENT) {
		grh = (ib_grh_t *)(uintptr_t)recv_buf;
		adds_vect.av_send_grh = B_TRUE;
		adds_vect.av_dgid.gid_prefix = b2h64(grh->SGID.gid_prefix);
		adds_vect.av_dgid.gid_guid = b2h64(grh->SGID.gid_guid);
		adds_vect.av_sgid.gid_prefix = b2h64(grh->DGID.gid_prefix);
		adds_vect.av_sgid.gid_guid = b2h64(grh->DGID.gid_guid);
		(void) ibtl_find_sgid_ix(&adds_vect.av_sgid, ud_chan,
		    port, &adds_vect.av_sgid_ix);
		ver_tc_flow = b2h32(grh->IPVer_TC_Flow);
		adds_vect.av_flow = ver_tc_flow & IB_GRH_FLOW_LABEL_MASK;
		adds_vect.av_tclass = (ver_tc_flow & IB_GRH_TCLASS_MASK) >> 20;
		adds_vect.av_hop = grh->HopLmt;
	} else {
		adds_vect.av_send_grh = B_FALSE;
		adds_vect.av_dgid.gid_prefix = 0;
		adds_vect.av_sgid.gid_prefix = 0;
		adds_vect.av_dgid.gid_guid = 0;
		adds_vect.av_sgid.gid_guid = 0;
		adds_vect.av_sgid_ix = 0;
		adds_vect.av_flow = 0;
		adds_vect.av_tclass = 0;
		adds_vect.av_hop = 0;
	}

	adds_vect.av_srate = IBT_SRATE_1X;	/* assume the minimum */
	adds_vect.av_srvl = wc->wc_sl;
	adds_vect.av_dlid = wc->wc_slid;
	adds_vect.av_src_path = wc->wc_path_bits;
	adds_vect.av_port_num = port;

	if ((retval = ibt_modify_ah(ud_dest->ud_dest_hca, ud_dest->ud_ah,
	    &adds_vect)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_modify_reply_ud_dest: "
		    "ibt_alloc_ah() failed: status = %d", retval);
		return (retval);
	}
	ud_dest->ud_dst_qpn = wc->wc_qpn & IB_QPN_MASK;
	ud_dest->ud_qkey = qkey;

	return (IBT_SUCCESS);
}


/*
 * Function:
 *	ibt_is_privileged_ud_dest
 * Input:
 *	ud_dest		A previously allocated destination handle.
 * Output:
 *	none
 * Returns:
 *	B_FALSE/B_TRUE
 * Description:
 *	Determine if a UD destination Handle is a privileged handle.
 */
boolean_t
ibt_is_privileged_ud_dest(ibt_ud_dest_hdl_t ud_dest)
{
	return ((ud_dest->ud_qkey & IB_PRIVILEGED_QKEY_BIT) ? B_TRUE : B_FALSE);
}


/*
 * Function:
 *	ibt_update_channel_qkey
 * Input:
 *	ud_chan		The UD channel handle, that is to be used to
 *			communicate with the specified destination.
 *
 *	ud_dest		A UD destination handle returned from
 *			ibt_alloc_ud_dest(9F).
 * Output:
 *	none
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *   ibt_update_channel_qkey() sets the Q_Key in the specified channel context
 *   to the Q_Key in the specified destination handle. This function can be used
 *   to enable sends to a privileged destination. All posted send work requests
 *   that contain a privileged destination handle now use the Q_Key in the
 *   channel context.
 *
 *   ibt_update_channel_qkey() can also be used to enable the caller to receive
 *   from the specified remote destination on the specified channel.
 */
ibt_status_t
ibt_update_channel_qkey(ibt_channel_hdl_t ud_chan, ibt_ud_dest_hdl_t ud_dest)
{
	ibt_status_t		retval;
	ibt_qp_info_t		qp_info;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_update_channel_qkey(%p, %p)",
	    ud_chan, ud_dest);

	if (ud_chan->ch_qp.qp_type != IBT_UD_SRV) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_update_channel_qkey: "
		    "type of channel (%d) is not UD",
		    ud_chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}
	bzero(&qp_info, sizeof (ibt_qp_info_t));

	qp_info.qp_trans = IBT_UD_SRV;
	qp_info.qp_state = ud_chan->ch_current_state;
	qp_info.qp_current_state = ud_chan->ch_current_state;
	qp_info.qp_transport.ud.ud_qkey = ud_dest->ud_qkey;

	retval = ibt_modify_qp(ud_chan, IBT_CEP_SET_QKEY | IBT_CEP_SET_STATE,
	    &qp_info, NULL);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_update_channel_qkey: "
		    "Failed to modify QP %p: status %d", ud_chan, retval);
	} else {
		ud_chan->ch_transport.ud.ud_qkey = ud_dest->ud_qkey;
	}

	return (retval);
}


/*
 * Function:
 *	ibt_set_chan_private
 * Input:
 *	chan		A previously allocated channel handle.
 *	clnt_private	The client private data.
 * Output:
 *	none.
 * Returns:
 *	none.
 * Description:
 *	Set the client private data.
 */
void
ibt_set_chan_private(ibt_channel_hdl_t chan, void *clnt_private)
{
	chan->ch_clnt_private = clnt_private;
}


/*
 * Function:
 *	ibt_get_chan_private
 * Input:
 *	chan		A previously allocated channel handle.
 * Output:
 *	A pointer to the client private data.
 * Returns:
 *	none.
 * Description:
 *	Get a pointer to client private data.
 */
void *
ibt_get_chan_private(ibt_channel_hdl_t chan)
{
	return (chan->ch_clnt_private);
}

/*
 * Function:
 *	ibt_channel_to_hca_guid
 * Input:
 *	chan		Channel Handle.
 * Output:
 *	none.
 * Returns:
 *	hca_guid	Returned HCA GUID on which the specified Channel is
 *			allocated. Valid if it is non-NULL on return.
 * Description:
 *	A helper function to retrieve HCA GUID for the specified Channel.
 */
ib_guid_t
ibt_channel_to_hca_guid(ibt_channel_hdl_t chan)
{
	IBTF_DPRINTF_L3(ibtl_chan, "ibt_channel_to_hca_guid(%p)", chan);

	return (IBTL_HCA2HCAGUID(IBTL_CHAN2HCA(chan)));
}

/*
 * Protection Domain Verbs Functions.
 */

/*
 * Function:
 *	ibt_alloc_pd
 * Input:
 *	hca_hdl		The IBT HCA handle, the device on which we need
 *			to create the requested Protection Domain.
 *	flags		IBT_PD_NO_FLAGS, IBT_PD_USER_MAP or IBT_PD_DEFER_ALLOC
 * Output:
 *	pd		IBT Protection Domain Handle.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_HCA_HDL_INVALID
 * Description:
 *	Allocate a Protection Domain.
 */
ibt_status_t
ibt_alloc_pd(ibt_hca_hdl_t hca_hdl, ibt_pd_flags_t flags, ibt_pd_hdl_t *pd)
{
	ibt_status_t	retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_pd(%p, %x)", hca_hdl, flags);

	/* re-direct the call to CI's call */
	ibtl_qp_flow_control_enter();
	retval = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_pd(
	    IBTL_HCA2CIHCA(hca_hdl), flags, pd);
	ibtl_qp_flow_control_exit();
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_pd: CI PD Alloc Err");
		return (retval);
	}

	/* Update the PDs Resource Count per HCA Device. */
	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_pd_cnt++;
	mutex_exit(&hca_hdl->ha_mutex);

	return (retval);
}

/*
 * Function:
 *	ibt_free_pd
 * Input:
 *	hca_hdl		The IBT HCA handle, the device on which we need
 *			to free the requested Protection Domain.
 *	pd		IBT Protection Domain Handle.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_HCA_HDL_INVALID
 *	IBT_MEM_PD_HDL_INVALID
 *	IBT_MEM_PD_IN_USE
 * Description:
 *	Release/de-allocate a Protection Domain.
 */
ibt_status_t
ibt_free_pd(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd)
{
	ibt_status_t	retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_free_pd(%p, %p)", hca_hdl, pd);

	/* re-direct the call to CI's call */
	retval = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_free_pd(
	    IBTL_HCA2CIHCA(hca_hdl), pd);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_free_pd: CI Free PD Failed");
		return (retval);
	}

	/* Update the PDs Resource Count per HCA Device. */
	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_pd_cnt--;
	mutex_exit(&hca_hdl->ha_mutex);

	return (retval);
}


/*
 * Address Handle Verbs Functions.
 */

/*
 * Function:
 *	ibt_alloc_ah
 * Input:
 *	hca_hdl		The IBT HCA Handle.
 *	pd		The IBT Protection Domain to associate with this handle.
 *	adds_vectp	Points to an ibt_adds_vect_t struct.
 * Output:
 *	ah		IBT Address Handle.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_HCA_HDL_INVALID
 *	IBT_INSUFF_RESOURCE
 *	IBT_MEM_PD_HDL_INVALID
 * Description:
 *	Allocate and returns an Address Handle.
 */
ibt_status_t
ibt_alloc_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_flags_t flags, ibt_pd_hdl_t pd,
    ibt_adds_vect_t *adds_vectp, ibt_ah_hdl_t *ah)
{
	ibt_status_t	retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_alloc_ah(%p, %x, %p, %p)",
	    hca_hdl, flags, pd, adds_vectp);

	/* XXX - if av_send_grh, need to compute av_sgid_ix from av_sgid */

	/* re-direct the call to CI's call */
	retval = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_ah(
	    IBTL_HCA2CIHCA(hca_hdl), flags, pd, adds_vectp, ah);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_alloc_ah: "
		    "ibc_alloc_ah failed: status = %d", retval);
		return (retval);
	}

	/* Update the AHs Resource Count per HCA Device. */
	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_ah_cnt++;
	mutex_exit(&hca_hdl->ha_mutex);

	return (retval);
}


/*
 * Function:
 *	ibt_free_ah
 * Input:
 *	hca_hdl		The IBT HCA Handle.
 *	ah		IBT Address Handle.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_HCA_HDL_INVALID
 *	IBT_AH_HDL_INVALID
 * Description:
 *	Release/de-allocate the specified Address Handle.
 */
ibt_status_t
ibt_free_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah)
{
	ibt_status_t	retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_free_ah(%p, %p)", hca_hdl, ah);

	/* re-direct the call to CI's call */
	retval = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_free_ah(
	    IBTL_HCA2CIHCA(hca_hdl), ah);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtl_chan, "ibt_free_ah: CI Free AH Failed");
		return (retval);
	}

	/* Update the AHs Resource Count per HCA Device. */
	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_ah_cnt--;
	mutex_exit(&hca_hdl->ha_mutex);

	return (retval);
}


/*
 * Function:
 *	ibt_query_ah
 * Input:
 *	hca_hdl		The IBT HCA Handle.
 *	ah		IBT Address Handle.
 * Output:
 *	pd		The Protection Domain Handle with which this
 *			Address Handle is associated.
 *	adds_vectp	Points to an ibt_adds_vect_t struct.
 * Returns:
 *	IBT_SUCCESS/IBT_HCA_HDL_INVALID/IBT_AH_HDL_INVALID
 * Description:
 *	Obtain the address vector information for the specified address handle.
 */
ibt_status_t
ibt_query_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah, ibt_pd_hdl_t *pd,
    ibt_adds_vect_t *adds_vectp)
{
	ibt_status_t	retval;

	IBTF_DPRINTF_L3(ibtl_chan, "ibt_query_ah(%p, %p)", hca_hdl, ah);

	/* re-direct the call to CI's call */
	retval = (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_query_ah(
	    IBTL_HCA2CIHCA(hca_hdl), ah, pd, adds_vectp));

	/*
	 * We need to fill in av_sgid, as the CI does only saves/restores
	 * av_sgid_ix.
	 */
	if (retval == IBT_SUCCESS) {
		ibtl_hca_devinfo_t *hca_devp = hca_hdl->ha_hca_devp;
		uint8_t port = adds_vectp->av_port_num;

		mutex_enter(&ibtl_clnt_list_mutex);
		if (port > 0 && port <= hca_devp->hd_hca_attr->hca_nports &&
		    adds_vectp->av_sgid_ix < IBTL_HDIP2SGIDTBLSZ(hca_devp)) {
			ib_gid_t *sgidp;

			sgidp = hca_devp->hd_portinfop[port-1].p_sgid_tbl;
			adds_vectp->av_sgid = sgidp[adds_vectp->av_sgid_ix];
		} else {
			adds_vectp->av_sgid.gid_prefix = 0;
			adds_vectp->av_sgid.gid_guid = 0;
		}
		mutex_exit(&ibtl_clnt_list_mutex);
	}
	return (retval);
}


/*
 * Function:
 *	ibt_modify_ah
 * Input:
 *	hca_hdl		The IBT HCA Handle.
 *	ah		IBT Address Handle.
 * Output:
 *	adds_vectp	Points to an ibt_adds_vect_t struct. The new address
 *			vector information is specified is returned in this
 *			structure.
 * Returns:
 *	IBT_SUCCESS/IBT_HCA_HDL_INVALID/IBT_AH_HDL_INVALID
 * Description:
 *	Modify the address vector information for the specified Address Handle.
 */
ibt_status_t
ibt_modify_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah,
    ibt_adds_vect_t *adds_vectp)
{
	IBTF_DPRINTF_L3(ibtl_chan, "ibt_modify_ah(%p, %p)", hca_hdl, ah);

	/* XXX - if av_send_grh, need to compute av_sgid_ix from av_sgid */

	/* re-direct the call to CI's call */
	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_modify_ah(
	    IBTL_HCA2CIHCA(hca_hdl), ah, adds_vectp));
}

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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ib/ibtl/impl/ibtl.h>
#include <sys/ib/ibtl/impl/ibtl_cm.h>

/*
 * ibtl_qp.c
 *	These routines implement (most of) the verbs related to
 *	Queue Pairs.
 */

/* Globals. */
static char ibtf_qp[] = "ibtl";

/* This table indirectly initializes the ibt_cep_next_state[] table. */
typedef struct ibt_cep_next_state_s {
	ibt_cep_state_t		next_state;
	ibt_cep_modify_flags_t	modify_flags;
} ibt_cep_next_state_t;

struct	{
	ibt_cep_state_t		current_state;
	ibt_cep_state_t		next_state;
	ibt_cep_modify_flags_t	modify_flags;
} ibt_cep_next_state_inits[] = {
	{ IBT_STATE_RESET, IBT_STATE_INIT, IBT_CEP_SET_RESET_INIT},
	{ IBT_STATE_INIT, IBT_STATE_RTR, IBT_CEP_SET_INIT_RTR},
	{ IBT_STATE_RTR, IBT_STATE_RTS, IBT_CEP_SET_RTR_RTS}
};

ibt_cep_next_state_t ibt_cep_next_state[IBT_STATE_NUM];

_NOTE(SCHEME_PROTECTS_DATA("unique", ibt_cep_next_state))

/* The following data and functions can increase system stability. */

int ibtl_qp_calls_curr;
int ibtl_qp_calls_max = 128;	/* limit on # of simultaneous QP verb calls */
kmutex_t ibtl_qp_mutex;
kcondvar_t ibtl_qp_cv;

void
ibtl_qp_flow_control_enter(void)
{
	mutex_enter(&ibtl_qp_mutex);
	while (ibtl_qp_calls_curr >= ibtl_qp_calls_max) {
		cv_wait(&ibtl_qp_cv, &ibtl_qp_mutex);
	}
	++ibtl_qp_calls_curr;
	mutex_exit(&ibtl_qp_mutex);
}

void
ibtl_qp_flow_control_exit(void)
{
	mutex_enter(&ibtl_qp_mutex);
	cv_signal(&ibtl_qp_cv);
	--ibtl_qp_calls_curr;
	mutex_exit(&ibtl_qp_mutex);
}

/*
 * Function:
 *	ibt_alloc_qp
 * Input:
 *	hca_hdl		HCA Handle.
 *	type		Specifies the type of QP to alloc in ibt_alloc_qp()
 *	qp_attrp	Specifies the ibt_qp_alloc_attr_t that are needed to
 *			allocate a QP and transition it to the RTS state for
 *			UDs and INIT state for all other QPs.
 * Output:
 *	queue_sizes_p	Returned sizes for SQ, RQ, SQ WR SGL elements & RQ
 *			WR SGL elements.
 *	qpn_p		Returned QP Number of the allocated QP.
 *	ibt_qp_p	The ibt_qp_hdl_t of the allocated QP.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Allocate a QP with specified attributes.
 */
ibt_status_t
ibt_alloc_qp(ibt_hca_hdl_t hca_hdl, ibt_qp_type_t type,
    ibt_qp_alloc_attr_t *qp_attrp, ibt_chan_sizes_t *queue_sizes_p,
    ib_qpn_t *qpn_p, ibt_qp_hdl_t *ibt_qp_p)
{
	ibt_status_t		retval;
	ibtl_channel_t		*chanp;
	ibt_tran_srv_t		qp_type;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_alloc_qp(%p, %d, %p, %p, %p, %p) ",
	    hca_hdl, type, qp_attrp, queue_sizes_p, qpn_p, ibt_qp_p);

	switch (type) {
	case IBT_UD_RQP:
		qp_type = IBT_UD_SRV;
		break;
	case IBT_RC_RQP:
		qp_type = IBT_RC_SRV;
		break;
	case IBT_UC_RQP:
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_qp: Unreliable Connected "
		    "Transport Type is not supported.");
		*ibt_qp_p = NULL;
		return (IBT_NOT_SUPPORTED);
	case IBT_RD_RQP:
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_qp: Reliable Datagram "
		    "Transport Type is not supported.");
		*ibt_qp_p = NULL;
		return (IBT_NOT_SUPPORTED);
	default:
		/* shouldn't happen ILLEGAL Type */
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_qp: Illegal Transport Type "
		    "%d", type);
		*ibt_qp_p = NULL;
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	/* Get CI CQ handles */
	if ((qp_attrp->qp_scq_hdl == NULL) || (qp_attrp->qp_rcq_hdl == NULL)) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_qp: Invalid CQ Handle");
		*ibt_qp_p = NULL;
		return (IBT_CQ_HDL_INVALID);
	}
	qp_attrp->qp_ibc_scq_hdl = qp_attrp->qp_scq_hdl->cq_ibc_cq_hdl;
	qp_attrp->qp_ibc_rcq_hdl = qp_attrp->qp_rcq_hdl->cq_ibc_cq_hdl;

	if ((qp_attrp->qp_alloc_flags & IBT_QP_USES_SRQ) &&
	    (qp_attrp->qp_srq_hdl != NULL))
		qp_attrp->qp_ibc_srq_hdl =
		    qp_attrp->qp_srq_hdl->srq_ibc_srq_hdl;
	else
		qp_attrp->qp_ibc_srq_hdl = NULL;

	/* Allocate Channel structure */
	chanp = kmem_zalloc(sizeof (*chanp), KM_SLEEP);

	ibtl_qp_flow_control_enter();
	retval = (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_qp)(
	    IBTL_HCA2CIHCA(hca_hdl), &chanp->ch_qp, type, qp_attrp,
	    queue_sizes_p, qpn_p, &chanp->ch_qp.qp_ibc_qp_hdl);
	ibtl_qp_flow_control_exit();
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_qp: "
		    "Failed to allocate QP: %d", retval);
		kmem_free(chanp, sizeof (*chanp));
		*ibt_qp_p = NULL;
		return (retval);
	}

	/* Initialize the internal QP struct. */
	chanp->ch_qp.qp_type = qp_type;
	chanp->ch_qp.qp_hca = hca_hdl;
	chanp->ch_qp.qp_send_cq = qp_attrp->qp_scq_hdl;
	chanp->ch_qp.qp_recv_cq = qp_attrp->qp_rcq_hdl;
	chanp->ch_current_state = IBT_STATE_RESET;
	mutex_init(&chanp->ch_cm_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&chanp->ch_cm_cv, NULL, CV_DEFAULT, NULL);

	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_qp_cnt++;
	mutex_exit(&hca_hdl->ha_mutex);

	IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_qp: SUCCESS: qp %p owned by '%s'",
	    chanp, hca_hdl->ha_clnt_devp->clnt_name);

	*ibt_qp_p = chanp;

	return (retval);
}


/*
 * Function:
 *	ibt_initialize_qp
 * Input:
 *	ibt_qp		The previously allocated IBT QP Handle.
 *	modify_attrp	Specifies the QP Modify attributes that to transition
 *			the QP to the RTS state for UDs (including special QPs)
 *			and INIT state for all other QPs.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Transition the QP to the RTS state for UDs (including special QPs)
 *	and INIT state for all other QPs.
 */
ibt_status_t
ibt_initialize_qp(ibt_qp_hdl_t ibt_qp, ibt_qp_info_t *modify_attrp)
{
	ibt_status_t		status;
	ibt_cep_state_t		state;
	ibc_hca_hdl_t		ibc_hca_hdl = IBTL_CHAN2CIHCA(ibt_qp);
	ibc_qp_hdl_t		ibc_qp_hdl = IBTL_CHAN2CIQP(ibt_qp);
	ibc_operations_t	*hca_ops_p = IBTL_CHAN2CIHCAOPS_P(ibt_qp);
	ibt_cep_modify_flags_t	modify_flags;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_initialize_qp(%p, %p)",
	    ibt_qp, modify_attrp);

	/*
	 * Validate the QP Type from the channel with QP Type from the
	 * modify attribute struct.
	 */
	if (ibt_qp->ch_qp.qp_type != modify_attrp->qp_trans) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_initialize_qp: "
		    "QP Type mismatch: Chan QP Type<%d>, Modify QP Type<%d>",
		    ibt_qp->ch_qp.qp_type, modify_attrp->qp_trans);
		return (IBT_QP_SRV_TYPE_INVALID);
	}
	if (ibt_qp->ch_current_state != IBT_STATE_RESET) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_initialize_qp: "
		    "QP needs to be in RESET state: Chan QP State<%d>",
		    ibt_qp->ch_current_state);
		return (IBT_CHAN_STATE_INVALID);
	}

	/*
	 * Initialize the QP to the RTS state for UDs
	 * and INIT state for all other QPs.
	 */
	switch (modify_attrp->qp_trans) {
	case IBT_UD_SRV:

		/*
		 * Bring the QP to the RTS state.
		 */
		state = IBT_STATE_RESET;
		ibtl_qp_flow_control_enter();
		do {
			modify_attrp->qp_current_state = state;
			modify_flags = ibt_cep_next_state[state].modify_flags;
			modify_attrp->qp_state = state =
			    ibt_cep_next_state[state].next_state;

			IBTF_DPRINTF_L3(ibtf_qp, "ibt_initialize_qp: "
			    "modifying qp state to 0x%x", state);
			status = (hca_ops_p->ibc_modify_qp)(ibc_hca_hdl,
			    ibc_qp_hdl, modify_flags, modify_attrp, NULL);
		} while ((state != IBT_STATE_RTS) && (status == IBT_SUCCESS));
		ibtl_qp_flow_control_exit();

		if (status == IBT_SUCCESS) {
			ibt_qp->ch_current_state = state;
			ibt_qp->ch_transport.ud.ud_port_num =
			    modify_attrp->qp_transport.ud.ud_port;
			ibt_qp->ch_transport.ud.ud_qkey =
			    modify_attrp->qp_transport.ud.ud_qkey;
		}
		break;
	case IBT_UC_SRV:
	case IBT_RD_SRV:
	case IBT_RC_SRV:

		/*
		 * Bring the QP to the INIT state.
		 */
		modify_attrp->qp_state = IBT_STATE_INIT;

		ibtl_qp_flow_control_enter();
		status = (hca_ops_p->ibc_modify_qp)(ibc_hca_hdl, ibc_qp_hdl,
		    IBT_CEP_SET_RESET_INIT, modify_attrp, NULL);
		ibtl_qp_flow_control_exit();
		if (status == IBT_SUCCESS)
			ibt_qp->ch_current_state = IBT_STATE_INIT;
		break;
	default:
		/* shouldn't happen ILLEGAL Type */
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_initialize_qp: Illegal Type %d",
		    modify_attrp->qp_trans);
		return (IBT_QP_SRV_TYPE_INVALID);
	} /* End switch */

	return (status);
}


/*
 * Function:
 *	ibt_alloc_special_qp
 * Input:
 *	hca_hdl		HCA Handle.
 *	type		Specifies the type of Special QP to be allocated.
 *	qp_attrp	Specifies the ibt_qp_alloc_attr_t that are needed to
 *			allocate a special QP.
 * Output:
 *	queue_sizes_p	Returned sizes for SQ, RQ, SQ WR SGL elements & RQ
 *			WR SGL elements.
 *	qpn_p		Returned qpn of the allocated QP.
 *	ibt_qp_p	The ibt_qp_hdl_t of the allocated QP.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Allocate a special QP with specified attributes.
 */
ibt_status_t
ibt_alloc_special_qp(ibt_hca_hdl_t hca_hdl, uint8_t port, ibt_sqp_type_t type,
    ibt_qp_alloc_attr_t *qp_attrp, ibt_chan_sizes_t *queue_sizes_p,
    ibt_qp_hdl_t *ibt_qp_p)
{
	ibt_qp_hdl_t	chanp;
	ibt_status_t	retval;
	ibt_tran_srv_t	sqp_type;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_alloc_special_qp(%p, %d, %x, %p, %p, %p)",
	    hca_hdl, port, type, qp_attrp, queue_sizes_p, ibt_qp_p);

	switch (type) {
	case IBT_SMI_SQP:
	case IBT_GSI_SQP:
		sqp_type = IBT_UD_SRV;
		break;

	case IBT_RAWIP_SQP:
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_special_qp: Raw IP "
		    "Transport Type is not supported.");
		*ibt_qp_p = NULL;
		return (IBT_NOT_SUPPORTED);

	case IBT_RAWETHER_SQP:
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_special_qp: Raw Ethernet "
		    "Transport Type is not supported.");
		*ibt_qp_p = NULL;
		return (IBT_NOT_SUPPORTED);

	default:
		/* Shouldn't happen */
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_special_qp: "
		    "Illegal Type 0x%x", type);
		*ibt_qp_p = NULL;
		return (IBT_QP_SPECIAL_TYPE_INVALID);
	}

	/* convert the CQ handles for the CI */
	qp_attrp->qp_ibc_scq_hdl = qp_attrp->qp_scq_hdl->cq_ibc_cq_hdl;
	qp_attrp->qp_ibc_rcq_hdl = qp_attrp->qp_rcq_hdl->cq_ibc_cq_hdl;

	/* Allocate Channel structure */
	chanp = kmem_zalloc(sizeof (*chanp), KM_SLEEP);

	ibtl_qp_flow_control_enter();
	retval = (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_special_qp)(
	    IBTL_HCA2CIHCA(hca_hdl), port, &chanp->ch_qp, type, qp_attrp,
	    queue_sizes_p, &chanp->ch_qp.qp_ibc_qp_hdl);
	ibtl_qp_flow_control_exit();
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_alloc_special_qp: "
		    "Failed to allocate Special QP: %d", retval);
		kmem_free(chanp, sizeof (*chanp));
		*ibt_qp_p = NULL;
		return (retval);
	}

	/* Initialize the internal QP struct. */
	chanp->ch_qp.qp_type = sqp_type;
	chanp->ch_qp.qp_hca = hca_hdl;
	chanp->ch_qp.qp_send_cq = qp_attrp->qp_scq_hdl;
	chanp->ch_qp.qp_recv_cq = qp_attrp->qp_rcq_hdl;
	chanp->ch_current_state = IBT_STATE_RESET;
	mutex_init(&chanp->ch_cm_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&chanp->ch_cm_cv, NULL, CV_DEFAULT, NULL);

	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_qp_cnt++;
	mutex_exit(&hca_hdl->ha_mutex);

	*ibt_qp_p = chanp;

	return (retval);
}


/*
 * Function:
 *	ibt_flush_qp
 * Input:
 *	ibtl_qp		Handle for QP that needs to be flushed.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_QP_HDL_INVALID
 * Description:
 *	Put the QP into error state to flush out work requests.
 */
ibt_status_t
ibt_flush_qp(ibt_qp_hdl_t ibt_qp)
{
	ibt_qp_info_t		modify_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_flush_qp(%p)", ibt_qp);

	if (ibt_qp->ch_qp.qp_type == IBT_RC_SRV) {
		mutex_enter(&ibtl_free_qp_mutex);
		if ((ibt_qp->ch_transport.rc.rc_free_flags &
		    (IBTL_RC_QP_CONNECTED | IBTL_RC_QP_CLOSING)) ==
		    IBTL_RC_QP_CONNECTED) {
			mutex_exit(&ibtl_free_qp_mutex);
			IBTF_DPRINTF_L2(ibtf_qp, "ibt_flush_qp(%p): "
			    "called with a connected RC QP", ibt_qp);
			return (IBT_CHAN_STATE_INVALID);
		}
		mutex_exit(&ibtl_free_qp_mutex);
	}

	bzero(&modify_attr, sizeof (ibt_qp_info_t));

	/*
	 * Set the QP state to error to flush any uncompleted WRs.
	 */
	modify_attr.qp_state = IBT_STATE_ERROR;
	modify_attr.qp_trans = ibt_qp->ch_qp.qp_type;

	retval = ibt_modify_qp(ibt_qp, IBT_CEP_SET_STATE, &modify_attr, NULL);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_flush_qp: "
		    "failed on chan %p: %d", ibt_qp, retval);
	}
	return (retval);
}


/*
 * ibtl_cm_chan_is_open()
 *
 *	Inform IBTL that the connection has been established on this
 *	channel so that a later call to ibtl_cm_chan_is_closed()
 *	will be required to free the QPN used by this channel.
 *
 *	chan	Channel Handle
 */
void
ibtl_cm_chan_is_open(ibt_channel_hdl_t chan)
{
	IBTF_DPRINTF_L3(ibtf_qp, "ibtl_cm_chan_is_open(%p)", chan);
	ASSERT(chan->ch_qp.qp_type == IBT_RC_SRV);
	mutex_enter(&ibtl_free_qp_mutex);
	ASSERT(chan->ch_transport.rc.rc_free_flags == 0);
	chan->ch_transport.rc.rc_free_flags |= IBTL_RC_QP_CONNECTED;
	mutex_exit(&ibtl_free_qp_mutex);
}

/*
 * ibtl_cm_is_chan_closing()
 *
 *	Returns 1, if the connection that has been
 *	started for this channel has moved to TIMEWAIT
 *	If not, returns 0
 *
 *	chan	Channel Handle
 */
int
ibtl_cm_is_chan_closing(ibt_channel_hdl_t chan)
{
	IBTF_DPRINTF_L3(ibtf_qp, "ibtl_cm_is_chan_closing(%p)", chan);
	ASSERT(chan->ch_qp.qp_type == IBT_RC_SRV);
	mutex_enter(&ibtl_free_qp_mutex);
	if (chan->ch_transport.rc.rc_free_flags & IBTL_RC_QP_CLOSING) {
		mutex_exit(&ibtl_free_qp_mutex);
		return (1);
	}
	mutex_exit(&ibtl_free_qp_mutex);
	return (0);
}

/*
 * ibtl_cm_is_chan_closed()
 *
 *	Returns 1, if the connection that has been
 *	started for this channel has completed TIMEWAIT
 *	If not, returns 0
 *
 *	chan	Channel Handle
 */
int
ibtl_cm_is_chan_closed(ibt_channel_hdl_t chan)
{
	IBTF_DPRINTF_L3(ibtf_qp, "ibtl_cm_is_chan_closed(%p)", chan);
	ASSERT(chan->ch_qp.qp_type == IBT_RC_SRV);
	mutex_enter(&ibtl_free_qp_mutex);
	if (chan->ch_transport.rc.rc_free_flags & IBTL_RC_QP_CLOSED) {
		mutex_exit(&ibtl_free_qp_mutex);
		return (1);
	}
	mutex_exit(&ibtl_free_qp_mutex);
	return (0);
}
/*
 * ibtl_cm_chan_is_closing()
 *
 *	Inform IBTL that the TIMEWAIT delay for the connection has been
 *	started for this channel so that the QP can be freed.
 *
 *	chan	Channel Handle
 */
void
ibtl_cm_chan_is_closing(ibt_channel_hdl_t chan)
{
	IBTF_DPRINTF_L3(ibtf_qp, "ibtl_cm_chan_is_closing(%p)", chan);
	ASSERT(chan->ch_qp.qp_type == IBT_RC_SRV);
	mutex_enter(&ibtl_free_qp_mutex);
	ASSERT(chan->ch_transport.rc.rc_free_flags == IBTL_RC_QP_CONNECTED);
	chan->ch_transport.rc.rc_free_flags |= IBTL_RC_QP_CLOSING;
	mutex_exit(&ibtl_free_qp_mutex);
}
/*
 * ibtl_cm_chan_is_closed()
 *
 *	Inform IBTL that the TIMEWAIT delay for the connection has been
 *	reached for this channel so that the QPN can be reused.
 *
 *	chan	Channel Handle
 */
void
ibtl_cm_chan_is_closed(ibt_channel_hdl_t chan)
{
	ibt_status_t status;
	ibtl_hca_t *ibtl_hca = chan->ch_qp.qp_hca;

	IBTF_DPRINTF_L3(ibtf_qp, "ibtl_cm_chan_is_closed(%p)", chan);
	ASSERT(chan->ch_qp.qp_type == IBT_RC_SRV);
	mutex_enter(&ibtl_free_qp_mutex);
	ASSERT((chan->ch_transport.rc.rc_free_flags &
	    (IBTL_RC_QP_CONNECTED | IBTL_RC_QP_CLOSING)) ==
	    (IBTL_RC_QP_CONNECTED | IBTL_RC_QP_CLOSING));

	chan->ch_transport.rc.rc_free_flags &= ~IBTL_RC_QP_CONNECTED;
	chan->ch_transport.rc.rc_free_flags &= ~IBTL_RC_QP_CLOSING;
	chan->ch_transport.rc.rc_free_flags |= IBTL_RC_QP_CLOSED;

	ibtl_cm_set_chan_private(chan, NULL);

	if ((chan->ch_transport.rc.rc_free_flags & IBTL_RC_QP_FREED) == 0) {
		mutex_exit(&ibtl_free_qp_mutex);
		return;
	}
	mutex_exit(&ibtl_free_qp_mutex);
	ibtl_qp_flow_control_enter();
	if ((status = (IBTL_CHAN2CIHCAOPS_P(chan)->ibc_release_qpn)
	    (IBTL_CHAN2CIHCA(chan), chan->ch_transport.rc.rc_qpn_hdl)) ==
	    IBT_SUCCESS) {
		/* effectively, this is kmem_free(chan); */
		ibtl_free_qp_async_check(&chan->ch_qp);

		/* decrement ha_qpn_cnt and check for close in progress */
		ibtl_close_hca_check(ibtl_hca);
	} else
		IBTF_DPRINTF_L2(ibtf_qp, "ibtl_cm_chan_is_closed: "
		    "ibc_release_qpn failed: status = %d\n", status);
	ibtl_qp_flow_control_exit();
}

/*
 * ibtl_cm_chan_is_reused()
 *
 *	Inform IBTL that the channel is going to be re-used
 *	chan	Channel Handle
 */
void
ibtl_cm_chan_is_reused(ibt_channel_hdl_t chan)
{
	IBTF_DPRINTF_L3(ibtf_qp, "ibtl_cm_chan_is_reused(%p)", chan);
	ASSERT(chan->ch_qp.qp_type == IBT_RC_SRV);
	mutex_enter(&ibtl_free_qp_mutex);
	ASSERT(((chan->ch_transport.rc.rc_free_flags & IBTL_RC_QP_CONNECTED) !=
	    IBTL_RC_QP_CONNECTED));

	/* channel is no longer in closed state, shall be re-used */
	chan->ch_transport.rc.rc_free_flags = 0;

	mutex_exit(&ibtl_free_qp_mutex);

}

/*
 * Function:	ibt_free_qp()
 *
 * Input:	ibt_qp		Handle for Channel(QP) that needs to be freed.
 *
 * Output:	NONE.
 *
 * Returns:	IBT_SUCCESS
 *		IBT_QP_STATE_INVALID
 *		IBT_QP_HDL_INVALID
 *
 * Description:
 *		Free a previously allocated QP.
 */
ibt_status_t
ibt_free_qp(ibt_qp_hdl_t ibt_qp)
{
	ibt_status_t		status;
	ibtl_hca_t		*ibtl_hca = ibt_qp->ch_qp.qp_hca;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_free_qp(%p)", ibt_qp);

	if (ibt_qp->ch_qp.qp_type == IBT_RC_SRV) {
		ibtl_qp_flow_control_enter();
		mutex_enter(&ibtl_free_qp_mutex);
		if (ibt_qp->ch_transport.rc.rc_free_flags &
		    IBTL_RC_QP_CONNECTED) {
			if ((ibt_qp->ch_transport.rc.rc_free_flags &
			    IBTL_RC_QP_CLOSING) == 0) {
				IBTF_DPRINTF_L2(ibtf_qp, "ibt_free_qp: ERROR - "
				    "need to call ibt_close_rc_channel");
				mutex_exit(&ibtl_free_qp_mutex);
				ibtl_qp_flow_control_exit();
				return (IBT_CHAN_STATE_INVALID);
			}
			ibt_qp->ch_transport.rc.rc_free_flags |=
			    IBTL_RC_QP_FREED;
			status = (IBTL_CHAN2CIHCAOPS_P(ibt_qp)->ibc_free_qp)
			    (IBTL_CHAN2CIHCA(ibt_qp), IBTL_CHAN2CIQP(ibt_qp),
			    IBC_FREE_QP_ONLY,
			    &ibt_qp->ch_transport.rc.rc_qpn_hdl);
			mutex_exit(&ibtl_free_qp_mutex);
			ibtl_qp_flow_control_exit();

			if (status == IBT_SUCCESS) {
				mutex_enter(&ibtl_clnt_list_mutex);
				ibtl_hca->ha_qpn_cnt++;
				mutex_exit(&ibtl_clnt_list_mutex);
				mutex_enter(&ibtl_hca->ha_mutex);
				ibtl_hca->ha_qp_cnt--;
				mutex_exit(&ibtl_hca->ha_mutex);
				IBTF_DPRINTF_L3(ibtf_qp, "ibt_free_qp(%p) - "
				    "SUCCESS", ibt_qp);
			} else
				IBTF_DPRINTF_L2(ibtf_qp, "ibt_free_qp: "
				    "ibc_free_qp failed: status = %d", status);
			return (status);
		}
		mutex_exit(&ibtl_free_qp_mutex);
	} else
		ibtl_qp_flow_control_enter();

	status = (IBTL_CHAN2CIHCAOPS_P(ibt_qp)->ibc_free_qp)
	    (IBTL_CHAN2CIHCA(ibt_qp), IBTL_CHAN2CIQP(ibt_qp),
	    IBC_FREE_QP_AND_QPN, NULL);
	ibtl_qp_flow_control_exit();

	if (status == IBT_SUCCESS) {
		/* effectively, this is kmem_free(ibt_qp); */
		ibtl_free_qp_async_check(&ibt_qp->ch_qp);

		mutex_enter(&ibtl_hca->ha_mutex);
		ibtl_hca->ha_qp_cnt--;
		mutex_exit(&ibtl_hca->ha_mutex);
		IBTF_DPRINTF_L3(ibtf_qp, "ibt_free_qp(%p) - SUCCESS", ibt_qp);
	} else {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_free_qp: "
		    "ibc_free_qp failed with error %d", status);
	}

	return (status);
}


/* helper function for ibt_query_qp */
static void
ibtl_fillin_sgid(ibt_cep_path_t *pathp, ibtl_hca_devinfo_t *hca_devp)
{
	uint8_t port;
	uint32_t sgid_ix;
	ib_gid_t *sgidp;

	port = pathp->cep_hca_port_num;
	sgid_ix = pathp->cep_adds_vect.av_sgid_ix;
	if (port == 0 || port > hca_devp->hd_hca_attr->hca_nports ||
	    sgid_ix >= IBTL_HDIP2SGIDTBLSZ(hca_devp)) {
		pathp->cep_adds_vect.av_sgid.gid_prefix = 0;
		pathp->cep_adds_vect.av_sgid.gid_guid = 0;
	} else {
		mutex_enter(&ibtl_clnt_list_mutex);
		sgidp = hca_devp->hd_portinfop[port-1].p_sgid_tbl;
		pathp->cep_adds_vect.av_sgid = sgidp[sgid_ix];
		mutex_exit(&ibtl_clnt_list_mutex);
	}
}


/*
 * Function:	ibt_query_qp
 *
 * Input:	ibt_qp 			- The IBT QP Handle.
 *
 * Output:	ibt_qp_query_attrp 	- Points to a ibt_qp_query_attr_t
 *					  that on return contains all the
 *					  attributes of the specified qp.
 *
 * Returns:	IBT_SUCCESS
 *		IBT_QP_HDL_INVALID
 *
 * Description:
 *		Query QP attributes
 *
 */
ibt_status_t
ibt_query_qp(ibt_qp_hdl_t ibt_qp, ibt_qp_query_attr_t *qp_query_attrp)
{
	ibt_status_t		retval;
	ibtl_hca_devinfo_t	*hca_devp;
	ibt_qp_info_t		*qp_infop;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_query_qp(%p, %p)",
	    ibt_qp, qp_query_attrp);

	ibtl_qp_flow_control_enter();
	retval = (IBTL_CHAN2CIHCAOPS_P(ibt_qp)->ibc_query_qp(
	    IBTL_CHAN2CIHCA(ibt_qp), IBTL_CHAN2CIQP(ibt_qp), qp_query_attrp));
	ibtl_qp_flow_control_exit();
	if (retval == IBT_SUCCESS) {
		ibt_qp->ch_current_state = qp_query_attrp->qp_info.qp_state;

		/* need to fill in sgid from port and sgid_ix for RC and UC */
		hca_devp = ibt_qp->ch_qp.qp_hca->ha_hca_devp;
		qp_infop = &qp_query_attrp->qp_info;

		switch (qp_infop->qp_trans) {
		case IBT_RC_SRV:
			ibtl_fillin_sgid(&qp_infop->qp_transport.rc.rc_path,
			    hca_devp);
			ibtl_fillin_sgid(&qp_infop->qp_transport.rc.rc_alt_path,
			    hca_devp);
			break;
		case IBT_UC_SRV:
			ibtl_fillin_sgid(&qp_infop->qp_transport.uc.uc_path,
			    hca_devp);
			ibtl_fillin_sgid(&qp_infop->qp_transport.uc.uc_alt_path,
			    hca_devp);
			break;
		}
	} else {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_query_qp: "
		    "failed on chan %p: %d", ibt_qp, retval);
	}

	return (retval);
}


/*
 * Function:
 *	ibt_modify_qp
 * Input:
 *	ibt_qp		The IBT QP Handle.
 *	flags		Specifies which attributes in ibt_qp_mod_attr_t
 *			are to be modified.
 *	qp_attrp	Points to an ibt_qp_mod_attr_t struct that contains all
 *			the attributes of the specified QP that a client is
 *			allowed to modify after a QP has been allocated
 * Output:
 *	actual_sz	Returned actual queue sizes.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Modify the attributes of an existing QP.
 */
ibt_status_t
ibt_modify_qp(ibt_qp_hdl_t ibt_qp, ibt_cep_modify_flags_t flags,
    ibt_qp_info_t *modify_attrp, ibt_queue_sizes_t *actual_sz)
{
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_modify_qp(%p, %d, %p, %p)",
	    ibt_qp, flags, modify_attrp, actual_sz);

	ibtl_qp_flow_control_enter();
	retval = (IBTL_CHAN2CIHCAOPS_P(ibt_qp)->ibc_modify_qp)(
	    IBTL_CHAN2CIHCA(ibt_qp), IBTL_CHAN2CIQP(ibt_qp), flags,
	    modify_attrp, actual_sz);
	ibtl_qp_flow_control_exit();
	if (retval == IBT_SUCCESS) {
		ibt_qp->ch_current_state = modify_attrp->qp_state;
		if (ibt_qp->ch_qp.qp_type == IBT_UD_SRV) {
			if (flags & (IBT_CEP_SET_PORT | IBT_CEP_SET_RESET_INIT))
				ibt_qp->ch_transport.ud.ud_port_num =
				    modify_attrp->qp_transport.ud.ud_port;
			if (flags & (IBT_CEP_SET_QKEY | IBT_CEP_SET_RESET_INIT))
				ibt_qp->ch_transport.ud.ud_qkey =
				    modify_attrp->qp_transport.ud.ud_qkey;
		}
	} else {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_modify_qp: failed on chan %p: %d",
		    ibt_qp, retval);

		if (retval == IBT_CHAN_STATE_INVALID) {
			/* That means our cache had invalid QP state value. */
			ibt_qp_query_attr_t	qp_attr;

			/* Query the channel (QP) */
			if (ibt_query_qp(ibt_qp, &qp_attr) == IBT_SUCCESS)
				ibt_qp->ch_current_state =
				    qp_attr.qp_info.qp_state;
		}
	}
	return (retval);
}


/*
 * Function:
 *	ibt_migrate_path
 * Input:
 *	rc_chan		A previously allocated RC channel handle.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS on Success else appropriate error.
 * Description:
 *	Force the CI to use the alternate path. The alternate path becomes
 *	the primary path. A new alternate path should be loaded and enabled.
 *	Assumes that the given channel is in RTS/SQD state
 */
ibt_status_t
ibt_migrate_path(ibt_channel_hdl_t rc_chan)
{
	ibt_status_t		retval;
	ibt_qp_info_t		qp_info;
	ibt_qp_query_attr_t	qp_attr;
	ibt_cep_modify_flags_t	cep_flags;
	int			retries = 1;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_migrate_path: channel %p", rc_chan);

	if (rc_chan->ch_qp.qp_type != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_migrate_path: "
		    "Invalid Channel type: Applicable only to RC Channel");
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	if (rc_chan->ch_current_state != IBT_STATE_RTS &&
	    rc_chan->ch_current_state != IBT_STATE_SQD) {
		if (ibt_query_qp(rc_chan, &qp_attr) == IBT_SUCCESS) {
			/* ch_current_state is fixed by ibt_query_qp */
			if (rc_chan->ch_current_state != IBT_STATE_RTS &&
			    rc_chan->ch_current_state != IBT_STATE_SQD)
				return (IBT_CHAN_STATE_INVALID);
			retries = 0;
		} else /* query_qp should never really fail */
			return (IBT_CHAN_STATE_INVALID);
	}

retry:
	/* Call modify_qp */
	cep_flags = IBT_CEP_SET_MIG | IBT_CEP_SET_STATE;
	qp_info.qp_state = rc_chan->ch_current_state;
	qp_info.qp_current_state = rc_chan->ch_current_state;
	qp_info.qp_trans = IBT_RC_SRV;
	qp_info.qp_transport.rc.rc_mig_state = IBT_STATE_MIGRATED;
	retval = ibt_modify_qp(rc_chan, cep_flags, &qp_info, NULL);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_migrate_path:"
		    " ibt_modify_qp() returned = %d", retval);
		if (rc_chan->ch_current_state != qp_info.qp_state &&
		    --retries >= 0) {
			/*
			 * That means our cached 'state' was invalid.
			 * We know ibt_modify_qp() fixed it up, so it
			 * might be worth retrying.
			 */
			if (rc_chan->ch_current_state != IBT_STATE_RTS &&
			    rc_chan->ch_current_state != IBT_STATE_SQD)
				return (IBT_CHAN_STATE_INVALID);
			IBTF_DPRINTF_L2(ibtf_qp, "ibt_migrate_path:"
			    " retrying after 'state' fixed");
			goto retry;
		}
	}
	return (retval);
}


/*
 * Function:
 *	ibt_set_qp_private
 * Input:
 *	ibt_qp		The ibt_qp_hdl_t of the allocated QP.
 *	clnt_private	The client private data.
 * Output:
 *	none.
 * Returns:
 *	none.
 * Description:
 *	Set the client private data.
 */
void
ibt_set_qp_private(ibt_qp_hdl_t ibt_qp, void *clnt_private)
{
	ibt_qp->ch_clnt_private = clnt_private;
}


/*
 * Function:
 *	ibt_get_qp_private
 * Input:
 *	ibt_qp		The ibt_qp_hdl_t of the allocated QP.
 * Output:
 *	none.
 * Returns:
 *	The client private data.
 * Description:
 *	Get the client private data.
 */
void *
ibt_get_qp_private(ibt_qp_hdl_t ibt_qp)
{
	return (ibt_qp->ch_clnt_private);
}


/*
 * Function:
 *	ibt_qp_to_hca_guid
 * Input:
 *	ibt_qp		The ibt_qp_hdl_t of the allocated QP.
 * Output:
 *	none.
 * Returns:
 *	hca_guid	Returned HCA GUID on which the specified QP is
 *			allocated. Valid if it is non-NULL on return.
 * Description:
 *	A helper function to retrieve HCA GUID for the specified QP.
 */
ib_guid_t
ibt_qp_to_hca_guid(ibt_qp_hdl_t ibt_qp)
{
	IBTF_DPRINTF_L3(ibtf_qp, "ibt_qp_to_hca_guid(%p)", ibt_qp);

	return (IBTL_HCA2HCAGUID(IBTL_CHAN2HCA(ibt_qp)));
}


/*
 * Function:
 *	ibt_recover_ud_qp
 * Input:
 *	ibt_qp		An QP Handle which is in SQError state.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_QP_SRV_TYPE_INVALID
 *	IBT_QP_STATE_INVALID.
 * Description:
 *	Recover an UD QP which has transitioned to SQ Error state. The
 *	ibt_recover_ud_qp() transitions the QP from SQ Error state to
 *	Ready-To-Send QP state.
 *
 *	If a work request posted to a UD QP's send queue completes with an
 *	error (see ibt_wc_status_t), the QP gets transitioned to SQ Error state.
 *	In order to reuse this QP, ibt_recover_ud_qp() can be used to recover
 *	the QP to a usable (Ready-to-Send) state.
 */
ibt_status_t
ibt_recover_ud_qp(ibt_qp_hdl_t ibt_qp)
{
	IBTF_DPRINTF_L3(ibtf_qp, "ibt_recover_ud_qp(%p)", ibt_qp);

	return (ibt_recover_ud_channel(IBTL_QP2CHAN(ibt_qp)));
}


/*
 * Function:
 *	ibt_recycle_ud
 * Input:
 *	ud_chan		The IBT UD QP Handle.
 *	various attributes
 *
 * Output:
 *	none
 * Returns:
 *	IBT_SUCCESS
 *	IBT_CHAN_SRV_TYPE_INVALID
 *	IBT_CHAN_STATE_INVALID
 *
 * Description:
 *	Revert the UD QP back to a usable state.
 */
ibt_status_t
ibt_recycle_ud(ibt_channel_hdl_t ud_chan, uint8_t hca_port_num,
    uint16_t pkey_ix, ib_qkey_t qkey)
{
	ibt_qp_query_attr_t	qp_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_recycle_ud(%p, %d, %x, %x): ",
	    ud_chan, hca_port_num, pkey_ix, qkey);

	if (ud_chan->ch_qp.qp_type != IBT_UD_SRV) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_recycle_ud: "
		    "chan %p is not a UD channel", ud_chan);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	retval = ibt_query_qp(ud_chan, &qp_attr);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_recycle_ud: "
		    "ibt_query_qp failed on chan %p: %d", ud_chan, retval);
		return (retval);
	}
	if (qp_attr.qp_info.qp_state != IBT_STATE_ERROR) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_recycle_ud: "
		    "chan %p is in state %d (not in ERROR state)",
		    ud_chan, qp_attr.qp_info.qp_state);
		ud_chan->ch_current_state = qp_attr.qp_info.qp_state;
		return (IBT_CHAN_STATE_INVALID);
	}

	/* transition the QP from ERROR to RESET */
	qp_attr.qp_info.qp_state = IBT_STATE_RESET;
	qp_attr.qp_info.qp_trans = ud_chan->ch_qp.qp_type;
	retval = ibt_modify_qp(ud_chan, IBT_CEP_SET_STATE, &qp_attr.qp_info,
	    NULL);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_recycle_ud: "
		    "ibt_modify_qp(ERROR=>RESET) failed on chan %p: %d",
		    ud_chan, retval);
		return (retval);
	}
	ud_chan->ch_current_state = IBT_STATE_RESET;

	/* transition the QP back to RTS */
	qp_attr.qp_info.qp_transport.ud.ud_port = hca_port_num;
	qp_attr.qp_info.qp_transport.ud.ud_qkey = qkey;
	qp_attr.qp_info.qp_transport.ud.ud_pkey_ix = pkey_ix;
	retval = ibt_initialize_qp(ud_chan, &qp_attr.qp_info);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_recycle_ud: "
		    "ibt_initialize_qp failed on chan %p: %d", ud_chan, retval);
		/* the man page says the QP should be left in ERROR state */
		(void) ibt_flush_qp(ud_chan);
	}
	return (retval);
}

/*
 * Function:
 *	ibt_pause_sendq
 * Input:
 *	chan		The IBT QP Handle.
 *	modify_flags	IBT_CEP_SET_NOTHING or IBT_CEP_SET_SQD_EVENT
 *
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_CHAN_STATE_INVALID
 *	IBT_INVALID_PARAM
 *
 * Description:
 *	Place the send queue of the specified channel into the send queue
 *	drained (SQD) state.
 *
 */
ibt_status_t
ibt_pause_sendq(ibt_channel_hdl_t chan, ibt_cep_modify_flags_t modify_flags)
{
	ibt_qp_info_t		modify_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_pause_sendq(%p, %x)", chan, modify_flags);

	modify_flags &= IBT_CEP_SET_SQD_EVENT;	/* ignore other bits */
	modify_flags |= IBT_CEP_SET_STATE;

	bzero(&modify_attr, sizeof (ibt_qp_info_t));
	/*
	 * Set the QP state to SQD.
	 */
	modify_attr.qp_state = IBT_STATE_SQD;
	modify_attr.qp_trans = chan->ch_qp.qp_type;

	retval = ibt_modify_qp(chan, modify_flags, &modify_attr, NULL);

	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_pause_sendq: "
		    "failed on chan %p: %d", chan, retval);
	}
	return (retval);
}


/*
 * Function:
 *	ibt_unpause_sendq
 * Input:
 *	chan	The IBT Channel Handle.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_CHAN_STATE_INVALID
 * Description:
 *	Un-pauses the previously paused channel. This call will transition the
 *	QP from SQD to RTS state.
 */
ibt_status_t
ibt_unpause_sendq(ibt_channel_hdl_t chan)
{
	ibt_qp_info_t		modify_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_unpause_sendq(%p)", chan);

	bzero(&modify_attr, sizeof (ibt_qp_info_t));

	/*
	 * Set the QP state to RTS.
	 */
	modify_attr.qp_current_state = IBT_STATE_SQD;
	modify_attr.qp_state = IBT_STATE_RTS;
	modify_attr.qp_trans = chan->ch_qp.qp_type;

	retval = ibt_modify_qp(chan, IBT_CEP_SET_STATE, &modify_attr, NULL);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_unpause_sendq: "
		    "failed on chan %p: %d", chan, retval);
	}
	return (retval);
}


/*
 * Function:
 *	ibt_resize_queues
 * Input:
 *	chan		A previously allocated channel handle.
 *	flags		QP Flags
 *				IBT_SEND_Q
 *				IBT_RECV_Q
 *	request_sz	Requested new sizes.
 * Output:
 *	actual_sz	Returned actual sizes.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Resize the SendQ/RecvQ sizes of a channel. Can only be called on
 *	a previously opened channel.
 */
ibt_status_t
ibt_resize_queues(ibt_channel_hdl_t chan, ibt_qflags_t flags,
    ibt_queue_sizes_t *request_sz, ibt_queue_sizes_t *actual_sz)
{
	ibt_cep_modify_flags_t	modify_flags = IBT_CEP_SET_STATE;
	ibt_qp_info_t		modify_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_resize_queues(%p, 0x%X, %p, %p)",
	    chan, flags, request_sz, actual_sz);

	if ((flags & (IBT_SEND_Q | IBT_RECV_Q)) == 0)  {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_resize_queues: "
		    "Flags <0x%X> not set", flags);
		return (IBT_INVALID_PARAM);
	}

	bzero(&modify_attr, sizeof (ibt_qp_info_t));

	modify_attr.qp_current_state = chan->ch_current_state;
	modify_attr.qp_trans = chan->ch_qp.qp_type;
	modify_attr.qp_state = chan->ch_current_state;

	if (flags & IBT_SEND_Q) {
		modify_attr.qp_sq_sz = request_sz->qs_sq;
		modify_flags |= IBT_CEP_SET_SQ_SIZE;
	}

	if (flags & IBT_RECV_Q) {
		modify_attr.qp_rq_sz = request_sz->qs_rq;
		modify_flags |= IBT_CEP_SET_RQ_SIZE;
	}

	retval = ibt_modify_qp(chan, modify_flags, &modify_attr, actual_sz);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_resize_queues: "
		    "failed on QP %p: %d", chan, retval);
	}

	return (retval);
}


/*
 * Function:
 *	ibt_query_queues
 * Input:
 *	chan		A previously allocated channel handle.
 * Output:
 *	actual_sz	Returned actual sizes.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Query the SendQ/RecvQ sizes of a channel.
 */
ibt_status_t
ibt_query_queues(ibt_channel_hdl_t chan, ibt_queue_sizes_t *actual_sz)
{
	ibt_status_t		retval;
	ibt_qp_query_attr_t	qp_query_attr;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_query_queues(%p)", chan);

	/* Perform Query QP and retrieve QP sizes. */
	retval = ibt_query_qp(chan, &qp_query_attr);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_query_queues: "
		    "ibt_query_qp failed: qp %p: %d", chan, retval);
		return (retval);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(actual_sz->qs_rq,
	    actual_sz->qs_sq))
	actual_sz->qs_sq = qp_query_attr.qp_info.qp_sq_sz;
	actual_sz->qs_rq = qp_query_attr.qp_info.qp_rq_sz;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(actual_sz->qs_rq,
	    actual_sz->qs_sq))
	chan->ch_current_state = qp_query_attr.qp_info.qp_state;

	return (retval);
}


/*
 * Function:
 *	ibt_modify_rdma
 * Input:
 *	rc_chan		A previously allocated channel handle.
 *
 *	modify_flags	Bitwise "or" of any of the following:
 *			IBT_CEP_SET_RDMA_R	Enable/Disable RDMA RD
 *			IBT_CEP_SET_RDMA_W	Enable/Disable RDMA WR
 *			IBT_CEP_SET_ATOMIC	Enable/Disable Atomics
 *
 *	flags		Channel End Point (CEP) Disable Flags (0 => enable).
 *			IBT_CEP_NO_RDMA_RD	Disable incoming RDMA RD's
 *			IBT_CEP_NO_RDMA_WR	Disable incoming RDMA WR's
 *			IBT_CEP_NO_ATOMIC	Disable incoming Atomics.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_QP_SRV_TYPE_INVALID
 *	IBT_CHAN_HDL_INVALID
 *	IBT_CHAN_ATOMICS_NOT_SUPPORTED
 *	IBT_CHAN_STATE_INVALID
 * Description:
 *	Enable/disable RDMA operations. To enable an operation clear the
 *	"disable" flag. Can call this function when the channel is in
 *	INIT, RTS or SQD states. If called in any other state
 *	IBT_CHAN_STATE_INVALID is returned. When the operation completes the
 *	channel state is left unchanged.
 */
ibt_status_t
ibt_modify_rdma(ibt_channel_hdl_t rc_chan,
    ibt_cep_modify_flags_t modify_flags, ibt_cep_flags_t flags)
{
	ibt_status_t		retval;
	ibt_qp_info_t		modify_attr;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_modify_rdma(%p, 0x%x, 0x%x)",
	    rc_chan, modify_flags, flags);

	if (rc_chan->ch_qp.qp_type != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_modify_rdma: "
		    "Invalid Channel type: 0x%X, Applicable only to RC Channel",
		    rc_chan->ch_qp.qp_type);
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	bzero(&modify_attr, sizeof (ibt_qp_info_t));

	/*
	 * Can only call this function when the channel in INIT, RTS or SQD
	 * states.
	 */
	if ((rc_chan->ch_current_state != IBT_STATE_INIT) &&
	    (rc_chan->ch_current_state != IBT_STATE_RTS) &&
	    (rc_chan->ch_current_state != IBT_STATE_SQD)) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_modify_rdma: Invalid Channel "
		    "state: 0x%X", rc_chan->ch_current_state);
		return (IBT_CHAN_STATE_INVALID);
	}

	modify_attr.qp_state = modify_attr.qp_current_state =
	    rc_chan->ch_current_state;
	modify_attr.qp_trans = rc_chan->ch_qp.qp_type;
	modify_attr.qp_flags = flags;

	modify_flags &= (IBT_CEP_SET_RDMA_R | IBT_CEP_SET_RDMA_W |
	    IBT_CEP_SET_ATOMIC);
	modify_flags |= IBT_CEP_SET_STATE;

	retval = ibt_modify_qp(rc_chan, modify_flags, &modify_attr, NULL);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_modify_rdma: "
		    "failed on chan %p: %d", rc_chan, retval);
	}
	return (retval);
}


/*
 * Function:
 *	ibt_set_rdma_resource
 * Input:
 *	chan		A previously allocated RC channel handle.
 *	modify_flags	Bitwise "or" of any of the following:
 *			IBT_CEP_SET_RDMARA_OUT	Initiator depth (rdma_ra_out)
 *			IBT_CEP_SET_RDMARA_IN	Responder Resources
 *						(rdma_ra_in)
 *	rdma_ra_out	Outgoing RDMA Reads/Atomics
 *	rdma_ra_in	Incoming RDMA Reads/Atomics
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Change the number of resources to be used for incoming and outgoing
 *	RDMA reads & Atomics. Can only be called on a previously opened
 *	RC channel.  Can only be called on a paused channel, and this will
 *	un-pause that channel.
 */
ibt_status_t
ibt_set_rdma_resource(ibt_channel_hdl_t chan,
    ibt_cep_modify_flags_t modify_flags, uint8_t rdma_ra_out,
    uint8_t resp_rdma_ra_out)
{
	ibt_qp_info_t		modify_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_set_rdma_resource(%p, 0x%x, %d, %d)",
	    chan, modify_flags, rdma_ra_out, resp_rdma_ra_out);

	if (chan->ch_qp.qp_type != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_set_rdma_resource: "
		    "Invalid Channel type: 0x%X, Applicable only to RC Channel",
		    chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	bzero(&modify_attr, sizeof (ibt_qp_info_t));

	modify_attr.qp_trans = chan->ch_qp.qp_type;
	modify_attr.qp_state = IBT_STATE_SQD;

	modify_attr.qp_transport.rc.rc_rdma_ra_out = rdma_ra_out;
	modify_attr.qp_transport.rc.rc_rdma_ra_in = resp_rdma_ra_out;
	modify_flags &= (IBT_CEP_SET_RDMARA_OUT | IBT_CEP_SET_RDMARA_IN);
	modify_flags |= IBT_CEP_SET_STATE;

	retval = ibt_modify_qp(chan, modify_flags, &modify_attr, NULL);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_set_rdma_resource: "
		    "failed on chan %p: %d", chan, retval);
	}
	return (retval);
}


/*
 * Function:
 *	ibt_change_port
 * Input:
 *	rc_chan		A previously allocated RC channel handle.
 *	port_num	New HCA port.
 * Output:
 *	none.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Change the primary physical port of a channel. (This is done only if
 *	HCA supports this capability).
 */
ibt_status_t
ibt_change_port(ibt_channel_hdl_t chan, uint8_t port_num)
{
	ibt_cep_modify_flags_t	modify_flags;
	ibt_qp_info_t		modify_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_qp, "ibt_change_port(%p, %d)", chan, port_num);

	if (chan->ch_qp.qp_type != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_change_port: "
		    "Invalid Channel type: 0x%X, Applicable only to RC Channel",
		    chan->ch_qp.qp_type);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}
	bzero(&modify_attr, sizeof (ibt_qp_info_t));

	modify_attr.qp_state = IBT_STATE_SQD;
	modify_attr.qp_trans = chan->ch_qp.qp_type;
	modify_attr.qp_transport.rc.rc_path.cep_hca_port_num = port_num;

	modify_flags = IBT_CEP_SET_STATE | IBT_CEP_SET_PORT;

	retval = ibt_modify_qp(chan, modify_flags, &modify_attr, NULL);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_qp, "ibt_change_port: "
		    "failed on chan %p: %d", chan, retval);
	}
	return (retval);
}


void
ibtl_init_cep_states(void)
{
	int	index;
	int	ibt_nstate_inits;

	IBTF_DPRINTF_L3(ibtf_qp, "ibtl_init_cep_states()");

	ibt_nstate_inits = sizeof (ibt_cep_next_state_inits) /
	    sizeof (ibt_cep_next_state_inits[0]);

	/*
	 * Initialize CEP next state table, using an indirect lookup table so
	 * that this code isn't dependent on the ibt_cep_state_t enum values.
	 */
	for (index = 0; index < ibt_nstate_inits; index++) {
		ibt_cep_state_t	state;

		state = ibt_cep_next_state_inits[index].current_state;

		ibt_cep_next_state[state].next_state =
		    ibt_cep_next_state_inits[index].next_state;

		ibt_cep_next_state[state].modify_flags =
		    ibt_cep_next_state_inits[index].modify_flags;
	}
}

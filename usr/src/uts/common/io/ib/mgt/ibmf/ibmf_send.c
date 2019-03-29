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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the MAD send logic in IBMF.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>

#define	IBMF_SEND_WR_ID_TO_ADDR(id, ptr)		\
	(ptr) = (void *)(uintptr_t)(id)

extern int ibmf_trace_level;

static void ibmf_i_do_send_cb(void *taskq_arg);
static void ibmf_i_do_send_compl(ibmf_handle_t ibmf_handle,
    ibmf_msg_impl_t *msgimplp, ibmf_send_wqe_t *send_wqep);

/*
 * ibmf_i_issue_pkt():
 *	Post an IB packet on the specified QP's send queue
 */
int
ibmf_i_issue_pkt(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp,
    ibmf_qp_handle_t ibmf_qp_handle, ibmf_send_wqe_t *send_wqep)
{
	int			ret;
	ibt_status_t		status;
	ibt_wr_ds_t		sgl[1];
	ibt_qp_hdl_t		ibt_qp_handle;

	_NOTE(ASSUMING_PROTECTED(*send_wqep))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqep))

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_issue_pkt_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_issue_pkt() enter, clientp = %p, msg = %p, "
	    "qp_hdl = %p,  swqep = %p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, msg, msgimplp, tnf_opaque, ibmf_qp_handle,
	    ibmf_qp_handle, tnf_opaque, send_wqep, send_wqep);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));
	ASSERT(MUTEX_NOT_HELD(&clientp->ic_mutex));

	/*
	 * if the qp handle provided in ibmf_send_pkt()
	 * is not the default qp handle for this client,
	 * then the wqe must be sent on this qp,
	 * else use the default qp handle set up during ibmf_register()
	 */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		ibt_qp_handle = clientp->ic_qp->iq_qp_handle;
	} else {
		ibt_qp_handle =
		    ((ibmf_alt_qp_t *)ibmf_qp_handle)->isq_qp_handle;
	}

	/* initialize the send WQE */
	ibmf_i_init_send_wqe(clientp, msgimplp, sgl, send_wqep,
	    msgimplp->im_ud_dest, ibt_qp_handle, ibmf_qp_handle);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*send_wqep))

	/*
	 * Issue the wqe to the transport.
	 * NOTE: ibt_post_send() will not block, so, it is ok
	 * to hold the msgimpl mutex across this call.
	 */
	status = ibt_post_send(send_wqep->send_qp_handle, &send_wqep->send_wr,
	    1, NULL);
	if (status != IBT_SUCCESS) {
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, send_pkt_failed, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_issue_pkt_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_issue_pkt(): %s, status = %d\n",
		    tnf_string, msg, "post send failure",
		    tnf_uint, ibt_status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_issue_pkt_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_issue_pkt(() exit\n");
		return (IBMF_TRANSPORT_FAILURE);
	}

	ret = IBMF_SUCCESS;

	/* bump the number of active sends */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&clientp->ic_mutex);
		clientp->ic_sends_active++;
		mutex_exit(&clientp->ic_mutex);
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, sends_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
	} else {
		ibmf_alt_qp_t *qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		mutex_enter(&qpp->isq_mutex);
		qpp->isq_sends_active++;
		mutex_exit(&qpp->isq_mutex);
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, sends_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_issue_pkt_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_issue_pkt() exit\n");
	return (ret);
}

/*
 * ibmf_i_send_pkt()
 *	Send an IB packet after allocating send resources
 */
int
ibmf_i_send_pkt(ibmf_client_t *clientp, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_msg_impl_t *msgimplp, int block)
{
	ibmf_send_wqe_t	*send_wqep;
	int		status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_send_pkt_start,
	    IBMF_TNF_TRACE, "",
	    "ibmf_i_send_pkt(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, block = %d\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, ibmf_qp_handle, tnf_opaque, msg, msgimplp,
	    tnf_uint, block, block);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqep))

	/*
	 * Reset send_done to indicate we have not received the completion
	 * for this send yet.
	 */
	msgimplp->im_trans_state_flags &= ~IBMF_TRANS_STATE_FLAG_SEND_DONE;

	/*
	 * Allocate resources needed to send a UD packet including the
	 * send WQE context
	 */
	status = ibmf_i_alloc_send_resources(clientp->ic_myci,
	    msgimplp, block, &send_wqep);
	if (status != IBMF_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_send_pkt_err,
		    IBMF_TNF_ERROR, "", "ibmf_i_send_pkt(): %s, status = %d\n",
		    tnf_string, msg, "unable to allocate send resources",
		    tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_pkt_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_send_pkt() exit\n");
		return (status);
	}

	/* Set the segment number in the send WQE context */
	if (msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP)
		send_wqep->send_rmpp_segment = msgimplp->im_rmpp_ctx.rmpp_ns;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*send_wqep))

	/*
	 * Increment the count of pending send completions.
	 * Only when this count is zero should the client be notified
	 * of completion of the transaction.
	 */
	msgimplp->im_pending_send_compls += 1;

	/* Send the packet */
	status = ibmf_i_issue_pkt(clientp, msgimplp, ibmf_qp_handle, send_wqep);
	if (status != IBMF_SUCCESS) {
		ibmf_i_free_send_resources(clientp->ic_myci, msgimplp,
		    send_wqep);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_i_send_pkt_err,
		    IBMF_TNF_ERROR, "", "ibmf_i_send_pkt(): %s, status = %d\n",
		    tnf_string, msg, "unable to issue packet",
		    tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_pkt_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_send_pkt() exit\n");
		return (status);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_pkt_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_pkt() exit, status = %d\n",
	    tnf_uint, status, status);

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_send_single_pkt():
 *	Send a single IB packet.  Only used to send non-RMPP packets.
 */
int
ibmf_i_send_single_pkt(ibmf_client_t *clientp, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_msg_impl_t *msgimplp, int block)
{
	int	status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_send_single_pkt_start,
	    IBMF_TNF_TRACE, "",
	    "ibmf_i_send_single_pkt(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, block = %d\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, ibmf_qp_handle, tnf_opaque, msg, msgimplp,
	    tnf_uint, block, block);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	status = ibmf_i_send_pkt(clientp, ibmf_qp_handle, msgimplp, block);
	if (status != IBMF_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_send_single_pkt_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_send_single_pkt(): %s, msgp = 0x%p\n",
		    tnf_string, msg, "unable to send packet",
		    tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_send_single_pkt_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_send_single_pkt() exit\n");
		return (status);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_single_pkt_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_single_pkt() exit\n");
	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_handle_send_completion():
 *	Process the WQE from the SQ identified in the work completion entry.
 */
/* ARGSUSED */
void
ibmf_i_handle_send_completion(ibmf_ci_t *cip, ibt_wc_t *wcp)
{
	ibmf_client_t		*clientp, *cclientp;
	ibmf_send_wqe_t		*send_wqep;
	ibmf_qp_handle_t	ibmf_qp_handle;
	ibmf_alt_qp_t		*qpp;
	int			ret;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_handle_send_completion_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_handle_send_completion() enter, cip = %p, wcp = %p\n",
	    tnf_opaque, cip, cip, tnf_opaque, wcp, wcp);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqep))

	ASSERT(wcp->wc_id != NULL);

	ASSERT(IBMF_IS_SEND_WR_ID(wcp->wc_id));

	/* get the IBMF send WQE context */
	IBMF_SEND_WR_ID_TO_ADDR(wcp->wc_id, send_wqep);

	ASSERT(send_wqep != NULL);

	/* get the client context */
	cclientp =  clientp = send_wqep->send_client;

	/* Check if this is a completion for a BUSY MAD sent by IBMF */
	if (clientp == NULL) {
		ibmf_msg_impl_t		*msgimplp;

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_handle_send_completion, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_send_completion(): NULL client\n");

		msgimplp = send_wqep->send_msg;

		/*
		 * Deregister registered memory and free it, and
		 * free up the send WQE context
		 */
		(void) ibt_deregister_mr(cip->ci_ci_handle,
		    send_wqep->send_mem_hdl);
		kmem_free(send_wqep->send_mem, IBMF_MEM_PER_WQE);
		kmem_free(send_wqep, sizeof (ibmf_send_wqe_t));

		/* Free up the message context */
		ibmf_i_put_ud_dest(cip, msgimplp->im_ibmf_ud_dest);
		ibmf_i_clean_ud_dest_list(cip, B_FALSE);
		kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_send_completion_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_send_completion() exit\n");
		return;
	}

	/* get the QP handle */
	ibmf_qp_handle = send_wqep->send_ibmf_qp_handle;
	qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;

	ASSERT(clientp != NULL);

	/* decrement the number of active sends */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&clientp->ic_mutex);
		clientp->ic_sends_active--;
		mutex_exit(&clientp->ic_mutex);
	} else {
		mutex_enter(&qpp->isq_mutex);
		qpp->isq_sends_active--;
		mutex_exit(&qpp->isq_mutex);
	}

	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_SUB32_KSTATS(clientp, sends_active, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	send_wqep->send_status = ibmf_i_ibt_wc_to_ibmf_status(wcp->wc_status);

	/*
	 * issue the callback using taskq. If no taskq or if the
	 * dispatch fails, we do the send processing in the callback context
	 * which is the interrupt context
	 */
	if (cclientp->ic_send_taskq == NULL) {
		/* Do the processing in callback context */
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, send_cb_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
		ibmf_i_do_send_cb((void *)send_wqep);
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_SUB32_KSTATS(clientp, send_cb_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_send_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_handle_send_completion(): %s\n",
		    tnf_string, msg, "ci_send_taskq == NULL");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_send_completion_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_send_completion() exit\n");
		return;
	}

	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_ADD32_KSTATS(clientp, send_cb_active, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	/* Use taskq for processing if the IBMF_REG_FLAG_NO_OFFLOAD isn't set */
	if ((clientp->ic_reg_flags & IBMF_REG_FLAG_NO_OFFLOAD) == 0) {
		ret = taskq_dispatch(cclientp->ic_send_taskq, ibmf_i_do_send_cb,
		    send_wqep, TQ_NOSLEEP);
		if (ret == TASKQID_INVALID) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_handle_send_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_handle_send_completion(): %s\n",
			    tnf_string, msg, "send: dispatch failed");
			ibmf_i_do_send_cb((void *)send_wqep);
		}
	} else {
		ibmf_i_do_send_cb((void *)send_wqep);
	}

	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_SUB32_KSTATS(clientp, send_cb_active, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*send_wqep))

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_handle_send_completion_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_handle_send_completion() exit\n");
}

/*
 * ibmf_i_do_send_cb():
 *	Do the send completion processing
 */
static void
ibmf_i_do_send_cb(void *taskq_arg)
{
	ibmf_ci_t		*cip;
	ibmf_msg_impl_t		*msgimplp;
	ibmf_client_t		*clientp;
	ibmf_send_wqe_t		*send_wqep;
	boolean_t		found;
	int			msg_trans_state_flags, msg_flags;
	uint_t			ref_cnt;
	ibmf_qp_handle_t	ibmf_qp_handle;
	struct kmem_cache	*kmem_cachep;
	timeout_id_t		msg_rp_unset_id, msg_tr_unset_id;
	timeout_id_t		msg_rp_set_id, msg_tr_set_id;
	ibmf_alt_qp_t		*altqp;
	boolean_t		inc_refcnt;

	send_wqep = taskq_arg;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_do_send_cb_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_do_send_cb() enter, send_wqep = %p\n",
	    tnf_opaque, send_wqep, send_wqep);

	clientp = send_wqep->send_client;
	cip = clientp->ic_myci;
	msgimplp = send_wqep->send_msg;

	/* get the QP handle */
	ibmf_qp_handle = send_wqep->send_ibmf_qp_handle;

	/* Get the WQE kmem cache pointer based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT)
		kmem_cachep = cip->ci_send_wqes_cache;
	else {
		altqp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		kmem_cachep = altqp->isq_send_wqes_cache;
	}

	/* Look for a message in the client's message list */
	inc_refcnt = B_TRUE;
	found = ibmf_i_find_msg_client(clientp, msgimplp, inc_refcnt);

	/*
	 * If the message context was not found, then it's likely
	 * been freed up. So, do nothing in this timeout handler
	 */
	if (found == B_FALSE) {
		kmem_cache_free(kmem_cachep, send_wqep);
		mutex_enter(&cip->ci_mutex);
		IBMF_SUB32_PORT_KSTATS(cip, send_wqes_alloced, 1);
		mutex_exit(&cip->ci_mutex);
		if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
			mutex_enter(&cip->ci_mutex);
			cip->ci_wqes_alloced--;
			if (cip->ci_wqes_alloced == 0)
				cv_signal(&cip->ci_wqes_cv);
			mutex_exit(&cip->ci_mutex);
		} else {
			mutex_enter(&altqp->isq_mutex);
			altqp->isq_wqes_alloced--;
			if (altqp->isq_wqes_alloced == 0)
				cv_signal(&altqp->isq_wqes_cv);
			mutex_exit(&altqp->isq_mutex);
		}
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_do_send_cb, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_send_cb(): %s\n", tnf_string, msg,
		    "Message not found, return without processing send cb");
		return;
	}

	/* Grab the message context lock */
	mutex_enter(&msgimplp->im_mutex);

	/*
	 * Decrement the count of pending send completions for
	 * this transaction
	 */
	msgimplp->im_pending_send_compls -= 1;

	/*
	 * If the pending send completions is not zero, then we must
	 * not attempt to notify the client of a transaction completion
	 * in this instance of the send completion handler. Notification
	 * of transaction completion should be provided only by the
	 * last send completion so that all send completions are accounted
	 * for before the client is notified and subsequently attempts to
	 * reuse the message for an other transaction.
	 * If this is not done, the message may be reused while the
	 * send WR from the old transaction is still active in the QP's WQ.
	 * This could result in an attempt to modify the address handle with
	 * information for the new transaction which could be potentially
	 * incompatible, such as an incorrect port number. Such an
	 * incompatible modification of the address handle of the old
	 * transaction could result in a QP error.
	 */
	if (msgimplp->im_pending_send_compls != 0) {
		IBMF_MSG_DECR_REFCNT(msgimplp);
		mutex_exit(&msgimplp->im_mutex);
		kmem_cache_free(kmem_cachep, send_wqep);
		mutex_enter(&cip->ci_mutex);
		IBMF_SUB32_PORT_KSTATS(cip, send_wqes_alloced, 1);
		mutex_exit(&cip->ci_mutex);
		if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
			mutex_enter(&cip->ci_mutex);
			cip->ci_wqes_alloced--;
			if (cip->ci_wqes_alloced == 0)
				cv_signal(&cip->ci_wqes_cv);
			mutex_exit(&cip->ci_mutex);
		} else {
			mutex_enter(&altqp->isq_mutex);
			altqp->isq_wqes_alloced--;
			if (altqp->isq_wqes_alloced == 0)
				cv_signal(&altqp->isq_wqes_cv);
			mutex_exit(&altqp->isq_mutex);
		}
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_do_send_cb, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_send_cb(): %s\n", tnf_string, msg,
		    "Message found with pending send completions, "
		    "return without processing send cb");
		return;
	}

	/*
	 * If the message has been marked unitialized or done
	 * release the message mutex and return
	 */
	if ((msgimplp->im_trans_state_flags & IBMF_TRANS_STATE_FLAG_UNINIT) ||
	    (msgimplp->im_trans_state_flags & IBMF_TRANS_STATE_FLAG_DONE)) {
		IBMF_MSG_DECR_REFCNT(msgimplp);
		msg_trans_state_flags = msgimplp->im_trans_state_flags;
		msg_flags = msgimplp->im_flags;
		ref_cnt = msgimplp->im_ref_count;
		mutex_exit(&msgimplp->im_mutex);
		/*
		 * This thread may notify the client only if the
		 * transaction is done, the message has been removed
		 * from the client's message list, and the message
		 * reference count is 0.
		 * If the transaction is done, and the message reference
		 * count = 0, there is still a possibility that a
		 * packet could arrive for the message and its reference
		 * count increased if the message is still on the list.
		 * If the message is still on the list, it will be
		 * removed by a call to ibmf_i_client_rem_msg() at
		 * the completion point of the transaction.
		 * So, the reference count should be checked after the
		 * message has been removed.
		 */
		if ((msg_trans_state_flags & IBMF_TRANS_STATE_FLAG_DONE) &&
		    !(msg_flags & IBMF_MSG_FLAGS_ON_LIST) &&
		    (ref_cnt == 0)) {

			ibmf_i_notify_sequence(clientp, msgimplp, msg_flags);

		}
		kmem_cache_free(kmem_cachep, send_wqep);
		mutex_enter(&cip->ci_mutex);
		IBMF_SUB32_PORT_KSTATS(cip, send_wqes_alloced, 1);
		mutex_exit(&cip->ci_mutex);
		if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
			mutex_enter(&cip->ci_mutex);
			cip->ci_wqes_alloced--;
			if (cip->ci_wqes_alloced == 0)
				cv_signal(&cip->ci_wqes_cv);
			mutex_exit(&cip->ci_mutex);
		} else {
			mutex_enter(&altqp->isq_mutex);
			altqp->isq_wqes_alloced--;
			if (altqp->isq_wqes_alloced == 0)
				cv_signal(&altqp->isq_wqes_cv);
			mutex_exit(&altqp->isq_mutex);
		}
		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_do_send_cb, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_send_cb(): %s, msg = %p\n", tnf_string, msg,
		    "Message marked for removal, return without processing "
		    "send cb", tnf_opaque, msgimplp, msgimplp);
		return;
	}

	/* Perform send completion processing of the message context */
	ibmf_i_do_send_compl((ibmf_handle_t)clientp, msgimplp, send_wqep);

	msg_rp_unset_id = msg_tr_unset_id = msg_rp_set_id = msg_tr_set_id = 0;

	/* Save the message flags before releasing the mutex */
	msg_trans_state_flags = msgimplp->im_trans_state_flags;
	msg_flags = msgimplp->im_flags;
	msg_rp_unset_id = msgimplp->im_rp_unset_timeout_id;
	msg_tr_unset_id = msgimplp->im_tr_unset_timeout_id;
	msgimplp->im_rp_unset_timeout_id = 0;
	msgimplp->im_tr_unset_timeout_id = 0;

	/*
	 * Decrement the message reference count
	 * This count was inceremented when the message was found on the
	 * client's message list
	 */
	IBMF_MSG_DECR_REFCNT(msgimplp);

	if (msg_trans_state_flags & IBMF_TRANS_STATE_FLAG_DONE) {
		if (msgimplp->im_rp_timeout_id != 0) {
			msg_rp_set_id = msgimplp->im_rp_timeout_id;
			msgimplp->im_rp_timeout_id = 0;
		}
		if (msgimplp->im_tr_timeout_id != 0) {
			msg_tr_set_id = msgimplp->im_tr_timeout_id;
			msgimplp->im_tr_timeout_id = 0;
		}
	}

	mutex_exit(&msgimplp->im_mutex);

	if (msg_rp_unset_id != 0) {
		(void) untimeout(msg_rp_unset_id);
	}

	if (msg_tr_unset_id != 0) {
		(void) untimeout(msg_tr_unset_id);
	}

	if (msg_rp_set_id != 0) {
		(void) untimeout(msg_rp_set_id);
	}

	if (msg_tr_set_id != 0) {
		(void) untimeout(msg_tr_set_id);
	}

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_i_do_send_cb, IBMF_TNF_TRACE, "",
	    "ibmf_i_do_send_cb(): %s, msg = %p\n",
	    tnf_string, msg, "Send callback done.  Dec ref count",
	    tnf_opaque, msgimplp, msgimplp);

	/*
	 * If the transaction is done, signal the block thread if the
	 * transaction is blocking, or call the client's transaction done
	 * notification callback
	 */
	if (msg_trans_state_flags & IBMF_TRANS_STATE_FLAG_DONE) {

		/* Remove the message from the client's message list */
		ibmf_i_client_rem_msg(clientp, msgimplp, &ref_cnt);

		/*
		 * Notify the client if the message reference count is zero.
		 * At this point, we know that the transaction is done and
		 * the message has been removed from the client's message list.
		 * So, we only need to make sure the reference count is zero
		 * before notifying the client.
		 */
		if (ref_cnt == 0) {

			ibmf_i_notify_sequence(clientp, msgimplp, msg_flags);

		}
	}

	kmem_cache_free(kmem_cachep, send_wqep);
	mutex_enter(&cip->ci_mutex);
	IBMF_SUB32_PORT_KSTATS(cip, send_wqes_alloced, 1);
	mutex_exit(&cip->ci_mutex);
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&cip->ci_mutex);
		cip->ci_wqes_alloced--;
		if (cip->ci_wqes_alloced == 0)
			cv_signal(&cip->ci_wqes_cv);
		mutex_exit(&cip->ci_mutex);
	} else {
		mutex_enter(&altqp->isq_mutex);
		altqp->isq_wqes_alloced--;
		if (altqp->isq_wqes_alloced == 0)
			cv_signal(&altqp->isq_wqes_cv);
		mutex_exit(&altqp->isq_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_do_send_cb_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_do_send_cb() exit\n");
}

/*
 * ibmf_i_do_send_compl():
 *	Determine if the transaction is complete
 */
/* ARGSUSED */
static void
ibmf_i_do_send_compl(ibmf_handle_t ibmf_handle, ibmf_msg_impl_t *msgimplp,
    ibmf_send_wqe_t *send_wqep)
{
	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_do_send_compl_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_do_send_compl(): ibmf_hdl = 0x%p "
	    "msgp = %p, send_wqep = 0x%p, msg_flags = 0x%x\n",
	    tnf_opaque, ibmf_hdl, ibmf_handle, tnf_opaque, msgimplp, msgimplp,
	    tnf_opaque, send_wqep, send_wqep,
	    tnf_opaque, msg_flags, msgimplp->im_flags);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	/*
	 * For RMPP transactions, we only care about the final packet of the
	 * transaction.  For others, the code does not need to wait for the send
	 * completion (although bad things can happen if it never occurs).
	 * The final packets of a transaction are sent when the state is either
	 * ABORT or RECEVR_TERMINATE.
	 * Don't mark the transaction as send_done if there are still more
	 * packets to be sent, including doing the second part of a double-sided
	 * transaction.
	 */
	if ((msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP) ||
	    (msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP)) {

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_do_send_compl, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_send_compl(): %s msgp = %p, rmpp_state = 0x%x\n",
		    tnf_string, msg, "Received send callback for RMPP trans",
		    tnf_opaque, msg, msgimplp,
		    tnf_opaque, rmpp_state, msgimplp->im_rmpp_ctx.rmpp_state);

		/*
		 * For ABORT state, we should not return control to
		 * the client from the send completion handler.
		 * Control should be returned in the error timeout handler.
		 *
		 * The exception is when the IBMF_TRANS_STATE_FLAG_RECV_DONE
		 * flag has already been set. This flag is set when
		 * ibmf_i_terminate_transaction is called from one of the
		 * three timeout handlers. In this case return control from
		 * here.
		 */
		if (msgimplp->im_rmpp_ctx.rmpp_state == IBMF_RMPP_STATE_ABORT) {
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
			if (msgimplp->im_trans_state_flags &
			    IBMF_TRANS_STATE_FLAG_RECV_DONE) {
				msgimplp->im_trans_state_flags |=
				    IBMF_TRANS_STATE_FLAG_DONE;
			}
		}

		if ((msgimplp->im_rmpp_ctx.rmpp_state ==
		    IBMF_RMPP_STATE_RECEVR_TERMINATE) ||
		    (msgimplp->im_rmpp_ctx.rmpp_state ==
		    IBMF_RMPP_STATE_DONE)) {
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
			if (msgimplp->im_trans_state_flags  &
			    IBMF_TRANS_STATE_FLAG_RECV_DONE) {
				msgimplp->im_trans_state_flags |=
				    IBMF_TRANS_STATE_FLAG_DONE;
			}
		}

		/*
		 * If the transaction is a send-only RMPP, then
		 * set the SEND_DONE flag on every send completion
		 * as long as there are no outstanding ones.
		 * This is needed so that the transaction can return
		 * in the receive path, where ibmf_i_terminate_transaction
		 * is called from ibmf_i_rmpp_sender_active_flow,
		 * after checking if the SEND_DONE flag is set.
		 * When a new MAD is sent as part of the RMPP transaction,
		 * the SEND_DONE flag will get reset.
		 * The RECV_DONE indicates that the last ACK was received.
		 */
		if ((msgimplp->im_flags & IBMF_MSG_FLAGS_SEQUENCED) == 0) {
			if (msgimplp->im_pending_send_compls == 0) {
				msgimplp->im_trans_state_flags |=
				    IBMF_TRANS_STATE_FLAG_SEND_DONE;
				if (msgimplp->im_trans_state_flags  &
				    IBMF_TRANS_STATE_FLAG_RECV_DONE) {
					msgimplp->im_trans_state_flags |=
					    IBMF_TRANS_STATE_FLAG_DONE;
				}
			}
		}

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_do_send_compl_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_send_compl() exit\n");
		return;
	}

	/*
	 * Only non-RMPP send completion gets here.
	 * If the send is a single-packet send that does not use RMPP, and if
	 * the transaction is not a sequenced transaction, call the transaction
	 * callback handler after flagging the transaction as done.  If the
	 * message is sequenced, start a timer to bound the wait for the first
	 * data packet of the response.
	 */
	if (msgimplp->im_flags & IBMF_MSG_FLAGS_SEQUENCED) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_do_send_compl, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_send_compl(): %s msgp = %p\n", tnf_string, msg,
		    "Sequenced transaction, setting response timer",
		    tnf_opaque, msg, msgimplp);

		/*
		 * Check if the send completion already occured,
		 * which could imply that this is a send completion
		 * for some previous transaction that has come in very late.
		 * In this case exit here.
		 */
		if (msgimplp->im_trans_state_flags  &
		    IBMF_TRANS_STATE_FLAG_SEND_DONE) {
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_do_send_compl_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_do_send_compl() exit, "
			    "Duplicate SEND completion\n");
			return;
		}

		/* mark as send_compl happened */
		msgimplp->im_trans_state_flags |=
		    IBMF_TRANS_STATE_FLAG_SEND_DONE;

		if (msgimplp->im_trans_state_flags  &
		    IBMF_TRANS_STATE_FLAG_RECV_DONE) {
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_DONE;
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_do_send_compl_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_do_send_compl() exit, RECV_DONE\n");
			return;
		}

		/*
		 * check if response was received before send
		 * completion
		 */
		if (((msgimplp->im_trans_state_flags &
		    IBMF_TRANS_STATE_FLAG_DONE) == 0) &&
		    ((msgimplp->im_trans_state_flags &
		    IBMF_TRANS_STATE_FLAG_RECV_ACTIVE) == 0)) {
			/* set timer for first packet of response */
			ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp,
			    IBMF_RESP_TIMER);
		}
	} else {
		msgimplp->im_msg_status = IBMF_SUCCESS;
		msgimplp->im_trans_state_flags |=
		    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		msgimplp->im_trans_state_flags |= IBMF_TRANS_STATE_FLAG_DONE;
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_do_send_compl_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_do_send_compl() exit\n");
}

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
 * This file implements the IBMF message related functions.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>

extern int ibmf_trace_level;

/*
 * ibmf_i_client_add_msg():
 *	Add the message to the client message list
 */
void
ibmf_i_client_add_msg(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp)
{
	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_client_add_msg_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_client_add_msg(): clientp = 0x%p, msgp = 0x%p\n",
	    tnf_opaque, clientp, clientp, tnf_opaque, msg, msgimplp);

	ASSERT(MUTEX_NOT_HELD(&msgimplp->im_mutex));

	mutex_enter(&clientp->ic_msg_mutex);

	/*
	 * If this is a termination message, add the message to
	 * the termination message list else add the message
	 * to the regular message list.
	 */
	mutex_enter(&msgimplp->im_mutex);
	if (msgimplp->im_flags & IBMF_MSG_FLAGS_TERMINATION) {

		mutex_exit(&msgimplp->im_mutex);
		/* Put the message on the list */
		if (clientp->ic_term_msg_list == NULL) {
			clientp->ic_term_msg_list = clientp->ic_term_msg_last =
			    msgimplp;
		} else {
			msgimplp->im_msg_prev = clientp->ic_term_msg_last;
			clientp->ic_term_msg_last->im_msg_next = msgimplp;
			clientp->ic_term_msg_last = msgimplp;
		}
	} else {

		mutex_exit(&msgimplp->im_mutex);
		/*
		 * Increment the counter and kstats for active messages
		 */
		clientp->ic_msgs_active++;
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, msgs_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		/* Put the message on the list */
		if (clientp->ic_msg_list == NULL) {
			clientp->ic_msg_list = clientp->ic_msg_last = msgimplp;
		} else {
			msgimplp->im_msg_prev = clientp->ic_msg_last;
			clientp->ic_msg_last->im_msg_next = msgimplp;
			clientp->ic_msg_last = msgimplp;
		}
	}

	msgimplp->im_msg_next = NULL;

	/* Set the message flags to indicate the message is on the list */
	mutex_enter(&msgimplp->im_mutex);
	msgimplp->im_flags |= IBMF_MSG_FLAGS_ON_LIST;
	mutex_exit(&msgimplp->im_mutex);

	mutex_exit(&clientp->ic_msg_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_client_add_msg_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_client_add_msg() exit\n");
}

/*
 * ibmf_i_client_rem_msg():
 *	Remove the message from the client's message list
 *	The refcnt will hold the message reference count at the time
 *	the message was removed from the message list. Any packets
 *	arriving after this point for the message will be dropped.
 *	The message reference count is used by the threads processing
 *	the message to decide which one should notify the client
 *	(the one that decrements the reference count to zero).
 */
void
ibmf_i_client_rem_msg(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp,
    uint_t *refcnt)
{
	ibmf_msg_impl_t *tmpmsg, *prevmsg = NULL;

	ASSERT(MUTEX_NOT_HELD(&msgimplp->im_mutex));

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_client_rem_msg_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_client_rem_msg(): clientp = 0x%p, msgp = 0x%p\n",
	    tnf_opaque, clientp, clientp, tnf_opaque, msg, msgimplp);

	mutex_enter(&clientp->ic_msg_mutex);

	/*
	 * If this is a termination message, remove the message from
	 * the termination message list else remove the message
	 * from the regular message list.
	 */
	mutex_enter(&msgimplp->im_mutex);
	if (msgimplp->im_flags & IBMF_MSG_FLAGS_TERMINATION) {

		mutex_exit(&msgimplp->im_mutex);
		tmpmsg = clientp->ic_term_msg_list;

		while (tmpmsg != NULL) {
			if (tmpmsg == msgimplp)
				break;
			prevmsg = tmpmsg;
			tmpmsg = tmpmsg->im_msg_next;
		}

		ASSERT(tmpmsg != NULL);

		if (tmpmsg->im_msg_next == NULL)
			clientp->ic_term_msg_last = prevmsg;
		else
			tmpmsg->im_msg_next->im_msg_prev = prevmsg;

		if (prevmsg != NULL)
			prevmsg->im_msg_next = tmpmsg->im_msg_next;
		else
			clientp->ic_term_msg_list = tmpmsg->im_msg_next;
	} else {

		mutex_exit(&msgimplp->im_mutex);
		/*
		 * Decrement the counter and kstats for active messages
		 */
		ASSERT(clientp->ic_msgs_active != 0);
		clientp->ic_msgs_active--;
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_SUB32_KSTATS(clientp, msgs_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		tmpmsg = clientp->ic_msg_list;

		while (tmpmsg != NULL) {
			if (tmpmsg == msgimplp)
				break;
			prevmsg = tmpmsg;
			tmpmsg = tmpmsg->im_msg_next;
		}

		ASSERT(tmpmsg != NULL);

		if (tmpmsg->im_msg_next == NULL)
			clientp->ic_msg_last = prevmsg;
		else
			tmpmsg->im_msg_next->im_msg_prev = prevmsg;

		if (prevmsg != NULL)
			prevmsg->im_msg_next = tmpmsg->im_msg_next;
		else
			clientp->ic_msg_list = tmpmsg->im_msg_next;
	}

	/* Save away the message reference count and clear the list flag */
	mutex_enter(&msgimplp->im_mutex);
	*refcnt = msgimplp->im_ref_count;
	msgimplp->im_flags &= ~IBMF_MSG_FLAGS_ON_LIST;
	mutex_exit(&msgimplp->im_mutex);

	mutex_exit(&clientp->ic_msg_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_client_rem_msg_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_client_rem_msg() exit\n");
}

/*
 * ibmf_i_find_msg():
 *	Walk the client message list for the message corresponding to
 *	the parameters specified
 *	The msg_list parameter should be either IBMF_REG_MSG_LIST
 *	or IBMF_TERM_MSG_LIST for the termination message list.
 */
ibmf_msg_impl_t *
ibmf_i_find_msg(ibmf_client_t *clientp, uint64_t tid, uint8_t mgt_class,
    uint8_t r_method, ib_lid_t lid, ib_gid_t *gid, boolean_t gid_pr,
    ibmf_rmpp_hdr_t *rmpp_hdr, boolean_t msg_list)
{
	ibmf_msg_impl_t *msgimplp;
	ib_gid_t	*ctx_gidp;
	int		msg_found;

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_find_msg_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_find_msg(): clientp = 0x%p, tid = 0x%p, mgmt_class = 0x%x, "
	    "lid = 0x%x, gidp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, tid, tid, tnf_opaque, mgt_class, mgt_class,
	    tnf_opaque, lid, lid, tnf_opaque, gid, gid);

	msg_found = B_FALSE;

	mutex_enter(&clientp->ic_msg_mutex);

	if (msg_list == IBMF_REG_MSG_LIST)
		msgimplp = clientp->ic_msg_list;
	else
		msgimplp = clientp->ic_term_msg_list;

	/*
	 * Look for a transaction (message) context that matches the
	 * transaction ID, gid or lid, and management class of the
	 * incoming packet.
	 *
	 * If the client decides to do a non-rmpp or rmpp send only,
	 * despite expecting a response, then the response should check
	 * if the message context for the send still exists.
	 * If it does, it should be skipped.
	 */
	while (msgimplp != NULL) {

		if (gid_pr == B_TRUE) {

			ctx_gidp = &msgimplp->im_global_addr.ig_sender_gid;

			/* first match gid */
			if ((ctx_gidp->gid_prefix != gid->gid_prefix) ||
			    (ctx_gidp->gid_guid != gid->gid_guid)) {

				msgimplp = msgimplp->im_msg_next;
				continue;
			}
		} else  {

			IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_find_msg, IBMF_TNF_TRACE, "",
			    "ibmf_i_find_msg(): %s, msgp = 0x%p, tid = 0x%p, "
			    "remote_lid = 0x%x, mgmt_class = 0x%x\n",
			    tnf_string, msg, "Comparing to msg",
			    tnf_opaque, msg, msgimplp,
			    tnf_opaque, tid, msgimplp->im_tid,
			    tnf_opaque, remote_lid,
			    msgimplp->im_local_addr.ia_remote_lid,
			    tnf_opaque, class, msgimplp->im_mgt_class);

			/* first match lid */
			if (msgimplp->im_local_addr.ia_remote_lid != lid) {
				msgimplp = msgimplp->im_msg_next;
				continue;
			}
		}

		/* next match tid and class */
		if ((msgimplp->im_tid != tid) ||
		    (msgimplp->im_mgt_class != mgt_class)) {

			msgimplp = msgimplp->im_msg_next;
			continue;
		}

		/*
		 * For unsolicited transactions, the message is found
		 * if the method matches, but,
		 * If the response is an ACK, and the transaction is
		 * in RMPP receiver mode, then skip this message.
		 */
		if (msgimplp->im_unsolicited == B_TRUE) {
			ibmf_rmpp_ctx_t *rmpp_ctx;
			ibmf_msg_bufs_t *msgbufp;

			mutex_enter(&msgimplp->im_mutex);
			rmpp_ctx = &msgimplp->im_rmpp_ctx;

			if ((msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP) &&
			    ((rmpp_ctx->rmpp_state ==
			    IBMF_RMPP_STATE_RECEVR_ACTIVE) ||
			    (rmpp_ctx->rmpp_state ==
			    IBMF_RMPP_STATE_RECEVR_TERMINATE))) {
				/* Continue if ACK packet */
				if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_ACK) {
					mutex_exit(&msgimplp->im_mutex);
					msgimplp = msgimplp->im_msg_next;
					continue;
				}
			}

			if (msgimplp->im_trans_state_flags ==
			    IBMF_TRANS_STATE_FLAG_RECV_ACTIVE) {
				msgbufp = &msgimplp->im_msgbufs_recv;
				if (msgbufp->im_bufs_mad_hdr->R_Method ==
				    r_method) {
					mutex_exit(&msgimplp->im_mutex);
					msg_found = B_TRUE;
					break;
				}
			}

			mutex_exit(&msgimplp->im_mutex);
		}

		/*
		 * if this was an unsequenced, non-RMPP transaction there should
		 * be no incoming packets
		 */
		if ((!(msgimplp->im_transp_op_flags &
		    IBMF_MSG_TRANS_FLAG_RMPP)) &&
		    (!(msgimplp->im_transp_op_flags &
		    IBMF_MSG_TRANS_FLAG_SEQ))) {

			msgimplp = msgimplp->im_msg_next;
			continue;
		}


		/*
		 * if this is a sequenced transaction,
		 * (the send and response may or may not be RMPP)
		 * and the method of the incoming MAD is the same as the
		 * method in the send message context with the response bit
		 * set then this message matches.
		 */
		if (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_SEQ) {
			ibmf_msg_bufs_t *msgbufp;

			mutex_enter(&msgimplp->im_mutex);

			msgbufp = &msgimplp->im_msgbufs_send;

			if ((msgbufp->im_bufs_mad_hdr->R_Method |
			    IBMF_RMPP_METHOD_RESP_BIT) == r_method) {
				mutex_exit(&msgimplp->im_mutex);
				msg_found = B_TRUE;
				break;
			}

			mutex_exit(&msgimplp->im_mutex);
		}

		/*
		 * if this is an RMPP SEND transaction there should only
		 * be ACK, STOP, and ABORTS RMPP packets.
		 * The response data packets would have been detected in
		 * the check above.
		 */
		if (msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_RMPP) {
			ibmf_rmpp_ctx_t *rmpp_ctx = &msgimplp->im_rmpp_ctx;
			ibmf_msg_bufs_t *msgbufp;

			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rmpp_ctx))

			if ((rmpp_hdr != NULL) &&
			    (rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_ACTIVE)) {

				/*
				 * If non-sequenced, then there should be
				 * no DATA packets incoming for this transaction
				 */
				if (!(msgimplp->im_transp_op_flags &
				    IBMF_MSG_TRANS_FLAG_SEQ)) {
					/* Continue if DATA packet */
					if (rmpp_hdr->rmpp_type ==
					    IBMF_RMPP_TYPE_DATA) {
						msgimplp =
						    msgimplp->im_msg_next;
						continue;
					}
				}


				/* Skip if R_Method does not match */
				if ((rmpp_ctx->rmpp_state ==
				    IBMF_RMPP_STATE_SENDER_ACTIVE) ||
				    (rmpp_ctx->rmpp_state ==
				    IBMF_RMPP_STATE_SENDER_SWITCH)) {
					/* Continue if DATA packet */
					if (rmpp_hdr->rmpp_type ==
					    IBMF_RMPP_TYPE_DATA) {
						msgimplp =
						    msgimplp->im_msg_next;
						continue;
					}

					/*
					 * Continue if method does not match
					 * Ignore response bit during match.
					 */
					msgbufp = &msgimplp->im_msgbufs_send;
					if ((msgbufp->im_bufs_mad_hdr->
					    R_Method & MAD_METHOD_MASK) !=
					    (r_method & MAD_METHOD_MASK)) {
						msgimplp = msgimplp->
						    im_msg_next;
						continue;
					}
				}

				/* Skip if R_Method does not match */
				if ((rmpp_ctx->rmpp_state ==
				    IBMF_RMPP_STATE_RECEVR_ACTIVE) ||
				    (rmpp_ctx->rmpp_state ==
				    IBMF_RMPP_STATE_RECEVR_TERMINATE)) {
					/* Continue if ACK packet */
					if (rmpp_hdr->rmpp_type ==
					    IBMF_RMPP_TYPE_ACK) {
						msgimplp =
						    msgimplp->im_msg_next;
						continue;
					}

					/* Continue if method does not match */
					msgbufp = &msgimplp->im_msgbufs_recv;
					if (msgbufp->im_bufs_mad_hdr->
					    R_Method != r_method) {
						msgimplp = msgimplp->
						    im_msg_next;
						continue;
					}
				}
			}
		}

		/*
		 * For a sequenced non-RMPP transaction, if the
		 * TID/LID/MgtClass are the same, and if the method
		 * of the incoming MAD and the message context are the
		 * same, then the MAD is likely to be a new request from
		 * the remote entity, so skip this message.
		 */
		if ((msgimplp->im_transp_op_flags & IBMF_MSG_TRANS_FLAG_SEQ) &&
		    !(msgimplp->im_transp_op_flags &
		    IBMF_MSG_TRANS_FLAG_RMPP)) {
			ibmf_msg_bufs_t *msgbufp;

			mutex_enter(&msgimplp->im_mutex);

			msgbufp = &msgimplp->im_msgbufs_send;

			mutex_exit(&msgimplp->im_mutex);

			/* Continue if method is the same */
			if (msgbufp->im_bufs_mad_hdr->
			    R_Method == r_method) {
				msgimplp = msgimplp-> im_msg_next;
				continue;
			}
		}

		/* everything matches, found the correct message */
		msg_found = B_TRUE;
		break;
	}

	if (msg_found == B_TRUE) {

		mutex_enter(&msgimplp->im_mutex);

		IBMF_MSG_INCR_REFCNT(msgimplp);

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_find_msg, IBMF_TNF_TRACE, "",
		    "ibmf_i_find_msg(): %s, msgp = 0x%p, ref_cnt = 0x%d\n",
		    tnf_string, msg, "Found message. Inc ref count",
		    tnf_opaque, msgimplp, msgimplp,
		    tnf_uint, ref_count, msgimplp->im_ref_count);

		mutex_exit(&msgimplp->im_mutex);
	}

	mutex_exit(&clientp->ic_msg_mutex);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_find_msg_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_find_msg() exit, msgp = 0x%p\n", tnf_opaque, msg, msgimplp);

	return (msgimplp);
}

/*
 * ibmf_i_find_msg_client():
 *	Walk the client message list to find the specified message
 */
boolean_t
ibmf_i_find_msg_client(ibmf_client_t *clp, ibmf_msg_impl_t *msgimplp,
    boolean_t inc_refcnt)
{
	ibmf_msg_impl_t	*msgp;
	boolean_t	found = B_FALSE;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_find_msg_client_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_find_msg_client(): clientp = 0x%p, msgp = 0x%p\n",
	    tnf_opaque, clientp, clp, tnf_opaque, msg, msgimplp);

	mutex_enter(&clp->ic_msg_mutex);

	msgp = clp->ic_msg_list;
	while (msgp != NULL) {

		if (msgp == msgimplp) {

			/* grab the mutex */
			mutex_enter(&msgimplp->im_mutex);

			if (inc_refcnt == B_TRUE)
				IBMF_MSG_INCR_REFCNT(msgimplp);

			IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_find_msg_client, IBMF_TNF_TRACE, "",
			    "ibmf_i_find_msg_client(): %s, msgp = 0x%p, "
			    "ref_cnt = 0x%d\n",
			    tnf_string, msg, "Found message. Inc ref count",
			    tnf_opaque, msgimplp, msgimplp,
			    tnf_uint, ref_count, msgimplp->im_ref_count);

			mutex_exit(&msgimplp->im_mutex);

			found = B_TRUE;

			break;
		}
		msgp = msgp->im_msg_next;
	}

	/*
	 * If not found on the regular message list,
	 * look in the termination list.
	 */
	if (found == B_FALSE) {
		msgp = clp->ic_term_msg_list;
		while (msgp != NULL) {
			if (msgp == msgimplp) {

				/* grab the mutex */
				mutex_enter(&msgimplp->im_mutex);

				if (inc_refcnt == B_TRUE)
					IBMF_MSG_INCR_REFCNT(msgimplp);

				IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
				    ibmf_i_find_msg_client, IBMF_TNF_TRACE, "",
				    "ibmf_i_find_msg_client(): %s, "
				    "msgp = 0x%p, ref_cnt = 0x%d\n", tnf_string,
				    msg, "Found message. Inc ref count",
				    tnf_opaque, msgimplp, msgimplp, tnf_uint,
				    ref_count, msgimplp->im_ref_count);

				mutex_exit(&msgimplp->im_mutex);
				found = B_TRUE;
				break;
			}
			msgp = msgp->im_msg_next;
		}
	}

	mutex_exit(&clp->ic_msg_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_find_msg_client_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_find_msg_client() exit\n");

	return (found);
}

/*
 * ibmf_setup_recvbuf_on_error():
 *
 * This function is used to set up the receive buffers to provide
 * a context for sending ABORT MADs in cases where the protocol
 * fails before the receive buffers have been setup. This can happen
 * if the initial receive MAD has a bad version, or an unexpected
 * segment number, for example.
 * We allocate IBMF_MAD_SIZE memory as we only need the information
 * stored in the MAD header and the class header to be able to send
 * the ABORT.
 */
int
ibmf_setup_recvbuf_on_error(ibmf_msg_impl_t *msgimplp, uchar_t *mad)
{
	size_t		offset;
	uint32_t	cl_hdr_sz, cl_hdr_off;
	ib_mad_hdr_t	*mad_hdr;
	uchar_t		*msgbufp;
	ibmf_client_t	*clientp = (ibmf_client_t *)msgimplp->im_client;

	ASSERT(msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL);

	/*
	 * Allocate enough memory for the MAD headers only.
	 */
	msgimplp->im_msgbufs_recv.im_bufs_mad_hdr =
	    (ib_mad_hdr_t *)kmem_zalloc(IBMF_MAD_SIZE, KM_NOSLEEP);
	if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_setup_recvbuf_on_error, IBMF_TNF_ERROR, "",
		    "ibmf_setup_recvbuf_on_error(): %s\n", tnf_string, msg,
		    "recv buf mem allocation failure");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_setup_recvbuf_on_error_end, IBMF_TNF_TRACE, "",
		    "ibmf_setup_recvbuf_on_error() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_ADD32_KSTATS(clientp, recv_bufs_alloced, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	mad_hdr = (ib_mad_hdr_t *)mad;

	/* Get the class header size and offset */
	ibmf_i_mgt_class_to_hdr_sz_off(mad_hdr->MgmtClass, &cl_hdr_sz,
	    &cl_hdr_off);

	msgbufp = (uchar_t *)msgimplp->im_msgbufs_recv.im_bufs_mad_hdr;

	/* copy the MAD and class header */
	bcopy((const void *)mad, (void *)msgbufp,
	    sizeof (ib_mad_hdr_t) + cl_hdr_off + cl_hdr_sz);

	/* offset of the class header */
	offset = sizeof (ib_mad_hdr_t) + cl_hdr_off;

	/* initialize class header pointer */
	if (cl_hdr_sz == 0) {
		msgimplp->im_msgbufs_recv.im_bufs_cl_hdr = NULL;
	} else {
		msgimplp->im_msgbufs_recv.im_bufs_cl_hdr =
		    (void *)(msgbufp + offset);
	}

	/* Set the class header length */
	msgimplp->im_msgbufs_recv.im_bufs_cl_hdr_len = cl_hdr_sz;

	/* offset of the class data */
	offset += cl_hdr_sz;

	/* initialize data area pointer */
	msgimplp->im_msgbufs_recv.im_bufs_cl_data = (void *)(msgbufp + offset);
	msgimplp->im_msgbufs_recv.im_bufs_cl_data_len = IBMF_MAD_SIZE -
	    sizeof (ib_mad_hdr_t) - cl_hdr_off - cl_hdr_sz;

	return (IBMF_SUCCESS);
}

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
 * This file contains the routines to implement the RMPP protocol.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>

extern ibmf_state_t *ibmf_statep;
extern int ibmf_trace_level;

#define	IBMF_BUF_PKTS	10

static void ibmf_i_rmpp_sender_active_flow(ibmf_client_t *clientp,
    ibmf_qp_handle_t qp_hdl, ibmf_msg_impl_t *msgimplp, uchar_t *mad);
static void ibmf_i_rmpp_sender_switch_flow(ibmf_client_t *clientp,
    ibmf_qp_handle_t qp_hdl, ibmf_msg_impl_t *msgimplp, uchar_t *mad);
static void ibmf_i_rmpp_recvr_flow_main(ibmf_client_t *clientp,
    ibmf_qp_handle_t qp_hdl, ibmf_msg_impl_t *msgimplp, uchar_t *mad);
static void ibmf_i_rmpp_recvr_active_flow(ibmf_client_t *clientp,
    ibmf_qp_handle_t qp_hdl, ibmf_msg_impl_t *msgimplp, uchar_t *mad);
static void ibmf_i_rmpp_recvr_term_flow(ibmf_client_t *clientp,
    ibmf_qp_handle_t qp_hdl, ibmf_msg_impl_t *msgimplp, uchar_t *mad);
static boolean_t ibmf_i_is_valid_rmpp_status(ibmf_rmpp_hdr_t *rmpp_hdr);

/*
 * ibmf_i_is_rmpp():
 *	Check if the client and QP context supports RMPP transfers
 */
boolean_t
ibmf_i_is_rmpp(ibmf_client_t *clientp, ibmf_qp_handle_t ibmf_qp_handle)
{
	ibmf_alt_qp_t	*qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;
	boolean_t	is_rmpp;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_is_rmpp_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_is_rmpp(): clientp = %p, "
	    "ibmf_qp_handle = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, ibmf_qp_handle, ibmf_qp_handle);

	if ((clientp->ic_reg_flags & IBMF_REG_FLAG_RMPP) == 0) {
		is_rmpp = B_FALSE;
	} else if ((ibmf_qp_handle != IBMF_QP_HANDLE_DEFAULT) &&
	    (qpp->isq_supports_rmpp == B_FALSE)) {
		is_rmpp = B_FALSE;
	} else {
		is_rmpp = B_TRUE;
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_is_rmpp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_is_rmpp() exit, is_rmpp = %d\n",
	    tnf_uint, is_rmpp, is_rmpp);

	return (is_rmpp);
}

/*
 * ibmf_i_rmpp_sender_active_flow():
 *	Perform RMPP processing for the sender side transaction.
 *	Refer to figure 178 "RMPP Sender Main Flow Diagram" of
 *	the InfiniBand Architecture Specification Volume 1, Release 1.1
 */
static void
ibmf_i_rmpp_sender_active_flow(ibmf_client_t *clientp, ibmf_qp_handle_t qp_hdl,
    ibmf_msg_impl_t *msgimplp, uchar_t *mad)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ibmf_rmpp_hdr_t *rmpp_hdr;
	uint32_t	abort_status;
	int		status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_sender_active_flow_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_sender_active_flow(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, madp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, qp_hdl, tnf_opaque, msg, msgimplp,
	    tnf_opaque, mad, mad);

	/*
	 * RMPP header is located just after the MAD header for SA MADs
	 * If this changes for Vendor MADs, we will need some way for
	 * the client to specify the byte offset of the RMPP header
	 * within the MAD.
	 */
	rmpp_hdr = (ibmf_rmpp_hdr_t *)(mad + sizeof (ib_mad_hdr_t));

	if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_DATA) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow(): %s\n", tnf_string, msg,
		    "Data packet received, discarding it");

		/*
		 * According to the IB spec, we discard the packet and resend
		 * packets next_seg->window_last.  However, next_seg is equal to
		 * window_last so send_rmpp_window() will just reset the timer.
		 */
		ibmf_i_send_rmpp_window(msgimplp, IBMF_NO_BLOCK);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_rmpp_sender_active_flow_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow() exit\n");

		return;
	}

	if (rmpp_hdr->rmpp_type != IBMF_RMPP_TYPE_ACK) {

		if ((rmpp_hdr->rmpp_type != IBMF_RMPP_TYPE_STOP) &&
		    (rmpp_hdr->rmpp_type != IBMF_RMPP_TYPE_ABORT)) {

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_sender_active_flow(): %s\n",
			    tnf_string, msg,
			    "Unrecognized packet received, sending ABORT");

			/* abort with status BadT */
			status = ibmf_i_send_rmpp(msgimplp,
			    IBMF_RMPP_TYPE_ABORT, IBMF_RMPP_STATUS_BADT,
			    0, 0, IBMF_NO_BLOCK);
			if (status != IBMF_SUCCESS) {
				IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
				    ibmf_i_rmpp_sender_active_flow,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_rmpp_sender_active_flow(): %s\n",
				    tnf_string, msg, "RMPP ABORT send failed");
				msgimplp->im_trans_state_flags |=
				    IBMF_TRANS_STATE_FLAG_SEND_DONE;
			}

			mutex_enter(&clientp->ic_kstat_mutex);
			IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
			mutex_exit(&clientp->ic_kstat_mutex);

		} else {

			abort_status = rmpp_hdr->rmpp_status;

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_sender_active_flow(): %s, "
			    "status = %d\n", tnf_string, msg,
			    "STOP or ABORT packet received, terminating",
			    tnf_uint, abort_status, abort_status);
		}

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;
		msgimplp->im_trans_state_flags |=
		    IBMF_TRANS_STATE_FLAG_SEND_DONE;

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout, msgimplp,
		    IBMF_RESP_TIMER);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_rmpp_sender_active_flow_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow() exit\n");

		return;
	}

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_rmpp_sender_active_flow,
	    IBMF_TNF_TRACE, "", "ibmf_i_rmpp_sender_active_flow(): %s, "
	    "msgp = 0x%p, recvd seg = %d wl = %d wf = %d\n",
	    tnf_string, msg, "ACK packet received",
	    tnf_opaque, msgp, msgimplp, tnf_uint, recvd_seg,
	    b2h32(rmpp_hdr->rmpp_segnum), tnf_uint, wl, rmpp_ctx->rmpp_wl,
	    tnf_uint, wf, rmpp_ctx->rmpp_wf);


	/* only ACK packets get here */
	if (b2h32(rmpp_hdr->rmpp_segnum) > rmpp_ctx->rmpp_wl) {

		/* abort with status S2B */
		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
		    IBMF_RMPP_STATUS_S2B, 0, 0, IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_sender_active_flow(): %s\n",
			    tnf_string, msg, "RMPP ABORT send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow(): %s\n",
		    tnf_string, msg, "Segnum > WL");

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_rmpp_sender_active_flow_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow() exit\n");

		return;
	}

	if (b2h32(rmpp_hdr->rmpp_segnum) < rmpp_ctx->rmpp_wf) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow(): %s\n",
		    tnf_string, msg, "Segnum < WF");

		/* discard the packet by not processing it here */

		/* send the window */
		ibmf_i_send_rmpp_window(msgimplp, IBMF_NO_BLOCK);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_rmpp_sender_active_flow_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow() exit\n");

		return;
	}

	/* only ACK packets with valid segnum get here */
	if (b2h32(rmpp_hdr->rmpp_pyldlen_nwl) < rmpp_ctx->rmpp_wl) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow(): %s\n",
		    tnf_string, msg, "NWL < WL");

		/* abort with status W2S */
		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
		    IBMF_RMPP_STATUS_W2S, 0, 0, IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_sender_active_flow(): %s\n",
			    tnf_string, msg, "RMPP ABORT send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_rmpp_sender_active_flow_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow() exit\n");

		return;
	}

	/* is ACK of last packet */

	if (b2h32(rmpp_hdr->rmpp_segnum) == rmpp_ctx->rmpp_num_pkts) {

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow(): %s, msgp = 0x%p, "
		    "double-sided = %d\n", tnf_string, msg, "Last packet",
		    tnf_opaque, msgimplp, msgimplp,
		    tnf_opaque, double_sided, rmpp_ctx->rmpp_is_ds);

		if (rmpp_ctx->rmpp_is_ds) {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_sender_active_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_sender_active_flow(): %s, "
			    "msgp = 0x%p\n", tnf_string, msg,
			    "Doublesided,sending ACK and switching to receiver",
			    tnf_opaque, msgimplp, msgimplp);

			rmpp_ctx->rmpp_is_ds = B_FALSE;
			rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_SENDER_SWITCH;
			rmpp_ctx->rmpp_wf = 1;
			rmpp_ctx->rmpp_wl = 1;
			rmpp_ctx->rmpp_es = 1;

			(void) ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ACK,
			    IBMF_RMPP_STATUS_NORMAL, 0, 1, IBMF_NO_BLOCK);

			/* set the response timer */
			ibmf_i_set_timer(ibmf_i_send_timeout,
			    msgimplp, IBMF_RESP_TIMER);

			/* proceed with sender switch to receiver */
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_rmpp_sender_active_flow_end,
			    IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_sender_active_flow() exit\n");
			return;
		}

		/* successful termination */
		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_DONE;
		ibmf_i_terminate_transaction(clientp, msgimplp, IBMF_SUCCESS);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_rmpp_sender_active_flow_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_active_flow() exit\n");
		return;
	}

	/* update RMPP context and send the next window */
	rmpp_ctx->rmpp_wf = b2h32(rmpp_hdr->rmpp_segnum) + 1;
	rmpp_ctx->rmpp_ns = b2h32(rmpp_hdr->rmpp_segnum) + 1;
	rmpp_ctx->rmpp_wl =
	    (rmpp_ctx->rmpp_num_pkts < b2h32(rmpp_hdr->rmpp_pyldlen_nwl)) ?
	    rmpp_ctx->rmpp_num_pkts : b2h32(rmpp_hdr->rmpp_pyldlen_nwl);

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_rmpp_sender_active_flow,
	    IBMF_TNF_TRACE, "", "ibmf_i_rmpp_sender_active_flow(): %s, "
	    "wf = %d, wl = %d, ns = %d\n",
	    tnf_string, msg, "sending next window",
	    tnf_uint, wf, rmpp_ctx->rmpp_wf, tnf_uint, wl, rmpp_ctx->rmpp_wl,
	    tnf_uint, ns, rmpp_ctx->rmpp_ns);

	/* send the window */
	ibmf_i_send_rmpp_window(msgimplp, IBMF_NO_BLOCK);

	/* carry on with the protocol */
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_sender_active_flow_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_sender_active_flow() exit\n");
}

/*
 * ibmf_i_rmpp_sender_switch_flow():
 *	Perform sender to receiver flow processing switch.
 *	Refer to figure 179 "RMPP Sender Direction Switch Flow Diagram" of
 *	the InfiniBand Architecture Specification Volume 1, Release 1.1
 */
static void
ibmf_i_rmpp_sender_switch_flow(ibmf_client_t *clientp, ibmf_qp_handle_t qp_hdl,
    ibmf_msg_impl_t *msgimplp, uchar_t *mad)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ibmf_rmpp_hdr_t *rmpp_hdr;
	int		status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_sender_switch_flow_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_sender_switch_flow(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, madp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, qp_hdl, tnf_opaque, msg, msgimplp,
	    tnf_opaque, mad, mad);

	rmpp_hdr = (ibmf_rmpp_hdr_t *)(mad + sizeof (ib_mad_hdr_t));

	if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_ACK) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_sender_switch_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_switch_flow(): %s\n", tnf_string, msg,
		    "ACK packet received, sending ACK");

		(void) ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ACK,
		    IBMF_RMPP_STATUS_NORMAL, 0, 1, IBMF_NO_BLOCK);

		/* set the response timer */
		ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp,
		    IBMF_RESP_TIMER);

	} else if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_DATA) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_sender_switch_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_switch_flow(): %s\n", tnf_string, msg,
		    "DATA packet received, processing packet");

		msgimplp->im_flags |= IBMF_MSG_FLAGS_RECV_RMPP;
		ibmf_i_rmpp_recvr_flow_main(clientp, qp_hdl, msgimplp, mad);

	} else {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_rmpp_sender_switch_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_sender_switch_flow(): %s\n", tnf_string, msg,
		    "Unexpected packet received, sending ABORT BADT");

		/* abort with status BadT */
		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
		    IBMF_RMPP_STATUS_BADT, 0, 0, IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_sender_switch_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_sender_switch_flow(): %s\n",
			    tnf_string, msg, "RMPP ABORT send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_sender_switch_flow_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_sender_switch_flow() exit\n");
}

/*
 * ibmf_i_rmpp_recvr_flow_main():
 *	Perform RMPP receiver flow processing.
 *	Refer to figure 176 "RMPP Receiver Main Flow Diagram" of
 *	the InfiniBand Architecture Specification Volume 1, Release 1.1
 */
static void
ibmf_i_rmpp_recvr_flow_main(ibmf_client_t *clientp, ibmf_qp_handle_t qp_hdl,
    ibmf_msg_impl_t *msgimplp, uchar_t *mad)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ibmf_rmpp_hdr_t *rmpp_hdr;
	ib_mad_hdr_t	*mad_hdr;
	uchar_t		*msgbufp;
	uchar_t		*datap;
	uint32_t	data_sz, offset, num_pkts;
	uint32_t	cl_hdr_sz, cl_data_sz, cl_hdr_off, cl_hdrdata_sz;
	size_t		buf_sz;
	int		status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_recvr_flow_main_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_recvr_flow_main(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, madp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, qp_hdl, tnf_opaque, msg, msgimplp,
	    tnf_opaque, mad, mad);

	rmpp_hdr = (ibmf_rmpp_hdr_t *)(mad + sizeof (ib_mad_hdr_t));

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_rmpp_recvr_flow_main,
	    IBMF_TNF_TRACE, "", "ibmf_i_rmpp_recvr_flow_main(): "
	    "segnum = %d, es = %d, wl = %d\n", tnf_uint, segnum,
	    b2h32(rmpp_hdr->rmpp_segnum), tnf_uint, es, rmpp_ctx->rmpp_es,
	    tnf_uint, wl, rmpp_ctx->rmpp_wl);

	/*
	 * check that this is the segment we expected;
	 * assume this check will succeed for the first segment since we cannot
	 * send an ACK if we haven't allocated the rmpp context yet
	 */
	if (b2h32(rmpp_hdr->rmpp_segnum) != rmpp_ctx->rmpp_es) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main(): %s\n", tnf_string, msg,
		    "Unexpected segment number, discarding packet");

		/* discard this packet by not processing it here */

		/*
		 * If the receive buffer is not yet allocated, this is
		 * probably the first MAD received for the receive context.
		 * We need to set up the receive buffer before calling
		 * ibmf_i_send_rmpp() to send an ACK packet.
		 */
		if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {
			status = ibmf_setup_recvbuf_on_error(msgimplp, mad);
			if (status != IBMF_SUCCESS) {
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L2,
				    ibmf_i_rmpp_recvr_flow_main_err,
				    IBMF_TNF_ERROR, "",
				    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
				    tnf_string, msg,
				    "ibmf_setup_recvbuf_on_error() failed");
				return;
			}
		}

		/* send an ACK of ES - 1 if ES is greater than 1 */
		if (rmpp_ctx->rmpp_es > 1) {
			(void) ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ACK,
			    IBMF_RMPP_STATUS_NORMAL, rmpp_ctx->rmpp_es - 1,
			    rmpp_ctx->rmpp_es - 1 + IBMF_RMPP_DEFAULT_WIN_SZ,
			    IBMF_NO_BLOCK);
		}

		/*
		 * reset the timer if we're still waiting for the first seg;
		 * this is the same timer that is normally set in send_compl
		 * NOTE: this should be in the IB spec's flowchart but isn't
		 */
		if (rmpp_ctx->rmpp_es == 1) {
			ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp,
			    IBMF_RESP_TIMER);
		}

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_rmpp_recvr_flow_main_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main() exit\n");
		return;
	}

	mad_hdr = (ib_mad_hdr_t *)mad;

	ibmf_i_mgt_class_to_hdr_sz_off(mad_hdr->MgmtClass, &cl_hdr_sz,
	    &cl_hdr_off);

	if ((rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_FIRST_PKT) ||
	    (b2h32(rmpp_hdr->rmpp_segnum) == 1)) {

		/* first packet flag should be set and seg num should be 1 */
		if (((rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_FIRST_PKT) == 0) ||
		    (b2h32(rmpp_hdr->rmpp_segnum) != 1)) {

			/*
			 * If the receive buffer is not yet allocated, this is
			 * probably the first MAD received for the receive ctx.
			 * We need to set up the receive buffer before calling
			 * ibmf_i_send_rmpp() to send an ABORT packet.
			 */
			if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {
				status = ibmf_setup_recvbuf_on_error(msgimplp,
				    mad);
				if (status != IBMF_SUCCESS) {
					IBMF_TRACE_1(IBMF_TNF_NODEBUG,
					    DPRINT_L2,
					    ibmf_i_rmpp_recvr_flow_main_err,
					    IBMF_TNF_ERROR, "",
					    "ibmf_i_rmpp_recvr_flow_main(): "
					    "%s\n", tnf_string, msg,
					    "ibmf_setup_recvbuf_on_error() "
					    "failed");
					return;
				}
			}

			/* abort with status BadT */
			status = ibmf_i_send_rmpp(msgimplp,
			    IBMF_RMPP_TYPE_ABORT, IBMF_RMPP_STATUS_IFSN,
			    0, 0, IBMF_NO_BLOCK);
			if (status != IBMF_SUCCESS) {
				IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
				    ibmf_i_rmpp_recvr_flow_main,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
				    tnf_string, msg, "RMPP ABORT send failed");
				msgimplp->im_trans_state_flags |=
				    IBMF_TRANS_STATE_FLAG_SEND_DONE;
			}

			mutex_enter(&clientp->ic_kstat_mutex);
			IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
			mutex_exit(&clientp->ic_kstat_mutex);

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
			    tnf_string, msg, "Inconsistent first and segment "
			    "number detected, sending ABORT IFSN");

			rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

			ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

			ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
			    msgimplp, IBMF_RESP_TIMER);

			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_rmpp_recvr_flow_main_end, IBMF_TNF_TRACE,
			    "", "ibmf_i_rmpp_recvr_flow_main() exit\n");
			return;
		}

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main(): %s\n", tnf_string, msg,
		    "Segment number 1 received:", tnf_opaque, msgp, msgimplp);

		cl_data_sz = MAD_SIZE_IN_BYTES -
		    sizeof (ib_mad_hdr_t) - cl_hdr_off - cl_hdr_sz;

		cl_hdrdata_sz = MAD_SIZE_IN_BYTES -
		    sizeof (ib_mad_hdr_t) - cl_hdr_off;

		/*
		 * Calculate the number of packets by dividing the payload
		 * length in the RMPP header by the payload size for
		 * a single packet of that management class (including the
		 * class header).
		 */
		buf_sz = b2h32(rmpp_hdr->rmpp_pyldlen_nwl);
		if ((buf_sz % cl_hdrdata_sz) != 0)
			num_pkts = (buf_sz / cl_hdrdata_sz) + 1;
		else {
			if (buf_sz > 0)
				num_pkts = buf_sz / cl_hdrdata_sz;
			else
				num_pkts = 1;
		}

		/*
		 * If the payload length of the message is not specified
		 * in the first packet's RMPP header, we create a
		 * temporary receive buffer with space for data payloads
		 * of IBMF_BUF_PKTS packets. If the number of packets
		 * received exceeds the capacity in the receive buffer,
		 * the temporary receive buffer will be freed up, and
		 * a larger temporary receive buffer will be allocated.
		 * When the last packet is received, the final receive
		 * buffer will be allocated with the real size of the message.
		 * The data will be copied from the old buffer to the new
		 * buffer.
		 */
		if (b2h32(rmpp_hdr->rmpp_pyldlen_nwl) != 0) {
			/*
			 * rmpp_pyld_len is the total length of just the
			 * class data. Class headers from each packet are
			 * not included in this calculation.
			 */
			msgimplp->im_msgbufs_recv.im_bufs_cl_data_len =
			    rmpp_ctx->rmpp_pyld_len =
			    b2h32(rmpp_hdr->rmpp_pyldlen_nwl) -
			    (num_pkts * cl_hdr_sz);
		} else {
			msgimplp->im_msgbufs_recv.im_bufs_cl_data_len =
			    rmpp_ctx->rmpp_pyld_len =
			    IBMF_BUF_PKTS * cl_data_sz;
			rmpp_ctx->rmpp_flags |= IBMF_CTX_RMPP_FLAGS_DYN_PYLD;
		}

		ASSERT(msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL);

		/* allocate memory for the message data */
		msgimplp->im_msgbufs_recv.im_bufs_mad_hdr =
		    (ib_mad_hdr_t *)kmem_zalloc(sizeof (ib_mad_hdr_t) +
		    cl_hdr_off + cl_hdr_sz + rmpp_ctx->rmpp_pyld_len,
		    KM_NOSLEEP);
		if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
			    tnf_string, msg,
			    "mem allocation failure (known rmpp payload)");

			ibmf_i_terminate_transaction(
			    msgimplp->im_client, msgimplp,
			    IBMF_NO_MEMORY);

			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_rmpp_recvr_flow_main_end, IBMF_TNF_TRACE,
			    "", "ibmf_i_rmpp_recvr_flow_main() exit\n");
			return;
		}
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, recv_bufs_alloced, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		msgbufp = (uchar_t *)msgimplp->im_msgbufs_recv.im_bufs_mad_hdr;

		/* copy the MAD and class header */
		bcopy((const void *)mad, (void *)msgbufp,
		    sizeof (ib_mad_hdr_t) + cl_hdr_off + cl_hdr_sz);

		offset = sizeof (ib_mad_hdr_t) + cl_hdr_off;

		/* initialize class header pointer */
		if (cl_hdr_sz == 0) {
			msgimplp->im_msgbufs_recv.im_bufs_cl_hdr = NULL;
		} else {
			msgimplp->im_msgbufs_recv.im_bufs_cl_hdr =
			    (void *)(msgbufp + offset);
		}
		msgimplp->im_msgbufs_recv.im_bufs_cl_hdr_len = cl_hdr_sz;

		offset += cl_hdr_sz;

		/* initialize data area pointer */
		msgimplp->im_msgbufs_recv.im_bufs_cl_data =
		    (void *)(msgbufp + offset);

		rmpp_ctx->rmpp_data_offset = 0;

		cl_data_sz = MAD_SIZE_IN_BYTES -
		    sizeof (ib_mad_hdr_t) - cl_hdr_off - cl_hdr_sz;

		rmpp_ctx->rmpp_pkt_data_sz = cl_data_sz;

		/*
		 * calculate number of expected packets for transaction
		 * timeout calculation
		 */
		if (rmpp_ctx->rmpp_flags & IBMF_CTX_RMPP_FLAGS_DYN_PYLD) {

			/*
			 * if the payload length is not specified in
			 * the first packet, just guess how many packets
			 * might arrive
			 */
			msgimplp->im_rmpp_ctx.rmpp_num_pkts = 100;
		} else {
			msgimplp->im_rmpp_ctx.rmpp_num_pkts =
			    rmpp_ctx->rmpp_pyld_len / cl_data_sz;

			/* round up */
			if ((rmpp_ctx->rmpp_pyld_len % cl_data_sz) != 0)
				msgimplp->im_rmpp_ctx.rmpp_num_pkts++;
		}

		/* set the transaction timer if there are more packets */
		if ((rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_LAST_PKT) == 0) {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
			    tnf_string, msg,
			    "First pkt recvd; setting trans timer: ",
			    tnf_opaque, msg, msgimplp);

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): setting trans"
			    " timer %p %d\n", tnf_opaque, msg, msgimplp,
			    tnf_opaque, timeout_id, msgimplp->im_rp_timeout_id);

			ibmf_i_set_timer(ibmf_i_recv_timeout, msgimplp,
			    IBMF_TRANS_TIMER);
		}
	}

	offset = sizeof (ib_mad_hdr_t) + cl_hdr_off + cl_hdr_sz;

	/*
	 * copy the data from the packet into the data buffer in
	 * the message.
	 */

	if (rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_LAST_PKT)
		data_sz = b2h32(rmpp_hdr->rmpp_pyldlen_nwl) - cl_hdr_sz;
	else
		data_sz = rmpp_ctx->rmpp_pkt_data_sz;

	/* if a payload length was specified and we've met or exceeded it */
	if (((data_sz + rmpp_ctx->rmpp_data_offset) >=
	    rmpp_ctx->rmpp_pyld_len) &&
	    ((rmpp_ctx->rmpp_flags & IBMF_CTX_RMPP_FLAGS_DYN_PYLD) == 0)) {

		/* last packet flag should be set */
		if ((rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_LAST_PKT) == 0) {

			/* abort with status Incon. last and payload length */
			status = ibmf_i_send_rmpp(msgimplp,
			    IBMF_RMPP_TYPE_ABORT, IBMF_RMPP_STATUS_ILPL,
			    0, 0, IBMF_NO_BLOCK);
			if (status != IBMF_SUCCESS) {
				IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
				    ibmf_i_rmpp_recvr_flow_main,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
				    tnf_string, msg, "RMPP ABORT send failed");
				msgimplp->im_trans_state_flags |=
				    IBMF_TRANS_STATE_FLAG_SEND_DONE;
			}

			mutex_enter(&clientp->ic_kstat_mutex);
			IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
			mutex_exit(&clientp->ic_kstat_mutex);

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
			    tnf_string, msg,
			    "Inconsistent last and payload length detected,"
			    " sending ABORT ILPL, unsetting trans timer");

			rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

			ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

			ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
			    msgimplp, IBMF_RESP_TIMER);

			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_rmpp_recvr_flow_main_end, IBMF_TNF_TRACE,
			    "", "ibmf_i_rmpp_recvr_flow_main() exit\n");

			return;
		}
	} else if (((data_sz + rmpp_ctx->rmpp_data_offset) >=
	    rmpp_ctx->rmpp_pyld_len) &&
	    ((rmpp_ctx->rmpp_flags & IBMF_CTX_RMPP_FLAGS_DYN_PYLD) != 0) &&
	    ((rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_LAST_PKT) == 0)) {

		/*
		 * If the payload length was not specified in the first
		 * packet's RMPP header, we have a temporary receive buffer
		 * the size of which will be exceeded with this incoming
		 * packet. We need to allocate a new temporary receive buffer
		 * with an additional IBMF_BUF_PKTS data payloads.
		 */
		ib_mad_hdr_t	*old_buf;
		size_t		prev_pyld_len;

		old_buf = msgimplp->im_msgbufs_recv.im_bufs_mad_hdr;
		prev_pyld_len = rmpp_ctx->rmpp_pyld_len;

		rmpp_ctx->rmpp_pyld_len +=
		    IBMF_BUF_PKTS * rmpp_ctx->rmpp_pkt_data_sz;
		msgimplp->im_msgbufs_recv.im_bufs_cl_data_len =
			    rmpp_ctx->rmpp_pyld_len;
		msgimplp->im_msgbufs_recv.im_bufs_mad_hdr =
		    (ib_mad_hdr_t *)kmem_zalloc(sizeof (ib_mad_hdr_t) +
		    cl_hdr_off + cl_hdr_sz + rmpp_ctx->rmpp_pyld_len,
		    KM_NOSLEEP);
		if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): %s, allocsz = %d\n",
			    tnf_string, msg,
			    "mem allocation failure (unknown rmpp payload)",
			    tnf_uint, alloc_size,
			    sizeof (ib_mad_hdr_t) + cl_hdr_off + cl_hdr_sz +
			    rmpp_ctx->rmpp_pyld_len);

			ibmf_i_terminate_transaction(
			    msgimplp->im_client, msgimplp,
			    IBMF_NO_MEMORY);

			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_rmpp_recvr_flow_main_end, IBMF_TNF_TRACE,
			    "", "ibmf_i_rmpp_recvr_flow_main() exit\n");
			return;
		}
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, recv_bufs_alloced, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		msgbufp = (uchar_t *)msgimplp->im_msgbufs_recv.im_bufs_mad_hdr;

		/* copy the MAD and class header */
		bcopy((const void *)old_buf, (void *)msgbufp,
		    sizeof (ib_mad_hdr_t) + cl_hdr_off + cl_hdr_sz +
		    prev_pyld_len);

		kmem_free(old_buf, sizeof (ib_mad_hdr_t) + cl_hdr_off +
		    cl_hdr_sz + prev_pyld_len);
	}

	/* don't overflow buffer */
	if (rmpp_ctx->rmpp_data_offset + data_sz >
	    rmpp_ctx->rmpp_pyld_len) {
		data_sz = rmpp_ctx->rmpp_pyld_len -
		    rmpp_ctx->rmpp_data_offset;
	}

	datap = (uchar_t *)msgimplp->im_msgbufs_recv.im_bufs_cl_data;

	bcopy((void *)&mad[offset],
	    (void *)(datap + rmpp_ctx->rmpp_data_offset), data_sz);

	rmpp_ctx->rmpp_data_offset += data_sz;

	rmpp_ctx->rmpp_es++;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_rmpp_recvr_flow_main,
	    IBMF_TNF_TRACE, "", "ibmf_i_rmpp_recvr_flow_main(): es = %d\n",
	    tnf_uint, es, rmpp_ctx->rmpp_es);

	if (rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_LAST_PKT) {

		/*
		 * Since this is the last packet, we finally know the
		 * size of the receive buffer we need to allocate.
		 * Allocate the needed size and free the temporary receive
		 * buffer.
		 */
		if ((rmpp_ctx->rmpp_flags & IBMF_CTX_RMPP_FLAGS_DYN_PYLD) !=
		    0) {
			ib_mad_hdr_t	*old_buf;
			size_t		prev_pyld_len;

			rmpp_ctx->rmpp_flags &= ~IBMF_CTX_RMPP_FLAGS_DYN_PYLD;
			old_buf = msgimplp->im_msgbufs_recv.im_bufs_mad_hdr;
			prev_pyld_len = rmpp_ctx->rmpp_pyld_len;
			rmpp_ctx->rmpp_pyld_len = rmpp_ctx->rmpp_data_offset;
			msgimplp->im_msgbufs_recv.im_bufs_cl_data_len =
			    rmpp_ctx->rmpp_pyld_len;
			msgimplp->im_msgbufs_recv.im_bufs_mad_hdr =
			    (ib_mad_hdr_t *)kmem_zalloc(sizeof (ib_mad_hdr_t) +
			    cl_hdr_off + cl_hdr_sz + rmpp_ctx->rmpp_pyld_len,
			    KM_NOSLEEP);
			if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {
				IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
				    ibmf_i_rmpp_recvr_flow_main,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
				    tnf_string, msg,
				    "mem allocation failure (final payload)");
				ibmf_i_terminate_transaction(
				    msgimplp->im_client, msgimplp,
				    IBMF_NO_MEMORY);
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_rmpp_recvr_flow_main_end,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_rmpp_recvr_flow_main() exit\n");
				return;
			}
			mutex_enter(&clientp->ic_kstat_mutex);
			IBMF_ADD32_KSTATS(clientp, recv_bufs_alloced, 1);
			mutex_exit(&clientp->ic_kstat_mutex);

			msgbufp = (uchar_t *)
			    msgimplp->im_msgbufs_recv.im_bufs_mad_hdr;

			/* copy the data to the new buffer */
			bcopy((const void *)old_buf, (void *)msgbufp,
			    sizeof (ib_mad_hdr_t) + cl_hdr_off + cl_hdr_sz +
			    rmpp_ctx->rmpp_pyld_len);

			offset = sizeof (ib_mad_hdr_t) + cl_hdr_off;

			/* initialize class header pointer */
			if (cl_hdr_sz == 0) {
				msgimplp->im_msgbufs_recv.im_bufs_cl_hdr = NULL;
			} else {
				msgimplp->im_msgbufs_recv.im_bufs_cl_hdr =
				    (void *)(msgbufp + offset);
			}
			msgimplp->im_msgbufs_recv.im_bufs_cl_hdr_len =
			    cl_hdr_sz;

			offset += cl_hdr_sz;

			/* initialize data area pointer */
			msgimplp->im_msgbufs_recv.im_bufs_cl_data =
			    (void *)(msgbufp + offset);

			kmem_free(old_buf, sizeof (ib_mad_hdr_t) + cl_hdr_off +
			    cl_hdr_sz + prev_pyld_len);
		}

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main(): %s, msgp = 0x%p\n",
		    tnf_string, msg,
		    "Last pkt rcvd; state to recv_term, sending ack",
		    tnf_opaque, msgp, msgimplp);

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_RECEVR_TERMINATE;

		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ACK,
		    IBMF_RMPP_STATUS_NORMAL, rmpp_ctx->rmpp_es - 1,
		    rmpp_ctx->rmpp_es - 1 + IBMF_RMPP_DEFAULT_WIN_SZ,
		    IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
			    tnf_string, msg, "RMPP ACK send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		/* unset the transaction timer if it's not the first segment */
		if ((rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_FIRST_PKT) == 0) {
			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): %s, msgp = 0x%p\n",
			    tnf_string, msg, "Last, but not first segment",
			    tnf_opaque, msgp, msgimplp);
			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_flow_main(): unsetting timer "
			    "%p %d\n", tnf_opaque, msgp, msgimplp,
			    tnf_opaque, timeout_id, msgimplp->im_rp_timeout_id);

			ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);
		}

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main(): %s, msgp = 0x%p\n",
		    tnf_string, msg,
		    "Last pkt rcvd; setting resp timer",
		    tnf_opaque, msgp, msgimplp);

		/*
		 * The RMPP receive transaction has been broken
		 * up into two parts. At this point in the
		 * transaction, all the data has been received.
		 * From the perspective of the client, the transaction
		 * is complete. So, control is returned to the client
		 * at this point. However, the RMPP protocol requires
		 * a wait after receiving the last data packet, so that,
		 * duplicate packets may be absorbed. This wait is
		 * implemented in the second part of the transaction under
		 * a duplicate message context.
		 * The regular message context is marked as done in
		 * ibmf_i_terminate_transaction().
		 * The IBMF_MSG_FLAGS_SET_TERMINATION flag indicates
		 * that the duplicate message context needs to be created
		 * to handle the termination loop.
		 */
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main(): last packet, "
		    " returning data to client for message %p\n",
		    tnf_opaque, msgp, msgimplp);

		ibmf_i_terminate_transaction(clientp, msgimplp, IBMF_SUCCESS);

		/* Mark this message for early termination */
		msgimplp->im_flags |= IBMF_MSG_FLAGS_SET_TERMINATION;

		return;
	}

	if (b2h32(rmpp_hdr->rmpp_segnum) == rmpp_ctx->rmpp_wl) {
		IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main(): %s, msgp = 0x%p"
		    "segnum = %d, wl = %d\n", tnf_string, msg,
		    "Last packet in window received", tnf_opaque, msgimplp,
		    msgimplp, tnf_opaque, seg, b2h32(rmpp_hdr->rmpp_segnum),
		    tnf_opaque, wl, rmpp_ctx->rmpp_wl);

		(void) ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ACK,
		    IBMF_RMPP_STATUS_NORMAL,
		    rmpp_ctx->rmpp_es - 1,
		    rmpp_ctx->rmpp_es - 1 +
		    IBMF_RMPP_DEFAULT_WIN_SZ, IBMF_NO_BLOCK);

		/* update the window */
		rmpp_ctx->rmpp_wl += IBMF_RMPP_DEFAULT_WIN_SZ;

	} else {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_flow_main, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_flow_main(): %s\n",
		    tnf_string, msg, "Packet in window received");

	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_recvr_flow_main_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_recvr_flow_main() exit\n");
}

/*
 * ibmf_i_rmpp_recvr_active_flow():
 *	Perform RMPP receiver flow initiation processing.
 *	Refer to figure 176 "RMPP Receiver Main Flow Diagram" of
 *	the InfiniBand Architecture Specification Volume 1, Release 1.1
 */
static void
ibmf_i_rmpp_recvr_active_flow(ibmf_client_t *clientp, ibmf_qp_handle_t qp_hdl,
    ibmf_msg_impl_t *msgimplp, uchar_t *mad)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ibmf_rmpp_hdr_t *rmpp_hdr;
	uint32_t	abort_status;
	int		status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_recvr_active_flow_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_recvr_active_flow(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, madp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, qp_hdl, tnf_opaque, msg, msgimplp,
	    tnf_opaque, mad, mad);

	rmpp_hdr = (ibmf_rmpp_hdr_t *)(mad + sizeof (ib_mad_hdr_t));

	if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_ACK) {

		/* discard this packet by not processing it here */

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_active_flow(): %s\n", tnf_string, msg,
		    "ACK packet received, discarding packet");

		/*
		 * reset the timer if we're still waiting for the first seg;
		 * this is the same timer that is normally set in send_compl
		 * NOTE: this should be in the IB spec's flowchart but isn't
		 */
		if (rmpp_ctx->rmpp_es == 1) {
			ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp,
			    IBMF_RESP_TIMER);
		}

		return;
	}

	if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_DATA) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_active_flow(): %s\n", tnf_string, msg,
		    "DATA packet received, processing packet");

		ibmf_i_rmpp_recvr_flow_main(clientp, qp_hdl, msgimplp, mad);

	} else if ((rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_STOP) ||
	    (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_ABORT)) {

		abort_status = rmpp_hdr->rmpp_status;

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_rmpp_recvr_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_active_flow(): %s, status = %d\n",
		    tnf_string, msg,
		    "STOP/ABORT packet received, terminating transaction",
		    tnf_uint, abort_status, abort_status);

		/* discard the packet and terminate the transaction */
		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;
		msgimplp->im_trans_state_flags |=
		    IBMF_TRANS_STATE_FLAG_SEND_DONE;

		ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);

	} else {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_rmpp_recvr_active_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_active_flow(): %s\n", tnf_string, msg,
		    "Unrecognized packet received, terminating transaction");

		/* abort with status BadT */
		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
		    IBMF_RMPP_STATUS_BADT, 0, 0, IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_recvr_active_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_active_flow(): %s\n",
			    tnf_string, msg, "RMPP ABORT send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_recvr_active_flow_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_recvr_active_flow() exit\n");
}

/*
 * ibmf_i_rmpp_recvr_term_flow():
 *	Perform RMPP receiver termination flow processing.
 *	Refer to figure 177 "RMPP Receiver Termination Flow Diagram" of
 *	the InfiniBand Architecture Specification Volume 1, Release 1.1
 */
static void
ibmf_i_rmpp_recvr_term_flow(ibmf_client_t *clientp, ibmf_qp_handle_t qp_hdl,
    ibmf_msg_impl_t *msgimplp, uchar_t *mad)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ibmf_rmpp_hdr_t *rmpp_hdr;
	int		status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_recvr_term_flow_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_recvr_term_flow(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, madp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, qp_hdl, tnf_opaque, msg, msgimplp,
	    tnf_opaque, mad, mad);

	rmpp_hdr = (ibmf_rmpp_hdr_t *)(mad + sizeof (ib_mad_hdr_t));

	if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_DATA) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_term_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_term_flow(): %s\n", tnf_string, msg,
		    "Data packet received, resending ACK");

		(void) ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ACK,
		    IBMF_RMPP_STATUS_NORMAL, rmpp_ctx->rmpp_es - 1,
		    rmpp_ctx->rmpp_es - 1 + IBMF_RMPP_DEFAULT_WIN_SZ,
		    IBMF_NO_BLOCK);

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_term_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_term_flow(): setting resp timer %d %p\n",
		    tnf_opaque, msgimplp, msgimplp, tnf_opaque,
		    timeout_id, msgimplp->im_rp_timeout_id);

		/* set the response timer */
		ibmf_i_set_timer(ibmf_i_recv_timeout, msgimplp,
		    IBMF_RESP_TIMER);

	} else if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_ACK) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_rmpp_recvr_term_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_term_flow(): %s, msgp = 0x%p\n",
		    tnf_string, msg, "ACK packet received",
		    tnf_opaque, msgimplp, msgimplp);

		if (rmpp_ctx->rmpp_is_ds) {
			/*
			 * received ACK from sender which is indication that
			 * we can send response; notify client that data has
			 * arrived; it will call msg_transport to send response
			 */
			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_rmpp_recvr_term_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_term_flow(): %s, msgp = 0x%p\n",
			    tnf_string, msg,
			    "Received final ack for double-sided trans",
			    tnf_opaque, msgimplp, msgimplp);

			/*
			 * successful termination
			 */
			rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_DONE;
			ibmf_i_terminate_transaction(clientp, msgimplp,
			    IBMF_SUCCESS);

		} else {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_recvr_term_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_term_flow(): %s, msgp = 0x%p\n",
			    tnf_string, msg, "Received ACK while in recv_term "
			    "state for single sided trans",
			    tnf_opaque, msgimplp, msgimplp);

			/* abort with status BadT */
			(void) ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
			    IBMF_RMPP_STATUS_BADT, 0, 0, IBMF_NO_BLOCK);

			rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

			ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

			ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
			    msgimplp, IBMF_RESP_TIMER);
		}

	} else {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_rmpp_recvr_term_flow, IBMF_TNF_TRACE, "",
		    "ibmf_i_rmpp_recvr_term_flow(): %s\n", tnf_string, msg,
		    "Unexpected packet received, sending ABORT BADT");

		/* abort with status BadT */
		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
		    IBMF_RMPP_STATUS_BADT, 0, 0, IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_i_rmpp_recvr_term_flow, IBMF_TNF_TRACE, "",
			    "ibmf_i_rmpp_recvr_term_flow(): %s\n",
			    tnf_string, msg, "RMPP ABORT send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);

	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_rmpp_recvr_term_flow_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_rmpp_recvr_term_flow() exit\n");
}

/*
 * ibmf_i_is_valid_rmpp_status():
 *	Check for a valid RMPP status
 */
static boolean_t
ibmf_i_is_valid_rmpp_status(ibmf_rmpp_hdr_t *rmpp_hdr)
{
	boolean_t	found = B_TRUE;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_is_valid_rmpp_status_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_is_valid_rmpp_status(): rmpp_hdr = 0x%p\n",
	    tnf_opaque, rmpp_hdr, rmpp_hdr);

	if (((rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_DATA) ||
	    (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_ACK)) &&
	    (rmpp_hdr->rmpp_status != IBMF_RMPP_STATUS_NORMAL))
		found = B_FALSE;

	if ((rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_RESX) &&
	    (rmpp_hdr->rmpp_type != IBMF_RMPP_TYPE_STOP))
		found = B_FALSE;

	if (((rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_T2L) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_ILPL) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_IFSN) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_BADT) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_W2S) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_S2B) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_IS) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_UNV) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_TMR) ||
	    (rmpp_hdr->rmpp_status == IBMF_RMPP_STATUS_USP)) &&
	    (rmpp_hdr->rmpp_type != IBMF_RMPP_TYPE_ABORT))
		found = B_FALSE;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_is_valid_rmpp_status_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_is_valid_rmpp_status_flow() exit\n");

	return (found);
}

/*
 * ibmf_i_handle_rmpp():
 *	Handle RMPP processing of an incoming IB packet
 */
void
ibmf_i_handle_rmpp(ibmf_client_t *clientp, ibmf_qp_handle_t qp_hdl,
    ibmf_msg_impl_t *msgimplp, uchar_t *madp)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ibmf_rmpp_hdr_t *rmpp_hdr;
	int		status;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_handle_rmpp_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_handle_rmpp(): clientp = 0x%p, qp_hdl = 0x%p, "
	    "msgp = 0x%p, madp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, qp_hdl, qp_hdl, tnf_opaque, msg, msgimplp,
	    tnf_opaque, mad, madp);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	rmpp_hdr = (ibmf_rmpp_hdr_t *)(madp + sizeof (ib_mad_hdr_t));

	/*
	 * Check the version in the RMPP header
	 */
	if (rmpp_hdr->rmpp_version != IBMF_RMPP_VERSION) {

		/*
		 * If the receive buffer is not yet allocated, this is
		 * probably the first MAD received for the receive context.
		 * We need to set up the receive buffer before calling
		 * ibmf_i_send_rmpp() to send an ABORT packet.
		 */
		if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {
			status = ibmf_setup_recvbuf_on_error(msgimplp, madp);
			if (status != IBMF_SUCCESS) {
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L2,
				    ibmf_i_handle_rmpp_err, IBMF_TNF_ERROR, "",
				    "ibmf_i_handle_rmpp(): %s\n", tnf_string,
				    msg,
				    "ibmf_setup_recvbuf_on_error() failed");
				return;
			}
		}

		/*
		 * Drop the message if the transaction has not yet
		 * been identified as a send or receive RMPP transaction.
		 * This is because the send completion of an abort packet
		 * will hit the non-rmpp code which attempts to reset the
		 * RESP timer set after sending the abort packet, causing
		 * an assert.
		 */
		if (((msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP) == 0) &&
		    (msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP) == 0) {
			/*
			 * Reset the response timer since we're still
			 * waiting for the first response MAD, provided
			 * that the send completion has occured
			 */
			if (msgimplp->im_trans_state_flags &
			    IBMF_TRANS_STATE_FLAG_SEND_DONE) {
				ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp,
				    IBMF_RESP_TIMER);
			}

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_handle_rmpp, IBMF_TNF_TRACE, "",
			    "ibmf_i_handle_rmpp(): %s\n", tnf_string, msg,
			    "BAD version detected, dropping MAD");

			return;
		}

		/* abort with status BadT */
		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
		    IBMF_RMPP_STATUS_UNV, 0, 0, IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L2,
			    ibmf_i_handle_rmpp_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_handle_rmpp(): %s\n", tnf_string, msg,
			    "RMPP ABORT send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_handle_rmpp, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_rmpp(): %s\n", tnf_string, msg,
		    "Unsupported RMPP version detected, sending ABORT UNV");

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_rmpp_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_rmpp() exit\n");

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

		ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);

		return;
	}

	/*
	 * Check for a valid status in the RMPP header
	 */
	if (ibmf_i_is_valid_rmpp_status(rmpp_hdr) != B_TRUE) {

		/*
		 * If the receive buffer is not yet allocated, this is
		 * probably the first MAD received for the receive context.
		 * We need to set up the receive buffer before calling
		 * ibmf_i_send_rmpp() to send an ABORT packet.
		 */
		if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {
			status = ibmf_setup_recvbuf_on_error(msgimplp, madp);
			if (status != IBMF_SUCCESS) {
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L2,
				    ibmf_i_handle_rmpp_err, IBMF_TNF_ERROR, "",
				    "ibmf_i_handle_rmpp(): %s\n", tnf_string,
				    msg,
				    "ibmf_setup_recvbuf_on_error() failed");
				return;
			}
		}

		/*
		 * Drop the message if the transaction has not yet
		 * been identified as a send or receive RMPP transaction.
		 * This is because the send completion of an abort packet
		 * will hit the non-rmpp code which attempts to reset the
		 * RESP timer set after sending the abort packet, causing
		 * an assert.
		 */
		if (((msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP) == 0) &&
		    (msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP) == 0) {
			/*
			 * Reset the response timer since we're still
			 * waiting for the first response MAD, provided
			 * that the send completion has occured
			 */
			if (msgimplp->im_trans_state_flags &
			    IBMF_TRANS_STATE_FLAG_SEND_DONE) {
				ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp,
				    IBMF_RESP_TIMER);
			}

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_handle_rmpp, IBMF_TNF_TRACE, "",
			    "ibmf_i_handle_rmpp(): %s\n", tnf_string, msg,
			    "Invalid RMPP status detected, dropping MAD");

			return;
		}

		/* abort with status BadT */
		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_ABORT,
		    IBMF_RMPP_STATUS_IS, 0, 0, IBMF_NO_BLOCK);
		if (status != IBMF_SUCCESS) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L2,
			    ibmf_i_handle_rmpp_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_handle_rmpp(): %s\n", tnf_string, msg,
			    "RMPP ABORT send failed");
			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_SEND_DONE;
		}

		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, rmpp_errors, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_handle_rmpp, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_rmpp(): %s\n", tnf_string, msg,
		    "Invalid RMPP status detected, sending ABORT IS");

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_rmpp_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_rmpp() exit\n");

		rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_ABORT;

		ibmf_i_unset_timer(msgimplp, IBMF_TRANS_TIMER);

		ibmf_i_set_timer(ibmf_i_err_terminate_timeout,
		    msgimplp, IBMF_RESP_TIMER);

		return;
	}

	/*
	 * We could check the MAD here and do an optional abort.
	 * This abort if the MAD header is bad is not required by the spec.
	 * Also, we should account for RRespTime here.
	 */

	/*
	 * The RMPP engine has four execution flow paths corresponding
	 * to the four states the RMPP state machine can be in at any
	 * given time.  The packet will be dropped if the context is not in any
	 * of these four states.
	 */
	switch (rmpp_ctx->rmpp_state) {
	case IBMF_RMPP_STATE_SENDER_ACTIVE :
		ibmf_i_rmpp_sender_active_flow(clientp, qp_hdl, msgimplp, madp);
		break;
	case IBMF_RMPP_STATE_SENDER_SWITCH :
		ibmf_i_rmpp_sender_switch_flow(clientp, qp_hdl, msgimplp, madp);
		break;
	case IBMF_RMPP_STATE_RECEVR_ACTIVE :
		ibmf_i_rmpp_recvr_active_flow(clientp, qp_hdl, msgimplp, madp);
		break;
	case IBMF_RMPP_STATE_RECEVR_TERMINATE :
		ibmf_i_rmpp_recvr_term_flow(clientp, qp_hdl, msgimplp, madp);
		break;
	default:
		/* Including IBMF_RMPP_STATE_ABORT */
		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_i_handle_rmpp, IBMF_TNF_TRACE, "",
		    "ibmf_i_handle_rmpp(): %s, rmpp_state = 0x%x\n",
		    tnf_string, msg, "Dropping packet",
		    tnf_opaque, rmpp_state, rmpp_ctx->rmpp_state);

		/* Reinitiate the resp timer if the state is ABORT */
		if (rmpp_ctx->rmpp_state == IBMF_RMPP_STATE_ABORT) {
			ibmf_i_set_timer(ibmf_i_err_terminate_timeout, msgimplp,
			    IBMF_RESP_TIMER);

			return;
		}

		/*
		 * Drop the message if the transaction has not yet
		 * been identified as a send or receive RMPP transaction.
		 */
		if (((msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP) == 0) &&
		    (msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP) == 0) {
			/*
			 * Reset the response timer since we're still
			 * waiting for the first response MAD, provided
			 * that the send completion has occured
			 */
			if (msgimplp->im_trans_state_flags &
			    IBMF_TRANS_STATE_FLAG_SEND_DONE) {
				ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp,
				    IBMF_RESP_TIMER);
			}

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_handle_rmpp, IBMF_TNF_TRACE, "",
			    "ibmf_i_handle_rmpp(): %s\n", tnf_string, msg,
			    "BAD 1st RMPP packet, dropping MAD");

			return;
		}
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_handle_rmpp_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_handle_rmpp() exit\n");
}

/*
 * ibmf_i_send_rmpp():
 * ibmf_i_send_rmpp() is called to send any
 * type RMPP packet. The RMPP status is passed in as an argument.
 * In addition, the segment field and the payload length / new window last
 * field are passed in as arguments.
 */
int
ibmf_i_send_rmpp(ibmf_msg_impl_t *msgimplp, uint8_t rmpp_type,
    uint8_t rmpp_status, uint32_t segno, uint32_t nwl, int block)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	int		status;

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_send_rmpp_start,
	    IBMF_TNF_TRACE, "",
	    "ibmf_i_send_rmpp(): msgp = 0x%p, rmpp_type = 0x%x, "
	    "rmpp_status = %d, segno = %d, nwl = %d\n",
	    tnf_opaque, msg, msgimplp,
	    tnf_uint, rmpp_type, rmpp_type,
	    tnf_uint, rmpp_status, rmpp_status,
	    tnf_uint, segno, segno,
	    tnf_uint, nwl, nwl);

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_send_rmpp,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_rmpp(): msgp = 0x%p, "
	    "next_seg = 0x%x, num_pkts = %d\n",
	    tnf_opaque, msg, msgimplp,
	    tnf_uint, next_seg, msgimplp->im_rmpp_ctx.rmpp_ns,
	    tnf_uint, num_pkts, msgimplp->im_rmpp_ctx.rmpp_num_pkts);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	rmpp_ctx->rmpp_type = rmpp_type;
	rmpp_ctx->rmpp_status = rmpp_status;
	rmpp_ctx->rmpp_word3 = segno;
	rmpp_ctx->rmpp_word4 = nwl;

	/*
	 * send packet without blocking
	 */
	status = ibmf_i_send_pkt(msgimplp->im_client, msgimplp->im_qp_hdl,
	    msgimplp, block);
	if (status != IBMF_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_send_rmpp_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_send_rmpp(): %s, status = %d\n", tnf_string, msg,
		    "unable to send packet", tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_rmpp_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_send_rmpp() exit\n");
		return (status);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_rmpp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_rmpp() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_send_rmpp_window():
 *	Send an RMPP protocol window of packets
 */
void
ibmf_i_send_rmpp_window(ibmf_msg_impl_t *msgimplp, int block)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	int status, i, numpkts = rmpp_ctx->rmpp_wl - rmpp_ctx->rmpp_ns + 1;
	uint32_t	payload_length, cl_hdr_sz, cl_hdr_off;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_send_rmpp_window_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_rmpp_window(): msgp = 0x%p\n",
	    tnf_opaque, msg, msgimplp);

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_send_rmpp_window,
	    IBMF_TNF_TRACE, "", "ibmf_i_handle_rmpp(): wl = %d "
	    "ns = %d, num_pkts = %d\n", tnf_uint, wl, rmpp_ctx->rmpp_wl,
	    tnf_uint, ns, rmpp_ctx->rmpp_ns, tnf_uint, num_pkts,
	    rmpp_ctx->rmpp_num_pkts);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	ibmf_i_mgt_class_to_hdr_sz_off(
	    msgimplp->im_msgbufs_send.im_bufs_mad_hdr->MgmtClass,
	    &cl_hdr_sz, &cl_hdr_off);

	for (i = 1; i <= numpkts; i++) {

		if (rmpp_ctx->rmpp_ns == 1)
			payload_length = rmpp_ctx->rmpp_pyld_len +
			    (rmpp_ctx->rmpp_num_pkts * cl_hdr_sz);
		else if (rmpp_ctx->rmpp_ns == rmpp_ctx->rmpp_num_pkts)
			payload_length = rmpp_ctx->rmpp_last_pkt_sz + cl_hdr_sz;
		else
			payload_length = rmpp_ctx->rmpp_pkt_data_sz;

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_send_rmpp_window,
		    IBMF_TNF_TRACE, "", "ibmf_i_handle_rmpp(): ns = %d, "
		    "pl = %d\n", tnf_uint, ns, rmpp_ctx->rmpp_ns,
		    tnf_uint, pl, payload_length);

		status = ibmf_i_send_rmpp(msgimplp, IBMF_RMPP_TYPE_DATA,
		    IBMF_RMPP_STATUS_NORMAL, rmpp_ctx->rmpp_ns, payload_length,
		    block);
		if (status != IBMF_SUCCESS) {

			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_send_rmpp_window_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_send_rmpp_window(): %s\n", tnf_string, msg,
			    "Send rmpp window failed");
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_send_rmpp_window_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_send_rmpp_window() exit\n");
			return;
		}

		rmpp_ctx->rmpp_ns++;

		rmpp_ctx->rmpp_data_offset += rmpp_ctx->rmpp_pkt_data_sz;
	}

	/* Set the response timer */
	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_send_rmpp_window,
	    IBMF_TNF_TRACE, "", "ibmf_i_handle_rmpp(): setting timer %p %d\n",
	    tnf_opaque, msgimplp, msgimplp, tnf_opaque, timeout_id,
	    msgimplp->im_rp_timeout_id);

	ibmf_i_set_timer(ibmf_i_send_timeout, msgimplp, IBMF_RESP_TIMER);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_rmpp_window_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_rmpp_window() exit\n");
}

/*
 * ibmf_i_send_rmpp_pkts():
 *	Send a message using the RMPP protocol
 */
int
ibmf_i_send_rmpp_pkts(ibmf_client_t *clientp, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_msg_impl_t *msgimplp, boolean_t isDS, int block)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	size_t		buf_sz = msgimplp->im_msgbufs_send.im_bufs_cl_data_len;
	uint32_t	num_pkts, resid;
	uint32_t	cl_hdr_sz, cl_data_sz, cl_hdr_off;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_send_rmpp_pkts_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_rmpp_pkts(): clientp = 0x%p, "
	    "qphdl = 0x%p, msgp = 0x%p, block = %d\n",
	    tnf_opaque, clientp, clientp, tnf_opaque, qphdl, ibmf_qp_handle,
	    tnf_opaque, msg, msgimplp, tnf_uint, block, block);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	ibmf_i_mgt_class_to_hdr_sz_off(
	    msgimplp->im_msgbufs_send.im_bufs_mad_hdr->MgmtClass,
	    &cl_hdr_sz, &cl_hdr_off);

	cl_data_sz = MAD_SIZE_IN_BYTES - sizeof (ib_mad_hdr_t) - cl_hdr_off -
	    cl_hdr_sz;

	if ((resid = (buf_sz % cl_data_sz)) != 0)
		num_pkts = (buf_sz / cl_data_sz) + 1;
	else {
		if (buf_sz > 0)
			num_pkts = buf_sz / cl_data_sz;
		else
			num_pkts = 1;
	}

	rmpp_ctx->rmpp_wf = 1;
	rmpp_ctx->rmpp_wl = 1;
	rmpp_ctx->rmpp_ns = 1;
	rmpp_ctx->rmpp_is_ds = isDS;
	rmpp_ctx->rmpp_pyld_len = buf_sz;
	rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_SENDER_ACTIVE;
	rmpp_ctx->rmpp_type = IBMF_RMPP_TYPE_DATA;
	rmpp_ctx->rmpp_respt = IBMF_RMPP_TERM_RRESPT;
	rmpp_ctx->rmpp_status = IBMF_RMPP_STATUS_NORMAL;
	rmpp_ctx->rmpp_num_pkts = num_pkts;
	rmpp_ctx->rmpp_pkt_data_sz =
	    (buf_sz < cl_data_sz) ? buf_sz : cl_data_sz;
	rmpp_ctx->rmpp_last_pkt_sz =
	    (resid == 0) ? ((buf_sz == 0) ? 0 : cl_data_sz) : resid;
	rmpp_ctx->rmpp_data_offset = 0;

	ibmf_i_send_rmpp_window(msgimplp, block);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_send_rmpp_pkts_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_send_rmpp_pkts() exit\n");

	return (IBMF_SUCCESS);
}

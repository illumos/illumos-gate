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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/sunddi.h>
#include <sys/sdt.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibtl_types.h>

#include <sys/ib/clients/iser/iser.h>

/*
 * iser_cq.c
 *    Routines for completion queue handlers for iSER.
 */
static void iser_msg_handle(iser_chan_t *chan, iser_msg_t *msg);
int iser_iscsihdr_handle(iser_chan_t *chan, iser_msg_t *msg);
static int iser_ib_poll_send_completions(ibt_cq_hdl_t cq_hdl,
    iser_chan_t *iser_chan);
static int iser_ib_poll_recv_completions(ibt_cq_hdl_t cq_hdl,
    iser_chan_t *iser_chan);

void
iser_ib_sendcq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	iser_chan_t	*iser_chan;
	ibt_status_t	status;

	iser_chan = (iser_chan_t *)arg;

	/*
	 * Poll for work request completion while successful. If the
	 * queue empties or otherwise becomes invalid, stop polling.
	 */
	do {
		status = iser_ib_poll_send_completions(cq_hdl, iser_chan);
	} while (status == IBT_SUCCESS);

	if (status == IBT_CQ_EMPTY) {
		/* We've emptied the CQ, rearm it before we're done here */
		status = ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION);
		if (status != IBT_SUCCESS) {
			/* Unexpected error */
			ISER_LOG(CE_NOTE, "iser_ib_sendcq_handler: "
			    "ibt_enable_cq_notify error (%d)", status);
			return;
		}

		/* Now, check for more completions after the rearm */
		do {
			status = iser_ib_poll_send_completions(
			    cq_hdl, iser_chan);
		} while (status == IBT_SUCCESS);
	}
}

static int
iser_ib_poll_send_completions(ibt_cq_hdl_t cq_hdl, iser_chan_t *iser_chan)
{
	ibt_wc_t	wc[ISER_IB_SCQ_POLL_MAX];
	ibt_wrid_t	wrid;
	idm_buf_t	*idb = NULL;
	idm_task_t	*idt = NULL;
	iser_wr_t	*wr = NULL;
	int		i;
	uint_t		npoll = 0;
	ibt_status_t	status;
	iser_conn_t	*iser_conn;
	idm_status_t	idm_status;
	iser_mr_t	*mr;

	iser_conn = iser_chan->ic_conn;

	/* Poll ISER_IB_SCQ_POLL_MAX completions from the CQ */
	status = ibt_poll_cq(cq_hdl, wc, ISER_IB_SCQ_POLL_MAX, &npoll);

	if (status != IBT_SUCCESS) {
		if (status != IBT_CQ_EMPTY) {
			/* Unexpected error */
			ISER_LOG(CE_NOTE, "iser_ib_sendcq_handler: ibt_poll_cq "
			    "unexpected error (%d)", status);
		}
		/* CQ is empty. Either way, move along... */
		return (status);
	}

	/*
	 * Handle each of the completions we've polled
	 */
	for (i = 0; i < npoll; i++) {

		DTRACE_PROBE3(iser__send__cqe, iser_chan_t *, iser_chan,
		    ibt_wc_t *, &wc[i], ibt_wc_status_t, wc[i].wc_status);

		/* Grab the wrid of the completion */
		wrid = wc[i].wc_id;

		/* Decrement this channel's SQ posted count */
		mutex_enter(&iser_chan->ic_sq_post_lock);
		iser_chan->ic_sq_post_count--;
		mutex_exit(&iser_chan->ic_sq_post_lock);

		/* Pull in the wr handle */
		wr = (iser_wr_t *)(uintptr_t)wrid;
		ASSERT(wr != NULL);

		/* Set an idm_status for return to IDM */
		idm_status = (wc[i].wc_status == IBT_WC_SUCCESS) ?
		    IDM_STATUS_SUCCESS : IDM_STATUS_FAIL;

		/*
		 * A non-success status here indicates the QP went
		 * into an error state while this WR was being
		 * processed. This can also happen when the
		 * channel is closed on the remote end. Clean up
		 * the resources, then push CE_TRANSPORT_FAIL
		 * into IDM.
		 */
		if (wc[i].wc_status != IBT_WC_SUCCESS) {
			/*
			 * Free the resources attached to this
			 * completion.
			 */
			if (wr->iw_msg != NULL) {
				/* Free iser_msg handle */
				iser_msg_free(wr->iw_msg);
			}

			if (wr->iw_pdu != NULL) {
				/* Complete the PDU */
				idm_pdu_complete(wr->iw_pdu, idm_status);
			}

			if (wr->iw_buf != NULL) {
				/* Invoke buffer callback */
				idb = wr->iw_buf;
				mr = ((iser_buf_t *)
				    idb->idb_buf_private)->iser_mr;
#ifdef DEBUG
				bcopy(&wc[i],
				    &((iser_buf_t *)idb->idb_buf_private)->
				    buf_wc, sizeof (ibt_wc_t));
#endif
				idt = idb->idb_task_binding;
				mutex_enter(&idt->idt_mutex);
				if (wr->iw_type == ISER_WR_RDMAW) {
					DTRACE_ISCSI_8(xfer__done,
					    idm_conn_t *, idt->idt_ic,
					    uintptr_t, idb->idb_buf,
					    uint32_t, idb->idb_bufoffset,
					    uint64_t, mr->is_mrva, uint32_t, 0,
					    uint32_t, mr->is_mrrkey,
					    uint32_t, idb->idb_xfer_len,
					    int, XFER_BUF_TX_TO_INI);
					idm_buf_tx_to_ini_done(idt, idb,
					    IDM_STATUS_FAIL);
				} else { /* ISER_WR_RDMAR */
					DTRACE_ISCSI_8(xfer__done,
					    idm_conn_t *, idt->idt_ic,
					    uintptr_t, idb->idb_buf,
					    uint32_t, idb->idb_bufoffset,
					    uint64_t, mr->is_mrva, uint32_t, 0,
					    uint32_t, mr->is_mrrkey,
					    uint32_t, idb->idb_xfer_len,
					    int, XFER_BUF_RX_FROM_INI);
					idm_buf_rx_from_ini_done(idt, idb,
					    IDM_STATUS_FAIL);
				}
			}

			/* Free the iser wr handle */
			iser_wr_free(wr);

			/*
			 * Tell IDM that the channel has gone down,
			 * unless it already knows.
			 */
			mutex_enter(&iser_conn->ic_lock);
			switch (iser_conn->ic_stage) {
			case ISER_CONN_STAGE_IC_DISCONNECTED:
			case ISER_CONN_STAGE_IC_FREED:
			case ISER_CONN_STAGE_CLOSING:
			case ISER_CONN_STAGE_CLOSED:
				break;

			default:
				idm_conn_event(iser_conn->ic_idmc,
				    CE_TRANSPORT_FAIL, idm_status);
				iser_conn->ic_stage = ISER_CONN_STAGE_CLOSING;
			}
			mutex_exit(&iser_conn->ic_lock);

			/* Move onto the next completion */
			continue;
		}

		/*
		 * For a success status, just invoke the PDU or
		 * buffer completion. We use our WR handle's
		 * "iw_type" here so that we can properly process
		 * because the CQE's opcode is invalid if the status
		 * is failed.
		 */
		switch (wr->iw_type) {
		case ISER_WR_SEND:
			/* Free the msg handle */
			ASSERT(wr->iw_msg != NULL);
			iser_msg_free(wr->iw_msg);

			if (wr->iw_pdu == NULL) {
				/* This is a hello exchange message */
				mutex_enter(&iser_conn->ic_lock);
				if (iser_conn->ic_stage ==
				    ISER_CONN_STAGE_HELLOREPLY_SENT) {
					/*
					 * We're on the target side,
					 * and have just successfully
					 * sent the HelloReply msg.
					 */
					iser_conn->ic_stage =
					    ISER_CONN_STAGE_LOGGED_IN;
				}
				mutex_exit(&iser_conn->ic_lock);
			} else {
				/* This is a normal control message */
				idm_pdu_complete(wr->iw_pdu, idm_status);
			}

			/* Free the wr handle */
			iser_wr_free(wr);

			break;

		case ISER_WR_RDMAW:
		case ISER_WR_RDMAR:
			/*
			 * Invoke the appropriate callback;
			 * the buffer will be freed there.
			 */
			idb = wr->iw_buf;
			mr = ((iser_buf_t *)idb->idb_buf_private)->iser_mr;
#ifdef DEBUG
			bcopy(&wc[i],
			    &((iser_buf_t *)idb->idb_buf_private)->buf_wc,
			    sizeof (ibt_wc_t));
#endif
			idt = idb->idb_task_binding;

			mutex_enter(&idt->idt_mutex);
			if (wr->iw_type == ISER_WR_RDMAW) {
				DTRACE_ISCSI_8(xfer__done,
				    idm_conn_t *, idt->idt_ic,
				    uintptr_t, idb->idb_buf,
				    uint32_t, idb->idb_bufoffset,
				    uint64_t, mr->is_mrva, uint32_t, 0,
				    uint32_t, mr->is_mrrkey,
				    uint32_t, idb->idb_xfer_len,
				    int, XFER_BUF_TX_TO_INI);
				idm_buf_tx_to_ini_done(idt, idb, idm_status);
			} else {
				DTRACE_ISCSI_8(xfer__done,
				    idm_conn_t *, idt->idt_ic,
				    uintptr_t, idb->idb_buf,
				    uint32_t, idb->idb_bufoffset,
				    uint64_t, mr->is_mrva, uint32_t, 0,
				    uint32_t, mr->is_mrrkey,
				    uint32_t, idb->idb_xfer_len,
				    int, XFER_BUF_RX_FROM_INI);
				idm_buf_rx_from_ini_done(idt, idb, idm_status);
			}

			/* Free the wr handle */
			iser_wr_free(wr);

			break;

		default:
			ASSERT(0);
			break;
		}
	}

	return (status);
}

void
iser_ib_recvcq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	iser_chan_t	*iser_chan;
	ibt_status_t	status;

	iser_chan = (iser_chan_t *)arg;

	/*
	 * Poll for work request completion while successful. If the
	 * queue empties or otherwise becomes invalid, stop polling.
	 */
	do {
		status = iser_ib_poll_recv_completions(cq_hdl, iser_chan);
	} while (status == IBT_SUCCESS);

	if (status == IBT_CQ_EMPTY) {
		/* We've emptied the CQ, rearm it before we're done here */
		status = ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION);
		if (status != IBT_SUCCESS) {
			/* Unexpected error */
			ISER_LOG(CE_NOTE, "iser_ib_recvcq_handler: "
			    "ibt_enable_cq_notify error (%d)", status);
			return;
		}

		/* Now, check for more completions after the rearm */
		do {
			status = iser_ib_poll_recv_completions(
			    cq_hdl, iser_chan);
		} while (status == IBT_SUCCESS);
	}
}

static int
iser_ib_poll_recv_completions(ibt_cq_hdl_t cq_hdl, iser_chan_t *iser_chan)
{
	ibt_wc_t	wc;
	iser_msg_t	*msg;
	iser_qp_t	*iser_qp;
	int		status;

	iser_qp = &(iser_chan->ic_qp);

	bzero(&wc, sizeof (ibt_wc_t));
	status = ibt_poll_cq(cq_hdl, &wc, 1, NULL);
	if (status == IBT_CQ_EMPTY) {
		/* CQ is empty, return */
		return (status);
	}

	if (status != IBT_SUCCESS) {
		/* Unexpected error */
		ISER_LOG(CE_NOTE, "iser_ib_poll_recv_completions: "
		    "ibt_poll_cq error (%d)", status);
		mutex_enter(&iser_qp->qp_lock);
		iser_qp->rq_level--;
		mutex_exit(&iser_qp->qp_lock);
		/* Free the msg handle (if we got it back) */
		if ((msg = (iser_msg_t *)(uintptr_t)wc.wc_id) != NULL) {
			iser_msg_free(msg);
		}
		return (status);
	}

	/* Retrieve the iSER msg handle */
	msg = (iser_msg_t *)(uintptr_t)wc.wc_id;
	ASSERT(msg != NULL);

	/*
	 * Decrement the posted level in the RQ, then check
	 * to see if we need to fill the RQ back up (or if
	 * we are already on the taskq).
	 */
	mutex_enter(&iser_chan->ic_conn->ic_lock);
	mutex_enter(&iser_qp->qp_lock);
	iser_qp->rq_level--;

	if ((iser_qp->rq_taskqpending == B_FALSE) &&
	    (iser_qp->rq_level <= iser_qp->rq_lwm) &&
	    (iser_chan->ic_conn->ic_stage >= ISER_CONN_STAGE_IC_CONNECTED) &&
	    (iser_chan->ic_conn->ic_stage <= ISER_CONN_STAGE_LOGGED_IN)) {
		/* Set the pending flag and fire off a post_recv */
		iser_qp->rq_taskqpending = B_TRUE;
		mutex_exit(&iser_qp->qp_lock);

		status = iser_ib_post_recv_async(iser_chan->ic_chanhdl);

		if (status != DDI_SUCCESS) {
			ISER_LOG(CE_NOTE, "iser_ib_poll_recv_completions: "
			    "task dispatch failed");
			/* Failure to launch, unset the pending flag */
			mutex_enter(&iser_qp->qp_lock);
			iser_qp->rq_taskqpending = B_FALSE;
			mutex_exit(&iser_qp->qp_lock);
		}
	} else {
		mutex_exit(&iser_qp->qp_lock);
	}

	DTRACE_PROBE3(iser__recv__cqe, iser_chan_t *, iser_chan,
	    ibt_wc_t *, &wc, ibt_wc_status_t, wc.wc_status);
	if (wc.wc_status != IBT_WC_SUCCESS) {
		/*
		 * Tell IDM that the channel has gone down,
		 * unless it already knows.
		 */
		switch (iser_chan->ic_conn->ic_stage) {
		case ISER_CONN_STAGE_IC_DISCONNECTED:
		case ISER_CONN_STAGE_IC_FREED:
		case ISER_CONN_STAGE_CLOSING:
		case ISER_CONN_STAGE_CLOSED:
			break;

		default:
			idm_conn_event(iser_chan->ic_conn->ic_idmc,
			    CE_TRANSPORT_FAIL, IDM_STATUS_FAIL);
			iser_chan->ic_conn->ic_stage =
			    ISER_CONN_STAGE_CLOSING;
		}
		mutex_exit(&iser_chan->ic_conn->ic_lock);

		iser_msg_free(msg);
		return (DDI_SUCCESS);
	} else {
		mutex_exit(&iser_chan->ic_conn->ic_lock);

		/*
		 * We have an iSER message in, let's handle it.
		 * We will free the iser_msg_t later in this path,
		 * depending upon the action required.
		 */
		iser_msg_handle(iser_chan, msg);
		return (DDI_SUCCESS);
	}
}

static void
iser_msg_handle(iser_chan_t *chan, iser_msg_t *msg)
{
	int		opcode;
	iser_ctrl_hdr_t	*hdr = NULL;
	iser_conn_t	*iser_conn = chan->ic_conn;
	int		status;

	hdr = (iser_ctrl_hdr_t *)(uintptr_t)msg->msg_ds.ds_va;
	ASSERT(hdr != NULL);

	opcode = hdr->opcode;
	if (opcode == ISER_OPCODE_CTRL_TYPE_PDU) {
		/*
		 * Handle an iSCSI Control PDU iSER message.
		 * Note we'll free the msg handle in the PDU callback.
		 */
		status = iser_iscsihdr_handle(chan, msg);
		if (status != DDI_SUCCESS) {
			/*
			 * We are unable to handle this message, and
			 * have no way to recover from this.  Fail the
			 * transport.
			 */
			ISER_LOG(CE_NOTE, "iser_msg_handle: failed "
			    "iser_iscsihdr_handle");
			iser_msg_free(msg);
			idm_conn_event(iser_conn->ic_idmc,
			    CE_TRANSPORT_FAIL, IDM_STATUS_FAIL);
		}
	} else if (opcode == ISER_OPCODE_HELLO_MSG) { /* at the target */
		/*
		 * We are currently not supporting Hello Exchange,
		 * since OFED iSER does not. May be revisited.
		 */
		ASSERT(opcode != ISER_OPCODE_HELLO_MSG);

		if (iser_conn->ic_type != ISER_CONN_TYPE_TGT) {
			idm_conn_event(iser_conn->ic_idmc,
			    CE_TRANSPORT_FAIL, IDM_STATUS_FAIL);
		}

		iser_hello_hdr_t *hello_hdr = (iser_hello_hdr_t *)hdr;

		ISER_LOG(CE_NOTE, "received Hello message: opcode[%d], "
		    "maxver[%d], minver[%d], iser_ird[%d], msg (0x%p)",
		    hello_hdr->opcode, hello_hdr->maxver, hello_hdr->minver,
		    ntohs(hello_hdr->iser_ird), (void *)msg);

		mutex_enter(&iser_conn->ic_lock);

		if (iser_conn->ic_stage != ISER_CONN_STAGE_HELLO_WAIT) {
			/* target is not expected to receive a Hello */
			idm_conn_event(iser_conn->ic_idmc,
			    CE_TRANSPORT_FAIL, IDM_STATUS_FAIL);
		}

		iser_conn->ic_stage = ISER_CONN_STAGE_HELLOREPLY_SENT;
		mutex_exit(&iser_conn->ic_lock);

		/* Prepare and send a HelloReply message */
		status = iser_xfer_helloreply_msg(chan);
		if (status != ISER_STATUS_SUCCESS) {

			mutex_enter(&iser_conn->ic_lock);
			iser_conn->ic_stage =
			    ISER_CONN_STAGE_HELLOREPLY_SENT_FAIL;
			mutex_exit(&iser_conn->ic_lock);

			idm_conn_event(iser_conn->ic_idmc,
			    CE_TRANSPORT_FAIL, status);
		}

		/* Free this msg handle */
		iser_msg_free(msg);

	} else if (opcode == ISER_OPCODE_HELLOREPLY_MSG) { /* at initiator */

		/*
		 * We are currently not supporting Hello Exchange,
		 * since OFED iSER does not. May be revisited.
		 */
		ASSERT(opcode != ISER_OPCODE_HELLOREPLY_MSG);

		if (iser_conn->ic_type != ISER_CONN_TYPE_INI) {
			idm_conn_event(iser_conn->ic_idmc,
			    CE_TRANSPORT_FAIL, status);
		}

		iser_helloreply_hdr_t *hello_hdr = (iser_helloreply_hdr_t *)hdr;

		ISER_LOG(CE_NOTE, "received Hello Reply message: opcode[%d], "
		    "maxver[%d], curver[%d], iser_ord[%d], msg (0x%p)",
		    hello_hdr->opcode, hello_hdr->maxver, hello_hdr->curver,
		    ntohs(hello_hdr->iser_ord), (void *)msg);

		/* Free this msg handle */
		iser_msg_free(msg);

		/*
		 * Signal the receipt of HelloReply to the waiting thread
		 * so that the initiator can proceed to the Full Feature
		 * Phase.
		 */
		mutex_enter(&iser_conn->ic_lock);
		iser_conn->ic_stage = ISER_CONN_STAGE_HELLOREPLY_RCV;
		cv_signal(&iser_conn->ic_stage_cv);
		mutex_exit(&iser_conn->ic_lock);
	} else {
		/* Protocol error: free the msg handle and fail the session */
		ISER_LOG(CE_NOTE, "iser_msg_handle: unsupported opcode (0x%x): "
		    "terminating session on IDM handle (0x%p)", opcode,
		    (void *) iser_conn->ic_idmc);

		iser_msg_free(msg);
		idm_conn_event(iser_conn->ic_idmc, CE_TRANSPORT_FAIL,
		    IDM_STATUS_FAIL);
	}
}

#define	IDM_PDU_OPCODE(PDU) \
	((PDU)->isp_hdr->opcode & ISCSI_OPCODE_MASK)

/* network to host translation for 24b integers */
static uint32_t
n2h24(uchar_t *ptr)
{
	return ((ptr[0] << 16) | (ptr[1] << 8) | ptr[2]);
}

/* ARGSUSED */
static void
iser_rx_pdu_cb(idm_pdu_t *pdu, idm_status_t status)
{
	/* Free the iser msg handle and the PDU handle */
	iser_msg_free((iser_msg_t *)pdu->isp_transport_private);
	idm_pdu_free(pdu);
}

int
iser_iscsihdr_handle(iser_chan_t *chan, iser_msg_t *msg)
{
	idm_pdu_t	*pdu;
	uint8_t		*iser_hdrp;
	uint8_t		*iscsi_hdrp;
	iscsi_hdr_t	*bhs;

	pdu = idm_pdu_alloc_nosleep(sizeof (iscsi_hdr_t), 0);
	pdu->isp_ic = chan->ic_conn->ic_idmc;
	ASSERT(pdu->isp_ic != NULL);

	/* Set the iser_msg handle into the transport-private field */
	pdu->isp_transport_private = (void *)msg;

	/* Set up a pointer in the pdu handle to the iSER header */
	iser_hdrp = (uint8_t *)(uintptr_t)msg->msg_ds.ds_va;
	if (iser_hdrp == NULL) {
		ISER_LOG(CE_NOTE, "iser_iscsihdr_handle: iser_hdrp is NULL");
		idm_pdu_free(pdu);
		return (ISER_STATUS_FAIL);
	}
	pdu->isp_transport_hdr = (void *)iser_hdrp;
	pdu->isp_transport_hdrlen = ISER_HEADER_LENGTH;

	/*
	 * Set up a pointer to the iSCSI header, which is directly
	 * after the iSER header in the message.
	 */
	iscsi_hdrp = ((uint8_t *)(uintptr_t)msg->msg_ds.ds_va) +
	    ISER_HEADER_LENGTH;
	if (iscsi_hdrp == NULL) {
		ISER_LOG(CE_NOTE, "iser_iscsihdr_handle: iscsi_hdrp is NULL");
		idm_pdu_free(pdu);
		return (ISER_STATUS_FAIL);
	}
	pdu->isp_hdr = (iscsi_hdr_t *)(uintptr_t)iscsi_hdrp;

	/* Fill in the BHS */
	bhs = pdu->isp_hdr;
	pdu->isp_hdrlen	= sizeof (iscsi_hdr_t) +
	    (bhs->hlength * sizeof (uint32_t));
	pdu->isp_datalen = n2h24(bhs->dlength);
	pdu->isp_callback = iser_rx_pdu_cb;

	/*
	 * If datalen > 0, then non-scsi data may be present. Allocate
	 * space in the PDU handle and set a pointer to the data.
	 */
	if (pdu->isp_datalen) {
		pdu->isp_data = ((uint8_t *)(uintptr_t)pdu->isp_hdr) +
		    pdu->isp_hdrlen;
	}

	/* Process RX PDU */
	idm_pdu_rx(pdu->isp_ic, pdu);

	return (DDI_SUCCESS);
}

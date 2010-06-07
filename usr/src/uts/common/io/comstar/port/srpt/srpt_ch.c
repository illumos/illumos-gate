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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * RDMA channel interface for Solaris SCSI RDMA Protocol Target (SRP)
 * transport port provider module for the COMSTAR framework.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>
#include <sys/taskq.h>
#include <sys/scsi/scsi.h>
#include <sys/ib/ibtl/ibti.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>

#include "srp.h"
#include "srpt_impl.h"
#include "srpt_ioc.h"
#include "srpt_stp.h"
#include "srpt_ch.h"

extern srpt_ctxt_t *srpt_ctxt;
extern uint16_t srpt_send_msg_depth;

/*
 * Prototypes.
 */
static void srpt_ch_scq_hdlr(ibt_cq_hdl_t cq_dhl, void *arg);
static void srpt_ch_rcq_hdlr(ibt_cq_hdl_t cq_dhl, void *arg);
static void srpt_ch_process_iu(srpt_channel_t *ch, srpt_iu_t *iu);

/*
 * srpt_ch_alloc()
 */
srpt_channel_t *
srpt_ch_alloc(srpt_target_port_t *tgt, uint8_t port)
{
	ibt_status_t			status;
	srpt_channel_t			*ch;
	ibt_cq_attr_t			cq_attr;
	ibt_rc_chan_alloc_args_t	ch_args;
	uint32_t			cq_real_size;
	srpt_ioc_t			*ioc;

	ASSERT(tgt != NULL);
	ioc = tgt->tp_ioc;
	ASSERT(ioc != NULL);

	ch = kmem_zalloc(sizeof (*ch), KM_SLEEP);
	rw_init(&ch->ch_rwlock, NULL, RW_DRIVER, NULL);
	mutex_init(&ch->ch_reflock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ch->ch_cv_complete, NULL, CV_DRIVER, NULL);
	ch->ch_refcnt	= 1;
	ch->ch_cv_waiters = 0;

	ch->ch_state  = SRPT_CHANNEL_CONNECTING;
	ch->ch_tgt    = tgt;
	ch->ch_req_lim_delta = 0;
	ch->ch_ti_iu_len = 0;

	cq_attr.cq_size	 = srpt_send_msg_depth * 2;
	cq_attr.cq_sched = 0;
	cq_attr.cq_flags = IBT_CQ_NO_FLAGS;

	status = ibt_alloc_cq(ioc->ioc_ibt_hdl, &cq_attr, &ch->ch_scq_hdl,
	    &cq_real_size);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L1("ch_alloc, send CQ alloc error (%d)",
		    status);
		goto scq_alloc_err;
	}

	cq_attr.cq_size	 = srpt_send_msg_depth + 1;
	cq_attr.cq_sched = 0;
	cq_attr.cq_flags = IBT_CQ_NO_FLAGS;

	status = ibt_alloc_cq(ioc->ioc_ibt_hdl, &cq_attr, &ch->ch_rcq_hdl,
	    &cq_real_size);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ch_alloc, receive CQ alloc error (%d)",
		    status);
		goto rcq_alloc_err;
	}

	ibt_set_cq_handler(ch->ch_scq_hdl, srpt_ch_scq_hdlr, ch);
	ibt_set_cq_handler(ch->ch_rcq_hdl, srpt_ch_rcq_hdlr, ch);
	(void) ibt_enable_cq_notify(ch->ch_scq_hdl, IBT_NEXT_COMPLETION);
	(void) ibt_enable_cq_notify(ch->ch_rcq_hdl, IBT_NEXT_COMPLETION);

	ch_args.rc_flags   = IBT_WR_SIGNALED;

	/* Maker certain initiator can not read/write our memory */
	ch_args.rc_control = 0;

	ch_args.rc_hca_port_num = port;

	/*
	 * Any SRP IU can result in a number of STMF data buffer transfers
	 * and those transfers themselves could span multiple initiator
	 * buffers.  Therefore, the number of send WQE's actually required
	 * can vary.  Here we assume that on average an I/O will require
	 * no more than SRPT_MAX_OUT_IO_PER_CMD send WQE's.  In practice
	 * this will prevent send work queue overrun, but we will also
	 * inform STMF to throttle I/O should the work queue become full.
	 *
	 * If the HCA tells us the max outstanding WRs for a channel is
	 * lower than our default, use the HCA value.
	 */
	ch_args.rc_sizes.cs_sq = min(ioc->ioc_attr.hca_max_chan_sz,
	    (srpt_send_msg_depth * SRPT_MAX_OUT_IO_PER_CMD));
	ch_args.rc_sizes.cs_rq =  0;
	ch_args.rc_sizes.cs_sq_sgl = 2;
	ch_args.rc_sizes.cs_rq_sgl = 0;

	ch_args.rc_scq = ch->ch_scq_hdl;
	ch_args.rc_rcq = ch->ch_rcq_hdl;
	ch_args.rc_pd  = ioc->ioc_pd_hdl;
	ch_args.rc_clone_chan = NULL;
	ch_args.rc_srq = ioc->ioc_srq_hdl;

	status = ibt_alloc_rc_channel(ioc->ioc_ibt_hdl, IBT_ACHAN_USES_SRQ,
	    &ch_args, &ch->ch_chan_hdl, &ch->ch_sizes);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ch_alloc, IBT channel alloc error (%d)",
		    status);
		goto qp_alloc_err;
	}

	/*
	 * Create pool of send WQE entries to map send wqe work IDs
	 * to various types (specifically in error cases where OP
	 * is not known).
	 */
	ch->ch_num_swqe = ch->ch_sizes.cs_sq;
	SRPT_DPRINTF_L2("ch_alloc, number of SWQEs = %u", ch->ch_num_swqe);
	ch->ch_swqe = kmem_zalloc(sizeof (srpt_swqe_t) * ch->ch_num_swqe,
	    KM_SLEEP);
	if (ch->ch_swqe == NULL) {
		SRPT_DPRINTF_L2("ch_alloc, SWQE alloc error");
		(void) ibt_free_channel(ch->ch_chan_hdl);
		goto qp_alloc_err;
	}
	mutex_init(&ch->ch_swqe_lock, NULL, MUTEX_DRIVER, NULL);
	ch->ch_head = 1;
	for (ch->ch_tail = 1; ch->ch_tail < ch->ch_num_swqe -1; ch->ch_tail++) {
		ch->ch_swqe[ch->ch_tail].sw_next = ch->ch_tail + 1;
	}
	ch->ch_swqe[ch->ch_tail].sw_next = 0;

	ibt_set_chan_private(ch->ch_chan_hdl, ch);
	return (ch);

qp_alloc_err:
	(void) ibt_free_cq(ch->ch_rcq_hdl);

rcq_alloc_err:
	(void) ibt_free_cq(ch->ch_scq_hdl);

scq_alloc_err:
	cv_destroy(&ch->ch_cv_complete);
	mutex_destroy(&ch->ch_reflock);
	rw_destroy(&ch->ch_rwlock);
	kmem_free(ch, sizeof (*ch));

	return (NULL);
}

/*
 * srpt_ch_add_ref()
 */
void
srpt_ch_add_ref(srpt_channel_t *ch)
{
	mutex_enter(&ch->ch_reflock);
	ch->ch_refcnt++;
	SRPT_DPRINTF_L4("ch_add_ref, ch (%p), refcnt (%d)",
	    (void *)ch, ch->ch_refcnt);
	ASSERT(ch->ch_refcnt != 0);
	mutex_exit(&ch->ch_reflock);
}

/*
 * srpt_ch_release_ref()
 *
 * A non-zero value for wait causes thread to block until all references
 * to channel are released.
 */
void
srpt_ch_release_ref(srpt_channel_t *ch, uint_t wait)
{
	mutex_enter(&ch->ch_reflock);

	SRPT_DPRINTF_L4("ch_release_ref, ch (%p), refcnt (%d), wait (%d)",
	    (void *)ch, ch->ch_refcnt, wait);

	ASSERT(ch->ch_refcnt != 0);

	ch->ch_refcnt--;

	if (ch->ch_refcnt != 0) {
		if (wait) {
			ch->ch_cv_waiters++;
			while (ch->ch_refcnt != 0) {
				cv_wait(&ch->ch_cv_complete, &ch->ch_reflock);
			}
			ch->ch_cv_waiters--;
		} else {
			mutex_exit(&ch->ch_reflock);
			return;
		}
	}

	/*
	 * Last thread out frees the IB resources, locks/conditions and memory
	 */
	if (ch->ch_cv_waiters > 0) {
		/* we're not last, wake someone else up */
		cv_signal(&ch->ch_cv_complete);
		mutex_exit(&ch->ch_reflock);
		return;
	}

	SRPT_DPRINTF_L3("ch_release_ref - release resources");
	if (ch->ch_chan_hdl) {
		SRPT_DPRINTF_L3("ch_release_ref - free channel");
		(void) ibt_free_channel(ch->ch_chan_hdl);
	}

	if (ch->ch_scq_hdl) {
		(void) ibt_free_cq(ch->ch_scq_hdl);
	}

	if (ch->ch_rcq_hdl) {
		(void) ibt_free_cq(ch->ch_rcq_hdl);
	}

	/*
	 * There should be no IU's associated with this
	 * channel on the SCSI session.
	 */
	if (ch->ch_session != NULL) {
		ASSERT(list_is_empty(&ch->ch_session->ss_task_list));

		/*
		 * Currently only have one channel per session, we will
		 * need to release a reference when support is added
		 * for multi-channel target login.
		 */
		srpt_stp_free_session(ch->ch_session);
		ch->ch_session = NULL;
	}

	kmem_free(ch->ch_swqe, sizeof (srpt_swqe_t) * ch->ch_num_swqe);
	mutex_destroy(&ch->ch_swqe_lock);
	mutex_exit(&ch->ch_reflock);
	mutex_destroy(&ch->ch_reflock);
	rw_destroy(&ch->ch_rwlock);
	kmem_free(ch, sizeof (srpt_channel_t));
}

/*
 * srpt_ch_disconnect()
 */
void
srpt_ch_disconnect(srpt_channel_t *ch)
{
	ibt_status_t		status;

	SRPT_DPRINTF_L3("ch_disconnect, invoked for ch (%p)",
	    (void *)ch);

	rw_enter(&ch->ch_rwlock, RW_WRITER);

	/*
	 * If we are already in the process of disconnecting then
	 * nothing need be done, CM will call-back into us when done.
	 */
	if (ch->ch_state == SRPT_CHANNEL_DISCONNECTING) {
		SRPT_DPRINTF_L2("ch_disconnect, called when"
		    " disconnect in progress");
		rw_exit(&ch->ch_rwlock);
		return;
	}
	ch->ch_state = SRPT_CHANNEL_DISCONNECTING;
	rw_exit(&ch->ch_rwlock);

	/*
	 * Initiate the sending of the CM DREQ message, the private data
	 * should be the SRP Target logout IU.  We don't really care about
	 * the remote CM DREP message returned.  We issue this in an
	 * asynchronous manner and will cleanup when called back by CM.
	 */
	status = ibt_close_rc_channel(ch->ch_chan_hdl, IBT_NONBLOCKING,
	    NULL, 0, NULL, NULL, 0);

	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ch_disconnect, close RC channel"
		    " err(%d)", status);
	}
}

/*
 * srpt_ch_cleanup()
 */
void
srpt_ch_cleanup(srpt_channel_t *ch)
{
	srpt_iu_t		*iu;
	srpt_iu_t		*next;
	ibt_wc_t		wc;
	srpt_target_port_t	*tgt;
	srpt_channel_t		*tgt_ch;
	scsi_task_t		*iutask;

	SRPT_DPRINTF_L3("ch_cleanup, invoked for ch(%p), state(%d)",
	    (void *)ch, ch->ch_state);

	/* add a ref for the channel until we're done */
	srpt_ch_add_ref(ch);

	tgt = ch->ch_tgt;
	ASSERT(tgt != NULL);

	/*
	 * Make certain the channel is in the target ports list of
	 * known channels and remove it (releasing the target
	 * ports reference to the channel).
	 */
	mutex_enter(&tgt->tp_ch_list_lock);
	tgt_ch = list_head(&tgt->tp_ch_list);
	while (tgt_ch != NULL) {
		if (tgt_ch == ch) {
			list_remove(&tgt->tp_ch_list, tgt_ch);
			srpt_ch_release_ref(tgt_ch, 0);
			break;
		}
		tgt_ch = list_next(&tgt->tp_ch_list, tgt_ch);
	}
	mutex_exit(&tgt->tp_ch_list_lock);

	if (tgt_ch == NULL) {
		SRPT_DPRINTF_L2("ch_cleanup, target channel no"
		    "longer known to target");
		srpt_ch_release_ref(ch, 0);
		return;
	}

	rw_enter(&ch->ch_rwlock, RW_WRITER);
	ch->ch_state = SRPT_CHANNEL_DISCONNECTING;
	rw_exit(&ch->ch_rwlock);

	/*
	 * Don't accept any further incoming requests, and clean
	 * up the receive queue.  The send queue is left alone
	 * so tasks can finish and clean up (whether normally
	 * or via abort).
	 */
	if (ch->ch_rcq_hdl) {
		ibt_set_cq_handler(ch->ch_rcq_hdl, NULL, NULL);

		while (ibt_poll_cq(ch->ch_rcq_hdl, &wc, 1, NULL) ==
		    IBT_SUCCESS) {
			iu = (srpt_iu_t *)(uintptr_t)wc.wc_id;
			SRPT_DPRINTF_L4("ch_cleanup, recovering"
			    " outstanding RX iu(%p)", (void *)iu);
			mutex_enter(&iu->iu_lock);
			srpt_ioc_repost_recv_iu(iu->iu_ioc, iu);
			/*
			 * Channel reference has not yet been added for this
			 * IU, so do not decrement.
			 */
			mutex_exit(&iu->iu_lock);
		}
	}

	/*
	 * Go through the list of outstanding IU for the channel's SCSI
	 * session and for each either abort or complete an abort.
	 */
	rw_enter(&ch->ch_rwlock, RW_READER);
	if (ch->ch_session != NULL) {
		rw_enter(&ch->ch_session->ss_rwlock, RW_READER);
		iu = list_head(&ch->ch_session->ss_task_list);
		while (iu != NULL) {
			next = list_next(&ch->ch_session->ss_task_list, iu);

			mutex_enter(&iu->iu_lock);
			if (ch == iu->iu_ch) {
				if (iu->iu_stmf_task == NULL) {
					cmn_err(CE_NOTE,
					    "ch_cleanup, NULL stmf task");
					ASSERT(0);
				}
				iutask = iu->iu_stmf_task;
			} else {
				iutask = NULL;
			}
			mutex_exit(&iu->iu_lock);

			if (iutask != NULL) {
				SRPT_DPRINTF_L4("ch_cleanup, aborting "
				    "task(%p)", (void *)iutask);
				stmf_abort(STMF_QUEUE_TASK_ABORT, iutask,
				    STMF_ABORTED, NULL);
			}
			iu = next;
		}
		rw_exit(&ch->ch_session->ss_rwlock);
	}
	rw_exit(&ch->ch_rwlock);

	srpt_ch_release_ref(ch, 0);
}

/*
 * srpt_ch_rsp_comp()
 *
 * Process a completion for an IB SEND message.  A SEND completion
 * is for a SRP response packet sent back to the initiator.  It
 * will not have a STMF SCSI task associated with it if it was
 * sent for a rejected IU, or was a task management abort response.
 */
static void
srpt_ch_rsp_comp(srpt_channel_t *ch, srpt_iu_t *iu,
	ibt_wc_status_t wc_status)
{
	stmf_status_t	st = STMF_SUCCESS;

	ASSERT(iu->iu_ch == ch);

	/*
	 * Process the completion regardless whether it's a failure or
	 * success.  At this point, we've processed as far as we can and
	 * just need to complete the associated task.
	 */

	if (wc_status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ch_rsp_comp, WC status err(%d)",
		    wc_status);

		st = STMF_FAILURE;

		if (wc_status != IBT_WC_WR_FLUSHED_ERR) {
			srpt_ch_disconnect(ch);
		}
	}

	/*
	 * If the IU response completion is not associated with
	 * with a SCSI task, release the IU to return the resource
	 * and the reference to the channel it holds.
	 */
	mutex_enter(&iu->iu_lock);
	atomic_dec_32(&iu->iu_sq_posted_cnt);

	if (iu->iu_stmf_task == NULL) {
		srpt_ioc_repost_recv_iu(iu->iu_ioc, iu);
		mutex_exit(&iu->iu_lock);
		srpt_ch_release_ref(ch, 0);
		return;
	}

	/*
	 * We should not get a SEND completion where the task has already
	 * completed aborting and STMF has been informed.
	 */
	ASSERT((iu->iu_flags & SRPT_IU_ABORTED) == 0);

	/*
	 * Let STMF know we are done.
	 */
	mutex_exit(&iu->iu_lock);

	stmf_send_status_done(iu->iu_stmf_task, st, STMF_IOF_LPORT_DONE);
}

/*
 * srpt_ch_data_comp()
 *
 * Process an IB completion for a RDMA operation.  This completion
 * should be associated with the last RDMA operation for any
 * data buffer transfer.
 */
static void
srpt_ch_data_comp(srpt_channel_t *ch, stmf_data_buf_t *stmf_dbuf,
	ibt_wc_status_t wc_status)
{
	srpt_ds_dbuf_t		*dbuf;
	srpt_iu_t		*iu;
	stmf_status_t		status;

	ASSERT(stmf_dbuf != NULL);

	dbuf = (srpt_ds_dbuf_t *)stmf_dbuf->db_port_private;

	ASSERT(dbuf != NULL);

	iu = dbuf->db_iu;

	ASSERT(iu != NULL);
	ASSERT(iu->iu_ch == ch);

	/*
	 * If work completion indicates non-flush failure, then
	 * start a channel disconnect (asynchronous) and release
	 * the reference to the IU.  The task will be cleaned
	 * up with STMF during channel shutdown processing.
	 */
	if (wc_status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ch_data_comp, WC status err(%d)",
		    wc_status);
		if (wc_status != IBT_WC_WR_FLUSHED_ERR) {
			srpt_ch_disconnect(ch);
		}
		atomic_dec_32(&iu->iu_sq_posted_cnt);
		return;
	}

	/*
	 * If STMF has requested this task be aborted, then if this is the
	 * last I/O operation outstanding, notify STMF the task has been
	 *  aborted and ignore the completion.
	 */
	mutex_enter(&iu->iu_lock);
	atomic_dec_32(&iu->iu_sq_posted_cnt);

	if ((iu->iu_flags & SRPT_IU_STMF_ABORTING) != 0) {
		scsi_task_t	*abort_task = iu->iu_stmf_task;

		mutex_exit(&iu->iu_lock);
		stmf_abort(STMF_REQUEUE_TASK_ABORT_LPORT, abort_task,
		    STMF_ABORTED, NULL);
		return;
	}

	/*
	 * We should not get an RDMA completion where the task has already
	 * completed aborting and STMF has been informed.
	 */
	ASSERT((iu->iu_flags & SRPT_IU_ABORTED) == 0);

	/*
	 * Good completion for last RDMA op associated with a data buffer
	 * I/O, if specified initiate status otherwise let STMF know we are
	 * done.
	 */
	stmf_dbuf->db_xfer_status = STMF_SUCCESS;
	mutex_exit(&iu->iu_lock);

	DTRACE_SRP_8(xfer__done, srpt_channel_t, ch,
	    ibt_wr_ds_t, &(dbuf->db_sge), srpt_iu_t, iu,
	    ibt_send_wr_t, 0, uint32_t, stmf_dbuf->db_data_size,
	    uint32_t, 0, uint32_t, 0,
	    uint32_t, (stmf_dbuf->db_flags & DB_DIRECTION_TO_RPORT) ? 1 : 0);

	if ((stmf_dbuf->db_flags & DB_SEND_STATUS_GOOD) != 0) {
		status = srpt_stp_send_status(dbuf->db_iu->iu_stmf_task, 0);
		if (status == STMF_SUCCESS) {
			return;
		}
		stmf_dbuf->db_xfer_status = STMF_FAILURE;
	}
	stmf_data_xfer_done(dbuf->db_iu->iu_stmf_task, stmf_dbuf, 0);
}

/*
 * srpt_ch_scq_hdlr()
 */
static void
srpt_ch_scq_hdlr(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibt_status_t		status;
	srpt_channel_t		*ch = arg;
	ibt_wc_t		wc[SRPT_SEND_WC_POLL_SIZE];
	ibt_wc_t		*wcp;
	int			i;
	uint32_t		cq_rearmed = 0;
	uint32_t		entries;
	srpt_swqe_t		*swqe;

	ASSERT(ch != NULL);

	/* Reference channel for the duration of this call */
	srpt_ch_add_ref(ch);

	for (;;) {
		status = ibt_poll_cq(cq_hdl, &wc[0], SRPT_SEND_WC_POLL_SIZE,
		    &entries);

		if (status != IBT_SUCCESS) {
			if (status != IBT_CQ_EMPTY) {
				/*
				 * This error should not happen. It indicates
				 * something abnormal has gone wrong and means
				 * either a hardware or programming logic error.
				 */
				SRPT_DPRINTF_L2(
				    "ch_scq_hdlr, unexpected CQ err(%d)",
				    status);
				srpt_ch_disconnect(ch);
			}

			/*
			 * If we have not rearmed the CQ do so now and poll to
			 * eliminate race; otherwise we are done.
			 */
			if (cq_rearmed == 0) {
				(void) ibt_enable_cq_notify(ch->ch_scq_hdl,
				    IBT_NEXT_COMPLETION);
				cq_rearmed = 1;
				continue;
			} else {
				break;
			}
		}

		for (wcp = wc, i = 0; i < entries; i++, wcp++) {

			/*
			 * A zero work ID indicates this CQE is associated
			 * with an intermediate post of a RDMA data transfer
			 * operation.  Since intermediate data requests are
			 * unsignaled, we should only get these if there was
			 * an error.  No action is required.
			 */
			if (wcp->wc_id == 0) {
				continue;
			}
			swqe = ch->ch_swqe + wcp->wc_id;

			switch (swqe->sw_type) {
			case SRPT_SWQE_TYPE_RESP:
				srpt_ch_rsp_comp(ch, (srpt_iu_t *)
				    swqe->sw_addr, wcp->wc_status);
				break;

			case SRPT_SWQE_TYPE_DATA:
				srpt_ch_data_comp(ch, (stmf_data_buf_t *)
				    swqe->sw_addr, wcp->wc_status);
				break;

			default:
				SRPT_DPRINTF_L2("ch_scq_hdlr, bad type(%d)",
				    swqe->sw_type);
				ASSERT(0);
			}

			srpt_ch_free_swqe_wrid(ch, wcp->wc_id);
		}
	}

	srpt_ch_release_ref(ch, 0);
}

/*
 * srpt_ch_rcq_hdlr()
 */
static void
srpt_ch_rcq_hdlr(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibt_status_t		status;
	srpt_channel_t		*ch = arg;
	ibt_wc_t		wc[SRPT_RECV_WC_POLL_SIZE];
	ibt_wc_t		*wcp;
	int			i;
	uint32_t		entries;
	srpt_iu_t		*iu;
	uint_t			cq_rearmed = 0;

	/*
	 * The channel object will exists while the CQ handler call-back
	 * is installed.
	 */
	ASSERT(ch != NULL);
	srpt_ch_add_ref(ch);

	/*
	 * If we know a channel disconnect has started do nothing
	 * and let channel cleanup code recover resources from the CQ.
	 * We are not concerned about races with the state transition
	 * since the code will do the correct thing either way. This
	 * is simply to circumvent rearming the CQ, and it will
	 * catch the state next time.
	 */
	rw_enter(&ch->ch_rwlock, RW_READER);
	if (ch->ch_state == SRPT_CHANNEL_DISCONNECTING) {
		SRPT_DPRINTF_L2("ch_rcq_hdlr, channel disconnecting");
		rw_exit(&ch->ch_rwlock);
		srpt_ch_release_ref(ch, 0);
		return;
	}
	rw_exit(&ch->ch_rwlock);

	for (;;) {
		status = ibt_poll_cq(cq_hdl, &wc[0], SRPT_RECV_WC_POLL_SIZE,
		    &entries);

		if (status != IBT_SUCCESS) {
			if (status != IBT_CQ_EMPTY) {
				/*
				 * This error should not happen. It indicates
				 * something abnormal has gone wrong and means
				 * either a hardware or programming logic error.
				 */
				SRPT_DPRINTF_L2(
				    "ch_rcq_hdlr, unexpected CQ err(%d)",
				    status);
				srpt_ch_disconnect(ch);
				break;
			}

			/*
			 * If we have not rearmed the CQ do so now and poll to
			 * eliminate race; otherwise we are done.
			 */
			if (cq_rearmed == 0) {
				(void) ibt_enable_cq_notify(ch->ch_rcq_hdl,
				    IBT_NEXT_COMPLETION);
				cq_rearmed = 1;
				continue;
			} else {
				break;
			}
		}

		for (wcp = wc, i = 0; i < entries; i++, wcp++) {

			/*
			 *  Check wc_status before proceeding.  If the
			 *  status indicates a channel problem, stop processing.
			 */
			if (wcp->wc_status != IBT_WC_SUCCESS) {
				if (wcp->wc_status == IBT_WC_WR_FLUSHED_ERR) {
					SRPT_DPRINTF_L2(
					    "ch_rcq, unexpected"
					    " wc_status err(%d)",
					    wcp->wc_status);
					srpt_ch_disconnect(ch);
					goto done;
				} else {
					/* skip IUs with errors */
					SRPT_DPRINTF_L2(
					    "ch_rcq, ERROR comp(%d)",
					    wcp->wc_status);
					/* XXX - verify not leaking IUs */
					continue;
				}
			}

			iu = (srpt_iu_t *)(uintptr_t)wcp->wc_id;
			ASSERT(iu != NULL);

			/*
			 * Process the IU.
			 */
			ASSERT(wcp->wc_type == IBT_WRC_RECV);
			srpt_ch_process_iu(ch, iu);
		}
	}

done:
	srpt_ch_release_ref(ch, 0);
}

/*
 * srpt_ch_srp_cmd()
 */
static int
srpt_ch_srp_cmd(srpt_channel_t *ch, srpt_iu_t *iu)
{
	srp_cmd_req_t		*cmd = (srp_cmd_req_t *)iu->iu_buf;
	srp_indirect_desc_t	*i_desc;
	uint_t			i_di_cnt;
	uint_t			i_do_cnt;
	uint8_t			do_fmt;
	uint8_t			di_fmt;
	uint32_t		*cur_desc_off;
	int			i;
	ibt_status_t		status;
	uint8_t			addlen;


	DTRACE_SRP_2(task__command, srpt_channel_t, ch, srp_cmd_req_t, cmd);
	iu->iu_ch  = ch;
	iu->iu_tag = cmd->cr_tag;

	/*
	 * The SRP specification and SAM require support for bi-directional
	 * data transfer, so we create a single buffer descriptor list that
	 * in the IU buffer that covers the data-in and data-out buffers.
	 * In practice we will just see unidirectional transfers with either
	 * data-in or data out descriptors.  If we were to take that as fact,
	 * we could reduce overhead slightly.
	 */

	/*
	 * additional length is a 6-bit number in 4-byte words, so multiply by 4
	 * to get bytes.
	 */
	addlen = cmd->cr_add_cdb_len & 0x3f;	/* mask off 6 bits */

	cur_desc_off = (uint32_t *)(void *)&cmd->cr_add_data;
	cur_desc_off  += addlen;		/* 32-bit arithmetic */
	iu->iu_num_rdescs = 0;
	iu->iu_rdescs = (srp_direct_desc_t *)(void *)cur_desc_off;

	/*
	 * Examine buffer description for Data In (i.e. data flows
	 * to the initiator).
	 */
	i_do_cnt = i_di_cnt = 0;
	di_fmt = cmd->cr_buf_fmt >> 4;
	if (di_fmt == SRP_DATA_DESC_DIRECT) {
		iu->iu_num_rdescs = 1;
		cur_desc_off = (uint32_t *)(void *)&iu->iu_rdescs[1];
	} else if (di_fmt == SRP_DATA_DESC_INDIRECT) {
		i_desc = (srp_indirect_desc_t *)iu->iu_rdescs;
		i_di_cnt  = b2h32(i_desc->id_table.dd_len) /
		    sizeof (srp_direct_desc_t);

		/*
		 * Some initiators like OFED occasionally use the wrong counts,
		 * so check total to allow for this.  NOTE: we do not support
		 * reading of the descriptor table from the initiator, so if
		 * not all descriptors are in the IU we drop the task.
		 */
		if (i_di_cnt > (cmd->cr_dicnt + cmd->cr_docnt)) {
			SRPT_DPRINTF_L2("ch_srp_cmd, remote RDMA of"
			    " descriptors not supported");
			SRPT_DPRINTF_L2("ch_srp_cmd, sizeof entry (%d),"
			    " i_di_cnt(%d), cr_dicnt(%d)",
			    (uint_t)sizeof (srp_direct_desc_t),
			    i_di_cnt, cmd->cr_dicnt);
			iu->iu_rdescs = NULL;
			return (1);
		}
		bcopy(&i_desc->id_desc[0], iu->iu_rdescs,
		    sizeof (srp_direct_desc_t) * i_di_cnt);
		iu->iu_num_rdescs += i_di_cnt;
		cur_desc_off = (uint32_t *)(void *)&i_desc->id_desc[i_di_cnt];
	}

	/*
	 * Examine buffer description for Data Out (i.e. data flows
	 * from the initiator).
	 */
	do_fmt = cmd->cr_buf_fmt & 0x0F;
	if (do_fmt == SRP_DATA_DESC_DIRECT) {
		if (di_fmt == SRP_DATA_DESC_DIRECT) {
			bcopy(cur_desc_off, &iu->iu_rdescs[iu->iu_num_rdescs],
			    sizeof (srp_direct_desc_t));
		}
		iu->iu_num_rdescs++;
	} else if (do_fmt == SRP_DATA_DESC_INDIRECT) {
		i_desc = (srp_indirect_desc_t *)cur_desc_off;
		i_do_cnt  = b2h32(i_desc->id_table.dd_len) /
		    sizeof (srp_direct_desc_t);

		/*
		 * Some initiators like OFED occasionally use the wrong counts,
		 * so check total to allow for this.  NOTE: we do not support
		 * reading of the descriptor table from the initiator, so if
		 * not all descriptors are in the IU we drop the task.
		 */
		if ((i_di_cnt + i_do_cnt) > (cmd->cr_dicnt + cmd->cr_docnt)) {
			SRPT_DPRINTF_L2("ch_srp_cmd, remote RDMA of"
			    " descriptors not supported");
			SRPT_DPRINTF_L2("ch_srp_cmd, sizeof entry (%d),"
			    " i_do_cnt(%d), cr_docnt(%d)",
			    (uint_t)sizeof (srp_direct_desc_t),
			    i_do_cnt, cmd->cr_docnt);
			iu->iu_rdescs = 0;
			return (1);
		}
		bcopy(&i_desc->id_desc[0], &iu->iu_rdescs[iu->iu_num_rdescs],
		    sizeof (srp_direct_desc_t) * i_do_cnt);
		iu->iu_num_rdescs += i_do_cnt;
	}

	iu->iu_tot_xfer_len = 0;
	for (i = 0; i < iu->iu_num_rdescs; i++) {
		iu->iu_rdescs[i].dd_vaddr = b2h64(iu->iu_rdescs[i].dd_vaddr);
		iu->iu_rdescs[i].dd_hdl   = b2h32(iu->iu_rdescs[i].dd_hdl);
		iu->iu_rdescs[i].dd_len   = b2h32(iu->iu_rdescs[i].dd_len);
		iu->iu_tot_xfer_len += iu->iu_rdescs[i].dd_len;
	}

#ifdef DEBUG
	if (srpt_errlevel >= SRPT_LOG_L4) {
		SRPT_DPRINTF_L4("ch_srp_cmd, iu->iu_tot_xfer_len (%d)",
		    iu->iu_tot_xfer_len);
		for (i = 0; i < iu->iu_num_rdescs; i++) {
			SRPT_DPRINTF_L4("ch_srp_cmd, rdescs[%d].dd_vaddr"
			    " (0x%08llx)",
			    i, (u_longlong_t)iu->iu_rdescs[i].dd_vaddr);
			SRPT_DPRINTF_L4("ch_srp_cmd, rdescs[%d].dd_hdl"
			    " (0x%08x)", i, iu->iu_rdescs[i].dd_hdl);
			SRPT_DPRINTF_L4("ch_srp_cmd, rdescs[%d].dd_len (%d)",
			    i, iu->iu_rdescs[i].dd_len);
		}
		SRPT_DPRINTF_L4("ch_srp_cmd, LUN (0x%08lx)",
		    (unsigned long int) *((uint64_t *)(void *) cmd->cr_lun));
	}
#endif
	rw_enter(&ch->ch_rwlock, RW_READER);

	if (ch->ch_state == SRPT_CHANNEL_DISCONNECTING) {
		/*
		 * The channel has begun disconnecting, so ignore the
		 * the command returning the IU resources.
		 */
		rw_exit(&ch->ch_rwlock);
		return (1);
	}

	/*
	 * Once a SCSI task is allocated and assigned to the IU, it
	 * owns those IU resources, which will be held until STMF
	 * is notified the task is done (from a lport perspective).
	 */
	iu->iu_stmf_task = stmf_task_alloc(ch->ch_tgt->tp_lport,
	    ch->ch_session->ss_ss, cmd->cr_lun,
	    SRP_CDB_SIZE + (addlen * 4), 0);
	if (iu->iu_stmf_task == NULL) {
		/*
		 * Could not allocate, return status to the initiator
		 * indicating that we are temporarily unable to process
		 * commands.  If unable to send, immediately return IU
		 * resource.
		 */
		SRPT_DPRINTF_L2("ch_srp_cmd, SCSI task allocation failure");
		rw_exit(&ch->ch_rwlock);
		mutex_enter(&iu->iu_lock);
		status = srpt_stp_send_response(iu, STATUS_BUSY, 0, 0, 0,
		    NULL, SRPT_NO_FENCE_SEND);
		mutex_exit(&iu->iu_lock);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L2("ch_srp_cmd, error(%d) posting error"
			    " response", status);
			return (1);
		} else {
			return (0);
		}
	}

	iu->iu_stmf_task->task_port_private = iu;
	iu->iu_stmf_task->task_flags = 0;

	if (di_fmt != 0) {
		iu->iu_stmf_task->task_flags |= TF_WRITE_DATA;
	}
	if (do_fmt != 0) {
		iu->iu_stmf_task->task_flags |= TF_READ_DATA;
	}

	switch (cmd->cr_task_attr) {
	case SRP_TSK_ATTR_QTYPE_SIMPLE:
		iu->iu_stmf_task->task_flags |=	TF_ATTR_SIMPLE_QUEUE;
		break;

	case SRP_TSK_ATTR_QTYPE_HEAD_OF_Q:
		iu->iu_stmf_task->task_flags |=	TF_ATTR_HEAD_OF_QUEUE;
		break;

	case SRP_TSK_ATTR_QTYPE_ORDERED:
		iu->iu_stmf_task->task_flags |=	TF_ATTR_ORDERED_QUEUE;
		break;

	case SRP_TSK_ATTR_QTYPE_ACA_Q_TAG:
		iu->iu_stmf_task->task_flags |=	TF_ATTR_ACA;
		break;

	default:
		SRPT_DPRINTF_L2("ch_srp_cmd, reserved task attr (%d)",
		    cmd->cr_task_attr);
		iu->iu_stmf_task->task_flags |=	TF_ATTR_ORDERED_QUEUE;
		break;
	}
	iu->iu_stmf_task->task_additional_flags = 0;
	iu->iu_stmf_task->task_priority		= 0;
	iu->iu_stmf_task->task_mgmt_function    = TM_NONE;
	iu->iu_stmf_task->task_max_nbufs	= STMF_BUFS_MAX;
	iu->iu_stmf_task->task_expected_xfer_length = iu->iu_tot_xfer_len;
	iu->iu_stmf_task->task_csn_size		= 0;

	bcopy(cmd->cr_cdb, iu->iu_stmf_task->task_cdb,
	    SRP_CDB_SIZE);
	if (addlen != 0) {
		bcopy(&cmd->cr_add_data,
		    iu->iu_stmf_task->task_cdb + SRP_CDB_SIZE,
		    addlen * 4);
	}

	/*
	 * Add the IU/task to the session and post to STMF.  The task will
	 * remain in the session's list until STMF is informed by SRP that
	 * it is done with the task.
	 */
	DTRACE_SRP_3(scsi__command, srpt_channel_t, iu->iu_ch,
	    scsi_task_t, iu->iu_stmf_task, srp_cmd_req_t, cmd);
	srpt_stp_add_task(ch->ch_session, iu);

	SRPT_DPRINTF_L3("ch_srp_cmd, new task (%p) posted",
	    (void *)iu->iu_stmf_task);
	stmf_post_task(iu->iu_stmf_task, NULL);
	rw_exit(&ch->ch_rwlock);

	return (0);
}

/*
 * srpt_ch_task_mgmt_abort()
 *
 * Returns 0 on success, indicating we've sent a management response.
 * Returns !0 to indicate failure; the IU should be reposted.
 */
static ibt_status_t
srpt_ch_task_mgmt_abort(srpt_channel_t *ch, srpt_iu_t *iu,
	uint64_t tag_to_abort)
{
	srpt_session_t	*session = ch->ch_session;
	srpt_iu_t	*ss_iu;
	ibt_status_t	status;

	/*
	 * Locate the associated task (tag_to_abort) in the
	 * session's active task list.
	 */
	rw_enter(&session->ss_rwlock, RW_READER);
	ss_iu = list_head(&session->ss_task_list);
	while (ss_iu != NULL) {
		mutex_enter(&ss_iu->iu_lock);
		if ((tag_to_abort == ss_iu->iu_tag)) {
			mutex_exit(&ss_iu->iu_lock);
			break;
		}
		mutex_exit(&ss_iu->iu_lock);
		ss_iu = list_next(&session->ss_task_list, ss_iu);
	}
	rw_exit(&session->ss_rwlock);

	/*
	 * Take appropriate action based on state of task
	 * to be aborted:
	 * 1) No longer exists - do nothing.
	 * 2) Previously aborted or status queued - do nothing.
	 * 3) Otherwise - initiate abort.
	 */
	if (ss_iu == NULL)  {
		goto send_mgmt_resp;
	}

	mutex_enter(&ss_iu->iu_lock);
	if ((ss_iu->iu_flags & (SRPT_IU_STMF_ABORTING |
	    SRPT_IU_ABORTED | SRPT_IU_RESP_SENT)) != 0) {
		mutex_exit(&ss_iu->iu_lock);
		goto send_mgmt_resp;
	}

	/*
	 * Set aborting flag and notify STMF of abort request.  No
	 * additional I/O will be queued for this IU.
	 */
	SRPT_DPRINTF_L3("ch_task_mgmt_abort, task found");
	ss_iu->iu_flags |= SRPT_IU_SRP_ABORTING;
	mutex_exit(&ss_iu->iu_lock);
	stmf_abort(STMF_QUEUE_TASK_ABORT,
	    ss_iu->iu_stmf_task, STMF_ABORTED, NULL);

send_mgmt_resp:
	mutex_enter(&iu->iu_lock);
	status = srpt_stp_send_mgmt_response(iu, SRP_TM_SUCCESS,
	    SRPT_FENCE_SEND);
	mutex_exit(&iu->iu_lock);

	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ch_task_mgmt_abort, err(%d)"
		    " posting abort response", status);
	}

	return (status);
}

/*
 * srpt_ch_srp_task_mgmt()
 */
static int
srpt_ch_srp_task_mgmt(srpt_channel_t *ch, srpt_iu_t *iu)
{
	srp_tsk_mgmt_t		*tsk = (srp_tsk_mgmt_t *)iu->iu_buf;
	uint8_t			tm_fn;
	ibt_status_t		status;

	SRPT_DPRINTF_L3("ch_srp_task_mgmt, SRP TASK MGMT func(%d)",
	    tsk->tm_function);

	/*
	 * Both tag and lun fileds have the same corresponding offsets
	 * in both srp_tsk_mgmt_t and srp_cmd_req_t structures.  The
	 * casting will allow us to use the same dtrace translator.
	 */
	DTRACE_SRP_2(task__command, srpt_channel_t, ch,
	    srp_cmd_req_t, (srp_cmd_req_t *)tsk);

	iu->iu_ch  = ch;
	iu->iu_tag = tsk->tm_tag;

	/*
	 * Task management aborts are processed directly by the SRP driver;
	 * all other task management requests are handed off to STMF.
	 */
	switch (tsk->tm_function) {
	case SRP_TSK_MGMT_ABORT_TASK:
		/*
		 * Initiate SCSI transport protocol specific task abort
		 * logic.
		 */
		status = srpt_ch_task_mgmt_abort(ch, iu, tsk->tm_task_tag);
		if (status != IBT_SUCCESS) {
			/* repost this IU */
			return (1);
		} else {
			return (0);
		}

	case SRP_TSK_MGMT_ABORT_TASK_SET:
		tm_fn = TM_ABORT_TASK_SET;
		break;

	case SRP_TSK_MGMT_CLEAR_TASK_SET:
		tm_fn = TM_CLEAR_TASK_SET;
		break;

	case SRP_TSK_MGMT_LUN_RESET:
		tm_fn = TM_LUN_RESET;
		break;

	case SRP_TSK_MGMT_CLEAR_ACA:
		tm_fn = TM_CLEAR_ACA;
		break;

	default:
		/*
		 * SRP does not support the requested task management
		 * function; return a not supported status in the response.
		 */
		SRPT_DPRINTF_L2("ch_srp_task_mgmt, SRP task mgmt fn(%d)"
		    " not supported", tsk->tm_function);
		mutex_enter(&iu->iu_lock);
		status = srpt_stp_send_mgmt_response(iu,
		    SRP_TM_NOT_SUPPORTED, SRPT_NO_FENCE_SEND);
		mutex_exit(&iu->iu_lock);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L2("ch_srp_task_mgmt, err(%d) posting"
			    " response", status);
			return (1);
		}
		return (0);
	}

	rw_enter(&ch->ch_rwlock, RW_READER);
	if (ch->ch_state == SRPT_CHANNEL_DISCONNECTING) {
		/*
		 * The channel has begun disconnecting, so ignore the
		 * the command returning the IU resources.
		 */
		rw_exit(&ch->ch_rwlock);
		return (1);
	}

	/*
	 * Once a SCSI mgmt task is allocated and assigned to the IU, it
	 * owns those IU resources, which will be held until we inform
	 * STMF that we are done with the task (from an lports perspective).
	 */
	iu->iu_stmf_task = stmf_task_alloc(ch->ch_tgt->tp_lport,
	    ch->ch_session->ss_ss, tsk->tm_lun, 0, STMF_TASK_EXT_NONE);
	if (iu->iu_stmf_task == NULL) {
		/*
		 * Could not allocate, return status to the initiator
		 * indicating that we are temporarily unable to process
		 * commands.  If unable to send, immediately return IU
		 * resource.
		 */
		SRPT_DPRINTF_L2("ch_srp_task_mgmt, SCSI task allocation"
		    " failure");
		rw_exit(&ch->ch_rwlock);
		mutex_enter(&iu->iu_lock);
		status = srpt_stp_send_response(iu, STATUS_BUSY, 0, 0, 0,
		    NULL, SRPT_NO_FENCE_SEND);
		mutex_exit(&iu->iu_lock);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L2("ch_srp_task_mgmt, err(%d) posting"
			    "busy response", status);
			/* repost the IU */
			return (1);
		}
		return (0);
	}

	iu->iu_stmf_task->task_port_private = iu;
	iu->iu_stmf_task->task_flags = 0;
	iu->iu_stmf_task->task_additional_flags =
	    TASK_AF_NO_EXPECTED_XFER_LENGTH;
	iu->iu_stmf_task->task_priority = 0;
	iu->iu_stmf_task->task_mgmt_function = tm_fn;
	iu->iu_stmf_task->task_max_nbufs = STMF_BUFS_MAX;
	iu->iu_stmf_task->task_expected_xfer_length = 0;
	iu->iu_stmf_task->task_csn_size = 0;

	/*
	 * Add the IU/task to the session and post to STMF.  The task will
	 * remain in the session's list until STMF is informed by SRP that
	 * it is done with the task.
	 */
	srpt_stp_add_task(ch->ch_session, iu);

	SRPT_DPRINTF_L3("ch_srp_task_mgmt, new mgmt task(%p) posted",
	    (void *)iu->iu_stmf_task);
	stmf_post_task(iu->iu_stmf_task, NULL);
	rw_exit(&ch->ch_rwlock);

	return (0);
}

/*
 * srpt_ch_process_iu()
 */
static void
srpt_ch_process_iu(srpt_channel_t *ch, srpt_iu_t *iu)
{
	srpt_iu_data_t	*iud;
	int		status = 1;

	/*
	 * IU adds reference to channel which will represent a
	 * a reference by STMF.  If for whatever reason the IU
	 * is not handed off to STMF, then this reference will be
	 * released.  Otherwise, the reference will be released when
	 * SRP informs STMF that the associated SCSI task is done.
	 */
	srpt_ch_add_ref(ch);

	/*
	 * Validate login RC channel state. Normally active, if
	 * not active then we need to handle a possible race between the
	 * receipt of a implied RTU and CM calling back to notify of the
	 * state transition.
	 */
	rw_enter(&ch->ch_rwlock, RW_READER);
	if (ch->ch_state == SRPT_CHANNEL_DISCONNECTING) {
		rw_exit(&ch->ch_rwlock);
		goto repost_iu;
	}
	rw_exit(&ch->ch_rwlock);

	iud = iu->iu_buf;

	switch (iud->rx_iu.srp_op) {
	case SRP_IU_CMD:
		status = srpt_ch_srp_cmd(ch, iu);
		break;

	case SRP_IU_TASK_MGMT:
		status = srpt_ch_srp_task_mgmt(ch, iu);
		return;

	case SRP_IU_I_LOGOUT:
		SRPT_DPRINTF_L3("ch_process_iu, SRP INITIATOR LOGOUT");
		/*
		 * Initiators should logout by issuing a CM disconnect
		 * request (DREQ) with the logout IU in the private data;
		 * however some initiators have been known to send the
		 * IU in-band, if this happens just initiate the logout.
		 * Note that we do not return a response as per the
		 * specification.
		 */
		srpt_stp_logout(ch);
		break;

	case SRP_IU_AER_RSP:
	case SRP_IU_CRED_RSP:
	default:
		/*
		 * We don't send asynchronous events or ask for credit
		 * adjustments, so nothing need be done.  Log we got an
		 * unexpected IU but then just repost the IU to the SRQ.
		 */
		SRPT_DPRINTF_L2("ch_process_iu, invalid IU from initiator,"
		    " IU opcode(%d)", iud->rx_iu.srp_op);
		break;
	}

	if (status == 0) {
		return;
	}

repost_iu:
	SRPT_DPRINTF_L4("process_iu:  reposting iu %p", (void *)iu);
	mutex_enter(&iu->iu_lock);
	srpt_ioc_repost_recv_iu(iu->iu_ioc, iu);
	mutex_exit(&iu->iu_lock);
	srpt_ch_release_ref(ch, 0);
}

/*
 * srpt_ch_post_send
 */
ibt_status_t
srpt_ch_post_send(srpt_channel_t *ch, srpt_iu_t *iu, uint32_t len,
	uint_t fence)
{
	ibt_status_t		status;
	ibt_send_wr_t		wr;
	ibt_wr_ds_t		ds;
	uint_t			posted;

	ASSERT(ch != NULL);
	ASSERT(iu != NULL);
	ASSERT(mutex_owned(&iu->iu_lock));

	rw_enter(&ch->ch_rwlock, RW_READER);
	if (ch->ch_state == SRPT_CHANNEL_DISCONNECTING) {
		rw_exit(&ch->ch_rwlock);
		SRPT_DPRINTF_L2("ch_post_send, bad ch state (%d)",
		    ch->ch_state);
		return (IBT_FAILURE);
	}
	rw_exit(&ch->ch_rwlock);

	wr.wr_id = srpt_ch_alloc_swqe_wrid(ch, SRPT_SWQE_TYPE_RESP,
	    (void *)iu);
	if (wr.wr_id == 0) {
		SRPT_DPRINTF_L2("ch_post_send, queue full");
		return (IBT_FAILURE);
	}

	atomic_inc_32(&iu->iu_sq_posted_cnt);

	wr.wr_flags = IBT_WR_SEND_SIGNAL;
	if (fence == SRPT_FENCE_SEND) {
		wr.wr_flags |= IBT_WR_SEND_FENCE;
	}
	wr.wr_opcode = IBT_WRC_SEND;
	wr.wr_trans  = IBT_RC_SRV;
	wr.wr_nds = 1;
	wr.wr_sgl = &ds;

	ds.ds_va = iu->iu_sge.ds_va;
	ds.ds_key = iu->iu_sge.ds_key;
	ds.ds_len = len;

	SRPT_DPRINTF_L4("ch_post_send, posting SRP response to channel"
	    " ds.ds_va (0x%16llx), ds.ds_key (0x%08x), "
	    " ds.ds_len (%d)",
	    (u_longlong_t)ds.ds_va, ds.ds_key, ds.ds_len);

	status = ibt_post_send(ch->ch_chan_hdl, &wr, 1, &posted);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("ch_post_send, post_send failed (%d)",
		    status);
		atomic_dec_32(&iu->iu_sq_posted_cnt);
		srpt_ch_free_swqe_wrid(ch, wr.wr_id);
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * srpt_ch_alloc_swqe_wrid()
 */
ibt_wrid_t
srpt_ch_alloc_swqe_wrid(srpt_channel_t *ch,
	srpt_swqe_type_t wqe_type, void *addr)
{
	ibt_wrid_t	wrid;

	mutex_enter(&ch->ch_swqe_lock);
	if (ch->ch_head == ch->ch_tail) {
		mutex_exit(&ch->ch_swqe_lock);
		return ((ibt_wrid_t)0);
	}
	wrid = (ibt_wrid_t)ch->ch_head;
	ch->ch_swqe[ch->ch_head].sw_type = wqe_type;
	ch->ch_swqe[ch->ch_head].sw_addr = addr;
	ch->ch_head = ch->ch_swqe[ch->ch_head].sw_next;
	ch->ch_swqe_posted++;
	mutex_exit(&ch->ch_swqe_lock);
	return (wrid);
}

/*
 * srpt_ch_free_swqe_wrid()
 */
void
srpt_ch_free_swqe_wrid(srpt_channel_t *ch, ibt_wrid_t id)
{
	mutex_enter(&ch->ch_swqe_lock);
	ch->ch_swqe[ch->ch_tail].sw_next = id;
	ch->ch_tail = (uint32_t)id;
	ch->ch_swqe_posted--;
	mutex_exit(&ch->ch_swqe_lock);
}

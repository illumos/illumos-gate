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
 * IB CM handlers for s Solaris SCSI RDMA Protocol Target (SRP)
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
#include <sys/ib/ibtl/ibti.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>

#include "srp.h"
#include "srpt_impl.h"
#include "srpt_cm.h"
#include "srpt_stp.h"
#include "srpt_ch.h"

extern uint16_t srpt_send_msg_depth;
extern srpt_ctxt_t  *srpt_ctxt;

/*
 * srpt_cm_req_hdlr() - Login request
 *
 * CM has called back with a CM REQ message associated with an
 * SRP initiator login request.
 */
static ibt_cm_status_t
srpt_cm_req_hdlr(srpt_target_port_t *tgt, ibt_cm_event_t *event,
	ibt_cm_return_args_t *ret_args, void *ret_priv_data,
	ibt_priv_data_len_t ret_priv_data_len)
{
	ibt_cm_status_t		status;
	ibt_cm_req_rcv_t	*req;
	srp_login_req_t		login;
	srp_login_rej_t		login_rej;
	srp_login_rsp_t		login_rsp;
	srpt_channel_t		*ch = NULL;
	char			remote_gid[SRPT_ALIAS_LEN];
	char			local_gid[SRPT_ALIAS_LEN];

	ASSERT(tgt != NULL);
	req = &event->cm_event.req;

	if (event->cm_priv_data_len <  sizeof (srp_login_req_t)) {
		SRPT_DPRINTF_L2("cm_req_hdlr, IU size expected (>= %d),"
		    " received size (%d)", (uint_t)sizeof (srp_login_req_t),
		    event->cm_priv_data_len);
		return (IBT_CM_REJECT);
	}

	if (event->cm_priv_data == NULL) {
		SRPT_DPRINTF_L2("cm_req_hdlr, NULL ULP private data pointer");
		return (IBT_CM_REJECT);
	}

	if (ret_priv_data_len <  sizeof (srp_login_rej_t)) {
		SRPT_DPRINTF_L2("cm_req_hdlr, return private len too"
		    " small (%d)", ret_priv_data_len);
		return (IBT_CM_REJECT);
	}

	if (ret_priv_data == NULL) {
		SRPT_DPRINTF_L2("cm_req_hdlr, NULL ULP return private data"
		    " pointer");
		return (IBT_CM_REJECT);
	}

	/*
	 * Copy to avoid potential alignment problems, process login
	 * creating a new channel and possibly session.
	 */
	bcopy(event->cm_priv_data, &login,  sizeof (login));

	ALIAS_STR(local_gid,
	    req->req_prim_addr.av_sgid.gid_prefix,
	    req->req_prim_addr.av_sgid.gid_guid);
	ALIAS_STR(remote_gid,
	    req->req_prim_addr.av_dgid.gid_prefix,
	    req->req_prim_addr.av_dgid.gid_guid);

	ch = srpt_stp_login(tgt, &login, &login_rsp,
	    &login_rej, req->req_prim_hca_port, local_gid, remote_gid);
	if (ch != NULL) {
		bcopy(&login_rsp, ret_priv_data,  SRP_LOGIN_RSP_SIZE);
		ret_args->cm_ret_len = SRP_LOGIN_RSP_SIZE;

		SRPT_DPRINTF_L3("cm_req_hdlr, rsp priv len(%d)"
		    " ch created on port(%d)"
		    ", cm_req_hdlr, req ra_out(%d), ra_in(%d)"
		    ", retry(%d)",
		    ret_args->cm_ret_len, req->req_prim_hca_port,
		    req->req_rdma_ra_out, req->req_rdma_ra_in,
		    req->req_retry_cnt);

		ret_args->cm_ret.rep.cm_channel = ch->ch_chan_hdl;
		ret_args->cm_ret.rep.cm_rdma_ra_out =
		    min(tgt->tp_ioc->ioc_attr.hca_max_rdma_out_chan,
		    req->req_rdma_ra_in);
		ret_args->cm_ret.rep.cm_rdma_ra_in =
		    min(tgt->tp_ioc->ioc_attr.hca_max_rdma_in_chan,
		    req->req_rdma_ra_out);
		ret_args->cm_ret.rep.cm_rnr_retry_cnt = req->req_retry_cnt;

		SRPT_DPRINTF_L3("cm_req_hdlr, hca_max_rdma_in_chan (%d)"
		    ", hca_max_rdma_out_chan (%d)"
		    ", updated ra_out(%d), ra_in(%d), retry(%d)",
		    tgt->tp_ioc->ioc_attr.hca_max_rdma_in_chan,
		    tgt->tp_ioc->ioc_attr.hca_max_rdma_out_chan,
		    ret_args->cm_ret.rep.cm_rdma_ra_out,
		    ret_args->cm_ret.rep.cm_rdma_ra_in,
		    ret_args->cm_ret.rep.cm_rnr_retry_cnt);
		status = IBT_CM_ACCEPT;

	} else {
		bcopy(&login_rej, ret_priv_data,  sizeof (login_rej));
		ret_args->cm_ret_len =  sizeof (login_rej);
		status = IBT_CM_REJECT;
	}

	return (status);
}

/*
 * srpt_cm_conn_est_hdlr() - Connection established
 *
 * CM has called back to inform us that a connection attempt has
 * completed (explicit or implicit) and may now be used.
 */
/* ARGSUSED */
static ibt_cm_status_t
srpt_cm_conn_est_hdlr(srpt_target_port_t *tgt, ibt_cm_event_t *event)
{
	srpt_channel_t		*ch;

	ASSERT(tgt != NULL);
	ASSERT(event != NULL);

	ch = (srpt_channel_t *)ibt_get_chan_private(event->cm_channel);
	ASSERT(ch != NULL);

	SRPT_DPRINTF_L3("cm_conn_est_hdlr, invoked for ch(%p)",
	    (void *)ch);

	rw_enter(&ch->ch_rwlock, RW_WRITER);
	if (ch->ch_state != SRPT_CHANNEL_CONNECTING &&
	    ch->ch_state != SRPT_CHANNEL_CONNECTED) {
		SRPT_DPRINTF_L2("cm_conn_est_hdlr, invalid ch state (%d)",
		    ch->ch_state);
		rw_exit(&ch->ch_rwlock);
		return (IBT_CM_REJECT);
	}

	ch->ch_state = SRPT_CHANNEL_CONNECTED;

	rw_exit(&ch->ch_rwlock);
	return (IBT_CM_ACCEPT);
}

/*
 * srpt_cm_conn_closed_hdlr() - Channel closed
 *
 * CM callback indicating a channel has been completely closed.
 */
/* ARGSUSED */
static ibt_cm_status_t
srpt_cm_conn_closed_hdlr(srpt_target_port_t *tgt, ibt_cm_event_t *event)
{
	ibt_cm_status_t		status = IBT_CM_ACCEPT;
	srpt_channel_t		*ch;

	ASSERT(tgt != NULL);
	ASSERT(event != NULL);

	ch = (srpt_channel_t *)ibt_get_chan_private(event->cm_channel);
	ASSERT(ch != NULL);

	SRPT_DPRINTF_L3("cm_conn_closed_hdlr, invoked for chan_hdl(%p),"
	    " event(%d)", (void *)ch->ch_chan_hdl,
	    event->cm_event.closed);

	switch (event->cm_event.closed) {

	case IBT_CM_CLOSED_DREP_RCVD:
	case IBT_CM_CLOSED_DREQ_TIMEOUT:
	case IBT_CM_CLOSED_DUP:
	case IBT_CM_CLOSED_ABORT:
	case IBT_CM_CLOSED_ALREADY:
		/*
		 * These cases indicate the SRP target initiated
		 * the closing of the channel and it is now closed.
		 * Cleanup the channel (which will remove the targets
		 * reference) and then release CM's reference.
		 */
		SRPT_DPRINTF_L3("cm_conn_closed_hdlr, local close call-back");
		srpt_ch_cleanup(ch);
		srpt_ch_release_ref(ch, 1);
		break;

	case IBT_CM_CLOSED_DREQ_RCVD:
	case IBT_CM_CLOSED_REJ_RCVD:
	case IBT_CM_CLOSED_STALE:
		/*
		 * These cases indicate that the SRP initiator is closing
		 * the channel.  CM will have already closed the RC channel,
		 * so simply initiate cleanup which will remove the target
		 * ports reference to the channel and then release the
		 * reference held by the CM.
		 */
		SRPT_DPRINTF_L3("cm_conn_closed_hdlr, remote close,"
		    " free channel");
		if (ch != NULL) {
			srpt_ch_cleanup(ch);
			srpt_ch_release_ref(ch, 1);
		} else {
			SRPT_DPRINTF_L2("cm_conn_closed_hdlr, NULL channel");
		}
		break;

	default:
		SRPT_DPRINTF_L2("cm_conn_closed_hdlr, unknown close type (%d)",
		    event->cm_event.closed);
		status = IBT_CM_DEFAULT;
		break;
	}
	return (status);
}

/*
 * srpt_cm_failure_hdlr() - Called when the channel is in error.  Cleanup
 * and release the channel.
 */
static ibt_cm_status_t
srpt_cm_failure_hdlr(ibt_cm_event_t *event)
{
	srpt_channel_t		*ch;

	ASSERT(event != NULL);

	ch = (srpt_channel_t *)ibt_get_chan_private(event->cm_channel);
	ASSERT(ch != NULL);

	SRPT_DPRINTF_L3("cm_failure_hdlr, chan_hdl: 0x%p, code: %d"
	    "msg: %d reason: %d", (void *)event->cm_channel,
	    event->cm_event.failed.cf_code,
	    event->cm_event.failed.cf_msg,
	    event->cm_event.failed.cf_reason);

	srpt_ch_cleanup(ch);
	srpt_ch_release_ref(ch, 1);

	return (IBT_CM_ACCEPT);
}

/*
 * srpt_cm_hdlr() - CM call-back handler.
 */
ibt_cm_status_t
srpt_cm_hdlr(void *cm_private, ibt_cm_event_t *event,
	ibt_cm_return_args_t *ret_args, void *ret_priv_data,
	ibt_priv_data_len_t ret_len_max)
{
	ibt_cm_status_t		status = IBT_CM_ACCEPT;

	switch (event->cm_type) {

	case IBT_CM_EVENT_REQ_RCV:
		SRPT_DPRINTF_L3("cm_hdlr, REQ received");
		status = srpt_cm_req_hdlr((srpt_target_port_t *)cm_private,
		    event, ret_args, ret_priv_data, ret_len_max);
		break;

	case IBT_CM_EVENT_REP_RCV:
		SRPT_DPRINTF_L3("cm_hdlr, REP received");
		break;

	case IBT_CM_EVENT_MRA_RCV:
		SRPT_DPRINTF_L3("cm_hdlr, MRA received");
		break;

	case IBT_CM_EVENT_CONN_EST:
		SRPT_DPRINTF_L3("cm_hdlr, Connection established");
		status = srpt_cm_conn_est_hdlr(
		    (srpt_target_port_t *)cm_private, event);
		break;

	case IBT_CM_EVENT_CONN_CLOSED:
		SRPT_DPRINTF_L3("cm_hdlr, Connection closed");
		status = srpt_cm_conn_closed_hdlr(
		    (srpt_target_port_t *)cm_private, event);
		break;

	case IBT_CM_EVENT_FAILURE:
		SRPT_DPRINTF_L3("cm_hdlr, Event failure");
		status = srpt_cm_failure_hdlr(event);
		break;

	case IBT_CM_EVENT_LAP_RCV:
		SRPT_DPRINTF_L3("cm_hdlr, LAP received");
		break;

	case IBT_CM_EVENT_APR_RCV:
		SRPT_DPRINTF_L3("cm_hdlr, APR received");
		break;

	default:
		SRPT_DPRINTF_L3("cm_hdlr, unknown event received");
		break;
	}

	return (status);
}

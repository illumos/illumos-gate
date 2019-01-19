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
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibtl_types.h>

#include <sys/ib/clients/iser/iser.h>

extern idm_transport_ops_t	iser_transport_ops;

/*
 * iser_cm.c
 *    InfiniBand Communication Manager routines for iSER
 */
static ibt_cm_status_t iser_ib_handle_cm_req(idm_svc_t *svc_hdl,
    ibt_cm_event_t *evp, ibt_cm_return_args_t *rargsp, void *rcmp,
    ibt_priv_data_len_t rcmp_len);

static ibt_cm_status_t iser_ib_handle_cm_rep(iser_state_t *statep,
    ibt_cm_event_t *evp, ibt_cm_return_args_t *rargsp, void *rcmp,
    ibt_priv_data_len_t rcmp_len);

static ibt_cm_status_t iser_handle_cm_conn_est(ibt_cm_event_t *evp);
static ibt_cm_status_t iser_handle_cm_conn_closed(ibt_cm_event_t *evp);
static ibt_cm_status_t iser_handle_cm_event_failure(ibt_cm_event_t *evp);

/*
 * iser_ib_cm_handler()
 */
ibt_cm_status_t
iser_ib_cm_handler(void *cm_private, ibt_cm_event_t *eventp,
    ibt_cm_return_args_t *ret_args, void *ret_priv_data,
    ibt_priv_data_len_t ret_len_max)
{
	ibt_cm_status_t	ret = IBT_CM_REJECT;

	switch (eventp->cm_type) {

	case IBT_CM_EVENT_REQ_RCV:
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler: IBT_CM_EVENT_REQ_RCV");
		ret = iser_ib_handle_cm_req((idm_svc_t *)cm_private, eventp,
		    ret_args, ret_priv_data, ret_len_max);
		break;

	case IBT_CM_EVENT_REP_RCV:
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler: IBT_CM_EVENT_REP_RCV");
		ret = iser_ib_handle_cm_rep((iser_state_t *)cm_private,
		    eventp, ret_args, ret_priv_data, ret_len_max);
		break;

	case IBT_CM_EVENT_CONN_EST:
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler: IBT_CM_EVENT_CONN_EST");
		ret = iser_handle_cm_conn_est(eventp);
		break;

	case IBT_CM_EVENT_CONN_CLOSED:
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler: "
		    "IBT_CM_EVENT_CONN_CLOSED");
		ret = iser_handle_cm_conn_closed(eventp);
		break;

	case IBT_CM_EVENT_FAILURE:
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler:  Event failure");
		ret = iser_handle_cm_event_failure(eventp);
		break;

	case IBT_CM_EVENT_MRA_RCV:
		/* Not supported */
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler:  MRA message received");
		break;

	case IBT_CM_EVENT_LAP_RCV:
		/* Not supported */
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler: LAP message received");
		break;

	case IBT_CM_EVENT_APR_RCV:
		/* Not supported */
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler: APR message received");
		break;

	default:
		ISER_LOG(CE_NOTE, "iser_ib_cm_handler: unknown event (0x%x)",
		    eventp->cm_type);
		break;
	}

	return (ret);
}

/* ARGSUSED */
static ibt_cm_status_t
iser_ib_handle_cm_req(idm_svc_t *svc_hdl, ibt_cm_event_t *evp,
    ibt_cm_return_args_t *rargsp, void *rcmp, ibt_priv_data_len_t rcmp_len)
{

	iser_private_data_t	iser_priv_data;
	ibt_ip_cm_info_t	ipcm_info;
	iser_chan_t		*chan;
	iser_conn_t		*iser_conn;
	int			status;

	/*
	 * CM private data brings IP information
	 * Private data received is a stream of bytes and may not be properly
	 * aligned. So, bcopy the data onto the stack before accessing it.
	 */
	bcopy((uint8_t *)evp->cm_priv_data, &iser_priv_data,
	    sizeof (iser_private_data_t));

	/* extract the CM IP info */
	status = ibt_get_ip_data(evp->cm_priv_data_len, evp->cm_priv_data,
	    &ipcm_info);
	if (status != IBT_SUCCESS) {
		return (IBT_CM_REJECT);
	}

	ISER_LOG(CE_NOTE, "iser_ib_handle_cm_req: ipcm_info (0x%p): src IP "
	    "(0x%08x) src port (0x%04x) dst IP: (0x%08x)", (void *)&ipcm_info,
	    ipcm_info.src_addr.un.ip4addr, ipcm_info.src_port,
	    ipcm_info.dst_addr.un.ip4addr);

	/* Allocate a channel to establish the new connection */
	chan = iser_ib_alloc_channel_nopathlookup(
	    evp->cm_event.req.req_hca_guid,
	    evp->cm_event.req.req_prim_hca_port);
	if (chan == NULL) {
		ISER_LOG(CE_NOTE, "iser_ib_handle_cm_req: failed to allocate "
		    "a channel from src IP (0x%08x) src port (0x%04x) "
		    "to dst IP: (0x%08x) on hca(%llx %d)",
		    ipcm_info.src_addr.un.ip4addr, ipcm_info.src_port,
		    ipcm_info.dst_addr.un.ip4addr,
		    (longlong_t)evp->cm_event.req.req_hca_guid,
		    evp->cm_event.req.req_prim_hca_port);
		return (IBT_CM_REJECT);
	}

	/* Set the local and remote ip */
	chan->ic_localip = ipcm_info.dst_addr;
	chan->ic_remoteip = ipcm_info.src_addr;

	/* Set the local and remote port numbers on the channel handle */
	chan->ic_lport = svc_hdl->is_svc_req.sr_port;
	chan->ic_rport = ipcm_info.src_port;

	/* Allocate the iser_conn_t for the IDM svc binding */
	iser_conn = kmem_zalloc(sizeof (iser_conn_t), KM_SLEEP);

	/* Set up the iser_conn attributes */
	mutex_init(&iser_conn->ic_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&iser_conn->ic_stage_cv, NULL, CV_DEFAULT, NULL);
	iser_conn->ic_type = ISER_CONN_TYPE_TGT;
	iser_conn->ic_chan = chan;
	iser_conn->ic_stage = ISER_CONN_STAGE_ALLOCATED;

	/* Hold a reference to the iSER service handle */
	iser_tgt_svc_hold((iser_svc_t *)svc_hdl->is_iser_svc);

	iser_conn->ic_idms = svc_hdl;

	/*
	 * Now set a pointer to the iser_conn in the iser_chan for
	 * access during CM event handling
	 */
	chan->ic_conn = iser_conn;

	rargsp->cm_ret.rep.cm_channel = chan->ic_chanhdl;

	return (IBT_CM_ACCEPT);
}

/* ARGSUSED */
static ibt_cm_status_t
iser_ib_handle_cm_rep(iser_state_t *statep, ibt_cm_event_t *evp,
    ibt_cm_return_args_t *rargsp, void *rcmp, ibt_priv_data_len_t rcmp_len)
{
	/* pre-post work requests into the receive queue */
	iser_ib_post_recv(evp->cm_channel);

	/* It looks like the RTU need not be send specifically */
	return (IBT_CM_ACCEPT);
}

static ibt_cm_status_t
iser_handle_cm_conn_est(ibt_cm_event_t *evp)
{
	iser_chan_t	*iser_chan;
	iser_conn_t	*iser_conn;
	iser_svc_t	*iser_svc;
	idm_status_t	status;
	idm_conn_t	*ic;

	iser_chan = (iser_chan_t *)ibt_get_chan_private(evp->cm_channel);

	/*
	 * An ibt_open_rc_channel() comes in as a IBT_CM_EVENT_REQ_RCV on the
	 * iSER-IB target, upon which the target sends a Response, accepting
	 * the request. This comes in as a IBT_CM_EVENT_REP_RCV on the iSER-IB
	 * initiator, which then sends an RTU. Upon getting this RTU from the
	 * iSER-IB initiator, the IBT_CM_EVENT_CONN_EST event is generated on
	 * the target. Then subsequently an IBT_CM_EVENT_CONN_EST event is
	 * generated on the initiator.
	 *
	 * Our new connection has been established on the target. If we are
	 * receiving this event on the target side, the iser_channel can be
	 * used as it is already populated. On the target side, an IDM
	 * connection is then allocated and the IDM layer is notified.
	 * If we are on the initiator we needn't do anything, since we
	 * already have the IDM linkage in place for this connection.
	 */
	if (iser_chan->ic_conn->ic_type == ISER_CONN_TYPE_TGT) {

		iser_conn = iser_chan->ic_conn;
		iser_svc  = (iser_svc_t *)iser_conn->ic_idms->is_iser_svc;

		mutex_enter(&iser_conn->ic_lock);

		status = idm_svc_conn_create(iser_conn->ic_idms,
		    IDM_TRANSPORT_TYPE_ISER, &ic);
		if (status != IDM_STATUS_SUCCESS) {
			/*
			 * No IDM rsrcs or something equally Bad.
			 * Return non-SUCCESS to IBCM. It'll give
			 * us a CONN_CLOSED, which we'll handle
			 * below.
			 */
			ISER_LOG(CE_NOTE, "iser_handle_cm_conn_est: "
			    "idm_svc_conn_create_failed");
			mutex_exit(&iser_conn->ic_lock);
			return (IBT_CM_NO_RESOURCE);
		}

		/* We no longer need the hold on the iSER service handle */
		iser_tgt_svc_rele(iser_svc);

		/* Hold a reference on the IDM connection handle */
		idm_conn_hold(ic);

		/* Set the transport ops and conn on the idm_conn handle */
		ic->ic_transport_ops = &iser_transport_ops;
		ic->ic_transport_private = (void *)iser_conn;
		ic->ic_transport_hdrlen = ISER_HEADER_LENGTH;
		iser_conn->ic_idmc = ic;

		/*
		 * Set the local and remote addresses in the idm conn handle.
		 */
		iser_ib_conv_ibtaddr2sockaddr(&ic->ic_laddr,
		    &iser_conn->ic_chan->ic_localip, iser_chan->ic_lport);
		iser_ib_conv_ibtaddr2sockaddr(&ic->ic_raddr,
		    &iser_conn->ic_chan->ic_remoteip, iser_chan->ic_rport);

		/*
		 * Kick the state machine.  At CS_S3_XPT_UP the state machine
		 * will notify the client (target) about the new connection.
		 */
		idm_conn_event(ic, CE_CONNECT_ACCEPT, (uintptr_t)NULL);
		iser_conn->ic_stage = ISER_CONN_STAGE_IC_CONNECTED;
		mutex_exit(&iser_conn->ic_lock);

		/*
		 * Post work requests on the receive queue
		 */
		iser_ib_post_recv(iser_chan->ic_chanhdl);

	}

	return (IBT_CM_ACCEPT);
}

static ibt_cm_status_t
iser_handle_cm_conn_closed(ibt_cm_event_t *evp)
{

	iser_chan_t	*chan;

	chan = (iser_chan_t *)ibt_get_chan_private(evp->cm_channel);

	ISER_LOG(CE_NOTE, "iser_handle_cm_conn_closed: chan (0x%p) "
	    "reason (0x%x)", (void *)chan, evp->cm_event.closed);

	switch (evp->cm_event.closed) {
	case IBT_CM_CLOSED_DREP_RCVD:	/* we requested a disconnect */
	case IBT_CM_CLOSED_ALREADY:	/* duplicate close */
		/* ignore these */
		return (IBT_CM_ACCEPT);

	case IBT_CM_CLOSED_DREQ_RCVD:	/* request to close the channel */
	case IBT_CM_CLOSED_REJ_RCVD:	/* reject after conn establishment */
	case IBT_CM_CLOSED_DREQ_TIMEOUT: /* our close request timed out */
	case IBT_CM_CLOSED_DUP:		/* duplicate close request */
	case IBT_CM_CLOSED_ABORT:	/* aborted connection establishment */
	case IBT_CM_CLOSED_STALE:	/* stale / unref connection */
		/* handle these depending upon our connection state */
		mutex_enter(&chan->ic_conn->ic_lock);
		switch (chan->ic_conn->ic_stage) {
		case ISER_CONN_STAGE_UNDEFINED:
		case ISER_CONN_STAGE_CLOSED:
			/* do nothing, just drop the lock */
			mutex_exit(&chan->ic_conn->ic_lock);
			break;

		case ISER_CONN_STAGE_ALLOCATED:
			/*
			 * We blew up or were offlined during connection
			 * establishment. Teardown the iSER conn and chan
			 * handles.
			 */
			mutex_exit(&chan->ic_conn->ic_lock);
			iser_internal_conn_destroy(chan->ic_conn);
			break;

		case ISER_CONN_STAGE_IC_DISCONNECTED:
		case ISER_CONN_STAGE_IC_FREED:
		case ISER_CONN_STAGE_CLOSING:
			/* we're down, set CLOSED */
			chan->ic_conn->ic_stage = ISER_CONN_STAGE_CLOSED;
			mutex_exit(&chan->ic_conn->ic_lock);
			break;

		case ISER_CONN_STAGE_IC_CONNECTED:
		case ISER_CONN_STAGE_HELLO_SENT:
		case ISER_CONN_STAGE_HELLO_SENT_FAIL:
		case ISER_CONN_STAGE_HELLO_WAIT:
		case ISER_CONN_STAGE_HELLO_RCV:
		case ISER_CONN_STAGE_HELLO_RCV_FAIL:
		case ISER_CONN_STAGE_HELLOREPLY_SENT:
		case ISER_CONN_STAGE_HELLOREPLY_SENT_FAIL:
		case ISER_CONN_STAGE_HELLOREPLY_RCV:
		case ISER_CONN_STAGE_HELLOREPLY_RCV_FAIL:
		case ISER_CONN_STAGE_LOGGED_IN:
			/* for all other stages, fail the transport */
			idm_conn_event(chan->ic_conn->ic_idmc,
			    CE_TRANSPORT_FAIL, IDM_STATUS_FAIL);
			chan->ic_conn->ic_stage = ISER_CONN_STAGE_CLOSING;
			mutex_exit(&chan->ic_conn->ic_lock);
			break;

		default:
			mutex_exit(&chan->ic_conn->ic_lock);
			ASSERT(0);

		}

		/* accept the event */
		return (IBT_CM_ACCEPT);

	default:
		/* unknown event */
		ISER_LOG(CE_NOTE, "iser_handle_cm_conn_closed: unknown closed "
		    "event: (0x%x)", evp->cm_event.closed);
		return (IBT_CM_REJECT);
	}
}

/*
 * Handle EVENT FAILURE
 */
static ibt_cm_status_t
iser_handle_cm_event_failure(ibt_cm_event_t *evp)
{
	iser_chan_t	*chan;

	chan = (iser_chan_t *)ibt_get_chan_private(evp->cm_channel);

	ISER_LOG(CE_NOTE, "iser_handle_cm_event_failure: chan (0x%p): "
	    "code: %d msg: %d reason: %d", (void *)chan,
	    evp->cm_event.failed.cf_code, evp->cm_event.failed.cf_msg,
	    evp->cm_event.failed.cf_reason);

	if ((evp->cm_channel == NULL) || (chan == NULL)) {
		/* channel not established yet */
		return (IBT_CM_ACCEPT);
	}

	if ((evp->cm_event.failed.cf_code != IBT_CM_FAILURE_STALE) &&
	    (evp->cm_event.failed.cf_msg == IBT_CM_FAILURE_REQ)) {
		/*
		 * This end is active, just ignore, ibt_open_rc_channel()
		 * caller will take care of cleanup.
		 */
		return (IBT_CM_ACCEPT);
	}

	/* handle depending upon our connection state */
	mutex_enter(&chan->ic_conn->ic_lock);
	switch (chan->ic_conn->ic_stage) {
	case ISER_CONN_STAGE_UNDEFINED:
	case ISER_CONN_STAGE_CLOSED:
		/* do nothing, just drop the lock */
		mutex_exit(&chan->ic_conn->ic_lock);
		break;

	case ISER_CONN_STAGE_ALLOCATED:
		/*
		 * We blew up or were offlined during connection
		 * establishment. Teardown the iSER conn and chan
		 * handles.
		 */
		mutex_exit(&chan->ic_conn->ic_lock);
		iser_internal_conn_destroy(chan->ic_conn);
		break;

	case ISER_CONN_STAGE_IC_DISCONNECTED:
	case ISER_CONN_STAGE_IC_FREED:
	case ISER_CONN_STAGE_CLOSING:
		/* update to CLOSED, then drop the lock */
		chan->ic_conn->ic_stage = ISER_CONN_STAGE_CLOSED;
		mutex_exit(&chan->ic_conn->ic_lock);
		break;

	case ISER_CONN_STAGE_IC_CONNECTED:
	case ISER_CONN_STAGE_HELLO_SENT:
	case ISER_CONN_STAGE_HELLO_SENT_FAIL:
	case ISER_CONN_STAGE_HELLO_WAIT:
	case ISER_CONN_STAGE_HELLO_RCV:
	case ISER_CONN_STAGE_HELLO_RCV_FAIL:
	case ISER_CONN_STAGE_HELLOREPLY_SENT:
	case ISER_CONN_STAGE_HELLOREPLY_SENT_FAIL:
	case ISER_CONN_STAGE_HELLOREPLY_RCV:
	case ISER_CONN_STAGE_HELLOREPLY_RCV_FAIL:
	case ISER_CONN_STAGE_LOGGED_IN:
		/* fail the transport and move the conn to CLOSING */
		idm_conn_event(chan->ic_conn->ic_idmc, CE_TRANSPORT_FAIL,
		    IDM_STATUS_FAIL);
		chan->ic_conn->ic_stage = ISER_CONN_STAGE_CLOSING;
		mutex_exit(&chan->ic_conn->ic_lock);
		break;

	default:
		mutex_exit(&chan->ic_conn->ic_lock);
		ASSERT(0);
	}

	/* accept the event */
	return (IBT_CM_ACCEPT);
}

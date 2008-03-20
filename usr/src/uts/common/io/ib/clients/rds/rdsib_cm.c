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
/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
/*
 * Sun elects to include this software in Sun product
 * under the OpenIB BSD license.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ib/clients/rds/rdsib_cm.h>
#include <sys/ib/clients/rds/rdsib_ib.h>
#include <sys/ib/clients/rds/rdsib_buf.h>
#include <sys/ib/clients/rds/rdsib_ep.h>

/*
 * This file contains CM related work:
 *
 * Service registration/deregistration
 * Path lookup
 * CM connection callbacks
 * CM active and passive connection establishment
 * Connection failover
 */

#define	SRCIP	src_addr.un.ip4addr
#define	DSTIP	dst_addr.un.ip4addr

/*
 * Handle an incoming CM REQ
 */
/* ARGSUSED */
static ibt_cm_status_t
rds_handle_cm_req(rds_state_t *statep, ibt_cm_event_t *evp,
    ibt_cm_return_args_t *rargsp, void *rcmp, ibt_priv_data_len_t rcmp_len)
{
	ibt_cm_req_rcv_t	*reqp;
	ib_gid_t		lgid, rgid;
	rds_cm_private_data_t	cmp;
	rds_session_t		*sp;
	rds_ep_t		*ep;
	ibt_channel_hdl_t	chanhdl;
	ibt_ip_cm_info_t	ipcm_info;
	int			ret;

	RDS_DPRINTF2("rds_handle_cm_req", "Enter");

	reqp = &evp->cm_event.req;
	rgid = reqp->req_prim_addr.av_dgid; /* requester gid */
	lgid = reqp->req_prim_addr.av_sgid; /* receiver gid */

	RDS_DPRINTF2(LABEL, "REQ Received: From: %llx:%llx To: %llx:%llx",
	    rgid.gid_prefix, rgid.gid_guid, lgid.gid_prefix, lgid.gid_guid);

	/* validate service id */
	if (reqp->req_service_id == RDS_SERVICE_ID) {
		RDS_DPRINTF0(LABEL, "Version Mismatch: Remote system "
		    "(GUID: 0x%llx) is running an older version of RDS",
		    rgid.gid_guid);
		return (IBT_CM_REJECT);
	}

	/*
	 * CM private data brings IP information
	 * Private data received is a stream of bytes and may not be properly
	 * aligned. So, bcopy the data onto the stack before accessing it.
	 */
	bcopy((uint8_t *)evp->cm_priv_data, &cmp,
	    sizeof (rds_cm_private_data_t));

	/* extract the CM IP info */
	ret = ibt_get_ip_data(evp->cm_priv_data_len, evp->cm_priv_data,
	    &ipcm_info);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2("rds_handle_cm_req", "ibt_get_ip_data failed: %d",
		    ret);
		return (IBT_CM_REJECT);
	}

	RDS_DPRINTF2("rds_handle_cm_req",
	    "REQ Received: From IP: 0x%x To IP: 0x%x type: %d",
	    ntohl(ipcm_info.SRCIP), ntohl(ipcm_info.DSTIP), cmp.cmp_eptype);

	if (cmp.cmp_version != RDS_VERSION) {
		RDS_DPRINTF0(LABEL, "Version Mismatch: Local version: %d "
		    "Remote version: %d", RDS_VERSION, cmp.cmp_version);
		return (IBT_CM_REJECT);
	}

	/* RDS supports V4 addresses only */
	if ((ipcm_info.src_addr.family != AF_INET) ||
	    (ipcm_info.dst_addr.family != AF_INET)) {
		RDS_DPRINTF2(LABEL, "Unsupported Address Family: "
		    "src: %d dst: %d", ipcm_info.src_addr.family,
		    ipcm_info.dst_addr.family);
		return (IBT_CM_REJECT);
	}

	if (cmp.cmp_arch != RDS_THIS_ARCH) {
		RDS_DPRINTF2(LABEL, "ARCH does not match (%d != %d)",
		    cmp.cmp_arch, RDS_THIS_ARCH);
		return (IBT_CM_REJECT);
	}

	if ((cmp.cmp_eptype != RDS_EP_TYPE_CTRL) &&
	    (cmp.cmp_eptype != RDS_EP_TYPE_DATA)) {
		RDS_DPRINTF2(LABEL, "Unknown Channel type: %d", cmp.cmp_eptype);
		return (IBT_CM_REJECT);
	}

	/* user_buffer_size should be same on all nodes */
	if (cmp.cmp_user_buffer_size != UserBufferSize) {
		RDS_DPRINTF2(LABEL,
		    "UserBufferSize Mismatch, this node: %d remote node: %d",
		    UserBufferSize, cmp.cmp_user_buffer_size);
		return (IBT_CM_REJECT);
	}

	/*
	 * RDS needs more time to process a failover REQ so send an MRA.
	 * Otherwise, the remote may retry the REQ and fail the connection.
	 */
	if ((cmp.cmp_failover) && (cmp.cmp_eptype == RDS_EP_TYPE_DATA)) {
		RDS_DPRINTF2("rds_handle_cm_req", "Session Failover, send MRA");
		(void) ibt_cm_delay(IBT_CM_DELAY_REQ, evp->cm_session_id,
		    10000000 /* 10 sec */, NULL, 0);
	}

	/* Is there a session to the destination node? */
	rw_enter(&statep->rds_sessionlock, RW_READER);
	sp = rds_session_lkup(statep, ntohl(ipcm_info.SRCIP), rgid.gid_guid);
	rw_exit(&statep->rds_sessionlock);

	if (sp == NULL) {
		/*
		 * currently there is no session to the destination
		 * remote ip in the private data is the local ip and vice
		 * versa
		 */
		sp = rds_session_create(statep, ntohl(ipcm_info.DSTIP),
		    ntohl(ipcm_info.SRCIP), reqp, RDS_SESSION_PASSIVE);
		if (sp == NULL) {
			/* Check the list anyway. */
			rw_enter(&statep->rds_sessionlock, RW_READER);
			sp = rds_session_lkup(statep, ntohl(ipcm_info.SRCIP),
			    rgid.gid_guid);
			rw_exit(&statep->rds_sessionlock);
			if (sp == NULL) {
				/*
				 * The only way this can fail is due to lack
				 * of kernel resources
				 */
				return (IBT_CM_REJECT);
			}
		}
	}

	rw_enter(&sp->session_lock, RW_WRITER);

	/* catch peer-to-peer case as soon as possible */
	if ((sp->session_state == RDS_SESSION_STATE_CREATED) ||
	    (sp->session_state == RDS_SESSION_STATE_INIT)) {
		/* Check possible peer-to-peer case here */
		if (sp->session_type != RDS_SESSION_PASSIVE) {
			RDS_DPRINTF2("rds_handle_cm_req",
			    "SP(%p) Peer-peer connection handling", sp);
			if (lgid.gid_guid > rgid.gid_guid) {
				/* this node is active so reject this request */
				rw_exit(&sp->session_lock);
				return (IBT_CM_REJECT);
			} else {
				/* this node is passive, change the session */
				sp->session_type = RDS_SESSION_PASSIVE;
				sp->session_lgid = lgid;
				sp->session_rgid = rgid;
			}
		}
	}

	RDS_DPRINTF2(LABEL, "SP(%p) state: %d", sp, sp->session_state);

	switch (sp->session_state) {
	case RDS_SESSION_STATE_CONNECTED:
		RDS_DPRINTF2(LABEL, "STALE Session Detected SP(%p)", sp);
		sp->session_state = RDS_SESSION_STATE_ERROR;
		RDS_DPRINTF3("rds_handle_cm_req", "SP(%p) State "
		    "RDS_SESSION_STATE_ERROR", sp);

		/* FALLTHRU */
	case RDS_SESSION_STATE_ERROR:
	case RDS_SESSION_STATE_PASSIVE_CLOSING:
		sp->session_type = RDS_SESSION_PASSIVE;
		rw_exit(&sp->session_lock);

		rds_session_close(sp, IBT_NOCALLBACKS, 1);

		/* move the session to init state */
		rw_enter(&sp->session_lock, RW_WRITER);
		ret = rds_session_reinit(sp, lgid);
		sp->session_myip = ntohl(ipcm_info.DSTIP);
		sp->session_lgid = lgid;
		sp->session_rgid = rgid;
		if (ret != 0) {
			rds_session_fini(sp);
			sp->session_state = RDS_SESSION_STATE_FAILED;
			RDS_DPRINTF3("rds_handle_cm_req", "SP(%p) State "
			    "RDS_SESSION_STATE_FAILED", sp);
			rw_exit(&sp->session_lock);
			return (IBT_CM_REJECT);
		} else {
			sp->session_state = RDS_SESSION_STATE_INIT;
			RDS_DPRINTF3("rds_handle_cm_req", "SP(%p) State "
			    "RDS_SESSION_STATE_INIT", sp);
		}

		if (cmp.cmp_eptype == RDS_EP_TYPE_CTRL) {
			ep = &sp->session_ctrlep;
		} else {
			ep = &sp->session_dataep;
		}
		break;
	case RDS_SESSION_STATE_CREATED:
	case RDS_SESSION_STATE_FAILED:
	case RDS_SESSION_STATE_FINI:
		/*
		 * Initialize both channels, we accept this connection
		 * only if both channels are initialized
		 */
		sp->session_type = RDS_SESSION_PASSIVE;
		sp->session_lgid = lgid;
		sp->session_rgid = rgid;
		sp->session_state = RDS_SESSION_STATE_CREATED;
		RDS_DPRINTF3("rds_handle_cm_req", "SP(%p) State "
		    "RDS_SESSION_STATE_CREATED", sp);
		ret = rds_session_init(sp);
		if (ret != 0) {
			/* Seems like there are not enough resources */
			sp->session_state = RDS_SESSION_STATE_FAILED;
			RDS_DPRINTF3("rds_handle_cm_req", "SP(%p) State "
			    "RDS_SESSION_STATE_FAILED", sp);
			rw_exit(&sp->session_lock);
			return (IBT_CM_REJECT);
		}
		sp->session_state = RDS_SESSION_STATE_INIT;
		RDS_DPRINTF3("rds_handle_cm_req", "SP(%p) State "
		    "RDS_SESSION_STATE_INIT", sp);

		/* FALLTHRU */
	case RDS_SESSION_STATE_INIT:
		/*
		 * When re-using an existing session, make sure the
		 * session is still through the same HCA. Otherwise, the
		 * memory registrations have to moved to the new HCA.
		 */
		if (cmp.cmp_eptype == RDS_EP_TYPE_DATA) {
			if (sp->session_lgid.gid_guid != lgid.gid_guid) {
				RDS_DPRINTF2("rds_handle_cm_req",
				    "Existing Session but different gid "
				    "existing: 0x%llx, new: 0x%llx, "
				    "sending an MRA",
				    sp->session_lgid.gid_guid, lgid.gid_guid);
				(void) ibt_cm_delay(IBT_CM_DELAY_REQ,
				    evp->cm_session_id, 10000000 /* 10 sec */,
				    NULL, 0);
				ret = rds_session_reinit(sp, lgid);
				if (ret != 0) {
					rds_session_fini(sp);
					sp->session_state =
					    RDS_SESSION_STATE_FAILED;
					sp->session_failover = 0;
					RDS_DPRINTF3("rds_failover_session",
					    "SP(%p) State "
					    "RDS_SESSION_STATE_FAILED", sp);
					rw_exit(&sp->session_lock);
					return (IBT_CM_REJECT);
				}
			}
			ep = &sp->session_dataep;
		} else {
			ep = &sp->session_ctrlep;
		}

		break;
	default:
		RDS_DPRINTF2(LABEL, "ERROR: SP(%p) is in an unexpected "
		    "state: %d", sp, sp->session_state);
		rw_exit(&sp->session_lock);
		return (IBT_CM_REJECT);
	}

	sp->session_failover = 0; /* reset any previous value */
	if (cmp.cmp_failover) {
		RDS_DPRINTF2("rds_handle_cm_req",
		    "SP(%p) Failover Session (BP %p)", sp, cmp.cmp_last_bufid);
		sp->session_failover = 1;
	}

	mutex_enter(&ep->ep_lock);
	if (ep->ep_state == RDS_EP_STATE_UNCONNECTED) {
		ep->ep_state = RDS_EP_STATE_PASSIVE_PENDING;
		sp->session_type = RDS_SESSION_PASSIVE;
		rw_exit(&sp->session_lock);
	} else if (ep->ep_state == RDS_EP_STATE_ACTIVE_PENDING) {
		rw_exit(&sp->session_lock);
		/*
		 * Peer to peer connection. There is an active
		 * connection pending on this ep. The one with
		 * greater port guid becomes active and the
		 * other becomes passive.
		 */
		RDS_DPRINTF2("rds_handle_cm_req",
		    "EP(%p) Peer-peer connection handling", ep);
		if (lgid.gid_guid > rgid.gid_guid) {
			/* this node is active so reject this request */
			mutex_exit(&ep->ep_lock);
			RDS_DPRINTF2(LABEL, "SP(%p) EP(%p): "
			    "Rejecting passive in favor of active", sp, ep);
			return (IBT_CM_REJECT);
		} else {
			/*
			 * This session is not the active end, change it
			 * to passive end.
			 */
			ep->ep_state = RDS_EP_STATE_PASSIVE_PENDING;

			rw_enter(&sp->session_lock, RW_WRITER);
			sp->session_type = RDS_SESSION_PASSIVE;
			sp->session_lgid = lgid;
			sp->session_rgid = rgid;
			rw_exit(&sp->session_lock);
		}
	} else {
		rw_exit(&sp->session_lock);
	}

	ep->ep_lbufid = cmp.cmp_last_bufid;
	ep->ep_ackwr.wr.rc.rcwr.rdma.rdma_raddr = (ib_vaddr_t)cmp.cmp_ack_addr;
	ep->ep_ackwr.wr.rc.rcwr.rdma.rdma_rkey = cmp.cmp_ack_rkey;
	cmp.cmp_last_bufid = ep->ep_rbufid;
	cmp.cmp_ack_addr = ep->ep_ack_addr;
	cmp.cmp_ack_rkey = ep->ep_ack_rkey;
	mutex_exit(&ep->ep_lock);

	/* continue with accepting the connection request for this channel */
	chanhdl = rds_ep_alloc_rc_channel(ep, reqp->req_prim_hca_port);
	if (chanhdl == NULL) {
		mutex_enter(&ep->ep_lock);
		ep->ep_state = RDS_EP_STATE_UNCONNECTED;
		mutex_exit(&ep->ep_lock);
		return (IBT_CM_REJECT);
	}

	/* pre-post recv buffers in the RQ */
	rds_post_recv_buf((void *)chanhdl);

	rargsp->cm_ret_len = sizeof (rds_cm_private_data_t);
	bcopy((uint8_t *)&cmp, rcmp, sizeof (rds_cm_private_data_t));
	rargsp->cm_ret.rep.cm_channel = chanhdl;
	rargsp->cm_ret.rep.cm_rdma_ra_out = 4;
	rargsp->cm_ret.rep.cm_rdma_ra_in = 4;
	rargsp->cm_ret.rep.cm_rnr_retry_cnt = MinRnrRetry;

	RDS_DPRINTF2("rds_handle_cm_req", "Return: SP(%p) EP(%p) Chan (%p)",
	    sp, ep, chanhdl);

	return (IBT_CM_ACCEPT);
}

/*
 * Handle an incoming CM REP
 * Pre-post recv buffers for the QP
 */
/* ARGSUSED */
static ibt_cm_status_t
rds_handle_cm_rep(ibt_cm_event_t *evp, ibt_cm_return_args_t *rargsp,
    void *rcmp, ibt_priv_data_len_t rcmp_len)
{
	rds_ep_t	*ep;
	rds_cm_private_data_t	cmp;

	RDS_DPRINTF2("rds_handle_cm_rep", "Enter");

	/* pre-post recv buffers in the RQ */
	rds_post_recv_buf((void *)evp->cm_channel);

	ep = (rds_ep_t *)ibt_get_chan_private(evp->cm_channel);
	bcopy((uint8_t *)evp->cm_priv_data, &cmp,
	    sizeof (rds_cm_private_data_t));
	ep->ep_lbufid = cmp.cmp_last_bufid;
	ep->ep_ackwr.wr.rc.rcwr.rdma.rdma_raddr = (ib_vaddr_t)cmp.cmp_ack_addr;
	ep->ep_ackwr.wr.rc.rcwr.rdma.rdma_rkey = cmp.cmp_ack_rkey;

	rargsp->cm_ret_len = 0;

	RDS_DPRINTF2("rds_handle_cm_rep", "Return: lbufid: %p", ep->ep_lbufid);

	return (IBT_CM_ACCEPT);
}

/*
 * Handle CONN EST
 */
static ibt_cm_status_t
rds_handle_cm_conn_est(ibt_cm_event_t *evp)
{
	rds_session_t	*sp;
	rds_ep_t	*ep;

	ep = (rds_ep_t *)ibt_get_chan_private(evp->cm_channel);

	RDS_DPRINTF2("rds_handle_cm_conn_est", "EP(%p) State: %d", ep,
	    ep->ep_state);

	mutex_enter(&ep->ep_lock);
	ASSERT((ep->ep_state == RDS_EP_STATE_ACTIVE_PENDING) ||
	    (ep->ep_state == RDS_EP_STATE_PASSIVE_PENDING));
	ep->ep_state = RDS_EP_STATE_CONNECTED;
	ep->ep_chanhdl = evp->cm_channel;
	sp = ep->ep_sp;
	mutex_exit(&ep->ep_lock);

	(void) rds_session_active(sp);

	RDS_DPRINTF2("rds_handle_cm_conn_est", "Return");
	return (IBT_CM_ACCEPT);
}

/*
 * Handle CONN CLOSED
 */
static ibt_cm_status_t
rds_handle_cm_conn_closed(ibt_cm_event_t *evp)
{
	rds_ep_t	*ep;
	rds_session_t	*sp;

	/* Catch DREQs but ignore DREPs */
	if (evp->cm_event.closed != IBT_CM_CLOSED_DREQ_RCVD) {
		RDS_DPRINTF2("rds_handle_cm_conn_closed",
		    "Ignoring Event: %d received", evp->cm_event.closed);
		return (IBT_CM_ACCEPT);
	}

	ep = (rds_ep_t *)ibt_get_chan_private(evp->cm_channel);
	sp = ep->ep_sp;
	RDS_DPRINTF2("rds_handle_cm_conn_closed", "EP(%p) Enter", ep);

	mutex_enter(&ep->ep_lock);
	if (ep->ep_state != RDS_EP_STATE_CONNECTED) {
		/* Ignore this DREQ */
		RDS_DPRINTF2("rds_handle_cm_conn_closed",
		    "EP(%p) not connected, state: %d", ep, ep->ep_state);
		mutex_exit(&ep->ep_lock);
		return (IBT_CM_ACCEPT);
	}
	ep->ep_state = RDS_EP_STATE_CLOSING;
	mutex_exit(&ep->ep_lock);

	rw_enter(&sp->session_lock, RW_WRITER);
	RDS_DPRINTF2("rds_handle_cm_conn_closed", "SP(%p) - state: %d", sp,
	    sp->session_state);

	switch (sp->session_state) {
	case RDS_SESSION_STATE_CONNECTED:
		sp->session_state = RDS_SESSION_STATE_PASSIVE_CLOSING;
		RDS_DPRINTF3("rds_handle_cm_conn_closed", "SP(%p) State "
		    "RDS_SESSION_STATE_PASSIVE_CLOSING", sp);
		break;

	case RDS_SESSION_STATE_PASSIVE_CLOSING:
		sp->session_state = RDS_SESSION_STATE_CLOSED;
		RDS_DPRINTF3("rds_handle_cm_conn_closed", "SP(%p) State "
		    "RDS_SESSION_STATE_CLOSED", sp);
		rds_passive_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FINI;
		RDS_DPRINTF3("rds_handle_cm_conn_closed",
		    "SP(%p) State RDS_SESSION_STATE_FINI", sp);
		break;

	case RDS_SESSION_STATE_ACTIVE_CLOSING:
	case RDS_SESSION_STATE_ERROR:
	case RDS_SESSION_STATE_CLOSED:
		break;

	case RDS_SESSION_STATE_INIT:
		sp->session_state = RDS_SESSION_STATE_ERROR;
		RDS_DPRINTF3("rds_handle_cm_conn_closed", "SP(%p) State "
		    "RDS_SESSION_STATE_ERROR", sp);
		rds_passive_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FAILED;
		RDS_DPRINTF3("rds_handle_cm_conn_closed",
		    "SP(%p) State RDS_SESSION_STATE_FAILED", sp);
		break;

	default:
		RDS_DPRINTF2("rds_handle_cm_conn_closed",
		    "SP(%p) - Unexpected state: %d", sp, sp->session_state);
		rds_passive_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FAILED;
		RDS_DPRINTF3("rds_handle_cm_conn_closed", "SP(%p) State "
		    "RDS_SESSION_STATE_FAILED", sp);
	}
	rw_exit(&sp->session_lock);

	mutex_enter(&ep->ep_lock);
	ep->ep_state = RDS_EP_STATE_CLOSED;
	mutex_exit(&ep->ep_lock);

	RDS_DPRINTF2("rds_handle_cm_conn_closed", "SP(%p) Return", sp);
	return (IBT_CM_ACCEPT);
}

/*
 * Handle EVENT FAILURE
 */
static ibt_cm_status_t
rds_handle_cm_event_failure(ibt_cm_event_t *evp)
{
	rds_ep_t	*ep;
	rds_session_t	*sp;
	int		ret;

	RDS_DPRINTF2("rds_handle_cm_event_failure", "Enter: Chan hdl: 0x%p "
	    "Code: %d msg: %d reason: %d", evp->cm_channel,
	    evp->cm_event.failed.cf_code, evp->cm_event.failed.cf_msg,
	    evp->cm_event.failed.cf_reason);

	if (evp->cm_event.failed.cf_reason == IBT_CM_INVALID_SID) {
		RDS_DPRINTF0(LABEL,
		    "Received REJ with reason IBT_CM_INVALID_SID: "
		    "The remote system could be running an older RDS version");
	}

	if (evp->cm_channel == NULL) {
		return (IBT_CM_ACCEPT);
	}

	if ((evp->cm_event.failed.cf_code != IBT_CM_FAILURE_STALE) &&
	    (evp->cm_event.failed.cf_msg == IBT_CM_FAILURE_REQ)) {
		/*
		 * This end is active, just ignore, ibt_open_rc_channel()
		 * caller will take care of cleanup.
		 */
		RDS_DPRINTF2("rds_handle_cm_event_failure",
		    "Ignoring this event: Chan hdl: 0x%p", evp->cm_channel);
		return (IBT_CM_ACCEPT);
	}

	ep = (rds_ep_t *)ibt_get_chan_private(evp->cm_channel);
	sp = ep->ep_sp;

	rw_enter(&sp->session_lock, RW_WRITER);
	if (sp->session_type == RDS_SESSION_PASSIVE) {
		RDS_DPRINTF2("rds_handle_cm_event_failure",
		    "SP(%p) - state: %d", sp, sp->session_state);
		if ((sp->session_state == RDS_SESSION_STATE_INIT) ||
		    (sp->session_state == RDS_SESSION_STATE_CONNECTED)) {
			sp->session_state = RDS_SESSION_STATE_ERROR;
			RDS_DPRINTF3("rds_handle_cm_event_failure",
			    "SP(%p) State RDS_SESSION_STATE_ERROR", sp);

			/*
			 * Store the cm_channel for freeing later
			 * Active side frees it on ibt_open_rc_channel
			 * failure
			 */
			if (ep->ep_chanhdl == NULL) {
				ep->ep_chanhdl = evp->cm_channel;
			}
			rw_exit(&sp->session_lock);

			/*
			 * rds_passive_session_fini should not be called
			 * directly in the CM handler. It will cause a deadlock.
			 */
			ret = ddi_taskq_dispatch(rds_taskq,
			    rds_cleanup_passive_session, (void *)sp,
			    DDI_NOSLEEP);
			if (ret != DDI_SUCCESS) {
				RDS_DPRINTF1("rds_handle_cm_event_failure",
				    "SP(%p) TaskQ dispatch FAILED:%d", sp, ret);
			}
			return (IBT_CM_ACCEPT);
		}
	}
	rw_exit(&sp->session_lock);

	RDS_DPRINTF2("rds_handle_cm_event_failure", "SP(%p) Return", sp);
	return (IBT_CM_ACCEPT);
}

/*
 * CM Handler
 *
 * Called by IBCM
 * The cm_private type differs for active and passive events.
 */
ibt_cm_status_t
rds_cm_handler(void *cm_private, ibt_cm_event_t *eventp,
    ibt_cm_return_args_t *ret_args, void *ret_priv_data,
    ibt_priv_data_len_t ret_len_max)
{
	ibt_cm_status_t		ret = IBT_CM_ACCEPT;

	RDS_DPRINTF2("rds_cm_handler", "Enter: event: %d", eventp->cm_type);

	switch (eventp->cm_type) {
	case IBT_CM_EVENT_REQ_RCV:
		ret = rds_handle_cm_req((rds_state_t *)cm_private, eventp,
		    ret_args, ret_priv_data, ret_len_max);
		break;
	case IBT_CM_EVENT_REP_RCV:
		ret = rds_handle_cm_rep(eventp, ret_args, ret_priv_data,
		    ret_len_max);
		break;
	case IBT_CM_EVENT_MRA_RCV:
		/* Not supported */
		break;
	case IBT_CM_EVENT_CONN_EST:
		ret = rds_handle_cm_conn_est(eventp);
		break;
	case IBT_CM_EVENT_CONN_CLOSED:
		ret = rds_handle_cm_conn_closed(eventp);
		break;
	case IBT_CM_EVENT_FAILURE:
		ret = rds_handle_cm_event_failure(eventp);
		break;
	case IBT_CM_EVENT_LAP_RCV:
		/* Not supported */
		RDS_DPRINTF2(LABEL, "LAP message received");
		break;
	case IBT_CM_EVENT_APR_RCV:
		/* Not supported */
		RDS_DPRINTF2(LABEL, "APR message received");
		break;
	default:
		break;
	}

	RDS_DPRINTF2("rds_cm_handler", "Return");

	return (ret);
}

/* This is based on OFED Linux RDS */
#define	RDS_PORT_NUM	6556

/*
 * Register the wellknown service with service id: RDS_SERVICE_ID
 * Incoming connection requests should arrive on this service id.
 */
ibt_srv_hdl_t
rds_register_service(ibt_clnt_hdl_t rds_ibhdl)
{
	ibt_srv_hdl_t	srvhdl;
	ibt_srv_desc_t	srvdesc;
	int		ret;

	RDS_DPRINTF2("rds_register_service", "Enter: 0x%p", rds_ibhdl);

	bzero(&srvdesc, sizeof (ibt_srv_desc_t));
	srvdesc.sd_handler = rds_cm_handler;
	srvdesc.sd_flags = IBT_SRV_NO_FLAGS;

	/*
	 * Register the old service id for backward compatibility
	 * REQs received on this service id would be rejected
	 */
	ret = ibt_register_service(rds_ibhdl, &srvdesc, RDS_SERVICE_ID,
	    1, &rdsib_statep->rds_old_srvhdl, NULL);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2(LABEL,
		    "RDS Service (0x%llx) Registration Failed: %d",
		    RDS_SERVICE_ID, ret);
		return (NULL);
	}

	/*
	 * This is the new service id as per:
	 * Annex A11: RDMA IP CM Service
	 */
	rdsib_statep->rds_service_id = ibt_get_ip_sid(IPPROTO_TCP,
	    RDS_PORT_NUM);
	ret = ibt_register_service(rds_ibhdl, &srvdesc,
	    rdsib_statep->rds_service_id, 1, &srvhdl, NULL);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2(LABEL,
		    "RDS Service (0x%llx) Registration Failed: %d",
		    rdsib_statep->rds_service_id, ret);
		return (NULL);
	}

	RDS_DPRINTF2("rds_register_service", "Return: 0x%p", srvhdl);
	return (srvhdl);
}

/* Bind the RDS service on all ports */
int
rds_bind_service(rds_state_t *statep)
{
	rds_hca_t	*hcap;
	ib_gid_t	gid;
	uint_t		jx, nbinds = 0, nports = 0;
	int		ret;

	RDS_DPRINTF2("rds_bind_service", "Enter: 0x%p", statep);

	hcap = statep->rds_hcalistp;
	while (hcap != NULL) {
		for (jx = 0; jx < hcap->hca_nports; jx++) {
			nports++;
			if (hcap->hca_pinfop[jx].p_linkstate !=
			    IBT_PORT_ACTIVE) {
				/*
				 * service bind will be called in the async
				 * handler when the port comes up
				 */
				continue;
			}

			gid = hcap->hca_pinfop[jx].p_sgid_tbl[0];
			RDS_DPRINTF5(LABEL, "HCA: 0x%llx Port: %d "
			    "gid: %llx:%llx", hcap->hca_guid,
			    hcap->hca_pinfop[jx].p_port_num, gid.gid_prefix,
			    gid.gid_guid);

			/* pass statep as cm_private */
			ret = ibt_bind_service(statep->rds_srvhdl, gid,
			    NULL, statep, NULL);
			if (ret != IBT_SUCCESS) {
				RDS_DPRINTF2(LABEL, "Bind service for "
				    "HCA: 0x%llx Port: %d gid %llx:%llx "
				    "failed: %d", hcap->hca_guid,
				    hcap->hca_pinfop[jx].p_port_num,
				    gid.gid_prefix, gid.gid_guid, ret);
				continue;
			}

			nbinds++;

			/* bind the old service, ignore if it fails */
			ret = ibt_bind_service(statep->rds_old_srvhdl, gid,
			    NULL, statep, NULL);
			if (ret != IBT_SUCCESS) {
				RDS_DPRINTF2(LABEL, "Bind service for "
				    "HCA: 0x%llx Port: %d gid %llx:%llx "
				    "failed: %d", hcap->hca_guid,
				    hcap->hca_pinfop[jx].p_port_num,
				    gid.gid_prefix, gid.gid_guid, ret);
			}
		}
		hcap = hcap->hca_nextp;
	}

	RDS_DPRINTF2(LABEL, "RDS Service available on %d/%d ports",
	    nbinds, nports);

#if 0
	if (nbinds == 0) {
		return (-1);
	}
#endif

	RDS_DPRINTF2("rds_bind_service", "Return");

	return (0);
}

/* Open an RC connection */
int
rds_open_rc_channel(rds_ep_t *ep, ibt_path_info_t *pinfo,
    ibt_execution_mode_t mode, ibt_channel_hdl_t *chanhdl)
{
	rds_session_t		*sp;
	ibt_chan_open_args_t	ocargs;
	ibt_rc_returns_t	ocrets;
	rds_cm_private_data_t	cmp;
	uint8_t			hca_port;
	ibt_channel_hdl_t	hdl;
	ibt_status_t		ret = 0;
	ibt_ip_cm_info_t	ipcm_info;

	RDS_DPRINTF2("rds_open_rc_channel", "Enter: EP(%p) mode: %d", ep, mode);

	sp = ep->ep_sp;

	bzero(&ipcm_info, sizeof (ibt_ip_cm_info_t));
	ipcm_info.src_addr.family = AF_INET;
	ipcm_info.SRCIP = htonl(sp->session_myip);
	ipcm_info.dst_addr.family = AF_INET;
	ipcm_info.DSTIP = htonl(sp->session_remip);
	ipcm_info.src_port = htons(6556); /* based on OFED RDS */
	ret = ibt_format_ip_private_data(&ipcm_info,
	    sizeof (rds_cm_private_data_t), &cmp);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2(LABEL, "SP(%p) EP(%p) ibt_format_ip_private_data "
		    "failed: %d", sp, ep, ret);
		return (-1);
	}

	hca_port = pinfo->pi_prim_cep_path.cep_hca_port_num;

	hdl = rds_ep_alloc_rc_channel(ep, hca_port);
	if (hdl == NULL) {
		return (-1);
	}

	cmp.cmp_version = RDS_VERSION;
	cmp.cmp_arch = RDS_THIS_ARCH;
	cmp.cmp_eptype = ep->ep_type;
	cmp.cmp_failover = sp->session_failover;
	cmp.cmp_last_bufid = ep->ep_rbufid;
	cmp.cmp_user_buffer_size = UserBufferSize;
	cmp.cmp_ack_addr = ep->ep_ack_addr;
	cmp.cmp_ack_rkey = ep->ep_ack_rkey;

	bzero(&ocargs, sizeof (ibt_chan_open_args_t));
	bzero(&ocrets, sizeof (ibt_rc_returns_t));
	ocargs.oc_path = pinfo;
	ocargs.oc_cm_handler = rds_cm_handler;
	ocargs.oc_cm_clnt_private = NULL;
	ocargs.oc_rdma_ra_out = 4;
	ocargs.oc_rdma_ra_in = 4;
	ocargs.oc_priv_data_len = sizeof (rds_cm_private_data_t);
	ocargs.oc_priv_data = &cmp;
	ocargs.oc_path_retry_cnt = IBPathRetryCount;
	ocargs.oc_path_rnr_retry_cnt = MinRnrRetry;
	ret = ibt_open_rc_channel(hdl, IBT_OCHAN_NO_FLAGS,
	    mode, &ocargs, &ocrets);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2(LABEL, "SP(%p) EP(%p) ibt_open_rc_channel "
		    "failed: %d", sp, ep, ret);
		(void) ibt_flush_channel(hdl);
		(void) ibt_free_channel(hdl);

		mutex_enter(&ep->ep_lock);
		/* don't cleanup if this failure is due to peer-peer race */
		if (ep->ep_state == RDS_EP_STATE_ACTIVE_PENDING) {
			/* cleanup stuff allocated in rds_ep_alloc_rc_channel */
			ep->ep_state = RDS_EP_STATE_ERROR;
			rds_ep_free_rc_channel(ep);
		}
		mutex_exit(&ep->ep_lock);

		return (-1);
	}

	*chanhdl = hdl;

	RDS_DPRINTF2("rds_open_rc_channel", "Return: EP(%p) Chan: %p", ep,
	    *chanhdl);

	return (0);
}

int
rds_close_rc_channel(ibt_channel_hdl_t chanhdl, ibt_execution_mode_t mode)
{
	int	ret;

	RDS_DPRINTF2("rds_close_rc_channel", "Enter: Chan(%p) Mode(%d)",
	    chanhdl, mode);

	ret = ibt_close_rc_channel(chanhdl, mode, NULL, 0, NULL, NULL, 0);

	RDS_DPRINTF2("rds_close_rc_channel", "Return Chan(%p)", chanhdl);

	return (ret);
}

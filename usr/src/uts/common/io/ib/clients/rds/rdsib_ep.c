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

#include <sys/stream.h>
#include <sys/ib/clients/rds/rdsib_cm.h>
#include <sys/ib/clients/rds/rdsib_ib.h>
#include <sys/ib/clients/rds/rdsib_buf.h>
#include <sys/ib/clients/rds/rdsib_ep.h>
#include <sys/ib/clients/rds/rds_kstat.h>
#include <sys/zone.h>

#define	RDS_POLL_CQ_IN_2TICKS	1

/*
 * This File contains the endpoint related calls
 */

extern boolean_t rds_islocal(ipaddr_t addr);
extern uint_t rds_wc_signal;

#define	RDS_LOOPBACK	0
#define	RDS_LOCAL	1
#define	RDS_REMOTE	2

#define	IBT_IPADDR	1

static uint8_t
rds_is_port_marked(rds_session_t *sp, in_port_t port, uint_t qualifier)
{
	uint8_t	ret;

	switch (qualifier) {
	case RDS_LOOPBACK: /* loopback */
		rw_enter(&rds_loopback_portmap_lock, RW_READER);
		ret = (rds_loopback_portmap[port/8] & (1 << (port % 8)));
		rw_exit(&rds_loopback_portmap_lock);
		break;

	case RDS_LOCAL: /* Session local */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_local_portmap_lock, RW_READER);
		ret = (sp->session_local_portmap[port/8] & (1 << (port % 8)));
		rw_exit(&sp->session_local_portmap_lock);
		break;

	case RDS_REMOTE: /* Session remote */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_remote_portmap_lock, RW_READER);
		ret = (sp->session_remote_portmap[port/8] & (1 << (port % 8)));
		rw_exit(&sp->session_remote_portmap_lock);
		break;
	}

	return (ret);
}

static uint8_t
rds_check_n_mark_port(rds_session_t *sp, in_port_t port, uint_t qualifier)
{
	uint8_t	ret;

	switch (qualifier) {
	case RDS_LOOPBACK: /* loopback */
		rw_enter(&rds_loopback_portmap_lock, RW_WRITER);
		ret = (rds_loopback_portmap[port/8] & (1 << (port % 8)));
		if (!ret) {
			/* port is not marked, mark it */
			rds_loopback_portmap[port/8] =
			    rds_loopback_portmap[port/8] | (1 << (port % 8));
		}
		rw_exit(&rds_loopback_portmap_lock);
		break;

	case RDS_LOCAL: /* Session local */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_local_portmap_lock, RW_WRITER);
		ret = (sp->session_local_portmap[port/8] & (1 << (port % 8)));
		if (!ret) {
			/* port is not marked, mark it */
			sp->session_local_portmap[port/8] =
			    sp->session_local_portmap[port/8] |
			    (1 << (port % 8));
		}
		rw_exit(&sp->session_local_portmap_lock);
		break;

	case RDS_REMOTE: /* Session remote */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_remote_portmap_lock, RW_WRITER);
		ret = (sp->session_remote_portmap[port/8] & (1 << (port % 8)));
		if (!ret) {
			/* port is not marked, mark it */
			sp->session_remote_portmap[port/8] =
			    sp->session_remote_portmap[port/8] |
			    (1 << (port % 8));
		}
		rw_exit(&sp->session_remote_portmap_lock);
		break;
	}

	return (ret);
}

static uint8_t
rds_check_n_unmark_port(rds_session_t *sp, in_port_t port, uint_t qualifier)
{
	uint8_t	ret;

	switch (qualifier) {
	case RDS_LOOPBACK: /* loopback */
		rw_enter(&rds_loopback_portmap_lock, RW_WRITER);
		ret = (rds_loopback_portmap[port/8] & (1 << (port % 8)));
		if (ret) {
			/* port is marked, unmark it */
			rds_loopback_portmap[port/8] =
			    rds_loopback_portmap[port/8] & ~(1 << (port % 8));
		}
		rw_exit(&rds_loopback_portmap_lock);
		break;

	case RDS_LOCAL: /* Session local */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_local_portmap_lock, RW_WRITER);
		ret = (sp->session_local_portmap[port/8] & (1 << (port % 8)));
		if (ret) {
			/* port is marked, unmark it */
			sp->session_local_portmap[port/8] =
			    sp->session_local_portmap[port/8] &
			    ~(1 << (port % 8));
		}
		rw_exit(&sp->session_local_portmap_lock);
		break;

	case RDS_REMOTE: /* Session remote */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_remote_portmap_lock, RW_WRITER);
		ret = (sp->session_remote_portmap[port/8] & (1 << (port % 8)));
		if (ret) {
			/* port is marked, unmark it */
			sp->session_remote_portmap[port/8] =
			    sp->session_remote_portmap[port/8] &
			    ~(1 << (port % 8));
		}
		rw_exit(&sp->session_remote_portmap_lock);
		break;
	}

	return (ret);
}

static void
rds_mark_all_ports(rds_session_t *sp, uint_t qualifier)
{
	switch (qualifier) {
	case RDS_LOOPBACK: /* loopback */
		rw_enter(&rds_loopback_portmap_lock, RW_WRITER);
		(void) memset(rds_loopback_portmap, 0xFF, RDS_PORT_MAP_SIZE);
		rw_exit(&rds_loopback_portmap_lock);
		break;

	case RDS_LOCAL: /* Session local */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_local_portmap_lock, RW_WRITER);
		(void) memset(sp->session_local_portmap, 0xFF,
		    RDS_PORT_MAP_SIZE);
		rw_exit(&sp->session_local_portmap_lock);
		break;

	case RDS_REMOTE: /* Session remote */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_remote_portmap_lock, RW_WRITER);
		(void) memset(sp->session_remote_portmap, 0xFF,
		    RDS_PORT_MAP_SIZE);
		rw_exit(&sp->session_remote_portmap_lock);
		break;
	}
}

static void
rds_unmark_all_ports(rds_session_t *sp, uint_t qualifier)
{
	switch (qualifier) {
	case RDS_LOOPBACK: /* loopback */
		rw_enter(&rds_loopback_portmap_lock, RW_WRITER);
		bzero(rds_loopback_portmap, RDS_PORT_MAP_SIZE);
		rw_exit(&rds_loopback_portmap_lock);
		break;

	case RDS_LOCAL: /* Session local */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_local_portmap_lock, RW_WRITER);
		bzero(sp->session_local_portmap, RDS_PORT_MAP_SIZE);
		rw_exit(&sp->session_local_portmap_lock);
		break;

	case RDS_REMOTE: /* Session remote */
		ASSERT(sp != NULL);
		rw_enter(&sp->session_remote_portmap_lock, RW_WRITER);
		bzero(sp->session_remote_portmap, RDS_PORT_MAP_SIZE);
		rw_exit(&sp->session_remote_portmap_lock);
		break;
	}
}

static boolean_t
rds_add_session(rds_session_t *sp, boolean_t locked)
{
	boolean_t retval = B_TRUE;

	RDS_DPRINTF2("rds_add_session", "Enter: SP(%p)", sp);

	if (!locked) {
		rw_enter(&rdsib_statep->rds_sessionlock, RW_WRITER);
	}

	/* Don't allow more sessions than configured in rdsib.conf */
	if (rdsib_statep->rds_nsessions >= (MaxNodes - 1)) {
		RDS_DPRINTF1("rds_add_session", "Max session limit reached");
		retval = B_FALSE;
	} else {
		sp->session_nextp = rdsib_statep->rds_sessionlistp;
		rdsib_statep->rds_sessionlistp = sp;
		rdsib_statep->rds_nsessions++;
		RDS_INCR_SESS();
	}

	if (!locked) {
		rw_exit(&rdsib_statep->rds_sessionlock);
	}

	RDS_DPRINTF2("rds_add_session", "Return: SP(%p)", sp);

	return (retval);
}

/* Session lookup based on destination IP or destination node guid */
rds_session_t *
rds_session_lkup(rds_state_t *statep, ipaddr_t remoteip, ib_guid_t node_guid)
{
	rds_session_t	*sp;

	RDS_DPRINTF4("rds_session_lkup", "Enter: 0x%p 0x%x 0x%llx", statep,
	    remoteip, node_guid);

	/* A read/write lock is expected, will panic if none of them are held */
	ASSERT(rw_lock_held(&statep->rds_sessionlock));
	sp = statep->rds_sessionlistp;
	while (sp) {
		if ((sp->session_remip == remoteip) || ((node_guid != 0) &&
		    (sp->session_rgid.gid_guid == node_guid))) {
			break;
		}

		sp = sp->session_nextp;
	}

	RDS_DPRINTF4("rds_session_lkup", "Return: SP(%p)", sp);

	return (sp);
}

boolean_t
rds_session_lkup_by_sp(rds_session_t *sp)
{
	rds_session_t *sessionp;

	RDS_DPRINTF4("rds_session_lkup_by_sp", "Enter: 0x%p", sp);

	rw_enter(&rdsib_statep->rds_sessionlock, RW_READER);
	sessionp = rdsib_statep->rds_sessionlistp;
	while (sessionp) {
		if (sessionp == sp) {
			rw_exit(&rdsib_statep->rds_sessionlock);
			return (B_TRUE);
		}

		sessionp = sessionp->session_nextp;
	}
	rw_exit(&rdsib_statep->rds_sessionlock);

	return (B_FALSE);
}

static void
rds_ep_fini(rds_ep_t *ep)
{
	RDS_DPRINTF3("rds_ep_fini", "Enter: EP(%p) type: %d", ep, ep->ep_type);

	/* free send pool */
	rds_free_send_pool(ep);

	/* free recv pool */
	rds_free_recv_pool(ep);

	mutex_enter(&ep->ep_lock);
	ep->ep_hca_guid = 0;
	mutex_exit(&ep->ep_lock);

	RDS_DPRINTF3("rds_ep_fini", "Return EP(%p)", ep);
}

/* Assumes SP write lock is held */
int
rds_ep_init(rds_ep_t *ep, ib_guid_t hca_guid)
{
	uint_t		ret;

	RDS_DPRINTF3("rds_ep_init", "Enter: EP(%p) Type: %d", ep, ep->ep_type);

	/* send pool */
	ret = rds_init_send_pool(ep, hca_guid);
	if (ret != 0) {
		RDS_DPRINTF2(LABEL, "EP(%p): rds_init_send_pool failed: %d",
		    ep, ret);
		return (-1);
	}

	/* recv pool */
	ret = rds_init_recv_pool(ep);
	if (ret != 0) {
		RDS_DPRINTF2(LABEL, "EP(%p): rds_init_recv_pool failed: %d",
		    ep, ret);
		rds_free_send_pool(ep);
		return (-1);
	}

	/* reset the ep state */
	mutex_enter(&ep->ep_lock);
	ep->ep_state = RDS_EP_STATE_UNCONNECTED;
	ep->ep_hca_guid = hca_guid;
	ep->ep_lbufid = 0;
	ep->ep_rbufid = 0;
	ep->ep_segfbp = NULL;
	ep->ep_seglbp = NULL;

	/* Initialize the WR to send acknowledgements */
	ep->ep_ackwr.wr_id = RDS_RDMAW_WRID;
	ep->ep_ackwr.wr_flags = IBT_WR_SEND_SOLICIT;
	ep->ep_ackwr.wr_trans = IBT_RC_SRV;
	ep->ep_ackwr.wr_opcode = IBT_WRC_RDMAW;
	ep->ep_ackwr.wr_nds = 1;
	ep->ep_ackwr.wr_sgl = &ep->ep_ackds;
	ep->ep_ackwr.wr.rc.rcwr.rdma.rdma_raddr = 0;
	ep->ep_ackwr.wr.rc.rcwr.rdma.rdma_rkey = 0;
	mutex_exit(&ep->ep_lock);

	RDS_DPRINTF3("rds_ep_init", "Return: EP(%p) type: %d", ep, ep->ep_type);

	return (0);
}

static int
rds_ep_reinit(rds_ep_t *ep, ib_guid_t hca_guid)
{
	int	ret;

	RDS_DPRINTF3("rds_ep_reinit", "Enter: EP(%p) Type: %d",
	    ep, ep->ep_type);

	/* Re-initialize send pool */
	ret = rds_reinit_send_pool(ep, hca_guid);
	if (ret != 0) {
		RDS_DPRINTF2("rds_ep_reinit",
		    "EP(%p): rds_reinit_send_pool failed: %d", ep, ret);
		return (-1);
	}

	/* free all the receive buffers in the pool */
	rds_free_recv_pool(ep);

	RDS_DPRINTF3("rds_ep_reinit", "Return: EP(%p) Type: %d",
	    ep, ep->ep_type);

	return (0);
}

void
rds_session_fini(rds_session_t *sp)
{
	RDS_DPRINTF2("rds_session_fini", "Enter: SP(0x%p)", sp);

	rds_ep_fini(&sp->session_dataep);
	rds_ep_fini(&sp->session_ctrlep);

	RDS_DPRINTF2("rds_session_fini", "Return: SP(0x%p)", sp);
}

/*
 * Allocate and initialize the resources needed for the control and
 * data channels
 */
int
rds_session_init(rds_session_t *sp)
{
	int		ret;
	rds_hca_t	*hcap;
	ib_guid_t	hca_guid;

	RDS_DPRINTF2("rds_session_init", "Enter: SP(0x%p)", sp);

	/* CALLED WITH SESSION WRITE LOCK */

	hcap = rds_gid_to_hcap(rdsib_statep, sp->session_lgid);
	if (hcap == NULL) {
		RDS_DPRINTF2("rds_session_init", "SGID is on an uninitialized "
		    "HCA: %llx", sp->session_lgid.gid_guid);
		return (-1);
	}

	hca_guid = hcap->hca_guid;
	sp->session_hca_guid = hca_guid;

	/* allocate and initialize the ctrl channel */
	ret = rds_ep_init(&sp->session_ctrlep, hca_guid);
	if (ret != 0) {
		RDS_DPRINTF2(LABEL, "SP(%p): Ctrl EP(%p) initialization "
		    "failed", sp, &sp->session_ctrlep);
		return (-1);
	}

	RDS_DPRINTF2(LABEL, "SP(%p) Control EP(%p)", sp, &sp->session_ctrlep);

	/* allocate and initialize the data channel */
	ret = rds_ep_init(&sp->session_dataep, hca_guid);
	if (ret != 0) {
		RDS_DPRINTF2(LABEL, "SP(%p): Data EP(%p) initialization "
		    "failed", sp, &sp->session_dataep);
		rds_ep_fini(&sp->session_ctrlep);
		return (-1);
	}

	/* Clear the portmaps */
	rds_unmark_all_ports(sp, RDS_LOCAL);
	rds_unmark_all_ports(sp, RDS_REMOTE);

	RDS_DPRINTF2(LABEL, "SP(%p) Data EP(%p)", sp, &sp->session_dataep);

	RDS_DPRINTF2("rds_session_init", "Return");

	return (0);
}

/*
 * This should be called before moving a session from ERROR state to
 * INIT state. This will update the HCA keys incase the session has moved from
 * one HCA to another.
 */
int
rds_session_reinit(rds_session_t *sp, ib_gid_t lgid)
{
	rds_hca_t	*hcap, *hcap1;
	int		ret;

	RDS_DPRINTF2("rds_session_reinit", "Enter: SP(0x%p) - state: %d",
	    sp, sp->session_state);

	/* CALLED WITH SESSION WRITE LOCK */

	/* Clear the portmaps */
	rds_unmark_all_ports(sp, RDS_LOCAL);
	rds_unmark_all_ports(sp, RDS_REMOTE);

	/* This should not happen but just a safe guard */
	if (sp->session_dataep.ep_ack_addr == 0) {
		RDS_DPRINTF2("rds_session_reinit",
		    "ERROR: Unexpected: SP(0x%p) - state: %d",
		    sp, sp->session_state);
		return (-1);
	}

	/* make the last buffer as the acknowledged */
	*(uintptr_t *)sp->session_dataep.ep_ack_addr =
	    (uintptr_t)sp->session_dataep.ep_sndpool.pool_tailp;

	hcap = rds_gid_to_hcap(rdsib_statep, lgid);
	if (hcap == NULL) {
		RDS_DPRINTF2("rds_session_reinit", "SGID is on an "
		    "uninitialized HCA: %llx", lgid.gid_guid);
		return (-1);
	}

	hcap1 = rds_gid_to_hcap(rdsib_statep, sp->session_lgid);
	if (hcap1 == NULL) {
		RDS_DPRINTF2("rds_session_reinit", "Seems like HCA %llx "
		    "is unplugged", sp->session_lgid.gid_guid);
	} else if (hcap->hca_guid == hcap1->hca_guid) {
		/*
		 * No action is needed as the session did not move across
		 * HCAs
		 */
		RDS_DPRINTF2("rds_session_reinit", "Failover on the same HCA");
		return (0);
	}

	RDS_DPRINTF2("rds_session_reinit", "Failover across HCAs");

	sp->session_hca_guid = hcap->hca_guid;

	/* re-initialize the control channel */
	ret = rds_ep_reinit(&sp->session_ctrlep, hcap->hca_guid);
	if (ret != 0) {
		RDS_DPRINTF2("rds_session_reinit",
		    "SP(%p): Ctrl EP(%p) re-initialization failed",
		    sp, &sp->session_ctrlep);
		return (-1);
	}

	RDS_DPRINTF2("rds_session_reinit", "SP(%p) Control EP(%p)",
	    sp, &sp->session_ctrlep);

	/* re-initialize the data channel */
	ret = rds_ep_reinit(&sp->session_dataep, hcap->hca_guid);
	if (ret != 0) {
		RDS_DPRINTF2("rds_session_reinit",
		    "SP(%p): Data EP(%p) re-initialization failed",
		    sp, &sp->session_dataep);
		return (-1);
	}

	RDS_DPRINTF2("rds_session_reinit", "SP(%p) Data EP(%p)",
	    sp, &sp->session_dataep);

	sp->session_lgid = lgid;

	RDS_DPRINTF2("rds_session_reinit", "Return: SP(0x%p)", sp);

	return (0);
}

static int
rds_session_connect(rds_session_t *sp)
{
	ibt_channel_hdl_t	ctrlchan, datachan;
	rds_ep_t		*ep;
	int			ret;

	RDS_DPRINTF2("rds_session_connect", "Enter SP(%p)", sp);

	sp->session_pinfo.pi_sid = rdsib_statep->rds_service_id;

	/* Override the packet life time based on the conf file */
	if (IBPktLifeTime != 0) {
		sp->session_pinfo.pi_prim_cep_path.cep_cm_opaque1 =
		    IBPktLifeTime;
	}

	/* Session type may change if we run into peer-to-peer case. */
	rw_enter(&sp->session_lock, RW_READER);
	if (sp->session_type == RDS_SESSION_PASSIVE) {
		RDS_DPRINTF2("rds_session_connect", "SP(%p) is no longer the "
		    "active end", sp);
		rw_exit(&sp->session_lock);
		return (0); /* return success */
	}
	rw_exit(&sp->session_lock);

	/* connect the data ep first */
	ep = &sp->session_dataep;
	mutex_enter(&ep->ep_lock);
	if (ep->ep_state == RDS_EP_STATE_UNCONNECTED) {
		ep->ep_state = RDS_EP_STATE_ACTIVE_PENDING;
		mutex_exit(&ep->ep_lock);
		ret = rds_open_rc_channel(ep, &sp->session_pinfo, IBT_BLOCKING,
		    &datachan);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "EP(%p): rds_open_rc_channel "
			    "failed: %d", ep, ret);
			return (-1);
		}
		sp->session_dataep.ep_chanhdl = datachan;
	} else {
		RDS_DPRINTF2(LABEL, "SP(%p) Data EP(%p) is in "
		    "unexpected state: %d", sp, ep, ep->ep_state);
		mutex_exit(&ep->ep_lock);
		return (-1);
	}

	RDS_DPRINTF3(LABEL, "SP(%p) EP(%p): Data channel is connected",
	    sp, ep);

	ep = &sp->session_ctrlep;
	mutex_enter(&ep->ep_lock);
	if (ep->ep_state == RDS_EP_STATE_UNCONNECTED) {
		ep->ep_state = RDS_EP_STATE_ACTIVE_PENDING;
		mutex_exit(&ep->ep_lock);
		ret = rds_open_rc_channel(ep, &sp->session_pinfo, IBT_BLOCKING,
		    &ctrlchan);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "EP(%p): rds_open_rc_channel "
			    "failed: %d", ep, ret);
			return (-1);
		}
		sp->session_ctrlep.ep_chanhdl = ctrlchan;
	} else {
		RDS_DPRINTF2(LABEL, "SP(%p) Control EP(%p) is in "
		    "unexpected state: %d", sp, ep, ep->ep_state);
		mutex_exit(&ep->ep_lock);
		return (-1);
	}

	RDS_DPRINTF2(LABEL, "Session (%p) 0x%x <--> 0x%x is CONNECTED",
	    sp, sp->session_myip, sp->session_remip);

	RDS_DPRINTF2("rds_session_connect", "Return SP(%p)", sp);

	return (0);
}

/*
 * Can be called with or without session_lock.
 */
void
rds_session_close(rds_session_t *sp, ibt_execution_mode_t mode, uint_t wait)
{
	rds_ep_t		*ep;

	RDS_DPRINTF2("rds_session_close", "SP(%p) State: %d", sp,
	    sp->session_state);

	ep = &sp->session_dataep;
	RDS_DPRINTF3(LABEL, "EP(%p) State: %d", ep, ep->ep_state);

	/* wait until the SQ is empty before closing */
	if (wait != 0) {
		(void) rds_is_sendq_empty(ep, wait);
	}

	mutex_enter(&ep->ep_lock);
	while (ep->ep_state == RDS_EP_STATE_CLOSING) {
		mutex_exit(&ep->ep_lock);
		delay(drv_usectohz(300000));
		mutex_enter(&ep->ep_lock);
	}

	if (ep->ep_state == RDS_EP_STATE_CONNECTED) {
		ep->ep_state = RDS_EP_STATE_CLOSING;
		mutex_exit(&ep->ep_lock);
		(void) rds_close_rc_channel(ep->ep_chanhdl, mode);
		if (wait == 0) {
			/* make sure all WCs are flushed before proceeding */
			(void) rds_is_sendq_empty(ep, 1);
		}
		mutex_enter(&ep->ep_lock);
	}
	rds_ep_free_rc_channel(ep);
	ep->ep_state = RDS_EP_STATE_UNCONNECTED;
	ep->ep_segfbp = NULL;
	ep->ep_seglbp = NULL;
	mutex_exit(&ep->ep_lock);

	ep = &sp->session_ctrlep;
	RDS_DPRINTF3(LABEL, "EP(%p) State: %d", ep, ep->ep_state);

	/* wait until the SQ is empty before closing */
	if (wait != 0) {
		(void) rds_is_sendq_empty(ep, wait);
	}

	mutex_enter(&ep->ep_lock);
	while (ep->ep_state == RDS_EP_STATE_CLOSING) {
		mutex_exit(&ep->ep_lock);
		delay(drv_usectohz(300000));
		mutex_enter(&ep->ep_lock);
	}

	if (ep->ep_state == RDS_EP_STATE_CONNECTED) {
		ep->ep_state = RDS_EP_STATE_CLOSING;
		mutex_exit(&ep->ep_lock);
		(void) rds_close_rc_channel(ep->ep_chanhdl, mode);
		if (wait == 0) {
			/* make sure all WCs are flushed before proceeding */
			(void) rds_is_sendq_empty(ep, 1);
		}
		mutex_enter(&ep->ep_lock);
	}
	rds_ep_free_rc_channel(ep);
	ep->ep_state = RDS_EP_STATE_UNCONNECTED;
	ep->ep_segfbp = NULL;
	ep->ep_seglbp = NULL;
	mutex_exit(&ep->ep_lock);

	RDS_DPRINTF2("rds_session_close", "Return (%p)", sp);
}

/* Free the session */
static void
rds_destroy_session(rds_session_t *sp)
{
	rds_ep_t	*ep;
	rds_bufpool_t	*pool;

	ASSERT((sp->session_state == RDS_SESSION_STATE_CLOSED) ||
	    (sp->session_state == RDS_SESSION_STATE_FAILED) ||
	    (sp->session_state == RDS_SESSION_STATE_FINI) ||
	    (sp->session_state == RDS_SESSION_STATE_PASSIVE_CLOSING));

	rw_enter(&sp->session_lock, RW_READER);
	RDS_DPRINTF2("rds_destroy_session", "SP(%p) State: %d", sp,
	    sp->session_state);
	while (!((sp->session_state == RDS_SESSION_STATE_CLOSED) ||
	    (sp->session_state == RDS_SESSION_STATE_FAILED) ||
	    (sp->session_state == RDS_SESSION_STATE_FINI))) {
		rw_exit(&sp->session_lock);
		delay(drv_usectohz(1000000));
		rw_enter(&sp->session_lock, RW_READER);
		RDS_DPRINTF2("rds_destroy_session", "SP(%p) State: %d WAITING "
		    "ON SESSION", sp, sp->session_state);
	}
	rw_exit(&sp->session_lock);

	/* data channel */
	ep = &sp->session_dataep;

	/* send pool locks */
	pool = &ep->ep_sndpool;
	cv_destroy(&pool->pool_cv);
	mutex_destroy(&pool->pool_lock);

	/* recv pool locks */
	pool = &ep->ep_rcvpool;
	cv_destroy(&pool->pool_cv);
	mutex_destroy(&pool->pool_lock);
	mutex_destroy(&ep->ep_recvqp.qp_lock);

	/* control channel */
	ep = &sp->session_ctrlep;

	/* send pool locks */
	pool = &ep->ep_sndpool;
	cv_destroy(&pool->pool_cv);
	mutex_destroy(&pool->pool_lock);

	/* recv pool locks */
	pool = &ep->ep_rcvpool;
	cv_destroy(&pool->pool_cv);
	mutex_destroy(&pool->pool_lock);
	mutex_destroy(&ep->ep_recvqp.qp_lock);

	/* session */
	rw_destroy(&sp->session_lock);
	rw_destroy(&sp->session_local_portmap_lock);
	rw_destroy(&sp->session_remote_portmap_lock);

	/* free the session */
	kmem_free(sp, sizeof (rds_session_t));

	RDS_DPRINTF2("rds_destroy_session", "SP(%p) Return", sp);
}

/* This is called on the taskq thread */
void
rds_failover_session(void *arg)
{
	rds_session_t	*sp = (rds_session_t *)arg;
	ib_gid_t	lgid, rgid;
	ipaddr_t	myip, remip;
	int		ret, cnt = 0;
	uint8_t		sp_state;

	RDS_DPRINTF2("rds_failover_session", "Enter: (%p)", sp);

	/* Make sure the session is still alive */
	if (rds_session_lkup_by_sp(sp) == B_FALSE) {
		RDS_DPRINTF2("rds_failover_session",
		    "Return: SP(%p) not ALIVE", sp);
		return;
	}

	RDS_INCR_FAILOVERS();

	rw_enter(&sp->session_lock, RW_WRITER);
	if (sp->session_type != RDS_SESSION_ACTIVE) {
		/*
		 * The remote side must have seen the error and initiated
		 * a re-connect.
		 */
		RDS_DPRINTF2("rds_failover_session",
		    "SP(%p) has become passive", sp);
		rw_exit(&sp->session_lock);
		return;
	}
	sp->session_failover = 1;
	sp_state = sp->session_state;
	rw_exit(&sp->session_lock);

	/*
	 * The session is in ERROR state but close both channels
	 * for a clean start.
	 */
	if (sp_state == RDS_SESSION_STATE_ERROR) {
		rds_session_close(sp, IBT_BLOCKING, 1);
	}

	/* wait 1 sec before re-connecting */
	delay(drv_usectohz(1000000));

	do {
		ibt_ip_path_attr_t	ipattr;
		ibt_ip_addr_t		dstip;

		/* The ipaddr should be in the network order */
		myip = sp->session_myip;
		remip = sp->session_remip;
		ret = rds_sc_path_lookup(&myip, &remip);
		if (ret == 0) {
			RDS_DPRINTF2(LABEL, "Path not found (0x%x 0x%x)",
			    myip, remip);
		}
		/* check if we have (new) path from the source to destination */
		lgid.gid_prefix = 0;
		lgid.gid_guid = 0;
		rgid.gid_prefix = 0;
		rgid.gid_guid = 0;

		bzero(&ipattr, sizeof (ibt_ip_path_attr_t));
		dstip.family = AF_INET;
		dstip.un.ip4addr = remip;
		ipattr.ipa_dst_ip = &dstip;
		ipattr.ipa_src_ip.family = AF_INET;
		ipattr.ipa_src_ip.un.ip4addr = myip;
		ipattr.ipa_ndst = 1;
		ipattr.ipa_max_paths = 1;
		RDS_DPRINTF2(LABEL, "ibt_get_ip_paths: 0x%x <-> 0x%x ",
		    myip, remip);
		ret = ibt_get_ip_paths(rdsib_statep->rds_ibhdl,
		    IBT_PATH_NO_FLAGS, &ipattr, &sp->session_pinfo, NULL, NULL);
		if (ret == IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "ibt_get_ip_paths success");
			lgid = sp->session_pinfo.
			    pi_prim_cep_path.cep_adds_vect.av_sgid;
			rgid = sp->session_pinfo.
			    pi_prim_cep_path.cep_adds_vect.av_dgid;
			break;
		}

		RDS_DPRINTF2(LABEL, "ibt_get_ip_paths failed, ret: %d ", ret);

		/* wait 1 sec before re-trying */
		delay(drv_usectohz(1000000));
		cnt++;
	} while (cnt < 5);

	if (ret != IBT_SUCCESS) {
		rw_enter(&sp->session_lock, RW_WRITER);
		if (sp->session_type == RDS_SESSION_ACTIVE) {
			rds_session_fini(sp);
			sp->session_state = RDS_SESSION_STATE_FAILED;
			sp->session_failover = 0;
			RDS_DPRINTF3("rds_failover_session",
			    "SP(%p) State RDS_SESSION_STATE_FAILED", sp);
		} else {
			RDS_DPRINTF2("rds_failover_session",
			    "SP(%p) has become passive", sp);
		}
		rw_exit(&sp->session_lock);
		return;
	}

	RDS_DPRINTF2(LABEL, "lgid: %llx:%llx rgid: %llx:%llx",
	    lgid.gid_prefix, lgid.gid_guid, rgid.gid_prefix,
	    rgid.gid_guid);

	rw_enter(&sp->session_lock, RW_WRITER);
	if (sp->session_type != RDS_SESSION_ACTIVE) {
		/*
		 * The remote side must have seen the error and initiated
		 * a re-connect.
		 */
		RDS_DPRINTF2("rds_failover_session",
		    "SP(%p) has become passive", sp);
		rw_exit(&sp->session_lock);
		return;
	}

	/* move the session to init state */
	ret = rds_session_reinit(sp, lgid);
	sp->session_lgid = lgid;
	sp->session_rgid = rgid;
	if (ret != 0) {
		rds_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FAILED;
		sp->session_failover = 0;
		RDS_DPRINTF3("rds_failover_session",
		    "SP(%p) State RDS_SESSION_STATE_FAILED", sp);
		rw_exit(&sp->session_lock);
		return;
	} else {
		sp->session_state = RDS_SESSION_STATE_INIT;
		RDS_DPRINTF3("rds_failover_session",
		    "SP(%p) State RDS_SESSION_STATE_INIT", sp);
	}
	rw_exit(&sp->session_lock);

	rds_session_open(sp);

	RDS_DPRINTF2("rds_failover_session", "Return: (%p)", sp);
}

void
rds_handle_send_error(rds_ep_t *ep)
{
	if (rds_is_sendq_empty(ep, 0)) {
		/* Session should already be in ERROR, try to reconnect */
		RDS_DPRINTF2("rds_handle_send_error",
		    "Dispatching taskq to failover SP(%p)", ep->ep_sp);
		(void) ddi_taskq_dispatch(rds_taskq, rds_failover_session,
		    (void *)ep->ep_sp, DDI_SLEEP);
	}
}

/*
 * Called in the CM handler on the passive side
 * Called on a taskq thread.
 */
void
rds_cleanup_passive_session(void *arg)
{
	rds_session_t	*sp = arg;

	RDS_DPRINTF2("rds_cleanup_passive_session", "SP(%p) State: %d", sp,
	    sp->session_state);
	ASSERT((sp->session_state == RDS_SESSION_STATE_CLOSED) ||
	    (sp->session_state == RDS_SESSION_STATE_ERROR));

	rds_session_close(sp, IBT_BLOCKING, 1);

	rw_enter(&sp->session_lock, RW_WRITER);
	if (sp->session_state == RDS_SESSION_STATE_CLOSED) {
		rds_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FINI;
		sp->session_failover = 0;
		RDS_DPRINTF3("rds_cleanup_passive_session",
		    "SP(%p) State RDS_SESSION_STATE_FINI", sp);
	} else if (sp->session_state == RDS_SESSION_STATE_ERROR) {
		rds_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FAILED;
		sp->session_failover = 0;
		RDS_DPRINTF3("rds_cleanup_passive_session",
		    "SP(%p) State RDS_SESSION_STATE_FAILED", sp);
	}
	rw_exit(&sp->session_lock);

	RDS_DPRINTF2("rds_cleanup_passive_session", "Return: SP (%p)", sp);
}

/*
 * Called by the CM handler on the passive side
 * Called with WRITE lock on the session
 */
void
rds_passive_session_fini(rds_session_t *sp)
{
	rds_ep_t	*ep;

	RDS_DPRINTF2("rds_passive_session_fini", "SP(%p) State: %d", sp,
	    sp->session_state);
	ASSERT((sp->session_state == RDS_SESSION_STATE_CLOSED) ||
	    (sp->session_state == RDS_SESSION_STATE_ERROR));

	/* clean the data channel */
	ep = &sp->session_dataep;
	(void) rds_is_sendq_empty(ep, 1);
	mutex_enter(&ep->ep_lock);
	RDS_DPRINTF2("rds_passive_session_fini", "EP(%p) State: %d", ep,
	    ep->ep_state);
	rds_ep_free_rc_channel(ep);
	mutex_exit(&ep->ep_lock);

	/* clean the control channel */
	ep = &sp->session_ctrlep;
	(void) rds_is_sendq_empty(ep, 1);
	mutex_enter(&ep->ep_lock);
	RDS_DPRINTF2("rds_passive_session_fini", "EP(%p) State: %d", ep,
	    ep->ep_state);
	rds_ep_free_rc_channel(ep);
	mutex_exit(&ep->ep_lock);

	rds_session_fini(sp);
	sp->session_failover = 0;

	RDS_DPRINTF2("rds_passive_session_fini", "Return: SP (%p)", sp);
}

void
rds_close_this_session(rds_session_t *sp, uint8_t wait)
{
	switch (sp->session_state) {
	case RDS_SESSION_STATE_CONNECTED:
		sp->session_state = RDS_SESSION_STATE_ACTIVE_CLOSING;
		rw_exit(&sp->session_lock);

		rds_session_close(sp, IBT_BLOCKING, wait);

		rw_enter(&sp->session_lock, RW_WRITER);
		sp->session_state = RDS_SESSION_STATE_CLOSED;
		RDS_DPRINTF3("rds_close_sessions",
		    "SP(%p) State RDS_SESSION_STATE_CLOSED", sp);
		rds_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FINI;
		sp->session_failover = 0;
		RDS_DPRINTF3("rds_close_sessions",
		    "SP(%p) State RDS_SESSION_STATE_FINI", sp);
		break;

	case RDS_SESSION_STATE_ERROR:
	case RDS_SESSION_STATE_PASSIVE_CLOSING:
	case RDS_SESSION_STATE_INIT:
		sp->session_state = RDS_SESSION_STATE_ACTIVE_CLOSING;
		rw_exit(&sp->session_lock);

		rds_session_close(sp, IBT_BLOCKING, wait);

		rw_enter(&sp->session_lock, RW_WRITER);
		sp->session_state = RDS_SESSION_STATE_CLOSED;
		RDS_DPRINTF3("rds_close_sessions",
		    "SP(%p) State RDS_SESSION_STATE_CLOSED", sp);
		/* FALLTHRU */
	case RDS_SESSION_STATE_CLOSED:
		rds_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FINI;
		sp->session_failover = 0;
		RDS_DPRINTF3("rds_close_sessions",
		    "SP(%p) State RDS_SESSION_STATE_FINI", sp);
		break;
	}
}

/*
 * Can be called:
 * 1. on driver detach
 * 2. on taskq thread
 * arg is always NULL
 */
/* ARGSUSED */
void
rds_close_sessions(void *arg)
{
	rds_session_t *sp, *spnextp;

	RDS_DPRINTF2("rds_close_sessions", "Enter");

	/* wait until all the buffers are freed by the sockets */
	while (RDS_GET_RXPKTS_PEND() != 0) {
		/* wait one second and try again */
		RDS_DPRINTF2("rds_close_sessions", "waiting on "
		    "pending packets", RDS_GET_RXPKTS_PEND());
		delay(drv_usectohz(1000000));
	}
	RDS_DPRINTF2("rds_close_sessions", "No more RX packets pending");

	/* close all the sessions */
	rw_enter(&rdsib_statep->rds_sessionlock, RW_WRITER);
	sp = rdsib_statep->rds_sessionlistp;
	while (sp) {
		rw_enter(&sp->session_lock, RW_WRITER);
		RDS_DPRINTF2("rds_close_sessions", "SP(%p) State: %d", sp,
		    sp->session_state);
		rds_close_this_session(sp, 2);
		rw_exit(&sp->session_lock);
		sp = sp->session_nextp;
	}

	sp = rdsib_statep->rds_sessionlistp;
	rdsib_statep->rds_sessionlistp = NULL;
	rdsib_statep->rds_nsessions = 0;
	rw_exit(&rdsib_statep->rds_sessionlock);

	while (sp) {
		spnextp = sp->session_nextp;
		rds_destroy_session(sp);
		RDS_DECR_SESS();
		sp = spnextp;
	}

	/* free the global pool */
	rds_free_recv_caches(rdsib_statep);

	RDS_DPRINTF2("rds_close_sessions", "Return");
}

void
rds_session_open(rds_session_t *sp)
{
	int		ret;

	RDS_DPRINTF2("rds_session_open", "Enter SP(%p)", sp);

	ret = rds_session_connect(sp);
	if (ret == -1) {
		/*
		 * may be the session has become passive due to
		 * hitting peer-to-peer case
		 */
		rw_enter(&sp->session_lock, RW_READER);
		if (sp->session_type == RDS_SESSION_PASSIVE) {
			RDS_DPRINTF2("rds_session_open", "SP(%p) "
			    "has become passive from active", sp);
			rw_exit(&sp->session_lock);
			return;
		}

		/* get the lock for writing */
		rw_exit(&sp->session_lock);
		rw_enter(&sp->session_lock, RW_WRITER);
		sp->session_state = RDS_SESSION_STATE_ERROR;
		RDS_DPRINTF3("rds_session_open",
		    "SP(%p) State RDS_SESSION_STATE_ERROR", sp);
		rw_exit(&sp->session_lock);

		/* Connect request failed */
		rds_session_close(sp, IBT_BLOCKING, 1);

		rw_enter(&sp->session_lock, RW_WRITER);
		rds_session_fini(sp);
		sp->session_state = RDS_SESSION_STATE_FAILED;
		sp->session_failover = 0;
		RDS_DPRINTF3("rds_session_open",
		    "SP(%p) State RDS_SESSION_STATE_FAILED", sp);
		rw_exit(&sp->session_lock);

		return;
	}

	RDS_DPRINTF2("rds_session_open", "Return: SP(%p)", sp);
}

/*
 * Creates a session and inserts it into the list of sessions. The session
 * state would be CREATED.
 * Return Values:
 *	EWOULDBLOCK
 */
rds_session_t *
rds_session_create(rds_state_t *statep, ipaddr_t localip, ipaddr_t remip,
    ibt_cm_req_rcv_t *reqp, uint8_t type)
{
	ib_gid_t	lgid, rgid;
	rds_session_t	*newp, *oldp;
	rds_ep_t	*dataep, *ctrlep;
	rds_bufpool_t	*pool;
	int		ret;

	RDS_DPRINTF2("rds_session_create", "Enter: 0x%p 0x%x 0x%x, type: %d",
	    statep, localip, remip, type);

	/* Check if there is space for a new session */
	rw_enter(&statep->rds_sessionlock, RW_READER);
	if (statep->rds_nsessions >= (MaxNodes - 1)) {
		rw_exit(&statep->rds_sessionlock);
		RDS_DPRINTF1("rds_session_create", "No More Sessions allowed");
		return (NULL);
	}
	rw_exit(&statep->rds_sessionlock);

	/* Allocate and initialize global buffer pool */
	ret = rds_init_recv_caches(statep);
	if (ret != 0) {
		RDS_DPRINTF2(LABEL, "Buffer Cache Initialization failed");
		return (NULL);
	}

	/* enough memory for session (includes 2 endpoints) */
	newp = kmem_zalloc(sizeof (rds_session_t), KM_SLEEP);

	newp->session_remip = remip;
	newp->session_myip = localip;
	newp->session_type = type;
	newp->session_state = RDS_SESSION_STATE_CREATED;
	RDS_DPRINTF3("rds_session_create",
	    "SP(%p) State RDS_SESSION_STATE_CREATED", newp);
	rw_init(&newp->session_lock, NULL, RW_DRIVER, NULL);
	rw_init(&newp->session_local_portmap_lock, NULL, RW_DRIVER, NULL);
	rw_init(&newp->session_remote_portmap_lock, NULL, RW_DRIVER, NULL);

	/* Initialize data endpoint */
	dataep = &newp->session_dataep;
	dataep->ep_remip = newp->session_remip;
	dataep->ep_myip = newp->session_myip;
	dataep->ep_state = RDS_EP_STATE_UNCONNECTED;
	dataep->ep_sp = newp;
	dataep->ep_type = RDS_EP_TYPE_DATA;
	mutex_init(&dataep->ep_lock, NULL, MUTEX_DRIVER, NULL);

	/* Initialize send pool locks */
	pool = &dataep->ep_sndpool;
	mutex_init(&pool->pool_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&pool->pool_cv, NULL, CV_DRIVER, NULL);

	/* Initialize recv pool locks */
	pool = &dataep->ep_rcvpool;
	mutex_init(&dataep->ep_recvqp.qp_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pool->pool_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&pool->pool_cv, NULL, CV_DRIVER, NULL);

	/* Initialize control endpoint */
	ctrlep = &newp->session_ctrlep;
	ctrlep->ep_remip = newp->session_remip;
	ctrlep->ep_myip = newp->session_myip;
	ctrlep->ep_state = RDS_EP_STATE_UNCONNECTED;
	ctrlep->ep_sp = newp;
	ctrlep->ep_type = RDS_EP_TYPE_CTRL;
	mutex_init(&ctrlep->ep_lock, NULL, MUTEX_DRIVER, NULL);

	/* Initialize send pool locks */
	pool = &ctrlep->ep_sndpool;
	mutex_init(&pool->pool_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&pool->pool_cv, NULL, CV_DRIVER, NULL);

	/* Initialize recv pool locks */
	pool = &ctrlep->ep_rcvpool;
	mutex_init(&ctrlep->ep_recvqp.qp_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pool->pool_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&pool->pool_cv, NULL, CV_DRIVER, NULL);

	/* lkup if there is already a session */
	rw_enter(&statep->rds_sessionlock, RW_WRITER);
	oldp = rds_session_lkup(statep, remip, 0);
	if (oldp != NULL) {
		/* A session to this destination exists */
		rw_exit(&statep->rds_sessionlock);
		rw_destroy(&newp->session_lock);
		rw_destroy(&newp->session_local_portmap_lock);
		rw_destroy(&newp->session_remote_portmap_lock);
		mutex_destroy(&dataep->ep_lock);
		mutex_destroy(&ctrlep->ep_lock);
		kmem_free(newp, sizeof (rds_session_t));
		return (NULL);
	}

	/* Insert this session into the list */
	if (rds_add_session(newp, B_TRUE) != B_TRUE) {
		/* No room to add this session */
		rw_exit(&statep->rds_sessionlock);
		rw_destroy(&newp->session_lock);
		rw_destroy(&newp->session_local_portmap_lock);
		rw_destroy(&newp->session_remote_portmap_lock);
		mutex_destroy(&dataep->ep_lock);
		mutex_destroy(&ctrlep->ep_lock);
		kmem_free(newp, sizeof (rds_session_t));
		return (NULL);
	}

	/* unlock the session list */
	rw_exit(&statep->rds_sessionlock);

	if (type == RDS_SESSION_ACTIVE) {
		ipaddr_t		localip1, remip1;
		ibt_ip_path_attr_t	ipattr;
		ibt_ip_addr_t		dstip;

		/* The ipaddr should be in the network order */
		localip1 = localip;
		remip1 = remip;
		ret = rds_sc_path_lookup(&localip1, &remip1);
		if (ret == 0) {
			RDS_DPRINTF2(LABEL, "Path not found (0x%x 0x%x)",
			    localip, remip);
		}

		/* Get the gids for the source and destination ip addrs */
		lgid.gid_prefix = 0;
		lgid.gid_guid = 0;
		rgid.gid_prefix = 0;
		rgid.gid_guid = 0;

		bzero(&ipattr, sizeof (ibt_ip_path_attr_t));
		dstip.family = AF_INET;
		dstip.un.ip4addr = remip1;
		ipattr.ipa_dst_ip = &dstip;
		ipattr.ipa_src_ip.family = AF_INET;
		ipattr.ipa_src_ip.un.ip4addr = localip1;
		ipattr.ipa_ndst = 1;
		ipattr.ipa_max_paths = 1;
		RDS_DPRINTF2(LABEL, "ibt_get_ip_paths: 0x%x <-> 0x%x ",
		    localip1, remip1);
		ret = ibt_get_ip_paths(rdsib_statep->rds_ibhdl,
		    IBT_PATH_NO_FLAGS, &ipattr, &newp->session_pinfo,
		    NULL, NULL);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "ibt_get_ip_paths failed, ret: %d "
			    "lgid: %llx:%llx rgid: %llx:%llx", lgid.gid_prefix,
			    lgid.gid_guid, rgid.gid_prefix, rgid.gid_guid);

			RDS_SESSION_TRANSITION(newp, RDS_SESSION_STATE_FAILED);
			return (NULL);
		}
		RDS_DPRINTF2(LABEL, "ibt_get_ip_paths success");
		lgid =
		    newp->session_pinfo.pi_prim_cep_path.cep_adds_vect.av_sgid;
		rgid =
		    newp->session_pinfo.pi_prim_cep_path.cep_adds_vect.av_dgid;

		RDS_DPRINTF2(LABEL, "lgid: %llx:%llx rgid: %llx:%llx",
		    lgid.gid_prefix, lgid.gid_guid, rgid.gid_prefix,
		    rgid.gid_guid);
	}

	rw_enter(&newp->session_lock, RW_WRITER);
	/* check for peer-to-peer case */
	if (type == newp->session_type) {
		/* no peer-to-peer case */
		if (type == RDS_SESSION_ACTIVE) {
			newp->session_lgid = lgid;
			newp->session_rgid = rgid;
		} else {
			/* rgid is requester gid & lgid is receiver gid */
			newp->session_rgid = reqp->req_prim_addr.av_dgid;
			newp->session_lgid = reqp->req_prim_addr.av_sgid;
		}
	}
	rw_exit(&newp->session_lock);

	RDS_DPRINTF2("rds_session_create", "Return SP(%p)", newp);

	return (newp);
}

void
rds_handle_close_session_request(void *arg)
{
	rds_session_t	*sp = (rds_session_t *)arg;

	RDS_DPRINTF2("rds_handle_close_session_request",
	    "Enter: Closing this Session (%p)", sp);

	rw_enter(&sp->session_lock, RW_WRITER);
	RDS_DPRINTF2("rds_handle_close_session_request",
	    "SP(%p) State: %d", sp, sp->session_state);
	rds_close_this_session(sp, 2);
	rw_exit(&sp->session_lock);

	RDS_DPRINTF2("rds_handle_close_session_request", "Return SP(%p)", sp);
}

void
rds_handle_control_message(rds_session_t *sp, rds_ctrl_pkt_t *cpkt)
{
	RDS_DPRINTF4("rds_handle_control_message", "Enter: SP(%p) code: %d "
	    "port: %d", sp, cpkt->rcp_code, cpkt->rcp_port);

	switch (cpkt->rcp_code) {
	case RDS_CTRL_CODE_STALL:
		RDS_INCR_STALLS_RCVD();
		(void) rds_check_n_mark_port(sp, cpkt->rcp_port, RDS_REMOTE);
		break;
	case RDS_CTRL_CODE_UNSTALL:
		RDS_INCR_UNSTALLS_RCVD();
		(void) rds_check_n_unmark_port(sp, cpkt->rcp_port, RDS_REMOTE);
		break;
	case RDS_CTRL_CODE_STALL_PORTS:
		rds_mark_all_ports(sp, RDS_REMOTE);
		break;
	case RDS_CTRL_CODE_UNSTALL_PORTS:
		rds_unmark_all_ports(sp, RDS_REMOTE);
		break;
	case RDS_CTRL_CODE_HEARTBEAT:
		break;
	case RDS_CTRL_CODE_CLOSE_SESSION:
		RDS_DPRINTF2("rds_handle_control_message",
		    "SP(%p) Remote Requested to close this session", sp);
		(void) ddi_taskq_dispatch(rds_taskq,
		    rds_handle_close_session_request, (void *)sp, DDI_SLEEP);
		break;
	default:
		RDS_DPRINTF2(LABEL, "ERROR: Invalid Control code: %d",
		    cpkt->rcp_code);
		break;
	}

	RDS_DPRINTF4("rds_handle_control_message", "Return");
}

int
rds_post_control_message(rds_session_t *sp, uint8_t code, in_port_t port)
{
	ibt_send_wr_t	wr;
	rds_ep_t	*ep;
	rds_buf_t	*bp;
	rds_ctrl_pkt_t	*cp;
	int		ret;

	RDS_DPRINTF4("rds_post_control_message", "Enter: SP(%p) Code: %d "
	    "Port: %d", sp, code, port);

	ep = &sp->session_ctrlep;

	bp = rds_get_send_buf(ep, 1);
	if (bp == NULL) {
		RDS_DPRINTF2(LABEL, "No buffers available to send control "
		    "message: SP(%p) Code: %d Port: %d", sp, code,
		    port);
		return (-1);
	}

	cp = (rds_ctrl_pkt_t *)(uintptr_t)bp->buf_ds.ds_va;
	cp->rcp_code = code;
	cp->rcp_port = port;
	bp->buf_ds.ds_len = RDS_CTRLPKT_SIZE;

	wr.wr_id = (uintptr_t)bp;
	wr.wr_flags = IBT_WR_SEND_SOLICIT;
	wr.wr_trans = IBT_RC_SRV;
	wr.wr_opcode = IBT_WRC_SEND;
	wr.wr_nds = 1;
	wr.wr_sgl = &bp->buf_ds;
	RDS_DPRINTF5(LABEL, "ds_va %p ds_len %d ds_lkey 0x%llx",
	    bp->buf_ds.ds_va, bp->buf_ds.ds_len, bp->buf_ds.ds_key);
	ret = ibt_post_send(ep->ep_chanhdl, &wr, 1, NULL);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2(LABEL, "EP(%p): ibt_post_send failed: "
		    "%d", ep, ret);
		bp->buf_state = RDS_SNDBUF_FREE;
		rds_free_send_buf(ep, bp, NULL, 1, B_FALSE);
		return (-1);
	}

	RDS_DPRINTF4("rds_post_control_message", "Return SP(%p) Code: %d "
	    "Port: %d", sp, code, port);

	return (0);
}

void
rds_stall_port(rds_session_t *sp, in_port_t port, uint_t qualifier)
{
	int		ret;

	RDS_DPRINTF4("rds_stall_port", "Enter: SP(%p) Port %d", sp, port);

	RDS_INCR_STALLS_TRIGGERED();

	if (!rds_check_n_mark_port(sp, port, qualifier)) {

		if (sp != NULL) {
			ret = rds_post_control_message(sp,
			    RDS_CTRL_CODE_STALL, port);
			if (ret != 0) {
				(void) rds_check_n_unmark_port(sp, port,
				    qualifier);
				return;
			}
			RDS_INCR_STALLS_SENT();
		}
	} else {
		RDS_DPRINTF3(LABEL,
		    "Port %d is already in stall state", port);
	}

	RDS_DPRINTF4("rds_stall_port", "Return: SP(%p) Port %d", sp, port);
}

void
rds_resume_port(in_port_t port)
{
	rds_session_t	*sp;
	uint_t		ix;
	int		ret;

	RDS_DPRINTF4("rds_resume_port", "Enter: Port %d", port);

	RDS_INCR_UNSTALLS_TRIGGERED();

	/* resume loopback traffic */
	(void) rds_check_n_unmark_port(NULL, port, RDS_LOOPBACK);

	/* send unstall messages to resume the remote traffic */
	rw_enter(&rdsib_statep->rds_sessionlock, RW_READER);

	sp = rdsib_statep->rds_sessionlistp;
	for (ix = 0; ix < rdsib_statep->rds_nsessions; ix++) {
		ASSERT(sp != NULL);
		if ((sp->session_state == RDS_SESSION_STATE_CONNECTED) &&
		    (rds_check_n_unmark_port(sp, port, RDS_LOCAL))) {
				ret = rds_post_control_message(sp,
				    RDS_CTRL_CODE_UNSTALL, port);
				if (ret != 0) {
					(void) rds_check_n_mark_port(sp, port,
					    RDS_LOCAL);
				} else {
					RDS_INCR_UNSTALLS_SENT();
				}
		}

		sp = sp->session_nextp;
	}

	rw_exit(&rdsib_statep->rds_sessionlock);

	RDS_DPRINTF4("rds_resume_port", "Return: Port %d", port);
}

static int
rds_build_n_post_msg(rds_ep_t *ep, uio_t *uiop, in_port_t sendport,
    in_port_t recvport)
{
	ibt_send_wr_t	*wrp, wr;
	rds_buf_t	*bp, *bp1;
	rds_data_hdr_t	*pktp;
	uint32_t	msgsize, npkts, residual, pktno, ix;
	int		ret;

	RDS_DPRINTF4("rds_build_n_post_msg", "Enter: EP(%p) UIOP(%p)",
	    ep, uiop);

	/* how many pkts are needed to carry this msg */
	msgsize = uiop->uio_resid;
	npkts = ((msgsize - 1) / UserBufferSize) + 1;
	residual = ((msgsize - 1) % UserBufferSize) + 1;

	RDS_DPRINTF5(LABEL, "EP(%p) UIOP(%p) msg size: %d npkts: %d", ep, uiop,
	    msgsize, npkts);

	/* Get the buffers needed to post this message */
	bp = rds_get_send_buf(ep, npkts);
	if (bp == NULL) {
		RDS_INCR_ENOBUFS();
		return (ENOBUFS);
	}

	if (npkts > 1) {
		/*
		 * multi-pkt messages are posted at the same time as a list
		 * of WRs
		 */
		wrp = (ibt_send_wr_t *)kmem_zalloc(sizeof (ibt_send_wr_t) *
		    npkts, KM_SLEEP);
	}


	pktno = 0;
	bp1 = bp;
	do {
		/* prepare the header */
		pktp = (rds_data_hdr_t *)(uintptr_t)bp1->buf_ds.ds_va;
		pktp->dh_datalen = UserBufferSize;
		pktp->dh_npkts = npkts - pktno;
		pktp->dh_psn = pktno;
		pktp->dh_sendport = sendport;
		pktp->dh_recvport = recvport;
		bp1->buf_ds.ds_len = RdsPktSize;

		/* copy the data */
		ret = uiomove((uint8_t *)pktp + RDS_DATA_HDR_SZ,
		    UserBufferSize, UIO_WRITE, uiop);
		if (ret != 0) {
			break;
		}

		if (uiop->uio_resid == 0) {
			pktp->dh_datalen = residual;
			bp1->buf_ds.ds_len = residual + RDS_DATA_HDR_SZ;
			break;
		}
		pktno++;
		bp1 = bp1->buf_nextp;
	} while (uiop->uio_resid);

	if (ret) {
		/* uiomove failed */
		RDS_DPRINTF2("rds_build_n_post_msg", "UIO(%p) Move FAILED: %d",
		    uiop, ret);
		if (npkts > 1) {
			kmem_free(wrp, npkts * sizeof (ibt_send_wr_t));
		}
		rds_free_send_buf(ep, bp, NULL, npkts, B_FALSE);
		return (ret);
	}

	if (npkts > 1) {
		/* multi-pkt message */
		RDS_DPRINTF5(LABEL, "EP(%p) Sending Multiple Packets", ep);

		bp1 = bp;
		for (ix = 0; ix < npkts; ix++) {
			wrp[ix].wr_id = (uintptr_t)bp1;
			wrp[ix].wr_flags = IBT_WR_NO_FLAGS;
			wrp[ix].wr_trans = IBT_RC_SRV;
			wrp[ix].wr_opcode = IBT_WRC_SEND;
			wrp[ix].wr_nds = 1;
			wrp[ix].wr_sgl = &bp1->buf_ds;
			bp1 = bp1->buf_nextp;
		}
		wrp[npkts - 1].wr_flags = IBT_WR_SEND_SOLICIT;

		ret = ibt_post_send(ep->ep_chanhdl, wrp, npkts, &ix);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "EP(%p): ibt_post_send failed: "
			    "%d for %d pkts", ep, ret, npkts);
			rds_free_send_buf(ep, bp, NULL, npkts, B_FALSE);
			kmem_free(wrp, npkts * sizeof (ibt_send_wr_t));
			return (ret);
		}

		kmem_free(wrp, npkts * sizeof (ibt_send_wr_t));
	} else {
		/* single pkt */
		RDS_DPRINTF5(LABEL, "EP(%p) Sending Single Packet", ep);
		wr.wr_id = (uintptr_t)bp;
		wr.wr_flags = IBT_WR_SEND_SOLICIT;
		wr.wr_trans = IBT_RC_SRV;
		wr.wr_opcode = IBT_WRC_SEND;
		wr.wr_nds = 1;
		wr.wr_sgl = &bp->buf_ds;
		RDS_DPRINTF5(LABEL, "ds_va %p ds_key 0x%llx ds_len %d ",
		    bp->buf_ds.ds_va, bp->buf_ds.ds_key, bp->buf_ds.ds_len);
		ret = ibt_post_send(ep->ep_chanhdl, &wr, 1, NULL);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "EP(%p): ibt_post_send failed: "
			    "%d", ep, ret);
			rds_free_send_buf(ep, bp, NULL, 1, B_FALSE);
			return (ret);
		}
	}

	RDS_INCR_TXPKTS(npkts);
	RDS_INCR_TXBYTES(msgsize);

	RDS_DPRINTF4("rds_build_n_post_msg", "Return: EP(%p) UIOP(%p)",
	    ep, uiop);

	return (0);
}

static int
rds_deliver_loopback_msg(uio_t *uiop, ipaddr_t recvip, ipaddr_t sendip,
    in_port_t recvport, in_port_t sendport, zoneid_t zoneid)
{
	mblk_t		*mp;
	int		ret;

	RDS_DPRINTF4("rds_deliver_loopback_msg", "Enter");

	RDS_DPRINTF3(LABEL, "Loopback message: sendport: "
	    "%d to recvport: %d", sendport, recvport);

	mp = allocb(uiop->uio_resid, BPRI_MED);
	if (mp == NULL) {
		RDS_DPRINTF2(LABEL, "allocb failed, size: %d\n",
		    uiop->uio_resid);
		return (ENOSPC);
	}
	mp->b_wptr = mp->b_rptr + uiop->uio_resid;

	ret = uiomove(mp->b_rptr, uiop->uio_resid, UIO_WRITE, uiop);
	if (ret) {
		RDS_DPRINTF2(LABEL, "ERROR: uiomove returned: %d", ret);
		freeb(mp);
		return (ret);
	}

	ret = rds_deliver_new_msg(mp, recvip, sendip, recvport, sendport,
	    zoneid);
	if (ret != 0) {
		if (ret == ENOSPC) {
			/*
			 * The message is delivered but cannot take more,
			 * stop further loopback traffic to this port
			 */
			RDS_DPRINTF3("rds_deliver_loopback_msg",
			    "Port %d NO SPACE", recvport);
			rds_stall_port(NULL, recvport, RDS_LOOPBACK);
		} else {
			RDS_DPRINTF2(LABEL, "Loopback message: port %d -> "
			    "port %d failed: %d", sendport, recvport, ret);
			return (ret);
		}
	}

	RDS_DPRINTF4("rds_deliver_loopback_msg", "Return");
	return (0);
}

static void
rds_resend_messages(void *arg)
{
	rds_session_t	*sp = (rds_session_t *)arg;
	rds_ep_t	*ep;
	rds_bufpool_t	*spool;
	rds_buf_t	*bp, *endp, *tmp;
	ibt_send_wr_t	*wrp;
	uint_t		nwr = 0, ix, jx;
	int		ret;

	RDS_DPRINTF2("rds_resend_messages", "Enter: SP(%p)", sp);

	ep = &sp->session_dataep;

	spool = &ep->ep_sndpool;
	mutex_enter(&spool->pool_lock);

	ASSERT(spool->pool_nfree == spool->pool_nbuffers);

	if (ep->ep_lbufid == 0) {
		RDS_DPRINTF2("rds_resend_messages",
		    "SP(%p) Remote session is cleaned up ", sp);
		/*
		 * The remote end cleaned up its session. There may be loss
		 * of messages. Mark all buffers as acknowledged.
		 */
		tmp = spool->pool_tailp;
	} else {
		tmp = (rds_buf_t *)ep->ep_lbufid;
		RDS_DPRINTF2("rds_resend_messages",
		    "SP(%p) Last successful BP(%p) ", sp, tmp);
	}

	endp = spool->pool_tailp;
	bp = spool->pool_headp;
	jx = 0;
	while ((bp != NULL) && (bp != tmp)) {
		bp->buf_state = RDS_SNDBUF_FREE;
		jx++;
		bp = bp->buf_nextp;
	}

	if (bp == NULL) {
		mutex_exit(&spool->pool_lock);
		RDS_DPRINTF2("rds_resend_messages", "Alert: lbufid(%p) is not "
		    "found in the list", tmp);

		rw_enter(&sp->session_lock, RW_WRITER);
		if (sp->session_state == RDS_SESSION_STATE_INIT) {
			sp->session_state = RDS_SESSION_STATE_CONNECTED;
		} else {
			RDS_DPRINTF2("rds_resend_messages", "SP(%p) State: %d "
			    "Expected State: %d", sp, sp->session_state,
			    RDS_SESSION_STATE_CONNECTED);
		}
		sp->session_failover = 0;
		rw_exit(&sp->session_lock);
		return;
	}

	/* Found the match */
	bp->buf_state = RDS_SNDBUF_FREE;
	jx++;

	spool->pool_tailp = bp;
	bp = bp->buf_nextp;
	spool->pool_tailp->buf_nextp = NULL;
	nwr = spool->pool_nfree - jx;
	spool->pool_nfree = jx;
	mutex_exit(&spool->pool_lock);

	RDS_DPRINTF2("rds_resend_messages", "SP(%p): Number of "
	    "bufs (BP %p) to re-send: %d", sp, bp, nwr);

	if (bp) {
		wrp = (ibt_send_wr_t *)kmem_zalloc(sizeof (ibt_send_wr_t) * 100,
		    KM_SLEEP);

		while (nwr) {
			jx = (nwr > 100) ? 100 : nwr;

			tmp = bp;
			for (ix = 0; ix < jx; ix++) {
				bp->buf_state = RDS_SNDBUF_PENDING;
				wrp[ix].wr_id = (uintptr_t)bp;
				wrp[ix].wr_flags = IBT_WR_SEND_SOLICIT;
				wrp[ix].wr_trans = IBT_RC_SRV;
				wrp[ix].wr_opcode = IBT_WRC_SEND;
				wrp[ix].wr_nds = 1;
				wrp[ix].wr_sgl = &bp->buf_ds;
				bp = bp->buf_nextp;
			}

			ret = ibt_post_send(ep->ep_chanhdl, wrp, jx, &ix);
			if (ret != IBT_SUCCESS) {
				RDS_DPRINTF2(LABEL, "EP(%p): ibt_post_send "
				    "failed: %d for % pkts", ep, ret, jx);
				break;
			}

			mutex_enter(&spool->pool_lock);
			spool->pool_nbusy += jx;
			mutex_exit(&spool->pool_lock);

			nwr -= jx;
		}

		kmem_free(wrp, sizeof (ibt_send_wr_t) * 100);

		if (nwr != 0) {

			/*
			 * An error while failover is in progress. Some WRs are
			 * posted while other remain. If any of the posted WRs
			 * complete in error then they would dispatch a taskq to
			 * do a failover. Getting the session lock will prevent
			 * the taskq to wait until we are done here.
			 */
			rw_enter(&sp->session_lock, RW_READER);

			/*
			 * Wait until all the previous WRs are completed and
			 * then queue the remaining, otherwise the order of
			 * the messages may change.
			 */
			(void) rds_is_sendq_empty(ep, 1);

			/* free the remaining buffers */
			rds_free_send_buf(ep, tmp, endp, nwr, B_FALSE);

			rw_exit(&sp->session_lock);
			return;
		}
	}

	rw_enter(&sp->session_lock, RW_WRITER);
	if (sp->session_state == RDS_SESSION_STATE_INIT) {
		sp->session_state = RDS_SESSION_STATE_CONNECTED;
	} else {
		RDS_DPRINTF2("rds_resend_messages", "SP(%p) State: %d "
		    "Expected State: %d", sp, sp->session_state,
		    RDS_SESSION_STATE_CONNECTED);
	}
	sp->session_failover = 0;
	rw_exit(&sp->session_lock);

	RDS_DPRINTF2("rds_resend_messages", "Return: SP(%p)", sp);
}

/*
 * This is called when a channel is connected. Transition the session to
 * CONNECTED state iff both channels are connected.
 */
void
rds_session_active(rds_session_t *sp)
{
	rds_ep_t	*ep;
	uint_t		failover;

	RDS_DPRINTF2("rds_session_active", "Enter: 0x%p", sp);

	rw_enter(&sp->session_lock, RW_READER);

	failover = sp->session_failover;

	/*
	 * we establish the data channel first, so check the control channel
	 * first but make sure it is initialized.
	 */
	ep = &sp->session_ctrlep;
	mutex_enter(&ep->ep_lock);
	if (ep->ep_state != RDS_EP_STATE_CONNECTED) {
		/* the session is not ready yet */
		mutex_exit(&ep->ep_lock);
		rw_exit(&sp->session_lock);
		return;
	}
	mutex_exit(&ep->ep_lock);

	/* control channel is connected, check the data channel */
	ep = &sp->session_dataep;
	mutex_enter(&ep->ep_lock);
	if (ep->ep_state != RDS_EP_STATE_CONNECTED) {
		/* data channel is not yet connected */
		mutex_exit(&ep->ep_lock);
		rw_exit(&sp->session_lock);
		return;
	}
	mutex_exit(&ep->ep_lock);

	if (failover) {
		rw_exit(&sp->session_lock);

		/*
		 * The session has failed over. Previous msgs have to be
		 * re-sent before the session is moved to the connected
		 * state.
		 */
		RDS_DPRINTF2("rds_session_active", "SP(%p) Dispatching taskq "
		    "to re-send messages", sp);
		(void) ddi_taskq_dispatch(rds_taskq,
		    rds_resend_messages, (void *)sp, DDI_SLEEP);
		return;
	}

	/* the session is ready */
	sp->session_state = RDS_SESSION_STATE_CONNECTED;
	RDS_DPRINTF3("rds_session_active",
	    "SP(%p) State RDS_SESSION_STATE_CONNECTED", sp);

	rw_exit(&sp->session_lock);

	RDS_DPRINTF2("rds_session_active", "Return: SP(%p) is CONNECTED", sp);
}

static int
rds_ep_sendmsg(rds_ep_t *ep, uio_t *uiop, in_port_t sendport,
    in_port_t recvport)
{
	int	ret;

	RDS_DPRINTF4("rds_ep_sendmsg", "Enter: EP(%p) sendport: %d recvport: "
	    "%d", ep, sendport, recvport);

	/* make sure the remote port is not stalled */
	if (rds_is_port_marked(ep->ep_sp, recvport, RDS_REMOTE)) {
		RDS_DPRINTF2(LABEL, "SP(%p) Port:%d is in stall state",
		    ep->ep_sp, recvport);
		RDS_INCR_EWOULDBLOCK();
		ret = ENOMEM;
	} else {
		ret = rds_build_n_post_msg(ep, uiop, sendport, recvport);
	}

	RDS_DPRINTF4("rds_ep_sendmsg", "Return: EP(%p)", ep);

	return (ret);
}

/* Send a message to a destination socket */
int
rds_sendmsg(uio_t *uiop, ipaddr_t sendip, ipaddr_t recvip, in_port_t sendport,
    in_port_t recvport, zoneid_t zoneid)
{
	rds_session_t	*sp;
	ib_gid_t	lgid, rgid;
	int		ret;

	RDS_DPRINTF4("rds_sendmsg", "Enter: uiop: 0x%p, srcIP: 0x%x destIP: "
	    "0x%x sndport: %d recvport: %d", uiop, sendip, recvip,
	    sendport, recvport);

	/* If msg length is 0, just return success */
	if (uiop->uio_resid == 0) {
		RDS_DPRINTF2("rds_sendmsg", "Zero sized message");
		return (0);
	}

	/* Is there a session to the destination? */
	rw_enter(&rdsib_statep->rds_sessionlock, RW_READER);
	sp = rds_session_lkup(rdsib_statep, recvip, 0);
	rw_exit(&rdsib_statep->rds_sessionlock);

	/* Is this a loopback message? */
	if ((sp == NULL) && (rds_islocal(recvip))) {
		/* make sure the port is not stalled */
		if (rds_is_port_marked(NULL, recvport, RDS_LOOPBACK)) {
			RDS_DPRINTF2(LABEL, "Local Port:%d is in stall state",
			    recvport);
			RDS_INCR_EWOULDBLOCK();
			return (ENOMEM);
		}
		ret = rds_deliver_loopback_msg(uiop, recvip, sendip, recvport,
		    sendport, zoneid);
		return (ret);
	}

	/* Not a loopback message */
	if (sp == NULL) {
		/* There is no session to the destination, create one. */
		RDS_DPRINTF3(LABEL, "There is no session to the destination "
		    "IP: 0x%x", recvip);
		sp = rds_session_create(rdsib_statep, sendip, recvip, NULL,
		    RDS_SESSION_ACTIVE);
		if (sp != NULL) {
			rw_enter(&sp->session_lock, RW_WRITER);
			if (sp->session_type == RDS_SESSION_ACTIVE) {
				ret = rds_session_init(sp);
				if (ret != 0) {
					RDS_DPRINTF2("rds_sendmsg",
					    "SP(%p): rds_session_init failed",
					    sp);
					sp->session_state =
					    RDS_SESSION_STATE_FAILED;
					RDS_DPRINTF3("rds_sendmsg",
					    "SP(%p) State "
					    "RDS_SESSION_STATE_FAILED", sp);
					rw_exit(&sp->session_lock);
					return (EFAULT);
				}
				sp->session_state = RDS_SESSION_STATE_INIT;
				RDS_DPRINTF3("rds_sendmsg",
				    "SP(%p) State "
				    "RDS_SESSION_STATE_INIT", sp);
				rw_exit(&sp->session_lock);
				rds_session_open(sp);
			} else {
				rw_exit(&sp->session_lock);
			}
		} else {
			/* Is a session created for this destination */
			rw_enter(&rdsib_statep->rds_sessionlock, RW_READER);
			sp = rds_session_lkup(rdsib_statep, recvip, 0);
			rw_exit(&rdsib_statep->rds_sessionlock);
			if (sp == NULL) {
				return (EFAULT);
			}
		}
	}

	/* There is a session to the destination */
	rw_enter(&sp->session_lock, RW_READER);
	if (sp->session_state == RDS_SESSION_STATE_CONNECTED) {
		rw_exit(&sp->session_lock);

		ret = rds_ep_sendmsg(&sp->session_dataep, uiop, sendport,
		    recvport);
		return (ret);
	} else if ((sp->session_state == RDS_SESSION_STATE_FAILED) ||
	    (sp->session_state == RDS_SESSION_STATE_FINI)) {
		ipaddr_t sendip1, recvip1;

		RDS_DPRINTF3("rds_sendmsg", "SP(%p) is not connected, State: "
		    "%d", sp, sp->session_state);
		rw_exit(&sp->session_lock);
		rw_enter(&sp->session_lock, RW_WRITER);
		if ((sp->session_state == RDS_SESSION_STATE_FAILED) ||
		    (sp->session_state == RDS_SESSION_STATE_FINI)) {
			ibt_ip_path_attr_t	ipattr;
			ibt_ip_addr_t		dstip;

			sp->session_state = RDS_SESSION_STATE_CREATED;
			sp->session_type = RDS_SESSION_ACTIVE;
			RDS_DPRINTF3("rds_sendmsg", "SP(%p) State "
			    "RDS_SESSION_STATE_CREATED", sp);
			rw_exit(&sp->session_lock);


			/* The ipaddr should be in the network order */
			sendip1 = sendip;
			recvip1 = recvip;
			ret = rds_sc_path_lookup(&sendip1, &recvip1);
			if (ret == 0) {
				RDS_DPRINTF2(LABEL, "Path not found "
				    "(0x%x 0x%x)", sendip1, recvip1);
			}

			/* Resolve the IP addresses */
			lgid.gid_prefix = 0;
			lgid.gid_guid = 0;
			rgid.gid_prefix = 0;
			rgid.gid_guid = 0;

			bzero(&ipattr, sizeof (ibt_ip_path_attr_t));
			dstip.family = AF_INET;
			dstip.un.ip4addr = recvip1;
			ipattr.ipa_dst_ip = &dstip;
			ipattr.ipa_src_ip.family = AF_INET;
			ipattr.ipa_src_ip.un.ip4addr = sendip1;
			ipattr.ipa_ndst = 1;
			ipattr.ipa_max_paths = 1;
			RDS_DPRINTF2(LABEL, "ibt_get_ip_paths: 0x%x <-> 0x%x ",
			    sendip1, recvip1);
			ret = ibt_get_ip_paths(rdsib_statep->rds_ibhdl,
			    IBT_PATH_NO_FLAGS, &ipattr, &sp->session_pinfo,
			    NULL, NULL);
			if (ret != IBT_SUCCESS) {
				RDS_DPRINTF2("rds_sendmsg",
				    "ibt_get_ip_paths failed, ret: %d ", ret);

				rw_enter(&sp->session_lock, RW_WRITER);
				if (sp->session_type == RDS_SESSION_ACTIVE) {
					sp->session_state =
					    RDS_SESSION_STATE_FAILED;
					RDS_DPRINTF3("rds_sendmsg",
					    "SP(%p) State "
					    "RDS_SESSION_STATE_FAILED", sp);
					rw_exit(&sp->session_lock);
					return (EFAULT);
				} else {
					rw_exit(&sp->session_lock);
					return (ENOMEM);
				}
			}
			RDS_DPRINTF2(LABEL, "ibt_get_ip_paths success");
			lgid = sp->session_pinfo.
			    pi_prim_cep_path.cep_adds_vect.av_sgid;
			rgid = sp->session_pinfo.
			    pi_prim_cep_path.cep_adds_vect.av_dgid;

			RDS_DPRINTF2(LABEL, "lgid: %llx:%llx rgid: %llx:%llx",
			    lgid.gid_prefix, lgid.gid_guid, rgid.gid_prefix,
			    rgid.gid_guid);

			rw_enter(&sp->session_lock, RW_WRITER);
			if (sp->session_type == RDS_SESSION_ACTIVE) {
				sp->session_lgid = lgid;
				sp->session_rgid = rgid;
				ret = rds_session_init(sp);
				if (ret != 0) {
					RDS_DPRINTF2("rds_sendmsg",
					    "SP(%p): rds_session_init failed",
					    sp);
					sp->session_state =
					    RDS_SESSION_STATE_FAILED;
					RDS_DPRINTF3("rds_sendmsg",
					    "SP(%p) State "
					    "RDS_SESSION_STATE_FAILED", sp);
					rw_exit(&sp->session_lock);
					return (EFAULT);
				}
				sp->session_state = RDS_SESSION_STATE_INIT;
				rw_exit(&sp->session_lock);

				rds_session_open(sp);

			} else {
				RDS_DPRINTF2("rds_sendmsg",
				    "SP(%p): type changed to %d",
				    sp, sp->session_type);
				rw_exit(&sp->session_lock);
				return (ENOMEM);
			}
		} else {
			RDS_DPRINTF2("rds_sendmsg",
			    "SP(%p): Session state %d changed",
			    sp, sp->session_state);
			rw_exit(&sp->session_lock);
			return (ENOMEM);
		}
	} else {
		RDS_DPRINTF4("rds_sendmsg", "SP(%p): Session is in %d state",
		    sp, sp->session_state);
		rw_exit(&sp->session_lock);
		return (ENOMEM);
	}

	rw_enter(&sp->session_lock, RW_READER);
	if (sp->session_state == RDS_SESSION_STATE_CONNECTED) {
		rw_exit(&sp->session_lock);

		ret = rds_ep_sendmsg(&sp->session_dataep, uiop, sendport,
		    recvport);
	} else {
		RDS_DPRINTF2("rds_sendmsg", "SP(%p): state(%d) not connected",
		    sp, sp->session_state);
		rw_exit(&sp->session_lock);
	}

	RDS_DPRINTF4("rds_sendmsg", "Return: SP(%p) ret: %d", sp, ret);

	return (ret);
}

/* Note: This is called on the CQ handler thread */
void
rds_received_msg(rds_ep_t *ep, rds_buf_t *bp)
{
	mblk_t		*mp, *mp1;
	rds_data_hdr_t	*pktp, *pktp1;
	uint8_t		*datap;
	rds_buf_t	*bp1;
	rds_bufpool_t	*rpool;
	uint_t		npkts, ix;
	int		ret;

	RDS_DPRINTF4("rds_received_msg", "Enter: EP(%p)", ep);

	pktp = (rds_data_hdr_t *)(uintptr_t)bp->buf_ds.ds_va;
	datap = ((uint8_t *)(uintptr_t)bp->buf_ds.ds_va) + RDS_DATA_HDR_SZ;
	npkts = pktp->dh_npkts;

	/* increment rx pending here */
	rpool = &ep->ep_rcvpool;
	mutex_enter(&rpool->pool_lock);
	rpool->pool_nbusy += npkts;
	mutex_exit(&rpool->pool_lock);

	/* this will get freed by sockfs */
	mp = esballoc(datap, pktp->dh_datalen, BPRI_HI, &bp->buf_frtn);
	if (mp == NULL) {
		RDS_DPRINTF2(LABEL, "EP(%p) BP(%p): allocb failed",
		    ep, bp);
		rds_free_recv_buf(bp, npkts);
		return;
	}
	mp->b_wptr = datap + pktp->dh_datalen;
	mp->b_datap->db_type = M_DATA;

	mp1 = mp;
	bp1 = bp->buf_nextp;
	while (bp1 != NULL) {
		pktp1 = (rds_data_hdr_t *)(uintptr_t)bp1->buf_ds.ds_va;
		datap = ((uint8_t *)(uintptr_t)bp1->buf_ds.ds_va) +
		    RDS_DATA_HDR_SZ;

		mp1->b_cont = esballoc(datap, pktp1->dh_datalen,
		    BPRI_HI, &bp1->buf_frtn);
		if (mp1->b_cont == NULL) {
			RDS_DPRINTF2(LABEL, "EP(%p) BP(%p): allocb failed",
			    ep, bp1);
			freemsg(mp);
			rds_free_recv_buf(bp1, pktp1->dh_npkts);
			return;
		}
		mp1 = mp1->b_cont;
		mp1->b_wptr = datap + pktp1->dh_datalen;
		mp1->b_datap->db_type = M_DATA;

		bp1 = bp1->buf_nextp;
	}

	RDS_INCR_RXPKTS_PEND(npkts);
	RDS_INCR_RXPKTS(npkts);
	RDS_INCR_RXBYTES(msgdsize(mp));

	RDS_DPRINTF5(LABEL, "Deliver Message: sendIP: 0x%x recvIP: 0x%x "
	    "sendport: %d recvport: %d npkts: %d pktno: %d", ep->ep_remip,
	    ep->ep_myip, pktp->dh_sendport, pktp->dh_recvport,
	    npkts, pktp->dh_psn);

	/* store the last buffer id, no lock needed */
	if (npkts > 1) {
		ep->ep_rbufid = pktp1->dh_bufid;
	} else {
		ep->ep_rbufid = pktp->dh_bufid;
	}

	ret = rds_deliver_new_msg(mp, ep->ep_myip, ep->ep_remip,
	    pktp->dh_recvport, pktp->dh_sendport, ALL_ZONES);
	if (ret != 0) {
		if (ret == ENOSPC) {
			/*
			 * The message is delivered but cannot take more,
			 * stop further remote messages coming to this port
			 */
			RDS_DPRINTF3("rds_received_msg", "Port %d NO SPACE",
			    pktp->dh_recvport);
			rds_stall_port(ep->ep_sp, pktp->dh_recvport, RDS_LOCAL);
		} else {
			RDS_DPRINTF2(LABEL, "rds_deliver_new_msg returned: %d",
			    ret);
		}
	}

	mutex_enter(&ep->ep_lock);
	/* The first message can come in before the conn est event */
	if ((ep->ep_rdmacnt == 0) && (ep->ep_state == RDS_EP_STATE_CONNECTED)) {
		ep->ep_rdmacnt++;
		*(uintptr_t *)(uintptr_t)ep->ep_ackds.ds_va = ep->ep_rbufid;
		mutex_exit(&ep->ep_lock);

		/* send acknowledgement */
		RDS_INCR_TXACKS();
		ret = ibt_post_send(ep->ep_chanhdl, &ep->ep_ackwr, 1, &ix);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "EP(%p): ibt_post_send for "
			    "acknowledgement failed: %d, SQ depth: %d",
			    ep, ret, ep->ep_sndpool.pool_nbusy);
			mutex_enter(&ep->ep_lock);
			ep->ep_rdmacnt--;
			mutex_exit(&ep->ep_lock);
		}
	} else {
		/* no room to send acknowledgement */
		mutex_exit(&ep->ep_lock);
	}

	RDS_DPRINTF4("rds_received_msg", "Return: EP(%p)", ep);
}

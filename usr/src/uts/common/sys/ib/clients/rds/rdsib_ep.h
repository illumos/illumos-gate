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

#ifndef _RDSIB_EP_H
#define	_RDSIB_EP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>

/*
 * Control channel or Data channel
 */
typedef enum rds_ep_type_s {
	RDS_EP_TYPE_CTRL		= 1,
	RDS_EP_TYPE_DATA		= 2
} rds_ep_type_t;

/*
 * Channel States
 *
 * RDS_EP_STATE_UNCONNECTED - Initial state when rds_ep_t is created
 * RDS_EP_STATE_ACTIVE_PENDING - Active side connection in progress
 * RDS_EP_STATE_PASSIVE_PENDING - Passice side connection in progress
 * RDS_EP_STATE_CONNECTED - Channel is connected
 * RDS_EP_STATE_DESTROY_TIMEWAIT - Channel is closed
 */
typedef enum rds_ep_state_s {
	RDS_EP_STATE_UNCONNECTED		= 0,
	RDS_EP_STATE_ACTIVE_PENDING		= 1,
	RDS_EP_STATE_PASSIVE_PENDING		= 2,
	RDS_EP_STATE_CONNECTED			= 3,
	RDS_EP_STATE_CLOSING			= 4,
	RDS_EP_STATE_CLOSED			= 5,
	RDS_EP_STATE_ERROR			= 6
} rds_ep_state_t;

/*
 * Session State Machine Diagram
 *
 *                     -----------------
 *                    |       (6)       |
 *                    |                 |
 *                    v                 |
 *             --> (Created)-------->(Failed)
 *            |     |         (5)       ^
 *            |     |(1)                |
 *            |     |                   |(9)
 *            |     v                   |
 *            |    (Init)<--------------|
 *            |     | |       (8)       |
 *            |     | |                 |
 *            |  (2)|  --------------   |
 *        (11)|     |         (7)    |  |
 *            |     v                v  |
 *            |    (Connected)------>(Error)
 *            |     |         (10)
 *            |     |(3)
 *            |     |
 *            |     v
 *            |    (Closed)
 *            |     |
 *            |     |(4)
 *            |     |
 *            |     v
 *             --- (Fini) ------->(Destroy)
 *                         (12)
 *
 *	(1) rds_session_init()
 *	(2) rds_session_open()
 *	(3) rds_session_close()
 *	(4) rds_session_fini()
 *	(4) rds_passive_session_fini()
 *	(5) Failure in rds_session_init()
 *	(6) rds_sendmsg(3SOCKET)/Incoming CM REQ
 *	(7) Failure in rds_session_open()
 *	(8) rds_session_close(), rds_get_ibaddr() and rds_session_reinit()
 *	(9) rds_session_close() and rds_session_fini()
 *	(9) rds_cleanup_passive_session() and rds_passive_session_fini()
 *	(10) Connection Error/Incoming REQ
 *	(11) rds_sendmsg(3SOCKET)/Incoming REQ
 *
 *
 * Created   - Session is allocated and inserted into the sessionlist but
 *             not all members are initialized.
 * Init      - All members are initialized, send buffer pool is allocated.
 * Connected - Data and ctrl RC channels are opened.
 * Closed    - Data and ctrl RC channels are closed.
 * Fini      - Send buffer pool and buffers in the receive pool are freed.
 * Destroy   - Session is removed from the session list and is ready to be
 *             freed.
 * Failed    - Session initialization has failed (send buffer pool allocation).
 * Error     - (1) Failed to open the RC channels.
 *             (2) An error occurred on the RC channels while sending.
 *             (3) Received a new CM REQ message on the existing connection.
 */
typedef enum rds_session_state_s {
	RDS_SESSION_STATE_CREATED		= 0,
	RDS_SESSION_STATE_FAILED		= 1,
	RDS_SESSION_STATE_INIT			= 2,
	RDS_SESSION_STATE_CONNECTED		= 3,
	RDS_SESSION_STATE_HCA_CLOSING		= 4,
	RDS_SESSION_STATE_ERROR			= 5,
	RDS_SESSION_STATE_ACTIVE_CLOSING	= 6,
	RDS_SESSION_STATE_PASSIVE_CLOSING	= 7,
	RDS_SESSION_STATE_CLOSED		= 8,
	RDS_SESSION_STATE_FINI			= 9,
	RDS_SESSION_STATE_DESTROY		= 10
} rds_session_state_t;

#define	RDS_SESSION_TRANSITION(sp, state)			\
		rw_enter(&sp->session_lock, RW_WRITER);		\
		sp->session_state = state;			\
		rw_exit(&sp->session_lock)

/* Active or Passive */
#define	RDS_SESSION_ACTIVE	1
#define	RDS_SESSION_PASSIVE	2

/*
 * RDS QP Information
 *
 * lock  - Synchronize access
 * depth - Max number of WRs that can be posted.
 * level - Number of outstanding WRs in the QP
 * lwm   - Water mark at which to post more receive WRs.
 * taskqpending - Indicates if a taskq thread is dispatched to post receive
 *		WRs in the RQ
 */
typedef struct rds_qp_s {
	kmutex_t		qp_lock;
	uint32_t		qp_depth;
	uint32_t		qp_level;
	uint32_t		qp_lwm;
	boolean_t		qp_taskqpending;
} rds_qp_t;

/*
 * RDS EndPoint(One end of RC connection)
 *
 * sp        - Parent Session
 * type      - Control or Data Channel
 * remip     - Same as session_remip
 * myip      - Same as session_myip
 * snd_lkey  - LKey for the send buffer pool
 * hca_guid  - HCA guid
 * snd_mrhdl - Memory handle for the send buffer pool
 * lock      - Protects the members
 * state     - See rds_ep_state_t
 * chanhdl   - RC channel handle
 * sendcq    - Send CQ handle
 * recvcq    - Recv CQ handle
 * sndpool   - Send buffer Pool
 * rcvpool   - Recv buffer Pool
 * segfbp    - First packet of a segmented message.
 * seglbp    - Last packet of a segmented message.
 * lbufid    - Last successful buffer that was received by the remote.
 *             Valid only during session failover/reconnect.
 * rbufid    - Last buffer (remote buffer) that was received successfully
 *             from the remote node.
 * ds        - SGL used for send acknowledgement.
 * ackwr     - WR to send acknowledgement.
 * ackhdl    - Memory handle for 'ack_addr'.
 * ack_rkey  - RKey for 'ack_addr'.
 * ack_addr  - Memory region to receive RDMA acknowledgement from remote.
 */
typedef struct rds_ep_s {
	struct rds_session_s	*ep_sp;
	rds_ep_type_t		ep_type;
	ipaddr_t		ep_remip;
	ipaddr_t		ep_myip;
	ibt_lkey_t		ep_snd_lkey;
	ib_guid_t		ep_hca_guid;
	ibt_mr_hdl_t		ep_snd_mrhdl;
	kmutex_t		ep_lock;
	rds_ep_state_t		ep_state;
	ibt_channel_hdl_t	ep_chanhdl;
	ibt_cq_hdl_t		ep_sendcq;
	ibt_cq_hdl_t		ep_recvcq;
	rds_bufpool_t		ep_sndpool;
	rds_bufpool_t		ep_rcvpool;
	rds_qp_t		ep_recvqp;
	uint_t			ep_rdmacnt;
	rds_buf_t		*ep_segfbp;
	rds_buf_t		*ep_seglbp;
	uintptr_t		ep_lbufid;
	uintptr_t		ep_rbufid;
	ibt_wr_ds_t		ep_ackds;
	ibt_send_wr_t		ep_ackwr;
	ibt_mr_hdl_t		ep_ackhdl;
	ibt_rkey_t		ep_ack_rkey;
	uintptr_t		ep_ack_addr;
} rds_ep_t;

/*
 * One end of an RDS session
 *
 * nextp   - Pointer to the next session in the session list.
 *           This is protected by rds_state_t:rds_sessionlock.
 * remip   - IP address of the node having the remote end of the session.
 * myip    - IP address of this end of the session.
 * lgid    - IB local (source) gid, hosting "myip".
 * rgid    - IB remote (destination) gid, hosting "remip".
 * lock    - Provides read/write access to members of the session.
 * type    - Identifies which end of session (active or passive).
 * state   - State of session (rds_session_state_t).
 * dataep  - Data endpoint
 * ctrlep  - Control endpoint
 * failover- Flag to indicate that an error occured and the session is
 *           re-connecting.
 * portmap_lock - To serialize access to portmap.
 * portmap - Bitmap of sockets.
 *           The maximum number of sockets seem to be 65536, the portmap has
 *           1 bit for each remote socket. A set bit indicates that the
 *           corresponding remote socket is stalled and vice versa.
 */
typedef struct rds_session_s {
	struct rds_session_s	*session_nextp;
	ipaddr_t		session_remip;
	ipaddr_t		session_myip;
	ib_guid_t		session_hca_guid;
	ib_gid_t		session_lgid;
	ib_gid_t		session_rgid;
	krwlock_t		session_lock;
	uint8_t			session_type;
	uint8_t			session_state;
	struct rds_ep_s		session_dataep;
	struct rds_ep_s		session_ctrlep;
	uint_t			session_failover;
	krwlock_t		session_local_portmap_lock;
	krwlock_t		session_remote_portmap_lock;
	uint8_t			session_local_portmap[RDS_PORT_MAP_SIZE];
	uint8_t			session_remote_portmap[RDS_PORT_MAP_SIZE];
	ibt_path_info_t		session_pinfo;
} rds_session_t;

/* defined in rds_ep.c */
int rds_ep_init(rds_ep_t *ep, ib_guid_t hca_guid);
rds_session_t *rds_session_create(rds_state_t *statep, ipaddr_t destip,
    ipaddr_t srcip, ibt_cm_req_rcv_t *reqp, uint8_t type);
int rds_session_init(rds_session_t *sp);
int rds_session_reinit(rds_session_t *sp, ib_gid_t lgid);
void rds_session_open(rds_session_t *sp);
void rds_session_close(rds_session_t *sp, ibt_execution_mode_t mode,
    uint_t wait);
rds_session_t *rds_session_lkup(rds_state_t *statep, ipaddr_t destip,
    ib_guid_t node_guid);
void rds_recycle_session(rds_session_t *sp);
void rds_session_active(rds_session_t *sp);
void rds_close_sessions(void *arg);
void rds_received_msg(rds_ep_t *ep, rds_buf_t *bp);
void rds_handle_control_message(rds_session_t *sp, rds_ctrl_pkt_t *cp);
void rds_handle_send_error(rds_ep_t *ep);
void rds_session_fini(rds_session_t *sp);
void rds_passive_session_fini(rds_session_t *sp);
void rds_cleanup_passive_session(void *arg);

/* defined in rds_ib.c */
ibt_channel_hdl_t rds_ep_alloc_rc_channel(rds_ep_t *ep, uint8_t hca_port);
void rds_ep_free_rc_channel(rds_ep_t *ep);
void rds_post_recv_buf(void *arg);
void rds_poll_send_completions(ibt_cq_hdl_t cq, struct rds_ep_s *ep,
    boolean_t lock);

/* defined in rds_cm.c */
int rds_open_rc_channel(rds_ep_t *ep, ibt_path_info_t *pinfo,
    ibt_execution_mode_t mode, ibt_channel_hdl_t *chanhdl);
int rds_close_rc_channel(ibt_channel_hdl_t chanhdl, ibt_execution_mode_t mode);

int rds_deliver_new_msg(mblk_t *mp, ipaddr_t local_addr, ipaddr_t rem_addr,
    in_port_t local_port, in_port_t rem_port, zoneid_t zoneid);

/* defined in rds_sc.c */
int rds_sc_path_lookup(ipaddr_t *localip, ipaddr_t *remip);

#ifdef __cplusplus
}
#endif

#endif	/* _RDSIB_EP_H */

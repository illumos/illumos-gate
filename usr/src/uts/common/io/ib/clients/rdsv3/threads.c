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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
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
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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
#include <sys/rds.h>
#include <sys/sunddi.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

/*
 * All of connection management is simplified by serializing it through
 * work queues that execute in a connection managing thread.
 *
 * TCP wants to send acks through sendpage() in response to data_ready(),
 * but it needs a process context to do so.
 *
 * The receive paths need to allocate but can't drop packets (!) so we have
 * a thread around to block allocating if the receive fast path sees an
 * allocation failure.
 */

/*
 * Grand Unified Theory of connection life cycle:
 * At any point in time, the connection can be in one of these states:
 * DOWN, CONNECTING, UP, DISCONNECTING, ERROR
 *
 * The following transitions are possible:
 *  ANY		  -> ERROR
 *  UP		  -> DISCONNECTING
 *  ERROR	  -> DISCONNECTING
 *  DISCONNECTING -> DOWN
 *  DOWN	  -> CONNECTING
 *  CONNECTING	  -> UP
 *
 * Transition to state DISCONNECTING/DOWN:
 *  -	Inside the shutdown worker; synchronizes with xmit path
 *	through c_send_lock, and with connection management callbacks
 *	via c_cm_lock.
 *
 *	For receive callbacks, we rely on the underlying transport
 *	(TCP, IB/RDMA) to provide the necessary synchronisation.
 */
struct rdsv3_workqueue_struct_s *rdsv3_wq;

void
rdsv3_connect_complete(struct rdsv3_connection *conn)
{
	RDSV3_DPRINTF4("rdsv3_connect_complete", "Enter(conn: %p)", conn);

	if (!rdsv3_conn_transition(conn, RDSV3_CONN_CONNECTING,
	    RDSV3_CONN_UP)) {
#ifndef __lock_lint
		RDSV3_DPRINTF2("rdsv3_connect_complete",
		    "%s: Cannot transition to state UP, "
		    "current state is %d",
		    __func__,
		    atomic_get(&conn->c_state));
#endif
		conn->c_state = RDSV3_CONN_ERROR;
		rdsv3_queue_work(rdsv3_wq, &conn->c_down_w);
		return;
	}

	RDSV3_DPRINTF2("rdsv3_connect_complete",
	    "conn %p for %u.%u.%u.%u to %u.%u.%u.%u complete",
	    conn, NIPQUAD(conn->c_laddr), NIPQUAD(conn->c_faddr));

	conn->c_reconnect_jiffies = 0;
	set_bit(0, &conn->c_map_queued);
	rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_send_w, 0);
	rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_recv_w, 0);

	RDSV3_DPRINTF4("rdsv3_connect_complete", "Return(conn: %p)", conn);
}

/*
 * This random exponential backoff is relied on to eventually resolve racing
 * connects.
 *
 * If connect attempts race then both parties drop both connections and come
 * here to wait for a random amount of time before trying again.  Eventually
 * the backoff range will be so much greater than the time it takes to
 * establish a connection that one of the pair will establish the connection
 * before the other's random delay fires.
 *
 * Connection attempts that arrive while a connection is already established
 * are also considered to be racing connects.  This lets a connection from
 * a rebooted machine replace an existing stale connection before the transport
 * notices that the connection has failed.
 *
 * We should *always* start with a random backoff; otherwise a broken connection
 * will always take several iterations to be re-established.
 */
static void
rdsv3_queue_reconnect(struct rdsv3_connection *conn)
{
	unsigned long rand;

	RDSV3_DPRINTF2("rdsv3_queue_reconnect",
	    "conn %p for %u.%u.%u.%u to %u.%u.%u.%u reconnect jiffies %lu",
	    conn, NIPQUAD(conn->c_laddr), NIPQUAD(conn->c_faddr),
	    conn->c_reconnect_jiffies);

	set_bit(RDSV3_RECONNECT_PENDING, &conn->c_flags);
	if (conn->c_reconnect_jiffies == 0) {
		conn->c_reconnect_jiffies = rdsv3_sysctl_reconnect_min_jiffies;
		rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_conn_w, 0);
		return;
	}

	(void) random_get_pseudo_bytes((uint8_t *)&rand, sizeof (rand));
	RDSV3_DPRINTF5("rdsv3",
	    "%lu delay %lu ceil conn %p for %u.%u.%u.%u -> %u.%u.%u.%u",
	    rand % conn->c_reconnect_jiffies, conn->c_reconnect_jiffies,
	    conn, NIPQUAD(conn->c_laddr), NIPQUAD(conn->c_faddr));
	rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_conn_w,
	    rand % conn->c_reconnect_jiffies);

	conn->c_reconnect_jiffies = min(conn->c_reconnect_jiffies * 2,
	    rdsv3_sysctl_reconnect_max_jiffies);
}

void
rdsv3_connect_worker(struct rdsv3_work_s *work)
{
	struct rdsv3_connection *conn = container_of(work,
	    struct rdsv3_connection, c_conn_w.work);
	int ret;

	RDSV3_DPRINTF2("rdsv3_connect_worker", "Enter(work: %p)", work);

	clear_bit(RDSV3_RECONNECT_PENDING, &conn->c_flags);
	if (rdsv3_conn_transition(conn, RDSV3_CONN_DOWN,
	    RDSV3_CONN_CONNECTING)) {
		ret = conn->c_trans->conn_connect(conn);
		RDSV3_DPRINTF5("rdsv3",
		    "connect conn %p for %u.%u.%u.%u -> %u.%u.%u.%u "
		    "ret %d", conn, NIPQUAD(conn->c_laddr),
		    NIPQUAD(conn->c_faddr), ret);
		RDSV3_DPRINTF2("rdsv3_connect_worker",
		    "conn %p for %u.%u.%u.%u to %u.%u.%u.%u dispatched, ret %d",
		    conn, NIPQUAD(conn->c_laddr), NIPQUAD(conn->c_faddr), ret);

		if (ret) {
			if (rdsv3_conn_transition(conn, RDSV3_CONN_CONNECTING,
			    RDSV3_CONN_DOWN))
				rdsv3_queue_reconnect(conn);
			else {
				RDSV3_DPRINTF2("rdsv3_connect_worker",
				    "RDS: connect failed: %p", conn);
				rdsv3_conn_drop(conn);
			}
		}
	}

	RDSV3_DPRINTF2("rdsv3_connect_worker", "Return(work: %p)", work);
}

extern struct avl_tree	rdsv3_conn_hash;

void
rdsv3_shutdown_worker(struct rdsv3_work_s *work)
{
	struct rdsv3_connection *conn = container_of(work,
	    struct rdsv3_connection, c_down_w);
	struct rdsv3_conn_info_s conn_info;

	RDSV3_DPRINTF2("rdsv3_shutdown_worker", "Enter(work: %p)", work);

	/* shut it down unless it's down already */
	if (!rdsv3_conn_transition(conn, RDSV3_CONN_DOWN, RDSV3_CONN_DOWN)) {
		/*
		 * Quiesce the connection mgmt handlers before we start tearing
		 * things down. We don't hold the mutex for the entire
		 * duration of the shutdown operation, else we may be
		 * deadlocking with the CM handler. Instead, the CM event
		 * handler is supposed to check for state DISCONNECTING
		 */
		mutex_enter(&conn->c_cm_lock);
		if (!rdsv3_conn_transition(conn, RDSV3_CONN_UP,
		    RDSV3_CONN_DISCONNECTING) &&
		    !rdsv3_conn_transition(conn, RDSV3_CONN_ERROR,
		    RDSV3_CONN_DISCONNECTING)) {
			RDSV3_DPRINTF2("rdsv3_shutdown_worker",
			    "RDS: connect failed: conn: %p, state: %d",
			    conn, atomic_get(&conn->c_state));
			rdsv3_conn_drop(conn);
			mutex_exit(&conn->c_cm_lock);
			return;
		}
		mutex_exit(&conn->c_cm_lock);

		mutex_enter(&conn->c_send_lock);
		conn->c_trans->conn_shutdown(conn);
		rdsv3_conn_reset(conn);
		mutex_exit(&conn->c_send_lock);

		if (!rdsv3_conn_transition(conn, RDSV3_CONN_DISCONNECTING,
		    RDSV3_CONN_DOWN)) {
			/*
			 * This can happen - eg when we're in the middle of
			 * tearing down the connection, and someone unloads
			 * the rds module. Quite reproduceable with loopback
			 * connections. Mostly harmless.
			 */
#ifndef __lock_lint
			RDSV3_DPRINTF2("rdsv3_shutdown_worker",
			    "failed to transition to state DOWN, "
			    "current statis is: %d conn: %p",
			    atomic_get(&conn->c_state), conn);
			rdsv3_conn_drop(conn);
#endif
			return;
		}
	}

	/*
	 * Then reconnect if it's still live.
	 * The passive side of an IB loopback connection is never added
	 * to the conn hash, so we never trigger a reconnect on this
	 * conn - the reconnect is always triggered by the active peer.
	 */
	rdsv3_cancel_delayed_work(&conn->c_conn_w);

	conn_info.c_laddr = conn->c_laddr;
	conn_info.c_faddr = conn->c_faddr;
	if (avl_find(&rdsv3_conn_hash, &conn_info, NULL) == conn)
		rdsv3_queue_reconnect(conn);

	RDSV3_DPRINTF2("rdsv3_shutdown_worker", "Return(work: %p)", work);
}

void
rdsv3_send_worker(struct rdsv3_work_s *work)
{
	struct rdsv3_connection *conn = container_of(work,
	    struct rdsv3_connection, c_send_w.work);
	int ret;

	RDSV3_DPRINTF4("rdsv3_send_worker", "Enter(work: %p)", work);

	if (rdsv3_conn_state(conn) == RDSV3_CONN_UP) {
		ret = rdsv3_send_xmit(conn);
		RDSV3_DPRINTF5("rdsv3", "conn %p ret %d", conn, ret);
		switch (ret) {
		case -EAGAIN:
			rdsv3_stats_inc(s_send_immediate_retry);
			rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_send_w, 0);
			break;
		case -ENOMEM:
			rdsv3_stats_inc(s_send_delayed_retry);
			rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_send_w, 2);
		default:
			break;
		}
	}

	RDSV3_DPRINTF4("rdsv3_send_worker", "Return(work: %p)", work);
}

void
rdsv3_recv_worker(struct rdsv3_work_s *work)
{
	struct rdsv3_connection *conn = container_of(work,
	    struct rdsv3_connection, c_recv_w.work);
	int ret;

	RDSV3_DPRINTF4("rdsv3_recv_worker", "Enter(work: %p)", work);

	if (rdsv3_conn_state(conn) == RDSV3_CONN_UP) {
		ret = conn->c_trans->recv(conn);
		RDSV3_DPRINTF5("rdsv3", "conn %p ret %d", conn, ret);
		switch (ret) {
		case -EAGAIN:
			rdsv3_stats_inc(s_recv_immediate_retry);
			rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_recv_w, 0);
			break;
		case -ENOMEM:
			rdsv3_stats_inc(s_recv_delayed_retry);
			rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_recv_w, 2);
		default:
			break;
		}
	}

	RDSV3_DPRINTF4("rdsv3_recv_worker", "Return(work: %p)", work);
}

void
rdsv3_threads_exit(void)
{
	rdsv3_destroy_task_workqueue(rdsv3_wq);
}

int
rdsv3_threads_init(void)
{
	rdsv3_wq = rdsv3_create_task_workqueue("krdsd");
	if (rdsv3_wq == NULL)
		return (-ENOMEM);

	return (0);
}

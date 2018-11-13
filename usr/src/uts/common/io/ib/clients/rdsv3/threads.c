/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file threads.c
 * Oracle elects to have and use the contents of threads.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
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
#include <sys/containerof.h>

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
	conn->c_last_connect_jiffies = ddi_get_lbolt();

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
void
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
	struct rdsv3_connection *conn = __containerof(work,
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

void
rdsv3_send_worker(struct rdsv3_work_s *work)
{
	struct rdsv3_connection *conn = __containerof(work,
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
	struct rdsv3_connection *conn = __containerof(work,
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
rdsv3_shutdown_worker(struct rdsv3_work_s *work)
{
	struct rdsv3_connection *conn = __containerof(work,
	    struct rdsv3_connection, c_down_w);
	rdsv3_conn_shutdown(conn);
}

#define	time_after(a, b)	((long)(b) - (long)(a) < 0)

void
rdsv3_reaper_worker(struct rdsv3_work_s *work)
{
	struct rdsv3_connection *conn = __containerof(work,
	    struct rdsv3_connection, c_reap_w.work);

	if (rdsv3_conn_state(conn) != RDSV3_CONN_UP &&
	    !time_after(conn->c_last_connect_jiffies,
	    ddi_get_lbolt() - RDSV3_REAPER_WAIT_JIFFIES)) {
		rdsv3_conn_destroy(conn);
	} else {
		rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_reap_w,
		    RDSV3_REAPER_WAIT_JIFFIES);
	}
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
	if (!rdsv3_wq)
		return (-ENOMEM);

	return (0);
}

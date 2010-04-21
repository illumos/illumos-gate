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
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/rds.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/loop.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

/* converting this to RCU is a chore for another day.. */
static krwlock_t rdsv3_conn_lock;
static unsigned long rdsv3_conn_count;
struct avl_tree rdsv3_conn_hash;
static struct kmem_cache *rdsv3_conn_slab = NULL;

#define	rdsv3_conn_info_set(var, test, suffix) do {               \
	if (test)                                               \
		var |= RDSV3_INFO_CONNECTION_FLAG_##suffix;     \
} while (0)

static inline int
rdsv3_conn_is_sending(struct rdsv3_connection *conn)
{
	int ret = 0;

	if (!mutex_tryenter(&conn->c_send_lock))
		ret = 1;
	else
		mutex_exit(&conn->c_send_lock);

	return (ret);
}

static struct rdsv3_connection *
rdsv3_conn_lookup(uint32_be_t laddr, uint32_be_t faddr, avl_index_t *pos)
{
	struct rdsv3_connection *conn;
	struct rdsv3_conn_info_s conn_info;
	avl_index_t place = 0;

	conn_info.c_laddr = laddr;
	conn_info.c_faddr = faddr;

	conn = avl_find(&rdsv3_conn_hash, &conn_info, &place);

	RDSV3_DPRINTF5("rdsv3_conn_lookup",
	    "returning conn %p for %u.%u.%u.%u -> %u.%u.%u.%u",
	    conn, NIPQUAD(laddr), NIPQUAD(faddr));

	if (pos != NULL)
		*pos = place;

	return (conn);
}

/*
 * This is called by transports as they're bringing down a connection.
 * It clears partial message state so that the transport can start sending
 * and receiving over this connection again in the future.  It is up to
 * the transport to have serialized this call with its send and recv.
 */
void
rdsv3_conn_reset(struct rdsv3_connection *conn)
{
	RDSV3_DPRINTF2("rdsv3_conn_reset",
	    "connection %u.%u.%u.%u to %u.%u.%u.%u reset",
	    NIPQUAD(conn->c_laddr), NIPQUAD(conn->c_faddr));

	rdsv3_stats_inc(s_conn_reset);
	rdsv3_send_reset(conn);
	conn->c_flags = 0;

	/*
	 * Do not clear next_rx_seq here, else we cannot distinguish
	 * retransmitted packets from new packets, and will hand all
	 * of them to the application. That is not consistent with the
	 * reliability guarantees of RDS.
	 */
}

/*
 * There is only every one 'conn' for a given pair of addresses in the
 * system at a time.  They contain messages to be retransmitted and so
 * span the lifetime of the actual underlying transport connections.
 *
 * For now they are not garbage collected once they're created.  They
 * are torn down as the module is removed, if ever.
 */
static struct rdsv3_connection *
__rdsv3_conn_create(uint32_be_t laddr, uint32_be_t faddr,
    struct rdsv3_transport *trans, int gfp,
    int is_outgoing)
{
	struct rdsv3_connection *conn, *parent = NULL;
	avl_index_t pos;
	int ret;

	rw_enter(&rdsv3_conn_lock, RW_READER);
	conn = rdsv3_conn_lookup(laddr, faddr, &pos);
	if (conn &&
	    conn->c_loopback &&
	    conn->c_trans != &rdsv3_loop_transport &&
	    !is_outgoing) {
		/*
		 * This is a looped back IB connection, and we're
		 * called by the code handling the incoming connect.
		 * We need a second connection object into which we
		 * can stick the other QP.
		 */
		parent = conn;
		conn = parent->c_passive;
	}
	rw_exit(&rdsv3_conn_lock);
	if (conn)
		goto out;

	RDSV3_DPRINTF2("__rdsv3_conn_create", "Enter(%x -> %x)",
	    ntohl(laddr), ntohl(faddr));

	conn = kmem_cache_alloc(rdsv3_conn_slab, gfp);
	if (conn == NULL) {
		conn = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* see rdsv3_conn_constructor */
	conn->c_laddr = laddr;
	conn->c_faddr = faddr;

	ret = rdsv3_cong_get_maps(conn);
	if (ret) {
		kmem_cache_free(rdsv3_conn_slab, conn);
		conn = ERR_PTR(ret);
		goto out;
	}

	/*
	 * This is where a connection becomes loopback.  If *any* RDS sockets
	 * can bind to the destination address then we'd rather the messages
	 * flow through loopback rather than either transport.
	 */
	if (rdsv3_trans_get_preferred(faddr)) {
		conn->c_loopback = 1;
		if (is_outgoing && trans->t_prefer_loopback) {
			/*
			 * "outgoing" connection - and the transport
			 * says it wants the connection handled by the
			 * loopback transport. This is what TCP does.
			 */
			trans = &rdsv3_loop_transport;
		}
	}

	conn->c_trans = trans;

	ret = trans->conn_alloc(conn, gfp);
	if (ret) {
		kmem_cache_free(rdsv3_conn_slab, conn);
		conn = ERR_PTR(ret);
		goto out;
	}

	conn->c_state = RDSV3_CONN_DOWN;
	conn->c_reconnect_jiffies = 0;
	RDSV3_INIT_DELAYED_WORK(&conn->c_send_w, rdsv3_send_worker);
	RDSV3_INIT_DELAYED_WORK(&conn->c_recv_w, rdsv3_recv_worker);
	RDSV3_INIT_DELAYED_WORK(&conn->c_conn_w, rdsv3_connect_worker);
	RDSV3_INIT_WORK(&conn->c_down_w, rdsv3_shutdown_worker);
	mutex_init(&conn->c_cm_lock, NULL, MUTEX_DRIVER, NULL);
	conn->c_flags = 0;

	RDSV3_DPRINTF2("__rdsv3_conn_create",
	    "allocated conn %p for %u.%u.%u.%u -> %u.%u.%u.%u over %s %s",
	    conn, NIPQUAD(laddr), NIPQUAD(faddr),
	    trans->t_name ? trans->t_name : "[unknown]",
	    is_outgoing ? "(outgoing)" : "");

	/*
	 * Since we ran without holding the conn lock, someone could
	 * have created the same conn (either normal or passive) in the
	 * interim. We check while holding the lock. If we won, we complete
	 * init and return our conn. If we lost, we rollback and return the
	 * other one.
	 */
	rw_enter(&rdsv3_conn_lock, RW_WRITER);
	if (parent) {
		/* Creating passive conn */
		if (parent->c_passive) {
			trans->conn_free(conn->c_transport_data);
			kmem_cache_free(rdsv3_conn_slab, conn);
			conn = parent->c_passive;
		} else {
			parent->c_passive = conn;
			rdsv3_cong_add_conn(conn);
			rdsv3_conn_count++;
		}
	} else {
		/* Creating normal conn */
		struct rdsv3_connection *found;

		found = rdsv3_conn_lookup(laddr, faddr, &pos);
		if (found) {
			trans->conn_free(conn->c_transport_data);
			kmem_cache_free(rdsv3_conn_slab, conn);
			conn = found;
		} else {
			avl_insert(&rdsv3_conn_hash, conn, pos);
			rdsv3_cong_add_conn(conn);
			rdsv3_conn_count++;
		}
	}

	rw_exit(&rdsv3_conn_lock);

	RDSV3_DPRINTF2("__rdsv3_conn_create", "Return(conn: %p)", conn);

out:
	return (conn);
}

struct rdsv3_connection *
rdsv3_conn_create(uint32_be_t laddr, uint32_be_t faddr,
    struct rdsv3_transport *trans, int gfp)
{
	return (__rdsv3_conn_create(laddr, faddr, trans, gfp, 0));
}

struct rdsv3_connection *
rdsv3_conn_create_outgoing(uint32_be_t laddr, uint32_be_t faddr,
    struct rdsv3_transport *trans, int gfp)
{
	return (__rdsv3_conn_create(laddr, faddr, trans, gfp, 1));
}

void
rdsv3_conn_destroy(struct rdsv3_connection *conn)
{
	struct rdsv3_message *rm, *rtmp;

	RDSV3_DPRINTF4("rdsv3_conn_destroy",
	    "freeing conn %p for %u.%u.%u.%u -> %u.%u.%u.%u",
	    conn, NIPQUAD(conn->c_laddr), NIPQUAD(conn->c_faddr));

	avl_remove(&rdsv3_conn_hash, conn);

	/* wait for the rds thread to shut it down */
	conn->c_state = RDSV3_CONN_ERROR;
	rdsv3_cancel_delayed_work(&conn->c_conn_w);
	rdsv3_cancel_delayed_work(&conn->c_send_w);
	rdsv3_cancel_delayed_work(&conn->c_recv_w);
	rdsv3_shutdown_worker(&conn->c_down_w);
	rdsv3_flush_workqueue(rdsv3_wq);

	/* tear down queued messages */
	RDSV3_FOR_EACH_LIST_NODE_SAFE(rm, rtmp,
	    &conn->c_send_queue,
	    m_conn_item) {
		list_remove_node(&rm->m_conn_item);
		ASSERT(!list_link_active(&rm->m_sock_item));
		rdsv3_message_put(rm);
	}
	if (conn->c_xmit_rm)
		rdsv3_message_put(conn->c_xmit_rm);

	conn->c_trans->conn_free(conn->c_transport_data);

	/*
	 * The congestion maps aren't freed up here.  They're
	 * freed by rdsv3_cong_exit() after all the connections
	 * have been freed.
	 */
	rdsv3_cong_remove_conn(conn);

	ASSERT(list_is_empty(&conn->c_retrans));
	kmem_cache_free(rdsv3_conn_slab, conn);

	rdsv3_conn_count--;
}

/* ARGSUSED */
static void
rdsv3_conn_message_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens,
    int want_send)
{
	struct list *list;
	struct rdsv3_connection *conn;
	struct rdsv3_message *rm;
	unsigned int total = 0;

	RDSV3_DPRINTF4("rdsv3_conn_message_info", "Enter");

	len /= sizeof (struct rdsv3_info_message);

	rw_enter(&rdsv3_conn_lock, RW_READER);

	if (avl_is_empty(&rdsv3_conn_hash)) {
		/* no connections */
		rw_exit(&rdsv3_conn_lock);
		return;
	}

	conn = (struct rdsv3_connection *)avl_first(&rdsv3_conn_hash);

	do {
		if (want_send)
			list = &conn->c_send_queue;
		else
			list = &conn->c_retrans;

		mutex_enter(&conn->c_lock);

		/* XXX too lazy to maintain counts.. */
		RDSV3_FOR_EACH_LIST_NODE(rm, list, m_conn_item) {
			total++;
			if (total <= len)
				rdsv3_inc_info_copy(&rm->m_inc, iter,
				    conn->c_laddr, conn->c_faddr, 0);
		}

		mutex_exit(&conn->c_lock);

		conn = AVL_NEXT(&rdsv3_conn_hash, conn);
	} while (conn != NULL);

	rw_exit(&rdsv3_conn_lock);

	lens->nr = total;
	lens->each = sizeof (struct rdsv3_info_message);

	RDSV3_DPRINTF4("rdsv3_conn_message_info", "Return");
}

static void
rdsv3_conn_message_info_send(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens)
{
	rdsv3_conn_message_info(sock, len, iter, lens, 1);
}

static void
rdsv3_conn_message_info_retrans(struct rsock *sock,
    unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens)
{
	rdsv3_conn_message_info(sock, len, iter, lens, 0);
}

/* ARGSUSED */
void
rdsv3_for_each_conn_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter,
    struct rdsv3_info_lengths *lens,
    int (*visitor)(struct rdsv3_connection *, void *),
    size_t item_len)
{
#ifndef __lock_lint
	uint64_t buffer[(item_len + 7) / 8];
#else
	uint64_t buffer[256];
#endif
	struct rdsv3_connection *conn;

	rw_enter(&rdsv3_conn_lock, RW_READER);

	lens->nr = 0;
	lens->each = item_len;

	if (avl_is_empty(&rdsv3_conn_hash)) {
		/* no connections */
		rw_exit(&rdsv3_conn_lock);
		return;
	}

	conn = (struct rdsv3_connection *)avl_first(&rdsv3_conn_hash);

	do {
		/* XXX no c_lock usage.. */
		if (!visitor(conn, buffer))
			continue;

		/*
		 * We copy as much as we can fit in the buffer,
		 * but we count all items so that the caller
		 * can resize the buffer.
		 */
		if (len >= item_len) {
			rdsv3_info_copy(iter, buffer, item_len);
			len -= item_len;
		}
		lens->nr++;
		conn = AVL_NEXT(&rdsv3_conn_hash, conn);
	} while (conn != NULL);

	rw_exit(&rdsv3_conn_lock);
}

static int
rdsv3_conn_info_visitor(struct rdsv3_connection *conn, void *buffer)
{
	struct rdsv3_info_connection *cinfo = buffer;

	cinfo->next_tx_seq = conn->c_next_tx_seq;
	cinfo->next_rx_seq = conn->c_next_rx_seq;
	cinfo->laddr = conn->c_laddr;
	cinfo->faddr = conn->c_faddr;
	(void) strncpy((char *)cinfo->transport, conn->c_trans->t_name,
	    sizeof (cinfo->transport));
	cinfo->flags = 0;

	rdsv3_conn_info_set(cinfo->flags,
	    rdsv3_conn_is_sending(conn), SENDING);
	/* XXX Future: return the state rather than these funky bits */
	rdsv3_conn_info_set(cinfo->flags,
	    atomic_get(&conn->c_state) == RDSV3_CONN_CONNECTING,
	    CONNECTING);
	rdsv3_conn_info_set(cinfo->flags,
	    atomic_get(&conn->c_state) == RDSV3_CONN_UP,
	    CONNECTED);
	return (1);
}

static void
rdsv3_conn_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter, struct rdsv3_info_lengths *lens)
{
	rdsv3_for_each_conn_info(sock, len, iter, lens,
	    rdsv3_conn_info_visitor, sizeof (struct rdsv3_info_connection));
}

int
rdsv3_conn_init()
{
	RDSV3_DPRINTF4("rdsv3_conn_init", "Enter");

	rdsv3_conn_slab = kmem_cache_create("rdsv3_connection",
	    sizeof (struct rdsv3_connection), 0, rdsv3_conn_constructor,
	    rdsv3_conn_destructor, NULL, NULL, NULL, 0);
	if (rdsv3_conn_slab == NULL) {
		RDSV3_DPRINTF1("rdsv3_conn_init",
		    "kmem_cache_create(rdsv3_conn_slab) failed");
		return (-1);
	}

	avl_create(&rdsv3_conn_hash, rdsv3_conn_compare,
	    sizeof (struct rdsv3_connection), offsetof(struct rdsv3_connection,
	    c_hash_node));

	rw_init(&rdsv3_conn_lock, NULL, RW_DRIVER, NULL);

	rdsv3_loop_init();

	rdsv3_info_register_func(RDSV3_INFO_CONNECTIONS, rdsv3_conn_info);
	rdsv3_info_register_func(RDSV3_INFO_SEND_MESSAGES,
	    rdsv3_conn_message_info_send);
	rdsv3_info_register_func(RDSV3_INFO_RETRANS_MESSAGES,
	    rdsv3_conn_message_info_retrans);

	RDSV3_DPRINTF4("rdsv3_conn_init", "Return");

	return (0);
}

void
rdsv3_conn_exit()
{
	RDSV3_DPRINTF4("rdsv3_conn_exit", "Enter");

	rdsv3_loop_exit();

	rw_destroy(&rdsv3_conn_lock);
	avl_destroy(&rdsv3_conn_hash);

	ASSERT(rdsv3_conn_slab);
	kmem_cache_destroy(rdsv3_conn_slab);

	RDSV3_DPRINTF4("rdsv3_conn_exit", "Return");
}

/*
 * Force a disconnect
 */
void
rdsv3_conn_drop(struct rdsv3_connection *conn)
{
	conn->c_state = RDSV3_CONN_ERROR;
	rdsv3_queue_work(rdsv3_wq, &conn->c_down_w);
}

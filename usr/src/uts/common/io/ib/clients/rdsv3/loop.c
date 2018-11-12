/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file loop.c
 * Oracle elects to have and use the contents of loop.c under and governed
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
#include <sys/containerof.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/loop.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

kmutex_t loop_conns_lock;
list_t loop_conns;

/*
 * This 'loopback' transport is a special case for flows that originate
 * and terminate on the same machine.
 *
 * Connection build-up notices if the destination address is thought of
 * as a local address by a transport.  At that time it decides to use the
 * loopback transport instead of the bound transport of the sending socket.
 *
 * The loopback transport's sending path just hands the sent rds_message
 * straight to the receiving path via an embedded rds_incoming.
 */

/*
 * Usually a message transits both the sender and receiver's conns as it
 * flows to the receiver.  In the loopback case, though, the receive path
 * is handed the sending conn so the sense of the addresses is reversed.
 */
static int
rdsv3_loop_xmit(struct rdsv3_connection *conn, struct rdsv3_message *rm,
    unsigned int hdr_off, unsigned int sg,
    unsigned int off)
{
	/* Do not send cong updates to loopback */
	if (rm->m_inc.i_hdr.h_flags & RDSV3_FLAG_CONG_BITMAP) {
		rdsv3_cong_map_updated(conn->c_fcong, ~(uint64_t)0);
		return (sizeof (struct rdsv3_header) + RDSV3_CONG_MAP_BYTES);
	}
	ASSERT(!(hdr_off || sg || off));

	RDSV3_DPRINTF4("rdsv3_loop_xmit", "Enter(conn: %p, rm: %p)", conn, rm);

	rdsv3_inc_init(&rm->m_inc, conn, conn->c_laddr);
	/* For the embedded inc. Matching put is in loop_inc_free() */
	rdsv3_message_addref(rm);

	rdsv3_recv_incoming(conn, conn->c_laddr, conn->c_faddr, &rm->m_inc,
	    KM_NOSLEEP);

	rdsv3_send_drop_acked(conn, ntohll(rm->m_inc.i_hdr.h_sequence),
	    NULL);

	rdsv3_inc_put(&rm->m_inc);

	RDSV3_DPRINTF4("rdsv3_loop_xmit", "Return(conn: %p, rm: %p)", conn, rm);

	return (sizeof (struct rdsv3_header) +
	    ntohl(rm->m_inc.i_hdr.h_len));
}

/*
 * See rds_loop_xmit(). Since our inc is embedded in the rm, we
 * make sure the rm lives at least until the inc is done.
 */
static void
rdsv3_loop_inc_free(struct rdsv3_incoming *inc)
{
	struct rdsv3_message *rm = __containerof(inc, struct rdsv3_message,
	    m_inc);
	rdsv3_message_put(rm);
}

static int
rdsv3_loop_xmit_cong_map(struct rdsv3_connection *conn,
    struct rdsv3_cong_map *map,
    unsigned long offset)
{
	RDSV3_DPRINTF4("rdsv3_loop_xmit_cong_map", "Enter(conn: %p)", conn);

	ASSERT(!offset);
	ASSERT(map == conn->c_lcong);

	rdsv3_cong_map_updated(conn->c_fcong, ~(uint64_t)0);

	RDSV3_DPRINTF4("rdsv3_loop_xmit_cong_map", "Return(conn: %p)", conn);

	return (sizeof (struct rdsv3_header) + RDSV3_CONG_MAP_BYTES);
}

/* we need to at least give the thread something to succeed */
/* ARGSUSED */
static int
rdsv3_loop_recv(struct rdsv3_connection *conn)
{
	return (0);
}

struct rdsv3_loop_connection {
	struct list_node loop_node;
	struct rdsv3_connection *conn;
};

/*
 * Even the loopback transport needs to keep track of its connections,
 * so it can call rdsv3_conn_destroy() on them on exit. N.B. there are
 * 1+ loopback addresses (127.*.*.*) so it's not a bug to have
 * multiple loopback conns allocated, although rather useless.
 */
/* ARGSUSED */
static int
rdsv3_loop_conn_alloc(struct rdsv3_connection *conn, int gfp)
{
	struct rdsv3_loop_connection *lc;

	RDSV3_DPRINTF4("rdsv3_loop_conn_alloc", "Enter(conn: %p)", conn);

	lc = kmem_zalloc(sizeof (struct rdsv3_loop_connection), KM_NOSLEEP);
	if (!lc)
		return (-ENOMEM);

	list_link_init(&lc->loop_node);
	lc->conn = conn;
	conn->c_transport_data = lc;

	mutex_enter(&loop_conns_lock);
	list_insert_tail(&loop_conns, lc);
	mutex_exit(&loop_conns_lock);

	RDSV3_DPRINTF4("rdsv3_loop_conn_alloc", "Return(conn: %p)", conn);

	return (0);
}

static void
rdsv3_loop_conn_free(void *arg)
{
	struct rdsv3_loop_connection *lc = arg;
	RDSV3_DPRINTF5("rdsv3_loop_conn_free", "lc %p\n", lc);
	list_remove_node(&lc->loop_node);
	kmem_free(lc, sizeof (struct rdsv3_loop_connection));
}

static int
rdsv3_loop_conn_connect(struct rdsv3_connection *conn)
{
	rdsv3_connect_complete(conn);
	return (0);
}

/* ARGSUSED */
static void
rdsv3_loop_conn_shutdown(struct rdsv3_connection *conn)
{
}

void
rdsv3_loop_exit(void)
{
	struct rdsv3_loop_connection *lc, *_lc;
	list_t tmp_list;

	RDSV3_DPRINTF4("rdsv3_loop_exit", "Enter");

	list_create(&tmp_list, sizeof (struct rdsv3_loop_connection),
	    offsetof(struct rdsv3_loop_connection, loop_node));

	/* avoid calling conn_destroy with irqs off */
	mutex_enter(&loop_conns_lock);
	list_splice(&loop_conns, &tmp_list);
	mutex_exit(&loop_conns_lock);

	RDSV3_FOR_EACH_LIST_NODE_SAFE(lc, _lc, &tmp_list, loop_node) {
		ASSERT(!lc->conn->c_passive);
		rdsv3_conn_destroy(lc->conn);
	}

	list_destroy(&loop_conns);
	mutex_destroy(&loop_conns_lock);

	RDSV3_DPRINTF4("rdsv3_loop_exit", "Return");
}

/*
 * This is missing .xmit_* because loop doesn't go through generic
 * rdsv3_send_xmit() and doesn't call rdsv3_recv_incoming().  .listen_stop and
 * .laddr_check are missing because transport.c doesn't iterate over
 * rdsv3_loop_transport.
 */
#ifndef __lock_lint
struct rdsv3_transport rdsv3_loop_transport = {
	.xmit			= rdsv3_loop_xmit,
	.xmit_cong_map		= rdsv3_loop_xmit_cong_map,
	.recv			= rdsv3_loop_recv,
	.conn_alloc		= rdsv3_loop_conn_alloc,
	.conn_free		= rdsv3_loop_conn_free,
	.conn_connect		= rdsv3_loop_conn_connect,
	.conn_shutdown		= rdsv3_loop_conn_shutdown,
	.inc_copy_to_user	= rdsv3_message_inc_copy_to_user,
	.inc_free		= rdsv3_loop_inc_free,
	.t_name			= "loopback",
};
#else
struct rdsv3_transport rdsv3_loop_transport;
#endif

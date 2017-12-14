/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file recv.c
 * Oracle elects to have and use the contents of rds_recv.c under and governed
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

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

void
rdsv3_inc_init(struct rdsv3_incoming *inc, struct rdsv3_connection *conn,
    uint32_be_t saddr)
{
	RDSV3_DPRINTF5("rdsv3_inc_init", "Enter(inc: %p, conn: %p)", inc, conn);
	inc->i_refcount = 1;
	list_link_init(&inc->i_item);
	inc->i_conn = conn;
	inc->i_saddr = saddr;
	inc->i_rdma_cookie = 0;
}

void
rdsv3_inc_addref(struct rdsv3_incoming *inc)
{
	RDSV3_DPRINTF4("rdsv3_inc_addref",
	    "addref inc %p ref %d", inc, atomic_get(&inc->i_refcount));
	atomic_inc_32(&inc->i_refcount);
}

void
rdsv3_inc_put(struct rdsv3_incoming *inc)
{
	RDSV3_DPRINTF4("rdsv3_inc_put", "put inc %p ref %d",
	    inc, atomic_get(&inc->i_refcount));
	if (atomic_dec_and_test(&inc->i_refcount)) {
		ASSERT(!list_link_active(&inc->i_item));

		inc->i_conn->c_trans->inc_free(inc);
	}
}

/*ARGSUSED*/
static void
rdsv3_recv_rcvbuf_delta(struct rdsv3_sock *rs, struct rsock *sk,
    struct rdsv3_cong_map *map,
    int delta, uint16_be_t port)
{
	int now_congested;

	RDSV3_DPRINTF4("rdsv3_recv_rcvbuf_delta",
	    "Enter(rs: %p, map: %p, delta: %d, port: %d)",
	    rs, map, delta, port);

	if (delta == 0)
		return;

	rs->rs_rcv_bytes += delta;
	now_congested = rs->rs_rcv_bytes > rdsv3_sk_rcvbuf(rs);

	RDSV3_DPRINTF5("rdsv3_recv_rcvbuf_delta",
	    "rs %p (%u.%u.%u.%u:%u) recv bytes %d buf %d "
	    "now_cong %d delta %d",
	    rs, NIPQUAD(rs->rs_bound_addr),
	    (int)ntohs(rs->rs_bound_port), rs->rs_rcv_bytes,
	    rdsv3_sk_rcvbuf(rs), now_congested, delta);

	/* wasn't -> am congested */
	if (!rs->rs_congested && now_congested) {
		rs->rs_congested = 1;
		rdsv3_cong_set_bit(map, port);
		rdsv3_cong_queue_updates(map);
	}
	/* was -> aren't congested */
	/*
	 * Require more free space before reporting uncongested to prevent
	 * bouncing cong/uncong state too often
	 */
	else if (rs->rs_congested &&
	    (rs->rs_rcv_bytes < (rdsv3_sk_rcvbuf(rs)/2))) {
		rs->rs_congested = 0;
		rdsv3_cong_clear_bit(map, port);
		rdsv3_cong_queue_updates(map);
	}

	/* do nothing if no change in cong state */

	RDSV3_DPRINTF4("rdsv3_recv_rcvbuf_delta", "Return(rs: %p)", rs);
}

/*
 * Process all extension headers that come with this message.
 */
static void
rdsv3_recv_incoming_exthdrs(struct rdsv3_incoming *inc, struct rdsv3_sock *rs)
{
	struct rdsv3_header *hdr = &inc->i_hdr;
	unsigned int pos = 0, type, len;
	union {
		struct rdsv3_ext_header_version version;
		struct rdsv3_ext_header_rdma rdma;
		struct rdsv3_ext_header_rdma_dest rdma_dest;
	} buffer;

	RDSV3_DPRINTF4("rdsv3_recv_incoming_exthdrs", "Enter");
	while (1) {
		len = sizeof (buffer);
		type = rdsv3_message_next_extension(hdr, &pos, &buffer, &len);
		if (type == RDSV3_EXTHDR_NONE)
			break;
		RDSV3_DPRINTF4("recv_incoming_exthdrs", "type %d", type);
		/* Process extension header here */
		switch (type) {
		case RDSV3_EXTHDR_RDMA:
			rdsv3_rdma_unuse(rs, ntohl(buffer.rdma.h_rdma_rkey),
			    0);
			break;

		case RDSV3_EXTHDR_RDMA_DEST:
			/*
			 * We ignore the size for now. We could stash it
			 * somewhere and use it for error checking.
			 */
			inc->i_rdma_cookie = rdsv3_rdma_make_cookie(
			    ntohl(buffer.rdma_dest.h_rdma_rkey),
			    ntohl(buffer.rdma_dest.h_rdma_offset));

			break;
		}
	}
	RDSV3_DPRINTF4("rdsv3_recv_incoming_exthdrs", "Return");
}

/*
 * The transport must make sure that this is serialized against other
 * rx and conn reset on this specific conn.
 *
 * We currently assert that only one fragmented message will be sent
 * down a connection at a time.  This lets us reassemble in the conn
 * instead of per-flow which means that we don't have to go digging through
 * flows to tear down partial reassembly progress on conn failure and
 * we save flow lookup and locking for each frag arrival.  It does mean
 * that small messages will wait behind large ones.  Fragmenting at all
 * is only to reduce the memory consumption of pre-posted buffers.
 *
 * The caller passes in saddr and daddr instead of us getting it from the
 * conn.  This lets loopback, who only has one conn for both directions,
 * tell us which roles the addrs in the conn are playing for this message.
 */
/* ARGSUSED */
void
rdsv3_recv_incoming(struct rdsv3_connection *conn, uint32_be_t saddr,
    uint32_be_t daddr, struct rdsv3_incoming *inc, int gfp)
{
	struct rdsv3_sock *rs = NULL;
	struct rsock *sk;

	inc->i_conn = conn;
	inc->i_rx_jiffies = jiffies;

	RDSV3_DPRINTF5("rdsv3_recv_incoming",
	    "conn %p next %llu inc %p seq %llu len %u sport %u dport %u "
	    "flags 0x%x rx_jiffies %lu", conn,
	    (unsigned long long)conn->c_next_rx_seq,
	    inc,
	    (unsigned long long)ntohll(inc->i_hdr.h_sequence),
	    ntohl(inc->i_hdr.h_len),
	    ntohs(inc->i_hdr.h_sport),
	    ntohs(inc->i_hdr.h_dport),
	    inc->i_hdr.h_flags,
	    inc->i_rx_jiffies);

	/*
	 * Sequence numbers should only increase.  Messages get their
	 * sequence number as they're queued in a sending conn.  They
	 * can be dropped, though, if the sending socket is closed before
	 * they hit the wire.  So sequence numbers can skip forward
	 * under normal operation.  They can also drop back in the conn
	 * failover case as previously sent messages are resent down the
	 * new instance of a conn.  We drop those, otherwise we have
	 * to assume that the next valid seq does not come after a
	 * hole in the fragment stream.
	 *
	 * The headers don't give us a way to realize if fragments of
	 * a message have been dropped.  We assume that frags that arrive
	 * to a flow are part of the current message on the flow that is
	 * being reassembled.  This means that senders can't drop messages
	 * from the sending conn until all their frags are sent.
	 *
	 * XXX we could spend more on the wire to get more robust failure
	 * detection, arguably worth it to avoid data corruption.
	 */
	if (ntohll(inc->i_hdr.h_sequence) < conn->c_next_rx_seq &&
	    (inc->i_hdr.h_flags & RDSV3_FLAG_RETRANSMITTED)) {
		rdsv3_stats_inc(s_recv_drop_old_seq);
		goto out;
	}
	conn->c_next_rx_seq = ntohll(inc->i_hdr.h_sequence) + 1;

	if (rdsv3_sysctl_ping_enable && inc->i_hdr.h_dport == 0) {
		rdsv3_stats_inc(s_recv_ping);
		(void) rdsv3_send_pong(conn, inc->i_hdr.h_sport);
		goto out;
	}

	rs = rdsv3_find_bound(conn, inc->i_hdr.h_dport);
	if (!rs) {
		rdsv3_stats_inc(s_recv_drop_no_sock);
		goto out;
	}

	/* Process extension headers */
	rdsv3_recv_incoming_exthdrs(inc, rs);

	/* We can be racing with rdsv3_release() which marks the socket dead. */
	sk = rdsv3_rs_to_sk(rs);

	/* serialize with rdsv3_release -> sock_orphan */
	rw_enter(&rs->rs_recv_lock, RW_WRITER);
	if (!rdsv3_sk_sock_flag(sk, SOCK_DEAD)) {
		int error, bytes;
		RDSV3_DPRINTF5("rdsv3_recv_incoming",
		    "adding inc %p to rs %p's recv queue", inc, rs);
		rdsv3_stats_inc(s_recv_queued);
		rdsv3_recv_rcvbuf_delta(rs, sk, inc->i_conn->c_lcong,
		    ntohl(inc->i_hdr.h_len),
		    inc->i_hdr.h_dport);
		rdsv3_inc_addref(inc);
		list_insert_tail(&rs->rs_recv_queue, inc);
		bytes = rs->rs_rcv_bytes;
		rw_exit(&rs->rs_recv_lock);

		__rdsv3_wake_sk_sleep(sk);

		/* wake up anyone waiting in poll */
		sk->sk_upcalls->su_recv(sk->sk_upper_handle, NULL,
		    bytes, 0, &error, NULL);
		if (error != 0) {
			RDSV3_DPRINTF2("rdsv3_recv_incoming",
			    "su_recv returned: %d", error);
		}
	} else {
		rdsv3_stats_inc(s_recv_drop_dead_sock);
		rw_exit(&rs->rs_recv_lock);
	}

out:
	if (rs)
		rdsv3_sock_put(rs);
}

/*
 * be very careful here.  This is being called as the condition in
 * wait_event_*() needs to cope with being called many times.
 */
static int
rdsv3_next_incoming(struct rdsv3_sock *rs, struct rdsv3_incoming **inc)
{
	if (!*inc) {
		rw_enter(&rs->rs_recv_lock, RW_READER);
		if (!list_is_empty(&rs->rs_recv_queue)) {
			*inc = list_head(&rs->rs_recv_queue);
			rdsv3_inc_addref(*inc);
		}
		rw_exit(&rs->rs_recv_lock);
	}

	return (*inc != NULL);
}

static int
rdsv3_still_queued(struct rdsv3_sock *rs, struct rdsv3_incoming *inc,
    int drop)
{
	struct rsock *sk = rdsv3_rs_to_sk(rs);
	int ret = 0;

	RDSV3_DPRINTF4("rdsv3_still_queued", "Enter rs: %p inc: %p drop: %d",
	    rs, inc, drop);

	rw_enter(&rs->rs_recv_lock, RW_WRITER);
	if (list_link_active(&inc->i_item)) {
		ret = 1;
		if (drop) {
			/* XXX make sure this i_conn is reliable */
			rdsv3_recv_rcvbuf_delta(rs, sk, inc->i_conn->c_lcong,
			    -ntohl(inc->i_hdr.h_len),
			    inc->i_hdr.h_dport);
			list_remove_node(&inc->i_item);
			rdsv3_inc_put(inc);
		}
	}
	rw_exit(&rs->rs_recv_lock);

	RDSV3_DPRINTF5("rdsv3_still_queued",
	    "inc %p rs %p still %d dropped %d", inc, rs, ret, drop);
	return (ret);
}

/*
 * Pull errors off the error queue.
 * If msghdr is NULL, we will just purge the error queue.
 */
int
rdsv3_notify_queue_get(struct rdsv3_sock *rs, struct msghdr *msghdr)
{
	struct rdsv3_notifier *notifier;
	struct rds_rdma_notify cmsg;
	unsigned int count = 0, max_messages = ~0U;
	list_t copy;
	int err = 0;

	RDSV3_DPRINTF4("rdsv3_notify_queue_get", "Enter(rs: %p)", rs);

	list_create(&copy, sizeof (struct rdsv3_notifier),
	    offsetof(struct rdsv3_notifier, n_list));


	/*
	 * put_cmsg copies to user space and thus may sleep. We can't do this
	 * with rs_lock held, so first grab as many notifications as we can
	 * stuff
	 * in the user provided cmsg buffer. We don't try to copy more, to avoid
	 * losing notifications - except when the buffer is so small that
	 * it wouldn't
	 * even hold a single notification. Then we give as much of this
	 * single
	 * msg as we can squeeze in, and set MSG_CTRUNC.
	 */
	if (msghdr) {
		max_messages =
		    msghdr->msg_controllen / CMSG_SPACE(sizeof (cmsg));
		if (!max_messages)
			max_messages = 1;
	}

	mutex_enter(&rs->rs_lock);
	while (!list_is_empty(&rs->rs_notify_queue) && count < max_messages) {
		notifier = list_remove_head(&rs->rs_notify_queue);
		list_insert_tail(&copy, notifier);
		count++;
	}
	mutex_exit(&rs->rs_lock);

	if (!count)
		return (0);

	while (!list_is_empty(&copy)) {
		notifier = list_remove_head(&copy);

		if (msghdr) {
			cmsg.user_token = notifier->n_user_token;
			cmsg.status  = notifier->n_status;

			err = rdsv3_put_cmsg(msghdr, SOL_RDS,
			    RDS_CMSG_RDMA_STATUS, sizeof (cmsg), &cmsg);
			if (err)
				break;
		}

		kmem_free(notifier, sizeof (struct rdsv3_notifier));
	}

	/*
	 * If we bailed out because of an error in put_cmsg,
	 * we may be left with one or more notifications that we
	 * didn't process. Return them to the head of the list.
	 */
	if (!list_is_empty(&copy)) {
		mutex_enter(&rs->rs_lock);
		list_splice(&copy, &rs->rs_notify_queue);
		mutex_exit(&rs->rs_lock);
	}

	RDSV3_DPRINTF4("rdsv3_notify_queue_get", "Return(rs: %p)", rs);

	return (err);
}

/*
 * Queue a congestion notification
 */
static int
rdsv3_notify_cong(struct rdsv3_sock *rs, struct msghdr *msghdr)
{
	uint64_t notify = rs->rs_cong_notify;
	int err;

	err = rdsv3_put_cmsg(msghdr, SOL_RDS, RDS_CMSG_CONG_UPDATE,
	    sizeof (notify), &notify);
	if (err)
		return (err);

	mutex_enter(&rs->rs_lock);
	rs->rs_cong_notify &= ~notify;
	mutex_exit(&rs->rs_lock);

	return (0);
}

/*
 * Receive any control messages.
 */
static int
rdsv3_cmsg_recv(struct rdsv3_incoming *inc, struct msghdr *msg)
{
	int ret = 0;
	if (inc->i_rdma_cookie) {
		ret = rdsv3_put_cmsg(msg, SOL_RDS, RDS_CMSG_RDMA_DEST,
		    sizeof (inc->i_rdma_cookie), &inc->i_rdma_cookie);
	}
	return (ret);
}

int
rdsv3_recvmsg(struct rdsv3_sock *rs, uio_t *uio,
    struct nmsghdr *msg, size_t size, int msg_flags)
{
	struct rsock *sk = rdsv3_rs_to_sk(rs);
	int ret = 0;
	struct sockaddr_in *sin = NULL;
	struct rdsv3_incoming *inc = NULL;
	boolean_t nonblock = B_FALSE;

	RDSV3_DPRINTF4("rdsv3_recvmsg",
	    "Enter(rs: %p size: %d msg_flags: 0x%x)", rs, size, msg_flags);

	if ((uio->uio_fmode & (FNDELAY | FNONBLOCK)) ||
	    (msg_flags & MSG_DONTWAIT))
		nonblock = B_TRUE;

	if (msg_flags & MSG_OOB)
		goto out;

	/* mark the first cmsg position */
	if (msg) {
		msg->msg_control = NULL;
	}

	while (1) {
		/*
		 * If there are pending notifications, do those -
		 * and nothing else
		 */
		if (!list_is_empty(&rs->rs_notify_queue)) {
			ret = rdsv3_notify_queue_get(rs, msg);

			if (msg && msg->msg_namelen) {
				sin = kmem_zalloc(sizeof (struct sockaddr_in),
				    KM_SLEEP);
				sin->sin_family = AF_INET_OFFLOAD;
				if (inc) {
					sin->sin_port = inc->i_hdr.h_sport;
					sin->sin_addr.s_addr = inc->i_saddr;
				}
				msg->msg_namelen = sizeof (struct sockaddr_in);
				msg->msg_name = sin;
			}
			break;
		}

		if (rs->rs_cong_notify) {
			ret = rdsv3_notify_cong(rs, msg);
			goto out;
		}

		if (!rdsv3_next_incoming(rs, &inc)) {
			if (nonblock) {
				ret = -EAGAIN;
				break;
			}

			RDSV3_DPRINTF3("rdsv3_recvmsg",
			    "Before wait (rs: %p)", rs);

#if 0
			ret = rdsv3_wait_sig(sk->sk_sleep,
			    !(list_is_empty(&rs->rs_notify_queue) &&
			    !rs->rs_cong_notify &&
			    !rdsv3_next_incoming(rs, &inc)));
			if (ret == 0) {
				/* signal/timeout pending */
				RDSV3_DPRINTF2("rdsv3_recvmsg",
				    "woke due to signal");
				ret = -ERESTART;
			}
#else
			mutex_enter(&sk->sk_sleep->waitq_mutex);
			sk->sk_sleep->waitq_waiters++;
			while ((list_is_empty(&rs->rs_notify_queue) &&
			    !rs->rs_cong_notify &&
			    !rdsv3_next_incoming(rs, &inc))) {
				ret = cv_wait_sig(&sk->sk_sleep->waitq_cv,
				    &sk->sk_sleep->waitq_mutex);
				if (ret == 0) {
					/* signal/timeout pending */
					RDSV3_DPRINTF2("rdsv3_recvmsg",
					    "woke due to signal");
					ret = -EINTR;
					break;
				}
			}
			sk->sk_sleep->waitq_waiters--;
			mutex_exit(&sk->sk_sleep->waitq_mutex);
#endif

			RDSV3_DPRINTF5("rdsv3_recvmsg",
			    "recvmsg woke rs: %p inc %p ret %d",
			    rs, inc, -ret);

			if (ret < 0)
				break;

			/*
			 * if the wakeup was due to rs_notify_queue or
			 * rs_cong_notify then we need to handle those first.
			 */
			continue;
		}

		RDSV3_DPRINTF5("rdsv3_recvmsg",
		    "copying inc %p from %u.%u.%u.%u:%u to user", inc,
		    NIPQUAD(inc->i_conn->c_faddr),
		    ntohs(inc->i_hdr.h_sport));

		ret = inc->i_conn->c_trans->inc_copy_to_user(inc, uio, size);
		if (ret < 0)
			break;

		/*
		 * if the message we just copied isn't at the head of the
		 * recv queue then someone else raced us to return it, try
		 * to get the next message.
		 */
		if (!rdsv3_still_queued(rs, inc, !(msg_flags & MSG_PEEK))) {
			rdsv3_inc_put(inc);
			inc = NULL;
			rdsv3_stats_inc(s_recv_deliver_raced);
			continue;
		}

		if (ret < ntohl(inc->i_hdr.h_len)) {
			if (msg_flags & MSG_TRUNC)
				ret = ntohl(inc->i_hdr.h_len);
			msg->msg_flags |= MSG_TRUNC;
		}

		if (rdsv3_cmsg_recv(inc, msg)) {
			ret = -EFAULT;
			goto out;
		}

		rdsv3_stats_inc(s_recv_delivered);

		if (msg->msg_namelen) {
			sin = kmem_alloc(sizeof (struct sockaddr_in), KM_SLEEP);
			sin->sin_family = AF_INET_OFFLOAD;
			sin->sin_port = inc->i_hdr.h_sport;
			sin->sin_addr.s_addr = inc->i_saddr;
			(void) memset(sin->sin_zero, 0,
			    sizeof (sin->sin_zero));
			msg->msg_namelen = sizeof (struct sockaddr_in);
			msg->msg_name = sin;
		}
		break;
	}

	if (inc)
		rdsv3_inc_put(inc);

out:
	if (msg && msg->msg_control == NULL)
		msg->msg_controllen = 0;

	RDSV3_DPRINTF4("rdsv3_recvmsg", "Return(rs: %p, ret: %d)", rs, ret);

	return (ret);
}

/*
 * The socket is being shut down and we're asked to drop messages that were
 * queued for recvmsg.  The caller has unbound the socket so the receive path
 * won't queue any more incoming fragments or messages on the socket.
 */
void
rdsv3_clear_recv_queue(struct rdsv3_sock *rs)
{
	struct rsock *sk = rdsv3_rs_to_sk(rs);
	struct rdsv3_incoming *inc, *tmp;

	RDSV3_DPRINTF4("rdsv3_clear_recv_queue", "Enter(rs: %p)", rs);

	rw_enter(&rs->rs_recv_lock, RW_WRITER);
	RDSV3_FOR_EACH_LIST_NODE_SAFE(inc, tmp, &rs->rs_recv_queue, i_item) {
		rdsv3_recv_rcvbuf_delta(rs, sk, inc->i_conn->c_lcong,
		    -ntohl(inc->i_hdr.h_len),
		    inc->i_hdr.h_dport);
		list_remove_node(&inc->i_item);
		rdsv3_inc_put(inc);
	}
	rw_exit(&rs->rs_recv_lock);

	RDSV3_DPRINTF4("rdsv3_clear_recv_queue", "Return(rs: %p)", rs);
}

/*
 * inc->i_saddr isn't used here because it is only set in the receive
 * path.
 */
void
rdsv3_inc_info_copy(struct rdsv3_incoming *inc,
    struct rdsv3_info_iterator *iter,
    uint32_be_t saddr, uint32_be_t daddr, int flip)
{
	struct rds_info_message minfo;

	minfo.seq = ntohll(inc->i_hdr.h_sequence);
	minfo.len = ntohl(inc->i_hdr.h_len);

	if (flip) {
		minfo.laddr = daddr;
		minfo.faddr = saddr;
		minfo.lport = inc->i_hdr.h_dport;
		minfo.fport = inc->i_hdr.h_sport;
	} else {
		minfo.laddr = saddr;
		minfo.faddr = daddr;
		minfo.lport = inc->i_hdr.h_sport;
		minfo.fport = inc->i_hdr.h_dport;
	}

	rdsv3_info_copy(iter, &minfo, sizeof (minfo));
}

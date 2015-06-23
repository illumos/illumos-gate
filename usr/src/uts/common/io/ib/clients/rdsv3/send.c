/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file send.c
 * Oracle elects to have and use the contents of send.c under and governed
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
#include <sys/stropts.h>
#include <sys/systm.h>

#include <sys/rds.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

/*
 * When transmitting messages in rdsv3_send_xmit, we need to emerge from
 * time to time and briefly release the CPU. Otherwise the softlock watchdog
 * will kick our shin.
 * Also, it seems fairer to not let one busy connection stall all the
 * others.
 *
 * send_batch_count is the number of times we'll loop in send_xmit. Setting
 * it to 0 will restore the old behavior (where we looped until we had
 * drained the queue).
 */
static int send_batch_count = 64;

extern void rdsv3_ib_send_unmap_rdma(void *ic, struct rdsv3_rdma_op *op);
/*
 * Reset the send state. Caller must hold c_send_lock when calling here.
 */
void
rdsv3_send_reset(struct rdsv3_connection *conn)
{
	struct rdsv3_message *rm, *tmp;
	struct rdsv3_rdma_op *ro;

	RDSV3_DPRINTF4("rdsv3_send_reset", "Enter(conn: %p)", conn);

	ASSERT(MUTEX_HELD(&conn->c_send_lock));

	if (conn->c_xmit_rm) {
		rm = conn->c_xmit_rm;
		ro = rm->m_rdma_op;
		if (ro && ro->r_mapped) {
			RDSV3_DPRINTF2("rdsv3_send_reset",
			    "rm %p mflg 0x%x map %d mihdl %p sgl %p",
			    rm, rm->m_flags, ro->r_mapped,
			    ro->r_rdma_sg[0].mihdl,
			    ro->r_rdma_sg[0].swr.wr_sgl);
			rdsv3_ib_send_unmap_rdma(conn->c_transport_data, ro);
		}
		/*
		 * Tell the user the RDMA op is no longer mapped by the
		 * transport. This isn't entirely true (it's flushed out
		 * independently) but as the connection is down, there's
		 * no ongoing RDMA to/from that memory
		 */
		rdsv3_message_unmapped(conn->c_xmit_rm);
		rdsv3_message_put(conn->c_xmit_rm);
		conn->c_xmit_rm = NULL;
	}

	conn->c_xmit_sg = 0;
	conn->c_xmit_hdr_off = 0;
	conn->c_xmit_data_off = 0;
	conn->c_xmit_rdma_sent = 0;
	conn->c_map_queued = 0;

	conn->c_unacked_packets = rdsv3_sysctl_max_unacked_packets;
	conn->c_unacked_bytes = rdsv3_sysctl_max_unacked_bytes;

	/* Mark messages as retransmissions, and move them to the send q */
	mutex_enter(&conn->c_lock);
	RDSV3_FOR_EACH_LIST_NODE_SAFE(rm, tmp, &conn->c_retrans, m_conn_item) {
		set_bit(RDSV3_MSG_ACK_REQUIRED, &rm->m_flags);
		set_bit(RDSV3_MSG_RETRANSMITTED, &rm->m_flags);
		if (rm->m_rdma_op && rm->m_rdma_op->r_mapped) {
			RDSV3_DPRINTF4("_send_reset",
			    "RT rm %p mflg 0x%x sgl %p",
			    rm, rm->m_flags,
			    rm->m_rdma_op->r_rdma_sg[0].swr.wr_sgl);
		}
	}
	list_move_tail(&conn->c_send_queue, &conn->c_retrans);
	mutex_exit(&conn->c_lock);

	RDSV3_DPRINTF4("rdsv3_send_reset", "Return(conn: %p)", conn);
}

/*
 * We're making the concious trade-off here to only send one message
 * down the connection at a time.
 *   Pro:
 *      - tx queueing is a simple fifo list
 *   	- reassembly is optional and easily done by transports per conn
 *      - no per flow rx lookup at all, straight to the socket
 *   	- less per-frag memory and wire overhead
 *   Con:
 *      - queued acks can be delayed behind large messages
 *   Depends:
 *      - small message latency is higher behind queued large messages
 *      - large message latency isn't starved by intervening small sends
 */
int
rdsv3_send_xmit(struct rdsv3_connection *conn)
{
	struct rdsv3_message *rm;
	unsigned int tmp;
	unsigned int send_quota = send_batch_count;
	struct rdsv3_scatterlist *sg;
	int ret = 0;
	int was_empty = 0;
	list_t to_be_dropped;

restart:
	if (!rdsv3_conn_up(conn))
		goto out;

	RDSV3_DPRINTF4("rdsv3_send_xmit", "Enter(conn: %p)", conn);

	list_create(&to_be_dropped, sizeof (struct rdsv3_message),
	    offsetof(struct rdsv3_message, m_conn_item));

	/*
	 * sendmsg calls here after having queued its message on the send
	 * queue.  We only have one task feeding the connection at a time.  If
	 * another thread is already feeding the queue then we back off.  This
	 * avoids blocking the caller and trading per-connection data between
	 * caches per message.
	 */
	if (!mutex_tryenter(&conn->c_send_lock)) {
		RDSV3_DPRINTF4("rdsv3_send_xmit",
		    "Another thread running(conn: %p)", conn);
		rdsv3_stats_inc(s_send_sem_contention);
		ret = -ENOMEM;
		goto out;
	}
	atomic_inc_32(&conn->c_senders);

	if (conn->c_trans->xmit_prepare)
		conn->c_trans->xmit_prepare(conn);

	/*
	 * spin trying to push headers and data down the connection until
	 * the connection doesn't make forward progress.
	 */
	while (--send_quota) {
		/*
		 * See if need to send a congestion map update if we're
		 * between sending messages.  The send_sem protects our sole
		 * use of c_map_offset and _bytes.
		 * Note this is used only by transports that define a special
		 * xmit_cong_map function. For all others, we create allocate
		 * a cong_map message and treat it just like any other send.
		 */
		if (conn->c_map_bytes) {
			ret = conn->c_trans->xmit_cong_map(conn, conn->c_lcong,
			    conn->c_map_offset);
			if (ret <= 0)
				break;

			conn->c_map_offset += ret;
			conn->c_map_bytes -= ret;
			if (conn->c_map_bytes)
				continue;
		}

		/*
		 * If we're done sending the current message, clear the
		 * offset and S/G temporaries.
		 */
		rm = conn->c_xmit_rm;
		if (rm != NULL &&
		    conn->c_xmit_hdr_off == sizeof (struct rdsv3_header) &&
		    conn->c_xmit_sg == rm->m_nents) {
			conn->c_xmit_rm = NULL;
			conn->c_xmit_sg = 0;
			conn->c_xmit_hdr_off = 0;
			conn->c_xmit_data_off = 0;
			conn->c_xmit_rdma_sent = 0;

			/* Release the reference to the previous message. */
			rdsv3_message_put(rm);
			rm = NULL;
		}

		/* If we're asked to send a cong map update, do so. */
		if (rm == NULL && test_and_clear_bit(0, &conn->c_map_queued)) {
			if (conn->c_trans->xmit_cong_map != NULL) {
				conn->c_map_offset = 0;
				conn->c_map_bytes =
				    sizeof (struct rdsv3_header) +
				    RDSV3_CONG_MAP_BYTES;
				continue;
			}

			rm = rdsv3_cong_update_alloc(conn);
			if (IS_ERR(rm)) {
				ret = PTR_ERR(rm);
				break;
			}

			conn->c_xmit_rm = rm;
		}

		/*
		 * Grab the next message from the send queue, if there is one.
		 *
		 * c_xmit_rm holds a ref while we're sending this message down
		 * the connction.  We can use this ref while holding the
		 * send_sem.. rdsv3_send_reset() is serialized with it.
		 */
		if (rm == NULL) {
			unsigned int len;

			mutex_enter(&conn->c_lock);

			if (!list_is_empty(&conn->c_send_queue)) {
				rm = list_remove_head(&conn->c_send_queue);
				rdsv3_message_addref(rm);

				/*
				 * Move the message from the send queue to
				 * the retransmit
				 * list right away.
				 */
				list_insert_tail(&conn->c_retrans, rm);
			}

			mutex_exit(&conn->c_lock);

			if (rm == NULL) {
				was_empty = 1;
				break;
			}

			/*
			 * Unfortunately, the way Infiniband deals with
			 * RDMA to a bad MR key is by moving the entire
			 * queue pair to error state. We cold possibly
			 * recover from that, but right now we drop the
			 * connection.
			 * Therefore, we never retransmit messages with
			 * RDMA ops.
			 */
			if (rm->m_rdma_op &&
			    test_bit(RDSV3_MSG_RETRANSMITTED, &rm->m_flags)) {
				mutex_enter(&conn->c_lock);
				if (test_and_clear_bit(RDSV3_MSG_ON_CONN,
				    &rm->m_flags))
					list_remove_node(&rm->m_conn_item);
					list_insert_tail(&to_be_dropped, rm);
				mutex_exit(&conn->c_lock);
				rdsv3_message_put(rm);
				continue;
			}

			/* Require an ACK every once in a while */
			len = ntohl(rm->m_inc.i_hdr.h_len);
			if (conn->c_unacked_packets == 0 ||
			    conn->c_unacked_bytes < len) {
				set_bit(RDSV3_MSG_ACK_REQUIRED, &rm->m_flags);

				conn->c_unacked_packets =
				    rdsv3_sysctl_max_unacked_packets;
				conn->c_unacked_bytes =
				    rdsv3_sysctl_max_unacked_bytes;
				rdsv3_stats_inc(s_send_ack_required);
			} else {
				conn->c_unacked_bytes -= len;
				conn->c_unacked_packets--;
			}

			conn->c_xmit_rm = rm;
		}

		/*
		 * Try and send an rdma message.  Let's see if we can
		 * keep this simple and require that the transport either
		 * send the whole rdma or none of it.
		 */
		if (rm->m_rdma_op && !conn->c_xmit_rdma_sent) {
			ret = conn->c_trans->xmit_rdma(conn, rm->m_rdma_op);
			if (ret)
				break;
			conn->c_xmit_rdma_sent = 1;
			/*
			 * The transport owns the mapped memory for now.
			 * You can't unmap it while it's on the send queue
			 */
			set_bit(RDSV3_MSG_MAPPED, &rm->m_flags);
		}

		if (conn->c_xmit_hdr_off < sizeof (struct rdsv3_header) ||
		    conn->c_xmit_sg < rm->m_nents) {
			ret = conn->c_trans->xmit(conn, rm,
			    conn->c_xmit_hdr_off,
			    conn->c_xmit_sg,
			    conn->c_xmit_data_off);
			if (ret <= 0)
				break;

			if (conn->c_xmit_hdr_off <
			    sizeof (struct rdsv3_header)) {
				tmp = min(ret,
				    sizeof (struct rdsv3_header) -
				    conn->c_xmit_hdr_off);
				conn->c_xmit_hdr_off += tmp;
				ret -= tmp;
			}

			sg = &rm->m_sg[conn->c_xmit_sg];
			while (ret) {
				tmp = min(ret, rdsv3_sg_len(sg) -
				    conn->c_xmit_data_off);
				conn->c_xmit_data_off += tmp;
				ret -= tmp;
				if (conn->c_xmit_data_off == rdsv3_sg_len(sg)) {
					conn->c_xmit_data_off = 0;
					sg++;
					conn->c_xmit_sg++;
					ASSERT(!(ret != 0 &&
					    conn->c_xmit_sg == rm->m_nents));
				}
			}
		}
	}

	/* Nuke any messages we decided not to retransmit. */
	if (!list_is_empty(&to_be_dropped))
		rdsv3_send_remove_from_sock(&to_be_dropped, RDS_RDMA_DROPPED);

	if (conn->c_trans->xmit_complete)
		conn->c_trans->xmit_complete(conn);

	/*
	 * We might be racing with another sender who queued a message but
	 * backed off on noticing that we held the c_send_lock.  If we check
	 * for queued messages after dropping the sem then either we'll
	 * see the queued message or the queuer will get the sem.  If we
	 * notice the queued message then we trigger an immediate retry.
	 *
	 * We need to be careful only to do this when we stopped processing
	 * the send queue because it was empty.  It's the only way we
	 * stop processing the loop when the transport hasn't taken
	 * responsibility for forward progress.
	 */
	mutex_exit(&conn->c_send_lock);

	if (conn->c_map_bytes || (send_quota == 0 && !was_empty)) {
		/*
		 * We exhausted the send quota, but there's work left to
		 * do. Return and (re-)schedule the send worker.
		 */
		ret = -EAGAIN;
	}

	atomic_dec_32(&conn->c_senders);

	if (ret == 0 && was_empty) {
		/*
		 * A simple bit test would be way faster than taking the
		 * spin lock
		 */
		mutex_enter(&conn->c_lock);
		if (!list_is_empty(&conn->c_send_queue)) {
			rdsv3_stats_inc(s_send_sem_queue_raced);
			ret = -EAGAIN;
		}
		mutex_exit(&conn->c_lock);
	}

out:
	RDSV3_DPRINTF4("rdsv3_send_xmit", "Return(conn: %p, ret: %d)",
	    conn, ret);
	return (ret);
}

static void
rdsv3_send_sndbuf_remove(struct rdsv3_sock *rs, struct rdsv3_message *rm)
{
	uint32_t len = ntohl(rm->m_inc.i_hdr.h_len);

	ASSERT(mutex_owned(&rs->rs_lock));

	ASSERT(rs->rs_snd_bytes >= len);
	rs->rs_snd_bytes -= len;

	if (rs->rs_snd_bytes == 0)
		rdsv3_stats_inc(s_send_queue_empty);
}

static inline int
rdsv3_send_is_acked(struct rdsv3_message *rm, uint64_t ack,
    is_acked_func is_acked)
{
	if (is_acked)
		return (is_acked(rm, ack));
	return (ntohll(rm->m_inc.i_hdr.h_sequence) <= ack);
}

/*
 * Returns true if there are no messages on the send and retransmit queues
 * which have a sequence number greater than or equal to the given sequence
 * number.
 */
int
rdsv3_send_acked_before(struct rdsv3_connection *conn, uint64_t seq)
{
	struct rdsv3_message *rm;
	int ret = 1;

	RDSV3_DPRINTF4("rdsv3_send_acked_before", "Enter(conn: %p)", conn);

	mutex_enter(&conn->c_lock);

	/* XXX - original code spits out warning */
	rm = list_head(&conn->c_retrans);
	if (ntohll(rm->m_inc.i_hdr.h_sequence) < seq)
		ret = 0;

	/* XXX - original code spits out warning */
	rm = list_head(&conn->c_send_queue);
	if (ntohll(rm->m_inc.i_hdr.h_sequence) < seq)
		ret = 0;

	mutex_exit(&conn->c_lock);

	RDSV3_DPRINTF4("rdsv3_send_acked_before", "Return(conn: %p)", conn);

	return (ret);
}

/*
 * This is pretty similar to what happens below in the ACK
 * handling code - except that we call here as soon as we get
 * the IB send completion on the RDMA op and the accompanying
 * message.
 */
void
rdsv3_rdma_send_complete(struct rdsv3_message *rm, int status)
{
	struct rdsv3_sock *rs = NULL;
	struct rdsv3_rdma_op *ro;
	struct rdsv3_notifier *notifier;

	RDSV3_DPRINTF4("rdsv3_rdma_send_complete", "Enter(rm: %p)", rm);

	mutex_enter(&rm->m_rs_lock);

	ro = rm->m_rdma_op;
	if (test_bit(RDSV3_MSG_ON_SOCK, &rm->m_flags) &&
	    ro && ro->r_notify && ro->r_notifier) {
		notifier = ro->r_notifier;
		rs = rm->m_rs;
		rdsv3_sk_sock_hold(rdsv3_rs_to_sk(rs));

		notifier->n_status = status;
		mutex_enter(&rs->rs_lock);
		list_insert_tail(&rs->rs_notify_queue, notifier);
		mutex_exit(&rs->rs_lock);
		ro->r_notifier = NULL;
	}

	mutex_exit(&rm->m_rs_lock);

	if (rs) {
		struct rsock *sk = rdsv3_rs_to_sk(rs);
		int error;

		rdsv3_wake_sk_sleep(rs);

		/* wake up anyone waiting in poll */
		sk->sk_upcalls->su_recv(sk->sk_upper_handle, NULL,
		    0, 0, &error, NULL);
		if (error != 0) {
			RDSV3_DPRINTF2("rdsv3_recv_incoming",
			    "su_recv returned: %d", error);
		}

		rdsv3_sk_sock_put(rdsv3_rs_to_sk(rs));
	}

	RDSV3_DPRINTF4("rdsv3_rdma_send_complete", "Return(rm: %p)", rm);
}

/*
 * This is the same as rdsv3_rdma_send_complete except we
 * don't do any locking - we have all the ingredients (message,
 * socket, socket lock) and can just move the notifier.
 */
static inline void
__rdsv3_rdma_send_complete(struct rdsv3_sock *rs, struct rdsv3_message *rm,
    int status)
{
	struct rdsv3_rdma_op *ro;
	void *ic;

	RDSV3_DPRINTF4("__rdsv3_rdma_send_complete",
	    "Enter(rs: %p, rm: %p)", rs, rm);

	ro = rm->m_rdma_op;
	if (ro && ro->r_notify && ro->r_notifier) {
		ro->r_notifier->n_status = status;
		list_insert_tail(&rs->rs_notify_queue, ro->r_notifier);
		ro->r_notifier = NULL;
	}

	/* No need to wake the app - caller does this */
}

/*
 * This is called from the IB send completion when we detect
 * a RDMA operation that failed with remote access error.
 * So speed is not an issue here.
 */
struct rdsv3_message *
rdsv3_send_get_message(struct rdsv3_connection *conn,
    struct rdsv3_rdma_op *op)
{
	struct rdsv3_message *rm, *tmp, *found = NULL;

	RDSV3_DPRINTF4("rdsv3_send_get_message", "Enter(conn: %p)", conn);

	mutex_enter(&conn->c_lock);

	RDSV3_FOR_EACH_LIST_NODE_SAFE(rm, tmp, &conn->c_retrans, m_conn_item) {
		if (rm->m_rdma_op == op) {
			atomic_inc_32(&rm->m_refcount);
			found = rm;
			goto out;
		}
	}

	RDSV3_FOR_EACH_LIST_NODE_SAFE(rm, tmp, &conn->c_send_queue,
	    m_conn_item) {
		if (rm->m_rdma_op == op) {
			atomic_inc_32(&rm->m_refcount);
			found = rm;
			break;
		}
	}

out:
	mutex_exit(&conn->c_lock);

	return (found);
}

/*
 * This removes messages from the socket's list if they're on it.  The list
 * argument must be private to the caller, we must be able to modify it
 * without locks.  The messages must have a reference held for their
 * position on the list.  This function will drop that reference after
 * removing the messages from the 'messages' list regardless of if it found
 * the messages on the socket list or not.
 */
void
rdsv3_send_remove_from_sock(struct list *messages, int status)
{
	struct rdsv3_sock *rs = NULL;
	struct rdsv3_message *rm;

	RDSV3_DPRINTF4("rdsv3_send_remove_from_sock", "Enter");

	while (!list_is_empty(messages)) {
		int was_on_sock = 0;
		rm = list_remove_head(messages);

		/*
		 * If we see this flag cleared then we're *sure* that someone
		 * else beat us to removing it from the sock.  If we race
		 * with their flag update we'll get the lock and then really
		 * see that the flag has been cleared.
		 *
		 * The message spinlock makes sure nobody clears rm->m_rs
		 * while we're messing with it. It does not prevent the
		 * message from being removed from the socket, though.
		 */
		mutex_enter(&rm->m_rs_lock);
		if (!test_bit(RDSV3_MSG_ON_SOCK, &rm->m_flags))
			goto unlock_and_drop;

		if (rs != rm->m_rs) {
			if (rs) {
				rdsv3_wake_sk_sleep(rs);
				rdsv3_sk_sock_put(rdsv3_rs_to_sk(rs));
			}
			rs = rm->m_rs;
			rdsv3_sk_sock_hold(rdsv3_rs_to_sk(rs));
		}

		mutex_enter(&rs->rs_lock);
		if (test_and_clear_bit(RDSV3_MSG_ON_SOCK, &rm->m_flags)) {
			struct rdsv3_rdma_op *ro = rm->m_rdma_op;
			struct rdsv3_notifier *notifier;

			list_remove_node(&rm->m_sock_item);
			rdsv3_send_sndbuf_remove(rs, rm);
			if (ro && ro->r_notifier &&
			    (status || ro->r_notify)) {
				notifier = ro->r_notifier;
				list_insert_tail(&rs->rs_notify_queue,
				    notifier);
				if (!notifier->n_status)
					notifier->n_status = status;
				rm->m_rdma_op->r_notifier = NULL;
			}
			was_on_sock = 1;
			rm->m_rs = NULL;
		}
		mutex_exit(&rs->rs_lock);

unlock_and_drop:
		mutex_exit(&rm->m_rs_lock);
		rdsv3_message_put(rm);
		if (was_on_sock)
			rdsv3_message_put(rm);
	}

	if (rs) {
		rdsv3_wake_sk_sleep(rs);
		rdsv3_sk_sock_put(rdsv3_rs_to_sk(rs));
	}

	RDSV3_DPRINTF4("rdsv3_send_remove_from_sock", "Return");
}

/*
 * Transports call here when they've determined that the receiver queued
 * messages up to, and including, the given sequence number.  Messages are
 * moved to the retrans queue when rdsv3_send_xmit picks them off the send
 * queue. This means that in the TCP case, the message may not have been
 * assigned the m_ack_seq yet - but that's fine as long as tcp_is_acked
 * checks the RDSV3_MSG_HAS_ACK_SEQ bit.
 *
 * XXX It's not clear to me how this is safely serialized with socket
 * destruction.  Maybe it should bail if it sees SOCK_DEAD.
 */
void
rdsv3_send_drop_acked(struct rdsv3_connection *conn, uint64_t ack,
    is_acked_func is_acked)
{
	struct rdsv3_message *rm, *tmp;
	list_t list;

	RDSV3_DPRINTF4("rdsv3_send_drop_acked", "Enter(conn: %p)", conn);

	list_create(&list, sizeof (struct rdsv3_message),
	    offsetof(struct rdsv3_message, m_conn_item));

	mutex_enter(&conn->c_lock);

	RDSV3_FOR_EACH_LIST_NODE_SAFE(rm, tmp, &conn->c_retrans, m_conn_item) {
		if (!rdsv3_send_is_acked(rm, ack, is_acked))
			break;

		list_remove_node(&rm->m_conn_item);
		list_insert_tail(&list, rm);
		clear_bit(RDSV3_MSG_ON_CONN, &rm->m_flags);
	}

#if 0
XXX
	/* order flag updates with spin locks */
	if (!list_is_empty(&list))
		smp_mb__after_clear_bit();
#endif

	mutex_exit(&conn->c_lock);

	/* now remove the messages from the sock list as needed */
	rdsv3_send_remove_from_sock(&list, RDS_RDMA_SUCCESS);

	RDSV3_DPRINTF4("rdsv3_send_drop_acked", "Return(conn: %p)", conn);
}

void
rdsv3_send_drop_to(struct rdsv3_sock *rs, struct sockaddr_in *dest)
{
	struct rdsv3_message *rm, *tmp;
	struct rdsv3_connection *conn;
	list_t list;
	int wake = 0;

	RDSV3_DPRINTF4("rdsv3_send_drop_to", "Enter(rs: %p)", rs);

	list_create(&list, sizeof (struct rdsv3_message),
	    offsetof(struct rdsv3_message, m_sock_item));

	/* get all the messages we're dropping under the rs lock */
	mutex_enter(&rs->rs_lock);

	RDSV3_FOR_EACH_LIST_NODE_SAFE(rm, tmp, &rs->rs_send_queue,
	    m_sock_item) {
		if (dest && (dest->sin_addr.s_addr != rm->m_daddr ||
		    dest->sin_port != rm->m_inc.i_hdr.h_dport))
			continue;
		wake = 1;
		list_remove(&rs->rs_send_queue, rm);
		list_insert_tail(&list, rm);
		rdsv3_send_sndbuf_remove(rs, rm);
		clear_bit(RDSV3_MSG_ON_SOCK, &rm->m_flags);
	}

	mutex_exit(&rs->rs_lock);

	conn = NULL;

	/* now remove the messages from the conn list as needed */
	RDSV3_FOR_EACH_LIST_NODE(rm, &list, m_sock_item) {
		/*
		 * We do this here rather than in the loop above, so that
		 * we don't have to nest m_rs_lock under rs->rs_lock
		 */
		mutex_enter(&rm->m_rs_lock);
		/* If this is a RDMA operation, notify the app. */
		__rdsv3_rdma_send_complete(rs, rm, RDS_RDMA_CANCELED);
		rm->m_rs = NULL;
		mutex_exit(&rm->m_rs_lock);

		/*
		 * If we see this flag cleared then we're *sure* that someone
		 * else beat us to removing it from the conn.  If we race
		 * with their flag update we'll get the lock and then really
		 * see that the flag has been cleared.
		 */
		if (!test_bit(RDSV3_MSG_ON_CONN, &rm->m_flags))
			continue;

		if (conn != rm->m_inc.i_conn) {
			if (conn)
				mutex_exit(&conn->c_lock);
			conn = rm->m_inc.i_conn;
			mutex_enter(&conn->c_lock);
		}

		if (test_and_clear_bit(RDSV3_MSG_ON_CONN, &rm->m_flags)) {
			list_remove_node(&rm->m_conn_item);
			rdsv3_message_put(rm);
		}
	}

	if (conn)
		mutex_exit(&conn->c_lock);

	if (wake)
		rdsv3_wake_sk_sleep(rs);

	while (!list_is_empty(&list)) {
		rm = list_remove_head(&list);

		rdsv3_message_wait(rm);
		rdsv3_message_put(rm);
	}

	RDSV3_DPRINTF4("rdsv3_send_drop_to", "Return(rs: %p)", rs);
}

/*
 * we only want this to fire once so we use the callers 'queued'.  It's
 * possible that another thread can race with us and remove the
 * message from the flow with RDSV3_CANCEL_SENT_TO.
 */
static int
rdsv3_send_queue_rm(struct rdsv3_sock *rs, struct rdsv3_connection *conn,
    struct rdsv3_message *rm, uint16_be_t sport,
    uint16_be_t dport, int *queued)
{
	uint32_t len;

	RDSV3_DPRINTF4("rdsv3_send_queue_rm", "Enter(rs: %p, rm: %p)", rs, rm);

	if (*queued)
		goto out;

	len = ntohl(rm->m_inc.i_hdr.h_len);

	/*
	 * this is the only place which holds both the socket's rs_lock
	 * and the connection's c_lock
	 */
	mutex_enter(&rs->rs_lock);

	/*
	 * If there is a little space in sndbuf, we don't queue anything,
	 * and userspace gets -EAGAIN. But poll() indicates there's send
	 * room. This can lead to bad behavior (spinning) if snd_bytes isn't
	 * freed up by incoming acks. So we check the *old* value of
	 * rs_snd_bytes here to allow the last msg to exceed the buffer,
	 * and poll() now knows no more data can be sent.
	 */
	if (rs->rs_snd_bytes < rdsv3_sk_sndbuf(rs)) {
		rs->rs_snd_bytes += len;

		/*
		 * let recv side know we are close to send space exhaustion.
		 * This is probably not the optimal way to do it, as this
		 * means we set the flag on *all* messages as soon as our
		 * throughput hits a certain threshold.
		 */
		if (rs->rs_snd_bytes >= rdsv3_sk_sndbuf(rs) / 2)
			set_bit(RDSV3_MSG_ACK_REQUIRED, &rm->m_flags);

		list_insert_tail(&rs->rs_send_queue, rm);
		set_bit(RDSV3_MSG_ON_SOCK, &rm->m_flags);

		rdsv3_message_addref(rm);
		rm->m_rs = rs;

		/*
		 * The code ordering is a little weird, but we're
		 * trying to minimize the time we hold c_lock
		 */
		rdsv3_message_populate_header(&rm->m_inc.i_hdr, sport,
		    dport, 0);
		rm->m_inc.i_conn = conn;
		rdsv3_message_addref(rm);	/* XXX - called twice */

		mutex_enter(&conn->c_lock);
		rm->m_inc.i_hdr.h_sequence = htonll(conn->c_next_tx_seq++);
		list_insert_tail(&conn->c_send_queue, rm);
		set_bit(RDSV3_MSG_ON_CONN, &rm->m_flags);
		mutex_exit(&conn->c_lock);

		RDSV3_DPRINTF5("rdsv3_send_queue_rm",
		    "queued msg %p len %d, rs %p bytes %d seq %llu",
		    rm, len, rs, rs->rs_snd_bytes,
		    (unsigned long long)ntohll(
		    rm->m_inc.i_hdr.h_sequence));

		*queued = 1;
	}

	mutex_exit(&rs->rs_lock);

	RDSV3_DPRINTF4("rdsv3_send_queue_rm", "Return(rs: %p)", rs);
out:
	return (*queued);
}

static int
rdsv3_cmsg_send(struct rdsv3_sock *rs, struct rdsv3_message *rm,
    struct msghdr *msg, int *allocated_mr)
{
	struct cmsghdr *cmsg;
	int ret = 0;

	RDSV3_DPRINTF4("rdsv3_cmsg_send", "Enter(rs: %p)", rs);

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {

		if (cmsg->cmsg_level != SOL_RDS)
			continue;

		RDSV3_DPRINTF4("rdsv3_cmsg_send", "cmsg(%p, %p) type %d",
		    cmsg, rm, cmsg->cmsg_type);
		/*
		 * As a side effect, RDMA_DEST and RDMA_MAP will set
		 * rm->m_rdma_cookie and rm->m_rdma_mr.
		 */
		switch (cmsg->cmsg_type) {
		case RDS_CMSG_RDMA_ARGS:
			ret = rdsv3_cmsg_rdma_args(rs, rm, cmsg);
			break;

		case RDS_CMSG_RDMA_DEST:
			ret = rdsv3_cmsg_rdma_dest(rs, rm, cmsg);
			break;

		case RDS_CMSG_RDMA_MAP:
			ret = rdsv3_cmsg_rdma_map(rs, rm, cmsg);
			if (ret)
				*allocated_mr = 1;
			break;

		default:
			return (-EINVAL);
		}

		if (ret)
			break;
	}

	RDSV3_DPRINTF4("rdsv3_cmsg_send", "Return(rs: %p)", rs);

	return (ret);
}

extern unsigned long rdsv3_max_bcopy_size;

int
rdsv3_sendmsg(struct rdsv3_sock *rs, uio_t *uio, struct nmsghdr *msg,
    size_t payload_len)
{
	struct rsock *sk = rdsv3_rs_to_sk(rs);
	struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
	uint32_be_t daddr;
	uint16_be_t dport;
	struct rdsv3_message *rm = NULL;
	struct rdsv3_connection *conn;
	int ret = 0;
	int queued = 0, allocated_mr = 0;
	int nonblock = msg->msg_flags & MSG_DONTWAIT;
	long timeo = rdsv3_sndtimeo(sk, nonblock);

	RDSV3_DPRINTF4("rdsv3_sendmsg", "Enter(rs: %p)", rs);

	if (msg->msg_namelen) {
		/* XXX fail non-unicast destination IPs? */
		if (msg->msg_namelen < sizeof (*usin) ||
		    usin->sin_family != AF_INET_OFFLOAD) {
			ret = -EINVAL;
			RDSV3_DPRINTF2("rdsv3_sendmsg", "returning: %d", -ret);
			goto out;
		}
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
	} else {
		/* We only care about consistency with ->connect() */
		mutex_enter(&sk->sk_lock);
		daddr = rs->rs_conn_addr;
		dport = rs->rs_conn_port;
		mutex_exit(&sk->sk_lock);
	}

	/* racing with another thread binding seems ok here */
	if (daddr == 0 || rs->rs_bound_addr == 0) {
		ret = -ENOTCONN; /* XXX not a great errno */
		RDSV3_DPRINTF2("rdsv3_sendmsg", "returning: %d", -ret);
		goto out;
	}

	if (payload_len > rdsv3_max_bcopy_size) {
		RDSV3_DPRINTF2("rdsv3_sendmsg", "Message too large: %d",
		    payload_len);
		ret = -EMSGSIZE;
		goto out;
	}

	rm = rdsv3_message_copy_from_user(uio, payload_len);
	if (IS_ERR(rm)) {
		ret = PTR_ERR(rm);
		RDSV3_DPRINTF2("rdsv3_sendmsg",
		    "rdsv3_message_copy_from_user failed %d", -ret);
		rm = NULL;
		goto out;
	}

	rm->m_daddr = daddr;

	/* Parse any control messages the user may have included. */
	ret = rdsv3_cmsg_send(rs, rm, msg, &allocated_mr);
	if (ret) {
		RDSV3_DPRINTF2("rdsv3_sendmsg",
		    "rdsv3_cmsg_send(rs: %p rm: %p msg: %p) returned: %d",
		    rs, rm, msg, ret);
		goto out;
	}

	/*
	 * rdsv3_conn_create has a spinlock that runs with IRQ off.
	 * Caching the conn in the socket helps a lot.
	 */
	mutex_enter(&rs->rs_conn_lock);
	if (rs->rs_conn && rs->rs_conn->c_faddr == daddr) {
		conn = rs->rs_conn;
	} else {
		conn = rdsv3_conn_create_outgoing(rs->rs_bound_addr,
		    daddr, rs->rs_transport, KM_NOSLEEP);
		if (IS_ERR(conn)) {
			mutex_exit(&rs->rs_conn_lock);
			ret = PTR_ERR(conn);
			RDSV3_DPRINTF2("rdsv3_sendmsg",
			    "rdsv3_conn_create_outgoing failed %d",
			    -ret);
			goto out;
		}
		rs->rs_conn = conn;
	}
	mutex_exit(&rs->rs_conn_lock);

	if ((rm->m_rdma_cookie || rm->m_rdma_op) &&
	    conn->c_trans->xmit_rdma == NULL) {
		RDSV3_DPRINTF2("rdsv3_sendmsg", "rdma_op %p conn xmit_rdma %p",
		    rm->m_rdma_op, conn->c_trans->xmit_rdma);
		ret = -EOPNOTSUPP;
		goto out;
	}

	/*
	 * If the connection is down, trigger a connect. We may
	 * have scheduled a delayed reconnect however - in this case
	 * we should not interfere.
	 */
	if (rdsv3_conn_state(conn) == RDSV3_CONN_DOWN &&
	    !test_and_set_bit(RDSV3_RECONNECT_PENDING, &conn->c_flags))
		rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_conn_w, 0);

	ret = rdsv3_cong_wait(conn->c_fcong, dport, nonblock, rs);
	if (ret) {
		mutex_enter(&rs->rs_congested_lock);
		rs->rs_seen_congestion = 1;
		cv_signal(&rs->rs_congested_cv);
		mutex_exit(&rs->rs_congested_lock);

		RDSV3_DPRINTF2("rdsv3_sendmsg",
		    "rdsv3_cong_wait (dport: %d) returned: %d", dport, ret);
		goto out;
	}

	(void) rdsv3_send_queue_rm(rs, conn, rm, rs->rs_bound_port, dport,
	    &queued);
	if (!queued) {
		/* rdsv3_stats_inc(s_send_queue_full); */
		/* XXX make sure this is reasonable */
		if (payload_len > rdsv3_sk_sndbuf(rs)) {
			ret = -EMSGSIZE;
			RDSV3_DPRINTF2("rdsv3_sendmsg",
			    "msgsize(%d) too big, returning: %d",
			    payload_len, -ret);
			goto out;
		}
		if (nonblock) {
			ret = -EAGAIN;
			RDSV3_DPRINTF3("rdsv3_sendmsg",
			    "send queue full (%d), returning: %d",
			    payload_len, -ret);
			goto out;
		}

#if 0
		ret = rdsv3_wait_sig(sk->sk_sleep,
		    (rdsv3_send_queue_rm(rs, conn, rm, rs->rs_bound_port,
		    dport, &queued)));
		if (ret == 0) {
			/* signal/timeout pending */
			RDSV3_DPRINTF2("rdsv3_sendmsg",
			    "woke due to signal: %d", ret);
			ret = -ERESTART;
			goto out;
		}
#else
		mutex_enter(&sk->sk_sleep->waitq_mutex);
		sk->sk_sleep->waitq_waiters++;
		while (!rdsv3_send_queue_rm(rs, conn, rm, rs->rs_bound_port,
		    dport, &queued)) {
			ret = cv_wait_sig(&sk->sk_sleep->waitq_cv,
			    &sk->sk_sleep->waitq_mutex);
			if (ret == 0) {
				/* signal/timeout pending */
				RDSV3_DPRINTF2("rdsv3_sendmsg",
				    "woke due to signal: %d", ret);
				ret = -EINTR;
				sk->sk_sleep->waitq_waiters--;
				mutex_exit(&sk->sk_sleep->waitq_mutex);
				goto out;
			}
		}
		sk->sk_sleep->waitq_waiters--;
		mutex_exit(&sk->sk_sleep->waitq_mutex);
#endif

		RDSV3_DPRINTF5("rdsv3_sendmsg", "sendmsg woke queued %d",
		    queued);

		ASSERT(queued);
		ret = 0;
	}

	/*
	 * By now we've committed to the send.  We reuse rdsv3_send_worker()
	 * to retry sends in the rds thread if the transport asks us to.
	 */
	rdsv3_stats_inc(s_send_queued);

	if (!test_bit(RDSV3_LL_SEND_FULL, &conn->c_flags))
		(void) rdsv3_send_worker(&conn->c_send_w.work);

	rdsv3_message_put(rm);
	RDSV3_DPRINTF4("rdsv3_sendmsg", "Return(rs: %p, len: %d)",
	    rs, payload_len);
	return (payload_len);

out:
	/*
	 * If the user included a RDMA_MAP cmsg, we allocated a MR on the fly.
	 * If the sendmsg goes through, we keep the MR. If it fails with EAGAIN
	 * or in any other way, we need to destroy the MR again
	 */
	if (allocated_mr)
		rdsv3_rdma_unuse(rs, rdsv3_rdma_cookie_key(rm->m_rdma_cookie),
		    1);

	if (rm)
		rdsv3_message_put(rm);
	return (ret);
}

/*
 * Reply to a ping packet.
 */
int
rdsv3_send_pong(struct rdsv3_connection *conn, uint16_be_t dport)
{
	struct rdsv3_message *rm;
	int ret = 0;

	RDSV3_DPRINTF4("rdsv3_send_pong", "Enter(conn: %p)", conn);

	rm = rdsv3_message_alloc(0, KM_NOSLEEP);
	if (!rm) {
		ret = -ENOMEM;
		goto out;
	}

	rm->m_daddr = conn->c_faddr;

	/*
	 * If the connection is down, trigger a connect. We may
	 * have scheduled a delayed reconnect however - in this case
	 * we should not interfere.
	 */
	if (rdsv3_conn_state(conn) == RDSV3_CONN_DOWN &&
	    !test_and_set_bit(RDSV3_RECONNECT_PENDING, &conn->c_flags))
		rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_conn_w, 0);

	ret = rdsv3_cong_wait(conn->c_fcong, dport, 1, NULL);
	if (ret)
		goto out;

	mutex_enter(&conn->c_lock);
	list_insert_tail(&conn->c_send_queue, rm);
	set_bit(RDSV3_MSG_ON_CONN, &rm->m_flags);
	rdsv3_message_addref(rm);
	rm->m_inc.i_conn = conn;

	rdsv3_message_populate_header(&rm->m_inc.i_hdr, 0, dport,
	    conn->c_next_tx_seq);
	conn->c_next_tx_seq++;
	mutex_exit(&conn->c_lock);

	rdsv3_stats_inc(s_send_queued);
	rdsv3_stats_inc(s_send_pong);

	if (!test_bit(RDSV3_LL_SEND_FULL, &conn->c_flags))
		(void) rdsv3_send_xmit(conn);

	rdsv3_message_put(rm);

	RDSV3_DPRINTF4("rdsv3_send_pong", "Return(conn: %p)", conn);
	return (0);

out:
	if (rm)
		rdsv3_message_put(rm);
	return (ret);
}

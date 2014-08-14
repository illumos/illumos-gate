/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file ib_recv.c
 * Oracle elects to have and use the contents of ib_recv.c under and governed
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
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/rds.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

static struct kmem_cache *rdsv3_ib_incoming_slab;
static atomic_t	rdsv3_ib_allocation = ATOMIC_INIT(0);

void
rdsv3_ib_recv_init_ring(struct rdsv3_ib_connection *ic)
{
	struct rdsv3_ib_recv_work *recv;
	struct rdsv3_header *hdrp;
	uint32_t i;

	RDSV3_DPRINTF4("rdsv3_ib_recv_init_ring", "ic: %p", ic);

	hdrp = ic->i_recv_hdrs;
	for (i = 0, recv = ic->i_recvs; i < ic->i_recv_ring.w_nr; i++, recv++) {
		recv->r_ibinc = NULL;
		recv->r_frag = NULL;

		/* initialize the hdr sgl permanently */
		recv->r_sge[0].ds_va = (ib_vaddr_t)(uintptr_t)hdrp++;
		recv->r_sge[0].ds_len = sizeof (struct rdsv3_header);
		recv->r_sge[0].ds_key = ic->i_mr->lkey;
	}
}

static void
rdsv3_ib_recv_clear_one(struct rdsv3_ib_connection *ic,
    struct rdsv3_ib_recv_work *recv)
{
	RDSV3_DPRINTF4("rdsv3_ib_recv_clear_one", "ic: %p, recv: %p",
	    ic, recv);

	if (recv->r_ibinc) {
		rdsv3_inc_put(&recv->r_ibinc->ii_inc);
		recv->r_ibinc = NULL;
	}

	if (recv->r_frag) {
		kmem_cache_free(ic->rds_ibdev->ib_frag_slab, recv->r_frag);
		recv->r_frag = NULL;
	}

	RDSV3_DPRINTF4("rdsv3_ib_recv_clear_one", "Return: ic: %p, recv: %p",
	    ic, recv);
}

void
rdsv3_ib_recv_clear_ring(struct rdsv3_ib_connection *ic)
{
	uint32_t i;

	RDSV3_DPRINTF4("rdsv3_ib_recv_clear_ring", "ic: %p", ic);

	for (i = 0; i < ic->i_recv_ring.w_nr; i++)
		rdsv3_ib_recv_clear_one(ic, &ic->i_recvs[i]);
}

extern int atomic_add_unless(atomic_t *, uint_t, ulong_t);

static int
rdsv3_ib_recv_refill_one(struct rdsv3_connection *conn,
    struct rdsv3_ib_recv_work *recv)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;
	ibt_mi_hdl_t mi_hdl;
	ibt_iov_attr_t iov_attr;
	ibt_iov_t iov_arr[1];

	RDSV3_DPRINTF5("rdsv3_ib_recv_refill_one", "conn: %p, recv: %p",
	    conn, recv);

	if (!recv->r_ibinc) {
		if (!atomic_add_unless(&rdsv3_ib_allocation, 1,
		    ic->i_max_recv_alloc)) {
			rdsv3_ib_stats_inc(s_ib_rx_alloc_limit);
			goto out;
		}
		recv->r_ibinc = kmem_cache_alloc(rdsv3_ib_incoming_slab,
		    KM_NOSLEEP);
		if (recv->r_ibinc == NULL) {
			atomic_dec_32(&rdsv3_ib_allocation);
			goto out;
		}
		rdsv3_inc_init(&recv->r_ibinc->ii_inc, conn, conn->c_faddr);
		recv->r_ibinc->ii_ibdev = ic->rds_ibdev;
		recv->r_ibinc->ii_pool = ic->rds_ibdev->inc_pool;
	}

	if (!recv->r_frag) {
		recv->r_frag = kmem_cache_alloc(ic->rds_ibdev->ib_frag_slab,
		    KM_NOSLEEP);
		if (!recv->r_frag)
			goto out;
	}

	/* Data sge, structure copy */
	recv->r_sge[1] = recv->r_frag->f_sge;

	RDSV3_DPRINTF5("rdsv3_ib_recv_refill_one", "Return: conn: %p, recv: %p",
	    conn, recv);

	return (0);
out:
	if (recv->r_ibinc) {
		kmem_cache_free(rdsv3_ib_incoming_slab, recv->r_ibinc);
		atomic_dec_32(&rdsv3_ib_allocation);
		recv->r_ibinc = NULL;
	}
	return (-ENOMEM);
}

/*
 * This tries to allocate and post unused work requests after making sure that
 * they have all the allocations they need to queue received fragments into
 * sockets.  The i_recv_mutex is held here so that ring_alloc and _unalloc
 * pairs don't go unmatched.
 *
 * -1 is returned if posting fails due to temporary resource exhaustion.
 */
int
rdsv3_ib_recv_refill(struct rdsv3_connection *conn, int prefill)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;
	struct rdsv3_ib_recv_work *recv;
	unsigned int posted = 0;
	int ret = 0, avail;
	uint32_t pos, i;

	RDSV3_DPRINTF4("rdsv3_ib_recv_refill", "conn: %p, prefill: %d",
	    conn, prefill);

	if (prefill || rdsv3_conn_up(conn)) {
		uint_t w_nr = ic->i_recv_ring.w_nr;

		avail = rdsv3_ib_ring_alloc(&ic->i_recv_ring, w_nr, &pos);
		if ((avail <= 0) || (pos >= w_nr)) {
			RDSV3_DPRINTF2("rdsv3_ib_recv_refill",
			    "Argh - ring alloc returned pos=%u, avail: %d",
			    pos, avail);
			return (-EINVAL);
		}

		/* populate the WRs */
		for (i = 0; i < avail; i++) {
			recv = &ic->i_recvs[pos];
			ret = rdsv3_ib_recv_refill_one(conn, recv);
			if (ret) {
				rdsv3_ib_ring_unalloc(&ic->i_recv_ring,
				    avail - i);
				break;
			}
			ic->i_recv_wrs[i].wr_id = (ibt_wrid_t)pos;
			ic->i_recv_wrs[i].wr_nds = RDSV3_IB_RECV_SGE;
			ic->i_recv_wrs[i].wr_sgl = &recv->r_sge[0];

			pos = (pos + 1) % w_nr;
		}

		if (i) {
			/* post the WRs at one shot */
			ret = ibt_post_recv(ib_get_ibt_channel_hdl(ic->i_cm_id),
			    &ic->i_recv_wrs[0], i, &posted);
			RDSV3_DPRINTF3("rdsv3_ib_recv_refill",
			    "attempted: %d posted: %d WRs ret %d",
			    i, posted, ret);
			if (ret) {
				RDSV3_DPRINTF2("rdsv3_ib_recv_refill",
				    "disconnecting and reconnecting\n",
				    NIPQUAD(conn->c_faddr), ret);
				rdsv3_ib_ring_unalloc(&ic->i_recv_ring,
				    i - posted);
				rdsv3_conn_drop(conn);
			}
		}
	}

	/* We're doing flow control - update the window. */
	if (ic->i_flowctl && posted)
		rdsv3_ib_advertise_credits(conn, posted);

	RDSV3_DPRINTF4("rdsv3_ib_recv_refill", "Return: conn: %p, posted: %d",
	    conn, posted);
	return (ret);
}

/*
 * delayed freed incoming's
 */
struct rdsv3_inc_pool {
	list_t			f_list;	/* list of freed incoming */
	kmutex_t		f_lock; /* lock of fmr pool */
	int32_t			f_listcnt;
};

void
rdsv3_ib_destroy_inc_pool(struct rdsv3_ib_device *rds_ibdev)
{
	struct rdsv3_inc_pool *pool = rds_ibdev->inc_pool;

	if (pool) {
		list_destroy(&pool->f_list);
		kmem_free((void *) pool, sizeof (*pool));
	}
}

int
rdsv3_ib_create_inc_pool(struct rdsv3_ib_device *rds_ibdev)
{
	struct rdsv3_inc_pool *pool;

	pool = (struct rdsv3_inc_pool *)kmem_zalloc(sizeof (*pool), KM_NOSLEEP);
	if (pool == NULL) {
		return (-ENOMEM);
	}
	list_create(&pool->f_list, sizeof (struct rdsv3_ib_incoming),
	    offsetof(struct rdsv3_ib_incoming, ii_obj));
	mutex_init(&pool->f_lock, NULL, MUTEX_DRIVER, NULL);
	rds_ibdev->inc_pool = pool;
	return (0);
}

static void
rdsv3_ib_inc_drop(struct rdsv3_ib_incoming *ibinc)
{
	struct rdsv3_page_frag *frag;
	struct rdsv3_page_frag *pos;

	RDSV3_FOR_EACH_LIST_NODE_SAFE(frag, pos, &ibinc->ii_frags, f_item) {
		list_remove_node(&frag->f_item);
		kmem_cache_free(ibinc->ii_ibdev->ib_frag_slab, frag);
	}

	ASSERT(list_is_empty(&ibinc->ii_frags));
	kmem_cache_free(rdsv3_ib_incoming_slab, ibinc);
	atomic_dec_uint(&rdsv3_ib_allocation);
}

void
rdsv3_ib_drain_inclist(void *data)
{
	struct rdsv3_inc_pool *pool = (struct rdsv3_inc_pool *)data;
	struct rdsv3_ib_incoming *ibinc;
	list_t *listp = &pool->f_list;
	kmutex_t *lockp = &pool->f_lock;
	int i = 0;

	for (;;) {
		mutex_enter(lockp);
		ibinc = (struct rdsv3_ib_incoming *)list_remove_head(listp);
		if (ibinc)
			pool->f_listcnt--;
		mutex_exit(lockp);
		if (!ibinc)
			break;
		i++;
		rdsv3_ib_inc_drop(ibinc);
	}
}

void
rdsv3_ib_inc_free(struct rdsv3_incoming *inc)
{
	struct rdsv3_ib_incoming *ibinc;
	rdsv3_af_thr_t *af_thr;

	RDSV3_DPRINTF4("rdsv3_ib_inc_free", "inc: %p", inc);

	ibinc = container_of(inc, struct rdsv3_ib_incoming, ii_inc);
	/* save af_thr in a local as ib_inc might be freed at mutex_exit */
	af_thr = ibinc->ii_ibdev->inc_soft_cq;

	mutex_enter(&ibinc->ii_pool->f_lock);
	list_insert_tail(&ibinc->ii_pool->f_list, ibinc);
	ibinc->ii_pool->f_listcnt++;
	mutex_exit(&ibinc->ii_pool->f_lock);

	rdsv3_af_thr_fire(af_thr);
}

int
rdsv3_ib_inc_copy_to_user(struct rdsv3_incoming *inc, uio_t *uiop,
    size_t size)
{
	struct rdsv3_ib_incoming *ibinc;
	struct rdsv3_page_frag *frag;
	unsigned long to_copy;
	unsigned long frag_off = 0;
	int copied = 0;
	int ret;
	uint32_t len;

	ibinc = container_of(inc, struct rdsv3_ib_incoming, ii_inc);
	frag = list_head(&ibinc->ii_frags);
	len = ntohl(inc->i_hdr.h_len);

	RDSV3_DPRINTF4("rdsv3_ib_inc_copy_to_user", "inc: %p, size: %d len: %d",
	    inc, size, len);

	while (copied < size && copied < len) {
		if (frag_off == RDSV3_FRAG_SIZE) {
			frag = list_next(&ibinc->ii_frags, frag);
			frag_off = 0;
		}

		to_copy = min(len - copied, RDSV3_FRAG_SIZE - frag_off);
		to_copy = min(size - copied, to_copy);

		RDSV3_DPRINTF5("rdsv3_ib_inc_copy_to_user",
		    "%lu bytes to user %p from frag [%p, %u] + %lu",
		    to_copy, uiop,
		    frag->f_page, frag->f_offset, frag_off);

		ret = uiomove((caddr_t)(frag->f_page +
		    frag->f_offset + frag_off),
		    to_copy, UIO_READ, uiop);
		if (ret) {
			RDSV3_DPRINTF2("rdsv3_ib_inc_copy_to_user",
			    "uiomove (%d) returned: %d", to_copy, ret);
			break;
		}

		frag_off += to_copy;
		copied += to_copy;
	}

	RDSV3_DPRINTF4("rdsv3_ib_inc_copy_to_user",
	    "Return: inc: %p, copied: %d", inc, copied);

	return (copied);
}

/* ic starts out kmem_zalloc()ed */
void
rdsv3_ib_recv_init_ack(struct rdsv3_ib_connection *ic)
{
	ibt_send_wr_t *wr = &ic->i_ack_wr;
	ibt_wr_ds_t *sge = &ic->i_ack_sge;

	RDSV3_DPRINTF4("rdsv3_ib_recv_init_ack", "ic: %p", ic);

	sge->ds_va = ic->i_ack_dma;
	sge->ds_len = sizeof (struct rdsv3_header);
	sge->ds_key = ic->i_mr->lkey;

	wr->wr_sgl = sge;
	wr->wr_nds = 1;
	wr->wr_opcode = IBT_WRC_SEND;
	wr->wr_id = RDSV3_IB_ACK_WR_ID;
	wr->wr_flags = IBT_WR_SEND_SIGNAL | IBT_WR_SEND_SOLICIT;
}

/*
 * You'd think that with reliable IB connections you wouldn't need to ack
 * messages that have been received.  The problem is that IB hardware generates
 * an ack message before it has DMAed the message into memory.  This creates a
 * potential message loss if the HCA is disabled for any reason between when it
 * sends the ack and before the message is DMAed and processed.  This is only a
 * potential issue if another HCA is available for fail-over.
 *
 * When the remote host receives our ack they'll free the sent message from
 * their send queue.  To decrease the latency of this we always send an ack
 * immediately after we've received messages.
 *
 * For simplicity, we only have one ack in flight at a time.  This puts
 * pressure on senders to have deep enough send queues to absorb the latency of
 * a single ack frame being in flight.  This might not be good enough.
 *
 * This is implemented by have a long-lived send_wr and sge which point to a
 * statically allocated ack frame.  This ack wr does not fall under the ring
 * accounting that the tx and rx wrs do.  The QP attribute specifically makes
 * room for it beyond the ring size.  Send completion notices its special
 * wr_id and avoids working with the ring in that case.
 */
void
rdsv3_ib_set_ack(struct rdsv3_ib_connection *ic, uint64_t seq,
    int ack_required)
{
	RDSV3_DPRINTF4("rdsv3_ib_set_ack", "ic: %p, seq: %lld ack: %d",
	    ic, seq, ack_required);

	mutex_enter(&ic->i_ack_lock);
	ic->i_ack_next = seq;
	if (ack_required)
		set_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
	mutex_exit(&ic->i_ack_lock);
}

static uint64_t
rdsv3_ib_get_ack(struct rdsv3_ib_connection *ic)
{
	uint64_t seq;

	RDSV3_DPRINTF4("rdsv3_ib_get_ack", "ic: %p", ic);

	clear_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);

	mutex_enter(&ic->i_ack_lock);
	seq = ic->i_ack_next;
	mutex_exit(&ic->i_ack_lock);

	return (seq);
}

static void
rdsv3_ib_send_ack(struct rdsv3_ib_connection *ic, unsigned int adv_credits)
{
	struct rdsv3_header *hdr = ic->i_ack;
	uint64_t seq;
	int ret;

	RDSV3_DPRINTF4("rdsv3_ib_send_ack", "ic: %p adv_credits: %d",
	    ic, adv_credits);

	seq = rdsv3_ib_get_ack(ic);

	RDSV3_DPRINTF4("rdsv3_ib_send_ack", "send_ack: ic %p ack %llu",
	    ic, (unsigned long long) seq);
	rdsv3_message_populate_header(hdr, 0, 0, 0);
	hdr->h_ack = htonll(seq);
	hdr->h_credit = adv_credits;
	rdsv3_message_make_checksum(hdr);
	ic->i_ack_queued = jiffies;

	ret = ibt_post_send(RDSV3_QP2CHANHDL(ic->i_cm_id->qp), &ic->i_ack_wr, 1,
	    NULL);
	if (ret) {
		/*
		 * Failed to send. Release the WR, and
		 * force another ACK.
		 */
		clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
		set_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
		rdsv3_ib_stats_inc(s_ib_ack_send_failure);
		RDSV3_DPRINTF2("rdsv3_ib_send_ack", "sending ack failed\n");
		rdsv3_conn_drop(ic->conn);
	} else {
		rdsv3_ib_stats_inc(s_ib_ack_sent);
	}
	RDSV3_DPRINTF4("rdsv3_ib_send_ack", "Return: ic: %p adv_credits: %d",
	    ic, adv_credits);
}

/*
 * There are 3 ways of getting acknowledgements to the peer:
 *  1.	We call rdsv3_ib_attempt_ack from the recv completion handler
 *	to send an ACK-only frame.
 *	However, there can be only one such frame in the send queue
 *	at any time, so we may have to postpone it.
 *  2.	When another (data) packet is transmitted while there's
 *	an ACK in the queue, we piggyback the ACK sequence number
 *	on the data packet.
 *  3.	If the ACK WR is done sending, we get called from the
 *	send queue completion handler, and check whether there's
 *	another ACK pending (postponed because the WR was on the
 *	queue). If so, we transmit it.
 *
 * We maintain 2 variables:
 *  -	i_ack_flags, which keeps track of whether the ACK WR
 *	is currently in the send queue or not (IB_ACK_IN_FLIGHT)
 *  -	i_ack_next, which is the last sequence number we received
 *
 * Potentially, send queue and receive queue handlers can run concurrently.
 * It would be nice to not have to use a spinlock to synchronize things,
 * but the one problem that rules this out is that 64bit updates are
 * not atomic on all platforms. Things would be a lot simpler if
 * we had atomic64 or maybe cmpxchg64 everywhere.
 *
 * Reconnecting complicates this picture just slightly. When we
 * reconnect, we may be seeing duplicate packets. The peer
 * is retransmitting them, because it hasn't seen an ACK for
 * them. It is important that we ACK these.
 *
 * ACK mitigation adds a header flag "ACK_REQUIRED"; any packet with
 * this flag set *MUST* be acknowledged immediately.
 */

/*
 * When we get here, we're called from the recv queue handler.
 * Check whether we ought to transmit an ACK.
 */
void
rdsv3_ib_attempt_ack(struct rdsv3_ib_connection *ic)
{
	unsigned int adv_credits;

	RDSV3_DPRINTF4("rdsv3_ib_attempt_ack", "ic: %p", ic);

	if (!test_bit(IB_ACK_REQUESTED, &ic->i_ack_flags))
		return;

	if (test_and_set_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags)) {
		rdsv3_ib_stats_inc(s_ib_ack_send_delayed);
		return;
	}

	/* Can we get a send credit? */
	if (!rdsv3_ib_send_grab_credits(ic, 1, &adv_credits, 0)) {
		rdsv3_ib_stats_inc(s_ib_tx_throttle);
		clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
		return;
	}

	clear_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
	rdsv3_ib_send_ack(ic, adv_credits);

	RDSV3_DPRINTF4("rdsv3_ib_attempt_ack", "Return: ic: %p", ic);
}

/*
 * We get here from the send completion handler, when the
 * adapter tells us the ACK frame was sent.
 */
void
rdsv3_ib_ack_send_complete(struct rdsv3_ib_connection *ic)
{
	RDSV3_DPRINTF4("rdsv3_ib_ack_send_complete", "ic: %p", ic);
	clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
	rdsv3_ib_attempt_ack(ic);
}

/*
 * This is called by the regular xmit code when it wants to piggyback
 * an ACK on an outgoing frame.
 */
uint64_t
rdsv3_ib_piggyb_ack(struct rdsv3_ib_connection *ic)
{
	RDSV3_DPRINTF4("rdsv3_ib_piggyb_ack", "ic: %p", ic);
	if (test_and_clear_bit(IB_ACK_REQUESTED, &ic->i_ack_flags)) {
		rdsv3_ib_stats_inc(s_ib_ack_send_piggybacked);
	}
	return (rdsv3_ib_get_ack(ic));
}

/*
 * It's kind of lame that we're copying from the posted receive pages into
 * long-lived bitmaps.  We could have posted the bitmaps and rdma written into
 * them.  But receiving new congestion bitmaps should be a *rare* event, so
 * hopefully we won't need to invest that complexity in making it more
 * efficient.  By copying we can share a simpler core with TCP which has to
 * copy.
 */
static void
rdsv3_ib_cong_recv(struct rdsv3_connection *conn,
    struct rdsv3_ib_incoming *ibinc)
{
	struct rdsv3_cong_map *map;
	unsigned int map_off;
	unsigned int map_page;
	struct rdsv3_page_frag *frag;
	unsigned long frag_off;
	unsigned long to_copy;
	unsigned long copied;
	uint64_t uncongested = 0;
	caddr_t addr;

	RDSV3_DPRINTF4("rdsv3_ib_cong_recv", "conn: %p, ibinc: %p",
	    conn, ibinc);

	/* catch completely corrupt packets */
	if (ntohl(ibinc->ii_inc.i_hdr.h_len) != RDSV3_CONG_MAP_BYTES)
		return;

	map = conn->c_fcong;
	map_page = 0;
	map_off = 0;

	frag = list_head(&ibinc->ii_frags);
	frag_off = 0;

	copied = 0;

	while (copied < RDSV3_CONG_MAP_BYTES) {
		uint64_t *src, *dst;
		unsigned int k;

		to_copy = min(RDSV3_FRAG_SIZE - frag_off, PAGE_SIZE - map_off);
		ASSERT(!(to_copy & 7)); /* Must be 64bit aligned. */

		addr = frag->f_page + frag->f_offset;

		src = (uint64_t *)(addr + frag_off);
		dst = (uint64_t *)(map->m_page_addrs[map_page] + map_off);
		RDSV3_DPRINTF4("rdsv3_ib_cong_recv",
		    "src: %p dst: %p copied: %d", src, dst, copied);
		for (k = 0; k < to_copy; k += 8) {
			/*
			 * Record ports that became uncongested, ie
			 * bits that changed from 0 to 1.
			 */
			uncongested |= ~(*src) & *dst;
			*dst++ = *src++;
		}

		copied += to_copy;
		RDSV3_DPRINTF4("rdsv3_ib_cong_recv",
		    "src: %p dst: %p copied: %d", src, dst, copied);

		map_off += to_copy;
		if (map_off == PAGE_SIZE) {
			map_off = 0;
			map_page++;
		}

		frag_off += to_copy;
		if (frag_off == RDSV3_FRAG_SIZE) {
			frag = list_next(&ibinc->ii_frags, frag);
			frag_off = 0;
		}
	}

#if 0
XXX
	/* the congestion map is in little endian order */
	uncongested = le64_to_cpu(uncongested);
#endif

	rdsv3_cong_map_updated(map, uncongested);

	RDSV3_DPRINTF4("rdsv3_ib_cong_recv", "Return: conn: %p, ibinc: %p",
	    conn, ibinc);
}

static void
rdsv3_ib_process_recv(struct rdsv3_connection *conn,
    struct rdsv3_ib_recv_work *recv, uint32_t data_len,
    struct rdsv3_ib_ack_state *state)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;
	struct rdsv3_ib_incoming *ibinc = ic->i_ibinc;
	struct rdsv3_header *ihdr, *hdr;

	/* XXX shut down the connection if port 0,0 are seen? */

	RDSV3_DPRINTF5("rdsv3_ib_process_recv",
	    "ic %p ibinc %p recv %p byte len %u", ic, ibinc, recv, data_len);

	if (data_len < sizeof (struct rdsv3_header)) {
		RDSV3_DPRINTF2("rdsv3_ib_process_recv",
		    "incoming message from %u.%u.%u.%u didn't include a "
		    "header, disconnecting and reconnecting",
		    NIPQUAD(conn->c_faddr));
		rdsv3_conn_drop(conn);
		return;
	}
	data_len -= sizeof (struct rdsv3_header);

	ihdr = &ic->i_recv_hdrs[recv - ic->i_recvs];

	/* Validate the checksum. */
	if (!rdsv3_message_verify_checksum(ihdr)) {
		RDSV3_DPRINTF2("rdsv3_ib_process_recv", "incoming message "
		    "from %u.%u.%u.%u has corrupted header - "
		    "forcing a reconnect",
		    NIPQUAD(conn->c_faddr));
		rdsv3_conn_drop(conn);
		rdsv3_stats_inc(s_recv_drop_bad_checksum);
		return;
	}

	/* Process the ACK sequence which comes with every packet */
	state->ack_recv = ntohll(ihdr->h_ack);
	state->ack_recv_valid = 1;

	/* Process the credits update if there was one */
	if (ihdr->h_credit)
		rdsv3_ib_send_add_credits(conn, ihdr->h_credit);

	if (ihdr->h_sport == 0 && ihdr->h_dport == 0 && data_len == 0) {
		/*
		 * This is an ACK-only packet. The fact that it gets
		 * special treatment here is that historically, ACKs
		 * were rather special beasts.
		 */
		rdsv3_ib_stats_inc(s_ib_ack_received);
		return;
	}

	/*
	 * If we don't already have an inc on the connection then this
	 * fragment has a header and starts a message.. copy its header
	 * into the inc and save the inc so we can hang upcoming fragments
	 * off its list.
	 */
	if (!ibinc) {
		ibinc = recv->r_ibinc;
		recv->r_ibinc = NULL;
		ic->i_ibinc = ibinc;

		hdr = &ibinc->ii_inc.i_hdr;
		(void) memcpy(hdr, ihdr, sizeof (*hdr));
		ic->i_recv_data_rem = ntohl(hdr->h_len);

		RDSV3_DPRINTF5("rdsv3_ib_process_recv",
		    "ic %p ibinc %p rem %u flag 0x%x", ic, ibinc,
		    ic->i_recv_data_rem, hdr->h_flags);
	} else {
		hdr = &ibinc->ii_inc.i_hdr;
		/*
		 * We can't just use memcmp here; fragments of a
		 * single message may carry different ACKs
		 */
		if (hdr->h_sequence != ihdr->h_sequence ||
		    hdr->h_len != ihdr->h_len ||
		    hdr->h_sport != ihdr->h_sport ||
		    hdr->h_dport != ihdr->h_dport) {
			RDSV3_DPRINTF2("rdsv3_ib_process_recv",
			    "fragment header mismatch; forcing reconnect");
			rdsv3_conn_drop(conn);
			return;
		}
	}

	list_insert_tail(&ibinc->ii_frags, recv->r_frag);
	recv->r_frag = NULL;

	if (ic->i_recv_data_rem > RDSV3_FRAG_SIZE)
		ic->i_recv_data_rem -= RDSV3_FRAG_SIZE;
	else {
		ic->i_recv_data_rem = 0;
		ic->i_ibinc = NULL;

		if (ibinc->ii_inc.i_hdr.h_flags == RDSV3_FLAG_CONG_BITMAP)
			rdsv3_ib_cong_recv(conn, ibinc);
		else {
			rdsv3_recv_incoming(conn, conn->c_faddr, conn->c_laddr,
			    &ibinc->ii_inc, KM_NOSLEEP);
			state->ack_next = ntohll(hdr->h_sequence);
			state->ack_next_valid = 1;
		}

		/*
		 * Evaluate the ACK_REQUIRED flag *after* we received
		 * the complete frame, and after bumping the next_rx
		 * sequence.
		 */
		if (hdr->h_flags & RDSV3_FLAG_ACK_REQUIRED) {
			rdsv3_stats_inc(s_recv_ack_required);
			state->ack_required = 1;
		}

		rdsv3_inc_put(&ibinc->ii_inc);
	}

	RDSV3_DPRINTF4("rdsv3_ib_process_recv",
	    "Return: conn: %p recv: %p len: %d state: %p",
	    conn, recv, data_len, state);
}

void
rdsv3_ib_recv_cqe_handler(struct rdsv3_ib_connection *ic, ibt_wc_t *wc,
    struct rdsv3_ib_ack_state *state)
{
	struct rdsv3_connection *conn = ic->conn;
	struct rdsv3_ib_recv_work *recv;
	struct rdsv3_ib_work_ring *recv_ringp = &ic->i_recv_ring;

	RDSV3_DPRINTF4("rdsv3_ib_recv_cqe_handler",
	    "rwc wc_id 0x%llx status %u byte_len %u imm_data %u\n",
	    (unsigned long long)wc->wc_id, wc->wc_status,
	    wc->wc_bytes_xfer, ntohl(wc->wc_immed_data));

	rdsv3_ib_stats_inc(s_ib_rx_cq_event);

	recv = &ic->i_recvs[rdsv3_ib_ring_oldest(recv_ringp)];

	/*
	 * Also process recvs in connecting state because it is possible
	 * to get a recv completion _before_ the rdmacm ESTABLISHED
	 * event is processed.
	 */
	if (rdsv3_conn_up(conn) || rdsv3_conn_connecting(conn)) {
		/* We expect errors as the qp is drained during shutdown */
		if (wc->wc_status == IBT_WC_SUCCESS) {
			rdsv3_ib_process_recv(conn, recv,
			    wc->wc_bytes_xfer, state);
		} else {
			RDSV3_DPRINTF2("rdsv3_ib_recv_cqe_handler",
			    "recv completion on "
			    "%u.%u.%u.%u had status %u, "
			    "disconnecting and reconnecting\n",
			    NIPQUAD(conn->c_faddr),
			    wc->wc_status);
			rdsv3_conn_drop(conn);
		}
	}

	rdsv3_ib_ring_free(recv_ringp, 1);

	/*
	 * If we ever end up with a really empty receive ring, we're
	 * in deep trouble, as the sender will definitely see RNR
	 * timeouts.
	 */
	if (rdsv3_ib_ring_empty(recv_ringp))
		rdsv3_ib_stats_inc(s_ib_rx_ring_empty);

	if (rdsv3_ib_ring_low(recv_ringp)) {
		rdsv3_af_thr_fire(ic->i_refill_rq);
	}
}

int
rdsv3_ib_recv(struct rdsv3_connection *conn)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;
	int ret = 0;

	RDSV3_DPRINTF4("rdsv3_ib_recv", "conn %p\n", conn);

	if (rdsv3_conn_up(conn))
		rdsv3_ib_attempt_ack(ic);

	RDSV3_DPRINTF4("rdsv3_ib_recv", "Return: conn: %p", conn);

	return (ret);
}

extern int rdsv3_ib_inc_constructor(void *buf, void *arg, int kmflags);
extern void rdsv3_ib_inc_destructor(void *buf, void *arg);

int
rdsv3_ib_recv_init(void)
{
	RDSV3_DPRINTF4("rdsv3_ib_recv_init", "Enter");

	rdsv3_ib_incoming_slab = kmem_cache_create("rdsv3_ib_incoming",
	    sizeof (struct rdsv3_ib_incoming), 0, rdsv3_ib_inc_constructor,
	    rdsv3_ib_inc_destructor, NULL, NULL, NULL, 0);
	if (!rdsv3_ib_incoming_slab) {
		RDSV3_DPRINTF2("rdsv3_ib_recv_init", "kmem_cache_create "
		    "failed");
		return (-ENOMEM);
	}

	RDSV3_DPRINTF4("rdsv3_ib_recv_init", "Return");
	return (0);
}

void
rdsv3_ib_recv_exit(void)
{
	RDSV3_DPRINTF4("rdsv3_ib_recv_exit", "Enter");
	kmem_cache_destroy(rdsv3_ib_incoming_slab);
	RDSV3_DPRINTF4("rdsv3_ib_recv_exit", "Return");
}

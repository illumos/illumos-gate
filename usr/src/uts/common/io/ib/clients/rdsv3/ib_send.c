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

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

static void
rdsv3_ib_send_rdma_complete(struct rdsv3_message *rm,
    int wc_status)
{
	int notify_status;

	RDSV3_DPRINTF4("rdsv3_ib_send_rdma_complete", "rm: %p, wc_status: %d",
	    rm, wc_status);

	switch (wc_status) {
	case IBT_WC_WR_FLUSHED_ERR:
		return;

	case IBT_WC_SUCCESS:
		notify_status = RDSV3_RDMA_SUCCESS;
		break;

	case IBT_WC_REMOTE_ACCESS_ERR:
		notify_status = RDSV3_RDMA_REMOTE_ERROR;
		break;

	default:
		notify_status = RDSV3_RDMA_OTHER_ERROR;
		break;
	}
	rdsv3_rdma_send_complete(rm, notify_status);

	RDSV3_DPRINTF4("rdsv3_ib_send_rdma_complete", "rm: %p, wc_status: %d",
	    rm, wc_status);
}

static void rdsv3_ib_dma_unmap_sg_rdma(struct ib_device *dev,
    uint_t num, struct rdsv3_rdma_sg scat[]);

void
rdsv3_ib_send_unmap_rdma(struct rdsv3_ib_connection *ic,
    struct rdsv3_rdma_op *op)
{
	RDSV3_DPRINTF4("rdsv3_ib_send_unmap_rdma", "ic: %p, op: %p", ic, op);
	if (op->r_mapped) {
		op->r_mapped = 0;
		if (ic->i_cm_id) {
			rdsv3_ib_dma_unmap_sg_rdma(ic->i_cm_id->device,
			    op->r_nents, op->r_rdma_sg);
		} else {
			rdsv3_ib_dma_unmap_sg_rdma((struct ib_device *)NULL,
			    op->r_nents, op->r_rdma_sg);
		}
	}
}

static void
rdsv3_ib_send_unmap_rm(struct rdsv3_ib_connection *ic,
    struct rdsv3_ib_send_work *send,
    int wc_status)
{
	struct rdsv3_message *rm = send->s_rm;

	RDSV3_DPRINTF4("rdsv3_ib_send_unmap_rm", "ic %p send %p rm %p\n",
	    ic, send, rm);

	rdsv3_ib_dma_unmap_sg(ic->i_cm_id->device,
	    rm->m_sg, rm->m_nents);

	if (rm->m_rdma_op != NULL) {
		rdsv3_ib_send_unmap_rdma(ic, rm->m_rdma_op);

		/*
		 * If the user asked for a completion notification on this
		 * message, we can implement three different semantics:
		 *  1.	Notify when we received the ACK on the RDS message
		 *	that was queued with the RDMA. This provides reliable
		 *	notification of RDMA status at the expense of a one-way
		 *	packet delay.
		 *  2.	Notify when the IB stack gives us the completion
		 *	event for the RDMA operation.
		 *  3.	Notify when the IB stack gives us the completion
		 *	event for the accompanying RDS messages.
		 * Here, we implement approach #3. To implement approach #2,
		 * call rdsv3_rdma_send_complete from the cq_handler.
		 * To implement #1,
		 * don't call rdsv3_rdma_send_complete at all, and fall back to
		 * the notify
		 * handling in the ACK processing code.
		 *
		 * Note: There's no need to explicitly sync any RDMA buffers
		 * using
		 * ib_dma_sync_sg_for_cpu - the completion for the RDMA
		 * operation itself unmapped the RDMA buffers, which takes care
		 * of synching.
		 */
		rdsv3_ib_send_rdma_complete(rm, wc_status);

		if (rm->m_rdma_op->r_write)
			rdsv3_stats_add(s_send_rdma_bytes,
			    rm->m_rdma_op->r_bytes);
		else
			rdsv3_stats_add(s_recv_rdma_bytes,
			    rm->m_rdma_op->r_bytes);
	}

	/*
	 * If anyone waited for this message to get flushed out, wake
	 * them up now
	 */
	rdsv3_message_unmapped(rm);

	rdsv3_message_put(rm);
	send->s_rm = NULL;
}

void
rdsv3_ib_send_init_ring(struct rdsv3_ib_connection *ic)
{
	struct rdsv3_ib_send_work *send;
	uint32_t i;

	RDSV3_DPRINTF4("rdsv3_ib_send_init_ring", "ic: %p", ic);

	for (i = 0, send = ic->i_sends; i < ic->i_send_ring.w_nr; i++, send++) {
		send->s_rm = NULL;
		send->s_op = NULL;
	}
}

void
rdsv3_ib_send_clear_ring(struct rdsv3_ib_connection *ic)
{
	struct rdsv3_ib_send_work *send;
	uint32_t i;

	RDSV3_DPRINTF4("rdsv3_ib_send_clear_ring", "ic: %p", ic);

	for (i = 0, send = ic->i_sends; i < ic->i_send_ring.w_nr; i++, send++) {
		if (send->s_opcode == 0xdd)
			continue;
		if (send->s_rm)
			rdsv3_ib_send_unmap_rm(ic, send, IBT_WC_WR_FLUSHED_ERR);
		if (send->s_op)
			rdsv3_ib_send_unmap_rdma(ic, send->s_op);
	}

	RDSV3_DPRINTF4("rdsv3_ib_send_clear_ring", "Return: ic: %p", ic);
}

/*
 * The _oldest/_free ring operations here race cleanly with the alloc/unalloc
 * operations performed in the send path.  As the sender allocs and potentially
 * unallocs the next free entry in the ring it doesn't alter which is
 * the next to be freed, which is what this is concerned with.
 */
void
rdsv3_ib_send_cq_comp_handler(struct ib_cq *cq, void *context)
{
	struct rdsv3_connection *conn = context;
	struct rdsv3_ib_connection *ic = conn->c_transport_data;
	ibt_wc_t wc;
	struct rdsv3_ib_send_work *send;
	uint32_t completed, polled;
	uint32_t oldest;
	uint32_t i = 0;
	int ret;

	RDSV3_DPRINTF4("rdsv3_ib_send_cq_comp_handler", "conn: %p cq: %p",
	    conn, cq);

	rdsv3_ib_stats_inc(s_ib_tx_cq_call);
	ret = ibt_enable_cq_notify(RDSV3_CQ2CQHDL(cq), IBT_NEXT_COMPLETION);
	if (ret)
		RDSV3_DPRINTF2("rdsv3_ib_send_cq_comp_handler",
		    "ib_req_notify_cq send failed: %d", ret);

	while (ibt_poll_cq(RDSV3_CQ2CQHDL(cq), &wc, 1, &polled) ==
	    IBT_SUCCESS) {
		RDSV3_DPRINTF5("rdsv3_ib_send_cq_comp_handler",
		    "swc wr_id 0x%llx status %u byte_len %u imm_data %u\n",
		    (unsigned long long)wc.wc_id, wc.wc_status,
		    wc.wc_bytes_xfer, ntohl(wc.wc_immed_data));
		rdsv3_ib_stats_inc(s_ib_tx_cq_event);

		if (wc.wc_id == RDSV3_IB_ACK_WR_ID) {
			if (ic->i_ack_queued + HZ/2 < jiffies)
				rdsv3_ib_stats_inc(s_ib_tx_stalled);
			rdsv3_ib_ack_send_complete(ic);
			continue;
		}

		oldest = rdsv3_ib_ring_oldest(&ic->i_send_ring);

		completed = rdsv3_ib_ring_completed(&ic->i_send_ring,
		    wc.wc_id, oldest);

		for (i = 0; i < completed; i++) {
			send = &ic->i_sends[oldest];

			/*
			 * In the error case, wc.opcode sometimes contains
			 * garbage
			 */
			switch (send->s_opcode) {
			case IBT_WRC_SEND:
				if (send->s_rm)
					rdsv3_ib_send_unmap_rm(ic, send,
					    wc.wc_status);
				break;
			case IBT_WRC_RDMAW:
			case IBT_WRC_RDMAR:
				/*
				 * Nothing to be done - the SG list will
				 * be unmapped
				 * when the SEND completes.
				 */
				break;
			default:
#ifndef __lock_lint
				RDSV3_DPRINTF2("rdsv3_ib_send_cq_comp_handler",
				    "RDS/IB: %s: unexpected opcode "
				    "0x%x in WR!",
				    __func__, send->s_opcode);
#endif
				break;
			}

			send->s_opcode = 0xdd;
			if (send->s_queued + HZ/2 < jiffies)
				rdsv3_ib_stats_inc(s_ib_tx_stalled);

			/*
			 * If a RDMA operation produced an error, signal
			 * this right
			 * away. If we don't, the subsequent SEND that goes
			 * with this
			 * RDMA will be canceled with ERR_WFLUSH, and the
			 * application
			 * never learn that the RDMA failed.
			 */
			if (wc.wc_status ==
			    IBT_WC_REMOTE_ACCESS_ERR && send->s_op) {
				struct rdsv3_message *rm;

				rm = rdsv3_send_get_message(conn, send->s_op);
				if (rm) {
					if (rm->m_rdma_op != NULL)
						rdsv3_ib_send_unmap_rdma(ic,
						    rm->m_rdma_op);
					rdsv3_ib_send_rdma_complete(rm,
					    wc.wc_status);
					rdsv3_message_put(rm);
				}
			}

			oldest = (oldest + 1) % ic->i_send_ring.w_nr;
		}

		RDSV3_DPRINTF4("rdsv3_ib_send_cq_comp_handler", "compl: %d",
		    completed);
		rdsv3_ib_ring_free(&ic->i_send_ring, completed);

		if (test_and_clear_bit(RDSV3_LL_SEND_FULL, &conn->c_flags) ||
		    test_bit(0, &conn->c_map_queued))
			rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_send_w, 0);

		/* We expect errors as the qp is drained during shutdown */
		if (wc.wc_status != IBT_WC_SUCCESS && rdsv3_conn_up(conn)) {
			RDSV3_DPRINTF2("rdsv3_ib_send_cq_comp_handler",
			    "send completion on %u.%u.%u.%u "
			    "had status %u, disconnecting and reconnecting\n",
			    NIPQUAD(conn->c_faddr), wc.wc_status);
			rdsv3_conn_drop(conn);
		}
	}

	RDSV3_DPRINTF4("rdsv3_ib_send_cq_comp_handler",
	    "Return: conn: %p, cq: %p", conn, cq);
}

/*
 * This is the main function for allocating credits when sending
 * messages.
 *
 * Conceptually, we have two counters:
 *  -	send credits: this tells us how many WRs we're allowed
 *	to submit without overruning the reciever's queue. For
 *	each SEND WR we post, we decrement this by one.
 *
 *  -	posted credits: this tells us how many WRs we recently
 *	posted to the receive queue. This value is transferred
 *	to the peer as a "credit update" in a RDS header field.
 *	Every time we transmit credits to the peer, we subtract
 *	the amount of transferred credits from this counter.
 *
 * It is essential that we avoid situations where both sides have
 * exhausted their send credits, and are unable to send new credits
 * to the peer. We achieve this by requiring that we send at least
 * one credit update to the peer before exhausting our credits.
 * When new credits arrive, we subtract one credit that is withheld
 * until we've posted new buffers and are ready to transmit these
 * credits (see rdsv3_ib_send_add_credits below).
 *
 * The RDS send code is essentially single-threaded; rdsv3_send_xmit
 * grabs c_send_lock to ensure exclusive access to the send ring.
 * However, the ACK sending code is independent and can race with
 * message SENDs.
 *
 * In the send path, we need to update the counters for send credits
 * and the counter of posted buffers atomically - when we use the
 * last available credit, we cannot allow another thread to race us
 * and grab the posted credits counter.  Hence, we have to use a
 * spinlock to protect the credit counter, or use atomics.
 *
 * Spinlocks shared between the send and the receive path are bad,
 * because they create unnecessary delays. An early implementation
 * using a spinlock showed a 5% degradation in throughput at some
 * loads.
 *
 * This implementation avoids spinlocks completely, putting both
 * counters into a single atomic, and updating that atomic using
 * atomic_add (in the receive path, when receiving fresh credits),
 * and using atomic_cmpxchg when updating the two counters.
 */
int
rdsv3_ib_send_grab_credits(struct rdsv3_ib_connection *ic,
    uint32_t wanted, uint32_t *adv_credits, int need_posted, int max_posted)
{
	unsigned int avail, posted, got = 0, advertise;
	long oldval, newval;

	RDSV3_DPRINTF4("rdsv3_ib_send_grab_credits", "ic: %p, %d %d %d %d",
	    ic, wanted, *adv_credits, need_posted, max_posted);

	*adv_credits = 0;
	if (!ic->i_flowctl)
		return (wanted);

try_again:
	advertise = 0;
	oldval = newval = atomic_get(&ic->i_credits);
	posted = IB_GET_POST_CREDITS(oldval);
	avail = IB_GET_SEND_CREDITS(oldval);

	RDSV3_DPRINTF5("rdsv3_ib_send_grab_credits",
	    "wanted (%u): credits=%u posted=%u\n", wanted, avail, posted);

	/* The last credit must be used to send a credit update. */
	if (avail && !posted)
		avail--;

	if (avail < wanted) {
		struct rdsv3_connection *conn = ic->i_cm_id->context;

		/* Oops, there aren't that many credits left! */
		set_bit(RDSV3_LL_SEND_FULL, &conn->c_flags);
		got = avail;
	} else {
		/* Sometimes you get what you want, lalala. */
		got = wanted;
	}
	newval -= IB_SET_SEND_CREDITS(got);

	/*
	 * If need_posted is non-zero, then the caller wants
	 * the posted regardless of whether any send credits are
	 * available.
	 */
	if (posted && (got || need_posted)) {
		advertise = min(posted, max_posted);
		newval -= IB_SET_POST_CREDITS(advertise);
	}

	/* Finally bill everything */
	if (atomic_cmpxchg(&ic->i_credits, oldval, newval) != oldval)
		goto try_again;

	*adv_credits = advertise;

	RDSV3_DPRINTF4("rdsv3_ib_send_grab_credits", "ic: %p, %d %d %d %d",
	    ic, got, *adv_credits, need_posted, max_posted);
	return (got);
}

void
rdsv3_ib_send_add_credits(struct rdsv3_connection *conn, unsigned int credits)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;

	if (credits == 0)
		return;

	RDSV3_DPRINTF5("rdsv3_ib_send_add_credits",
	    "credits (%u): current=%u%s\n",
	    credits,
	    IB_GET_SEND_CREDITS(atomic_get(&ic->i_credits)),
	    test_bit(RDSV3_LL_SEND_FULL, &conn->c_flags) ?
	    ", ll_send_full" : "");

	atomic_add_32(&ic->i_credits, IB_SET_SEND_CREDITS(credits));
	if (test_and_clear_bit(RDSV3_LL_SEND_FULL, &conn->c_flags))
		rdsv3_queue_delayed_work(rdsv3_wq, &conn->c_send_w, 0);

	ASSERT(!(IB_GET_SEND_CREDITS(credits) >= 16384));

	rdsv3_ib_stats_inc(s_ib_rx_credit_updates);

	RDSV3_DPRINTF4("rdsv3_ib_send_add_credits",
	    "Return: conn: %p, credits: %d",
	    conn, credits);
}

void
rdsv3_ib_advertise_credits(struct rdsv3_connection *conn, unsigned int posted)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;

	RDSV3_DPRINTF4("rdsv3_ib_advertise_credits", "conn: %p, posted: %d",
	    conn, posted);

	if (posted == 0)
		return;

	atomic_add_32(&ic->i_credits, IB_SET_POST_CREDITS(posted));

	/*
	 * Decide whether to send an update to the peer now.
	 * If we would send a credit update for every single buffer we
	 * post, we would end up with an ACK storm (ACK arrives,
	 * consumes buffer, we refill the ring, send ACK to remote
	 * advertising the newly posted buffer... ad inf)
	 *
	 * Performance pretty much depends on how often we send
	 * credit updates - too frequent updates mean lots of ACKs.
	 * Too infrequent updates, and the peer will run out of
	 * credits and has to throttle.
	 * For the time being, 16 seems to be a good compromise.
	 */
	if (IB_GET_POST_CREDITS(atomic_get(&ic->i_credits)) >= 16)
		set_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
}

static inline void
rdsv3_ib_xmit_populate_wr(struct rdsv3_ib_connection *ic,
    ibt_send_wr_t *wr, unsigned int pos,
    struct rdsv3_scatterlist *scat, unsigned int off, unsigned int length,
    int send_flags)
{
	ibt_wr_ds_t *sge;

	RDSV3_DPRINTF4("rdsv3_ib_xmit_populate_wr",
	    "ic: %p, wr: %p scat: %p %d %d %d %d",
	    ic, wr, scat, pos, off, length, send_flags);

	wr->wr_id = pos;
	wr->wr_trans = IBT_RC_SRV;
	wr->wr_flags = send_flags;
	wr->wr_opcode = IBT_WRC_SEND;

	if (length != 0) {
		int	ix, len, assigned;
		ibt_wr_ds_t *sgl;

		ASSERT(length <= scat->length - off);

		sgl = scat->sgl;
		if (off != 0) {
			/* find the right sgl to begin with */
			while (sgl->ds_len <= off) {
				off -= sgl->ds_len;
				sgl++;
			}
		}

		ix = 1; /* first data sgl is at 1 */
		assigned = 0;
		len = length;
		do {
			sge = &wr->wr_sgl[ix++];
			sge->ds_va = sgl->ds_va + off;
			assigned = min(len, sgl->ds_len - off);
			sge->ds_len = assigned;
			sge->ds_key = sgl->ds_key;
			len -= assigned;
			if (len != 0) {
				sgl++;
				off = 0;
			}
		} while (len > 0);

		wr->wr_nds = ix;
	} else {
		/*
		 * We're sending a packet with no payload. There is only
		 * one SGE
		 */
		wr->wr_nds = 1;
	}

	sge = &wr->wr_sgl[0];
	sge->ds_va = ic->i_send_hdrs_dma + (pos * sizeof (struct rdsv3_header));
	sge->ds_len = sizeof (struct rdsv3_header);
	sge->ds_key = ic->i_mr->lkey;

	RDSV3_DPRINTF4("rdsv3_ib_xmit_populate_wr",
	    "Return: ic: %p, wr: %p scat: %p", ic, wr, scat);
}

/*
 * This can be called multiple times for a given message.  The first time
 * we see a message we map its scatterlist into the IB device so that
 * we can provide that mapped address to the IB scatter gather entries
 * in the IB work requests.  We translate the scatterlist into a series
 * of work requests that fragment the message.  These work requests complete
 * in order so we pass ownership of the message to the completion handler
 * once we send the final fragment.
 *
 * The RDS core uses the c_send_lock to only enter this function once
 * per connection.  This makes sure that the tx ring alloc/unalloc pairs
 * don't get out of sync and confuse the ring.
 */
int
rdsv3_ib_xmit(struct rdsv3_connection *conn, struct rdsv3_message *rm,
    unsigned int hdr_off, unsigned int sg, unsigned int off)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;
	struct ib_device *dev = ic->i_cm_id->device;
	struct rdsv3_ib_send_work *send = NULL;
	struct rdsv3_ib_send_work *first;
	struct rdsv3_ib_send_work *prev;
	ibt_send_wr_t *wr;
	struct rdsv3_scatterlist *scat;
	uint32_t pos;
	uint32_t i;
	uint32_t work_alloc;
	uint32_t credit_alloc;
	uint32_t posted;
	uint32_t adv_credits = 0;
	int send_flags = 0;
	int sent;
	int ret;
	int flow_controlled = 0;

	RDSV3_DPRINTF4("rdsv3_ib_xmit", "conn: %p, rm: %p", conn, rm);

	ASSERT(!(off % RDSV3_FRAG_SIZE));
	ASSERT(!(hdr_off != 0 && hdr_off != sizeof (struct rdsv3_header)));

	/* Do not send cong updates to IB loopback */
	if (conn->c_loopback &&
	    rm->m_inc.i_hdr.h_flags & RDSV3_FLAG_CONG_BITMAP) {
		rdsv3_cong_map_updated(conn->c_fcong, ~(uint64_t)0);
		return (sizeof (struct rdsv3_header) + RDSV3_CONG_MAP_BYTES);
	}

#ifndef __lock_lint
	/* FIXME we may overallocate here */
	if (ntohl(rm->m_inc.i_hdr.h_len) == 0)
		i = 1;
	else
		i = ceil(ntohl(rm->m_inc.i_hdr.h_len), RDSV3_FRAG_SIZE);
#endif

	work_alloc = rdsv3_ib_ring_alloc(&ic->i_send_ring, i, &pos);
	if (work_alloc == 0) {
		set_bit(RDSV3_LL_SEND_FULL, &conn->c_flags);
		rdsv3_ib_stats_inc(s_ib_tx_ring_full);
		ret = -ENOMEM;
		goto out;
	}

	credit_alloc = work_alloc;
	if (ic->i_flowctl) {
		credit_alloc = rdsv3_ib_send_grab_credits(ic, work_alloc,
		    &posted, 0, RDSV3_MAX_ADV_CREDIT);
		adv_credits += posted;
		if (credit_alloc < work_alloc) {
			rdsv3_ib_ring_unalloc(&ic->i_send_ring,
			    work_alloc - credit_alloc);
			work_alloc = credit_alloc;
			flow_controlled++;
		}
		if (work_alloc == 0) {
			set_bit(RDSV3_LL_SEND_FULL, &conn->c_flags);
			rdsv3_ib_stats_inc(s_ib_tx_throttle);
			ret = -ENOMEM;
			goto out;
		}
	}

	/* map the message the first time we see it */
	if (ic->i_rm == NULL) {
		/*
		 * printk(KERN_NOTICE
		 * "rdsv3_ib_xmit prep msg dport=%u flags=0x%x len=%d\n",
		 * be16_to_cpu(rm->m_inc.i_hdr.h_dport),
		 * rm->m_inc.i_hdr.h_flags,
		 * be32_to_cpu(rm->m_inc.i_hdr.h_len));
		 */
		if (rm->m_nents) {
			rm->m_count = rdsv3_ib_dma_map_sg(dev,
			    rm->m_sg, rm->m_nents);
			RDSV3_DPRINTF5("rdsv3_ib_xmit",
			    "ic %p mapping rm %p: %d\n", ic, rm, rm->m_count);
			if (rm->m_count == 0) {
				rdsv3_ib_stats_inc(s_ib_tx_sg_mapping_failure);
				rdsv3_ib_ring_unalloc(&ic->i_send_ring,
				    work_alloc);
				ret = -ENOMEM; /* XXX ? */
				RDSV3_DPRINTF2("rdsv3_ib_xmit",
				    "fail: ic %p mapping rm %p: %d\n",
				    ic, rm, rm->m_count);
				goto out;
			}
		} else {
			rm->m_count = 0;
		}

		ic->i_unsignaled_wrs = rdsv3_ib_sysctl_max_unsig_wrs;
		ic->i_unsignaled_bytes = rdsv3_ib_sysctl_max_unsig_bytes;
		rdsv3_message_addref(rm);
		ic->i_rm = rm;

		/* Finalize the header */
		if (test_bit(RDSV3_MSG_ACK_REQUIRED, &rm->m_flags))
			rm->m_inc.i_hdr.h_flags |= RDSV3_FLAG_ACK_REQUIRED;
		if (test_bit(RDSV3_MSG_RETRANSMITTED, &rm->m_flags))
			rm->m_inc.i_hdr.h_flags |= RDSV3_FLAG_RETRANSMITTED;

		/*
		 * If it has a RDMA op, tell the peer we did it. This is
		 * used by the peer to release use-once RDMA MRs.
		 */
		if (rm->m_rdma_op) {
			struct rdsv3_ext_header_rdma ext_hdr;

			ext_hdr.h_rdma_rkey = htonl(rm->m_rdma_op->r_key);
			(void) rdsv3_message_add_extension(&rm->m_inc.i_hdr,
			    RDSV3_EXTHDR_RDMA, &ext_hdr,
			    sizeof (ext_hdr));
		}
		if (rm->m_rdma_cookie) {
			(void) rdsv3_message_add_rdma_dest_extension(
			    &rm->m_inc.i_hdr,
			    rdsv3_rdma_cookie_key(rm->m_rdma_cookie),
			    rdsv3_rdma_cookie_offset(rm->m_rdma_cookie));
		}

		/*
		 * Note - rdsv3_ib_piggyb_ack clears the ACK_REQUIRED bit, so
		 * we should not do this unless we have a chance of at least
		 * sticking the header into the send ring. Which is why we
		 * should call rdsv3_ib_ring_alloc first.
		 */
		rm->m_inc.i_hdr.h_ack = htonll(rdsv3_ib_piggyb_ack(ic));
		rdsv3_message_make_checksum(&rm->m_inc.i_hdr);

		/*
		 * Update adv_credits since we reset the ACK_REQUIRED bit.
		 */
		(void) rdsv3_ib_send_grab_credits(ic, 0, &posted, 1,
		    RDSV3_MAX_ADV_CREDIT - adv_credits);
		adv_credits += posted;
		ASSERT(adv_credits <= 255);
	} else if (ic->i_rm != rm)
		RDSV3_PANIC();

	send = &ic->i_sends[pos];
	first = send;
	prev = NULL;
	scat = &rm->m_sg[sg];
	sent = 0;
	i = 0;

	/*
	 * Sometimes you want to put a fence between an RDMA
	 * READ and the following SEND.
	 * We could either do this all the time
	 * or when requested by the user. Right now, we let
	 * the application choose.
	 */
	if (rm->m_rdma_op && rm->m_rdma_op->r_fence)
		send_flags = IBT_WR_SEND_FENCE;

	/*
	 * We could be copying the header into the unused tail of the page.
	 * That would need to be changed in the future when those pages might
	 * be mapped userspace pages or page cache pages.  So instead we always
	 * use a second sge and our long-lived ring of mapped headers.  We send
	 * the header after the data so that the data payload can be aligned on
	 * the receiver.
	 */

	/* handle a 0-len message */
	if (ntohl(rm->m_inc.i_hdr.h_len) == 0) {
		wr = &ic->i_send_wrs[0];
		rdsv3_ib_xmit_populate_wr(ic, wr, pos, NULL, 0, 0, send_flags);
		send->s_queued = jiffies;
		send->s_op = NULL;
		send->s_opcode = wr->wr_opcode;
		goto add_header;
	}

	/* if there's data reference it with a chain of work reqs */
	for (; i < work_alloc && scat != &rm->m_sg[rm->m_count]; i++) {
		unsigned int len;

		send = &ic->i_sends[pos];

		wr = &ic->i_send_wrs[i];
		len = min(RDSV3_FRAG_SIZE,
		    rdsv3_ib_sg_dma_len(dev, scat) - off);
		rdsv3_ib_xmit_populate_wr(ic, wr, pos, scat, off, len,
		    send_flags);
		send->s_queued = jiffies;
		send->s_op = NULL;
		send->s_opcode = wr->wr_opcode;

		/*
		 * We want to delay signaling completions just enough to get
		 * the batching benefits but not so much that we create dead
		 * time
		 * on the wire.
		 */
		if (ic->i_unsignaled_wrs-- == 0) {
			ic->i_unsignaled_wrs = rdsv3_ib_sysctl_max_unsig_wrs;
			wr->wr_flags |=
			    IBT_WR_SEND_SIGNAL | IBT_WR_SEND_SOLICIT;
		}

		ic->i_unsignaled_bytes -= len;
		if (ic->i_unsignaled_bytes <= 0) {
			ic->i_unsignaled_bytes =
			    rdsv3_ib_sysctl_max_unsig_bytes;
			wr->wr_flags |=
			    IBT_WR_SEND_SIGNAL | IBT_WR_SEND_SOLICIT;
		}

		/*
		 * Always signal the last one if we're stopping due to flow
		 * control.
		 */
		if (flow_controlled && i == (work_alloc-1)) {
			wr->wr_flags |=
			    IBT_WR_SEND_SIGNAL | IBT_WR_SEND_SOLICIT;
		}

		RDSV3_DPRINTF5("rdsv3_ib_xmit", "send %p wr %p num_sge %u \n",
		    send, wr, wr->wr_nds);

		sent += len;
		off += len;
		if (off == rdsv3_ib_sg_dma_len(dev, scat)) {
			scat++;
			off = 0;
		}

add_header:
		/*
		 * Tack on the header after the data. The header SGE
		 * should already
		 * have been set up to point to the right header buffer.
		 */
		(void) memcpy(&ic->i_send_hdrs[pos], &rm->m_inc.i_hdr,
		    sizeof (struct rdsv3_header));

		if (0) {
			struct rdsv3_header *hdr = &ic->i_send_hdrs[pos];

			RDSV3_DPRINTF2("rdsv3_ib_xmit",
			    "send WR dport=%u flags=0x%x len=%d",
			    ntohs(hdr->h_dport),
			    hdr->h_flags,
			    ntohl(hdr->h_len));
		}
		if (adv_credits) {
			struct rdsv3_header *hdr = &ic->i_send_hdrs[pos];

			/* add credit and redo the header checksum */
			hdr->h_credit = adv_credits;
			rdsv3_message_make_checksum(hdr);
			adv_credits = 0;
			rdsv3_ib_stats_inc(s_ib_tx_credit_updates);
		}

		prev = send;

		pos = (pos + 1) % ic->i_send_ring.w_nr;
	}

	/*
	 * Account the RDS header in the number of bytes we sent, but just once.
	 * The caller has no concept of fragmentation.
	 */
	if (hdr_off == 0)
		sent += sizeof (struct rdsv3_header);

	/* if we finished the message then send completion owns it */
	if (scat == &rm->m_sg[rm->m_count]) {
		prev->s_rm = ic->i_rm;
		wr->wr_flags |= IBT_WR_SEND_SIGNAL | IBT_WR_SEND_SOLICIT;
		ic->i_rm = NULL;
	}

	if (i < work_alloc) {
		rdsv3_ib_ring_unalloc(&ic->i_send_ring, work_alloc - i);
		work_alloc = i;
	}
	if (ic->i_flowctl && i < credit_alloc)
		rdsv3_ib_send_add_credits(conn, credit_alloc - i);

	/* XXX need to worry about failed_wr and partial sends. */
	ret = ibt_post_send(ib_get_ibt_channel_hdl(ic->i_cm_id),
	    ic->i_send_wrs, i, &posted);
	if (posted != i) {
		RDSV3_DPRINTF2("rdsv3_ib_xmit",
		    "ic %p first %p nwr: %d ret %d:%d",
		    ic, first, i, ret, posted);
	}
	if (ret) {
		RDSV3_DPRINTF2("rdsv3_ib_xmit",
		    "RDS/IB: ib_post_send to %u.%u.%u.%u "
		    "returned %d\n", NIPQUAD(conn->c_faddr), ret);
		rdsv3_ib_ring_unalloc(&ic->i_send_ring, work_alloc);
		if (prev->s_rm) {
			ic->i_rm = prev->s_rm;
			prev->s_rm = NULL;
		}
#if 1
		RDSV3_DPRINTF2("rdsv3_ib_xmit", "ibt_post_send FAIL");
		ret = -EAGAIN;
#else
		/* Finesse this later */
		RDSV3_PANIC();
#endif
		goto out;
	}

	ret = sent;

	RDSV3_DPRINTF4("rdsv3_ib_xmit", "Return: conn: %p, rm: %p", conn, rm);
out:
	ASSERT(!adv_credits);
	return (ret);
}

static void
rdsv3_ib_dma_unmap_sg_rdma(struct ib_device *dev, uint_t num,
	struct rdsv3_rdma_sg scat[])
{
	ibt_hca_hdl_t hca_hdl;
	int i;
	int num_sgl;

	RDSV3_DPRINTF4("rdsv3_ib_dma_unmap_sg", "rdma_sg: %p", scat);

	if (dev) {
		hca_hdl = ib_get_ibt_hca_hdl(dev);
	} else {
		hca_hdl = scat[0].hca_hdl;
		RDSV3_DPRINTF2("rdsv3_ib_dma_unmap_sg_rdma",
		    "NULL dev use cached hca_hdl %p", hca_hdl);
	}

	if (hca_hdl == NULL)
		return;
	scat[0].hca_hdl = NULL;

	for (i = 0; i < num; i++) {
		if (scat[i].mihdl != NULL) {
			num_sgl = (scat[i].iovec.bytes / PAGESIZE) + 2;
			kmem_free(scat[i].swr.wr_sgl,
			    (num_sgl * sizeof (ibt_wr_ds_t)));
			scat[i].swr.wr_sgl = NULL;
			(void) ibt_unmap_mem_iov(hca_hdl, scat[i].mihdl);
			scat[i].mihdl = NULL;
		} else
			break;
	}
}

/* ARGSUSED */
uint_t
rdsv3_ib_dma_map_sg_rdma(struct ib_device *dev, struct rdsv3_rdma_sg scat[],
    uint_t num, struct rdsv3_scatterlist **scatl)
{
	ibt_hca_hdl_t hca_hdl;
	ibt_iov_attr_t iov_attr;
	struct buf *bp;
	uint_t i, j, k;
	uint_t count;
	struct rdsv3_scatterlist *sg;
	int ret;

	RDSV3_DPRINTF4("rdsv3_ib_dma_map_sg_rdma", "scat: %p, num: %d",
	    scat, num);

	hca_hdl = ib_get_ibt_hca_hdl(dev);
	scat[0].hca_hdl = hca_hdl;
	bzero(&iov_attr, sizeof (ibt_iov_attr_t));
	iov_attr.iov_flags = IBT_IOV_BUF;
	iov_attr.iov_lso_hdr_sz = 0;

	for (i = 0, count = 0; i < num; i++) {
		/* transpose umem_cookie  to buf structure */
		bp = ddi_umem_iosetup(scat[i].umem_cookie,
		    scat[i].iovec.addr & PAGEOFFSET, scat[i].iovec.bytes,
		    B_WRITE, 0, 0, NULL, DDI_UMEM_SLEEP);
		if (bp == NULL) {
			/* free resources  and return error */
			goto out;
		}
		/* setup ibt_map_mem_iov() attributes */
		iov_attr.iov_buf = bp;
		iov_attr.iov_wr_nds = (scat[i].iovec.bytes / PAGESIZE) + 2;
		scat[i].swr.wr_sgl =
		    kmem_zalloc(iov_attr.iov_wr_nds * sizeof (ibt_wr_ds_t),
		    KM_SLEEP);

		ret = ibt_map_mem_iov(hca_hdl, &iov_attr,
		    (ibt_all_wr_t *)&scat[i].swr, &scat[i].mihdl);
		freerbuf(bp);
		if (ret != IBT_SUCCESS) {
			RDSV3_DPRINTF2("rdsv3_ib_dma_map_sg_rdma",
			    "ibt_map_mem_iov returned: %d", ret);
			/* free resources and return error */
			kmem_free(scat[i].swr.wr_sgl,
			    iov_attr.iov_wr_nds * sizeof (ibt_wr_ds_t));
			goto out;
		}
		count += scat[i].swr.wr_nds;

#ifdef  DEBUG
		for (j = 0; j < scat[i].swr.wr_nds; j++) {
			RDSV3_DPRINTF5("rdsv3_ib_dma_map_sg_rdma",
			    "sgl[%d] va %llx len %x", j,
			    scat[i].swr.wr_sgl[j].ds_va,
			    scat[i].swr.wr_sgl[j].ds_len);
		}
#endif
		RDSV3_DPRINTF4("rdsv3_ib_dma_map_sg_rdma",
		    "iovec.bytes: 0x%x scat[%d]swr.wr_nds: %d",
		    scat[i].iovec.bytes, i, scat[i].swr.wr_nds);
	}

	count = ((count - 1) / RDSV3_IB_MAX_SGE) + 1;
	RDSV3_DPRINTF4("rdsv3_ib_dma_map_sg_rdma", "Ret: num: %d", count);
	return (count);

out:
	rdsv3_ib_dma_unmap_sg_rdma(dev, num, scat);
	return (0);
}

int
rdsv3_ib_xmit_rdma(struct rdsv3_connection *conn, struct rdsv3_rdma_op *op)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;
	struct rdsv3_ib_send_work *send = NULL;
	struct rdsv3_rdma_sg *scat;
	uint64_t remote_addr;
	uint32_t pos;
	uint32_t work_alloc;
	uint32_t i, j, k, idx;
	uint32_t left, count;
	uint32_t posted;
	int sent;
	ibt_status_t status;
	ibt_send_wr_t *wr;
	ibt_wr_ds_t *sge;

	RDSV3_DPRINTF4("rdsv3_ib_xmit_rdma", "rdsv3_ib_conn: %p", ic);

	/* map the message the first time we see it */
	if (!op->r_mapped) {
		op->r_count = rdsv3_ib_dma_map_sg_rdma(ic->i_cm_id->device,
		    op->r_rdma_sg, op->r_nents, &op->r_sg);
		RDSV3_DPRINTF5("rdsv3_ib_xmit_rdma", "ic %p mapping op %p: %d",
		    ic, op, op->r_count);
		if (op->r_count == 0) {
			rdsv3_ib_stats_inc(s_ib_tx_sg_mapping_failure);
			RDSV3_DPRINTF2("rdsv3_ib_xmit_rdma",
			    "fail: ic %p mapping op %p: %d",
			    ic, op, op->r_count);
			return (-ENOMEM); /* XXX ? */
		}
		op->r_mapped = 1;
	}

	/*
	 * Instead of knowing how to return a partial rdma read/write
	 * we insist that there
	 * be enough work requests to send the entire message.
	 */
	work_alloc = rdsv3_ib_ring_alloc(&ic->i_send_ring, op->r_count, &pos);
	if (work_alloc != op->r_count) {
		rdsv3_ib_ring_unalloc(&ic->i_send_ring, work_alloc);
		rdsv3_ib_stats_inc(s_ib_tx_ring_full);
		return (-ENOMEM);
	}

	/*
	 * take the scatter list and transpose into a list of
	 * send wr's each with a scatter list of RDSV3_IB_MAX_SGE
	 */
	scat = &op->r_rdma_sg[0];
	sent = 0;
	remote_addr = op->r_remote_addr;

	for (i = 0, k = 0; i < op->r_nents; i++) {
		left = scat[i].swr.wr_nds;
		for (idx = 0; left > 0; k++) {
			send = &ic->i_sends[pos];
			send->s_queued = jiffies;
			send->s_opcode = op->r_write ? IBT_WRC_RDMAW :
			    IBT_WRC_RDMAR;
			send->s_op = op;

			wr = &ic->i_send_wrs[k];
			wr->wr_flags = 0;
			wr->wr_id = pos;
			wr->wr_trans = IBT_RC_SRV;
			wr->wr_opcode = op->r_write ? IBT_WRC_RDMAW :
			    IBT_WRC_RDMAR;
			wr->wr.rc.rcwr.rdma.rdma_raddr = remote_addr;
			wr->wr.rc.rcwr.rdma.rdma_rkey = op->r_key;

			if (left > RDSV3_IB_MAX_SGE) {
				count = RDSV3_IB_MAX_SGE;
				left -= RDSV3_IB_MAX_SGE;
			} else {
				count = left;
				left = 0;
			}
			wr->wr_nds = count;

			for (j = 0; j < count; j++) {
				sge = &wr->wr_sgl[j];
				*sge = scat[i].swr.wr_sgl[idx];
				remote_addr += scat[i].swr.wr_sgl[idx].ds_len;
				sent += scat[i].swr.wr_sgl[idx].ds_len;
				idx++;
				RDSV3_DPRINTF4("xmit_rdma",
				    "send_wrs[%d]sgl[%d] va %llx len %x",
				    k, j, sge->ds_va, sge->ds_len);
			}
			RDSV3_DPRINTF4("rdsv3_ib_xmit_rdma",
			    "wr[%d] %p key: %x code: %d tlen: %d",
			    k, wr, wr->wr.rc.rcwr.rdma.rdma_rkey,
			    wr->wr_opcode, sent);

			/*
			 * We want to delay signaling completions just enough
			 * to get the batching benefits but not so much that
			 * we create dead time on the wire.
			 */
			if (ic->i_unsignaled_wrs-- == 0) {
				ic->i_unsignaled_wrs =
				    rdsv3_ib_sysctl_max_unsig_wrs;
				wr->wr_flags = IBT_WR_SEND_SIGNAL;
			}

			pos = (pos + 1) % ic->i_send_ring.w_nr;
		}
	}

	status = ibt_post_send(ib_get_ibt_channel_hdl(ic->i_cm_id),
	    ic->i_send_wrs, k, &posted);
	if (status != IBT_SUCCESS) {
		RDSV3_DPRINTF2("rdsv3_ib_xmit_rdma",
		    "RDS/IB: rdma ib_post_send returned %d", status);
		rdsv3_ib_ring_unalloc(&ic->i_send_ring, work_alloc);
	}
	return (status);
}

void
rdsv3_ib_xmit_complete(struct rdsv3_connection *conn)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;

	RDSV3_DPRINTF4("rdsv3_ib_xmit_complete", "conn: %p", conn);

	/*
	 * We may have a pending ACK or window update we were unable
	 * to send previously (due to flow control). Try again.
	 */
	rdsv3_ib_attempt_ack(ic);
}

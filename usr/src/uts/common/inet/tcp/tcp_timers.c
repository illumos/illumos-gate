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
 * Copyright (c) 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#include <sys/callo.h>
#include <sys/strsubr.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>

/*
 * Implementation of TCP Timers.
 * =============================
 *
 * INTERFACE:
 *
 * There are two basic functions dealing with tcp timers:
 *
 *	timeout_id_t	tcp_timeout(connp, func, time)
 * 	clock_t		tcp_timeout_cancel(connp, timeout_id)
 *	TCP_TIMER_RESTART(tcp, intvl)
 *
 * tcp_timeout() starts a timer for the 'tcp' instance arranging to call 'func'
 * after 'time' ticks passed. The function called by timeout() must adhere to
 * the same restrictions as a driver soft interrupt handler - it must not sleep
 * or call other functions that might sleep. The value returned is the opaque
 * non-zero timeout identifier that can be passed to tcp_timeout_cancel() to
 * cancel the request. The call to tcp_timeout() may fail in which case it
 * returns zero. This is different from the timeout(9F) function which never
 * fails.
 *
 * The call-back function 'func' always receives 'connp' as its single
 * argument. It is always executed in the squeue corresponding to the tcp
 * structure. The tcp structure is guaranteed to be present at the time the
 * call-back is called.
 *
 * NOTE: The call-back function 'func' is never called if tcp is in
 * 	the TCPS_CLOSED state.
 *
 * tcp_timeout_cancel() attempts to cancel a pending tcp_timeout()
 * request. locks acquired by the call-back routine should not be held across
 * the call to tcp_timeout_cancel() or a deadlock may result.
 *
 * tcp_timeout_cancel() returns -1 if the timeout request is invalid.
 * Otherwise, it returns an integer value greater than or equal to 0.
 *
 * NOTE: both tcp_timeout() and tcp_timeout_cancel() should always be called
 * 	within squeue context corresponding to the tcp instance. Since the
 *	call-back is also called via the same squeue, there are no race
 *	conditions described in untimeout(9F) manual page since all calls are
 *	strictly serialized.
 *
 *      TCP_TIMER_RESTART() is a macro that attempts to cancel a pending timeout
 *	stored in tcp_timer_tid and starts a new one using
 *	MSEC_TO_TICK(intvl). It always uses tcp_timer() function as a call-back
 *	and stores the return value of tcp_timeout() in the tcp->tcp_timer_tid
 *	field.
 *
 * IMPLEMENTATION:
 *
 * TCP timers are implemented using three-stage process. The call to
 * tcp_timeout() uses timeout(9F) function to call tcp_timer_callback() function
 * when the timer expires. The tcp_timer_callback() arranges the call of the
 * tcp_timer_handler() function via squeue corresponding to the tcp
 * instance. The tcp_timer_handler() calls actual requested timeout call-back
 * and passes tcp instance as an argument to it. Information is passed between
 * stages using the tcp_timer_t structure which contains the connp pointer, the
 * tcp call-back to call and the timeout id returned by the timeout(9F).
 *
 * The tcp_timer_t structure is not used directly, it is embedded in an mblk_t -
 * like structure that is used to enter an squeue. The mp->b_rptr of this pseudo
 * mblk points to the beginning of tcp_timer_t structure. The tcp_timeout()
 * returns the pointer to this mblk.
 *
 * The pseudo mblk is allocated from a special tcp_timer_cache kmem cache. It
 * looks like a normal mblk without actual dblk attached to it.
 *
 * To optimize performance each tcp instance holds a small cache of timer
 * mblocks. In the current implementation it caches up to two timer mblocks per
 * tcp instance. The cache is preserved over tcp frees and is only freed when
 * the whole tcp structure is destroyed by its kmem destructor. Since all tcp
 * timer processing happens on a corresponding squeue, the cache manipulation
 * does not require any locks. Experiments show that majority of timer mblocks
 * allocations are satisfied from the tcp cache and do not involve kmem calls.
 *
 * The tcp_timeout() places a refhold on the connp instance which guarantees
 * that it will be present at the time the call-back function fires. The
 * tcp_timer_handler() drops the reference after calling the call-back, so the
 * call-back function does not need to manipulate the references explicitly.
 */

kmem_cache_t *tcp_timercache;

static void	tcp_ip_notify(tcp_t *);
static void	tcp_timer_callback(void *);
static void	tcp_timer_free(tcp_t *, mblk_t *);
static void	tcp_timer_handler(void *, mblk_t *, void *, ip_recv_attr_t *);

/*
 * tim is in millisec.
 */
timeout_id_t
tcp_timeout(conn_t *connp, void (*f)(void *), hrtime_t tim)
{
	mblk_t *mp;
	tcp_timer_t *tcpt;
	tcp_t *tcp = connp->conn_tcp;

	ASSERT(connp->conn_sqp != NULL);

	TCP_DBGSTAT(tcp->tcp_tcps, tcp_timeout_calls);

	if (tcp->tcp_timercache == NULL) {
		mp = tcp_timermp_alloc(KM_NOSLEEP | KM_PANIC);
	} else {
		TCP_DBGSTAT(tcp->tcp_tcps, tcp_timeout_cached_alloc);
		mp = tcp->tcp_timercache;
		tcp->tcp_timercache = mp->b_next;
		mp->b_next = NULL;
		ASSERT(mp->b_wptr == NULL);
	}

	CONN_INC_REF(connp);
	tcpt = (tcp_timer_t *)mp->b_rptr;
	tcpt->connp = connp;
	tcpt->tcpt_proc = f;
	/*
	 * TCP timers are normal timeouts. Plus, they do not require more than
	 * a 10 millisecond resolution. By choosing a coarser resolution and by
	 * rounding up the expiration to the next resolution boundary, we can
	 * batch timers in the callout subsystem to make TCP timers more
	 * efficient. The roundup also protects short timers from expiring too
	 * early before they have a chance to be cancelled.
	 */
	tcpt->tcpt_tid = timeout_generic(CALLOUT_NORMAL, tcp_timer_callback, mp,
	    tim * MICROSEC, CALLOUT_TCP_RESOLUTION, CALLOUT_FLAG_ROUNDUP);
	VERIFY(!(tcpt->tcpt_tid & CALLOUT_ID_FREE));

	return ((timeout_id_t)mp);
}

static void
tcp_timer_callback(void *arg)
{
	mblk_t *mp = (mblk_t *)arg;
	tcp_timer_t *tcpt;
	conn_t	*connp;

	tcpt = (tcp_timer_t *)mp->b_rptr;
	connp = tcpt->connp;
	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_timer_handler, connp,
	    NULL, SQ_FILL, SQTAG_TCP_TIMER);
}

/* ARGSUSED */
static void
tcp_timer_handler(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	tcp_timer_t *tcpt;
	conn_t *connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;

	tcpt = (tcp_timer_t *)mp->b_rptr;
	ASSERT(connp == tcpt->connp);
	ASSERT((squeue_t *)arg2 == connp->conn_sqp);

	if (tcpt->tcpt_tid & CALLOUT_ID_FREE) {
		/*
		 * This timeout was cancelled after it was enqueued to the
		 * squeue; free the timer and return.
		 */
		tcp_timer_free(connp->conn_tcp, mp);
		return;
	}

	/*
	 * If the TCP has reached the closed state, don't proceed any
	 * further. This TCP logically does not exist on the system.
	 * tcpt_proc could for example access queues, that have already
	 * been qprocoff'ed off.
	 */
	if (tcp->tcp_state != TCPS_CLOSED) {
		(*tcpt->tcpt_proc)(connp);
	} else {
		tcp->tcp_timer_tid = 0;
	}

	tcp_timer_free(connp->conn_tcp, mp);
}

/*
 * There is potential race with untimeout and the handler firing at the same
 * time. The mblock may be freed by the handler while we are trying to use
 * it. But since both should execute on the same squeue, this race should not
 * occur.
 */
clock_t
tcp_timeout_cancel(conn_t *connp, timeout_id_t id)
{
	mblk_t	*mp = (mblk_t *)id;
	tcp_timer_t *tcpt;
	clock_t delta;

	TCP_DBGSTAT(connp->conn_tcp->tcp_tcps, tcp_timeout_cancel_reqs);

	if (mp == NULL)
		return (-1);

	tcpt = (tcp_timer_t *)mp->b_rptr;
	ASSERT(tcpt->connp == connp);

	delta = untimeout_default(tcpt->tcpt_tid, 0);

	if (delta >= 0) {
		TCP_DBGSTAT(connp->conn_tcp->tcp_tcps, tcp_timeout_canceled);
		tcp_timer_free(connp->conn_tcp, mp);
		CONN_DEC_REF(connp);
	} else {
		/*
		 * If we were unable to untimeout successfully, it has already
		 * been enqueued on the squeue; mark the ID with the free
		 * bit.	 This bit can never be set in a valid identifier, and
		 * we'll use it to prevent the timeout from being executed.
		 * And note that we're within the squeue perimeter here, so
		 * we don't need to worry about racing with timer handling
		 * (which also executes within the perimeter).
		 */
		tcpt->tcpt_tid |= CALLOUT_ID_FREE;
		delta = 0;
	}

	return (TICK_TO_MSEC(delta));
}

/*
 * Allocate space for the timer event. The allocation looks like mblk, but it is
 * not a proper mblk. To avoid confusion we set b_wptr to NULL.
 *
 * Dealing with failures: If we can't allocate from the timer cache we try
 * allocating from dblock caches using allocb_tryhard(). In this case b_wptr
 * points to b_rptr.
 * If we can't allocate anything using allocb_tryhard(), we perform a last
 * attempt and use kmem_alloc_tryhard(). In this case we set b_wptr to -1 and
 * save the actual allocation size in b_datap.
 */
mblk_t *
tcp_timermp_alloc(int kmflags)
{
	mblk_t *mp = (mblk_t *)kmem_cache_alloc(tcp_timercache,
	    kmflags & ~KM_PANIC);

	if (mp != NULL) {
		mp->b_next = mp->b_prev = NULL;
		mp->b_rptr = (uchar_t *)(&mp[1]);
		mp->b_wptr = NULL;
		mp->b_datap = NULL;
		mp->b_queue = NULL;
		mp->b_cont = NULL;
	} else if (kmflags & KM_PANIC) {
		/*
		 * Failed to allocate memory for the timer. Try allocating from
		 * dblock caches.
		 */
		/* ipclassifier calls this from a constructor - hence no tcps */
		TCP_G_STAT(tcp_timermp_allocfail);
		mp = allocb_tryhard(sizeof (tcp_timer_t));
		if (mp == NULL) {
			size_t size = 0;
			/*
			 * Memory is really low. Try tryhard allocation.
			 *
			 * ipclassifier calls this from a constructor -
			 * hence no tcps
			 */
			TCP_G_STAT(tcp_timermp_allocdblfail);
			mp = kmem_alloc_tryhard(sizeof (mblk_t) +
			    sizeof (tcp_timer_t), &size, kmflags);
			mp->b_rptr = (uchar_t *)(&mp[1]);
			mp->b_next = mp->b_prev = NULL;
			mp->b_wptr = (uchar_t *)-1;
			mp->b_datap = (dblk_t *)size;
			mp->b_queue = NULL;
			mp->b_cont = NULL;
		}
		ASSERT(mp->b_wptr != NULL);
	}
	/* ipclassifier calls this from a constructor - hence no tcps */
	TCP_G_DBGSTAT(tcp_timermp_alloced);

	return (mp);
}

/*
 * Free per-tcp timer cache.
 * It can only contain entries from tcp_timercache.
 */
void
tcp_timermp_free(tcp_t *tcp)
{
	mblk_t *mp;

	while ((mp = tcp->tcp_timercache) != NULL) {
		ASSERT(mp->b_wptr == NULL);
		tcp->tcp_timercache = tcp->tcp_timercache->b_next;
		kmem_cache_free(tcp_timercache, mp);
	}
}

/*
 * Free timer event. Put it on the per-tcp timer cache if there is not too many
 * events there already (currently at most two events are cached).
 * If the event is not allocated from the timer cache, free it right away.
 */
static void
tcp_timer_free(tcp_t *tcp, mblk_t *mp)
{
	mblk_t *mp1 = tcp->tcp_timercache;

	if (mp->b_wptr != NULL) {
		/*
		 * This allocation is not from a timer cache, free it right
		 * away.
		 */
		if (mp->b_wptr != (uchar_t *)-1)
			freeb(mp);
		else
			kmem_free(mp, (size_t)mp->b_datap);
	} else if (mp1 == NULL || mp1->b_next == NULL) {
		/* Cache this timer block for future allocations */
		mp->b_rptr = (uchar_t *)(&mp[1]);
		mp->b_next = mp1;
		tcp->tcp_timercache = mp;
	} else {
		kmem_cache_free(tcp_timercache, mp);
		TCP_DBGSTAT(tcp->tcp_tcps, tcp_timermp_freed);
	}
}

/*
 * Stop all TCP timers.
 */
void
tcp_timers_stop(tcp_t *tcp)
{
	if (tcp->tcp_timer_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_timer_tid);
		tcp->tcp_timer_tid = 0;
	}
	if (tcp->tcp_ka_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_ka_tid);
		tcp->tcp_ka_tid = 0;
	}
	if (tcp->tcp_ack_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_ack_tid);
		tcp->tcp_ack_tid = 0;
	}
	if (tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_push_tid);
		tcp->tcp_push_tid = 0;
	}
	if (tcp->tcp_reass_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_reass_tid);
		tcp->tcp_reass_tid = 0;
	}
}

/*
 * Timer callback routine for keepalive probe.  We do a fake resend of
 * last ACKed byte.  Then set a timer using RTO.  When the timer expires,
 * check to see if we have heard anything from the other end for the last
 * RTO period.  If we have, set the timer to expire for another
 * tcp_keepalive_intrvl and check again.  If we have not, set a timer using
 * RTO << 1 and check again when it expires.  Keep exponentially increasing
 * the timeout if we have not heard from the other side.  If for more than
 * (tcp_ka_interval + tcp_ka_abort_thres) we have not heard anything,
 * kill the connection unless the keepalive abort threshold is 0.  In
 * that case, we will probe "forever."
 * If tcp_ka_cnt and tcp_ka_rinterval are non-zero, then we do not follow
 * the exponential backoff, but send probes tcp_ka_cnt times in regular
 * intervals of tcp_ka_rinterval milliseconds until we hear back from peer.
 * Kill the connection if we don't hear back from peer after tcp_ka_cnt
 * probes are sent.
 */
void
tcp_keepalive_timer(void *arg)
{
	mblk_t	*mp;
	conn_t	*connp = (conn_t *)arg;
	tcp_t  	*tcp = connp->conn_tcp;
	int32_t	firetime;
	int32_t	idletime;
	int32_t	ka_intrvl;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	tcp->tcp_ka_tid = 0;

	if (tcp->tcp_fused)
		return;

	TCPS_BUMP_MIB(tcps, tcpTimKeepalive);
	ka_intrvl = tcp->tcp_ka_interval;

	/*
	 * Keepalive probe should only be sent if the application has not
	 * done a close on the connection.
	 */
	if (tcp->tcp_state > TCPS_CLOSE_WAIT) {
		return;
	}
	/* Timer fired too early, restart it. */
	if (tcp->tcp_state < TCPS_ESTABLISHED) {
		tcp->tcp_ka_tid = TCP_TIMER(tcp, tcp_keepalive_timer,
		    ka_intrvl);
		return;
	}

	idletime = TICK_TO_MSEC(ddi_get_lbolt() - tcp->tcp_last_recv_time);
	/*
	 * If we have not heard from the other side for a long
	 * time, kill the connection unless the keepalive abort
	 * threshold is 0.  In that case, we will probe "forever."
	 */
	if (tcp->tcp_ka_abort_thres != 0 &&
	    idletime > (ka_intrvl + tcp->tcp_ka_abort_thres)) {
		TCPS_BUMP_MIB(tcps, tcpTimKeepaliveDrop);
		(void) tcp_clean_death(tcp, tcp->tcp_client_errno ?
		    tcp->tcp_client_errno : ETIMEDOUT);
		return;
	}

	if (tcp->tcp_snxt == tcp->tcp_suna &&
	    idletime >= ka_intrvl) {
		/* Fake resend of last ACKed byte. */
		mblk_t	*mp1 = allocb(1, BPRI_LO);

		if (mp1 != NULL) {
			*mp1->b_wptr++ = '\0';
			mp = tcp_xmit_mp(tcp, mp1, 1, NULL, NULL,
			    tcp->tcp_suna - 1, B_FALSE, NULL, B_TRUE);
			freeb(mp1);
			/*
			 * if allocation failed, fall through to start the
			 * timer back.
			 */
			if (mp != NULL) {
				tcp_send_data(tcp, mp);
				TCPS_BUMP_MIB(tcps, tcpTimKeepaliveProbe);
				if (tcp->tcp_ka_rinterval) {
					firetime = tcp->tcp_ka_rinterval;
				} else if (tcp->tcp_ka_last_intrvl != 0) {
					int max;
					/*
					 * We should probe again at least
					 * in ka_intrvl, but not more than
					 * tcp_rto_max.
					 */
					max = tcp->tcp_rto_max;
					firetime = MIN(ka_intrvl - 1,
					    tcp->tcp_ka_last_intrvl << 1);
					if (firetime > max)
						firetime = max;
				} else {
					firetime = tcp->tcp_rto;
				}
				tcp->tcp_ka_tid = TCP_TIMER(tcp,
				    tcp_keepalive_timer, firetime);
				tcp->tcp_ka_last_intrvl = firetime;
				return;
			}
		}
	} else {
		tcp->tcp_ka_last_intrvl = 0;
	}

	/* firetime can be negative if (mp1 == NULL || mp == NULL) */
	if ((firetime = ka_intrvl - idletime) < 0) {
		firetime = ka_intrvl;
	}
	tcp->tcp_ka_tid = TCP_TIMER(tcp, tcp_keepalive_timer, firetime);
}

void
tcp_reass_timer(void *arg)
{
	conn_t *connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;

	tcp->tcp_reass_tid = 0;
	if (tcp->tcp_reass_head == NULL)
		return;
	ASSERT(tcp->tcp_reass_tail != NULL);
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		tcp_sack_remove(tcp->tcp_sack_list,
		    TCP_REASS_END(tcp->tcp_reass_tail), &tcp->tcp_num_sack_blk);
	}
	tcp_close_mpp(&tcp->tcp_reass_head);
	tcp->tcp_reass_tail = NULL;
	TCP_STAT(tcp->tcp_tcps, tcp_reass_timeout);
}

/* This function handles the push timeout. */
void
tcp_push_timer(void *arg)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;

	TCP_DBGSTAT(tcp->tcp_tcps, tcp_push_timer_cnt);

	ASSERT(tcp->tcp_listener == NULL);

	ASSERT(!IPCL_IS_NONSTR(connp));

	tcp->tcp_push_tid = 0;

	if (tcp->tcp_rcv_list != NULL &&
	    tcp_rcv_drain(tcp) == TH_ACK_NEEDED)
		tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt, tcp->tcp_rnxt, TH_ACK);
}

/*
 * This function handles delayed ACK timeout.
 */
void
tcp_ack_timer(void *arg)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;
	mblk_t *mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	TCP_DBGSTAT(tcps, tcp_ack_timer_cnt);

	tcp->tcp_ack_tid = 0;

	if (tcp->tcp_fused)
		return;

	/*
	 * Do not send ACK if there is no outstanding unack'ed data.
	 */
	if (tcp->tcp_rnxt == tcp->tcp_rack) {
		return;
	}

	if ((tcp->tcp_rnxt - tcp->tcp_rack) > tcp->tcp_mss) {
		/*
		 * Make sure we don't allow deferred ACKs to result in
		 * timer-based ACKing.  If we have held off an ACK
		 * when there was more than an mss here, and the timer
		 * goes off, we have to worry about the possibility
		 * that the sender isn't doing slow-start, or is out
		 * of step with us for some other reason.  We fall
		 * permanently back in the direction of
		 * ACK-every-other-packet as suggested in RFC 1122.
		 */
		if (tcp->tcp_rack_abs_max > 2)
			tcp->tcp_rack_abs_max--;
		tcp->tcp_rack_cur_max = 2;
	}
	mp = tcp_ack_mp(tcp);

	if (mp != NULL) {
		BUMP_LOCAL(tcp->tcp_obsegs);
		TCPS_BUMP_MIB(tcps, tcpOutAck);
		TCPS_BUMP_MIB(tcps, tcpOutAckDelayed);
		tcp_send_data(tcp, mp);
	}
}

/*
 * Notify IP that we are having trouble with this connection.  IP should
 * make note so it can potentially use a different IRE.
 */
static void
tcp_ip_notify(tcp_t *tcp)
{
	conn_t		*connp = tcp->tcp_connp;
	ire_t		*ire;

	/*
	 * Note: in the case of source routing we want to blow away the
	 * route to the first source route hop.
	 */
	ire = connp->conn_ixa->ixa_ire;
	if (ire != NULL && !(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
		if (ire->ire_ipversion == IPV4_VERSION) {
			/*
			 * As per RFC 1122, we send an RTM_LOSING to inform
			 * routing protocols.
			 */
			ip_rts_change(RTM_LOSING, ire->ire_addr,
			    ire->ire_gateway_addr, ire->ire_mask,
			    connp->conn_laddr_v4,  0, 0, 0,
			    (RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFA),
			    ire->ire_ipst);
		}
		(void) ire_no_good(ire);
	}
}

/*
 * tcp_timer is the timer service routine.  It handles the retransmission,
 * FIN_WAIT_2 flush, and zero window probe timeout events.  It figures out
 * from the state of the tcp instance what kind of action needs to be done
 * at the time it is called.
 */
void
tcp_timer(void *arg)
{
	mblk_t		*mp;
	clock_t		first_threshold;
	clock_t		second_threshold;
	clock_t		ms;
	uint32_t	mss;
	conn_t		*connp = (conn_t *)arg;
	tcp_t		*tcp = connp->conn_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	boolean_t	dont_timeout = B_FALSE;

	tcp->tcp_timer_tid = 0;

	if (tcp->tcp_fused)
		return;

	first_threshold =  tcp->tcp_first_timer_threshold;
	second_threshold = tcp->tcp_second_timer_threshold;
	switch (tcp->tcp_state) {
	case TCPS_IDLE:
	case TCPS_BOUND:
	case TCPS_LISTEN:
		return;
	case TCPS_SYN_RCVD: {
		tcp_t	*listener = tcp->tcp_listener;

		if (tcp->tcp_syn_rcvd_timeout == 0 && (listener != NULL)) {
			/* it's our first timeout */
			tcp->tcp_syn_rcvd_timeout = 1;
			mutex_enter(&listener->tcp_eager_lock);
			listener->tcp_syn_rcvd_timeout++;
			if (!tcp->tcp_dontdrop && !tcp->tcp_closemp_used) {
				/*
				 * Make this eager available for drop if we
				 * need to drop one to accomodate a new
				 * incoming SYN request.
				 */
				MAKE_DROPPABLE(listener, tcp);
			}
			if (!listener->tcp_syn_defense &&
			    (listener->tcp_syn_rcvd_timeout >
			    (tcps->tcps_conn_req_max_q0 >> 2)) &&
			    (tcps->tcps_conn_req_max_q0 > 200)) {
				/* We may be under attack. Put on a defense. */
				listener->tcp_syn_defense = B_TRUE;
				cmn_err(CE_WARN, "High TCP connect timeout "
				    "rate! System (port %d) may be under a "
				    "SYN flood attack!",
				    ntohs(listener->tcp_connp->conn_lport));

				listener->tcp_ip_addr_cache = kmem_zalloc(
				    IP_ADDR_CACHE_SIZE * sizeof (ipaddr_t),
				    KM_NOSLEEP);
			}
			mutex_exit(&listener->tcp_eager_lock);
		} else if (listener != NULL) {
			mutex_enter(&listener->tcp_eager_lock);
			tcp->tcp_syn_rcvd_timeout++;
			if (tcp->tcp_syn_rcvd_timeout > 1 &&
			    !tcp->tcp_closemp_used) {
				/*
				 * This is our second timeout. Put the tcp in
				 * the list of droppable eagers to allow it to
				 * be dropped, if needed. We don't check
				 * whether tcp_dontdrop is set or not to
				 * protect ourselve from a SYN attack where a
				 * remote host can spoof itself as one of the
				 * good IP source and continue to hold
				 * resources too long.
				 */
				MAKE_DROPPABLE(listener, tcp);
			}
			mutex_exit(&listener->tcp_eager_lock);
		}
	}
		/* FALLTHRU */
	case TCPS_SYN_SENT:
		first_threshold =  tcp->tcp_first_ctimer_threshold;
		second_threshold = tcp->tcp_second_ctimer_threshold;

		/*
		 * If an app has set the second_threshold to 0, it means that
		 * we need to retransmit forever, unless this is a passive
		 * open.  We need to set second_threshold back to a normal
		 * value such that later comparison with it still makes
		 * sense.  But we set dont_timeout to B_TRUE so that we will
		 * never time out.
		 */
		if (second_threshold == 0) {
			second_threshold = tcps->tcps_ip_abort_linterval;
			if (tcp->tcp_active_open)
				dont_timeout = B_TRUE;
		}
		break;
	case TCPS_ESTABLISHED:
	case TCPS_CLOSE_WAIT:
		/*
		 * If the end point has not been closed, TCP can retransmit
		 * forever.  But if the end point is closed, the normal
		 * timeout applies.
		 */
		if (second_threshold == 0) {
			second_threshold = tcps->tcps_ip_abort_linterval;
			dont_timeout = B_TRUE;
		}
		/* FALLTHRU */
	case TCPS_FIN_WAIT_1:
	case TCPS_CLOSING:
	case TCPS_LAST_ACK:
		/* If we have data to rexmit */
		if (tcp->tcp_suna != tcp->tcp_snxt) {
			clock_t	time_to_wait;

			TCPS_BUMP_MIB(tcps, tcpTimRetrans);
			if (!tcp->tcp_xmit_head)
				break;
			time_to_wait = ddi_get_lbolt() -
			    (clock_t)tcp->tcp_xmit_head->b_prev;
			time_to_wait = tcp->tcp_rto -
			    TICK_TO_MSEC(time_to_wait);
			/*
			 * If the timer fires too early, 1 clock tick earlier,
			 * restart the timer.
			 */
			if (time_to_wait > msec_per_tick) {
				TCP_STAT(tcps, tcp_timer_fire_early);
				TCP_TIMER_RESTART(tcp, time_to_wait);
				return;
			}
			/*
			 * When we probe zero windows, we force the swnd open.
			 * If our peer acks with a closed window swnd will be
			 * set to zero by tcp_rput(). As long as we are
			 * receiving acks tcp_rput will
			 * reset 'tcp_ms_we_have_waited' so as not to trip the
			 * first and second interval actions.  NOTE: the timer
			 * interval is allowed to continue its exponential
			 * backoff.
			 */
			if (tcp->tcp_swnd == 0 || tcp->tcp_zero_win_probe) {
				if (connp->conn_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_TRACE, "tcp_timer: zero win");
				}
			} else {
				/*
				 * After retransmission, we need to do
				 * slow start.  Set the ssthresh to one
				 * half of current effective window and
				 * cwnd to one MSS.  Also reset
				 * tcp_cwnd_cnt.
				 *
				 * Note that if tcp_ssthresh is reduced because
				 * of ECN, do not reduce it again unless it is
				 * already one window of data away (tcp_cwr
				 * should then be cleared) or this is a
				 * timeout for a retransmitted segment.
				 */
				uint32_t npkt;

				if (!tcp->tcp_cwr || tcp->tcp_rexmit) {
					npkt = ((tcp->tcp_timer_backoff ?
					    tcp->tcp_cwnd_ssthresh :
					    tcp->tcp_snxt -
					    tcp->tcp_suna) >> 1) / tcp->tcp_mss;
					tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) *
					    tcp->tcp_mss;
				}
				tcp->tcp_cwnd = tcp->tcp_mss;
				tcp->tcp_cwnd_cnt = 0;
				if (tcp->tcp_ecn_ok) {
					tcp->tcp_cwr = B_TRUE;
					tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
					tcp->tcp_ecn_cwr_sent = B_FALSE;
				}
			}
			break;
		}
		/*
		 * We have something to send yet we cannot send.  The
		 * reason can be:
		 *
		 * 1. Zero send window: we need to do zero window probe.
		 * 2. Zero cwnd: because of ECN, we need to "clock out
		 * segments.
		 * 3. SWS avoidance: receiver may have shrunk window,
		 * reset our knowledge.
		 *
		 * Note that condition 2 can happen with either 1 or
		 * 3.  But 1 and 3 are exclusive.
		 */
		if (tcp->tcp_unsent != 0) {
			/*
			 * Should not hold the zero-copy messages for too long.
			 */
			if (tcp->tcp_snd_zcopy_aware && !tcp->tcp_xmit_zc_clean)
				tcp->tcp_xmit_head = tcp_zcopy_backoff(tcp,
				    tcp->tcp_xmit_head, B_TRUE);

			if (tcp->tcp_cwnd == 0) {
				/*
				 * Set tcp_cwnd to 1 MSS so that a
				 * new segment can be sent out.  We
				 * are "clocking out" new data when
				 * the network is really congested.
				 */
				ASSERT(tcp->tcp_ecn_ok);
				tcp->tcp_cwnd = tcp->tcp_mss;
			}
			if (tcp->tcp_swnd == 0) {
				/* Extend window for zero window probe */
				tcp->tcp_swnd++;
				tcp->tcp_zero_win_probe = B_TRUE;
				TCPS_BUMP_MIB(tcps, tcpOutWinProbe);
			} else {
				/*
				 * Handle timeout from sender SWS avoidance.
				 * Reset our knowledge of the max send window
				 * since the receiver might have reduced its
				 * receive buffer.  Avoid setting tcp_max_swnd
				 * to one since that will essentially disable
				 * the SWS checks.
				 *
				 * Note that since we don't have a SWS
				 * state variable, if the timeout is set
				 * for ECN but not for SWS, this
				 * code will also be executed.  This is
				 * fine as tcp_max_swnd is updated
				 * constantly and it will not affect
				 * anything.
				 */
				tcp->tcp_max_swnd = MAX(tcp->tcp_swnd, 2);
			}
			tcp_wput_data(tcp, NULL, B_FALSE);
			return;
		}
		/* Is there a FIN that needs to be to re retransmitted? */
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
		    !tcp->tcp_fin_acked)
			break;
		/* Nothing to do, return without restarting timer. */
		TCP_STAT(tcps, tcp_timer_fire_miss);
		return;
	case TCPS_FIN_WAIT_2:
		/*
		 * User closed the TCP endpoint and peer ACK'ed our FIN.
		 * We waited some time for for peer's FIN, but it hasn't
		 * arrived.  We flush the connection now to avoid
		 * case where the peer has rebooted.
		 */
		if (TCP_IS_DETACHED(tcp)) {
			(void) tcp_clean_death(tcp, 0);
		} else {
			TCP_TIMER_RESTART(tcp,
			    tcp->tcp_fin_wait_2_flush_interval);
		}
		return;
	case TCPS_TIME_WAIT:
		(void) tcp_clean_death(tcp, 0);
		return;
	default:
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE|SL_ERROR,
			    "tcp_timer: strange state (%d) %s",
			    tcp->tcp_state, tcp_display(tcp, NULL,
			    DISP_PORT_ONLY));
		}
		return;
	}

	/*
	 * If the system is under memory pressure or the max number of
	 * connections have been established for the listener, be more
	 * aggressive in aborting connections.
	 */
	if (tcps->tcps_reclaim || (tcp->tcp_listen_cnt != NULL &&
	    tcp->tcp_listen_cnt->tlc_cnt > tcp->tcp_listen_cnt->tlc_max)) {
		second_threshold = tcp_early_abort * SECONDS;

		/* We will ignore the never timeout promise in this case... */
		dont_timeout = B_FALSE;
	}

	ASSERT(second_threshold != 0);

	if ((ms = tcp->tcp_ms_we_have_waited) > second_threshold) {
		/*
		 * Should not hold the zero-copy messages for too long.
		 */
		if (tcp->tcp_snd_zcopy_aware && !tcp->tcp_xmit_zc_clean)
			tcp->tcp_xmit_head = tcp_zcopy_backoff(tcp,
			    tcp->tcp_xmit_head, B_TRUE);

		if (dont_timeout) {
			/*
			 * Reset tcp_ms_we_have_waited to avoid overflow since
			 * we are going to retransmit forever.
			 */
			tcp->tcp_ms_we_have_waited = second_threshold;
			goto timer_rexmit;
		}

		/*
		 * For zero window probe, we need to send indefinitely,
		 * unless we have not heard from the other side for some
		 * time...
		 */
		if ((tcp->tcp_zero_win_probe == 0) ||
		    (TICK_TO_MSEC(ddi_get_lbolt() - tcp->tcp_last_recv_time) >
		    second_threshold)) {
			TCPS_BUMP_MIB(tcps, tcpTimRetransDrop);
			/*
			 * If TCP is in SYN_RCVD state, send back a
			 * RST|ACK as BSD does.  Note that tcp_zero_win_probe
			 * should be zero in TCPS_SYN_RCVD state.
			 */
			if (tcp->tcp_state == TCPS_SYN_RCVD) {
				tcp_xmit_ctl("tcp_timer: RST sent on timeout "
				    "in SYN_RCVD",
				    tcp, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_RST | TH_ACK);
			}
			(void) tcp_clean_death(tcp,
			    tcp->tcp_client_errno ?
			    tcp->tcp_client_errno : ETIMEDOUT);
			return;
		} else {
			/*
			 * If the system is under memory pressure, we also
			 * abort connection in zero window probing.
			 */
			if (tcps->tcps_reclaim) {
				(void) tcp_clean_death(tcp,
				    tcp->tcp_client_errno ?
				    tcp->tcp_client_errno : ETIMEDOUT);
				TCP_STAT(tcps, tcp_zwin_mem_drop);
				return;
			}
			/*
			 * Set tcp_ms_we_have_waited to second_threshold
			 * so that in next timeout, we will do the above
			 * check (ddi_get_lbolt() - tcp_last_recv_time).
			 * This is also to avoid overflow.
			 *
			 * We don't need to decrement tcp_timer_backoff
			 * to avoid overflow because it will be decremented
			 * later if new timeout value is greater than
			 * tcp_rto_max.  In the case when tcp_rto_max is
			 * greater than second_threshold, it means that we
			 * will wait longer than second_threshold to send
			 * the next
			 * window probe.
			 */
			tcp->tcp_ms_we_have_waited = second_threshold;
		}
	} else if (ms > first_threshold) {
		/*
		 * Should not hold the zero-copy messages for too long.
		 */
		if (tcp->tcp_snd_zcopy_aware && !tcp->tcp_xmit_zc_clean)
			tcp->tcp_xmit_head = tcp_zcopy_backoff(tcp,
			    tcp->tcp_xmit_head, B_TRUE);

		/*
		 * We have been retransmitting for too long...  The RTT
		 * we calculated is probably incorrect.  Reinitialize it.
		 * Need to compensate for 0 tcp_rtt_sa.  Reset
		 * tcp_rtt_update so that we won't accidentally cache a
		 * bad value.  But only do this if this is not a zero
		 * window probe.
		 */
		if (tcp->tcp_rtt_sa != 0 && tcp->tcp_zero_win_probe == 0) {
			tcp->tcp_rtt_sd += (tcp->tcp_rtt_sa >> 3) +
			    (tcp->tcp_rtt_sa >> 5);
			tcp->tcp_rtt_sa = 0;
			tcp_ip_notify(tcp);
			tcp->tcp_rtt_update = 0;
		}
	}

timer_rexmit:
	tcp->tcp_timer_backoff++;
	if ((ms = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
	    tcps->tcps_rexmit_interval_extra + (tcp->tcp_rtt_sa >> 5)) <
	    tcp->tcp_rto_min) {
		/*
		 * This means the original RTO is tcp_rexmit_interval_min.
		 * So we will use tcp_rexmit_interval_min as the RTO value
		 * and do the backoff.
		 */
		ms = tcp->tcp_rto_min << tcp->tcp_timer_backoff;
	} else {
		ms <<= tcp->tcp_timer_backoff;
	}
	if (ms > tcp->tcp_rto_max) {
		ms = tcp->tcp_rto_max;
		/*
		 * ms is at max, decrement tcp_timer_backoff to avoid
		 * overflow.
		 */
		tcp->tcp_timer_backoff--;
	}
	tcp->tcp_ms_we_have_waited += ms;
	if (tcp->tcp_zero_win_probe == 0) {
		tcp->tcp_rto = ms;
	}
	TCP_TIMER_RESTART(tcp, ms);
	/*
	 * This is after a timeout and tcp_rto is backed off.  Set
	 * tcp_set_timer to 1 so that next time RTO is updated, we will
	 * restart the timer with a correct value.
	 */
	tcp->tcp_set_timer = 1;
	mss = tcp->tcp_snxt - tcp->tcp_suna;
	if (mss > tcp->tcp_mss)
		mss = tcp->tcp_mss;
	if (mss > tcp->tcp_swnd && tcp->tcp_swnd != 0)
		mss = tcp->tcp_swnd;

	if ((mp = tcp->tcp_xmit_head) != NULL)
		mp->b_prev = (mblk_t *)ddi_get_lbolt();
	mp = tcp_xmit_mp(tcp, mp, mss, NULL, NULL, tcp->tcp_suna, B_TRUE, &mss,
	    B_TRUE);

	/*
	 * When slow start after retransmission begins, start with
	 * this seq no.  tcp_rexmit_max marks the end of special slow
	 * start phase.
	 */
	tcp->tcp_rexmit_nxt = tcp->tcp_suna;
	if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
	    (tcp->tcp_unsent == 0)) {
		tcp->tcp_rexmit_max = tcp->tcp_fss;
	} else {
		tcp->tcp_rexmit_max = tcp->tcp_snxt;
	}
	tcp->tcp_rexmit = B_TRUE;
	tcp->tcp_dupack_cnt = 0;

	/*
	 * Remove all rexmit SACK blk to start from fresh.
	 */
	if (tcp->tcp_snd_sack_ok)
		TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list, tcp);
	if (mp == NULL) {
		return;
	}

	tcp->tcp_csuna = tcp->tcp_snxt;
	TCPS_BUMP_MIB(tcps, tcpRetransSegs);
	TCPS_UPDATE_MIB(tcps, tcpRetransBytes, mss);
	tcp_send_data(tcp, mp);

}

/*
 * Handle lingering timeouts. This function is called when the SO_LINGER timeout
 * expires.
 */
void
tcp_close_linger_timeout(void *arg)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t 	*tcp = connp->conn_tcp;

	tcp->tcp_client_errno = ETIMEDOUT;
	tcp_stop_lingering(tcp);
}

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
 * Copyright (c) 2012, Joyent Inc. All rights reserved.
 */

/*
 * This file contains functions related to TCP time wait processing.  Also
 * refer to the time wait handling comments in tcp_impl.h.
 */

#include <sys/types.h>
#include <sys/strsun.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#include <sys/callo.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/tcp_cluster.h>

static void	tcp_timewait_close(void *, mblk_t *, void *, ip_recv_attr_t *);

/*
 * TCP_TIME_WAIT_DELAY governs how often the time_wait_collector runs.
 * Running it every 5 seconds seems to give the best results.
 */
#define	TCP_TIME_WAIT_DELAY ((hrtime_t)5 * NANOSEC)

/*
 * Remove a connection from the list of detached TIME_WAIT connections.
 * It returns B_FALSE if it can't remove the connection from the list
 * as the connection has already been removed from the list due to an
 * earlier call to tcp_time_wait_remove(); otherwise it returns B_TRUE.
 */
boolean_t
tcp_time_wait_remove(tcp_t *tcp, tcp_squeue_priv_t *tcp_time_wait)
{
	boolean_t	locked = B_FALSE;

	if (tcp_time_wait == NULL) {
		tcp_time_wait = *((tcp_squeue_priv_t **)
		    squeue_getprivate(tcp->tcp_connp->conn_sqp, SQPRIVATE_TCP));
		mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
		locked = B_TRUE;
	} else {
		ASSERT(MUTEX_HELD(&tcp_time_wait->tcp_time_wait_lock));
	}

	/* 0 means that the tcp_t has not been added to the time wait list. */
	if (tcp->tcp_time_wait_expire == 0) {
		ASSERT(tcp->tcp_time_wait_next == NULL);
		ASSERT(tcp->tcp_time_wait_prev == NULL);
		if (locked)
			mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
		return (B_FALSE);
	}
	ASSERT(TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_state == TCPS_TIME_WAIT);

	if (tcp == tcp_time_wait->tcp_time_wait_head) {
		ASSERT(tcp->tcp_time_wait_prev == NULL);
		tcp_time_wait->tcp_time_wait_head = tcp->tcp_time_wait_next;
		if (tcp_time_wait->tcp_time_wait_head != NULL) {
			tcp_time_wait->tcp_time_wait_head->tcp_time_wait_prev =
			    NULL;
		} else {
			tcp_time_wait->tcp_time_wait_tail = NULL;
		}
	} else if (tcp == tcp_time_wait->tcp_time_wait_tail) {
		ASSERT(tcp->tcp_time_wait_next == NULL);
		tcp_time_wait->tcp_time_wait_tail = tcp->tcp_time_wait_prev;
		ASSERT(tcp_time_wait->tcp_time_wait_tail != NULL);
		tcp_time_wait->tcp_time_wait_tail->tcp_time_wait_next = NULL;
	} else {
		ASSERT(tcp->tcp_time_wait_prev->tcp_time_wait_next == tcp);
		ASSERT(tcp->tcp_time_wait_next->tcp_time_wait_prev == tcp);
		tcp->tcp_time_wait_prev->tcp_time_wait_next =
		    tcp->tcp_time_wait_next;
		tcp->tcp_time_wait_next->tcp_time_wait_prev =
		    tcp->tcp_time_wait_prev;
	}
	tcp->tcp_time_wait_next = NULL;
	tcp->tcp_time_wait_prev = NULL;
	tcp->tcp_time_wait_expire = 0;

	if (locked)
		mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
	return (B_TRUE);
}

/* Constants used for fast checking of a localhost address */
#if defined(_BIG_ENDIAN)
#define	IPv4_LOCALHOST	0x7f000000U
#define	IPv4_LH_MASK	0xffffff00U
#else
#define	IPv4_LOCALHOST	0x0000007fU
#define	IPv4_LH_MASK	0x00ffffffU
#endif

#define	IS_LOCAL_HOST(x)	( \
	((x)->tcp_connp->conn_ipversion == IPV4_VERSION && \
	((x)->tcp_connp->conn_laddr_v4 & IPv4_LH_MASK) == IPv4_LOCALHOST) || \
	((x)->tcp_connp->conn_ipversion == IPV6_VERSION && \
	IN6_IS_ADDR_LOOPBACK(&(x)->tcp_connp->conn_laddr_v6)))

/*
 * Add a connection to the list of detached TIME_WAIT connections
 * and set its time to expire.
 */
void
tcp_time_wait_append(tcp_t *tcp)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	squeue_t	*sqp = tcp->tcp_connp->conn_sqp;
	tcp_squeue_priv_t *tcp_time_wait =
	    *((tcp_squeue_priv_t **)squeue_getprivate(sqp, SQPRIVATE_TCP));
	hrtime_t firetime = 0;

	tcp_timers_stop(tcp);

	/* Freed above */
	ASSERT(tcp->tcp_timer_tid == 0);
	ASSERT(tcp->tcp_ack_tid == 0);

	/* must have happened at the time of detaching the tcp */
	ASSERT(tcp->tcp_ptpahn == NULL);
	ASSERT(tcp->tcp_flow_stopped == 0);
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == 0);
	ASSERT(tcp->tcp_listener == NULL);

	tcp->tcp_time_wait_expire = ddi_get_lbolt64();
	if (IS_LOCAL_HOST(tcp)) {
		/*
		 * This is the fastpath for handling localhost connections.
		 * Since we don't have to worry about packets on the localhost
		 * showing up after a long network delay, we want to expire
		 * these quickly so the port range on the localhost doesn't
		 * get starved by short-running, local apps.
		 *
		 * Leave tcp_time_wait_expire at the current time. This
		 * essentially means the connection is expired now and it will
		 * clean up the next time tcp_time_wait_collector runs.  We set
		 * firetime to use a short delay so that if we have to start a
		 * tcp_time_wait_collector thread below, it runs soon instead
		 * of after a delay of time_wait_interval. firetime being set
		 * to a non-0 value is also our indicator that we should add
		 * this connection to the head of the time wait list (since we
		 * are already expired) so that its sure to get cleaned up on
		 * the next run of tcp_time_wait_collector (which expects the
		 * entries to appear in time-order and stops when it hits the
		 * first non-expired entry).
		 */
		firetime = TCP_TIME_WAIT_DELAY;
	} else {
		/*
		 * Since tcp_time_wait_expire is lbolt64, it should not wrap
		 * around in practice.  Hence it cannot be 0.  Note that zero
		 * means that the tcp_t is not in the TIME_WAIT list.
		 */
		tcp->tcp_time_wait_expire += MSEC_TO_TICK(
		    tcps->tcps_time_wait_interval);
	}

	ASSERT(TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_state == TCPS_TIME_WAIT);
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	TCP_DBGSTAT(tcps, tcp_time_wait);

	mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
	if (tcp_time_wait->tcp_time_wait_head == NULL) {
		ASSERT(tcp_time_wait->tcp_time_wait_tail == NULL);
		tcp_time_wait->tcp_time_wait_head = tcp;

		/*
		 * Even if the list was empty before, there may be a timer
		 * running since a tcp_t can be removed from the list
		 * in other places, such as tcp_clean_death().  So check if
		 * a timer is needed.
		 */
		if (tcp_time_wait->tcp_time_wait_tid == 0) {
			if (firetime == 0)
				firetime = (hrtime_t)
				    (tcps->tcps_time_wait_interval + 1) *
				    MICROSEC;

			tcp_time_wait->tcp_time_wait_tid =
			    timeout_generic(CALLOUT_NORMAL,
			    tcp_time_wait_collector, sqp, firetime,
			    CALLOUT_TCP_RESOLUTION, CALLOUT_FLAG_ROUNDUP);
		}
		tcp_time_wait->tcp_time_wait_tail = tcp;
	} else {
		/*
		 * The list is not empty, so a timer must be running.  If not,
		 * tcp_time_wait_collector() must be running on this
		 * tcp_time_wait list at the same time.
		 */
		ASSERT(tcp_time_wait->tcp_time_wait_tid != 0 ||
		    tcp_time_wait->tcp_time_wait_running);
		ASSERT(tcp_time_wait->tcp_time_wait_tail != NULL);
		ASSERT(tcp_time_wait->tcp_time_wait_tail->tcp_state ==
		    TCPS_TIME_WAIT);

		if (firetime == 0) {
			/* add at end */
			tcp_time_wait->tcp_time_wait_tail->tcp_time_wait_next =
			    tcp;
			tcp->tcp_time_wait_prev =
			    tcp_time_wait->tcp_time_wait_tail;
			tcp_time_wait->tcp_time_wait_tail = tcp;
		} else {
			/* add at head */
			tcp->tcp_time_wait_next =
			    tcp_time_wait->tcp_time_wait_head;
			tcp_time_wait->tcp_time_wait_head->tcp_time_wait_prev =
			    tcp;
			tcp_time_wait->tcp_time_wait_head = tcp;
		}
	}
	mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
}

/*
 * Wrapper to call tcp_close_detached() via squeue to clean up TIME-WAIT
 * tcp_t.  Used in tcp_time_wait_collector().
 */
/* ARGSUSED */
static void
tcp_timewait_close(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;

	ASSERT(tcp != NULL);
	if (tcp->tcp_state == TCPS_CLOSED) {
		return;
	}

	ASSERT((connp->conn_family == AF_INET &&
	    connp->conn_ipversion == IPV4_VERSION) ||
	    (connp->conn_family == AF_INET6 &&
	    (connp->conn_ipversion == IPV4_VERSION ||
	    connp->conn_ipversion == IPV6_VERSION)));
	ASSERT(!tcp->tcp_listener);

	ASSERT(TCP_IS_DETACHED(tcp));

	/*
	 * Because they have no upstream client to rebind or tcp_close()
	 * them later, we axe the connection here and now.
	 */
	tcp_close_detached(tcp);
}

/*
 * Blows away all tcps whose TIME_WAIT has expired. List traversal
 * is done forwards from the head.
 * This walks all stack instances since
 * tcp_time_wait remains global across all stacks.
 */
/* ARGSUSED */
void
tcp_time_wait_collector(void *arg)
{
	tcp_t *tcp;
	int64_t now;
	mblk_t *mp;
	conn_t *connp;
	kmutex_t *lock;
	boolean_t removed;
	extern void (*cl_inet_disconnect)(netstackid_t, uint8_t, sa_family_t,
	    uint8_t *, in_port_t, uint8_t *, in_port_t, void *);

	squeue_t *sqp = (squeue_t *)arg;
	tcp_squeue_priv_t *tcp_time_wait =
	    *((tcp_squeue_priv_t **)squeue_getprivate(sqp, SQPRIVATE_TCP));

	mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
	tcp_time_wait->tcp_time_wait_tid = 0;
#ifdef DEBUG
	tcp_time_wait->tcp_time_wait_running = B_TRUE;
#endif

	if (tcp_time_wait->tcp_free_list != NULL &&
	    tcp_time_wait->tcp_free_list->tcp_in_free_list == B_TRUE) {
		TCP_G_STAT(tcp_freelist_cleanup);
		while ((tcp = tcp_time_wait->tcp_free_list) != NULL) {
			tcp_time_wait->tcp_free_list = tcp->tcp_time_wait_next;
			tcp->tcp_time_wait_next = NULL;
			tcp_time_wait->tcp_free_list_cnt--;
			ASSERT(tcp->tcp_tcps == NULL);
			CONN_DEC_REF(tcp->tcp_connp);
		}
		ASSERT(tcp_time_wait->tcp_free_list_cnt == 0);
	}

	/*
	 * In order to reap time waits reliably, we should use a
	 * source of time that is not adjustable by the user -- hence
	 * the call to ddi_get_lbolt64().
	 */
	now = ddi_get_lbolt64();
	while ((tcp = tcp_time_wait->tcp_time_wait_head) != NULL) {
		/*
		 * lbolt64 should not wrap around in practice...  So we can
		 * do a direct comparison.
		 */
		if (now < tcp->tcp_time_wait_expire)
			break;

		removed = tcp_time_wait_remove(tcp, tcp_time_wait);
		ASSERT(removed);

		connp = tcp->tcp_connp;
		ASSERT(connp->conn_fanout != NULL);
		lock = &connp->conn_fanout->connf_lock;
		/*
		 * This is essentially a TW reclaim fast path optimization for
		 * performance where the timewait collector checks under the
		 * fanout lock (so that no one else can get access to the
		 * conn_t) that the refcnt is 2 i.e. one for TCP and one for
		 * the classifier hash list. If ref count is indeed 2, we can
		 * just remove the conn under the fanout lock and avoid
		 * cleaning up the conn under the squeue, provided that
		 * clustering callbacks are not enabled. If clustering is
		 * enabled, we need to make the clustering callback before
		 * setting the CONDEMNED flag and after dropping all locks and
		 * so we forego this optimization and fall back to the slow
		 * path. Also please see the comments in tcp_closei_local
		 * regarding the refcnt logic.
		 *
		 * Since we are holding the tcp_time_wait_lock, its better
		 * not to block on the fanout_lock because other connections
		 * can't add themselves to time_wait list. So we do a
		 * tryenter instead of mutex_enter.
		 */
		if (mutex_tryenter(lock)) {
			mutex_enter(&connp->conn_lock);
			if ((connp->conn_ref == 2) &&
			    (cl_inet_disconnect == NULL)) {
				ipcl_hash_remove_locked(connp,
				    connp->conn_fanout);
				/*
				 * Set the CONDEMNED flag now itself so that
				 * the refcnt cannot increase due to any
				 * walker.
				 */
				connp->conn_state_flags |= CONN_CONDEMNED;
				mutex_exit(lock);
				mutex_exit(&connp->conn_lock);
				if (tcp_time_wait->tcp_free_list_cnt <
				    tcp_free_list_max_cnt) {
					/* Add to head of tcp_free_list */
					mutex_exit(
					    &tcp_time_wait->tcp_time_wait_lock);
					tcp_cleanup(tcp);
					ASSERT(connp->conn_latch == NULL);
					ASSERT(connp->conn_policy == NULL);
					ASSERT(tcp->tcp_tcps == NULL);
					ASSERT(connp->conn_netstack == NULL);

					mutex_enter(
					    &tcp_time_wait->tcp_time_wait_lock);
					tcp->tcp_time_wait_next =
					    tcp_time_wait->tcp_free_list;
					tcp_time_wait->tcp_free_list = tcp;
					tcp_time_wait->tcp_free_list_cnt++;
					continue;
				} else {
					/* Do not add to tcp_free_list */
					mutex_exit(
					    &tcp_time_wait->tcp_time_wait_lock);
					tcp_bind_hash_remove(tcp);
					ixa_cleanup(tcp->tcp_connp->conn_ixa);
					tcp_ipsec_cleanup(tcp);
					CONN_DEC_REF(tcp->tcp_connp);
				}
			} else {
				CONN_INC_REF_LOCKED(connp);
				mutex_exit(lock);
				mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
				mutex_exit(&connp->conn_lock);
				/*
				 * We can reuse the closemp here since conn has
				 * detached (otherwise we wouldn't even be in
				 * time_wait list). tcp_closemp_used can safely
				 * be changed without taking a lock as no other
				 * thread can concurrently access it at this
				 * point in the connection lifecycle.
				 */

				if (tcp->tcp_closemp.b_prev == NULL)
					tcp->tcp_closemp_used = B_TRUE;
				else
					cmn_err(CE_PANIC,
					    "tcp_timewait_collector: "
					    "concurrent use of tcp_closemp: "
					    "connp %p tcp %p\n", (void *)connp,
					    (void *)tcp);

				TCP_DEBUG_GETPCSTACK(tcp->tcmp_stk, 15);
				mp = &tcp->tcp_closemp;
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
				    tcp_timewait_close, connp, NULL,
				    SQ_FILL, SQTAG_TCP_TIMEWAIT);
			}
		} else {
			mutex_enter(&connp->conn_lock);
			CONN_INC_REF_LOCKED(connp);
			mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
			mutex_exit(&connp->conn_lock);
			/*
			 * We can reuse the closemp here since conn has
			 * detached (otherwise we wouldn't even be in
			 * time_wait list). tcp_closemp_used can safely
			 * be changed without taking a lock as no other
			 * thread can concurrently access it at this
			 * point in the connection lifecycle.
			 */

			if (tcp->tcp_closemp.b_prev == NULL)
				tcp->tcp_closemp_used = B_TRUE;
			else
				cmn_err(CE_PANIC, "tcp_timewait_collector: "
				    "concurrent use of tcp_closemp: "
				    "connp %p tcp %p\n", (void *)connp,
				    (void *)tcp);

			TCP_DEBUG_GETPCSTACK(tcp->tcmp_stk, 15);
			mp = &tcp->tcp_closemp;
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
			    tcp_timewait_close, connp, NULL,
			    SQ_FILL, SQTAG_TCP_TIMEWAIT);
		}
		mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
	}

	if (tcp_time_wait->tcp_free_list != NULL)
		tcp_time_wait->tcp_free_list->tcp_in_free_list = B_TRUE;

	/*
	 * If the time wait list is not empty and there is no timer running,
	 * restart it.
	 */
	if ((tcp = tcp_time_wait->tcp_time_wait_head) != NULL &&
	    tcp_time_wait->tcp_time_wait_tid == 0) {
		hrtime_t firetime;

		/* shouldn't be necessary, but just in case */
		if (tcp->tcp_time_wait_expire < now)
			tcp->tcp_time_wait_expire = now;

		firetime = TICK_TO_NSEC(tcp->tcp_time_wait_expire - now);
		/* This ensures that we won't wake up too often. */
		firetime = MAX(TCP_TIME_WAIT_DELAY, firetime);
		tcp_time_wait->tcp_time_wait_tid =
		    timeout_generic(CALLOUT_NORMAL, tcp_time_wait_collector,
		    sqp, firetime, CALLOUT_TCP_RESOLUTION,
		    CALLOUT_FLAG_ROUNDUP);
	}
#ifdef DEBUG
	tcp_time_wait->tcp_time_wait_running = B_FALSE;
#endif
	mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
}

/*
 * tcp_time_wait_processing() handles processing of incoming packets when
 * the tcp_t is in the TIME_WAIT state.
 *
 * A TIME_WAIT tcp_t that has an associated open TCP end point (not in
 * detached state) is never put on the time wait list.
 */
void
tcp_time_wait_processing(tcp_t *tcp, mblk_t *mp, uint32_t seg_seq,
    uint32_t seg_ack, int seg_len, tcpha_t *tcpha, ip_recv_attr_t *ira)
{
	int32_t		bytes_acked;
	int32_t		gap;
	int32_t		rgap;
	tcp_opt_t	tcpopt;
	uint_t		flags;
	uint32_t	new_swnd = 0;
	conn_t		*nconnp;
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	BUMP_LOCAL(tcp->tcp_ibsegs);
	DTRACE_PROBE2(tcp__trace__recv, mblk_t *, mp, tcp_t *, tcp);

	flags = (unsigned int)tcpha->tha_flags & 0xFF;
	new_swnd = ntohs(tcpha->tha_win) <<
	    ((tcpha->tha_flags & TH_SYN) ? 0 : tcp->tcp_snd_ws);
	if (tcp->tcp_snd_ts_ok) {
		if (!tcp_paws_check(tcp, tcpha, &tcpopt)) {
			tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
			    tcp->tcp_rnxt, TH_ACK);
			goto done;
		}
	}
	gap = seg_seq - tcp->tcp_rnxt;
	rgap = tcp->tcp_rwnd - (gap + seg_len);
	if (gap < 0) {
		TCPS_BUMP_MIB(tcps, tcpInDataDupSegs);
		TCPS_UPDATE_MIB(tcps, tcpInDataDupBytes,
		    (seg_len > -gap ? -gap : seg_len));
		seg_len += gap;
		if (seg_len < 0 || (seg_len == 0 && !(flags & TH_FIN))) {
			if (flags & TH_RST) {
				goto done;
			}
			if ((flags & TH_FIN) && seg_len == -1) {
				/*
				 * When TCP receives a duplicate FIN in
				 * TIME_WAIT state, restart the 2 MSL timer.
				 * See page 73 in RFC 793. Make sure this TCP
				 * is already on the TIME_WAIT list. If not,
				 * just restart the timer.
				 */
				if (TCP_IS_DETACHED(tcp)) {
					if (tcp_time_wait_remove(tcp, NULL) ==
					    B_TRUE) {
						tcp_time_wait_append(tcp);
						TCP_DBGSTAT(tcps,
						    tcp_rput_time_wait);
					}
				} else {
					ASSERT(tcp != NULL);
					TCP_TIMER_RESTART(tcp,
					    tcps->tcps_time_wait_interval);
				}
				tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_ACK);
				goto done;
			}
			flags |=  TH_ACK_NEEDED;
			seg_len = 0;
			goto process_ack;
		}

		/* Fix seg_seq, and chew the gap off the front. */
		seg_seq = tcp->tcp_rnxt;
	}

	if ((flags & TH_SYN) && gap > 0 && rgap < 0) {
		/*
		 * Make sure that when we accept the connection, pick
		 * an ISS greater than (tcp_snxt + tcp_iss_incr/2) for the
		 * old connection.
		 *
		 * The next ISS generated is equal to tcp_iss_incr_extra
		 * + tcp_iss_incr/2 + other components depending on the
		 * value of tcp_strong_iss.  We pre-calculate the new
		 * ISS here and compare with tcp_snxt to determine if
		 * we need to make adjustment to tcp_iss_incr_extra.
		 *
		 * The above calculation is ugly and is a
		 * waste of CPU cycles...
		 */
		uint32_t new_iss = tcps->tcps_iss_incr_extra;
		int32_t adj;
		ip_stack_t *ipst = tcps->tcps_netstack->netstack_ip;

		switch (tcps->tcps_strong_iss) {
		case 2: {
			/* Add time and MD5 components. */
			uint32_t answer[4];
			struct {
				uint32_t ports;
				in6_addr_t src;
				in6_addr_t dst;
			} arg;
			MD5_CTX context;

			mutex_enter(&tcps->tcps_iss_key_lock);
			context = tcps->tcps_iss_key;
			mutex_exit(&tcps->tcps_iss_key_lock);
			arg.ports = connp->conn_ports;
			/* We use MAPPED addresses in tcp_iss_init */
			arg.src = connp->conn_laddr_v6;
			arg.dst = connp->conn_faddr_v6;
			MD5Update(&context, (uchar_t *)&arg,
			    sizeof (arg));
			MD5Final((uchar_t *)answer, &context);
			answer[0] ^= answer[1] ^ answer[2] ^ answer[3];
			new_iss += (gethrtime() >> ISS_NSEC_SHT) + answer[0];
			break;
		}
		case 1:
			/* Add time component and min random (i.e. 1). */
			new_iss += (gethrtime() >> ISS_NSEC_SHT) + 1;
			break;
		default:
			/* Add only time component. */
			new_iss += (uint32_t)gethrestime_sec() *
			    tcps->tcps_iss_incr;
			break;
		}
		if ((adj = (int32_t)(tcp->tcp_snxt - new_iss)) > 0) {
			/*
			 * New ISS not guaranteed to be tcp_iss_incr/2
			 * ahead of the current tcp_snxt, so add the
			 * difference to tcp_iss_incr_extra.
			 */
			tcps->tcps_iss_incr_extra += adj;
		}
		/*
		 * If tcp_clean_death() can not perform the task now,
		 * drop the SYN packet and let the other side re-xmit.
		 * Otherwise pass the SYN packet back in, since the
		 * old tcp state has been cleaned up or freed.
		 */
		if (tcp_clean_death(tcp, 0) == -1)
			goto done;
		nconnp = ipcl_classify(mp, ira, ipst);
		if (nconnp != NULL) {
			TCP_STAT(tcps, tcp_time_wait_syn_success);
			/* Drops ref on nconnp */
			tcp_reinput(nconnp, mp, ira, ipst);
			return;
		}
		goto done;
	}

	/*
	 * rgap is the amount of stuff received out of window.  A negative
	 * value is the amount out of window.
	 */
	if (rgap < 0) {
		TCPS_BUMP_MIB(tcps, tcpInDataPastWinSegs);
		TCPS_UPDATE_MIB(tcps, tcpInDataPastWinBytes, -rgap);
		/* Fix seg_len and make sure there is something left. */
		seg_len += rgap;
		if (seg_len <= 0) {
			if (flags & TH_RST) {
				goto done;
			}
			flags |=  TH_ACK_NEEDED;
			seg_len = 0;
			goto process_ack;
		}
	}
	/*
	 * Check whether we can update tcp_ts_recent.  This test is
	 * NOT the one in RFC 1323 3.4.  It is from Braden, 1993, "TCP
	 * Extensions for High Performance: An Update", Internet Draft.
	 */
	if (tcp->tcp_snd_ts_ok &&
	    TSTMP_GEQ(tcpopt.tcp_opt_ts_val, tcp->tcp_ts_recent) &&
	    SEQ_LEQ(seg_seq, tcp->tcp_rack)) {
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = ddi_get_lbolt64();
	}

	if (seg_seq != tcp->tcp_rnxt && seg_len > 0) {
		/* Always ack out of order packets */
		flags |= TH_ACK_NEEDED;
		seg_len = 0;
	} else if (seg_len > 0) {
		TCPS_BUMP_MIB(tcps, tcpInClosed);
		TCPS_BUMP_MIB(tcps, tcpInDataInorderSegs);
		TCPS_UPDATE_MIB(tcps, tcpInDataInorderBytes, seg_len);
	}
	if (flags & TH_RST) {
		(void) tcp_clean_death(tcp, 0);
		goto done;
	}
	if (flags & TH_SYN) {
		tcp_xmit_ctl("TH_SYN", tcp, seg_ack, seg_seq + 1,
		    TH_RST|TH_ACK);
		/*
		 * Do not delete the TCP structure if it is in
		 * TIME_WAIT state.  Refer to RFC 1122, 4.2.2.13.
		 */
		goto done;
	}
process_ack:
	if (flags & TH_ACK) {
		bytes_acked = (int)(seg_ack - tcp->tcp_suna);
		if (bytes_acked <= 0) {
			if (bytes_acked == 0 && seg_len == 0 &&
			    new_swnd == tcp->tcp_swnd)
				TCPS_BUMP_MIB(tcps, tcpInDupAck);
		} else {
			/* Acks something not sent */
			flags |= TH_ACK_NEEDED;
		}
	}
	if (flags & TH_ACK_NEEDED) {
		/*
		 * Time to send an ack for some reason.
		 */
		tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
		    tcp->tcp_rnxt, TH_ACK);
	}
done:
	freemsg(mp);
}

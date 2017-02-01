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
 * Copyright 2016 Joyent, Inc.
 * Copyright (c) 2016 by Delphix. All rights reserved.
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

static void tcp_time_wait_purge(tcp_t *, tcp_squeue_priv_t *);

#define	TW_BUCKET(t)					\
	(((t) / MSEC_TO_TICK(TCP_TIME_WAIT_DELAY)) % TCP_TIME_WAIT_BUCKETS)

#define	TW_BUCKET_NEXT(b)	(((b) + 1) % TCP_TIME_WAIT_BUCKETS)


/*
 * Remove a connection from the list of detached TIME_WAIT connections.
 * It returns B_FALSE if it can't remove the connection from the list
 * as the connection has already been removed from the list due to an
 * earlier call to tcp_time_wait_remove(); otherwise it returns B_TRUE.
 */
boolean_t
tcp_time_wait_remove(tcp_t *tcp, tcp_squeue_priv_t *tsp)
{
	boolean_t	locked = B_FALSE;

	if (tsp == NULL) {
		tsp = *((tcp_squeue_priv_t **)
		    squeue_getprivate(tcp->tcp_connp->conn_sqp, SQPRIVATE_TCP));
		mutex_enter(&tsp->tcp_time_wait_lock);
		locked = B_TRUE;
	} else {
		ASSERT(MUTEX_HELD(&tsp->tcp_time_wait_lock));
	}

	/* 0 means that the tcp_t has not been added to the time wait list. */
	if (tcp->tcp_time_wait_expire == 0) {
		ASSERT(tcp->tcp_time_wait_next == NULL);
		ASSERT(tcp->tcp_time_wait_prev == NULL);
		if (locked)
			mutex_exit(&tsp->tcp_time_wait_lock);
		return (B_FALSE);
	}
	ASSERT(TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_state == TCPS_TIME_WAIT);
	ASSERT(tsp->tcp_time_wait_cnt > 0);

	if (tcp->tcp_time_wait_next != NULL) {
		tcp->tcp_time_wait_next->tcp_time_wait_prev =
		    tcp->tcp_time_wait_prev;
	}
	if (tcp->tcp_time_wait_prev != NULL) {
		tcp->tcp_time_wait_prev->tcp_time_wait_next =
		    tcp->tcp_time_wait_next;
	} else {
		unsigned int bucket;

		bucket = TW_BUCKET(tcp->tcp_time_wait_expire);
		ASSERT(tsp->tcp_time_wait_bucket[bucket] == tcp);
		tsp->tcp_time_wait_bucket[bucket] = tcp->tcp_time_wait_next;
	}
	tcp->tcp_time_wait_next = NULL;
	tcp->tcp_time_wait_prev = NULL;
	tcp->tcp_time_wait_expire = 0;
	tsp->tcp_time_wait_cnt--;

	if (locked)
		mutex_exit(&tsp->tcp_time_wait_lock);
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
	tcp_squeue_priv_t *tsp =
	    *((tcp_squeue_priv_t **)squeue_getprivate(sqp, SQPRIVATE_TCP));
	int64_t		now, schedule;
	unsigned int	bucket;

	tcp_timers_stop(tcp);

	/* Freed above */
	ASSERT(tcp->tcp_timer_tid == 0);
	ASSERT(tcp->tcp_ack_tid == 0);

	/* must have happened at the time of detaching the tcp */
	ASSERT(TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_state == TCPS_TIME_WAIT);
	ASSERT(tcp->tcp_ptpahn == NULL);
	ASSERT(tcp->tcp_flow_stopped == 0);
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == 0);
	ASSERT(tcp->tcp_listener == NULL);

	TCP_DBGSTAT(tcps, tcp_time_wait);
	mutex_enter(&tsp->tcp_time_wait_lock);

	/*
	 * Immediately expire loopback connections.  Since there is no worry
	 * about packets on the local host showing up after a long network
	 * delay, this is safe and allows much higher rates of connection churn
	 * for applications operating locally.
	 *
	 * This typically bypasses the tcp_free_list fast path due to squeue
	 * re-entry for the loopback close operation.
	 */
	if (tcp->tcp_loopback) {
		tcp_time_wait_purge(tcp, tsp);
		mutex_exit(&tsp->tcp_time_wait_lock);
		return;
	}

	/*
	 * In order to reap TIME_WAITs reliably, we should use a source of time
	 * that is not adjustable by the user.  While it would be more accurate
	 * to grab this timestamp before (potentially) sleeping on the
	 * tcp_time_wait_lock, doing so complicates bucket addressing later.
	 */
	now = ddi_get_lbolt64();

	/*
	 * Each squeue uses an arbitrary time offset when scheduling
	 * expiration timers.  This prevents the bucketing from forcing
	 * tcp_time_wait_collector to run in locksetup across squeues.
	 *
	 * This offset is (re)initialized when a new TIME_WAIT connection is
	 * added to an squeue which has no connections waiting to expire.
	 */
	if (tsp->tcp_time_wait_tid == 0) {
		ASSERT(tsp->tcp_time_wait_cnt == 0);
		tsp->tcp_time_wait_offset =
		    now % MSEC_TO_TICK(TCP_TIME_WAIT_DELAY);
	}
	now -= tsp->tcp_time_wait_offset;

	/*
	 * Use the netstack-defined timeout, rounded up to the minimum
	 * time_wait_collector interval.
	 */
	schedule = now + MSEC_TO_TICK(tcps->tcps_time_wait_interval);
	tcp->tcp_time_wait_expire = schedule;

	/*
	 * Append the connection into the appropriate bucket.
	 */
	bucket = TW_BUCKET(tcp->tcp_time_wait_expire);
	tcp->tcp_time_wait_next = tsp->tcp_time_wait_bucket[bucket];
	tsp->tcp_time_wait_bucket[bucket] = tcp;
	if (tcp->tcp_time_wait_next != NULL) {
		ASSERT(tcp->tcp_time_wait_next->tcp_time_wait_prev == NULL);
		tcp->tcp_time_wait_next->tcp_time_wait_prev = tcp;
	}
	tsp->tcp_time_wait_cnt++;

	/*
	 * Round delay up to the nearest bucket boundary.
	 */
	schedule += MSEC_TO_TICK(TCP_TIME_WAIT_DELAY);
	schedule -= schedule % MSEC_TO_TICK(TCP_TIME_WAIT_DELAY);

	/*
	 * The newly inserted entry may require a tighter schedule for the
	 * expiration timer.
	 */
	if (schedule < tsp->tcp_time_wait_schedule) {
		callout_id_t old_tid = tsp->tcp_time_wait_tid;

		tsp->tcp_time_wait_schedule = schedule;
		tsp->tcp_time_wait_tid =
		    timeout_generic(CALLOUT_NORMAL,
		    tcp_time_wait_collector, sqp,
		    TICK_TO_NSEC(schedule - now),
		    CALLOUT_TCP_RESOLUTION, CALLOUT_FLAG_ROUNDUP);

		/*
		 * It is possible for the timer to fire before the untimeout
		 * action is able to complete.  In that case, the exclusion
		 * offered by the tcp_time_wait_collector_active flag will
		 * prevent multiple collector threads from processing records
		 * simultaneously from the same squeue.
		 */
		mutex_exit(&tsp->tcp_time_wait_lock);
		(void) untimeout_default(old_tid, 0);
		return;
	}

	/*
	 * Start a fresh timer if none exists.
	 */
	if (tsp->tcp_time_wait_schedule == 0) {
		ASSERT(tsp->tcp_time_wait_tid == 0);

		tsp->tcp_time_wait_schedule = schedule;
		tsp->tcp_time_wait_tid =
		    timeout_generic(CALLOUT_NORMAL,
		    tcp_time_wait_collector, sqp,
		    TICK_TO_NSEC(schedule - now),
		    CALLOUT_TCP_RESOLUTION, CALLOUT_FLAG_ROUNDUP);
	}
	mutex_exit(&tsp->tcp_time_wait_lock);
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


static void
tcp_time_wait_purge(tcp_t *tcp, tcp_squeue_priv_t *tsp)
{
	mblk_t *mp;
	conn_t *connp = tcp->tcp_connp;
	kmutex_t *lock;

	ASSERT(MUTEX_HELD(&tsp->tcp_time_wait_lock));
	ASSERT(connp->conn_fanout != NULL);

	lock = &connp->conn_fanout->connf_lock;

	/*
	 * This is essentially a TIME_WAIT reclaim fast path optimization for
	 * performance where the connection is checked under the fanout lock
	 * (so that no one else can get access to the conn_t) that the refcnt
	 * is 2 (one each for TCP and the classifier hash list).  That is the
	 * case and clustering callbacks are not enabled, the conn can be
	 * removed under the fanout lock and avoid clean-up under the squeue.
	 *
	 * This optimization is forgone when clustering is enabled since the
	 * clustering callback must be made before setting the CONDEMNED flag
	 * and after dropping all locks
	 *
	 * See the comments in tcp_closei_local for additional information
	 * regarding the refcnt logic.
	 */
	if (mutex_tryenter(lock)) {
		mutex_enter(&connp->conn_lock);
		if (connp->conn_ref == 2 && cl_inet_disconnect == NULL) {
			ipcl_hash_remove_locked(connp, connp->conn_fanout);
			/*
			 * Set the CONDEMNED flag now itself so that the refcnt
			 * cannot increase due to any walker.
			 */
			connp->conn_state_flags |= CONN_CONDEMNED;
			mutex_exit(&connp->conn_lock);
			mutex_exit(lock);
			if (tsp->tcp_free_list_cnt < tcp_free_list_max_cnt) {
				/*
				 * Add to head of tcp_free_list
				 */
				tcp_cleanup(tcp);
				ASSERT(connp->conn_latch == NULL);
				ASSERT(connp->conn_policy == NULL);
				ASSERT(tcp->tcp_tcps == NULL);
				ASSERT(connp->conn_netstack == NULL);

				tcp->tcp_time_wait_next = tsp->tcp_free_list;
				tcp->tcp_in_free_list = B_TRUE;
				tsp->tcp_free_list = tcp;
				tsp->tcp_free_list_cnt++;
			} else {
				/*
				 * Do not add to tcp_free_list
				 */
				tcp_bind_hash_remove(tcp);
				ixa_cleanup(tcp->tcp_connp->conn_ixa);
				tcp_ipsec_cleanup(tcp);
				CONN_DEC_REF(tcp->tcp_connp);
			}

			/*
			 * With the fast-path complete, we can bail.
			 */
			return;
		} else {
			/*
			 * Fall back to slow path.
			 */
			CONN_INC_REF_LOCKED(connp);
			mutex_exit(&connp->conn_lock);
			mutex_exit(lock);
		}
	} else {
		CONN_INC_REF(connp);
	}

	/*
	 * We can reuse the closemp here since conn has detached (otherwise we
	 * wouldn't even be in time_wait list). It is safe to change
	 * tcp_closemp_used without taking a lock as no other thread can
	 * concurrently access it at this point in the connection lifecycle.
	 */
	if (tcp->tcp_closemp.b_prev == NULL) {
		tcp->tcp_closemp_used = B_TRUE;
	} else {
		cmn_err(CE_PANIC,
		    "tcp_timewait_collector: concurrent use of tcp_closemp: "
		    "connp %p tcp %p\n", (void *)connp, (void *)tcp);
	}

	TCP_DEBUG_GETPCSTACK(tcp->tcmp_stk, 15);
	mp = &tcp->tcp_closemp;
	mutex_exit(&tsp->tcp_time_wait_lock);
	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_timewait_close, connp, NULL,
	    SQ_FILL, SQTAG_TCP_TIMEWAIT);
	mutex_enter(&tsp->tcp_time_wait_lock);
}

/*
 * Purge any tcp_t instances associated with this squeue which have expired
 * from the TIME_WAIT state.
 */
void
tcp_time_wait_collector(void *arg)
{
	tcp_t *tcp;
	int64_t now, sched_active, sched_cur, sched_new;
	unsigned int idx;

	squeue_t *sqp = (squeue_t *)arg;
	tcp_squeue_priv_t *tsp =
	    *((tcp_squeue_priv_t **)squeue_getprivate(sqp, SQPRIVATE_TCP));

	mutex_enter(&tsp->tcp_time_wait_lock);

	/*
	 * Because of timer scheduling complexity and the fact that the
	 * tcp_time_wait_lock is dropped during tcp_time_wait_purge, it is
	 * possible for multiple tcp_time_wait_collector threads to run against
	 * the same squeue.  This flag is used to exclude other collectors from
	 * the squeue during execution.
	 */
	if (tsp->tcp_time_wait_collector_active) {
		mutex_exit(&tsp->tcp_time_wait_lock);
		return;
	}
	tsp->tcp_time_wait_collector_active = B_TRUE;

	/*
	 * After its assignment here, the value of sched_active must not be
	 * altered as it is used to validate the state of the
	 * tcp_time_wait_collector callout schedule for this squeue.
	 *
	 * The same does not hold true of sched_cur, which holds the timestamp
	 * of the bucket undergoing processing.  While it is initially equal to
	 * sched_active, certain conditions below can walk it forward,
	 * triggering the retry loop.
	 */
	sched_cur = sched_active = tsp->tcp_time_wait_schedule;

	/*
	 * Purge the free list if necessary
	 */
	if (tsp->tcp_free_list != NULL) {
		TCP_G_STAT(tcp_freelist_cleanup);
		while ((tcp = tsp->tcp_free_list) != NULL) {
			tsp->tcp_free_list = tcp->tcp_time_wait_next;
			tcp->tcp_time_wait_next = NULL;
			tsp->tcp_free_list_cnt--;
			ASSERT(tcp->tcp_tcps == NULL);
			CONN_DEC_REF(tcp->tcp_connp);
		}
		ASSERT(tsp->tcp_free_list_cnt == 0);
	}

	/*
	 * If there are no connections pending, clear timer-related state to be
	 * reinitialized by the next caller.
	 */
	if (tsp->tcp_time_wait_cnt == 0) {
		tsp->tcp_time_wait_offset = 0;
		tsp->tcp_time_wait_schedule = 0;
		tsp->tcp_time_wait_tid = 0;
		tsp->tcp_time_wait_collector_active = B_FALSE;
		mutex_exit(&tsp->tcp_time_wait_lock);
		return;
	}

retry:
	/*
	 * Grab the bucket which we were scheduled to cleanse.
	 */
	idx = TW_BUCKET(sched_cur - 1);
	now = ddi_get_lbolt64() - tsp->tcp_time_wait_offset;
	tcp = tsp->tcp_time_wait_bucket[idx];

	while (tcp != NULL) {
		/*
		 * Since the bucket count is sized to prevent wrap-around
		 * during typical operation and timers are schedule to process
		 * buckets with only expired connections, there is only one
		 * reason to encounter a connection expiring in the future:
		 * The tcp_time_wait_collector thread has been so delayed in
		 * its processing that connections have wrapped around the
		 * timing wheel into this bucket.
		 *
		 * In that case, the remaining entires in the bucket can be
		 * ignored since, being appended sequentially, they should all
		 * expire in the future.
		 */
		if (now < tcp->tcp_time_wait_expire) {
			break;
		}

		/*
		 * Pull the connection out of the bucket.
		 */
		VERIFY(tcp_time_wait_remove(tcp, tsp));

		/*
		 * Purge the connection.
		 *
		 * While tcp_time_wait_lock will be temporarily dropped as part
		 * of the process, there is no risk of the timer being
		 * (re)scheduled while the collector is running since a value
		 * corresponding to the past is left in tcp_time_wait_schedule.
		 */
		tcp_time_wait_purge(tcp, tsp);

		/*
		 * Because tcp_time_wait_remove clears the tcp_time_wait_next
		 * field, the next item must be grabbed directly from the
		 * bucket itself.
		 */
		tcp = tsp->tcp_time_wait_bucket[idx];
	}

	if (tsp->tcp_time_wait_cnt == 0) {
		/*
		 * There is not a need for the collector to schedule a new
		 * timer if no pending items remain.  The timer state can be
		 * cleared only if it was untouched while the collector dropped
		 * its locks during tcp_time_wait_purge.
		 */
		if (tsp->tcp_time_wait_schedule == sched_active) {
			tsp->tcp_time_wait_offset = 0;
			tsp->tcp_time_wait_schedule = 0;
			tsp->tcp_time_wait_tid = 0;
		}
		tsp->tcp_time_wait_collector_active = B_FALSE;
		mutex_exit(&tsp->tcp_time_wait_lock);
		return;
	} else {
		unsigned int nidx;

		/*
		 * Locate the next bucket containing entries.
		 */
		sched_new = sched_cur + MSEC_TO_TICK(TCP_TIME_WAIT_DELAY);
		nidx = TW_BUCKET_NEXT(idx);
		while (tsp->tcp_time_wait_bucket[nidx] == NULL) {
			if (nidx == idx) {
				break;
			}
			nidx = TW_BUCKET_NEXT(nidx);
			sched_new += MSEC_TO_TICK(TCP_TIME_WAIT_DELAY);
		}
		ASSERT(tsp->tcp_time_wait_bucket[nidx] != NULL);
	}

	/*
	 * It is possible that the system is under such dire load that between
	 * the timer scheduling and TIME_WAIT processing delay, execution
	 * overran the interval allocated to this bucket.
	 */
	now = ddi_get_lbolt64() - tsp->tcp_time_wait_offset;
	if (sched_new <= now) {
		/*
		 * Attempt to right the situation by immediately performing a
		 * purge on the next bucket.  This loop will continue as needed
		 * until the schedule can be pushed out ahead of the clock.
		 */
		sched_cur = sched_new;
		DTRACE_PROBE3(tcp__time__wait__overrun,
		    tcp_squeue_priv_t *, tsp, int64_t, sched_new, int64_t, now);
		goto retry;
	}

	/*
	 * Another thread may have snuck in to reschedule the timer while locks
	 * were dropped during tcp_time_wait_purge.  Defer to the running timer
	 * if that is the case.
	 */
	if (tsp->tcp_time_wait_schedule != sched_active) {
		tsp->tcp_time_wait_collector_active = B_FALSE;
		mutex_exit(&tsp->tcp_time_wait_lock);
		return;
	}

	/*
	 * Schedule the next timer.
	 */
	tsp->tcp_time_wait_schedule = sched_new;
	tsp->tcp_time_wait_tid =
	    timeout_generic(CALLOUT_NORMAL,
	    tcp_time_wait_collector, sqp,
	    TICK_TO_NSEC(sched_new - now),
	    CALLOUT_TCP_RESOLUTION, CALLOUT_FLAG_ROUNDUP);
	tsp->tcp_time_wait_collector_active = B_FALSE;
	mutex_exit(&tsp->tcp_time_wait_lock);
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

	boolean_t keepalive = (seg_len == 0 || seg_len == 1) &&
	    (seg_seq + 1 == tcp->tcp_rnxt);
	if (tcp->tcp_snd_ts_ok && !(flags & TH_RST) && !keepalive) {
		int options;
		if (tcp->tcp_snd_sack_ok)
			tcpopt.tcp = tcp;
		else
			tcpopt.tcp = NULL;
		options = tcp_parse_options(tcpha, &tcpopt);
		if (!(options & TCP_OPT_TSTAMP_PRESENT)) {
			DTRACE_TCP1(droppedtimestamp, tcp_t *, tcp);
			goto done;
		} else if (!tcp_paws_check(tcp, &tcpopt)) {
			tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt, tcp->tcp_rnxt,
			    TH_ACK);
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
	 * Check whether we can update tcp_ts_recent. This test is from RFC
	 * 7323, section 5.3.
	 */
	if (tcp->tcp_snd_ts_ok && !(flags & TH_RST) &&
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

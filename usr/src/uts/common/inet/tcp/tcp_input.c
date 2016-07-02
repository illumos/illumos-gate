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
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

/* This file contains all TCP input processing functions. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#include <sys/tsol/tnet.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/tcp_cluster.h>
#include <inet/proto_set.h>
#include <inet/ipsec_impl.h>

/*
 * RFC7323-recommended phrasing of TSTAMP option, for easier parsing
 */

#ifdef _BIG_ENDIAN
#define	TCPOPT_NOP_NOP_TSTAMP ((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | \
	(TCPOPT_TSTAMP << 8) | 10)
#else
#define	TCPOPT_NOP_NOP_TSTAMP ((10 << 24) | (TCPOPT_TSTAMP << 16) | \
	(TCPOPT_NOP << 8) | TCPOPT_NOP)
#endif

/*
 *  PAWS needs a timer for 24 days.  This is the number of ticks in 24 days
 */
#define	PAWS_TIMEOUT	((clock_t)(24*24*60*60*hz))

/*
 * Since tcp_listener is not cleared atomically with tcp_detached
 * being cleared we need this extra bit to tell a detached connection
 * apart from one that is in the process of being accepted.
 */
#define	TCP_IS_DETACHED_NONEAGER(tcp)	\
	(TCP_IS_DETACHED(tcp) &&	\
	    (!(tcp)->tcp_hard_binding))

/*
 * Steps to do when a tcp_t moves to TIME-WAIT state.
 *
 * This connection is done, we don't need to account for it.  Decrement
 * the listener connection counter if needed.
 *
 * Decrement the connection counter of the stack.  Note that this counter
 * is per CPU.  So the total number of connections in a stack is the sum of all
 * of them.  Since there is no lock for handling all of them exclusively, the
 * resulting sum is only an approximation.
 *
 * Unconditionally clear the exclusive binding bit so this TIME-WAIT
 * connection won't interfere with new ones.
 *
 * Start the TIME-WAIT timer.  If upper layer has not closed the connection,
 * the timer is handled within the context of this tcp_t.  When the timer
 * fires, tcp_clean_death() is called.  If upper layer closes the connection
 * during this period, tcp_time_wait_append() will be called to add this
 * tcp_t to the global TIME-WAIT list.  Note that this means that the
 * actual wait time in TIME-WAIT state will be longer than the
 * tcps_time_wait_interval since the period before upper layer closes the
 * connection is not accounted for when tcp_time_wait_append() is called.
 *
 * If upper layer has closed the connection, call tcp_time_wait_append()
 * directly.
 *
 */
#define	SET_TIME_WAIT(tcps, tcp, connp)				\
{								\
	(tcp)->tcp_state = TCPS_TIME_WAIT;			\
	if ((tcp)->tcp_listen_cnt != NULL)			\
		TCP_DECR_LISTEN_CNT(tcp);			\
	atomic_dec_64(						\
	    (uint64_t *)&(tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_conn_cnt); \
	(connp)->conn_exclbind = 0;				\
	if (!TCP_IS_DETACHED(tcp)) {				\
		TCP_TIMER_RESTART(tcp, (tcps)->tcps_time_wait_interval); \
	} else {						\
		tcp_time_wait_append(tcp);			\
		TCP_DBGSTAT(tcps, tcp_rput_time_wait);		\
	}							\
}

/*
 * If tcp_drop_ack_unsent_cnt is greater than 0, when TCP receives more
 * than tcp_drop_ack_unsent_cnt number of ACKs which acknowledge unsent
 * data, TCP will not respond with an ACK.  RFC 793 requires that
 * TCP responds with an ACK for such a bogus ACK.  By not following
 * the RFC, we prevent TCP from getting into an ACK storm if somehow
 * an attacker successfully spoofs an acceptable segment to our
 * peer; or when our peer is "confused."
 */
static uint32_t tcp_drop_ack_unsent_cnt = 10;

/*
 * To protect TCP against attacker using a small window and requesting
 * large amount of data (DoS attack by conuming memory), TCP checks the
 * window advertised in the last ACK of the 3-way handshake.  TCP uses
 * the tcp_mss (the size of one packet) value for comparion.  The window
 * should be larger than tcp_mss.  But while a sane TCP should advertise
 * a receive window larger than or equal to 4*MSS to avoid stop and go
 * tarrfic, not all TCP stacks do that.  This is especially true when
 * tcp_mss is a big value.
 *
 * To work around this issue, an additional fixed value for comparison
 * is also used.  If the advertised window is smaller than both tcp_mss
 * and tcp_init_wnd_chk, the ACK is considered as invalid.  So for large
 * tcp_mss value (say, 8K), a window larger than tcp_init_wnd_chk but
 * smaller than 8K is considered to be OK.
 */
static uint32_t tcp_init_wnd_chk = 4096;

/* Process ICMP source quench message or not. */
static boolean_t tcp_icmp_source_quench = B_FALSE;

static boolean_t tcp_outbound_squeue_switch = B_FALSE;

static mblk_t	*tcp_conn_create_v4(conn_t *, conn_t *, mblk_t *,
		    ip_recv_attr_t *);
static mblk_t	*tcp_conn_create_v6(conn_t *, conn_t *, mblk_t *,
		    ip_recv_attr_t *);
static boolean_t	tcp_drop_q0(tcp_t *);
static void	tcp_icmp_error_ipv6(tcp_t *, mblk_t *, ip_recv_attr_t *);
static mblk_t	*tcp_input_add_ancillary(tcp_t *, mblk_t *, ip_pkt_t *,
		    ip_recv_attr_t *);
static void	tcp_input_listener(void *, mblk_t *, void *, ip_recv_attr_t *);
static void	tcp_process_options(tcp_t *, tcpha_t *);
static mblk_t	*tcp_reass(tcp_t *, mblk_t *, uint32_t);
static void	tcp_reass_elim_overlap(tcp_t *, mblk_t *);
static void	tcp_rsrv_input(void *, mblk_t *, void *, ip_recv_attr_t *);
static void	tcp_set_rto(tcp_t *, time_t);
static void	tcp_setcred_data(mblk_t *, ip_recv_attr_t *);

/*
 * Set the MSS associated with a particular tcp based on its current value,
 * and a new one passed in. Observe minimums and maximums, and reset other
 * state variables that we want to view as multiples of MSS.
 *
 * The value of MSS could be either increased or descreased.
 */
void
tcp_mss_set(tcp_t *tcp, uint32_t mss)
{
	uint32_t	mss_max;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	if (connp->conn_ipversion == IPV4_VERSION)
		mss_max = tcps->tcps_mss_max_ipv4;
	else
		mss_max = tcps->tcps_mss_max_ipv6;

	if (mss < tcps->tcps_mss_min)
		mss = tcps->tcps_mss_min;
	if (mss > mss_max)
		mss = mss_max;
	/*
	 * Unless naglim has been set by our client to
	 * a non-mss value, force naglim to track mss.
	 * This can help to aggregate small writes.
	 */
	if (mss < tcp->tcp_naglim || tcp->tcp_mss == tcp->tcp_naglim)
		tcp->tcp_naglim = mss;
	/*
	 * TCP should be able to buffer at least 4 MSS data for obvious
	 * performance reason.
	 */
	if ((mss << 2) > connp->conn_sndbuf)
		connp->conn_sndbuf = mss << 2;

	/*
	 * Set the send lowater to at least twice of MSS.
	 */
	if ((mss << 1) > connp->conn_sndlowat)
		connp->conn_sndlowat = mss << 1;

	/*
	 * Update tcp_cwnd according to the new value of MSS. Keep the
	 * previous ratio to preserve the transmit rate.
	 */
	tcp->tcp_cwnd = (tcp->tcp_cwnd / tcp->tcp_mss) * mss;
	tcp->tcp_cwnd_cnt = 0;

	tcp->tcp_mss = mss;
	(void) tcp_maxpsz_set(tcp, B_TRUE);
}

/*
 * Extract option values from a tcp header.  We put any found values into the
 * tcpopt struct and return a bitmask saying which options were found.
 */
int
tcp_parse_options(tcpha_t *tcpha, tcp_opt_t *tcpopt)
{
	uchar_t		*endp;
	int		len;
	uint32_t	mss;
	uchar_t		*up = (uchar_t *)tcpha;
	int		found = 0;
	int32_t		sack_len;
	tcp_seq		sack_begin, sack_end;
	tcp_t		*tcp;

	endp = up + TCP_HDR_LENGTH(tcpha);
	up += TCP_MIN_HEADER_LENGTH;
	/*
	 * If timestamp option is aligned as recommended in RFC 7323 Appendix
	 * A, and is the only option, return quickly.
	 */
	if (TCP_HDR_LENGTH(tcpha) == (uint32_t)TCP_MIN_HEADER_LENGTH +
	    TCPOPT_REAL_TS_LEN &&
	    OK_32PTR(up) &&
	    *(uint32_t *)up == TCPOPT_NOP_NOP_TSTAMP) {
		tcpopt->tcp_opt_ts_val = ABE32_TO_U32((up+4));
		tcpopt->tcp_opt_ts_ecr = ABE32_TO_U32((up+8));

		return (TCP_OPT_TSTAMP_PRESENT);
	}
	while (up < endp) {
		len = endp - up;
		switch (*up) {
		case TCPOPT_EOL:
			break;

		case TCPOPT_NOP:
			up++;
			continue;

		case TCPOPT_MAXSEG:
			if (len < TCPOPT_MAXSEG_LEN ||
			    up[1] != TCPOPT_MAXSEG_LEN)
				break;

			mss = BE16_TO_U16(up+2);
			/* Caller must handle tcp_mss_min and tcp_mss_max_* */
			tcpopt->tcp_opt_mss = mss;
			found |= TCP_OPT_MSS_PRESENT;

			up += TCPOPT_MAXSEG_LEN;
			continue;

		case TCPOPT_WSCALE:
			if (len < TCPOPT_WS_LEN || up[1] != TCPOPT_WS_LEN)
				break;

			if (up[2] > TCP_MAX_WINSHIFT)
				tcpopt->tcp_opt_wscale = TCP_MAX_WINSHIFT;
			else
				tcpopt->tcp_opt_wscale = up[2];
			found |= TCP_OPT_WSCALE_PRESENT;

			up += TCPOPT_WS_LEN;
			continue;

		case TCPOPT_SACK_PERMITTED:
			if (len < TCPOPT_SACK_OK_LEN ||
			    up[1] != TCPOPT_SACK_OK_LEN)
				break;
			found |= TCP_OPT_SACK_OK_PRESENT;
			up += TCPOPT_SACK_OK_LEN;
			continue;

		case TCPOPT_SACK:
			if (len <= 2 || up[1] <= 2 || len < up[1])
				break;

			/* If TCP is not interested in SACK blks... */
			if ((tcp = tcpopt->tcp) == NULL) {
				up += up[1];
				continue;
			}
			sack_len = up[1] - TCPOPT_HEADER_LEN;
			up += TCPOPT_HEADER_LEN;

			/*
			 * If the list is empty, allocate one and assume
			 * nothing is sack'ed.
			 */
			if (tcp->tcp_notsack_list == NULL) {
				tcp_notsack_update(&(tcp->tcp_notsack_list),
				    tcp->tcp_suna, tcp->tcp_snxt,
				    &(tcp->tcp_num_notsack_blk),
				    &(tcp->tcp_cnt_notsack_list));

				/*
				 * Make sure tcp_notsack_list is not NULL.
				 * This happens when kmem_alloc(KM_NOSLEEP)
				 * returns NULL.
				 */
				if (tcp->tcp_notsack_list == NULL) {
					up += sack_len;
					continue;
				}
				tcp->tcp_fack = tcp->tcp_suna;
			}

			while (sack_len > 0) {
				if (up + 8 > endp) {
					up = endp;
					break;
				}
				sack_begin = BE32_TO_U32(up);
				up += 4;
				sack_end = BE32_TO_U32(up);
				up += 4;
				sack_len -= 8;
				/*
				 * Bounds checking.  Make sure the SACK
				 * info is within tcp_suna and tcp_snxt.
				 * If this SACK blk is out of bound, ignore
				 * it but continue to parse the following
				 * blks.
				 */
				if (SEQ_LEQ(sack_end, sack_begin) ||
				    SEQ_LT(sack_begin, tcp->tcp_suna) ||
				    SEQ_GT(sack_end, tcp->tcp_snxt)) {
					continue;
				}
				tcp_notsack_insert(&(tcp->tcp_notsack_list),
				    sack_begin, sack_end,
				    &(tcp->tcp_num_notsack_blk),
				    &(tcp->tcp_cnt_notsack_list));
				if (SEQ_GT(sack_end, tcp->tcp_fack)) {
					tcp->tcp_fack = sack_end;
				}
			}
			found |= TCP_OPT_SACK_PRESENT;
			continue;

		case TCPOPT_TSTAMP:
			if (len < TCPOPT_TSTAMP_LEN ||
			    up[1] != TCPOPT_TSTAMP_LEN)
				break;

			tcpopt->tcp_opt_ts_val = BE32_TO_U32(up+2);
			tcpopt->tcp_opt_ts_ecr = BE32_TO_U32(up+6);

			found |= TCP_OPT_TSTAMP_PRESENT;

			up += TCPOPT_TSTAMP_LEN;
			continue;

		default:
			if (len <= 1 || len < (int)up[1] || up[1] == 0)
				break;
			up += up[1];
			continue;
		}
		break;
	}
	return (found);
}

/*
 * Process all TCP option in SYN segment.  Note that this function should
 * be called after tcp_set_destination() is called so that the necessary info
 * from IRE is already set in the tcp structure.
 *
 * This function sets up the correct tcp_mss value according to the
 * MSS option value and our header size.  It also sets up the window scale
 * and timestamp values, and initialize SACK info blocks.  But it does not
 * change receive window size after setting the tcp_mss value.  The caller
 * should do the appropriate change.
 */
static void
tcp_process_options(tcp_t *tcp, tcpha_t *tcpha)
{
	int options;
	tcp_opt_t tcpopt;
	uint32_t mss_max;
	char *tmp_tcph;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	tcpopt.tcp = NULL;
	options = tcp_parse_options(tcpha, &tcpopt);

	/*
	 * Process MSS option.  Note that MSS option value does not account
	 * for IP or TCP options.  This means that it is equal to MTU - minimum
	 * IP+TCP header size, which is 40 bytes for IPv4 and 60 bytes for
	 * IPv6.
	 */
	if (!(options & TCP_OPT_MSS_PRESENT)) {
		if (connp->conn_ipversion == IPV4_VERSION)
			tcpopt.tcp_opt_mss = tcps->tcps_mss_def_ipv4;
		else
			tcpopt.tcp_opt_mss = tcps->tcps_mss_def_ipv6;
	} else {
		if (connp->conn_ipversion == IPV4_VERSION)
			mss_max = tcps->tcps_mss_max_ipv4;
		else
			mss_max = tcps->tcps_mss_max_ipv6;
		if (tcpopt.tcp_opt_mss < tcps->tcps_mss_min)
			tcpopt.tcp_opt_mss = tcps->tcps_mss_min;
		else if (tcpopt.tcp_opt_mss > mss_max)
			tcpopt.tcp_opt_mss = mss_max;
	}

	/* Process Window Scale option. */
	if (options & TCP_OPT_WSCALE_PRESENT) {
		tcp->tcp_snd_ws = tcpopt.tcp_opt_wscale;
		tcp->tcp_snd_ws_ok = B_TRUE;
	} else {
		tcp->tcp_snd_ws = B_FALSE;
		tcp->tcp_snd_ws_ok = B_FALSE;
		tcp->tcp_rcv_ws = B_FALSE;
	}

	/* Process Timestamp option. */
	if ((options & TCP_OPT_TSTAMP_PRESENT) &&
	    (tcp->tcp_snd_ts_ok || TCP_IS_DETACHED(tcp))) {
		tmp_tcph = (char *)tcp->tcp_tcpha;

		tcp->tcp_snd_ts_ok = B_TRUE;
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = ddi_get_lbolt64();
		ASSERT(OK_32PTR(tmp_tcph));
		ASSERT(connp->conn_ht_ulp_len == TCP_MIN_HEADER_LENGTH);

		/* Fill in our template header with basic timestamp option. */
		tmp_tcph += connp->conn_ht_ulp_len;
		tmp_tcph[0] = TCPOPT_NOP;
		tmp_tcph[1] = TCPOPT_NOP;
		tmp_tcph[2] = TCPOPT_TSTAMP;
		tmp_tcph[3] = TCPOPT_TSTAMP_LEN;
		connp->conn_ht_iphc_len += TCPOPT_REAL_TS_LEN;
		connp->conn_ht_ulp_len += TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcpha->tha_offset_and_reserved += (3 << 4);
	} else {
		tcp->tcp_snd_ts_ok = B_FALSE;
	}

	/*
	 * Process SACK options.  If SACK is enabled for this connection,
	 * then allocate the SACK info structure.  Note the following ways
	 * when tcp_snd_sack_ok is set to true.
	 *
	 * For active connection: in tcp_set_destination() called in
	 * tcp_connect().
	 *
	 * For passive connection: in tcp_set_destination() called in
	 * tcp_input_listener().
	 *
	 * That's the reason why the extra TCP_IS_DETACHED() check is there.
	 * That check makes sure that if we did not send a SACK OK option,
	 * we will not enable SACK for this connection even though the other
	 * side sends us SACK OK option.  For active connection, the SACK
	 * info structure has already been allocated.  So we need to free
	 * it if SACK is disabled.
	 */
	if ((options & TCP_OPT_SACK_OK_PRESENT) &&
	    (tcp->tcp_snd_sack_ok ||
	    (tcps->tcps_sack_permitted != 0 && TCP_IS_DETACHED(tcp)))) {
		ASSERT(tcp->tcp_num_sack_blk == 0);
		ASSERT(tcp->tcp_notsack_list == NULL);

		tcp->tcp_snd_sack_ok = B_TRUE;
		if (tcp->tcp_snd_ts_ok) {
			tcp->tcp_max_sack_blk = 3;
		} else {
			tcp->tcp_max_sack_blk = 4;
		}
	} else if (tcp->tcp_snd_sack_ok) {
		/*
		 * Resetting tcp_snd_sack_ok to B_FALSE so that
		 * no SACK info will be used for this
		 * connection.  This assumes that SACK usage
		 * permission is negotiated.  This may need
		 * to be changed once this is clarified.
		 */
		ASSERT(tcp->tcp_num_sack_blk == 0);
		ASSERT(tcp->tcp_notsack_list == NULL);
		tcp->tcp_snd_sack_ok = B_FALSE;
	}

	/*
	 * Now we know the exact TCP/IP header length, subtract
	 * that from tcp_mss to get our side's MSS.
	 */
	tcp->tcp_mss -= connp->conn_ht_iphc_len;

	/*
	 * Here we assume that the other side's header size will be equal to
	 * our header size.  We calculate the real MSS accordingly.  Need to
	 * take into additional stuffs IPsec puts in.
	 *
	 * Real MSS = Opt.MSS - (our TCP/IP header - min TCP/IP header)
	 */
	tcpopt.tcp_opt_mss -= connp->conn_ht_iphc_len +
	    tcp->tcp_ipsec_overhead -
	    ((connp->conn_ipversion == IPV4_VERSION ?
	    IP_SIMPLE_HDR_LENGTH : IPV6_HDR_LEN) + TCP_MIN_HEADER_LENGTH);

	/*
	 * Set MSS to the smaller one of both ends of the connection.
	 * We should not have called tcp_mss_set() before, but our
	 * side of the MSS should have been set to a proper value
	 * by tcp_set_destination().  tcp_mss_set() will also set up the
	 * STREAM head parameters properly.
	 *
	 * If we have a larger-than-16-bit window but the other side
	 * didn't want to do window scale, tcp_rwnd_set() will take
	 * care of that.
	 */
	tcp_mss_set(tcp, MIN(tcpopt.tcp_opt_mss, tcp->tcp_mss));

	/*
	 * Initialize tcp_cwnd value. After tcp_mss_set(), tcp_mss has been
	 * updated properly.
	 */
	TCP_SET_INIT_CWND(tcp, tcp->tcp_mss, tcps->tcps_slow_start_initial);
}

/*
 * Add a new piece to the tcp reassembly queue.  If the gap at the beginning
 * is filled, return as much as we can.  The message passed in may be
 * multi-part, chained using b_cont.  "start" is the starting sequence
 * number for this piece.
 */
static mblk_t *
tcp_reass(tcp_t *tcp, mblk_t *mp, uint32_t start)
{
	uint32_t	end;
	mblk_t		*mp1;
	mblk_t		*mp2;
	mblk_t		*next_mp;
	uint32_t	u1;
	tcp_stack_t	*tcps = tcp->tcp_tcps;


	/* Walk through all the new pieces. */
	do {
		ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
		    (uintptr_t)INT_MAX);
		end = start + (int)(mp->b_wptr - mp->b_rptr);
		next_mp = mp->b_cont;
		if (start == end) {
			/* Empty.  Blast it. */
			freeb(mp);
			continue;
		}
		mp->b_cont = NULL;
		TCP_REASS_SET_SEQ(mp, start);
		TCP_REASS_SET_END(mp, end);
		mp1 = tcp->tcp_reass_tail;
		if (!mp1) {
			tcp->tcp_reass_tail = mp;
			tcp->tcp_reass_head = mp;
			TCPS_BUMP_MIB(tcps, tcpInDataUnorderSegs);
			TCPS_UPDATE_MIB(tcps, tcpInDataUnorderBytes,
			    end - start);
			continue;
		}
		/* New stuff completely beyond tail? */
		if (SEQ_GEQ(start, TCP_REASS_END(mp1))) {
			/* Link it on end. */
			mp1->b_cont = mp;
			tcp->tcp_reass_tail = mp;
			TCPS_BUMP_MIB(tcps, tcpInDataUnorderSegs);
			TCPS_UPDATE_MIB(tcps, tcpInDataUnorderBytes,
			    end - start);
			continue;
		}
		mp1 = tcp->tcp_reass_head;
		u1 = TCP_REASS_SEQ(mp1);
		/* New stuff at the front? */
		if (SEQ_LT(start, u1)) {
			/* Yes... Check for overlap. */
			mp->b_cont = mp1;
			tcp->tcp_reass_head = mp;
			tcp_reass_elim_overlap(tcp, mp);
			continue;
		}
		/*
		 * The new piece fits somewhere between the head and tail.
		 * We find our slot, where mp1 precedes us and mp2 trails.
		 */
		for (; (mp2 = mp1->b_cont) != NULL; mp1 = mp2) {
			u1 = TCP_REASS_SEQ(mp2);
			if (SEQ_LEQ(start, u1))
				break;
		}
		/* Link ourselves in */
		mp->b_cont = mp2;
		mp1->b_cont = mp;

		/* Trim overlap with following mblk(s) first */
		tcp_reass_elim_overlap(tcp, mp);

		/* Trim overlap with preceding mblk */
		tcp_reass_elim_overlap(tcp, mp1);

	} while (start = end, mp = next_mp);
	mp1 = tcp->tcp_reass_head;
	/* Anything ready to go? */
	if (TCP_REASS_SEQ(mp1) != tcp->tcp_rnxt)
		return (NULL);
	/* Eat what we can off the queue */
	for (;;) {
		mp = mp1->b_cont;
		end = TCP_REASS_END(mp1);
		TCP_REASS_SET_SEQ(mp1, 0);
		TCP_REASS_SET_END(mp1, 0);
		if (!mp) {
			tcp->tcp_reass_tail = NULL;
			break;
		}
		if (end != TCP_REASS_SEQ(mp)) {
			mp1->b_cont = NULL;
			break;
		}
		mp1 = mp;
	}
	mp1 = tcp->tcp_reass_head;
	tcp->tcp_reass_head = mp;
	return (mp1);
}

/* Eliminate any overlap that mp may have over later mblks */
static void
tcp_reass_elim_overlap(tcp_t *tcp, mblk_t *mp)
{
	uint32_t	end;
	mblk_t		*mp1;
	uint32_t	u1;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	end = TCP_REASS_END(mp);
	while ((mp1 = mp->b_cont) != NULL) {
		u1 = TCP_REASS_SEQ(mp1);
		if (!SEQ_GT(end, u1))
			break;
		if (!SEQ_GEQ(end, TCP_REASS_END(mp1))) {
			mp->b_wptr -= end - u1;
			TCP_REASS_SET_END(mp, u1);
			TCPS_BUMP_MIB(tcps, tcpInDataPartDupSegs);
			TCPS_UPDATE_MIB(tcps, tcpInDataPartDupBytes,
			    end - u1);
			break;
		}
		mp->b_cont = mp1->b_cont;
		TCP_REASS_SET_SEQ(mp1, 0);
		TCP_REASS_SET_END(mp1, 0);
		freeb(mp1);
		TCPS_BUMP_MIB(tcps, tcpInDataDupSegs);
		TCPS_UPDATE_MIB(tcps, tcpInDataDupBytes, end - u1);
	}
	if (!mp1)
		tcp->tcp_reass_tail = mp;
}

/*
 * This function does PAWS protection check, per RFC 7323 section 5. Requires
 * that timestamp options are already processed into tcpoptp. Returns B_TRUE if
 * the segment passes the PAWS test, else returns B_FALSE.
 */
boolean_t
tcp_paws_check(tcp_t *tcp, const tcp_opt_t *tcpoptp)
{
	if (TSTMP_LT(tcpoptp->tcp_opt_ts_val,
	    tcp->tcp_ts_recent)) {
		if (LBOLT_FASTPATH64 <
		    (tcp->tcp_last_rcv_lbolt + PAWS_TIMEOUT)) {
			/* This segment is not acceptable. */
			return (B_FALSE);
		} else {
			/*
			 * Connection has been idle for
			 * too long.  Reset the timestamp
			 */
			tcp->tcp_ts_recent =
			    tcpoptp->tcp_opt_ts_val;
		}
	}
	return (B_TRUE);
}

/*
 * Defense for the SYN attack -
 * 1. When q0 is full, drop from the tail (tcp_eager_prev_drop_q0) the oldest
 *    one from the list of droppable eagers. This list is a subset of q0.
 *    see comments before the definition of MAKE_DROPPABLE().
 * 2. Don't drop a SYN request before its first timeout. This gives every
 *    request at least til the first timeout to complete its 3-way handshake.
 * 3. Maintain tcp_syn_rcvd_timeout as an accurate count of how many
 *    requests currently on the queue that has timed out. This will be used
 *    as an indicator of whether an attack is under way, so that appropriate
 *    actions can be taken. (It's incremented in tcp_timer() and decremented
 *    either when eager goes into ESTABLISHED, or gets freed up.)
 * 4. The current threshold is - # of timeout > q0len/4 => SYN alert on
 *    # of timeout drops back to <= q0len/32 => SYN alert off
 */
static boolean_t
tcp_drop_q0(tcp_t *tcp)
{
	tcp_t	*eager;
	mblk_t	*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(MUTEX_HELD(&tcp->tcp_eager_lock));
	ASSERT(tcp->tcp_eager_next_q0 != tcp->tcp_eager_prev_q0);

	/* Pick oldest eager from the list of droppable eagers */
	eager = tcp->tcp_eager_prev_drop_q0;

	/* If list is empty. return B_FALSE */
	if (eager == tcp) {
		return (B_FALSE);
	}

	/* If allocated, the mp will be freed in tcp_clean_death_wrapper() */
	if ((mp = allocb(0, BPRI_HI)) == NULL)
		return (B_FALSE);

	/*
	 * Take this eager out from the list of droppable eagers since we are
	 * going to drop it.
	 */
	MAKE_UNDROPPABLE(eager);

	if (tcp->tcp_connp->conn_debug) {
		(void) strlog(TCP_MOD_ID, 0, 3, SL_TRACE,
		    "tcp_drop_q0: listen half-open queue (max=%d) overflow"
		    " (%d pending) on %s, drop one", tcps->tcps_conn_req_max_q0,
		    tcp->tcp_conn_req_cnt_q0,
		    tcp_display(tcp, NULL, DISP_PORT_ONLY));
	}

	TCPS_BUMP_MIB(tcps, tcpHalfOpenDrop);

	/* Put a reference on the conn as we are enqueueing it in the sqeue */
	CONN_INC_REF(eager->tcp_connp);

	SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp,
	    tcp_clean_death_wrapper, eager->tcp_connp, NULL,
	    SQ_FILL, SQTAG_TCP_DROP_Q0);

	return (B_TRUE);
}

/*
 * Handle a SYN on an AF_INET6 socket; can be either IPv4 or IPv6
 */
static mblk_t *
tcp_conn_create_v6(conn_t *lconnp, conn_t *connp, mblk_t *mp,
    ip_recv_attr_t *ira)
{
	tcp_t 		*ltcp = lconnp->conn_tcp;
	tcp_t		*tcp = connp->conn_tcp;
	mblk_t		*tpi_mp;
	ipha_t		*ipha;
	ip6_t		*ip6h;
	sin6_t 		sin6;
	uint_t		ifindex = ira->ira_ruifindex;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (ira->ira_flags & IRAF_IS_IPV4) {
		ipha = (ipha_t *)mp->b_rptr;

		connp->conn_ipversion = IPV4_VERSION;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &connp->conn_laddr_v6);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &connp->conn_faddr_v6);
		connp->conn_saddr_v6 = connp->conn_laddr_v6;

		sin6 = sin6_null;
		sin6.sin6_addr = connp->conn_faddr_v6;
		sin6.sin6_port = connp->conn_fport;
		sin6.sin6_family = AF_INET6;
		sin6.__sin6_src_id = ip_srcid_find_addr(&connp->conn_laddr_v6,
		    IPCL_ZONEID(lconnp), tcps->tcps_netstack);

		if (connp->conn_recv_ancillary.crb_recvdstaddr) {
			sin6_t	sin6d;

			sin6d = sin6_null;
			sin6d.sin6_addr = connp->conn_laddr_v6;
			sin6d.sin6_port = connp->conn_lport;
			sin6d.sin6_family = AF_INET;
			tpi_mp = mi_tpi_extconn_ind(NULL,
			    (char *)&sin6d, sizeof (sin6_t),
			    (char *)&tcp,
			    (t_scalar_t)sizeof (intptr_t),
			    (char *)&sin6d, sizeof (sin6_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		} else {
			tpi_mp = mi_tpi_conn_ind(NULL,
			    (char *)&sin6, sizeof (sin6_t),
			    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		}
	} else {
		ip6h = (ip6_t *)mp->b_rptr;

		connp->conn_ipversion = IPV6_VERSION;
		connp->conn_laddr_v6 = ip6h->ip6_dst;
		connp->conn_faddr_v6 = ip6h->ip6_src;
		connp->conn_saddr_v6 = connp->conn_laddr_v6;

		sin6 = sin6_null;
		sin6.sin6_addr = connp->conn_faddr_v6;
		sin6.sin6_port = connp->conn_fport;
		sin6.sin6_family = AF_INET6;
		sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;
		sin6.__sin6_src_id = ip_srcid_find_addr(&connp->conn_laddr_v6,
		    IPCL_ZONEID(lconnp), tcps->tcps_netstack);

		if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src)) {
			/* Pass up the scope_id of remote addr */
			sin6.sin6_scope_id = ifindex;
		} else {
			sin6.sin6_scope_id = 0;
		}
		if (connp->conn_recv_ancillary.crb_recvdstaddr) {
			sin6_t	sin6d;

			sin6d = sin6_null;
			sin6.sin6_addr = connp->conn_laddr_v6;
			sin6d.sin6_port = connp->conn_lport;
			sin6d.sin6_family = AF_INET6;
			if (IN6_IS_ADDR_LINKSCOPE(&connp->conn_laddr_v6))
				sin6d.sin6_scope_id = ifindex;

			tpi_mp = mi_tpi_extconn_ind(NULL,
			    (char *)&sin6d, sizeof (sin6_t),
			    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
			    (char *)&sin6d, sizeof (sin6_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		} else {
			tpi_mp = mi_tpi_conn_ind(NULL,
			    (char *)&sin6, sizeof (sin6_t),
			    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		}
	}

	tcp->tcp_mss = tcps->tcps_mss_def_ipv6;
	return (tpi_mp);
}

/* Handle a SYN on an AF_INET socket */
static mblk_t *
tcp_conn_create_v4(conn_t *lconnp, conn_t *connp, mblk_t *mp,
    ip_recv_attr_t *ira)
{
	tcp_t 		*ltcp = lconnp->conn_tcp;
	tcp_t		*tcp = connp->conn_tcp;
	sin_t		sin;
	mblk_t		*tpi_mp = NULL;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ipha_t		*ipha;

	ASSERT(ira->ira_flags & IRAF_IS_IPV4);
	ipha = (ipha_t *)mp->b_rptr;

	connp->conn_ipversion = IPV4_VERSION;
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &connp->conn_laddr_v6);
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &connp->conn_faddr_v6);
	connp->conn_saddr_v6 = connp->conn_laddr_v6;

	sin = sin_null;
	sin.sin_addr.s_addr = connp->conn_faddr_v4;
	sin.sin_port = connp->conn_fport;
	sin.sin_family = AF_INET;
	if (lconnp->conn_recv_ancillary.crb_recvdstaddr) {
		sin_t	sind;

		sind = sin_null;
		sind.sin_addr.s_addr = connp->conn_laddr_v4;
		sind.sin_port = connp->conn_lport;
		sind.sin_family = AF_INET;
		tpi_mp = mi_tpi_extconn_ind(NULL,
		    (char *)&sind, sizeof (sin_t), (char *)&tcp,
		    (t_scalar_t)sizeof (intptr_t), (char *)&sind,
		    sizeof (sin_t), (t_scalar_t)ltcp->tcp_conn_req_seqnum);
	} else {
		tpi_mp = mi_tpi_conn_ind(NULL,
		    (char *)&sin, sizeof (sin_t),
		    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
		    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
	}

	tcp->tcp_mss = tcps->tcps_mss_def_ipv4;
	return (tpi_mp);
}

/*
 * Called via squeue to get on to eager's perimeter. It sends a
 * TH_RST if eager is in the fanout table. The listener wants the
 * eager to disappear either by means of tcp_eager_blowoff() or
 * tcp_eager_cleanup() being called. tcp_eager_kill() can also be
 * called (via squeue) if the eager cannot be inserted in the
 * fanout table in tcp_input_listener().
 */
/* ARGSUSED */
void
tcp_eager_kill(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t	*econnp = (conn_t *)arg;
	tcp_t	*eager = econnp->conn_tcp;
	tcp_t	*listener = eager->tcp_listener;

	/*
	 * We could be called because listener is closing. Since
	 * the eager was using listener's queue's, we avoid
	 * using the listeners queues from now on.
	 */
	ASSERT(eager->tcp_detached);
	econnp->conn_rq = NULL;
	econnp->conn_wq = NULL;

	/*
	 * An eager's conn_fanout will be NULL if it's a duplicate
	 * for an existing 4-tuples in the conn fanout table.
	 * We don't want to send an RST out in such case.
	 */
	if (econnp->conn_fanout != NULL && eager->tcp_state > TCPS_LISTEN) {
		tcp_xmit_ctl("tcp_eager_kill, can't wait",
		    eager, eager->tcp_snxt, 0, TH_RST);
	}

	/* We are here because listener wants this eager gone */
	if (listener != NULL) {
		mutex_enter(&listener->tcp_eager_lock);
		tcp_eager_unlink(eager);
		if (eager->tcp_tconnind_started) {
			/*
			 * The eager has sent a conn_ind up to the
			 * listener but listener decides to close
			 * instead. We need to drop the extra ref
			 * placed on eager in tcp_input_data() before
			 * sending the conn_ind to listener.
			 */
			CONN_DEC_REF(econnp);
		}
		mutex_exit(&listener->tcp_eager_lock);
		CONN_DEC_REF(listener->tcp_connp);
	}

	if (eager->tcp_state != TCPS_CLOSED)
		tcp_close_detached(eager);
}

/*
 * Reset any eager connection hanging off this listener marked
 * with 'seqnum' and then reclaim it's resources.
 */
boolean_t
tcp_eager_blowoff(tcp_t	*listener, t_scalar_t seqnum)
{
	tcp_t	*eager;
	mblk_t 	*mp;

	eager = listener;
	mutex_enter(&listener->tcp_eager_lock);
	do {
		eager = eager->tcp_eager_next_q;
		if (eager == NULL) {
			mutex_exit(&listener->tcp_eager_lock);
			return (B_FALSE);
		}
	} while (eager->tcp_conn_req_seqnum != seqnum);

	if (eager->tcp_closemp_used) {
		mutex_exit(&listener->tcp_eager_lock);
		return (B_TRUE);
	}
	eager->tcp_closemp_used = B_TRUE;
	TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
	CONN_INC_REF(eager->tcp_connp);
	mutex_exit(&listener->tcp_eager_lock);
	mp = &eager->tcp_closemp;
	SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp, tcp_eager_kill,
	    eager->tcp_connp, NULL, SQ_FILL, SQTAG_TCP_EAGER_BLOWOFF);
	return (B_TRUE);
}

/*
 * Reset any eager connection hanging off this listener
 * and then reclaim it's resources.
 */
void
tcp_eager_cleanup(tcp_t *listener, boolean_t q0_only)
{
	tcp_t	*eager;
	mblk_t	*mp;
	tcp_stack_t	*tcps = listener->tcp_tcps;

	ASSERT(MUTEX_HELD(&listener->tcp_eager_lock));

	if (!q0_only) {
		/* First cleanup q */
		TCP_STAT(tcps, tcp_eager_blowoff_q);
		eager = listener->tcp_eager_next_q;
		while (eager != NULL) {
			if (!eager->tcp_closemp_used) {
				eager->tcp_closemp_used = B_TRUE;
				TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
				CONN_INC_REF(eager->tcp_connp);
				mp = &eager->tcp_closemp;
				SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp,
				    tcp_eager_kill, eager->tcp_connp, NULL,
				    SQ_FILL, SQTAG_TCP_EAGER_CLEANUP);
			}
			eager = eager->tcp_eager_next_q;
		}
	}
	/* Then cleanup q0 */
	TCP_STAT(tcps, tcp_eager_blowoff_q0);
	eager = listener->tcp_eager_next_q0;
	while (eager != listener) {
		if (!eager->tcp_closemp_used) {
			eager->tcp_closemp_used = B_TRUE;
			TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
			CONN_INC_REF(eager->tcp_connp);
			mp = &eager->tcp_closemp;
			SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp,
			    tcp_eager_kill, eager->tcp_connp, NULL, SQ_FILL,
			    SQTAG_TCP_EAGER_CLEANUP_Q0);
		}
		eager = eager->tcp_eager_next_q0;
	}
}

/*
 * If we are an eager connection hanging off a listener that hasn't
 * formally accepted the connection yet, get off his list and blow off
 * any data that we have accumulated.
 */
void
tcp_eager_unlink(tcp_t *tcp)
{
	tcp_t	*listener = tcp->tcp_listener;

	ASSERT(listener != NULL);
	ASSERT(MUTEX_HELD(&listener->tcp_eager_lock));
	if (tcp->tcp_eager_next_q0 != NULL) {
		ASSERT(tcp->tcp_eager_prev_q0 != NULL);

		/* Remove the eager tcp from q0 */
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
		listener->tcp_conn_req_cnt_q0--;

		tcp->tcp_eager_next_q0 = NULL;
		tcp->tcp_eager_prev_q0 = NULL;

		/*
		 * Take the eager out, if it is in the list of droppable
		 * eagers.
		 */
		MAKE_UNDROPPABLE(tcp);

		if (tcp->tcp_syn_rcvd_timeout != 0) {
			/* we have timed out before */
			ASSERT(listener->tcp_syn_rcvd_timeout > 0);
			listener->tcp_syn_rcvd_timeout--;
		}
	} else {
		tcp_t   **tcpp = &listener->tcp_eager_next_q;
		tcp_t	*prev = NULL;

		for (; tcpp[0]; tcpp = &tcpp[0]->tcp_eager_next_q) {
			if (tcpp[0] == tcp) {
				if (listener->tcp_eager_last_q == tcp) {
					/*
					 * If we are unlinking the last
					 * element on the list, adjust
					 * tail pointer. Set tail pointer
					 * to nil when list is empty.
					 */
					ASSERT(tcp->tcp_eager_next_q == NULL);
					if (listener->tcp_eager_last_q ==
					    listener->tcp_eager_next_q) {
						listener->tcp_eager_last_q =
						    NULL;
					} else {
						/*
						 * We won't get here if there
						 * is only one eager in the
						 * list.
						 */
						ASSERT(prev != NULL);
						listener->tcp_eager_last_q =
						    prev;
					}
				}
				tcpp[0] = tcp->tcp_eager_next_q;
				tcp->tcp_eager_next_q = NULL;
				tcp->tcp_eager_last_q = NULL;
				ASSERT(listener->tcp_conn_req_cnt_q > 0);
				listener->tcp_conn_req_cnt_q--;
				break;
			}
			prev = tcpp[0];
		}
	}
	tcp->tcp_listener = NULL;
}

/* BEGIN CSTYLED */
/*
 *
 * The sockfs ACCEPT path:
 * =======================
 *
 * The eager is now established in its own perimeter as soon as SYN is
 * received in tcp_input_listener(). When sockfs receives conn_ind, it
 * completes the accept processing on the acceptor STREAM. The sending
 * of conn_ind part is common for both sockfs listener and a TLI/XTI
 * listener but a TLI/XTI listener completes the accept processing
 * on the listener perimeter.
 *
 * Common control flow for 3 way handshake:
 * ----------------------------------------
 *
 * incoming SYN (listener perimeter)	-> tcp_input_listener()
 *
 * incoming SYN-ACK-ACK (eager perim) 	-> tcp_input_data()
 * send T_CONN_IND (listener perim)	-> tcp_send_conn_ind()
 *
 * Sockfs ACCEPT Path:
 * -------------------
 *
 * open acceptor stream (tcp_open allocates tcp_tli_accept()
 * as STREAM entry point)
 *
 * soaccept() sends T_CONN_RES on the acceptor STREAM to tcp_tli_accept()
 *
 * tcp_tli_accept() extracts the eager and makes the q->q_ptr <-> eager
 * association (we are not behind eager's squeue but sockfs is protecting us
 * and no one knows about this stream yet. The STREAMS entry point q->q_info
 * is changed to point at tcp_wput().
 *
 * tcp_accept_common() sends any deferred eagers via tcp_send_pending() to
 * listener (done on listener's perimeter).
 *
 * tcp_tli_accept() calls tcp_accept_finish() on eagers perimeter to finish
 * accept.
 *
 * TLI/XTI client ACCEPT path:
 * ---------------------------
 *
 * soaccept() sends T_CONN_RES on the listener STREAM.
 *
 * tcp_tli_accept() -> tcp_accept_swap() complete the processing and send
 * a M_SETOPS mblk to eager perimeter to finish accept (tcp_accept_finish()).
 *
 * Locks:
 * ======
 *
 * listener->tcp_eager_lock protects the listeners->tcp_eager_next_q0 and
 * and listeners->tcp_eager_next_q.
 *
 * Referencing:
 * ============
 *
 * 1) We start out in tcp_input_listener by eager placing a ref on
 * listener and listener adding eager to listeners->tcp_eager_next_q0.
 *
 * 2) When a SYN-ACK-ACK arrives, we send the conn_ind to listener. Before
 * doing so we place a ref on the eager. This ref is finally dropped at the
 * end of tcp_accept_finish() while unwinding from the squeue, i.e. the
 * reference is dropped by the squeue framework.
 *
 * 3) The ref on listener placed in 1 above is dropped in tcp_accept_finish
 *
 * The reference must be released by the same entity that added the reference
 * In the above scheme, the eager is the entity that adds and releases the
 * references. Note that tcp_accept_finish executes in the squeue of the eager
 * (albeit after it is attached to the acceptor stream). Though 1. executes
 * in the listener's squeue, the eager is nascent at this point and the
 * reference can be considered to have been added on behalf of the eager.
 *
 * Eager getting a Reset or listener closing:
 * ==========================================
 *
 * Once the listener and eager are linked, the listener never does the unlink.
 * If the listener needs to close, tcp_eager_cleanup() is called which queues
 * a message on all eager perimeter. The eager then does the unlink, clears
 * any pointers to the listener's queue and drops the reference to the
 * listener. The listener waits in tcp_close outside the squeue until its
 * refcount has dropped to 1. This ensures that the listener has waited for
 * all eagers to clear their association with the listener.
 *
 * Similarly, if eager decides to go away, it can unlink itself and close.
 * When the T_CONN_RES comes down, we check if eager has closed. Note that
 * the reference to eager is still valid because of the extra ref we put
 * in tcp_send_conn_ind.
 *
 * Listener can always locate the eager under the protection
 * of the listener->tcp_eager_lock, and then do a refhold
 * on the eager during the accept processing.
 *
 * The acceptor stream accesses the eager in the accept processing
 * based on the ref placed on eager before sending T_conn_ind.
 * The only entity that can negate this refhold is a listener close
 * which is mutually exclusive with an active acceptor stream.
 *
 * Eager's reference on the listener
 * ===================================
 *
 * If the accept happens (even on a closed eager) the eager drops its
 * reference on the listener at the start of tcp_accept_finish. If the
 * eager is killed due to an incoming RST before the T_conn_ind is sent up,
 * the reference is dropped in tcp_closei_local. If the listener closes,
 * the reference is dropped in tcp_eager_kill. In all cases the reference
 * is dropped while executing in the eager's context (squeue).
 */
/* END CSTYLED */

/* Process the SYN packet, mp, directed at the listener 'tcp' */

/*
 * THIS FUNCTION IS DIRECTLY CALLED BY IP VIA SQUEUE FOR SYN.
 * tcp_input_data will not see any packets for listeners since the listener
 * has conn_recv set to tcp_input_listener.
 */
/* ARGSUSED */
static void
tcp_input_listener(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	tcpha_t		*tcpha;
	uint32_t	seg_seq;
	tcp_t		*eager;
	int		err;
	conn_t		*econnp = NULL;
	squeue_t	*new_sqp;
	mblk_t		*mp1;
	uint_t 		ip_hdr_len;
	conn_t		*lconnp = (conn_t *)arg;
	tcp_t		*listener = lconnp->conn_tcp;
	tcp_stack_t	*tcps = listener->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;
	uint_t		flags;
	mblk_t		*tpi_mp;
	uint_t		ifindex = ira->ira_ruifindex;
	boolean_t	tlc_set = B_FALSE;

	ip_hdr_len = ira->ira_ip_hdr_length;
	tcpha = (tcpha_t *)&mp->b_rptr[ip_hdr_len];
	flags = (unsigned int)tcpha->tha_flags & 0xFF;

	DTRACE_TCP5(receive, mblk_t *, NULL, ip_xmit_attr_t *, lconnp->conn_ixa,
	    __dtrace_tcp_void_ip_t *, mp->b_rptr, tcp_t *, listener,
	    __dtrace_tcp_tcph_t *, tcpha);

	if (!(flags & TH_SYN)) {
		if ((flags & TH_RST) || (flags & TH_URG)) {
			freemsg(mp);
			return;
		}
		if (flags & TH_ACK) {
			/* Note this executes in listener's squeue */
			tcp_xmit_listeners_reset(mp, ira, ipst, lconnp);
			return;
		}

		freemsg(mp);
		return;
	}

	if (listener->tcp_state != TCPS_LISTEN)
		goto error2;

	ASSERT(IPCL_IS_BOUND(lconnp));

	mutex_enter(&listener->tcp_eager_lock);

	/*
	 * The system is under memory pressure, so we need to do our part
	 * to relieve the pressure.  So we only accept new request if there
	 * is nothing waiting to be accepted or waiting to complete the 3-way
	 * handshake.  This means that busy listener will not get too many
	 * new requests which they cannot handle in time while non-busy
	 * listener is still functioning properly.
	 */
	if (tcps->tcps_reclaim && (listener->tcp_conn_req_cnt_q > 0 ||
	    listener->tcp_conn_req_cnt_q0 > 0)) {
		mutex_exit(&listener->tcp_eager_lock);
		TCP_STAT(tcps, tcp_listen_mem_drop);
		goto error2;
	}

	if (listener->tcp_conn_req_cnt_q >= listener->tcp_conn_req_max) {
		mutex_exit(&listener->tcp_eager_lock);
		TCP_STAT(tcps, tcp_listendrop);
		TCPS_BUMP_MIB(tcps, tcpListenDrop);
		if (lconnp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE|SL_ERROR,
			    "tcp_input_listener: listen backlog (max=%d) "
			    "overflow (%d pending) on %s",
			    listener->tcp_conn_req_max,
			    listener->tcp_conn_req_cnt_q,
			    tcp_display(listener, NULL, DISP_PORT_ONLY));
		}
		goto error2;
	}

	if (listener->tcp_conn_req_cnt_q0 >=
	    listener->tcp_conn_req_max + tcps->tcps_conn_req_max_q0) {
		/*
		 * Q0 is full. Drop a pending half-open req from the queue
		 * to make room for the new SYN req. Also mark the time we
		 * drop a SYN.
		 *
		 * A more aggressive defense against SYN attack will
		 * be to set the "tcp_syn_defense" flag now.
		 */
		TCP_STAT(tcps, tcp_listendropq0);
		listener->tcp_last_rcv_lbolt = ddi_get_lbolt64();
		if (!tcp_drop_q0(listener)) {
			mutex_exit(&listener->tcp_eager_lock);
			TCPS_BUMP_MIB(tcps, tcpListenDropQ0);
			if (lconnp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 3, SL_TRACE,
				    "tcp_input_listener: listen half-open "
				    "queue (max=%d) full (%d pending) on %s",
				    tcps->tcps_conn_req_max_q0,
				    listener->tcp_conn_req_cnt_q0,
				    tcp_display(listener, NULL,
				    DISP_PORT_ONLY));
			}
			goto error2;
		}
	}

	/*
	 * Enforce the limit set on the number of connections per listener.
	 * Note that tlc_cnt starts with 1.  So need to add 1 to tlc_max
	 * for comparison.
	 */
	if (listener->tcp_listen_cnt != NULL) {
		tcp_listen_cnt_t *tlc = listener->tcp_listen_cnt;
		int64_t now;

		if (atomic_inc_32_nv(&tlc->tlc_cnt) > tlc->tlc_max + 1) {
			mutex_exit(&listener->tcp_eager_lock);
			now = ddi_get_lbolt64();
			atomic_dec_32(&tlc->tlc_cnt);
			TCP_STAT(tcps, tcp_listen_cnt_drop);
			tlc->tlc_drop++;
			if (now - tlc->tlc_report_time >
			    MSEC_TO_TICK(TCP_TLC_REPORT_INTERVAL)) {
				zcmn_err(lconnp->conn_zoneid, CE_WARN,
				    "Listener (port %d) connection max (%u) "
				    "reached: %u attempts dropped total\n",
				    ntohs(listener->tcp_connp->conn_lport),
				    tlc->tlc_max, tlc->tlc_drop);
				tlc->tlc_report_time = now;
			}
			goto error2;
		}
		tlc_set = B_TRUE;
	}

	mutex_exit(&listener->tcp_eager_lock);

	/*
	 * IP sets ira_sqp to either the senders conn_sqp (for loopback)
	 * or based on the ring (for packets from GLD). Otherwise it is
	 * set based on lbolt i.e., a somewhat random number.
	 */
	ASSERT(ira->ira_sqp != NULL);
	new_sqp = ira->ira_sqp;

	econnp = (conn_t *)tcp_get_conn(arg2, tcps);
	if (econnp == NULL)
		goto error2;

	ASSERT(econnp->conn_netstack == lconnp->conn_netstack);
	econnp->conn_sqp = new_sqp;
	econnp->conn_initial_sqp = new_sqp;
	econnp->conn_ixa->ixa_sqp = new_sqp;

	econnp->conn_fport = tcpha->tha_lport;
	econnp->conn_lport = tcpha->tha_fport;

	err = conn_inherit_parent(lconnp, econnp);
	if (err != 0)
		goto error3;

	/* We already know the laddr of the new connection is ours */
	econnp->conn_ixa->ixa_src_generation = ipst->ips_src_generation;

	ASSERT(OK_32PTR(mp->b_rptr));
	ASSERT(IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION ||
	    IPH_HDR_VERSION(mp->b_rptr) == IPV6_VERSION);

	if (lconnp->conn_family == AF_INET) {
		ASSERT(IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION);
		tpi_mp = tcp_conn_create_v4(lconnp, econnp, mp, ira);
	} else {
		tpi_mp = tcp_conn_create_v6(lconnp, econnp, mp, ira);
	}

	if (tpi_mp == NULL)
		goto error3;

	eager = econnp->conn_tcp;
	eager->tcp_detached = B_TRUE;
	SOCK_CONNID_INIT(eager->tcp_connid);

	/*
	 * Initialize the eager's tcp_t and inherit some parameters from
	 * the listener.
	 */
	tcp_init_values(eager, listener);

	ASSERT((econnp->conn_ixa->ixa_flags &
	    (IXAF_SET_ULP_CKSUM | IXAF_VERIFY_SOURCE |
	    IXAF_VERIFY_PMTU | IXAF_VERIFY_LSO)) ==
	    (IXAF_SET_ULP_CKSUM | IXAF_VERIFY_SOURCE |
	    IXAF_VERIFY_PMTU | IXAF_VERIFY_LSO));

	if (!tcps->tcps_dev_flow_ctl)
		econnp->conn_ixa->ixa_flags |= IXAF_NO_DEV_FLOW_CTL;

	/* Prepare for diffing against previous packets */
	eager->tcp_recvifindex = 0;
	eager->tcp_recvhops = 0xffffffffU;

	if (!(ira->ira_flags & IRAF_IS_IPV4) && econnp->conn_bound_if == 0) {
		if (IN6_IS_ADDR_LINKSCOPE(&econnp->conn_faddr_v6) ||
		    IN6_IS_ADDR_LINKSCOPE(&econnp->conn_laddr_v6)) {
			econnp->conn_incoming_ifindex = ifindex;
			econnp->conn_ixa->ixa_flags |= IXAF_SCOPEID_SET;
			econnp->conn_ixa->ixa_scopeid = ifindex;
		}
	}

	if ((ira->ira_flags & (IRAF_IS_IPV4|IRAF_IPV4_OPTIONS)) ==
	    (IRAF_IS_IPV4|IRAF_IPV4_OPTIONS) &&
	    tcps->tcps_rev_src_routes) {
		ipha_t *ipha = (ipha_t *)mp->b_rptr;
		ip_pkt_t *ipp = &econnp->conn_xmit_ipp;

		/* Source routing option copyover (reverse it) */
		err = ip_find_hdr_v4(ipha, ipp, B_TRUE);
		if (err != 0) {
			freemsg(tpi_mp);
			goto error3;
		}
		ip_pkt_source_route_reverse_v4(ipp);
	}

	ASSERT(eager->tcp_conn.tcp_eager_conn_ind == NULL);
	ASSERT(!eager->tcp_tconnind_started);
	/*
	 * If the SYN came with a credential, it's a loopback packet or a
	 * labeled packet; attach the credential to the TPI message.
	 */
	if (ira->ira_cred != NULL)
		mblk_setcred(tpi_mp, ira->ira_cred, ira->ira_cpid);

	eager->tcp_conn.tcp_eager_conn_ind = tpi_mp;
	ASSERT(eager->tcp_ordrel_mp == NULL);

	/* Inherit the listener's non-STREAMS flag */
	if (IPCL_IS_NONSTR(lconnp)) {
		econnp->conn_flags |= IPCL_NONSTR;
		/* All non-STREAMS tcp_ts are sockets */
		eager->tcp_issocket = B_TRUE;
	} else {
		/*
		 * Pre-allocate the T_ordrel_ind mblk for TPI socket so that
		 * at close time, we will always have that to send up.
		 * Otherwise, we need to do special handling in case the
		 * allocation fails at that time.
		 */
		if ((eager->tcp_ordrel_mp = mi_tpi_ordrel_ind()) == NULL)
			goto error3;
	}
	/*
	 * Now that the IP addresses and ports are setup in econnp we
	 * can do the IPsec policy work.
	 */
	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		if (lconnp->conn_policy != NULL) {
			/*
			 * Inherit the policy from the listener; use
			 * actions from ira
			 */
			if (!ip_ipsec_policy_inherit(econnp, lconnp, ira)) {
				CONN_DEC_REF(econnp);
				freemsg(mp);
				goto error3;
			}
		}
	}

	/*
	 * tcp_set_destination() may set tcp_rwnd according to the route
	 * metrics. If it does not, the eager's receive window will be set
	 * to the listener's receive window later in this function.
	 */
	eager->tcp_rwnd = 0;

	if (is_system_labeled()) {
		ip_xmit_attr_t *ixa = econnp->conn_ixa;

		ASSERT(ira->ira_tsl != NULL);
		/* Discard any old label */
		if (ixa->ixa_free_flags & IXA_FREE_TSL) {
			ASSERT(ixa->ixa_tsl != NULL);
			label_rele(ixa->ixa_tsl);
			ixa->ixa_free_flags &= ~IXA_FREE_TSL;
			ixa->ixa_tsl = NULL;
		}
		if ((lconnp->conn_mlp_type != mlptSingle ||
		    lconnp->conn_mac_mode != CONN_MAC_DEFAULT) &&
		    ira->ira_tsl != NULL) {
			/*
			 * If this is an MLP connection or a MAC-Exempt
			 * connection with an unlabeled node, packets are to be
			 * exchanged using the security label of the received
			 * SYN packet instead of the server application's label.
			 * tsol_check_dest called from ip_set_destination
			 * might later update TSF_UNLABELED by replacing
			 * ixa_tsl with a new label.
			 */
			label_hold(ira->ira_tsl);
			ip_xmit_attr_replace_tsl(ixa, ira->ira_tsl);
			DTRACE_PROBE2(mlp_syn_accept, conn_t *,
			    econnp, ts_label_t *, ixa->ixa_tsl)
		} else {
			ixa->ixa_tsl = crgetlabel(econnp->conn_cred);
			DTRACE_PROBE2(syn_accept, conn_t *,
			    econnp, ts_label_t *, ixa->ixa_tsl)
		}
		/*
		 * conn_connect() called from tcp_set_destination will verify
		 * the destination is allowed to receive packets at the
		 * security label of the SYN-ACK we are generating. As part of
		 * that, tsol_check_dest() may create a new effective label for
		 * this connection.
		 * Finally conn_connect() will call conn_update_label.
		 * All that remains for TCP to do is to call
		 * conn_build_hdr_template which is done as part of
		 * tcp_set_destination.
		 */
	}

	/*
	 * Since we will clear tcp_listener before we clear tcp_detached
	 * in the accept code we need tcp_hard_binding aka tcp_accept_inprogress
	 * so we can tell a TCP_IS_DETACHED_NONEAGER apart.
	 */
	eager->tcp_hard_binding = B_TRUE;

	tcp_bind_hash_insert(&tcps->tcps_bind_fanout[
	    TCP_BIND_HASH(econnp->conn_lport)], eager, 0);

	CL_INET_CONNECT(econnp, B_FALSE, err);
	if (err != 0) {
		tcp_bind_hash_remove(eager);
		goto error3;
	}

	SOCK_CONNID_BUMP(eager->tcp_connid);

	/*
	 * Adapt our mss, ttl, ... based on the remote address.
	 */

	if (tcp_set_destination(eager) != 0) {
		TCPS_BUMP_MIB(tcps, tcpAttemptFails);
		/* Undo the bind_hash_insert */
		tcp_bind_hash_remove(eager);
		goto error3;
	}

	/* Process all TCP options. */
	tcp_process_options(eager, tcpha);

	/* Is the other end ECN capable? */
	if (tcps->tcps_ecn_permitted >= 1 &&
	    (tcpha->tha_flags & (TH_ECE|TH_CWR)) == (TH_ECE|TH_CWR)) {
		eager->tcp_ecn_ok = B_TRUE;
	}

	/*
	 * The listener's conn_rcvbuf should be the default window size or a
	 * window size changed via SO_RCVBUF option. First round up the
	 * eager's tcp_rwnd to the nearest MSS. Then find out the window
	 * scale option value if needed. Call tcp_rwnd_set() to finish the
	 * setting.
	 *
	 * Note if there is a rpipe metric associated with the remote host,
	 * we should not inherit receive window size from listener.
	 */
	eager->tcp_rwnd = MSS_ROUNDUP(
	    (eager->tcp_rwnd == 0 ? econnp->conn_rcvbuf :
	    eager->tcp_rwnd), eager->tcp_mss);
	if (eager->tcp_snd_ws_ok)
		tcp_set_ws_value(eager);
	/*
	 * Note that this is the only place tcp_rwnd_set() is called for
	 * accepting a connection.  We need to call it here instead of
	 * after the 3-way handshake because we need to tell the other
	 * side our rwnd in the SYN-ACK segment.
	 */
	(void) tcp_rwnd_set(eager, eager->tcp_rwnd);

	ASSERT(eager->tcp_connp->conn_rcvbuf != 0 &&
	    eager->tcp_connp->conn_rcvbuf == eager->tcp_rwnd);

	ASSERT(econnp->conn_rcvbuf != 0 &&
	    econnp->conn_rcvbuf == eager->tcp_rwnd);

	/* Put a ref on the listener for the eager. */
	CONN_INC_REF(lconnp);
	mutex_enter(&listener->tcp_eager_lock);
	listener->tcp_eager_next_q0->tcp_eager_prev_q0 = eager;
	eager->tcp_eager_next_q0 = listener->tcp_eager_next_q0;
	listener->tcp_eager_next_q0 = eager;
	eager->tcp_eager_prev_q0 = listener;

	/* Set tcp_listener before adding it to tcp_conn_fanout */
	eager->tcp_listener = listener;
	eager->tcp_saved_listener = listener;

	/*
	 * Set tcp_listen_cnt so that when the connection is done, the counter
	 * is decremented.
	 */
	eager->tcp_listen_cnt = listener->tcp_listen_cnt;

	/*
	 * Tag this detached tcp vector for later retrieval
	 * by our listener client in tcp_accept().
	 */
	eager->tcp_conn_req_seqnum = listener->tcp_conn_req_seqnum;
	listener->tcp_conn_req_cnt_q0++;
	if (++listener->tcp_conn_req_seqnum == -1) {
		/*
		 * -1 is "special" and defined in TPI as something
		 * that should never be used in T_CONN_IND
		 */
		++listener->tcp_conn_req_seqnum;
	}
	mutex_exit(&listener->tcp_eager_lock);

	if (listener->tcp_syn_defense) {
		/* Don't drop the SYN that comes from a good IP source */
		ipaddr_t *addr_cache;

		addr_cache = (ipaddr_t *)(listener->tcp_ip_addr_cache);
		if (addr_cache != NULL && econnp->conn_faddr_v4 ==
		    addr_cache[IP_ADDR_CACHE_HASH(econnp->conn_faddr_v4)]) {
			eager->tcp_dontdrop = B_TRUE;
		}
	}

	/*
	 * We need to insert the eager in its own perimeter but as soon
	 * as we do that, we expose the eager to the classifier and
	 * should not touch any field outside the eager's perimeter.
	 * So do all the work necessary before inserting the eager
	 * in its own perimeter. Be optimistic that conn_connect()
	 * will succeed but undo everything if it fails.
	 */
	seg_seq = ntohl(tcpha->tha_seq);
	eager->tcp_irs = seg_seq;
	eager->tcp_rack = seg_seq;
	eager->tcp_rnxt = seg_seq + 1;
	eager->tcp_tcpha->tha_ack = htonl(eager->tcp_rnxt);
	TCPS_BUMP_MIB(tcps, tcpPassiveOpens);
	eager->tcp_state = TCPS_SYN_RCVD;
	DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
	    econnp->conn_ixa, void, NULL, tcp_t *, eager, void, NULL,
	    int32_t, TCPS_LISTEN);

	mp1 = tcp_xmit_mp(eager, eager->tcp_xmit_head, eager->tcp_mss,
	    NULL, NULL, eager->tcp_iss, B_FALSE, NULL, B_FALSE);
	if (mp1 == NULL) {
		/*
		 * Increment the ref count as we are going to
		 * enqueueing an mp in squeue
		 */
		CONN_INC_REF(econnp);
		goto error;
	}

	/*
	 * We need to start the rto timer. In normal case, we start
	 * the timer after sending the packet on the wire (or at
	 * least believing that packet was sent by waiting for
	 * conn_ip_output() to return). Since this is the first packet
	 * being sent on the wire for the eager, our initial tcp_rto
	 * is at least tcp_rexmit_interval_min which is a fairly
	 * large value to allow the algorithm to adjust slowly to large
	 * fluctuations of RTT during first few transmissions.
	 *
	 * Starting the timer first and then sending the packet in this
	 * case shouldn't make much difference since tcp_rexmit_interval_min
	 * is of the order of several 100ms and starting the timer
	 * first and then sending the packet will result in difference
	 * of few micro seconds.
	 *
	 * Without this optimization, we are forced to hold the fanout
	 * lock across the ipcl_bind_insert() and sending the packet
	 * so that we don't race against an incoming packet (maybe RST)
	 * for this eager.
	 *
	 * It is necessary to acquire an extra reference on the eager
	 * at this point and hold it until after tcp_send_data() to
	 * ensure against an eager close race.
	 */

	CONN_INC_REF(econnp);

	TCP_TIMER_RESTART(eager, eager->tcp_rto);

	/*
	 * Insert the eager in its own perimeter now. We are ready to deal
	 * with any packets on eager.
	 */
	if (ipcl_conn_insert(econnp) != 0)
		goto error;

	ASSERT(econnp->conn_ixa->ixa_notify_cookie == econnp->conn_tcp);
	freemsg(mp);
	/*
	 * Send the SYN-ACK. Use the right squeue so that conn_ixa is
	 * only used by one thread at a time.
	 */
	if (econnp->conn_sqp == lconnp->conn_sqp) {
		DTRACE_TCP5(send, mblk_t *, NULL, ip_xmit_attr_t *,
		    econnp->conn_ixa, __dtrace_tcp_void_ip_t *, mp1->b_rptr,
		    tcp_t *, eager, __dtrace_tcp_tcph_t *,
		    &mp1->b_rptr[econnp->conn_ixa->ixa_ip_hdr_length]);
		(void) conn_ip_output(mp1, econnp->conn_ixa);
		CONN_DEC_REF(econnp);
	} else {
		SQUEUE_ENTER_ONE(econnp->conn_sqp, mp1, tcp_send_synack,
		    econnp, NULL, SQ_PROCESS, SQTAG_TCP_SEND_SYNACK);
	}
	return;
error:
	freemsg(mp1);
	eager->tcp_closemp_used = B_TRUE;
	TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
	mp1 = &eager->tcp_closemp;
	SQUEUE_ENTER_ONE(econnp->conn_sqp, mp1, tcp_eager_kill,
	    econnp, NULL, SQ_FILL, SQTAG_TCP_CONN_REQ_2);

	/*
	 * If a connection already exists, send the mp to that connections so
	 * that it can be appropriately dealt with.
	 */
	ipst = tcps->tcps_netstack->netstack_ip;

	if ((econnp = ipcl_classify(mp, ira, ipst)) != NULL) {
		if (!IPCL_IS_CONNECTED(econnp)) {
			/*
			 * Something bad happened. ipcl_conn_insert()
			 * failed because a connection already existed
			 * in connected hash but we can't find it
			 * anymore (someone blew it away). Just
			 * free this message and hopefully remote
			 * will retransmit at which time the SYN can be
			 * treated as a new connection or dealth with
			 * a TH_RST if a connection already exists.
			 */
			CONN_DEC_REF(econnp);
			freemsg(mp);
		} else {
			SQUEUE_ENTER_ONE(econnp->conn_sqp, mp, tcp_input_data,
			    econnp, ira, SQ_FILL, SQTAG_TCP_CONN_REQ_1);
		}
	} else {
		/* Nobody wants this packet */
		freemsg(mp);
	}
	return;
error3:
	CONN_DEC_REF(econnp);
error2:
	freemsg(mp);
	if (tlc_set)
		atomic_dec_32(&listener->tcp_listen_cnt->tlc_cnt);
}

/*
 * In an ideal case of vertical partition in NUMA architecture, its
 * beneficial to have the listener and all the incoming connections
 * tied to the same squeue. The other constraint is that incoming
 * connections should be tied to the squeue attached to interrupted
 * CPU for obvious locality reason so this leaves the listener to
 * be tied to the same squeue. Our only problem is that when listener
 * is binding, the CPU that will get interrupted by the NIC whose
 * IP address the listener is binding to is not even known. So
 * the code below allows us to change that binding at the time the
 * CPU is interrupted by virtue of incoming connection's squeue.
 *
 * This is usefull only in case of a listener bound to a specific IP
 * address. For other kind of listeners, they get bound the
 * very first time and there is no attempt to rebind them.
 */
void
tcp_input_listener_unbound(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira)
{
	conn_t		*connp = (conn_t *)arg;
	squeue_t	*sqp = (squeue_t *)arg2;
	squeue_t	*new_sqp;
	uint32_t	conn_flags;

	/*
	 * IP sets ira_sqp to either the senders conn_sqp (for loopback)
	 * or based on the ring (for packets from GLD). Otherwise it is
	 * set based on lbolt i.e., a somewhat random number.
	 */
	ASSERT(ira->ira_sqp != NULL);
	new_sqp = ira->ira_sqp;

	if (connp->conn_fanout == NULL)
		goto done;

	if (!(connp->conn_flags & IPCL_FULLY_BOUND)) {
		mutex_enter(&connp->conn_fanout->connf_lock);
		mutex_enter(&connp->conn_lock);
		/*
		 * No one from read or write side can access us now
		 * except for already queued packets on this squeue.
		 * But since we haven't changed the squeue yet, they
		 * can't execute. If they are processed after we have
		 * changed the squeue, they are sent back to the
		 * correct squeue down below.
		 * But a listner close can race with processing of
		 * incoming SYN. If incoming SYN processing changes
		 * the squeue then the listener close which is waiting
		 * to enter the squeue would operate on the wrong
		 * squeue. Hence we don't change the squeue here unless
		 * the refcount is exactly the minimum refcount. The
		 * minimum refcount of 4 is counted as - 1 each for
		 * TCP and IP, 1 for being in the classifier hash, and
		 * 1 for the mblk being processed.
		 */

		if (connp->conn_ref != 4 ||
		    connp->conn_tcp->tcp_state != TCPS_LISTEN) {
			mutex_exit(&connp->conn_lock);
			mutex_exit(&connp->conn_fanout->connf_lock);
			goto done;
		}
		if (connp->conn_sqp != new_sqp) {
			while (connp->conn_sqp != new_sqp)
				(void) atomic_cas_ptr(&connp->conn_sqp, sqp,
				    new_sqp);
			/* No special MT issues for outbound ixa_sqp hint */
			connp->conn_ixa->ixa_sqp = new_sqp;
		}

		do {
			conn_flags = connp->conn_flags;
			conn_flags |= IPCL_FULLY_BOUND;
			(void) atomic_cas_32(&connp->conn_flags,
			    connp->conn_flags, conn_flags);
		} while (!(connp->conn_flags & IPCL_FULLY_BOUND));

		mutex_exit(&connp->conn_fanout->connf_lock);
		mutex_exit(&connp->conn_lock);

		/*
		 * Assume we have picked a good squeue for the listener. Make
		 * subsequent SYNs not try to change the squeue.
		 */
		connp->conn_recv = tcp_input_listener;
	}

done:
	if (connp->conn_sqp != sqp) {
		CONN_INC_REF(connp);
		SQUEUE_ENTER_ONE(connp->conn_sqp, mp, connp->conn_recv, connp,
		    ira, SQ_FILL, SQTAG_TCP_CONN_REQ_UNBOUND);
	} else {
		tcp_input_listener(connp, mp, sqp, ira);
	}
}

/*
 * Send up all messages queued on tcp_rcv_list.
 */
uint_t
tcp_rcv_drain(tcp_t *tcp)
{
	mblk_t *mp;
	uint_t ret = 0;
#ifdef DEBUG
	uint_t cnt = 0;
#endif
	queue_t	*q = tcp->tcp_connp->conn_rq;

	/* Can't drain on an eager connection */
	if (tcp->tcp_listener != NULL)
		return (ret);

	/* Can't be a non-STREAMS connection */
	ASSERT(!IPCL_IS_NONSTR(tcp->tcp_connp));

	/* No need for the push timer now. */
	if (tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_push_tid);
		tcp->tcp_push_tid = 0;
	}

	/*
	 * Handle two cases here: we are currently fused or we were
	 * previously fused and have some urgent data to be delivered
	 * upstream.  The latter happens because we either ran out of
	 * memory or were detached and therefore sending the SIGURG was
	 * deferred until this point.  In either case we pass control
	 * over to tcp_fuse_rcv_drain() since it may need to complete
	 * some work.
	 */
	if ((tcp->tcp_fused || tcp->tcp_fused_sigurg)) {
		if (tcp_fuse_rcv_drain(q, tcp, tcp->tcp_fused ? NULL :
		    &tcp->tcp_fused_sigurg_mp))
			return (ret);
	}

	while ((mp = tcp->tcp_rcv_list) != NULL) {
		tcp->tcp_rcv_list = mp->b_next;
		mp->b_next = NULL;
#ifdef DEBUG
		cnt += msgdsize(mp);
#endif
		putnext(q, mp);
	}
#ifdef DEBUG
	ASSERT(cnt == tcp->tcp_rcv_cnt);
#endif
	tcp->tcp_rcv_last_head = NULL;
	tcp->tcp_rcv_last_tail = NULL;
	tcp->tcp_rcv_cnt = 0;

	if (canputnext(q))
		return (tcp_rwnd_reopen(tcp));

	return (ret);
}

/*
 * Queue data on tcp_rcv_list which is a b_next chain.
 * tcp_rcv_last_head/tail is the last element of this chain.
 * Each element of the chain is a b_cont chain.
 *
 * M_DATA messages are added to the current element.
 * Other messages are added as new (b_next) elements.
 */
void
tcp_rcv_enqueue(tcp_t *tcp, mblk_t *mp, uint_t seg_len, cred_t *cr)
{
	ASSERT(seg_len == msgdsize(mp));
	ASSERT(tcp->tcp_rcv_list == NULL || tcp->tcp_rcv_last_head != NULL);

	if (is_system_labeled()) {
		ASSERT(cr != NULL || msg_getcred(mp, NULL) != NULL);
		/*
		 * Provide for protocols above TCP such as RPC. NOPID leaves
		 * db_cpid unchanged.
		 * The cred could have already been set.
		 */
		if (cr != NULL)
			mblk_setcred(mp, cr, NOPID);
	}

	if (tcp->tcp_rcv_list == NULL) {
		ASSERT(tcp->tcp_rcv_last_head == NULL);
		tcp->tcp_rcv_list = mp;
		tcp->tcp_rcv_last_head = mp;
	} else if (DB_TYPE(mp) == DB_TYPE(tcp->tcp_rcv_last_head)) {
		tcp->tcp_rcv_last_tail->b_cont = mp;
	} else {
		tcp->tcp_rcv_last_head->b_next = mp;
		tcp->tcp_rcv_last_head = mp;
	}

	while (mp->b_cont)
		mp = mp->b_cont;

	tcp->tcp_rcv_last_tail = mp;
	tcp->tcp_rcv_cnt += seg_len;
	tcp->tcp_rwnd -= seg_len;
}

/* Generate an ACK-only (no data) segment for a TCP endpoint */
mblk_t *
tcp_ack_mp(tcp_t *tcp)
{
	uint32_t	seq_no;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	/*
	 * There are a few cases to be considered while setting the sequence no.
	 * Essentially, we can come here while processing an unacceptable pkt
	 * in the TCPS_SYN_RCVD state, in which case we set the sequence number
	 * to snxt (per RFC 793), note the swnd wouldn't have been set yet.
	 * If we are here for a zero window probe, stick with suna. In all
	 * other cases, we check if suna + swnd encompasses snxt and set
	 * the sequence number to snxt, if so. If snxt falls outside the
	 * window (the receiver probably shrunk its window), we will go with
	 * suna + swnd, otherwise the sequence no will be unacceptable to the
	 * receiver.
	 */
	if (tcp->tcp_zero_win_probe) {
		seq_no = tcp->tcp_suna;
	} else if (tcp->tcp_state == TCPS_SYN_RCVD) {
		ASSERT(tcp->tcp_swnd == 0);
		seq_no = tcp->tcp_snxt;
	} else {
		seq_no = SEQ_GT(tcp->tcp_snxt,
		    (tcp->tcp_suna + tcp->tcp_swnd)) ?
		    (tcp->tcp_suna + tcp->tcp_swnd) : tcp->tcp_snxt;
	}

	if (tcp->tcp_valid_bits) {
		/*
		 * For the complex case where we have to send some
		 * controls (FIN or SYN), let tcp_xmit_mp do it.
		 */
		return (tcp_xmit_mp(tcp, NULL, 0, NULL, NULL, seq_no, B_FALSE,
		    NULL, B_FALSE));
	} else {
		/* Generate a simple ACK */
		int	data_length;
		uchar_t	*rptr;
		tcpha_t	*tcpha;
		mblk_t	*mp1;
		int32_t	total_hdr_len;
		int32_t	tcp_hdr_len;
		int32_t	num_sack_blk = 0;
		int32_t sack_opt_len;
		ip_xmit_attr_t *ixa = connp->conn_ixa;

		/*
		 * Allocate space for TCP + IP headers
		 * and link-level header
		 */
		if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
			num_sack_blk = MIN(tcp->tcp_max_sack_blk,
			    tcp->tcp_num_sack_blk);
			sack_opt_len = num_sack_blk * sizeof (sack_blk_t) +
			    TCPOPT_NOP_LEN * 2 + TCPOPT_HEADER_LEN;
			total_hdr_len = connp->conn_ht_iphc_len + sack_opt_len;
			tcp_hdr_len = connp->conn_ht_ulp_len + sack_opt_len;
		} else {
			total_hdr_len = connp->conn_ht_iphc_len;
			tcp_hdr_len = connp->conn_ht_ulp_len;
		}
		mp1 = allocb(total_hdr_len + tcps->tcps_wroff_xtra, BPRI_MED);
		if (!mp1)
			return (NULL);

		/* Update the latest receive window size in TCP header. */
		tcp->tcp_tcpha->tha_win =
		    htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);
		/* copy in prototype TCP + IP header */
		rptr = mp1->b_rptr + tcps->tcps_wroff_xtra;
		mp1->b_rptr = rptr;
		mp1->b_wptr = rptr + total_hdr_len;
		bcopy(connp->conn_ht_iphc, rptr, connp->conn_ht_iphc_len);

		tcpha = (tcpha_t *)&rptr[ixa->ixa_ip_hdr_length];

		/* Set the TCP sequence number. */
		tcpha->tha_seq = htonl(seq_no);

		/* Set up the TCP flag field. */
		tcpha->tha_flags = (uchar_t)TH_ACK;
		if (tcp->tcp_ecn_echo_on)
			tcpha->tha_flags |= TH_ECE;

		tcp->tcp_rack = tcp->tcp_rnxt;
		tcp->tcp_rack_cnt = 0;

		/* fill in timestamp option if in use */
		if (tcp->tcp_snd_ts_ok) {
			uint32_t llbolt = (uint32_t)LBOLT_FASTPATH;

			U32_TO_BE32(llbolt,
			    (char *)tcpha + TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcpha + TCP_MIN_HEADER_LENGTH+8);
		}

		/* Fill in SACK options */
		if (num_sack_blk > 0) {
			uchar_t *wptr = (uchar_t *)tcpha +
			    connp->conn_ht_ulp_len;
			sack_blk_t *tmp;
			int32_t	i;

			wptr[0] = TCPOPT_NOP;
			wptr[1] = TCPOPT_NOP;
			wptr[2] = TCPOPT_SACK;
			wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
			    sizeof (sack_blk_t);
			wptr += TCPOPT_REAL_SACK_LEN;

			tmp = tcp->tcp_sack_list;
			for (i = 0; i < num_sack_blk; i++) {
				U32_TO_BE32(tmp[i].begin, wptr);
				wptr += sizeof (tcp_seq);
				U32_TO_BE32(tmp[i].end, wptr);
				wptr += sizeof (tcp_seq);
			}
			tcpha->tha_offset_and_reserved +=
			    ((num_sack_blk * 2 + 1) << 4);
		}

		ixa->ixa_pktlen = total_hdr_len;

		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			((ipha_t *)rptr)->ipha_length = htons(total_hdr_len);
		} else {
			ip6_t *ip6 = (ip6_t *)rptr;

			ip6->ip6_plen = htons(total_hdr_len - IPV6_HDR_LEN);
		}

		/*
		 * Prime pump for checksum calculation in IP.  Include the
		 * adjustment for a source route if any.
		 */
		data_length = tcp_hdr_len + connp->conn_sum;
		data_length = (data_length >> 16) + (data_length & 0xFFFF);
		tcpha->tha_sum = htons(data_length);

		if (tcp->tcp_ip_forward_progress) {
			tcp->tcp_ip_forward_progress = B_FALSE;
			connp->conn_ixa->ixa_flags |= IXAF_REACH_CONF;
		} else {
			connp->conn_ixa->ixa_flags &= ~IXAF_REACH_CONF;
		}
		return (mp1);
	}
}

/*
 * Dummy socket upcalls for if/when the conn_t gets detached from a
 * direct-callback sonode via a user-driven close().  Easy to catch with
 * DTrace FBT, and should be mostly harmless.
 */

/* ARGSUSED */
static sock_upper_handle_t
tcp_dummy_newconn(sock_upper_handle_t x, sock_lower_handle_t y,
    sock_downcalls_t *z, cred_t *cr, pid_t pid, sock_upcalls_t **ignored)
{
	ASSERT(0);	/* Panic in debug, otherwise ignore. */
	return (NULL);
}

/* ARGSUSED */
static void
tcp_dummy_connected(sock_upper_handle_t x, sock_connid_t y, cred_t *cr,
    pid_t pid)
{
	ASSERT(x == NULL);
	/* Normally we'd crhold(cr) and attach it to socket state. */
	/* LINTED */
}

/* ARGSUSED */
static int
tcp_dummy_disconnected(sock_upper_handle_t x, sock_connid_t y, int blah)
{
	ASSERT(0);	/* Panic in debug, otherwise ignore. */
	return (-1);
}

/* ARGSUSED */
static void
tcp_dummy_opctl(sock_upper_handle_t x, sock_opctl_action_t y, uintptr_t blah)
{
	ASSERT(x == NULL);
	/* We really want this one to be a harmless NOP for now. */
	/* LINTED */
}

/* ARGSUSED */
static ssize_t
tcp_dummy_recv(sock_upper_handle_t x, mblk_t *mp, size_t len, int flags,
    int *error, boolean_t *push)
{
	ASSERT(x == NULL);

	/*
	 * Consume the message, set ESHUTDOWN, and return an error.
	 * Nobody's home!
	 */
	freemsg(mp);
	*error = ESHUTDOWN;
	return (-1);
}

/* ARGSUSED */
static void
tcp_dummy_set_proto_props(sock_upper_handle_t x, struct sock_proto_props *y)
{
	ASSERT(0);	/* Panic in debug, otherwise ignore. */
}

/* ARGSUSED */
static void
tcp_dummy_txq_full(sock_upper_handle_t x, boolean_t y)
{
	ASSERT(0);	/* Panic in debug, otherwise ignore. */
}

/* ARGSUSED */
static void
tcp_dummy_signal_oob(sock_upper_handle_t x, ssize_t len)
{
	ASSERT(x == NULL);
	/* Otherwise, this would signal socket state about OOB data. */
}

/* ARGSUSED */
static void
tcp_dummy_set_error(sock_upper_handle_t x, int err)
{
	ASSERT(0);	/* Panic in debug, otherwise ignore. */
}

/* ARGSUSED */
static void
tcp_dummy_onearg(sock_upper_handle_t x)
{
	ASSERT(0);	/* Panic in debug, otherwise ignore. */
}

static sock_upcalls_t tcp_dummy_upcalls = {
	tcp_dummy_newconn,
	tcp_dummy_connected,
	tcp_dummy_disconnected,
	tcp_dummy_opctl,
	tcp_dummy_recv,
	tcp_dummy_set_proto_props,
	tcp_dummy_txq_full,
	tcp_dummy_signal_oob,
	tcp_dummy_onearg,
	tcp_dummy_set_error,
	tcp_dummy_onearg
};

/*
 * Handle M_DATA messages from IP. Its called directly from IP via
 * squeue for received IP packets.
 *
 * The first argument is always the connp/tcp to which the mp belongs.
 * There are no exceptions to this rule. The caller has already put
 * a reference on this connp/tcp and once tcp_input_data() returns,
 * the squeue will do the refrele.
 *
 * The TH_SYN for the listener directly go to tcp_input_listener via
 * squeue. ICMP errors go directly to tcp_icmp_input().
 *
 * sqp: NULL = recursive, sqp != NULL means called from squeue
 */
void
tcp_input_data(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	int32_t		bytes_acked;
	int32_t		gap;
	mblk_t		*mp1;
	uint_t		flags;
	uint32_t	new_swnd = 0;
	uchar_t		*iphdr;
	uchar_t		*rptr;
	int32_t		rgap;
	uint32_t	seg_ack;
	int		seg_len;
	uint_t		ip_hdr_len;
	uint32_t	seg_seq;
	tcpha_t		*tcpha;
	int		urp;
	tcp_opt_t	tcpopt;
	ip_pkt_t	ipp;
	boolean_t	ofo_seg = B_FALSE; /* Out of order segment */
	uint32_t	cwnd;
	uint32_t	add;
	int		npkt;
	int		mss;
	conn_t		*connp = (conn_t *)arg;
	squeue_t	*sqp = (squeue_t *)arg2;
	tcp_t		*tcp = connp->conn_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	sock_upcalls_t	*sockupcalls;

	/*
	 * RST from fused tcp loopback peer should trigger an unfuse.
	 */
	if (tcp->tcp_fused) {
		TCP_STAT(tcps, tcp_fusion_aborted);
		tcp_unfuse(tcp);
	}

	iphdr = mp->b_rptr;
	rptr = mp->b_rptr;
	ASSERT(OK_32PTR(rptr));

	ip_hdr_len = ira->ira_ip_hdr_length;
	if (connp->conn_recv_ancillary.crb_all != 0) {
		/*
		 * Record packet information in the ip_pkt_t
		 */
		ipp.ipp_fields = 0;
		if (ira->ira_flags & IRAF_IS_IPV4) {
			(void) ip_find_hdr_v4((ipha_t *)rptr, &ipp,
			    B_FALSE);
		} else {
			uint8_t nexthdrp;

			/*
			 * IPv6 packets can only be received by applications
			 * that are prepared to receive IPv6 addresses.
			 * The IP fanout must ensure this.
			 */
			ASSERT(connp->conn_family == AF_INET6);

			(void) ip_find_hdr_v6(mp, (ip6_t *)rptr, B_TRUE, &ipp,
			    &nexthdrp);
			ASSERT(nexthdrp == IPPROTO_TCP);

			/* Could have caused a pullup? */
			iphdr = mp->b_rptr;
			rptr = mp->b_rptr;
		}
	}
	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(mp->b_next == NULL);

	tcpha = (tcpha_t *)&rptr[ip_hdr_len];
	seg_seq = ntohl(tcpha->tha_seq);
	seg_ack = ntohl(tcpha->tha_ack);
	ASSERT((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	seg_len = (int)(mp->b_wptr - rptr) -
	    (ip_hdr_len + TCP_HDR_LENGTH(tcpha));
	if ((mp1 = mp->b_cont) != NULL && mp1->b_datap->db_type == M_DATA) {
		do {
			ASSERT((uintptr_t)(mp1->b_wptr - mp1->b_rptr) <=
			    (uintptr_t)INT_MAX);
			seg_len += (int)(mp1->b_wptr - mp1->b_rptr);
		} while ((mp1 = mp1->b_cont) != NULL &&
		    mp1->b_datap->db_type == M_DATA);
	}

	DTRACE_TCP5(receive, mblk_t *, NULL, ip_xmit_attr_t *, connp->conn_ixa,
	    __dtrace_tcp_void_ip_t *, iphdr, tcp_t *, tcp,
	    __dtrace_tcp_tcph_t *, tcpha);

	if (tcp->tcp_state == TCPS_TIME_WAIT) {
		tcp_time_wait_processing(tcp, mp, seg_seq, seg_ack,
		    seg_len, tcpha, ira);
		return;
	}

	if (sqp != NULL) {
		/*
		 * This is the correct place to update tcp_last_recv_time. Note
		 * that it is also updated for tcp structure that belongs to
		 * global and listener queues which do not really need updating.
		 * But that should not cause any harm.  And it is updated for
		 * all kinds of incoming segments, not only for data segments.
		 */
		tcp->tcp_last_recv_time = LBOLT_FASTPATH;
	}

	flags = (unsigned int)tcpha->tha_flags & 0xFF;

	BUMP_LOCAL(tcp->tcp_ibsegs);
	DTRACE_PROBE2(tcp__trace__recv, mblk_t *, mp, tcp_t *, tcp);

	if ((flags & TH_URG) && sqp != NULL) {
		/*
		 * TCP can't handle urgent pointers that arrive before
		 * the connection has been accept()ed since it can't
		 * buffer OOB data.  Discard segment if this happens.
		 *
		 * We can't just rely on a non-null tcp_listener to indicate
		 * that the accept() has completed since unlinking of the
		 * eager and completion of the accept are not atomic.
		 * tcp_detached, when it is not set (B_FALSE) indicates
		 * that the accept() has completed.
		 *
		 * Nor can it reassemble urgent pointers, so discard
		 * if it's not the next segment expected.
		 *
		 * Otherwise, collapse chain into one mblk (discard if
		 * that fails).  This makes sure the headers, retransmitted
		 * data, and new data all are in the same mblk.
		 */
		ASSERT(mp != NULL);
		if (tcp->tcp_detached || !pullupmsg(mp, -1)) {
			freemsg(mp);
			return;
		}
		/* Update pointers into message */
		iphdr = rptr = mp->b_rptr;
		tcpha = (tcpha_t *)&rptr[ip_hdr_len];
		if (SEQ_GT(seg_seq, tcp->tcp_rnxt)) {
			/*
			 * Since we can't handle any data with this urgent
			 * pointer that is out of sequence, we expunge
			 * the data.  This allows us to still register
			 * the urgent mark and generate the M_PCSIG,
			 * which we can do.
			 */
			mp->b_wptr = (uchar_t *)tcpha + TCP_HDR_LENGTH(tcpha);
			seg_len = 0;
		}
	}

	sockupcalls = connp->conn_upcalls;
	/* A conn_t may have belonged to a now-closed socket.  Be careful. */
	if (sockupcalls == NULL)
		sockupcalls = &tcp_dummy_upcalls;

	switch (tcp->tcp_state) {
	case TCPS_SYN_SENT:
		if (connp->conn_final_sqp == NULL &&
		    tcp_outbound_squeue_switch && sqp != NULL) {
			ASSERT(connp->conn_initial_sqp == connp->conn_sqp);
			connp->conn_final_sqp = sqp;
			if (connp->conn_final_sqp != connp->conn_sqp) {
				DTRACE_PROBE1(conn__final__sqp__switch,
				    conn_t *, connp);
				CONN_INC_REF(connp);
				SQUEUE_SWITCH(connp, connp->conn_final_sqp);
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
				    tcp_input_data, connp, ira, ip_squeue_flag,
				    SQTAG_CONNECT_FINISH);
				return;
			}
			DTRACE_PROBE1(conn__final__sqp__same, conn_t *, connp);
		}
		if (flags & TH_ACK) {
			/*
			 * Note that our stack cannot send data before a
			 * connection is established, therefore the
			 * following check is valid.  Otherwise, it has
			 * to be changed.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_iss) ||
			    SEQ_GT(seg_ack, tcp->tcp_snxt)) {
				freemsg(mp);
				if (flags & TH_RST)
					return;
				tcp_xmit_ctl("TCPS_SYN_SENT-Bad_seq",
				    tcp, seg_ack, 0, TH_RST);
				return;
			}
			ASSERT(tcp->tcp_suna + 1 == seg_ack);
		}
		if (flags & TH_RST) {
			if (flags & TH_ACK) {
				DTRACE_TCP5(connect__refused, mblk_t *, NULL,
				    ip_xmit_attr_t *, connp->conn_ixa,
				    void_ip_t *, iphdr, tcp_t *, tcp,
				    tcph_t *, tcpha);
				(void) tcp_clean_death(tcp, ECONNREFUSED);
			}
			freemsg(mp);
			return;
		}
		if (!(flags & TH_SYN)) {
			freemsg(mp);
			return;
		}

		/* Process all TCP options. */
		tcp_process_options(tcp, tcpha);
		/*
		 * The following changes our rwnd to be a multiple of the
		 * MIN(peer MSS, our MSS) for performance reason.
		 */
		(void) tcp_rwnd_set(tcp, MSS_ROUNDUP(connp->conn_rcvbuf,
		    tcp->tcp_mss));

		/* Is the other end ECN capable? */
		if (tcp->tcp_ecn_ok) {
			if ((flags & (TH_ECE|TH_CWR)) != TH_ECE) {
				tcp->tcp_ecn_ok = B_FALSE;
			}
		}
		/*
		 * Clear ECN flags because it may interfere with later
		 * processing.
		 */
		flags &= ~(TH_ECE|TH_CWR);

		tcp->tcp_irs = seg_seq;
		tcp->tcp_rack = seg_seq;
		tcp->tcp_rnxt = seg_seq + 1;
		tcp->tcp_tcpha->tha_ack = htonl(tcp->tcp_rnxt);
		if (!TCP_IS_DETACHED(tcp)) {
			/* Allocate room for SACK options if needed. */
			connp->conn_wroff = connp->conn_ht_iphc_len;
			if (tcp->tcp_snd_sack_ok)
				connp->conn_wroff += TCPOPT_MAX_SACK_LEN;
			if (!tcp->tcp_loopback)
				connp->conn_wroff += tcps->tcps_wroff_xtra;

			(void) proto_set_tx_wroff(connp->conn_rq, connp,
			    connp->conn_wroff);
		}
		if (flags & TH_ACK) {
			/*
			 * If we can't get the confirmation upstream, pretend
			 * we didn't even see this one.
			 *
			 * XXX: how can we pretend we didn't see it if we
			 * have updated rnxt et. al.
			 *
			 * For loopback we defer sending up the T_CONN_CON
			 * until after some checks below.
			 */
			mp1 = NULL;
			/*
			 * tcp_sendmsg() checks tcp_state without entering
			 * the squeue so tcp_state should be updated before
			 * sending up connection confirmation.  Probe the
			 * state change below when we are sure the connection
			 * confirmation has been sent.
			 */
			tcp->tcp_state = TCPS_ESTABLISHED;
			if (!tcp_conn_con(tcp, iphdr, mp,
			    tcp->tcp_loopback ? &mp1 : NULL, ira)) {
				tcp->tcp_state = TCPS_SYN_SENT;
				freemsg(mp);
				return;
			}
			TCPS_CONN_INC(tcps);
			/* SYN was acked - making progress */
			tcp->tcp_ip_forward_progress = B_TRUE;

			/* One for the SYN */
			tcp->tcp_suna = tcp->tcp_iss + 1;
			tcp->tcp_valid_bits &= ~TCP_ISS_VALID;

			/*
			 * If SYN was retransmitted, need to reset all
			 * retransmission info.  This is because this
			 * segment will be treated as a dup ACK.
			 */
			if (tcp->tcp_rexmit) {
				tcp->tcp_rexmit = B_FALSE;
				tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
				tcp->tcp_rexmit_max = tcp->tcp_snxt;
				tcp->tcp_ms_we_have_waited = 0;

				/*
				 * Set tcp_cwnd back to 1 MSS, per
				 * recommendation from
				 * draft-floyd-incr-init-win-01.txt,
				 * Increasing TCP's Initial Window.
				 */
				tcp->tcp_cwnd = tcp->tcp_mss;
			}

			tcp->tcp_swl1 = seg_seq;
			tcp->tcp_swl2 = seg_ack;

			new_swnd = ntohs(tcpha->tha_win);
			tcp->tcp_swnd = new_swnd;
			if (new_swnd > tcp->tcp_max_swnd)
				tcp->tcp_max_swnd = new_swnd;

			/*
			 * Always send the three-way handshake ack immediately
			 * in order to make the connection complete as soon as
			 * possible on the accepting host.
			 */
			flags |= TH_ACK_NEEDED;

			/*
			 * Trace connect-established here.
			 */
			DTRACE_TCP5(connect__established, mblk_t *, NULL,
			    ip_xmit_attr_t *, tcp->tcp_connp->conn_ixa,
			    void_ip_t *, iphdr, tcp_t *, tcp, tcph_t *, tcpha);

			/* Trace change from SYN_SENT -> ESTABLISHED here */
			DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
			    connp->conn_ixa, void, NULL, tcp_t *, tcp,
			    void, NULL, int32_t, TCPS_SYN_SENT);

			/*
			 * Special case for loopback.  At this point we have
			 * received SYN-ACK from the remote endpoint.  In
			 * order to ensure that both endpoints reach the
			 * fused state prior to any data exchange, the final
			 * ACK needs to be sent before we indicate T_CONN_CON
			 * to the module upstream.
			 */
			if (tcp->tcp_loopback) {
				mblk_t *ack_mp;

				ASSERT(!tcp->tcp_unfusable);
				ASSERT(mp1 != NULL);
				/*
				 * For loopback, we always get a pure SYN-ACK
				 * and only need to send back the final ACK
				 * with no data (this is because the other
				 * tcp is ours and we don't do T/TCP).  This
				 * final ACK triggers the passive side to
				 * perform fusion in ESTABLISHED state.
				 */
				if ((ack_mp = tcp_ack_mp(tcp)) != NULL) {
					if (tcp->tcp_ack_tid != 0) {
						(void) TCP_TIMER_CANCEL(tcp,
						    tcp->tcp_ack_tid);
						tcp->tcp_ack_tid = 0;
					}
					tcp_send_data(tcp, ack_mp);
					BUMP_LOCAL(tcp->tcp_obsegs);
					TCPS_BUMP_MIB(tcps, tcpOutAck);

					if (!IPCL_IS_NONSTR(connp)) {
						/* Send up T_CONN_CON */
						if (ira->ira_cred != NULL) {
							mblk_setcred(mp1,
							    ira->ira_cred,
							    ira->ira_cpid);
						}
						putnext(connp->conn_rq, mp1);
					} else {
						(*sockupcalls->su_connected)
						    (connp->conn_upper_handle,
						    tcp->tcp_connid,
						    ira->ira_cred,
						    ira->ira_cpid);
						freemsg(mp1);
					}

					freemsg(mp);
					return;
				}
				/*
				 * Forget fusion; we need to handle more
				 * complex cases below.  Send the deferred
				 * T_CONN_CON message upstream and proceed
				 * as usual.  Mark this tcp as not capable
				 * of fusion.
				 */
				TCP_STAT(tcps, tcp_fusion_unfusable);
				tcp->tcp_unfusable = B_TRUE;
				if (!IPCL_IS_NONSTR(connp)) {
					if (ira->ira_cred != NULL) {
						mblk_setcred(mp1, ira->ira_cred,
						    ira->ira_cpid);
					}
					putnext(connp->conn_rq, mp1);
				} else {
					(*sockupcalls->su_connected)
					    (connp->conn_upper_handle,
					    tcp->tcp_connid, ira->ira_cred,
					    ira->ira_cpid);
					freemsg(mp1);
				}
			}

			/*
			 * Check to see if there is data to be sent.  If
			 * yes, set the transmit flag.  Then check to see
			 * if received data processing needs to be done.
			 * If not, go straight to xmit_check.  This short
			 * cut is OK as we don't support T/TCP.
			 */
			if (tcp->tcp_unsent)
				flags |= TH_XMIT_NEEDED;

			if (seg_len == 0 && !(flags & TH_URG)) {
				freemsg(mp);
				goto xmit_check;
			}

			flags &= ~TH_SYN;
			seg_seq++;
			break;
		}
		tcp->tcp_state = TCPS_SYN_RCVD;
		DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
		    connp->conn_ixa, void_ip_t *, NULL, tcp_t *, tcp,
		    tcph_t *, NULL, int32_t, TCPS_SYN_SENT);
		mp1 = tcp_xmit_mp(tcp, tcp->tcp_xmit_head, tcp->tcp_mss,
		    NULL, NULL, tcp->tcp_iss, B_FALSE, NULL, B_FALSE);
		if (mp1 != NULL) {
			tcp_send_data(tcp, mp1);
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}
		freemsg(mp);
		return;
	case TCPS_SYN_RCVD:
		if (flags & TH_ACK) {
			uint32_t pinit_wnd;

			/*
			 * In this state, a SYN|ACK packet is either bogus
			 * because the other side must be ACKing our SYN which
			 * indicates it has seen the ACK for their SYN and
			 * shouldn't retransmit it or we're crossing SYNs
			 * on active open.
			 */
			if ((flags & TH_SYN) && !tcp->tcp_active_open) {
				freemsg(mp);
				tcp_xmit_ctl("TCPS_SYN_RCVD-bad_syn",
				    tcp, seg_ack, 0, TH_RST);
				return;
			}
			/*
			 * NOTE: RFC 793 pg. 72 says this should be
			 * tcp->tcp_suna <= seg_ack <= tcp->tcp_snxt
			 * but that would mean we have an ack that ignored
			 * our SYN.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_suna) ||
			    SEQ_GT(seg_ack, tcp->tcp_snxt)) {
				freemsg(mp);
				tcp_xmit_ctl("TCPS_SYN_RCVD-bad_ack",
				    tcp, seg_ack, 0, TH_RST);
				return;
			}
			/*
			 * No sane TCP stack will send such a small window
			 * without receiving any data.  Just drop this invalid
			 * ACK.  We also shorten the abort timeout in case
			 * this is an attack.
			 */
			pinit_wnd = ntohs(tcpha->tha_win) << tcp->tcp_snd_ws;
			if (pinit_wnd < tcp->tcp_mss &&
			    pinit_wnd < tcp_init_wnd_chk) {
				freemsg(mp);
				TCP_STAT(tcps, tcp_zwin_ack_syn);
				tcp->tcp_second_ctimer_threshold =
				    tcp_early_abort * SECONDS;
				return;
			}
		}
		break;
	case TCPS_LISTEN:
		/*
		 * Only a TLI listener can come through this path when a
		 * acceptor is going back to be a listener and a packet
		 * for the acceptor hits the classifier. For a socket
		 * listener, this can never happen because a listener
		 * can never accept connection on itself and hence a
		 * socket acceptor can not go back to being a listener.
		 */
		ASSERT(!TCP_IS_SOCKET(tcp));
		/*FALLTHRU*/
	case TCPS_CLOSED:
	case TCPS_BOUND: {
		conn_t	*new_connp;
		ip_stack_t *ipst = tcps->tcps_netstack->netstack_ip;

		/*
		 * Don't accept any input on a closed tcp as this TCP logically
		 * does not exist on the system. Don't proceed further with
		 * this TCP. For instance, this packet could trigger another
		 * close of this tcp which would be disastrous for tcp_refcnt.
		 * tcp_close_detached / tcp_clean_death / tcp_closei_local must
		 * be called at most once on a TCP. In this case we need to
		 * refeed the packet into the classifier and figure out where
		 * the packet should go.
		 */
		new_connp = ipcl_classify(mp, ira, ipst);
		if (new_connp != NULL) {
			/* Drops ref on new_connp */
			tcp_reinput(new_connp, mp, ira, ipst);
			return;
		}
		/* We failed to classify. For now just drop the packet */
		freemsg(mp);
		return;
	}
	case TCPS_IDLE:
		/*
		 * Handle the case where the tcp_clean_death() has happened
		 * on a connection (application hasn't closed yet) but a packet
		 * was already queued on squeue before tcp_clean_death()
		 * was processed. Calling tcp_clean_death() twice on same
		 * connection can result in weird behaviour.
		 */
		freemsg(mp);
		return;
	default:
		break;
	}

	/*
	 * Already on the correct queue/perimeter.
	 * If this is a detached connection and not an eager
	 * connection hanging off a listener then new data
	 * (past the FIN) will cause a reset.
	 * We do a special check here where it
	 * is out of the main line, rather than check
	 * if we are detached every time we see new
	 * data down below.
	 */
	if (TCP_IS_DETACHED_NONEAGER(tcp) &&
	    (seg_len > 0 && SEQ_GT(seg_seq + seg_len, tcp->tcp_rnxt))) {
		TCPS_BUMP_MIB(tcps, tcpInClosed);
		DTRACE_PROBE2(tcp__trace__recv, mblk_t *, mp, tcp_t *, tcp);
		freemsg(mp);
		tcp_xmit_ctl("new data when detached", tcp,
		    tcp->tcp_snxt, 0, TH_RST);
		(void) tcp_clean_death(tcp, EPROTO);
		return;
	}

	mp->b_rptr = (uchar_t *)tcpha + TCP_HDR_LENGTH(tcpha);
	urp = ntohs(tcpha->tha_urp) - TCP_OLD_URP_INTERPRETATION;
	new_swnd = ntohs(tcpha->tha_win) <<
	    ((tcpha->tha_flags & TH_SYN) ? 0 : tcp->tcp_snd_ws);

	/*
	 * We are interested in two TCP options: timestamps (if negotiated) and
	 * SACK (if negotiated). Skip option parsing if neither is negotiated.
	 */
	if (tcp->tcp_snd_ts_ok || tcp->tcp_snd_sack_ok) {
		int options;
		if (tcp->tcp_snd_sack_ok)
			tcpopt.tcp = tcp;
		else
			tcpopt.tcp = NULL;
		options = tcp_parse_options(tcpha, &tcpopt);
		/*
		 * RST segments must not be subject to PAWS and are not
		 * required to have timestamps.
		 */
		if (tcp->tcp_snd_ts_ok && !(flags & TH_RST)) {
			/*
			 * Per RFC 7323 section 3.2., silently drop non-RST
			 * segments without expected TSopt. This is a 'SHOULD'
			 * requirement.
			 */
			if (!(options & TCP_OPT_TSTAMP_PRESENT)) {
				/*
				 * Leave a breadcrumb for people to detect this
				 * behavior.
				 */
				DTRACE_TCP1(droppedtimestamp, tcp_t *, tcp);
				freemsg(mp);
				return;
			}

			if (!tcp_paws_check(tcp, &tcpopt)) {
				/*
				 * This segment is not acceptable.
				 * Drop it and send back an ACK.
				 */
				freemsg(mp);
				flags |= TH_ACK_NEEDED;
				goto ack_check;
			}
		}
	}
try_again:;
	mss = tcp->tcp_mss;
	gap = seg_seq - tcp->tcp_rnxt;
	rgap = tcp->tcp_rwnd - (gap + seg_len);
	/*
	 * gap is the amount of sequence space between what we expect to see
	 * and what we got for seg_seq.  A positive value for gap means
	 * something got lost.  A negative value means we got some old stuff.
	 */
	if (gap < 0) {
		/* Old stuff present.  Is the SYN in there? */
		if (seg_seq == tcp->tcp_irs && (flags & TH_SYN) &&
		    (seg_len != 0)) {
			flags &= ~TH_SYN;
			seg_seq++;
			urp--;
			/* Recompute the gaps after noting the SYN. */
			goto try_again;
		}
		TCPS_BUMP_MIB(tcps, tcpInDataDupSegs);
		TCPS_UPDATE_MIB(tcps, tcpInDataDupBytes,
		    (seg_len > -gap ? -gap : seg_len));
		/* Remove the old stuff from seg_len. */
		seg_len += gap;
		/*
		 * Anything left?
		 * Make sure to check for unack'd FIN when rest of data
		 * has been previously ack'd.
		 */
		if (seg_len < 0 || (seg_len == 0 && !(flags & TH_FIN))) {
			/*
			 * Resets are only valid if they lie within our offered
			 * window.  If the RST bit is set, we just ignore this
			 * segment.
			 */
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}

			/*
			 * The arriving of dup data packets indicate that we
			 * may have postponed an ack for too long, or the other
			 * side's RTT estimate is out of shape. Start acking
			 * more often.
			 */
			if (SEQ_GEQ(seg_seq + seg_len - gap, tcp->tcp_rack) &&
			    tcp->tcp_rack_cnt >= 1 &&
			    tcp->tcp_rack_abs_max > 2) {
				tcp->tcp_rack_abs_max--;
			}
			tcp->tcp_rack_cur_max = 1;

			/*
			 * This segment is "unacceptable".  None of its
			 * sequence space lies within our advertized window.
			 *
			 * Adjust seg_len to the original value for tracing.
			 */
			seg_len -= gap;
			if (connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: unacceptable, gap %d, rgap %d, "
				    "flags 0x%x, seg_seq %u, seg_ack %u, "
				    "seg_len %d, rnxt %u, snxt %u, %s",
				    gap, rgap, flags, seg_seq, seg_ack,
				    seg_len, tcp->tcp_rnxt, tcp->tcp_snxt,
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
			}

			/*
			 * Arrange to send an ACK in response to the
			 * unacceptable segment per RFC 793 page 69. There
			 * is only one small difference between ours and the
			 * acceptability test in the RFC - we accept ACK-only
			 * packet with SEG.SEQ = RCV.NXT+RCV.WND and no ACK
			 * will be generated.
			 *
			 * Note that we have to ACK an ACK-only packet at least
			 * for stacks that send 0-length keep-alives with
			 * SEG.SEQ = SND.NXT-1 as recommended by RFC1122,
			 * section 4.2.3.6. As long as we don't ever generate
			 * an unacceptable packet in response to an incoming
			 * packet that is unacceptable, it should not cause
			 * "ACK wars".
			 */
			flags |=  TH_ACK_NEEDED;

			/*
			 * Continue processing this segment in order to use the
			 * ACK information it contains, but skip all other
			 * sequence-number processing.	Processing the ACK
			 * information is necessary in order to
			 * re-synchronize connections that may have lost
			 * synchronization.
			 *
			 * We clear seg_len and flag fields related to
			 * sequence number processing as they are not
			 * to be trusted for an unacceptable segment.
			 */
			seg_len = 0;
			flags &= ~(TH_SYN | TH_FIN | TH_URG);
			goto process_ack;
		}

		/* Fix seg_seq, and chew the gap off the front. */
		seg_seq = tcp->tcp_rnxt;
		urp += gap;
		do {
			mblk_t	*mp2;
			ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
			    (uintptr_t)UINT_MAX);
			gap += (uint_t)(mp->b_wptr - mp->b_rptr);
			if (gap > 0) {
				mp->b_rptr = mp->b_wptr - gap;
				break;
			}
			mp2 = mp;
			mp = mp->b_cont;
			freeb(mp2);
		} while (gap < 0);
		/*
		 * If the urgent data has already been acknowledged, we
		 * should ignore TH_URG below
		 */
		if (urp < 0)
			flags &= ~TH_URG;
	}
	/*
	 * rgap is the amount of stuff received out of window.  A negative
	 * value is the amount out of window.
	 */
	if (rgap < 0) {
		mblk_t	*mp2;

		if (tcp->tcp_rwnd == 0) {
			TCPS_BUMP_MIB(tcps, tcpInWinProbe);
		} else {
			TCPS_BUMP_MIB(tcps, tcpInDataPastWinSegs);
			TCPS_UPDATE_MIB(tcps, tcpInDataPastWinBytes, -rgap);
		}

		/*
		 * seg_len does not include the FIN, so if more than
		 * just the FIN is out of window, we act like we don't
		 * see it.  (If just the FIN is out of window, rgap
		 * will be zero and we will go ahead and acknowledge
		 * the FIN.)
		 */
		flags &= ~TH_FIN;

		/* Fix seg_len and make sure there is something left. */
		seg_len += rgap;
		if (seg_len <= 0) {
			/*
			 * Resets are only valid if they lie within our offered
			 * window.  If the RST bit is set, we just ignore this
			 * segment.
			 */
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}

			/* Per RFC 793, we need to send back an ACK. */
			flags |= TH_ACK_NEEDED;

			/*
			 * Send SIGURG as soon as possible i.e. even
			 * if the TH_URG was delivered in a window probe
			 * packet (which will be unacceptable).
			 *
			 * We generate a signal if none has been generated
			 * for this connection or if this is a new urgent
			 * byte. Also send a zero-length "unmarked" message
			 * to inform SIOCATMARK that this is not the mark.
			 *
			 * tcp_urp_last_valid is cleared when the T_exdata_ind
			 * is sent up. This plus the check for old data
			 * (gap >= 0) handles the wraparound of the sequence
			 * number space without having to always track the
			 * correct MAX(tcp_urp_last, tcp_rnxt). (BSD tracks
			 * this max in its rcv_up variable).
			 *
			 * This prevents duplicate SIGURGS due to a "late"
			 * zero-window probe when the T_EXDATA_IND has already
			 * been sent up.
			 */
			if ((flags & TH_URG) &&
			    (!tcp->tcp_urp_last_valid || SEQ_GT(urp + seg_seq,
			    tcp->tcp_urp_last))) {
				if (IPCL_IS_NONSTR(connp)) {
					if (!TCP_IS_DETACHED(tcp)) {
						(*sockupcalls->su_signal_oob)
						    (connp->conn_upper_handle,
						    urp);
					}
				} else {
					mp1 = allocb(0, BPRI_MED);
					if (mp1 == NULL) {
						freemsg(mp);
						return;
					}
					if (!TCP_IS_DETACHED(tcp) &&
					    !putnextctl1(connp->conn_rq,
					    M_PCSIG, SIGURG)) {
						/* Try again on the rexmit. */
						freemsg(mp1);
						freemsg(mp);
						return;
					}
					/*
					 * If the next byte would be the mark
					 * then mark with MARKNEXT else mark
					 * with NOTMARKNEXT.
					 */
					if (gap == 0 && urp == 0)
						mp1->b_flag |= MSGMARKNEXT;
					else
						mp1->b_flag |= MSGNOTMARKNEXT;
					freemsg(tcp->tcp_urp_mark_mp);
					tcp->tcp_urp_mark_mp = mp1;
					flags |= TH_SEND_URP_MARK;
				}
				tcp->tcp_urp_last_valid = B_TRUE;
				tcp->tcp_urp_last = urp + seg_seq;
			}
			/*
			 * If this is a zero window probe, continue to
			 * process the ACK part.  But we need to set seg_len
			 * to 0 to avoid data processing.  Otherwise just
			 * drop the segment and send back an ACK.
			 */
			if (tcp->tcp_rwnd == 0 && seg_seq == tcp->tcp_rnxt) {
				flags &= ~(TH_SYN | TH_URG);
				seg_len = 0;
				goto process_ack;
			} else {
				freemsg(mp);
				goto ack_check;
			}
		}
		/* Pitch out of window stuff off the end. */
		rgap = seg_len;
		mp2 = mp;
		do {
			ASSERT((uintptr_t)(mp2->b_wptr - mp2->b_rptr) <=
			    (uintptr_t)INT_MAX);
			rgap -= (int)(mp2->b_wptr - mp2->b_rptr);
			if (rgap < 0) {
				mp2->b_wptr += rgap;
				if ((mp1 = mp2->b_cont) != NULL) {
					mp2->b_cont = NULL;
					freemsg(mp1);
				}
				break;
			}
		} while ((mp2 = mp2->b_cont) != NULL);
	}
ok:;
	/*
	 * TCP should check ECN info for segments inside the window only.
	 * Therefore the check should be done here.
	 */
	if (tcp->tcp_ecn_ok) {
		if (flags & TH_CWR) {
			tcp->tcp_ecn_echo_on = B_FALSE;
		}
		/*
		 * Note that both ECN_CE and CWR can be set in the
		 * same segment.  In this case, we once again turn
		 * on ECN_ECHO.
		 */
		if (connp->conn_ipversion == IPV4_VERSION) {
			uchar_t tos = ((ipha_t *)rptr)->ipha_type_of_service;

			if ((tos & IPH_ECN_CE) == IPH_ECN_CE) {
				tcp->tcp_ecn_echo_on = B_TRUE;
			}
		} else {
			uint32_t vcf = ((ip6_t *)rptr)->ip6_vcf;

			if ((vcf & htonl(IPH_ECN_CE << 20)) ==
			    htonl(IPH_ECN_CE << 20)) {
				tcp->tcp_ecn_echo_on = B_TRUE;
			}
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
		tcp->tcp_last_rcv_lbolt = LBOLT_FASTPATH64;
	}

	if (seg_seq != tcp->tcp_rnxt || tcp->tcp_reass_head) {
		/*
		 * FIN in an out of order segment.  We record this in
		 * tcp_valid_bits and the seq num of FIN in tcp_ofo_fin_seq.
		 * Clear the FIN so that any check on FIN flag will fail.
		 * Remember that FIN also counts in the sequence number
		 * space.  So we need to ack out of order FIN only segments.
		 */
		if (flags & TH_FIN) {
			tcp->tcp_valid_bits |= TCP_OFO_FIN_VALID;
			tcp->tcp_ofo_fin_seq = seg_seq + seg_len;
			flags &= ~TH_FIN;
			flags |= TH_ACK_NEEDED;
		}
		if (seg_len > 0) {
			/* Fill in the SACK blk list. */
			if (tcp->tcp_snd_sack_ok) {
				tcp_sack_insert(tcp->tcp_sack_list,
				    seg_seq, seg_seq + seg_len,
				    &(tcp->tcp_num_sack_blk));
			}

			/*
			 * Attempt reassembly and see if we have something
			 * ready to go.
			 */
			mp = tcp_reass(tcp, mp, seg_seq);
			/* Always ack out of order packets */
			flags |= TH_ACK_NEEDED | TH_PUSH;
			if (mp) {
				ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
				    (uintptr_t)INT_MAX);
				seg_len = mp->b_cont ? msgdsize(mp) :
				    (int)(mp->b_wptr - mp->b_rptr);
				seg_seq = tcp->tcp_rnxt;
				/*
				 * A gap is filled and the seq num and len
				 * of the gap match that of a previously
				 * received FIN, put the FIN flag back in.
				 */
				if ((tcp->tcp_valid_bits & TCP_OFO_FIN_VALID) &&
				    seg_seq + seg_len == tcp->tcp_ofo_fin_seq) {
					flags |= TH_FIN;
					tcp->tcp_valid_bits &=
					    ~TCP_OFO_FIN_VALID;
				}
				if (tcp->tcp_reass_tid != 0) {
					(void) TCP_TIMER_CANCEL(tcp,
					    tcp->tcp_reass_tid);
					/*
					 * Restart the timer if there is still
					 * data in the reassembly queue.
					 */
					if (tcp->tcp_reass_head != NULL) {
						tcp->tcp_reass_tid = TCP_TIMER(
						    tcp, tcp_reass_timer,
						    tcps->tcps_reass_timeout);
					} else {
						tcp->tcp_reass_tid = 0;
					}
				}
			} else {
				/*
				 * Keep going even with NULL mp.
				 * There may be a useful ACK or something else
				 * we don't want to miss.
				 *
				 * But TCP should not perform fast retransmit
				 * because of the ack number.  TCP uses
				 * seg_len == 0 to determine if it is a pure
				 * ACK.  And this is not a pure ACK.
				 */
				seg_len = 0;
				ofo_seg = B_TRUE;

				if (tcps->tcps_reass_timeout != 0 &&
				    tcp->tcp_reass_tid == 0) {
					tcp->tcp_reass_tid = TCP_TIMER(tcp,
					    tcp_reass_timer,
					    tcps->tcps_reass_timeout);
				}
			}
		}
	} else if (seg_len > 0) {
		TCPS_BUMP_MIB(tcps, tcpInDataInorderSegs);
		TCPS_UPDATE_MIB(tcps, tcpInDataInorderBytes, seg_len);
		/*
		 * If an out of order FIN was received before, and the seq
		 * num and len of the new segment match that of the FIN,
		 * put the FIN flag back in.
		 */
		if ((tcp->tcp_valid_bits & TCP_OFO_FIN_VALID) &&
		    seg_seq + seg_len == tcp->tcp_ofo_fin_seq) {
			flags |= TH_FIN;
			tcp->tcp_valid_bits &= ~TCP_OFO_FIN_VALID;
		}
	}
	if ((flags & (TH_RST | TH_SYN | TH_URG | TH_ACK)) != TH_ACK) {
	if (flags & TH_RST) {
		freemsg(mp);
		switch (tcp->tcp_state) {
		case TCPS_SYN_RCVD:
			(void) tcp_clean_death(tcp, ECONNREFUSED);
			break;
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT_1:
		case TCPS_FIN_WAIT_2:
		case TCPS_CLOSE_WAIT:
			(void) tcp_clean_death(tcp, ECONNRESET);
			break;
		case TCPS_CLOSING:
		case TCPS_LAST_ACK:
			(void) tcp_clean_death(tcp, 0);
			break;
		default:
			ASSERT(tcp->tcp_state != TCPS_TIME_WAIT);
			(void) tcp_clean_death(tcp, ENXIO);
			break;
		}
		return;
	}
	if (flags & TH_SYN) {
		/*
		 * See RFC 793, Page 71
		 *
		 * The seq number must be in the window as it should
		 * be "fixed" above.  If it is outside window, it should
		 * be already rejected.  Note that we allow seg_seq to be
		 * rnxt + rwnd because we want to accept 0 window probe.
		 */
		ASSERT(SEQ_GEQ(seg_seq, tcp->tcp_rnxt) &&
		    SEQ_LEQ(seg_seq, tcp->tcp_rnxt + tcp->tcp_rwnd));
		freemsg(mp);
		/*
		 * If the ACK flag is not set, just use our snxt as the
		 * seq number of the RST segment.
		 */
		if (!(flags & TH_ACK)) {
			seg_ack = tcp->tcp_snxt;
		}
		tcp_xmit_ctl("TH_SYN", tcp, seg_ack, seg_seq + 1,
		    TH_RST|TH_ACK);
		ASSERT(tcp->tcp_state != TCPS_TIME_WAIT);
		(void) tcp_clean_death(tcp, ECONNRESET);
		return;
	}
	/*
	 * urp could be -1 when the urp field in the packet is 0
	 * and TCP_OLD_URP_INTERPRETATION is set. This implies that the urgent
	 * byte was at seg_seq - 1, in which case we ignore the urgent flag.
	 */
	if (flags & TH_URG && urp >= 0) {
		if (!tcp->tcp_urp_last_valid ||
		    SEQ_GT(urp + seg_seq, tcp->tcp_urp_last)) {
			/*
			 * Non-STREAMS sockets handle the urgent data a litte
			 * differently from STREAMS based sockets. There is no
			 * need to mark any mblks with the MSG{NOT,}MARKNEXT
			 * flags to keep SIOCATMARK happy. Instead a
			 * su_signal_oob upcall is made to update the mark.
			 * Neither is a T_EXDATA_IND mblk needed to be
			 * prepended to the urgent data. The urgent data is
			 * delivered using the su_recv upcall, where we set
			 * the MSG_OOB flag to indicate that it is urg data.
			 *
			 * Neither TH_SEND_URP_MARK nor TH_MARKNEXT_NEEDED
			 * are used by non-STREAMS sockets.
			 */
			if (IPCL_IS_NONSTR(connp)) {
				if (!TCP_IS_DETACHED(tcp)) {
					(*sockupcalls->su_signal_oob)
					    (connp->conn_upper_handle, urp);
				}
			} else {
				/*
				 * If we haven't generated the signal yet for
				 * this urgent pointer value, do it now.  Also,
				 * send up a zero-length M_DATA indicating
				 * whether or not this is the mark. The latter
				 * is not needed when a T_EXDATA_IND is sent up.
				 * However, if there are allocation failures
				 * this code relies on the sender retransmitting
				 * and the socket code for determining the mark
				 * should not block waiting for the peer to
				 * transmit. Thus, for simplicity we always
				 * send up the mark indication.
				 */
				mp1 = allocb(0, BPRI_MED);
				if (mp1 == NULL) {
					freemsg(mp);
					return;
				}
				if (!TCP_IS_DETACHED(tcp) &&
				    !putnextctl1(connp->conn_rq, M_PCSIG,
				    SIGURG)) {
					/* Try again on the rexmit. */
					freemsg(mp1);
					freemsg(mp);
					return;
				}
				/*
				 * Mark with NOTMARKNEXT for now.
				 * The code below will change this to MARKNEXT
				 * if we are at the mark.
				 *
				 * If there are allocation failures (e.g. in
				 * dupmsg below) the next time tcp_input_data
				 * sees the urgent segment it will send up the
				 * MSGMARKNEXT message.
				 */
				mp1->b_flag |= MSGNOTMARKNEXT;
				freemsg(tcp->tcp_urp_mark_mp);
				tcp->tcp_urp_mark_mp = mp1;
				flags |= TH_SEND_URP_MARK;
#ifdef DEBUG
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: sent M_PCSIG 2 seq %x urp %x "
				    "last %x, %s",
				    seg_seq, urp, tcp->tcp_urp_last,
				    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
			}
			tcp->tcp_urp_last_valid = B_TRUE;
			tcp->tcp_urp_last = urp + seg_seq;
		} else if (tcp->tcp_urp_mark_mp != NULL) {
			/*
			 * An allocation failure prevented the previous
			 * tcp_input_data from sending up the allocated
			 * MSG*MARKNEXT message - send it up this time
			 * around.
			 */
			flags |= TH_SEND_URP_MARK;
		}

		/*
		 * If the urgent byte is in this segment, make sure that it is
		 * all by itself.  This makes it much easier to deal with the
		 * possibility of an allocation failure on the T_exdata_ind.
		 * Note that seg_len is the number of bytes in the segment, and
		 * urp is the offset into the segment of the urgent byte.
		 * urp < seg_len means that the urgent byte is in this segment.
		 */
		if (urp < seg_len) {
			if (seg_len != 1) {
				uint32_t  tmp_rnxt;
				/*
				 * Break it up and feed it back in.
				 * Re-attach the IP header.
				 */
				mp->b_rptr = iphdr;
				if (urp > 0) {
					/*
					 * There is stuff before the urgent
					 * byte.
					 */
					mp1 = dupmsg(mp);
					if (!mp1) {
						/*
						 * Trim from urgent byte on.
						 * The rest will come back.
						 */
						(void) adjmsg(mp,
						    urp - seg_len);
						tcp_input_data(connp,
						    mp, NULL, ira);
						return;
					}
					(void) adjmsg(mp1, urp - seg_len);
					/* Feed this piece back in. */
					tmp_rnxt = tcp->tcp_rnxt;
					tcp_input_data(connp, mp1, NULL, ira);
					/*
					 * If the data passed back in was not
					 * processed (ie: bad ACK) sending
					 * the remainder back in will cause a
					 * loop. In this case, drop the
					 * packet and let the sender try
					 * sending a good packet.
					 */
					if (tmp_rnxt == tcp->tcp_rnxt) {
						freemsg(mp);
						return;
					}
				}
				if (urp != seg_len - 1) {
					uint32_t  tmp_rnxt;
					/*
					 * There is stuff after the urgent
					 * byte.
					 */
					mp1 = dupmsg(mp);
					if (!mp1) {
						/*
						 * Trim everything beyond the
						 * urgent byte.  The rest will
						 * come back.
						 */
						(void) adjmsg(mp,
						    urp + 1 - seg_len);
						tcp_input_data(connp,
						    mp, NULL, ira);
						return;
					}
					(void) adjmsg(mp1, urp + 1 - seg_len);
					tmp_rnxt = tcp->tcp_rnxt;
					tcp_input_data(connp, mp1, NULL, ira);
					/*
					 * If the data passed back in was not
					 * processed (ie: bad ACK) sending
					 * the remainder back in will cause a
					 * loop. In this case, drop the
					 * packet and let the sender try
					 * sending a good packet.
					 */
					if (tmp_rnxt == tcp->tcp_rnxt) {
						freemsg(mp);
						return;
					}
				}
				tcp_input_data(connp, mp, NULL, ira);
				return;
			}
			/*
			 * This segment contains only the urgent byte.  We
			 * have to allocate the T_exdata_ind, if we can.
			 */
			if (IPCL_IS_NONSTR(connp)) {
				int error;

				(*sockupcalls->su_recv)
				    (connp->conn_upper_handle, mp, seg_len,
				    MSG_OOB, &error, NULL);
				/*
				 * We should never be in middle of a
				 * fallback, the squeue guarantees that.
				 */
				ASSERT(error != EOPNOTSUPP);
				mp = NULL;
				goto update_ack;
			} else if (!tcp->tcp_urp_mp) {
				struct T_exdata_ind *tei;
				mp1 = allocb(sizeof (struct T_exdata_ind),
				    BPRI_MED);
				if (!mp1) {
					/*
					 * Sigh... It'll be back.
					 * Generate any MSG*MARK message now.
					 */
					freemsg(mp);
					seg_len = 0;
					if (flags & TH_SEND_URP_MARK) {


						ASSERT(tcp->tcp_urp_mark_mp);
						tcp->tcp_urp_mark_mp->b_flag &=
						    ~MSGNOTMARKNEXT;
						tcp->tcp_urp_mark_mp->b_flag |=
						    MSGMARKNEXT;
					}
					goto ack_check;
				}
				mp1->b_datap->db_type = M_PROTO;
				tei = (struct T_exdata_ind *)mp1->b_rptr;
				tei->PRIM_type = T_EXDATA_IND;
				tei->MORE_flag = 0;
				mp1->b_wptr = (uchar_t *)&tei[1];
				tcp->tcp_urp_mp = mp1;
#ifdef DEBUG
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: allocated exdata_ind %s",
				    tcp_display(tcp, NULL,
				    DISP_PORT_ONLY));
#endif /* DEBUG */
				/*
				 * There is no need to send a separate MSG*MARK
				 * message since the T_EXDATA_IND will be sent
				 * now.
				 */
				flags &= ~TH_SEND_URP_MARK;
				freemsg(tcp->tcp_urp_mark_mp);
				tcp->tcp_urp_mark_mp = NULL;
			}
			/*
			 * Now we are all set.  On the next putnext upstream,
			 * tcp_urp_mp will be non-NULL and will get prepended
			 * to what has to be this piece containing the urgent
			 * byte.  If for any reason we abort this segment below,
			 * if it comes back, we will have this ready, or it
			 * will get blown off in close.
			 */
		} else if (urp == seg_len) {
			/*
			 * The urgent byte is the next byte after this sequence
			 * number. If this endpoint is non-STREAMS, then there
			 * is nothing to do here since the socket has already
			 * been notified about the urg pointer by the
			 * su_signal_oob call above.
			 *
			 * In case of STREAMS, some more work might be needed.
			 * If there is data it is marked with MSGMARKNEXT and
			 * and any tcp_urp_mark_mp is discarded since it is not
			 * needed. Otherwise, if the code above just allocated
			 * a zero-length tcp_urp_mark_mp message, that message
			 * is tagged with MSGMARKNEXT. Sending up these
			 * MSGMARKNEXT messages makes SIOCATMARK work correctly
			 * even though the T_EXDATA_IND will not be sent up
			 * until the urgent byte arrives.
			 */
			if (!IPCL_IS_NONSTR(tcp->tcp_connp)) {
				if (seg_len != 0) {
					flags |= TH_MARKNEXT_NEEDED;
					freemsg(tcp->tcp_urp_mark_mp);
					tcp->tcp_urp_mark_mp = NULL;
					flags &= ~TH_SEND_URP_MARK;
				} else if (tcp->tcp_urp_mark_mp != NULL) {
					flags |= TH_SEND_URP_MARK;
					tcp->tcp_urp_mark_mp->b_flag &=
					    ~MSGNOTMARKNEXT;
					tcp->tcp_urp_mark_mp->b_flag |=
					    MSGMARKNEXT;
				}
			}
#ifdef DEBUG
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
			    "tcp_rput: AT MARK, len %d, flags 0x%x, %s",
			    seg_len, flags,
			    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
		}
#ifdef DEBUG
		else {
			/* Data left until we hit mark */
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
			    "tcp_rput: URP %d bytes left, %s",
			    urp - seg_len, tcp_display(tcp, NULL,
			    DISP_PORT_ONLY));
		}
#endif /* DEBUG */
	}

process_ack:
	if (!(flags & TH_ACK)) {
		freemsg(mp);
		goto xmit_check;
	}
	}
	bytes_acked = (int)(seg_ack - tcp->tcp_suna);

	if (bytes_acked > 0)
		tcp->tcp_ip_forward_progress = B_TRUE;
	if (tcp->tcp_state == TCPS_SYN_RCVD) {
		/*
		 * tcp_sendmsg() checks tcp_state without entering
		 * the squeue so tcp_state should be updated before
		 * sending up a connection confirmation or a new
		 * connection indication.
		 */
		tcp->tcp_state = TCPS_ESTABLISHED;

		/*
		 * We are seeing the final ack in the three way
		 * hand shake of a active open'ed connection
		 * so we must send up a T_CONN_CON
		 */
		if (tcp->tcp_active_open) {
			if (!tcp_conn_con(tcp, iphdr, mp, NULL, ira)) {
				freemsg(mp);
				tcp->tcp_state = TCPS_SYN_RCVD;
				return;
			}
			/*
			 * Don't fuse the loopback endpoints for
			 * simultaneous active opens.
			 */
			if (tcp->tcp_loopback) {
				TCP_STAT(tcps, tcp_fusion_unfusable);
				tcp->tcp_unfusable = B_TRUE;
			}
			/*
			 * For simultaneous active open, trace receipt of final
			 * ACK as tcp:::connect-established.
			 */
			DTRACE_TCP5(connect__established, mblk_t *, NULL,
			    ip_xmit_attr_t *, connp->conn_ixa, void_ip_t *,
			    iphdr, tcp_t *, tcp, tcph_t *, tcpha);
		} else if (IPCL_IS_NONSTR(connp)) {
			/*
			 * 3-way handshake has completed, so notify socket
			 * of the new connection.
			 *
			 * We are here means eager is fine but it can
			 * get a TH_RST at any point between now and till
			 * accept completes and disappear. We need to
			 * ensure that reference to eager is valid after
			 * we get out of eager's perimeter. So we do
			 * an extra refhold.
			 */
			CONN_INC_REF(connp);

			if (!tcp_newconn_notify(tcp, ira)) {
				/*
				 * The state-change probe for SYN_RCVD ->
				 * ESTABLISHED has not fired yet. We reset
				 * the state to SYN_RCVD so that future
				 * state-change probes report correct state
				 * transistions.
				 */
				tcp->tcp_state = TCPS_SYN_RCVD;
				freemsg(mp);
				/* notification did not go up, so drop ref */
				CONN_DEC_REF(connp);
				/* ... and close the eager */
				ASSERT(TCP_IS_DETACHED(tcp));
				(void) tcp_close_detached(tcp);
				return;
			}
			/*
			 * tcp_newconn_notify() changes conn_upcalls and
			 * connp->conn_upper_handle.  Fix things now, in case
			 * there's data attached to this ack.
			 */
			if (connp->conn_upcalls != NULL)
				sockupcalls = connp->conn_upcalls;
			/*
			 * For passive open, trace receipt of final ACK as
			 * tcp:::accept-established.
			 */
			DTRACE_TCP5(accept__established, mlbk_t *, NULL,
			    ip_xmit_attr_t *, connp->conn_ixa, void_ip_t *,
			    iphdr, tcp_t *, tcp, tcph_t *, tcpha);
		} else {
			/*
			 * 3-way handshake complete - this is a STREAMS based
			 * socket, so pass up the T_CONN_IND.
			 */
			tcp_t	*listener = tcp->tcp_listener;
			mblk_t	*mp = tcp->tcp_conn.tcp_eager_conn_ind;

			tcp->tcp_tconnind_started = B_TRUE;
			tcp->tcp_conn.tcp_eager_conn_ind = NULL;
			ASSERT(mp != NULL);
			/*
			 * We are here means eager is fine but it can
			 * get a TH_RST at any point between now and till
			 * accept completes and disappear. We need to
			 * ensure that reference to eager is valid after
			 * we get out of eager's perimeter. So we do
			 * an extra refhold.
			 */
			CONN_INC_REF(connp);

			/*
			 * The listener also exists because of the refhold
			 * done in tcp_input_listener. Its possible that it
			 * might have closed. We will check that once we
			 * get inside listeners context.
			 */
			CONN_INC_REF(listener->tcp_connp);
			if (listener->tcp_connp->conn_sqp ==
			    connp->conn_sqp) {
				/*
				 * We optimize by not calling an SQUEUE_ENTER
				 * on the listener since we know that the
				 * listener and eager squeues are the same.
				 * We are able to make this check safely only
				 * because neither the eager nor the listener
				 * can change its squeue. Only an active connect
				 * can change its squeue
				 */
				tcp_send_conn_ind(listener->tcp_connp, mp,
				    listener->tcp_connp->conn_sqp);
				CONN_DEC_REF(listener->tcp_connp);
			} else if (!tcp->tcp_loopback) {
				SQUEUE_ENTER_ONE(listener->tcp_connp->conn_sqp,
				    mp, tcp_send_conn_ind,
				    listener->tcp_connp, NULL, SQ_FILL,
				    SQTAG_TCP_CONN_IND);
			} else {
				SQUEUE_ENTER_ONE(listener->tcp_connp->conn_sqp,
				    mp, tcp_send_conn_ind,
				    listener->tcp_connp, NULL, SQ_NODRAIN,
				    SQTAG_TCP_CONN_IND);
			}
			/*
			 * For passive open, trace receipt of final ACK as
			 * tcp:::accept-established.
			 */
			DTRACE_TCP5(accept__established, mlbk_t *, NULL,
			    ip_xmit_attr_t *, connp->conn_ixa, void_ip_t *,
			    iphdr, tcp_t *, tcp, tcph_t *, tcpha);
		}
		TCPS_CONN_INC(tcps);

		tcp->tcp_suna = tcp->tcp_iss + 1;	/* One for the SYN */
		bytes_acked--;
		/* SYN was acked - making progress */
		tcp->tcp_ip_forward_progress = B_TRUE;

		/*
		 * If SYN was retransmitted, need to reset all
		 * retransmission info as this segment will be
		 * treated as a dup ACK.
		 */
		if (tcp->tcp_rexmit) {
			tcp->tcp_rexmit = B_FALSE;
			tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
			tcp->tcp_rexmit_max = tcp->tcp_snxt;
			tcp->tcp_ms_we_have_waited = 0;
			tcp->tcp_cwnd = mss;
		}

		/*
		 * We set the send window to zero here.
		 * This is needed if there is data to be
		 * processed already on the queue.
		 * Later (at swnd_update label), the
		 * "new_swnd > tcp_swnd" condition is satisfied
		 * the XMIT_NEEDED flag is set in the current
		 * (SYN_RCVD) state. This ensures tcp_wput_data() is
		 * called if there is already data on queue in
		 * this state.
		 */
		tcp->tcp_swnd = 0;

		if (new_swnd > tcp->tcp_max_swnd)
			tcp->tcp_max_swnd = new_swnd;
		tcp->tcp_swl1 = seg_seq;
		tcp->tcp_swl2 = seg_ack;
		tcp->tcp_valid_bits &= ~TCP_ISS_VALID;

		/* Trace change from SYN_RCVD -> ESTABLISHED here */
		DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
		    connp->conn_ixa, void, NULL, tcp_t *, tcp, void, NULL,
		    int32_t, TCPS_SYN_RCVD);

		/* Fuse when both sides are in ESTABLISHED state */
		if (tcp->tcp_loopback && do_tcp_fusion)
			tcp_fuse(tcp, iphdr, tcpha);

	}
	/* This code follows 4.4BSD-Lite2 mostly. */
	if (bytes_acked < 0)
		goto est;

	/*
	 * If TCP is ECN capable and the congestion experience bit is
	 * set, reduce tcp_cwnd and tcp_ssthresh.  But this should only be
	 * done once per window (or more loosely, per RTT).
	 */
	if (tcp->tcp_cwr && SEQ_GT(seg_ack, tcp->tcp_cwr_snd_max))
		tcp->tcp_cwr = B_FALSE;
	if (tcp->tcp_ecn_ok && (flags & TH_ECE)) {
		if (!tcp->tcp_cwr) {
			npkt = ((tcp->tcp_snxt - tcp->tcp_suna) >> 1) / mss;
			tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) * mss;
			tcp->tcp_cwnd = npkt * mss;
			/*
			 * If the cwnd is 0, use the timer to clock out
			 * new segments.  This is required by the ECN spec.
			 */
			if (npkt == 0) {
				TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				/*
				 * This makes sure that when the ACK comes
				 * back, we will increase tcp_cwnd by 1 MSS.
				 */
				tcp->tcp_cwnd_cnt = 0;
			}
			tcp->tcp_cwr = B_TRUE;
			/*
			 * This marks the end of the current window of in
			 * flight data.  That is why we don't use
			 * tcp_suna + tcp_swnd.  Only data in flight can
			 * provide ECN info.
			 */
			tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
			tcp->tcp_ecn_cwr_sent = B_FALSE;
		}
	}

	mp1 = tcp->tcp_xmit_head;
	if (bytes_acked == 0) {
		if (!ofo_seg && seg_len == 0 && new_swnd == tcp->tcp_swnd) {
			int dupack_cnt;

			TCPS_BUMP_MIB(tcps, tcpInDupAck);
			/*
			 * Fast retransmit.  When we have seen exactly three
			 * identical ACKs while we have unacked data
			 * outstanding we take it as a hint that our peer
			 * dropped something.
			 *
			 * If TCP is retransmitting, don't do fast retransmit.
			 */
			if (mp1 && tcp->tcp_suna != tcp->tcp_snxt &&
			    ! tcp->tcp_rexmit) {
				/* Do Limited Transmit */
				if ((dupack_cnt = ++tcp->tcp_dupack_cnt) <
				    tcps->tcps_dupack_fast_retransmit) {
					/*
					 * RFC 3042
					 *
					 * What we need to do is temporarily
					 * increase tcp_cwnd so that new
					 * data can be sent if it is allowed
					 * by the receive window (tcp_rwnd).
					 * tcp_wput_data() will take care of
					 * the rest.
					 *
					 * If the connection is SACK capable,
					 * only do limited xmit when there
					 * is SACK info.
					 *
					 * Note how tcp_cwnd is incremented.
					 * The first dup ACK will increase
					 * it by 1 MSS.  The second dup ACK
					 * will increase it by 2 MSS.  This
					 * means that only 1 new segment will
					 * be sent for each dup ACK.
					 */
					if (tcp->tcp_unsent > 0 &&
					    (!tcp->tcp_snd_sack_ok ||
					    (tcp->tcp_snd_sack_ok &&
					    tcp->tcp_notsack_list != NULL))) {
						tcp->tcp_cwnd += mss <<
						    (tcp->tcp_dupack_cnt - 1);
						flags |= TH_LIMIT_XMIT;
					}
				} else if (dupack_cnt ==
				    tcps->tcps_dupack_fast_retransmit) {

				/*
				 * If we have reduced tcp_ssthresh
				 * because of ECN, do not reduce it again
				 * unless it is already one window of data
				 * away.  After one window of data, tcp_cwr
				 * should then be cleared.  Note that
				 * for non ECN capable connection, tcp_cwr
				 * should always be false.
				 *
				 * Adjust cwnd since the duplicate
				 * ack indicates that a packet was
				 * dropped (due to congestion.)
				 */
				if (!tcp->tcp_cwr) {
					npkt = ((tcp->tcp_snxt -
					    tcp->tcp_suna) >> 1) / mss;
					tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) *
					    mss;
					tcp->tcp_cwnd = (npkt +
					    tcp->tcp_dupack_cnt) * mss;
				}
				if (tcp->tcp_ecn_ok) {
					tcp->tcp_cwr = B_TRUE;
					tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
					tcp->tcp_ecn_cwr_sent = B_FALSE;
				}

				/*
				 * We do Hoe's algorithm.  Refer to her
				 * paper "Improving the Start-up Behavior
				 * of a Congestion Control Scheme for TCP,"
				 * appeared in SIGCOMM'96.
				 *
				 * Save highest seq no we have sent so far.
				 * Be careful about the invisible FIN byte.
				 */
				if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
				    (tcp->tcp_unsent == 0)) {
					tcp->tcp_rexmit_max = tcp->tcp_fss;
				} else {
					tcp->tcp_rexmit_max = tcp->tcp_snxt;
				}

				/*
				 * For SACK:
				 * Calculate tcp_pipe, which is the
				 * estimated number of bytes in
				 * network.
				 *
				 * tcp_fack is the highest sack'ed seq num
				 * TCP has received.
				 *
				 * tcp_pipe is explained in the above quoted
				 * Fall and Floyd's paper.  tcp_fack is
				 * explained in Mathis and Mahdavi's
				 * "Forward Acknowledgment: Refining TCP
				 * Congestion Control" in SIGCOMM '96.
				 */
				if (tcp->tcp_snd_sack_ok) {
					if (tcp->tcp_notsack_list != NULL) {
						tcp->tcp_pipe = tcp->tcp_snxt -
						    tcp->tcp_fack;
						tcp->tcp_sack_snxt = seg_ack;
						flags |= TH_NEED_SACK_REXMIT;
					} else {
						/*
						 * Always initialize tcp_pipe
						 * even though we don't have
						 * any SACK info.  If later
						 * we get SACK info and
						 * tcp_pipe is not initialized,
						 * funny things will happen.
						 */
						tcp->tcp_pipe =
						    tcp->tcp_cwnd_ssthresh;
					}
				} else {
					flags |= TH_REXMIT_NEEDED;
				} /* tcp_snd_sack_ok */

				} else {
					/*
					 * Here we perform congestion
					 * avoidance, but NOT slow start.
					 * This is known as the Fast
					 * Recovery Algorithm.
					 */
					if (tcp->tcp_snd_sack_ok &&
					    tcp->tcp_notsack_list != NULL) {
						flags |= TH_NEED_SACK_REXMIT;
						tcp->tcp_pipe -= mss;
						if (tcp->tcp_pipe < 0)
							tcp->tcp_pipe = 0;
					} else {
					/*
					 * We know that one more packet has
					 * left the pipe thus we can update
					 * cwnd.
					 */
					cwnd = tcp->tcp_cwnd + mss;
					if (cwnd > tcp->tcp_cwnd_max)
						cwnd = tcp->tcp_cwnd_max;
					tcp->tcp_cwnd = cwnd;
					if (tcp->tcp_unsent > 0)
						flags |= TH_XMIT_NEEDED;
					}
				}
			}
		} else if (tcp->tcp_zero_win_probe) {
			/*
			 * If the window has opened, need to arrange
			 * to send additional data.
			 */
			if (new_swnd != 0) {
				/* tcp_suna != tcp_snxt */
				/* Packet contains a window update */
				TCPS_BUMP_MIB(tcps, tcpInWinUpdate);
				tcp->tcp_zero_win_probe = 0;
				tcp->tcp_timer_backoff = 0;
				tcp->tcp_ms_we_have_waited = 0;

				/*
				 * Transmit starting with tcp_suna since
				 * the one byte probe is not ack'ed.
				 * If TCP has sent more than one identical
				 * probe, tcp_rexmit will be set.  That means
				 * tcp_ss_rexmit() will send out the one
				 * byte along with new data.  Otherwise,
				 * fake the retransmission.
				 */
				flags |= TH_XMIT_NEEDED;
				if (!tcp->tcp_rexmit) {
					tcp->tcp_rexmit = B_TRUE;
					tcp->tcp_dupack_cnt = 0;
					tcp->tcp_rexmit_nxt = tcp->tcp_suna;
					tcp->tcp_rexmit_max = tcp->tcp_suna + 1;
				}
			}
		}
		goto swnd_update;
	}

	/*
	 * Check for "acceptability" of ACK value per RFC 793, pages 72 - 73.
	 * If the ACK value acks something that we have not yet sent, it might
	 * be an old duplicate segment.  Send an ACK to re-synchronize the
	 * other side.
	 * Note: reset in response to unacceptable ACK in SYN_RECEIVE
	 * state is handled above, so we can always just drop the segment and
	 * send an ACK here.
	 *
	 * In the case where the peer shrinks the window, we see the new window
	 * update, but all the data sent previously is queued up by the peer.
	 * To account for this, in tcp_process_shrunk_swnd(), the sequence
	 * number, which was already sent, and within window, is recorded.
	 * tcp_snxt is then updated.
	 *
	 * If the window has previously shrunk, and an ACK for data not yet
	 * sent, according to tcp_snxt is recieved, it may still be valid. If
	 * the ACK is for data within the window at the time the window was
	 * shrunk, then the ACK is acceptable. In this case tcp_snxt is set to
	 * the sequence number ACK'ed.
	 *
	 * If the ACK covers all the data sent at the time the window was
	 * shrunk, we can now set tcp_is_wnd_shrnk to B_FALSE.
	 *
	 * Should we send ACKs in response to ACK only segments?
	 */

	if (SEQ_GT(seg_ack, tcp->tcp_snxt)) {
		if ((tcp->tcp_is_wnd_shrnk) &&
		    (SEQ_LEQ(seg_ack, tcp->tcp_snxt_shrunk))) {
			uint32_t data_acked_ahead_snxt;

			data_acked_ahead_snxt = seg_ack - tcp->tcp_snxt;
			tcp_update_xmit_tail(tcp, seg_ack);
			tcp->tcp_unsent -= data_acked_ahead_snxt;
		} else {
			TCPS_BUMP_MIB(tcps, tcpInAckUnsent);
			/* drop the received segment */
			freemsg(mp);

			/*
			 * Send back an ACK.  If tcp_drop_ack_unsent_cnt is
			 * greater than 0, check if the number of such
			 * bogus ACks is greater than that count.  If yes,
			 * don't send back any ACK.  This prevents TCP from
			 * getting into an ACK storm if somehow an attacker
			 * successfully spoofs an acceptable segment to our
			 * peer.  If this continues (count > 2 X threshold),
			 * we should abort this connection.
			 */
			if (tcp_drop_ack_unsent_cnt > 0 &&
			    ++tcp->tcp_in_ack_unsent >
			    tcp_drop_ack_unsent_cnt) {
				TCP_STAT(tcps, tcp_in_ack_unsent_drop);
				if (tcp->tcp_in_ack_unsent > 2 *
				    tcp_drop_ack_unsent_cnt) {
					(void) tcp_clean_death(tcp, EPROTO);
				}
				return;
			}
			mp = tcp_ack_mp(tcp);
			if (mp != NULL) {
				BUMP_LOCAL(tcp->tcp_obsegs);
				TCPS_BUMP_MIB(tcps, tcpOutAck);
				tcp_send_data(tcp, mp);
			}
			return;
		}
	} else if (tcp->tcp_is_wnd_shrnk && SEQ_GEQ(seg_ack,
	    tcp->tcp_snxt_shrunk)) {
			tcp->tcp_is_wnd_shrnk = B_FALSE;
	}

	/*
	 * TCP gets a new ACK, update the notsack'ed list to delete those
	 * blocks that are covered by this ACK.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
		tcp_notsack_remove(&(tcp->tcp_notsack_list), seg_ack,
		    &(tcp->tcp_num_notsack_blk), &(tcp->tcp_cnt_notsack_list));
	}

	/*
	 * If we got an ACK after fast retransmit, check to see
	 * if it is a partial ACK.  If it is not and the congestion
	 * window was inflated to account for the other side's
	 * cached packets, retract it.  If it is, do Hoe's algorithm.
	 */
	if (tcp->tcp_dupack_cnt >= tcps->tcps_dupack_fast_retransmit) {
		ASSERT(tcp->tcp_rexmit == B_FALSE);
		if (SEQ_GEQ(seg_ack, tcp->tcp_rexmit_max)) {
			tcp->tcp_dupack_cnt = 0;
			/*
			 * Restore the orig tcp_cwnd_ssthresh after
			 * fast retransmit phase.
			 */
			if (tcp->tcp_cwnd > tcp->tcp_cwnd_ssthresh) {
				tcp->tcp_cwnd = tcp->tcp_cwnd_ssthresh;
			}
			tcp->tcp_rexmit_max = seg_ack;
			tcp->tcp_cwnd_cnt = 0;

			/*
			 * Remove all notsack info to avoid confusion with
			 * the next fast retrasnmit/recovery phase.
			 */
			if (tcp->tcp_snd_sack_ok) {
				TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list,
				    tcp);
			}
		} else {
			if (tcp->tcp_snd_sack_ok &&
			    tcp->tcp_notsack_list != NULL) {
				flags |= TH_NEED_SACK_REXMIT;
				tcp->tcp_pipe -= mss;
				if (tcp->tcp_pipe < 0)
					tcp->tcp_pipe = 0;
			} else {
				/*
				 * Hoe's algorithm:
				 *
				 * Retransmit the unack'ed segment and
				 * restart fast recovery.  Note that we
				 * need to scale back tcp_cwnd to the
				 * original value when we started fast
				 * recovery.  This is to prevent overly
				 * aggressive behaviour in sending new
				 * segments.
				 */
				tcp->tcp_cwnd = tcp->tcp_cwnd_ssthresh +
				    tcps->tcps_dupack_fast_retransmit * mss;
				tcp->tcp_cwnd_cnt = tcp->tcp_cwnd;
				flags |= TH_REXMIT_NEEDED;
			}
		}
	} else {
		tcp->tcp_dupack_cnt = 0;
		if (tcp->tcp_rexmit) {
			/*
			 * TCP is retranmitting.  If the ACK ack's all
			 * outstanding data, update tcp_rexmit_max and
			 * tcp_rexmit_nxt.  Otherwise, update tcp_rexmit_nxt
			 * to the correct value.
			 *
			 * Note that SEQ_LEQ() is used.  This is to avoid
			 * unnecessary fast retransmit caused by dup ACKs
			 * received when TCP does slow start retransmission
			 * after a time out.  During this phase, TCP may
			 * send out segments which are already received.
			 * This causes dup ACKs to be sent back.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_rexmit_max)) {
				if (SEQ_GT(seg_ack, tcp->tcp_rexmit_nxt)) {
					tcp->tcp_rexmit_nxt = seg_ack;
				}
				if (seg_ack != tcp->tcp_rexmit_max) {
					flags |= TH_XMIT_NEEDED;
				}
			} else {
				tcp->tcp_rexmit = B_FALSE;
				tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
			}
			tcp->tcp_ms_we_have_waited = 0;
		}
	}

	TCPS_BUMP_MIB(tcps, tcpInAckSegs);
	TCPS_UPDATE_MIB(tcps, tcpInAckBytes, bytes_acked);
	tcp->tcp_suna = seg_ack;
	if (tcp->tcp_zero_win_probe != 0) {
		tcp->tcp_zero_win_probe = 0;
		tcp->tcp_timer_backoff = 0;
	}

	/*
	 * If tcp_xmit_head is NULL, then it must be the FIN being ack'ed.
	 * Note that it cannot be the SYN being ack'ed.  The code flow
	 * will not reach here.
	 */
	if (mp1 == NULL) {
		goto fin_acked;
	}

	/*
	 * Update the congestion window.
	 *
	 * If TCP is not ECN capable or TCP is ECN capable but the
	 * congestion experience bit is not set, increase the tcp_cwnd as
	 * usual.
	 */
	if (!tcp->tcp_ecn_ok || !(flags & TH_ECE)) {
		cwnd = tcp->tcp_cwnd;
		add = mss;

		if (cwnd >= tcp->tcp_cwnd_ssthresh) {
			/*
			 * This is to prevent an increase of less than 1 MSS of
			 * tcp_cwnd.  With partial increase, tcp_wput_data()
			 * may send out tinygrams in order to preserve mblk
			 * boundaries.
			 *
			 * By initializing tcp_cwnd_cnt to new tcp_cwnd and
			 * decrementing it by 1 MSS for every ACKs, tcp_cwnd is
			 * increased by 1 MSS for every RTTs.
			 */
			if (tcp->tcp_cwnd_cnt <= 0) {
				tcp->tcp_cwnd_cnt = cwnd + add;
			} else {
				tcp->tcp_cwnd_cnt -= add;
				add = 0;
			}
		}
		tcp->tcp_cwnd = MIN(cwnd + add, tcp->tcp_cwnd_max);
	}

	/* See if the latest urgent data has been acknowledged */
	if ((tcp->tcp_valid_bits & TCP_URG_VALID) &&
	    SEQ_GT(seg_ack, tcp->tcp_urg))
		tcp->tcp_valid_bits &= ~TCP_URG_VALID;

	/* Can we update the RTT estimates? */
	if (tcp->tcp_snd_ts_ok) {
		/* Ignore zero timestamp echo-reply. */
		if (tcpopt.tcp_opt_ts_ecr != 0) {
			tcp_set_rto(tcp, (int32_t)LBOLT_FASTPATH -
			    (int32_t)tcpopt.tcp_opt_ts_ecr);
		}

		/* If needed, restart the timer. */
		if (tcp->tcp_set_timer == 1) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
			tcp->tcp_set_timer = 0;
		}
		/*
		 * Update tcp_csuna in case the other side stops sending
		 * us timestamps.
		 */
		tcp->tcp_csuna = tcp->tcp_snxt;
	} else if (SEQ_GT(seg_ack, tcp->tcp_csuna)) {
		/*
		 * An ACK sequence we haven't seen before, so get the RTT
		 * and update the RTO. But first check if the timestamp is
		 * valid to use.
		 */
		if ((mp1->b_next != NULL) &&
		    SEQ_GT(seg_ack, (uint32_t)(uintptr_t)(mp1->b_next)))
			tcp_set_rto(tcp, (int32_t)LBOLT_FASTPATH -
			    (int32_t)(intptr_t)mp1->b_prev);
		else
			TCPS_BUMP_MIB(tcps, tcpRttNoUpdate);

		/* Remeber the last sequence to be ACKed */
		tcp->tcp_csuna = seg_ack;
		if (tcp->tcp_set_timer == 1) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
			tcp->tcp_set_timer = 0;
		}
	} else {
		TCPS_BUMP_MIB(tcps, tcpRttNoUpdate);
	}

	/* Eat acknowledged bytes off the xmit queue. */
	for (;;) {
		mblk_t	*mp2;
		uchar_t	*wptr;

		wptr = mp1->b_wptr;
		ASSERT((uintptr_t)(wptr - mp1->b_rptr) <= (uintptr_t)INT_MAX);
		bytes_acked -= (int)(wptr - mp1->b_rptr);
		if (bytes_acked < 0) {
			mp1->b_rptr = wptr + bytes_acked;
			/*
			 * Set a new timestamp if all the bytes timed by the
			 * old timestamp have been ack'ed.
			 */
			if (SEQ_GT(seg_ack,
			    (uint32_t)(uintptr_t)(mp1->b_next))) {
				mp1->b_prev =
				    (mblk_t *)(uintptr_t)LBOLT_FASTPATH;
				mp1->b_next = NULL;
			}
			break;
		}
		mp1->b_next = NULL;
		mp1->b_prev = NULL;
		mp2 = mp1;
		mp1 = mp1->b_cont;

		/*
		 * This notification is required for some zero-copy
		 * clients to maintain a copy semantic. After the data
		 * is ack'ed, client is safe to modify or reuse the buffer.
		 */
		if (tcp->tcp_snd_zcopy_aware &&
		    (mp2->b_datap->db_struioflag & STRUIO_ZCNOTIFY))
			tcp_zcopy_notify(tcp);
		freeb(mp2);
		if (bytes_acked == 0) {
			if (mp1 == NULL) {
				/* Everything is ack'ed, clear the tail. */
				tcp->tcp_xmit_tail = NULL;
				/*
				 * Cancel the timer unless we are still
				 * waiting for an ACK for the FIN packet.
				 */
				if (tcp->tcp_timer_tid != 0 &&
				    tcp->tcp_snxt == tcp->tcp_suna) {
					(void) TCP_TIMER_CANCEL(tcp,
					    tcp->tcp_timer_tid);
					tcp->tcp_timer_tid = 0;
				}
				goto pre_swnd_update;
			}
			if (mp2 != tcp->tcp_xmit_tail)
				break;
			tcp->tcp_xmit_tail = mp1;
			ASSERT((uintptr_t)(mp1->b_wptr - mp1->b_rptr) <=
			    (uintptr_t)INT_MAX);
			tcp->tcp_xmit_tail_unsent = (int)(mp1->b_wptr -
			    mp1->b_rptr);
			break;
		}
		if (mp1 == NULL) {
			/*
			 * More was acked but there is nothing more
			 * outstanding.  This means that the FIN was
			 * just acked or that we're talking to a clown.
			 */
fin_acked:
			ASSERT(tcp->tcp_fin_sent);
			tcp->tcp_xmit_tail = NULL;
			if (tcp->tcp_fin_sent) {
				/* FIN was acked - making progress */
				if (!tcp->tcp_fin_acked)
					tcp->tcp_ip_forward_progress = B_TRUE;
				tcp->tcp_fin_acked = B_TRUE;
				if (tcp->tcp_linger_tid != 0 &&
				    TCP_TIMER_CANCEL(tcp,
				    tcp->tcp_linger_tid) >= 0) {
					tcp_stop_lingering(tcp);
					freemsg(mp);
					mp = NULL;
				}
			} else {
				/*
				 * We should never get here because
				 * we have already checked that the
				 * number of bytes ack'ed should be
				 * smaller than or equal to what we
				 * have sent so far (it is the
				 * acceptability check of the ACK).
				 * We can only get here if the send
				 * queue is corrupted.
				 *
				 * Terminate the connection and
				 * panic the system.  It is better
				 * for us to panic instead of
				 * continuing to avoid other disaster.
				 */
				tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_RST|TH_ACK);
				panic("Memory corruption "
				    "detected for connection %s.",
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
				/*NOTREACHED*/
			}
			goto pre_swnd_update;
		}
		ASSERT(mp2 != tcp->tcp_xmit_tail);
	}
	if (tcp->tcp_unsent) {
		flags |= TH_XMIT_NEEDED;
	}
pre_swnd_update:
	tcp->tcp_xmit_head = mp1;
swnd_update:
	/*
	 * The following check is different from most other implementations.
	 * For bi-directional transfer, when segments are dropped, the
	 * "normal" check will not accept a window update in those
	 * retransmitted segemnts.  Failing to do that, TCP may send out
	 * segments which are outside receiver's window.  As TCP accepts
	 * the ack in those retransmitted segments, if the window update in
	 * the same segment is not accepted, TCP will incorrectly calculates
	 * that it can send more segments.  This can create a deadlock
	 * with the receiver if its window becomes zero.
	 */
	if (SEQ_LT(tcp->tcp_swl2, seg_ack) ||
	    SEQ_LT(tcp->tcp_swl1, seg_seq) ||
	    (tcp->tcp_swl1 == seg_seq && new_swnd > tcp->tcp_swnd)) {
		/*
		 * The criteria for update is:
		 *
		 * 1. the segment acknowledges some data.  Or
		 * 2. the segment is new, i.e. it has a higher seq num. Or
		 * 3. the segment is not old and the advertised window is
		 * larger than the previous advertised window.
		 */
		if (tcp->tcp_unsent && new_swnd > tcp->tcp_swnd)
			flags |= TH_XMIT_NEEDED;
		tcp->tcp_swnd = new_swnd;
		if (new_swnd > tcp->tcp_max_swnd)
			tcp->tcp_max_swnd = new_swnd;
		tcp->tcp_swl1 = seg_seq;
		tcp->tcp_swl2 = seg_ack;
	}
est:
	if (tcp->tcp_state > TCPS_ESTABLISHED) {

		switch (tcp->tcp_state) {
		case TCPS_FIN_WAIT_1:
			if (tcp->tcp_fin_acked) {
				tcp->tcp_state = TCPS_FIN_WAIT_2;
				DTRACE_TCP6(state__change, void, NULL,
				    ip_xmit_attr_t *, connp->conn_ixa,
				    void, NULL, tcp_t *, tcp, void, NULL,
				    int32_t, TCPS_FIN_WAIT_1);
				/*
				 * We implement the non-standard BSD/SunOS
				 * FIN_WAIT_2 flushing algorithm.
				 * If there is no user attached to this
				 * TCP endpoint, then this TCP struct
				 * could hang around forever in FIN_WAIT_2
				 * state if the peer forgets to send us
				 * a FIN.  To prevent this, we wait only
				 * 2*MSL (a convenient time value) for
				 * the FIN to arrive.  If it doesn't show up,
				 * we flush the TCP endpoint.  This algorithm,
				 * though a violation of RFC-793, has worked
				 * for over 10 years in BSD systems.
				 * Note: SunOS 4.x waits 675 seconds before
				 * flushing the FIN_WAIT_2 connection.
				 */
				TCP_TIMER_RESTART(tcp,
				    tcp->tcp_fin_wait_2_flush_interval);
			}
			break;
		case TCPS_FIN_WAIT_2:
			break;	/* Shutdown hook? */
		case TCPS_LAST_ACK:
			freemsg(mp);
			if (tcp->tcp_fin_acked) {
				(void) tcp_clean_death(tcp, 0);
				return;
			}
			goto xmit_check;
		case TCPS_CLOSING:
			if (tcp->tcp_fin_acked) {
				SET_TIME_WAIT(tcps, tcp, connp);
				DTRACE_TCP6(state__change, void, NULL,
				    ip_xmit_attr_t *, connp->conn_ixa, void,
				    NULL, tcp_t *, tcp, void, NULL, int32_t,
				    TCPS_CLOSING);
			}
			/*FALLTHRU*/
		case TCPS_CLOSE_WAIT:
			freemsg(mp);
			goto xmit_check;
		default:
			ASSERT(tcp->tcp_state != TCPS_TIME_WAIT);
			break;
		}
	}
	if (flags & TH_FIN) {
		/* Make sure we ack the fin */
		flags |= TH_ACK_NEEDED;
		if (!tcp->tcp_fin_rcvd) {
			tcp->tcp_fin_rcvd = B_TRUE;
			tcp->tcp_rnxt++;
			tcpha = tcp->tcp_tcpha;
			tcpha->tha_ack = htonl(tcp->tcp_rnxt);

			/*
			 * Generate the ordrel_ind at the end unless the
			 * conn is detached or it is a STREAMS based eager.
			 * In the eager case we defer the notification until
			 * tcp_accept_finish has run.
			 */
			if (!TCP_IS_DETACHED(tcp) && (IPCL_IS_NONSTR(connp) ||
			    (tcp->tcp_listener == NULL &&
			    !tcp->tcp_hard_binding)))
				flags |= TH_ORDREL_NEEDED;
			switch (tcp->tcp_state) {
			case TCPS_SYN_RCVD:
				tcp->tcp_state = TCPS_CLOSE_WAIT;
				DTRACE_TCP6(state__change, void, NULL,
				    ip_xmit_attr_t *, connp->conn_ixa,
				    void, NULL, tcp_t *, tcp, void, NULL,
				    int32_t, TCPS_SYN_RCVD);
				/* Keepalive? */
				break;
			case TCPS_ESTABLISHED:
				tcp->tcp_state = TCPS_CLOSE_WAIT;
				DTRACE_TCP6(state__change, void, NULL,
				    ip_xmit_attr_t *, connp->conn_ixa,
				    void, NULL, tcp_t *, tcp, void, NULL,
				    int32_t, TCPS_ESTABLISHED);
				/* Keepalive? */
				break;
			case TCPS_FIN_WAIT_1:
				if (!tcp->tcp_fin_acked) {
					tcp->tcp_state = TCPS_CLOSING;
					DTRACE_TCP6(state__change, void, NULL,
					    ip_xmit_attr_t *, connp->conn_ixa,
					    void, NULL, tcp_t *, tcp, void,
					    NULL, int32_t, TCPS_FIN_WAIT_1);
					break;
				}
				/* FALLTHRU */
			case TCPS_FIN_WAIT_2:
				SET_TIME_WAIT(tcps, tcp, connp);
				DTRACE_TCP6(state__change, void, NULL,
				    ip_xmit_attr_t *, connp->conn_ixa, void,
				    NULL, tcp_t *, tcp, void, NULL, int32_t,
				    TCPS_FIN_WAIT_2);
				if (seg_len) {
					/*
					 * implies data piggybacked on FIN.
					 * break to handle data.
					 */
					break;
				}
				freemsg(mp);
				goto ack_check;
			}
		}
	}
	if (mp == NULL)
		goto xmit_check;
	if (seg_len == 0) {
		freemsg(mp);
		goto xmit_check;
	}
	if (mp->b_rptr == mp->b_wptr) {
		/*
		 * The header has been consumed, so we remove the
		 * zero-length mblk here.
		 */
		mp1 = mp;
		mp = mp->b_cont;
		freeb(mp1);
	}
update_ack:
	tcpha = tcp->tcp_tcpha;
	tcp->tcp_rack_cnt++;
	{
		uint32_t cur_max;

		cur_max = tcp->tcp_rack_cur_max;
		if (tcp->tcp_rack_cnt >= cur_max) {
			/*
			 * We have more unacked data than we should - send
			 * an ACK now.
			 */
			flags |= TH_ACK_NEEDED;
			cur_max++;
			if (cur_max > tcp->tcp_rack_abs_max)
				tcp->tcp_rack_cur_max = tcp->tcp_rack_abs_max;
			else
				tcp->tcp_rack_cur_max = cur_max;
		} else if (TCP_IS_DETACHED(tcp)) {
			/* We don't have an ACK timer for detached TCP. */
			flags |= TH_ACK_NEEDED;
		} else if (seg_len < mss) {
			/*
			 * If we get a segment that is less than an mss, and we
			 * already have unacknowledged data, and the amount
			 * unacknowledged is not a multiple of mss, then we
			 * better generate an ACK now.  Otherwise, this may be
			 * the tail piece of a transaction, and we would rather
			 * wait for the response.
			 */
			uint32_t udif;
			ASSERT((uintptr_t)(tcp->tcp_rnxt - tcp->tcp_rack) <=
			    (uintptr_t)INT_MAX);
			udif = (int)(tcp->tcp_rnxt - tcp->tcp_rack);
			if (udif && (udif % mss))
				flags |= TH_ACK_NEEDED;
			else
				flags |= TH_ACK_TIMER_NEEDED;
		} else {
			/* Start delayed ack timer */
			flags |= TH_ACK_TIMER_NEEDED;
		}
	}
	tcp->tcp_rnxt += seg_len;
	tcpha->tha_ack = htonl(tcp->tcp_rnxt);

	if (mp == NULL)
		goto xmit_check;

	/* Update SACK list */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		tcp_sack_remove(tcp->tcp_sack_list, tcp->tcp_rnxt,
		    &(tcp->tcp_num_sack_blk));
	}

	if (tcp->tcp_urp_mp) {
		tcp->tcp_urp_mp->b_cont = mp;
		mp = tcp->tcp_urp_mp;
		tcp->tcp_urp_mp = NULL;
		/* Ready for a new signal. */
		tcp->tcp_urp_last_valid = B_FALSE;
#ifdef DEBUG
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_rput: sending exdata_ind %s",
		    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
	}

	/*
	 * Check for ancillary data changes compared to last segment.
	 */
	if (connp->conn_recv_ancillary.crb_all != 0) {
		mp = tcp_input_add_ancillary(tcp, mp, &ipp, ira);
		if (mp == NULL)
			return;
	}

	if (IPCL_IS_NONSTR(connp)) {
		/*
		 * Non-STREAMS socket
		 */
		boolean_t push = flags & (TH_PUSH|TH_FIN);
		int error;

		if ((*sockupcalls->su_recv)(connp->conn_upper_handle,
		    mp, seg_len, 0, &error, &push) <= 0) {
			/*
			 * We should never be in middle of a
			 * fallback, the squeue guarantees that.
			 */
			ASSERT(error != EOPNOTSUPP);
			if (error == ENOSPC)
				tcp->tcp_rwnd -= seg_len;
		} else if (push) {
			/* PUSH bit set and sockfs is not flow controlled */
			flags |= tcp_rwnd_reopen(tcp);
		}
	} else if (tcp->tcp_listener != NULL || tcp->tcp_hard_binding) {
		/*
		 * Side queue inbound data until the accept happens.
		 * tcp_accept/tcp_rput drains this when the accept happens.
		 * M_DATA is queued on b_cont. Otherwise (T_OPTDATA_IND or
		 * T_EXDATA_IND) it is queued on b_next.
		 * XXX Make urgent data use this. Requires:
		 *	Removing tcp_listener check for TH_URG
		 *	Making M_PCPROTO and MARK messages skip the eager case
		 */

		tcp_rcv_enqueue(tcp, mp, seg_len, ira->ira_cred);
	} else {
		/* Active STREAMS socket */
		if (mp->b_datap->db_type != M_DATA ||
		    (flags & TH_MARKNEXT_NEEDED)) {
			if (tcp->tcp_rcv_list != NULL) {
				flags |= tcp_rcv_drain(tcp);
			}
			ASSERT(tcp->tcp_rcv_list == NULL ||
			    tcp->tcp_fused_sigurg);

			if (flags & TH_MARKNEXT_NEEDED) {
#ifdef DEBUG
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: sending MSGMARKNEXT %s",
				    tcp_display(tcp, NULL,
				    DISP_PORT_ONLY));
#endif /* DEBUG */
				mp->b_flag |= MSGMARKNEXT;
				flags &= ~TH_MARKNEXT_NEEDED;
			}

			if (is_system_labeled())
				tcp_setcred_data(mp, ira);

			putnext(connp->conn_rq, mp);
			if (!canputnext(connp->conn_rq))
				tcp->tcp_rwnd -= seg_len;
		} else if ((flags & (TH_PUSH|TH_FIN)) ||
		    tcp->tcp_rcv_cnt + seg_len >= connp->conn_rcvbuf >> 3) {
			if (tcp->tcp_rcv_list != NULL) {
				/*
				 * Enqueue the new segment first and then
				 * call tcp_rcv_drain() to send all data
				 * up.  The other way to do this is to
				 * send all queued data up and then call
				 * putnext() to send the new segment up.
				 * This way can remove the else part later
				 * on.
				 *
				 * We don't do this to avoid one more call to
				 * canputnext() as tcp_rcv_drain() needs to
				 * call canputnext().
				 */
				tcp_rcv_enqueue(tcp, mp, seg_len,
				    ira->ira_cred);
				flags |= tcp_rcv_drain(tcp);
			} else {
				if (is_system_labeled())
					tcp_setcred_data(mp, ira);

				putnext(connp->conn_rq, mp);
				if (!canputnext(connp->conn_rq))
					tcp->tcp_rwnd -= seg_len;
			}
		} else {
			/*
			 * Enqueue all packets when processing an mblk
			 * from the co queue and also enqueue normal packets.
			 */
			tcp_rcv_enqueue(tcp, mp, seg_len, ira->ira_cred);
		}
		/*
		 * Make sure the timer is running if we have data waiting
		 * for a push bit. This provides resiliency against
		 * implementations that do not correctly generate push bits.
		 */
		if (tcp->tcp_rcv_list != NULL && tcp->tcp_push_tid == 0) {
			/*
			 * The connection may be closed at this point, so don't
			 * do anything for a detached tcp.
			 */
			if (!TCP_IS_DETACHED(tcp))
				tcp->tcp_push_tid = TCP_TIMER(tcp,
				    tcp_push_timer,
				    tcps->tcps_push_timer_interval);
		}
	}

xmit_check:
	/* Is there anything left to do? */
	ASSERT(!(flags & TH_MARKNEXT_NEEDED));
	if ((flags & (TH_REXMIT_NEEDED|TH_XMIT_NEEDED|TH_ACK_NEEDED|
	    TH_NEED_SACK_REXMIT|TH_LIMIT_XMIT|TH_ACK_TIMER_NEEDED|
	    TH_ORDREL_NEEDED|TH_SEND_URP_MARK)) == 0)
		goto done;

	/* Any transmit work to do and a non-zero window? */
	if ((flags & (TH_REXMIT_NEEDED|TH_XMIT_NEEDED|TH_NEED_SACK_REXMIT|
	    TH_LIMIT_XMIT)) && tcp->tcp_swnd != 0) {
		if (flags & TH_REXMIT_NEEDED) {
			uint32_t snd_size = tcp->tcp_snxt - tcp->tcp_suna;

			TCPS_BUMP_MIB(tcps, tcpOutFastRetrans);
			if (snd_size > mss)
				snd_size = mss;
			if (snd_size > tcp->tcp_swnd)
				snd_size = tcp->tcp_swnd;
			mp1 = tcp_xmit_mp(tcp, tcp->tcp_xmit_head, snd_size,
			    NULL, NULL, tcp->tcp_suna, B_TRUE, &snd_size,
			    B_TRUE);

			if (mp1 != NULL) {
				tcp->tcp_xmit_head->b_prev =
				    (mblk_t *)LBOLT_FASTPATH;
				tcp->tcp_csuna = tcp->tcp_snxt;
				TCPS_BUMP_MIB(tcps, tcpRetransSegs);
				TCPS_UPDATE_MIB(tcps, tcpRetransBytes,
				    snd_size);
				tcp_send_data(tcp, mp1);
			}
		}
		if (flags & TH_NEED_SACK_REXMIT) {
			tcp_sack_rexmit(tcp, &flags);
		}
		/*
		 * For TH_LIMIT_XMIT, tcp_wput_data() is called to send
		 * out new segment.  Note that tcp_rexmit should not be
		 * set, otherwise TH_LIMIT_XMIT should not be set.
		 */
		if (flags & (TH_XMIT_NEEDED|TH_LIMIT_XMIT)) {
			if (!tcp->tcp_rexmit) {
				tcp_wput_data(tcp, NULL, B_FALSE);
			} else {
				tcp_ss_rexmit(tcp);
			}
		}
		/*
		 * Adjust tcp_cwnd back to normal value after sending
		 * new data segments.
		 */
		if (flags & TH_LIMIT_XMIT) {
			tcp->tcp_cwnd -= mss << (tcp->tcp_dupack_cnt - 1);
			/*
			 * This will restart the timer.  Restarting the
			 * timer is used to avoid a timeout before the
			 * limited transmitted segment's ACK gets back.
			 */
			if (tcp->tcp_xmit_head != NULL)
				tcp->tcp_xmit_head->b_prev =
				    (mblk_t *)LBOLT_FASTPATH;
		}

		/* Anything more to do? */
		if ((flags & (TH_ACK_NEEDED|TH_ACK_TIMER_NEEDED|
		    TH_ORDREL_NEEDED|TH_SEND_URP_MARK)) == 0)
			goto done;
	}
ack_check:
	if (flags & TH_SEND_URP_MARK) {
		ASSERT(tcp->tcp_urp_mark_mp);
		ASSERT(!IPCL_IS_NONSTR(connp));
		/*
		 * Send up any queued data and then send the mark message
		 */
		if (tcp->tcp_rcv_list != NULL) {
			flags |= tcp_rcv_drain(tcp);

		}
		ASSERT(tcp->tcp_rcv_list == NULL || tcp->tcp_fused_sigurg);
		mp1 = tcp->tcp_urp_mark_mp;
		tcp->tcp_urp_mark_mp = NULL;
		if (is_system_labeled())
			tcp_setcred_data(mp1, ira);

		putnext(connp->conn_rq, mp1);
#ifdef DEBUG
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_rput: sending zero-length %s %s",
		    ((mp1->b_flag & MSGMARKNEXT) ? "MSGMARKNEXT" :
		    "MSGNOTMARKNEXT"),
		    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
		flags &= ~TH_SEND_URP_MARK;
	}
	if (flags & TH_ACK_NEEDED) {
		/*
		 * Time to send an ack for some reason.
		 */
		mp1 = tcp_ack_mp(tcp);

		if (mp1 != NULL) {
			tcp_send_data(tcp, mp1);
			BUMP_LOCAL(tcp->tcp_obsegs);
			TCPS_BUMP_MIB(tcps, tcpOutAck);
		}
		if (tcp->tcp_ack_tid != 0) {
			(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_ack_tid);
			tcp->tcp_ack_tid = 0;
		}
	}
	if (flags & TH_ACK_TIMER_NEEDED) {
		/*
		 * Arrange for deferred ACK or push wait timeout.
		 * Start timer if it is not already running.
		 */
		if (tcp->tcp_ack_tid == 0) {
			tcp->tcp_ack_tid = TCP_TIMER(tcp, tcp_ack_timer,
			    tcp->tcp_localnet ?
			    tcps->tcps_local_dack_interval :
			    tcps->tcps_deferred_ack_interval);
		}
	}
	if (flags & TH_ORDREL_NEEDED) {
		/*
		 * Notify upper layer about an orderly release. If this is
		 * a non-STREAMS socket, then just make an upcall. For STREAMS
		 * we send up an ordrel_ind, unless this is an eager, in which
		 * case the ordrel will be sent when tcp_accept_finish runs.
		 * Note that for non-STREAMS we make an upcall even if it is an
		 * eager, because we have an upper handle to send it to.
		 */
		ASSERT(IPCL_IS_NONSTR(connp) || tcp->tcp_listener == NULL);
		ASSERT(!tcp->tcp_detached);

		if (IPCL_IS_NONSTR(connp)) {
			ASSERT(tcp->tcp_ordrel_mp == NULL);
			tcp->tcp_ordrel_done = B_TRUE;
			(*sockupcalls->su_opctl)(connp->conn_upper_handle,
			    SOCK_OPCTL_SHUT_RECV, 0);
			goto done;
		}

		if (tcp->tcp_rcv_list != NULL) {
			/*
			 * Push any mblk(s) enqueued from co processing.
			 */
			flags |= tcp_rcv_drain(tcp);
		}
		ASSERT(tcp->tcp_rcv_list == NULL || tcp->tcp_fused_sigurg);

		mp1 = tcp->tcp_ordrel_mp;
		tcp->tcp_ordrel_mp = NULL;
		tcp->tcp_ordrel_done = B_TRUE;
		putnext(connp->conn_rq, mp1);
	}
done:
	ASSERT(!(flags & TH_MARKNEXT_NEEDED));
}

/*
 * Attach ancillary data to a received TCP segments for the
 * ancillary pieces requested by the application that are
 * different than they were in the previous data segment.
 *
 * Save the "current" values once memory allocation is ok so that
 * when memory allocation fails we can just wait for the next data segment.
 */
static mblk_t *
tcp_input_add_ancillary(tcp_t *tcp, mblk_t *mp, ip_pkt_t *ipp,
    ip_recv_attr_t *ira)
{
	struct T_optdata_ind *todi;
	int optlen;
	uchar_t *optptr;
	struct T_opthdr *toh;
	crb_t addflag;	/* Which pieces to add */
	mblk_t *mp1;
	conn_t	*connp = tcp->tcp_connp;

	optlen = 0;
	addflag.crb_all = 0;
	/* If app asked for pktinfo and the index has changed ... */
	if (connp->conn_recv_ancillary.crb_ip_recvpktinfo &&
	    ira->ira_ruifindex != tcp->tcp_recvifindex) {
		optlen += sizeof (struct T_opthdr) +
		    sizeof (struct in6_pktinfo);
		addflag.crb_ip_recvpktinfo = 1;
	}
	/* If app asked for hoplimit and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvhoplimit &&
	    ipp->ipp_hoplimit != tcp->tcp_recvhops) {
		optlen += sizeof (struct T_opthdr) + sizeof (uint_t);
		addflag.crb_ipv6_recvhoplimit = 1;
	}
	/* If app asked for tclass and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvtclass &&
	    ipp->ipp_tclass != tcp->tcp_recvtclass) {
		optlen += sizeof (struct T_opthdr) + sizeof (uint_t);
		addflag.crb_ipv6_recvtclass = 1;
	}
	/*
	 * If app asked for hopbyhop headers and it has changed ...
	 * For security labels, note that (1) security labels can't change on
	 * a connected socket at all, (2) we're connected to at most one peer,
	 * (3) if anything changes, then it must be some other extra option.
	 */
	if (connp->conn_recv_ancillary.crb_ipv6_recvhopopts &&
	    ip_cmpbuf(tcp->tcp_hopopts, tcp->tcp_hopoptslen,
	    (ipp->ipp_fields & IPPF_HOPOPTS),
	    ipp->ipp_hopopts, ipp->ipp_hopoptslen)) {
		optlen += sizeof (struct T_opthdr) + ipp->ipp_hopoptslen;
		addflag.crb_ipv6_recvhopopts = 1;
		if (!ip_allocbuf((void **)&tcp->tcp_hopopts,
		    &tcp->tcp_hopoptslen, (ipp->ipp_fields & IPPF_HOPOPTS),
		    ipp->ipp_hopopts, ipp->ipp_hopoptslen))
			return (mp);
	}
	/* If app asked for dst headers before routing headers ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvrthdrdstopts &&
	    ip_cmpbuf(tcp->tcp_rthdrdstopts, tcp->tcp_rthdrdstoptslen,
	    (ipp->ipp_fields & IPPF_RTHDRDSTOPTS),
	    ipp->ipp_rthdrdstopts, ipp->ipp_rthdrdstoptslen)) {
		optlen += sizeof (struct T_opthdr) +
		    ipp->ipp_rthdrdstoptslen;
		addflag.crb_ipv6_recvrthdrdstopts = 1;
		if (!ip_allocbuf((void **)&tcp->tcp_rthdrdstopts,
		    &tcp->tcp_rthdrdstoptslen,
		    (ipp->ipp_fields & IPPF_RTHDRDSTOPTS),
		    ipp->ipp_rthdrdstopts, ipp->ipp_rthdrdstoptslen))
			return (mp);
	}
	/* If app asked for routing headers and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvrthdr &&
	    ip_cmpbuf(tcp->tcp_rthdr, tcp->tcp_rthdrlen,
	    (ipp->ipp_fields & IPPF_RTHDR),
	    ipp->ipp_rthdr, ipp->ipp_rthdrlen)) {
		optlen += sizeof (struct T_opthdr) + ipp->ipp_rthdrlen;
		addflag.crb_ipv6_recvrthdr = 1;
		if (!ip_allocbuf((void **)&tcp->tcp_rthdr,
		    &tcp->tcp_rthdrlen, (ipp->ipp_fields & IPPF_RTHDR),
		    ipp->ipp_rthdr, ipp->ipp_rthdrlen))
			return (mp);
	}
	/* If app asked for dest headers and it has changed ... */
	if ((connp->conn_recv_ancillary.crb_ipv6_recvdstopts ||
	    connp->conn_recv_ancillary.crb_old_ipv6_recvdstopts) &&
	    ip_cmpbuf(tcp->tcp_dstopts, tcp->tcp_dstoptslen,
	    (ipp->ipp_fields & IPPF_DSTOPTS),
	    ipp->ipp_dstopts, ipp->ipp_dstoptslen)) {
		optlen += sizeof (struct T_opthdr) + ipp->ipp_dstoptslen;
		addflag.crb_ipv6_recvdstopts = 1;
		if (!ip_allocbuf((void **)&tcp->tcp_dstopts,
		    &tcp->tcp_dstoptslen, (ipp->ipp_fields & IPPF_DSTOPTS),
		    ipp->ipp_dstopts, ipp->ipp_dstoptslen))
			return (mp);
	}

	if (optlen == 0) {
		/* Nothing to add */
		return (mp);
	}
	mp1 = allocb(sizeof (struct T_optdata_ind) + optlen, BPRI_MED);
	if (mp1 == NULL) {
		/*
		 * Defer sending ancillary data until the next TCP segment
		 * arrives.
		 */
		return (mp);
	}
	mp1->b_cont = mp;
	mp = mp1;
	mp->b_wptr += sizeof (*todi) + optlen;
	mp->b_datap->db_type = M_PROTO;
	todi = (struct T_optdata_ind *)mp->b_rptr;
	todi->PRIM_type = T_OPTDATA_IND;
	todi->DATA_flag = 1;	/* MORE data */
	todi->OPT_length = optlen;
	todi->OPT_offset = sizeof (*todi);
	optptr = (uchar_t *)&todi[1];
	/*
	 * If app asked for pktinfo and the index has changed ...
	 * Note that the local address never changes for the connection.
	 */
	if (addflag.crb_ip_recvpktinfo) {
		struct in6_pktinfo *pkti;
		uint_t ifindex;

		ifindex = ira->ira_ruifindex;
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_PKTINFO;
		toh->len = sizeof (*toh) + sizeof (*pkti);
		toh->status = 0;
		optptr += sizeof (*toh);
		pkti = (struct in6_pktinfo *)optptr;
		pkti->ipi6_addr = connp->conn_laddr_v6;
		pkti->ipi6_ifindex = ifindex;
		optptr += sizeof (*pkti);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		tcp->tcp_recvifindex = ifindex;
	}
	/* If app asked for hoplimit and it has changed ... */
	if (addflag.crb_ipv6_recvhoplimit) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_HOPLIMIT;
		toh->len = sizeof (*toh) + sizeof (uint_t);
		toh->status = 0;
		optptr += sizeof (*toh);
		*(uint_t *)optptr = ipp->ipp_hoplimit;
		optptr += sizeof (uint_t);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		tcp->tcp_recvhops = ipp->ipp_hoplimit;
	}
	/* If app asked for tclass and it has changed ... */
	if (addflag.crb_ipv6_recvtclass) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_TCLASS;
		toh->len = sizeof (*toh) + sizeof (uint_t);
		toh->status = 0;
		optptr += sizeof (*toh);
		*(uint_t *)optptr = ipp->ipp_tclass;
		optptr += sizeof (uint_t);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		tcp->tcp_recvtclass = ipp->ipp_tclass;
	}
	if (addflag.crb_ipv6_recvhopopts) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_HOPOPTS;
		toh->len = sizeof (*toh) + ipp->ipp_hopoptslen;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy((uchar_t *)ipp->ipp_hopopts, optptr, ipp->ipp_hopoptslen);
		optptr += ipp->ipp_hopoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_hopopts, &tcp->tcp_hopoptslen,
		    (ipp->ipp_fields & IPPF_HOPOPTS),
		    ipp->ipp_hopopts, ipp->ipp_hopoptslen);
	}
	if (addflag.crb_ipv6_recvrthdrdstopts) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_RTHDRDSTOPTS;
		toh->len = sizeof (*toh) + ipp->ipp_rthdrdstoptslen;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy(ipp->ipp_rthdrdstopts, optptr, ipp->ipp_rthdrdstoptslen);
		optptr += ipp->ipp_rthdrdstoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_rthdrdstopts,
		    &tcp->tcp_rthdrdstoptslen,
		    (ipp->ipp_fields & IPPF_RTHDRDSTOPTS),
		    ipp->ipp_rthdrdstopts, ipp->ipp_rthdrdstoptslen);
	}
	if (addflag.crb_ipv6_recvrthdr) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_RTHDR;
		toh->len = sizeof (*toh) + ipp->ipp_rthdrlen;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy(ipp->ipp_rthdr, optptr, ipp->ipp_rthdrlen);
		optptr += ipp->ipp_rthdrlen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_rthdr, &tcp->tcp_rthdrlen,
		    (ipp->ipp_fields & IPPF_RTHDR),
		    ipp->ipp_rthdr, ipp->ipp_rthdrlen);
	}
	if (addflag.crb_ipv6_recvdstopts) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_DSTOPTS;
		toh->len = sizeof (*toh) + ipp->ipp_dstoptslen;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy(ipp->ipp_dstopts, optptr, ipp->ipp_dstoptslen);
		optptr += ipp->ipp_dstoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_dstopts, &tcp->tcp_dstoptslen,
		    (ipp->ipp_fields & IPPF_DSTOPTS),
		    ipp->ipp_dstopts, ipp->ipp_dstoptslen);
	}
	ASSERT(optptr == mp->b_wptr);
	return (mp);
}

/* The minimum of smoothed mean deviation in RTO calculation. */
#define	TCP_SD_MIN	400

/*
 * Set RTO for this connection.  The formula is from Jacobson and Karels'
 * "Congestion Avoidance and Control" in SIGCOMM '88.  The variable names
 * are the same as those in Appendix A.2 of that paper.
 *
 * m = new measurement
 * sa = smoothed RTT average (8 * average estimates).
 * sv = smoothed mean deviation (mdev) of RTT (4 * deviation estimates).
 */
static void
tcp_set_rto(tcp_t *tcp, clock_t rtt)
{
	long m = TICK_TO_MSEC(rtt);
	clock_t sa = tcp->tcp_rtt_sa;
	clock_t sv = tcp->tcp_rtt_sd;
	clock_t rto;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	TCPS_BUMP_MIB(tcps, tcpRttUpdate);
	tcp->tcp_rtt_update++;

	/* tcp_rtt_sa is not 0 means this is a new sample. */
	if (sa != 0) {
		/*
		 * Update average estimator:
		 *	new rtt = 7/8 old rtt + 1/8 Error
		 */

		/* m is now Error in estimate. */
		m -= sa >> 3;
		if ((sa += m) <= 0) {
			/*
			 * Don't allow the smoothed average to be negative.
			 * We use 0 to denote reinitialization of the
			 * variables.
			 */
			sa = 1;
		}

		/*
		 * Update deviation estimator:
		 *	new mdev = 3/4 old mdev + 1/4 (abs(Error) - old mdev)
		 */
		if (m < 0)
			m = -m;
		m -= sv >> 2;
		sv += m;
	} else {
		/*
		 * This follows BSD's implementation.  So the reinitialized
		 * RTO is 3 * m.  We cannot go less than 2 because if the
		 * link is bandwidth dominated, doubling the window size
		 * during slow start means doubling the RTT.  We want to be
		 * more conservative when we reinitialize our estimates.  3
		 * is just a convenient number.
		 */
		sa = m << 3;
		sv = m << 1;
	}
	if (sv < TCP_SD_MIN) {
		/*
		 * We do not know that if sa captures the delay ACK
		 * effect as in a long train of segments, a receiver
		 * does not delay its ACKs.  So set the minimum of sv
		 * to be TCP_SD_MIN, which is default to 400 ms, twice
		 * of BSD DATO.  That means the minimum of mean
		 * deviation is 100 ms.
		 *
		 */
		sv = TCP_SD_MIN;
	}
	tcp->tcp_rtt_sa = sa;
	tcp->tcp_rtt_sd = sv;
	/*
	 * RTO = average estimates (sa / 8) + 4 * deviation estimates (sv)
	 *
	 * Add tcp_rexmit_interval extra in case of extreme environment
	 * where the algorithm fails to work.  The default value of
	 * tcp_rexmit_interval_extra should be 0.
	 *
	 * As we use a finer grained clock than BSD and update
	 * RTO for every ACKs, add in another .25 of RTT to the
	 * deviation of RTO to accomodate burstiness of 1/4 of
	 * window size.
	 */
	rto = (sa >> 3) + sv + tcps->tcps_rexmit_interval_extra + (sa >> 5);

	TCP_SET_RTO(tcp, rto);

	/* Now, we can reset tcp_timer_backoff to use the new RTO... */
	tcp->tcp_timer_backoff = 0;
}

/*
 * On a labeled system we have some protocols above TCP, such as RPC, which
 * appear to assume that every mblk in a chain has a db_credp.
 */
static void
tcp_setcred_data(mblk_t *mp, ip_recv_attr_t *ira)
{
	ASSERT(is_system_labeled());
	ASSERT(ira->ira_cred != NULL);

	while (mp != NULL) {
		mblk_setcred(mp, ira->ira_cred, NOPID);
		mp = mp->b_cont;
	}
}

uint_t
tcp_rwnd_reopen(tcp_t *tcp)
{
	uint_t ret = 0;
	uint_t thwin;
	conn_t *connp = tcp->tcp_connp;

	/* Learn the latest rwnd information that we sent to the other side. */
	thwin = ((uint_t)ntohs(tcp->tcp_tcpha->tha_win))
	    << tcp->tcp_rcv_ws;
	/* This is peer's calculated send window (our receive window). */
	thwin -= tcp->tcp_rnxt - tcp->tcp_rack;
	/*
	 * Increase the receive window to max.  But we need to do receiver
	 * SWS avoidance.  This means that we need to check the increase of
	 * of receive window is at least 1 MSS.
	 */
	if (connp->conn_rcvbuf - thwin >= tcp->tcp_mss) {
		/*
		 * If the window that the other side knows is less than max
		 * deferred acks segments, send an update immediately.
		 */
		if (thwin < tcp->tcp_rack_cur_max * tcp->tcp_mss) {
			TCPS_BUMP_MIB(tcp->tcp_tcps, tcpOutWinUpdate);
			ret = TH_ACK_NEEDED;
		}
		tcp->tcp_rwnd = connp->conn_rcvbuf;
	}
	return (ret);
}

/*
 * Handle a packet that has been reclassified by TCP.
 * This function drops the ref on connp that the caller had.
 */
void
tcp_reinput(conn_t *connp, mblk_t *mp, ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	if (connp->conn_incoming_ifindex != 0 &&
	    connp->conn_incoming_ifindex != ira->ira_ruifindex) {
		freemsg(mp);
		CONN_DEC_REF(connp);
		return;
	}

	if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) ||
	    (ira->ira_flags & IRAF_IPSEC_SECURE)) {
		ip6_t *ip6h;
		ipha_t *ipha;

		if (ira->ira_flags & IRAF_IS_IPV4) {
			ipha = (ipha_t *)mp->b_rptr;
			ip6h = NULL;
		} else {
			ipha = NULL;
			ip6h = (ip6_t *)mp->b_rptr;
		}
		mp = ipsec_check_inbound_policy(mp, connp, ipha, ip6h, ira);
		if (mp == NULL) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
			/* Note that mp is NULL */
			ip_drop_input("ipIfStatsInDiscards", mp, NULL);
			CONN_DEC_REF(connp);
			return;
		}
	}

	if (IPCL_IS_TCP(connp)) {
		/*
		 * do not drain, certain use cases can blow
		 * the stack
		 */
		SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
		    connp->conn_recv, connp, ira,
		    SQ_NODRAIN, SQTAG_IP_TCP_INPUT);
	} else {
		/* Not TCP; must be SOCK_RAW, IPPROTO_TCP */
		(connp->conn_recv)(connp, mp, NULL,
		    ira);
		CONN_DEC_REF(connp);
	}

}

/* ARGSUSED */
static void
tcp_rsrv_input(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	queue_t	*q = connp->conn_rq;

	ASSERT(!IPCL_IS_NONSTR(connp));
	mutex_enter(&tcp->tcp_rsrv_mp_lock);
	tcp->tcp_rsrv_mp = mp;
	mutex_exit(&tcp->tcp_rsrv_mp_lock);

	if (TCP_IS_DETACHED(tcp) || q == NULL) {
		return;
	}

	if (tcp->tcp_fused) {
		tcp_fuse_backenable(tcp);
		return;
	}

	if (canputnext(q)) {
		/* Not flow-controlled, open rwnd */
		tcp->tcp_rwnd = connp->conn_rcvbuf;

		/*
		 * Send back a window update immediately if TCP is above
		 * ESTABLISHED state and the increase of the rcv window
		 * that the other side knows is at least 1 MSS after flow
		 * control is lifted.
		 */
		if (tcp->tcp_state >= TCPS_ESTABLISHED &&
		    tcp_rwnd_reopen(tcp) == TH_ACK_NEEDED) {
			tcp_xmit_ctl(NULL, tcp,
			    (tcp->tcp_swnd == 0) ? tcp->tcp_suna :
			    tcp->tcp_snxt, tcp->tcp_rnxt, TH_ACK);
		}
	}
}

/*
 * The read side service routine is called mostly when we get back-enabled as a
 * result of flow control relief.  Since we don't actually queue anything in
 * TCP, we have no data to send out of here.  What we do is clear the receive
 * window, and send out a window update.
 */
void
tcp_rsrv(queue_t *q)
{
	conn_t		*connp = Q_TO_CONN(q);
	tcp_t		*tcp = connp->conn_tcp;
	mblk_t		*mp;

	/* No code does a putq on the read side */
	ASSERT(q->q_first == NULL);

	/*
	 * If tcp->tcp_rsrv_mp == NULL, it means that tcp_rsrv() has already
	 * been run.  So just return.
	 */
	mutex_enter(&tcp->tcp_rsrv_mp_lock);
	if ((mp = tcp->tcp_rsrv_mp) == NULL) {
		mutex_exit(&tcp->tcp_rsrv_mp_lock);
		return;
	}
	tcp->tcp_rsrv_mp = NULL;
	mutex_exit(&tcp->tcp_rsrv_mp_lock);

	CONN_INC_REF(connp);
	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_rsrv_input, connp,
	    NULL, SQ_PROCESS, SQTAG_TCP_RSRV);
}

/* At minimum we need 8 bytes in the TCP header for the lookup */
#define	ICMP_MIN_TCP_HDR	8

/*
 * tcp_icmp_input is called as conn_recvicmp to process ICMP error messages
 * passed up by IP. The message is always received on the correct tcp_t.
 * Assumes that IP has pulled up everything up to and including the ICMP header.
 */
/* ARGSUSED2 */
void
tcp_icmp_input(void *arg1, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t		*connp = (conn_t *)arg1;
	icmph_t		*icmph;
	ipha_t		*ipha;
	int		iph_hdr_length;
	tcpha_t		*tcpha;
	uint32_t	seg_seq;
	tcp_t		*tcp = connp->conn_tcp;

	/* Assume IP provides aligned packets */
	ASSERT(OK_32PTR(mp->b_rptr));
	ASSERT((MBLKL(mp) >= sizeof (ipha_t)));

	/*
	 * It's possible we have a closed, but not yet destroyed, TCP
	 * connection. Several fields (e.g. conn_ixa->ixa_ire) are invalid
	 * in the closed state, so don't take any chances and drop the packet.
	 */
	if (tcp->tcp_state == TCPS_CLOSED) {
		freemsg(mp);
		return;
	}

	/*
	 * Verify IP version. Anything other than IPv4 or IPv6 packet is sent
	 * upstream. ICMPv6 is handled in tcp_icmp_error_ipv6.
	 */
	if (!(ira->ira_flags & IRAF_IS_IPV4)) {
		tcp_icmp_error_ipv6(tcp, mp, ira);
		return;
	}

	/* Skip past the outer IP and ICMP headers */
	iph_hdr_length = ira->ira_ip_hdr_length;
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	/*
	 * If we don't have the correct outer IP header length
	 * or if we don't have a complete inner IP header
	 * drop it.
	 */
	if (iph_hdr_length < sizeof (ipha_t) ||
	    (ipha_t *)&icmph[1] + 1 > (ipha_t *)mp->b_wptr) {
noticmpv4:
		freemsg(mp);
		return;
	}
	ipha = (ipha_t *)&icmph[1];

	/* Skip past the inner IP and find the ULP header */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	tcpha = (tcpha_t *)((char *)ipha + iph_hdr_length);
	/*
	 * If we don't have the correct inner IP header length or if the ULP
	 * is not IPPROTO_TCP or if we don't have at least ICMP_MIN_TCP_HDR
	 * bytes of TCP header, drop it.
	 */
	if (iph_hdr_length < sizeof (ipha_t) ||
	    ipha->ipha_protocol != IPPROTO_TCP ||
	    (uchar_t *)tcpha + ICMP_MIN_TCP_HDR > mp->b_wptr) {
		goto noticmpv4;
	}

	seg_seq = ntohl(tcpha->tha_seq);
	switch (icmph->icmph_type) {
	case ICMP_DEST_UNREACHABLE:
		switch (icmph->icmph_code) {
		case ICMP_FRAGMENTATION_NEEDED:
			/*
			 * Update Path MTU, then try to send something out.
			 */
			tcp_update_pmtu(tcp, B_TRUE);
			tcp_rexmit_after_error(tcp);
			break;
		case ICMP_PORT_UNREACHABLE:
		case ICMP_PROTOCOL_UNREACHABLE:
			switch (tcp->tcp_state) {
			case TCPS_SYN_SENT:
			case TCPS_SYN_RCVD:
				/*
				 * ICMP can snipe away incipient
				 * TCP connections as long as
				 * seq number is same as initial
				 * send seq number.
				 */
				if (seg_seq == tcp->tcp_iss) {
					(void) tcp_clean_death(tcp,
					    ECONNREFUSED);
				}
				break;
			}
			break;
		case ICMP_HOST_UNREACHABLE:
		case ICMP_NET_UNREACHABLE:
			/* Record the error in case we finally time out. */
			if (icmph->icmph_code == ICMP_HOST_UNREACHABLE)
				tcp->tcp_client_errno = EHOSTUNREACH;
			else
				tcp->tcp_client_errno = ENETUNREACH;
			if (tcp->tcp_state == TCPS_SYN_RCVD) {
				if (tcp->tcp_listener != NULL &&
				    tcp->tcp_listener->tcp_syn_defense) {
					/*
					 * Ditch the half-open connection if we
					 * suspect a SYN attack is under way.
					 */
					(void) tcp_clean_death(tcp,
					    tcp->tcp_client_errno);
				}
			}
			break;
		default:
			break;
		}
		break;
	case ICMP_SOURCE_QUENCH: {
		/*
		 * use a global boolean to control
		 * whether TCP should respond to ICMP_SOURCE_QUENCH.
		 * The default is false.
		 */
		if (tcp_icmp_source_quench) {
			/*
			 * Reduce the sending rate as if we got a
			 * retransmit timeout
			 */
			uint32_t npkt;

			npkt = ((tcp->tcp_snxt - tcp->tcp_suna) >> 1) /
			    tcp->tcp_mss;
			tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) * tcp->tcp_mss;
			tcp->tcp_cwnd = tcp->tcp_mss;
			tcp->tcp_cwnd_cnt = 0;
		}
		break;
	}
	}
	freemsg(mp);
}

/*
 * tcp_icmp_error_ipv6 is called from tcp_icmp_input to process ICMPv6
 * error messages passed up by IP.
 * Assumes that IP has pulled up all the extension headers as well
 * as the ICMPv6 header.
 */
static void
tcp_icmp_error_ipv6(tcp_t *tcp, mblk_t *mp, ip_recv_attr_t *ira)
{
	icmp6_t		*icmp6;
	ip6_t		*ip6h;
	uint16_t	iph_hdr_length = ira->ira_ip_hdr_length;
	tcpha_t		*tcpha;
	uint8_t		*nexthdrp;
	uint32_t	seg_seq;

	/*
	 * Verify that we have a complete IP header.
	 */
	ASSERT((MBLKL(mp) >= sizeof (ip6_t)));

	icmp6 = (icmp6_t *)&mp->b_rptr[iph_hdr_length];
	ip6h = (ip6_t *)&icmp6[1];
	/*
	 * Verify if we have a complete ICMP and inner IP header.
	 */
	if ((uchar_t *)&ip6h[1] > mp->b_wptr) {
noticmpv6:
		freemsg(mp);
		return;
	}

	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &iph_hdr_length, &nexthdrp))
		goto noticmpv6;
	tcpha = (tcpha_t *)((char *)ip6h + iph_hdr_length);
	/*
	 * Validate inner header. If the ULP is not IPPROTO_TCP or if we don't
	 * have at least ICMP_MIN_TCP_HDR bytes of  TCP header drop the
	 * packet.
	 */
	if ((*nexthdrp != IPPROTO_TCP) ||
	    ((uchar_t *)tcpha + ICMP_MIN_TCP_HDR) > mp->b_wptr) {
		goto noticmpv6;
	}

	seg_seq = ntohl(tcpha->tha_seq);
	switch (icmp6->icmp6_type) {
	case ICMP6_PACKET_TOO_BIG:
		/*
		 * Update Path MTU, then try to send something out.
		 */
		tcp_update_pmtu(tcp, B_TRUE);
		tcp_rexmit_after_error(tcp);
		break;
	case ICMP6_DST_UNREACH:
		switch (icmp6->icmp6_code) {
		case ICMP6_DST_UNREACH_NOPORT:
			if (((tcp->tcp_state == TCPS_SYN_SENT) ||
			    (tcp->tcp_state == TCPS_SYN_RCVD)) &&
			    (seg_seq == tcp->tcp_iss)) {
				(void) tcp_clean_death(tcp, ECONNREFUSED);
			}
			break;
		case ICMP6_DST_UNREACH_ADMIN:
		case ICMP6_DST_UNREACH_NOROUTE:
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
		case ICMP6_DST_UNREACH_ADDR:
			/* Record the error in case we finally time out. */
			tcp->tcp_client_errno = EHOSTUNREACH;
			if (((tcp->tcp_state == TCPS_SYN_SENT) ||
			    (tcp->tcp_state == TCPS_SYN_RCVD)) &&
			    (seg_seq == tcp->tcp_iss)) {
				if (tcp->tcp_listener != NULL &&
				    tcp->tcp_listener->tcp_syn_defense) {
					/*
					 * Ditch the half-open connection if we
					 * suspect a SYN attack is under way.
					 */
					(void) tcp_clean_death(tcp,
					    tcp->tcp_client_errno);
				}
			}


			break;
		default:
			break;
		}
		break;
	case ICMP6_PARAM_PROB:
		/* If this corresponds to an ICMP_PROTOCOL_UNREACHABLE */
		if (icmp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER &&
		    (uchar_t *)ip6h + icmp6->icmp6_pptr ==
		    (uchar_t *)nexthdrp) {
			if (tcp->tcp_state == TCPS_SYN_SENT ||
			    tcp->tcp_state == TCPS_SYN_RCVD) {
				(void) tcp_clean_death(tcp, ECONNREFUSED);
			}
			break;
		}
		break;

	case ICMP6_TIME_EXCEEDED:
	default:
		break;
	}
	freemsg(mp);
}

/*
 * CALLED OUTSIDE OF SQUEUE! It can not follow any pointers that tcp might
 * change. But it can refer to fields like tcp_suna and tcp_snxt.
 *
 * Function tcp_verifyicmp is called as conn_verifyicmp to verify the ICMP
 * error messages received by IP. The message is always received on the correct
 * tcp_t.
 */
/* ARGSUSED */
boolean_t
tcp_verifyicmp(conn_t *connp, void *arg2, icmph_t *icmph, icmp6_t *icmp6,
    ip_recv_attr_t *ira)
{
	tcpha_t		*tcpha = (tcpha_t *)arg2;
	uint32_t	seq = ntohl(tcpha->tha_seq);
	tcp_t		*tcp = connp->conn_tcp;

	/*
	 * TCP sequence number contained in payload of the ICMP error message
	 * should be within the range SND.UNA <= SEG.SEQ < SND.NXT. Otherwise,
	 * the message is either a stale ICMP error, or an attack from the
	 * network. Fail the verification.
	 */
	if (SEQ_LT(seq, tcp->tcp_suna) || SEQ_GEQ(seq, tcp->tcp_snxt))
		return (B_FALSE);

	/* For "too big" we also check the ignore flag */
	if (ira->ira_flags & IRAF_IS_IPV4) {
		ASSERT(icmph != NULL);
		if (icmph->icmph_type == ICMP_DEST_UNREACHABLE &&
		    icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED &&
		    tcp->tcp_tcps->tcps_ignore_path_mtu)
			return (B_FALSE);
	} else {
		ASSERT(icmp6 != NULL);
		if (icmp6->icmp6_type == ICMP6_PACKET_TOO_BIG &&
		    tcp->tcp_tcps->tcps_ignore_path_mtu)
			return (B_FALSE);
	}
	return (B_TRUE);
}

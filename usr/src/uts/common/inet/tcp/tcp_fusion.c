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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <sys/cmn_err.h>
#include <sys/tihdr.h>

#include <inet/common.h>
#include <inet/optcom.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <inet/ip_impl.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/ipsec_impl.h>
#include <inet/ipclassifier.h>
#include <inet/ipp_common.h>
#include <inet/ip_if.h>

/*
 * This file implements TCP fusion - a protocol-less data path for TCP
 * loopback connections.  The fusion of two local TCP endpoints occurs
 * at connection establishment time.  Various conditions (see details
 * in tcp_fuse()) need to be met for fusion to be successful.  If it
 * fails, we fall back to the regular TCP data path; if it succeeds,
 * both endpoints proceed to use tcp_fuse_output() as the transmit path.
 * tcp_fuse_output() enqueues application data directly onto the peer's
 * receive queue; no protocol processing is involved.
 *
 * Sychronization is handled by squeue and the mutex tcp_non_sq_lock.
 * One of the requirements for fusion to succeed is that both endpoints
 * need to be using the same squeue.  This ensures that neither side
 * can disappear while the other side is still sending data. Flow
 * control information is manipulated outside the squeue, so the
 * tcp_non_sq_lock must be held when touching tcp_flow_stopped.
 */

/*
 * Setting this to false means we disable fusion altogether and
 * loopback connections would go through the protocol paths.
 */
boolean_t do_tcp_fusion = B_TRUE;

/*
 * This routine gets called by the eager tcp upon changing state from
 * SYN_RCVD to ESTABLISHED.  It fuses a direct path between itself
 * and the active connect tcp such that the regular tcp processings
 * may be bypassed under allowable circumstances.  Because the fusion
 * requires both endpoints to be in the same squeue, it does not work
 * for simultaneous active connects because there is no easy way to
 * switch from one squeue to another once the connection is created.
 * This is different from the eager tcp case where we assign it the
 * same squeue as the one given to the active connect tcp during open.
 */
void
tcp_fuse(tcp_t *tcp, uchar_t *iphdr, tcpha_t *tcpha)
{
	conn_t		*peer_connp, *connp = tcp->tcp_connp;
	tcp_t		*peer_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	netstack_t	*ns;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(!tcp->tcp_fused);
	ASSERT(tcp->tcp_loopback);
	ASSERT(tcp->tcp_loopback_peer == NULL);
	/*
	 * We need to inherit conn_rcvbuf of the listener tcp,
	 * but we can't really use tcp_listener since we get here after
	 * sending up T_CONN_IND and tcp_tli_accept() may be called
	 * independently, at which point tcp_listener is cleared;
	 * this is why we use tcp_saved_listener. The listener itself
	 * is guaranteed to be around until tcp_accept_finish() is called
	 * on this eager -- this won't happen until we're done since we're
	 * inside the eager's perimeter now.
	 */
	ASSERT(tcp->tcp_saved_listener != NULL);
	/*
	 * Lookup peer endpoint; search for the remote endpoint having
	 * the reversed address-port quadruplet in ESTABLISHED state,
	 * which is guaranteed to be unique in the system.  Zone check
	 * is applied accordingly for loopback address, but not for
	 * local address since we want fusion to happen across Zones.
	 */
	if (connp->conn_ipversion == IPV4_VERSION) {
		peer_connp = ipcl_conn_tcp_lookup_reversed_ipv4(connp,
		    (ipha_t *)iphdr, tcpha, ipst);
	} else {
		peer_connp = ipcl_conn_tcp_lookup_reversed_ipv6(connp,
		    (ip6_t *)iphdr, tcpha, ipst);
	}

	/*
	 * We can only proceed if peer exists, resides in the same squeue
	 * as our conn and is not raw-socket. We also restrict fusion to
	 * endpoints of the same type (STREAMS or non-STREAMS). The squeue
	 * assignment of this eager tcp was done earlier at the time of SYN
	 * processing in ip_fanout_tcp{_v6}.  Note that similar squeues by
	 * itself doesn't guarantee a safe condition to fuse, hence we perform
	 * additional tests below.
	 */
	ASSERT(peer_connp == NULL || peer_connp != connp);
	if (peer_connp == NULL || peer_connp->conn_sqp != connp->conn_sqp ||
	    !IPCL_IS_TCP(peer_connp) ||
	    IPCL_IS_NONSTR(connp) != IPCL_IS_NONSTR(peer_connp)) {
		if (peer_connp != NULL) {
			TCP_STAT(tcps, tcp_fusion_unqualified);
			CONN_DEC_REF(peer_connp);
		}
		return;
	}
	peer_tcp = peer_connp->conn_tcp;	/* active connect tcp */

	ASSERT(peer_tcp != NULL && peer_tcp != tcp && !peer_tcp->tcp_fused);
	ASSERT(peer_tcp->tcp_loopback_peer == NULL);
	ASSERT(peer_connp->conn_sqp == connp->conn_sqp);

	/*
	 * Due to IRE changes the peer and us might not agree on tcp_loopback.
	 * We bail in that case.
	 */
	if (!peer_tcp->tcp_loopback) {
		TCP_STAT(tcps, tcp_fusion_unqualified);
		CONN_DEC_REF(peer_connp);
		return;
	}
	/*
	 * Fuse the endpoints; we perform further checks against both
	 * tcp endpoints to ensure that a fusion is allowed to happen.
	 */
	ns = tcps->tcps_netstack;
	ipst = ns->netstack_ip;

	if (!tcp->tcp_unfusable && !peer_tcp->tcp_unfusable &&
	    tcp->tcp_xmit_head == NULL && peer_tcp->tcp_xmit_head == NULL) {
		mblk_t *mp;
		queue_t *peer_rq = peer_connp->conn_rq;

		ASSERT(!TCP_IS_DETACHED(peer_tcp));
		ASSERT(tcp->tcp_fused_sigurg_mp == NULL);
		ASSERT(peer_tcp->tcp_fused_sigurg_mp == NULL);

		/*
		 * We need to drain data on both endpoints during unfuse.
		 * If we need to send up SIGURG at the time of draining,
		 * we want to be sure that an mblk is readily available.
		 * This is why we pre-allocate the M_PCSIG mblks for both
		 * endpoints which will only be used during/after unfuse.
		 * The mblk might already exist if we are doing a re-fuse.
		 */
		if (!IPCL_IS_NONSTR(tcp->tcp_connp)) {
			ASSERT(!IPCL_IS_NONSTR(peer_tcp->tcp_connp));

			if (tcp->tcp_fused_sigurg_mp == NULL) {
				if ((mp = allocb(1, BPRI_HI)) == NULL)
					goto failed;
				tcp->tcp_fused_sigurg_mp = mp;
			}

			if (peer_tcp->tcp_fused_sigurg_mp == NULL) {
				if ((mp = allocb(1, BPRI_HI)) == NULL)
					goto failed;
				peer_tcp->tcp_fused_sigurg_mp = mp;
			}

			if ((mp = allocb(sizeof (struct stroptions),
			    BPRI_HI)) == NULL)
				goto failed;
		}

		/* Fuse both endpoints */
		peer_tcp->tcp_loopback_peer = tcp;
		tcp->tcp_loopback_peer = peer_tcp;
		peer_tcp->tcp_fused = tcp->tcp_fused = B_TRUE;

		/*
		 * We never use regular tcp paths in fusion and should
		 * therefore clear tcp_unsent on both endpoints.  Having
		 * them set to non-zero values means asking for trouble
		 * especially after unfuse, where we may end up sending
		 * through regular tcp paths which expect xmit_list and
		 * friends to be correctly setup.
		 */
		peer_tcp->tcp_unsent = tcp->tcp_unsent = 0;

		tcp_timers_stop(tcp);
		tcp_timers_stop(peer_tcp);

		/*
		 * Set receive buffer and max packet size for the
		 * active open tcp.
		 * eager's values will be set in tcp_accept_finish.
		 */
		(void) tcp_rwnd_set(peer_tcp, peer_tcp->tcp_connp->conn_rcvbuf);

		/*
		 * Set the write offset value to zero since we won't
		 * be needing any room for TCP/IP headers.
		 */
		if (!IPCL_IS_NONSTR(peer_tcp->tcp_connp)) {
			struct stroptions *stropt;

			DB_TYPE(mp) = M_SETOPTS;
			mp->b_wptr += sizeof (*stropt);

			stropt = (struct stroptions *)mp->b_rptr;
			stropt->so_flags = SO_WROFF | SO_MAXBLK;
			stropt->so_wroff = 0;
			stropt->so_maxblk = INFPSZ;

			/* Send the options up */
			putnext(peer_rq, mp);
		} else {
			struct sock_proto_props sopp;

			/* The peer is a non-STREAMS end point */
			ASSERT(IPCL_IS_TCP(peer_connp));

			sopp.sopp_flags = SOCKOPT_WROFF | SOCKOPT_MAXBLK;
			sopp.sopp_wroff = 0;
			sopp.sopp_maxblk = INFPSZ;
			(*peer_connp->conn_upcalls->su_set_proto_props)
			    (peer_connp->conn_upper_handle, &sopp);
		}
	} else {
		TCP_STAT(tcps, tcp_fusion_unqualified);
	}
	CONN_DEC_REF(peer_connp);
	return;

failed:
	if (tcp->tcp_fused_sigurg_mp != NULL) {
		freeb(tcp->tcp_fused_sigurg_mp);
		tcp->tcp_fused_sigurg_mp = NULL;
	}
	if (peer_tcp->tcp_fused_sigurg_mp != NULL) {
		freeb(peer_tcp->tcp_fused_sigurg_mp);
		peer_tcp->tcp_fused_sigurg_mp = NULL;
	}
	CONN_DEC_REF(peer_connp);
}

/*
 * Unfuse a previously-fused pair of tcp loopback endpoints.
 */
void
tcp_unfuse(tcp_t *tcp)
{
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;
	tcp_stack_t *tcps = tcp->tcp_tcps;

	ASSERT(tcp->tcp_fused && peer_tcp != NULL);
	ASSERT(peer_tcp->tcp_fused && peer_tcp->tcp_loopback_peer == tcp);
	ASSERT(tcp->tcp_connp->conn_sqp == peer_tcp->tcp_connp->conn_sqp);
	ASSERT(tcp->tcp_unsent == 0 && peer_tcp->tcp_unsent == 0);

	/*
	 * Cancel any pending push timers.
	 */
	if (tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_push_tid);
		tcp->tcp_push_tid = 0;
	}
	if (peer_tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(peer_tcp, peer_tcp->tcp_push_tid);
		peer_tcp->tcp_push_tid = 0;
	}

	/*
	 * Drain any pending data; Note that in case of a detached tcp, the
	 * draining will happen later after the tcp is unfused.  For non-
	 * urgent data, this can be handled by the regular tcp_rcv_drain().
	 * If we have urgent data sitting in the receive list, we will
	 * need to send up a SIGURG signal first before draining the data.
	 * All of these will be handled by the code in tcp_fuse_rcv_drain()
	 * when called from tcp_rcv_drain().
	 */
	if (!TCP_IS_DETACHED(tcp)) {
		(void) tcp_fuse_rcv_drain(tcp->tcp_connp->conn_rq, tcp,
		    &tcp->tcp_fused_sigurg_mp);
	}
	if (!TCP_IS_DETACHED(peer_tcp)) {
		(void) tcp_fuse_rcv_drain(peer_tcp->tcp_connp->conn_rq,
		    peer_tcp,  &peer_tcp->tcp_fused_sigurg_mp);
	}

	/* Lift up any flow-control conditions */
	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped) {
		tcp_clrqfull(tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
	}
	mutex_exit(&tcp->tcp_non_sq_lock);

	mutex_enter(&peer_tcp->tcp_non_sq_lock);
	if (peer_tcp->tcp_flow_stopped) {
		tcp_clrqfull(peer_tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
	}
	mutex_exit(&peer_tcp->tcp_non_sq_lock);

	/*
	 * Update tha_seq and tha_ack in the header template
	 */
	tcp->tcp_tcpha->tha_seq = htonl(tcp->tcp_snxt);
	tcp->tcp_tcpha->tha_ack = htonl(tcp->tcp_rnxt);
	peer_tcp->tcp_tcpha->tha_seq = htonl(peer_tcp->tcp_snxt);
	peer_tcp->tcp_tcpha->tha_ack = htonl(peer_tcp->tcp_rnxt);

	/* Unfuse the endpoints */
	peer_tcp->tcp_fused = tcp->tcp_fused = B_FALSE;
	peer_tcp->tcp_loopback_peer = tcp->tcp_loopback_peer = NULL;
}

/*
 * Fusion output routine used to handle urgent data sent by STREAMS based
 * endpoints. This routine is called by tcp_fuse_output() for handling
 * non-M_DATA mblks.
 */
void
tcp_fuse_output_urg(tcp_t *tcp, mblk_t *mp)
{
	mblk_t *mp1;
	struct T_exdata_ind *tei;
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;
	mblk_t *head, *prev_head = NULL;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL && peer_tcp->tcp_loopback_peer == tcp);
	ASSERT(!IPCL_IS_NONSTR(tcp->tcp_connp));
	ASSERT(DB_TYPE(mp) == M_PROTO || DB_TYPE(mp) == M_PCPROTO);
	ASSERT(mp->b_cont != NULL && DB_TYPE(mp->b_cont) == M_DATA);
	ASSERT(MBLKL(mp) >= sizeof (*tei) && MBLKL(mp->b_cont) > 0);

	/*
	 * Urgent data arrives in the form of T_EXDATA_REQ from above.
	 * Each occurence denotes a new urgent pointer.  For each new
	 * urgent pointer we signal (SIGURG) the receiving app to indicate
	 * that it needs to go into urgent mode.  This is similar to the
	 * urgent data handling in the regular tcp.  We don't need to keep
	 * track of where the urgent pointer is, because each T_EXDATA_REQ
	 * "advances" the urgent pointer for us.
	 *
	 * The actual urgent data carried by T_EXDATA_REQ is then prepended
	 * by a T_EXDATA_IND before being enqueued behind any existing data
	 * destined for the receiving app.  There is only a single urgent
	 * pointer (out-of-band mark) for a given tcp.  If the new urgent
	 * data arrives before the receiving app reads some existing urgent
	 * data, the previous marker is lost.  This behavior is emulated
	 * accordingly below, by removing any existing T_EXDATA_IND messages
	 * and essentially converting old urgent data into non-urgent.
	 */
	ASSERT(tcp->tcp_valid_bits & TCP_URG_VALID);
	/* Let sender get out of urgent mode */
	tcp->tcp_valid_bits &= ~TCP_URG_VALID;

	/*
	 * This flag indicates that a signal needs to be sent up.
	 * This flag will only get cleared once SIGURG is delivered and
	 * is not affected by the tcp_fused flag -- delivery will still
	 * happen even after an endpoint is unfused, to handle the case
	 * where the sending endpoint immediately closes/unfuses after
	 * sending urgent data and the accept is not yet finished.
	 */
	peer_tcp->tcp_fused_sigurg = B_TRUE;

	/* Reuse T_EXDATA_REQ mblk for T_EXDATA_IND */
	DB_TYPE(mp) = M_PROTO;
	tei = (struct T_exdata_ind *)mp->b_rptr;
	tei->PRIM_type = T_EXDATA_IND;
	tei->MORE_flag = 0;
	mp->b_wptr = (uchar_t *)&tei[1];

	TCP_STAT(tcps, tcp_fusion_urg);
	TCPS_BUMP_MIB(tcps, tcpOutUrg);

	head = peer_tcp->tcp_rcv_list;
	while (head != NULL) {
		/*
		 * Remove existing T_EXDATA_IND, keep the data which follows
		 * it and relink our list.  Note that we don't modify the
		 * tcp_rcv_last_tail since it never points to T_EXDATA_IND.
		 */
		if (DB_TYPE(head) != M_DATA) {
			mp1 = head;

			ASSERT(DB_TYPE(mp1->b_cont) == M_DATA);
			head = mp1->b_cont;
			mp1->b_cont = NULL;
			head->b_next = mp1->b_next;
			mp1->b_next = NULL;
			if (prev_head != NULL)
				prev_head->b_next = head;
			if (peer_tcp->tcp_rcv_list == mp1)
				peer_tcp->tcp_rcv_list = head;
			if (peer_tcp->tcp_rcv_last_head == mp1)
				peer_tcp->tcp_rcv_last_head = head;
			freeb(mp1);
		}
		prev_head = head;
		head = head->b_next;
	}
}

/*
 * Fusion output routine, called by tcp_output() and tcp_wput_proto().
 * If we are modifying any member that can be changed outside the squeue,
 * like tcp_flow_stopped, we need to take tcp_non_sq_lock.
 */
boolean_t
tcp_fuse_output(tcp_t *tcp, mblk_t *mp, uint32_t send_size)
{
	conn_t		*connp = tcp->tcp_connp;
	tcp_t		*peer_tcp = tcp->tcp_loopback_peer;
	conn_t		*peer_connp = peer_tcp->tcp_connp;
	boolean_t	flow_stopped, peer_data_queued = B_FALSE;
	boolean_t	urgent = (DB_TYPE(mp) != M_DATA);
	boolean_t	push = B_TRUE;
	mblk_t		*mp1 = mp;
	uint_t		ip_hdr_len;
	uint32_t	recv_size = send_size;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	netstack_t	*ns = tcps->tcps_netstack;
	ip_stack_t	*ipst = ns->netstack_ip;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	iaflags_t	ixaflags = connp->conn_ixa->ixa_flags;
	boolean_t	do_ipsec, hooks_out, hooks_in, ipobs_enabled;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL && peer_tcp->tcp_loopback_peer == tcp);
	ASSERT(connp->conn_sqp == peer_connp->conn_sqp);
	ASSERT(DB_TYPE(mp) == M_DATA || DB_TYPE(mp) == M_PROTO ||
	    DB_TYPE(mp) == M_PCPROTO);

	if (send_size == 0) {
		freemsg(mp);
		return (B_TRUE);
	}

	/*
	 * Handle urgent data; we either send up SIGURG to the peer now
	 * or do it later when we drain, in case the peer is detached
	 * or if we're short of memory for M_PCSIG mblk.
	 */
	if (urgent) {
		tcp_fuse_output_urg(tcp, mp);

		mp1 = mp->b_cont;
	}

	/*
	 * Check that we are still using an IRE_LOCAL or IRE_LOOPBACK before
	 * further processes.
	 */
	if (!ip_output_verify_local(connp->conn_ixa))
		goto unfuse;

	/*
	 * Build IP and TCP header in case we have something that needs the
	 * headers. Those cases are:
	 * 1. IPsec
	 * 2. IPobs
	 * 3. FW_HOOKS
	 *
	 * If tcp_xmit_mp() fails to dupb() the message, unfuse the connection
	 * and back to regular path.
	 */
	if (ixaflags & IXAF_IS_IPV4) {
		do_ipsec = (ixaflags & IXAF_IPSEC_SECURE) ||
		    CONN_INBOUND_POLICY_PRESENT(peer_connp, ipss);

		hooks_out = HOOKS4_INTERESTED_LOOPBACK_OUT(ipst);
		hooks_in = HOOKS4_INTERESTED_LOOPBACK_IN(ipst);
		ipobs_enabled = (ipst->ips_ip4_observe.he_interested != 0);
	} else {
		do_ipsec = (ixaflags & IXAF_IPSEC_SECURE) ||
		    CONN_INBOUND_POLICY_PRESENT_V6(peer_connp, ipss);

		hooks_out = HOOKS6_INTERESTED_LOOPBACK_OUT(ipst);
		hooks_in = HOOKS6_INTERESTED_LOOPBACK_IN(ipst);
		ipobs_enabled = (ipst->ips_ip6_observe.he_interested != 0);
	}

	/* We do logical 'or' for efficiency */
	if (ipobs_enabled | do_ipsec | hooks_in | hooks_out) {
		if ((mp1 = tcp_xmit_mp(tcp, mp1, tcp->tcp_mss, NULL, NULL,
		    tcp->tcp_snxt, B_TRUE, NULL, B_FALSE)) == NULL)
			/* If tcp_xmit_mp fails, use regular path */
			goto unfuse;

		/*
		 * Leave all IP relevant processes to ip_output_process_local(),
		 * which handles IPsec, IPobs, and FW_HOOKS.
		 */
		mp1 = ip_output_process_local(mp1, connp->conn_ixa, hooks_out,
		    hooks_in, do_ipsec ? peer_connp : NULL);

		/* If the message is dropped for any reason. */
		if (mp1 == NULL)
			goto unfuse;

		/*
		 * Data length might have been changed by FW_HOOKS.
		 * We assume that the first mblk contains the TCP/IP headers.
		 */
		if (hooks_in || hooks_out) {
			tcpha_t *tcpha;

			ip_hdr_len = (ixaflags & IXAF_IS_IPV4) ?
			    IPH_HDR_LENGTH((ipha_t *)mp1->b_rptr) :
			    ip_hdr_length_v6(mp1, (ip6_t *)mp1->b_rptr);

			tcpha = (tcpha_t *)&mp1->b_rptr[ip_hdr_len];
			ASSERT((uchar_t *)tcpha + sizeof (tcpha_t) <=
			    mp1->b_wptr);
			recv_size += htonl(tcpha->tha_seq) - tcp->tcp_snxt;

		}

		/*
		 * The message duplicated by tcp_xmit_mp is freed.
		 * Note: the original message passed in remains unchanged.
		 */
		freemsg(mp1);
	}

	/*
	 * Enqueue data into the peer's receive list; we may or may not
	 * drain the contents depending on the conditions below.
	 *
	 * For non-STREAMS sockets we normally queue data directly in the
	 * socket by calling the su_recv upcall. However, if the peer is
	 * detached we use tcp_rcv_enqueue() instead. Queued data will be
	 * drained when the accept completes (in tcp_accept_finish()).
	 */
	if (IPCL_IS_NONSTR(peer_connp) &&
	    !TCP_IS_DETACHED(peer_tcp)) {
		int error;
		int flags = 0;

		if ((tcp->tcp_valid_bits & TCP_URG_VALID) &&
		    (tcp->tcp_urg == tcp->tcp_snxt)) {
			flags = MSG_OOB;
			(*peer_connp->conn_upcalls->su_signal_oob)
			    (peer_connp->conn_upper_handle, 0);
			tcp->tcp_valid_bits &= ~TCP_URG_VALID;
		}
		if ((*peer_connp->conn_upcalls->su_recv)(
		    peer_connp->conn_upper_handle, mp, recv_size,
		    flags, &error, &push) < 0) {
			ASSERT(error != EOPNOTSUPP);
			peer_data_queued = B_TRUE;
		}
	} else {
		if (IPCL_IS_NONSTR(peer_connp) &&
		    (tcp->tcp_valid_bits & TCP_URG_VALID) &&
		    (tcp->tcp_urg == tcp->tcp_snxt)) {
			/*
			 * Can not deal with urgent pointers
			 * that arrive before the connection has been
			 * accept()ed.
			 */
			tcp->tcp_valid_bits &= ~TCP_URG_VALID;
			freemsg(mp);
			return (B_TRUE);
		}

		tcp_rcv_enqueue(peer_tcp, mp, recv_size,
		    tcp->tcp_connp->conn_cred);

		/* In case it wrapped around and also to keep it constant */
		peer_tcp->tcp_rwnd += recv_size;
	}

	/*
	 * Exercise flow-control when needed; we will get back-enabled
	 * in either tcp_accept_finish(), tcp_unfuse(), or when data is
	 * consumed. If peer endpoint is detached, we emulate streams flow
	 * control by checking the peer's queue size and high water mark;
	 * otherwise we simply use canputnext() to decide if we need to stop
	 * our flow.
	 *
	 * Since we are accessing our tcp_flow_stopped and might modify it,
	 * we need to take tcp->tcp_non_sq_lock.
	 */
	mutex_enter(&tcp->tcp_non_sq_lock);
	flow_stopped = tcp->tcp_flow_stopped;
	if ((TCP_IS_DETACHED(peer_tcp) &&
	    (peer_tcp->tcp_rcv_cnt >= peer_connp->conn_rcvbuf)) ||
	    (!TCP_IS_DETACHED(peer_tcp) &&
	    !IPCL_IS_NONSTR(peer_connp) && !canputnext(peer_connp->conn_rq))) {
		peer_data_queued = B_TRUE;
	}

	if (!flow_stopped && (peer_data_queued ||
	    (TCP_UNSENT_BYTES(tcp) >= connp->conn_sndbuf))) {
		tcp_setqfull(tcp);
		flow_stopped = B_TRUE;
		TCP_STAT(tcps, tcp_fusion_flowctl);
		DTRACE_PROBE3(tcp__fuse__output__flowctl, tcp_t *, tcp,
		    uint_t, send_size, uint_t, peer_tcp->tcp_rcv_cnt);
	} else if (flow_stopped && !peer_data_queued &&
	    (TCP_UNSENT_BYTES(tcp) <= connp->conn_sndlowat)) {
		tcp_clrqfull(tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
		flow_stopped = B_FALSE;
	}
	mutex_exit(&tcp->tcp_non_sq_lock);

	ipst->ips_loopback_packets++;
	tcp->tcp_last_sent_len = send_size;

	/* Need to adjust the following SNMP MIB-related variables */
	tcp->tcp_snxt += send_size;
	tcp->tcp_suna = tcp->tcp_snxt;
	peer_tcp->tcp_rnxt += recv_size;
	peer_tcp->tcp_last_recv_len = recv_size;
	peer_tcp->tcp_rack = peer_tcp->tcp_rnxt;

	TCPS_BUMP_MIB(tcps, tcpOutDataSegs);
	TCPS_UPDATE_MIB(tcps, tcpOutDataBytes, send_size);

	TCPS_BUMP_MIB(tcps, tcpHCInSegs);
	TCPS_BUMP_MIB(tcps, tcpInDataInorderSegs);
	TCPS_UPDATE_MIB(tcps, tcpInDataInorderBytes, send_size);

	BUMP_LOCAL(tcp->tcp_obsegs);
	BUMP_LOCAL(peer_tcp->tcp_ibsegs);

	DTRACE_TCP5(send, void, NULL, ip_xmit_attr_t *, connp->conn_ixa,
	    __dtrace_tcp_void_ip_t *, NULL, tcp_t *, tcp,
	    __dtrace_tcp_tcph_t *, NULL);
	DTRACE_TCP5(receive, void, NULL, ip_xmit_attr_t *,
	    peer_connp->conn_ixa, __dtrace_tcp_void_ip_t *, NULL,
	    tcp_t *, peer_tcp, __dtrace_tcp_tcph_t *, NULL);

	if (!IPCL_IS_NONSTR(peer_tcp->tcp_connp) &&
	    !TCP_IS_DETACHED(peer_tcp)) {
		/*
		 * Drain the peer's receive queue it has urgent data or if
		 * we're not flow-controlled.
		 */
		if (urgent || !flow_stopped) {
			ASSERT(peer_tcp->tcp_rcv_list != NULL);
			/*
			 * For TLI-based streams, a thread in tcp_accept_swap()
			 * can race with us.  That thread will ensure that the
			 * correct peer_connp->conn_rq is globally visible
			 * before peer_tcp->tcp_detached is visible as clear,
			 * but we must also ensure that the load of conn_rq
			 * cannot be reordered to be before the tcp_detached
			 * check.
			 */
			membar_consumer();
			(void) tcp_fuse_rcv_drain(peer_connp->conn_rq, peer_tcp,
			    NULL);
		}
	}
	return (B_TRUE);
unfuse:
	tcp_unfuse(tcp);
	return (B_FALSE);
}

/*
 * This routine gets called to deliver data upstream on a fused or
 * previously fused tcp loopback endpoint; the latter happens only
 * when there is a pending SIGURG signal plus urgent data that can't
 * be sent upstream in the past.
 */
boolean_t
tcp_fuse_rcv_drain(queue_t *q, tcp_t *tcp, mblk_t **sigurg_mpp)
{
	mblk_t *mp;
	conn_t	*connp = tcp->tcp_connp;

#ifdef DEBUG
	uint_t cnt = 0;
#endif
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	tcp_t		*peer_tcp = tcp->tcp_loopback_peer;

	ASSERT(tcp->tcp_loopback);
	ASSERT(tcp->tcp_fused || tcp->tcp_fused_sigurg);
	ASSERT(!tcp->tcp_fused || tcp->tcp_loopback_peer != NULL);
	ASSERT(IPCL_IS_NONSTR(connp) || sigurg_mpp != NULL || tcp->tcp_fused);

	/* No need for the push timer now, in case it was scheduled */
	if (tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_push_tid);
		tcp->tcp_push_tid = 0;
	}
	/*
	 * If there's urgent data sitting in receive list and we didn't
	 * get a chance to send up a SIGURG signal, make sure we send
	 * it first before draining in order to ensure that SIOCATMARK
	 * works properly.
	 */
	if (tcp->tcp_fused_sigurg) {
		ASSERT(!IPCL_IS_NONSTR(tcp->tcp_connp));

		tcp->tcp_fused_sigurg = B_FALSE;
		/*
		 * sigurg_mpp is normally NULL, i.e. when we're still
		 * fused and didn't get here because of tcp_unfuse().
		 * In this case try hard to allocate the M_PCSIG mblk.
		 */
		if (sigurg_mpp == NULL &&
		    (mp = allocb(1, BPRI_HI)) == NULL &&
		    (mp = allocb_tryhard(1)) == NULL) {
			/* Alloc failed; try again next time */
			tcp->tcp_push_tid = TCP_TIMER(tcp,
			    tcp_push_timer, tcps->tcps_push_timer_interval);
			return (B_TRUE);
		} else if (sigurg_mpp != NULL) {
			/*
			 * Use the supplied M_PCSIG mblk; it means we're
			 * either unfused or in the process of unfusing,
			 * and the drain must happen now.
			 */
			mp = *sigurg_mpp;
			*sigurg_mpp = NULL;
		}
		ASSERT(mp != NULL);

		/* Send up the signal */
		DB_TYPE(mp) = M_PCSIG;
		*mp->b_wptr++ = (uchar_t)SIGURG;
		putnext(q, mp);

		/*
		 * Let the regular tcp_rcv_drain() path handle
		 * draining the data if we're no longer fused.
		 */
		if (!tcp->tcp_fused)
			return (B_FALSE);
	}

	/* Drain the data */
	while ((mp = tcp->tcp_rcv_list) != NULL) {
		tcp->tcp_rcv_list = mp->b_next;
		mp->b_next = NULL;
#ifdef DEBUG
		cnt += msgdsize(mp);
#endif
		ASSERT(!IPCL_IS_NONSTR(connp));
		putnext(q, mp);
		TCP_STAT(tcps, tcp_fusion_putnext);
	}

#ifdef DEBUG
	ASSERT(cnt == tcp->tcp_rcv_cnt);
#endif
	tcp->tcp_rcv_last_head = NULL;
	tcp->tcp_rcv_last_tail = NULL;
	tcp->tcp_rcv_cnt = 0;
	tcp->tcp_rwnd = tcp->tcp_connp->conn_rcvbuf;

	mutex_enter(&peer_tcp->tcp_non_sq_lock);
	if (peer_tcp->tcp_flow_stopped && (TCP_UNSENT_BYTES(peer_tcp) <=
	    peer_tcp->tcp_connp->conn_sndlowat)) {
		tcp_clrqfull(peer_tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
	}
	mutex_exit(&peer_tcp->tcp_non_sq_lock);

	return (B_TRUE);
}

/*
 * Calculate the size of receive buffer for a fused tcp endpoint.
 */
size_t
tcp_fuse_set_rcv_hiwat(tcp_t *tcp, size_t rwnd)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	uint32_t	max_win;

	ASSERT(tcp->tcp_fused);

	/* Ensure that value is within the maximum upper bound */
	if (rwnd > tcps->tcps_max_buf)
		rwnd = tcps->tcps_max_buf;
	/*
	 * Round up to system page size in case SO_RCVBUF is modified
	 * after SO_SNDBUF; the latter is also similarly rounded up.
	 */
	rwnd = P2ROUNDUP_TYPED(rwnd, PAGESIZE, size_t);
	max_win = TCP_MAXWIN << tcp->tcp_rcv_ws;
	if (rwnd > max_win) {
		rwnd = max_win - (max_win % tcp->tcp_mss);
		if (rwnd < tcp->tcp_mss)
			rwnd = max_win;
	}

	/*
	 * Record high water mark, this is used for flow-control
	 * purposes in tcp_fuse_output().
	 */
	tcp->tcp_connp->conn_rcvbuf = rwnd;
	tcp->tcp_rwnd = rwnd;
	return (rwnd);
}

/*
 * Calculate the maximum outstanding unread data block for a fused tcp endpoint.
 */
int
tcp_fuse_maxpsz(tcp_t *tcp)
{
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;
	conn_t *connp = tcp->tcp_connp;
	uint_t sndbuf = connp->conn_sndbuf;
	uint_t maxpsz = sndbuf;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL);
	ASSERT(peer_tcp->tcp_connp->conn_rcvbuf != 0);
	/*
	 * In the fused loopback case, we want the stream head to split
	 * up larger writes into smaller chunks for a more accurate flow-
	 * control accounting.  Our maxpsz is half of the sender's send
	 * buffer or the receiver's receive buffer, whichever is smaller.
	 * We round up the buffer to system page size due to the lack of
	 * TCP MSS concept in Fusion.
	 */
	if (maxpsz > peer_tcp->tcp_connp->conn_rcvbuf)
		maxpsz = peer_tcp->tcp_connp->conn_rcvbuf;
	maxpsz = P2ROUNDUP_TYPED(maxpsz, PAGESIZE, uint_t) >> 1;

	return (maxpsz);
}

/*
 * Called to release flow control.
 */
void
tcp_fuse_backenable(tcp_t *tcp)
{
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL && peer_tcp->tcp_fused);
	ASSERT(peer_tcp->tcp_loopback_peer == tcp);
	ASSERT(!TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_connp->conn_sqp ==
	    peer_tcp->tcp_connp->conn_sqp);

	if (tcp->tcp_rcv_list != NULL)
		(void) tcp_fuse_rcv_drain(tcp->tcp_connp->conn_rq, tcp, NULL);

	mutex_enter(&peer_tcp->tcp_non_sq_lock);
	if (peer_tcp->tcp_flow_stopped &&
	    (TCP_UNSENT_BYTES(peer_tcp) <=
	    peer_tcp->tcp_connp->conn_sndlowat)) {
		tcp_clrqfull(peer_tcp);
	}
	mutex_exit(&peer_tcp->tcp_non_sq_lock);

	TCP_STAT(tcp->tcp_tcps, tcp_fusion_backenabled);
}

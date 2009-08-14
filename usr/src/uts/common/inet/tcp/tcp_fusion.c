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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 * Return true if this connection needs some IP functionality
 */
static boolean_t
tcp_loopback_needs_ip(tcp_t *tcp, netstack_t *ns)
{
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	/*
	 * If ire is not cached, do not use fusion
	 */
	if (tcp->tcp_connp->conn_ire_cache == NULL) {
		/*
		 * There is no need to hold conn_lock here because when called
		 * from tcp_fuse() there can be no window where conn_ire_cache
		 * can change. This is not true when called from
		 * tcp_fuse_output() as conn_ire_cache can become null just
		 * after the check. It will be necessary to recheck for a NULL
		 * conn_ire_cache in tcp_fuse_output() to avoid passing a
		 * stale ill pointer to FW_HOOKS.
		 */
		return (B_TRUE);
	}
	if (tcp->tcp_ipversion == IPV4_VERSION) {
		if (tcp->tcp_ip_hdr_len != IP_SIMPLE_HDR_LENGTH)
			return (B_TRUE);
		if (CONN_OUTBOUND_POLICY_PRESENT(tcp->tcp_connp, ipss))
			return (B_TRUE);
		if (CONN_INBOUND_POLICY_PRESENT(tcp->tcp_connp, ipss))
			return (B_TRUE);
	} else {
		if (tcp->tcp_ip_hdr_len != IPV6_HDR_LEN)
			return (B_TRUE);
		if (CONN_OUTBOUND_POLICY_PRESENT_V6(tcp->tcp_connp, ipss))
			return (B_TRUE);
		if (CONN_INBOUND_POLICY_PRESENT_V6(tcp->tcp_connp, ipss))
			return (B_TRUE);
	}
	if (!CONN_IS_LSO_MD_FASTPATH(tcp->tcp_connp))
		return (B_TRUE);
	return (B_FALSE);
}


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
tcp_fuse(tcp_t *tcp, uchar_t *iphdr, tcph_t *tcph)
{
	conn_t *peer_connp, *connp = tcp->tcp_connp;
	tcp_t *peer_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	netstack_t	*ns;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(!tcp->tcp_fused);
	ASSERT(tcp->tcp_loopback);
	ASSERT(tcp->tcp_loopback_peer == NULL);
	/*
	 * We need to inherit tcp_recv_hiwater of the listener tcp,
	 * but we can't really use tcp_listener since we get here after
	 * sending up T_CONN_IND and tcp_wput_accept() may be called
	 * independently, at which point tcp_listener is cleared;
	 * this is why we use tcp_saved_listener. The listener itself
	 * is guaranteed to be around until tcp_accept_finish() is called
	 * on this eager -- this won't happen until we're done since we're
	 * inside the eager's perimeter now.
	 *
	 * We can also get called in the case were a connection needs
	 * to be re-fused. In this case tcp_saved_listener will be
	 * NULL but tcp_refuse will be true.
	 */
	ASSERT(tcp->tcp_saved_listener != NULL || tcp->tcp_refuse);
	/*
	 * Lookup peer endpoint; search for the remote endpoint having
	 * the reversed address-port quadruplet in ESTABLISHED state,
	 * which is guaranteed to be unique in the system.  Zone check
	 * is applied accordingly for loopback address, but not for
	 * local address since we want fusion to happen across Zones.
	 */
	if (tcp->tcp_ipversion == IPV4_VERSION) {
		peer_connp = ipcl_conn_tcp_lookup_reversed_ipv4(connp,
		    (ipha_t *)iphdr, tcph, ipst);
	} else {
		peer_connp = ipcl_conn_tcp_lookup_reversed_ipv6(connp,
		    (ip6_t *)iphdr, tcph, ipst);
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
	 * In particular we bail out for non-simple TCP/IP or if IPsec/
	 * IPQoS policy/kernel SSL exists. We also need to check if
	 * the connection is quiescent to cover the case when we are
	 * trying to re-enable fusion after IPobservability is turned off.
	 */
	ns = tcps->tcps_netstack;
	ipst = ns->netstack_ip;

	if (!tcp->tcp_unfusable && !peer_tcp->tcp_unfusable &&
	    !tcp_loopback_needs_ip(tcp, ns) &&
	    !tcp_loopback_needs_ip(peer_tcp, ns) &&
	    tcp->tcp_kssl_ent == NULL &&
	    tcp->tcp_xmit_head == NULL && peer_tcp->tcp_xmit_head == NULL &&
	    !IPP_ENABLED(IPP_LOCAL_OUT|IPP_LOCAL_IN, ipst)) {
		mblk_t *mp;
		queue_t *peer_rq = peer_tcp->tcp_rq;

		ASSERT(!TCP_IS_DETACHED(peer_tcp));
		ASSERT(tcp->tcp_fused_sigurg_mp == NULL ||
		    (!IPCL_IS_NONSTR(connp) && tcp->tcp_refuse));
		ASSERT(peer_tcp->tcp_fused_sigurg_mp == NULL ||
		    (!IPCL_IS_NONSTR(peer_connp) && peer_tcp->tcp_refuse));
		ASSERT(tcp->tcp_kssl_ctx == NULL);

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

		if (!tcp->tcp_refuse) {
			/*
			 * Set receive buffer and max packet size for the
			 * active open tcp.
			 * eager's values will be set in tcp_accept_finish.
			 */

			(void) tcp_rwnd_set(peer_tcp,
			    peer_tcp->tcp_recv_hiwater);

			/*
			 * Set the write offset value to zero since we won't
			 * be needing any room for TCP/IP headers.
			 */
			if (!IPCL_IS_NONSTR(peer_tcp->tcp_connp)) {
				struct stroptions *stropt;

				DB_TYPE(mp) = M_SETOPTS;
				mp->b_wptr += sizeof (*stropt);

				stropt = (struct stroptions *)mp->b_rptr;
				stropt->so_flags = SO_WROFF;
				stropt->so_wroff = 0;

				/* Send the options up */
				putnext(peer_rq, mp);
			} else {
				struct sock_proto_props sopp;

				/* The peer is a non-STREAMS end point */
				ASSERT(IPCL_IS_TCP(peer_connp));

				sopp.sopp_flags = SOCKOPT_WROFF;
				sopp.sopp_wroff = 0;
				(*peer_connp->conn_upcalls->su_set_proto_props)
				    (peer_connp->conn_upper_handle, &sopp);
			}
		} else {
			/*
			 * Endpoints are being re-fused, so options will not
			 * be sent up. In case of STREAMS, free the stroptions
			 * mblk.
			 */
			if (!IPCL_IS_NONSTR(connp))
				freemsg(mp);
		}
		tcp->tcp_refuse = B_FALSE;
		peer_tcp->tcp_refuse = B_FALSE;
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
		(void) tcp_fuse_rcv_drain(tcp->tcp_rq, tcp,
		    &tcp->tcp_fused_sigurg_mp);
	}
	if (!TCP_IS_DETACHED(peer_tcp)) {
		(void) tcp_fuse_rcv_drain(peer_tcp->tcp_rq, peer_tcp,
		    &peer_tcp->tcp_fused_sigurg_mp);
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
	 * Update th_seq and th_ack in the header template
	 */
	U32_TO_ABE32(tcp->tcp_snxt, tcp->tcp_tcph->th_seq);
	U32_TO_ABE32(tcp->tcp_rnxt, tcp->tcp_tcph->th_ack);
	U32_TO_ABE32(peer_tcp->tcp_snxt, peer_tcp->tcp_tcph->th_seq);
	U32_TO_ABE32(peer_tcp->tcp_rnxt, peer_tcp->tcp_tcph->th_ack);

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
	BUMP_MIB(&tcps->tcps_mib, tcpOutUrg);

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
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;
	boolean_t flow_stopped, peer_data_queued = B_FALSE;
	boolean_t urgent = (DB_TYPE(mp) != M_DATA);
	boolean_t push = B_TRUE;
	mblk_t *mp1 = mp;
	ill_t *ilp, *olp;
	ipif_t *iifp, *oifp;
	ipha_t *ipha;
	ip6_t *ip6h;
	tcph_t *tcph;
	uint_t ip_hdr_len;
	uint32_t seq;
	uint32_t recv_size = send_size;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	netstack_t	*ns = tcps->tcps_netstack;
	ip_stack_t	*ipst = ns->netstack_ip;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL && peer_tcp->tcp_loopback_peer == tcp);
	ASSERT(tcp->tcp_connp->conn_sqp == peer_tcp->tcp_connp->conn_sqp);
	ASSERT(DB_TYPE(mp) == M_DATA || DB_TYPE(mp) == M_PROTO ||
	    DB_TYPE(mp) == M_PCPROTO);

	/* If this connection requires IP, unfuse and use regular path */
	if (tcp_loopback_needs_ip(tcp, ns) ||
	    tcp_loopback_needs_ip(peer_tcp, ns) ||
	    IPP_ENABLED(IPP_LOCAL_OUT|IPP_LOCAL_IN, ipst) ||
	    list_head(&ipst->ips_ipobs_cb_list) != NULL) {
		TCP_STAT(tcps, tcp_fusion_aborted);
		tcp->tcp_refuse = B_TRUE;
		peer_tcp->tcp_refuse = B_TRUE;

		bcopy(peer_tcp->tcp_tcph, &tcp->tcp_saved_tcph,
		    sizeof (tcph_t));
		bcopy(tcp->tcp_tcph, &peer_tcp->tcp_saved_tcph,
		    sizeof (tcph_t));
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			bcopy(peer_tcp->tcp_ipha, &tcp->tcp_saved_ipha,
			    sizeof (ipha_t));
			bcopy(tcp->tcp_ipha, &peer_tcp->tcp_saved_ipha,
			    sizeof (ipha_t));
		} else {
			bcopy(peer_tcp->tcp_ip6h, &tcp->tcp_saved_ip6h,
			    sizeof (ip6_t));
			bcopy(tcp->tcp_ip6h, &peer_tcp->tcp_saved_ip6h,
			    sizeof (ip6_t));
		}
		goto unfuse;
	}

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

	if (tcp->tcp_ipversion == IPV4_VERSION &&
	    (HOOKS4_INTERESTED_LOOPBACK_IN(ipst) ||
	    HOOKS4_INTERESTED_LOOPBACK_OUT(ipst)) ||
	    tcp->tcp_ipversion == IPV6_VERSION &&
	    (HOOKS6_INTERESTED_LOOPBACK_IN(ipst) ||
	    HOOKS6_INTERESTED_LOOPBACK_OUT(ipst))) {
		/*
		 * Build ip and tcp header to satisfy FW_HOOKS.
		 * We only build it when any hook is present.
		 */
		if ((mp1 = tcp_xmit_mp(tcp, mp1, tcp->tcp_mss, NULL, NULL,
		    tcp->tcp_snxt, B_TRUE, NULL, B_FALSE)) == NULL)
			/* If tcp_xmit_mp fails, use regular path */
			goto unfuse;

		/*
		 * The ipif and ill can be safely referenced under the
		 * protection of conn_lock - see head of function comment for
		 * conn_get_held_ipif(). It is necessary to check that both
		 * the ipif and ill can be looked up (i.e. not condemned). If
		 * not, bail out and unfuse this connection.
		 */
		mutex_enter(&peer_tcp->tcp_connp->conn_lock);
		if ((peer_tcp->tcp_connp->conn_ire_cache == NULL) ||
		    (peer_tcp->tcp_connp->conn_ire_cache->ire_marks &
		    IRE_MARK_CONDEMNED) ||
		    ((oifp = peer_tcp->tcp_connp->conn_ire_cache->ire_ipif)
		    == NULL) ||
		    (!IPIF_CAN_LOOKUP(oifp)) ||
		    ((olp = oifp->ipif_ill) == NULL) ||
		    (ill_check_and_refhold(olp) != 0)) {
			mutex_exit(&peer_tcp->tcp_connp->conn_lock);
			goto unfuse;
		}
		mutex_exit(&peer_tcp->tcp_connp->conn_lock);

		/* PFHooks: LOOPBACK_OUT */
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			ipha = (ipha_t *)mp1->b_rptr;

			DTRACE_PROBE4(ip4__loopback__out__start,
			    ill_t *, NULL, ill_t *, olp,
			    ipha_t *, ipha, mblk_t *, mp1);
			FW_HOOKS(ipst->ips_ip4_loopback_out_event,
			    ipst->ips_ipv4firewall_loopback_out,
			    NULL, olp, ipha, mp1, mp1, 0, ipst);
			DTRACE_PROBE1(ip4__loopback__out__end, mblk_t *, mp1);
		} else {
			ip6h = (ip6_t *)mp1->b_rptr;

			DTRACE_PROBE4(ip6__loopback__out__start,
			    ill_t *, NULL, ill_t *, olp,
			    ip6_t *, ip6h, mblk_t *, mp1);
			FW_HOOKS6(ipst->ips_ip6_loopback_out_event,
			    ipst->ips_ipv6firewall_loopback_out,
			    NULL, olp, ip6h, mp1, mp1, 0, ipst);
			DTRACE_PROBE1(ip6__loopback__out__end, mblk_t *, mp1);
		}
		ill_refrele(olp);

		if (mp1 == NULL)
			goto unfuse;

		/*
		 * The ipif and ill can be safely referenced under the
		 * protection of conn_lock - see head of function comment for
		 * conn_get_held_ipif(). It is necessary to check that both
		 * the ipif and ill can be looked up (i.e. not condemned). If
		 * not, bail out and unfuse this connection.
		 */
		mutex_enter(&tcp->tcp_connp->conn_lock);
		if ((tcp->tcp_connp->conn_ire_cache == NULL) ||
		    (tcp->tcp_connp->conn_ire_cache->ire_marks &
		    IRE_MARK_CONDEMNED) ||
		    ((iifp = tcp->tcp_connp->conn_ire_cache->ire_ipif)
		    == NULL) ||
		    (!IPIF_CAN_LOOKUP(iifp)) ||
		    ((ilp = iifp->ipif_ill) == NULL) ||
		    (ill_check_and_refhold(ilp) != 0)) {
			mutex_exit(&tcp->tcp_connp->conn_lock);
			goto unfuse;
		}
		mutex_exit(&tcp->tcp_connp->conn_lock);

		/* PFHooks: LOOPBACK_IN */
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			DTRACE_PROBE4(ip4__loopback__in__start,
			    ill_t *, ilp, ill_t *, NULL,
			    ipha_t *, ipha, mblk_t *, mp1);
			FW_HOOKS(ipst->ips_ip4_loopback_in_event,
			    ipst->ips_ipv4firewall_loopback_in,
			    ilp, NULL, ipha, mp1, mp1, 0, ipst);
			DTRACE_PROBE1(ip4__loopback__in__end, mblk_t *, mp1);
			ill_refrele(ilp);
			if (mp1 == NULL)
				goto unfuse;

			ip_hdr_len = IPH_HDR_LENGTH(ipha);
		} else {
			DTRACE_PROBE4(ip6__loopback__in__start,
			    ill_t *, ilp, ill_t *, NULL,
			    ip6_t *, ip6h, mblk_t *, mp1);
			FW_HOOKS6(ipst->ips_ip6_loopback_in_event,
			    ipst->ips_ipv6firewall_loopback_in,
			    ilp, NULL, ip6h, mp1, mp1, 0, ipst);
			DTRACE_PROBE1(ip6__loopback__in__end, mblk_t *, mp1);
			ill_refrele(ilp);
			if (mp1 == NULL)
				goto unfuse;

			ip_hdr_len = ip_hdr_length_v6(mp1, ip6h);
		}

		/* Data length might be changed by FW_HOOKS */
		tcph = (tcph_t *)&mp1->b_rptr[ip_hdr_len];
		seq = ABE32_TO_U32(tcph->th_seq);
		recv_size += seq - tcp->tcp_snxt;

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
	if (IPCL_IS_NONSTR(peer_tcp->tcp_connp) &&
	    !TCP_IS_DETACHED(peer_tcp)) {
		int error;
		int flags = 0;

		if ((tcp->tcp_valid_bits & TCP_URG_VALID) &&
		    (tcp->tcp_urg == tcp->tcp_snxt)) {
			flags = MSG_OOB;
			(*peer_tcp->tcp_connp->conn_upcalls->su_signal_oob)
			    (peer_tcp->tcp_connp->conn_upper_handle, 0);
			tcp->tcp_valid_bits &= ~TCP_URG_VALID;
		}
		if ((*peer_tcp->tcp_connp->conn_upcalls->su_recv)(
		    peer_tcp->tcp_connp->conn_upper_handle, mp, recv_size,
		    flags, &error, &push) < 0) {
			ASSERT(error != EOPNOTSUPP);
			peer_data_queued = B_TRUE;
		}
	} else {
		if (IPCL_IS_NONSTR(peer_tcp->tcp_connp) &&
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

		tcp_rcv_enqueue(peer_tcp, mp, recv_size);

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
	    (peer_tcp->tcp_rcv_cnt >= peer_tcp->tcp_recv_hiwater)) ||
	    (!TCP_IS_DETACHED(peer_tcp) &&
	    !IPCL_IS_NONSTR(peer_tcp->tcp_connp) &&
	    !canputnext(peer_tcp->tcp_rq))) {
		peer_data_queued = B_TRUE;
	}

	if (!flow_stopped && (peer_data_queued ||
	    (TCP_UNSENT_BYTES(tcp) >= tcp->tcp_xmit_hiwater))) {
		tcp_setqfull(tcp);
		flow_stopped = B_TRUE;
		TCP_STAT(tcps, tcp_fusion_flowctl);
		DTRACE_PROBE3(tcp__fuse__output__flowctl, tcp_t *, tcp,
		    uint_t, send_size, uint_t, peer_tcp->tcp_rcv_cnt);
	} else if (flow_stopped && !peer_data_queued &&
	    (TCP_UNSENT_BYTES(tcp) <= tcp->tcp_xmit_lowater)) {
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
	peer_tcp->tcp_rack = peer_tcp->tcp_rnxt;

	BUMP_MIB(&tcps->tcps_mib, tcpOutDataSegs);
	UPDATE_MIB(&tcps->tcps_mib, tcpOutDataBytes, send_size);

	BUMP_MIB(&tcps->tcps_mib, tcpInSegs);
	BUMP_MIB(&tcps->tcps_mib, tcpInDataInorderSegs);
	UPDATE_MIB(&tcps->tcps_mib, tcpInDataInorderBytes, send_size);

	BUMP_LOCAL(tcp->tcp_obsegs);
	BUMP_LOCAL(peer_tcp->tcp_ibsegs);

	DTRACE_PROBE2(tcp__fuse__output, tcp_t *, tcp, uint_t, send_size);

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
			 * correct peer_tcp->tcp_rq is globally visible before
			 * peer_tcp->tcp_detached is visible as clear, but we
			 * must also ensure that the load of tcp_rq cannot be
			 * reordered to be before the tcp_detached check.
			 */
			membar_consumer();
			(void) tcp_fuse_rcv_drain(peer_tcp->tcp_rq, peer_tcp,
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
			    tcp_push_timer,
			    MSEC_TO_TICK(
			    tcps->tcps_push_timer_interval));
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
	tcp->tcp_rwnd = tcp->tcp_recv_hiwater;

	mutex_enter(&peer_tcp->tcp_non_sq_lock);
	if (peer_tcp->tcp_flow_stopped && (TCP_UNSENT_BYTES(peer_tcp) <=
	    peer_tcp->tcp_xmit_lowater)) {
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

	ASSERT(tcp->tcp_fused);

	/* Ensure that value is within the maximum upper bound */
	if (rwnd > tcps->tcps_max_buf)
		rwnd = tcps->tcps_max_buf;

	/* Obey the absolute minimum tcp receive high water mark */
	if (rwnd < tcps->tcps_sth_rcv_hiwat)
		rwnd = tcps->tcps_sth_rcv_hiwat;

	/*
	 * Round up to system page size in case SO_RCVBUF is modified
	 * after SO_SNDBUF; the latter is also similarly rounded up.
	 */
	rwnd = P2ROUNDUP_TYPED(rwnd, PAGESIZE, size_t);

	/*
	 * Record high water mark, this is used for flow-control
	 * purposes in tcp_fuse_output().
	 */
	tcp->tcp_recv_hiwater = rwnd;
	return (rwnd);
}

/*
 * Calculate the maximum outstanding unread data block for a fused tcp endpoint.
 */
int
tcp_fuse_maxpsz(tcp_t *tcp)
{
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;
	uint_t sndbuf = tcp->tcp_xmit_hiwater;
	uint_t maxpsz = sndbuf;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL);
	ASSERT(peer_tcp->tcp_recv_hiwater != 0);
	/*
	 * In the fused loopback case, we want the stream head to split
	 * up larger writes into smaller chunks for a more accurate flow-
	 * control accounting.  Our maxpsz is half of the sender's send
	 * buffer or the receiver's receive buffer, whichever is smaller.
	 * We round up the buffer to system page size due to the lack of
	 * TCP MSS concept in Fusion.
	 */
	if (maxpsz > peer_tcp->tcp_recv_hiwater)
		maxpsz = peer_tcp->tcp_recv_hiwater;
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
		(void) tcp_fuse_rcv_drain(tcp->tcp_rq, tcp, NULL);

	mutex_enter(&peer_tcp->tcp_non_sq_lock);
	if (peer_tcp->tcp_flow_stopped &&
	    (TCP_UNSENT_BYTES(peer_tcp) <=
	    peer_tcp->tcp_xmit_lowater)) {
		tcp_clrqfull(peer_tcp);
	}
	mutex_exit(&peer_tcp->tcp_non_sq_lock);

	TCP_STAT(tcp->tcp_tcps, tcp_fusion_backenabled);
}

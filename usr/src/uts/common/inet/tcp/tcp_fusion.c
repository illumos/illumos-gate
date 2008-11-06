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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
 * receive queue; no protocol processing is involved.  After enqueueing
 * the data, the sender can either push (putnext) data up the receiver's
 * read queue; or the sender can simply return and let the receiver
 * retrieve the enqueued data via the synchronous streams entry point
 * tcp_fuse_rrw().  The latter path is taken if synchronous streams is
 * enabled (the default).  It is disabled if sockfs no longer resides
 * directly on top of tcp module due to a module insertion or removal.
 * It also needs to be temporarily disabled when sending urgent data
 * because the tcp_fuse_rrw() path bypasses the M_PROTO processing done
 * by strsock_proto() hook.
 *
 * Sychronization is handled by squeue and the mutex tcp_non_sq_lock.
 * One of the requirements for fusion to succeed is that both endpoints
 * need to be using the same squeue.  This ensures that neither side
 * can disappear while the other side is still sending data.  By itself,
 * squeue is not sufficient for guaranteeing safety when synchronous
 * streams is enabled.  The reason is that tcp_fuse_rrw() doesn't enter
 * the squeue and its access to tcp_rcv_list and other fusion-related
 * fields needs to be sychronized with the sender.  tcp_non_sq_lock is
 * used for this purpose.  When there is urgent data, the sender needs
 * to push the data up the receiver's streams read queue.  In order to
 * avoid holding the tcp_non_sq_lock across putnext(), the sender sets
 * the peer tcp's tcp_fuse_syncstr_plugged bit and releases tcp_non_sq_lock
 * (see macro TCP_FUSE_SYNCSTR_PLUG_DRAIN()).  If tcp_fuse_rrw() enters
 * after this point, it will see that synchronous streams is plugged and
 * will wait on tcp_fuse_plugcv.  After the sender has finished pushing up
 * all urgent data, it will clear the tcp_fuse_syncstr_plugged bit using
 * TCP_FUSE_SYNCSTR_UNPLUG_DRAIN().  This will cause any threads waiting
 * on tcp_fuse_plugcv to return EBUSY, and in turn cause strget() to call
 * getq_noenab() to dequeue data from the stream head instead.  Once the
 * data on the stream head has been consumed, tcp_fuse_rrw() may again
 * be used to process tcp_rcv_list.  However, if TCP_FUSE_SYNCSTR_STOP()
 * has been called, all future calls to tcp_fuse_rrw() will return EBUSY,
 * effectively disabling synchronous streams.
 *
 * The following note applies only to the synchronous streams mode.
 *
 * Flow control is done by checking the size of receive buffer and
 * the number of data blocks, both set to different limits.  This is
 * different than regular streams flow control where cumulative size
 * check dominates block count check -- streams queue high water mark
 * typically represents bytes.  Each enqueue triggers notifications
 * to the receiving process; a build up of data blocks indicates a
 * slow receiver and the sender should be blocked or informed at the
 * earliest moment instead of further wasting system resources.  In
 * effect, this is equivalent to limiting the number of outstanding
 * segments in flight.
 */

/*
 * Setting this to false means we disable fusion altogether and
 * loopback connections would go through the protocol paths.
 */
boolean_t do_tcp_fusion = B_TRUE;

/*
 * Enabling this flag allows sockfs to retrieve data directly
 * from a fused tcp endpoint using synchronous streams interface.
 */
boolean_t do_tcp_direct_sockfs = B_TRUE;

/*
 * This is the minimum amount of outstanding writes allowed on
 * a synchronous streams-enabled receiving endpoint before the
 * sender gets flow-controlled.  Setting this value to 0 means
 * that the data block limit is equivalent to the byte count
 * limit, which essentially disables the check.
 */
#define	TCP_FUSION_RCV_UNREAD_MIN	8
uint_t tcp_fusion_rcv_unread_min = TCP_FUSION_RCV_UNREAD_MIN;

static void		tcp_fuse_syncstr_enable(tcp_t *);
static void		tcp_fuse_syncstr_disable(tcp_t *);
static boolean_t	strrput_sig(queue_t *, boolean_t);

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
	 * We need to inherit q_hiwat of the listener tcp, but we can't
	 * really use tcp_listener since we get here after sending up
	 * T_CONN_IND and tcp_wput_accept() may be called independently,
	 * at which point tcp_listener is cleared; this is why we use
	 * tcp_saved_listener.  The listener itself is guaranteed to be
	 * around until tcp_accept_finish() is called on this eager --
	 * this won't happen until we're done since we're inside the
	 * eager's perimeter now.
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
	 * as our conn and is not raw-socket.  The squeue assignment of
	 * this eager tcp was done earlier at the time of SYN processing
	 * in ip_fanout_tcp{_v6}.  Note that similar squeues by itself
	 * doesn't guarantee a safe condition to fuse, hence we perform
	 * additional tests below.
	 */
	ASSERT(peer_connp == NULL || peer_connp != connp);
	if (peer_connp == NULL || peer_connp->conn_sqp != connp->conn_sqp ||
	    !IPCL_IS_TCP(peer_connp)) {
		if (peer_connp != NULL) {
			TCP_STAT(tcps, tcp_fusion_unqualified);
			CONN_DEC_REF(peer_connp);
		}
		return;
	}
	peer_tcp = peer_connp->conn_tcp;	/* active connect tcp */

	ASSERT(peer_tcp != NULL && peer_tcp != tcp && !peer_tcp->tcp_fused);
	ASSERT(peer_tcp->tcp_loopback && peer_tcp->tcp_loopback_peer == NULL);
	ASSERT(peer_connp->conn_sqp == connp->conn_sqp);

	/*
	 * Fuse the endpoints; we perform further checks against both
	 * tcp endpoints to ensure that a fusion is allowed to happen.
	 * In particular we bail out for non-simple TCP/IP or if IPsec/
	 * IPQoS policy/kernel SSL exists.
	 */
	ns = tcps->tcps_netstack;
	ipst = ns->netstack_ip;

	if (!tcp->tcp_unfusable && !peer_tcp->tcp_unfusable &&
	    !tcp_loopback_needs_ip(tcp, ns) &&
	    !tcp_loopback_needs_ip(peer_tcp, ns) &&
	    tcp->tcp_kssl_ent == NULL &&
	    !IPP_ENABLED(IPP_LOCAL_OUT|IPP_LOCAL_IN, ipst)) {
		mblk_t *mp;
		struct stroptions *stropt;
		queue_t *peer_rq = peer_tcp->tcp_rq;

		ASSERT(!TCP_IS_DETACHED(peer_tcp) && peer_rq != NULL);
		ASSERT(tcp->tcp_fused_sigurg_mp == NULL);
		ASSERT(peer_tcp->tcp_fused_sigurg_mp == NULL);
		ASSERT(tcp->tcp_kssl_ctx == NULL);

		/*
		 * We need to drain data on both endpoints during unfuse.
		 * If we need to send up SIGURG at the time of draining,
		 * we want to be sure that an mblk is readily available.
		 * This is why we pre-allocate the M_PCSIG mblks for both
		 * endpoints which will only be used during/after unfuse.
		 */
		if ((mp = allocb(1, BPRI_HI)) == NULL)
			goto failed;

		tcp->tcp_fused_sigurg_mp = mp;

		if ((mp = allocb(1, BPRI_HI)) == NULL)
			goto failed;

		peer_tcp->tcp_fused_sigurg_mp = mp;

		/* Allocate M_SETOPTS mblk */
		if ((mp = allocb(sizeof (*stropt), BPRI_HI)) == NULL)
			goto failed;

		/* If either tcp or peer_tcp sodirect enabled then disable */
		if (tcp->tcp_sodirect != NULL) {
			mutex_enter(tcp->tcp_sodirect->sod_lockp);
			SOD_DISABLE(tcp->tcp_sodirect);
			mutex_exit(tcp->tcp_sodirect->sod_lockp);
			tcp->tcp_sodirect = NULL;
		}
		if (peer_tcp->tcp_sodirect != NULL) {
			mutex_enter(peer_tcp->tcp_sodirect->sod_lockp);
			SOD_DISABLE(peer_tcp->tcp_sodirect);
			mutex_exit(peer_tcp->tcp_sodirect->sod_lockp);
			peer_tcp->tcp_sodirect = NULL;
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
		 * At this point we are a detached eager tcp and therefore
		 * don't have a queue assigned to us until accept happens.
		 * In the mean time the peer endpoint may immediately send
		 * us data as soon as fusion is finished, and we need to be
		 * able to flow control it in case it sends down huge amount
		 * of data while we're still detached.  To prevent that we
		 * inherit the listener's q_hiwat value; this is temporary
		 * since we'll repeat the process in tcp_accept_finish().
		 */
		if (!tcp->tcp_refuse) {
			(void) tcp_fuse_set_rcv_hiwat(tcp,
			    tcp->tcp_saved_listener->tcp_rq->q_hiwat);

			/*
			 * Set the stream head's write offset value to zero
			 * since we won't be needing any room for TCP/IP
			 * headers; tell it to not break up the writes (this
			 * would reduce the amount of work done by kmem); and
			 * configure our receive buffer. Note that we can only
			 * do this for the active connect tcp since our eager
			 * is still detached; it will be dealt with later in
			 * tcp_accept_finish().
			 */
			DB_TYPE(mp) = M_SETOPTS;
			mp->b_wptr += sizeof (*stropt);

			stropt = (struct stroptions *)mp->b_rptr;
			stropt->so_flags = SO_MAXBLK | SO_WROFF | SO_HIWAT;
			stropt->so_maxblk = tcp_maxpsz_set(peer_tcp, B_FALSE);
			stropt->so_wroff = 0;

			/*
			 * Record the stream head's high water mark for
			 * peer endpoint; this is used for flow-control
			 * purposes in tcp_fuse_output().
			 */
			stropt->so_hiwat = tcp_fuse_set_rcv_hiwat(peer_tcp,
			    peer_rq->q_hiwat);

			tcp->tcp_refuse = B_FALSE;
			peer_tcp->tcp_refuse = B_FALSE;
			/* Send the options up */
			putnext(peer_rq, mp);
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

	ASSERT(tcp->tcp_fused && peer_tcp != NULL);
	ASSERT(peer_tcp->tcp_fused && peer_tcp->tcp_loopback_peer == tcp);
	ASSERT(tcp->tcp_connp->conn_sqp == peer_tcp->tcp_connp->conn_sqp);
	ASSERT(tcp->tcp_unsent == 0 && peer_tcp->tcp_unsent == 0);
	ASSERT(tcp->tcp_fused_sigurg_mp != NULL);
	ASSERT(peer_tcp->tcp_fused_sigurg_mp != NULL);

	/*
	 * We disable synchronous streams, drain any queued data and
	 * clear tcp_direct_sockfs.  The synchronous streams entry
	 * points will become no-ops after this point.
	 */
	tcp_fuse_disable_pair(tcp, B_TRUE);

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
	freeb(peer_tcp->tcp_fused_sigurg_mp);
	freeb(tcp->tcp_fused_sigurg_mp);
	peer_tcp->tcp_fused_sigurg_mp = NULL;
	tcp->tcp_fused_sigurg_mp = NULL;
}

/*
 * Fusion output routine for urgent data.  This routine is called by
 * tcp_fuse_output() for handling non-M_DATA mblks.
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
	uint_t max_unread;
	boolean_t flow_stopped, peer_data_queued = B_FALSE;
	boolean_t urgent = (DB_TYPE(mp) != M_DATA);
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
	max_unread = peer_tcp->tcp_fuse_rcv_unread_hiwater;

	/*
	 * Handle urgent data; we either send up SIGURG to the peer now
	 * or do it later when we drain, in case the peer is detached
	 * or if we're short of memory for M_PCSIG mblk.
	 */
	if (urgent) {
		/*
		 * We stop synchronous streams when we have urgent data
		 * queued to prevent tcp_fuse_rrw() from pulling it.  If
		 * for some reasons the urgent data can't be delivered
		 * below, synchronous streams will remain stopped until
		 * someone drains the tcp_rcv_list.
		 */
		TCP_FUSE_SYNCSTR_PLUG_DRAIN(peer_tcp);
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

	mutex_enter(&peer_tcp->tcp_non_sq_lock);
	/*
	 * Wake up and signal the peer; it is okay to do this before
	 * enqueueing because we are holding the lock.  One of the
	 * advantages of synchronous streams is the ability for us to
	 * find out when the application performs a read on the socket,
	 * by way of tcp_fuse_rrw() entry point being called.  Every
	 * data that gets enqueued onto the receiver is treated as if
	 * it has arrived at the receiving endpoint, thus generating
	 * SIGPOLL/SIGIO for asynchronous socket just as in the strrput()
	 * case.  However, we only wake up the application when necessary,
	 * i.e. during the first enqueue.  When tcp_fuse_rrw() is called
	 * it will send everything upstream.
	 */
	if (peer_tcp->tcp_direct_sockfs && !urgent &&
	    !TCP_IS_DETACHED(peer_tcp)) {
		/* Update poll events and send SIGPOLL/SIGIO if necessary */
		STR_WAKEUP_SENDSIG(STREAM(peer_tcp->tcp_rq),
		    peer_tcp->tcp_rcv_list);
	}

	/*
	 * Enqueue data into the peer's receive list; we may or may not
	 * drain the contents depending on the conditions below.
	 */
	tcp_rcv_enqueue(peer_tcp, mp, recv_size);

	/* In case it wrapped around and also to keep it constant */
	peer_tcp->tcp_rwnd += recv_size;
	/*
	 * We increase the peer's unread message count here whilst still
	 * holding it's tcp_non_sq_lock. This ensures that the increment
	 * occurs in the same lock acquisition perimeter as the enqueue.
	 * Depending on lock hierarchy, we can release these locks which
	 * creates a window in which we can race with tcp_fuse_rrw()
	 */
	peer_tcp->tcp_fuse_rcv_unread_cnt++;

	/*
	 * Exercise flow-control when needed; we will get back-enabled
	 * in either tcp_accept_finish(), tcp_unfuse(), or tcp_fuse_rrw().
	 * If tcp_direct_sockfs is on or if the peer endpoint is detached,
	 * we emulate streams flow control by checking the peer's queue
	 * size and high water mark; otherwise we simply use canputnext()
	 * to decide if we need to stop our flow.
	 *
	 * The outstanding unread data block check does not apply for a
	 * detached receiver; this is to avoid unnecessary blocking of the
	 * sender while the accept is currently in progress and is quite
	 * similar to the regular tcp.
	 */
	if (TCP_IS_DETACHED(peer_tcp) || max_unread == 0)
		max_unread = UINT_MAX;

	/*
	 * Since we are accessing our tcp_flow_stopped and might modify it,
	 * we need to take tcp->tcp_non_sq_lock. The lock for the highest
	 * address is held first. Dropping peer_tcp->tcp_non_sq_lock should
	 * not be an issue here since we are within the squeue and the peer
	 * won't disappear.
	 */
	if (tcp > peer_tcp) {
		mutex_exit(&peer_tcp->tcp_non_sq_lock);
		mutex_enter(&tcp->tcp_non_sq_lock);
		mutex_enter(&peer_tcp->tcp_non_sq_lock);
	} else {
		mutex_enter(&tcp->tcp_non_sq_lock);
	}
	flow_stopped = tcp->tcp_flow_stopped;
	if (((peer_tcp->tcp_direct_sockfs || TCP_IS_DETACHED(peer_tcp)) &&
	    (peer_tcp->tcp_rcv_cnt >= peer_tcp->tcp_fuse_rcv_hiwater ||
	    peer_tcp->tcp_fuse_rcv_unread_cnt >= max_unread)) ||
	    (!peer_tcp->tcp_direct_sockfs && !TCP_IS_DETACHED(peer_tcp) &&
	    !canputnext(peer_tcp->tcp_rq))) {
		peer_data_queued = B_TRUE;
	}

	if (!flow_stopped && (peer_data_queued ||
	    (TCP_UNSENT_BYTES(tcp) >= tcp->tcp_xmit_hiwater))) {
		tcp_setqfull(tcp);
		flow_stopped = B_TRUE;
		TCP_STAT(tcps, tcp_fusion_flowctl);
		DTRACE_PROBE4(tcp__fuse__output__flowctl, tcp_t *, tcp,
		    uint_t, send_size, uint_t, peer_tcp->tcp_rcv_cnt,
		    uint_t, peer_tcp->tcp_fuse_rcv_unread_cnt);
	} else if (flow_stopped && !peer_data_queued &&
	    (TCP_UNSENT_BYTES(tcp) <= tcp->tcp_xmit_lowater)) {
		tcp_clrqfull(tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
		flow_stopped = B_FALSE;
	}
	mutex_exit(&tcp->tcp_non_sq_lock);

	/*
	 * If we are in synchronous streams mode and the peer read queue is
	 * not full then schedule a push timer if one is not scheduled
	 * already. This is needed for applications which use MSG_PEEK to
	 * determine the number of bytes available before issuing a 'real'
	 * read. It also makes flow control more deterministic, particularly
	 * for smaller message sizes.
	 */
	if (!urgent && peer_tcp->tcp_direct_sockfs &&
	    peer_tcp->tcp_push_tid == 0 && !TCP_IS_DETACHED(peer_tcp) &&
	    canputnext(peer_tcp->tcp_rq)) {
		peer_tcp->tcp_push_tid = TCP_TIMER(peer_tcp, tcp_push_timer,
		    MSEC_TO_TICK(tcps->tcps_push_timer_interval));
	}
	mutex_exit(&peer_tcp->tcp_non_sq_lock);
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

	if (!TCP_IS_DETACHED(peer_tcp)) {
		/*
		 * Drain the peer's receive queue it has urgent data or if
		 * we're not flow-controlled.  There is no need for draining
		 * normal data when tcp_direct_sockfs is on because the peer
		 * will pull the data via tcp_fuse_rrw().
		 */
		if (urgent || (!flow_stopped && !peer_tcp->tcp_direct_sockfs)) {
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
			/*
			 * If synchronous streams was stopped above due
			 * to the presence of urgent data, re-enable it.
			 */
			if (urgent)
				TCP_FUSE_SYNCSTR_UNPLUG_DRAIN(peer_tcp);
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
#ifdef DEBUG
	uint_t cnt = 0;
#endif
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	tcp_t		*peer_tcp = tcp->tcp_loopback_peer;
	boolean_t	sd_rd_eof = B_FALSE;

	ASSERT(tcp->tcp_loopback);
	ASSERT(tcp->tcp_fused || tcp->tcp_fused_sigurg);
	ASSERT(!tcp->tcp_fused || tcp->tcp_loopback_peer != NULL);
	ASSERT(sigurg_mpp != NULL || tcp->tcp_fused);

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
		/*
		 * sigurg_mpp is normally NULL, i.e. when we're still
		 * fused and didn't get here because of tcp_unfuse().
		 * In this case try hard to allocate the M_PCSIG mblk.
		 */
		if (sigurg_mpp == NULL &&
		    (mp = allocb(1, BPRI_HI)) == NULL &&
		    (mp = allocb_tryhard(1)) == NULL) {
			/* Alloc failed; try again next time */
			tcp->tcp_push_tid = TCP_TIMER(tcp, tcp_push_timer,
			    MSEC_TO_TICK(tcps->tcps_push_timer_interval));
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

		tcp->tcp_fused_sigurg = B_FALSE;
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

	/*
	 * In the synchronous streams case, we generate SIGPOLL/SIGIO for
	 * each M_DATA that gets enqueued onto the receiver.  At this point
	 * we are about to drain any queued data via putnext().  In order
	 * to avoid extraneous signal generation from strrput(), we set
	 * STRGETINPROG flag at the stream head prior to the draining and
	 * restore it afterwards.  This masks out signal generation only
	 * for M_DATA messages and does not affect urgent data. We only do
	 * this if the STREOF flag is not set which can happen if the
	 * application shuts down the read side of a stream. In this case
	 * we simply free these messages to approximate the flushq behavior
	 * which normally occurs when STREOF is on the stream head read queue.
	 */
	if (tcp->tcp_direct_sockfs)
		sd_rd_eof = strrput_sig(q, B_FALSE);

	/* Drain the data */
	while ((mp = tcp->tcp_rcv_list) != NULL) {
		tcp->tcp_rcv_list = mp->b_next;
		mp->b_next = NULL;
#ifdef DEBUG
		cnt += msgdsize(mp);
#endif
		if (sd_rd_eof) {
			freemsg(mp);
		} else {
			putnext(q, mp);
			TCP_STAT(tcps, tcp_fusion_putnext);
		}
	}

	if (tcp->tcp_direct_sockfs && !sd_rd_eof)
		(void) strrput_sig(q, B_TRUE);

	ASSERT(cnt == tcp->tcp_rcv_cnt);
	tcp->tcp_rcv_last_head = NULL;
	tcp->tcp_rcv_last_tail = NULL;
	tcp->tcp_rcv_cnt = 0;
	tcp->tcp_fuse_rcv_unread_cnt = 0;
	tcp->tcp_rwnd = q->q_hiwat;

	if (peer_tcp->tcp_flow_stopped && (TCP_UNSENT_BYTES(peer_tcp) <=
	    peer_tcp->tcp_xmit_lowater)) {
		tcp_clrqfull(peer_tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
	}

	return (B_TRUE);
}

/*
 * Synchronous stream entry point for sockfs to retrieve
 * data directly from tcp_rcv_list.
 * tcp_fuse_rrw() might end up modifying the peer's tcp_flow_stopped,
 * for which it  must take the tcp_non_sq_lock of the peer as well
 * making any change. The order of taking the locks is based on
 * the TCP pointer itself. Before we get the peer we need to take
 * our tcp_non_sq_lock so that the peer doesn't disappear. However,
 * we cannot drop the lock if we have to grab the peer's lock (because
 * of ordering), since the peer might disappear in the interim. So,
 * we take our tcp_non_sq_lock, get the peer, increment the ref on the
 * peer's conn, drop all the locks and then take the tcp_non_sq_lock in the
 * desired order. Incrementing the conn ref on the peer means that the
 * peer won't disappear when we drop our tcp_non_sq_lock.
 */
int
tcp_fuse_rrw(queue_t *q, struiod_t *dp)
{
	tcp_t *tcp = Q_TO_CONN(q)->conn_tcp;
	mblk_t *mp;
	tcp_t *peer_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	mutex_enter(&tcp->tcp_non_sq_lock);

	/*
	 * If tcp_fuse_syncstr_plugged is set, then another thread is moving
	 * the underlying data to the stream head.  We need to wait until it's
	 * done, then return EBUSY so that strget() will dequeue data from the
	 * stream head to ensure data is drained in-order.
	 */
plugged:
	if (tcp->tcp_fuse_syncstr_plugged) {
		do {
			cv_wait(&tcp->tcp_fuse_plugcv, &tcp->tcp_non_sq_lock);
		} while (tcp->tcp_fuse_syncstr_plugged);

		mutex_exit(&tcp->tcp_non_sq_lock);
		TCP_STAT(tcps, tcp_fusion_rrw_plugged);
		TCP_STAT(tcps, tcp_fusion_rrw_busy);
		return (EBUSY);
	}

	peer_tcp = tcp->tcp_loopback_peer;

	/*
	 * If someone had turned off tcp_direct_sockfs or if synchronous
	 * streams is stopped, we return EBUSY.  This causes strget() to
	 * dequeue data from the stream head instead.
	 */
	if (!tcp->tcp_direct_sockfs || tcp->tcp_fuse_syncstr_stopped) {
		mutex_exit(&tcp->tcp_non_sq_lock);
		TCP_STAT(tcps, tcp_fusion_rrw_busy);
		return (EBUSY);
	}

	/*
	 * Grab lock in order. The highest addressed tcp is locked first.
	 * We don't do this within the tcp_rcv_list check since if we
	 * have to drop the lock, for ordering, then the tcp_rcv_list
	 * could change.
	 */
	if (peer_tcp > tcp) {
		CONN_INC_REF(peer_tcp->tcp_connp);
		mutex_exit(&tcp->tcp_non_sq_lock);
		mutex_enter(&peer_tcp->tcp_non_sq_lock);
		mutex_enter(&tcp->tcp_non_sq_lock);
		/*
		 * This might have changed in the interim
		 * Once read-side tcp_non_sq_lock is dropped above
		 * anything can happen, we need to check all
		 * known conditions again once we reaquire
		 * read-side tcp_non_sq_lock.
		 */
		if (tcp->tcp_fuse_syncstr_plugged) {
			mutex_exit(&peer_tcp->tcp_non_sq_lock);
			CONN_DEC_REF(peer_tcp->tcp_connp);
			goto plugged;
		}
		if (!tcp->tcp_direct_sockfs || tcp->tcp_fuse_syncstr_stopped) {
			mutex_exit(&tcp->tcp_non_sq_lock);
			mutex_exit(&peer_tcp->tcp_non_sq_lock);
			CONN_DEC_REF(peer_tcp->tcp_connp);
			TCP_STAT(tcps, tcp_fusion_rrw_busy);
			return (EBUSY);
		}
		CONN_DEC_REF(peer_tcp->tcp_connp);
	} else {
		mutex_enter(&peer_tcp->tcp_non_sq_lock);
	}

	if ((mp = tcp->tcp_rcv_list) != NULL) {

		DTRACE_PROBE3(tcp__fuse__rrw, tcp_t *, tcp,
		    uint32_t, tcp->tcp_rcv_cnt, ssize_t, dp->d_uio.uio_resid);

		tcp->tcp_rcv_list = NULL;
		TCP_STAT(tcps, tcp_fusion_rrw_msgcnt);

		/*
		 * At this point nothing should be left in tcp_rcv_list.
		 * The only possible case where we would have a chain of
		 * b_next-linked messages is urgent data, but we wouldn't
		 * be here if that's true since urgent data is delivered
		 * via putnext() and synchronous streams is stopped until
		 * tcp_fuse_rcv_drain() is finished.
		 */
		ASSERT(DB_TYPE(mp) == M_DATA && mp->b_next == NULL);

		tcp->tcp_rcv_last_head = NULL;
		tcp->tcp_rcv_last_tail = NULL;
		tcp->tcp_rcv_cnt = 0;
		tcp->tcp_fuse_rcv_unread_cnt = 0;

		if (peer_tcp->tcp_flow_stopped &&
		    (TCP_UNSENT_BYTES(peer_tcp) <=
		    peer_tcp->tcp_xmit_lowater)) {
			tcp_clrqfull(peer_tcp);
			TCP_STAT(tcps, tcp_fusion_backenabled);
		}
	}
	mutex_exit(&peer_tcp->tcp_non_sq_lock);
	/*
	 * Either we just dequeued everything or we get here from sockfs
	 * and have nothing to return; in this case clear RSLEEP.
	 */
	ASSERT(tcp->tcp_rcv_last_head == NULL);
	ASSERT(tcp->tcp_rcv_last_tail == NULL);
	ASSERT(tcp->tcp_rcv_cnt == 0);
	ASSERT(tcp->tcp_fuse_rcv_unread_cnt == 0);
	STR_WAKEUP_CLEAR(STREAM(q));

	mutex_exit(&tcp->tcp_non_sq_lock);
	dp->d_mp = mp;
	return (0);
}

/*
 * Synchronous stream entry point used by certain ioctls to retrieve
 * information about or peek into the tcp_rcv_list.
 */
int
tcp_fuse_rinfop(queue_t *q, infod_t *dp)
{
	tcp_t	*tcp = Q_TO_CONN(q)->conn_tcp;
	mblk_t	*mp;
	uint_t	cmd = dp->d_cmd;
	int	res = 0;
	int	error = 0;
	struct stdata *stp = STREAM(q);

	mutex_enter(&tcp->tcp_non_sq_lock);
	/* If shutdown on read has happened, return nothing */
	mutex_enter(&stp->sd_lock);
	if (stp->sd_flag & STREOF) {
		mutex_exit(&stp->sd_lock);
		goto done;
	}
	mutex_exit(&stp->sd_lock);

	/*
	 * It is OK not to return an answer if tcp_rcv_list is
	 * currently not accessible.
	 */
	if (!tcp->tcp_direct_sockfs || tcp->tcp_fuse_syncstr_stopped ||
	    tcp->tcp_fuse_syncstr_plugged || (mp = tcp->tcp_rcv_list) == NULL)
		goto done;

	if (cmd & INFOD_COUNT) {
		/*
		 * We have at least one message and
		 * could return only one at a time.
		 */
		dp->d_count++;
		res |= INFOD_COUNT;
	}
	if (cmd & INFOD_BYTES) {
		/*
		 * Return size of all data messages.
		 */
		dp->d_bytes += tcp->tcp_rcv_cnt;
		res |= INFOD_BYTES;
	}
	if (cmd & INFOD_FIRSTBYTES) {
		/*
		 * Return size of first data message.
		 */
		dp->d_bytes = msgdsize(mp);
		res |= INFOD_FIRSTBYTES;
		dp->d_cmd &= ~INFOD_FIRSTBYTES;
	}
	if (cmd & INFOD_COPYOUT) {
		mblk_t *mp1;
		int n;

		if (DB_TYPE(mp) == M_DATA) {
			mp1 = mp;
		} else {
			mp1 = mp->b_cont;
			ASSERT(mp1 != NULL);
		}

		/*
		 * Return data contents of first message.
		 */
		ASSERT(DB_TYPE(mp1) == M_DATA);
		while (mp1 != NULL && dp->d_uiop->uio_resid > 0) {
			n = MIN(dp->d_uiop->uio_resid, MBLKL(mp1));
			if (n != 0 && (error = uiomove((char *)mp1->b_rptr, n,
			    UIO_READ, dp->d_uiop)) != 0) {
				goto done;
			}
			mp1 = mp1->b_cont;
		}
		res |= INFOD_COPYOUT;
		dp->d_cmd &= ~INFOD_COPYOUT;
	}
done:
	mutex_exit(&tcp->tcp_non_sq_lock);

	dp->d_res |= res;

	return (error);
}

/*
 * Enable synchronous streams on a fused tcp loopback endpoint.
 */
static void
tcp_fuse_syncstr_enable(tcp_t *tcp)
{
	queue_t *rq = tcp->tcp_rq;
	struct stdata *stp = STREAM(rq);

	/* We can only enable synchronous streams for sockfs mode */
	tcp->tcp_direct_sockfs = tcp->tcp_issocket && do_tcp_direct_sockfs;

	if (!tcp->tcp_direct_sockfs)
		return;

	mutex_enter(&stp->sd_lock);
	mutex_enter(QLOCK(rq));

	/*
	 * We replace our q_qinfo with one that has the qi_rwp entry point.
	 * Clear SR_SIGALLDATA because we generate the equivalent signal(s)
	 * for every enqueued data in tcp_fuse_output().
	 */
	rq->q_qinfo = &tcp_loopback_rinit;
	rq->q_struiot = tcp_loopback_rinit.qi_struiot;
	stp->sd_struiordq = rq;
	stp->sd_rput_opt &= ~SR_SIGALLDATA;

	mutex_exit(QLOCK(rq));
	mutex_exit(&stp->sd_lock);
}

/*
 * Disable synchronous streams on a fused tcp loopback endpoint.
 */
static void
tcp_fuse_syncstr_disable(tcp_t *tcp)
{
	queue_t *rq = tcp->tcp_rq;
	struct stdata *stp = STREAM(rq);

	if (!tcp->tcp_direct_sockfs)
		return;

	mutex_enter(&stp->sd_lock);
	mutex_enter(QLOCK(rq));

	/*
	 * Reset q_qinfo to point to the default tcp entry points.
	 * Also restore SR_SIGALLDATA so that strrput() can generate
	 * the signals again for future M_DATA messages.
	 */
	rq->q_qinfo = &tcp_rinitv4;	/* No open - same as rinitv6 */
	rq->q_struiot = tcp_rinitv4.qi_struiot;
	stp->sd_struiordq = NULL;
	stp->sd_rput_opt |= SR_SIGALLDATA;
	tcp->tcp_direct_sockfs = B_FALSE;

	mutex_exit(QLOCK(rq));
	mutex_exit(&stp->sd_lock);
}

/*
 * Enable synchronous streams on a pair of fused tcp endpoints.
 */
void
tcp_fuse_syncstr_enable_pair(tcp_t *tcp)
{
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL);

	tcp_fuse_syncstr_enable(tcp);
	tcp_fuse_syncstr_enable(peer_tcp);
}

/*
 * Used to enable/disable signal generation at the stream head. We already
 * generated the signal(s) for these messages when they were enqueued on the
 * receiver. We also check if STREOF is set here. If it is, we return false
 * and let the caller decide what to do.
 */
static boolean_t
strrput_sig(queue_t *q, boolean_t on)
{
	struct stdata *stp = STREAM(q);

	mutex_enter(&stp->sd_lock);
	if (stp->sd_flag == STREOF) {
		mutex_exit(&stp->sd_lock);
		return (B_TRUE);
	}
	if (on)
		stp->sd_flag &= ~STRGETINPROG;
	else
		stp->sd_flag |= STRGETINPROG;
	mutex_exit(&stp->sd_lock);

	return (B_FALSE);
}

/*
 * Disable synchronous streams on a pair of fused tcp endpoints and drain
 * any queued data; called either during unfuse or upon transitioning from
 * a socket to a stream endpoint due to _SIOCSOCKFALLBACK.
 */
void
tcp_fuse_disable_pair(tcp_t *tcp, boolean_t unfusing)
{
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL);

	/*
	 * Force any tcp_fuse_rrw() calls to block until we've moved the data
	 * onto the stream head.
	 */
	TCP_FUSE_SYNCSTR_PLUG_DRAIN(tcp);
	TCP_FUSE_SYNCSTR_PLUG_DRAIN(peer_tcp);

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
	 * Drain any pending data; the detached check is needed because
	 * we may be called as a result of a tcp_unfuse() triggered by
	 * tcp_fuse_output().  Note that in case of a detached tcp, the
	 * draining will happen later after the tcp is unfused.  For non-
	 * urgent data, this can be handled by the regular tcp_rcv_drain().
	 * If we have urgent data sitting in the receive list, we will
	 * need to send up a SIGURG signal first before draining the data.
	 * All of these will be handled by the code in tcp_fuse_rcv_drain()
	 * when called from tcp_rcv_drain().
	 */
	if (!TCP_IS_DETACHED(tcp)) {
		(void) tcp_fuse_rcv_drain(tcp->tcp_rq, tcp,
		    (unfusing ? &tcp->tcp_fused_sigurg_mp : NULL));
	}
	if (!TCP_IS_DETACHED(peer_tcp)) {
		(void) tcp_fuse_rcv_drain(peer_tcp->tcp_rq, peer_tcp,
		    (unfusing ? &peer_tcp->tcp_fused_sigurg_mp : NULL));
	}

	/*
	 * Make all current and future tcp_fuse_rrw() calls fail with EBUSY.
	 * To ensure threads don't sneak past the checks in tcp_fuse_rrw(),
	 * a given stream must be stopped prior to being unplugged (but the
	 * ordering of operations between the streams is unimportant).
	 */
	TCP_FUSE_SYNCSTR_STOP(tcp);
	TCP_FUSE_SYNCSTR_STOP(peer_tcp);
	TCP_FUSE_SYNCSTR_UNPLUG_DRAIN(tcp);
	TCP_FUSE_SYNCSTR_UNPLUG_DRAIN(peer_tcp);

	/* Lift up any flow-control conditions */
	if (tcp->tcp_flow_stopped) {
		tcp_clrqfull(tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
	}
	if (peer_tcp->tcp_flow_stopped) {
		tcp_clrqfull(peer_tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
	}

	/* Disable synchronous streams */
	tcp_fuse_syncstr_disable(tcp);
	tcp_fuse_syncstr_disable(peer_tcp);
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
	tcp->tcp_fuse_rcv_hiwater = rwnd;
	return (rwnd);
}

/*
 * Calculate the maximum outstanding unread data block for a fused tcp endpoint.
 */
int
tcp_fuse_maxpsz_set(tcp_t *tcp)
{
	tcp_t *peer_tcp = tcp->tcp_loopback_peer;
	uint_t sndbuf = tcp->tcp_xmit_hiwater;
	uint_t maxpsz = sndbuf;

	ASSERT(tcp->tcp_fused);
	ASSERT(peer_tcp != NULL);
	ASSERT(peer_tcp->tcp_fuse_rcv_hiwater != 0);
	/*
	 * In the fused loopback case, we want the stream head to split
	 * up larger writes into smaller chunks for a more accurate flow-
	 * control accounting.  Our maxpsz is half of the sender's send
	 * buffer or the receiver's receive buffer, whichever is smaller.
	 * We round up the buffer to system page size due to the lack of
	 * TCP MSS concept in Fusion.
	 */
	if (maxpsz > peer_tcp->tcp_fuse_rcv_hiwater)
		maxpsz = peer_tcp->tcp_fuse_rcv_hiwater;
	maxpsz = P2ROUNDUP_TYPED(maxpsz, PAGESIZE, uint_t) >> 1;

	/*
	 * Calculate the peer's limit for the number of outstanding unread
	 * data block.  This is the amount of data blocks that are allowed
	 * to reside in the receiver's queue before the sender gets flow
	 * controlled.  It is used only in the synchronous streams mode as
	 * a way to throttle the sender when it performs consecutive writes
	 * faster than can be read.  The value is derived from SO_SNDBUF in
	 * order to give the sender some control; we divide it with a large
	 * value (16KB) to produce a fairly low initial limit.
	 */
	if (tcp_fusion_rcv_unread_min == 0) {
		/* A value of 0 means that we disable the check */
		peer_tcp->tcp_fuse_rcv_unread_hiwater = 0;
	} else {
		peer_tcp->tcp_fuse_rcv_unread_hiwater =
		    MAX(sndbuf >> 14, tcp_fusion_rcv_unread_min);
	}
	return (maxpsz);
}

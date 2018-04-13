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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/tsol/tndb.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ipclassifier.h>
#include <inet/ipsec_impl.h>

#include "sctp_impl.h"
#include "sctp_addr.h"

/*
 * Common accept code.  Called by sctp_conn_request.
 * cr_pkt is the INIT / INIT ACK packet.
 */
static int
sctp_accept_comm(sctp_t *listener, sctp_t *acceptor, mblk_t *cr_pkt,
    uint_t ip_hdr_len, sctp_init_chunk_t *iack)
{

	sctp_hdr_t		*sctph;
	sctp_chunk_hdr_t	*ich;
	sctp_init_chunk_t	*init;
	int			err;
	uint_t			sctp_options;
	conn_t			*aconnp;
	conn_t			*lconnp;
	sctp_stack_t		*sctps = listener->sctp_sctps;

	sctph = (sctp_hdr_t *)(cr_pkt->b_rptr + ip_hdr_len);
	ASSERT(OK_32PTR(sctph));

	aconnp = acceptor->sctp_connp;
	lconnp = listener->sctp_connp;
	aconnp->conn_lport = lconnp->conn_lport;
	aconnp->conn_fport = sctph->sh_sport;

	ich = (sctp_chunk_hdr_t *)(iack + 1);
	init = (sctp_init_chunk_t *)(ich + 1);

	/* acceptor isn't in any fanouts yet, so don't need to hold locks */
	ASSERT(acceptor->sctp_faddrs == NULL);
	err = sctp_get_addrparams(acceptor, listener, cr_pkt, ich,
	    &sctp_options);
	if (err != 0)
		return (err);

	if ((err = sctp_set_hdraddrs(acceptor)) != 0)
		return (err);

	if ((err = sctp_build_hdrs(acceptor, KM_NOSLEEP)) != 0)
		return (err);

	if ((sctp_options & SCTP_PRSCTP_OPTION) &&
	    listener->sctp_prsctp_aware && sctps->sctps_prsctp_enabled) {
		acceptor->sctp_prsctp_aware = B_TRUE;
	} else {
		acceptor->sctp_prsctp_aware = B_FALSE;
	}

	/* Get  initial TSNs */
	acceptor->sctp_ltsn = ntohl(iack->sic_inittsn);
	acceptor->sctp_recovery_tsn = acceptor->sctp_lastack_rxd =
	    acceptor->sctp_ltsn - 1;
	acceptor->sctp_adv_pap = acceptor->sctp_lastack_rxd;
	/* Serial numbers are initialized to the same value as the TSNs */
	acceptor->sctp_lcsn = acceptor->sctp_ltsn;

	if (!sctp_initialize_params(acceptor, init, iack))
		return (ENOMEM);

	/*
	 * Copy sctp_secret from the listener in case we need to validate
	 * a possibly delayed cookie.
	 */
	bcopy(listener->sctp_secret, acceptor->sctp_secret, SCTP_SECRET_LEN);
	bcopy(listener->sctp_old_secret, acceptor->sctp_old_secret,
	    SCTP_SECRET_LEN);
	acceptor->sctp_last_secret_update = ddi_get_lbolt64();

	/*
	 * After acceptor is inserted in the hash list, it can be found.
	 * So we need to lock it here.
	 */
	RUN_SCTP(acceptor);

	sctp_conn_hash_insert(&sctps->sctps_conn_fanout[
	    SCTP_CONN_HASH(sctps, aconnp->conn_ports)], acceptor, 0);
	sctp_bind_hash_insert(&sctps->sctps_bind_fanout[
	    SCTP_BIND_HASH(ntohs(aconnp->conn_lport))], acceptor, 0);

	SCTP_ASSOC_EST(sctps, acceptor);
	return (0);
}

/* Process the COOKIE packet, mp, directed at the listener 'sctp' */
sctp_t *
sctp_conn_request(sctp_t *sctp, mblk_t *mp, uint_t ifindex, uint_t ip_hdr_len,
    sctp_init_chunk_t *iack, ip_recv_attr_t *ira)
{
	sctp_t	*eager;
	ip6_t	*ip6h;
	int	err;
	conn_t	*connp, *econnp;
	sctp_stack_t	*sctps;
	cred_t		*cr;
	pid_t		cpid;
	in6_addr_t	faddr, laddr;
	ip_xmit_attr_t	*ixa;
	sctp_listen_cnt_t *slc = sctp->sctp_listen_cnt;
	boolean_t	slc_set = B_FALSE;

	/*
	 * No need to check for duplicate as this is the listener
	 * and we are holding the lock.  This means that no new
	 * connection can be created out of it.  And since the
	 * fanout already done cannot find a match, it means that
	 * there is no duplicate.
	 */
	ASSERT(OK_32PTR(mp->b_rptr));

	connp = sctp->sctp_connp;
	sctps = sctp->sctp_sctps;

	/*
	 * Enforce the limit set on the number of connections per listener.
	 * Note that tlc_cnt starts with 1.  So need to add 1 to tlc_max
	 * for comparison.
	 */
	if (slc != NULL) {
		int64_t now;

		if (atomic_inc_32_nv(&slc->slc_cnt) > slc->slc_max + 1) {
			now = ddi_get_lbolt64();
			atomic_dec_32(&slc->slc_cnt);
			SCTP_KSTAT(sctps, sctp_listen_cnt_drop);
			slc->slc_drop++;
			if (now - slc->slc_report_time >
			    MSEC_TO_TICK(SCTP_SLC_REPORT_INTERVAL)) {
				zcmn_err(connp->conn_zoneid, CE_WARN,
				    "SCTP listener (port %d) association max "
				    "(%u) reached: %u attempts dropped total\n",
				    ntohs(connp->conn_lport),
				    slc->slc_max, slc->slc_drop);
				slc->slc_report_time = now;
			}
			return (NULL);
		}
		slc_set = B_TRUE;
	}

	if ((eager = sctp_create_eager(sctp)) == NULL) {
		if (slc_set)
			atomic_dec_32(&slc->slc_cnt);
		return (NULL);
	}
	econnp = eager->sctp_connp;

	if (connp->conn_policy != NULL) {
		/* Inherit the policy from the listener; use actions from ira */
		if (!ip_ipsec_policy_inherit(econnp, connp, ira)) {
			sctp_close_eager(eager);
			SCTPS_BUMP_MIB(sctps, sctpListenDrop);
			return (NULL);
		}
	}

	ip6h = (ip6_t *)mp->b_rptr;
	if (ira->ira_flags & IXAF_IS_IPV4) {
		ipha_t	*ipha;

		ipha = (ipha_t *)ip6h;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &laddr);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &faddr);
	} else {
		laddr = ip6h->ip6_dst;
		faddr = ip6h->ip6_src;
	}

	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		/*
		 * XXX need to fix the cached policy issue here.
		 * We temporarily set the conn_laddr/conn_faddr here so
		 * that IPsec can use it for the latched policy
		 * selector.  This is obvioursly wrong as SCTP can
		 * use different addresses...
		 */
		econnp->conn_laddr_v6 = laddr;
		econnp->conn_faddr_v6 = faddr;
		econnp->conn_saddr_v6 = laddr;
	}
	if (ipsec_conn_cache_policy(econnp,
	    (ira->ira_flags & IRAF_IS_IPV4) != 0) != 0) {
		sctp_close_eager(eager);
		SCTPS_BUMP_MIB(sctps, sctpListenDrop);
		return (NULL);
	}

	/* Save for getpeerucred */
	cr = ira->ira_cred;
	cpid = ira->ira_cpid;

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

		if ((connp->conn_mlp_type != mlptSingle ||
		    connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
		    ira->ira_tsl != NULL) {
			/*
			 * If this is an MLP connection or a MAC-Exempt
			 * connection with an unlabeled node, packets are to be
			 * exchanged using the security label of the received
			 * Cookie packet instead of the server application's
			 * label.
			 * tsol_check_dest called from ip_set_destination
			 * might later update TSF_UNLABELED by replacing
			 * ixa_tsl with a new label.
			 */
			label_hold(ira->ira_tsl);
			ip_xmit_attr_replace_tsl(ixa, ira->ira_tsl);
		} else {
			ixa->ixa_tsl = crgetlabel(econnp->conn_cred);
		}
	}

	err = sctp_accept_comm(sctp, eager, mp, ip_hdr_len, iack);
	if (err != 0) {
		sctp_close_eager(eager);
		SCTPS_BUMP_MIB(sctps, sctpListenDrop);
		return (NULL);
	}

	ASSERT(eager->sctp_current->sf_ixa != NULL);

	ixa = eager->sctp_current->sf_ixa;
	if (!(ira->ira_flags & IXAF_IS_IPV4)) {
		ASSERT(!(ixa->ixa_flags & IXAF_IS_IPV4));

		if (IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src) ||
		    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst)) {
			eager->sctp_linklocal = 1;

			ixa->ixa_flags |= IXAF_SCOPEID_SET;
			ixa->ixa_scopeid = ifindex;
			econnp->conn_incoming_ifindex = ifindex;
		}
	}

	/*
	 * On a clustered note send this notification to the clustering
	 * subsystem.
	 */
	if (cl_sctp_connect != NULL) {
		uchar_t	*slist;
		uchar_t	*flist;
		size_t	fsize;
		size_t	ssize;

		fsize = sizeof (in6_addr_t) * eager->sctp_nfaddrs;
		ssize = sizeof (in6_addr_t) * eager->sctp_nsaddrs;
		slist = kmem_alloc(ssize, KM_NOSLEEP);
		flist = kmem_alloc(fsize, KM_NOSLEEP);
		if (slist == NULL || flist == NULL) {
			if (slist != NULL)
				kmem_free(slist, ssize);
			if (flist != NULL)
				kmem_free(flist, fsize);
			sctp_close_eager(eager);
			SCTPS_BUMP_MIB(sctps, sctpListenDrop);
			SCTP_KSTAT(sctps, sctp_cl_connect);
			return (NULL);
		}
		/* The clustering module frees these list */
		sctp_get_saddr_list(eager, slist, ssize);
		sctp_get_faddr_list(eager, flist, fsize);
		(*cl_sctp_connect)(econnp->conn_family, slist,
		    eager->sctp_nsaddrs, econnp->conn_lport, flist,
		    eager->sctp_nfaddrs, econnp->conn_fport, B_FALSE,
		    (cl_sctp_handle_t)eager);
	}

	/* Connection established, so send up the conn_ind */
	if ((eager->sctp_ulpd = sctp->sctp_ulp_newconn(sctp->sctp_ulpd,
	    (sock_lower_handle_t)eager, NULL, cr, cpid,
	    &eager->sctp_upcalls)) == NULL) {
		sctp_close_eager(eager);
		SCTPS_BUMP_MIB(sctps, sctpListenDrop);
		return (NULL);
	}
	ASSERT(SCTP_IS_DETACHED(eager));
	eager->sctp_detached = B_FALSE;
	return (eager);
}

/*
 * Connect to a peer - this function inserts the sctp in the
 * bind and conn fanouts, sends the INIT, and replies to the client
 * with an OK ack.
 */
int
sctp_connect(sctp_t *sctp, const struct sockaddr *dst, uint32_t addrlen,
    cred_t *cr, pid_t pid)
{
	sin_t		*sin;
	sin6_t		*sin6;
	in6_addr_t	dstaddr;
	in_port_t	dstport;
	mblk_t		*initmp;
	sctp_tf_t	*tbf;
	sctp_t		*lsctp;
	char		buf[INET6_ADDRSTRLEN];
	int		sleep = sctp->sctp_cansleep ? KM_SLEEP : KM_NOSLEEP;
	int		err;
	sctp_faddr_t	*cur_fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	conn_t		*connp = sctp->sctp_connp;
	uint_t		scope_id = 0;
	ip_xmit_attr_t	*ixa;

	/*
	 * Determine packet type based on type of address passed in
	 * the request should contain an IPv4 or IPv6 address.
	 * Make sure that address family matches the type of
	 * family of the address passed down.
	 */
	if (addrlen < sizeof (sin_t)) {
		return (EINVAL);
	}
	switch (dst->sa_family) {
	case AF_INET:
		sin = (sin_t *)dst;

		/* Check for attempt to connect to non-unicast */
		if (CLASSD(sin->sin_addr.s_addr) ||
		    (sin->sin_addr.s_addr == INADDR_BROADCAST)) {
			ip0dbg(("sctp_connect: non-unicast\n"));
			return (EINVAL);
		}
		if (connp->conn_ipv6_v6only)
			return (EAFNOSUPPORT);

		/* convert to v6 mapped */
		/* Check for attempt to connect to INADDR_ANY */
		if (sin->sin_addr.s_addr == INADDR_ANY)  {
			struct in_addr v4_addr;
			/*
			 * SunOS 4.x and 4.3 BSD allow an application
			 * to connect a TCP socket to INADDR_ANY.
			 * When they do this, the kernel picks the
			 * address of one interface and uses it
			 * instead.  The kernel usually ends up
			 * picking the address of the loopback
			 * interface.  This is an undocumented feature.
			 * However, we provide the same thing here
			 * in case any TCP apps that use this feature
			 * are being ported to SCTP...
			 */
			v4_addr.s_addr = htonl(INADDR_LOOPBACK);
			IN6_INADDR_TO_V4MAPPED(&v4_addr, &dstaddr);
		} else {
			IN6_INADDR_TO_V4MAPPED(&sin->sin_addr, &dstaddr);
		}
		dstport = sin->sin_port;
		break;
	case AF_INET6:
		sin6 = (sin6_t *)dst;
		/* Check for attempt to connect to non-unicast. */
		if ((addrlen < sizeof (sin6_t)) ||
		    IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
			ip0dbg(("sctp_connect: non-unicast\n"));
			return (EINVAL);
		}
		if (connp->conn_ipv6_v6only &&
		    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			return (EAFNOSUPPORT);
		}
		/* check for attempt to connect to unspec */
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			dstaddr = ipv6_loopback;
		} else {
			dstaddr = sin6->sin6_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&dstaddr)) {
				sctp->sctp_linklocal = 1;
				scope_id = sin6->sin6_scope_id;
			}
		}
		dstport = sin6->sin6_port;
		connp->conn_flowinfo = sin6->sin6_flowinfo;
		break;
	default:
		dprint(1, ("sctp_connect: unknown family %d\n",
		    dst->sa_family));
		return (EAFNOSUPPORT);
	}

	(void) inet_ntop(AF_INET6, &dstaddr, buf, sizeof (buf));
	dprint(1, ("sctp_connect: attempting connect to %s...\n", buf));

	RUN_SCTP(sctp);

	if (connp->conn_family != dst->sa_family ||
	    (connp->conn_state_flags & CONN_CLOSING)) {
		WAKE_SCTP(sctp);
		return (EINVAL);
	}

	/* We update our cred/cpid based on the caller of connect */
	if (connp->conn_cred != cr) {
		crhold(cr);
		crfree(connp->conn_cred);
		connp->conn_cred = cr;
	}
	connp->conn_cpid = pid;

	/* Cache things in conn_ixa without any refhold */
	ixa = connp->conn_ixa;
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;
	if (is_system_labeled()) {
		/* We need to restart with a label based on the cred */
		ip_xmit_attr_restore_tsl(ixa, ixa->ixa_cred);
	}

	switch (sctp->sctp_state) {
	case SCTPS_IDLE: {
		struct sockaddr_storage	ss;

		/*
		 * We support a quick connect capability here, allowing
		 * clients to transition directly from IDLE to COOKIE_WAIT.
		 * sctp_bindi will pick an unused port, insert the connection
		 * in the bind hash and transition to BOUND state. SCTP
		 * picks and uses what it considers the optimal local address
		 * set (just like specifiying INADDR_ANY to bind()).
		 */
		dprint(1, ("sctp_connect: idle, attempting bind...\n"));
		ASSERT(sctp->sctp_nsaddrs == 0);

		bzero(&ss, sizeof (ss));
		ss.ss_family = connp->conn_family;
		WAKE_SCTP(sctp);
		if ((err = sctp_bind(sctp, (struct sockaddr *)&ss,
		    sizeof (ss))) != 0) {
			return (err);
		}
		RUN_SCTP(sctp);
	}
	/* FALLTHROUGH */

	case SCTPS_BOUND:
		ASSERT(sctp->sctp_nsaddrs > 0);

		/* do the connect */
		/* XXX check for attempt to connect to self */
		connp->conn_fport = dstport;

		/*
		 * Don't allow this connection to completely duplicate
		 * an existing connection.
		 *
		 * Ensure that the duplicate check and insertion is atomic.
		 */
		sctp_conn_hash_remove(sctp);
		tbf = &sctps->sctps_conn_fanout[SCTP_CONN_HASH(sctps,
		    connp->conn_ports)];
		mutex_enter(&tbf->tf_lock);
		lsctp = sctp_lookup(sctp, &dstaddr, tbf, &connp->conn_ports,
		    SCTPS_COOKIE_WAIT);
		if (lsctp != NULL) {
			/* found a duplicate connection */
			mutex_exit(&tbf->tf_lock);
			SCTP_REFRELE(lsctp);
			WAKE_SCTP(sctp);
			return (EADDRINUSE);
		}

		/*
		 * OK; set up the peer addr (this may grow after we get
		 * the INIT ACK from the peer with additional addresses).
		 */
		if ((err = sctp_add_faddr(sctp, &dstaddr, sleep,
		    B_FALSE)) != 0) {
			mutex_exit(&tbf->tf_lock);
			WAKE_SCTP(sctp);
			return (err);
		}
		cur_fp = sctp->sctp_faddrs;
		ASSERT(cur_fp->sf_ixa != NULL);

		/* No valid src addr, return. */
		if (cur_fp->sf_state == SCTP_FADDRS_UNREACH) {
			mutex_exit(&tbf->tf_lock);
			WAKE_SCTP(sctp);
			return (EADDRNOTAVAIL);
		}

		sctp->sctp_primary = cur_fp;
		sctp->sctp_current = cur_fp;
		sctp->sctp_mss = cur_fp->sf_pmss;
		sctp_conn_hash_insert(tbf, sctp, 1);
		mutex_exit(&tbf->tf_lock);

		ixa = cur_fp->sf_ixa;
		ASSERT(ixa->ixa_cred != NULL);

		if (scope_id != 0) {
			ixa->ixa_flags |= IXAF_SCOPEID_SET;
			ixa->ixa_scopeid = scope_id;
		} else {
			ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		}

		/* initialize composite headers */
		if ((err = sctp_set_hdraddrs(sctp)) != 0) {
			sctp_conn_hash_remove(sctp);
			WAKE_SCTP(sctp);
			return (err);
		}

		if ((err = sctp_build_hdrs(sctp, KM_SLEEP)) != 0) {
			sctp_conn_hash_remove(sctp);
			WAKE_SCTP(sctp);
			return (err);
		}

		/*
		 * Turn off the don't fragment bit on the (only) faddr,
		 * so that if one of the messages exchanged during the
		 * initialization sequence exceeds the path mtu, it
		 * at least has a chance to get there. SCTP does no
		 * fragmentation of initialization messages.  The DF bit
		 * will be turned on again in sctp_send_cookie_echo()
		 * (but the cookie echo will still be sent with the df bit
		 * off).
		 */
		cur_fp->sf_df = B_FALSE;

		/* Mark this address as alive */
		cur_fp->sf_state = SCTP_FADDRS_ALIVE;

		/* Send the INIT to the peer */
		SCTP_FADDR_TIMER_RESTART(sctp, cur_fp, cur_fp->sf_rto);
		sctp->sctp_state = SCTPS_COOKIE_WAIT;
		/*
		 * sctp_init_mp() could result in modifying the source
		 * address list, so take the hash lock.
		 */
		mutex_enter(&tbf->tf_lock);
		initmp = sctp_init_mp(sctp, cur_fp);
		if (initmp == NULL) {
			mutex_exit(&tbf->tf_lock);
			/*
			 * It may happen that all the source addresses
			 * (loopback/link local) are removed.  In that case,
			 * faile the connect.
			 */
			if (sctp->sctp_nsaddrs == 0) {
				sctp_conn_hash_remove(sctp);
				SCTP_FADDR_TIMER_STOP(cur_fp);
				WAKE_SCTP(sctp);
				return (EADDRNOTAVAIL);
			}

			/* Otherwise, let the retransmission timer retry */
			WAKE_SCTP(sctp);
			goto notify_ulp;
		}
		mutex_exit(&tbf->tf_lock);

		/*
		 * On a clustered note send this notification to the clustering
		 * subsystem.
		 */
		if (cl_sctp_connect != NULL) {
			uchar_t		*slist;
			uchar_t		*flist;
			size_t		ssize;
			size_t		fsize;

			fsize = sizeof (in6_addr_t) * sctp->sctp_nfaddrs;
			ssize = sizeof (in6_addr_t) * sctp->sctp_nsaddrs;
			slist = kmem_alloc(ssize, KM_SLEEP);
			flist = kmem_alloc(fsize, KM_SLEEP);
			/* The clustering module frees the lists */
			sctp_get_saddr_list(sctp, slist, ssize);
			sctp_get_faddr_list(sctp, flist, fsize);
			(*cl_sctp_connect)(connp->conn_family, slist,
			    sctp->sctp_nsaddrs, connp->conn_lport,
			    flist, sctp->sctp_nfaddrs, connp->conn_fport,
			    B_TRUE, (cl_sctp_handle_t)sctp);
		}
		ASSERT(ixa->ixa_cred != NULL);
		ASSERT(ixa->ixa_ire != NULL);

		(void) conn_ip_output(initmp, ixa);
		BUMP_LOCAL(sctp->sctp_opkts);
		WAKE_SCTP(sctp);

notify_ulp:
		sctp_set_ulp_prop(sctp);

		return (0);
	default:
		ip0dbg(("sctp_connect: invalid state. %d\n", sctp->sctp_state));
		WAKE_SCTP(sctp);
		return (EINVAL);
	}
}

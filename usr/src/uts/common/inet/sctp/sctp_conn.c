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
	cred_t			*cr;
	sctp_stack_t	*sctps = listener->sctp_sctps;

	sctph = (sctp_hdr_t *)(cr_pkt->b_rptr + ip_hdr_len);
	ASSERT(OK_32PTR(sctph));

	acceptor->sctp_lport = listener->sctp_lport;
	acceptor->sctp_fport = sctph->sh_sport;

	ich = (sctp_chunk_hdr_t *)(iack + 1);
	init = (sctp_init_chunk_t *)(ich + 1);

	/* acceptor isn't in any fanouts yet, so don't need to hold locks */
	ASSERT(acceptor->sctp_faddrs == NULL);
	err = sctp_get_addrparams(acceptor, listener, cr_pkt, ich,
	    &sctp_options);
	if (err != 0)
		return (err);

	aconnp = acceptor->sctp_connp;
	lconnp = listener->sctp_connp;
	if (lconnp->conn_mlp_type != mlptSingle) {
		cr = aconnp->conn_peercred = DB_CRED(cr_pkt);
		if (cr != NULL)
			crhold(cr);
	}

	if ((err = sctp_set_hdraddrs(acceptor)) != 0)
		return (err);

	if ((sctp_options & SCTP_PRSCTP_OPTION) &&
	    listener->sctp_prsctp_aware && sctps->sctps_prsctp_enabled) {
		acceptor->sctp_prsctp_aware = B_TRUE;
	} else {
		acceptor->sctp_prsctp_aware = B_FALSE;
	}
	/* The new sctp_t is fully bound now. */
	acceptor->sctp_connp->conn_fully_bound = B_TRUE;

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
	acceptor->sctp_last_secret_update = lbolt64;

	/*
	 * After acceptor is inserted in the hash list, it can be found.
	 * So we need to lock it here.
	 */
	RUN_SCTP(acceptor);

	sctp_conn_hash_insert(&sctps->sctps_conn_fanout[
	    SCTP_CONN_HASH(sctps, acceptor->sctp_ports)], acceptor, 0);
	sctp_bind_hash_insert(&sctps->sctps_bind_fanout[
	    SCTP_BIND_HASH(ntohs(acceptor->sctp_lport))], acceptor, 0);

	/*
	 * No need to check for multicast destination since ip will only pass
	 * up multicasts to those that have expressed interest
	 * TODO: what about rejecting broadcasts?
	 * Also check that source is not a multicast or broadcast address.
	 */
	/* XXXSCTP */
	acceptor->sctp_state = SCTPS_ESTABLISHED;
	acceptor->sctp_assoc_start_time = (uint32_t)lbolt;
	/*
	 * listener->sctp_rwnd should be the default window size or a
	 * window size changed via SO_RCVBUF option.
	 */
	acceptor->sctp_rwnd = listener->sctp_rwnd;
	acceptor->sctp_irwnd = acceptor->sctp_rwnd;
	acceptor->sctp_pd_point = acceptor->sctp_rwnd;
	acceptor->sctp_upcalls = listener->sctp_upcalls;
#if 0
	bcopy(&listener->sctp_upcalls, &acceptor->sctp_upcalls,
	    sizeof (sctp_upcalls_t));
#endif

	return (0);
}

/* Process the COOKIE packet, mp, directed at the listener 'sctp' */
sctp_t *
sctp_conn_request(sctp_t *sctp, mblk_t *mp, uint_t ifindex, uint_t ip_hdr_len,
    sctp_init_chunk_t *iack, mblk_t *ipsec_mp)
{
	sctp_t	*eager;
	uint_t	ipvers;
	ip6_t	*ip6h;
	int	err;
	conn_t	*connp, *econnp;
	sctp_stack_t	*sctps;
	struct sock_proto_props sopp;

	/*
	 * No need to check for duplicate as this is the listener
	 * and we are holding the lock.  This means that no new
	 * connection can be created out of it.  And since the
	 * fanout already done cannot find a match, it means that
	 * there is no duplicate.
	 */
	ipvers = IPH_HDR_VERSION(mp->b_rptr);
	ASSERT(ipvers == IPV6_VERSION || ipvers == IPV4_VERSION);
	ASSERT(OK_32PTR(mp->b_rptr));

	if ((eager = sctp_create_eager(sctp)) == NULL) {
		return (NULL);
	}

	if (ipvers != IPV4_VERSION) {
		ip6h = (ip6_t *)mp->b_rptr;
		if (IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src))
			eager->sctp_linklocal = 1;
		/*
		 * Record ifindex (might be zero) to tie this connection to
		 * that interface if either the listener was bound or
		 * if the connection is using link-local addresses.
		 */
		if (sctp->sctp_bound_if == ifindex ||
		    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src))
			eager->sctp_bound_if = ifindex;
		/*
		 * XXX broken. bound_if is always overwritten by statement
		 * below. What is the right thing to do here?
		 */
		eager->sctp_bound_if = sctp->sctp_bound_if;
	}

	connp = sctp->sctp_connp;
	sctps = sctp->sctp_sctps;
	econnp = eager->sctp_connp;

	if (connp->conn_policy != NULL) {
		ipsec_in_t *ii;

		ASSERT(ipsec_mp != NULL);
		ii = (ipsec_in_t *)(ipsec_mp->b_rptr);
		ASSERT(ii->ipsec_in_policy == NULL);
		IPPH_REFHOLD(connp->conn_policy);
		ii->ipsec_in_policy = connp->conn_policy;

		ipsec_mp->b_datap->db_type = IPSEC_POLICY_SET;
		if (!ip_bind_ipsec_policy_set(econnp, ipsec_mp)) {
			sctp_close_eager(eager);
			BUMP_MIB(&sctps->sctps_mib, sctpListenDrop);
			return (NULL);
		}
	}

	if (ipsec_mp != NULL) {
		/*
		 * XXX need to fix the cached policy issue here.
		 * We temporarily set the conn_src/conn_rem here so
		 * that IPsec can use it for the latched policy
		 * selector.  This is obvioursly wrong as SCTP can
		 * use different addresses...
		 */
		if (ipvers == IPV4_VERSION) {
			ipha_t	*ipha;

			ipha = (ipha_t *)mp->b_rptr;
			econnp->conn_src = ipha->ipha_dst;
			econnp->conn_rem = ipha->ipha_src;
		} else {
			econnp->conn_srcv6 = ip6h->ip6_dst;
			econnp->conn_remv6 = ip6h->ip6_src;
		}
	}
	if (ipsec_conn_cache_policy(econnp, ipvers == IPV4_VERSION) != 0) {
		sctp_close_eager(eager);
		BUMP_MIB(&sctps->sctps_mib, sctpListenDrop);
		return (NULL);
	}

	err = sctp_accept_comm(sctp, eager, mp, ip_hdr_len, iack);
	if (err) {
		sctp_close_eager(eager);
		BUMP_MIB(&sctps->sctps_mib, sctpListenDrop);
		return (NULL);
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
			BUMP_MIB(&sctps->sctps_mib, sctpListenDrop);
			SCTP_KSTAT(sctps, sctp_cl_connect);
			return (NULL);
		}
		/* The clustering module frees these list */
		sctp_get_saddr_list(eager, slist, ssize);
		sctp_get_faddr_list(eager, flist, fsize);
		(*cl_sctp_connect)(eager->sctp_family, slist,
		    eager->sctp_nsaddrs, eager->sctp_lport, flist,
		    eager->sctp_nfaddrs, eager->sctp_fport, B_FALSE,
		    (cl_sctp_handle_t)eager);
	}

	/* Connection established, so send up the conn_ind */
	if ((eager->sctp_ulpd = sctp->sctp_ulp_newconn(sctp->sctp_ulpd,
	    (sock_lower_handle_t)eager, NULL, NULL, 0,
	    &eager->sctp_upcalls)) == NULL) {
		sctp_close_eager(eager);
		BUMP_MIB(&sctps->sctps_mib, sctpListenDrop);
		return (NULL);
	}
	ASSERT(SCTP_IS_DETACHED(eager));
	eager->sctp_detached = B_FALSE;
	bzero(&sopp, sizeof (sopp));
	sopp.sopp_flags = SOCKOPT_MAXBLK|SOCKOPT_WROFF;
	sopp.sopp_maxblk = strmsgsz;
	if (eager->sctp_family == AF_INET) {
		sopp.sopp_wroff = sctps->sctps_wroff_xtra +
		    sizeof (sctp_data_hdr_t) + sctp->sctp_hdr_len;
	} else {
		sopp.sopp_wroff = sctps->sctps_wroff_xtra +
		    sizeof (sctp_data_hdr_t) + sctp->sctp_hdr6_len;
	}
	eager->sctp_ulp_prop(eager->sctp_ulpd, &sopp);
	return (eager);
}

/*
 * Connect to a peer - this function inserts the sctp in the
 * bind and conn fanouts, sends the INIT, and replies to the client
 * with an OK ack.
 */
int
sctp_connect(sctp_t *sctp, const struct sockaddr *dst, uint32_t addrlen)
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
	int 		hdrlen;
	ip6_rthdr_t	*rth;
	int		err;
	sctp_faddr_t	*cur_fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	struct sock_proto_props sopp;

	/*
	 * Determine packet type based on type of address passed in
	 * the request should contain an IPv4 or IPv6 address.
	 * Make sure that address family matches the type of
	 * family of the the address passed down
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
		if (sctp->sctp_connp->conn_ipv6_v6only)
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
		if (sin->sin_family == AF_INET) {
			hdrlen = sctp->sctp_hdr_len;
		} else {
			hdrlen = sctp->sctp_hdr6_len;
		}
		break;
	case AF_INET6:
		sin6 = (sin6_t *)dst;
		/* Check for attempt to connect to non-unicast. */
		if ((addrlen < sizeof (sin6_t)) ||
		    IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
			ip0dbg(("sctp_connect: non-unicast\n"));
			return (EINVAL);
		}
		if (sctp->sctp_connp->conn_ipv6_v6only &&
		    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			return (EAFNOSUPPORT);
		}
		/* check for attempt to connect to unspec */
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			dstaddr = ipv6_loopback;
		} else {
			dstaddr = sin6->sin6_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&dstaddr))
				sctp->sctp_linklocal = 1;
		}
		dstport = sin6->sin6_port;
		hdrlen = sctp->sctp_hdr6_len;
		break;
	default:
		dprint(1, ("sctp_connect: unknown family %d\n",
		    dst->sa_family));
		return (EAFNOSUPPORT);
	}

	(void) inet_ntop(AF_INET6, &dstaddr, buf, sizeof (buf));
	dprint(1, ("sctp_connect: attempting connect to %s...\n", buf));

	RUN_SCTP(sctp);

	if (sctp->sctp_family != dst->sa_family ||
	    (sctp->sctp_connp->conn_state_flags & CONN_CLOSING)) {
		WAKE_SCTP(sctp);
		return (EINVAL);
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
		ss.ss_family = sctp->sctp_family;
		WAKE_SCTP(sctp);
		if ((err = sctp_bind(sctp, (struct sockaddr *)&ss,
		    sizeof (ss))) != 0) {
			return (err);
		}
		RUN_SCTP(sctp);
		/* FALLTHRU */
	}

	case SCTPS_BOUND:
		ASSERT(sctp->sctp_nsaddrs > 0);

		/* do the connect */
		/* XXX check for attempt to connect to self */
		sctp->sctp_fport = dstport;

		ASSERT(sctp->sctp_iphc);
		ASSERT(sctp->sctp_iphc6);

		/*
		 * Don't allow this connection to completely duplicate
		 * an existing connection.
		 *
		 * Ensure that the duplicate check and insertion is atomic.
		 */
		sctp_conn_hash_remove(sctp);
		tbf = &sctps->sctps_conn_fanout[SCTP_CONN_HASH(sctps,
		    sctp->sctp_ports)];
		mutex_enter(&tbf->tf_lock);
		lsctp = sctp_lookup(sctp, &dstaddr, tbf, &sctp->sctp_ports,
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

		/* No valid src addr, return. */
		if (cur_fp->state == SCTP_FADDRS_UNREACH) {
			mutex_exit(&tbf->tf_lock);
			WAKE_SCTP(sctp);
			return (EADDRNOTAVAIL);
		}

		sctp->sctp_primary = cur_fp;
		sctp->sctp_current = cur_fp;
		sctp->sctp_mss = cur_fp->sfa_pmss;
		sctp_conn_hash_insert(tbf, sctp, 1);
		mutex_exit(&tbf->tf_lock);

		/* initialize composite headers */
		if ((err = sctp_set_hdraddrs(sctp)) != 0) {
			sctp_conn_hash_remove(sctp);
			WAKE_SCTP(sctp);
			return (err);
		}

		/*
		 * Massage a routing header (if present) putting the first hop
		 * in ip6_dst.
		 */
		rth = ip_find_rthdr_v6(sctp->sctp_ip6h,
		    (uint8_t *)sctp->sctp_sctph6);
		if (rth != NULL) {
			(void) ip_massage_options_v6(sctp->sctp_ip6h, rth,
			    sctps->sctps_netstack);
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
		cur_fp->df = B_FALSE;

		/* Mark this address as alive */
		cur_fp->state = SCTP_FADDRS_ALIVE;

		/* This sctp_t is fully bound now. */
		sctp->sctp_connp->conn_fully_bound = B_TRUE;

		/* Send the INIT to the peer */
		SCTP_FADDR_TIMER_RESTART(sctp, cur_fp, cur_fp->rto);
		sctp->sctp_state = SCTPS_COOKIE_WAIT;
		/*
		 * sctp_init_mp() could result in modifying the source
		 * address list, so take the hash lock.
		 */
		mutex_enter(&tbf->tf_lock);
		initmp = sctp_init_mp(sctp);
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
			(*cl_sctp_connect)(sctp->sctp_family, slist,
			    sctp->sctp_nsaddrs, sctp->sctp_lport,
			    flist, sctp->sctp_nfaddrs, sctp->sctp_fport,
			    B_TRUE, (cl_sctp_handle_t)sctp);
		}
		WAKE_SCTP(sctp);
		/* OK to call IP_PUT() here instead of sctp_add_sendq(). */
		CONN_INC_REF(sctp->sctp_connp);
		initmp->b_flag |= MSGHASREF;
		IP_PUT(initmp, sctp->sctp_connp, sctp->sctp_current->isv4);
		BUMP_LOCAL(sctp->sctp_opkts);

notify_ulp:
		bzero(&sopp, sizeof (sopp));
		sopp.sopp_flags = SOCKOPT_WROFF;
		sopp.sopp_wroff = sctps->sctps_wroff_xtra + hdrlen +
		    sizeof (sctp_data_hdr_t);
		sctp->sctp_ulp_prop(sctp->sctp_ulpd, &sopp);

		return (0);
	default:
		ip0dbg(("sctp_connect: invalid state. %d\n", sctp->sctp_state));
		WAKE_SCTP(sctp);
		return (EINVAL);
	}
}

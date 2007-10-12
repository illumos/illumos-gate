/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)rtsock.c	8.6 (Berkeley) 2/11/95
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines that processes routing socket requests.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/zone.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/strsun.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>

#include <inet/ipclassifier.h>

#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

#define	RTS_MSG_SIZE(type, rtm_addrs, af, sacnt) \
	(rts_data_msg_size(rtm_addrs, af, sacnt) + rts_header_msg_size(type))

static size_t	rts_copyfromsockaddr(struct sockaddr *sa, in6_addr_t *addrp);
static void	rts_fill_msg(int type, int rtm_addrs, ipaddr_t dst,
    ipaddr_t mask, ipaddr_t gateway, ipaddr_t src_addr, ipaddr_t brd_addr,
    ipaddr_t author, const ipif_t *ipif, mblk_t *mp, uint_t, const tsol_gc_t *);
static int	rts_getaddrs(rt_msghdr_t *rtm, in6_addr_t *dst_addrp,
    in6_addr_t *gw_addrp, in6_addr_t *net_maskp, in6_addr_t *authorp,
    in6_addr_t *if_addrp, in6_addr_t *src_addrp, ushort_t *indexp,
    sa_family_t *afp, tsol_rtsecattr_t *rtsecattr, int *error);
static void	rts_getifdata(if_data_t *if_data, const ipif_t *ipif);
static int	rts_getmetrics(ire_t *ire, rt_metrics_t *metrics);
static mblk_t	*rts_rtmget(mblk_t *mp, ire_t *ire, ire_t *sire,
    sa_family_t af);
static void	rts_setmetrics(ire_t *ire, uint_t which, rt_metrics_t *metrics);
static void	ip_rts_request_retry(ipsq_t *, queue_t *q, mblk_t *mp, void *);

/*
 * Send the ack to all the routing queues.  In case of the originating queue,
 * send it only if the loopback is set.
 *
 * Messages are sent upstream only on routing sockets that did not specify an
 * address family when they were created or when the address family matches the
 * one specified by the caller.
 *
 */
void
rts_queue_input(mblk_t *mp, queue_t *q, sa_family_t af, ip_stack_t *ipst)
{
	mblk_t	*mp1;
	int	checkqfull;
	conn_t 	*connp, *next_connp;

	mutex_enter(&ipst->ips_rts_clients->connf_lock);
	connp = ipst->ips_rts_clients->connf_head;

	while (connp != NULL) {
		/*
		 * If there was a family specified when this routing socket was
		 * created and it doesn't match the family of the message to
		 * copy, then continue.
		 */
		if ((connp->conn_proto != AF_UNSPEC) &&
		    (connp->conn_proto != af)) {
			connp = connp->conn_next;
			continue;
		}
		/*
		 * For the originating queue, we only copy the message upstream
		 * if loopback is set.  For others reading on the routing
		 * socket, we check if there is room upstream for a copy of the
		 * message.
		 */
		if ((q != NULL) && (CONNP_TO_RQ(connp) == RD(q))) {
			if (connp->conn_loopback == 0) {
				connp = connp->conn_next;
				continue;
			}
			/*
			 * Just because it is the same queue doesn't mean it
			 * will promptly read its acks. Have to avoid using
			 * all of kernel memory.
			 */
			checkqfull = B_TRUE;
		} else {
			checkqfull = B_TRUE;
		}
		CONN_INC_REF(connp);
		mutex_exit(&ipst->ips_rts_clients->connf_lock);
		/* Pass to rts_input */
		if (!checkqfull || canputnext(CONNP_TO_RQ(connp))) {
			mp1 = dupmsg(mp);
			if (mp1 == NULL)
				mp1 = copymsg(mp);
			if (mp1 != NULL)
				(connp->conn_recv)(connp, mp1, NULL);
		}

		mutex_enter(&ipst->ips_rts_clients->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_connp = connp->conn_next;
		CONN_DEC_REF(connp);
		connp = next_connp;
	}
	mutex_exit(&ipst->ips_rts_clients->connf_lock);
	freemsg(mp);
}

/*
 * Takes an ire and sends an ack to all the routing sockets. This
 * routine is used
 * - when a route is created/deleted through the ioctl interface.
 * - when ire_expire deletes a stale redirect
 */
void
ip_rts_rtmsg(int type, ire_t *ire, int error, ip_stack_t *ipst)
{
	mblk_t		*mp;
	rt_msghdr_t	*rtm;
	int		rtm_addrs = (RTA_DST | RTA_NETMASK | RTA_GATEWAY);
	sa_family_t	af;
	in6_addr_t	gw_addr_v6;

	if (ire == NULL)
		return;
	ASSERT(ire->ire_ipversion == IPV4_VERSION ||
	    ire->ire_ipversion == IPV6_VERSION);

	if (ire->ire_flags & RTF_SETSRC)
		rtm_addrs |= RTA_SRC;

	switch (ire->ire_ipversion) {
	case IPV4_VERSION:
		af = AF_INET;
		mp = rts_alloc_msg(type, rtm_addrs, af, 0);
		if (mp == NULL)
			return;
		rts_fill_msg(type, rtm_addrs, ire->ire_addr, ire->ire_mask,
		    ire->ire_gateway_addr, ire->ire_src_addr, 0, 0, NULL, mp,
		    0, NULL);
		break;
	case IPV6_VERSION:
		af = AF_INET6;
		mp = rts_alloc_msg(type, rtm_addrs, af, 0);
		if (mp == NULL)
			return;
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
		rts_fill_msg_v6(type, rtm_addrs, &ire->ire_addr_v6,
		    &ire->ire_mask_v6, &gw_addr_v6,
		    &ire->ire_src_addr_v6, &ipv6_all_zeros, &ipv6_all_zeros,
		    NULL, mp, 0, NULL);
		break;
	}
	rtm = (rt_msghdr_t *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)&mp->b_rptr[rtm->rtm_msglen];
	rtm->rtm_addrs = rtm_addrs;
	rtm->rtm_flags = ire->ire_flags;
	if (error != 0)
		rtm->rtm_errno = error;
	else
		rtm->rtm_flags |= RTF_DONE;
	rts_queue_input(mp, NULL, af, ipst);
}

/* ARGSUSED */
static void
ip_rts_request_retry(ipsq_t *dummy_sq, queue_t *q, mblk_t *mp, void *dummy)
{
	(void) ip_rts_request(q, mp, DB_CRED(mp));
}

/*
 * This is a call from the RTS module
 * indicating that this is a Routing Socket
 * Stream. Insert this conn_t in routing
 * socket client list.
 */
void
ip_rts_register(conn_t *connp)
{
	ip_stack_t *ipst = connp->conn_netstack->netstack_ip;

	connp->conn_loopback = 1;
	ipcl_hash_insert_wildcard(ipst->ips_rts_clients, connp);
}

/*
 * This is a call from the RTS module indicating that it is closing.
 */
void
ip_rts_unregister(conn_t *connp)
{
	ipcl_hash_remove(connp);
}

/*
 * Processes requests received on a routing socket. It extracts all the
 * arguments and calls the appropriate function to process the request.
 *
 * RTA_SRC bit flag requests are sent by 'route -setsrc'.
 *
 * In general, this function does not consume the message supplied but rather
 * sends the message upstream with an appropriate UNIX errno.
 *
 * We may need to restart this operation if the ipif cannot be looked up
 * due to an exclusive operation that is currently in progress. The restart
 * entry point is ip_rts_request_retry. While the request is enqueud in the
 * ipsq the ioctl could be aborted and the conn close. To ensure that we don't
 * have stale conn pointers, ip_wput_ioctl does a conn refhold. This is
 * released at the completion of the rts ioctl at the end of this function
 * by calling CONN_OPER_PENDING_DONE or when the ioctl is aborted and
 * conn close occurs in conn_ioctl_cleanup.
 */
int
ip_rts_request(queue_t *q, mblk_t *mp, cred_t *ioc_cr)
{
	rt_msghdr_t	*rtm = NULL;
	in6_addr_t	dst_addr_v6;
	in6_addr_t	src_addr_v6;
	in6_addr_t	gw_addr_v6;
	in6_addr_t	net_mask_v6;
	in6_addr_t	author_v6;
	in6_addr_t	if_addr_v6;
	mblk_t		*mp1, *ioc_mp = mp;
	ire_t		*ire = NULL;
	ire_t		*sire = NULL;
	int		error = 0;
	int		match_flags = MATCH_IRE_DSTONLY;
	int		match_flags_local = MATCH_IRE_TYPE | MATCH_IRE_GW;
	int		found_addrs;
	sa_family_t	af;
	ipaddr_t	dst_addr;
	ipaddr_t	gw_addr;
	ipaddr_t	src_addr;
	ipaddr_t	net_mask;
	ushort_t	index;
	ipif_t		*ipif = NULL;
	ipif_t		*tmp_ipif = NULL;
	IOCP		iocp = (IOCP)mp->b_rptr;
	conn_t		*connp;
	boolean_t	gcgrp_xtraref = B_FALSE;
	tsol_gcgrp_addr_t ga;
	tsol_rtsecattr_t rtsecattr;
	struct rtsa_s	*rtsap = NULL;
	tsol_gcgrp_t	*gcgrp = NULL;
	tsol_gc_t	*gc = NULL;
	ts_label_t	*tsl = NULL;
	zoneid_t	zoneid;
	ip_stack_t	*ipst;

	ip1dbg(("ip_rts_request: mp is %x\n", DB_TYPE(mp)));

	ASSERT(CONN_Q(q));
	connp = Q_TO_CONN(q);
	zoneid = connp->conn_zoneid;
	ipst = connp->conn_netstack->netstack_ip;

	ASSERT(mp->b_cont != NULL);
	/* ioc_mp holds mp */
	mp = mp->b_cont;

	/*
	 * The Routing Socket data starts on
	 * next block. If there is no next block
	 * this is an indication from routing module
	 * that it is a routing socket stream queue.
	 */
	ASSERT(mp->b_cont != NULL);
	mp1 = dupmsg(mp->b_cont);
	if (mp1 == NULL) {
		error  = ENOBUFS;
		goto done;
	}
	mp = mp1;

	if (mp->b_cont != NULL && !pullupmsg(mp, -1)) {
		freemsg(mp);
		error =  EINVAL;
		goto done;
	}
	if ((mp->b_wptr - mp->b_rptr) < sizeof (rt_msghdr_t)) {
		freemsg(mp);
		error = EINVAL;
		goto done;
	}

	/*
	 * Check the routing message for basic consistency including the
	 * version number and that the number of octets written is the same
	 * as specified by the rtm_msglen field.
	 *
	 * At this point, an error can be delivered back via rtm_errno.
	 */
	rtm = (rt_msghdr_t *)mp->b_rptr;
	if ((mp->b_wptr - mp->b_rptr) != rtm->rtm_msglen) {
		error = EINVAL;
		goto done;
	}
	if (rtm->rtm_version != RTM_VERSION) {
		error = EPROTONOSUPPORT;
		goto done;
	}

	/* Only allow RTM_GET or RTM_RESOLVE for unprivileged process */
	if (rtm->rtm_type != RTM_GET &&
	    rtm->rtm_type != RTM_RESOLVE &&
	    (ioc_cr == NULL ||
	    secpolicy_ip_config(ioc_cr, B_FALSE) != 0)) {
		error = EPERM;
		goto done;
	}

	found_addrs = rts_getaddrs(rtm, &dst_addr_v6, &gw_addr_v6, &net_mask_v6,
	    &author_v6, &if_addr_v6, &src_addr_v6, &index, &af, &rtsecattr,
	    &error);

	if (error != 0)
		goto done;

	if ((found_addrs & RTA_DST) == 0) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Based on the address family of the destination address, determine
	 * the destination, gateway and netmask and return the appropriate error
	 * if an unknown address family was specified (following the errno
	 * values that 4.4BSD-Lite2 returns.)
	 */
	switch (af) {
	case AF_INET:
		IN6_V4MAPPED_TO_IPADDR(&dst_addr_v6, dst_addr);
		IN6_V4MAPPED_TO_IPADDR(&src_addr_v6, src_addr);
		IN6_V4MAPPED_TO_IPADDR(&gw_addr_v6, gw_addr);
		if (((found_addrs & RTA_NETMASK) == 0) ||
		    (rtm->rtm_flags & RTF_HOST))
			net_mask = IP_HOST_MASK;
		else
			IN6_V4MAPPED_TO_IPADDR(&net_mask_v6, net_mask);
		break;
	case AF_INET6:
		if (((found_addrs & RTA_NETMASK) == 0) ||
		    (rtm->rtm_flags & RTF_HOST))
			net_mask_v6 = ipv6_all_ones;
		break;
	default:
		/*
		 * These errno values are meant to be compatible with
		 * 4.4BSD-Lite2 for the given message types.
		 */
		switch (rtm->rtm_type) {
		case RTM_ADD:
		case RTM_DELETE:
			error = ESRCH;
			goto done;
		case RTM_GET:
		case RTM_CHANGE:
			error = EAFNOSUPPORT;
			goto done;
		default:
			error = EOPNOTSUPP;
			goto done;
		}
	}

	/*
	 * At this point, the address family must be something known.
	 */
	ASSERT(af == AF_INET || af == AF_INET6);

	if (index != 0) {
		ill_t   *ill;

		/*
		 * IPC must be refheld somewhere in ip_wput_nondata or
		 * ip_wput_ioctl etc... and cleaned up if ioctl is killed.
		 * If ILL_CHANGING the request is queued in the ipsq.
		 */
		ill = ill_lookup_on_ifindex(index, af == AF_INET6,
		    CONNP_TO_WQ(connp), ioc_mp, ip_rts_request_retry, &error,
		    ipst);
		if (ill == NULL) {
			if (error != EINPROGRESS)
				error = EINVAL;
			goto done;
		}

		ipif = ipif_get_next_ipif(NULL, ill);
		ill_refrele(ill);
		/*
		 * If this is replacement ipif, prevent a route from
		 * being added.
		 */
		if (ipif != NULL && ipif->ipif_replace_zero) {
			error = ENETDOWN;
			goto done;
		}
		match_flags |= MATCH_IRE_ILL;
	}

	/*
	 * If a netmask was supplied in the message, then subsequent route
	 * lookups will attempt to match on the netmask as well.
	 */
	if ((found_addrs & RTA_NETMASK) != 0)
		match_flags |= MATCH_IRE_MASK;

	/*
	 * We only process any passed-in route security attributes for
	 * either RTM_ADD or RTM_CHANGE message; We overload them
	 * to do an RTM_GET as a different label; ignore otherwise.
	 */
	if (rtm->rtm_type == RTM_ADD || rtm->rtm_type == RTM_CHANGE ||
	    rtm->rtm_type == RTM_GET) {
		ASSERT(rtsecattr.rtsa_cnt <= TSOL_RTSA_REQUEST_MAX);
		if (rtsecattr.rtsa_cnt > 0)
			rtsap = &rtsecattr.rtsa_attr[0];
	}

	switch (rtm->rtm_type) {
	case RTM_ADD:
		/* if we are adding a route, gateway is a must */
		if ((found_addrs & RTA_GATEWAY) == 0) {
			error = EINVAL;
			goto done;
		}

		/* Multirouting does not support net routes. */
		if ((rtm->rtm_flags & (RTF_MULTIRT | RTF_HOST)) ==
		    RTF_MULTIRT) {
			error = EADDRNOTAVAIL;
			goto done;
		}

		/*
		 * Multirouting and user-specified source addresses
		 * do not support interface based routing.
		 * Assigning a source address to an interface based
		 * route is achievable by plumbing a new ipif and
		 * setting up the interface route via this ipif,
		 * though.
		 */
		if (rtm->rtm_flags & (RTF_MULTIRT | RTF_SETSRC)) {
			if ((rtm->rtm_flags & RTF_GATEWAY) == 0) {
				error = EADDRNOTAVAIL;
				goto done;
			}
		}

		switch (af) {
		case AF_INET:
			if (src_addr != INADDR_ANY) {
				/*
				 * The RTF_SETSRC flag is present, check that
				 * the supplied src address is not the loopback
				 * address. This would produce martian packets.
				 */
				if (src_addr == htonl(INADDR_LOOPBACK)) {
					error = EINVAL;
					goto done;
				}
				/*
				 * Also check that the supplied address is a
				 * valid, local one.
				 */
				tmp_ipif = ipif_lookup_addr(src_addr, NULL,
				    ALL_ZONES, CONNP_TO_WQ(connp), ioc_mp,
				    ip_rts_request_retry, &error, ipst);
				if (tmp_ipif == NULL) {
					if (error != EINPROGRESS)
						error = EADDRNOTAVAIL;
					goto done;
				}
				if (!(tmp_ipif->ipif_flags & IPIF_UP) ||
				    (tmp_ipif->ipif_flags &
				    (IPIF_NOLOCAL | IPIF_ANYCAST))) {
					error = EINVAL;
					goto done;
				}
			} else {
				/*
				 * The RTF_SETSRC modifier must be associated
				 * to a non-null source address.
				 */
				if (rtm->rtm_flags & RTF_SETSRC) {
					error = EINVAL;
					goto done;
				}
			}

			error = ip_rt_add(dst_addr, net_mask, gw_addr, src_addr,
			    rtm->rtm_flags, ipif, &ire, B_FALSE,
			    CONNP_TO_WQ(connp), ioc_mp, ip_rts_request_retry,
			    rtsap, ipst);
			if (ipif != NULL)
				ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));
			break;
		case AF_INET6:
			if (!IN6_IS_ADDR_UNSPECIFIED(&src_addr_v6)) {
				/*
				 * The RTF_SETSRC flag is present, check that
				 * the supplied src address is not the loopback
				 * address. This would produce martian packets.
				 */
				if (IN6_IS_ADDR_LOOPBACK(&src_addr_v6)) {
					error = EINVAL;
					goto done;
				}
				/*
				 * Also check that the supplied address is a
				 * valid, local one.
				 */
				tmp_ipif = ipif_lookup_addr_v6(&src_addr_v6,
				    NULL, ALL_ZONES, CONNP_TO_WQ(connp), ioc_mp,
				    ip_rts_request_retry, &error, ipst);
				if (tmp_ipif == NULL) {
					if (error != EINPROGRESS)
						error = EADDRNOTAVAIL;
					goto done;
				}

				if (!(tmp_ipif->ipif_flags & IPIF_UP) ||
				    (tmp_ipif->ipif_flags &
				    (IPIF_NOLOCAL | IPIF_ANYCAST))) {
					error = EINVAL;
					goto done;
				}

				error = ip_rt_add_v6(&dst_addr_v6, &net_mask_v6,
				    &gw_addr_v6, &src_addr_v6, rtm->rtm_flags,
				    ipif, &ire, CONNP_TO_WQ(connp), ioc_mp,
				    ip_rts_request_retry, rtsap, ipst);
				break;
			}
			/*
			 * The RTF_SETSRC modifier must be associated
			 * to a non-null source address.
			 */
			if (rtm->rtm_flags & RTF_SETSRC) {
				error = EINVAL;
				goto done;
			}
			error = ip_rt_add_v6(&dst_addr_v6, &net_mask_v6,
			    &gw_addr_v6, NULL, rtm->rtm_flags,
			    ipif, &ire, CONNP_TO_WQ(connp), ioc_mp,
			    ip_rts_request_retry, rtsap, ipst);
			if (ipif != NULL)
				ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));
			break;
		}
		if (error != 0)
			goto done;
		ASSERT(ire != NULL);
		rts_setmetrics(ire, rtm->rtm_inits, &rtm->rtm_rmx);
		break;
	case RTM_DELETE:
		/* if we are deleting a route, gateway is a must */
		if ((found_addrs & RTA_GATEWAY) == 0) {
			error = EINVAL;
			goto done;
		}
		/*
		 * The RTF_SETSRC modifier does not make sense
		 * when deleting a route.
		 */
		if (rtm->rtm_flags & RTF_SETSRC) {
			error = EINVAL;
			goto done;
		}

		switch (af) {
		case AF_INET:
			error = ip_rt_delete(dst_addr, net_mask, gw_addr,
			    found_addrs, rtm->rtm_flags, ipif, B_FALSE,
			    CONNP_TO_WQ(connp), ioc_mp, ip_rts_request_retry,
			    ipst);
			break;
		case AF_INET6:
			error = ip_rt_delete_v6(&dst_addr_v6, &net_mask_v6,
			    &gw_addr_v6, found_addrs, rtm->rtm_flags, ipif,
			    CONNP_TO_WQ(connp), ioc_mp, ip_rts_request_retry,
			    ipst);
			break;
		}
		break;
	case RTM_GET:
	case RTM_CHANGE:
		/*
		 * In the case of RTM_GET, the forwarding table should be
		 * searched recursively with default being matched if the
		 * specific route doesn't exist.  Also, if a gateway was
		 * specified then the gateway address must also be matched.
		 *
		 * In the case of RTM_CHANGE, the gateway address (if supplied)
		 * is the new gateway address so matching on the gateway address
		 * is not done.  This can lead to ambiguity when looking up the
		 * route to change as usually only the destination (and netmask,
		 * if supplied) is used for the lookup.  However if a RTA_IFP
		 * sockaddr is also supplied, it can disambiguate which route to
		 * change provided the ambigous routes are tied to distinct
		 * ill's (or interface indices).  If the routes are not tied to
		 * any particular interfaces (for example, with traditional
		 * gateway routes), then a RTA_IFP sockaddr will be of no use as
		 * it won't match any such routes.
		 * RTA_SRC is not supported for RTM_GET and RTM_CHANGE,
		 * except when RTM_CHANGE is combined to RTF_SETSRC.
		 */
		if (((found_addrs & RTA_SRC) != 0) &&
		    ((rtm->rtm_type == RTM_GET) ||
		    !(rtm->rtm_flags & RTF_SETSRC))) {
			error = EOPNOTSUPP;
			goto done;
		}

		if (rtm->rtm_type == RTM_GET) {
			match_flags |=
			    (MATCH_IRE_DEFAULT | MATCH_IRE_RECURSIVE |
			    MATCH_IRE_SECATTR);
			match_flags_local |= MATCH_IRE_SECATTR;
			if ((found_addrs & RTA_GATEWAY) != 0)
				match_flags |= MATCH_IRE_GW;
			if (ioc_cr)
				tsl = crgetlabel(ioc_cr);
			if (rtsap != NULL) {
				if (rtsa_validate(rtsap) != 0) {
					error = EINVAL;
					goto done;
				}
				if (tsl != NULL &&
				    crgetzoneid(ioc_cr) != GLOBAL_ZONEID &&
				    (tsl->tsl_doi != rtsap->rtsa_doi ||
				    !bldominates(&tsl->tsl_label,
				    &rtsap->rtsa_slrange.lower_bound))) {
					error = EPERM;
					goto done;
				}
				tsl = labelalloc(
				    &rtsap->rtsa_slrange.lower_bound,
				    rtsap->rtsa_doi, KM_NOSLEEP);
			}
		}
		if (rtm->rtm_type == RTM_CHANGE) {
			if ((found_addrs & RTA_GATEWAY) &&
			    (rtm->rtm_flags & RTF_SETSRC)) {
				/*
				 * Do not want to change the gateway,
				 * but rather the source address.
				 */
				match_flags |= MATCH_IRE_GW;
			}
		}

		/*
		 * If the netmask is all ones (either as supplied or as derived
		 * above), then first check for an IRE_LOOPBACK or
		 * IRE_LOCAL entry.
		 *
		 * If we didn't check for or find an IRE_LOOPBACK or IRE_LOCAL
		 * entry, then look in the forwarding table.
		 */
		switch (af) {
		case AF_INET:
			if (net_mask == IP_HOST_MASK) {
				ire = ire_ctable_lookup(dst_addr, gw_addr,
				    IRE_LOCAL | IRE_LOOPBACK, NULL, zoneid,
				    tsl, match_flags_local, ipst);
				/*
				 * If we found an IRE_LOCAL, make sure
				 * it is one that would be used by this
				 * zone to send packets.
				 */
				if (ire != NULL &&
				    ire->ire_type == IRE_LOCAL &&
				    ipst->ips_ip_restrict_interzone_loopback &&
				    !ire_local_ok_across_zones(ire,
				    zoneid, &dst_addr, tsl, ipst)) {
					ire_refrele(ire);
					ire = NULL;
				}
			}
			if (ire == NULL) {
				ire = ire_ftable_lookup(dst_addr, net_mask,
				    gw_addr, 0, ipif, &sire, zoneid, 0,
				    tsl, match_flags, ipst);
			}
			break;
		case AF_INET6:
			if (IN6_ARE_ADDR_EQUAL(&net_mask_v6, &ipv6_all_ones)) {
				ire = ire_ctable_lookup_v6(&dst_addr_v6,
				    &gw_addr_v6, IRE_LOCAL | IRE_LOOPBACK, NULL,
				    zoneid, tsl, match_flags_local, ipst);
				/*
				 * If we found an IRE_LOCAL, make sure
				 * it is one that would be used by this
				 * zone to send packets.
				 */
				if (ire != NULL &&
				    ire->ire_type == IRE_LOCAL &&
				    ipst->ips_ip_restrict_interzone_loopback &&
				    !ire_local_ok_across_zones(ire,
				    zoneid, (void *)&dst_addr_v6, tsl, ipst)) {
					ire_refrele(ire);
					ire = NULL;
				}
			}
			if (ire == NULL) {
				ire = ire_ftable_lookup_v6(&dst_addr_v6,
				    &net_mask_v6, &gw_addr_v6, 0, ipif, &sire,
				    zoneid, 0, tsl, match_flags, ipst);
			}
			break;
		}
		if (tsl != NULL && tsl != crgetlabel(ioc_cr))
			label_rele(tsl);

		if (ire == NULL) {
			error = ESRCH;
			goto done;
		}
		/* we know the IRE before we come here */
		switch (rtm->rtm_type) {
		case RTM_GET:
			mp1 = rts_rtmget(mp, ire, sire, af);
			if (mp1 == NULL) {
				error = ENOBUFS;
				goto done;
			}
			freemsg(mp);
			mp = mp1;
			rtm = (rt_msghdr_t *)mp->b_rptr;
			break;
		case RTM_CHANGE:
			/*
			 * Do not allow to the multirouting state of a route
			 * to be changed. This aims to prevent undesirable
			 * stages where both multirt and non-multirt routes
			 * for the same destination are declared.
			 */
			if ((ire->ire_flags & RTF_MULTIRT) !=
			    (rtm->rtm_flags & RTF_MULTIRT)) {
				error = EINVAL;
				goto done;
			}
			/*
			 * Note that we do not need to do
			 * ire_flush_cache_*(IRE_FLUSH_ADD) as a change
			 * in metrics or gateway will not affect existing
			 * routes since it does not create a more specific
			 * route.
			 */
			switch (af) {
			case AF_INET:
				ire_flush_cache_v4(ire, IRE_FLUSH_DELETE);
				if ((found_addrs & RTA_GATEWAY) != 0 &&
				    (ire->ire_gateway_addr != gw_addr)) {
					ire->ire_gateway_addr = gw_addr;
				}

				if (rtsap != NULL) {
					ga.ga_af = AF_INET;
					IN6_IPADDR_TO_V4MAPPED(
					    ire->ire_gateway_addr, &ga.ga_addr);

					gcgrp = gcgrp_lookup(&ga, B_TRUE);
					if (gcgrp == NULL) {
						error = ENOMEM;
						goto done;
					}
				}

				if ((found_addrs & RTA_SRC) != 0 &&
				    (rtm->rtm_flags & RTF_SETSRC) != 0 &&
				    (ire->ire_src_addr != src_addr)) {

					if (src_addr != INADDR_ANY) {
						/*
						 * The RTF_SETSRC flag is
						 * present, check that the
						 * supplied src address is not
						 * the loopback address. This
						 * would produce martian
						 * packets.
						 */
						if (src_addr ==
						    htonl(INADDR_LOOPBACK)) {
							error = EINVAL;
							goto done;
						}
						/*
						 * Also check that the the
						 * supplied addr is a valid
						 * local address.
						 */
						tmp_ipif = ipif_lookup_addr(
						    src_addr, NULL, ALL_ZONES,
						    CONNP_TO_WQ(connp), ioc_mp,
						    ip_rts_request_retry,
						    &error, ipst);
						if (tmp_ipif == NULL) {
							error = (error ==
							    EINPROGRESS) ?
							    error :
							    EADDRNOTAVAIL;
							goto done;
						}

						if (!(tmp_ipif->ipif_flags &
						    IPIF_UP) ||
						    (tmp_ipif->ipif_flags &
						    (IPIF_NOLOCAL |
						    IPIF_ANYCAST))) {
							error = EINVAL;
							goto done;
						}
						ire->ire_flags |= RTF_SETSRC;
					} else {
						ire->ire_flags &= ~RTF_SETSRC;
					}
					ire->ire_src_addr = src_addr;
				}
				break;
			case AF_INET6:
				ire_flush_cache_v6(ire, IRE_FLUSH_DELETE);
				mutex_enter(&ire->ire_lock);
				if ((found_addrs & RTA_GATEWAY) != 0 &&
				    !IN6_ARE_ADDR_EQUAL(
				    &ire->ire_gateway_addr_v6, &gw_addr_v6)) {
					ire->ire_gateway_addr_v6 = gw_addr_v6;
				}

				if (rtsap != NULL) {
					ga.ga_af = AF_INET6;
					ga.ga_addr = ire->ire_gateway_addr_v6;

					gcgrp = gcgrp_lookup(&ga, B_TRUE);
					if (gcgrp == NULL) {
						error = ENOMEM;
						goto done;
					}
				}

				if ((found_addrs & RTA_SRC) != 0 &&
				    (rtm->rtm_flags & RTF_SETSRC) != 0 &&
				    !IN6_ARE_ADDR_EQUAL(
				    &ire->ire_src_addr_v6, &src_addr_v6)) {

					if (!IN6_IS_ADDR_UNSPECIFIED(
					    &src_addr_v6)) {
						/*
						 * The RTF_SETSRC flag is
						 * present, check that the
						 * supplied src address is not
						 * the loopback address. This
						 * would produce martian
						 * packets.
						 */
						if (IN6_IS_ADDR_LOOPBACK(
						    &src_addr_v6)) {
							mutex_exit(
							    &ire->ire_lock);
							error = EINVAL;
							goto done;
						}
						/*
						 * Also check that the the
						 * supplied addr is a valid
						 * local address.
						 */
						tmp_ipif = ipif_lookup_addr_v6(
						    &src_addr_v6, NULL,
						    ALL_ZONES,
						    CONNP_TO_WQ(connp), ioc_mp,
						    ip_rts_request_retry,
						    &error, ipst);
						if (tmp_ipif == NULL) {
							mutex_exit(
							    &ire->ire_lock);
							error = (error ==
							    EINPROGRESS) ?
							    error :
							    EADDRNOTAVAIL;
							goto done;
						}
						if (!(tmp_ipif->ipif_flags &
						    IPIF_UP) ||
						    (tmp_ipif->ipif_flags &
						    (IPIF_NOLOCAL |
						    IPIF_ANYCAST))) {
							mutex_exit(
							    &ire->ire_lock);
							error = EINVAL;
							goto done;
						}
						ire->ire_flags |= RTF_SETSRC;
					} else {
						ire->ire_flags &= ~RTF_SETSRC;
					}
					ire->ire_src_addr_v6 = src_addr_v6;
				}
				mutex_exit(&ire->ire_lock);
				break;
			}

			if (rtsap != NULL) {
				in_addr_t ga_addr4;

				ASSERT(gcgrp != NULL);

				/*
				 * Create and add the security attribute to
				 * prefix IRE; it will add a reference to the
				 * group upon allocating a new entry.  If it
				 * finds an already-existing entry for the
				 * security attribute, it simply returns it
				 * and no new group reference is made.
				 */
				gc = gc_create(rtsap, gcgrp, &gcgrp_xtraref);
				if (gc == NULL ||
				    (error = tsol_ire_init_gwattr(ire,
				    ire->ire_ipversion, gc, NULL)) != 0) {
					if (gc != NULL) {
						GC_REFRELE(gc);
					} else {
						/* gc_create failed */
						error = ENOMEM;
					}
					goto done;
				}

				/*
				 * Now delete any existing gateway IRE caches
				 * as well as all caches using the gateway,
				 * and allow them to be created on demand
				 * through ip_newroute{_v6}.
				 */
				IN6_V4MAPPED_TO_IPADDR(&ga.ga_addr, ga_addr4);
				if (af == AF_INET) {
					ire_clookup_delete_cache_gw(
					    ga_addr4, ALL_ZONES, ipst);
				} else {
					ire_clookup_delete_cache_gw_v6(
					    &ga.ga_addr, ALL_ZONES, ipst);
				}
			}
			rts_setmetrics(ire, rtm->rtm_inits, &rtm->rtm_rmx);
			break;
		}
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
done:
	if (ire != NULL)
		ire_refrele(ire);
	if (sire != NULL)
		ire_refrele(sire);
	if (ipif != NULL)
		ipif_refrele(ipif);
	if (tmp_ipif != NULL)
		ipif_refrele(tmp_ipif);

	if (gcgrp_xtraref)
		GCGRP_REFRELE(gcgrp);

	if (error == EINPROGRESS) {
		if (rtm != NULL)
			freemsg(mp);
		return (error);
	}
	if (rtm != NULL) {
		ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
		if (error != 0) {
			rtm->rtm_errno = error;
			/* Send error ACK */
			ip1dbg(("ip_rts_request: error %d\n", error));
		} else {
			rtm->rtm_flags |= RTF_DONE;
			/* OK ACK already set up by caller except this */
			ip2dbg(("ip_rts_request: OK ACK\n"));
		}
		rts_queue_input(mp, q, af, ipst);
	}
	iocp->ioc_error = error;
	ioc_mp->b_datap->db_type = M_IOCACK;
	if (iocp->ioc_error != 0)
		iocp->ioc_count = 0;
	(connp->conn_recv)(connp, ioc_mp, NULL);
	/* conn was refheld in ip_wput_ioctl. */
	CONN_OPER_PENDING_DONE(connp);

	return (error);
}

/*
 * Build a reply to the RTM_GET request contained in the given message block
 * using the retrieved IRE of the destination address, the parent IRE (if it
 * exists) and the address family.
 *
 * Returns a pointer to a message block containing the reply if successful,
 * otherwise NULL is returned.
 */
static mblk_t *
rts_rtmget(mblk_t *mp, ire_t *ire, ire_t *sire, sa_family_t af)
{
	rt_msghdr_t	*rtm;
	rt_msghdr_t	*new_rtm;
	mblk_t		*new_mp;
	int		rtm_addrs;
	int		rtm_flags;
	in6_addr_t	gw_addr_v6;
	tsol_ire_gw_secattr_t *attrp = NULL;
	tsol_gc_t	*gc = NULL;
	tsol_gcgrp_t	*gcgrp = NULL;
	int		sacnt = 0;

	ASSERT(ire->ire_ipif != NULL);
	rtm = (rt_msghdr_t *)mp->b_rptr;

	if (sire != NULL && sire->ire_gw_secattr != NULL)
		attrp = sire->ire_gw_secattr;
	else if (ire->ire_gw_secattr != NULL)
		attrp = ire->ire_gw_secattr;

	if (attrp != NULL) {
		mutex_enter(&attrp->igsa_lock);
		if ((gc = attrp->igsa_gc) != NULL) {
			gcgrp = gc->gc_grp;
			ASSERT(gcgrp != NULL);
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
			sacnt = 1;
		} else if ((gcgrp = attrp->igsa_gcgrp) != NULL) {
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
			gc = gcgrp->gcgrp_head;
			sacnt = gcgrp->gcgrp_count;
		}
		mutex_exit(&attrp->igsa_lock);

		/* do nothing if there's no gc to report */
		if (gc == NULL) {
			ASSERT(sacnt == 0);
			if (gcgrp != NULL) {
				/* we might as well drop the lock now */
				rw_exit(&gcgrp->gcgrp_rwlock);
				gcgrp = NULL;
			}
			attrp = NULL;
		}

		ASSERT(gc == NULL || (gcgrp != NULL &&
		    RW_LOCK_HELD(&gcgrp->gcgrp_rwlock)));
	}
	ASSERT(sacnt == 0 || gc != NULL);

	/*
	 * Always return RTA_DST, RTA_GATEWAY and RTA_NETMASK.
	 *
	 * The 4.4BSD-Lite2 code (net/rtsock.c) returns both
	 * RTA_IFP and RTA_IFA if either is defined, and also
	 * returns RTA_BRD if the appropriate interface is
	 * point-to-point.
	 */
	rtm_addrs = (RTA_DST | RTA_GATEWAY | RTA_NETMASK);
	if (rtm->rtm_addrs & (RTA_IFP | RTA_IFA)) {
		rtm_addrs |= (RTA_IFP | RTA_IFA);
		if (ire->ire_ipif->ipif_flags & IPIF_POINTOPOINT)
			rtm_addrs |= RTA_BRD;
	}

	new_mp = rts_alloc_msg(RTM_GET, rtm_addrs, af, sacnt);
	if (new_mp == NULL) {
		if (gcgrp != NULL)
			rw_exit(&gcgrp->gcgrp_rwlock);
		return (NULL);
	}

	/*
	 * We set the destination address, gateway address,
	 * netmask and flags in the RTM_GET response depending
	 * on whether we found a parent IRE or not.
	 * In particular, if we did find a parent IRE during the
	 * recursive search, use that IRE's gateway address.
	 * Otherwise, we use the IRE's source address for the
	 * gateway address.
	 */
	ASSERT(af == AF_INET || af == AF_INET6);
	switch (af) {
	case AF_INET:
		if (sire == NULL) {
			rtm_flags = ire->ire_flags;
			rts_fill_msg(RTM_GET, rtm_addrs, ire->ire_addr,
			    ire->ire_mask, ire->ire_src_addr, ire->ire_src_addr,
			    ire->ire_ipif->ipif_pp_dst_addr, 0, ire->ire_ipif,
			    new_mp, sacnt, gc);
		} else {
			if (sire->ire_flags & RTF_SETSRC)
				rtm_addrs |= RTA_SRC;

			rtm_flags = sire->ire_flags;
			rts_fill_msg(RTM_GET, rtm_addrs, sire->ire_addr,
			    sire->ire_mask, sire->ire_gateway_addr,
			    (sire->ire_flags & RTF_SETSRC) ?
			    sire->ire_src_addr : ire->ire_src_addr,
			    ire->ire_ipif->ipif_pp_dst_addr,
			    0, ire->ire_ipif, new_mp, sacnt, gc);
		}
		break;
	case AF_INET6:
		if (sire == NULL) {
			rtm_flags = ire->ire_flags;
			rts_fill_msg_v6(RTM_GET, rtm_addrs, &ire->ire_addr_v6,
			    &ire->ire_mask_v6, &ire->ire_src_addr_v6,
			    &ire->ire_src_addr_v6,
			    &ire->ire_ipif->ipif_v6pp_dst_addr,
			    &ipv6_all_zeros, ire->ire_ipif, new_mp,
			    sacnt, gc);
		} else {
			if (sire->ire_flags & RTF_SETSRC)
				rtm_addrs |= RTA_SRC;

			rtm_flags = sire->ire_flags;
			mutex_enter(&sire->ire_lock);
			gw_addr_v6 = sire->ire_gateway_addr_v6;
			mutex_exit(&sire->ire_lock);
			rts_fill_msg_v6(RTM_GET, rtm_addrs, &sire->ire_addr_v6,
			    &sire->ire_mask_v6, &gw_addr_v6,
			    (sire->ire_flags & RTF_SETSRC) ?
			    &sire->ire_src_addr_v6 : &ire->ire_src_addr_v6,
			    &ire->ire_ipif->ipif_v6pp_dst_addr, &ipv6_all_zeros,
			    ire->ire_ipif, new_mp, sacnt, gc);
		}
		break;
	}

	if (gcgrp != NULL)
		rw_exit(&gcgrp->gcgrp_rwlock);

	new_rtm = (rt_msghdr_t *)new_mp->b_rptr;

	/*
	 * The rtm_msglen, rtm_version and rtm_type fields in
	 * RTM_GET response are filled in by rts_fill_msg.
	 *
	 * rtm_addrs and rtm_flags are filled in based on what
	 * was requested and the state of the IREs looked up
	 * above.
	 *
	 * rtm_inits and rtm_rmx are filled in with metrics
	 * based on whether a parent IRE was found or not.
	 *
	 * TODO: rtm_index and rtm_use should probably be
	 * filled in with something resonable here and not just
	 * copied from the request.
	 */
	new_rtm->rtm_index = rtm->rtm_index;
	new_rtm->rtm_pid = rtm->rtm_pid;
	new_rtm->rtm_seq = rtm->rtm_seq;
	new_rtm->rtm_use = rtm->rtm_use;
	new_rtm->rtm_addrs = rtm_addrs;
	new_rtm->rtm_flags = rtm_flags;
	if (sire == NULL)
		new_rtm->rtm_inits = rts_getmetrics(ire, &new_rtm->rtm_rmx);
	else
		new_rtm->rtm_inits = rts_getmetrics(sire, &new_rtm->rtm_rmx);

	return (new_mp);
}

/*
 * Fill the given if_data_t with interface statistics.
 */
static void
rts_getifdata(if_data_t *if_data, const ipif_t *ipif)
{
	if_data->ifi_type = ipif->ipif_type;	/* ethernet, tokenring, etc */
	if_data->ifi_addrlen = 0;		/* media address length */
	if_data->ifi_hdrlen = 0;		/* media header length */
	if_data->ifi_mtu = ipif->ipif_mtu;	/* maximum transmission unit */
	if_data->ifi_metric = ipif->ipif_metric; /* metric (external only) */
	if_data->ifi_baudrate = 0;		/* linespeed */

	if_data->ifi_ipackets = 0;		/* packets received on if */
	if_data->ifi_ierrors = 0;		/* input errors on interface */
	if_data->ifi_opackets = 0;		/* packets sent on interface */
	if_data->ifi_oerrors = 0;		/* output errors on if */
	if_data->ifi_collisions = 0;		/* collisions on csma if */
	if_data->ifi_ibytes = 0;		/* total number received */
	if_data->ifi_obytes = 0;		/* total number sent */
	if_data->ifi_imcasts = 0;		/* multicast packets received */
	if_data->ifi_omcasts = 0;		/* multicast packets sent */
	if_data->ifi_iqdrops = 0;		/* dropped on input */
	if_data->ifi_noproto = 0;		/* destined for unsupported */
						/* protocol. */
}

/*
 * Set the metrics on a forwarding table route.
 */
static void
rts_setmetrics(ire_t *ire, uint_t which, rt_metrics_t *metrics)
{
	clock_t		rtt;
	clock_t		rtt_sd;
	ipif_t		*ipif;
	ifrt_t		*ifrt;
	mblk_t		*mp;
	in6_addr_t	gw_addr_v6;

	/*
	 * Bypass obtaining the lock and searching ipif_saved_ire_mp in the
	 * common case of no metrics.
	 */
	if (which == 0)
		return;
	ire->ire_uinfo.iulp_set = B_TRUE;

	/*
	 * iulp_rtt and iulp_rtt_sd are in milliseconds, but 4.4BSD-Lite2's
	 * <net/route.h> says: rmx_rtt and rmx_rttvar are stored as
	 * microseconds.
	 */
	if (which & RTV_RTT)
		rtt = metrics->rmx_rtt / 1000;
	if (which & RTV_RTTVAR)
		rtt_sd = metrics->rmx_rttvar / 1000;

	/*
	 * Update the metrics in the IRE itself.
	 */
	mutex_enter(&ire->ire_lock);
	if (which & RTV_MTU)
		ire->ire_max_frag = metrics->rmx_mtu;
	if (which & RTV_RTT)
		ire->ire_uinfo.iulp_rtt = rtt;
	if (which & RTV_SSTHRESH)
		ire->ire_uinfo.iulp_ssthresh = metrics->rmx_ssthresh;
	if (which & RTV_RTTVAR)
		ire->ire_uinfo.iulp_rtt_sd = rtt_sd;
	if (which & RTV_SPIPE)
		ire->ire_uinfo.iulp_spipe = metrics->rmx_sendpipe;
	if (which & RTV_RPIPE)
		ire->ire_uinfo.iulp_rpipe = metrics->rmx_recvpipe;
	mutex_exit(&ire->ire_lock);

	/*
	 * Search through the ifrt_t chain hanging off the IPIF in order to
	 * reflect the metric change there.
	 */
	ipif = ire->ire_ipif;
	if (ipif == NULL)
		return;
	ASSERT((ipif->ipif_isv6 && ire->ire_ipversion == IPV6_VERSION) ||
	    ((!ipif->ipif_isv6 && ire->ire_ipversion == IPV4_VERSION)));
	if (ipif->ipif_isv6) {
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
	}
	mutex_enter(&ipif->ipif_saved_ire_lock);
	for (mp = ipif->ipif_saved_ire_mp; mp != NULL; mp = mp->b_cont) {
		/*
		 * On a given ipif, the triple of address, gateway and mask is
		 * unique for each saved IRE (in the case of ordinary interface
		 * routes, the gateway address is all-zeroes).
		 */
		ifrt = (ifrt_t *)mp->b_rptr;
		if (ipif->ipif_isv6) {
			if (!IN6_ARE_ADDR_EQUAL(&ifrt->ifrt_v6addr,
			    &ire->ire_addr_v6) ||
			    !IN6_ARE_ADDR_EQUAL(&ifrt->ifrt_v6gateway_addr,
			    &gw_addr_v6) ||
			    !IN6_ARE_ADDR_EQUAL(&ifrt->ifrt_v6mask,
			    &ire->ire_mask_v6))
				continue;
		} else {
			if (ifrt->ifrt_addr != ire->ire_addr ||
			    ifrt->ifrt_gateway_addr != ire->ire_gateway_addr ||
			    ifrt->ifrt_mask != ire->ire_mask)
				continue;
		}
		if (which & RTV_MTU)
			ifrt->ifrt_max_frag = metrics->rmx_mtu;
		if (which & RTV_RTT)
			ifrt->ifrt_iulp_info.iulp_rtt = rtt;
		if (which & RTV_SSTHRESH) {
			ifrt->ifrt_iulp_info.iulp_ssthresh =
			    metrics->rmx_ssthresh;
		}
		if (which & RTV_RTTVAR)
			ifrt->ifrt_iulp_info.iulp_rtt_sd = metrics->rmx_rttvar;
		if (which & RTV_SPIPE)
			ifrt->ifrt_iulp_info.iulp_spipe = metrics->rmx_sendpipe;
		if (which & RTV_RPIPE)
			ifrt->ifrt_iulp_info.iulp_rpipe = metrics->rmx_recvpipe;
		break;
	}
	mutex_exit(&ipif->ipif_saved_ire_lock);
}

/*
 * Get the metrics from a forwarding table route.
 */
static int
rts_getmetrics(ire_t *ire, rt_metrics_t *metrics)
{
	int	metrics_set = 0;

	bzero(metrics, sizeof (rt_metrics_t));
	/*
	 * iulp_rtt and iulp_rtt_sd are in milliseconds, but 4.4BSD-Lite2's
	 * <net/route.h> says: rmx_rtt and rmx_rttvar are stored as
	 * microseconds.
	 */
	metrics->rmx_rtt = ire->ire_uinfo.iulp_rtt * 1000;
	metrics_set |= RTV_RTT;
	metrics->rmx_mtu = ire->ire_max_frag;
	metrics_set |= RTV_MTU;
	metrics->rmx_ssthresh = ire->ire_uinfo.iulp_ssthresh;
	metrics_set |= RTV_SSTHRESH;
	metrics->rmx_rttvar = ire->ire_uinfo.iulp_rtt_sd * 1000;
	metrics_set |= RTV_RTTVAR;
	metrics->rmx_sendpipe = ire->ire_uinfo.iulp_spipe;
	metrics_set |= RTV_SPIPE;
	metrics->rmx_recvpipe = ire->ire_uinfo.iulp_rpipe;
	metrics_set |= RTV_RPIPE;
	return (metrics_set);
}

/*
 * Takes a pointer to a routing message and extracts necessary info by looking
 * at the rtm->rtm_addrs bits and store the requested sockaddrs in the pointers
 * passed (all of which must be valid).
 *
 * The bitmask of sockaddrs actually found in the message is returned, or zero
 * is returned in the case of an error.
 */
static int
rts_getaddrs(rt_msghdr_t *rtm, in6_addr_t *dst_addrp, in6_addr_t *gw_addrp,
    in6_addr_t *net_maskp, in6_addr_t *authorp, in6_addr_t *if_addrp,
    in6_addr_t *in_src_addrp, ushort_t *indexp, sa_family_t *afp,
    tsol_rtsecattr_t *rtsecattr, int *error)
{
	struct sockaddr *sa;
	int	i;
	int	addr_bits;
	int	length;
	int	found_addrs = 0;
	caddr_t	cp;
	size_t	size;
	struct sockaddr_dl *sdl;

	*dst_addrp = ipv6_all_zeros;
	*gw_addrp = ipv6_all_zeros;
	*net_maskp = ipv6_all_zeros;
	*authorp = ipv6_all_zeros;
	*if_addrp = ipv6_all_zeros;
	*in_src_addrp = ipv6_all_zeros;
	*indexp = 0;
	*afp = AF_UNSPEC;
	rtsecattr->rtsa_cnt = 0;
	*error = 0;

	/*
	 * At present we handle only RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_IFP,
	 * RTA_IFA and RTA_AUTHOR.  The rest will be added as we need them.
	 */
	cp = (caddr_t)&rtm[1];
	length = rtm->rtm_msglen;
	for (i = 0; (i < RTA_NUMBITS) && ((cp - (caddr_t)rtm) < length); i++) {
		/*
		 * The address family we are working with starts out as
		 * AF_UNSPEC, but is set to the one specified with the
		 * destination address.
		 *
		 * If the "working" address family that has been set to
		 * something other than AF_UNSPEC, then the address family of
		 * subsequent sockaddrs must either be AF_UNSPEC (for
		 * compatibility with older programs) or must be the same as our
		 * "working" one.
		 *
		 * This code assumes that RTA_DST (1) comes first in the loop.
		 */
		sa = (struct sockaddr *)cp;
		addr_bits = (rtm->rtm_addrs & (1 << i));
		if (addr_bits == 0)
			continue;
		switch (addr_bits) {
		case RTA_DST:
			size = rts_copyfromsockaddr(sa, dst_addrp);
			*afp = sa->sa_family;
			break;
		case RTA_GATEWAY:
			if (sa->sa_family != *afp && sa->sa_family != AF_UNSPEC)
				return (0);
			size = rts_copyfromsockaddr(sa, gw_addrp);
			break;
		case RTA_NETMASK:
			if (sa->sa_family != *afp && sa->sa_family != AF_UNSPEC)
				return (0);
			size = rts_copyfromsockaddr(sa, net_maskp);
			break;
		case RTA_IFP:
			if (sa->sa_family != AF_LINK &&
			    sa->sa_family != AF_UNSPEC)
				return (0);
			sdl = (struct sockaddr_dl *)cp;
			*indexp = sdl->sdl_index;
			size = sizeof (struct sockaddr_dl);
			break;
		case RTA_SRC:
			/* Source address of the incoming packet */
			size = rts_copyfromsockaddr(sa, in_src_addrp);
			*afp = sa->sa_family;
			break;
		case RTA_IFA:
			if (sa->sa_family != *afp && sa->sa_family != AF_UNSPEC)
				return (0);
			size = rts_copyfromsockaddr(sa, if_addrp);
			break;
		case RTA_AUTHOR:
			if (sa->sa_family != *afp && sa->sa_family != AF_UNSPEC)
				return (0);
			size = rts_copyfromsockaddr(sa, authorp);
			break;
		default:
			return (0);
		}
		if (size == 0)
			return (0);
		cp += size;
		found_addrs |= addr_bits;
	}

	/*
	 * Parse the routing message and look for any security-
	 * related attributes for the route.  For each valid
	 * attribute, allocate/obtain the corresponding kernel
	 * route security attributes.
	 */
	*error = tsol_rtsa_init(rtm, rtsecattr, cp);
	ASSERT(rtsecattr->rtsa_cnt <= TSOL_RTSA_REQUEST_MAX);

	return (found_addrs);
}

/*
 * Fills the message with the given info.
 */
static void
rts_fill_msg(int type, int rtm_addrs, ipaddr_t dst, ipaddr_t mask,
    ipaddr_t gateway, ipaddr_t src_addr, ipaddr_t brd_addr, ipaddr_t author,
    const ipif_t *ipif, mblk_t *mp, uint_t sacnt, const tsol_gc_t *gc)
{
	rt_msghdr_t	*rtm;
	sin_t		*sin;
	size_t		data_size, header_size;
	uchar_t		*cp;
	int		i;

	ASSERT(mp != NULL);
	ASSERT(sacnt == 0 || gc != NULL);
	/*
	 * First find the type of the message
	 * and its length.
	 */
	header_size = rts_header_msg_size(type);
	/*
	 * Now find the size of the data
	 * that follows the message header.
	 */
	data_size = rts_data_msg_size(rtm_addrs, AF_INET, sacnt);

	rtm = (rt_msghdr_t *)mp->b_rptr;
	mp->b_wptr = &mp->b_rptr[header_size];
	cp = mp->b_wptr;
	bzero(cp, data_size);
	for (i = 0; i < RTA_NUMBITS; i++) {
		sin = (sin_t *)cp;
		switch (rtm_addrs & (1 << i)) {
		case RTA_DST:
			sin->sin_addr.s_addr = dst;
			sin->sin_family = AF_INET;
			cp += sizeof (sin_t);
			break;
		case RTA_GATEWAY:
			sin->sin_addr.s_addr = gateway;
			sin->sin_family = AF_INET;
			cp += sizeof (sin_t);
			break;
		case RTA_NETMASK:
			sin->sin_addr.s_addr = mask;
			sin->sin_family = AF_INET;
			cp += sizeof (sin_t);
			break;
		case RTA_IFP:
			cp += ill_dls_info((struct sockaddr_dl *)cp, ipif);
			break;
		case RTA_IFA:
		case RTA_SRC:
			sin->sin_addr.s_addr = src_addr;
			sin->sin_family = AF_INET;
			cp += sizeof (sin_t);
			break;
		case RTA_AUTHOR:
			sin->sin_addr.s_addr = author;
			sin->sin_family = AF_INET;
			cp += sizeof (sin_t);
			break;
		case RTA_BRD:
			/*
			 * RTA_BRD is used typically to specify a point-to-point
			 * destination address.
			 */
			sin->sin_addr.s_addr = brd_addr;
			sin->sin_family = AF_INET;
			cp += sizeof (sin_t);
			break;
		}
	}

	if (gc != NULL) {
		rtm_ext_t *rtm_ext;
		struct rtsa_s *rp_dst;
		tsol_rtsecattr_t *rsap;
		int i;

		ASSERT(gc->gc_grp != NULL);
		ASSERT(RW_LOCK_HELD(&gc->gc_grp->gcgrp_rwlock));
		ASSERT(sacnt > 0);

		rtm_ext = (rtm_ext_t *)cp;
		rtm_ext->rtmex_type = RTMEX_GATEWAY_SECATTR;
		rtm_ext->rtmex_len = TSOL_RTSECATTR_SIZE(sacnt);

		rsap = (tsol_rtsecattr_t *)(rtm_ext + 1);
		rsap->rtsa_cnt = sacnt;
		rp_dst = rsap->rtsa_attr;

		for (i = 0; i < sacnt; i++, gc = gc->gc_next, rp_dst++) {
			ASSERT(gc->gc_db != NULL);
			bcopy(&gc->gc_db->gcdb_attr, rp_dst, sizeof (*rp_dst));
		}
		cp = (uchar_t *)rp_dst;
	}

	mp->b_wptr = cp;
	mp->b_cont = NULL;
	/*
	 * set the fields that are common to
	 * to different messages.
	 */
	rtm->rtm_msglen = (short)(header_size + data_size);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = (uchar_t)type;
}

/*
 * Allocates and initializes a routing socket message.
 */
mblk_t *
rts_alloc_msg(int type, int rtm_addrs, sa_family_t af, uint_t sacnt)
{
	size_t	length;
	mblk_t	*mp;

	length = RTS_MSG_SIZE(type, rtm_addrs, af, sacnt);
	mp = allocb(length, BPRI_MED);
	if (mp == NULL)
		return (mp);
	bzero(mp->b_rptr, length);
	return (mp);
}

/*
 * Returns the size of the routing
 * socket message header size.
 */
size_t
rts_header_msg_size(int type)
{
	switch (type) {
	case RTM_DELADDR:
	case RTM_NEWADDR:
		return (sizeof (ifa_msghdr_t));
	case RTM_IFINFO:
		return (sizeof (if_msghdr_t));
	default:
		return (sizeof (rt_msghdr_t));
	}
}

/*
 * Returns the size of the message needed with the given rtm_addrs and family.
 *
 * It is assumed that all of the sockaddrs (with the exception of RTA_IFP) are
 * of the same family (currently either AF_INET or AF_INET6).
 */
size_t
rts_data_msg_size(int rtm_addrs, sa_family_t af, uint_t sacnt)
{
	int	i;
	size_t	length = 0;

	for (i = 0; i < RTA_NUMBITS; i++) {
		switch (rtm_addrs & (1 << i)) {
		case RTA_IFP:
			length += sizeof (struct sockaddr_dl);
			break;
		case RTA_DST:
		case RTA_GATEWAY:
		case RTA_NETMASK:
		case RTA_SRC:
		case RTA_IFA:
		case RTA_AUTHOR:
		case RTA_BRD:
			ASSERT(af == AF_INET || af == AF_INET6);
			switch (af) {
			case AF_INET:
				length += sizeof (sin_t);
				break;
			case AF_INET6:
				length += sizeof (sin6_t);
				break;
			}
			break;
		}
	}
	if (sacnt > 0)
		length += sizeof (rtm_ext_t) + TSOL_RTSECATTR_SIZE(sacnt);

	return (length);
}

/*
 * This routine is called to generate a message to the routing
 * socket indicating that a redirect has occured, a routing lookup
 * has failed, or that a protocol has detected timeouts to a particular
 * destination. This routine is called for message types RTM_LOSING,
 * RTM_REDIRECT, and RTM_MISS.
 */
void
ip_rts_change(int type, ipaddr_t dst_addr, ipaddr_t gw_addr, ipaddr_t net_mask,
    ipaddr_t source, ipaddr_t author, int flags, int error, int rtm_addrs,
    ip_stack_t *ipst)
{
	rt_msghdr_t	*rtm;
	mblk_t		*mp;

	if (rtm_addrs == 0)
		return;
	mp = rts_alloc_msg(type, rtm_addrs, AF_INET, 0);
	if (mp == NULL)
		return;
	rts_fill_msg(type, rtm_addrs, dst_addr, net_mask, gw_addr, source, 0,
	    author, NULL, mp, 0, NULL);
	rtm = (rt_msghdr_t *)mp->b_rptr;
	rtm->rtm_flags = flags;
	rtm->rtm_errno = error;
	rtm->rtm_flags |= RTF_DONE;
	rtm->rtm_addrs = rtm_addrs;
	rts_queue_input(mp, NULL, AF_INET, ipst);
}

/*
 * This routine is called to generate a message to the routing
 * socket indicating that the status of a network interface has changed.
 * Message type generated RTM_IFINFO.
 */
void
ip_rts_ifmsg(const ipif_t *ipif)
{
	if_msghdr_t	*ifm;
	mblk_t		*mp;
	sa_family_t	af;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	/*
	 * This message should be generated only
	 * when the physical device is changing
	 * state.
	 */
	if (ipif->ipif_id != 0)
		return;
	if (ipif->ipif_isv6) {
		af = AF_INET6;
		mp = rts_alloc_msg(RTM_IFINFO, RTA_IFP, af, 0);
		if (mp == NULL)
			return;
		rts_fill_msg_v6(RTM_IFINFO, RTA_IFP, &ipv6_all_zeros,
		    &ipv6_all_zeros, &ipv6_all_zeros, &ipv6_all_zeros,
		    &ipv6_all_zeros, &ipv6_all_zeros, ipif, mp, 0, NULL);
	} else {
		af = AF_INET;
		mp = rts_alloc_msg(RTM_IFINFO, RTA_IFP, af, 0);
		if (mp == NULL)
			return;
		rts_fill_msg(RTM_IFINFO, RTA_IFP, 0, 0, 0, 0, 0, 0, ipif, mp,
		    0, NULL);
	}
	ifm = (if_msghdr_t *)mp->b_rptr;
	ifm->ifm_index = ipif->ipif_ill->ill_phyint->phyint_ifindex;
	ifm->ifm_flags = ipif->ipif_flags | ipif->ipif_ill->ill_flags |
	    ipif->ipif_ill->ill_phyint->phyint_flags;
	rts_getifdata(&ifm->ifm_data, ipif);
	ifm->ifm_addrs = RTA_IFP;
	rts_queue_input(mp, NULL, af, ipst);
}

/*
 * This is called to generate messages to the routing socket
 * indicating a network interface has had addresses associated with it.
 * The structure of the code is based on the 4.4BSD-Lite2 <net/rtsock.c>.
 */
void
ip_rts_newaddrmsg(int cmd, int error, const ipif_t *ipif)
{
	int		pass;
	int		ncmd;
	int		rtm_addrs;
	mblk_t		*mp;
	ifa_msghdr_t	*ifam;
	rt_msghdr_t	*rtm;
	sa_family_t	af;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	if (ipif->ipif_isv6)
		af = AF_INET6;
	else
		af = AF_INET;
	/*
	 * If the request is DELETE, send RTM_DELETE and RTM_DELADDR.
	 * if the request is ADD, send RTM_NEWADDR and RTM_ADD.
	 */
	for (pass = 1; pass < 3; pass++) {
		if ((cmd == RTM_ADD && pass == 1) ||
		    (cmd == RTM_DELETE && pass == 2)) {
			ncmd = ((cmd == RTM_ADD) ? RTM_NEWADDR : RTM_DELADDR);

			rtm_addrs = (RTA_IFA | RTA_NETMASK | RTA_BRD | RTA_IFP);
			mp = rts_alloc_msg(ncmd, rtm_addrs, af, 0);
			if (mp == NULL)
				continue;
			switch (af) {
			case AF_INET:
				rts_fill_msg(ncmd, rtm_addrs, 0,
				    ipif->ipif_net_mask, 0, ipif->ipif_lcl_addr,
				    ipif->ipif_pp_dst_addr, 0, ipif, mp,
				    0, NULL);
				break;
			case AF_INET6:
				rts_fill_msg_v6(ncmd, rtm_addrs,
				    &ipv6_all_zeros, &ipif->ipif_v6net_mask,
				    &ipv6_all_zeros, &ipif->ipif_v6lcl_addr,
				    &ipif->ipif_v6pp_dst_addr, &ipv6_all_zeros,
				    ipif, mp, 0, NULL);
				break;
			}
			ifam = (ifa_msghdr_t *)mp->b_rptr;
			ifam->ifam_index =
			    ipif->ipif_ill->ill_phyint->phyint_ifindex;
			ifam->ifam_metric = ipif->ipif_metric;
			ifam->ifam_flags = ((cmd == RTM_ADD) ? RTF_UP : 0);
			ifam->ifam_addrs = rtm_addrs;
			rts_queue_input(mp, NULL, af, ipst);
		}
		if ((cmd == RTM_ADD && pass == 2) ||
		    (cmd == RTM_DELETE && pass == 1)) {
			rtm_addrs = (RTA_DST | RTA_NETMASK);
			mp = rts_alloc_msg(cmd, rtm_addrs, af, 0);
			if (mp == NULL)
				continue;
			switch (af) {
			case AF_INET:
				rts_fill_msg(cmd, rtm_addrs,
				    ipif->ipif_lcl_addr, ipif->ipif_net_mask, 0,
				    0, 0, 0, NULL, mp, 0, NULL);
				break;
			case AF_INET6:
				rts_fill_msg_v6(cmd, rtm_addrs,
				    &ipif->ipif_v6lcl_addr,
				    &ipif->ipif_v6net_mask, &ipv6_all_zeros,
				    &ipv6_all_zeros, &ipv6_all_zeros,
				    &ipv6_all_zeros, NULL, mp, 0, NULL);
				break;
			}
			rtm = (rt_msghdr_t *)mp->b_rptr;
			rtm->rtm_index =
			    ipif->ipif_ill->ill_phyint->phyint_ifindex;
			rtm->rtm_flags = ((cmd == RTM_ADD) ? RTF_UP : 0);
			rtm->rtm_errno = error;
			if (error == 0)
				rtm->rtm_flags |= RTF_DONE;
			rtm->rtm_addrs = rtm_addrs;
			rts_queue_input(mp, NULL, af, ipst);
		}
	}
}

/*
 * Based on the address family specified in a sockaddr, copy the address field
 * into an in6_addr_t.
 *
 * In the case of AF_UNSPEC, we assume the family is actually AF_INET for
 * compatibility with programs that leave the family cleared in the sockaddr.
 * Callers of rts_copyfromsockaddr should check the family themselves if they
 * wish to verify its value.
 *
 * In the case of AF_INET6, a check is made to ensure that address is not an
 * IPv4-mapped address.
 */
size_t
rts_copyfromsockaddr(struct sockaddr *sa, in6_addr_t *addrp)
{
	switch (sa->sa_family) {
	case AF_INET:
	case AF_UNSPEC:
		IN6_IPADDR_TO_V4MAPPED(((sin_t *)sa)->sin_addr.s_addr, addrp);
		return (sizeof (sin_t));
	case AF_INET6:
		*addrp = ((sin6_t *)sa)->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(addrp))
			return (0);
		return (sizeof (sin6_t));
	default:
		return (0);
	}
}

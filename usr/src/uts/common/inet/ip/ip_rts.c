/*
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
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

/*
 * This file contains routines that processes routing socket requests.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/strsubr.h>
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
    ipaddr_t author, ipaddr_t ifaddr, const ill_t *ill, mblk_t *mp,
    const tsol_gc_t *);
static int	rts_getaddrs(rt_msghdr_t *rtm, in6_addr_t *dst_addrp,
    in6_addr_t *gw_addrp, in6_addr_t *net_maskp, in6_addr_t *authorp,
    in6_addr_t *if_addrp, in6_addr_t *src_addrp, ushort_t *indexp,
    sa_family_t *afp, tsol_rtsecattr_t *rtsecattr, int *error);
static void	rts_getifdata(if_data_t *if_data, const ipif_t *ipif);
static int	rts_getmetrics(ire_t *ire, ill_t *ill, rt_metrics_t *metrics);
static mblk_t	*rts_rtmget(mblk_t *mp, ire_t *ire, ire_t *ifire,
    const in6_addr_t *setsrc, tsol_ire_gw_secattr_t *attrp, sa_family_t af);
static void	rts_setmetrics(ire_t *ire, uint_t which, rt_metrics_t *metrics);
static ire_t	*ire_lookup_v4(ipaddr_t dst_addr, ipaddr_t net_mask,
    ipaddr_t gw_addr, const ill_t *ill, zoneid_t zoneid,
    const ts_label_t *tsl, int match_flags, ip_stack_t *ipst, ire_t **pifire,
    ipaddr_t *v4setsrcp, tsol_ire_gw_secattr_t **gwattrp);
static ire_t	*ire_lookup_v6(const in6_addr_t *dst_addr_v6,
    const in6_addr_t *net_mask_v6, const in6_addr_t *gw_addr_v6,
    const ill_t *ill, zoneid_t zoneid, const ts_label_t *tsl, int match_flags,
    ip_stack_t *ipst, ire_t **pifire,
    in6_addr_t *v6setsrcp, tsol_ire_gw_secattr_t **gwattrp);

/*
 * Send `mp' to all eligible routing queues.  A queue is ineligible if:
 *
 *  1. SO_USELOOPBACK is off and it is not the originating queue.
 *  2. RTA_UNDER_IPMP is on and RTSQ_UNDER_IPMP is not set in `flags'.
 *  3. RTA_UNDER_IPMP is off and RTSQ_NORMAL is not set in `flags'.
 *  4. It is not the same address family as `af', and `af' isn't AF_UNSPEC.
 */
void
rts_queue_input(mblk_t *mp, conn_t *o_connp, sa_family_t af, uint_t flags,
    ip_stack_t *ipst)
{
	mblk_t	*mp1;
	conn_t 	*connp, *next_connp;

	/*
	 * Since we don't have an ill_t here, RTSQ_DEFAULT must already be
	 * resolved to one or more of RTSQ_NORMAL|RTSQ_UNDER_IPMP at this point.
	 */
	ASSERT(!(flags & RTSQ_DEFAULT));

	mutex_enter(&ipst->ips_rts_clients->connf_lock);
	connp = ipst->ips_rts_clients->connf_head;

	for (; connp != NULL; connp = next_connp) {
		next_connp = connp->conn_next;
		/*
		 * If there was a family specified when this routing socket was
		 * created and it doesn't match the family of the message to
		 * copy, then continue.
		 */
		if ((connp->conn_proto != AF_UNSPEC) &&
		    (connp->conn_proto != af))
			continue;

		/*
		 * Queue the message only if the conn_t and flags match.
		 */
		if (connp->conn_rtaware & RTAW_UNDER_IPMP) {
			if (!(flags & RTSQ_UNDER_IPMP))
				continue;
		} else {
			if (!(flags & RTSQ_NORMAL))
				continue;
		}
		/*
		 * For the originating queue, we only copy the message upstream
		 * if loopback is set.  For others reading on the routing
		 * socket, we check if there is room upstream for a copy of the
		 * message.
		 */
		if ((o_connp == connp) && connp->conn_useloopback == 0) {
			connp = connp->conn_next;
			continue;
		}
		CONN_INC_REF(connp);
		mutex_exit(&ipst->ips_rts_clients->connf_lock);
		/* Pass to rts_input */
		if (IPCL_IS_NONSTR(connp) ? !connp->conn_flow_cntrld :
		    canputnext(connp->conn_rq)) {
			mp1 = dupmsg(mp);
			if (mp1 == NULL)
				mp1 = copymsg(mp);
			/* Note that we pass a NULL ira to rts_input */
			if (mp1 != NULL)
				(connp->conn_recv)(connp, mp1, NULL, NULL);
		}

		mutex_enter(&ipst->ips_rts_clients->connf_lock);
		/* reload next_connp since conn_next may have changed */
		next_connp = connp->conn_next;
		CONN_DEC_REF(connp);
	}
	mutex_exit(&ipst->ips_rts_clients->connf_lock);
	freemsg(mp);
}

/*
 * Takes an ire and sends an ack to all the routing sockets. This
 * routine is used
 * - when a route is created/deleted through the ioctl interface.
 * - when a stale redirect is deleted
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

	ASSERT(!(ire->ire_type & IRE_IF_CLONE));

	if (ire->ire_flags & RTF_SETSRC)
		rtm_addrs |= RTA_SRC;

	switch (ire->ire_ipversion) {
	case IPV4_VERSION:
		af = AF_INET;
		mp = rts_alloc_msg(type, rtm_addrs, af, 0);
		if (mp == NULL)
			return;
		rts_fill_msg(type, rtm_addrs, ire->ire_addr, ire->ire_mask,
		    ire->ire_gateway_addr, ire->ire_setsrc_addr, 0, 0, 0, NULL,
		    mp, NULL);
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
		    &ire->ire_setsrc_addr_v6, &ipv6_all_zeros, &ipv6_all_zeros,
		    &ipv6_all_zeros, NULL, mp, NULL);
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
	rts_queue_input(mp, NULL, af, RTSQ_ALL, ipst);
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

	connp->conn_useloopback = 1;
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
 */
int
ip_rts_request_common(mblk_t *mp, conn_t *connp, cred_t *ioc_cr)
{
	rt_msghdr_t	*rtm = NULL;
	in6_addr_t	dst_addr_v6;
	in6_addr_t	src_addr_v6;
	in6_addr_t	gw_addr_v6;
	in6_addr_t	net_mask_v6;
	in6_addr_t	author_v6;
	in6_addr_t	if_addr_v6;
	mblk_t		*mp1;
	ire_t		*ire = NULL;
	ire_t		*ifire = NULL;
	ipaddr_t	v4setsrc;
	in6_addr_t	v6setsrc = ipv6_all_zeros;
	tsol_ire_gw_secattr_t *gwattr = NULL;
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
	boolean_t	gcgrp_xtraref = B_FALSE;
	tsol_gcgrp_addr_t ga;
	tsol_rtsecattr_t rtsecattr;
	struct rtsa_s	*rtsap = NULL;
	tsol_gcgrp_t	*gcgrp = NULL;
	tsol_gc_t	*gc = NULL;
	ts_label_t	*tsl = NULL;
	zoneid_t	zoneid;
	ip_stack_t	*ipst;
	ill_t   	*ill = NULL;

	zoneid = connp->conn_zoneid;
	ipst = connp->conn_netstack->netstack_ip;

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

	/* Handle RTA_IFP */
	if (index != 0) {
		ipif_t		*ipif;
lookup:
		ill = ill_lookup_on_ifindex(index, af == AF_INET6, ipst);
		if (ill == NULL) {
			error = EINVAL;
			goto done;
		}

		/*
		 * Since all interfaces in an IPMP group must be equivalent,
		 * we prevent changes to a specific underlying interface's
		 * routing configuration.  However, for backward compatibility,
		 * we intepret a request to add a route on an underlying
		 * interface as a request to add a route on its IPMP interface.
		 */
		if (IS_UNDER_IPMP(ill)) {
			switch (rtm->rtm_type) {
			case RTM_CHANGE:
			case RTM_DELETE:
				error = EINVAL;
				goto done;
			case RTM_ADD:
				index = ipmp_ill_get_ipmp_ifindex(ill);
				ill_refrele(ill);
				if (index == 0) {
					ill = NULL; /* already refrele'd */
					error = EINVAL;
					goto done;
				}
				goto lookup;
			}
		}

		match_flags |= MATCH_IRE_ILL;
		/*
		 * This provides the same zoneid as in Solaris 10
		 * that -ifp picks the zoneid from the first ipif on the ill.
		 * But it might not be useful since the first ipif will always
		 * have the same zoneid as the ill.
		 */
		ipif = ipif_get_next_ipif(NULL, ill);
		if (ipif != NULL) {
			zoneid = ipif->ipif_zoneid;
			ipif_refrele(ipif);
		}
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
				uint_t type;

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
				 * valid, local one. Only allow IFF_UP ones
				 */
				type = ip_type_v4(src_addr, ipst);
				if (!(type & (IRE_LOCAL|IRE_LOOPBACK))) {
					error = EADDRNOTAVAIL;
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
			    rtm->rtm_flags, ill, &ire, B_FALSE,
			    rtsap, ipst, zoneid);
			if (ill != NULL)
				ASSERT(!MUTEX_HELD(&ill->ill_lock));
			break;
		case AF_INET6:
			if (!IN6_IS_ADDR_UNSPECIFIED(&src_addr_v6)) {
				uint_t type;

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
				 * valid, local one. Only allow UP ones.
				 */
				type = ip_type_v6(&src_addr_v6, ipst);
				if (!(type & (IRE_LOCAL|IRE_LOOPBACK))) {
					error = EADDRNOTAVAIL;
					goto done;
				}

				error = ip_rt_add_v6(&dst_addr_v6, &net_mask_v6,
				    &gw_addr_v6, &src_addr_v6, rtm->rtm_flags,
				    ill, &ire, rtsap, ipst, zoneid);
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
			    ill, &ire, rtsap, ipst, zoneid);
			if (ill != NULL)
				ASSERT(!MUTEX_HELD(&ill->ill_lock));
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
			    found_addrs, rtm->rtm_flags, ill, B_FALSE,
			    ipst, zoneid);
			break;
		case AF_INET6:
			error = ip_rt_delete_v6(&dst_addr_v6, &net_mask_v6,
			    &gw_addr_v6, found_addrs, rtm->rtm_flags, ill,
			    ipst, zoneid);
			break;
		}
		break;
	case RTM_GET:
	case RTM_CHANGE:
		/*
		 * In the case of RTM_GET, the forwarding table should be
		 * searched recursively.  Also, if a gateway was
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
			match_flags |= MATCH_IRE_SECATTR;
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
		 * entry, then look for any other type of IRE.
		 */
		switch (af) {
		case AF_INET:
			if (net_mask == IP_HOST_MASK) {
				ire = ire_ftable_lookup_v4(dst_addr, 0, gw_addr,
				    IRE_LOCAL | IRE_LOOPBACK, NULL, zoneid,
				    tsl, match_flags_local, 0, ipst, NULL);
			}
			if (ire == NULL) {
				ire = ire_lookup_v4(dst_addr, net_mask,
				    gw_addr, ill, zoneid, tsl, match_flags,
				    ipst, &ifire, &v4setsrc, &gwattr);
				IN6_IPADDR_TO_V4MAPPED(v4setsrc, &v6setsrc);
			}
			break;
		case AF_INET6:
			if (IN6_ARE_ADDR_EQUAL(&net_mask_v6, &ipv6_all_ones)) {
				ire = ire_ftable_lookup_v6(&dst_addr_v6, NULL,
				    &gw_addr_v6, IRE_LOCAL | IRE_LOOPBACK, NULL,
				    zoneid, tsl, match_flags_local, 0, ipst,
				    NULL);
			}
			if (ire == NULL) {
				ire = ire_lookup_v6(&dst_addr_v6,
				    &net_mask_v6, &gw_addr_v6, ill, zoneid,
				    tsl, match_flags, ipst, &ifire, &v6setsrc,
				    &gwattr);
			}
			break;
		}
		if (tsl != NULL && tsl != crgetlabel(ioc_cr))
			label_rele(tsl);

		if (ire == NULL) {
			error = ESRCH;
			goto done;
		}
		/*
		 * Want to return failure if we get an IRE_NOROUTE from
		 * ire_route_recursive
		 */
		if (ire->ire_type & IRE_NOROUTE) {
			ire_refrele(ire);
			ire = NULL;
			error = ESRCH;
			goto done;
		}

		/* we know the IRE before we come here */
		switch (rtm->rtm_type) {
		case RTM_GET:
			mp1 = rts_rtmget(mp, ire, ifire, &v6setsrc, gwattr, af);
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
				    (ire->ire_setsrc_addr != src_addr)) {
					if (src_addr != INADDR_ANY) {
						uint_t type;

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
						 * Also check that the
						 * supplied addr is a valid
						 * local address.
						 */
						type = ip_type_v4(src_addr,
						    ipst);
						if (!(type &
						    (IRE_LOCAL|IRE_LOOPBACK))) {
							error = EADDRNOTAVAIL;
							goto done;
						}
						ire->ire_flags |= RTF_SETSRC;
						ire->ire_setsrc_addr =
						    src_addr;
					} else {
						ire->ire_flags &= ~RTF_SETSRC;
						ire->ire_setsrc_addr =
						    INADDR_ANY;
					}
					/*
					 * Let conn_ixa caching know that
					 * source address selection changed
					 */
					ip_update_source_selection(ipst);
				}
				ire_flush_cache_v4(ire, IRE_FLUSH_GWCHANGE);
				break;
			case AF_INET6:
				mutex_enter(&ire->ire_lock);
				if ((found_addrs & RTA_GATEWAY) != 0 &&
				    !IN6_ARE_ADDR_EQUAL(
				    &ire->ire_gateway_addr_v6, &gw_addr_v6)) {
					ire->ire_gateway_addr_v6 = gw_addr_v6;
				}
				mutex_exit(&ire->ire_lock);

				if (rtsap != NULL) {
					ga.ga_af = AF_INET6;
					mutex_enter(&ire->ire_lock);
					ga.ga_addr = ire->ire_gateway_addr_v6;
					mutex_exit(&ire->ire_lock);

					gcgrp = gcgrp_lookup(&ga, B_TRUE);
					if (gcgrp == NULL) {
						error = ENOMEM;
						goto done;
					}
				}

				if ((found_addrs & RTA_SRC) != 0 &&
				    (rtm->rtm_flags & RTF_SETSRC) != 0 &&
				    !IN6_ARE_ADDR_EQUAL(
				    &ire->ire_setsrc_addr_v6, &src_addr_v6)) {
					if (!IN6_IS_ADDR_UNSPECIFIED(
					    &src_addr_v6)) {
						uint_t type;

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
							error = EINVAL;
							goto done;
						}
						/*
						 * Also check that the
						 * supplied addr is a valid
						 * local address.
						 */
						type = ip_type_v6(&src_addr_v6,
						    ipst);
						if (!(type &
						    (IRE_LOCAL|IRE_LOOPBACK))) {
							error = EADDRNOTAVAIL;
							goto done;
						}
						mutex_enter(&ire->ire_lock);
						ire->ire_flags |= RTF_SETSRC;
						ire->ire_setsrc_addr_v6 =
						    src_addr_v6;
						mutex_exit(&ire->ire_lock);
					} else {
						mutex_enter(&ire->ire_lock);
						ire->ire_flags &= ~RTF_SETSRC;
						ire->ire_setsrc_addr_v6 =
						    ipv6_all_zeros;
						mutex_exit(&ire->ire_lock);
					}
					/*
					 * Let conn_ixa caching know that
					 * source address selection changed
					 */
					ip_update_source_selection(ipst);
				}
				ire_flush_cache_v6(ire, IRE_FLUSH_GWCHANGE);
				break;
			}

			if (rtsap != NULL) {
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
				    ire->ire_ipversion, gc)) != 0) {
					if (gc != NULL) {
						GC_REFRELE(gc);
					} else {
						/* gc_create failed */
						error = ENOMEM;
					}
					goto done;
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
	if (ifire != NULL)
		ire_refrele(ifire);
	if (ill != NULL)
		ill_refrele(ill);

	if (gcgrp_xtraref)
		GCGRP_REFRELE(gcgrp);

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
		rts_queue_input(mp, connp, af, RTSQ_ALL, ipst);
	}
	return (error);
}

/*
 * Helper function that can do recursive lookups including when
 * MATCH_IRE_GW and/or MATCH_IRE_MASK is set.
 */
static ire_t *
ire_lookup_v4(ipaddr_t dst_addr, ipaddr_t net_mask, ipaddr_t gw_addr,
    const ill_t *ill, zoneid_t zoneid, const ts_label_t *tsl,
    int match_flags, ip_stack_t *ipst, ire_t **pifire, ipaddr_t *v4setsrcp,
    tsol_ire_gw_secattr_t **gwattrp)
{
	ire_t		*ire;
	ire_t		*ifire = NULL;
	uint_t		ire_type;

	*pifire = NULL;
	*v4setsrcp = INADDR_ANY;
	*gwattrp = NULL;

	/* Skip IRE_IF_CLONE */
	match_flags |= MATCH_IRE_TYPE;
	ire_type = (IRE_ONLINK|IRE_OFFLINK) & ~IRE_IF_CLONE;

	/*
	 * ire_route_recursive can't match gateway or mask thus if they are
	 * set we have to do two steps of lookups
	 */
	if (match_flags & (MATCH_IRE_GW|MATCH_IRE_MASK)) {
		ire = ire_ftable_lookup_v4(dst_addr, net_mask, gw_addr,
		    ire_type, ill, zoneid, tsl, match_flags, 0, ipst, NULL);

		if (ire == NULL ||(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)))
			return (ire);

		if (ire->ire_type & IRE_ONLINK)
			return (ire);

		if (ire->ire_flags & RTF_SETSRC) {
			ASSERT(ire->ire_setsrc_addr != INADDR_ANY);
			*v4setsrcp = ire->ire_setsrc_addr;
			v4setsrcp = NULL;
		}

		/* The first ire_gw_secattr is passed back */
		if (ire->ire_gw_secattr != NULL) {
			*gwattrp = ire->ire_gw_secattr;
			gwattrp = NULL;
		}

		/* Look for an interface ire recursively based on the gateway */
		dst_addr = ire->ire_gateway_addr;
		match_flags &= ~(MATCH_IRE_GW|MATCH_IRE_MASK);
		/*
		 * Don't allow anything unusual past the first iteration.
		 * After the first lookup, we should no longer look for
		 * (IRE_LOCAL|IRE_LOOPBACK|IRE_BROADCAST) or RTF_INDIRECT
		 * routes.
		 *
		 * In addition, after we have found a direct IRE_OFFLINK,
		 * we should only look for interface or clone routes.
		 */
		match_flags |= MATCH_IRE_DIRECT; /* no more RTF_INDIRECTs */

		if ((ire->ire_type & IRE_OFFLINK) &&
		    !(ire->ire_flags & RTF_INDIRECT)) {
			ire_type = IRE_IF_ALL;
		} else {
			/*
			 * no more local, loopback, broadcast routes
			 */
			if (!(match_flags & MATCH_IRE_TYPE))
				ire_type = (IRE_OFFLINK|IRE_ONLINK);
			ire_type &= ~(IRE_LOCAL|IRE_LOOPBACK|IRE_BROADCAST);
		}
		match_flags |= MATCH_IRE_TYPE;

		ifire = ire_route_recursive_v4(dst_addr, ire_type, ill, zoneid,
		    tsl, match_flags, IRR_INCOMPLETE, 0, ipst, v4setsrcp,
		    gwattrp, NULL);
	} else {
		ire = ire_route_recursive_v4(dst_addr, ire_type, ill, zoneid,
		    tsl, match_flags, IRR_INCOMPLETE, 0, ipst, v4setsrcp,
		    gwattrp, NULL);
	}
	*pifire = ifire;
	return (ire);
}

static ire_t *
ire_lookup_v6(const in6_addr_t *dst_addr_v6,
    const in6_addr_t *net_mask_v6, const in6_addr_t *gw_addr_v6,
    const ill_t *ill, zoneid_t zoneid, const ts_label_t *tsl, int match_flags,
    ip_stack_t *ipst, ire_t **pifire,
    in6_addr_t *v6setsrcp, tsol_ire_gw_secattr_t **gwattrp)
{
	ire_t		*ire;
	ire_t		*ifire = NULL;
	uint_t		ire_type;

	*pifire = NULL;
	*v6setsrcp = ipv6_all_zeros;
	*gwattrp = NULL;

	/* Skip IRE_IF_CLONE */
	match_flags |= MATCH_IRE_TYPE;
	ire_type = (IRE_ONLINK|IRE_OFFLINK) & ~IRE_IF_CLONE;

	/*
	 * ire_route_recursive can't match gateway or mask thus if they are
	 * set we have to do two steps of lookups
	 */
	if (match_flags & (MATCH_IRE_GW|MATCH_IRE_MASK)) {
		in6_addr_t dst;

		ire = ire_ftable_lookup_v6(dst_addr_v6, net_mask_v6,
		    gw_addr_v6, ire_type, ill, zoneid, tsl, match_flags, 0,
		    ipst, NULL);

		if (ire == NULL ||(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)))
			return (ire);

		if (ire->ire_type & IRE_ONLINK)
			return (ire);

		if (ire->ire_flags & RTF_SETSRC) {
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(
			    &ire->ire_setsrc_addr_v6));
			*v6setsrcp = ire->ire_setsrc_addr_v6;
			v6setsrcp = NULL;
		}

		/* The first ire_gw_secattr is passed back */
		if (ire->ire_gw_secattr != NULL) {
			*gwattrp = ire->ire_gw_secattr;
			gwattrp = NULL;
		}

		mutex_enter(&ire->ire_lock);
		dst = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
		match_flags &= ~(MATCH_IRE_GW|MATCH_IRE_MASK);
		/*
		 * Don't allow anything unusual past the first iteration.
		 * After the first lookup, we should no longer look for
		 * (IRE_LOCAL|IRE_LOOPBACK|IRE_BROADCAST) or RTF_INDIRECT
		 * routes.
		 *
		 * In addition, after we have found a direct IRE_OFFLINK,
		 * we should only look for interface or clone routes.
		 */
		match_flags |= MATCH_IRE_DIRECT; /* no more RTF_INDIRECTs */

		if ((ire->ire_type & IRE_OFFLINK) &&
		    !(ire->ire_flags & RTF_INDIRECT)) {
			ire_type = IRE_IF_ALL;
		} else {
			/*
			 * no more local, loopback routes
			 */
			if (!(match_flags & MATCH_IRE_TYPE))
				ire_type = (IRE_OFFLINK|IRE_ONLINK);
			ire_type &= ~(IRE_LOCAL|IRE_LOOPBACK);
		}
		match_flags |= MATCH_IRE_TYPE;

		ifire = ire_route_recursive_v6(&dst, ire_type, ill, zoneid, tsl,
		    match_flags, IRR_INCOMPLETE, 0, ipst, v6setsrcp, gwattrp,
		    NULL);
	} else {
		ire = ire_route_recursive_v6(dst_addr_v6, ire_type, ill, zoneid,
		    tsl, match_flags, IRR_INCOMPLETE, 0, ipst, v6setsrcp,
		    gwattrp, NULL);
	}
	*pifire = ifire;
	return (ire);
}


/*
 * Handle IP_IOC_RTS_REQUEST ioctls
 */
int
ip_rts_request(queue_t *q, mblk_t *mp, cred_t *ioc_cr)
{
	conn_t	*connp = Q_TO_CONN(q);
	IOCP	iocp = (IOCP)mp->b_rptr;
	mblk_t	*mp1, *ioc_mp = mp;
	int	error = 0;
	ip_stack_t	*ipst;

	ipst = connp->conn_netstack->netstack_ip;

	ASSERT(mp->b_cont != NULL);
	/* ioc_mp holds mp */
	mp = mp->b_cont;

	/*
	 * The Routing Socket data starts on
	 * next block. If there is no next block
	 * this is an indication from routing module
	 * that it is a routing socket stream queue.
	 * We need to support that for compatibility with SDP since
	 * it has a contract private interface to use IP_IOC_RTS_REQUEST.
	 * Note: SDP no longer uses IP_IOC_RTS_REQUEST - we can remove this.
	 */
	if (mp->b_cont == NULL) {
		/*
		 * This is a message from SDP
		 * indicating that this is a Routing Socket
		 * Stream. Insert this conn_t in routing
		 * socket client list.
		 */
		connp->conn_useloopback = 1;
		ipcl_hash_insert_wildcard(ipst->ips_rts_clients, connp);
		goto done;
	}
	mp1 = dupmsg(mp->b_cont);
	if (mp1 == NULL) {
		error  = ENOBUFS;
		goto done;
	}
	mp = mp1;

	error = ip_rts_request_common(mp, connp, ioc_cr);
done:
	iocp->ioc_error = error;
	ioc_mp->b_datap->db_type = M_IOCACK;
	if (iocp->ioc_error != 0)
		iocp->ioc_count = 0;
	/* Note that we pass a NULL ira to rts_input */
	(connp->conn_recv)(connp, ioc_mp, NULL, NULL);

	/* conn was refheld in ip_wput_ioctl. */
	CONN_DEC_IOCTLREF(connp);
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
rts_rtmget(mblk_t *mp, ire_t *ire, ire_t *ifire, const in6_addr_t *setsrc,
    tsol_ire_gw_secattr_t *attrp, sa_family_t af)
{
	rt_msghdr_t	*rtm;
	rt_msghdr_t	*new_rtm;
	mblk_t		*new_mp;
	int		rtm_addrs;
	int		rtm_flags;
	tsol_gc_t	*gc = NULL;
	tsol_gcgrp_t	*gcgrp = NULL;
	ill_t		*ill;
	ipif_t		*ipif = NULL;
	ipaddr_t	brdaddr;	/* IFF_POINTOPOINT destination */
	ipaddr_t	ifaddr;
	in6_addr_t	brdaddr6;	/* IFF_POINTOPOINT destination */
	in6_addr_t	ifaddr6;
	ipaddr_t	v4setsrc;

	rtm = (rt_msghdr_t *)mp->b_rptr;

	/*
	 * Find the ill used to send packets. This will be NULL in case
	 * of a reject or blackhole.
	 */
	if (ifire != NULL)
		ill = ire_nexthop_ill(ifire);
	else
		ill = ire_nexthop_ill(ire);

	if (attrp != NULL) {
		mutex_enter(&attrp->igsa_lock);
		if ((gc = attrp->igsa_gc) != NULL) {
			gcgrp = gc->gc_grp;
			ASSERT(gcgrp != NULL);
			rw_enter(&gcgrp->gcgrp_rwlock, RW_READER);
		}
		mutex_exit(&attrp->igsa_lock);
	}

	/*
	 * Always return RTA_DST, RTA_GATEWAY and RTA_NETMASK.
	 *
	 * The 4.4BSD-Lite2 code (net/rtsock.c) returns both
	 * RTA_IFP and RTA_IFA if either is defined, and also
	 * returns RTA_BRD if the appropriate interface is
	 * point-to-point.
	 */
	rtm_addrs = (RTA_DST | RTA_GATEWAY | RTA_NETMASK);
	if ((rtm->rtm_addrs & (RTA_IFP | RTA_IFA)) && ill != NULL) {
		rtm_addrs |= (RTA_IFP | RTA_IFA);
		/*
		 * We associate an IRE with an ILL, hence we don't exactly
		 * know what might make sense for RTA_IFA and RTA_BRD. We
		 * pick the first ipif on the ill.
		 */
		ipif = ipif_get_next_ipif(NULL, ill);
		if (ipif != NULL) {
			if (ipif->ipif_isv6)
				ifaddr6 = ipif->ipif_v6lcl_addr;
			else
				ifaddr = ipif->ipif_lcl_addr;
			if (ipif->ipif_flags & IPIF_POINTOPOINT) {
				rtm_addrs |= RTA_BRD;
				if (ipif->ipif_isv6)
					brdaddr6 = ipif->ipif_v6pp_dst_addr;
				else
					brdaddr = ipif->ipif_pp_dst_addr;
			}
			ipif_refrele(ipif);
		}
	}

	new_mp = rts_alloc_msg(RTM_GET, rtm_addrs, af, gc != NULL ? 1 : 0);
	if (new_mp == NULL) {
		if (gcgrp != NULL)
			rw_exit(&gcgrp->gcgrp_rwlock);
		if (ill != NULL)
			ill_refrele(ill);
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
		IN6_V4MAPPED_TO_IPADDR(setsrc, v4setsrc);
		if (v4setsrc != INADDR_ANY)
			rtm_addrs |= RTA_SRC;

		rtm_flags = ire->ire_flags;
		rts_fill_msg(RTM_GET, rtm_addrs, ire->ire_addr,
		    ire->ire_mask, ire->ire_gateway_addr, v4setsrc,
		    brdaddr, 0, ifaddr, ill, new_mp, gc);
		break;
	case AF_INET6:
		if (!IN6_IS_ADDR_UNSPECIFIED(setsrc))
			rtm_addrs |= RTA_SRC;

		rtm_flags = ire->ire_flags;
		rts_fill_msg_v6(RTM_GET, rtm_addrs, &ire->ire_addr_v6,
		    &ire->ire_mask_v6, &ire->ire_gateway_addr_v6,
		    setsrc, &brdaddr6, &ipv6_all_zeros,
		    &ifaddr6, ill, new_mp, gc);
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
	new_rtm->rtm_inits = rts_getmetrics(ire, ill, &new_rtm->rtm_rmx);
	if (ill != NULL)
		ill_refrele(ill);
	return (new_mp);
}

/*
 * Fill the given if_data_t with interface statistics.
 */
static void
rts_getifdata(if_data_t *if_data, const ipif_t *ipif)
{
	if_data->ifi_type = ipif->ipif_ill->ill_type;
						/* ethernet, tokenring, etc */
	if_data->ifi_addrlen = 0;		/* media address length */
	if_data->ifi_hdrlen = 0;		/* media header length */
	if_data->ifi_mtu = ipif->ipif_ill->ill_mtu;	/* mtu */
						/* metric (external only) */
	if_data->ifi_metric = ipif->ipif_ill->ill_metric;
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
	ill_t		*ill;
	ifrt_t		*ifrt;
	mblk_t		*mp;
	in6_addr_t	gw_addr_v6;

	/* Need to add back some metrics to the IRE? */
	/*
	 * Bypass obtaining the lock and searching ill_saved_ire_mp in the
	 * common case of no metrics.
	 */
	if (which == 0)
		return;
	ire->ire_metrics.iulp_set = B_TRUE;

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
		ire->ire_metrics.iulp_mtu = metrics->rmx_mtu;
	if (which & RTV_RTT)
		ire->ire_metrics.iulp_rtt = rtt;
	if (which & RTV_SSTHRESH)
		ire->ire_metrics.iulp_ssthresh = metrics->rmx_ssthresh;
	if (which & RTV_RTTVAR)
		ire->ire_metrics.iulp_rtt_sd = rtt_sd;
	if (which & RTV_SPIPE)
		ire->ire_metrics.iulp_spipe = metrics->rmx_sendpipe;
	if (which & RTV_RPIPE)
		ire->ire_metrics.iulp_rpipe = metrics->rmx_recvpipe;
	mutex_exit(&ire->ire_lock);

	/*
	 * Search through the ifrt_t chain hanging off the ILL in order to
	 * reflect the metric change there.
	 */
	ill = ire->ire_ill;
	if (ill == NULL)
		return;
	ASSERT((ill->ill_isv6 && ire->ire_ipversion == IPV6_VERSION) ||
	    ((!ill->ill_isv6 && ire->ire_ipversion == IPV4_VERSION)));
	if (ill->ill_isv6) {
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
	}
	mutex_enter(&ill->ill_saved_ire_lock);
	for (mp = ill->ill_saved_ire_mp; mp != NULL; mp = mp->b_cont) {
		/*
		 * On a given ill, the tuple of address, gateway, mask,
		 * ire_type and zoneid unique for each saved IRE.
		 */
		ifrt = (ifrt_t *)mp->b_rptr;
		if (ill->ill_isv6) {
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
		if (ifrt->ifrt_zoneid != ire->ire_zoneid ||
		    ifrt->ifrt_type != ire->ire_type)
			continue;

		if (which & RTV_MTU)
			ifrt->ifrt_metrics.iulp_mtu = metrics->rmx_mtu;
		if (which & RTV_RTT)
			ifrt->ifrt_metrics.iulp_rtt = rtt;
		if (which & RTV_SSTHRESH) {
			ifrt->ifrt_metrics.iulp_ssthresh =
			    metrics->rmx_ssthresh;
		}
		if (which & RTV_RTTVAR)
			ifrt->ifrt_metrics.iulp_rtt_sd = metrics->rmx_rttvar;
		if (which & RTV_SPIPE)
			ifrt->ifrt_metrics.iulp_spipe = metrics->rmx_sendpipe;
		if (which & RTV_RPIPE)
			ifrt->ifrt_metrics.iulp_rpipe = metrics->rmx_recvpipe;
		break;
	}
	mutex_exit(&ill->ill_saved_ire_lock);

	/*
	 * Update any IRE_IF_CLONE hanging created from this IRE_IF so they
	 * get any new iulp_mtu.
	 * We do that by deleting them; ire_create_if_clone will pick
	 * up the new metrics.
	 */
	if ((ire->ire_type & IRE_INTERFACE) && ire->ire_dep_children != 0)
		ire_dep_delete_if_clone(ire);
}

/*
 * Get the metrics from a forwarding table route.
 */
static int
rts_getmetrics(ire_t *ire, ill_t *ill, rt_metrics_t *metrics)
{
	int	metrics_set = 0;

	bzero(metrics, sizeof (rt_metrics_t));

	/*
	 * iulp_rtt and iulp_rtt_sd are in milliseconds, but 4.4BSD-Lite2's
	 * <net/route.h> says: rmx_rtt and rmx_rttvar are stored as
	 * microseconds.
	 */
	metrics->rmx_rtt = ire->ire_metrics.iulp_rtt * 1000;
	metrics_set |= RTV_RTT;
	if (ire->ire_metrics.iulp_mtu != 0) {
		metrics->rmx_mtu = ire->ire_metrics.iulp_mtu;
		metrics_set |= RTV_MTU;
	} else if (ill != NULL) {
		metrics->rmx_mtu = ill->ill_mtu;
		metrics_set |= RTV_MTU;
	}
	metrics->rmx_ssthresh = ire->ire_metrics.iulp_ssthresh;
	metrics_set |= RTV_SSTHRESH;
	metrics->rmx_rttvar = ire->ire_metrics.iulp_rtt_sd * 1000;
	metrics_set |= RTV_RTTVAR;
	metrics->rmx_sendpipe = ire->ire_metrics.iulp_spipe;
	metrics_set |= RTV_SPIPE;
	metrics->rmx_recvpipe = ire->ire_metrics.iulp_rpipe;
	metrics_set |= RTV_RPIPE;
	return (metrics_set);
}

/*
 * Given two sets of metrics (src and dst), use the dst values if they are
 * set. If a dst value is not set but the src value is set, then we use
 * the src value.
 * dst is updated with the new values.
 * This is used to merge information from a dce_t and ire_metrics, where the
 * dce values takes precedence.
 */
void
rts_merge_metrics(iulp_t *dst, const iulp_t *src)
{
	if (!src->iulp_set)
		return;

	if (dst->iulp_ssthresh == 0)
		dst->iulp_ssthresh = src->iulp_ssthresh;
	if (dst->iulp_rtt == 0)
		dst->iulp_rtt = src->iulp_rtt;
	if (dst->iulp_rtt_sd == 0)
		dst->iulp_rtt_sd = src->iulp_rtt_sd;
	if (dst->iulp_spipe == 0)
		dst->iulp_spipe = src->iulp_spipe;
	if (dst->iulp_rpipe == 0)
		dst->iulp_rpipe = src->iulp_rpipe;
	if (dst->iulp_rtomax == 0)
		dst->iulp_rtomax = src->iulp_rtomax;
	if (dst->iulp_sack == 0)
		dst->iulp_sack = src->iulp_sack;
	if (dst->iulp_tstamp_ok == 0)
		dst->iulp_tstamp_ok = src->iulp_tstamp_ok;
	if (dst->iulp_wscale_ok == 0)
		dst->iulp_wscale_ok = src->iulp_wscale_ok;
	if (dst->iulp_ecn_ok == 0)
		dst->iulp_ecn_ok = src->iulp_ecn_ok;
	if (dst->iulp_pmtud_ok == 0)
		dst->iulp_pmtud_ok = src->iulp_pmtud_ok;
	if (dst->iulp_mtu == 0)
		dst->iulp_mtu = src->iulp_mtu;
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
	if (((cp - (caddr_t)rtm) < length) && is_system_labeled()) {
		*error = tsol_rtsa_init(rtm, rtsecattr, cp);
		ASSERT(rtsecattr->rtsa_cnt <= TSOL_RTSA_REQUEST_MAX);
	}

	return (found_addrs);
}

/*
 * Fills the message with the given info.
 */
static void
rts_fill_msg(int type, int rtm_addrs, ipaddr_t dst, ipaddr_t mask,
    ipaddr_t gateway, ipaddr_t src_addr, ipaddr_t brd_addr, ipaddr_t author,
    ipaddr_t ifaddr, const ill_t *ill, mblk_t *mp,
    const tsol_gc_t *gc)
{
	rt_msghdr_t	*rtm;
	sin_t		*sin;
	size_t		data_size, header_size;
	uchar_t		*cp;
	int		i;

	ASSERT(mp != NULL);
	/*
	 * First find the type of the message
	 * and its length.
	 */
	header_size = rts_header_msg_size(type);
	/*
	 * Now find the size of the data
	 * that follows the message header.
	 */
	data_size = rts_data_msg_size(rtm_addrs, AF_INET, gc != NULL ? 1 : 0);

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
			cp += ill_dls_info((struct sockaddr_dl *)cp, ill);
			break;
		case RTA_IFA:
			sin->sin_addr.s_addr = ifaddr;
			sin->sin_family = AF_INET;
			cp += sizeof (sin_t);
			break;
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

		ASSERT(gc->gc_grp != NULL);
		ASSERT(RW_LOCK_HELD(&gc->gc_grp->gcgrp_rwlock));

		rtm_ext = (rtm_ext_t *)cp;
		rtm_ext->rtmex_type = RTMEX_GATEWAY_SECATTR;
		rtm_ext->rtmex_len = TSOL_RTSECATTR_SIZE(1);

		rsap = (tsol_rtsecattr_t *)(rtm_ext + 1);
		rsap->rtsa_cnt = 1;
		rp_dst = rsap->rtsa_attr;

		ASSERT(gc->gc_db != NULL);
		bcopy(&gc->gc_db->gcdb_attr, rp_dst, sizeof (*rp_dst));
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
 * Note that sacnt is either zero or one.
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
	case RTM_CHGADDR:
	case RTM_FREEADDR:
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
	    author, 0, NULL, mp, NULL);
	rtm = (rt_msghdr_t *)mp->b_rptr;
	rtm->rtm_flags = flags;
	rtm->rtm_errno = error;
	rtm->rtm_flags |= RTF_DONE;
	rtm->rtm_addrs = rtm_addrs;
	rts_queue_input(mp, NULL, AF_INET, RTSQ_ALL, ipst);
}

/*
 * This routine is called to generate a message to the routing
 * socket indicating that the status of a network interface has changed.
 * Message type generated RTM_IFINFO.
 */
void
ip_rts_ifmsg(const ipif_t *ipif, uint_t flags)
{
	ip_rts_xifmsg(ipif, 0, 0, flags);
}

void
ip_rts_xifmsg(const ipif_t *ipif, uint64_t set, uint64_t clear, uint_t flags)
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
		    &ipv6_all_zeros, &ipv6_all_zeros, &ipv6_all_zeros,
		    ipif->ipif_ill, mp, NULL);
	} else {
		af = AF_INET;
		mp = rts_alloc_msg(RTM_IFINFO, RTA_IFP, af, 0);
		if (mp == NULL)
			return;
		rts_fill_msg(RTM_IFINFO, RTA_IFP, 0, 0, 0, 0, 0, 0, 0,
		    ipif->ipif_ill, mp, NULL);
	}
	ifm = (if_msghdr_t *)mp->b_rptr;
	ifm->ifm_index = ipif->ipif_ill->ill_phyint->phyint_ifindex;
	ifm->ifm_flags = (ipif->ipif_flags | ipif->ipif_ill->ill_flags |
	    ipif->ipif_ill->ill_phyint->phyint_flags | set) & ~clear;
	rts_getifdata(&ifm->ifm_data, ipif);
	ifm->ifm_addrs = RTA_IFP;

	if (flags & RTSQ_DEFAULT) {
		flags = RTSQ_ALL;
		/*
		 * If this message is for an underlying interface, prevent
		 * "normal" (IPMP-unaware) routing sockets from seeing it.
		 */
		if (IS_UNDER_IPMP(ipif->ipif_ill))
			flags &= ~RTSQ_NORMAL;
	}

	rts_queue_input(mp, NULL, af, flags, ipst);
}

/*
 * If cmd is RTM_ADD or RTM_DELETE, generate the rt_msghdr_t message;
 * otherwise (RTM_NEWADDR, RTM_DELADDR, RTM_CHGADDR and RTM_FREEADDR)
 * generate the ifa_msghdr_t message.
 */
static void
rts_new_rtsmsg(int cmd, int error, const ipif_t *ipif, uint_t flags)
{
	int		rtm_addrs;
	mblk_t		*mp;
	ifa_msghdr_t	*ifam;
	rt_msghdr_t	*rtm;
	sa_family_t	af;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	/*
	 * Do not report unspecified address if this is the RTM_CHGADDR or
	 * RTM_FREEADDR message.
	 */
	if (cmd == RTM_CHGADDR || cmd == RTM_FREEADDR) {
		if (!ipif->ipif_isv6) {
			if (ipif->ipif_lcl_addr == INADDR_ANY)
				return;
		} else if (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr)) {
			return;
		}
	}

	if (ipif->ipif_isv6)
		af = AF_INET6;
	else
		af = AF_INET;

	if (cmd == RTM_ADD || cmd == RTM_DELETE)
		rtm_addrs = (RTA_DST | RTA_NETMASK);
	else
		rtm_addrs = (RTA_IFA | RTA_NETMASK | RTA_BRD | RTA_IFP);

	mp = rts_alloc_msg(cmd, rtm_addrs, af, 0);
	if (mp == NULL)
		return;

	if (cmd != RTM_ADD && cmd != RTM_DELETE) {
		switch (af) {
		case AF_INET:
			rts_fill_msg(cmd, rtm_addrs, 0,
			    ipif->ipif_net_mask, 0, ipif->ipif_lcl_addr,
			    ipif->ipif_pp_dst_addr, 0,
			    ipif->ipif_lcl_addr, ipif->ipif_ill,
			    mp, NULL);
			break;
		case AF_INET6:
			rts_fill_msg_v6(cmd, rtm_addrs,
			    &ipv6_all_zeros, &ipif->ipif_v6net_mask,
			    &ipv6_all_zeros, &ipif->ipif_v6lcl_addr,
			    &ipif->ipif_v6pp_dst_addr, &ipv6_all_zeros,
			    &ipif->ipif_v6lcl_addr, ipif->ipif_ill,
			    mp, NULL);
			break;
		}
		ifam = (ifa_msghdr_t *)mp->b_rptr;
		ifam->ifam_index =
		    ipif->ipif_ill->ill_phyint->phyint_ifindex;
		ifam->ifam_metric = ipif->ipif_ill->ill_metric;
		ifam->ifam_flags = ((cmd == RTM_NEWADDR) ? RTF_UP : 0);
		ifam->ifam_addrs = rtm_addrs;
	} else {
		switch (af) {
		case AF_INET:
			rts_fill_msg(cmd, rtm_addrs,
			    ipif->ipif_lcl_addr, ipif->ipif_net_mask, 0,
			    0, 0, 0, 0, NULL, mp, NULL);
			break;
		case AF_INET6:
			rts_fill_msg_v6(cmd, rtm_addrs,
			    &ipif->ipif_v6lcl_addr,
			    &ipif->ipif_v6net_mask, &ipv6_all_zeros,
			    &ipv6_all_zeros, &ipv6_all_zeros,
			    &ipv6_all_zeros, &ipv6_all_zeros,
			    NULL, mp, NULL);
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
	}
	rts_queue_input(mp, NULL, af, flags, ipst);
}

/*
 * This is called to generate messages to the routing socket
 * indicating a network interface has had addresses associated with it.
 * The structure of the code is based on the 4.4BSD-Lite2 <net/rtsock.c>.
 */
void
ip_rts_newaddrmsg(int cmd, int error, const ipif_t *ipif, uint_t flags)
{
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	if (flags & RTSQ_DEFAULT) {
		flags = RTSQ_ALL;
		/*
		 * If this message is for an underlying interface, prevent
		 * "normal" (IPMP-unaware) routing sockets from seeing it.
		 */
		if (IS_UNDER_IPMP(ipif->ipif_ill))
			flags &= ~RTSQ_NORMAL;
	}

	/*
	 * Let conn_ixa caching know that source address selection
	 * changed
	 */
	if (cmd == RTM_ADD || cmd == RTM_DELETE)
		ip_update_source_selection(ipst);

	/*
	 * If the request is DELETE, send RTM_DELETE and RTM_DELADDR.
	 * if the request is ADD, send RTM_NEWADDR and RTM_ADD.
	 * otherwise simply send the request.
	 */
	switch (cmd) {
	case RTM_ADD:
		rts_new_rtsmsg(RTM_NEWADDR, error, ipif, flags);
		rts_new_rtsmsg(RTM_ADD, error, ipif, flags);
		break;
	case RTM_DELETE:
		rts_new_rtsmsg(RTM_DELETE, error, ipif, flags);
		rts_new_rtsmsg(RTM_DELADDR, error, ipif, flags);
		break;
	default:
		rts_new_rtsmsg(cmd, error, ipif, flags);
		break;
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

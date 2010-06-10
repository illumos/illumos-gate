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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/xti_inet.h>
#include <sys/ucred.h>
#include <sys/zone.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/policy.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/sdt.h>
#include <sys/socket.h>
#include <sys/ethernet.h>
#include <sys/mac.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if_dl.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/arp.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>

#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/sctp.h>

#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/tcp.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/optcom.h>
#include <inet/ip_ndp.h>
#include <inet/ip_listutils.h>
#include <netinet/igmp.h>
#include <netinet/ip_mroute.h>
#include <netinet/udp.h>
#include <inet/ipp_common.h>

#include <net/pfkeyv2.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/ipdrop.h>
#include <inet/ip_netinfo.h>

#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/udp_impl.h>
#include <sys/sunddi.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

/*
 * Return how much size is needed for the different ancillary data items
 */
uint_t
conn_recvancillary_size(conn_t *connp, crb_t recv_ancillary,
    ip_recv_attr_t *ira, mblk_t *mp, ip_pkt_t *ipp)
{
	uint_t		ancil_size;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	/*
	 * If IP_RECVDSTADDR is set we include the destination IP
	 * address as an option. With IP_RECVOPTS we include all
	 * the IP options.
	 */
	ancil_size = 0;
	if (recv_ancillary.crb_recvdstaddr &&
	    (ira->ira_flags & IRAF_IS_IPV4)) {
		ancil_size += sizeof (struct T_opthdr) +
		    sizeof (struct in_addr);
		IP_STAT(ipst, conn_in_recvdstaddr);
	}

	/*
	 * ip_recvpktinfo is used for both AF_INET and AF_INET6 but
	 * are different
	 */
	if (recv_ancillary.crb_ip_recvpktinfo &&
	    connp->conn_family == AF_INET) {
		ancil_size += sizeof (struct T_opthdr) +
		    sizeof (struct in_pktinfo);
		IP_STAT(ipst, conn_in_recvpktinfo);
	}

	if ((recv_ancillary.crb_recvopts) &&
	    (ipp->ipp_fields & IPPF_IPV4_OPTIONS)) {
		ancil_size += sizeof (struct T_opthdr) +
		    ipp->ipp_ipv4_options_len;
		IP_STAT(ipst, conn_in_recvopts);
	}

	if (recv_ancillary.crb_recvslla) {
		ip_stack_t *ipst = connp->conn_netstack->netstack_ip;
		ill_t *ill;

		/* Make sure ira_l2src is setup if not already */
		if (!(ira->ira_flags & IRAF_L2SRC_SET)) {
			ill = ill_lookup_on_ifindex(ira->ira_rifindex, B_FALSE,
			    ipst);
			if (ill != NULL) {
				ip_setl2src(mp, ira, ill);
				ill_refrele(ill);
			}
		}
		ancil_size += sizeof (struct T_opthdr) +
		    sizeof (struct sockaddr_dl);
		IP_STAT(ipst, conn_in_recvslla);
	}

	if (recv_ancillary.crb_recvif) {
		ancil_size += sizeof (struct T_opthdr) + sizeof (uint_t);
		IP_STAT(ipst, conn_in_recvif);
	}

	/*
	 * ip_recvpktinfo is used for both AF_INET and AF_INET6 but
	 * are different
	 */
	if (recv_ancillary.crb_ip_recvpktinfo &&
	    connp->conn_family == AF_INET6) {
		ancil_size += sizeof (struct T_opthdr) +
		    sizeof (struct in6_pktinfo);
		IP_STAT(ipst, conn_in_recvpktinfo);
	}

	if (recv_ancillary.crb_ipv6_recvhoplimit) {
		ancil_size += sizeof (struct T_opthdr) + sizeof (int);
		IP_STAT(ipst, conn_in_recvhoplimit);
	}

	if (recv_ancillary.crb_ipv6_recvtclass) {
		ancil_size += sizeof (struct T_opthdr) + sizeof (int);
		IP_STAT(ipst, conn_in_recvtclass);
	}

	if (recv_ancillary.crb_ipv6_recvhopopts &&
	    (ipp->ipp_fields & IPPF_HOPOPTS)) {
		ancil_size += sizeof (struct T_opthdr) + ipp->ipp_hopoptslen;
		IP_STAT(ipst, conn_in_recvhopopts);
	}
	/*
	 * To honor RFC3542 when an application asks for both IPV6_RECVDSTOPTS
	 * and IPV6_RECVRTHDR, we pass up the item rthdrdstopts (the destination
	 * options that appear before a routing header.
	 * We also pass them up if IPV6_RECVRTHDRDSTOPTS is set.
	 */
	if (ipp->ipp_fields & IPPF_RTHDRDSTOPTS) {
		if (recv_ancillary.crb_ipv6_recvrthdrdstopts ||
		    (recv_ancillary.crb_ipv6_recvdstopts &&
		    recv_ancillary.crb_ipv6_recvrthdr)) {
			ancil_size += sizeof (struct T_opthdr) +
			    ipp->ipp_rthdrdstoptslen;
			IP_STAT(ipst, conn_in_recvrthdrdstopts);
		}
	}
	if ((recv_ancillary.crb_ipv6_recvrthdr) &&
	    (ipp->ipp_fields & IPPF_RTHDR)) {
		ancil_size += sizeof (struct T_opthdr) + ipp->ipp_rthdrlen;
		IP_STAT(ipst, conn_in_recvrthdr);
	}
	if ((recv_ancillary.crb_ipv6_recvdstopts ||
	    recv_ancillary.crb_old_ipv6_recvdstopts) &&
	    (ipp->ipp_fields & IPPF_DSTOPTS)) {
		ancil_size += sizeof (struct T_opthdr) + ipp->ipp_dstoptslen;
		IP_STAT(ipst, conn_in_recvdstopts);
	}
	if (recv_ancillary.crb_recvucred && ira->ira_cred != NULL) {
		ancil_size += sizeof (struct T_opthdr) +
		    ucredminsize(ira->ira_cred);
		IP_STAT(ipst, conn_in_recvucred);
	}

	/*
	 * If SO_TIMESTAMP is set allocate the appropriate sized
	 * buffer. Since gethrestime() expects a pointer aligned
	 * argument, we allocate space necessary for extra
	 * alignment (even though it might not be used).
	 */
	if (recv_ancillary.crb_timestamp) {
		ancil_size += sizeof (struct T_opthdr) +
		    sizeof (timestruc_t) + _POINTER_ALIGNMENT;
		IP_STAT(ipst, conn_in_timestamp);
	}

	/*
	 * If IP_RECVTTL is set allocate the appropriate sized buffer
	 */
	if (recv_ancillary.crb_recvttl &&
	    (ira->ira_flags & IRAF_IS_IPV4)) {
		ancil_size += sizeof (struct T_opthdr) + sizeof (uint8_t);
		IP_STAT(ipst, conn_in_recvttl);
	}

	return (ancil_size);
}

/*
 * Lay down the ancillary data items at "ancil_buf".
 * Assumes caller has used conn_recvancillary_size to allocate a sufficiently
 * large buffer - ancil_size.
 */
void
conn_recvancillary_add(conn_t *connp, crb_t recv_ancillary,
    ip_recv_attr_t *ira, ip_pkt_t *ipp, uchar_t *ancil_buf, uint_t ancil_size)
{
	/*
	 * Copy in destination address before options to avoid
	 * any padding issues.
	 */
	if (recv_ancillary.crb_recvdstaddr &&
	    (ira->ira_flags & IRAF_IS_IPV4)) {
		struct T_opthdr *toh;
		ipaddr_t *dstptr;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IP;
		toh->name = IP_RECVDSTADDR;
		toh->len = sizeof (struct T_opthdr) + sizeof (ipaddr_t);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		dstptr = (ipaddr_t *)ancil_buf;
		*dstptr = ipp->ipp_addr_v4;
		ancil_buf += sizeof (ipaddr_t);
		ancil_size -= toh->len;
	}

	/*
	 * ip_recvpktinfo is used for both AF_INET and AF_INET6 but
	 * are different
	 */
	if (recv_ancillary.crb_ip_recvpktinfo &&
	    connp->conn_family == AF_INET) {
		ip_stack_t *ipst = connp->conn_netstack->netstack_ip;
		struct T_opthdr *toh;
		struct in_pktinfo *pktinfop;
		ill_t *ill;
		ipif_t *ipif;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IP;
		toh->name = IP_PKTINFO;
		toh->len = sizeof (struct T_opthdr) + sizeof (*pktinfop);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		pktinfop = (struct in_pktinfo *)ancil_buf;

		pktinfop->ipi_ifindex = ira->ira_ruifindex;
		pktinfop->ipi_spec_dst.s_addr = INADDR_ANY;

		/* Find a good address to report */
		ill = ill_lookup_on_ifindex(ira->ira_ruifindex, B_FALSE, ipst);
		if (ill != NULL) {
			ipif = ipif_good_addr(ill, IPCL_ZONEID(connp));
			if (ipif != NULL) {
				pktinfop->ipi_spec_dst.s_addr =
				    ipif->ipif_lcl_addr;
				ipif_refrele(ipif);
			}
			ill_refrele(ill);
		}
		pktinfop->ipi_addr.s_addr = ipp->ipp_addr_v4;
		ancil_buf += sizeof (struct in_pktinfo);
		ancil_size -= toh->len;
	}

	if ((recv_ancillary.crb_recvopts) &&
	    (ipp->ipp_fields & IPPF_IPV4_OPTIONS)) {
		struct T_opthdr *toh;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IP;
		toh->name = IP_RECVOPTS;
		toh->len = sizeof (struct T_opthdr) + ipp->ipp_ipv4_options_len;
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		bcopy(ipp->ipp_ipv4_options, ancil_buf,
		    ipp->ipp_ipv4_options_len);
		ancil_buf += ipp->ipp_ipv4_options_len;
		ancil_size -= toh->len;
	}

	if (recv_ancillary.crb_recvslla) {
		ip_stack_t *ipst = connp->conn_netstack->netstack_ip;
		struct T_opthdr *toh;
		struct sockaddr_dl *dstptr;
		ill_t *ill;
		int alen = 0;

		ill = ill_lookup_on_ifindex(ira->ira_rifindex, B_FALSE, ipst);
		if (ill != NULL)
			alen = ill->ill_phys_addr_length;

		/*
		 * For loopback multicast and broadcast the packet arrives
		 * with ira_ruifdex being the physical interface, but
		 * ira_l2src is all zero since ip_postfrag_loopback doesn't
		 * know our l2src. We don't report the address in that case.
		 */
		if (ira->ira_flags & IRAF_LOOPBACK)
			alen = 0;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IP;
		toh->name = IP_RECVSLLA;
		toh->len = sizeof (struct T_opthdr) +
		    sizeof (struct sockaddr_dl);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		dstptr = (struct sockaddr_dl *)ancil_buf;
		dstptr->sdl_family = AF_LINK;
		dstptr->sdl_index = ira->ira_ruifindex;
		if (ill != NULL)
			dstptr->sdl_type = ill->ill_type;
		else
			dstptr->sdl_type = 0;
		dstptr->sdl_nlen = 0;
		dstptr->sdl_alen = alen;
		dstptr->sdl_slen = 0;
		bcopy(ira->ira_l2src, dstptr->sdl_data, alen);
		ancil_buf += sizeof (struct sockaddr_dl);
		ancil_size -= toh->len;
		if (ill != NULL)
			ill_refrele(ill);
	}

	if (recv_ancillary.crb_recvif) {
		struct T_opthdr *toh;
		uint_t		*dstptr;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IP;
		toh->name = IP_RECVIF;
		toh->len = sizeof (struct T_opthdr) + sizeof (uint_t);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		dstptr = (uint_t *)ancil_buf;
		*dstptr = ira->ira_ruifindex;
		ancil_buf += sizeof (uint_t);
		ancil_size -= toh->len;
	}

	/*
	 * ip_recvpktinfo is used for both AF_INET and AF_INET6 but
	 * are different
	 */
	if (recv_ancillary.crb_ip_recvpktinfo &&
	    connp->conn_family == AF_INET6) {
		struct T_opthdr *toh;
		struct in6_pktinfo *pkti;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_PKTINFO;
		toh->len = sizeof (struct T_opthdr) + sizeof (*pkti);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		pkti = (struct in6_pktinfo *)ancil_buf;
		if (ira->ira_flags & IRAF_IS_IPV4) {
			IN6_IPADDR_TO_V4MAPPED(ipp->ipp_addr_v4,
			    &pkti->ipi6_addr);
		} else {
			pkti->ipi6_addr = ipp->ipp_addr;
		}
		pkti->ipi6_ifindex = ira->ira_ruifindex;

		ancil_buf += sizeof (*pkti);
		ancil_size -= toh->len;
	}
	if (recv_ancillary.crb_ipv6_recvhoplimit) {
		struct T_opthdr *toh;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_HOPLIMIT;
		toh->len = sizeof (struct T_opthdr) + sizeof (uint_t);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		*(uint_t *)ancil_buf = ipp->ipp_hoplimit;
		ancil_buf += sizeof (uint_t);
		ancil_size -= toh->len;
	}
	if (recv_ancillary.crb_ipv6_recvtclass) {
		struct T_opthdr *toh;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_TCLASS;
		toh->len = sizeof (struct T_opthdr) + sizeof (uint_t);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);

		if (ira->ira_flags & IRAF_IS_IPV4)
			*(uint_t *)ancil_buf = ipp->ipp_type_of_service;
		else
			*(uint_t *)ancil_buf = ipp->ipp_tclass;
		ancil_buf += sizeof (uint_t);
		ancil_size -= toh->len;
	}
	if (recv_ancillary.crb_ipv6_recvhopopts &&
	    (ipp->ipp_fields & IPPF_HOPOPTS)) {
		struct T_opthdr *toh;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_HOPOPTS;
		toh->len = sizeof (struct T_opthdr) + ipp->ipp_hopoptslen;
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		bcopy(ipp->ipp_hopopts, ancil_buf, ipp->ipp_hopoptslen);
		ancil_buf += ipp->ipp_hopoptslen;
		ancil_size -= toh->len;
	}
	/*
	 * To honor RFC3542 when an application asks for both IPV6_RECVDSTOPTS
	 * and IPV6_RECVRTHDR, we pass up the item rthdrdstopts (the destination
	 * options that appear before a routing header.
	 * We also pass them up if IPV6_RECVRTHDRDSTOPTS is set.
	 */
	if (ipp->ipp_fields & IPPF_RTHDRDSTOPTS) {
		if (recv_ancillary.crb_ipv6_recvrthdrdstopts ||
		    (recv_ancillary.crb_ipv6_recvdstopts &&
		    recv_ancillary.crb_ipv6_recvrthdr)) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)ancil_buf;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_DSTOPTS;
			toh->len = sizeof (struct T_opthdr) +
			    ipp->ipp_rthdrdstoptslen;
			toh->status = 0;
			ancil_buf += sizeof (struct T_opthdr);
			bcopy(ipp->ipp_rthdrdstopts, ancil_buf,
			    ipp->ipp_rthdrdstoptslen);
			ancil_buf += ipp->ipp_rthdrdstoptslen;
			ancil_size -= toh->len;
		}
	}
	if (recv_ancillary.crb_ipv6_recvrthdr &&
	    (ipp->ipp_fields & IPPF_RTHDR)) {
		struct T_opthdr *toh;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_RTHDR;
		toh->len = sizeof (struct T_opthdr) + ipp->ipp_rthdrlen;
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		bcopy(ipp->ipp_rthdr, ancil_buf, ipp->ipp_rthdrlen);
		ancil_buf += ipp->ipp_rthdrlen;
		ancil_size -= toh->len;
	}
	if ((recv_ancillary.crb_ipv6_recvdstopts ||
	    recv_ancillary.crb_old_ipv6_recvdstopts) &&
	    (ipp->ipp_fields & IPPF_DSTOPTS)) {
		struct T_opthdr *toh;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_DSTOPTS;
		toh->len = sizeof (struct T_opthdr) + ipp->ipp_dstoptslen;
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		bcopy(ipp->ipp_dstopts, ancil_buf, ipp->ipp_dstoptslen);
		ancil_buf += ipp->ipp_dstoptslen;
		ancil_size -= toh->len;
	}

	if (recv_ancillary.crb_recvucred && ira->ira_cred != NULL) {
		struct T_opthdr *toh;
		cred_t		*rcr = connp->conn_cred;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = SOL_SOCKET;
		toh->name = SCM_UCRED;
		toh->len = sizeof (struct T_opthdr) +
		    ucredminsize(ira->ira_cred);
		toh->status = 0;
		(void) cred2ucred(ira->ira_cred, ira->ira_cpid, &toh[1], rcr);
		ancil_buf += toh->len;
		ancil_size -= toh->len;
	}
	if (recv_ancillary.crb_timestamp) {
		struct	T_opthdr *toh;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = SOL_SOCKET;
		toh->name = SCM_TIMESTAMP;
		toh->len = sizeof (struct T_opthdr) +
		    sizeof (timestruc_t) + _POINTER_ALIGNMENT;
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		/* Align for gethrestime() */
		ancil_buf = (uchar_t *)P2ROUNDUP((intptr_t)ancil_buf,
		    sizeof (intptr_t));
		gethrestime((timestruc_t *)ancil_buf);
		ancil_buf = (uchar_t *)toh + toh->len;
		ancil_size -= toh->len;
	}

	/*
	 * CAUTION:
	 * Due to aligment issues
	 * Processing of IP_RECVTTL option
	 * should always be the last. Adding
	 * any option processing after this will
	 * cause alignment panic.
	 */
	if (recv_ancillary.crb_recvttl &&
	    (ira->ira_flags & IRAF_IS_IPV4)) {
		struct	T_opthdr *toh;
		uint8_t	*dstptr;

		toh = (struct T_opthdr *)ancil_buf;
		toh->level = IPPROTO_IP;
		toh->name = IP_RECVTTL;
		toh->len = sizeof (struct T_opthdr) + sizeof (uint8_t);
		toh->status = 0;
		ancil_buf += sizeof (struct T_opthdr);
		dstptr = (uint8_t *)ancil_buf;
		*dstptr = ipp->ipp_hoplimit;
		ancil_buf += sizeof (uint8_t);
		ancil_size -= toh->len;
	}

	/* Consumed all of allocated space */
	ASSERT(ancil_size == 0);

}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved, or -1.
 */
int
conn_opt_get(conn_opt_arg_t *coa, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr)
{
	int		*i1 = (int *)ptr;
	conn_t		*connp = coa->coa_connp;
	ip_xmit_attr_t	*ixa = coa->coa_ixa;
	ip_pkt_t	*ipp = coa->coa_ipp;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	uint_t		len;

	ASSERT(MUTEX_HELD(&coa->coa_connp->conn_lock));

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_DEBUG:
			*i1 = connp->conn_debug ? SO_DEBUG : 0;
			break;	/* goto sizeof (int) option return */
		case SO_KEEPALIVE:
			*i1 = connp->conn_keepalive ? SO_KEEPALIVE : 0;
			break;
		case SO_LINGER:	{
			struct linger *lgr = (struct linger *)ptr;

			lgr->l_onoff = connp->conn_linger ? SO_LINGER : 0;
			lgr->l_linger = connp->conn_lingertime;
			}
			return (sizeof (struct linger));

		case SO_OOBINLINE:
			*i1 = connp->conn_oobinline ? SO_OOBINLINE : 0;
			break;
		case SO_REUSEADDR:
			*i1 = connp->conn_reuseaddr ? SO_REUSEADDR : 0;
			break;	/* goto sizeof (int) option return */
		case SO_TYPE:
			*i1 = connp->conn_so_type;
			break;	/* goto sizeof (int) option return */
		case SO_DONTROUTE:
			*i1 = (ixa->ixa_flags & IXAF_DONTROUTE) ?
			    SO_DONTROUTE : 0;
			break;	/* goto sizeof (int) option return */
		case SO_USELOOPBACK:
			*i1 = connp->conn_useloopback ? SO_USELOOPBACK : 0;
			break;	/* goto sizeof (int) option return */
		case SO_BROADCAST:
			*i1 = connp->conn_broadcast ? SO_BROADCAST : 0;
			break;	/* goto sizeof (int) option return */

		case SO_SNDBUF:
			*i1 = connp->conn_sndbuf;
			break;	/* goto sizeof (int) option return */
		case SO_RCVBUF:
			*i1 = connp->conn_rcvbuf;
			break;	/* goto sizeof (int) option return */
		case SO_RCVTIMEO:
		case SO_SNDTIMEO:
			/*
			 * Pass these two options in order for third part
			 * protocol usage. Here just return directly.
			 */
			*i1 = 0;
			break;
		case SO_DGRAM_ERRIND:
			*i1 = connp->conn_dgram_errind ? SO_DGRAM_ERRIND : 0;
			break;	/* goto sizeof (int) option return */
		case SO_RECVUCRED:
			*i1 = connp->conn_recv_ancillary.crb_recvucred;
			break;	/* goto sizeof (int) option return */
		case SO_TIMESTAMP:
			*i1 = connp->conn_recv_ancillary.crb_timestamp;
			break;	/* goto sizeof (int) option return */
		case SO_VRRP:
			*i1 = connp->conn_isvrrp;
			break;	/* goto sizeof (int) option return */
		case SO_ANON_MLP:
			*i1 = connp->conn_anon_mlp;
			break;	/* goto sizeof (int) option return */
		case SO_MAC_EXEMPT:
			*i1 = (connp->conn_mac_mode == CONN_MAC_AWARE);
			break;	/* goto sizeof (int) option return */
		case SO_MAC_IMPLICIT:
			*i1 = (connp->conn_mac_mode == CONN_MAC_IMPLICIT);
			break;	/* goto sizeof (int) option return */
		case SO_ALLZONES:
			*i1 = connp->conn_allzones;
			break;	/* goto sizeof (int) option return */
		case SO_EXCLBIND:
			*i1 = connp->conn_exclbind ? SO_EXCLBIND : 0;
			break;
		case SO_PROTOTYPE:
			*i1 = connp->conn_proto;
			break;

		case SO_DOMAIN:
			*i1 = connp->conn_family;
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_IP:
		if (connp->conn_family != AF_INET)
			return (-1);
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			if (!(ipp->ipp_fields & IPPF_IPV4_OPTIONS))
				return (0);

			len = ipp->ipp_ipv4_options_len;
			if (len > 0) {
				bcopy(ipp->ipp_ipv4_options, ptr, len);
			}
			return (len);

		case IP_PKTINFO: {
			/*
			 * This also handles IP_RECVPKTINFO.
			 * IP_PKTINFO and IP_RECVPKTINFO have same value.
			 * Differentiation is based on the size of the
			 * argument passed in.
			 */
			struct in_pktinfo *pktinfo;

#ifdef notdef
			/* optcom doesn't provide a length with "get" */
			if (inlen == sizeof (int)) {
				/* This is IP_RECVPKTINFO option. */
				*i1 = connp->conn_recv_ancillary.
				    crb_ip_recvpktinfo;
				return (sizeof (int));
			}
#endif
			/* XXX assumes that caller has room for max size! */

			pktinfo = (struct in_pktinfo *)ptr;
			pktinfo->ipi_ifindex = ixa->ixa_ifindex;
			if (ipp->ipp_fields & IPPF_ADDR)
				pktinfo->ipi_spec_dst.s_addr = ipp->ipp_addr_v4;
			else
				pktinfo->ipi_spec_dst.s_addr = INADDR_ANY;
			return (sizeof (struct in_pktinfo));
		}
		case IP_DONTFRAG:
			*i1 = (ixa->ixa_flags & IXAF_DONTFRAG) != 0;
			return (sizeof (int));
		case IP_TOS:
		case T_IP_TOS:
			*i1 = (int)ipp->ipp_type_of_service;
			break;	/* goto sizeof (int) option return */
		case IP_TTL:
			*i1 = (int)ipp->ipp_unicast_hops;
			break;	/* goto sizeof (int) option return */
		case IP_DHCPINIT_IF:
			return (-1);
		case IP_NEXTHOP:
			if (ixa->ixa_flags & IXAF_NEXTHOP_SET) {
				*(ipaddr_t *)ptr = ixa->ixa_nexthop_v4;
				return (sizeof (ipaddr_t));
			} else {
				return (0);
			}

		case IP_MULTICAST_IF:
			/* 0 address if not set */
			*(ipaddr_t *)ptr = ixa->ixa_multicast_ifaddr;
			return (sizeof (ipaddr_t));
		case IP_MULTICAST_TTL:
			*(uchar_t *)ptr = ixa->ixa_multicast_ttl;
			return (sizeof (uchar_t));
		case IP_MULTICAST_LOOP:
			*ptr = (ixa->ixa_flags & IXAF_MULTICAST_LOOP) ? 1 : 0;
			return (sizeof (uint8_t));
		case IP_RECVOPTS:
			*i1 = connp->conn_recv_ancillary.crb_recvopts;
			break;	/* goto sizeof (int) option return */
		case IP_RECVDSTADDR:
			*i1 = connp->conn_recv_ancillary.crb_recvdstaddr;
			break;	/* goto sizeof (int) option return */
		case IP_RECVIF:
			*i1 = connp->conn_recv_ancillary.crb_recvif;
			break;	/* goto sizeof (int) option return */
		case IP_RECVSLLA:
			*i1 = connp->conn_recv_ancillary.crb_recvslla;
			break;	/* goto sizeof (int) option return */
		case IP_RECVTTL:
			*i1 = connp->conn_recv_ancillary.crb_recvttl;
			break;	/* goto sizeof (int) option return */
		case IP_ADD_MEMBERSHIP:
		case IP_DROP_MEMBERSHIP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case IP_BLOCK_SOURCE:
		case IP_UNBLOCK_SOURCE:
		case IP_ADD_SOURCE_MEMBERSHIP:
		case IP_DROP_SOURCE_MEMBERSHIP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
		case MRT_INIT:
		case MRT_DONE:
		case MRT_ADD_VIF:
		case MRT_DEL_VIF:
		case MRT_ADD_MFC:
		case MRT_DEL_MFC:
			/* cannot "get" the value for these */
			return (-1);
		case MRT_VERSION:
		case MRT_ASSERT:
			(void) ip_mrouter_get(name, connp, ptr);
			return (sizeof (int));
		case IP_SEC_OPT:
			return (ipsec_req_from_conn(connp, (ipsec_req_t	*)ptr,
			    IPSEC_AF_V4));
		case IP_BOUND_IF:
			/* Zero if not set */
			*i1 = connp->conn_bound_if;
			break;	/* goto sizeof (int) option return */
		case IP_UNSPEC_SRC:
			*i1 = connp->conn_unspec_src;
			break;	/* goto sizeof (int) option return */
		case IP_BROADCAST_TTL:
			if (ixa->ixa_flags & IXAF_BROADCAST_TTL_SET)
				*(uchar_t *)ptr = ixa->ixa_broadcast_ttl;
			else
				*(uchar_t *)ptr = ipst->ips_ip_broadcast_ttl;
			return (sizeof (uchar_t));
		default:
			return (-1);
		}
		break;
	case IPPROTO_IPV6:
		if (connp->conn_family != AF_INET6)
			return (-1);
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = (int)ipp->ipp_unicast_hops;
			break;	/* goto sizeof (int) option return */
		case IPV6_MULTICAST_IF:
			/* 0 index if not set */
			*i1 = ixa->ixa_multicast_ifindex;
			break;	/* goto sizeof (int) option return */
		case IPV6_MULTICAST_HOPS:
			*i1 = ixa->ixa_multicast_ttl;
			break;	/* goto sizeof (int) option return */
		case IPV6_MULTICAST_LOOP:
			*i1 = (ixa->ixa_flags & IXAF_MULTICAST_LOOP) ? 1 : 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_JOIN_GROUP:
		case IPV6_LEAVE_GROUP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
			/* cannot "get" the value for these */
			return (-1);
		case IPV6_BOUND_IF:
			/* Zero if not set */
			*i1 = connp->conn_bound_if;
			break;	/* goto sizeof (int) option return */
		case IPV6_UNSPEC_SRC:
			*i1 = connp->conn_unspec_src;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVPKTINFO:
			*i1 = connp->conn_recv_ancillary.crb_ip_recvpktinfo;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVTCLASS:
			*i1 = connp->conn_recv_ancillary.crb_ipv6_recvtclass;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVPATHMTU:
			*i1 = connp->conn_ipv6_recvpathmtu;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPLIMIT:
			*i1 = connp->conn_recv_ancillary.crb_ipv6_recvhoplimit;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPOPTS:
			*i1 = connp->conn_recv_ancillary.crb_ipv6_recvhopopts;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVDSTOPTS:
			*i1 = connp->conn_recv_ancillary.crb_ipv6_recvdstopts;
			break;	/* goto sizeof (int) option return */
		case _OLD_IPV6_RECVDSTOPTS:
			*i1 =
			    connp->conn_recv_ancillary.crb_old_ipv6_recvdstopts;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDRDSTOPTS:
			*i1 = connp->conn_recv_ancillary.
			    crb_ipv6_recvrthdrdstopts;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDR:
			*i1 = connp->conn_recv_ancillary.crb_ipv6_recvrthdr;
			break;	/* goto sizeof (int) option return */
		case IPV6_PKTINFO: {
			/* XXX assumes that caller has room for max size! */
			struct in6_pktinfo *pkti;

			pkti = (struct in6_pktinfo *)ptr;
			pkti->ipi6_ifindex = ixa->ixa_ifindex;
			if (ipp->ipp_fields & IPPF_ADDR)
				pkti->ipi6_addr = ipp->ipp_addr;
			else
				pkti->ipi6_addr = ipv6_all_zeros;
			return (sizeof (struct in6_pktinfo));
		}
		case IPV6_TCLASS:
			*i1 = ipp->ipp_tclass;
			break;	/* goto sizeof (int) option return */
		case IPV6_NEXTHOP: {
			sin6_t *sin6 = (sin6_t *)ptr;

			if (ixa->ixa_flags & IXAF_NEXTHOP_SET)
				return (0);

			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = ixa->ixa_nexthop_v6;

			return (sizeof (sin6_t));
		}
		case IPV6_HOPOPTS:
			if (!(ipp->ipp_fields & IPPF_HOPOPTS))
				return (0);
			bcopy(ipp->ipp_hopopts, ptr,
			    ipp->ipp_hopoptslen);
			return (ipp->ipp_hopoptslen);
		case IPV6_RTHDRDSTOPTS:
			if (!(ipp->ipp_fields & IPPF_RTHDRDSTOPTS))
				return (0);
			bcopy(ipp->ipp_rthdrdstopts, ptr,
			    ipp->ipp_rthdrdstoptslen);
			return (ipp->ipp_rthdrdstoptslen);
		case IPV6_RTHDR:
			if (!(ipp->ipp_fields & IPPF_RTHDR))
				return (0);
			bcopy(ipp->ipp_rthdr, ptr, ipp->ipp_rthdrlen);
			return (ipp->ipp_rthdrlen);
		case IPV6_DSTOPTS:
			if (!(ipp->ipp_fields & IPPF_DSTOPTS))
				return (0);
			bcopy(ipp->ipp_dstopts, ptr, ipp->ipp_dstoptslen);
			return (ipp->ipp_dstoptslen);
		case IPV6_PATHMTU:
			return (ip_fill_mtuinfo(connp, ixa,
			    (struct ip6_mtuinfo *)ptr));
		case IPV6_SEC_OPT:
			return (ipsec_req_from_conn(connp, (ipsec_req_t	*)ptr,
			    IPSEC_AF_V6));
		case IPV6_SRC_PREFERENCES:
			return (ip6_get_src_preferences(ixa, (uint32_t *)ptr));
		case IPV6_DONTFRAG:
			*i1 = (ixa->ixa_flags & IXAF_DONTFRAG) != 0;
			return (sizeof (int));
		case IPV6_USE_MIN_MTU:
			if (ixa->ixa_flags & IXAF_USE_MIN_MTU)
				*i1 = ixa->ixa_use_min_mtu;
			else
				*i1 = IPV6_USE_MIN_MTU_MULTICAST;
			break;
		case IPV6_V6ONLY:
			*i1 = connp->conn_ipv6_v6only;
			return (sizeof (int));
		default:
			return (-1);
		}
		break;
	case IPPROTO_UDP:
		switch (name) {
		case UDP_ANONPRIVBIND:
			*i1 = connp->conn_anon_priv_bind;
			break;
		case UDP_EXCLBIND:
			*i1 = connp->conn_exclbind ? UDP_EXCLBIND : 0;
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_TCP:
		switch (name) {
		case TCP_RECVDSTADDR:
			*i1 = connp->conn_recv_ancillary.crb_recvdstaddr;
			break;
		case TCP_ANONPRIVBIND:
			*i1 = connp->conn_anon_priv_bind;
			break;
		case TCP_EXCLBIND:
			*i1 = connp->conn_exclbind ? TCP_EXCLBIND : 0;
			break;
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}
	return (sizeof (int));
}

static int conn_opt_set_socket(conn_opt_arg_t *coa, t_scalar_t name,
    uint_t inlen, uchar_t *invalp, boolean_t checkonly, cred_t *cr);
static int conn_opt_set_ip(conn_opt_arg_t *coa, t_scalar_t name,
    uint_t inlen, uchar_t *invalp, boolean_t checkonly, cred_t *cr);
static int conn_opt_set_ipv6(conn_opt_arg_t *coa, t_scalar_t name,
    uint_t inlen, uchar_t *invalp, boolean_t checkonly, cred_t *cr);
static int conn_opt_set_udp(conn_opt_arg_t *coa, t_scalar_t name,
    uint_t inlen, uchar_t *invalp, boolean_t checkonly, cred_t *cr);
static int conn_opt_set_tcp(conn_opt_arg_t *coa, t_scalar_t name,
    uint_t inlen, uchar_t *invalp, boolean_t checkonly, cred_t *cr);

/*
 * This routine sets the most common socket options including some
 * that are transport/ULP specific.
 * It returns errno or zero.
 *
 * For fixed length options, there is no sanity check
 * of passed in length is done. It is assumed *_optcom_req()
 * routines do the right thing.
 */
int
conn_opt_set(conn_opt_arg_t *coa, t_scalar_t level, t_scalar_t name,
    uint_t inlen, uchar_t *invalp, boolean_t checkonly, cred_t *cr)
{
	ASSERT(MUTEX_NOT_HELD(&coa->coa_connp->conn_lock));

	/* We have different functions for different levels */
	switch (level) {
	case SOL_SOCKET:
		return (conn_opt_set_socket(coa, name, inlen, invalp,
		    checkonly, cr));
	case IPPROTO_IP:
		return (conn_opt_set_ip(coa, name, inlen, invalp,
		    checkonly, cr));
	case IPPROTO_IPV6:
		return (conn_opt_set_ipv6(coa, name, inlen, invalp,
		    checkonly, cr));
	case IPPROTO_UDP:
		return (conn_opt_set_udp(coa, name, inlen, invalp,
		    checkonly, cr));
	case IPPROTO_TCP:
		return (conn_opt_set_tcp(coa, name, inlen, invalp,
		    checkonly, cr));
	default:
		return (0);
	}
}

/*
 * Handle SOL_SOCKET
 * Note that we do not handle SO_PROTOTYPE here. The ULPs that support
 * it implement their own checks and setting of conn_proto.
 */
/* ARGSUSED1 */
static int
conn_opt_set_socket(conn_opt_arg_t *coa, t_scalar_t name, uint_t inlen,
    uchar_t *invalp, boolean_t checkonly, cred_t *cr)
{
	conn_t		*connp = coa->coa_connp;
	ip_xmit_attr_t	*ixa = coa->coa_ixa;
	int		*i1 = (int *)invalp;
	boolean_t	onoff = (*i1 == 0) ? 0 : 1;

	switch (name) {
	case SO_ALLZONES:
		if (IPCL_IS_BOUND(connp))
			return (EINVAL);
		break;
	case SO_VRRP:
		if (secpolicy_ip_config(cr, checkonly) != 0)
			return (EACCES);
		break;
	case SO_MAC_EXEMPT:
		if (secpolicy_net_mac_aware(cr) != 0)
			return (EACCES);
		if (IPCL_IS_BOUND(connp))
			return (EINVAL);
		break;
	case SO_MAC_IMPLICIT:
		if (secpolicy_net_mac_implicit(cr) != 0)
			return (EACCES);
		break;
	}
	if (checkonly)
		return (0);

	mutex_enter(&connp->conn_lock);
	/* Here we set the actual option value */
	switch (name) {
	case SO_DEBUG:
		connp->conn_debug = onoff;
		break;
	case SO_KEEPALIVE:
		connp->conn_keepalive = onoff;
		break;
	case SO_LINGER: {
		struct linger *lgr = (struct linger *)invalp;

		if (lgr->l_onoff) {
			connp->conn_linger = 1;
			connp->conn_lingertime = lgr->l_linger;
		} else {
			connp->conn_linger = 0;
			connp->conn_lingertime = 0;
		}
		break;
	}
	case SO_OOBINLINE:
		connp->conn_oobinline = onoff;
		coa->coa_changed |= COA_OOBINLINE_CHANGED;
		break;
	case SO_REUSEADDR:
		connp->conn_reuseaddr = onoff;
		break;
	case SO_DONTROUTE:
		if (onoff)
			ixa->ixa_flags |= IXAF_DONTROUTE;
		else
			ixa->ixa_flags &= ~IXAF_DONTROUTE;
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case SO_USELOOPBACK:
		connp->conn_useloopback = onoff;
		break;
	case SO_BROADCAST:
		connp->conn_broadcast = onoff;
		break;
	case SO_SNDBUF:
		/* ULP has range checked the value */
		connp->conn_sndbuf = *i1;
		coa->coa_changed |= COA_SNDBUF_CHANGED;
		break;
	case SO_RCVBUF:
		/* ULP has range checked the value */
		connp->conn_rcvbuf = *i1;
		coa->coa_changed |= COA_RCVBUF_CHANGED;
		break;
	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
		/*
		 * Pass these two options in order for third part
		 * protocol usage.
		 */
		break;
	case SO_DGRAM_ERRIND:
		connp->conn_dgram_errind = onoff;
		break;
	case SO_RECVUCRED:
		connp->conn_recv_ancillary.crb_recvucred = onoff;
		break;
	case SO_ALLZONES:
		connp->conn_allzones = onoff;
		coa->coa_changed |= COA_ROUTE_CHANGED;
		if (onoff)
			ixa->ixa_zoneid = ALL_ZONES;
		else
			ixa->ixa_zoneid = connp->conn_zoneid;
		break;
	case SO_TIMESTAMP:
		connp->conn_recv_ancillary.crb_timestamp = onoff;
		break;
	case SO_VRRP:
		connp->conn_isvrrp = onoff;
		break;
	case SO_ANON_MLP:
		connp->conn_anon_mlp = onoff;
		break;
	case SO_MAC_EXEMPT:
		connp->conn_mac_mode = onoff ?
		    CONN_MAC_AWARE : CONN_MAC_DEFAULT;
		break;
	case SO_MAC_IMPLICIT:
		connp->conn_mac_mode = onoff ?
		    CONN_MAC_IMPLICIT : CONN_MAC_DEFAULT;
		break;
	case SO_EXCLBIND:
		connp->conn_exclbind = onoff;
		break;
	}
	mutex_exit(&connp->conn_lock);
	return (0);
}

/* Handle IPPROTO_IP */
static int
conn_opt_set_ip(conn_opt_arg_t *coa, t_scalar_t name, uint_t inlen,
    uchar_t *invalp, boolean_t checkonly, cred_t *cr)
{
	conn_t		*connp = coa->coa_connp;
	ip_xmit_attr_t	*ixa = coa->coa_ixa;
	ip_pkt_t	*ipp = coa->coa_ipp;
	int		*i1 = (int *)invalp;
	boolean_t	onoff = (*i1 == 0) ? 0 : 1;
	ipaddr_t	addr = (ipaddr_t)*i1;
	uint_t		ifindex;
	zoneid_t	zoneid = IPCL_ZONEID(connp);
	ipif_t		*ipif;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	int		error;

	if (connp->conn_family != AF_INET)
		return (EINVAL);

	switch (name) {
	case IP_TTL:
		/* Don't allow zero */
		if (*i1 < 1 || *i1 > 255)
			return (EINVAL);
		break;
	case IP_MULTICAST_IF:
		if (addr == INADDR_ANY) {
			/* Clear */
			ifindex = 0;
			break;
		}
		ipif = ipif_lookup_addr(addr, NULL, zoneid, ipst);
		if (ipif == NULL)
			return (EHOSTUNREACH);
		/* not supported by the virtual network iface */
		if (IS_VNI(ipif->ipif_ill)) {
			ipif_refrele(ipif);
			return (EINVAL);
		}
		ifindex = ipif->ipif_ill->ill_phyint->phyint_ifindex;
		ipif_refrele(ipif);
		break;
	case IP_NEXTHOP: {
		ire_t	*ire;

		if (addr == INADDR_ANY) {
			/* Clear */
			break;
		}
		/* Verify that the next-hop is on-link */
		ire = ire_ftable_lookup_v4(addr, 0, 0, IRE_ONLINK, NULL, zoneid,
		    NULL, MATCH_IRE_TYPE, 0, ipst, NULL);
		if (ire == NULL)
			return (EHOSTUNREACH);
		ire_refrele(ire);
		break;
	}
	case IP_OPTIONS:
	case T_IP_OPTIONS: {
		uint_t newlen;

		if (ipp->ipp_fields & IPPF_LABEL_V4)
			newlen = inlen + (ipp->ipp_label_len_v4 + 3) & ~3;
		else
			newlen = inlen;
		if ((inlen & 0x3) || newlen > IP_MAX_OPT_LENGTH) {
			return (EINVAL);
		}
		break;
	}
	case IP_PKTINFO: {
		struct in_pktinfo *pktinfo;

		/* Two different valid lengths */
		if (inlen != sizeof (int) &&
		    inlen != sizeof (struct in_pktinfo))
			return (EINVAL);
		if (inlen == sizeof (int))
			break;

		pktinfo = (struct in_pktinfo *)invalp;
		if (pktinfo->ipi_spec_dst.s_addr != INADDR_ANY) {
			switch (ip_laddr_verify_v4(pktinfo->ipi_spec_dst.s_addr,
			    zoneid, ipst, B_FALSE)) {
			case IPVL_UNICAST_UP:
			case IPVL_UNICAST_DOWN:
				break;
			default:
				return (EADDRNOTAVAIL);
			}
		}
		if (!ip_xmit_ifindex_valid(pktinfo->ipi_ifindex, zoneid,
		    B_FALSE, ipst))
			return (ENXIO);
		break;
	}
	case IP_BOUND_IF:
		ifindex = *(uint_t *)i1;

		/* Just check it is ok. */
		if (!ip_xmit_ifindex_valid(ifindex, zoneid, B_FALSE, ipst))
			return (ENXIO);
		break;
	}
	if (checkonly)
		return (0);

	/* Here we set the actual option value */
	/*
	 * conn_lock protects the bitfields, and is used to
	 * set the fields atomically. Not needed for ixa settings since
	 * the caller has an exclusive copy of the ixa.
	 * We can not hold conn_lock across the multicast options though.
	 */
	switch (name) {
	case IP_OPTIONS:
	case T_IP_OPTIONS:
		/* Save options for use by IP. */
		mutex_enter(&connp->conn_lock);
		error = optcom_pkt_set(invalp, inlen,
		    (uchar_t **)&ipp->ipp_ipv4_options,
		    &ipp->ipp_ipv4_options_len);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			return (error);
		}
		if (ipp->ipp_ipv4_options_len == 0) {
			ipp->ipp_fields &= ~IPPF_IPV4_OPTIONS;
		} else {
			ipp->ipp_fields |= IPPF_IPV4_OPTIONS;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		coa->coa_changed |= COA_WROFF_CHANGED;
		break;

	case IP_TTL:
		mutex_enter(&connp->conn_lock);
		ipp->ipp_unicast_hops = *i1;
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		break;
	case IP_TOS:
	case T_IP_TOS:
		mutex_enter(&connp->conn_lock);
		if (*i1 == -1) {
			ipp->ipp_type_of_service = 0;
		} else {
			ipp->ipp_type_of_service = *i1;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		break;
	case IP_MULTICAST_IF:
		ixa->ixa_multicast_ifindex = ifindex;
		ixa->ixa_multicast_ifaddr = addr;
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IP_MULTICAST_TTL:
		ixa->ixa_multicast_ttl = *invalp;
		/* Handled automatically by ip_output */
		break;
	case IP_MULTICAST_LOOP:
		if (*invalp != 0)
			ixa->ixa_flags |= IXAF_MULTICAST_LOOP;
		else
			ixa->ixa_flags &= ~IXAF_MULTICAST_LOOP;
		/* Handled automatically by ip_output */
		break;
	case IP_RECVOPTS:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_recvopts = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IP_RECVDSTADDR:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_recvdstaddr = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IP_RECVIF:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_recvif = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IP_RECVSLLA:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_recvslla = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IP_RECVTTL:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_recvttl = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IP_PKTINFO: {
		/*
		 * This also handles IP_RECVPKTINFO.
		 * IP_PKTINFO and IP_RECVPKTINFO have same value.
		 * Differentiation is based on the size of the
		 * argument passed in.
		 */
		struct in_pktinfo *pktinfo;

		if (inlen == sizeof (int)) {
			/* This is IP_RECVPKTINFO option. */
			mutex_enter(&connp->conn_lock);
			connp->conn_recv_ancillary.crb_ip_recvpktinfo =
			    onoff;
			mutex_exit(&connp->conn_lock);
			break;
		}

		/* This is IP_PKTINFO option. */
		mutex_enter(&connp->conn_lock);
		pktinfo = (struct in_pktinfo *)invalp;
		if (pktinfo->ipi_spec_dst.s_addr != INADDR_ANY) {
			ipp->ipp_fields |= IPPF_ADDR;
			IN6_INADDR_TO_V4MAPPED(&pktinfo->ipi_spec_dst,
			    &ipp->ipp_addr);
		} else {
			ipp->ipp_fields &= ~IPPF_ADDR;
			ipp->ipp_addr = ipv6_all_zeros;
		}
		mutex_exit(&connp->conn_lock);
		ixa->ixa_ifindex = pktinfo->ipi_ifindex;
		coa->coa_changed |= COA_ROUTE_CHANGED;
		coa->coa_changed |= COA_HEADER_CHANGED;
		break;
	}
	case IP_DONTFRAG:
		if (onoff) {
			ixa->ixa_flags |= (IXAF_DONTFRAG | IXAF_PMTU_IPV4_DF);
			ixa->ixa_flags &= ~IXAF_PMTU_DISCOVERY;
		} else {
			ixa->ixa_flags &= ~(IXAF_DONTFRAG | IXAF_PMTU_IPV4_DF);
			ixa->ixa_flags |= IXAF_PMTU_DISCOVERY;
		}
		/* Need to redo ip_attr_connect */
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IP_ADD_MEMBERSHIP:
	case IP_DROP_MEMBERSHIP:
	case MCAST_JOIN_GROUP:
	case MCAST_LEAVE_GROUP:
		return (ip_opt_set_multicast_group(connp, name,
		    invalp, B_FALSE, checkonly));

	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE:
	case IP_ADD_SOURCE_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		return (ip_opt_set_multicast_sources(connp, name,
		    invalp, B_FALSE, checkonly));

	case IP_SEC_OPT:
		mutex_enter(&connp->conn_lock);
		error = ipsec_set_req(cr, connp, (ipsec_req_t *)invalp);
		mutex_exit(&connp->conn_lock);
		if (error != 0) {
			return (error);
		}
		/* This is an IPsec policy change - redo ip_attr_connect */
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IP_NEXTHOP:
		ixa->ixa_nexthop_v4 = addr;
		if (addr != INADDR_ANY)
			ixa->ixa_flags |= IXAF_NEXTHOP_SET;
		else
			ixa->ixa_flags &= ~IXAF_NEXTHOP_SET;
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;

	case IP_BOUND_IF:
		ixa->ixa_ifindex = ifindex;		/* Send */
		mutex_enter(&connp->conn_lock);
		connp->conn_incoming_ifindex = ifindex;	/* Receive */
		connp->conn_bound_if = ifindex;		/* getsockopt */
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IP_UNSPEC_SRC:
		mutex_enter(&connp->conn_lock);
		connp->conn_unspec_src = onoff;
		if (onoff)
			ixa->ixa_flags &= ~IXAF_VERIFY_SOURCE;
		else
			ixa->ixa_flags |= IXAF_VERIFY_SOURCE;

		mutex_exit(&connp->conn_lock);
		break;
	case IP_BROADCAST_TTL:
		ixa->ixa_broadcast_ttl = *invalp;
		ixa->ixa_flags |= IXAF_BROADCAST_TTL_SET;
		/* Handled automatically by ip_output */
		break;
	case MRT_INIT:
	case MRT_DONE:
	case MRT_ADD_VIF:
	case MRT_DEL_VIF:
	case MRT_ADD_MFC:
	case MRT_DEL_MFC:
	case MRT_ASSERT:
		if ((error = secpolicy_ip_config(cr, B_FALSE)) != 0) {
			return (error);
		}
		error = ip_mrouter_set((int)name, connp, checkonly,
		    (uchar_t *)invalp, inlen);
		if (error) {
			return (error);
		}
		return (0);

	}
	return (0);
}

/* Handle IPPROTO_IPV6 */
static int
conn_opt_set_ipv6(conn_opt_arg_t *coa, t_scalar_t name, uint_t inlen,
    uchar_t *invalp, boolean_t checkonly, cred_t *cr)
{
	conn_t		*connp = coa->coa_connp;
	ip_xmit_attr_t	*ixa = coa->coa_ixa;
	ip_pkt_t	*ipp = coa->coa_ipp;
	int		*i1 = (int *)invalp;
	boolean_t	onoff = (*i1 == 0) ? 0 : 1;
	uint_t		ifindex;
	zoneid_t	zoneid = IPCL_ZONEID(connp);
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	int		error;

	if (connp->conn_family != AF_INET6)
		return (EINVAL);

	switch (name) {
	case IPV6_MULTICAST_IF:
		/*
		 * The only possible error is EINVAL.
		 * We call this option on both V4 and V6
		 * If both fail, then this call returns
		 * EINVAL. If at least one of them succeeds we
		 * return success.
		 */
		ifindex = *(uint_t *)i1;

		if (!ip_xmit_ifindex_valid(ifindex, zoneid, B_TRUE, ipst) &&
		    !ip_xmit_ifindex_valid(ifindex, zoneid, B_FALSE, ipst))
			return (EINVAL);
		break;
	case IPV6_UNICAST_HOPS:
		/* Don't allow zero. -1 means to use default */
		if (*i1 < -1 || *i1 == 0 || *i1 > IPV6_MAX_HOPS)
			return (EINVAL);
		break;
	case IPV6_MULTICAST_HOPS:
		/* -1 means use default */
		if (*i1 < -1 || *i1 > IPV6_MAX_HOPS)
			return (EINVAL);
		break;
	case IPV6_MULTICAST_LOOP:
		if (*i1 != 0 && *i1 != 1)
			return (EINVAL);
		break;
	case IPV6_BOUND_IF:
		ifindex = *(uint_t *)i1;

		if (!ip_xmit_ifindex_valid(ifindex, zoneid, B_TRUE, ipst))
			return (ENXIO);
		break;
	case IPV6_PKTINFO: {
		struct in6_pktinfo *pkti;
		boolean_t isv6;

		if (inlen != 0 && inlen != sizeof (struct in6_pktinfo))
			return (EINVAL);
		if (inlen == 0)
			break;	/* Clear values below */

		/*
		 * Verify the source address and ifindex. Privileged users
		 * can use any source address.
		 */
		pkti = (struct in6_pktinfo *)invalp;

		/*
		 * For link-local addresses we use the ipi6_ifindex when
		 * we verify the local address.
		 * If net_rawaccess then any source address can be used.
		 */
		if (!IN6_IS_ADDR_UNSPECIFIED(&pkti->ipi6_addr) &&
		    secpolicy_net_rawaccess(cr) != 0) {
			uint_t scopeid = 0;
			in6_addr_t *v6src = &pkti->ipi6_addr;
			ipaddr_t v4src;
			ip_laddr_t laddr_type = IPVL_UNICAST_UP;

			if (IN6_IS_ADDR_V4MAPPED(v6src)) {
				IN6_V4MAPPED_TO_IPADDR(v6src, v4src);
				if (v4src != INADDR_ANY) {
					laddr_type = ip_laddr_verify_v4(v4src,
					    zoneid, ipst, B_FALSE);
				}
			} else {
				if (IN6_IS_ADDR_LINKSCOPE(v6src))
					scopeid = pkti->ipi6_ifindex;

				laddr_type = ip_laddr_verify_v6(v6src, zoneid,
				    ipst, B_FALSE, scopeid);
			}
			switch (laddr_type) {
			case IPVL_UNICAST_UP:
			case IPVL_UNICAST_DOWN:
				break;
			default:
				return (EADDRNOTAVAIL);
			}
			ixa->ixa_flags |= IXAF_VERIFY_SOURCE;
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&pkti->ipi6_addr)) {
			/* Allow any source */
			ixa->ixa_flags &= ~IXAF_VERIFY_SOURCE;
		}
		isv6 = !(IN6_IS_ADDR_V4MAPPED(&pkti->ipi6_addr));
		if (!ip_xmit_ifindex_valid(pkti->ipi6_ifindex, zoneid, isv6,
		    ipst))
			return (ENXIO);
		break;
	}
	case IPV6_HOPLIMIT:
		/* It is only allowed as ancilary data */
		if (!coa->coa_ancillary)
			return (EINVAL);

		if (inlen != 0 && inlen != sizeof (int))
			return (EINVAL);
		if (inlen == sizeof (int)) {
			if (*i1 > 255 || *i1 < -1 || *i1 == 0)
				return (EINVAL);
		}
		break;
	case IPV6_TCLASS:
		if (inlen != 0 && inlen != sizeof (int))
			return (EINVAL);
		if (inlen == sizeof (int)) {
			if (*i1 > 255 || *i1 < -1)
				return (EINVAL);
		}
		break;
	case IPV6_NEXTHOP:
		if (inlen != 0 && inlen != sizeof (sin6_t))
			return (EINVAL);
		if (inlen == sizeof (sin6_t)) {
			sin6_t *sin6 = (sin6_t *)invalp;
			ire_t	*ire;

			if (sin6->sin6_family != AF_INET6)
				return (EAFNOSUPPORT);
			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
				return (EADDRNOTAVAIL);

			/* Verify that the next-hop is on-link */
			ire = ire_ftable_lookup_v6(&sin6->sin6_addr,
			    0, 0, IRE_ONLINK, NULL, zoneid,
			    NULL, MATCH_IRE_TYPE, 0, ipst, NULL);
			if (ire == NULL)
				return (EHOSTUNREACH);
			ire_refrele(ire);
			break;
		}
		break;
	case IPV6_RTHDR:
	case IPV6_DSTOPTS:
	case IPV6_RTHDRDSTOPTS:
	case IPV6_HOPOPTS: {
		/* All have the length field in the same place */
		ip6_hbh_t *hopts = (ip6_hbh_t *)invalp;
		/*
		 * Sanity checks - minimum size, size a multiple of
		 * eight bytes, and matching size passed in.
		 */
		if (inlen != 0 &&
		    inlen != (8 * (hopts->ip6h_len + 1)))
			return (EINVAL);
		break;
	}
	case IPV6_PATHMTU:
		/* Can't be set */
		return (EINVAL);

	case IPV6_USE_MIN_MTU:
		if (inlen != sizeof (int))
			return (EINVAL);
		if (*i1 < -1 || *i1 > 1)
			return (EINVAL);
		break;
	case IPV6_SRC_PREFERENCES:
		if (inlen != sizeof (uint32_t))
			return (EINVAL);
		break;
	case IPV6_V6ONLY:
		if (*i1 < 0 || *i1 > 1) {
			return (EINVAL);
		}
		break;
	}
	if (checkonly)
		return (0);

	/* Here we set the actual option value */
	/*
	 * conn_lock protects the bitfields, and is used to
	 * set the fields atomically. Not needed for ixa settings since
	 * the caller has an exclusive copy of the ixa.
	 * We can not hold conn_lock across the multicast options though.
	 */
	ASSERT(MUTEX_NOT_HELD(&coa->coa_connp->conn_lock));
	switch (name) {
	case IPV6_MULTICAST_IF:
		ixa->ixa_multicast_ifindex = ifindex;
		/* Need to redo ip_attr_connect */
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IPV6_UNICAST_HOPS:
		/* -1 means use default */
		mutex_enter(&connp->conn_lock);
		if (*i1 == -1) {
			ipp->ipp_unicast_hops = connp->conn_default_ttl;
		} else {
			ipp->ipp_unicast_hops = (uint8_t)*i1;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		break;
	case IPV6_MULTICAST_HOPS:
		/* -1 means use default */
		if (*i1 == -1) {
			ixa->ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
		} else {
			ixa->ixa_multicast_ttl = (uint8_t)*i1;
		}
		/* Handled automatically by ip_output */
		break;
	case IPV6_MULTICAST_LOOP:
		if (*i1 != 0)
			ixa->ixa_flags |= IXAF_MULTICAST_LOOP;
		else
			ixa->ixa_flags &= ~IXAF_MULTICAST_LOOP;
		/* Handled automatically by ip_output */
		break;
	case IPV6_JOIN_GROUP:
	case IPV6_LEAVE_GROUP:
	case MCAST_JOIN_GROUP:
	case MCAST_LEAVE_GROUP:
		return (ip_opt_set_multicast_group(connp, name,
		    invalp, B_TRUE, checkonly));

	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		return (ip_opt_set_multicast_sources(connp, name,
		    invalp, B_TRUE, checkonly));

	case IPV6_BOUND_IF:
		ixa->ixa_ifindex = ifindex;		/* Send */
		mutex_enter(&connp->conn_lock);
		connp->conn_incoming_ifindex = ifindex;	/* Receive */
		connp->conn_bound_if = ifindex;		/* getsockopt */
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IPV6_UNSPEC_SRC:
		mutex_enter(&connp->conn_lock);
		connp->conn_unspec_src = onoff;
		if (onoff)
			ixa->ixa_flags &= ~IXAF_VERIFY_SOURCE;
		else
			ixa->ixa_flags |= IXAF_VERIFY_SOURCE;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVPKTINFO:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_ip_recvpktinfo = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVTCLASS:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_ipv6_recvtclass = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVPATHMTU:
		mutex_enter(&connp->conn_lock);
		connp->conn_ipv6_recvpathmtu = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVHOPLIMIT:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_ipv6_recvhoplimit =
		    onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVHOPOPTS:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_ipv6_recvhopopts = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVDSTOPTS:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_ipv6_recvdstopts = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case _OLD_IPV6_RECVDSTOPTS:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_old_ipv6_recvdstopts =
		    onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVRTHDRDSTOPTS:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_ipv6_recvrthdrdstopts =
		    onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_RECVRTHDR:
		mutex_enter(&connp->conn_lock);
		connp->conn_recv_ancillary.crb_ipv6_recvrthdr = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	case IPV6_PKTINFO:
		mutex_enter(&connp->conn_lock);
		if (inlen == 0) {
			ipp->ipp_fields &= ~IPPF_ADDR;
			ipp->ipp_addr = ipv6_all_zeros;
			ixa->ixa_ifindex = 0;
		} else {
			struct in6_pktinfo *pkti;

			pkti = (struct in6_pktinfo *)invalp;
			ipp->ipp_addr = pkti->ipi6_addr;
			if (!IN6_IS_ADDR_UNSPECIFIED(&ipp->ipp_addr))
				ipp->ipp_fields |= IPPF_ADDR;
			else
				ipp->ipp_fields &= ~IPPF_ADDR;
			ixa->ixa_ifindex = pkti->ipi6_ifindex;
		}
		mutex_exit(&connp->conn_lock);
		/* Source and ifindex might have changed */
		coa->coa_changed |= COA_HEADER_CHANGED;
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IPV6_HOPLIMIT:
		mutex_enter(&connp->conn_lock);
		if (inlen == 0 || *i1 == -1) {
			/* Revert to default */
			ipp->ipp_fields &= ~IPPF_HOPLIMIT;
			ixa->ixa_flags &= ~IXAF_NO_TTL_CHANGE;
		} else {
			ipp->ipp_hoplimit = *i1;
			ipp->ipp_fields |= IPPF_HOPLIMIT;
			/* Ensure that it sticks for multicast packets */
			ixa->ixa_flags |= IXAF_NO_TTL_CHANGE;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		break;
	case IPV6_TCLASS:
		/*
		 * IPV6_TCLASS accepts -1 as use kernel default
		 * and [0, 255] as the actualy traffic class.
		 */
		mutex_enter(&connp->conn_lock);
		if (inlen == 0 || *i1 == -1) {
			ipp->ipp_tclass = 0;
			ipp->ipp_fields &= ~IPPF_TCLASS;
		} else {
			ipp->ipp_tclass = *i1;
			ipp->ipp_fields |= IPPF_TCLASS;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		break;
	case IPV6_NEXTHOP:
		if (inlen == 0) {
			ixa->ixa_flags &= ~IXAF_NEXTHOP_SET;
		} else {
			sin6_t *sin6 = (sin6_t *)invalp;

			ixa->ixa_nexthop_v6 = sin6->sin6_addr;
			if (!IN6_IS_ADDR_UNSPECIFIED(&ixa->ixa_nexthop_v6))
				ixa->ixa_flags |= IXAF_NEXTHOP_SET;
			else
				ixa->ixa_flags &= ~IXAF_NEXTHOP_SET;
		}
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IPV6_HOPOPTS:
		mutex_enter(&connp->conn_lock);
		error = optcom_pkt_set(invalp, inlen,
		    (uchar_t **)&ipp->ipp_hopopts, &ipp->ipp_hopoptslen);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			return (error);
		}
		if (ipp->ipp_hopoptslen == 0) {
			ipp->ipp_fields &= ~IPPF_HOPOPTS;
		} else {
			ipp->ipp_fields |= IPPF_HOPOPTS;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		coa->coa_changed |= COA_WROFF_CHANGED;
		break;
	case IPV6_RTHDRDSTOPTS:
		mutex_enter(&connp->conn_lock);
		error = optcom_pkt_set(invalp, inlen,
		    (uchar_t **)&ipp->ipp_rthdrdstopts,
		    &ipp->ipp_rthdrdstoptslen);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			return (error);
		}
		if (ipp->ipp_rthdrdstoptslen == 0) {
			ipp->ipp_fields &= ~IPPF_RTHDRDSTOPTS;
		} else {
			ipp->ipp_fields |= IPPF_RTHDRDSTOPTS;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		coa->coa_changed |= COA_WROFF_CHANGED;
		break;
	case IPV6_DSTOPTS:
		mutex_enter(&connp->conn_lock);
		error = optcom_pkt_set(invalp, inlen,
		    (uchar_t **)&ipp->ipp_dstopts, &ipp->ipp_dstoptslen);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			return (error);
		}
		if (ipp->ipp_dstoptslen == 0) {
			ipp->ipp_fields &= ~IPPF_DSTOPTS;
		} else {
			ipp->ipp_fields |= IPPF_DSTOPTS;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		coa->coa_changed |= COA_WROFF_CHANGED;
		break;
	case IPV6_RTHDR:
		mutex_enter(&connp->conn_lock);
		error = optcom_pkt_set(invalp, inlen,
		    (uchar_t **)&ipp->ipp_rthdr, &ipp->ipp_rthdrlen);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			return (error);
		}
		if (ipp->ipp_rthdrlen == 0) {
			ipp->ipp_fields &= ~IPPF_RTHDR;
		} else {
			ipp->ipp_fields |= IPPF_RTHDR;
		}
		mutex_exit(&connp->conn_lock);
		coa->coa_changed |= COA_HEADER_CHANGED;
		coa->coa_changed |= COA_WROFF_CHANGED;
		break;

	case IPV6_DONTFRAG:
		if (onoff) {
			ixa->ixa_flags |= IXAF_DONTFRAG;
			ixa->ixa_flags &= ~IXAF_PMTU_DISCOVERY;
		} else {
			ixa->ixa_flags &= ~IXAF_DONTFRAG;
			ixa->ixa_flags |= IXAF_PMTU_DISCOVERY;
		}
		/* Need to redo ip_attr_connect */
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;

	case IPV6_USE_MIN_MTU:
		ixa->ixa_flags |= IXAF_USE_MIN_MTU;
		ixa->ixa_use_min_mtu = *i1;
		/* Need to redo ip_attr_connect */
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;

	case IPV6_SEC_OPT:
		mutex_enter(&connp->conn_lock);
		error = ipsec_set_req(cr, connp, (ipsec_req_t *)invalp);
		mutex_exit(&connp->conn_lock);
		if (error != 0) {
			return (error);
		}
		/* This is an IPsec policy change - redo ip_attr_connect */
		coa->coa_changed |= COA_ROUTE_CHANGED;
		break;
	case IPV6_SRC_PREFERENCES:
		/*
		 * This socket option only affects connected
		 * sockets that haven't already bound to a specific
		 * IPv6 address.  In other words, sockets that
		 * don't call bind() with an address other than the
		 * unspecified address and that call connect().
		 * ip_set_destination_v6() passes these preferences
		 * to the ipif_select_source_v6() function.
		 */
		mutex_enter(&connp->conn_lock);
		error = ip6_set_src_preferences(ixa, *(uint32_t *)invalp);
		mutex_exit(&connp->conn_lock);
		if (error != 0) {
			return (error);
		}
		break;
	case IPV6_V6ONLY:
		mutex_enter(&connp->conn_lock);
		connp->conn_ipv6_v6only = onoff;
		mutex_exit(&connp->conn_lock);
		break;
	}
	return (0);
}

/* Handle IPPROTO_UDP */
/* ARGSUSED1 */
static int
conn_opt_set_udp(conn_opt_arg_t *coa, t_scalar_t name, uint_t inlen,
    uchar_t *invalp, boolean_t checkonly, cred_t *cr)
{
	conn_t		*connp = coa->coa_connp;
	int		*i1 = (int *)invalp;
	boolean_t	onoff = (*i1 == 0) ? 0 : 1;
	int		error;

	switch (name) {
	case UDP_ANONPRIVBIND:
		if ((error = secpolicy_net_privaddr(cr, 0, IPPROTO_UDP)) != 0) {
			return (error);
		}
		break;
	}
	if (checkonly)
		return (0);

	/* Here we set the actual option value */
	mutex_enter(&connp->conn_lock);
	switch (name) {
	case UDP_ANONPRIVBIND:
		connp->conn_anon_priv_bind = onoff;
		break;
	case UDP_EXCLBIND:
		connp->conn_exclbind = onoff;
		break;
	}
	mutex_exit(&connp->conn_lock);
	return (0);
}

/* Handle IPPROTO_TCP */
/* ARGSUSED1 */
static int
conn_opt_set_tcp(conn_opt_arg_t *coa, t_scalar_t name, uint_t inlen,
    uchar_t *invalp, boolean_t checkonly, cred_t *cr)
{
	conn_t		*connp = coa->coa_connp;
	int		*i1 = (int *)invalp;
	boolean_t	onoff = (*i1 == 0) ? 0 : 1;
	int		error;

	switch (name) {
	case TCP_ANONPRIVBIND:
		if ((error = secpolicy_net_privaddr(cr, 0, IPPROTO_TCP)) != 0) {
			return (error);
		}
		break;
	}
	if (checkonly)
		return (0);

	/* Here we set the actual option value */
	mutex_enter(&connp->conn_lock);
	switch (name) {
	case TCP_ANONPRIVBIND:
		connp->conn_anon_priv_bind = onoff;
		break;
	case TCP_EXCLBIND:
		connp->conn_exclbind = onoff;
		break;
	case TCP_RECVDSTADDR:
		connp->conn_recv_ancillary.crb_recvdstaddr = onoff;
		break;
	}
	mutex_exit(&connp->conn_lock);
	return (0);
}

int
conn_getsockname(conn_t *connp, struct sockaddr *sa, uint_t *salenp)
{
	sin_t		*sin;
	sin6_t		*sin6;

	if (connp->conn_family == AF_INET) {
		if (*salenp < sizeof (sin_t))
			return (EINVAL);

		*salenp = sizeof (sin_t);
		/* Fill zeroes and then initialize non-zero fields */
		sin = (sin_t *)sa;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		if (!IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_saddr_v6) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&connp->conn_saddr_v6)) {
			sin->sin_addr.s_addr = connp->conn_saddr_v4;
		} else {
			/*
			 * INADDR_ANY
			 * conn_saddr is not set, we might be bound to
			 * broadcast/multicast. Use conn_bound_addr as
			 * local address instead (that could
			 * also still be INADDR_ANY)
			 */
			sin->sin_addr.s_addr = connp->conn_bound_addr_v4;
		}
		sin->sin_port = connp->conn_lport;
	} else {
		if (*salenp < sizeof (sin6_t))
			return (EINVAL);

		*salenp = sizeof (sin6_t);
		/* Fill zeroes and then initialize non-zero fields */
		sin6 = (sin6_t *)sa;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_saddr_v6)) {
			sin6->sin6_addr = connp->conn_saddr_v6;
		} else {
			/*
			 * conn_saddr is not set, we might be bound to
			 * broadcast/multicast. Use conn_bound_addr as
			 * local address instead (which could
			 * also still be unspecified)
			 */
			sin6->sin6_addr = connp->conn_bound_addr_v6;
		}
		sin6->sin6_port = connp->conn_lport;
		if (IN6_IS_ADDR_LINKSCOPE(&sin6->sin6_addr) &&
		    (connp->conn_ixa->ixa_flags & IXAF_SCOPEID_SET))
			sin6->sin6_scope_id = connp->conn_ixa->ixa_scopeid;
	}
	return (0);
}

int
conn_getpeername(conn_t *connp, struct sockaddr *sa, uint_t *salenp)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;

	if (connp->conn_family == AF_INET) {
		if (*salenp < sizeof (sin_t))
			return (EINVAL);

		*salenp = sizeof (sin_t);
		/* initialize */
		sin = (sin_t *)sa;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = connp->conn_faddr_v4;
		sin->sin_port = connp->conn_fport;
	} else {
		if (*salenp < sizeof (sin6_t))
			return (EINVAL);

		*salenp = sizeof (sin6_t);
		/* initialize */
		sin6 = (sin6_t *)sa;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = connp->conn_faddr_v6;
		sin6->sin6_port =  connp->conn_fport;
		sin6->sin6_flowinfo = connp->conn_flowinfo;
		if (IN6_IS_ADDR_LINKSCOPE(&sin6->sin6_addr) &&
		    (connp->conn_ixa->ixa_flags & IXAF_SCOPEID_SET))
			sin6->sin6_scope_id = connp->conn_ixa->ixa_scopeid;
	}
	return (0);
}

static uint32_t	cksum_massage_options_v4(ipha_t *, netstack_t *);
static uint32_t cksum_massage_options_v6(ip6_t *, uint_t, netstack_t *);

/*
 * Allocate and fill in conn_ht_iphc based on the current information
 * in the conn.
 * Normally used when we bind() and connect().
 * Returns failure if can't allocate memory, or if there is a problem
 * with a routing header/option.
 *
 * We allocate space for the transport header (ulp_hdr_len + extra) and
 * indicate the offset of the ulp header by setting ixa_ip_hdr_length.
 * The extra is there for transports that want some spare room for future
 * options. conn_ht_iphc_allocated is what was allocated; conn_ht_iphc_len
 * excludes the extra part.
 *
 * We massage an routing option/header and store the ckecksum difference
 * in conn_sum.
 *
 * Caller needs to update conn_wroff if desired.
 */
int
conn_build_hdr_template(conn_t *connp, uint_t ulp_hdr_length, uint_t extra,
    const in6_addr_t *v6src, const in6_addr_t *v6dst, uint32_t flowinfo)
{
	ip_xmit_attr_t	*ixa = connp->conn_ixa;
	ip_pkt_t	*ipp = &connp->conn_xmit_ipp;
	uint_t		ip_hdr_length;
	uchar_t		*hdrs;
	uint_t		hdrs_len;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ip_hdr_length = ip_total_hdrs_len_v4(ipp);
		/* In case of TX label and IP options it can be too much */
		if (ip_hdr_length > IP_MAX_HDR_LENGTH) {
			/* Preserves existing TX errno for this */
			return (EHOSTUNREACH);
		}
	} else {
		ip_hdr_length = ip_total_hdrs_len_v6(ipp);
	}
	ixa->ixa_ip_hdr_length = ip_hdr_length;
	hdrs_len = ip_hdr_length + ulp_hdr_length + extra;
	ASSERT(hdrs_len != 0);

	if (hdrs_len != connp->conn_ht_iphc_allocated) {
		/* Allocate new before we free any old */
		hdrs = kmem_alloc(hdrs_len, KM_NOSLEEP);
		if (hdrs == NULL)
			return (ENOMEM);

		if (connp->conn_ht_iphc != NULL) {
			kmem_free(connp->conn_ht_iphc,
			    connp->conn_ht_iphc_allocated);
		}
		connp->conn_ht_iphc = hdrs;
		connp->conn_ht_iphc_allocated = hdrs_len;
	} else {
		hdrs = connp->conn_ht_iphc;
	}
	hdrs_len -= extra;
	connp->conn_ht_iphc_len = hdrs_len;

	connp->conn_ht_ulp = hdrs + ip_hdr_length;
	connp->conn_ht_ulp_len = ulp_hdr_length;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t	*ipha = (ipha_t *)hdrs;

		IN6_V4MAPPED_TO_IPADDR(v6src, ipha->ipha_src);
		IN6_V4MAPPED_TO_IPADDR(v6dst, ipha->ipha_dst);
		ip_build_hdrs_v4(hdrs, ip_hdr_length, ipp, connp->conn_proto);
		ipha->ipha_length = htons(hdrs_len);
		if (ixa->ixa_flags & IXAF_PMTU_IPV4_DF)
			ipha->ipha_fragment_offset_and_flags |= IPH_DF_HTONS;
		else
			ipha->ipha_fragment_offset_and_flags &= ~IPH_DF_HTONS;

		if (ipp->ipp_fields & IPPF_IPV4_OPTIONS) {
			connp->conn_sum = cksum_massage_options_v4(ipha,
			    connp->conn_netstack);
		} else {
			connp->conn_sum = 0;
		}
	} else {
		ip6_t	*ip6h = (ip6_t *)hdrs;

		ip6h->ip6_src = *v6src;
		ip6h->ip6_dst = *v6dst;
		ip_build_hdrs_v6(hdrs, ip_hdr_length, ipp, connp->conn_proto,
		    flowinfo);
		ip6h->ip6_plen = htons(hdrs_len - IPV6_HDR_LEN);

		if (ipp->ipp_fields & IPPF_RTHDR) {
			connp->conn_sum = cksum_massage_options_v6(ip6h,
			    ip_hdr_length, connp->conn_netstack);

			/*
			 * Verify that the first hop isn't a mapped address.
			 * Routers along the path need to do this verification
			 * for subsequent hops.
			 */
			if (IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_dst))
				return (EADDRNOTAVAIL);

		} else {
			connp->conn_sum = 0;
		}
	}
	return (0);
}

/*
 * Prepend a header template to data_mp based on the ip_pkt_t
 * and the passed in source, destination and protocol.
 *
 * Returns failure if can't allocate memory, in which case data_mp is freed.
 * We allocate space for the transport header (ulp_hdr_len) and
 * indicate the offset of the ulp header by setting ixa_ip_hdr_length.
 *
 * We massage an routing option/header and return the ckecksum difference
 * in *sump. This is in host byte order.
 *
 * Caller needs to update conn_wroff if desired.
 */
mblk_t *
conn_prepend_hdr(ip_xmit_attr_t *ixa, const ip_pkt_t *ipp,
    const in6_addr_t *v6src, const in6_addr_t *v6dst,
    uint8_t protocol, uint32_t flowinfo, uint_t ulp_hdr_length, mblk_t *data_mp,
    uint_t data_length, uint_t wroff_extra, uint32_t *sump, int *errorp)
{
	uint_t		ip_hdr_length;
	uchar_t		*hdrs;
	uint_t		hdrs_len;
	mblk_t		*mp;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ip_hdr_length = ip_total_hdrs_len_v4(ipp);
		ASSERT(ip_hdr_length <= IP_MAX_HDR_LENGTH);
	} else {
		ip_hdr_length = ip_total_hdrs_len_v6(ipp);
	}
	hdrs_len = ip_hdr_length + ulp_hdr_length;
	ASSERT(hdrs_len != 0);

	ixa->ixa_ip_hdr_length = ip_hdr_length;

	/* Can we prepend to data_mp? */
	if (data_mp != NULL &&
	    data_mp->b_rptr - data_mp->b_datap->db_base >= hdrs_len &&
	    data_mp->b_datap->db_ref == 1) {
		hdrs = data_mp->b_rptr - hdrs_len;
		data_mp->b_rptr = hdrs;
		mp = data_mp;
	} else {
		mp = allocb(hdrs_len + wroff_extra, BPRI_MED);
		if (mp == NULL) {
			freemsg(data_mp);
			*errorp = ENOMEM;
			return (NULL);
		}
		mp->b_wptr = mp->b_datap->db_lim;
		hdrs = mp->b_rptr = mp->b_wptr - hdrs_len;
		mp->b_cont = data_mp;
	}

	/*
	 * Set the source in the header. ip_build_hdrs_v4/v6 will overwrite it
	 * if PKTINFO (aka IPPF_ADDR) was set.
	 */
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t *ipha = (ipha_t *)hdrs;

		ASSERT(IN6_IS_ADDR_V4MAPPED(v6dst));
		IN6_V4MAPPED_TO_IPADDR(v6src, ipha->ipha_src);
		IN6_V4MAPPED_TO_IPADDR(v6dst, ipha->ipha_dst);
		ip_build_hdrs_v4(hdrs, ip_hdr_length, ipp, protocol);
		ipha->ipha_length = htons(hdrs_len + data_length);
		if (ixa->ixa_flags & IXAF_PMTU_IPV4_DF)
			ipha->ipha_fragment_offset_and_flags |= IPH_DF_HTONS;
		else
			ipha->ipha_fragment_offset_and_flags &= ~IPH_DF_HTONS;

		if (ipp->ipp_fields & IPPF_IPV4_OPTIONS) {
			*sump = cksum_massage_options_v4(ipha,
			    ixa->ixa_ipst->ips_netstack);
		} else {
			*sump = 0;
		}
	} else {
		ip6_t *ip6h = (ip6_t *)hdrs;

		ip6h->ip6_src = *v6src;
		ip6h->ip6_dst = *v6dst;
		ip_build_hdrs_v6(hdrs, ip_hdr_length, ipp, protocol, flowinfo);
		ip6h->ip6_plen = htons(hdrs_len + data_length - IPV6_HDR_LEN);

		if (ipp->ipp_fields & IPPF_RTHDR) {
			*sump = cksum_massage_options_v6(ip6h,
			    ip_hdr_length, ixa->ixa_ipst->ips_netstack);

			/*
			 * Verify that the first hop isn't a mapped address.
			 * Routers along the path need to do this verification
			 * for subsequent hops.
			 */
			if (IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_dst)) {
				*errorp = EADDRNOTAVAIL;
				freemsg(mp);
				return (NULL);
			}
		} else {
			*sump = 0;
		}
	}
	return (mp);
}

/*
 * Massage a source route if any putting the first hop
 * in ipha_dst. Compute a starting value for the checksum which
 * takes into account that the original ipha_dst should be
 * included in the checksum but that IP will include the
 * first hop from the source route in the tcp checksum.
 */
static uint32_t
cksum_massage_options_v4(ipha_t *ipha, netstack_t *ns)
{
	in_addr_t	dst;
	uint32_t	cksum;

	/* Get last hop then diff against first hop */
	cksum = ip_massage_options(ipha, ns);
	cksum = (cksum & 0xFFFF) + (cksum >> 16);
	dst = ipha->ipha_dst;
	cksum -= ((dst >> 16) + (dst & 0xffff));
	if ((int)cksum < 0)
		cksum--;
	cksum = (cksum & 0xFFFF) + (cksum >> 16);
	cksum = (cksum & 0xFFFF) + (cksum >> 16);
	ASSERT(cksum < 0x10000);
	return (ntohs(cksum));
}

static uint32_t
cksum_massage_options_v6(ip6_t *ip6h, uint_t ip_hdr_len, netstack_t *ns)
{
	uint8_t		*end;
	ip6_rthdr_t	*rth;
	uint32_t	cksum;

	end = (uint8_t *)ip6h + ip_hdr_len;
	rth = ip_find_rthdr_v6(ip6h, end);
	if (rth == NULL)
		return (0);

	cksum = ip_massage_options_v6(ip6h, rth, ns);
	cksum = (cksum & 0xFFFF) + (cksum >> 16);
	ASSERT(cksum < 0x10000);
	return (ntohs(cksum));
}

/*
 * ULPs that change the destination address need to call this for each
 * change to discard any state about a previous destination that might
 * have been multicast or multirt.
 */
void
ip_attr_newdst(ip_xmit_attr_t *ixa)
{
	ixa->ixa_flags &= ~(IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM |
	    IXAF_NO_TTL_CHANGE | IXAF_IPV6_ADD_FRAGHDR |
	    IXAF_NO_LOOP_ZONEID_SET);
}

/*
 * Determine the nexthop which will be used.
 * Normally this is just the destination, but if a IPv4 source route, or
 * IPv6 routing header, is in the ip_pkt_t then we extract the nexthop from
 * there.
 */
void
ip_attr_nexthop(const ip_pkt_t *ipp, const ip_xmit_attr_t *ixa,
    const in6_addr_t *dst, in6_addr_t *nexthop)
{
	if (!(ipp->ipp_fields & (IPPF_IPV4_OPTIONS|IPPF_RTHDR))) {
		*nexthop = *dst;
		return;
	}
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipaddr_t v4dst;
		ipaddr_t v4nexthop;

		IN6_V4MAPPED_TO_IPADDR(dst, v4dst);
		v4nexthop = ip_pkt_source_route_v4(ipp);
		if (v4nexthop == INADDR_ANY)
			v4nexthop = v4dst;

		IN6_IPADDR_TO_V4MAPPED(v4nexthop, nexthop);
	} else {
		const in6_addr_t *v6nexthop;

		v6nexthop = ip_pkt_source_route_v6(ipp);
		if (v6nexthop == NULL)
			v6nexthop = dst;

		*nexthop = *v6nexthop;
	}
}

/*
 * Update the ip_xmit_attr_t based the addresses, conn_xmit_ipp and conn_ixa.
 * If IPDF_IPSEC is set we cache the IPsec policy to handle the unconnected
 * case (connected latching is done in conn_connect).
 * Note that IPsec policy lookup requires conn_proto and conn_laddr to be
 * set, but doesn't otherwise use the conn_t.
 *
 * Caller must set/clear IXAF_IS_IPV4 as appropriately.
 * Caller must use ip_attr_nexthop() to determine the nexthop argument.
 *
 * The caller must NOT hold conn_lock (to avoid problems with ill_refrele
 * causing the squeue to run doing ipcl_walk grabbing conn_lock.)
 *
 * Updates laddrp and uinfo if they are non-NULL.
 *
 * TSOL notes: The callers if ip_attr_connect must check if the destination
 * is different than before and in that case redo conn_update_label.
 * The callers of conn_connect do not need that since conn_connect
 * performs the conn_update_label.
 */
int
ip_attr_connect(const conn_t *connp, ip_xmit_attr_t *ixa,
    const in6_addr_t *v6src, const in6_addr_t *v6dst,
    const in6_addr_t *v6nexthop, in_port_t dstport, in6_addr_t *laddrp,
    iulp_t *uinfo, uint32_t flags)
{
	in6_addr_t		laddr = *v6src;
	int			error;

	ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));

	if (connp->conn_zone_is_global)
		flags |= IPDF_ZONE_IS_GLOBAL;
	else
		flags &= ~IPDF_ZONE_IS_GLOBAL;

	/*
	 * Lookup the route to determine a source address and the uinfo.
	 * If the ULP has a source route option then the caller will
	 * have set v6nexthop to be the first hop.
	 */
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipaddr_t v4dst;
		ipaddr_t v4src, v4nexthop;

		IN6_V4MAPPED_TO_IPADDR(v6dst, v4dst);
		IN6_V4MAPPED_TO_IPADDR(v6nexthop, v4nexthop);
		IN6_V4MAPPED_TO_IPADDR(v6src, v4src);

		if (connp->conn_unspec_src || v4src != INADDR_ANY)
			flags &= ~IPDF_SELECT_SRC;
		else
			flags |= IPDF_SELECT_SRC;

		error = ip_set_destination_v4(&v4src, v4dst, v4nexthop, ixa,
		    uinfo, flags, connp->conn_mac_mode);
		IN6_IPADDR_TO_V4MAPPED(v4src, &laddr);
	} else {
		if (connp->conn_unspec_src || !IN6_IS_ADDR_UNSPECIFIED(v6src))
			flags &= ~IPDF_SELECT_SRC;
		else
			flags |= IPDF_SELECT_SRC;

		error = ip_set_destination_v6(&laddr, v6dst, v6nexthop, ixa,
		    uinfo, flags, connp->conn_mac_mode);
	}
	/* Pass out some address even if we hit a RTF_REJECT etc */
	if (laddrp != NULL)
		*laddrp = laddr;

	if (error != 0)
		return (error);

	if (flags & IPDF_IPSEC) {
		/*
		 * Set any IPsec policy in ixa. Routine also looks at ULP
		 * ports.
		 */
		ipsec_cache_outbound_policy(connp, v6src, v6dst, dstport, ixa);
	}
	return (0);
}

/*
 * Connect the conn based on the addresses, conn_xmit_ipp and conn_ixa.
 * Assumes that conn_faddr and conn_fport are already set. As such it is not
 * usable for SCTP, since SCTP has multiple faddrs.
 *
 * Caller must hold conn_lock to provide atomic constency between the
 * conn_t's addresses and the ixa.
 * NOTE: this function drops and reaquires conn_lock since it can't be
 * held across ip_attr_connect/ip_set_destination.
 *
 * The caller needs to handle inserting in the receive-side fanout when
 * appropriate after conn_connect returns.
 */
int
conn_connect(conn_t *connp, iulp_t *uinfo, uint32_t flags)
{
	ip_xmit_attr_t	*ixa = connp->conn_ixa;
	in6_addr_t	nexthop;
	in6_addr_t	saddr, faddr;
	in_port_t	fport;
	int		error;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	if (connp->conn_ipversion == IPV4_VERSION)
		ixa->ixa_flags |= IXAF_IS_IPV4;
	else
		ixa->ixa_flags &= ~IXAF_IS_IPV4;

	/* We do IPsec latching below - hence no caching in ip_attr_connect */
	flags &= ~IPDF_IPSEC;

	/* In case we had previously done an ip_attr_connect */
	ip_attr_newdst(ixa);

	/*
	 * Determine the nexthop and copy the addresses before dropping
	 * conn_lock.
	 */
	ip_attr_nexthop(&connp->conn_xmit_ipp, connp->conn_ixa,
	    &connp->conn_faddr_v6, &nexthop);
	saddr = connp->conn_saddr_v6;
	faddr = connp->conn_faddr_v6;
	fport = connp->conn_fport;

	mutex_exit(&connp->conn_lock);
	error = ip_attr_connect(connp, ixa, &saddr, &faddr, &nexthop, fport,
	    &saddr, uinfo, flags | IPDF_VERIFY_DST);
	mutex_enter(&connp->conn_lock);

	/* Could have changed even if an error */
	connp->conn_saddr_v6 = saddr;
	if (error != 0)
		return (error);

	/*
	 * Check whether Trusted Solaris policy allows communication with this
	 * host, and pretend that the destination is unreachable if not.
	 * Compute any needed label and place it in ipp_label_v4/v6.
	 *
	 * Later conn_build_hdr_template() takes ipp_label_v4/v6 to form
	 * the packet.
	 *
	 * TSOL Note: Any concurrent threads would pick a different ixa
	 * (and ipp if they are to change the ipp)  so we
	 * don't have to worry about concurrent threads.
	 */
	if (is_system_labeled()) {
		if (connp->conn_mlp_type != mlptSingle)
			return (ECONNREFUSED);

		/*
		 * conn_update_label will set ipp_label* which will later
		 * be used by conn_build_hdr_template.
		 */
		error = conn_update_label(connp, ixa,
		    &connp->conn_faddr_v6, &connp->conn_xmit_ipp);
		if (error != 0)
			return (error);
	}

	/*
	 * Ensure that we match on the selected local address.
	 * This overrides conn_laddr in the case we had earlier bound to a
	 * multicast or broadcast address.
	 */
	connp->conn_laddr_v6 = connp->conn_saddr_v6;

	/*
	 * Allow setting new policies.
	 * The addresses/ports are already set, thus the IPsec policy calls
	 * can handle their passed-in conn's.
	 */
	connp->conn_policy_cached = B_FALSE;

	/*
	 * Cache IPsec policy in this conn.  If we have per-socket policy,
	 * we'll cache that.  If we don't, we'll inherit global policy.
	 *
	 * This is done before the caller inserts in the receive-side fanout.
	 * Note that conn_policy_cached is set by ipsec_conn_cache_policy() even
	 * for connections where we don't have a policy. This is to prevent
	 * global policy lookups in the inbound path.
	 *
	 * If we insert before we set conn_policy_cached,
	 * CONN_INBOUND_POLICY_PRESENT() check can still evaluate true
	 * because global policy cound be non-empty. We normally call
	 * ipsec_check_policy() for conn_policy_cached connections only if
	 * conn_in_enforce_policy is set. But in this case,
	 * conn_policy_cached can get set anytime since we made the
	 * CONN_INBOUND_POLICY_PRESENT() check and ipsec_check_policy() is
	 * called, which will make the above assumption false.  Thus, we
	 * need to insert after we set conn_policy_cached.
	 */
	error = ipsec_conn_cache_policy(connp,
	    connp->conn_ipversion == IPV4_VERSION);
	if (error != 0)
		return (error);

	/*
	 * We defer to do LSO check until here since now we have better idea
	 * whether IPsec is present. If the underlying ill is LSO capable,
	 * copy its capability in so the ULP can decide whether to enable LSO
	 * on this connection. So far, only TCP/IPv4 is implemented, so won't
	 * claim LSO for IPv6.
	 *
	 * Currently, won't enable LSO for IRE_LOOPBACK or IRE_LOCAL, because
	 * the receiver can not handle it. Also not to enable LSO for MULTIRT.
	 */
	ixa->ixa_flags &= ~IXAF_LSO_CAPAB;

	ASSERT(ixa->ixa_ire != NULL);
	if (ixa->ixa_ipst->ips_ip_lso_outbound && (flags & IPDF_LSO) &&
	    !(ixa->ixa_flags & IXAF_IPSEC_SECURE) &&
	    !(ixa->ixa_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)) &&
	    !(ixa->ixa_ire->ire_flags & RTF_MULTIRT) &&
	    (ixa->ixa_nce != NULL) &&
	    ((ixa->ixa_flags & IXAF_IS_IPV4) ?
	    ILL_LSO_TCP_IPV4_USABLE(ixa->ixa_nce->nce_ill) :
	    ILL_LSO_TCP_IPV6_USABLE(ixa->ixa_nce->nce_ill))) {
		ixa->ixa_lso_capab = *ixa->ixa_nce->nce_ill->ill_lso_capab;
		ixa->ixa_flags |= IXAF_LSO_CAPAB;
	}

	/* Check whether ZEROCOPY capability is usable for this connection. */
	ixa->ixa_flags &= ~IXAF_ZCOPY_CAPAB;

	if ((flags & IPDF_ZCOPY) &&
	    !(ixa->ixa_flags & IXAF_IPSEC_SECURE) &&
	    !(ixa->ixa_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)) &&
	    !(ixa->ixa_ire->ire_flags & RTF_MULTIRT) &&
	    (ixa->ixa_nce != NULL) &&
	    ILL_ZCOPY_USABLE(ixa->ixa_nce->nce_ill)) {
		ixa->ixa_flags |= IXAF_ZCOPY_CAPAB;
	}
	return (0);
}

/*
 * Predicates to check if the addresses match conn_last*
 */

/*
 * Compare the conn against an address.
 * If using mapped addresses on AF_INET6 sockets, use the _v6 function
 */
boolean_t
conn_same_as_last_v4(conn_t *connp, sin_t *sin)
{
	ASSERT(connp->conn_family == AF_INET);
	return (sin->sin_addr.s_addr == connp->conn_v4lastdst &&
	    sin->sin_port == connp->conn_lastdstport);
}

/*
 * Compare, including for mapped addresses
 */
boolean_t
conn_same_as_last_v6(conn_t *connp, sin6_t *sin6)
{
	return (IN6_ARE_ADDR_EQUAL(&connp->conn_v6lastdst, &sin6->sin6_addr) &&
	    sin6->sin6_port == connp->conn_lastdstport &&
	    sin6->sin6_flowinfo == connp->conn_lastflowinfo &&
	    sin6->sin6_scope_id == connp->conn_lastscopeid);
}

/*
 * Compute a label and place it in the ip_packet_t.
 * Handles IPv4 and IPv6.
 * The caller should have a correct ixa_tsl and ixa_zoneid and have
 * already called conn_connect or ip_attr_connect to ensure that tsol_check_dest
 * has been called.
 */
int
conn_update_label(const conn_t *connp, const ip_xmit_attr_t *ixa,
    const in6_addr_t *v6dst, ip_pkt_t *ipp)
{
	int		err;
	ipaddr_t	v4dst;

	if (IN6_IS_ADDR_V4MAPPED(v6dst)) {
		uchar_t		opt_storage[IP_MAX_OPT_LENGTH];

		IN6_V4MAPPED_TO_IPADDR(v6dst, v4dst);

		err = tsol_compute_label_v4(ixa->ixa_tsl, ixa->ixa_zoneid,
		    v4dst, opt_storage, ixa->ixa_ipst);
		if (err == 0) {
			/* Length contained in opt_storage[IPOPT_OLEN] */
			err = optcom_pkt_set(opt_storage,
			    opt_storage[IPOPT_OLEN],
			    (uchar_t **)&ipp->ipp_label_v4,
			    &ipp->ipp_label_len_v4);
		}
		if (err != 0) {
			DTRACE_PROBE4(tx__ip__log__info__updatelabel,
			    char *, "conn(1) failed to update options(2) "
			    "on ixa(3)",
			    conn_t *, connp, char *, opt_storage,
			    ip_xmit_attr_t *, ixa);
		}
		if (ipp->ipp_label_len_v4 != 0)
			ipp->ipp_fields |= IPPF_LABEL_V4;
		else
			ipp->ipp_fields &= ~IPPF_LABEL_V4;
	} else {
		uchar_t		opt_storage[TSOL_MAX_IPV6_OPTION];
		uint_t		optlen;

		err = tsol_compute_label_v6(ixa->ixa_tsl, ixa->ixa_zoneid,
		    v6dst, opt_storage, ixa->ixa_ipst);
		if (err == 0) {
			/*
			 * Note that ipp_label_v6 is just the option - not
			 * the hopopts extension header.
			 *
			 * Length contained in opt_storage[IPOPT_OLEN], but
			 * that doesn't include the two byte options header.
			 */
			optlen = opt_storage[IPOPT_OLEN];
			if (optlen != 0)
				optlen += 2;

			err = optcom_pkt_set(opt_storage, optlen,
			    (uchar_t **)&ipp->ipp_label_v6,
			    &ipp->ipp_label_len_v6);
		}
		if (err != 0) {
			DTRACE_PROBE4(tx__ip__log__info__updatelabel,
			    char *, "conn(1) failed to update options(2) "
			    "on ixa(3)",
			    conn_t *, connp, char *, opt_storage,
			    ip_xmit_attr_t *, ixa);
		}
		if (ipp->ipp_label_len_v6 != 0)
			ipp->ipp_fields |= IPPF_LABEL_V6;
		else
			ipp->ipp_fields &= ~IPPF_LABEL_V6;
	}
	return (err);
}

/*
 * Inherit all options settings from the parent/listener to the eager.
 * Returns zero on success; ENOMEM if memory allocation failed.
 *
 * We assume that the eager has not had any work done i.e., the conn_ixa
 * and conn_xmit_ipp are all zero.
 * Furthermore we assume that no other thread can access the eager (because
 * it isn't inserted in any fanout list).
 */
int
conn_inherit_parent(conn_t *lconnp, conn_t *econnp)
{
	cred_t	*credp;
	int	err;
	void	*notify_cookie;
	uint32_t xmit_hint;

	econnp->conn_family = lconnp->conn_family;
	econnp->conn_ipv6_v6only = lconnp->conn_ipv6_v6only;
	econnp->conn_wq = lconnp->conn_wq;
	econnp->conn_rq = lconnp->conn_rq;

	/*
	 * Make a safe copy of the transmit attributes.
	 * conn_connect will later be used by the caller to setup the ire etc.
	 */
	ASSERT(econnp->conn_ixa->ixa_refcnt == 1);
	ASSERT(econnp->conn_ixa->ixa_ire == NULL);
	ASSERT(econnp->conn_ixa->ixa_dce == NULL);
	ASSERT(econnp->conn_ixa->ixa_nce == NULL);

	/* Preserve ixa_notify_cookie and xmit_hint */
	notify_cookie = econnp->conn_ixa->ixa_notify_cookie;
	xmit_hint = econnp->conn_ixa->ixa_xmit_hint;
	ixa_safe_copy(lconnp->conn_ixa, econnp->conn_ixa);
	econnp->conn_ixa->ixa_notify_cookie = notify_cookie;
	econnp->conn_ixa->ixa_xmit_hint = xmit_hint;

	econnp->conn_bound_if = lconnp->conn_bound_if;
	econnp->conn_incoming_ifindex = lconnp->conn_incoming_ifindex;

	/* Inherit all RECV options */
	econnp->conn_recv_ancillary = lconnp->conn_recv_ancillary;

	err = ip_pkt_copy(&lconnp->conn_xmit_ipp, &econnp->conn_xmit_ipp,
	    KM_NOSLEEP);
	if (err != 0)
		return (err);

	econnp->conn_zoneid = lconnp->conn_zoneid;
	econnp->conn_allzones = lconnp->conn_allzones;

	/* This is odd. Pick a flowlabel for each connection instead? */
	econnp->conn_flowinfo = lconnp->conn_flowinfo;

	econnp->conn_default_ttl = lconnp->conn_default_ttl;

	/*
	 * TSOL: tsol_input_proc() needs the eager's cred before the
	 * eager is accepted
	 */
	ASSERT(lconnp->conn_cred != NULL);
	econnp->conn_cred = credp = lconnp->conn_cred;
	crhold(credp);
	econnp->conn_cpid = lconnp->conn_cpid;
	econnp->conn_open_time = ddi_get_lbolt64();

	/*
	 * Cache things in the ixa without any refhold.
	 * Listener might not have set up ixa_cred
	 */
	ASSERT(!(econnp->conn_ixa->ixa_free_flags & IXA_FREE_CRED));
	econnp->conn_ixa->ixa_cred = econnp->conn_cred;
	econnp->conn_ixa->ixa_cpid = econnp->conn_cpid;
	if (is_system_labeled())
		econnp->conn_ixa->ixa_tsl = crgetlabel(econnp->conn_cred);

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		econnp->conn_mac_mode = CONN_MAC_AWARE;

	econnp->conn_zone_is_global = lconnp->conn_zone_is_global;

	/*
	 * We eliminate the need for sockfs to send down a T_SVR4_OPTMGMT_REQ
	 * via soaccept()->soinheritoptions() which essentially applies
	 * all the listener options to the new connection. The options that we
	 * need to take care of are:
	 * SO_DEBUG, SO_REUSEADDR, SO_KEEPALIVE, SO_DONTROUTE, SO_BROADCAST,
	 * SO_USELOOPBACK, SO_OOBINLINE, SO_DGRAM_ERRIND, SO_LINGER,
	 * SO_SNDBUF, SO_RCVBUF.
	 *
	 * SO_RCVBUF:	conn_rcvbuf is set.
	 * SO_SNDBUF:	conn_sndbuf is set.
	 */

	/* Could we define a struct and use a struct copy for this? */
	econnp->conn_sndbuf = lconnp->conn_sndbuf;
	econnp->conn_rcvbuf = lconnp->conn_rcvbuf;
	econnp->conn_sndlowat = lconnp->conn_sndlowat;
	econnp->conn_rcvlowat = lconnp->conn_rcvlowat;
	econnp->conn_dgram_errind = lconnp->conn_dgram_errind;
	econnp->conn_oobinline = lconnp->conn_oobinline;
	econnp->conn_debug = lconnp->conn_debug;
	econnp->conn_keepalive = lconnp->conn_keepalive;
	econnp->conn_linger = lconnp->conn_linger;
	econnp->conn_lingertime = lconnp->conn_lingertime;

	/* Set the IP options */
	econnp->conn_broadcast = lconnp->conn_broadcast;
	econnp->conn_useloopback = lconnp->conn_useloopback;
	econnp->conn_reuseaddr = lconnp->conn_reuseaddr;
	return (0);
}

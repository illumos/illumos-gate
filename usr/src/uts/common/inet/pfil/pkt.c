/*
 * Copyright (C) 2000, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __hpux
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/rwlock.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#if SOLARIS2 >= 8
# include <netinet/ip6.h>
#else
# include <net/if_dl.h>
#endif

#undef IPOPT_EOL
#undef IPOPT_NOP
#undef IPOPT_RR
#undef IPOPT_LSRR
#undef IPOPT_SSRR
#include <inet/common.h>
#include <inet/ip.h>
#if SOLARIS2 >= 8
#include <inet/ip6.h>
#endif
#include <inet/ip_ire.h>
#include <inet/ip_if.h>

#include "compat.h"
#include "qif.h"


extern krwlock_t pfil_rw;
extern queue_t *pfildq;

#if 1
/* ------------------------------------------------------------------------ */
/* Function: pfil_make_dl_packet (mb, ip, dst, ifname, output_q)            */
/* Returns: On success, datalink msg block.                                 */
/*	    On failure, NULL.                                               */
/* Parameters:								    */
/*	mblk_t *mb: IP message block       				    */
/*      struct ip *ip: ip header start pointer				    */
/*      void *dst: destination address.                                     */
/*            if it is null, destination address is in ip                   */
/*            for IPV4, the parameter should be an instance of in_addr      */
/*            for IPV6, the parameter should be an instance of in6_addr     */
/*      char *ifname: output interface name                                 */
/*            if neither of dst and ifname is NULL, the routing for dst     */
/*            should have same interface name as ifname;                    */
/*            If ifname is NULL,  output interface name is not specified    */
/*            so it is decided by routing table.                            */
/*            if dst is NULL(ifname is not NULL), destination address       */
/*            in IP packet will be used for routing lookup, and the packet  */
/*            will be send out to interface ifname                          */
/*      queue_t **output_q: the write queue of pfil module where the        */
/*            returned message block can be putnext                         */ 
/*                                                                          */
/* This function is called to make a datalink message based on the IP       */
/* message block mb, If the function successfully returns, output_q         */ 
/* is set to the pfil module's write queue of output interface. Please use  */ 
/* pfil_send_dl_packet to putnext the returned packet to output_q.          */
/*                                                                          */
/* This function will return with a 'lock' held on the qif structure via    */
/* the PT_ENTER_READ() macro if qif_iflookup succeeds.  This lock is then   */
/* intended to be released when the queue returned is no longer referenced. */
/*                                                                          */
/* fr_fastroute, fr_send_icmp_err, fr_send_reset will call this func to     */
/* prepare packet.                                                          */
/*                                                                          */
/* ip_nexthop[_route] is called to search routing info in this func.        */
/* ------------------------------------------------------------------------ */
mblk_t *pfil_make_dl_packet(mb, ip, dst, ifname, output_q)
mblk_t *mb;
struct ip *ip;
void *dst;
char *ifname;
queue_t **output_q;
{
	mblk_t *mp;
	qif_t *qif;
	int ip_inf_bind = 0;
	char out_ifname_buf[LIFNAMSIZ];
	struct sockaddr_storage target;
	int sap;

	if (ip->ip_v == IPV4_VERSION) {
		struct sockaddr_in *target_in;
		target_in = (struct sockaddr_in *)&target;
		sap = IP_DL_SAP;
		target_in->sin_family = AF_INET;
		if (dst == NULL)
			target_in->sin_addr = ip->ip_dst;
		else {
			target_in->sin_addr.s_addr = *(ipaddr_t *)dst;
			if (ifname != NULL)
				ip_inf_bind = 1;
		}
	}
#ifdef USE_INET6
	else if (ip->ip_v == IPV6_VERSION) {
		struct sockaddr_in6 *target_in6;
		target_in6 = (struct sockaddr_in6 *)&target;
		sap = IP6_DL_SAP;
		target_in6->sin6_family = AF_INET6;
		if (dst == NULL)
			target_in6->sin6_addr = ((ip6_t *)ip)->ip6_dst;
		else {
			bcopy(dst, &target_in6->sin6_addr,
			      sizeof(struct in6_addr));
			if (ifname != NULL)
				ip_inf_bind = 1;
		}
	}
#endif

	if (ip_inf_bind)
		mp = ip_nexthop((struct sockaddr *)&target, ifname);
	else {
		mp = ip_nexthop_route((struct sockaddr *)&target,
				      out_ifname_buf);
		if (ifname == NULL)
			ifname = out_ifname_buf;
	}

	if (mp == NULL)
		return NULL;

	/*
	 * Sometimes the ip_nexthop* functions can't give us a usable packet
	 * header, for example, when the (nexthop) destination is in need of
	 * address resolution.  We'd like to punt our packet up to pfild and
	 * let it send the packet through the normal IP mechanisms, which will
	 * handle ARP/ND, but if the packet is being sent to an explicit router
	 * there is no way pfild can indicate that to the IP stack.  So in
	 * desperation, we discard the packet we are working on and instead
	 * construct an IP packet with ip_p == 0 to the nexthop router and let
	 * pfild send that.  This will start the ARP/ND resolution process
	 * so that next time we need to send a packet to that router, the IRE
	 * cache is all ready to go.
	 */
	if ((MTYPE(mp) == M_PROTO) && (dst != NULL))
		if ((ip->ip_v == IPV4_VERSION) &&
		    (ip->ip_dst.s_addr != *(ipaddr_t *)dst)) {

			ASSERT(MTYPE(mb) == M_DATA);
			if (mb->b_cont != NULL) {
				freemsg(mb->b_cont);
				mb->b_cont = NULL;
			}

			/*
			 * We don't bother to calculate the IP checksum, raw
			 * socket will finally do it.
			 */
			ip = (struct ip *)mb->b_rptr;
			ip->ip_hl = 5;
			ip->ip_tos = 0;
			ip->ip_len = sizeof (struct ip);
			ip->ip_id = 0;
			ip->ip_off = 0;
			ip->ip_ttl = 1;
			ip->ip_p = 0;
			ip->ip_src = *(struct in_addr *)dst;
			ip->ip_dst = *(struct in_addr *)dst;

			mb->b_wptr = mb->b_rptr + sizeof (struct ip);
		}

	/* look for output queue */
	rw_enter(&pfil_rw, RW_READER);
	qif = (qif_t *)qif_iflookup(ifname, sap);
	if (qif == NULL) {
		rw_exit(&pfil_rw);
		freeb(mp);
		return NULL;
	}

	PT_ENTER_READ(&qif->qf_ptl);
	*output_q = WR(qif->qf_q);
	rw_exit(&pfil_rw);

	/* OK, by now, we can link the IP message to lay2 header */
	linkb(mp, mb);
	mb = mp;

	return mb;
}


/* ------------------------------------------------------------------------ */
/* Function: pfil_send_dl_packet (output_q, mb)                             */
/* Returns: void                                                            */
/* Parameters:								    */
/*      queue_t *output_q: pfil module's write queue                        */
/*	mblk_t *mb: Lay2 message block. This parameter should be the return */
/*                  value of pfil_make_layer2_packet             	    */
/* This function is called to send the packet returned by                   */
/* pfil_make_dl_packet.                                                     */
/* In this function, PT_EXIT_READ is used after the putnext call to release */
/* the qif structure held by function pfil_make_layer2_packet.              */
/* ------------------------------------------------------------------------ */
void pfil_send_dl_packet(output_q, mb)
queue_t *output_q;
mblk_t *mb;
{
	qif_t *qif;

	/*
	 * NOTE: It is not permitted to hold a lock across putnext() so we
	 * use a semaphore-like operation to signal when it is ok to delete
	 * the qif structure.  With the current locking structure, putnext()
	 * may be called here after qprocsoff() has been called on output_q,
	 * but before the queue was completely closed.  See pfilmodclose().
	 */

	if (MTYPE(mb) == M_PROTO && pfildq != NULL) {
		/*
		 * If pfil_make_dl_packet() returned an M_PROTO message it's
		 * probably an ARP AR_ENTRY_QUERY message, which we can't
		 * handle, so we just send the IP packet up to pfild to
		 * transmit it via a raw socket.
		 */
		putnext(pfildq, mb->b_cont);
		mb->b_cont = NULL;
		freemsg(mb);
	} else {
		putnext(output_q, mb);
	}

	qif = output_q->q_ptr;
	PT_EXIT_READ(&qif->qf_ptl);
}

#else /* pfil_sendbuf implementation for no IRE_ILL_CN definition */

/* ------------------------------------------------------------------------ */
/* Function:    pfil_sendbuf                                                */
/* Returns:     int  - 0 == success, 1 == failure                           */
/* Parameters:  m(I) - pointer to streams message                           */
/*                                                                          */
/* Output an IPv4 packet to whichever interface has the correct route.      */
/* ------------------------------------------------------------------------ */
int pfil_sendbuf(m)
mblk_t *m;
{
	queue_t *q = NULL;
	struct ip *ip;
	size_t hlen;
	ire_t *dir;
	u_char *s;
	ill_t *il;

	ip = (struct ip *)m->b_rptr;

#ifdef	MATCH_IRE_DSTONLY
	dir = ire_route_lookup(ip->ip_dst.s_addr, 0xffffffff, 0, 0,
				NULL, NULL, NULL,
				MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|
				MATCH_IRE_RECURSIVE);
#else
	dir = ire_lookup(ip->ip_dst.s_addr);
#endif

	if (dir) {
#if SOLARIS2 >= 8
		if (!dir->ire_fp_mp || !dir->ire_dlureq_mp)
#else
		if (!dir->ire_ll_hdr_mp || !dir->ire_ll_hdr_length)
#endif
			return 2;
	}

	if (dir) {
		mblk_t *mp, *mp2;

		il = ire_to_ill(dir);
		if (!il)
			return 2;
#if SOLARIS2 < 8
		mp = dir->ire_ll_hdr_mp;
		hlen = dir->ire_ll_hdr_length;
#else
		mp = dir->ire_fp_mp;
		hlen = mp ? mp->b_wptr - mp->b_rptr : 0;
		mp = dir->ire_dlureq_mp;
#endif
		s = (u_char *)ip;

		if (hlen &&
#ifdef	ICK_M_CTL_MAGIC
		    (il->ill_ick.ick_magic != ICK_M_CTL_MAGIC) &&
#endif
		    (s - m->b_datap->db_base) >= hlen) {
			s -= hlen;
			m->b_rptr = (u_char *)s;
			bcopy((char *)mp->b_rptr, (char *)s, hlen);
		} else {
			mp2 = copyb(mp);
			if (!mp2)
				goto bad_nexthop;
			mp2->b_cont = m;
			m = mp2;
		}

		if (dir->ire_stq)
			q = dir->ire_stq;
		else if (dir->ire_rfq)
			q = WR(dir->ire_rfq);
		if (q)
			q = q->q_next;
		if (q) {
			RW_EXIT(&pfil_rw);
			putnext(q, m);
			READ_ENTER(&pfil_rw);
			return 0;
		}
	}
bad_nexthop:
	freemsg(m);
	return 1;
}
#endif /* 1 */

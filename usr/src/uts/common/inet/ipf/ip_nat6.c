/*
 * Copyright (C) 1995-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/file.h>
#if defined(__NetBSD__) && (NetBSD >= 199905) && !defined(IPFILTER_LKM) && \
    defined(_KERNEL)
# include "opt_ipfilter_log.h"
#endif
#if !defined(_KERNEL)
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#if defined(_KERNEL) && (__FreeBSD_version >= 220000)
# include <sys/filio.h>
# include <sys/fcntl.h>
#else
# include <sys/ioctl.h>
#endif
#if !defined(AIX)
# include <sys/fcntl.h>
#endif
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL)
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__)
#  include <sys/mbuf.h>
# endif
#endif
#if defined(__SVR4) || defined(__svr4__)
# include <sys/filio.h>
# include <sys/byteorder.h>
# ifdef _KERNEL
#  include <sys/dditypes.h>
# endif
# include <sys/stream.h>
# include <sys/kmem.h>
#endif
#if __FreeBSD_version >= 300000
# include <sys/queue.h>
#endif
#include <net/if.h>
#if __FreeBSD_version >= 300000
# include <net/if_var.h>
# if defined(_KERNEL) && !defined(IPFILTER_LKM)
#  include "opt_ipfilter.h"
# endif
#endif
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#ifdef RFC1825
# include <vpn/md5.h>
# include <vpn/ipsec.h>
extern struct ifnet vpnif;
#endif

#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_proxy.h"
#include "netinet/ipf_stack.h"
#ifdef	IPFILTER_SYNC
#include "netinet/ip_sync.h"
#endif
#if (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
#endif
/* END OF INCLUDES */

#undef	SOCKADDR_IN
#define	SOCKADDR_IN	struct sockaddr_in

#if !defined(lint)
static const char rcsid[] = "@(#)$Id: ip_nat6.c,v 1.2 2008/02/14 21:05:50 darrenr Exp $";
#endif

static	hostmap_t *nat6_hostmap __P((ipnat_t *, i6addr_t *, i6addr_t *,
				    i6addr_t *, u_32_t, ipf_stack_t *));
static	INLINE	int nat6_newmap __P((fr_info_t *, nat_t *, natinfo_t *));
static	INLINE	int nat6_newrdr __P((fr_info_t *, nat_t *, natinfo_t *));
static	INLINE	int nat6_finalise __P((fr_info_t *, nat_t *, natinfo_t *,
				      tcphdr_t *, nat_t **, int));
static	void	nat6_tabmove __P((nat_t *, ipf_stack_t *));
static	int	nat6_match __P((fr_info_t *, ipnat_t *));
static	INLINE	int nat_icmpquerytype6 __P((int));


/* ------------------------------------------------------------------------ */
/* Function:    nat6_addrdr                                                 */
/* Returns:     Nil                                                         */
/* Parameters:  n(I) - pointer to NAT rule to add                           */
/*                                                                          */
/* Adds a redirect rule to the hash table of redirect rules and the list of */
/* loaded NAT rules.  Updates the bitmask indicating which netmasks are in  */
/* use by redirect rules.                                                   */
/* ------------------------------------------------------------------------ */
void nat6_addrdr(n, ifs)
ipnat_t *n;
ipf_stack_t *ifs;
{
	ipnat_t **np;
	i6addr_t j;
	u_int hv;
	int k;

	k = count6bits(n->in_out[1].i6);
	if ((k >= 0) && (k != 128))
		ifs->ifs_rdr6_masks[k >> 5] |= 1 << (k & 31);
	IP6_AND(&n->in_out[0], &n->in_out[1], &j);
	hv = NAT_HASH_FN6(&j, 0, ifs->ifs_ipf_rdrrules_sz);
	np = ifs->ifs_rdr_rules + hv;
	while (*np != NULL)
		np = &(*np)->in_rnext;
	n->in_rnext = NULL;
	n->in_prnext = np;
	n->in_hv = hv;
	*np = n;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_addnat                                                 */
/* Returns:     Nil                                                         */
/* Parameters:  n(I) - pointer to NAT rule to add                           */
/*                                                                          */
/* Adds a NAT map rule to the hash table of rules and the list of  loaded   */
/* NAT rules.  Updates the bitmask indicating which netmasks are in use by  */
/* redirect rules.                                                          */
/* ------------------------------------------------------------------------ */
void nat6_addnat(n, ifs)
ipnat_t *n;
ipf_stack_t *ifs;
{
	ipnat_t **np;
	i6addr_t j;
	u_int hv;
	int k;

	k = count6bits(n->in_in[1].i6);
	if ((k >= 0) && (k != 128))
		ifs->ifs_nat6_masks[k >> 5] |= 1 << (k & 31);
	IP6_AND(&n->in_in[0], &n->in_in[1], &j);
	hv = NAT_HASH_FN6(&j, 0, ifs->ifs_ipf_natrules_sz);
	np = ifs->ifs_nat_rules + hv;
	while (*np != NULL)
		np = &(*np)->in_mnext;
	n->in_mnext = NULL;
	n->in_pmnext = np;
	n->in_hv = hv;
	*np = n;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_hostmap                                                */
/* Returns:     struct hostmap* - NULL if no hostmap could be created,      */
/*                                else a pointer to the hostmapping to use  */
/* Parameters:  np(I)   - pointer to NAT rule                               */
/*              real(I) - real IP address                                   */
/*              map(I)  - mapped IP address                                 */
/*              port(I) - destination port number                           */
/* Write Locks: ipf_nat                                                     */
/*                                                                          */
/* Check if an ip address has already been allocated for a given mapping    */
/* that is not doing port based translation.  If is not yet allocated, then */
/* create a new entry if a non-NULL NAT rule pointer has been supplied.     */
/* ------------------------------------------------------------------------ */
static struct hostmap *nat6_hostmap(np, src, dst, map, port, ifs)
ipnat_t *np;
i6addr_t *src, *dst, *map;
u_32_t port;
ipf_stack_t *ifs;
{
	hostmap_t *hm;
	u_int hv;

	hv = (src->i6[3] ^ dst->i6[3]);
	hv += (src->i6[2] ^ dst->i6[2]);
	hv += (src->i6[1] ^ dst->i6[1]);
	hv += (src->i6[0] ^ dst->i6[0]);
	hv += src->i6[3];
	hv += src->i6[2];
	hv += src->i6[1];
	hv += src->i6[0];
	hv += dst->i6[3];
	hv += dst->i6[2];
	hv += dst->i6[1];
	hv += dst->i6[0];
	hv %= HOSTMAP_SIZE;
	for (hm = ifs->ifs_maptable[hv]; hm; hm = hm->hm_next)
		if (IP6_EQ(&hm->hm_srcip6, src) &&
		    IP6_EQ(&hm->hm_dstip6, dst) &&
		    ((np == NULL) || (np == hm->hm_ipnat)) &&
		    ((port == 0) || (port == hm->hm_port))) {
			hm->hm_ref++;
			return hm;
		}

	if (np == NULL)
		return NULL;

	KMALLOC(hm, hostmap_t *);
	if (hm) {
		hm->hm_hnext = ifs->ifs_ipf_hm_maplist;
		hm->hm_phnext = &ifs->ifs_ipf_hm_maplist;
		if (ifs->ifs_ipf_hm_maplist != NULL)
			ifs->ifs_ipf_hm_maplist->hm_phnext = &hm->hm_hnext;
		ifs->ifs_ipf_hm_maplist = hm;

		hm->hm_next = ifs->ifs_maptable[hv];
		hm->hm_pnext = ifs->ifs_maptable + hv;
		if (ifs->ifs_maptable[hv] != NULL)
			ifs->ifs_maptable[hv]->hm_pnext = &hm->hm_next;
		ifs->ifs_maptable[hv] = hm;
		hm->hm_ipnat = np;
		hm->hm_src = *src;
		hm->hm_dst = *dst;
		hm->hm_map = *map;
		hm->hm_ref = 1;
		hm->hm_port = port;
		hm->hm_v = 6;
	}
	return hm;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_newmap                                                 */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/*                                                                          */
/* Given an empty NAT structure, populate it with new information about a   */
/* new NAT session, as defined by the matching NAT rule.                    */
/* ni.nai_ip is passed in uninitialised and must be set, in host byte order,*/
/* to the new IP address for the translation.                               */
/* ------------------------------------------------------------------------ */
static INLINE int nat6_newmap(fin, nat, ni)
fr_info_t *fin;
nat_t *nat;
natinfo_t *ni;
{
	u_short st_port, dport, sport, port, sp, dp;
	i6addr_t in, st_ip;
	hostmap_t *hm;
	u_32_t flags;
	ipnat_t *np;
	nat_t *natl;
	int l;
	ipf_stack_t *ifs = fin->fin_ifs;

	/*
	 * If it's an outbound packet which doesn't match any existing
	 * record, then create a new port
	 */
	l = 0;
	hm = NULL;
	np = ni->nai_np;
	st_ip = np->in_next6;
	st_port = np->in_pnext;
	flags = ni->nai_flags;
	sport = ni->nai_sport;
	dport = ni->nai_dport;

	/*
	 * Do a loop until we either run out of entries to try or we find
	 * a NAT mapping that isn't currently being used.  This is done
	 * because the change to the source is not (usually) being fixed.
	 */
	do {
		port = 0;
		in = np->in_next6;
		if (l == 0) {
			/*
			 * Check to see if there is an existing NAT
			 * setup for this IP address pair.
			 */
			hm = nat6_hostmap(np, &fin->fin_src6, &fin->fin_dst6,
					 &in, 0, ifs);
			if (hm != NULL)
				in = hm->hm_map;
		} else if ((l == 1) && (hm != NULL)) {
			fr_hostmapdel(&hm);
		}

		nat->nat_hm = hm;

		if (IP6_ISONES(&np->in_out[1]) && (np->in_pnext == 0)) {
			if (l > 0)
				return -1;
		}

		if (np->in_redir == NAT_BIMAP &&
		    IP6_EQ(&np->in_in[1], &np->in_out[1])) {
			i6addr_t temp;
			/*
			 * map the address block in a 1:1 fashion
			 */
			temp.i6[0] = fin->fin_src6.i6[0] &
					~np->in_in[1].i6[0];
			temp.i6[1] = fin->fin_src6.i6[1] &
					~np->in_in[1].i6[1];
			temp.i6[2] = fin->fin_src6.i6[2] &
					~np->in_in[1].i6[2];
			temp.i6[3] = fin->fin_src6.i6[3] &
					~np->in_in[1].i6[3];
			in = np->in_out[0];
			IP6_MERGE(&in, &temp, &np->in_in[0]);

#ifdef	NEED_128BIT_MATH
		} else if (np->in_redir & NAT_MAPBLK) {
			if ((l >= np->in_ppip) || ((l > 0) &&
			     !(flags & IPN_TCPUDP)))
				return -1;
			/*
			 * map-block - Calculate destination address.
			 */
			IP6_MASK(&in, &fin->fin_src6, &np->in_in[1]);
			in = ntol(in);
			inb = in;
			in /= np->in_ippip;
			in &= ntohl(~np->in_out[1]);
			in += ntohl(np->in_out[0]);
			/*
			 * Calculate destination port.
			 */
			if ((flags & IPN_TCPUDP) &&
			    (np->in_ppip != 0)) {
				port = ntohs(sport) + l;
				port %= np->in_ppip;
				port += np->in_ppip *
					(inb.s_addr % np->in_ippip);
				port += MAPBLK_MINPORT;
				port = htons(port);
			}
#endif

		} else if (IP6_ISZERO(&np->in_out[0]) &&
		    IP6_ISONES(&np->in_out[1])) {
			/*
			 * 0/128 - use the interface's IP address.
			 */
			if ((l > 0) ||
			    fr_ifpaddr(6, FRI_NORMAL, fin->fin_ifp,
				       (void *)&in, NULL, fin->fin_ifs) == -1)
				return -1;

		} else if (IP6_ISZERO(&np->in_out[0]) &&
		    IP6_ISZERO(&np->in_out[1])) {
			/*
			 * 0/0 - use the original source address/port.
			 */
			if (l > 0)
				return -1;
			in = fin->fin_src6;

		} else if (!IP6_ISONES(&np->in_out[1]) &&
			   (np->in_pnext == 0) && ((l > 0) || (hm == NULL))) {
			IP6_INC(&np->in_next6);
		}

		natl = NULL;

		if ((flags & IPN_TCPUDP) &&
		    ((np->in_redir & NAT_MAPBLK) == 0) &&
		    (np->in_flags & IPN_AUTOPORTMAP)) {
			/*EMPTY*/;
#ifdef	NEED_128BIT_MATH
			/*
			 * XXX "ports auto" (without map-block)
			 */
			if ((l > 0) && (l % np->in_ppip == 0)) {
				if (l > np->in_space) {
					return -1;
				} else if ((l > np->in_ppip) &&
				    !IP6_ISONES(&np->in_out[1])) {
					IP6_INC(&np->in_next6);
				}
			}
			if (np->in_ppip != 0) {
				port = ntohs(sport);
				port += (l % np->in_ppip);
				port %= np->in_ppip;
				port += np->in_ppip *
					(ntohl(fin->fin_src6) %
					 np->in_ippip);
				port += MAPBLK_MINPORT;
				port = htons(port);
			}
#endif

		} else if (((np->in_redir & NAT_MAPBLK) == 0) &&
			   (flags & IPN_TCPUDPICMP) && (np->in_pnext != 0)) {
			/*
			 * Standard port translation.  Select next port.
			 */
			if (np->in_flags & IPN_SEQUENTIAL) {
				port = np->in_pnext;
			} else {
				port = ipf_random() % (ntohs(np->in_pmax) -
						       ntohs(np->in_pmin));
				port += ntohs(np->in_pmin);
			}
			port = htons(port);
			np->in_pnext++;

			if (np->in_pnext > ntohs(np->in_pmax)) {
				np->in_pnext = ntohs(np->in_pmin);
				if (!IP6_ISONES(&np->in_out[1])) {
					IP6_INC(&np->in_next6);
				}
			}
		}

		if (np->in_flags & IPN_IPRANGE) {
			if (IP6_GT(&np->in_next6, &np->in_out[1]))
				np->in_next6 = np->in_out[0];
		} else {
			i6addr_t a1, a2;

			a1 = np->in_next6;
			IP6_INC(&a1);
			IP6_AND(&a1, &np->in_out[1], &a2);
			if (!IP6_ISONES(&np->in_out[1]) &&
			    IP6_GT(&a2, &np->in_out[0])) {
				IP6_ADD(&np->in_out[0], 1, &np->in_next6);
			}
		}

		if ((port == 0) && (flags & (IPN_TCPUDPICMP|IPN_ICMPQUERY)))
			port = sport;

		/*
		 * Here we do a lookup of the connection as seen from
		 * the outside.  If an IP# pair already exists, try
		 * again.  So if you have A->B becomes C->B, you can
		 * also have D->E become C->E but not D->B causing
		 * another C->B.  Also take protocol and ports into
		 * account when determining whether a pre-existing
		 * NAT setup will cause an external conflict where
		 * this is appropriate.
		 */
		sp = fin->fin_data[0];
		dp = fin->fin_data[1];
		fin->fin_data[0] = fin->fin_data[1];
		fin->fin_data[1] = htons(port);
		natl = nat6_inlookup(fin, flags & ~(SI_WILDP|NAT_SEARCH),
		    (u_int)fin->fin_p, &fin->fin_dst6.in6, &in.in6);
		fin->fin_data[0] = sp;
		fin->fin_data[1] = dp;

		/*
		 * Has the search wrapped around and come back to the
		 * start ?
		 */
		if ((natl != NULL) &&
		    (np->in_pnext != 0) && (st_port == np->in_pnext) &&
		    !IP6_ISZERO(&np->in_next6) &&
		    IP6_EQ(&st_ip, &np->in_next6))
			return -1;
		l++;
	} while (natl != NULL);

	if (np->in_space > 0)
		np->in_space--;

	/* Setup the NAT table */
	nat->nat_inip6 = fin->fin_src6;
	nat->nat_outip6 = in;
	nat->nat_oip6 = fin->fin_dst6;
	if (nat->nat_hm == NULL)
		nat->nat_hm = nat6_hostmap(np, &fin->fin_src6, &fin->fin_dst6,
		    &nat->nat_outip6, 0, ifs);

	if (flags & IPN_TCPUDP) {
		nat->nat_inport = sport;
		nat->nat_outport = port;	/* sport */
		nat->nat_oport = dport;
		((tcphdr_t *)fin->fin_dp)->th_sport = port;
	} else if (flags & IPN_ICMPQUERY) {
		((struct icmp6_hdr *)fin->fin_dp)->icmp6_id = port;
		nat->nat_inport = port;
		nat->nat_outport = port;
	}
	
	ni->nai_port = port;
	ni->nai_nport = dport;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_newrdr                                                 */
/* Returns:     int - -1 == error, 0 == success (no move), 1 == success and */
/*                    allow rule to be moved if IPN_ROUNDR is set.          */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/*                                                                          */
/* ni.nai_ip is passed in uninitialised and must be set, in host byte order,*/
/* to the new IP address for the translation.                               */
/* ------------------------------------------------------------------------ */
static INLINE int nat6_newrdr(fin, nat, ni)
fr_info_t *fin;
nat_t *nat;
natinfo_t *ni;
{
	u_short nport, dport, sport;
	i6addr_t in;
	u_short sp, dp;
	hostmap_t *hm;
	u_32_t flags;
	ipnat_t *np;
	nat_t *natl;
	int move;
	ipf_stack_t *ifs = fin->fin_ifs;

	move = 1;
	hm = NULL;
	in.i6[0] = 0;
	in.i6[1] = 0;
	in.i6[2] = 0;
	in.i6[3] = 0;
	np = ni->nai_np;
	flags = ni->nai_flags;
	sport = ni->nai_sport;
	dport = ni->nai_dport;

	/*
	 * If the matching rule has IPN_STICKY set, then we want to have the
	 * same rule kick in as before.  Why would this happen?  If you have
	 * a collection of rdr rules with "round-robin sticky", the current
	 * packet might match a different one to the previous connection but
	 * we want the same destination to be used.
	 */
	if ((np->in_flags & (IPN_ROUNDR|IPN_STICKY)) ==
	    (IPN_ROUNDR|IPN_STICKY)) {
		hm = nat6_hostmap(NULL, &fin->fin_src6, &fin->fin_dst6, &in,
		    (u_32_t)dport, ifs);
		if (hm != NULL) {
			in = hm->hm_map;
			np = hm->hm_ipnat;
			ni->nai_np = np;
			move = 0;
		}
	}

	/*
	 * Otherwise, it's an inbound packet. Most likely, we don't
	 * want to rewrite source ports and source addresses. Instead,
	 * we want to rewrite to a fixed internal address and fixed
	 * internal port.
	 */
	if (np->in_flags & IPN_SPLIT) {
		in = np->in_next6;

		if ((np->in_flags & (IPN_ROUNDR|IPN_STICKY)) == IPN_STICKY) {
			hm = nat6_hostmap(np, &fin->fin_src6, &fin->fin_dst6,
			    &in, (u_32_t)dport, ifs);
			if (hm != NULL) {
				in = hm->hm_map;
				move = 0;
			}
		}

		if (hm == NULL || hm->hm_ref == 1) {
			if (IP6_EQ(&np->in_in[0], &in)) {
				np->in_next6 = np->in_in[1];
				move = 0;
			} else {
				np->in_next6 = np->in_in[0];
			}
		}

	} else if (IP6_ISZERO(&np->in_in[0]) &&
	    IP6_ISONES(&np->in_in[1])) {
		/*
		 * 0/128 - use the interface's IP address.
		 */
		if (fr_ifpaddr(6, FRI_NORMAL, fin->fin_ifp, (void *)&in, NULL,
			   fin->fin_ifs) == -1)
			return -1;

	} else if (IP6_ISZERO(&np->in_in[0]) &&
	    IP6_ISZERO(&np->in_in[1])) {
		/*
		 * 0/0 - use the original destination address/port.
		 */
		in = fin->fin_dst6;

	} else if (np->in_redir == NAT_BIMAP &&
	    IP6_EQ(&np->in_in[1], &np->in_out[1])) {
		i6addr_t temp;
		/*
		 * map the address block in a 1:1 fashion
		 */
		temp.i6[0] = fin->fin_dst6.i6[0] & ~np->in_in[1].i6[0];
		temp.i6[1] = fin->fin_dst6.i6[1] & ~np->in_in[1].i6[1];
		temp.i6[2] = fin->fin_dst6.i6[2] & ~np->in_in[1].i6[2];
		temp.i6[3] = fin->fin_dst6.i6[3] & ~np->in_in[1].i6[3];
		in = np->in_in[0];
		IP6_MERGE(&in, &temp, &np->in_in[1]);
	} else {
		in = np->in_in[0];
	}

	if ((np->in_pnext == 0) || ((flags & NAT_NOTRULEPORT) != 0))
		nport = dport;
	else {
		/*
		 * Whilst not optimized for the case where
		 * pmin == pmax, the gain is not significant.
		 */
		if (((np->in_flags & IPN_FIXEDDPORT) == 0) &&
		    (np->in_pmin != np->in_pmax)) {
			nport = ntohs(dport) - ntohs(np->in_pmin) +
				ntohs(np->in_pnext);
			nport = htons(nport);
		} else
			nport = np->in_pnext;
	}

	/*
	 * When the redirect-to address is set to 0.0.0.0, just
	 * assume a blank `forwarding' of the packet.  We don't
	 * setup any translation for this either.
	 */
	if (IP6_ISZERO(&in)) {
		if (nport == dport)
			return -1;
		in = fin->fin_dst6;
	}

	/*
	 * Check to see if this redirect mapping already exists and if
	 * it does, return "failure" (allowing it to be created will just
	 * cause one or both of these "connections" to stop working.)
	 */
	sp = fin->fin_data[0];
	dp = fin->fin_data[1];
	fin->fin_data[1] = fin->fin_data[0];
	fin->fin_data[0] = ntohs(nport);
	natl = nat6_outlookup(fin, flags & ~(SI_WILDP|NAT_SEARCH),
	    (u_int)fin->fin_p, &in.in6, &fin->fin_src6.in6);
	fin->fin_data[0] = sp;
	fin->fin_data[1] = dp;
	if (natl != NULL)
		return -1;

	nat->nat_inip6 = in;
	nat->nat_outip6 = fin->fin_dst6;
	nat->nat_oip6 = fin->fin_src6;
	if ((nat->nat_hm == NULL) && ((np->in_flags & IPN_STICKY) != 0))
		nat->nat_hm = nat6_hostmap(np, &fin->fin_src6,
		    &fin->fin_dst6, &in, (u_32_t)dport, ifs);

	ni->nai_nport = nport;
	ni->nai_port = sport;

	if (flags & IPN_TCPUDP) {
		nat->nat_inport = nport;
		nat->nat_outport = dport;
		nat->nat_oport = sport;
		((tcphdr_t *)fin->fin_dp)->th_dport = nport;
	} else if (flags & IPN_ICMPQUERY) {
		((struct icmp6_hdr *)fin->fin_dp)->icmp6_id = nport;
		nat->nat_inport = nport;
		nat->nat_outport = nport;
	}

	return move;
}

/* ------------------------------------------------------------------------ */
/* Function:    nat6_new                                                    */
/* Returns:     nat_t* - NULL == failure to create new NAT structure,       */
/*                       else pointer to new NAT structure                  */
/* Parameters:  fin(I)       - pointer to packet information                */
/*              np(I)        - pointer to NAT rule                          */
/*              natsave(I)   - pointer to where to store NAT struct pointer */
/*              flags(I)     - flags describing the current packet          */
/*              direction(I) - direction of packet (in/out)                 */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* Attempts to create a new NAT entry.  Does not actually change the packet */
/* in any way.                                                              */
/*                                                                          */
/* This fucntion is in three main parts: (1) deal with creating a new NAT   */
/* structure for a "MAP" rule (outgoing NAT translation); (2) deal with     */
/* creating a new NAT structure for a "RDR" rule (incoming NAT translation) */
/* and (3) building that structure and putting it into the NAT table(s).    */
/* ------------------------------------------------------------------------ */
nat_t *nat6_new(fin, np, natsave, flags, direction)
fr_info_t *fin;
ipnat_t *np;
nat_t **natsave;
u_int flags;
int direction;
{
	tcphdr_t *tcp = NULL;
	hostmap_t *hm = NULL;
	nat_t *nat, *natl;
	u_int nflags;
	natinfo_t ni;
	int move;
	ipf_stack_t *ifs = fin->fin_ifs;

	/*
	 * Trigger automatic call to ipf_extraflush() if the
	 * table has reached capcity specified by hi watermark.
	 */
	if (NAT_TAB_WATER_LEVEL(ifs) > ifs->ifs_nat_flush_level_hi)
		ifs->ifs_nat_doflush = 1;

	if (ifs->ifs_nat_stats.ns_inuse >= ifs->ifs_ipf_nattable_max) {
		ifs->ifs_nat_stats.ns_memfail++;
		return NULL;
	}

	move = 1;
	nflags = np->in_flags & flags;
	nflags &= NAT_FROMRULE;

	ni.nai_np = np;
	ni.nai_nflags = nflags;
	ni.nai_flags = flags;

	/* Give me a new nat */
	KMALLOC(nat, nat_t *);
	if (nat == NULL) {
		ifs->ifs_nat_stats.ns_memfail++;
		/*
		 * Try to automatically tune the max # of entries in the
		 * table allowed to be less than what will cause kmem_alloc()
		 * to fail and try to eliminate panics due to out of memory
		 * conditions arising.
		 */
		if (ifs->ifs_ipf_nattable_max > ifs->ifs_ipf_nattable_sz) {
			ifs->ifs_ipf_nattable_max =
			    ifs->ifs_nat_stats.ns_inuse - 100;
			printf("ipf_nattable_max reduced to %d\n",
			    ifs->ifs_ipf_nattable_max);
		}
		return NULL;
	}

	if (flags & IPN_TCPUDP) {
		tcp = fin->fin_dp;
		ni.nai_sport = htons(fin->fin_sport);
		ni.nai_dport = htons(fin->fin_dport);
	} else if (flags & IPN_ICMPQUERY) {
		/*
		 * In the ICMP query NAT code, we translate the ICMP id fields
		 * to make them unique. This is indepedent of the ICMP type
		 * (e.g. in the unlikely event that a host sends an echo and
		 * an tstamp request with the same id, both packets will have
		 * their ip address/id field changed in the same way).
		 *
		 * The icmp_id field is used by the sender to identify the
		 * process making the icmp request. (the receiver justs
		 * copies it back in its response). So, it closely matches
		 * the concept of source port. We overlay sport, so we can
		 * maximally reuse the existing code.
		 */
		ni.nai_sport = ((struct icmp6_hdr *)fin->fin_dp)->icmp6_id;
		ni.nai_dport = ni.nai_sport;
	}

	bzero((char *)nat, sizeof (*nat));
	nat->nat_flags = flags;
	nat->nat_redir = np->in_redir;

	if ((flags & NAT_SLAVE) == 0) {
		MUTEX_ENTER(&ifs->ifs_ipf_nat_new);
	}

	/*
	 * Search the current table for a match.
	 */
	if (direction == NAT_OUTBOUND) {
		/*
		 * We can now arrange to call this for the same connection
		 * because ipf_nat_new doesn't protect the code path into
		 * this function.
		 */
		natl = nat6_outlookup(fin, nflags, (u_int)fin->fin_p,
		    &fin->fin_src6.in6, &fin->fin_dst6.in6);
		if (natl != NULL) {
			KFREE(nat);
			nat = natl;
			goto done;
		}

		move = nat6_newmap(fin, nat, &ni);
		if (move == -1)
			goto badnat;

		np = ni.nai_np;
	} else {
		/*
		 * NAT_INBOUND is used only for redirects rules
		 */
		natl = nat6_inlookup(fin, nflags, (u_int)fin->fin_p,
		    &fin->fin_src6.in6, &fin->fin_dst6.in6);
		if (natl != NULL) {
			KFREE(nat);
			nat = natl;
			goto done;
		}

		move = nat6_newrdr(fin, nat, &ni);
		if (move == -1)
			goto badnat;

		np = ni.nai_np;
	}

	if ((move == 1) && (np->in_flags & IPN_ROUNDR)) {
		if (np->in_redir == NAT_REDIRECT) {
			nat_delrdr(np);
			nat6_addrdr(np, ifs);
		} else if (np->in_redir == NAT_MAP) {
			nat_delnat(np);
			nat6_addnat(np, ifs);
		}
	}

	if (nat6_finalise(fin, nat, &ni, tcp, natsave, direction) == -1) {
		goto badnat;
	}

	nat_calc_chksum_diffs(nat);

	if (flags & SI_WILDP)
		ifs->ifs_nat_stats.ns_wilds++;
	goto done;
badnat:
	ifs->ifs_nat_stats.ns_badnat++;
	if ((hm = nat->nat_hm) != NULL)
		fr_hostmapdel(&hm);
	KFREE(nat);
	nat = NULL;
done:
	if ((flags & NAT_SLAVE) == 0) {
		MUTEX_EXIT(&ifs->ifs_ipf_nat_new);
	}
	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_finalise                                               */
/* Returns:     int - 0 == sucess, -1 == failure                            */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* This is the tail end of constructing a new NAT entry and is the same     */
/* for both IPv4 and IPv6.                                                  */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
static INLINE int nat6_finalise(fin, nat, ni, tcp, natsave, direction)
fr_info_t *fin;
nat_t *nat;
natinfo_t *ni;
tcphdr_t *tcp;
nat_t **natsave;
int direction;
{
	frentry_t *fr;
	ipnat_t *np;
	ipf_stack_t *ifs = fin->fin_ifs;

	np = ni->nai_np;

	COPYIFNAME(fin->fin_ifp, nat->nat_ifnames[0], fin->fin_v);

#ifdef	IPFILTER_SYNC
	if ((nat->nat_flags & SI_CLONE) == 0)
		nat->nat_sync = ipfsync_new(SMC_NAT, fin, nat);
#endif

	nat->nat_me = natsave;
	nat->nat_dir = direction;
	nat->nat_ifps[0] = np->in_ifps[0];
	nat->nat_ifps[1] = np->in_ifps[1];
	nat->nat_ptr = np;
	nat->nat_p = fin->fin_p;
	nat->nat_v = fin->fin_v;
	nat->nat_mssclamp = np->in_mssclamp;
	fr = fin->fin_fr;
	nat->nat_fr = fr;
	nat->nat_v = 6;

#ifdef	IPF_V6_PROXIES
	if ((np->in_apr != NULL) && ((ni->nai_flags & NAT_SLAVE) == 0))
		if (appr_new(fin, nat) == -1)
			return -1;
#endif

	if (nat6_insert(nat, fin->fin_rev, ifs) == 0) {
		if (ifs->ifs_nat_logging)
			nat_log(nat, (u_int)np->in_redir, ifs);
		np->in_use++;
		if (fr != NULL) {
			MUTEX_ENTER(&fr->fr_lock);
			fr->fr_ref++;
			MUTEX_EXIT(&fr->fr_lock);
		}
		return 0;
	}

	/*
	 * nat6_insert failed, so cleanup time...
	 */
	return -1;
}


/* ------------------------------------------------------------------------ */
/* Function:   nat6_insert                                                  */
/* Returns:    int - 0 == sucess, -1 == failure                             */
/* Parameters: nat(I) - pointer to NAT structure                            */
/*             rev(I) - flag indicating forward/reverse direction of packet */
/* Write Lock: ipf_nat                                                      */
/*                                                                          */
/* Insert a NAT entry into the hash tables for searching and add it to the  */
/* list of active NAT entries.  Adjust global counters when complete.       */
/* ------------------------------------------------------------------------ */
int nat6_insert(nat, rev, ifs)
nat_t	*nat;
int	rev;
ipf_stack_t *ifs;
{
	u_int hv1, hv2;
	nat_t **natp;

	/*
	 * Try and return an error as early as possible, so calculate the hash
	 * entry numbers first and then proceed.
	 */
	if ((nat->nat_flags & (SI_W_SPORT|SI_W_DPORT)) == 0) {
		hv1 = NAT_HASH_FN6(&nat->nat_inip6, nat->nat_inport,
				  0xffffffff);
		hv1 = NAT_HASH_FN6(&nat->nat_oip6, hv1 + nat->nat_oport,
				  ifs->ifs_ipf_nattable_sz);
		hv2 = NAT_HASH_FN6(&nat->nat_outip6, nat->nat_outport,
				  0xffffffff);
		hv2 = NAT_HASH_FN6(&nat->nat_oip6, hv2 + nat->nat_oport,
				  ifs->ifs_ipf_nattable_sz);
	} else {
		hv1 = NAT_HASH_FN6(&nat->nat_inip6, 0, 0xffffffff);
		hv1 = NAT_HASH_FN6(&nat->nat_oip6, hv1,
				  ifs->ifs_ipf_nattable_sz);
		hv2 = NAT_HASH_FN6(&nat->nat_outip6, 0, 0xffffffff);
		hv2 = NAT_HASH_FN6(&nat->nat_oip6, hv2,
				  ifs->ifs_ipf_nattable_sz);
	}

	if ((ifs->ifs_nat_stats.ns_bucketlen[0][hv1] >=
	    ifs->ifs_fr_nat_maxbucket) ||
	    (ifs->ifs_nat_stats.ns_bucketlen[1][hv2] >=
	    ifs->ifs_fr_nat_maxbucket)) {
		return -1;
	}

	nat->nat_hv[0] = hv1;
	nat->nat_hv[1] = hv2;

	MUTEX_INIT(&nat->nat_lock, "nat entry lock");

	nat->nat_rev = rev;
	nat->nat_ref = 1;
	nat->nat_bytes[0] = 0;
	nat->nat_pkts[0] = 0;
	nat->nat_bytes[1] = 0;
	nat->nat_pkts[1] = 0;

	nat->nat_ifnames[0][LIFNAMSIZ - 1] = '\0';
	nat->nat_ifps[0] = fr_resolvenic(nat->nat_ifnames[0], 6, ifs);

	if (nat->nat_ifnames[1][0] !='\0') {
		nat->nat_ifnames[1][LIFNAMSIZ - 1] = '\0';
		nat->nat_ifps[1] = fr_resolvenic(nat->nat_ifnames[1], 6, ifs);
	} else {
		(void) strncpy(nat->nat_ifnames[1], nat->nat_ifnames[0],
			       LIFNAMSIZ);
		nat->nat_ifnames[1][LIFNAMSIZ - 1] = '\0';
		nat->nat_ifps[1] = nat->nat_ifps[0];
	}

	nat->nat_next = ifs->ifs_nat_instances;
	nat->nat_pnext = &ifs->ifs_nat_instances;
	if (ifs->ifs_nat_instances)
		ifs->ifs_nat_instances->nat_pnext = &nat->nat_next;
	ifs->ifs_nat_instances = nat;

	natp = &ifs->ifs_nat_table[0][hv1];
	if (*natp)
		(*natp)->nat_phnext[0] = &nat->nat_hnext[0];
	nat->nat_phnext[0] = natp;
	nat->nat_hnext[0] = *natp;
	*natp = nat;
	ifs->ifs_nat_stats.ns_bucketlen[0][hv1]++;

	natp = &ifs->ifs_nat_table[1][hv2];
	if (*natp)
		(*natp)->nat_phnext[1] = &nat->nat_hnext[1];
	nat->nat_phnext[1] = natp;
	nat->nat_hnext[1] = *natp;
	*natp = nat;
	ifs->ifs_nat_stats.ns_bucketlen[1][hv2]++;

	fr_setnatqueue(nat, rev, ifs);

	ifs->ifs_nat_stats.ns_added++;
	ifs->ifs_nat_stats.ns_inuse++;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_icmperrorlookup                                        */
/* Returns:     nat_t* - point to matching NAT structure                    */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              dir(I) - direction of packet (in/out)                       */
/*                                                                          */
/* Check if the ICMP error message is related to an existing TCP, UDP or    */
/* ICMP query nat entry.  It is assumed that the packet is already of the   */
/* the required length.                                                     */
/* ------------------------------------------------------------------------ */
nat_t *nat6_icmperrorlookup(fin, dir)
fr_info_t *fin;
int dir;
{
	int flags = 0, minlen;
	struct icmp6_hdr *orgicmp;
	tcphdr_t *tcp = NULL;
	u_short data[2];
	nat_t *nat;
	ip6_t *oip6;
	u_int p;

	minlen = 40;
	/*
	 * Does it at least have the return (basic) IP header ?
	 * Only a basic IP header (no options) should be with an ICMP error
	 * header.  Also, if it's not an error type, then return.
	 */
	if (!(fin->fin_flx & FI_ICMPERR))
		return NULL;

	/*
	 * Check packet size
	 */
	if (fin->fin_plen < ICMP6ERR_IPICMPHLEN)
		return NULL;
	oip6 = (ip6_t *)((char *)fin->fin_dp + 8);

	/*
	 * Is the buffer big enough for all of it ?  It's the size of the IP
	 * header claimed in the encapsulated part which is of concern.  It
	 * may be too big to be in this buffer but not so big that it's
	 * outside the ICMP packet, leading to TCP deref's causing problems.
	 * This is possible because we don't know how big oip_hl is when we
	 * do the pullup early in fr_check() and thus can't gaurantee it is
	 * all here now.
	 */
#ifdef  _KERNEL
	{
	mb_t *m;

	m = fin->fin_m;
# if defined(MENTAT)
	if ((char *)oip6 + fin->fin_dlen - ICMPERR_ICMPHLEN > (char *)m->b_wptr)
		return NULL;
# else
	if ((char *)oip6 + fin->fin_dlen - ICMPERR_ICMPHLEN >
	    (char *)fin->fin_ip + M_LEN(m))
		return NULL;
# endif
	}
#endif

	if (IP6_NEQ(&fin->fin_dst6, &oip6->ip6_src))
		return NULL;

	p = oip6->ip6_nxt;
	if (p == IPPROTO_TCP)
		flags = IPN_TCP;
	else if (p == IPPROTO_UDP)
		flags = IPN_UDP;
	else if (p == IPPROTO_ICMPV6) {
		orgicmp = (struct icmp6_hdr *)(oip6 + 1);

		/* see if this is related to an ICMP query */
		if (nat_icmpquerytype6(orgicmp->icmp6_type)) {
			data[0] = fin->fin_data[0];
			data[1] = fin->fin_data[1];
			fin->fin_data[0] = 0;
			fin->fin_data[1] = orgicmp->icmp6_id;

			flags = IPN_ICMPERR|IPN_ICMPQUERY;
			/*
			 * NOTE : dir refers to the direction of the original
			 *        ip packet. By definition the icmp error
			 *        message flows in the opposite direction.
			 */
			if (dir == NAT_INBOUND)
				nat = nat6_inlookup(fin, flags, p,
				    &oip6->ip6_dst, &oip6->ip6_src);
			else
				nat = nat6_outlookup(fin, flags, p,
				    &oip6->ip6_dst, &oip6->ip6_src);
			fin->fin_data[0] = data[0];
			fin->fin_data[1] = data[1];
			return nat;
		}
	}

	if (flags & IPN_TCPUDP) {
		minlen += 8;		/* + 64bits of data to get ports */
		if (fin->fin_plen < ICMPERR_ICMPHLEN + minlen)
			return NULL;

		data[0] = fin->fin_data[0];
		data[1] = fin->fin_data[1];
		tcp = (tcphdr_t *)(oip6 + 1);
		fin->fin_data[0] = ntohs(tcp->th_dport);
		fin->fin_data[1] = ntohs(tcp->th_sport);

		if (dir == NAT_INBOUND) {
			nat = nat6_inlookup(fin, flags, p,
			    &oip6->ip6_dst, &oip6->ip6_src);
		} else {
			nat = nat6_outlookup(fin, flags, p,
			    &oip6->ip6_dst, &oip6->ip6_src);
		}
		fin->fin_data[0] = data[0];
		fin->fin_data[1] = data[1];
		return nat;
	}
	if (dir == NAT_INBOUND)
		return nat6_inlookup(fin, 0, p, &oip6->ip6_dst, &oip6->ip6_src);
	else
		return nat6_outlookup(fin, 0, p, &oip6->ip6_dst,
		    &oip6->ip6_src);
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_icmperror                                              */
/* Returns:     nat_t* - point to matching NAT structure                    */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              nflags(I) - NAT flags for this packet                       */
/*              dir(I)    - direction of packet (in/out)                    */
/*                                                                          */
/* Fix up an ICMP packet which is an error message for an existing NAT      */
/* session.  This will correct both packet header data and checksums.       */
/*                                                                          */
/* This should *ONLY* be used for incoming ICMP error packets to make sure  */
/* a NAT'd ICMP packet gets correctly recognised.                           */
/* ------------------------------------------------------------------------ */
nat_t *nat6_icmperror(fin, nflags, dir)
fr_info_t *fin;
u_int *nflags;
int dir;
{
	u_32_t sum1, sum2, sumd, psum1, psum2, psumd, sumd1;
	i6addr_t in;
	struct icmp6_hdr *icmp6, *orgicmp;
	int dlen;
	udphdr_t *udp;
	tcphdr_t *tcp;
	nat_t *nat;
	ip6_t *oip6;
	if ((fin->fin_flx & (FI_SHORT|FI_FRAGBODY)))
		return NULL;

	/*
	 * nat6_icmperrorlookup() looks up nat entry associated with the
	 * offending IP packet and returns pointer to the entry, or NULL
	 * if packet wasn't natted or for `defective' packets.
	 */

	if ((fin->fin_v != 6) || !(nat = nat6_icmperrorlookup(fin, dir)))
		return NULL;

	sumd1 = 0;
	*nflags = IPN_ICMPERR;
	icmp6 = fin->fin_dp;
	oip6 = (ip6_t *)((char *)icmp6 + sizeof (*icmp6));
	udp = (udphdr_t *)(((char *)oip6) + sizeof (*oip6));
	tcp = (tcphdr_t *)udp;
	dlen = fin->fin_plen - ((char *)udp - (char *)fin->fin_ip);

	/*
	 * Need to adjust ICMP header to include the real IP#'s and
	 * port #'s.  There are three steps required.
	 *
	 * Step 1
	 * No update needed for ip6 header checksum.
	 *
	 * Unlike IPv4, we need to update icmp_cksum for IPv6 address
	 * changes because there's no ip_sum change to cancel it.
	 */

	if (IP6_EQ((i6addr_t *)&oip6->ip6_dst, &nat->nat_oip6)) {
		sum1 = LONG_SUM6((i6addr_t *)&oip6->ip6_src);
		in = nat->nat_inip6;
		oip6->ip6_src = in.in6;
	} else {
		sum1 = LONG_SUM6((i6addr_t *)&oip6->ip6_dst);
		in = nat->nat_outip6;
		oip6->ip6_dst = in.in6;
	}

	sum2 = LONG_SUM6(&in);
	CALC_SUMD(sum1, sum2, sumd);

	/*
	 * Step 2
	 * Perform other adjustments based on protocol of offending packet.
	 */

	switch (oip6->ip6_nxt) {
		case IPPROTO_TCP :
		case IPPROTO_UDP :

			/*
			* For offending TCP/UDP IP packets, translate the ports
			* based on the NAT specification.
			*
			* Advance notice : Now it becomes complicated :-)
			*
			* Since the port and IP addresse fields are both part
			* of the TCP/UDP checksum of the offending IP packet,
			* we need to adjust that checksum as well.
			*
			* To further complicate things, the TCP/UDP checksum
			* may not be present.  We must check to see if the
			* length of the data portion is big enough to hold
			* the checksum.  In the UDP case, a test to determine
			* if the checksum is even set is also required.
			*
			* Any changes to an IP address, port or checksum within
			* the ICMP packet requires a change to icmp_cksum.
			*
			* Be extremely careful here ... The change is dependent
			* upon whether or not the TCP/UPD checksum is present.
			*
			* If TCP/UPD checksum is present, the icmp_cksum must
			* compensate for checksum modification resulting from
			* IP address change only.  Port change and resulting
			* data checksum adjustments cancel each other out.
			*
			* If TCP/UDP checksum is not present, icmp_cksum must
			* compensate for port change only.  The IP address
			* change does not modify anything else in this case.
			*/

			psum1 = 0;
			psum2 = 0;
			psumd = 0;

			if ((tcp->th_dport == nat->nat_oport) &&
			    (tcp->th_sport != nat->nat_inport)) {

				/*
				 * Translate the source port.
				 */

				psum1 = ntohs(tcp->th_sport);
				psum2 = ntohs(nat->nat_inport);
				tcp->th_sport = nat->nat_inport;

			} else if ((tcp->th_sport == nat->nat_oport) &&
				    (tcp->th_dport != nat->nat_outport)) {

				/*
				 * Translate the destination port.
				 */

				psum1 = ntohs(tcp->th_dport);
				psum2 = ntohs(nat->nat_outport);
				tcp->th_dport = nat->nat_outport;
			}

			if ((oip6->ip6_nxt == IPPROTO_TCP) && (dlen >= 18)) {

				/*
				 * TCP checksum present.
				 *
				 * Adjust data checksum and icmp checksum to
				 * compensate for any IP address change.
				 */

				sum1 = ntohs(tcp->th_sum);
				fix_datacksum(&tcp->th_sum, sumd);
				sum2 = ntohs(tcp->th_sum);
				CALC_SUMD(sum1, sum2, sumd);
				sumd1 += sumd;

				/*
				 * Also make data checksum adjustment to
				 * compensate for any port change.
				 */

				if (psum1 != psum2) {
					CALC_SUMD(psum1, psum2, psumd);
					fix_datacksum(&tcp->th_sum, psumd);
				}

			} else if ((oip6->ip6_nxt == IPPROTO_UDP) &&
				   (dlen >= 8) && (udp->uh_sum != 0)) {

				/*
				 * The UDP checksum is present and set.
				 *
				 * Adjust data checksum and icmp checksum to
				 * compensate for any IP address change.
				 */

				sum1 = ntohs(udp->uh_sum);
				fix_datacksum(&udp->uh_sum, sumd);
				sum2 = ntohs(udp->uh_sum);
				CALC_SUMD(sum1, sum2, sumd);
				sumd1 += sumd;

				/*
				 * Also make data checksum adjustment to
				 * compensate for any port change.
				 */

				if (psum1 != psum2) {
					CALC_SUMD(psum1, psum2, psumd);
					fix_datacksum(&udp->uh_sum, psumd);
				}

			} else {

				/*
				 * Data checksum was not present.
				 *
				 * Compensate for any port change.
				 */

				CALC_SUMD(psum2, psum1, psumd);
				sumd1 += psumd;
			}
			break;

		case IPPROTO_ICMPV6 :

			orgicmp = (struct icmp6_hdr *)udp;

			if ((nat->nat_dir == NAT_OUTBOUND) &&
			    (orgicmp->icmp6_id != nat->nat_inport) &&
			    (dlen >= 8)) {

				/*
				 * Fix ICMP checksum (of the offening ICMP
				 * query packet) to compensate the change
				 * in the ICMP id of the offending ICMP
				 * packet.
				 *
				 * Since you modify orgicmp->icmp_id with
				 * a delta (say x) and you compensate that
				 * in origicmp->icmp_cksum with a delta
				 * minus x, you don't have to adjust the
				 * overall icmp->icmp_cksum
				 */

				sum1 = ntohs(orgicmp->icmp6_id);
				sum2 = ntohs(nat->nat_inport);
				CALC_SUMD(sum1, sum2, sumd);
				orgicmp->icmp6_id = nat->nat_inport;
				fix_datacksum(&orgicmp->icmp6_cksum, sumd);

			} /* nat_dir can't be NAT_INBOUND for icmp queries */

			break;

		default :

			break;

	} /* switch (oip6->ip6_nxt) */

	/*
	 * Step 3
	 * Make the adjustments to icmp checksum.
	 */

	if (sumd1 != 0) {
		sumd1 = (sumd1 & 0xffff) + (sumd1 >> 16);
		sumd1 = (sumd1 & 0xffff) + (sumd1 >> 16);
		fix_incksum(&icmp6->icmp6_cksum, sumd1);
	}
	return nat;
}


/*
 * NB: these lookups don't lock access to the list, it assumed that it has
 * already been done!
 */

/* ------------------------------------------------------------------------ */
/* Function:    nat6_inlookup                                               */
/* Returns:     nat_t* - NULL == no match,                                  */
/*                       else pointer to matching NAT entry                 */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              flags(I)  - NAT flags for this packet                       */
/*              p(I)      - protocol for this packet                        */
/*              src(I)    - source IP address                               */
/*              mapdst(I) - destination IP address                          */
/*                                                                          */
/* Lookup a nat entry based on the mapped destination ip address/port and   */
/* real source address/port.  We use this lookup when receiving a packet,   */
/* we're looking for a table entry, based on the destination address.       */
/*                                                                          */
/* NOTE: THE PACKET BEING CHECKED (IF FOUND) HAS A MAPPING ALREADY.         */
/*                                                                          */
/* NOTE: IT IS ASSUMED THAT ipf_nat IS ONLY HELD WITH A READ LOCK WHEN      */
/*       THIS FUNCTION IS CALLED WITH NAT_SEARCH SET IN nflags.             */
/*                                                                          */
/* flags   -> relevant are IPN_UDP/IPN_TCP/IPN_ICMPQUERY that indicate if   */
/*            the packet is of said protocol                                */
/* ------------------------------------------------------------------------ */
nat_t *nat6_inlookup(fin, flags, p, src, mapdst)
fr_info_t *fin;
u_int flags, p;
struct in6_addr *src, *mapdst;
{
	u_short sport, dport;
	u_int sflags;
	nat_t *nat;
	int nflags;
	i6addr_t dst;
	void *ifp;
	u_int hv;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (fin != NULL)
		ifp = fin->fin_ifp;
	else
		ifp = NULL;
	sport = 0;
	dport = 0;
	dst.in6 = *mapdst;
	sflags = flags & NAT_TCPUDPICMP;

	switch (p)
	{
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		sport = htons(fin->fin_data[0]);
		dport = htons(fin->fin_data[1]);
		break;
	case IPPROTO_ICMPV6 :
		if (flags & IPN_ICMPERR)
			sport = fin->fin_data[1];
		else
			dport = fin->fin_data[1];
		break;
	default :
		break;
	}


	if ((flags & SI_WILDP) != 0)
		goto find_in_wild_ports;

	hv = NAT_HASH_FN6(&dst, dport, 0xffffffff);
	hv = NAT_HASH_FN6(src, hv + sport, ifs->ifs_ipf_nattable_sz);
	nat = ifs->ifs_nat_table[1][hv];
	for (; nat; nat = nat->nat_hnext[1]) {
		if (nat->nat_v != 6)
			continue;

		if (nat->nat_ifps[0] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[0]))
				continue;
		} else if (ifp != NULL)
			nat->nat_ifps[0] = ifp;

		nflags = nat->nat_flags;

		if (IP6_EQ(&nat->nat_oip6, src) &&
		    IP6_EQ(&nat->nat_outip6, &dst) &&
		    (((p == 0) &&
		    (sflags == (nat->nat_flags & IPN_TCPUDPICMP))) ||
		    (p == nat->nat_p))) {
			switch (p)
			{
#if 0
			case IPPROTO_GRE :
				if (nat->nat_call[1] != fin->fin_data[0])
					continue;
				break;
#endif
			case IPPROTO_ICMPV6 :
				if ((flags & IPN_ICMPERR) != 0) {
					if (nat->nat_outport != sport)
						continue;
				} else {
					if (nat->nat_outport != dport)
						continue;
				}
				break;
			case IPPROTO_TCP :
			case IPPROTO_UDP :
				if (nat->nat_oport != sport)
					continue;
				if (nat->nat_outport != dport)
					continue;
				break;
			default :
				break;
			}

#ifdef	IPF_V6_PROXIES
			ipn = nat->nat_ptr;
			if ((ipn != NULL) && (nat->nat_aps != NULL))
				if (appr_match(fin, nat) != 0)
					continue;
#endif
			return nat;
		}
	}

	/*
	 * So if we didn't find it but there are wildcard members in the hash
	 * table, go back and look for them.  We do this search and update here
	 * because it is modifying the NAT table and we want to do this only
	 * for the first packet that matches.  The exception, of course, is
	 * for "dummy" (FI_IGNORE) lookups.
	 */
find_in_wild_ports:
	if (!(flags & NAT_TCPUDP) || !(flags & NAT_SEARCH))
		return NULL;
	if (ifs->ifs_nat_stats.ns_wilds == 0)
		return NULL;

	RWLOCK_EXIT(&ifs->ifs_ipf_nat);

	hv = NAT_HASH_FN6(&dst, 0, 0xffffffff);
	hv = NAT_HASH_FN6(src, hv, ifs->ifs_ipf_nattable_sz);

	WRITE_ENTER(&ifs->ifs_ipf_nat);

	nat = ifs->ifs_nat_table[1][hv];
	for (; nat; nat = nat->nat_hnext[1]) {
		if (nat->nat_v != 6)
			continue;

		if (nat->nat_ifps[0] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[0]))
				continue;
		} else if (ifp != NULL)
			nat->nat_ifps[0] = ifp;

		if (nat->nat_p != fin->fin_p)
			continue;
		if (IP6_NEQ(&nat->nat_oip6, src) ||
		    IP6_NEQ(&nat->nat_outip6, &dst))
			continue;

		nflags = nat->nat_flags;
		if (!(nflags & (NAT_TCPUDP|SI_WILDP)))
			continue;

		if (nat_wildok(nat, (int)sport, (int)dport, nflags,
			       NAT_INBOUND) == 1) {
			if ((fin->fin_flx & FI_IGNORE) != 0)
				break;
			if ((nflags & SI_CLONE) != 0) {
				nat = fr_natclone(fin, nat);
				if (nat == NULL)
					break;
			} else {
				MUTEX_ENTER(&ifs->ifs_ipf_nat_new);
				ifs->ifs_nat_stats.ns_wilds--;
				MUTEX_EXIT(&ifs->ifs_ipf_nat_new);
			}
			nat->nat_oport = sport;
			nat->nat_outport = dport;
			nat->nat_flags &= ~(SI_W_DPORT|SI_W_SPORT);
			nat6_tabmove(nat, ifs);
			break;
		}
	}

	MUTEX_DOWNGRADE(&ifs->ifs_ipf_nat);

	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_tabmove                                                */
/* Returns:     Nil                                                         */
/* Parameters:  nat(I) - pointer to NAT structure                           */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* This function is only called for TCP/UDP NAT table entries where the     */
/* original was placed in the table without hashing on the ports and we now */
/* want to include hashing on port numbers.                                 */
/* ------------------------------------------------------------------------ */
static void nat6_tabmove(nat, ifs)
nat_t *nat;
ipf_stack_t *ifs;
{
	nat_t **natp;
	u_int hv;

	if (nat->nat_flags & SI_CLONE)
		return;

	/*
	 * Remove the NAT entry from the old location
	 */
	if (nat->nat_hnext[0])
		nat->nat_hnext[0]->nat_phnext[0] = nat->nat_phnext[0];
	*nat->nat_phnext[0] = nat->nat_hnext[0];
	ifs->ifs_nat_stats.ns_bucketlen[0][nat->nat_hv[0]]--;

	if (nat->nat_hnext[1])
		nat->nat_hnext[1]->nat_phnext[1] = nat->nat_phnext[1];
	*nat->nat_phnext[1] = nat->nat_hnext[1];
	ifs->ifs_nat_stats.ns_bucketlen[1][nat->nat_hv[1]]--;

	/*
	 * Add into the NAT table in the new position
	 */
	hv = NAT_HASH_FN6(&nat->nat_inip6, nat->nat_inport, 0xffffffff);
	hv = NAT_HASH_FN6(&nat->nat_oip6, hv + nat->nat_oport,
			 ifs->ifs_ipf_nattable_sz);
	nat->nat_hv[0] = hv;
	natp = &ifs->ifs_nat_table[0][hv];
	if (*natp)
		(*natp)->nat_phnext[0] = &nat->nat_hnext[0];
	nat->nat_phnext[0] = natp;
	nat->nat_hnext[0] = *natp;
	*natp = nat;
	ifs->ifs_nat_stats.ns_bucketlen[0][hv]++;

	hv = NAT_HASH_FN6(&nat->nat_outip6, nat->nat_outport, 0xffffffff);
	hv = NAT_HASH_FN6(&nat->nat_oip6, hv + nat->nat_oport,
			 ifs->ifs_ipf_nattable_sz);
	nat->nat_hv[1] = hv;
	natp = &ifs->ifs_nat_table[1][hv];
	if (*natp)
		(*natp)->nat_phnext[1] = &nat->nat_hnext[1];
	nat->nat_phnext[1] = natp;
	nat->nat_hnext[1] = *natp;
	*natp = nat;
	ifs->ifs_nat_stats.ns_bucketlen[1][hv]++;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_outlookup                                              */
/* Returns:     nat_t* - NULL == no match,                                  */
/*                       else pointer to matching NAT entry                 */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              flags(I) - NAT flags for this packet                        */
/*              p(I)     - protocol for this packet                         */
/*              src(I)   - source IP address                                */
/*              dst(I)   - destination IP address                           */
/*              rw(I)    - 1 == write lock on ipf_nat held, 0 == read lock. */
/*                                                                          */
/* Lookup a nat entry based on the source 'real' ip address/port and        */
/* destination address/port.  We use this lookup when sending a packet out, */
/* we're looking for a table entry, based on the source address.            */
/*                                                                          */
/* NOTE: THE PACKET BEING CHECKED (IF FOUND) HAS A MAPPING ALREADY.         */
/*                                                                          */
/* NOTE: IT IS ASSUMED THAT ipf_nat IS ONLY HELD WITH A READ LOCK WHEN      */
/*       THIS FUNCTION IS CALLED WITH NAT_SEARCH SET IN nflags.             */
/*                                                                          */
/* flags   -> relevant are IPN_UDP/IPN_TCP/IPN_ICMPQUERY that indicate if   */
/*            the packet is of said protocol                                */
/* ------------------------------------------------------------------------ */
nat_t *nat6_outlookup(fin, flags, p, src, dst)
fr_info_t *fin;
u_int flags, p;
struct in6_addr *src , *dst;
{
	u_short sport, dport;
	u_int sflags;
	nat_t *nat;
	int nflags;
	void *ifp;
	u_int hv;
	ipf_stack_t *ifs = fin->fin_ifs;

	ifp = fin->fin_ifp;

	sflags = flags & IPN_TCPUDPICMP;
	sport = 0;
	dport = 0;

	switch (p)
	{
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		sport = htons(fin->fin_data[0]);
		dport = htons(fin->fin_data[1]);
		break;
	case IPPROTO_ICMPV6 :
		if (flags & IPN_ICMPERR)
			sport = fin->fin_data[1];
		else
			dport = fin->fin_data[1];
		break;
	default :
		break;
	}

	if ((flags & SI_WILDP) != 0)
		goto find_out_wild_ports;

	hv = NAT_HASH_FN6(src, sport, 0xffffffff);
	hv = NAT_HASH_FN6(dst, hv + dport, ifs->ifs_ipf_nattable_sz);
	nat = ifs->ifs_nat_table[0][hv];
	for (; nat; nat = nat->nat_hnext[0]) {
		if (nat->nat_v != 6)
			continue;

		if (nat->nat_ifps[1] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[1]))
				continue;
		} else if (ifp != NULL)
			nat->nat_ifps[1] = ifp;

		nflags = nat->nat_flags;
 
		if (IP6_EQ(&nat->nat_inip6, src) &&
		    IP6_EQ(&nat->nat_oip6, dst) &&
		    (((p == 0) && (sflags == (nflags & NAT_TCPUDPICMP))) ||
		    (p == nat->nat_p))) {
			switch (p)
			{
#if 0
			case IPPROTO_GRE :
				if (nat->nat_call[1] != fin->fin_data[0])
					continue;
				break;
#endif
			case IPPROTO_TCP :
			case IPPROTO_UDP :
				if (nat->nat_oport != dport)
					continue;
				if (nat->nat_inport != sport)
					continue;
				break;
			default :
				break;
			}

#ifdef	IPF_V6_PROXIES
			ipn = nat->nat_ptr;
			if ((ipn != NULL) && (nat->nat_aps != NULL))
				if (appr_match(fin, nat) != 0)
					continue;
#endif
			return nat;
		}
	}

	/*
	 * So if we didn't find it but there are wildcard members in the hash
	 * table, go back and look for them.  We do this search and update here
	 * because it is modifying the NAT table and we want to do this only
	 * for the first packet that matches.  The exception, of course, is
	 * for "dummy" (FI_IGNORE) lookups.
	 */
find_out_wild_ports:
	if (!(flags & NAT_TCPUDP) || !(flags & NAT_SEARCH))
		return NULL;
	if (ifs->ifs_nat_stats.ns_wilds == 0)
		return NULL;

	RWLOCK_EXIT(&ifs->ifs_ipf_nat);

	hv = NAT_HASH_FN6(src, 0, 0xffffffff);
	hv = NAT_HASH_FN6(dst, hv, ifs->ifs_ipf_nattable_sz);

	WRITE_ENTER(&ifs->ifs_ipf_nat);

	nat = ifs->ifs_nat_table[0][hv];
	for (; nat; nat = nat->nat_hnext[0]) {
		if (nat->nat_v != 6)
			continue;

		if (nat->nat_ifps[1] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[1]))
				continue;
		} else if (ifp != NULL)
			nat->nat_ifps[1] = ifp;

		if (nat->nat_p != fin->fin_p)
			continue;
		if (IP6_NEQ(&nat->nat_inip6, src) ||
		    IP6_NEQ(&nat->nat_oip6, dst))
			continue;

		nflags = nat->nat_flags;
		if (!(nflags & (NAT_TCPUDP|SI_WILDP)))
			continue;

		if (nat_wildok(nat, (int)sport, (int)dport, nflags,
			       NAT_OUTBOUND) == 1) {
			if ((fin->fin_flx & FI_IGNORE) != 0)
				break;
			if ((nflags & SI_CLONE) != 0) {
				nat = fr_natclone(fin, nat);
				if (nat == NULL)
					break;
			} else {
				MUTEX_ENTER(&ifs->ifs_ipf_nat_new);
				ifs->ifs_nat_stats.ns_wilds--;
				MUTEX_EXIT(&ifs->ifs_ipf_nat_new);
			}
			nat->nat_inport = sport;
			nat->nat_oport = dport;
			if (nat->nat_outport == 0)
				nat->nat_outport = sport;
			nat->nat_flags &= ~(SI_W_DPORT|SI_W_SPORT);
			nat6_tabmove(nat, ifs);
			break;
		}
	}

	MUTEX_DOWNGRADE(&ifs->ifs_ipf_nat);

	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_lookupredir                                            */
/* Returns:     nat_t* - NULL == no match,                                  */
/*                       else pointer to matching NAT entry                 */
/* Parameters:  np(I) - pointer to description of packet to find NAT table  */
/*                      entry for.                                          */
/*                                                                          */
/* Lookup the NAT tables to search for a matching redirect                  */
/* ------------------------------------------------------------------------ */
nat_t *nat6_lookupredir(np, ifs)
natlookup_t *np;
ipf_stack_t *ifs;
{
	fr_info_t fi;
	nat_t *nat;

	bzero((char *)&fi, sizeof (fi));
	if (np->nl_flags & IPN_IN) {
		fi.fin_data[0] = ntohs(np->nl_realport);
		fi.fin_data[1] = ntohs(np->nl_outport);
	} else {
		fi.fin_data[0] = ntohs(np->nl_inport);
		fi.fin_data[1] = ntohs(np->nl_outport);
	}
	if (np->nl_flags & IPN_TCP)
		fi.fin_p = IPPROTO_TCP;
	else if (np->nl_flags & IPN_UDP)
		fi.fin_p = IPPROTO_UDP;
	else if (np->nl_flags & (IPN_ICMPERR|IPN_ICMPQUERY))
		fi.fin_p = IPPROTO_ICMPV6;

	fi.fin_ifs = ifs;
	/*
	 * We can do two sorts of lookups:
	 * - IPN_IN: we have the `real' and `out' address, look for `in'.
	 * - default: we have the `in' and `out' address, look for `real'.
	 */
	if (np->nl_flags & IPN_IN) {
		if ((nat = nat6_inlookup(&fi, np->nl_flags, fi.fin_p,
					 &np->nl_realip6, &np->nl_outip6))) {
			np->nl_inipaddr = nat->nat_inip6;
			np->nl_inport = nat->nat_inport;
		}
	} else {
		/*
		 * If nl_inip is non null, this is a lookup based on the real
		 * ip address. Else, we use the fake.
		 */
		if ((nat = nat6_outlookup(&fi, np->nl_flags, fi.fin_p,
					  &np->nl_inip6, &np->nl_outip6))) {
			if ((np->nl_flags & IPN_FINDFORWARD) != 0) {
				fr_info_t fin;
				bzero((char *)&fin, sizeof (fin));
				fin.fin_p = nat->nat_p;
				fin.fin_data[0] = ntohs(nat->nat_outport);
				fin.fin_data[1] = ntohs(nat->nat_oport);
				fin.fin_ifs = ifs;
				if (nat6_inlookup(&fin, np->nl_flags, fin.fin_p,
						 &nat->nat_outip6.in6,
						 &nat->nat_oip6.in6) != NULL) {
					np->nl_flags &= ~IPN_FINDFORWARD;
				}
			}

			np->nl_realip6 = nat->nat_outip6.in6;
			np->nl_realport = nat->nat_outport;
		}
 	}

	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat6_match                                                  */
/* Returns:     int - 0 == no match, 1 == match                             */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              np(I)    - pointer to NAT rule                              */
/*                                                                          */
/* Pull the matching of a packet against a NAT rule out of that complex     */
/* loop inside fr_checknat6in() and lay it out properly in its own function.*/
/* ------------------------------------------------------------------------ */
static int nat6_match(fin, np)
fr_info_t *fin;
ipnat_t *np;
{
	frtuc_t *ft;

	if (fin->fin_v != 6)
		return 0;

	if (np->in_p && fin->fin_p != np->in_p)
		return 0;

	if (fin->fin_out) {
		if (!(np->in_redir & (NAT_MAP|NAT_MAPBLK)))
			return 0;
		if (IP6_MASKNEQ(&fin->fin_src6, &np->in_in[1], &np->in_in[0])
		    ^ ((np->in_flags & IPN_NOTSRC) != 0))
			return 0;
		if (IP6_MASKNEQ(&fin->fin_dst6, &np->in_src[1], &np->in_src[0])
		    ^ ((np->in_flags & IPN_NOTDST) != 0))
			return 0;
	} else {
		if (!(np->in_redir & NAT_REDIRECT))
			return 0;
		if (IP6_MASKNEQ(&fin->fin_src6, &np->in_src[1], &np->in_src[0])
		    ^ ((np->in_flags & IPN_NOTSRC) != 0))
			return 0;
		if (IP6_MASKNEQ(&fin->fin_dst6, &np->in_out[1], &np->in_out[0])
		    ^ ((np->in_flags & IPN_NOTDST) != 0))
			return 0;
	}

	ft = &np->in_tuc;
	if (!(fin->fin_flx & FI_TCPUDP) ||
	    (fin->fin_flx & (FI_SHORT|FI_FRAGBODY))) {
		if (ft->ftu_scmp || ft->ftu_dcmp)
			return 0;
		return 1;
	}

	return fr_tcpudpchk(fin, ft);
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_checknat6out                                             */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     0 == no packet translation occurred,                 */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              passp(I) - pointer to filtering result flags                */
/*                                                                          */
/* Check to see if an outcoming packet should be changed.  ICMP packets are */
/* first checked to see if they match an existing entry (if an error),      */
/* otherwise a search of the current NAT table is made.  If neither results */
/* in a match then a search for a matching NAT rule is made.  Create a new  */
/* NAT entry if a we matched a NAT rule.  Lastly, actually change the       */
/* packet header(s) as required.                                            */
/* ------------------------------------------------------------------------ */
int fr_checknat6out(fin, passp)
fr_info_t *fin;
u_32_t *passp;
{
	struct ifnet *ifp, *sifp;
	int rval, natfailed;
	ipnat_t *np = NULL;
	u_int nflags = 0;
	i6addr_t ipa, iph;
	int natadd = 1;
	frentry_t *fr;
	nat_t *nat;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (ifs->ifs_nat_stats.ns_rules == 0 || ifs->ifs_fr_nat_lock != 0)
		return 0;

	natfailed = 0;
	fr = fin->fin_fr;
	sifp = fin->fin_ifp;
	if ((fr != NULL) && !(fr->fr_flags & FR_DUP) &&
	    fr->fr_tifs[fin->fin_rev].fd_ifp &&
	    fr->fr_tifs[fin->fin_rev].fd_ifp != (void *)-1)
		fin->fin_ifp = fr->fr_tifs[fin->fin_rev].fd_ifp;
	ifp = fin->fin_ifp;

	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		switch (fin->fin_p)
		{
		case IPPROTO_TCP :
			nflags = IPN_TCP;
			break;
		case IPPROTO_UDP :
			nflags = IPN_UDP;
			break;
		case IPPROTO_ICMPV6 :
			/*
			 * This is an incoming packet, so the destination is
			 * the icmp6_id and the source port equals 0
			 */
			if ((fin->fin_flx & FI_ICMPQUERY) != 0)
				nflags = IPN_ICMPQUERY;
			break;
		default :
			break;
		}

#ifdef	IPF_V6_PROXIES
		if ((nflags & IPN_TCPUDP))
			tcp = fin->fin_dp;
#endif
	}

	ipa = fin->fin_src6;

	READ_ENTER(&ifs->ifs_ipf_nat);

	if ((fin->fin_p == IPPROTO_ICMPV6) && !(nflags & IPN_ICMPQUERY) &&
	    (nat = nat6_icmperror(fin, &nflags, NAT_OUTBOUND)))
		/*EMPTY*/;
	else if ((fin->fin_flx & FI_FRAG) && (nat = fr_nat_knownfrag(fin)))
		natadd = 0;
	else if ((nat = nat6_outlookup(fin, nflags|NAT_SEARCH,
		    (u_int)fin->fin_p, &fin->fin_src6.in6,
		    &fin->fin_dst6.in6))) {
		nflags = nat->nat_flags;
	} else {
		u_32_t hv, nmsk;
		i6addr_t msk;
		int i;

		/*
		 * If there is no current entry in the nat table for this IP#,
		 * create one for it (if there is a matching rule).
		 */
		RWLOCK_EXIT(&ifs->ifs_ipf_nat);
		i = 3;
		msk.i6[0] = 0xffffffff;
		msk.i6[1] = 0xffffffff;
		msk.i6[2] = 0xffffffff;
		msk.i6[3] = 0xffffffff;
		nmsk = ifs->ifs_nat6_masks[3];
		WRITE_ENTER(&ifs->ifs_ipf_nat);
maskloop:
		IP6_AND(&ipa, &msk, &iph);
		hv = NAT_HASH_FN6(&iph, 0, ifs->ifs_ipf_natrules_sz);
		for (np = ifs->ifs_nat_rules[hv]; np; np = np->in_mnext)
		{
			if ((np->in_ifps[1] && (np->in_ifps[1] != ifp)))
				continue;
			if (np->in_v != 6)
				continue;
			if (np->in_p && (np->in_p != fin->fin_p))
				continue;
			if ((np->in_flags & IPN_RF) && !(np->in_flags & nflags))
				continue;
			if (np->in_flags & IPN_FILTER) {
				if (!nat6_match(fin, np))
					continue;
			} else if (!IP6_MASKEQ(&ipa, &np->in_in[1],
			    &np->in_in[0]))
				continue;

			if ((fr != NULL) &&
			    !fr_matchtag(&np->in_tag, &fr->fr_nattag))
				continue;

#ifdef	IPF_V6_PROXIES
			if (*np->in_plabel != '\0') {
				if (((np->in_flags & IPN_FILTER) == 0) &&
				    (np->in_dport != tcp->th_dport))
					continue;
				if (appr_ok(fin, tcp, np) == 0)
					continue;
			}
#endif

			if (nat = nat6_new(fin, np, NULL, nflags,
					   NAT_OUTBOUND)) {
				np->in_hits++;
				break;
			} else
				natfailed = -1;
		}
		if ((np == NULL) && (i >= 0)) {
			while (i >= 0) {
				while (nmsk) {
					msk.i6[i] = htonl(ntohl(msk.i6[i])<<1);
					if ((nmsk & 0x80000000) != 0) {
						nmsk <<= 1;
						goto maskloop;
					}
					nmsk <<= 1;
				}
				msk.i6[i--] = 0;
				if (i >= 0) {
					nmsk = ifs->ifs_nat6_masks[i];
					if (nmsk != 0)
						goto maskloop;
				}
			}
		}
		MUTEX_DOWNGRADE(&ifs->ifs_ipf_nat);
	}

	if (nat != NULL) {
		rval = fr_nat6out(fin, nat, natadd, nflags);
	} else {
		rval = natfailed;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_nat);

	if (rval == -1) {
		if (passp != NULL)
			*passp = FR_BLOCK;
		fin->fin_flx |= FI_BADNAT;
	}
	fin->fin_ifp = sifp;
	return rval;
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_nat6out                                                  */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              nat(I)    - pointer to NAT structure                        */
/*              natadd(I) - flag indicating if it is safe to add frag cache */
/*              nflags(I) - NAT flags set for this packet                   */
/*                                                                          */
/* Translate a packet coming "out" on an interface.                         */
/* ------------------------------------------------------------------------ */
int fr_nat6out(fin, nat, natadd, nflags)
fr_info_t *fin;
nat_t *nat;
int natadd;
u_32_t nflags;
{
	struct icmp6_hdr *icmp6;
	u_short *csump;
	tcphdr_t *tcp;
	ipnat_t *np;
	int i;
	ipf_stack_t *ifs = fin->fin_ifs;

#if SOLARIS && defined(_KERNEL)
	net_handle_t net_data_p = ifs->ifs_ipf_ipv6;
#endif

	tcp = NULL;
	icmp6 = NULL;
	csump = NULL;
	np = nat->nat_ptr;

	if ((natadd != 0) && (fin->fin_flx & FI_FRAG))
		(void) fr_nat_newfrag(fin, 0, nat);

	MUTEX_ENTER(&nat->nat_lock);
	nat->nat_bytes[1] += fin->fin_plen;
	nat->nat_pkts[1]++;
	MUTEX_EXIT(&nat->nat_lock);
	
	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		if ((nat->nat_outport != 0) && (nflags & IPN_TCPUDP)) {
			tcp = fin->fin_dp;

			tcp->th_sport = nat->nat_outport;
			fin->fin_data[0] = ntohs(nat->nat_outport);
		}

		if ((nat->nat_outport != 0) && (nflags & IPN_ICMPQUERY)) {
			icmp6 = fin->fin_dp;
			icmp6->icmp6_id = nat->nat_outport;
		}

		csump = nat_proto(fin, nat, nflags);
	}

	fin->fin_ip6->ip6_src = nat->nat_outip6.in6;
	fin->fin_src6 = nat->nat_outip6;

	nat_update(fin, nat, np);

	/*
	 * TCP/UDP/ICMPv6 checksum needs to be adjusted.
	 */
	if (csump != NULL && (!(nflags & IPN_TCPUDP) ||
	    !NET_IS_HCK_L4_FULL(net_data_p, fin->fin_m))) {
		if (nflags & IPN_TCPUDP &&
	   	    NET_IS_HCK_L4_PART(net_data_p, fin->fin_m)) {
			if (nat->nat_dir == NAT_OUTBOUND)
				fix_outcksum(csump, nat->nat_sumd[1]);
			else
				fix_incksum(csump, nat->nat_sumd[1]);
		} else {
			if (nat->nat_dir == NAT_OUTBOUND)
				fix_outcksum(csump, nat->nat_sumd[0]);
			else
				fix_incksum(csump, nat->nat_sumd[0]);
		}
	}
#ifdef	IPFILTER_SYNC
	ipfsync_update(SMC_NAT, fin, nat->nat_sync);
#endif
	/* ------------------------------------------------------------- */
	/* A few quick notes:						 */
	/*	Following are test conditions prior to calling the 	 */
	/*	appr_check routine.					 */
	/*								 */
	/* 	A NULL tcp indicates a non TCP/UDP packet.  When dealing */
	/*	with a redirect rule, we attempt to match the packet's	 */
	/*	source port against in_dport, otherwise	we'd compare the */
	/*	packet's destination.			 		 */
	/* ------------------------------------------------------------- */
	if ((np != NULL) && (np->in_apr != NULL)) {
		i = appr_check(fin, nat);
		if (i == 0)
			i = 1;
	} else
		i = 1;
	ATOMIC_INCL(ifs->ifs_nat_stats.ns_mapped[1]);
	fin->fin_flx |= FI_NATED;
	return i;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_checknat6in                                              */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     0 == no packet translation occurred,                 */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              passp(I) - pointer to filtering result flags                */
/*                                                                          */
/* Check to see if an incoming packet should be changed.  ICMP packets are  */
/* first checked to see if they match an existing entry (if an error),      */
/* otherwise a search of the current NAT table is made.  If neither results */
/* in a match then a search for a matching NAT rule is made.  Create a new  */
/* NAT entry if a we matched a NAT rule.  Lastly, actually change the       */
/* packet header(s) as required.                                            */
/* ------------------------------------------------------------------------ */
int fr_checknat6in(fin, passp)
fr_info_t *fin;
u_32_t *passp;
{
	u_int nflags, natadd;
	int rval, natfailed;
	struct ifnet *ifp;
	struct icmp6_hdr *icmp6;
	tcphdr_t *tcp;
	u_short dport;
	ipnat_t *np;
	nat_t *nat;
	i6addr_t ipa, iph;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (ifs->ifs_nat_stats.ns_rules == 0 || ifs->ifs_fr_nat_lock != 0)
		return 0;

	tcp = NULL;
	icmp6 = NULL;
	dport = 0;
	natadd = 1;
	nflags = 0;
	natfailed = 0;
	ifp = fin->fin_ifp;

	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		switch (fin->fin_p)
		{
		case IPPROTO_TCP :
			nflags = IPN_TCP;
			break;
		case IPPROTO_UDP :
			nflags = IPN_UDP;
			break;
		case IPPROTO_ICMPV6 :
			icmp6 = fin->fin_dp;

			/*
			 * This is an incoming packet, so the destination is
			 * the icmp_id and the source port equals 0
			 */
			if ((fin->fin_flx & FI_ICMPQUERY) != 0) {
				nflags = IPN_ICMPQUERY;
				dport = icmp6->icmp6_id;	
			} break;
		default :
			break;
		}
		
		if ((nflags & IPN_TCPUDP)) {
			tcp = fin->fin_dp;
			dport = tcp->th_dport;
		}
	}

	ipa = fin->fin_dst6;

	READ_ENTER(&ifs->ifs_ipf_nat);

	if ((fin->fin_p == IPPROTO_ICMPV6) && !(nflags & IPN_ICMPQUERY) &&
	    (nat = nat6_icmperror(fin, &nflags, NAT_INBOUND)))
		/*EMPTY*/;
	else if ((fin->fin_flx & FI_FRAG) && (nat = fr_nat_knownfrag(fin)))
		natadd = 0;
	else if ((nat = nat6_inlookup(fin, nflags|NAT_SEARCH, (u_int)fin->fin_p,
	    &fin->fin_src6.in6, &ipa.in6))) {
		nflags = nat->nat_flags;
	} else {
		u_32_t hv, rmsk;
		i6addr_t msk;
		int i;

		RWLOCK_EXIT(&ifs->ifs_ipf_nat);
		i = 3;
		msk.i6[0] = 0xffffffff;
		msk.i6[1] = 0xffffffff;
		msk.i6[2] = 0xffffffff;
		msk.i6[3] = 0xffffffff;
		rmsk = ifs->ifs_rdr6_masks[3];
		WRITE_ENTER(&ifs->ifs_ipf_nat);
		/*
		 * If there is no current entry in the nat table for this IP#,
		 * create one for it (if there is a matching rule).
		 */
maskloop:
		IP6_AND(&ipa, &msk, &iph);
		hv = NAT_HASH_FN6(&iph, 0, ifs->ifs_ipf_rdrrules_sz);
		for (np = ifs->ifs_rdr_rules[hv]; np; np = np->in_rnext) {
			if (np->in_ifps[0] && (np->in_ifps[0] != ifp))
				continue;
			if (np->in_v != fin->fin_v)
				continue;
			if (np->in_p && (np->in_p != fin->fin_p))
				continue;
			if ((np->in_flags & IPN_RF) && !(np->in_flags & nflags))
				continue;
			if (np->in_flags & IPN_FILTER) {
				if (!nat6_match(fin, np))
					continue;
			} else {
				if (!IP6_MASKEQ(&ipa, &np->in_out[1],
				    &np->in_out[0]))
					continue;
				if (np->in_pmin &&
				    ((ntohs(np->in_pmax) < ntohs(dport)) ||
				     (ntohs(dport) < ntohs(np->in_pmin))))
					continue;
			}

#ifdef	IPF_V6_PROXIES
			if (*np->in_plabel != '\0') {
				if (!appr_ok(fin, tcp, np)) {
					continue;
				}
			}
#endif

			nat = nat6_new(fin, np, NULL, nflags, NAT_INBOUND);
			if (nat != NULL) {
				np->in_hits++;
				break;
			} else
				natfailed = -1;
		}

		if ((np == NULL) && (i >= 0)) {
			while (i >= 0) {
				while (rmsk) {
					msk.i6[i] = htonl(ntohl(msk.i6[i])<<1);
					if ((rmsk & 0x80000000) != 0) {
						rmsk <<= 1;
						goto maskloop;
					}
					rmsk <<= 1;
				}
				msk.i6[i--] = 0;
				if (i >= 0) {
					rmsk = ifs->ifs_rdr6_masks[i];
					if (rmsk != 0)
						goto maskloop;
				}
			}
		}
		MUTEX_DOWNGRADE(&ifs->ifs_ipf_nat);
	}
	if (nat != NULL) {
		rval = fr_nat6in(fin, nat, natadd, nflags);
	} else {
		rval = natfailed;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_nat);

	if (rval == -1) {
		if (passp != NULL)
			*passp = FR_BLOCK;
		fin->fin_flx |= FI_BADNAT;
	}
	return rval;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_nat6in                                                   */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              nat(I)    - pointer to NAT structure                        */
/*              natadd(I) - flag indicating if it is safe to add frag cache */
/*              nflags(I) - NAT flags set for this packet                   */
/* Locks Held:  ipf_nat (READ)                                              */
/*                                                                          */
/* Translate a packet coming "in" on an interface.                          */
/* ------------------------------------------------------------------------ */
int fr_nat6in(fin, nat, natadd, nflags)
fr_info_t *fin;
nat_t *nat;
int natadd;
u_32_t nflags;
{
	struct icmp6_hdr *icmp6;
	u_short *csump;
	tcphdr_t *tcp;
	ipnat_t *np;
	ipf_stack_t *ifs = fin->fin_ifs;

#if SOLARIS && defined(_KERNEL)
	net_handle_t net_data_p = ifs->ifs_ipf_ipv6;
#endif

	tcp = NULL;
	csump = NULL;
	np = nat->nat_ptr;
	fin->fin_fr = nat->nat_fr;

	if ((natadd != 0) && (fin->fin_flx & FI_FRAG))
		(void) fr_nat_newfrag(fin, 0, nat);

#ifdef	IPF_V6_PROXIES
	if (np != NULL) {

	/* ------------------------------------------------------------- */
	/* A few quick notes:						 */
	/*	Following are test conditions prior to calling the 	 */
	/*	appr_check routine.					 */
	/*								 */
	/* 	A NULL tcp indicates a non TCP/UDP packet.  When dealing */
	/*	with a map rule, we attempt to match the packet's	 */
	/*	source port against in_dport, otherwise	we'd compare the */
	/*	packet's destination.			 		 */
	/* ------------------------------------------------------------- */
		if (np->in_apr != NULL) {
			i = appr_check(fin, nat);
			if (i == -1) {
				return -1;
			}
		}
	}
#endif

#ifdef	IPFILTER_SYNC
	ipfsync_update(SMC_NAT, fin, nat->nat_sync);
#endif

	MUTEX_ENTER(&nat->nat_lock);
	nat->nat_bytes[0] += fin->fin_plen;
	nat->nat_pkts[0]++;
	MUTEX_EXIT(&nat->nat_lock);

	fin->fin_ip6->ip6_dst = nat->nat_inip6.in6;
	fin->fin_dst6 = nat->nat_inip6;

	if (nflags & IPN_TCPUDP)
		tcp = fin->fin_dp;

	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		if ((nat->nat_inport != 0) && (nflags & IPN_TCPUDP)) {
			tcp->th_dport = nat->nat_inport;
			fin->fin_data[1] = ntohs(nat->nat_inport);
		}


		if ((nat->nat_inport != 0) && (nflags & IPN_ICMPQUERY)) {
			icmp6 = fin->fin_dp;

			icmp6->icmp6_id = nat->nat_inport;
		}

		csump = nat_proto(fin, nat, nflags);
	}

	nat_update(fin, nat, np);

	/*
	 * In case they are being forwarded, inbound packets always need to have
	 * their checksum adjusted even if hardware checksum validation said OK.
	 */
	if (csump != NULL) {
		if (nat->nat_dir == NAT_OUTBOUND)
			fix_incksum(csump, nat->nat_sumd[0]);
		else
			fix_outcksum(csump, nat->nat_sumd[0]);
	}

#if SOLARIS && defined(_KERNEL)
	if (nflags & IPN_TCPUDP &&
	    NET_IS_HCK_L4_PART(net_data_p, fin->fin_m)) {
		/*
		 * Need to adjust the partial checksum result stored in
		 * db_cksum16, which will be used for validation in IP.
		 * See IP_CKSUM_RECV().
		 * Adjustment data should be the inverse of the IP address
		 * changes, because db_cksum16 is supposed to be the complement
		 * of the pesudo header.
		 */
		csump = &fin->fin_m->b_datap->db_cksum16;
		if (nat->nat_dir == NAT_OUTBOUND)
			fix_outcksum(csump, nat->nat_sumd[1]);
		else
			fix_incksum(csump, nat->nat_sumd[1]);
	}
#endif

	ATOMIC_INCL(ifs->ifs_nat_stats.ns_mapped[0]);
	fin->fin_flx |= FI_NATED;
	if (np != NULL && np->in_tag.ipt_num[0] != 0)
		fin->fin_nattag = &np->in_tag;
	return 1;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_icmpquerytype6                                          */
/* Returns:     int - 1 == success, 0 == failure                            */
/* Parameters:  icmptype(I) - ICMP type number                              */
/*                                                                          */
/* Tests to see if the ICMP type number passed is a query/response type or  */
/* not.                                                                     */
/* ------------------------------------------------------------------------ */
static INLINE int nat_icmpquerytype6(icmptype)
int icmptype;
{

	/*
	 * For the ICMP query NAT code, it is essential that both the query
	 * and the reply match on the NAT rule. Because the NAT structure
	 * does not keep track of the icmptype, and a single NAT structure
	 * is used for all icmp types with the same src, dest and id, we
	 * simply define the replies as queries as well. The funny thing is,
	 * altough it seems silly to call a reply a query, this is exactly
	 * as it is defined in the IPv4 specification
	 */

	switch (icmptype)
	{

	case ICMP6_ECHO_REPLY:
	case ICMP6_ECHO_REQUEST:
	/* route aedvertisement/solliciation is currently unsupported: */
	/* it would require rewriting the ICMP data section            */
	case ICMP6_MEMBERSHIP_QUERY:
	case ICMP6_MEMBERSHIP_REPORT:
	case ICMP6_MEMBERSHIP_REDUCTION:
	case ICMP6_WRUREQUEST:
	case ICMP6_WRUREPLY:
	case MLD6_MTRACE_RESP:
	case MLD6_MTRACE:
		return 1;
	default:
		return 0;
	}
}

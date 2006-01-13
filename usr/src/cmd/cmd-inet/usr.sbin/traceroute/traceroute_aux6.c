/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright (c) 1988, 1989, 1991, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * @(#)$Header: traceroute.c,v 1.49 97/06/13 02:30:23 leres Exp $ (LBL)
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <libintl.h>
#include <errno.h>
#include <netdb.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <libinetutil.h>
#include "traceroute.h"

int check_reply6(struct msghdr *, int, int, uchar_t *, uchar_t *);
void *find_ancillary_data(struct msghdr *, int, int);
extern char *inet_name(union any_in_addr *, int);
static int IPv6_hdrlen(ip6_t *, int, uint8_t *);
static char *pr_type6(uchar_t);
void print_addr6(uchar_t *, int, struct sockaddr *);
boolean_t print_icmp_other6(uchar_t, uchar_t);
void send_probe6(int, struct msghdr *, struct ip *, int, int,
    struct timeval *, int);
void set_ancillary_data(struct msghdr *, int, union any_in_addr *, int, uint_t);
struct ip *set_buffers6(int);
static boolean_t update_hoplimit_ancillary_data(struct msghdr *, int);

/*
 * prepares the buffer to be sent as an IP datagram
 */
struct ip *
set_buffers6(int plen)
{
	struct ip *outip;
	uchar_t *outp;
	struct udphdr *outudp;
	struct icmp *outicmp;
	int optlen = 0;

	outip = (struct ip *)malloc((size_t)plen);
	if (outip == NULL) {
		Fprintf(stderr, "%s: malloc: %s\n", prog, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (gw_count > 0) {
		/* ip6_rthdr0 structure includes one gateway address */
		optlen = sizeof (struct ip6_rthdr0) +
		    gw_count * sizeof (struct in6_addr);
	}

	(void) memset((char *)outip, 0, (size_t)plen);
	outp = (uchar_t *)(outip + 1);

	if (useicmp) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		outicmp = (struct icmp *)outp;
		outicmp->icmp_type = ICMP6_ECHO_REQUEST;
		outicmp->icmp_id = htons(ident);
	} else {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		outudp = (struct udphdr *)outp;
		/*
		 * "source port" is set at bind() call, so we don't do it
		 * again
		 */
		outudp->uh_ulen = htons((ushort_t)(plen -
		    (sizeof (struct ip6_hdr) + optlen)));
	}

	return (outip);
}

/*
 * Initialize the msghdr for specifying hoplimit, outgoing interface and routing
 * header for the probe packets.
 */
void
set_ancillary_data(struct msghdr *msgp, int hoplimit,
    union any_in_addr *gwIPlist, int gw_cnt, uint_t if_index)
{
	size_t hoplimit_space;
	size_t rthdr_space;
	size_t pktinfo_space;
	size_t bufspace;
	struct cmsghdr *cmsgp;
	uchar_t *cmsg_datap;
	int i;

	msgp->msg_control = NULL;
	msgp->msg_controllen = 0;

	/*
	 * Need to figure out size of buffer needed for ancillary data
	 * containing routing header and packet info options.
	 *
	 * Portable heuristic to compute upper bound on space needed for
	 * N ancillary data options. It assumes up to _MAX_ALIGNMENT padding
	 * after both header and data as the worst possible upper bound on space
	 * consumed by padding.
	 * It also adds one extra "sizeof (struct cmsghdr)" for the last option.
	 * This is needed because we would like to use CMSG_NXTHDR() while
	 * composing the buffer. The CMSG_NXTHDR() macro is designed better for
	 * parsing than composing the buffer. It requires the pointer it returns
	 * to leave space in buffer for addressing a cmsghdr and we want to make
	 * sure it works for us while we skip beyond the last ancillary data
	 * option.
	 *
	 * bufspace[i]  = sizeof(struct cmsghdr) + <pad after header> +
	 *		<option[i] content length> + <pad after data>;
	 *
	 * total_bufspace = bufspace[0] + bufspace[1] + ...
	 *		    ... + bufspace[N-1] + sizeof (struct cmsghdr);
	 */

	rthdr_space = 0;
	pktinfo_space = 0;
	/* We'll always set the hoplimit of the outgoing packets */
	hoplimit_space = sizeof (int);
	bufspace = sizeof (struct cmsghdr) + _MAX_ALIGNMENT +
	    hoplimit_space + _MAX_ALIGNMENT;

	if (gw_cnt > 0) {
		rthdr_space = inet6_rth_space(IPV6_RTHDR_TYPE_0, gw_cnt);
		bufspace += sizeof (struct cmsghdr) + _MAX_ALIGNMENT +
		    rthdr_space + _MAX_ALIGNMENT;
	}

	if (if_index != 0) {
		pktinfo_space = sizeof (struct in6_pktinfo);
		bufspace += sizeof (struct cmsghdr) + _MAX_ALIGNMENT +
		    pktinfo_space + _MAX_ALIGNMENT;
	}

	/*
	 * We need to temporarily set the msgp->msg_controllen to bufspace
	 * (we will later trim it to actual length used). This is needed because
	 * CMSG_NXTHDR() uses it to check we have not exceeded the bounds.
	 */
	bufspace += sizeof (struct cmsghdr);
	msgp->msg_controllen = bufspace;

	msgp->msg_control = (struct cmsghdr *)malloc(bufspace);
	if (msgp->msg_control == NULL) {
		Fprintf(stderr, "%s: malloc %s\n", prog, strerror(errno));
		exit(EXIT_FAILURE);
	}
	cmsgp = CMSG_FIRSTHDR(msgp);

	/*
	 * Fill ancillary data. First hoplimit, then rthdr and pktinfo if
	 * needed.
	 */

	/* set hoplimit ancillary data */
	cmsgp->cmsg_level = IPPROTO_IPV6;
	cmsgp->cmsg_type = IPV6_HOPLIMIT;
	cmsg_datap = CMSG_DATA(cmsgp);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	*(int *)cmsg_datap = hoplimit;
	cmsgp->cmsg_len = cmsg_datap + hoplimit_space - (uchar_t *)cmsgp;
	cmsgp = CMSG_NXTHDR(msgp, cmsgp);

	/* set rthdr ancillary data if needed */
	if (gw_cnt > 0) {
		struct ip6_rthdr0 *rthdr0p;

		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_RTHDR;
		cmsg_datap = CMSG_DATA(cmsgp);

		/*
		 * Initialize rthdr structure
		 */
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		rthdr0p = (struct ip6_rthdr0 *)cmsg_datap;
		if (inet6_rth_init(rthdr0p, rthdr_space,
		    IPV6_RTHDR_TYPE_0, gw_cnt) == NULL) {
			Fprintf(stderr, "%s: inet6_rth_init failed\n",
			    prog);
			exit(EXIT_FAILURE);
		}

		/*
		 * Stuff in gateway addresses
		 */
		for (i = 0; i < gw_cnt; i++) {
			if (inet6_rth_add(rthdr0p,
			    &gwIPlist[i].addr6) == -1) {
				Fprintf(stderr,
				    "%s: inet6_rth_add\n", prog);
				exit(EXIT_FAILURE);
			}
		}

		cmsgp->cmsg_len = cmsg_datap + rthdr_space - (uchar_t *)cmsgp;
		cmsgp = CMSG_NXTHDR(msgp, cmsgp);
	}

	/* set pktinfo ancillary data if needed */
	if (if_index != 0) {
		struct in6_pktinfo *pktinfop;

		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_PKTINFO;
		cmsg_datap = CMSG_DATA(cmsgp);

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		pktinfop = (struct in6_pktinfo *)cmsg_datap;
		/*
		 * We don't know if pktinfop->ipi6_addr is aligned properly,
		 * therefore let's use bcopy, instead of assignment.
		 */
		(void) bcopy(&in6addr_any, &pktinfop->ipi6_addr,
		sizeof (struct in6_addr));

		/*
		 *  We can assume pktinfop->ipi6_ifindex is 32 bit aligned.
		 */
		pktinfop->ipi6_ifindex = if_index;
		cmsgp->cmsg_len = cmsg_datap + pktinfo_space - (uchar_t *)cmsgp;
		cmsgp = CMSG_NXTHDR(msgp, cmsgp);
	}

	msgp->msg_controllen = (char *)cmsgp - (char *)msgp->msg_control;
}

/*
 * Parses the given msg->msg_control to find the IPV6_HOPLIMIT ancillary data
 * and update the hoplimit.
 * Returns _B_FALSE if it can't find IPV6_HOPLIMIT ancillary data, _B_TRUE
 * otherwise.
 */
static boolean_t
update_hoplimit_ancillary_data(struct msghdr *msg, int hoplimit)
{
	struct cmsghdr *cmsg;
	int *intp;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_HOPLIMIT) {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			intp = (int *)(CMSG_DATA(cmsg));
			*intp = hoplimit;
			return (_B_TRUE);
		}
	}

	return (_B_FALSE);
}

/*
 * send a probe packet to the destination
 */
void
send_probe6(int sndsock, struct msghdr *msg6, struct ip *outip, int seq,
    int ttl, struct timeval *tp, int packlen)
{
	uchar_t *outp;
	struct icmp *outicmp;
	struct outdata *outdata;
	struct iovec iov;
	int cc;
	int optlen = 0;
	int send_size;
	struct sockaddr_in6 *to6;

	if (gw_count > 0) {
		/* ip6_rthdr0 structure includes one gateway address */
		optlen = sizeof (struct ip6_rthdr0) +
		    gw_count * sizeof (struct in6_addr);
	}

	send_size = packlen - sizeof (struct ip6_hdr) - optlen;

	/* if using UDP, further discount UDP header size */
	if (!useicmp)
		send_size -= sizeof (struct udphdr);

	/* initialize buffer pointers */
	outp = (uchar_t *)(outip + 1);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	outicmp = (struct icmp *)outp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	outdata = (struct outdata *)(outp + ICMP6_MINLEN);

	if (!update_hoplimit_ancillary_data(msg6, ttl)) {
		Fprintf(stderr,
		    "%s: can't find IPV6_HOPLIMIT ancillary data\n", prog);
		exit(EXIT_FAILURE);
	}

	/* Payload */
	outdata->seq = seq;
	outdata->ttl = ttl;
	outdata->tv = *tp;

	if (useicmp) {
		outicmp->icmp_seq = htons(seq);
	} else {
		to6 = (struct sockaddr_in6 *)msg6->msg_name;
		to6->sin6_port =  htons((port + seq) % (MAX_PORT + 1));
	}

	iov.iov_base = outp;
	iov.iov_len = send_size;

	msg6->msg_iov = &iov;
	msg6->msg_iovlen = 1;

	cc = sendmsg(sndsock, msg6, 0);

	if (cc < 0 || cc != send_size)  {
		if (cc < 0) {
			Fprintf(stderr, "%s: sendmsg: %s\n", prog,
			    strerror(errno));
		}
		Printf("%s: wrote %s %d chars, ret=%d\n",
		    prog, hostname, send_size, cc);
		(void) fflush(stdout);
	}
}

/*
 * Return a pointer to the ancillary data for the given cmsg_level and
 * cmsg_type.
 * If not found return NULL.
 */
void *
find_ancillary_data(struct msghdr *msg, int cmsg_level, int cmsg_type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == cmsg_level &&
		    cmsg->cmsg_type == cmsg_type) {
			return (CMSG_DATA(cmsg));
		}
	}
	return (NULL);
}

/*
 * Check out the reply packet to see if it's what we were expecting.
 * Returns REPLY_GOT_TARGET if the reply comes from the target
 *         REPLY_GOT_GATEWAY if an intermediate gateway sends TIME_EXCEEDED
 *         REPLY_GOT_OTHER for other kinds of unreachables indicating none of
 *	   the above two cases
 *
 * It also sets the icmp type and icmp code values
 */
int
check_reply6(struct msghdr *msg, int cc, int seq, uchar_t *type, uchar_t *code)
{
	uchar_t *buf = msg->msg_iov->iov_base;
	struct sockaddr_in6 *from_in6 = (struct sockaddr_in6 *)msg->msg_name;
	icmp6_t *icp6;
	ulong_t ip6hdr_len;
	uint8_t last_hdr;
	int save_cc = cc;
	char temp_buf[INET6_ADDRSTRLEN];	/* use for inet_ntop() */

	/* Ignore packets > 64k or control buffers that don't fit */
	if (msg->msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
		if (verbose) {
			Printf("Truncated message: msg_flags 0x%x from %s\n",
			    msg->msg_flags,
			    inet_ntop(AF_INET6,
			    (void *)&(from_in6->sin6_addr),
			    temp_buf, sizeof (temp_buf)));
		}
		return (REPLY_SHORT_PKT);
	}
	if (cc < ICMP6_MINLEN) {
		if (verbose) {
			Printf("packet too short (%d bytes) from %s\n",
			    cc,
			    inet_ntop(AF_INET6,
			    (void *)&(from_in6->sin6_addr),
			    temp_buf, sizeof (temp_buf)));
		}
		return (REPLY_SHORT_PKT);
	}
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	icp6 = (icmp6_t *)buf;
	*type = icp6->icmp6_type;
	*code = icp6->icmp6_code;

	/*
	 * traceroute interprets only ICMP6_TIME_EXCEED_TRANSIT,
	 * ICMP6_DST_UNREACH, ICMP6_ECHO_REPLY, ICMP6_PACKET_TOO_BIG and
	 * ICMP6_PARAMPROB_NEXTHEADER, ignores others
	 */
	if ((*type == ICMP6_TIME_EXCEEDED &&
	    *code == ICMP6_TIME_EXCEED_TRANSIT) ||
	    *type == ICMP6_DST_UNREACH || *type == ICMP6_ECHO_REPLY ||
	    *type == ICMP6_PACKET_TOO_BIG ||
	    (*type == ICMP6_PARAM_PROB &&
	    *code == ICMP6_PARAMPROB_NEXTHEADER)) {
		ip6_t *hip6;
		struct udphdr *up;
		icmp6_t *hicmp6;

		cc -= ICMP6_MINLEN;
		hip6 = (ip6_t *)&(icp6->icmp6_data32[1]);
		last_hdr = hip6->ip6_nxt;
		ip6hdr_len = IPv6_hdrlen(hip6, cc, &last_hdr);

		cc -= ip6hdr_len;
		if (useicmp) {
			if (*type == ICMP6_ECHO_REPLY &&
			    icp6->icmp6_id == htons(ident) &&
			    icp6->icmp6_seq == htons(seq)) {
				return (REPLY_GOT_TARGET);
			}

			/* LINTED E_BAD_PTR_CAST_ALIGN */
			hicmp6 = (icmp6_t *)((uchar_t *)hip6 + ip6hdr_len);

			if (ICMP6_MINLEN <= cc &&
			    last_hdr == IPPROTO_ICMPV6 &&
			    hicmp6->icmp6_id == htons(ident) &&
			    hicmp6->icmp6_seq == htons(seq)) {
				if (*type == ICMP6_TIME_EXCEEDED) {
					return (REPLY_GOT_GATEWAY);
				} else {
					return (REPLY_GOT_OTHER);
				}
			}
		} else {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			up = (struct udphdr *)((uchar_t *)hip6 + ip6hdr_len);
			/*
			 * at least 4 bytes of UDP header is required for this
			 * check
			 */
			if (4 <= cc &&
			    last_hdr == IPPROTO_UDP &&
			    up->uh_sport == htons(ident) &&
			    up->uh_dport == htons((port + seq) %
			    (MAX_PORT + 1))) {
				if (*type == ICMP6_DST_UNREACH &&
				    *code == ICMP6_DST_UNREACH_NOPORT) {
					return (REPLY_GOT_TARGET);
				} else if (*type == ICMP6_TIME_EXCEEDED) {
					return (REPLY_GOT_GATEWAY);
				} else {
					return (REPLY_GOT_OTHER);
				}
			}
		}
	}

	if (verbose) {
		int i, j;
		uchar_t *lp = (uchar_t *)icp6;
		struct in6_addr *dst;
		struct in6_pktinfo *pkti;

		pkti = (struct in6_pktinfo *)find_ancillary_data(msg,
		    IPPROTO_IPV6, IPV6_PKTINFO);
		if (pkti == NULL) {
			Fprintf(stderr,
			    "%s: can't find IPV6_PKTINFO ancillary data\n",
			    prog);
			exit(EXIT_FAILURE);
		}
		dst = &pkti->ipi6_addr;
		cc = save_cc;
		Printf("\n%d bytes from %s to ", cc,
		    inet_ntop(AF_INET6, (const void *)&(from_in6->sin6_addr),
			temp_buf, sizeof (temp_buf)));
		Printf("%s: icmp type %d (%s) code %d\n",
		    inet_ntop(AF_INET6, (const void *)dst,
			temp_buf, sizeof (temp_buf)),
		    *type, pr_type6(*type), *code);
		for (i = 0; i < cc; i += 4) {
			Printf("%2d: x", i);
			for (j = 0; ((j < 4) && ((i + j) < cc)); j++)
				Printf("%2.2x", *lp++);
			(void) putchar('\n');
		}
	}

	return (REPLY_SHORT_PKT);
}

/*
 * Return the length of the IPv6 related headers (including extension headers)
 */
static int
IPv6_hdrlen(ip6_t *ip6h, int pkt_len, uint8_t *last_hdr_rtrn)
{
	int length;
	int exthdrlength;
	uint8_t nexthdr;
	uint8_t *whereptr;
	ip6_hbh_t *hbhhdr;
	ip6_dest_t *desthdr;
	ip6_rthdr_t *rthdr;
	ip6_frag_t *fraghdr;
	uint8_t	*endptr;

	length = sizeof (ip6_t);

	whereptr = ((uint8_t *)&ip6h[1]); 	/* point to next hdr */
	endptr = ((uint8_t *)ip6h) + pkt_len;

	nexthdr = ip6h->ip6_nxt;
	*last_hdr_rtrn = IPPROTO_NONE;

	if (whereptr >= endptr)
		return (length);

	while (whereptr < endptr) {
		*last_hdr_rtrn = nexthdr;
		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
			hbhhdr = (ip6_hbh_t *)whereptr;
			exthdrlength = 8 * (hbhhdr->ip6h_len + 1);
			if ((uchar_t *)hbhhdr + exthdrlength > endptr)
				return (length);
			nexthdr = hbhhdr->ip6h_nxt;
			length += exthdrlength;
			break;

		case IPPROTO_DSTOPTS:
			desthdr = (ip6_dest_t *)whereptr;
			exthdrlength = 8 * (desthdr->ip6d_len + 1);
			if ((uchar_t *)desthdr + exthdrlength > endptr)
				return (length);
			nexthdr = desthdr->ip6d_nxt;
			length += exthdrlength;
			break;

		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr_t *)whereptr;
			exthdrlength = 8 * (rthdr->ip6r_len + 1);
			if ((uchar_t *)rthdr + exthdrlength > endptr)
				return (length);
			nexthdr = rthdr->ip6r_nxt;
			length += exthdrlength;
			break;

		case IPPROTO_FRAGMENT:
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			fraghdr = (ip6_frag_t *)whereptr;
			if ((uchar_t *)&fraghdr[1] > endptr)
				return (length);
			nexthdr = fraghdr->ip6f_nxt;
			length += sizeof (struct ip6_frag);
			break;

		case IPPROTO_NONE:
		default:
			return (length);
		}
		whereptr = (uint8_t *)ip6h + length;
	}
	*last_hdr_rtrn = nexthdr;

	return (length);
}

/*
 * convert an ICMP6 "type" field to a printable string.
 */
static char *
pr_type6(uchar_t type)
{
	static struct icmptype_table ttab6[] = {
		{ICMP6_DST_UNREACH,		"Dest Unreachable"},
		{ICMP6_PACKET_TOO_BIG,		"Packet Too Big"},
		{ICMP6_TIME_EXCEEDED,		"Time Exceeded"},
		{ICMP6_PARAM_PROB,		"Param Problem"},
		{ICMP6_ECHO_REQUEST,		"Echo Request"},
		{ICMP6_ECHO_REPLY,		"Echo Reply"},
		{MLD_LISTENER_QUERY,		"Multicast Listener Query"},
		{MLD_LISTENER_REPORT,		"Multicast Listener Report"},
		{MLD_LISTENER_REDUCTION,	"Multicast Listener Done"},
		{ND_ROUTER_SOLICIT,		"Router Solicitation"},
		{ND_ROUTER_ADVERT,		"Router Advertisement"},
		{ND_NEIGHBOR_SOLICIT,		"Neighbor Solicitation"},
		{ND_NEIGHBOR_ADVERT,		"Neighbor Advertisement"},
		{ND_REDIRECT,			"Redirect Message"}
	};
	int i = 0;

	for (i = 0; i < A_CNT(ttab6); i++) {
		if (ttab6[i].type == type)
			return (ttab6[i].message);
	}

	return ("OUT-OF-RANGE");
}


/*
 * print the IPv6 src address of the reply packet
 */
void
print_addr6(uchar_t *buf, int cc, struct sockaddr *from)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in6 *from_in6 = (struct sockaddr_in6 *)from;
	ip6_t *ip;
	union any_in_addr ip_addr;
	char *resolved_name;
	char temp_buf[INET6_ADDRSTRLEN];	/* use for inet_ntop() */

	ip_addr.addr6 = from_in6->sin6_addr;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ip = (ip6_t *)buf;

	(void) inet_ntop(AF_INET6, &(from_in6->sin6_addr), temp_buf,
	    sizeof (temp_buf));
	if (!nflag)
		resolved_name = inet_name(&ip_addr, AF_INET6);
	/*
	 * If the IPv6 address cannot be resolved to hostname, inet_name()
	 * returns the IPv6 address as a string. In that case, we choose not
	 * to print it twice. This saves us space on display.
	 */
	if (nflag || (strcmp(temp_buf, resolved_name) == 0))
		Printf(" %s", temp_buf);
	else
		Printf(" %s (%s)", resolved_name, temp_buf);

	if (verbose) {
		Printf(" %d bytes to %s", cc, inet_ntop(AF_INET6,
		    (const void *) &(ip->ip6_dst), temp_buf,
		    sizeof (temp_buf)));
	}
}

/*
 * ICMP6 messages which doesn't mean we got the target, or we got a gateway, are
 * processed here. It returns _B_TRUE if it's some sort of 'unreachable'.
 */
boolean_t
print_icmp_other6(uchar_t type, uchar_t code)
{
	boolean_t unreach = _B_FALSE;

	switch (type) {

	/* this corresponds to "ICMP_UNREACH_NEEDFRAG" in ICMP */
	case ICMP6_PACKET_TOO_BIG:
		unreach = _B_TRUE;
		Printf(" !B");
		break;

	case ICMP6_PARAM_PROB:
		/* this corresponds to "ICMP_UNREACH_PROTOCOL" in ICMP */
		if (code == ICMP6_PARAMPROB_NEXTHEADER) {
			unreach = _B_TRUE;
			Printf(" !R");
		}
		break;

	case ICMP6_DST_UNREACH:
		switch (code) {
		case ICMP6_DST_UNREACH_NOPORT:
			break;

		case ICMP6_DST_UNREACH_NOROUTE:
			unreach = _B_TRUE;
			Printf(" !H");
			break;

		case ICMP6_DST_UNREACH_ADMIN:
			unreach = _B_TRUE;
			Printf(" !X");
			break;

		case ICMP6_DST_UNREACH_ADDR:
			unreach = _B_TRUE;
			Printf(" !A");
			break;

		case ICMP6_DST_UNREACH_NOTNEIGHBOR:
			unreach = _B_TRUE;
			Printf(" !E");
			break;

		default:
			unreach = _B_TRUE;
			Printf(" !<%d>", code);
			break;
		}
		break;
	default:
		break;
	}

	return (unreach);
}

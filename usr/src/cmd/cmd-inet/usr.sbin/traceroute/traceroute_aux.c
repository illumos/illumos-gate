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

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <libinetutil.h>
#include "traceroute.h"

/*
 * IPv4 source routing option.
 * In order to avoid padding for the alignment of IPv4 addresses, ipsr_addrs
 * is defined as a 2-D array of uint8_t, instead of 1-D array of struct in_addr.
 */
struct ip_sourceroute {
	uint8_t ipsr_code;
	uint8_t ipsr_len;
	uint8_t ipsr_ptr;
	/* up to 9 IPv4 addresses */
	uint8_t ipsr_addrs[1][sizeof (struct in_addr)];
};

int check_reply(struct msghdr *, int, int, uchar_t *, uchar_t *);
extern ushort_t in_cksum(ushort_t *, int);
extern char *inet_name(union any_in_addr *, int);
static char *pr_type(uchar_t);
void print_addr(uchar_t *, int, struct sockaddr *);
boolean_t print_icmp_other(uchar_t, uchar_t);
void send_probe(int, struct sockaddr *, struct ip *, int, int,
    struct timeval *, int);
struct ip *set_buffers(int);
void set_IPv4opt_sourcerouting(int, union any_in_addr *, union any_in_addr *);

/*
 * prepares the buffer to be sent as an IP datagram
 */
struct ip *
set_buffers(int plen)
{
	struct ip *outip;
	uchar_t *outp;		/* packet following the IP header (UDP/ICMP) */
	struct udphdr *outudp;
	struct icmp *outicmp;
	int optlen = 0;

	outip = (struct ip *)malloc((size_t)plen);
	if (outip == NULL) {
		Fprintf(stderr, "%s: malloc: %s\n", prog, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (gw_count > 0) {
		/* 8 = 5 (NO OPs) + 3 (code, len, ptr) */
		optlen = 8 + gw_count * sizeof (struct in_addr);
	}

	(void) memset((char *)outip, 0, (size_t)plen);
	outp = (uchar_t *)(outip + 1);

	outip->ip_v = IPVERSION;
	if (settos)
		outip->ip_tos = tos;

	/*
	 * LBNL bug fixed: missing '- optlen' before, causing optlen
	 * added twice
	 *
	 * BSD bug: BSD touches the header fields 'len' and 'ip_off'
	 * even when HDRINCL is set. It applies htons() on these
	 * fields. It should send the header untouched when HDRINCL
	 * is set.
	 */
	outip->ip_len = htons(plen - optlen);
	outip->ip_off = htons(off);
	outip->ip_hl = (outp - (uchar_t *)outip) >> 2;

	/* setup ICMP or UDP */
	if (useicmp) {
		outip->ip_p = IPPROTO_ICMP;

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		outicmp = (struct icmp *)outp;
		outicmp->icmp_type = ICMP_ECHO;
		outicmp->icmp_id = htons(ident);
	} else {
		outip->ip_p = IPPROTO_UDP;

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		outudp = (struct udphdr *)outp;
		outudp->uh_sport = htons(ident);
		outudp->uh_ulen =
		    htons((ushort_t)(plen - (sizeof (struct ip) + optlen)));
	}

	return (outip);
}

/*
 * Setup the source routing for IPv4.
 */
void
set_IPv4opt_sourcerouting(int sndsock, union any_in_addr *ip_addr,
    union any_in_addr *gwIPlist)
{
	struct protoent *pe;
	struct ip_sourceroute *srp;
	uchar_t optlist[MAX_IPOPTLEN];
	int i;
	int gwV4_count;

	if ((pe = getprotobyname("ip")) == NULL) {
		Fprintf(stderr, "%s: unknown protocol ip\n", prog);
		exit(EXIT_FAILURE);
	}

	gwV4_count = (gw_count < MAX_GWS) ? gw_count : MAX_GWS - 1;
	/* final hop */
	gwIPlist[gwV4_count].addr = ip_addr->addr;

	/*
	 * the option length passed to setsockopt() needs to be a multiple of
	 * 32 bits. Therefore we need to use a 1-byte padding (source routing
	 * information takes 4x+3 bytes).
	 */
	optlist[0] = IPOPT_NOP;

	srp = (struct ip_sourceroute *)&optlist[1];
	srp->ipsr_code = IPOPT_LSRR;
	/* 3 = 1 (code) + 1 (len) + 1 (ptr) */
	srp->ipsr_len = 3 + (gwV4_count + 1) * sizeof (gwIPlist[0].addr);
	srp->ipsr_ptr = IPOPT_MINOFF;

	for (i = 0; i <= gwV4_count; i++) {
		(void) bcopy((char *)&gwIPlist[i].addr, &srp->ipsr_addrs[i],
		    sizeof (struct in_addr));
	}

	if (setsockopt(sndsock, pe->p_proto, IP_OPTIONS, (const char *)optlist,
	    srp->ipsr_len + 1) < 0) {
		Fprintf(stderr, "%s: IP_OPTIONS: %s\n", prog, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/*
 * send a probe packet to the destination
 */
void
send_probe(int sndsock, struct sockaddr *to, struct ip *outip,
    int seq, int ttl, struct timeval *tp, int packlen)
{
	int cc;
	struct udpiphdr *ui;
	uchar_t *outp;		/* packet following the IP header (UDP/ICMP) */
	struct udphdr *outudp;
	struct icmp *outicmp;
	struct outdata *outdata;
	struct ip tip;
	int optlen = 0;
	int send_size;

	/* initialize buffer pointers */
	outp = (uchar_t *)(outip + 1);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	outudp =  (struct udphdr *)outp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	outicmp = (struct icmp *)outp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	outdata = (struct outdata *)(outp + ICMP_MINLEN);

	if (gw_count > 0) {
		/* 8 = 5 (NO OPs) + 3 (code, len, ptr) */
		optlen = 8 + gw_count * sizeof (struct in_addr);
	}

	if (raw_req) {
		send_size = packlen - optlen;
	} else if (useicmp) {
		send_size = packlen - optlen - sizeof (struct ip);
	} else {
		send_size = packlen - optlen - sizeof (struct ip) -
		    sizeof (struct udphdr);
	}

	outip->ip_ttl = ttl;
	outip->ip_id = htons(ident + seq);

	/*
	 * If a raw IPv4 packet is going to be sent, the Time to Live
	 * field in the packet was initialized above.  Otherwise, it is
	 * initialized here using the IPPROTO_IP level socket option.
	 */
	if (!raw_req) {
		if (setsockopt(sndsock, IPPROTO_IP, IP_TTL, (char *)&ttl,
		    sizeof (ttl)) < 0) {
			Fprintf(stderr, "%s: IP_TTL: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * In most cases, the kernel will recalculate the ip checksum.
	 * But we must do it anyway so that the udp checksum comes out
	 * right.
	 */
	if (docksum) {
		outip->ip_sum =
		    in_cksum((ushort_t *)outip, sizeof (*outip) + optlen);
		if (outip->ip_sum == 0)
			outip->ip_sum = 0xffff;
	}

	/* Payload */
	outdata->seq = seq;
	outdata->ttl = ttl;
	outdata->tv = *tp;

	if (useicmp) {
		outicmp->icmp_seq = htons(seq);
	} else {
		outudp->uh_dport  = htons((port + seq) % (MAX_PORT + 1));
	}

	if (!raw_req)
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		((struct sockaddr_in *)to)->sin_port = outudp->uh_dport;

	/* (We can only do the checksum if we know our ip address) */
	if (docksum) {
		if (useicmp) {
			outicmp->icmp_cksum = 0;
			outicmp->icmp_cksum = in_cksum((ushort_t *)outicmp,
			    packlen - (sizeof (struct ip) + optlen));
			if (outicmp->icmp_cksum == 0)
				outicmp->icmp_cksum = 0xffff;
		} else {
			/* Checksum (must save and restore ip header) */
			tip = *outip;
			ui = (struct udpiphdr *)outip;
			ui->ui_next = 0;
			ui->ui_prev = 0;
			ui->ui_x1 = 0;
			ui->ui_len = outudp->uh_ulen;
			outudp->uh_sum = 0;
			outudp->uh_sum = in_cksum((ushort_t *)ui, packlen);
			if (outudp->uh_sum == 0)
				outudp->uh_sum = 0xffff;
			*outip = tip;
		}
	}

	if (raw_req) {
		cc = sendto(sndsock, (char *)outip, send_size, 0, to,
		    sizeof (struct sockaddr_in));
	} else if (useicmp) {
		cc = sendto(sndsock, (char *)outicmp, send_size, 0, to,
		    sizeof (struct sockaddr_in));
	} else {
		cc = sendto(sndsock, (char *)outp, send_size, 0, to,
		    sizeof (struct sockaddr_in));
	}

	if (cc < 0 || cc != send_size)  {
		if (cc < 0) {
			Fprintf(stderr, "%s: sendto: %s\n", prog,
			    strerror(errno));
		}
		Printf("%s: wrote %s %d chars, ret=%d\n",
		    prog, hostname, send_size, cc);
		(void) fflush(stdout);
	}
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
check_reply(struct msghdr *msg, int cc, int seq, uchar_t *type, uchar_t *code)
{
	uchar_t *buf = msg->msg_iov->iov_base;
	struct sockaddr_in *from_in = (struct sockaddr_in *)msg->msg_name;
	struct icmp *icp;
	int hlen;
	int save_cc = cc;
	struct ip *ip;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ip = (struct ip *)buf;
	hlen = ip->ip_hl << 2;
	if (cc < hlen + ICMP_MINLEN) {
		if (verbose) {
			Printf("packet too short (%d bytes) from %s\n",
			    cc, inet_ntoa(from_in->sin_addr));
		}
		return (REPLY_SHORT_PKT);
	}
	cc -= hlen;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	icp = (struct icmp *)(buf + hlen);

	*type = icp->icmp_type;
	*code = icp->icmp_code;

	/*
	 * traceroute interpretes only ICMP_TIMXCEED_INTRANS, ICMP_UNREACH and
	 * ICMP_ECHOREPLY, ignores others
	 */
	if ((*type == ICMP_TIMXCEED && *code == ICMP_TIMXCEED_INTRANS) ||
	    *type == ICMP_UNREACH || *type == ICMP_ECHOREPLY) {
		struct ip *hip;
		struct udphdr *up;
		struct icmp *hicmp;

		cc -= ICMP_MINLEN;
		hip = &icp->icmp_ip;
		hlen = hip->ip_hl << 2;
		cc -= hlen;
		if (useicmp) {
			if (*type == ICMP_ECHOREPLY &&
			    icp->icmp_id == htons(ident) &&
			    icp->icmp_seq == htons(seq))
				return (REPLY_GOT_TARGET);

			/* LINTED E_BAD_PTR_CAST_ALIGN */
			hicmp = (struct icmp *)((uchar_t *)hip + hlen);

			if (ICMP_MINLEN <= cc &&
			    hip->ip_p == IPPROTO_ICMP &&
			    hicmp->icmp_id == htons(ident) &&
			    hicmp->icmp_seq == htons(seq)) {
				return ((*type == ICMP_TIMXCEED) ?
				    REPLY_GOT_GATEWAY : REPLY_GOT_OTHER);
			}
		} else {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			up = (struct udphdr *)((uchar_t *)hip + hlen);
			/*
			 * at least 4 bytes of UDP header is required for this
			 * check
			 */
			if (4 <= cc &&
			    hip->ip_p == IPPROTO_UDP &&
			    up->uh_sport == htons(ident) &&
			    up->uh_dport == htons((port + seq) %
				(MAX_PORT + 1))) {
				if (*type == ICMP_UNREACH &&
				    *code == ICMP_UNREACH_PORT) {
					return (REPLY_GOT_TARGET);
				} else if (*type == ICMP_TIMXCEED) {
					return (REPLY_GOT_GATEWAY);
				} else {
					return (REPLY_GOT_OTHER);
				}
			}
		}
	}

	if (verbose) {
		int i, j;
		uchar_t *lp = (uchar_t *)ip;

		cc = save_cc;
		Printf("\n%d bytes from %s to ", cc,
		    inet_ntoa(from_in->sin_addr));
		Printf("%s: icmp type %d (%s) code %d\n",
		    inet_ntoa(ip->ip_dst), *type, pr_type(*type), *code);
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
 * convert an ICMP "type" field to a printable string.
 */
static char *
pr_type(uchar_t type)
{
	static struct icmptype_table ttab[] = {
		{ICMP_ECHOREPLY,	"Echo Reply"},
		{1,			"ICMP 1"},
		{2,			"ICMP 2"},
		{ICMP_UNREACH,		"Dest Unreachable"},
		{ICMP_SOURCEQUENCH,	"Source Quench"},
		{ICMP_REDIRECT,		"Redirect"},
		{6,			"ICMP 6"},
		{7,			"ICMP 7"},
		{ICMP_ECHO,		"Echo"},
		{ICMP_ROUTERADVERT,	"Router Advertisement"},
		{ICMP_ROUTERSOLICIT,	"Router Solicitation"},
		{ICMP_TIMXCEED,		"Time Exceeded"},
		{ICMP_PARAMPROB,	"Param Problem"},
		{ICMP_TSTAMP,		"Timestamp"},
		{ICMP_TSTAMPREPLY,	"Timestamp Reply"},
		{ICMP_IREQ,		"Info Request"},
		{ICMP_IREQREPLY,	"Info Reply"},
		{ICMP_MASKREQ,		"Netmask Request"},
		{ICMP_MASKREPLY,	"Netmask Reply"}
	};
	int i = 0;

	for (i = 0; i < A_CNT(ttab); i++) {
		if (ttab[i].type == type)
			return (ttab[i].message);
	}

	return ("OUT-OF-RANGE");
}

/*
 * print the IPv4 src address of the reply packet
 */
void
print_addr(uchar_t *buf, int cc, struct sockaddr *from)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in *from_in = (struct sockaddr_in *)from;
	struct ip *ip;
	union any_in_addr ip_addr;

	ip_addr.addr = from_in->sin_addr;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ip = (struct ip *)buf;

	if (nflag) {
		Printf(" %s", inet_ntoa(from_in->sin_addr));
	} else {
		Printf(" %s (%s)", inet_name(&ip_addr, AF_INET),
		    inet_ntoa(from_in->sin_addr));
	}

	if (verbose)
		Printf(" %d bytes to %s", cc, inet_ntoa(ip->ip_dst));
}

/*
 * ICMP messages which doesn't mean we got the target, or we got a gateway, are
 * processed here. It returns _B_TRUE if it's some sort of 'unreachable'.
 */
boolean_t
print_icmp_other(uchar_t type, uchar_t code)
{
	boolean_t unreach = _B_FALSE;

	/*
	 * this function only prints '!*' for ICMP unreachable messages,
	 * ignores others.
	 */
	if (type != ICMP_UNREACH) {
		return (_B_FALSE);
	}

	switch (code) {
	case ICMP_UNREACH_PORT:
		break;

	case ICMP_UNREACH_NET_UNKNOWN:
	case ICMP_UNREACH_NET:
		unreach = _B_TRUE;
		Printf(" !N");
		break;

	case ICMP_UNREACH_HOST_UNKNOWN:
	case ICMP_UNREACH_HOST:
		unreach = _B_TRUE;
		Printf(" !H");
		break;

	case ICMP_UNREACH_PROTOCOL:
		Printf(" !P");
		break;

	case ICMP_UNREACH_NEEDFRAG:
		unreach = _B_TRUE;
		Printf(" !F");
		break;

	case ICMP_UNREACH_SRCFAIL:
		unreach = _B_TRUE;
		Printf(" !S");
		break;

	case ICMP_UNREACH_FILTER_PROHIB:
	case ICMP_UNREACH_NET_PROHIB:
	case ICMP_UNREACH_HOST_PROHIB:
		unreach = _B_TRUE;
		Printf(" !X");
		break;

	case ICMP_UNREACH_TOSNET:
	case ICMP_UNREACH_TOSHOST:
		unreach = _B_TRUE;
		Printf(" !T");
		break;

	case ICMP_UNREACH_ISOLATED:
	case ICMP_UNREACH_HOST_PRECEDENCE:
	case ICMP_UNREACH_PRECEDENCE_CUTOFF:
		unreach = _B_TRUE;
		Printf(" !U");
		break;

	default:
		unreach = _B_TRUE;
		Printf(" !<%d>", code);
		break;
	}

	return (unreach);
}

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <inet/ip6.h>
#include <inet/ipsecah.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "snoop.h"


/*
 * IPv6 extension header masks.  These are used by the print_ipv6_extensions()
 * function to return information to the caller about which extension headers
 * were processed.  This can be useful if the caller wants to know if the
 * packet is an IPv6 fragment, for example.
 */
#define	SNOOP_HOPOPTS	0x01U
#define	SNOOP_ROUTING	0x02U
#define	SNOOP_DSTOPTS	0x04U
#define	SNOOP_FRAGMENT	0x08U
#define	SNOOP_AH	0x10U
#define	SNOOP_ESP	0x20U
#define	SNOOP_IPV6	0x40U

extern char *dlc_header;

static void prt_routing_hdr();
static void prt_fragment_hdr();
static void prt_hbh_options();
static void prt_dest_options();
static void print_route();
static void print_ipoptions();
char *getproto();

/* Keep track of how many nested IP headers we have. */
unsigned int encap_levels;
unsigned int total_encap_levels = 1;

int
interpret_ip(flags, ip, fraglen)
	int flags;
	struct ip *ip;
	int fraglen;
{
	char *data;
	char buff[24];
	boolean_t isfrag = B_FALSE;
	boolean_t morefrag;
	uint16_t fragoffset;
	int hdrlen;
	uint16_t iplen, uitmp;
	extern char *src_name, *dst_name;

	if (ip->ip_v == IPV6_VERSION) {
		iplen = interpret_ipv6(flags, (ip6_t *)ip, fraglen);
		return (iplen);
	}

	/* XXX Should this count for mix-and-match v4/v6 encapsulations? */
	if (encap_levels == 0)
		total_encap_levels = 0;
	encap_levels++;
	total_encap_levels++;

	hdrlen = ip->ip_hl * 4;
	data = ((char *)ip) + hdrlen;
	iplen = ntohs(ip->ip_len) - hdrlen;
	fraglen -= hdrlen;
	if (fraglen > iplen)
		fraglen = iplen;
	if (fraglen < 0) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "IP truncated: header missing %d bytes", -fraglen);
		encap_levels--;
		return (fraglen + iplen);
	}
	/*
	 * We flag this as a fragment if the more fragments bit is set, or
	 * if the fragment offset is non-zero.
	 */
	morefrag = (ntohs(ip->ip_off) & IP_MF) == 0 ? B_FALSE : B_TRUE;
	fragoffset = (ntohs(ip->ip_off) & 0x1FFF) * 8;
	if (morefrag || fragoffset != 0)
		isfrag = B_TRUE;

	if (encap_levels == 1) {
		src_name = addrtoname(AF_INET, &ip->ip_src);
		dst_name = addrtoname(AF_INET, &ip->ip_dst);
	} /* Else we already have the src_name and dst_name we want! */

	if (flags & F_SUM) {
		if (isfrag) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "%s IP fragment ID=%d Offset=%-4d MF=%d TOS=0x%x "
			    "TTL=%d",
			    getproto(ip->ip_p),
			    ntohs(ip->ip_id),
			    fragoffset,
			    morefrag,
			    ip->ip_tos,
			    ip->ip_ttl);
		} else {
			(void) strlcpy(buff, inet_ntoa(ip->ip_dst),
			    sizeof (buff));
			uitmp = ntohs(ip->ip_len);
			(void) snprintf(get_sum_line(), MAXLINE,
			    "IP  D=%s S=%s LEN=%u%s, ID=%d, TOS=0x%x, TTL=%d",
			    buff,
			    inet_ntoa(ip->ip_src),
			    uitmp,
			    iplen > fraglen ? "?" : "",
			    ntohs(ip->ip_id),
			    ip->ip_tos,
			    ip->ip_ttl);
		}
	}

	if (flags & F_DTAIL) {
		show_header("IP:   ", "IP Header", iplen);
		show_space();
		(void) snprintf(get_line((char *)ip - dlc_header, 1),
		    get_line_remain(), "Version = %d", ip->ip_v);
		(void) snprintf(get_line((char *)ip - dlc_header, 1),
		    get_line_remain(), "Header length = %d bytes", hdrlen);
		(void) snprintf(get_line((char *)&ip->ip_tos - dlc_header, 1),
		    get_line_remain(), "Type of service = 0x%02x", ip->ip_tos);
		(void) snprintf(get_line((char *)&ip->ip_tos - dlc_header, 1),
		    get_line_remain(), "      xxx. .... = %d (precedence)",
		    ip->ip_tos >> 5);
		(void) snprintf(get_line((char *)&ip->ip_tos - dlc_header, 1),
		    get_line_remain(), "      %s",
		    getflag(ip->ip_tos, IPTOS_LOWDELAY,
		    "low delay", "normal delay"));
		(void) snprintf(get_line((char *)&ip->ip_tos - dlc_header, 1),
		    get_line_remain(), "      %s",
		    getflag(ip->ip_tos, IPTOS_THROUGHPUT,
		    "high throughput", "normal throughput"));
		(void) snprintf(get_line((char *)&ip->ip_tos - dlc_header, 1),
		    get_line_remain(), "      %s",
		    getflag(ip->ip_tos, IPTOS_RELIABILITY,
		    "high reliability", "normal reliability"));
		(void) snprintf(get_line((char *)&ip->ip_tos - dlc_header, 1),
		    get_line_remain(), "      %s",
		    getflag(ip->ip_tos, IPTOS_ECT,
		    "ECN capable transport", "not ECN capable transport"));
		(void) snprintf(get_line((char *)&ip->ip_tos - dlc_header, 1),
		    get_line_remain(), "      %s",
		    getflag(ip->ip_tos, IPTOS_CE,
		    "ECN congestion experienced",
		    "no ECN congestion experienced"));
		/* warning: ip_len is signed in netinet/ip.h */
		uitmp = ntohs(ip->ip_len);
		(void) snprintf(get_line((char *)&ip->ip_len - dlc_header, 2),
		    get_line_remain(), "Total length = %u bytes%s", uitmp,
		    iplen > fraglen ? " -- truncated" : "");
		(void) snprintf(get_line((char *)&ip->ip_id - dlc_header, 2),
		    get_line_remain(), "Identification = %d", ntohs(ip->ip_id));
		/* warning: ip_off is signed in netinet/ip.h */
		uitmp = ntohs(ip->ip_off);
		(void) snprintf(get_line((char *)&ip->ip_off - dlc_header, 1),
		    get_line_remain(), "Flags = 0x%x", uitmp >> 12);
		(void) snprintf(get_line((char *)&ip->ip_off - dlc_header, 1),
		    get_line_remain(), "      %s",
		    getflag(uitmp >> 8, IP_DF >> 8,
		    "do not fragment", "may fragment"));
		(void) snprintf(get_line((char *)&ip->ip_off - dlc_header, 1),
		    get_line_remain(), "      %s",
		    getflag(uitmp >> 8, IP_MF >> 8,
		    "more fragments", "last fragment"));
		(void) snprintf(get_line((char *)&ip->ip_off - dlc_header, 2),
		    get_line_remain(), "Fragment offset = %u bytes",
		    fragoffset);
		(void) snprintf(get_line((char *)&ip->ip_ttl - dlc_header, 1),
		    get_line_remain(), "Time to live = %d seconds/hops",
		    ip->ip_ttl);
		(void) snprintf(get_line((char *)&ip->ip_p - dlc_header, 1),
		    get_line_remain(), "Protocol = %d (%s)", ip->ip_p,
		    getproto(ip->ip_p));
		/*
		 * XXX need to compute checksum and print whether it's correct
		 */
		(void) snprintf(get_line((char *)&ip->ip_sum - dlc_header, 1),
		    get_line_remain(), "Header checksum = %04x",
		    ntohs(ip->ip_sum));
		(void) snprintf(get_line((char *)&ip->ip_src - dlc_header, 1),
		    get_line_remain(), "Source address = %s, %s",
		    inet_ntoa(ip->ip_src), addrtoname(AF_INET, &ip->ip_src));
		(void) snprintf(get_line((char *)&ip->ip_dst - dlc_header, 1),
		    get_line_remain(), "Destination address = %s, %s",
		    inet_ntoa(ip->ip_dst), addrtoname(AF_INET, &ip->ip_dst));

		/* Print IP options - if any */

		print_ipoptions(ip + 1, hdrlen - sizeof (struct ip));
		show_space();
	}

	/*
	 * If we are in detail mode, and this is not the first fragment of
	 * a fragmented packet, print out a little line stating this.
	 * Otherwise, go to the next protocol layer only if this is not a
	 * fragment, or we are in detail mode and this is the first fragment
	 * of a fragmented packet.
	 */
	if (flags & F_DTAIL && fragoffset != 0) {
		(void) snprintf(get_detail_line(data - dlc_header, iplen),
		    MAXLINE,
		    "%s:  [%d byte(s) of data, continuation of IP ident=%d]",
		    getproto(ip->ip_p),
		    iplen,
		    ntohs(ip->ip_id));
	} else if (!isfrag || (flags & F_DTAIL) && isfrag && fragoffset == 0) {
		/* go to the next protocol layer */

		if (fraglen > 0) {
			switch (ip->ip_p) {
			case IPPROTO_IP:
				break;
			case IPPROTO_ENCAP:
				(void) interpret_ip(flags, (struct ip *)data,
				    fraglen);
				break;
			case IPPROTO_ICMP:
				interpret_icmp(flags, (struct icmp *)data,
				    iplen, fraglen);
				break;
			case IPPROTO_IGMP:
				interpret_igmp(flags, data, iplen, fraglen);
				break;
			case IPPROTO_GGP:
				break;
			case IPPROTO_TCP:
				interpret_tcp(flags, data, iplen, fraglen);
				break;

			case IPPROTO_ESP:
				interpret_esp(flags, data, iplen, fraglen);
				break;
			case IPPROTO_AH:
				interpret_ah(flags, data, iplen, fraglen);
				break;

			case IPPROTO_OSPF:
				interpret_ospf(flags, data, iplen, fraglen);
				break;

			case IPPROTO_EGP:
			case IPPROTO_PUP:
				break;
			case IPPROTO_UDP:
				interpret_udp(flags, data, iplen, fraglen);
				break;

			case IPPROTO_IDP:
			case IPPROTO_HELLO:
			case IPPROTO_ND:
			case IPPROTO_RAW:
				break;
			case IPPROTO_IPV6:	/* IPV6 encap */
				(void) interpret_ipv6(flags, (ip6_t *)data,
				    iplen);
				break;
			case IPPROTO_SCTP:
				interpret_sctp(flags, data, iplen, fraglen);
				break;
			}
		}
	}

	encap_levels--;
	return (iplen);
}

int
interpret_ipv6(flags, ip6h, fraglen)
	int flags;
	ip6_t *ip6h;
	int fraglen;
{
	uint8_t *data;
	int hdrlen, iplen;
	extern char *src_name, *dst_name;
	int version, flow, class;
	uchar_t proto;
	boolean_t isfrag = B_FALSE;
	uint8_t extmask;
	/*
	 * The print_srcname and print_dstname strings are the hostname
	 * parts of the verbose IPv6 header output, including the comma
	 * and the space after the litteral address strings.
	 */
	char print_srcname[MAXHOSTNAMELEN + 2];
	char print_dstname[MAXHOSTNAMELEN + 2];
	char src_addrstr[INET6_ADDRSTRLEN];
	char dst_addrstr[INET6_ADDRSTRLEN];

	iplen = ntohs(ip6h->ip6_plen);
	hdrlen = IPV6_HDR_LEN;
	fraglen -= hdrlen;
	if (fraglen < 0)
		return (fraglen + hdrlen);
	data = ((uint8_t *)ip6h) + hdrlen;

	proto = ip6h->ip6_nxt;

	src_name = addrtoname(AF_INET6, &ip6h->ip6_src);
	dst_name = addrtoname(AF_INET6, &ip6h->ip6_dst);

	/*
	 * Use endian-aware masks to extract traffic class and
	 * flowinfo.  Also, flowinfo is now 20 bits and class 8
	 * rather than 24 and 4.
	 */
	class = ntohl((ip6h->ip6_vcf & IPV6_FLOWINFO_TCLASS) >> 20);
	flow = ntohl(ip6h->ip6_vcf & IPV6_FLOWINFO_FLOWLABEL);

	/*
	 * NOTE: the F_SUM and F_DTAIL flags are mutually exclusive,
	 * so the code within the first part of the following if statement
	 * will not affect the detailed printing of the packet.
	 */
	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(), "IPv6  S=%s D=%s LEN=%d "
		    "HOPS=%d CLASS=0x%x FLOW=0x%x",
		    src_name, dst_name, iplen, ip6h->ip6_hops, class, flow);
	} else if (flags & F_DTAIL) {

		(void) inet_ntop(AF_INET6, &ip6h->ip6_src, src_addrstr,
		    INET6_ADDRSTRLEN);
		(void) inet_ntop(AF_INET6, &ip6h->ip6_dst, dst_addrstr,
		    INET6_ADDRSTRLEN);

		version = ntohl(ip6h->ip6_vcf) >> 28;

		if (strcmp(src_name, src_addrstr) == 0)
			print_srcname[0] = '\0';
		else
			snprintf(print_srcname, sizeof (print_srcname),
				", %s", src_name);

		if (strcmp(dst_name, dst_addrstr) == 0)
			print_dstname[0] = '\0';
		else
			snprintf(print_dstname, sizeof (print_dstname),
				", %s", dst_name);

		show_header("IPv6:   ", "IPv6 Header", iplen);
		show_space();

		(void) sprintf(get_line((char *)ip6h - dlc_header, 1),
		    "Version = %d", version);
		(void) sprintf(get_line((char *)ip6h - dlc_header, 1),
		    "Traffic Class = %d", class);
		(void) sprintf(get_line((char *)&ip6h->ip6_vcf - dlc_header, 4),
		    "Flow label = 0x%x", flow);
		(void) sprintf(get_line((char *)&ip6h->ip6_plen -
		    dlc_header, 2), "Payload length = %d", iplen);
		(void) sprintf(get_line((char *)&ip6h->ip6_nxt -
		    dlc_header, 1), "Next Header = %d (%s)", proto,
		    getproto(proto));
		(void) sprintf(get_line((char *)&ip6h->ip6_hops -
		    dlc_header, 1), "Hop Limit = %d", ip6h->ip6_hops);
		(void) sprintf(get_line((char *)&ip6h->ip6_src - dlc_header, 1),
		    "Source address = %s%s", src_addrstr, print_srcname);
		(void) sprintf(get_line((char *)&ip6h->ip6_dst - dlc_header, 1),
		    "Destination address = %s%s", dst_addrstr, print_dstname);

		show_space();
	}

	/*
	 * Print IPv6 Extension Headers, or skip them in the summary case.
	 * Set isfrag to true if one of the extension headers encounterred
	 * was a fragment header.
	 */
	if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_DSTOPTS ||
	    proto == IPPROTO_ROUTING || proto == IPPROTO_FRAGMENT) {
		extmask = print_ipv6_extensions(flags, &data, &proto, &iplen,
		    &fraglen);
		if ((extmask & SNOOP_FRAGMENT) != 0) {
			isfrag = B_TRUE;
		}
	}

	/*
	 * We only want to print upper layer information if this is not
	 * a fragment, or if we're printing in detail.  Note that the
	 * proto variable will be set to IPPROTO_NONE if this is a fragment
	 * with a non-zero fragment offset.
	 */
	if (!isfrag || flags & F_DTAIL) {
		/* go to the next protocol layer */

		switch (proto) {
		case IPPROTO_IP:
			break;
		case IPPROTO_ENCAP:
			(void) interpret_ip(flags, (struct ip *)data, fraglen);
			break;
		case IPPROTO_ICMPV6:
			interpret_icmpv6(flags, (icmp6_t *)data, iplen,
			    fraglen);
			break;
		case IPPROTO_IGMP:
			interpret_igmp(flags, data, iplen, fraglen);
			break;
		case IPPROTO_GGP:
			break;
		case IPPROTO_TCP:
			interpret_tcp(flags, data, iplen, fraglen);
			break;
		case IPPROTO_ESP:
			interpret_esp(flags, data, iplen, fraglen);
			break;
		case IPPROTO_AH:
			interpret_ah(flags, data, iplen, fraglen);
			break;
		case IPPROTO_EGP:
		case IPPROTO_PUP:
			break;
		case IPPROTO_UDP:
			interpret_udp(flags, data, iplen, fraglen);
			break;
		case IPPROTO_IDP:
		case IPPROTO_HELLO:
		case IPPROTO_ND:
		case IPPROTO_RAW:
			break;
		case IPPROTO_IPV6:
			(void) interpret_ipv6(flags, (ip6_t *)data, iplen);
			break;
		case IPPROTO_SCTP:
			interpret_sctp(flags, data, iplen, fraglen);
			break;
		case IPPROTO_OSPF:
			interpret_ospf6(flags, data, iplen, fraglen);
			break;
		}
	}

	return (iplen);
}

/*
 * ip_ext: data including the extension header.
 * iplen: length of the data remaining in the packet.
 * Returns a mask of IPv6 extension headers it processed.
 */
uint8_t
print_ipv6_extensions(int flags, uint8_t **hdr, uint8_t *next, int *iplen,
    int *fraglen)
{
	uint8_t *data_ptr;
	uchar_t proto = *next;
	boolean_t is_extension_header;
	struct ip6_hbh *ipv6ext_hbh;
	struct ip6_dest *ipv6ext_dest;
	struct ip6_rthdr *ipv6ext_rthdr;
	struct ip6_frag *ipv6ext_frag;
	uint32_t exthdrlen;
	uint8_t extmask = 0;

	if ((hdr == NULL) || (*hdr == NULL) || (next == NULL) || (iplen == 0))
		return (0);

	data_ptr = *hdr;
	is_extension_header = B_TRUE;
	while (is_extension_header) {

		/*
		 * There must be at least enough data left to read the
		 * next header and header length fields from the next
		 * header.
		 */
		if (*fraglen < 2) {
			proto = IPPROTO_NONE;
			return (extmask);
		}

		switch (proto) {
		case IPPROTO_HOPOPTS:
			ipv6ext_hbh = (struct ip6_hbh *)data_ptr;
			exthdrlen = 8 + ipv6ext_hbh->ip6h_len * 8;
			if (*fraglen <= exthdrlen) {
				proto = IPPROTO_NONE;
				return (extmask);
			}
			prt_hbh_options(flags, ipv6ext_hbh);
			extmask |= SNOOP_HOPOPTS;
			proto = ipv6ext_hbh->ip6h_nxt;
			break;
		case IPPROTO_DSTOPTS:
			ipv6ext_dest = (struct ip6_dest *)data_ptr;
			exthdrlen = 8 + ipv6ext_dest->ip6d_len * 8;
			if (*fraglen <= exthdrlen) {
				proto = IPPROTO_NONE;
				return (extmask);
			}
			prt_dest_options(flags, ipv6ext_dest);
			extmask |= SNOOP_DSTOPTS;
			proto = ipv6ext_dest->ip6d_nxt;
			break;
		case IPPROTO_ROUTING:
			ipv6ext_rthdr = (struct ip6_rthdr *)data_ptr;
			exthdrlen = 8 + ipv6ext_rthdr->ip6r_len * 8;
			if (*fraglen <= exthdrlen) {
				proto = IPPROTO_NONE;
				return (extmask);
			}
			prt_routing_hdr(flags, ipv6ext_rthdr);
			extmask |= SNOOP_ROUTING;
			proto = ipv6ext_rthdr->ip6r_nxt;
			break;
		case IPPROTO_FRAGMENT:
			ipv6ext_frag = (struct ip6_frag *)data_ptr;
			exthdrlen = sizeof (struct ip6_frag);
			if (*fraglen <= exthdrlen) {
				proto = IPPROTO_NONE;
				return (extmask);
			}
			prt_fragment_hdr(flags, ipv6ext_frag);
			extmask |= SNOOP_FRAGMENT;
			/*
			 * If this is not the first fragment, forget about
			 * the rest of the packet, snoop decoding is
			 * stateless.
			 */
			if ((ipv6ext_frag->ip6f_offlg & IP6F_OFF_MASK) != 0)
				proto = IPPROTO_NONE;
			else
				proto = ipv6ext_frag->ip6f_nxt;
			break;
		default:
			is_extension_header = B_FALSE;
			break;
		}

		if (is_extension_header) {
			*iplen -= exthdrlen;
			*fraglen -= exthdrlen;
			data_ptr += exthdrlen;
		}
	}

	*next = proto;
	*hdr = data_ptr;
	return (extmask);
}

static void
print_ipoptions(opt, optlen)
	uchar_t *opt;
	int optlen;
{
	int len;
	char *line;

	if (optlen <= 0) {
		(void) sprintf(get_line((char *)&opt - dlc_header, 1),
		    "No options");
		return;
	}

	(void) sprintf(get_line((char *)&opt - dlc_header, 1),
	    "Options: (%d bytes)", optlen);

	while (optlen > 0) {
		line = get_line((char *)&opt - dlc_header, 1);
		len = opt[1];
		switch (opt[0]) {
		case IPOPT_EOL:
			(void) strcpy(line, "  - End of option list");
			return;
		case IPOPT_NOP:
			(void) strcpy(line, "  - No op");
			len = 1;
			break;
		case IPOPT_RR:
			(void) sprintf(line, "  - Record route (%d bytes)",
			    len);
			print_route(opt);
			break;
		case IPOPT_TS:
			(void) sprintf(line, "  - Time stamp (%d bytes)", len);
			break;
		case IPOPT_SECURITY:
			(void) sprintf(line, "  - Security (%d bytes)", len);
			break;
		case IPOPT_LSRR:
			(void) sprintf(line,
			    "  - Loose source route (%d bytes)", len);
			print_route(opt);
			break;
		case IPOPT_SATID:
			(void) sprintf(line, "  - SATNET Stream id (%d bytes)",
			    len);
			break;
		case IPOPT_SSRR:
			(void) sprintf(line,
			    "  - Strict source route, (%d bytes)", len);
			print_route(opt);
			break;
		default:
			sprintf(line, "  - Option %d (unknown - %d bytes) %s",
			    opt[0], len, tohex((char *)&opt[2], len - 2));
			break;
		}
		if (len <= 0) {
			(void) sprintf(line, "  - Incomplete option len %d",
				len);
			break;
		}
		opt += len;
		optlen -= len;
	}
}

static void
print_route(opt)
	uchar_t *opt;
{
	int len, pointer;
	struct in_addr addr;
	char *line;

	len = opt[1];
	pointer = opt[2];

	(void) sprintf(get_line((char *)(&opt + 2) - dlc_header, 1),
	    "    Pointer = %d", pointer);

	pointer -= IPOPT_MINOFF;
	opt += (IPOPT_OFFSET + 1);
	len -= (IPOPT_OFFSET + 1);

	while (len > 0) {
		line = get_line((char *)&(opt) - dlc_header, 4);
		memcpy((char *)&addr, opt, sizeof (addr));
		if (addr.s_addr == INADDR_ANY)
			(void) strcpy(line, "      -");
		else
			(void) sprintf(line, "      %s",
			    addrtoname(AF_INET, &addr));
		if (pointer == 0)
			(void) strcat(line, "  <-- (current)");

		opt += sizeof (addr);
		len -= sizeof (addr);
		pointer -= sizeof (addr);
	}
}

char *
getproto(p)
	int p;
{
	switch (p) {
	case IPPROTO_HOPOPTS:	return ("IPv6-HopOpts");
	case IPPROTO_IPV6:	return ("IPv6");
	case IPPROTO_ROUTING:	return ("IPv6-Route");
	case IPPROTO_FRAGMENT:	return ("IPv6-Frag");
	case IPPROTO_RSVP:	return ("RSVP");
	case IPPROTO_ENCAP:	return ("IP-in-IP");
	case IPPROTO_AH:	return ("AH");
	case IPPROTO_ESP:	return ("ESP");
	case IPPROTO_ICMP:	return ("ICMP");
	case IPPROTO_ICMPV6:	return ("ICMPv6");
	case IPPROTO_DSTOPTS:	return ("IPv6-DstOpts");
	case IPPROTO_IGMP:	return ("IGMP");
	case IPPROTO_GGP:	return ("GGP");
	case IPPROTO_TCP:	return ("TCP");
	case IPPROTO_EGP:	return ("EGP");
	case IPPROTO_PUP:	return ("PUP");
	case IPPROTO_UDP:	return ("UDP");
	case IPPROTO_IDP:	return ("IDP");
	case IPPROTO_HELLO:	return ("HELLO");
	case IPPROTO_ND:	return ("ND");
	case IPPROTO_EON:	return ("EON");
	case IPPROTO_RAW:	return ("RAW");
	case IPPROTO_OSPF:	return ("OSPF");
	default:		return ("");
	}
}

static void
prt_routing_hdr(flags, ipv6ext_rthdr)
	int flags;
	struct ip6_rthdr *ipv6ext_rthdr;
{
	uint8_t nxt_hdr;
	uint8_t type;
	uint32_t len;
	uint8_t segleft;
	uint32_t numaddrs;
	int i;
	struct ip6_rthdr0 *ipv6ext_rthdr0;
	struct in6_addr *addrs;
	char addr[INET6_ADDRSTRLEN];

	/* in summary mode, we don't do anything. */
	if (flags & F_SUM) {
		return;
	}

	nxt_hdr = ipv6ext_rthdr->ip6r_nxt;
	type = ipv6ext_rthdr->ip6r_type;
	len = 8 * (ipv6ext_rthdr->ip6r_len + 1);
	segleft = ipv6ext_rthdr->ip6r_segleft;

	show_header("IPv6-Route:  ", "IPv6 Routing Header", 0);
	show_space();

	(void) sprintf(get_line((char *)ipv6ext_rthdr - dlc_header, 1),
	    "Next header = %d (%s)", nxt_hdr, getproto(nxt_hdr));
	(void) sprintf(get_line((char *)ipv6ext_rthdr - dlc_header, 1),
	    "Header length = %d", len);
	(void) sprintf(get_line((char *)ipv6ext_rthdr - dlc_header, 1),
	    "Routing type = %d", type);
	(void) sprintf(get_line((char *)ipv6ext_rthdr - dlc_header, 1),
	    "Segments left = %d", segleft);

	if (type == IPV6_RTHDR_TYPE_0) {
		/*
		 * XXX This loop will print all addresses in the routing header,
		 * XXX not just the segments left.
		 * XXX (The header length field is twice the number of
		 * XXX addresses)
		 * XXX At some future time, we may want to change this
		 * XXX to differentiate between the hops yet to do
		 * XXX and the hops already taken.
		 */
		ipv6ext_rthdr0 = (struct ip6_rthdr0 *)ipv6ext_rthdr;
		numaddrs = ipv6ext_rthdr0->ip6r0_len / 2;
		addrs = (struct in6_addr *)(ipv6ext_rthdr0 + 1);
		for (i = 0; i < numaddrs; i++) {
			(void) inet_ntop(AF_INET6, &addrs[i], addr,
			    INET6_ADDRSTRLEN);
			(void) sprintf(get_line((char *)ipv6ext_rthdr -
			    dlc_header, 1),
			    "address[%d]=%s", i, addr);
		}
	}

	show_space();
}

static void
prt_fragment_hdr(flags, ipv6ext_frag)
	int flags;
	struct ip6_frag *ipv6ext_frag;
{
	boolean_t morefrag;
	uint16_t fragoffset;
	uint8_t nxt_hdr;
	uint32_t fragident;

	/* extract the various fields from the fragment header */
	nxt_hdr = ipv6ext_frag->ip6f_nxt;
	morefrag = (ipv6ext_frag->ip6f_offlg & IP6F_MORE_FRAG) == 0
	    ? B_FALSE : B_TRUE;
	fragoffset = ntohs(ipv6ext_frag->ip6f_offlg & IP6F_OFF_MASK);
	fragident = ntohl(ipv6ext_frag->ip6f_ident);

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(),
		    "IPv6 fragment ID=%d Offset=%-4d MF=%d",
		    fragident,
		    fragoffset,
		    morefrag);
	} else { /* F_DTAIL */
		show_header("IPv6-Frag:  ", "IPv6 Fragment Header", 0);
		show_space();

		(void) sprintf(get_line((char *)ipv6ext_frag - dlc_header, 1),
		    "Next Header = %d (%s)", nxt_hdr, getproto(nxt_hdr));
		(void) sprintf(get_line((char *)ipv6ext_frag - dlc_header, 1),
		    "Fragment Offset = %d", fragoffset);
		(void) sprintf(get_line((char *)ipv6ext_frag - dlc_header, 1),
		    "More Fragments Flag = %s", morefrag ? "true" : "false");
		(void) sprintf(get_line((char *)ipv6ext_frag - dlc_header, 1),
		    "Identification = %d", fragident);

		show_space();
	}
}

static void
prt_hbh_options(flags, ipv6ext_hbh)
	int flags;
	struct ip6_hbh *ipv6ext_hbh;
{
	uint8_t *data;
	uint32_t len, olen;
	uint8_t op_type;
	uint8_t op_len;
	uint8_t nxt_hdr;

	/* in summary mode, we don't do anything. */
	if (flags & F_SUM) {
		return;
	}

	show_header("IPv6-HopOpts:  ", "IPv6 Hop-by-Hop Options Header", 0);
	show_space();

	/*
	 * Store the lengh of this ext hdr in bytes.  The caller has
	 * ensured that there is at least len bytes of data left.
	 */
	len = ipv6ext_hbh->ip6h_len * 8 + 8;

	data = (uint8_t *)ipv6ext_hbh + 2;
	len -= 2;

	nxt_hdr = ipv6ext_hbh->ip6h_nxt;
	(void) sprintf(get_line((char *)ipv6ext_hbh - dlc_header, 1),
	    "Next Header = %u (%s)", nxt_hdr, getproto(nxt_hdr));

	while (len > 0) {
		GETINT8(op_type, data);
		olen = len;
		switch (op_type) {
		case IP6OPT_PAD1:
			(void) sprintf(get_line((char *)ipv6ext_hbh -
			    dlc_header, 1),
			    "pad1 option ");
			len--;
			break;
		case IP6OPT_PADN:
			GETINT8(op_len, data);
			(void) sprintf(get_line((char *)ipv6ext_hbh -
			    dlc_header, 1),
			    "padN option len = %u", op_len);
			data += op_len;	/* skip pads */
			len -= (op_len + 2);
			break;
		case IP6OPT_JUMBO: {
			uint32_t payload_len;

			GETINT8(op_len, data);
			(void) sprintf(get_line((char *)ipv6ext_hbh -
			    dlc_header, 1),
			    "Jumbo Payload Option len = %u bytes", op_len);
			if (op_len == sizeof (uint32_t)) {
				GETINT32(payload_len, data);
				(void) sprintf(get_line((char *)ipv6ext_hbh -
				    dlc_header, 1),
				    "Jumbo Payload Length = %u bytes",
				    payload_len);
			} else {
				data += op_len;
			}
			len -= (op_len + 2);
			break;
		}
		case IP6OPT_ROUTER_ALERT: {
			uint16_t value;
			const char *label[] = {"MLD", "RSVP", "AN"};

			GETINT8(op_len, data);
			(void) snprintf(get_line((char *)ipv6ext_hbh -
			    dlc_header, 1), get_line_remain(),
			    "Router Alert Option len = %u bytes", op_len);
			if (op_len == sizeof (uint16_t)) {
				GETINT16(value, data);
				(void) snprintf(get_line((char *)ipv6ext_hbh -
				    dlc_header, 1), get_line_remain(),
				    "Alert Type = %d (%s)", value,
				    value < sizeof (label) / sizeof (label[0]) ?
				    label[value] : "???");
			} else {
				data += op_len;
			}
			len -= (op_len + 2);
			break;
		}
		default:
			GETINT8(op_len, data);
			(void) sprintf(get_line((char *)ipv6ext_hbh -
			    dlc_header, 1),
			    "Option type = %u, len = %u", op_type, op_len);
			data += op_len;
			len -= (op_len + 2);
		}
		/* check for corrupt length */
		if (olen <= len) {
			(void) sprintf(get_line((char *)ipv6ext_hbh -
			    dlc_header, 1),
			    "Incomplete option len = %u, len = %u", op_type,
			    len);
			break;
		}
	}

	show_space();
}

static void
prt_dest_options(flags, ipv6ext_dest)
	int flags;
	struct ip6_dest *ipv6ext_dest;
{
	uint8_t *data;
	uint32_t len, olen;
	uint8_t op_type;
	uint32_t op_len;
	uint8_t nxt_hdr;
	uint8_t value;

	/* in summary mode, we don't do anything. */
	if (flags & F_SUM) {
		return;
	}

	show_header("IPv6-DstOpts:  ", "IPv6 Destination Options Header", 0);
	show_space();

	/*
	 * Store the length of this ext hdr in bytes.  The caller has
	 * ensured that there is at least len bytes of data left.
	 */
	len = ipv6ext_dest->ip6d_len * 8 + 8;

	data = (uint8_t *)ipv6ext_dest + 2; /* skip hdr/len */
	len -= 2;

	nxt_hdr = ipv6ext_dest->ip6d_nxt;
	(void) sprintf(get_line((char *)ipv6ext_dest - dlc_header, 1),
	    "Next Header = %u (%s)", nxt_hdr, getproto(nxt_hdr));

	while (len > 0) {
		GETINT8(op_type, data);
		olen = len;
		switch (op_type) {
		case IP6OPT_PAD1:
			(void) sprintf(get_line((char *)ipv6ext_dest -
			    dlc_header, 1),
			    "pad1 option ");
			len--;
			break;
		case IP6OPT_PADN:
			GETINT8(op_len, data);
			(void) sprintf(get_line((char *)ipv6ext_dest -
			    dlc_header, 1),
			    "padN option len = %u", op_len);
			data += op_len;
			len -= (op_len + 2);
			break;
		case IP6OPT_TUNNEL_LIMIT:
			GETINT8(op_len, data);
			GETINT8(value, data);
			(void) sprintf(get_line((char *)ipv6ext_dest -
			    dlc_header, 1),
			    "tunnel encapsulation limit len = %d, value = %d",
			    op_len, value);
			len -= (op_len + 2);
			break;
		default:
			GETINT8(op_len, data);
			(void) sprintf(get_line((char *)ipv6ext_dest -
			    dlc_header, 1),
			    "Option type = %u, len = %u", op_type, op_len);
			data += op_len;
			len -= (op_len + 2);
		}
		/* check for corrupt length */
		if (olen <= len) {
			(void) sprintf(get_line((char *)ipv6ext_dest -
			    dlc_header, 1),
			    "Incomplete option len = %u, len = %u", op_type,
			    len);
			break;
		}
	}

	show_space();
}

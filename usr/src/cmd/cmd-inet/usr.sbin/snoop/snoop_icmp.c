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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
#include "snoop.h"
#include "snoop_mip.h"

static void interpret_options(char *, int);
static void interpret_mldv2qry(icmp6_t *, int);
static void interpret_mldv2rpt(icmp6_t *, int);


/* Mobile-IP routines from snoop_mip.c */
extern void interpret_icmp_mip_ext(uchar_t *, int);
extern const char *get_mip_adv_desc(uint8_t);

/* Router advertisement message structure. */
struct icmp_ra_addr {
	uint32_t addr;
	uint32_t preference;
};

/*ARGSUSED*/
void
interpret_icmp(int flags, struct icmp *icmp, int iplen, int ilen)
{
	char *pt, *pc, *px;
	char *line;
	char buff[67627];	/* Router adv. can have 256 routers ....   */
				/* Each router has a name 256 char long .. */
	char extbuff[MAXHOSTNAMELEN + 1];
	struct udphdr *orig_uhdr;
	int num_rtr_addrs = 0;
	extern char *prot_nest_prefix;

	if (ilen < ICMP_MINLEN)
		return;		/* incomplete header */

	pt = "Unknown";
	pc = "";
	px = "";

	switch (icmp->icmp_type) {
	case ICMP_ECHOREPLY:
		pt = "Echo reply";
		(void) sprintf(buff, "ID: %d Sequence number: %d",
		    ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
		pc = buff;
		break;
	case ICMP_UNREACH:
		pt = "Destination unreachable";
		switch (icmp->icmp_code) {
		case ICMP_UNREACH_NET:
			if (ilen >= ICMP_ADVLENMIN) {
				(void) sprintf(buff, "Net %s unreachable",
				    addrtoname(AF_INET,
				    &icmp->icmp_ip.ip_dst));
				pc = buff;
			} else {
				pc = "Bad net";
			}
			break;
		case ICMP_UNREACH_HOST:
			if (ilen >= ICMP_ADVLENMIN) {
				(void) sprintf(buff, "Host %s unreachable",
				    addrtoname(AF_INET,
				    &icmp->icmp_ip.ip_dst));
				pc = buff;
			} else {
				pc = "Bad host";
			}
			break;
		case ICMP_UNREACH_PROTOCOL:
			if (ilen >= ICMP_ADVLENMIN) {
				(void) sprintf(buff, "Bad protocol %d",
				    icmp->icmp_ip.ip_p);
				pc = buff;
			} else {
				pc = "Bad protocol";
			}
			break;
		case ICMP_UNREACH_PORT:
			if (ilen >= ICMP_ADVLENMIN) {
				orig_uhdr = (struct udphdr *)((uchar_t *)icmp +
				    ICMP_MINLEN + icmp->icmp_ip.ip_hl * 4);
				switch (icmp->icmp_ip.ip_p) {
				case IPPROTO_TCP:
					(void) sprintf(buff, "TCP port %d"
					    " unreachable",
					    ntohs(orig_uhdr->uh_dport));
					pc = buff;
					break;
				case IPPROTO_UDP:
					(void) sprintf(buff, "UDP port %d"
					    " unreachable",
					    ntohs(orig_uhdr->uh_dport));
					pc = buff;
					break;
				default:
					pc = "Port unreachable";
					break;
				}
			} else {
				pc = "Bad port";
			}
			break;
		case ICMP_UNREACH_NEEDFRAG:
			if (ntohs(icmp->icmp_nextmtu) != 0) {
				(void) sprintf(buff, "Needed to fragment:"
				    " next hop MTU = %d",
				    ntohs(icmp->icmp_nextmtu));
				pc = buff;
			} else {
				pc = "Needed to fragment";
			}
			break;
		case ICMP_UNREACH_SRCFAIL:
			pc = "Source route failed";
			break;
		case ICMP_UNREACH_NET_UNKNOWN:
			pc = "Unknown network";
			break;
		case ICMP_UNREACH_HOST_UNKNOWN:
			pc = "Unknown host";
			break;
		case ICMP_UNREACH_ISOLATED:
			pc = "Source host isolated";
			break;
		case ICMP_UNREACH_NET_PROHIB:
			pc = "Net administratively prohibited";
			break;
		case ICMP_UNREACH_HOST_PROHIB:
			pc = "Host administratively prohibited";
			break;
		case ICMP_UNREACH_TOSNET:
			pc = "Net unreachable for this TOS";
			break;
		case ICMP_UNREACH_TOSHOST:
			pc = "Host unreachable for this TOS";
			break;
		case ICMP_UNREACH_FILTER_PROHIB:
			pc = "Communication administratively prohibited";
			break;
		case ICMP_UNREACH_HOST_PRECEDENCE:
			pc = "Host precedence violation";
			break;
		case ICMP_UNREACH_PRECEDENCE_CUTOFF:
			pc = "Precedence cutoff in effect";
			break;
		default:
			break;
		}
		break;
	case ICMP_SOURCEQUENCH:
		pt = "Packet lost, slow down";
		break;
	case ICMP_REDIRECT:
		pt = "Redirect";
		switch (icmp->icmp_code) {
		case ICMP_REDIRECT_NET:
			pc = "for network";
			break;
		case ICMP_REDIRECT_HOST:
			pc = "for host";
			break;
		case ICMP_REDIRECT_TOSNET:
			pc = "for tos and net";
			break;
		case ICMP_REDIRECT_TOSHOST:
			pc = "for tos and host";
			break;
		default:
			break;
		}
		(void) sprintf(buff, "%s %s to %s",
		    pc, addrtoname(AF_INET, &icmp->icmp_ip.ip_dst),
		    addrtoname(AF_INET, &icmp->icmp_gwaddr));
		pc = buff;
		break;
	case ICMP_ECHO:
		pt = "Echo request";
		(void) sprintf(buff, "ID: %d Sequence number: %d",
		    ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
		pc = buff;
		break;
	case ICMP_ROUTERADVERT:

#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime

		pt = "Router advertisement";
		(void) sprintf(buff, "Lifetime %ds [%d]:",
		    ntohs(icmp->icmp_lifetime), icmp->icmp_num_addrs);
		if (icmp->icmp_wpa == 2) {
			struct icmp_ra_addr *ra;
			char ra_buf[MAXHOSTNAMELEN + 32];
			char ra_ext_buf[50];
			struct in_addr sin;
			int icmp_ra_len;
			int i;

			/* Cannot trust anything from the network... */
			num_rtr_addrs = MIN((ilen - ICMP_MINLEN) / 8,
			    icmp->icmp_num_addrs);

			ra = (struct icmp_ra_addr *)icmp->icmp_data;
			for (i = 0; i < num_rtr_addrs; i++) {
				sin.s_addr = ra->addr;
				(void) snprintf(ra_buf, sizeof (ra_buf),
				    " {%s %u}",
				    addrtoname(AF_INET, &sin),
				    ntohl(ra->preference));
				if (strlcat(buff, ra_buf, sizeof (buff)) >=
				    sizeof (buff)) {
					buff[sizeof (buff) -
					    strlen("<Too Long>)")] = '\0';
					(void) strlcat(buff, "<Too Long>",
					    sizeof (buff));
					break;
				}
				ra++;
			}

			icmp_ra_len = ICMP_MINLEN + num_rtr_addrs *
			    sizeof (struct icmp_ra_addr);
			if (ilen > icmp_ra_len) {
				int curr_len = ilen - icmp_ra_len;
				int ocurr_len;
				exthdr_t *exthdr = (exthdr_t *)ra;

				extbuff[0] = '\0';

				while (curr_len > 0) {
					/* Append Mobile-IP description */
					(void) snprintf(ra_ext_buf,
					    sizeof (ra_ext_buf), ", %s",
					    get_mip_adv_desc(exthdr->type));
					(void) strlcat(extbuff, ra_ext_buf,
					    sizeof (extbuff));

					/* Special case for padding */
					if (exthdr->type ==
					    ICMP_ADV_MSG_PADDING_EXT) {

						curr_len--;
						exthdr = (exthdr_t *)
						    ((char *)exthdr + 1);
						continue;
					}

					/* else normal extension */
					ocurr_len = curr_len;
					curr_len -= sizeof (*exthdr) +
					    exthdr->length;
					/* detect bad length */
					if (ocurr_len < curr_len)
						break;
					exthdr = (exthdr_t *)
					    ((char *)exthdr + sizeof (*exthdr) +
					    exthdr->length);
				}
				px = extbuff;
			}
			pc = buff;
		}
		break;
	case ICMP_ROUTERSOLICIT:
		pt = "Router solicitation";
		break;
	case ICMP_TIMXCEED:
		pt = "Time exceeded";
		switch (icmp->icmp_code) {
		case ICMP_TIMXCEED_INTRANS:
			pc = "in transit";
			break;
		case ICMP_TIMXCEED_REASS:
			pc = "in reassembly";
			break;
		default:
			break;
		}
		break;
	case ICMP_PARAMPROB:
		pt = "IP parameter problem";
		switch (icmp->icmp_code) {
		case ICMP_PARAMPROB_OPTABSENT:
			pc = "Required option missing";
			break;
		case ICMP_PARAMPROB_BADLENGTH:
			pc = "Bad length";
			break;
		case 0: /* Should this be the default? */
			(void) sprintf(buff, "Problem at octet %d\n",
			    icmp->icmp_pptr);
			pc = buff;
		default:
			break;
		}
		break;
	case ICMP_TSTAMP:
		pt = "Timestamp request";
		break;
	case ICMP_TSTAMPREPLY:
		pt = "Timestamp reply";
		break;
	case ICMP_IREQ:
		pt = "Information request";
		break;
	case ICMP_IREQREPLY:
		pt = "Information reply";
		break;
	case ICMP_MASKREQ:
		pt = "Address mask request";
		break;
	case ICMP_MASKREPLY:
		pt = "Address mask reply";
		(void) sprintf(buff, "Mask = 0x%x", ntohl(icmp->icmp_mask));
		pc = buff;
		break;
	default:
		break;
	}

	if (flags & F_SUM) {
		line = get_sum_line();
		if (*pc) {
			if (*px) {
				(void) sprintf(line, "ICMP %s (%s)%s",
				    pt, pc, px);
			} else {
				(void) sprintf(line, "ICMP %s (%s)", pt, pc);
			}
		} else {
			(void) sprintf(line, "ICMP %s", pt);
		}
	}

	if (flags & F_DTAIL) {
		show_header("ICMP:  ", "ICMP Header", ilen);
		show_space();
		(void) sprintf(get_line(0, 0), "Type = %d (%s)",
		    icmp->icmp_type, pt);
		if (*pc) {
			(void) sprintf(get_line(0, 0), "Code = %d (%s)",
			    icmp->icmp_code, pc);
		} else {
			(void) sprintf(get_line(0, 0), "Code = %d",
			    icmp->icmp_code);
		}
		(void) sprintf(get_line(0, 0), "Checksum = %x",
		    ntohs(icmp->icmp_cksum));

		if (icmp->icmp_type == ICMP_UNREACH ||
		    icmp->icmp_type == ICMP_REDIRECT) {
			if (ilen > 28) {
				show_space();
				(void) sprintf(get_line(0, 0),
				    "[ subject header follows ]");
				show_space();
				prot_nest_prefix = "ICMP:";
				(void) interpret_ip(flags,
				    (struct ip *)icmp->icmp_data, 28);
				prot_nest_prefix = "";
			}
		} else if (icmp->icmp_type == ICMP_PARAMPROB) {
			if (ilen > 28) {
				show_space();
				(void) sprintf(get_line(0, 0),
				    "[ subject header follows ]");
				show_space();
				prot_nest_prefix = "ICMP:";
				(void) interpret_ip(flags,
				    (struct ip *)icmp->icmp_data, 28);
				prot_nest_prefix = "";
			}
		} else if (icmp->icmp_type == ICMP_ROUTERADVERT) {
			if (icmp->icmp_wpa == 2) {
				int icmp_ra_len;

				show_space();
				icmp_ra_len = ICMP_MINLEN +
				    num_rtr_addrs *
				    sizeof (struct icmp_ra_addr);
				prot_nest_prefix = "";
				if (ilen > icmp_ra_len) {
					interpret_icmp_mip_ext(
					    (uchar_t *)icmp + icmp_ra_len,
					    ilen - icmp_ra_len);
				}
			}
		}
		show_space();
	}
}

/*ARGSUSED*/
void
interpret_icmpv6(int flags, icmp6_t *icmp6, int iplen, int ilen)
{
	char *pt, *pc;
	char *line;
	extern char *prot_nest_prefix;
	char addrstr[INET6_ADDRSTRLEN];
	char buff[2048];

	if (ilen < ICMP6_MINLEN)
		return;		/* incomplete header */

	pt = "Unknown";
	pc = "";

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		pt = "Destination unreachable";
		switch (icmp6->icmp6_code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			pc = "No route to destination";
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			pc = "Communication administratively prohibited";
			break;
		case ICMP6_DST_UNREACH_ADDR:
			pc = "Address unreachable";
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			if (ilen >= ICMP6_MINLEN + IPV6_HDR_LEN +
				sizeof (struct udphdr)) {

				ip6_t *orig_ip6hdr = (ip6_t *)&icmp6[1];

				switch (orig_ip6hdr->ip6_nxt) {
				case IPPROTO_TCP: {
					struct tcphdr *orig_thdr =
					    (struct tcphdr *)&orig_ip6hdr[1];

					(void) sprintf(buff, "TCP port %hu"
					    " unreachable",
					    ntohs(orig_thdr->th_dport));
					pc = buff;
					break;
				    }
				case IPPROTO_UDP: {
					struct udphdr *orig_uhdr =
					    (struct udphdr *)&orig_ip6hdr[1];

					(void) sprintf(buff, "UDP port %hu"
					    " unreachable",
					    ntohs(orig_uhdr->uh_dport));
					pc = buff;
					break;
				    }
				default:
					pc = "Port unreachable";
					break;
				}
			} else {
				pc = "Bad port";
			}
			break;
		default:
			break;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		pt = "Packet too big";
		break;
	case ND_REDIRECT:
		pt = "Redirect";
		break;
	case ICMP6_TIME_EXCEEDED:
		pt = "Time exceeded";
		switch (icmp6->icmp6_code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			pc = "Hop limit exceeded in transit";
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			pc = "Fragment reassembly time exceeded";
			break;
		default:
			break;
		}
		break;
	case ICMP6_PARAM_PROB:
		pt = "Parameter problem";
		switch (icmp6->icmp6_code) {
		case ICMP6_PARAMPROB_HEADER:
			pc = "Erroneous header field";
			break;
		case ICMP6_PARAMPROB_NEXTHEADER:
			pc = "Unrecognized next header type";
			break;
		case ICMP6_PARAMPROB_OPTION:
			pc = "Unrecognized IPv6 option";
			break;
		}
		break;
	case ICMP6_ECHO_REQUEST:
		pt = "Echo request";
		(void) sprintf(buff, "ID: %d Sequence number: %d",
		    ntohs(icmp6->icmp6_id), ntohs(icmp6->icmp6_seq));
		pc = buff;
		break;
	case ICMP6_ECHO_REPLY:
		pt = "Echo reply";
		(void) sprintf(buff, "ID: %d Sequence number: %d",
		    ntohs(icmp6->icmp6_id), ntohs(icmp6->icmp6_seq));
		pc = buff;
		break;
	case MLD_LISTENER_QUERY:
		if (ilen == MLD_MINLEN)
			pt = "Group membership query - MLDv1";
		else if (ilen >= MLD_V2_QUERY_MINLEN)
			pt = "Group membership query - MLDv2";
		else
			pt = "Unknown membership query";
		break;
	case MLD_LISTENER_REPORT:
		pt = "Group membership report - MLDv1";
		break;
	case MLD_LISTENER_REDUCTION:
		pt = "Group membership termination - MLDv1";
		break;
	case MLD_V2_LISTENER_REPORT:
		pt = "Group membership report - MLDv2";
		break;
	case ND_ROUTER_SOLICIT:
		pt = "Router solicitation";
		break;
	case ND_ROUTER_ADVERT:
		pt = "Router advertisement";
		break;
	case ND_NEIGHBOR_SOLICIT:
		pt = "Neighbor solicitation";
		break;
	case ND_NEIGHBOR_ADVERT:
		pt = "Neighbor advertisement";
		break;
	default:
		break;
	}

	if (flags & F_SUM) {
		line = get_sum_line();
		if (*pc)
			(void) sprintf(line, "ICMPv6 %s (%s)", pt, pc);
		else
			(void) sprintf(line, "ICMPv6 %s", pt);
	}

	if (flags & F_DTAIL) {
		show_header("ICMPv6:  ", "ICMPv6 Header", ilen);
		show_space();
		(void) sprintf(get_line(0, 0), "Type = %d (%s)",
		    icmp6->icmp6_type, pt);
		if (*pc)
			(void) sprintf(get_line(0, 0), "Code = %d (%s)",
			    icmp6->icmp6_code, pc);
		else
			(void) sprintf(get_line(0, 0), "Code = %d",
			    icmp6->icmp6_code);
		(void) sprintf(get_line(0, 0), "Checksum = %x",
		    ntohs(icmp6->icmp6_cksum));

		switch (icmp6->icmp6_type) {
		case ICMP6_DST_UNREACH:
			if (ilen > ICMP6_MINLEN + IPV6_HDR_LEN) {
				show_space();
				(void) sprintf(get_line(0, 0),
				    "[ subject header follows ]");
				show_space();
				prot_nest_prefix = "ICMPv6:";
				(void) interpret_ipv6(flags, (ip6_t *)&icmp6[1],
				    ICMP6_MINLEN + IPV6_HDR_LEN);
				prot_nest_prefix = "";
			}
			break;
		case ICMP6_PACKET_TOO_BIG:
			show_space();
			(void) sprintf(get_line(0, 0),
			    " Packet too big MTU = %d",
			    ntohl(icmp6->icmp6_mtu));
			show_space();
			break;
		case ND_REDIRECT: {
			nd_redirect_t *rd = (nd_redirect_t *)icmp6;

			(void) sprintf(get_line(0, 0), "Target address= %s",
			    inet_ntop(AF_INET6, (char *)&rd->nd_rd_target,
			    addrstr, INET6_ADDRSTRLEN));

			(void) sprintf(get_line(0, 0),
			    "Destination address= %s",
			    inet_ntop(AF_INET6, (char *)&rd->nd_rd_dst,
			    addrstr, INET6_ADDRSTRLEN));
			show_space();
			interpret_options((char *)icmp6 + sizeof (*rd),
			    ilen - sizeof (*rd));
			break;
		}
		case ND_NEIGHBOR_SOLICIT: {
			struct nd_neighbor_solicit *ns;
			if (ilen < sizeof (*ns))
				break;
			ns = (struct nd_neighbor_solicit *)icmp6;
			(void) sprintf(get_line(0, 0), "Target node = %s, %s",
			    inet_ntop(AF_INET6, (char *)&ns->nd_ns_target,
			    addrstr, INET6_ADDRSTRLEN),
			    addrtoname(AF_INET6, &ns->nd_ns_target));
			show_space();
			interpret_options((char *)icmp6 + sizeof (*ns),
			    ilen - sizeof (*ns));
			break;
		}

		case ND_NEIGHBOR_ADVERT: {
			struct nd_neighbor_advert *na;

			if (ilen < sizeof (*na))
				break;
			na = (struct nd_neighbor_advert *)icmp6;
			(void) sprintf(get_line(0, 0), "Target node = %s, %s",
			    inet_ntop(AF_INET6, (char *)&na->nd_na_target,
			    addrstr, INET6_ADDRSTRLEN),
			    addrtoname(AF_INET6, &na->nd_na_target));
			(void) sprintf(get_line(0, 0),
			    "Router flag: %s, Solicited flag: %s, "
			    "Override flag: %s",
			    na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER ?
			    "SET" : "NOT SET",
			    na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED ?
			    "SET" : "NOT SET",
			    na->nd_na_flags_reserved & ND_NA_FLAG_OVERRIDE ?
			    "SET" : "NOT SET");

			show_space();
			interpret_options((char *)icmp6 + sizeof (*na),
			    ilen - sizeof (*na));
		}
		break;

		case ND_ROUTER_SOLICIT: {
			if (ilen < sizeof (struct nd_router_solicit))
				break;
			interpret_options(
			    (char *)icmp6 + sizeof (struct nd_router_solicit),
			    ilen - sizeof (struct nd_router_solicit));
			break;
		}

		case ND_ROUTER_ADVERT: {
			struct nd_router_advert *ra;

			if (ilen < sizeof (*ra))
				break;
			ra = (struct nd_router_advert *)icmp6;
			(void) sprintf(get_line(0, 0),
			    "Max hops= %d, Router lifetime= %d",
			    ra->nd_ra_curhoplimit,
			    ntohs(ra->nd_ra_router_lifetime));

			(void) sprintf(get_line(0, 0),
			    "Managed addr conf flag: %s, Other conf flag: %s",
			    ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED ?
			    "SET" : "NOT SET",
			    ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER ?
			    "SET" : "NOT SET");

			(void) sprintf(get_line(0, 0),
			    "Reachable time: %u, Reachable retrans time %u",
			    ntohl(ra->nd_ra_reachable),
			    ntohl(ra->nd_ra_retransmit));
			show_space();

			interpret_options((char *)icmp6 + sizeof (*ra),
			    ilen - sizeof (*ra));
			break;
		}
		case ICMP6_PARAM_PROB:
			if (ilen < sizeof (*icmp6))
				break;
			(void) sprintf(get_line(0, 0), "Ptr = %u",
			    ntohl(icmp6->icmp6_pptr));
			show_space();
			break;

		case MLD_LISTENER_QUERY: {
			struct mld_hdr *mldg = (struct mld_hdr *)icmp6;

			if (ilen < MLD_MINLEN)
				break;

			if (ilen >= MLD_V2_QUERY_MINLEN) {
				interpret_mldv2qry(icmp6, ilen);
			} else {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "Multicast address= %s",
				    inet_ntop(AF_INET6, mldg->mld_addr.s6_addr,
				    addrstr, INET6_ADDRSTRLEN));
			}
			show_space();
			break;
		}

		case MLD_LISTENER_REPORT:
		case MLD_LISTENER_REDUCTION: {
			struct mld_hdr *mldg;

			if (ilen < sizeof (*mldg))
				break;
			mldg = (struct mld_hdr *)icmp6;
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Multicast address= %s", inet_ntop(AF_INET6,
			    mldg->mld_addr.s6_addr, addrstr, INET6_ADDRSTRLEN));
			show_space();
			break;
		}

		case MLD_V2_LISTENER_REPORT: {
			interpret_mldv2rpt(icmp6, ilen);
			show_space();
			break;
		}

		default:
			break;
		}
	}
}

#define	LIFETIME_INFINITY		0xffffffffUL

static void
interpret_lifetime(char *buf, uint32_t net_lifetime)
{
	uint32_t lifetime = ntohl(net_lifetime);

	if (lifetime == 0) {
		sprintf(buf, "INVALID");
		return;
	}
	if (lifetime == LIFETIME_INFINITY) {
		sprintf(buf, "INFINITY");
		return;
	}
	sprintf(buf, "%lu", lifetime);
}

static void
interpret_options(char *optc, int ilen)
{
#define	PREFIX_OPTION_LENGTH    4
#define	MTU_OPTION_LENGTH	1

	struct nd_opt_hdr *opt;

	for (; ilen >= sizeof (*opt); ) {
		opt = (struct nd_opt_hdr *)optc;
		if (opt->nd_opt_len == 0)
			return;
		switch (opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
		{
			struct nd_opt_lla *lopt;
			char	*buf, chbuf[128];
			uint_t	addr_len;
			int	i;

			if (ilen < (int)opt->nd_opt_len * 8)
				break;

			buf = chbuf;

			lopt = (struct nd_opt_lla *)opt;
			if (lopt->nd_opt_lla_type == ND_OPT_SOURCE_LINKADDR) {
				(void) sprintf(get_line(0, 0),
				    "+++ ICMPv6 Source LL Addr option +++");
			} else {
				(void) sprintf(get_line(0, 0),
				    "+++ ICMPv6 Target LL Addr option +++");
			}

			/*
			 * The option length is in 8 octet units, and
			 * includes the first two bytes (the type and
			 * lenght fields) of the option.
			 */
			addr_len = lopt->nd_opt_lla_len * 8 - 2;
			for (i = 0; i < addr_len; i++) {
				snprintf(buf, sizeof (chbuf) - (buf - chbuf),
				    "%x:", lopt->nd_opt_lla_hdw_addr[i]);
				buf += strlen(buf);
				if (buf >= &chbuf[sizeof (chbuf)]) {
					buf = NULL;
					chbuf[sizeof (chbuf) -
					    strlen("<Too Long>)")] = '\0';
					(void) strlcat(chbuf, "<Too Long>",
					    sizeof (chbuf));
					break;
				}
			}
			if (buf)
				*(buf - 1) = '\0'; /* Erase last colon */
			(void) sprintf(get_line(0, 0),
			    "Link Layer address: %s", chbuf);
			show_space();
			break;
		}
		case ND_OPT_MTU: {
			struct nd_opt_mtu *mopt;
			if (opt->nd_opt_len != MTU_OPTION_LENGTH ||
			    ilen < sizeof (struct nd_opt_mtu))
				break;
			(void) sprintf(get_line(0, 0),
			    "+++ ICMPv6 MTU option +++");
			mopt = (struct nd_opt_mtu *)opt;
			(void) sprintf(get_line(0, 0),
			    "MTU = %u ", ntohl(mopt->nd_opt_mtu_mtu));
			show_space();
			break;
		}
		case ND_OPT_PREFIX_INFORMATION: {
			struct nd_opt_prefix_info *popt;
			char validstr[30];
			char preferredstr[30];
			char prefixstr[INET6_ADDRSTRLEN];

			if (opt->nd_opt_len != PREFIX_OPTION_LENGTH ||
			    ilen < sizeof (struct nd_opt_prefix_info))
				break;
			popt = (struct nd_opt_prefix_info *)opt;
			(void) sprintf(get_line(0, 0),
			    "+++ ICMPv6 Prefix option +++");
			(void) sprintf(get_line(0, 0),
			    "Prefix length = %d ", popt->nd_opt_pi_prefix_len);
			(void) sprintf(get_line(0, 0),
			    "Onlink flag: %s, Autonomous addr conf flag: %s",
			    popt->nd_opt_pi_flags_reserved &
			    ND_OPT_PI_FLAG_ONLINK ? "SET" : "NOT SET",
			    popt->nd_opt_pi_flags_reserved &
			    ND_OPT_PI_FLAG_AUTO ? "SET" : "NOT SET");

			interpret_lifetime(validstr,
			    popt->nd_opt_pi_valid_time);
			interpret_lifetime(preferredstr,
			    popt->nd_opt_pi_preferred_time);

			(void) sprintf(get_line(0, 0),
			    "Valid Lifetime %s, Preferred Lifetime %s",
			    validstr, preferredstr);
			(void) sprintf(get_line(0, 0), "Prefix %s",
			    inet_ntop(AF_INET6,
			    (char *)&popt->nd_opt_pi_prefix, prefixstr,
			    INET6_ADDRSTRLEN));
			show_space();
			break;
		}
		case ND_OPT_DNS_RESOLVER: {
			char addrstr[INET6_ADDRSTRLEN];
			char lifestr[30];
			int i, naddr;
			struct nd_opt_dns_resolver *optr =
			    (struct nd_opt_dns_resolver *)optc;

			if (opt->nd_opt_len < 3 || ilen < opt->nd_opt_len * 8)
				break;

			(void) sprintf(get_line(0, 0),
			    "+++ ICMPv6 Recursive DNS Server option +++");

			interpret_lifetime(lifestr, optr->nd_opt_dnsr_lifetime);
			(void) sprintf(get_line(0, 0), "Lifetime %s", lifestr);

			naddr = (opt->nd_opt_len - 1) / 2;

			for (i = 0; i < naddr; i++) {
				const char *ns = inet_ntop(AF_INET6,
				    &optr->nd_opt_dnsr_addr[i],
				    addrstr,
				    INET6_ADDRSTRLEN);
				sprintf(get_line(0, 0), "Nameserver %s", ns);
			}
			show_space();
			break;
		}
		case ND_OPT_DNS_SEARCHLIST: {
			struct nd_opt_dns_sl *opts =
			    (struct nd_opt_dns_sl *)optc;
			char lifestr[30];
			uchar_t *msg, *namep, *end;

			(void) sprintf(get_line(0, 0),
			    "+++ ICMPv6 DNS Search List option +++");
			interpret_lifetime(lifestr, opts->nd_opt_dnss_lifetime);
			(void) sprintf(get_line(0, 0), "Lifetime %s", lifestr);

			msg = &opts->nd_opt_dnss_names[0];
			end = (uint8_t *)(optc + opt->nd_opt_len * 8);
			namep = msg;

			/*
			 * Names are encoded in DNS wire format and then
			 * padded with zero bytes to the end of the option.
			 * dn_expand() returns the length of the
			 * wire-format name so the parser can advance
			 * to the next name in the message, or -1 on failure.
			 *
			 * The only 1-byte encoded DNS name is '.' (the root),
			 * which is meaningless in a DNS search path.
			 * It is encoded as a single zero byte, so if we
			 * see it we can quit parsing.
			 */
			while (namep < end) {
				char namebuf[256];

				int count = dn_expand(msg, end, namep,
				    namebuf, sizeof (namebuf));

				if (count <= 1)
					break;

				(void) sprintf(get_line(0, 0),
				    "Name: %s", namebuf);
				namep += count;
			}
			show_space();
			break;
		}
		default:
			break;
		}
		optc += opt->nd_opt_len * 8;
		ilen -= opt->nd_opt_len * 8;
	}
}

static void
interpret_mldv2qry(icmp6_t *icmp6, int ilen)
{
	mld2q_t *qry;
	in6_addr_t *src;
	int rem = ilen;
	int srccnt;
	char addrstr[INET6_ADDRSTRLEN];

	if (ilen < sizeof (*qry)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Malformed MLD Query");
		return;
	}
	qry = (mld2q_t *)icmp6;
	rem -= sizeof (*qry);
	srccnt = ntohs(qry->mld2q_numsrc);
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "Multicast address= %s", inet_ntop(AF_INET6,
	    &qry->mld2q_addr.s6_addr, addrstr, INET6_ADDRSTRLEN));
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "%d Source Address%s:", srccnt, (srccnt == 1) ? "" : "es");

	src = (in6_addr_t *)&qry[1];
	while (srccnt > 0 && rem >= sizeof (*src)) {
		rem -= sizeof (*src);

		(void) snprintf(get_line(0, 0), get_line_remain(), "    %s",
		    inet_ntop(AF_INET6, src, addrstr, INET6_ADDRSTRLEN));

		srccnt--;
		src++;
	}
}

#define	MAX_MLDV2_REPORT_TYPE	6

const char *mldv2rpt_types[] = {
	"<unknown>",
	"MODE_IS_INCLUDE",
	"MODE_IS_EXCLUDE",
	"CHANGE_TO_INCLUDE",
	"CHANGE_TO_EXCLUDE",
	"ALLOW_NEW_SOURCES",
	"BLOCK_OLD_SOURCES",
};

static void
interpret_mldv2rpt(icmp6_t *icmp6, int ilen)
{
	mld2r_t *rpt;
	mld2mar_t *mar;
	in6_addr_t *src;
	int rem = ilen, auxlen;
	uint16_t marcnt, srccnt;
	char addrstr[INET6_ADDRSTRLEN];

	if (ilen < sizeof (*rpt)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Malformed MLDv2 Report");
		return;
	}
	rpt = (mld2r_t *)icmp6;
	mar = (mld2mar_t *)&rpt[1];
	marcnt = ntohs(rpt->mld2r_nummar);
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "%d Multicast Address Record%s:", marcnt, (marcnt == 1) ? "" : "s");
	rem -= sizeof (*rpt);
	while (marcnt > 0 && rem >= sizeof (*mar)) {
		rem -= sizeof (*mar);

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Multicast address= %s  type = %s", inet_ntop(AF_INET6,
		    &mar->mld2mar_group.s6_addr, addrstr, INET6_ADDRSTRLEN),
		    (mar->mld2mar_type > MAX_MLDV2_REPORT_TYPE) ?
		    "<unknown>" : mldv2rpt_types[mar->mld2mar_type]);
		srccnt = ntohs(mar->mld2mar_numsrc);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "%d Source Address%s:", srccnt, (srccnt == 1) ? "" : "es");

		src = (in6_addr_t *)&mar[1];
		while (srccnt > 0 && rem >= sizeof (*src)) {
			rem -= sizeof (*src);

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "    %s", inet_ntop(AF_INET6, src, addrstr,
			    INET6_ADDRSTRLEN));

			srccnt--;
			src++;
		}

		marcnt--;
		auxlen = mar->mld2mar_auxlen * 4;
		rem -= auxlen;
		mar = (mld2mar_t *)((uint8_t *)src + auxlen);
	}
}

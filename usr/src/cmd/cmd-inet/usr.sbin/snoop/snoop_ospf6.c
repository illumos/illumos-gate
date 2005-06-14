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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "snoop.h"
#include "snoop_ospf.h"
#include "snoop_ospf6.h"

extern char *dlc_header;
static char *sum_line;
extern const struct bits ospf_db_flags_bits[];
extern const struct bits ospf_rla_flag_bits[];
extern const struct bits ospf_option_bits[];

const struct bits ospf6_option_bits[] = {
	{ OSPF_OPTION_V6,	"V6" },
	{ OSPF_OPTION_E,	"E" },
	{ OSPF_OPTION_MC,	"MC" },
	{ OSPF_OPTION_N,	"N" },
	{ OSPF_OPTION_R,	"R" },
	{ OSPF_OPTION_DC,	"DC" },
	{ 0,			NULL }
};

/*
 * return a printable string in dotted-decimal notation
 * for id.
 */
static char *
print_ipaddr(uint32_t id)
{
	struct in_addr tmp;

	tmp.s_addr = id;
	return (inet_ntoa(tmp));
}

static int
interpret_ospf6_hello(int flags, struct ospf6hdr *op, int fraglen)
{
	uint32_t *nbr;
	int j;

	if (fraglen < OSPF6_MIN_HEADER_SIZE + OSPF_MIN_HELLO_HEADER_SIZE)
		return (-1); /* truncated packet */

	if (flags & F_SUM) {
		if (op->ospf6_hello.hello_dr != 0) {
			(void) sprintf(sum_line, "DR=%s ",
			    print_ipaddr(op->ospf6_hello.hello_dr));
		}
		sum_line += strlen(sum_line);
		if (op->ospf6_hello.hello_bdr != 0) {
			(void) sprintf(sum_line, "BDR=%s ",
			    print_ipaddr(op->ospf6_hello.hello_bdr));
		}
		sum_line += strlen(sum_line);
		j = 0;
		nbr = op->ospf6_hello.hello_neighbor;
		while ((uchar_t *)nbr < ((uchar_t *)op + fraglen)) {
			if ((uchar_t *)nbr + sizeof (struct in_addr) >
			    ((uchar_t *)op + fraglen))
				return (-1); /* truncated */
			++nbr;
			j++;
		}
		(void) sprintf(sum_line, "%d nbrs", j);
		sum_line += strlen(sum_line);

	}
	if (flags & F_DTAIL) {
		show_header("OSPF HELLO:  ", "Hello Packet",
		    ntohs(op->ospf6_len));
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Options = %s", ospf_print_bits(ospf6_option_bits,
		    op->ospf6_hello.hello6_options));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Interface ID = %s",
		    print_ipaddr(op->ospf6_hello.hello_ifid));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Hello interval = %d",
		    ntohs(op->ospf6_hello.hello_helloint));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Priority = %d", op->ospf6_hello.hello6_priority);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Dead interval = %u", ntohl(op->ospf6_hello.hello_deadint));
		if (op->ospf6_hello.hello_dr != 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Designated Router = %s",
			    print_ipaddr(op->ospf6_hello.hello_dr));
		}
		if (op->ospf6_hello.hello_bdr != 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Backup Designated Router = %s",
			    print_ipaddr(op->ospf6_hello.hello_bdr));
		}
		nbr = op->ospf6_hello.hello_neighbor;
		while ((uchar_t *)nbr < ((uchar_t *)op + fraglen)) {
			if ((uchar_t *)nbr + sizeof (struct in_addr) >
			    ((uchar_t *)op + fraglen))
				return (-1); /* truncated */
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Neigbor: %s", print_ipaddr(*nbr));
			++nbr;
		}
	}
	return (fraglen);
}

static void
ospf6_print_ls_type(int flags, uint_t ls6_type, uint32_t ls6_stateid,
    uint32_t ls6_router)
{
	char scope[15];

	if (flags & F_SUM)
		return;

	switch (ls6_type & LS6_SCOPE_MASK) {
	case LS6_SCOPE_LINKLOCAL:
		snprintf(scope, sizeof (scope), "linklocal");
		break;
	case LS6_SCOPE_AREA:
		snprintf(scope, sizeof (scope), "area");
		break;
	case LS6_SCOPE_AS:
		snprintf(scope, sizeof (scope), "AS");
		break;
	default:
		snprintf(scope, sizeof (scope), "");
		break;
	}
	switch (ls6_type & LS_TYPE_MASK) {
	case LS_TYPE_ROUTER:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s Router = %s", scope, print_ipaddr(ls6_router));
		}
		break;
	case LS_TYPE_NETWORK:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s Net DR %s IF %s", scope,
			    print_ipaddr(ls6_router),
			    print_ipaddr(ls6_stateid));
		}
		break;
	case LS_TYPE_INTER_AP:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s Inter-area-prefix = %s ABR %s", scope,
			    print_ipaddr(ls6_stateid),
			    print_ipaddr(ls6_router));
		}
		break;
	case LS_TYPE_INTER_AR:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s Inter-area-router = %s Router %s", scope,
			    print_ipaddr(ls6_router),
			    print_ipaddr(ls6_stateid));
		}
		break;
	case LS_TYPE_ASE:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s ASE = %s ASBR %s", scope,
			    print_ipaddr(ls6_stateid),
			    print_ipaddr(ls6_router));
		}
		break;
	case LS_TYPE_GROUP:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s group = %s Router %s", scope,
			    print_ipaddr(ls6_stateid),
			    print_ipaddr(ls6_router));
		}
		break;
	case LS_TYPE_TYPE7:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s Type 7 = %s Router %s", scope,
			    print_ipaddr(ls6_stateid),
			    print_ipaddr(ls6_router));
		}
		break;
	case LS_TYPE_LINK:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s link = %s Router %s", scope,
			    print_ipaddr(ls6_stateid),
			    print_ipaddr(ls6_router));
		}
		break;
	case LS_TYPE_INTRA_AP:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s Inter-area-prefix = %s Router %s", scope,
			    print_ipaddr(ls6_stateid),
			    print_ipaddr(ls6_router));
		}
		break;
	default:
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s Unknown type = 0x%x", ls6_type);
		}
		break;
	}
}

static int
ospf6_print_lsaprefix(int flags, struct lsa6_prefix *lpfx)
{
	int k;
	struct in6_addr prefix;
	char prefixstr[INET6_ADDRSTRLEN];

	k = (lpfx->lsa6_plen + 31)/32;
	if (k * 4 > sizeof (struct in6_addr)) {
		if (flags & F_SUM) {
			sprintf(sum_line, "Unknown prefix len %d",
			    lpfx->lsa6_plen);
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Unknown prefix len %d", lpfx->lsa6_plen);
		}
	}
	memset((void *)&prefix, 0, sizeof (prefix));
	memcpy((void *)&prefix, lpfx->lsa6_pfx, k * 4);
	(void) inet_ntop(AF_INET6, (char *)&prefix, prefixstr,
	    INET6_ADDRSTRLEN);
	if (flags & F_SUM) {
		sprintf(sum_line, "%s/%d", prefixstr, lpfx->lsa6_plen);
		sum_line += strlen(sum_line);
	}
	if (flags & F_DTAIL) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "%s/%d", prefixstr, lpfx->lsa6_plen);
	}
	if (lpfx->lsa6_popt != 0) {
		if (flags & F_SUM) {
			sprintf(sum_line, "(opt = %x)", lpfx->lsa6_popt);
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "(opt = %x)", lpfx->lsa6_popt);
		}
	}
	return (sizeof (*lpfx) - 4 + k * 4);
}

static void
interpret_ospf6_lsa_hdr(int flags, struct lsa6_hdr *lsah)
{
	if (flags & F_SUM)
		return;

	if (flags & F_DTAIL) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Sequence = %X ", ntohl(lsah->ls6_seq));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Age = %X ", ospf_print_lsa_age(ntohl(lsah->ls6_age)));
	}

	ospf6_print_ls_type(flags, lsah->ls6_type, lsah->ls6_stateid,
	    lsah->ls6_router);

}

#define	TRUNC(addr)	((uchar_t *)(addr) > fragend)
static int
interpret_ospf6_lsa(int flags, struct lsa6 *lsa, uchar_t *fragend)
{
	uchar_t *ls_end;
	int  k, j;
	struct rla6link *rl;
	uint32_t *addr;
	struct lsa6_prefix *lpfx;
	struct llsa *llsa;
	char addrstr[INET6_ADDRSTRLEN];

	interpret_ospf6_lsa_hdr(flags, &lsa->ls6_hdr);

	ls_end = (uchar_t *)lsa + ntohs(lsa->ls6_hdr.ls6_length);

	if (TRUNC(ls_end))
		return (-1);

	switch (ntohs(lsa->ls6_hdr.ls6_type)) {

	case LS_TYPE_ROUTER|LS6_SCOPE_AREA:
		if (TRUNC(&lsa->lsa_un.un_rla.rla6_flags))
			return (-1);

		(void) ospf_print_bits(ospf_rla_flag_bits,
		    lsa->lsa_un.un_rla.rla6_flags);

		if (TRUNC(&lsa->lsa_un.un_rla.rla6_options))
			return (-1);
		(void) ospf_print_bits(ospf_option_bits,
		    ntohl(lsa->lsa_un.un_rla.rla6_options));

		rl = lsa->lsa_un.un_rla.rla_link;
		if (TRUNC(rl))
			return (-1);

		while (rl + sizeof (*rl) <= (struct rla6link *)ls_end) {
			if (TRUNC((uchar_t *)rl + sizeof (*rl)))
				return (-1);
			if (flags & F_SUM) {
				sprintf(sum_line, "{");		/* } (ctags) */
				sum_line += strlen(sum_line);
			}
			switch (rl->link_type) {
			case RLA_TYPE_VIRTUAL:
				if (flags & F_SUM) {
					sprintf(sum_line, "virt ");
					sum_line += strlen(sum_line);
				}
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Virtual Link");
				}
				/* FALLTHROUGH */
			case RLA_TYPE_ROUTER:
				if (flags & F_SUM) {
					sprintf(sum_line, "nbrid %s",
					    print_ipaddr(rl->link_nrtid));
					sum_line += strlen(sum_line);
					sprintf(sum_line, " nbrif %s",
					    print_ipaddr(rl->link_nifid));
					sum_line += strlen(sum_line);
					sprintf(sum_line, " if %s",
					    print_ipaddr(rl->link_ifid));
					sum_line += strlen(sum_line);
				}
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Neighbor = %s",
					    print_ipaddr(rl->link_nrtid));
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "Interface = %s id %s",
					    print_ipaddr(rl->link_nifid),
					    print_ipaddr(rl->link_ifid));
				}
				break;
			case RLA_TYPE_TRANSIT:
				if (flags & F_SUM) {
					sprintf(sum_line, "dr %s",
					    print_ipaddr(rl->link_nrtid));
					sum_line += strlen(sum_line);
					sprintf(sum_line, " drif %s",
					    print_ipaddr(rl->link_nifid));
					sum_line += strlen(sum_line);
					sprintf(sum_line, " if %s",
					    print_ipaddr(rl->link_ifid));
					sum_line += strlen(sum_line);
				}
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "Designated Router = %s",
					    print_ipaddr(rl->link_nrtid));
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "DR Interface = %s id %s",
					    print_ipaddr(rl->link_nifid),
					    print_ipaddr(rl->link_ifid));
				}
				break;
			default:
				if (flags & F_SUM) {
					sprintf(sum_line,
					    "Unknown link type %d",
					    rl->link_type);
					sum_line += strlen(sum_line);
				}
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "Unknown link type %d",
					    rl->link_type);
				}

			}
			if (flags & F_SUM) {
				sprintf(sum_line, " metric %d",
				    ntohs(rl->link_metric));
				sum_line += strlen(sum_line);
			}
			if (flags & F_DTAIL) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(), " metric = %d",
				    ntohs(rl->link_metric));
			}
			if (flags & F_SUM) { 			/* { (ctags) */
				sprintf(sum_line,  " }");
				sum_line += strlen(sum_line);
			}
			rl++;
			if ((uchar_t *)rl > fragend)
				return (-1); /* truncated */
		}
		break;
	case LS_TYPE_NETWORK | LS6_SCOPE_AREA:

		if (TRUNC(&lsa->lsa_un.un_nla.nla_options))
			return (-1);

		(void) ospf_print_bits(ospf6_option_bits,
		    ntohl(lsa->lsa_un.un_nla.nla_options));

		if (flags & F_SUM) {
			sprintf(sum_line, " rtrs");
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			snprintf(get_line(0, 0), get_line_remain(),
			    "Routers:");
		}
		addr = lsa->lsa_un.un_nla.nla_router;
		while ((uchar_t *)addr < ls_end) {
			if ((uchar_t *)addr + sizeof (struct in_addr) > ls_end)
				return (-1); /* truncated */
			if (flags & F_SUM) {
				sprintf(sum_line, " %s", print_ipaddr(*addr));
				sum_line += strlen(sum_line);
			}
			if (flags & F_DTAIL) {
				snprintf(get_line(0, 0), get_line_remain(),
				    "\t%s", print_ipaddr(*addr));
			}
			++addr;
		}
		break;
	case LS_TYPE_INTER_AP | LS6_SCOPE_AREA:

		if (TRUNC(&lsa->lsa_un.un_inter_ap.inter_ap_metric))
			return (-1);

		if (flags & F_SUM) {
			sprintf(sum_line, " metric %s",
			    ntohl(lsa->lsa_un.un_inter_ap.inter_ap_metric) &
			    SLA_MASK_METRIC);
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			snprintf(get_line(0, 0), get_line_remain(),
			    "Metric = %s",
			    ntohl(lsa->lsa_un.un_inter_ap.inter_ap_metric) &
			    SLA_MASK_METRIC);
		}
		lpfx = lsa->lsa_un.un_inter_ap.inter_ap_prefix;
		if (lpfx > (struct lsa6_prefix *)ls_end)
			return (-1);
		while (lpfx + sizeof (*lpfx) <= (struct lsa6_prefix *)ls_end) {
			k = ospf6_print_lsaprefix(flags, lpfx);
			lpfx = (struct lsa6_prefix *)(((uchar_t *)lpfx) + k);
			if (lpfx > (struct lsa6_prefix *)ls_end)
				return (-1);
		}
		break;
	case LS_TYPE_LINK:
		llsa = &lsa->lsa_un.un_llsa;
		if (TRUNC(llsa->llsa_options))
			return (-1);
		ospf_print_bits(ospf6_option_bits, ntohl(llsa->llsa_options));
		if (TRUNC(llsa->llsa_nprefix))
			return (-1);
		(void) inet_ntop(AF_INET6, &llsa->llsa_lladdr,
		    addrstr, INET6_ADDRSTRLEN);
		if (flags & F_SUM)  {
			sprintf(sum_line, " pri %d lladdr %s npref %d",
			    ntohl(llsa->llsa_priority), addrstr,
			    ntohl(llsa->llsa_nprefix));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL)  {
			snprintf(get_line(0, 0), get_line_remain(),
			    "Priority %d", ntohl(llsa->llsa_priority));
			snprintf(get_line(0, 0), get_line_remain(),
			    "Link Local addr %d", addrstr);
			snprintf(get_line(0, 0), get_line_remain(),
			    "npref %d", ntohl(llsa->llsa_nprefix));
		}
		lpfx = llsa->llsa_prefix;
		for (j = 0; j < ntohl(llsa->llsa_nprefix); j++) {
			if (TRUNC(lpfx))
				return (-1);
			k = ospf6_print_lsaprefix(flags, lpfx);
			lpfx = (struct lsa6_prefix *)(((uchar_t *)lpfx) + k);
		}
		break;

	case LS_TYPE_INTRA_AP | LS6_SCOPE_AREA:
		if (TRUNC(&lsa->lsa_un.un_intra_ap.intra_ap_rtid))
			return (-1);
		ospf6_print_ls_type(flags,
		    ntohs(lsa->lsa_un.un_intra_ap.intra_ap_lstype),
		    lsa->lsa_un.un_intra_ap.intra_ap_lsid,
		    lsa->lsa_un.un_intra_ap.intra_ap_rtid);
		if (TRUNC(&lsa->lsa_un.un_intra_ap.intra_ap_nprefix))
			return (-1);
		if (flags & F_SUM) {
			sprintf(sum_line, " npref %d",
			    ntohs(lsa->lsa_un.un_intra_ap.intra_ap_nprefix));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			snprintf(get_line(0, 0), get_line_remain(), "NPref %d",
			    ntohs(lsa->lsa_un.un_intra_ap.intra_ap_nprefix));
		}

		lpfx = lsa->lsa_un.un_intra_ap.intra_ap_prefix;
		for (j = 0;
		    j < ntohs(lsa->lsa_un.un_intra_ap.intra_ap_nprefix); j++) {
			if (TRUNC(lpfx))
				return (-1);
			k = ospf6_print_lsaprefix(flags, lpfx);
			lpfx = (struct lsa6_prefix *)(((uchar_t *)lpfx) + k);
		}
		break;

	default:
		if (flags & F_SUM)  {
			sprintf(sum_line, " Unknown LSA type (%d)",
			    lsa->ls6_hdr.ls6_type);
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL)  {
			snprintf(get_line(0, 0), get_line_remain(),
			    " Unknown LSA type %d", lsa->ls6_hdr.ls6_type);

		}
		break;
	}
	return (0);
}
#undef TRUNC
int
interpret_ospf6(int flags, struct ospf6hdr *ospf, int iplen, int fraglen)
{
	boolean_t trunc = B_FALSE;
	struct lsa6_hdr *lsah;
	struct lsr6 *lsr;
	struct lsa6 *lsa;
	int nlsa, nlsah;

	if ((fraglen < OSPF6_MIN_HEADER_SIZE) ||
	    (fraglen < ntohs(ospf->ospf6_len)))
		return (fraglen);	/* incomplete header */

	if (ospf->ospf6_version != 3) {
		if (ospf->ospf6_version == 2) {
			if (flags & F_DTAIL)
				snprintf(get_line(0, 0), get_line_remain(),
				    "ospfv2 packet in ipv6 header");
			return (interpret_ospf(flags, ospf, iplen, fraglen));
		} else  {
			return (fraglen);
		}
	}

	if (fraglen > ntohs(ospf->ospf6_len))
		fraglen = ntohs(ospf->ospf6_len);

	if (ospf->ospf6_type > OSPF_TYPE_MAX) {
		if (flags & F_SUM) {
			(void) sprintf(sum_line, "Unknown OSPF TYPE %d \n",
			    ospf->ospf6_type);
			sum_line += strlen(sum_line);
		}
		if (flags & F_SUM) {
			show_header("OSPFv3:  ", "OSPFv3 Header", fraglen);
			show_space();
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Unknown OSPF Type = %d", ospf->ospf6_type);
		}
		return (fraglen);
	}

	if (flags & F_SUM) {
		sum_line = (char *)get_sum_line();
		(void) sprintf(sum_line, "OSPFv3 %s RTRID=%s ",
		    ospf_types[ospf->ospf6_type],
		    print_ipaddr(ospf->ospf6_routerid));
		sum_line += strlen(sum_line);
		(void) sprintf(sum_line, "AREA=%s LEN=%d instance %u ",
		    print_ipaddr(ospf->ospf6_areaid),
		    ntohs((ushort_t)ospf->ospf6_len), ospf->ospf6_instanceid);
		sum_line += strlen(sum_line);
	}

	if (flags & F_DTAIL) {
		show_header("OSPFv3:  ", "OSPF Header", fraglen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Version = %d", ospf->ospf6_version);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Type = %s", ospf_types[ospf->ospf6_type]);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Router ID = %s", print_ipaddr(ospf->ospf6_routerid));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Area ID = %s", print_ipaddr(ospf->ospf6_areaid));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Checksum = 0x%x", ospf->ospf6_chksum);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Instance = %u", ospf->ospf6_instanceid);
	}

	switch (ospf->ospf6_type) {
	case OSPF_TYPE_HELLO:
		if (interpret_ospf6_hello(flags, ospf, fraglen) < 0)
			trunc = B_TRUE;
		break;

	case OSPF_TYPE_DB:
		if (fraglen < OSPF6_MIN_HEADER_SIZE +
		    OSPF6_MIN_DB_HEADER_SIZE) {
			trunc = B_TRUE;
			break;
		}
		if (flags & F_SUM) {
			sprintf(sum_line, " %s %s mtu %u S %X", ospf_print_bits(
			    ospf6_option_bits,
			    ntohl(ospf->ospf6_db.db_options)),
			    ospf_print_bits(ospf_db_flags_bits,
			    ospf->ospf6_db.db_flags),
			    ntohs(ospf->ospf6_db.db_mtu),
			    ntohl(ospf->ospf6_db.db_seq));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			show_header("OSPF DB:  ", "Database Description Packet",
			    fraglen);
			show_space();
			snprintf(get_line(0, 0), get_line_remain(),
			    "Options = %s", ospf_print_bits(
			    ospf6_option_bits, ospf->ospf6_db.db_options));
			snprintf(get_line(0, 0), get_line_remain(),
			    "Flags = %s", ospf_print_bits(
			    ospf_db_flags_bits, ospf->ospf6_db.db_flags));
			snprintf(get_line(0, 0), get_line_remain(),
			    "MTU = %u", ntohl(ospf->ospf6_db.db_seq));
			snprintf(get_line(0, 0), get_line_remain(),
			    "Sequence = 0x%X", ntohl(ospf->ospf6_db.db_seq));
			/*  Print all the LS advs */
			lsah = ospf->ospf6_db.db_lshdr;
			while ((uchar_t *)lsah < ((uchar_t *)ospf + fraglen)) {
				if ((uchar_t *)lsah + sizeof (struct lsa6_hdr) >
				    ((uchar_t *)ospf + fraglen)) {
					trunc = B_TRUE;
					break;
				}
				interpret_ospf6_lsa_hdr(flags, lsah);
				++lsah;
			}
		}
		break;

	case OSPF_TYPE_LSR:
		if (fraglen < OSPF6_MIN_HEADER_SIZE +
		    OSPF_MIN_LSR_HEADER_SIZE) {
			trunc = B_TRUE;
			break;
		}
		if (flags & F_DTAIL) {
			show_header("OSPF LSR:  ", "Link State Request Packet",
			    fraglen);
			show_space();
		}
		lsr = ospf->ospf6_lsr;
		nlsah = 0;
		while ((uchar_t *)lsr < ((uchar_t *)ospf + fraglen)) {
			if ((uchar_t *)lsr + sizeof (struct lsr6) >
			    ((uchar_t *)ospf + fraglen)) {
				trunc = B_TRUE;
				break;
			}
			nlsah++;
			if (flags & F_DTAIL) {
				ospf6_print_ls_type(flags, ntohl(lsr->ls_type),
				    lsr->ls_stateid, lsr->ls_router);
			}
			++lsr;
		}
		if (flags & F_SUM) {
			sprintf(sum_line, "%d LSAs", nlsah);
			sum_line += strlen(sum_line);
		}
		break;

	case OSPF_TYPE_LSU:
		if (fraglen < OSPF6_MIN_HEADER_SIZE +
		    OSPF_MIN_LSU_HEADER_SIZE) {
			trunc = B_TRUE;
			break;
		}
		if (flags & F_DTAIL) {
			show_header("OSPF LSU:  ", "Link State Update Packet",
			    fraglen);
			show_space();
		}
		lsa = ospf->ospf6_lsu.lsu_lsa;
		nlsa = ntohl(ospf->ospf6_lsu.lsu_count);
		if (flags & F_SUM) {
			sprintf(sum_line, "%d LSAs", nlsa);
			sum_line += strlen(sum_line);
			break;
		}
		while (nlsa-- != 0) {
			uchar_t *fragend = (uchar_t *)ospf + fraglen;
			if (((uchar_t *)lsa >= fragend) ||
			    ((uchar_t *)lsa + sizeof (struct lsa_hdr) >
			    fragend) ||
			    ((uchar_t *)lsa + ntohs(lsa->ls6_hdr.ls6_length) >
			    fragend)) {
				trunc = B_TRUE;
				break;
			}

			if (interpret_ospf6_lsa(flags, lsa, fragend) < 0) {
				trunc = B_TRUE;
				break;
			}
			lsa = (struct lsa6 *)((uchar_t *)lsa +
			    ntohs(lsa->ls6_hdr.ls6_length));
		}
		break;

	case OSPF_TYPE_LSA:
		if (flags & F_DTAIL) {
			show_header("OSPF LSA:  ", "Link State Ack Packet",
			    fraglen);
			show_space();
		}
		lsah = ospf->ospf6_lsa.lsa_lshdr;
		nlsah = 0;
		while ((uchar_t *)lsah < ((uchar_t *)ospf + fraglen)) {
			if ((uchar_t *)lsah + sizeof (struct lsa6_hdr) >
			    ((uchar_t *)ospf + fraglen)) {
				trunc = B_TRUE;
				break;
			}
			nlsah++;
			if (flags & F_DTAIL)
				interpret_ospf6_lsa_hdr(flags, lsah);
			++lsah;
		}
		if (flags & F_SUM) {
			sprintf(sum_line, "%d LSAs", nlsah);
			sum_line += strlen(sum_line);
		}
		break;

	default:
		/* NOTREACHED */
		break;
	}
	if (trunc) {
		if (flags & F_SUM)
			sprintf(sum_line, "--truncated");
		if (flags & F_DTAIL)
			snprintf(get_line(0, 0), get_line_remain(),
			    "--truncated");
	}

	return (fraglen);
}

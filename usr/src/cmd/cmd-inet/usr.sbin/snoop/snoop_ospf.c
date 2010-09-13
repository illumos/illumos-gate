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

char *ospf_types[] = {
	"umd", 		/* 0 */
	"Hello",	/* 1 */
	"DD",		/* 2 */
	"LSReq",	/* 3 */
	"LSUpd",	/* 4 */
	"LSAck",	/* 5 */
};

static char *ospf_authtypes[] = {
	"None", 	/* 0 */
	"simple",	/* 1 */
	"md5",		/* 2 */
};

const struct bits ospf_rla_flag_bits[] = {
	{ RLA_FLAG_B,		"B" },
	{ RLA_FLAG_E,		"E" },
	{ RLA_FLAG_V,		"V" },
	{ RLA_FLAG_W,		"W" },
	{ 0, 			NULL }
};

const struct bits ospf_db_flags_bits[] = {
	{ OSPF_DB_INIT,		"I" },
	{ OSPF_DB_MORE,		"M" },
	{ OSPF_DB_MASTER,	"MS" },
	{ 0, 			NULL }
};

const struct bits ospf_option_bits[] = {
	{ OSPF_OPTION_T,	"T" },
	{ OSPF_OPTION_E,	"E" },
	{ OSPF_OPTION_MC,	"MC" },
	{ 0,			NULL }
};

static int interpret_ospf_hello(int, struct ospfhdr *, int);
static void ospf_print_ls_type(int, uint32_t, struct in_addr, struct in_addr);
static void interpret_ospf_lsa_hdr(int, struct lsa_hdr *);
static int interpret_ospf_lsa(int flags, struct lsa *lsa, uchar_t *);

char *
ospf_print_bits(const struct bits *bp, uchar_t options)
{
	static char bitstring[32];

	bitstring[0] = '\0';
	do {
		if (options & bp->bit) {
			strcat(bitstring, bp->str);
			strcat(bitstring, "/");
		}
	} while ((++bp)->bit);

	/* wipe out the trailing "/" */
	bitstring[strlen(bitstring) - 1] = '\0';
	return (bitstring);
}

char *
ospf_print_lsa_age(long age)
{
	long sec, mins, hour;
	static char lsa_age[16];

	sec = age % 60;
	mins = (age / 60) % 60;
	hour = age / 3600;
	if (hour != 0)
		snprintf(lsa_age, sizeof (lsa_age), "%u:%02u:%02u",
		    hour, mins, sec);
	else if (mins != 0)
		snprintf(lsa_age, sizeof (lsa_age), "%u:%02u", mins, sec);
	else
		snprintf(lsa_age, sizeof (lsa_age), "%u", sec);
	return (lsa_age);
}

static int
interpret_ospf_hello(int flags, struct ospfhdr *op, int fraglen)
{
	struct in_addr *nbr;
	int j;

	if (fraglen < OSPF_MIN_HEADER_SIZE + OSPF_MIN_HELLO_HEADER_SIZE)
		return (-1); /* truncated packet */

	if (flags & F_SUM) {
		if (op->ospf_hello.hello_dr.s_addr != 0) {
			(void) sprintf(sum_line, "DR=%s ",
			    inet_ntoa(op->ospf_hello.hello_dr));
		}
		sum_line += strlen(sum_line);
		if (op->ospf_hello.hello_bdr.s_addr != 0) {
			(void) sprintf(sum_line, "BDR=%s ",
			    inet_ntoa(op->ospf_hello.hello_bdr));
		}
		sum_line += strlen(sum_line);
		nbr = op->ospf_hello.hello_neighbor;
		j = 0;
		while ((uchar_t *)nbr < ((uchar_t *)op + fraglen)) {
			if ((uchar_t *)nbr + sizeof (struct in_addr) >
			    ((uchar_t *)op + fraglen))
				return (-1); /* truncated */
			j++;
			++nbr;
		}
		(void) sprintf(sum_line, "%d nbrs", j);
		sum_line += strlen(sum_line);

	}
	if (flags & F_DTAIL) {
		show_header("OSPF HELLO:  ", "Hello Packet",
		    ntohs(op->ospf_len));
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Options = %s", ospf_print_bits(ospf_option_bits,
		    op->ospf_hello.hello_options));
		(void) snprintf(get_line(0, 0), get_line_remain(), "Mask = %s",
		    inet_ntoa(op->ospf_hello.hello_mask));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Hello interval = %d",
		    ntohs(op->ospf_hello.hello_helloint));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Priority = %d", op->ospf_hello.hello_priority);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Dead interval = %u", ntohl(op->ospf_hello.hello_deadint));
		if (op->ospf_hello.hello_dr.s_addr != 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Designated Router = %s",
			    inet_ntoa(op->ospf_hello.hello_dr));
		}
		if (op->ospf_hello.hello_bdr.s_addr != 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Backup Designated Router = %s",
			    inet_ntoa(op->ospf_hello.hello_bdr));
		}
		nbr = op->ospf_hello.hello_neighbor;
		while ((uchar_t *)nbr < ((uchar_t *)op + fraglen)) {
			if ((uchar_t *)nbr + sizeof (struct in_addr) >
			    ((uchar_t *)op + fraglen))
				return (-1); /* truncated */
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Neighbor: %s", inet_ntoa(*nbr));
			++nbr;
		}
	}
	return (fraglen);
}

static void
ospf_print_ls_type(int flags, uint32_t ls_type, struct in_addr ls_stateid,
    struct in_addr ls_router)
{
	switch (ls_type) {
	case LS_TYPE_ROUTER:
		if (flags & F_SUM) {
			sprintf(sum_line, " rtr %s ", inet_ntoa(ls_router));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Router LSA; Router = %s ", inet_ntoa(ls_router));
		}
		break;
	case LS_TYPE_NETWORK:
		if (flags & F_SUM) {
			sprintf(sum_line, " net dr %s ", inet_ntoa(ls_router));
			sum_line += strlen(sum_line);
			sprintf(sum_line, "if %s ", inet_ntoa(ls_stateid));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Network LSA Router = %s ", inet_ntoa(ls_router));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "            Interface = %s ",
			    inet_ntoa(ls_stateid));
		}
		break;
	case LS_TYPE_SUM_IP:
		if (flags & F_SUM) {
			sprintf(sum_line, " sum %s ", inet_ntoa(ls_stateid));
			sum_line += strlen(sum_line);
			sprintf(sum_line, "abr %s ", inet_ntoa(ls_router));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Summary LSA IP = %s ", inet_ntoa(ls_stateid));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "            Area Border Router = %s ",
			    inet_ntoa(ls_router));
		}
		break;
	case LS_TYPE_SUM_ABR:
		if (flags & F_SUM) {
			sprintf(sum_line, "abr %s ", inet_ntoa(ls_stateid));
			sum_line += strlen(sum_line);
			sprintf(sum_line, "asbr %s ", inet_ntoa(ls_router));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "ASBR Summary abr = %s ", inet_ntoa(ls_stateid));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "             asbr = %s ", inet_ntoa(ls_router));
		}
		break;
	case LS_TYPE_ASE:
		if (flags & F_SUM) {
			sprintf(sum_line, " ase %s", inet_ntoa(ls_stateid));
			sum_line += strlen(sum_line);
			sprintf(sum_line, " asbr %s", inet_ntoa(ls_router));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "AS External LSA ase = %s ", inet_ntoa(ls_stateid));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "                asbr = %s ", inet_ntoa(ls_router));
		}

		break;
	case LS_TYPE_GROUP:
		if (flags & F_SUM) {
			sprintf(sum_line, " group %s", inet_ntoa(ls_stateid));
			sum_line += strlen(sum_line);
			sprintf(sum_line, " rtr %s", inet_ntoa(ls_router));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Group LSA %s ", inet_ntoa(ls_stateid));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "          rtr = %s ", inet_ntoa(ls_router));
		}
		break;
	default:
		if (flags & F_SUM) {
			sprintf(sum_line, " unknown LSA type %d", ls_type);
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Unknown LSA type %d", ls_type);
		}
		break;
	}
}

static void
interpret_ospf_lsa_hdr(int flags, struct lsa_hdr *lsah)
{
	if (flags & F_SUM)
		return;

	if (flags & F_DTAIL) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Options = %s",
		    ospf_print_bits(ospf_option_bits, lsah->ls_options));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Sequence = %X ", ntohl(lsah->ls_seq));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Age = %X ", ospf_print_lsa_age(ntohs(lsah->ls_age)));
	}

	ospf_print_ls_type(flags, lsah->ls_type, lsah->ls_stateid,
	    lsah->ls_router);

}

#define	TRUNC(addr)	((uchar_t *)(addr) > fragend)
static int
interpret_ospf_lsa(int flags, struct lsa *lsa, uchar_t *fragend)
{
	uchar_t *ls_end;
	int rla_count, k;
	struct rlalink *rl;
	struct tos_metric *tosp;
	struct in_addr *addr;
	uint32_t *tosmetric;
	struct aslametric *am;
	uint32_t tm;
	int tos, metric;

	interpret_ospf_lsa_hdr(flags, &lsa->ls_hdr);

	ls_end = (uchar_t *)lsa + ntohs(lsa->ls_hdr.ls_length);

	if (TRUNC(ls_end))
		return (-1);

	switch (lsa->ls_hdr.ls_type) {

	case LS_TYPE_ROUTER:
		if (TRUNC(&lsa->lsa_un.un_rla.rla_flags))
			return (-1);

		if (flags & F_DTAIL) {
			(void) ospf_print_bits(ospf_rla_flag_bits,
			    lsa->lsa_un.un_rla.rla_flags);
		}

		if (TRUNC(&lsa->lsa_un.un_rla.rla_count))
			return (-1);
		rla_count = ntohs(lsa->lsa_un.un_rla.rla_count);

		rl = lsa->lsa_un.un_rla.rla_link;
		if (TRUNC(rl))
			return (-1);

		while (rla_count-- != 0) {
			if (TRUNC((uchar_t *)rl + sizeof (*rl)))
				return (-1);
			switch (rl->link_type) {
			case RLA_TYPE_VIRTUAL:
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Virtual Link");
				}
				/* fall through */
			case RLA_TYPE_ROUTER:
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Neighbor = %s",
					    inet_ntoa(rl->link_id));
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Interface = %s",
					    inet_ntoa(rl->link_data));
				}
				break;
			case RLA_TYPE_TRANSIT:
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "Designated Router = %s",
					    inet_ntoa(rl->link_id));
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Interface = %s",
					    inet_ntoa(rl->link_data));
				}
				break;
			case RLA_TYPE_STUB:
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Network = %s",
					    inet_ntoa(rl->link_id));
					(void) snprintf(get_line(0, 0),
					    get_line_remain(), "Mask = %s",
					    inet_ntoa(rl->link_data));
				}
				break;
			default:
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "Unknown link type %d",
					    rl->link_type);
				}

			}
			if (flags & F_DTAIL) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(), "TOS 0 metric = %d",
				    ntohs(rl->link_tos0metric));
			}
			tosp = (struct tos_metric *)(
				(uchar_t *)rl + sizeof (rl->link_tos0metric));
			for (k = 0; k > (int)rl->link_toscount; ++k, ++tosp) {
				if (TRUNC(tosp))
					return (-1);
				if (flags & F_DTAIL) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "TOS %d metric = %d",
					    tosp->tos_type,
					    ntohs(tosp->tos_metric));
				}

			}
			rl = (struct rlalink *)((uchar_t *)(rl + 1) +
			    ((rl->link_toscount) * sizeof (*tosp)));
			if (TRUNC(rl))
				return (-1); /* truncated */
		}
		break;
	case LS_TYPE_NETWORK:

		if (TRUNC(&lsa->lsa_un.un_nla.nla_mask))
			return (-1);

		if (flags & F_DTAIL) {
			snprintf(get_line(0, 0), get_line_remain(),
			    "Mask = %s",
			    inet_ntoa(lsa->lsa_un.un_nla.nla_mask));
			snprintf(get_line(0, 0), get_line_remain(),
			    "Routers:");
		}
		addr = lsa->lsa_un.un_nla.nla_router;
		while ((uchar_t *)addr < ls_end) {
			if ((uchar_t *)addr + sizeof (struct in_addr) > ls_end)
				return (-1); /* truncated */
			if (flags & F_DTAIL) {
				snprintf(get_line(0, 0), get_line_remain(),
				    "\t%s", inet_ntoa(*addr));
			}
			++addr;
		}
		break;
	case LS_TYPE_SUM_IP:

		if (TRUNC((uchar_t *)&lsa->lsa_un.un_sla.sla_mask +
		    sizeof (struct in_addr)))
			return (-1);

		if (flags & F_DTAIL) {
			snprintf(get_line(0, 0), get_line_remain(), "Mask = %s",
			    inet_ntoa(lsa->lsa_un.un_sla.sla_mask));
		}
		/* FALLTHROUGH */
	case LS_TYPE_SUM_ABR:
		if (TRUNC(&lsa->lsa_un.un_sla.sla_tosmetric))
			return (-1);
		tosmetric = lsa->lsa_un.un_sla.sla_tosmetric;
		while ((uchar_t *)tosmetric < ls_end) {
			if ((uchar_t *)tosmetric + sizeof (tm) > fragend)
				return (-1); /* truncated */
			tm = ntohl(*tosmetric);
			tos = (tm & SLA_MASK_TOS) >> SLA_SHIFT_TOS;
			metric = tm & SLA_MASK_METRIC;
			if (flags & F_DTAIL) {
				snprintf(get_line(0, 0), get_line_remain(),
				    " tos %d metric %d", tos, metric);
			}
			++tosmetric;
		}
		break;
	case LS_TYPE_ASE:
		if (TRUNC(&lsa->lsa_un.un_asla.asla_mask))
			return (-1);
		if (flags & F_DTAIL) {
			snprintf(get_line(0, 0), get_line_remain(), "Mask = %s",
			    inet_ntoa(lsa->lsa_un.un_asla.asla_mask));
		}
		am = lsa->lsa_un.un_asla.asla_metric;
		while ((uchar_t *)am < ls_end) {
			if ((uchar_t *)am + sizeof (tm) > fragend)
				return (-1); /* truncated */
			tm = ntohl(am->asla_tosmetric);
			tos = (tm & ASLA_MASK_TOS) >> ASLA_SHIFT_TOS;
			metric = tm & ASLA_MASK_METRIC;
			if (flags & F_DTAIL) {
				snprintf(get_line(0, 0), get_line_remain(),
				    " type %d tos %d metric %d",
				    (tm & ASLA_FLAG_EXTERNAL) ? 2 : 1,
				    tos, metric);
			}
			if (am->asla_forward.s_addr != 0) {
				if (flags & F_DTAIL)  {
					snprintf(get_line(0, 0),
					    get_line_remain(), " Forward %s",
					    inet_ntoa(am->asla_forward));
				}
			}
			if (am->asla_tag.s_addr != 0) {
				if (flags & F_DTAIL)  {
					snprintf(get_line(0, 0),
					    get_line_remain(), " Tag %s",
					    inet_ntoa(am->asla_tag));
				}
			}
			++am;
		}
		break;
	default:
		if (flags & F_DTAIL)  {
			snprintf(get_line(0, 0), get_line_remain(),
			    " Unknown LSA type %d", lsa->ls_hdr.ls_type);

		}
		break;
	}
	return (0);
}
#undef TRUNC

int
interpret_ospf(int flags, struct ospfhdr *ospf, int iplen, int fraglen)
{
	int nlsa, nlsah = 0;
	struct lsa_hdr *lsah;
	struct lsr *lsr;
	struct lsa *lsa;
	boolean_t trunc = B_FALSE;

	if ((fraglen < OSPF_MIN_HEADER_SIZE) ||
	    (fraglen < ntohs(ospf->ospf_len)))
		return (fraglen);	/* incomplete header */

	if (fraglen > ntohs(ospf->ospf_len))
		fraglen = ntohs(ospf->ospf_len);


	if (ospf->ospf_type > OSPF_TYPE_MAX) {
		if (flags & F_SUM) {
			(void) sprintf(sum_line, "Unknown OSPF TYPE %d \n",
			    ospf->ospf_type);
			sum_line += strlen(sum_line);
		}
		if (flags & F_SUM) {
			show_header("OSPF:  ", "OSPF Header", fraglen);
			show_space();
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Unknown OSPF Type = %d", ospf->ospf_type);
		}
		return (fraglen);
	}

	if (flags & F_SUM) {
		sum_line = (char *)get_sum_line();
		(void) sprintf(sum_line, "OSPF %s RTRID=%s ",
		    ospf_types[ospf->ospf_type],
		    inet_ntoa(ospf->ospf_routerid));
		sum_line += strlen(sum_line);
		(void) sprintf(sum_line, "AREA=%s LEN=%d ",
		    inet_ntoa(ospf->ospf_areaid),
		    ntohs((ushort_t)ospf->ospf_len));
		sum_line += strlen(sum_line);
	}

	if (flags & F_DTAIL) {
		show_header("OSPF:  ", "OSPF Header", fraglen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Version = %d", ospf->ospf_version);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Type = %s", ospf_types[ospf->ospf_type]);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Router ID = %s", inet_ntoa(ospf->ospf_routerid));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Area ID = %s", inet_ntoa(ospf->ospf_areaid));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Checksum = 0x%x", ospf->ospf_chksum);

		if (ospf->ospf_authtype > OSPF_AUTH_TYPE_MAX) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Auth = %d (unknown auth type)",
			    ospf->ospf_authtype);
		} else {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Auth = %s", ospf_authtypes[ospf->ospf_authtype]);
		}
	}

	if (ospf->ospf_version != 2) {
		if (ospf->ospf_version == 3) {
			if (flags & F_DTAIL)
				snprintf(get_line(0, 0), get_line_remain(),
				    "ospfv3 packet in ipv4 header");
			return (interpret_ospf6(flags, ospf, iplen, fraglen));
		} else  {
			return (fraglen);
		}
	}

	switch (ospf->ospf_type) {
	case OSPF_TYPE_HELLO:
		if (interpret_ospf_hello(flags, ospf, fraglen) < 0)
			trunc = B_TRUE;
		break;

	case OSPF_TYPE_DB:
		if (fraglen < OSPF_MIN_HEADER_SIZE + OSPF_MIN_DB_HEADER_SIZE) {
			trunc = B_TRUE;
			break;
		}
		if (flags & F_SUM) {
			sprintf(sum_line, " %s %s S %X", ospf_print_bits(
			    ospf_option_bits, ospf->ospf_db.db_options),
			    ospf_print_bits(ospf_db_flags_bits,
			    ospf->ospf_db.db_flags),
			    ntohl(ospf->ospf_db.db_seq));
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL) {
			show_header("OSPF DB:  ", "Database Description Packet",
			    fraglen);
			show_space();
			snprintf(get_line(0, 0), get_line_remain(),
			    "Options = %s", ospf_print_bits(
			    ospf_option_bits, ospf->ospf_db.db_options));
			snprintf(get_line(0, 0), get_line_remain(),
			    "Flags = %s", ospf_print_bits(
			    ospf_db_flags_bits, ospf->ospf_db.db_flags));
			snprintf(get_line(0, 0), get_line_remain(),
			    "Sequence = 0x%X", ntohl(ospf->ospf_db.db_seq));
			/*  Print all the LS advs */
			lsah = ospf->ospf_db.db_lshdr;
			while ((uchar_t *)lsah < ((uchar_t *)ospf + fraglen)) {
				if ((uchar_t *)lsah + sizeof (struct lsa_hdr) >
				    ((uchar_t *)ospf + fraglen)) {
					trunc = B_TRUE;
					break;
				}
				interpret_ospf_lsa_hdr(flags, lsah);
				++lsah;
			}
		}
		break;

	case OSPF_TYPE_LSR:
		if (fraglen < OSPF_MIN_HEADER_SIZE + OSPF_MIN_LSR_HEADER_SIZE) {
			trunc = B_TRUE;
			break;
		}
		if (flags & F_DTAIL) {
			snprintf(get_line(0, 0), get_line_remain(),
			    "Link State Request Packet");
		}
		lsr = ospf->ospf_lsr;
		while ((uchar_t *)lsr < ((uchar_t *)ospf + fraglen)) {
			if ((uchar_t *)lsr + sizeof (struct lsr) >
			    ((uchar_t *)ospf + fraglen)) {
				trunc = B_TRUE;
				break;
			}
			if (flags & F_SUM) {
				nlsah++;
			}
			if (flags & F_DTAIL) {
				ospf_print_ls_type(flags, ntohl(lsr->ls_type),
				    lsr->ls_stateid, lsr->ls_router);
			}
			++lsr;
		}
		if (flags & F_SUM) {
			sprintf(sum_line, " %d LSAs", nlsah);
			sum_line += strlen(sum_line);
		}
		break;

	case OSPF_TYPE_LSU:
		if (fraglen < OSPF_MIN_HEADER_SIZE + OSPF_MIN_LSU_HEADER_SIZE) {
			trunc = B_TRUE;
			break;
		}
		if (flags & F_DTAIL) {
			show_header("OSPF LSU:  ", "Link State Update Packet",
			    fraglen);
			show_space();
		}
		lsa = ospf->ospf_lsu.lsu_lsa;
		nlsa = ntohl(ospf->ospf_lsu.lsu_count);
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
			    ((uchar_t *)lsa + ntohs(lsa->ls_hdr.ls_length) >
			    fragend)) {
				trunc = B_TRUE;
				break;
			}

			if (interpret_ospf_lsa(flags, lsa, fragend) < 0) {
				trunc = B_TRUE;
				break;
			}
			lsa = (struct lsa *)((uchar_t *)lsa +
			    ntohs(lsa->ls_hdr.ls_length));
		}

		break;

	case OSPF_TYPE_LSA:
		if (flags & F_DTAIL) {
			show_header("OSPF LSA:  ", "Link State Ack Packet",
			    fraglen);
			show_space();
		}
		lsah = ospf->ospf_lsa.lsa_lshdr;
		nlsah = 0;
		while ((uchar_t *)lsah < ((uchar_t *)ospf + fraglen)) {
			if ((uchar_t *)lsah + sizeof (struct lsa_hdr) >
			    ((uchar_t *)ospf + fraglen)) {
				trunc = B_TRUE;
				break;
			}
			nlsah++;
			if (flags & F_DTAIL)
				interpret_ospf_lsa_hdr(flags, lsah);
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
		if (flags & F_SUM) {
			sprintf(sum_line, "--truncated");
			sum_line += strlen(sum_line);
		}
		if (flags & F_DTAIL)
			snprintf(get_line(0, 0), get_line_remain(),
			    "--truncated");
	}

	return (fraglen);
}

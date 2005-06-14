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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <inet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "snoop.h"

static void interpret_igmpv3qry(struct igmp *, int);
static void interpret_igmpv3rpt(struct igmp *, int);


/*ARGSUSED*/
void
interpret_igmp(int flags, char *data, int iplen, int ilen)
{
	const char *pt;
	char *line;
	struct igmp *igmp = (struct igmp *)data;
	char addrstr[INET_ADDRSTRLEN];

	if (ilen < IGMP_MINLEN) {
		/* incomplete header */
		line = get_sum_line();
		(void) snprintf(line, MAXLINE, "Malformed IGMP packet");
		return;
	}

	switch (igmp->igmp_type) {
	case IGMP_MEMBERSHIP_QUERY:
		if (ilen == IGMP_MINLEN) {
			if (igmp->igmp_code == 0)
				pt = "v1 membership query";
			else
				pt = "v2 membership query";
		} else if (ilen >= IGMP_V3_QUERY_MINLEN) {
			pt = "v3 membership query";
		} else {
			pt = "Unknown membership query";
		}
		break;
	case IGMP_V1_MEMBERSHIP_REPORT:
		pt = "v1 membership report";
		break;
	case IGMP_V2_MEMBERSHIP_REPORT:
		pt = "v2 membership report";
		break;
	case IGMP_V3_MEMBERSHIP_REPORT:
		pt = "v3 membership report";
		break;
	case IGMP_V2_LEAVE_GROUP:
		pt = "v2 leave group";
		break;

	default:
		pt = "Unknown";
		break;
	}

	if (flags & F_SUM) {
		line = get_sum_line();
		(void) snprintf(line, MAXLINE, "IGMP %s", pt);
	}

	if (flags & F_DTAIL) {
		show_header("IGMP:  ", "IGMP Header", ilen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Type = %d (%s)", igmp->igmp_type, pt);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Max Response Time = %d", igmp->igmp_code);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Checksum = %x", ntohs(igmp->igmp_cksum));

		if (igmp->igmp_type == IGMP_MEMBERSHIP_QUERY &&
		    ilen >= IGMP_V3_QUERY_MINLEN) {
			interpret_igmpv3qry(igmp, ilen);
		} else if (igmp->igmp_type == IGMP_V3_MEMBERSHIP_REPORT) {
			interpret_igmpv3rpt(igmp, ilen);
		} else {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Group = %s",
			    inet_ntop(AF_INET, &igmp->igmp_group.s_addr,
			    addrstr, INET_ADDRSTRLEN));
		}

		show_space();
	}
}

static void
interpret_igmpv3qry(struct igmp *igmp, int ilen)
{
	struct igmp3q *qry;
	struct in_addr *src;
	int rem = ilen;
	int srccnt;
	char addrstr[INET_ADDRSTRLEN];

	if (ilen < sizeof (*qry)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Malformed IGMP Query");
		return;
	}

	qry = (struct igmp3q *)igmp;
	rem -= sizeof (*qry);
	srccnt = ntohs(qry->igmp3q_numsrc);
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "Group = %s", inet_ntop(AF_INET, &qry->igmp3q_group, addrstr,
	    INET_ADDRSTRLEN));
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "%d Source Address%s:", srccnt, (srccnt == 1) ? "" : "es");

	src = (struct in_addr *)&qry[1];
	while (srccnt > 0 && rem >= sizeof (*src)) {
		rem -= sizeof (*src);

		(void) snprintf(get_line(0, 0), get_line_remain(), "    %s",
		    inet_ntop(AF_INET, &src->s_addr, addrstr, INET_ADDRSTRLEN));

		srccnt--;
		src++;
	}
}

#define	MAX_IGMPV3_REPORT_TYPE	6

const char *igmpv3rpt_types[] = {
	"<unknown>",
	"MODE_IS_INCLUDE",
	"MODE_IS_EXCLUDE",
	"CHANGE_TO_INCLUDE",
	"CHANGE_TO_EXCLUDE",
	"ALLOW_NEW_SOURCES",
	"BLOCK_OLD_SOURCES",
};

static void
interpret_igmpv3rpt(struct igmp *igmp, int ilen)
{
	struct igmp3r *rpt;
	struct grphdr *grh;
	struct in_addr *src;
	int rem = ilen, auxlen;
	uint16_t grhcnt, srccnt;
	char addrstr[INET_ADDRSTRLEN];

	if (ilen < sizeof (*rpt)) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Malformed IGMPv3 Report");
		return;
	}

	rpt = (struct igmp3r *)igmp;
	grh = (struct grphdr *)&rpt[1];
	grhcnt = ntohs(rpt->igmp3r_numrec);
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "%d Group Record%s:", grhcnt, (grhcnt == 1) ? "" : "s");
	rem -= sizeof (*rpt);
	while (grhcnt > 0 && rem >= sizeof (*grh)) {
		rem -= sizeof (*grh);

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Group = %s  type = %s", inet_ntop(AF_INET,
		    &grh->grphdr_group.s_addr, addrstr, INET_ADDRSTRLEN),
		    (grh->grphdr_type > MAX_IGMPV3_REPORT_TYPE) ?
		    "<unknown>" : igmpv3rpt_types[grh->grphdr_type]);
		srccnt = ntohs(grh->grphdr_numsrc);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "%d Source Address%s:", srccnt, (srccnt == 1) ? "" : "es");

		src = (struct in_addr *)&grh[1];
		while (srccnt > 0 && rem >= sizeof (*src)) {
			rem -= sizeof (*src);

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "    %s", inet_ntop(AF_INET, &src->s_addr, addrstr,
			    INET_ADDRSTRLEN));

			srccnt--;
			src++;
		}

		grhcnt--;
		auxlen = grh->grphdr_auxlen * 4;
		rem -= auxlen;
		grh = (struct grphdr *)((uint8_t *)src + auxlen);
	}
}

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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS */

#include <ctype.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <inet/led.h>
#include <inet/ip6.h>
#include <arpa/inet.h>
#include <protocols/routed.h>
#include <protocols/ripngd.h>
#include "snoop.h"

extern char *dlc_header;
static char *show_cmd6();

static struct in6_addr all_zeroes_addr = { {	0x0, 0x0, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x0 } };

int
interpret_rip6(int flags, struct rip6 *rip6, int fraglen)
{
	char *p;
	struct netinfo6 *n;
	int len, count;
	struct in6_addr *dst;
	int notdefault = 0;
	char dststr[INET6_ADDRSTRLEN];

	if (flags & F_SUM) {
		switch (rip6->rip6_cmd) {
		case RIPCMD6_REQUEST:	p = "C";		break;
		case RIPCMD6_RESPONSE:	p = "R";		break;
		default: p = "?"; break;
		}

		switch (rip6->rip6_cmd) {
		case RIPCMD6_REQUEST:
		case RIPCMD6_RESPONSE:
			len = fraglen - 4;
			count = 0;
			for (n = rip6->rip6_nets;
			    len >= sizeof (struct netinfo6); n++) {
				count++;
				len -= sizeof (struct netinfo6);
			}
			(void) sprintf(get_sum_line(),
			    "RIPng %s (%d destinations)", p, count);
			break;
		default:
			(void) sprintf(get_sum_line(), "RIPng %s", p);
			break;
		}
	}

	if (flags & F_DTAIL) {

		show_header("RIPng:  ", "Routing Information Protocol for IPv6",
		    fraglen);
		show_space();
		(void) sprintf(get_line((char *)(uintptr_t)rip6->rip6_cmd -
		    dlc_header, 1), "Opcode = %d (%s)", rip6->rip6_cmd,
		    show_cmd6(rip6->rip6_cmd));
		(void) sprintf(get_line((char *)(uintptr_t)rip6->rip6_vers -
		    dlc_header, 1), "Version = %d", rip6->rip6_vers);

		switch (rip6->rip6_cmd) {
		case RIPCMD6_REQUEST:
		case RIPCMD6_RESPONSE:
			show_space();
			(void) sprintf(get_line(0, 0), "Address"
			    "                       Prefix        Metric");
			len = fraglen - 4;
			for (n = rip6->rip6_nets;
			    len >= sizeof (struct netinfo6); n++) {
				if (rip6->rip6_vers > 0) {
					n->rip6_metric = n->rip6_metric;
				}
				dst = &n->rip6_prefix;
				notdefault = bcmp((caddr_t *)dst,
				    (caddr_t *)&all_zeroes_addr, sizeof (*dst));
				(void) inet_ntop(AF_INET6, (char *)dst, dststr,
				    INET6_ADDRSTRLEN);
				(void) sprintf(get_line((char *)n - dlc_header,
				    sizeof (struct netinfo6)),
				    "%-30s %-10d     %-5d %s",
				    notdefault ? dststr :
				    " (default)", n->rip6_prefix_length,
				    n->rip6_metric, n->rip6_metric == 16 ?
				    " (not reachable)":"");
				len -= sizeof (struct netinfo);
			}
			break;
		}
	}
	return (fraglen);
}

static char *
show_cmd6(c)
	int c;
{
	switch (c) {
	case RIPCMD6_REQUEST:	return ("route request");
	case RIPCMD6_RESPONSE:	return ("route response");
	}
	return ("?");
}

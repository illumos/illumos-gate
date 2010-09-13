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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"
#include "tables.h"

static void	print_opt(struct nd_opt_hdr *opt, int len);

void
print_route_sol(char *str, struct phyint *pi,
    struct nd_router_solicit *rs, int len, struct sockaddr_in6 *addr)
{
	struct nd_opt_hdr *opt;
	char abuf[INET6_ADDRSTRLEN];

	logmsg(LOG_DEBUG, "%s %s (%d bytes) on %s\n", str,
	    inet_ntop(addr->sin6_family, (void *)&addr->sin6_addr,
	    abuf, sizeof (abuf)),
	    len, pi->pi_name);

	len -= sizeof (*rs);
	opt = (struct nd_opt_hdr *)&rs[1];
	print_opt(opt, len);
}

void
print_route_adv(char *str, struct phyint *pi,
    struct nd_router_advert *ra, int len, struct sockaddr_in6 *addr)
{
	struct nd_opt_hdr *opt;
	char abuf[INET6_ADDRSTRLEN];

	logmsg(LOG_DEBUG, "%s %s (%d bytes) on %s\n", str,
	    inet_ntop(addr->sin6_family, (void *)&addr->sin6_addr,
	    abuf, sizeof (abuf)),
	    len, pi->pi_name);
	logmsg(LOG_DEBUG, "\tMax hop limit: %u\n", ra->nd_ra_curhoplimit);
	logmsg(LOG_DEBUG, "\tManaged address configuration: %s\n",
	    (ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED) ?
	    "Set" : "Not set");
	logmsg(LOG_DEBUG, "\tOther configuration flag: %s\n",
	    (ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER) ?
	    "Set" : "Not set");
	logmsg(LOG_DEBUG, "\tRouter lifetime: %u\n",
	    ntohs(ra->nd_ra_router_lifetime));
	logmsg(LOG_DEBUG, "\tReachable timer: %u\n",
	    ntohl(ra->nd_ra_reachable));
	logmsg(LOG_DEBUG, "\tReachable retrans timer: %u\n",
	    ntohl(ra->nd_ra_retransmit));

	len -= sizeof (*ra);
	opt = (struct nd_opt_hdr *)&ra[1];
	print_opt(opt, len);
}

static void
print_opt(struct nd_opt_hdr *opt, int len)
{
	struct nd_opt_prefix_info *po;
	struct nd_opt_mtu *mo;
	struct nd_opt_lla *lo;
	int optlen;
	char abuf[INET6_ADDRSTRLEN];
	char llabuf[BUFSIZ];

	while (len >= sizeof (struct nd_opt_hdr)) {
		optlen = opt->nd_opt_len * 8;
		if (optlen == 0) {
			logmsg(LOG_DEBUG, "Zero length option!\n");
			break;
		}
		switch (opt->nd_opt_type) {
		case ND_OPT_PREFIX_INFORMATION:
			po = (struct nd_opt_prefix_info *)opt;
			if (optlen != sizeof (*po) ||
			    optlen > len)
				break;

			logmsg(LOG_DEBUG, "\tPrefix: %s/%u\n",
			    inet_ntop(AF_INET6, (void *)&po->nd_opt_pi_prefix,
			    abuf, sizeof (abuf)),
			    po->nd_opt_pi_prefix_len);
			logmsg(LOG_DEBUG, "\t\tOn link flag:%s\n",
			    (po->nd_opt_pi_flags_reserved &
			    ND_OPT_PI_FLAG_ONLINK) ?
			    "Set" : "Not set");
			logmsg(LOG_DEBUG, "\t\tAuto addrconf flag:%s\n",
			    (po->nd_opt_pi_flags_reserved &
			    ND_OPT_PI_FLAG_AUTO) ?
			    "Set" : "Not set");
			logmsg(LOG_DEBUG, "\t\tValid time: %u\n",
			    ntohl(po->nd_opt_pi_valid_time));
			logmsg(LOG_DEBUG, "\t\tPreferred time: %u\n",
			    ntohl(po->nd_opt_pi_preferred_time));
			break;
		case ND_OPT_MTU:
			mo = (struct nd_opt_mtu *)opt;
			if (optlen != sizeof (*mo) ||
			    optlen > len)
				break;
			logmsg(LOG_DEBUG, "\tMTU: %d\n",
			    ntohl(mo->nd_opt_mtu_mtu));
			break;
		case ND_OPT_SOURCE_LINKADDR:
			lo = (struct nd_opt_lla *)opt;
			if (optlen < 8 ||
			    optlen > len)
				break;
			(void) fmt_lla(llabuf, sizeof (llabuf),
			    lo->nd_opt_lla_hdw_addr,
			    optlen - sizeof (nd_opt_hdr_t));
			logmsg(LOG_DEBUG, "\tSource LLA: len %d <%s>\n",
			    optlen - sizeof (nd_opt_hdr_t),
			    llabuf);
			break;
		case ND_OPT_TARGET_LINKADDR:
			lo = (struct nd_opt_lla *)opt;
			if (optlen < 8||
			    optlen > len)
				break;
			(void) fmt_lla(llabuf, sizeof (llabuf),
			    lo->nd_opt_lla_hdw_addr,
			    optlen - sizeof (nd_opt_hdr_t));
			logmsg(LOG_DEBUG, "\tTarget LLA: len %d <%s>\n",
			    optlen - sizeof (nd_opt_hdr_t),
			    llabuf);
			break;
		case ND_OPT_REDIRECTED_HEADER:
			logmsg(LOG_DEBUG, "\tRedirected header option!\n");
			break;
		default:
			logmsg(LOG_DEBUG, "Unknown option %d (0x%x)\n",
			    opt->nd_opt_type, opt->nd_opt_type);
			break;
		}
		opt = (struct nd_opt_hdr *)((char *)opt + optlen);
		len -= optlen;
	}
}

char *
fmt_lla(char *llabuf, int bufsize, uchar_t *lla, int llalen)
{
	int i;
	char *cp = llabuf;

	for (i = 0; i < llalen; i++) {
		if (i == llalen - 1) /* Last byte? */
			(void) snprintf(cp, bufsize, "%02x", lla[i] & 0xFF);
		else
			(void) snprintf(cp, bufsize, "%02x:", lla[i] & 0xFF);
		bufsize -= strlen(cp);
		cp += strlen(cp);
	}
	return (llabuf);
}

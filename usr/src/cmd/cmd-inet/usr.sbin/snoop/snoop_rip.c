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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define	RIPVERSION	RIPv2
#include <protocols/routed.h>
#include "snoop.h"

static const char *show_cmd(int);
static int get_numtokens(unsigned int);
static const struct rip_sec_entry *rip_next_sec_entry(
    const struct rip_sec_entry *, int);

int
interpret_rip(int flags, struct rip *rip, int fraglen)
{
	const struct netinfo *nip;
	const struct entryinfo *ep;
	const struct netauth *nap;
	const struct rip_sec_entry *rsep, *rsn;
	const struct rip_emetric *rep;
	const uint32_t *tokp;
	int len, count;
	const char *cmdstr, *auth;
	struct in_addr dst;
	uint32_t mval;
	const struct sockaddr_in *sin;
	/* Room for IP destination + "/" + IP mask */
	char addrstr[15+1+15+1];
	/* Room for "RIPv" + uint8_t as %d */
	char ripvers[4+3+1];

	/* RIP header is 4 octets long */
	if ((len = fraglen - 4) < 0)
		return (0);

	if (flags & F_SUM) {
		switch (rip->rip_cmd) {
		case RIPCMD_REQUEST:	cmdstr = "C";		break;
		case RIPCMD_RESPONSE:	cmdstr = "R";		break;
		case RIPCMD_TRACEON:	cmdstr = "Traceon";	break;
		case RIPCMD_TRACEOFF:	cmdstr = "Traceoff";	break;
		case RIPCMD_POLL:	cmdstr = "Poll";	break;
		case RIPCMD_POLLENTRY:	cmdstr = "Poll entry";	break;
		case RIPCMD_SEC_RESPONSE: cmdstr = "R - SEC";	break;
		case RIPCMD_SEC_T_RESPONSE: cmdstr = "R - SEC_T"; break;
		default: cmdstr = "?"; break;
		}

		if (rip->rip_vers == RIPv1)
			(void) strlcpy(ripvers, "RIP", sizeof (ripvers));
		else
			(void) snprintf(ripvers, sizeof (ripvers), "RIPv%d",
			    rip->rip_vers);

		switch (rip->rip_cmd) {
		case RIPCMD_REQUEST:
		case RIPCMD_RESPONSE:
		case RIPCMD_POLL:
			nip = rip->rip_nets;
			auth = "";
			if (len >= sizeof (*nip) &&
			    nip->n_family == RIP_AF_AUTH) {
				nap = (struct netauth *)nip;
				len -= sizeof (*nip);
				if (nap->a_type == RIP_AUTH_MD5 &&
				    len >= ntohs(nap->au.a_md5.md5_auth_len))
					len -= ntohs(nap->au.a_md5.
					    md5_auth_len);
				auth = " +Auth";
			}
			count = len / sizeof (*nip);
			len %= sizeof (*nip);
			(void) snprintf(get_sum_line(), MAXLINE,
			    "%s %s (%d destinations%s%s)", ripvers, cmdstr,
			    count, (len != 0 ? "?" : ""), auth);
			break;

		case RIPCMD_TRACEON:
		case RIPCMD_TRACEOFF:
			(void) snprintf(get_sum_line(), MAXLINE,
			    "%s %s File=\"%.*s\"", ripvers, cmdstr, len,
			    rip->rip_tracefile);
			len = 0;
			break;

		case RIPCMD_SEC_RESPONSE:
		case RIPCMD_SEC_T_RESPONSE:
			if (len < sizeof (rip->rip_tsol.rip_generation))
				break;
			len -= sizeof (rip->rip_tsol.rip_generation);
			count = 0;
			rsep = rip->rip_tsol.rip_sec_entry;
			while (len > 0) {
				rsn = rip_next_sec_entry(rsep, len);
				if (rsn == NULL)
					break;
				len -= (const char *)rsn - (const char *)rsep;
				rsep = rsn;
				count++;
			}
			(void) snprintf(get_sum_line(), MAXLINE,
			    "%s %s (%d destinations%s)", ripvers, cmdstr,
			    count, (len != 0 ? "?" : ""));
			break;

		default:
			(void) snprintf(get_sum_line(), MAXLINE,
			    "%s %d (%s)", ripvers, rip->rip_cmd, cmdstr);
			len = 0;
			break;
		}
	}

	if (flags & F_DTAIL) {

		len = fraglen - 4;
		show_header("RIP:  ", "Routing Information Protocol", fraglen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Opcode = %d (%s)", rip->rip_cmd,
		    show_cmd(rip->rip_cmd));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Version = %d", rip->rip_vers);

		switch (rip->rip_cmd) {
		case RIPCMD_REQUEST:
		case RIPCMD_RESPONSE:
		case RIPCMD_POLL:
			show_space();
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Destination                     Next Hop        "
			    "Tag    Metric");
			for (nip = rip->rip_nets; len >= sizeof (*nip); nip++,
			    len -= sizeof (*nip)) {
				if (nip->n_family == RIP_AF_AUTH) {
					nap = (const struct netauth *)nip;
					if (nap->a_type == RIP_AUTH_NONE) {
						(void) snprintf(get_line
						    ((char *)nip - dlc_header,
							sizeof (*nip)),
						    get_line_remain(),
						    " *** Auth None");
					} else if (nap->a_type == RIP_AUTH_PW) {
						(void) snprintf(get_line
						    ((char *)nip - dlc_header,
							sizeof (*nip)),
						    get_line_remain(),
						    " *** Auth PW \"%.*s\"",
						    RIP_AUTH_PW_LEN,
						    nap->au.au_pw);
					} else if (nap->a_type ==
					    RIP_AUTH_MD5) {
						(void) snprintf(get_line(0, 0),
						    get_line_remain(),
						    " *** Auth MD5 pkt len %d, "
						    "keyid %d, sequence %08lX, "
						    "authlen %d",
						    ntohs(nap->au.a_md5.
							md5_pkt_len),
						    nap->au.a_md5.md5_keyid,
						    (long)ntohl(nap->au.a_md5.
							md5_seqno),
						    ntohs(nap->au.a_md5.
							md5_auth_len));
						if (len - sizeof (*nip) >=
						    ntohs(nap->au.a_md5.
						    md5_auth_len))
							len -= ntohs(nap->au.
							    a_md5.md5_auth_len);
						else
							len = sizeof (*nip);
					} else {
						(void) snprintf(get_line
						    ((char *)nip - dlc_header,
							sizeof (*nip)),
						    get_line_remain(),
						    " *** Auth Type %d?",
						    ntohs(nap->a_type));
					}
					continue;
				}
				if (nip->n_family == RIP_AF_UNSPEC &&
				    rip->rip_cmd == RIPCMD_REQUEST) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    " *** All routes");
					continue;
				}
				if (nip->n_family != RIP_AF_INET) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    " *** Address Family %d?",
					    ntohs(nip->n_family));
					continue;
				}
				if (nip->n_dst == htonl(RIP_DEFAULT)) {
					(void) strcpy(addrstr, "default");
				} else {
					dst.s_addr = nip->n_dst;
					(void) strlcpy(addrstr, inet_ntoa(dst),
					    sizeof (addrstr));
				}
				if (nip->n_dst != htonl(RIP_DEFAULT) &&
				    rip->rip_vers >= RIPv2) {
					count = strlen(addrstr);
					mval = ntohl(nip->n_mask);
					/* LINTED */
					if (mval == INADDR_ANY) {
						/* No mask */;
					} else if ((mval + (mval & -mval)) ==
					    0) {
						(void) snprintf(addrstr + count,
						    sizeof (addrstr) - count,
						    "/%d", 33 - ffs(mval));
					} else {
						dst.s_addr = nip->n_mask;
						(void) snprintf(addrstr + count,
						    sizeof (addrstr) - count,
						    "/%s", inet_ntoa(dst));
					}
				}
				dst.s_addr = nip->n_nhop;
				mval = ntohl(nip->n_metric);
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "%-31s %-15s %-6d %d%s",
				    addrstr,
				    dst.s_addr == htonl(INADDR_ANY) ?
				    "--" : addrtoname(AF_INET, &dst),
				    ntohs(nip->n_tag),
				    mval,
				    (mval == HOPCNT_INFINITY ?
					" (not reachable)" : ""));
			}
			break;

		case RIPCMD_POLLENTRY:
			if (len < sizeof (*ep))
				break;
			len -= sizeof (*ep);
			ep = (const struct entryinfo *)rip->rip_nets;
			/* LINTED */
			sin = (const struct sockaddr_in *)&ep->rtu_dst;
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Destination = %s %s",
			    inet_ntoa(sin->sin_addr),
			    addrtoname(AF_INET, (void *)&sin->sin_addr));
			/* LINTED */
			sin = (const struct sockaddr_in *)&ep->rtu_router;
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Router      = %s %s",
			    inet_ntoa(sin->sin_addr),
			    addrtoname(AF_INET, (void *)&sin->sin_addr));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Flags = %4x", (unsigned)ep->rtu_flags);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "State = %d", ep->rtu_state);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Timer = %d", ep->rtu_timer);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Metric = %d", ep->rtu_metric);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Int flags = %8x", ep->int_flags);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Int name = \"%.*s\"", sizeof (ep->int_name),
			    ep->int_name);
			break;

		case RIPCMD_SEC_RESPONSE:
		case RIPCMD_SEC_T_RESPONSE:
			if (len < sizeof (rip->rip_tsol.rip_generation))
				break;
			len -= sizeof (rip->rip_tsol.rip_generation);
			show_space();
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Generation = %u",
			    (unsigned)ntohl(rip->rip_tsol.rip_generation));
			rsep = rip->rip_tsol.rip_sec_entry;
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Address         E-METRIC");
			rsep = rip->rip_tsol.rip_sec_entry;
			while (len > 0) {
				char *cp;
				int blen, num;

				rsn = rip_next_sec_entry(rsep, len);
				if (rsn == NULL)
					break;
				dst.s_addr = rsep->rip_dst;
				cp = get_line(0, 0);
				blen = get_line_remain();
				(void) snprintf(cp, blen, "%-16s ",
				    inet_ntoa(dst));
				cp += 17;
				blen -= 17;
				rep = rsep->rip_emetric;
				for (count = ntohl(rsep->rip_count); count > 0;
				    count--) {
					(void) snprintf(cp, blen, "metric=%d",
					    ntohs(rep->rip_metric));
					blen -= strlen(cp);
					cp += strlen(cp);
					tokp = rep->rip_token;
					num = get_numtokens(
					    ntohs(rep->rip_mask));
					/* advance to the next emetric */
					rep = (const struct rip_emetric *)
					    &rep->rip_token[num];
					if (num > 0) {
						(void) snprintf(cp, blen,
						    ",tokens=%lx",
						    (long)ntohl(*tokp));
						tokp++;
						num--;
					} else {
						(void) strlcpy(cp, ",no tokens",
						    blen);
					}
					while (num > 0) {
						blen -= strlen(cp);
						cp += strlen(cp);
						(void) snprintf(cp, blen,
						    ",%lx",
						    (long)ntohl(*tokp));
						tokp++;
						num--;
					}
					blen -= strlen(cp);
					cp += strlen(cp);
				}
				if (rsep->rip_count == 0) {
					(void) strlcpy(cp,
					    "NULL (not reachable)", blen);
				}
				len -= (const char *)rsn - (const char *)rsep;
				rsep = rsn;
			}
			break;

		case RIPCMD_TRACEON:
		case RIPCMD_TRACEOFF:
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Trace file = %.*s", len, rip->rip_tracefile);
			len = 0;
			break;
		}
	}

	return (fraglen - len);
}

static const char *
show_cmd(int c)
{
	switch (c) {
	case RIPCMD_REQUEST:
		return ("route request");
	case RIPCMD_RESPONSE:
		return ("route response");
	case RIPCMD_TRACEON:
		return ("route trace on");
	case RIPCMD_TRACEOFF:
		return ("route trace off");
	case RIPCMD_POLL:
		return ("route poll");
	case RIPCMD_POLLENTRY:
		return ("route poll entry");
	case RIPCMD_SEC_RESPONSE:
		return ("route sec response");
	case RIPCMD_SEC_T_RESPONSE:
		return ("route sec_t response");
	}
	return ("?");
}

static int
get_numtokens(unsigned int mask)
{
	int num = 0;

	while (mask != 0) {
		num++;
		mask &= mask - 1;
	}
	return (num);
}

static const struct rip_sec_entry *
rip_next_sec_entry(const struct rip_sec_entry *rsep, int len)
{
	const struct rip_emetric *rep;
	const char *limit = (const char *)rsep + len;
	long count;

	if ((const char *)(rep = rsep->rip_emetric) > limit)
		return (NULL);
	count = ntohl(rsep->rip_count);
	while (count > 0) {
		if ((const char *)rep->rip_token > limit)
			return (NULL);
		rep = (struct rip_emetric *)
		    &rep->rip_token[get_numtokens(ntohs(rep->rip_mask))];
		if ((const char *)rep > limit)
			return (NULL);
		count--;
	}
	return ((const struct rip_sec_entry *)rep);
}

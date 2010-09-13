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
 * This file delivers /usr/lib/servinfo which provides description for
 * IANA and running RPC services. Given a IANA name or RPC program name
 * or number, the program uses getservbyname(3SOCKET) and rpcbind(3NSL)
 * to obtain port and proto information for the specified service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netconfig.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <rpc/rpcent.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdir.h>
#include <inttypes.h>
#include <limits.h>
#include <libintl.h>
#include <locale.h>

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

#define	TCP	"tcp"
#define	TCP6	"tcp6"
#define	UDP	"udp"
#define	UDP6	"udp6"

#define	DEFAULT 0x1
#define	PORT	0x2
#define	PROTO	0x4

#define	NETID_LEN	12 /* length for a netid or 2^16 port value */

static void
usage(char *arg0)
{
	(void) fprintf(stderr, gettext("Usage: %s [-R] [-Pp] [-tu[6]] "
	    "-s service_name\n"), arg0);
}

static rpcport_t
uaddr2port(char *addr)
{
	rpcport_t port = 0;
	char *dot, *p;

	if ((dot = strrchr(addr, '.')) == 0) {
		return (0);
	} else {
		if (dot == addr)
			return (0);

		p = dot - 1;
		while (*p != '.') {
			/*
			 * If the first dot hasn't been seen, it's a
			 * malformed universal address.
			 */
			if (p == addr)
				return (0);
			p--;
		}

		port = strtol(p + 1, &dot, 10) << 8;
		port = port | strtol(dot + 1, (char **)NULL, 10);
	}

	return (port);
}

static int
svc_getrpcinfo(char *sname, char *sproto, int options)
{
	struct netconfig *nconf;
	struct rpcblist *blist;
	int	prognum = -1;
	rpcport_t rpc_port;
	struct rpcent  rentry;
	struct rpcent  *rpc;
	char line[LINE_MAX] = "";
	int  line_len = LINE_MAX - 1;
	char buf[NETID_LEN];

	prognum = atoi(sname);
	if (prognum > 0)
		rpc = (struct rpcent *)getrpcbynumber(prognum);
	else
		rpc = (struct rpcent *)getrpcbyname(sname);

	/*
	 * If an entry doesn't exist, it could be a running program
	 * without a registered RPC entry.
	 */
	if (rpc == NULL) {
		if (prognum <= 0) {
			(void) fprintf(stderr,
			    gettext("Can't get rpc entry\n"));
			return (1);
		}

		rpc = &rentry;
		rpc->r_number = prognum;
		rpc->r_name = sname;
	}

	if (setnetconfig() == NULL) {
		(void) fprintf(stderr, gettext("setnetconfig failed\n"));
		return (1);
	}

	if ((nconf = getnetconfigent(TCP)) == NULL) {
		(void) fprintf(stderr, gettext("getnetconfig failed\n"));
		return (1);
	}

	if ((blist = (struct rpcblist *)rpcb_getmaps(nconf, "localhost"))
	    == NULL) {
		(void) fprintf(stderr,
		    gettext("Failed: rpcb_getmaps failed\n"));
		return (1);
	}

	for (; blist != NULL; blist = blist->rpcb_next) {
		if (blist->rpcb_map.r_prog != rpc->r_number)
			continue;

		if (sproto) {
			if (strcmp(blist->rpcb_map.r_netid, sproto) != 0)
				continue;
		} else {
			if (strcmp(blist->rpcb_map.r_netid, UDP) &&
			    strcmp(blist->rpcb_map.r_netid, UDP6) &&
			    strcmp(blist->rpcb_map.r_netid, TCP) &&
			    strcmp(blist->rpcb_map.r_netid, TCP6))
				continue;
		}
		rpc_port = uaddr2port(blist->rpcb_map.r_addr);

		if (options & DEFAULT) {
			(void) printf("Program %ld\n", blist->rpcb_map.r_prog);
			(void) printf("Protocol %s\n", blist->rpcb_map.r_netid);
			(void) printf("Port %ld\n", rpc_port);
			(void) printf("Version %ld\n", blist->rpcb_map.r_vers);
			(void) printf("Name %s\n", rpc->r_name);

		} else if (options & PROTO) {
			if (strstr(line, blist->rpcb_map.r_netid))
				continue;

			(void) snprintf(buf, sizeof (buf), "%5s ",
			    blist->rpcb_map.r_netid);

			if (strlen(buf) > line_len)
				continue;

			line_len = line_len - strlen(buf);
			(void) strlcat(line, buf, sizeof (line));
		} else {
			(void) snprintf(buf, sizeof (buf), "%-7ld ", rpc_port);

			if (strstr(line, buf) || strlen(buf) > line_len)
				continue;

			line_len = line_len - strlen(buf);
			(void) strlcat(line, buf, sizeof (line));
		}
	}

	/*
	 * Print the concatenated output if options is PROTO or PORT.
	 */
	if (options & (PROTO | PORT))
		(void) puts(line);

	return (0);
}

int
main(int argc, char *argv[])
{
	struct servent *service;
	char *sname = NULL;
	char *sproto = NULL;
	int options = DEFAULT;
	int c, isrpc = 0, v6_flag = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "s:PplRtu6?")) != -1) {
		switch (c) {
		case 's':
			sname = optarg;
			break;
		case 't':
			sproto = TCP;
			break;
		case 'u':
			sproto = UDP;
			break;
		case '6':
			v6_flag = 1;
			break;
		case 'P':
			options = PROTO;
			break;
		case 'p':
			options = PORT;
			break;
		case 'R':
			isrpc = 1;
			break;
		default:
			usage(argv[0]);
			return (1);
		}
	}
	if (sname == NULL) {
		usage(argv[0]);
		return (1);
	}

	/*
	 * Specified service is an RPC service.
	 */
	if (isrpc) {
		if (sproto && v6_flag) {
			if (strcmp(sproto, TCP) == 0)
				sproto = TCP6;
			if (strcmp(sproto, UDP) == 0)
				sproto = UDP6;
		}

		return (svc_getrpcinfo(sname, sproto, options));
	}

	if ((service = getservbyname(sname, sproto)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "Failed to get information for %s\n"), sname);
		return (1);
	}

	if (options & DEFAULT) {
		(void) printf("Name %s\n", service->s_name);
		(void) printf("Protocol %s\n", service->s_proto);
		(void) printf("Port %d\n", htons(service->s_port));
	} else if (options & PROTO)
		(void) printf("%s\n", service->s_proto);
	else
		(void) printf("%d\n", htons(service->s_port));

	return (0);
}

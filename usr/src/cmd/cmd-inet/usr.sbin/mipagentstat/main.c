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
#include <stdlib.h>
#include <door.h>
#include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <libintl.h>
#include <locale.h>
#include "conflib.h"
#include "mipagentstat_door.h"

/*
 * Main for mipagentstat. This uses the protocol defined in
 * "mipagentstat_door.h" to act as a door client to mipagent.
 * It displays statistics tables for home and foreign agents
 * by enumerating the registration tables in mipagent. Each
 * door call retrieves an single entry from the table. Doors
 * are fast enough that performance is good for this approach,
 * and memory usage (particularly in mipagent) is small and
 * non-disruptive to the rest of the process. This is a priority
 * since we expect that mipagent may eventually be required to
 * service thousands of nodes.
 *
 * mipagentstat follows the following logic flow:
 *
 * 1. (main) Process command-line arguments
 * 2. (main) Call enumerate_stats for each agent to stat
 * 3. (enumerate_stats) Display table banner if there are any entries
 * 4. (enumerate_stats)
 *		while more entries forthcoming
 *			get next entry via a door_call
 *			display the entry with display_entry
 * 5. (display_entry) convert address to printable format; print it.
 */

/* Flag to tell display function whether or not to resolve host names */
#define	NO_NAME_RESOLUTION	0x01
#define	PEER_PROTECTION		0x02

/* *80* columns for addrs/hostnames or NAIs, times, and registered flags. */
#define	MN_ADDR_COL_WIDTH	26	/* Mobile Node - NAI likely */
#define	MA_ADDR_COL_WIDTH	24	/* mipagent-peer - NAI unlikely */
#define	TIME_COL_WIDTH		9	/* lifetime, and remaining (ulongs) */
#define	FLAG_COL_WIDTH		8	/* services being given */
#define	PROT_TYPE_COL_WIDTH	8	/* enough to print protection types */

/*
 * Displays the header for the mobile node stats listing. Column widths for
 * the fields are defined by the macros M*_ADDR_COL_WIDTH and TIME_COL_WIDTH.
 *
 * type		IN	Foreign or Home Agent
 */
static void display_mn_header(enum_stat_type type) {
	(void) printf("\n%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s\n",
		    MN_ADDR_COL_WIDTH, MN_ADDR_COL_WIDTH, "Mobile Node",
		    MA_ADDR_COL_WIDTH, MA_ADDR_COL_WIDTH,
		    (type == FOREIGN_AGENT ? "Home Agent" : "Foreign Agent"),
		    TIME_COL_WIDTH, TIME_COL_WIDTH, "Time (s)",
		    TIME_COL_WIDTH, TIME_COL_WIDTH, "Time (s)",
		    FLAG_COL_WIDTH, FLAG_COL_WIDTH, "Service");
	(void) printf("%*s %-*.*s %-*.*s %-*.*s\n",
		    (MN_ADDR_COL_WIDTH + MA_ADDR_COL_WIDTH) + 1, "",
		    TIME_COL_WIDTH, TIME_COL_WIDTH, "Granted ",
		    TIME_COL_WIDTH, TIME_COL_WIDTH, "Remaining",
		    FLAG_COL_WIDTH, FLAG_COL_WIDTH, "Flags");
	(void) printf("%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s\n",
		    MN_ADDR_COL_WIDTH, MN_ADDR_COL_WIDTH,
		    "-------------------------------------------------",
		    MA_ADDR_COL_WIDTH, MA_ADDR_COL_WIDTH,
		    "-------------------------------------------------",
		    TIME_COL_WIDTH, TIME_COL_WIDTH,
		    "-------------------------------------------------",
		    TIME_COL_WIDTH, TIME_COL_WIDTH,
		    "-------------------------------------------------",
		    FLAG_COL_WIDTH, FLAG_COL_WIDTH,
		    "-------------------------------------------------");
}

/*
 * Displays the header for the agent stats listing.  Column widths for the
 * fields are defined by the macros PEER_ADDR_COL_WIDTH, and
 * PROT_TYPE_COL_WIDTH.
 */
static void display_agent_header(enum_stat_type type) {
	(void) printf("\n%-*.*s %-*.*s\n",
	    MA_ADDR_COL_WIDTH, MA_ADDR_COL_WIDTH,
	    (type == FOREIGN_AGENT_PEER ? "Foreign" : "Home"),
	    PROT_TYPE_COL_WIDTH * 4 + 3, PROT_TYPE_COL_WIDTH * 4 + 3,
	    "..... Security Association(s) .....");
	(void) printf("%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s\n",
	    MA_ADDR_COL_WIDTH, MA_ADDR_COL_WIDTH, "Agent",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, "Requests",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, "Replies",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, "FTunnel",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, "RTunnel");
	(void) printf("%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s\n",
	    MA_ADDR_COL_WIDTH, MA_ADDR_COL_WIDTH,
	    "-------------------------------------------------",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH,
	    "-------------------------------------------------",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH,
	    "-------------------------------------------------",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH,
	    "-------------------------------------------------",
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH,
	    "-------------------------------------------------");
}



/*
 * Converts the address in src to a string. If NO_NAME_RESOLUTION is
 * not set in flags, we try to resolve the address to a host name
 * using getipnodebyaddr. If this fails (for any reason) or if
 * NO_NAME_RESOLUTION is set in flags, we just convert the address
 * to presentation format using inet_ntop.
 *
 * af		IN	Address familiy of src
 * src		IN	Address to resolve or convert to presentation
 * srclen	IN	Length of src buffer
 * buf		IN/OUT	Buffer to hold coverted string. Should be big
 *			enough to hold either an address or a fully
 *			qualified host name string.
 * bufsz	IN	Size of buf
 * flags	IN	Special flags
 *
 * Returns		A pointer to a character buffer containing the
 *			printable address or host name. Never returns
 *			NULL. The pointer may point into buf; either
 *			way, the caller must not free the result.
 */
static char *addr2str(int af,
			void *src,
			size_t srclen,
			char *buf,
			size_t bufsz,
			int flags) {
	char *answer;
	struct hostent *he;
	int err;
	size_t addrlen;

	/*
	 * If -n wasn't given at the command line, try to resolve
	 * the hostname into an address.
	 */
	if ((flags & NO_NAME_RESOLUTION) == 0) {
	    /* Set the addrlen according to the AF */
	    switch (af) {
	    case AF_INET:
		addrlen = sizeof (struct in_addr);
		break;
	    case AF_INET6:
		addrlen = sizeof (struct in6_addr);
		break;
	    default:
		addrlen = srclen;
		break;
	    }

	    he = getipnodebyaddr(src, addrlen, af, &err);
	    if (he && err != 0) {
		(void) strncpy(buf, he->h_name, bufsz);
		freehostent(he);
		return (buf);
	    }
	}

	/*
	 * Else we shouldn't or couldn't resolve the hostname,
	 * so just convert to presentation format.
	 */

	answer = (char *)inet_ntop(af, src, buf, bufsz);

	return (answer ? answer : "<bad address>");
}

/*
 * Displays a single mobile node entry, formatting the fields
 * according to the macros M*_ADDR_COL_WIDTH and TIME_COL_WIDTH
 * and using addr2str to conver the addresses in stat_args into
 * printable strings.
 *
 * stat_args	IN	An entry returned from the stat door call
 * flags	IN	Passed through to addr2str
 */
static void display_mn_entry(DoorStatArgs stat_args, int flags) {
	char node_str[NI_MAXHOST];
	char agent_str[NI_MAXHOST];
	char service_str[FLAG_COL_WIDTH];
	struct timeval now;
	ulong_t expires = stat_args.expires;

	(void) gettimeofday(&now, NULL);

	/* Calculate what to print in the Service Flags column */
	(void) snprintf(service_str, sizeof (service_str), "%s%s%s%s%s%s%s%s",
	    (stat_args.service_flags & SERVICE_SIMULTANEOUS_BINDINGS ?
		"S" : "."),
	    (stat_args.service_flags & SERVICE_FWD_BROADCASTS ?
		"B" : "."),
	    (stat_args.service_flags & SERVICE_DECAPSULATION_BY_MN ?
		"D" : "."),
	    (stat_args.service_flags & SERVICE_MIN_ENCAP ?
		"M" : "."),
	    (stat_args.service_flags & SERVICE_GRE_ENCAP ?
		"G" : "."),
	    (stat_args.service_flags & SERVICE_VJ_COMPRESSION ?
		"V" : "."),
	    (stat_args.service_flags & SERVICE_REVERSE_TUNNEL ?
		"T" : "."),
	    (stat_args.service_flags & SERVICE_BIT_UNUSED ?
		"?" : "."));
	/* When the last reg bit becomes defined, it *replaces* the ? entry. */

	(void) printf("%-*.*s %-*.*s %-*lu %-*lu %*.*s\n",
	    /* Mobile Node */
	    MN_ADDR_COL_WIDTH, MN_ADDR_COL_WIDTH,
	    addr2str(stat_args.node_af,
		stat_args.node,
		sizeof (stat_args.node),
		node_str,
		NI_MAXHOST,
		flags),
	    /* Agent */
	    MA_ADDR_COL_WIDTH, MA_ADDR_COL_WIDTH,
	    addr2str(stat_args.agent_af,
		stat_args.agent,
		sizeof (stat_args.agent),
		agent_str,
		NI_MAXHOST,
		flags),
	    /* Time granted and expires */
	    TIME_COL_WIDTH, expires - stat_args.granted,
	    TIME_COL_WIDTH, (expires < now.tv_sec ?
		0 :
		expires - now.tv_sec),
	    /* Flags indicating services for the mn */
	    FLAG_COL_WIDTH, FLAG_COL_WIDTH, service_str);
}


/*
 * Displays a single agent-peer entry, formatting the fields
 * according to the macros M*_ADDR_COL_WIDTH and PROT_TYPE_COL_WIDTH
 * and using addr2str to conver the addresses in stat_args into
 * printable strings depending on whether the '-n' flag was set.
 *
 * stat_args	IN	An entry returned from the stat door call
 * flags	IN	Passed through to addr2str
 */
static void display_agent_entry(DoorStatArgs stat_args, int flags) {
	char agent_str[MA_ADDR_COL_WIDTH];
	char request_str[PROT_TYPE_COL_WIDTH] = "";
	char reply_str[PROT_TYPE_COL_WIDTH] = "";
	char tunnel_str[PROT_TYPE_COL_WIDTH] = "";
	char reversetunnel_str[PROT_TYPE_COL_WIDTH] = "";

	/* calculate what to print in the protection columns */
	if (stat_args.service_flags & IPSEC_REQUEST_AH) {
		(void) strcat(request_str, "AH ");
	}
	if (stat_args.service_flags & IPSEC_REQUEST_ESP) {
		(void) strcat(request_str, "ESP");
	}

	if (stat_args.service_flags & IPSEC_REPLY_AH) {
		(void) strcat(reply_str, "AH ");
	}
	if (stat_args.service_flags & IPSEC_REPLY_ESP) {
		(void) strcat(reply_str, "ESP");
	}

	if (stat_args.service_flags & IPSEC_TUNNEL_AH) {
		(void) strcat(tunnel_str, "AH ");
	}
	if (stat_args.service_flags & IPSEC_TUNNEL_ESP) {
		(void) strcat(tunnel_str, "ESP");
	}

	if (stat_args.service_flags & IPSEC_REVERSE_TUNNEL_AH) {
		(void) strcat(reversetunnel_str, "AH ");
	}
	if (stat_args.service_flags & IPSEC_REVERSE_TUNNEL_ESP) {
		(void) strcat(reversetunnel_str, "ESP");
	}

	(void) printf("%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s\n",
	    /* agent-peer */
	    MA_ADDR_COL_WIDTH, MA_ADDR_COL_WIDTH,
	    addr2str(stat_args.agent_af,
		stat_args.agent,
		sizeof (stat_args.agent),
		agent_str,
		MA_ADDR_COL_WIDTH,
		flags),
	    /* protection info */
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, request_str,
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, reply_str,
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, tunnel_str,
	    PROT_TYPE_COL_WIDTH, PROT_TYPE_COL_WIDTH, reversetunnel_str);
}


/*
 * Enumerates through mipagent's entire table of foreign or home
 * agent entries. We use a doors IPC to communicate with mipagent.
 * Each door call retrieves a single entry, keeping memory usage
 * low. Memory management is simplified by using the automatic
 * variable stat_args to allocate all needed memory. Each entry
 * is displayed based on the flags passed in.  If flags indicate
 * the user wants to see the protection in place (-p) with our
 * agent peers, then display_agent_entry() is called, otherwise
 * the user wants mobile nodes, and we call display_mn_entry().
 *
 * type		IN	Foreign or Home Agent
 * flags	IN	Passed through to display_*_entries()
 */
static void enumerate_stats(enum_stat_type type, int flags) {
	int fd = open(MIPAGENTSTAT_DOOR, O_RDONLY);
	door_arg_t arg;
	DoorStatArgs stat_args;

	if (fd == -1) {
	    (void) fprintf(stderr, gettext("mipagent unavailable\n"));
	    exit(1);
	}

	/* Set up door args */
	(void) memset(&stat_args, 0, sizeof (stat_args));
	stat_args.type = type;
	stat_args.op = FIRST_ENT;

	(void) memset(&arg, 0, sizeof (arg));
	arg.data_ptr = (char *)&stat_args;
	arg.data_size = sizeof (stat_args);
	arg.rbuf = (char *)&stat_args;
	arg.rsize = sizeof (stat_args);

	/* Do the first entry. If the server is down, we find out here. */
	if (door_call(fd, &arg) == -1) {
	    (void) fprintf(stderr, gettext("mipagent unavailable\n"));
	    exit(1);
	}

	/*
	 * Now that we know the server is up, display the banner,
	 * then display information, or at least the fact that
	 * there's nothing to display!
	 */
	if (flags & PEER_PROTECTION)
		/* display the mobility agent peer stat header */
		display_agent_header(type);
	else
		/* display the mn-stat header */
		display_mn_header(type);

	if (arg.data_size == 0) {
	    (void) fprintf(stdout, gettext("<none>\n\n"));
	    goto done;
	}

	/* Switch to next entry mode for the rest of the enumeration */
	stat_args.op = NEXT_ENT;

	/* Enumerate */
	while (arg.data_size != 0) {
	    if (arg.data_size < sizeof (stat_args)) {
		(void) fprintf(stderr, gettext("bad reply from mipagent\n"));
		break;
	    }

	    if (flags & PEER_PROTECTION)
		display_agent_entry(stat_args, flags);
	    else
		display_mn_entry(stat_args, flags);

	    if (door_call(fd, &arg) == -1) {
		perror("door_call");
		break;
	    }
	}

done:
	(void) close(fd);
}

static void usage(char **argv) {
	(void) printf(gettext("Usage: %s [ -fhp ]\n"), *argv);
}

/*
 * Entry point for mipagentstat. main simply processes the command
 * line arguments and uses them to dispatch foreign or home agent
 * statistics enumerations. If no arguments are given, we retrieve
 * both home and foreign agent stats.
 */
int
main(int argc, char **argv) {
	int c;
	int type = 0;
	int flags = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "fhnp")) != EOF) {
	    switch (c) {
	    case 'f':
		type |= DO_FA;
		break;
	    case 'h':
		type |= DO_HA;
		break;
	    case 'n':
		/*
		 * private flag: if true, we don't try to resolve
		 * addresses into host names. This can result in
		 * a significantly faster listing, and follows the
		 * tried and true behavior of utilities like netstat.
		 */
		flags |= NO_NAME_RESOLUTION;
		break;
	    case 'p':
		/*
		 * User wants to see the protection with our agent peers.
		 * This is set in type because doors doesn't see any flags.
		 */
		flags |= PEER_PROTECTION;
		break;
	    default:
		usage(argv);
		exit(1);
	    }
	}

	if ((!(type & DO_FA)) && (!(type & DO_HA)))
		/* Neither is set, so user didn't specify, therefore do both. */
		type |= DO_BOTH;

	if (flags & PEER_PROTECTION) {
		if (type & DO_FA)
			/* user types -fp, wants peers of the FA = HA-peers */
			enumerate_stats(HOME_AGENT_PEER, flags);

		if (type & DO_HA)
			/* user types -hp, wants peers of the HA = FA-peers */
			enumerate_stats(FOREIGN_AGENT_PEER, flags);
	} else {
		if (type & DO_FA)
			enumerate_stats(FOREIGN_AGENT, flags);

		if (type & DO_HA)
			enumerate_stats(HOME_AGENT, flags);
	}

	return (0);
}

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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <math.h>

#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stropts.h>
#include <sys/file.h>
#include <sys/sysmacros.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <stdlib.h>
#include <priv_utils.h>

#include <libinetutil.h>
#include "ping.h"

/*
 * This macro is used to compare 16bit, wrapping sequence numbers. Inspired by
 * TCP's SEQ_LEQ macro.
 */
#define	PINGSEQ_LEQ(a, b)	((int16_t)((a)-(b)) <= 0)

#define	MAX_WAIT		10	/* max sec. to wait for response */
#define	MAX_TRAFFIC_CLASS	255	/* max traffic class for IPv6 */
#define	MAX_FLOW_LABEL		0xFFFFF	/* max flow label for IPv6 */
#define	MAX_TOS			255	/* max type-of-service for IPv4 */

#define	TIMEOUT			20	/* default timeout value */
#define	DEFAULT_DATALEN		56

#define	MULTICAST_NOLOOP	1	/* multicast options */
#define	MULTICAST_TTL		2
#define	MULTICAST_IF		4

#define	IF_INDEX		0	/* types of -i argument */
#define	IF_NAME			1
#define	IF_ADDR			2
#define	IF_ADDR6		3

#ifdef BSD
#define	setbuf(s, b)	setlinebuf((s))
#endif /* BSD */


/* interface identification */
union if_id {
	int index;		/* interface index (e.g., 1, 2) */
	char *name;		/* interface name (e.g., le0, hme0) */
	union any_in_addr addr;	/* interface address (e.g., 10.123.4.5) */
};

/* stores the interface supplied by the user */
struct if_entry {
	char *str;		/* unresolved, string input */
	int id_type;		/* type of ID (index, name, addr, addr6) */
	union if_id id;		/* ID */
};

char *progname;
char *targethost;
char *nexthop;

static int send_sock;			/* send sockets */
static int send_sock6;
static struct sockaddr_in to;		/* where to send */
static struct sockaddr_in6 to6;
static union any_in_addr gw_IP_list[MAX_GWS];	/* gateways */
static union any_in_addr gw_IP_list6[MAX_GWS6];
static int if_index = 0;		/* outgoing interface index */
boolean_t is_alive = _B_FALSE;		/* is target host alive */
struct targetaddr *current_targetaddr;	/* current target IP address to probe */
static struct targetaddr *targetaddr_list; /* list of IP addresses to probe */
static int num_targetaddrs;		/* no of target addresses to probe */
static int num_v4 = 0;			/* count of IPv4 addresses */
static int num_v6 = 0;			/* count of IPv6 addresses */
boolean_t verbose = _B_FALSE;		/* verbose output */
boolean_t stats = _B_FALSE;		/* display statistics */
static boolean_t settos = _B_FALSE;	/* set type-of-service value */
boolean_t rr_option = _B_FALSE;		/* true if using record route */
boolean_t send_reply = _B_FALSE;	/* Send an ICMP_{ECHO|TSTAMP}REPLY */
					/* that goes to target and comes back */
					/* to the the sender via src routing. */
boolean_t strict = _B_FALSE;		/* true if using strict source route */
boolean_t ts_option = _B_FALSE;		/* true if using timestamp option */
boolean_t use_icmp_ts = _B_FALSE;	/* Use ICMP timestamp request */
boolean_t use_udp = _B_FALSE;		/* Use UDP instead of ICMP */
boolean_t probe_all = _B_FALSE;		/* probe all the IP addresses */
boolean_t nflag = _B_FALSE;		/* do not reverse lookup addresses */
boolean_t bypass = _B_FALSE;		/* bypass IPsec policy */
static int family_input = AF_UNSPEC;	/* address family supplied by user */
int datalen = DEFAULT_DATALEN;		/* How much data */
int ts_flag;				/* timestamp flag value */
static int num_gw;			/* number of gateways */
static int eff_num_gw;			/* effective number of gateways */
					/* if send_reply, it's 2*num_gw+1 */
static int num_wraps = -1;		/* no of times 64K icmp_seq wrapped */
static ushort_t dest_port = 32768 + 666; /* starting port for the UDP probes */
static char *gw_list[MAXMAX_GWS];	/* list of gateways as user enters */
static int interval = 1;		/* interval between transmissions */
static int options;			/* socket options */
static int moptions;			/* multicast options */
int npackets;				/* number of packets to send */
static ushort_t tos;			/* type-of-service value */
static int hoplimit = -1;		/* time-to-live value */
static int dontfrag;			/* IP*_DONTFRAG */
static int timeout = TIMEOUT;		/* timeout value (sec) for probes */
static struct if_entry out_if;		/* interface argument */
int ident;				/* ID for this ping run */
static hrtime_t t_last_probe_sent;	/* the time we sent the last probe */

/*
 * This buffer stores the received packets. Currently it needs to be 32 bit
 * aligned. In the future, we'll be using 64 bit alignment, so let's use 64 bit
 * alignment now.
 */
static uint64_t in_pkt[(IP_MAXPACKET + 1)/8];

/* Used to store the ancillary data that comes with the received packets */
static uint64_t ancillary_data[(IP_MAXPACKET + 1)/8];

static int ntransmitted;	/* number of packet sent to single IP address */
int nreceived;			/* # of packets we got back from target host */
int nreceived_last_target;	/* received from last target IP */
/*
 * These are used for statistics. tmin is initialized to maximum longint value.
 * The max value is also used for timeouts.   All times are in microseconds.
 */
long long tmin = LLONG_MAX;
long long tmax;
int64_t tsum;			/* sum of all times, for doing average */
int64_t tsum2;			/* sum of squared times, for std. dev. */

static struct targetaddr *build_targetaddr_list(struct addrinfo *,
    union any_in_addr *);
extern void check_reply(struct addrinfo *, struct msghdr *, int, ushort_t);
extern void check_reply6(struct addrinfo *, struct msghdr *, int, ushort_t);
static struct targetaddr *create_targetaddr_item(int, union any_in_addr *,
    union any_in_addr *);
void find_dstaddr(ushort_t, union any_in_addr *);
static struct ifaddrlist *find_if(struct ifaddrlist *, int);
static void finish();
static void get_gwaddrs(char *[], int, union any_in_addr *,
    union any_in_addr *, int *, int *);
static void get_hostinfo(char *, int, struct addrinfo **);
static ushort_t in_cksum(ushort_t *, int);
static int int_arg(char *s, char *what);
boolean_t is_a_target(struct addrinfo *, union any_in_addr *);
static void mirror_gws(union any_in_addr *, int);
static void pinger(int, struct sockaddr *, struct msghdr *, int);
char *pr_name(char *, int);
char *pr_protocol(int);
static void print_unknown_host_msg(const char *, const char *);
static void recv_icmp_packet(struct addrinfo *, int, int, ushort_t, ushort_t);
static void resolve_nodes(struct addrinfo **, struct addrinfo **,
    union any_in_addr **);
void schedule_sigalrm();
static void select_all_src_addrs(union any_in_addr **, struct addrinfo *,
    union any_in_addr *, union any_in_addr *);
static void select_src_addr(union any_in_addr *, int, union any_in_addr *);
void send_scheduled_probe();
boolean_t seq_match(ushort_t, int, ushort_t);
extern void set_ancillary_data(struct msghdr *, int, union any_in_addr *, int,
    uint_t);
extern void set_IPv4_options(int, union any_in_addr *, int, struct in_addr *,
    struct in_addr *);
static void set_nexthop(int, struct addrinfo *, int);
static boolean_t setup_socket(int, int *, int *, int *, ushort_t *,
    struct addrinfo *);
void sigalrm_handler();
void tvsub(struct timeval *, struct timeval *);
static void usage(char *);

/*
 * main()
 */
int
main(int argc, char *argv[])
{
	struct addrinfo	*ai_dst = NULL;		/* addrinfo host list */
	struct addrinfo	*ai_nexthop = NULL;		/* addrinfo nexthop */
	union any_in_addr *src_addr_list = NULL;	/* src addrs to use */
	int recv_sock = -1;				/* receive sockets */
	int recv_sock6 = -1;
	ushort_t udp_src_port;			/* src ports for UDP probes */
	ushort_t udp_src_port6;			/* used to identify replies */
	uint_t flowinfo = 0;
	uint_t class = 0;
	char abuf[INET6_ADDRSTRLEN];
	int c;
	int i;
	boolean_t has_sys_ip_config;

	progname = argv[0];

	/*
	 * This program needs the net_icmpaccess privilege for creating
	 * raw ICMP sockets.  It needs sys_ip_config for using the
	 * IP_NEXTHOP socket option (IPv4 only).  We'll fail
	 * on the socket call and report the error there when we have
	 * insufficient privileges.
	 *
	 * Shared-IP zones don't have the sys_ip_config privilege, so
	 * we need to check for it in our limit set before trying
	 * to set it.
	 */
	has_sys_ip_config = priv_ineffect(PRIV_SYS_IP_CONFIG);

	(void) __init_suid_priv(PU_CLEARLIMITSET, PRIV_NET_ICMPACCESS,
	    has_sys_ip_config ? PRIV_SYS_IP_CONFIG : (char *)NULL,
	    (char *)NULL);

	setbuf(stdout, (char *)0);

	while ((c = getopt(argc, argv,
	    "abA:c:dDF:G:g:I:i:LlnN:P:p:rRSsTt:UvX:x:Y0123?")) != -1) {
		switch ((char)c) {
		case 'A':
			if (strcmp(optarg, "inet") == 0) {
				family_input = AF_INET;
			} else if (strcmp(optarg, "inet6") == 0) {
				family_input = AF_INET6;
			} else {
				Fprintf(stderr,
				    "%s: unknown address family %s\n",
				    progname, optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'a':
			probe_all = _B_TRUE;
			break;

		case 'c':
			i = int_arg(optarg, "traffic class");
			if (i > MAX_TRAFFIC_CLASS) {
				Fprintf(stderr, "%s: traffic class %d out of "
				    "range\n", progname, i);
				exit(EXIT_FAILURE);
			}
			class = (uint_t)i;
			break;

		case 'd':
			options |= SO_DEBUG;
			break;

		case 'D':
			dontfrag = 1;
			break;

		case 'b':
			bypass = _B_TRUE;
			break;

		case 'F':
			i = int_arg(optarg, "flow label");
			if (i > MAX_FLOW_LABEL) {
				Fprintf(stderr, "%s: flow label %d out of "
				    "range\n", progname, i);
				exit(EXIT_FAILURE);
			}
			flowinfo = (uint_t)i;
			break;

		case 'I':
			stats = _B_TRUE;
			interval = int_arg(optarg, "interval");
			break;

		case 'i':
			/*
			 * this can accept interface index, interface name, and
			 * address configured on the interface
			 */
			moptions |= MULTICAST_IF;
			out_if.str = optarg;

			if (inet_pton(AF_INET6, optarg, &out_if.id.addr) > 0) {
				out_if.id_type = IF_ADDR6;
			} else if (inet_pton(AF_INET, optarg,
			    &out_if.id.addr) > 0) {
				out_if.id_type = IF_ADDR;
			} else if (strcmp(optarg, "0") == 0) {
				out_if.id_type = IF_INDEX;
				out_if.id.index = 0;
			} else if ((out_if.id.index = atoi(optarg)) != 0) {
				out_if.id_type = IF_INDEX;
			} else {
				out_if.id.name = optarg;
				out_if.id_type = IF_NAME;
			}
			break;

		case 'L':
			moptions |= MULTICAST_NOLOOP;
			break;

		case 'l':
			send_reply = _B_TRUE;
			strict = _B_FALSE;
			break;

		case 'n':
			nflag = _B_TRUE;
			break;

		case 'P':
			settos = _B_TRUE;
			i = int_arg(optarg, "type-of-service");
			if (i > MAX_TOS) {
				Fprintf(stderr, "%s: tos value %d out of "
				    "range\n", progname, i);
				exit(EXIT_FAILURE);
			}
			tos = (ushort_t)i;
			break;

		case 'p':
			i = int_arg(optarg, "port number");
			if (i > MAX_PORT) {
				Fprintf(stderr, "%s: port number %d out of "
				    "range\n", progname, i);
				exit(EXIT_FAILURE);
			}
			dest_port = (ushort_t)i;
			break;

		case 'r':
			options |= SO_DONTROUTE;
			break;

		case 'R':
			rr_option = _B_TRUE;
			break;

		case 'S':
			send_reply = _B_TRUE;
			strict = _B_TRUE;
			break;

		case 's':
			stats = _B_TRUE;
			break;

		case 'T':
			ts_option = _B_TRUE;
			break;

		case 't':
			moptions |= MULTICAST_TTL;
			hoplimit = int_arg(optarg, "ttl");
			if (hoplimit > MAXTTL) {
				Fprintf(stderr, "%s: ttl %d out of range\n",
				    progname, hoplimit);
				exit(EXIT_FAILURE);
			}
			break;

		case 'U':
			use_udp = _B_TRUE;
			use_icmp_ts = _B_FALSE;
			break;

		case 'v':
			verbose = _B_TRUE;
			break;
		/*
		 * 'x' and 'X' has been undocumented flags for source routing.
		 * Now we document loose source routing with the new flag 'g',
		 * which is same as in traceroute. We still keep x/X as
		 * as undocumented. 'G', which is for strict source routing is
		 * also undocumented.
		 */
		case 'x':
		case 'g':
			strict = _B_FALSE;
			if (num_gw > MAXMAX_GWS) {
				Fprintf(stderr, "%s: too many gateways\n",
				    progname);
				exit(EXIT_FAILURE);
			}
			gw_list[num_gw++] = optarg;
			break;

		case 'X':
		case 'G':
			strict = _B_TRUE;
			if (num_gw > MAXMAX_GWS) {
				Fprintf(stderr, "%s: too many gateways\n",
				    progname);
				exit(EXIT_FAILURE);
			}
			gw_list[num_gw++] = optarg;
			break;

		case 'N':
			if (nexthop != NULL) {
				Fprintf(stderr, "%s: only one next hop gateway"
				    " allowed\n", progname);
				exit(EXIT_FAILURE);
			}
			nexthop = optarg;
			break;

		case 'Y':
			use_icmp_ts = _B_TRUE;
			use_udp = _B_FALSE;
			break;

		case '0':
		case '1':
		case '2':
		case '3':
			ts_flag = (char)c - '0';
			break;

		case '?':
			usage(progname);
			exit(EXIT_FAILURE);
			break;

		default:
			usage(progname);
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (optind >= argc) {
		usage(progname);
		exit(EXIT_FAILURE);
	}

	/*
	 * send_reply, which sends the probe packet back to itself
	 * doesn't work with UDP
	 */
	if (use_udp)
		send_reply = _B_FALSE;

	if (getenv("MACHINE_THAT_GOES_PING") != NULL)
		stats = _B_TRUE;

	targethost = argv[optind];
	optind++;
	if (optind < argc) {
		if (stats) {
			datalen = int_arg(argv[optind], "data size");
			optind++;
			if (optind < argc) {
				npackets = int_arg(argv[optind],
				    "packet count");
				if (npackets < 1) {
					Fprintf(stderr, "%s: packet count %d "
					    "out of range\n", progname,
					    npackets);
					exit(EXIT_FAILURE);
				}
			}
		} else {
			timeout = int_arg(argv[optind], "timeout");
		}
	}

	/*
	 * Let's prepare sockaddr_in* structures, cause we might need both of
	 * them.
	 */
	bzero((char *)&to, sizeof (struct sockaddr_in));
	to.sin_family = AF_INET;

	bzero((char *)&to6, sizeof (struct sockaddr_in6));
	to6.sin6_family = AF_INET6;
	to6.sin6_flowinfo = htonl((class << 20) | flowinfo);

	if (stats)
		(void) sigset(SIGINT, finish);

	ident = (int)getpid() & 0xFFFF;

	/* resolve the hostnames */
	resolve_nodes(&ai_dst, &ai_nexthop, &src_addr_list);

	/*
	 * We should make sure datalen is reasonable.
	 * 	IP_MAXPACKET >= IPv4/IPv6 header length +
	 *			IPv4 options/IPv6 routing header length +
	 *			ICMP/ICMP6/UDP header length +
	 *			datalen
	 */

	if (family_input == AF_INET6 ||
	    (family_input == AF_UNSPEC && num_v6 != 0)) {
		size_t exthdr_len = 0;

		if (send_reply) {
			exthdr_len = sizeof (struct ip6_rthdr0) +
			    2 * num_gw * sizeof (struct in6_addr);
		} else if (num_gw > 0) {
			exthdr_len = sizeof (struct ip6_rthdr0) +
			    num_gw * sizeof (struct in6_addr);
		}

		/*
		 * Size of ICMP6 header and UDP header are the same. Let's
		 * use ICMP6_MINLEN.
		 */
		if (datalen > (IP_MAXPACKET - (sizeof (struct ip6_hdr) +
		    exthdr_len + ICMP6_MINLEN))) {
			Fprintf(stderr,
			    "%s: data size too large for IPv6 packet\n",
			    progname);
			num_v6 = 0;
		}
	}

	if (family_input == AF_INET ||
	    (family_input == AF_UNSPEC && num_v4 != 0)) {
		size_t opt_len = 0;

		if (send_reply) {
			/*
			 * Includes 3 bytes code+ptr+len, the intermediate
			 * gateways, the actual and the effective target.
			 */
			opt_len = 3 +
			    (2 * num_gw + 2) * sizeof (struct in_addr);
		} else if (num_gw > 0) {
			opt_len = 3 + (num_gw + 1) * sizeof (struct in_addr);
		}

		if (rr_option) {
			opt_len = MAX_IPOPTLEN;
		} else if (ts_option) {
			if ((ts_flag & 0x0f) <= IPOPT_TS_TSANDADDR) {
				opt_len = MAX_IPOPTLEN;
			} else {
				opt_len += IPOPT_MINOFF +
				    2 * sizeof (struct ipt_ta);
				/*
				 * Note: BSD/4.X is broken in their check so we
				 * have to  bump up this number by at least one.
				 */
				opt_len++;
			}
		}

		/* Round up to 4 byte boundary */
		if (opt_len & 0x3)
			opt_len = (opt_len & ~0x3) + 4;

		if (datalen > (IP_MAXPACKET - (sizeof (struct ip) + opt_len +
		    ICMP_MINLEN))) {
			Fprintf(stderr,
			    "%s: data size too large for IPv4 packet\n",
			    progname);
			num_v4 = 0;
		}
	}

	if (num_v4 == 0 && num_v6 == 0) {
		exit(EXIT_FAILURE);
	}

	/* setup the sockets */
	if (num_v6 != 0) {
		if (!setup_socket(AF_INET6, &send_sock6, &recv_sock6,
		    &if_index, &udp_src_port6, ai_nexthop))
			exit(EXIT_FAILURE);
	}

	if (num_v4 != 0) {
		if (!setup_socket(AF_INET, &send_sock, &recv_sock, &if_index,
		    &udp_src_port, ai_nexthop))
			exit(EXIT_FAILURE);
	}

	__priv_relinquish();

	/*
	 * If sending back to ourself, add the mirror image of current
	 * gateways, so that the probes travel to and from the target
	 * by visiting the same gateways in reverse order.
	 */
	if (send_reply) {
		if (num_v6 != 0)
			mirror_gws(gw_IP_list6, AF_INET6);
		if (num_v4 != 0)
			mirror_gws(gw_IP_list, AF_INET);

		/* We add 1 because we put the target as the middle gateway */
		eff_num_gw = 2 * num_gw + 1;

	} else {
		eff_num_gw = num_gw;
	}

	targetaddr_list = build_targetaddr_list(ai_dst, src_addr_list);
	current_targetaddr = targetaddr_list;

	/*
	 * Set the starting_seq_num for the first targetaddr.
	 * If we are sending ICMP Echo Requests, the sequence number is same as
	 * ICMP sequence number, and it starts from zero. If we are sending UDP
	 * packets, the sequence number is the destination UDP port number,
	 * which starts from dest_port. At each probe, this sequence number is
	 * incremented by one.
	 * We set the starting_seq_num for first targetaddr here. The
	 * following ones will be set by looking at where we left with the last
	 * targetaddr.
	 */
	current_targetaddr->starting_seq_num = use_udp ? dest_port : 0;

	if (stats) {
		if (probe_all || !nflag) {
			Printf("PING %s: %d data bytes\n", targethost, datalen);
		} else {
			if (ai_dst->ai_family == AF_INET) {
				(void) inet_ntop(AF_INET,
				    &((struct sockaddr_in *)(void *)
				    ai_dst->ai_addr)->sin_addr,
				    abuf, sizeof (abuf));
			} else {
				(void) inet_ntop(AF_INET6,
				    &((struct sockaddr_in6 *)(void *)
				    ai_dst->ai_addr)->sin6_addr,
				    abuf, sizeof (abuf));
			}
			Printf("PING %s (%s): %d data bytes\n",
			    targethost, abuf, datalen);
		}
	}

	/* Let's get things going */
	send_scheduled_probe();

	/* SIGALRM is used to send the next scheduled probe */
	(void) sigset(SIGALRM, sigalrm_handler);
	schedule_sigalrm();

	/*
	 * From now on, we'll always be listening to ICMP packets. As SIGALRM
	 * comes in, sigalrm_handler() will be invoked and send another
	 * probe.
	 */
	recv_icmp_packet(ai_dst, recv_sock6, recv_sock, udp_src_port6,
	    udp_src_port);

	return (EXIT_SUCCESS);	/* should never come here */
}

/*
 * Build the target IP address list. Use command line options and
 * name lookup results returned from name server to determine which addresses
 * to probe, how many times, in which order.
 */
static struct targetaddr *
build_targetaddr_list(struct addrinfo *ai_dst, union any_in_addr *src_addr_list)
{
	struct targetaddr *head = NULL;
	struct targetaddr *targetaddr;
	struct targetaddr **nextp;
	int num_dst;
	int i;
	struct addrinfo *aip;

	aip = ai_dst;
	if (probe_all)
		num_dst = num_v4 + num_v6;
	else
		num_dst = 1;
	num_targetaddrs = num_dst;
	nextp = &head;
	for (aip = ai_dst, i = 0; aip != NULL; aip = aip->ai_next, i++) {
		if (aip->ai_family == AF_INET && num_v4 != 0) {
			targetaddr = create_targetaddr_item(aip->ai_family,
			    (union any_in_addr *)
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    &((struct sockaddr_in *)
			    aip->ai_addr)->sin_addr,
			    &src_addr_list[i]);
		} else if (aip->ai_family == AF_INET6 && num_v6 != 0) {
			targetaddr = create_targetaddr_item(aip->ai_family,
			    (union any_in_addr *)
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    &((struct sockaddr_in6 *)
			    aip->ai_addr)->sin6_addr,
			    &src_addr_list[i]);
		} else {
			continue;
		}
		*nextp = targetaddr;
		nextp = &targetaddr->next;
		if (num_targetaddrs == 1)
			break;
	}
	if (npackets == 0 && stats)
		*nextp = head;	/* keep going indefinitely */

	return (head);
}

/*
 * Given an address family, dst and src addresses, by also looking at the
 * options provided at the command line, this function creates a targetaddr
 * to be linked with others, forming a global targetaddr list. Each targetaddr
 * item contains information about probes sent to a specific IP address.
 */
static struct targetaddr *
create_targetaddr_item(int family, union any_in_addr *dst_addr,
    union any_in_addr *src_addr)
{
	struct targetaddr *targetaddr;

	targetaddr = (struct targetaddr *)malloc(sizeof (struct targetaddr));
	if (targetaddr == NULL) {
		Fprintf(stderr, "%s: malloc %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}
	targetaddr->family = family;
	targetaddr->dst_addr = *dst_addr;
	targetaddr->src_addr = *src_addr;
	if (stats) {
		/*
		 * npackets is only defined if we are in stats mode.
		 * npackets determines how many probes to send to each target
		 * IP address. npackets == 0 means send only 1 and move on to
		 * next target IP.
		 */
		if (npackets > 0)
			targetaddr->num_probes = npackets;
		else
			targetaddr->num_probes = 1;
	} else {
		targetaddr->num_probes = timeout;
	}
	targetaddr->num_sent = 0;
	targetaddr->got_reply = _B_FALSE;
	targetaddr->probing_done = _B_FALSE;
	targetaddr->starting_seq_num = 0; /* actual value will be set later */
	targetaddr->next = NULL;	/* actual value will be set later */

	return (targetaddr);
}

/*
 * print "unknown host" message
 */
static void
print_unknown_host_msg(const char *protocol, const char *hostname)
{
	Fprintf(stderr, "%s: unknown%s host %s\n", progname, protocol,
	    hostname);
}

/*
 * Resolve hostnames for the target host and gateways. Also, determine source
 * addresses to use for each target address.
 */
static void
resolve_nodes(struct addrinfo **ai_dstp, struct addrinfo **ai_nexthopp,
    union any_in_addr **src_addr_listp)
{
	struct addrinfo *ai_dst = NULL;
	struct addrinfo *ai_nexthop = NULL;
	struct addrinfo *aip = NULL;
	union any_in_addr *src_addr_list = NULL;
	int num_resolved_gw = 0;
	int num_resolved_gw6 = 0;

	get_hostinfo(targethost, family_input, &ai_dst);
	if (ai_dst == NULL) {
		print_unknown_host_msg("", targethost);
		exit(EXIT_FAILURE);
	}
	if (nexthop != NULL) {
		get_hostinfo(nexthop, family_input, &ai_nexthop);
		if (ai_nexthop == NULL) {
			print_unknown_host_msg("", nexthop);
			exit(EXIT_FAILURE);
		}
	}
	/* Get a count of the v4 & v6 addresses */
	for (aip = ai_dst; aip != NULL; aip = aip->ai_next) {
		switch (aip->ai_family) {
		case AF_INET:
			num_v4++;
			break;
		case AF_INET6:
			num_v6++;
			break;
		}
	}

	if (family_input == AF_UNSPEC && !probe_all) {
		family_input = ai_dst->ai_family;
	}

	/* resolve gateways */
	if (num_gw > 0) {
		get_gwaddrs(gw_list, family_input, gw_IP_list, gw_IP_list6,
		    &num_resolved_gw, &num_resolved_gw6);

		/* we couldn't resolve a gateway as an IPv6 host */
		if (num_resolved_gw6 != num_gw && num_v6 != 0 &&
		    (family_input == AF_INET6 || family_input == AF_UNSPEC)) {
			print_unknown_host_msg(" IPv6",
			    gw_list[num_resolved_gw6]);
			num_v6 = 0;
		}

		/* we couldn't resolve a gateway as an IPv4 host */
		if (num_resolved_gw != num_gw && num_v4 != 0 &&
		    (family_input == AF_INET || family_input == AF_UNSPEC)) {
			print_unknown_host_msg(" IPv4",
			    gw_list[num_resolved_gw]);
			num_v4 = 0;
		}
	}

	if (num_v4 == 0 && num_v6 == 0)
		exit(EXIT_FAILURE);

	select_all_src_addrs(&src_addr_list, ai_dst, gw_IP_list, gw_IP_list6);
	*ai_dstp = ai_dst;
	*ai_nexthopp = ai_nexthop;
	*src_addr_listp = src_addr_list;
}

/*
 * Resolve the gateway names, splitting results into v4 and v6 lists.
 * Gateway addresses are added to the appropriate passed-in array; the
 * number of resolved gateways for each af is returned in resolved[6].
 * Assumes that passed-in arrays are large enough for MAX_GWS[6] addrs
 * and resolved[6] ptrs are non-null; ignores array and counter if the
 * address family param makes them irrelevant.
 */
static void
get_gwaddrs(char **gw_list, int family, union any_in_addr *gwIPlist,
    union any_in_addr *gwIPlist6, int *resolved, int *resolved6)
{
	int i;
	boolean_t check_v4 = _B_TRUE, check_v6 = _B_TRUE;
	struct addrinfo	*ai = NULL;
	struct addrinfo	*aip = NULL;

	*resolved = *resolved6 = 0;
	switch (family) {
	case AF_UNSPEC:
		break;
	case AF_INET:
		check_v6 = _B_FALSE;
		break;
	case AF_INET6:
		check_v4 = _B_FALSE;
		break;
	default:
		return;
	}

	if (check_v4 && num_gw >= MAX_GWS) {
		check_v4 = _B_FALSE;
		Fprintf(stderr, "%s: too many IPv4 gateways\n", progname);
	}
	if (check_v6 && num_gw > MAX_GWS6) {
		check_v6 = _B_FALSE;
		Fprintf(stderr, "%s: too many IPv6 gateways\n", progname);
	}

	for (i = 0; i < num_gw; i++) {
		if (!check_v4 && !check_v6)
			return;
		get_hostinfo(gw_list[i], family, &ai);
		if (ai == NULL)
			return;
		if (check_v4 && num_v4 != 0) {
			for (aip = ai; aip != NULL; aip = aip->ai_next) {
				if (aip->ai_family == AF_INET) {
					/* LINTED E_BAD_PTR_CAST_ALIGN */
					bcopy(&((struct sockaddr_in *)
					    aip->ai_addr)->sin_addr,
					    &gwIPlist[i].addr,
					    aip->ai_addrlen);
					(*resolved)++;
					break;
				}
			}
		} else if (check_v4) {
			check_v4 = _B_FALSE;
		}
		if (check_v6 && num_v6 != 0) {
			for (aip = ai; aip != NULL; aip = aip->ai_next) {
				if (aip->ai_family == AF_INET6) {
					/* LINTED E_BAD_PTR_CAST_ALIGN */
					bcopy(&((struct sockaddr_in6 *)
					    aip->ai_addr)->sin6_addr,
					    &gwIPlist6[i].addr6,
					    aip->ai_addrlen);
					(*resolved6)++;
					break;
				}
			}
		} else if (check_v6) {
			check_v6 = _B_FALSE;
		}
	}
	freeaddrinfo(ai);
}

/*
 * Given the list of gateways, extends the list with its mirror image. This is
 * used when -l/-S is used. The middle gateway will be the target address. We'll
 * leave it blank for now.
 */
static void
mirror_gws(union any_in_addr *gwIPlist, int family)
{
	int effective_num_gw;
	int i;

	/* We add 1 because we put the target as the middle gateway */
	effective_num_gw = 2 * num_gw + 1;

	if ((family == AF_INET && effective_num_gw >= MAX_GWS) ||
	    (family == AF_INET6 && effective_num_gw > MAX_GWS6)) {
		Fprintf(stderr, "%s: too many %s gateways\n",
		    progname, (family == AF_INET) ? "IPv4" : "IPv6");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_gw; i++)
		gwIPlist[num_gw + i + 1].addr6 = gwIPlist[num_gw - i - 1].addr6;
}

/*
 * Given IP address or hostname, return addrinfo list.
 * Assumes that addrinfo ** ptr is non-null.
 */
static void
get_hostinfo(char *host, int family, struct addrinfo **aipp)
{
	struct addrinfo hints, *ai;
	struct in6_addr addr6;
	struct in_addr addr;
	boolean_t broadcast;		/* is this 255.255.255.255? */
	char tmp_buf[INET6_ADDRSTRLEN];
	int rc;

	/* check if broadcast */
	if (strcmp(host, "255.255.255.255") == 0)
		broadcast = _B_TRUE;
	else
		broadcast = _B_FALSE;

	/* check if IPv4-mapped address or broadcast */
	if (((inet_pton(AF_INET6, host, &addr6) > 0) &&
	    IN6_IS_ADDR_V4MAPPED(&addr6)) || broadcast) {
		if (!broadcast) {
			/*
			 * Peel off the "mapping" stuff, leaving 32 bit IPv4
			 * address.
			 */
			IN6_V4MAPPED_TO_INADDR(&addr6, &addr);

			/* convert it back to a string */
			(void) inet_ntop(AF_INET, (void *)&addr, tmp_buf,
			    sizeof (tmp_buf));
			/*
			 * Now the host is an IPv4 address.
			 * Since it previously was a v4 mapped v6 address
			 * we can be sure that the size of buffer 'host'
			 * is large enough to contain the associated v4
			 * address and so we don't need to use a strn/lcpy
			 * here.
			 */
			(void) strcpy(host, tmp_buf);
		}
		/*
		 * If it's a broadcast address, it cannot be an IPv6 address.
		 * Also, if it's a mapped address, we convert it into IPv4
		 * address because ping will send and receive IPv4 packets for
		 * that address. Therefore, it's a failure case to ask
		 * get_hostinfo() to treat a broadcast or a mapped address
		 * as an IPv6 address.
		 */
		if (family == AF_INET6) {
			return;
		}
	}

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_family = family;
	hints.ai_flags = AI_ADDRCONFIG;
	rc = getaddrinfo(host, NULL, &hints, &ai);
	if (rc != 0) {
		if (rc != EAI_NONAME)
			Fprintf(stderr, "%s: getaddrinfo: %s\n", progname,
			    gai_strerror(rc));
		return;
	}
	*aipp = ai;
}

/*
 * For each IP address of the target host, determine a source address to use.
 */
static void
select_all_src_addrs(union any_in_addr **src_addr_list, struct addrinfo *ai,
    union any_in_addr *gwv4, union any_in_addr *gwv6)
{
	union any_in_addr *list;
	struct addrinfo *aip;
	int num_dst = 1;
	int i;

	if (probe_all) {
		for (aip = ai; aip->ai_next != NULL; aip = aip->ai_next)
			num_dst++;
	}

	list = calloc((size_t)num_dst, sizeof (union any_in_addr));
	if (list == NULL) {
		Fprintf(stderr, "%s: calloc: %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * If there's a gateway, a routing header as a consequence, our kernel
	 * picks the source address based on the first hop address, rather than
	 * final destination address.
	 */
	if (num_gw > 0) {
		if (ai->ai_family == AF_INET)
			select_src_addr(gwv4, ai->ai_family, &list[0]);
		else
			select_src_addr(gwv6, ai->ai_family, &list[0]);
		/*
		 * Since the first gateway address is fixed, we'll use the same
		 * src address for every different final destination address
		 * we send to.
		 */
		for (i = 1; i < num_dst; i++)
			list[i] = list[0];
	} else {
		/*
		 * Although something like 'ping -l host' results in a routing
		 * header, the first gateway address is the target host's
		 * address. Therefore, as far as src address selection goes,
		 * the result is same as having no routing header.
		 */
		for (i = 0, aip = ai; i < num_dst && aip != NULL;
		    i++, aip = aip->ai_next) {
			if (aip->ai_family == AF_INET) {
				if (num_v4 != 0) {
					select_src_addr((union any_in_addr *)
					    /* LINTED E_BAD_PTR_CAST_ALIGN */
					    &((struct sockaddr_in *)
					    aip->ai_addr)->sin_addr,
					    aip->ai_family,
					    &list[i]);
				}
			} else {
				if (num_v6 != 0) {
					select_src_addr((union any_in_addr *)
					    /* LINTED E_BAD_PTR_CAST_ALIGN */
					    &((struct sockaddr_in6 *)
					    aip->ai_addr)->sin6_addr,
					    aip->ai_family,
					    &list[i]);
				}
			}
		}
	}

	*src_addr_list = list;
}

/*
 * For a given destination address, determine a source address to use.
 * Returns wildcard address if it cannot determine the source address.
 */
static void
select_src_addr(union any_in_addr *dst_addr, int family,
    union any_in_addr *src_addr)
{
	struct sockaddr *sock;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int tmp_fd;
	size_t sock_len;

	sock = (struct sockaddr *)malloc(sizeof (struct sockaddr_in6));
	if (sock == NULL) {
		Fprintf(stderr, "%s: malloc: %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}
	(void) bzero(sock, sizeof (struct sockaddr_in6));

	if (family == AF_INET) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin = (struct sockaddr_in *)sock;
		sin->sin_family = AF_INET;
		sin->sin_addr = dst_addr->addr;
		sin->sin_port = IPPORT_ECHO;	/* port shouldn't be 0 */
		sock_len = sizeof (struct sockaddr_in);
	} else {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6 = (struct sockaddr_in6 *)sock;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = dst_addr->addr6;
		sin6->sin6_port = IPPORT_ECHO;	/* port shouldn't be 0 */
		sock_len = sizeof (struct sockaddr_in6);
	}

	/* open a UDP socket */
	if ((tmp_fd = socket(family, SOCK_DGRAM, 0)) < 0) {
		Fprintf(stderr, "%s: udp socket: %s\n", progname,
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* connect it */
	if (connect(tmp_fd, sock, sock_len) < 0) {
		/*
		 * If there's no route to the destination, this connect() call
		 * fails. We just return all-zero (wildcard) as the source
		 * address, so that user can get to see "no route to dest"
		 * message, as it'll try to send the probe packet out and will
		 * receive ICMP unreachable.
		 */
		if (family == AF_INET)
			src_addr->addr.s_addr = INADDR_ANY;
		else
			src_addr->addr6 = in6addr_any;
		free(sock);
		return;
	}

	/* get the local sock info */
	if (getsockname(tmp_fd, sock, &sock_len) < 0) {
		Fprintf(stderr, "%s: getsockname: %s\n", progname,
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (family == AF_INET) {
		src_addr->addr = sin->sin_addr;
	} else {
		src_addr->addr6 = sin6->sin6_addr;
	}

	(void) close(tmp_fd);
	free(sock);
}

/*
 * Set the IP_NEXTHOP/IPV6_NEXTHOP socket option.
 * exits on failure
 */
static void
set_nexthop(int family, struct addrinfo	*ai_nexthop, int sock)
{
	if (family == AF_INET) {
		ipaddr_t nh;

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		nh = ((struct sockaddr_in *)ai_nexthop->
		    ai_addr)->sin_addr.s_addr;

		/* now we need the sys_ip_config privilege */
		(void) __priv_bracket(PRIV_ON);
		if (setsockopt(sock, IPPROTO_IP, IP_NEXTHOP,
		    &nh, sizeof (ipaddr_t)) < 0) {
			if (errno == EPERM)
				Fprintf(stderr, "%s: Insufficient privilege "
				    "to specify IPv4 nexthop router.\n",
				    progname);
			else
				Fprintf(stderr, "%s: setsockopt %s\n",
				    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
		(void) __priv_bracket(PRIV_OFF);
		/* revert to non-privileged user */
	} else {
		struct sockaddr_in6 *nh;

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		nh = (struct sockaddr_in6 *)ai_nexthop->
		    ai_addr;

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_NEXTHOP,
		    nh, sizeof (struct sockaddr_in6)) < 0) {
			Fprintf(stderr, "%s: setsockopt %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

/*
 * Setup the socket for the given address family.
 * Returns _B_TRUE on success, _B_FALSE on failure. Failure is the case when no
 * interface can be found, or the specified interface (-i) is not found. On
 * library call failures, it exit()s.
 */
static boolean_t
setup_socket(int family, int *send_sockp, int *recv_sockp, int *if_index,
    ushort_t *udp_src_port, struct addrinfo *ai_nexthop)
{
	int send_sock;
	int recv_sock;
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	struct sockaddr *sp;
	struct ipsec_req req;
	size_t slen;
	int on = 1;
	uchar_t char_op;
	int int_op;

	/* now we need the net_icmpaccess privilege */
	(void) __priv_bracket(PRIV_ON);

	recv_sock = socket(family, SOCK_RAW,
	    (family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);

	if (recv_sock < 0) {
		Fprintf(stderr, "%s: socket %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* revert to non-privileged user after opening sockets */
	(void) __priv_bracket(PRIV_OFF);

	if (bypass) {
		(void) memset(&req, 0, sizeof (req));
		req.ipsr_ah_req = IPSEC_PREF_NEVER;
		req.ipsr_esp_req = IPSEC_PREF_NEVER;

		if (setsockopt(recv_sock, (family == AF_INET) ? IPPROTO_IP :
		    IPPROTO_IPV6, IP_SEC_OPT, &req, sizeof (req)) < 0) {
			switch (errno) {
			case EPROTONOSUPPORT:
				/*
				 * No IPsec subsystem or policy loaded.
				 * Bypass implicitly allowed.
				 */
				break;
			case EPERM:
				Fprintf(stderr, "%s: Insufficient privilege "
				    "to bypass IPsec policy.\n", progname);
				exit(EXIT_FAILURE);
				break;
			default:
				Fprintf(stderr, "%s: setsockopt %s\n", progname,
				    strerror(errno));
				exit(EXIT_FAILURE);
				break;
			}
		}
	}

	/*
	 * We always receive on raw icmp socket. But the sending socket can be
	 * raw icmp or udp, depending on the use of -U flag.
	 */
	if (use_udp) {
		send_sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
		if (send_sock < 0) {
			Fprintf(stderr, "%s: socket %s\n", progname,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (bypass) {
			if (setsockopt(send_sock, (family == AF_INET) ?
			    IPPROTO_IP : IPPROTO_IPV6, IP_SEC_OPT, &req,
			    sizeof (req)) < 0) {
				switch (errno) {
				case EPROTONOSUPPORT:
					/*
					 * No IPsec subsystem or policy loaded.
					 * Bypass implicitly allowed.
					 */
					break;
				case EPERM:
					Fprintf(stderr, "%s: Insufficient "
					    "privilege to bypass IPsec "
					    "policy.\n", progname);
					exit(EXIT_FAILURE);
					break;
				default:
					Fprintf(stderr, "%s: setsockopt %s\n",
					    progname, strerror(errno));
					exit(EXIT_FAILURE);
					break;
				}
			}
		}

		/*
		 * In order to distinguish replies to our UDP probes from
		 * other pings', we need to know our source port number.
		 */
		if (family == AF_INET) {
			sp = (struct sockaddr *)&sin;
			slen = sizeof (sin);
		} else {
			sp = (struct sockaddr *)&sin6;
			slen = sizeof (sin6);
		}
		bzero(sp, slen);
		sp->sa_family = family;

		/* Let's bind() send_sock to wildcard address and port */
		if (bind(send_sock, sp, slen) < 0) {
			Fprintf(stderr, "%s: bind %s\n", progname,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* .... and see what port kernel picked for us */
		if (getsockname(send_sock, sp, &slen) < 0) {
			Fprintf(stderr, "%s: getsockname %s\n", progname,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
		*udp_src_port = (family == AF_INET) ? sin.sin_port :
		    sin6.sin6_port;
	} else {
		send_sock = recv_sock;
	}

	if (nexthop != NULL)
		set_nexthop(family, ai_nexthop, send_sock);

	int_op = 48 * 1024;
	if (int_op < datalen)
		int_op = datalen;
	if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, (char *)&int_op,
	    sizeof (int_op)) == -1) {
		Fprintf(stderr, "%s: setsockopt SO_RCVBUF %s\n", progname,
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setsockopt(send_sock, SOL_SOCKET, SO_SNDBUF, (char *)&int_op,
	    sizeof (int_op)) == -1) {
		Fprintf(stderr, "%s: setsockopt SO_SNDBUF %s\n", progname,
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (options & SO_DEBUG) {
		if (setsockopt(send_sock, SOL_SOCKET, SO_DEBUG, (char *)&on,
		    sizeof (on)) == -1) {
			Fprintf(stderr, "%s: setsockopt SO_DEBUG %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (options & SO_DONTROUTE) {
		if (setsockopt(send_sock, SOL_SOCKET, SO_DONTROUTE, (char *)&on,
		    sizeof (on)) == -1) {
			Fprintf(stderr, "%s: setsockopt SO_DONTROUTE %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (moptions & MULTICAST_NOLOOP) {
		if (family == AF_INET) {
			char_op = 0;	/* used to turn off option */

			if (setsockopt(send_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
			    (char *)&char_op, sizeof (char_op)) == -1) {
				Fprintf(stderr, "%s: setsockopt "
				    "IP_MULTICAST_NOLOOP %s\n", progname,
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else {
			int_op = 0;	/* used to turn off option */

			if (setsockopt(send_sock, IPPROTO_IPV6,
			    IPV6_MULTICAST_LOOP, (char *)&int_op,
			    sizeof (int_op)) == -1) {
				Fprintf(stderr, "%s: setsockopt "
				    "IPV6_MULTICAST_NOLOOP %s\n", progname,
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
	}

	if (moptions & MULTICAST_TTL) {
		char_op = hoplimit;

		/* Applies to unicast and multicast. */
		if (family == AF_INET) {
			if (setsockopt(send_sock, IPPROTO_IP, IP_MULTICAST_TTL,
			    (char *)&char_op, sizeof (char)) == -1) {
				Fprintf(stderr, "%s: setsockopt "
				    "IP_MULTICAST_TTL %s\n", progname,
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (setsockopt(send_sock, IPPROTO_IP, IP_TTL,
			    (char *)&hoplimit, sizeof (hoplimit)) == -1) {
				Fprintf(stderr, "%s: setsockopt IP_TTL %s\n",
				    progname, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		/*
		 * AF_INET6 case is handled in set_ancillary_data() function.
		 * This is because when ancillary data is used (for routing
		 * header and outgoing interface index), the hoplimit set using
		 * setsockopt() is ignored.
		 */
	}

	/*
	 * did the user specify an interface?
	 * Applies to unicast, broadcast and multicast.
	 */
	if (moptions & MULTICAST_IF) {
		struct ifaddrlist *al = NULL;		/* interface list */
		struct ifaddrlist *my_if;
		char errbuf[ERRBUFSIZE];
		int num_ifs;
		int num_src_ifs;		/* exclude down and loopback */
		int i;

		/* pull out the interface list */
		num_ifs = ifaddrlist(&al, family, LIFC_UNDER_IPMP, errbuf);
		if (num_ifs == -1) {
			Fprintf(stderr, "%s: %s\n", progname, errbuf);
			exit(EXIT_FAILURE);
		}

		/* filter out down and loopback interfaces */
		num_src_ifs = 0;
		for (i = 0; i < num_ifs; i++) {
			if (!(al[i].flags & IFF_LOOPBACK) &&
			    (al[i].flags & IFF_UP))
				num_src_ifs++;
		}

		if (num_src_ifs == 0) {
			Fprintf(stderr, "%s: can't find any %s interface\n",
			    progname, (family == AF_INET) ? "IPv4" : "IPv6");

			return (_B_FALSE);	/* failure */
		}

		/* locate the specified interface */
		my_if = find_if(al, num_ifs);
		if (my_if == NULL) {
			Fprintf(stderr, "%s: %s is an invalid %s interface\n",
			    progname, out_if.str,
			    (family == AF_INET) ? "IPv4" : "IPv6");

			return (_B_FALSE);
		}

		if (family == AF_INET) {
			struct in_pktinfo pktinfo;

			if (setsockopt(send_sock, IPPROTO_IP, IP_MULTICAST_IF,
			    (char *)&my_if->addr.addr,
			    sizeof (struct in_addr)) == -1) {
				Fprintf(stderr, "%s: setsockopt "
				    "IP_MULTICAST_IF %s\n", progname,
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
			bzero(&pktinfo, sizeof (pktinfo));
			pktinfo.ipi_ifindex = my_if->index;
			if (setsockopt(send_sock, IPPROTO_IP, IP_PKTINFO,
			    (char *)&pktinfo, sizeof (pktinfo)) == -1) {
				Fprintf(stderr, "%s: setsockopt "
				    "IP_PKTINFO %s\n", progname,
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else {
			/*
			 * the outgoing interface is set in set_ancillary_data()
			 * function
			 */
			*if_index = my_if->index;
		}

		free(al);
	}

	if (settos && family == AF_INET) {
		int_op = tos;
		if (setsockopt(send_sock, IPPROTO_IP, IP_TOS, (char *)&int_op,
		    sizeof (int_op)) == -1) {
			Fprintf(stderr, "%s: setsockopt IP_TOS %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* We enable or disable to not depend on the kernel default */
	if (family == AF_INET) {
		if (setsockopt(send_sock, IPPROTO_IP, IP_DONTFRAG,
		    (char *)&dontfrag, sizeof (dontfrag)) == -1) {
			Fprintf(stderr, "%s: setsockopt IP_DONTFRAG %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		if (setsockopt(send_sock, IPPROTO_IPV6, IPV6_DONTFRAG,
		    (char *)&dontfrag, sizeof (dontfrag)) == -1) {
			Fprintf(stderr, "%s: setsockopt IPV6_DONTFRAG %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* receiving IPv6 extension headers in verbose mode */
	if (verbose && family == AF_INET6) {
		if (setsockopt(recv_sock, IPPROTO_IPV6, IPV6_RECVHOPOPTS,
		    (char *)&on, sizeof (on)) == -1) {
			Fprintf(stderr, "%s: setsockopt IPV6_RECVHOPOPTS %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (setsockopt(recv_sock, IPPROTO_IPV6, IPV6_RECVDSTOPTS,
		    (char *)&on, sizeof (on)) == -1) {
			Fprintf(stderr, "%s: setsockopt IPV6_RECVDSTOPTS %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (setsockopt(recv_sock, IPPROTO_IPV6, IPV6_RECVRTHDR,
		    (char *)&on, sizeof (on)) == -1) {
			Fprintf(stderr, "%s: setsockopt IPV6_RECVRTHDR %s\n",
			    progname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	*send_sockp = send_sock;
	*recv_sockp = recv_sock;

	/* successful */
	return (_B_TRUE);
}

/*
 * Pull out the record containing all the info about the interface specified by
 * `out_if'. Skips interfaces which are down or loopback.
 */
static struct ifaddrlist *
find_if(struct ifaddrlist *al, int num_ifs)
{
	static struct ifaddrlist tmp_if;
	boolean_t found;
	int i;

	i = 0;
	found = _B_FALSE;

	while (i < num_ifs && !found) {
		tmp_if = al[i];

		/* skip down or loopback interfaces */
		if ((tmp_if.flags & IFF_LOOPBACK) || !(tmp_if.flags & IFF_UP)) {
			i++;
			continue;
		}

		/* the type of interface id is variable */
		switch (out_if.id_type) {
		case IF_INDEX:
			if (out_if.id.index == tmp_if.index)
				found = _B_TRUE;
			break;

		case IF_NAME:
			if (strcmp(out_if.id.name, tmp_if.device) == 0)
				found = _B_TRUE;
			break;

		case IF_ADDR:
			if (out_if.id.addr.addr.s_addr ==
			    tmp_if.addr.addr.s_addr) {
				found = _B_TRUE;
			}
			break;

		case IF_ADDR6:
			if (IN6_ARE_ADDR_EQUAL(&out_if.id.addr.addr6,
			    &tmp_if.addr.addr6)) {
				found = _B_TRUE;
			}
			break;

		default:
			break;
		}

		i++;
	}

	if (found)
		return (&tmp_if);
	else
		return (NULL);
}

/*
 * Invoked by SIGALRM, sigalrm_handler() is, responsible for calling
 * send_scheduled_probe() to send next probe.
 */
void
sigalrm_handler(void)
{
	/*
	 * Guard againist denial-of-service attacks. Make sure ping doesn't
	 * send probes for every SIGALRM it receives. Evil hacker can generate
	 * SIGALRMs as fast as it can, but ping will ignore those which are
	 * received too soon (earlier than 0.5 sec) after it sent the last
	 * probe.  We use gethrtime() instead of gettimeofday() because
	 * the latter is not linear and is prone to resetting or drifting
	 */
	if ((gethrtime() - t_last_probe_sent) < 500000000) {
		return;
	}
	send_scheduled_probe();
	schedule_sigalrm();
}

/*
 * Schedule next SIGALRM.
 */
void
schedule_sigalrm(void)
{
	int waittime;

	if (npackets == 0 ||
	    current_targetaddr->num_sent < current_targetaddr->num_probes) {
		(void) alarm(interval);
	} else {
		if (current_targetaddr->got_reply) {
			waittime = 2 * tmax / MICROSEC;
			if (waittime == 0)
				waittime = 1;
		} else {
			waittime = MAX_WAIT;
		}
		(void) alarm(waittime);
	}
}

/*
 * Called by sigalrm_handler(), check_reply() or check_reply6(),
 * send_scheduled_probe() looks at the current_targetaddr and determines what
 * should be sent next and calls pinger().
 */
void
send_scheduled_probe()
{
	static struct msghdr msg6;
	static boolean_t first_probe = _B_TRUE;
	char tmp_buf[INET6_ADDRSTRLEN];

	/*
	 * We are about to move to next targetaddr if it's either we sent
	 * all the probes, or somebody set the probing_done flag to
	 * _B_TRUE prompting us to move on.
	 */
	if (current_targetaddr->num_sent == current_targetaddr->num_probes ||
	    current_targetaddr->probing_done) {
		/*
		 * is this a dead target?
		 */
		if (!stats && !current_targetaddr->got_reply) {
			if (!probe_all) {
				Printf("no answer from %s\n", targethost);
			} else {
				Printf("no answer from %s(%s)\n", targethost,
				    inet_ntop(current_targetaddr->family,
				    &current_targetaddr->dst_addr,
				    tmp_buf, sizeof (tmp_buf)));
			}
		}
		/*
		 * Before we move onto next item, let's do some clean up.
		 */
		current_targetaddr->got_reply = _B_FALSE;
		current_targetaddr->probing_done = _B_FALSE;
		/*
		 * If this is probe-all without stats mode, then we need to
		 * preserve this count. This is needed when we try to map an
		 * icmp_seq to IP address. Otherwise, clear it.
		 */
		if (stats || !probe_all)
			current_targetaddr->num_sent = 0;
		nreceived_last_target = 0;

		current_targetaddr = current_targetaddr->next;

		/*
		 * Did we reach the end of road?
		 */
		if (current_targetaddr == NULL) {
			(void) alarm(0);	/* cancel alarm */
			if (stats)
				finish();
			if (is_alive)
				exit(EXIT_SUCCESS);
			else
				exit(EXIT_FAILURE);
		} else {
			/*
			 * We use starting_seq_num for authenticating replies.
			 * Each time we move to a new targetaddr, which has
			 * a different target IP address, we update this field.
			 */
			current_targetaddr->starting_seq_num = use_udp ?
			    dest_port : (ntransmitted % (MAX_ICMP_SEQ + 1));
		}
	}

	if (current_targetaddr->family == AF_INET6) {
		if (send_reply) {
			/* sending back to ourself */
			to6.sin6_addr = current_targetaddr->src_addr.addr6;
		} else {
			to6.sin6_addr = current_targetaddr->dst_addr.addr6;
		}
		/*
		 * Setting the ancillary data once is enough, if we are
		 * not using source routing through target (-l/-S). In
		 * case -l/-S used, the middle gateway will be the
		 * IP address of the source, which can be different
		 * for each target IP.
		 */
		if (first_probe ||
		    (send_reply && current_targetaddr->num_sent == 0)) {
			if (send_reply) {
				/* target is the middle gateway now */
				gw_IP_list6[num_gw].addr6 =
				    current_targetaddr->dst_addr.addr6;
			}
			set_ancillary_data(&msg6, hoplimit, gw_IP_list6,
			    eff_num_gw, if_index);
			first_probe = _B_FALSE;
		}
		pinger(send_sock6, (struct sockaddr *)&to6, &msg6, AF_INET6);
	} else {
		to.sin_addr = current_targetaddr->dst_addr.addr;
		/*
		 * Set IPv4 options when sending the first probe to a target
		 * IP address. Some options change when the target address
		 * changes.
		 */
		if (current_targetaddr->num_sent == 0) {
			if (eff_num_gw > 0) {
				gw_IP_list[num_gw].addr =
				    current_targetaddr->dst_addr.addr;
				/*
				 * If send_reply, the target becomes the
				 * middle gateway, sender becomes the last
				 * gateway.
				 */
				if (send_reply) {
					gw_IP_list[eff_num_gw].addr =
					    current_targetaddr->src_addr.addr;
				}
			}
			/*
			 * In IPv4, if source routing is used, the target
			 * address shows up as the last gateway, hence +1.
			 */
			set_IPv4_options(send_sock, gw_IP_list,
			    (eff_num_gw > 0) ? eff_num_gw + 1 : 0,
			    &current_targetaddr->src_addr.addr, &to.sin_addr);
		}
		pinger(send_sock, (struct sockaddr *)&to, NULL, AF_INET);
	}

	current_targetaddr->num_sent++;
}

/*
 * recv_icmp_packet()'s job is to listen to icmp packets and filter out
 * those ping is interested in.
 */
static void
recv_icmp_packet(struct addrinfo *ai_dst, int recv_sock6, int recv_sock,
ushort_t udp_src_port6, ushort_t udp_src_port)
{
	struct msghdr in_msg;
	struct iovec iov;
	struct sockaddr_in6 from6;
	fd_set fds;
	int result;
	int cc;
	boolean_t always_true = _B_TRUE; /* lint doesn't like while(_B_TRUE) */

	while (always_true) {
		(void) FD_ZERO(&fds);
		if (recv_sock6 != -1)
			FD_SET(recv_sock6, &fds);
		if (recv_sock != -1)
			FD_SET(recv_sock, &fds);

		result = select(MAX(recv_sock6, recv_sock) + 1, &fds,
		    (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)NULL);
		if (result == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				Fprintf(stderr, "%s: select %s\n", progname,
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else if (result > 0) {
			in_msg.msg_name = &from6;
			in_msg.msg_namelen = sizeof (from6);
			iov.iov_base = in_pkt;
			iov.iov_len = sizeof (in_pkt);
			in_msg.msg_iov = &iov;
			in_msg.msg_iovlen = 1;
			in_msg.msg_control = ancillary_data;
			in_msg.msg_controllen = sizeof (ancillary_data);

			/* Do we have an ICMP6 packet waiting? */
			if ((recv_sock6 != -1) &&
			    (FD_ISSET(recv_sock6, &fds))) {
				cc = recvmsg(recv_sock6, &in_msg, 0);
				if (cc < 0) {
					if (errno != EINTR) {
						Fprintf(stderr,
						    "%s: recvmsg %s\n",
						    progname, strerror(errno));
					}
					continue;
				} else if (cc > 0) {
					check_reply6(ai_dst, &in_msg, cc,
					    udp_src_port6);
				}
			}
			/* Do we have an ICMP packet waiting? */
			if ((recv_sock != -1) && (FD_ISSET(recv_sock, &fds))) {
				cc = recvmsg(recv_sock, &in_msg, 0);
				if (cc < 0) {
					if (errno != EINTR) {
						Fprintf(stderr,
						    "%s: recvmsg %s\n",
						    progname, strerror(errno));
					}
					continue;
				} if (cc > 0) {
					check_reply(ai_dst, &in_msg, cc,
					    udp_src_port);
				}
			}
		}
		/*
		 * If we were probing last IP address of the target host and
		 * received a reply for each probe sent to this address,
		 * then we are done!
		 */
		if ((npackets > 0) && (current_targetaddr->next == NULL) &&
		    (nreceived_last_target == npackets)) {
			(void) alarm(0);	/* cancel alarm */
			finish();
		}
	} /* infinite loop */
}

/*
 * Given a host (with possibly multiple IP addresses) and an IP address, this
 * function determines if this IP address is one of the host's addresses to
 * which we're sending probes. Used to determine if we are interested in a
 * packet.
 */
boolean_t
is_a_target(struct addrinfo *ai, union any_in_addr *addr)
{
	int num_addrs;
	int i;
	struct addrinfo *aip;

	aip = ai;
	if (probe_all)
		num_addrs = num_v4 + num_v6;
	else
		num_addrs = 1;
	for (i = 0; i < num_addrs && aip != NULL; i++) {
		if (aip->ai_family == AF_INET6) {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			if (IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)
			    aip->ai_addr)->sin6_addr, &addr->addr6))
				return (_B_TRUE);
		} else {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			if (((struct sockaddr_in *)
			    aip->ai_addr)->sin_addr.s_addr == addr->addr.s_addr)
				return (_B_TRUE);
		}
	}

	return (_B_FALSE);
}

/*
 * Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in network
 * byte-order, to compute the round-trip time.
 */
static void
pinger(int send_sock, struct sockaddr *whereto, struct msghdr *msg6,
    int family)
{
	static uint64_t out_pkt_buf[(IP_MAXPACKET + 1) / 8];
	uchar_t *out_pkt = (uchar_t *)&out_pkt_buf;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct icmp *icp = (struct icmp *)out_pkt;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in6 *to6 = (struct sockaddr_in6 *)whereto;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in *to = (struct sockaddr_in *)whereto;
	struct timeval *tp;
	struct timeval t_snd;
	uchar_t *datap;
	struct iovec iov;
	int start = 0;
	int cc;
	int i;

	/* using UDP? */
	if (use_udp) {
		cc = datalen;

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		tp = (struct timeval *)out_pkt;
		datap = &out_pkt[sizeof (struct timeval)];

		/*
		 * This sets the port whether we are handling a v4 or v6
		 * sockaddr structure.
		 */
		to->sin_port = htons(dest_port);

		dest_port = (dest_port + 1) % (MAX_PORT + 1);
		ntransmitted++;
	} else {	/* using ICMP */
		cc = datalen + ICMP_MINLEN;

		if (family == AF_INET6) {
			icp->icmp_type = send_reply ?
			    ICMP6_ECHO_REPLY : ICMP6_ECHO_REQUEST;
		} else if (use_icmp_ts) {	/* family is AF_INET */
			icp->icmp_type = send_reply ?
			    ICMP_TSTAMPREPLY : ICMP_TSTAMP;
		} else {
			icp->icmp_type = send_reply ?
			    ICMP_ECHOREPLY : ICMP_ECHO;
		}

		icp->icmp_code = 0;
		icp->icmp_cksum = 0;
		icp->icmp_seq = htons(ntransmitted++ % (MAX_ICMP_SEQ + 1));
		if (icp->icmp_seq == 0)
			num_wraps++;
		icp->icmp_id = htons(ident);		/* ID */

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		tp = (struct timeval *)&out_pkt[ICMP_MINLEN];
		datap = &out_pkt[ICMP_MINLEN + sizeof (struct timeval)];
	}

	start = sizeof (struct timeval);	/* skip for time */

	(void) gettimeofday(&t_snd, (struct timezone *)NULL);

	/* if packet is big enough to store timeval OR ... */
	if ((datalen >= sizeof (struct timeval)) ||
	    (family == AF_INET && use_icmp_ts))
		*tp = t_snd;

	if (family == AF_INET && use_icmp_ts) {
		start = sizeof (struct id_ts);	/* skip for ICMP timestamps */
		/* Number of milliseconds since midnight */
		icp->icmp_otime = htonl((tp->tv_sec % (24*60*60)) * 1000 +
		    tp->tv_usec / 1000);
	}

	for (i = start; i < datalen; i++)
		*datap++ = i;

	if (family == AF_INET) {
		if (!use_udp)
			icp->icmp_cksum = in_cksum((ushort_t *)icp, cc);

		i = sendto(send_sock, (char *)out_pkt, cc, 0, whereto,
		    sizeof (struct sockaddr_in));
	} else {
		/*
		 * Fill in the rest of the msghdr structure. msg_control is set
		 * in set_ancillary_data().
		 */
		msg6->msg_name = to6;
		msg6->msg_namelen = sizeof (struct sockaddr_in6);

		iov.iov_base = out_pkt;
		iov.iov_len = cc;

		msg6->msg_iov = &iov;
		msg6->msg_iovlen = 1;

		i = sendmsg(send_sock, msg6, 0);
	}

	/* This is a more precise time (right after we send the packet) */
	t_last_probe_sent = gethrtime();

	if (i < 0 || i != cc)  {
		if (i < 0) {
			Fprintf(stderr, "%s: sendto %s\n", progname,
			    strerror(errno));
			if (!stats)
				exit(EXIT_FAILURE);
		}
		Printf("ping: wrote %s %d chars, ret=%d\n",
		    targethost, cc, i);
		(void) fflush(stdout);
	}
}

/*
 * Return a hostname for the given IP address.
 */
char *
pr_name(char *addr, int family)
{
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa;
	static struct in6_addr prev_addr = IN6ADDR_ANY_INIT;
	char *cp;
	char abuf[INET6_ADDRSTRLEN];
	static char buf[NI_MAXHOST + INET6_ADDRSTRLEN + 3];
	uint_t slen, alen, hlen;

	switch (family) {
	case AF_INET:
		(void) memset(&sin, 0, sizeof (sin));
		slen = sizeof (struct sockaddr_in);
		alen = sizeof (struct in_addr);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin.sin_addr = *(struct in_addr *)addr;
		sin.sin_port = 0;
		sa = (struct sockaddr *)&sin;
		break;
	case AF_INET6:
		(void) memset(&sin6, 0, sizeof (sin6));
		slen = sizeof (struct sockaddr_in6);
		alen = sizeof (struct in6_addr);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6.sin6_addr = *(struct in6_addr *)addr;
		sin6.sin6_port = 0;
		sa = (struct sockaddr *)&sin6;
		break;
	default:
		(void) snprintf(buf, sizeof (buf), "<invalid address family>");
		return (buf);
	}
	sa->sa_family = family;

	/* compare with the buffered (previous) lookup */
	if (memcmp(addr, &prev_addr, alen) != 0) {
		int flags = (nflag) ? NI_NUMERICHOST : NI_NAMEREQD;
		if (getnameinfo(sa, slen, buf, sizeof (buf),
		    NULL, 0, flags) != 0) {
			/* getnameinfo() failed; return just the address */
			if (inet_ntop(family, (const void*)addr,
			    buf, sizeof (buf)) == NULL)
				buf[0] = 0;
		} else if (!nflag) {
			/* append numeric address to hostname string */
			hlen = strlen(buf);
			cp = (char *)(buf + hlen);
			(void) snprintf(cp, sizeof (buf) - hlen, " (%s)",
			    inet_ntop(family, (const void *)addr, abuf,
			    sizeof (abuf)));
		}

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		prev_addr = *(struct in6_addr *)addr;
	}
	return (buf);
}

/*
 * Return the protocol string, given its protocol number.
 */
char *
pr_protocol(int prot)
{
	static char buf[20];

	switch (prot) {
	case IPPROTO_ICMPV6:
		(void) strlcpy(buf, "icmp6", sizeof (buf));
		break;

	case IPPROTO_ICMP:
		(void) strlcpy(buf, "icmp", sizeof (buf));
		break;

	case IPPROTO_TCP:
		(void) strlcpy(buf, "tcp", sizeof (buf));
		break;

	case IPPROTO_UDP:
		(void) strlcpy(buf, "udp", sizeof (buf));
		break;

	default:
		(void) snprintf(buf, sizeof (buf), "prot %d", prot);
		break;
	}

	return (buf);
}

/*
 * Checks if value is between seq_begin and seq_begin+seq_len. Note that
 * sequence numbers wrap around after MAX_ICMP_SEQ (== MAX_PORT).
 */
boolean_t
seq_match(ushort_t seq_begin, int seq_len, ushort_t value)
{
	/*
	 * If seq_len is too big, like some value greater than MAX_ICMP_SEQ/2,
	 * truncate it down to MAX_ICMP_SEQ/2. We are not going to accept any
	 * reply which come 83hr later!
	 */
	if (seq_len > MAX_ICMP_SEQ / 2) {
		seq_begin = (seq_begin + seq_len - MAX_ICMP_SEQ / 2) %
		    (MAX_ICMP_SEQ + 1);
		seq_len = MAX_ICMP_SEQ / 2;
	}

	if (PINGSEQ_LEQ(seq_begin, value) &&
	    PINGSEQ_LEQ(value, (seq_begin + seq_len - 1) % (MAX_ICMP_SEQ + 1)))
		return (_B_TRUE);
	else
		return (_B_FALSE);
}

/*
 * For a given icmp_seq, find which destination address we must have sent this
 * to.
 */
void
find_dstaddr(ushort_t icmpseq, union any_in_addr *ipaddr)
{
	struct targetaddr *target = targetaddr_list;
	int real_seq;
	int targetaddr_index;
	int real_npackets;
	int i;

	ipaddr->addr6 = in6addr_any;

	/*
	 * If this is probe_all and not stats, then the number of probes sent to
	 * each IP address may be different (remember, we stop sending to one IP
	 * address as soon as it replies). They are stored in target->num_sent
	 * field. Since we don't wrap around the list (!stats), they are also
	 * preserved.
	 */
	if (probe_all && !stats) {
		do {
			if (seq_match(target->starting_seq_num,
			    target->num_sent, icmpseq)) {
				ipaddr->addr6 = target->dst_addr.addr6;
				/*
				 * We are not immediately return()ing here.
				 * Because of wrapping, we might find another
				 * match later, which is more likely to be the
				 * real one.
				 */
			}
			target = target->next;
		} while (target != NULL);
	} else {
		/*
		 * Find the absolute (non-wrapped) seq number within the last
		 * 64K
		 */
		if (icmpseq < (ntransmitted % (MAX_ICMP_SEQ + 1))) {
			real_seq = num_wraps * (MAX_ICMP_SEQ + 1) + icmpseq;
		} else {
			real_seq = (num_wraps - 1) * (MAX_ICMP_SEQ + 1) +
			    icmpseq;
		}

		/* Make sure it's non-negative */
		if (real_seq < 0)
			return;
		real_npackets = (npackets == 0) ? 1 : npackets;

		/*
		 * We sent npackets many packets to each of those
		 * num_targetaddrs many IP addresses.
		 */
		targetaddr_index =
		    (real_seq % (num_targetaddrs * real_npackets)) /
		    real_npackets;
		for (i = 0; i < targetaddr_index; i++)
			target = target->next;
		ipaddr->addr6 = target->dst_addr.addr6;
	}
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
static ushort_t
in_cksum(ushort_t *addr, int len)
{
	int nleft = len;
	ushort_t *w = addr;
	ushort_t answer;
	ushort_t odd_byte = 0;
	int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(uchar_t *)(&odd_byte) = *(uchar_t *)w;
		sum += odd_byte;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
 * Subtract 2 timeval structs:  out = out - in.
 * Out is assumed to be >= in.
 */
void
tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		out->tv_sec--;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

/*
 * Print out statistics, and give up.
 * Heavily buffered STDIO is used here, so that all the statistics
 * will be written with 1 sys-write call.  This is nice when more
 * than one copy of the program is running on a terminal;  it prevents
 * the statistics output from becoming intermingled.
 */
static void
finish()
{
	Printf("\n----%s PING Statistics----\n", targethost);
	Printf("%d packets transmitted, ", ntransmitted);
	Printf("%d packets received, ", nreceived);
	if (ntransmitted) {
		if (nreceived <= ntransmitted) {
			Printf("%d%% packet loss",
			    (int)(((ntransmitted-nreceived)*100) /
			    ntransmitted));
		} else {
			Printf("%.2f times amplification",
			    (double)nreceived / (double)ntransmitted);
		}
	}
	(void) putchar('\n');

	/* if packet is big enough to store timeval AND ... */
	if ((datalen >= sizeof (struct timeval)) && (nreceived > 0)) {
		double mean = (double)tsum / nreceived;
		double smean = (double)tsum2 / nreceived;
		double sd =
		    sqrt(((smean - mean*mean) * nreceived) / (nreceived-1));

		Printf("round-trip (ms)  min/avg/max/stddev = "
		    TIMEFORMAT "/" TIMEFORMAT "/"
		    TIMEFORMAT "/" TIMEFORMAT "\n",
		    (double)tmin / 1000, mean / 1000,
		    (double)tmax / 1000, sd / 1000);
	}
	(void) fflush(stdout);

	exit(is_alive ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * print the usage line
 */
static void
usage(char *cmdname)
{
	Fprintf(stderr, "usage: %s host [timeout]\n", cmdname);
	Fprintf(stderr,
/* CSTYLED */
"usage: %s -s [-l | -U] [-abdDLnRrv] [-A addr_family] [-c traffic_class]\n\t"
"[-g gateway [-g gateway ...]] [-N nexthop] [-F flow_label] [-I interval]\n\t"
"[-i interface] [-P tos] [-p port] [-t ttl] host [data_size] [npackets]\n",
	    cmdname);
}

/*
 * Parse integer argument; exit with an error if it's not a number.
 * Now it also accepts hex. values.
 */
static int
int_arg(char *s, char *what)
{
	char *cp;
	char *ep;
	int num;

	errno = 0;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		cp = s + 2;
		num = (int)strtol(cp, &ep, 16);
	} else {
		num = (int)strtol(s, &ep, 10);
	}

	if (errno || *ep != '\0' || num < 0) {
		(void) Fprintf(stderr, "%s: bad %s: %s\n",
		    progname, what, s);
		exit(EXIT_FAILURE);
	}

	return (num);
}

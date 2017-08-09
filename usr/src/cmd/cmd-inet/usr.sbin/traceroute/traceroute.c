/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * Copyright (c) 1988, 1989, 1991, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * @(#)$Header: traceroute.c,v 1.49 97/06/13 02:30:23 leres Exp $ (LBL)
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/sysmacros.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <malloc.h>
#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>
#include <zone.h>
#include <thread.h>
#include <synch.h>

#include <priv_utils.h>

#include <libinetutil.h>
#include "traceroute.h"

#define	MAX_SEQ			65535	/* max sequence value for ICMP */
#define	MAX_TRAFFIC_CLASS	255	/* max traffic class for IPv6 */
#define	MAX_FLOW_LABEL		0xFFFFF	/* max flow label for IPv6 */
#define	MAX_TOS			255	/* max type-of-service for IPv4 */
#define	STR_LEN			30

/* store the information about a host */
struct hostinfo {
	char *name;		/* hostname */
	int family;		/* address family of the IP addresses */
	int num_addr;			/* number of IP addresses */
	union any_in_addr *addrs;	/* list of IP addresses */
};

/* used to store a bunch of protocol specific values */
struct pr_set {
	int family;		/* AF_INET or AF_INET6 */
	char name[STR_LEN];	/* "IPv4" or "IPv6" */
	char icmp[STR_LEN];	/* "icmp" or "ipv6-icmp" */
	int icmp_minlen;
	int addr_len;
	int ip_hdr_len;
	int packlen;
	int sock_size;		/* size of sockaddr_in or sockaddr_in6 */
	struct sockaddr *to;
	struct sockaddr *from;
	void *from_sin_addr;
	union any_in_addr *gwIPlist;
	/* pointers to v4/v6 functions */
	struct ip *(*set_buffers_fn) (int);
	int (*check_reply_fn)(struct msghdr *, int, int, uchar_t *, uchar_t *);
	boolean_t (*print_icmp_other_fn)(uchar_t, uchar_t);
	void (*print_addr_fn)(uchar_t *, int, struct sockaddr *);

};

/*
 * LBNL bug fixed: in LBNL traceroute 'uchar_t packet[512];'
 * Not sufficient to hold the complete packet for ECHO REPLY of a big probe.
 * Packet size is reported incorrectly in such a case.
 * Also this buffer needs to be 32 bit aligned. In the future the alignment
 * requirement will be increased to 64 bit. So, let's use 64 bit alignment now.
 */
static uint64_t packet[(IP_MAXPACKET + 1)/8];	/* received packet */

static struct ip *outip4;	/* output buffer to send as an IPv4 datagram */
static struct ip *outip6;	/* output buffer to send as an IPv6 datagram */

/* Used to store the ancillary data that comes with the received packets */
static uint64_t ancillary_data[(IP_MAXPACKET + 1)/8];

/* first get the gw names, later you'll resolve them based on the family */
static char *gwlist[MAXMAX_GWS];		/* gateway names list */
static union any_in_addr gwIPlist[MAX_GWS];	/* gateway IPv4 address list */
static union any_in_addr gwIP6list[MAX_GWS6];	/* gateway IPv6 address list */

static int family_input = AF_UNSPEC;	/* User supplied protocol family */
static int rcvsock4;		/* receive (icmp) socket file descriptor */
static int sndsock4;		/* send (udp/icmp) socket file descriptor */
static int rcvsock6;		/* receive (icmp6) socket file descriptor */
static int sndsock6;		/* send (udp6/icmp6) socket file descriptor */
int gw_count = 0;		/* number of gateways */
static struct sockaddr_in whereto;	/* Who to try to reach */
static struct sockaddr_in6 whereto6;
static struct sockaddr_in wherefrom;	/* Who we are */
static struct sockaddr_in6 wherefrom6;
static int packlen_input = 0;		/* user input for packlen */

char *prog;
static char *source_input = NULL; /* this is user arg. source, doesn't change */
static char *source = NULL;	/* this gets modified after name lookup */
char *hostname;
static char *device = NULL;   	/* interface name */
static struct pr_set *pr4;	/* protocol info for IPv4 */
static struct pr_set *pr6;	/* protocol info for IPv6 */
static struct ifaddrlist *al4;	/* list of interfaces */
static struct ifaddrlist *al6;	/* list of interfaces */
static uint_t if_index = 0;	/* interface index */
static int num_v4 = 0;		/* count of IPv4 addresses */
static int num_v6 = 0;		/* count of IPv6 addresses */
static int num_ifs4 = 0;	/* count of local IPv4 interfaces */
static int num_ifs6 = 0;	/* count of local IPv6 interfaces */

static int nprobes = 3;		/* number of probes */
static int max_ttl = 30;	/* max number of hops */
static int first_ttl = 1;	/* initial number of hops */
ushort_t ident;			/* used to authenticate replies */
ushort_t port = 32768 + 666;	/* start udp dest port # for probe packets */

static int options = 0;		/* socket options */
boolean_t verbose = _B_FALSE;	/* verbose output */
static int waittime = 5;	/* time to wait for response (in seconds) */
static struct timeval delay = {0, 0}; /* delay between consecutive probe */
boolean_t nflag = _B_FALSE;	/* print addresses numerically */
static boolean_t showttl = _B_FALSE; /* print the ttl(hop limit) of recvd pkt */
boolean_t useicmp = _B_FALSE;  	/* use icmp echo instead of udp packets */
boolean_t docksum = _B_TRUE;	/* calculate checksums */
static boolean_t collect_stat = _B_FALSE;	/* print statistics */
boolean_t settos = _B_FALSE;   	/* set type-of-service field */
int dontfrag = 0;		/* IP*_DONTFRAG */
static int max_timeout = 5;	/* quit after this consecutive timeouts */
static boolean_t probe_all = _B_FALSE;	/* probe all the IFs of the target */
static boolean_t pick_src = _B_FALSE;	/* traceroute picks the src address */

/*
 * flow and class are specific to IPv6, tos and off are specific to IPv4.
 * Each protocol uses the ones that are specific to itself, and ignores
 * others.
 */
static uint_t flow = 0;		/* IPv6 flow info */
static uint_t class = 0;	/* IPv6 class */
uchar_t tos = 0;		/* IPv4 type-of-service */
ushort_t off = 0;		/* set DF bit */

static jmp_buf env;		/* stack environment for longjmp() */
boolean_t raw_req;		/* if sndsock for IPv4 must be raw */

/*
 * Name service lookup related data.
 */
static mutex_t tr_nslock = ERRORCHECKMUTEX;
static boolean_t tr_nsactive = _B_FALSE;	/* Lookup ongoing */
static hrtime_t tr_nsstarttime;			/* Start time */
static int tr_nssleeptime = 2;			/* Interval between checks */
static int tr_nswarntime = 2;			/* Interval to warn after */

/* Forwards */
static uint_t calc_packetlen(int, struct pr_set *);
extern int check_reply(struct msghdr *, int, int, uchar_t *, uchar_t *);
extern int check_reply6(struct msghdr *, int, int, uchar_t *, uchar_t *);
static double deltaT(struct timeval *, struct timeval *);
static char *device_name(struct ifaddrlist *, int, union any_in_addr *,
    struct pr_set *);
extern void *find_ancillary_data(struct msghdr *, int, int);
static boolean_t has_addr(struct addrinfo *, union any_in_addr *);
static struct ifaddrlist *find_device(struct ifaddrlist *, int, char *);
static struct ifaddrlist *find_ifaddr(struct ifaddrlist *, int,
    union any_in_addr *, int);
static void get_gwaddrs(char **, int, union any_in_addr *,
    union any_in_addr *, int *, int *);
static void get_hostinfo(char *, int, struct addrinfo **);
char *inet_name(union any_in_addr *, int);
ushort_t in_cksum(ushort_t *, int);
extern int ip_hdr_length_v6(ip6_t *, int, uint8_t *);
extern char *pr_type(uchar_t);
extern char *pr_type6(uchar_t);
extern void print_addr(uchar_t *, int, struct sockaddr *);
extern void print_addr6(uchar_t *, int, struct sockaddr *);
extern boolean_t print_icmp_other(uchar_t, uchar_t);
extern boolean_t print_icmp_other6(uchar_t, uchar_t);
static void print_stats(int, int, double, double, double, double);
static void print_unknown_host_msg(const char *, const char *);
static void record_stats(double, int *, double *, double *, double *, double *);
static void resolve_nodes(int *, struct addrinfo **);
static void select_src_addr(union any_in_addr *, union any_in_addr *, int);
extern void send_probe(int, struct sockaddr *, struct ip *, int, int,
    struct timeval *, int);
extern void send_probe6(int, struct msghdr *, struct ip *, int, int,
    struct timeval *, int);
extern void set_ancillary_data(struct msghdr *, int, union any_in_addr *, int,
    uint_t);
extern struct ip *set_buffers(int);
extern struct ip *set_buffers6(int);
extern void set_IPv4opt_sourcerouting(int, union any_in_addr *,
    union any_in_addr *);
static void set_sin(struct sockaddr *, union any_in_addr *, int);
static int set_src_addr(struct pr_set *, struct ifaddrlist **);
static void setup_protocol(struct pr_set *, int);
static void setup_socket(struct pr_set *, int);
static void sig_handler(int);
static int str2int(const char *, const char *, int, int);
static double str2dbl(const char *, const char *, double, double);
static void trace_it(struct addrinfo *);
static void traceroute(union any_in_addr *, struct msghdr *, struct pr_set *,
    int, struct ifaddrlist *);
static void tv_sub(struct timeval *, struct timeval *);
static void usage(void);
static int wait_for_reply(int, struct msghdr *, struct timeval *);
static double xsqrt(double);
static void *ns_warning_thr(void *);

/*
 * main
 */
int
main(int argc, char **argv)
{
	struct addrinfo *ai_dst = NULL;		/* destination host */
	/*
	 * "probing_successful" indicates if we could successfully send probes,
	 * not necessarily received reply from the target (this behavior is from
	 * the original traceroute). It's _B_FALSE if packlen is invalid, or no
	 * interfaces found.
	 */
	boolean_t probing_successful = _B_FALSE;
	int longjmp_return;			/* return value from longjump */
	int i = 0;
	char *cp;
	int op;
	char *ep;
	char temp_buf[INET6_ADDRSTRLEN];	/* use for inet_ntop() */
	double pause;

	/*
	 * A raw socket will be used for IPv4 if there is sufficient
	 * privilege.
	 */
	raw_req = priv_ineffect(PRIV_NET_RAWACCESS);

	/*
	 * We'll need the privilege only when we open the sockets; that's
	 * when we'll fail if the program has insufficient privileges.
	 */
	(void) __init_suid_priv(PU_CLEARLIMITSET, PRIV_NET_ICMPACCESS,
	    raw_req ? PRIV_NET_RAWACCESS : NULL, NULL);

	(void) setlinebuf(stdout);

	if ((cp = strrchr(argv[0], '/')) != NULL)
		prog = cp + 1;
	else
		prog = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "adFIlnrSvxA:c:f:g:i:L:m:P:p:Q:q:s:"
	    "t:w:")) != EOF) {
		switch (op) {
		case 'A':
			if (strcmp(optarg, "inet") == 0) {
				family_input = AF_INET;
			} else if (strcmp(optarg, "inet6") == 0) {
				family_input = AF_INET6;
			} else {
				Fprintf(stderr,
				    "%s: unknown address family %s\n",
				    prog, optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'a':
			probe_all = _B_TRUE;
			break;

		case 'c':
			class = str2int(optarg, "traffic class", 0,
			    MAX_TRAFFIC_CLASS);
			break;

		case 'd':
			options |= SO_DEBUG;
			break;

		case 'f':
			first_ttl = str2int(optarg, "first ttl", 1, MAXTTL);
			break;

		case 'F':
			off = IP_DF;
			dontfrag = 1;
			break;

		case 'g':
			if (!raw_req) {
				Fprintf(stderr,
				    "%s: privilege to specify a loose source "
				    "route gateway is unavailable\n",
				    prog);
				exit(EXIT_FAILURE);
			}
			if (gw_count >= MAXMAX_GWS) {
				Fprintf(stderr,
				    "%s: Too many gateways\n", prog);
				exit(EXIT_FAILURE);
			}
			gwlist[gw_count] = strdup(optarg);
			if (gwlist[gw_count] == NULL) {
				Fprintf(stderr, "%s: strdup %s\n", prog,
				    strerror(errno));
				exit(EXIT_FAILURE);
			}

			++gw_count;
			break;

		case 'l':
			showttl = _B_TRUE;
			break;

		case 'i':
			/* this can be IF name or IF index */
			if_index = (uint_t)strtol(optarg, &ep, 10);

			/* convert IF index <-->  IF name */
			if (errno != 0 || *ep != '\0') {
				device = optarg;
				if_index = if_nametoindex((const char *)device);

				/*
				 * In case it fails, check to see if the problem
				 * is other than "IF not found".
				 */
				if (if_index == 0 && errno != ENXIO) {
					Fprintf(stderr, "%s: if_nametoindex:"
					    "%s\n", prog, strerror(errno));
					exit(EXIT_FAILURE);
				}
			} else {
				device = (char *)malloc(LIFNAMSIZ + 1);
				if (device == NULL) {
					Fprintf(stderr, "%s: malloc: %s\n",
					    prog, strerror(errno));
					exit(EXIT_FAILURE);
				}

				device = if_indextoname(if_index, device);
				if (device != NULL) {
					device[LIFNAMSIZ] = '\0';
				} else if (errno != ENXIO) {
					/*
					 * The problem was other than "index
					 * not found".
					 */
					Fprintf(stderr, "%s: if_indextoname:"
					    "%s\n", prog, strerror(errno));
					exit(EXIT_FAILURE);
				}
			}

			if (device == NULL || if_index == 0) {
				Fprintf(stderr, "%s: interface %s "
				    "doesn't match any actual interfaces\n",
				    prog, optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'I':
			useicmp = _B_TRUE;
			break;

		case 'L':
			flow = str2int(optarg, "flow label", 0, MAX_FLOW_LABEL);
			break;

		case 'm':
			max_ttl = str2int(optarg, "max ttl(hop limit)", 1,
			    MAXTTL);
			break;

		case 'n':
			nflag = _B_TRUE;
			break;

		case 'P':
			pause = str2dbl(optarg, "pause", 0, INT_MAX);
			delay.tv_sec = (time_t)pause;
			delay.tv_usec = (suseconds_t)((pause - delay.tv_sec) *
			    1000000);
			break;

		case 'p':
			port = str2int(optarg, "port", 1, MAX_PORT);
			break;

		case 'Q':
			max_timeout = str2int(optarg, "max timeout", 1, -1);
			break;

		case 'q':
			nprobes = str2int(optarg, "nprobes", 1, -1);
			break;

		case 'r':
			options |= SO_DONTROUTE;
			break;

		case 'S':
			collect_stat = _B_TRUE;
			break;

		case 's':
			/*
			 * set the ip source address of the outbound
			 * probe (e.g., on a multi-homed host).
			 */
			source_input = optarg;
			break;

		case 't':
			tos = (uchar_t)str2int(optarg, "tos", 0, MAX_TOS);
			settos = _B_TRUE;
			break;

		case 'v':
			verbose = _B_TRUE;
			break;

		case 'x':
			docksum = _B_FALSE;
			break;

		case 'w':
			waittime = str2int(optarg, "wait time", 2, -1);
			break;

		default:
			usage();
			break;
		}
	}

	/*
	 * If it's probe_all, SIGQUIT makes traceroute exit(). But we set the
	 * address to jump back to in traceroute(). Until then, we'll need to
	 * temporarily specify one.
	 */
	if (probe_all) {
		if ((longjmp_return = setjmp(env)) != 0) {
			if (longjmp_return == SIGQUIT) {
				Printf("(exiting)\n");
				exit(EXIT_SUCCESS);
			} else {		/* should never happen */
				exit(EXIT_FAILURE);
			}
		}
		(void) signal(SIGQUIT, sig_handler);
	}

	if ((gw_count > 0) && (options & SO_DONTROUTE)) {
		Fprintf(stderr, "%s: loose source route gateways (-g)"
		    " cannot be specified when probe packets are sent"
		    " directly to a host on an attached network (-r)\n",
		    prog);
		exit(EXIT_FAILURE);
	}

	i = argc - optind;
	if (i == 1 || i == 2) {
		hostname = argv[optind];

		if (i == 2) {
			/* accept any length now, we'll check it later */
			packlen_input = str2int(argv[optind + 1],
			    "packet length", 0, -1);
		}
	} else {
		usage();
	}

	if (first_ttl > max_ttl) {
		Fprintf(stderr,
		    "%s: first ttl(hop limit) (%d) may not be greater"
		    " than max ttl(hop limit) (%d)\n",
		    prog, first_ttl, max_ttl);
		exit(EXIT_FAILURE);
	}

	/*
	 * Start up the name services warning thread.
	 */
	if (thr_create(NULL, 0, ns_warning_thr, NULL,
	    THR_DETACHED | THR_DAEMON, NULL) != 0) {
		Fprintf(stderr, "%s: failed to create name services "
		    "thread: %s\n", prog, strerror(errno));
		exit(EXIT_FAILURE);
	}


	/* resolve hostnames */
	resolve_nodes(&family_input, &ai_dst);
	if (ai_dst == NULL) {
		exit(EXIT_FAILURE);
	}

	/*
	 * If it's probe_all, SIGINT makes traceroute skip to probing next IP
	 * address of the target. The new interrupt handler is assigned in
	 * traceroute() function. Until then let's ignore the signal.
	 */
	if (probe_all)
		(void) signal(SIGINT, SIG_IGN);

	ident = (getpid() & 0xffff) | 0x8000;

	/*
	 * We KNOW that probe_all == TRUE if family is AF_UNSPEC,
	 * since family is set to the specific AF found unless it's
	 * probe_all. So if family == AF_UNSPEC, we need to init pr4 and pr6.
	 */
	switch (family_input) {
	case AF_UNSPEC:
		pr4 = (struct pr_set *)malloc(sizeof (struct pr_set));
		if (pr4 == NULL) {
			Fprintf(stderr,
			    "%s: malloc %s\n", prog, strerror(errno));
			exit(EXIT_FAILURE);
		}
		pr6 = (struct pr_set *)malloc(sizeof (struct pr_set));
		if (pr6 == NULL) {
			Fprintf(stderr,
			    "%s: malloc %s\n", prog, strerror(errno));
			exit(EXIT_FAILURE);
		}
		setup_protocol(pr6, AF_INET6);
		setup_protocol(pr4, AF_INET);
		outip6 = (*pr6->set_buffers_fn)(pr6->packlen);
		setup_socket(pr6, pr6->packlen);

		outip4 = (*pr4->set_buffers_fn)(pr4->packlen);
		setup_socket(pr4, pr4->packlen);
		num_ifs6 = set_src_addr(pr6, &al6);
		num_ifs4 = set_src_addr(pr4, &al4);
		break;
	case AF_INET6:
		pr6 = (struct pr_set *)malloc(sizeof (struct pr_set));
		if (pr6 == NULL) {
			Fprintf(stderr,
			    "%s: malloc %s\n", prog, strerror(errno));
			exit(EXIT_FAILURE);
		}
		setup_protocol(pr6, AF_INET6);
		outip6 = (*pr6->set_buffers_fn)(pr6->packlen);
		setup_socket(pr6, pr6->packlen);
		num_ifs6 = set_src_addr(pr6, &al6);
		break;
	case AF_INET:
		pr4 = (struct pr_set *)malloc(sizeof (struct pr_set));
		if (pr4 == NULL) {
			Fprintf(stderr,
			    "%s: malloc %s\n", prog, strerror(errno));
			exit(EXIT_FAILURE);
		}
		setup_protocol(pr4, AF_INET);
		outip4 = (*pr4->set_buffers_fn)(pr4->packlen);
		setup_socket(pr4, pr4->packlen);
		num_ifs4 = set_src_addr(pr4, &al4);
		break;
	default:
		Fprintf(stderr, "%s: unknow address family.\n", prog);
		exit(EXIT_FAILURE);
	}

	if (num_v4 + num_v6 > 1 && !probe_all) {
		if (ai_dst->ai_family == AF_INET) {
			Fprintf(stderr,
			    "%s: Warning: %s has multiple addresses;"
			    " using %s\n", prog, hostname,
			    inet_ntop(AF_INET,
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    (void *)&((struct sockaddr_in *)
			    ai_dst->ai_addr)->sin_addr,
			    temp_buf, sizeof (temp_buf)));
		} else {
			Fprintf(stderr,
			    "%s: Warning: %s has multiple addresses;"
			    " using %s\n", prog, hostname,
			    inet_ntop(AF_INET6,
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    (void *)&((struct sockaddr_in6 *)
			    ai_dst->ai_addr)->sin6_addr,
			    temp_buf, sizeof (temp_buf)));
		}
	}

	if (num_ifs4 + num_ifs6 > 0) {
		trace_it(ai_dst);
		probing_successful = _B_TRUE;
	}

	(void) close(rcvsock4);
	(void) close(sndsock4);
	(void) close(rcvsock6);
	(void) close(sndsock6);

	/*
	 * if we could probe any of the IP addresses of the target, that means
	 * this was a successful operation
	 */
	if (probing_successful)
		return (EXIT_SUCCESS);
	else
		return (EXIT_FAILURE);
}

/*
 * print "unknown host" message
 */
static void
print_unknown_host_msg(const char *protocol, const char *host)
{
	Fprintf(stderr, "%s: unknown%s host %s\n", prog, protocol, host);
}

/*
 * resolve destination host and gateways
 */
static void
resolve_nodes(int *family, struct addrinfo **ai_dstp)
{
	struct addrinfo *ai_dst = NULL;
	struct addrinfo *aip = NULL;
	int num_resolved_gw = 0;
	int num_resolved_gw6 = 0;

	get_hostinfo(hostname, *family, &ai_dst);
	if (ai_dst == NULL) {
		print_unknown_host_msg("", hostname);
		exit(EXIT_FAILURE);
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

	if (*family == AF_UNSPEC && !probe_all) {
		*family = ai_dst->ai_family;
	}

	/* resolve gateways */
	if (gw_count > 0) {
		get_gwaddrs(gwlist, *family, gwIPlist, gwIP6list,
		    &num_resolved_gw, &num_resolved_gw6);

		/* we couldn't resolve a gateway as an IPv6 host */
		if (num_resolved_gw6 != gw_count && num_v6 != 0) {
			if (*family == AF_INET6 || *family == AF_UNSPEC)
				print_unknown_host_msg(" IPv6",
				    gwlist[num_resolved_gw6]);
			num_v6 = 0;
		}

		/* we couldn't resolve a gateway as an IPv4 host */
		if (num_resolved_gw != gw_count && num_v4 != 0) {
			if (*family == AF_INET || *family == AF_UNSPEC)
				print_unknown_host_msg(" IPv4",
				    gwlist[num_resolved_gw]);
			num_v4 = 0;
		}
	}

	*ai_dstp = (num_v4 + num_v6 > 0) ? ai_dst : NULL;
}

/*
 * Given IP address or hostname, return v4 and v6 hostinfo lists.
 * Assumes that hostinfo ** ptrs are non-null.
 */
static void
get_hostinfo(char *host, int family, struct addrinfo **aipp)
{
	struct addrinfo hints, *ai;
	struct in6_addr addr6;
	struct in_addr addr;
	char abuf[INET6_ADDRSTRLEN];	/* use for inet_ntop() */
	int rc;

	/*
	 * Take care of v4-mapped addresses. It should run same as v4, after
	 * chopping off the prefix, leaving the IPv4 address
	 */
	if ((inet_pton(AF_INET6, host, &addr6) > 0) &&
	    IN6_IS_ADDR_V4MAPPED(&addr6)) {
		/* peel off the "mapping" stuff, leaving 32 bit IPv4 address */
		IN6_V4MAPPED_TO_INADDR(&addr6, &addr);

		/* convert it back to a string */
		(void) inet_ntop(AF_INET, &addr, abuf, sizeof (abuf));

		/* now the host is an IPv4 address */
		(void) strcpy(host, abuf);

		/*
		 * If it's a mapped address, we convert it into IPv4
		 * address because traceroute will send and receive IPv4
		 * packets for that address. Therefore, it's a failure case to
		 * ask get_hostinfo() to treat a mapped address as an IPv6
		 * address.
		 */
		if (family == AF_INET6) {
			return;
		}
	}

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_family = family;
	hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
	rc = getaddrinfo(host, NULL, &hints, &ai);
	if (rc != 0) {
		if (rc != EAI_NONAME)
			Fprintf(stderr, "%s: getaddrinfo: %s\n", prog,
			    gai_strerror(rc));
		*aipp = NULL;
		return;
	}
	*aipp = ai;
}

/*
 * Calculate the packet length to be used, and check against the valid range.
 * Returns -1 if range check fails.
 */
static uint_t
calc_packetlen(int plen_input, struct pr_set *pr)
{
	int minpacket;			/* min ip packet size */
	int optlen;			/* length of ip options */
	int plen;

	/*
	 * LBNL bug fixed: miscalculation of optlen
	 */
	if (gw_count > 0) {
		/*
		 * IPv4:
		 * ----
		 * 5 (NO OPs) + 3 (code, len, ptr) + gateways
		 * IP options field can hold up to 9 gateways. But the API
		 * allows you to specify only 8, because the last one is the
		 * destination host. When this packet is sent, on the wire
		 * you see one gateway replaced by 4 NO OPs. The other 1 NO
		 * OP is for alignment
		 *
		 * IPv6:
		 * ----
		 * Well, formula is different, but the result is same.
		 * 8 byte fixed part for Type 0 Routing header, followed by
		 * gateway addresses
		 */
		optlen = 8 + gw_count * pr->addr_len;
	} else {
		optlen = 0;
	}

	/* take care of the packet length calculations and checks */
	minpacket = pr->ip_hdr_len + sizeof (struct outdata) + optlen;
	if (useicmp)
		minpacket += pr->icmp_minlen;	/* minimum ICMP header size */
	else
		minpacket += sizeof (struct udphdr);
	plen = plen_input;
	if (plen == 0) {
		plen = minpacket;		/* minimum sized packet */
	} else if (minpacket > plen || plen > IP_MAXPACKET) {
		Fprintf(stderr, "%s: %s packet size must be >= %d and <= %d\n",
		    prog, pr->name, minpacket, IP_MAXPACKET);
		return (0);
	}

	return (plen);
}

/*
 * Sets the source address by resolving -i and -s arguments, or if -i and -s
 * don't dictate any, it sets the pick_src to make sure traceroute uses the
 * kernel's pick of the source address.
 * Returns number of interfaces configured on the source host, 0 on error or
 * there's no interface which is up amd not a loopback.
 */
static int
set_src_addr(struct pr_set *pr, struct ifaddrlist **alp)
{
	union any_in_addr *ap;
	struct ifaddrlist *al = NULL;
	struct ifaddrlist *tmp1_al = NULL;
	struct ifaddrlist *tmp2_al = NULL;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in *sin_from = (struct sockaddr_in *)pr->from;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in6 *sin6_from = (struct sockaddr_in6 *)pr->from;
	struct addrinfo *aip;
	char errbuf[ERRBUFSIZE];
	char abuf[INET6_ADDRSTRLEN];		/* use for inet_ntop() */
	int num_ifs;				/* all the interfaces  */
	int num_src_ifs;			/* exclude loopback and down */
	int i;
	uint_t ifaddrflags = 0;

	source = source_input;

	if (device != NULL)
		ifaddrflags |= LIFC_UNDER_IPMP;

	/* get the interface address list */
	num_ifs = ifaddrlist(&al, pr->family, ifaddrflags, errbuf);
	if (num_ifs < 0) {
		Fprintf(stderr, "%s: ifaddrlist: %s\n", prog, errbuf);
		exit(EXIT_FAILURE);
	}

	num_src_ifs = 0;
	for (i = 0; i < num_ifs; i++) {
		if (!(al[i].flags & IFF_LOOPBACK) && (al[i].flags & IFF_UP))
			num_src_ifs++;
	}

	if (num_src_ifs == 0) {
		Fprintf(stderr, "%s: can't find any %s network interfaces\n",
		    prog, pr->name);
		return (0);
	}

	/* verify the device */
	if (device != NULL) {
		tmp1_al = find_device(al, num_ifs, device);

		if (tmp1_al == NULL) {
			Fprintf(stderr, "%s: %s (index %d) is an invalid %s"
			    " interface\n", prog, device, if_index, pr->name);
			free(al);
			return (0);
		}
	}

	/* verify the source address */
	if (source != NULL) {
		get_hostinfo(source, pr->family, &aip);
		if (aip == NULL) {
			Fprintf(stderr,
			    "%s: %s is an invalid %s source address\n",
			    prog, source, pr->name);

			free(al);
			return (0);
		}

		source = aip->ai_canonname;

		if (pr->family == AF_INET)
			ap = (union any_in_addr *)
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    &((struct sockaddr_in *)aip->ai_addr)->sin_addr;
		else
			ap = (union any_in_addr *)
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    &((struct sockaddr_in6 *)aip->ai_addr)->sin6_addr;

		/*
		 * LBNL bug fixed: used to accept any src address
		 */
		tmp2_al = find_ifaddr(al, num_ifs, ap, pr->family);
		if (tmp2_al == NULL) {
			(void) inet_ntop(pr->family, ap, abuf, sizeof (abuf));
			Fprintf(stderr, "%s: %s is not a local %s address\n",
			    prog, abuf, pr->name);
			free(al);
			freeaddrinfo(aip);
			return (0);
		}
	}

	pick_src = _B_FALSE;

	if (source == NULL) {			/* no -s used */
		if (device == NULL) {		/* no -i used, no -s used */
			pick_src = _B_TRUE;
		} else {			/* -i used, no -s used */
			/*
			 * -i used, but not -s, and it's IPv4: set the source
			 * address to whatever the interface has configured on
			 * it.
			 */
			if (pr->family == AF_INET)
				set_sin(pr->from, &(tmp1_al->addr), pr->family);
			else
				pick_src = _B_TRUE;
		}
	} else {				/* -s used */
		if (device == NULL) {		/* no -i used, -s used */
			set_sin(pr->from, ap, pr->family);

			if (aip->ai_next != NULL) {
				(void) inet_ntop(pr->family, pr->from_sin_addr,
				    abuf, sizeof (abuf));
				Fprintf(stderr, "%s: Warning: %s has multiple "
				    "addresses; using %s\n", prog, source,
				    abuf);
			}
		} else {			/* -i and -s used */
			/*
			 * Make sure the source specified matches the
			 * interface address. You only care about this for IPv4
			 * IPv6 can handle IF not matching src address
			 */
			if (pr->family == AF_INET) {
				if (!has_addr(aip, &tmp1_al->addr)) {
					Fprintf(stderr,
					    "%s: %s is not on interface %s\n",
					    prog, source, device);
					exit(EXIT_FAILURE);
				}
				/*
				 * make sure we use the one matching the
				 * interface's address
				 */
				*ap = tmp1_al->addr;
			}

			set_sin(pr->from, ap, pr->family);
		}
	}

	/*
	 * Binding at this point will set the source address to be used
	 * for both IPv4 (when raw IP datagrams are not required) and
	 * IPv6.  If the address being bound to is zero, then the kernel
	 * will end up choosing the source address when the datagram is
	 * sent.
	 *
	 * For raw IPv4 datagrams, the source address is initialized
	 * within traceroute() along with the outbound destination
	 * address.
	 */
	if (pr->family == AF_INET && !raw_req) {
		sin_from->sin_family = AF_INET;
		sin_from->sin_port = htons(ident);
		if (bind(sndsock4, (struct sockaddr *)pr->from,
			sizeof (struct sockaddr_in)) < 0) {
			Fprintf(stderr, "%s: bind: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else if (pr->family == AF_INET6) {
		sin6_from->sin6_family = AF_INET6;
		sin6_from->sin6_port = htons(ident);
		if (bind(sndsock6, (struct sockaddr *)pr->from,
			sizeof (struct sockaddr_in6)) < 0) {
			Fprintf(stderr, "%s: bind: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}

		whereto6.sin6_flowinfo = htonl((class << 20) | flow);
	}
	*alp = al;
	return (num_ifs);
}

/*
 * Returns the complete ifaddrlist structure matching the desired interface
 * address. Ignores interfaces which are either down or loopback.
 */
static struct ifaddrlist *
find_ifaddr(struct ifaddrlist *al, int len, union any_in_addr *addr,
    int family)
{
	struct ifaddrlist *tmp_al = al;
	int i;
	size_t addr_len = (family == AF_INET) ? sizeof (struct in_addr) :
	    sizeof (struct in6_addr);

	for (i = 0; i < len; i++, tmp_al++) {
		if ((!(tmp_al->flags & IFF_LOOPBACK) &&
		    (tmp_al->flags & IFF_UP)) &&
		    (memcmp(&tmp_al->addr, addr, addr_len) == 0))
			break;
	}

	if (i < len) {
		return (tmp_al);
	} else {
		return (NULL);
	}
}

/*
 * Returns the complete ifaddrlist structure matching the desired interface name
 * Ignores interfaces which are either down or loopback.
 */
static struct ifaddrlist *
find_device(struct ifaddrlist *al, int len, char *device)
{
	struct ifaddrlist *tmp_al = al;
	int i;

	for (i = 0; i < len; i++, tmp_al++) {
		if ((!(tmp_al->flags & IFF_LOOPBACK) &&
		    (tmp_al->flags & IFF_UP)) &&
		    (strcmp(tmp_al->device, device) == 0))
			break;
	}

	if (i < len) {
		return (tmp_al);
	} else {
		return (NULL);
	}
}

/*
 * returns _B_TRUE if given hostinfo contains the given address
 */
static boolean_t
has_addr(struct addrinfo *ai, union any_in_addr *addr)
{
	struct addrinfo *ai_tmp = NULL;
	union any_in_addr *ap;

	for (ai_tmp = ai; ai_tmp != NULL; ai_tmp = ai_tmp->ai_next) {
		if (ai_tmp->ai_family == AF_INET6)
			continue;
		ap = (union any_in_addr *)
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    &((struct sockaddr_in *)ai_tmp->ai_addr)->sin_addr;
		if (memcmp(ap, addr, sizeof (struct in_addr)) == 0)
			break;
	}

	if (ai_tmp != NULL) {
		return (_B_TRUE);
	} else {
		return (_B_FALSE);
	}
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
get_gwaddrs(char **gwlist, int family, union any_in_addr *gwIPlist,
    union any_in_addr *gwIPlist6, int *resolved, int *resolved6)
{
	int i;
	boolean_t check_v4 = _B_TRUE, check_v6 = _B_TRUE;
	struct addrinfo *ai = NULL;
	struct addrinfo *aip = NULL;

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

	if (check_v4 && gw_count >= MAX_GWS) {
		check_v4 = _B_FALSE;
		Fprintf(stderr, "%s: too many IPv4 gateways\n", prog);
		num_v4 = 0;
	}
	if (check_v6 && gw_count >= MAX_GWS6) {
		check_v6 = _B_FALSE;
		Fprintf(stderr, "%s: too many IPv6 gateways\n", prog);
		num_v6 = 0;
	}

	for (i = 0; i < gw_count; i++) {
		if (!check_v4 && !check_v6)
			return;
		get_hostinfo(gwlist[i], family, &ai);
		if (ai == NULL)
			return;
		if (check_v4 && num_v4 != 0) {
			check_v4 = _B_FALSE;
			for (aip = ai; aip != NULL; aip = aip->ai_next) {
				if (aip->ai_family == AF_INET) {
					/* LINTED E_BAD_PTR_CAST_ALIGN */
					bcopy(&((struct sockaddr_in *)
					    aip->ai_addr)->sin_addr,
					    &gwIPlist[i].addr,
					    aip->ai_addrlen);
					(*resolved)++;
					check_v4 = _B_TRUE;
					break;
				}
			}
		} else if (check_v4) {
			check_v4 = _B_FALSE;
		}
		if (check_v6 && num_v6 != 0) {
			check_v6 = _B_FALSE;
			for (aip = ai; aip != NULL; aip = aip->ai_next) {
				if (aip->ai_family == AF_INET6) {
					/* LINTED E_BAD_PTR_CAST_ALIGN */
					bcopy(&((struct sockaddr_in6 *)
					    aip->ai_addr)->sin6_addr,
					    &gwIPlist6[i].addr6,
					    aip->ai_addrlen);
					(*resolved6)++;
					check_v6 = _B_TRUE;
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
 * set protocol specific values here
 */
static void
setup_protocol(struct pr_set *pr, int family)
{
	/*
	 * Set the global variables for each AF. This is going to save us lots
	 * of "if (family == AF_INET)... else .."
	 */
	pr->family = family;

	if (family == AF_INET) {
		if (!docksum) {
			Fprintf(stderr,
			    "%s: Warning: checksums disabled\n", prog);
		}
		(void) strcpy(pr->name, "IPv4");
		(void) strcpy(pr->icmp, "icmp");
		pr->icmp_minlen = ICMP_MINLEN;
		pr->addr_len = sizeof (struct in_addr);
		pr->ip_hdr_len = sizeof (struct ip);
		pr->sock_size = sizeof (struct sockaddr_in);
		pr->to = (struct sockaddr *)&whereto;
		pr->from = (struct sockaddr *)&wherefrom;
		pr->from_sin_addr = (void *)&wherefrom.sin_addr;
		pr->gwIPlist = gwIPlist;
		pr->set_buffers_fn = set_buffers;
		pr->check_reply_fn = check_reply;
		pr->print_icmp_other_fn = print_icmp_other;
		pr->print_addr_fn = print_addr;
		pr->packlen = calc_packetlen(packlen_input, pr);
	} else {
		(void) strcpy(pr->name, "IPv6");
		(void) strcpy(pr->icmp, "ipv6-icmp");
		pr->icmp_minlen = ICMP6_MINLEN;
		pr->addr_len = sizeof (struct in6_addr);
		pr->ip_hdr_len = sizeof (struct ip6_hdr);
		pr->sock_size = sizeof (struct sockaddr_in6);
		pr->to = (struct sockaddr *)&whereto6;
		pr->from = (struct sockaddr *)&wherefrom6;
		pr->from_sin_addr = (void *)&wherefrom6.sin6_addr;
		pr->gwIPlist = gwIP6list;
		pr->set_buffers_fn = set_buffers6;
		pr->check_reply_fn = check_reply6;
		pr->print_icmp_other_fn = print_icmp_other6;
		pr->print_addr_fn = print_addr6;
		pr->packlen = calc_packetlen(packlen_input, pr);
	}
	if (pr->packlen == 0)
		exit(EXIT_FAILURE);
}

/*
 * setup the sockets for the given protocol's address family
 */
static void
setup_socket(struct pr_set *pr, int packet_len)
{
	int on = 1;
	struct protoent *pe;
	int type;
	int proto;
	int int_op;
	int rsock;
	int ssock;

	if ((pe = getprotobyname(pr->icmp)) == NULL) {
		Fprintf(stderr, "%s: unknown protocol %s\n", prog, pr->icmp);
		exit(EXIT_FAILURE);
	}

	/* privilege bracketing */
	(void) __priv_bracket(PRIV_ON);

	if ((rsock = socket(pr->family, SOCK_RAW, pe->p_proto)) < 0) {
		Fprintf(stderr, "%s: icmp socket: %s\n", prog, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (options & SO_DEBUG) {
		if (setsockopt(rsock, SOL_SOCKET, SO_DEBUG, (char *)&on,
		    sizeof (on)) < 0) {
			Fprintf(stderr, "%s: SO_DEBUG: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	if (options & SO_DONTROUTE) {
		if (setsockopt(rsock, SOL_SOCKET, SO_DONTROUTE, (char *)&on,
		    sizeof (on)) < 0) {
			Fprintf(stderr, "%s: SO_DONTROUTE: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (pr->family == AF_INET6) {
		/* Enable receipt of destination address info */
		if (setsockopt(rsock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		    (char *)&on, sizeof (on)) < 0) {
			Fprintf(stderr, "%s: IPV6_RECVPKTINFO: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
		/* Enable receipt of hoplimit info */
		if (setsockopt(rsock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		    (char *)&on, sizeof (on)) < 0) {
			Fprintf(stderr, "%s: IPV6_RECVHOPLIMIT: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}

	}

	/*
	 * Initialize the socket type and protocol based on the address
	 * family, whether or not a raw IP socket is required (for IPv4)
	 * or whether ICMP will be used instead of UDP.
	 *
	 * For historical reasons, the datagrams sent out by
	 * traceroute(1M) do not have the "don't fragment" flag set.  For
	 * this reason as well as the ability to set the Loose Source and
	 * Record Route (LSRR) option, a raw IP socket will be used for
	 * IPv4 when run in the global zone.  Otherwise, the actual
	 * datagram that will be sent will be a regular UDP or ICMP echo
	 * request packet.  However for convenience and for future options
	 * when other IP header information may be specified using
	 * traceroute, the buffer including the raw IP and UDP or ICMP
	 * header is always filled in.  When the probe is actually sent,
	 * the size of the request and the start of the packet is set
	 * according to the type of datagram to send.
	 */
	if (pr->family == AF_INET && raw_req) {
		type = SOCK_RAW;
		proto = IPPROTO_RAW;
	} else if (useicmp) {
		type = SOCK_RAW;
		if (pr->family == AF_INET)
			proto = IPPROTO_ICMP;
		else
			proto = IPPROTO_ICMPV6;
	} else {
		type = SOCK_DGRAM;
		proto = IPPROTO_UDP;
	}
	ssock = socket(pr->family, type, proto);

	if (ssock < 0) {
		if (proto == IPPROTO_RAW) {
			Fprintf(stderr, "%s: raw socket: %s\n", prog,
			    strerror(errno));
		} else if (proto == IPPROTO_UDP) {
			Fprintf(stderr, "%s: udp socket: %s\n", prog,
			    strerror(errno));
		} else {
			Fprintf(stderr, "%s: icmp socket: %s\n", prog,
			    strerror(errno));
		}
		exit(EXIT_FAILURE);
	}

	if (setsockopt(ssock, SOL_SOCKET, SO_SNDBUF, (char *)&packet_len,
	    sizeof (packet_len)) < 0) {
		Fprintf(stderr, "%s: SO_SNDBUF: %s\n", prog, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pr->family == AF_INET && raw_req) {
		if (setsockopt(ssock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
		    sizeof (on)) < 0) {
			Fprintf(stderr, "%s: IP_HDRINCL: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (options & SO_DEBUG) {
		if (setsockopt(ssock, SOL_SOCKET, SO_DEBUG, (char *)&on,
		    sizeof (on)) < 0) {
			Fprintf(stderr, "%s: SO_DEBUG: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	if (options & SO_DONTROUTE) {
		if (setsockopt(ssock, SOL_SOCKET, SO_DONTROUTE,
		    (char *)&on, sizeof (on)) < 0) {
			Fprintf(stderr, "%s: SO_DONTROUTE: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * If a raw IPv4 packet is going to be sent, the Type of Service
	 * field in the packet will be initialized in set_buffers().
	 * Otherwise, it is initialized here using the IPPROTO_IP level
	 * socket option.
	 */
	if (settos && !raw_req) {
		int_op = tos;
		if (setsockopt(ssock, IPPROTO_IP, IP_TOS, (char *)&int_op,
		    sizeof (int_op)) < 0) {
			Fprintf(stderr, "%s: IP_TOS: %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* We enable or disable to not depend on the kernel default */
	if (pr->family == AF_INET) {
		if (setsockopt(ssock, IPPROTO_IP, IP_DONTFRAG,
		    (char *)&dontfrag, sizeof (dontfrag)) == -1) {
			Fprintf(stderr, "%s: IP_DONTFRAG %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		if (setsockopt(ssock, IPPROTO_IPV6, IPV6_DONTFRAG,
		    (char *)&dontfrag, sizeof (dontfrag)) == -1) {
			Fprintf(stderr, "%s: IPV6_DONTFRAG %s\n", prog,
			    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (pr->family == AF_INET) {
		rcvsock4 = rsock;
		sndsock4 = ssock;
	} else {
		rcvsock6 = rsock;
		sndsock6 = ssock;
	}
	/* Revert to non-privileged user after configuring sockets */
	(void) __priv_bracket(PRIV_OFF);
}

/*
 * If we are "probing all", this function calls traceroute() for each IP address
 * of the target, otherwise calls only once. Returns _B_FALSE if traceroute()
 * fails.
 */
static void
trace_it(struct addrinfo *ai_dst)
{
	struct msghdr msg6;
	int num_dst_IPaddrs;
	struct addrinfo *aip;
	int i;

	if (!probe_all)
		num_dst_IPaddrs = 1;
	else
		num_dst_IPaddrs = num_v4 + num_v6;

	/*
	 * Initialize the msg6 structure using the hoplimit for the first
	 * probe packet, gateway addresses and the outgoing interface index.
	 */
	if (ai_dst->ai_family == AF_INET6 || (probe_all && num_v6)) {
		msg6.msg_control = NULL;
		msg6.msg_controllen = 0;
		set_ancillary_data(&msg6, first_ttl, pr6->gwIPlist, gw_count,
		    if_index);
	}

	/* run traceroute for all the IP addresses of the multihomed dest */
	for (aip = ai_dst, i = 0; i < num_dst_IPaddrs && aip != NULL; i++) {
		union any_in_addr *addrp;
		if (aip->ai_family == AF_INET) {
			addrp = (union any_in_addr *)
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    &((struct sockaddr_in *)
			    aip->ai_addr)->sin_addr;
			set_sin((struct sockaddr *)pr4->to, addrp,
			    aip->ai_family);
			traceroute(addrp, &msg6, pr4, num_ifs4, al4);
		} else {
			addrp = (union any_in_addr *)
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    &((struct sockaddr_in6 *)
			    aip->ai_addr)->sin6_addr;
			set_sin((struct sockaddr *)pr6->to, addrp,
			    aip->ai_family);
			traceroute(addrp, &msg6, pr6, num_ifs6, al6);
		}
		aip = aip->ai_next;
		if (i < (num_dst_IPaddrs - 1))
			(void) putchar('\n');
	}
}

/*
 * set the IP address in a sockaddr struct
 */
static void
set_sin(struct sockaddr *sock, union any_in_addr *addr, int family)
{
	sock->sa_family = family;

	if (family == AF_INET)
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		((struct sockaddr_in *)sock)->sin_addr = addr->addr;
	else
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		((struct sockaddr_in6 *)sock)->sin6_addr = addr->addr6;
}

/*
 * returns the IF name on which the given IP address is configured
 */
static char *
device_name(struct ifaddrlist *al, int len, union any_in_addr *ip_addr,
    struct pr_set *pr)
{
	int i;
	struct ifaddrlist *tmp_al;

	tmp_al = al;

	for (i = 0; i < len; i++, tmp_al++) {
		if (memcmp(&tmp_al->addr, ip_addr, pr->addr_len) == 0) {
			return (tmp_al->device);
		}
	}

	return (NULL);
}

/*
 * Trace the route to the host with given IP address.
 */
static void
traceroute(union any_in_addr *ip_addr, struct msghdr *msg6, struct pr_set *pr,
    int num_ifs, struct ifaddrlist *al)
{
	int ttl;
	int probe;
	uchar_t type;				/* icmp type */
	uchar_t code;				/* icmp code */
	int reply;
	int seq = 0;
	char abuf[INET6_ADDRSTRLEN];		/* use for inet_ntop() */
	int longjmp_return;			/* return value from longjump */
	struct ip *ip = (struct ip *)packet;
	boolean_t got_there = _B_FALSE;		/* we hit the destination */
	static boolean_t first_pkt = _B_TRUE;
	int hoplimit;				/* hoplimit for IPv6 packets */
	struct in6_addr addr6;
	int num_src_ifs;			/* excludes down and loopback */
	struct msghdr in_msg;
	struct iovec iov;
	int *intp;
	int sndsock;
	int rcvsock;

	msg6->msg_name = pr->to;
	msg6->msg_namelen = sizeof (struct sockaddr_in6);
	sndsock =  (pr->family == AF_INET) ? sndsock4 : sndsock6;
	rcvsock =  (pr->family == AF_INET) ? rcvsock4 : rcvsock6;

	/* carry out the source address selection */
	if (pick_src) {
		union any_in_addr src_addr;
		char *dev_name;
		int i;

		/*
		 * If there's a gateway, a routing header as a consequence, our
		 * kernel picks the source address based on the first hop
		 * address, rather than final destination address.
		 */
		if (gw_count > 0) {
			(void) select_src_addr(pr->gwIPlist, &src_addr,
			    pr->family);
		} else {
			(void) select_src_addr(ip_addr, &src_addr, pr->family);
		}
		set_sin(pr->from, &src_addr, pr->family);

		/* filter out down and loopback interfaces */
		num_src_ifs = 0;
		for (i = 0; i < num_ifs; i++) {
			if (!(al[i].flags & IFF_LOOPBACK) &&
			    (al[i].flags & IFF_UP))
				num_src_ifs++;
		}

		if (num_src_ifs > 1) {
			dev_name = device_name(al, num_ifs, &src_addr, pr);
			if (dev_name == NULL)
				dev_name = "?";

			(void) inet_ntop(pr->family, pr->from_sin_addr, abuf,
			    sizeof (abuf));
			Fprintf(stderr,
			    "%s: Warning: Multiple interfaces found;"
			    " using %s @ %s\n", prog, abuf, dev_name);
		}
	}

	if (pr->family == AF_INET) {
		outip4->ip_src = *(struct in_addr *)pr->from_sin_addr;
		outip4->ip_dst = ip_addr->addr;
	}

	/*
	 * If the hostname is an IPv6 literal address, let's not print it twice.
	 */
	if (pr->family == AF_INET6 &&
	    inet_pton(AF_INET6, hostname, &addr6) > 0) {
		Fprintf(stderr, "%s to %s", prog, hostname);
	} else {
		Fprintf(stderr, "%s to %s (%s)", prog, hostname,
		    inet_ntop(pr->family, ip_addr, abuf, sizeof (abuf)));
	}

	if (source)
		Fprintf(stderr, " from %s", source);
	Fprintf(stderr, ", %d hops max, %d byte packets\n", max_ttl,
	    pr->packlen);
	(void) fflush(stderr);

	/*
	 * Setup the source routing for IPv4. For IPv6, we did the required
	 * setup in the caller function, trace_it(), because it's independent
	 * from the IP address of target.
	 */
	if (pr->family == AF_INET && gw_count > 0)
		set_IPv4opt_sourcerouting(sndsock, ip_addr, pr->gwIPlist);

	if (probe_all) {
		/* interrupt handler sig_handler() jumps back to here */
		if ((longjmp_return = setjmp(env)) != 0) {
			switch (longjmp_return) {
			case SIGINT:
				Printf("(skipping)\n");
				return;
			case SIGQUIT:
				Printf("(exiting)\n");
				exit(EXIT_SUCCESS);
			default:	/* should never happen */
				exit(EXIT_FAILURE);
			}
		}
		(void) signal(SIGINT, sig_handler);
	}

	for (ttl = first_ttl; ttl <= max_ttl; ++ttl) {
		union any_in_addr lastaddr;
		int timeouts = 0;
		double rtt;		/* for statistics */
		int nreceived = 0;
		double rttmin, rttmax;
		double rttsum, rttssq;
		int unreachable;

		got_there = _B_FALSE;
		unreachable = 0;

		/*
		 * The following line clears both IPv4 and IPv6 address stored
		 * in the union.
		 */
		lastaddr.addr6 = in6addr_any;

		if ((ttl == (first_ttl + 1)) && (options & SO_DONTROUTE)) {
			Fprintf(stderr,
			    "%s: host %s is not on a directly-attached"
			    " network\n", prog, hostname);
			break;
		}

		Printf("%2d ", ttl);
		(void) fflush(stdout);

		for (probe = 0; (probe < nprobes) && (timeouts < max_timeout);
		    ++probe) {
			int cc;
			struct timeval t1, t2;

			/*
			 * Put a delay before sending this probe packet. Don't
			 * delay it if it's the very first packet.
			 */
			if (!first_pkt) {
				if (delay.tv_sec > 0)
					(void) sleep((uint_t)delay.tv_sec);
				if (delay.tv_usec > 0)
					(void) usleep(delay.tv_usec);
			} else {
				first_pkt = _B_FALSE;
			}

			(void) gettimeofday(&t1, NULL);

			if (pr->family == AF_INET) {
				send_probe(sndsock, pr->to, outip4, seq, ttl,
				    &t1, pr->packlen);
			} else {
				send_probe6(sndsock, msg6, outip6, seq, ttl,
				    &t1, pr->packlen);
			}

			/* prepare msghdr for recvmsg() */
			in_msg.msg_name = pr->from;
			in_msg.msg_namelen = pr->sock_size;

			iov.iov_base = (char *)packet;
			iov.iov_len = sizeof (packet);

			in_msg.msg_iov = &iov;
			in_msg.msg_iovlen = 1;

			in_msg.msg_control = ancillary_data;
			in_msg.msg_controllen = sizeof (ancillary_data);

			while ((cc = wait_for_reply(rcvsock, &in_msg,
			    &t1)) != 0) {
				(void) gettimeofday(&t2, NULL);

				reply = (*pr->check_reply_fn) (&in_msg, cc, seq,
				    &type, &code);

				in_msg.msg_controllen =
				    sizeof (ancillary_data);
				/* Skip short packet */
				if (reply == REPLY_SHORT_PKT) {
					continue;
				}

				timeouts = 0;

				/*
				 * if reply comes from a different host, print
				 * the hostname
				 */
				if (memcmp(pr->from_sin_addr, &lastaddr,
				    pr->addr_len) != 0) {
					(*pr->print_addr_fn) ((uchar_t *)packet,
					    cc, pr->from);
					/* store the address response */
					(void) memcpy(&lastaddr,
					    pr->from_sin_addr, pr->addr_len);
				}

				rtt = deltaT(&t1, &t2);
				if (collect_stat) {
					record_stats(rtt, &nreceived, &rttmin,
					    &rttmax, &rttsum, &rttssq);
				} else {
					Printf("  %.3f ms", rtt);
				}

				if (pr->family == AF_INET6) {
					intp = find_ancillary_data(&in_msg,
					    IPPROTO_IPV6, IPV6_HOPLIMIT);
					if (intp == NULL) {
						Fprintf(stderr,
						    "%s: can't find "
						    "IPV6_HOPLIMIT ancillary "
						    "data\n", prog);
						exit(EXIT_FAILURE);
					}
					hoplimit = *intp;
				}

				if (reply == REPLY_GOT_TARGET) {
					got_there = _B_TRUE;

					if (((pr->family == AF_INET) &&
					    (ip->ip_ttl <= 1)) ||
					    ((pr->family == AF_INET6) &&
					    (hoplimit <= 1)))
						Printf(" !");
				}

				if (!collect_stat && showttl) {
					if (pr->family == AF_INET) {
						Printf(" (ttl=%d)",
						    (int)ip->ip_ttl);
					} else if (hoplimit != -1) {
						Printf(" (hop limit=%d)",
						    hoplimit);
					}
				}

				if (reply == REPLY_GOT_OTHER) {
					if ((*pr->print_icmp_other_fn)
					    (type, code)) {
						unreachable++;
					}
				}

				/* special case */
				if (pr->family == AF_INET &&
				    type == ICMP_UNREACH &&
				    code == ICMP_UNREACH_PROTOCOL)
					got_there = _B_TRUE;

				break;
			}

			seq = (seq + 1) % (MAX_SEQ + 1);

			if (cc == 0) {
				Printf(" *");
				timeouts++;
			}

			(void) fflush(stdout);
		}

		if (collect_stat) {
			print_stats(probe, nreceived, rttmin, rttmax, rttsum,
			    rttssq);
		}

		(void) putchar('\n');

		/* either we hit the target or received too many unreachables */
		if (got_there ||
		    (unreachable > 0 && unreachable >= nprobes - 1))
			break;
	}

	/* Ignore the SIGINT between traceroute() runs */
	if (probe_all)
		(void) signal(SIGINT, SIG_IGN);
}

/*
 * for a given destination address and address family, it finds out what
 * source address kernel is going to pick
 */
static void
select_src_addr(union any_in_addr *dst_addr, union any_in_addr *src_addr,
    int family)
{
	int tmp_fd;
	struct sockaddr *sock;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	size_t sock_len;

	sock = (struct sockaddr *)malloc(sizeof (struct sockaddr_in6));
	if (sock == NULL) {
		Fprintf(stderr, "%s: malloc %s\n", prog, strerror(errno));
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
		Fprintf(stderr, "%s: udp socket: %s\n", prog,
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
		Fprintf(stderr, "%s: getsockname: %s\n", prog,
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (family == AF_INET) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin = (struct sockaddr_in *)sock;
		src_addr->addr = sin->sin_addr;
	} else {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6 = (struct sockaddr_in6 *)sock;
		src_addr->addr6 = sin6->sin6_addr;
	}

	free(sock);
	(void) close(tmp_fd);
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
ushort_t
in_cksum(ushort_t *addr, int len)
{
	int nleft = len;
	ushort_t *w = addr;
	ushort_t answer;
	int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(uchar_t *)w;

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
 * Wait until a reply arrives or timeout occurs. If packet arrived, read it
 * return the size of the packet read.
 */
static int
wait_for_reply(int sock, struct msghdr *msg, struct timeval *tp)
{
	fd_set fds;
	struct timeval now, wait;
	int cc = 0;
	int result;

	(void) FD_ZERO(&fds);
	FD_SET(sock, &fds);

	wait.tv_sec = tp->tv_sec + waittime;
	wait.tv_usec = tp->tv_usec;
	(void) gettimeofday(&now, NULL);
	tv_sub(&wait, &now);

	if (wait.tv_sec < 0 || wait.tv_usec < 0)
		return (0);

	result = select(sock + 1, &fds, (fd_set *)NULL, (fd_set *)NULL, &wait);

	if (result == -1) {
		if (errno != EINTR) {
			Fprintf(stderr, "%s: select: %s\n", prog,
			    strerror(errno));
		}
	} else if (result > 0)
		cc = recvmsg(sock, msg, 0);

	return (cc);
}

/*
 * Construct an Internet address representation. If the nflag has been supplied,
 * give numeric value, otherwise try for symbolic name.
 */
char *
inet_name(union any_in_addr *in, int family)
{
	char *cp;
	static boolean_t first = _B_TRUE;
	static char domain[NI_MAXHOST + 1];
	static char line[NI_MAXHOST + 1];	/* assuming		*/
				/* (NI_MAXHOST + 1) >= INET6_ADDRSTRLEN */
	char hbuf[NI_MAXHOST];
	socklen_t slen;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa;
	int flags;

	switch (family) {
	case AF_INET:
		slen = sizeof (struct sockaddr_in);
		sin.sin_addr = in->addr;
		sin.sin_port = 0;
		sa = (struct sockaddr *)&sin;
		break;
	case AF_INET6:
		slen = sizeof (struct sockaddr_in6);
		sin6.sin6_addr = in->addr6;
		sin6.sin6_port = 0;
		sin6.sin6_scope_id = 0;
		sa = (struct sockaddr *)&sin6;
		break;
	default:
		(void) snprintf(line, sizeof (line),
		    "<invalid address family>");
		return (line);
	}
	sa->sa_family = family;

	if (first && !nflag) {
		/* find out the domain name */
		first = _B_FALSE;
		mutex_enter(&tr_nslock);
		tr_nsactive = _B_TRUE;
		tr_nsstarttime = gethrtime();
		mutex_exit(&tr_nslock);
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
		    (cp = strchr(domain, '.')) != NULL) {
			(void) strncpy(domain, cp + 1, sizeof (domain) - 1);
			domain[sizeof (domain) - 1] = '\0';
		} else {
			domain[0] = '\0';
		}
		mutex_enter(&tr_nslock);
		tr_nsactive = _B_FALSE;
		mutex_exit(&tr_nslock);
	}

	flags = (nflag) ? NI_NUMERICHOST : NI_NAMEREQD;
	mutex_enter(&tr_nslock);
	tr_nsactive = _B_TRUE;
	tr_nsstarttime = gethrtime();
	mutex_exit(&tr_nslock);
	if (getnameinfo(sa, slen, hbuf, sizeof (hbuf), NULL, 0, flags) != 0) {
		if (inet_ntop(family, (const void *)&in->addr6,
		    hbuf, sizeof (hbuf)) == NULL)
			hbuf[0] = 0;
	} else if (!nflag && (cp = strchr(hbuf, '.')) != NULL &&
	    strcmp(cp + 1, domain) == 0) {
		*cp = '\0';
	}
	mutex_enter(&tr_nslock);
	tr_nsactive = _B_FALSE;
	mutex_exit(&tr_nslock);
	(void) strlcpy(line, hbuf, sizeof (line));

	return (line);
}

/*
 * return the difference (in msec) between two time values
 */
static double
deltaT(struct timeval *t1p, struct timeval *t2p)
{
	double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
	    (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}

/*
 * Subtract 2 timeval structs:  out = out - in.
 * Out is assumed to be >= in.
 */
static void
tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)   {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

/*
 * record statistics
 */
static void
record_stats(double rtt, int *nreceived, double *rttmin, double *rttmax,
    double *rttsum, double *rttssq)
{
	if (*nreceived == 0) {
		*rttmin = rtt;
		*rttmax = rtt;
		*rttsum = rtt;
		*rttssq = rtt * rtt;
	} else {
		if (rtt < *rttmin)
			*rttmin = rtt;

		if (rtt > *rttmax)
			*rttmax = rtt;

		*rttsum += rtt;
		*rttssq += rtt * rtt;
	}

	(*nreceived)++;
}

/*
 * display statistics
 */
static void
print_stats(int ntransmitted, int nreceived, double rttmin, double rttmax,
    double rttsum, double rttssq)
{
	double rttavg;			/* average round-trip time */
	double rttstd;			/* rtt standard deviation */

	if (ntransmitted > 0 && ntransmitted >= nreceived) {
		int missed = ntransmitted - nreceived;
		double loss = 100 * (double)missed / (double)ntransmitted;

		if (nreceived > 0) {
			rttavg = rttsum / nreceived;
			rttstd = rttssq - (rttavg * rttsum);
			rttstd = xsqrt(rttstd / nreceived);

			Printf("  %.3f", rttmin);
			Printf("/%.3f", rttavg);
			Printf("/%.3f", rttmax);

			Printf(" (%.3f) ms ", rttstd);
		}

		Printf(" %d/%d pkts", nreceived, ntransmitted);

		if (nreceived == 0)
			Printf(" (100%% loss)");
		else
			Printf(" (%.2g%% loss)", loss);
	}
}

/*
 * square root function
 */
double
xsqrt(double y)
{
	double t, x;

	if (y <= 0) {
		return (0.0);
	}

	x = (y < 1.0) ? 1.0 : y;
	do {
		t = x;
		x = (t + (y/t))/2.0;
	} while (0 < x && x < t);

	return (x);
}

/*
 * String to double with optional min and max.
 */
static double
str2dbl(const char *str, const char *what, double mi, double ma)
{
	double val;
	char *ep;

	errno = 0;

	val = strtod(str, &ep);
	if (errno != 0 || *ep != '\0') {
		Fprintf(stderr, "%s: \"%s\" bad value for %s \n",
		    prog, str, what);
		exit(EXIT_FAILURE);
	}
	if (val < mi && mi >= 0) {
		Fprintf(stderr, "%s: %s must be >= %f\n", prog, what, mi);
		exit(EXIT_FAILURE);
	}
	if (val > ma && ma >= 0) {
		Fprintf(stderr, "%s: %s must be <= %f\n", prog, what, ma);
		exit(EXIT_FAILURE);
	}
	return (val);
}

/*
 * String to int with optional min and max. Handles decimal and hex.
 */
static int
str2int(const char *str, const char *what, int mi, int ma)
{
	const char *cp;
	int val;
	char *ep;

	errno = 0;

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		val = (int)strtol(cp, &ep, 16);
	} else {
		val = (int)strtol(str, &ep, 10);
	}
	if (errno != 0 || *ep != '\0') {
		Fprintf(stderr, "%s: \"%s\" bad value for %s \n",
		    prog, str, what);
		exit(EXIT_FAILURE);
	}
	if (val < mi && mi >= 0) {
		if (mi == 0) {
			Fprintf(stderr, "%s: %s must be >= %d\n",
			    prog, what, mi);
		} else {
			Fprintf(stderr, "%s: %s must be > %d\n",
			    prog, what, mi - 1);
		}
		exit(EXIT_FAILURE);
	}
	if (val > ma && ma >= 0) {
		Fprintf(stderr, "%s: %s must be <= %d\n", prog, what, ma);
		exit(EXIT_FAILURE);
	}
	return (val);
}

/*
 * This is the interrupt handler for SIGINT and SIGQUIT. It's completely handled
 * where it jumps to.
 */
static void
sig_handler(int sig)
{
	longjmp(env, sig);
}

/*
 * display the usage of traceroute
 */
static void
usage(void)
{
	Fprintf(stderr, "Usage: %s [-adFIlnSvx] [-A address_family] "
	    "[-c traffic_class]\n"
	    "\t[-f first_hop] [-g gateway [-g gateway ...]| -r] [-i iface]\n"
	    "\t[-L flow_label] [-m max_hop] [-P pause_sec] [-p port] "
	    "[-Q max_timeout]\n"
	    "\t[-q nqueries] [-s src_addr] [-t tos] [-w wait_time] host "
	    "[packetlen]\n", prog);
	exit(EXIT_FAILURE);
}

/* ARGSUSED */
static void *
ns_warning_thr(void *unused)
{
	for (;;) {
		hrtime_t now;

		(void) sleep(tr_nssleeptime);

		now = gethrtime();
		mutex_enter(&tr_nslock);
		if (tr_nsactive && now - tr_nsstarttime >=
		    tr_nswarntime * NANOSEC) {
			Fprintf(stderr, "%s: warning: responses "
			    "received, but name service lookups are "
			    "taking a while. Use %s -n to disable "
			    "name service lookups.\n",
			    prog, prog);
			mutex_exit(&tr_nslock);
			return (NULL);
		}
		mutex_exit(&tr_nslock);
	}

	/* LINTED: E_STMT_NOT_REACHED */
	return (NULL);
}

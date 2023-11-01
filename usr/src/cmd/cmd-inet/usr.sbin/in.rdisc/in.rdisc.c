/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley. The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#define	ALIGN(ptr)	(ptr)

#ifdef SYSV
#define	signal(s, f)	sigset(s, (void (*)(int))f)
#define	random()	rand()
#endif

#define	ALL_HOSTS_ADDRESS		"224.0.0.1"
#define	ALL_ROUTERS_ADDRESS		"224.0.0.2"

#define	MAXIFS 256

/* For router advertisement */
struct icmp_ra {
	uchar_t		icmp_type;	/* type of message, see below */
	uchar_t		icmp_code;	/* type sub code */
	ushort_t	icmp_cksum;	/* ones complement cksum of struct */
	uchar_t		icmp_num_addrs;
	uchar_t		icmp_wpa;	/* Words per address */
	short		icmp_lifetime;
};

struct icmp_ra_addr {
	ulong_t	addr;
	ulong_t preference;
};

/* Router constants */
#define	MAX_INITIAL_ADVERT_INTERVAL	16
#define	MAX_INITIAL_ADVERTISEMENTS	3
#define	MAX_RESPONSE_DELAY		2	/* Not used */

/* Host constants */
#define	MAX_SOLICITATIONS		3
#define	SOLICITATION_INTERVAL		3
#define	MAX_SOLICITATION_DELAY		1	/* Not used */

#define	IGNORE_PREFERENCE	0x80000000	/* Maximum negative */

#define	MAX_ADV_INT 600


/*
 * A doubly linked list of all physical interfaces that each contain a
 * doubly linked list of logical interfaces aka IP addresses.
 */
struct phyint {
	char		pi_name[IFNAMSIZ];	/* Used to identify it */
	int		pi_state;		/* See below */
	struct logint	*pi_logical_first;
	struct logint	*pi_logical_last;
	struct phyint	*pi_next;
	struct phyint	*pi_prev;
};

struct logint {
	char		li_name[IFNAMSIZ];	/* Used to identify it */
	int		li_state;		/* See below */
	struct in_addr	li_address;	/* Used to identify the interface */
	struct in_addr	li_localaddr;	/* Actual address of the interface */
	int		li_preference;
	int		li_index;	/* interface index (SIOCGLIFINDEX) */
	uint64_t	li_flags;
	struct in_addr	li_bcastaddr;
	struct in_addr	li_remoteaddr;
	struct in_addr	li_netmask;
	struct logint	*li_next;	/* Next logical for this physical */
	struct logint	*li_prev;	/* Prev logical for this physical */
	struct phyint	*li_physical;	/* Back pointer */
};

struct phyint *phyint;
int num_usable_interfaces;		/* Num used for sending/receiving */

/*
 * State bits
 */
#define	ST_MARKED	0x01		/* To determine removed interfaces */
#define	ST_JOINED	0x02		/* Joined multicast group */
#define	ST_DELETED	0x04		/* Interface should be ignored */

/* Function prototypes */
static void	solicitor(struct sockaddr_in *sin);
static void	advertise(struct sockaddr_in *sin);

static void	age_table(int time);
static void	flush_unreachable_routers(void);
static void	record_router(struct in_addr router, long preference, int ttl);

static void	add_route(struct in_addr addr);
static void	del_route(struct in_addr addr);
static void	rtioctl(struct in_addr addr, int op);

static int	support_multicast(void);
static int	sendbcast(int s, char *packet, int packetlen);
static int	sendbcastif(int s, char *packet, int packetlen,
		    struct logint *li);
static int	sendmcast(int s, char *packet, int packetlen,
		    struct sockaddr_in *sin);
static int	sendmcastif(int s, char *packet, int packetlen,
		    struct sockaddr_in *sin, struct logint *li);

static int	ismulticast(struct sockaddr_in *sin);
static int	isbroadcast(struct sockaddr_in *sin);
int		in_cksum(ushort_t *addr, int len);
static struct logint *find_directly_connected_logint(struct in_addr in,
    struct phyint *pi);
static void	force_preference(int preference);

static void	timer(void);
static void	finish(void);
static void	report(void);
static void	report_interfaces(void);
static void	report_routes(void);
static void	reinitifs(void);

static struct phyint *find_phyint(char *name);
static struct phyint *add_phyint(char *name);
static void	free_phyint(struct phyint *pi);
static struct logint *find_logint(struct phyint *pi, char *name);
static struct logint *add_logint(struct phyint *pi, char *name);
static void	free_logint(struct logint *li);

static void	deleted_phyint(struct phyint *pi, int s,
		    struct sockaddr_in *joinaddr);
static void	added_logint(struct logint *li, int s,
		    struct sockaddr_in *joinaddr);
static void	deleted_logint(struct logint *li, struct logint *newli, int s,
		    struct sockaddr_in *joinaddr);

static int	initifs(int s, struct sockaddr_in *joinaddr, int preference);
static boolean_t getconfig(int sock, uint64_t if_flags, struct sockaddr *addr,
		    struct ifreq *ifr, struct logint *li);

static void	pr_pack(char *buf, int cc, struct sockaddr_in *from);
char		*pr_name(struct in_addr addr);
char		*pr_type(int t);

static void	initlog(void);
static void	logerr(char *, ...);
static void	logtrace(char *, ...);
static void	logdebug(char *, ...);
static void	logperror(char *);

/* Local variables */

#define	MAXPACKET	4096	/* max packet size */
uchar_t	packet[MAXPACKET];

char usage[] =
"Usage:	rdisc [-s] [-v] [-f] [-a] [send_address] [receive_address]\n"
"	rdisc -r [-v] [-p <preference>] [-T <secs>] \n"
"		[send_address] [receive_address]\n";


int s;				/* Socket file descriptor */
struct sockaddr_in whereto;	/* Address to send to */
struct sockaddr_in g_joinaddr;	/* Address to receive on */
char    *sendaddress, *recvaddress;	/* For logging purposes only */

/* Common variables */
int verbose = 0;
int debug = 0;
int trace = 0;
int start_solicit = 0;	/* -s parameter set */
int solicit = 0;	/* Are we currently sending solicitations? */
int responder;
int ntransmitted = 0;
int nreceived = 0;
int forever = 0;	/* Never give up on host. If 0 defer fork until */
			/* first response.				*/

/* Router variables */
int max_adv_int = MAX_ADV_INT;
int min_adv_int;
int lifetime;
int initial_advert_interval = MAX_INITIAL_ADVERT_INTERVAL;
int initial_advertisements = MAX_INITIAL_ADVERTISEMENTS;
ulong_t g_preference = 0;	/* Setable with -p option */

/* Host variables */
int max_solicitations = MAX_SOLICITATIONS;
unsigned int solicitation_interval = SOLICITATION_INTERVAL;
int best_preference = 1;	/* Set to record only the router(s) with the */
				/* best preference in the kernel. Not set   */
				/* puts all routes in the kernel.	    */


static void
prusage()
{
	(void) fprintf(stderr, usage);
	exit(1);
}

static int	sock = -1;

static void
do_fork()
{
	int t;

	if (trace)
		return;

	if (fork())
		exit(0);
	for (t = 0; t < 20; t++)
		if (t != s)
			(void) close(t);
	sock = -1;
	(void) open("/", 0);
	(void) dup2(0, 1);
	(void) dup2(0, 2);
#ifndef SYSV
	t = open("/dev/tty", 2);
	if (t >= 0) {
		(void) ioctl(t, TIOCNOTTY, (char *)0);
		(void) close(t);
	}
#else
	(void) setpgrp();
#endif
	initlog();
}

/*
 *			M A I N
 */
int
main(int argc, char *argv[])
{
#ifndef SYSV
	struct sigvec sv;
#endif
	struct sockaddr_in from;
	char **av = argv;
	struct sockaddr_in *to = &whereto;
	ulong_t val;

	min_adv_int = (max_adv_int * 3 / 4);
	lifetime = (3*max_adv_int);

	argc--, av++;
	while (argc > 0 && *av[0] == '-') {
	    while (*++av[0])
		switch (*av[0]) {
		case 'd':
			debug = 1;
			break;
		case 't':
			trace = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 's':
			start_solicit = solicit = 1;
			break;
		case 'r':
			responder = 1;
			break;
		case 'a':
			best_preference = 0;
			break;
		case 'b':
			best_preference = 1;
			break;
		case 'f':
			forever = 1;
			break;
		case 'T':
			argc--, av++;
			if (argc != 0) {
				val = strtol(av[0], (char **)NULL, 0);
				if (val < 4 || val > 1800) {
					(void) fprintf(stderr,
					    "Bad Max Advertisement Interval\n");
					exit(1);
				}
				max_adv_int = val;
				min_adv_int = (max_adv_int * 3 / 4);
				lifetime = (3*max_adv_int);
			} else {
				prusage();
				/* NOTREACHED */
			}
			goto next;
		case 'p':
			argc--, av++;
			if (argc != 0) {
				val = strtoul(av[0], (char **)NULL, 0);
				g_preference = val;
			} else {
				prusage();
				/* NOTREACHED */
			}
			goto next;
		default:
			prusage();
			/* NOTREACHED */
		}
	next:
		argc--, av++;
	}
	if (argc < 1)  {
		if (support_multicast()) {
			if (responder)
				sendaddress = ALL_HOSTS_ADDRESS;
			else
				sendaddress = ALL_ROUTERS_ADDRESS;
		} else
			sendaddress = "255.255.255.255";
	} else {
		sendaddress = av[0];
		argc--;
	}
	if (argc < 1) {
		if (support_multicast()) {
			if (responder)
				recvaddress = ALL_ROUTERS_ADDRESS;
			else
				recvaddress = ALL_HOSTS_ADDRESS;
		} else
			recvaddress = "255.255.255.255";
	} else {
		recvaddress = av[0];
		argc--;
	}
	if (argc != 0) {
		(void) fprintf(stderr, "Extra paramaters\n");
		prusage();
		/* NOTREACHED */
	}

	if (solicit && responder) {
		prusage();
		/* NOTREACHED */
	}

	if (!(solicit && !forever)) {
		do_fork();
	}

	bzero((char *)&whereto, sizeof (struct sockaddr_in));
	to->sin_family = AF_INET;
	to->sin_addr.s_addr = inet_addr(sendaddress);
	if (to->sin_addr.s_addr == (unsigned long)-1) {
		logerr("in.rdisc: bad address %s\n", sendaddress);
		exit(1);
	}

	bzero((char *)&g_joinaddr, sizeof (struct sockaddr_in));
	g_joinaddr.sin_family = AF_INET;
	g_joinaddr.sin_addr.s_addr = inet_addr(recvaddress);
	if (g_joinaddr.sin_addr.s_addr == (unsigned long)-1) {
		logerr("in.rdisc: bad address %s\n", recvaddress);
		exit(1);
	}

	if (responder) {
#ifdef SYSV
		srand((int)gethostid());
#else
		srandom((int)gethostid());
#endif
	}

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		logperror("socket");
		exit(5);
	}

#ifdef SYSV
	setvbuf(stdout, NULL, _IOLBF, 0);
#else
	setlinebuf(stdout);
#endif

	(void) signal(SIGINT, finish);
	(void) signal(SIGTERM, finish);
	(void) signal(SIGHUP, reinitifs);
	(void) signal(SIGUSR1, report);

	if (initifs(s, &g_joinaddr, g_preference) < 0) {
		logerr("Failed initializing interfaces\n");
		exit(2);
	}

	/*
	 * If there are no usable interfaces and we are soliciting
	 * waiting for to return an exit code (i.e. forever isn't set)
	 * give up immediately.
	 */
	if (num_usable_interfaces == 0 && solicit && !forever) {
		logerr("in.rdisc: No interfaces up\n");
		exit(5);
	}

#ifdef SYSV
	(void) signal(SIGALRM, timer);
#else
	/*
	 * Make sure that this signal actually interrupts (rather than
	 * restarts) the recvfrom call below.
	 */
	sv.sv_handler = timer;
	sv.sv_mask = 0;
	sv.sv_flags = SV_INTERRUPT;
	(void) sigvec(SIGALRM, &sv, (struct sigvec *)NULL);
#endif
	timer();	/* start things going */

	for (;;) {
		int len = sizeof (packet);
		socklen_t fromlen = (socklen_t)sizeof (from);
		int cc;
		sigset_t newmask, oldmask;

		if ((cc = recvfrom(s, (char *)packet, len, 0,
		    (struct sockaddr *)&from,
		    &fromlen)) < 0) {
			if (errno == EINTR)
				continue;
			logperror("recvfrom");
			continue;
		}
		/* Block all signals while processing */
		(void) sigfillset(&newmask);
		(void) sigprocmask(SIG_SETMASK, &newmask, &oldmask);
		pr_pack((char *)packet, cc, &from);
		(void) sigprocmask(SIG_SETMASK, &oldmask, NULL);
	}
	/* NOTREACHED */
}

static void
report(void)
{
	report_interfaces();
	report_routes();
}

#define	TIMER_INTERVAL	6
#define	GETIFCONF_TIMER	30

static int left_until_advertise;

/* Called every TIMER_INTERVAL */
static void
timer(void)
{
	static int time;
	static int left_until_getifconf;
	static int left_until_solicit;

	time += TIMER_INTERVAL;

	left_until_getifconf -= TIMER_INTERVAL;
	left_until_advertise -= TIMER_INTERVAL;
	left_until_solicit -= TIMER_INTERVAL;

	if (left_until_getifconf < 0) {
		(void) initifs(s, &g_joinaddr, g_preference);
		left_until_getifconf = GETIFCONF_TIMER;
	}
	if (responder && left_until_advertise <= 0) {
		ntransmitted++;
		advertise(&whereto);
		if (ntransmitted < initial_advertisements)
			left_until_advertise = initial_advert_interval;
		else
			left_until_advertise = min_adv_int +
				((max_adv_int - min_adv_int) *
				(random() % 1000)/1000);
	} else if (solicit && left_until_solicit <= 0) {
		if (ntransmitted < max_solicitations) {
			ntransmitted++;
			solicitor(&whereto);
			left_until_solicit = solicitation_interval;
		} else {
			solicit = 0;
			if (!forever && nreceived == 0)
				exit(5);
		}
	}
	age_table(TIMER_INTERVAL);
	(void) alarm(TIMER_INTERVAL);
}

/*
 *			S O L I C I T O R
 *
 * Compose and transmit an ICMP ROUTER SOLICITATION REQUEST packet.
 * The IP packet will be added on by the kernel.
 */
static void
solicitor(struct sockaddr_in *sin)
{
	static uchar_t outpack[MAXPACKET];
	register struct icmp *icp = (struct icmp *)ALIGN(outpack);
	int packetlen, i;

	if (verbose) {
		logtrace("Sending solicitation to %s\n",
			pr_name(sin->sin_addr));
	}
	icp->icmp_type = ICMP_ROUTERSOLICIT;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_void = 0; /* Reserved */
	packetlen = 8;

	/* Compute ICMP checksum here */
	icp->icmp_cksum = in_cksum((ushort_t *)icp, packetlen);

	if (isbroadcast(sin))
		i = sendbcast(s, (char *)outpack, packetlen);
	else if (ismulticast(sin))
		i = sendmcast(s, (char *)outpack, packetlen, sin);
	else {
		struct logint *li;

		li = find_directly_connected_logint(sin->sin_addr, NULL);
		if (li != NULL && (li->li_flags & IFF_NORTEXCH)) {
			if (verbose) {
				logtrace("Suppressing sending %s on %s "
				    "(no route exchange on interface)\n",
				    pr_type((int)icp->icmp_type), li->li_name);
			}
			return;
		} else {
			i = sendto(s, (char *)outpack, packetlen, 0,
			    (struct sockaddr *)sin, sizeof (struct sockaddr));
		}
	}

	if (i < 0 || i != packetlen)  {
		if (i < 0) {
		    logperror("sendto");
		}
		logerr("wrote %s %d chars, ret=%d\n",
			sendaddress, packetlen, i);
	}
}

/*
 *			A D V E R T I S E
 *
 * Compose and transmit an ICMP ROUTER ADVERTISEMENT packet.
 * The IP packet will be added on by the kernel.
 */
static void
advertise(struct sockaddr_in *sin)
{
	struct phyint *pi;
	struct logint *li, *li_tmp;
	static uchar_t outpack[MAXPACKET];
	register struct icmp_ra *rap = (struct icmp_ra *)ALIGN(outpack);
	struct icmp_ra_addr *ap;
	int packetlen, cc;

	if (verbose) {
		logtrace("Sending advertisement to %s\n",
			pr_name(sin->sin_addr));
	}

	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		rap->icmp_type = ICMP_ROUTERADVERT;
		rap->icmp_code = 0;
		rap->icmp_cksum = 0;
		rap->icmp_num_addrs = 0;
		rap->icmp_wpa = 2;
		rap->icmp_lifetime = htons(lifetime);
		packetlen = ICMP_MINLEN;

		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			if (li->li_state & ST_DELETED)
				continue;

			/*
			 * XXX Just truncate the list of addresses.
			 * Should probably send multiple packets.
			 */
			if (packetlen + rap->icmp_wpa * 4 > sizeof (outpack)) {
				if (debug)
					logdebug("full packet: %d addresses\n",
						rap->icmp_num_addrs);
				break;
			}
			ap = (struct icmp_ra_addr *)ALIGN(outpack + packetlen);
			ap->addr = li->li_localaddr.s_addr;
			ap->preference = htonl(li->li_preference);
			packetlen += rap->icmp_wpa * 4;
			rap->icmp_num_addrs++;
		}

		if (rap->icmp_num_addrs == 0)
			continue;

		/* Compute ICMP checksum here */
		rap->icmp_cksum = in_cksum((ushort_t *)rap, packetlen);

		if (isbroadcast(sin))
			cc = sendbcastif(s, (char *)outpack, packetlen,
			    pi->pi_logical_first);
		else if (ismulticast(sin))
			cc = sendmcastif(s, (char *)outpack, packetlen, sin,
			    pi->pi_logical_first);
		else {
			/*
			 * Verify that the physical interface matches the
			 * destination address.
			 */
			li_tmp = find_directly_connected_logint(sin->sin_addr,
			    pi);
			if (li_tmp == NULL)
				continue;
			if (li_tmp->li_flags & IFF_NORTEXCH) {
				if (verbose) {
					logtrace("Suppressing sending %s on %s "
					    "(no route exchange on "
					    "interface)\n",
					    pr_type((int)rap->icmp_type),
					    li_tmp->li_name);
				}
				continue;
			}
			if (debug) {
				logdebug("Unicast to %s ",
				    pr_name(sin->sin_addr));
				logdebug("on interface %s\n", pi->pi_name);
			}
			cc = sendto(s, (char *)outpack, packetlen, 0,
			    (struct sockaddr *)sin, sizeof (struct sockaddr));
		}
		if (cc < 0 || cc != packetlen)  {
			if (cc < 0) {
				logperror("sendto");
			} else {
				logerr("wrote %s %d chars, ret=%d\n",
					sendaddress, packetlen, cc);
			}
		}
	}
}

/*
 *			P R _ T Y P E
 *
 * Convert an ICMP "type" field to a printable string.
 */
char *
pr_type(int t)
{
	static char *ttab[] = {
		"Echo Reply",
		"ICMP 1",
		"ICMP 2",
		"Dest Unreachable",
		"Source Quench",
		"Redirect",
		"ICMP 6",
		"ICMP 7",
		"Echo",
		"Router Advertise",
		"Router Solicitation",
		"Time Exceeded",
		"Parameter Problem",
		"Timestamp",
		"Timestamp Reply",
		"Info Request",
		"Info Reply",
		"Netmask Request",
		"Netmask Reply"
	};

	if (t < 0 || t > 16)
		return ("OUT-OF-RANGE");

	return (ttab[t]);
}

/*
 *			P R _ N A M E
 *
 * Return a string name for the given IP address.
 */
char *
pr_name(struct in_addr addr)
{
	struct hostent *phe;
	static char buf[256];

	phe = gethostbyaddr((char *)&addr.s_addr, 4, AF_INET);
	if (phe == NULL)
		return (inet_ntoa(addr));
	(void) sprintf(buf, "%s (%s)", phe->h_name, inet_ntoa(addr));
	return (buf);
}

/*
 *			P R _ P A C K
 *
 * Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
static void
pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
	struct ip *ip;
	register struct icmp *icp;
	register int i;
	int hlen;
	struct logint *li;

	ip = (struct ip *)ALIGN(buf);
	hlen = ip->ip_hl << 2;
	if (cc < hlen + ICMP_MINLEN) {
		if (verbose)
			logtrace("packet too short (%d bytes) from %s\n", cc,
				pr_name(from->sin_addr));
		return;
	}

	cc -= hlen;
	icp = (struct icmp *)ALIGN(buf + hlen);

	/*
	 * Let's check if IFF_NORTEXCH flag is set on the interface which
	 * recevied this packet.
	 * TODO: this code can be re-written using one socket per interface
	 * to determine which interface the packet is recevied.
	 */
	li = find_directly_connected_logint(ip->ip_src, NULL);
	if (li != NULL && (li->li_flags & IFF_NORTEXCH)) {
		if (verbose) {
			logtrace("Ignoring received %s on %s "
			    "(no route exchange on interface)",
			    pr_type((int)icp->icmp_type), li->li_name);
		}
		return;
	}

	if (ip->ip_p == 0) {
		/*
		 * Assume that we are running on a pre-4.3BSD system
		 * such as SunOS before 4.0
		 */
		icp = (struct icmp *)ALIGN(buf);
	}
	switch (icp->icmp_type) {
	case ICMP_ROUTERADVERT: {
		struct icmp_ra *rap = (struct icmp_ra *)ALIGN(icp);
		struct icmp_ra_addr *ap;

		if (responder)
			break;

		/* TBD verify that the link is multicast or broadcast */
		/* XXX Find out the link it came in over? */
#ifdef notdef
		if (debug) {
			logdebug("ROUTER_ADVERTISEMENT: \n");
			pr_hex(buf+hlen, cc);
		}
#endif /* notdef */
		if (in_cksum((ushort_t *)ALIGN(buf+hlen), cc)) {
			if (verbose)
				logtrace("ICMP %s from %s: Bad checksum\n",
					pr_type((int)rap->icmp_type),
					pr_name(from->sin_addr));
			return;
		}
		if (rap->icmp_code != 0) {
			if (verbose)
				logtrace("ICMP %s from %s: Code = %d\n",
					pr_type((int)rap->icmp_type),
					pr_name(from->sin_addr),
					rap->icmp_code);
			return;
		}
		if (rap->icmp_num_addrs < 1) {
			if (verbose)
				logtrace("ICMP %s from %s: No addresses\n",
					pr_type((int)rap->icmp_type),
					pr_name(from->sin_addr));
			return;
		}
		if (rap->icmp_wpa < 2) {
			if (verbose)
				logtrace("ICMP %s from %s: Words/addr = %d\n",
					pr_type((int)rap->icmp_type),
					pr_name(from->sin_addr),
					rap->icmp_wpa);
			return;
		}
		if ((unsigned)cc <
		    ICMP_MINLEN + rap->icmp_num_addrs * rap->icmp_wpa * 4) {
			if (verbose)
				logtrace("ICMP %s from %s: Too short %d, %d\n",
					pr_type((int)rap->icmp_type),
					pr_name(from->sin_addr),
					cc,
					ICMP_MINLEN +
					rap->icmp_num_addrs *
					rap->icmp_wpa * 4);
			return;
		}
		rap->icmp_lifetime = ntohs(rap->icmp_lifetime);
		if ((rap->icmp_lifetime < 4 && rap->icmp_lifetime != 0) ||
		    rap->icmp_lifetime > 9000) {
			if (verbose)
			    logtrace("ICMP %s from %s: Invalid lifetime %d\n",
					pr_type((int)rap->icmp_type),
					pr_name(from->sin_addr),
					rap->icmp_lifetime);
			return;
		}
		if (verbose)
			logtrace("ICMP %s from %s, lifetime %d\n",
				pr_type((int)rap->icmp_type),
				pr_name(from->sin_addr),
				rap->icmp_lifetime);

		/*
		 * Check that at least one router address is a neighbor
		 * on the arriving link.
		 */
		for (i = 0; (unsigned)i < rap->icmp_num_addrs; i++) {
			struct in_addr ina;
			ap = (struct icmp_ra_addr *)
				ALIGN(buf + hlen + ICMP_MINLEN +
					i * rap->icmp_wpa * 4);
			ap->preference = ntohl(ap->preference);
			ina.s_addr = ap->addr;
			if (verbose)
				logtrace("\taddress %s, preference 0x%x\n",
					pr_name(ina),
					ap->preference);
			if (!responder) {
				if (find_directly_connected_logint(ina, NULL) !=
				    NULL) {
					record_router(ina,
					    (long)ap->preference,
					    rap->icmp_lifetime);
				}
			}
		}
		nreceived++;
		if (!forever) {
			(void) alarm(0);
			do_fork();
			forever = 1;
			(void) alarm(TIMER_INTERVAL);
		}
		break;
	}

	case ICMP_ROUTERSOLICIT: {
		struct sockaddr_in sin;

		if (!responder)
			break;

		/* TBD verify that the link is multicast or broadcast */
		/* XXX Find out the link it came in over? */
#ifdef notdef
		if (debug) {
			logdebug("ROUTER_SOLICITATION: \n");
			pr_hex(buf+hlen, cc);
		}
#endif /* notdef */
		if (in_cksum((ushort_t *)ALIGN(buf+hlen), cc)) {
			if (verbose)
				logtrace("ICMP %s from %s: Bad checksum\n",
					pr_type((int)icp->icmp_type),
					pr_name(from->sin_addr));
			return;
		}
		if (icp->icmp_code != 0) {
			if (verbose)
				logtrace("ICMP %s from %s: Code = %d\n",
					pr_type((int)icp->icmp_type),
					pr_name(from->sin_addr),
					icp->icmp_code);
			return;
		}

		if (cc < ICMP_MINLEN) {
			if (verbose)
				logtrace("ICMP %s from %s: Too short %d, %d\n",
					pr_type((int)icp->icmp_type),
					pr_name(from->sin_addr),
					cc,
					ICMP_MINLEN);
			return;
		}

		if (verbose)
			logtrace("ICMP %s from %s\n",
				pr_type((int)icp->icmp_type),
				pr_name(from->sin_addr));

		if (!responder)
			break;

		/*
		 * Check that ip_src is either a neighbor
		 * on the arriving link or 0.
		 */
		sin.sin_family = AF_INET;
		if (ip->ip_src.s_addr == 0) {
			/*
			 * If it was sent to the broadcast address we respond
			 * to the broadcast address.
			 */
			if (IN_CLASSD(ntohl(ip->ip_dst.s_addr))) {
				sin.sin_addr.s_addr =
				    htonl(INADDR_ALLHOSTS_GROUP);
			} else
				sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
			/* Restart the timer when we broadcast */
			left_until_advertise = min_adv_int +
				((max_adv_int - min_adv_int)
				 * (random() % 1000)/1000);
		} else {
			if (li == NULL) {
				if (verbose)
					logtrace("ICMP %s from %s: %s\n",
						pr_type((int)icp->icmp_type),
						pr_name(from->sin_addr),
					"source not directly connected");
				break;
			}
			sin.sin_addr.s_addr = ip->ip_src.s_addr;
		}
		nreceived++;
		ntransmitted++;
		advertise(&sin);
		break;
	}
	}
}


/*
 *			I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
int
in_cksum(ushort_t *addr, int len)
{
	register int nleft = len;
	register ushort_t *w = addr;
	register ushort_t answer;
	ushort_t odd_byte = 0;
	register int sum = 0;

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
 *			F I N I S H
 *
 * Print out statistics, and give up.
 * Heavily buffered stdio is used here, so that all the statistics
 * will be written with 1 sys-write call.  This is nice when more
 * than one copy of the program is running on a terminal;  it prevents
 * the statistics output from becoming intermingled.
 */
static void
finish(void)
{
	if (responder) {
		/*
		 * Send out a packet with a preference so that all
		 * hosts will know that we are dead.
		 */
		logerr("terminated\n");
		force_preference(IGNORE_PREFERENCE);
		ntransmitted++;
		advertise(&whereto);
	}
	if (verbose) {
		logtrace("\n----%s rdisc Statistics----\n", sendaddress);
		logtrace("%d packets transmitted, ", ntransmitted);
		logtrace("%d packets received, ", nreceived);
		logtrace("\n");
	}
	(void) fflush(stdout);
	exit(0);
}

#include <ctype.h>

#ifdef notdef
int
pr_hex(unsigned char *data, int len)
{
	FILE *out;

	out = stdout;

	while (len) {
		register int i;
		char charstring[17];

		(void) strcpy(charstring, "                "); /* 16 spaces */
		for (i = 0; i < 16; i++) {
			/*
			 * output the bytes one at a time,
			 * not going past "len" bytes
			 */
			if (len) {
				char ch = *data & 0x7f; /* strip parity */
				if (!isprint((uchar_t)ch))
					ch = ' '; /* ensure printable */
				charstring[i] = ch;
				(void) fprintf(out, "%02x ", *data++);
				len--;
			} else
				(void) fprintf(out, "   ");
			if (i == 7)
				(void) fprintf(out, "   ");
		}

		(void) fprintf(out, "    *%s*\n", charstring);
	}
}
#endif /* notdef */

static int
isbroadcast(struct sockaddr_in *sin)
{
	return (sin->sin_addr.s_addr == htonl(INADDR_BROADCAST));
}

static int
ismulticast(struct sockaddr_in *sin)
{
	return (IN_CLASSD(ntohl(sin->sin_addr.s_addr)));
}

/* From libc/rpc/pmap_rmt.c */


/* Only send once per physical interface */
static int
sendbcast(int s, char *packet, int packetlen)
{
	struct phyint *pi;
	struct logint *li;
	boolean_t bcast;
	int cc;

	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		bcast = B_FALSE;
		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			if (li->li_state & ST_DELETED)
				continue;

			if (li->li_flags & IFF_BROADCAST) {
				bcast = B_TRUE;
				break;
			}
		}
		if (!bcast)
			continue;
		cc = sendbcastif(s, packet, packetlen, li);
		if (cc != packetlen) {
			return (cc);
		}
	}
	return (packetlen);
}

static int
sendbcastif(int s, char *packet, int packetlen, struct logint *li)
{
	int cc;
	struct sockaddr_in baddr;
	struct icmp *icp = (struct icmp *)ALIGN(packet);

	baddr.sin_family = AF_INET;

	if ((li->li_flags & IFF_BROADCAST) == 0) {
		if (verbose) {
			logtrace("Suppressing sending %s on %s "
			    "(interface is not broadcast capable)\n",
			    pr_type((int)icp->icmp_type), li->li_name);
		}
		return (packetlen);
	}
	if (li->li_flags & IFF_NORTEXCH) {
		if (verbose) {
			logtrace("Suppressing sending %s on %s "
			    "(no route exchange on interface)\n",
			    pr_type((int)icp->icmp_type), li->li_name);
		}
		return (packetlen);
	}

	baddr.sin_addr = li->li_bcastaddr;
	if (debug)
		logdebug("Broadcast to %s\n",
			pr_name(baddr.sin_addr));
	cc = sendto(s, packet, packetlen, 0,
	    (struct sockaddr *)&baddr, sizeof (struct sockaddr));
	if (cc != packetlen) {
		logperror("sendbcast: sendto");
		logerr("Cannot send broadcast packet to %s\n",
			pr_name(baddr.sin_addr));
	}
	return (cc);
}

static int
sendmcast(int s, char *packet, int packetlen, struct sockaddr_in *sin)
{
	struct phyint *pi;
	struct logint *li;
	boolean_t mcast;
	int cc;

	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		mcast = B_FALSE;
		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			if (li->li_state & ST_DELETED)
				continue;

			if (li->li_flags & IFF_MULTICAST) {
				mcast = B_TRUE;
				break;
			}
		}
		if (!mcast)
			continue;
		cc = sendmcastif(s, packet, packetlen, sin, li);
		if (cc != packetlen) {
			return (cc);
		}
	}
	return (packetlen);
}

static int
sendmcastif(int s, char *packet, int packetlen, struct sockaddr_in *sin,
    struct logint *li)
{
	int cc;
	struct sockaddr_in ifaddr;
	struct icmp *icp = (struct icmp *)ALIGN(packet);

	ifaddr.sin_family = AF_INET;

	if ((li->li_flags & IFF_MULTICAST) == 0) {
		if (verbose) {
			logtrace("Suppressing sending %s on %s "
			    "(interface is not multicast capable)\n",
			    pr_type((int)icp->icmp_type), li->li_name);
		}
		return (packetlen);
	}
	if (li->li_flags & IFF_NORTEXCH) {
		if (verbose) {
			logtrace("Suppressing sending %s on %s "
			    "(no route exchange on interface)\n",
			    pr_type((int)icp->icmp_type), li->li_name);
		}
		return (packetlen);
	}

	ifaddr.sin_addr = li->li_address;
	if (debug)
		logdebug("Multicast to interface %s\n",
			pr_name(ifaddr.sin_addr));
	if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
	    (char *)&ifaddr.sin_addr,
	    sizeof (ifaddr.sin_addr)) < 0) {
		logperror("setsockopt (IP_MULTICAST_IF)");
		logerr("Cannot send multicast packet over interface %s\n",
			pr_name(ifaddr.sin_addr));
		return (-1);
	}
	cc = sendto(s, packet, packetlen, 0,
	    (struct sockaddr *)sin, sizeof (struct sockaddr));
	if (cc != packetlen) {
		logperror("sendmcast: sendto");
		logerr("Cannot send multicast packet over interface %s\n",
			pr_name(ifaddr.sin_addr));
	}
	return (cc);
}

static void
reinitifs(void)
{
	(void) initifs(s, &g_joinaddr, g_preference);
}

static void
force_preference(int preference)
{
	struct phyint *pi;
	struct logint *li;

	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			if (li->li_state & ST_DELETED)
				continue;

			li->li_preference = preference;
		}
	}
}

/*
 * Returns -1 on failure.
 */
static int
initifs(int s, struct sockaddr_in *joinaddr, int preference)
{
	struct ifconf ifc;
	struct ifreq ifreq, *ifr;
	struct lifreq lifreq;
	int n;
	char *buf;
	int numifs;
	unsigned bufsize;
	struct phyint *pi;
	struct logint *li;
	int num_deletions;
	char phyintname[IFNAMSIZ];
	char *cp;
	int old_num_usable_interfaces = num_usable_interfaces;

	/*
	 * Mark all interfaces so that we can determine which ones
	 * have gone away.
	 */
	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		pi->pi_state |= ST_MARKED;
		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			li->li_state |= ST_MARKED;
		}
	}

	if (sock < 0) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0) {
			logperror("initifs: socket");
			return (-1);
		}
	}
#ifdef SIOCGIFNUM
	if (ioctl(sock, SIOCGIFNUM, (char *)&numifs) < 0) {
		logperror("initifs: SIOCGIFNUM");
		return (-1);
	}
#else
	numifs = MAXIFS;
#endif
	bufsize = numifs * sizeof (struct ifreq);
	buf = (char *)malloc(bufsize);
	if (buf == NULL) {
		logerr("out of memory\n");
		(void) close(sock);
		sock = -1;
		return (-1);
	}
	ifc.ifc_len = bufsize;
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, (char *)&ifc) < 0) {
		logperror("initifs: ioctl (get interface configuration)");
		(void) close(sock);
		sock = -1;
		(void) free(buf);
		return (-1);
	}
	ifr = ifc.ifc_req;
	for (n = ifc.ifc_len/sizeof (struct ifreq); n > 0; n--, ifr++) {
		ifreq = *ifr;
		/*
		 * We need to use new interface ioctls to get 64-bit flags.
		 */
		(void) strncpy(lifreq.lifr_name, ifr->ifr_name,
		    sizeof (ifr->ifr_name));
		if (ioctl(sock, SIOCGLIFFLAGS, (char *)&lifreq) < 0) {
			logperror("initifs: ioctl (get interface flags)");
			continue;
		}
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;
		if ((lifreq.lifr_flags & IFF_UP) == 0)
			continue;
		if (lifreq.lifr_flags & IFF_LOOPBACK)
			continue;
		if ((lifreq.lifr_flags & (IFF_MULTICAST | IFF_BROADCAST)) == 0)
			continue;

		/* Create the physical name by truncating at the ':' */
		strncpy(phyintname, ifreq.ifr_name, sizeof (phyintname));
		if ((cp = strchr(phyintname, ':')) != NULL)
			*cp = '\0';

		pi = find_phyint(phyintname);
		if (pi == NULL) {
			pi = add_phyint(phyintname);
			if (pi == NULL) {
				logerr("out of memory\n");
				(void) close(sock);
				sock = -1;
				(void) free(buf);
				return (-1);
			}
		}
		pi->pi_state &= ~ST_MARKED;

		li = find_logint(pi, ifreq.ifr_name);
		if (li != NULL) {
			/*
			 * Detect significant changes.
			 * We treat netmask changes as insignificant but all
			 * other changes cause a delete plus add of the
			 * logical interface.
			 * Note: if the flags and localaddr are unchanged
			 * then nothing but the netmask and the broadcast
			 * address could have changed since the other addresses
			 * are derived from the flags and the localaddr.
			 */
			struct logint newli;

			if (!getconfig(sock, lifreq.lifr_flags, &ifr->ifr_addr,
			    &ifreq, &newli)) {
				free_logint(li);
				continue;
			}

			if (newli.li_flags != li->li_flags ||
			    newli.li_localaddr.s_addr !=
			    li->li_localaddr.s_addr || newli.li_index !=
			    li->li_index) {
				/* Treat as an interface deletion + addition */
				li->li_state |= ST_DELETED;
				deleted_logint(li, &newli, s, joinaddr);
				free_logint(li);
				li = NULL;	/* li recreated below */
			} else {
				/*
				 * No significant changes.
				 * Just update the netmask, and broadcast.
				 */
				li->li_netmask = newli.li_netmask;
				li->li_bcastaddr = newli.li_bcastaddr;
			}
		}
		if (li == NULL) {
			li = add_logint(pi, ifreq.ifr_name);
			if (li == NULL) {
				logerr("out of memory\n");
				(void) close(sock);
				sock = -1;
				(void) free(buf);
				return (-1);
			}

			/* init li */
			if (!getconfig(sock, lifreq.lifr_flags, &ifr->ifr_addr,
			    &ifreq, li)) {
				free_logint(li);
				continue;
			}
			li->li_preference = preference;
			added_logint(li, s, joinaddr);
		}
		li->li_state &= ~ST_MARKED;
	}
	(void) free(buf);

	/*
	 * Determine which interfaces have gone away.
	 * The deletion is done in three phases:
	 * 1. Mark ST_DELETED
	 * 2. Inform using the deleted_* function.
	 * 3. Unlink and free the actual memory.
	 * Note that for #3 the physical interface must be deleted after
	 * the logical ones.
	 * Also count the number of physical interfaces.
	 */
	num_usable_interfaces = 0;
	num_deletions = 0;
	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		if (pi->pi_state & ST_MARKED) {
			num_deletions++;
			pi->pi_state |= ST_DELETED;
		}
		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			if (li->li_state & ST_MARKED) {
				num_deletions++;
				li->li_state |= ST_DELETED;
			}
		}
		if (!(pi->pi_state & ST_DELETED))
			num_usable_interfaces++;
	}
	if (num_deletions != 0) {
		struct phyint *nextpi;
		struct logint *nextli;

		for (pi = phyint; pi != NULL; pi = pi->pi_next) {
			if (pi->pi_state & ST_DELETED) {
				/*
				 * By deleting the physical interface pi, all of
				 * the corresponding logical interfaces will
				 * also be deleted so there is no need to delete
				 * them individually.
				 */
				deleted_phyint(pi, s, joinaddr);
			} else {
				for (li = pi->pi_logical_first; li != NULL;
				    li = li->li_next) {
					if (li->li_state & ST_DELETED) {
						deleted_logint(li, NULL, s,
						    joinaddr);
					}
				}
			}
		}
		/* Do the actual linked list update + free */
		for (pi = phyint; pi != NULL; pi = nextpi) {
			nextpi = pi->pi_next;
			for (li = pi->pi_logical_first; li != NULL;
			    li = nextli) {
				nextli = li->li_next;
				if (li->li_state & ST_DELETED)
					free_logint(li);
			}
			if (pi->pi_state & ST_DELETED)
				free_phyint(pi);
		}
	}
	/*
	 * When the set of available interfaces goes from zero to
	 * non-zero we restart solicitations if '-s' was specified.
	 */
	if (old_num_usable_interfaces == 0 && num_usable_interfaces > 0 &&
	    start_solicit && !solicit) {
		if (debug)
			logdebug("switching to solicitations: num if %d\n",
			    num_usable_interfaces);
		solicit = start_solicit;
		ntransmitted = 0;
		ntransmitted++;
		solicitor(&whereto);
	}
	return (0);
}

static boolean_t
getconfig(int sock, uint64_t if_flags, struct sockaddr *addr,
    struct ifreq *ifr, struct logint *li)
{
	struct ifreq ifreq;
	struct sockaddr_in *sin;
	struct lifreq lifreq;

	ifreq = *ifr;	/* Copy name etc */

	li->li_flags = if_flags;
	sin = (struct sockaddr_in *)ALIGN(addr);
	li->li_localaddr = sin->sin_addr;

	(void) strlcpy(lifreq.lifr_name, ifr->ifr_name,
	    sizeof (lifreq.lifr_name));
	if (ioctl(sock, SIOCGLIFINDEX, &lifreq) < 0) {
		logperror("initifs: ioctl (get if index)");
		/* Continue with 0; a safe value never used for interfaces */
		li->li_index = 0;
	} else {
		li->li_index = lifreq.lifr_index;
	}

	if (if_flags & IFF_POINTOPOINT) {
		li->li_netmask.s_addr = (unsigned long)0xffffffff;
		if (ioctl(sock, SIOCGIFDSTADDR, (char *)&ifreq) < 0) {
			logperror("initifs: ioctl (get dest addr)");
			return (B_FALSE);
		}
		/* A pt-pt link is identified by the remote address */
		sin = (struct sockaddr_in *)ALIGN(&ifreq.ifr_addr);
		li->li_address = sin->sin_addr;
		li->li_remoteaddr = sin->sin_addr;
		/* Simulate broadcast for pt-pt */
		li->li_bcastaddr = sin->sin_addr;
		li->li_flags |= IFF_BROADCAST;
	} else {
		/*
		 * Non pt-pt links are identified by the local
		 * address
		 */
		li->li_address = li->li_localaddr;
		li->li_remoteaddr = li->li_address;
		if (ioctl(sock, SIOCGIFNETMASK, (char *)&ifreq) < 0) {
			logperror("initifs: ioctl (get netmask)");
			return (B_FALSE);
		}
		sin = (struct sockaddr_in *)ALIGN(&ifreq.ifr_addr);
		li->li_netmask = sin->sin_addr;
		if (if_flags & IFF_BROADCAST) {
			if (ioctl(sock, SIOCGIFBRDADDR, (char *)&ifreq) < 0) {
				logperror(
				    "initifs: ioctl (get broadcast address)");
				return (B_FALSE);
			}
			sin = (struct sockaddr_in *)ALIGN(&ifreq.ifr_addr);
			li->li_bcastaddr = sin->sin_addr;
		}
	}
	return (B_TRUE);
}


static int
support_multicast(void)
{
	int sock;
	uchar_t ttl = 1;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		logperror("support_multicast: socket");
		return (0);
	}

	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
	    (char *)&ttl, sizeof (ttl)) < 0) {
		(void) close(sock);
		return (0);
	}
	(void) close(sock);
	return (1);
}

/*
 * For a given destination address, find the logical interface to use.
 * If opi is NULL check all interfaces. Otherwise just match against
 * the specified physical interface.
 * Return logical interface if there's a match, NULL otherwise.
 */
static struct logint *
find_directly_connected_logint(struct in_addr in, struct phyint *opi)
{
	struct phyint *pi;
	struct logint *li;

	if (opi == NULL)
		pi = phyint;
	else
		pi = opi;

	for (; pi != NULL; pi = pi->pi_next) {
		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			if (li->li_state & ST_DELETED)
				continue;

			/* Check that the subnetwork numbers match */
			if ((in.s_addr & li->li_netmask.s_addr) ==
			    (li->li_remoteaddr.s_addr &
			    li->li_netmask.s_addr))
				return (li);
		}
		if (opi != NULL)
			break;
	}
	return (NULL);
}

/*
 * INTERFACES - physical and logical identified by name
 */


static void
report_interfaces(void)
{
	struct phyint *pi;
	struct logint *li;

	logdebug("\nInterfaces:\n\n");
	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		logdebug("Phyint %s state 0x%x\n",
		    pi->pi_name, pi->pi_state);
		for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
			logdebug("IF %s state 0x%x, flags 0x%x, addr %s\n",
			    li->li_name, li->li_state, li->li_flags,
			    pr_name(li->li_address));
			logdebug("\tlocal %s pref 0x%x ",
			    pr_name(li->li_localaddr), li->li_preference);
			logdebug("bcast %s\n",
			    pr_name(li->li_bcastaddr));
			logdebug("\tremote %s ",
			    pr_name(li->li_remoteaddr));
			logdebug("netmask %s\n",
			    pr_name(li->li_netmask));
		}
	}
}

static struct phyint *
find_phyint(char *name)
{
	struct phyint *pi;

	for (pi = phyint; pi != NULL; pi = pi->pi_next) {
		if (strcmp(pi->pi_name, name) == 0)
			return (pi);
	}
	return (NULL);
}

/* Assumes that the entry does not exist - caller must use find_* */
static struct phyint *
add_phyint(char *name)
{
	struct phyint *pi;

	pi = malloc(sizeof (*pi));
	if (pi == NULL)
		return (NULL);
	bzero((char *)pi, sizeof (*pi));

	strncpy(pi->pi_name, name, sizeof (pi->pi_name));
	/* Link into list */
	pi->pi_next = phyint;
	pi->pi_prev = NULL;
	if (phyint != NULL)
		phyint->pi_prev = pi;
	phyint = pi;
	return (pi);
}

static void
free_phyint(struct phyint *pi)
{
	assert(pi->pi_logical_first == NULL);
	assert(pi->pi_logical_last == NULL);

	if (pi->pi_prev == NULL) {
		/* Delete first */
		assert(phyint == pi);
		phyint = pi->pi_next;
	} else {
		assert(pi->pi_prev->pi_next == pi);
		pi->pi_prev->pi_next = pi->pi_next;
	}
	if (pi->pi_next != NULL) {
		assert(pi->pi_next->pi_prev == pi);
		pi->pi_next->pi_prev = pi->pi_prev;
	}
	free(pi);
}

static struct logint *
find_logint(struct phyint *pi, char *name)
{
	struct logint *li;

	for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
		if (strcmp(li->li_name, name) == 0)
			return (li);
	}
	return (NULL);
}

/*
 * Assumes that the entry does not exist - caller must use find_*
 * Tail insertion.
 */
static struct logint *
add_logint(struct phyint *pi, char *name)
{
	struct logint *li;

	li = malloc(sizeof (*li));
	if (li == NULL)
		return (NULL);
	bzero((char *)li, sizeof (*li));

	strncpy(li->li_name, name, sizeof (li->li_name));
	/* Link into list */
	li->li_prev = pi->pi_logical_last;
	if (pi->pi_logical_last == NULL) {
		/* First one */
		assert(pi->pi_logical_first == NULL);
		pi->pi_logical_first = li;
	} else {
		pi->pi_logical_last->li_next = li;
	}
	li->li_next = NULL;
	li->li_physical = pi;
	pi->pi_logical_last = li;
	return (li);

}

static void
free_logint(struct logint *li)
{
	struct phyint *pi;

	pi = li->li_physical;
	if (li->li_prev == NULL) {
		/* Delete first */
		assert(pi->pi_logical_first == li);
		pi->pi_logical_first = li->li_next;
	} else {
		assert(li->li_prev->li_next == li);
		li->li_prev->li_next = li->li_next;
	}
	if (li->li_next == NULL) {
		/* Delete last */
		assert(pi->pi_logical_last == li);
		pi->pi_logical_last = li->li_prev;
	} else {
		assert(li->li_next->li_prev == li);
		li->li_next->li_prev = li->li_prev;
	}
	free(li);
}


/* Tell all the logical interfaces that they are going away */
static void
deleted_phyint(struct phyint *pi, int s,
    struct sockaddr_in *joinaddr)
{
	struct logint *li;

	if (debug)
		logdebug("Deleting physical interface %s\n", pi->pi_name);

	for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
		li->li_state |= ST_DELETED;
	}
	for (li = pi->pi_logical_first; li != NULL; li = li->li_next) {
		deleted_logint(li, NULL, s, joinaddr);
	}
}

/*
 * Join the multicast address if no other logical interface has done
 * so for this physical interface.
 */
static void
added_logint(struct logint *li, int s,
    struct sockaddr_in *joinaddr)
{
	if (debug)
		logdebug("Adding logical interface %s\n", li->li_name);

	if ((!(li->li_physical->pi_state & ST_JOINED)) &&
	    (!isbroadcast(joinaddr))) {
		struct ip_mreq mreq;

		mreq.imr_multiaddr = joinaddr->sin_addr;
		mreq.imr_interface = li->li_address;

		if (debug)
			logdebug("Joining MC on interface %s\n", li->li_name);

		if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    (char *)&mreq, sizeof (mreq)) < 0) {
			logperror("setsockopt (IP_ADD_MEMBERSHIP)");
		} else {
			li->li_physical->pi_state |= ST_JOINED;
			li->li_state |= ST_JOINED;
		}
	}
}

/*
 * Leave the multicast address if this logical interface joined it.
 * Look for a replacement logical interface for the same physical interface.
 * Remove any routes which are no longer reachable.
 *
 * If newli is non-NULL, then it is likely that the address of a logical
 * interface has changed.  In this case, the membership should be dropped using
 * the new address of the interface in question.
 *
 * XXX When a physical interface is being deleted by deleted_phyint(), this
 * routine will be called for each logical interface associated with the
 * physical one.  This should be made more efficient as there is no point in
 * searching for an alternate logical interface to add group membership to as
 * they all are marked ST_DELETED.
 */
static void
deleted_logint(struct logint *li, struct logint *newli, int s,
    struct sockaddr_in *joinaddr)
{
	struct phyint *pi;
	struct logint *oli;

	if (debug)
		logdebug("Deleting logical interface %s\n", li->li_name);

	assert(li->li_state & ST_DELETED);

	if (li->li_state & ST_JOINED) {
		struct ip_mreq mreq;

		pi = li->li_physical;
		assert(pi->pi_state & ST_JOINED);
		assert(!isbroadcast(joinaddr));

		mreq.imr_multiaddr = joinaddr->sin_addr;
		if (newli != NULL)
			mreq.imr_interface = newli->li_address;
		else
			mreq.imr_interface = li->li_address;

		if (debug)
			logdebug("Leaving MC on interface %s\n", li->li_name);

		if (setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		    (char *)&mreq, sizeof (mreq)) < 0) {
			/*
			 * EADDRNOTAVAIL will be returned if the interface has
			 * been unplumbed or if the interface no longer has
			 * IFF_MULTICAST set.  The former is the common case
			 * while the latter is rare so don't log the error
			 * unless some other error was returned or if debug is
			 * set.
			 */
			if (errno != EADDRNOTAVAIL) {
				logperror("setsockopt (IP_DROP_MEMBERSHIP)");
			} else if (debug) {
				logdebug("%s: %s\n",
				    "setsockopt (IP_DROP_MEMBERSHIP)",
				    strerror(errno));
			}
		}
		li->li_physical->pi_state &= ~ST_JOINED;
		li->li_state &= ~ST_JOINED;

		/* Is there another interface that can join? */
		for (oli = pi->pi_logical_first; oli != NULL;
		    oli = oli->li_next) {
			if (oli->li_state & ST_DELETED)
				continue;

			mreq.imr_multiaddr = joinaddr->sin_addr;
			mreq.imr_interface = oli->li_address;

			if (debug)
				logdebug("Joining MC on interface %s\n",
				    oli->li_name);

			if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				(char *)&mreq, sizeof (mreq)) < 0) {
				logperror("setsockopt (IP_ADD_MEMBERSHIP)");
			} else {
				pi->pi_state |= ST_JOINED;
				oli->li_state |= ST_JOINED;
				break;
			}
		}
	}

	flush_unreachable_routers();
}



/*
 * TABLES
 */
struct table {
	struct in_addr	router;
	int		preference;
	int		remaining_time;
	int		in_kernel;
	struct table	*next;
};

struct table *table;

static void
report_routes(void)
{
	struct table *tp;

	logdebug("\nRoutes:\n\n");
	tp = table;
	while (tp) {
		logdebug("Router %s, pref 0x%x, time %d, %s kernel\n",
		    pr_name(tp->router), tp->preference,
		    tp->remaining_time,
		    (tp->in_kernel ? "in" : "not in"));
		tp = tp->next;
	}
}

static struct table *
find_router(struct in_addr addr)
{
	struct table *tp;

	tp = table;
	while (tp) {
		if (tp->router.s_addr == addr.s_addr)
			return (tp);
		tp = tp->next;
	}
	return (NULL);
}

static int
max_preference(void)
{
	struct table *tp;
	int max = (int)IGNORE_PREFERENCE;

	tp = table;
	while (tp) {
		if (tp->preference > max)
			max = tp->preference;
		tp = tp->next;
	}
	return (max);
}


/* Note: this might leave the kernel with no default route for a short time. */
static void
age_table(int time)
{
	struct table **tpp, *tp;
	int recalculate_max = 0;
	int max = max_preference();

	tpp = &table;
	while (*tpp != NULL) {
		tp = *tpp;
		tp->remaining_time -= time;
		if (tp->remaining_time <= 0) {
			*tpp = tp->next;
			if (debug) {
				logdebug("Timed out router %s\n",
				    pr_name(tp->router));
			}
			if (tp->in_kernel)
				del_route(tp->router);
			if (best_preference &&
			    tp->preference == max)
				recalculate_max++;
			free((char *)tp);
		} else {
			tpp = &tp->next;
		}
	}
	if (recalculate_max) {
		int max = max_preference();

		if (max != IGNORE_PREFERENCE) {
			tp = table;
			while (tp) {
				if (tp->preference == max && !tp->in_kernel) {
					add_route(tp->router);
					tp->in_kernel++;
				}
				tp = tp->next;
			}
		}
	}
}

/*
 * Remove any routes which are no longer directly connected.
 */
static void
flush_unreachable_routers(void)
{
	struct table **tpp, *tp;
	int recalculate_max = 0;
	int max = max_preference();

	tpp = &table;
	while (*tpp != NULL) {
		tp = *tpp;
		if (find_directly_connected_logint(tp->router, NULL) == NULL) {
			*tpp = tp->next;
			if (debug) {
				logdebug("Unreachable router %s\n",
				    pr_name(tp->router));
			}
			if (tp->in_kernel)
				del_route(tp->router);
			if (best_preference &&
			    tp->preference == max)
				recalculate_max++;
			free((char *)tp);
		} else {
			tpp = &tp->next;
		}
	}
	if (recalculate_max) {
		int max = max_preference();

		if (max != IGNORE_PREFERENCE) {
			tp = table;
			while (tp) {
				if (tp->preference == max && !tp->in_kernel) {
					add_route(tp->router);
					tp->in_kernel++;
				}
				tp = tp->next;
			}
		}
	}
}

static void
record_router(struct in_addr router, long preference, int ttl)
{
	struct table *tp;
	int old_max = max_preference();
	int changed_up = 0;	/* max preference could have increased */
	int changed_down = 0;	/* max preference could have decreased */

	if (debug)
		logdebug("Recording %s, preference 0x%x\n",
			pr_name(router),
			preference);
	tp = find_router(router);
	if (tp) {
		if (tp->preference > preference &&
		    tp->preference == old_max)
			changed_down++;
		else if (preference > tp->preference)
			changed_up++;
		tp->preference = preference;
		tp->remaining_time = ttl;
	} else {
		if (preference > old_max)
			changed_up++;
		tp = (struct table *)ALIGN(malloc(sizeof (struct table)));
		if (tp == NULL) {
			logerr("Out of memory\n");
			return;
		}
		tp->router = router;
		tp->preference = preference;
		tp->remaining_time = ttl;
		tp->in_kernel = 0;
		tp->next = table;
		table = tp;
	}
	if (!tp->in_kernel &&
	    (!best_preference || tp->preference == max_preference()) &&
	    tp->preference != IGNORE_PREFERENCE) {
		add_route(tp->router);
		tp->in_kernel++;
	}
	if (tp->preference == IGNORE_PREFERENCE && tp->in_kernel) {
		del_route(tp->router);
		tp->in_kernel = 0;
	}
	if (best_preference && changed_down) {
		/* Check if we should add routes */
		int new_max = max_preference();
		if (new_max != IGNORE_PREFERENCE) {
			tp = table;
			while (tp) {
				if (tp->preference == new_max &&
				    !tp->in_kernel) {
					add_route(tp->router);
					tp->in_kernel++;
				}
				tp = tp->next;
			}
		}
	}
	if (best_preference && (changed_up || changed_down)) {
		/* Check if we should remove routes already in the kernel */
		int new_max = max_preference();
		tp = table;
		while (tp) {
			if (tp->preference < new_max && tp->in_kernel) {
				del_route(tp->router);
				tp->in_kernel = 0;
			}
			tp = tp->next;
		}
	}
}


#include <net/route.h>

static void
add_route(struct in_addr addr)
{
	if (debug)
		logdebug("Add default route to %s\n", pr_name(addr));
	rtioctl(addr, SIOCADDRT);
}

static void
del_route(struct in_addr addr)
{
	if (debug)
		logdebug("Delete default route to %s\n", pr_name(addr));
	rtioctl(addr, SIOCDELRT);
}

static void
rtioctl(struct in_addr addr, int op)
{
	int sock;
	struct rtentry rt;
	struct sockaddr_in *sin;
	bzero((char *)&rt, sizeof (struct rtentry));
	rt.rt_dst.sa_family = AF_INET;
	rt.rt_gateway.sa_family = AF_INET;
	sin = (struct sockaddr_in *)ALIGN(&rt.rt_gateway);
	sin->sin_addr = addr;
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		logperror("rtioctl: socket");
		return;
	}
	if (ioctl(sock, op, (char *)&rt) < 0) {
		if (!(op == SIOCADDRT && errno == EEXIST))
			logperror("ioctl (add/delete route)");
	}
	(void) close(sock);
}



/*
 * LOGGER
 */

#include <syslog.h>

static int logging = 0;

static void
initlog(void)
{
	logging++;
	openlog("in.rdisc", LOG_PID | LOG_CONS, LOG_DAEMON);
}

static void
logimpl(int pri, char *fmt, va_list ap)
{
	FILE *log;

	if (pri == LOG_ERR)
		log = stderr;
	else
		log = stdout;

	if (logging)
		vsyslog(pri, fmt, ap);
	else
		(void) vfprintf(log, fmt, ap);
}

static void
logerr(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logimpl(LOG_ERR, fmt, ap);
	va_end(ap);
}

static void
logtrace(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logimpl(LOG_INFO, fmt, ap);
	va_end(ap);
}

static void
logdebug(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logimpl(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

static void
logperror(char *str)
{
	if (logging)
		syslog(LOG_ERR, "%s: %s\n", str, strerror(errno));
	else
		(void) fprintf(stderr, "%s: %s\n", str, strerror(errno));
}

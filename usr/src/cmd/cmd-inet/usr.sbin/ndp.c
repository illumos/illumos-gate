/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * ndp - display and manipulate Neighbor Cache Entries from NDP
 */

#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <wait.h>
#include <sys/mac.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netdb.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inet/ip.h>
#include <net/if_dl.h>
#include <net/route.h>

typedef	struct	sockaddr_in6	sin6_t;

#define	BUF_SIZE 2048
typedef struct rtmsg_pkt {
	struct	rt_msghdr m_rtm;
	char	m_space[BUF_SIZE];
} rtmsg_pkt_t;

enum ndp_action {
	NDP_A_DEFAULT,
	NDP_A_GET,		/* Show a single NDP entry */
	NDP_A_GET_ALL,		/* Show NDP entries */
	NDP_A_GET_FOREVER,	/* Repeatedly show entries */
	NDP_A_DELETE,		/* Delete an NDP entry */
	NDP_A_SET_NCE,		/* Set NDP entry */
	NDP_A_SET_FILE		/* Read in & set NDP entries */
};

typedef	int	(ndp_addr_f)(int, struct lifreq *, void *);
typedef	void	(ndp_void_f)(void);

static	void	ndp_usage(const char *, ...);
static	void	ndp_fatal(const char *, ...);
static	void	ndp_badflag(enum ndp_action);
static	void	ndp_missingarg(char);

static	void	ndp_run_in_child(ndp_void_f *);
static	void	ndp_do_run(void);
static	void	ndp_setup_handler(sigset_t *);
static	void	ndp_start_timer(time_t period);
static	void	ndp_run_periodically(time_t, ndp_void_f *);

static	int	ndp_salen(const struct sockaddr *sa);
static	int	ndp_extract_sockaddrs(struct rt_msghdr *, struct sockaddr **,
		    struct sockaddr **, struct sockaddr **, struct sockaddr **,
		    struct sockaddr_dl **);
static	int	ndp_rtmsg_get(int, rtmsg_pkt_t *, struct sockaddr *);
static	int	ndp_find_interface(int, struct sockaddr *, char *, int);

static	int	ndp_initialize_lifreq(int, struct lifreq *, struct sockaddr *);
static	int	ndp_host_enumerate(char *, ndp_addr_f *, void *);

static	int	ndp_display(struct lifreq *);
static	int	ndp_display_missing(struct lifreq *);
static	void	ndp_lifr2ip(struct lifreq *, char *, int);

static	int	ndp_get(int, struct lifreq *, void *);
static	void	ndp_get_all(void);
static	int	ndp_delete(int, struct lifreq *, void *);
static	int	ndp_set(int, struct lifreq *, void *);
static	int	ndp_set_nce(char *, char *, char *[], int);
static	int	ndp_set_file(char *);

static	char		*ndp_iface = NULL;
static	char		*netstat_path = "/usr/bin/netstat";
static	pid_t		ndp_pid;
static	boolean_t	ndp_noresolve = B_FALSE; /* Don't lookup addresses */
static	boolean_t	ndp_run = B_TRUE;

#define	MAX_ATTEMPTS 5
#define	MAX_OPTS 5
#define	WORDSEPS " \t\r\n"

/*
 * Macros borrowed from route(1M) for working with PF_ROUTE messages
 */
#define	RT_ADVANCE(x, n) ((x) += ndp_salen(n))
#define	RT_NEXTADDR(cp, w, u) \
	l = ndp_salen(u); \
	(void) memmove(cp, u, l); \
	cp += l;

/*
 * Print an error to stderr and then exit non-zero.
 */
static void
ndp_fatal(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vwarnx(format, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

/*
 * Print out the command usage to stderr, along with any reason why it's being
 * printed, and then exit non-zero.
 */
static void
ndp_usage(const char *reason, ...)
{
	va_list ap;
	const char *ndp_progname = getprogname();

	if (reason != NULL) {
		va_start(ap, reason);
		(void) fprintf(stderr, "%s: ", ndp_progname);
		(void) vfprintf(stderr, reason, ap);
		(void) fprintf(stderr, "\n");
		va_end(ap);
	}

	(void) fprintf(stderr,
	    "Usage: %s [-n] [-i iface] hostname\n"
	    "       %s [-n] [-i iface] -s nodeaddr etheraddr [temp] [proxy]\n"
	    "       %s [-n] [-i iface] -d nodeaddr\n"
	    "       %s [-n] [-i iface] -f filename\n"
	    "       %s [-n] -a\n"
	    "       %s [-n] -A period\n",
	    ndp_progname, ndp_progname, ndp_progname,
	    ndp_progname, ndp_progname, ndp_progname);
	exit(EXIT_FAILURE);
}

static void
ndp_badflag(enum ndp_action action)
{
	switch (action) {
	case NDP_A_DEFAULT:
	case NDP_A_GET:
		ndp_usage("Already going to print an entry, "
		    "but extra -%c given", optopt);
		break;
	case NDP_A_GET_ALL:
		ndp_usage("Already going to print all entries (-a), "
		    "but extra -%c given", optopt);
		break;
	case NDP_A_GET_FOREVER:
		ndp_usage("Already going to repeatedly print all entries (-A), "
		    "but extra -%c given", optopt);
		break;
	case NDP_A_DELETE:
		ndp_usage("Already going to delete an entry (-d), "
		    "but extra -%c given", optopt);
		break;
	case NDP_A_SET_NCE:
		ndp_usage("Already going to set an entry (-s), "
		    "but extra -%c given", optopt);
		break;
	case NDP_A_SET_FILE:
		ndp_usage("Already going to set from file (-f), "
		    "but extra -%c given", optopt);
		break;
	}
}

static void
ndp_missingarg(char flag)
{
	switch (flag) {
	case 'A':
		ndp_usage("Missing time period after -%c", flag);
		break;
	case 'd':
		ndp_usage("Missing node name after -%c", flag);
		break;
	case 'f':
		ndp_usage("Missing filename after -%c", flag);
		break;
	case 's':
		ndp_usage("Missing node name after -%c", flag);
		break;
	case 'i':
		ndp_usage("Missing interface name after -%c", flag);
		break;
	default:
		ndp_usage("Missing option argument after -%c", flag);
		break;
	}
}

/*
 * Run a function that's going to exec in a child process, and don't return
 * until it exits.
 */
static void
ndp_run_in_child(ndp_void_f *func)
{
	pid_t child_pid;
	int childstat = 0, status = 0;

	child_pid = fork();
	if (child_pid == (pid_t)-1) {
		ndp_fatal("Unable to fork: %s", strerror(errno));
	} else if (child_pid == (pid_t)0) {
		func();
		exit(EXIT_FAILURE);
	}

	while (waitpid(child_pid, &childstat, 0) == -1) {
		if (errno == EINTR)
			continue;

		ndp_fatal("Failed to wait on child: %s", strerror(errno));
	}

	status = WEXITSTATUS(childstat);
	if (status != 0) {
		ndp_fatal("Child process exited with %d", status);
	}
}

/*
 * SIGALRM handler to schedule a run.
 */
static void
ndp_do_run(void)
{
	ndp_run = B_TRUE;
}


/*
 * Prepare signal masks, and install the SIGALRM handler. Return old signal
 * masks through the first argument.
 */
static void
ndp_setup_handler(sigset_t *oset)
{
	struct sigaction sa;

	/*
	 * Mask off SIGALRM so we only trigger the handler when we're ready
	 * using sigsuspend(3C), in case the child process takes longer to
	 * run than the alarm interval.
	 */
	if (sigprocmask(0, NULL, oset) != 0) {
		ndp_fatal("Unable to set signal mask: %s", strerror(errno));
	}

	if (sighold(SIGALRM) != 0) {
		ndp_fatal("Unable to add SIGALRM to signal mask: %s",
		    strerror(errno));
	}

	sa.sa_flags = 0;
	sa.sa_handler = ndp_do_run;

	if (sigemptyset(&sa.sa_mask) != 0) {
		ndp_fatal("Unable to prepare empty signal set: %s",
		    strerror(errno));
	}

	if (sigaction(SIGALRM, &sa, NULL) != 0) {
		ndp_fatal("Unable to install timer handler: %s",
		    strerror(errno));
	}
}

/*
 * Start the printing timer.
 */
static void
ndp_start_timer(time_t period)
{
	timer_t timer;
	struct itimerspec interval;
	interval.it_value.tv_sec  = interval.it_interval.tv_sec  = period;
	interval.it_value.tv_nsec = interval.it_interval.tv_nsec = 0;

	if (timer_create(CLOCK_REALTIME, NULL, &timer) != 0) {
		ndp_fatal("Unable to create timer: %s", strerror(errno));
	}

	if (timer_settime(timer, 0, &interval, NULL) != 0) {
		ndp_fatal("Unable to set time on timer: %s", strerror(errno));
	}
}


/*
 * Run a given function forever periodically in a child process.
 */
static void
ndp_run_periodically(time_t period, ndp_void_f *func)
{
	sigset_t oset;

	ndp_setup_handler(&oset);
	ndp_start_timer(period);

	do {
		if (ndp_run) {
			ndp_run = B_FALSE;
			ndp_run_in_child(func);
		}
		(void) sigsuspend(&oset);
	} while (errno == EINTR);

	/*
	 * Only an EFAULT should get us here. Abort so we get a core dump.
	 */
	warnx("Failure while waiting on timer: %s", strerror(errno));
	abort();
}

/*
 * Given an address, return its size.
 */
static int
ndp_salen(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (sizeof (struct sockaddr_in));
	case AF_LINK:
		return (sizeof (struct sockaddr_dl));
	case AF_INET6:
		return (sizeof (struct sockaddr_in6));
	default:
		warnx("Unrecognized sockaddr with address family %d!",
		    sa->sa_family);
		abort();
	}
	/*NOTREACHED*/
}

/*
 * Extract all socket addresses from a routing message, and return them
 * through the pointers given as arguments to ndp_extract_sockaddrs. None
 * of the pointers should be null.
 */
static int
ndp_extract_sockaddrs(struct rt_msghdr *rtm, struct sockaddr **dst,
    struct sockaddr **gate, struct sockaddr **mask, struct sockaddr **src,
    struct sockaddr_dl **ifp)
{
	struct sockaddr *sa;
	char *cp;
	int i;

	if (rtm->rtm_version != RTM_VERSION) {
		warnx("Routing message version %d not understood",
		    rtm->rtm_version);
		return (-1);
	}

	if (rtm->rtm_errno != 0)  {
		warnx("Routing message couldn't be processed: %s",
		    strerror(rtm->rtm_errno));
		return (-1);
	}

	cp = ((char *)(rtm + 1));
	if (rtm->rtm_addrs != 0) {
		for (i = 1; i != 0; i <<= 1) {
			if ((i & rtm->rtm_addrs) == 0)
				continue;

			/*LINTED*/
			sa = (struct sockaddr *)cp;
			switch (i) {
			case RTA_DST:
				*dst = sa;
				break;
			case RTA_GATEWAY:
				*gate = sa;
				break;
			case RTA_NETMASK:
				*mask = sa;
				break;
			case RTA_IFP:
				if (sa->sa_family == AF_LINK &&
				    ((struct sockaddr_dl *)sa)->sdl_nlen != 0)
					*ifp = (struct sockaddr_dl *)sa;
				break;
			case RTA_SRC:
				*src = sa;
				break;
			}
			RT_ADVANCE(cp, sa);
		}
	}

	return (0);
}

/*
 * Given an IPv6 address, use routing information to look up
 * the destination and interface it would pass through.
 */
static int
ndp_rtmsg_get(int fd, rtmsg_pkt_t *msg, struct sockaddr *sin6p)
{
	static int seq = 0;
	struct sockaddr_dl sdl;
	int mlen, l;
	char ipaddr[INET6_ADDRSTRLEN];
	char *cp = msg->m_space;
	struct	rt_msghdr *m_rtm = &msg->m_rtm;

	bzero(msg, sizeof (rtmsg_pkt_t));
	bzero(&sdl, sizeof (struct sockaddr_dl));

	m_rtm->rtm_type = RTM_GET;
	m_rtm->rtm_version = RTM_VERSION;
	m_rtm->rtm_seq = ++seq;
	m_rtm->rtm_addrs = RTA_DST | RTA_IFP;
	m_rtm->rtm_msglen = sizeof (rtmsg_pkt_t);

	/* Place the address we're looking up after the header */
	RT_NEXTADDR(cp, RTA_DST, sin6p);

	/* Load an empty link-level address, so we get an interface back */
	sdl.sdl_family = AF_LINK;
	RT_NEXTADDR(cp, RTA_IFP, (struct sockaddr *)&sdl);

	m_rtm->rtm_msglen = cp - (char *)msg;

	if ((mlen = write(fd, (char *)msg, m_rtm->rtm_msglen)) < 0) {
		if (errno == ESRCH) {
			/*LINTED*/
			if (inet_ntop(AF_INET6, &((sin6_t *)sin6p)->sin6_addr,
			    ipaddr, sizeof (ipaddr)) == NULL) {
				(void) snprintf(ipaddr, sizeof (ipaddr),
				    "(failed to format IP)");
			};
			warnx("An appropriate interface for the address %s "
			    "is not in the routing table; use -i to force an "
			    "interface", ipaddr);
			return (-1);
		} else {
			warnx("Failed to send routing message: %s",
			    strerror(errno));
			return (-1);
		}
	} else if (mlen < (int)m_rtm->rtm_msglen) {
		warnx("Failed to write all bytes to routing socket");
		return (-1);
	}

	/*
	 * Keep reading routing messages until we find the response to the one
	 * we just sent. Note that we depend on the sequence number being unique
	 * to the running program.
	 */
	do {
		mlen = read(fd, (char *)msg, sizeof (rtmsg_pkt_t));
	} while (mlen > 0 &&
	    (m_rtm->rtm_seq != seq || m_rtm->rtm_pid != ndp_pid));
	if (mlen < 0) {
		warnx("Failed to read from routing socket: %s",
		    strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Find the interface that the IPv6 address would be routed through, and store
 * the name of the interface in the buffer passed in.
 */
static int
ndp_find_interface(int fd, struct sockaddr *sin6p, char *buf, int buflen)
{
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL, *src = NULL;
	struct sockaddr_dl *ifp = NULL;
	rtmsg_pkt_t msg;

	if (ndp_rtmsg_get(fd, &msg, sin6p) != 0) {
		return (-1);
	}

	if (ndp_extract_sockaddrs(&msg.m_rtm, &dst, &gate,
	    &mask, &src, &ifp) != 0) {
		return (-1);
	}

	if (ifp == NULL) {
		warnx("Unable to find appropriate interface for address");
		return (-1);
	} else {
		if (ifp->sdl_nlen >= buflen) {
			warnx("The interface name \"%.*s\" is too big for the "
			    "available buffer", ifp->sdl_nlen, ifp->sdl_data);
			return (-1);
		} else {
			(void) snprintf(buf, buflen, "%.*s", ifp->sdl_nlen,
			    ifp->sdl_data);
		}
	}

	return (0);
}

/*
 * Zero out a lifreq struct for a SIOCLIF*ND ioctl, set the address, and fetch
 * the appropriate interface using the given routing socket.
 */
static int
ndp_initialize_lifreq(int route, struct lifreq *lifrp, struct sockaddr *sap)
{
	struct sockaddr_storage *lnr_addr;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct sockaddr_in6 *sin6p = (sin6_t *)sap;
	char *lifr_name = lifrp->lifr_name;

	bzero(lifrp, sizeof (struct lifreq));
	lnr_addr = &lifrp->lifr_nd.lnr_addr;

	if (ndp_iface != NULL) {
		(void) strlcpy(lifr_name, ndp_iface, LIFNAMSIZ);
	} else if (sin6p->sin6_scope_id != 0) {
		int zone_id = sin6p->sin6_scope_id;
		if (if_indextoname(zone_id, lifr_name) == NULL) {
			warnx("Invalid zone identifier: %d", zone_id);
			return (-1);
		}
	} else if (IN6_IS_ADDR_LINKSCOPE(&sin6p->sin6_addr)) {
		warnx("Link-scope addresses should specify an interface with "
		    "a zone ID, or with -i.");
		return (-1);
	} else {
		if (ndp_find_interface(route, sap, lifr_name, LIFNAMSIZ) != 0)
			return (-1);
	}

	(void) memcpy(lnr_addr, sap, sizeof (struct sockaddr_storage));

	return (0);
}

/*
 * Take a host identifier, find the corresponding IPv6 addresses and then pass
 * them to the specified function, along with any desired data.
 */
static int
ndp_host_enumerate(char *host, ndp_addr_f *addr_func, void *data)
{
	struct lifreq lifr;
	struct addrinfo hints, *serverinfo, *p;
	int err, attempts = 0;
	int inet6, route;

	bzero(&hints, sizeof (struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_protocol = IPPROTO_IPV6;

	while (attempts < MAX_ATTEMPTS) {
		err = getaddrinfo(host, NULL, &hints, &serverinfo);

		if (err == 0) {
			break;
		} else if (err == EAI_AGAIN) {
			attempts++;
		} else {
			warnx("Unable to lookup %s: %s", host,
			    gai_strerror(err));
			return (-1);
		}
	}

	if (attempts == MAX_ATTEMPTS) {
		warnx("Failed multiple times to lookup %s", host);
		return (-1);
	}

	inet6 = socket(PF_INET6, SOCK_DGRAM, 0);
	if (inet6 < 0) {
		warnx("Failed to open IPv6 socket: %s", strerror(errno));
		err = -1;
	}

	route = socket(PF_ROUTE, SOCK_RAW, 0);
	if (route < 0) {
		warnx("Failed to open routing socket: %s", strerror(errno));
		err = -1;
	}

	if (err == 0) {
		for (p = serverinfo; p != NULL; p = p->ai_next) {
			if (ndp_initialize_lifreq(route, &lifr, p->ai_addr)
			    != 0) {
				err = -1;
				continue;
			}

			if (addr_func(inet6, &lifr, data) != 0) {
				err = -1;
				continue;
			}
		}
	}

	if (close(route) != 0) {
		warnx("Failed to close routing socket: %s", strerror(errno));
		err = -1;
	}

	if (close(inet6) != 0) {
		warnx("Failed to close IPv6 socket: %s", strerror(errno));
		err = -1;
	}

	/* Clean up linked list */
	freeaddrinfo(serverinfo);

	return (err);
}

static int
ndp_display(struct lifreq *lifrp)
{
	struct sockaddr_in6 *lnr_addr;
	char ipaddr[INET6_ADDRSTRLEN];
	char *lladdr = NULL;
	char hostname[NI_MAXHOST];
	int flags, gni_flags;

	lnr_addr = (struct sockaddr_in6 *)&lifrp->lifr_nd.lnr_addr;
	flags = lifrp->lifr_nd.lnr_flags;

	if (inet_ntop(AF_INET6, &lnr_addr->sin6_addr, ipaddr,
	    sizeof (ipaddr)) == NULL) {
		warnx("Couldn't convert IPv6 address to string: %s",
		    strerror(errno));
		return (-1);
	};

	if ((lladdr = _link_ntoa((uchar_t *)lifrp->lifr_nd.lnr_hdw_addr,
	    NULL, lifrp->lifr_nd.lnr_hdw_len, IFT_ETHER)) == NULL) {
		warnx("Couldn't convert link-layer address to string: %s",
		    strerror(errno));
		return (-1);
	}

	gni_flags = ndp_noresolve ? NI_NUMERICHOST : 0;

	if (getnameinfo((struct sockaddr *)lnr_addr, sizeof (sin6_t), hostname,
	    sizeof (hostname), NULL, 0, gni_flags) != 0) {
		warnx("Unable to lookup hostname for %s", ipaddr);
		free(lladdr);
		return (-1);
	}

	(void) printf("%s (%s) at %s", ipaddr, hostname, lladdr);

	if (flags & NDF_ISROUTER_ON) {
		(void) printf(" router");
	}

	if (flags & NDF_ANYCAST_ON) {
		(void) printf(" any");
	}

	if (!(flags & NDF_STATIC)) {
		(void) printf(" temp");
	}

	if (flags & NDF_PROXY_ON) {
		(void) printf(" proxy");
	}

	(void) printf("\n");

	free(lladdr);
	return (0);
}

static int
ndp_display_missing(struct lifreq *lifrp)
{
	struct sockaddr_in6 *lnr_addr;
	char ipaddr[INET6_ADDRSTRLEN];
	char hostname[NI_MAXHOST];
	int flags = ndp_noresolve ? NI_NUMERICHOST : 0;
	lnr_addr = (struct sockaddr_in6 *)&lifrp->lifr_nd.lnr_addr;

	if (inet_ntop(AF_INET6, &lnr_addr->sin6_addr, ipaddr,
	    sizeof (ipaddr)) == NULL) {
		warnx("Couldn't convert IPv6 address to string: %s",
		    strerror(errno));
		return (-1);
	};

	if (getnameinfo((struct sockaddr *)lnr_addr, sizeof (sin6_t), hostname,
	    sizeof (hostname), NULL, 0, flags) != 0) {
		warnx("Unable to lookup hostname for %s", ipaddr);
		return (-1);
	}

	(void) printf("%s (%s) -- no entry\n", ipaddr, hostname);
	return (0);
}

static void
ndp_lifr2ip(struct lifreq *lifrp, char *ipaddr, int buflen)
{
	sin6_t *lnr_addr = (sin6_t *)&lifrp->lifr_nd.lnr_addr;
	if (inet_ntop(AF_INET6, &lnr_addr->sin6_addr, ipaddr,
	    buflen) == NULL) {
		(void) snprintf(ipaddr, buflen, "(failed to format IP)");
	};
}

/*
 * Perform a SIOCLIFGETND and print out information about it
 */
/*ARGSUSED*/
static int
ndp_get(int fd, struct lifreq *lifrp, void *unused)
{
	char ipaddr[INET6_ADDRSTRLEN];
	if (ioctl(fd, SIOCLIFGETND, lifrp) < 0) {
		if (errno == ESRCH) {
			return (ndp_display_missing(lifrp));
		} else {
			ndp_lifr2ip(lifrp, ipaddr, sizeof (ipaddr));
			warnx("Couldn't lookup %s: %s",
			    ipaddr, strerror(errno));
			return (-1);
		}
	}

	return (ndp_display(lifrp));
}

/*
 * Print out all NDP entries
 */
static void
ndp_get_all(void)
{
	(void) execl(netstat_path, "netstat",
	    (ndp_noresolve ? "-np" : "-p"),
	    "-f", "inet6", (char *)0);
	ndp_fatal("Coudn't exec %s: %s", netstat_path, strerror(errno));
}

/*
 * Perform a SIOCLIFDELND ioctl
 */
/*ARGSUSED*/
static int
ndp_delete(int fd, struct lifreq *lifrp, void *unused)
{
	char ipaddr[INET6_ADDRSTRLEN];

	if (ioctl(fd, SIOCLIFDELND, lifrp) < 0) {
		ndp_lifr2ip(lifrp, ipaddr, sizeof (ipaddr));
		if (errno == ESRCH) {
			warnx("No entry for %s", ipaddr);
			return (-1);
		} else if (errno == EPERM) {
			warnx("Permission denied, "
			    "could not delete entry for %s", ipaddr);
			return (-1);
		} else {
			warnx("Couldn't delete mapping for %s: %s",
			    ipaddr, strerror(errno));
			return (-1);
		}
	}

	return (0);
}

/*
 * Perform a SIOCLIFSETND ioctl using properties from the example structure.
 */
static int
ndp_set(int fd, struct lifreq *lifrp, void *data)
{
	char ipaddr[INET6_ADDRSTRLEN];
	const lif_nd_req_t *nd_attrs = data;

	(void) memcpy(lifrp->lifr_nd.lnr_hdw_addr, nd_attrs->lnr_hdw_addr,
	    ND_MAX_HDW_LEN);
	lifrp->lifr_nd.lnr_hdw_len = nd_attrs->lnr_hdw_len;
	lifrp->lifr_nd.lnr_flags = nd_attrs->lnr_flags;

	lifrp->lifr_nd.lnr_state_create = nd_attrs->lnr_state_create;
	lifrp->lifr_nd.lnr_state_same_lla = nd_attrs->lnr_state_same_lla;
	lifrp->lifr_nd.lnr_state_diff_lla = nd_attrs->lnr_state_diff_lla;

	if (ioctl(fd, SIOCLIFSETND, lifrp) < 0) {
		ndp_lifr2ip(lifrp, ipaddr, sizeof (ipaddr));
		if (errno == EPERM) {
			warnx("Permission denied, "
			    "could not set entry for %s", ipaddr);
			return (-1);
		} else {
			warnx("Failed to set mapping for %s: %s",
			    ipaddr, strerror(errno));
			return (-1);
		}
	}

	return (0);
}

/*
 * Given a host identifier, a link-layer address and possible options,
 * add/update the NDP mappings.
 */
static int
ndp_set_nce(char *host, char *lladdr, char *opts[], int optlen)
{
	lif_nd_req_t nd_attrs;
	uchar_t *ea;
	char *opt;
	int i;
	boolean_t temp = B_FALSE;
	boolean_t any = B_FALSE;
	boolean_t router = B_FALSE;

	bzero(&nd_attrs, sizeof (lif_nd_req_t));

	ea = _link_aton(lladdr, &nd_attrs.lnr_hdw_len);

	if (ea == NULL) {
		warnx("Unable to parse link-layer address \"%s\"", lladdr);
		return (-1);
	}

	if (nd_attrs.lnr_hdw_len > sizeof (nd_attrs.lnr_hdw_addr)) {
		warnx("The size of the link-layer address is "
		    "too large to set\n");
		free(ea);
		return (-1);
	}

	(void) memcpy(nd_attrs.lnr_hdw_addr, ea, nd_attrs.lnr_hdw_len);

	free(ea);

	nd_attrs.lnr_state_create = ND_REACHABLE;
	nd_attrs.lnr_state_same_lla = ND_UNCHANGED;
	nd_attrs.lnr_state_diff_lla = ND_STALE;

	for (i = 0; i < optlen; i++) {
		opt = opts[i];
		if (strcmp(opt, "temp") == 0) {
			temp = B_TRUE;
		} else if (strcmp(opt, "any") == 0) {
			any = B_TRUE;
		} else if (strcmp(opt, "router") == 0) {
			router = B_TRUE;
		} else if (strcmp(opt, "proxy") == 0) {
			warnx("NDP proxying is currently not supported");
			return (-1);
		} else {
			warnx("Unrecognized option \"%s\"", opt);
			return (-1);
		}
	}

	if (!temp) {
		nd_attrs.lnr_flags |= NDF_STATIC;
	}

	if (any) {
		nd_attrs.lnr_flags |= NDF_ANYCAST_ON;
	} else {
		nd_attrs.lnr_flags |= NDF_ANYCAST_OFF;
	}

	if (router) {
		nd_attrs.lnr_flags |= NDF_ISROUTER_OFF;
	} else {
		nd_attrs.lnr_flags |= NDF_ISROUTER_OFF;
	}

	return (ndp_host_enumerate(host, ndp_set, &nd_attrs));
}

/*
 * Read in a file and set the mappings from each line.
 */
static int
ndp_set_file(char *filename)
{
	char *line = NULL, *lasts = NULL, *curr;
	char *host, *lladdr;
	char *opts[MAX_OPTS];
	int optlen = 0, lineno = 0;
	size_t cap = 0;
	boolean_t failed_line = B_FALSE;
	FILE *stream = fopen(filename, "r");

	if (stream == NULL) {
		ndp_fatal("Error while opening file %s: %s",
		    filename, strerror(errno));
	}

	errno = 0;
	while (getline(&line, &cap, stream) != -1) {
		lineno++;

		if (line[0] == '#')
			continue;

		host = strtok_r(line, WORDSEPS, &lasts);
		if (host == NULL) {
			warnx("Line %d incomplete, skipping: "
			    "missing host identifier", lineno);
			failed_line = B_TRUE;
			continue;
		}

		lladdr = strtok_r(NULL, WORDSEPS, &lasts);
		if (lladdr == NULL) {
			warnx("Line %d incomplete, skipping: "
			    "missing link-layer address", lineno);
			failed_line = B_TRUE;
			continue;
		}

		for (optlen = 0; optlen < MAX_OPTS; optlen++) {
			curr = strtok_r(NULL, WORDSEPS, &lasts);
			if (curr == NULL)
				break;
			opts[optlen] = curr;
		}

		if (ndp_set_nce(host, lladdr, opts, optlen) != 0) {
			failed_line = B_TRUE;
			continue;
		}
	}

	free(line);

	if (errno != 0 || ferror(stream)) {
		ndp_fatal("Error while reading from file %s: %s", filename,
		    strerror(errno));
	}

	if (fclose(stream) != 0) {
		ndp_fatal("Error close file %s: %s", filename, strerror(errno));
	}

	return (failed_line ? -1 : 0);
}

int
main(int argc, char *argv[])
{
	char *flagarg = NULL, *lladdr = NULL;
	char **opts;
	char *endptr;
	int c, argsleft, optlen = 0, err = 0;
	long long period;
	enum ndp_action action = NDP_A_DEFAULT;

	setprogname(basename(argv[0]));

	if (argc < 2) {
		ndp_usage("No arguments given.");
	}

	while ((c = getopt(argc, argv, ":naA:d:f:i:s:")) != -1) {
		switch (c) {
		case 'n':
			ndp_noresolve = B_TRUE;
			break;
		case 'i':
			ndp_iface = optarg;
			break;
		case 's':
			if (action != NDP_A_DEFAULT)
				ndp_badflag(action);
			action = NDP_A_SET_NCE;
			flagarg = optarg;

			if ((argc - optind) < 1) {
				ndp_usage("Missing link-layer address after "
				    "the node address, \"%s\"", flagarg);
			}
			lladdr = argv[optind++];

			/*
			 * Grab any following keywords up to the next flag
			 */
			opts = argv + optind;
			while ((argc - optind) > 0) {
				if (argv[optind][0] == '-')
					ndp_usage("Encountered \"%s\" after "
					    "flag parsing is done",
					    argv[optind]);
				optind++;
				optlen++;
			}
			break;
		case 'a':
			if (action != NDP_A_DEFAULT)
				ndp_badflag(action);
			action = NDP_A_GET_ALL;
			break;
		case 'A':
			if (action != NDP_A_DEFAULT)
				ndp_badflag(action);
			action = NDP_A_GET_FOREVER;
			flagarg = optarg;
			break;
		case 'd':
			if (action != NDP_A_DEFAULT)
				ndp_badflag(action);
			action = NDP_A_DELETE;
			flagarg = optarg;
			break;
		case 'f':
			if (action != NDP_A_DEFAULT)
				ndp_badflag(action);
			action = NDP_A_SET_FILE;
			flagarg = optarg;
			break;
		case ':':
			ndp_missingarg(optopt);
			break;
		case '?':
			ndp_usage("Unrecognized flag \"-%c\"", optopt);
		default:
			ndp_usage(NULL);
		}
	}

	argsleft = argc - optind;
	ndp_pid = getpid();

	if (action != NDP_A_DEFAULT && argsleft != 0) {
		ndp_usage("Extra arguments leftover after parsing flags");
	}

	switch (action) {
	case NDP_A_DEFAULT:
	case NDP_A_GET:
		if (argsleft != 1) {
			ndp_usage("Multiple arguments given without any flags");
		}
		err = ndp_host_enumerate(argv[optind], ndp_get, NULL);
		break;
	case NDP_A_GET_ALL:
		ndp_get_all();
		/*NOTREACHED*/
		break;
	case NDP_A_GET_FOREVER:
		errno = 0;
		period = strtoll(flagarg, &endptr, 10);
		if ((period == 0 && errno != 0) ||
		    (endptr[0] != '\0') ||
		    (period < 0)) {
			ndp_usage("Given period should be a positive integer,"
			    " not \"%s\"", flagarg);
		}
		if (period > 86400) {
			ndp_usage("Given period should be shorter than a day;"
			    " given \"%s\" seconds", flagarg);
		}
		ndp_run_periodically(period, ndp_get_all);
		/*NOTREACHED*/
		break;
	case NDP_A_DELETE:
		err = ndp_host_enumerate(flagarg, ndp_delete, NULL);
		break;
	case NDP_A_SET_NCE:
		err = ndp_set_nce(flagarg, lladdr, opts, optlen);
		break;
	case NDP_A_SET_FILE:
		err = ndp_set_file(flagarg);
		break;
	}

	return (err == 0 ? 0 : 1);
}

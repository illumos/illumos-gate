/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/route.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <malloc.h>
#include <stropts.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include "pfild.h"

extern int vas(const struct pfil_ifaddrs *, int);

/*
 * pfild.c:  interface data and packet transmission daemon for pfil
 *
 * pfild provides the pfil kernel module with certain data that are not
 * directly available to kernel code using supported OS interfaces.  pfild
 * accesses the routing tables and network interface parameters using
 * interfaces readily available to a user space daemon, copies the data into
 * the kernel via /dev/pfil, and waits for any changes to the data.
 *
 * pfild also provides a way for the kernel module to originate IP packets
 * without resorting to unsupported kernel interfaces.  If the kernel
 * sends up an M_DATA message, pfild sends it on a raw IP socket so that it
 * gets routed and transmitted as a normal packet.
 */


/* file descriptors for talking to pfil, ifnet, routing kernel modules */
static int pfil_fd, ip_fd, ip6_fd, route_fd;

/*
 * flag indicates that some interface or routing data have changed since
 * last update.
 */
static int flag = 1;
/*
 * debuglevel indicates to what level debugging messages should be emitted.
 */
static int debuglevel = 0;

/* Wait for this many ms of quiet time after changes before doing an update. */
#define	QUIETTIME 200


/*
 * Send a message to the pfil kernel module.
 * Returns zero for success, otherwise non-zero with errror in errno.
 */
int
pfil_msg(uint32_t cmd, void *buf, size_t len)
{
	int error;

	if (debuglevel > 0)
		(void) fprintf(stderr, "pfil_msg(%x,%p,%d)\n", cmd, buf, len);

	if (pfil_fd >= 0) {
		struct strbuf ctl, data;

		ctl.buf = (void *)&cmd;
		ctl.len = sizeof (cmd);
		data.buf = buf;
		data.len = len;

		error = putmsg(pfil_fd, &ctl, &data, 0);
		if (debuglevel > 0)
			(void) fprintf(stderr,
			    "pfild:pfil_msg():putmsg(%d,%p,%p,0) = %d\n",
			    pfil_fd, &ctl, &data, 0, error);
	} else {
		error = 0;
		if (debuglevel > 0)
			(void) fprintf(stderr,
			    "pfild:pfil_msg():pfil_fd < 0\n");
	}

	return (error);
}


/*
 * Handle a PF_ROUTE message.  If an address has been added or deleted, treat
 * this as an indication that some interface data has been udpated.  If a route
 * has been added or deleted, treat this as an indication that the routing
 * table has been updated.  The current implementation completely updates both
 * sets of data when either kind of change is indicated.
 *
 * p points to, and size indicates the size of, the message.
 */
static void
handle_msg(const ifa_msghdr_t *p, size_t size)
{
	if (size < sizeof (*p) ||
	    size < p->ifam_msglen ||
	    p->ifam_version != RTM_VERSION) {
		if (debuglevel > 0)
			(void) fprintf(stderr,
			    "Not a valid version %u RTM message - "
			    "%u bytes version %u\n",
			    RTM_VERSION, size, p->ifam_version);
		return;
	}

	switch (p->ifam_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_ADD:
	case RTM_DELETE:
		flag = 1;
		break;
	default:
		break;
	}

	if (debuglevel > 0)
		(void) fprintf(stderr,
		    "pfild:handle_msg(): msg rcvd %d flag %d\n",
		    p->ifam_type, flag);
}


#include <arpa/inet.h>
static const char *
dumpaddr(void *p)
{
	static char buf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin = p;
	struct sockaddr_in6 *sin6 = p;
	switch (sin->sin_family) {
	case AF_INET:
		return (inet_ntop(sin->sin_family, &sin->sin_addr, buf,
		    sizeof (buf)));
	case AF_INET6:
		return (inet_ntop(sin6->sin6_family, &sin6->sin6_addr, buf,
		    sizeof (buf)));
	default:
		return ("<none>");
	}
}


#define	ERRBUFSIZE 100
static char errbuf[ERRBUFSIZE];

#define	LIFN_MARGIN 5		/* a few extra in case things are changing */

/*
 * Fetch the address configuration data for all interfaces and push it into
 * the pfil kernel module.  Fetch the routing table, compute the valid address
 * set data for all interfaces and push it into the pfil kernel module.
 */
static int
do_update(void)
{
	int numifs, i;
	struct lifreq *lifrbuf;
	struct lifconf lifc;
	struct pfil_ifaddrs *ifaddrlist;
	struct lifnum lifn;
	const int lifc_flags = 0;
	void *buf;
	size_t bufsize;

	flag = 0;

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = lifc_flags;
	if (ioctl(ip_fd, SIOCGLIFNUM, (char *)&lifn) < 0) {
		(void) snprintf(errbuf, ERRBUFSIZE, "SIOCGLIFNUM: %s",
		    strerror(errno));
		return (-1);
	}

	bufsize = (lifn.lifn_count + LIFN_MARGIN) * sizeof (struct lifreq);
	buf = malloc(bufsize);
	if (buf == NULL) {
		(void) snprintf(errbuf, ERRBUFSIZE, "malloc: %s",
		    strerror(errno));
		return (-1);
	}
	lifrbuf = buf;
	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = lifc_flags;
	lifc.lifc_buf = buf;
	lifc.lifc_len = bufsize;
	if (ioctl(ip_fd, SIOCGLIFCONF, (char *)&lifc) < 0) {
		(void) snprintf(errbuf, ERRBUFSIZE, "SIOCGLIFCONF: %s",
		    strerror(errno));
		free(buf);
		return (-1);
	}

	numifs = lifc.lifc_len / sizeof (struct lifreq);

	/* Allocate memory for the number of interfaces retrieved. */
	ifaddrlist = calloc(numifs, sizeof (struct pfil_ifaddrs));
	if (ifaddrlist == NULL) {
		(void) snprintf(errbuf, ERRBUFSIZE, "calloc: %s",
		    strerror(errno));
		free(buf);
		return (-1);
	}

	/* Populate the interface entries in the ifaddrlist. */
	for (i = 0; i < numifs; i++) {
		int isv6 = (lifrbuf[i].lifr_addr.ss_family == AF_INET6);
		int fd = (isv6 ? ip6_fd : ip_fd);

		(void) strncpy(ifaddrlist[i].name, lifrbuf[i].lifr_name,
		    LIFNAMSIZ);
		(void) memcpy(&ifaddrlist[i].localaddr, &lifrbuf[i].lifr_addr,
		    sizeof (ifaddrlist[i].localaddr));

		if (ioctl(fd, SIOCGLIFNETMASK, &lifrbuf[i]) < 0) {
			(void) snprintf(errbuf, ERRBUFSIZE,
			    "SIOCGLIFNETMASK %.*s: %s",
			    LIFNAMSIZ, ifaddrlist[i].name, strerror(errno));
			free(ifaddrlist);
			free(buf);
			return (-1);
		}
		(void) memcpy(&ifaddrlist[i].netmask, &lifrbuf[i].lifr_addr,
		    sizeof (ifaddrlist[i].netmask));

		if (ioctl(fd, SIOCGLIFBRDADDR, &lifrbuf[i]) < 0) {
			if (errno != EADDRNOTAVAIL) {
				(void) snprintf(errbuf, ERRBUFSIZE,
				    "SIOCGLIFBRDADDR %.*s: %s",
				    LIFNAMSIZ, ifaddrlist[i].name,
				    strerror(errno));
				free(ifaddrlist);
				free(buf);
				return (-1);
			}
		} else {
			(void) memcpy(&ifaddrlist[i].broadaddr,
			    &lifrbuf[i].lifr_broadaddr,
			    sizeof (ifaddrlist[i].broadaddr));
		}

		if (ioctl(fd, SIOCGLIFDSTADDR, &lifrbuf[i]) < 0) {
			if (errno != EADDRNOTAVAIL) {
				(void) snprintf(errbuf, ERRBUFSIZE,
				    "SIOCGLIFDSTADDR %.*s: %s",
				    LIFNAMSIZ, ifaddrlist[i].name,
				    strerror(errno));
				free(ifaddrlist);
				free(buf);
				return (-1);
			}
		} else {
			(void) memcpy(&ifaddrlist[i].dstaddr,
			    &lifrbuf[i].lifr_dstaddr,
			    sizeof (ifaddrlist[i].dstaddr));
		}

		if (ioctl(fd, SIOCGLIFMTU, &lifrbuf[i]) < 0) {
			(void) snprintf(errbuf, ERRBUFSIZE,
			    "SIOCGLIFDSTADDR %.*s: %s",
			    LIFNAMSIZ, ifaddrlist[i].name,
			    strerror(errno));
			free(ifaddrlist);
			free(buf);
			return (-1);
		} else {
			ifaddrlist[i].mtu = lifrbuf[i].lifr_mtu;
		}

		if (debuglevel > 0) {
			(void) fprintf(stderr, "%.*s:\n",
			    LIFNAMSIZ, ifaddrlist[i].name);
			(void) fprintf(stderr, "	localaddr %s (%d)\n",
			    dumpaddr(&ifaddrlist[i].localaddr),
			    ifaddrlist[i].localaddr.in.sin_family);
			(void) fprintf(stderr, "	netmask %s (%d)\n",
			    dumpaddr(&ifaddrlist[i].netmask),
			    ifaddrlist[i].netmask.in.sin_family);
			(void) fprintf(stderr, "	broadaddr %s (%d)\n",
			    dumpaddr(&ifaddrlist[i].broadaddr),
			    ifaddrlist[i].broadaddr.in.sin_family);
			(void) fprintf(stderr, "	dstaddr %s (%d)\n",
			    dumpaddr(&ifaddrlist[i].dstaddr),
			    ifaddrlist[i].dstaddr.in.sin_family);
			(void) fprintf(stderr, "	mtu %u\n",
			    ifaddrlist[i].mtu);
		}
	}

	free(buf);

	/*
	 * Now send this table of interfaces and addresses down into
	 * the pfil kernel module.
	 */
	if (pfil_msg(PFILCMD_IFADDRS,
	    ifaddrlist, i * sizeof (struct pfil_ifaddrs)) < 0) {
		(void) snprintf(errbuf, ERRBUFSIZE,
		    "PFILCMD_IFADDRS: %s", strerror(errno));
		free(ifaddrlist);
		return (-1);
	}

	/*
	 * Next, compute and send the table of valid addresses.
	 */

	if (vas(ifaddrlist, numifs) < 0) {
		(void) snprintf(errbuf, ERRBUFSIZE,
		    "PFILCMD_IFADDRSET: %s", strerror(errno));
		free(ifaddrlist);
		return (-1);
	}

	free(ifaddrlist);

	return (0);
}


/*
 * Send an arbitrary IP packet out from the system using sendto on the
 * raw IP socket.  Currently only IPv4 is implemented.
 */
static void
sendpkt(const void *buf, int len)
{
	const struct ip *iph = buf;
	int n;

	if (debuglevel > 0) {
		fprintf(stderr, "pfild sendpkt %u bytes:\n", len);
		fprintf(stderr, " %08X %08X %08X %08X\n",
			((uint32_t *)buf)[0],
			((uint32_t *)buf)[1],
			((uint32_t *)buf)[2],
			((uint32_t *)buf)[3]);
		fprintf(stderr, " %08X %08X %08X %08X\n",
			((uint32_t *)buf)[4],
			((uint32_t *)buf)[5],
			((uint32_t *)buf)[6],
			((uint32_t *)buf)[7]);
		fprintf(stderr, " %08X %08X %08X %08X\n",
			((uint32_t *)buf)[8],
			((uint32_t *)buf)[9],
			((uint32_t *)buf)[10],
			((uint32_t *)buf)[11]);
	}

	if (iph->ip_v == 4 && len > 20) {
		struct sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = 0;
		sin.sin_addr = iph->ip_dst;
		n = sendto(ip_fd, buf, n, 0, (void *)&sin, sizeof (sin));
	} else {
		n = -1;
		errno = EINVAL;
	}

	if (n < 0)
		perror("pfild: raw socket send");
}


static void usage(const char *prog)
{
	fprintf(stderr, "%s: [-d]\n", prog);
	exit(1);
}


int
main(int argc, char *argv[])
{
	int c, n;
	const int on = 1;
	int make_daemon = 1;
	struct pollfd pollfds[2];
	union { char bytes[1024]; ifa_msghdr_t msg; } buffer;
	int pid;

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case '?' :
			usage(argv[0]);
			break;
		case 'd' :
			make_daemon = 0;
			debuglevel++;
			break;
		}
	}

	pfil_fd = open("/dev/pfil", O_RDWR);
	if (pfil_fd < 0) {
		perror("pfild: open(/dev/pfil)");
		return (1);
	}

	ip_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ip_fd < 0) {
		perror("pfild: inet socket");
		return (1);
	}
	if (setsockopt(ip_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		perror("pfild: inet socket IP_HDRINCL option");
		return (1);
	}

	ip6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (ip6_fd < 0) {
		perror("pfild: inet6 socket");
		return (1);
	}

	route_fd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (route_fd < 0) {
		perror("pfild: socket(PF_ROUTE)");
		return (1);
	}

	if (make_daemon) {
		/* Background */
		if ((pid = fork()) > 0)
			return (0);
		if (pid < 0) {
			(void) fprintf(stderr, "%s: fork() failed %s\n",
			    argv[0], strerror(errno));
			return (1);
			/* NOTREACHED */
		}
		(void) setsid();
		(void) close(0);
		(void) close(1);
		(void) close(2);
		(void) open("/dev/null", O_RDWR);
		(void) dup(0);
		(void) dup(0);
		(void) chdir("/");
	}

	/*
	 * Main loop:  Poll for messages from PF_ROUTE socket or pfil stream.
	 * PF_ROUTE messages may indicate a need to update the kernel module's
	 * interface data.  pfil messages contain packets to be transmitted.
	 * Errors in processing don't terminate the program, but errors in
	 * polling will terminate the program to avoid busy looping.
	 */

	pollfds[0].fd = route_fd;
	pollfds[0].events = POLLRDNORM;
	pollfds[1].fd = pfil_fd;
	pollfds[1].events = POLLRDNORM;

	while (1) {
		if (flag) {
			/* Wait for a moment of quiet, then do the update. */
			n = poll(pollfds, 1, QUIETTIME);
			if (n < 1 || !(pollfds[0].revents & POLLRDNORM)) {
				if (do_update() != 0 && make_daemon == 0)
					(void) fprintf(stderr, "pfild: %s\n",
					    errbuf);
			}
		}

		if (poll(pollfds, 2, -1) < 0) {
			perror("pfild: poll()");
			return (1);
		}

		/* Check for route_fd message. */
		if (pollfds[0].revents & POLLRDNORM) {
			n = read(route_fd, &buffer, sizeof (buffer));

			if (n < 1) {
				if (n < 0)
					perror("pfild: read(PF_ROUTE)");
				else
					(void) fprintf(stderr,
					    "pfild: read(PF_ROUTE) EOF\n");
				return (1);
			}

			handle_msg(&buffer.msg, n);
		}

		/* Check for pfil_fd message. */
		if (pollfds[1].revents & POLLRDNORM) {
			char pktbuf[IP_MAXPACKET];
			struct strbuf ctl, data;
			int flags;

			ctl.maxlen = 0;	/* We don't want any control message. */
			ctl.buf = pktbuf;
			data.maxlen = sizeof (pktbuf);
			data.buf = pktbuf;
			flags = 0;

			n = getmsg(pfil_fd, &ctl, &data, &flags);

			if (n < 0) {
				perror("pfild: getmsg(pfil)");
				return (1);
			}
			if (n > 0) {
				fprintf(stderr,
				    "pfild: invalid packet from kernel "
				    "n=%d ctl.len=%u data.len=%u\n",
				    n, ctl.len, data.len);
				return (1);
			}

			sendpkt(data.buf, data.len);
		}
	}

	/* NOTREACHED */
}

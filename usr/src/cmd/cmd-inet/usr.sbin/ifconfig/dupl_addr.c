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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Perform IPv6 duplicate address detection for a given interface
 * and IPv6 address.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"
#include "ifconfig.h"
#include <netinet/icmp6.h>
#include <netinet/in_systm.h>		/* For IP_MAXPACKET */
#include <netinet/ip.h>			/* For IP_MAXPACKET */

/* XXX extract DupAddrDetectTransmits from LNKINFO? */
int DupAddrDetectTransmits = 1;		/* XXX Make configurable? */
int RetransTimer = ND_RETRANS_TIMER;	/* Milliseconds. */

#define	IPV6_MAX_HOPS	255

struct in6_addr all_nodes_mcast = { { 0xff, 0x2, 0x0, 0x0,
					0x0, 0x0, 0x0, 0x0,
					0x0, 0x0, 0x0, 0x0,
					0x0, 0x0, 0x0, 0x1 } };

static void	in6_solmulti_addr(struct in6_addr *addr,
		    struct in6_addr *multi);
static int	run_dad(int s, char *phyname, struct sockaddr_in6 *testaddr,
		    struct sockaddr_in6 *solicited_mc, int ifindex);
static int	send_dad_probe(int s, char *phyname,
		    struct sockaddr_in6 *testaddr,
		    struct sockaddr_in6 *solicited_mc);
static int	recv_dad(int s, char *phyname, struct sockaddr_in6 *testaddr,
		    int ifindex);
static boolean_t verify_opt_len(struct nd_opt_hdr *opt, int optlen,
		    struct sockaddr_in6 *from);
static void	dad_failed(char *phyname, struct sockaddr_in6 *testaddr,
		    int code);
static void	print_na(char *str, char *phyname,
		    struct nd_neighbor_advert *na, int len,
		    struct sockaddr_in6 *addr);
static void	print_ns(char *str, char *phyname,
		    struct nd_neighbor_solicit *ns, int len,
		    struct sockaddr_in6 *addr);
static void	print_opt(struct nd_opt_hdr *opt, int len);
static char	*fmt_lla(char *llabuf, int bufsize, char *lla, int llalen);


/*
 * Performing duplicate address detection.
 *
 * Returns 0 if the address is ok, 1 if there is a duplicate,
 * and -1  (with errno set) if there is some internal error.
 * As a side effect this does a syslog and a stderr printf
 * identifying any duplicate.
 * Note that the state of the interface name is unchanged.
 */
int
do_dad(char *ifname, struct sockaddr_in6 *testaddr)
{
	int s;
	struct lifreq lifr;
	char *cp;
	char phyname[LIFNAMSIZ];
	int ifindex;
	int64_t saved_flags;
	int ret = -1;	/* Assume error by default */
	struct sockaddr_in6 solicited_mc;

	/*
	 * Truncate name at ':'. Needed for SIOCGLIFLNKINFO
	 * Keep untruncated ifname for other use.
	 */
	(void) strncpy(phyname, ifname, sizeof (phyname));
	cp = strchr(phyname, ':');
	if (cp != NULL)
		*cp = '\0';

	/*
	 * Get a socket to use to send and receive neighbor solicitations
	 * for DAD.  Also used for ioctls below.
	 */
	if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		Perror0("socket");
		return (-1);
	}

	/*
	 * Determine interface index (for IPV6_BOUND_PIF) and
	 * save the flag values so they can be restored on return.
	 */
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFINDEX, (caddr_t)&lifr) < 0) {
		Perror0("do_dad: SIOCGLIFINDEX");
		goto done;
	}
	ifindex = lifr.lifr_index;
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0("do_dad: SIOCGLIFFLAGS");
		goto done;
	}
	saved_flags = lifr.lifr_flags;
	if (!(saved_flags & IFF_MULTICAST)) {
		/* Not possible to do DAD. Pretend it is ok */
		ret = 0;
		goto done;
	}
	(void) strncpy(lifr.lifr_name, phyname, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFLNKINFO, (caddr_t)&lifr) < 0) {
		Perror0("do_dad: SIOCGLIFLNKINFO");
		goto done;
	}
	if (lifr.lifr_ifinfo.lir_reachretrans != 0) {
		RetransTimer = lifr.lifr_ifinfo.lir_reachretrans;
	}

	/*
	 * Set NOLOCAL and UP flags.
	 * This prevents the use of the interface except when the user binds
	 * to unspecified IPv6 address, and sends to a link local multicast
	 * address.
	 */
	lifr.lifr_flags = saved_flags | IFF_NOLOCAL | IFF_UP;

	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0("do_dad: SIOCSLIFFLAGS");
		goto restore;
	}

	/*
	 * IPV6_BOUND_PIF prevents load spreading to happen. If we
	 * just do IPV6_BOUND_IF, the packet can go out on a different
	 * interface other than "ifindex", if interface is part of
	 * a group. In that case, we will get back the copy of NS that
	 * we sent and think it is a duplicate(Switch loops back the
	 * copy on all interfaces other than the one we sent the packet on).
	 */
	if (setsockopt(s, IPPROTO_IPV6, IPV6_BOUND_PIF, (char *)&ifindex,
	    sizeof (ifindex)) < 0) {
		Perror0("IPV6_BOUND_PIF");
		goto restore;
	}

	{
		int hops = IPV6_MAX_HOPS;
		int on = 1;
		int off = 0;

		if (debug > 1)
			off = 1;	/* Force duplicate */

		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		    (char *)&hops, sizeof (hops)) < 0) {
			Perror0("IPV6_MULTICAST_HOPS");
			goto restore;
		}
		if (setsockopt(s, IPPROTO_IPV6, IPV6_UNSPEC_SRC,
		    (char *)&on, sizeof (on)) < 0) {
			Perror0("IPV6_UNSPEC_SRC");
			goto restore;
		}

		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		    (char *)&off, sizeof (off)) < 0) {
			Perror0("IPV6_MULTICAST_LOOP");
			goto restore;
		}

		/* Enable receipt of ancillary data */
		if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		    (char *)&on, sizeof (on)) < 0) {
			Perror0("IPV6_RECVHOPLIMIT");
			goto restore;
		}
		if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		    (char *)&on, sizeof (on)) < 0) {
			Perror0("IPV6_RECVPKTINFO");
			goto restore;
		}
		if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVRTHDR,
		    (char *)&on, sizeof (on)) < 0) {
			Perror0("IPV6_RECVRTHDR");
			goto restore;
		}
	}

	/*
	 * Extract the address and determine the solicited node multicast
	 * address to use.
	 */
	(void) memset(&solicited_mc, 0, sizeof (solicited_mc));
	solicited_mc.sin6_family = AF_INET6;
	in6_solmulti_addr(&testaddr->sin6_addr, &solicited_mc.sin6_addr);

	/* Join the solicited node multicast address and all-nodes. */
	{
		struct ipv6_mreq v6mcastr;

		v6mcastr.ipv6mr_multiaddr = solicited_mc.sin6_addr;
		v6mcastr.ipv6mr_interface = ifindex;

		if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		    (char *)&v6mcastr, sizeof (v6mcastr)) < 0) {
			Perror0("IPV6_JOIN_GROUP");
			goto restore;
		}

		v6mcastr.ipv6mr_multiaddr = all_nodes_mcast;
		v6mcastr.ipv6mr_interface = ifindex;

		if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		    (char *)&v6mcastr, sizeof (v6mcastr)) < 0) {
			Perror0("IPV6_JOIN_GROUP");
			goto restore;
		}
	}

	ret = run_dad(s, phyname, testaddr, &solicited_mc, ifindex);

restore:
	/* Restore flags */
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	lifr.lifr_flags = saved_flags;
	if (ioctl(s, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0("do_dad: SIOCSLIFFLAGS");
		ret = -1;
		goto done;
	}
done:
	(void) close(s);
	return (ret);
}


/*
 * Determine the solicited node multicast address for a given address.
 */
static void
in6_solmulti_addr(struct in6_addr *addr, struct in6_addr *multi)
{
	struct in6_addr solicited_prefix = {
		{ 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x1, 0xFF, 0x0, 0x0, 0x0 } };
	int i;

	*multi = solicited_prefix;
	for (i = 13; i < 16; i++)
		multi->s6_addr[i] = addr->s6_addr[i];
}

static int
run_dad(int s, char *phyname, struct sockaddr_in6 *testaddr,
    struct sockaddr_in6 *solicited_mc, int ifindex)
{
	int time_left;	/* In milliseconds */
	struct timeval starttime;
	struct timeval curtime;
	struct pollfd fds;
	int i;
	int ret;

	if (debug)
		(void) printf("run_dad(%s)\n", phyname);

	/*
	 * Perform duplicate address detection sequence
	 * 1. Send a neighbor solicitation with an unspecified source
	 *    address to the solicited node MC address with the testaddr
	 *    being the target.
	 * 2. Wait for up to RetransTimer milliseconds for either a
	 *    neighbor advertisement (sent to all-nodes) or a DAD neighbor
	 *    solicitation for the testaddr.
	 * 3. Perform step 1 and 2 DupAddrDetectTransmits times.
	 */

	/* XXX perform a random delay: 0 - MAX_RTR_SOLICITATION_DELAY */
	/* XXX use poll+recv logic for the random delay */

	for (i = 0; i < DupAddrDetectTransmits; i++) {
		if (send_dad_probe(s, phyname, testaddr, solicited_mc) < 0)
			return (-1);

		/*
		 * Track time to make sure total wait is RetransTimer
		 * even though random packet will awake poll.
		 */
		(void) gettimeofday(&starttime, NULL);
		/* CONSTCOND */
		while (1) {
			(void) gettimeofday(&curtime, NULL);
			time_left = RetransTimer -
				(curtime.tv_sec - starttime.tv_sec) * 1000 -
				(curtime.tv_usec - starttime.tv_usec) / 1000;

			if (debug) {
				(void) printf("run_dad: time_left %d ms\n",
				    time_left);
			}
			if (time_left <= 0) {
				if (debug)
					(void) printf("run_dad: timeout\n");
				break;
			}
			fds.fd = s;
			fds.events = POLLIN;

			switch (poll(&fds, 1, time_left)) {
			case -1:
				Perror0("poll");
				return (-1);
			case 0:
				/* Need loop will break */
				break;
			default:
				/* Huh? */
				(void) fprintf(stderr, "poll returns > 1!\n");
				return (-1);
			case 1:
				if (fds.revents & POLLIN) {
					ret = recv_dad(s, phyname, testaddr,
					    ifindex);
					if (ret < 0)
						return (-1);
					if (ret > 0) {
						dad_failed(phyname, testaddr,
						    ret);
						return (1);
					}
				}
				break;
			}
		}
	}
	return (0);
}

/*
 * Send a DAD NS packet. Assumes an IPV6_UNSPEC_SRC and an IPV6_BOUND_IF
 * have been done by the caller.
 */
static int
send_dad_probe(int s, char *phyname, struct sockaddr_in6 *testaddr,
    struct sockaddr_in6 *solicited_mc)
{
	static uint64_t outpack[(IP_MAXPACKET + 1)/8];
	struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)outpack;
	int packetlen = 0;
	int cc;

	ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns->nd_ns_code = 0;
	ns->nd_ns_cksum = 0;
	ns->nd_ns_reserved = 0;
	ns->nd_ns_target = testaddr->sin6_addr;
	packetlen += sizeof (struct nd_neighbor_solicit);
	cc = sendto(s, (char *)outpack, packetlen, 0,
	    (struct sockaddr *)solicited_mc, sizeof (*solicited_mc));
	if (cc < 0 || cc != packetlen) {
		char abuf[INET6_ADDRSTRLEN];

		if (cc < 0) {
			Perror0("DAD, sendto");
			return (-1);
		}
		(void) inet_ntop(solicited_mc->sin6_family,
		    (void *)&solicited_mc->sin6_addr, abuf, sizeof (abuf));

		(void) fprintf(stderr, "wrote %s %d chars, ret=%d\n",
		    abuf, packetlen, cc);
		return (-1);
	}
	if (debug)
		print_ns("Sent NS", phyname, ns, packetlen, solicited_mc);

	return (0);
}

/*
 * Return a pointer to the specified option buffer.
 * If not found return NULL.
 */
static void *
find_ancillary(struct msghdr *msg, int cmsg_type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == cmsg_type) {
			return (CMSG_DATA(cmsg));
		}
	}
	return (NULL);
}

/*
 * Receive an ICMP packet. If the packet signals a duplicate address for
 * testaddr then return  a positive non-zero number. Otherwise return zero.
 * Internal errors cause a return of -1.
 */
static int
recv_dad(int s, char *phyname, struct sockaddr_in6 *testaddr, int ifindex)
{
	struct sockaddr_in6 from;
	struct icmp6_hdr *icmp;
	struct nd_neighbor_solicit *ns;
	struct nd_neighbor_advert *na;
	static uint64_t in_packet[(IP_MAXPACKET + 1)/8];
	static uint64_t ancillary_data[(IP_MAXPACKET + 1)/8];
	int len;
	char abuf[INET6_ADDRSTRLEN];
	struct msghdr msg;
	struct iovec iov;
	uchar_t *opt;
	uint_t hoplimit;
	struct in6_addr dst;
	int rcv_ifindex;

	iov.iov_base = (char *)in_packet;
	iov.iov_len = sizeof (in_packet);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = (struct sockaddr *)&from;
	msg.msg_namelen = sizeof (from);
	msg.msg_control = ancillary_data;
	msg.msg_controllen = sizeof (ancillary_data);

	if ((len = recvmsg(s, &msg, 0)) < 0) {
		Perror0("DAD recvmsg");
		return (-1);
	}
	if (len == 0)
		return (0);

	if (debug) {
		(void) inet_ntop(AF_INET6, (void *)&from.sin6_addr,
		    abuf, sizeof (abuf));
	}
	/* Ignore packets > 64k or control buffers that don't fit */
	if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
		if (debug) {
			(void) fprintf(stderr,
			    "Truncated message: msg_flags 0x%x from %s\n",
			    msg.msg_flags, abuf);
		}
		return (0);
	}

	icmp = (struct icmp6_hdr *)in_packet;

	if (len < ICMP6_MINLEN) {
		if (debug) {
			(void) fprintf(stderr,
			    "Too short ICMP packet: %d bytes from %s\n",
			    len, abuf);
		}
		return (0);
	}

	opt = find_ancillary(&msg, IPV6_HOPLIMIT);
	if (opt == NULL) {
		/* Unknown hoplimit - must drop */
		if (debug) {
			(void) fprintf(stderr,
			    "Unknown hop limit from %s\n", abuf);
		}
		return (0);
	}
	hoplimit = *(uint_t *)opt;
	opt = find_ancillary(&msg, IPV6_PKTINFO);
	if (opt == NULL) {
		/* Unknown destination address - must drop */
		if (debug) {
			(void) fprintf(stderr,
			    "Unknown destination from %s\n", abuf);
		}
		return (0);
	}
	dst = ((struct in6_pktinfo *)opt)->ipi6_addr;
	rcv_ifindex = ((struct in6_pktinfo *)opt)->ipi6_ifindex;
	opt = find_ancillary(&msg, IPV6_RTHDR);
	if (opt != NULL) {
		/* Can't allow routing headers in ND messages */
		if (debug) {
			(void) fprintf(stderr,
			    "ND message with routing header from %s\n", abuf);
		}
		return (0);
	}

	switch (icmp->icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:
		/*
		 * Assumes that the kernel has verified the AH (if present)
		 * and the ICMP checksum.
		 */
		if (hoplimit != IPV6_MAX_HOPS) {
			if (debug) {
				(void) fprintf(stderr,
				    "NS hop limit: %d from %s\n",
				    hoplimit, abuf);
			}
			return (0);
		}

		if (icmp->icmp6_code != 0) {
			if (debug) {
				(void) fprintf(stderr, "NS code: %d from %s\n",
				    icmp->icmp6_code, abuf);
			}
			return (0);
		}

		if (len < sizeof (struct nd_neighbor_solicit)) {
			if (debug) {
				(void) fprintf(stderr,
				    "NS too short: %d bytes from %s\n",
				    len, abuf);
			}
			return (0);
		}
		ns = (struct nd_neighbor_solicit *)icmp;
		if (IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target)) {
			if (debug) {
				char abuf2[INET6_ADDRSTRLEN];

				(void) inet_ntop(AF_INET6,
				    (void *)&ns->nd_ns_target,
				    abuf2, sizeof (abuf2));
				(void) fprintf(stderr,
				    "NS with multicast target: %s from %s\n",
				    abuf2, abuf);
			}
			return (0);
		}

		if (len > sizeof (struct nd_neighbor_solicit)) {
			if (!verify_opt_len((struct nd_opt_hdr *)&ns[1],
			    len - sizeof (struct nd_neighbor_solicit), &from))
				return (0);
		}

		if (debug)
			print_ns("Received valid NS", phyname, ns, len, &from);
		if (!IN6_IS_ADDR_UNSPECIFIED(&from.sin6_addr)) {
			/* Sender is doing address resolution */
			return (0);
		}
		if (rcv_ifindex != ifindex) {
			if (debug) {
				(void) fprintf(stderr,
				    "Received Neighbor solicitation on"
				    " ifindex %d, expecting on %d\n",
				    rcv_ifindex, ifindex);
			}
			return (0);
		}
		if (IN6_ARE_ADDR_EQUAL(&testaddr->sin6_addr,
		    &ns->nd_ns_target)) {
			if (debug) {
				(void) fprintf(stderr,
				    "NS - duplicate from %s\n",
				    abuf);
			}
			return (1);
		}
		return (0);

	case ND_NEIGHBOR_ADVERT:
		/*
		 * Assumes that the kernel has verified the AH (if present)
		 * and the ICMP checksum.
		 */
		if (hoplimit != IPV6_MAX_HOPS) {
			if (debug) {
				(void) fprintf(stderr,
				    "NA hop limit: %d from %s\n",
				    hoplimit, abuf);
			}
			return (0);
		}

		if (icmp->icmp6_code != 0) {
			if (debug) {
				(void) fprintf(stderr, "NA code: %d from %s\n",
				    icmp->icmp6_code, abuf);
			}
			return (0);
		}

		if (len < sizeof (struct nd_neighbor_advert)) {
			if (debug) {
				(void) fprintf(stderr,
				    "NA too short: %d bytes from %s\n",
				    len, abuf);
			}
			return (0);
		}
		na = (struct nd_neighbor_advert *)icmp;
		if (IN6_IS_ADDR_MULTICAST(&na->nd_na_target)) {
			if (debug) {
				char abuf2[INET6_ADDRSTRLEN];

				(void) inet_ntop(AF_INET6,
				    (void *)&na->nd_na_target,
				    abuf2, sizeof (abuf2));
				(void) fprintf(stderr,
				    "NA with multicast target: %s from %s\n",
				    abuf2, abuf);
			}
			return (0);
		}

		if (IN6_IS_ADDR_MULTICAST(&dst) &&
		    (na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED)) {
			if (debug) {
				char abuf2[INET6_ADDRSTRLEN];

				(void) inet_ntop(AF_INET6,
				    (void *)&na->nd_na_target,
				    abuf2, sizeof (abuf2));
				(void) fprintf(stderr,
				    "NA solicited w/ mc target: %s from %s\n",
				    abuf2, abuf);
			}
			return (0);
		}

		if (len > sizeof (struct nd_neighbor_advert)) {
			if (!verify_opt_len((struct nd_opt_hdr *)&na[1],
			    len - sizeof (struct nd_neighbor_advert), &from))
				return (0);
		}

		if (debug)
			print_na("Received valid NA", phyname, na, len, &from);

		if (IN6_ARE_ADDR_EQUAL(&testaddr->sin6_addr,
		    &na->nd_na_target)) {
			if (debug) {
				(void) fprintf(stderr,
				    "NA - duplicate from %s\n",
				    abuf);
			}
			return (1);
		}
		return (0);
	default:
		return (0);
	}
}

/*
 * Verify that all options have a non-zero length and that
 * the options fit within the total length of the packet (optlen).
 */
static boolean_t
verify_opt_len(struct nd_opt_hdr *opt, int optlen, struct sockaddr_in6 *from)
{
	while (optlen > 0) {
		if (opt->nd_opt_len == 0) {
			if (debug) {
				char abuf[INET6_ADDRSTRLEN];

				(void) inet_ntop(AF_INET6,
				    (void *)&from->sin6_addr,
				    abuf, sizeof (abuf));

				(void) fprintf(stderr,
				    "Zero length option type 0x%x from %s\n",
				    opt->nd_opt_type, abuf);
			}
			return (_B_FALSE);
		}
		optlen -= 8 * opt->nd_opt_len;
		if (optlen < 0) {
			if (debug) {
				char abuf[INET6_ADDRSTRLEN];

				(void) inet_ntop(AF_INET6,
				    (void *)&from->sin6_addr,
				    abuf, sizeof (abuf));

				(void) fprintf(stderr,
				    "Too large option: type 0x%x len %u "
				    "from %s\n",
				    opt->nd_opt_type, opt->nd_opt_len,
				    abuf);
			}
			return (_B_FALSE);
		}
		opt = (struct nd_opt_hdr *)((char *)opt +
		    8 * opt->nd_opt_len);
	}
	return (_B_TRUE);
}


static void
dad_failed(char *phyname, struct sockaddr_in6 *testaddr, int code)
{
	char abuf[INET6_ADDRSTRLEN];

	(void) inet_ntop(testaddr->sin6_family,
	    (void *)&testaddr->sin6_addr,
	    abuf, sizeof (abuf));
	(void) fprintf(stderr,
	    "ifconfig: "
	    "Duplicate address detected on link %s for address %s. Code %d\n",
	    phyname, abuf, code);

	openlog("ifconfig", LOG_CONS, LOG_DAEMON);
	syslog(LOG_CRIT,
	    "Duplicate address detected on link %s for address %s. Code %d\n",
	    phyname, abuf, code);
	closelog();
}

/* Printing functions */

static void
print_ns(char *str, char *phyname,
    struct nd_neighbor_solicit *ns, int len, struct sockaddr_in6 *addr)
{
	struct nd_opt_hdr *opt;
	char abuf[INET6_ADDRSTRLEN];

	(void) printf("%s %s (%d bytes) on %s\n", str,
	    inet_ntop(addr->sin6_family, (void *)&addr->sin6_addr,
	    abuf, sizeof (abuf)),
	    len, phyname);
	(void) printf("\ttarget %s\n",
	    inet_ntop(addr->sin6_family, (void *)&ns->nd_ns_target,
	    abuf, sizeof (abuf)));
	len -= sizeof (*ns);
	opt = (struct nd_opt_hdr *)&ns[1];
	print_opt(opt, len);
}

static void
print_na(char *str, char *phyname,
    struct nd_neighbor_advert *na, int len, struct sockaddr_in6 *addr)
{
	struct nd_opt_hdr *opt;
	char abuf[INET6_ADDRSTRLEN];

	(void) printf("%s %s (%d bytes) on %s\n", str,
	    inet_ntop(addr->sin6_family, (void *)&addr->sin6_addr,
	    abuf, sizeof (abuf)),
	    len, phyname);
	(void) printf("\ttarget %s\n",
	    inet_ntop(addr->sin6_family, (void *)&na->nd_na_target,
	    abuf, sizeof (abuf)));
	(void) printf("\tRouter: %s\n",
	    (na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER) ?
	    "Set" : "Not set");
	(void) printf("\tSolicited: %s\n",
	    (na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED) ?
	    "Set" : "Not set");
	(void) printf("\tOverride: %s\n",
	    (na->nd_na_flags_reserved & ND_NA_FLAG_OVERRIDE) ?
	    "Set" : "Not set");

	len -= sizeof (*na);
	opt = (struct nd_opt_hdr *)&na[1];
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
			if (debug)
				(void) printf("Zero length option!\n");
			break;
		}
		switch (opt->nd_opt_type) {
		case ND_OPT_PREFIX_INFORMATION:
			po = (struct nd_opt_prefix_info *)opt;
			if (optlen != sizeof (*po) ||
			    optlen > len)
				break;

			(void) printf("\tOn link flag:%s\n",
			    (po->nd_opt_pi_flags_reserved &
			    ND_OPT_PI_FLAG_ONLINK) ?
			    "Set" : "Not set");
			(void) printf("\tAuto addrconf flag:%s\n",
			    (po->nd_opt_pi_flags_reserved &
			    ND_OPT_PI_FLAG_AUTO) ?
			    "Set" : "Not set");
			(void) printf("\tValid time: %u\n",
			    ntohl(po->nd_opt_pi_valid_time));
			(void) printf("\tPreferred time: %u\n",
			    ntohl(po->nd_opt_pi_preferred_time));
			(void) printf("\tPrefix: %s/%u\n",
			    inet_ntop(AF_INET6, (void *)&po->nd_opt_pi_prefix,
			    abuf, sizeof (abuf)),
			    po->nd_opt_pi_prefix_len);
			break;
		case ND_OPT_MTU:
			mo = (struct nd_opt_mtu *)opt;
			if (optlen != sizeof (*mo) ||
			    optlen > len)
				break;
			(void) printf("\tMTU: %d\n",
			    ntohl(mo->nd_opt_mtu_mtu));
			break;
		case ND_OPT_SOURCE_LINKADDR:
			lo = (struct nd_opt_lla *)opt;
			if (optlen < 8 ||
			    optlen > len)
				break;
			(void) fmt_lla(llabuf, sizeof (llabuf),
			    (char *)lo->nd_opt_lla_hdw_addr, optlen - 2);
			(void) printf("\tSource LLA: len %d <%s>\n",
			    optlen-2, llabuf);
			break;
		case ND_OPT_TARGET_LINKADDR:
			lo = (struct nd_opt_lla *)opt;
			if (optlen < 8||
			    optlen > len)
				break;
			(void) fmt_lla(llabuf, sizeof (llabuf),
			    (char *)lo->nd_opt_lla_hdw_addr, optlen - 2);
			(void) printf("\tTarget LLA: len %d <%s>\n",
			    optlen-2, llabuf);
			break;
		case ND_OPT_REDIRECTED_HEADER:
			(void) printf("\tRedirected header option!\n");
			break;
		default:
			(void) printf("Unkown option %d (0x%x)\n",
			    opt->nd_opt_type, opt->nd_opt_type);
			break;
		}
		opt = (struct nd_opt_hdr *)((char *)opt + optlen);
		len -= optlen;
	}
}

static char *
fmt_lla(char *llabuf, int bufsize, char *lla, int llalen)
{
	int i;
	char *cp = llabuf;

	for (i = 0; i < llalen; i++) {
		if (i == llalen - 1)
			(void) snprintf(cp, bufsize, "%02x", lla[i] & 0xFF);
		else
			(void) snprintf(cp, bufsize, "%02x:", lla[i] & 0xFF);
		bufsize -= strlen(cp);
		cp += strlen(cp);
	}
	return (llabuf);
}

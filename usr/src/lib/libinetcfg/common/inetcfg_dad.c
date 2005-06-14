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

/*
 * This module uses the ancillary data feature that is made available
 * though the UNIX 98 standards version of the Socket interface. This
 * interface is normally accessed via libxnet. However, to use libxnet,
 * this library would have to be compiled with _XOPEN_SOURCE=500 and
 * __EXTENSIONS__. Unfortunately, this makes linting both the library
 * and its consumers impractical. Therefore, this module is itself compiled
 * for use with the UNIX 98 version of the Socket interface and the
 * xnet versions of the Socket interfaces are called directly.
 * Hopefully, our Socket implementation will one day support the ancillary
 * data feature directly and this hack will no longer be needed. In the
 * meantime, changes to this file should be made with the knowledge that the
 * data types used by this module may differ in defintion fron the same data
 * types in the other modules.
 */
#define	_XOPEN_SOURCE	500
#define	__EXTENSIONS__	1

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <inetcfg.h>

#define	IPV6_MAX_HOPS		255

static int dup_addr_detect_transmits = 1;

static struct in6_addr all_nodes_mcast = { { 0xff, 0x2, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x1 } };

static struct in6_addr solicited_prefix = { { 0xff, 0x2, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x0,
						0x0, 0x0, 0x0, 0x1,
						0xff, 0x0, 0x0, 0x0 } };

extern int __xnet_socket(int family, int type, int protocol);
extern int __xnet_recvmsg(int sock, struct msghdr *msg, int flags);
extern int __xnet_sendto(int sock, const void *buf, size_t len,
    int flags, const struct sockaddr *addr, socklen_t addrlen);

/*
 * Verifies that all options have a non-zero length and that
 * the options fit within the total length of the packet (optlen).
 *
 * Returns: _B_TRUE if valid, _B_FALSE otherwise.
 */
static boolean_t
dad_verify_optlen(struct nd_opt_hdr *opt, ssize_t optlen)
{
	assert(opt != NULL);
	assert(optlen > 0);

	while (optlen > 0) {
		if ((opt->nd_opt_len == 0)) {
			return (_B_FALSE);
		}
		optlen -= 8 * opt->nd_opt_len;
		if (optlen < 0) {
			return (_B_FALSE);
		}
		opt = (struct nd_opt_hdr *)((char *)opt +
		    8 * opt->nd_opt_len);
	}
	return (_B_TRUE);
}

/*
 * Returns a pointer to the specified option buffer.
 *
 * Returns: A pointer to the option buffer or NULL if not found.
 */
static void *
dad_find_ancillary(struct msghdr *msg, int cmsg_type)
{
	struct cmsghdr *cmsg;

	assert(msg != NULL);

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
 * Receives an ICMP packet and tests it to see if it indicates that
 * testaddr is a duplicate address. This routine returns ICFG_SUCCESS
 * if no duplicate address is detected. If an unexpected error is
 * encountered receiving the packet, then ICFG_FAILURE is returned.
 * And of course ICFG_DAD_FOUND is returned if a duplicate address
 * is detected.
 *
 * Returns: ICFG_SUCCESS, ICFG_FAILURE or ICFG_DAD_FOUND.
 */
static int
dad_receive(int sock, struct sockaddr_in6 *testaddr, int ifindex)
{
	struct sockaddr_in6 from;
	struct icmp6_hdr *icmp;
	struct nd_neighbor_solicit *ns;
	struct nd_neighbor_advert *na;
	static uint64_t in_packet[(IP_MAXPACKET + 1)/8];
	static uint64_t ancillary_data[(IP_MAXPACKET + 1)/8];
	ssize_t len;
	struct msghdr msg;
	struct iovec iov;
	void *opt;
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

	if ((len = __xnet_recvmsg(sock, &msg, 0)) < 0) {
		/* Error was encountered - return failure */
		return (ICFG_FAILURE);
	}

	if (len == 0) {
		/* Ignore zero length messages */
		return (ICFG_SUCCESS);
	}

	if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
		/* Ignore packets > 64k or control buffers that don't fit */
		return (ICFG_SUCCESS);
	}

	icmp = (struct icmp6_hdr *)in_packet;

	if (len < ICMP6_MINLEN) {
		/* Ignore packet if it is too small to be icmp */
		return (ICFG_SUCCESS);
	}

	opt = dad_find_ancillary(&msg, IPV6_HOPLIMIT);
	if (opt == NULL) {
		/* Unknown hoplimit - must drop */
		return (ICFG_SUCCESS);
	}
	hoplimit = *(uint_t *)opt;

	opt = dad_find_ancillary(&msg, IPV6_PKTINFO);
	if (opt == NULL) {
		/* Unknown destination address - must drop */
		return (ICFG_SUCCESS);
	}
	dst = ((struct in6_pktinfo *)opt)->ipi6_addr;
	rcv_ifindex = ((struct in6_pktinfo *)opt)->ipi6_ifindex;

	opt = dad_find_ancillary(&msg, IPV6_RTHDR);
	if (opt != NULL) {
		/* Can't allow routing headers in ND messages */
		return (ICFG_SUCCESS);
	}

	/*
	 * We're only interested in neighbor solicitations (someone
	 * else soliciting for the same address) and advertisements.
	 * We must verify each. In either case, we assume that the
	 * kernel verified the AH (if present) and the ICMP checksum.
	 */
	switch (icmp->icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:

		if (hoplimit != IPV6_MAX_HOPS) {
			/* Packet came from different subnet */
			return (ICFG_SUCCESS);
		}

		if (icmp->icmp6_code != 0) {
			/* There are no codes for neighbor solicitations */
			return (ICFG_SUCCESS);
		}

		if (len < sizeof (struct nd_neighbor_solicit)) {
			/* Packet is too small */
			return (ICFG_SUCCESS);
		}

		ns = (struct nd_neighbor_solicit *)icmp;
		if (IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target)) {
			/* NS target was multicast */
			return (ICFG_SUCCESS);
		}

		if (len > sizeof (struct nd_neighbor_solicit)) {
			/*
			 * A neighbor solicitation packet has the form
			 * of a header directly followed by options.
			 */
			if (!dad_verify_optlen((struct nd_opt_hdr *)&ns[1],
			    len - sizeof (struct nd_neighbor_solicit))) {
				/* Invalid options */
				return (ICFG_SUCCESS);
			}
		}

		if (!IN6_IS_ADDR_UNSPECIFIED(&from.sin6_addr)) {
			/* Sender is doing address resolution */
			return (ICFG_SUCCESS);
		}

		if (rcv_ifindex != ifindex) {
			/* Packet not received on test interface */
			return (ICFG_SUCCESS);
		}

		if (!IN6_ARE_ADDR_EQUAL(&testaddr->sin6_addr,
		    &ns->nd_ns_target)) {
			/* NS wasn't for test address */
			return (ICFG_SUCCESS);
		}

		return (ICFG_DAD_FOUND);

	case ND_NEIGHBOR_ADVERT:

		if (hoplimit != IPV6_MAX_HOPS) {
			/* Packet came from different subnet */
			return (ICFG_SUCCESS);
		}

		if (icmp->icmp6_code != 0) {
			/* There are no codes for neighbor advertisements */
			return (ICFG_SUCCESS);
		}

		if (len < sizeof (struct nd_neighbor_advert)) {
			/* Packet is too small */
			return (ICFG_SUCCESS);
		}

		na = (struct nd_neighbor_advert *)icmp;
		if (IN6_IS_ADDR_MULTICAST(&na->nd_na_target)) {
			/* NA target was multicast */
			return (ICFG_SUCCESS);
		}

		if (IN6_IS_ADDR_MULTICAST(&dst) &&
		    (na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED)) {
			/* Dest was multicast and solicited flag not zero */
			return (ICFG_SUCCESS);
		}

		if (len > sizeof (struct nd_neighbor_advert)) {
			/*
			 * A neighbor advertisement packet has the form
			 * of a header directly followed by options.
			 */
			if (!dad_verify_optlen((struct nd_opt_hdr *)&na[1],
			    len - sizeof (struct nd_neighbor_advert))) {
				return (ICFG_SUCCESS);
			}
		}

		if (!IN6_ARE_ADDR_EQUAL(&testaddr->sin6_addr,
		    &na->nd_na_target)) {
			/* NA wasn't for test address */
			return (ICFG_SUCCESS);
		}
		return (ICFG_DAD_FOUND);

	default:
		return (ICFG_SUCCESS);
	}
}

/*
 * Sends a DAD neighbor solicitation packet. Assumes the socket has been
 * configured correctly (i.e., an IPV6_UNSPEC_SRC and an IPV6_BOUND_IF have
 * been done by the caller, etc.).
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
static int
dad_send_probe(int sock, struct sockaddr_in6 *testaddr,
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
	packetlen = sizeof (struct nd_neighbor_solicit);
	cc = __xnet_sendto(sock, (char *)outpack, packetlen, 0,
	    (struct sockaddr *)solicited_mc, sizeof (*solicited_mc));
	if (cc != packetlen) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Build a solicited node multicast address for a given address.
 */
static void
in6_solmulti_addr(struct in6_addr *addr, struct in6_addr *multi)
{
	int i;

	*multi = solicited_prefix;
	for (i = 13; i < 16; i++) {
		multi->s6_addr[i] = addr->s6_addr[i];
	}
}

/*
 * Loops sending DAD probes and polling for responses.
 *
 * Returns: ICFG_SUCCESS, ICFG_FAILURE, ICFG_DAD_FOUND or ICFG_DAD_FAILED.
 */
static int
dad_loop(int sock, struct sockaddr_in6 *testaddr,
    struct sockaddr_in6 *solicited_mc, int ifindex, int retrans_timer)
{
	int time_left;	/* In milliseconds */
	struct timeval starttime;
	struct timeval curtime;
	struct pollfd fds;
	int i;
	int ret;

	/*
	 * Perform duplicate address detection sequence
	 * 1. Send a neighbor solicitation with an unspecified source
	 *    address to the solicited node MC address with the testaddr
	 *    being the target.
	 * 2. Wait for up to retrans_timer milliseconds for either a
	 *    neighbor advertisement (sent to all-nodes) or a DAD neighbor
	 *    solicitation for the testaddr.
	 * 3. Perform step 1 and 2 dup_addr_detect_transmits times.
	 */
	for (i = 0; i < dup_addr_detect_transmits; i++) {
		ret = dad_send_probe(sock, testaddr, solicited_mc);
		if (ret != ICFG_SUCCESS) {
			return (ret);
		}

		/*
		 * Track time to make sure total wait is retrans_timer
		 * even though random packet will awake poll.
		 */
		(void) gettimeofday(&starttime, NULL);
		/* CONSTCOND */
		while (1) {
			(void) gettimeofday(&curtime, NULL);
			time_left = retrans_timer -
				(curtime.tv_sec - starttime.tv_sec) * 1000 -
				(curtime.tv_usec - starttime.tv_usec) / 1000;

			if (time_left <= 0) {
				break;
			}
			fds.fd = sock;
			fds.events = POLLIN;

			switch (poll(&fds, 1, time_left)) {
			case -1:
				return (ICFG_FAILURE);
			case 0:
				/* Need loop will break */
				break;
			case 1:
				if (fds.revents & POLLIN) {
					ret = dad_receive(sock, testaddr,
					    ifindex);
					if (ret != ICFG_SUCCESS) {
						return (ret);
					}
				}
				break;
			default:
				return (ICFG_DAD_FAILED);
			}
		}
	}
	return (ICFG_SUCCESS);
}

/*
 * Configures a socket for DAD.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
static int
dad_configure_socket(int sock, int ifindex, struct sockaddr_in6 *solicited_mc)
{
	struct ipv6_mreq v6mcastr;
	int hops = IPV6_MAX_HOPS;
	int on = 1;
	int off = 0;

	/*
	 * IPV6_BOUND_PIF prevents load spreading from happening. If we
	 * just do IPV6_BOUND_IF, the packet can go out on a different
	 * interface other than "ifindex", if interface is part of
	 * a group. In that case, we will get back the copy of NS that
	 * we sent and think it is a duplicate(Switch loops back the
	 * copy on all interfaces other than the one we sent the packet on).
	 */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_PIF, (char *)&ifindex,
	    sizeof (ifindex)) < 0) {
		return (ICFG_FAILURE);
	}

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	    (char *)&hops, sizeof (hops)) < 0) {
		return (ICFG_FAILURE);
	}

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNSPEC_SRC,
	    (char *)&on, sizeof (on)) < 0) {
		return (ICFG_FAILURE);
	}

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
	    (char *)&off, sizeof (off)) < 0) {
		return (ICFG_FAILURE);
	}

	/*
	 * Enable receipt of ancillary data
	 */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
	    (char *)&on, sizeof (on)) < 0) {
		return (ICFG_FAILURE);
	}
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
	    (char *)&on, sizeof (on)) < 0) {
		return (ICFG_FAILURE);
	}
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVRTHDR,
	    (char *)&on, sizeof (on)) < 0) {
		return (ICFG_FAILURE);
	}

	/*
	 * Join the solicited node multicast address and all-nodes.
	 */
	v6mcastr.ipv6mr_multiaddr = solicited_mc->sin6_addr;
	v6mcastr.ipv6mr_interface = ifindex;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    (char *)&v6mcastr, sizeof (v6mcastr)) < 0) {
		return (ICFG_FAILURE);
	}

	v6mcastr.ipv6mr_multiaddr = all_nodes_mcast;
	v6mcastr.ipv6mr_interface = ifindex;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    (char *)&v6mcastr, sizeof (v6mcastr)) < 0) {
		return (ICFG_FAILURE);
	}
	return (ICFG_SUCCESS);
}

/*
 * Performs duplicate address detection.
 *
 * Returns: ICFG_SUCCESS, ICFG_FAILURE, ICFG_DAD_FOUND or ICFG_DAD_FAILED.
 *
 * Note: the state of the interface name is unchanged.
 */
int
dad_test(icfg_handle_t handle, uint64_t flags, struct sockaddr_in6 *testaddr)
{
	struct sockaddr_in6 solicited_mc;
	lif_ifinfo_req_t linkinfo;
	int retrans_timer = ND_RETRANS_TIMER;
	int ifindex;
	int sock;
	int syserr = 0;
	int restore_ret;
	int ret;

	/*
	 * Check the address assigned to the interface.
	 * Skip the check if IFF_NOLOCAL, IFF_NONUD, IFF_ANYCAST, or
	 * IFF_LOOPBACK. Note that IFF_NONUD turns of both NUD and DAD.
	 * DAD is not possible if not IFF_MULTICAST.
	 */
	if (flags & (IFF_NOLOCAL|IFF_LOOPBACK|IFF_NONUD|IFF_ANYCAST) ||
	    !(flags & IFF_MULTICAST)) {
		return (ICFG_SUCCESS);
	}

	/*
	 * If the address is all zeroes, then just return success.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&testaddr->sin6_addr)) {
		return (ICFG_SUCCESS);
	}

	/*
	 * Determine interface index (for IPV6_BOUND_PIF) and
	 * save the flag values so they can be restored on return.
	 */
	if ((ret = icfg_get_index(handle, &ifindex)) != ICFG_SUCCESS) {
		return (ret);
	}

	if ((ret = icfg_get_linkinfo(handle, &linkinfo)) != ICFG_SUCCESS) {
		return (ret);
	}

	if (linkinfo.lir_reachretrans != 0) {
		retrans_timer = linkinfo.lir_reachretrans;
	}

	/*
	 * Set NOLOCAL and UP flags.
	 * This prevents the use of the interface except when the user binds
	 * to unspecified IPv6 address, and sends to a link local multicast
	 * address.
	 */
	ret = icfg_set_flags(handle, flags | IFF_NOLOCAL | IFF_UP);
	if (ret != ICFG_SUCCESS) {
		return (ret);
	}

	/*
	 * Extract the address and determine the solicited node multicast
	 * address to use.
	 */
	(void) memset(&solicited_mc, 0, sizeof (solicited_mc));
	solicited_mc.sin6_family = AF_INET6;
	in6_solmulti_addr(&testaddr->sin6_addr, &solicited_mc.sin6_addr);

	/*
	 * Get a socket to use to send and receive neighbor solicitations
	 * for DAD.  Also used for ioctls below.
	 */
	if ((sock = __xnet_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		syserr = errno;
		ret = ICFG_FAILURE;
		goto restore;
	}

	ret = dad_configure_socket(sock, ifindex, &solicited_mc);
	if (ret != ICFG_SUCCESS) {
		syserr = errno;
		(void) close(sock);
		goto restore;
	}

	ret = dad_loop(sock, testaddr, &solicited_mc, ifindex,
	    retrans_timer);
	if (ret == ICFG_FAILURE) {
		syserr = errno;
	}
	(void) close(sock);

restore:
	/* Restore flags */
	if ((restore_ret = icfg_set_flags(handle, flags)) != ICFG_SUCCESS) {
		if (ret == ICFG_SUCCESS) {
			syserr = errno;
			ret = restore_ret;
		}
	}

	if (ret == ICFG_FAILURE) {
		errno = syserr;
	}

	return (ret);
}

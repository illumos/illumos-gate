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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"

#define	IF_SEPARATOR	':'

struct interface	*ifnet;

static int		setup_listen_sock(int ifindex);
static void		addrouteforif(struct interface *ifp);
static void		resetup_listen_sock(struct interface *, int);

/*
 * This is called at startup and after that, every CHECK_INTERVAL seconds or
 * when a SIGHUP is received.
 */
void
initifs(void)
{
	static char *buf = NULL;
	static uint_t maxbufsize = 0;
	int bufsize;
	int numifs;
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq lifr;
	struct lifreq *lifrp;
	int n;
	struct interface ifs;
	struct interface *ifp;
	int netmaskchange = 0;
	boolean_t changes = _B_FALSE;

	lifn.lifn_family = AF_INET6;
	lifn.lifn_flags = 0;
	if (ioctl(iocsoc, SIOCGLIFNUM, (char *)&lifn) < 0) {
		syslog(LOG_ERR, "initifs: ioctl (get interface numbers): %m");
		return;
	}
	numifs = lifn.lifn_count;
	bufsize = numifs * sizeof (struct lifreq);

	if (buf == NULL || bufsize > maxbufsize) {
		if (buf != NULL)
			free(buf);
		maxbufsize = bufsize;
		buf = (char *)malloc(maxbufsize);
		if (buf == NULL) {
			syslog(LOG_ERR, "initifs: out of memory");
			return;
		}
	}

	lifc.lifc_family = AF_INET6;
	lifc.lifc_flags = 0;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	if (ioctl(iocsoc, SIOCGLIFCONF, (char *)&lifc) < 0) {
		syslog(LOG_ERR,
		    "initifs: ioctl (get interface configuration): %m");
		return;
	}

	/*
	 * Mark all of the currently known interfaces in order to determine
	 * which of the these interfaces no longer exist.
	 */
	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next)
		ifp->int_flags |= RIP6_IFF_MARKED;
	lifrp = lifc.lifc_req;
	for (n = lifc.lifc_len / sizeof (struct lifreq); n > 0; n--, lifrp++) {
		bzero((char *)&ifs, sizeof (ifs));
		(void) strncpy(lifr.lifr_name, lifrp->lifr_name,
		    sizeof (lifr.lifr_name));
		if (ioctl(iocsoc, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
			syslog(LOG_ERR,
			    "initifs: ioctl (get interface flags): %m");
			continue;
		}
		if (!(lifr.lifr_flags & IFF_IPV6) ||
		    !(lifr.lifr_flags & IFF_MULTICAST) ||
		    (lifr.lifr_flags & IFF_LOOPBACK))
			continue;

		ifp = if_ifwithname(lifr.lifr_name);
		if (ifp != NULL)
			ifp->int_flags &= ~RIP6_IFF_MARKED;
		if (lifr.lifr_flags & IFF_POINTOPOINT)
			ifs.int_flags |= RIP6_IFF_POINTOPOINT;
		if (lifr.lifr_flags & IFF_NORTEXCH)
			ifs.int_flags |= RIP6_IFF_NORTEXCH;
		if (lifr.lifr_flags & IFF_PRIVATE)
			ifs.int_flags |= RIP6_IFF_PRIVATE;
		if (lifr.lifr_flags & IFF_UP) {
			ifs.int_flags |= RIP6_IFF_UP;
		} else {
			if (ifp != NULL) {
				if (ifp->int_flags & RIP6_IFF_UP) {
					/*
					 * If there is an transition from up to
					 * down for an exisiting interface,
					 * increment the counter.
					 */
					ifp->int_transitions++;
					changes = _B_TRUE;
				}
				if_purge(ifp);
			}
			continue;
		}

		if (ifs.int_flags & RIP6_IFF_POINTOPOINT) {
			/*
			 * For point-to-point interfaces, retrieve both the
			 * local and the remote addresses.
			 */
			if (ioctl(iocsoc, SIOCGLIFADDR, (char *)&lifr) < 0) {
				syslog(LOG_ERR,
				    "initifs: ioctl (get interface address): "
				    "%m");
				continue;
			}
			ifs.int_addr =
			    ((struct sockaddr_in6 *)&lifr.lifr_addr)->sin6_addr;
			if (ioctl(iocsoc, SIOCGLIFDSTADDR, (char *)&lifr) < 0) {
				syslog(LOG_ERR,
				    "initifs: ioctl (get destination address): "
				    "%m");
				continue;
			}
			ifs.int_dstaddr = ((struct sockaddr_in6 *)
			    &lifr.lifr_dstaddr)->sin6_addr;
			ifs.int_prefix_length = IPV6_ABITS;
		} else {
			/*
			 * For other interfaces, retreieve the prefix (including
			 * the prefix length.
			 */
			if (ioctl(iocsoc, SIOCGLIFSUBNET, (char *)&lifr) < 0) {
				syslog(LOG_ERR,
				    "initifs: ioctl (get subnet prefix): %m");
				continue;
			}
			/*
			 * This should never happen but check for it in any case
			 * since the kernel stores it as an signed integer.
			 */
			if (lifr.lifr_addrlen < 0 ||
			    lifr.lifr_addrlen > IPV6_ABITS) {
				syslog(LOG_ERR,
				    "initifs: ioctl (get subnet prefix) "
				    "returned invalid prefix length of %d",
				    lifr.lifr_addrlen);
				continue;
			}
			ifs.int_prefix_length = lifr.lifr_addrlen;
			ifs.int_addr = ((struct sockaddr_in6 *)
			    &lifr.lifr_subnet)->sin6_addr;
		}

		if (ioctl(iocsoc, SIOCGLIFMETRIC, (char *)&lifr) < 0 ||
		    lifr.lifr_metric < 0)
			ifs.int_metric = 1;
		else
			ifs.int_metric = lifr.lifr_metric + 1;

		if (ioctl(iocsoc, SIOCGLIFINDEX, (char *)&lifr) < 0) {
			syslog(LOG_ERR, "initifs: ioctl (get index): %m");
			continue;
		}
		ifs.int_ifindex = lifr.lifr_index;

		if (ioctl(iocsoc, SIOCGLIFMTU, (char *)&lifr) < 0) {
			syslog(LOG_ERR, "initifs: ioctl (get mtu): %m");
			continue;
		}

		/*
		 * If the interface's recorded MTU doesn't make sense, use
		 * IPV6_MIN_MTU instead.
		 */
		if (lifr.lifr_mtu < IPV6_MIN_MTU)
			ifs.int_mtu = IPV6_MIN_MTU;
		else
			ifs.int_mtu = lifr.lifr_mtu;

		if (ifp != NULL) {
			/*
			 * RIP6_IFF_NORTEXCH flag change by itself shouldn't
			 * cause an if_purge() call, which also purges all the
			 * routes heard off this interface. So, let's suppress
			 * changes of RIP6_IFF_NORTEXCH	in the following
			 * comparisons.
			 */
			if (ifp->int_prefix_length == ifs.int_prefix_length &&
			    ((ifp->int_flags | RIP6_IFF_NORTEXCH) ==
			    (ifs.int_flags | RIP6_IFF_NORTEXCH)) &&
			    ifp->int_metric == ifs.int_metric &&
			    ifp->int_ifindex == ifs.int_ifindex) {
				/*
				 * Now let's make sure we capture the latest
				 * value of RIP6_IFF_NORTEXCH flag.
				 */
				if (ifs.int_flags & RIP6_IFF_NORTEXCH)
					ifp->int_flags |= RIP6_IFF_NORTEXCH;
				else
					ifp->int_flags &= ~RIP6_IFF_NORTEXCH;

				if (!(ifp->int_flags & RIP6_IFF_POINTOPOINT) &&
				    IN6_ARE_ADDR_EQUAL(&ifp->int_addr,
					&ifs.int_addr))
					continue;
				if ((ifp->int_flags & RIP6_IFF_POINTOPOINT) &&
				    IN6_ARE_ADDR_EQUAL(&ifp->int_dstaddr,
					&ifs.int_dstaddr))
					continue;
			}
			if_purge(ifp);
			if (ifp->int_prefix_length != ifs.int_prefix_length)
				netmaskchange = 1;
			ifp->int_addr = ifs.int_addr;
			ifp->int_dstaddr = ifs.int_dstaddr;
			ifp->int_metric = ifs.int_metric;
			/*
			 * If there is an transition from down to up for an
			 * exisiting interface, increment the counter.
			 */
			if (!(ifp->int_flags & RIP6_IFF_UP) &&
			    (ifs.int_flags & RIP6_IFF_UP))
				ifp->int_transitions++;
			ifp->int_flags |= ifs.int_flags;
			ifp->int_prefix_length = ifs.int_prefix_length;

			/*
			 * If the interface index has changed, we may need to
			 * set up the listen socket again.
			 */
			if (ifp->int_ifindex != ifs.int_ifindex) {
				if (ifp->int_sock != -1) {
					resetup_listen_sock(ifp,
					    ifs.int_ifindex);
				}
				ifp->int_ifindex = ifs.int_ifindex;
			}

			ifp->int_mtu = ifs.int_mtu;
		} else {
			char *cp;
			int log_num;

			ifp = (struct interface *)
			    malloc(sizeof (struct interface));
			if (ifp == NULL) {
				syslog(LOG_ERR, "initifs: out of memory");
				return;
			}
			*ifp = ifs;
			ifp->int_name = ifp->int_ifbase = NULL;
			ifp->int_name =
			    (char *)malloc((size_t)strlen(lifr.lifr_name) + 1);
			if (ifp->int_name == NULL) {
				free(ifp);
				syslog(LOG_ERR, "initifs: out of memory");
				return;
			}
			(void) strcpy(ifp->int_name, lifr.lifr_name);
			ifp->int_ifbase =
			    (char *)malloc((size_t)strlen(lifr.lifr_name) + 1);
			if (ifp->int_ifbase == NULL) {
				free(ifp->int_name);
				free(ifp);
				syslog(LOG_ERR, "initifs: out of memory");
				return;
			}
			(void) strcpy(ifp->int_ifbase, lifr.lifr_name);
			cp = (char *)index(ifp->int_ifbase, IF_SEPARATOR);
			if (cp != NULL) {
				/*
				 * Verify that the value following the separator
				 * is an integer greater than zero (the only
				 * possible value for a logical interface).
				 */
				log_num = atoi((char *)(cp + 1));
				if (log_num <= 0) {
					free(ifp->int_ifbase);
					free(ifp->int_name);
					free(ifp);
					syslog(LOG_ERR,
					    "initifs: interface name %s could "
					    "not be parsed", ifp->int_name);
					return;
				}
				*cp = '\0';
			} else {
				log_num = 0;
			}
			if (log_num == 0) {
				ifp->int_sock =
				    setup_listen_sock(ifp->int_ifindex);
			} else {
				ifp->int_sock = -1;
			}
			ifp->int_next = ifnet;
			ifnet = ifp;
			traceinit(ifp);
		}
		addrouteforif(ifp);
		changes = _B_TRUE;
	}

	/*
	 * Any remaining interfaces that are still marked and which were in an
	 * up state (RIP6_IFF_UP) need to removed from the routing table.
	 */
	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
		if ((ifp->int_flags & (RIP6_IFF_MARKED | RIP6_IFF_UP)) ==
		    (RIP6_IFF_MARKED | RIP6_IFF_UP)) {
			if_purge(ifp);
			ifp->int_flags &= ~RIP6_IFF_MARKED;
			changes = _B_TRUE;
		}
	}
	if (netmaskchange)
		rtchangeall();
	if (supplier & changes)
		dynamic_update((struct interface *)NULL);
}

static void
addrouteforif(struct interface *ifp)
{
	struct rt_entry *rt;
	struct in6_addr *dst;

	if (ifp->int_flags & RIP6_IFF_POINTOPOINT)
		dst = &ifp->int_dstaddr;
	else
		dst = &ifp->int_addr;

	rt = rtlookup(dst, ifp->int_prefix_length);

	if (rt != NULL) {
		if (rt->rt_state & RTS_INTERFACE)
			return;
		rtdelete(rt);
	}
	rtadd(dst, &ifp->int_addr, ifp->int_prefix_length, ifp->int_metric, 0,
	    _B_TRUE, ifp);
}

static int
setup_listen_sock(int ifindex)
{
	int sock;
	struct sockaddr_in6 sin6;
	uint_t hops;
	struct ipv6_mreq allrouters_mreq;
	int on = 1;
	int off = 0;
	int recvsize;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock == -1)
		goto sock_fail;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, (char *)&ifindex,
	    sizeof (ifindex)) < 0) {
		syslog(LOG_ERR,
		    "setup_listen_sock: setsockopt: IPV6_BOUND_IF: %m");
		goto sock_fail;
	}

	hops = IPV6_MAX_HOPS;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&hops,
	    sizeof (hops)) < 0) {
		syslog(LOG_ERR,
		    "setup_listen_sock: setsockopt: IPV6_UNICAST_HOPS: %m");
		goto sock_fail;
	}

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&hops,
	    sizeof (hops)) < 0) {
		syslog(LOG_ERR,
		    "setup_listen_sock: setsockopt: IPV6_MULTICAST_HOPS: %m");
		goto sock_fail;
	}

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&off,
	    sizeof (off)) < 0) {
		syslog(LOG_ERR,
		    "setup_listen_sock: setsockopt: IPV6_MULTICAST_LOOP: %m");
		goto sock_fail;
	}

	allrouters_mreq.ipv6mr_multiaddr = allrouters_in6;
	allrouters_mreq.ipv6mr_interface = ifindex;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    (char *)&allrouters_mreq, sizeof (allrouters_mreq)) < 0) {
		if (errno != EADDRINUSE) {
			syslog(LOG_ERR,
			    "setup_listen_sock: setsockopt: "
			    "IPV6_JOIN_GROUP: %m");
			goto sock_fail;
		}
	}

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, (char *)&on,
	    sizeof (off)) < 0) {
		syslog(LOG_ERR,
		    "setup_listen_sock: setsockopt: IPV6_RECVHOPLIMIT: %m");
		goto sock_fail;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
	    sizeof (on)) < 0) {
		syslog(LOG_ERR,
		    "setup_listen_sock: setsockopt: SO_REUSEADDR: %m");
		goto sock_fail;
	}

	recvsize = RCVBUFSIZ;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&recvsize,
	    sizeof (int)) < 0) {
		syslog(LOG_ERR, "setup_listen_sock: setsockopt: SO_RCVBUF: %m");
		goto sock_fail;
	}

	bzero((char *)&sin6, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = rip6_port;
	if (bind(sock, (struct sockaddr *)&sin6, sizeof (sin6)) < 0) {
		syslog(LOG_ERR, "setup_listen_sock: bind: %m");
		goto sock_fail;
	}

	poll_ifs_num++;
	if (poll_ifs == NULL) {
		poll_ifs = (struct pollfd *)
		    malloc(max_poll_ifs * sizeof (struct pollfd));
	} else if (poll_ifs_num > max_poll_ifs) {
		max_poll_ifs *= 2;
		poll_ifs = (struct pollfd *)realloc((char *)poll_ifs,
		    max_poll_ifs * sizeof (struct pollfd));
	}
	if (poll_ifs == NULL) {
		syslog(LOG_ERR, "setup_listen_sock: out of memory");
		goto sock_fail;
	}

	poll_ifs[poll_ifs_num - 1].fd = sock;
	poll_ifs[poll_ifs_num - 1].events = POLLIN;
	return (sock);

sock_fail:
	if (sock > 0)
		(void) close(sock);
	return (-1);
}

/*
 * resetup_listen_sock is primarily used in the case where a tunnel was
 * plumbed, unplumbed, then plumbed again.  This would cause the binding set by
 * IPV6_BOUND_IF to be useless, and sends to the associated socket will be
 * transmitted on the wrong interface.  resetup_listen_sock
 *	closes the socket,
 *	removes the socket from poll_ifs[]
 *	plugs the hole in poll_ifs[]
 *	calls setup_listen_sock to set up the socket again
 */
void
resetup_listen_sock(struct interface *ifp, int newindex)
{
	int i;

	(void) close(ifp->int_sock);

	/* Remove socket from poll_ifs[]. */
	for (i = poll_ifs_num - 1; i >= 0; i--) {

		if (poll_ifs[i].fd == ifp->int_sock) {

			poll_ifs[i].fd = 0;
			poll_ifs[i].events = 0;

			/*
			 * Remove hole in poll_ifs.  Possibly exchange
			 * poll_ifs[i] with poll_ifs[poll_ifs_num-1].
			 */
			if (i != poll_ifs_num - 1) {
				poll_ifs[i] = poll_ifs[poll_ifs_num - 1];
				poll_ifs[poll_ifs_num - 1].fd = 0;
				poll_ifs[poll_ifs_num - 1].events = 0;
			}
			poll_ifs_num--;

			/* Now set everything up again. */
			ifp->int_sock = setup_listen_sock(newindex);
			break;
		}
	}
}

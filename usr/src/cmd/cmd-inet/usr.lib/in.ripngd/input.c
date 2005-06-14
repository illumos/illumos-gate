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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routing Table Management Daemon
 */
#include "defs.h"

static char	buf1[INET6_ADDRSTRLEN];
static char	buf2[INET6_ADDRSTRLEN];

static void	rip_input(struct sockaddr_in6 *from, int size, uint_t hopcount,
    struct interface *ifp);

/*
 * Return a pointer to the specified option buffer.
 * If not found return NULL.
 */
static void *
find_ancillary(struct msghdr *rmsg, int cmsg_type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(rmsg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(rmsg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == cmsg_type) {
			return (CMSG_DATA(cmsg));
		}
	}
	return (NULL);
}

/*
 * Read a packet and passes it to rip_input() for processing.
 */
void
in_data(struct interface *ifp)
{
	struct sockaddr_in6 from;
	int len;
	struct msghdr rmsg;
	struct iovec iov;
	uchar_t *hopcntopt;

	iov.iov_base = packet;
	iov.iov_len = IPV6_MAX_PACKET;
	rmsg.msg_name = &from;
	rmsg.msg_namelen = (socklen_t)sizeof (from);
	rmsg.msg_iov = &iov;
	rmsg.msg_iovlen = 1;
	rmsg.msg_control = control;
	rmsg.msg_controllen = IPV6_MAX_PACKET;

	if ((len = recvmsg(ifp->int_sock, &rmsg, 0)) < 0) {
		/*
		 * Only syslog if a true error occurred.
		 */
		if (errno != EINTR)
			syslog(LOG_ERR, "in_data: recvmsg: %m");
		return;
	}
	if (len == 0)
		return;

	if (tracing & INPUT_BIT) {
		(void) inet_ntop(from.sin6_family, &from.sin6_addr, buf1,
		    sizeof (buf1));
	}

	/* Ignore packets > 64k or control buffers that don't fit */
	if (rmsg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		if (tracing & INPUT_BIT) {
			(void) fprintf(stderr,
			    "Truncated message: msg_flags 0x%x from %s\n",
			    rmsg.msg_flags, buf1);
		}
		return;
	}

	if ((hopcntopt = find_ancillary(&rmsg, IPV6_HOPLIMIT)) == NULL) {
		if (tracing & INPUT_BIT) {
			(void) fprintf(stderr, "Unknown hop limit from %s\n",
			    buf1);
		}
		return;
	}
	rip_input(&from, len, *(uint_t *)hopcntopt, ifp);
}

/*
 * Process a newly received packet.
 */
static void
rip_input(struct sockaddr_in6 *from, int size, uint_t hopcount,
    struct interface *ifp)
{
	struct rt_entry *rt;
	struct netinfo6 *n;
	int newsize;
	boolean_t changes = _B_FALSE;
	int answer = supplier;
	struct in6_addr prefix;
	struct in6_addr nexthop;
	struct in6_addr *gate;
	boolean_t foundnexthop = _B_FALSE;
	struct sioc_addrreq sa;
	struct sockaddr_in6 *sin6;

	TRACE_INPUT(ifp, from, size);
	if (tracing & INPUT_BIT) {
		(void) inet_ntop(from->sin6_family, (void *)&from->sin6_addr,
		    buf1, sizeof (buf1));
	}

	/*
	 * If the packet is recevied on an interface with IFF_NORTEXCH flag set,
	 * we ignore the packet.
	 */
	if (ifp->int_flags & RIP6_IFF_NORTEXCH) {
		if (tracing & INPUT_BIT) {
			(void) fprintf(ftrace,
			    "Ignore received RIPng packet on %s "
			    "(no route exchange on interface)\n",
			    ifp->int_name);
			(void) fflush(ftrace);
		}
		return;
	}
	if (msg->rip6_vers != RIPVERSION6) {
		if (tracing & INPUT_BIT) {
			(void) fprintf(ftrace,
			    "Bad version number %d in packet from %s\n",
			    msg->rip6_vers, buf1);
			(void) fflush(ftrace);
		}
		return;
	}
	if (ntohs(msg->rip6_res1) != 0) {
		if (tracing & INPUT_BIT) {
			(void) fprintf(ftrace,
			    "Non-zero reserved octets found in packet from "
			    "%s\n",
			    buf1);
			(void) fflush(ftrace);
		}
	}

	switch (msg->rip6_cmd) {

	case RIPCMD6_REQUEST:		/* multicasted request */
		ifp->int_ipackets++;
		newsize = 0;

		/*
		 * Adjust size by the length of the command, version and
		 * reserved fields (which are in total 32-bit aligned).
		 */
		size -= sizeof (msg->rip6_cmd) + sizeof (msg->rip6_vers) +
		    sizeof (msg->rip6_res1);

		/*
		 * From section 2.4.1 of RFC 2080:
		 *
		 *	If there is exactly one entry in the request with a
		 *	destination prefix of zero, a prefix length of zero and
		 *	an infinite metric, then supply the entire routing
		 *	table.
		 */
		n = msg->rip6_nets;
		if (size == sizeof (struct netinfo6) &&
		    n->rip6_prefix_length == 0 &&
		    n->rip6_metric == HOPCNT_INFINITY) {
			rtcreate_prefix(&n->rip6_prefix, &prefix,
			    n->rip6_prefix_length);
			if (IN6_IS_ADDR_UNSPECIFIED(&prefix)) {
				supply(from, ifp, 0,
				    from->sin6_port == rip6_port);
				return;
			}
		}
		for (; size >= sizeof (struct netinfo6);
		    size -= sizeof (struct netinfo6), n++) {
			if (n->rip6_prefix_length > IPV6_ABITS) {
				if (tracing & INPUT_BIT) {
					(void) fprintf(ftrace,
					    "Bad prefix length %d in request "
					    "from %s\n",
					    n->rip6_prefix_length, buf1);
					(void) fflush(ftrace);
				}
				continue;
			}
			if (IN6_IS_ADDR_LINKLOCAL(&n->rip6_prefix) ||
			    IN6_IS_ADDR_MULTICAST(&n->rip6_prefix)) {
				if (tracing & INPUT_BIT) {
					(void) fprintf(ftrace,
					    "Bad prefix %s in request from "
					    "%s\n",
					    inet_ntop(AF_INET6,
						(void *)&n->rip6_prefix, buf2,
						sizeof (buf2)),
					    buf1);
					(void) fflush(ftrace);
				}
				continue;
			}
			rtcreate_prefix(&n->rip6_prefix, &prefix,
			    n->rip6_prefix_length);
			rt = rtlookup(&prefix, n->rip6_prefix_length);

			n->rip6_metric = (rt == NULL ?
			    HOPCNT_INFINITY :
			    min(rt->rt_metric, HOPCNT_INFINITY));
			newsize += sizeof (struct netinfo6);
		}
		if (size > 0) {
			if (tracing & INPUT_BIT) {
				(void) fprintf(ftrace,
				    "Ignoring %d octets of trailing data in "
				    "request from %s\n",
				    size, buf1);
				(void) fflush(ftrace);
			}
		}
		if (answer && newsize > 0) {
			/*
			 * Adjust newsize by the length of the command, version
			 * and reserved fields (which are in total 32-bit
			 * aligned).
			 */
			msg->rip6_cmd = RIPCMD6_RESPONSE;
			newsize += sizeof (msg->rip6_cmd) +
			    sizeof (msg->rip6_vers) + sizeof (msg->rip6_res1);
			sendpacket(from, ifp, newsize, 0);
		}
		return;

	case RIPCMD6_RESPONSE:
		if (hopcount != IPV6_MAX_HOPS) {
			if (tracing & INPUT_BIT) {
				(void) fprintf(ftrace,
				    "Bad hop count %d in response from %s\n",
				    hopcount, buf1);
				(void) fflush(ftrace);
			}
			return;
		}

		if (from->sin6_port != rip6_port) {
			if (tracing & INPUT_BIT) {
				(void) fprintf(ftrace,
				    "Bad source port %d in response from %s\n",
				    from->sin6_port, buf1);
				(void) fflush(ftrace);
			}
			return;
		}

		if (!IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr)) {
			if (tracing & INPUT_BIT) {
				(void) fprintf(ftrace,
				    "Bad source address (not link-local) in "
				    "response from %s\n", buf1);
				(void) fflush(ftrace);
			}
			return;
		}
		ifp->int_ipackets++;

		/*
		 * Adjust size by the length of the command, version and
		 * reserved fields (which are in total 32-bit aligned).
		 */
		size -= sizeof (msg->rip6_cmd) + sizeof (msg->rip6_vers) +
		    sizeof (msg->rip6_res1);
		for (n = msg->rip6_nets;
		    supplier && size >= sizeof (struct netinfo6);
		    size -= sizeof (struct netinfo6), n++) {
			/*
			 * From section 2.1.1 of RFC 2080:
			 *
			 * This is a next hop RTE if n->rip6_metric is set to
			 * HOPCNT_NEXTHOP.  If the next hop address (which is
			 * placed in the prefix field of this special RTE) is
			 * unspecified or is not a link-local address, then use
			 * the originator's address instead (effectively turning
			 * off next hop RTE processing.)
			 */
			if (n->rip6_metric == HOPCNT_NEXTHOP) {
				/*
				 * First check to see if the unspecified address
				 * was given as the next hop address.  This is
				 * the correct way of specifying the end of use
				 * of a next hop address.
				 */
				if (IN6_IS_ADDR_UNSPECIFIED(&n->rip6_prefix)) {
					foundnexthop = _B_FALSE;
					continue;
				}
				/*
				 * A next hop address that is not a link-local
				 * address is treated as the unspecified one.
				 * Trace this event if input tracing is enabled.
				 */
				if (!IN6_IS_ADDR_LINKLOCAL(&n->rip6_prefix)) {
					foundnexthop = _B_FALSE;
					if (tracing & INPUT_BIT) {
						(void) fprintf(ftrace,
						    "Bad next hop %s in "
						    "response from %s\n",
						    inet_ntop(AF_INET6,
							(void *)&n->rip6_prefix,
							buf2, sizeof (buf2)),
						    buf1);
					}
					continue;
				}
				/*
				 * Verify that the next hop address is not one
				 * of our own.
				 */
				sin6 = (struct sockaddr_in6 *)&sa.sa_addr;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_addr = n->rip6_prefix;
				if (ioctl(iocsoc, SIOCTMYADDR,
				    (char *)&sa) < 0) {
					syslog(LOG_ERR,
					    "rip_input: "
					    "ioctl (verify my address): %m");
					return;
				}
				if (sa.sa_res != 0) {
					foundnexthop = _B_FALSE;
					if (tracing & INPUT_BIT) {
						(void) fprintf(ftrace,
						    "Bad next hop %s is self "
						    "in response from %s\n",
						    inet_ntop(AF_INET6,
							(void *)&n->rip6_prefix,
							buf2, sizeof (buf2)),
						    buf1);
					}
					continue;
				}
				foundnexthop = _B_TRUE;
				nexthop = n->rip6_prefix;
				continue;
			}
			if (foundnexthop)
				gate = &nexthop;
			else
				gate = &from->sin6_addr;

			if (n->rip6_metric > HOPCNT_INFINITY ||
			    n->rip6_metric < 1) {
				if (tracing & INPUT_BIT) {
					(void) fprintf(ftrace,
					    "Bad metric %d in response from "
					    "%s\n",
					    n->rip6_metric, buf1);
					(void) fflush(ftrace);
				}
				continue;
			}
			if (n->rip6_prefix_length > IPV6_ABITS) {
				if (tracing & INPUT_BIT) {
					(void) fprintf(ftrace,
					    "Bad prefix length %d in response "
					    "from %s\n",
					    n->rip6_prefix_length, buf1);
					(void) fflush(ftrace);
				}
				continue;
			}

			if (IN6_IS_ADDR_LINKLOCAL(&n->rip6_prefix) ||
			    IN6_IS_ADDR_MULTICAST(&n->rip6_prefix)) {
				if (tracing & INPUT_BIT) {

					(void) fprintf(ftrace,
					    "Bad prefix %s in response from "
					    "%s\n",
					    inet_ntop(AF_INET6,
						(void *)&n->rip6_prefix, buf2,
						sizeof (buf2)),
					    buf1);
					(void) fflush(ftrace);
				}
				continue;
			}
			/* Include metric for incoming interface */
			n->rip6_metric += IFMETRIC(ifp);

			rtcreate_prefix(&n->rip6_prefix, &prefix,
			    n->rip6_prefix_length);
			rt = rtlookup(&prefix, n->rip6_prefix_length);
			if (rt == NULL) {
				if (n->rip6_metric < HOPCNT_INFINITY) {
					rtadd(&prefix,
					    gate, n->rip6_prefix_length,
					    n->rip6_metric, n->rip6_route_tag,
					    _B_FALSE, ifp);
					changes = _B_TRUE;
				}
				continue;
			}

			/*
			 * If the supplied metric is at least HOPCNT_INFINITY
			 * and the current metric of the route is
			 * HOPCNT_INFINITY, then this particular RTE is ignored.
			 */
			if (n->rip6_metric >= HOPCNT_INFINITY &&
			    rt->rt_metric == HOPCNT_INFINITY)
				continue;

			/*
			 * From section 2.4.2 of RFC 2080:
			 *
			 * Update if any one of the following is true
			 *
			 *	1) From current gateway and a different metric.
			 *	2) From current gateway and a different index.
			 *	3) A shorter (smaller) metric.
			 *	4) Equivalent metric and an age at least
			 *	   one-half of EXPIRE_TIME.
			 *
			 * Otherwise, update timer for the interface on which
			 * the packet arrived.
			 */
			if (IN6_ARE_ADDR_EQUAL(gate, &rt->rt_router)) {
				if (n->rip6_metric != rt->rt_metric ||
				    rt->rt_ifp != ifp) {
					rtchange(rt, gate, n->rip6_metric, ifp);
					changes = _B_TRUE;
				} else if (n->rip6_metric < HOPCNT_INFINITY) {
					rt->rt_timer = 0;
				}
			} else if (n->rip6_metric < rt->rt_metric ||
			    (rt->rt_timer > (EXPIRE_TIME / 2) &&
				rt->rt_metric == n->rip6_metric)) {
				rtchange(rt, gate, n->rip6_metric, ifp);
				changes = _B_TRUE;
			}
		}
		if (changes && supplier)
			dynamic_update(ifp);
		return;

	default:
		if (tracing & INPUT_BIT) {
			(void) fprintf(ftrace,
			    "Bad command %d in packet from %s\n",
			    msg->rip6_cmd, buf1);
			(void) fflush(ftrace);
		}
		return;
	}
}

/*
 * If changes have occurred, and if we have not sent a multicast
 * recently, send a dynamic update.  This update is sent only
 * on interfaces other than the one on which we received notice
 * of the change.  If we are within MIN_WAIT_TIME of a full update,
 * don't bother sending; if we just sent a dynamic update
 * and set a timer (nextmcast), delay until that time.
 * If we just sent a full update, delay the dynamic update.
 * Set a timer for a randomized value to suppress additional
 * dynamic updates until it expires; if we delayed sending
 * the current changes, set needupdate.
 */
void
dynamic_update(struct interface *ifp)
{
	int delay;

	if (now.tv_sec - lastfullupdate.tv_sec >=
	    supplyinterval - MIN_WAIT_TIME)
		return;

	if (now.tv_sec - lastmcast.tv_sec >= MIN_WAIT_TIME &&
	    /* BEGIN CSTYLED */
	    timercmp(&nextmcast, &now, <)) {
	    /* END CSTYLED */
		TRACE_ACTION("send dynamic update",
		    (struct rt_entry *)NULL);
		supplyall(&allrouters, RTS_CHANGED, ifp, _B_TRUE);
		lastmcast = now;
		needupdate = _B_FALSE;
		nextmcast.tv_sec = 0;
	} else {
		needupdate = _B_TRUE;
		TRACE_ACTION("delay dynamic update",
		    (struct rt_entry *)NULL);
	}

	if (nextmcast.tv_sec == 0) {
		delay = GET_RANDOM(MIN_WAIT_TIME * 1000000,
		    MAX_WAIT_TIME * 1000000);
		if (tracing & ACTION_BIT) {
			(void) fprintf(ftrace,
			    "inhibit dynamic update for %d msec\n",
			    delay / 1000);
			(void) fflush(ftrace);
		}
		nextmcast.tv_sec = delay / 1000000;
		nextmcast.tv_usec = delay % 1000000;
		timevaladd(&nextmcast, &now);
		/*
		 * If the next possibly dynamic update
		 * is within MIN_WAIT_TIME of the next full
		 * update, force the delay past the full
		 * update, or we might send a dynamic update
		 * just before the full update.
		 */
		if (nextmcast.tv_sec >
		    lastfullupdate.tv_sec + supplyinterval - MIN_WAIT_TIME) {
			nextmcast.tv_sec =
			    lastfullupdate.tv_sec + supplyinterval + 1;
		}
	}
}

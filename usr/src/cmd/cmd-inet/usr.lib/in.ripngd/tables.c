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

boolean_t	install = _B_TRUE;	/* update kernel routing table */
struct rthash	*net_hashes[IPV6_ABITS + 1];

/*
 * Size of routing socket message used by in.ripngd which includes the header,
 * space for the RTA_DST, RTA_GATEWAY and RTA_NETMASK (each a sockaddr_in6)
 * plus space for the RTA_IFP (a sockaddr_dl).
 */
#define	RIPNG_RTM_MSGLEN	sizeof (struct rt_msghdr) +	\
				sizeof (struct sockaddr_in6) +	\
				sizeof (struct sockaddr_in6) +	\
				sizeof (struct sockaddr_in6) +	\
				sizeof (struct sockaddr_dl)

static int	rtmseq;				/* rtm_seq sequence number */
static int	rtsock;				/* Routing socket */
static struct	rt_msghdr	*rt_msg;	/* Routing socket message */
static struct	sockaddr_in6	*rta_dst;	/* RTA_DST sockaddr */
static struct	sockaddr_in6	*rta_gateway;	/* RTA_GATEWAY sockaddr */
static struct	sockaddr_in6	*rta_netmask;	/* RTA_NETMASK sockaddr */
static struct	sockaddr_dl	*rta_ifp;	/* RTA_IFP sockaddr */

/* simulate vax insque and remque instructions. */

typedef struct vq {
	caddr_t	 fwd, back;
} vq_t;

#define	insque(e, p)	((vq_t *)(e))->back = (caddr_t)(p); \
			((vq_t *)(e))->fwd = \
				(caddr_t)((vq_t *)((vq_t *)(p))->fwd); \
			((vq_t *)((vq_t *)(p))->fwd)->back = (caddr_t)(e); \
			((vq_t *)(p))->fwd = (caddr_t)(e);

#define	remque(e)	((vq_t *)((vq_t *)(e))->back)->fwd =  \
				(caddr_t)((vq_t *)(e))->fwd; \
			((vq_t *)((vq_t *)(e))->fwd)->back = \
				(caddr_t)((vq_t *)(e))->back; \
			((vq_t *)(e))->fwd = NULL; \
			((vq_t *)(e))->back = NULL;

static void
log_change(int level, struct rt_entry *orig, struct rt_entry *new)
{
	char buf1[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];
	char buf3[INET6_ADDRSTRLEN];

	(void) inet_ntop(AF_INET6, (void *) &new->rt_dst, buf1, sizeof (buf1));
	(void) inet_ntop(AF_INET6, (void *) &orig->rt_router, buf2,
	    sizeof (buf2));
	(void) inet_ntop(AF_INET6, (void *) &new->rt_router, buf3,
	    sizeof (buf3));

	syslog(level, "\tdst %s from gw %s if %s to gw %s if %s metric %d",
	    buf1, buf2,
	    (orig->rt_ifp != NULL && orig->rt_ifp->int_name != NULL) ?
		orig->rt_ifp->int_name : "(noname)",
	    buf3,
	    (new->rt_ifp != NULL && new->rt_ifp->int_name != NULL) ?
		new->rt_ifp->int_name : "(noname)", new->rt_metric);
}

static void
log_single(int level, struct rt_entry *rt)
{
	char buf1[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];

	(void) inet_ntop(AF_INET6, (void *)&rt->rt_dst, buf1, sizeof (buf1));
	(void) inet_ntop(AF_INET6, (void *)&rt->rt_router, buf2, sizeof (buf2));

	syslog(level, "\tdst %s gw %s if %s metric %d",
	    buf1, buf2,
	    (rt->rt_ifp != NULL && rt->rt_ifp->int_name != NULL) ?
		rt->rt_ifp->int_name : "(noname)",
	    rt->rt_metric);
}

/*
 * Computes a hash by XOR-ing the (up to sixteen) octets that make up an IPv6
 * address.  This function assumes that that there are no one-bits in the
 * address beyond the prefix length.
 */
static uint8_t
rthash(struct in6_addr *dst, int prefix_length)
{
	uint8_t val = 0;
	int i;

	for (i = 0; prefix_length > 0; prefix_length -= 8, i++)
		val ^= dst->s6_addr[i];
	return (val);
}

/*
 * Given a prefix length, fill in the struct in6_addr representing an IPv6
 * netmask.
 */
static void
rtmask_to_bits(uint_t prefix_length, struct in6_addr *prefix)
{
	uint_t mask = 0xff;
	int i;

	bzero((caddr_t)prefix, sizeof (struct in6_addr));
	for (i = 0; prefix_length >= 8; prefix_length -= 8, i++)
		prefix->s6_addr[i] = 0xff;
	mask = (mask << (8 - prefix_length));
	if (mask != 0)
		prefix->s6_addr[i] = mask;
}

void
rtcreate_prefix(struct in6_addr *p1, struct in6_addr *dst, int bits)
{
	uchar_t mask;
	int j;

	for (j = 0; bits >= 8; bits -= 8, j++)
		dst->s6_addr[j] = p1->s6_addr[j];

	if (bits != 0) {
		mask = 0xff << (8 - bits);
		dst->s6_addr[j] = p1->s6_addr[j] & mask;
		j++;
	}

	for (; j < 16; j++)
		dst->s6_addr[j] = 0;
}

/*
 * Lookup dst in the tables for an exact match.
 */
struct rt_entry *
rtlookup(struct in6_addr *dst, int prefix_length)
{
	struct rt_entry *rt;
	struct rthash *rh;
	uint_t	hash;

	if (net_hashes[prefix_length] == NULL)
		return (NULL);

	hash = rthash(dst, prefix_length);

	rh = &net_hashes[prefix_length][hash & ROUTEHASHMASK];

	for (rt = rh->rt_forw; rt != (struct rt_entry *)rh; rt = rt->rt_forw) {
		if (rt->rt_hash != hash)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&rt->rt_dst, dst) &&
		    rt->rt_prefix_length == prefix_length)
			return (rt);
	}
	return (NULL);
}

/*
 * Given an IPv6 prefix (destination and prefix length), a gateway, an
 * interface name and route flags, send down the requested command returning
 * the return value and errno (in the case of error) from the write() on the
 * routing socket.
 */
static int
rtcmd(uchar_t type, struct in6_addr *dst, struct in6_addr *gateway,
    uint_t prefix_length, char *name, int flags)
{
	int rlen;

	rta_ifp->sdl_index = if_nametoindex(name);
	if (rta_ifp->sdl_index == 0)
		return (-1);

	rta_dst->sin6_addr = *dst;
	rta_gateway->sin6_addr = *gateway;
	rtmask_to_bits(prefix_length, &rta_netmask->sin6_addr);

	rt_msg->rtm_type = type;
	rt_msg->rtm_flags = flags;
	rt_msg->rtm_seq = ++rtmseq;
	rlen = write(rtsock, rt_msg, RIPNG_RTM_MSGLEN);
	if (rlen >= 0 && rlen < RIPNG_RTM_MSGLEN) {
		syslog(LOG_ERR,
		    "rtcmd: write to routing socket got only %d for rlen\n",
		    rlen);
	}
	return (rlen);
}

void
rtadd(struct in6_addr *dst, struct in6_addr *gate, int prefix_length,
    int metric, int tag, boolean_t ifroute, struct interface *ifp)
{
	struct rt_entry *rt;
	struct rthash *rh;
	uint_t hash;
	struct in6_addr pdst;
	int rlen;

	if (metric >= HOPCNT_INFINITY)
		return;

	if (net_hashes[prefix_length] == NULL) {
		struct rthash *trh;

		rh = (struct rthash *)
		    calloc(ROUTEHASHSIZ, sizeof (struct rt_entry));
		if (rh == NULL)
			return;
		for (trh = rh; trh < &rh[ROUTEHASHSIZ]; trh++)
			trh->rt_forw = trh->rt_back = (struct rt_entry *)trh;
		net_hashes[prefix_length] = rh;
	}
	rtcreate_prefix(dst, &pdst, prefix_length);

	hash = rthash(&pdst, prefix_length);
	rh = &net_hashes[prefix_length][hash & ROUTEHASHMASK];
	rt = (struct rt_entry *)malloc(sizeof (*rt));
	if (rt == NULL) {
		/*
		 * In the event of an allocation failure, log the error and
		 * continue since on the next update another attempt will be
		 * made.
		 */
		syslog(LOG_ERR, "rtadd: malloc: %m");
		return;
	}
	rt->rt_hash = hash;
	rt->rt_dst = pdst;
	rt->rt_prefix_length = prefix_length;
	rt->rt_router = *gate;
	rt->rt_metric = metric;
	rt->rt_tag = tag;
	rt->rt_timer = 0;
	rt->rt_flags = RTF_UP;
	if (prefix_length == IPV6_ABITS)
		rt->rt_flags |= RTF_HOST;
	rt->rt_state = RTS_CHANGED;
	if (ifroute) {
		rt->rt_state |= RTS_INTERFACE;
		if (ifp->int_flags & RIP6_IFF_PRIVATE)
			rt->rt_state |= RTS_PRIVATE;
	} else {
		rt->rt_flags |= RTF_GATEWAY;
	}
	rt->rt_ifp = ifp;

	insque(rt, rh);
	TRACE_ACTION("ADD", rt);
	/*
	 * If the RTM_ADD fails because the gateway is unreachable
	 * from this host, discard the entry.  This should never
	 * happen.
	 */
	if (install && (rt->rt_state & RTS_INTERFACE) == 0) {
		rlen = rtcmd(RTM_ADD, &rt->rt_dst, &rt->rt_router,
		    prefix_length, ifp->int_name, rt->rt_flags);
		if (rlen < 0) {
			if (errno != EEXIST) {
				syslog(LOG_ERR, "rtadd: RTM_ADD: %m");
				log_single(LOG_ERR, rt);
			}
			if (errno == ENETUNREACH) {
				TRACE_ACTION("DELETE", rt);
				remque(rt);
				free((char *)rt);
			}
		} else if (rlen < RIPNG_RTM_MSGLEN) {
			log_single(LOG_ERR, rt);
		}
	}
}

/*
 * Handle the case when the metric changes but the gateway is the same (or the
 * interface index associated with the gateway changes), or when both gateway
 * and metric changes, or when only the gateway changes but the existing route
 * is more than one-half of EXPIRE_TIME in age. Note that routes with metric >=
 * HOPCNT_INFINITY are not in the kernel.
 */
void
rtchange(struct rt_entry *rt, struct in6_addr *gate, short metric,
    struct interface *ifp)
{
	boolean_t dokern = _B_FALSE;
	boolean_t dokerndelete;
	boolean_t metricchanged = _B_FALSE;
	int oldmetric;
	struct rt_entry oldroute;
	int rlen;

	if (metric >= HOPCNT_INFINITY) {
		rtdown(rt);
		return;
	}

	if (!IN6_ARE_ADDR_EQUAL(&rt->rt_router, gate) || rt->rt_ifp != ifp)
		dokern = _B_TRUE;
	oldmetric = rt->rt_metric;
	if (oldmetric >= HOPCNT_INFINITY)
		dokerndelete = _B_FALSE;
	else
		dokerndelete = dokern;
	if (metric != rt->rt_metric)
		metricchanged = _B_TRUE;
	rt->rt_timer = 0;
	if (dokern || metricchanged) {
		TRACE_ACTION("CHANGE FROM", rt);
		if ((rt->rt_state & RTS_INTERFACE) && metric != 0) {
			rt->rt_state &= ~RTS_INTERFACE;
			if (rt->rt_ifp != NULL) {
				syslog(LOG_ERR,
				    "rtchange: changing route from "
				    "interface %s (timed out)",
				    (rt->rt_ifp->int_name != NULL) ?
					rt->rt_ifp->int_name : "(noname)");
			} else {
				syslog(LOG_ERR,
				    "rtchange: "
				    "changing route no interface for route");
			}
		}
		if (dokern) {
			oldroute = *rt;
			rt->rt_router = *gate;
			rt->rt_ifp = ifp;
		}
		rt->rt_metric = metric;
		if (!(rt->rt_state & RTS_INTERFACE))
			rt->rt_flags |= RTF_GATEWAY;
		else
			rt->rt_flags &= ~RTF_GATEWAY;
		rt->rt_state |= RTS_CHANGED;
		TRACE_ACTION("CHANGE TO", rt);
	}
	if (install && (rt->rt_state & RTS_INTERFACE) == 0) {
		if (dokerndelete) {
			rlen = rtcmd(RTM_ADD, &rt->rt_dst, &rt->rt_router,
			    rt->rt_prefix_length, rt->rt_ifp->int_name,
			    rt->rt_flags);
			if (rlen < 0) {
				if (errno != EEXIST) {
					syslog(LOG_ERR,
					    "rtchange: RTM_ADD: %m");
					log_change(LOG_ERR, rt,
					    (struct rt_entry *)&oldroute);
				}
			} else if (rlen < RIPNG_RTM_MSGLEN) {
				log_change(LOG_ERR, rt,
				    (struct rt_entry *)&oldroute);
			}

			rlen = rtcmd(RTM_DELETE, &oldroute.rt_dst,
			    &oldroute.rt_router, oldroute.rt_prefix_length,
			    oldroute.rt_ifp->int_name, oldroute.rt_flags);
			if (rlen < 0) {
				syslog(LOG_ERR, "rtchange: RTM_DELETE: %m");
				log_change(LOG_ERR, rt,
				    (struct rt_entry *)&oldroute);
			} else if (rlen < RIPNG_RTM_MSGLEN) {
				log_change(LOG_ERR, rt,
				    (struct rt_entry *)&oldroute);
			}
		} else if (dokern || oldmetric >= HOPCNT_INFINITY) {
			rlen = rtcmd(RTM_ADD, &rt->rt_dst, &rt->rt_router,
			    rt->rt_prefix_length, ifp->int_name, rt->rt_flags);
			if (rlen < 0 && errno != EEXIST) {
				syslog(LOG_ERR, "rtchange: RTM_ADD: %m");
				log_change(LOG_ERR, rt,
				    (struct rt_entry *)&oldroute);
			} else if (rlen < RIPNG_RTM_MSGLEN) {
				log_change(LOG_ERR, rt,
				    (struct rt_entry *)&oldroute);
			}
		}
	}
}

void
rtdown(struct rt_entry *rt)
{
	int rlen;

	if (rt->rt_metric != HOPCNT_INFINITY) {
		TRACE_ACTION("DELETE", rt);
		if (install && (rt->rt_state & RTS_INTERFACE) == 0) {
			rlen = rtcmd(RTM_DELETE, &rt->rt_dst,
			    &rt->rt_router, rt->rt_prefix_length,
			    rt->rt_ifp->int_name, rt->rt_flags);
			if (rlen < 0) {
				syslog(LOG_ERR, "rtdown: RTM_DELETE: %m");
				log_single(LOG_ERR, rt);
			} else if (rlen < RIPNG_RTM_MSGLEN) {
				log_single(LOG_ERR, rt);
			}
		}
		rt->rt_metric = HOPCNT_INFINITY;
		rt->rt_state |= RTS_CHANGED;
	}
	if (rt->rt_timer < EXPIRE_TIME)
		rt->rt_timer = EXPIRE_TIME;
}

void
rtdelete(struct rt_entry *rt)
{

	if (rt->rt_state & RTS_INTERFACE) {
		if (rt->rt_ifp != NULL) {
			syslog(LOG_ERR,
			    "rtdelete: "
			    "deleting route to interface %s (timed out)",
			    (rt->rt_ifp->int_name != NULL) ?
				rt->rt_ifp->int_name : "(noname)");
			log_single(LOG_ERR, rt);
		}
	}
	rtdown(rt);
	remque(rt);
	free((char *)rt);
}

/*
 * Mark all the routes heard off a particular interface "down".  Unlike the
 * routes managed by in.routed, all of these routes have an interface associated
 * with them.
 */
void
rtpurgeif(struct interface *ifp)
{
	struct rthash *rh;
	struct rt_entry *rt;
	int i;

	for (i = IPV6_ABITS; i >= 0; i--) {
		if (net_hashes[i] == NULL)
			continue;

		for (rh = net_hashes[i];
		    rh < &net_hashes[i][ROUTEHASHSIZ]; rh++) {
			for (rt = rh->rt_forw; rt != (struct rt_entry *)rh;
			    rt = rt->rt_forw) {
				if (rt->rt_ifp == ifp) {
					rtdown(rt);
					rt->rt_ifp = NULL;
					rt->rt_state &= ~RTS_INTERFACE;
				}
			}
		}
	}
}

/*
 * Called when the subnetmask has changed on one or more interfaces.
 * Re-evaluates all non-interface routes by doing a rtchange so that
 * routes that were believed to be host routes before the netmask change
 * can be converted to network routes and vice versa.
 */
void
rtchangeall(void)
{
	struct rthash *rh;
	struct rt_entry *rt;
	int i;

	for (i = IPV6_ABITS; i >= 0; i--) {
		if (net_hashes[i] == NULL)
			continue;

		for (rh = net_hashes[i];
		    rh < &net_hashes[i][ROUTEHASHSIZ]; rh++) {
			for (rt = rh->rt_forw; rt != (struct rt_entry *)rh;
			    rt = rt->rt_forw) {
				if ((rt->rt_state & RTS_INTERFACE) == 0) {
					rtchange(rt, &rt->rt_router,
					    rt->rt_metric, rt->rt_ifp);
				}
			}
		}
	}
}

static void
rtdumpentry(FILE *fp, struct rt_entry *rt)
{
	char buf1[INET6_ADDRSTRLEN];
	static struct bits {
		ulong_t	t_bits;
		char	*t_name;
	} flagbits[] = {
		/* BEGIN CSTYLED */
		{ RTF_UP,		"UP" },
		{ RTF_GATEWAY,		"GATEWAY" },
		{ RTF_HOST,		"HOST" },
		{ 0,			NULL }
		/* END CSTYLED */
	}, statebits[] = {
		/* BEGIN CSTYLED */
		{ RTS_INTERFACE,	"INTERFACE" },
		{ RTS_CHANGED,		"CHANGED" },
		{ RTS_PRIVATE,		"PRIVATE" },
		{ 0,			NULL }
		/* END CSTYLED */
	};
	struct bits *p;
	boolean_t first;
	char c;

	(void) fprintf(fp, "prefix %s/%d ",
	    inet_ntop(AF_INET6, (void *)&rt->rt_dst, buf1, sizeof (buf1)),
	    rt->rt_prefix_length);
	(void) fprintf(fp, "via %s metric %d timer %d",
	    inet_ntop(AF_INET6, (void *)&rt->rt_router, buf1, sizeof (buf1)),
	    rt->rt_metric, rt->rt_timer);
	if (rt->rt_ifp != NULL) {
		(void) fprintf(fp, " if %s",
		    (rt->rt_ifp->int_name != NULL) ?
			rt->rt_ifp->int_name : "(noname)");
	}
	(void) fprintf(fp, " state");
	c = ' ';
	for (first = _B_TRUE, p = statebits; p->t_bits > 0; p++) {
		if ((rt->rt_state & p->t_bits) == 0)
			continue;
		(void) fprintf(fp, "%c%s", c, p->t_name);
		if (first) {
			c = '|';
			first = _B_FALSE;
		}
	}
	if (first)
		(void) fprintf(fp, " 0");
	if (rt->rt_flags & (RTF_UP | RTF_GATEWAY)) {
		c = ' ';
		for (first = _B_TRUE, p = flagbits; p->t_bits > 0; p++) {
			if ((rt->rt_flags & p->t_bits) == 0)
				continue;
			(void) fprintf(fp, "%c%s", c, p->t_name);
			if (first) {
				c = '|';
				first = _B_FALSE;
			}
		}
	}
	(void) putc('\n', fp);
	(void) fflush(fp);
}

static void
rtdump2(FILE *fp)
{
	struct rthash *rh;
	struct rt_entry *rt;
	int i;

	for (i = IPV6_ABITS; i >= 0; i--) {
		if (net_hashes[i] == NULL)
			continue;

		for (rh = net_hashes[i];
		    rh < &net_hashes[i][ROUTEHASHSIZ]; rh++) {
			for (rt = rh->rt_forw; rt != (struct rt_entry *)rh;
			    rt = rt->rt_forw) {
				rtdumpentry(fp, rt);
			}
		}
	}
}

void
rtdump(void)
{
	if (ftrace != NULL)
		rtdump2(ftrace);
	else
		rtdump2(stderr);
}

/*
 * Create a routing socket for sending RTM_ADD and RTM_DELETE messages and
 * initialize the routing socket message header and as much of the sockaddrs
 * as possible.
 */
void
setup_rtsock(void)
{
	char *cp;
	int off = 0;

	rtsock = socket(PF_ROUTE, SOCK_RAW, AF_INET6);
	if (rtsock < 0) {
		syslog(LOG_ERR, "setup_rtsock: socket: %m");
		exit(EXIT_FAILURE);
	}

	/* We don't want to listen to our own messages */
	if (setsockopt(rtsock, SOL_SOCKET, SO_USELOOPBACK, (char *)&off,
	    sizeof (off)) < 0) {
		syslog(LOG_ERR, "setup_rtsock: setsockopt: SO_USELOOPBACK: %m");
		exit(EXIT_FAILURE);
	}

	/*
	 * Allocate storage for the routing socket message.
	 */
	rt_msg = (struct rt_msghdr *)malloc(RIPNG_RTM_MSGLEN);
	if (rt_msg == NULL) {
		syslog(LOG_ERR, "setup_rtsock: malloc: %m");
		exit(EXIT_FAILURE);
	}

	/*
	 * Initialize the routing socket message by zero-filling it and then
	 * setting the fields where are constant through the lifetime of the
	 * process.
	 */
	bzero(rt_msg, RIPNG_RTM_MSGLEN);
	rt_msg->rtm_msglen = RIPNG_RTM_MSGLEN;
	rt_msg->rtm_version = RTM_VERSION;
	rt_msg->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP;
	rt_msg->rtm_pid = getpid();
	if (rt_msg->rtm_pid < 0) {
		syslog(LOG_ERR, "setup_rtsock: getpid: %m");
		exit(EXIT_FAILURE);
	}

	/*
	 * Initialize the constant portion of the RTA_DST sockaddr.
	 */
	cp = (char *)rt_msg + sizeof (struct rt_msghdr);
	rta_dst = (struct sockaddr_in6 *)cp;
	rta_dst->sin6_family = AF_INET6;

	/*
	 * Initialize the constant portion of the RTA_GATEWAY sockaddr.
	 */
	cp += sizeof (struct sockaddr_in6);
	rta_gateway = (struct sockaddr_in6 *)cp;
	rta_gateway->sin6_family = AF_INET6;

	/*
	 * Initialize the constant portion of the RTA_NETMASK sockaddr.
	 */
	cp += sizeof (struct sockaddr_in6);
	rta_netmask = (struct sockaddr_in6 *)cp;
	rta_netmask->sin6_family = AF_INET6;

	/*
	 * Initialize the constant portion of the RTA_IFP sockaddr.
	 */
	cp += sizeof (struct sockaddr_in6);
	rta_ifp = (struct sockaddr_dl *)cp;
	rta_ifp->sdl_family = AF_LINK;
}

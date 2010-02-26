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
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include <inetcfg.h>
#include <libnwam.h>
#include "events.h"
#include "ncp.h"
#include "ncu.h"
#include "util.h"

/*
 * routing_events.c - this file contains routines to retrieve routing socket
 * events and package them for high level processing.
 */

#define	RTMBUFSZ	sizeof (struct rt_msghdr) + \
			(RTAX_MAX * sizeof (struct sockaddr_storage))

static void printaddrs(int, void *);
static char *printaddr(void **);
static void *getaddr(int, int, void *);
static void setaddr(int, int *, void *, struct sockaddr *);

union rtm_buf
{
	/* Routing information. */
	struct
	{
		struct rt_msghdr rtm;
		struct sockaddr_storage addr[RTAX_MAX];
	} r;

	/* Interface information. */
	struct
	{
		struct if_msghdr ifm;
		struct sockaddr_storage addr[RTAX_MAX];
	} im;

	/* Interface address information. */
	struct
	{
		struct ifa_msghdr ifa;
		struct sockaddr_storage addr[RTAX_MAX];
	} ia;
};

static int v4_sock = -1;
static int v6_sock = -1;
static pthread_t v4_routing, v6_routing;
static int seq = 0;

static const char *
rtmtype_str(int type)
{
	static char typestr[12]; /* strlen("type ") + enough for an int */

	switch (type) {
	case RTM_NEWADDR:
		return ("NEWADDR");
	case RTM_DELADDR:
		return ("DELADDR");
	case RTM_CHGADDR:
		return ("CHGADDR");
	case RTM_FREEADDR:
		return ("FREEADDR");
	case RTM_IFINFO:
		return ("IFINFO");
	default:
		(void) snprintf(typestr, sizeof (typestr), "type %d", type);
		return (typestr);
	}
}

/* ARGSUSED0 */
static void *
routing_events_v4(void *arg)
{
	int n;
	union rtm_buf buffer;
	struct rt_msghdr *rtm;
	struct ifa_msghdr *ifa;
	struct if_msghdr *ifm;
	char *addrs, *if_name;
	struct sockaddr_dl *addr_dl;
	struct sockaddr *addr;
	nwamd_event_t ip_event;

	nlog(LOG_DEBUG, "v4 routing socket %d", v4_sock);

	for (;;) {
		rtm = &buffer.r.rtm;
		n = read(v4_sock, &buffer, sizeof (buffer));
		if (n == -1 && errno == EAGAIN) {
			continue;
		} else if (n == -1) {
			nlog(LOG_ERR, "error reading routing socket "
			    "%d: %m", v4_sock);
			/* Low likelihood.  What's recovery path?  */
			continue;
		}

		if (rtm->rtm_msglen < n) {
			nlog(LOG_ERR, "only read %d bytes from "
			    "routing socket but message claims to be "
			    "of length %d", rtm->rtm_msglen);
			continue;
		}

		if (rtm->rtm_version != RTM_VERSION) {
			nlog(LOG_ERR, "tossing routing message of "
			    "version %d type %d", rtm->rtm_version,
			    rtm->rtm_type);
			continue;
		}

		if (rtm->rtm_msglen != n) {
			nlog(LOG_DEBUG, "routing message of %d size came from "
			    "read of %d on socket %d", rtm->rtm_msglen,
			    n, v4_sock);
		}

		switch (rtm->rtm_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_CHGADDR:
		case RTM_FREEADDR:

			ifa = (void *)rtm;
			addrs = (char *)ifa + sizeof (*ifa);

			nlog(LOG_DEBUG, "v4 routing message %s: "
			    "index %d flags %x", rtmtype_str(rtm->rtm_type),
			    ifa->ifam_index, ifa->ifam_flags);
			printaddrs(ifa->ifam_addrs, addrs);

			if ((addr = (struct sockaddr *)getaddr(RTA_IFA,
			    ifa->ifam_addrs, addrs)) == NULL)
				break;

			/* Ignore routing socket messages for 0.0.0.0 */
			/*LINTED*/
			if (((struct sockaddr_in *)addr)->sin_addr.s_addr
			    == INADDR_ANY) {
				nlog(LOG_DEBUG, "routing_events_v4: "
				    "tossing message for 0.0.0.0");
				break;
			}

			if ((addr_dl = (struct sockaddr_dl *)getaddr
			    (RTA_IFP, ifa->ifam_addrs, addrs)) == NULL)
				break;
			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;
			if_name = addr_dl->sdl_data; /* no lifnum */

			if (ifa->ifam_index == 0) {
				nlog(LOG_DEBUG, "tossing index 0 message");
				break;
			}
			if (ifa->ifam_type != rtm->rtm_type) {
				nlog(LOG_INFO,
				    "routing_events_v4: unhandled type %d",
				    ifa->ifam_type);
				break;
			}

			/* Create and enqueue IF_STATE event */
			ip_event = nwamd_event_init_if_state(if_name,
			    ifa->ifam_flags,
			    (rtm->rtm_type == RTM_NEWADDR ||
			    rtm->rtm_type == RTM_CHGADDR ? B_TRUE : B_FALSE),
			    ifa->ifam_index, addr);
			if (ip_event != NULL)
				nwamd_event_enqueue(ip_event);
			break;

		case RTM_IFINFO:

			ifm = (void *)rtm;
			addrs = (char *)ifm + sizeof (*ifm);
			nlog(LOG_DEBUG, "v4 routing message %s: "
			    "index %d flags %x", rtmtype_str(rtm->rtm_type),
			    ifm->ifm_index, ifm->ifm_flags);
			printaddrs(ifm->ifm_addrs, addrs);

			if ((addr_dl = (struct sockaddr_dl *)getaddr(RTA_IFP,
			    ifm->ifm_addrs, addrs)) == NULL)
				break;
			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;
			if_name = addr_dl->sdl_data; /* no lifnum */

			if (ifm->ifm_index == 0) {
				nlog(LOG_DEBUG, "tossing index 0 message");
				break;
			}
			if (ifm->ifm_type != RTM_IFINFO) {
				nlog(LOG_DEBUG,
				    "routing_events_v4: unhandled type %d",
				    ifm->ifm_type);
				break;
			}

			/* Create and enqueue IF_STATE event */
			ip_event = nwamd_event_init_if_state(if_name,
			    ifm->ifm_flags, B_FALSE, ifm->ifm_index, NULL);
			if (ip_event != NULL)
				nwamd_event_enqueue(ip_event);
			break;

		default:
			nlog(LOG_DEBUG, "v4 routing message %s discarded",
			    rtmtype_str(rtm->rtm_type));
			break;
		}
	}
	/* NOTREACHED */
	return (NULL);
}

/* ARGSUSED0 */
static void *
routing_events_v6(void *arg)
{
	int n;
	union rtm_buf buffer;
	struct rt_msghdr *rtm;
	struct ifa_msghdr *ifa;
	struct if_msghdr *ifm;
	char *addrs, *if_name;
	struct sockaddr_dl *addr_dl;
	struct sockaddr *addr;
	nwamd_event_t ip_event;

	nlog(LOG_DEBUG, "v6 routing socket %d", v6_sock);

	for (;;) {

		rtm = &buffer.r.rtm;
		n = read(v6_sock, &buffer, sizeof (buffer));
		if (n == -1 && errno == EAGAIN) {
			continue;
		} else if (n == -1) {
			nlog(LOG_ERR, "error reading routing socket "
			    "%d: %m", v6_sock);
			/* Low likelihood.  What's recovery path?  */
			continue;
		}

		if (rtm->rtm_msglen < n) {
			nlog(LOG_ERR, "only read %d bytes from "
			    "routing socket but message claims to be "
			    "of length %d", rtm->rtm_msglen);
			continue;
		}

		if (rtm->rtm_version != RTM_VERSION) {
			nlog(LOG_ERR, "tossing routing message of "
			    "version %d type %d", rtm->rtm_version,
			    rtm->rtm_type);
			continue;
		}

		if (rtm->rtm_msglen != n) {
			nlog(LOG_DEBUG, "routing message of %d size came from "
			    "read of %d on socket %d", rtm->rtm_msglen,
			    n, v6_sock);
		}

		switch (rtm->rtm_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_CHGADDR:
		case RTM_FREEADDR:

			ifa = (void *)rtm;
			addrs = (char *)ifa + sizeof (*ifa);

			nlog(LOG_DEBUG, "v6 routing message %s: "
			    "index %d flags %x", rtmtype_str(rtm->rtm_type),
			    ifa->ifam_index, ifa->ifam_flags);
			printaddrs(ifa->ifam_addrs, addrs);

			if ((addr = (struct sockaddr *)getaddr(RTA_IFA,
			    ifa->ifam_addrs, addrs)) == NULL)
				break;

			/* Ignore messages for link local address */
			/*LINTED*/
			if (IN6_IS_ADDR_LINKLOCAL(
			    &((struct sockaddr_in6 *)addr)->sin6_addr)) {
				nlog(LOG_INFO, "routing_events_v6: "
				    "tossing message for link local address");
				break;
			}

			if ((addr_dl = (struct sockaddr_dl *)getaddr
			    (RTA_IFP, ifa->ifam_addrs, addrs)) == NULL)
				break;
			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;
			if_name = addr_dl->sdl_data; /* no lifnum */

			if (ifa->ifam_index == 0) {
				nlog(LOG_DEBUG, "tossing index 0 message");
				break;
			}
			if (ifa->ifam_type != rtm->rtm_type) {
				nlog(LOG_DEBUG,
				    "routing_events_v6: unhandled type %d",
				    ifa->ifam_type);
				break;
			}

			/* Create and enqueue IF_STATE event */
			ip_event = nwamd_event_init_if_state(if_name,
			    ifa->ifam_flags,
			    (rtm->rtm_type == RTM_NEWADDR ||
			    rtm->rtm_type == RTM_CHGADDR ? B_TRUE : B_FALSE),
			    ifa->ifam_index, addr);
			if (ip_event != NULL)
				nwamd_event_enqueue(ip_event);
			break;

		case RTM_IFINFO:

			ifm = (void *)rtm;
			addrs = (char *)ifm + sizeof (*ifm);
			nlog(LOG_DEBUG, "v6 routing message %s: "
			    "index %d flags %x", rtmtype_str(rtm->rtm_type),
			    ifm->ifm_index, ifm->ifm_flags);
			printaddrs(ifm->ifm_addrs, addrs);

			if ((addr_dl = (struct sockaddr_dl *)getaddr(RTA_IFP,
			    ifm->ifm_addrs, addrs)) == NULL)
				break;
			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;
			if_name = addr_dl->sdl_data; /* no lifnum */

			if (ifm->ifm_index == 0) {
				nlog(LOG_DEBUG, "tossing index 0 message");
				break;
			}
			if (ifm->ifm_type != RTM_IFINFO) {
				nlog(LOG_DEBUG,
				    "routing_events_v6: unhandled type %d",
				    ifm->ifm_type);
				break;
			}

			/* Create and enqueue IF_STATE event */
			ip_event = nwamd_event_init_if_state(if_name,
			    ifm->ifm_flags, B_FALSE, ifm->ifm_index, NULL);
			if (ip_event != NULL)
				nwamd_event_enqueue(ip_event);
			break;

		default:
			nlog(LOG_DEBUG, "v6 routing message %s discarded",
			    rtmtype_str(rtm->rtm_type));
			break;
		}
	}
	/* NOTREACHED */
	return (NULL);
}

void
nwamd_routing_events_init(void)
{
	pthread_attr_t attr;

	/*
	 * Initialize routing sockets here so that we know the routing threads
	 * (and any requests to add a route) will be working with a valid socket
	 * by the time we start handling events.
	 */
	v4_sock = socket(AF_ROUTE, SOCK_RAW, AF_INET);
	if (v4_sock == -1)
		pfail("failed to open v4 routing socket: %m");

	v6_sock = socket(AF_ROUTE, SOCK_RAW, AF_INET6);
	if (v6_sock == -1)
		pfail("failed to open v6 routing socket: %m");

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&v4_routing, &attr, routing_events_v4, NULL) != 0 ||
	    pthread_create(&v6_routing, &attr, routing_events_v6, NULL) != 0)
		pfail("routing thread creation failed");
	(void) pthread_attr_destroy(&attr);
}

void
nwamd_routing_events_fini(void)
{
	(void) pthread_cancel(v4_routing);
	(void) pthread_cancel(v6_routing);
}

void
nwamd_add_route(struct sockaddr *dest, struct sockaddr *mask,
    struct sockaddr *gateway, const char *ifname)
{
	char rtbuf[RTMBUFSZ];
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct rt_msghdr *rtm = (struct rt_msghdr *)rtbuf;
	void *addrs = rtbuf + sizeof (struct rt_msghdr);
	struct sockaddr_dl sdl;
	icfg_if_t intf;
	icfg_handle_t h;
	int rlen, index;
	int af;

	af = gateway->sa_family;

	/* set interface for default route to be associated with */
	(void) strlcpy(intf.if_name, ifname, sizeof (intf.if_name));
	intf.if_protocol = af;
	if (icfg_open(&h, &intf) != ICFG_SUCCESS) {
		nlog(LOG_ERR, "nwamd_add_route: "
		    "icfg_open failed on %s", ifname);
		return;
	}
	if (icfg_get_index(h, &index) != ICFG_SUCCESS) {
		nlog(LOG_ERR, "nwamd_add_route: "
		    "icfg_get_index failed on %s", ifname);
	}
	icfg_close(h);
	(void) bzero(&sdl, sizeof (struct sockaddr_dl));
	sdl.sdl_family = AF_LINK;
	sdl.sdl_index = index;

	(void) bzero(rtm, RTMBUFSZ);
	rtm->rtm_pid = getpid();
	rtm->rtm_type = RTM_ADD;
	rtm->rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_seq = ++seq;
	rtm->rtm_msglen = sizeof (rtbuf);
	setaddr(RTA_DST, &rtm->rtm_addrs, &addrs, dest);
	setaddr(RTA_GATEWAY, &rtm->rtm_addrs, &addrs, gateway);
	setaddr(RTA_NETMASK, &rtm->rtm_addrs, &addrs, mask);
	setaddr(RTA_IFP, &rtm->rtm_addrs, &addrs, (struct sockaddr *)&sdl);

	if ((rlen = write(af == AF_INET ? v4_sock : v6_sock,
	    rtbuf, rtm->rtm_msglen)) < 0) {
		nlog(LOG_ERR, "nwamd_add_route: "
		    "got error %s writing to routing socket", strerror(errno));
	} else if (rlen < rtm->rtm_msglen) {
		nlog(LOG_ERR, "nwamd_add_route: "
		    "only wrote %d bytes of %d to routing socket\n",
		    rlen, rtm->rtm_msglen);
	}
}

static char *
printaddr(void **address)
{
	static char buffer[80];
	sa_family_t family = *(sa_family_t *)*address;
	struct sockaddr_in *s4 = *address;
	struct sockaddr_in6 *s6 = *address;
	struct sockaddr_dl *dl = *address;

	switch (family) {
	case AF_UNSPEC:
		(void) inet_ntop(AF_UNSPEC, &s4->sin_addr, buffer,
		    sizeof (buffer));
		*address = (char *)*address + sizeof (*s4);
		break;
	case AF_INET:
		(void) inet_ntop(AF_INET, &s4->sin_addr, buffer,
		    sizeof (buffer));
		*address = (char *)*address + sizeof (*s4);
		break;
	case AF_INET6:
		(void) inet_ntop(AF_INET6, &s6->sin6_addr, buffer,
		    sizeof (buffer));
		*address = (char *)*address + sizeof (*s6);
		break;
	case AF_LINK:
		(void) snprintf(buffer, sizeof (buffer), "link %.*s",
		    dl->sdl_nlen, dl->sdl_data);
		*address = (char *)*address + sizeof (*dl);
		break;
	default:
		/*
		 * We can't reliably update the size of this thing
		 * because we don't know what its type is.  So bump
		 * it by a sockaddr_in and see what happens.  The
		 * caller should really make sure this never happens.
		 */
		*address = (char *)*address + sizeof (*s4);
		(void) snprintf(buffer, sizeof (buffer),
		    "unknown address family %d", family);
		break;
	}
	return (buffer);
}

static void
printaddrs(int mask, void *address)
{
	if (mask == 0)
		return;
	if (mask & RTA_DST)
		nlog(LOG_DEBUG, "destination address: %s", printaddr(&address));
	if (mask & RTA_GATEWAY)
		nlog(LOG_DEBUG, "gateway address: %s", printaddr(&address));
	if (mask & RTA_NETMASK)
		nlog(LOG_DEBUG, "netmask: %s", printaddr(&address));
	if (mask & RTA_GENMASK)
		nlog(LOG_DEBUG, "cloning mask: %s", printaddr(&address));
	if (mask & RTA_IFP)
		nlog(LOG_DEBUG, "interface name: %s", printaddr(&address));
	if (mask & RTA_IFA)
		nlog(LOG_DEBUG, "interface address: %s", printaddr(&address));
	if (mask & RTA_AUTHOR)
		nlog(LOG_DEBUG, "author: %s", printaddr(&address));
	if (mask & RTA_BRD)
		nlog(LOG_DEBUG, "broadcast address: %s", printaddr(&address));
}

static void
nextaddr(void **address)
{
	sa_family_t family = *(sa_family_t *)*address;

	switch (family) {
	case AF_UNSPEC:
	case AF_INET:
		*address = (char *)*address + sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		*address = (char *)*address + sizeof (struct sockaddr_in6);
		break;
	case AF_LINK:
		*address = (char *)*address + sizeof (struct sockaddr_dl);
		break;
	default:
		nlog(LOG_ERR, "unknown af (%d) while parsing rtm", family);
		break;
	}
}

static void *
getaddr(int addrid, int mask, void *addresses)
{
	int i;
	void *p = addresses;

	if ((mask & addrid) == 0)
		return (NULL);

	for (i = 1; i < addrid; i <<= 1) {
		if (i & mask)
			nextaddr(&p);
	}
	return (p);
}

static void
setaddr(int addrid, int *maskp, void *addressesp, struct sockaddr *address)
{
	struct sockaddr *p = *((struct sockaddr **)addressesp);

	*maskp |= addrid;

	switch (address->sa_family) {
	case AF_INET:
		(void) memcpy(p, address, sizeof (struct sockaddr_in));
		break;
	case AF_INET6:
		(void) memcpy(p, address, sizeof (struct sockaddr_in6));
		break;
	case AF_LINK:
		(void) memcpy(p, address, sizeof (struct sockaddr_dl));
		break;
	default:
		nlog(LOG_ERR, "setaddr: unknown af (%d) while setting addr",
		    address->sa_family);
		break;
	}
	nextaddr(addressesp);
}
